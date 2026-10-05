/* SPDX-License-Identifier: GPL-2.0 */
/* One synchronous continuation under retained owner/TB locks. No PCIe enable,
 * tunnel, host/DART activation or release. All storage survives until reboot. */
#include "j314s-bootstrap-pins.h"
#include "j314s-uid-core.h"
#include "j314s-child-config-core.h"
#include "j314s-readiness-core.h"
#include "j314s-bootstrap-core.h"
#include "j314s-inventory-core.h"
struct j314s_combined_io {
 int (*read)(void*,unsigned,unsigned,bool,unsigned,unsigned,u32*);
 int (*write)(void*,unsigned,unsigned,bool,unsigned,unsigned,const u32*);
 bool (*valid)(void*);u64 (*now)(void*);void (*sleep)(void*,bool);
 void *ctx;u64 deadline;bool attempted;unsigned operations;
};
struct j314s_combined_result {
 struct j314s_bootstrap_pins pins;
 struct j314s_uid_io uidio;
 struct j314s_bootstrap_io bootstrap;
 struct j314s_bob_inv_result inventory;
 struct j314s_bob_inv_io invio;
 struct j314s_ready_io ready;
 unsigned char drom[1036];unsigned drom_size,phase,root_pcie;
 bool completed;int status;struct j314s_combined_io *io;
};
static bool j314s_combined_valid(void*p)
{struct j314s_combined_result*r=p;return r->io->valid(r->io->ctx)&&j314s_bootstrap_pins_valid(&r->pins);}
static bool j314s_combined_expired(void*p)
{struct j314s_combined_result*r=p;return r->io->operations>=8192||r->io->now(r->io->ctx)>=r->io->deadline;}
static u64 j314s_combined_now(void*p)
{struct j314s_combined_result*r=p;return r->io->now(r->io->ctx);}
static void j314s_combined_sleep(void*p,bool fast)
{struct j314s_combined_result*r=p;r->io->sleep(r->io->ctx,fast);}
static void j314s_combined_uid_sleep(void*p){j314s_combined_sleep(p,false);}
static int j314s_combined_gate(struct j314s_combined_result*r)
{if(!j314s_combined_valid(r))return -EPERM;
 if(j314s_combined_expired(r))return -ETIMEDOUT;
 r->io->operations++;return 0;}
static int j314s_combined_read(void*p,unsigned side,unsigned port,bool sw,unsigned off,unsigned n,u32*v)
{
 struct j314s_combined_result*r=p;int x=j314s_combined_gate(r);if(x)return x;
 if(side>1||(sw&&port)||(!sw&&(!port||port>(side?r->pins.max_port:7)))||!n||n>13||off>8192-n)return -EINVAL;
 x=r->io->read(r->io->ctx,side?r->pins.route:0,port,sw,off,n,v);if(x)return x;
 return j314s_combined_valid(r)?(j314s_combined_expired(r)?-ETIMEDOUT:0):-EPERM;
}
static int j314s_combined_contained(struct j314s_combined_result*r)
{
 u32 v;int x;
 if(!r->root_pcie)return -EPERM;
 x=j314s_combined_read(r,0,r->pins.down,false,r->root_pcie,1,&v);if(x)return x;
 if(((v>>8)&255)!=4||(v>>31))return -EPERM;
 if(r->phase==4){
  if(!r->ready.cpcie)return -EPERM;
  x=j314s_combined_read(r,1,r->inventory.pci_up,false,r->ready.cpcie,1,&v);if(x)return x;
  if(((v>>8)&255)!=4||(v>>31))return -EPERM;
 }
 return 0;
}
static int j314s_combined_write(void*p,unsigned side,unsigned port,bool sw,unsigned off,unsigned n,const u32*v)
{
 struct j314s_combined_result*r=p;int x;bool allow=false;
 if(side>1||!n||n>4||off>8192-n)return -EINVAL;
 if(r->phase==1)allow=side==1&&sw&&!port&&n==1&&
  ((off==25&&!(v[0]&~0xffffcU))||(off==26&&v[0]==0x80000024U));
 else if(r->phase==2)allow=sw&&!port&&((side==0&&n==1&&(off==r->bootstrap.io.rt||off==r->bootstrap.io.rt+3))||
  (side==1&&((off==1&&n==4)||(off==5&&n==1))));
 else if(r->phase==4)allow=j314s_ready_write_allowed(&r->ready,side,port,sw,off,n);
 if(!allow)return -EPERM;
 x=j314s_combined_contained(r);if(x)return x;x=j314s_combined_gate(r);if(x)return x;
 x=r->io->write(r->io->ctx,side?r->pins.route:0,port,sw,off,n,v);if(x)return x;
 if(!j314s_combined_valid(r))return -EPERM;
 if(j314s_combined_expired(r))return -ETIMEDOUT;
 return j314s_combined_contained(r);
}
static int j314s_combined_uid_read(void*p,unsigned off,unsigned n,u32*v)
{return j314s_combined_read(p,1,0,true,off,n,v);}
static int j314s_combined_uid_write(void*p,unsigned off,u32 v)
{return j314s_combined_write(p,1,0,true,off,1,&v);}
static bool j314s_combined_protocol(void*p,const u32*h)
{struct j314s_combined_result*r=p;return !memcmp(h,r->pins.child_before,20);}
static struct j314s_ready_io j314s_combined_ready_io(struct j314s_combined_result*r)
{
 return (struct j314s_ready_io){.pins=&r->pins,.read=j314s_combined_read,.write=j314s_combined_write,
 .valid=j314s_combined_valid,.now=j314s_combined_now,.sleep=j314s_combined_sleep,.ctx=r,.deadline=r->io->deadline};
}
static int j314s_combined_bootstrap_once(struct j314s_combined_io*io,const struct j314s_bootstrap_pins*pins,struct j314s_combined_result*r)
{
 u32 h[8];int x;
 if(!io||!r||!pins||!io->read||!io->write||!io->valid||!io->now||!io->sleep)return -EINVAL;
 if(io->attempted)return -EALREADY;
 io->attempted=true;
 memset(r,0,sizeof(*r));r->io=io;r->pins=*pins;r->status=-EINPROGRESS;
 if(!j314s_bootstrap_pins_valid(&r->pins)){x=-EPERM;goto out;}
 /* Native scan/bootstrap waits for the logical primary's PHY. Capturing a
  * child through a live pairedsecondary does not prove that write sequence. */
 if(r->pins.lane!=r->pins.route){x=-EOPNOTSUPP;goto out;}
 r->bootstrap.io=j314s_combined_ready_io(r);
 x=j314s_combined_read(r,0,0,true,0,5,h);if(x)goto out;
 if(memcmp(h,r->pins.root,20)){x=-ESTALE;goto out;}
 x=j314s_combined_read(r,0,r->pins.down,false,0,8,h);if(x)goto out;
 if((h[2]&0xffffff)!=0x100101||((h[3]>>20)&63)!=r->pins.down){x=-EPERM;goto out;}
 x=j314s_ready_cap(&r->bootstrap.io,0,r->pins.down,false,h[1]&255,4,&r->root_pcie);if(x)goto out;
 x=j314s_combined_contained(r);if(x)goto out;
 r->phase=1;
 r->uidio=(struct j314s_uid_io){.pins=&r->pins,.read=j314s_combined_uid_read,.write=j314s_combined_uid_write,
 .valid=j314s_combined_valid,.expired=j314s_combined_expired,.ctx=r,.expected_uid=r->pins.uid,
 .now_ns=j314s_combined_now,.protocol=j314s_combined_protocol,.poll_delay=j314s_combined_uid_sleep};
 x=j314s_uid_identity(&r->uidio,r->pins.child_before,r->drom,&r->drom_size);if(x)goto out;
 x=j314s_bootstrap_disabled_ports(r->drom,r->drom_size,&r->pins,&r->inventory.disabled_ports);if(x)goto out;
 r->phase=2;r->bootstrap.expected_uid=r->pins.uid;
 x=j314s_bootstrap_once(&r->bootstrap);if(x)goto out;
 r->phase=3;r->invio=(struct j314s_bob_inv_io){.pins=&r->pins,.read=j314s_combined_read,.expired=j314s_combined_expired,.valid=j314s_combined_valid,.ctx=r};
 x=j314s_bob_inv_collect(&r->invio,&r->inventory);if(x)goto out;
 r->phase=4;r->ready=j314s_combined_ready_io(r);r->ready.up=r->inventory.pci_up;
 x=j314s_ready_once(&r->ready);if(x)goto out;
 x=j314s_combined_contained(r);if(x)goto out;
 r->completed=true;
out:r->status=x;return x;
}
