/* SPDX-License-Identifier: GPL-2.0 */
/* Include after apple-j314s-child-capture.inc. Direct synchronous continuation
 * only, called with compiled exact pins after capture succeeds. */
#include "j314s-combined-bootstrap.h"
static struct {
 bool consumed;
 struct apple_nhi *anhi;
 struct j314s_combined_io io;
 struct j314s_combined_result *result;
} j314s_next_owner;
static bool j314s_next_valid(void *ctx)
{
 struct apple_nhi*a=ctx;struct j314s_combined_result*r=j314s_next_owner.result;
 struct j314s_child_observation*c=&j314s_child_owner.result.child;
 return j314s_next_owner.consumed&&j314s_next_owner.anhi==a&&r&&
  j314s_child_owner_valid(a)&&j314s_child_capture_proven(a->acio)&&
  c->stable&&c->usb4&&c->uid_read&&c->route==r->pins.route&&j314s_child_owner.result.lane==r->pins.lane&&
  !memcmp(c->child_header,r->pins.child_before,20)&&
  c->uid_words[0]==(u32)(r->pins.uid>>32)&&c->uid_words[1]==(u32)r->pins.uid;
}
static u64 j314s_next_now(void *ctx){return ktime_get_boottime_ns();}
static void j314s_next_sleep(void *ctx,bool fast)
{if(fast)usleep_range(5,10);else usleep_range(1000,2000);}
static int j314s_next_read(void*ctx,unsigned route,unsigned port,bool sw,unsigned off,unsigned n,u32*v)
{
 struct apple_nhi*a=ctx;struct j314s_combined_result*r=j314s_next_owner.result;
 if(!j314s_next_valid(a)||!r||!n||n>13||off>8192-n||
    (route&&route!=r->pins.route)||(sw&&port)||(!sw&&(!port||port>(route?r->pins.max_port:7))))return -EPERM;
 /* DROM/configure/RR must precede every child adapter access. */
 if(route&&!sw&&r->phase<3)return -EPERM;
 return tb_cfg_read(a->tb->ctl,v,route,port,sw?TB_CFG_SWITCH:TB_CFG_PORT,off,n);
}
static int j314s_next_write(void*ctx,unsigned route,unsigned port,bool sw,unsigned off,unsigned n,const u32*v)
{
 struct apple_nhi*a=ctx;struct j314s_combined_result*r=j314s_next_owner.result;bool okay=false;
 if(!j314s_next_valid(a)||!r||!n||n>4||off>8192-n||(route&&route!=r->pins.route))return -EPERM;
 if(r->phase==1)okay=route==r->pins.route&&sw&&!port&&n==1&&
   ((off==25&&!(v[0]&~0xffffcU))||(off==26&&v[0]==0x80000024U));
 else if(r->phase==2)okay=sw&&!port&&((!route&&n==1&&(off==r->bootstrap.io.rt||off==r->bootstrap.io.rt+3))||
   (route&&((off==1&&n==4)||(off==5&&n==1))));
 else if(r->phase==4)okay=j314s_ready_write_allowed(&r->ready,!!route,port,sw,off,n);
 if(!okay)return -EPERM;
 return tb_cfg_write(a->tb->ctl,v,route,port,sw?TB_CFG_SWITCH:TB_CFG_PORT,off,n);
}
static int apple_j314s_child_bootstrap(struct apple_nhi*a,const struct j314s_bootstrap_pins*pins)
{
 struct j314s_combined_result*r;int ret;unsigned p;
 lockdep_assert_held(&a->acio->lock);lockdep_assert_held(&a->tb->lock);
 if(j314s_next_owner.consumed)return -EALREADY;
 j314s_next_owner.consumed=true;j314s_next_owner.anhi=a;
 if(!j314s_child_capture_proven(a->acio)||!j314s_bootstrap_pins_valid(pins))return -EPERM;
 r=kzalloc(sizeof(*r),GFP_KERNEL);if(!r)return -ENOMEM;
 /* Retain all evidence and owner storage on every outcome until reboot. */
 j314s_next_owner.result=r;
 j314s_next_owner.io=(struct j314s_combined_io){.read=j314s_next_read,.write=j314s_next_write,
  .valid=j314s_next_valid,.now=j314s_next_now,.sleep=j314s_next_sleep,.ctx=a,
  .deadline=ktime_get_boottime_ns()+120ULL*NSEC_PER_SEC};
 ret=j314s_combined_bootstrap_once(&j314s_next_owner.io,pins,r);
 dev_info(a->dev,"j314s-child-bootstrap: status%d phase%u complete%u ops%u DROM%u configured%u PCIeUP%u ready-phase%d; PCIe disabled\n",
 ret,r->phase,r->completed,j314s_next_owner.io.operations,r->drom_size,r->bootstrap.header_done,r->inventory.pci_up,r->ready.phase);
 if(r->drom_size)dev_info(a->dev,"j314s-child-bootstrap: observed DROM product %04x:%04x; identity descriptor, not a register-schema permit\n",r->uidio.product_vendor,r->uidio.product_device);
 if(r->drom_size)dev_info(a->dev,"j314s-child-bootstrap: validated DROM %*phN\n",r->drom_size,r->drom);
 for(p=1;p<=r->inventory.max_port&&p<=63;p++)if(r->inventory.child_read[p])
  dev_info(a->dev,"j314s-child-bootstrap: child port%u raw %*phN\n",p,32,r->inventory.child_ports[p]);
 return ret;
}
static bool j314s_child_bootstrap_proven(struct apple_cio*c)
{
 lockdep_assert_held(&c->lock);
 return j314s_next_owner.consumed&&j314s_next_owner.anhi&&j314s_next_owner.anhi->acio==c&&
  j314s_next_owner.result&&j314s_next_owner.io.attempted&&j314s_next_owner.result->completed&&
  !j314s_next_owner.result->status&&!READ_ONCE(c->root_probe_status);
}

static int apple_j314s_child_bootstrap_captured(struct apple_nhi*a)
{
 struct j314s_bootstrap_pins pins;struct j314s_link_result*r=&j314s_child_owner.result;
 lockdep_assert_held(&a->acio->lock);lockdep_assert_held(&a->tb->lock);
 if(!j314s_child_capture_proven(a->acio)||!r->child.stable||!r->child.uid_read||!r->child.usb4||
  !j314s_bootstrap_bind_capture(&pins,r->root,r->child.child_header,r->child.uid_words,r->lane,r->child.route))return -EOPNOTSUPP;
 if(pins.lane!=pins.route){
  dev_info(a->dev,"j314s-child-bootstrap: secondary physical link captured, primary native-ready proof absent; no bootstrap writes\n");
  return -EOPNOTSUPP;
 }
 return apple_j314s_child_bootstrap(a,&pins);
}
