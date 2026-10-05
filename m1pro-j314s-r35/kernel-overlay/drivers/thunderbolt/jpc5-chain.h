/* SPDX-License-Identifier: GPL-2.0 */
#ifndef JPC5_CHAIN_H
#define JPC5_CHAIN_H
#include "jpc5-pins.h"
#include "jpc5-drom.h"
#include "jpc5-uid-core.h"
#include "jpc5-child-config-core.h"
#include "jpc5-readiness-core.h"
/* Retained caller allocates each edge once and holds ACIO/TB locks throughout.
 * valid() must bind original owner, task, cable generation, disabled external
 * host and ROOT PE-clear. consume() irrevocably records this parent/lane in
 * original owner's edge set; rejecting duplicate attempts across contexts.
 * Both successful and failed contexts remain retained until normal reboot.
 * No callable kernel front end is provided by this isolated candidate. */
struct jpc5_node {
 unsigned depth;u64 route,uid;u32 header[5],ports[64][8];bool read[64];
 unsigned pcie_cap[64],phy[64],phy_status[64],up;u64 phy_status_valid;struct jpc5_pairs pairs;
 bool identity,configured,ready;unsigned char drom[1036];unsigned drom_size;
};
struct jpc5_io {
 int (*read)(void*,u64,unsigned,bool,unsigned,unsigned,u32*);
 int (*write)(void*,u64,unsigned,bool,unsigned,unsigned,const u32*);
 bool (*valid)(void*);int (*consume)(void*,u64,unsigned);
 int (*capture_uid)(void*,u64);
 u64 (*now)(void*);void (*sleep)(void*,bool);void*ctx;
 u64 original_deadline;unsigned operations;bool attempted;
};
struct jpc5_edge {
 struct jpc5_io*io;struct jpc5_node parent,child;struct jpc5_bootstrap_pins pins;
 struct jpc5_ready_io ready;unsigned lane,peer,phase;bool complete,survey_terminal;int status;
};
static int jpc5_gate(struct jpc5_edge*e)
{
 if(!e->io->valid(e->io->ctx))return -EPERM;
 if(e->io->operations>=16384||e->io->now(e->io->ctx)>=e->io->original_deadline)return -ETIMEDOUT;
 e->io->operations++;return 0;
}
static int jpc5_read(struct jpc5_edge*e,unsigned side,unsigned p,bool sw,unsigned off,unsigned n,u32*v)
{
 int x;
 if(side>1||!n||n>13||off>8192-n||(sw?p!=0:(!p||p>23)))return -EINVAL;
 x=jpc5_gate(e);if(x)return x;
 x=e->io->read(e->io->ctx,side?e->child.route:e->parent.route,p,sw,off,n,v);
 if(x)return x;
 return jpc5_gate(e);
}
static int jpc5_identity(struct jpc5_edge*e,unsigned side)
{
 struct jpc5_node*n=side?&e->child:&e->parent;u32 h[5],uid[2];int x;
 x=jpc5_read(e,side,0,true,0,5,h);if(x)return x;
 x=jpc5_read(e,side,0,true,7,2,uid);if(x)return x;
 return memcmp(h,n->header,20)||(((u64)uid[0]<<32)|uid[1])!=n->uid?-ESTALE:0;
}
static int jpc5_contained(struct jpc5_edge*e)
{
 int x;u32 v;
 for(unsigned side=0;side<2;side++){
  struct jpc5_node*n=side?&e->child:&e->parent;
  if(!n->identity)continue;
  x=jpc5_identity(e,side);if(x)return x;
  for(unsigned p=1;p<=23;p++)if(n->pcie_cap[p]){
   x=jpc5_read(e,side,p,false,n->pcie_cap[p],1,&v);if(x)return x;
   if(((v>>8)&255)!=4||(v>>31))return -EPERM;
  }
 }
 return 0;
}
static int jpc5_write(struct jpc5_edge*e,unsigned side,unsigned p,bool sw,unsigned off,unsigned n,const u32*v)
{
 bool allow=false;int x;u32 fresh;
 if(!v||side>1||!n||n>4||off>8192-n)return -EINVAL;
 if(e->phase==1&&!side&&!sw&&(p==e->lane||p==e->peer)&&off==4&&n==1){
  x=jpc5_read(e,0,p,false,4,1,&fresh);if(x)return x;
  allow=v[0]==(fresh&~(1U<<31));
 }else if(e->phase==2&&side&&sw&&!p&&n==1)
  allow=(off==25&&!(v[0]&~0xffffcU))||(off==26&&v[0]==0x80000024U);
 else if(e->phase==3&&side&&sw&&!p){
  allow=off==1&&n==4&&!memcmp(v,e->pins.child_after+1,16);
  if(off==5&&n==1){x=jpc5_read(e,1,0,true,5,1,&fresh);if(x)return x;
   allow=!(fresh&1)&&v[0]==((fresh&~(1U<<23))|(1U<<24));}
 }
 else if(e->phase==5)allow=jpc5_ready_write_allowed(&e->ready,side,p,sw,off,n);
 if(!allow)return -EPERM;
 x=jpc5_contained(e);if(x)return x;x=jpc5_gate(e);if(x)return x;
 x=e->io->write(e->io->ctx,side?e->child.route:e->parent.route,p,sw,off,n,v);
 if(x)return x;
 /* Header upload changes child identity exactly once; readback below must
  * prove desired header before any further operation can be admitted. */
 if(e->phase==3&&off==1)memcpy(e->child.header,e->pins.child_after,20);
 x=jpc5_gate(e);if(x)return x;return jpc5_contained(e);
}
static bool jpc5_valid(void*p){struct jpc5_edge*e=p;return e->io->valid(e->io->ctx);}
static bool jpc5_expired(void*p){struct jpc5_edge*e=p;return e->io->operations>=16384||e->io->now(e->io->ctx)>=e->io->original_deadline;}
static u64 jpc5_now(void*p){struct jpc5_edge*e=p;return e->io->now(e->io->ctx);}
static void jpc5_sleep(void*p,bool fast){struct jpc5_edge*e=p;e->io->sleep(e->io->ctx,fast);}
static void jpc5_uid_sleep(void*p){jpc5_sleep(p,false);}
static int jpc5_read_cb(void*p,unsigned s,unsigned port,bool sw,unsigned off,unsigned n,u32*v){return jpc5_read(p,s,port,sw,off,n,v);}
static int jpc5_write_cb(void*p,unsigned s,unsigned port,bool sw,unsigned off,unsigned n,const u32*v){return jpc5_write(p,s,port,sw,off,n,v);}
static int jpc5_child_read(void*p,unsigned off,unsigned n,u32*v){return jpc5_read(p,1,0,true,off,n,v);}
static int jpc5_child_write(void*p,unsigned off,unsigned n,const u32*v){return jpc5_write(p,1,0,true,off,n,v);}
static int jpc5_uid_write_cb(void*p,unsigned off,u32 v){return jpc5_write(p,1,0,true,off,1,&v);}
static bool jpc5_protocol(void*p,const u32*h){struct jpc5_edge*e=p;return !memcmp(h,e->pins.child_before,20);}
static int jpc5_cap(struct jpc5_edge*e,unsigned side,unsigned port,unsigned first,unsigned wanted,unsigned*out)
{
 bool seen[256]={false};unsigned count=0;u32 v;int x;*out=0;
 while(first){
  if(first<8||first>255||seen[first]||count++>=64)return -EINVAL;
  seen[first]=true;x=jpc5_read(e,side,port,false,first,1,&v);if(x)return x;
  if(((v>>8)&255)==wanted){if(*out)return -EINVAL;*out=first;}
  first=v&255;
 }
 return *out?0:-ENOENT;
}
static int jpc5_inventory(struct jpc5_edge*e,unsigned side)
{
 struct jpc5_node*n=side?&e->child:&e->parent;unsigned up=0;int x;u32 v;
 x=jpc5_identity(e,side);if(x)return x;
 memset(n->read,0,sizeof(n->read));memset(n->pcie_cap,0,sizeof(n->pcie_cap));memset(n->phy,0,sizeof(n->phy));
 for(unsigned p=1;p<=23;p++){
  if(n->pairs.disabled&(1ULL<<p))continue;
  x=jpc5_read(e,side,p,false,0,8,n->ports[p]);
  /* Exact Intel5786 schema only; absent adapters13..16 documented by R54. */
  if(x==-ENODEV&&p>=13&&p<=16)continue;
  if(x)return x;
  n->read[p]=true;
  if(((n->ports[p][3]>>20)&63)!=p)return -ESTALE;
  unsigned type=n->ports[p][2]&0xffffff;
  if(type==1){x=jpc5_cap(e,side,p,n->ports[p][1]&255,1,&n->phy[p]);if(x)return x;}
  if(type==0x100101||type==0x100102){
   x=jpc5_cap(e,side,p,n->ports[p][1]&255,4,&n->pcie_cap[p]);if(x)return x;
   x=jpc5_read(e,side,p,false,n->pcie_cap[p],1,&v);if(x)return x;if(v>>31)return -EBUSY;
   if(type==0x100102){if(up++)return -EINVAL;n->up=p;}
  }
 }
 return up==1?jpc5_identity(e,side):-EINVAL;
}
/* Survey actual paired PHY words before choosing one downstream edge.
 * Exactly one connected pair is required; branch fanout is not auto-selected.
 * Read all pairs before returning so later activity cannot be ignored. */
static int jpc5_select_live_primary(struct jpc5_edge*e,unsigned*lane)
{
 unsigned found=0;u32 phy[2];int x;*lane=0;e->survey_terminal=false;
 for(unsigned p=1;p<=23;p++){
  struct jpc5_node*n=&e->parent;unsigned peer=n->pairs.peer[p];
  if(!peer||n->pairs.secondary[p]||p==1||peer==1||
     (n->pairs.disabled&(1ULL<<p)))continue;
  if(!n->read[p]||!n->read[peer]||!n->phy[p]||!n->phy[peer]||
     (n->ports[p][2]&0xffffff)!=1||(n->ports[peer][2]&0xffffff)!=1)return -EPERM;
  for(unsigned j=0;j<2;j++){
   unsigned port=j?peer:p;
   x=jpc5_read(e,0,port,false,n->phy[port]+1,1,&phy[j]);if(x)return x;
   n->phy_status[port]=phy[j];n->phy_status_valid|=1ULL<<port;
  }
  bool live=false;
  for(unsigned j=0;j<2;j++){
   unsigned state=(phy[j]>>26)&15;
   if(phy[j]==~0U||(phy[j]&(1U<<14))||state>7)return -EOPNOTSUPP;
   if(state==1)return -EAGAIN; /* Connecting is not a proven terminal. */
   if(state>=2&&state<=6)live=true;
  }
  if(live){found++;*lane=p;}
 }
 if(!found)e->survey_terminal=true;
 return found==1?0:found?-E2BIG:-ENOLINK;
}
static int jpc5_chain_once(struct jpc5_io*io,const struct jpc5_node*parent,unsigned lane,struct jpc5_edge*e)
{
 const u32 fresh[5]={0x57868087,0x8505c16b,0,0,0x4000000a};u32 h[5],uid[2],v,w;int x;
 if(!io||!parent||!e||!io->read||!io->write||!io->valid||!io->consume||!io->capture_uid||!io->now||!io->sleep)return -EINVAL;
 if(io->attempted)return -EALREADY;
 io->attempted=true;
 memset(e,0,sizeof(*e));e->io=io;e->status=-EINPROGRESS;e->parent=*parent;e->lane=lane;
 if(!parent->identity||!parent->configured||!parent->ready||parent->depth<1||parent->depth>=5||
    !jpc5_route_depth(parent->route,parent->depth)||!lane||lane>23||lane==1||
    !parent->uid||parent->uid==~0ULL||parent->header[0]!=fresh[0]||
    parent->header[1]!=(fresh[1]|(parent->depth<<20))||parent->header[2]!=(u32)parent->route||
    parent->header[3]!=(0x80000000U|(u32)(parent->route>>32))||parent->header[4]!=0x400020ff){x=-EPERM;goto out;}
 /* Consume caller's retained edge ticket even when validation later fails. */
 x=io->consume(io->ctx,parent->route,lane);if(x)goto out;
 x=jpc5_gate(e);if(x)goto out;
 struct jpc5_bootstrap_pins parentpin={.uid=parent->uid};
 struct jpc5_uid_io parentuid={.pins=&parentpin};
 x=jpc5_uid_drom_validate_expected(parent->drom,parent->drom_size,&parentuid);if(x)goto out;
 x=jpc5_pairs_parse(parent->drom,parent->drom_size,23,&e->parent.pairs);if(x)goto out;
 if(!e->parent.pairs.peer[lane]||e->parent.pairs.secondary[lane]||(e->parent.pairs.disabled&(1ULL<<lane))){x=-EPERM;goto out;}
 e->peer=e->parent.pairs.peer[lane];
 e->child.route=parent->route|((u64)lane<<(parent->depth*8));e->child.depth=parent->depth+1;
 x=jpc5_inventory(e,0);if(x)goto out;
 if(!e->parent.phy[lane]||!e->parent.phy[e->peer]||
    (e->parent.ports[lane][2]&0xffffff)!=1||(e->parent.ports[e->peer][2]&0xffffff)!=1){x=-EPERM;goto out;}
 x=jpc5_down_map(&e->parent.pairs,e->parent.ports,e->parent.read,23,1,lane,&e->pins.down);if(x)goto out;
 e->phase=1;
 /* Standard paired-port unlock order before scan; RMW preserves live fields. */
 for(unsigned k=0;k<2;k++){
  unsigned p=k?e->peer:lane;
  x=jpc5_read(e,0,p,false,4,1,&v);if(x)goto out;v&=~(1U<<31);
  x=jpc5_write(e,0,p,false,4,1,&v);if(x)goto out;
  x=jpc5_read(e,0,p,false,4,1,&w);if(x)goto out;if(v!=w){x=-EIO;goto out;}
 }
 /* Readiness uses logical primary; secondary-only evidence never authorizes
  * TMU writes. Poll original owner budget, no attempt or deadline renewal. */
 for(unsigned k=0;;k++){
  x=jpc5_read(e,0,lane,false,e->parent.phy[lane]+1,1,&v);if(x)goto out;
  unsigned state=(v>>26)&15;
  if(!(v&(1U<<14))&&state>=2&&state<=6)break;
  if(k==49){x=-ENOLINK;goto out;}io->sleep(io->ctx,false);
 }
 x=jpc5_read(e,1,0,true,0,5,h);if(x)goto out;
 if(memcmp(h,fresh,20)){x=-EOPNOTSUPP;goto out;}
 x=jpc5_read(e,1,0,true,7,2,uid);if(x)goto out;
 memcpy(e->child.header,h,20);e->child.uid=((u64)uid[0]<<32)|uid[1];
 if(!e->child.uid||e->child.uid==~0ULL||e->child.uid==parent->uid){x=-ESTALE;goto out;}
 x=jpc5_identity(e,1);if(x)goto out;
 x=io->capture_uid(io->ctx,e->child.uid);if(x)goto out;e->child.identity=true;
 memcpy(e->pins.root,parent->header,20);memcpy(e->pins.child_before,h,20);memcpy(e->pins.child_after,h,20);
 e->pins.child_after[1]|=e->child.depth<<20;e->pins.child_after[2]=(u32)e->child.route;
 e->pins.child_after[3]=0x80000000U|(u32)(e->child.route>>32);e->pins.child_after[4]=0x400020ff;
 e->pins.uid=e->child.uid;e->pins.route=lane;e->pins.upstream=1;e->pins.max_port=23;
 e->pins.depth=e->child.depth;e->pins.parent_route=parent->route;e->pins.child_route=e->child.route;
 if(!jpc5_bootstrap_pins_valid(&e->pins)){x=-EPERM;goto out;}
 e->phase=2;
 struct jpc5_uid_io u={.pins=&e->pins,.read=jpc5_child_read,.write=jpc5_uid_write_cb,.valid=jpc5_valid,.expired=jpc5_expired,
 .ctx=e,.expected_uid=e->child.uid,.now_ns=jpc5_now,.protocol=jpc5_protocol,.poll_delay=jpc5_uid_sleep};
 x=jpc5_uid_identity(&u,h,e->child.drom,&e->child.drom_size);if(x)goto out;
 x=jpc5_pairs_parse(e->child.drom,e->child.drom_size,23,&e->child.pairs);if(x)goto out;
 if(e->child.pairs.disabled&(1ULL<<1)){x=-EPERM;goto out;}
 e->phase=3;
 struct jpc5_child_cfg_io cfg={.pins=&e->pins,.read=jpc5_child_read,.write=jpc5_child_write,.valid=jpc5_valid,.expired=jpc5_expired,.ctx=e,.expected_uid=e->child.uid};
 u32 before[5],after[5];x=jpc5_child_cfg_once(&cfg,before,after);if(x)goto out;e->child.configured=true;
 x=jpc5_read(e,1,0,true,5,1,&v);if(x)goto out;if(v&1){x=-EBUSY;goto out;}
 v=(v&~(1U<<23))|(1U<<24);x=jpc5_write(e,1,0,true,5,1,&v);if(x)goto out;
 x=jpc5_read(e,1,0,true,5,1,&w);if(x)goto out;if(v!=w){x=-EIO;goto out;}
 for(unsigned k=0;;k++){
  x=jpc5_read(e,1,0,true,6,1,&v);if(x)goto out;if(v&(1U<<24))break;
  if(k==199){x=-ETIMEDOUT;goto out;}io->sleep(io->ctx,false);
 }
 e->phase=4;x=jpc5_inventory(e,1);if(x)goto out;
 e->phase=5;e->ready=(struct jpc5_ready_io){.pins=&e->pins,.read=jpc5_read_cb,.write=jpc5_write_cb,.valid=jpc5_valid,
 .now=jpc5_now,.sleep=jpc5_sleep,.ctx=e,.deadline=io->original_deadline,.up=e->child.up,.chain_child_depth=e->child.depth};
 x=jpc5_ready_once(&e->ready);if(x)goto out;
 x=jpc5_contained(e);if(x)goto out;e->child.ready=true;e->complete=true;
 out:e->status=x;return x;
}
#endif
