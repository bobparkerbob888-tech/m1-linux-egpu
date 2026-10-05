/* SPDX-License-Identifier: GPL-2.0 */
/* Isolated dormant candidate. Include after apple-j314s-child-bootstrap.inc.
 * No callsite, parameter, export, worker, PCIe or DMA admission is added.
 * Intended caller is same cold synchronous startup with both locks held,
 * before c->current_cable_info changes and before ANY provider activation. */
#include "jc-chain.h"
#define JC_MAX_EDGES 3
#define JC_MAX_CONTEXTS (JC_MAX_EDGES+1)
struct jc_kernel_edge {
 struct apple_nhi*a;struct task_struct*task;
 struct jc_io io;struct jc_edge edge;struct jc_node*seed;
 unsigned parent_route,lane;u64 captured_uid;bool consumed,surveying;
};
static struct {
 struct apple_nhi*a;struct task_struct*task;
 struct j314s_combined_result*first;u64 deadline;
 unsigned count;bool failed;
 struct jc_kernel_edge*edges[JC_MAX_CONTEXTS];
} jc_owner;
static bool jc_kernel_valid(void*p)
{
 struct jc_kernel_edge*k=p;struct apple_nhi*a=k->a;
 return a&&jc_owner.a==a&&jc_owner.task==current&&k->task==current&&
  !jc_owner.failed&&jc_owner.first==j314s_next_owner.result&&
  jc_owner.deadline==j314s_next_owner.io.deadline&&
  k->io.original_deadline==jc_owner.deadline&&
  ktime_get_boottime_ns()<jc_owner.deadline&&
  !a->enum_host&&!a->enum_bound&&!a->enum_stopping&&
  j314s_next_valid(a)&&j314s_child_bootstrap_proven(a->acio);
}
static int jc_kernel_root_blocked(struct jc_kernel_edge*k)
{
 struct j314s_combined_result*r=jc_owner.first;u32 v;int x;
 if(!jc_kernel_valid(k)||!r->root_pcie)return -EPERM;
 x=tb_cfg_read(k->a->tb->ctl,&v,0,r->pins.down,TB_CFG_PORT,r->root_pcie,1);
 if(x)return x;
 return ((v>>8)&255)!=4||(v>>31)||!jc_kernel_valid(k)?-EPERM:0;
}
static int jc_kernel_consume(void*p,unsigned route,unsigned lane)
{
 struct jc_kernel_edge*k=p;
 if(!jc_kernel_valid(k)||k->consumed||k->parent_route!=route||k->lane!=lane)return -EPERM;
 for(unsigned j=0;j<jc_owner.count;j++){
  struct jc_kernel_edge*other=jc_owner.edges[j];
  if(other!=k&&other->consumed&&other->parent_route==route&&other->lane==lane)return -EALREADY;
 }
 k->consumed=true;return 0;
}
static int jc_kernel_capture_uid(void*p,u64 uid)
{
 struct jc_kernel_edge*k=p;
 if(!jc_kernel_valid(k)||!k->consumed||k->captured_uid||!uid||uid==~0ULL||uid==jc_owner.first->pins.uid)return -ESTALE;
 for(unsigned j=0;j<jc_owner.count;j++)if(jc_owner.edges[j]->captured_uid==uid)return -ESTALE;
 k->captured_uid=uid;return 0;
}
static u64 jc_kernel_now(void*p){return ktime_get_boottime_ns();}
static void jc_kernel_sleep(void*p,bool fast)
{if(fast)usleep_range(5,10);else usleep_range(1000,2000);}
static int jc_kernel_read(void*p,unsigned route,unsigned port,bool sw,unsigned off,unsigned n,u32*v)
{
 struct jc_kernel_edge*k=p;
 if(!jc_kernel_valid(k)||(!k->consumed&&!k->surveying)||!n||n>13||off>8192-n||
   (route!=k->edge.parent.route&&route!=k->edge.child.route)||
   (k->surveying&&route!=k->edge.parent.route)||
   (sw?port!=0:(!port||port>23))||
   (route==k->edge.child.route&&!sw&&k->edge.phase<4))return -EPERM;
 return tb_cfg_read(k->a->tb->ctl,v,route,port,sw?TB_CFG_SWITCH:TB_CFG_PORT,off,n);
}
static int jc_kernel_write(void*p,unsigned route,unsigned port,bool sw,unsigned off,unsigned n,const u32*v)
{
 struct jc_kernel_edge*k=p;struct jc_edge*e=&k->edge;bool allow=false;int x;
 if(!jc_kernel_valid(k)||!k->consumed||!n||n>4||off>8192-n||
    (route!=e->parent.route&&route!=e->child.route))return -EPERM;
 bool side=route==e->child.route;
 if(e->phase==1)allow=!side&&!sw&&(port==e->lane||port==e->peer)&&off==4&&n==1&&!(v[0]>>31);
 else if(e->phase==2)allow=side&&sw&&!port&&n==1&&
  ((off==25&&!(v[0]&~0xffffcU))||(off==26&&v[0]==0x80000024U));
 else if(e->phase==3)allow=side&&sw&&!port&&((off==1&&n==4)||(off==5&&n==1));
 else if(e->phase==5)allow=jc_ready_write_allowed(&e->ready,side,port,sw,off,n);
 if(!allow)return -EPERM;
 x=jc_kernel_root_blocked(k);if(x)return x;
 /* root read can stall; valid includes original deadline immediately here. */
 if(!jc_kernel_valid(k))return -ETIMEDOUT;
 x=tb_cfg_write(k->a->tb->ctl,v,route,port,sw?TB_CFG_SWITCH:TB_CFG_PORT,off,n);
 if(x)return x;
 return jc_kernel_root_blocked(k);
}
/* parent_index0 is original proven enclosure; index1..N is the completed
 * corresponding retained child. Caller supplies a DROM-derived primary lane.
 * Unknown branch inventory is evidence only, never GPU/tunnel authorization. */
static int __maybe_unused apple_j314s_chain_prepare_edge(struct apple_nhi*a,unsigned parent_index,unsigned lane)
{
 struct jc_kernel_edge*k;struct jc_node*seed=NULL;int ret;
 lockdep_assert_held(&a->acio->lock);lockdep_assert_held(&a->tb->lock);
 if(!j314s_next_valid(a)||!j314s_child_bootstrap_proven(a->acio)||
    a->enum_host||a->enum_bound||jc_owner.failed)return -EPERM;
 if(!jc_owner.a){jc_owner.a=a;jc_owner.task=current;jc_owner.first=j314s_next_owner.result;jc_owner.deadline=j314s_next_owner.io.deadline;}
 if(jc_owner.a!=a||jc_owner.task!=current||parent_index>jc_owner.count||
    jc_owner.count>=JC_MAX_CONTEXTS||ktime_get_boottime_ns()>=jc_owner.deadline)return -EPERM;
 k=kzalloc(sizeof(*k),GFP_KERNEL);if(!k)return -ENOMEM;
 k->a=a;k->task=current;k->lane=lane;
 /* Retained before any operation. Partial initialization is never recycled. */
 jc_owner.edges[jc_owner.count++]=k;
 if(parent_index){
  struct jc_kernel_edge*parent=jc_owner.edges[parent_index-1];
  if(parent==k||!parent->edge.complete){ret=-EPERM;goto fail;}
  seed=&parent->edge.child;
 }else{
  struct j314s_combined_result*r=jc_owner.first;
  seed=kzalloc(sizeof(*seed),GFP_KERNEL);if(!seed){ret=-ENOMEM;goto fail;}
  /* Retained seed copy contains the first sameboot proven DROM and UID. */
  seed->route=r->pins.route;seed->depth=1;seed->uid=r->pins.uid;
  memcpy(seed->header,r->pins.child_after,20);memcpy(seed->drom,r->drom,r->drom_size);seed->drom_size=r->drom_size;
  seed->identity=seed->configured=seed->ready=true;
 }
 k->seed=seed;k->parent_route=seed->route;
 k->io=(struct jc_io){.read=jc_kernel_read,.write=jc_kernel_write,.valid=jc_kernel_valid,
 .consume=jc_kernel_consume,.capture_uid=jc_kernel_capture_uid,.now=jc_kernel_now,.sleep=jc_kernel_sleep,.ctx=k,.original_deadline=jc_owner.deadline};
 ret=jc_kernel_root_blocked(k);if(ret)goto fail;
 if(!lane){
  bool terminal=false;
  /* Read-only first-parent survey. No arbitrary lane/old route assumption. */
  k->edge.io=&k->io;k->edge.parent=*seed;k->surveying=true;
  struct jc_bootstrap_pins parentpin={.uid=seed->uid};
  struct jc_uid_io parentuid={.pins=&parentpin};
  ret=jc_uid_drom_validate_expected(seed->drom,seed->drom_size,&parentuid);
  if(!ret)ret=jc_pairs_parse(seed->drom,seed->drom_size,23,&k->edge.parent.pairs);
  if(!ret)ret=jc_inventory(&k->edge,0);
  if(!ret){ret=jc_select_live_primary(&k->edge,&lane);terminal=ret==-ENOLINK&&k->edge.survey_terminal;}
  k->surveying=false;
  /* Only an entirely read-only survey can declare end of chain. A timeout
   * or ENOLINK after unlock/configuration remains a failed consumed attempt. */
  if(terminal){
   if(!jc_kernel_valid(k)){ret=-ETIMEDOUT;goto fail;}
   return 1;
  }
  if(ret)goto fail;
  /* Last slot is terminal observation only. Never unlock a fourth edge. */
  if(jc_owner.count>JC_MAX_EDGES){ret=-E2BIG;goto fail;}
  k->lane=lane;
 }
 ret=jc_chain_once(&k->io,seed,lane,&k->edge);
 dev_info(a->dev,"j314s-chain candidate route%x UID%016llx phase%u status%d ready%u ops%u; no PCIe tunnel or GPU access\n",
 k->edge.child.route,k->edge.child.uid,k->edge.phase,ret,k->edge.complete,k->io.operations);
 if(k->edge.child.identity)
  dev_info(a->dev,"j314s-chain observed parent%x primary%u peer%u PCIeDOWN%u child-header %*phN\n",
   k->edge.parent.route,k->edge.lane,k->edge.peer,k->edge.pins.down,20,k->edge.child.header);
 if(k->edge.child.drom_size)
  dev_info(a->dev,"j314s-chain validated DROM %*phN\n",k->edge.child.drom_size,k->edge.child.drom);
 for(unsigned j=1;j<=23;j++)if(k->edge.child.read[j])
  dev_info(a->dev,"j314s-chain child route%x port%u header %*phN\n",k->edge.child.route,j,32,k->edge.child.ports[j]);
 if(ret)goto fail;
 return 0;
fail:jc_owner.failed=true;return ret;
}
