/* SPDX-License-Identifier: GPL-2.0 */
/* Isolated dormant candidate. Include after apple-j314s-child-bootstrap.inc.
 * No callsite, parameter, export, worker, PCIe or DMA admission is added.
 * Intended caller is same cold synchronous startup with both locks held,
 * before c->current_cable_info changes and before ANY provider activation. */
#include "jpc5-chain.h"
#define JPC5_MAX_EDGES 4
#define JPC5_MAX_CONTEXTS (JPC5_MAX_EDGES+1)
struct jpc_kernel_edge {
 struct apple_nhi*a;struct task_struct*task;
 struct jpc5_io io;struct jpc5_edge edge;struct jpc5_node*seed;
 u64 parent_route;unsigned lane;u64 captured_uid;bool consumed,surveying;
};
static struct {
 struct apple_nhi*a;struct task_struct*task;
 struct j314s_combined_result*first;u64 deadline;
 unsigned count;bool failed;
 struct jpc_kernel_edge*edges[JPC5_MAX_CONTEXTS];
} jpc_chain_owners[3];
#define jpc_chain_owner jpc_chain_owners[jpc_boot_peer_controller()]
static bool jpc_jc_kernel_valid(void*p)
{
 struct jpc_kernel_edge*k=p;struct apple_nhi*a=k->a;
 return a&&jpc_chain_owner.a==a&&jpc_chain_owner.task==current&&k->task==current&&
  !jpc_chain_owner.failed&&jpc_chain_owner.first==jpc_next_owner.result&&
  jpc_chain_owner.deadline==jpc_next_owner.io.deadline&&
  k->io.original_deadline==jpc_chain_owner.deadline&&
  ktime_get_boottime_ns()<jpc_chain_owner.deadline&&
  !a->enum_host&&!a->enum_bound&&!a->enum_stopping&&
  jpc_next_valid(a)&&jpc_bootstrap_proven(a->acio);
}
static int jpc_jc_kernel_root_blocked(struct jpc_kernel_edge*k)
{
 struct j314s_combined_result*r=jpc_chain_owner.first;u32 v;int x;
 if(!jpc_jc_kernel_valid(k)||!r->root_pcie)return -EPERM;
 x=tb_cfg_read(k->a->tb->ctl,&v,0,r->pins.down,TB_CFG_PORT,r->root_pcie,1);
 if(x)return x;
 return ((v>>8)&255)!=4||(v>>31)||!jpc_jc_kernel_valid(k)?-EPERM:0;
}
static int jpc_jc_kernel_consume(void*p,u64 route,unsigned lane)
{
 struct jpc_kernel_edge*k=p;
 if(!jpc_jc_kernel_valid(k)||k->consumed||k->parent_route!=route||k->lane!=lane)return -EPERM;
 for(unsigned j=0;j<jpc_chain_owner.count;j++){
  struct jpc_kernel_edge*other=jpc_chain_owner.edges[j];
  if(other!=k&&other->consumed&&other->parent_route==route&&other->lane==lane)return -EALREADY;
 }
 k->consumed=true;return 0;
}
static int jpc_jc_kernel_capture_uid(void*p,u64 uid)
{
 struct jpc_kernel_edge*k=p;
 if(!jpc_jc_kernel_valid(k)||!k->consumed||k->captured_uid||!uid||uid==~0ULL||uid==jpc_chain_owner.first->pins.uid)return -ESTALE;
 for(unsigned j=0;j<jpc_chain_owner.count;j++)if(jpc_chain_owner.edges[j]->captured_uid==uid)return -ESTALE;
 k->captured_uid=uid;return 0;
}
static u64 jpc_jc_kernel_now(void*p){return ktime_get_boottime_ns();}
static void jpc_jc_kernel_sleep(void*p,bool fast)
{if(fast)usleep_range(5,10);else usleep_range(1000,2000);}
static int jpc_jc_kernel_read(void*p,u64 route,unsigned port,bool sw,unsigned off,unsigned n,u32*v)
{
 struct jpc_kernel_edge*k=p;
 if(!jpc_jc_kernel_valid(k)||(!k->consumed&&!k->surveying)||!n||n>13||off>8192-n||
   (route!=k->edge.parent.route&&route!=k->edge.child.route)||
   (k->surveying&&route!=k->edge.parent.route)||
   (sw?port!=0:(!port||port>23))||
   (route==k->edge.child.route&&!sw&&k->edge.phase<4))return -EPERM;
 return tb_cfg_read(k->a->tb->ctl,v,route,port,sw?TB_CFG_SWITCH:TB_CFG_PORT,off,n);
}
static int jpc_jc_kernel_write(void*p,u64 route,unsigned port,bool sw,unsigned off,unsigned n,const u32*v)
{
 struct jpc_kernel_edge*k=p;struct jpc5_edge*e=&k->edge;bool allow=false;int x;
 if(!jpc_jc_kernel_valid(k)||!k->consumed||!n||n>4||off>8192-n||
    (route!=e->parent.route&&route!=e->child.route))return -EPERM;
 bool side=route==e->child.route;
 if(e->phase==1)allow=!side&&!sw&&(port==e->lane||port==e->peer)&&off==4&&n==1&&!(v[0]>>31);
 else if(e->phase==2)allow=side&&sw&&!port&&n==1&&
  ((off==25&&!(v[0]&~0xffffcU))||(off==26&&v[0]==0x80000024U));
 else if(e->phase==3)allow=side&&sw&&!port&&((off==1&&n==4)||(off==5&&n==1));
 else if(e->phase==5)allow=jpc5_ready_write_allowed(&e->ready,side,port,sw,off,n);
 if(!allow)return -EPERM;
 x=jpc_jc_kernel_root_blocked(k);if(x)return x;
 /* root read can stall; valid includes original deadline immediately here. */
 if(!jpc_jc_kernel_valid(k))return -ETIMEDOUT;
 x=tb_cfg_write(k->a->tb->ctl,v,route,port,sw?TB_CFG_SWITCH:TB_CFG_PORT,off,n);
 if(x)return x;
 return jpc_jc_kernel_root_blocked(k);
}
/* parent_index0 is original proven enclosure; index1..N is the completed
 * corresponding retained child. Caller supplies a DROM-derived primary lane.
 * Unknown branch inventory is evidence only, never GPU/tunnel authorization. */
static int __maybe_unused jpc_apple_j314s_chain_prepare_edge(struct apple_nhi*a,unsigned parent_index,unsigned lane)
{
 struct jpc_kernel_edge*k;struct jpc5_node*seed=NULL;int ret;
 lockdep_assert_held(&a->acio->lock);lockdep_assert_held(&a->tb->lock);
 if(!jpc_next_valid(a)||!jpc_bootstrap_proven(a->acio)||
    a->enum_host||a->enum_bound||jpc_chain_owner.failed)return -EPERM;
 if(!jpc_chain_owner.a){jpc_chain_owner.a=a;jpc_chain_owner.task=current;jpc_chain_owner.first=jpc_next_owner.result;jpc_chain_owner.deadline=jpc_next_owner.io.deadline;}
 if(jpc_chain_owner.a!=a||jpc_chain_owner.task!=current||parent_index>jpc_chain_owner.count||
    jpc_chain_owner.count>=JPC5_MAX_CONTEXTS||ktime_get_boottime_ns()>=jpc_chain_owner.deadline)return -EPERM;
 k=kzalloc(sizeof(*k),GFP_KERNEL);if(!k)return -ENOMEM;
 k->a=a;k->task=current;k->lane=lane;
 /* Retained before any operation. Partial initialization is never recycled. */
 jpc_chain_owner.edges[jpc_chain_owner.count++]=k;
 if(parent_index){
  struct jpc_kernel_edge*parent=jpc_chain_owner.edges[parent_index-1];
  if(parent==k||!parent->edge.complete){ret=-EPERM;goto fail;}
  seed=&parent->edge.child;
 }else{
  struct j314s_combined_result*r=jpc_chain_owner.first;
  seed=kzalloc(sizeof(*seed),GFP_KERNEL);if(!seed){ret=-ENOMEM;goto fail;}
  /* Retained seed copy contains the first sameboot proven DROM and UID. */
  seed->route=r->pins.route;seed->depth=1;seed->uid=r->pins.uid;
  memcpy(seed->header,r->pins.child_after,20);memcpy(seed->drom,r->drom,r->drom_size);seed->drom_size=r->drom_size;
  seed->identity=seed->configured=seed->ready=true;
 }
 k->seed=seed;k->parent_route=seed->route;
 k->io=(struct jpc5_io){.read=jpc_jc_kernel_read,.write=jpc_jc_kernel_write,.valid=jpc_jc_kernel_valid,
 .consume=jpc_jc_kernel_consume,.capture_uid=jpc_jc_kernel_capture_uid,.now=jpc_jc_kernel_now,.sleep=jpc_jc_kernel_sleep,.ctx=k,.original_deadline=jpc_chain_owner.deadline};
 ret=jpc_jc_kernel_root_blocked(k);if(ret)goto fail;
 if(!lane){
  bool terminal=false;
  /* Read-only first-parent survey. No arbitrary lane/old route assumption. */
  k->edge.io=&k->io;k->edge.parent=*seed;k->surveying=true;
  struct jpc5_bootstrap_pins parentpin={.uid=seed->uid};
  struct jpc5_uid_io parentuid={.pins=&parentpin};
  ret=jpc5_uid_drom_validate_expected(seed->drom,seed->drom_size,&parentuid);
  if(!ret)ret=jpc5_pairs_parse(seed->drom,seed->drom_size,23,&k->edge.parent.pairs);
  if(!ret)ret=jpc5_inventory(&k->edge,0);
  if(!ret){ret=jpc5_select_live_primary(&k->edge,&lane);terminal=ret==-ENOLINK&&k->edge.survey_terminal;}
  k->surveying=false;
  /* Only an entirely read-only survey can declare end of chain. A timeout
   * or ENOLINK after unlock/configuration remains a failed consumed attempt. */
  if(terminal){
   if(!jpc_jc_kernel_valid(k)){ret=-ETIMEDOUT;goto fail;}
   return 1;
  }
  if(ret)goto fail;
  /* Last slot is terminal observation only. Never unlock a fourth edge. */
  if(jpc_chain_owner.count>JPC5_MAX_EDGES){ret=-E2BIG;goto fail;}
  k->lane=lane;
 }
 ret=jpc5_chain_once(&k->io,seed,lane,&k->edge);
 dev_info(a->dev,"j314s-chain candidate route%llx UID%016llx phase%u status%d ready%u ops%u; no PCIe tunnel or GPU access\n",
 k->edge.child.route,k->edge.child.uid,k->edge.phase,ret,k->edge.complete,k->io.operations);
 if(k->edge.child.identity)
  dev_info(a->dev,"j314s-chain observed parent%llx primary%u peer%u PCIeDOWN%u child-header %*phN\n",
   k->edge.parent.route,k->edge.lane,k->edge.peer,k->edge.pins.down,20,k->edge.child.header);
 if(k->edge.child.drom_size)
  dev_info(a->dev,"j314s-chain validated DROM %*phN\n",k->edge.child.drom_size,k->edge.child.drom);
 for(unsigned j=1;j<=23;j++)if(k->edge.child.read[j])
  dev_info(a->dev,"j314s-chain child route%llx port%u header %*phN\n",k->edge.child.route,j,32,k->edge.child.ports[j]);
 if(ret)goto fail;
 return 0;
fail:jpc_chain_owner.failed=true;return ret;
}
