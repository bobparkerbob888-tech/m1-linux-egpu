/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/apple-j314s-chain-report.h>
#include "apple-j314s-chain.inc"
#include "jc-linear.h"
static bool j314s_chain_inventory;
module_param(j314s_chain_inventory,bool,0444);
MODULE_PARM_DESC(j314s_chain_inventory,"Cold controller0 bounded linear router inventory only; no extra GPU/tunnel admission");
static struct {
 bool consumed,published;int status;
 struct apple_nhi*a;u64 generation;u32 cable;
 struct apple_j314s_chain_report report;
 struct apple_j314s_chain_list_report list;struct jc_linear_io linear;
} jc_inventory_owner;
static bool jc_linear_valid(void*p)
{
 struct apple_nhi*a=p;
 return j314s_next_valid(a)&&j314s_child_bootstrap_proven(a->acio)&&
  !jc_owner.failed&&!a->enum_host&&!a->enum_bound&&
  ktime_get_boottime_ns()<j314s_next_owner.io.deadline;
}
static int jc_linear_prepare(void*p,unsigned index)
{return apple_j314s_chain_prepare_edge(p,index,0);}
static int jc_linear_record(void*p,unsigned index,bool terminal)
{
 struct apple_j314s_chain_list_report*l=&jc_inventory_owner.list;
 struct apple_j314s_chain_report*r;
 struct jc_kernel_edge*k;struct jc_node*n;
 if(index>3||jc_owner.count!=index+1||!(k=jc_owner.edges[index])||
    !jc_linear_valid(p))return -EPERM;
 if(terminal){
  if(!k->edge.survey_terminal||k->consumed||k->io.attempted||k->captured_uid)return -EPERM;
  n=&k->edge.parent;r=&l->tail;l->tail_phy_mask=n->phy_status_valid;
  for(unsigned j=1;j<=23;j++)l->tail_phy[j]=n->phy_status[j];
 }else{
  if(index>=3||!k->edge.complete||!k->edge.child.ready||k->edge.ready.phase!=5)return -EPERM;
  n=&k->edge.child;r=&l->edges[index];
 }
 if(n->drom_size>sizeof(r->drom)||!n->identity||!n->configured||!n->ready)return -EPERM;
 r->parent_route=k->edge.parent.route;r->parent_uid=k->edge.parent.uid;
 r->route=n->route;r->uid=n->uid;r->primary=k->edge.lane;
 r->peer=k->edge.peer;r->pcie_down=k->edge.pins.down;r->pcie_up=n->up;
 memcpy(r->header,n->header,sizeof(r->header));
 for(unsigned j=1;j<=23;j++)if(n->read[j]){
  r->read_mask|=1U<<j;memcpy(r->ports[j],n->ports[j],sizeof(r->ports[j]));
 }
 r->drom_size=n->drom_size;memcpy(r->drom,n->drom,r->drom_size);
 r->operations=k->io.operations;r->original_deadline=jc_owner.deadline;
 r->completed_ns=ktime_get_boottime_ns();
 if(r->completed_ns>=r->original_deadline)return -ETIMEDOUT;
 l->operations+=r->operations;
 if(terminal)l->terminal=1;else l->count++;
 return 0;
}
static int apple_j314s_chain_inventory_once(struct apple_nhi*a)
{
 struct apple_j314s_chain_list_report*l=&jc_inventory_owner.list;int ret;
 lockdep_assert_held(&a->acio->lock);lockdep_assert_held(&a->tb->lock);
 if(!j314s_chain_inventory)return 0;
 if(jc_inventory_owner.consumed)return -EALREADY;
 jc_inventory_owner.consumed=true;jc_inventory_owner.status=-EINPROGRESS;
 jc_inventory_owner.a=a;jc_inventory_owner.generation=a->acio->external_cable_generation;
 jc_inventory_owner.cable=a->acio->root_cable_snapshot;
 jc_inventory_owner.linear=(struct jc_linear_io){.prepare=jc_linear_prepare,.record=jc_linear_record,.valid=jc_linear_valid,.ctx=a};
 ret=jc_linear_once(&jc_inventory_owner.linear);
 if(!ret){
  l->original_deadline=jc_owner.deadline;l->completed_ns=ktime_get_boottime_ns();
  if(!l->terminal||l->count!=jc_inventory_owner.linear.count||l->count>3||
     l->completed_ns>=l->original_deadline)ret=-EPERM;
  else if(l->count)jc_inventory_owner.report=l->edges[0];
 }
 if(ret)jc_owner.failed=true;
 jc_inventory_owner.status=ret;
 smp_store_release(&jc_inventory_owner.published,true);
 return ret;
}
int apple_cio_j314s_chain_state(unsigned controller,u32*flags,int*status,
 struct apple_j314s_chain_report*report)
{
 struct apple_nhi*a;
 if(!flags||!status||!report)return -EINVAL;
 *flags=0;*status=-EINPROGRESS;memset(report,0,sizeof(*report));
 if(controller||!j314s_chain_inventory)return -EOPNOTSUPP;
 if(!smp_load_acquire(&jc_inventory_owner.published))return -EAGAIN;
 a=jc_inventory_owner.a;
 if(!a||!mutex_trylock(&a->acio->lock))return -EAGAIN;
 *flags=1;*status=jc_inventory_owner.status;
 if(!*status){
  if(!jc_inventory_owner.list.count||READ_ONCE(j314s_owned_cio[0])!=a->acio||jc_owner.a!=a||jc_owner.failed||
     READ_ONCE(a->acio->root_stopping)||READ_ONCE(a->acio->root_probe_status)||
     READ_ONCE(a->acio->external_cable_generation)!=jc_inventory_owner.generation||
     READ_ONCE(a->acio->root_cable_snapshot)!=jc_inventory_owner.cable||
     READ_ONCE(a->acio->target_cable_info)!=jc_inventory_owner.cable||
     jc_inventory_owner.report.completed_ns>=jc_inventory_owner.report.original_deadline)
   *status=-ESTALE;
  else {*report=jc_inventory_owner.report;*flags=7;}
 }
 mutex_unlock(&a->acio->lock);return 0;
}
EXPORT_SYMBOL_GPL(apple_cio_j314s_chain_state);

int apple_cio_j314s_chain_list_state(unsigned controller,u32*flags,int*status,
 struct apple_j314s_chain_list_report*report)
{
 struct apple_nhi*a;
 if(!flags||!status||!report)return -EINVAL;
 *flags=0;*status=-EINPROGRESS;memset(report,0,sizeof(*report));
 if(controller||!j314s_chain_inventory)return -EOPNOTSUPP;
 if(!smp_load_acquire(&jc_inventory_owner.published))return -EAGAIN;
 a=jc_inventory_owner.a;
 if(!a||!mutex_trylock(&a->acio->lock))return -EAGAIN;
 *flags=1;*status=jc_inventory_owner.status;
 if(!*status){
  if(!jc_inventory_owner.list.terminal||jc_inventory_owner.list.count>3||READ_ONCE(j314s_owned_cio[0])!=a->acio||jc_owner.a!=a||jc_owner.failed||
     READ_ONCE(a->acio->root_stopping)||READ_ONCE(a->acio->root_probe_status)||
     READ_ONCE(a->acio->external_cable_generation)!=jc_inventory_owner.generation||
     READ_ONCE(a->acio->root_cable_snapshot)!=jc_inventory_owner.cable||
     READ_ONCE(a->acio->target_cable_info)!=jc_inventory_owner.cable||
     jc_inventory_owner.list.completed_ns>=jc_inventory_owner.list.original_deadline)
   *status=-ESTALE;
  else {*report=jc_inventory_owner.list;*flags=15;}
 }
 mutex_unlock(&a->acio->lock);return 0;
}
EXPORT_SYMBOL_GPL(apple_cio_j314s_chain_list_state);
