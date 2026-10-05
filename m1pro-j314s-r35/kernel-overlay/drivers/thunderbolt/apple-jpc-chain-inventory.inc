/* SPDX-License-Identifier: GPL-2.0 */
#include "apple-jpc-chain-report.h"
#include "apple-jpc-chain.inc"
#include "jpc5-linear.h"
static const bool jpc_chain_inventory=true;
static struct {
 bool consumed,published;int status;
 struct apple_nhi*a;u64 generation;u32 cable;
 struct apple_jpc_chain_report report;
 struct apple_jpc_chain_list_report list;struct jpc5_linear_io linear;
} jpc_inventory_owners[3];
#define jpc_inventory_owner jpc_inventory_owners[jpc_boot_peer_controller()]
static bool jpc_jc_linear_valid(void*p)
{
 struct apple_nhi*a=p;
 return jpc_next_valid(a)&&jpc_bootstrap_proven(a->acio)&&
  !jpc_chain_owner.failed&&!a->enum_host&&!a->enum_bound&&
  ktime_get_boottime_ns()<jpc_next_owner.io.deadline;
}
static int jpc_jc_linear_prepare(void*p,unsigned index)
{return jpc_apple_j314s_chain_prepare_edge(p,index,0);}
static int jpc_jc_linear_record(void*p,unsigned index,bool terminal)
{
 struct apple_jpc_chain_list_report*l=&jpc_inventory_owner.list;
 struct apple_jpc_chain_report*r;
 struct jpc_kernel_edge*k;struct jpc5_node*n;
 if(index>4||jpc_chain_owner.count!=index+1||!(k=jpc_chain_owner.edges[index])||
    !jpc_jc_linear_valid(p))return -EPERM;
 if(terminal){
  if(!k->edge.survey_terminal||k->consumed||k->io.attempted||k->captured_uid)return -EPERM;
  n=&k->edge.parent;r=&l->tail;l->tail_phy_mask=n->phy_status_valid;
  for(unsigned j=1;j<=23;j++)l->tail_phy[j]=n->phy_status[j];
 }else{
  if(index>=4||!k->edge.complete||!k->edge.child.ready||k->edge.ready.phase!=5)return -EPERM;
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
 r->operations=k->io.operations;r->original_deadline=jpc_chain_owner.deadline;
 r->completed_ns=ktime_get_boottime_ns();
 if(r->completed_ns>=r->original_deadline)return -ETIMEDOUT;
 l->operations+=r->operations;
 if(terminal)l->terminal=1;else l->count++;
 return 0;
}
static int jpc_apple_j314s_chain_inventory_once(struct apple_nhi*a)
{
 struct apple_jpc_chain_list_report*l=&jpc_inventory_owner.list;int ret;
 lockdep_assert_held(&a->acio->lock);lockdep_assert_held(&a->tb->lock);
 if(!jpc_chain_inventory)return 0;
 if(jpc_inventory_owner.consumed)return -EALREADY;
 jpc_inventory_owner.consumed=true;jpc_inventory_owner.status=-EINPROGRESS;
 jpc_inventory_owner.a=a;jpc_inventory_owner.generation=a->acio->external_cable_generation;
 jpc_inventory_owner.cable=a->acio->root_cable_snapshot;
 jpc_inventory_owner.linear=(struct jpc5_linear_io){.prepare=jpc_jc_linear_prepare,.record=jpc_jc_linear_record,.valid=jpc_jc_linear_valid,.ctx=a};
 ret=jpc5_linear_once(&jpc_inventory_owner.linear);
 if(!ret){
  l->original_deadline=jpc_chain_owner.deadline;l->completed_ns=ktime_get_boottime_ns();
  if(!l->terminal||l->count!=jpc_inventory_owner.linear.count||l->count>4||
     l->completed_ns>=l->original_deadline)ret=-EPERM;
  else if(l->count)jpc_inventory_owner.report=l->edges[0];
 }
 if(ret)jpc_chain_owner.failed=true;
 jpc_inventory_owner.status=ret;
 smp_store_release(&jpc_inventory_owner.published,true);
 return ret;
}
int jpc_apple_cio_j314s_chain_state(unsigned controller,u32*flags,int*status,
 struct apple_jpc_chain_report*report);
int jpc_apple_cio_j314s_chain_state(unsigned controller,u32*flags,int*status,
 struct apple_jpc_chain_report*report)
{
 struct apple_nhi*a;
 if(!flags||!status||!report)return -EINVAL;
 *flags=0;*status=-EINPROGRESS;memset(report,0,sizeof(*report));
 if(controller<1||controller>2||controller!=jpc_boot_peer_controller()||!jpc_chain_inventory)return -EOPNOTSUPP;
 if(!smp_load_acquire(&jpc_inventory_owner.published))return -EAGAIN;
 a=jpc_inventory_owner.a;
 if(!a||!mutex_trylock(&a->acio->lock))return -EAGAIN;
 *flags=1;*status=jpc_inventory_owner.status;
 if(!*status){
  if(!jpc_inventory_owner.list.count||READ_ONCE(j314s_owned_cio[controller])!=a->acio||jpc_chain_owner.a!=a||jpc_chain_owner.failed||
     READ_ONCE(a->acio->root_stopping)||READ_ONCE(a->acio->root_probe_status)||
     READ_ONCE(a->acio->external_cable_generation)!=jpc_inventory_owner.generation||
     READ_ONCE(a->acio->root_cable_snapshot)!=jpc_inventory_owner.cable||
     READ_ONCE(a->acio->target_cable_info)!=jpc_inventory_owner.cable||
     jpc_inventory_owner.report.completed_ns>=jpc_inventory_owner.report.original_deadline)
   *status=-ESTALE;
  else {*report=jpc_inventory_owner.report;*flags=7;}
 }
 mutex_unlock(&a->acio->lock);return 0;
}
EXPORT_SYMBOL_GPL(jpc_apple_cio_j314s_chain_state);

int jpc_apple_cio_j314s_chain_list_state(unsigned controller,u32*flags,int*status,
 struct apple_jpc_chain_list_report*report);
int jpc_apple_cio_j314s_chain_list_state(unsigned controller,u32*flags,int*status,
 struct apple_jpc_chain_list_report*report)
{
 struct apple_nhi*a;
 if(!flags||!status||!report)return -EINVAL;
 *flags=0;*status=-EINPROGRESS;memset(report,0,sizeof(*report));
 if(controller<1||controller>2||controller!=jpc_boot_peer_controller()||!jpc_chain_inventory)return -EOPNOTSUPP;
 if(!smp_load_acquire(&jpc_inventory_owner.published))return -EAGAIN;
 a=jpc_inventory_owner.a;
 if(!a||!mutex_trylock(&a->acio->lock))return -EAGAIN;
 *flags=1;*status=jpc_inventory_owner.status;
 if(!*status){
  if(!jpc_inventory_owner.list.terminal||jpc_inventory_owner.list.count>4||READ_ONCE(j314s_owned_cio[controller])!=a->acio||jpc_chain_owner.a!=a||jpc_chain_owner.failed||
     READ_ONCE(a->acio->root_stopping)||READ_ONCE(a->acio->root_probe_status)||
     READ_ONCE(a->acio->external_cable_generation)!=jpc_inventory_owner.generation||
     READ_ONCE(a->acio->root_cable_snapshot)!=jpc_inventory_owner.cable||
     READ_ONCE(a->acio->target_cable_info)!=jpc_inventory_owner.cable||
     jpc_inventory_owner.list.completed_ns>=jpc_inventory_owner.list.original_deadline)
   *status=-ESTALE;
  else {*report=jpc_inventory_owner.list;*flags=15;}
 }
 mutex_unlock(&a->acio->lock);return 0;
}
EXPORT_SYMBOL_GPL(jpc_apple_cio_j314s_chain_list_state);
