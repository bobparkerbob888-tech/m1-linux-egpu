/* Include after chain-tunnels. Dormant until explicit integration calls seal.
 * No writes, no host/DMA policy changes, no replay, no lifetime extension. */
#include "apple-jpc-tunnel-report.h"
static struct {
 bool consumed,sealed,failed;
 typeof(jpc_provider_owner)*ticket;
 struct task_struct*task;
 struct apple_jpc_tunnel_report report;
} jpc_jct_receipts[3];
#define jpc_jct_receipt jpc_jct_receipts[jpc_boot_peer_controller()]
static bool jpc_jct_proof_owner(void)
{
 typeof(jpc_provider_owner)*t=&jpc_provider_owner;
 return jpc_jct_receipt.consumed&&jpc_jct_receipt.sealed&&!jpc_jct_receipt.failed&&
  jpc_jct_receipt.ticket==t&&jpc_jct_receipt.task==current&&jpc_jct_context.task==current&&
  jpc_jct_context.ticket==t&&jpc_jct_context.consumed&&!jpc_jct_context.failed&&
  jpc_jct_context.deadline==t->deadline&&jpc_jct_receipt.report.original_deadline==t->deadline&&
  t->complete&&t->phase==4&&!t->status&&jpc_provider_frozen_valid()&&
  jpc_chain_owner.first==t->bootstrap&&jpc_chain_owner.a==t->a&&jpc_chain_owner.deadline==t->deadline&&
  !jpc_chain_owner.failed&&jpc_jct_inventory_matches(jpc_jct_context.count)&&
  jpc_jct_receipt.report.count==jpc_jct_context.count+1;
}
/* Pure active-owner admission for host lifecycle callers. No ACIO locks,
 * transport, mutation or callback into host. Historical receipt is not enough:
 * the original synchronous provider actor and deadline must still be live. */
int jpc_apple_cio_j314s_chain_owner_validate(void*,const void*,unsigned,u64,unsigned);
int jpc_apple_cio_j314s_chain_owner_validate(void*owner,const void*ticket,unsigned port,u64 deadline,unsigned gpu_count)
{
 typeof(jpc_provider_owner)*t=&jpc_provider_owner;
 if(!gpu_count)gpu_count=jpc_jct_receipt.report.count;
 if(owner!=t->a||ticket!=t||port!=3||port!=t->down||deadline!=t->deadline||
    (!gpu_count||gpu_count>5)||!jpc_jct_proof_owner()||
    jpc_jct_context.count!=gpu_count-1||jpc_jct_receipt.report.count!=gpu_count||
    jpc_jct_receipt.report.status||!jpc_jct_receipt.report.audits||
    jpc_jct_receipt.report.last_verified_ns>=deadline)return -EPERM;
#ifndef JCT_LINEAR_INVENTORY
 /* A one-edge observation lacks a terminal survey for multiGPU admission. */
 return -EPERM;
#else
 for(unsigned j=0;j<jpc_jct_context.count;j++){
  struct jpc_jct_owner*c=jpc_jct_context.edges[j];
  const struct apple_jpc_tunnel_path*p=&jpc_jct_receipt.report.paths[j+1];
  if(!c||!c->complete||c->status||c->captured!=jpc_chain_owner.edges[j]||
     c->captured->io.original_deadline!=deadline||!c->captured->edge.complete||
     !c->captured->edge.child.ready||c->path.phase!=5||c->path.pe!=3||
     c->path.programmed!=4||p->status||p->phase!=5||p->pe!=3||p->programmed!=4||
     p->route[0]!=c->captured->edge.parent.route||p->route[1]!=c->captured->edge.child.route||
     p->uid[0]!=c->captured->edge.parent.uid||p->uid[1]!=c->captured->edge.child.uid)
   return -EPERM;
 }
 return jpc_jct_proof_owner()?0:-EPERM;
#endif
}
EXPORT_SYMBOL_GPL(jpc_apple_cio_j314s_chain_owner_validate);
int jpc_apple_cio_j314s_chain_proof_after(void*,const void*,unsigned,u64,unsigned,u64);
int jpc_apple_cio_j314s_chain_proof_after(void*owner,const void*ticket,unsigned port,u64 deadline,unsigned count,u64 after_ns)
{
 int ret=jpc_apple_cio_j314s_chain_owner_validate(owner,ticket,port,deadline,count);
 if(ret)return ret;
 return after_ns&&after_ns>=jpc_jct_receipt.report.sealed_ns&&after_ns<deadline&&
  jpc_jct_receipt.report.last_verified_ns>after_ns?0:-ESTALE;
}
EXPORT_SYMBOL_GPL(jpc_apple_cio_j314s_chain_proof_after);

/* The only transport primitive in this include is a read. Its callsites use
 * sealed receipt fields only, never caller-selected addresses or sizes. */
static int jpc_jct_proof_read(u64 route,unsigned port,unsigned space,unsigned off,unsigned n,u32*v)
{
 typeof(jpc_provider_owner)*t=&jpc_provider_owner;int ret;
 if(!jpc_jct_proof_owner()||jpc_jct_receipt.report.read_operations>=32768)return -EPERM;
 ++jpc_jct_receipt.report.read_operations;
 ret=tb_cfg_read(t->tb->ctl,v,route,port,space,off,n);
 if(!jpc_jct_proof_owner())return -ETIMEDOUT;
 return ret;
}
static int jpc_jct_proof_path(const struct apple_jpc_tunnel_path*p,unsigned index)
{
 u32 v[5];int ret;
 if(p->status||p->phase!=5||p->pe!=3||p->programmed!=4)return -EPERM;
 for(unsigned side=0;side<2;side++){
  ret=jpc_jct_proof_read(p->route[side],0,TB_CFG_SWITCH,0,5,v);if(ret)return ret;
  if(memcmp(v,p->header[side],sizeof(v)))return -ESTALE;
  /* Root UID is not an enclosure UID; root identity uses pinned full header. */
  if(index||side){
   ret=jpc_jct_proof_read(p->route[side],0,TB_CFG_SWITCH,7,2,v);if(ret)return ret;
   if((((u64)v[0]<<32)|v[1])!=p->uid[side])return -ESTALE;
  }
  ret=jpc_jct_proof_read(p->route[side],p->adapter[side],TB_CFG_PORT,p->pcie[side],1,v);if(ret)return ret;
  if(((v[0]>>8)&255)!=4||!(v[0]&(1U<<31)))return -ESTALE;
  if(index||side){
   ret=jpc_jct_proof_read(p->route[side],0,TB_CFG_SWITCH,6,1,v);if(ret)return ret;
   if((v[0]&(3U<<24))!=(3U<<24))return -ESTALE;
  }
 }
 for(unsigned j=0;j<4;j++){
  const struct apple_jpc_tunnel_hop*h=&p->hops[j];
  if(h->side>1)return -EPERM;
  ret=jpc_jct_proof_read(p->route[h->side],h->port,TB_CFG_HOPS,h->id*2,2,v);if(ret)return ret;
  if(v[0]!=h->desired[0]||(v[1]&~0x10000000U)!=h->desired[1])return -EIO;
 }
 return 0;
}
int jpc_apple_cio_j314s_tunnel_proof_locked(void*owner,const void*ticket,u64 deadline)
{
 typeof(jpc_provider_owner)*t=&jpc_provider_owner;int ret=0;
 if(owner!=t->a||ticket!=t||deadline!=t->deadline||!jpc_jct_proof_owner())return -EPERM;
 lockdep_assert_held(&jpc_provider_action_lock);
 lockdep_assert_held(&t->c->lock);lockdep_assert_held(&t->tb->lock);
 /* No phase8 host audit here: resource/native phases have their own DMA gates. */
 for(unsigned j=0;j<jpc_jct_receipt.report.count&&!ret;j++)ret=jpc_jct_proof_path(&jpc_jct_receipt.report.paths[j],j);
 if(!ret&&!jpc_jct_proof_owner())ret=-ETIMEDOUT;
 jpc_jct_receipt.report.status=ret;
 if(ret){jpc_jct_receipt.failed=true;jpc_jct_context.failed=true;return ret;}
 ++jpc_jct_receipt.report.audits;
 jpc_jct_receipt.report.last_verified_ns=ktime_get_boottime_ns();
 if(jpc_jct_receipt.report.last_verified_ns>=deadline){
  jpc_jct_receipt.failed=true;jpc_jct_context.failed=true;
  return jpc_jct_receipt.report.status=-ETIMEDOUT;
 }
 return 0;
}
EXPORT_SYMBOL_GPL(jpc_apple_cio_j314s_tunnel_proof_locked);
/* Capture immutable plans only before PCI scanning. Called explicitly by the
 * future reviewed cold caller after all tunnels, never from a getter. */
static int __maybe_unused jpc_apple_j314s_tunnel_seal_locked(void)
{
 typeof(jpc_provider_owner)*t=&jpc_provider_owner;
 struct apple_jpc_tunnel_report*r=&jpc_jct_receipt.report;int ret=-EPERM;
 lockdep_assert_held(&jpc_provider_action_lock);
 lockdep_assert_held(&t->c->lock);lockdep_assert_held(&t->tb->lock);
 if(jpc_jct_receipt.consumed)return -EALREADY;
 jpc_jct_receipt.consumed=true;jpc_jct_receipt.ticket=t;jpc_jct_receipt.task=current;
 r->version=1;r->status=-EINPROGRESS;r->original_deadline=t->deadline;
 if(jpc_jct_context.count>4||jpc_raw_records||jpc_raw_snapshot||
    !jpc_raw_valid(t)||jpc_jct_context.failed)goto fail;
 r->count=jpc_jct_context.count+1;
 for(unsigned j=0;j<r->count;j++){
  struct apple_jpc_tunnel_path*p=&r->paths[j];
  if(!j){
   struct jraw_pt_state*s=jpc_raw_path;
   if(s->phase!=5||s->pe!=3||s->programmed!=4)goto fail;
   p->route[1]=t->route;p->uid[1]=t->bootstrap->pins.uid;
   memcpy(p->header[0],t->bootstrap->pins.root,20);memcpy(p->header[1],t->bootstrap->pins.child_after,20);
   for(unsigned k=0;k<2;k++){
    p->lane[k]=jraw_pt_lane(s,k);p->adapter[k]=jraw_pt_adapter(s,k);p->pcie[k]=s->pcie[k];
    p->credits[k]=s->credits[k];p->existing[k]=s->existing[k];p->control[k]=s->control[k];
   }
   for(unsigned k=0;k<4;k++){
    struct jraw_pt_hop*h=&s->plan[k];
    p->hops[k]=(struct apple_jpc_tunnel_hop){h->route,h->port,h->id,h->out,h->next,{h->before[0],h->before[1]},{h->desired[0],h->desired[1]}};
   }
   p->phase=s->phase;p->pe=s->pe;p->programmed=s->programmed;p->operations=s->ops;
  }else{
   struct jpc_jct_owner*c=jpc_jct_context.edges[j-1];struct jpc5_t_pt_state*s;
   if(!c||!c->complete||c->status||!jpc_jct_valid(c))goto fail;
   s=&c->path;
   if(s->phase!=5||s->pe!=3||s->programmed!=4)goto fail;
   memcpy(p->route,s->wire_route,sizeof(p->route));memcpy(p->header,s->chain_header,sizeof(p->header));
   p->uid[0]=c->captured->edge.parent.uid;p->uid[1]=c->captured->edge.child.uid;
   for(unsigned k=0;k<2;k++){
    p->lane[k]=s->lane[k];p->adapter[k]=s->adapter[k];p->pcie[k]=s->pcie[k];
    p->credits[k]=s->credits[k];p->existing[k]=s->existing[k];p->control[k]=s->control[k];
   }
   for(unsigned k=0;k<4;k++){
    struct jpc5_t_pt_hop*h=&s->plan[k];
    p->hops[k]=(struct apple_jpc_tunnel_hop){h->route,h->port,h->id,h->out,h->next,{h->before[0],h->before[1]},{h->desired[0],h->desired[1]}};
   }
   p->phase=s->phase;p->pe=s->pe;p->programmed=s->programmed;p->operations=s->ops;p->status=c->status;
  }
 }
 r->sealed_ns=ktime_get_boottime_ns();jpc_jct_receipt.sealed=true;
 ret=jpc_apple_cio_j314s_tunnel_proof_locked(t->a,t,t->deadline);if(ret)goto fail;
 return 0;
fail:jpc_jct_receipt.failed=true;jpc_jct_context.failed=true;r->status=ret;return ret;
}
/* Historical getter: no MMIO, no actor/deadline-now test, no mutation, no retry. */
int jpc_apple_cio_j314s_tunnel_state(unsigned controller,u32*flags,int*status,struct apple_jpc_tunnel_report*report);
int jpc_apple_cio_j314s_tunnel_state(unsigned controller,u32*flags,int*status,struct apple_jpc_tunnel_report*report)
{
 typeof(jpc_provider_owner)*t=&jpc_provider_owner;
 if(!flags||!status||!report)return -EINVAL;
 *flags=0;*status=-EINPROGRESS;memset(report,0,sizeof(*report));if(controller<1||controller>2||controller!=jpc_boot_peer_controller())return -EINVAL;
 if(!mutex_trylock(&jpc_provider_action_lock))return -EAGAIN;
 if(jpc_jct_receipt.consumed){*report=jpc_jct_receipt.report;*status=report->status;}
 if(jpc_jct_receipt.sealed)*flags|=1;
 if(jpc_jct_receipt.ticket==t&&jpc_provider_identity_valid())*flags|=2;
 if(jpc_jct_receipt.sealed&&!jpc_jct_context.failed&&!jpc_jct_receipt.failed&&report->count>=1&&report->count<=5)*flags|=4;
 if((*flags&7)==7&&!report->status&&report->audits&&report->sealed_ns<=report->last_verified_ns&&
    report->last_verified_ns<report->original_deadline)*flags|=8;
 mutex_unlock(&jpc_provider_action_lock);return 0;
}
EXPORT_SYMBOL_GPL(jpc_apple_cio_j314s_tunnel_state);
