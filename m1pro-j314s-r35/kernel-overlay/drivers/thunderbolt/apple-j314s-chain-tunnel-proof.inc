/* Include after chain-tunnels. Dormant until explicit integration calls seal.
 * No writes, no host/DMA policy changes, no replay, no lifetime extension. */
#include <linux/apple-j314s-tunnel-report.h>
static struct {
 bool consumed,sealed,failed;
 typeof(j314s_provider_owner)*ticket;
 struct task_struct*task;
 struct apple_j314s_tunnel_report report;
} jct_receipt;
static bool jct_proof_owner(void)
{
 typeof(j314s_provider_owner)*t=&j314s_provider_owner;
 return jct_receipt.consumed&&jct_receipt.sealed&&!jct_receipt.failed&&
  jct_receipt.ticket==t&&jct_receipt.task==current&&jct_context.task==current&&
  jct_context.ticket==t&&jct_context.consumed&&!jct_context.failed&&
  jct_context.deadline==t->deadline&&jct_receipt.report.original_deadline==t->deadline&&
  t->complete&&t->phase==4&&!t->status&&j314s_provider_frozen_valid()&&
  jc_owner.first==t->bootstrap&&jc_owner.a==t->a&&jc_owner.deadline==t->deadline&&
  !jc_owner.failed&&jct_inventory_matches(jct_context.count)&&
  jct_receipt.report.count==jct_context.count+1;
}
/* Pure active-owner admission for host lifecycle callers. No ACIO locks,
 * transport, mutation or callback into host. Historical receipt is not enough:
 * the original synchronous provider actor and deadline must still be live. */
int apple_cio_j314s_chain_owner_validate(void*,const void*,unsigned,u64,unsigned);
int apple_cio_j314s_chain_owner_validate(void*owner,const void*ticket,unsigned port,u64 deadline,unsigned gpu_count)
{
 typeof(j314s_provider_owner)*t=&j314s_provider_owner;
 if(owner!=t->a||ticket!=t||port!=3||port!=t->down||deadline!=t->deadline||
    (gpu_count!=2&&gpu_count!=4)||!jct_proof_owner()||
    jct_context.count!=gpu_count-1||jct_receipt.report.count!=gpu_count||
    jct_receipt.report.status||!jct_receipt.report.audits||
    jct_receipt.report.last_verified_ns>=deadline)return -EPERM;
#ifndef JCT_LINEAR_INVENTORY
 /* A one-edge observation lacks a terminal survey for multiGPU admission. */
 return -EPERM;
#else
 for(unsigned j=0;j<jct_context.count;j++){
  struct jct_owner*c=jct_context.edges[j];
  const struct apple_j314s_tunnel_path*p=&jct_receipt.report.paths[j+1];
  if(!c||!c->complete||c->status||c->captured!=jc_owner.edges[j]||
     c->captured->io.original_deadline!=deadline||!c->captured->edge.complete||
     !c->captured->edge.child.ready||c->path.phase!=5||c->path.pe!=3||
     c->path.programmed!=4||p->status||p->phase!=5||p->pe!=3||p->programmed!=4||
     p->route[0]!=c->captured->edge.parent.route||p->route[1]!=c->captured->edge.child.route||
     p->uid[0]!=c->captured->edge.parent.uid||p->uid[1]!=c->captured->edge.child.uid)
   return -EPERM;
 }
 return jct_proof_owner()?0:-EPERM;
#endif
}
EXPORT_SYMBOL_GPL(apple_cio_j314s_chain_owner_validate);
int apple_cio_j314s_chain_proof_after(void*,const void*,unsigned,u64,unsigned,u64);
int apple_cio_j314s_chain_proof_after(void*owner,const void*ticket,unsigned port,u64 deadline,unsigned count,u64 after_ns)
{
 int ret=apple_cio_j314s_chain_owner_validate(owner,ticket,port,deadline,count);
 if(ret)return ret;
 return after_ns&&after_ns>=jct_receipt.report.sealed_ns&&after_ns<deadline&&
  jct_receipt.report.last_verified_ns>after_ns?0:-ESTALE;
}
EXPORT_SYMBOL_GPL(apple_cio_j314s_chain_proof_after);

/* The only transport primitive in this include is a read. Its callsites use
 * sealed receipt fields only, never caller-selected addresses or sizes. */
static int jct_proof_read(unsigned route,unsigned port,unsigned space,unsigned off,unsigned n,u32*v)
{
 typeof(j314s_provider_owner)*t=&j314s_provider_owner;int ret;
 if(!jct_proof_owner()||jct_receipt.report.read_operations>=32768)return -EPERM;
 ++jct_receipt.report.read_operations;
 ret=tb_cfg_read(t->tb->ctl,v,route,port,space,off,n);
 if(!jct_proof_owner())return -ETIMEDOUT;
 return ret;
}
static int jct_proof_path(const struct apple_j314s_tunnel_path*p,unsigned index)
{
 u32 v[5];int ret;
 if(p->status||p->phase!=5||p->pe!=3||p->programmed!=4)return -EPERM;
 for(unsigned side=0;side<2;side++){
  ret=jct_proof_read(p->route[side],0,TB_CFG_SWITCH,0,5,v);if(ret)return ret;
  if(memcmp(v,p->header[side],sizeof(v)))return -ESTALE;
  /* Root UID is not an enclosure UID; root identity uses pinned full header. */
  if(index||side){
   ret=jct_proof_read(p->route[side],0,TB_CFG_SWITCH,7,2,v);if(ret)return ret;
   if((((u64)v[0]<<32)|v[1])!=p->uid[side])return -ESTALE;
  }
  ret=jct_proof_read(p->route[side],p->adapter[side],TB_CFG_PORT,p->pcie[side],1,v);if(ret)return ret;
  if(((v[0]>>8)&255)!=4||!(v[0]&(1U<<31)))return -ESTALE;
  if(index||side){
   ret=jct_proof_read(p->route[side],0,TB_CFG_SWITCH,6,1,v);if(ret)return ret;
   if((v[0]&(3U<<24))!=(3U<<24))return -ESTALE;
  }
 }
 for(unsigned j=0;j<4;j++){
  const struct apple_j314s_tunnel_hop*h=&p->hops[j];
  if(h->side>1)return -EPERM;
  ret=jct_proof_read(p->route[h->side],h->port,TB_CFG_HOPS,h->id*2,2,v);if(ret)return ret;
  if(v[0]!=h->desired[0]||(v[1]&~0x10000000U)!=h->desired[1])return -EIO;
 }
 return 0;
}
int apple_cio_j314s_tunnel_proof_locked(void*owner,const void*ticket,u64 deadline)
{
 typeof(j314s_provider_owner)*t=&j314s_provider_owner;int ret=0;
 if(owner!=t->a||ticket!=t||deadline!=t->deadline||!jct_proof_owner())return -EPERM;
 lockdep_assert_held(&j314s_provider_action_lock);
 lockdep_assert_held(&t->c->lock);lockdep_assert_held(&t->tb->lock);
 /* No phase8 host audit here: resource/native phases have their own DMA gates. */
 for(unsigned j=0;j<jct_receipt.report.count&&!ret;j++)ret=jct_proof_path(&jct_receipt.report.paths[j],j);
 if(!ret&&!jct_proof_owner())ret=-ETIMEDOUT;
 jct_receipt.report.status=ret;
 if(ret){jct_receipt.failed=true;jct_context.failed=true;return ret;}
 ++jct_receipt.report.audits;
 jct_receipt.report.last_verified_ns=ktime_get_boottime_ns();
 if(jct_receipt.report.last_verified_ns>=deadline){
  jct_receipt.failed=true;jct_context.failed=true;
  return jct_receipt.report.status=-ETIMEDOUT;
 }
 return 0;
}
EXPORT_SYMBOL_GPL(apple_cio_j314s_tunnel_proof_locked);
/* Capture immutable plans only before PCI scanning. Called explicitly by the
 * future reviewed cold caller after all tunnels, never from a getter. */
static int __maybe_unused apple_j314s_tunnel_seal_locked(void)
{
 typeof(j314s_provider_owner)*t=&j314s_provider_owner;
 struct apple_j314s_tunnel_report*r=&jct_receipt.report;int ret=-EPERM;
 lockdep_assert_held(&j314s_provider_action_lock);
 lockdep_assert_held(&t->c->lock);lockdep_assert_held(&t->tb->lock);
 if(jct_receipt.consumed)return -EALREADY;
 jct_receipt.consumed=true;jct_receipt.ticket=t;jct_receipt.task=current;
 r->version=1;r->status=-EINPROGRESS;r->original_deadline=t->deadline;
 if(!jct_context.count||jct_context.count>3||j314s_raw_records||j314s_raw_snapshot||
    !j314s_raw_valid(t)||jct_context.failed)goto fail;
 r->count=jct_context.count+1;
 for(unsigned j=0;j<r->count;j++){
  struct apple_j314s_tunnel_path*p=&r->paths[j];
  if(!j){
   struct jraw_pt_state*s=j314s_raw_path;
   if(s->phase!=5||s->pe!=3||s->programmed!=4)goto fail;
   p->route[1]=t->route;p->uid[1]=t->bootstrap->pins.uid;
   memcpy(p->header[0],t->bootstrap->pins.root,20);memcpy(p->header[1],t->bootstrap->pins.child_after,20);
   for(unsigned k=0;k<2;k++){
    p->lane[k]=jraw_pt_lane(s,k);p->adapter[k]=jraw_pt_adapter(s,k);p->pcie[k]=s->pcie[k];
    p->credits[k]=s->credits[k];p->existing[k]=s->existing[k];p->control[k]=s->control[k];
   }
   for(unsigned k=0;k<4;k++){
    struct jraw_pt_hop*h=&s->plan[k];
    p->hops[k]=(struct apple_j314s_tunnel_hop){h->route,h->port,h->id,h->out,h->next,{h->before[0],h->before[1]},{h->desired[0],h->desired[1]}};
   }
   p->phase=s->phase;p->pe=s->pe;p->programmed=s->programmed;p->operations=s->ops;
  }else{
   struct jct_owner*c=jct_context.edges[j-1];struct jct_pt_state*s;
   if(!c||!c->complete||c->status||!jct_valid(c))goto fail;
   s=&c->path;
   if(s->phase!=5||s->pe!=3||s->programmed!=4)goto fail;
   memcpy(p->route,s->wire_route,sizeof(p->route));memcpy(p->header,s->chain_header,sizeof(p->header));
   p->uid[0]=c->captured->edge.parent.uid;p->uid[1]=c->captured->edge.child.uid;
   for(unsigned k=0;k<2;k++){
    p->lane[k]=s->lane[k];p->adapter[k]=s->adapter[k];p->pcie[k]=s->pcie[k];
    p->credits[k]=s->credits[k];p->existing[k]=s->existing[k];p->control[k]=s->control[k];
   }
   for(unsigned k=0;k<4;k++){
    struct jct_pt_hop*h=&s->plan[k];
    p->hops[k]=(struct apple_j314s_tunnel_hop){h->route,h->port,h->id,h->out,h->next,{h->before[0],h->before[1]},{h->desired[0],h->desired[1]}};
   }
   p->phase=s->phase;p->pe=s->pe;p->programmed=s->programmed;p->operations=s->ops;p->status=c->status;
  }
 }
 r->sealed_ns=ktime_get_boottime_ns();jct_receipt.sealed=true;
 ret=apple_cio_j314s_tunnel_proof_locked(t->a,t,t->deadline);if(ret)goto fail;
 return 0;
fail:jct_receipt.failed=true;jct_context.failed=true;r->status=ret;return ret;
}
/* Historical getter: no MMIO, no actor/deadline-now test, no mutation, no retry. */
int apple_cio_j314s_tunnel_state(unsigned controller,u32*flags,int*status,struct apple_j314s_tunnel_report*report)
{
 typeof(j314s_provider_owner)*t=&j314s_provider_owner;
 if(!flags||!status||!report)return -EINVAL;
 *flags=0;*status=-EINPROGRESS;memset(report,0,sizeof(*report));if(controller)return -EINVAL;
 if(!mutex_trylock(&j314s_provider_action_lock))return -EAGAIN;
 if(jct_receipt.consumed){*report=jct_receipt.report;*status=report->status;}
 if(jct_receipt.sealed)*flags|=1;
 if(jct_receipt.ticket==t&&j314s_provider_identity_valid())*flags|=2;
 if(jct_receipt.sealed&&!jct_context.failed&&!jct_receipt.failed&&report->count>=2&&report->count<=4)*flags|=4;
 if((*flags&7)==7&&!report->status&&report->audits&&report->sealed_ns<=report->last_verified_ns&&
    report->last_verified_ns<report->original_deadline)*flags|=8;
 mutex_unlock(&j314s_provider_action_lock);return 0;
}
EXPORT_SYMBOL_GPL(apple_cio_j314s_tunnel_state);
