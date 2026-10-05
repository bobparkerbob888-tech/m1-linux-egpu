#include <linux/apple-jmx-native-report.h>
extern int apple_apciec_jpc_bind_native_once(struct device*,unsigned,const void*,const struct apple_jpc_native_policy*);
/* This metadata proof never locks ACIO/TB or performs transport under host locks. */
int apple_cio_jpc_native_policy_validate(void*,const void*,unsigned,u64,const struct apple_jpc_native_policy*,
 const struct apple_dart_j314s_sample*,unsigned,u64);
int apple_cio_jpc_native_policy_validate(void*owner,const void*ticket,unsigned port,u64 deadline,
 const struct apple_jpc_native_policy*policy,const struct apple_dart_j314s_sample*sample,unsigned aic_base,u64 after)
{
 typeof(jpc_provider_owner)*t=&jpc_provider_owner;
 typeof(jpc_native_requests[0])*n;
 struct j314s_peer_capture_owner*peer;unsigned displays=0,desktop=0;u8 evidence=0;
 if(t->controller<1||t->controller>2)return -EPERM;
 n=&jpc_native_requests[t->controller];
 if(!j314s_combined_boot_mask(saved_command_line)||
    !n->consumed||n->failed||n->task!=current||n->complete||!policy||
    memcmp(policy,&n->policy,sizeof(*policy))||owner!=t->a||ticket!=t||port!=t->down||
    deadline!=t->deadline||!jpc_provider_frozen_valid()||!jpc_jct_proof_owner()||
    policy->version!=1||policy->reserved||policy->controller!=t->controller||policy->count!=5||
    policy->router_count!=jpc_jct_receipt.report.count||!policy->router_count||policy->router_count>5||
    !jpc_raw_records||!jpc_raw_record_count||jpc_raw_record_count>64)return -EPERM;
 peer=j314s_peer_slot(t->a);if(!peer||!peer->lease.complete||peer->lease.failed||
    memcmp(policy->root_uid,peer->root_uid,sizeof(policy->root_uid)))return -ESTALE;
 for(unsigned j=0;j<sizeof(policy->evidence_sha256);j++)evidence|=policy->evidence_sha256[j];
 if(!evidence)return -EPERM;
 for(unsigned j=0;j<policy->router_count;j++){
  const struct apple_jpc_tunnel_path*p=&jpc_jct_receipt.report.paths[j];
  if(policy->route[j]!=p->route[1]||policy->router_uid[j]!=p->uid[1]||!p->uid[1]||
     p->status||p->phase!=5||p->pe!=3||p->programmed!=4)return -ESTALE;
 }
 for(unsigned j=0;j<jpc_raw_record_count;j++){
  const struct ep_identity*x=&jpc_raw_records[j];unsigned k;
  if((x->class_rev>>24)!=3)continue;
  for(k=0;k<policy->count;k++)if(policy->clients[k].rid==x->rid)break;
  if(k==policy->count)return -EPERM;
  const struct apple_jpc_native_identity*y=&policy->clients[k];
  if(x->id!=y->id||x->class_rev!=y->class_rev||x->subsystem!=y->subsystem||
     x->header!=y->header||x->serial!=y->serial||!x->serial||x->serial==~0ULL)return -ESTALE;
  displays++;
 }
 if(displays!=policy->count)return -EPERM;
 for(unsigned j=0;j<policy->count;j++){
  const struct apple_jpc_native_identity*x=&policy->clients[j];
  u32 expected=x->model==1?0x2d0410de:x->model==2?0x2c0210de:x->model==3?0x2c1810de:0;
  if(!expected||x->id!=expected||!x->rid||x->rid>65535||(x->rid&7)||
     (x->class_rev>>16)!=0x0300||x->header>255||(x->header&127)||
     (j&&policy->clients[j-1].rid>=x->rid))return -EPERM;
  if(x->model==2)desktop|=BIT(j);
  for(unsigned k=0;k<j;k++)if(policy->clients[k].serial==x->serial)return -EPERM;
 }
 if(policy->desktop_review_mask!=desktop)return -EPERM;
 if(sample&&(memcmp(sample,&t->sample,sizeof(*sample))||!jpc_provider_sample_valid(sample)||
    aic_base!=(t->controller==1?0x66e:0x68e)))return -ESTALE;
 if(!sample&&aic_base)return -EPERM;
 if(after&&(!sample||after>=deadline||jpc_jct_receipt.report.last_verified_ns<=after))return -ESTALE;
 return jpc_provider_frozen_valid()?0:-EPERM;
}
EXPORT_SYMBOL_GPL(apple_cio_jpc_native_policy_validate);
static int jpc_native_live_proof(void)
{
 typeof(jpc_provider_owner)*t=&jpc_provider_owner;int ret;
 mutex_lock(&t->c->lock);mutex_lock(&t->tb->lock);
 ret=jpc_apple_cio_j314s_tunnel_proof_locked(t->a,t,t->deadline);
 mutex_unlock(&t->tb->lock);mutex_unlock(&t->c->lock);return ret;
}
static int jpc_native_continue(void)
{
 typeof(jpc_provider_owner)*t=&jpc_provider_owner;typeof(jpc_native_requests[0])*n=&jpc_native_requests[t->controller];
 const struct j314s_multi_resource_owner*capture=NULL;unsigned phase=0;u64 after;int ret,post;
 lockdep_assert_held(&jpc_provider_action_lock);
 if(n->phase||!n->consumed||n->failed||n->task!=current)return -EPERM;
 n->phase=10;
 ret=jpc_native_live_proof();if(ret)goto fail;
 ret=apple_cio_jpc_native_policy_validate(t->a,t,t->down,t->deadline,&n->policy,NULL,0,0);if(ret)goto fail;
 ret=apple_apciec_jpc_bind_native_once(t->host,t->down,t,&n->policy);if(ret)goto fail;
 ret=apple_apciec_j314s_capture_multiple(t->host,t->down,t,n->policy.count,&capture,&phase);
 post=jpc_native_live_proof();if(!ret)ret=post;if(ret)goto fail;
 if(!capture||phase!=12){ret=-EPERM;goto fail;}n->phase=12;
 ret=apple_apciec_j314s_assign_multi(t->host,t->down,t,n->policy.count,&phase);
 post=jpc_native_live_proof();if(!ret)ret=post;if(ret)goto fail;
 if(phase!=14){ret=-EPERM;goto fail;}n->phase=14;
 ret=apple_apciec_j314s_native_prepare_multi(t->host,t->down,t,n->policy.count,&phase);
 if(ret)goto fail;
 if(phase!=39){ret=-EPERM;goto fail;}n->phase=39;
 after=ktime_get_boottime_ns();ret=jpc_native_live_proof();if(ret)goto fail;
 ret=apple_cio_jpc_native_policy_validate(t->a,t,t->down,t->deadline,&n->policy,&t->sample,t->controller==1?0x66e:0x68e,after);
 if(ret)goto fail;
 ret=apple_apciec_j314s_native_publish_multi(t->host,t->down,t,n->policy.count,&phase);
 post=jpc_native_live_proof();if(!ret)ret=post;if(ret)goto fail;
 if(phase!=40){ret=-EPERM;goto fail;}n->phase=40;n->completed_ns=ktime_get_boottime_ns();
 if(n->completed_ns>=t->deadline){ret=-ETIMEDOUT;goto fail;}
 n->complete=true;n->status=0;return 0;
 fail:n->failed=true;n->status=ret;return ret;
}
int apple_cio_jpc_prepare_native_once(unsigned controller,const struct apple_jpc_native_policy*policy)
{
 typeof(jpc_native_requests[0])*n;u32 flags=0;int status=-EINPROGRESS,ret;
 if(controller<1||controller>2||controller!=jpc_boot_peer_controller()||
    !j314s_combined_boot_mask(saved_command_line)||!policy)return -EINVAL;
 n=&jpc_native_requests[controller];mutex_lock(&jpc_native_action_lock);
 if(n->consumed){ret=-EALREADY;goto out;}
 n->consumed=true;n->task=current;n->status=-EINPROGRESS;n->policy=*policy;
 if(policy->version!=1||policy->reserved||policy->controller!=controller||policy->count!=5){ret=-EPERM;goto fail;}
 if(!jpc_chain_action_consumed[controller])ret=apple_cio_jpc_prepare_chain_once(controller);
 else ret=jpc_next_owner.actor==current?0:-EPERM;
 if(ret)goto fail;
 ret=apple_cio_jpc_inventory_state(controller,&flags,&status);
 if(ret||flags!=511||status){ret=ret?ret:-EPERM;goto fail;}
 ret=apple_cio_jpc_prepare_provider_once(controller);
 if(ret)goto fail;
 if(!n->complete||n->phase!=40||n->status){ret=-EPERM;goto fail;}
 goto out;
 fail:n->failed=true;n->status=ret;
 out:mutex_unlock(&jpc_native_action_lock);return ret;
}
EXPORT_SYMBOL_GPL(apple_cio_jpc_prepare_native_once);
int apple_cio_jpc_native_state(unsigned controller,u32*flags,int*status,struct apple_jmx_native_report*r)
{
 typeof(jpc_provider_owner)*t=&jpc_provider_owner;typeof(jpc_native_requests[0])*n;int ret=0;
 if(!flags||!status||!r||controller<1||controller>2||controller!=jpc_boot_peer_controller())return -EINVAL;
 *flags=0;*status=-EINPROGRESS;memset(r,0,sizeof(*r));n=&jpc_native_requests[controller];
 if(!mutex_trylock(&jpc_native_action_lock))return -EAGAIN;
 if(!mutex_trylock(&jpc_provider_action_lock)){mutex_unlock(&jpc_native_action_lock);return -EAGAIN;}
 if(!n->consumed||n->failed||!n->complete||n->status||n->phase!=40||!n->completed_ns||n->completed_ns>=t->deadline||
    t->failed||!t->complete||t->status||!jpc_raw_complete||jpc_raw_status||!jpc_provider_identity_valid()){
  *status=n->status?n->status:t->status?t->status:-EPERM;goto out;
 }
 ret=apple_apciec_jmx_native_state(t->host,flags,status,r);
 if(!ret&&!*status&&(r->controller!=controller||r->count!=n->policy.count||r->phase!=40||
    r->original_deadline!=t->deadline||!r->completed_ns||r->completed_ns>n->completed_ns)){
  *flags=0;*status=-ESTALE;memset(r,0,sizeof(*r));
 }
 out:mutex_unlock(&jpc_provider_action_lock);mutex_unlock(&jpc_native_action_lock);return ret;
}
EXPORT_SYMBOL_GPL(apple_cio_jpc_native_state);
