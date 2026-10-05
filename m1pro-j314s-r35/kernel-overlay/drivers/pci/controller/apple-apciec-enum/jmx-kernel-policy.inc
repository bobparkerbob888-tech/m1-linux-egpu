extern int apple_cio_j314s_chain_owner_validate(void*,const void*,unsigned,u64,unsigned);
extern int apple_cio_j314s_chain_proof_after(void*,const void*,unsigned,u64,unsigned,u64);
#include "jmx-resource.inc"
/* No caller in this candidate. Future exact peer supplier must provide a
 * metadata-only proof of its same-boot root/route/UID and fault-review policy.
 * A user/model request is not an implementation of this callback. */
struct jmx_kernel_policy {
 struct jmx_policy policy;
 const void*ticket;struct task_struct*actor;u64 deadline;
 const struct ep_identity*raw;unsigned raw_count;
 int (*proof)(void*,const void*,unsigned,u64,const struct jmx_policy*);
 void*owner;bool frozen;
 int (*native_proof)(void*,const void*,unsigned,u64,const struct jmx_policy*,
  const struct apple_dart_j314s_sample*,unsigned,u64);
 struct apple_dart_j314s_sample native_sample;
 unsigned native_aic_base;bool native_attempted,native_frozen;
 unsigned capture_limit;bool capture_budget_frozen;
};
static const struct jmx_kernel_policy*jmx_binding(struct apple_apciec*p,bool historical)
{
 const struct jmx_kernel_policy*b=p?p->j314s_mixed_policy:NULL;
 if(!b||!b->frozen||!jmx_policy_valid(&b->policy)||!p->profile||
    !apciec_profile_j314s(p->profile)||p->profile->index!=b->policy.controller||
    b->ticket!=p->retained_ticket||!b->ticket||!b->proof||!b->owner||
    b->deadline!=p->retained_identity_deadline||b->deadline!=p->j314s_provider_deadline||
    b->raw!=p->retained_records||b->raw_count!=p->retained_record_count||
    !p->retained_raw_identity||!p->j314s_raw_capability||p->retained_failed)return NULL;
 if(!historical&&(b->actor!=current||ktime_get_boottime_ns()>=b->deadline||
    b->proof(b->owner,b->ticket,b->policy.controller,b->deadline,&b->policy)))return NULL;
 return b;
}
static bool jmx_host_capture(struct apple_apciec*p,unsigned g,
 const struct ep_snapshot*s,const struct ep_identity*id)
{
 const struct jmx_kernel_policy*b=jmx_binding(p,false);
 return b&&jmx_capture_schema(&b->policy,g,s,id);
}
static int __maybe_unused jmx_bind_raw_once(struct apple_apciec*p,const void*ticket,
 const struct jmx_policy*policy,
 int(*proof)(void*,const void*,unsigned,u64,const struct jmx_policy*),void*owner,
 int(*native_proof)(void*,const void*,unsigned,u64,const struct jmx_policy*,
  const struct apple_dart_j314s_sample*,unsigned,u64))
{
 struct jmx_kernel_policy*b;unsigned indices[JM_MAX_GPUS];int ret;
 lockdep_assert_held(&p->lifecycle);
 if(p->j314s_mixed_policy||!policy||!proof||!owner||!native_proof||!jmx_policy_valid(policy)||
    !p->profile||p->profile->index!=policy->controller||!apciec_profile_j314s(p->profile)||
    !ticket||ticket!=p->retained_ticket||p->retained_phase!=10||p->retained_failed||
    p->retained_scan_task||p->j314s_multi_resource||p->j314s_resource||
    !p->retained_raw_identity||!p->j314s_raw_capability||
    !p->retained_identity_deadline||p->retained_identity_deadline!=p->j314s_provider_deadline||
    ktime_get_boottime_ns()>=p->retained_identity_deadline)return -EPERM;
 b=kvzalloc(sizeof(*b),GFP_KERNEL);if(!b)return -ENOMEM;
 p->j314s_mixed_policy=b; /* Failed binding is retained and cannot be replayed. */
 b->policy=*policy;b->ticket=ticket;b->actor=current;b->deadline=p->retained_identity_deadline;
 b->raw=p->retained_records;b->raw_count=p->retained_record_count;b->proof=proof;b->owner=owner;b->native_proof=native_proof;
 ret=proof(owner,ticket,policy->controller,b->deadline,policy);
 if(!ret)ret=jmx_raw_selection(policy,b->raw,b->raw_count,indices);
 if(ret||ktime_get_boottime_ns()>=b->deadline)return ret?ret:-ETIMEDOUT;
 b->frozen=true;
 /* A pre-existing C0 budget is immutable. Peer raw-only scans arrive with
  * zero cumulative metadata; this creates a new capture allowance, retaining
  * spent operations and the original provider deadline, never renewing it. */
 if(p->j314s_scan_expected||p->j314s_scan_limit||p->j314s_scan_ticket||
    p->j314s_scan_actor||p->j314s_scan_original_deadline){
  unsigned limit=policy->count==1?16384:policy->count==2?32768:65536;
  if(p->j314s_scan_expected!=policy->count||p->j314s_scan_limit!=limit||
     p->j314s_scan_ticket!=ticket||p->j314s_scan_actor!=current||
     p->j314s_scan_original_deadline!=b->deadline||p->retained_scan_deadline!=b->deadline){b->frozen=false;return -EPERM;}
 }else if(p->retained_scan_exhausted||p->retained_scan_ops>8192){b->frozen=false;return -EPERM;}
 b->capture_limit=policy->count==1?16384:policy->count==2?32768:65536;
 p->j314s_scan_expected=policy->count;p->j314s_scan_limit=b->capture_limit;
 p->j314s_scan_ticket=ticket;p->j314s_scan_actor=current;
 p->j314s_scan_original_deadline=b->deadline;p->retained_scan_deadline=b->deadline;
 b->capture_budget_frozen=true;return 0;
}

/* IRQ/config callbacks use historical metadata only; never call supplier code. */
static bool jmx_native_scope(struct apple_apciec*p,unsigned count,bool historical)
{
 const struct jmx_kernel_policy*b;
 if(!p||!p->profile||!apciec_profile_j314s(p->profile))return false;
 if(!p->j314s_mixed_policy)return !p->profile->index&&(count==2||count==4);
 b=jmx_binding(p,historical);
 return b&&b->policy.count==count;
}
static int jmx_native_base(struct apple_apciec*p)
{
 static const unsigned base[3]={0x64e,0x66e,0x68e};
 if(!p||!p->profile||p->profile->index>=3)return -EPERM;
 if(!p->j314s_mixed_policy)return p->profile->index?-EPERM:base[0];
 {const struct jmx_kernel_policy*b=jmx_binding(p,true);
 return b&&b->native_frozen&&b->native_aic_base==base[p->profile->index]?
  b->native_aic_base:-EPERM;}
}
static bool jmx_native_sample(struct apple_apciec*p,const struct apple_dart_j314s_sample*s)
{
 /* Retain the currently supported T8110 register schema. A different actual
  * peer schema refuses; it is never silently replaced by the C0 fixture. */
 if(!j314s_measured_dma_sample(s))return false;
 if(!p->j314s_mixed_policy)return p->profile&&!p->profile->index;
 {const struct jmx_kernel_policy*b=jmx_binding(p,true);
 return b&&b->native_frozen&&!memcmp(s,&b->native_sample,sizeof(*s));}
}
static int jmx_native_freeze(struct apple_apciec*p)
{
 static const unsigned base[3]={0x64e,0x66e,0x68e};
 struct jmx_kernel_policy*b=p->j314s_mixed_policy;int ret;
 if(!b)return 0;
 if(!jmx_binding(p,false)||!b->native_proof||b->native_attempted||
    p->retained_phase!=14||!p->j314s_resource||p->profile->index>=3)return -EPERM;
 b->native_attempted=true; /* Consumed before proof; failures cannot renew. */
 b->native_sample=p->j314s_resource->dma_sample;b->native_aic_base=base[p->profile->index];
 if(!j314s_measured_dma_sample(&b->native_sample)||an_msi_profile_base(p)!=b->native_aic_base)return -EPERM;
 ret=b->native_proof(b->owner,b->ticket,b->policy.controller,b->deadline,
  &b->policy,&b->native_sample,b->native_aic_base,0);
 if(ret||!jmx_binding(p,false))return ret?ret:-EPERM;
 b->native_frozen=true;return 0;
}
static int jmx_native_owner(struct apple_apciec*p,const void*ticket,unsigned port,
 u64 deadline,unsigned count,u64 after)
{
 const struct jmx_kernel_policy*b;
 if(!p->j314s_mixed_policy)return after?
  apple_cio_j314s_chain_proof_after(p->supplier_context,ticket,port,deadline,count,after):
  apple_cio_j314s_chain_owner_validate(p->supplier_context,ticket,port,deadline,count);
 b=jmx_binding(p,false);
 if(!b||ticket!=b->ticket||port!=3||deadline!=b->deadline||count!=b->policy.count)return -EPERM;
 if(!after)return 0; /* jmx_binding just performed the original actor proof. */
 if(!b->native_frozen||!b->native_proof||after>=b->deadline)return -EPERM;
 return b->native_proof(b->owner,ticket,b->policy.controller,deadline,&b->policy,
  &b->native_sample,b->native_aic_base,after);
}

static unsigned jmx_capture_budget(struct apple_apciec*p)
{
 const struct jmx_kernel_policy*b=jmx_binding(p,true);unsigned limit;
 if(!b||!b->capture_budget_frozen)return 0;
 limit=b->policy.count==1?16384:b->policy.count==2?32768:(b->policy.count==4||b->policy.count==5)?65536:0;
 if(!limit||b->capture_limit!=limit||p->j314s_scan_expected!=b->policy.count||
    p->j314s_scan_limit!=limit||p->j314s_scan_ticket!=b->ticket||
    p->j314s_scan_actor!=current||b->actor!=current||
    p->j314s_scan_original_deadline!=b->deadline||p->retained_scan_deadline!=b->deadline)return 0;
 return limit;
}
static bool jmx_resource_scope(struct apple_apciec*p)
{
 if(!p||!p->profile||!apciec_profile_j314s(p->profile))return false;
 if(!p->j314s_mixed_policy)return !p->profile->index;
 return jmx_binding(p,true)&&jmx_capture_budget(p);
}
static int jmx_commit_owner(struct apple_apciec*p,unsigned port,const void*ticket,unsigned phase)
{
 const struct jmx_kernel_policy*b=jmx_binding(p,false);
 if(!b||!retain_prepare||phase<10||phase>14||p->retained_phase!=phase||
    !jmx_capture_budget(p)||ticket!=b->ticket||port!=3||port!=p->root_down_port||
    !p->retained||p->retained_failed||p->retained_availability_probe||p->retained_provider_prepare||
    !p->prepared||!p->power_ready||!p->retained_rc_ready||!p->tunnel_ready||
    !p->dart||p->iommu_ready||p->msi_domain_ready||p->retained_scan_exhausted)return -EPERM;
 return 0;
}
