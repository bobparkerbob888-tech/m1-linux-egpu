#include "apple-jpc-native-policy.h"
extern int apple_cio_jpc_native_policy_validate(void*,const void*,unsigned,u64,
 const struct apple_jpc_native_policy*,const struct apple_dart_j314s_sample*,unsigned,u64);
struct jpc_host_binding {struct apple_apciec*p;struct apple_jpc_native_policy policy;};
static bool jpc_host_policy_equal(const struct jpc_host_binding*c,const struct jmx_policy*p)
{
 if(!c||!p||!jmx_policy_valid(p)||c->policy.controller!=p->controller||
    c->policy.count!=p->count||c->policy.desktop_review_mask!=p->desktop_review_mask)return false;
 for(unsigned j=0;j<p->count;j++){
  const struct apple_jpc_native_identity*x=&c->policy.clients[j];const struct jm_identity*y=&p->identity[j];
  if(x->model!=p->model[j]||x->rid!=y->rid||x->id!=y->id||x->class_rev!=y->class_rev||
     x->subsystem!=y->subsystem||x->header!=y->header||x->serial!=y->serial)return false;
 }
 return true;
}
static int jpc_host_identity_proof(void*arg,const void*ticket,unsigned controller,u64 deadline,const struct jmx_policy*policy)
{
 struct jpc_host_binding*c=arg;
 if(!jpc_host_policy_equal(c,policy)||!c->p||c->p->profile->index!=controller||controller!=c->policy.controller)return -EPERM;
 return apple_cio_jpc_native_policy_validate(c->p->supplier_context,ticket,c->p->root_down_port,deadline,&c->policy,NULL,0,0);
}
static int jpc_host_native_proof(void*arg,const void*ticket,unsigned controller,u64 deadline,const struct jmx_policy*policy,
 const struct apple_dart_j314s_sample*sample,unsigned aic_base,u64 after)
{
 struct jpc_host_binding*c=arg;
 if(!jpc_host_policy_equal(c,policy)||!c->p||c->p->profile->index!=controller||controller!=c->policy.controller)return -EPERM;
 return apple_cio_jpc_native_policy_validate(c->p->supplier_context,ticket,c->p->root_down_port,deadline,&c->policy,sample,aic_base,after);
}
int apple_apciec_jpc_bind_native_once(struct device*,unsigned,const void*,const struct apple_jpc_native_policy*);
int apple_apciec_jpc_bind_native_once(struct device*dev,unsigned port,const void*ticket,const struct apple_jpc_native_policy*policy)
{
 struct apple_apciec*p=dev_get_drvdata(dev);struct jpc_host_binding*c;struct jmx_policy typed={0};int ret;
 if(!p||!policy||policy->version!=1||policy->reserved||policy->controller<1||policy->controller>2||
    policy->count!=5||p->profile->index!=policy->controller||!jpc_host_mode(p)||
    !j314s_combined_boot_mask(saved_command_line))return -EPERM;
 mutex_lock(&p->lifecycle);
 if(p->j314s_mixed_policy||p->retained_phase!=10||ticket!=p->retained_ticket||port!=p->root_down_port){ret=-EPERM;goto out;}
 c=kvzalloc(sizeof(*c),GFP_KERNEL);if(!c){ret=-ENOMEM;goto out;}
 c->p=p;c->policy=*policy;typed.controller=policy->controller;typed.count=policy->count;typed.desktop_review_mask=policy->desktop_review_mask;
 for(unsigned j=0;j<typed.count;j++){
  const struct apple_jpc_native_identity*x=&policy->clients[j];
  typed.identity[j]=(struct jm_identity){x->rid,x->id,x->class_rev,x->subsystem,x->header,x->serial};typed.model[j]=x->model;
 }
 /* Fixed actual supplier callbacks only; external callers cannot supply an accepting callback. */
 ret=jmx_bind_raw_once(p,ticket,&typed,jpc_host_identity_proof,c,jpc_host_native_proof);
 out:mutex_unlock(&p->lifecycle);return ret;
}
EXPORT_SYMBOL_GPL(apple_apciec_jpc_bind_native_once);
