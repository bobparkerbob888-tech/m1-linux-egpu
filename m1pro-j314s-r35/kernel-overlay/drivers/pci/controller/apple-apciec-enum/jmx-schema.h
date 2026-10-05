/* Dormant pure schema, never hardware authorization. Includes original jm types.
 * Policy identities must be frozen from same-boot retained raw records after
 * the controller owner proves its exact router chain. They are not UUIDs or
 * IDs supplied by userspace. Existing jm_build remains 5060-only. */
#ifndef JMX_SCHEMA_H
#define JMX_SCHEMA_H
#include "j314s-multi-admission.h"
#include "j314s-boot0-schema.h"
enum jmx_model { JMX_GB206_5060TI=1, JMX_GB203_5080=2, JMX_GB203_5090M=3 };
struct jmx_policy {
 unsigned controller,count;
 struct jm_identity identity[JM_MAX_GPUS];
 enum jmx_model model[JM_MAX_GPUS];
 /* Explicit opt-in only after fresh fault review of desktop's exact branch.
  * Schema code cannot establish that review, controller power or DMA proof. */
 unsigned desktop_review_mask;
};
static unsigned jmx_model_id(enum jmx_model model)
{
 switch(model){case JMX_GB206_5060TI:return 0x2d0410de;
 case JMX_GB203_5080:return 0x2c0210de;
 case JMX_GB203_5090M:return 0x2c1810de;default:return 0;}
}
static int jmx_policy_valid(const struct jmx_policy*p)
{
 unsigned i,j,desktop=0;
 if(!p||p->controller>2||(p->count!=1&&p->count!=2&&p->count!=4&&p->count!=5))return 0;
 for(i=0;i<p->count;i++){
  const struct jm_identity*x=&p->identity[i];
  if(!jmx_model_id(p->model[i])||x->id!=jmx_model_id(p->model[i])||
     (x->class_rev>>16)!=0x0300||x->header>255||(x->header&127)||
     !x->rid||x->rid>65535||(x->rid&7)||!x->serial||x->serial==~(u64)0)
   return 0;
  if(p->model[i]==JMX_GB203_5080)desktop|=1U<<i;
  for(j=0;j<i;j++)if(p->identity[j].rid==x->rid||p->identity[j].serial==x->serial)return 0;
  if(i&&p->identity[i-1].rid>=x->rid)return 0;
 }
 /* No default exemption and no unused review bits. */
 return p->desktop_review_mask==desktop;
}
static int jmx_identity(const struct jmx_policy*p,unsigned index,const struct jm_identity*id)
{return jmx_policy_valid(p)&&index<p->count&&id&&jm_equal(&p->identity[index],id);}
/* Check every display, including unselected/unknown-vendor displays. Audio
 * stays in the raw tree for alias/capability checks; it is never a GPU client. */
static int jmx_select(const struct jmx_policy*p,const struct jm_identity*raw,
 unsigned records,unsigned selected[JM_MAX_GPUS])
{
 unsigned i,g,count=0,found[JM_MAX_GPUS]={0},out[JM_MAX_GPUS]={0};
 if(!jmx_policy_valid(p)||!raw||!selected||!records||records>JM_MAX_RECORDS)return -1;
 for(i=0;i<records;i++){
  if((raw[i].class_rev>>24)!=3)continue;
  for(g=0;g<p->count;g++)if(jmx_identity(p,g,&raw[i]))break;
  if(g==p->count||found[g]++)return -1;
  out[g]=i;count++;
 }
 if(count!=p->count)return -1;
 for(g=0;g<p->count;g++){if(!found[g])return -1;selected[g]=out[g];}
 return 0;
}
static int jmx_boot0(const struct jmx_policy*p,unsigned index,
 const struct jm_identity*actual,unsigned first,unsigned second)
{return jmx_identity(p,index,actual)&&j314s_boot0_schema_valid(actual->id,first,second);}
#endif
