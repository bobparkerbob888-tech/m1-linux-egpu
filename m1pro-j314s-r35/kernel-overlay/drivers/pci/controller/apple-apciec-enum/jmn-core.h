/* SPDX-License-Identifier: GPL-2.0 */
#ifndef JMN_CORE_H
#define JMN_CORE_H
#include "j314s-multi-admission.h"
/* Compile-only orchestrator. No callback may manufacture a receipt from a pure
 * planner. Caller retains immutable actual capture, joint hardware assignment,
 * objects and failed contexts until reboot. No automatic teardown/retry. */
enum jmn_phase { JMN_EMPTY,JMN_OBJECTS,JMN_CLAIMS,JMN_ACS,JMN_MMIO,JMN_DMA,
 JMN_MSI,JMN_SEALED,JMN_PUBLISHED,JMN_FAILED };
struct jmn_evidence {
 const void*device[JM_MAX_GPUS],*group[JM_MAX_GPUS],*domain[JM_MAX_GPUS],*msi;
 unsigned alias_count[JM_MAX_GPUS],alias[JM_MAX_GPUS];u32 rid_table[64];
};
struct jmn_io {
 bool (*valid)(void*,bool historical);u64 (*now)(void*);
 int (*assignment)(void*,const struct jm_capture*,const struct jm_plan*);
 int (*plan)(void*,const struct jm_capture*,struct jm_plan*);
 int (*objects)(void*,const struct jm_capture*,const struct jm_plan*);
 int (*claims)(void*);int (*acs)(void*);int (*mmio)(void*);
 int (*dma)(void*);int (*msi)(void*);
 int (*audit)(void*,enum jmn_phase,struct jmn_evidence*);
 int (*seal)(void*);int (*publish)(void*);
 int (*driver)(void*,unsigned,bool);
 void (*failure)(void*,const char*,enum jmn_phase,int); /* Diagnostic only, no I/O. */
 void*ctx;u64 original_deadline;
};
struct jmn_owner {
 struct jm_capture capture;struct jm_plan plan;struct jmn_evidence evidence;
 enum jmn_phase phase;bool consumed,failed,complete,publication_consumed;int status;
 const struct jmn_io*io;u64 completed_ns;
};
static int jmn_gate(struct jmn_owner*o)
{
 if(!o->io->valid(o->io->ctx,false)||o->failed)return -EPERM;
 if(!o->io->original_deadline||o->io->now(o->io->ctx)>=o->io->original_deadline)return -ETIMEDOUT;
 return 0;
}
static int jmn_evidence_valid(const struct jmn_owner*o,const struct jmn_evidence*e)
{
 unsigned i,j;
 if(o->phase>=JMN_DMA){
  if(o->plan.count==1||o->plan.count==5){
   /* Only a supplied typed planner can produce count1/5; legacy jm_build
    * rejects it. Preserve the exact full64 SID table audit. */
   if(!o->io->plan)return -EPERM;
   for(unsigned i=0;i<64;i++)if(o->plan.rid2sid[i]!=e->rid_table[i])return -EPERM;
  }else if(jm_rid_table(&o->plan,e->rid_table))return -EPERM;
  for(i=0;i<o->plan.count;i++){
   if(!e->device[i]||!e->group[i]||!e->domain[i]||e->alias_count[i]!=1||
      e->alias[i]!=o->plan.client[i].identity.rid)return -EPERM;
   for(j=0;j<i;j++)if(e->device[i]==e->device[j]||e->group[i]==e->group[j]||e->domain[i]==e->domain[j])return -EPERM;
  }
  for(i=o->plan.count;i<JM_MAX_GPUS;i++)if(e->device[i]||e->group[i]||e->domain[i]||e->alias_count[i]||e->alias[i])return -EPERM;
 }
 if(o->phase>=JMN_MSI&&!e->msi)return -EPERM;
 return 0;
}
static int jmn_audit(struct jmn_owner*o)
{
 struct jmn_evidence e={0};int ret=jmn_gate(o);if(ret)return ret;
 ret=o->io->audit(o->io->ctx,o->phase,&e);if(ret)return ret;
 ret=jmn_evidence_valid(o,&e);if(ret)return ret;
 if(o->phase>=JMN_DMA&&o->evidence.device[0])
  for(unsigned j=0;j<o->plan.count;j++)if(e.device[j]!=o->evidence.device[j]||e.group[j]!=o->evidence.group[j]||e.domain[j]!=o->evidence.domain[j])return -ESTALE;
 if(o->phase>=JMN_MSI&&o->evidence.msi&&e.msi!=o->evidence.msi)return -ESTALE;
 o->evidence=e;return jmn_gate(o);
}
static int jmn_prepare_once(struct jmn_owner*o,const struct jmn_io*i,const struct jm_capture*c)
{
 int ret;const char*stage="callbacks";
 if(!o||!i||!c)return -EINVAL;
 if(o->consumed)return -EALREADY;
 o->consumed=true;o->status=-EINPROGRESS;o->io=i;
 if(!i->valid||!i->now||!i->assignment||!i->objects||!i->claims||!i->acs||!i->mmio||
    !i->dma||!i->msi||!i->audit||!i->seal||!i->publish||!i->driver){ret=-EOPNOTSUPP;goto fail;}
 o->capture=*c;
 stage="plan";
 if(i->plan?i->plan(i->ctx,&o->capture,&o->plan):jm_build(&o->capture,&o->plan)){ret=-EPERM;goto fail;}
 ret=jmn_gate(o);if(ret)goto fail;
 stage="assignment";ret=i->assignment(i->ctx,&o->capture,&o->plan);if(ret)goto fail;
 stage="pre-objects-audit";ret=jmn_audit(o);if(ret)goto fail;
 stage="objects";ret=i->objects(i->ctx,&o->capture,&o->plan);if(ret)goto fail;
 o->phase=JMN_OBJECTS;stage="objects-audit";ret=jmn_audit(o);if(ret)goto fail;
 #define JMN_STEP(name,ph) do {stage=#name "-gate";ret=jmn_gate(o);if(ret)goto fail;stage=#name;ret=i->name(i->ctx);if(ret)goto fail;o->phase=ph;stage=#name "-audit";ret=jmn_audit(o);if(ret)goto fail;}while(0)
 JMN_STEP(claims,JMN_CLAIMS);JMN_STEP(acs,JMN_ACS);JMN_STEP(mmio,JMN_MMIO);
 JMN_STEP(dma,JMN_DMA);JMN_STEP(msi,JMN_MSI);JMN_STEP(seal,JMN_SEALED);
 #undef JMN_STEP
 return 0; /* Sealed but unpublished: caller releases host lifecycle for tunnel proof. */
 fail:if(i->failure)i->failure(i->ctx,stage,o->phase,ret);
 o->failed=true;o->phase=JMN_FAILED;o->status=ret;return ret;
}
static int jmn_publish_once(struct jmn_owner*o)
{
 const struct jmn_io*i;int ret;const char*stage="publish-entry";
 if(!o||!o->consumed||!o->io)return -EINVAL;
 if(o->publication_consumed)return -EALREADY;
 o->publication_consumed=true;i=o->io;
 if(o->failed||o->complete||o->phase!=JMN_SEALED){ret=-EPERM;goto fail;}
 stage="publish-gate";ret=jmn_gate(o);if(ret)goto fail;
 stage="publish-pre-audit";ret=jmn_audit(o);if(ret)goto fail;
 stage="publish";ret=i->publish(i->ctx);if(ret)goto fail;
 o->phase=JMN_PUBLISHED;stage="publish-audit";ret=jmn_audit(o);if(ret)goto fail;
 stage="publish-completion";o->completed_ns=i->now(i->ctx);if(o->completed_ns>=i->original_deadline){ret=-ETIMEDOUT;goto fail;}
 o->status=0;o->complete=true;return 0;
 fail:if(i->failure)i->failure(i->ctx,stage,o->phase,ret);
 o->failed=true;o->phase=JMN_FAILED;o->status=ret;return ret;
}
/* Convenience only; production must interpose locked tunnel proof between phases. */
static int __attribute__((unused)) jmn_once(struct jmn_owner*o,const struct jmn_io*i,const struct jm_capture*c)
{int ret=jmn_prepare_once(o,i,c);return ret?ret:jmn_publish_once(o);}
/* Persistent hook after cold completion: exact selected device, no deadline
 * renewal, no missing-owner fallback. Live driver audit remains mandatory. */
static int jmn_driver_admit(struct jmn_owner*o,const void*device,bool irq)
{
 if(!o||!o->consumed||o->failed||!o->complete||o->status||o->phase!=JMN_PUBLISHED||
    !o->io||!o->io->valid||!o->io->driver||!o->io->valid(o->io->ctx,true))return -EPERM;
 for(unsigned j=0;j<o->plan.count;j++)if(device&&device==o->evidence.device[j])return o->io->driver(o->io->ctx,j,irq);
 return -EPERM;
}
#endif
