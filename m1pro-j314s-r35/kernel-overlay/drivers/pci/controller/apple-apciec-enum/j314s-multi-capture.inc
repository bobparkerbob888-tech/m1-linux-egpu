#include "jmx-kernel-policy.inc"
#include "jmx-rebar-prepass.inc"
/* SPDX-License-Identifier: GPL-2.0 */
/* Dormant adapter after j314s-endpoint-resources.inc. One cold sizing batch;
 * no BAR assignment, command enable, PCI objects, DMA or driver binding.
 * Exact completed router/tunnel-list owner proof is mandatory at entry and
 * at each capture boundary. The export accepts only fresh raw phase10. */
extern int apple_cio_j314s_chain_owner_validate(void*,const void*,unsigned,u64,unsigned);
static int j314s_multi_io_slot(const struct ep_snapshot*s,unsigned b,
 const struct ep_identity*id)
{
 if(!j314s_ep_schema_limit(s,id,16)||b!=5||s->bars[b].saved[0]!=1||
    s->bars[b].saved[1]||s->bars[b].upper)return -EOPNOTSUPP;
 return 0;
}
static int j314s_multi_selected_records(struct apple_apciec*p,
 struct j314s_multi_resource_owner*m,unsigned expected)
{
 unsigned i,j,count=0;
 if(p->j314s_mixed_policy){
  const struct jmx_kernel_policy*b=jmx_binding(p,false);unsigned indices[JM_MAX_GPUS];
  if(!b||b->policy.count!=expected||jmx_raw_selection(&b->policy,p->retained_records,p->retained_record_count,indices))return -EPERM;
  for(i=0;i<expected;i++)m->selected[i]=p->retained_records[indices[i]];
  m->count=expected;return 0;
 }
 if(!jmx_native_scope(p,expected,true))return -EINVAL;
 for(i=0;i<p->retained_record_count;i++){
  const struct ep_identity*id=&p->retained_records[i];
  if((id->class_rev>>24)!=3)continue;
  /* Unknown/mixed display functions fail before any sizing write. */
  if(id->id!=0x2d0410de||!j314s_gpu_schema(id)||!id->serial||
     id->serial==~0ULL||count>=expected)return -EPERM;
  for(j=0;j<count;j++)if(m->selected[j].rid==id->rid||
     m->selected[j].serial==id->serial)return -ESTALE;
  m->selected[count++]=*id;
 }
 if(count!=expected)return -ENODEV;
 for(i=0;i<count;i++)for(j=i+1;j<count;j++)
  if(m->selected[j].rid<m->selected[i].rid){
   struct ep_identity swap=m->selected[i];m->selected[i]=m->selected[j];m->selected[j]=swap;
  }
 /* Preserve the previously measured first branch, not a guessed slot. */
 if(m->selected[0].rid!=0x300||m->selected[0].serial!=PROVISION_PRIVATE_ID_28||
    m->selected[0].subsystem!=0x41cd1458)return -ESTALE;
 m->count=count;return 0;
}
int apple_apciec_j314s_capture_multiple(struct device*,unsigned,const void*,
 unsigned,const struct j314s_multi_resource_owner**,unsigned*);
int apple_apciec_j314s_capture_multiple(struct device*dev,unsigned port,
 const void*ticket,unsigned expected,const struct j314s_multi_resource_owner**result,
 unsigned*phase)
{
 struct apple_apciec*p=dev_get_drvdata(dev);struct j314s_multi_resource_owner*m=NULL;
 struct j314s_ep_context c;struct ep_io io;unsigned i;unsigned long flags;int ret;
 if(!p||!ticket||!result||!phase||(!jmx_native_scope(p,expected,true)))return -EINVAL;
 *result=NULL;*phase=0;mutex_lock(&p->lifecycle);
 if(!jmx_resource_scope(p)||!p->j314s_raw_capability||
    p->j314s_multi_resource||p->j314s_resource||p->endpoint_snapshot||p->bridge||
    p->discovery_bridge||p->iommu_ready||p->msi_domain_ready||!p->tunnel_ready||
    !p->retained_record_count||p->retained_record_count>EP_MAX_RECORDS){ret=-EPERM;goto out;}
 ret=retained_commit_owner(p,port,ticket,10);if(ret)goto out;
 ret=jmx_native_owner(p,ticket,port,p->retained_identity_deadline,expected,0);
 if(ret)goto out;
 m=kzalloc(sizeof(*m),GFP_KERNEL);if(!m){ret=-ENOMEM;goto out;}
 p->j314s_multi_resource=m;m->attempted=true;m->ticket=ticket;
 m->task=current;m->deadline=p->retained_scan_deadline;m->status=-EINPROGRESS;
 ret=j314s_multi_selected_records(p,m,expected);if(ret)goto fail;
 /* All ownership is recorded before the first selected device is touched. */
 for(i=0;i<m->count;i++){
  m->owners[i]=kzalloc(sizeof(*m->owners[i]),GFP_KERNEL);
  m->snapshots[i]=kvzalloc(sizeof(*m->snapshots[i]),GFP_KERNEL);
  if(!m->owners[i]||!m->snapshots[i]){ret=-ENOMEM;goto fail;}
  m->owners[i]->attempted=true;m->owners[i]->ticket=ticket;
  m->owners[i]->task=current;m->owners[i]->selected=m->selected[i];
  m->owners[i]->deadline=m->deadline;m->owners[i]->status=-EINPROGRESS;
 }
 p->retained_phase=11;m->active=true;
 ret=jmx_rebar_prepass(p,m);if(ret)goto fail;
 for(i=0;i<m->count;i++){
  struct j314s_resource_owner*o=m->owners[i];struct ep_snapshot*s=m->snapshots[i];
  m->active_index=i;
  ret=jmx_native_owner(p,ticket,port,p->retained_identity_deadline,expected,0);
  if(ret)goto fail;
  ret=retained_ep_budget(p,2ULL*NSEC_PER_SEC,2048);if(ret)goto fail;
  ret=apple_dart_j314s_sample_get(&p->dart->dev,dev,&o->dma_sample);if(ret)goto fail;
  if(!j314s_measured_dma_sample(&o->dma_sample)){ret=-ESTALE;goto fail;}
  p->j314s_resource=o;p->endpoint_snapshot=s;p->endpoint_selected_rid=o->selected.rid;
  c=(struct j314s_ep_context){p,o};
  io=(struct ep_io){.ctx=&c,.read=j314s_ep_read,.write=j314s_ep_write,
   .safe=j314s_ep_safe,.probe_ready=j314s_ep_probe_ready,.valid=j314s_ep_valid,
   .now=retained_raw_clock,.deadline=m->deadline,.records=p->retained_records,
   .count=p->retained_record_count,.root_rid=(unsigned)p->bus_start<<8};
  raw_spin_lock_irqsave(&p->lock,flags);o->active=true;
  p->endpoint_sizing=true;p->retained_scan_task=current;
  raw_spin_unlock_irqrestore(&p->lock,flags);
  ret=j314s_ep_safe(&c,o->selected.rid);
  if(!ret)ret=ep_capture_limit(&io,&o->selected,s,16);
  if(!ret)ret=j314s_capture_disabled_capabilities(&io,&s->functions[s->selected]);
  if(!ret&&(!j314s_ep_schema_limit(s,&o->selected,16)||(p->j314s_mixed_policy&&!jmx_host_capture(p,i,s,&o->selected))))ret=-EOPNOTSUPP;
  if(!ret)ret=ep_size_bars_policy(&io,s,&o->selected,j314s_multi_io_slot);
  if(!ret&&o->rebar_attempted&&(!o->rebar_complete||s->bars[1].size!=0x10000000ULL))ret=-ESTALE;
  if(!ret)ret=j314s_ep_safe(&c,o->selected.rid);
  raw_spin_lock_irqsave(&p->lock,flags);o->active=false;
  p->endpoint_sizing=false;p->retained_scan_task=NULL;
  raw_spin_unlock_irqrestore(&p->lock,flags);
  if(ret){o->failed=true;o->status=ret;goto fail;}
  ret=jmx_native_owner(p,ticket,port,p->retained_identity_deadline,expected,0);
  if(ret){o->failed=true;o->status=ret;goto fail;}
  o->completed_ns=ktime_get_boottime_ns();
  if(o->completed_ns>=m->deadline){ret=-ETIMEDOUT;goto fail;}
  o->complete=true;o->status=0;
 }
 m->completed_ns=ktime_get_boottime_ns();
 if(m->completed_ns>=m->deadline){ret=-ETIMEDOUT;goto fail;}
 /* Compatibility pointers do not mean these unplanned snapshots are assigned.
  * Subsequent multi code must require the complete global plan/receipt. */
 p->j314s_resource=m->owners[0];p->endpoint_snapshot=m->snapshots[0];
 p->endpoint_selected_rid=m->selected[0].rid;
 m->active=false;m->task=NULL;m->complete=true;m->status=0;
 p->retained_phase=12;*result=m;ret=0;goto out;
fail:
 if(m->active&&m->active_index<m->count&&m->owners[m->active_index]){
  m->owners[m->active_index]->failed=true;m->owners[m->active_index]->status=ret;
 }
 m->active=false;m->failed=true;m->status=ret;m->task=NULL;p->retained_failed=true;
 /* Preserve every allocation and any partial BAR write until normal reboot. */
out:
 *phase=p->retained_phase;mutex_unlock(&p->lifecycle);return ret;
}
EXPORT_SYMBOL_GPL(apple_apciec_j314s_capture_multiple);
