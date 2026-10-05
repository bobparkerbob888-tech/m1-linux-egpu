/* Same-boot target-only capture + sizing + plan. No assignment/decode/DMA.
 * Include after endpoint-resource.inc. Host lifecycle is outer serialization. */
#include "j314s-endpoint-plan.h"
#include "j314s-sample-profile.h"
#include <linux/apple-j314s-bar-report.h>
struct j314s_ep_context {struct apple_apciec*p;struct j314s_resource_owner*o;};
static bool j314s_ep_valid(void*arg)
{
 struct j314s_ep_context*c=arg;struct apple_apciec*p=c->p;
 return jmx_resource_scope(p)&&p->j314s_raw_capability&&
  p->j314s_resource==c->o&&c->o->active&&!c->o->failed&&c->o->task==current&&
  p->retained_scan_task==current&&p->endpoint_sizing&&
  p->endpoint_selected_rid==c->o->selected.rid&&
  !retained_commit_owner(p,3,c->o->ticket,11)&&p->tunnel_ready&&
  !retained_ep_budget(p,0,1);
}
static int j314s_ep_read(void*arg,unsigned rid,unsigned off,u32*v)
{
 struct j314s_ep_context*c=arg;struct pci_bus b={.number=rid>>8,.sysdata=c->p,.ops=&apple_apciec_ops};
 return apple_apciec_config_read(&b,rid&255,off,4,v)==PCIBIOS_SUCCESSFUL?0:-EIO;
}
static int j314s_ep_write(void*arg,unsigned rid,unsigned off,u32 v)
{
 struct j314s_ep_context*c=arg;struct pci_bus b={.number=rid>>8,.sysdata=c->p,.ops=&apple_apciec_ops};
 return apple_apciec_config_write(&b,rid&255,off,4,v)==PCIBIOS_SUCCESSFUL?0:-EIO;
}
static int j314s_ep_safe(void*arg,unsigned rid)
{
 struct j314s_ep_context*c=arg;unsigned j;u32 command;int ret;
 if(!j314s_ep_valid(arg)||rid!=c->o->selected.rid)return -EPERM;
 ret=retained_dma_blocked(c->p);if(ret)return ret;
 for(j=0;j<c->p->retained_record_count;j++){
  ret=j314s_ep_read(c,c->p->retained_records[j].rid,4,&command);if(ret)return ret;
  if(command&65535)return -EPERM;
 }
 return j314s_ep_valid(c)?0:-EPERM;
}
static int j314s_ep_probe_ready(void*arg)
{
 struct j314s_ep_context*c=arg;
 return j314s_ep_valid(arg)?retained_ep_budget(c->p,NSEC_PER_SEC,256):-EPERM;
}
int apple_apciec_j314s_endpoint_resources(struct device*dev,unsigned port,
 const void*ticket,const struct ep_identity*selected,const struct ep_snapshot**result,
 unsigned*phase);
int apple_apciec_j314s_endpoint_resources(struct device*dev,unsigned port,
 const void*ticket,const struct ep_identity*selected,const struct ep_snapshot**result,
 unsigned*phase)
{
 struct apple_apciec*p=dev_get_drvdata(dev);struct j314s_resource_owner*o;
 struct j314s_ep_context c;struct ep_io io;unsigned j;int ret;unsigned long flags;
 if(!result||!phase)return -EINVAL;
 *result=NULL;*phase=0;
 if(!p||!ticket||!selected||!j314s_gpu_schema(selected))return -EINVAL;
 mutex_lock(&p->lifecycle);
 if(p->j314s_mixed_policy||!apciec_profile_j314s(p->profile)||p->profile->index||!p->j314s_raw_capability||
    p->j314s_resource||p->endpoint_snapshot||!p->tunnel_ready||p->bridge||
    p->iommu_ready||p->msi_domain_ready||!p->retained_record_count||
    p->retained_record_count>EP_MAX_RECORDS){ret=-EPERM;goto out;}
 ret=retained_commit_owner(p,port,ticket,10);if(ret)goto out;
 for(j=0;j<p->retained_record_count;j++)
  if(ep_identity_equal(selected,&p->retained_records[j]))break;
 if(j==p->retained_record_count){ret=-ESTALE;goto out;}
 o=kzalloc(sizeof(*o),GFP_KERNEL);if(!o){ret=-ENOMEM;goto out;}
 p->j314s_resource=o;o->attempted=true;o->ticket=ticket;o->task=current;
 o->selected=*selected;o->deadline=p->retained_scan_deadline;o->status=-EINPROGRESS;
 p->retained_phase=11;
 ret=retained_ep_budget(p,2ULL*NSEC_PER_SEC,2048);if(ret)goto fail;
 /* Immutable pre-reset sample is copied before any endpoint sizing writes. */
 ret=apple_dart_j314s_sample_get(&p->dart->dev,dev,&o->dma_sample);if(ret)goto fail;
 if(!j314s_measured_dma_sample(&o->dma_sample)){ret=-ESTALE;goto fail;}
 p->endpoint_snapshot=kvzalloc(sizeof(*p->endpoint_snapshot),GFP_KERNEL);
 if(!p->endpoint_snapshot){ret=-ENOMEM;goto fail;}
 p->endpoint_selected_rid=selected->rid;p->endpoint_sizing=true;
 c=(struct j314s_ep_context){p,o};
 io=(struct ep_io){.ctx=&c,.read=j314s_ep_read,.write=j314s_ep_write,
  .safe=j314s_ep_safe,.probe_ready=j314s_ep_probe_ready,.valid=j314s_ep_valid,
  .now=retained_raw_clock,.deadline=o->deadline,.records=p->retained_records,
  .count=p->retained_record_count,.root_rid=(unsigned)p->bus_start<<8};
 raw_spin_lock_irqsave(&p->lock,flags);o->active=true;p->retained_scan_task=current;
 raw_spin_unlock_irqrestore(&p->lock,flags);
 ret=j314s_ep_safe(&c,selected->rid);
 if(!ret)ret=ep_capture(&io,&o->selected,p->endpoint_snapshot);
 if(!ret)ret=j314s_capture_disabled_capabilities(&io,
  &p->endpoint_snapshot->functions[p->endpoint_snapshot->selected]);
 if(!ret&&!j314s_ep_schema(p->endpoint_snapshot,&o->selected))ret=-EOPNOTSUPP;
 if(!ret)ret=ep_size_bars_policy(&io,p->endpoint_snapshot,&o->selected,j314s_ep_io_slot);
 if(!ret)ret=j314s_ep_plan(p->endpoint_snapshot,&o->selected);
 if(!ret)ret=j314s_ep_safe(&c,selected->rid);
 raw_spin_lock_irqsave(&p->lock,flags);o->active=false;p->retained_scan_task=NULL;
 p->endpoint_sizing=false;raw_spin_unlock_irqrestore(&p->lock,flags);
 if(ret)goto fail;
 ret=retained_ep_budget(p,0,1);if(ret)goto fail;
 o->completed_ns=ktime_get_boottime_ns();
 if(o->completed_ns>=o->deadline){ret=-ETIMEDOUT;goto fail;}
 p->retained_phase=12;o->complete=true;o->status=0;*result=p->endpoint_snapshot;
 goto out;
fail:
 o->failed=true;o->status=ret;p->retained_failed=true;
 /* All state and any interrupted BAR-sizing write remain owned. No retry. */
out:
 *phase=p->retained_phase;
 if(p->endpoint_snapshot)retained_ep_dump(p,ret);
 mutex_unlock(&p->lifecycle);return ret;
}
EXPORT_SYMBOL_GPL(apple_apciec_j314s_endpoint_resources);

/* Actual retained plan completion; external readers gain no action permit. */
int apple_apciec_j314s_resource_state(struct device*dev,u32*flags,int*status,
 struct apple_j314s_bar_report*report)
{
 struct apple_apciec*p;struct j314s_resource_owner*o;struct ep_snapshot*s;
 u32 f=0;unsigned j,k;
 if(!flags||!status||!report)return -EINVAL;
 *flags=0;*status=-EINPROGRESS;memset(report,0,sizeof(*report));
 p=dev?dev_get_drvdata(dev):NULL;if(!p)return -ENODEV;
 if(!mutex_trylock(&p->lifecycle))return -EAGAIN;
 o=p->j314s_resource;s=p->endpoint_snapshot;
 if(!o||!o->attempted)goto out;
 f|=1;*status=o->status;
 if(!apciec_profile_j314s(p->profile)||p->profile->index||!p->j314s_raw_capability||
    o->ticket!=p->retained_ticket||!j314s_gpu_schema(&o->selected)||
    !j314s_measured_dma_sample(&o->dma_sample)||o->deadline!=p->retained_scan_deadline)
  goto invalid;
 f|=2;
 if(!s||!s->captured||!j314s_ep_schema(s,&o->selected))goto invalid;
 f|=4;if(!s->sized)goto invalid;
 f|=8;
 if(!s->planned||s->memory_assigned||o->failed||o->active||!o->complete||o->status||
    p->retained_failed||p->retained_phase!=12||p->endpoint_sizing||p->retained_scan_task||
    !o->completed_ns||o->completed_ns>=o->deadline)goto invalid;
 f|=16;*status=0;
 report->rid=o->selected.rid;report->id=o->selected.id;report->class_rev=o->selected.class_rev;
 report->subsystem=o->selected.subsystem;report->header=o->selected.header;report->serial=o->selected.serial;
 report->completed_ns=o->completed_ns;report->deadline=o->deadline;
 report->function_count=s->count;report->ancestor_count=s->ancestor_count;report->dma_sample=o->dma_sample;
 for(j=0;j<6;j++){
  const struct ep_bar*b=&s->bars[j];struct apple_j314s_bar*d=&report->bars[j];
  memcpy(d->saved,b->saved,sizeof(d->saved));memcpy(d->mask,b->mask,sizeof(d->mask));
  d->size=b->size;d->pci=b->pci;d->cpu=b->cpu;d->flags=b->flags;d->window=b->window;
  d->upper=b->upper;d->unsupported_io=b->unsupported_io;
 }
 for(j=0;j<s->ancestor_count;j++){
  report->bridges[j].rid=s->bridges[j].rid;
  for(k=0;k<3;k++){
   report->bridges[j].start[k]=s->bridges[j].start[k];report->bridges[j].end[k]=s->bridges[j].end[k];
   report->bridges[j].active[k]=s->bridges[j].active[k];
  }
 }
 goto out;
invalid:
 if(!*status)*status=-ESTALE;
out:
 *flags=f;mutex_unlock(&p->lifecycle);return 0;
}
EXPORT_SYMBOL_GPL(apple_apciec_j314s_resource_state);
