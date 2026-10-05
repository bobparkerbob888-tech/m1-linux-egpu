#include <linux/apple-j314s-multi-report.h>
/* Retained history only. No register reads, task permission, retry or budget renewal. */
int apple_apciec_j314s_multi_state(struct device*dev,u32*flags,int*status,struct apple_j314s_multi_report*r)
{
 struct apple_apciec*p=dev?dev_get_drvdata(dev):NULL;struct jmn_kernel*k;unsigned j,b;u32 f=0;
 if(!flags||!status||!r)return -EINVAL;
 *flags=0;*status=-EINPROGRESS;memset(r,0,sizeof(*r));r->version=1;
 if(!p)return -ENODEV;
 if(!mutex_trylock(&p->lifecycle))return -EAGAIN;
 k=p->j314s_multi_native;if(!k)goto out;
 if(k->owner.plan.count>4){*status=-EOPNOTSUPP;goto out;}
 *status=k->owner.status;r->phase=p->retained_phase;
 if(k->owner.consumed)f|=1;
 if(k->bridge&&k->owner.plan.count&&jmx_native_scope(k->p,k->owner.plan.count,true))f|=2;
 if(k->config&&k->config->mmio_complete)f|=4;
 if(k->rid_attempted&&p->iommu_ready)f|=8;
 if(k->msi_attempted&&p->msi_domain_ready)f|=16;
 if(k->sealed)f|=32;
 if(k->published&&k->published_count==k->owner.plan.count)f|=64;
 if(f!=127||k->failed||k->owner.failed||!k->owner.complete||k->owner.status||k->task||
    p->retained_phase!=40||!jmn_root_valid(k,true)||!k->owner.completed_ns||
    k->owner.completed_ns>=k->deadline||k->prepared_ns>=k->owner.completed_ns)goto invalid;
 for(j=0;j<k->owner.plan.count;j++){
  struct pci_dev*d=k->selected[j];const struct jm_client*c=&k->owner.plan.client[j];
  struct apple_j314s_multi_client_report*q=&r->client[j];
  if(!d||k->clients[j].failed||!k->clients[j].dma_ready||!k->clients[j].rid_ready||
     !k->clients[j].irq_ready||!pci_dev_is_added(d)||!k->sealed_groups[j]||
     d->dev.iommu_group!=k->sealed_groups[j])goto invalid;
  q->rid=c->identity.rid;q->id=c->identity.id;q->class_rev=c->identity.class_rev;
  q->subsystem=c->identity.subsystem;q->header=c->identity.header;q->serial=c->identity.serial;
  q->sid=c->sid;q->group=iommu_group_id(k->sealed_groups[j]);
  q->boot0[0]=k->config->boot0[j][0];q->boot0[1]=k->config->boot0[j][1];
  for(b=0;b<6;b++){
   q->bars[b].start=k->sealed_bars[j][b].start;q->bars[b].end=k->sealed_bars[j][b].end;
   q->bars[b].flags=k->sealed_bars[j][b].flags;
  }
 }
 r->count=k->owner.plan.count;r->raw_count=k->owner.capture.count;r->path_count=k->owner.plan.path_count;
 r->operations=k->operations;r->completed_ns=k->owner.completed_ns;r->prepared_ns=k->prepared_ns;
 r->original_deadline=k->deadline;r->assignment_ns=((const struct jma_kernel_owner*)k->assignment_receipt)->completed_ns;
 memcpy(r->rid2sid,k->owner.evidence.rid_table,sizeof(r->rid2sid));
 f|=128;*status=0;goto out;
invalid:if(!*status)*status=-ESTALE;
out:*flags=f;mutex_unlock(&p->lifecycle);return 0;
}
EXPORT_SYMBOL_GPL(apple_apciec_j314s_multi_state);

#include <linux/apple-jmx-native-report.h>
/* Retained history only. No register reads, task permission, retry or budget renewal. */
int apple_apciec_jmx_native_state(struct device*dev,u32*flags,int*status,struct apple_jmx_native_report*r)
{
 struct apple_apciec*p=dev?dev_get_drvdata(dev):NULL;struct jmn_kernel*k;unsigned j,b;u32 f=0;
 if(!flags||!status||!r)return -EINVAL;
 *flags=0;*status=-EINPROGRESS;memset(r,0,sizeof(*r));r->version=1;
 if(!p)return -ENODEV;
 if(!mutex_trylock(&p->lifecycle))return -EAGAIN;
 k=p->j314s_multi_native;if(!k)goto out;
 if(!p->j314s_mixed_policy||!jmx_binding(p,true)||k->owner.plan.count>5){*status=-EPERM;goto out;}
 r->controller=p->profile->index;
 *status=k->owner.status;r->phase=p->retained_phase;
 if(k->owner.consumed)f|=1;
 if(k->bridge&&k->owner.plan.count&&jmx_native_scope(k->p,k->owner.plan.count,true))f|=2;
 if(k->config&&k->config->mmio_complete)f|=4;
 if(k->rid_attempted&&p->iommu_ready)f|=8;
 if(k->msi_attempted&&p->msi_domain_ready)f|=16;
 if(k->sealed)f|=32;
 if(k->published&&k->published_count==k->owner.plan.count)f|=64;
 if(f!=127||k->failed||k->owner.failed||!k->owner.complete||k->owner.status||k->task||
    p->retained_phase!=40||!jmn_root_valid(k,true)||!k->owner.completed_ns||
    k->owner.completed_ns>=k->deadline||k->prepared_ns>=k->owner.completed_ns)goto invalid;
 for(j=0;j<k->owner.plan.count;j++){
  struct pci_dev*d=k->selected[j];const struct jm_client*c=&k->owner.plan.client[j];
  struct apple_j314s_multi_client_report*q=&r->client[j];
  if(!d||k->clients[j].failed||!k->clients[j].dma_ready||!k->clients[j].rid_ready||
     !k->clients[j].irq_ready||!pci_dev_is_added(d)||!k->sealed_groups[j]||
     d->dev.iommu_group!=k->sealed_groups[j])goto invalid;
  r->model[j]=p->j314s_mixed_policy->policy.model[j];
  q->rid=c->identity.rid;q->id=c->identity.id;q->class_rev=c->identity.class_rev;
  q->subsystem=c->identity.subsystem;q->header=c->identity.header;q->serial=c->identity.serial;
  q->sid=c->sid;q->group=iommu_group_id(k->sealed_groups[j]);
  q->boot0[0]=k->config->boot0[j][0];q->boot0[1]=k->config->boot0[j][1];
  for(b=0;b<6;b++){
   q->bars[b].start=k->sealed_bars[j][b].start;q->bars[b].end=k->sealed_bars[j][b].end;
   q->bars[b].flags=k->sealed_bars[j][b].flags;
  }
 }
 r->count=k->owner.plan.count;r->raw_count=k->owner.capture.count;r->path_count=k->owner.plan.path_count;
 r->operations=k->operations;r->completed_ns=k->owner.completed_ns;r->prepared_ns=k->prepared_ns;
 r->original_deadline=k->deadline;r->assignment_ns=((const struct jma_kernel_owner*)k->assignment_receipt)->completed_ns;
 memcpy(r->rid2sid,k->owner.evidence.rid_table,sizeof(r->rid2sid));
 f|=128;*status=0;goto out;
invalid:if(!*status)*status=-ESTALE;
out:*flags=f;mutex_unlock(&p->lifecycle);return 0;
}
EXPORT_SYMBOL_GPL(apple_apciec_jmx_native_state);
