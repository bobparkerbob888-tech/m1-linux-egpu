#include "j314s-assignment-plan.h"
#include "j314s-assignment-owner.inc"
static noinline int ja_host_read(struct apple_apciec*p,unsigned rid,unsigned off,u32*v)
{
 struct pci_bus b={.number=rid>>8,.sysdata=p,.ops=&apple_apciec_ops};
 return apple_apciec_config_read(&b,rid&255,off,4,v)==PCIBIOS_SUCCESSFUL?0:-EIO;
}
static int ja_host_match(struct apple_apciec*p,unsigned rid,unsigned off,u32 want,u32 mask)
{u32 v;int ret=ja_host_read(p,rid,off,&v);return ret?ret:((v&mask)==(want&mask)?0:-ESTALE);}
static int ja_host_gate(struct apple_apciec*p,bool windows)
{
 struct j314s_assignment_owner*o=p->j314s_assignment;struct ep_snapshot*s=p->endpoint_snapshot;
 const struct ep_function*f;unsigned j,ari,sriov;u32 v;int ret;
 if(!o||!o->active||o->task!=current||o->failed||o->complete||
    !s||!j314s_ep_schema(s,&o->plan.selected)||s->memory_assigned||
    p->retained_scan_task!=current)return -EPERM;
 ret=retained_commit_owner(p,3,o->ticket,13);if(ret)return ret;
 ret=retained_ep_budget(p,1000000ULL,96);if(ret)return ret;
 if(windows){ret=j314s_assignment_owner_valid(p,true);if(ret)return ret;}
 ret=retained_dma_blocked(p);if(ret)return ret;
 for(j=0;j<s->count;j++){
  f=&s->functions[j];ret=ja_host_match(p,f->identity.rid,4,0,65535);if(ret)return ret;
  ret=ja_host_match(p,f->identity.rid,0,f->identity.id,~0U);if(ret)return ret;
 }
 f=&s->functions[s->selected];
 ret=ja_host_match(p,f->identity.rid,8,f->identity.class_rev,~0U);if(ret)return ret;
 ret=ja_host_match(p,f->identity.rid,12,f->identity.header<<16,0xff0000);if(ret)return ret;
 ret=ja_host_match(p,f->identity.rid,0x2c,f->identity.subsystem,~0U);if(ret)return ret;
 if(f->serial_present){
  ret=ja_host_match(p,f->identity.rid,f->serial_offset+4,(u32)f->identity.serial,~0U);if(ret)return ret;
  ret=ja_host_match(p,f->identity.rid,f->serial_offset+8,f->identity.serial>>32,~0U);if(ret)return ret;
 }
 ret=j314s_cap_offsets(f,&ari,&sriov);if(ret)return ret;
 if(ari){if(!j314s_cap_sample(f,ari+4,&v))return -EINVAL;ret=ja_host_match(p,f->identity.rid,ari+4,v,~0U);if(ret)return ret;}
 if(sriov){if(!j314s_cap_sample(f,sriov+8,&v))return -EINVAL;ret=ja_host_match(p,f->identity.rid,sriov+8,v,65535);if(ret)return ret;
  if(!j314s_cap_sample(f,sriov+0x10,&v))return -EINVAL;
  ret=ja_host_match(p,f->identity.rid,sriov+0x10,v,65535);if(ret)return ret;}
 if(f->pcie){ret=ja_host_match(p,f->identity.rid,f->pcie+0x28,f->devctl2,65535);if(ret)return ret;}
 if(f->msi){ret=ja_host_match(p,f->identity.rid,f->msi,f->msi_control<<16,0xffff0000);if(ret)return ret;}
 if(f->msix){ret=ja_host_match(p,f->identity.rid,f->msix,f->msix_control<<16,0xffff0000);if(ret)return ret;}
 ret=retained_identity_port_audit(p,true);if(ret)return ret;
 return retained_root_rc_audit(p);
}
static int ja_host_reserve(struct apple_apciec*p)
{
 struct j314s_assignment_owner*o=p->j314s_assignment;unsigned j;int ret;
 INIT_LIST_HEAD(&o->private_windows);
 for(j=0;j<3;j++){
  struct resource*r=&o->resources[j];ret=ja_host_gate(p,false);if(ret)return ret;
  *r=(struct resource){.name="J314s retained aperture",.start=ja_window_cpu[j],
   .end=ja_window_cpu[j]+ja_window_size[j]-1,.flags=ja_window_flags[j]};
  o->entries[j]=resource_list_create_entry(r,0);if(!o->entries[j])return -ENOMEM;
  o->entries[j]->offset=ja_window_cpu[j]-ja_window_pci[j];
  resource_list_add_tail(o->entries[j],&o->private_windows);
  ret=ja_host_gate(p,false);if(ret)return ret;
  if(request_resource_conflict(&iomem_resource,r))return -EBUSY;
  o->reserved[j]=true;
 }
 o->ready=true;return ja_host_gate(p,true);
}
static int ja_host_write_step(struct apple_apciec*p)
{
 struct j314s_assignment_owner*o=p->j314s_assignment;const struct ja_step*s=&o->plan.steps[o->execution];
 const struct ja_register*r=&o->plan.regs[s->reg];struct pci_bus b={.number=r->rid>>8,.sysdata=p,.ops=&apple_apciec_ops};
 unsigned long flags;u32 clock=0;bool pfm=!r->rid&&(r->offset==0x24||r->offset==0x28||r->offset==0x2c);int ret;
 ret=ja_host_gate(p,true);if(ret)return ret;
 ret=ja_host_match(p,r->rid,r->offset,s->before,~0U);if(ret)return ret;
 raw_spin_lock_irqsave(&p->lock,flags);o->armed=true;raw_spin_unlock_irqrestore(&p->lock,flags);
 if(pfm){
  ret=retained_ep_budget(p,1000000ULL,6);if(ret)goto unarm;
  p->retained_scan_ops+=6;clock=readl(p->port+0x800);
  if(clock==~0U||!(clock&BIT(0))||(clock&BIT(8))){ret=-EIO;goto unarm;}
  if(ktime_get_boottime_ns()>=o->deadline){ret=-ETIMEDOUT;goto unarm;}
  writel(clock|BIT(8),p->port+0x800);
  if(readl(p->port+0x800)!=(clock|BIT(8))){ret=-EIO;goto restore;}
 }
 ret=apple_apciec_config_write(&b,r->rid&255,r->offset,4,s->value)==PCIBIOS_SUCCESSFUL?0:-EIO;
 if(!ret&&pfm){
  if(ktime_get_boottime_ns()>=o->deadline)ret=-ETIMEDOUT;
  else writel(1,p->port+apple_apciec_logical_offset(p,0x994));
 }
restore:
 /* Restore only this call's transient clock hold even on expiry; this is
  * bounded cleanup, never a new configuration attempt or owner release. */
 if(pfm){writel(clock,p->port+0x800);if(readl(p->port+0x800)!=clock)ret=-EIO;}
unarm:
 raw_spin_lock_irqsave(&p->lock,flags);o->armed=false;raw_spin_unlock_irqrestore(&p->lock,flags);
 if(!ret)ret=ja_host_match(p,r->rid,r->offset,s->value,~0U);
 return ret;
}
int apple_apciec_j314s_assign_resources(struct device*dev,unsigned port,const void*ticket,unsigned*phase);
int apple_apciec_j314s_assign_resources(struct device*dev,unsigned port,const void*ticket,unsigned*phase)
{
 struct apple_apciec*p=dev_get_drvdata(dev);struct j314s_assignment_owner*o=NULL;unsigned j;unsigned long flags;int ret;
 if(!p||!ticket||!phase)return -EINVAL;
 *phase=0;mutex_lock(&p->lifecycle);
 if(!apciec_profile_j314s(p->profile)||p->profile->index||p->j314s_assignment||
    !p->j314s_resource||!p->j314s_resource->complete||p->j314s_resource->failed||
    !p->j314s_raw_capability||!p->endpoint_snapshot||p->bridge||p->native||
    p->iommu_ready||p->msi_domain_ready){ret=-EPERM;goto out;}
 ret=retained_commit_owner(p,port,ticket,12);if(ret)goto out;
 o=kzalloc(sizeof(*o),GFP_KERNEL);if(!o){ret=-ENOMEM;goto out;}
 p->j314s_assignment=o;o->attempted=true;o->ticket=ticket;o->task=current;
 o->deadline=p->retained_scan_deadline;o->status=-EINPROGRESS;p->retained_phase=13;
 ret=ja_plan_build(p->endpoint_snapshot,&p->j314s_resource->selected,&o->plan);if(ret)goto fail;
 raw_spin_lock_irqsave(&p->lock,flags);o->active=true;p->retained_scan_task=current;raw_spin_unlock_irqrestore(&p->lock,flags);
 ret=ja_host_reserve(p);if(ret)goto fail;
 for(j=0;j<o->plan.count;j++){const struct ja_register*r=&o->plan.regs[j];ret=ja_host_match(p,r->rid,r->offset,r->before,~0U);if(ret)goto fail;}
 while(o->execution<o->plan.step_count){ret=ja_host_write_step(p);if(ret)goto fail;}
 for(j=0;j<o->plan.count;j++){const struct ja_register*r=&o->plan.regs[j];ret=ja_host_match(p,r->rid,r->offset,r->after,~0U);if(ret)goto fail;}
 ret=ja_host_gate(p,true);if(ret)goto fail;
 o->completed_ns=ktime_get_boottime_ns();if(o->completed_ns>=o->deadline){ret=-ETIMEDOUT;goto fail;}
 p->endpoint_snapshot->memory_assigned=true;o->complete=true;o->status=0;p->retained_phase=14;goto done;
fail:
 o->failed=true;o->status=ret;p->retained_failed=true;
done:
 raw_spin_lock_irqsave(&p->lock,flags);o->active=false;o->armed=false;p->retained_scan_task=NULL;raw_spin_unlock_irqrestore(&p->lock,flags);
 /* Retain all attempted ownership, resources and hardware state. No retry. */
out:
 *phase=p->retained_phase;mutex_unlock(&p->lifecycle);return ret;
}
EXPORT_SYMBOL_GPL(apple_apciec_j314s_assign_resources);
