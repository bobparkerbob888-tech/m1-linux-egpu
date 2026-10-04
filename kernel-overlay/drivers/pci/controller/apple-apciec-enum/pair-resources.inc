/* SPDX-License-Identifier: GPL-2.0 */
/* Included after endpoint-resource.inc. All owners survive any failure. */
#include "pair-resource-plan.h"
#include "pair-assignment-core.h"
static void pn_select(struct ep_context *c,struct ep_io *io,struct ep_snapshot *s)
{
 c->rid=s->functions[s->selected].identity.rid;c->p->endpoint_selected_rid=c->rid;
 io->selected=&s->functions[s->selected].identity;
 io->selected_serial_offset=s->functions[s->selected].serial_offset;
}
static int pn_assignment_audit(void *ctx)
{
 struct tn_assignment_context *a=ctx;struct apple_apciec *p=a->ep->p;int r;
 if(!pn_mode(p)||!retained_ep_valid(a->ep)||a->ep->phase!=13||
  tn_owner_validate(p)||p->pair_assignment_steps>PN_ASSIGN_WRITES)return -EPERM;
 r=retained_ep_budget(p,NSEC_PER_SEC,512);if(r)return r;
 pn_select(a->ep,a->io,p->pair_secondary_snapshot);
 r=ep_selected_recheck(a->io,0x300);
 pn_select(a->ep,a->io,p->endpoint_snapshot);
 if(r)return r;
 r=ep_selected_recheck(a->io,0x600);if(r)return r;
 r=retained_ep_safe(a->ep,0x600);if(r)return r;
 r=retained_identity_port_audit(p,true);if(r)return r;
 return retained_root_rc_audit(p);
}
static int pn_assignment_write(void *ctx,unsigned rid,unsigned off,u32 value)
{
 struct tn_assignment_context *a=ctx;struct apple_apciec *p=a->ep->p;
 struct pci_bus bus={.number=rid>>8,.sysdata=p,.ops=&apple_apciec_ops};
 unsigned long flags;u32 clock=0;bool pfm=rid==0&&(off==0x24||off==0x28||off==0x2c);int r;
 r=pn_assignment_audit(ctx);if(r)return r;
 if(!pn_expected_write(p->pair_assignment_steps,rid,off,value))return -EPERM;
 raw_spin_lock_irqsave(&p->lock,flags);
 if(p->endpoint_assignment_armed){raw_spin_unlock_irqrestore(&p->lock,flags);return -EPERM;}
 p->endpoint_assignment_armed=true;raw_spin_unlock_irqrestore(&p->lock,flags);
 if(pfm){
  p->retained_scan_ops+=6;clock=readl(p->port+0x800);
  if(clock==~0U||!(clock&BIT(0))||(clock&BIT(8))){r=-EIO;goto unarm;}
  writel(clock|BIT(8),p->port+0x800);
  if(readl(p->port+0x800)!=(clock|BIT(8))){r=-EIO;goto restore;}
 }
 r=apple_apciec_config_write(&bus,rid&255,off,4,value)==PCIBIOS_SUCCESSFUL?0:-EIO;
 if(!r&&pfm)writel(1,p->port+apple_apciec_logical_offset(p,0x994));
restore:
 if(pfm){writel(clock,p->port+0x800);if(readl(p->port+0x800)!=clock)r=-EIO;}
unarm:
 raw_spin_lock_irqsave(&p->lock,flags);p->endpoint_assignment_armed=false;raw_spin_unlock_irqrestore(&p->lock,flags);
 return r;
}
static int pn_assignment_final(struct tn_assignment_context *a)
{
 unsigned step,rid,off,j;u32 want,got;int r;
 for(step=0;step<PN_ASSIGN_WRITES;step++){
  pn_write_at(step,&rid,&off,&want);r=ep_read(a->io,rid,off,&got);if(r)return r;if(got!=want)return -EIO;
 }
 for(j=0;j<2;j++){
  rid=j?0x300:0x600;r=ep_read(a->io,rid,0x24,&got);if(r)return r;if(got!=1)return -EIO;
 }
 return pn_assignment_audit(a);
}
int apple_apciec_retained_pair_resources(struct device *dev,unsigned port,const void *ticket,
 const struct ep_snapshot **primary,const struct ep_snapshot **secondary,unsigned *phase)
{
 struct apple_apciec *p=dev_get_drvdata(dev);struct ep_context c;struct ep_io io;
 struct tn_assignment_context a;struct pn_assign_io ops;unsigned long flags;
 unsigned j,k;int r;bool consumed=false;
 if(primary)*primary=NULL;
 if(secondary)*secondary=NULL;
 if(phase)*phase=0;
 if(!p||!primary||!secondary||!phase)return -EINVAL;
 mutex_lock(&p->lifecycle);
 r=retained_commit_owner(p,port,ticket,10);if(r)goto out;
 if(!pn_mode(p)||!endpoint_resources||!endpoint_memory_assign||!p->retained_raw_identity||
  !p->tunnel_ready||p->bridge||p->endpoint_snapshot||p->pair_secondary_snapshot||p->retained_record_count!=8){r=-EPERM;goto out;}
 for(j=0;j<8;j++)if(p->retained_records[j].rid!=pn_positions[j].rid){r=-EPERM;goto out;}
 if(!pn_serial_ok(0x600,p->retained_records[7].serial)||!pn_serial_ok(0x300,p->retained_records[3].serial)){r=-ESTALE;goto out;}
 consumed=true;p->retained_phase=11;
 r=retained_ep_budget(p,3ULL*NSEC_PER_SEC,4096);if(r)goto fail;
 p->endpoint_snapshot=kvzalloc(sizeof(*p->endpoint_snapshot),GFP_KERNEL);
 p->pair_secondary_snapshot=kvzalloc(sizeof(*p->pair_secondary_snapshot),GFP_KERNEL);
 if(!p->endpoint_snapshot||!p->pair_secondary_snapshot){r=-ENOMEM;goto fail;}
 p->endpoint_selected_rid=0x600;p->endpoint_sizing=true;
 c=(struct ep_context){p,ticket,0x600,true,11};
 r=retained_dma_blocked(p);if(r)goto fail;r=tn_aperture_descriptor(p);if(r)goto fail;
 io=(struct ep_io){.ctx=&c,.read=retained_ep_read,.write=retained_ep_write,
 .safe=retained_ep_safe,.probe_ready=retained_ep_probe_ready,.valid=retained_ep_valid,
 .now=retained_raw_clock,.deadline=p->retained_scan_deadline,.records=p->retained_records,
 .count=8,.root_rid=(unsigned)p->bus_start<<8};
 raw_spin_lock_irqsave(&p->lock,flags);p->retained_scan_task=current;raw_spin_unlock_irqrestore(&p->lock,flags);
 /* Capture both before either probe, preserving both immutable original views. */
 for(j=0;j<2;j++){
  struct ep_snapshot *s=j?p->pair_secondary_snapshot:p->endpoint_snapshot;
  unsigned idx=j?3:7,other=j?7:3;u32 v;
  c.rid=p->retained_records[idx].rid;p->endpoint_selected_rid=c.rid;
  r=retained_ep_safe(&c,c.rid);if(r)goto fail;
  r=ep_capture(&io,&p->retained_records[idx],s);if(r)goto fail;
  /* ep_capture appends BAR samples only on selected GPU; complete the other
   * function's samples so both captures can be compared without exceptions. */
  for(k=0;k<6;k++){r=ep_sample_read(&io,&s->functions[other],0x10+4*k,&v);if(r)goto fail;}
 }
 for(j=0;j<2;j++){
  struct ep_snapshot *s=j?p->pair_secondary_snapshot:p->endpoint_snapshot;
  pn_select(&c,&io,s);
  r=ep_size_bars_policy(&io,s,io.selected,pn_io_slot_policy);if(r)goto fail;
 }
 r=pn_resource_plan(p->endpoint_snapshot,p->pair_secondary_snapshot);if(r)goto fail;
 pn_select(&c,&io,p->endpoint_snapshot);
 r=tn_owner_prepare(&c);if(r)goto fail;
 a=(struct tn_assignment_context){&c,&io};
 ops=(struct pn_assign_io){&a,pn_assignment_audit,tn_assignment_read,pn_assignment_write};
 r=pn_assign_memory(&ops,p->endpoint_snapshot,p->pair_secondary_snapshot);if(r)goto fail;
 if(p->pair_assignment_steps!=PN_ASSIGN_WRITES){r=-EIO;goto fail;}
 r=pn_assignment_final(&a);if(r)goto fail;
 if(p->retained_scan_exhausted||ktime_get_boottime_ns()>=io.deadline){r=-ETIMEDOUT;goto fail;}
 p->endpoint_snapshot->memory_assigned=true;p->pair_secondary_snapshot->memory_assigned=true;
 p->retained_phase=14;*primary=p->endpoint_snapshot;*secondary=p->pair_secondary_snapshot;
 dev_info(p->dev,"pair-resources: phase14 targets0600/%016llx 0300/%016llx assigned; decode/DMA disabled\n",
  p->retained_records[7].serial,p->retained_records[3].serial);goto finish;
fail:
 p->retained_failed=true;if(p->endpoint_owner)p->endpoint_owner->failed=true;
 dev_info(p->dev,"pair-resources: status%d phase%u retained; no retry\n",r,p->retained_phase);
finish:
 raw_spin_lock_irqsave(&p->lock,flags);
 p->retained_scan_task=NULL;p->endpoint_sizing=false;p->endpoint_assignment_armed=false;
 raw_spin_unlock_irqrestore(&p->lock,flags);
out:
 if(consumed)*phase=p->retained_phase;
 mutex_unlock(&p->lifecycle);return r;
}
EXPORT_SYMBOL_GPL(apple_apciec_retained_pair_resources);
