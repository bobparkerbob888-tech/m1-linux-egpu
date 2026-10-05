/* Runs under consumed phase13, same host ticket and original deadline. */
#include "target-assignment-core.h"
struct tn_assignment_context{struct ep_context *ep;struct ep_io *io;};
static int tn_assignment_audit(void *ctx)
{
 struct tn_assignment_context *a=ctx;struct apple_apciec *p=a->ep->p;int r;
 if(!retained_ep_valid(a->ep)||a->ep->phase!=13||a->ep->rid!=0x600||
  !p->profile||p->profile->index!=1||tn_owner_validate(p)||p->tn_assignment_steps>25)return -EPERM;
 r=retained_ep_budget(p,NSEC_PER_SEC,512);if(r)return r;
 r=ep_selected_recheck(a->io,0x600);if(r)return r;
 r=retained_ep_safe(a->ep,0x600);if(r)return r;
 r=retained_identity_port_audit(p,true);if(r)return r;
 return retained_root_rc_audit(p);
}
static int tn_assignment_read(void *ctx,unsigned rid,unsigned off,u32 *v)
{struct tn_assignment_context *a=ctx;return ep_read(a->io,rid,off,v);}
static int tn_assignment_write(void *ctx,unsigned rid,unsigned off,u32 v)
{
 struct tn_assignment_context *a=ctx;struct apple_apciec *p=a->ep->p;
 struct pci_bus bus={.number=rid>>8,.sysdata=p,.ops=&apple_apciec_ops};
 unsigned long flags;u32 clock=0;bool pfm=rid==0&&(off==0x24||off==0x28||off==0x2c);int r;
 r=tn_assignment_audit(ctx);if(r)return r;
 if(!tn_expected_write(p->tn_assignment_steps,rid,off,v))return -EPERM;
 raw_spin_lock_irqsave(&p->lock,flags);
 if(p->endpoint_assignment_armed){raw_spin_unlock_irqrestore(&p->lock,flags);return -EPERM;}
 p->endpoint_assignment_armed=true;raw_spin_unlock_irqrestore(&p->lock,flags);
 if(pfm) {
  p->retained_scan_ops+=6;clock=readl(p->port+0x800);
  if(clock==~0U||!(clock&BIT(0))||(clock&BIT(8))){r=-EIO;goto unarm;}
  writel(clock|BIT(8),p->port+0x800);
  if(readl(p->port+0x800)!=(clock|BIT(8))){r=-EIO;goto restore;}
 }
 r=apple_apciec_config_write(&bus,rid&255,off,4,v)==PCIBIOS_SUCCESSFUL?0:-EIO;
 if(!r&&pfm)writel(1,p->port+apple_apciec_logical_offset(p,0x994));
restore:
 if(pfm){writel(clock,p->port+0x800);if(readl(p->port+0x800)!=clock)r=-EIO;}
unarm:
 raw_spin_lock_irqsave(&p->lock,flags);p->endpoint_assignment_armed=false;raw_spin_unlock_irqrestore(&p->lock,flags);
 return r;
}
static int tn_assignment_final(struct tn_assignment_context *a)
{
 unsigned j,k,type;u32 got,want;u64 pci,cpu,size;int r;
 for(j=0;j<7;j++)if(tn_positions[j].forwarding)for(k=0x20;k<=0x2c;k+=4){
  if(!tn_window(tn_positions[j].rid,k,&want))return -EINVAL;
  r=ep_read(a->io,tn_positions[j].rid,k,&got);if(r)return r;if(got!=want)return -EIO;
 }
 for(j=0;j<6;j++)if(tn_bar(j,&pci,&cpu,&size,&type)){
  r=ep_read(a->io,0x600,0x10+4*j,&got);if(r)return r;if(got!=((u32)pci|type))return -EIO;
  if(type&4){r=ep_read(a->io,0x600,0x14+4*j,&got);if(r)return r;if(got!=(pci>>32))return -EIO;}
 }
 r=ep_read(a->io,0x600,0x24,&got);if(r)return r;if(got!=1)return -EIO;
 r=ep_read(a->io,0x200,0x18,&got);if(r)return r;if(got&0xffffff)return -EIO;
 return tn_assignment_audit(a);
}
static int tn_assign_retained(struct ep_context *c,struct ep_io *io)
{
 struct apple_apciec *p=c->p;struct tn_assignment_context a={c,io};
 struct tn_assign_io ops={&a,tn_assignment_audit,tn_assignment_read,tn_assignment_write};int r;
 if(!p->profile||p->profile->index!=1||!c->sizing||c->rid!=0x600||
   !p->endpoint_snapshot->planned||p->tn_assignment_steps)return -EPERM;
 r=tn_owner_prepare(c);if(r)return r;
 r=tn_assign_memory(&ops,p->endpoint_snapshot);if(r)return r;
 if(p->tn_assignment_steps!=25)return -EIO;
 return tn_assignment_final(&a);
}
