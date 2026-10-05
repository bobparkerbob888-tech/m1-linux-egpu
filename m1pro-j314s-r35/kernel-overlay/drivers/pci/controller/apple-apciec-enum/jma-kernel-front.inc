/* Dormant concrete adapter; requires p->j314s_multi_assignment and dispatcher
 * routing before legacy guards. Include after single assignment helpers. */
#include "jma-kernel-normalize.inc"
static int jma_kernel_owner_valid(struct apple_apciec*p,bool empty)
{
 struct jma_kernel_owner*o=p->j314s_multi_assignment;unsigned j;
 if(!o||!o->attempted||!o->ready||o->failed||!o->capture||o->capture!=p->j314s_multi_resource||
    !o->capture->complete||o->capture->failed||o->ticket!=p->retained_ticket||
    o->deadline!=p->retained_scan_deadline||p->retained_failed||
    o->capture->count!=o->plan.assigned.gpus||!jmx_native_scope(p,o->capture?o->capture->count:0,true))return -EPERM;
 for(j=0;j<o->capture->count;j++){
  unsigned idx=o->plan.assigned.selected[j];const struct ep_identity*a=&o->capture->selected[j];
  const struct jm_identity*b;
  if(idx>=o->plan.assigned.count)return -ESTALE;
  b=&o->plan.assigned.record[idx].identity;
  if(a->rid!=b->rid||a->id!=b->id||a->class_rev!=b->class_rev||a->header!=b->header||
     a->subsystem!=b->subsystem||a->serial!=b->serial)return -ESTALE;
 }
 for(j=0;j<2;j++){
  const struct jm_window*w=&o->plan.assigned.window[j];struct resource*r=&o->resources[j];
  if(!o->reserved[j]||!o->entries[j]||r->parent!=&iomem_resource||(empty&&r->child)||
     r->start!=w->cpu||r->end!=w->cpu+w->size-1||
     r->flags!=(IORESOURCE_MEM|(j?(IORESOURCE_PREFETCH|IORESOURCE_MEM_64):0))||
     o->entries[j]->res!=r||o->entries[j]->offset!=w->cpu-w->pci)return -ESTALE;
 }
 if(o->private_windows.next!=&o->entries[0]->node||o->private_windows.prev!=&o->entries[1]->node||
    o->entries[0]->node.prev!=&o->private_windows||o->entries[0]->node.next!=&o->entries[1]->node||
    o->entries[1]->node.prev!=&o->entries[0]->node||o->entries[1]->node.next!=&o->private_windows)return -ESTALE;
 return 0;
}
static bool jma_kernel_map_permit(struct apple_apciec*p,unsigned rid)
{
 struct jma_kernel_owner*o=p->j314s_multi_assignment;unsigned j;
 if(!o||!o->active||o->failed||o->complete||o->task!=current||
    !jmx_native_scope(p,o->capture?o->capture->count:0,true)||!p->j314s_raw_capability||
    !p->retained||!p->power_ready||!p->tunnel_ready||p->iommu_ready||p->msi_domain_ready||
    o->ticket!=p->retained_ticket||o->deadline!=p->retained_scan_deadline||
    o->deadline>p->retained_identity_deadline||p->retained_phase!=13||p->retained_failed||
    p->retained_scan_task!=current||p->retained_scan_exhausted||p->retained_scan_ops>=retained_scan_limit(p)||
    ktime_get_boottime_ns()>=o->deadline)return false;
 for(j=0;j<p->retained_record_count;j++)if(p->retained_records[j].rid==rid)return true;
 return false;
}
static int jma_kernel_config_locked(struct pci_bus*bus,unsigned devfn,int off,int size,u32*v,bool write)
{
 struct apple_apciec*p=bus->sysdata;struct jma_kernel_owner*o=p->j314s_multi_assignment;
 unsigned rid=(bus->number<<8)|devfn;u64 ecam=PCIE_ECAM_OFFSET(bus->number,devfn,off);
 lockdep_assert_held(&p->lock);
 if(size!=4||off<0||off>0xffc||(off&3)||ecam+4>p->ecam_size||!jma_kernel_map_permit(p,rid))return PCIBIOS_DEVICE_NOT_FOUND;
 if(write){const struct jma_write*s;
  if(!o->ready||!o->armed||o->execution>=o->plan.count)return PCIBIOS_SET_FAILED;
  s=&o->plan.writes[o->execution];
  if(rid!=s->rid||(unsigned)off!=s->offset||*v!=s->after)return PCIBIOS_SET_FAILED;
  o->armed=false;o->execution++; /* consume before access */
 }
 p->retained_scan_ops++;
 return write?pci_generic_config_write(bus,devfn,off,4,*v):pci_generic_config_read(bus,devfn,off,4,v);
}
static int jma_k_gate(struct apple_apciec*p,bool windows)
{
 struct jma_kernel_owner*o=p->j314s_multi_assignment;unsigned j;int ret;
 if(!o||!jma_kernel_map_permit(p,o->capture->selected[0].rid))return -EPERM;
 ret=retained_commit_owner(p,3,o->ticket,13);if(ret)return ret;
 ret=retained_ep_budget(p,1000000ULL,96);if(ret)return ret;
 if(windows){ret=jma_kernel_owner_valid(p,true);if(ret)return ret;}
 ret=retained_dma_blocked(p);if(ret)return ret;
 for(j=0;j<p->retained_record_count;j++){
  ret=ja_host_match(p,p->retained_records[j].rid,4,0,65535);if(ret)return ret;
  ret=ja_host_match(p,p->retained_records[j].rid,0,p->retained_records[j].id,~0U);if(ret)return ret;
 }
 for(j=0;j<64;j++)if(readl(p->port+APCIEC_RID2SID+4*j))return -ESTALE;
 if(readl(p->port+APCIEC_MSICFG))return -ESTALE;
 ret=retained_identity_port_audit(p,true);if(ret)return ret;
 return retained_root_rc_audit(p);
}
static int jma_k_audit(struct apple_apciec*p,bool final)
{
 struct jma_kernel_owner*o=p->j314s_multi_assignment;unsigned g,j,k;int ret;
 for(g=0;g<o->capture->count;g++){
  const struct ep_snapshot*s=o->capture->snapshots[g];
  for(j=0;j<s->count;j++){
   const struct ep_function*f=&s->functions[j];
   for(k=0;k<f->sample_count;k++){
    const struct ep_sample*a=&f->samples[k];u32 want=a->value,mask=~0U;unsigned x;
    /* Status halves are W1C/volatile; commands and controls remain audited. */
    if(a->offset==4)mask=65535;
    if(f->pcie&&(a->offset==f->pcie+8||a->offset==f->pcie+0x10||a->offset==f->pcie+0x28))mask=65535;
    if(final)for(x=0;x<o->plan.count;x++)if(o->plan.writes[x].rid==f->identity.rid&&o->plan.writes[x].offset==a->offset)want=o->plan.writes[x].after;
    ret=ja_host_match(p,f->identity.rid,a->offset,want,mask);if(ret)return ret;
   }
  }
 }
 return jma_k_gate(p,true);
}
static int jma_k_write(struct apple_apciec*p)
{
 struct jma_kernel_owner*o=p->j314s_multi_assignment;const struct jma_write*s=&o->plan.writes[o->execution];
 struct pci_bus bus={.number=s->rid>>8,.sysdata=p,.ops=&apple_apciec_ops};
 unsigned long flags;u32 clock=0;bool hold=!s->rid&&(s->offset==0x24||s->offset==0x28||s->offset==0x2c);int ret;
 ret=jma_k_gate(p,true);if(ret)return ret;
 ret=ja_host_match(p,s->rid,s->offset,s->before,~0U);if(ret)return ret;
 raw_spin_lock_irqsave(&p->lock,flags);o->armed=true;raw_spin_unlock_irqrestore(&p->lock,flags);
 if(hold){
  ret=retained_ep_budget(p,1000000ULL,6);if(ret)goto unarm;
  p->retained_scan_ops+=6;clock=readl(p->port+0x800);
  if(clock==~0U||!(clock&BIT(0))||(clock&BIT(8))){ret=-EIO;goto unarm;}
  if(ktime_get_boottime_ns()>=o->deadline){ret=-ETIMEDOUT;goto unarm;}
  writel(clock|BIT(8),p->port+0x800);
  if(readl(p->port+0x800)!=(clock|BIT(8))){ret=-EIO;goto restore;}
 }
 ret=apple_apciec_config_write(&bus,s->rid&255,s->offset,4,s->after)==PCIBIOS_SUCCESSFUL?0:-EIO;
 if(!ret&&hold){if(ktime_get_boottime_ns()>=o->deadline)ret=-ETIMEDOUT;
  else writel(1,p->port+apple_apciec_logical_offset(p,0x994));}
restore:
 if(hold){writel(clock,p->port+0x800);if(readl(p->port+0x800)!=clock)ret=-EIO;}
unarm:
 raw_spin_lock_irqsave(&p->lock,flags);o->armed=false;raw_spin_unlock_irqrestore(&p->lock,flags);
 if(!ret)ret=ja_host_match(p,s->rid,s->offset,s->after,~0U);
 return ret;
}
/* Failure-only immutable input dump: no register access or retry. */
static void jma_dump_input(struct apple_apciec*p,const struct jma_input*in,int status)
{
 const struct jm_capture*c=&in->capture;unsigned j,g,b;
 dev_err(p->dev,"jma-plan-input: status%d controller%u count%u gpus%u\n",status,c->controller,c->count,c->gpus);
 for(j=0;j<2;j++)dev_err(p->dev,"jma-plan-input: window%u pci%016llx cpu%016llx size%016llx\n",j,
  (unsigned long long)c->window[j].pci,(unsigned long long)c->window[j].cpu,(unsigned long long)c->window[j].size);
 for(j=0;j<c->count&&j<JM_MAX_RECORDS;j++){
  const struct jm_record*r=&c->record[j];
  dev_err(p->dev,"jma-plan-input: record%u rid%04x id%08x class%08x subsystem%08x header%02x serial%016llx parent%u buses%u,%u,%u command%08x bridge%08x,%08x,%08x,%08x\n",
   j,r->identity.rid,r->identity.id,r->identity.class_rev,r->identity.subsystem,r->identity.header,
   (unsigned long long)r->identity.serial,r->parent,r->primary,r->secondary,r->subordinate,in->command[j],
   in->bridge[j][0],in->bridge[j][1],in->bridge[j][2],in->bridge[j][3]);
 }
 for(g=0;g<c->gpus&&g<JM_MAX_GPUS;g++){
  dev_err(p->dev,"jma-plan-input: gpu%u selected%u saved%08x,%08x,%08x,%08x,%08x,%08x masks%08x,%08x,%08x,%08x,%08x,%08x\n",g,c->selected[g],
   in->saved[g][0],in->saved[g][1],in->saved[g][2],in->saved[g][3],in->saved[g][4],in->saved[g][5],
   in->mask[g][0],in->mask[g][1],in->mask[g][2],in->mask[g][3],in->mask[g][4],in->mask[g][5]);
  for(b=0;b<3;b++)dev_err(p->dev,"jma-plan-input: gpu%u bar%u pci%016llx cpu%016llx size%016llx window%u\n",g,b?2*b-1:0,
   (unsigned long long)c->bars[g][b].pci,(unsigned long long)c->bars[g][b].cpu,
   (unsigned long long)c->bars[g][b].size,c->bars[g][b].window);
 }
}
static int jma_kernel_assign(struct device*dev,unsigned port,const void*ticket)
{
 struct apple_apciec*p=dev?dev_get_drvdata(dev):NULL;struct jma_kernel_owner*o;
 struct jma_plan*scratch=NULL;struct j314s_multi_resource_owner*m;unsigned j,g,b;unsigned long flags;int ret;const char*stage="normalize";
 if(!p||!ticket)return -EINVAL;
 mutex_lock(&p->lifecycle);m=p->j314s_multi_resource;
 if(!m||!m->complete||m->failed||m->ticket!=ticket||p->j314s_multi_assignment||
    p->j314s_assignment||p->native||p->bridge||p->discovery_bridge||p->iommu_ready||p->msi_domain_ready||
    !jmx_native_scope(p,m->count,false)){ret=-EPERM;goto out;}
 ret=retained_commit_owner(p,port,ticket,12);if(ret)goto out;
 o=kvzalloc(sizeof(*o),GFP_KERNEL);if(!o){ret=-ENOMEM;goto out;}
 p->j314s_multi_assignment=o;o->attempted=true;o->capture=m;o->ticket=ticket;
 o->task=current;o->deadline=p->retained_scan_deadline;o->status=-EINPROGRESS;
 INIT_LIST_HEAD(&o->private_windows);
 ret=jma_k_normalize(p,o);if(ret)goto fail;
 scratch=kvzalloc(sizeof(*scratch),GFP_KERNEL);if(!scratch){ret=-ENOMEM;goto fail;}
 stage="plan";if(p->j314s_mixed_policy){const struct jmx_kernel_policy*b=jmx_binding(p,false);
  ret=b?jma_build_mixed(&o->input,&o->plan,scratch,&b->policy):-EPERM;
 }else ret=jma_build(&o->input,&o->plan,scratch);kvfree(scratch);if(ret){jma_dump_input(p,&o->input,ret);ret=-EINVAL;goto fail;}
 raw_spin_lock_irqsave(&p->lock,flags);o->active=true;p->retained_phase=13;p->retained_scan_task=current;raw_spin_unlock_irqrestore(&p->lock,flags);
 for(j=0;j<2;j++){
  const struct jm_window*w=&o->plan.assigned.window[j];struct resource*r=&o->resources[j];
  stage="reserve-gate";ret=jma_k_gate(p,false);if(ret)goto fail;
  *r=(struct resource){.name="J314s retained joint aperture",.start=w->cpu,.end=w->cpu+w->size-1,
   .flags=IORESOURCE_MEM|(j?(IORESOURCE_PREFETCH|IORESOURCE_MEM_64):0)};
  o->entries[j]=resource_list_create_entry(r,0);if(!o->entries[j]){ret=-ENOMEM;goto fail;}
  o->entries[j]->offset=w->cpu-w->pci;resource_list_add_tail(o->entries[j],&o->private_windows);
  stage="reserve-window";if(request_resource_conflict(&iomem_resource,r)){ret=-EBUSY;goto fail;}o->reserved[j]=true;
 }
 o->ready=true;stage="pre-write-audit";ret=jma_k_audit(p,false);if(ret)goto fail;
 while(o->execution<o->plan.count){unsigned before=o->execution;stage="write-tuple";ret=jma_k_write(p);if(ret){
  const struct jma_write*w=&o->plan.writes[before];
  dev_err(p->dev,"jma-assign: tuple=%u rid=%04x offset=%03x before=%08x after=%08x status=%d consumed=%u\n",before,w->rid,w->offset,w->before,w->after,ret,o->execution);
  goto fail;}
  if(o->execution!=before+1){ret=-ESTALE;goto fail;}}
 stage="post-write-audit";ret=jma_k_audit(p,true);if(ret)goto fail;
 stage="completion";o->completed_ns=ktime_get_boottime_ns();if(o->completed_ns>=o->deadline){ret=-ETIMEDOUT;goto fail;}
 for(g=0;g<m->count;g++){
  struct ep_snapshot*s=m->snapshots[g];
  for(j=0;j<3;j++){const struct jm_bar*a=&o->plan.assigned.bars[g][j];b=j?2*j-1:0;
   s->bars[b].pci=a->pci;s->bars[b].cpu=a->cpu;s->bars[b].window=j?0:1;}
  for(j=0;j<s->ancestor_count;j++){unsigned index=s->ancestors[j];struct ep_bridge_plan*q=&s->bridges[j];
   q->rid=s->functions[index].identity.rid;
   for(b=0;b<2;b++){unsigned w=b?0:1;q->start[w]=o->plan.start[index][b];q->end[w]=o->plan.end[index][b];q->active[w]=!!q->end[w];}}
  s->planned=true;s->memory_assigned=true;
 }
 o->complete=true;o->status=0;p->retained_phase=14;ret=0;goto done;
fail:
 dev_err(p->dev,"jma-assign: stage=%s hostphase=%u status=%d operations=%u execution=%u/%u\n",stage,p->retained_phase,ret,p->retained_scan_ops,o->execution,o->plan.count);
 o->failed=true;o->status=ret;p->retained_failed=true;
done:
 raw_spin_lock_irqsave(&p->lock,flags);o->active=false;o->armed=false;o->task=NULL;p->retained_scan_task=NULL;raw_spin_unlock_irqrestore(&p->lock,flags);
 /* All reservations and partial hardware remain retained until normal reboot. */
out:
 mutex_unlock(&p->lifecycle);return ret;
}

/* Historical immutable receipt: no new permission, task check, MMIO or expiry
 * extension. Caller holds lifecycle; subsequent claims audit the resource tree. */
static const struct jma_kernel_owner*jma_kernel_receipt(struct apple_apciec*p)
{
 struct jma_kernel_owner*o=p->j314s_multi_assignment;unsigned g;
 lockdep_assert_held(&p->lifecycle);
 if(jma_kernel_owner_valid(p,false)||!o->complete||o->active||o->armed||o->status||
    o->execution!=o->plan.count||!o->completed_ns||o->completed_ns>=o->deadline||
    p->retained_failed||p->retained_phase<14)return NULL;
 for(g=0;g<o->capture->count;g++)if(!o->capture->snapshots[g]->planned||
   !o->capture->snapshots[g]->memory_assigned)return NULL;
 return o;
}
