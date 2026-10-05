/* One memory-only GB206 register read using current-boot assigned BAR0.
 * One captured+fresh CED/URD baseline clear; new/fatal errors fail retained. */
static int j314s_nm_clean(struct apple_apciec*p)
{
 struct j314s_native_context*n=p->j314s_native;unsigned j;u32 v;int ret;
 for(j=0;j<n->layout.count;j++) {
  const struct ep_function*f=j314s_native_function(p,n->layout.rid[j]);
  ret=j314s_nd_read(p,f->identity.rid,PCI_STATUS,2,&v);if(ret)return ret;
  if(v&(PCI_STATUS_PARITY|PCI_STATUS_SIG_TARGET_ABORT|PCI_STATUS_REC_TARGET_ABORT|
        PCI_STATUS_REC_MASTER_ABORT|PCI_STATUS_SIG_SYSTEM_ERROR|PCI_STATUS_DETECTED_PARITY))return -EIO;
  ret=j314s_nd_read(p,f->identity.rid,f->pcie+PCI_EXP_DEVSTA,2,&v);if(ret)return ret;
  if(v&(PCI_EXP_DEVSTA_CED|PCI_EXP_DEVSTA_NFED|PCI_EXP_DEVSTA_FED|PCI_EXP_DEVSTA_URD))return -EIO;
 }
 return 0;
}
/* R10 observed DevSta CED|URD on upstream/downstream/GPU before decode.
 * Revalidate sameboot capture and all fresh statuses before the first clear.
 * Root/PCI status and NFED/FED must remain clean; no reset/control writes. */
static int j314s_nm_baseline(struct apple_apciec*p)
{
 struct j314s_native_context*n=p->j314s_native;
 u32 before[J314S_NATIVE_PATH_MAX],expected[J314S_NATIVE_PATH_MAX],v,captured;
 unsigned j;int ret;
 if(!j314s_native_actor(p)||n->mmio_next||n->mmio_enabled||n->status_consumed||
    n->status_armed||n->status_pending)return -EPERM;
 for(j=0;j<n->layout.count;j++) {
  const struct ep_function*f=j314s_native_function(p,n->layout.rid[j]);
  if(!j314s_cap_sample(f,f->pcie+PCI_EXP_DEVCTL,&captured))return -EPERM;
  expected[j]=(captured>>16)&15;
  if(expected[j]&~9U)return -EPERM;
  ret=j314s_nd_read(p,f->identity.rid,PCI_STATUS,2,&v);if(ret)return ret;
  if(v&(PCI_STATUS_PARITY|PCI_STATUS_SIG_TARGET_ABORT|PCI_STATUS_REC_TARGET_ABORT|
        PCI_STATUS_REC_MASTER_ABORT|PCI_STATUS_SIG_SYSTEM_ERROR|PCI_STATUS_DETECTED_PARITY))return -EIO;
  ret=j314s_nd_read(p,f->identity.rid,f->pcie+PCI_EXP_DEVSTA,2,&before[j]);if(ret)return ret;
  if((before[j]&15)!=expected[j])return -ESTALE;
 }
 for(j=0;j<n->layout.count;j++)if(expected[j]) {
  const struct ep_function*f=j314s_native_function(p,n->layout.rid[j]);
  ret=retained_dma_blocked(p);if(ret)return ret;
  if(!j314s_native_actor(p))return -ETIMEDOUT;
  n->status_slot=j;n->status_rid=f->identity.rid;n->status_off=f->pcie+PCI_EXP_DEVSTA;
  n->status_before=before[j];n->status_value=expected[j];n->status_armed=true;
  dev_info(p->dev,"J314s baseline W1C RID%04x offset%03x before%04x captured-errors%04x\n",
           f->identity.rid,n->status_off,before[j],expected[j]);
  ret=pci_write_config_word(n->devices[j],n->status_off,expected[j]);
  if(ret||n->status_armed||n->status_pending||!(n->status_consumed&BIT(j)))return ret?-EIO:-EPERM;
 }
 return j314s_nm_clean(p);
}
int apple_apciec_j314s_probe_mmio(struct device*,unsigned,const void*,unsigned*);
int apple_apciec_j314s_probe_mmio(struct device*dev,unsigned port,const void*ticket,unsigned*phase)
{
 struct apple_apciec*p=dev_get_drvdata(dev);struct j314s_native_context*n;
 const struct ep_snapshot*s;unsigned j;unsigned long flags;int ret;
 if(!p||!phase)return -EINVAL;
 mutex_lock(&p->lifecycle);n=p->j314s_native;s=p->endpoint_snapshot;
 ret=retained_commit_owner(p,port,ticket,16);if(ret)goto out;
 if(!n||!n->discovered||n->failed||n->mmio_attempted||n->task||n->probe.pending||
    !j314s_native_target_identity(p)||!s||s->functions[s->selected].identity.id!=0x2d0410de||
    j314s_nd_claims(p,false)){ret=-EPERM;goto out;}
 n->mmio_attempted=true;n->status=-EINPROGRESS;
 n->deadline=min(ktime_get_boottime_ns()+2ULL*NSEC_PER_SEC,p->retained_identity_deadline);
 if(n->deadline<=ktime_get_boottime_ns()+NSEC_PER_SEC){ret=-ETIMEDOUT;goto fail;}
 p->retained_phase=17;
 raw_spin_lock_irqsave(&p->lock,flags);n->task=current;n->ops=0;raw_spin_unlock_irqrestore(&p->lock,flags);
 ret=j314s_nd_hardware(p);if(!ret)ret=j314s_nm_baseline(p);if(ret)goto close;
 ret=j314s_nd_claims(p,false);if(ret)goto close;
 if(!j314s_native_actor(p)||!j314s_native_selected(p)->non_mappable_bars||n->cpu_mapping_permitted){ret=-EPERM;goto close;}
 /* One selected device only: exact assigned CPU resources were proven above.
  * Ancestors and every unselected function remain non-mappable. */
 j314s_native_selected(p)->non_mappable_bars=false;n->cpu_mapping_permitted=true;
 n->bar0=pci_iomap_range(j314s_native_selected(p),0,0,sizeof(u32));
 if(!n->bar0){ret=-ENOMEM;goto close;}
 for(j=0;j<n->layout.count;j++) {
  if(!j314s_native_actor(p)||n->mmio_next!=j||n->command_pending||n->command_armed){ret=-EPERM;goto close;}
  n->command_armed=true;
  ret=pci_write_config_word(n->devices[j],PCI_COMMAND,j==n->layout.selected?
                           PCI_COMMAND_MEMORY:PCI_COMMAND_MEMORY|PCI_COMMAND_MASTER);
  if(ret||n->mmio_next!=j+1||n->command_pending||n->command_armed){ret=ret?-EIO:-EPERM;goto close;}
 }
 ret=j314s_nd_hardware(p);if(!ret)ret=j314s_nm_clean(p);if(ret)goto close;
 for(j=0;j<2;j++) {
  if(!j314s_native_actor(p)){ret=-ETIMEDOUT;goto close;}
  n->ops++;n->boot0[j]=readl(n->bar0);
 }
 if(!j314s_native_actor(p)){ret=-ETIMEDOUT;goto close;}
 ret=mp_boot0_valid(n->boot0[0],n->boot0[1])?0:-ENODEV;
 if(!ret)ret=j314s_nm_clean(p);
 if(!ret)ret=j314s_nd_hardware(p);
 if(!ret)ret=j314s_nd_claims(p,false);
close:
 raw_spin_lock_irqsave(&p->lock,flags);n->task=NULL;raw_spin_unlock_irqrestore(&p->lock,flags);
 if(ret)goto fail;
 n->mmio_complete=true;n->status=0;p->retained_phase=18;goto out;
fail:n->failed=true;n->status=ret;p->retained_failed=true;
out:*phase=p->retained_phase;mutex_unlock(&p->lifecycle);return ret;
}
EXPORT_SYMBOL_GPL(apple_apciec_j314s_probe_mmio);
