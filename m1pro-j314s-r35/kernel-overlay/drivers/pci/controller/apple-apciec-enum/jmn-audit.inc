/* Include after supplier's concrete jmc config/claims audit helpers. */
static int jmn_phase_objects(struct jmn_kernel*k,enum jmn_phase phase)
{
 unsigned observed=0;
 if(!k->bridge||k->bridge!=k->p->discovery_bridge||!k->bridge->discovery_only||
    k->bridge->sysdata!=k->p||k->bridge->discovery_dma_device)return -EPERM;
 for(unsigned b=0;b<256;b++)if(k->buses[b]){
  struct pci_dev*d;
  if(k->buses[b]->number!=b||pci_find_host_bridge(k->buses[b])!=k->bridge)return -ESTALE;
  list_for_each_entry(d,&k->buses[b]->devices,bus_list){
   bool found=false;
   for(unsigned j=0;j<k->owner.plan.path_count;j++)if(k->devices[k->owner.plan.path[j]]==d){found=true;break;}
   if(!found||++observed>k->owner.plan.path_count)return -EPERM;
  }
 }
 if(observed!=k->owner.plan.path_count)return -ESTALE;
 for(unsigned j=0;j<k->owner.plan.path_count;j++){
  unsigned raw=k->owner.plan.path[j];struct pci_dev*d=k->devices[raw];
  const struct jm_identity*id=&k->owner.capture.record[raw].identity;
  int selected=jmn_pub_index(k,d);bool published=phase>=JMN_PUBLISHED;
  if(!d||!device_is_registered(&d->dev)||pci_find_host_bridge(d->bus)!=k->bridge||
     pci_dev_id(d)!=id->rid||((u32)d->device<<16|d->vendor)!=id->id||
     (d->class<<8|d->revision)!=id->class_rev||d->hdr_type!=(id->header&127)||
     !!d->multifunction!=!!(id->header&128)||d->is_virtfn||pci_num_vf(d)||d->ari_enabled||
     (id->serial&&pci_get_dsn(d)!=id->serial))return -ESTALE;
  if(!d->hdr_type&&((u32)d->subsystem_device<<16|d->subsystem_vendor)!=id->subsystem)return -ESTALE;
  if(selected<0){
   if(!d->hdr_type||pci_dev_is_added(d)||d->driver||d->dev.driver||!d->non_mappable_bars||
      d->dev.iommu_group||dev_iommu_fwspec_get(&d->dev)||d->discovery_dma_admitted||
      d->discovery_driver_admitted||!!d->discovery_mem_ancestor!=published)return -EPERM;
  }else{
   if(!!pci_dev_is_added(d)!=published||!!d->discovery_driver_admitted!=published||
      d->discovery_mem_ancestor||!!d->non_mappable_bars!=(phase<JMN_MMIO))return -EPERM;
   if(!k->owner.complete&&(d->driver||d->dev.driver||d->is_busmaster))return -EPERM;
   if(phase<JMN_DMA){
    if(d->dev.iommu_group||dev_iommu_fwspec_get(&d->dev)||d->discovery_dma_admitted)return -EPERM;
   }else if(!d->discovery_dma_admitted)return -EPERM;
  }
 }
 return 0;
}
static int jmn_phase_audit(struct jmn_kernel*k,enum jmn_phase phase)
{
 int ret;
 lockdep_assert_held(&k->p->lifecycle);
 if(!jmn_kvalid(k,true)||phase==JMN_FAILED||k->owner.failed)return -EPERM;
 if(phase==JMN_EMPTY)return k->ops->blocked(k);
 ret=jmn_phase_objects(k,phase);if(ret)return ret;
 ret=jmn_callback_config_audit(k,phase);if(ret)return ret;
 if(phase>=JMN_CLAIMS){ret=jmn_callback_claims_audit(k);if(ret)return ret;}
 if(phase<JMN_DMA){
  if(k->p->native||k->p->iommu_ready||k->p->msi_domain_ready)return -EPERM;
  ret=retained_dma_blocked(k->p);if(ret)return ret;
  for(unsigned j=0;j<64;j++)if(readl(k->p->port+APCIEC_RID2SID+4*j))return -ESTALE;
 }else{
  ret=jmn_hw_dma_audit(k);if(ret)return ret;
  for(unsigned j=0;j<64;j++)if(readl(k->p->port+APCIEC_RID2SID+4*j)!=k->owner.plan.rid2sid[j])return -ESTALE;
 }
 if(phase>=JMN_MSI){
  struct apciec_native_msi*m=k->clients[0].msi;u32 cfg;
  if(!m||!m->exact_multi||m->pair||m->exact_single||m->multi_count!=k->owner.plan.count||
     m->multi_owner!=k||m->multi_validate!=jmn_hw_msi_valid||!an_msi_pair_ready(m)||
     m->domain!=k->msi_domain||m->aic_kind!=APCIEC_AIC2||m->aic_die||m->aic_base!=jmx_native_base(k->p))return -EPERM;
  if(readl(k->p->port+APCIEC_MSIBASE)||readl(k->p->port+APCIEC_MSIADDR)!=0xfffff000)return -ESTALE;
  cfg=readl(k->p->port+APCIEC_MSICFG);
  if(cfg&&(!k->owner.complete||cfg!=0x51))return -ESTALE;
  for(unsigned j=0;j<k->owner.plan.count;j++)if(m->multi_clients[j]!=&k->clients[j]||
     k->clients[j].target!=k->selected[j]||dev_get_msi_domain(&k->selected[j]->dev)!=m->domain)return -EPERM;
 }
 if(phase>=JMN_SEALED){
  if(!k->sealed||jmn_owner_slot(k,true)!=k)return -EPERM;
  for(unsigned j=0;j<k->owner.plan.count;j++){
   struct pci_dev*d=k->selected[j];
   if(d->dev.iommu_group!=k->sealed_groups[j]||iommu_get_domain_for_dev(&d->dev)!=k->sealed_domains[j])return -ESTALE;
   for(unsigned b=0;b<PCI_NUM_RESOURCES;b++){
    const struct resource*a=&d->resource[b],*r=&k->sealed_bars[j][b];
    if(a->start!=r->start||a->end!=r->end||a->flags!=r->flags||a->parent!=r->parent)return -ESTALE;
   }
  }
 }
 if(phase==JMN_PUBLISHED&&(!k->published||k->published_count!=k->owner.plan.count||
    k->publication_active||k->p->retained_phase!=40||!k->bridge->preserve_config||
    k->bridge->enable_device!=jmn_pub_enable||k->bridge->disable_device!=jmn_pub_disable||
    k->bridge->discovery_driver_device))return -EPERM;
 return 0;
}
static void __maybe_unused jmn_install_audit_ops(struct jmn_kernel_ops*ops)
{ops->audit=jmn_phase_audit;}
