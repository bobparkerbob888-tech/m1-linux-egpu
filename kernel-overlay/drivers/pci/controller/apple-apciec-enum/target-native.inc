int apple_apciec_retained_transit_native_prepare(struct device*,unsigned,const void*,unsigned*);
int apple_apciec_retained_transit_native_audit(struct device*,unsigned,const void*);
extern int apple_dart_native_transit_audit(struct device*,struct device*,struct device*);
/* SPDX-License-Identifier: GPL-2.0 */
/* Controller1 only. All partial ownership is retained until normal reboot.
 * Include after native-host.inc. No broad PCI scan or excluded bus3 access. */
static const unsigned tn_ancestors[5]={0,1,3,4,5};
static bool tn_host(struct apple_apciec*p)
{return p&&p->profile==&apciec_profiles[1];}
static const struct ep_function *tn_function(struct apple_apciec*p,unsigned rid)
{
 int j=tn_index(rid);
 if(j<0||!p->endpoint_snapshot||p->endpoint_snapshot->count!=7||
    p->endpoint_snapshot->functions[j].identity.rid!=rid)return NULL;
 return &p->endpoint_snapshot->functions[j];
}
static int tn_read(struct apple_apciec*p,unsigned rid,unsigned off,unsigned size,u32*v)
{
 struct pci_bus bus={.number=rid>>8,.sysdata=p,.ops=&apple_apciec_ops};
 return apple_apciec_config_read(&bus,rid&255,off,size,v)?-EIO:0;
}
static int tn_write(struct apple_apciec*p,unsigned rid,unsigned off,unsigned size,u32 v)
{
 struct pci_bus bus={.number=rid>>8,.sysdata=p,.ops=&apple_apciec_ops};u32 got;int ret;
 ret=apple_apciec_config_write(&bus,rid&255,off,size,v);
 if(!ret)ret=apple_apciec_config_read(&bus,rid&255,off,size,&got);
 return ret?-EIO:got==v?0:-ESTALE;
}
static int tn_config_locked(struct pci_bus*bus,unsigned devfn,int where,int size,u32*v,bool write)
{
 struct apple_apciec*p=bus->sysdata;unsigned rid=(bus->number<<8)|devfn;
 const struct ep_function*f;u32 old;int ret,j;bool allowed=false;
 lockdep_assert_held(&p->lock);
 if(!tn_host(p)||!p->native||!p->native->active||p->native->failed||
    !(f=tn_function(p,rid))||!apple_apciec_map_bus(bus,devfn,where))
  return PCIBIOS_DEVICE_NOT_FOUND;
 j=tn_index(rid);
 if(write){
  ret=pci_generic_config_read(bus,devfn,where,size,&old);if(ret)return ret;
  if(p->retained_phase==19&&p->discovery_task==current&&
     ktime_get_boottime_ns()<p->discovery_deadline){
   if(where==PCI_COMMAND&&size==2)
    allowed=old==0&&*v==tn_initial_command(rid)&&*v!=0;
   if(tn_positions[j].forwarding&&f->acs&&where==f->acs+PCI_ACS_CTRL&&size==2)
    allowed=old==0&&*v==(PCI_ACS_SV|PCI_ACS_RR|PCI_ACS_CR|PCI_ACS_UF)&&
      (f->acs_bits&*v)==*v;
  }else if(p->retained_phase==20){
   allowed=an_write_for(p->native,f,tn_positions[j].forwarding||j==6,j==6,
                        where,size,old,*v);
   /* No config write ever reaches the excluded local bridge. */
  }
  if(!allowed)return PCIBIOS_SET_FAILED;
 }
 p->native->config_ops++;
 ret=write?pci_generic_config_write(bus,devfn,where,size,*v):
           pci_generic_config_read(bus,devfn,where,size,v);
 if(write&&rid==0x600&&!ret&&size==4)an_pbi_written(p->native,f,where,*v);
 return ret;
}
static int tn_target_identity(struct apple_apciec*p)
{
 struct pci_dev*d=p->native?p->native->target:NULL;
 const struct ep_function*f=tn_function(p,0x600);
 if(!tn_host(p)||!d||!f||!f->identity.serial||d!=p->discovery_devices[6]||
    pci_dev_id(d)!=0x600||d->vendor!=0x10de||d->device!=0x2d04||
    d->subsystem_vendor!=0x1458||d->subsystem_device!=0x41cd||
    d->class!=0x030000||d->revision!=0xa1||
    pci_get_dsn(d)!=f->identity.serial||
    pci_find_host_bridge(d->bus)!=p->discovery_bridge||
    !p->discovery_bridge->discovery_only)return -ESTALE;
 return 0;
}
static int tn_alias(struct pci_dev*d,u16 alias,void*arg)
{
 struct apple_apciec*p=arg;
 if(d!=p->native->target||alias!=0x600||p->native->aliases)return -EPERM;
 p->native->aliases++;return 0;
}
static int tn_dma_audit(struct apple_apciec*p)
{
 struct device*d=&p->native->target->dev;
 struct iommu_fwspec*fw=dev_iommu_fwspec_get(d);
 struct iommu_domain*domain=iommu_get_domain_for_dev(d);
 if(tn_target_identity(p)||!d->iommu_group||!domain||domain->type!=IOMMU_DOMAIN_DMA||
    !fw||fw->iommu_fwnode!=of_fwnode_handle(p->retained_dart_node)||fw->num_ids||
    dev_is_dma_coherent(d)||domain->pgsize_bitmap!=0x4000||
    !domain->geometry.force_aperture||domain->geometry.aperture_start||
    domain->geometry.aperture_end!=0xffffffffULL)return -EPERM;
 return apple_dart_native_transit_audit(p->dev,&p->dart->dev,d);
}
static int tn_firmware_prepare(struct apple_apciec*p)
{
 struct device_node*aic;__be32 map[4],mask=cpu_to_be32(0xffff),ranges[5];int ret;
 if(!p->retained_dart_node||!p->retained_dart_node->phandle)return -EINVAL;
 aic=of_find_node_by_path("/soc/interrupt-controller@23b100000");
 if(!aic||!aic->phandle||!of_device_is_compatible(aic,"apple,t8103-aic")){
  of_node_put(aic);return -EINVAL;}
 map[0]=cpu_to_be32(0x600);map[1]=cpu_to_be32(p->retained_dart_node->phandle);
 map[2]=map[3]=cpu_to_be32(1);
 ranges[0]=cpu_to_be32(aic->phandle);ranges[1]=0;ranges[2]=cpu_to_be32(818);
 ranges[3]=cpu_to_be32(IRQ_TYPE_EDGE_RISING);ranges[4]=cpu_to_be32(32);of_node_put(aic);
 of_changeset_init(&p->native->firmware);
 ret=an_add_property(p,"iommu-map",map,sizeof(map));
 if(!ret)ret=an_add_property(p,"iommu-map-mask",&mask,sizeof(mask));
 if(!ret)ret=an_add_property(p,"msi-ranges",ranges,sizeof(ranges));
 if(!ret)ret=an_add_property(p,"msi-controller",NULL,0);
 if(!ret)ret=an_add_property(p,"dma-noncoherent",NULL,0);
 if(!ret)ret=an_add_property(p,"research,native-endpoint-memory-only",NULL,0);
 if(!ret)ret=of_changeset_apply(&p->native->firmware);
 return ret;
}
static int tn_device_audit(struct apple_apciec*p,unsigned i)
{
 struct pci_dev*d=p->discovery_devices[i];const struct ep_function*f=tn_function(p,tn_positions[i].rid);
 if(!d||!f||pci_dev_id(d)!=f->identity.rid||d->vendor!=(f->identity.id&65535)||
    d->device!=(f->identity.id>>16)||d->class!=(f->identity.class_rev>>8)||
    d->revision!=(f->identity.class_rev&255)||d->hdr_type!=(f->identity.header&127)||
    d->multifunction!=!!(f->identity.header&128)||d->driver||d->dev.driver||
    !d->non_mappable_bars||d->is_busmaster||d->is_physfn||d->is_virtfn||d->ari_enabled||
    dev_iommu_fwspec_get(&d->dev)||d->dev.iommu_group||
    !device_is_registered(&d->dev)||pci_get_dsn(d)!=f->identity.serial||
    pci_find_host_bridge(d->bus)!=p->discovery_bridge)return -EPERM;
 if(i==6&&((d->subsystem_device<<16)|d->subsystem_vendor)!=f->identity.subsystem)return -ESTALE;
 return 0;
}
static int tn_claim_tree(struct apple_apciec*p,bool claim,bool before_driver)
{
 unsigned kind,depth,b;int ret;struct resource*parent[2]={&p->endpoint_owner->resources[1],&p->endpoint_owner->resources[0]};
 for(depth=0;depth<5;depth++)for(kind=0;kind<2;kind++){
  unsigned idx=kind?PCI_BRIDGE_PREF_MEM_WINDOW:PCI_BRIDGE_MEM_WINDOW;
  struct pci_dev*d=p->discovery_devices[tn_ancestors[depth]];struct resource*r=&d->resource[idx];
  u64 start=kind?0x580000000ULL:0x604000000ULL,end=kind?0x591ffffffULL:0x607ffffffULL;
  if(r->start!=start||r->end!=end||!(r->flags&IORESOURCE_MEM)||
     !!(r->flags&IORESOURCE_PREFETCH)!=!!kind)return -ESTALE;
  if(claim){if(r->parent)return -EEXIST;ret=pci_claim_resource(d,idx);if(ret)return ret;}
  if(r->parent!=parent[kind]||parent[kind]->child!=r||r->sibling)return -EPERM;
  parent[kind]=r;
 }
 for(b=0;b<6;b++){
  const struct ep_bar*bar=&p->endpoint_snapshot->bars[b];struct resource*r=&p->discovery_devices[6]->resource[b];
  if(b==2||b==4){if(r->flags)return -EPERM;continue;}
  if(b==5){if(r->parent)return -EPERM;continue;}
  kind=b!=0;
  if(r->start!=bar->cpu||resource_size(r)!=bar->size||!(r->flags&IORESOURCE_MEM)||
     !!(r->flags&IORESOURCE_PREFETCH)!=!!kind||!!(r->flags&IORESOURCE_MEM_64)!=!!kind||
     (r->flags&(IORESOURCE_UNSET|IORESOURCE_DISABLED)))return -ESTALE;
  if(claim){if(r->parent)return -EEXIST;ret=pci_claim_resource(p->discovery_devices[6],b);if(ret)return ret;}
  if(r->parent!=parent[kind]||(before_driver&&r->child))return -EPERM;
 }
 if(parent[0]->child!=&p->discovery_devices[6]->resource[0]||
    p->discovery_devices[6]->resource[0].sibling||
    parent[1]->child!=&p->discovery_devices[6]->resource[1]||
    p->discovery_devices[6]->resource[1].sibling!=&p->discovery_devices[6]->resource[3]||
    p->discovery_devices[6]->resource[3].sibling||p->endpoint_owner->resources[2].child||
    p->discovery_devices[6]->resource[PCI_ROM_RESOURCE].parent)return -EPERM;
 return 0;
}
static int tn_hardware_audit(struct apple_apciec*p,bool decoded,bool before_driver)
{
 unsigned j,k;u32 v,want;int ret;
 if(!tn_host(p)||p->discovery_failed||p->discovery_probe.pending||
    !p->power_ready||!p->tunnel_ready)return -EPERM;
 for(j=0;j<7;j++){
  const struct ep_function*f=tn_function(p,tn_positions[j].rid);unsigned rid=tn_positions[j].rid;
  if(!f||(f->devctl2&PCI_EXP_DEVCTL2_ARI))return -EPERM;
  ret=tn_read(p,rid,0,4,&v);if(ret||v!=f->identity.id)return ret?ret:-ESTALE;
  ret=tn_read(p,rid,4,2,&v);if(ret||(decoded?!tn_command_ok(rid,v,before_driver):v!=0))return ret?ret:-EPERM;
  if(j<6){ret=tn_read(p,rid,0x18,4,&v);if(ret||v!=f->buses)return ret?ret:-ESTALE;}
  if(tn_positions[j].forwarding)for(k=0x20;k<=0x2c;k+=4){
   if(!tn_window(rid,k,&want))return -EPERM;
   ret=tn_read(p,rid,k,4,&v);if(ret||v!=want)return ret?ret:-ESTALE;
  }
 }
 for(j=0;j<5;j++)if(j==0||j==1||j==3){
  const struct ep_bar*b=&p->endpoint_snapshot->bars[j];
  want=(u32)b->pci|(b->saved[0]&15);ret=tn_read(p,0x600,0x10+4*j,4,&v);
  if(ret||v!=want)return ret?ret:-ESTALE;
  if(j){ret=tn_read(p,0x600,0x14+4*j,4,&v);if(ret||v!=(u32)(b->pci>>32))return ret?ret:-ESTALE;}
 }
 return 0;
}
/* Exactly two ordinary PCI BAR0 reads. Mapping stays owned until reboot. */
static int tn_boot0_probe(struct apple_apciec*p)
{
 struct resource*r=&p->native->target->resource[0];u32 v,cached,before,after;unsigned j;int ret;
 if(p->mmio_regs||p->mmio.attempted||p->retained_phase!=19||p->discovery_task!=current||
    !r->parent||r->start!=0x604000000ULL||resource_size(r)!=0x4000000||
    !(r->flags&IORESOURCE_MEM)||(r->flags&(IORESOURCE_IO|IORESOURCE_PREFETCH|
     IORESOURCE_MEM_NONPOSTED|IORESOURCE_UNSET|IORESOURCE_DISABLED)))return -EPERM;
 if(ktime_get_boottime_ns()>=p->discovery_deadline)return -ETIMEDOUT;
 p->mmio.attempted=true;
 ret=tn_hardware_audit(p,true,true);if(ret)return ret;
 for(j=0;j<5;j++){
  const struct ep_function*f=tn_function(p,tn_positions[tn_ancestors[j]].rid);
  if(!f||!f->msi||f->msi<0x40||f->msi>0xfc||(f->msi&3)||f->msix||!f->pcie||!f->pm)return -EPERM;
  ret=md_cached(f,f->msi,&cached);if(ret||(cached&255)!=PCI_CAP_ID_MSI||
     ((cached>>16)&PCI_MSI_FLAGS_ENABLE))return -EPERM;
  ret=tn_read(p,f->identity.rid,f->msi,4,&v);if(ret||v!=cached)return ret?ret:-ESTALE;
  ret=tn_read(p,f->identity.rid,f->pcie+PCI_EXP_DEVCTL,2,&v);if(ret||(v&15))return ret?ret:-EPERM;
  ret=tn_read(p,f->identity.rid,f->pm+PCI_PM_CTRL,2,&v);if(ret||(v&PCI_PM_CTRL_STATE_MASK))return ret?ret:-EPERM;
 }
 p->mmio_regs=pci_iomap_range(p->native->target,0,0,sizeof(u32));
 if(!p->mmio_regs)return -ENOMEM;
 before=readl(p->port+0x100);if(before==~0U)return -ENODEV;
 for(j=0;j<2;j++){
  if(ktime_get_boottime_ns()>=p->discovery_deadline)return -ETIMEDOUT;
  p->mmio_boot0[j]=readl(p->mmio_regs);
 }
 if(ktime_get_boottime_ns()>=p->discovery_deadline)return -ETIMEDOUT;
 after=readl(p->port+0x100);
 dev_info(p->dev,"transit-BOOT0: %08x/%08x INTSTAT%08x->%08x; retained mapping, no retry\n",
          p->mmio_boot0[0],p->mmio_boot0[1],before,after);
 if(after==~0U||((after&~before)&(BIT(26)|BIT(25)|BIT(23)|BIT(21))))return -EIO;
 return mp_boot0_valid(p->mmio_boot0[0],p->mmio_boot0[1])?0:-ENODEV;
}
static int tn_state_audit(struct apple_apciec*p,bool before_driver)
{
 unsigned j,k;u32 v;int ret;
 if(!p->native||!p->native->active||p->native->failed||!p->native->dma_ready||
    !p->native->rid_ready||!p->native->irq_ready||p->native->aliases!=1||
    !mp_boot0_valid(p->mmio_boot0[0],p->mmio_boot0[1])||
    p->discovery_count!=7||p->discovery_bridge->discovery_dma_device!=p->native->target||
    dev_get_msi_domain(&p->native->target->dev)!=p->native->msi->domain)return -EPERM;
 ret=tn_dma_audit(p);if(ret)return ret;
 for(j=0;j<64;j++)if(readl(p->port+APCIEC_RID2SID+4*j)!=(j==1?BIT(31)|BIT(16)|0x600:0))return -ESTALE;
 v=readl(p->port+APCIEC_MSICFG);
 if((v&&v!=0x51)||(before_driver&&v)||readl(p->port+APCIEC_MSIBASE)||
    readl(p->port+APCIEC_MSIADDR)!=0xfffff000)return -ESTALE;
 for(j=0;j<7;j++){
  struct pci_dev*d=p->discovery_devices[j];const struct ep_function*f=tn_function(p,tn_positions[j].rid);
  if(!d||!f||pci_get_dsn(d)!=f->identity.serial)return -ESTALE;
  if(j!=6&&(d->driver||d->dev.driver||d->dev.iommu_group||dev_iommu_fwspec_get(&d->dev)))return -EPERM;
  if(j==2){
   if(d->subordinate)return -EPERM;
   for(k=0;k<PCI_NUM_RESOURCES;k++)if(d->resource[k].parent)return -EPERM;
  }
  if(tn_positions[j].forwarding&&pci_pcie_type(d)==PCI_EXP_TYPE_DOWNSTREAM&&
     !pci_acs_enabled(d,PCI_ACS_SV|PCI_ACS_RR|PCI_ACS_CR|PCI_ACS_UF))return -EPERM;
 }
 if(before_driver&&(p->native->target->driver||p->native->target->dev.driver||p->native->enable_attempted))return -EPERM;
 ret=tn_hardware_audit(p,true,before_driver);
 return ret?ret:tn_claim_tree(p,false,before_driver);
}
static int tn_enable_device(struct pci_host_bridge*b,struct pci_dev*d)
{
 struct apple_apciec*p=b->sysdata;int j,ret;
 if(!tn_host(p)||!p->native||p->native->failed||p->retained_phase!=20||
    !p->native->dma_ready||!p->native->rid_ready||!p->native->irq_ready)return -EPERM;
 j=tn_index(pci_dev_id(d));if(j<0||p->discovery_devices[j]!=d||j==2)return -EPERM;
 ret=tn_dma_audit(p);if(ret)return ret;
 if(j==6){if(p->native->enable_attempted)return -EPERM;p->native->enable_attempted=true;}
 return 0;
}
static void tn_disable_device(struct pci_host_bridge*b,struct pci_dev*d)
{
 struct apple_apciec*p=b->sysdata;
 if(tn_host(p)&&p->native&&p->native->target==d)WRITE_ONCE(p->native->enable_attempted,true);
}
int apple_apciec_retained_transit_native_prepare(struct device*dev,unsigned port,
 const void*ticket,unsigned*phase)
{
 struct apple_apciec*p=dev_get_drvdata(dev);struct resource_entry*e;struct pci_bus*bus;
 struct pci_dev*target;unsigned j;unsigned long flags;int ret;const char*step="admission";bool locked=false;
 if(!p||!phase||!tn_host(p)||!endpoint_native_driver||!endpoint_pci_register)return -EINVAL;
 mutex_lock(&p->lifecycle);
 ret=retained_commit_owner(p,port,ticket,14);if(ret)goto out;
 if(p->native||p->discovery_attempted||p->discovery_bridge||p->retained_scan_task||
    !p->endpoint_snapshot||!p->endpoint_snapshot->memory_assigned||
    p->endpoint_snapshot->count!=7||p->endpoint_snapshot->selected!=6||
    p->endpoint_snapshot->ancestor_count!=5||tn_owner_validate(p)||
    of_find_property(p->dev->of_node,"iommu-map",NULL)||driver_find("nvidia",&pci_bus_type)){
  ret=-EPERM;goto out;}
 if(ktime_get_boottime_ns()+10ULL*NSEC_PER_SEC>=p->retained_identity_deadline){ret=-ETIMEDOUT;goto out;}
 p->discovery_attempted=true;p->retained_phase=15;
 p->discovery_deadline=min(ktime_get_boottime_ns()+30ULL*NSEC_PER_SEC,p->retained_identity_deadline);
 raw_spin_lock_irqsave(&p->lock,flags);p->discovery_task=current;raw_spin_unlock_irqrestore(&p->lock,flags);
 ret=retained_dma_blocked(p);if(!ret)ret=tn_hardware_audit(p,false,true);if(ret)goto failed;
 INIT_LIST_HEAD(&p->discovery_windows);
 p->discovery_bus_resource=(struct resource){.name="J293 transit buses",.start=0,.end=6,.flags=IORESOURCE_BUS};
 for(j=0;j<4;j++){
  e=resource_list_create_entry(j<3?&p->endpoint_owner->resources[j]:&p->discovery_bus_resource,0);
  if(!e){ret=-ENOMEM;goto failed;}
  if(j<3)e->offset=p->endpoint_owner->entries[j]->offset;
  resource_list_add_tail(e,&p->discovery_windows);
 }
 pci_lock_rescan_remove();locked=true;step="exact-scan";
 bus=pci_create_root_bus(p->dev,0,&apple_apciec_ops,p,&p->discovery_windows);
 if(!bus){ret=-ENODEV;goto failed;}
 p->discovery_buses[0]=bus;p->discovery_bridge=pci_find_host_bridge(bus);
 p->discovery_bridge->discovery_only=true;p->discovery_bridge->native_aer=false;
 p->discovery_bridge->native_pcie_hotplug=false;p->discovery_bridge->native_pme=false;p->discovery_bridge->native_dpc=false;
 if(bus->busn_res.start||bus->busn_res.end!=6||!bus->busn_res.parent){ret=-EPERM;goto failed;}
 for(j=0;j<7;j++){
  const struct tn_position*a=&tn_positions[j];struct pci_dev*d;
  ret=tn_hardware_audit(p,false,true);if(ret)goto failed;
  bus=p->discovery_buses[a->rid>>8];if(!bus){ret=-EPERM;goto failed;}
  d=pci_scan_single_device(bus,a->rid&255);p->discovery_devices[j]=d;if(d)p->discovery_count++;
  ret=tn_device_audit(p,j);if(ret)goto failed;
  if(a->forwarding){
   bus=pci_add_new_bus(bus,d,a->secondary);if(!bus){ret=-ENOMEM;goto failed;}
   p->discovery_buses[a->secondary]=bus;
   if(!pci_bus_insert_busn_res(bus,a->secondary,a->subordinate)){ret=-EBUSY;goto failed;}
   pci_read_bridge_bases(bus);
  }
 }
 ret=tn_hardware_audit(p,false,true);if(!ret)ret=tn_claim_tree(p,true,true);if(ret)goto failed;
 step="native-owner";p->native=kzalloc(sizeof(*p->native),GFP_KERNEL);if(!p->native){ret=-ENOMEM;goto failed;}
 target=p->discovery_devices[6];p->native->host=p;p->native->target=pci_dev_get(target);
 p->native->active=true;p->retained_phase=19;
 ret=tn_target_identity(p);if(ret)goto failed;
 ret=pci_for_each_dma_alias(target,tn_alias,p);if(ret||p->native->aliases!=1){ret=ret?ret:-EPERM;goto failed;}
 step="firmware";ret=tn_firmware_prepare(p);if(ret)goto failed;
 p->discovery_bridge->discovery_dma_device=target;
 step="DART";ret=iommu_probe_device(&target->dev);if(!ret)ret=tn_dma_audit(p);if(ret)goto failed;
 p->native->dma_ready=true;
 for(j=0;j<64;j++)if(readl(p->port+APCIEC_RID2SID+4*j)){ret=-ESTALE;goto failed;}
 writel(BIT(31)|BIT(16)|0x600,p->port+APCIEC_RID2SID+4);
 if(readl(p->port+APCIEC_RID2SID+4)!=(BIT(31)|BIT(16)|0x600)){ret=-EIO;goto failed;}
 p->native->rid_ready=true;p->iommu_ready=true;
 step="MSI";ret=an_msi_prepare(p);if(ret)goto failed;
 step="ACS";
 for(j=0;j<7;j++){
  const struct ep_function*f=tn_function(p,tn_positions[j].rid);struct pci_dev*d=p->discovery_devices[j];
  unsigned bits=PCI_ACS_SV|PCI_ACS_RR|PCI_ACS_CR|PCI_ACS_UF;
  if(!tn_positions[j].forwarding||pci_pcie_type(d)!=PCI_EXP_TYPE_DOWNSTREAM)continue;
  if(!f->acs||(f->acs_bits&bits)!=bits||(f->acs_bits>>16)){ret=-EPERM;goto failed;}
  ret=tn_write(p,tn_positions[j].rid,f->acs+PCI_ACS_CTRL,2,bits);if(ret)goto failed;
  if(!pci_acs_enabled(d,bits)){ret=-EPERM;goto failed;}
 }
 step="decode";
 for(j=0;j<7;j++)if(j!=2){
  ret=tn_write(p,tn_positions[j].rid,PCI_COMMAND,2,tn_initial_command(tn_positions[j].rid));if(ret)goto failed;
 }
 p->discovery_bridge->enable_device=tn_enable_device;p->discovery_bridge->disable_device=tn_disable_device;
 p->discovery_bridge->preserve_config=true;
 step="BOOT0";ret=tn_boot0_probe(p);if(ret)goto failed;
 step="prepublication-audit";ret=tn_state_audit(p,true);if(ret)goto failed;
 ret=device_set_driver_override(&target->dev,"apple-apciec-native-pending");
 if(ret||driver_find("nvidia",&pci_bus_type)){ret=ret?ret:-EBUSY;goto failed;}
 p->discovery_bridge->discovery_driver_device=target;
 for(j=0;j<5;j++)WRITE_ONCE(p->discovery_devices[tn_ancestors[j]]->discovery_mem_ancestor,true);
 if(ktime_get_boottime_ns()>=p->discovery_deadline){ret=-ETIMEDOUT;goto failed;}
 p->retained_phase=20;
 step="publication";pci_bus_add_device(target);pm_runtime_forbid(&target->dev);
 if(!pci_dev_is_added(target)||pci_dev_binding_disallowed(target)){ret=-EPERM;goto failed;}
 ret=tn_state_audit(p,true);if(ret)goto failed;
 dev_info(dev,"transit-native: phase20 target%s serial%016llx ready; excluded0300/0301 untouched\n",pci_name(target),(unsigned long long)p->endpoint_snapshot->functions[6].identity.serial);
 goto close;
failed:
 p->discovery_failed=true;if(p->native)p->native->failed=true;
 if(p->discovery_bridge)p->discovery_bridge->discovery_driver_device=NULL;
 dev_err(dev,"transit-native: failed%d phase%u step%s; all owners retained until normal reboot\n",ret,p->retained_phase,step);
close:
 raw_spin_lock_irqsave(&p->lock,flags);p->discovery_task=NULL;raw_spin_unlock_irqrestore(&p->lock,flags);
 if(locked)pci_unlock_rescan_remove();
out:
 *phase=p->retained_phase;mutex_unlock(&p->lifecycle);return ret;
}
EXPORT_SYMBOL_GPL(apple_apciec_retained_transit_native_prepare);
int apple_apciec_retained_transit_native_audit(struct device*dev,unsigned port,const void*ticket)
{
 struct apple_apciec*p=dev_get_drvdata(dev);int ret;
 if(!tn_host(p))return -EINVAL;
 mutex_lock(&p->lifecycle);
 ret=port==3&&p->retained_ticket==ticket&&p->retained_phase==20?tn_state_audit(p,true):-EPERM;
 mutex_unlock(&p->lifecycle);return ret;
}
EXPORT_SYMBOL_GPL(apple_apciec_retained_transit_native_audit);
