int apple_apciec_retained_pair_native_prepare(struct device*,unsigned,const void*,unsigned*);
int apple_apciec_retained_pair_native_audit(struct device*,unsigned,const void*);
extern int apple_dart_native_pair_audit(struct device*,struct device*,struct device*,struct device*);
/* SPDX-License-Identifier: GPL-2.0 */
/* R54 opt-in controller1 pair only. All partial ownership remains retained.
 * Include after target-native.inc and pair resource policy. No audio access. */
static const unsigned np_ancestors[6]={0,1,4,5,6,2};
static const unsigned np_targets[2]={7,3},np_rids[2]={0x600,0x300};
static struct ep_snapshot *np_snapshot(struct apple_apciec*p,unsigned which)
{return which?p->pair_secondary_snapshot:p->endpoint_snapshot;}
static bool np_is_gpu(unsigned rid){return rid==0x300||rid==0x600;}
static u16 np_initial_command(unsigned rid)
{return pn_initial_command(rid);}
static bool np_command_ok(unsigned rid,u16 v,bool before)
{
 return pn_command_ok(rid,v,before);
}
static struct apciec_native *np_client(struct apple_apciec*p,unsigned rid)
{return !p->pair_native?NULL:rid==0x600?&p->pair_native->clients[0]:rid==0x300?&p->pair_native->clients[1]:NULL;}

static bool np_host(struct apple_apciec*p)
{return pn_mode(p);}
static const struct ep_function *np_function(struct apple_apciec*p,unsigned rid)
{
 int j=pn_index(rid);
 if(j<0||!p->endpoint_snapshot||p->endpoint_snapshot->count!=8||
    p->endpoint_snapshot->functions[j].identity.rid!=rid)return NULL;
 return &p->endpoint_snapshot->functions[j];
}
static int np_read(struct apple_apciec*p,unsigned rid,unsigned off,unsigned size,u32*v)
{
 struct pci_bus bus={.number=rid>>8,.sysdata=p,.ops=&apple_apciec_ops};
 return apple_apciec_config_read(&bus,rid&255,off,size,v)?-EIO:0;
}
static int np_write(struct apple_apciec*p,unsigned rid,unsigned off,unsigned size,u32 v)
{
 struct pci_bus bus={.number=rid>>8,.sysdata=p,.ops=&apple_apciec_ops};u32 got;int ret;
 ret=apple_apciec_config_write(&bus,rid&255,off,size,v);
 if(!ret)ret=apple_apciec_config_read(&bus,rid&255,off,size,&got);
 return ret?-EIO:got==v?0:-ESTALE;
}
static int np_config_locked(struct pci_bus*bus,unsigned devfn,int where,int size,u32*v,bool write)
{
 struct apple_apciec*p=bus->sysdata;unsigned rid=(bus->number<<8)|devfn;
 const struct ep_function*f;struct apciec_native*n;u32 old;int ret,j;bool allowed=false;
 lockdep_assert_held(&p->lock);
 if(!np_host(p)||!p->pair_native||!p->native||!p->native->active||p->native->failed||
    !p->pair_native->clients[1].active||p->pair_native->clients[1].failed||
    !(f=np_function(p,rid))||!apple_apciec_map_bus(bus,devfn,where))return PCIBIOS_DEVICE_NOT_FOUND;
 j=pn_index(rid);n=np_client(p,rid);if(!n)n=p->native;
 if(write){
  ret=pci_generic_config_read(bus,devfn,where,size,&old);if(ret)return ret;
  if(p->retained_phase==29&&p->discovery_task==current&&ktime_get_boottime_ns()<p->discovery_deadline){
   if(where==PCI_COMMAND&&size==2)allowed=old==0&&*v==np_initial_command(rid)&&*v!=0&&
     p->native->dma_ready&&p->pair_native->clients[1].dma_ready&&p->native->rid_ready&&p->pair_native->clients[1].rid_ready;
   if(pn_positions[j].forwarding&&f->acs&&where==f->acs+PCI_ACS_CTRL&&size==2)
    allowed=old==0&&*v==(PCI_ACS_SV|PCI_ACS_RR|PCI_ACS_CR|PCI_ACS_UF)&&(f->acs_bits&*v)==*v;
  }else if(p->retained_phase==30){
   allowed=an_msi_pair_ready(p->native->msi)&&an_write_for(n,f,true,np_is_gpu(rid),where,size,old,*v);
  }
  if(!allowed)return PCIBIOS_SET_FAILED;
 }
 n->config_ops++;
 ret=write?pci_generic_config_write(bus,devfn,where,size,*v):pci_generic_config_read(bus,devfn,where,size,v);
 if(write&&np_is_gpu(rid)&&!ret&&size==4)an_pbi_written(n,f,where,*v);
 return ret;
}
static int np_target_identity(struct apple_apciec*p)
{
 unsigned i;u64 serials[2];
 if(!np_host(p)||!p->pair_native)return -EPERM;
 for(i=0;i<2;i++) {
  struct pci_dev*d=p->pair_native->clients[i].target;const struct ep_function*f=np_function(p,np_rids[i]);
  if(!d||!f||!f->identity.serial||f->identity.serial==~0ULL||d!=p->discovery_devices[np_targets[i]]||
     pci_dev_id(d)!=np_rids[i]||d->vendor!=0x10de||d->device!=0x2d04||
     d->subsystem_vendor!=0x1458||d->subsystem_device!=0x41cd||d->class!=0x030000||d->revision!=0xa1||
     pci_get_dsn(d)!=f->identity.serial||pci_find_host_bridge(d->bus)!=p->discovery_bridge||
     !p->discovery_bridge->discovery_only)return -ESTALE;
  serials[i]=f->identity.serial;
 }
 return serials[0]==PROVISION_PRIVATE_ID_6&&serials[0]!=serials[1]&&
  serials[1]!=PROVISION_PRIVATE_ID_5&&serials[1]!=PROVISION_PRIVATE_ID_24&&serials[1]!=PROVISION_PRIVATE_ID_20?0:-ESTALE;
}
static int np_alias(struct pci_dev*d,u16 alias,void*arg)
{
 struct apciec_native*n=arg;
 if(d!=n->target||alias!=pci_dev_id(n->target)||!np_is_gpu(alias)||n->aliases)return -EPERM;
 n->aliases++;return 0;
}
static int np_dma_audit(struct apple_apciec*p)
{
 unsigned i;
 if(np_target_identity(p))return -EPERM;
 for(i=0;i<2;i++) {
  struct device*d=&p->pair_native->clients[i].target->dev;
  struct iommu_fwspec*fw=dev_iommu_fwspec_get(d);struct iommu_domain*domain=iommu_get_domain_for_dev(d);
  if(!d->iommu_group||!domain||domain->type!=IOMMU_DOMAIN_DMA||!fw||fw->iommu_fwnode!=of_fwnode_handle(p->retained_dart_node)||
     fw->num_ids||dev_is_dma_coherent(d)||domain->pgsize_bitmap!=0x4000||!domain->geometry.force_aperture||
     domain->geometry.aperture_start||domain->geometry.aperture_end!=0xffffffffULL)return -EPERM;
 }
 return apple_dart_native_pair_audit(p->dev,&p->dart->dev,&p->pair_native->clients[0].target->dev,&p->pair_native->clients[1].target->dev);
}
static int np_firmware_prepare(struct apple_apciec*p)
{
 unsigned range_cells;__be32 map[8],mask=cpu_to_be32(0xffff),ranges[6];int ret;
 if(!p->retained_dart_node||!p->retained_dart_node->phandle)return -EINVAL;
 ret=an_aic_ranges(p,ranges,&range_cells);if(ret)return ret;
 map[0]=cpu_to_be32(0x600);map[1]=cpu_to_be32(p->retained_dart_node->phandle);
 map[2]=map[3]=cpu_to_be32(1);
 map[4]=cpu_to_be32(0x300);map[5]=map[1];map[6]=cpu_to_be32(2);map[7]=cpu_to_be32(1);
 of_changeset_init(&p->native->firmware);
 ret=an_add_property(p,"iommu-map",map,sizeof(map));
 if(!ret)ret=an_add_property(p,"iommu-map-mask",&mask,sizeof(mask));
 if(!ret)ret=an_add_property(p,"msi-ranges",ranges,range_cells*sizeof(*ranges));
 if(!ret)ret=an_add_property(p,"msi-controller",NULL,0);
 if(!ret)ret=an_add_property(p,"dma-noncoherent",NULL,0);
 if(!ret)ret=an_add_property(p,"research,native-endpoint-memory-only",NULL,0);
 if(!ret)ret=an_add_property(p,"research,native-endpoint-pair",NULL,0);
 if(!ret)ret=of_changeset_apply(&p->native->firmware);
 return ret;
}
static int np_device_audit(struct apple_apciec*p,unsigned i)
{
 struct pci_dev*d=p->discovery_devices[i];const struct ep_function*f=np_function(p,pn_positions[i].rid);
 if(!d||!f||pci_dev_id(d)!=f->identity.rid||d->vendor!=(f->identity.id&65535)||
    d->device!=(f->identity.id>>16)||d->class!=(f->identity.class_rev>>8)||
    d->revision!=(f->identity.class_rev&255)||d->hdr_type!=(f->identity.header&127)||
    d->multifunction!=!!(f->identity.header&128)||d->driver||d->dev.driver||
    !d->non_mappable_bars||d->is_busmaster||d->is_physfn||d->is_virtfn||d->ari_enabled||
    dev_iommu_fwspec_get(&d->dev)||d->dev.iommu_group||
    !device_is_registered(&d->dev)||pci_get_dsn(d)!=f->identity.serial||
    pci_find_host_bridge(d->bus)!=p->discovery_bridge)return -EPERM;
 if((i==3||i==7)&&((d->subsystem_device<<16)|d->subsystem_vendor)!=f->identity.subsystem)return -ESTALE;
 return 0;
}
static int np_claim_tree(struct apple_apciec*p,bool claim,bool before_driver)
{
 const int parents[8]={-1,0,1,2,1,4,5,6};
 unsigned kind,depth,g,b;int ret;
 if(tn_owner_validate(p))return -EPERM;
 for(depth=0;depth<6;depth++)for(kind=0;kind<2;kind++) {
  unsigned j=np_ancestors[depth],idx=kind?PCI_BRIDGE_PREF_MEM_WINDOW:PCI_BRIDGE_MEM_WINDOW;
  struct pci_dev*d=p->discovery_devices[j];struct resource*r=&d->resource[idx];
  struct resource*parent=j?&p->discovery_devices[parents[j]]->resource[idx]:&p->endpoint_owner->resources[kind?0:1];
  u64 start=kind?(j==2?0x5a0000000ULL:0x580000000ULL):(j==2?0x608000000ULL:0x604000000ULL);
  u64 end=kind?((j<3)?0x5b1ffffffULL:0x591ffffffULL):((j<3)?0x60bffffffULL:0x607ffffffULL);
  if(r->start!=start||r->end!=end||!(r->flags&IORESOURCE_MEM)||!!(r->flags&IORESOURCE_PREFETCH)!=!!kind||
     (r->flags&(IORESOURCE_UNSET|IORESOURCE_DISABLED)))return -ESTALE;
  if(claim){if(r->parent)return -EEXIST;ret=pci_claim_resource(d,idx);if(ret)return ret;}
  if(r->parent!=parent)return -EPERM;
 }
 for(g=0;g<2;g++)for(b=0;b<6;b++) {
  unsigned j=np_targets[g];struct pci_dev*d=p->discovery_devices[j];
  const struct ep_bar*bar=&np_snapshot(p,g)->bars[b];struct resource*r=&d->resource[b];
  if(b==2||b==4){if(r->flags||r->parent)return -EPERM;continue;}
  if(b==5){if(r->parent)return -EPERM;continue;}
  kind=b!=0;
  if(r->start!=bar->cpu||resource_size(r)!=bar->size||!(r->flags&IORESOURCE_MEM)||
     !!(r->flags&IORESOURCE_PREFETCH)!=!!kind||!!(r->flags&IORESOURCE_MEM_64)!=!!kind||
     (r->flags&(IORESOURCE_UNSET|IORESOURCE_DISABLED)))return -ESTALE;
  if(claim){if(r->parent)return -EEXIST;ret=pci_claim_resource(d,b);if(ret)return ret;}
  if(r->parent!=&p->discovery_devices[parents[j]]->resource[kind?PCI_BRIDGE_PREF_MEM_WINDOW:PCI_BRIDGE_MEM_WINDOW]||
     (before_driver&&r->child))return -EPERM;
 }
 /* Kernel resource children sort by address: transit0208 precedes local0200. */
 for(kind=0;kind<2;kind++) {
  unsigned idx=kind?PCI_BRIDGE_PREF_MEM_WINDOW:PCI_BRIDGE_MEM_WINDOW;
  struct resource *r[8];for(b=0;b<8;b++)r[b]=&p->discovery_devices[b]->resource[idx];
  if(p->endpoint_owner->resources[kind?0:1].child!=r[0]||r[0]->sibling||r[0]->child!=r[1]||r[1]->sibling||
     r[1]->child!=r[4]||r[4]->sibling!=r[2]||r[2]->sibling||r[4]->child!=r[5]||r[5]->sibling||
     r[5]->child!=r[6]||r[6]->sibling)return -EPERM;
  for(g=0;g<2;g++) {
   struct pci_dev*d=p->discovery_devices[np_targets[g]];struct resource*first=&d->resource[kind?1:0];
   if(r[g?2:6]->child!=first)return -EPERM;
   if(kind){if(first->sibling!=&d->resource[3]||d->resource[3].sibling)return -EPERM;}
   else if(first->sibling)return -EPERM;
  }
 }
 if(p->endpoint_owner->resources[2].child)return -EPERM;
 for(g=0;g<2;g++)if(p->discovery_devices[np_targets[g]]->resource[PCI_ROM_RESOURCE].parent)return -EPERM;
 return 0;
}

static int np_hardware_audit(struct apple_apciec*p,bool decoded,bool before_driver)
{
 unsigned j,k,g;u32 v,want;int ret;
 if(!np_host(p)||p->discovery_failed||p->discovery_probe.pending||!p->power_ready||!p->tunnel_ready)return -EPERM;
 for(j=0;j<8;j++) {
  const struct ep_function*f=np_function(p,pn_positions[j].rid);unsigned rid=pn_positions[j].rid;
  if(!f||(f->devctl2&PCI_EXP_DEVCTL2_ARI))return -EPERM;
  ret=np_read(p,rid,0,4,&v);if(ret||v!=f->identity.id)return ret?ret:-ESTALE;
  ret=np_read(p,rid,4,2,&v);if(ret||(decoded?!np_command_ok(rid,v,before_driver):v!=0))return ret?ret:-EPERM;
  if(!np_is_gpu(rid)){ret=np_read(p,rid,0x18,4,&v);if(ret||v!=f->buses)return ret?ret:-ESTALE;}
  if(pn_positions[j].forwarding)for(k=0x20;k<=0x2c;k+=4){
   if(!pn_window(rid,k,&want))return -EPERM;
   ret=np_read(p,rid,k,4,&v);if(ret||v!=want)return ret?ret:-ESTALE;
  }
 }
 for(g=0;g<2;g++)for(j=0;j<5;j++)if(j==0||j==1||j==3){
  const struct ep_bar*b=&np_snapshot(p,g)->bars[j];want=(u32)b->pci|(b->saved[0]&15);
  ret=np_read(p,np_rids[g],0x10+4*j,4,&v);if(ret||v!=want)return ret?ret:-ESTALE;
  if(j){ret=np_read(p,np_rids[g],0x14+4*j,4,&v);if(ret||v!=(u32)(b->pci>>32))return ret?ret:-ESTALE;}
 }
 return 0;
}
/* Exactly two ordinary PCI BAR0 reads. Mapping stays owned until reboot. */
static int np_boot0_probe(struct apple_apciec*p,unsigned which)
{
 struct apciec_native_pair*pair=p->pair_native;struct resource*r;
 u32 v,cached,before,after;unsigned j;int ret;
 if(which>=2||!pair)return -EPERM;
 r=&pair->clients[which].target->resource[0];
 if(pair->boot0_regs[which]||pair->boot0_attempted[which]||p->retained_phase!=29||p->discovery_task!=current||
    !r->parent||r->start!=(which?0x608000000ULL:0x604000000ULL)||resource_size(r)!=0x4000000||
    !(r->flags&IORESOURCE_MEM)||(r->flags&(IORESOURCE_IO|IORESOURCE_PREFETCH|IORESOURCE_MEM_NONPOSTED|IORESOURCE_UNSET|IORESOURCE_DISABLED)))return -EPERM;
 if(ktime_get_boottime_ns()>=p->discovery_deadline)return -ETIMEDOUT;
 pair->boot0_attempted[which]=true;ret=np_hardware_audit(p,true,true);if(ret)return ret;
 for(j=0;j<6;j++) {
  const struct ep_function*f=np_function(p,pn_positions[np_ancestors[j]].rid);
  if(!f||!f->msi||f->msi<0x40||f->msi>0xfc||(f->msi&3)||f->msix||!f->pcie||!f->pm)return -EPERM;
  ret=md_cached(f,f->msi,&cached);if(ret||(cached&255)!=PCI_CAP_ID_MSI||((cached>>16)&PCI_MSI_FLAGS_ENABLE))return -EPERM;
  ret=np_read(p,f->identity.rid,f->msi,4,&v);if(ret||v!=cached)return ret?ret:-ESTALE;
  ret=np_read(p,f->identity.rid,f->pcie+PCI_EXP_DEVCTL,2,&v);if(ret||(v&15))return ret?ret:-EPERM;
  ret=np_read(p,f->identity.rid,f->pm+PCI_PM_CTRL,2,&v);if(ret||(v&PCI_PM_CTRL_STATE_MASK))return ret?ret:-EPERM;
 }
 pair->boot0_regs[which]=pci_iomap_range(pair->clients[which].target,0,0,sizeof(u32));
 if(!pair->boot0_regs[which])return -ENOMEM;
 before=readl(p->port+0x100);if(before==~0U)return -ENODEV;
 for(j=0;j<2;j++) {
  if(ktime_get_boottime_ns()>=p->discovery_deadline)return -ETIMEDOUT;
  pair->boot0[which][j]=readl(pair->boot0_regs[which]);
 }
 if(ktime_get_boottime_ns()>=p->discovery_deadline)return -ETIMEDOUT;
 after=readl(p->port+0x100);
 dev_info(p->dev,"pair-BOOT0: rid%04x %08x/%08x INTSTAT%08x->%08x; retained mapping, no retry\n",np_rids[which],pair->boot0[which][0],pair->boot0[which][1],before,after);
 if(after==~0U||((after&~before)&(BIT(26)|BIT(25)|BIT(23)|BIT(21))))return -EIO;
 return mp_boot0_valid(pair->boot0[which][0],pair->boot0[which][1])?0:-ENODEV;
}

static int np_state_audit(struct apple_apciec*p,bool before_driver)
{
 unsigned j,i;u32 v;int ret;
 if(!np_host(p)||!p->pair_native||p->native!=&p->pair_native->clients[0]||p->discovery_count!=8||
    !p->discovery_bridge||p->discovery_bridge->discovery_dma_device!=p->native->target||
    !an_msi_pair_ready(p->native->msi))return -EPERM;
 for(i=0;i<2;i++) {
  struct apciec_native*n=&p->pair_native->clients[i];
  if(n->aliases!=1||!mp_boot0_valid(p->pair_native->boot0[i][0],p->pair_native->boot0[i][1])||
     !n->target->discovery_dma_admitted||dev_get_msi_domain(&n->target->dev)!=p->native->msi->domain||
     (before_driver&&(n->target->driver||n->target->dev.driver||n->enable_attempted)))return -EPERM;
 }
 ret=np_dma_audit(p);if(ret)return ret;
 for(j=0;j<64;j++) {
  u32 wanted=j==1?BIT(31)|BIT(16)|0x600:j==2?BIT(31)|(2U<<16)|0x300:0;
  if(readl(p->port+APCIEC_RID2SID+4*j)!=wanted)return -ESTALE;
 }
 v=readl(p->port+APCIEC_MSICFG);
 if((v&&v!=0x51)||(before_driver&&v)||readl(p->port+APCIEC_MSIBASE)||readl(p->port+APCIEC_MSIADDR)!=0xfffff000)return -ESTALE;
 for(j=0;j<8;j++) {
  struct pci_dev*d=p->discovery_devices[j];const struct ep_function*f=np_function(p,pn_positions[j].rid);
  if(!d||!f||pci_get_dsn(d)!=f->identity.serial)return -ESTALE;
  if(!np_is_gpu(pn_positions[j].rid)&&(d->driver||d->dev.driver||d->dev.iommu_group||dev_iommu_fwspec_get(&d->dev)))return -EPERM;
  if(pn_positions[j].forwarding&&pci_pcie_type(d)==PCI_EXP_TYPE_DOWNSTREAM&&
     !pci_acs_enabled(d,PCI_ACS_SV|PCI_ACS_RR|PCI_ACS_CR|PCI_ACS_UF))return -EPERM;
 }
 ret=np_hardware_audit(p,true,before_driver);return ret?ret:np_claim_tree(p,false,before_driver);
}

static int np_enable_device(struct pci_host_bridge*b,struct pci_dev*d)
{
 struct apple_apciec*p=b->sysdata;struct apciec_native*n;int j,ret;
 if(!np_host(p)||!p->pair_native||p->retained_phase!=30||!an_msi_pair_ready(p->native->msi))return -EPERM;
 j=pn_index(pci_dev_id(d));if(j<0||p->discovery_devices[j]!=d)return -EPERM;
 ret=np_dma_audit(p);if(ret)return ret;n=np_client(p,pci_dev_id(d));
 if(n){if(n->enable_attempted)return -EPERM;n->enable_attempted=true;}
 return 0;
}
static void np_disable_device(struct pci_host_bridge*b,struct pci_dev*d)
{
 struct apple_apciec*p=b->sysdata;struct apciec_native*n=np_host(p)?np_client(p,pci_dev_id(d)):NULL;
 if(n&&n->target==d)WRITE_ONCE(n->enable_attempted,true);
}
int apple_apciec_retained_pair_native_prepare(struct device*dev,unsigned port,
 const void*ticket,unsigned*phase)
{
 struct apple_apciec*p=dev_get_drvdata(dev);struct resource_entry*e;struct pci_bus*bus;
 unsigned j,i;unsigned long flags;int ret;const char*step="admission";bool locked=false;
 if(!p||!phase||!np_host(p)||!endpoint_native_driver||!endpoint_pci_register)return -EINVAL;
 mutex_lock(&p->lifecycle);
 ret=retained_commit_owner(p,port,ticket,14);if(ret)goto out;
 if(p->native||p->pair_native||p->discovery_attempted||p->discovery_bridge||p->retained_scan_task||
    !p->endpoint_snapshot||!p->pair_secondary_snapshot||tn_owner_validate(p)||
    of_find_property(p->dev->of_node,"iommu-map",NULL)||driver_find("nvidia",&pci_bus_type)) {ret=-EPERM;goto out;}
 for(i=0;i<2;i++) {
  struct ep_snapshot*s=np_snapshot(p,i);
  if(!s->memory_assigned||s->count!=8||s->selected!=np_targets[i]||s->ancestor_count!=(i?3:5)){ret=-EPERM;goto out;}
 }
 for(j=0;j<8;j++)if(memcmp(&p->endpoint_snapshot->functions[j],&p->pair_secondary_snapshot->functions[j],sizeof(struct ep_function))){ret=-ESTALE;goto out;}
 if(ktime_get_boottime_ns()+10ULL*NSEC_PER_SEC>=p->retained_identity_deadline){ret=-ETIMEDOUT;goto out;}
 p->discovery_attempted=true;p->retained_phase=15;
 p->discovery_deadline=min(ktime_get_boottime_ns()+30ULL*NSEC_PER_SEC,p->retained_identity_deadline);
 raw_spin_lock_irqsave(&p->lock,flags);p->discovery_task=current;raw_spin_unlock_irqrestore(&p->lock,flags);
 ret=retained_dma_blocked(p);if(!ret)ret=np_hardware_audit(p,false,true);if(ret)goto failed;
 INIT_LIST_HEAD(&p->discovery_windows);
 p->discovery_bus_resource=(struct resource){.name="J293 pair buses",.start=0,.end=6,.flags=IORESOURCE_BUS};
 for(j=0;j<4;j++) {
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
 for(j=0;j<8;j++) {
  const struct pn_position*a=&pn_positions[j];struct pci_dev*d;
  ret=np_hardware_audit(p,false,true);if(ret)goto failed;
  bus=p->discovery_buses[a->rid>>8];if(!bus){ret=-EPERM;goto failed;}
  d=pci_scan_single_device(bus,a->rid&255);p->discovery_devices[j]=d;if(d)p->discovery_count++;
  ret=np_device_audit(p,j);if(ret)goto failed;
  if(a->forwarding) {
   bus=pci_add_new_bus(bus,d,a->secondary);if(!bus){ret=-ENOMEM;goto failed;}
   p->discovery_buses[a->secondary]=bus;
   if(!pci_bus_insert_busn_res(bus,a->secondary,a->subordinate)){ret=-EBUSY;goto failed;}
   pci_read_bridge_bases(bus);
  }
 }
 ret=np_hardware_audit(p,false,true);if(!ret)ret=np_claim_tree(p,true,true);if(ret)goto failed;
 step="native-owner";p->pair_native=kzalloc(sizeof(*p->pair_native),GFP_KERNEL);
 if(!p->pair_native){ret=-ENOMEM;goto failed;}
 p->native=&p->pair_native->clients[0];
 for(i=0;i<2;i++) {
  struct apciec_native*n=&p->pair_native->clients[i];n->host=p;n->target=pci_dev_get(p->discovery_devices[np_targets[i]]);n->active=true;
 }
 p->retained_phase=29;
 ret=np_target_identity(p);if(ret)goto failed;
 for(i=0;i<2;i++) {
  struct apciec_native*n=&p->pair_native->clients[i];ret=pci_for_each_dma_alias(n->target,np_alias,n);
  if(ret||n->aliases!=1){ret=ret?ret:-EPERM;goto failed;}
 }
 /* Both downstream branches must enforce ACS before either IOMMU group is created. */
 step="ACS-before-DART";
 for(j=0;j<8;j++) {
  const struct ep_function*f=np_function(p,pn_positions[j].rid);struct pci_dev*d=p->discovery_devices[j];
  unsigned bits=PCI_ACS_SV|PCI_ACS_RR|PCI_ACS_CR|PCI_ACS_UF;
  if(!pn_positions[j].forwarding||pci_pcie_type(d)!=PCI_EXP_TYPE_DOWNSTREAM)continue;
  if(!f->acs||(f->acs_bits&bits)!=bits||(f->acs_bits>>16)){ret=-EPERM;goto failed;}
  ret=np_write(p,pn_positions[j].rid,f->acs+PCI_ACS_CTRL,2,bits);if(ret)goto failed;
  if(!pci_acs_enabled(d,bits)){ret=-EPERM;goto failed;}
 }
 step="firmware";ret=np_firmware_prepare(p);if(ret)goto failed;
 p->discovery_bridge->discovery_dma_device=p->native->target;
 step="DART-pair";
 for(i=0;i<2;i++) {
  struct apciec_native*n=&p->pair_native->clients[i];WRITE_ONCE(n->target->discovery_dma_admitted,true);
  ret=iommu_probe_device(&n->target->dev);if(ret)goto failed;
 }
 ret=np_dma_audit(p);if(ret)goto failed;
 for(i=0;i<2;i++)p->pair_native->clients[i].dma_ready=true;
 for(j=0;j<64;j++)if(readl(p->port+APCIEC_RID2SID+4*j)){ret=-ESTALE;goto failed;}
 for(i=0;i<2;i++) {
  u32 value=BIT(31)|((i+1)<<16)|np_rids[i];writel(value,p->port+APCIEC_RID2SID+4*(i+1));
  if(readl(p->port+APCIEC_RID2SID+4*(i+1))!=value){ret=-EIO;goto failed;}
 }
 for(i=0;i<2;i++)p->pair_native->clients[i].rid_ready=true;
 p->iommu_ready=true;
 step="MSI-shared";ret=an_msi_prepare_pair(p,&p->pair_native->clients[0],&p->pair_native->clients[1]);if(ret)goto failed;
 step="decode";
 for(j=0;j<8;j++) {
  ret=np_write(p,pn_positions[j].rid,PCI_COMMAND,2,np_initial_command(pn_positions[j].rid));if(ret)goto failed;
 }
 p->discovery_bridge->enable_device=np_enable_device;p->discovery_bridge->disable_device=np_disable_device;
 p->discovery_bridge->preserve_config=true;
 step="BOOT0-pair";for(i=0;i<2;i++){ret=np_boot0_probe(p,i);if(ret)goto failed;}
 step="prepublication-audit";ret=np_state_audit(p,true);if(ret)goto failed;
 for(i=0;i<2;i++) {
  ret=device_set_driver_override(&p->pair_native->clients[i].target->dev,"apple-apciec-native-pending");if(ret)goto failed;
 }
 if(driver_find("nvidia",&pci_bus_type)){ret=-EBUSY;goto failed;}
 for(j=0;j<6;j++)WRITE_ONCE(p->discovery_devices[np_ancestors[j]]->discovery_mem_ancestor,true);
 if(ktime_get_boottime_ns()>=p->discovery_deadline){ret=-ETIMEDOUT;goto failed;}
 p->retained_phase=30;step="publication";
 for(i=0;i<2;i++) {
  struct pci_dev*d=p->pair_native->clients[i].target;WRITE_ONCE(d->discovery_driver_admitted,true);
  pci_bus_add_device(d);pm_runtime_forbid(&d->dev);
  if(!pci_dev_is_added(d)||pci_dev_binding_disallowed(d)){ret=-EPERM;goto failed;}
 }
 ret=np_state_audit(p,true);if(ret)goto failed;
 dev_info(dev,"pair-native: phase30 target%s serial%016llx target%s serial%016llx ready; audio0301/0601 untouched\n",
  pci_name(p->pair_native->clients[0].target),(unsigned long long)p->endpoint_snapshot->functions[7].identity.serial,
  pci_name(p->pair_native->clients[1].target),(unsigned long long)p->endpoint_snapshot->functions[3].identity.serial);
 goto close;
failed:
 p->discovery_failed=true;
 if(p->pair_native)for(i=0;i<2;i++) {
  p->pair_native->clients[i].failed=true;
  if(p->pair_native->clients[i].target)WRITE_ONCE(p->pair_native->clients[i].target->discovery_driver_admitted,false);
 }
 if(p->discovery_bridge)p->discovery_bridge->discovery_driver_device=NULL;
 dev_err(dev,"pair-native: failed%d phase%u step%s; all owners retained until normal reboot\n",ret,p->retained_phase,step);
close:
 raw_spin_lock_irqsave(&p->lock,flags);p->discovery_task=NULL;raw_spin_unlock_irqrestore(&p->lock,flags);
 if(locked)pci_unlock_rescan_remove();
out:
 *phase=p->retained_phase;mutex_unlock(&p->lifecycle);return ret;
}

EXPORT_SYMBOL_GPL(apple_apciec_retained_pair_native_prepare);
int apple_apciec_retained_pair_native_audit(struct device*dev,unsigned port,const void*ticket)
{
 struct apple_apciec*p=dev_get_drvdata(dev);int ret;
 if(!np_host(p))return -EINVAL;
 mutex_lock(&p->lifecycle);
 ret=port==3&&p->retained_ticket==ticket&&p->retained_phase==30?np_state_audit(p,true):-EPERM;
 mutex_unlock(&p->lifecycle);return ret;
}
EXPORT_SYMBOL_GPL(apple_apciec_retained_pair_native_audit);
