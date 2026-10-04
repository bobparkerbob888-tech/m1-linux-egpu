/* SPDX-License-Identifier: GPL-2.0 */
/* Retained one-shot expansion of the two downstream enclosures. No retries,
 * resets, bridge drivers, broad scans or release of any acquired owner. */
static struct apciec_native *am_client(struct apciec_multi *,unsigned);
static bool endpoint_chain_resources;
module_param(endpoint_chain_resources,bool,0444);
static bool am_valid(void *arg)
{
 struct apciec_multi *m=arg;struct apple_apciec*p=m->host;
 return endpoint_chain_resources && m==p->multi && !m->failed &&
  m->task==current && ktime_get_boottime_ns()<m->deadline && m->ops<32768 &&
  p->native && p->native->active && !p->native->failed &&
  !p->native->enable_attempted && !p->native->target->driver &&
  !p->native->target->dev.driver && p->power_ready && p->tunnel_ready;
}
static int am_config_locked(struct pci_bus *bus,unsigned devfn,int off,int width,u32 *value,bool write)
{
 struct apple_apciec*p=bus->sysdata;struct apciec_multi*m=p->multi;
 unsigned rid=(bus->number<<8)|devfn;int j=am_index(rid),ret;u32 old;
 lockdep_assert_held(&p->lock);
 if(!m||m->failed||j<0||!apple_apciec_map_bus(bus,devfn,off))return PCIBIOS_DEVICE_NOT_FOUND;
 if(!m->ready&&!am_valid(m))return PCIBIOS_DEVICE_NOT_FOUND;
 if(write){
  if(!m->ready&&!am_valid(m))return PCIBIOS_SET_FAILED;
  ret=pci_generic_config_read(bus,devfn,off,width,&old);if(ret)return ret;
  if(m->ready){
   const struct am_layout*a=&am_layout[j];
   struct apciec_native*n=a->gpu?am_client(m,a->gpu):p->native;
   if(!n||!an_write_for(n,&m->functions[j],a->gpu||a->secondary,!!a->gpu,off,width,old,*value))return PCIBIOS_SET_FAILED;
  }else if(m->armed){
   if(rid!=m->write_rid||off!=m->write_off||width!=m->write_width||*value!=m->write_value)return PCIBIOS_SET_FAILED;
  }else if(j<8||m->phase!=2||!m->functions[j].identity.id||
    !pd_write_allowed(&m->probe,&m->functions[j],off,width,old,*value))return PCIBIOS_SET_FAILED;
 }
 m->ops++;
 ret=write?pci_generic_config_write(bus,devfn,off,width,*value):pci_generic_config_read(bus,devfn,off,width,value);
 if(!ret&&write&&m->ready&&am_layout[j].gpu&&width==4)
  an_pbi_written(am_client(m,am_layout[j].gpu),&m->functions[j],off,*value);
 return ret;
}
static int am_read_width(struct apciec_multi*m,unsigned rid,unsigned off,unsigned width,u32*v)
{
 struct pci_bus bus={.number=rid>>8,.sysdata=m->host,.ops=&apple_apciec_ops};
 if(!am_valid(m))return -EPERM;
 return apple_apciec_config_read(&bus,rid&255,off,width,v)?-EIO:0;
}
static int am_read(void*arg,unsigned rid,unsigned off,u32*v)
{return am_read_width(arg,rid,off,4,v);}
static u64 am_now(void*arg){return ktime_get_boottime_ns();}
static int am_exact_write(struct apciec_multi*m,unsigned rid,unsigned off,unsigned width,u32 value)
{
 struct apple_apciec*p=m->host;
 struct pci_bus bus={.number=rid>>8,.sysdata=p,.ops=&apple_apciec_ops};
 bool pfm=!rid&&(off==0x24||off==0x28||off==0x2c);
 u32 before=0,got=0;int ret=-EPERM;unsigned long flags;
 if(!am_valid(m)||m->armed||m->probe.pending)return -EPERM;
 /* Caller must derive every write from the verified immutable layout. */
 if(pfm){
  before=readl(p->port+0x800);
  if(before==~0U||!(before&BIT(0))||(before&BIT(8)))return -ESTALE;
  writel(before|BIT(8),p->port+0x800);
  if(readl(p->port+0x800)!=(before|BIT(8)))goto restore;
 }
 raw_spin_lock_irqsave(&p->lock,flags);
 m->write_rid=rid;m->write_off=off;m->write_width=width;m->write_value=value;m->armed=true;
 raw_spin_unlock_irqrestore(&p->lock,flags);
 ret=apple_apciec_config_write(&bus,rid&255,off,width,value)?-EIO:0;
 raw_spin_lock_irqsave(&p->lock,flags);m->armed=false;raw_spin_unlock_irqrestore(&p->lock,flags);
 if(!ret&&pfm)writel(1,p->port+apple_apciec_logical_offset(p,0x994));
restore:
 if(pfm){writel(before,p->port+0x800);if(readl(p->port+0x800)!=before)ret=-EIO;}
 if(!ret)ret=am_read_width(m,rid,off,width,&got);
 return ret?ret:got==value?0:-ESTALE;
}
static int am_capture(struct apciec_multi*m,unsigned j)
{
 struct ep_function*f=&m->functions[j];unsigned rid=am_layout[j].rid;
 struct ep_io io={.ctx=m,.read=am_read,.valid=am_valid,.now=am_now,.deadline=m->deadline};
 struct ep_identity id={.rid=rid};u32 status,v;int ret;
 ret=ep_read(&io,rid,0,&id.id);if(ret)return ret;
 ret=ep_read(&io,rid,8,&id.class_rev);if(ret)return ret;
 ret=ep_read(&io,rid,12,&v);if(ret)return ret;id.header=(v>>16)&255;
 ret=ep_read(&io,rid,4,&status);if(ret)return ret;
 dev_info(m->host->dev,"chain-id: RID%04x ID%08x class%08x header%02x status%08x\n",rid,id.id,id.class_rev,id.header,status);
 if(status&7)return -EPERM;
 if((id.header&127)==1){
  if(id.id!=0x57868086||id.class_rev!=0x06040085||id.header!=1)return -ESTALE;
 }else{
  if((id.id&65535)!=0x10de)return -ESTALE;
  if(am_layout[j].gpu){
   if(id.id!=0x2d0410de||id.class_rev!=0x030000a1||id.header!=0x80)return -ESTALE;
  }else if((id.class_rev>>8)!=0x040300)return -ESTALE;
  ret=ep_read(&io,rid,0x2c,&id.subsystem);if(ret)return ret;
  dev_info(m->host->dev,"chain-id: RID%04x subsystem%08x\n",rid,id.subsystem);
  if(am_layout[j].gpu&&id.subsystem!=0x41cd1458)return -ESTALE;
 }
 /* Capture the linked capability chain before any standard PCI probes. */
 memset(f,0,sizeof(*f));f->identity=id;
 ret=ep_caps(&io,f,status);if(ret)return ret;id.serial=f->identity.serial;
 memset(f,0,sizeof(*f));ret=ep_function_read(&io,&id,f);if(ret)return ret;
 if((id.header&127)==1){
  static const u64 uid[]={PROVISION_PRIVATE_ID_11,PROVISION_PRIVATE_ID_12,PROVISION_PRIVATE_ID_13};
  if(!f->serial_present||f->identity.serial!=uid[am_layout[j].enclosure])return -ESTALE;
 }
 if((f->devctl2&PCI_EXP_DEVCTL2_ARI)||(f->pm&&(f->pmcsr&PCI_PM_CTRL_STATE_MASK))||
    (f->msi_control&PCI_MSI_FLAGS_ENABLE)||(f->msix_control&PCI_MSIX_FLAGS_ENABLE))return -EPERM;
 if((id.header&127)==1&&f->pcie){
  u32 link;ret=ep_read(&io,rid,f->pcie+0x10,&link);if(ret)return ret;
  dev_info(m->host->dev,"chain-link: RID%04x link-control-status%08x\n",rid,link);
 }
 dev_info(m->host->dev,"chain-pci: captured RID%04x ID%08x class%08x DSN%016llx\n",rid,id.id,id.class_rev,(unsigned long long)f->identity.serial);
 return 0;
}
static int am_bus_prepare(struct apciec_multi*m,unsigned j)
{
 const struct am_layout*a=&am_layout[j];
 struct pci_bus *bus;u32 before;int ret;
 if(!a->secondary)return 0;
 ret=am_read(m,a->rid,PCI_PRIMARY_BUS,&before);if(ret)return ret;
 if(j<2){if(before!=(j|((j+1)<<8)|(3<<16)))return -ESTALE;}
 else if(j==2){if(before!=am_buses(j))return -ESTALE;return 0;}
 else if(before)return -ESTALE;
 ret=am_exact_write(m,a->rid,PCI_PRIMARY_BUS,4,am_buses(j));if(ret)return ret;
 if(j<2){
  bus=m->buses[a->secondary];
  if(!bus||adjust_resource(&bus->busn_res,a->secondary,10-a->secondary))return -EBUSY;
  return 0;
 }
 bus=pci_add_new_bus(m->buses[a->rid>>8],m->devices[j],a->secondary);
 if(!bus)return -ENOMEM;
 m->buses[a->secondary]=bus;
 if(!pci_bus_insert_busn_res(bus,a->secondary,a->subordinate))return -EBUSY;
 /* Windows are still disabled; their explicit programming comes next. */
 pci_read_bridge_bases(bus);
 return 0;
}
/* Fresh enumeration only: never touch an endpoint until its local link has
 * finished training and stayed active for 100ms. Read-only, bounded to 2s;
 * unlike generic recovery helpers this never retrains or resets the link. */
static int am_wait_gpu_link(struct apciec_multi*m,unsigned j)
{
 const struct am_layout*a=&am_layout[j];struct ep_function*f=&m->functions[j];
 u64 start=am_now(m),stable=0,now;u32 cap,link;int ret;unsigned polls=0;
 if(j!=9&&j!=16)return 0;
 if(!f->pcie||a->secondary!=(j==9?6:9))return -EPERM;
 ret=am_read(m,a->rid,f->pcie+PCI_EXP_LNKCAP,&cap);if(ret)return ret;
 if(cap==~0U||!(cap&PCI_EXP_LNKCAP_DLLLARC))return -EOPNOTSUPP;
 while(polls++<101){
  if(!am_valid(m))return -EPERM;
  now=am_now(m);if(now-start>=2ULL*NSEC_PER_SEC)return -ETIMEDOUT;
  ret=am_read(m,a->rid,f->pcie+PCI_EXP_LNKCTL,&link);if(ret)return ret;
  if(link==~0U||(link&(PCI_EXP_LNKCTL_LD|PCI_EXP_LNKCTL_RL)))return -ESTALE;
  if((link>>16)&PCI_EXP_LNKSTA_DLLLA && !((link>>16)&PCI_EXP_LNKSTA_LT) &&
     ((link>>16)&PCI_EXP_LNKSTA_CLS) && ((link>>16)&PCI_EXP_LNKSTA_NLW)){
   if(!stable)stable=now;
   if(now-stable>=100ULL*NSEC_PER_MSEC){
    dev_info(m->host->dev,"chain-link-ready: RID%04x status%08x polls%u stable100ms\n",a->rid,link,polls);
    return 0;
   }
  }else stable=0;
  msleep(20);
 }
 return -ETIMEDOUT;
}
static int am_scan(struct apciec_multi*m)
{
 struct apple_apciec*p=m->host;unsigned j;int ret;
 for(j=0;j<4;j++)m->buses[j]=p->discovery_buses[j];
 for(j=0;j<8;j++){m->devices[j]=p->discovery_devices[j];m->functions[j]=*pd_function(p,am_layout[j].rid);}
 if(adjust_resource(&m->buses[0]->busn_res,0,10))return -EBUSY;
 for(j=0;j<AM_FUNCTIONS;j++){
  const struct am_layout*a=&am_layout[j];struct pci_dev*d;
  if(j>=8){
   ret=am_capture(m,j);if(ret)return ret;
   m->phase=2;
   if(!m->buses[a->rid>>8])return -EPERM;
   d=pci_scan_single_device(m->buses[a->rid>>8],a->rid&255);m->devices[j]=d;
   m->phase=1;
   if(!d||m->probe.pending||d->driver||d->dev.driver||d->dev.iommu_group||dev_iommu_fwspec_get(&d->dev)||
      !d->non_mappable_bars||d->is_busmaster||d->ari_enabled||
      d->vendor!=(m->functions[j].identity.id&65535)||d->device!=(m->functions[j].identity.id>>16)||
      pci_get_dsn(d)!=m->functions[j].identity.serial)return -EPERM;
  }
  ret=am_bus_prepare(m,j);if(ret)return ret;
  ret=am_wait_gpu_link(m,j);if(ret)return ret;
  m->count=j+1;
 }
 return 0;
}
