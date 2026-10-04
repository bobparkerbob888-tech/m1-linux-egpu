/* SPDX-License-Identifier: GPL-2.0 */
extern int apple_dart_native_group_audit(struct device*,struct device**,const unsigned*,unsigned);
static struct apciec_native *am_client(struct apciec_multi*m,unsigned gpu)
{return gpu==1?m->host->native:gpu>=2&&gpu<=3?&m->clients[gpu-2]:NULL;}
static int am_dma_audit(struct apple_apciec*p)
{
 struct apciec_multi*m=p->multi;struct device*clients[3];unsigned sids[]={1,2,3},j;
 if(!m||m->failed)return -EPERM;
 for(j=0;j<3;j++){
  struct apciec_native*n=am_client(m,j+1);struct iommu_fwspec*fw;
  if(!n||!n->target)return -EPERM;
  clients[j]=&n->target->dev;
  fw=dev_iommu_fwspec_get(clients[j]);
  if(!fw||fw->iommu_fwnode!=of_fwnode_handle(p->retained_dart_node)||fw->num_ids)return -EPERM;
 }
 return apple_dart_native_group_audit(&p->dart->dev,clients,sids,3);
}
static int am_alias(struct pci_dev*d,u16 alias,void*arg)
{
 struct apciec_native*n=arg;
 if(d!=n->target||alias!=pci_dev_id(d)||n->aliases)return -EPERM;
 n->aliases++;return 0;
}
static int am_acs(struct apciec_multi*m)
{
 const unsigned required=PCI_ACS_SV|PCI_ACS_RR|PCI_ACS_CR|PCI_ACS_UF;
 unsigned j;u32 value;int ret;
 for(j=0;j<AM_FUNCTIONS;j++){
  struct pci_dev*d=m->devices[j];struct ep_function*f=&m->functions[j];
  if(!am_layout[j].secondary||pci_pcie_type(d)!=PCI_EXP_TYPE_DOWNSTREAM)continue;
  if(!f->acs||(f->acs_bits&required)!=required)return -EOPNOTSUPP;
  ret=am_read_width(m,am_layout[j].rid,f->acs+PCI_ACS_CTRL,2,&value);if(ret)return ret;
  if(value!=(f->acs_bits>>16)||value)return -ESTALE;
  ret=am_exact_write(m,am_layout[j].rid,f->acs+PCI_ACS_CTRL,2,required);if(ret)return ret;
  if(!pci_acs_enabled(d,required))return -EPERM;
  f->acs_bits|=required<<16;
 }
 return 0;
}
static int am_iommu(struct apciec_multi*m)
{
 struct apple_apciec*p=m->host;struct property*prop;__be32 map[12];unsigned j;int ret;
 const __be32*prior;int length;
 prior=of_get_property(p->dev->of_node,"iommu-map",&length);
 if(!prior||length!=16||be32_to_cpu(prior[0])!=0x300||
    be32_to_cpu(prior[1])!=p->retained_dart_node->phandle||
    be32_to_cpu(prior[2])!=1||be32_to_cpu(prior[3])!=1)return -ESTALE;
 for(j=0;j<3;j++){
  map[4*j]=cpu_to_be32((j+1)*0x300);map[4*j+1]=cpu_to_be32(p->retained_dart_node->phandle);
  map[4*j+2]=cpu_to_be32(j+1);map[4*j+3]=cpu_to_be32(1);
 }
 prop=kzalloc(sizeof(*prop),GFP_KERNEL);if(!prop)return -ENOMEM;
 prop->name=kstrdup("iommu-map",GFP_KERNEL);prop->value=kmemdup(map,sizeof(map),GFP_KERNEL);prop->length=sizeof(map);
 if(!prop->name||!prop->value)return -ENOMEM;
 of_changeset_init(&m->firmware);
 ret=of_changeset_update_property(&m->firmware,p->dev->of_node,prop);
 if(!ret)ret=of_changeset_apply(&m->firmware);
 if(ret)return ret;
 for(j=1;j<3;j++){
  struct apciec_native*n=am_client(m,j+1);int index=am_index((j+1)*0x300);
  n->host=p;n->target=pci_dev_get(m->devices[index]);n->active=true;n->msi=p->native->msi;
  ret=pci_for_each_dma_alias(n->target,am_alias,n);if(ret||n->aliases!=1)return ret?ret:-EPERM;
  WRITE_ONCE(n->target->discovery_dma_admitted,true);
  ret=iommu_probe_device(&n->target->dev);if(ret)return ret;
 }
 ret=am_dma_audit(p);if(ret)return ret;
 for(j=1;j<3;j++){
  struct apciec_native*n=am_client(m,j+1);unsigned sid=j+1;u32 rid=(j+1)*0x300;
  if(readl(p->port+APCIEC_RID2SID+4*sid))return -ESTALE;
  n->dma_ready=true;
  writel(BIT(31)|(sid<<16)|rid,p->port+APCIEC_RID2SID+4*sid);
  if(readl(p->port+APCIEC_RID2SID+4*sid)!=(BIT(31)|(sid<<16)|rid))return -EIO;
  n->rid_ready=true;
  dev_set_msi_domain(&n->target->dev,p->native->msi->domain);n->irq_ready=true;
 }
 return 0;
}
/* Bridges must forward upstream requests, matching the original three
 * retained bridges. GPU bus mastering stays off until its driver owns DMA. */
static u16 am_initial_command(const struct am_layout*a)
{
 return a->secondary ? PCI_COMMAND_MEMORY|PCI_COMMAND_MASTER :
        a->gpu ? PCI_COMMAND_MEMORY : 0;
}
static bool am_command_ok(const struct am_layout*a,u16 cmd,bool before_driver)
{
 u16 initial=am_initial_command(a);
 if(before_driver)return cmd==initial;
 if(!initial)return !cmd;
 return (cmd&initial)==initial &&
        !(cmd&~(PCI_COMMAND_MEMORY|PCI_COMMAND_MASTER|PCI_COMMAND_INTX_DISABLE));
}
static int am_state_audit(struct apple_apciec*p,bool before_driver)
{
 struct apciec_multi*m=p->multi;unsigned j,k;u32 v;int ret;
 if(!m||m->failed||m->count!=AM_FUNCTIONS||!p->power_ready||!p->tunnel_ready)return -EPERM;
 ret=am_dma_audit(p);if(ret)return ret;
 for(j=0;j<64;j++){
  u32 wanted=j>=1&&j<=3?BIT(31)|(j<<16)|(j*0x300):0;
  if(readl(p->port+APCIEC_RID2SID+4*j)!=wanted)return -ESTALE;
 }
 v=readl(p->port+APCIEC_MSICFG);
 if((v&&v!=0x51)||readl(p->port+APCIEC_MSIBASE)||readl(p->port+APCIEC_MSIADDR)!=0xfffff000||
    (before_driver&&v))return -ESTALE;
 for(j=0;j<AM_FUNCTIONS;j++){
  const struct am_layout*a=&am_layout[j];const struct ep_function*f=&m->functions[j];struct pci_dev*d=m->devices[j];u16 cmd;
  if(!d||pci_read_config_dword(d,0,&v)||v!=f->identity.id||pci_read_config_word(d,PCI_COMMAND,&cmd)||
     pci_get_dsn(d)!=f->identity.serial)return -ESTALE;
  if(!am_command_ok(a,cmd,before_driver))return -EPERM;
  if(!a->gpu&&(d->driver||d->dev.driver||d->dev.iommu_group||dev_iommu_fwspec_get(&d->dev)))return -EPERM;
  if(a->gpu){
   struct apciec_native*n=am_client(m,a->gpu);
   if(!n->dma_ready||!n->rid_ready||!n->irq_ready||dev_get_msi_domain(&d->dev)!=p->native->msi->domain||
      (before_driver&&(d->driver||d->dev.driver||n->enable_attempted)))return -EPERM;
   for(k=0;k<5;k++)if(k!=2&&k!=4){struct resource*r=&d->resource[k];
    if(!r->parent||r->parent->start>r->start||r->parent->end<r->end||(before_driver&&r->child))return -EPERM;}
  }
  if(a->secondary){
   if(pci_pcie_type(d)==PCI_EXP_TYPE_DOWNSTREAM&&
      !pci_acs_enabled(d,PCI_ACS_SV|PCI_ACS_RR|PCI_ACS_CR|PCI_ACS_UF))return -EPERM;
   if(pci_read_config_dword(d,PCI_PRIMARY_BUS,&v)||v!=am_buses(j))return -ESTALE;
   for(k=0;k<2;k++){struct resource*r=&d->resource[k?PCI_BRIDGE_PREF_MEM_WINDOW:PCI_BRIDGE_MEM_WINDOW];
    if(r->start!=(k?a->pref_start:a->mem_start)||r->end!=(k?a->pref_end:a->mem_end)||!r->parent)return -ESTALE;}
  }
 }
 return 0;
}
static int am_enable_device(struct apple_apciec*p,struct pci_dev*d)
{
 struct apciec_multi*m=p->multi;int j,ret;struct apciec_native*n;
 if(!m||!m->ready||m->failed||p->retained_phase!=22)return -EPERM;
 j=am_index(pci_dev_id(d));if(j<0||m->devices[j]!=d||(!am_layout[j].gpu&&!am_layout[j].secondary))return -EPERM;
 ret=am_dma_audit(p);if(ret)return ret;
 if(am_layout[j].gpu){
  n=am_client(m,am_layout[j].gpu);if(n->enable_attempted)return -EPERM;n->enable_attempted=true;
 }
 return 0;
}
int apple_apciec_retained_expand_chain(struct device*dev,unsigned port,const void*ticket,u64 deadline,unsigned*phase)
{
 struct apple_apciec*p=dev_get_drvdata(dev);struct apciec_multi*m;unsigned j;int ret;const char*step="admission";
 if(!p||!phase||!endpoint_chain_resources||!endpoint_native_driver)return -EINVAL;
 mutex_lock(&p->lifecycle);
 if(port!=3||ticket!=p->retained_ticket||p->retained_phase!=20||p->multi||deadline!=p->retained_identity_deadline||
    driver_find("nvidia",&pci_bus_type)){ret=-EPERM;goto out;}
 ret=an_state_audit(p,true);if(ret)goto out;
 m=kzalloc(sizeof(*m),GFP_KERNEL);if(!m){ret=-ENOMEM;goto out;}
 m->host=p;m->task=current;m->deadline=deadline;m->phase=1;m->attempted=true;p->multi=m;p->retained_phase=21;
 pci_lock_rescan_remove();
 step="enumeration";ret=am_scan(m);
 if(!ret){step="resources";ret=am_resources(m);}
 if(!ret){step="ACS-isolation";ret=am_acs(m);}
 if(!ret){step="DMA";ret=am_iommu(m);}
 if(!ret){
  step="memory-decode";
  for(j=0;j<AM_FUNCTIONS;j++){
   const struct am_layout*a=&am_layout[j];
   if((a->gpu||a->secondary)&&j!=0&&j!=1&&j!=2&&j!=3){
    ret=am_exact_write(m,a->rid,PCI_COMMAND,2,am_initial_command(a));if(ret)break;
   }
  }
 }
 if(!ret){step="audit";ret=am_state_audit(p,true);}
 if(!ret){
  step="publication";
  for(j=0;j<AM_FUNCTIONS;j++){
   const struct am_layout*a=&am_layout[j];struct pci_dev*d=m->devices[j];
   if(a->secondary)WRITE_ONCE(d->discovery_mem_ancestor,true);
   if(a->gpu<2)continue;
   ret=device_set_driver_override(&d->dev,"apple-apciec-native-pending");if(ret)break;
   WRITE_ONCE(d->discovery_driver_admitted,true);pci_bus_add_device(d);
   if(!pci_dev_is_added(d)||pci_dev_binding_disallowed(d)){ret=-EPERM;break;}
   pm_runtime_forbid(&d->dev);
  }
 }
 if(!ret){step="published-audit";ret=am_state_audit(p,true);}
 if(ret){m->failed=true;p->native->failed=true;}
 else{m->ready=true;m->phase=4;p->retained_phase=22;}
 m->task=NULL;
 pci_unlock_rescan_remove();
 dev_info(dev,"chain-native: status%d phase%u step%s functions%u; all owners retained\n",ret,p->retained_phase,step,m->count);
out:
 *phase=p->retained_phase;mutex_unlock(&p->lifecycle);return ret;
}
EXPORT_SYMBOL_GPL(apple_apciec_retained_expand_chain);
