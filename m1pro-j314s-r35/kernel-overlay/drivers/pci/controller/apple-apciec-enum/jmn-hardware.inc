/* Concrete target-multi backend; include after jmn-kernel.inc. No automatic
 * caller, warm append, GPU reset or publication. Remaining config/claims/MMIO
 * contracts must be supplied before jmn_kernel_once can reach this backend. */
/* Slots are retained through every failure. A controller never claims or
 * dispatches another controller's native context. No reset/unregister API. */
#define JMN_CONTROLLERS 3
static struct jmn_kernel *jmn_sealed_owners[JMN_CONTROLLERS];
static struct jmn_kernel *jmn_active_owners[JMN_CONTROLLERS];
static int jmn_owner_index(const struct jmn_kernel*k)
{
 if(!k||!k->p||!k->p->profile||!apciec_profile_j314s(k->p->profile)||
    k->p->profile->index>=JMN_CONTROLLERS)return -1;
 return k->p->profile->index;
}
static struct jmn_kernel*jmn_owner_slot(const struct jmn_kernel*k,bool sealed)
{
 int i=jmn_owner_index(k);
 return i<0?NULL:sealed?smp_load_acquire(&jmn_sealed_owners[i]):
  smp_load_acquire(&jmn_active_owners[i]);
}
static int jmn_owner_claim(struct jmn_kernel*k,bool sealed)
{
 int i=jmn_owner_index(k);struct jmn_kernel**slot;
 if(i<0)return -EPERM;
 if(sealed&&jmn_owner_slot(k,false)!=k)return -EPERM;
 slot=sealed?&jmn_sealed_owners[i]:&jmn_active_owners[i];
 return cmpxchg(slot,NULL,k)?-EALREADY:0;
}
static struct jmn_kernel*jmn_owner_bridge(struct pci_host_bridge*b,bool sealed)
{
 struct jmn_kernel*found=NULL;
 if(!b)return NULL;
 for(unsigned i=0;i<JMN_CONTROLLERS;i++){
  struct jmn_kernel*k=sealed?smp_load_acquire(&jmn_sealed_owners[i]):
   smp_load_acquire(&jmn_active_owners[i]);
  if(!k||k->bridge!=b)continue;
  if(found||jmn_owner_index(k)!=(int)i||b->sysdata!=k->p)return NULL;
  found=k;
 }
 return found;
}
static struct jmn_kernel*jmn_owner_device(struct pci_dev*d,bool sealed)
{return d&&d->bus?jmn_owner_bridge(pci_find_host_bridge(d->bus),sealed):NULL;}
static bool jmn_export_present(struct pci_dev*d)
{return jmn_owner_device(d,false)!=NULL;}
static int jmn_hw_firmware(struct jmn_kernel*k)
{
 struct apple_apciec*p=k->p;__be32 map[4*JM_MAX_GPUS],mask=cpu_to_be32(0xffff),ranges[6];
 unsigned cells;const void*actual;int len,ret;
 if(jmn_owner_slot(k,false)||k->firmware_attempted||p->native||p->iommu_ready||p->msi_domain_ready||
    !p->dart||!p->retained_dart_node||!p->retained_dart_node->phandle||
    !p->j314s_resource||!jmx_native_sample(p,&p->j314s_resource->dma_sample)||
    p->rid_entries!=64||!k->bridge||!k->bridge->discovery_only)return -EPERM;
 k->firmware_attempted=true;ret=jmn_owner_claim(k,false);if(ret)return ret;k->sample=p->j314s_resource->dma_sample;
 if(k->sample.ias!=32||k->sample.oas!=42||k->sample.sid_count!=64)return -EPERM;
 ret=retained_dma_blocked(p);if(ret)return ret;
 for(unsigned j=0;j<64;j++)if(readl(p->port+APCIEC_RID2SID+4*j))return -ESTALE;
 if(readl(p->port+APCIEC_MSICFG))return -ESTALE;
 ret=an_aic_ranges(p,ranges,&cells);if(ret)return ret;
 actual=of_get_property(p->dev->of_node,"msi-ranges",&len);
 if(cells!=6||!actual||len!=sizeof(ranges)||memcmp(actual,ranges,len)||an_msi_profile_base(p)!=jmx_native_base(p))return -ESTALE;
 for(unsigned j=0;j<k->owner.plan.count;j++){
  struct pci_dev*d=k->selected[j];u16 command;
  if(!d||d->driver||d->dev.driver||pci_dev_is_added(d)||d->is_busmaster||
     pci_read_config_word(d,PCI_COMMAND,&command)||command!=PCI_COMMAND_MEMORY||
     d->dev.iommu_group||dev_iommu_fwspec_get(&d->dev))return -EPERM;
  k->clients[j].host=p;k->clients[j].target=pci_dev_get(d);k->clients[j].active=true;
  map[4*j]=cpu_to_be32(k->owner.plan.client[j].identity.rid);
  map[4*j+1]=cpu_to_be32(p->retained_dart_node->phandle);
  map[4*j+2]=cpu_to_be32(j+1);map[4*j+3]=cpu_to_be32(1);
 }
 p->native=&k->clients[0];p->sid_count=64;
 of_changeset_init(&p->native->firmware);
 ret=an_add_property(p,"iommu-map",map,16*k->owner.plan.count);
 if(!ret)ret=an_add_property(p,"iommu-map-mask",&mask,sizeof(mask));
 if(!ret)ret=an_add_property(p,"msi-controller",NULL,0);
 if(!ret)ret=an_add_property(p,"dma-noncoherent",NULL,0);
 if(!ret)ret=an_add_property(p,"research,native-endpoint-memory-only",NULL,0);
 if(!ret)ret=jmn_gate(&k->owner);
 if(!ret)ret=of_changeset_apply(&p->native->firmware);
 return ret?ret:jmn_gate(&k->owner);
}
struct jmn_group_check{struct device*expected;unsigned count;};
static int jmn_hw_one_group(struct device*d,void*v)
{struct jmn_group_check*c=v;return d!=c->expected||c->count++?-EPERM:0;}
static int jmn_hw_dma_audit(struct jmn_kernel*k)
{
 struct apple_apciec*p=k->p;struct device*clients[JM_MAX_GPUS];unsigned sids[JM_MAX_GPUS];const __be32*map;u32 mask;int len;
 if(!jmn_kvalid(k,true)||!k->firmware_attempted||!p->dart||p->native!=&k->clients[0]||
    !jmx_native_sample(p,&k->sample)||k->sample.ias!=32||k->sample.oas!=42)return -EPERM;
 map=of_get_property(p->dev->of_node,"iommu-map",&len);
 if(!map||len!=16*k->owner.plan.count||of_property_read_u32(p->dev->of_node,"iommu-map-mask",&mask)||mask!=0xffff)return -EPERM;
 for(unsigned j=0;j<k->owner.plan.count;j++){
  struct pci_dev*d=k->selected[j];struct iommu_fwspec*fw;struct iommu_domain*domain;
  struct jmn_alias_context alias={d,k->owner.plan.client[j].identity.rid,0};
  struct jmn_group_check group;
  if(!d)return -EPERM;
  group=(struct jmn_group_check){&d->dev,0};
  clients[j]=&d->dev;sids[j]=j+1;fw=dev_iommu_fwspec_get(clients[j]);domain=iommu_get_domain_for_dev(clients[j]);
  if(!fw||fw->iommu_fwnode!=of_fwnode_handle(p->retained_dart_node)||fw->num_ids||
     !domain||domain->type!=IOMMU_DOMAIN_DMA||domain->pgsize_bitmap!=0x4000||
     !domain->geometry.force_aperture||domain->geometry.aperture_start||domain->geometry.aperture_end!=0xffffffffULL||
     dev_is_dma_coherent(clients[j])||!d->dev.iommu_group||
     iommu_group_for_each_dev(d->dev.iommu_group,&group,jmn_hw_one_group)||group.count!=1||
     pci_for_each_dma_alias(d,jmn_kalias,&alias)||alias.count!=1||k->aliases[j]!=1||
     be32_to_cpup(map+4*j)!=alias.rid||be32_to_cpup(map+4*j+1)!=p->retained_dart_node->phandle||
     be32_to_cpup(map+4*j+2)!=sids[j]||be32_to_cpup(map+4*j+3)!=1)return -EPERM;
  for(unsigned z=0;z<j;z++)if(d->dev.iommu_group==k->selected[z]->dev.iommu_group||domain==iommu_get_domain_for_dev(&k->selected[z]->dev))return -EPERM;
  k->clients[j].aliases=1;
 }
 return apple_dart_t8110_group_audit_try(&p->dart->dev,clients,sids,k->owner.plan.count,p->dev,32,42);
}
static int jmn_hw_rid_install(struct jmn_kernel*k)
{
 struct apple_apciec*p=k->p;int ret;
 if(k->rid_attempted)return -EALREADY;
 k->rid_attempted=true;
 ret=jmn_hw_dma_audit(k);if(ret)return ret;
 for(unsigned j=0;j<64;j++)if(readl(p->port+APCIEC_RID2SID+4*j))return -ESTALE;
 if(readl(p->port+APCIEC_MSICFG))return -ESTALE;
 for(unsigned j=0;j<k->owner.plan.count;j++){
  unsigned sid=j+1;u32 value=k->owner.plan.rid2sid[sid];
  ret=jmn_gate(&k->owner);if(ret)return ret;
  if(readl(p->port+APCIEC_RID2SID+4*sid))return -ESTALE;
  k->clients[j].dma_ready=true;writel(value,p->port+APCIEC_RID2SID+4*sid);
  if(readl(p->port+APCIEC_RID2SID+4*sid)!=value)return -EIO;
  k->clients[j].rid_ready=true;
 }
 for(unsigned j=0;j<64;j++)if(readl(p->port+APCIEC_RID2SID+4*j)!=k->owner.plan.rid2sid[j])return -ESTALE;
 p->iommu_ready=true;return jmn_gate(&k->owner);
}
static bool jmn_hw_msi_valid(void*v)
{
 struct jmn_kernel*k=v;
 /* Called by IRQ callbacks under the port spinlock: metadata only. */
 return k&&jmn_owner_slot(k,false)==k&&k->owner.consumed&&
  !READ_ONCE(k->owner.failed)&&!READ_ONCE(k->p->retained_failed)&&
  k->firmware_attempted&&k->rid_attempted&&
  k->p->native==&k->clients[0]&&jmx_native_scope(k->p,k->owner.plan.count,true);
}
static int jmn_hw_msi(struct jmn_kernel*k)
{
 struct apciec_native*clients[JM_MAX_GPUS];int ret;
 if(k->msi_attempted)return -EALREADY;
 k->msi_attempted=true;
 ret=jmn_hw_dma_audit(k);if(ret)return ret;
 for(unsigned j=0;j<k->owner.plan.count;j++)clients[j]=&k->clients[j];
 ret=jmn_gate(&k->owner);if(ret)return ret;
 ret=an_msi_prepare_mode(k->p,clients,k->owner.plan.count,jmn_hw_msi_valid,k);if(ret)return ret;
 k->msi_domain=k->clients[0].msi->domain;
 if(!an_msi_pair_ready(k->clients[0].msi))return -EPERM;
 return jmn_gate(&k->owner);
}
static int jmn_hw_live(struct jmn_kernel*k,bool sealed)
{
 struct apciec_native_msi*m=k->clients[0].msi;int ret;
 if(!jmn_kvalid(k,true)||k->owner.failed||!m||!m->exact_multi||m->exact_single||m->pair||
    m->multi_count!=k->owner.plan.count||m->multi_owner!=k||m->multi_validate!=jmn_hw_msi_valid||
    !an_msi_pair_ready(m)||m->domain!=k->msi_domain||m->aic_kind!=APCIEC_AIC2||m->aic_die||m->aic_base!=jmx_native_base(k->p))return -EPERM;
 ret=k->ops->audit(k,k->owner.phase);if(ret)return ret;
 ret=jmn_hw_dma_audit(k);if(ret)return ret;
 for(unsigned j=0;j<64;j++)if(readl(k->p->port+APCIEC_RID2SID+4*j)!=k->owner.plan.rid2sid[j])return -ESTALE;
 if(readl(k->p->port+APCIEC_MSIBASE)||readl(k->p->port+APCIEC_MSIADDR)!=0xfffff000)return -ESTALE;
 {u32 cfg=readl(k->p->port+APCIEC_MSICFG);if(cfg&&cfg!=0x51)return -ESTALE;}
 for(unsigned j=0;j<k->owner.plan.count;j++){
  struct pci_dev*d=k->selected[j];const struct jm_identity*id=&k->owner.plan.client[j].identity;u16 cmd;
  if(m->multi_clients[j]!=&k->clients[j]||k->clients[j].target!=d||
     pci_find_host_bridge(d->bus)!=k->bridge||pci_dev_id(d)!=id->rid||
     ((u32)d->device<<16|d->vendor)!=id->id||(d->class<<8|d->revision)!=id->class_rev||
     ((u32)d->subsystem_device<<16|d->subsystem_vendor)!=id->subsystem||pci_get_dsn(d)!=id->serial||
     d->is_virtfn||pci_num_vf(d)||d->ari_enabled||dev_get_msi_domain(&d->dev)!=m->domain||
     pci_read_config_word(d,PCI_COMMAND,&cmd)||!(cmd&PCI_COMMAND_MEMORY)||
     (cmd&~(PCI_COMMAND_MEMORY|PCI_COMMAND_MASTER|PCI_COMMAND_INTX_DISABLE)))return -EPERM;
  if(sealed){
   if(d->dev.iommu_group!=k->sealed_groups[j]||iommu_get_domain_for_dev(&d->dev)!=k->sealed_domains[j])return -ESTALE;
   for(unsigned b=0;b<PCI_NUM_RESOURCES;b++){
    const struct resource*a=&d->resource[b],*r=&k->sealed_bars[j][b];
    if(a->start!=r->start||a->end!=r->end||a->flags!=r->flags||a->parent!=r->parent)return -ESTALE;
   }
  }
 }
 return 0;
}
static int jmn_hw_seal(struct jmn_kernel*k)
{
 int ret;if(k->sealed||jmn_owner_slot(k,true))return -EALREADY;
 ret=jmn_gate(&k->owner);if(ret)return ret;
 ret=jmn_hw_live(k,false);if(ret)return ret;
 for(unsigned j=0;j<k->owner.plan.count;j++){
  struct pci_dev*d=k->selected[j];u16 cmd;
  if(pci_dev_is_added(d)||d->driver||d->dev.driver||d->is_busmaster||
     pci_read_config_word(d,PCI_COMMAND,&cmd)||(cmd&PCI_COMMAND_MASTER))return -EPERM;
  memcpy(k->sealed_bars[j],d->resource,sizeof(d->resource));
  k->sealed_groups[j]=d->dev.iommu_group;k->sealed_domains[j]=iommu_get_domain_for_dev(&d->dev);
 }
 ret=jmn_gate(&k->owner);if(ret)return ret;
 k->sealed=true;get_device(k->p->dev);get_device(&k->p->dart->dev);
 return jmn_owner_claim(k,true);
}
static int jmn_hw_driver(struct jmn_kernel*k,unsigned index,bool irq)
{
 struct pci_dev*d;struct apciec_native_msi*m;int ret;u16 cmd;
 bool standard=k->p->j314s_mixed_policy&&k->owner.plan.count==5;
 if(index>=k->owner.plan.count||!k->sealed||jmn_owner_slot(k,true)!=k)return -EPERM;
 d=k->selected[index];m=k->clients[index].msi;
 lockdep_assert_held(&k->p->lifecycle);
 if(!pci_dev_is_added(d)||pci_dev_binding_disallowed(d))return -EPERM;
 ret=jmn_hw_live(k,true);if(ret)goto out;
 if(pci_read_config_word(d,PCI_COMMAND,&cmd)){ret=-EIO;goto out;}
 if(!irq){ret=(cmd&PCI_COMMAND_MASTER)||d->is_busmaster?-EPERM:0;goto out;}
 if(standard?(!d->msi_enabled||d->msix_enabled):(!d->msi_enabled&&!d->msix_enabled)){ret=-EPERM;goto out;}
 __msi_lock_descs(&d->dev);
 if(!mutex_trylock(&m->lock)){ret=-EBUSY;goto descout;}
 {struct msi_desc*desc;unsigned vectors=0;ret=-EPERM;
  msi_for_each_desc(desc,&d->dev,MSI_DESC_ASSOCIATED){
   if(desc->dev!=&d->dev||!desc->irq||!desc->nvec_used||desc->nvec_used>32||vectors>32-desc->nvec_used||
      (standard&&(desc->pci.msi_attrib.is_msix||desc->nvec_used!=1)))goto msiout;
   for(unsigned j=0;j<desc->nvec_used;j++){
    unsigned irqno=desc->irq+j;struct irq_data*data=irq_domain_get_irq_data(m->domain,irqno);
    if(!data||data->hwirq>=32||irq_data_get_irq_chip_data(data)!=m||irq_data_get_irq_chip(data)!=&an_msi_chip||
       READ_ONCE(m->virqs[data->hwirq])!=irqno||
       !an_msi_vector_owned(&k->clients[index],data->hwirq)||irq_get_msi_desc(irqno)!=desc||
       !irq_has_action(irqno)||!j314s_parent_irq_matches(m,data))goto msiout;
    vectors++;
   }
  }
  if(standard?vectors==1:vectors>0)ret=0;
 }
 msiout:mutex_unlock(&m->lock);
 descout:__msi_unlock_descs(&d->dev);
 out:return ret;
}
static int jmn_export_admit(struct pci_dev*d,bool irq)
{
 struct jmn_kernel*k=jmn_owner_device(d,true);
 int ret;
 if(!k||k!=jmn_owner_slot(k,false))return -EOPNOTSUPP;
 if(!mutex_trylock(&k->p->lifecycle))return -EBUSY;
 ret=jmn_driver_admit(&k->owner,d,irq);
 mutex_unlock(&k->p->lifecycle);return ret;
}
/* Caller invokes once on its private ops copy; never modifies global policy. */
static void __maybe_unused jmn_install_hardware_ops(struct jmn_kernel_ops*ops)
{
 ops->firmware=jmn_hw_firmware;ops->dma_audit=jmn_hw_dma_audit;
 ops->rid_install=jmn_hw_rid_install;ops->msi=jmn_hw_msi;
 ops->seal=jmn_hw_seal;ops->driver=jmn_hw_driver;
}

/* Metadata-only initial mode selection, never truncates MSI-X vectors.
 * Frozen MSI capability was validated by ep_caps before publication. */
static bool jmn_standard_msi_cap(const struct ep_function*f,unsigned actual)
{
 u32 h;unsigned length;
 if(!f||!f->msi||actual!=f->msi||f->msi<0x40||(f->msi&3)||
    /* Bit9 is Extended Message Data capable; bit10 enable stays forbidden. */
    f->msi_control&~0x3ffU||f->msi_control&0x71||
    ((f->msi_control>>1)&7)>5||ja_sample(f,f->msi,&h)||
    (h&255)!=PCI_CAP_ID_MSI||(h>>16)!=f->msi_control)return false;
 length=(f->msi_control&PCI_MSI_FLAGS_64BIT)?16:12;
 if(f->msi_control&PCI_MSI_FLAGS_MASKBIT)length+=8;
 if(f->msi>256-length)return false;
 for(unsigned off=4;off<length;off+=4)if(ja_sample(f,f->msi+off,&h))return false;
 return true;
}
int apple_apciec_j314s_native_irq_limit(struct pci_dev*d);
int apple_apciec_j314s_native_irq_limit(struct pci_dev*d)
{
 struct jmn_kernel*k=jmn_owner_device(d,true);int ret=-EPERM;unsigned matches=0,index=0;
 if(!k||jmn_owner_slot(k,false)!=k)return -EOPNOTSUPP;
 if(!mutex_trylock(&k->p->lifecycle))return -EBUSY;
 if(!jmn_kvalid(k,true)||!k->sealed||!k->published||!k->owner.complete||
    k->owner.failed||k->owner.status||k->owner.phase!=JMN_PUBLISHED||
    k->p->retained_phase!=40||!pci_dev_is_added(d)||pci_dev_binding_disallowed(d))goto out;
 for(unsigned j=0;j<k->owner.plan.count;j++)if(k->selected[j]==d&&
    k->owner.evidence.device[j]==d&&k->clients[j].target==d){matches++;index=j;}
 if(matches!=1)goto out;
 if(k->p->j314s_mixed_policy&&k->owner.plan.count==5&&k->p->profile->index>0){
  const struct ep_function*f=jmc_function(k,k->owner.plan.client[index].index);
  if(d->msi_enabled||d->msix_enabled||!jmn_standard_msi_cap(f,d->msi_cap)){
   dev_err(k->p->dev,"j314s-initial-msi-refused: rid=%04x actual=%02x captured=%02x control=%04x msi=%u msix=%u\n",
    k->owner.plan.client[index].identity.rid,d->msi_cap,f?f->msi:0,f?f->msi_control:0,d->msi_enabled,d->msix_enabled);
   goto out;
  }
  ret=1;
 }else if(!k->p->j314s_mixed_policy&&!k->p->profile->index&&
         (k->owner.plan.count==2||k->owner.plan.count==4))ret=8;
 out:mutex_unlock(&k->p->lifecycle);return ret;
}
EXPORT_SYMBOL_GPL(apple_apciec_j314s_native_irq_limit);
