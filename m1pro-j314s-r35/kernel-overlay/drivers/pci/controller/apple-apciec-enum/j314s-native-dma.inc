/* Target-only native admission after sameboot assignment/discovery/MMIO proof.
 * Include after legacy native-host.inc. Caller holds lifecycle throughout.
 * No publication, driver matching, bus-master enable or retries here. */
extern int apple_dart_t8110_group_audit_try(struct device *,struct device **,
 const unsigned *,unsigned,struct device *,unsigned,unsigned);
static bool j314s_native_target_identity(struct apple_apciec *);
static struct pci_dev *j314s_native_selected(struct apple_apciec *);
static struct pci_host_bridge *j314s_native_bridge(struct apple_apciec *);
static int j314s_native_dma_audit(struct apple_apciec *p)
{
 struct device *clients[1];unsigned sids[1]={1};
 struct iommu_fwspec *fw;struct iommu_domain *domain;struct pci_dev *d;
 if(!p||!apciec_profile_j314s(p->profile)||p->profile->index||!p->native||
    !p->native->active||p->native->failed||p->native->host!=p||
    !p->j314s_resource||!p->j314s_resource->complete||p->j314s_resource->failed||
    !j314s_measured_dma_sample(&p->j314s_resource->dma_sample)||
    !p->dart||!p->retained_dart_node||!j314s_native_target_identity(p))return -EPERM;
 d=j314s_native_selected(p);
 if(!d||p->native->target!=d||!j314s_native_bridge(p)||
    j314s_native_bridge(p)->discovery_dma_device!=d||
    pci_dev_id(d)!=p->j314s_resource->selected.rid||p->native->aliases!=1)return -EPERM;
 clients[0]=&d->dev;fw=dev_iommu_fwspec_get(clients[0]);domain=iommu_get_domain_for_dev(clients[0]);
 if(!fw||fw->iommu_fwnode!=of_fwnode_handle(p->retained_dart_node)||fw->num_ids||
    !domain||domain->type!=IOMMU_DOMAIN_DMA||domain->pgsize_bitmap!=0x4000||
    !domain->geometry.force_aperture||domain->geometry.aperture_start||
    domain->geometry.aperture_end!=0xffffffffULL||dev_is_dma_coherent(clients[0]))return -EPERM;
 /* Inspects exact paging roots, SID1 only, every other SID/TTBR disabled,
  * all64 stream slots and error state using normal T8110 provider ownership. */
 return apple_dart_t8110_group_audit_try(&p->dart->dev,clients,sids,1,p->dev,
                  p->j314s_resource->dma_sample.ias,p->j314s_resource->dma_sample.oas);
}
static int j314s_native_alias(struct pci_dev *d,u16 alias,void *arg)
{
 struct apple_apciec *p=arg;
 if(!j314s_native_target_identity(p)||d!=p->native->target||
    alias!=p->j314s_resource->selected.rid||p->native->aliases)return -EPERM;
 p->native->aliases++;return 0;
}
static int j314s_native_firmware(struct apple_apciec *p)
{
 __be32 map[4],mask=cpu_to_be32(0xffff),ranges[6];
 const void *actual;unsigned cells;int ret,len;
 if(!p->retained_dart_node||!p->retained_dart_node->phandle)return -EPERM;
 ret=an_aic_ranges(p,ranges,&cells);if(ret)return ret;
 actual=of_get_property(p->dev->of_node,"msi-ranges",&len);
 if(!actual||cells!=6||len!=cells*sizeof(*ranges)||memcmp(actual,ranges,len)||
    an_msi_profile_base(p)!=0x64e)return -ESTALE;
 /* msiranges already exists in pinned J314s profile; do not duplicate it. */
 map[0]=cpu_to_be32(p->j314s_resource->selected.rid);
 map[1]=cpu_to_be32(p->retained_dart_node->phandle);
 map[2]=cpu_to_be32(1);map[3]=cpu_to_be32(1);
 of_changeset_init(&p->native->firmware);
 ret=an_add_property(p,"iommu-map",map,sizeof(map));
 if(!ret)ret=an_add_property(p,"iommu-map-mask",&mask,sizeof(mask));
 if(!ret)ret=an_add_property(p,"msi-controller",NULL,0);
 if(!ret)ret=an_add_property(p,"dma-noncoherent",NULL,0);
 if(!ret)ret=an_add_property(p,"research,native-endpoint-memory-only",NULL,0);
 if(!ret&&ktime_get_boottime_ns()>=p->retained_identity_deadline)ret=-ETIMEDOUT;
 if(!ret)ret=of_changeset_apply(&p->native->firmware);
 return ret;
}
static int j314s_native_dma_prepare(struct apple_apciec *p)
{
 struct pci_dev *d;struct pci_host_bridge *bridge;unsigned j;u16 command;u32 ridword;int ret;
 lockdep_assert_held(&p->lifecycle);
 if(!apciec_profile_j314s(p->profile)||p->profile->index||!p->j314s_raw_capability||
    !p->native||p->native->host!=p||!p->native->active||p->native->failed||
    p->native->dma_ready||p->native->rid_ready||p->native->irq_ready||p->native->aliases||
    !p->j314s_resource||!p->j314s_resource->complete||p->j314s_resource->failed||
    !j314s_native_target_identity(p)||p->iommu_ready||p->msi_domain_ready||
    !p->power_ready||!p->tunnel_ready||p->rid_entries!=64||
    ktime_get_boottime_ns()>=p->retained_identity_deadline)return -EPERM;
 d=j314s_native_selected(p);bridge=j314s_native_bridge(p);
 if(!d||p->native->target!=d||!bridge||!bridge->discovery_only||bridge->discovery_dma_device||
    pci_find_host_bridge(d->bus)!=bridge||d->driver||d->dev.driver||pci_dev_is_added(d)||
    d->dev.iommu_group||dev_iommu_fwspec_get(&d->dev)||
    pci_read_config_word(d,PCI_COMMAND,&command)||(command&PCI_COMMAND_MASTER))return -EPERM;
 ret=retained_dma_blocked(p);if(ret)return ret;
 if(!j314s_measured_dma_sample(&p->j314s_resource->dma_sample))return -ESTALE;
 p->sid_count=p->j314s_resource->dma_sample.sid_count;
 ret=pci_for_each_dma_alias(d,j314s_native_alias,p);
 if(ret||p->native->aliases!=1)return ret?ret:-EPERM;
 ret=j314s_native_firmware(p);if(ret)return ret;
 if(ktime_get_boottime_ns()>=p->retained_identity_deadline)return -ETIMEDOUT;
 bridge->discovery_dma_device=d;
 ret=iommu_probe_device(&d->dev);if(ret)return ret;
 ret=j314s_native_dma_audit(p);if(ret)return ret;
 /* No RID has pointed at a translated stream until full domain audit passed. */
 for(j=0;j<64;j++)if(readl(p->port+APCIEC_RID2SID+4*j))return -ESTALE;
 if(readl(p->port+APCIEC_MSICFG))return -ESTALE;
 if(ktime_get_boottime_ns()>=p->retained_identity_deadline)return -ETIMEDOUT;
 p->native->dma_ready=true;
 ridword=BIT(31)|BIT(16)|p->j314s_resource->selected.rid;
 writel(ridword,p->port+APCIEC_RID2SID+4);
 if(readl(p->port+APCIEC_RID2SID+4)!=ridword)return -EIO;
 p->native->rid_ready=true;p->iommu_ready=true;
 return ktime_get_boottime_ns()>=p->retained_identity_deadline?-ETIMEDOUT:j314s_native_dma_audit(p);
}
static int j314s_native_msi_audit(struct apple_apciec *p)
{
 struct apciec_native_msi *m;unsigned j;u32 expected,v;
 if(!p||!p->native||!p->native->dma_ready||!p->native->rid_ready||
    !p->native->irq_ready||p->native->failed||!p->msi_domain_ready||
    !j314s_native_target_identity(p))return -EPERM;
 m=p->native->msi;
 if(!m||!m->exact_single||m->pair||m->p!=p||m->pair_clients[0]!=p->native||
    m->pair_clients[1]||m->aic_kind!=APCIEC_AIC2||m->aic_die||m->aic_base!=0x64e||
    !m->domain||m->stopping||dev_get_msi_domain(&p->native->target->dev)!=m->domain)return -EPERM;
 expected=BIT(31)|BIT(16)|p->j314s_resource->selected.rid;
 for(j=0;j<64;j++)if(readl(p->port+APCIEC_RID2SID+4*j)!=(j==1?expected:0))return -ESTALE;
 v=readl(p->port+APCIEC_MSICFG);
 if((v&&v!=0x51)||readl(p->port+APCIEC_MSIBASE)||readl(p->port+APCIEC_MSIADDR)!=0xfffff000)return -ESTALE;
 return j314s_native_dma_audit(p);
}
static int j314s_native_msi_prepare(struct apple_apciec *p)
{
 int ret;
 lockdep_assert_held(&p->lifecycle);
 if(!p->native||!p->native->dma_ready||!p->native->rid_ready||p->native->msi||
    p->native->irq_ready||p->native->failed||an_msi_profile_base(p)!=0x64e||
    ktime_get_boottime_ns()>=p->retained_identity_deadline)return -EPERM;
 ret=j314s_native_dma_audit(p);if(ret)return ret;
 ret=an_msi_prepare(p);if(ret)return ret;
 p->native->msi->exact_single=true;p->native->msi->pair_clients[0]=p->native;
 if(ktime_get_boottime_ns()>=p->retained_identity_deadline)return -ETIMEDOUT;
 return j314s_native_msi_audit(p);
}
