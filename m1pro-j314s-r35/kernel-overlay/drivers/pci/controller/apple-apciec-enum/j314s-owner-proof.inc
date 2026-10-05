static bool jmn_export_present(struct pci_dev*d);
static int jmn_export_admit(struct pci_dev *,bool);
/* SPDX-License-Identifier: GPL-2.0 */
/* Target native receipt: private phase40 seal after sameboot identity, resources,
 * selected SID1 T8110 domain and strict single-client AIC2 MSI ownership. */
#include <linux/interrupt.h>
#include "j314s-owner-core.h"
extern int apple_dart_t8110_group_audit_try(struct device *,struct device **,
 const unsigned *,unsigned,struct device *,unsigned,unsigned);
struct j314s_endpoint_receipt {
 struct apciec_native *native;
 struct pci_dev *target;
 struct iommu_domain *domain;
 struct iommu_group *group;
 struct ep_identity identity;
 struct resource bars[PCI_STD_NUM_BARS];
 unsigned rid,sid;
};
struct j314s_owner_receipt {
 struct apple_apciec *host;
 struct device *provider;
 struct pci_host_bridge *bridge;
 struct apciec_native_msi *msi;
 const void *ticket;
 unsigned count,ias,oas;
 struct j314s_endpoint_receipt clients[J314S_OWNER_MAX_CLIENTS];
};
static struct j314s_owner_receipt *j314s_owner_receipts[3];
static struct j314s_owner_receipt *j314s_failed_or_pending_receipts[3];
static atomic_t j314s_seal_attempts[3]={ATOMIC_INIT(0),ATOMIC_INIT(0),ATOMIC_INIT(0)};
static const u8 j314s_owner_profile_digest[32]={
 0xf2,0xca,0x15,0x95,0xb7,0x17,0x33,0x29,0x1a,0xa4,0x41,0xf2,0x47,0x17,0xb9,0x27,
 0x56,0xa6,0x67,0xf3,0x9c,0xd2,0xcc,0x12,0xe9,0x91,0xfc,0x67,0x8f,0xc7,0x62,0x4f};

static bool j314s_owner_host(struct apple_apciec *p)
{
 struct device_node *node;struct resource res;const u8 *digest;int len;bool same;
 const struct property *memory_only;
 if(!p||!p->dev||!p->dev->of_node||!apciec_profile_j314s(p->profile)||
    apciec_profile_node(p->dev->of_node)!=p->profile||
    !p->dev->driver||strcmp(p->dev->driver->name,"apple-apciec-research-disabled")||
    !p->j314s_raw_capability||!p->j314s_resource||!p->j314s_resource->complete||
    p->j314s_resource->failed||!j314s_measured_dma_sample(&p->j314s_resource->dma_sample)||
    !j314s_native_target_identity(p)||!p->retained||!p->retained_ticket||p->retained_failed||
    p->retained_phase!=J314S_NATIVE_PHASE_COMMITTED||
    p->retained_availability_probe||p->retained_provider_prepare||
    !p->prepared||!p->port_prepared||!p->power_ready||!p->tunnel_ready||
    !p->iommu_ready||!p->msi_domain_ready||!p->port||!p->ecam||
    !p->native||!p->dart||!p->retained_dart_node||p->retained_dart_window||
    p->rid_entries!=64||p->sid_count!=64||p->discovery_failed||
    !p->discovery_bridge||!p->discovery_bridge->discovery_only||
    p->discovery_bridge->dev.parent!=p->dev||p->discovery_bridge->sysdata!=p||
    !p->discovery_bridge->preserve_config||!p->discovery_bridge->enable_device||
    !p->discovery_bridge->disable_device)return false;
 memory_only=of_find_property(p->dev->of_node,"research,native-endpoint-memory-only",NULL);
 if(!memory_only||memory_only->length)return false;
 digest=of_get_property(p->dev->of_node,"research,j314s-fresh-profile",&len);
 if(!digest||len!=sizeof(j314s_owner_profile_digest)||
    memcmp(digest,j314s_owner_profile_digest,sizeof(j314s_owner_profile_digest)))return false;
 node=of_find_node_by_path(p->profile->dart_path);
 same=node&&node==p->retained_dart_node&&node==p->dart->dev.of_node&&
  node->parent==p->dev->of_node&&p->dart->dev.parent==p->dev&&
  of_device_is_compatible(node,"apple,t8110-dart");
 of_node_put(node);
 if(!same||of_address_to_resource(p->retained_dart_node,0,&res)||
    res.start!=p->profile->dart||resource_size(&res)!=0x4000||
    res.flags!=(IORESOURCE_MEM|IORESOURCE_MEM_NONPOSTED))return false;
 return true;
}
static int j314s_msi_parent_audit(const struct j314s_owner_receipt *r)
{
 struct apciec_native_msi *m=r->msi;
 const struct apciec_aic_platform *plat=an_aic_platform();
 struct device_node *expected;bool same;
 if(!m||m->p!=r->host||!m->exact_single||m->pair||m->pair_clients[0]!=r->host->native||
    m->pair_clients[1]||READ_ONCE(m->stopping)||!m->domain||
    !plat||plat->kind!=APCIEC_AIC2||r->host->profile->index>=plat->nr_ports||
    m->domain->host_data!=m||m->domain->ops!=&an_msi_ops||
    m->aic_kind!=APCIEC_AIC2||m->aic_die!=plat->die||
    m->aic_base!=plat->base[r->host->profile->index]||
    apciec_aic_validate(m->aic_kind,m->aic_die,m->aic_base,32,65536,
                       m->spec.param,m->spec.param_count))return -EPERM;
 expected=an_aic_node(plat);same=expected&&expected==m->aic&&
  m->spec.fwnode==of_fwnode_handle(expected)&&
  m->domain->parent==irq_find_matching_fwspec(&m->spec,DOMAIN_BUS_WIRED);
 of_node_put(expected);
 if(!same||readl(r->host->port+APCIEC_MSIBASE)||
    readl(r->host->port+APCIEC_MSIADDR)!=0xfffff000)return -EPERM;
 {u32 cfg=readl(r->host->port+APCIEC_MSICFG);if(cfg&&cfg!=0x51)return -EPERM;}
 return 0;
}
static int j314s_owner_caps_disabled(struct apple_apciec *p,struct pci_dev *d)
{
 const struct ep_function *f=NULL;unsigned j,ari,sriov;u32 v;
 if(!p->endpoint_snapshot||p->endpoint_snapshot->count>EP_MAX_RECORDS)return -EPERM;
 for(j=0;j<p->endpoint_snapshot->count;j++)
  if(p->endpoint_snapshot->functions[j].identity.rid==pci_dev_id(d)){
   if(f)return -EPERM;
   f=&p->endpoint_snapshot->functions[j];
  }
 if(!f||!j314s_capabilities_disabled(f)||j314s_cap_offsets(f,&ari,&sriov))return -EPERM;
 if(pci_read_config_dword(d,f->pcie+PCI_EXP_DEVCTL2,&v)||(v&PCI_EXP_DEVCTL2_ARI))return -EPERM;
 if(ari&&(pci_read_config_dword(d,ari+4,&v)||(v>>16)))return -EPERM;
 if(sriov&&(pci_read_config_dword(d,sriov+8,&v)||(v&65535)||
            pci_read_config_dword(d,sriov+0x10,&v)||(v&65535)))return -EPERM;
 return 0;
}
struct j314s_alias_context {struct pci_dev *target;unsigned rid,count;};
static int j314s_alias_exact(struct pci_dev *d,u16 alias,void *arg)
{
 struct j314s_alias_context *c=arg;
 if(d!=c->target||alias!=c->rid||c->count)return -EPERM;
 c->count++;return 0;
}
/* Host lifecycle is held; provider locking is nonblocking to avoid inversion
 * under NVIDIA's device lock. Driver must hold its own probe/init lifetime. */
static int j314s_owner_live_audit(const struct j314s_owner_receipt *r)
{
 struct apple_apciec *p=r->host;
 struct device *clients[J314S_OWNER_MAX_CLIENTS];
 unsigned sids[J314S_OWNER_MAX_CLIENTS],rids[J314S_OWNER_MAX_CLIENTS];
 const __be32 *map;unsigned i,j,k;int len,ret;u32 mask;
 if(!j314s_owner_host(p)||r->count!=1||r->ias!=32||r->oas!=42||
    r->clients[0].rid!=p->j314s_resource->selected.rid||r->clients[0].sid!=1||
    r->ticket!=p->retained_ticket||r->bridge!=p->discovery_bridge||
    r->provider!=&p->dart->dev||!r->msi||!r->msi->domain||!r->count||r->count>J314S_OWNER_MAX_CLIENTS||
    r->clients[0].native!=p->native)return -EPERM;
 map=of_get_property(p->dev->of_node,"iommu-map",&len);
 if(!map||len!=r->count*4*sizeof(*map)||
    of_property_read_u32(p->dev->of_node,"iommu-map-mask",&mask)||mask!=0xffff)return -EPERM;
 for(i=0;i<r->count;i++) {
  const struct j314s_endpoint_receipt *e=&r->clients[i];
  struct apciec_native *n=e->native;struct pci_dev *d=e->target;
  struct iommu_fwspec *fw;u16 cmd;
  struct j314s_alias_context aliases={.target=d,.rid=e->rid};
  rids[i]=e->rid;sids[i]=e->sid;
  if(!n||!d||n->target!=d||n->host!=p||!READ_ONCE(n->active)||READ_ONCE(n->failed)||
     !READ_ONCE(n->dma_ready)||!READ_ONCE(n->rid_ready)||!READ_ONCE(n->irq_ready)||
     n->aliases!=1||n->msi!=r->msi||pci_find_host_bridge(d->bus)!=r->bridge||
     pci_dev_id(d)!=e->rid||d->vendor!=0x10de||(d->class>>16)!=PCI_BASE_CLASS_DISPLAY||
     PCI_FUNC(d->devfn)||d->hdr_type!=PCI_HEADER_TYPE_NORMAL||
     d->hdr_type!=(e->identity.header&0x7f)||!!d->multifunction!=!!(e->identity.header&0x80)||
     d->is_virtfn||pci_num_vf(d)||d->ari_enabled||
     e->identity.rid!=e->rid||((u32)d->device<<16|d->vendor)!=e->identity.id||
     ((u32)d->subsystem_device<<16|d->subsystem_vendor)!=e->identity.subsystem||
     (d->class<<8|d->revision)!=e->identity.class_rev||
     !e->identity.serial||pci_get_dsn(d)!=e->identity.serial||
     d->dev.iommu_group!=e->group||!e->group||
     iommu_get_domain_for_dev(&d->dev)!=e->domain||!e->domain||
     e->domain->type!=IOMMU_DOMAIN_DMA||dev_is_dma_coherent(&d->dev)||
     dev_get_msi_domain(&d->dev)!=r->msi->domain)return -EPERM;
  if(pci_for_each_dma_alias(d,j314s_alias_exact,&aliases)||aliases.count!=1)return -EPERM;
  if(j314s_owner_caps_disabled(p,d))return -EPERM;
  fw=dev_iommu_fwspec_get(&d->dev);
  if(!fw||fw->iommu_fwnode!=of_fwnode_handle(p->retained_dart_node)||fw->num_ids)return -EPERM;
  for(j=0;j<i;j++)if(d==r->clients[j].target||e->group==r->clients[j].group||
                       e->domain==r->clients[j].domain)return -EPERM;
  if(be32_to_cpup(map+4*i)!=e->rid||be32_to_cpup(map+4*i+1)!=p->retained_dart_node->phandle||
     be32_to_cpup(map+4*i+2)!=e->sid||be32_to_cpup(map+4*i+3)!=1)return -EPERM;
  if(pci_read_config_word(d,PCI_COMMAND,&cmd)||
     cmd&~(PCI_COMMAND_MEMORY|PCI_COMMAND_MASTER|PCI_COMMAND_INTX_DISABLE)||
     !(cmd&PCI_COMMAND_MEMORY))return -EPERM;
  for(k=0;k<PCI_STD_NUM_BARS;k++) {
   const struct resource *now=&d->resource[k],*saved=&e->bars[k];
   if(now->start!=saved->start||now->end!=saved->end||now->flags!=saved->flags||
      now->parent!=saved->parent)return -ESTALE;
   if(now->flags&IORESOURCE_MEM) {
    if(!now->parent||now->end<now->start||now->flags&IORESOURCE_UNSET||
       d->non_mappable_bars)return -EPERM;
   } else if(now->flags&IORESOURCE_IO) {if(now->start||now->parent)return -EPERM;}
  }
  clients[i]=&d->dev;
 }
 if(!j314s_owner_shape(r->count,rids,sids,r->ias,r->oas))return -EPERM;
 for(i=0;i<64;i++) {
  u32 expected=0;
  for(j=0;j<r->count;j++)if(sids[j]==i)expected=APCIEC_RID_VALID|(i<<16)|rids[j];
  if(readl(p->port+APCIEC_RID2SID+4*i)!=expected)return -ESTALE;
 }
 ret=j314s_msi_parent_audit(r);if(ret)return ret;
 return apple_dart_t8110_group_audit_try(r->provider,clients,sids,r->count,p->dev,r->ias,r->oas);
}

/* Not exported. Target native owner calls exactly
 * once, under lifecycle lock, after its independently verified phase40 commit.
 * No user/module can supply a receipt, and no receipt/owner is freed this boot. */
static int j314s_owner_seal_locked(struct apple_apciec *p,
 const void *ticket,struct apciec_native *const *natives,const unsigned *rids,
 const unsigned *sids,unsigned count,unsigned ias,unsigned oas)
{
 struct j314s_owner_receipt *r;unsigned i,j,index;int ret;
 if(!j314s_owner_host(p)||count!=1||ias!=32||oas!=42||!rids||!sids||
    rids[0]!=p->j314s_resource->selected.rid||sids[0]!=1||
    ticket!=p->retained_ticket||!natives||
    !j314s_owner_shape(count,rids,sids,ias,oas))return -EPERM;
 lockdep_assert_held(&p->lifecycle);index=p->profile->index;
 if(index>=3||atomic_cmpxchg(&j314s_seal_attempts[index],0,1))return -EPERM;
 r=kzalloc(sizeof(*r),GFP_KERNEL);if(!r)return -ENOMEM;
 j314s_failed_or_pending_receipts[index]=r; /* Intentionally retained on every failure. */
 r->host=p;r->provider=&p->dart->dev;r->bridge=p->discovery_bridge;
 r->ticket=ticket;r->count=count;r->ias=ias;r->oas=oas;r->msi=p->native->msi;
 if(!p->endpoint_snapshot||!p->endpoint_snapshot->captured||
    !p->endpoint_snapshot->planned||!p->endpoint_snapshot->memory_assigned||
    !p->endpoint_snapshot->count||p->endpoint_snapshot->count>EP_MAX_RECORDS)return -EPERM;
 for(i=0;i<count;i++) {
  struct j314s_endpoint_receipt *e=&r->clients[i];const struct ep_function *f=NULL;
  if(!natives[i]||!natives[i]->target)return -EPERM;
  e->native=natives[i];e->target=pci_dev_get(natives[i]->target);e->rid=rids[i];e->sid=sids[i];
  for(j=0;j<p->endpoint_snapshot->count;j++)
   if(p->endpoint_snapshot->functions[j].identity.rid==e->rid) {
    if(f)return -EPERM;
    f=&p->endpoint_snapshot->functions[j];
   }
  if(!f||!f->serial_present)return -EPERM;
  e->identity=f->identity;e->domain=iommu_get_domain_for_dev(&e->target->dev);
  e->group=e->target->dev.iommu_group;
  memcpy(e->bars,e->target->resource,sizeof(e->bars));
 }
 ret=j314s_owner_live_audit(r);if(ret)return ret;
 get_device(p->dev);get_device(r->provider);
 smp_store_release(&j314s_owner_receipts[index],r);
 return 0;
}

/* AIC's parent hwirq includes event type and die, not just vector number.
 * Ask the already validated parent domain to translate its exact fwspec. */
static bool j314s_parent_irq_matches(struct apciec_native_msi *m,
                                     struct irq_data *data)
{
 struct irq_domain *parent=m->domain->parent;
 struct irq_fwspec spec=m->spec;
 irq_hw_number_t expected;unsigned type;
 if(!parent||!parent->ops||!parent->ops->translate||!data||
    data->hwirq>=32||!data->parent_data||data->parent_data->domain!=parent)
  return false;
 if(apciec_aic_vector(m->aic_kind,m->aic_die,m->aic_base,65536,
                      data->hwirq,1,spec.param,spec.param_count))return false;
 if(parent->ops->translate(parent,&spec,&expected,&type))return false;
 return type==IRQ_TYPE_EDGE_RISING&&data->parent_data->hwirq==expected;
}
static int j314s_leaf_irq_audit(const struct j314s_owner_receipt *r,struct pci_dev *d)
{
 struct msi_desc *desc;struct apciec_native_msi *m=r->msi;
 unsigned vectors=0,i;int ret=-EPERM;
 if(!d->msi_enabled&&!d->msix_enabled)return -EPERM;
 /* Descriptor mutex precedes parent allocator mutex, matching MSI allocation. */
 __msi_lock_descs(&d->dev);
 if(!mutex_trylock(&m->lock)){ret=-EBUSY;goto unlock_descs;}
 if(READ_ONCE(m->stopping))goto unlock_parent;
 msi_for_each_desc(desc,&d->dev,MSI_DESC_ASSOCIATED) {
  if(desc->dev!=&d->dev||!desc->irq||!desc->nvec_used||desc->nvec_used>32||
     vectors>32-desc->nvec_used)goto unlock_parent;
  for(i=0;i<desc->nvec_used;i++) {
   unsigned irq=desc->irq+i;struct irq_data *data=irq_domain_get_irq_data(m->domain,irq);
   if(!data||data->hwirq>=32||irq_data_get_irq_chip_data(data)!=m||
      irq_data_get_irq_chip(data)!=&an_msi_chip||!test_bit(data->hwirq,m->used)||
      irq_get_msi_desc(irq)!=desc||!irq_has_action(irq)||
      READ_ONCE(m->owners[data->hwirq])!=r->clients[0].native||
      READ_ONCE(m->virqs[data->hwirq])!=irq||
      !j314s_parent_irq_matches(m,data))goto unlock_parent;
   vectors++;
  }
 }
 if(vectors)ret=0;
unlock_parent:mutex_unlock(&m->lock);
unlock_descs:__msi_unlock_descs(&d->dev);return ret;
}
static int j314s_native_attest(struct pci_dev *d,bool leaf_irq)
{
 struct j314s_owner_receipt *r=NULL;unsigned i,j;int ret=-EPERM;u16 cmd;
 if(!d||!of_machine_is_compatible("apple,j314s"))return -EPERM;
 for(i=0;i<3;i++) {
  struct j314s_owner_receipt *candidate=smp_load_acquire(&j314s_owner_receipts[i]);
  if(!candidate)continue;
  for(j=0;j<candidate->count;j++)if(candidate->clients[j].target==d){if(r)return -EPERM;r=candidate;}
 }
 if(!r)return -EOPNOTSUPP;
 if(!pci_dev_is_added(d)||pci_dev_binding_disallowed(d))return -EPERM;
 if(!mutex_trylock(&r->host->lifecycle))return -EBUSY;
 ret=j314s_owner_live_audit(r);if(ret){dev_err(r->host->dev,"J314s driver owner audit failed irq=%u status=%d\n",leaf_irq,ret);goto out;}
 if(pci_read_config_word(d,PCI_COMMAND,&cmd)){ret=-EIO;goto out;}
 if(!leaf_irq&&((cmd&PCI_COMMAND_MASTER)||d->is_busmaster)){ret=-EPERM;goto out;}
 if(leaf_irq){ret=j314s_leaf_irq_audit(r,d);if(ret)dev_err(r->host->dev,"J314s driver leaf IRQ audit failed status=%d\n",ret);}
out:mutex_unlock(&r->host->lifecycle);return ret;
}
int apple_apciec_j314s_native_admit(struct pci_dev *d);
int apple_apciec_j314s_native_admit(struct pci_dev *d)
{return jmn_export_present(d)?jmn_export_admit(d,false):j314s_native_attest(d,false);}
EXPORT_SYMBOL_GPL(apple_apciec_j314s_native_admit);
int apple_apciec_j314s_native_irq_admit(struct pci_dev *d);
int apple_apciec_j314s_native_irq_admit(struct pci_dev *d)
{return jmn_export_present(d)?jmn_export_admit(d,true):j314s_native_attest(d,true);}
EXPORT_SYMBOL_GPL(apple_apciec_j314s_native_irq_admit);

/* Metadata-only completion for native historical report. No new action grant. */
static bool j314s_owner_published(struct apple_apciec *p)
{
 struct j314s_owner_receipt *r=smp_load_acquire(&j314s_owner_receipts[0]);
 return p&&apciec_profile_j314s(p->profile)&&!p->profile->index&&r&&
  p->j314s_resource&&r->host==p&&r->ticket==p->retained_ticket&&r->count==1&&r->ias==32&&r->oas==42&&
  r->clients[0].native==p->native&&r->clients[0].target==j314s_native_selected(p)&&
  r->clients[0].rid==p->j314s_resource->selected.rid&&r->clients[0].sid==1;
}
