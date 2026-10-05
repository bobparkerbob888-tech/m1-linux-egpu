#include "aic-platform.inc"
/* SPDX-License-Identifier: GPL-2.0 */
/* Ordinary PCI MSI parent domain. The selected native driver owns its IRQs.
 * No guest isolation or interrupt-remapping claim is made. */
struct apciec_native_msi {
 struct apple_apciec *p;
 struct device_node *aic;
 struct irq_domain *domain;
 struct irq_fwspec spec;
 struct mutex lock;
 DECLARE_BITMAP(used, 32);
 unsigned aic_base;
 unsigned aic_kind, aic_die; 
 bool stopping;
 bool pair, exact_single, exact_multi;
 unsigned multi_count;struct apciec_native*multi_clients[5];
 bool (*multi_validate)(void*);void*multi_owner;
 struct apciec_native *pair_clients[2], *owners[32];
 unsigned virqs[32];
};

/* Only the opt-in pair uses per-device IRQ allocation ownership. Legacy
 * three/single-target paths retain their existing checks. Native owners are
 * never freed during a boot, including allocation/publication failure. */
static bool an_msi_pair_ready(struct apciec_native_msi *m)
{
 unsigned i;
 if(!m||!m->p||!m->p->profile||(!m->pair&&!m->exact_single&&!m->exact_multi)||(m->pair&&m->exact_single)||READ_ONCE(m->stopping))return false;
 if(m->exact_single && (!apciec_profile_j314s(m->p->profile)||m->p->profile->index||
    m->pair_clients[0]!=m->p->native||m->pair_clients[1]||
    !m->p->native||m->p->native->host!=m->p))return false;
 if(m->exact_multi&&((m->pair||m->exact_single)||
  !jmx_native_scope(m->p,m->multi_count,true)||!m->multi_validate||!m->multi_owner||
  !m->multi_validate(m->multi_owner)||
  m->multi_clients[0]!=m->p->native))return false;
 for(i=0;i<(m->exact_multi?m->multi_count:m->exact_single?1:2);i++) {
  struct apciec_native *n=m->exact_multi?m->multi_clients[i]:m->pair_clients[i];
  if(!n||!READ_ONCE(n->active)||READ_ONCE(n->failed)||
     !READ_ONCE(n->dma_ready)||!READ_ONCE(n->rid_ready)||
     !READ_ONCE(n->irq_ready)||n->msi!=m)return false;
  if(m->exact_multi){
   if(n->host!=m->p||!n->target)return false;
   for(unsigned j=0;j<i;j++)if(n==m->multi_clients[j]||n->target==m->multi_clients[j]->target)return false;
  }
 }
 return true;
}
static bool an_msi_vector_owned(struct apciec_native *n,unsigned local)
{
 struct apciec_native_msi *m=n?n->msi:NULL;
 struct irq_data *data;struct msi_desc *desc;unsigned virq;
 if(!m||local>=32||!test_bit(local,m->used))return false;
 if(!m->pair&&!m->exact_single&&!m->exact_multi)return true;
 if(!an_msi_pair_ready(m)||READ_ONCE(m->owners[local])!=n)return false;
 virq=READ_ONCE(m->virqs[local]);if(!virq)return false;
 data=irq_domain_get_irq_data(m->domain,virq);desc=irq_get_msi_desc(virq);
 return data&&data->hwirq==local&&irq_data_get_irq_chip_data(data)==m&&
        desc&&desc->dev==&n->target->dev&&virq>=desc->irq&&
        virq-desc->irq<desc->nvec_used;
}
static bool an_msi_pair_irq(struct apciec_native_msi *m,struct irq_data *d)
{
 struct apciec_native *n;
 if(!m->pair&&!m->exact_single&&!m->exact_multi)return true;
 if(d->hwirq>=32)return false;
 n=READ_ONCE(m->owners[d->hwirq]);
 return n&&READ_ONCE(m->virqs[d->hwirq])==d->irq&&an_msi_vector_owned(n,d->hwirq);
}

static void an_msi_compose(struct irq_data *d, struct msi_msg *msg)
{
 msg->address_hi = 0;
 msg->address_lo = 0xfffff000;
 msg->data = d->hwirq;
}

static void an_msi_unmask(struct irq_data *d)
{
 struct apciec_native_msi *m = irq_data_get_irq_chip_data(d);
 struct apple_apciec *p = m->p;
 unsigned long flags;
 bool ready;
 raw_spin_lock_irqsave(&p->lock, flags);
 ready = p->native && p->native->irq_ready && p->native->rid_ready &&
         !p->native->failed && !m->stopping && d->hwirq < 32 &&
         test_bit(d->hwirq, m->used) && an_msi_pair_irq(m,d);
 if (ready) {
  /* Message address/base were validated while controller delivery was off.
   * The IRQ core starts this vector only after its handler is installed. */
  writel(0x51, p->port + APCIEC_MSICFG);
  ready = readl(p->port + APCIEC_MSICFG) == 0x51;
  if (!ready) { p->native->failed = true;
   if(m->pair)m->pair_clients[1]->failed=true;
   if(m->exact_multi)for(unsigned j=0;j<m->multi_count;j++)m->multi_clients[j]->failed=true;
  }
 }
 raw_spin_unlock_irqrestore(&p->lock, flags);
 if (ready) irq_chip_unmask_parent(d);
 else irq_chip_mask_parent(d);
}

static void an_msi_eoi(struct irq_data *d)
{
 struct apciec_native_msi *m = irq_data_get_irq_chip_data(d);
 if (READ_ONCE(m->stopping) || !READ_ONCE(m->p->native->irq_ready) ||
     READ_ONCE(m->p->native->failed) || !an_msi_pair_irq(m,d)) {
  irq_chip_mask_parent(d);
  return;
 }
 irq_chip_eoi_parent(d);
}

static struct irq_chip an_msi_chip = {
 .name = "APCIEC-native",
 .irq_mask = irq_chip_mask_parent,
 .irq_unmask = an_msi_unmask,
 .irq_eoi = an_msi_eoi,
 .irq_set_affinity = irq_chip_set_affinity_parent,
 .irq_set_type = irq_chip_set_type_parent,
 .irq_compose_msi_msg = an_msi_compose,
};

/* Five typed clients share the actual32-vector controller pool. Bound each
 * client to1 before allocation, including per-descriptor MSI-X requests. */
static int an_msi_client_budget(struct apciec_native_msi*m,struct apciec_native*owner,unsigned nr)
{
 unsigned held=0;
 if(!m->exact_multi||m->multi_count!=5)return 0;
 if(!owner||!m->p->j314s_mixed_policy||!jmx_native_scope(m->p,5,true)||nr!=1)return -ENOSPC;
 for(unsigned j=0;j<32;j++)if(test_bit(j,m->used)&&READ_ONCE(m->owners[j])==owner)held++;
 return held==0?0:-ENOSPC;
}
static int an_msi_alloc(struct irq_domain *domain, unsigned virq,
                       unsigned nr, void *arg)
{
 struct apciec_native_msi *m = domain->host_data;
 struct irq_fwspec spec = m->spec;
 unsigned i;
 struct apciec_native *owner=NULL;
 msi_alloc_info_t *info=arg;
 int local, ret;
 if (!nr || nr > 32 || !is_power_of_2(nr)) return -EINVAL;
 mutex_lock(&m->lock);
 if (m->stopping || !m->p->native->irq_ready || m->p->native->failed) {
  ret = -ESHUTDOWN; goto out;
 }
 if(m->pair||m->exact_single||m->exact_multi) {
  if(!an_msi_pair_ready(m)||!info||!info->desc||!info->desc->dev||
     info->desc->nvec_used!=nr){ret=-EPERM;goto out;}
  for(i=0;i<(m->exact_multi?m->multi_count:m->exact_single?1:2);i++){
   struct apciec_native*n=m->exact_multi?m->multi_clients[i]:m->pair_clients[i];
   if(info->desc->dev==&n->target->dev){if(owner){ret=-EPERM;goto out;}owner=n;}
  }
  if(!owner){ret=-EPERM;goto out;}
 }
 ret=an_msi_client_budget(m,owner,nr);if(ret)goto out;
 local = bitmap_find_free_region(m->used, 32, order_base_2(nr));
 if (local < 0) { ret = -ENOSPC; goto out; }
 if (apciec_aic_vector(m->aic_kind, m->aic_die, m->aic_base, 65536,
                       local, nr, spec.param, spec.param_count)) {
  bitmap_release_region(m->used, local, order_base_2(nr));
  ret = -EINVAL; goto out;
 }
 ret = irq_domain_alloc_irqs_parent(domain, virq, nr, &spec);
 if (ret) {
  irq_domain_free_irqs_parent(domain, virq, nr);
  bitmap_release_region(m->used, local, order_base_2(nr));
  goto out;
 }
 for (i = 0; i < nr; i++) {
  if(m->pair||m->exact_single||m->exact_multi) {WRITE_ONCE(m->owners[local+i],owner);WRITE_ONCE(m->virqs[local+i],virq+i);}
  irq_domain_set_hwirq_and_chip(domain, virq + i, local + i, &an_msi_chip, m);
  irq_chip_mask_parent(irq_domain_get_irq_data(domain, virq + i));
 }
out:
 mutex_unlock(&m->lock);
 return ret;
}

static void an_msi_free(struct irq_domain *domain, unsigned virq, unsigned nr)
{
 struct apciec_native_msi *m = domain->host_data;
 struct irq_data *d;
 unsigned i;
 mutex_lock(&m->lock);
 for (i = 0; i < nr; i++) {
  d = irq_domain_get_irq_data(domain, virq + i);
  if (WARN_ON(!d || d->hwirq >= 32 || !test_bit(d->hwirq, m->used))) continue;
  if(m->pair||m->exact_single||m->exact_multi) {
   if(WARN_ON(READ_ONCE(m->virqs[d->hwirq])!=virq+i||!READ_ONCE(m->owners[d->hwirq])))continue;
   WRITE_ONCE(m->owners[d->hwirq],NULL);WRITE_ONCE(m->virqs[d->hwirq],0);
  }
  irq_chip_mask_parent(d);
  clear_bit(d->hwirq, m->used);
 }
 irq_domain_free_irqs_common(domain, virq, nr);
 mutex_unlock(&m->lock);
}

static const struct irq_domain_ops an_msi_ops = {
 .alloc = an_msi_alloc, .free = an_msi_free,
};
static const struct msi_parent_ops an_msi_parent_ops = {
 .supported_flags = MSI_GENERIC_FLAGS_MASK | MSI_FLAG_PCI_MSIX | MSI_FLAG_MULTI_PCI_MSI,
 .required_flags = MSI_FLAG_USE_DEF_DOM_OPS | MSI_FLAG_USE_DEF_CHIP_OPS |
                   MSI_FLAG_PCI_MSI_MASK_PARENT,
 .chip_flags = MSI_CHIP_FLAG_SET_EOI,
 .bus_select_token = DOMAIN_BUS_PCI_MSI,
 .init_dev_msi_info = msi_lib_init_dev_msi_info,
};

static int an_msi_profile_base(struct apple_apciec *p)
{
 const struct apciec_aic_platform *plat = an_aic_platform();
 if (!p || !p->dev || !p->profile ||
     !apciec_profile_valid(p->profile) ||
     !p->dev->of_node ||
     apciec_profile_node(p->dev->of_node) != p->profile) return -EPERM;
 if (!plat || p->profile->index >= plat->nr_ports) return -EPERM;
 return plat->base[p->profile->index];
}

static int an_msi_prepare_mode(struct apple_apciec *p,
 struct apciec_native*const*clients,unsigned count,bool(*validate)(void*),void*owner)
{
 struct apciec_native_msi *m;
 struct irq_domain_info info = {};
 struct of_phandle_args args = {};
 const struct apciec_aic_platform *plat = an_aic_platform();
 struct device_node *expected;
 u32 vector_count;
 unsigned aic_base;
 int ret;
 if(count){
  if(!jmx_native_scope(p,count,true)||!clients||!validate||!owner||
     p->native!=clients[0])return -EPERM;
  for(unsigned j=0;j<count;j++){
   struct apciec_native*n=clients[j];
   if(!n||n->host!=p||!n->target||!n->active||n->failed||!n->dma_ready||!n->rid_ready||
      n->irq_ready||n->msi||n->target->driver||n->target->dev.driver||pci_dev_is_added(n->target))return -EPERM;
   for(unsigned k=0;k<j;k++)if(n==clients[k]||n->target==clients[k]->target)return -EPERM;
  }
 }
 ret = an_msi_profile_base(p);
 if (ret < 0) return ret;
 aic_base = ret;
 if (p->native->msi || p->msi_domain_ready || readl(p->port + APCIEC_MSICFG))
  return -EPERM;
 m = kzalloc(sizeof(*m), GFP_KERNEL);
 if (!m) return -ENOMEM;
 p->native->msi = m; /* All context is retained until normal reboot. */
 m->p = p;
 if(apciec_profile_j314s(p->profile)){
  if((!count&&p->profile->index)||!p->native->host||p->native->host!=p)return -EPERM;
  if(count){m->exact_multi=true;m->multi_count=count;m->multi_validate=validate;m->multi_owner=owner;
   for(unsigned j=0;j<count;j++)m->multi_clients[j]=clients[j];
  }else{m->exact_single=true;m->pair_clients[0]=p->native;}
 }
 m->aic_base = aic_base;
 m->aic_kind = plat->kind; m->aic_die = plat->die;
 mutex_init(&m->lock);
 ret = of_parse_phandle_with_args(p->dev->of_node, "msi-ranges", "#interrupt-cells", 0, &args);
 if (ret) return ret;
 m->aic = args.np;
 expected = an_aic_node(plat);
 if (!expected || expected != args.np ||
     apciec_aic_validate(plat->kind, plat->die, aic_base, 32, 65536,
                        args.args, args.args_count) ||
     of_property_count_u32_elems(p->dev->of_node, "msi-ranges") != args.args_count + 2 ||
     of_property_read_u32_index(p->dev->of_node, "msi-ranges", args.args_count + 1, &vector_count) || vector_count != 32) {
  of_node_put(expected); return -EINVAL;
 }
 of_node_put(expected);
 of_phandle_args_to_fwspec(args.np, args.args, args.args_count, &m->spec);
 info.parent = irq_find_matching_fwspec(&m->spec, DOMAIN_BUS_WIRED);
 if (!info.parent || irq_find_matching_fwnode(dev_fwnode(p->dev), DOMAIN_BUS_PCI_MSI))
  return -EBUSY;
 info.fwnode = dev_fwnode(p->dev);
 info.ops = &an_msi_ops;
 info.size = 32;
 info.host_data = m;
 m->domain = msi_create_parent_irq_domain(&info, &an_msi_parent_ops);
 if (!m->domain) return -ENOMEM;
 /* Local index base is0; parent AIC base is never written to MSIBASE. */
 if(apciec_profile_j314s(p->profile)&&ktime_get_boottime_ns()>=p->retained_identity_deadline)return -ETIMEDOUT;
 writel(0, p->port + APCIEC_MSIBASE);
 if(apciec_profile_j314s(p->profile)&&ktime_get_boottime_ns()>=p->retained_identity_deadline)return -ETIMEDOUT;
 writel(0xfffff000, p->port + APCIEC_MSIADDR);
 if (readl(p->port + APCIEC_MSIBASE) ||
     readl(p->port + APCIEC_MSIADDR) != 0xfffff000 ||
     readl(p->port + APCIEC_MSICFG)) return -EIO;
 dev_set_msi_domain(&p->native->target->dev, m->domain);
 p->msi_domain_ready = true;
 p->native->irq_ready = true;
 if(count)for(unsigned j=0;j<count;j++){
  clients[j]->msi=m;clients[j]->irq_ready=true;dev_set_msi_domain(&clients[j]->target->dev,m->domain);
 }
 return 0;
}

static int an_msi_prepare(struct apple_apciec*p)
{return an_msi_prepare_mode(p,NULL,0,NULL,NULL);}

/* Call before publishing either GPU; one shared parent domain and bitmap. */
static int an_msi_prepare_pair(struct apple_apciec *p,struct apciec_native *primary,
                               struct apciec_native *secondary)
{
 struct apciec_native_msi *m;int ret;
 if(!pn_mode(p)||p->native!=primary||
    !primary||!secondary||primary==secondary||primary->host!=p||secondary->host!=p||
    !primary->target||!secondary->target||primary->target==secondary->target||
    pci_dev_id(primary->target)!=0x600||pci_dev_id(secondary->target)!=0x300||
    primary->target->dev.driver||secondary->target->dev.driver||
    pci_dev_is_added(primary->target)||pci_dev_is_added(secondary->target)||
    !primary->active||!secondary->active||primary->failed||secondary->failed||
    !primary->dma_ready||!secondary->dma_ready||!primary->rid_ready||!secondary->rid_ready||
    primary->irq_ready||secondary->irq_ready||secondary->msi)return -EPERM;
 ret=an_msi_prepare(p);if(ret)return ret;
 m=primary->msi;m->pair_clients[0]=primary;m->pair_clients[1]=secondary;
 secondary->msi=m;secondary->irq_ready=true;m->pair=true;
 dev_set_msi_domain(&secondary->target->dev,m->domain);
 return an_msi_pair_ready(m)?0:-EPERM;
}
