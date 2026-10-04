/* SPDX-License-Identifier: GPL-2.0 */
/* Standard PCI objects over the exact already-discovered topology.  This is
 * a new consumed transaction; the raw-discovery budget is never reopened.
 * All objects and partial claims remain alive until the normal stock reboot. */
static const unsigned pd_rids[8] = {0, 0x100, 0x200, 0x300, 0x301, 0x208, 0x210, 0x218};

static const struct ep_function *pd_function(struct apple_apciec *p, unsigned rid)
{
 unsigned j;
 for (j = 0; j < p->endpoint_snapshot->count; j++)
  if (p->endpoint_snapshot->functions[j].identity.rid == rid)
   return &p->endpoint_snapshot->functions[j];
 return NULL;
}

static int pd_read(struct apple_apciec *p, unsigned rid, unsigned off, unsigned width, u32 *v)
{
 struct pci_bus bus = {.number = rid >> 8, .sysdata = p, .ops = &apple_apciec_ops};
 return apple_apciec_config_read(&bus, rid & 255, off, width, v) ? -EIO : 0;
}

static int pd_hardware_audit(struct apple_apciec *p)
{
 unsigned j; u32 v; int ret;
 bool mmio = endpoint_mmio_probe && p->mmio_task == current && p->retained_phase == 17;
 if (p->discovery_failed || p->discovery_probe.pending ||
     (mmio ? !mp_active(&p->mmio, ktime_get_boottime_ns()) :
      (p->discovery_task != current || p->retained_phase != 15 ||
       ktime_get_boottime_ns() >= p->discovery_deadline))) return -EPERM;
 ret = retained_dma_blocked(p);
 if (!ret) ret = retained_identity_port_audit(p, true);
 if (!ret) ret = retained_root_rc_audit(p);
 if (ret) return ret;
 for (j = 0; j < 8; j++) {
  const struct ep_function *f = pd_function(p, pd_rids[j]);
  if (!f || (f->devctl2 & PCI_EXP_DEVCTL2_ARI)) return -EPERM;
  ret = pd_read(p, pd_rids[j], 0, 4, &v);
  if (ret || v != f->identity.id) return ret ? ret : -ESTALE;
  ret = pd_read(p, pd_rids[j], 4, 2, &v);
  if (ret || v != (mmio ? mp_expected_command(&p->mmio, pd_rids[j]) : 0))
   return ret ? ret : -EPERM;
  if (j >= 5) {
   ret = pd_read(p, pd_rids[j], 0x18, 4, &v);
   if (ret || v) return ret ? ret : -EPERM;
   ret = pd_read(p, pd_rids[j], f->pcie + PCI_EXP_LNKSTA, 2, &v);
   if (ret || (v & (PCI_EXP_LNKSTA_DLLLA | PCI_EXP_LNKSTA_LT)))
    return ret ? ret : -EPERM;
  }
 }
 for (j = 0; j < p->endpoint_owner->plan.count; j++) {
  const struct as_register *r = &p->endpoint_owner->plan.regs[j];
  ret = pd_read(p, r->rid, r->offset, 4, &v);
  if (ret || v != r->after) return ret ? ret : -ESTALE;
 }
 return 0;
}

static int pd_device_audit(struct apple_apciec *p, struct pci_dev *dev, unsigned index)
{
 const struct ep_function *f = pd_function(p, pd_rids[index]);
 const struct ep_identity *id;
 if (!f || !dev) return -ENODEV;
 id = &f->identity;
 if (dev->vendor != (id->id & 0xffff) || dev->device != (id->id >> 16) ||
     dev->class != (id->class_rev >> 8) || dev->revision != (id->class_rev & 255) ||
     dev->hdr_type != (id->header & 0x7f) ||
     dev->multifunction != !!(id->header & 0x80) ||
     dev->driver || dev->dev.driver || !dev->non_mappable_bars ||
     dev->is_busmaster || dev->is_physfn || dev->is_virtfn || dev->ari_enabled ||
     dev_iommu_fwspec_get(&dev->dev) || dev->dev.iommu_group ||
     !device_is_registered(&dev->dev) ||
     pci_find_host_bridge(dev->bus) != p->discovery_bridge ||
     !p->discovery_bridge->discovery_only) return -EPERM;
 if (!dev->hdr_type &&
     ((dev->subsystem_device << 16) | dev->subsystem_vendor) != id->subsystem)
  return -ESTALE;
 if (pci_get_dsn(dev) != id->serial) return -ESTALE;
 return 0;
}

static int pd_tree_audit(struct apple_apciec *p)
{
 struct as_owner *owner = p->endpoint_owner;
 unsigned kind, depth;
 if (!owner || !owner->ready || owner->failed || owner->resources[2].child)
  return -EPERM;
 for (kind = 0; kind < 3; kind++) {
  const struct as_aperture *a = &owner->plan.apertures[kind];
  struct resource *r = &owner->resources[kind];
  if (!owner->reserved[kind] || r->parent != &iomem_resource ||
      r->start != a->cpu || r->end != a->cpu + a->size - 1 ||
      owner->entries[kind]->res != r ||
      owner->entries[kind]->offset != a->cpu - a->pci) return -EPERM;
 }
 for (kind = 0; kind < 2; kind++) {
  struct resource *parent = &owner->resources[kind ? 0 : 1];
  unsigned idx = kind ? PCI_BRIDGE_PREF_MEM_WINDOW : PCI_BRIDGE_MEM_WINDOW;
  for (depth = 0; depth < 3; depth++) {
   struct resource *r = &p->discovery_devices[depth]->resource[idx];
   if (parent->child != r || r->parent != parent || r->sibling) return -EPERM;
   parent = r;
  }
  if (kind) {
   struct resource *b1 = &p->discovery_devices[3]->resource[1];
   struct resource *b3 = &p->discovery_devices[3]->resource[3];
   if (parent->child != b1 || b1->parent != parent || b1->sibling != b3 ||
       b3->parent != parent || b3->sibling || b1->child || b3->child) return -EPERM;
  } else {
   struct resource *b0 = &p->discovery_devices[3]->resource[0];
   if (parent->child != b0 || b0->parent != parent || b0->sibling || b0->child) return -EPERM;
  }
 }
 return 0;
}

/* R40: validate the same retained owner after exact PCI claims were installed.
 * as_owner_validate remains the strict pre-publication/no-children gate.
 * This is a pre-binding audit: only the exact bridge/BAR claim tree is allowed;
 * driver-owned BAR subregions are not admitted by this helper. */
static int pd_published_owner_audit(struct apple_apciec *p)
{
 const unsigned long flags[3] = {
  IORESOURCE_MEM | IORESOURCE_PREFETCH | IORESOURCE_MEM_64,
  IORESOURCE_MEM, IORESOURCE_MEM | IORESOURCE_PREFETCH};
 const struct as_owner *owner;
 unsigned j;
 if (!p || p->discovery_count != 8 || p->discovery_failed ||
     !p->discovery_bridge || !p->discovery_bridge->discovery_only)
  return -EPERM;
 owner = p->endpoint_owner;
 if (!owner || !owner->attempted || !owner->ready || owner->failed ||
     !owner->plan.built || as_apertures_gate(owner->plan.apertures))
  return -EPERM;
 for (j = 0; j < 4; j++)
  if (!p->discovery_devices[j]) return -EPERM;
 for (j = 0; j < 3; j++) {
  const struct as_aperture *a = &owner->plan.apertures[j];
  const struct resource *r = &owner->resources[j];
  const struct resource_entry *e = owner->entries[j];
  if (!owner->reserved[j] || !e || r->parent != &iomem_resource ||
      r->start != a->cpu || r->end != a->cpu + a->size - 1 ||
      r->flags != flags[j] || e->res != r || e->offset != a->cpu - a->pci)
   return -EPERM;
 }
 if (owner->private_windows.next != &owner->entries[0]->node ||
     owner->private_windows.prev != &owner->entries[2]->node)
  return -EPERM;
 for (j = 0; j < 3; j++) {
  const struct list_head *prev = j ? &owner->entries[j-1]->node : &owner->private_windows;
  const struct list_head *next = j == 2 ? &owner->private_windows : &owner->entries[j+1]->node;
  if (owner->entries[j]->node.prev != prev || owner->entries[j]->node.next != next)
   return -EPERM;
 }
 /* Legitimate children are required, not ignored: check the complete exact
  * root/upstream/downstream/BAR0,BAR1,BAR3 tree and empty unused aperture. */
 return pd_tree_audit(p);
}

static int pd_claim_resources(struct apple_apciec *p)
{
 const struct ep_snapshot *s = p->endpoint_snapshot;
 unsigned depth, kind, bar; int ret;
 struct resource *parent[2] = {&p->endpoint_owner->resources[1],
                               &p->endpoint_owner->resources[0]};
 /* Claim exact ancestor windows top-down, never the clipping/reprogramming helper. */
 for (depth = 0; depth < 3; depth++) {
  struct pci_dev *dev = p->discovery_devices[depth];
  const struct ep_bridge_plan *bp = &s->bridges[2 - depth];
  if (bp->rid != pd_rids[depth]) return -EPERM;
  for (kind = 0; kind < 2; kind++) {
   unsigned plan_window = kind ? 0 : 1;
   unsigned idx = (kind ? PCI_BRIDGE_PREF_MEM_WINDOW : PCI_BRIDGE_MEM_WINDOW);
   struct resource *r = &dev->resource[idx];
   u64 offset = kind ? 0 : 0x400000000ULL;
   if (!bp->active[plan_window] || r->parent ||
       r->start != bp->start[plan_window] + offset ||
       r->end != bp->end[plan_window] + offset ||
       !(r->flags & IORESOURCE_MEM) ||
       !!(r->flags & IORESOURCE_PREFETCH) != !!kind) return -EPERM;
   ret = pci_claim_resource(dev, idx);
   if (ret) return ret;
   if (r->parent != parent[kind]) return -EPERM;
   parent[kind] = r;
  }
 }
 for (bar = 0; bar < 5; bar++) {
  const struct ep_bar *b = &s->bars[bar];
  struct resource *r = &p->discovery_devices[3]->resource[bar];
  if (b->upper) {
   if (r->flags) return -EPERM;
   continue;
  }
  kind = !!(b->flags & EP_BAR_PREF);
  if (!b->size || r->parent || r->start != b->cpu || resource_size(r) != b->size ||
      !(r->flags & IORESOURCE_MEM) ||
      !!(r->flags & IORESOURCE_MEM_64) != !!(b->flags & EP_BAR_64) ||
      !!(r->flags & IORESOURCE_PREFETCH) != !!kind ||
      (r->flags & (IORESOURCE_UNSET | IORESOURCE_DISABLED))) return -EPERM;
  ret = pci_claim_resource(p->discovery_devices[3], bar);
  if (ret) return ret;
  if (r->parent != parent[kind]) return -EPERM;
 }
 /* Standard probing may measure I/O/ROM/audio; these remain unassigned. */
 if (p->discovery_devices[3]->resource[5].parent ||
     p->discovery_devices[3]->resource[PCI_ROM_RESOURCE].parent) return -EPERM;
 for (bar = 0; bar < PCI_STD_NUM_BARS; bar++)
  if (p->discovery_devices[4]->resource[bar].parent) return -EPERM;
 return 0;
}

int apple_apciec_retained_register_pci(struct device *dev, unsigned port,
                                      const void *ticket, unsigned *phase)
{
 struct apple_apciec *p = dev_get_drvdata(dev);
 struct resource_entry *e;
 struct pci_bus *bus;
 unsigned j; unsigned long flags; u64 now; int ret;
 if (!p || !phase || !endpoint_pci_register || !endpoint_memory_assign) return -EINVAL;
 mutex_lock(&p->lifecycle);
 ret = retained_commit_owner(p, port, ticket, 14);
 if (ret) goto out;
 if (p->discovery_attempted || p->discovery_bridge || p->retained_scan_task ||
     !p->endpoint_snapshot || !p->endpoint_snapshot->memory_assigned ||
     p->endpoint_snapshot->count != 8 || p->endpoint_snapshot->ancestor_count != 3 ||
     !p->endpoint_execution.complete || as_owner_validate(p->endpoint_owner) ||
     of_find_property(p->dev->of_node, "iommu-map", NULL)) {
  ret = -EPERM; goto out;
 }
 now = ktime_get_boottime_ns();
 if (now >= p->retained_identity_deadline ||
     p->retained_identity_deadline - now < 2ULL * NSEC_PER_SEC) {
  ret = -ETIMEDOUT; goto out;
 }
 p->discovery_attempted = true;
 p->retained_phase = 15;
 p->discovery_deadline = min(now + 10ULL * NSEC_PER_SEC, p->retained_identity_deadline);
 raw_spin_lock_irqsave(&p->lock, flags);
 p->discovery_task = current;
 raw_spin_unlock_irqrestore(&p->lock, flags);
 ret = pd_hardware_audit(p);
 if (ret) goto close;
 INIT_LIST_HEAD(&p->discovery_windows);
 for (j = 0; j < 4; j++) {
  if (j == 3) p->discovery_bus_resource = (struct resource){
   .name = "J293 discovered buses", .start = 0, .end = 3, .flags = IORESOURCE_BUS};
  e = resource_list_create_entry(j < 3 ? &p->endpoint_owner->resources[j] : &p->discovery_bus_resource, 0);
  if (!e) {ret = -ENOMEM; goto close;}
  if (j < 3) e->offset = p->endpoint_owner->entries[j]->offset;
  resource_list_add_tail(e, &p->discovery_windows);
 }
 pci_lock_rescan_remove();
 bus = pci_create_root_bus(p->dev, 0, &apple_apciec_ops, p, &p->discovery_windows);
 if (!bus) {ret = -ENODEV; goto unlock;}
 p->discovery_buses[0] = bus;
 p->discovery_bridge = pci_find_host_bridge(bus);
 p->discovery_bridge->discovery_only = true;
 ret = as_owner_validate(p->endpoint_owner);
 if (ret || bus->busn_res.start != 0 || bus->busn_res.end != 3 || !bus->busn_res.parent) {
  ret = ret ? ret : -EPERM; goto unlock;
 }
 p->discovery_bridge->native_aer = false;
 p->discovery_bridge->native_pcie_hotplug = false;
 p->discovery_bridge->native_pme = false;
 p->discovery_bridge->native_dpc = false;
 for (j = 0; j < 8; j++) {
  struct pci_dev *pd;
  ret = pd_hardware_audit(p);
  if (ret) goto unlock;
  bus = p->discovery_buses[pd_rids[j] >> 8];
  if (!bus) {ret = -EPERM; goto unlock;}
  pd = pci_scan_single_device(bus, pd_rids[j] & 255);
  p->discovery_devices[j] = pd;
  if (pd) p->discovery_count++;
  ret = pd_device_audit(p, pd, j);
  if (!ret) ret = pd_hardware_audit(p);
  if (ret) goto unlock;
  if (j < 3) {
   const struct ep_function *f = pd_function(p, pd_rids[j]);
   unsigned secondary = (f->buses >> 8) & 255, subordinate = (f->buses >> 16) & 255;
   if ((f->buses & 255) != j || secondary != j + 1 || subordinate != 3) {
    ret = -EPERM; goto unlock;
   }
   bus = pci_add_new_bus(bus, pd, secondary);
   if (!bus) {ret = -ENOMEM; goto unlock;}
   p->discovery_buses[secondary] = bus;
   if (!pci_bus_insert_busn_res(bus, secondary, subordinate)) {
    ret = -EBUSY; goto unlock;
   }
   pci_read_bridge_bases(bus);
  }
 }
 ret = pd_claim_resources(p);
 if (!ret) ret = pd_tree_audit(p);
 if (!ret) ret = pd_hardware_audit(p);
 for (j = 0; !ret && j < 8; j++) ret = pd_device_audit(p, p->discovery_devices[j], j);
 unlock:
 pci_unlock_rescan_remove();
 close:
 raw_spin_lock_irqsave(&p->lock, flags);
 p->discovery_task = NULL;
 raw_spin_unlock_irqrestore(&p->lock, flags);
 if (!ret && (p->discovery_failed || p->discovery_probe.pending ||
              ktime_get_boottime_ns() >= p->discovery_deadline)) ret = -EIO;
 if (ret) p->discovery_failed = true;
 else p->retained_phase = 16;
 dev_info(p->dev, "retained-pci-register: status %d phase %u devices %u config-ops %u deadline %llu; no binding/decode/DMA\n",
  ret, p->retained_phase, p->discovery_count, p->discovery_ops,
  (unsigned long long)p->discovery_deadline);
 out:
 *phase = p->retained_phase;
 mutex_unlock(&p->lifecycle);
 return ret;
}
EXPORT_SYMBOL_GPL(apple_apciec_retained_register_pci);
