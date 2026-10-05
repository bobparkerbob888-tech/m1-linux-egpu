/* SPDX-License-Identifier: GPL-2.0 */
/* Selected native endpoint promotion. Standard IOMMU/PCI/IRQ APIs own their
 * mappings and device objects. The diagnostic owner persists until reboot. */
extern int apple_dart_native_selected_audit(struct device *, struct device *, unsigned);

static int am_dma_audit(struct apple_apciec *);
static int am_state_audit(struct apple_apciec *,bool);
static int am_enable_device(struct apple_apciec *,struct pci_dev *);
static bool an_target_identity(struct apple_apciec *p)
{
 struct pci_dev *d = p->native->target;
 return d && d == p->discovery_devices[3] && pci_dev_id(d) == 0x300 &&
        d->vendor == 0x10de && d->device == 0x2d04 &&
        d->subsystem_vendor == 0x1458 && d->subsystem_device == 0x41cd &&
        d->class == 0x030000 && d->revision == 0xa1 &&
        pci_find_host_bridge(d->bus) == p->discovery_bridge &&
        p->discovery_bridge->discovery_only;
}

static int an_alias(struct pci_dev *d, u16 alias, void *arg)
{
 struct apple_apciec *p = arg;
 if (d != p->native->target || alias != 0x300 || p->native->aliases)
  return -EPERM;
 p->native->aliases++;
 return 0;
}

static int an_add_property(struct apple_apciec *p, const char *name,
                           const void *value, unsigned size)
{
 struct property *prop;
 if (of_find_property(p->dev->of_node, name, NULL)) return -EEXIST;
 prop = kzalloc(sizeof(*prop), GFP_KERNEL);
 if (!prop) return -ENOMEM;
 prop->name = kstrdup(name, GFP_KERNEL);
 prop->value = size ? kmemdup(value, size, GFP_KERNEL) : NULL;
 prop->length = size;
 if (!prop->name || (size && !prop->value)) return -ENOMEM;
 return of_changeset_add_property(&p->native->firmware, p->dev->of_node, prop);
}

static int an_firmware_prepare(struct apple_apciec *p)
{
 unsigned range_cells;
 __be32 map[4], mask = cpu_to_be32(0xffff), ranges[6];
 int ret;
 if (!p->retained_dart_node || !p->retained_dart_node->phandle) return -EINVAL;
 ret = an_aic_ranges(p, ranges, &range_cells);
 if (ret) return ret;
 map[0] = cpu_to_be32(0x300); map[1] = cpu_to_be32(p->retained_dart_node->phandle);
 map[2] = cpu_to_be32(1); map[3] = cpu_to_be32(1);
 of_changeset_init(&p->native->firmware);
 ret = an_add_property(p, "iommu-map", map, sizeof(map));
 if (!ret) ret = an_add_property(p, "iommu-map-mask", &mask, sizeof(mask));
 if (!ret) ret = an_add_property(p, "msi-ranges", ranges, range_cells * sizeof(*ranges));
 if (!ret) ret = an_add_property(p, "msi-controller", NULL, 0);
 if (!ret) ret = an_add_property(p, "dma-noncoherent", NULL, 0);
 if (!ret) ret = an_add_property(p, "research,native-endpoint-memory-only", NULL, 0);
 if (!ret) ret = of_changeset_apply(&p->native->firmware);
 return ret;
}

static int an_dma_audit(struct apple_apciec *p)
{
 struct device *dev = &p->native->target->dev;
 struct iommu_fwspec *fw = dev_iommu_fwspec_get(dev);
 struct iommu_domain *domain = iommu_get_domain_for_dev(dev);
 if (!an_target_identity(p) || !dev->iommu_group || !domain ||
     domain->type != IOMMU_DOMAIN_DMA ||
     !fw || fw->iommu_fwnode != of_fwnode_handle(p->retained_dart_node) ||
     fw->num_ids != 0 || /* apple_dart_of_xlate keeps SID in private stream_maps. */
     dev_is_dma_coherent(dev) || domain->pgsize_bitmap != 0x4000 ||
     !domain->geometry.force_aperture || domain->geometry.aperture_start ||
     domain->geometry.aperture_end != 0xffffffffULL) {
  dev_err(p->dev, "native-dma-metadata: target%u group%u domain%u type%x fw%u provider-match%u ids%u sid%x coherent%u pages%lx force%u aperture%llx-%llx\n",
   an_target_identity(p), !!dev->iommu_group, !!domain, domain ? domain->type : 0,
   !!fw, fw && fw->iommu_fwnode == of_fwnode_handle(p->retained_dart_node),
   fw ? fw->num_ids : 0, fw && fw->num_ids ? fw->ids[0] : ~0U,
   dev_is_dma_coherent(dev), domain ? domain->pgsize_bitmap : 0,
   domain ? domain->geometry.force_aperture : 0,
   domain ? (unsigned long long)domain->geometry.aperture_start : 0,
   domain ? (unsigned long long)domain->geometry.aperture_end : 0);
  return -EPERM;
 }
 return p->multi ? am_dma_audit(p) : apple_dart_native_selected_audit(&p->dart->dev, dev, 1);
}

static int an_state_audit(struct apple_apciec *p, bool before_driver)
{
 unsigned j;
 u16 cmd;
 u32 v;
 int ret;
 if(p->multi)return am_state_audit(p,before_driver);
 if (!p->native || !p->native->active || p->native->failed ||
     !an_target_identity(p) || !p->native->dma_ready || !p->native->rid_ready ||
     !p->native->irq_ready || !p->power_ready || !p->tunnel_ready ||
     p->discovery_count != 8 || p->native->aliases != 1 ||
     p->discovery_bridge->discovery_dma_device != p->native->target ||
     dev_get_msi_domain(&p->native->target->dev) != p->native->msi->domain)
  return -EPERM;
 ret = an_dma_audit(p);
 if (ret) return ret;
 for (j = 0; j < 64; j++) {
  v = readl(p->port + APCIEC_RID2SID + 4*j);
  if (v != (j == 1 ? (BIT(31) | BIT(16) | 0x300) : 0)) return -ESTALE;
 }
 v = readl(p->port + APCIEC_MSICFG);
 if ((v && v != 0x51) || readl(p->port + APCIEC_MSIBASE) ||
     readl(p->port + APCIEC_MSIADDR) != 0xfffff000) return -ESTALE;
 for (j = 0; j < 8; j++) {
  struct pci_dev *d = p->discovery_devices[j];
  const struct ep_function *f = pd_function(p, pd_rids[j]);
  if (!d || !f || pci_read_config_dword(d, 0, &v) || v != f->identity.id ||
      pci_read_config_word(d, PCI_COMMAND, &cmd)) return -ESTALE;
  if (j < 4) {
   if ((cmd & ~(PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER | PCI_COMMAND_INTX_DISABLE)) ||
       !(cmd & PCI_COMMAND_MEMORY) || (before_driver && cmd != mp_target_command(j << 8)))
    return -EPERM;
  } else if (cmd) return -EPERM;
  if (j != 3 && (d->driver || d->dev.driver || d->dev.iommu_group ||
                 dev_iommu_fwspec_get(&d->dev))) return -EPERM;
 }
 /* The controller cannot deliver before an installed native IRQ owner. */
 if (before_driver && (p->native->target->driver || p->native->target->dev.driver ||
                       p->native->enable_attempted || readl(p->port + APCIEC_MSICFG)))
  return -EPERM;
 if (pci_get_dsn(p->native->target) != PROVISION_PRIVATE_ID_5) return -ESTALE;
 /* Resource ownership remains exact; driver BAR0 reservation can add a BUSY
  * child only after readiness, so the initial full tree proof runs here. */
 return before_driver ? pd_tree_audit(p) : 0;
}

static int an_enable_device(struct pci_host_bridge *bridge, struct pci_dev *dev)
{
 struct apple_apciec *p = bridge->sysdata;
 unsigned j;
 int ret;
 if(p&&p->multi)return am_enable_device(p,dev);
 if (!p || !p->native || p->retained_phase != 20 || p->native->failed ||
     !p->native->dma_ready || !p->native->rid_ready || !p->native->irq_ready)
  return -EPERM;
 for (j = 0; j < 4; j++) if (p->discovery_devices[j] == dev) break;
 if (j == 4) return -EPERM;
 ret = an_dma_audit(p);
 if (ret) return ret;
 if (j == 3) {
  if (p->native->enable_attempted) return -EPERM;
  p->native->enable_attempted = true;
 }
 return 0;
}

/* Read-only standard PCI/AER status after the selected driver's teardown.
 * No BAR reads, W1C writes, retry, reset, or release of the retained owners. */
static void an_driver_status(struct apple_apciec *p)
{
 struct md_snapshot s;
 unsigned j, k;
 int ret;
 if (p->native->status_logged) return;
 p->native->status_logged = true;
 ret = md_plan(p, &s);
 if (!ret) {
  for (j = 0; j < MD_PATHS; j++) {
   struct md_function *d = &s.function[j];
   for (k = 0; k < d->count; k++) {
    ret = pci_read_config_dword(p->discovery_devices[j], d->offset[k], &d->value[k]);
    if (ret) goto done;
    d->valid |= BIT(k);
   }
  }
 }
done:
 s.status = ret;
 md_log(p, &s, "native-driver-teardown");
 dev_info(p->dev, "native-driver-port: INTSTAT%08x LTSSM%08x; read-only\n",
          readl(p->port + 0x100), readl(p->port + 0x080));
}

/* The native NVIDIA failure path does not call the host disable callback.
 * Observe the standard driver-core result instead. All owners and this built-in
 * host remain retained until normal reboot; this notifier never alters probe
 * results or hardware state and never initiates another probe. */
static int an_probe_event(struct notifier_block *block, unsigned long action,
                           void *data)
{
 struct apciec_native *n = container_of(block, struct apciec_native, probe_notifier);
 struct apple_apciec *p = n->host;
 if (!p || !n->target || data != &n->target->dev || p->native != n ||
     !endpoint_native_driver || !n->active || n->failed ||
     p->retained_phase != 20 || !p->power_ready || !p->port)
  return NOTIFY_DONE;
 if (action == BUS_NOTIFY_BIND_DRIVER && !n->probe_begin_logged) {
  n->probe_begin_logged = true;
  dev_info(p->dev, "native-probe-port: before INTSTAT%08x LTSSM%08x; read-only\n",
           readl(p->port + 0x100), readl(p->port + 0x080));
 } else if (n->probe_begin_logged && !n->status_logged &&
            (action == BUS_NOTIFY_DRIVER_NOT_BOUND || action == BUS_NOTIFY_BOUND_DRIVER)) {
  dev_info(p->dev, "native-probe-event: action%lu; read-only result snapshot\n", action);
  an_driver_status(p);
 }
 return NOTIFY_DONE;
}

static void an_disable_device(struct pci_host_bridge *bridge, struct pci_dev *dev)
{
 struct apple_apciec *p = bridge->sysdata;
 if (!p || !p->native || dev != p->native->target) return;
 /* Ordinary PCI teardown clears BME first. Keep domain, RID, resources and
  * parent references until reboot; never make this device eligible again. */
 WRITE_ONCE(p->native->enable_attempted, true);
 an_driver_status(p);
}

/* NVIDIA's PCI post-box is admitted only for its read-only capabilities,
 * UUID and feature queries. The capability was captured before admission.
 * This is not a general vendor-command or firmware-write interface. */
static unsigned an_pbi_base(const struct ep_function *f)
{
 unsigned j, base = 0;
 if (f->sample_count > EP_MAX_SAMPLES) return 0;
 for (j = 0; j < f->sample_count; j++) {
  unsigned off = f->samples[j].offset;
  if (off != 0x9c ||
      (f->samples[j].value & 0xffff00ff) != 0x01140009) continue;
  if (base) return 0;
  base = off;
 }
 return base;
}

static bool an_pbi_allowed(const struct apciec_native *n,
                           const struct ep_function *f,
                           int where, int size, u32 old, u32 val)
{
 unsigned base = an_pbi_base(f);
 if (!base || size != 4) return false;
 if (where == base + 0x10)
  return (!n->pbi_owned && old == 0 && val == 0x15) ||
         (n->pbi_owned && old == 0x15 && val == 0);
 if (!n->pbi_owned) return false;
 if (where == base + 8) return val == 0 || val == 0x80 || val == 0x81;
 if (where != base + 4) return false;
 if (val == 0x80100000) return n->pbi_input == 0;
 if ((val & ~0x00030000U) != 0x8b100000) return false;
 return n->pbi_input == 0x80 || (n->pbi_input == 0x81 && !(val & 0x00030000));
}

static void an_pbi_written(struct apciec_native *n, const struct ep_function *f,
                           int where, u32 val)
{
 unsigned base = an_pbi_base(f);
 if (!base) return;
 if (where == base + 0x10) {
  n->pbi_owned = val == 0x15;
  n->pbi_input = ~0U;
 } else if (where == base + 8) n->pbi_input = val;
}

static bool an_write_for(struct apciec_native *n, const struct ep_function *f,
                         bool path, bool selected, int where, int size, u32 old, u32 val)
{
 if (!path || !n->dma_ready || !n->rid_ready || !n->irq_ready) return false;
 if (where == PCI_COMMAND && size == 2)
  return !(val & ~(PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER | PCI_COMMAND_INTX_DISABLE));
 if (f->pm && where == f->pm + PCI_PM_CTRL && size == 2)
  return !(val & (PCI_PM_CTRL_STATE_MASK | PCI_PM_CTRL_PME_ENABLE)) &&
         !((old ^ val) & ~(PCI_PM_CTRL_STATE_MASK | PCI_PM_CTRL_PME_ENABLE | PCI_PM_CTRL_PME_STATUS));
 if (!selected) return false;
 if (where == PCI_ROM_ADDRESS && size == 4) return !old && !val;
 if (where == PCI_CACHE_LINE_SIZE && size == 4) {
  /* Header type is read-only; NVIDIA writes zero in that byte. Neither
   * the observed nor requested BIST byte may be set. Keep the exact
   * selected multifunction endpoint header and accept its RO zero write. */
  return (old & 0xffff0000U) == 0x00800000U &&
         (!(val & 0xffff0000U) || (val & 0xffff0000U) == 0x00800000U);
 }
 if (f->pcie && where == f->pcie + PCI_EXP_DEVCTL && (size == 2 || size == 4)) {
  u32 permitted = PCI_EXP_DEVCTL_READRQ | PCI_EXP_DEVCTL_PAYLOAD |
                  PCI_EXP_DEVCTL_RELAX_EN | PCI_EXP_DEVCTL_NOSNOOP_EN |
                  PCI_EXP_DEVCTL_CERE | PCI_EXP_DEVCTL_NFERE |
                  PCI_EXP_DEVCTL_FERE | PCI_EXP_DEVCTL_URRE;
  if (f->devcap & PCI_EXP_DEVCAP_EXT_TAG) permitted |= PCI_EXP_DEVCTL_EXT_TAG;
  /* NVIDIA uses DWORD access. Zero DEVSTA bits preserve sticky evidence. */
  return !(val & (0xffff0000U | PCI_EXP_DEVCTL_BCR_FLR)) &&
         !(((old & 0xffff) ^ val) & ~permitted);
 }
 if (an_pbi_allowed(n, f, where, size, old, val)) return true;
 if (f->msix && where == f->msix + PCI_MSIX_FLAGS && size == 2)
  return !((old ^ val) & ~(PCI_MSIX_FLAGS_ENABLE | PCI_MSIX_FLAGS_MASKALL));
 if (!f->msi) return false;
 if (where == f->msi + PCI_MSI_FLAGS && size == 2)
  return !((old ^ val) & ~(PCI_MSI_FLAGS_ENABLE | PCI_MSI_FLAGS_QSIZE)) &&
         FIELD_GET(PCI_MSI_FLAGS_QSIZE, val) <= 5;
 if (where == f->msi + PCI_MSI_ADDRESS_LO && size == 4) return val == 0xfffff000;
 if (f->msi_control & PCI_MSI_FLAGS_64BIT) {
  if (where == f->msi + PCI_MSI_ADDRESS_HI && size == 4) return !val;
  if (where == f->msi + PCI_MSI_DATA_64 && size == 2)
   return an_msi_vector_owned(n,val);
  if ((f->msi_control & PCI_MSI_FLAGS_MASKBIT) && where == f->msi + PCI_MSI_MASK_64 && size == 4) return true;
 } else {
  if (where == f->msi + PCI_MSI_DATA_32 && size == 2)
   return an_msi_vector_owned(n,val);
  if ((f->msi_control & PCI_MSI_FLAGS_MASKBIT) && where == f->msi + PCI_MSI_MASK_32 && size == 4) return true;
 }
 return false;
}

static bool an_write_allowed(struct apple_apciec *p,const struct ep_function *f,
 unsigned rid,int where,int size,u32 old,u32 val)
{
 return an_write_for(p->native,f,rid==0||rid==0x100||rid==0x200||rid==0x300,
  rid==0x300,where,size,old,val);
}

static int an_config_locked(struct pci_bus *bus, unsigned devfn,
                            int where, int size, u32 *value, bool write)
{
 struct apple_apciec *p = bus->sysdata;
 unsigned rid = ((unsigned)bus->number << 8) | devfn;
 const struct ep_function *f = pd_function(p, rid);
 u32 old;
 int ret;
 lockdep_assert_held(&p->lock);
 if (!p->native->active || p->native->failed || !f ||
     !apple_apciec_map_bus(bus, devfn, where)) return PCIBIOS_DEVICE_NOT_FOUND;
 if (write) {
  ret = pci_generic_config_read(bus, devfn, where, size, &old);
  if (ret) return ret;
  if (!an_write_allowed(p, f, rid, where, size, old, *value)) {
   dev_warn_ratelimited(p->dev, "native-config denied RID%04x offset%x width%d value%08x\n", rid, where, size, *value);
   return PCIBIOS_SET_FAILED;
  }
 }
 p->native->config_ops++;
 ret = write ? pci_generic_config_write(bus, devfn, where, size, *value) :
               pci_generic_config_read(bus, devfn, where, size, value);
 if (write && rid == 0x300) {
  if (!ret && size == 4) an_pbi_written(p->native, f, where, *value);
  if (p->native->write_logs++ < 128)
   dev_info(p->dev, "native-config write RID%04x offset%x width%d old%08x value%08x result%d\n",
            rid, where, size, old, *value, ret);
 }
 return ret;
}

int apple_apciec_retained_native_prepare(struct device *dev, unsigned port,
                                        const void *ticket, unsigned *phase)
{
 struct apple_apciec *p = dev_get_drvdata(dev);
 struct pci_dev *target;
 unsigned j;
 int ret;
 const char *step = "admission";
 if (!p || !phase || !endpoint_native_driver || !endpoint_mmio_probe) return -EINVAL;
 mutex_lock(&p->lifecycle);
 ret = retained_commit_owner(p, port, ticket, 18);
 if (ret) goto out;
 if (p->native || p->mmio.failed || p->mmio.next != 4 || p->mmio.enabled != 15 ||
     p->discovery_failed || p->discovery_count != 8 || p->mmio_task ||
     p->discovery_task || p->retained_scan_task ||
     !mp_boot0_valid(p->mmio_boot0[0], p->mmio_boot0[1]) ||
     driver_find("nvidia", &pci_bus_type)) { ret = -EPERM; goto out; }
 ret = retained_dma_blocked(p);
 if (!ret) ret = pd_tree_audit(p);
 if (ret) goto out;
 p->native = kzalloc(sizeof(*p->native), GFP_KERNEL);
 if (!p->native) { ret = -ENOMEM; goto out; }
 p->retained_phase = 19;
 target = p->discovery_devices[3];
 p->native->target = pci_dev_get(target);
 p->native->active = true;
 if (!an_target_identity(p) || pci_get_dsn(target) != PROVISION_PRIVATE_ID_5) {
  ret = -ESTALE; goto failed;
 }
 for (j = 0; j < 8; j++)
  if (p->discovery_devices[j]->driver || p->discovery_devices[j]->dev.driver ||
      p->discovery_devices[j]->dev.iommu_group ||
      dev_iommu_fwspec_get(&p->discovery_devices[j]->dev)) { ret = -EPERM; goto failed; }
 step = "aliases";
 ret = pci_for_each_dma_alias(target, an_alias, p);
 if (ret || p->native->aliases != 1) { ret = ret ? ret : -EPERM; goto failed; }
 step = "firmware";
 ret = an_firmware_prepare(p);
 if (ret) goto failed;
 p->discovery_bridge->discovery_dma_device = target;
 step = "iommu-probe";
 ret = iommu_probe_device(&target->dev);
 if (!ret) {
  step = "dma-audit";
  ret = an_dma_audit(p);
 }
 if (ret) goto failed;
 step = "rid-table";
 p->native->dma_ready = true;
 /* Native slot0/SID0 remains reserved. No broad RID aliases are created. */
 for (j = 0; j < 64; j++)
  if (readl(p->port + APCIEC_RID2SID + 4*j)) { ret = -ESTALE; goto failed; }
 writel(BIT(31) | BIT(16) | 0x300, p->port + APCIEC_RID2SID + 4);
 if (readl(p->port + APCIEC_RID2SID + 4) != (BIT(31) | BIT(16) | 0x300)) {
  ret = -EIO; goto failed;
 }
 p->native->rid_ready = true;
 p->iommu_ready = true;
 step = "msi-prepare";
 ret = an_msi_prepare(p);
 if (ret) goto failed;
 p->discovery_bridge->enable_device = an_enable_device;
 p->discovery_bridge->disable_device = an_disable_device;
 p->discovery_bridge->preserve_config = true;
 step = "state-audit";
 ret = an_state_audit(p, true);
 if (ret) goto failed;
 /* Root replaces this exact placeholder with nvidia only after readiness.
  * It prevents a preloaded module from binding during ordinary publication. */
 step = "driver-placeholder";
 ret = device_set_driver_override(&target->dev, "apple-apciec-native-pending");
 if (ret || driver_find("nvidia", &pci_bus_type)) { ret = ret ? ret : -EBUSY; goto failed; }
 /* Register once while publication is still blocked. The retained host and
  * native context outlive the notifier for this bounded boot. */
 step = "probe-observer";
 p->native->host = p;
 p->native->probe_notifier.notifier_call = an_probe_event;
 ret = bus_register_notifier(&pci_bus_type, &p->native->probe_notifier);
 if (ret) goto failed;
 p->discovery_bridge->discovery_driver_device = target;
 p->retained_phase = 20;
 /* This calls ordinary final fixups/save/runtime-PM setup; placeholder blocks
  * matching. No lifecycle mutex is taken by config or native enable callbacks. */
 step = "pci-publication";
 pci_bus_add_device(target);
 pm_runtime_forbid(&target->dev);
 step = "state-audit";
 ret = an_state_audit(p, true);
 if (ret) goto failed;
 dev_info(p->dev, "retained-native-driver: native-ready phase20 GPU%s DART-SID1 domainDMA 16K MSI-local0..31 AIC738..769; driver pending\n", pci_name(target));
 goto out;
failed:
 p->native->failed = true;
 p->discovery_bridge->discovery_driver_device = NULL;
 dev_err(p->dev, "retained-native-driver: preparation failed %d phase%u step%s; all owners retained until stock reboot\n", ret, p->retained_phase, step);
out:
 *phase = p->retained_phase;
 mutex_unlock(&p->lifecycle);
 return ret;
}
EXPORT_SYMBOL_GPL(apple_apciec_retained_native_prepare);

int apple_apciec_retained_native_audit(struct device *dev, unsigned port, const void *ticket)
{
 struct apple_apciec *p = dev_get_drvdata(dev);
 int ret;
 if (!p || !endpoint_native_driver) return -EINVAL;
 mutex_lock(&p->lifecycle);
 ret = port == 3 && p->retained_ticket == ticket && p->retained_phase == 20 ?
       an_state_audit(p, true) : -EPERM;
 mutex_unlock(&p->lifecycle);
 return ret;
}
EXPORT_SYMBOL_GPL(apple_apciec_retained_native_audit);
