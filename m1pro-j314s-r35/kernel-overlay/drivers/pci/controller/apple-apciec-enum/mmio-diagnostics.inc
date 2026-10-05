/* SPDX-License-Identifier: GPL-2.0 */
/* Bounded status evidence around the original two CPU BAR reads. */
#define MD_PATHS 4
#define MD_VALUES 25
struct md_function {
 unsigned rid, pm, pcie, aer, count;
 unsigned offset[MD_VALUES];
 u32 value[MD_VALUES], valid;
};
struct md_snapshot {
 struct md_function function[MD_PATHS];
 int status;
};

static int md_cached(const struct ep_function *f, unsigned offset, u32 *value)
{
 unsigned i;
 if (!f || f->sample_count > EP_MAX_SAMPLES) return -EINVAL;
 for (i = 0; i < f->sample_count; i++)
  if (f->samples[i].offset == offset) {
   *value = f->samples[i].value;
   return 0;
  }
 return -ENOENT;
}

/* Walk only the already-preserved snapshot, with no hardware accesses. */
static int md_aer(const struct ep_function *f, unsigned *aer)
{
 unsigned offset = 0x100, i, seen[64];
 u32 value;
 for (i = 0; i < ARRAY_SIZE(seen); i++) {
  unsigned j;
  if (offset < 0x100 || offset > 0xffc || (offset & 3)) return -EINVAL;
  for (j = 0; j < i; j++) if (seen[j] == offset) return -ELOOP;
  seen[i] = offset;
  if (md_cached(f, offset, &value) || !value || value == ~0U) return -ESTALE;
  if (PCI_EXT_CAP_ID(value) == PCI_EXT_CAP_ID_ERR) {
   if (!PCI_EXT_CAP_VER(value) || offset > 0xfc8) return -EINVAL;
   *aer = offset;
   return 0;
  }
  offset = PCI_EXT_CAP_NEXT(value);
  if (!offset) return -ENOENT;
 }
 return -ELOOP;
}

static int md_add(struct md_function *d, unsigned offset)
{
 if (d->count >= MD_VALUES || offset > 0xffc || (offset & 3)) return -EINVAL;
 d->offset[d->count++] = offset;
 return 0;
}

static int md_plan(struct apple_apciec *p, struct md_snapshot *s)
{
 unsigned j, k;
 int ret;
 memset(s, 0, sizeof(*s));
 for (j = 0; j < MD_PATHS; j++) {
  struct md_function *d = &s->function[j];
  const struct ep_function *f = pd_function(p, j << 8);
  u32 header;
  if (!f || f->identity.rid != j << 8 || !p->discovery_devices[j] ||
      p->discovery_devices[j]->pm_cap != f->pm ||
      pci_pcie_cap(p->discovery_devices[j]) != f->pcie ||
      f->pm < 0x40 || f->pm > 0xf8 || (f->pm & 3) ||
      f->pcie < 0x40 || f->pcie > 0xe4 || (f->pcie & 3)) return -ESTALE;
  d->rid = j << 8; d->pm = f->pm; d->pcie = f->pcie;
  ret = md_aer(f, &d->aer);
  if (ret) return ret;
  if (d->aer != (j == 3 ? 0x1b8 : 0x100) ||
      md_cached(f, d->aer, &header) ||
      PCI_EXT_CAP_VER(header) != ((j == 1 || j == 2) ? 1 : 2)) return -ESTALE;
  /* These values are read-only or W1C status: reading does not clear them. */
  if (md_add(d, 0) || md_add(d, PCI_COMMAND) || md_add(d, f->pm) ||
      md_add(d, f->pm + PCI_PM_CTRL) || md_add(d, f->pcie) ||
      md_add(d, f->pcie + PCI_EXP_DEVCTL) ||
      md_add(d, f->pcie + PCI_EXP_LNKCTL) || md_add(d, d->aer)) return -EINVAL;
  for (k = PCI_ERR_UNCOR_STATUS; k <= PCI_ERR_HEADER_LOG + 12; k += 4)
   if (md_add(d, d->aer + k)) return -EINVAL;
  if (j < 3 && md_add(d, PCI_IO_BASE)) return -EINVAL; /* Secondary Status */
  if (!j && (md_add(d, d->aer + PCI_ERR_ROOT_STATUS) ||
             md_add(d, d->aer + PCI_ERR_ROOT_ERR_SRC))) return -EINVAL;
  if (j == 3) {
   /* NVIDIA 615 GB206 HAL maps kbifPollBarFirewallDisengage_GB202.
    * NV_EP_PCFG_GPU_VSEC_DEBUG_SEC_2 bit24 is observational only here.
    * The normal pre-probe firewall wait is a no-op for this device ID.
    */
   if (f->identity.id != 0x2d0410de || f->identity.subsystem != 0x41cd1458 ||
       f->identity.serial != PROVISION_PRIVATE_ID_5 ||
       md_cached(f, 0x2a4, &header) || header != 0x2bc1000b ||
       md_add(d, 0x2a4) || md_add(d, 0x2b8)) return -ESTALE;
  }
 }
 return 0;
}

static void md_log(struct apple_apciec *p, const struct md_snapshot *s, const char *when)
{
 unsigned j, k;
 for (j = 0; j < MD_PATHS; j++) {
  const struct md_function *d = &s->function[j];
  for (k = 0; k < d->count; k++) {
   if (!(d->valid & (1U << k))) continue;
   dev_info(p->dev, "retained-mmio-status: %s RID %04x offset %03x value %08x; read-only\n",
            when, d->rid, d->offset[k], d->value[k]);
  }
 }
 dev_info(p->dev, "retained-mmio-status: %s status %d ops %u deadline %llu; sticky baseline retained\n",
          when, s->status, p->mmio.ops, (unsigned long long)p->mmio.deadline);
}

static int md_capture(struct apple_apciec *p, struct md_snapshot *s, const char *when)
{
 unsigned j, k, rev;
 int ret = md_plan(p, s);
 if (ret) goto out;
 for (rev = 0; rev < MD_PATHS; rev++) {
  struct md_function *d;
  const struct ep_function *f;
  j = MD_PATHS - rev - 1;
  d = &s->function[j];
  f = pd_function(p, d->rid);
  for (k = 0; k < d->count; k++) {
   unsigned off = d->offset[k];
   u32 expected;
   if (!mp_active(&p->mmio, ktime_get_boottime_ns())) { ret = -ETIMEDOUT; goto out; }
   ret = pd_read(p, d->rid, off, 4, &d->value[k]);
   if (ret) goto out;
   d->valid |= 1U << k;
   if (!mp_active(&p->mmio, ktime_get_boottime_ns())) { ret = -ETIMEDOUT; goto out; }
   if (off == 0 || off == d->pm || off == d->pcie || off == d->aer ||
       (j == 3 && off == 0x2a4)) {
    ret = md_cached(f, off, &expected);
    if (ret || d->value[k] != expected) { ret = -ESTALE; goto out; }
   }
  }
 }
 out:
 s->status = ret;
 md_log(p, s, when);
 /* Logging cannot extend the original phase17 deadline or operation limit. */
 if (!ret && !mp_active(&p->mmio, ktime_get_boottime_ns())) ret = -ETIMEDOUT;
 s->status = ret;
 return ret;
}

static int md_observed(const struct md_function *d, unsigned off, unsigned width, u32 *value)
{
 unsigned k;
 for (k = 0; k < d->count; k++)
  if (d->offset[k] == (off & ~3U) && (d->valid & (1U << k))) {
   *value = d->value[k];
   if (width == 2) *value = (*value >> ((off & 2) * 8)) & 0xffff;
   return 0;
  }
 return -ENOENT;
}

static unsigned md_status_offset(const struct md_function *d, unsigned kind, unsigned *width)
{
 *width = kind <= 2 ? 2 : 4;
 switch (kind) {
 case 0: return PCI_STATUS;
 case 1: return PCI_SEC_STATUS;
 case 2: return d->pcie + PCI_EXP_DEVSTA;
 case 3: return d->aer + PCI_ERR_UNCOR_STATUS;
 case 4: return d->aer + PCI_ERR_COR_STATUS;
 default: return d->aer + PCI_ERR_ROOT_STATUS;
 }
}

static int md_clean(const struct md_snapshot *s)
{
 unsigned j, kind;
 if (s->status) return s->status;
 for (j = 0; j < MD_PATHS; j++)
  for (kind = 0; kind < 6; kind++) {
   const struct md_function *d = &s->function[j];
   unsigned width, slot, off = md_status_offset(d, kind, &width);
   u32 value, mask = mp_w1c_mask(d->rid, off, width, &slot);
   if (!mask) continue;
   if (md_observed(d, off, width, &value)) return -ESTALE;
   if ((kind == 3 || kind == 4) && (value & ~mask)) return -EPROTO;
   if (value & mask) return -EIO;
  }
 return 0;
}

static int md_clear_baseline(struct apple_apciec *p, const struct md_snapshot *s)
{
 static const unsigned order[] = {3, 4, 2, 0, 1, 5};
 unsigned rev, i;
 if (s->status || p->mmio.w1c_complete) return -EPERM;
 /* Unknown AER status cannot be cleared or described as a clean baseline. */
 for (rev = 0; rev < MD_PATHS; rev++) {
  const struct md_function *d = &s->function[rev];
  unsigned kind;
  for (kind = 3; kind <= 4; kind++) {
   unsigned width, slot, off = md_status_offset(d, kind, &width);
   u32 value, mask = mp_w1c_mask(d->rid, off, width, &slot);
   if (!mask || md_observed(d, off, width, &value)) return -ESTALE;
   if (value & ~mask) return -EPROTO;
  }
 }
 /* Downstream first; the root error aggregate is cleared last. */
 for (rev = 0; rev < MD_PATHS; rev++) {
  const struct md_function *d = &s->function[MD_PATHS - rev - 1];
  for (i = 0; i < ARRAY_SIZE(order); i++) {
   unsigned width, slot, off = md_status_offset(d, order[i], &width);
   u32 value, mask = mp_w1c_mask(d->rid, off, width, &slot);
   struct pci_bus bus = {.number = d->rid >> 8, .sysdata = p, .ops = &apple_apciec_ops};
   int ret;
   if (!mask) continue;
   ret = md_observed(d, off, width, &value);
   if (ret) return ret;
   value &= mask;
   if (!value) continue;
   dev_info(p->dev, "retained-mmio-status-clear: RID %04x offset %03x width %u observed %08x; one W1C\n",
            d->rid, off, width, value);
   if (!mp_arm_w1c(&p->mmio, ktime_get_boottime_ns(), d->rid, off, width, value))
    return -EPERM;
   /* Actual config callback consumes the token before a write and performs
    * exactly one readback. Generic size2 uses writew, never a dword RMW.
    */
   ret = apple_apciec_config_write(&bus, d->rid & 255, off, width, value);
   if (ret || p->mmio.w1c_armed || p->mmio.w1c_pending) return -EIO;
   if (!mp_active(&p->mmio, ktime_get_boottime_ns())) return -ETIMEDOUT;
  }
 }
 p->mmio.w1c_complete = true;
 return 0;
}

/* Exact external AppleT8103PCIeC, not the internal pcie-apple error layout.
 * 22G74 getPortInterrupts() reads logical0x100; clearPortInterrupts() writes
 * separately. Native predicates identify RID-map26, abort25, timeout23,
 * read-response21. The retained port already uses ioremap_np.
 */
static int md_port_status(struct apple_apciec *p, const char *when, u32 *value)
{
 int ret = 0;
 if (!p->port || p->retained_phase != 17 || p->mmio_task != current ||
     p->discovery_task || p->retained_scan_task) return -EPERM;
 if (!mp_active(&p->mmio, ktime_get_boottime_ns())) return -ETIMEDOUT;
 p->mmio.ops++; /* Same original 1024-operation ceiling; no added window. */
 *value = readl(p->port + 0x100);
 if (!mp_active(&p->mmio, ktime_get_boottime_ns())) ret = -ETIMEDOUT;
 else if (*value == ~0U) ret = -ENODEV;
 dev_info(p->dev, "retained-mmio-port-status: %s INTSTAT %08x RID-map %u completer-abort %u completion-timeout %u read-response-error %u status %d ops %u; no SoC write\n",
          when, *value, !!(*value & (1U << 26)), !!(*value & (1U << 25)),
          !!(*value & (1U << 23)), !!(*value & (1U << 21)), ret, p->mmio.ops);
 if (!ret && !mp_active(&p->mmio, ktime_get_boottime_ns())) ret = -ETIMEDOUT;
 return ret;
}

/* R41 proved upstream RID0100 ANFE/UR but its default COR_MASK=0x2000
 * suppressed Header Log. PCIe AER logging is enabled independently from
 * Device Control error-message reporting (which stays disabled).
 */
static int md_headerlog(struct apple_apciec *p, const struct md_snapshot *s,
                         bool restore)
{
 u32 mask, devctl, ue_mask, severity;
 int ret;
 if (!restore) {
  const struct md_function *d = &s->function[1];
  if (s->status || d->rid != 0x100 || d->aer != 0x100 || d->pcie != 0xc0 ||
      md_observed(d, d->aer + PCI_ERR_COR_MASK, 4, &mask) ||
      md_observed(d, d->pcie + PCI_EXP_DEVCTL, 2, &devctl) ||
      md_observed(d, d->aer + PCI_ERR_UNCOR_MASK, 4, &ue_mask) ||
      md_observed(d, d->aer + PCI_ERR_UNCOR_SEVER, 4, &severity) ||
      mask != PCI_ERR_COR_ADV_NFAT || (devctl & 0xf) || ue_mask ||
      (severity & PCI_ERR_UNC_UNSUP)) return -EPERM;
 }
 if (!mp_arm_headerlog(&p->mmio, ktime_get_boottime_ns(), restore)) return -EPERM;
 ret = pci_write_config_dword(p->discovery_devices[1], 0x100 + PCI_ERR_COR_MASK,
                              restore ? PCI_ERR_COR_ADV_NFAT : 0);
 if (ret || p->mmio.headerlog_armed || p->mmio.headerlog_pending ||
     p->mmio.headerlog_step != (restore ? 2U : 1U)) ret = -EIO;
 if (!ret && !mp_active(&p->mmio, ktime_get_boottime_ns())) ret = -ETIMEDOUT;
 dev_info(p->dev, "retained-mmio-header-log: RID0100 COR_MASK %s status %d step%u ops%u; reporting controls unchanged\n",
          restore ? "restored-2000" : "unmasked-ANFE", ret,
          p->mmio.headerlog_step, p->mmio.ops);
 return ret;
}

/* Before bridge forwarding is enabled, require disabled native message
 * sources and standard reporting controls on the exact three ancestors.
 * This is read-only; no interrupt or endpoint bus-master enable is added. */
static int md_bridge_forwarding_ready(struct apple_apciec *p)
{
 unsigned j;
 for (j = 0; j < 3; j++) {
  const struct ep_function *f = pd_function(p, j << 8);
  u32 v, cached;
  int ret;
  if (!f || f->identity.rid != j << 8 || !f->msi || f->msi < 0x40 ||
      f->msi > 0xfc || (f->msi & 3) || f->msix) return -ESTALE;
  ret = md_cached(f, f->msi, &cached);
  if (ret || (cached & 0xff) != PCI_CAP_ID_MSI ||
      ((cached >> 16) & PCI_MSI_FLAGS_ENABLE)) return -EPERM;
  ret = pd_read(p, f->identity.rid, f->msi, 4, &v);
  if (ret || v != cached) return ret ? ret : -ESTALE;
  ret = pd_read(p, f->identity.rid, f->pcie + PCI_EXP_DEVCTL, 2, &v);
  if (ret || (v & 0xf)) return ret ? ret : -EPERM;
  ret = pd_read(p, f->identity.rid, f->pm + PCI_PM_CTRL, 2, &v);
  if (ret || (v & PCI_PM_CTRL_STATE_MASK)) return ret ? ret : -EPERM;
 }
 return 0;
}
