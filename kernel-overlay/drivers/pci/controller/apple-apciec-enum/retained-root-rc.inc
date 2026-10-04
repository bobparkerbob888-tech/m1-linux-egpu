/* Exact current-boot host ECAM RC table. Never opens generic config access. */
static const u32 retained_rc_rows[4][3] = {
 {0x718, 0x0007c000, 0}, {0x8bc, 1, 0},
 {0x078, 0x00007000, 0}, {0x814, 0xffffffff, 0x0000f060},
};
static int retained_identity_gate(struct apple_apciec *p)
{
 if (!p->retained_raw_identity || p->retained_provider_prepare ||
     p->retained_availability_probe || !retained_prefix_capability_valid(p) ||
     !p->retained || !p->retained_ticket || !p->prepared || !p->power_ready ||
     !p->dart || !p->port || !p->ecam || !p->retained_prefix_ready ||
     !p->retained_prefix_attempted || p->retained_sample_regs ||
     p->retained_sample_attempted || p->root_down_port != 3 ||
     p->rid_entries != 64 || p->bus_start || p->bus_end != 255 ||
     p->bridge || p->iommu_ready || p->msi_domain_ready ||
     !p->profile || p->ecam_resource.start != p->profile->ecam ||
     resource_size(&p->ecam_resource) != 0x10000000 ||
     p->ecam_size != 0x10000000 ||
     p->ecam_resource.flags != (IORESOURCE_MEM | IORESOURCE_MEM_NONPOSTED))
  return -EPERM;
 return 0;
}
static int retained_rc_table(struct apple_apciec *p)
{
 const struct property *prop = of_find_property(p->dev->of_node,
                                            "apple,apcie-rc-tunables", NULL);
 const __be32 *v;
 unsigned int k, j;
 if (!prop || !prop->value || prop->length != sizeof(retained_rc_rows))
  return -EINVAL;
 v = prop->value;
 for (k = 0; k < 4; k++)
  for (j = 0; j < 3; j++)
   if (be32_to_cpu(v[3*k+j]) != retained_rc_rows[k][j])
    return -EINVAL;
 return 0;
}
static int retained_rc_read(struct apple_apciec *p, unsigned int off, u32 *v)
{
 int ret = retained_identity_gate(p);
 bool account = p->retained_phase == 13 && p->retained_scan_task == current;
 bool mmio = p->retained_phase == 17 && p->mmio_task == current;
 if (ret) return ret;
 if (off != 0 && off != 4 && off != 8 && off != 12 && off != 0x18 &&
     off != 0x718 && off != 0x8bc && off != 0x78 && off != 0x814)
  return -EPERM;
 if (account) {
  if (!endpoint_memory_assign || !p->endpoint_assignment_attempted ||
      p->retained_failed) return -EPERM;
  if (p->retained_scan_exhausted || p->retained_scan_ops >= 8192 ||
      ktime_get_boottime_ns() >= p->retained_scan_deadline) {
   p->retained_scan_exhausted = true; return -ETIMEDOUT;
  }
  p->retained_scan_ops++; /* Same original budget, before this direct ECAM read. */
 }
 if (mmio && (!endpoint_mmio_probe || !mp_active(&p->mmio, ktime_get_boottime_ns())))
  return -EPERM;
 dev_info(p->dev, "retained-root-rc: read begin root00:00.0 offset=%03x\n", off);
 if (account && ktime_get_boottime_ns() >= p->retained_scan_deadline) {
  p->retained_scan_exhausted = true; return -ETIMEDOUT;
 }
 /* Logging may sleep or stall: recheck immediately before this access. */
 if (mmio) {
  if (!mp_active(&p->mmio, ktime_get_boottime_ns())) {
   p->mmio.failed = true; return -ETIMEDOUT;
  }
  p->mmio.ops++;
 }
 *v = readl(p->ecam + off);
 if (mmio && ktime_get_boottime_ns() >= p->mmio.deadline) {
  p->mmio.failed = true; return -ETIMEDOUT;
 }
 dev_info(p->dev, "retained-root-rc: read offset=%03x value=%08x\n", off, *v);
 if (account && ktime_get_boottime_ns() >= p->retained_scan_deadline) {
  p->retained_scan_exhausted = true; return -ETIMEDOUT;
 }
 ret = retained_identity_gate(p);
 return ret ? ret : *v == U32_MAX ? -EIO : 0;
}
static int retained_rc_header(struct apple_apciec *p, bool initial)
{
 u32 id, command, class_rev, header, buses, again;
 int ret;
 ret = retained_rc_read(p, 0, &id); if (ret) return ret;
 if (!id || !(id & 0xffff) || (id & 0xffff) == 0xffff ||
     (id & 0xffff) == 1) return -ENODEV;
 if (!initial && id != p->retained_rc_identity) return -ESTALE;
 ret = retained_rc_read(p, 4, &command); if (ret) return ret;
 ret = retained_rc_read(p, 8, &class_rev); if (ret) return ret;
 ret = retained_rc_read(p, 12, &header); if (ret) return ret;
 ret = retained_rc_read(p, 0x18, &buses); if (ret) return ret;
 if ((command & 7) != mp_expected_command(&p->mmio, 0) || (class_rev >> 16) != 0x0604 ||
     ((header >> 16) & 0x7f) != 1 || (header & BIT(23)) ||
     (buses & 255) ||
     (((buses >> 8) & 255) > ((buses >> 16) & 255)) ||
     (!((buses >> 8) & 255) && ((buses >> 16) & 255)))
  return -EPERM;
 ret = retained_rc_read(p, 0, &again); if (ret) return ret;
 if (again != id) return -ESTALE;
 if (initial) p->retained_rc_identity = id;
 return 0;
}
static int retained_root_rc_audit(struct apple_apciec *p)
{
 unsigned int k;
 u32 v;
 int ret;
 if (!p->retained_rc_attempted || !p->retained_rc_ready)
  return -EPERM;
 ret = retained_rc_table(p); if (ret) return ret;
 ret = retained_rc_header(p, false); if (ret) return ret;
 for (k = 0; k < 4; k++) {
  ret = retained_rc_read(p, retained_rc_rows[k][0], &v); if (ret) return ret;
  if (v != p->retained_rc_values[k]) return -EIO;
 }
 return 0;
}
int apple_apciec_retained_root_rc_prepare(struct device *dev, unsigned int port,
                                         const void *ticket)
{
 struct apple_apciec *p = dev_get_drvdata(dev);
 u32 before[4], got;
 unsigned int k;
 int ret, post;
 if (!p) return -ENODEV;
 mutex_lock(&p->lifecycle);
 ret = retained_identity_gate(p);
 if (ret || port != 3 || ticket != p->retained_ticket ||
     p->retained_failed || p->retained_phase != 6 || p->tunnel_ready ||
     p->retained_scan_task || p->retained_rc_attempted || p->retained_rc_ready) {
  ret = ret ? ret : -EPERM; goto out;
 }
 p->retained_rc_attempted = true; /* Before any root access, no repeat. */
 ret = retained_rc_table(p); if (ret) goto fail;
 ret = availability_port_contained(p, 1, 0x00100001); if (ret) goto fail;
 ret = retained_dma_blocked(p); if (ret) goto fail;
 ret = retained_rc_header(p, true); if (ret) goto fail;
 for (k = 0; k < 4; k++) {
  ret = retained_rc_read(p, retained_rc_rows[k][0], &before[k]);
  if (ret) goto fail;
 }
 for (k = 0; k < 4; k++) {
  u32 off = retained_rc_rows[k][0];
  ret = retained_identity_gate(p); if (ret) goto fail;
  ret = availability_port_contained(p, 1, 0x00100001); if (ret) goto fail;
  ret = retained_dma_blocked(p); if (ret) goto fail;
  ret = retained_rc_read(p, off, &got); if (ret) goto fail;
  if (got != before[k]) { ret = -ESTALE; goto fail; }
  p->retained_rc_values[k] = (before[k] & ~retained_rc_rows[k][1]) | retained_rc_rows[k][2];
  dev_info(p->dev, "retained-root-rc: write begin root00:00.0 offset=%03x old=%08x next=%08x\n", off, before[k], p->retained_rc_values[k]);
  writel(p->retained_rc_values[k], p->ecam + off);
  ret = retained_rc_read(p, off, &got); if (ret) goto fail;
  if (got != p->retained_rc_values[k]) { ret = -EIO; goto fail; }
 }
 p->retained_rc_ready = true;
 ret = retained_root_rc_audit(p); if (ret) goto fail;
 ret = availability_port_contained(p, 1, 0x00100001); if (ret) goto fail;
 ret = retained_dma_blocked(p); if (ret) goto fail;
 dev_info(p->dev, "retained-root-rc: exact four rows complete, root id=%08x; PE/LTSSM still closed\n", p->retained_rc_identity);
 goto out;
 fail:
 p->retained_rc_ready = false;
 p->retained_failed = true;
 post = retained_identity_gate(p);
 if (!post) post = availability_port_contained(p, 1, 0x00100001);
 if (!post) post = retained_dma_blocked(p);
 dev_info(p->dev, "retained-root-rc: failed status %d post-containment %d; no retry\n", ret, post);
 out:
 mutex_unlock(&p->lifecycle);
 return ret;
}
EXPORT_SYMBOL_GPL(apple_apciec_retained_root_rc_prepare);

/* Read-only phase-aware proof. Availability/prepare predicates stay unchanged. */
static int retained_identity_port_audit(struct apple_apciec *p, bool link)
{
 int ret = retained_identity_gate(p);
 if (ret) return ret;
 if (readl(p->port + 0x814) != 1 || readl(p->port + 0x800) != 0x00100001 ||
     readl(p->port + 0x140) != 0x11 || readl(p->port + 0x80) != (link ? 1 : 0))
  return -EIO;
 return retained_dma_blocked(p);
}
static int retained_identity_release(struct apple_apciec *p)
{
 u32 v;
 int ret = retained_identity_port_audit(p, false);
 if (ret) return ret;
 ret = retained_root_rc_audit(p); if (ret) return ret;
 /* Native releaseResetFlow, then LTSSM. Prefix is never written a second time. */
 dev_info(p->dev, "retained-raw-identity: tunnel-reset clear begin\n");
 writel(0, p->port + 0x988);
 if (readl(p->port + 0x988)) return -EIO;
 ret = readl_poll_timeout(p->port + 0x98c, v,
                         v == U32_MAX || !(v & BIT(0)), 1000, 100000);
 if (ret || v == U32_MAX) return ret ? ret : -EIO;
 ret = retained_identity_port_audit(p, false); if (ret) return ret;
 dev_info(p->dev, "retained-raw-identity: LTSSM start begin\n");
 writel(1, p->port + 0x80);
 if (readl(p->port + 0x80) != 1) return -EIO;
 ret = readl_poll_timeout(p->port + 0x208, v,
                         v == U32_MAX || (v & BIT(0)), 1000, 100000);
 if (ret || v == U32_MAX) return ret ? ret : -EIO;
 ret = retained_identity_port_audit(p, true); if (ret) return ret;
 return retained_root_rc_audit(p);
}
int apple_apciec_retained_raw_final_audit(struct device *dev, unsigned int port,
                                         const void *ticket)
{
 struct apple_apciec *p = dev_get_drvdata(dev);
 int ret;
 u32 ltssm;
 if (!p) return -ENODEV;
 mutex_lock(&p->lifecycle);
 ret = retained_identity_gate(p);
 if (ret || port != 3 || ticket != p->retained_ticket || p->retained_scan_task) {
  ret = ret ? ret : -EPERM; goto out;
 }
 /* Failed actions may have reached hardware. Observe, never rewrite. */
 ltssm = readl(p->port + 0x80);
 ret = ltssm > 1 ? -EIO : retained_identity_port_audit(p, ltssm == 1);
 if (!ret && p->retained_rc_ready) ret = retained_root_rc_audit(p);
 if (!ret && !p->retained_rc_ready) ret = -EPERM;
 out:mutex_unlock(&p->lifecycle); return ret;
}
EXPORT_SYMBOL_GPL(apple_apciec_retained_raw_final_audit);
