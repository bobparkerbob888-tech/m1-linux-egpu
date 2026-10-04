/* SPDX-License-Identifier: GPL-2.0 */
/* Native CPU register-access proof; one observed status W1C baseline cleanup.
 * No GPU register writes, reset, driver, DMA or retry. */
#include "mmio-diagnostics.inc"
int apple_apciec_retained_probe_mmio(struct device *dev, unsigned port,
                                    const void *ticket, unsigned *phase)
{
 struct apple_apciec *p = dev_get_drvdata(dev);
 struct resource *bar;
 unsigned j; unsigned long flags; u64 now;
 struct md_snapshot before, after;
 int ret, diag_ret, restore_ret;
 u32 port_before = 0, port_after = 0;
 if (!p || !phase || !endpoint_mmio_probe || !endpoint_pci_register)
  return -EINVAL;
 mutex_lock(&p->lifecycle);
 ret = retained_commit_owner(p, port, ticket, 16);
 if (ret) goto out;
 if (p->mmio.attempted || p->mmio_task || p->mmio_regs ||
     p->discovery_task || p->retained_scan_task || p->discovery_failed ||
     p->discovery_probe.pending || p->discovery_count != 8 ||
     !p->discovery_bridge || !p->discovery_bridge->discovery_only ||
     !p->endpoint_snapshot || !p->endpoint_snapshot->memory_assigned ||
     pd_published_owner_audit(p)) {
  ret = -EPERM; goto out;
 }
 now = ktime_get_boottime_ns();
 if (now >= p->retained_identity_deadline ||
     p->retained_identity_deadline - now < NSEC_PER_SEC) {
  ret = -ETIMEDOUT; goto out;
 }
 p->mmio.attempted = true;
 p->mmio.deadline = min(now + 2ULL * NSEC_PER_SEC, p->retained_identity_deadline);
 p->retained_phase = 17;
 raw_spin_lock_irqsave(&p->lock, flags);
 p->mmio_task = current;
 raw_spin_unlock_irqrestore(&p->lock, flags);
 ret = pd_hardware_audit(p);
 if (!ret) ret = pd_published_owner_audit(p);
 for (j = 0; !ret && j < 8; j++)
  ret = pd_device_audit(p, p->discovery_devices[j], j);
 if (ret) goto close;
 bar = &p->discovery_devices[3]->resource[0];
 if (!bar->parent || bar->start != 0x480000000ULL ||
     resource_size(bar) != 0x4000000 || !(bar->flags & IORESOURCE_MEM) ||
     (bar->flags & (IORESOURCE_IO | IORESOURCE_PREFETCH | IORESOURCE_MEM_NONPOSTED |
                   IORESOURCE_UNSET | IORESOURCE_DISABLED))) {
  ret = -EPERM; goto close;
 }
 /* PCI BAR mappings use ordinary PCI semantics, unlike SoC controller MMIO. */
 p->mmio_regs = pci_iomap_range(p->discovery_devices[3], 0, 0, sizeof(u32));
 if (!p->mmio_regs) { ret = -ENOMEM; goto close; }
 ret = md_bridge_forwarding_ready(p);
 if (ret) goto close;
 for (j = 0; j < 4; j++) {
  if (!mp_active(&p->mmio, ktime_get_boottime_ns()) ||
      p->mmio.next != j || p->mmio.armed || p->mmio.pending) { ret = -EPERM; goto close; }
  p->mmio.armed = true;
  ret = pci_write_config_word(p->discovery_devices[j], PCI_COMMAND, mp_target_command(j << 8));
  if (ret || p->mmio.next != j + 1 || p->mmio.armed || p->mmio.pending) {
   ret = ret ? -EIO : -EPERM; goto close;
  }
 }
 ret = pd_hardware_audit(p);
 if (ret) goto close;
 if (!mp_active(&p->mmio, ktime_get_boottime_ns())) { ret = -ETIMEDOUT; goto close; }
 ret = md_capture(p, &before, "before-clear");
 if (ret) goto close;
 ret = md_clear_baseline(p, &before);
 if (ret) goto close;
 ret = md_capture(p, &after, "clean-baseline");
 if (!ret) ret = md_clean(&after);
 dev_info(p->dev, "retained-mmio-status: clean-baseline verification %d W1C-consumed %08x\n",
          ret, p->mmio.w1c_consumed);
 if (ret) goto close;
 ret = md_headerlog(p, &after, false);
 if (ret) goto close;
 dev_info(p->dev, "retained-mmio-probe: GPU0300 BAR0+0000 read begin; bridge forwarding6, GPU memory-only2, DMA blocked\n");
 ret = md_port_status(p, "before-BAR", &port_before);
 if (ret) goto close;
 if (!mp_active(&p->mmio, ktime_get_boottime_ns())) { ret = -ETIMEDOUT; goto close; }
 p->mmio.ops++;
 p->mmio_boot0[0] = readl(p->mmio_regs);
 if (!mp_active(&p->mmio, ktime_get_boottime_ns())) { ret = -ETIMEDOUT; goto close; }
 p->mmio.ops++;
 p->mmio_boot0[1] = readl(p->mmio_regs);
 ret = mp_boot0_valid(p->mmio_boot0[0], p->mmio_boot0[1]) ? 0 : -ENODEV;
 /* Keep the first BAR-result failure even if the evidence capture also fails. */
 diag_ret = md_port_status(p, "after-BAR", &port_after);
 dev_info(p->dev, "retained-mmio-port-status: before %08x after %08x newly-set %08x capture-status %d; sticky SoC bits not cleared\n",
          port_before, port_after, port_after & ~port_before, diag_ret);
 if (!diag_ret) diag_ret = md_capture(p, &after, "after");
 dev_info(p->dev, "retained-mmio-status: BAR-result %d after-capture %d; no retry\n", ret, diag_ret);
 if (!ret) ret = diag_ret;
 if (!ret) ret = pd_hardware_audit(p);
 if (!ret) ret = pd_published_owner_audit(p);
 close:
 if (p->mmio.headerlog_step == 1 && !p->mmio.headerlog_pending &&
     !p->mmio.headerlog_armed && mp_active(&p->mmio, ktime_get_boottime_ns())) {
  restore_ret = md_headerlog(p, NULL, true);
  if (!ret) ret = restore_ret;
 }
 raw_spin_lock_irqsave(&p->lock, flags);
 p->mmio_task = NULL;
 raw_spin_unlock_irqrestore(&p->lock, flags);
 if (!ret && (!mp_active(&p->mmio, ktime_get_boottime_ns()) ||
              p->mmio.next != 4 || p->mmio.enabled != 15 || p->mmio.armed || p->mmio.pending ||
              !p->mmio.w1c_complete || p->mmio.w1c_armed || p->mmio.w1c_pending ||
              p->mmio.headerlog_step != 2 || p->mmio.headerlog_armed || p->mmio.headerlog_pending)) ret = -EIO;
 if (ret) p->mmio.failed = true;
 else p->retained_phase = 18;
 dev_info(p->dev, "retained-mmio-probe: status %d phase %u enabled %x ops %u BOOT0 %08x/%08x deadline %llu; status W1C plus one logging-mask cycle, bridge6/GPU2; no GPU register writes/driver/DMA\n",
          ret, p->retained_phase, p->mmio.enabled, p->mmio.ops,
          p->mmio_boot0[0], p->mmio_boot0[1], (unsigned long long)p->mmio.deadline);
 out:
 *phase = p->retained_phase;
 mutex_unlock(&p->lifecycle);
 return ret;
}
EXPORT_SYMBOL_GPL(apple_apciec_retained_probe_mmio);
