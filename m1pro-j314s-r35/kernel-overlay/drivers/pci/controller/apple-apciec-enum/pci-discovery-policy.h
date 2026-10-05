/* SPDX-License-Identifier: GPL-2.0 */
/* Real PCI-core probes and their exact restores, never fabricated write success.
 * Caller supplies a fresh pre-write value under its serialized config lock.
 * This policy is only used by the separately consumed discovery transaction. */
#ifndef APCIEC_PCI_DISCOVERY_POLICY_H
#define APCIEC_PCI_DISCOVERY_POLICY_H
struct pd_probe {
 unsigned rid, offset, width;
 u32 saved;
 bool pending;
};
static bool pd_overlap(unsigned offset, unsigned width, unsigned first, unsigned length)
{
 return offset < first + length && first < offset + width;
}
static bool pd_probe_location(unsigned header, unsigned off, unsigned width,
                              u32 old, u32 value)
{
 if (width == 4 && off >= 0x10 && off <= (header == 1 ? 0x14 : 0x24) &&
     !(off & 3) && value == 0xffffffffU)
  return true;
 if (width == 4 && off == (header == 1 ? 0x38 : 0x30) && value == 0xfffff800U &&
     !(old & 1))
  return true;
 if (header != 1) return false;
 /* Standard pci_read_bridge_windows support probes; all are restored. */
 return (width == 2 && off == 0x1c && old == 0 && value == 0xe0f0) ||
        (width == 4 && off == 0x24 && old == 0 && value == 0xffe0fff0U) ||
        (width == 4 && off == 0x28 && value == 0xffffffffU);
}
static bool pd_write_allowed(struct pd_probe *probe, const struct ep_function *f,
                             unsigned off, unsigned width, u32 old, u32 value)
{
 unsigned header = f->identity.header & 0x7f;
 if ((width != 1 && width != 2 && width != 4) || off > 4096 - width ||
     (off & (width - 1)) || (header != 0 && header != 1)) return false;
 /* Decode and bus mastering never become enabled, including byte writes. */
 if (pd_overlap(off, width, 4, 2)) {
  if (off != 4 || width != 2 || (value & ~0x400U)) return false;
  return !probe->pending;
 }
 if (probe->pending) {
  if (probe->rid != f->identity.rid || probe->offset != off ||
      probe->width != width || probe->saved != value) return false;
  probe->pending = false;
  return true;
 }
 if (pd_probe_location(header, off, width, old, value)) {
  *probe = (struct pd_probe){f->identity.rid, off, width, old, true};
  return true;
 }
 /* Do not issue even an unchanged write with a reset/enable bit asserted. */
 if (header == 1 && pd_overlap(off, width, 0x3e, 2)) return false;
 if (f->pcie && (pd_overlap(off, width, f->pcie + 8, 2) ||
                pd_overlap(off, width, f->pcie + 0x10, 2) ||
                pd_overlap(off, width, f->pcie + 0x28, 2) ||
                pd_overlap(off, width, f->pcie + 0x30, 2))) return false;
 if (header == 1 && pd_overlap(off, width, 0x18, 4)) return false;
 /* PM initialization can clear PME/status while preserving D0 and other bits. */
 if (f->pm && off == f->pm + 4 && width == 2)
  return !(old & 3) && !(value & 3) && !((old ^ value) & ~0x8100U) &&
         !(value & 0x100U);
 /* Standard already-disabled capability writes still go to real hardware. */
 return old == value;
}
#endif
