/* SPDX-License-Identifier: GPL-2.0 */
#ifndef APCIEC_ENDPOINT_RESOURCE_TYPES_H
#define APCIEC_ENDPOINT_RESOURCE_TYPES_H
#define EP_MAX_RECORDS 64
#define EP_MAX_SAMPLES 256
#define EP_BAR_64 1U
#define EP_BAR_PREF 2U
/* Explicit preserved I/O: unsupported, unassigned and deliberately unsized. */
#define EP_BAR_IO_UNASSIGNED 4U
#define EP_BAR_NO_WINDOW (~0U)
struct ep_identity {
 unsigned rid; u32 id, class_rev, subsystem; u64 serial; unsigned header;
};
struct ep_sample { unsigned offset; u32 value; };
struct ep_function {
 struct ep_identity identity;
 unsigned command, sample_count, pm, msi, msix, pcie, acs, rebar, serial_offset;
 u32 buses, pmcsr, devcap, devctl, devcap2, devctl2, acs_bits;
 u32 msix_table, msix_pba, msix_control, msi_control;
 bool flr_capable, serial_present, ari, ats, pasid, sriov;
 struct ep_sample samples[EP_MAX_SAMPLES];
};
struct ep_bar {
 u32 saved[2], mask[2]; u64 size, pci, cpu; unsigned flags, window;
 bool upper, unsupported_io;
};
struct ep_bridge_plan { unsigned rid; u64 start[3], end[3]; bool active[3]; };
struct ep_snapshot {
 struct ep_function functions[EP_MAX_RECORDS];
 unsigned count, selected, ancestors[16], ancestor_count, same_device_mask;
 struct ep_bar bars[6]; struct ep_bridge_plan bridges[16];
 /* sized means supported memory BARs only; unsupported_io is never sized. */
 bool captured, sized, planned;
 bool memory_assigned; /* Host-local assignment/readback/audit completion only. */
 /* Raw topology and ACS evidence only: no pci_dev/IOMMU group exists yet. */
};
#endif
