/* SPDX-License-Identifier: GPL-2.0 */
#ifndef APPLE_APCIEC_ENUM_H
#define APPLE_APCIEC_ENUM_H
struct device;
bool apple_apciec_retained_enabled(void);
bool apple_apciec_availability_probe_enabled(void);
bool apple_apciec_raw_identity_enabled(void);
bool apple_apciec_endpoint_resources_enabled(void);
bool apple_apciec_endpoint_memory_assign_enabled(void);
bool apple_apciec_endpoint_native_enabled(void);
int apple_apciec_retained_native_prepare(struct device *, unsigned, const void *, unsigned *);
int apple_apciec_retained_native_audit(struct device *, unsigned, const void *);
int apple_apciec_retained_expand_chain(struct device *,unsigned,const void *,u64,unsigned *);
bool apple_apciec_endpoint_mmio_enabled(void);
int apple_apciec_retained_probe_mmio(struct device *, unsigned, const void *, unsigned *);
bool apple_apciec_endpoint_pci_enabled(void);
int apple_apciec_retained_register_pci(struct device *, unsigned, const void *, unsigned *);
bool apple_apciec_retained_dart_probe_allowed(struct device *dev);
/* 1 prefix-backed prepare/raw capability, 0 ordinary window, negative invalid. */
int apple_apciec_retained_dart_params_gate_required(struct device *dev);
/* NHI owns these callbacks and context until domain_stop and work flush finish.
 * get: hold ACIO PHY/power and both validated PMGR parent gates; no PCI DMA.
 * put: release only after host removal + port isolation. Never called on timeout.
 */
struct apple_apciec_supplier_ops {
	int (*get)(void *context);
	/* One-way preparation: retain successful power gets on partial failure. */
	int (*get_retained)(void *context);
	void (*put)(void *context);
};
int apple_apciec_enum_bind(struct device *dev, void *context,
	const struct apple_apciec_supplier_ops *ops, unsigned int root_down_port);
/* Prepare before either adapter enable; commit after BOTH succeed. */
int apple_apciec_enum_prepare(struct device *dev, unsigned int root_down_port);
/* Unwired research entry. Caller must establish fresh exact root/child PE-clear
 * isolation and retained owner before calling; this is NOT a DMA permit. */
/* Ticket lifetime belongs to retained NHI owner until reboot. Begin and finish:
 * caller holds ACIO then TB; populate: neither lock nor device/probe lock held.
 * No stage may be repeated, and a different ticket can never inherit state. */
int apple_apciec_retained_begin_power(struct device *dev, unsigned int port, const void *ticket);
/* Diagnostic-only entry points: immutable retained ticket, retain_commit off.
 * Begin retains power/reset as usual. Sample applies the exact native pre-RC
 * prefix, reads three exact DART registers, and never creates its provider. */
int apple_apciec_retained_begin_availability_probe(struct device *dev, unsigned int port, const void *ticket);
int apple_apciec_retained_sample_availability(struct device *dev, unsigned int port, const void *ticket);
/* Distinct immutable capability: prefix/provider only, never commit/scan. */
int apple_apciec_retained_begin_provider_prepare(struct device *dev, unsigned int port, const void *ticket);
int apple_apciec_retained_begin_raw_identity(struct device *dev, unsigned int port, const void *ticket, u64 deadline);
int apple_apciec_retained_populate_dart(struct device *dev, unsigned int port, const void *ticket);
int apple_apciec_retained_finish(struct device *dev, unsigned int port, const void *ticket);
int apple_apciec_enum_enable(struct device *dev, unsigned int root_down_port);
void apple_apciec_enum_disable(struct device *dev, unsigned int root_down_port);
/* Unbind after TB-lock stopping gate + disable, before depopulation; or after
 * tb_domain_remove/workflush/domain_released. Caller prevents later callbacks. */
int apple_apciec_enum_unbind(struct device *dev);
/* Caller holds ACIO -> TB for audit/commit. Scan holds neither and performs
 * bounded raw configuration discovery without PCI-core registration; same ticket. */
int apple_apciec_retained_prepared_audit(struct device *dev, unsigned int port, const void *ticket);
int apple_apciec_retained_commit(struct device *dev, unsigned int port, const void *ticket);
int apple_apciec_retained_root_rc_prepare(struct device *dev, unsigned int port, const void *ticket);
int apple_apciec_retained_raw_final_audit(struct device *dev, unsigned int port, const void *ticket);
int apple_apciec_retained_scan_quarantined(struct device *dev, unsigned int port, const void *ticket);
/* Caller pins exact cached identity and fresh authenticated router/cable proof.
 * Single consumed phase; immutable host-owned evidence is retained until reboot.
 * No device registration, DMA permit or IOMMU-group claim is produced. */
struct ep_identity;
struct ep_snapshot;
int apple_apciec_retained_records(struct device *, unsigned, const void *,
 const struct ep_identity **, unsigned *);
int apple_apciec_retained_endpoint_resources(struct device *, unsigned, const void *,
 const struct ep_identity *, bool, bool, const struct ep_snapshot **, unsigned *);
int apple_apciec_retained_transit_audit(struct device *, unsigned, const void *);
int apple_apciec_controller_index(struct device *dev);
int apple_apciec_retained_identify_transit_target(struct device *, unsigned,
 const void *, u64, unsigned *);
int apple_apciec_retained_transit_native_prepare(struct device *,unsigned,const void *,unsigned *);
int apple_apciec_retained_transit_native_audit(struct device *,unsigned,const void *);
#endif

/* Explicit R54 controller1 pair; never a dynamic extension of R53. */
bool apple_apciec_endpoint_pair_enabled(void);
int apple_apciec_retained_identify_pair(struct device *,unsigned,const void *,u64,unsigned *);
int apple_apciec_retained_pair_resources(struct device *,unsigned,const void *,const struct ep_snapshot **,const struct ep_snapshot **,unsigned *);
int apple_apciec_retained_pair_native_prepare(struct device *,unsigned,const void *,unsigned *);
int apple_apciec_retained_pair_native_audit(struct device *,unsigned,const void *);
