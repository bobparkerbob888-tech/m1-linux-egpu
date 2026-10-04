// SPDX-License-Identifier: GPL-2.0
/*
 * J293 APCIEC host-controller integration work, NOT an operational driver.
 * No live installation. Default-off probe maps only; supplier glue gates MMIO.
 * Register layouts below were independently recovered from Apple 22G74 J293
 * AppleT8103PCIeCPort and compared against Linux pcie-apple.c. They do not
 * establish power sequencing, tunnel lifecycle, or DMA isolation.
 */
#include <linux/bitfield.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/notifier.h>
#include <linux/slab.h>
#include "endpoint-resource-types.h"
#include <linux/ktime.h>
#include <linux/iommu.h>
#include <linux/dma-map-ops.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/irqchip/irq-msi-lib.h>
#include <linux/msi.h>
#include <linux/pm_runtime.h>
#include "pci-discovery-policy.h"
#include <linux/pci_regs.h>
#include "mmio-probe-core.h"
#include <linux/sched.h>
#include "apple-apciec-enum.h"
#include <linux/spinlock.h>
#include <linux/of.h>
#include <linux/of_pci.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/pci.h>
#include "../../pci.h"
#include <linux/resource_ext.h>
#include <linux/pci-ecam.h>
#include <linux/platform_device.h>
#include "pre-dart-core.h"
#include "assignment-plan-core.h"
#include "controller-profile.h"
#include "target-policy.h"
#include "pair-policy.h"
#include "pair-boot-policy.h"
#include <linux/init.h>
#include <generated/utsrelease.h>
#include "owned-windows.inc"
#include "assignment-execute-core.h"

/* Firmware ADT reg indices, confirmed by retained driver symbols. */
enum apciec_region { APCIEC_ECAM, APCIEC_COMMON, APCIEC_PORT, APCIEC_FABRIC,
		     APCIEC_DEBUG, APCIEC_REGIONS };
#define APCIEC_MSICFG  0x124
#define APCIEC_MSIBASE 0x128
#define APCIEC_MSIADDR 0x168
#define APCIEC_RID2SID 0x828
#define APCIEC_RID_VALID BIT(31)
#define APCIEC_RID_SID GENMASK(21, 16)
#define APCIEC_RID_RID GENMASK(15, 0)

static bool endpoint_mmio_probe;
module_param(endpoint_mmio_probe, bool, 0444);
MODULE_PARM_DESC(endpoint_mmio_probe, "One memory-only decode and read-only GPU identification probe; no DMA or driver");

static bool endpoint_pci_register;
module_param(endpoint_pci_register, bool, 0444);
MODULE_PARM_DESC(endpoint_pci_register, "Register the verified PCI topology without drivers or DMA");

static bool endpoint_memory_assign;
module_param(endpoint_memory_assign, bool, 0444);
MODULE_PARM_DESC(endpoint_memory_assign, "One exact private memory assignment after resource proof; no decode, PCI publication or DMA");

static bool endpoint_resources;
module_param(endpoint_resources, bool, 0444);
MODULE_PARM_DESC(endpoint_resources, "One exact retained endpoint snapshot/sizing/plan; no assignment or DMA");

#include "native-types.h"
#include "multi-types.h"
static bool endpoint_pair;
module_param(endpoint_pair,bool,0444);
MODULE_PARM_DESC(endpoint_pair,"Explicit R54 controller1 two-GPU retained policy");
static bool endpoint_native_driver;
module_param(endpoint_native_driver, bool, 0444);
MODULE_PARM_DESC(endpoint_native_driver, "One selected native PCI DMA/IRQ/driver admission, retained until reboot");
struct apple_apciec {
 const struct apciec_controller_profile *profile;
 struct apciec_native *native;
 struct apciec_multi *multi;
 struct mp_state mmio;
 struct task_struct *mmio_task;
 void __iomem *mmio_regs;
 u32 mmio_boot0[2];
 struct pci_host_bridge *discovery_bridge;
 struct list_head discovery_windows;
 struct pci_dev *discovery_devices[8];
 struct pci_bus *discovery_buses[7];
 struct resource discovery_bus_resource;
 struct task_struct *discovery_task;
 u64 discovery_deadline;
 unsigned discovery_ops, discovery_count;
 bool discovery_attempted, discovery_failed;
 struct pd_probe discovery_probe;
 struct ep_identity retained_records[EP_MAX_RECORDS];
 unsigned retained_record_count, endpoint_selected_rid;
 bool endpoint_sizing;
 struct ep_snapshot *endpoint_snapshot;
 struct ep_snapshot *pair_secondary_snapshot;
 struct apciec_native_pair *pair_native;
 unsigned pair_assignment_steps;
 struct as_owner *endpoint_owner;
 struct as_execution endpoint_execution;
 bool endpoint_assignment_attempted, endpoint_assignment_armed;
 unsigned tn_assignment_steps;
 struct apcie_tunable_table tunable_tables[3];
 void __iomem *tunable_regs[3];
 struct resource tunable_resource[3];
 bool predart_attempted;
	struct device *dev;
	struct mutex lifecycle;
	const struct apple_apciec_supplier_ops *supplier;
	void *supplier_context;
	unsigned int root_down_port;
	bool retained;
	const void *retained_ticket;
	unsigned int retained_phase;
	bool retained_failed;
	bool retained_dart_window;
	bool retained_availability_probe;
	bool retained_provider_prepare;
 bool retained_raw_identity;
 bool retained_rc_attempted, retained_rc_ready;
 u32 retained_rc_identity, retained_rc_values[4];
 u64 retained_identity_deadline;
	bool retained_prefix_attempted;
	bool retained_prefix_ready;
	bool retained_sample_attempted;
	void __iomem *retained_sample_regs;
	struct resource retained_sample_resource;
	struct task_struct *retained_scan_task;
	u64 retained_scan_deadline;
	unsigned int retained_scan_ops;
	bool retained_scan_exhausted;
	struct of_changeset retained_dart_changeset;
	struct property *retained_dart_status;
	struct device_node *retained_dart_node;
	bool attempted;
	bool dart_populated;
	bool port_prepared;
	bool prepared;
	struct platform_device *dart;
	struct resource bus_resource;
	struct resource ecam_resource, port_resource;
	struct pci_host_bridge *bridge;
	void __iomem *ecam;
	void __iomem *port;
	raw_spinlock_t lock;
	resource_size_t ecam_size;
	u8 bus_start, bus_end;
	/* Supplied only after firmware revision and endpoint DART validation. */
	u32 rid_entries;
	u32 sid_count;
	u32 msi_base;
	u32 msi_count;
	u32 msi_address;
	bool power_ready;
	bool tunnel_ready;
	bool iommu_ready;
	bool msi_domain_ready;
};

/* This driver uses a PRIVATE pci_host_bridge sysdata pointer, never
 * pci_host_common_init()/pci_config_window. Both transactions and lifecycle
 * invalidation serialize on this lock; shutdown must clear readiness under
 * lock before domain removal/unmapping and never wait while holding it.
 */
static bool pn_mode(struct apple_apciec *p)
{ return p && endpoint_pair && p->profile==&apciec_profiles[1] &&
 pn_boot_valid(UTS_RELEASE,saved_command_line); }
static int np_config_locked(struct pci_bus *,unsigned,int,int,u32 *,bool);
static int tn_owner_validate(struct apple_apciec *p);
static int tn_config_locked(struct pci_bus *, unsigned, int, int, u32 *, bool);
static int an_config_locked(struct pci_bus *, unsigned, int, int, u32 *, bool);
static int am_config_locked(struct pci_bus *, unsigned, int, int, u32 *, bool);
static void __iomem *apple_apciec_map_bus(struct pci_bus *bus,
				       unsigned int devfn, int where)
{
	struct apple_apciec *pcie = bus->sysdata;
	u64 offset;

	lockdep_assert_held(&pcie->lock);
	if ((pcie->retained && pcie->retained_scan_task != current &&
         pcie->discovery_task != current && pcie->mmio_task != current &&
         !(pcie->native && pcie->native->active && !pcie->native->failed)) ||
	    !pcie->power_ready || !pcie->tunnel_ready || !pcie->ecam ||
	    bus->number < pcie->bus_start || bus->number > pcie->bus_end ||
	    devfn > 255 || (bus->number == pcie->bus_start && devfn != 0) ||
	    where < 0 || where >= 4096)
		return NULL;
	/* Apple configSpaceAddress uses the absolute bus number. */
	offset = PCIE_ECAM_OFFSET(bus->number, devfn, where);
	if (offset >= pcie->ecam_size)
		return NULL;
	return pcie->ecam + offset;
}

static int apple_apciec_config_access(struct pci_bus *bus, unsigned int devfn,
				    int where, int size, u32 *value, bool write)
{
	struct apple_apciec *pcie = bus->sysdata;
	unsigned long flags;
	u64 offset;
	int ret;

	if ((size != 1 && size != 2 && size != 4) || where < 0 ||
	    where > 4096 - size || (where & (size - 1)))
		return PCIBIOS_BAD_REGISTER_NUMBER;
	if (!write)
		*value = ~0U;
	raw_spin_lock_irqsave(&pcie->lock, flags);
	if (pcie->native && pcie->native->active) {
        ret = pcie->profile == &apciec_profiles[1] && endpoint_pair ? np_config_locked(bus, devfn, where, size, value, write) : pcie->profile == &apciec_profiles[1] ? tn_config_locked(bus, devfn, where, size, value, write) : pcie->multi ? am_config_locked(bus, devfn, where, size, value, write) :
              an_config_locked(bus, devfn, where, size, value, write);
        goto unlock;
    }
	if (pcie->retained && pcie->mmio_task == current) {
        const struct ep_function *f = NULL;
        unsigned j, rid = ((unsigned)bus->number << 8) | devfn;
        u32 before;
        bool w1c = write && pcie->mmio.w1c_armed;
        bool headerlog = write && pcie->mmio.headerlog_armed;
        if (!endpoint_mmio_probe || !endpoint_pci_register || pcie->retained_phase != 17 ||
            pcie->discovery_task || pcie->retained_scan_task ||
            !mp_active(&pcie->mmio, ktime_get_boottime_ns()) ||
            pcie->mmio.ops > 1024 - (write ? 3 : 1)) {
                pcie->mmio.failed = true; ret = PCIBIOS_DEVICE_NOT_FOUND; goto unlock;
        }
        for (j = 0; j < pcie->endpoint_snapshot->count; j++)
                if (pcie->endpoint_snapshot->functions[j].identity.rid == rid)
                        f = &pcie->endpoint_snapshot->functions[j];
        if (!f || !apple_apciec_map_bus(bus, devfn, where)) {
                pcie->mmio.failed = true; ret = PCIBIOS_DEVICE_NOT_FOUND; goto unlock;
        }
        if (write) {
                pcie->mmio.ops++;
                ret = pci_generic_config_read(bus, devfn, where, size, &before);
                if (ret || !(headerlog ?
                    mp_allow_headerlog(&pcie->mmio, ktime_get_boottime_ns(),
                                       rid, where, size, before, *value) : w1c ?
                    mp_allow_w1c(&pcie->mmio, ktime_get_boottime_ns(),
                                  rid, where, size, before, *value) :
                    mp_allow_write(&pcie->mmio, ktime_get_boottime_ns(),
                                   rid, where, size, before, *value))) {
                        pcie->mmio.failed = true;
                        ret = ret ? ret : PCIBIOS_SET_FAILED; goto unlock;
                }
        }
        if (!mp_active(&pcie->mmio, ktime_get_boottime_ns())) {
                pcie->mmio.failed = true; ret = PCIBIOS_DEVICE_NOT_FOUND; goto unlock;
        }
        pcie->mmio.ops++;
        ret = write ? pci_generic_config_write(bus, devfn, where, size, *value) :
                      pci_generic_config_read(bus, devfn, where, size, value);
        if (!ret && write) {
                if (!mp_active(&pcie->mmio, ktime_get_boottime_ns())) ret = PCIBIOS_SET_FAILED;
                else {
                        pcie->mmio.ops++;
                        ret = pci_generic_config_read(bus, devfn, where, size, &before);
                        if (!ret && !(headerlog ? mp_complete_headerlog(&pcie->mmio, rid, before) :
                                     w1c ? mp_complete_w1c(&pcie->mmio, rid, before) :
                                          mp_complete_write(&pcie->mmio, rid, before)))
                                ret = PCIBIOS_SET_FAILED;
                }
        }
        if (ret) pcie->mmio.failed = true;
        goto unlock;
    }
	if (pcie->retained && pcie->discovery_task == current) {
        const struct ep_function *f = NULL;
        unsigned j, rid = ((unsigned)bus->number << 8) | devfn;
        u32 before;
        bool restoring = pcie->discovery_probe.pending;
        if (!endpoint_pci_register || pcie->retained_phase != 15 ||
            !pcie->discovery_attempted || pcie->discovery_failed ||
            pcie->retained_scan_task || pcie->discovery_ops > 16384 - (write ? 3 : 1) ||
            ktime_get_boottime_ns() >= pcie->discovery_deadline) {
                pcie->discovery_failed = true;
                ret = PCIBIOS_DEVICE_NOT_FOUND;
                goto unlock;
        }
        for (j = 0; j < pcie->endpoint_snapshot->count; j++)
                if (pcie->endpoint_snapshot->functions[j].identity.rid == rid)
                        f = &pcie->endpoint_snapshot->functions[j];
        if (!f || !apple_apciec_map_bus(bus, devfn, where)) {
                ret = PCIBIOS_DEVICE_NOT_FOUND;
                goto unlock;
        }
        if (write) {
                pcie->discovery_ops++;
                ret = pci_generic_config_read(bus, devfn, where, size, &before);
                if (ret || !pd_write_allowed(&pcie->discovery_probe, f,
                                             where, size, before, *value)) {
                        pcie->discovery_failed = true;
                        dev_err(pcie->dev, "PCI discovery denied write RID %04x offset %03x width %d value %08x\n",
                                rid, where, size, *value);
                        ret = ret ? ret : PCIBIOS_SET_FAILED;
                        goto unlock;
                }
        }
        if (ktime_get_boottime_ns() >= pcie->discovery_deadline) {
                pcie->discovery_failed = true;
                ret = PCIBIOS_DEVICE_NOT_FOUND;
                goto unlock;
        }
        pcie->discovery_ops++;
        ret = write ? pci_generic_config_write(bus, devfn, where, size, *value) :
                      pci_generic_config_read(bus, devfn, where, size, value);
        if (!ret && write && restoring) {
                if (ktime_get_boottime_ns() >= pcie->discovery_deadline)
                        ret = PCIBIOS_SET_FAILED;
                else {
                        pcie->discovery_ops++;
                        ret = pci_generic_config_read(bus, devfn, where, size, &before);
                        if (!ret && before != *value) ret = PCIBIOS_SET_FAILED;
                }
        }
        if (ret) pcie->discovery_failed = true;
        goto unlock;
    }
	if (pcie->retained && pcie->retained_scan_task == current) {
		if (pcie->profile->index &&
		    ((pcie->retained_phase==9 &&
		      !(endpoint_pair ? pn_mode(pcie) && pn_identity_config_allowed((bus->number << 8)|devfn,where,size,write,*value) : apciec_transit_config_allowed((bus->number << 8)|devfn,where,size,write,*value))) ||
             ((pcie->retained_phase==11||pcie->retained_phase==13) &&
              ((endpoint_pair ? !pn_mode(pcie) || pn_index((bus->number<<8)|devfn)<0 : tn_index((bus->number<<8)|devfn)<0) || size!=4 || where<0 || where>0xffc || (where&3))) ||
             (pcie->retained_phase!=9&&pcie->retained_phase!=11&&pcie->retained_phase!=13))) {
			ret = write ? PCIBIOS_SET_FAILED : PCIBIOS_DEVICE_NOT_FOUND;
			goto unlock;
		}
		if (pcie->retained_scan_ops >= 8192 ||
		    ktime_get_boottime_ns() >= pcie->retained_scan_deadline) {
			pcie->retained_scan_exhausted = true;
			ret = PCIBIOS_DEVICE_NOT_FOUND;
			goto unlock;
		}
		/* Only consumed phase11 memory BAR DWORDs extend raw discovery.
		 * Exact GPU BAR5 is preserved I/O and remains read-only. */
		if (write && ((pcie->retained_phase == 9 &&
		    (size != 4 || (where != 4 && where != 0x18))) ||
		    (pcie->retained_phase == 11 &&
		    (!endpoint_resources || !pcie->retained_raw_identity ||
		     !pcie->endpoint_sizing || size != 4 || where < 0x10 || where > 0x20 ||
		     (((unsigned)bus->number << 8) | devfn) != pcie->endpoint_selected_rid)) ||
		    (pcie->retained_phase == 13 && pcie->profile->index==0 &&
		     (!endpoint_memory_assign || !endpoint_resources || !pcie->retained_raw_identity ||
		      !pcie->endpoint_sizing || !pcie->endpoint_assignment_attempted ||
		      !pcie->endpoint_assignment_armed || !pcie->endpoint_owner ||
		      !pcie->endpoint_owner->ready || pcie->endpoint_owner->failed ||
		      as_owner_validate(pcie->endpoint_owner) ||
		      pcie->endpoint_execution.attempted_writes != pcie->endpoint_execution.next + 1 ||
		      pcie->endpoint_execution.completed_writes != pcie->endpoint_execution.next ||
		      pcie->retained_scan_deadline != pcie->endpoint_owner->plan.budget.raw_deadline ||
		      pcie->retained_identity_deadline != pcie->endpoint_owner->plan.budget.ticket_deadline ||
		      pcie->retained_scan_ops < pcie->endpoint_owner->plan.budget.config_ops ||
		      pcie->retained_scan_ops > 8192 - 256 ||
		      pcie->retained_scan_deadline < NSEC_PER_SEC ||
		      ktime_get_boottime_ns() > pcie->retained_scan_deadline - NSEC_PER_SEC ||
		      !as_next_write_allowed(&pcie->endpoint_owner->plan, &pcie->endpoint_execution,
		       ((unsigned)bus->number << 8) | devfn, where, size, *value))) ||
		    (pcie->retained_phase != 9 && pcie->retained_phase != 11 &&
		     pcie->retained_phase != 13))) {
			ret = PCIBIOS_SET_FAILED;
			goto unlock;
		}
        if(write && pcie->retained_phase==13 && pcie->profile->index==1) {
         if(!endpoint_memory_assign||!endpoint_resources||!pcie->retained_raw_identity||
            !pcie->endpoint_sizing||pcie->endpoint_selected_rid!=0x600||
            !pcie->endpoint_assignment_attempted||!pcie->endpoint_assignment_armed||
            tn_owner_validate(pcie)||pcie->retained_scan_ops>8192-512||
            pcie->retained_scan_deadline<=NSEC_PER_SEC||
            ktime_get_boottime_ns()>pcie->retained_scan_deadline-NSEC_PER_SEC||
            !(endpoint_pair ? pn_mode(pcie) && pn_expected_write(pcie->pair_assignment_steps,(bus->number<<8)|devfn,where,*value) : tn_expected_write(pcie->tn_assignment_steps,(bus->number<<8)|devfn,where,*value))) {
          ret=PCIBIOS_SET_FAILED;goto unlock;
         }
         if(endpoint_pair)pcie->pair_assignment_steps++;else pcie->tn_assignment_steps++; /* Consume before MMIO. */
        }
		if (write && pcie->retained_phase == 13)
			pcie->endpoint_assignment_armed = false; /* Consume before MMIO, even on error. */
		pcie->retained_scan_ops++;
	}
	offset = PCIE_ECAM_OFFSET(bus->number, devfn, where);
	if (!apple_apciec_map_bus(bus, devfn, where) ||
	    offset + size > pcie->ecam_size)
		ret = PCIBIOS_DEVICE_NOT_FOUND;
	else if (write) {
		/* Enumeration-only invariant: block every write width overlapping
		 * PCI_COMMAND MASTER, even before a pci_dev exists during scanning.
		 */
		if (where <= PCI_COMMAND && where + size > PCI_COMMAND)
			*value &= ~((PCI_COMMAND_MASTER | PCI_COMMAND_MEMORY | PCI_COMMAND_IO)
				    << ((PCI_COMMAND - where) * 8));
		ret = pci_generic_config_write(bus, devfn, where, size, *value);
	}
	else
		ret = pci_generic_config_read(bus, devfn, where, size, value);
 unlock:
	raw_spin_unlock_irqrestore(&pcie->lock, flags);
	return ret;
}

static int apple_apciec_config_read(struct pci_bus *bus, unsigned int devfn,
				   int where, int size, u32 *value)
{
	return apple_apciec_config_access(bus, devfn, where, size, value, false);
}

static int apple_apciec_config_write(struct pci_bus *bus, unsigned int devfn,
				    int where, int size, u32 value)
{
	return apple_apciec_config_access(bus, devfn, where, size, &value, true);
}

static struct pci_ops apple_apciec_ops = {
	.map_bus = apple_apciec_map_bus,
	.read = apple_apciec_config_read,
	.write = apple_apciec_config_write,
};

/* Allocation only. The commit path supplies the validated bus extent and
 * calls quarantined scan, never pci_host_probe() or endpoint driver binding.
 */
static int __maybe_unused apple_apciec_allocate_bridge(struct apple_apciec *pcie)
{
	pcie->bridge = pci_alloc_host_bridge(0);
	if (!pcie->bridge)
		return -ENOMEM;
	raw_spin_lock_init(&pcie->lock);
	pcie->bridge->dev.parent = pcie->dev;
	pcie->bridge->sysdata = pcie;
	pcie->bridge->ops = &apple_apciec_ops;
	return 0;
}

/* SID is allocated/validated by external DART integration before table enable.
 * Alias/skip records and revision-dependent capacity remain unresolved.
 */
static int __maybe_unused
apple_apciec_program_rid(struct apple_apciec *pcie, u32 index, u32 rid, u32 sid)
{
	u32 value;
	unsigned long flags;
	int ret = 0;

	raw_spin_lock_irqsave(&pcie->lock, flags);
	if (!pcie->power_ready || !pcie->iommu_ready) {
		ret = -EHOSTDOWN;
		goto out;
	}
	if (!index || index >= pcie->rid_entries || rid > U16_MAX ||
	    sid >= pcie->sid_count || sid > 63 || (rid && !sid)) {
		ret = -EINVAL;
		goto out;
	}
	value = rid ? APCIEC_RID_VALID | FIELD_PREP(APCIEC_RID_SID, sid) |
		FIELD_PREP(APCIEC_RID_RID, rid) : 0;
	writel(value, pcie->port + APCIEC_RID2SID + index * sizeof(u32));
out:
	raw_spin_unlock_irqrestore(&pcie->lock, flags);
	return ret;
}

/* Masking inherited MSI must work before domain creation or after teardown. */
static int __maybe_unused apple_apciec_mask_msi(struct apple_apciec *pcie)
{
	unsigned long flags;
	int ret = 0;

	raw_spin_lock_irqsave(&pcie->lock, flags);
	if (!pcie->power_ready)
		ret = -EHOSTDOWN;
	else
		writel(0, pcie->port + APCIEC_MSICFG);
	raw_spin_unlock_irqrestore(&pcie->lock, flags);
	return ret;
}

/* Encoding confirmed in configMSIRange(); hierarchical AIC MSI domain setup
 * is a separate requirement and has not been implemented here.
 */
static int __maybe_unused apple_apciec_program_msi(struct apple_apciec *pcie)
{
	u32 count;
	unsigned long flags;
	int ret = 0;

	raw_spin_lock_irqsave(&pcie->lock, flags);
	count = pcie->msi_count;
	if (!pcie->power_ready || !pcie->msi_domain_ready) {
		ret = -EHOSTDOWN;
		goto out;
	}
	if (!is_power_of_2(count) || count > 32 ||
	    pcie->msi_base > U16_MAX || (pcie->msi_address & 15)) {
		ret = -EINVAL;
		goto out;
	}
	writel((ilog2(count) << 4) | 1, pcie->port + APCIEC_MSICFG);
	writel((pcie->msi_base & 0xffff) | ((pcie->msi_base & 31) << 16),
	       pcie->port + APCIEC_MSIBASE);
	writel(pcie->msi_address, pcie->port + APCIEC_MSIADDR);
out:
	raw_spin_unlock_irqrestore(&pcie->lock, flags);
	return ret;
}

static bool retain_prepare;
static bool retain_commit;
#include "enumeration-core.inc"
#include "port-sequence.inc"
/* Mutually exclusive prefix capabilities; neither may inherit the other. */
static bool retained_prefix_capability_valid(struct apple_apciec *p)
{
 if (p->retained_availability_probe ||
     p->retained_provider_prepare == p->retained_raw_identity)
  return false;
 return p->retained_provider_prepare ? apple_apciec_availability_probe_enabled() :
  apple_apciec_raw_identity_enabled() && p->retained_identity_deadline &&
  ktime_get_boottime_ns() < p->retained_identity_deadline;
}
#include "dart-owner.inc"
#include "pre-dart.inc"
#include "lifecycle.inc"
#include "availability-probe.inc"
#include "retained-commit.inc"
#include "endpoint-resource.inc"
#include "pair-resources.inc"
#include "pci-discovery.inc"
#include "mmio-probe.inc"
#include "native-msi.inc"
#include "native-host.inc"
#include "multi-enumeration.inc"
#include "multi-resources.inc"
#include "multi-native.inc"
#include "target-native.inc"
#include "pair-native.inc"
bool apple_apciec_endpoint_pair_enabled(void)
{ return endpoint_pair && pn_boot_valid(UTS_RELEASE,saved_command_line); }
EXPORT_SYMBOL_GPL(apple_apciec_endpoint_pair_enabled);
bool apple_apciec_endpoint_native_enabled(void)
{
 return endpoint_native_driver;
}
EXPORT_SYMBOL_GPL(apple_apciec_endpoint_native_enabled);

/* Default off, read-only after boot. Requires explicit research DT + NHI glue. */
module_param(retain_prepare, bool, 0444);
MODULE_PARM_DESC(retain_prepare, "Allow unwired one-way preparation entry; never commit or release");
module_param(retain_commit, bool, 0444);
MODULE_PARM_DESC(retain_commit,"Retained ticket-only PCI configuration discovery, no binding or DMA permission");

static bool enum_only;
module_param(enum_only, bool, 0444);
MODULE_PARM_DESC(enum_only, "Enable isolated enumeration-only research component");

/* Called by exact marked child under its driver-core device lock. The host
 * closes this window while holding that same lock after create/probe returns. */
bool apple_apciec_retained_dart_probe_allowed(struct device *dev)
{
 struct apple_apciec *pcie;
 struct device_driver *driver;
 if (!dev)
  return false;
 driver = READ_ONCE(dev->driver);
 if (!driver || strcmp(driver->name,
                                  "apple-apciec-research-disabled"))
  return false;
 pcie = dev_get_drvdata(dev);
 return pcie && !READ_ONCE(pcie->retained_availability_probe) &&
        (!(READ_ONCE(pcie->retained_provider_prepare) || READ_ONCE(pcie->retained_raw_identity)) ||
         (retained_prefix_capability_valid(pcie) &&
          READ_ONCE(pcie->retained_prefix_attempted) &&
          READ_ONCE(pcie->retained_prefix_ready))) &&
        smp_load_acquire(&pcie->retained_dart_window) &&
        READ_ONCE(pcie->retained_phase) == 3 &&
        READ_ONCE(pcie->power_ready) && !READ_ONCE(pcie->retained_failed);
}
EXPORT_SYMBOL_GPL(apple_apciec_retained_dart_probe_allowed);

int apple_apciec_retained_dart_params_gate_required(struct device *dev)
{
 struct apple_apciec *pcie;
 if (!apple_apciec_retained_dart_probe_allowed(dev))
  return -EPERM;
 pcie = dev_get_drvdata(dev);
 if (READ_ONCE(pcie->retained_provider_prepare) || READ_ONCE(pcie->retained_raw_identity))
  return 1;
 /* Inconsistent capability must not bypass the driver's raw-parameter gate. */
 if (READ_ONCE(pcie->retained_prefix_attempted) ||
     READ_ONCE(pcie->retained_prefix_ready) ||
     READ_ONCE(pcie->retained_sample_attempted) ||
     READ_ONCE(pcie->retained_sample_regs))
  return -EPERM;
 return 0;
}
EXPORT_SYMBOL_GPL(apple_apciec_retained_dart_params_gate_required);

/* Read-only actual policy, never a hardware-ready or identity assertion. */
bool apple_apciec_retained_enabled(void)
{
 return enum_only && retain_prepare;
}
EXPORT_SYMBOL_GPL(apple_apciec_retained_enabled);
bool apple_apciec_availability_probe_enabled(void)
{
 return enum_only && retain_prepare && !retain_commit;
}
EXPORT_SYMBOL_GPL(apple_apciec_availability_probe_enabled);
bool apple_apciec_raw_identity_enabled(void)
{
 return enum_only && retain_prepare && retain_commit;
}
EXPORT_SYMBOL_GPL(apple_apciec_raw_identity_enabled);
bool apple_apciec_endpoint_resources_enabled(void)
{
 return endpoint_resources;
}
EXPORT_SYMBOL_GPL(apple_apciec_endpoint_resources_enabled);
bool apple_apciec_endpoint_mmio_enabled(void)
{
 return endpoint_mmio_probe && endpoint_pci_register;
}
EXPORT_SYMBOL_GPL(apple_apciec_endpoint_mmio_enabled);
bool apple_apciec_endpoint_pci_enabled(void)
{
 return endpoint_pci_register;
}
EXPORT_SYMBOL_GPL(apple_apciec_endpoint_pci_enabled);

bool apple_apciec_endpoint_memory_assign_enabled(void)
{
 return endpoint_memory_assign;
}
EXPORT_SYMBOL_GPL(apple_apciec_endpoint_memory_assign_enabled);

static int apple_apciec_probe(struct platform_device *pdev)
{
	struct apple_apciec *pcie;
	struct resource *res;
	u32 bus[2], entries;
	int ret;

	if (!enum_only || !of_machine_is_compatible("apple,j293"))
		return -EPERM;
	if (of_property_read_u32_array(pdev->dev.of_node, "bus-range", bus, 2) ||
	    bus[0] > bus[1] || bus[1] > 255 ||
	    of_property_read_u32(pdev->dev.of_node, "research,rid-entries", &entries) ||
	    (entries != 16 && entries != 64))
		return -EINVAL;
	pcie = kzalloc(sizeof(*pcie), GFP_KERNEL);
	if (!pcie)
		return -ENOMEM;
	pcie->profile = apciec_profile_node(pdev->dev.of_node);
	if (!pcie->profile) { kfree(pcie); return -EPERM; }
	pcie->dev = get_device(&pdev->dev);
	pcie->bus_start = bus[0];
	pcie->bus_end = bus[1];
	pcie->rid_entries = entries;
	mutex_init(&pcie->lifecycle);
	raw_spin_lock_init(&pcie->lock);
	res = platform_get_resource(pdev, IORESOURCE_MEM, APCIEC_ECAM);
	if (!res || !(res->flags & IORESOURCE_MEM_NONPOSTED) ||
	    res->start != pcie->profile->ecam ||
	    resource_size(res) != 0x10000000 ||
	    resource_size(res) < (((u64)bus[1] + 1) << 20)) {
		ret = -EINVAL;
		goto free_context;
	}
	pcie->ecam_resource = *res;
	pcie->ecam_size = resource_size(res);
	if (!request_mem_region(res->start, resource_size(res), dev_name(pcie->dev))) {
		ret = -EBUSY;
		goto free_context;
	}
	/* Honour this J293 resource's required non-posted MMIO policy.
	 * Keep explicit ownership: retained hardware cannot use devm teardown. */
	pcie->ecam = ioremap_np(res->start, resource_size(res));
	if (!pcie->ecam) {
		ret = -ENOMEM;
		goto release_ecam;
	}
	res = platform_get_resource(pdev, IORESOURCE_MEM, APCIEC_PORT);
	if (!res || !(res->flags & IORESOURCE_MEM_NONPOSTED) ||
	    res->start != pcie->profile->port || resource_size(res) != 0x8000) {
		ret = -EINVAL;
		goto unmap_ecam;
	}
	pcie->port_resource = *res;
	if (!request_mem_region(res->start, resource_size(res), dev_name(pcie->dev))) {
		ret = -EBUSY;
		goto unmap_ecam;
	}
	pcie->port = ioremap_np(res->start, resource_size(res));
	if (!pcie->port) {
		ret = -ENOMEM;
		goto release_port;
	}
	if (retain_prepare) {
		ret = apple_apciec_predart_load(pdev, pcie);
		if (ret) {
			iounmap(pcie->port);
			goto release_port;
		}
	}
	/* No MMIO until supplier get plus post-both-adapters callback. Explicit
	 * ownership survives unsafe parent removal, unlike devm allocations.
	 */
	platform_set_drvdata(pdev, pcie);
	return 0;
 release_port:
	release_mem_region(pcie->port_resource.start, resource_size(&pcie->port_resource));
 unmap_ecam:
	iounmap(pcie->ecam);
 release_ecam:
	release_mem_region(pcie->ecam_resource.start, resource_size(&pcie->ecam_resource));
 free_context:
	put_device(pcie->dev);
	kfree(pcie);
	return ret;
}

int apple_apciec_controller_index(struct device *dev)
{
 struct apple_apciec *p = dev_get_drvdata(dev);
 return p && p->profile ? p->profile->index : -ENODEV;
}
EXPORT_SYMBOL_GPL(apple_apciec_controller_index);

static void apple_apciec_remove(struct platform_device *pdev)
{
	struct apple_apciec *pcie = platform_get_drvdata(pdev);

	mutex_lock(&pcie->lifecycle);
	/* Provider owner must pre-quiesce before attempting removal. Never call
	 * an uncertain supplier pointer from an unexpected parent detach.
	 */
	if (pcie->power_ready || pcie->supplier || pcie->retained) {
		apple_apciec_close_config(pcie);
		pcie->retained = true;
		dev_err(pcie->dev, "Unsafe removal: preserving controller allocations and mappings\n");
		mutex_unlock(&pcie->lifecycle);
		return;
	}
	platform_set_drvdata(pdev, NULL);
	mutex_unlock(&pcie->lifecycle);
	apple_apciec_predart_free(pcie);
	iounmap(pcie->port);
	iounmap(pcie->ecam);
	release_mem_region(pcie->port_resource.start, resource_size(&pcie->port_resource));
	release_mem_region(pcie->ecam_resource.start, resource_size(&pcie->ecam_resource));
	put_device(pcie->dev);
	kfree(pcie);
}

/* Deliberately not matched to a production compatible. DT research nodes are
 * disabled and only describe DART resources, so this cannot bind accidentally.
 */
static const struct of_device_id apple_apciec_match[] = {
	{ .compatible = "research-only,apple-t8103-apciec-disabled" },
	{ }
};
MODULE_DEVICE_TABLE(of, apple_apciec_match);
static struct platform_driver apple_apciec_driver = {
	.probe = apple_apciec_probe,
	.remove = apple_apciec_remove,
	.driver = {
		.name = "apple-apciec-research-disabled",
		.of_match_table = apple_apciec_match,
		.suppress_bind_attrs = true,
	},
};
builtin_platform_driver(apple_apciec_driver);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("J293 enumeration-only research component; requires reviewed NHI supplier glue");
