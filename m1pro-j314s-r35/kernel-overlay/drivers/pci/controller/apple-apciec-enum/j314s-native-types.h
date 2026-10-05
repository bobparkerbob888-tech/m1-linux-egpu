/* SPDX-License-Identifier: GPL-2.0 */
#include "j314s-native-layout.h"
struct apple_apciec;
struct j314s_native_context {
 struct j314s_native_layout layout;
 struct pci_dev *devices[J314S_NATIVE_PATH_MAX];
 struct pci_bus *buses[256];
 struct resource bus_resource;
 struct task_struct *task;
 const void *ticket;
 u64 deadline,completed_ns;
 unsigned ops,mmio_next,mmio_enabled;
 bool status_armed,status_pending;
 unsigned status_rid,status_off,status_slot;
 u32 status_before,status_value,status_consumed;
 bool attempted,failed,discovered,mmio_attempted,mmio_complete;
 bool command_armed,command_pending,cpu_mapping_permitted,sealed,published;
 struct pd_probe probe;
 void __iomem *bar0;
 u32 boot0[2];
 int status;
};
static bool j314s_native_target_identity(struct apple_apciec *p);
static const struct ep_function *j314s_native_function(struct apple_apciec *p,unsigned rid);
static struct pci_dev *j314s_native_selected(struct apple_apciec *p);
static struct pci_host_bridge *j314s_native_bridge(struct apple_apciec *p);
static int j314s_native_config_locked(struct pci_bus *,unsigned,int,int,u32 *,bool);

static bool j314s_native_map_permit(struct apple_apciec*,unsigned);
