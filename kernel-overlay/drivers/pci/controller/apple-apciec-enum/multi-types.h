/* SPDX-License-Identifier: GPL-2.0 */
#ifndef APPLE_APCIEC_MULTI_TYPES_H
#define APPLE_APCIEC_MULTI_TYPES_H
#include "chain-pci-plan.h"
struct apciec_multi {
 struct apple_apciec *host;
 struct task_struct *task;
 u64 deadline;
 unsigned phase, ops, count;
 bool failed, ready, attempted, armed;
 unsigned write_rid, write_off, write_width;
 u32 write_value;
 struct pd_probe probe;
 struct pci_bus *buses[10];
 struct pci_dev *devices[AM_FUNCTIONS];
 struct ep_function functions[AM_FUNCTIONS];
 struct apciec_native clients[2];
 struct of_changeset firmware;
};
#endif
