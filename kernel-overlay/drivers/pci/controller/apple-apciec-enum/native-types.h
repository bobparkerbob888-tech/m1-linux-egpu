/* SPDX-License-Identifier: GPL-2.0 */
#ifndef APPLE_APCIEC_NATIVE_TYPES_H
#define APPLE_APCIEC_NATIVE_TYPES_H
struct apciec_native_msi;
struct apciec_native {
 struct pci_dev *target;
 struct apple_apciec *host;
 struct notifier_block probe_notifier;
 bool probe_begin_logged;
 struct of_changeset firmware;
 struct apciec_native_msi *msi;
 bool active, failed, dma_ready, rid_ready, irq_ready, enable_attempted;
 unsigned aliases, config_ops, write_logs;
 bool pbi_owned, status_logged;
 u32 pbi_input;
};
struct apciec_native_pair {
 struct apciec_native clients[2]; /* primary0600/SID1, secondary0300/SID2 */
 void __iomem *boot0_regs[2];
 bool boot0_attempted[2];
 u32 boot0[2][2];
};
#endif
