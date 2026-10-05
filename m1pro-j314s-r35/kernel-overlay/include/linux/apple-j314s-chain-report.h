/* SPDX-License-Identifier: GPL-2.0 */
#ifndef APPLE_J314S_CHAIN_REPORT_H
#define APPLE_J314S_CHAIN_REPORT_H
#include <linux/types.h>
struct apple_j314s_chain_report {
 u32 parent_route,route,primary,peer,pcie_down,pcie_up,header[5];
 u32 ports[24][8],read_mask,drom_size,operations;
 u64 parent_uid,uid,completed_ns,original_deadline;
 u8 drom[1036];
};
int apple_cio_j314s_chain_state(unsigned controller,u32 *flags,int *status,
 struct apple_j314s_chain_report *report);
#define APPLE_J314S_CHAIN_MAX_EDGES 3
struct apple_j314s_chain_list_report {
 u32 count,terminal,operations;
 u64 completed_ns,original_deadline;
 struct apple_j314s_chain_report edges[APPLE_J314S_CHAIN_MAX_EDGES];
 struct apple_j314s_chain_report tail;
 u32 tail_phy[24],tail_phy_mask;
};
int apple_cio_j314s_chain_list_state(unsigned controller,u32 *flags,int *status,
 struct apple_j314s_chain_list_report *report);
#endif
