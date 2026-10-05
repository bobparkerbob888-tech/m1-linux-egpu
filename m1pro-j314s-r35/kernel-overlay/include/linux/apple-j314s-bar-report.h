/* SPDX-License-Identifier: GPL-2.0 */
#ifndef APPLE_J314S_BAR_REPORT_H
#define APPLE_J314S_BAR_REPORT_H
#include <linux/types.h>
#include <linux/apple-dart-j314s-sample.h>
struct apple_j314s_bar {
 u32 saved[2],mask[2];
 u64 size,pci,cpu;
 u32 flags,window,upper,unsupported_io;
};
struct apple_j314s_bridge_plan {
 u32 rid,active[3];u64 start[3],end[3];
};
struct apple_j314s_bar_report {
 u32 rid,id,class_rev,subsystem,header;
 u64 serial,completed_ns,deadline;
 u32 function_count,ancestor_count;
 struct apple_dart_j314s_sample dma_sample;
 struct apple_j314s_bar bars[6];
 struct apple_j314s_bridge_plan bridges[8];
};
struct device;
int apple_apciec_j314s_resource_state(struct device*,u32*,int*,struct apple_j314s_bar_report*);
int apple_cio_j314s_bar_state(unsigned,u32*,int*,struct apple_j314s_bar_report*);
#endif
