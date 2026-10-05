/* SPDX-License-Identifier: GPL-2.0 */
#ifndef APPLE_J314S_NATIVE_REPORT_H
#define APPLE_J314S_NATIVE_REPORT_H
#include <linux/types.h>
struct apple_j314s_native_report {
 u32 rid,id,class_rev,subsystem,header,boot0[2],phase;
 u64 serial,completed_ns,deadline;
};
struct device;
int apple_apciec_j314s_native_state(struct device*,u32*,int*,struct apple_j314s_native_report*);
#endif
