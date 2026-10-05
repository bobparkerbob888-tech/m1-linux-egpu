/* SPDX-License-Identifier: GPL-2.0 */
#ifndef APPLE_J314S_MULTI_REPORT_H
#define APPLE_J314S_MULTI_REPORT_H
#include <linux/types.h>
struct apple_j314s_multi_client_report {
 u32 rid,id,class_rev,subsystem,header,sid,group,boot0[2];u64 serial;
 struct {u64 start,end,flags;} bars[6];
};
struct apple_j314s_multi_report {
 u32 version,count,phase,raw_count,path_count,operations,rid2sid[64];
 u64 completed_ns,prepared_ns,original_deadline,assignment_ns;
 struct apple_j314s_multi_client_report client[4];
};
struct device;
int apple_apciec_j314s_multi_state(struct device*,u32*,int*,struct apple_j314s_multi_report*);
int apple_cio_j314s_multi_state(unsigned,u32*,int*,struct apple_j314s_multi_report*);
#endif
