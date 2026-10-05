/* SPDX-License-Identifier: GPL-2.0 */
#ifndef APPLE_JMX_NATIVE_REPORT_H
#define APPLE_JMX_NATIVE_REPORT_H
#include <linux/apple-j314s-multi-report.h>
/* Historical typed-controller report. ABI of existing C0 report unchanged. */
struct apple_jmx_native_report {
 u32 version,controller,count,phase,raw_count,path_count,operations,rid2sid[64],model[5];
 u64 completed_ns,prepared_ns,original_deadline,assignment_ns;
 struct apple_j314s_multi_client_report client[5];
};
int apple_apciec_jmx_native_state(struct device*,u32*,int*,struct apple_jmx_native_report*);
/* Future ACIO wrapper must bind actual indexed private host. No caller here. */
int apple_cio_jmx_native_state(unsigned,u32*,int*,struct apple_jmx_native_report*);
#endif
