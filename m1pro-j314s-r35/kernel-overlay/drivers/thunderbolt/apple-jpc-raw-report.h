#ifndef APPLE_JPC_RAW_REPORT_H
#define APPLE_JPC_RAW_REPORT_H
#include <linux/types.h>
#include <linux/apple-dart-j314s-sample.h>
struct apple_jpc_raw_record {u32 rid,id,class_rev,subsystem,header;u64 serial;};
struct apple_jpc_raw_report {
 u32 version,controller,count,router_count,root_uid[2];
 u64 original_deadline,completed_ns;
 struct apple_dart_j314s_sample sample;
 struct apple_jpc_raw_record records[64];
};
int apple_cio_jpc_raw_report(unsigned,u32*,int*,struct apple_jpc_raw_report*);
#endif
