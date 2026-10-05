#ifndef APPLE_JPC_NATIVE_POLICY_H
#define APPLE_JPC_NATIVE_POLICY_H
#include <linux/types.h>
#define APPLE_JPC_NATIVE_MAX 5
struct apple_jpc_native_identity {
 u32 rid,id,class_rev,subsystem,header,model;
 u64 serial;
};
/* Root-bound measured manifest is copied before cold provider/raw work.
 * Each field is matched AGAIN to the new same-boot raw/tunnel receipts.
 * Zero desktop_review_mask never admits a desktop5080. No automatic model
 * selection from marketing names or UUID/DSN fabrication. */
struct apple_jpc_native_policy {
 u32 version,controller,count,desktop_review_mask;
 u32 root_uid[2],router_count,reserved;
 u64 route[5],router_uid[5];
 struct apple_jpc_native_identity clients[APPLE_JPC_NATIVE_MAX];
 u8 evidence_sha256[32];
};
int apple_cio_jpc_prepare_native_once(unsigned,const struct apple_jpc_native_policy*);
struct apple_jmx_native_report;
int apple_cio_jpc_native_state(unsigned,u32*,int*,struct apple_jmx_native_report*);
#endif
