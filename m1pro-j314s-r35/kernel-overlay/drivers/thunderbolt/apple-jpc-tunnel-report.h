#ifndef APPLE_JPC_TUNNEL_REPORT_H
#define APPLE_JPC_TUNNEL_REPORT_H
#include <linux/types.h>
#define APPLE_JPC_TUNNEL_PATHS 5
struct apple_jpc_tunnel_hop {
 __u32 side,port,id,out,next,before[2],desired[2];
};
struct apple_jpc_tunnel_path {
 __u64 uid[2];
 __u64 route[2];
 __u32 header[2][5],lane[2],adapter[2],pcie[2];
 __u32 credits[2],existing[2],control[2],pe,phase,programmed,operations;
 __s32 status;
 struct apple_jpc_tunnel_hop hops[4];
};
struct apple_jpc_tunnel_report {
 __u32 version,count,audits,read_operations;
 __s32 status;
 __u32 reserved;
 __u64 original_deadline,sealed_ns,last_verified_ns;
 struct apple_jpc_tunnel_path paths[APPLE_JPC_TUNNEL_PATHS];
};
/* flags15: sealed + immutable owner + all paths complete + latest live proof
 * succeeded before original deadline. Historical evidence, not action rights. */
int jpc_apple_cio_j314s_tunnel_state(unsigned,__u32*,int*,struct apple_jpc_tunnel_report*);
int jpc_apple_cio_j314s_tunnel_proof_locked(void*,const void*,__u64);
int jpc_apple_cio_j314s_chain_owner_validate(void*,const void*,unsigned,__u64,unsigned);
int jpc_apple_cio_j314s_chain_proof_after(void*,const void*,unsigned,__u64,unsigned,__u64);
#endif
