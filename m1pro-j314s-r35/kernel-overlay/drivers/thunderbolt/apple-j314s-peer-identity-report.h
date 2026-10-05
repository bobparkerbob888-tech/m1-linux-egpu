#ifndef APPLE_J314S_PEER_IDENTITY_REPORT_H
#define APPLE_J314S_PEER_IDENTITY_REPORT_H
#include <linux/types.h>
struct j314s_peer_identity_report {
 u32 controller,cable,operations,route,lane,header[5],uid[2],root_uid[2];
 u64 completed_ns,deadline;
};
#endif
