/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/apple-dart-j314s-sample.h>
struct j314s_resource_owner {
 const void *ticket;
 struct task_struct *task;
 struct ep_identity selected;
 struct apple_dart_j314s_sample dma_sample;
 bool attempted,active,failed,complete;
 bool rebar_attempted,rebar_armed,rebar_written,rebar_complete;
 unsigned rebar_offset;u32 rebar_before,rebar_after;
 struct ep_function *rebar_capture;
 u64 deadline,completed_ns;
 int status;
};
