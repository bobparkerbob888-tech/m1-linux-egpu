#include "j314s-multi-admission.h"
/* SPDX-License-Identifier: GPL-2.0 */
/* Retained globally before the first BAR sizing operation. */
struct j314s_multi_resource_owner {
 const void *ticket;
 struct task_struct *task;
 struct j314s_resource_owner *owners[JM_MAX_GPUS];
 struct ep_snapshot *snapshots[JM_MAX_GPUS];
 struct ep_identity selected[JM_MAX_GPUS];
 unsigned count,active_index;
 u64 deadline,completed_ns;
 bool attempted,active,failed,complete;
 int status;
};
