/* SPDX-License-Identifier: GPL-2.0 */
#include "j314s-multi-assignment.h"
struct jma_kernel_owner {
 struct j314s_multi_resource_owner *capture;
 struct jma_input input;
 struct jma_plan plan;
 struct resource resources[2];struct resource_entry *entries[2];
 struct list_head private_windows;
 const void *ticket;struct task_struct *task;
 u64 deadline,completed_ns;
 unsigned execution;
 bool attempted,active,armed,reserved[2],ready,complete,failed;
 int status;
};
