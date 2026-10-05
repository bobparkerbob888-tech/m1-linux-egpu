#include "j314s-assignment-plan-types.h"
/* Included after endpoint-resource-types.h and j314s-assignment-plan.h. */
struct j314s_assignment_owner {
 const void *ticket;struct task_struct *task;
 struct ja_plan plan;
 struct resource resources[3];struct resource_entry *entries[3];
 struct list_head private_windows;bool reserved[3];
 unsigned execution;int status;
 bool attempted,ready,active,armed,complete,failed;
 u64 deadline,completed_ns;
};
