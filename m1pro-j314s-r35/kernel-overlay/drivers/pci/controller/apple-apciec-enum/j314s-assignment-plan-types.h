#ifndef J314S_ASSIGNMENT_PLAN_TYPES_H
#define J314S_ASSIGNMENT_PLAN_TYPES_H
#define JA_MAX_REGS 38
#define JA_MAX_STEPS 46
struct ja_register {unsigned rid,offset;u32 before,after;bool writable;};
struct ja_step {unsigned reg;u32 before,value;};
struct ja_plan {
 struct ep_identity selected;
 struct ja_register regs[JA_MAX_REGS];
 struct ja_step steps[JA_MAX_STEPS];
 unsigned count,step_count;
 bool built;
};
#endif
