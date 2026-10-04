/* Private plan only: no PCI publication or DMA authority. */
#ifndef APCIEC_ASSIGNMENT_PLAN_TYPES_H
#define APCIEC_ASSIGNMENT_PLAN_TYPES_H
#include "assignment-budget.h"
#define AS_MAX_REGS 18
#define AS_MAX_STEPS 21
struct as_register {unsigned rid, offset; u32 before, after; bool write_permitted;};
struct as_step {unsigned reg; u32 before, value;};
struct as_plan {
 struct ep_identity selected;
 struct as_aperture apertures[3];
 struct as_budget budget;
 struct as_register regs[AS_MAX_REGS]; unsigned count;
 struct as_step steps[AS_MAX_STEPS]; unsigned step_count;
 bool built;
};
#endif
