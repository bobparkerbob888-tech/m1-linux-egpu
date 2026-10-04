/* Pure encoding using PCI_MEMORY_BASE/PREF_MEMORY_BASE/UPPER32 and BAR layouts.
 * No callbacks, MMIO, resources, PCI objects or deadline changes.
 * Input must be a fresh immutable successful resource snapshot; this validates its
 * exact branch, sizes/placements/windows again before producing any plan. */
#ifndef APCIEC_ASSIGNMENT_PLAN_CORE_H
#define APCIEC_ASSIGNMENT_PLAN_CORE_H
#include "endpoint-resource-types.h"
#include "endpoint-admission.h"
#include "assignment-plan-types.h"
static int as_sample(const struct ep_function *f, unsigned offset, u32 *value)
{
 unsigned j, found = 0;
 if (f->sample_count > EP_MAX_SAMPLES) return -EINVAL;
 for (j = 0; j < f->sample_count; j++) if (f->samples[j].offset == offset) {
  *value = f->samples[j].value; found++;
 }
 return found == 1 ? 0 : -EINVAL;
}
static int as_add_register(struct as_plan *p, unsigned rid, unsigned off,
                           u32 before, u32 after, bool write_permitted, unsigned *index)
{
 unsigned j;
 if (p->count >= AS_MAX_REGS || (off & 3)) return -E2BIG;
 for (j = 0; j < p->count; j++) if (p->regs[j].rid == rid && p->regs[j].offset == off) return -EINVAL;
 *index = p->count;
 p->regs[p->count++] = (struct as_register){rid, off, before, after, write_permitted};
 return 0;
}
static int as_add_step(struct as_plan *p, unsigned reg, u32 value)
{
 unsigned j; u32 before;
 if (reg >= p->count) return -EINVAL;
 before = p->regs[reg].before;
 if (!p->regs[reg].write_permitted) return value == before ? 0 : -EPERM;
 for (j = 0; j < p->step_count; j++) if (p->steps[j].reg == reg) before = p->steps[j].value;
 if (before == value) return 0; /* Final register audit still includes this row. */
 if (p->step_count >= AS_MAX_STEPS) return -E2BIG;
 p->steps[p->step_count++] = (struct as_step){reg, before, value};
 return 0;
}
static int as_snapshot_gate(const struct ep_snapshot *s)
{
 struct ep_identity ids[8]; unsigned j;
 if (!s || !s->captured || !s->sized || !s->planned || s->count != 8 ||
     s->selected >= s->count || s->ancestor_count != 3 || s->same_device_mask != 3)
  return -EPERM;
 for (j = 0; j < 8; j++) {
  if (s->functions[j].command || s->functions[j].sample_count > EP_MAX_SAMPLES) return -EPERM;
  ids[j] = s->functions[j].identity;
  {
   const struct ep_function *f = &s->functions[j]; u32 value;
   if (as_sample(f, 0, &value) || value != f->identity.id ||
       as_sample(f, 4, &value) || (value & 65535) ||
       as_sample(f, 8, &value) || value != f->identity.class_rev ||
       as_sample(f, 12, &value) || ((value >> 16) & 255) != f->identity.header)
    return -EPERM;
  }
 }
 if (endpoint_admit_records(ids, 8) ||
     !endpoint_identity_equal(&s->functions[s->selected].identity, &endpoint_allowed)) return -EPERM;
 {
  const struct ep_function *f = &s->functions[s->selected]; u32 lo, hi;
  if (!f->serial_present || f->serial_offset < 0x100 || f->serial_offset > 0xff4 ||
      (f->serial_offset & 3) || as_sample(f, 0x2c, &lo) || lo != f->identity.subsystem ||
      as_sample(f, f->serial_offset + 4, &lo) || as_sample(f, f->serial_offset + 8, &hi) ||
      (((u64)hi << 32) | lo) != f->identity.serial) return -EPERM;
 }
 for (j = 0; j < 3; j++) {
  unsigned index = s->ancestors[j], rid = (2 - j) << 8;
  const struct ep_function *f;
  if (index >= 8) return -EINVAL;
  f = &s->functions[index];
  {u32 raw_buses; if (as_sample(f, 0x18, &raw_buses) || raw_buses != f->buses) return -EPERM;}
  if (f->identity.rid != rid || s->bridges[j].rid != rid ||
      (f->identity.header & 127) != 1 || (f->buses & 255) != (rid >> 8) ||
      ((f->buses >> 8) & 255) != 3 - j || ((f->buses >> 16) & 255) < 3)
   return -EPERM;
 }
 return 0;
}
static int as_plan_build(const struct ep_snapshot *s, const struct as_aperture *apertures,
                         const struct as_observation *observation, struct as_plan *p)
{
 const u64 base[3] = {0x400000000ULL, 0x80000000ULL, 0xc0000000ULL};
 const u64 size[3] = {0x80000000ULL, 0x40000000ULL, 0x40000000ULL};
 const u64 delta[3] = {0, 0x400000000ULL, 0x400000000ULL};
 u64 end[3] = {0}; unsigned j, k, index, bar_regs[6]; int ret;
 if (!p || p->built || p->count || p->step_count) return -EPERM;
 ret = as_apertures_gate(apertures); if (ret) return ret;
 if (!observation) return -EINVAL;
 ret = as_budget_check(&observation->observed, observation, 2000000000ULL, 2048); if (ret) return ret;
 ret = as_snapshot_gate(s); if (ret) return ret;
 /* R34 memory-only snapshot requires a distinct, proven present I/O BAR5.
  * It is an observation only, never writable, assignable or sized. */
 {
  const struct ep_bar *io = &s->bars[5];
  if (!io->unsupported_io || io->upper || io->flags != EP_BAR_IO_UNASSIGNED ||
      io->window != EP_BAR_NO_WINDOW || io->saved[0] != 1 || io->saved[1] ||
      io->mask[0] || io->mask[1] || io->size || io->pci || io->cpu)
   return -EPERM;
  if (s->functions[s->selected].msix) {
   unsigned table = s->functions[s->selected].msix_table & 7;
   unsigned pba = s->functions[s->selected].msix_pba & 7;
   if (table >= 6 || pba >= 6 || s->bars[table].unsupported_io ||
       s->bars[pba].unsupported_io) return -EPERM;
  }
 }
 for (j = 0; j < 3; j++) p->apertures[j] = apertures[j];
 p->budget = observation->observed;
 p->selected = s->functions[s->selected].identity;
 for (j = 0; j < 6; j++) {
  const struct ep_bar *b = &s->bars[j]; unsigned flags, window;
  u64 mask, measured; bool wide;
  if (b->unsupported_io || (b->flags & EP_BAR_IO_UNASSIGNED)) {
   if (j != 5) return -EPERM;
   continue; /* Complete BAR5 state was validated above. */
  }
  if (b->upper) {
   if (!j || !(s->bars[j - 1].flags & EP_BAR_64) || s->bars[j - 1].upper ||
       b->size || b->pci || b->cpu) return -EINVAL;
   continue;
  }
  wide = (b->saved[0] & 6) == 4;
  if ((b->saved[0] & 1) || ((b->saved[0] & 6) && !wide) || (wide && j == 5)) return -EINVAL;
  flags = (wide ? EP_BAR_64 : 0) | ((b->saved[0] & 8) ? EP_BAR_PREF : 0);
  if (b->flags != flags || (b->mask[0] && (b->mask[0] & 15) != (b->saved[0] & 15))) return -EINVAL;
  if (wide && (!s->bars[j + 1].upper || b->saved[1] != s->bars[j + 1].saved[0])) return -EINVAL;
  if (!wide && (b->saved[1] || b->mask[1])) return -EINVAL;
  mask = ((u64)b->mask[1] << 32) | (b->mask[0] & ~15U);
  if (!wide) mask |= 0xffffffff00000000ULL;
  measured = ~mask + 1;
  if (!(b->mask[0] & ~15U) && !b->mask[1]) {
   if (b->saved[0] || wide || b->size || b->pci || b->cpu) return -EINVAL;
   continue;
  }
  if (!measured || (measured & (measured - 1)) || measured < 16 || measured != b->size) return -EINVAL;
  window = (flags & EP_BAR_PREF) ? ((flags & EP_BAR_64) ? 0 : 2) : 1;
  if (b->window != window || measured > size[window] || b->pci < base[window] ||
      b->pci - base[window] > size[window] - measured || (b->pci & (measured - 1)) ||
      b->cpu != b->pci + delta[window]) return -EINVAL;
  for (k = 0; k < j; k++) {
   const struct ep_bar *a = &s->bars[k];
   if (!a->upper && a->size && a->window == window &&
       b->pci < a->pci + a->size && a->pci < b->pci + b->size) return -EINVAL;
  }
  if (b->pci + b->size - 1 > end[window]) end[window] = b->pci + b->size - 1;
 }
 if (end[0] && end[2]) return -EOPNOTSUPP;
 for (j = 0; j < 3; j++) if (end[j]) end[j] |= 0xfffffULL;
 for (j = 0; j < 3; j++) for (k = 0; k < 3; k++) {
  const struct ep_bridge_plan *b = &s->bridges[j];
  if (b->active[k] != !!end[k] ||
      (end[k] && (b->start[k] != base[k] || b->end[k] != end[k])) ||
      (!end[k] && (b->start[k] || b->end[k]))) return -EINVAL;
 }
 /* Preserve every BAR preimage, including unimplemented/upper slots. */
 for (j = 0; j < 6; j++) {
  const struct ep_bar *b = &s->bars[j]; u32 after = b->saved[0], sample;
  if (as_sample(&s->functions[s->selected], 0x10 + 4*j, &sample) || sample != b->saved[0]) return -EINVAL;
  if (b->upper) after = s->bars[j - 1].pci >> 32;
  else if (b->size) after = (u32)b->pci | (b->saved[0] & 15);
  ret = as_add_register(p, p->selected.rid, 0x10 + 4*j, sample, after, !b->unsupported_io, &bar_regs[j]); if (ret) return ret;
 }
 for (j = 0; j < 6; j++) {
  ret = as_add_step(p, bar_regs[j], p->regs[bar_regs[j]].after); if (ret) return ret;
 }
 /* Closest ancestor through root. Commands remain0 throughout any execution. */
 for (j = 0; j < 3; j++) {
  const struct ep_function *f = &s->functions[s->ancestors[j]];
  u32 old[4], value[4], types; unsigned regs[4], pref = end[0] ? 0 : 2;
  for (k = 0; k < 4; k++) if (as_sample(f, 0x20 + 4*k, &old[k])) return -EINVAL;
  if (old[0] & 0x000f000f) return -EOPNOTSUPP;
  types = old[1] & 0x000f000f;
  if (types != 0 && types != 0x00010001) return -EOPNOTSUPP;
  if (end[0] && types != 0x00010001) return -EOPNOTSUPP;
  if (!types && (old[2] || old[3])) return -EINVAL;
  value[0] = end[1] ? ((base[1] >> 16) & 0xfff0) | (end[1] & 0xfff00000) : 0x0000fff0;
  value[1] = (end[pref] ? ((base[pref] >> 16) & 0xfff0) | (end[pref] & 0xfff00000) : 0x0000fff0) | types;
  value[2] = end[pref] ? base[pref] >> 32 : 0;
  value[3] = end[pref] ? end[pref] >> 32 : 0;
  for (k = 0; k < 4; k++) {
   ret = as_add_register(p, f->identity.rid, 0x20 + 4*k, old[k], value[k], true, &regs[k]); if (ret) return ret;
  }
  ret = as_add_step(p, regs[0], value[0]); if (ret) return ret;
  /* Same upper-limit-first convention as pci_setup_bridge_mmio_pref. */
  if (types) { ret = as_add_step(p, regs[3], 0); if (ret) return ret; }
  ret = as_add_step(p, regs[1], value[1]); if (ret) return ret;
  if (types) {
   ret = as_add_step(p, regs[2], value[2]); if (ret) return ret;
   ret = as_add_step(p, regs[3], value[3]); if (ret) return ret;
  }
 }
 /* Every step is tied to one saved register; every final value is reachable. */
 for (j = 0; j < p->count; j++) {
  u32 last = p->regs[j].before;
  for (k = 0; k < p->step_count; k++) if (p->steps[k].reg == j) last = p->steps[k].value;
  if (last != p->regs[j].after) return -EINVAL;
 }
 index = p->count; if (index != 18) return -EINVAL;
 p->built = true; return 0;
}
#endif
