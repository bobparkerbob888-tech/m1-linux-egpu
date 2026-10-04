/* SPDX-License-Identifier: GPL-2.0 */
/* Bounded configuration evidence and pure placement. Never assigns/enables. */
#ifndef APCIEC_ENDPOINT_RESOURCE_CORE_H
#define APCIEC_ENDPOINT_RESOURCE_CORE_H
#include "endpoint-resource-types.h"
struct ep_io {
 void *ctx;
 int (*read)(void *, unsigned, unsigned, u32 *);
 int (*write)(void *, unsigned, unsigned, u32);
 int (*safe)(void *, unsigned);
 int (*probe_ready)(void *); /* Explicit start of a BAR/pair, never a restore. */
 bool (*valid)(void *); u64 (*now)(void *);
 u64 deadline; unsigned ops, root_rid;
 const struct ep_identity *records, *selected; unsigned count, selected_serial_offset;
};
static int ep_gate(struct ep_io *i)
{
 if (!i->valid(i->ctx)) return -EPERM;
 return i->ops >= 32768 || i->now(i->ctx) >= i->deadline ? -ETIMEDOUT : 0;
}
static int ep_read(struct ep_io *i, unsigned rid, unsigned off, u32 *v)
{
 int r = ep_gate(i), after;
 if (r) return r;
 if (rid > 65535 || off > 4092 || (off & 3)) return -EINVAL;
 i->ops++; r = i->read(i->ctx, rid, off, v);
 after = ep_gate(i); return after ? after : r;
}
static int ep_sample_read(struct ep_io *i, struct ep_function *f, unsigned off, u32 *v)
{
 int r; unsigned j;
 if (off >= 0x40) for (j = 0; j < f->sample_count; j++)
  if (f->samples[j].offset == off) return -EINVAL;
 if (f->sample_count == EP_MAX_SAMPLES) return -E2BIG;
 r = ep_read(i, f->identity.rid, off, v); if (r) return r;
 f->samples[f->sample_count++] = (struct ep_sample){off, *v};
 return 0;
}
static int ep_selected_recheck(struct ep_io *i, unsigned rid)
{
 const struct ep_identity *id = i->selected; u32 v, lo; int r;
 if (!id || rid != id->rid) return -EPERM;
 r = ep_read(i, rid, 0, &v); if (r) return r; if (v != id->id) return -EPERM;
 r = ep_read(i, rid, 8, &v); if (r) return r; if (v != id->class_rev) return -EPERM;
 r = ep_read(i, rid, 12, &v); if (r) return r; if (((v >> 16) & 255) != id->header) return -EPERM;
 r = ep_read(i, rid, 0x2c, &v); if (r) return r; if (v != id->subsystem) return -EPERM;
 if (i->selected_serial_offset) {
  r = ep_read(i, rid, i->selected_serial_offset + 4, &lo); if (r) return r;
  r = ep_read(i, rid, i->selected_serial_offset + 8, &v); if (r) return r;
  if (((u64)v << 32 | lo) != id->serial) return -EPERM;
 } else if (id->serial) return -EPERM;
 return 0;
}
static int ep_write(struct ep_io *i, unsigned rid, unsigned off, u32 v)
{
 int r = ep_gate(i), after;
 if (r) return r;
 if (rid > 65535 || off < 0x10 || off > 0x24 || (off & 3)) return -EPERM;
 r = ep_selected_recheck(i, rid); if (r) return r;
 r = i->safe(i->ctx, rid); if (r) return r;
 r = ep_gate(i); if (r) return r;
 i->ops++; r = i->write(i->ctx, rid, off, v);
 after = ep_gate(i); return after ? after : r;
}
/* Ownership covers the entire known capability structure, including fields
 * not otherwise sampled. A linked header must not hide in an unsampled body. */
static int ep_cap_range(unsigned *starts, unsigned *lengths, unsigned count,
 unsigned off, unsigned length, unsigned limit)
{
 unsigned j;
 if (!length || length > limit || off > limit - length) return -EINVAL;
 for (j = 0; j < count; j++)
  if (off < starts[j] + lengths[j] && starts[j] < off + length) return -EINVAL;
 starts[count] = off; lengths[count] = length;
 return 0;
}
static bool ep_msix_overlap(const struct ep_function *f)
{
 u64 table = f->msix_table & ~7U, pba = f->msix_pba & ~7U;
 unsigned entries = (f->msix_control & 0x7ff) + 1;
 return f->msix && (f->msix_table & 7) == (f->msix_pba & 7) &&
        table < pba + ((entries + 63) / 64) * 8 && pba < table + (u64)entries * 16;
}
static int ep_caps(struct ep_io *i, struct ep_function *f, u32 status)
{
 unsigned seen[64], lengths[64], off, n = 0, j, k, length; u32 h, v; int r;
 if (status & (1U << 20)) {
  r = ep_sample_read(i, f, 0x34, &v); if (r) return r;
  off = v & 255;
  while (off) {
   if (off < 0x40 || off > 0xfc || (off & 3) || n == 48) return -EINVAL;
   for (j = 0; j < n; j++) if (seen[j] == off) return -ELOOP;
   for (j = 0; j < n; j++) if (off > seen[j] && off < seen[j] + lengths[j]) return -EINVAL;
   r = ep_sample_read(i, f, off, &h); if (r) return r;
   length = 4;
   switch (h & 255) {
   case 1:
    if (f->pm || off > 0xf8) return -EINVAL;
    length = 8;
    f->pm = off; r = ep_sample_read(i, f, off + 4, &f->pmcsr); if (r) return r;
    break;
   case 5:
    if (f->msi) return -EINVAL;
    f->msi = off; f->msi_control = h >> 16;
    length = (h & (1U << 23)) ? 16 : 12;
    if (h & (1U << 24)) length += 8;
    if (off + length > 256) return -EINVAL;
    for (k = 4; k < length; k += 4) { r = ep_sample_read(i, f, off + k, &v); if (r) return r; }
    break;
   case 0x11:
    if (f->msix || off > 0xf4) return -EINVAL;
    length = 12;
    f->msix = off; f->msix_control = h >> 16;
    r = ep_sample_read(i, f, off + 4, &f->msix_table); if (r) return r;
    r = ep_sample_read(i, f, off + 8, &f->msix_pba); if (r) return r;
    if ((f->msix_table & 7) > 5 || (f->msix_pba & 7) > 5) return -EINVAL;
    if (ep_msix_overlap(f)) return -EINVAL;
    break;
   case 0x10: {
    unsigned version = (h >> 16) & 15, type = (h >> 20) & 15;
    bool slot = !!(h & (1U << 24));
    if (f->pcie || !version || version > 2) return -EINVAL;
    switch (type) {
    case 0: case 1: case 5: case 7: case 8:
     if (slot) return -EINVAL;
     length = version == 1 ? 0x14 : 0x34; break;
    case 4: length = version == 1 ? 0x24 : (slot ? 0x3c : 0x34); break;
    case 6: length = version == 1 ? (slot ? 0x1c : 0x14) : (slot ? 0x3c : 0x34); break;
    case 9: if (slot) return -EINVAL; length = version == 1 ? 0x0c : 0x2c; break;
    case 10: if (slot) return -EINVAL; length = version == 1 ? 0x24 : 0x2c; break;
    default: return -EINVAL;
    }
    if (off + length > 256) return -EINVAL;
    f->pcie = off;
    r = ep_sample_read(i, f, off + 4, &f->devcap); if (r) return r;
    r = ep_sample_read(i, f, off + 8, &f->devctl); if (r) return r;
    f->flr_capable = !!(f->devcap & (1U << 28));
    if (version == 2) {
     r = ep_sample_read(i, f, off + 0x24, &f->devcap2); if (r) return r;
     r = ep_sample_read(i, f, off + 0x28, &f->devctl2); if (r) return r;
    }
    break;
   }
   case 9: /* Vendor-specific capability length includes its header. */
    length = (h >> 16) & 255;
    if (length < 3) return -EINVAL;
    break;
   default: break;
   }
   r = ep_cap_range(seen, lengths, n, off, length, 256); if (r) return r;
   n++;
   off = (h >> 8) & 255;
  }
 }
 n = 0; off = 0x100;
 while (off) {
  if (off < 0x100 || off > 0xffc || (off & 3) || n == 64) return -EINVAL;
  for (j = 0; j < n; j++) if (seen[j] == off) return -ELOOP;
  for (j = 0; j < n; j++) if (off > seen[j] && off < seen[j] + lengths[j]) return -EINVAL;
  r = ep_sample_read(i, f, off, &h); if (r) return r;
  if (!h || h == 0xffffffff) break;
  if (!((h >> 16) & 15) || !(h & 65535)) return -EINVAL;
  length = 4;
  switch (h & 65535) {
  case 3:
   if (f->serial_present || off > 0xff4) return -EINVAL;
   length = 12;
   f->serial_present = true; f->serial_offset = off;
   r = ep_sample_read(i, f, off + 4, &v); if (r) return r;
   f->identity.serial = v;
   r = ep_sample_read(i, f, off + 8, &v); if (r) return r;
   f->identity.serial |= (u64)v << 32;
   break;
  case 0xd:
   if (f->acs || off > 0xff8) return -EINVAL;
   f->acs = off; r = ep_sample_read(i, f, off + 4, &f->acs_bits); if (r) return r;
   length = 8;
   if (f->acs_bits & (1U << 5)) {
    unsigned bits = (f->acs_bits >> 8) & 255;
    if (!bits) bits = 256;
    length += ((bits + 31) / 32) * 4;
   }
   break;
  case 0xe: if (f->ari) return -EINVAL; f->ari = true; length = 8; break;
  case 0xf: if (f->ats) return -EINVAL; f->ats = true; length = 8; break;
  case 0x10: if (f->sriov) return -EINVAL; f->sriov = true; length = 0x40; break;
  case 0x1b: if (f->pasid) return -EINVAL; f->pasid = true; length = 8; break;
  case 0x15:
   if (f->rebar || off > 0xff4) return -EINVAL;
   f->rebar = off;
   r = ep_sample_read(i, f, off + 4, &v); if (r) return r;
   r = ep_sample_read(i, f, off + 8, &v); if (r) return r;
   length = (v >> 5) & 7;
   if (!length || length > 6 || off + 4 + length * 8 > 4096) return -EINVAL;
   for (k = 12; k < 4 + length * 8; k += 4) { r = ep_sample_read(i, f, off + k, &v); if (r) return r; }
   length = 4 + length * 8;
   break;
  default: break;
  }
  r = ep_cap_range(seen, lengths, n, off, length, 4096); if (r) return r;
  n++;
  off = h >> 20;
 }
 return 0;
}
static bool ep_identity_equal(const struct ep_identity *a, const struct ep_identity *b)
{
 return a->rid == b->rid && a->id == b->id && a->class_rev == b->class_rev &&
        a->subsystem == b->subsystem && a->serial == b->serial && a->header == b->header;
}
static int ep_function_read(struct ep_io *i, const struct ep_identity *id, struct ep_function *f)
{
 u32 v, status; int r; unsigned off;
 f->identity.rid = id->rid;
 r = ep_sample_read(i, f, 0, &f->identity.id); if (r) return r;
 r = ep_sample_read(i, f, 4, &status); if (r) return r;
 f->command = status & 65535; if (f->command & 7) return -EPERM;
 r = ep_sample_read(i, f, 8, &f->identity.class_rev); if (r) return r;
 r = ep_sample_read(i, f, 12, &v); if (r) return r;
 f->identity.header = (v >> 16) & 255;
 if ((f->identity.header & 127) > 1) return -EOPNOTSUPP;
 if ((f->identity.header & 127) == 1) {
  for (off = 0x18; off <= 0x30; off += 4) {
   r = ep_sample_read(i, f, off, &v); if (r) return r;
   if (off == 0x18) f->buses = v;
  }
 } else {
  r = ep_sample_read(i, f, 0x2c, &f->identity.subsystem); if (r) return r;
 }
 r = ep_caps(i, f, status); if (r) return r;
 /* Raw discovery cached subsystem/serial only on NVIDIA display functions. */
 if (f->identity.id != id->id || f->identity.class_rev != id->class_rev || f->identity.header != id->header) return -EPERM;
 if ((id->id & 65535) == 0x10de && (id->class_rev >> 24) == 3 &&
     !ep_identity_equal(&f->identity, id)) return -EPERM;
 return 0;
}
static int ep_capture(struct ep_io *i, const struct ep_identity *selected, struct ep_snapshot *s)
{
 unsigned j, k, matches = 0, bus; int r;
 if (!i->records || !i->count || i->count > EP_MAX_RECORDS || selected->rid > 65535 ||
     i->root_rid > 65535 || (i->root_rid & 255)) return -EINVAL;
 if (s->count || s->captured) return -EPERM;
 for (j = 0; j < i->count; j++) {
  if (i->records[j].rid > 65535) return -EINVAL;
  for (k = 0; k < j; k++) if (i->records[k].rid == i->records[j].rid) return -EINVAL;
  if (i->records[j].rid == selected->rid) {
   if (!ep_identity_equal(&i->records[j], selected)) return -EPERM;
   s->selected = j; matches++;
  }
 }
 if (matches != 1 || (selected->id & 65535) != 0x10de || (selected->class_rev >> 24) != 3 ||
     (selected->header & 127)) return -EPERM;
 for (j = 0; j < i->count; j++) {
  r = ep_function_read(i, &i->records[j], &s->functions[j]); if (r) return r;
  s->count++;
  if ((i->records[j].rid & ~7U) == (selected->rid & ~7U))
   s->same_device_mask |= 1U << (i->records[j].rid & 7);
 }
 bus = selected->rid >> 8;
 while (bus != (i->root_rid >> 8)) {
  unsigned parent = EP_MAX_RECORDS; u32 buses = 0;
  if (s->ancestor_count == 8) return -E2BIG;
  for (j = 0; j < s->count; j++) {
   const struct ep_function *f = &s->functions[j];
   if ((f->identity.class_rev >> 16) != 0x0604 || (f->identity.header & 127) != 1 ||
       ((f->buses >> 8) & 255) != bus) continue;
   if (parent != EP_MAX_RECORDS) return -EINVAL;
   parent = j; buses = f->buses;
  }
  if (parent == EP_MAX_RECORDS || (buses & 255) != (s->functions[parent].identity.rid >> 8) ||
      (buses & 255) >= bus || ((buses >> 16) & 255) < (selected->rid >> 8)) return -EINVAL;
  s->ancestors[s->ancestor_count++] = parent; bus = buses & 255;
 }
 if (!s->ancestor_count || s->functions[s->ancestors[s->ancestor_count - 1]].identity.rid != i->root_rid)
  return -EPERM;
 i->selected = selected;
 i->selected_serial_offset = s->functions[s->selected].serial_offset;
 r = ep_selected_recheck(i, selected->rid); if (r) return r;
 for (j = 0; j < 6; j++) {
  r = ep_sample_read(i, &s->functions[s->selected], 0x10 + 4 * j, &s->bars[j].saved[0]); if (r) return r;
 }
 r = i->safe(i->ctx, selected->rid); if (r) return r;
 r = ep_gate(i); if (r) return r;
 s->captured = true; return 0;
}
/* Only the observed exact endpoint's unassigned BAR5 I/O is an exception.
 * It remains present and unsized; it is never an absent/zero-sized memory BAR. */
static int ep_io_slot_policy_selected(const struct ep_snapshot *s, unsigned b,
 const struct ep_identity *allowed)
{
 const struct ep_identity expected = { .rid = 0x300, .id = 0x2d0410de,
  .class_rev = 0x030000a1, .subsystem = 0x41cd1458,
  .serial = PROVISION_PRIVATE_ID_6, .header = 0x80 };
 const struct ep_identity *want=&expected;
 if(allowed) {
  if(allowed->rid!=0x600 || allowed->id!=0x2d0410de ||
     allowed->class_rev!=0x030000a1 || allowed->subsystem!=0x41cd1458 ||
     !allowed->serial || allowed->serial==~0ULL || allowed->header!=0x80)
   return -EOPNOTSUPP;
  want=allowed;
 }
 if (b != 5 || s->selected >= s->count || s->count > EP_MAX_RECORDS ||
     !ep_identity_equal(&s->functions[s->selected].identity, want) ||
     s->bars[b].saved[0] != 1 || s->bars[b].saved[1] || s->bars[b].upper)
  return -EOPNOTSUPP;
 return 0;
}
static int ep_io_slot_policy(const struct ep_snapshot *s, unsigned b)
{ return ep_io_slot_policy_selected(s,b,NULL); }
static int ep_io_state(const struct ep_snapshot *s, unsigned b)
{
 const struct ep_bar *bar = &s->bars[b];
 if (ep_io_slot_policy(s, b) || !bar->unsupported_io ||
     bar->flags != EP_BAR_IO_UNASSIGNED || bar->window != EP_BAR_NO_WINDOW ||
     bar->mask[0] || bar->mask[1] || bar->size || bar->pci || bar->cpu)
  return -EINVAL;
 return 0;
}
static int ep_size_bars_policy(struct ep_io *i, struct ep_snapshot *s,
 const struct ep_identity *allowed,
 int (*slot_policy)(const struct ep_snapshot *,unsigned,const struct ep_identity *))
{
 unsigned b, rid; int r; u32 got;
 if (!s->captured || s->sized || s->selected >= s->count ||
     s->count > EP_MAX_RECORDS) return -EPERM;
 /* Reject unexpected I/O or overlap before any memory BAR probe. */
 for (b = 0; b < 6; b++) {
  const struct ep_bar *bar = &s->bars[b]; u32 old = bar->saved[0];
  if (bar->unsupported_io || (bar->flags & EP_BAR_IO_UNASSIGNED)) return -EPERM;
  if (old & 1) { r = slot_policy(s, b, allowed); if (r) return r; }
  else if ((old & 6) == 4) {
   if (b == 5 || (b == 4 && s->bars[5].saved[0] == 1)) return -EOPNOTSUPP;
   b++;
  }
 }
 rid = s->functions[s->selected].identity.rid;
 for (b = 0; b < 6; b++) {
  struct ep_bar *bar = &s->bars[b]; u32 old = bar->saved[0], lo, hi = 0; u64 mask, size;
  bool wide = (old & 6) == 4;
  if (old & 1) {
   r = slot_policy(s, b, allowed); if (r) return r;
   r = ep_selected_recheck(i, rid); if (r) return r;
   r = i->safe(i->ctx, rid); if (r) return r;
   r = ep_read(i, rid, 0x10 + 4 * b, &got); if (r) return r;
   if (got != old) return -EPERM;
   r = i->safe(i->ctx, rid); if (r) return r;
   r = ep_gate(i); if (r) return r;
   if (bar->mask[0] || bar->mask[1] || bar->size || bar->pci || bar->cpu)
    return -EPERM;
   bar->flags = EP_BAR_IO_UNASSIGNED; bar->window = EP_BAR_NO_WINDOW;
   bar->unsupported_io = true; /* No probe, size claim, write or assignment. */
   continue;
  }
  if ((old & 6) != 0 && !wide) return -EOPNOTSUPP;
  if (wide && b == 5) return -EINVAL;
  bar->flags = (wide ? EP_BAR_64 : 0) | ((old & 8) ? EP_BAR_PREF : 0);
  if (wide) { bar->saved[1] = s->bars[b + 1].saved[0]; s->bars[b + 1].upper = true; }
  if (i->probe_ready) { r = i->probe_ready(i->ctx); if (r) return r; }
  r = ep_read(i, rid, 0x10 + 4 * b, &got); if (r) return r;
  if (got != old) return -EPERM;
  if (wide) { r = ep_read(i, rid, 0x14 + 4 * b, &got); if (r) return r; if (got != bar->saved[1]) return -EPERM; }
  r = ep_write(i, rid, 0x10 + 4 * b, 0xffffffff); if (r) return r;
  if (wide) { r = ep_write(i, rid, 0x14 + 4 * b, 0xffffffff); if (r) return r; }
  r = ep_read(i, rid, 0x10 + 4 * b, &lo); if (r) return r;
  if (wide) { r = ep_read(i, rid, 0x14 + 4 * b, &hi); if (r) return r; }
  /* Failure is retained immediately; no blind restore/retry after loss of safety. */
  if (wide) { r = ep_write(i, rid, 0x14 + 4 * b, bar->saved[1]); if (r) return r; }
  r = ep_write(i, rid, 0x10 + 4 * b, old); if (r) return r;
  r = ep_read(i, rid, 0x10 + 4 * b, &got); if (r) return r; if (got != old) return -EIO;
  if (wide) { r = ep_read(i, rid, 0x14 + 4 * b, &got); if (r) return r; if (got != bar->saved[1]) return -EIO; }
  bar->mask[0] = lo; bar->mask[1] = hi;
  if (lo && (lo & 15) != (old & 15)) return -EIO;
  mask = ((u64)hi << 32) | (lo & ~15U);
  if (!wide) mask |= 0xffffffff00000000ULL;
  if (!(lo & ~15U) && !hi) {
   /* 32-bit 4GiB BAR and 64-bit 2^64 BAR cannot fit any aperture. */
   if (old || wide) return -ENOSPC;
   bar->size = 0;
  } else {
   size = ~mask + 1;
   if (!size || (size & (size - 1)) || size < 16) return -EINVAL;
   bar->size = size;
  }
  if (wide) b++;
 }
 r = ep_selected_recheck(i, rid); if (r) return r;
 r = i->safe(i->ctx, rid); if (r) return r;
 r = ep_gate(i); if (r) return r;
 s->sized = true; return 0;
}
static int ep_size_bars_selected(struct ep_io *i,struct ep_snapshot *s,const struct ep_identity *allowed)
{ return ep_size_bars_policy(i,s,allowed,ep_io_slot_policy_selected); }
static int ep_size_bars(struct ep_io *i, struct ep_snapshot *s)
{ return ep_size_bars_selected(i,s,NULL); }
/* Fixed authenticated aperture plan only, largest alignment first. No reservation
 * or assignment is implied. All ancestors cover ONLY this admitted endpoint. */
static int ep_plan(struct ep_snapshot *s)
{
 const u64 base[3] = {0x400000000ULL, 0x80000000ULL, 0xc0000000ULL};
 const u64 cap[3] = {0x80000000ULL, 0x40000000ULL, 0x40000000ULL};
 const u64 delta[3] = {0, 0x400000000ULL, 0x400000000ULL};
 u64 used[3] = {0}; bool done[6] = {0}; unsigned j, b, n, w;
 if (!s->sized || s->planned) return -EPERM;
 for (b = 0; b < 6; b++) {
  const struct ep_bar *bar = &s->bars[b];
  if (bar->unsupported_io || (bar->flags & EP_BAR_IO_UNASSIGNED) ||
      (!bar->upper && (bar->saved[0] & 1))) {
   if (ep_io_state(s, b)) return -EINVAL;
  }
 }
 if (s->functions[s->selected].msix) {
  const struct ep_function *f = &s->functions[s->selected];
  unsigned entries = (f->msix_control & 0x7ff) + 1;
  const u32 locations[2] = {f->msix_table, f->msix_pba};
  const u64 lengths[2] = {(u64)entries * 16, ((entries + 63) / 64) * 8};
  if (ep_msix_overlap(f)) return -EINVAL;
  for (j = 0; j < 2; j++) {
   const struct ep_bar *bar = &s->bars[locations[j] & 7];
   u64 offset = locations[j] & ~7U;
   if (bar->unsupported_io || bar->upper || !bar->size || lengths[j] > bar->size || offset > bar->size - lengths[j]) return -EINVAL;
  }
 }
 for (n = 0; n < 6; n++) {
  struct ep_bar *x; u64 start; b = 6;
  for (j = 0; j < 6; j++) if (!done[j] && !s->bars[j].unsupported_io && !s->bars[j].upper && s->bars[j].size &&
      (b == 6 || s->bars[j].size > s->bars[b].size)) b = j;
  if (b == 6) break;
  done[b] = true; x = &s->bars[b];
  w = (x->flags & EP_BAR_PREF) ? ((x->flags & EP_BAR_64) ? 0 : 2) : 1;
  if (x->size > cap[w] || (x->size & (x->size - 1))) return -ENOSPC;
  start = (base[w] + used[w] + x->size - 1) & ~(x->size - 1);
  if (start < base[w] || start - base[w] > cap[w] - x->size) return -ENOSPC;
  x->pci = start; x->cpu = start + delta[w]; x->window = w; used[w] = start - base[w] + x->size;
 }
 for (j = 0; j < s->ancestor_count; j++) {
  struct ep_bridge_plan *p = &s->bridges[j];
  p->rid = s->functions[s->ancestors[j]].identity.rid;
  /* A Type-1 bridge has one prefetch window. Two separated prefetch apertures
   * require a spanning window over resources we do not own: reject that plan. */
  if (used[0] && used[2]) return -EOPNOTSUPP;
  for (w = 0; w < 3; w++) if (used[w]) {
   p->active[w] = true; p->start[w] = base[w];
   p->end[w] = base[w] + ((used[w] + 0xfffff) & ~0xfffffULL) - 1;
   if (p->end[w] >= base[w] + cap[w]) return -ENOSPC;
   if (w == 0) {
    unsigned k; bool found = false;
    const struct ep_function *f = &s->functions[s->ancestors[j]];
    for (k = 0; k < f->sample_count; k++) if (f->samples[k].offset == 0x24) {
     u32 v = f->samples[k].value;
     if ((v & 15) != 1 || ((v >> 16) & 15) != 1) return -EOPNOTSUPP;
     found = true;
    }
    if (!found) return -EINVAL;
   }
  }
 }
 s->planned = true; return 0;
}
#endif
