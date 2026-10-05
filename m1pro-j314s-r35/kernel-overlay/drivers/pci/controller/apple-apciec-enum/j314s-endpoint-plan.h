/* SPDX-License-Identifier: GPL-2.0 */
/* Standard PCI schema admission, not a claim of GPU identity. Every full
 * identity below must be the exact current-boot raw record and revalidated. */
#ifndef J314S_ENDPOINT_PLAN_H
#define J314S_ENDPOINT_PLAN_H
#include "j314s-capabilities.h"
static bool j314s_gpu_schema(const struct ep_identity *id)
{
 unsigned device=id?id->id>>16:0;
 return id && (id->id&65535)==0x10de &&
  (device==0x2d04 || device==0x2c02 || device==0x2c18) &&
  id->rid>0 && id->rid<=65535 && !(id->rid&7) &&
  (id->class_rev>>16)==0x0300 && !(id->header&0x7f);
}
static bool j314s_ep_schema_limit(const struct ep_snapshot *s,const struct ep_identity *selected,unsigned ancestor_limit)
{
 const struct ep_function *f;unsigned j,k;
 if(!ancestor_limit||ancestor_limit>16||!s||!selected||!s->captured||!s->count||s->count>EP_MAX_RECORDS||
    s->selected>=s->count||!s->ancestor_count||s->ancestor_count>ancestor_limit||
    !j314s_gpu_schema(selected))return false;
 for(j=0;j<s->ancestor_count;j++){
  if(s->ancestors[j]>=s->count)return false;
  for(k=0;k<j;k++)if(s->ancestors[k]==s->ancestors[j])return false;
 }
 f=&s->functions[s->selected];
 return ep_identity_equal(&f->identity,selected) && !f->command &&
  f->pcie && (f->msi||f->msix) && !(f->msi_control&1) &&
  !(f->msix_control&0x8000) && j314s_capabilities_disabled(f) &&
  (f->serial_present == !!f->serial_offset) &&
  (f->serial_present || !selected->serial);
}
static bool j314s_ep_schema(const struct ep_snapshot*s,const struct ep_identity*selected)
{return j314s_ep_schema_limit(s,selected,8);}
static int j314s_ep_io_slot(const struct ep_snapshot *s,unsigned b,
                            const struct ep_identity *selected)
{
 if(!j314s_ep_schema(s,selected)||b!=5||s->bars[b].saved[0]!=1||
    s->bars[b].saved[1]||s->bars[b].upper)return -EOPNOTSUPP;
 return 0;
}
static int j314s_ep_io_state(const struct ep_snapshot *s,unsigned b,
                             const struct ep_identity *selected)
{
 const struct ep_bar *bar=&s->bars[b];
 return j314s_ep_io_slot(s,b,selected)||!bar->unsupported_io||
  bar->flags!=EP_BAR_IO_UNASSIGNED||bar->window!=EP_BAR_NO_WINDOW||
  bar->mask[0]||bar->mask[1]||bar->size||bar->pci||bar->cpu?-EINVAL:0;
}
static int j314s_ep_plan(struct ep_snapshot *s, const struct ep_identity *selected)
{
 const u64 base[3] = {0x800000000ULL, 0x100000ULL, 0x40000000ULL};
 const u64 cap[3] = {0x200000000ULL, 0x3ff00000ULL, 0x40000000ULL};
 const u64 delta[3] = {0, 0xa00000000ULL, 0xa00000000ULL};
 u64 used[3] = {0}; bool done[6] = {0}; unsigned j, b, n, w;
 if (!s->sized || s->planned || !j314s_ep_schema(s,selected)) return -EPERM;
 for (b = 0; b < 6; b++) {
  const struct ep_bar *bar = &s->bars[b];
  if (bar->unsupported_io || (bar->flags & EP_BAR_IO_UNASSIGNED) ||
      (!bar->upper && (bar->saved[0] & 1))) {
   if (j314s_ep_io_state(s,b,selected)) return -EINVAL;
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
