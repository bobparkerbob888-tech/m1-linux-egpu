/* SPDX-License-Identifier: GPL-2.0 */
/* Frozen snapshot-derived selected path; no fixed RID/DSN/topology count.
 * Pure admission only. Caller retains snapshot/assignment owner for boot. */
#ifndef APPLE_J314S_NATIVE_LAYOUT_H
#define APPLE_J314S_NATIVE_LAYOUT_H
#define J314S_NATIVE_PATH_MAX 9
struct j314s_native_layout {
 unsigned count, selected, max_bus;
 unsigned index[J314S_NATIVE_PATH_MAX],rid[J314S_NATIVE_PATH_MAX];
};
static int j314s_native_layout_build(const struct ep_snapshot *s,
                                    struct j314s_native_layout *out)
{
 struct j314s_native_layout l={0};unsigned i,j;
 if(!s||!out||!s->captured||!s->sized||!s->planned||!s->memory_assigned||
    !s->count||s->count>EP_MAX_RECORDS||s->selected>=s->count||
    !s->ancestor_count||s->ancestor_count>=J314S_NATIVE_PATH_MAX)return -EPERM;
 for(i=0;i<s->count;i++) {
  const struct ep_function*f=&s->functions[i];
  if(f->identity.rid>65535||f->command)
   return -EPERM;
  for(j=0;j<i;j++)if(s->functions[j].identity.rid==f->identity.rid)return -ESTALE;
 }
 l.count=s->ancestor_count+1;l.selected=l.count-1;
 for(i=0;i<l.count;i++) {
  const struct ep_function*f;
  j=i==l.selected?s->selected:s->ancestors[s->ancestor_count-1-i];
  if(j>=s->count)return -EPERM;
  f=&s->functions[j];l.index[i]=j;l.rid[i]=f->identity.rid;
  if(i==l.selected) {
   unsigned device=f->identity.id>>16;
   if((f->identity.id&65535)!=0x10de||
      (device!=0x2d04&&device!=0x2c02&&device!=0x2c18)||
      (f->identity.class_rev>>16)!=0x0300||(f->identity.header&127)||
      !l.rid[i]||(l.rid[i]&7)||!f->pcie)return -EPERM;
  }else if((f->identity.class_rev>>16)!=0x0604||
            (f->identity.header&127)!=1||!f->pcie)return -EPERM;
  for(j=0;j<i;j++)if(l.rid[j]==l.rid[i])return -EPERM;
 }
 if(l.rid[0])return -EPERM;
 l.max_bus=l.rid[l.selected]>>8;
 for(i=0;i<l.selected;i++) {
  const struct ep_function*f=&s->functions[l.index[i]];
  unsigned primary=f->buses&255,secondary=(f->buses>>8)&255,subordinate=(f->buses>>16)&255;
  if(primary!=(l.rid[i]>>8)||secondary!=(l.rid[i+1]>>8)||
     secondary<=primary||subordinate<(l.rid[l.selected]>>8))return -EPERM;
  if(subordinate>l.max_bus)l.max_bus=subordinate;
 }
 /* BAR0 CPU read later must use this exact assigned aperture, not old literals. */
 if(s->bars[0].upper||s->bars[0].unsupported_io||s->bars[0].size<4||
    !s->bars[0].pci||!s->bars[0].cpu||
    (s->bars[0].flags&(EP_BAR_PREF|EP_BAR_IO_UNASSIGNED)))return -EPERM;
 *out=l;return 0;
}
static inline bool j314s_native_layout_identity(const struct ep_snapshot *s,
 const struct j314s_native_layout *l,unsigned position,const struct ep_identity *id)
{
 const struct ep_identity*want;
 if(!s||!l||!id||!l->count||l->count>J314S_NATIVE_PATH_MAX||
    position>=l->count||l->index[position]>=s->count)return false;
 want=&s->functions[l->index[position]].identity;
 return id->rid==want->rid&&id->id==want->id&&id->class_rev==want->class_rev&&
  id->subsystem==want->subsystem&&id->header==want->header&&id->serial==want->serial;
}
#endif
