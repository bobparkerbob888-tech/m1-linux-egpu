/* SPDX-License-Identifier: GPL-2.0 */
/* LOCAL prototype: consumes measured snapshot; performs no hardware access. */
#ifndef BOB_TARGET_RESOURCE_PLAN_H
#define BOB_TARGET_RESOURCE_PLAN_H
static int tn_resource_plan(struct ep_snapshot *s, u64 retained_serial)
{
 static const unsigned ancestors[5]={5,4,3,1,0};
 unsigned j,k,type; u64 pci,cpu,size;
 if (!s || !retained_serial || !s->captured || !s->sized || s->planned ||
     s->memory_assigned || s->count!=7 || s->selected!=6 ||
     s->ancestor_count!=5 || s->same_device_mask!=1) return -EINVAL;
 for(j=0;j<7;j++) {
  const struct ep_function *f=&s->functions[j];
  if(f->identity.rid!=tn_positions[j].rid || f->command) return -EINVAL;
  if(j<6 && ((f->identity.header&127)!=1 ||
     (f->identity.class_rev>>16)!=0x0604)) return -EINVAL;
  if(j<6 && (f->buses&0xffffff)!=(j==2?0:((f->identity.rid>>8)|
     (tn_positions[j].secondary<<8)|(tn_positions[j].subordinate<<16))))
     return -EINVAL;
 }
 {const struct ep_identity *f=&s->functions[6].identity;
  if(f->id!=0x2d0410de || f->class_rev!=0x030000a1 ||
     f->subsystem!=0x41cd1458 || f->serial!=retained_serial ||
     f->header!=0x80) return -EINVAL;
 }
 for(j=0;j<5;j++) {
  bool found=false;
  if(s->ancestors[j]!=ancestors[j]) return -EINVAL;
  const struct ep_function *f=&s->functions[ancestors[j]];
  if(f->sample_count>EP_MAX_SAMPLES) return -EINVAL;
  for(k=0;k<f->sample_count;k++) if(f->samples[k].offset==0x24) {
   if(found || (f->samples[k].value&0x000f000f)!=0x00010001) return -EINVAL;
   found=true;
  }
  if(!found) return -EINVAL;
 }
 for(j=0;j<6;j++) {
  const struct ep_bar *b=&s->bars[j];
  if(b->pci || b->cpu) return -EINVAL;
  if(tn_bar(j,&pci,&cpu,&size,&type)) {
   if(b->upper || b->unsupported_io || b->size!=size ||
      (b->saved[0]&15)!=type || b->flags!=(j?3:0)) return -EINVAL;
  } else if(j==2 || j==4) {
   if(!b->upper || b->size || b->unsupported_io || b->flags) return -EINVAL;
  } else if(!b->unsupported_io || b->upper || b->size ||
    b->flags!=EP_BAR_IO_UNASSIGNED || b->saved[0]!=1 || b->saved[1] ||
    b->mask[0] || b->mask[1] || b->window!=EP_BAR_NO_WINDOW) return -EINVAL;
 }
 {
  const struct ep_function *f=&s->functions[6];
  if(f->msix) {
   const u32 loc[2]={f->msix_table,f->msix_pba};
   unsigned n=(f->msix_control&0x7ff)+1;
   u64 len[2]={(u64)n*16,((n+63)/64)*8},start[2];
   for(j=0;j<2;j++) {
    unsigned b=loc[j]&7;start[j]=loc[j]&~7U;
    if(b>5 || !tn_bar(b,&pci,&cpu,&size,&type) ||
       len[j]>size || start[j]>size-len[j]) return -EINVAL;
   }
   if((loc[0]&7)==(loc[1]&7) && start[0]<start[1]+len[1] &&
      start[1]<start[0]+len[0]) return -EINVAL;
  }
 }
 /* No output mutation until every measured-geometry prerequisite passes. */
 for(j=0;j<6;j++) if(tn_bar(j,&pci,&cpu,&size,&type)) {
  s->bars[j].pci=pci;s->bars[j].cpu=cpu;s->bars[j].window=j?0:1;
 }
 for(j=0;j<5;j++) {
  struct ep_bridge_plan *b=&s->bridges[j];
  *b=(struct ep_bridge_plan){.rid=tn_positions[ancestors[j]].rid};
  b->active[0]=b->active[1]=true;
  b->start[0]=0x580000000ULL;b->end[0]=0x591ffffffULL;
  b->start[1]=0x4000000;b->end[1]=0x7ffffff;
 }
 s->planned=true;return 0;
}
#endif
