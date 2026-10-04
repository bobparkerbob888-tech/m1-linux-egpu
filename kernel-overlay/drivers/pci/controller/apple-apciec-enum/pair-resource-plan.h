/* SPDX-License-Identifier: GPL-2.0 */
#ifndef BOB_PAIR_RESOURCE_PLAN_H
#define BOB_PAIR_RESOURCE_PLAN_H
static int pn_snapshot_validate(const struct ep_snapshot *s,unsigned rid)
{
 static const unsigned a600[5]={6,5,4,1,0},a300[3]={2,1,0};
 const unsigned *anc=rid==0x600?a600:a300;unsigned n=rid==0x600?5:3,j,k,type;
 u64 pci,cpu,size;
 if(!s||!s->captured||!s->sized||s->planned||s->memory_assigned||s->count!=8||
  s->selected!=(rid==0x600?7:3)||s->ancestor_count!=n||s->same_device_mask!=1)return -EINVAL;
 for(j=0;j<8;j++){
  const struct ep_function *f=&s->functions[j];const struct ep_identity *id=&f->identity;
  if(id->rid!=pn_positions[j].rid||f->command||f->sample_count>EP_MAX_SAMPLES)return -EINVAL;
  if(pn_positions[j].forwarding){
   u64 serial=j==0?0:j<=2||j==4?PROVISION_PRIVATE_ID_14:PROVISION_PRIVATE_ID_15;
   if(id->id!=(j?0x57868086:0x1010106b)||id->header!=1||id->serial!=serial||
    id->class_rev!=(j?0x06040085:0x06040000)||
    (f->buses&0xffffff)!=((id->rid>>8)|(pn_positions[j].secondary<<8)|(pn_positions[j].subordinate<<16)))return -EINVAL;
  }else if(id->id!=0x2d0410de||id->class_rev!=0x030000a1||id->header!=0x80||
   id->subsystem!=0x41cd1458||!pn_serial_ok(id->rid,id->serial))return -EINVAL;
 }
 for(j=0;j<n;j++){
  const struct ep_function *f=&s->functions[anc[j]];bool found=false;
  if(s->ancestors[j]!=anc[j])return -EINVAL;
  for(k=0;k<f->sample_count;k++)if(f->samples[k].offset==0x24){
   if(found||(f->samples[k].value&0x000f000f)!=0x00010001)return -EINVAL;
   found=true;
  }
  if(!found)return -EINVAL;
 }
 for(j=0;j<6;j++){
  const struct ep_bar *b=&s->bars[j];if(b->pci||b->cpu)return -EINVAL;
  if(pn_bar(rid,j,&pci,&cpu,&size,&type)){
   if(b->upper||b->unsupported_io||b->size!=size||(b->saved[0]&15)!=type||b->flags!=(j?3:0))return -EINVAL;
  }else if(j==2||j==4){if(!b->upper||b->size||b->unsupported_io||b->flags)return -EINVAL;}
  else if(!b->unsupported_io||b->upper||b->size||b->flags!=EP_BAR_IO_UNASSIGNED||
   b->saved[0]!=1||b->saved[1]||b->mask[0]||b->mask[1]||b->window!=EP_BAR_NO_WINDOW)return -EINVAL;
 }
 {
  const struct ep_function *f=&s->functions[s->selected];
  if(f->msix){const u32 loc[2]={f->msix_table,f->msix_pba};unsigned nvec=(f->msix_control&0x7ff)+1;
   u64 len[2]={(u64)nvec*16,((nvec+63)/64)*8},start[2];
   for(j=0;j<2;j++){unsigned b=loc[j]&7;start[j]=loc[j]&~7U;
    if(b>5||!pn_bar(rid,b,&pci,&cpu,&size,&type)||len[j]>size||start[j]>size-len[j])return -EINVAL;}
   if((loc[0]&7)==(loc[1]&7)&&start[0]<start[1]+len[1]&&start[1]<start[0]+len[0])return -EINVAL;
  }
 }
 return 0;
}
static void pn_snapshot_plan(struct ep_snapshot *s,unsigned rid)
{
 unsigned j,type;u64 pci,cpu,size;
 for(j=0;j<6;j++)if(pn_bar(rid,j,&pci,&cpu,&size,&type)){
  s->bars[j].pci=pci;s->bars[j].cpu=cpu;s->bars[j].window=j?0:1;
 }
 for(j=0;j<s->ancestor_count;j++){
  struct ep_bridge_plan *b=&s->bridges[j];u32 mem,pref;
  *b=(struct ep_bridge_plan){.rid=pn_positions[s->ancestors[j]].rid};
  pn_window(b->rid,0x20,&mem);pn_window(b->rid,0x24,&pref);
  b->active[0]=b->active[1]=true;
  b->start[0]=0x500000000ULL|((u64)(pref&0xfff0)<<16);
  b->end[0]=0x500000000ULL|(pref&0xfff00000)|0xfffff;
  b->start[1]=(u64)(mem&0xfff0)<<16;b->end[1]=(mem&0xfff00000)|0xfffff;
 }
 s->planned=true;
}
static int pn_resource_plan(struct ep_snapshot *primary,struct ep_snapshot *secondary)
{
 unsigned j,k;int r=pn_snapshot_validate(primary,0x600);if(r)return r;
 r=pn_snapshot_validate(secondary,0x300);if(r)return r;
 /* Captures must describe one immutable topology. All capability-derived fields
  * come from these same ordered samples; compare values without struct padding. */
 for(j=0;j<8;j++){
  const struct ep_function *a=&primary->functions[j],*b=&secondary->functions[j];
  if(!ep_identity_equal(&a->identity,&b->identity)||a->sample_count!=b->sample_count||
   a->command!=b->command||a->buses!=b->buses)return -ESTALE;
  for(k=0;k<a->sample_count;k++)if(a->samples[k].offset!=b->samples[k].offset||
   a->samples[k].value!=b->samples[k].value)return -ESTALE;
 }
 pn_snapshot_plan(primary,0x600);pn_snapshot_plan(secondary,0x300);return 0;
}
/* BAR5 remains untouched; this policy is never installed in legacy sizing. */
static int pn_io_slot_policy(const struct ep_snapshot *s,unsigned slot,const struct ep_identity *allowed)
{
 if(!allowed||slot!=5||s->count!=8||s->selected>=8||
  s->selected!=(allowed->rid==0x600?7:3)||!pn_serial_ok(allowed->rid,allowed->serial)||
  allowed->id!=0x2d0410de||allowed->class_rev!=0x030000a1||allowed->subsystem!=0x41cd1458||allowed->header!=0x80||
  !ep_identity_equal(&s->functions[s->selected].identity,allowed)||
  s->bars[5].saved[0]!=1||s->bars[5].saved[1]||s->bars[5].upper)return -EOPNOTSUPP;
 return 0;
}
#endif
