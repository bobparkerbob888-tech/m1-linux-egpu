/* SPDX-License-Identifier: GPL-2.0 */
/* Pure exact plan construction. No MMIO, allocation, resources or permits. */
#ifndef J314S_ASSIGNMENT_PLAN_H
#define J314S_ASSIGNMENT_PLAN_H
#include "j314s-assignment-plan-types.h"
static int ja_sample(const struct ep_function*f,unsigned off,u32*v)
{
 unsigned j,found=0;
 if(f->sample_count>EP_MAX_SAMPLES)return -EINVAL;
 for(j=0;j<f->sample_count;j++)if(f->samples[j].offset==off){*v=f->samples[j].value;found++;}
 return found==1?0:-EINVAL;
}
static int ja_reg(struct ja_plan*p,unsigned rid,unsigned off,u32 before,u32 after,bool writable,unsigned*idx)
{
 unsigned j;
 if(p->count>=JA_MAX_REGS||(off&3))return -E2BIG;
 for(j=0;j<p->count;j++)if(p->regs[j].rid==rid&&p->regs[j].offset==off)return -EINVAL;
 *idx=p->count;p->regs[p->count++]=(struct ja_register){rid,off,before,after,writable};return 0;
}
static int ja_step(struct ja_plan*p,unsigned reg,u32 value)
{
 unsigned j;u32 before;
 if(reg>=p->count)return -EINVAL;
 before=p->regs[reg].before;
 for(j=0;j<p->step_count;j++)if(p->steps[j].reg==reg)before=p->steps[j].value;
 if(!p->regs[reg].writable)return value==before?0:-EPERM;
 if(before==value)return 0;
 if(p->step_count>=JA_MAX_STEPS)return -E2BIG;
 p->steps[p->step_count++]=(struct ja_step){reg,before,value};return 0;
}
static int ja_plan_build(const struct ep_snapshot*s,const struct ep_identity*selected,struct ja_plan*p)
{
 const u64 base[3]={0x800000000ULL,0x100000ULL,0x40000000ULL};
 const u64 cap[3]={0x200000000ULL,0x3ff00000ULL,0x40000000ULL};
 const u64 delta[3]={0,0xa00000000ULL,0xa00000000ULL};
 u64 end[3]={0};unsigned j,k,bus,barreg[6];int ret;
 if(!p||p->built||p->count||p->step_count||!s||!s->sized||!s->planned||s->memory_assigned||
    !j314s_ep_schema(s,selected))return -EPERM;
 for(j=0;j<s->count;j++){
  const struct ep_function*f=&s->functions[j];u32 v;
  if(f->command||ja_sample(f,0,&v)||v!=f->identity.id||
     ja_sample(f,4,&v)||(v&65535)||ja_sample(f,8,&v)||v!=f->identity.class_rev||
     ja_sample(f,12,&v)||((v>>16)&255)!=f->identity.header)return -EPERM;
 }
 {
  const struct ep_function*f=&s->functions[s->selected];u32 lo,hi;
  if(ja_sample(f,0x2c,&lo)||lo!=selected->subsystem)return -EPERM;
  if(f->serial_present){
   if(f->serial_offset<0x100||f->serial_offset>0xff4||(f->serial_offset&3)||
      ja_sample(f,f->serial_offset+4,&lo)||ja_sample(f,f->serial_offset+8,&hi)||
      (((u64)hi<<32)|lo)!=selected->serial)return -EPERM;
  }else if(selected->serial)return -EPERM;
 }
 bus=selected->rid>>8;
 for(j=0;j<s->ancestor_count;j++){
  const struct ep_function*f=&s->functions[s->ancestors[j]];u32 v;
  if((f->identity.header&127)!=1||(f->identity.class_rev>>16)!=0x0604||
     ja_sample(f,0x18,&v)||v!=f->buses||(v&255)!=(f->identity.rid>>8)||
     ((v>>8)&255)!=bus||(v&255)>=bus||((v>>16)&255)<(selected->rid>>8)||
     s->bridges[j].rid!=f->identity.rid)return -EPERM;
  bus=v&255;
 }
 if(bus||s->functions[s->ancestors[s->ancestor_count-1]].identity.rid)return -EPERM;
 p->selected=*selected;
 for(j=0;j<6;j++){
  const struct ep_bar*b=&s->bars[j];u64 mask,measured;unsigned flags,w;bool wide;
  if(b->unsupported_io||(b->flags&EP_BAR_IO_UNASSIGNED)){
   if(j314s_ep_io_state(s,j,selected))return -EPERM;
   continue;
  }
  if(b->upper){if(!j||s->bars[j-1].upper||!(s->bars[j-1].flags&EP_BAR_64)||b->size||b->pci||b->cpu)return -EPERM;continue;}
  wide=(b->saved[0]&6)==4;
  if((b->saved[0]&1)||((b->saved[0]&6)&&!wide)||(wide&&j==5))return -EINVAL;
  flags=(wide?EP_BAR_64:0)|((b->saved[0]&8)?EP_BAR_PREF:0);
  if(b->flags!=flags||(b->mask[0]&&(b->mask[0]&15)!=(b->saved[0]&15)))return -EINVAL;
  if(wide&&(!s->bars[j+1].upper||b->saved[1]!=s->bars[j+1].saved[0]))return -EINVAL;
  if(!wide&&(b->saved[1]||b->mask[1]))return -EINVAL;
  mask=((u64)b->mask[1]<<32)|(b->mask[0]&~15U);if(!wide)mask|=0xffffffff00000000ULL;
  measured=~mask+1;
  if(!(b->mask[0]&~15U)&&!b->mask[1]){if(b->saved[0]||wide||b->size||b->pci||b->cpu)return -EINVAL;continue;}
  if(!measured||(measured&(measured-1))||measured<16||measured!=b->size)return -EINVAL;
  w=(flags&EP_BAR_PREF)?((flags&EP_BAR_64)?0:2):1;
  if(b->window!=w||measured>cap[w]||b->pci<base[w]||b->pci-base[w]>cap[w]-measured||
     (b->pci&(measured-1))||b->cpu!=b->pci+delta[w])return -EINVAL;
  for(k=0;k<j;k++){const struct ep_bar*a=&s->bars[k];if(!a->upper&&a->size&&a->window==w&&b->pci<a->pci+a->size&&a->pci<b->pci+b->size)return -EINVAL;}
  if(b->pci+b->size-1>end[w])end[w]=b->pci+b->size-1;
 }
 if(end[0]&&end[2])return -EOPNOTSUPP;
 for(j=0;j<3;j++)if(end[j])end[j]|=0xfffffULL;
 for(j=0;j<s->ancestor_count;j++)for(k=0;k<3;k++){
  const struct ep_bridge_plan*b=&s->bridges[j];
  if(b->active[k]!=!!end[k]||(end[k]&&(b->start[k]!=base[k]||b->end[k]!=end[k]))||
     (!end[k]&&(b->start[k]||b->end[k])))return -EINVAL;
 }
 for(j=0;j<6;j++){
  const struct ep_bar*b=&s->bars[j];u32 before,after=b->saved[0];
  if(ja_sample(&s->functions[s->selected],0x10+4*j,&before)||before!=b->saved[0])return -EINVAL;
  if(b->upper)after=s->bars[j-1].pci>>32;else if(b->size)after=(u32)b->pci|(b->saved[0]&15);
  ret=ja_reg(p,selected->rid,0x10+4*j,before,after,!b->unsupported_io,&barreg[j]);if(ret)return ret;
 }
 /* High half first for each 64bit BAR, then low half. Unimplemented and IO
  * values remain audited but produce no assignment write. Commands stay0. */
 for(j=0;j<6;j++){
  if(s->bars[j].upper)continue;
  if(s->bars[j].flags&EP_BAR_64){ret=ja_step(p,barreg[j+1],p->regs[barreg[j+1]].after);if(ret)return ret;}
  ret=ja_step(p,barreg[j],p->regs[barreg[j]].after);if(ret)return ret;
 }
 for(j=0;j<s->ancestor_count;j++){
  const struct ep_function*f=&s->functions[s->ancestors[j]];u32 old[4],value[4],types;unsigned regs[4],pref=end[0]?0:2;
  for(k=0;k<4;k++)if(ja_sample(f,0x20+4*k,&old[k]))return -EINVAL;
  if(old[0]&0x000f000f)return -EOPNOTSUPP;
  types=old[1]&0x000f000f;if(types&&types!=0x10001)return -EOPNOTSUPP;
  if(end[0]&&types!=0x10001)return -EOPNOTSUPP;
  if(!types&&(old[2]||old[3]))return -EINVAL;
  value[0]=end[1]?((base[1]>>16)&0xfff0)|(end[1]&0xfff00000):0xfff0;
  value[1]=(end[pref]?((base[pref]>>16)&0xfff0)|(end[pref]&0xfff00000):0xfff0)|types;
  value[2]=end[pref]?base[pref]>>32:0;value[3]=end[pref]?end[pref]>>32:0;
  for(k=0;k<4;k++){ret=ja_reg(p,f->identity.rid,0x20+4*k,old[k],value[k],true,&regs[k]);if(ret)return ret;}
  ret=ja_step(p,regs[0],value[0]);if(ret)return ret;
  if(types){ret=ja_step(p,regs[3],0);if(ret)return ret;}
  ret=ja_step(p,regs[1],value[1]);if(ret)return ret;
  if(types){ret=ja_step(p,regs[2],value[2]);if(ret)return ret;ret=ja_step(p,regs[3],value[3]);if(ret)return ret;}
 }
 for(j=0;j<p->count;j++){u32 last=p->regs[j].before;for(k=0;k<p->step_count;k++)if(p->steps[k].reg==j)last=p->steps[k].value;if(last!=p->regs[j].after)return -EINVAL;}
 if(p->count!=6+4*s->ancestor_count)return -EINVAL;
 p->built=true;return 0;
}
#endif
