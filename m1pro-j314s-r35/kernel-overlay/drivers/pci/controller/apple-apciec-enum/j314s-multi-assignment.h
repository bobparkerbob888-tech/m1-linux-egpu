/* SPDX-License-Identifier: GPL-2.0 */
#ifndef J314S_MULTI_ASSIGNMENT_H
#define J314S_MULTI_ASSIGNMENT_H
#include "j314s-multi-admission.h"
#include "jmx-schema.h"
#include "jmx-plan.h"
#define JMA_WRITES 640
struct jma_input {
 struct jm_capture capture; /* full owner-normalized sameboot records */
 u32 command[JM_MAX_RECORDS];
 u32 saved[JM_MAX_GPUS][6],mask[JM_MAX_GPUS][6];
 u32 bridge[JM_MAX_RECORDS][4]; /* frozen config 20,24,28,2c */
};
struct jma_write {unsigned rid,offset;u32 before,after;};
struct jma_plan {
 struct jm_capture assigned;
 struct jm_plan admission;
 u64 start[JM_MAX_RECORDS][2],end[JM_MAX_RECORDS][2];
 struct jma_write writes[JMA_WRITES];unsigned count;
};
static int jma_add(struct jma_plan*p,unsigned rid,unsigned off,u32 before,u32 after)
{unsigned i;if(p->count>=JMA_WRITES)return -1;
 for(i=0;i<p->count;i++)if(p->writes[i].rid==rid&&p->writes[i].offset==off)before=p->writes[i].after;
 if(before!=after)p->writes[p->count++]=(struct jma_write){rid,off,before,after};
 return 0;}
static int jma_free(const struct jm_capture*c,unsigned g,unsigned b,u64 pos,u64 size)
{unsigned i,j;for(i=0;i<=g;i++)for(j=0;j<3;j++){
 const struct jm_bar*a=&c->bars[i][j];if(i==g&&j>=b)break;
 if(jm_overlap(pos,size,a->pci,a->size))return 0;
 }return 1;}
static int jma_build_policy(const struct jma_input*in,struct jma_plan*out,struct jma_plan*work,const struct jmx_policy*policy)
{
 unsigned g,b,i,j,k,r,w;u64 size,mask,pos,last,cursor[2]={0};u32 old[4],v[4];
 if(!in||!out||!work||out==work)return -1;
 *work=(struct jma_plan){0};work->assigned=in->capture;
 if(work->assigned.count>JM_MAX_RECORDS||!work->assigned.count||
    (policy?(!jmx_policy_valid(policy)||work->assigned.gpus!=policy->count):(work->assigned.gpus!=2&&work->assigned.gpus!=4)))return -1;
 for(i=0;i<work->assigned.count;i++)if(in->command[i])return -1;
 for(w=0;w<2;w++)if(!jm_range(work->assigned.window[w].pci,work->assigned.window[w].size)||
  !jm_range(work->assigned.window[w].cpu,work->assigned.window[w].size)||
  (work->assigned.window[w].pci&0xfffff)||(work->assigned.window[w].size&0xfffff))return -1;
 for(g=0;g<work->assigned.gpus;g++){
  /* Only measured 32bit nonpref BAR0,64bit pref BAR1/3,IO5 held off. */
  if((in->saved[g][0]&15)||(in->saved[g][1]&15)!=12||
     (in->saved[g][3]&15)!=12||!(in->saved[g][5]&1))return -1;
  for(b=0;b<3;b++){
   unsigned slot=b?2*b-1:0;struct jm_bar*a=&work->assigned.bars[g][b];
   const struct jm_window*win=&work->assigned.window[b?1:0];
   if((in->mask[g][slot]&15)!=(in->saved[g][slot]&15))return -1;
   mask=(in->mask[g][slot]&~15U)|((u64)(b?in->mask[g][slot+1]:0xffffffffU)<<32);
   size=~mask+1;if(size<16||(size&(size-1))||size!=a->size||size>win->size)return -1;
   /* A supplied preferred location must itself be an exact valid translation. */
   if(a->pci&&(a->pci<win->pci||a->pci-win->pci>win->size-size||
      (a->pci&(size-1))||a->cpu!=win->cpu+(a->pci-win->pci)))return -1;
   pos=a->pci;
   if(g||!pos||pos<cursor[b?1:0]||!jma_free(&work->assigned,g,b,pos,size)) {
    /* Preserve per-GPU order within each aperture: never backfill a
     * previous GPU's alignment hole across sibling bridge subtrees. */
    pos=cursor[b?1:0]>win->pci?cursor[b?1:0]:win->pci;
    for(;;){
     if(pos>~(u64)0-(size-1))return -1;
     pos=(pos+size-1)&~(size-1);
     if(pos<win->pci||pos-win->pci>win->size-size)return -1;
     if(jma_free(&work->assigned,g,b,pos,size))break;
     /* Move beyond one intersecting allocation, then realign. */
     for(i=0;i<=g;i++)for(j=0;j<3;j++){
      const struct jm_bar*x=&work->assigned.bars[i][j];if(i==g&&j>=b)break;
      if(jm_overlap(pos,size,x->pci,x->size)){
       if(x->pci>~(u64)0-x->size)return -1;
       pos=x->pci+x->size;
      }
     }
    }
   }
   if(!b&&pos+size-1>0xffffffffULL)return -1;
   if(pos>~(u64)0-size)return -1;
   cursor[b?1:0]=pos+size;
   *a=(struct jm_bar){pos,win->cpu+(pos-win->pci),size,b?1U:0U};
  }
 }
 if(policy?jmx_build(&work->assigned,policy,&work->admission):jm_build(&work->assigned,&work->admission))return -1;
 /* Union every selected descendant BAR into each ancestor, exactly once. */
 for(g=0;g<work->assigned.gpus;g++)for(b=0;b<3;b++){
  const struct jm_bar*a=&work->assigned.bars[g][b];w=b?1:0;r=work->assigned.record[work->assigned.selected[g]].parent;
  while(r!=JM_ROOT){
   pos=a->pci&~0xfffffULL;last=(a->pci+a->size-1)|0xfffffULL;
   if(!work->end[r][w]||pos<work->start[r][w])work->start[r][w]=pos;
   if(last>work->end[r][w])work->end[r][w]=last;
   r=work->assigned.record[r].parent;
  }
 }
 /* Refuse interleaved sibling apertures instead of forwarding ambiguously. */
 for(i=0;i<work->assigned.count;i++)for(j=0;j<i;j++)
  if(work->assigned.record[i].parent==work->assigned.record[j].parent)
   for(w=0;w<2;w++)if(work->end[i][w]&&work->end[j][w]&&
    jm_overlap(work->start[i][w],work->end[i][w]-work->start[i][w]+1,work->start[j][w],work->end[j][w]-work->start[j][w]+1))return -1;
 for(g=0;g<work->assigned.gpus;g++)for(b=0;b<3;b++){
  unsigned slot=b?2*b-1:0;const struct jm_bar*a=&work->assigned.bars[g][b];r=work->assigned.record[work->assigned.selected[g]].identity.rid;
  if(b&&jma_add(work,r,0x10+4*(slot+1),in->saved[g][slot+1],a->pci>>32))return -1;
  if(jma_add(work,r,0x10+4*slot,in->saved[g][slot],(u32)a->pci|(in->saved[g][slot]&15)))return -1;
 }
 for(i=0;i<work->assigned.count;i++)if(work->end[i][0]||work->end[i][1]){
  r=work->assigned.record[i].identity.rid;for(k=0;k<4;k++)old[k]=in->bridge[i][k];
  if((old[0]&0x000f000f)||(old[1]&0x000f000f)!=0x10001)return -1;
  v[0]=((work->start[i][0]>>16)&0xfff0)|(work->end[i][0]&0xfff00000);
  v[1]=((work->start[i][1]>>16)&0xfff0)|(work->end[i][1]&0xfff00000)|0x10001;
  v[2]=work->start[i][1]>>32;v[3]=work->end[i][1]>>32;
  if(jma_add(work,r,0x20,old[0],v[0])||jma_add(work,r,0x2c,old[3],0)||
     jma_add(work,r,0x24,old[1],v[1])||jma_add(work,r,0x28,old[2],v[2])||
     jma_add(work,r,0x2c,old[3],v[3]))return -1;
 }
 *out=*work;return 0;
}
/* Original entry remains strict2/4 GB206, with no policy fallback. */
static int jma_build(const struct jma_input*in,struct jma_plan*out,struct jma_plan*work)
{return jma_build_policy(in,out,work,NULL);}
static int jma_build_mixed(const struct jma_input*in,struct jma_plan*out,struct jma_plan*work,const struct jmx_policy*policy)
{return policy?jma_build_policy(in,out,work,policy):-1;}
/* Executor is consumed before callback; first failure stops permanently.
 * The kernel adapter must provide owner/deadline/config gates in EVERY callback,
 * exact before/readback checks, and retain failed owners. No cleanup writes. */
struct jma_attempt {unsigned consumed,completed;int status;};
static int jma_execute(const struct jma_plan*p,struct jma_attempt*a,
 int(*write_checked)(void*,const struct jma_write*),void*ctx)
{unsigned i;int r;if(!p||!a||!write_checked||a->consumed||p->count>JMA_WRITES)return -1;
 a->consumed=1;a->status=-1;for(i=0;i<p->count;i++){
 r=write_checked(ctx,&p->writes[i]);if(r){a->status=r;return r;}a->completed++;
 }a->status=0;return 0;}
#endif
