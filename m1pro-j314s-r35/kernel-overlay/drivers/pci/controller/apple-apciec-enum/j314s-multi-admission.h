/* SPDX-License-Identifier: GPL-2.0 */
#ifndef J314S_MULTI_ADMISSION_H
#define J314S_MULTI_ADMISSION_H
/* Pure planning only. u32/u64 must be supplied by kernel or test harness.
 * Inputs are copied by the owner from one frozen, fully audited capture.
 * This cannot establish capture provenance, capability controls, ACS, or DMA
 * ownership. No result here authorizes hardware access or publication. */
#define JM_MAX_RECORDS 64
#define JM_MAX_GPUS 5
#define JM_ROOT 64
struct jm_identity { u32 rid,id,class_rev,subsystem,header; u64 serial; };
struct jm_record {
 struct jm_identity identity;
 unsigned parent; /* capture index, JM_ROOT only for root bridge */
 unsigned primary,secondary,subordinate;
};
struct jm_bar { u64 pci,cpu,size; unsigned window; };
struct jm_window { u64 pci,cpu,size; };
struct jm_capture {
 unsigned controller,count,gpus;
 struct jm_record record[JM_MAX_RECORDS];
 unsigned selected[JM_MAX_GPUS];
 struct jm_bar bars[JM_MAX_GPUS][3]; /* actual BAR0, BAR1, BAR3 */
 struct jm_window window[2]; /* independently owned nonprefetch/prefetch */
};
struct jm_client { struct jm_identity identity; unsigned index,sid; };
struct jm_plan {
 unsigned count,path_count;
 unsigned path[JM_MAX_RECORDS]; /* union of selected ancestors, root first */
 struct jm_client client[JM_MAX_GPUS]; /* ascending captured RID */
 u32 rid2sid[64]; /* every unselected entry remains zero */
};
static int jm_equal(const struct jm_identity*a,const struct jm_identity*b)
{return a->rid==b->rid&&a->id==b->id&&a->class_rev==b->class_rev&&
 a->subsystem==b->subsystem&&a->header==b->header&&a->serial==b->serial;}
static int jm_range(u64 start,u64 size)
{return size && start<=~(u64)0-(size-1);}
static int jm_overlap(u64 a,u64 as,u64 b,u64 bs)
{return a<=b+bs-1 && b<=a+as-1;}
static int jm_build(const struct jm_capture*c,struct jm_plan*out)
{
 struct jm_plan p={0};unsigned used[JM_MAX_RECORDS]={0};unsigned i,j,k,g,r,root=JM_ROOT;
 if(!c||!out||c->controller||!c->count||c->count>JM_MAX_RECORDS||
    (c->gpus!=2&&c->gpus!=4))return -1;
 for(i=0;i<2;i++)if(!jm_range(c->window[i].pci,c->window[i].size)||
    !jm_range(c->window[i].cpu,c->window[i].size))return -1;
 if(jm_overlap(c->window[0].pci,c->window[0].size,c->window[1].pci,c->window[1].size)||
    jm_overlap(c->window[0].cpu,c->window[0].size,c->window[1].cpu,c->window[1].size))return -1;
 for(i=0;i<c->count;i++) {
  const struct jm_record*f=&c->record[i];
  if(f->identity.rid>65535||f->identity.header>255)return -1;
  for(j=0;j<i;j++)if(f->identity.rid==c->record[j].identity.rid)return -1;
  if(f->parent==JM_ROOT){if(root!=JM_ROOT||f->identity.rid)return -1;root=i;}
  else if(f->parent>=c->count)return -1;
 }
 if(root==JM_ROOT)return -1;
 for(g=0;g<c->gpus;g++) {
  const struct jm_identity*id;
  i=c->selected[g];if(i>=c->count)return -1;id=&c->record[i].identity;
  if(id->id!=0x2d0410de||(id->class_rev>>16)!=0x0300||
     (id->header&127)||!id->rid||(id->rid&7)||!id->serial||id->serial==~(u64)0)return -1;
  for(j=0;j<g;j++)if(c->selected[j]==i||c->record[c->selected[j]].identity.serial==id->serial)return -1;
  p.client[g].identity=*id;p.client[g].index=i;
  for(k=0;k<c->count;k++) {
   const struct jm_record*f=&c->record[i];used[i]=1;
   if(i==root)break;
   r=f->parent;if(r>=c->count)return -1;
   f=&c->record[r];
   if((f->identity.class_rev>>16)!=0x0604||(f->identity.header&127)!=1||
      f->primary!=(f->identity.rid>>8)||f->secondary!=(c->record[i].identity.rid>>8)||
      f->secondary<=f->primary||f->subordinate<f->secondary||f->subordinate>255||
      f->subordinate<(id->rid>>8))return -1;
   i=r;
  }
  if(k==c->count)return -1;
  for(j=0;j<3;j++) {
   const struct jm_bar*b=&c->bars[g][j];const struct jm_window*w;
   if(b->window!=(j?1U:0U)||!jm_range(b->pci,b->size)||!jm_range(b->cpu,b->size)||
      (b->size&(b->size-1))||(b->pci&(b->size-1)))return -1;
   w=&c->window[b->window];
   if(b->pci<w->pci||b->size>w->size||b->pci-w->pci>w->size-b->size||
      b->cpu!=w->cpu+(b->pci-w->pci))return -1;
   for(i=0;i<=g;i++)for(k=0;k<3;k++) {
    const struct jm_bar*a=&c->bars[i][k];if(i==g&&k>=j)break;
    if(jm_overlap(a->pci,a->size,b->pci,b->size)||jm_overlap(a->cpu,a->size,b->cpu,b->size))return -1;
   }
  }
 }
 /* Bus-monotonic validated paths yield parent-first ordering. */
 for(i=0;i<c->count;i++)if(used[i]) {
  j=p.path_count++;while(j&&c->record[p.path[j-1]].identity.rid>c->record[i].identity.rid){p.path[j]=p.path[j-1];j--;}
  p.path[j]=i;
 }
 p.count=c->gpus;
 for(i=1;i<p.count;i++){struct jm_client x=p.client[i];j=i;while(j&&p.client[j-1].identity.rid>x.identity.rid){p.client[j]=p.client[j-1];j--;}p.client[j]=x;}
 for(i=0;i<p.count;i++){p.client[i].sid=i+1;p.rid2sid[i+1]=0x80000000U|((i+1)<<16)|p.client[i].identity.rid;}
 *out=p;return 0;
}
/* Caller matches the exact sealed pci_dev, host and capture before this check.
 * Exactly one self alias per selected client; no bridge/audio aliases. */
static int jm_alias(const struct jm_plan*p,unsigned client,const struct jm_identity*id,
 unsigned alias,unsigned previous)
{return p&&id&&p->count<=JM_MAX_GPUS&&client<p->count&&!previous&&
 jm_equal(&p->client[client].identity,id)&&alias==id->rid?0:-1;}
static int jm_rid_table(const struct jm_plan*p,const u32 actual[64])
{unsigned i;if(!p||!actual||(p->count!=2&&p->count!=4))return -1;
 for(i=0;i<64;i++)if(p->rid2sid[i]!=actual[i])return -1;
 return 0;}
#endif
