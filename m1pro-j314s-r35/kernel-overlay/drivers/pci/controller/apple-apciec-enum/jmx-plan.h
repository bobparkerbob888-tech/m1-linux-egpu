/* Namespaced original planner. No existing jm_build caller changes. */
static int jmx_build(const struct jm_capture*c,const struct jmx_policy*policy,struct jm_plan*out)
{
 struct jm_plan p={0};unsigned used[JM_MAX_RECORDS]={0};unsigned i,j,k,g,r,root=JM_ROOT;
 if(!c||!out||!jmx_policy_valid(policy)||c->controller!=policy->controller||c->gpus!=policy->count||!c->count||c->count>JM_MAX_RECORDS||
    (c->gpus!=1&&c->gpus!=2&&c->gpus!=4&&c->gpus!=5))return -1;
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
  if(!jmx_identity(policy,g,id)||(id->class_rev>>16)!=0x0300||
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
