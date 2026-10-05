/* Include after target resource helpers + assignment-plan (ja_sample). */
/* Raw enumeration captures subsystem/DSN only for NVIDIA display functions.
 * Capture adds measured optional identity for all functions; retain that full
 * identity and require equality across all independently captured snapshots. */
static bool jma_k_raw_identity(const struct ep_identity *f,const struct ep_identity *r)
{
 if(f->rid!=r->rid||f->id!=r->id||f->class_rev!=r->class_rev||f->header!=r->header)return false;
 if((r->id&0xffff)==0x10de&&(r->class_rev>>24)==3)return ep_identity_equal(f,r);
 return !r->subsystem&&!r->serial;
}
static int jma_k_samples(const struct ep_function*a,const struct ep_function*b)
{
 unsigned i,j;u32 v;
 if(!ep_identity_equal(&a->identity,&b->identity)||a->command||b->command||
    a->sample_count>EP_MAX_SAMPLES||b->sample_count>EP_MAX_SAMPLES||
    a->buses!=b->buses||a->pcie!=b->pcie||a->msi!=b->msi||a->msix!=b->msix||
    a->devctl!=b->devctl||a->devctl2!=b->devctl2||a->acs_bits!=b->acs_bits||
    a->msix_control!=b->msix_control||a->msi_control!=b->msi_control)return -ESTALE;
 for(i=0;i<a->sample_count;i++){
  if(ja_sample(a,a->samples[i].offset,&v))return -EINVAL;
  for(j=0;j<b->sample_count;j++)if(a->samples[i].offset==b->samples[j].offset&&
    a->samples[i].value!=b->samples[j].value)return -ESTALE;
 }
 for(i=0;i<b->sample_count;i++)if(ja_sample(b,b->samples[i].offset,&v))return -EINVAL;
 return 0;
}
/* J314s host is a 2/2 simple-bus with intentionally empty ranges so its
 * physical DART child keeps an identity translation. These are the already
 * reviewed R15 target aperture constants, not generic PCI ranges or J293 data. */
#include "jmx-window-profile.h"
static int jma_k_windows(struct apple_apciec*p,struct jma_kernel_owner*o)
{
 struct device_node*np;const struct property*prop;
 static const unsigned source[2]={1,0}; /* nonpref32, pref64; omit pref32 */
 if(!p||!o||!p->dev||!p->profile||!apciec_profile_j314s(p->profile)||
    (p->j314s_mixed_policy?!jmx_binding(p,false):p->profile->index)||!j314s_profile_valid())return -EPERM;
 np=p->dev->of_node;
 if(j314s_node_index(np,3)!=(int)p->profile->index||of_find_property(np,"device_type",NULL)||
    apple_endpoint_aperture_cell(np,"#address-cells",2)||
    apple_endpoint_aperture_cell(np,"#size-cells",2))return -EPERM;
 prop=of_find_property(np,"ranges",NULL);
 if(!prop||prop->length)return -EPERM;
 for(unsigned w=0;w<2;w++){
  unsigned j=source[w];
  o->input.capture.window[w]=p->j314s_mixed_policy?jmx_windows[p->profile->index][w]:
   (struct jm_window){ja_window_pci[j],ja_window_cpu[j],ja_window_size[j]};
 }
 return 0;
}
static int jma_k_normalize(struct apple_apciec*p,struct jma_kernel_owner*o)
{
 struct j314s_multi_resource_owner*m=o->capture;struct jm_capture*c=&o->input.capture;
 struct ep_snapshot*base=m->snapshots[0];unsigned g,j,k,r,parent,b;u32 v;int ret;
 if(!base||!base->count||base->count>JM_MAX_RECORDS||base->count!=p->retained_record_count)return -EPERM;
 if(p->j314s_mixed_policy&&!jmx_binding(p,false))return -EPERM;
 c->controller=p->j314s_mixed_policy?p->profile->index:0;c->count=base->count;c->gpus=m->count;
 for(j=0;j<c->count;j++){
  const struct ep_function*f=&base->functions[j];struct jm_record*d=&c->record[j];
  if(!jma_k_raw_identity(&f->identity,&p->retained_records[j])||f->command){
   dev_err(p->dev,"jma-normalize: raw identity rid%04x id%08x/%08x class%08x/%08x header%x/%x subsystem%08x/%08x serial%016llx/%016llx command%x\n",
    f->identity.rid,f->identity.id,p->retained_records[j].id,
    f->identity.class_rev,p->retained_records[j].class_rev,
    f->identity.header,p->retained_records[j].header,
    f->identity.subsystem,p->retained_records[j].subsystem,
    (unsigned long long)f->identity.serial,(unsigned long long)p->retained_records[j].serial,f->command);
   return -ESTALE;
  }
  d->identity=(struct jm_identity){f->identity.rid,f->identity.id,f->identity.class_rev,
   f->identity.subsystem,f->identity.header,f->identity.serial};
  d->primary=f->buses&255;d->secondary=(f->buses>>8)&255;d->subordinate=(f->buses>>16)&255;
  d->parent=JM_ROOT;
  if(f->identity.rid){
   parent=JM_ROOT;
   for(k=0;k<c->count;k++)if((base->functions[k].identity.header&127)==1&&
     ((base->functions[k].buses>>8)&255)==(f->identity.rid>>8)){
    if(parent!=JM_ROOT)return -EINVAL;
    parent=k;
   }
   if(parent==JM_ROOT)return -EINVAL;
   d->parent=parent;
  }
  if((f->identity.header&127)==1)for(k=0;k<4;k++){
   ret=ja_sample(f,0x20+4*k,&o->input.bridge[j][k]);if(ret)return ret;
  }
 }
 for(g=0;g<m->count;g++){
  struct ep_snapshot*s=m->snapshots[g];const struct ep_function*f;
  const struct j314s_resource_owner*owner=m->owners[g];
  if(!owner||!owner->complete||owner->failed||owner->active||owner->status||
     owner->ticket!=o->ticket||owner->deadline!=o->deadline||
     !ep_identity_equal(&owner->selected,&m->selected[g])||
     !j314s_measured_dma_sample(&owner->dma_sample))return -EPERM;
  if(!s||!s->sized||s->planned||s->memory_assigned||s->count!=c->count||
     !j314s_ep_schema_limit(s,&m->selected[g],16)||(p->j314s_mixed_policy?!jmx_host_capture(p,g,s,&m->selected[g]):m->selected[g].id!=0x2d0410de))return -EPERM;
  for(j=0;j<c->count;j++){ret=jma_k_samples(&base->functions[j],&s->functions[j]);if(ret){
   const struct ep_function*a=&base->functions[j],*b=&s->functions[j];unsigned x,y;
   dev_err(p->dev,"jma-normalize: shared snapshot gpu%u rid%04x status%d\n",g,a->identity.rid,ret);
   for(x=0;x<a->sample_count&&x<EP_MAX_SAMPLES;x++)for(y=0;y<b->sample_count&&y<EP_MAX_SAMPLES;y++)
    if(a->samples[x].offset==b->samples[y].offset&&a->samples[x].value!=b->samples[y].value){
     dev_err(p->dev,"jma-normalize: mismatch rid%04x offset%03x before%08x after%08x\n",a->identity.rid,a->samples[x].offset,a->samples[x].value,b->samples[y].value);
     return ret;
    }
   return ret;
  }}
  f=&s->functions[s->selected];c->selected[g]=s->selected;
  if(f->msix){
   const u32 loc[2]={f->msix_table,f->msix_pba};unsigned entries=(f->msix_control&0x7ff)+1;
   const u64 length[2]={(u64)entries*16,((entries+63)/64)*8};
   if(ep_msix_overlap(f))return -EINVAL;
   for(j=0;j<2;j++){
    b=loc[j]&7;if(b>=6)return -EINVAL;
    if(s->bars[b].upper||s->bars[b].unsupported_io||!s->bars[b].size||
       length[j]>s->bars[b].size||(loc[j]&~7U)>s->bars[b].size-length[j])return -EINVAL;
   }
  }
  if(j314s_multi_io_slot(s,5,&m->selected[g])||s->bars[5].size||s->bars[5].pci||s->bars[5].cpu||
     !s->bars[5].unsupported_io||s->bars[5].flags!=EP_BAR_IO_UNASSIGNED)return -EINVAL;
  for(j=0;j<6;j++){
   ret=ja_sample(f,0x10+4*j,&v);if(ret||v!=s->bars[j].saved[0]){
    dev_err(p->dev,"jma-normalize: BAR gpu%u rid%04x offset%03x sample%08x saved%08x status%d\n",g,f->identity.rid,0x10+4*j,ret?0:v,s->bars[j].saved[0],ret);return -ESTALE;
   }
   o->input.saved[g][j]=v;o->input.mask[g][j]=s->bars[j].mask[0];
  }
  for(j=0;j<3;j++){
   b=j?2*j-1:0;
   if(s->bars[b].upper||s->bars[b].unsupported_io||!s->bars[b].size||
      s->bars[b].flags!=(j?(EP_BAR_64|EP_BAR_PREF):0))return -EINVAL;
   if(j){
    if(!s->bars[b+1].upper||s->bars[b+1].size||s->bars[b+1].pci||s->bars[b+1].cpu||
       s->bars[b].saved[1]!=s->bars[b+1].saved[0])return -EINVAL;
    o->input.mask[g][b+1]=s->bars[b].mask[1];
   }
   c->bars[g][j]=(struct jm_bar){0,0,s->bars[b].size,j?1U:0U};
  }
  /* Independently validate every explicit ancestor edge against raw tree. */
  r=s->selected;
  for(j=0;j<s->ancestor_count;j++){
   if(c->record[r].parent!=s->ancestors[j]){
    dev_err(p->dev,"jma-normalize: ancestor gpu%u rid%04x depth%u raw-parent%u captured-parent%u\n",g,c->record[r].identity.rid,j,c->record[r].parent,s->ancestors[j]);return -ESTALE;
   }
   r=s->ancestors[j];
  }
  if(c->record[r].identity.rid||c->record[r].parent!=JM_ROOT){
   dev_err(p->dev,"jma-normalize: terminal gpu%u rid%04x parent%u\n",g,c->record[r].identity.rid,c->record[r].parent);return -ESTALE;
  }
 }
 return jma_k_windows(p,o);
}
