static int jmc_claim_tree(struct jmn_kernel*k,bool claim)
{
 const struct jma_kernel_owner*o=k->assignment_receipt;
 struct resource**objects=k->config->claim_objects,**parents=k->config->claim_parents;
 unsigned count=0,j,w,g,b,x,y;int ret;
 lockdep_assert_held(&k->p->lifecycle);
 if(!o)return jmc_refusal(k,"claims-receipt",64,0,0,0,-EPERM);
 ret=jma_kernel_owner_valid(k->p,false);if(ret)return jmc_refusal(k,"claims-owner",64,0,ret,0,-EPERM);
 if(&o->plan!=k->joint)return jmc_refusal(k,"claims-plan",64,0,0,0,-EPERM);
 for(j=0;j<k->owner.plan.path_count;j++){
  unsigned index=k->owner.plan.path[j],parent=k->joint->assigned.record[index].parent;
  struct pci_dev*d=k->devices[index];if(!d)return jmc_refusal(k,"claims-device",index,0,0,0,-EPERM);
  if(jmc_client(k,index)>=0)continue;
  if(parent!=JM_ROOT&&(parent>=JM_MAX_RECORDS||!k->devices[parent]))return jmc_refusal(k,"claims-parent",index,0,parent,0,-EPERM);
  for(w=0;w<2;w++){
   struct resource*r=&d->resource[w?PCI_BRIDGE_PREF_MEM_WINDOW:PCI_BRIDGE_MEM_WINDOW];
   struct resource*p=parent==JM_ROOT?(struct resource*)&o->resources[w]:
    &k->devices[parent]->resource[w?PCI_BRIDGE_PREF_MEM_WINDOW:PCI_BRIDGE_MEM_WINDOW];
   u64 delta=o->entries[w]->offset;
   if(!o->plan.end[index][w]||r->start!=o->plan.start[index][w]+delta||
      r->end!=o->plan.end[index][w]+delta||!(r->flags&IORESOURCE_MEM)||
      !!(r->flags&IORESOURCE_PREFETCH)!=!!w||r->flags&(IORESOURCE_UNSET|IORESOURCE_DISABLED))return -ESTALE;
   objects[count]=r;parents[count++]=p;
  }
 }
 for(g=0;g<k->owner.plan.count;g++){
  unsigned index=k->owner.plan.client[g].index,parent=k->joint->assigned.record[index].parent,source;
  struct pci_dev*d=k->selected[g];if(!d||parent>=JM_MAX_RECORDS||!k->devices[parent])return jmc_refusal(k,"claims-selected",index,0,parent,g,-EPERM);
  for(source=0;source<o->capture->count;source++)if(o->capture->snapshots[source]->selected==index)break;
  if(source==o->capture->count)return -ESTALE;
  for(b=0;b<6;b++){
   const struct ep_bar*a=&o->capture->snapshots[source]->bars[b];struct resource*r=&d->resource[b];
   if(a->upper){if(r->flags||r->parent)return -ESTALE;continue;}
   if(a->unsupported_io){if(r->parent||r->start||(r->flags&IORESOURCE_MEM))return -ESTALE;continue;}
   if(!a->size){if(r->parent)return -ESTALE;continue;}
   w=a->window==0?1:0;
   if(a->window>1||r->start!=a->cpu||resource_size(r)!=a->size||!(r->flags&IORESOURCE_MEM)||
      !!(r->flags&IORESOURCE_MEM_64)!=!!(a->flags&EP_BAR_64)||
      !!(r->flags&IORESOURCE_PREFETCH)!=!!w||(r->flags&(IORESOURCE_UNSET|IORESOURCE_DISABLED))||
      (!k->owner.complete&&r->child))return -ESTALE;
   objects[count]=r;parents[count++]=&k->devices[parent]->resource[w?PCI_BRIDGE_PREF_MEM_WINDOW:PCI_BRIDGE_MEM_WINDOW];
  }
  if(d->resource[PCI_ROM_RESOURCE].parent)return jmc_refusal(k,"claims-rom",index,0,1,0,-EPERM);
 }
 for(x=0;x<count;x++){
  if(claim){if(!jmc_actor(k)||objects[x]->parent)return -EPERM;
   if(request_resource_conflict(parents[x],objects[x]))return -EBUSY;}
  if(objects[x]->parent!=parents[x])return -ESTALE;
 }
 /* Every child of every owned forwarding aperture must be one exact object. */
 for(x=0;x<count;x++){
  struct resource*r=parents[x]->child;unsigned seen=0,expected=0;
  for(y=0;y<count;y++)if(parents[y]==parents[x])expected++;
  for(;r;r=r->sibling){if(++seen>count)return -ESTALE;
   for(y=0;y<count;y++)if(objects[y]==r&&parents[y]==parents[x])break;
   if(y==count)return -ESTALE;}
  if(seen!=expected)return -ESTALE;
 }
 ret=jma_kernel_owner_valid(k->p,false);return ret?jmc_refusal(k,"claims-owner-final",64,0,ret,0,ret):0;
}
static int jmn_callback_claims_audit(struct jmn_kernel*k)
{return k&&k->config&&k->config->claimed?jmc_claim_tree(k,false):-EPERM;}
static int jmc_claims(struct jmn_kernel*k)
{
 int ret;if(!jmc_actor(k)||k->config->claims_attempted)return -EPERM;
 k->config->claims_attempted=true;ret=jmc_claim_tree(k,true);
 if(!ret)k->config->claimed=true;
 return ret;
}
