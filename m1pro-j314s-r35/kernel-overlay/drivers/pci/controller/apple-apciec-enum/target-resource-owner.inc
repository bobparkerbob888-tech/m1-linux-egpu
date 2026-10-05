/* Exact controller1 CPU resource ownership, retained until normal shutdown. */
static const struct as_aperture tn_apertures[3]={
 {.flags=0x43000000,.pci=0x580000000ULL,.cpu=0x580000000ULL,.size=0x80000000ULL},
 {.flags=0x02000000,.pci=0x00100000ULL,.cpu=0x600100000ULL,.size=0x3ff00000ULL},
 {.flags=0x42000000,.pci=0x40000000ULL,.cpu=0x640000000ULL,.size=0x40000000ULL}
};
static int tn_aperture_descriptor(struct apple_apciec *p)
{
 static const u32 expected[3][7]={
  {0x43000000,5,0x80000000,5,0x80000000,0,0x80000000},
  {0x02000000,0,0x100000,6,0x100000,0,0x3ff00000},
  {0x42000000,0,0x40000000,6,0x40000000,0,0x40000000}};
 struct device_node *np=p->dev->of_node,*exact;
 const struct property *prop;const __be32 *cells;unsigned j,k;bool same;
 if(!p->profile||p->profile->index!=1)return -EPERM;
 exact=of_find_node_by_path("/soc/apciec@530000000");same=np==exact;of_node_put(exact);
 if(!same || of_find_property(np,"device_type",NULL) ||
  apple_endpoint_aperture_cell(np,"#address-cells",2) ||
  apple_endpoint_aperture_cell(np,"#size-cells",2))return -EPERM;
 prop=of_find_property(np,"ranges",NULL);if(!prop||prop->length)return -EPERM;
 prop=of_find_property(np,"research,apciec-bar-windows",NULL);
 if(!prop||!prop->value||prop->length!=sizeof(expected))return -EPERM;
 cells=prop->value;
 for(j=0;j<3;j++)for(k=0;k<7;k++)if(be32_to_cpup(cells+j*7+k)!=expected[j][k])return -EPERM;
 return 0;
}
static int tn_owner_validate(struct apple_apciec *p)
{
 const unsigned long flags[3]={IORESOURCE_MEM|IORESOURCE_PREFETCH|IORESOURCE_MEM_64,IORESOURCE_MEM,IORESOURCE_MEM|IORESOURCE_PREFETCH};
 struct as_owner *o=p->endpoint_owner;unsigned j;
 if(!p->profile||p->profile->index!=1||!o||!o->attempted||!o->ready||o->failed)return -EPERM;
 for(j=0;j<3;j++) {
  const struct as_aperture *a=&tn_apertures[j];struct resource *r=&o->resources[j];
  struct resource_entry *e=o->entries[j];
  if(!o->reserved[j]||!e||r->parent!=&iomem_resource||r->start!=a->cpu||
   r->end!=a->cpu+a->size-1||r->flags!=flags[j]||e->res!=r||e->offset!=a->cpu-a->pci)return -EPERM;
  if(e->node.prev!=(j?&o->entries[j-1]->node:&o->private_windows)||
   e->node.next!=(j==2?&o->private_windows:&o->entries[j+1]->node))return -EPERM;
 }
 if(o->private_windows.next!=&o->entries[0]->node||o->private_windows.prev!=&o->entries[2]->node)return -EPERM;
 return 0;
}
static int tn_owner_prepare(struct ep_context *c)
{
 struct apple_apciec *p=c->p;struct as_owner *o;unsigned j;int r;
 const unsigned long flags[3]={IORESOURCE_MEM|IORESOURCE_PREFETCH|IORESOURCE_MEM_64,IORESOURCE_MEM,IORESOURCE_MEM|IORESOURCE_PREFETCH};
 if(p->endpoint_owner||p->endpoint_assignment_attempted||c->phase!=11)return -EPERM;
 p->endpoint_assignment_attempted=true;p->retained_phase=13;c->phase=13;
 o=kzalloc(sizeof(*o),GFP_KERNEL);p->endpoint_owner=o;if(!o)return -ENOMEM;
 o->attempted=true;INIT_LIST_HEAD(&o->private_windows);
 for(j=0;j<3;j++) {
  const struct as_aperture *a=&tn_apertures[j];
  if(!retained_ep_valid(c)||(r=retained_ep_budget(p,2ULL*NSEC_PER_SEC,2048)))return -EPERM;
  o->resources[j]=(struct resource){.name="J293 controller1 retained aperture",.start=a->cpu,.end=a->cpu+a->size-1,.flags=flags[j]};
  o->entries[j]=resource_list_create_entry(&o->resources[j],0);if(!o->entries[j])return -ENOMEM;
  o->entries[j]->offset=a->cpu-a->pci;resource_list_add_tail(o->entries[j],&o->private_windows);
  if(request_resource_conflict(&iomem_resource,&o->resources[j]))return -EBUSY;
  o->reserved[j]=true;
 }
 o->ready=true;return tn_owner_validate(p);
}
