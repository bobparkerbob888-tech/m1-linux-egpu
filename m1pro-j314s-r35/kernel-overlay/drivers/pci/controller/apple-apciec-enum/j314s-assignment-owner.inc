/* Exact CPU ownership, retained across any error. No rollback or publication. */
static const u64 ja_window_pci[3]={0x800000000ULL,0x100000ULL,0x40000000ULL};
static const u64 ja_window_cpu[3]={0x800000000ULL,0xa00100000ULL,0xa40000000ULL};
static const u64 ja_window_size[3]={0x200000000ULL,0x3ff00000ULL,0x40000000ULL};
static const unsigned long ja_window_flags[3]={
 IORESOURCE_MEM|IORESOURCE_PREFETCH|IORESOURCE_MEM_64,
 IORESOURCE_MEM,IORESOURCE_MEM|IORESOURCE_PREFETCH};
static int j314s_assignment_owner_valid(struct apple_apciec*p,bool require_empty)
{
 struct j314s_assignment_owner*o=p->j314s_assignment;unsigned j;
 if(!apciec_profile_j314s(p->profile)||p->profile->index||!o||!o->attempted||
    !o->ready||o->failed||!o->plan.built||o->ticket!=p->retained_ticket||
    o->deadline!=p->retained_scan_deadline||!p->j314s_resource||
    !ep_identity_equal(&o->plan.selected,&p->j314s_resource->selected))return -EPERM;
 for(j=0;j<3;j++){
  const struct resource*r=&o->resources[j];const struct resource_entry*e=o->entries[j];
  if(!o->reserved[j]||!e||r->parent!=&iomem_resource||(require_empty&&r->child)||
     r->start!=ja_window_cpu[j]||r->end!=ja_window_cpu[j]+ja_window_size[j]-1||
     r->flags!=ja_window_flags[j]||e->res!=r||e->offset!=ja_window_cpu[j]-ja_window_pci[j])return -EPERM;
 }
 if(o->private_windows.next!=&o->entries[0]->node||o->private_windows.prev!=&o->entries[2]->node)return -EPERM;
 for(j=0;j<3;j++)if(o->entries[j]->node.prev!=(j?&o->entries[j-1]->node:&o->private_windows)||
  o->entries[j]->node.next!=(j==2?&o->private_windows:&o->entries[j+1]->node))return -EPERM;
 return 0;
}
