/* Target-only PCI object creation over the frozen assigned selected path. */
static int j314s_nd_read(struct apple_apciec*p,unsigned rid,unsigned off,unsigned width,u32*v)
{
 struct pci_bus bus={.number=rid>>8,.sysdata=p,.ops=&apple_apciec_ops};
 return apple_apciec_config_read(&bus,rid&255,off,width,v)?-EIO:0;
}
static int j314s_nd_hardware(struct apple_apciec*p)
{
 struct j314s_native_context*n=p->j314s_native;unsigned j;u32 v;int ret;
 const struct ja_plan*plan=&p->j314s_assignment->plan;
 if(!j314s_native_actor(p)||n->probe.pending)return -EPERM;
 ret=retained_dma_blocked(p);if(ret)return ret;
 for(j=0;j<n->layout.count;j++) {
  const struct ep_function*f=j314s_native_function(p,n->layout.rid[j]);
  ret=j314s_nd_read(p,f->identity.rid,0,4,&v);if(ret||v!=f->identity.id)return ret?ret:-ESTALE;
  ret=j314s_nd_read(p,f->identity.rid,4,2,&v);
  if(ret||v!=j314s_native_command(n,f->identity.rid))return ret?ret:-EPERM;
  ret=j314s_nd_read(p,f->identity.rid,8,4,&v);if(ret||v!=f->identity.class_rev)return ret?ret:-ESTALE;
  ret=j314s_nd_read(p,f->identity.rid,f->pcie+PCI_EXP_DEVCTL2,2,&v);
  if(ret||(v&PCI_EXP_DEVCTL2_ARI))return ret?ret:-EPERM;
  if(j==n->layout.selected) {
   unsigned ari,sriov;
   if(!j314s_capabilities_disabled(f)||j314s_cap_offsets(f,&ari,&sriov))return -EPERM;
   if(ari){ret=j314s_nd_read(p,f->identity.rid,ari+4,4,&v);if(ret||(v>>16))return ret?ret:-EPERM;}
   if(sriov){
    ret=j314s_nd_read(p,f->identity.rid,sriov+8,4,&v);if(ret||(v&65535))return ret?ret:-EPERM;
    ret=j314s_nd_read(p,f->identity.rid,sriov+0x10,4,&v);if(ret||(v&65535))return ret?ret:-EPERM;
   }
  }
  if(f->serial_present) {
   u32 hi,lo;ret=j314s_nd_read(p,f->identity.rid,f->serial_offset+4,4,&lo);
   if(!ret)ret=j314s_nd_read(p,f->identity.rid,f->serial_offset+8,4,&hi);
   if(ret||(((u64)hi<<32)|lo)!=f->identity.serial)return ret?ret:-ESTALE;
  }
 }
 for(j=0;j<plan->count;j++) {
  const struct ja_register*r=&plan->regs[j];
  ret=j314s_nd_read(p,r->rid,r->offset,4,&v);if(ret||v!=r->after)return ret?ret:-ESTALE;
 }
 return j314s_native_actor(p)?0:-ETIMEDOUT;
}
static int j314s_nd_device(struct apple_apciec*p,unsigned index)
{
 struct j314s_native_context*n=p->j314s_native;struct pci_dev*d=n->devices[index];
 const struct ep_function*f=j314s_native_function(p,n->layout.rid[index]);
 if(!d||!f||pci_dev_id(d)!=f->identity.rid||d->vendor!=(f->identity.id&65535)||
    d->device!=(f->identity.id>>16)||d->class!=(f->identity.class_rev>>8)||
    d->revision!=(f->identity.class_rev&255)||d->hdr_type!=(f->identity.header&127)||
    d->multifunction!=!!(f->identity.header&128)||d->driver||d->dev.driver||
    !d->non_mappable_bars||d->is_busmaster||pci_num_vf(d)||d->is_virtfn||d->ari_enabled||
    dev_iommu_fwspec_get(&d->dev)||d->dev.iommu_group||!device_is_registered(&d->dev)||
    pci_find_host_bridge(d->bus)!=p->discovery_bridge||!p->discovery_bridge->discovery_only)
  return -EPERM;
 if(!d->hdr_type&&(((u32)d->subsystem_device<<16)|d->subsystem_vendor)!=f->identity.subsystem)
  return -ESTALE;
 return 0;
}
/* Audit the complete claims created below, including no unexpected siblings.
 * Before driver binding, there may be no child claim underneath a GPU BAR. */
static int j314s_nd_claims(struct apple_apciec*p,bool claim)
{
 struct j314s_native_context*n=p->j314s_native;const struct ep_snapshot*s=p->endpoint_snapshot;
 struct resource*parent[3];unsigned w,j,b;int ret;
 if(j314s_assignment_owner_valid(p,false))return -EPERM;
 for(w=0;w<3;w++)parent[w]=&p->j314s_assignment->resources[w];
 for(j=0;j<n->layout.selected;j++) {
  const struct ep_bridge_plan*bp=&s->bridges[s->ancestor_count-1-j];
  struct pci_dev*d=n->devices[j];
  if(!d||bp->rid!=n->layout.rid[j]||bp->active[0]+bp->active[2]>1)return -EPERM;
  for(w=0;w<3;w++) {
   struct resource*r=&d->resource[w==1?PCI_BRIDGE_MEM_WINDOW:PCI_BRIDGE_PREF_MEM_WINDOW];
   u64 delta=p->j314s_assignment->entries[w]->offset;
   if(!bp->active[w])continue;
   if(r->start!=bp->start[w]+delta||r->end!=bp->end[w]+delta||
      !(r->flags&IORESOURCE_MEM)||!!(r->flags&IORESOURCE_PREFETCH)!=(w!=1)||
      (r->flags&(IORESOURCE_UNSET|IORESOURCE_DISABLED)))return -ESTALE;
   if(claim){if(r->parent)return -EPERM;ret=pci_claim_resource(d,r-d->resource);if(ret)return ret;}
   if(r->parent!=parent[w]||parent[w]->child!=r||r->sibling)return -EPERM;
   parent[w]=r;
  }
 }
 for(b=0;b<6;b++) {
  const struct ep_bar*x=&s->bars[b];struct resource*r=&n->devices[n->layout.selected]->resource[b];
  if(x->upper){if(r->flags||r->parent)return -EPERM;continue;}
  if(x->unsupported_io||!x->size){if(r->parent)return -EPERM;continue;}
  w=x->window;if(w>2||r->start!=x->cpu||resource_size(r)!=x->size||
    !(r->flags&IORESOURCE_MEM)||!!(r->flags&IORESOURCE_MEM_64)!=!!(x->flags&EP_BAR_64)||
    !!(r->flags&IORESOURCE_PREFETCH)!=!!(x->flags&EP_BAR_PREF)||
    (r->flags&(IORESOURCE_UNSET|IORESOURCE_DISABLED)))return -ESTALE;
  if(claim){if(r->parent)return -EPERM;ret=pci_claim_resource(n->devices[n->layout.selected],b);if(ret)return ret;}
  if(r->parent!=parent[w]||r->child)return -EPERM;
 }
 for(w=0;w<3;w++) {
  struct resource*r=parent[w]->child;unsigned actual=0,expected=0;
  for(b=0;b<6;b++)if(s->bars[b].size&&s->bars[b].window==w)expected++;
  for(;r;r=r->sibling) {
   if(++actual>6)return -EPERM;
   for(b=0;b<6;b++)if(s->bars[b].size&&s->bars[b].window==w&&
     r==&n->devices[n->layout.selected]->resource[b])break;
   if(b==6)return -EPERM;
  }
  if(actual!=expected)return -EPERM;
 }
 if(n->devices[n->layout.selected]->resource[PCI_ROM_RESOURCE].parent)return -EPERM;
 return 0;
}
int apple_apciec_j314s_discover(struct device*,unsigned,const void*,unsigned*);
int apple_apciec_j314s_discover(struct device*dev,unsigned port,const void*ticket,unsigned*phase)
{
 struct apple_apciec*p=dev_get_drvdata(dev);struct j314s_native_context*n;
 struct resource_entry*e;struct pci_bus*bus;unsigned j;unsigned long flags;int ret;
 if(!p||!phase)return -EINVAL;
 mutex_lock(&p->lifecycle);
 ret=retained_commit_owner(p,port,ticket,14);if(ret)goto out;
 if(!apciec_profile_j314s(p->profile)||p->profile->index||p->j314s_native||
    p->discovery_bridge||!p->j314s_assignment||!p->j314s_assignment->complete||
    p->j314s_assignment->status||p->j314s_assignment->execution!=p->j314s_assignment->plan.step_count||
    !p->endpoint_snapshot||!p->endpoint_snapshot->memory_assigned||j314s_assignment_owner_valid(p,true)||
    of_find_property(p->dev->of_node,"iommu-map",NULL)){ret=-EPERM;goto out;}
 n=kzalloc(sizeof(*n),GFP_KERNEL);if(!n){ret=-ENOMEM;goto out;}
 p->j314s_native=n;n->attempted=true;n->ticket=ticket;n->status=-EINPROGRESS;
 if(!j314s_ep_schema(p->endpoint_snapshot,&p->j314s_resource->selected)){ret=-EPERM;goto fail;}
 ret=j314s_native_layout_build(p->endpoint_snapshot,&n->layout);if(ret)goto fail;
 n->deadline=min(ktime_get_boottime_ns()+10ULL*NSEC_PER_SEC,p->retained_identity_deadline);
 if(n->deadline<=ktime_get_boottime_ns()+2ULL*NSEC_PER_SEC){ret=-ETIMEDOUT;goto fail;}
 p->retained_phase=15;
 raw_spin_lock_irqsave(&p->lock,flags);n->task=current;raw_spin_unlock_irqrestore(&p->lock,flags);
 ret=j314s_nd_hardware(p);if(ret)goto close;
 INIT_LIST_HEAD(&p->discovery_windows);
 n->bus_resource=(struct resource){.name="J314s selected captured buses",.start=0,.end=n->layout.max_bus,.flags=IORESOURCE_BUS};
 for(j=0;j<4;j++) {
  e=resource_list_create_entry(j<3?&p->j314s_assignment->resources[j]:&n->bus_resource,0);
  if(!e){ret=-ENOMEM;goto close;}
  if(j<3)e->offset=p->j314s_assignment->entries[j]->offset;
  resource_list_add_tail(e,&p->discovery_windows);
 }
 pci_lock_rescan_remove();
 bus=pci_create_root_bus(p->dev,0,&apple_apciec_ops,p,&p->discovery_windows);
 if(!bus){ret=-ENODEV;goto unlock;}
 n->buses[0]=bus;p->discovery_bridge=pci_find_host_bridge(bus);
 p->discovery_bridge->discovery_only=true;
 p->discovery_bridge->native_aer=false;p->discovery_bridge->native_pcie_hotplug=false;
 p->discovery_bridge->native_pme=false;p->discovery_bridge->native_dpc=false;
 if(bus->busn_res.start||bus->busn_res.end!=n->layout.max_bus||!bus->busn_res.parent){ret=-EPERM;goto unlock;}
 for(j=0;j<n->layout.count;j++) {
  const struct ep_function*f=j314s_native_function(p,n->layout.rid[j]);
  ret=j314s_nd_hardware(p);if(ret)goto unlock;
  bus=n->buses[n->layout.rid[j]>>8];if(!bus){ret=-EPERM;goto unlock;}
  n->devices[j]=pci_scan_single_device(bus,n->layout.rid[j]&255);
  ret=j314s_nd_device(p,j);if(!ret)ret=j314s_nd_hardware(p);if(ret)goto unlock;
  if(j<n->layout.selected) {
   unsigned secondary=(f->buses>>8)&255,subordinate=(f->buses>>16)&255;
   if(n->buses[secondary]){ret=-EPERM;goto unlock;}
   bus=pci_add_new_bus(bus,n->devices[j],secondary);if(!bus){ret=-ENOMEM;goto unlock;}
   n->buses[secondary]=bus;
   if(!pci_bus_insert_busn_res(bus,secondary,subordinate)){ret=-EBUSY;goto unlock;}
   pci_read_bridge_bases(bus);
  }
 }
 ret=j314s_nd_claims(p,true);if(!ret)ret=j314s_nd_claims(p,false);
 if(!ret)ret=j314s_nd_hardware(p);
 for(j=0;!ret&&j<n->layout.count;j++)ret=j314s_nd_device(p,j);
unlock:pci_unlock_rescan_remove();
close:
 if(!ret&&(!j314s_native_actor(p)||n->probe.pending))ret=-EPERM;
 raw_spin_lock_irqsave(&p->lock,flags);n->task=NULL;raw_spin_unlock_irqrestore(&p->lock,flags);
 if(ret)goto fail;
 n->discovered=true;n->status=0;p->retained_phase=16;goto out;
fail:n->failed=true;n->status=ret;p->retained_failed=true;
out:*phase=p->retained_phase;mutex_unlock(&p->lifecycle);return ret;
}
EXPORT_SYMBOL_GPL(apple_apciec_j314s_discover);
