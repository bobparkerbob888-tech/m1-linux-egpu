/* Target-only callbacks. Include after native-host.inc for reviewed generic
 * PCI discovery probes and driver write policy; never use its fixed RID set. */
static const struct ep_function *j314s_native_function(struct apple_apciec*p,unsigned rid)
{
 struct j314s_native_context*n=p?p->j314s_native:NULL;unsigned j;
 if(!n||!p->endpoint_snapshot)return NULL;
 for(j=0;j<n->layout.count;j++)if(n->layout.rid[j]==rid)
  return &p->endpoint_snapshot->functions[n->layout.index[j]];
 return NULL;
}
static struct pci_dev *j314s_native_selected(struct apple_apciec*p)
{
 struct j314s_native_context*n=p?p->j314s_native:NULL;
 return n&&n->layout.count&&n->layout.selected<n->layout.count?
  n->devices[n->layout.selected]:NULL;
}
static struct pci_host_bridge *j314s_native_bridge(struct apple_apciec*p)
{return p?p->discovery_bridge:NULL;}
static bool j314s_native_target_identity(struct apple_apciec*p)
{
 struct j314s_native_context*n=p?p->j314s_native:NULL;
 struct pci_dev*d=j314s_native_selected(p);const struct ep_function*f;
 if(!n||n->failed||!n->discovered||!d||!p->discovery_bridge||
    !p->discovery_bridge->discovery_only)return false;
 f=j314s_native_function(p,pci_dev_id(d));
 return f&&pci_dev_id(d)==n->layout.rid[n->layout.selected]&&
  d->vendor==(f->identity.id&65535)&&d->device==(f->identity.id>>16)&&
  d->class==(f->identity.class_rev>>8)&&d->revision==(f->identity.class_rev&255)&&
  d->hdr_type==(f->identity.header&127)&&d->multifunction==!!(f->identity.header&128)&&
  (((u32)d->subsystem_device<<16)|d->subsystem_vendor)==f->identity.subsystem&&
  pci_find_host_bridge(d->bus)==p->discovery_bridge&&
  (!p->native||p->native->target==d);
}
static unsigned j314s_native_command(struct j314s_native_context*n,unsigned rid)
{
 unsigned j;for(j=0;j<n->layout.count;j++)if(n->layout.rid[j]==rid)
  return n->mmio_enabled&BIT(j)?j==n->layout.selected?PCI_COMMAND_MEMORY:
   PCI_COMMAND_MEMORY|PCI_COMMAND_MASTER:0;
 return 0;
}
static bool j314s_native_actor(struct apple_apciec*p)
{
 struct j314s_native_context*n=p->j314s_native;
 return n&&n->attempted&&!n->failed&&n->ticket==p->retained_ticket&&
  n->task==current&&n->deadline&&n->deadline<=p->retained_identity_deadline&&
  ktime_get_boottime_ns()<n->deadline&&n->ops<=16384-3&&
  !p->retained_failed&&p->j314s_raw_capability&&p->power_ready&&p->tunnel_ready;
}
/* Called under the host config lock by the ECAM mapper as well as dispatch.
 * Target context never borrows broad legacy native-active mapping admission. */
static bool j314s_native_map_permit(struct apple_apciec*p,unsigned rid)
{
 struct j314s_native_context*n=p?p->j314s_native:NULL;
 if(!n||!apciec_profile_j314s(p->profile)||p->profile->index||
    !n->attempted||n->failed||p->retained_failed||
    !j314s_native_function(p,rid))return false;
 if(p->retained_phase==40&&n->sealed&&n->published)
  return p->native&&p->native->host==p&&p->native->active&&!p->native->failed&&
   p->native->dma_ready&&p->native->rid_ready&&p->native->irq_ready&&
   p->native->target==j314s_native_selected(p);
 return (p->retained_phase==15||p->retained_phase==17||p->retained_phase==19||
         p->retained_phase==40)&&j314s_native_actor(p);
}
static int j314s_native_config_locked(struct pci_bus*bus,unsigned devfn,
 int where,int size,u32*v,bool write)
{
 struct apple_apciec*p=bus->sysdata;struct j314s_native_context*n=p->j314s_native;
 unsigned rid=(bus->number<<8)|devfn;const struct ep_function*f;
 bool restoring=false,status_write=false;u32 old,after;int ret;
 lockdep_assert_held(&p->lock);
 if(!n||n->failed||!(f=j314s_native_function(p,rid))||
    !apple_apciec_map_bus(bus,devfn,where))return PCIBIOS_DEVICE_NOT_FOUND;
 if(p->retained_phase==40&&n->sealed&&n->published&&p->native&&p->native->active&&
    !p->native->failed&&p->native->dma_ready&&p->native->rid_ready&&p->native->irq_ready) {
  if(write) {
   ret=pci_generic_config_read(bus,devfn,where,size,&old);if(ret)return ret;
   if(rid==n->layout.rid[n->layout.selected]&&where==PCI_CACHE_LINE_SIZE&&size==4) {
    u32 header=(f->identity.header&255)<<16;
    if((old&0xffff0000U)!=header||((*v&0xffff0000U)&&(*v&0xffff0000U)!=header))return PCIBIOS_SET_FAILED;
   }else if(!an_write_for(p->native,f,true,rid==n->layout.rid[n->layout.selected],where,size,old,*v))
    return PCIBIOS_SET_FAILED;
  }
  p->native->config_ops++;
  ret=write?pci_generic_config_write(bus,devfn,where,size,*v):
            pci_generic_config_read(bus,devfn,where,size,v);
  if(!ret&&write&&size==4&&rid==n->layout.rid[n->layout.selected])an_pbi_written(p->native,f,where,*v);
  return ret;
 }
 if(!j314s_native_actor(p)||(p->retained_phase!=15&&p->retained_phase!=17&&p->retained_phase!=19&&p->retained_phase!=40))
  return PCIBIOS_DEVICE_NOT_FOUND;
 if(write) {
  n->ops++;ret=pci_generic_config_read(bus,devfn,where,size,&old);if(ret)goto failed;
  if(p->retained_phase==15) {
   restoring=n->probe.pending;
   if(!pd_write_allowed(&n->probe,f,where,size,old,*v)){ret=PCIBIOS_SET_FAILED;goto failed;}
  }else if(p->retained_phase==17&&n->status_armed) {
   /* Only captured+fresh CED/URD baseline. NFED/FED or new errors never clear. */
   unsigned slot=n->status_slot;
   if(slot>=n->layout.count||rid!=n->layout.rid[slot]||rid!=n->status_rid||
      (unsigned)where!=n->status_off||(unsigned)where!=f->pcie+PCI_EXP_DEVSTA||size!=2||
      n->mmio_next||n->mmio_enabled||n->command_armed||n->command_pending||
      n->status_pending||(n->status_consumed&BIT(slot))||old!=n->status_before||
      !*v||*v!=n->status_value||(*v&~9U)||(old&15)!=*v) {
    ret=PCIBIOS_SET_FAILED;goto failed;
   }
   n->status_armed=false;n->status_pending=true;n->status_consumed|=BIT(slot);
   status_write=true;
  }else if(p->retained_phase==17) {
   unsigned j=n->mmio_next;
   if(n->status_pending||!n->command_armed||n->command_pending||j>=n->layout.count||
      rid!=n->layout.rid[j]||where!=PCI_COMMAND||size!=2||old||
      *v!=(j==n->layout.selected?PCI_COMMAND_MEMORY:PCI_COMMAND_MEMORY|PCI_COMMAND_MASTER)) {
    ret=PCIBIOS_SET_FAILED;goto failed;
   }
   n->command_armed=false;n->command_pending=true;
  }else {ret=PCIBIOS_SET_FAILED;goto failed;}
 }
 if(!j314s_native_actor(p)){ret=PCIBIOS_DEVICE_NOT_FOUND;goto failed;}
 n->ops++;ret=write?pci_generic_config_write(bus,devfn,where,size,*v):
                  pci_generic_config_read(bus,devfn,where,size,v);
 if(ret)goto failed;
 if(write&&(restoring||p->retained_phase==17)) {
  if(!j314s_native_actor(p)){ret=PCIBIOS_SET_FAILED;goto failed;}
  n->ops++;ret=pci_generic_config_read(bus,devfn,where,size,&after);
  if(ret||(status_write?((after&15)||((after^old)&~9U)):after!=*v)){
   ret=ret?ret:PCIBIOS_SET_FAILED;goto failed;
  }
  if(status_write)n->status_pending=false;
  else if(p->retained_phase==17) {
   n->mmio_enabled|=BIT(n->mmio_next++);n->command_pending=false;
  }
 }
 return 0;
failed:n->failed=true;return ret;
}
