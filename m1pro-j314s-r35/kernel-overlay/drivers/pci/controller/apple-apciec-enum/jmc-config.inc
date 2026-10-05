/* Refusal-only metadata: no hardware access, actor recheck, or owner mutation. */
static int jmc_refusal(struct jmn_kernel*k,const char*stage,unsigned index,
 unsigned off,u32 observed,u32 expected,int ret)
{
 struct jmc_context*c;unsigned rid;
 if(!k||!k->config||!k->joint||!k->p||!k->p->dev)return ret;
 c=k->config;rid=index<k->joint->assigned.count?k->joint->assigned.record[index].identity.rid:0xffff;
 dev_err(k->p->dev,"j314s-native-refusal: stage=%s index=%u rid=%04x off=%03x observed=%08x expected=%08x ret=%d ops=%u phase=%u attempted=%u scope=%u armed=%u pending=%u enabled=%llx consumed=%llx failed=%u/%u/%u/%u attached=%u claimed=%u raw=%u power=%u tunnel=%u task=%u ticket=%u deadline=%llu original=%llu\n",
 stage,index,rid,off,observed,expected,ret,k->operations,k->owner.phase,
 c->mmio_attempted,c->scope,c->armed,c->pending,c->enabled,c->status_consumed,
 c->failed,k->failed,k->owner.failed,k->p->retained_failed,
 c->attached,c->claimed,k->p->j314s_raw_capability,k->p->power_ready,k->p->tunnel_ready,
 k->task==current,k->ticket==k->p->retained_ticket,k->deadline,k->io.original_deadline);
 return ret;
}
/* Include after jmn-kernel + concrete assignment receipt. */
static int jmc_client(struct jmn_kernel*k,unsigned index)
{unsigned j;for(j=0;j<k->owner.plan.count;j++)if(k->owner.plan.client[j].index==index)return j;return -1;}
static const struct ep_function*jmc_function(struct jmn_kernel*k,unsigned index)
{
 const struct jma_kernel_owner*o=k->assignment_receipt;int client=jmc_client(k,index);unsigned j;
 if(!o||index>=o->plan.assigned.count)return NULL;
 if(client>=0)for(j=0;j<o->capture->count;j++)if(o->capture->snapshots[j]->selected==index)
  return &o->capture->snapshots[j]->functions[index];
 return &o->capture->snapshots[0]->functions[index];
}
static unsigned jmc_expected_command(struct jmn_kernel*k,unsigned index)
{return k->config->enabled&BIT_ULL(index)?jmc_client(k,index)>=0?PCI_COMMAND_MEMORY:PCI_COMMAND_MEMORY|PCI_COMMAND_MASTER:0;}
static bool jmc_actor(struct jmn_kernel*k)
{
 struct jmc_context*c=k?k->config:NULL;
 return c&&c->attached&&!c->failed&&!k->failed&&!k->owner.failed&&!k->p->retained_failed&&
  k->task==current&&k->ticket==k->p->retained_ticket&&
  k->p->j314s_raw_capability&&k->p->power_ready&&k->p->tunnel_ready&&
  jmx_native_scope(k->p,k->joint->admission.count,true)&&
  k->deadline==k->io.original_deadline&&
  k->deadline<=k->p->retained_identity_deadline&&ktime_get_boottime_ns()<k->deadline&&k->operations<=16384-3;
}
static bool jmc_persistent(struct jmn_kernel*k)
{return k&&k->config&&!k->config->failed&&!k->failed&&k->sealed&&k->published&&k->owner.complete&&
 !k->owner.failed&&!k->owner.status&&k->owner.phase==JMN_PUBLISHED&&!k->p->retained_failed;}
static bool jmc_map_permit(struct jmn_kernel*k,unsigned rid)
{
 unsigned j;if(!k||!k->config||(!jmc_actor(k)&&!jmc_persistent(k)))return false;
 for(j=0;j<k->joint->assigned.count;j++)if(k->joint->assigned.record[j].identity.rid==rid)return true;
 return false;
}
static int jmc_config_locked(struct jmn_kernel*k,struct pci_bus*bus,unsigned devfn,int off,int size,u32*v,bool write)
{
 struct jmc_context*c=k->config;unsigned rid=(bus->number<<8)|devfn,index;const struct ep_function*f;
 bool restore=false,tuple=false;u32 old,after;int ret,client;
 lockdep_assert_held(&k->p->lock);
 if(bus->sysdata!=k->p||(size!=1&&size!=2&&size!=4)||off<0||off>4096-size||(off&(size-1))||
    PCIE_ECAM_OFFSET(bus->number,devfn,off)+size>k->p->ecam_size||!jmc_map_permit(k,rid))return PCIBIOS_DEVICE_NOT_FOUND;
 for(index=0;index<k->joint->assigned.count;index++)if(k->joint->assigned.record[index].identity.rid==rid)break;
 if(index==k->joint->assigned.count||!(f=jmc_function(k,index)))return PCIBIOS_DEVICE_NOT_FOUND;
 client=jmc_client(k,index);
 if(jmc_persistent(k)){
  if(write){
   ret=pci_generic_config_read(bus,devfn,off,size,&old);if(ret)return ret;
   if(client<0)return PCIBIOS_SET_FAILED;
   if(off==PCI_CACHE_LINE_SIZE&&size==4){u32 header=(f->identity.header&255)<<16;
    if((old&0xffff0000U)!=header||((*v&0xffff0000U)&&(*v&0xffff0000U)!=header))return PCIBIOS_SET_FAILED;
   }else if(!an_write_for(&k->clients[client],f,true,true,off,size,old,*v))return PCIBIOS_SET_FAILED;
  }
  ret=write?pci_generic_config_write(bus,devfn,off,size,*v):pci_generic_config_read(bus,devfn,off,size,v);
  if(!ret&&write&&size==4)an_pbi_written(&k->clients[client],f,off,*v);
  return ret;
 }
 if(write){
  k->operations++;ret=pci_generic_config_read(bus,devfn,off,size,&old);if(ret)goto fail;
  if(c->armed){
   if(c->pending||index!=c->tuple_index||(unsigned)off!=c->tuple_off||
      (unsigned)size!=c->tuple_width||old!=c->tuple_before||*v!=c->tuple_after){ret=PCIBIOS_SET_FAILED;goto fail;}
   if(c->tuple_kind==2){
    if(off!=f->pcie+PCI_EXP_DEVSTA||size!=2||c->enabled||
       (c->status_consumed&BIT_ULL(index))||!*v||(*v&~9U)||(old&15)!=*v){ret=PCIBIOS_SET_FAILED;goto fail;}
    c->status_consumed|=BIT_ULL(index);
   }else if(c->tuple_kind==3){
    if(off!=PCI_COMMAND||size!=2||old||(c->enabled&BIT_ULL(index))||
       *v!=(client>=0?PCI_COMMAND_MEMORY:PCI_COMMAND_MEMORY|PCI_COMMAND_MASTER)){ret=PCIBIOS_SET_FAILED;goto fail;}
   }else if(c->tuple_kind!=1||!f->acs||off!=f->acs+PCI_ACS_CTRL||size!=2||old||
     c->acs_done[index]||*v!=(PCI_ACS_SV|PCI_ACS_RR|PCI_ACS_CR|PCI_ACS_UF)){ret=PCIBIOS_SET_FAILED;goto fail;}
   c->armed=false;c->pending=true;tuple=true;
  }else if(c->scope&&c->index==index&&!c->claimed&&!c->mmio_attempted){
   restore=c->probe.pending;
   if(!pd_write_allowed(&c->probe,f,off,size,old,*v)){ret=PCIBIOS_SET_FAILED;goto fail;}
  }else {ret=PCIBIOS_SET_FAILED;goto fail;}
 }
 if(!jmc_actor(k)){ret=PCIBIOS_SET_FAILED;goto fail;}
 k->operations++;ret=write?pci_generic_config_write(bus,devfn,off,size,*v):pci_generic_config_read(bus,devfn,off,size,v);if(ret)goto fail;
 if(write&&(tuple||restore)){
  if(!jmc_actor(k)){ret=PCIBIOS_SET_FAILED;goto fail;}
  k->operations++;ret=pci_generic_config_read(bus,devfn,off,size,&after);
  if(ret||(tuple&&c->tuple_kind==2?((after&15)||((after^old)&~9U)):after!=*v)){ret=PCIBIOS_SET_FAILED;goto fail;}
  if(tuple){c->pending=false;if(c->tuple_kind==3)c->enabled|=BIT_ULL(index);if(c->tuple_kind==1)c->acs_done[index]=true;}
 }
 return 0;
fail:c->failed=true;k->failed=true;return ret;
}
static int jmc_read(struct jmn_kernel*k,unsigned index,unsigned off,unsigned width,u32*v)
{
 struct pci_bus b={.number=k->joint->assigned.record[index].identity.rid>>8,.sysdata=k->p,.ops=&apple_apciec_ops};
 int ret=apple_apciec_config_read(&b,k->joint->assigned.record[index].identity.rid&255,off,width,v);
 return ret?jmc_refusal(k,"read",index,off,ret,width,-EIO):0;
}
static int jmc_scope(struct jmn_kernel*k,unsigned index,bool begin)
{
 struct jmc_context*c=k->config;if(!jmc_actor(k)||index>=k->joint->assigned.count||c->armed||c->pending)return -EPERM;
 if(begin){if(c->scope||c->probe.pending)return -EPERM;c->scope=true;c->index=index;}
 else {if(!c->scope||c->index!=index||c->probe.pending)return -EPERM;c->scope=false;}
 return 0;
}
static int jmc_tuple(struct jmn_kernel*k,unsigned index,unsigned off,unsigned width,u32 before,u32 after,unsigned kind)
{
 struct jmc_context*c=k->config;unsigned long flags;int ret;
 if(!jmc_actor(k))return jmc_refusal(k,"tuple-actor",index,off,before,after,-EPERM);
 if(c->armed||c->pending||c->scope||index>=k->joint->assigned.count||!k->devices[index])return jmc_refusal(k,"tuple-state",index,off,before,after,-EPERM);
 raw_spin_lock_irqsave(&k->p->lock,flags);c->tuple_index=index;c->tuple_off=off;c->tuple_width=width;
 c->tuple_before=before;c->tuple_after=after;c->tuple_kind=kind;c->armed=true;raw_spin_unlock_irqrestore(&k->p->lock,flags);
 ret=pci_write_config_word(k->devices[index],off,after);
 if(ret||c->armed||c->pending){c->failed=true;return jmc_refusal(k,"tuple-result",index,off,ret,after,ret?-EIO:-EPERM);}return 0;
}
static int jmc_write_acs(struct jmn_kernel*k,unsigned index,u16 value)
{const struct ep_function*f=jmc_function(k,index);return f&&f->acs?jmc_tuple(k,index,f->acs+PCI_ACS_CTRL,2,0,value,1):-EPERM;}
