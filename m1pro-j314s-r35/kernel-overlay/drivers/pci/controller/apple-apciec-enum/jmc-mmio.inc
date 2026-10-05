/* Exact schema hook; cold/historical ownership remains in existing callers. */
static bool jmx_native_boot0(struct jmn_kernel*k,unsigned g)
{
 if(!k->p->j314s_mixed_policy)return mp_boot0_valid(k->config->boot0[g][0],k->config->boot0[g][1]);
 {const struct jmx_kernel_policy*b=jmx_binding(k->p,true);
 return b&&g<k->owner.plan.count&&jmx_boot0(&b->policy,g,&k->owner.plan.client[g].identity,k->config->boot0[g][0],k->config->boot0[g][1]);}
}
static bool jmx_native_model(struct jmn_kernel*k,unsigned g,struct pci_dev*d)
{
 if(!k->p->j314s_mixed_policy)return d->device==0x2d04;
 {const struct jmx_kernel_policy*b=jmx_binding(k->p,false);
 return b&&g<k->owner.plan.count&&jmx_identity(&b->policy,g,&k->owner.plan.client[g].identity)&&
  ((u32)d->device<<16|d->vendor)==b->policy.identity[g].id;}
}
static int jmc_clean(struct jmn_kernel*k)
{
 unsigned j;u32 v;int ret;
 for(j=0;j<k->owner.plan.path_count;j++){
  unsigned index=k->owner.plan.path[j];const struct ep_function*f=jmc_function(k,index);
  if(!f||!f->pcie)return -EPERM;
  ret=jmc_read(k,index,PCI_STATUS,2,&v);if(ret)return ret;
  if(v&(PCI_STATUS_PARITY|PCI_STATUS_SIG_TARGET_ABORT|PCI_STATUS_REC_TARGET_ABORT|
   PCI_STATUS_REC_MASTER_ABORT|PCI_STATUS_SIG_SYSTEM_ERROR|PCI_STATUS_DETECTED_PARITY))return -EIO;
  ret=jmc_read(k,index,f->pcie+PCI_EXP_DEVSTA,2,&v);if(ret)return ret;if(v&15)return -EIO;
 }return 0;
}
static int jmc_commands(struct jmn_kernel*k,bool zero)
{
 unsigned j;u32 v;int ret;
 for(j=0;j<k->joint->assigned.count;j++){
  unsigned want=zero?0:jmc_expected_command(k,j);
  ret=jmc_read(k,j,PCI_COMMAND,2,&v);if(ret)return ret;
  if(jmc_persistent(k)&&jmc_client(k,j)>=0){
   if(!(v&PCI_COMMAND_MEMORY)||(v&~(PCI_COMMAND_MEMORY|PCI_COMMAND_MASTER|PCI_COMMAND_INTX_DISABLE)))return -EPERM;
  }else if(v!=want)return jmc_refusal(k,"command",j,PCI_COMMAND,v,want,-EPERM);
 }return 0;
}
static int jmc_blocked(struct jmn_kernel*k)
{
 int ret;if(!jmc_actor(k))return jmc_refusal(k,"blocked-actor",64,0,0,0,-EPERM);
 if(k->config->enabled)return jmc_refusal(k,"blocked-enabled",64,0,0,0,-EPERM);
 ret=retained_dma_blocked(k->p);if(ret)return jmc_refusal(k,"blocked-dma",64,0,0,0,ret);
 for(unsigned j=0;j<64;j++)if(readl(k->p->port+APCIEC_RID2SID+4*j))return -ESTALE;
 return jmc_commands(k,true);
}
static int jmn_callback_config_audit(struct jmn_kernel*k,enum jmn_phase phase)
{
 const struct jma_kernel_owner*o=k->assignment_receipt;unsigned j,g;u32 v;int ret;
 if(!k->config||k->config->failed||k->config->probe.pending||k->config->armed||k->config->pending||
    (!jmc_actor(k)&&!jmc_persistent(k)))return -EPERM;
 ret=jmc_commands(k,false);if(ret)return ret;
 for(j=0;j<o->plan.assigned.count;j++){
  const struct ep_function*f=jmc_function(k,j);
  ret=jmc_read(k,j,0,4,&v);if(ret||v!=f->identity.id)return ret?ret:-ESTALE;
  ret=jmc_read(k,j,8,4,&v);if(ret||v!=f->identity.class_rev)return ret?ret:-ESTALE;
  ret=jmc_read(k,j,12,4,&v);if(ret||((v>>16)&255)!=f->identity.header)return ret?ret:-ESTALE;
 }
 for(g=0;g<o->capture->count;g++){
  const struct ep_snapshot*s=o->capture->snapshots[g];const struct ep_function*f=&s->functions[s->selected];unsigned b;
  ret=jmc_read(k,s->selected,0x2c,4,&v);if(ret||v!=f->identity.subsystem)return ret?ret:-ESTALE;
  if(f->serial_present){u32 hi,lo;ret=jmc_read(k,s->selected,f->serial_offset+4,4,&lo);if(ret)return ret;
   ret=jmc_read(k,s->selected,f->serial_offset+8,4,&hi);if(ret||(((u64)hi<<32)|lo)!=f->identity.serial)return ret?ret:-ESTALE;}
  for(b=0;b<6;b++){
   const struct ep_bar*a=&s->bars[b];u32 want=a->saved[0];
   if(a->upper)want=s->bars[b-1].pci>>32;else if(a->size)want=(u32)a->pci|(a->saved[0]&15);
   ret=jmc_read(k,s->selected,0x10+4*b,4,&v);if(ret||v!=want)return ret?ret:-ESTALE;
  }
 }
 for(j=0;j<o->plan.count;j++){
  const struct jma_write*s=&o->plan.writes[j];unsigned last=j,index;
  for(g=j+1;g<o->plan.count;g++)if(o->plan.writes[g].rid==s->rid&&o->plan.writes[g].offset==s->offset)last=g;
  if(last!=j)continue;
  for(index=0;index<o->plan.assigned.count;index++)if(o->plan.assigned.record[index].identity.rid==s->rid)break;
  if(index==o->plan.assigned.count)return -ESTALE;
  ret=jmc_read(k,index,s->offset,4,&v);if(ret||v!=s->after)return ret?ret:-ESTALE;
 }
 for(j=0;j<k->owner.plan.path_count;j++){
  unsigned index=k->owner.plan.path[j];const struct ep_function*f=jmc_function(k,index);
  unsigned ari,sriov;
  ret=jmc_read(k,index,0,4,&v);if(ret||v!=f->identity.id)return ret?ret:-ESTALE;
  ret=jmc_read(k,index,f->pcie+PCI_EXP_DEVCTL2,2,&v);if(ret||(v&PCI_EXP_DEVCTL2_ARI))return ret?ret:-EPERM;
  if(f->acs){ret=jmc_read(k,index,f->acs+PCI_ACS_CTRL,2,&v);if(ret||v!=(k->config->acs_done[index]?
   PCI_ACS_SV|PCI_ACS_RR|PCI_ACS_CR|PCI_ACS_UF:0))return ret?ret:-ESTALE;}
  if(jmc_client(k,index)>=0){
   if(!j314s_capabilities_disabled(f)||j314s_cap_offsets(f,&ari,&sriov))return -EPERM;
   if(ari){ret=jmc_read(k,index,ari+4,4,&v);if(ret||(v>>16))return ret?ret:-EPERM;}
   if(sriov){ret=jmc_read(k,index,sriov+8,2,&v);if(ret||v)return ret?ret:-EPERM;
    ret=jmc_read(k,index,sriov+0x10,2,&v);if(ret||v)return ret?ret:-EPERM;}
  }
 }
 if(phase>=JMN_CLAIMS){ret=jmn_callback_claims_audit(k);if(ret)return ret;}
 if(phase>=JMN_MMIO){
  if(!k->config->mmio_complete)return -EPERM;
  for(g=0;g<k->owner.plan.count;g++)if(!jmx_native_boot0(k,g))return -ESTALE;
  ret=jmc_clean(k);if(ret)return ret;
 }
 return 0;
}
/* Failure-only diagnostics. The frozen full chain was captured by ep_caps.
 * Never clear status, renew an owner, or turn diagnostic success into admission. */
static int jmc_aer_offset(const struct ep_function*f,unsigned*result)
{
 unsigned seen[64],n=0,off=0x100,aer=0,j;u32 h;
 while(off){
  if(off<0x100||off>0xffc||(off&3)||n==64)return -EINVAL;
  for(j=0;j<n;j++)if(seen[j]==off)return -EINVAL;
  if(ja_sample(f,off,&h))return -EINVAL;
  if(!h||h==0xffffffff)break;
  if(!((h>>16)&15)||!(h&65535))return -EINVAL;
  seen[n++]=off;
  if((h&65535)==PCI_EXT_CAP_ID_ERR){if(aer||off>0xfd4)return -EINVAL;aer=off;}
  off=h>>20;
 }
 if(!aer)return -ENOENT;
 for(j=0;j<n;j++)if(seen[j]>aer&&seen[j]<aer+0x2c)return -EINVAL;
 *result=aer;return 0;
}
static void jmc_aer_diagnostic(struct jmn_kernel*k,unsigned index,const struct ep_function*f)
{
 unsigned aer=0,off;u32 value,header;int ret=jmc_aer_offset(f,&aer);
 if(ret){jmc_refusal(k,"aer-frozen-chain",index,0,0,0,ret);return;}
 if(ja_sample(f,aer,&header))return;
 dev_err(k->p->dev,"j314s-aer-diagnostic: rid=%04x frozen-header=%08x captured-devctl=%08x; ten diagnostic dwords\n",f->identity.rid,header,f->devctl);
 for(off=4;off<=0x28;off+=4){
  value=0;ret=jmc_read(k,index,aer+off,4,&value);
  dev_err(k->p->dev,"j314s-aer-diagnostic: rid=%04x offset=%03x value=%08x ret=%d ops=%u; refusal retained\n",
   f->identity.rid,aer+off,value,ret,k->operations);
  if(ret)return;
 }
}
static int jmc_mmio(struct jmn_kernel*k)
{
 struct jmc_context*c=k->config;u32 before[64]={0},expected[64]={0},v;
 unsigned j,g;int ret;
 if(!jmc_actor(k))return jmc_refusal(k,"entry-actor",64,0,0,0,-EPERM);
 if(c->mmio_attempted||c->enabled||c->status_consumed||c->scope)return jmc_refusal(k,"entry-state",64,0,0,0,-EPERM);
 c->mmio_attempted=true;
 ret=jmc_blocked(k);if(ret)return jmc_refusal(k,"blocked",64,0,0,0,ret);ret=jmn_callback_claims_audit(k);if(ret)return jmc_refusal(k,"claims",64,0,0,0,ret);
 /* Read EVERY captured+fresh baseline before the first W1C. */
 for(j=0;j<k->owner.plan.path_count;j++){
  unsigned index=k->owner.plan.path[j];const struct ep_function*f=jmc_function(k,index);
  if(!j314s_cap_sample(f,f->pcie+PCI_EXP_DEVCTL,&v))return jmc_refusal(k,"capture-missing",index,f->pcie+PCI_EXP_DEVCTL,0,0,-EPERM);
  expected[index]=(v>>16)&15;if(expected[index]&~9U){jmc_aer_diagnostic(k,index,f);return jmc_refusal(k,"capture-devsta",index,f->pcie+PCI_EXP_DEVCTL,v,9,-EPERM);}
  ret=jmc_read(k,index,PCI_STATUS,2,&v);if(ret)return ret;
  if(v&(PCI_STATUS_PARITY|PCI_STATUS_SIG_TARGET_ABORT|PCI_STATUS_REC_TARGET_ABORT|
   PCI_STATUS_REC_MASTER_ABORT|PCI_STATUS_SIG_SYSTEM_ERROR|PCI_STATUS_DETECTED_PARITY))return -EIO;
  ret=jmc_read(k,index,f->pcie+PCI_EXP_DEVSTA,2,&before[index]);if(ret)return ret;
  if((before[index]&15)!=expected[index])return jmc_refusal(k,"fresh-devsta",index,f->pcie+PCI_EXP_DEVSTA,before[index],expected[index],-ESTALE);
 }
 for(j=0;j<k->owner.plan.path_count;j++){
  unsigned index=k->owner.plan.path[j];const struct ep_function*f=jmc_function(k,index);
  if(expected[index]){ret=retained_dma_blocked(k->p);if(ret)return jmc_refusal(k,"blocked-dma",64,0,0,0,ret);
   ret=jmc_tuple(k,index,f->pcie+PCI_EXP_DEVSTA,2,before[index],expected[index],2);if(ret)return ret;}
 }
 ret=jmc_clean(k);if(ret)return jmc_refusal(k,"clean",64,0,0,0,ret);
 for(g=0;g<k->owner.plan.count;g++){
  struct pci_dev*d=k->selected[g];
  if(!jmc_actor(k))return jmc_refusal(k,"map-actor",k->owner.plan.client[g].index,0,g,0,-EPERM);
  if(!d->non_mappable_bars)return jmc_refusal(k,"map-mappable",k->owner.plan.client[g].index,0,g,0,-EPERM);
  if(!jmx_native_model(k,g,d))return jmc_refusal(k,"map-model",k->owner.plan.client[g].index,0,((u32)d->device<<16)|d->vendor,g,-EPERM);
  if(c->bar0[g])return jmc_refusal(k,"map-existing",k->owner.plan.client[g].index,0,g,0,-EPERM);
  d->non_mappable_bars=false;c->bar0[g]=pci_iomap_range(d,0,0,sizeof(u32));if(!c->bar0[g])return -ENOMEM;
 }
 for(j=0;j<k->owner.plan.path_count;j++){
  unsigned index=k->owner.plan.path[j];
  ret=jmc_tuple(k,index,PCI_COMMAND,2,0,jmc_client(k,index)>=0?PCI_COMMAND_MEMORY:PCI_COMMAND_MEMORY|PCI_COMMAND_MASTER,3);if(ret)return ret;
 }
 ret=jmc_commands(k,false);if(ret)return ret;ret=jmc_clean(k);if(ret)return jmc_refusal(k,"clean",64,0,0,0,ret);
 for(g=0;g<k->owner.plan.count;g++){
  for(j=0;j<2;j++){if(!jmc_actor(k))return -ETIMEDOUT;k->operations++;c->boot0[g][j]=readl(c->bar0[g]);}
  if(!jmx_native_boot0(k,g))return -ENODEV;
 }
 ret=jmc_clean(k);if(ret)return jmc_refusal(k,"clean",64,0,0,0,ret);ret=jmn_callback_claims_audit(k);if(ret)return ret;
 if(!jmc_actor(k))return -ETIMEDOUT;
 c->mmio_complete=true;return 0;
}
static void jmc_install_callbacks(struct jmn_kernel_ops*ops)
{
 ops->config_scope=jmc_scope;ops->blocked=jmc_blocked;ops->claims=jmc_claims;
 ops->write_acs=jmc_write_acs;ops->mmio=jmc_mmio;
}
