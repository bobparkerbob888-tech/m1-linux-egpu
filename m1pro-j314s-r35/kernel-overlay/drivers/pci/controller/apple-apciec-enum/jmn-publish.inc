/* Include after concrete hardware and supplier callbacks. No cold caller. */
static int jmn_pub_index(struct jmn_kernel*k,struct pci_dev*d)
{
 if(!k||!d)return -1;
 for(unsigned j=0;j<k->owner.plan.count;j++)if(k->selected[j]==d)return j;
 return -1;
}
static int jmn_pub_enable(struct pci_host_bridge*b,struct pci_dev*d)
{
 struct jmn_kernel*k=jmn_owner_bridge(b,true);int index,ret;
 if(!k||b!=k->bridge||!k->published||!k->owner.complete||k->owner.failed||
    k->p->retained_phase!=40||!jmn_hw_msi_valid(k))return -EPERM;
 index=jmn_pub_index(k,d);
 if(index<0){
  bool found=false;
  for(unsigned j=0;j<k->owner.plan.path_count;j++){
   unsigned raw=k->owner.plan.path[j];
   if(k->devices[raw]==d&&(k->owner.capture.record[raw].identity.header&127)==1&&
      READ_ONCE(d->discovery_mem_ancestor)){found=true;break;}
  }
  if(!found)return -EPERM;
 }
 if(!mutex_trylock(&k->p->lifecycle))return -EBUSY;
 ret=jmn_hw_live(k,true);
 if(!ret&&index>=0){
  if(k->clients[index].enable_attempted)ret=-EALREADY;
  else WRITE_ONCE(k->clients[index].enable_attempted,true);
 }
 mutex_unlock(&k->p->lifecycle);return ret;
}
static void jmn_pub_disable(struct pci_host_bridge*b,struct pci_dev*d)
{
 struct jmn_kernel*k=jmn_owner_bridge(b,true);int index;
 if(!k||b!=k->bridge||(index=jmn_pub_index(k,d))<0)return;
 WRITE_ONCE(k->clients[index].enable_attempted,true);
}
static int jmn_pub_probe(struct notifier_block*nb,unsigned long action,void*data)
{
 struct apciec_native*n=container_of(nb,struct apciec_native,probe_notifier);
 struct jmn_kernel*k=jmn_owner_device(n->target,true);int index;
 if(!k||!n->target||data!=&n->target->dev||
    (index=jmn_pub_index(k,n->target))<0||n!=&k->clients[index])return NOTIFY_DONE;
 if(action==BUS_NOTIFY_BIND_DRIVER)WRITE_ONCE(n->probe_begin_logged,true);
 if(action==BUS_NOTIFY_DRIVER_NOT_BOUND&&READ_ONCE(n->probe_begin_logged)){
  WRITE_ONCE(n->failed,true);WRITE_ONCE(k->owner.failed,true);
  WRITE_ONCE(k->p->retained_failed,true);
  dev_err(k->p->dev,"J314s multi native probe failed RID%04x; collective owners retained\n",pci_dev_id(n->target));
 }
 return NOTIFY_DONE;
}
static int jmn_pub_publish(struct jmn_kernel*k)
{
 int ret;
 lockdep_assert_held(&k->p->lifecycle);
 if(k->publication_attempted||!k->sealed||k->owner.phase!=JMN_SEALED||
    k->owner.complete||k->owner.failed||driver_find("nvidia",&pci_bus_type))return -EPERM;
 k->publication_attempted=true;
 ret=jmn_gate(&k->owner);if(ret)return ret;
 ret=jmn_hw_live(k,true);if(ret)return ret;
 for(unsigned j=0;j<k->owner.plan.count;j++){
  struct pci_dev*d=k->selected[j];
  if(pci_dev_is_added(d)||d->driver||d->dev.driver||d->discovery_driver_admitted)return -EPERM;
  ret=device_set_driver_override(&d->dev,"apple-apciec-native-pending");if(ret)return ret;
  k->clients[j].probe_notifier.notifier_call=jmn_pub_probe;
  ret=bus_register_notifier(&pci_bus_type,&k->clients[j].probe_notifier);if(ret)return ret;
 }
 ret=jmn_gate(&k->owner);if(ret)return ret;
 if(driver_find("nvidia",&pci_bus_type))return -EBUSY;
 k->bridge->enable_device=jmn_pub_enable;k->bridge->disable_device=jmn_pub_disable;
 k->bridge->preserve_config=true;k->bridge->discovery_driver_device=NULL;
 k->publication_active=true;k->p->retained_phase=40;
 for(unsigned j=0;j<k->owner.plan.path_count;j++){
  unsigned raw=k->owner.plan.path[j];
  if((k->owner.capture.record[raw].identity.header&127)==1)
   WRITE_ONCE(k->devices[raw]->discovery_mem_ancestor,true);
 }
 pci_lock_rescan_remove();
 for(unsigned j=0;j<k->owner.plan.count;j++){
  struct pci_dev*d=k->selected[j];
  ret=jmn_gate(&k->owner);if(ret)goto out;
  WRITE_ONCE(d->discovery_driver_admitted,true);pci_bus_add_device(d);
  pm_runtime_forbid(&d->dev);
  if(!pci_dev_is_added(d)||pci_dev_binding_disallowed(d)||d->driver||d->dev.driver){ret=-EPERM;goto out;}
  k->published_count++;
 }
 ret=jmn_gate(&k->owner);
 if(!ret)k->published=true;
 out:k->publication_active=false;pci_unlock_rescan_remove();return ret;
}
static void __maybe_unused jmn_install_publication_ops(struct jmn_kernel_ops*ops)
{ops->publish=jmn_pub_publish;}
