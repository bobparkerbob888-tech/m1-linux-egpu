/* Native publication only after target resource/MMIO/DMA/MSI proof. */
static int j314s_np_enable(struct pci_host_bridge*b,struct pci_dev*d)
{
 struct apple_apciec*p=b->sysdata;struct j314s_native_context*n;
 unsigned j;int ret;
 if(!p||(n=p->j314s_native)==NULL||!n->published||!n->sealed||n->failed||
    p->retained_phase!=40||!p->native||p->native->failed)return -EPERM;
 for(j=0;j<n->layout.count;j++)if(n->devices[j]==d)break;
 if(j==n->layout.count)return -EPERM;
 ret=j314s_native_msi_audit(p);if(ret)return ret;
 if(j==n->layout.selected) {
  if(p->native->enable_attempted)return -EALREADY;
  p->native->enable_attempted=true;
 }
 return 0;
}
static void j314s_np_disable(struct pci_host_bridge*b,struct pci_dev*d)
{
 struct apple_apciec*p=b->sysdata;
 if(!p||!p->native||p->native->target!=d)return;
 /* No release/reset, no warm second enable. Keep domain/RID/IRQ owners. */
 WRITE_ONCE(p->native->enable_attempted,true);
}
static int j314s_np_probe_event(struct notifier_block*nb,unsigned long action,void*data)
{
 struct apciec_native*a=container_of(nb,struct apciec_native,probe_notifier);
 if(!a->host||a->host->native!=a||!a->active||data!=&a->target->dev)return NOTIFY_DONE;
 if(action==BUS_NOTIFY_BIND_DRIVER)a->probe_begin_logged=true;
 if(action==BUS_NOTIFY_DRIVER_NOT_BOUND&&a->probe_begin_logged) {
  WRITE_ONCE(a->failed,true);
  dev_err(a->host->dev,"J314s native driver probe failed; owner retained, retry prohibited\n");
 }
 if(action==BUS_NOTIFY_BOUND_DRIVER)dev_info(a->host->dev,"J314s selected native driver bound\n");
 return NOTIFY_DONE;
}
int apple_apciec_j314s_native_prepare(struct device*,unsigned,const void*,unsigned*);
int apple_apciec_j314s_native_prepare(struct device*dev,unsigned port,const void*ticket,unsigned*phase)
{
 struct apple_apciec*p=dev_get_drvdata(dev);struct j314s_native_context*n;
 struct pci_dev*d;unsigned j;unsigned long flags;int ret;
 if(!p||!phase)return -EINVAL;
 mutex_lock(&p->lifecycle);n=p->j314s_native;
 ret=retained_commit_owner(p,port,ticket,18);if(ret)goto out;
 if(!n||n->failed||!n->mmio_complete||!n->discovered||n->published||p->native||
    n->task||n->command_pending||n->command_armed||n->probe.pending||
    n->mmio_next!=n->layout.count||n->mmio_enabled!=(BIT(n->layout.count)-1)||
    !mp_boot0_valid(n->boot0[0],n->boot0[1])||!j314s_native_target_identity(p)||
    driver_find("nvidia",&pci_bus_type)){ret=-EPERM;goto out;}
 if(ktime_get_boottime_ns()>=p->retained_identity_deadline){ret=-ETIMEDOUT;goto out;}
 n->deadline=p->retained_identity_deadline;n->status=-EINPROGRESS;
 raw_spin_lock_irqsave(&p->lock,flags);n->task=current;n->ops=0;raw_spin_unlock_irqrestore(&p->lock,flags);
 p->retained_phase=19;
 ret=j314s_nd_hardware(p);if(!ret)ret=j314s_nd_claims(p,false);if(ret)goto close;
 for(j=0;j<n->layout.count;j++)if(n->devices[j]->driver||n->devices[j]->dev.driver||
    n->devices[j]->dev.iommu_group||dev_iommu_fwspec_get(&n->devices[j]->dev)) {
  ret=-EPERM;goto close;
 }
 p->native=kzalloc(sizeof(*p->native),GFP_KERNEL);if(!p->native){ret=-ENOMEM;goto close;}
 d=j314s_native_selected(p);p->native->target=pci_dev_get(d);p->native->host=p;p->native->active=true;
 ret=j314s_native_dma_prepare(p);if(ret)goto close;
 ret=j314s_native_msi_prepare(p);if(ret)goto close;
 ret=j314s_nd_claims(p,false);if(ret)goto close;
 ret=device_set_driver_override(&d->dev,"apple-apciec-native-pending");
 if(ret||driver_find("nvidia",&pci_bus_type)){ret=ret?ret:-EBUSY;goto close;}
 p->native->probe_notifier.notifier_call=j314s_np_probe_event;
 ret=bus_register_notifier(&pci_bus_type,&p->native->probe_notifier);if(ret)goto close;
 if(!j314s_native_actor(p)){ret=-ETIMEDOUT;goto close;}
 p->discovery_bridge->enable_device=j314s_np_enable;
 p->discovery_bridge->disable_device=j314s_np_disable;
 p->discovery_bridge->preserve_config=true;
 p->discovery_bridge->discovery_driver_device=d;
 /* This separate established lifetime enables native driver config/DMA/IRQ
  * callbacks without reusing the expired raw-transaction permit. */
 p->retained_phase=40;
 {
  struct apciec_native *natives[1]={p->native};
  unsigned rids[1]={p->j314s_resource->selected.rid},sids[1]={1};
  ret=j314s_owner_seal_locked(p,ticket,natives,rids,sids,1,32,42);
  if(ret)goto close;
  n->sealed=true;
 }
 if(!j314s_native_actor(p)){ret=-ETIMEDOUT;goto close;}
 n->published=true;
 pci_bus_add_device(d);pm_runtime_forbid(&d->dev);
 ret=j314s_native_msi_audit(p);
 if(!ret&&!pci_dev_is_added(d))ret=-EPERM;
 if(!ret&&!j314s_native_actor(p))ret=-ETIMEDOUT;
close:
 raw_spin_lock_irqsave(&p->lock,flags);n->task=NULL;raw_spin_unlock_irqrestore(&p->lock,flags);
 if(ret){n->failed=true;n->status=ret;p->retained_failed=true;if(p->native)p->native->failed=true;}
 else {n->completed_ns=ktime_get_boottime_ns();
  if(n->completed_ns>=p->retained_identity_deadline){ret=-ETIMEDOUT;n->failed=true;n->status=ret;p->retained_failed=true;p->native->failed=true;}
  else n->status=0;
 }
out:*phase=p->retained_phase;mutex_unlock(&p->lifecycle);return ret;
}
EXPORT_SYMBOL_GPL(apple_apciec_j314s_native_prepare);
