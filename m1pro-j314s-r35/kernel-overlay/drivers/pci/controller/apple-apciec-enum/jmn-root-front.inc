extern int apple_cio_j314s_chain_proof_after(void*,const void*,unsigned,u64,unsigned,u64);
/* Cold exact-multi host frontend. All allocations/owners survive failure. */
static bool jmn_root_valid(struct jmn_kernel*k,bool historical)
{
 struct apple_apciec*p=k?k->p:NULL;
 const struct jma_kernel_owner*a=k?k->assignment_receipt:NULL;
 if(!p||!a||p->j314s_multi_native!=k||k->failed||k->owner.failed||
    p->retained_failed||!jmx_native_scope(p,a->capture?a->capture->count:0,historical)||
    p->j314s_native||p->j314s_assignment||!p->retained||!p->power_ready||!p->tunnel_ready||
    a!=p->j314s_multi_assignment||!a->complete||a->failed||a->status||a->active||a->armed||
    !a->capture||a->capture!=p->j314s_multi_resource||!a->capture->complete||a->capture->failed||
    !jmx_native_scope(p,a->capture->count,historical)||a->ticket!=k->ticket||
    k->ticket!=p->retained_ticket||k->joint!=&a->plan||
    k->deadline!=p->retained_identity_deadline||a->deadline>k->deadline||
    !a->completed_ns||a->completed_ns>=a->deadline||a->execution!=a->plan.count)return false;
 /* Historical binding carries no I/O authority. Driver callbacks add current
  * hardware/group/resource/IRQ validation independently. */
 if(historical)return true;
 return k->task==current&&ktime_get_boottime_ns()<k->deadline&&
  !jmx_native_owner(p,k->ticket,3,k->deadline,a->capture->count,0);
}
static int jmn_root_assignment(struct jmn_kernel*k)
{
 const struct jma_kernel_owner*a=jma_kernel_receipt(k->p);
 if(!jmn_root_valid(k,false)||a!=k->assignment_receipt||jma_kernel_owner_valid(k->p,true)||
    k->p->retained_phase!=14||k->owner.plan.count!=a->capture->count||
    k->p->native||k->p->discovery_bridge||k->p->bridge||k->p->iommu_ready||k->p->msi_domain_ready)
  return -EPERM;
 return 0;
}
static int jmn_root_create(struct jmn_kernel*k)
{
 const struct jma_kernel_owner*a=k->assignment_receipt;
 struct apple_apciec*p=k->p;struct resource_entry*e;struct pci_bus*b;
 unsigned maxbus=0,j;int ret=0;
 if(!jmn_root_valid(k,false)||!a||k->bridge||p->discovery_bridge||p->bridge||
    jma_kernel_owner_valid(p,true))return -EPERM;
 for(j=0;j<k->owner.plan.path_count;j++){
  const struct jm_record*r=&k->owner.capture.record[k->owner.plan.path[j]];
  maxbus=max(maxbus,r->identity.rid>>8);
  if((r->identity.header&127)==1)maxbus=max(maxbus,r->subordinate);
 }
 if(!maxbus||maxbus>255)return -ERANGE;
 k->bus_resource=(struct resource){.name="J314s captured multi buses",.start=0,.end=maxbus,.flags=IORESOURCE_BUS};
 INIT_LIST_HEAD(&p->discovery_windows);
 for(j=0;j<3;j++){
  e=resource_list_create_entry(j<2?(struct resource*)&a->resources[j]:&k->bus_resource,0);
  if(!e)return -ENOMEM;
  if(j<2)e->offset=a->entries[j]->offset;
  resource_list_add_tail(e,&p->discovery_windows);
 }
 pci_lock_rescan_remove();
 b=pci_create_root_bus(p->dev,0,&apple_apciec_ops,p,&p->discovery_windows);
 if(!b){ret=-ENODEV;goto out;}
 k->buses[0]=b;k->bridge=pci_find_host_bridge(b);p->discovery_bridge=k->bridge;
 k->bridge->discovery_only=true;k->bridge->native_aer=false;
 k->bridge->native_pcie_hotplug=false;k->bridge->native_pme=false;k->bridge->native_dpc=false;
 if(b->busn_res.start||b->busn_res.end!=maxbus||!b->busn_res.parent||
    k->bridge->sysdata!=p||!jmn_root_valid(k,false))ret=-EPERM;
out:pci_unlock_rescan_remove();return ret;
}
int apple_apciec_j314s_assign_multi(struct device*,unsigned,const void*,unsigned,unsigned*);
int apple_apciec_j314s_assign_multi(struct device*dev,unsigned port,const void*ticket,unsigned count,unsigned*phase)
{
 struct apple_apciec*p=dev?dev_get_drvdata(dev):NULL;int ret;
 if(!p||!phase||port!=3||!jmx_native_scope(p,count,true))return -EINVAL;
 mutex_lock(&p->lifecycle);
 ret=!p->j314s_multi_resource||p->j314s_multi_resource->count!=count?-EPERM:
  jmx_native_owner(p,ticket,port,p->retained_identity_deadline,count,0);
 mutex_unlock(&p->lifecycle);
 if(!ret)ret=jma_kernel_assign(dev,port,ticket);
 mutex_lock(&p->lifecycle);
 if(!ret)ret=jmx_native_owner(p,ticket,port,p->retained_identity_deadline,count,0);
 if(ret&&p->j314s_multi_assignment)p->retained_failed=true;
 *phase=p->retained_phase;mutex_unlock(&p->lifecycle);return ret;
}
EXPORT_SYMBOL_GPL(apple_apciec_j314s_assign_multi);
static void jmn_root_fail(struct jmn_kernel*k,int ret)
{
 k->failed=true;k->owner.failed=true;k->owner.status=ret;k->owner.phase=JMN_FAILED;
 k->p->retained_failed=true;k->task=NULL;
}
int apple_apciec_j314s_native_prepare_multi(struct device*,unsigned,const void*,unsigned,unsigned*);
int apple_apciec_j314s_native_prepare_multi(struct device*dev,unsigned port,const void*ticket,unsigned count,unsigned*phase)
{
 struct apple_apciec*p=dev?dev_get_drvdata(dev):NULL;const struct jma_kernel_owner*a;
 struct jmn_kernel*k;struct jmn_kernel_ops*ops;int ret;
 if(!p||!phase||port!=3||!jmx_native_scope(p,count,true))return -EINVAL;
 mutex_lock(&p->lifecycle);
 ret=retained_commit_owner(p,port,ticket,14);if(ret)goto out;
 a=jma_kernel_receipt(p);
 if(!a||a->capture->count!=count||a->ticket!=ticket||p->j314s_multi_native||
    p->j314s_native||p->native||p->discovery_bridge||p->bridge||p->iommu_ready||p->msi_domain_ready){ret=-EPERM;goto out;}
 ret=jmx_native_owner(p,ticket,port,p->retained_identity_deadline,count,0);if(ret)goto out;
 ret=jmx_native_freeze(p);if(ret)goto out;
 k=kvzalloc(sizeof(*k),GFP_KERNEL);if(!k){ret=-ENOMEM;goto out;}
 p->j314s_multi_native=k;k->p=p;k->assignment_receipt=a;k->joint=&a->plan;
 k->ticket=ticket;k->task=current;k->deadline=p->retained_identity_deadline;
 ops=kzalloc(sizeof(*ops),GFP_KERNEL);k->config=kvzalloc(sizeof(*k->config),GFP_KERNEL);
 if(!ops||!k->config){ret=-ENOMEM;goto fail;}
 k->ops=ops;k->config->attached=true;
 ops->assignment=jmn_root_assignment;ops->root=jmn_root_create;ops->valid=jmn_root_valid;
 jmc_install_callbacks(ops);jmn_install_hardware_ops(ops);jmn_install_publication_ops(ops);jmn_install_audit_ops(ops);
 ret=jmn_kernel_prepare_once(k,k->deadline);if(ret)goto fail;
 if(!k->sealed||k->owner.phase!=JMN_SEALED||k->owner.complete||!jmn_root_valid(k,false)){ret=-EPERM;goto fail;}
 k->prepared_ns=ktime_get_boottime_ns();p->retained_phase=39;goto out;
fail:jmn_root_fail(k,ret);
out:*phase=p->retained_phase;mutex_unlock(&p->lifecycle);return ret;
}
EXPORT_SYMBOL_GPL(apple_apciec_j314s_native_prepare_multi);
int apple_apciec_j314s_native_publish_multi(struct device*,unsigned,const void*,unsigned,unsigned*);
int apple_apciec_j314s_native_publish_multi(struct device*dev,unsigned port,const void*ticket,unsigned count,unsigned*phase)
{
 struct apple_apciec*p=dev?dev_get_drvdata(dev):NULL;struct jmn_kernel*k;int ret;
 if(!p||!phase||port!=3||!jmx_native_scope(p,count,true))return -EINVAL;
 mutex_lock(&p->lifecycle);k=p->j314s_multi_native;
 if(!k||p->retained_phase!=39||k->ticket!=ticket||k->owner.plan.count!=count||!jmn_root_valid(k,false)){
  ret=-EPERM;goto out;
 }
 ret=jmx_native_owner(p,ticket,port,k->deadline,count,k->prepared_ns);
 if(ret){jmn_root_fail(k,ret);goto out;}
 ret=jmn_kernel_publish_once(k);if(ret){jmn_root_fail(k,ret);goto out;}
 if(!k->owner.complete||k->owner.phase!=JMN_PUBLISHED){ret=-EPERM;jmn_root_fail(k,ret);goto out;}
 p->retained_phase=40;k->task=NULL;
out:*phase=p->retained_phase;mutex_unlock(&p->lifecycle);return ret;
}
EXPORT_SYMBOL_GPL(apple_apciec_j314s_native_publish_multi);
