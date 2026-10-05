/* SPDX-License-Identifier: GPL-2.0 */
/* Dormant kernel adapter. No host field or frontend call is added.
 * Missing mandatory integration contracts cause refusal, never legacy fallback.
 * Include after R15 native helpers; lifecycle serialization is caller-owned. */
#include "j314s-multi-assignment.h"
#include "jmn-core.h"
struct jmn_kernel;
struct jmc_context;
struct jmn_kernel_ops {
 /* Must prove frozen resource_owner snapshots, completed SINGLE joint HW
  * assignment, exact CPU reservations, identity/task/deadline and cold phase.
  * Config dispatch needs its own exact task/RID/write tuple admission. */
 int (*assignment)(struct jmn_kernel*);
 int (*root)(struct jmn_kernel*); /* creates discovery_only root; no scanning */
 int (*blocked)(struct jmn_kernel*); /* all commands0 + all64 DART/RID blocked */
 int (*config_scope)(struct jmn_kernel*,unsigned,bool); /* exact planned scan */
 int (*claims)(struct jmn_kernel*); /* exact union resource children */
 int (*write_acs)(struct jmn_kernel*,unsigned,u16); /* consumed tuple RMW */
 int (*mmio)(struct jmn_kernel*); /* one-shot each selected BOOT0 + commands */
 int (*firmware)(struct jmn_kernel*); /* initial exact RID->SID1..N only map */
 int (*dma_audit)(struct jmn_kernel*); /* actual 16K IAS/OAS all64TTBR audit */
 int (*rid_install)(struct jmn_kernel*); /* exact once table, allotherszero */
 int (*msi)(struct jmn_kernel*); /* one exact-client AIC2 domain,32vectors */
 int (*audit)(struct jmn_kernel*,enum jmn_phase); /* currentHW+all claims */
 int (*seal)(struct jmn_kernel*); /* all devices before any publication */
 int (*publish)(struct jmn_kernel*); /* pending override, no driver bind */
 int (*driver)(struct jmn_kernel*,unsigned,bool); /* early + actual IRQ */
 bool (*valid)(struct jmn_kernel*,bool);
};
struct jmn_kernel {
 struct apple_apciec*p;const void*ticket;struct task_struct*task;u64 deadline,prepared_ns;unsigned operations;bool failed;
 struct resource bus_resource;struct jmc_context*config;const struct jma_plan*joint;const void*assignment_receipt;
 const struct jmn_kernel_ops*ops;struct jmn_owner owner;struct jmn_io io;
 struct pci_host_bridge*bridge;struct pci_bus*buses[256];
 struct pci_dev*devices[JM_MAX_RECORDS],*selected[JM_MAX_GPUS];
 struct irq_domain*msi_domain;unsigned aliases[JM_MAX_GPUS];
 struct apciec_native clients[JM_MAX_GPUS];struct apple_dart_j314s_sample sample;
 bool firmware_attempted,rid_attempted,msi_attempted,sealed;
 bool publication_attempted,publication_active,published;unsigned published_count;
 struct resource sealed_bars[JM_MAX_GPUS][PCI_NUM_RESOURCES];
 struct iommu_group*sealed_groups[JM_MAX_GPUS];struct iommu_domain*sealed_domains[JM_MAX_GPUS];
};
static bool jmn_kvalid(void*v,bool historical)
{
 struct jmn_kernel*k=v;
 return k&&k->p&&k->joint&&k->assignment_receipt&&k->ops&&k->ops->valid&&
  jmx_native_scope(k->p,k->joint->admission.count,historical)&&
  !k->p->retained_failed&&k->ops->valid(k,historical);
}
static u64 jmn_know(void*v){return ktime_get_boottime_ns();}
static int jmn_kplan(void*v,const struct jm_capture*c,struct jm_plan*plan)
{
 struct jmn_kernel*k=v;
 if(!k->p->j314s_mixed_policy)return jm_build(c,plan);
 {const struct jmx_kernel_policy*b=jmx_binding(k->p,false);
 return b?jmx_build(c,&b->policy,plan):-EPERM;}
}
static int jmn_kassignment(void*v,const struct jm_capture*c,const struct jm_plan*p)
{
 struct jmn_kernel*k=v;lockdep_assert_held(&k->p->lifecycle);
 if(!k->ops->assignment||!k->ops->root||!k->ops->blocked||!k->ops->config_scope||
    !k->ops->claims||!k->ops->write_acs||!k->ops->mmio||!k->ops->firmware||
    !k->ops->dma_audit||!k->ops->rid_install||!k->ops->msi||!k->ops->audit||
    !k->ops->seal||!k->ops->publish||!k->ops->driver||
    k->p->retained_phase==40||k->p->native||k->p->discovery_bridge||
    k->p->iommu_ready||k->p->msi_domain_ready||k->bridge||
    memcmp(c,&k->joint->assigned,sizeof(*c))||
    p->count!=k->joint->admission.count||p->path_count!=k->joint->admission.path_count)return -EPERM;
 for(unsigned j=0;j<p->count;j++)if(!jm_equal(&p->client[j].identity,&k->joint->admission.client[j].identity)||
  p->client[j].sid!=k->joint->admission.client[j].sid)return -ESTALE;
 for(unsigned j=0;j<p->path_count;j++)if(p->path[j]!=k->joint->admission.path[j])return -ESTALE;
 return k->ops->assignment(k);
}
static int jmn_kdevice(struct jmn_kernel*k,unsigned index)
{
 const struct jm_identity*f=&k->owner.capture.record[index].identity;struct pci_dev*d=k->devices[index];
 if(!d||pci_dev_id(d)!=f->rid||((u32)d->device<<16|d->vendor)!=f->id||
  (d->class<<8|d->revision)!=f->class_rev||d->hdr_type!=(f->header&127)||
  !!d->multifunction!=!!(f->header&128)||d->driver||d->dev.driver||
  !d->non_mappable_bars||d->is_busmaster||d->is_virtfn||pci_num_vf(d)||d->ari_enabled||
  d->dev.iommu_group||dev_iommu_fwspec_get(&d->dev)||!device_is_registered(&d->dev)||
  pci_find_host_bridge(d->bus)!=k->bridge)return -EPERM;
 if(!d->hdr_type&&((u32)d->subsystem_device<<16|d->subsystem_vendor)!=f->subsystem)return -ESTALE;
 if(f->serial&&pci_get_dsn(d)!=f->serial)return -ESTALE;
 return 0;
}
static int jmn_kobjects(void*v,const struct jm_capture*c,const struct jm_plan*p)
{
 struct jmn_kernel*k=v;int ret=k->ops->blocked(k);if(ret)return ret;
 ret=k->ops->root(k);if(ret)return ret;
 if(!k->bridge||!k->bridge->discovery_only||k->bridge->sysdata!=k->p||!k->buses[0])return -EPERM;
 pci_lock_rescan_remove();
 for(unsigned j=0;j<p->path_count;j++){
  unsigned index=p->path[j];const struct jm_record*f=&c->record[index];struct pci_bus*b=k->buses[f->identity.rid>>8];
  if(!b||k->devices[index]){ret=-EPERM;goto out;}
  ret=jmn_gate(&k->owner);if(!ret)ret=k->ops->blocked(k);if(ret)goto out;
  ret=k->ops->config_scope(k,index,true);if(ret)goto out;
  k->devices[index]=pci_scan_single_device(b,f->identity.rid&255);
  ret=k->ops->config_scope(k,index,false);if(ret)goto out;
  ret=jmn_kdevice(k,index);if(!ret)ret=k->ops->blocked(k);if(ret)goto out;
  if((f->identity.header&127)==1){
   if(k->buses[f->secondary]){ret=-EPERM;goto out;}
   b=pci_add_new_bus(b,k->devices[index],f->secondary);if(!b){ret=-ENOMEM;goto out;}
   k->buses[f->secondary]=b;
   if(!pci_bus_insert_busn_res(b,f->secondary,f->subordinate)){ret=-EBUSY;goto out;}
   pci_read_bridge_bases(b);
  }
 }
 for(unsigned j=0;j<p->count;j++){
  k->selected[j]=k->devices[p->client[j].index];if(!k->selected[j]){ret=-EPERM;goto out;}
 }
 out:pci_unlock_rescan_remove();return ret;
}
static int jmn_kacs(void*v)
{
 struct jmn_kernel*k=v;const unsigned required=PCI_ACS_SV|PCI_ACS_RR|PCI_ACS_CR|PCI_ACS_UF;
 for(unsigned j=0;j<k->owner.plan.path_count;j++){
  unsigned index=k->owner.plan.path[j];struct pci_dev*d=k->devices[index];u16 cap,ctrl;int off,ret;
  if(pci_pcie_type(d)!=PCI_EXP_TYPE_DOWNSTREAM)continue;
  off=pci_find_ext_capability(d,PCI_EXT_CAP_ID_ACS);
  if(!off||pci_read_config_word(d,off+PCI_ACS_CAP,&cap)||
     pci_read_config_word(d,off+PCI_ACS_CTRL,&ctrl)||(cap&required)!=required||ctrl)return -EOPNOTSUPP;
  ret=jmn_gate(&k->owner);if(ret)return ret;
  ret=k->ops->write_acs(k,index,required);if(ret)return ret;
  if(!pci_acs_enabled(d,required))return -EPERM;
 }
 return 0;
}
struct jmn_alias_context{struct pci_dev*d;unsigned rid,count;};
static int jmn_kalias(struct pci_dev*d,u16 rid,void*v)
{struct jmn_alias_context*a=v;if(d!=a->d||rid!=a->rid||a->count++)return -EPERM;return 0;}
static int jmn_kdma(void*v)
{
 struct jmn_kernel*k=v;int ret=k->ops->firmware(k);if(ret)return ret;
 for(unsigned j=0;j<k->owner.plan.count;j++){
  struct pci_dev*d=k->selected[j];struct jmn_alias_context a={d,k->owner.plan.client[j].identity.rid,0};
  ret=jmn_gate(&k->owner);if(ret)return ret;
  if(d->driver||d->dev.driver||d->dev.iommu_group||dev_iommu_fwspec_get(&d->dev)||
     pci_for_each_dma_alias(d,jmn_kalias,&a)||a.count!=1)return -EPERM;
  k->aliases[j]=a.count;WRITE_ONCE(d->discovery_dma_admitted,true);
  /* Root discovery bridge must gate ordinary IOMMU probing to this device. */
  k->bridge->discovery_dma_device=d;
  ret=iommu_probe_device(&d->dev);k->bridge->discovery_dma_device=NULL;if(ret)return ret;
 }
 k->bridge->discovery_dma_device=NULL;
 ret=k->ops->dma_audit(k);if(ret)return ret;
 ret=jmn_gate(&k->owner);if(ret)return ret;
 return k->ops->rid_install(k);
}
static int jmn_kaudit(void*v,enum jmn_phase phase,struct jmn_evidence*e)
{
 struct jmn_kernel*k=v;int ret=k->ops->audit(k,phase);if(ret)return ret;
 if(phase>=JMN_DMA){
  for(unsigned j=0;j<k->owner.plan.count;j++){
   struct pci_dev*d=k->selected[j];struct iommu_domain*domain=iommu_get_domain_for_dev(&d->dev);
   if(!domain||domain->type!=IOMMU_DOMAIN_DMA||dev_is_dma_coherent(&d->dev))return -EPERM;
   e->device[j]=d;e->group[j]=d->dev.iommu_group;e->domain[j]=domain;
   e->alias_count[j]=k->aliases[j];e->alias[j]=pci_dev_id(d);
  }
  for(unsigned j=0;j<64;j++)e->rid_table[j]=readl(k->p->port+APCIEC_RID2SID+4*j);
 }
 if(phase>=JMN_MSI){
  if(!k->msi_domain)return -EPERM;
  for(unsigned j=0;j<k->owner.plan.count;j++)if(dev_get_msi_domain(&k->selected[j]->dev)!=k->msi_domain)return -EPERM;
  e->msi=k->msi_domain;
 }
 return 0;
}
#define JMN_FORWARD(name) static int jmn_k##name(void*v){struct jmn_kernel*k=v;return k->ops->name(k);}
JMN_FORWARD(claims) JMN_FORWARD(mmio) JMN_FORWARD(msi) JMN_FORWARD(seal) JMN_FORWARD(publish)
#undef JMN_FORWARD
static int jmn_kdriver(void*v,unsigned index,bool irq)
{struct jmn_kernel*k=v;return k->ops->driver(k,index,irq);}
static void jmn_kfailure(void*v,const char*stage,enum jmn_phase phase,int ret)
{
 struct jmn_kernel*k=v;
 dev_err(k->p->dev,"j314s-multi-native: stage=%s phase=%u hostphase=%u status=%d operations=%u clients=%u published=%u\n",
  stage,phase,k->p->retained_phase,ret,k->operations,k->owner.plan.count,k->published_count);
}
static int __maybe_unused jmn_kernel_prepare_once(struct jmn_kernel*k,u64 deadline)
{
 if(!k||!k->p||!k->ops||!k->joint)return -EINVAL;
 if(k->owner.consumed)return -EALREADY;
 if(deadline!=k->p->retained_identity_deadline)return -EPERM;
 lockdep_assert_held(&k->p->lifecycle);
 k->io=(struct jmn_io){.valid=jmn_kvalid,.now=jmn_know,.assignment=jmn_kassignment,.plan=jmn_kplan,
 .objects=jmn_kobjects,.claims=jmn_kclaims,.acs=jmn_kacs,.mmio=jmn_kmmio,.dma=jmn_kdma,
 .msi=jmn_kmsi,.audit=jmn_kaudit,.seal=jmn_kseal,.publish=jmn_kpublish,.driver=jmn_kdriver,
 .failure=jmn_kfailure,.ctx=k,.original_deadline=deadline};
 return jmn_prepare_once(&k->owner,&k->io,&k->joint->assigned);
}

static int __maybe_unused jmn_kernel_publish_once(struct jmn_kernel*k)
{
 if(!k||!k->p)return -EINVAL;
 lockdep_assert_held(&k->p->lifecycle);
 return jmn_publish_once(&k->owner);
}
