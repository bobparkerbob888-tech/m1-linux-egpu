/* Same opaque retained ticket, one-way commit and out-of-parent-lock discovery.
 * No ordinary enable/shutdown path is changed or called from these APIs. */
static int retained_commit_owner(struct apple_apciec*p,unsigned port,const void*ticket,unsigned phase)
{
 if(p&&p->j314s_mixed_policy)return jmx_commit_owner(p,port,ticket,phase);
 if(!retain_prepare||(!retain_commit && !(p && apciec_profile_j314s(p->profile) &&
    p->j314s_raw_capability && p->retained_raw_identity)))return -EOPNOTSUPP;
 if(jpc_host_mode(p)) {
  if(phase<6||phase>10||apple_cio_jpc_raw_owner_validate(p->supplier_context,ticket,port,p->retained_identity_deadline))return -EPERM;
 }else if(p && (!p->profile || p->profile->index>1 || (p->profile->index==1 && phase>(pn_mode(p)?30:20))))return -EPERM;
 if(p && p->retained_raw_identity && (!retained_prefix_capability_valid(p) || !p->retained_rc_ready))return -EPERM;
 if(!p||!ticket||ticket!=p->retained_ticket||port!=3||port!=p->root_down_port||
    !p->retained||p->retained_failed||p->retained_availability_probe||p->retained_provider_prepare||
    !p->prepared||!p->power_ready||
    !p->dart||p->retained_phase!=phase||p->iommu_ready||p->msi_domain_ready)return -EPERM;
 return 0;
}
static int retained_dma_blocked(struct apple_apciec*p)
{
 unsigned n;int ret=apple_apciec_dart_blocked(p);
 if(ret)return ret;
 if(readl(p->port+APCIEC_MSICFG))return -EIO;
 for(n=0;n<p->rid_entries;n++)if(readl(p->port+APCIEC_RID2SID+4*n))return -EIO;
 return 0;
}
#include "retained-root-rc.inc"
int apple_apciec_retained_prepared_audit(struct device*dev,unsigned port,const void*ticket)
{
 struct apple_apciec*p=dev_get_drvdata(dev);int ret;
 if(!p)return -ENODEV;
 mutex_lock(&p->lifecycle);
 ret=retained_commit_owner(p,port,ticket,6);
 if(!ret)ret=p->retained_raw_identity?retained_identity_port_audit(p,false):apple_apciec_retained_isolated(p);
 if(!ret)ret=retained_dma_blocked(p);
 if(!ret&&p->retained_raw_identity)ret=retained_root_rc_audit(p);
 /* Read-only audit never consumes commit or changes readiness. */
 mutex_unlock(&p->lifecycle);return ret;
}
EXPORT_SYMBOL_GPL(apple_apciec_retained_prepared_audit);
int apple_apciec_retained_commit(struct device*dev,unsigned port,const void*ticket)
{
 struct apple_apciec*p=dev_get_drvdata(dev);unsigned long flags;int ret;
 if(!p)return -ENODEV;
 mutex_lock(&p->lifecycle);
 ret=retained_commit_owner(p,port,ticket,6);if(ret)goto out;
 if(p->tunnel_ready||p->bridge){ret=-EPERM;goto out;}
 p->retained_phase=7; /* Irreversible before the first release action. */
 ret=p->retained_raw_identity?retained_identity_port_audit(p,false):apple_apciec_retained_isolated(p);if(ret)goto fail;
 ret=retained_dma_blocked(p);if(ret)goto fail;
 /* Caller already proved four exact Hop entries and both PE bits. This host
  * independently requires blocked DART/RIDs/MSI before PERST/LTSSM release. */
 ret=p->retained_raw_identity?retained_identity_release(p):apple_apciec_release_and_wait(p);if(ret)goto fail;
 ret=retained_dma_blocked(p);if(ret)goto fail;
 raw_spin_lock_irqsave(&p->lock,flags);
 p->tunnel_ready=true; /* Config remains denied: scan_task is still NULL. */
 raw_spin_unlock_irqrestore(&p->lock,flags);
 p->retained_phase=8;
 goto out;
 fail:p->retained_failed=true;
 if(p->retained_raw_identity){int audit=retained_identity_gate(p);
  if(!audit)audit=retained_dma_blocked(p);
  dev_info(p->dev,"retained-raw-identity: commit status %d post-blocked audit %d\n",ret,audit);
 }
 out:mutex_unlock(&p->lifecycle);return ret;
}
EXPORT_SYMBOL_GPL(apple_apciec_retained_commit);
#include "retained-raw-core.h"
struct retained_raw_context {struct apple_apciec*p;const void*ticket;};
/* During unlocked scan this predicate pins only host/ticket/phase. The NHI
 * caller rechecks cable and parent context after reacquiring ACIO/TB. DART
 * remains configured blocked throughout; no map or valid RID is installed. */
static bool retained_raw_valid(void*arg)
{
 struct retained_raw_context*c=arg;
 return !retained_commit_owner(c->p,3,c->ticket,9)&&c->p->tunnel_ready;
}
static u64 retained_raw_clock(void*unused){return ktime_get_boottime_ns();}
static int retained_raw_config_read(void*arg,unsigned b,unsigned d,unsigned off,u32*v)
{
 struct retained_raw_context*c=arg;
 struct pci_bus bus={.number=b,.sysdata=c->p,.ops=&apple_apciec_ops};
 return apple_apciec_config_read(&bus,d,off,4,v)==PCIBIOS_SUCCESSFUL?0:-EIO;
}
static int retained_raw_config_write(void*arg,unsigned b,unsigned d,unsigned off,u32 v)
{
 struct retained_raw_context*c=arg;
 struct pci_bus bus={.number=b,.sysdata=c->p,.ops=&apple_apciec_ops};
 if(off!=4&&off!=0x18)return -EPERM;
 if(off==4&&(v&7))return -EPERM;
 return apple_apciec_config_write(&bus,d,off,4,v)==PCIBIOS_SUCCESSFUL?0:-EIO;
}
static void retained_raw_sleep(void*arg){usleep_range(1000,2000);}
static int retained_raw_host_readiness_audit(void*arg)
{
 struct retained_raw_context*c=arg;int ret;
 if(!retained_raw_valid(arg))return -EPERM;
 ret=retained_identity_port_audit(c->p,true);
 if(!ret)ret=retained_root_rc_audit(c->p);
 return ret;
}
static void retained_raw_record_link(void*arg,const struct retained_link_record*r)
{
 static const char*const names[]={"SNAPSHOT","ACTIVE","TIME_ONLY","LINK_DOWN","ROOT_SETTLE","ERROR"};
 struct retained_raw_context*c=arg;
 dev_info(c->p->dev,"retained-link: bus %02x devfn %02x cap %02x flags %04x bridge-control %04x link-cap %08x link-control-status %08x state %s waited-us %llu polls %u status %d\n",
 r->bus,r->devfn,r->cap,r->flags,r->bridge_control,r->link_cap,r->link_control_status,
 r->state<ARRAY_SIZE(names)?names[r->state]:"INVALID",(unsigned long long)(r->waited_ns/1000),r->polls,r->status);
 if(r->diagnostic_attempted)dev_info(c->p->dev,"retained-link-power: bus %02x devfn %02x state %s valid%x diagnostic-status%d slot-cap%08x slot-control-status%08x pm-cap%02x pm-header%08x pm-control-status%08x; read-only original scan\n",
  r->bus,r->devfn,r->state<ARRAY_SIZE(names)?names[r->state]:"INVALID",r->diagnostic_valid,r->diagnostic_status,
  r->slot_cap,r->slot_control_status,r->pm_cap,r->pm_header,r->pm_control_status);
 if(r->aer_stage){
  dev_info(c->p->dev,"retained-leaf-aer: bus%02x devfn%02x stage%s cap%03x valid%x status%d header%08x devctl%08x; original raw owner\n",
   r->bus,r->devfn,r->aer_stage==1?"pre-child-scan":"post-raw",r->aer_cap,r->aer_valid,r->aer_status,r->aer_header,r->aer_devctl);
  for(unsigned j=0;j<10;j++)if(r->aer_valid&(1U<<(j+2)))
   dev_info(c->p->dev,"retained-leaf-aer-value: bus%02x devfn%02x stage%u offset%03x value%08x\n",r->bus,r->devfn,r->aer_stage,r->aer_cap+4+4*j,r->aer_data[j]);
 }
}
static void retained_raw_record_device(void*arg,const struct retained_raw_record*r)
{
 struct retained_raw_context*c=arg;
 if (endpoint_resources || c->p->j314s_raw_capability) {
  unsigned j, rid = (r->bus << 8) | r->devfn;
  if (c->p->retained_record_count == EP_MAX_RECORDS) { c->p->retained_failed = true; return; }
  for (j = 0; j < c->p->retained_record_count; j++)
   if (c->p->retained_records[j].rid == rid) { c->p->retained_failed = true; return; }
  c->p->retained_records[c->p->retained_record_count++] = (struct ep_identity){
   .rid = rid, .id = r->id, .class_rev = r->class_rev, .subsystem = r->subsystem,
   .serial = r->serial, .header = r->header};
 }
 dev_info(c->p->dev,"retained-config: bus %02x devfn %02x id %08x class-rev %08x subsystem %08x serial %016llx command %04x; raw identity only\n",
 r->bus,r->devfn,r->id,r->class_rev,r->subsystem,(unsigned long long)r->serial,r->command);
}
extern int apple_cio_j314s_chain_owner_validate(void*,const void*,unsigned,u64,unsigned);
static int retained_scan_quarantined_policy(struct device*dev,unsigned port,const void*ticket,unsigned expected)
{
 struct apple_apciec*p=dev_get_drvdata(dev);struct retained_raw_io io={0};
 struct retained_raw_context context={p,ticket};unsigned long flags;int ret;
 if(!p)return -ENODEV;
 if(!p->profile || p->profile->index)return -EPERM;
 if(expected&&(expected!=2&&expected!=4))return -EINVAL;
 if(expected&&(!apciec_profile_j314s(p->profile)||!p->j314s_raw_capability))return -EPERM;
 /* No PCI core scan/device registration/quirks/retrain or driver binding.
  * Caller still holds neither ACIO/TB lock, retaining parent and ticket. */
 mutex_lock(&p->lifecycle);
 ret=retained_commit_owner(p,port,ticket,8);if(ret)goto out;
 if(expected){ret=apple_cio_j314s_chain_owner_validate(p->supplier_context,ticket,port,p->retained_identity_deadline,expected);if(ret)goto out;}
 if(!p->tunnel_ready){ret=-EPERM;goto out;}
 if(expected){ret=j314s_scan_budget_freeze(p,ticket,expected);if(ret)goto out;}
 p->retained_phase=9;
 ret=retained_dma_blocked(p);if(ret)goto fail;
 io=(struct retained_raw_io){.read=retained_raw_config_read,.write=retained_raw_config_write,
 .valid=retained_raw_valid,.now=retained_raw_clock,.record=retained_raw_record_device,
 .ctx=&context,.first=p->bus_start,.last=p->bus_end,
 .max_depth=expected?16:0,.max_buses=expected?32:0,
 .j314s_multi_initial=expected!=0,
 .deadline=ktime_get_boottime_ns()+(expected?30ULL:10ULL)*NSEC_PER_SEC};
 if(p->retained_raw_identity && io.deadline>p->retained_identity_deadline)io.deadline=p->retained_identity_deadline;
 io.strict_identity=p->retained_raw_identity;
 if(io.strict_identity){io.sleep=retained_raw_sleep;io.audit=retained_raw_host_readiness_audit;io.link_record=retained_raw_record_link;}
 raw_spin_lock_irqsave(&p->lock,flags);
 p->retained_scan_task=current;
 p->retained_scan_ops=0;p->retained_scan_exhausted=false;
 /* Raw io receives one fixed 30s multi / 10s legacy bound, always clipped
  * to the original provider deadline; its 8192 operation cap is unchanged.
  * Multi capture/assignment share the once-frozen provider deadline. */
 if(!expected)p->retained_scan_deadline=io.deadline;
 raw_spin_unlock_irqrestore(&p->lock,flags);
 ret=retained_raw_discover(&io);
 raw_spin_lock_irqsave(&p->lock,flags);
 p->retained_scan_task=NULL; /* Deny ALL subsequent config transactions. */
 raw_spin_unlock_irqrestore(&p->lock,flags);
 if(!ret&&p->retained_scan_exhausted)ret=-ETIMEDOUT;
 if(!ret&&expected&&io.nvidia!=expected)ret=-ENODEV;
 if(!ret&&expected)ret=apple_cio_j314s_chain_owner_validate(p->supplier_context,ticket,port,p->retained_identity_deadline,expected);
 if(!ret&&(endpoint_resources||p->j314s_raw_capability)&&(p->retained_failed||p->retained_record_count!=io.devices))ret=-EPERM;
 if(p->retained_raw_identity){int audit=retained_identity_gate(p);
  if(!audit)audit=retained_dma_blocked(p);
  if(!audit)audit=retained_identity_port_audit(p,true);
  if(!audit)audit=retained_root_rc_audit(p);
  dev_info(p->dev,"retained-raw-identity: scan status %d post-blocked/root audit %d\n",ret,audit);
  if(!ret)ret=audit;
 }else if(!ret)ret=retained_dma_blocked(p);
 dev_info(p->dev,"retained-config: status %d devices %u NVIDIA-display %u config-ops %u; raw identity only, no DMA permit\n",
 ret,io.devices,io.nvidia,p->retained_scan_ops);
 if(ret)goto fail;
 p->retained_phase=10;goto out;
 fail:p->retained_failed=true;
 /* All state stays retained. No bus/core devices exist to bind or remove.
  * Bus-number changes are not reversed/retried; guarded reboot restores stock. */
 out:mutex_unlock(&p->lifecycle);return ret;
}
int apple_apciec_retained_scan_quarantined(struct device*dev,unsigned port,const void*ticket)
{return retained_scan_quarantined_policy(dev,port,ticket,0);}
EXPORT_SYMBOL_GPL(apple_apciec_retained_scan_quarantined);
int apple_apciec_j314s_scan_multiple(struct device*,unsigned,const void*,unsigned);
int apple_apciec_j314s_scan_multiple(struct device*dev,unsigned port,const void*ticket,unsigned expected)
{if(expected!=2&&expected!=4)return -EINVAL;return retained_scan_quarantined_policy(dev,port,ticket,expected);}
EXPORT_SYMBOL_GPL(apple_apciec_j314s_scan_multiple);

#include "transit-identity.inc"
#include "pair-identity.inc"

int apple_apciec_jpc_scan_identity(struct device*,unsigned,const void*,unsigned);
int apple_apciec_jpc_scan_identity(struct device*dev,unsigned port,const void*ticket,unsigned routers)
{
 struct apple_apciec*p=dev_get_drvdata(dev);struct retained_raw_io io={0};
 struct retained_raw_context context={p,ticket};unsigned long flags;int ret;
 if(!p)return -ENODEV;
 if(!jpc_host_mode(p)||!routers||routers>5)return -EPERM;
 /* No PCI core scan/device registration/quirks/retrain or driver binding.
  * Caller still holds neither ACIO/TB lock, retaining parent and ticket. */
 mutex_lock(&p->lifecycle);
 ret=retained_commit_owner(p,port,ticket,8);if(ret)goto out;
 ret=jpc_apple_cio_j314s_chain_owner_validate(p->supplier_context,ticket,port,p->retained_identity_deadline,routers);if(ret)goto out;
 if(!p->tunnel_ready){ret=-EPERM;goto out;}
 p->retained_phase=9;
 ret=retained_dma_blocked(p);if(ret)goto fail;
 io=(struct retained_raw_io){.read=retained_raw_config_read,.write=retained_raw_config_write,
 .valid=retained_raw_valid,.now=retained_raw_clock,.record=retained_raw_record_device,
 .ctx=&context,.first=p->bus_start,.last=p->bus_end,
 .max_depth=16,.max_buses=32,
 .j314s_multi_initial=routers>1,
 .deadline=ktime_get_boottime_ns()+(routers>1?30ULL:10ULL)*NSEC_PER_SEC};
 if(p->retained_raw_identity && io.deadline>p->retained_identity_deadline)io.deadline=p->retained_identity_deadline;
 io.strict_identity=p->retained_raw_identity;
 if(io.strict_identity){io.sleep=retained_raw_sleep;io.audit=retained_raw_host_readiness_audit;io.link_record=retained_raw_record_link;}
 raw_spin_lock_irqsave(&p->lock,flags);
 p->retained_scan_task=current;
 p->retained_scan_ops=0;p->retained_scan_exhausted=false;
 /* Raw io receives one fixed 30s multi / 10s legacy bound, always clipped
  * to the original provider deadline; its 8192 operation cap is unchanged.
  * Multi capture/assignment share the once-frozen provider deadline. */
 p->retained_scan_deadline=io.deadline;
 raw_spin_unlock_irqrestore(&p->lock,flags);
 ret=retained_raw_discover(&io);
 raw_spin_lock_irqsave(&p->lock,flags);
 p->retained_scan_task=NULL; /* Deny ALL subsequent config transactions. */
 raw_spin_unlock_irqrestore(&p->lock,flags);
 if(!ret&&p->retained_scan_exhausted)ret=-ETIMEDOUT;
 if(!ret&&(endpoint_resources||p->j314s_raw_capability)&&(p->retained_failed||p->retained_record_count!=io.devices))ret=-EPERM;
 if(p->retained_raw_identity){int audit=retained_identity_gate(p);
  if(!audit)audit=retained_dma_blocked(p);
  if(!audit)audit=retained_identity_port_audit(p,true);
  if(!audit)audit=retained_root_rc_audit(p);
  dev_info(p->dev,"retained-raw-identity: scan status %d post-blocked/root audit %d\n",ret,audit);
  if(!ret)ret=audit;
 }else if(!ret)ret=retained_dma_blocked(p);
 dev_info(p->dev,"retained-config: status %d devices %u NVIDIA-display %u config-ops %u; raw identity only, no DMA permit\n",
 ret,io.devices,io.nvidia,p->retained_scan_ops);
 if(ret)goto fail;
 ret=jpc_apple_cio_j314s_chain_owner_validate(p->supplier_context,ticket,port,p->retained_identity_deadline,routers);if(ret)goto fail;
 p->retained_phase=10;goto out;
 fail:p->retained_failed=true;
 /* All state stays retained. No bus/core devices exist to bind or remove.
  * Bus-number changes are not reversed/retried; guarded reboot restores stock. */
 out:mutex_unlock(&p->lifecycle);return ret;
}

EXPORT_SYMBOL_GPL(apple_apciec_jpc_scan_identity);
