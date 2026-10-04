/* Local retained preparation experiment. No PE/Hop/scan/commit interface. */
#include <linux/workqueue.h>
#include "apple-external-handoff-core.h"
static bool external_endpoint_memory_assign;
module_param(external_endpoint_memory_assign,bool,0444);
MODULE_PARM_DESC(external_endpoint_memory_assign,"One exact private memory assignment; no decode, PCI publication or DMA");
static bool external_endpoint_resources;
module_param(external_endpoint_resources,bool,0444);
MODULE_PARM_DESC(external_endpoint_resources,"One exact endpoint resource capture/sizing/plan after raw identity; no assignment/DMA");
static bool external_pcie_raw_identity;
module_param(external_pcie_raw_identity,bool,0444);
MODULE_PARM_DESC(external_pcie_raw_identity,"One native-prefix blocked-DART/RC/tunnel/raw identity transaction; no PCI registration or DMA");
static bool external_dart_availability_probe;
module_param(external_dart_availability_probe,bool,0444);
MODULE_PARM_DESC(external_dart_availability_probe,"One retained DART register-availability diagnostic; no provider/tunnel/scan");
static bool external_dart_prepare_only;
module_param(external_dart_prepare_only,bool,0444);
MODULE_PARM_DESC(external_dart_prepare_only,"One retained blocked-DART preparation; no PCI tunnel/scan/commit");
static bool route1_pcie_tunnel;
module_param(route1_pcie_tunnel,bool,0444);
MODULE_PARM_DESC(route1_pcie_tunnel,"One retained exact route1 PCI path and quarantined scan; no DMA driver binding");
static bool external_host_prepare;
module_param(external_host_prepare, bool, 0444);
MODULE_PARM_DESC(external_host_prepare,"Retained external host preparation after same-call USB4 readiness; no PCIe enable");
#if IS_ENABLED(CONFIG_PCIE_APPLE_APCIEC_ENUM_RESEARCH)
#include <generated/utsrelease.h>
#include "pair-boot-policy.h"
extern bool apple_apciec_endpoint_pair_enabled(void);
static bool external_endpoint_pair;
module_param(external_endpoint_pair,bool,0444);
MODULE_PARM_DESC(external_endpoint_pair,"R54 exact controller1 two-GPU cold-boot transaction");
static bool external_pair_boot_valid(void)
{return !READ_ONCE(external_endpoint_pair) || tb_pair_boot_valid(UTS_RELEASE,saved_command_line);}
#include "apple-external-properties.h"
struct external_ticket {
 unsigned controller;
 bool endpoint_pair; /* Immutable explicit controller1 pair selection. */
 struct apple_nhi *anhi;
 struct apple_cio *acio;
 struct tb *tb;
 struct tb_switch *root;
 struct device_node *host_np, *dart_np;
 struct device *host;
 struct bob_inv_result inventory;
 struct ready_io geometry;
 struct external_node nodes[BOB_OWNED_NODES];
 u8 authenticated_drom[sizeof(uid_expected_drom)];
 struct work_struct work;
 struct external_steps steps;
 struct pt_state *tunnel;
 struct of_changeset changeset;
 u64 deadline;
 u32 cable;
 u64 cable_generation;
 unsigned node_phase;
 bool queued;
 bool availability_probe; /* Immutable once this same-call ticket is claimed. */
 bool prepare_only;
 bool raw_identity;
 bool endpoint_resources, endpoint_memory_assign, endpoint_attempted;
 unsigned endpoint_phase;
};
static DEFINE_SPINLOCK(external_barrier_lock);
static struct external_ticket *external_ticket[2];
static struct workqueue_struct *external_queue[2];
static bool external_outer_seen[2];
static int external_outer_status[2];
static atomic_t external_claimed[2]={ ATOMIC_INIT(0), ATOMIC_INIT(0) };
static bool apple_external_options(void)
{
 return external_endpoint_pair==apple_apciec_endpoint_pair_enabled() &&
 external_pair_boot_valid() &&
 (!external_endpoint_pair || (external_endpoint_memory_assign && external_pcie_raw_identity &&
  apple_apciec_endpoint_native_enabled() && apple_apciec_endpoint_pci_enabled() && apple_apciec_endpoint_mmio_enabled())) &&
 external_endpoint_memory_assign == apple_apciec_endpoint_memory_assign_enabled() &&
 (!external_endpoint_memory_assign || external_endpoint_resources) &&
 external_endpoint_resources == apple_apciec_endpoint_resources_enabled() &&
 (!external_endpoint_resources || external_pcie_raw_identity) &&
 external_dart_availability_probe + external_dart_prepare_only + external_pcie_raw_identity <= 1 &&
 (!external_pcie_raw_identity || (route1_pcie_tunnel && apple_apciec_raw_identity_enabled())) &&
 (!external_dart_prepare_only ||
  (!route1_pcie_tunnel && apple_apciec_availability_probe_enabled())) &&
 (!external_dart_availability_probe ||
         (!route1_pcie_tunnel && apple_apciec_availability_probe_enabled())) &&
 external_host_prepare && root_router_only && root_cable_only &&
 attached_router_identity && root_port1_unlock && route1_inventory &&
 route1_header_config && route1_usb4_ready && apple_apciec_retained_enabled();
}
static bool external_node_state(struct external_ticket *t)
{
 struct platform_device *h,*d;bool ok;
 if(of_device_is_available(t->host_np)!=(t->node_phase>=1) ||
    of_device_is_available(t->dart_np)!=(t->node_phase>=2))return false;
 if(of_node_check_flag(t->host_np,OF_POPULATED)!=(t->node_phase>=1) ||
    of_node_check_flag(t->host_np,OF_POPULATED_BUS)!=(t->node_phase>=2) ||
    of_node_check_flag(t->dart_np,OF_POPULATED)!=(t->node_phase>=2) ||
    of_node_check_flag(t->dart_np,OF_POPULATED_BUS))return false;
 h=of_find_device_by_node(t->host_np);d=of_find_device_by_node(t->dart_np);
 ok=t->node_phase? h && &h->dev==t->host && h->dev.driver &&
    !strcmp(h->dev.driver->name,"apple-apciec-research-disabled"):!h;
 if(t->node_phase>=2)ok=ok&&d&&d->dev.driver&&!strcmp(d->dev.driver->name,"apple-dart");
 else ok=ok&&!d;
 if(h)put_device(&h->dev);
 if(d)put_device(&d->dev);
 return ok;
}
static bool external_context(void *arg)
{
 struct external_ticket*t=arg;struct apple_nhi*a=t->anhi;struct apple_cio*c=t->acio;
 return t->controller<BOB_CONTROLLERS && bob_controller_index(a->np)==t->controller &&
 t->endpoint_pair==(t->controller==1 && READ_ONCE(external_endpoint_pair)) &&
 t->availability_probe==READ_ONCE(external_dart_availability_probe) &&
 t->prepare_only==READ_ONCE(external_dart_prepare_only) &&
 t->raw_identity==READ_ONCE(external_pcie_raw_identity) &&
 t->endpoint_resources==READ_ONCE(external_endpoint_resources) &&
 t->endpoint_memory_assign==READ_ONCE(external_endpoint_memory_assign) &&
 apple_external_options() && of_machine_is_compatible("apple,j293") &&
 a->acio==c && a->tb==t->tb && t->tb->root_switch==t->root && !tb_route(t->root) &&
 READ_ONCE(c->root_cable_nhi)==a && READ_ONCE(c->root_dma_retained) &&
 !READ_ONCE(c->root_stopping) && !READ_ONCE(a->enum_stopping) &&
 !READ_ONCE(c->root_probe_status) && smp_load_acquire(&c->root_cable_snapshot_valid) &&
 READ_ONCE(c->root_cable_snapshot)==t->cable &&
 READ_ONCE(c->external_cable_generation)==t->cable_generation &&
 READ_ONCE(c->target_cable_info)==t->cable && READ_ONCE(c->current_cable_info)==t->cable &&
 external_node_state(t) && external_nodes_unchanged_profile(t->nodes,t->controller,t->node_phase,
   t->endpoint_phase==(t->endpoint_pair?30:20) && apple_apciec_endpoint_native_enabled(),t->endpoint_pair) &&
 external_other_controllers_owned(t->acio->np);
}
static u64 external_clock(void *unused){return ktime_get_boottime_ns();}
static int external_read(void *arg,unsigned route,unsigned port,bool sw,unsigned off,unsigned n,u32*v)
{
 struct external_ticket*t=arg;
 if(!external_context(t)||ktime_get_boottime_ns()>=t->deadline||route>1||!n||n>8||off>8192-n||
    (sw?port!=0:!(port==1||(!route&&port==3)||(route&&port==t->inventory.pci_up))))return -EPERM;
 return tb_cfg_read(t->tb->ctl,v,route,port,sw?TB_CFG_SWITCH:TB_CFG_PORT,off,n);
}
static int external_proof_locked_state(struct external_ticket*t,unsigned pe)
{
 struct ready_io i={.read=external_read,.valid=external_context,.now=external_clock,
 .ctx=t,.deadline=t->deadline,.up=t->inventory.pci_up,.pe_expected=pe};
 u32 v[5];int ret;unsigned r,k;
 lockdep_assert_held(&t->acio->lock);lockdep_assert_held(&t->tb->lock);
 ret=ready_discover(&i);if(ret)return ret;
 if(i.rt!=t->geometry.rt||i.ct!=t->geometry.ct||i.rtime!=t->geometry.rtime||
 i.ctime!=t->geometry.ctime||i.rphy!=t->geometry.rphy||i.cphy!=t->geometry.cphy||
 i.rpcie!=t->geometry.rpcie||i.cpcie!=t->geometry.cpcie||i.usb4!=t->geometry.usb4)return -ESTALE;
 ret=ready_read(&i,1,0,true,7,2,v);if(ret)return ret;
 if(v[0]!=(u32)(bob_router_uid(t->controller,0)>>32)||v[1]!=(u32)bob_router_uid(t->controller,0))return -ESTALE;
 for(k=0;k<4;k++){
  const struct bob_inv_port*p=&t->inventory.selected[k];
  /* Native PORT CS0..3 include immutable type/number, not mutable link state. */
  ret=ready_read(&i,p->route,p->port,false,0,4,v);if(ret)return ret;
  if(memcmp(v,p->header,16))return -ESTALE;
 }
 for(r=0;r<2;r++){
  unsigned phy=r?i.cphy:i.rphy,time=r?i.ctime:i.rtime,tmu=r?i.ct:i.rt;
  ret=ready_read(&i,r,1,false,phy+1,1,v);if(ret)return ret;
  if(((v[0]>>26)&15)<TB_PORT_UP||((v[0]>>26)&15)>TB_PORT_CL2||v[0]&(BIT(11)|BIT(14)))return -ENOLINK;
  ret=ready_read(&i,r,0,true,tmu,1,v);if(ret)return ret;
  if(v[0]&BIT(27))return -ESTALE;
  if(v[0]&BIT(30)){
   ret=ready_read(&i,r,1,false,time+3,1,v);if(ret)return ret;
   if(v[0]&BIT(29))return -ESTALE;
  }
  ret=ready_read(&i,r,0,true,tmu+3,1,v);if(ret)return ret;
  if(v[0]>>16!=(r?16:1000))return -ESTALE;
  ret=ready_read(&i,r,1,false,time+6,1,v);if(ret)return ret;
  if(v[0]&2)return -ESTALE;
 }
 ret=ready_read(&i,1,1,false,i.ctime+8,1,v);if(ret)return ret;
 if(v[0]&BIT(15))return -ESTALE;
 ret=ready_read(&i,0,1,false,i.usb4+18,1,v);if(ret)return ret;
 if(v[0]&BIT(9))return -ESTALE;
 ret=ready_read(&i,1,0,true,5,2,v);if(ret)return ret;
 if((v[0]&(BIT(31)|BIT(24)|BIT(23)|1))!=(BIT(31)|BIT(24))||
 (v[1]&(BIT(24)|BIT(25)))!=(BIT(24)|BIT(25)))return -ESTALE;
 return ready_contained(&i);
}
static int external_proof_locked(struct external_ticket*t)
{return external_proof_locked_state(t,0);}
static int external_proof(void*arg,unsigned phase)
{
 struct external_ticket*t=arg;int ret;
 mutex_lock(&t->acio->lock);mutex_lock(&t->tb->lock);
 ret=t->node_phase==phase?external_proof_locked(t):-EPERM;
 mutex_unlock(&t->tb->lock);mutex_unlock(&t->acio->lock);return ret;
}
static int external_barrier(void*arg)
{
 struct external_ticket*t=arg;
 /* Never hold ACIO/TB while waiting for device/probe completion. */
 device_lock(t->acio->dev);device_unlock(t->acio->dev);
 device_lock(t->anhi->dev);device_unlock(t->anhi->dev);
 return READ_ONCE(external_outer_seen[t->controller])&&!READ_ONCE(external_outer_status[t->controller])?0:-EPERM;
}
static int external_outside_gate(struct external_ticket*t)
{
 if(ktime_get_boottime_ns()>=t->deadline)return -ETIMEDOUT;
 if(t->availability_probe!=READ_ONCE(external_dart_availability_probe)||
    t->prepare_only!=READ_ONCE(external_dart_prepare_only)||
    t->raw_identity!=READ_ONCE(external_pcie_raw_identity)||
    t->endpoint_resources!=READ_ONCE(external_endpoint_resources)||
    t->endpoint_memory_assign!=READ_ONCE(external_endpoint_memory_assign)||
    !apple_external_options()||READ_ONCE(t->acio->root_stopping)||
    READ_ONCE(t->anhi->enum_stopping)||READ_ONCE(t->acio->root_probe_status)||
    READ_ONCE(t->acio->target_cable_info)!=t->cable||
    READ_ONCE(t->acio->current_cable_info)!=t->cable||
    READ_ONCE(t->acio->external_cable_generation)!=t->cable_generation)return -ESHUTDOWN;
 return 0;
}
static int external_host_create(void*arg)
{
 struct external_ticket*t=arg;struct property*p;struct platform_device*h;int ret;
 lockdep_assert_not_held(&t->acio->lock);lockdep_assert_not_held(&t->tb->lock);
 ret=external_outside_gate(t);if(ret)return ret;
 p=kzalloc(sizeof(*p),GFP_KERNEL);if(!p)return -ENOMEM;
 p->name=kstrdup("status",GFP_KERNEL);p->value=kstrdup("okay",GFP_KERNEL);p->length=5;
 if(!p->name||!p->value)return -ENOMEM;
 of_changeset_init(&t->changeset);
 ret=of_changeset_update_property(&t->changeset,t->host_np,p);if(ret)return ret;
 ret=external_outside_gate(t);if(ret)return ret;
 ret=of_changeset_apply(&t->changeset);if(ret)return ret;
 /* Normal platform notifier is the sole creator. No attach/reprobe fallback. */
 h=of_find_device_by_node(t->host_np);if(!h)return -ENODEV;
 t->host=&h->dev;
 device_lock(t->host);
 ret=t->host->driver&&!strcmp(t->host->driver->name,"apple-apciec-research-disabled")&&
 dev_get_drvdata(t->host)?0:-ENODEV;
 device_unlock(t->host);
 if(!ret)t->node_phase=1;
 return ret;
}
static int external_attach(void*arg)
{
 static const char*const names[]={"apciec-core","apciec-port"};
 struct external_ticket*t=arg;unsigned k;int ret;
 lockdep_assert_not_held(&t->acio->lock);lockdep_assert_not_held(&t->tb->lock);
 if(t->anhi->enum_host||t->anhi->enum_pd[0]||t->anhi->enum_pd[1])return -EALREADY;
 t->anhi->enum_host=get_device(t->host);
 for(k=0;k<2;k++){
  struct device*pd;
  ret=external_outside_gate(t);if(ret)return ret;
  pd=dev_pm_domain_attach_by_name(t->host,names[k]);
  if(IS_ERR_OR_NULL(pd))return pd?PTR_ERR(pd):-ENODEV;
  t->anhi->enum_pd[k]=pd; /* Never detach successful partial attachments. */
 }
 return 0;
}
static int external_power(void*arg)
{
 struct external_ticket*t=arg;int ret,proof;
 mutex_lock(&t->acio->lock);mutex_lock(&t->tb->lock);
 ret=external_proof_locked(t);if(ret)goto out;
 if(t->anhi->enum_bound){ret=-EALREADY;goto out;}
 ret=apple_apciec_enum_bind(t->host,t->anhi,&apple_nhi_enum_supplier,3);if(ret)goto out;
 t->anhi->enum_port=3;t->anhi->enum_bound=true;
 ret=t->availability_probe?
 apple_apciec_retained_begin_availability_probe(t->host,3,t):
 t->prepare_only?apple_apciec_retained_begin_provider_prepare(t->host,3,t):
 t->raw_identity?apple_apciec_retained_begin_raw_identity(t->host,3,t,t->deadline):
 apple_apciec_retained_begin_power(t->host,3,t);
 if(t->prepare_only||t->raw_identity){
  proof=external_proof_locked(t);
  dev_info(t->anhi->dev,"dart-prepare-only: prefix status %d post-context/PE proof %d\n",ret,proof);
  if(!ret)ret=proof;
 }
 out:mutex_unlock(&t->tb->lock);mutex_unlock(&t->acio->lock);return ret;
}
static int external_availability_sample(void*arg)
{
 struct external_ticket*t=arg;int ret, proof;
 mutex_lock(&t->acio->lock);mutex_lock(&t->tb->lock);
 ret=t->availability_probe&&!t->prepare_only&&!t->raw_identity?external_proof_locked(t):-EPERM;
 if(!ret){
  ret=apple_apciec_retained_sample_availability(t->host,3,t);
  proof=external_proof_locked(t); /* After every sample result, including failure. */
  dev_info(t->anhi->dev,"dart-availability-probe: sample status %d post-context/PE proof %d\n",ret,proof);
  if(!ret)ret=proof;
 }
 /* Even a successful sample is not a DART provider or permission to commit. */
 mutex_unlock(&t->tb->lock);mutex_unlock(&t->acio->lock);return ret;
}
static int external_dart(void*arg)
{
 struct external_ticket*t=arg;int ret,proof;
 lockdep_assert_not_held(&t->acio->lock);lockdep_assert_not_held(&t->tb->lock);
 if(t->availability_probe)return -EPERM;
 ret=external_outside_gate(t);if(ret)return ret;
 ret=apple_apciec_retained_populate_dart(t->host,3,t);
 if(!ret)t->node_phase=2;
 if(t->prepare_only||t->raw_identity){
  proof=external_proof(t,t->node_phase);
  dev_info(t->anhi->dev,"dart-prepare-only: provider status %d post-context/PE proof %d\n",ret,proof);
  if(!ret)ret=proof;
 }
 return ret;
}
static int external_finish(void*arg)
{
 struct external_ticket*t=arg;int ret,proof;
 if(t->availability_probe)return -EPERM;
 mutex_lock(&t->acio->lock);mutex_lock(&t->tb->lock);
 ret=external_proof_locked(t);
 if(!ret){
  ret=apple_apciec_retained_finish(t->host,3,t);
  if(t->prepare_only||t->raw_identity){
   proof=external_proof_locked(t);
   dev_info(t->anhi->dev,"dart-prepare-only: finish status %d post-context/PE proof %d\n",ret,proof);
   if(!ret)ret=proof;
  }
 }
 mutex_unlock(&t->tb->lock);mutex_unlock(&t->acio->lock);return ret;
}
#include "apple-retained-pcie-tunnel.inc"
#include "apple-retained-endpoint.inc"
#include "apple-chain-tunnels.inc"
#include "apple-transit-endpoint.inc"
#include "apple-pair-endpoint.inc"
static void external_work(struct work_struct*w)
{
 struct external_ticket*t=container_of(w,struct external_ticket,work);
 int ret;
 dev_info(t->anhi->dev,"r23 external worker begin; existing ticket deadline unchanged\n");
 msleep(100); /* Process context, before acquiring any supplier/host locks. */
 if(t->availability_probe){
  ret=external_probe_steps_run(&t->steps);
  dev_info(t->anhi->dev,"dart-availability-probe: terminal status %d phase %u; retained until stock reboot; no provider/PE/Hop/scan/commit\n",ret,t->steps.phase);
  return; /* Unconditional: no diagnostic result enters the tunnel path. */
 }
 if(t->prepare_only){
  ret=external_steps_run(&t->steps);
  dev_info(t->anhi->dev,"dart-prepare-only: terminal status %d phase %u; retained until stock reboot; no PE/Hop/scan/commit\n",ret,t->steps.phase);
  return;
 }
 if(t->raw_identity){
  ret=external_steps_run(&t->steps);
  if(!ret)ret=apple_retained_pcie_tunnel(t);
  if(!ret&&!t->controller&&t->endpoint_resources)ret=apple_retained_endpoint_plan(t);
  if(!ret&&(t->controller||t->endpoint_resources))ret=apple_retained_chain_tunnels(t);
  if(!ret&&t->controller&&t->endpoint_resources)ret=t->endpoint_pair ?
   apple_retained_pair_endpoint_plan(t):apple_retained_transit_endpoint_plan(t);
  if(t->tunnel)dev_info(t->anhi->dev,"retained-raw-identity: last I/O route %u port %u space %u offset %u count %u write %u result %d; operations %u programmed %u PE attempted %u\n",
   t->tunnel->last_route,t->tunnel->last_port,t->tunnel->last_space,t->tunnel->last_offset,t->tunnel->last_count,t->tunnel->last_write,t->tunnel->last_result,t->tunnel->ops,t->tunnel->programmed,t->tunnel->pe_attempted);
  if(t->endpoint_pair)
   dev_info(t->anhi->dev,"retained-controller1-pair: terminal status %d phase %u; targets0600+0300 only; audio0301/0601 excluded\n",ret,t->endpoint_phase);
  else if(t->controller)
   dev_info(t->anhi->dev,"retained-transit-identity: controller1 terminal status %d phase %u; excluded RID0300/0301 untouched; selected RID0600 only\n",ret,t->endpoint_phase);
  else if(apple_apciec_endpoint_native_enabled())
   dev_info(t->anhi->dev,"retained-native-driver: terminal status %d phase %u; retained until stock reboot; selected GPU driver pending\n",ret,t->endpoint_phase);
  else if(apple_apciec_endpoint_mmio_enabled())
   dev_info(t->anhi->dev,"retained-mmio-probe: terminal status %d phase %u; retained until stock reboot; no endpoint driver or DMA permit\n",ret,t->endpoint_phase);
  else if(apple_apciec_endpoint_pci_enabled())
   dev_info(t->anhi->dev,"retained-pci-register: terminal status %d phase %u; retained until stock reboot; no endpoint driver or DMA permit\n",ret,t->endpoint_phase);
  else if(t->endpoint_memory_assign)
   dev_info(t->anhi->dev,"retained-memory-assignment: terminal status %d phase %u; retained until stock reboot; no decode, PCI registration, endpoint driver or DMA permit\n",ret,t->endpoint_phase);
  else if(t->endpoint_resources)
   dev_info(t->anhi->dev,"retained-endpoint-plan: terminal status %d phase %u; retained until stock reboot; no assignment, PCI registration, endpoint driver or DMA permit\n",ret,t->endpoint_phase);
  else dev_info(t->anhi->dev,"retained-raw-identity: terminal status %d phase %u; retained until stock reboot; no PCI registration, endpoint driver or DMA permit\n",ret,t->tunnel?t->tunnel->phase:t->steps.phase);
  return;
 }
 ret=external_steps_run(&t->steps);
 if(!ret&&route1_pcie_tunnel){
  ret=apple_retained_pcie_tunnel(t);
  if(t->tunnel)dev_info(t->anhi->dev,"retained-pcie: last I/O route %u port %u space %u offset %u count %u write %u result %d; operations %u programmed %u PE attempted %u\n",
  t->tunnel->last_route,t->tunnel->last_port,t->tunnel->last_space,t->tunnel->last_offset,t->tunnel->last_count,t->tunnel->last_write,t->tunnel->last_result,t->tunnel->ops,t->tunnel->programmed,t->tunnel->pe_attempted);
  dev_info(t->anhi->dev,"retained-pcie: terminal status %d phase %u; retained, no endpoint driver binding\n",ret,t->tunnel?t->tunnel->phase:0);
  return;
 }
 dev_info(t->anhi->dev,"external-prepare: terminal status %d phase %u; retained, no PE/Hop/scan\n",ret,t->steps.phase);
 if(!ret)dev_info(t->anhi->dev,"external-prepare: exact host isolated, DART blocked, both PE clear; no tunnel/scan\n");
 /* No reschedule, cleanup, unbind, put, changeset destroy or free. */
}
static void external_queue_locked(unsigned controller)
{
 struct external_ticket *t=external_ticket[controller];
 if(t&&external_outer_seen[controller]&&!t->queued){
  t->queued=true;
  queue_work(external_queue[controller],&t->work);
 }
}
/* Completion for one controller cannot release the other controller's ticket. */
int apple_cio_external_outer_complete_port(unsigned int controller,int overlay_status);
int apple_cio_external_outer_complete_port(unsigned int controller,int overlay_status)
{
 unsigned long flags;int ret=0;
 if(controller>=BOB_CONTROLLERS)return -EINVAL;
 if(!external_host_prepare)return -EOPNOTSUPP;
 spin_lock_irqsave(&external_barrier_lock,flags);
 if(external_outer_seen[controller])ret=-EALREADY;
 else{external_outer_status[controller]=overlay_status;external_outer_seen[controller]=true;external_queue_locked(controller);}
 spin_unlock_irqrestore(&external_barrier_lock,flags);return ret;
}
EXPORT_SYMBOL_GPL(apple_cio_external_outer_complete_port);
int apple_cio_external_outer_complete(int overlay_status);
int apple_cio_external_outer_complete(int overlay_status)
{return apple_cio_external_outer_complete_port(0,overlay_status);}
EXPORT_SYMBOL_GPL(apple_cio_external_outer_complete);
static int apple_external_claim(struct apple_nhi*a,const struct bob_inv_result*inv,const struct ready_io*ready)
{
 struct external_ticket*t;unsigned long flags;struct device_node*np;int ret;
 int controller=bob_controller_index(a->np);
 lockdep_assert_held(&a->acio->lock);lockdep_assert_held(&a->tb->lock);
 if(!external_host_prepare)return 0;
 dev_info(a->dev,"r23 external claim begin; readiness already complete\n");
 msleep(100); /* ACIO/TB are mutexes; no IRQ/spin lock is held here. */
 if(!apple_external_options()||!apple_unlock_context(a)||!child_inventory_valid(inv)||ready->phase!=5||inv->pci_up!=9||ready->up!=9||ready->rpcie!=9||ready->cpcie!=57)return -EPERM;
 if(controller<0)return -EPERM;
 if(controller && (!external_pcie_raw_identity || !route_chain_prepare || !route_chain_tunnels || !apple_j293_peer_retained(0)))return -EPERM;
 if(atomic_cmpxchg(&external_claimed[controller],0,1))return -EALREADY;
 t=kzalloc(sizeof(*t),GFP_KERNEL);if(!t)return -ENOMEM;
 t->controller=controller;
 t->endpoint_pair=controller==1 && READ_ONCE(external_endpoint_pair);
 t->availability_probe=READ_ONCE(external_dart_availability_probe);
 t->prepare_only=READ_ONCE(external_dart_prepare_only);
 t->raw_identity=READ_ONCE(external_pcie_raw_identity);
 t->endpoint_resources=READ_ONCE(external_endpoint_resources);
 t->endpoint_memory_assign=READ_ONCE(external_endpoint_memory_assign);
 t->anhi=a;t->acio=a->acio;t->tb=a->tb;t->root=a->tb->root_switch;
 t->inventory=*inv;t->geometry=*ready;t->geometry.ctx=NULL;
 memcpy(t->authenticated_drom,uid_expected_drom,sizeof(uid_expected_drom));
 { u64 uid=bob_router_uid(controller,0);unsigned j;
  for(j=0;j<8;j++)t->authenticated_drom[1+j]=uid>>(8*j);
  t->authenticated_drom[0]=uid_crc8(t->authenticated_drom+1);
 }
 ret=external_capture_nodes(t->nodes,controller);if(ret)return ret;
 if(!external_nodes_unchanged(t->nodes,t->controller,0,false)||!external_other_controllers_owned(a->acio->np))return -EPERM;
 t->cable=READ_ONCE(a->acio->root_cable_snapshot);
 t->cable_generation=READ_ONCE(a->acio->external_cable_generation);
 t->deadline=ktime_get_boottime_ns()+30ULL*NSEC_PER_SEC;
 t->host_np=of_find_node_by_path(bob_controller_paths[controller][7]);
 t->dart_np=of_find_node_by_path(bob_controller_paths[controller][8]);
 if(!t->host_np||!t->dart_np||t->dart_np->parent!=t->host_np)return -EPERM;
 np=of_parse_phandle(a->np,"research,apciec-host",0);
 if(np!=t->host_np){of_node_put(np);return -EPERM;}of_node_put(np);
 get_device(a->dev);get_device(a->acio->dev);
 get_device(&t->tb->dev);get_device(&t->root->dev);
 external_queue[controller]=alloc_ordered_workqueue("j293-external-retained-%u",WQ_MEM_RECLAIM,controller);
 if(!external_queue[controller])return -ENOMEM;
 INIT_WORK(&t->work,external_work);
 t->steps=(struct external_steps){external_barrier,external_proof,external_host_create,
 external_attach,external_power,
 t->availability_probe?external_availability_sample:external_dart,external_finish,t,0,false};
 spin_lock_irqsave(&external_barrier_lock,flags);
 external_ticket[controller]=t;external_queue_locked(controller);
 spin_unlock_irqrestore(&external_barrier_lock,flags);
 dev_info(a->dev,"external-prepare: same-call readiness ticket retained; awaiting outer OF return\n");
 dev_info(a->dev,"r23 external claim complete\n");
 return 0;
}
#else
static bool apple_external_options(void){return false;}
static int apple_external_claim(struct apple_nhi*a,const struct bob_inv_result*i,const struct ready_io*r)
{return external_host_prepare?-EOPNOTSUPP:0;}
#endif
