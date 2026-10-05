/* Single synchronous continuation owned by provider action mutex/task/ticket. */
#include "j314s-raw-tunnel-core.h"
extern int apple_apciec_j314s_begin_raw(struct device *,unsigned,const void *,u64);
extern int apple_apciec_j314s_endpoint_resources(struct device *,unsigned,const void *,
 const struct ep_identity *,const struct ep_snapshot **,unsigned *);
static const struct ep_snapshot *j314s_raw_snapshot;
static unsigned j314s_raw_resource_phase;
static struct jraw_pt_state *j314s_raw_path;
static bool j314s_raw_consumed,j314s_raw_complete;
static const struct ep_identity *j314s_raw_records;
static unsigned j314s_raw_record_count;
static int j314s_raw_status=-EINPROGRESS;
static bool j314s_raw_valid(void *arg)
{
 typeof(j314s_provider_owner)*t=&j314s_provider_owner;
 return arg==t&&j314s_raw_consumed&&!j314s_raw_complete&&j314s_raw_path&&
  t->complete&&t->phase==4&&!t->status&&j314s_provider_frozen_valid();
}
int apple_cio_j314s_raw_owner_validate(void *,const void *,unsigned,u64);
int apple_cio_j314s_raw_owner_validate(void *owner,const void *ticket,unsigned port,u64 deadline)
{
 typeof(j314s_provider_owner)*t=&j314s_provider_owner;
 if(owner!=t->a||ticket!=t||port!=3||port!=t->down||deadline!=t->deadline||
    !j314s_raw_valid(t)||t->up!=9||t->route!=1||t->bootstrap->pins.lane!=1)
  return -EPERM;
 return 0;
}
EXPORT_SYMBOL_GPL(apple_cio_j314s_raw_owner_validate);
static u64 j314s_raw_now(void *arg){return ktime_get_boottime_ns();}
static void j314s_raw_sleep(void *arg){usleep_range(50,100);}
static int j314s_raw_read(void *arg,unsigned r,unsigned p,unsigned sp,unsigned off,unsigned n,u32 *v)
{
 typeof(j314s_provider_owner)*t=arg;
 if(!j314s_raw_valid(arg)||r>1||!n||n>8||off>8192-n||sp>JRAW_PT_HOPS||
    (sp==JRAW_PT_SW?p!=0:(!p||p>63)))return -EPERM;
 return tb_cfg_read(t->tb->ctl,v,r,p,sp==JRAW_PT_SW?TB_CFG_SWITCH:sp==JRAW_PT_PORT?TB_CFG_PORT:TB_CFG_HOPS,off,n);
}
static int j314s_raw_write(void *arg,unsigned r,unsigned p,unsigned sp,unsigned off,unsigned n,const u32 *v)
{
 typeof(j314s_provider_owner)*t=arg;
 if(!j314s_raw_valid(arg)||!jraw_pt_write_allowed(j314s_raw_path,r,p,sp,off,n,v))return -EPERM;
 return tb_cfg_write(t->tb->ctl,v,r,p,sp==JRAW_PT_SW?TB_CFG_SWITCH:sp==JRAW_PT_PORT?TB_CFG_PORT:TB_CFG_HOPS,off,n);
}
static int j314s_raw_proof(void *arg,unsigned pe)
{
 if(!j314s_raw_valid(arg)||pe!=j314s_raw_path->pe)return -EPERM;
 return j314s_provider_live_state(pe);
}
static int j314s_raw_audit(void *arg)
{
 typeof(j314s_provider_owner)*t=arg;
 if(!j314s_raw_valid(arg))return -EPERM;
 return apple_apciec_retained_prepared_audit(t->host,3,t);
}
static int j314s_raw_commit(void *arg)
{
 typeof(j314s_provider_owner)*t=arg;int ret;
 if(!j314s_raw_valid(arg)||j314s_raw_path->phase!=4||
    j314s_raw_path->programmed!=4||j314s_raw_path->pe!=3)return -EPERM;
 ret=j314s_raw_proof(arg,3);
 if(!ret)ret=jraw_pt_verify(j314s_raw_path);
 return ret?ret:apple_apciec_retained_commit(t->host,3,t);
}
static int j314s_native_continue(void);
static int j314s_raw_continue_single(void)
{
 typeof(j314s_provider_owner)*t=&j314s_provider_owner;
 struct j314s_combined_result*r=t->bootstrap;int ret,post;
 if(j314s_raw_consumed)return -EALREADY;
 j314s_raw_consumed=true;
 j314s_raw_path=kzalloc(sizeof(*j314s_raw_path),GFP_KERNEL);
 if(!j314s_raw_path)return -ENOMEM;
 *j314s_raw_path=(struct jraw_pt_state){.read=j314s_raw_read,.write=j314s_raw_write,
  .valid=j314s_raw_valid,.now=j314s_raw_now,.sleep=j314s_raw_sleep,
  .proof=j314s_raw_proof,.audit=j314s_raw_audit,.commit=j314s_raw_commit,.ctx=t,
  .deadline=t->deadline,.phy={r->ready.rphy,r->ready.cphy},
  .pcie={r->ready.rpcie,r->ready.cpcie},.disabled={0,r->inventory.disabled_ports}};
 memcpy(j314s_raw_path->target_root,r->pins.root,sizeof(j314s_raw_path->target_root));
 mutex_lock(&t->c->lock);mutex_lock(&t->tb->lock);
 ret=j314s_provider_live_closed();
 if(!ret)ret=apple_apciec_j314s_begin_raw(t->host,3,t,t->deadline);
 if(!ret)ret=apple_apciec_retained_root_rc_prepare(t->host,3,t);
 if(!ret)ret=j314s_provider_live_closed();
 if(!ret)ret=jraw_pt_once(j314s_raw_path);
 mutex_unlock(&t->tb->lock);mutex_unlock(&t->c->lock);
 if(!ret&&!j314s_raw_valid(t))ret=-EPERM;
 if(!ret)ret=apple_apciec_retained_scan_quarantined(t->host,3,t);
 if(!ret)ret=apple_apciec_retained_raw_final_audit(t->host,3,t);
 if(!ret)ret=apple_apciec_retained_records(t->host,3,t,&j314s_raw_records,&j314s_raw_record_count);
 mutex_lock(&t->c->lock);mutex_lock(&t->tb->lock);
 post=j314s_raw_proof(t,j314s_raw_path->pe);
 if(!post&&j314s_raw_path->programmed==4)post=jraw_pt_verify(j314s_raw_path);
 if(!ret)ret=post;
 mutex_unlock(&t->tb->lock);mutex_unlock(&t->c->lock);
 if(!ret) {
  const struct ep_identity *selected=NULL;unsigned j;
  for(j=0;j<j314s_raw_record_count;j++) {
   const struct ep_identity *id=&j314s_raw_records[j];unsigned gpu=id->id>>16;
   if((id->id&65535)==0x10de&&(gpu==0x2d04||gpu==0x2c02||gpu==0x2c18)&&
      (id->class_rev>>16)==0x0300&&!(id->header&0x7f)&&!(id->rid&7)&&id->rid&&
      (!selected||id->rid<selected->rid))selected=id;
  }
  if(!selected)ret=-ENODEV;
  else ret=apple_apciec_j314s_endpoint_resources(t->host,3,t,selected,
               &j314s_raw_snapshot,&j314s_raw_resource_phase);
  mutex_lock(&t->c->lock);mutex_lock(&t->tb->lock);
  post=j314s_raw_proof(t,3);
  if(!post)post=jraw_pt_verify(j314s_raw_path);
  if(!ret)ret=post;
  mutex_unlock(&t->tb->lock);mutex_unlock(&t->c->lock);
  if(!ret&&(!j314s_raw_snapshot||!j314s_raw_snapshot->planned||
            j314s_raw_resource_phase!=12))ret=-EPERM;
 }
 if(!ret)ret=j314s_native_continue();
 j314s_raw_status=ret;j314s_raw_complete=!ret;
 pr_info("j314s-raw: status%d phase%u operations%u hops%u PE%u; records frozen, DMA blocked\n",
  ret,j314s_raw_path->phase,j314s_raw_path->ops,j314s_raw_path->programmed,j314s_raw_path->pe);
 return ret;
}

/* Historical evidence only. Getter never extends deadline or authorizes I/O. */
int apple_cio_j314s_raw_state(unsigned,u32 *,int *,unsigned *);
int apple_cio_j314s_raw_state(unsigned controller,u32 *flags,int *status,unsigned *count)
{
 if(controller||!flags||!status||!count)return -EINVAL;
 *flags=0;*status=-EINPROGRESS;*count=0;
 if(!mutex_trylock(&j314s_provider_action_lock))return -EAGAIN;
 if(j314s_raw_consumed)*flags|=BIT(0);
 if(j314s_raw_path){
  *flags|=BIT(1);
  if(j314s_raw_path->programmed==4)*flags|=BIT(2);
  if(j314s_raw_path->pe==3)*flags|=BIT(3);
 }
 if(j314s_raw_complete&&!j314s_raw_status&&!j314s_provider_owner.failed&&
    j314s_provider_identity_valid()&&j314s_raw_records&&j314s_raw_record_count){
  *flags|=BIT(4);*count=j314s_raw_record_count;*status=0;
 }else *status=j314s_provider_owner.failed?j314s_provider_owner.status:
  j314s_raw_status?j314s_raw_status:-EPERM;
 mutex_unlock(&j314s_provider_action_lock);return 0;
}
EXPORT_SYMBOL_GPL(apple_cio_j314s_raw_state);

#include <linux/apple-j314s-bar-report.h>
extern int apple_apciec_j314s_resource_state(struct device *,u32 *,int *,struct apple_j314s_bar_report *);
int apple_cio_j314s_bar_state(unsigned,u32 *,int *,struct apple_j314s_bar_report *);
int apple_cio_j314s_bar_state(unsigned controller,u32 *flags,int *status,struct apple_j314s_bar_report *report)
{
 int ret;typeof(j314s_provider_owner)*t=&j314s_provider_owner;
 if(controller||!flags||!status||!report)return -EINVAL;
 *flags=0;*status=-EINPROGRESS;memset(report,0,sizeof(*report));
 if(!mutex_trylock(&j314s_provider_action_lock))return -EAGAIN;
 if(t->failed||!j314s_raw_complete||j314s_raw_status||!j314s_provider_identity_valid()||!t->host){
  *status=t->failed?t->status:j314s_raw_status?j314s_raw_status:-EPERM;ret=0;
 }else ret=apple_apciec_j314s_resource_state(t->host,flags,status,report);
 mutex_unlock(&j314s_provider_action_lock);return ret;
}
EXPORT_SYMBOL_GPL(apple_cio_j314s_bar_state);

#include "apple-j314s-native-front.inc"

/* Explicit target linear path; original single implementation remains above.
 * Later definitions are appended after this include by the owning translation
 * unit: chain-tunnels then chain-tunnel-proof. No opaque host struct access. */
struct j314s_multi_resource_owner;
extern int apple_apciec_j314s_scan_multiple(struct device*,unsigned,const void*,unsigned);
extern int apple_apciec_j314s_capture_multiple(struct device*,unsigned,const void*,unsigned,
 const struct j314s_multi_resource_owner**,unsigned*);
extern int apple_apciec_j314s_assign_multi(struct device*,unsigned,const void*,unsigned,unsigned*);
extern int apple_apciec_j314s_native_prepare_multi(struct device*,unsigned,const void*,unsigned,unsigned*);
extern int apple_apciec_j314s_native_publish_multi(struct device*,unsigned,const void*,unsigned,unsigned*);
static int apple_j314s_chain_tunnels_cold(unsigned);
static int apple_j314s_tunnel_seal_locked(void);
int apple_cio_j314s_tunnel_proof_locked(void*,const void*,u64);
static struct {
 bool selected,consumed,complete;unsigned count,phase;int status;
 const struct j314s_multi_resource_owner*capture;
 u64 completed_ns;
} j314s_multi_front;
/* Actual immutable cold inventory, not a module-provided desired count.
 * Current provider actor owns this handoff; historic inventory task may differ. */
static int j314s_multi_count_locked(unsigned*count)
{
 typeof(j314s_provider_owner)*t=&j314s_provider_owner;
 *count=0;
 lockdep_assert_held(&j314s_provider_action_lock);
 lockdep_assert_held(&t->c->lock);lockdep_assert_held(&t->tb->lock);
 if(!j314s_provider_frozen_valid())return -EPERM;
 if(!j314s_chain_inventory){*count=1;return 0;}
#ifndef JCT_LINEAR_INVENTORY
 return -EOPNOTSUPP;
#else
 const struct apple_j314s_chain_list_report*l=&jc_inventory_owner.list;
 struct jc_kernel_edge*tail;
 if(!smp_load_acquire(&jc_inventory_owner.published)||jc_inventory_owner.status||
    !jc_inventory_owner.consumed||!l->terminal||(l->count!=1&&l->count!=3)||
    jc_inventory_owner.linear.count!=l->count||jc_owner.count!=l->count+1||
    jc_owner.failed||jc_owner.a!=t->a||jc_owner.first!=t->bootstrap||
    jc_owner.deadline!=t->deadline||l->original_deadline!=t->deadline||
    !l->completed_ns||l->completed_ns>=t->deadline||jc_inventory_owner.a!=t->a||
    jc_inventory_owner.generation!=t->generation||jc_inventory_owner.cable!=t->cable)
  return -EPERM;
 tail=jc_owner.edges[l->count];
 if(!tail||!tail->edge.survey_terminal||tail->consumed||tail->io.attempted||tail->captured_uid)return -EPERM;
 for(unsigned j=0;j<l->count;j++){
  const struct jc_kernel_edge*k=jc_owner.edges[j];
  if(!k||!k->edge.complete||!k->edge.child.ready||k->edge.ready.phase!=5||
     k->io.original_deadline!=t->deadline||
     l->edges[j].route!=k->edge.child.route||l->edges[j].uid!=k->edge.child.uid||
     l->edges[j].parent_route!=k->edge.parent.route||l->edges[j].parent_uid!=k->edge.parent.uid)
   return -ESTALE;
 }
 *count=l->count+1;return 0;
#endif
}
/* Action mutex remains held across all host calls. ACIO/TB locks bracket only
 * fresh tunnel proofs and cold TB writes; host lifecycle APIs run outside. */
static int j314s_multi_proof(void)
{
 typeof(j314s_provider_owner)*t=&j314s_provider_owner;int ret;
 lockdep_assert_held(&j314s_provider_action_lock);
 mutex_lock(&t->c->lock);mutex_lock(&t->tb->lock);
 ret=apple_cio_j314s_tunnel_proof_locked(t->a,t,t->deadline);
 mutex_unlock(&t->tb->lock);mutex_unlock(&t->c->lock);return ret;
}
static int j314s_raw_continue_multiple(unsigned expected)
{
 typeof(j314s_provider_owner)*t=&j314s_provider_owner;
 struct j314s_combined_result*r=t->bootstrap;int ret,post;
 if(j314s_raw_consumed||j314s_multi_front.consumed)return -EALREADY;
 j314s_raw_consumed=true;j314s_multi_front.consumed=true;
 j314s_multi_front.count=expected;j314s_multi_front.status=-EINPROGRESS;
 if(expected!=2&&expected!=4){ret=-EINVAL;goto done;}
 j314s_raw_path=kzalloc(sizeof(*j314s_raw_path),GFP_KERNEL);
 if(!j314s_raw_path){ret=-ENOMEM;goto done;}
 *j314s_raw_path=(struct jraw_pt_state){.read=j314s_raw_read,.write=j314s_raw_write,
  .valid=j314s_raw_valid,.now=j314s_raw_now,.sleep=j314s_raw_sleep,
  .proof=j314s_raw_proof,.audit=j314s_raw_audit,.commit=j314s_raw_commit,.ctx=t,
  .deadline=t->deadline,.phy={r->ready.rphy,r->ready.cphy},
  .pcie={r->ready.rpcie,r->ready.cpcie},.disabled={0,r->inventory.disabled_ports}};
 memcpy(j314s_raw_path->target_root,r->pins.root,sizeof(j314s_raw_path->target_root));
 mutex_lock(&t->c->lock);mutex_lock(&t->tb->lock);
 {unsigned actual=0;ret=j314s_multi_count_locked(&actual);if(!ret&&actual!=expected)ret=-ESTALE;}
 if(!ret)ret=j314s_provider_live_closed();
 if(!ret)ret=apple_apciec_j314s_begin_raw(t->host,3,t,t->deadline);
 if(!ret)ret=apple_apciec_retained_root_rc_prepare(t->host,3,t);
 if(!ret)ret=j314s_provider_live_closed();
 if(!ret)ret=jraw_pt_once(j314s_raw_path);
 if(!ret)ret=apple_j314s_chain_tunnels_cold(expected-1);
 if(!ret)ret=apple_j314s_tunnel_seal_locked();
 mutex_unlock(&t->tb->lock);mutex_unlock(&t->c->lock);
 if(ret)goto done;
 /* Each irreversible host stage is bracketed by fresh read-only tunnel proof.
  * No subsequent stage runs after either its action or its postproof failed. */
 ret=j314s_multi_proof();if(ret)goto done;
 ret=apple_apciec_j314s_scan_multiple(t->host,3,t,expected);
 post=j314s_multi_proof();if(!ret)ret=post;if(ret)goto done;
 ret=apple_apciec_retained_raw_final_audit(t->host,3,t);
 if(!ret)ret=apple_apciec_retained_records(t->host,3,t,&j314s_raw_records,&j314s_raw_record_count);
 if(ret||!j314s_raw_records||!j314s_raw_record_count){if(!ret)ret=-EPERM;goto done;}
 ret=j314s_multi_proof();if(ret)goto done;
 ret=apple_apciec_j314s_capture_multiple(t->host,3,t,expected,&j314s_multi_front.capture,&j314s_multi_front.phase);
 post=j314s_multi_proof();if(!ret)ret=post;if(ret)goto done;
 if(!j314s_multi_front.capture||j314s_multi_front.phase!=12){ret=-EPERM;goto done;}
 ret=j314s_multi_proof();if(ret)goto done;
 ret=apple_apciec_j314s_assign_multi(t->host,3,t,expected,&j314s_multi_front.phase);
 post=j314s_multi_proof();if(!ret)ret=post;if(ret)goto done;
 if(j314s_multi_front.phase!=14){ret=-EPERM;goto done;}
 ret=j314s_multi_proof();if(ret)goto done;
 ret=apple_apciec_j314s_native_prepare_multi(t->host,3,t,expected,&j314s_multi_front.phase);
 post=j314s_multi_proof();if(!ret)ret=post;if(ret)goto done;
 if(j314s_multi_front.phase!=39){ret=-EPERM;goto done;}
 /* Separate public API is essential: this proof occurs after collective seal,
  * before ANY pci_bus_add_device, outside the host lifecycle lock. */
 ret=j314s_multi_proof();if(ret)goto done;
 ret=apple_apciec_j314s_native_publish_multi(t->host,3,t,expected,&j314s_multi_front.phase);
 post=j314s_multi_proof();if(!ret)ret=post;if(ret)goto done;
 if(j314s_multi_front.phase!=40){ret=-EPERM;goto done;}
 j314s_multi_front.completed_ns=ktime_get_boottime_ns();
 if(j314s_multi_front.completed_ns>=t->deadline)ret=-ETIMEDOUT;
 done:
 j314s_multi_front.status=ret;j314s_multi_front.complete=!ret;
 j314s_raw_status=ret;j314s_raw_complete=!ret;
 pr_info("j314s-multi-front: status%d count%u hostphase%u records%u complete%u; exact cold multi pipeline\n",
  ret,expected,j314s_multi_front.phase,j314s_raw_record_count,j314s_multi_front.complete);
 return ret;
}
static int j314s_raw_continue(void)
{
 typeof(j314s_provider_owner)*t=&j314s_provider_owner;unsigned count;int ret;
 lockdep_assert_held(&j314s_provider_action_lock);
 if(j314s_multi_front.selected||j314s_raw_consumed)return -EALREADY;
 j314s_multi_front.selected=true;
 mutex_lock(&t->c->lock);mutex_lock(&t->tb->lock);
 ret=j314s_multi_count_locked(&count);
 mutex_unlock(&t->tb->lock);mutex_unlock(&t->c->lock);
 if(ret){j314s_multi_front.status=ret;j314s_raw_status=ret;return ret;}
 if(count==1)return j314s_raw_continue_single();
 return j314s_raw_continue_multiple(count);
}

#include <linux/apple-j314s-multi-report.h>
/* Historical multi completion only. No hardware, current actor requirement,
 * deadline renewal or fallback to the single-device native receipt. */
int apple_cio_j314s_multi_state(unsigned controller,u32*flags,int*status,
 struct apple_j314s_multi_report*report)
{
 typeof(j314s_provider_owner)*t=&j314s_provider_owner;int ret=0;
 if(!flags||!status||!report)return -EINVAL;
 *flags=0;*status=-EINPROGRESS;memset(report,0,sizeof(*report));if(controller)return -EINVAL;
 if(!mutex_trylock(&j314s_provider_action_lock))return -EAGAIN;
 if(t->failed||!t->complete||t->status||!t->host||!j314s_provider_identity_valid()||
    !j314s_multi_front.selected||!j314s_multi_front.consumed||!j314s_multi_front.complete||
    j314s_multi_front.status||j314s_multi_front.phase!=40||
    (j314s_multi_front.count!=2&&j314s_multi_front.count!=4)||
    !j314s_multi_front.completed_ns||j314s_multi_front.completed_ns>=t->deadline||
    !j314s_raw_complete||j314s_raw_status)
  *status=t->status?t->status:j314s_multi_front.status?j314s_multi_front.status:-EPERM;
 else {
  ret=apple_apciec_j314s_multi_state(t->host,flags,status,report);
  if(!ret&&!*status&&(report->count!=j314s_multi_front.count||report->phase!=40||
     report->original_deadline!=t->deadline||!report->completed_ns||
     report->completed_ns>j314s_multi_front.completed_ns)){
   *flags=0;*status=-ESTALE;memset(report,0,sizeof(*report));
  }
 }
 mutex_unlock(&j314s_provider_action_lock);return ret;
}
EXPORT_SYMBOL_GPL(apple_cio_j314s_multi_state);
