/* SPDX-License-Identifier: GPL-2.0 */
/* Include after combined child bootstrap and supplier attachment helper.
 * Exactly one synchronous exported cold-boot continuation, no worker retry. */
#include <linux/apple-dart-j314s-sample.h>
extern int apple_apciec_j314s_begin_provider(struct device*,unsigned,const void*,u64);
extern int apple_apciec_j314s_populate_provider(struct device*,unsigned,const void*,u64,
 struct apple_dart_j314s_sample*);
static DEFINE_MUTEX(j314s_provider_action_lock);
static struct {
 bool consumed, published, failed, complete;
 struct apple_nhi *a;
 struct apple_cio *c;
 struct tb *tb;
 struct tb_switch *root;
 struct j314s_combined_result *bootstrap;
 struct task_struct *task;
 struct device_node *host_np;
 struct device *host;
 struct of_changeset changeset;
 struct property *status_property;
 u32 cable;
 u64 generation, deadline, completed_ns;
 unsigned down,up,route,rootcap,childcap,phase;
 int status;
 struct apple_dart_j314s_sample sample;
} j314s_provider_owner;

/* Immutable proof published after locked live checks. No ACIO/TB mutex
 * acquisition under host lifecycle or child device/probe locks. */
static bool j314s_provider_identity_valid(void)
{
 typeof(j314s_provider_owner)*t=&j314s_provider_owner;
 struct apple_nhi *a=t->a;struct apple_cio*c=t->c;
 struct j314s_combined_result*r=t->bootstrap;
 if(!smp_load_acquire(&t->published)||!a||!c||!r||!t->deadline||
    !of_machine_is_compatible("apple,j314s")||!j314s_boot_valid()||
    !j314s_chosen_valid()||!j314s_inventory_options()||!j314s_profile_valid()||
    !READ_ONCE(root_router_only)||READ_ONCE(j314s_owned_cio[0])!=c||
    !READ_ONCE(j314s_arm_committed[0])||atomic_read(&j314s_power_attempt[0])!=1||
    j314s_node_index(c->np,0)!=0||j314s_node_index(a->np,1)!=0||
    a->acio!=c||a->tb!=t->tb||t->tb->root_switch!=t->root||
    READ_ONCE(c->root_cable_nhi)!=a||!READ_ONCE(c->root_dma_retained)||
    READ_ONCE(c->root_stopping)||READ_ONCE(c->root_probe_status)||
    !smp_load_acquire(&c->root_cable_snapshot_valid)||
    READ_ONCE(c->root_cable_snapshot)!=t->cable||
    READ_ONCE(c->target_cable_info)!=t->cable||
    READ_ONCE(c->current_cable_info)!=t->cable||
    READ_ONCE(c->external_cable_generation)!=t->generation||
    !a->nhi.ops||!a->nhi.ops->root_router_only||
    j314s_child_owner.anhi!=a||!j314s_child_owner.consumed||
    j314s_child_owner.cable!=t->cable||!j314s_child_owner.result.child.stable||
    j314s_next_owner.anhi!=a||!j314s_next_owner.consumed||
    j314s_next_owner.result!=r||!j314s_next_owner.io.attempted||
    j314s_next_owner.io.deadline!=t->deadline||!r->completed||r->status||
    r->phase!=4||r->ready.phase!=5||!j314s_bootstrap_pins_valid(&r->pins)||
    r->pins.down!=t->down||r->inventory.pci_up!=t->up||
    r->pins.route!=t->route||r->pins.lane!=r->pins.route||r->ready.rpcie!=t->rootcap||
    r->ready.cpcie!=t->childcap||r->ready.pe_expected||
    !t->root||tb_route(t->root)||t->root->config.vendor_id!=0x05ac||
    t->root->config.device_id!=0x2001||t->root->config.max_port_number!=7||
    t->root->config.upstream_port_number!=7||!t->root->config.enabled)
  return false;
 return true;
}

static bool j314s_provider_frozen_valid(void)
{
 return !READ_ONCE(j314s_provider_owner.failed) &&
  READ_ONCE(j314s_provider_owner.task)==current &&
  ktime_get_boottime_ns()<j314s_provider_owner.deadline &&
  j314s_provider_identity_valid();
}

/* Actual current root and child headers/UID plus both PCIe enable bits.
 * No write, no DROM retry, no reconfiguration. */
static int j314s_provider_live_state(unsigned pe)
{
 typeof(j314s_provider_owner)*t=&j314s_provider_owner;
 struct j314s_combined_result*r=t->bootstrap;u32 h[5],adapter[8],uid[2],v;int ret;
 lockdep_assert_held(&t->c->lock);lockdep_assert_held(&t->tb->lock);
 if(pe>3||!j314s_provider_frozen_valid())return -EPERM;
 ret=tb_cfg_read(t->tb->ctl,h,0,0,TB_CFG_SWITCH,0,5);if(ret)return ret;
 if(memcmp(h,r->pins.root,sizeof(h)))return -ESTALE;
 ret=tb_cfg_read(t->tb->ctl,h,t->route,0,TB_CFG_SWITCH,0,5);if(ret)return ret;
 if(memcmp(h,r->pins.child_after,sizeof(h)))return -ESTALE;
 ret=tb_cfg_read(t->tb->ctl,uid,t->route,0,TB_CFG_SWITCH,7,2);if(ret)return ret;
 if(uid[0]!=(u32)(r->pins.uid>>32)||uid[1]!=(u32)r->pins.uid)return -ESTALE;
 ret=tb_cfg_read(t->tb->ctl,adapter,0,t->down,TB_CFG_PORT,0,8);if(ret)return ret;
 if(!j314s_adapter_identity_equal(adapter,r->inventory.selected[1].header)||
    (adapter[2]&0xffffff)!=0x100101||((adapter[3]>>20)&63)!=t->down)return -ESTALE;
 ret=tb_cfg_read(t->tb->ctl,adapter,t->route,t->up,TB_CFG_PORT,0,8);if(ret)return ret;
 if(!j314s_adapter_identity_equal(adapter,r->inventory.selected[3].header)||
    (adapter[2]&0xffffff)!=0x100102||((adapter[3]>>20)&63)!=t->up)return -ESTALE;
 ret=tb_cfg_read(t->tb->ctl,&v,0,t->down,TB_CFG_PORT,t->rootcap,1);if(ret)return ret;
 if(((v>>8)&255)!=4||(v>>31)!=(pe&1))return -EPERM;
 ret=tb_cfg_read(t->tb->ctl,&v,t->route,t->up,TB_CFG_PORT,t->childcap,1);if(ret)return ret;
 if(((v>>8)&255)!=4||(v>>31)!=((pe>>1)&1))return -EPERM;
 return j314s_provider_frozen_valid()?0:-EPERM;
}

static int j314s_provider_live_closed(void){return j314s_provider_live_state(0);}
static int j314s_raw_continue(void);
int apple_cio_j314s_provider_owner_validate(void *owner,const void *ticket,
 unsigned port,u64 deadline,bool owner_locks_held);
int apple_cio_j314s_provider_owner_validate(void *owner,const void *ticket,
 unsigned port,u64 deadline,bool owner_locks_held)
{
 typeof(j314s_provider_owner)*t=&j314s_provider_owner;
 if(ticket!=t||owner!=t->a||port!=t->down||deadline!=t->deadline||
    !j314s_provider_frozen_valid()||!t->host||t->a->enum_host!=t->host||
    !t->a->enum_bound||t->a->enum_stopping||t->a->enum_port!=port)
  return -EPERM;
 if(owner_locks_held) {
  if(t->phase!=2)return -EPERM;
  return j314s_provider_live_closed();
 }
 /* Only the same serialized action thread, during split provider creation.
  * No TB read/lock here; pre/post live checks bracket the whole operation. */
 return t->phase==3?0:-EPERM;
}
EXPORT_SYMBOL_GPL(apple_cio_j314s_provider_owner_validate);

static int j314s_provider_map_host(void)
{
 typeof(j314s_provider_owner)*t=&j314s_provider_owner;
 struct platform_device*h;struct property*p;int ret;
 lockdep_assert_not_held(&t->c->lock);lockdep_assert_not_held(&t->tb->lock);
 if(!j314s_provider_frozen_valid())return -EPERM;
 p=kzalloc(sizeof(*p),GFP_KERNEL);if(!p)return -ENOMEM;
 t->status_property=p;p->name=kstrdup("status",GFP_KERNEL);
 p->value=kstrdup("okay",GFP_KERNEL);p->length=5;
 if(!p->name||!p->value)return -ENOMEM;
 of_changeset_init(&t->changeset);
 ret=of_changeset_update_property(&t->changeset,t->host_np,p);if(ret)return ret;
 ret=of_changeset_apply(&t->changeset);if(ret)return ret;
 /* Existing OF notifier is the ONLY creator; never attach/reprobe fallback. */
 h=of_find_device_by_node(t->host_np);if(!h)return -ENODEV;
 t->host=&h->dev;
 device_lock(t->host);
 ret=t->host->driver&&!strcmp(t->host->driver->name,"apple-apciec-research-disabled")&&
  dev_get_drvdata(t->host)?0:-ENODEV;
 device_unlock(t->host);
 return ret?ret:j314s_provider_frozen_valid()?0:-EPERM;
}

int apple_cio_j314s_prepare_provider_once(unsigned controller);
int apple_cio_j314s_prepare_provider_once(unsigned controller)
{
 typeof(j314s_provider_owner)*t=&j314s_provider_owner;
 struct j314s_combined_result*r;struct apple_cio*c;struct apple_nhi*a;
 unsigned flags=0;int status=-EINPROGRESS,ret;
 if(controller)return -EINVAL;
 mutex_lock(&j314s_provider_action_lock);
 if(t->consumed){ret=-EALREADY;goto end;}
 t->consumed=true;t->status=-EINPROGRESS;t->task=current;
 ret=apple_cio_j314s_inventory_state(0,&flags,&status);
 if(ret||flags!=0x1ff||status){ret=ret?ret:-EPERM;goto failed;}
 c=READ_ONCE(j314s_owned_cio[0]);if(!c){ret=-ENODEV;goto failed;}
 mutex_lock(&c->lock);a=READ_ONCE(c->root_cable_nhi);
 if(!a||a->acio!=c||!a->tb){ret=-EPERM;goto unlock_c;}
 mutex_lock(&a->tb->lock);r=j314s_next_owner.result;
 if(!j314s_child_capture_proven(c)||!j314s_child_bootstrap_proven(c)||!r||
    !j314s_disabled_endpoint(0)||a->enum_host||a->enum_bound||a->enum_pd[0]||a->enum_pd[1]||
    !r->root_pcie||r->root_pcie!=r->ready.rpcie||!r->ready.cpcie||
    r->pins.down!=3||r->pins.lane!=r->pins.route||!r->inventory.pci_up||r->inventory.pci_up>r->pins.max_port||
    r->ready.up!=r->inventory.pci_up||!j314s_next_owner.io.deadline) {
  ret=-EPERM;goto unlock_both;
 }
 t->a=a;t->c=c;t->tb=a->tb;t->root=a->tb->root_switch;t->bootstrap=r;
 t->cable=READ_ONCE(c->root_cable_snapshot);
 t->generation=READ_ONCE(c->external_cable_generation);
 t->deadline=j314s_next_owner.io.deadline; /* Never extend original bound. */
 t->down=r->pins.down;t->up=r->inventory.pci_up;t->route=r->pins.route;
 t->rootcap=r->ready.rpcie;t->childcap=r->ready.cpcie;
 t->host_np=of_find_node_by_path(j314s_paths[0][3]);
 if(!t->host_np){ret=-ENODEV;goto unlock_both;}
 smp_store_release(&t->published,true);
 ret=j314s_provider_live_closed();
unlock_both:
 mutex_unlock(&a->tb->lock);
unlock_c:
 mutex_unlock(&c->lock);
 if(ret)goto failed;
 t->phase=1;ret=j314s_provider_map_host();if(ret)goto failed;
 mutex_lock(&c->lock);mutex_lock(&a->tb->lock);
 ret=j314s_provider_live_closed();
 if(!ret)ret=j314s_supplier_attach(a);
 t->phase=2;
 if(!ret)ret=apple_apciec_j314s_begin_provider(t->host,t->down,t,t->deadline);
 if(!ret)ret=j314s_provider_live_closed();
 mutex_unlock(&a->tb->lock);mutex_unlock(&c->lock);
 if(ret)goto failed;
 t->phase=3;
 ret=apple_apciec_j314s_populate_provider(t->host,t->down,t,t->deadline,&t->sample);
 mutex_lock(&c->lock);mutex_lock(&a->tb->lock);
 if(!ret)ret=j314s_provider_live_closed();
 mutex_unlock(&a->tb->lock);mutex_unlock(&c->lock);
 if(ret)goto failed;
 t->completed_ns=ktime_get_boottime_ns();
 if(t->completed_ns>=t->deadline){ret=-ETIMEDOUT;goto failed;}
 t->phase=4;t->complete=true;t->status=0;
 pr_info("j314s-provider: blocked provider complete VA%u PA%u SID%u page%u; no tunnel/native permit\n",
  t->sample.ias,t->sample.oas,t->sample.sid_count,t->sample.page_shift);
 ret=j314s_raw_continue();
 if(ret)goto failed;
 goto end;
failed:
 WRITE_ONCE(t->failed,true);t->status=ret;
 pr_err("j314s-provider: one-shot failed%d phase%u; retaining owners until reboot\n",ret,t->phase);
end:
 mutex_unlock(&j314s_provider_action_lock);return ret;
}
EXPORT_SYMBOL_GPL(apple_cio_j314s_prepare_provider_once);

/* Read-only historical completion evidence. No MMIO, locks on devices/ACIO/TB,
 * retries, mutation permits or original-deadline extension. */
static bool j314s_provider_sample_valid(const struct apple_dart_j314s_sample *s)
{
 unsigned i;
 if(s->page_shift!=14||s->sid_count!=64||s->ias<32||s->ias>s->oas||
    (s->oas!=36&&s->oas!=42)||s->protect==~0U||(s->protect&1U))return false;
 for(i=0;i<4;i++)if(s->params[i]==~0U)return false;
 return ((s->params[0]>>24)&15)==14&&((s->params[2]>>16)&63)==s->ias&&
  ((s->params[2]>>24)&63)==s->oas&&(s->params[3]&511)==64;
}
int apple_cio_j314s_provider_state(unsigned controller,u32 *flags,int *status,
 struct apple_dart_j314s_sample *sample);
int apple_cio_j314s_provider_state(unsigned controller,u32 *flags,int *status,
 struct apple_dart_j314s_sample *sample)
{
 typeof(j314s_provider_owner)*t=&j314s_provider_owner;u32 f=0;
 struct device_driver *driver;
 if(!flags||!status||!sample)return -EINVAL;
 *flags=0;*status=-EINPROGRESS;memset(sample,0,sizeof(*sample));
 if(controller||!of_machine_is_compatible("apple,j314s"))return -EINVAL;
 if(!mutex_trylock(&j314s_provider_action_lock))return -EAGAIN;
 if(!t->consumed)goto out;
 f|=BIT(0);*status=t->status;
 if(!j314s_provider_identity_valid())goto invalid;
 f|=BIT(1);
 driver=t->host?READ_ONCE(t->host->driver):NULL;
 if(!driver||strcmp(driver->name,"apple-apciec-research-disabled")||
    !dev_get_drvdata(t->host))goto invalid;
 f|=BIT(2);
 if(t->a->enum_host!=t->host||!t->a->enum_bound||t->a->enum_stopping||
    t->a->enum_port!=t->down||!t->a->enum_pd[0]||!t->a->enum_pd[1])goto invalid;
 f|=BIT(3);
 if(!t->a->enum_retained_prepare||!t->a->enum_retained_pd[0]||
    !t->a->enum_retained_pd[1])goto invalid;
 f|=BIT(4);
 if(t->failed||!t->complete||t->phase!=4||t->status||!t->completed_ns||
    t->completed_ns>=t->deadline)goto invalid;
 f|=BIT(5);
 if(!j314s_provider_sample_valid(&t->sample))goto invalid;
 f|=BIT(6);*sample=t->sample;*status=0;goto out;
invalid:
 /* Preserve the concrete action failure; impossible success shapes fail closed. */
 if(!*status)*status=-ESTALE;
out:
 *flags=f;mutex_unlock(&j314s_provider_action_lock);return 0;
}
EXPORT_SYMBOL_GPL(apple_cio_j314s_provider_state);

#include "apple-j314s-raw-front.inc"
