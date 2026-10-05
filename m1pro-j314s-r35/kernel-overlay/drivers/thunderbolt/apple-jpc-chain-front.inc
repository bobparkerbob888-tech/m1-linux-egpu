/* Exactly one selected peer's cold continuation; no provider or GPU action.
 * Caller must be the future cold runtime loader before original120s expiry. */
static DEFINE_MUTEX(jpc_chain_action_lock);
static bool jpc_chain_action_consumed[3];
int apple_cio_jpc_prepare_chain_once(unsigned controller);
int apple_cio_jpc_prepare_chain_once(unsigned controller)
{
 struct apple_cio*c;struct apple_nhi*a;int ret;
 if(controller<1||controller>2||controller!=jpc_boot_peer_controller())return -EINVAL;
 mutex_lock(&jpc_chain_action_lock);
 if(jpc_chain_action_consumed[controller]){ret=-EALREADY;goto out;}
 jpc_chain_action_consumed[controller]=true;
 c=READ_ONCE(j314s_owned_cio[controller]);if(!c){ret=-ENODEV;goto out;}
 mutex_lock(&c->lock);a=READ_ONCE(c->root_cable_nhi);
 if(!a||a->acio!=c||!a->tb){ret=-EPERM;goto unlock;}
 mutex_lock(&a->tb->lock);
 ret=jpc_capture_valid(a)?apple_jpc_child_bootstrap_captured(a):-EPERM;
 if(!ret)ret=jpc_apple_j314s_chain_inventory_once(a);
 mutex_unlock(&a->tb->lock);
 unlock:mutex_unlock(&c->lock);
 out:mutex_unlock(&jpc_chain_action_lock);return ret;
}
EXPORT_SYMBOL_GPL(apple_cio_jpc_prepare_chain_once);
int apple_cio_jpc_inventory_state(unsigned,u32*,int*);
int apple_cio_jpc_inventory_state(unsigned controller,u32*flags,int*status)
{
 struct apple_cio*c;struct apple_nhi*a;struct j314s_peer_capture_owner*o;
 if(!flags||!status||controller<1||controller>2||controller!=jpc_boot_peer_controller())return -EINVAL;
 *flags=0;*status=-EINPROGRESS;c=READ_ONCE(j314s_owned_cio[controller]);
 if(!c||!mutex_trylock(&c->lock))return -EAGAIN;
 a=READ_ONCE(c->root_cable_nhi);o=a?j314s_peer_slot(a):NULL;
 if(o&&o->consumed&&o->lease.complete&&!o->lease.failed&&!o->status&&
    o->anhi==a&&a->acio==c&&jpc_next_owner.anhi==a&&jpc_next_owner.consumed&&
    jpc_next_owner.controller==controller&&jpc_next_owner.result&&
    jpc_next_owner.result->completed&&!jpc_next_owner.result->status&&
    jpc_inventory_owner.published&&!jpc_inventory_owner.status&&
    jpc_inventory_owner.a==a&&jpc_inventory_owner.list.terminal&&
    jpc_inventory_owner.generation==READ_ONCE(c->external_cable_generation)&&
    jpc_inventory_owner.cable==READ_ONCE(c->current_cable_info)&&
    !READ_ONCE(c->root_stopping)&&!READ_ONCE(c->root_probe_status)&&
    READ_ONCE(c->root_dma_retained)&&READ_ONCE(c->root_cable_snapshot)==o->cable&&
    READ_ONCE(c->target_cable_info)==o->cable){*flags=511;*status=0;}
 mutex_unlock(&c->lock);return 0;
}

EXPORT_SYMBOL_GPL(apple_cio_jpc_inventory_state);
