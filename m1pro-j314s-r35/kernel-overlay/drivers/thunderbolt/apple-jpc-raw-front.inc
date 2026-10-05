/* Cold peer identity only: no BAR sizing, publication or GPU initialization. */
extern int apple_apciec_jpc_begin_raw(struct device*,unsigned,const void*,u64);
extern int apple_apciec_jpc_scan_identity(struct device*,unsigned,const void*,unsigned);
static int jpc_apple_j314s_chain_tunnels_cold(unsigned);
static int jpc_apple_j314s_tunnel_seal_locked(void);
int jpc_apple_cio_j314s_tunnel_proof_locked(void*,const void*,u64);
static const struct ep_snapshot *jpc_raw_snapshot; /* permanently NULL */

static struct jraw_pt_state *jpc_raw_paths[3];
#define jpc_raw_path jpc_raw_paths[jpc_boot_peer_controller()]
static bool jpc_raw_consumeds[3],jpc_raw_completes[3];
#define jpc_raw_consumed jpc_raw_consumeds[jpc_boot_peer_controller()]
#define jpc_raw_complete jpc_raw_completes[jpc_boot_peer_controller()]
static const struct ep_identity *jpc_raw_recordss[3];
#define jpc_raw_records jpc_raw_recordss[jpc_boot_peer_controller()]
static unsigned jpc_raw_record_counts[3];
#define jpc_raw_record_count jpc_raw_record_counts[jpc_boot_peer_controller()]
static int jpc_raw_statuss[3]={-EINPROGRESS,-EINPROGRESS,-EINPROGRESS};
#define jpc_raw_status jpc_raw_statuss[jpc_boot_peer_controller()]
static bool jpc_raw_valid(void *arg)
{
 typeof(jpc_provider_owner)*t=&jpc_provider_owner;
 return arg==t&&jpc_raw_consumed&&!jpc_raw_complete&&jpc_raw_path&&
  t->complete&&t->phase==4&&!t->status&&jpc_provider_frozen_valid();
}
int apple_cio_jpc_raw_owner_validate(void *,const void *,unsigned,u64);
int apple_cio_jpc_raw_owner_validate(void *owner,const void *ticket,unsigned port,u64 deadline)
{
 typeof(jpc_provider_owner)*t=&jpc_provider_owner;
 if(owner!=t->a||ticket!=t||port!=3||port!=t->down||deadline!=t->deadline||
    !jpc_raw_valid(t)||t->up!=9||t->route!=1||t->bootstrap->pins.lane!=1)
  return -EPERM;
 return 0;
}
EXPORT_SYMBOL_GPL(apple_cio_jpc_raw_owner_validate);
static u64 jpc_raw_now(void *arg){return ktime_get_boottime_ns();}
static void jpc_raw_sleep(void *arg){usleep_range(50,100);}
static int jpc_raw_read(void *arg,unsigned r,unsigned p,unsigned sp,unsigned off,unsigned n,u32 *v)
{
 typeof(jpc_provider_owner)*t=arg;
 if(!jpc_raw_valid(arg)||r>1||!n||n>8||off>8192-n||sp>JRAW_PT_HOPS||
    (sp==JRAW_PT_SW?p!=0:(!p||p>63)))return -EPERM;
 return tb_cfg_read(t->tb->ctl,v,r,p,sp==JRAW_PT_SW?TB_CFG_SWITCH:sp==JRAW_PT_PORT?TB_CFG_PORT:TB_CFG_HOPS,off,n);
}
static int jpc_raw_write(void *arg,unsigned r,unsigned p,unsigned sp,unsigned off,unsigned n,const u32 *v)
{
 typeof(jpc_provider_owner)*t=arg;
 if(!jpc_raw_valid(arg)||!jraw_pt_write_allowed(jpc_raw_path,r,p,sp,off,n,v))return -EPERM;
 return tb_cfg_write(t->tb->ctl,v,r,p,sp==JRAW_PT_SW?TB_CFG_SWITCH:sp==JRAW_PT_PORT?TB_CFG_PORT:TB_CFG_HOPS,off,n);
}
static int jpc_raw_proof(void *arg,unsigned pe)
{
 if(!jpc_raw_valid(arg)||pe!=jpc_raw_path->pe)return -EPERM;
 return jpc_provider_live_state(pe);
}
static int jpc_raw_audit(void *arg)
{
 typeof(jpc_provider_owner)*t=arg;
 if(!jpc_raw_valid(arg))return -EPERM;
 return apple_apciec_retained_prepared_audit(t->host,3,t);
}
static int jpc_raw_commit(void *arg)
{
 typeof(jpc_provider_owner)*t=arg;int ret;
 if(!jpc_raw_valid(arg)||jpc_raw_path->phase!=4||
    jpc_raw_path->programmed!=4||jpc_raw_path->pe!=3)return -EPERM;
 ret=jpc_raw_proof(arg,3);
 if(!ret)ret=jraw_pt_verify(jpc_raw_path);
 return ret?ret:apple_apciec_retained_commit(t->host,3,t);
}

static int jpc_raw_continue(void)
{
 typeof(jpc_provider_owner)*t=&jpc_provider_owner;
 struct j314s_combined_result*r=t->bootstrap;unsigned edges;int ret,post;
 lockdep_assert_held(&jpc_provider_action_lock);
 if(jpc_raw_consumed)return -EALREADY;
 jpc_raw_consumed=true;
 edges=jpc_inventory_owner.list.count;
 if(edges>4||!jpc_inventory_owner.published||jpc_inventory_owner.status||
    !jpc_inventory_owner.list.terminal||jpc_inventory_owner.a!=t->a||
    jpc_inventory_owner.generation!=t->generation||jpc_inventory_owner.cable!=t->cable||
    jpc_inventory_owner.list.original_deadline!=t->deadline){ret=-EPERM;goto done;}
 jpc_raw_path=kzalloc(sizeof(*jpc_raw_path),GFP_KERNEL);
 if(!jpc_raw_path){ret=-ENOMEM;goto done;}
 *jpc_raw_path=(struct jraw_pt_state){.read=jpc_raw_read,.write=jpc_raw_write,
  .valid=jpc_raw_valid,.now=jpc_raw_now,.sleep=jpc_raw_sleep,
  .proof=jpc_raw_proof,.audit=jpc_raw_audit,.commit=jpc_raw_commit,.ctx=t,
  .deadline=t->deadline,.phy={r->ready.rphy,r->ready.cphy},
  .pcie={r->ready.rpcie,r->ready.cpcie},.disabled={0,r->inventory.disabled_ports}};
 memcpy(jpc_raw_path->target_root,r->pins.root,sizeof(jpc_raw_path->target_root));
 mutex_lock(&t->c->lock);mutex_lock(&t->tb->lock);
 ret=jpc_provider_live_closed();
 if(!ret)ret=apple_apciec_jpc_begin_raw(t->host,t->down,t,t->deadline);
 if(!ret)ret=apple_apciec_retained_root_rc_prepare(t->host,t->down,t);
 if(!ret)ret=jpc_provider_live_closed();
 if(!ret)ret=jraw_pt_once(jpc_raw_path);
 if(!ret)ret=jpc_apple_j314s_chain_tunnels_cold(edges);
 if(!ret)ret=jpc_apple_j314s_tunnel_seal_locked();
 mutex_unlock(&t->tb->lock);mutex_unlock(&t->c->lock);
 if(ret)goto done;
 ret=apple_apciec_jpc_scan_identity(t->host,t->down,t,edges+1);
 if(!ret)ret=apple_apciec_retained_raw_final_audit(t->host,t->down,t);
 if(!ret)ret=apple_apciec_retained_records(t->host,t->down,t,&jpc_raw_records,&jpc_raw_record_count);
 mutex_lock(&t->c->lock);mutex_lock(&t->tb->lock);
 post=jpc_apple_cio_j314s_tunnel_proof_locked(t->a,t,t->deadline);
 mutex_unlock(&t->tb->lock);mutex_unlock(&t->c->lock);
 if(!ret)ret=post;
 if(!ret&&(!jpc_raw_records||!jpc_raw_record_count||jpc_raw_record_count>64))ret=-EPERM;
 if(!ret&&jpc_native_requests[t->controller].consumed)ret=jpc_native_continue();
 done:jpc_raw_status=ret;jpc_raw_complete=!ret;
 pr_info("jpc-raw: controller%u status%d records%u; cold continuation complete\n",t->controller,ret,jpc_raw_record_count);
 return ret;
}
/* Historical evidence only. Getter never extends deadline or authorizes I/O. */
int apple_cio_jpc_raw_state(unsigned,u32 *,int *,unsigned *);
int apple_cio_jpc_raw_state(unsigned controller,u32 *flags,int *status,unsigned *count)
{
 if(controller<1||controller>2||controller!=jpc_boot_peer_controller()||!flags||!status||!count)return -EINVAL;
 *flags=0;*status=-EINPROGRESS;*count=0;
 if(!mutex_trylock(&jpc_provider_action_lock))return -EAGAIN;
 if(jpc_raw_consumed)*flags|=BIT(0);
 if(jpc_raw_path){
  *flags|=BIT(1);
  if(jpc_raw_path->programmed==4)*flags|=BIT(2);
  if(jpc_raw_path->pe==3)*flags|=BIT(3);
 }
 if(jpc_raw_complete&&!jpc_raw_status&&!jpc_provider_owner.failed&&
    jpc_provider_identity_valid()&&jpc_raw_records&&jpc_raw_record_count){
  *flags|=BIT(4);*count=jpc_raw_record_count;*status=0;
 }else *status=jpc_provider_owner.failed?jpc_provider_owner.status:
  jpc_raw_status?jpc_raw_status:-EPERM;
 mutex_unlock(&jpc_provider_action_lock);return 0;
}
EXPORT_SYMBOL_GPL(apple_cio_jpc_raw_state);

