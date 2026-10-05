/* Called after first endpoint preparation, before any NVIDIA driver probe.
 * Two adjacent PCIe tunnels extend the same physical branch. Existing root
 * tunnel, IRQ owner and SID1 mapping remain retained and audited throughout.
 */
extern int apple_apciec_retained_transit_native_prepare(struct device *,unsigned,const void *,unsigned *);
extern int apple_apciec_retained_transit_native_audit(struct device *,unsigned,const void *);
extern int apple_apciec_retained_identify_pair(struct device *,unsigned,const void *,u64,unsigned *);
extern int apple_apciec_retained_expand_chain(struct device *,unsigned,const void *,u64,unsigned *);
static bool route_chain_tunnels;
module_param(route_chain_tunnels,bool,0444);
struct chain_tunnel_context {
 struct external_ticket *ticket;
 struct chain_kernel_context *prepared;
 struct pt_state state;
 unsigned child;
};
static struct chain_tunnel_context *chain_tunnel_owner[2][2];
static atomic_t chain_tunnel_attempted[2] = { ATOMIC_INIT(0), ATOMIC_INIT(0) };
static bool chain_tunnel_valid(void *p)
{
 struct chain_tunnel_context *c=p;struct external_ticket *t=c->ticket;
 return route_chain_tunnels&&route_chain_prepare&&c->prepared&&c->child>=1&&c->child<bob_chain_count(t->controller)&&
  c->prepared==READ_ONCE(chain_prepared[t->controller])&&c->prepared->anhi==t->anhi&&
  c->prepared->io.node[c->child-1].tmu_ready&&c->prepared->io.node[c->child].tmu_ready&&
  (t->controller ? (t->endpoint_phase==8 ||
    (t->endpoint_phase>=10 && t->endpoint_phase<=(t->endpoint_pair?30:20) && c->state.phase==5 &&
     c->state.programmed==4 && c->state.pe==3)) : t->endpoint_phase==20)&&t->tunnel&&t->tunnel->phase==6&&t->tunnel->pe==3&&
  external_context(t)&&ktime_get_boottime_ns()<t->deadline;
}
static int chain_tunnel_read(void *p,unsigned r,unsigned port,unsigned space,unsigned off,unsigned n,u32 *v)
{
 struct chain_tunnel_context *c=p;unsigned route;
 if(r>1||!n||n>8||off>8192-n||space>PT_HOPS||
    (space==PT_SW?port!=0:(!port||port>23))||!chain_tunnel_valid(p))return -EPERM;
 route=c->prepared->io.node[c->child-1+r].route;
 return tb_cfg_read(c->ticket->tb->ctl,v,route,port,space==PT_SW?TB_CFG_SWITCH:space==PT_PORT?TB_CFG_PORT:TB_CFG_HOPS,off,n);
}
static int chain_tunnel_write(void *p,unsigned r,unsigned port,unsigned space,unsigned off,unsigned n,const u32 *v)
{
 struct chain_tunnel_context *c=p;unsigned route;
 if((c->ticket->controller && c->ticket->endpoint_phase!=8)||
    !chain_tunnel_valid(p)||r>1||!pt_write_allowed(&c->state,r,port,space,off,n,v))return -EPERM;
 route=c->prepared->io.node[c->child-1+r].route;
 return tb_cfg_write(c->ticket->tb->ctl,v,route,port,space==PT_SW?TB_CFG_SWITCH:space==PT_PORT?TB_CFG_PORT:TB_CFG_HOPS,off,n);
}
static int chain_tunnel_audit(void *p)
{
 struct chain_tunnel_context *c=p;struct external_ticket *t=c->ticket;int ret;
 if(!chain_tunnel_valid(p))return -EPERM;
 ret=pt_verify(t->tunnel);if(ret)return ret;
 ret=external_proof_locked_state(t,3);if(ret)return ret;
 return t->controller?apple_apciec_retained_transit_audit(t->host,3,t):apple_apciec_retained_native_audit(t->host,3,t);
}
static int chain_tunnel_identity_proof(void *p,unsigned pe)
{
 struct chain_tunnel_context *c=p;unsigned r;u32 h[5],uid[2],v;int ret;
 if(!chain_tunnel_valid(p)||pe>3)return -EPERM;
 for(r=0;r<2;r++){
  const struct chain_node *n=&c->prepared->io.node[c->child-1+r];
  ret=chain_tunnel_read(p,r,0,PT_SW,0,5,h);if(ret)return ret;
  if(memcmp(h,c->state.chain_header[r],sizeof(h)))return -ESTALE;
  ret=chain_tunnel_read(p,r,0,PT_SW,7,2,uid);if(ret)return ret;
  if(uid[0]!=n->uid_hi||uid[1]!=n->uid_lo)return -ESTALE;
  ret=chain_tunnel_read(p,r,r?9:10,PT_PORT,c->state.pcie[r],1,&v);if(ret)return ret;
  if((v>>31)!=((pe>>r)&1))return -ESTALE;
  ret=chain_tunnel_read(p,r,0,PT_SW,6,1,&v);if(ret)return ret;
  if((v&(3U<<24))!=(3U<<24))return -ESTALE;
 }
 return 0;
}
static int chain_tunnel_proof(void *p,unsigned pe)
{
 int ret=chain_tunnel_identity_proof(p,pe);
 return ret?ret:chain_tunnel_audit(p);
}
static int chain_tunnel_commit(void *p)
{
 struct chain_tunnel_context *c=p;
 if(c->state.programmed!=4||c->state.phase!=4||c->state.pe!=3)return -EPERM;
 return chain_tunnel_proof(p,3);
}
static int apple_retained_chain_tunnels(struct external_ticket *t)
{
 struct chain_kernel_context *prepared;unsigned child,r;int ret=0;
 if(!route_chain_tunnels)return 0;
 if(bob_attempt_once(chain_tunnel_attempted, t->anhi->np))return -EALREADY;
 prepared=READ_ONCE(chain_prepared[t->controller]);
 if(!prepared||prepared->anhi!=t->anhi||t->endpoint_phase!=(t->controller?8:20))return -EPERM;
 mutex_lock(&t->acio->lock);mutex_lock(&t->tb->lock);
 for(child=1;child<bob_chain_count(t->controller);child++){
  struct chain_tunnel_context *c=kzalloc(sizeof(*c),GFP_KERNEL);
  struct ready_io *g=&prepared->links[child-1].ready;
  if(!c){ret=-ENOMEM;break;}
  chain_tunnel_owner[t->controller][child-1]=c; /* Retain on every result. */
  c->ticket=t;c->prepared=prepared;c->child=child;
  c->state=(struct pt_state){.read=chain_tunnel_read,.write=chain_tunnel_write,
   .valid=chain_tunnel_valid,.now=external_clock,.sleep=apple_pt_sleep,
   .proof=chain_tunnel_proof,.audit=chain_tunnel_audit,.commit=chain_tunnel_commit,
   .ctx=c,.deadline=t->deadline,.phy={g->rphy,g->cphy},.pcie={g->rpcie,g->cpcie},
   .disabled={prepared->io.node[child-1].disabled,prepared->io.node[child].disabled},
   .chain_child_depth=child+1};
  for(r=0;r<2;r++)chain_expected(&prepared->io.node[child-1+r],c->state.chain_header[r]);
  ret=pt_once(&c->state);
  dev_info(t->anhi->dev,"chain-tunnel: route%x status%d phase%u hops%u PE%u credits%u/%u; owners retained\n",
   prepared->io.node[child].route,ret,c->state.phase,c->state.programmed,c->state.pe,c->state.credits[0],c->state.credits[1]);
  if(ret)break;
 }
 mutex_unlock(&t->tb->lock);mutex_unlock(&t->acio->lock);
 if(!ret)ret=t->controller?
  (t->endpoint_pair ? apple_apciec_retained_identify_pair(t->host,3,t,t->deadline,&t->endpoint_phase) :
   apple_apciec_retained_identify_transit_target(t->host,3,t,t->deadline,&t->endpoint_phase)):
  apple_apciec_retained_expand_chain(t->host,3,t,t->deadline,&t->endpoint_phase);
 return ret;
}
