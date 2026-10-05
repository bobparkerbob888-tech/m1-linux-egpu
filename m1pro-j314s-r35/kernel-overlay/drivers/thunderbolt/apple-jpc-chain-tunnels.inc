/* Dormant candidate. Include AFTER apple-j314s-raw-front.inc. No callsite,
 * parameter, worker, export or automatic expansion is introduced here.
 * Intended call is cold phase8, immediately after root tunnel commit and
 * BEFORE any PCI scan/BAR/native/GPU operation. ACIO and TB locks held. */
#include "jpc5-tunnel-core.h"
extern int apple_apciec_jpc_chain_closed_audit(struct device*,unsigned,const void*,u64);
struct jpc_jct_owner {
 struct jpc_kernel_edge *captured;
 struct jpc5_t_pt_state path;
 unsigned index;int status;bool complete;
};
static struct {
 typeof(jpc_provider_owner)*ticket;struct task_struct*task;
 u64 deadline;unsigned count;bool consumed,failed;
 struct jpc_jct_owner*edges[4];
} jpc_jct_contexts[3];
#define jpc_jct_context jpc_jct_contexts[jpc_boot_peer_controller()]
static bool jpc_jct_inventory_matches(unsigned count)
{
#ifdef JCT_LINEAR_INVENTORY
 struct jpc_kernel_edge*terminal;
 if(!jpc_inventory_owner.published||jpc_inventory_owner.status||
    !jpc_inventory_owner.list.terminal||jpc_inventory_owner.list.count!=count||
    jpc_chain_owner.count!=count+1||count>4)return false;
 terminal=jpc_chain_owner.edges[count];
 return terminal&&terminal->edge.survey_terminal&&!terminal->consumed&&
  !terminal->io.attempted&&!terminal->captured_uid;
#else
 /* Proven R15 one-edge receipt; additional edges require linear owner kit. */
 return count==1&&jpc_chain_owner.count==1;
#endif
}
/* Inventory is a completed cold-worker receipt; provider continuation owns
 * the current actor. Bind their immutable bootstrap/deadline, not task equality. */
static bool jpc_jct_valid(void*arg)
{
 struct jpc_jct_owner*c=arg;typeof(jpc_provider_owner)*t=&jpc_provider_owner;
 return c&&jpc_jct_context.consumed&&!jpc_jct_context.failed&&jpc_jct_context.ticket==t&&
  jpc_jct_context.task==current&&jpc_jct_context.deadline==t->deadline&&
  c->path.deadline==t->deadline&&ktime_get_boottime_ns()<t->deadline&&
  c->index<jpc_jct_context.count&&jpc_jct_context.edges[c->index]==c&&
  c->captured==jpc_chain_owner.edges[c->index]&&jpc_chain_owner.a==t->a&&jpc_chain_owner.first==t->bootstrap&&
  jpc_chain_owner.deadline==t->deadline&&c->captured->io.original_deadline==t->deadline&&
  !jpc_chain_owner.failed&&jpc_jct_inventory_matches(jpc_jct_context.count)&&
  c->captured->edge.complete&&c->captured->edge.child.ready&&
  jpc_raw_valid(t)&&!jpc_raw_records&&!jpc_raw_snapshot&&
  jpc_raw_path->phase==5&&jpc_raw_path->pe==3&&jpc_raw_path->programmed==4;
}
static int jpc_jct_read(void*arg,unsigned side,unsigned port,unsigned space,unsigned off,unsigned n,u32*v)
{
 struct jpc_jct_owner*c=arg;typeof(jpc_provider_owner)*t=jpc_jct_context.ticket;
 if(!jpc_jct_valid(c)||side>1||space>JPC5_T_PT_HOPS||!n||n>8||off>8192-n||
    (space==JPC5_T_PT_SW?port!=0:(!port||port>23)))return -EPERM;
 return tb_cfg_read(t->tb->ctl,v,c->path.wire_route[side],port,
  space==JPC5_T_PT_SW?TB_CFG_SWITCH:space==JPC5_T_PT_PORT?TB_CFG_PORT:TB_CFG_HOPS,off,n);
}
static int jpc_jct_identity(struct jpc_jct_owner*c,unsigned pe)
{
 u32 h[5],uid[2],v;int ret;
 if(!jpc_jct_valid(c)||pe>3)return -EPERM;
 for(unsigned side=0;side<2;side++){
  const struct jpc5_node*n=side?&c->captured->edge.child:&c->captured->edge.parent;
  ret=jpc5_t_pt_read(&c->path,side,0,JPC5_T_PT_SW,0,5,h);if(ret)return ret;
  if(memcmp(h,n->header,sizeof(h)))return -ESTALE;
  ret=jpc5_t_pt_read(&c->path,side,0,JPC5_T_PT_SW,7,2,uid);if(ret)return ret;
  if((((u64)uid[0]<<32)|uid[1])!=n->uid)return -ESTALE;
  ret=jpc5_t_pt_read(&c->path,side,c->path.adapter[side],JPC5_T_PT_PORT,c->path.pcie[side],1,&v);if(ret)return ret;
  if(((v>>8)&255)!=4||(v>>31)!=((pe>>side)&1))return -ESTALE;
  ret=jpc5_t_pt_read(&c->path,side,0,JPC5_T_PT_SW,6,1,&v);if(ret)return ret;
  if((v&(3U<<24))!=(3U<<24))return -ESTALE;
 }
 return 0;
}
static int jpc_jct_audit(void*arg)
{
 struct jpc_jct_owner*c=arg;typeof(jpc_provider_owner)*t=jpc_jct_context.ticket;int ret;
 if(!jpc_jct_valid(c))return -EPERM;
 ret=jpc_raw_proof(t,3);if(!ret)ret=jraw_pt_verify(jpc_raw_path);if(ret)return ret;
 ret=apple_apciec_jpc_chain_closed_audit(t->host,3,t,t->deadline);if(ret)return ret;
 for(unsigned j=0;j<c->index;j++){
  struct jpc_jct_owner*prior=jpc_jct_context.edges[j];
  if(!prior||!prior->complete||prior->status||prior->path.phase!=5||prior->path.pe!=3)return -EPERM;
  ret=jpc_jct_identity(prior,3);if(!ret)ret=jpc5_t_pt_verify(&prior->path);if(ret)return ret;
 }
 return jpc_jct_identity(c,c->path.pe);
}
static int jpc_jct_proof(void*arg,unsigned pe)
{struct jpc_jct_owner*c=arg;return pe!=c->path.pe?-EPERM:jpc_jct_audit(c);}
static int jpc_jct_write(void*arg,unsigned side,unsigned port,unsigned space,unsigned off,unsigned n,const u32*v)
{
 struct jpc_jct_owner*c=arg;typeof(jpc_provider_owner)*t=jpc_jct_context.ticket;
 if(!jpc_jct_valid(c)||!jpc5_t_pt_write_allowed(&c->path,side,port,space,off,n,v))return -EPERM;
 return tb_cfg_write(t->tb->ctl,v,c->path.wire_route[side],port,
  space==JPC5_T_PT_SW?TB_CFG_SWITCH:space==JPC5_T_PT_PORT?TB_CFG_PORT:TB_CFG_HOPS,off,n);
}
static int jpc_jct_commit(void*arg)
{
 struct jpc_jct_owner*c=arg;
 if(c->path.phase!=4||c->path.programmed!=4||c->path.pe!=3)return -EPERM;
 /* Adjacent tunnel commitment has NO reset/LTSSM/host action. */
 return jpc_jct_audit(c);
}
static int __maybe_unused jpc_apple_j314s_chain_tunnels_cold(unsigned count)
{
 typeof(jpc_provider_owner)*t=&jpc_provider_owner;int ret=0;
 lockdep_assert_held(&t->c->lock);lockdep_assert_held(&t->tb->lock);
 if(jpc_jct_context.consumed)return -EALREADY;
 jpc_jct_context.consumed=true;jpc_jct_context.ticket=t;jpc_jct_context.task=current;
 jpc_jct_context.deadline=t->deadline;jpc_jct_context.count=count;
 if(count>4||!jpc_jct_inventory_matches(count)||jpc_chain_owner.failed||jpc_chain_owner.a!=t->a||
    jpc_chain_owner.first!=t->bootstrap||jpc_chain_owner.deadline!=t->deadline||
    !jpc_raw_valid(t)||jpc_raw_records||jpc_raw_snapshot){ret=-EPERM;goto fail;}
 ret=apple_apciec_jpc_chain_closed_audit(t->host,3,t,t->deadline);if(ret)goto fail;
 for(unsigned j=0;j<count;j++){
  struct jpc_kernel_edge*k=jpc_chain_owner.edges[j];struct jpc5_edge*e=k?&k->edge:NULL;
  if(!e||!e->complete||!e->child.ready||e->ready.phase!=5||
     e->parent.route!=(j?jpc_chain_owner.edges[j-1]->edge.child.route:1)||
     e->parent.uid!=(j?jpc_chain_owner.edges[j-1]->edge.child.uid:t->bootstrap->pins.uid)||
     e->child.depth!=j+2||!jpc5_bootstrap_pins_valid(&e->pins)){ret=-EPERM;goto fail;}
  struct jpc_jct_owner*c=kzalloc(sizeof(*c),GFP_KERNEL);if(!c){ret=-ENOMEM;goto fail;}
  jpc_jct_context.edges[j]=c;c->captured=k;c->index=j;c->status=-EINPROGRESS;
  c->path=(struct jpc5_t_pt_state){.read=jpc_jct_read,.write=jpc_jct_write,.valid=jpc_jct_valid,
   .now=jpc_raw_now,.sleep=jpc_raw_sleep,.proof=jpc_jct_proof,.audit=jpc_jct_audit,
   .commit=jpc_jct_commit,.ctx=c,.deadline=t->deadline,.chain_child_depth=e->child.depth,
   .wire_route={e->parent.route,e->child.route},.lane={e->lane,1},
   .adapter={e->pins.down,e->child.up},.phy={e->ready.rphy,e->ready.cphy},
   .pcie={e->ready.rpcie,e->ready.cpcie},.disabled={e->parent.pairs.disabled,e->child.pairs.disabled}};
  memcpy(c->path.chain_header[0],e->parent.header,20);memcpy(c->path.chain_header[1],e->child.header,20);
  ret=jpc5_t_pt_once(&c->path);c->status=ret;c->complete=!ret;
  if(ret)goto fail;
 }
 return 0;
fail:jpc_jct_context.failed=true;return ret;
}
