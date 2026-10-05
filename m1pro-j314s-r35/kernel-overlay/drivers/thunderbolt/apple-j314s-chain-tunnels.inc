/* Dormant candidate. Include AFTER apple-j314s-raw-front.inc. No callsite,
 * parameter, worker, export or automatic expansion is introduced here.
 * Intended call is cold phase8, immediately after root tunnel commit and
 * BEFORE any PCI scan/BAR/native/GPU operation. ACIO and TB locks held. */
#include "jct-tunnel-core.h"
extern int apple_apciec_j314s_chain_closed_audit(struct device*,unsigned,const void*,u64);
struct jct_owner {
 struct jc_kernel_edge *captured;
 struct jct_pt_state path;
 unsigned index;int status;bool complete;
};
static struct {
 typeof(j314s_provider_owner)*ticket;struct task_struct*task;
 u64 deadline;unsigned count;bool consumed,failed;
 struct jct_owner*edges[3];
} jct_context;
static bool jct_inventory_matches(unsigned count)
{
#ifdef JCT_LINEAR_INVENTORY
 struct jc_kernel_edge*terminal;
 if(!jc_inventory_owner.published||jc_inventory_owner.status||
    !jc_inventory_owner.list.terminal||jc_inventory_owner.list.count!=count||
    jc_owner.count!=count+1||count>3)return false;
 terminal=jc_owner.edges[count];
 return terminal&&terminal->edge.survey_terminal&&!terminal->consumed&&
  !terminal->io.attempted&&!terminal->captured_uid;
#else
 /* Proven R15 one-edge receipt; additional edges require linear owner kit. */
 return count==1&&jc_owner.count==1;
#endif
}
/* Inventory is a completed cold-worker receipt; provider continuation owns
 * the current actor. Bind their immutable bootstrap/deadline, not task equality. */
static bool jct_valid(void*arg)
{
 struct jct_owner*c=arg;typeof(j314s_provider_owner)*t=&j314s_provider_owner;
 return c&&jct_context.consumed&&!jct_context.failed&&jct_context.ticket==t&&
  jct_context.task==current&&jct_context.deadline==t->deadline&&
  c->path.deadline==t->deadline&&ktime_get_boottime_ns()<t->deadline&&
  c->index<jct_context.count&&jct_context.edges[c->index]==c&&
  c->captured==jc_owner.edges[c->index]&&jc_owner.a==t->a&&jc_owner.first==t->bootstrap&&
  jc_owner.deadline==t->deadline&&c->captured->io.original_deadline==t->deadline&&
  !jc_owner.failed&&jct_inventory_matches(jct_context.count)&&
  c->captured->edge.complete&&c->captured->edge.child.ready&&
  j314s_raw_valid(t)&&!j314s_raw_records&&!j314s_raw_snapshot&&
  j314s_raw_path->phase==5&&j314s_raw_path->pe==3&&j314s_raw_path->programmed==4;
}
static int jct_read(void*arg,unsigned side,unsigned port,unsigned space,unsigned off,unsigned n,u32*v)
{
 struct jct_owner*c=arg;typeof(j314s_provider_owner)*t=jct_context.ticket;
 if(!jct_valid(c)||side>1||space>JCT_PT_HOPS||!n||n>8||off>8192-n||
    (space==JCT_PT_SW?port!=0:(!port||port>23)))return -EPERM;
 return tb_cfg_read(t->tb->ctl,v,c->path.wire_route[side],port,
  space==JCT_PT_SW?TB_CFG_SWITCH:space==JCT_PT_PORT?TB_CFG_PORT:TB_CFG_HOPS,off,n);
}
static int jct_identity(struct jct_owner*c,unsigned pe)
{
 u32 h[5],uid[2],v;int ret;
 if(!jct_valid(c)||pe>3)return -EPERM;
 for(unsigned side=0;side<2;side++){
  const struct jc_node*n=side?&c->captured->edge.child:&c->captured->edge.parent;
  ret=jct_pt_read(&c->path,side,0,JCT_PT_SW,0,5,h);if(ret)return ret;
  if(memcmp(h,n->header,sizeof(h)))return -ESTALE;
  ret=jct_pt_read(&c->path,side,0,JCT_PT_SW,7,2,uid);if(ret)return ret;
  if((((u64)uid[0]<<32)|uid[1])!=n->uid)return -ESTALE;
  ret=jct_pt_read(&c->path,side,c->path.adapter[side],JCT_PT_PORT,c->path.pcie[side],1,&v);if(ret)return ret;
  if(((v>>8)&255)!=4||(v>>31)!=((pe>>side)&1))return -ESTALE;
  ret=jct_pt_read(&c->path,side,0,JCT_PT_SW,6,1,&v);if(ret)return ret;
  if((v&(3U<<24))!=(3U<<24))return -ESTALE;
 }
 return 0;
}
static int jct_audit(void*arg)
{
 struct jct_owner*c=arg;typeof(j314s_provider_owner)*t=jct_context.ticket;int ret;
 if(!jct_valid(c))return -EPERM;
 ret=j314s_raw_proof(t,3);if(!ret)ret=jraw_pt_verify(j314s_raw_path);if(ret)return ret;
 ret=apple_apciec_j314s_chain_closed_audit(t->host,3,t,t->deadline);if(ret)return ret;
 for(unsigned j=0;j<c->index;j++){
  struct jct_owner*prior=jct_context.edges[j];
  if(!prior||!prior->complete||prior->status||prior->path.phase!=5||prior->path.pe!=3)return -EPERM;
  ret=jct_identity(prior,3);if(!ret)ret=jct_pt_verify(&prior->path);if(ret)return ret;
 }
 return jct_identity(c,c->path.pe);
}
static int jct_proof(void*arg,unsigned pe)
{struct jct_owner*c=arg;return pe!=c->path.pe?-EPERM:jct_audit(c);}
static int jct_write(void*arg,unsigned side,unsigned port,unsigned space,unsigned off,unsigned n,const u32*v)
{
 struct jct_owner*c=arg;typeof(j314s_provider_owner)*t=jct_context.ticket;
 if(!jct_valid(c)||!jct_pt_write_allowed(&c->path,side,port,space,off,n,v))return -EPERM;
 return tb_cfg_write(t->tb->ctl,v,c->path.wire_route[side],port,
  space==JCT_PT_SW?TB_CFG_SWITCH:space==JCT_PT_PORT?TB_CFG_PORT:TB_CFG_HOPS,off,n);
}
static int jct_commit(void*arg)
{
 struct jct_owner*c=arg;
 if(c->path.phase!=4||c->path.programmed!=4||c->path.pe!=3)return -EPERM;
 /* Adjacent tunnel commitment has NO reset/LTSSM/host action. */
 return jct_audit(c);
}
static int __maybe_unused apple_j314s_chain_tunnels_cold(unsigned count)
{
 typeof(j314s_provider_owner)*t=&j314s_provider_owner;int ret=0;
 lockdep_assert_held(&t->c->lock);lockdep_assert_held(&t->tb->lock);
 if(jct_context.consumed)return -EALREADY;
 jct_context.consumed=true;jct_context.ticket=t;jct_context.task=current;
 jct_context.deadline=t->deadline;jct_context.count=count;
 if(!count||count>3||!jct_inventory_matches(count)||jc_owner.failed||jc_owner.a!=t->a||
    jc_owner.first!=t->bootstrap||jc_owner.deadline!=t->deadline||
    !j314s_raw_valid(t)||j314s_raw_records||j314s_raw_snapshot){ret=-EPERM;goto fail;}
 ret=apple_apciec_j314s_chain_closed_audit(t->host,3,t,t->deadline);if(ret)goto fail;
 for(unsigned j=0;j<count;j++){
  struct jc_kernel_edge*k=jc_owner.edges[j];struct jc_edge*e=k?&k->edge:NULL;
  if(!e||!e->complete||!e->child.ready||e->ready.phase!=5||
     e->parent.route!=(j?jc_owner.edges[j-1]->edge.child.route:1)||
     e->parent.uid!=(j?jc_owner.edges[j-1]->edge.child.uid:t->bootstrap->pins.uid)||
     e->child.depth!=j+2||!jc_bootstrap_pins_valid(&e->pins)){ret=-EPERM;goto fail;}
  struct jct_owner*c=kzalloc(sizeof(*c),GFP_KERNEL);if(!c){ret=-ENOMEM;goto fail;}
  jct_context.edges[j]=c;c->captured=k;c->index=j;c->status=-EINPROGRESS;
  c->path=(struct jct_pt_state){.read=jct_read,.write=jct_write,.valid=jct_valid,
   .now=j314s_raw_now,.sleep=j314s_raw_sleep,.proof=jct_proof,.audit=jct_audit,
   .commit=jct_commit,.ctx=c,.deadline=t->deadline,.chain_child_depth=e->child.depth,
   .wire_route={e->parent.route,e->child.route},.lane={e->lane,1},
   .adapter={e->pins.down,e->child.up},.phy={e->ready.rphy,e->ready.cphy},
   .pcie={e->ready.rpcie,e->ready.cpcie},.disabled={e->parent.pairs.disabled,e->child.pairs.disabled}};
  memcpy(c->path.chain_header[0],e->parent.header,20);memcpy(c->path.chain_header[1],e->child.header,20);
  ret=jct_pt_once(&c->path);c->status=ret;c->complete=!ret;
  if(ret)goto fail;
 }
 return 0;
fail:jct_context.failed=true;return ret;
}
