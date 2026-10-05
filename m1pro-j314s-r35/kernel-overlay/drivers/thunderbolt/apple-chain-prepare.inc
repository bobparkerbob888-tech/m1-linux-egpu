/* SPDX-License-Identifier: GPL-2.0 */
#include "chain_prepare_core.h"
static bool route_chain_prepare;
module_param(route_chain_prepare, bool, 0444);
MODULE_PARM_DESC(route_chain_prepare,"J293 ACIO0 exact two downstream router control-plane preparation; no additional PCIe tunnels");
static atomic_t chain_attempted[2] = { ATOMIC_INIT(0), ATOMIC_INIT(0) };
struct chain_kernel_context;
struct chain_ready_context {struct chain_kernel_context *owner;unsigned child;struct ready_io ready;};
struct chain_kernel_context {struct apple_nhi *anhi;struct chain_io io;struct chain_ready_context links[2];};
static struct chain_kernel_context *chain_prepared[2];
static bool chain_kernel_valid(void *p)
{
 struct chain_kernel_context *c=p;
 return route_chain_prepare && route1_usb4_ready && route1_inventory &&
  route1_header_config && apple_unlock_context(c->anhi);
}
static u64 chain_kernel_now(void *p){return ktime_get_boottime_ns();}
static void chain_kernel_delay(void *p){usleep_range(1000,2000);}
static int chain_kernel_read(void *p,unsigned r,unsigned port,bool sw,unsigned off,unsigned n,u32 *v)
{
 struct chain_kernel_context *c=p;
 if(!chain_kernel_valid(p))return -EPERM;
 return tb_cfg_read(c->anhi->tb->ctl,v,r,port,sw?TB_CFG_SWITCH:TB_CFG_PORT,off,n);
}
static int chain_kernel_write(void *p,unsigned r,unsigned port,bool sw,unsigned off,unsigned n,const u32 *v)
{
 struct chain_kernel_context *c=p;
 if(!chain_kernel_valid(p))return -EPERM;
 return tb_cfg_write(c->anhi->tb->ctl,v,r,port,sw?TB_CFG_SWITCH:TB_CFG_PORT,off,n);
}
static bool chain_ready_valid(void *p)
{
 struct chain_ready_context *c=p;struct chain_node *n;
 if(!chain_kernel_valid(c->owner)||c->child<1||c->child>=bob_chain_count(c->owner->io.controller))return false;
 n=c->owner->io.node;
 return n[c->child].identity&&n[c->child].configured&&n[c->child].ready&&n[c->child-1].tmu_ready;
}
static u64 chain_ready_now(void *p){return ktime_get_boottime_ns();}
static void chain_ready_delay(void *p,bool shortpoll)
{if(shortpoll)usleep_range(5,10);else usleep_range(1000,2000);}
static int chain_ready_read(void *p,unsigned r,unsigned port,bool sw,unsigned off,unsigned n,u32 *v)
{
 struct chain_ready_context *c=p;
 if(r>1||!chain_ready_valid(p))return -EPERM;
 return chain_read(&c->owner->io,c->owner->io.node[c->child-1+r].route,port,sw,off,n,v);
}
static int chain_ready_write(void *p,unsigned r,unsigned port,bool sw,unsigned off,unsigned n,const u32 *v)
{
 struct chain_ready_context *c=p;struct chain_io *io=&c->owner->io;unsigned route;int ret;
 if(r>1||!chain_ready_valid(p)||!ready_write_allowed(&c->ready,r,port,sw,off,n))return -EPERM;
 ret=chain_blocked(io);if(ret)return ret;
 ret=chain_gate(io);if(ret)return ret;
 route=io->node[c->child-1+r].route;
 ret=tb_cfg_write(c->owner->anhi->tb->ctl,v,route,port,sw?TB_CFG_SWITCH:TB_CFG_PORT,off,n);
 return ret?ret:chain_blocked(io);
}
static int chain_kernel_link_ready(void *p,unsigned child)
{
 struct chain_kernel_context *c=p;struct chain_ready_context *r;unsigned j;int ret;
 if(child<1||child>=bob_chain_count(c->io.controller))return -EINVAL;
 r=&c->links[child-1];r->owner=c;r->child=child;
 r->ready=(struct ready_io){.read=chain_ready_read,.write=chain_ready_write,.valid=chain_ready_valid,
  .now=chain_ready_now,.sleep=chain_ready_delay,.ctx=r,.deadline=c->io.deadline,
  .up=9,.chain_child_depth=child+1};
 for(j=0;j<2;j++)chain_expected(&c->io.node[child-1+j],r->ready.chain_header[j]);
 ret=ready_once(&r->ready);
 dev_info(c->anhi->dev,"chain-readiness: route%x status%d phase%d operations%u parent-rate%u child-rate%u; PCIe pair disabled\n",
  c->io.node[child].route,ret,r->ready.phase,r->ready.ops,r->ready.observed[5]>>16,r->ready.observed[6]>>16);
 return ret;
}
static int apple_chain_prepare(struct apple_nhi *anhi,const struct bob_inv_result *inventory,const struct ready_io *ready)
{
 struct chain_kernel_context *c;unsigned j,k;int ret;
 lockdep_assert_held(&anhi->acio->lock);lockdep_assert_held(&anhi->tb->lock);
 if(!route_chain_prepare)return 0;
 if(bob_attempt_once(chain_attempted, anhi->np))return -EALREADY;
 c=kzalloc(sizeof(*c),GFP_KERNEL);if(!c)return -ENOMEM;
 /* Retained like the controller owner even after partial configuration.
  * This transaction adds no DMA buffers and never performs cleanup writes. */
 c->anhi=anhi;
 c->io=(struct chain_io){.read=chain_kernel_read,.write=chain_kernel_write,
  .valid=chain_kernel_valid,.now=chain_kernel_now,.delay=chain_kernel_delay,.link_ready=chain_kernel_link_ready,.ctx=c,
  .deadline=ktime_get_boottime_ns()+15ULL*NSEC_PER_SEC,.root_pcie_cap=ready->rpcie,.controller=bob_controller_index(anhi->np)};
 ret=chain_once(&c->io,inventory->disabled_ports);
 if(!ret)WRITE_ONCE(chain_prepared[c->io.controller],c);
 for(j=0;j<bob_chain_count(c->io.controller);j++){
  struct chain_node *n=&c->io.node[j];
  dev_info(anhi->dev,"chain-prepare: route%llx UID%08x%08x identity%u configured%u ready%u\n",(unsigned long long)n->route,n->uid_hi,n->uid_lo,n->identity,n->configured,n->ready);
  if(!n->ready)continue;
  for(k=1;k<=23;k++)if(n->ports[k][0])dev_info(anhi->dev,"chain-prepare: route%llx port%u header %*phN\n",(unsigned long long)n->route,k,32,n->ports[k]);
 }
 dev_info(anhi->dev,"chain-prepare: terminal status%d operations%u; no new PCIe tunnel or GPU initialized\n",ret,c->io.operations);
 return ret;
}
