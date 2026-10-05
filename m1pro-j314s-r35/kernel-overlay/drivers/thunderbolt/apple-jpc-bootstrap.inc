#include "jpc-boot-peer.h"
/* Selected peer graph continuation: separate indexed retained owners.
 * C0 bootstrap remains untouched. Included after original C0 bootstrap.
 * Cold graph deadline = original peer identity start +120s, never now+renewal. */
static bool jpc_capture_valid(struct apple_nhi*a)
{
 struct j314s_peer_capture_owner*o=j314s_peer_slot(a);struct apple_cio*c;
 int index;if(!o)return false;c=a->acio;index=j314s_node_index(c->np,0);
 lockdep_assert_held(&c->lock);lockdep_assert_held(&a->tb->lock);
 return index==jpc_boot_peer_controller()&&
  o->consumed&&o->lease.complete&&!o->lease.failed&&!o->status&&o->anhi==a&&
  o->lease.cio==c&&o->lease.nhi==a&&o->lease.ticket==o&&o->lease.controller==index&&
  o->completed_ns<o->lease.deadline&&o->result.child.stable&&
  j314s_boot_valid()&&j314s_chosen_valid()&&j314s_profile_valid()&&
  j314s_disabled_endpoint(index)&&READ_ONCE(j314s_owned_cio[index])==c&&
  READ_ONCE(c->root_dma_retained)&&READ_ONCE(c->root_cable_nhi)==a&&
  !READ_ONCE(c->root_stopping)&&!READ_ONCE(c->root_probe_status)&&
  READ_ONCE(c->root_cable_snapshot)==o->cable&&READ_ONCE(c->target_cable_info)==o->cable&&
  !a->enum_host&&!a->enum_bound&&!a->enum_stopping&&
  ktime_get_boottime_ns()<o->lease.deadline+100ULL*NSEC_PER_SEC;
}
static bool jpc_capture_proven(struct apple_cio*c)
{
 struct apple_nhi*a=READ_ONCE(c->root_cable_nhi);
 return a&&a->acio==c&&jpc_capture_valid(a);
}
/* SPDX-License-Identifier: GPL-2.0 */
/* Include after apple-j314s-child-capture.inc. Direct synchronous continuation
 * only, called with compiled exact pins after capture succeeds. */
/* Pure combined core already included by original C0 bootstrap. */
static struct {
 bool consumed;unsigned controller;struct task_struct *actor;
 struct apple_nhi *anhi;
 struct j314s_combined_io io;
 struct j314s_combined_result *result;
} jpc_next_owners[3];
#define jpc_next_owner jpc_next_owners[jpc_boot_peer_controller()]
static bool jpc_next_valid(void *ctx)
{
 struct apple_nhi*a=ctx;struct j314s_combined_result*r=jpc_next_owner.result;
 struct j314s_child_observation*c=&j314s_peer_slot(a)->result.child;
 return jpc_next_owner.consumed&&jpc_next_owner.controller==j314s_node_index(a->np,1)&&jpc_next_owner.actor==current&&jpc_next_owner.anhi==a&&r&&
  jpc_capture_valid(a)&&jpc_capture_proven(a->acio)&&
  c->stable&&c->usb4&&c->uid_read&&c->route==r->pins.route&&j314s_peer_slot(a)->result.lane==r->pins.lane&&
  !memcmp(c->child_header,r->pins.child_before,20)&&
  c->uid_words[0]==(u32)(r->pins.uid>>32)&&c->uid_words[1]==(u32)r->pins.uid;
}
static u64 jpc_next_now(void *ctx){return ktime_get_boottime_ns();}
static void jpc_next_sleep(void *ctx,bool fast)
{if(fast)usleep_range(5,10);else usleep_range(1000,2000);}
static int jpc_next_read(void*ctx,unsigned route,unsigned port,bool sw,unsigned off,unsigned n,u32*v)
{
 struct apple_nhi*a=ctx;struct j314s_combined_result*r=jpc_next_owner.result;
 if(!jpc_next_valid(a)||!r||!n||n>13||off>8192-n||
    (route&&route!=r->pins.route)||(sw&&port)||(!sw&&(!port||port>(route?r->pins.max_port:7))))return -EPERM;
 /* DROM/configure/RR must precede every child adapter access. */
 if(route&&!sw&&r->phase<3)return -EPERM;
 return tb_cfg_read(a->tb->ctl,v,route,port,sw?TB_CFG_SWITCH:TB_CFG_PORT,off,n);
}
static int jpc_next_write(void*ctx,unsigned route,unsigned port,bool sw,unsigned off,unsigned n,const u32*v)
{
 struct apple_nhi*a=ctx;struct j314s_combined_result*r=jpc_next_owner.result;bool okay=false;
 if(!jpc_next_valid(a)||!r||!n||n>4||off>8192-n||(route&&route!=r->pins.route))return -EPERM;
 if(r->phase==1)okay=route==r->pins.route&&sw&&!port&&n==1&&
   ((off==25&&!(v[0]&~0xffffcU))||(off==26&&v[0]==0x80000024U));
 else if(r->phase==2)okay=sw&&!port&&((!route&&n==1&&(off==r->bootstrap.io.rt||off==r->bootstrap.io.rt+3))||
   (route&&((off==1&&n==4)||(off==5&&n==1))));
 else if(r->phase==4)okay=j314s_ready_write_allowed(&r->ready,!!route,port,sw,off,n);
 if(!okay)return -EPERM;
 return tb_cfg_write(a->tb->ctl,v,route,port,sw?TB_CFG_SWITCH:TB_CFG_PORT,off,n);
}
static int apple_jpc_child_bootstrap(struct apple_nhi*a,const struct j314s_bootstrap_pins*pins)
{
 struct j314s_combined_result*r;int ret;unsigned p;
 lockdep_assert_held(&a->acio->lock);lockdep_assert_held(&a->tb->lock);
 if(jpc_next_owner.consumed)return -EALREADY;
 jpc_next_owner.consumed=true;jpc_next_owner.anhi=a;
 jpc_next_owner.controller=j314s_node_index(a->np,1);jpc_next_owner.actor=current;
 if(!jpc_capture_proven(a->acio)||!j314s_bootstrap_pins_valid(pins))return -EPERM;
 r=kzalloc(sizeof(*r),GFP_KERNEL);if(!r)return -ENOMEM;
 /* Retain all evidence and owner storage on every outcome until reboot. */
 jpc_next_owner.result=r;
 jpc_next_owner.io=(struct j314s_combined_io){.read=jpc_next_read,.write=jpc_next_write,
  .valid=jpc_next_valid,.now=jpc_next_now,.sleep=jpc_next_sleep,.ctx=a,
  .deadline=j314s_peer_slot(a)->lease.deadline+100ULL*NSEC_PER_SEC};
 ret=j314s_combined_bootstrap_once(&jpc_next_owner.io,pins,r);
 dev_info(a->dev,"j314s-child-bootstrap: status%d phase%u complete%u ops%u DROM%u configured%u PCIeUP%u ready-phase%d; PCIe disabled\n",
 ret,r->phase,r->completed,jpc_next_owner.io.operations,r->drom_size,r->bootstrap.header_done,r->inventory.pci_up,r->ready.phase);
 if(r->drom_size)dev_info(a->dev,"j314s-child-bootstrap: observed DROM product %04x:%04x; identity descriptor, not a register-schema permit\n",r->uidio.product_vendor,r->uidio.product_device);
 if(r->drom_size)dev_info(a->dev,"j314s-child-bootstrap: validated DROM %*phN\n",r->drom_size,r->drom);
 for(p=1;p<=r->inventory.max_port&&p<=63;p++)if(r->inventory.child_read[p])
  dev_info(a->dev,"j314s-child-bootstrap: child port%u raw %*phN\n",p,32,r->inventory.child_ports[p]);
 return ret;
}
static bool jpc_bootstrap_proven(struct apple_cio*c)
{
 lockdep_assert_held(&c->lock);
 return jpc_next_owner.consumed&&jpc_next_owner.anhi&&jpc_next_owner.anhi->acio==c&&
  jpc_next_owner.result&&jpc_next_owner.io.attempted&&jpc_next_owner.result->completed&&
  !jpc_next_owner.result->status&&!READ_ONCE(c->root_probe_status);
}

static int apple_jpc_child_bootstrap_captured(struct apple_nhi*a)
{
 struct j314s_bootstrap_pins pins;struct j314s_link_result*r=&j314s_peer_slot(a)->result;
 lockdep_assert_held(&a->acio->lock);lockdep_assert_held(&a->tb->lock);
 if(!jpc_capture_proven(a->acio)||!r->child.stable||!r->child.uid_read||!r->child.usb4||
  !j314s_bootstrap_bind_capture(&pins,r->root,r->child.child_header,r->child.uid_words,r->lane,r->child.route))return -EOPNOTSUPP;
 if(pins.lane!=pins.route){
  dev_info(a->dev,"j314s-child-bootstrap: secondary physical link captured, primary native-ready proof absent; no bootstrap writes\n");
  return -EOPNOTSUPP;
 }
 return apple_jpc_child_bootstrap(a,&pins);
}

static int apple_jpc_child_capture_indexed(struct apple_nhi*a,unsigned controller)
{
 if(!a||!a->acio||controller<1||controller>2||
    !j314s_boot_controller_admitted(saved_command_line,controller)||
    controller!=jpc_boot_peer_controller()||
    j314s_node_index(a->np,1)!=(int)controller||
    j314s_node_index(a->acio->np,0)!=(int)controller)return -EPERM;
 return apple_j314s_peer_capture(a);
}
