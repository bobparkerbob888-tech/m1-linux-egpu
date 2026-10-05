/* SPDX-License-Identifier: GPL-2.0 */
/* Included after apple-j314s-late-arm.inc. Retained controller0 owner only.
 * Cold one-shot observation, not downstream authorization or PCIe admission. */
#include "j314s-link-capture-core.h"
#include "j314s-drom-pair.h"
static struct {
 struct apple_nhi *anhi;
 struct j314s_link_io io;
 struct j314s_link_result result;
 unsigned long deadline;
 u32 cable;
 bool consumed;
} j314s_child_owner;

static bool j314s_child_owner_valid(void *ctx)
{
 struct apple_nhi *a=ctx;struct apple_cio *c=a->acio;
 struct tb_switch *sw=a->tb->root_switch;
 lockdep_assert_held(&c->lock);lockdep_assert_held(&a->tb->lock);
 return j314s_child_owner.consumed && j314s_child_owner.anhi==a &&
  of_machine_is_compatible("apple,j314s") && j314s_node_index(c->np,0)==0 &&
  j314s_node_index(a->np,1)==0 && READ_ONCE(j314s_owned_cio[0])==c &&
  READ_ONCE(j314s_arm_committed[0]) && atomic_read(&j314s_power_attempt[0])==1 &&
  j314s_boot_valid() && j314s_chosen_valid() && j314s_inventory_options() &&
  READ_ONCE(root_router_only) && j314s_profile_valid() && j314s_disabled_endpoint(0) &&
  READ_ONCE(c->root_cable_nhi)==a && READ_ONCE(c->root_dma_retained) &&
  !READ_ONCE(c->root_stopping) && !READ_ONCE(c->root_probe_status) &&
  !READ_ONCE(c->current_cable_info) &&
  smp_load_acquire(&c->root_cable_snapshot_valid) &&
  READ_ONCE(c->root_cable_snapshot)==j314s_child_owner.cable &&
  READ_ONCE(c->target_cable_info)==j314s_child_owner.cable &&
  sw && !tb_route(sw) && sw->config.vendor_id==0x05ac && sw->config.device_id==0x2001 &&
  sw->config.max_port_number==7 && sw->config.upstream_port_number==7 &&
  sw->config.enabled && a->tb->nhi->ops && a->tb->nhi->ops->root_router_only;
}
static bool j314s_child_owner_expired(void *ctx)
{return time_after_eq(jiffies,j314s_child_owner.deadline);}
static void j314s_child_owner_delay(void *ctx){msleep(20);}
static int j314s_child_owner_read(void *ctx,unsigned route,unsigned port,
 bool sw,unsigned off,unsigned n,u32 *words)
{
 struct apple_nhi *a=ctx;
 /* Root bounded SWITCH/capabilities/adapter reads, or selected one-hop
  * child SWITCH header and UID. No PATH config, DROM or child port reads. */
 if(!j314s_child_owner_valid(ctx)||j314s_child_owner_expired(ctx))return -EPERM;
 if(!n||n>8||off>0x1fff||n>0x2000-off)return -EINVAL;
 if(route) {
  if(route!=j314s_child_owner.result.primary || !sw || port ||
     !((off==0&&n==5)||(off==7&&n==2)))return -EPERM;
 } else if(sw ? port!=0 : (!port||port>7))return -EPERM;
 return tb_cfg_read(a->tb->ctl,words,route,port,sw?TB_CFG_SWITCH:TB_CFG_PORT,off,n);
}
static int j314s_child_owner_write(void *ctx,unsigned port,bool sw,unsigned off,u32 word)
{
 struct apple_nhi *a=ctx;struct j314s_link_result *r=&j314s_child_owner.result;
 unsigned i;bool allow=false;
 if(!j314s_child_owner_valid(ctx)||j314s_child_owner_expired(ctx))return -EPERM;
 if(sw && !port && r->cable_write_attempted && !r->cable_verified &&
    word==j314s_child_owner.cable && !r->cable_before) {
  for(i=0;i<r->nr_caps;i++)if(off==r->cap_offsets[i]+1 &&
    ((r->caps[i][0]>>8)&255)==5 && !((r->caps[i][0]>>16)&255) &&
    (r->caps[i][0]>>24)>=2)allow=true;
 } else if(!sw && port>=r->primary && port<=r->secondary && port>=1 && port<=2 && off==4 &&
    r->cable_verified && r->pair_write_attempted[port] && !r->pair_unlock_verified[port] &&
    word==r->pair_unlock_after[port] && word==(r->pair_unlock_before[port]&~0x80000000U))allow=true;
 if(!allow)return -EPERM;
 return tb_cfg_write(a->tb->ctl,&word,0,port,sw?TB_CFG_SWITCH:TB_CFG_PORT,off,1);
}
static int apple_j314s_child_capture(struct apple_nhi *a)
{
 struct apple_cio *c=a->acio;struct j314s_link_result *r=&j314s_child_owner.result;
 int ret,length=0;unsigned i;const unsigned char*drom;
 lockdep_assert_held(&c->lock);lockdep_assert_held(&a->tb->lock);
 if(j314s_child_owner.consumed)return -EALREADY;
 j314s_child_owner.consumed=true;j314s_child_owner.anhi=a;
 drom=of_get_property(a->np,"apple,thunderbolt-drom",&length);
 if(!j314s_profile_valid()||length<0||!j314s_drom_pair(drom,length))return -EPERM;
 j314s_child_owner.cable=READ_ONCE(c->root_cable_snapshot);
 j314s_child_owner.deadline=jiffies+msecs_to_jiffies(20000);
 j314s_child_owner.io=(struct j314s_link_io){
  .read=j314s_child_owner_read,.write=j314s_child_owner_write,
  .valid=j314s_child_owner_valid,.expired=j314s_child_owner_expired,
  .poll_delay=j314s_child_owner_delay,.ctx=a,.primary=1,.secondary=2,.pair_verified=true};
 ret=j314s_link_capture_once(&j314s_child_owner.io,j314s_child_owner.cable,r);
 dev_info(a->dev,"j314s-child-observation: status%d operations%u cable%#x write%u verified%u physical-lane%u unlock-write%u unlock-verified%u child-read%u usb4%u uid-read%u stable%u\n",
  ret,j314s_child_owner.io.operations,j314s_child_owner.cable,r->cable_write_attempted,r->cable_verified,
  r->lane,r->unlock_write_attempted,r->unlock_verified,r->child.header_read,r->child.usb4,r->child.uid_read,r->child.stable);
 for(i=1;i<=7;i++)if(r->phy_offsets[i])dev_info(a->dev,
  "j314s-child-observation: lane%u raw-adapter %*phN phy-offset%u raw-phy %*phN\n",
  i,32,r->ports[i],r->phy_offsets[i],8,r->phy[i]);
 for(i=1;i<=2;i++)if(r->pair_header_read[i])dev_info(a->dev,
  "j314s-child-observation: lane%u raw-adapter-before-unlock %*phN unlock-before%08x unlock-after%08x write%u verified%u\n",
  i,32,r->pair_before_unlock[i],r->pair_unlock_before[i],r->pair_unlock_after[i],r->pair_write_attempted[i],r->pair_unlock_verified[i]);
 dev_info(a->dev,"j314s-child-observation: exact-DROM primary%u secondary%u logical-route%u physical-ready-lane%u\n",r->primary,r->secondary,r->child.route,r->lane);
 if(r->child.header_read)dev_info(a->dev,"j314s-child-observation: raw header %*phN\n",20,r->child.child_header);
 if(r->child.uid_read)dev_info(a->dev,"j314s-child-observation: raw uid %*phN\n",8,r->child.uid_words);
 dev_info(a->dev,"j314s-child-observation: retained until reboot; no child configuration or PCIe tunnel\n");
 return ret;
}

/* Software-only status; caller holds the retained ACIO mutex. */
static bool j314s_child_capture_proven(struct apple_cio *c)
{
 lockdep_assert_held(&c->lock);
 return j314s_child_owner.consumed && j314s_child_owner.anhi &&
  j314s_child_owner.anhi->acio==c && j314s_child_owner.io.attempted &&
  j314s_child_owner.result.cable_verified && j314s_child_owner.result.unlock_verified &&
  j314s_child_owner.result.pair_unlock_verified[1] && j314s_child_owner.result.pair_unlock_verified[2] &&
  j314s_child_owner.result.child.stable && !READ_ONCE(c->root_probe_status);
}
