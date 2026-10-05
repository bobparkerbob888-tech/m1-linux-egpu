/* SPDX-License-Identifier: GPL-2.0 */
/* Included after apple-j314s-child-capture.inc. Separate controller1/2 owners; controller0 file unchanged.
 * Cold one-shot observation, not downstream authorization or PCIe admission. */
#include "peer-owner-core.h"
#include "apple-j314s-peer-identity-report.h"
struct j314s_peer_capture_owner {
 struct apple_nhi *anhi;
 struct jp_owner lease;
 int status;
 u32 root_uid[2];u64 completed_ns;
 struct j314s_link_io io;
 struct j314s_link_result result;
 unsigned long deadline;
 u32 cable;
 bool consumed;
};
static struct j314s_peer_capture_owner j314s_peer_owners[3];
static struct j314s_peer_capture_owner *j314s_peer_slot(struct apple_nhi *a)
{
 int i;if(!a||!a->acio||!a->tb)return NULL;
 i=j314s_node_index(a->acio->np,0);
 if(i<1||i>2||j314s_node_index(a->np,1)!=i)return NULL;
 return &j314s_peer_owners[i];
}

static bool j314s_peer_owner_valid(void *ctx)
{
 struct apple_nhi *a=ctx;struct j314s_peer_capture_owner *o=j314s_peer_slot(a);
 struct apple_cio *c;int index;if(!o)return false;c=a->acio;index=j314s_node_index(c->np,0);
 struct tb_switch *sw=a->tb->root_switch;
 lockdep_assert_held(&c->lock);lockdep_assert_held(&a->tb->lock);
 o->lease.operations=o->io.operations;
 return jp_valid(&o->lease,index,c,a,o,o->cable,ktime_get_boottime_ns()) && o->consumed && o->anhi==a &&
  of_machine_is_compatible("apple,j314s") && j314s_node_index(c->np,0)==index &&
  j314s_node_index(a->np,1)==index && READ_ONCE(j314s_owned_cio[index])==c &&
  READ_ONCE(j314s_arm_committed[index]) && atomic_read(&j314s_power_attempt[index])==1 &&
  j314s_boot_valid() && j314s_chosen_valid() && j314s_inventory_options() &&
  READ_ONCE(root_router_only) && j314s_profile_valid() && j314s_disabled_endpoint(index) &&
  READ_ONCE(c->root_cable_nhi)==a && READ_ONCE(c->root_dma_retained) &&
  !READ_ONCE(c->root_stopping) && !READ_ONCE(c->root_probe_status) &&
  !READ_ONCE(c->current_cable_info) &&
  smp_load_acquire(&c->root_cable_snapshot_valid) &&
  READ_ONCE(c->root_cable_snapshot)==o->cable &&
  READ_ONCE(c->target_cable_info)==o->cable &&
  sw && !tb_route(sw) && sw->config.vendor_id==0x05ac && sw->config.device_id==0x2001 &&
  sw->config.max_port_number==7 && sw->config.upstream_port_number==7 &&
  sw->config.enabled && a->tb->nhi->ops && a->tb->nhi->ops->root_router_only;
}
static bool j314s_peer_owner_expired(void *ctx)
{struct j314s_peer_capture_owner *o=j314s_peer_slot(ctx);
 return !o||time_after_eq(jiffies,o->deadline);}
static void j314s_peer_owner_delay(void *ctx){msleep(20);}
static int j314s_peer_owner_read(void *ctx,unsigned route,unsigned port,
 bool sw,unsigned off,unsigned n,u32 *words)
{
 struct apple_nhi *a=ctx;struct j314s_peer_capture_owner *o=j314s_peer_slot(a);
 if(!o)return -EPERM;
 /* Root bounded SWITCH/capabilities/adapter reads, or selected one-hop
  * child SWITCH header and UID. No PATH config, DROM or child port reads. */
 if(!j314s_peer_owner_valid(ctx)||j314s_peer_owner_expired(ctx))return -EPERM;
 if(!n||n>8||off>0x1fff||n>0x2000-off)return -EINVAL;
 if(route) {
  if(route!=o->result.primary || !sw || port ||
     !((off==0&&n==5)||(off==7&&n==2)))return -EPERM;
 } else if(sw ? port!=0 : (!port||port>7))return -EPERM;
 return tb_cfg_read(a->tb->ctl,words,route,port,sw?TB_CFG_SWITCH:TB_CFG_PORT,off,n);
}
static int j314s_peer_owner_write(void *ctx,unsigned port,bool sw,unsigned off,u32 word)
{
 struct apple_nhi *a=ctx;struct j314s_peer_capture_owner *o=j314s_peer_slot(a);
 struct j314s_link_result *r;if(!o)return -EPERM;r=&o->result;
 unsigned i;bool allow=false;
 if(!j314s_peer_owner_valid(ctx)||j314s_peer_owner_expired(ctx))return -EPERM;
 if(sw && !port && r->cable_write_attempted && !r->cable_verified &&
    word==o->cable && !r->cable_before) {
  for(i=0;i<r->nr_caps;i++)if(off==r->cap_offsets[i]+1 &&
    ((r->caps[i][0]>>8)&255)==5 && !((r->caps[i][0]>>16)&255) &&
    (r->caps[i][0]>>24)>=2)allow=true;
 } else if(!sw && port>=r->primary && port<=r->secondary && port>=1 && port<=2 && off==4 &&
    r->cable_verified && r->pair_write_attempted[port] && !r->pair_unlock_verified[port] &&
    word==r->pair_unlock_after[port] && word==(r->pair_unlock_before[port]&~0x80000000U))allow=true;
 if(!allow)return -EPERM;
 return tb_cfg_write(a->tb->ctl,&word,0,port,sw?TB_CFG_SWITCH:TB_CFG_PORT,off,1);
}
static int apple_j314s_peer_capture(struct apple_nhi *a)
{
 struct j314s_peer_capture_owner *o=j314s_peer_slot(a);
 struct apple_cio *c;struct j314s_link_result *r;
 if(!o)return -EPERM;
 c=a->acio;r=&o->result;
 int ret,length=0;unsigned i;const unsigned char*drom;
 lockdep_assert_held(&c->lock);lockdep_assert_held(&a->tb->lock);
 if(o->consumed)return -EALREADY;
 o->consumed=true;o->anhi=a;o->status=-EINPROGRESS;
 drom=of_get_property(a->np,"apple,thunderbolt-drom",&length);
 {int controller=j314s_node_index(c->np,0);bool profile=j314s_profile_valid();
  bool pair=controller>=1&&controller<=2&&length>=0&&
   j314s_drom_root_uid(drom,length,controller,o->root_uid);
  if(!profile||!pair){o->status=-EPERM;
   dev_err(a->dev,"j314s-peer-prelease: controller%d stage=drom profile%u pair%u length%d status%d\n",
    controller,profile,pair,length,o->status);return o->status;}}
 o->cable=READ_ONCE(c->root_cable_snapshot);
 {u64 now=ktime_get_boottime_ns();
  ret=jp_begin(&o->lease,j314s_node_index(c->np,0),c,a,o,o->cable,now,now+20ULL*NSEC_PER_SEC);
  if(ret){o->status=ret;dev_err(a->dev,"j314s-peer-prelease: controller%d stage=lease status%d\n",j314s_node_index(c->np,0),ret);return ret;}}
 o->deadline=jiffies+msecs_to_jiffies(20000);
 o->io=(struct j314s_link_io){
  .read=j314s_peer_owner_read,.write=j314s_peer_owner_write,
  .valid=j314s_peer_owner_valid,.expired=j314s_peer_owner_expired,
  .poll_delay=j314s_peer_owner_delay,.ctx=a,.primary=1,.secondary=2,.pair_verified=true};
 ret=j314s_link_capture_once(&o->io,o->cable,r);
 if(!ret){unsigned stable[2];int current_length=0;
  const unsigned char*current_drom=of_get_property(a->np,"apple,thunderbolt-drom",&current_length);
  if(!j314s_profile_valid()||current_length<0||
     !j314s_drom_root_uid(current_drom,current_length,j314s_node_index(c->np,0),stable)||
     memcmp(stable,o->root_uid,sizeof(stable)))ret=-ESTALE;
 }
 o->completed_ns=ktime_get_boottime_ns();
 if(jp_finish(&o->lease,ret,ktime_get_boottime_ns())&&!ret)ret=-ETIMEDOUT;
 o->status=ret;
 dev_info(a->dev,"j314s-peer-observation: status%d operations%u cable%#x write%u verified%u physical-lane%u unlock-write%u unlock-verified%u child-read%u usb4%u uid-read%u stable%u\n",
  ret,o->io.operations,o->cable,r->cable_write_attempted,r->cable_verified,
  r->lane,r->unlock_write_attempted,r->unlock_verified,r->child.header_read,r->child.usb4,r->child.uid_read,r->child.stable);
 for(i=1;i<=7;i++)if(r->phy_offsets[i])dev_info(a->dev,
  "j314s-peer-observation: lane%u raw-adapter %*phN phy-offset%u raw-phy %*phN\n",
  i,32,r->ports[i],r->phy_offsets[i],8,r->phy[i]);
 for(i=1;i<=2;i++)if(r->pair_header_read[i])dev_info(a->dev,
  "j314s-peer-observation: lane%u raw-adapter-before-unlock %*phN unlock-before%08x unlock-after%08x write%u verified%u\n",
  i,32,r->pair_before_unlock[i],r->pair_unlock_before[i],r->pair_unlock_after[i],r->pair_write_attempted[i],r->pair_unlock_verified[i]);
 dev_info(a->dev,"j314s-peer-observation: exact-DROM primary%u secondary%u logical-route%u physical-ready-lane%u\n",r->primary,r->secondary,r->child.route,r->lane);
 if(r->child.header_read)dev_info(a->dev,"j314s-peer-observation: raw header %*phN\n",20,r->child.child_header);
 if(r->child.uid_read)dev_info(a->dev,"j314s-peer-observation: raw uid %*phN\n",8,r->child.uid_words);
 dev_info(a->dev,"j314s-peer-observation: retained until reboot; no child configuration or PCIe tunnel\n");
 return ret;
}

/* Immutable software receipt. No current-task check and no hardware access. */
int apple_cio_j314s_peer_identity_state(unsigned controller,u32 *flags,int *status,
 struct j314s_peer_identity_report *report);
int apple_cio_j314s_peer_identity_state(unsigned controller,u32 *flags,int *status,
 struct j314s_peer_identity_report *report)
{
 struct apple_cio*c;struct j314s_peer_capture_owner*o;
 if(controller<1||controller>2||!flags||!status||!report)return -EINVAL;
 *flags=0;*status=-EINPROGRESS;memset(report,0,sizeof(*report));
 c=READ_ONCE(j314s_owned_cio[controller]);if(!c)return -ENODEV;
 if(!mutex_trylock(&c->lock))return -EAGAIN;
 o=&j314s_peer_owners[controller];
 if(o->consumed)*flags|=1;
 *status=o->status;
 if(!o->lease.complete||o->lease.failed||o->status||!o->anhi||o->anhi->acio!=c||
    j314s_node_index(c->np,0)!=(int)controller||!o->result.child.stable){
  mutex_unlock(&c->lock);return -EAGAIN;
 }
 *flags|=2;report->controller=controller;report->cable=o->cable;
 report->operations=o->io.operations;report->route=o->result.child.route;
 report->lane=o->result.lane;report->deadline=o->lease.deadline;
 report->completed_ns=o->completed_ns;memcpy(report->root_uid,o->root_uid,sizeof(report->root_uid));
 memcpy(report->header,o->result.child.child_header,sizeof(report->header));
 memcpy(report->uid,o->result.child.uid_words,sizeof(report->uid));
 mutex_unlock(&c->lock);return 0;
}
EXPORT_SYMBOL_GPL(apple_cio_j314s_peer_identity_state);
