/* Invoked only after retained worker phase6; default-off, no generic CM. */
#include "pcie_tunnel_core.h"
#include "apple-retained-pcie-api.h"
extern int apple_apciec_controller_index(struct device *);
extern int apple_apciec_retained_transit_audit(struct device *,unsigned,const void *);
extern int apple_apciec_retained_identify_transit_target(struct device *,unsigned,const void *,u64,unsigned *);
static bool apple_pt_valid(void *arg)
{
 struct external_ticket*t=arg;
 return route1_pcie_tunnel&&t->steps.phase==6&&t->node_phase==2&&
 t->tunnel&&external_context(t);
}
static int apple_pt_read(void*arg,unsigned r,unsigned p,unsigned space,unsigned off,unsigned n,u32*v)
{
 struct external_ticket*t=arg;
 if(!apple_pt_valid(t)||r>1||!n||n>8||off>8192-n||space>PT_HOPS||
  (space==PT_SW?p!=0:(!p||p>63)))return -EPERM;
 return tb_cfg_read(t->tb->ctl,v,r,p,space==PT_SW?TB_CFG_SWITCH:space==PT_PORT?TB_CFG_PORT:TB_CFG_HOPS,off,n);
}
static int apple_pt_write(void*arg,unsigned r,unsigned p,unsigned space,unsigned off,unsigned n,const u32*v)
{
 struct external_ticket*t=arg;
 if(!apple_pt_valid(t)||r>1||!n||n>8||off>8192-n||
 !pt_write_allowed(t->tunnel,r,p,space,off,n,v))return -EPERM;
 return tb_cfg_write(t->tb->ctl,v,r,p,space==PT_SW?TB_CFG_SWITCH:space==PT_PORT?TB_CFG_PORT:TB_CFG_HOPS,off,n);
}
static void apple_pt_sleep(void*unused){usleep_range(50,100);}
static int apple_pt_proof(void*arg,unsigned pe)
{
 struct external_ticket*t=arg;
 if(!apple_pt_valid(t)||pe!=t->tunnel->pe)return -EPERM;
 return external_proof_locked_state(t,pe);
}
static int apple_pt_audit(void*arg)
{
 struct external_ticket*t=arg;
 lockdep_assert_held(&t->acio->lock);lockdep_assert_held(&t->tb->lock);
 if(!apple_pt_valid(t))return -EPERM;
 return apple_apciec_retained_prepared_audit(t->host,3,t);
}
static int apple_pt_commit(void*arg)
{
 struct external_ticket*t=arg;int ret;
 if(t->tunnel->phase!=4||t->tunnel->pe!=3||t->tunnel->programmed!=4)return -EPERM;
 ret=apple_pt_proof(t,3);if(ret)return ret;
 ret=pt_verify(t->tunnel);if(ret)return ret;
 return apple_apciec_retained_commit(t->host,3,t);
}
static int apple_retained_pcie_tunnel(struct external_ticket*t)
{
 int ret,post,host_audit;
 /* The claim/lifetime already owns t and providers. Retain this allocation on
  * every result, including failures before a Hop or PE write. */
 if(t->availability_probe||t->prepare_only||!route1_pcie_tunnel||t->tunnel||t->steps.phase!=6)return -EPERM;
 t->tunnel=kzalloc(sizeof(*t->tunnel),GFP_KERNEL);if(!t->tunnel)return -ENOMEM;
 *t->tunnel=(struct pt_state){.read=apple_pt_read,.write=apple_pt_write,
 .valid=apple_pt_valid,.now=external_clock,.sleep=apple_pt_sleep,
 .proof=apple_pt_proof,.audit=apple_pt_audit,.commit=apple_pt_commit,.ctx=t,
 .deadline=t->deadline,.phy={t->geometry.rphy,t->geometry.cphy},
 .pcie={t->geometry.rpcie,t->geometry.cpcie},.disabled={0,t->inventory.disabled_ports}};
 mutex_lock(&t->acio->lock);mutex_lock(&t->tb->lock);
 if(t->raw_identity){
  ret=external_proof_locked(t);
  if(!ret)ret=apple_apciec_retained_root_rc_prepare(t->host,3,t);
  post=external_proof_locked(t);
  dev_info(t->anhi->dev,"retained-raw-identity: root RC status %d post-context/PE proof %d\n",ret,post);
  if(!ret)ret=post;
 }else ret=0;
 if(!ret)ret=pt_once(t->tunnel);
 mutex_unlock(&t->tb->lock);mutex_unlock(&t->acio->lock);
 if(ret)goto post_result;
 /* Raw configuration runs outside parent locks. No PCI registration/notifiers. */
 ret=external_outside_gate(t);if(ret)goto post_result;
 if(t->controller){
  if(apple_apciec_controller_index(t->host)!=1){ret=-EPERM;goto post_result;}
  /* Do not enter the legacy RID300 scan. Both tunnels must exist first. */
  ret=apple_apciec_retained_transit_audit(t->host,3,t);
  if(!ret)t->endpoint_phase=8;
 }else ret=apple_apciec_retained_scan_quarantined(t->host,3,t);
 post_result:
 if(ret&&!t->raw_identity)return ret;
 host_audit=0;
 if(t->raw_identity){
  host_audit=external_outside_gate(t);
  if(!host_audit)host_audit=t->controller?apple_apciec_retained_transit_audit(t->host,3,t):apple_apciec_retained_raw_final_audit(t->host,3,t);
 }

 mutex_lock(&t->acio->lock);mutex_lock(&t->tb->lock);
 post=pt_gate(t->tunnel);
 if(!post)post=apple_pt_proof(t,t->tunnel->pe);
 if(!post&&t->tunnel->programmed==4)post=pt_verify(t->tunnel);
 if(!ret)ret=post;
 if(!ret)ret=host_audit;
 if(!ret)t->tunnel->phase=6;
 if(t->raw_identity)dev_info(t->anhi->dev,"retained-raw-identity: post-transaction status %d context/PE proof %d host audit %d PE attempted %u observed-expected %u\n",ret,post,host_audit,t->tunnel->pe_attempted,t->tunnel->pe);
 dev_info(t->anhi->dev,"retained-pcie: plan down %u up %u credits %u/%u operations %u PE %u; no DMA mappings\n",
 t->tunnel->plan[0].next,t->tunnel->plan[2].next,t->tunnel->credits[0],t->tunnel->credits[1],t->tunnel->ops,t->tunnel->pe);
 mutex_unlock(&t->tb->lock);mutex_unlock(&t->acio->lock);
 return ret;
}
