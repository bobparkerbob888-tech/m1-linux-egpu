/* Include only after inventory types, under existing retained root ownership. */
#include "child_config_core.h"
static bool route1_header_config;
module_param(route1_header_config,bool,0444);
MODULE_PARM_DESC(route1_header_config,"Exact USB4 route1 CS1..4 upload after same-call identity and before inventory; no tunnel permit");
static atomic_t child_config_attempted[2] = { ATOMIC_INIT(0), ATOMIC_INIT(0) };
struct child_kernel_context {struct apple_nhi *anhi;const struct bob_inv_result *inventory;u64 deadline;};
static bool child_inventory_valid(const struct bob_inv_result *r)
{
 static const u32 expected[5]={0x57868087,0x8515c16b,1,0x80000000,0x400020ff};
 unsigned i;
 if(!r||memcmp(r->child_header,expected,sizeof(expected))||r->max_port!=23||r->upstream!=1||r->pci_up<2||r->pci_up>23)return false;
 if(!r->child_read[1]||!r->child_read[r->pci_up]||r->child_status[1]||r->child_status[r->pci_up])return false;
 for(i=0;i<4;i++){
  const struct bob_inv_port *p=&r->selected[i];
  unsigned route=i<2?0:1,port=i==0||i==2?1:i==1?3:r->pci_up;
  unsigned type=i==0||i==2?1:i==1?0x100101:0x100102;
  if(p->route!=route||p->port!=port||!p->count||p->count>64||(p->header[2]&0xffffff)!=type||((p->header[3]>>20)&63)!=port)return false;
 }
 return !memcmp(r->selected[2].header,r->child_ports[1],32)&&!memcmp(r->selected[3].header,r->child_ports[r->pci_up],32);
}
static bool child_kernel_valid(void *p)
{struct child_kernel_context*c=p;return route1_header_config&&route1_inventory&&apple_unlock_context(c->anhi)&&child_inventory_valid(c->inventory);}
static bool child_kernel_expired(void *p)
{struct child_kernel_context*c=p;return ktime_get_boottime_ns()>=c->deadline;}
static int child_kernel_read(void*p,unsigned off,unsigned n,u32*v)
{struct child_kernel_context*c=p;if(!((off==0&&n==5)||(off==7&&n==2)||(off==5&&n==2))||!child_kernel_valid(p)||child_kernel_expired(p))return -EPERM;return tb_cfg_read(c->anhi->tb->ctl,v,1,0,TB_CFG_SWITCH,off,n);}
#include "apple-usb4-readiness.inc"
/* Read-only verification ONLY after successful post-bootstrap bob_inv_collect,
 * itself reached after USB4 CRC identity and native configure/setup/RR.
 * Inventory storage remains owned and immutable until this returns. */
static int apple_child_config_after_inventory(struct apple_nhi *anhi,const struct bob_inv_result *inventory)
{
 struct child_kernel_context c={anhi,inventory,ktime_get_boottime_ns()+5ULL*NSEC_PER_SEC};
 struct child_cfg_io io={.read=child_kernel_read,.valid=child_kernel_valid,.expired=child_kernel_expired,.ctx=&c};
 const u32 expected[5]={0x57868087,0x8515c16b,1,0x80000000,0x400020ff};
 u32 after[5]={0},uid[2];int ret;
 u64 target=bob_router_uid(bob_controller_index(anhi->np),0);
 lockdep_assert_held(&anhi->acio->lock);lockdep_assert_held(&anhi->tb->lock);
 if(!route1_header_config)return 0;
 if(bob_attempt_once(child_config_attempted, anhi->np))return -EALREADY;
 if(!child_kernel_valid(&c))return -EPERM;
 ret=child_cfg_read(&io,0,5,after);
 if(!ret&&memcmp(after,expected,sizeof(expected)))ret=-ESTALE;
 if(!ret)ret=child_cfg_read(&io,7,2,uid);
 if(!ret&&(uid[0]!=(u32)(target>>32)||uid[1]!=(u32)target))ret=-ESTALE;
 if(!ret){
  u32 observation[2];
  ret=child_cfg_gate(&io);
  if(!ret)ret=child_kernel_read(&c,5,2,observation);
  if(!ret&&child_kernel_expired(&c))ret=-ETIMEDOUT;
  if(!ret&&!child_kernel_valid(&c))ret=-EPERM;
  if(!ret)dev_info(anhi->dev,"child-header-config: unvalidated CS5 %08x CS6 %08x; read-only observation\n",observation[0],observation[1]);
 }
 dev_info(anhi->dev,"child-header-verify: status %d operations %u; read-only after inventory\n",ret,io.operations);
 if(!ret)dev_info(anhi->dev,"child-header-verify: configured route1 header and UID verified; read-only\n");
 if(!ret)ret=apple_usb4_ready_after_child_config(anhi,inventory);
 return ret;
}
