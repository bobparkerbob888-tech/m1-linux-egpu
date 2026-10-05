/* Include AFTER apple-root1-unlock.inc. Exact observed r14 route1 header; no router configuration. */
#include "usb4_identity_core.h"
#include "apple-usb4-bootstrap.inc"
static const u32 uid_expected_header[5]={0x57868087,0x8505c16b,0,0,0x4000000a};
static atomic_t uid_usb4_attempted[2] = { ATOMIC_INIT(0), ATOMIC_INIT(0) };
struct uid_kernel_context {struct apple_nhi *anhi;u64 deadline;};
static u64 uid_kernel_clock(void *p){return ktime_get_boottime_ns();}
static bool uid_kernel_expired(void *p)
{struct uid_kernel_context *c=p;return ktime_get_boottime_ns()>=c->deadline;}
static bool uid_kernel_valid(void *p)
{struct uid_kernel_context *c=p;return apple_unlock_context(c->anhi);}
static void uid_kernel_delay(void *p){usleep_range(1000,1500);}
static bool uid_kernel_protocol(void *p,const u32 *h)
{
 return !memcmp(h,uid_expected_header,sizeof(uid_expected_header));
}
static int uid_kernel_read(void *p,unsigned off,unsigned n,u32 *v)
{struct uid_kernel_context *c=p;return tb_cfg_read(c->anhi->tb->ctl,v,1,0,TB_CFG_SWITCH,off,n);}
static int uid_kernel_write(void *p,unsigned off,u32 v)
{struct uid_kernel_context *c=p;if(!uid_kernel_valid(p))return -EPERM;
 if(off!=25&&off!=26)return -EPERM;
 return tb_cfg_write(c->anhi->tb->ctl,&v,1,0,TB_CFG_SWITCH,off,1);}
/* Parent calls only AFTER successful root1 unlock/readback, under BOTH locks.
 * Existing TB3 reader remains untouched. Dispatch policy waits for actual header.
 */
static int apple_usb4_identity(struct apple_nhi *anhi,u64 *disabled_ports)
{
 struct uid_kernel_context c={anhi,ktime_get_boottime_ns()+60ULL*NSEC_PER_SEC};
 struct uid_io io={.read=uid_kernel_read,.write=uid_kernel_write,
 .valid=uid_kernel_valid,.expired=uid_kernel_expired,.ctx=&c,
 .expected_uid=bob_router_uid(bob_controller_index(anhi->np),0),
 .now_ns=uid_kernel_clock,.protocol=uid_kernel_protocol,.poll_delay=uid_kernel_delay};
 u8 *drom;unsigned size=0;int ret;
 lockdep_assert_held(&anhi->acio->lock);lockdep_assert_held(&anhi->tb->lock);
 if(bob_attempt_once(uid_usb4_attempted, anhi->np))return -EALREADY;
 if(!uid_kernel_valid(&c))return -EPERM;
 drom=kzalloc(1036,GFP_KERNEL);if(!drom)return -ENOMEM;
 ret=uid_identity(&io,uid_expected_header,drom,&size);
 if(!ret)ret=bootstrap_disabled_ports(drom,size,disabled_ports);
 dev_info(anhi->dev,"usb4-identity: terminal status %d bytes %u operations %u; retained, no tunnel permit\n",ret,size,io.operations);
 if(!ret)dev_info(anhi->dev,"usb4-identity: UID %016llx DROM 0414:7a63 CRC32C verified; identity only\n",(unsigned long long)io.expected_uid);
 if(ret && size)dev_info(anhi->dev,"usb4-identity: rejected DROM %*phN\n",size,drom);
 kfree(drom);return ret;
}

/* Preserve existing TB3 reader; no TB3 bitbang fallback for USB4 headers. */
static int apple_attached_identity_dispatch(struct apple_nhi *anhi)
{
 u32 header[5];int ret;u64 disabled_ports=0;
 lockdep_assert_held(&anhi->acio->lock);lockdep_assert_held(&anhi->tb->lock);
 if(!attached_router_identity)return 0;
 if(!apple_unlock_context(anhi))return -EPERM;
 ret=tb_cfg_read(anhi->tb->ctl,header,1,0,TB_CFG_SWITCH,0,5);
 if(ret)return ret;
 if((header[4]>>29)!=0){
  ret=apple_usb4_identity(anhi,&disabled_ports);
  if(!ret&&route1_inventory)ret=apple_usb4_bootstrap_after_identity(anhi);
  if(!ret)ret=apple_route1_inventory_after_identity(anhi,disabled_ports);
  return ret;
 }
 if(bob_controller_index(anhi->np)!=0)return -EOPNOTSUPP;
 return bob_attached_identity(anhi->tb);
}
