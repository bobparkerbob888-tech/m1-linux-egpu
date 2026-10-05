/* Direct synchronous continuation of successful child header configuration.
 * All mutable owners remain retained by the parent on any terminal result.
 */
#include "usb4_readiness_core.h"
static int apple_external_claim(struct apple_nhi *, const struct bob_inv_result *, const struct ready_io *);
static int apple_chain_prepare(struct apple_nhi *, const struct bob_inv_result *, const struct ready_io *);
static bool route1_usb4_ready;
module_param(route1_usb4_ready,bool,0444);
MODULE_PARM_DESC(route1_usb4_ready,"One bounded USB4 route1 setup/TMU/CV transaction; PCIe adapters remain disabled");
static atomic_t usb4_ready_attempted[2] = { ATOMIC_INIT(0), ATOMIC_INIT(0) };
struct ready_kernel_context {struct child_kernel_context child;struct ready_io *io;};
static bool ready_kernel_valid(void *p)
{struct ready_kernel_context*c=p;return route1_usb4_ready&&child_kernel_valid(&c->child);}
static u64 ready_kernel_now(void *p)
{(void)p;return ktime_get_boottime_ns();}
static void ready_kernel_sleep(void *p,bool shortpoll)
{(void)p;if(shortpoll)usleep_range(5,10);else usleep_range(1000,2000);}
static int ready_kernel_read(void*p,unsigned route,unsigned port,bool sw,unsigned off,unsigned n,u32*v)
{
 struct ready_kernel_context*c=p;
 if(!ready_kernel_valid(p)||child_kernel_expired(&c->child)||route>1||!n||n>5||off>8192-n||
    (sw?port!=0:!(port==1||(!route&&port==3)||(route&&port==c->child.inventory->pci_up))))return -EPERM;
 return tb_cfg_read(c->child.anhi->tb->ctl,v,route,port,sw?TB_CFG_SWITCH:TB_CFG_PORT,off,n);
}
static int ready_kernel_write(void*p,unsigned route,unsigned port,bool sw,unsigned off,unsigned n,const u32*v)
{
 struct ready_kernel_context*c=p;
 if(!ready_kernel_valid(p)||child_kernel_expired(&c->child)||route>1||!n||n>5||off>8192-n||
    !ready_write_allowed(c->io,route,port,sw,off,n))return -EPERM;
 return tb_cfg_write(c->child.anhi->tb->ctl,v,route,port,sw?TB_CFG_SWITCH:TB_CFG_PORT,off,n);
}
static int apple_usb4_ready_after_child_config(struct apple_nhi*anhi,const struct bob_inv_result*inventory)
{
 struct ready_kernel_context c={.child={anhi,inventory,ktime_get_boottime_ns()+20ULL*NSEC_PER_SEC}};
 struct ready_io io={.read=ready_kernel_read,.write=ready_kernel_write,.valid=ready_kernel_valid,
  .now=ready_kernel_now,.sleep=ready_kernel_sleep,.ctx=&c,.deadline=c.child.deadline,.up=inventory->pci_up};
 int ret;
 lockdep_assert_held(&anhi->acio->lock);lockdep_assert_held(&anhi->tb->lock);
 if(!route1_usb4_ready)return 0;
 if(bob_attempt_once(usb4_ready_attempted, anhi->np))return -EALREADY;
 c.io=&io;
 if(!ready_kernel_valid(&c))return -EPERM;
 ret=ready_once(&io);
 dev_info(anhi->dev,"usb4-readiness: preflight valid %08x PHY %08x/%08x USB4 %08x TMU %08x/%08x rate %08x/%08x EUDM %08x UDM %08x/%08x DTS %08x/%08x CS5 %08x CS6 %08x; observations only\n",
  io.observed_valid,io.observed[0],io.observed[1],io.observed[2],io.observed[3],io.observed[4],io.observed[5],io.observed[6],io.observed[7],io.observed[8],io.observed[9],io.observed[10],io.observed[11],io.observed[12],io.observed[13]);
 dev_info(anhi->dev,"usb4-readiness: status %d phase %d operations %u; retained, PCIe adapters disabled\n",ret,io.phase,io.ops);
 if(!ret)dev_info(anhi->dev,"usb4-readiness: route1 RR TMU-HiFiBi CV CR verified; PE clear, no Hop/tunnel writes\n");
 if (!ret) ret=apple_chain_prepare(anhi,inventory,&io);
 if (!ret) ret=apple_external_claim(anhi,inventory,&io);
 return ret;
}
