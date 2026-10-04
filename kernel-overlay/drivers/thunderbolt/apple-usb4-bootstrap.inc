#include "usb4_bootstrap_core.h"
static atomic_t usb4_bootstrap_attempted[2] = { ATOMIC_INIT(0), ATOMIC_INIT(0) };
struct bootstrap_kernel {struct apple_nhi*anhi;u64 deadline;struct bootstrap_io*io;};
static bool bootstrap_kernel_valid(void*p)
{struct bootstrap_kernel*c=p;return route1_header_config&&route1_inventory&&route1_usb4_ready&&apple_unlock_context(c->anhi);}
static u64 bootstrap_kernel_now(void*p){(void)p;return ktime_get_boottime_ns();}
static void bootstrap_kernel_sleep(void*p,bool shortpoll){(void)p;(void)shortpoll;usleep_range(1000,2000);}
static int bootstrap_kernel_read(void*p,unsigned r,unsigned port,bool sw,unsigned off,unsigned n,u32*v)
{
 struct bootstrap_kernel*c=p;
 if(!bootstrap_kernel_valid(p)||ktime_get_boottime_ns()>=c->deadline||r>1||!n||n>5||off>8192-n||
    (sw?port!=0:(r!=0||(port!=1&&port!=3))))return -EPERM;
 return tb_cfg_read(c->anhi->tb->ctl,v,r,port,sw?TB_CFG_SWITCH:TB_CFG_PORT,off,n);
}
static int bootstrap_kernel_write(void*p,unsigned r,unsigned port,bool sw,unsigned off,unsigned n,const u32*v)
{
 struct bootstrap_kernel*c=p;struct ready_io*i=&c->io->io;
 if(!bootstrap_kernel_valid(p)||ktime_get_boottime_ns()>=c->deadline||!sw||port||!n||off>8192-n||
    !((r==0&&n==1&&(off==i->rt||off==i->rt+3))||(r==1&&((off==1&&n==4)||(off==5&&n==1)))))return -EPERM;
 return tb_cfg_write(c->anhi->tb->ctl,v,r,0,TB_CFG_SWITCH,off,n);
}
static int apple_usb4_bootstrap_after_identity(struct apple_nhi*anhi)
{
 struct bootstrap_kernel c={.anhi=anhi,.deadline=ktime_get_boottime_ns()+20ULL*NSEC_PER_SEC};
 struct bootstrap_io b={.expected_uid=bob_router_uid(bob_controller_index(anhi->np),0),.io={.read=bootstrap_kernel_read,.write=bootstrap_kernel_write,.valid=bootstrap_kernel_valid,.now=bootstrap_kernel_now,.sleep=bootstrap_kernel_sleep,.ctx=&c,.deadline=c.deadline}};
 int ret;c.io=&b;
 lockdep_assert_held(&anhi->acio->lock);lockdep_assert_held(&anhi->tb->lock);
 if(bob_attempt_once(usb4_bootstrap_attempted, anhi->np))return -EALREADY;
 if(!bootstrap_kernel_valid(&c))return -EPERM;
 ret=bootstrap_once(&b);
 if(b.header_done){
  dev_info(anhi->dev,"child-header-config: status 0 operations 5; retained, no tunnel permit\n");
  dev_info(anhi->dev,"child-header-config: exact route1 depth1 enabled CMUV20 readback verified; header stage wrote no CS5/tunnel registers\n");
 }
 dev_info(anhi->dev,"usb4-bootstrap: status %d operations %u; retained, root PE containment required\n",ret,b.io.ops);
 if(!ret)dev_info(anhi->dev,"usb4-bootstrap: route1 configured and RR verified before adapter inventory; root PE clear, no PE/Hop writes\n");
 return ret;
}
