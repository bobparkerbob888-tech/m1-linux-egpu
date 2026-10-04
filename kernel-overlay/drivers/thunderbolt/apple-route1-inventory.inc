/* Include after USB4 identity. Read-only inventory; no topology registration. */
#include "bob-route1-inventory-core.h"
static bool route1_inventory;
module_param(route1_inventory,bool,0444);
static atomic_t route1_inventory_attempted[2] = { ATOMIC_INIT(0), ATOMIC_INIT(0) };
struct inv_context {struct apple_nhi *anhi;u64 deadline;};
static bool inv_expired(void *p){struct inv_context*c=p;return ktime_get_boottime_ns()>=c->deadline;}
static bool inv_valid(void *p){struct inv_context*c=p;return apple_unlock_context(c->anhi);}
static int inv_read(void*p,unsigned route,unsigned port,bool sw,unsigned off,unsigned n,u32*v)
{struct inv_context*c=p;return tb_cfg_read(c->anhi->tb->ctl,v,route,port,sw?TB_CFG_SWITCH:TB_CFG_PORT,off,n);}
 #include "apple-child-config.inc"
/* Only direct caller is immediately after apple_usb4_identity returns0.
 * No log/state-file is a permit; both locks span identity and this call. */
static int apple_route1_inventory_after_identity(struct apple_nhi *anhi,u64 disabled_ports)
{
 struct inv_context c={anhi,ktime_get_boottime_ns()+15ULL*NSEC_PER_SEC};
 struct bob_inv_io io={.read=inv_read,.expired=inv_expired,.valid=inv_valid,.ctx=&c};
 struct bob_inv_result *r;int ret;unsigned p,i;
 lockdep_assert_held(&anhi->acio->lock);lockdep_assert_held(&anhi->tb->lock);
 if(!route1_inventory)return 0;
 if(bob_attempt_once(route1_inventory_attempted, anhi->np))return -EALREADY;
 if(!inv_valid(&c))return -EPERM;
 r=kzalloc(sizeof(*r),GFP_KERNEL);if(!r)return -ENOMEM;
 r->disabled_ports=disabled_ports;
 ret=bob_inv_collect(&io,r);
 /* Already-captured partial diagnostics are never validated identity proof. */
 for(p=1;p<=r->max_port && p<=23;p++){
  if(r->child_read[p])dev_info(anhi->dev,"route1-inventory: unvalidated port%u header %*phN\n",p,32,r->child_ports[p]);
  else if(r->child_status[p])dev_info(anhi->dev,"route1-inventory: unvalidated port%u read status %d\n",p,r->child_status[p]);
 }
 if(!ret){
  dev_info(anhi->dev,"route1-inventory: validated root lane1 PCIeDOWN3 child upstream1 PCIeUP%u; no tunnel permit\n",r->pci_up);
  for(p=0;p<4;p++)for(i=0;i<r->selected[p].count;i++)dev_info(anhi->dev,"route1-inventory: route%u port%u cap%u %08x %08x\n",r->selected[p].route,r->selected[p].port,r->selected[p].caps[i].offset,r->selected[p].caps[i].words[0],r->selected[p].caps[i].words[1]);
 }
 dev_info(anhi->dev,"route1-inventory: status %d operations %u; read-only, retained, no tunnel permit\n",ret,io.operations);
 if(!ret)ret=apple_child_config_after_inventory(anhi,r);
 kfree(r);return ret;
}
