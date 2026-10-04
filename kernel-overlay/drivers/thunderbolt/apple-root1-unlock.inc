/* SPDX-License-Identifier: GPL-2.0 */
static bool root_port1_unlock;
module_param(root_port1_unlock, bool, 0444);
MODULE_PARM_DESC(root_port1_unlock,"Research only: guarded root port1 config-access unlock after PHY UP; no PCIe permit");
static atomic_t apple_root1_unlock_attempted[2] = { ATOMIC_INIT(0), ATOMIC_INIT(0) };
#include "apple-root1-unlock-core.h"
static bool apple_unlock_context(void *context)
{
 struct apple_nhi *anhi=context;
 struct apple_cio *acio=anhi->acio;
 struct device_node *node;
 bool same;
 if(!root_port1_unlock || !root_router_only || !root_cable_only ||
    !attached_router_identity || !of_machine_is_compatible("apple,j293") ||
    !anhi->tb || !anhi->tb->root_switch || tb_route(anhi->tb->root_switch) ||
    !acio->root_dma_retained || acio->root_probe_status ||
    READ_ONCE(acio->root_stopping) || acio->current_cable_info ||
    !smp_load_acquire(&acio->root_cable_snapshot_valid) ||
    !READ_ONCE(acio->root_cable_snapshot) ||
    READ_ONCE(acio->root_cable_snapshot)!=READ_ONCE(acio->target_cable_info) ||
    !bob_identity_external_disabled(anhi->np)) return false;
 int controller=bob_controller_index(anhi->np);
 if(controller<0)return false;
 node=of_find_node_by_path(bob_controller_paths[controller][5]);
 same=node && node==anhi->np;
 of_node_put(node);
 return same;
}
static int apple_unlock_read(void *context,bool sw,unsigned int off,unsigned int count,u32 *words)
{
 struct apple_nhi *anhi=context;
 if(!count || count>8 || off>255 || off+count>257) return -EINVAL;
 return tb_cfg_read(anhi->tb->ctl,words,0,sw?0:1,sw?TB_CFG_SWITCH:TB_CFG_PORT,off,count);
}
static int apple_unlock_write(void *context,unsigned int off,u32 word)
{
 struct apple_nhi *anhi=context;
 if(off!=4 || !apple_unlock_context(anhi)) return -EPERM;
 return tb_cfg_write(anhi->tb->ctl,&word,0,1,TB_CFG_PORT,4,1);
}
static int apple_root1_unlock(struct apple_nhi *anhi)
{
 struct apple_unlock_io io={apple_unlock_read,apple_unlock_write,apple_unlock_context,anhi};
 u32 expected[5],before=0,after=0;
 int ret;
 if(!root_port1_unlock) return 0;
 lockdep_assert_held(&anhi->acio->lock);
 lockdep_assert_held(&anhi->tb->lock);
 if(bob_attempt_once(apple_root1_unlock_attempted, anhi->np)) return -EALREADY;
 if(!apple_unlock_context(anhi)) return -EPERM;
 memcpy(expected,&anhi->tb->root_switch->config,sizeof(expected));
 ret=apple_unlock_once(&io,expected,&before,&after);
 dev_info(anhi->dev,"root1-unlock: status %d before %08x after %08x; retained, no tunnel permit\n",ret,before,after);
 if(!ret) dev_info(anhi->dev,"root1-unlock: port1 config access readback verified; no scan/tunnel\n");
 return ret;
}
