/* SPDX-License-Identifier: GPL-2.0 */
/* Read-only route0 configuration inventory; never applies J293 header writes.
 * NHI caller pins control DMA/power on every outcome. No downstream scan. */
#include "apple-j314s-profile.h"
#include "j314s-boot-admission.h"
#include "j314s-root-header.inc"
static atomic_t j314s_root_inventory_attempt[3] = {ATOMIC_INIT(0),ATOMIC_INIT(0),ATOMIC_INIT(0)};
int tb_j314s_root_inventory_only(struct tb *tb);
int tb_j314s_root_inventory_only(struct tb *tb)
{
 struct tb_cm *tcm=tb_priv(tb);struct tb_switch *sw;struct tb_port *port;
 struct tb_regs_switch_header header;
 unsigned i;int ret=-EPERM,index=j314s_node_index(tb->nhi->dev->of_node,1);
 if(index<0||!j314s_boot_controller_admitted(saved_command_line,index)||!of_machine_is_compatible("apple,j314s")||!tb->nhi->ops||
    !tb->nhi->ops->root_router_only||atomic_cmpxchg(&j314s_root_inventory_attempt[index],0,1)||
    !j314s_profile_valid())return -EPERM;
 for(i=3;i<5;i++) {
  struct device_node *n=of_find_node_by_path(j314s_paths[index][i]);
  struct platform_device *p;const char *status;bool ok;
  if(!n)return -EPERM;
  ok=!of_property_read_string(n,"status",&status)&&!strcmp(status,"disabled")&&
   !of_node_check_flag(n,OF_POPULATED)&&!of_node_check_flag(n,OF_POPULATED_BUS);
  p=of_find_device_by_node(n);if(p){ok=false;put_device(&p->dev);}
  of_node_put(n);if(!ok)return -EPERM;
 }
 mutex_lock(&tb->lock);tcm->hotplug_active=false;tb_ctl_start(tb->ctl);
 sw=tb_switch_alloc(tb,&tb->dev,0);
 if(IS_ERR(sw)){ret=PTR_ERR(sw);goto out;}
 tb->root_switch=sw;
 ret=tb_sw_read(sw,&header,TB_CFG_SWITCH,0,5);if(ret)goto out;
 dev_info(tb->nhi->dev,"j314s-route0-inventory: initial raw header %*phN; vendor%04x device%04x maxport%u upstream%u enabled%u; before reviewed configuration\n",
  (int)sizeof(header),&header,header.vendor_id,header.device_id,header.max_port_number,header.upstream_port_number,header.enabled);
 if(header.depth||header.route_lo||header.route_hi||!header.max_port_number||
    header.max_port_number>63||header.max_port_number!=sw->config.max_port_number){ret=-EPERM;goto out;}
 ret=j314s_root_header_configure(tb,sw,&header);if(ret)goto out;
 tb_switch_for_each_port(sw,port) {
  ret=tb_port_read(port,&port->config,TB_CFG_PORT,0,sizeof(port->config)/sizeof(u32));
  if(ret)goto out;
  dev_info(tb->nhi->dev,"j314s-route0-inventory: port%u type%#x; identity only, no enable\n",port->port,port->config.type);
 }
 dev_info(tb->nhi->dev,"j314s-route0-inventory: complete; downstream identity and PCIe tunnels still unadmitted\n");
out:mutex_unlock(&tb->lock);return ret;
}
EXPORT_SYMBOL_FOR_MODULES(tb_j314s_root_inventory_only,"thunderbolt_apple");
