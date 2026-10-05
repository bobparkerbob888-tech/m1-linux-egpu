/* SPDX-License-Identifier: GPL-2.0 */
/* First J314s target trial: route0 reads only, no inherited child identity. */
static DEFINE_MUTEX(j314s_arm_lock);
static bool j314s_arm_consumed[3], j314s_arm_committed[3];
static bool j314s_probe_seen[3][2];
static atomic_t j314s_power_attempt[3] = {ATOMIC_INIT(0),ATOMIC_INIT(0),ATOMIC_INIT(0)};
static struct apple_cio *j314s_owned_cio[3];

static bool j314s_inventory_options(void)
{
 return !root_cable_only && !attached_router_identity && !root_port1_unlock &&
  !route1_inventory && !route1_header_config && !route1_usb4_ready &&
  !route_chain_prepare && !external_host_prepare && !route1_pcie_tunnel &&
  !external_endpoint_resources && !external_endpoint_memory_assign;
}
#include "j314s-peer-boot.h"
#include "j314s-boot-admission.h"
static bool j314s_boot_valid(void)
{return !!j314s_boot_admission_mask(saved_command_line);}
static bool j314s_chosen_valid(void)
{
 struct device_node *node=of_find_node_by_path("/chosen");
 const char *s;bool okay=false;
 if(node)okay=!of_property_read_string(node,"asahi,os-fw-version",&s)&&!strcmp(s,"13.5")&&
  !of_property_read_string(node,"bob,j314s-efi-overlay",&s)&&!strcmp(s,j314s_combined_boot_mask(saved_command_line)?"disabled-all9":j314s_peer_boot_controller(saved_command_line)?"disabled-peer-identity":"disabled-r22");
 of_node_put(node);return okay;
}
int apple_cio_arm_j314s_root_trial_port(unsigned controller);
int apple_cio_arm_j314s_root_trial_port(unsigned controller)
{
 unsigned i;int ret=-EPERM;
 if(controller>=3)return -EINVAL;
 if(j314s_combined_boot_mask(saved_command_line))return -EPERM;
 mutex_lock(&j314s_arm_lock);
 if(j314s_arm_consumed[controller])goto out;
 j314s_arm_consumed[controller]=true;
 /* Profiles cover three controllers; first unmeasured target trial owns only0.
  * Admission of1/2 needs a separate reviewed retained-peer transition. */
 if(controller!=j314s_peer_boot_controller(saved_command_line)||READ_ONCE(root_router_only)||j314s_probe_seen[controller][0]||
    j314s_probe_seen[controller][1]||atomic_read(&j314s_power_attempt[controller])||
    !j314s_boot_valid()||!j314s_chosen_valid()||!j314s_inventory_options()||
    !j314s_profile_valid())goto out;
 for(i=0;i<ARRAY_SIZE(j314s_disabled_devices);i++) {
  struct device_node *node=of_find_node_by_path(j314s_disabled_devices[i]);
  struct platform_device *pdev;
  const char *status;bool okay;
  if(!node)goto out;
  okay=!of_property_read_string(node,"status",&status)&&!strcmp(status,"disabled")&&
   !of_node_check_flag(node,OF_POPULATED)&&!of_node_check_flag(node,OF_POPULATED_BUS);
  pdev=of_find_device_by_node(node);
  if(pdev){okay=false;put_device(&pdev->dev);}
  of_node_put(node);if(!okay)goto out;
 }
 WRITE_ONCE(root_router_only,true);j314s_arm_committed[controller]=true;ret=0;
out:
 mutex_unlock(&j314s_arm_lock);
 pr_info("j314s-late-arm: controller%u result%d; software-only inventory admission\n",controller,ret);
 return ret;
}
EXPORT_SYMBOL_GPL(apple_cio_arm_j314s_root_trial_port);
static bool j314s_combined_pristine(void*unused)
{
 unsigned i;
 if(READ_ONCE(root_router_only)||!j314s_combined_boot_mask(saved_command_line)||
    !j314s_chosen_valid()||!j314s_inventory_options()||!j314s_profile_valid())return false;
 for(i=0;i<ARRAY_SIZE(j314s_disabled_devices);i++) {
  struct device_node*n=of_find_node_by_path(j314s_disabled_devices[i]);
  struct platform_device*p;const char*status;bool ok;
  if(!n)return false;
  ok=!of_property_read_string(n,"status",&status)&&!strcmp(status,"disabled")&&
   !of_node_check_flag(n,OF_POPULATED)&&!of_node_check_flag(n,OF_POPULATED_BUS);
  p=of_find_device_by_node(n);if(p){ok=false;put_device(&p->dev);}of_node_put(n);
  if(!ok)return false;
 }
 return true;
}
static bool j314s_combined_slot_pristine(void*unused,unsigned i)
{return i<3&&!j314s_arm_committed[i]&&!j314s_probe_seen[i][0]&&!j314s_probe_seen[i][1]&&
 !atomic_read(&j314s_power_attempt[i])&&!READ_ONCE(j314s_owned_cio[i]);}
#include "j314s-combined-arm-core.h"
static struct j314s_combined_arm_io j314s_combined_arm={
 .pristine=j314s_combined_pristine,.slot_pristine=j314s_combined_slot_pristine};
int apple_cio_arm_j314s_root_trial_mask(unsigned mask);
int apple_cio_arm_j314s_root_trial_mask(unsigned mask)
{
 int ret=-EPERM;unsigned i;
 mutex_lock(&j314s_arm_lock);
 if(!mask||mask!=j314s_combined_boot_mask(saved_command_line))goto out;
 for(i=0;i<3;i++)if(j314s_arm_consumed[i])j314s_combined_arm.consumed|=1U<<i;
 ret=j314s_combined_arm_once(&j314s_combined_arm,mask);
 for(i=0;i<3;i++)if(j314s_combined_arm.consumed&(1U<<i))j314s_arm_consumed[i]=true;
 if(!ret){for(i=0;i<3;i++)if(mask&(1U<<i))j314s_arm_committed[i]=true;
  WRITE_ONCE(root_router_only,true);}
out:mutex_unlock(&j314s_arm_lock);return ret;
}
EXPORT_SYMBOL_GPL(apple_cio_arm_j314s_root_trial_mask);
static int j314s_probe_admit(struct device *dev,bool nhi)
{
 int index=j314s_node_index(dev->of_node,nhi?1:0),ret=-EPERM;
 if(index<0)return ret;
 mutex_lock(&j314s_arm_lock);
 /* Never retry ACIO/NHI probe even when a supplier or profile is missing. */
 if(j314s_probe_seen[index][nhi])goto out;
 j314s_probe_seen[index][nhi]=true;
 if(!j314s_boot_controller_admitted(saved_command_line,index)||!j314s_arm_committed[index]||!READ_ONCE(root_router_only)||
    !j314s_boot_valid()||!j314s_chosen_valid()||!j314s_inventory_options()||
    !j314s_profile_valid())goto out;
 ret=0;
out:mutex_unlock(&j314s_arm_lock);return ret;
}
static bool j314s_disabled_endpoint(unsigned index)
{
 unsigned i;
 if(index>=3)return false;
 for(i=3;i<5;i++) {
  struct device_node *n=of_find_node_by_path(j314s_paths[index][i]);
  struct platform_device *p;
  const char *status;bool ok;
  if(!n)return false;
  ok=!of_property_read_string(n,"status",&status)&&!strcmp(status,"disabled")&&
   !of_node_check_flag(n,OF_POPULATED)&&!of_node_check_flag(n,OF_POPULATED_BUS);
  p=of_find_device_by_node(n);if(p){ok=false;put_device(&p->dev);}
  of_node_put(n);if(!ok)return false;
 }
 return true;
}
/* Provider created first, then consumer. T6000 internal NHI DART has SID1+2;
 * endpoint T8110 DART must remain disabled throughout this inventory trial. */
static int j314s_populate_dart_first(struct apple_cio *acio)
{
 struct device_node *nhi=NULL,*dartnode=NULL;
 struct of_phandle_args spec={};struct platform_device *dart;
 struct resource res;int i,ret=-EPERM,index=j314s_node_index(acio->np,0);
 const u64 bases[]={0x701a80000ULL,0xb01a80000ULL,0xf01a80000ULL};
 if(!j314s_boot_controller_admitted(saved_command_line,index)||!j314s_arm_committed[index]||!j314s_profile_valid()||!j314s_disabled_endpoint(index))return -EPERM;
 nhi=of_find_node_by_path(j314s_paths[index][1]);
 dartnode=of_find_node_by_path(j314s_paths[index][2]);
 if(!nhi||!dartnode||nhi->parent!=acio->np||dartnode->parent!=acio->np||
    !of_device_is_available(nhi)||!of_device_is_available(dartnode)||
    !of_device_is_compatible(nhi,"apple,t6000-usb4-nhi")||
    !of_device_is_compatible(dartnode,"apple,t6000-dart")||
    of_node_check_flag(nhi,OF_POPULATED)||of_node_check_flag(dartnode,OF_POPULATED)||
    of_count_phandle_with_args(nhi,"iommus","#iommu-cells")!=2)goto out;
 for(i=0;i<2;i++) {
  ret=of_parse_phandle_with_args(nhi,"iommus","#iommu-cells",i,&spec);
  if(ret)goto out;
  ret=spec.np==dartnode&&spec.args_count==1&&spec.args[0]==i+1?0:-EPERM;
  of_node_put(spec.np);spec.np=NULL;if(ret)goto out;
 }
 ret=of_address_to_resource(dartnode,0,&res);if(ret)goto out;
 if(res.start!=bases[index]||resource_size(&res)!=0x4000){ret=-EPERM;goto out;}
 of_node_set_flag(acio->np,OF_POPULATED_BUS);
 dart=of_platform_device_create(dartnode,NULL,acio->dev);
 if(!dart){ret=-ENODEV;goto out;}
 get_device(&dart->dev);device_lock(&dart->dev);
 ret=device_is_bound(&dart->dev)&&dart->dev.driver&&!strcmp(dart->dev.driver->name,"apple-dart")?0:-EPROBE_DEFER;
 device_unlock(&dart->dev);put_device(&dart->dev);
 if(!ret)ret=of_platform_populate(acio->np,NULL,NULL,acio->dev);
out:of_node_put(dartnode);of_node_put(nhi);return ret;
}
int tb_j314s_root_inventory_only(struct tb *tb);

/* Read-only snapshot: no DT edits, no hardware access, no owner release.
 * ACIO mutex is held over start and inventory, so an in-flight attempt returns
 * EAGAIN instead of presenting a zero-initialized status as success. */
int apple_cio_j314s_inventory_state(unsigned controller, u32 *flags, int *status);
int apple_cio_j314s_inventory_state(unsigned controller, u32 *flags, int *status)
{
 struct apple_cio *c;struct apple_nhi *nhi;u32 f=0;
 if (!flags || !status || controller >= 3 ||
     !of_machine_is_compatible("apple,j314s"))return -EINVAL;
 *flags=0;*status=-EINPROGRESS;
 mutex_lock(&j314s_arm_lock);
 if(j314s_arm_consumed[controller])f|=BIT(0);
 if(j314s_arm_committed[controller])f|=BIT(1);
 mutex_unlock(&j314s_arm_lock);
 if(atomic_read(&j314s_power_attempt[controller]))f|=BIT(2);
 c=READ_ONCE(j314s_owned_cio[controller]);
 *flags=f;
 if(!c)return 0;
 if(!mutex_trylock(&c->lock))return -EAGAIN;
 if(j314s_node_index(c->np,0)!=(int)controller) {
  mutex_unlock(&c->lock);return -EPERM;
 }
 f|=BIT(3);
 if(READ_ONCE(c->root_dma_retained))f|=BIT(4);
 nhi=READ_ONCE(c->root_cable_nhi);
 if(nhi && nhi->acio==c && nhi->tb) {
  f|=BIT(5);
  *status=READ_ONCE(c->root_probe_status);
 }
 if(!READ_ONCE(c->root_stopping))f|=BIT(6);
 if(j314s_child_capture_proven(c))f|=BIT(7);
 if(j314s_child_bootstrap_proven(c))f|=BIT(8);
 *flags=f;mutex_unlock(&c->lock);return 0;
}
EXPORT_SYMBOL_GPL(apple_cio_j314s_inventory_state);
