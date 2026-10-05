/* SPDX-License-Identifier: GPL-2.0 */
#ifndef BOB_J293_CONTROLLER_PROFILE_H
#define BOB_J293_CONTROLLER_PROFILE_H
/* Physical controllers, not logical Thunderbolt port numbers. No dynamic
 * discovery or permissive fallback: each UID/path is the recorded machine. */
#define BOB_CONTROLLERS 2
#define BOB_OWNED_NODES 9
static const char * const bob_controller_paths[2][9] = {
 {"/soc/mailbox@381100000", "/soc/reset-controller@23b784000",
  "/soc/pinctrl@24a820000/acio0-pins",
  "/soc/i2c@235010000/usb-pd@38/connector/ports/port@2",
  "/soc/cio@381ac0000/iommu@a80000", "/soc/cio@381ac0000/nhi@f00000",
  "/soc/cio@381ac0000", "/soc/apciec@3b0000000",
  "/soc/apciec@3b0000000/iommu@3a1008000"},
 {"/soc/mailbox@501100000", "/soc/reset-controller@23b784000",
  "/soc/pinctrl@24a820000/acio1-pins",
  "/soc/i2c@235010000/usb-pd@3f/connector/ports/port@2",
  "/soc/cio@501ac0000/iommu@a80000", "/soc/cio@501ac0000/nhi@f00000",
  "/soc/cio@501ac0000", "/soc/apciec@530000000",
  "/soc/apciec@530000000/iommu@521008000"}
};
static inline unsigned bob_chain_count(unsigned controller)
{ return controller == 0 ? 3 : controller == 1 ? 2 : 0; }
static inline unsigned long long bob_router_uid(unsigned controller, unsigned child)
{
 static const unsigned long long uid[2][3] = {
  {PROVISION_PRIVATE_ID_18,PROVISION_PRIVATE_ID_17,PROVISION_PRIVATE_ID_16},
  {PROVISION_PRIVATE_ID_19,PROVISION_PRIVATE_ID_15,0}
 };
 return controller < 2 && child < bob_chain_count(controller) ? uid[controller][child] : 0;
}
static inline int bob_controller_path_index(const char *path, bool nhi)
{
 unsigned i;
 if (!path) return -1;
 for (i=0;i<BOB_CONTROLLERS;i++)
  if (!strcmp(path,bob_controller_paths[i][nhi ? 5 : 6])) return i;
 return -1;
}
#ifdef __KERNEL__
/* device_node.full_name is the flattened-tree node name, not an absolute
 * path. Bind to the exact retained OF node object; equal leaf names do not
 * establish controller identity. Every lookup reference is balanced. */
static inline int bob_controller_node_index(const struct device_node *np, bool nhi)
{
 unsigned i;
 if (!np) return -1;
 for (i=0;i<BOB_CONTROLLERS;i++) {
  struct device_node *expected=of_find_node_by_path(bob_controller_paths[i][nhi ? 5 : 6]);
  bool same=expected && expected==np;
  of_node_put(expected);
  if (same) return i;
 }
 return -1;
}
static inline int bob_controller_index(const struct device_node *np)
{
 int i=bob_controller_node_index(np,true);
 return i>=0 ? i : bob_controller_node_index(np,false);
}
static inline bool bob_attempt_once(atomic_t attempts[2], const struct device_node *np)
{
 int i=bob_controller_index(np);
 return i<0 || atomic_cmpxchg(&attempts[i],0,1);
}
#endif
#endif
