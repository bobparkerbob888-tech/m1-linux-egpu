/* SPDX-License-Identifier: GPL-2.0 */
/* One-way software admission only. No hardware access or firmware mutation. */
static DEFINE_MUTEX(apple_j293_arm_lock);
static bool apple_j293_arm_consumed[2];
static bool apple_j293_probe_seen[2];
static bool apple_j293_arm_committed[2];

static bool apple_j293_arm_cmdline_valid(void)
{
 const char *p = saved_command_line;
 unsigned int mode = 0, trial = 0, overlay = 0;
 size_t len;
 while (*p) {
  p += strspn(p, " \t");
  len = strcspn(p, " \t");
  if (!len)
   break;
  if (!strncmp(p, "thunderbolt_apple.root_router_only=", 35))
   return false;
  if (!strncmp(p, "bob_kernel_mode=", 16)) {
   if (len != strlen("bob_kernel_mode=late-arm-r54-native-driver") ||
       strncmp(p, "bob_kernel_mode=late-arm-r54-native-driver", len))
    return false;
   mode++;
  }
  if (!strncmp(p, "bob_kernel_trial=", 17)) {
   if (len != strlen("bob_kernel_trial=oldm1-r54-20261004") ||
       strncmp(p, "bob_kernel_trial=oldm1-r54-20261004", len))
    return false;
   trial++;
  }
  if (!strncmp(p, "bob_j293_overlay=", 17)) {
   if (len != strlen("bob_j293_overlay=efi-disabled-r52") ||
       strncmp(p, "bob_j293_overlay=efi-disabled-r52", len))
    return false;
   overlay++;
  }
  p += len;
 }
 return mode == 1 && trial == 1 && overlay == 1;
}

int apple_cio_arm_j293_root_trial_port(unsigned int controller);
int apple_cio_arm_j293_root_trial_port(unsigned int controller)
{
 struct device_node *node;
 struct platform_device *device;
 const char *value;
 unsigned int i;
 int ret = -EPERM;
 const char *reason = "already consumed";

 if (controller >= BOB_CONTROLLERS) return -EINVAL;
 mutex_lock(&apple_j293_arm_lock);
 if (apple_j293_arm_consumed[controller])
  goto out;
 /* Rejected requests consume this software capability too. Never reset. */
 apple_j293_arm_consumed[controller] = true;
 reason = "prior controller activity or boot mode";
 if (apple_j293_probe_seen[controller] ||
     (!controller && READ_ONCE(root_router_only)) ||
     (controller && (!READ_ONCE(root_router_only) || !apple_j293_peer_retained(0))) ||
     atomic_read(&apple_cio_platform_attempted[controller]))
  goto out;
 reason = "boot marker";
 if (!apple_j293_arm_cmdline_valid())
  goto out;
 reason = "machine";
 if (!of_machine_is_compatible("apple,j293"))
  goto out;
 node = of_find_node_by_path("/chosen");
 reason = "firmware";
 if (!node)
  goto out;
 ret = of_property_read_string(node, "asahi,os-fw-version", &value);
 if (!ret && strcmp(value, "13.5"))
  ret = -EPERM;
 if (!ret) {
  reason = "EFI overlay marker";
  ret = of_property_read_string(node, "bob,j293-efi-overlay", &value);
  if (!ret && strcmp(value, "disabled-r52"))
   ret = -EPERM;
 }
 of_node_put(node);
 if (ret)
  goto out;
 ret = -EPERM;
 for (i = 0; i < BOB_OWNED_NODES; i++) {
  reason = bob_controller_paths[controller][i];
  node = of_find_node_by_path(reason);
  if (!node)
   goto out;
  /* Shared reset belongs to the retained controller0 owner; controller1
   * neither changes its status nor repeats its reset lifecycle. */
  if (controller && i == 1) {
   bool owned = apple_j293_peer_retained(0) && of_device_is_available(node) &&
    of_node_check_flag(node,OF_POPULATED);
   device=of_find_device_by_node(node);
   owned=owned && device && device_is_bound(&device->dev);
   if(device)put_device(&device->dev);
   of_node_put(node);
   if(!owned)goto out;
   continue;
  }
  if (of_property_read_string(node, "status", &value) ||
      strcmp(value, "disabled") ||
      of_node_check_flag(node, OF_POPULATED) ||
      of_node_check_flag(node, OF_POPULATED_BUS)) {
   of_node_put(node);
   goto out;
  }
  device = of_find_device_by_node(node);
  of_node_put(node);
  if (device) {
   put_device(&device->dev);
   goto out;
  }
 }
 /* Probes cannot pass the same mutex before the one-way mode commit. */
 WRITE_ONCE(root_router_only, true);
 apple_j293_arm_committed[controller] = true;
 ret = 0;
 reason = "armed; no hardware touched";
out:
 pr_info("j293-late-arm: result %d (%s)\n", ret, reason);
 mutex_unlock(&apple_j293_arm_lock);
 return ret;
}
EXPORT_SYMBOL_GPL(apple_cio_arm_j293_root_trial_port);
int apple_cio_arm_j293_root_trial(void);
int apple_cio_arm_j293_root_trial(void)
{return apple_cio_arm_j293_root_trial_port(0);}
EXPORT_SYMBOL_GPL(apple_cio_arm_j293_root_trial);

static int apple_j293_probe_admit(struct device *dev, bool nhi)
{
 struct device_node *expected;
 int ret = 0;
 int controller = bob_controller_node_index(dev->of_node,nhi);
 if (controller < 0) return apple_j293_arm_cmdline_valid() || READ_ONCE(root_router_only) ? -EPERM : 0;
 mutex_lock(&apple_j293_arm_lock);
 if (!apple_j293_arm_consumed[controller] && apple_j293_arm_cmdline_valid()) {
  /* A late-arm boot must never reach controller MMIO before admission.
   * Remember even a denied unexpected probe; later arming must fail. */
  apple_j293_probe_seen[controller] = true;
  ret = -EPERM;
  goto out;
 }
 if (apple_j293_arm_consumed[controller]) {
  if (!apple_j293_arm_committed[controller] || !READ_ONCE(root_router_only)) {
   ret = -EPERM;
   goto out;
  }
  expected = of_find_node_by_path(bob_controller_paths[controller][nhi ? 5 : 6]);
  if (!expected || expected != dev->of_node)
   ret = -EPERM;
  of_node_put(expected);
  if (ret)
   goto out;
 }
 /* Includes ordinary probes: arming after any admitted probe is forbidden. */
 apple_j293_probe_seen[controller] = true;
out:
 dev_info(dev, "j293-late-arm: %s probe admission %d (armed=%d mode=%d)\n",
          nhi ? "NHI" : "ACIO", ret, apple_j293_arm_consumed[controller],
          READ_ONCE(root_router_only));
 mutex_unlock(&apple_j293_arm_lock);
 return ret;
}
