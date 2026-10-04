// SPDX-License-Identifier: GPL-2.0-only
/* One boot, one fixed authenticated-tunables ACIO platform experiment. No unload path. */
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/utsname.h>
#include <generated/utsrelease.h>
#include <linux/string.h>
#include "overlay.inc"
#include "old-drom.inc"

extern bool apple_cio_platform_attempt_consumed(void);
extern int apple_cio_arm_j293_root_trial(void);
static bool arm;
module_param(arm, bool, 0400);
MODULE_PARM_DESC(arm, "Explicitly permit this one boot's platform-only activation");
static int overlay_id;
extern int apple_cio_external_outer_complete(int overlay_status);
static int apply_result;
module_param(apply_result, int, 0400);
static const char * const targets[] = {
#include "targets.inc"
};

static int disabled_unpopulated(const char *path)
{
 struct device_node *np = of_find_node_by_path(path);
 const char *status;
 int ret = -EINVAL;
 if (!np)
  return -ENOENT;
 if (!of_property_read_string(np, "status", &status) &&
     !strcmp(status, "disabled") && !of_node_check_flag(np, OF_POPULATED))
  ret = 0;
 of_node_put(np);
 return ret;
}

static int __init acio_runtime_enable_init(void)
{
 struct device_node *np;
 const char *fw;
 const void *drom;
 int drom_len;
 int i, ret;
 if (!arm || strcmp(init_utsname()->release, UTS_RELEASE) ||
     !of_machine_is_compatible("apple,j293"))
  return -EPERM;
 np = of_find_node_by_path("/chosen");
 if (!np)
  return -ENOENT;
 ret = of_property_read_string(np, "asahi,os-fw-version", &fw);
 if (!ret && strcmp(fw, "13.5"))
  ret = -EINVAL;
 of_node_put(np);
 if (ret)
  return ret;
 for (i = 0; i < ARRAY_SIZE(targets); i++) {
  ret = disabled_unpopulated(targets[i]);
  if (ret) {
   pr_err("ACIO activation: target not pristine: %s (%d)\n", targets[i], ret);
   return ret;
  }
 }
 ret = disabled_unpopulated("/soc/apciec@3b0000000");
 if (ret)
  return ret;
 ret = disabled_unpopulated("/soc/apciec@3b0000000/iommu@3a1008000");
 if (ret)
  return ret;
 np = of_find_node_by_path("/soc/apciec@3b0000000");
 if (!np)
  return -ENOENT;
 ret = of_find_property(np, "nonposted-mmio", NULL) ||
       of_find_property(np, "apple,apcie-common-tunables", NULL) ||
       of_find_property(np, "apple,apcie-debug-tunables", NULL) ||
       of_find_property(np, "apple,apcie-fabric-tunables", NULL) ||
       of_find_property(np, "research,apcie-common-absent", NULL) ||
       of_find_property(np, "research,apciec-bar-windows", NULL);
 of_node_put(np);
 if (ret)
  return -EINVAL;
 np = of_find_node_by_path("/soc/cio@381ac0000");
 ret = !of_property_read_bool(np, "research,j293-13-5-optional-acio-tunables") ||
       of_find_property(np, "apple,tunable-rc", NULL);
 of_node_put(np);
 if (ret)
  return -EINVAL;
 np = of_find_node_by_path("/soc/cio@381ac0000/nhi@f00000");
 ret = !!of_find_property(np, "apple,tunable-nhi", NULL);
 drom = of_get_property(np, "apple,thunderbolt-drom", &drom_len);
 if (!drom || drom_len != sizeof(expected_old_drom) ||
     memcmp(drom, expected_old_drom, sizeof(expected_old_drom)))
  ret = -EINVAL;
 of_node_put(np);
 if (ret || apple_cio_platform_attempt_consumed())
  return -EPERM;
 /* No module_exit: normal unload is prohibited, including init in flight.
  * Retain module even if overlay application reports partial failure. Never
  * remove/reapply an overlay whose notification could have powered hardware.
  */
 pr_info("ACIO r49 activation: late-arm registration begin\n");
 ret = apple_cio_arm_j293_root_trial();
 pr_info("ACIO r49 activation: late-arm registration returned %d\n", ret);
 if (ret)
  return ret;
 pr_info("ACIO activation: applying fixed port0 authenticated-tunables overlay once\n");
 apply_result = of_overlay_fdt_apply(port0_overlay, sizeof(port0_overlay),
                                    &overlay_id, NULL);
 /* No callback runs inside OF notification. Record return even on failure;
  * this alone cannot create the same-call readiness ticket. */
 ret = apple_cio_external_outer_complete(apply_result);
 pr_info("ACIO activation: external outer-return barrier status %d\n", ret);
 pr_info("ACIO activation: apply result %d overlay %d; retained until reboot\n",
         apply_result, overlay_id);
 return 0;
}
module_init(acio_runtime_enable_init);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("One-shot J293 r49 port0 retained PCIe trial; reboot to remove");
