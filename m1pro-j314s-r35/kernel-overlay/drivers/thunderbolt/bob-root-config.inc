/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>

#include "bob-controller-profile.h"

static atomic_t bob_root_configuration_attempted[2] = { ATOMIC_INIT(0), ATOMIC_INIT(0) };

static bool bob_root_scope_valid(struct tb *tb)
{
	int controller = bob_controller_index(tb->nhi->dev->of_node);
 const char * const *paths;
	struct device_node *node;
	struct platform_device *device;
	const char *status;
	unsigned int i;
	bool valid;

	if (bob_attempt_once(bob_root_configuration_attempted, tb->nhi->dev->of_node) ||
	    !of_machine_is_compatible("apple,j293") || !tb->nhi->ops ||
	    !tb->nhi->ops->root_router_only)
		return false;
	if (controller < 0) return false;
 node = of_find_node_by_path(bob_controller_paths[controller][5]);
	valid = node && node == tb->nhi->dev->of_node;
	of_node_put(node);
	if (!valid)
		return false;
	if (controller < 0) return false;
 paths = &bob_controller_paths[controller][7];
	for (i = 0; i < 2; i++) {
		node = of_find_node_by_path(paths[i]);
		valid = node && !of_property_read_string(node, "status", &status) &&
			!strcmp(status, "disabled") &&
			!of_node_check_flag(node, OF_POPULATED) &&
			!of_node_check_flag(node, OF_POPULATED_BUS);
		device = node ? of_find_device_by_node(node) : NULL;
		if (device) {
			valid = false;
			put_device(&device->dev);
		}
		of_node_put(node);
		if (!valid)
			return false;
	}
	return true;
}

#include "bob-root-config-check.h"
