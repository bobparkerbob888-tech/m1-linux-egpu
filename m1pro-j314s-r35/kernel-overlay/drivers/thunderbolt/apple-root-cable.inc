/* SPDX-License-Identifier: GPL-2.0 */
static bool root_cable_only;
module_param(root_cable_only, bool, 0444);
MODULE_PARM_DESC(root_cable_only, "Research: one validated ACIO0 root cable-information handoff, no unlock/tunnel");
static atomic_t apple_root_cable_attempted[2] = { ATOMIC_INIT(0), ATOMIC_INIT(0) };

static bool apple_root_cable_scope(struct apple_nhi *anhi)
{
	int controller = bob_controller_index(anhi->np);
 const char * const *paths;
	struct device_node *node;
	struct platform_device *device;
	const char *status;
	unsigned int i;
	bool valid;

	if (bob_attempt_once(apple_root_cable_attempted, anhi->np) ||
	    !root_router_only || !of_machine_is_compatible("apple,j293"))
		return false;
	if (controller < 0) return false;
 node = of_find_node_by_path(bob_controller_paths[controller][5]);
	valid = node && node == anhi->np;
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

#include "apple-root-cable-check.h"
