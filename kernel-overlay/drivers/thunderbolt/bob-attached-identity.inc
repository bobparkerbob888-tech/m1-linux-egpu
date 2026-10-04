/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/ktime.h>
#include <linux/moduleparam.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include "bob-attached-identity-core.h"

static bool attached_router_identity;
module_param(attached_router_identity, bool, 0444);
MODULE_PARM_DESC(attached_router_identity,
	"Research only: one ACIO0 route1 TB3 UID/DROM identity transaction; no unlock");
static atomic_t bob_identity_attempted = ATOMIC_INIT(0);

struct bob_identity_context {
	struct tb *tb;
	u64 deadline;
};

static bool bob_identity_expired(void *context)
{
	struct bob_identity_context *ctx = context;

	return ktime_get_boottime_ns() >= ctx->deadline;
}

static int bob_identity_read(void *context, unsigned int off,
			     unsigned int count, u32 *data)
{
	struct bob_identity_context *ctx = context;

	int ret = tb_cfg_read(ctx->tb->ctl, data, 1, 0, TB_CFG_SWITCH, off, count);

	/* Successful first header only; protocol validation remains in core. */
	if (!ret && off == 0 && count == 5)
		dev_info(ctx->tb->nhi->dev,
			 "attached-identity: route1 raw header %08x %08x %08x %08x %08x; protocol unvalidated\n",
			 data[0], data[1], data[2], data[3], data[4]);
	return ret;
}

static int bob_identity_write(void *context, unsigned int off, u32 data)
{
	struct bob_identity_context *ctx = context;

	return tb_cfg_write(ctx->tb->ctl, &data, 1, 0, TB_CFG_SWITCH, off, 1);
}

static bool bob_identity_external_disabled(struct device_node *np)
{
	int controller = bob_controller_index(np);
 const char * const *paths;
	struct device_node *node;
	struct platform_device *device;
	const char *status;
	unsigned int i;
	bool valid;

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

/* Called once under tb->lock AFTER all route0 port reads succeeded.
 * No owner teardown here, including on timeout/cleanup failure.
 */
static int bob_attached_identity(struct tb *tb)
{
	struct bob_identity_context ctx = { .tb = tb };
	struct bob_id_io io = {
		.read = bob_identity_read,
		.write = bob_identity_write,
		.expired = bob_identity_expired,
		.ctx = &ctx,
	};
	struct tb_switch *root = tb->root_switch;
	struct device_node *expected;
	u8 *drom;
	unsigned int size = 0;
	bool match;
	int ret;

	if (!attached_router_identity)
		return 0;
	lockdep_assert_held(&tb->lock);
	if (atomic_cmpxchg(&bob_identity_attempted, 0, 1))
		return -EALREADY;
	expected = of_find_node_by_path("/soc/cio@381ac0000/nhi@f00000");
	match = expected && expected == tb->nhi->dev->of_node;
	of_node_put(expected);
	if (!match || !of_machine_is_compatible("apple,j293") ||
	    !tb->nhi->ops || !tb->nhi->ops->root_router_only ||
	    !root || tb_route(root) || !root->config.max_port_number ||
	    root->config.upstream_port_number == 1 ||
	    root->ports[1].config.type != TB_TYPE_PORT ||
	    !bob_identity_external_disabled(tb->nhi->dev->of_node))
		return -EPERM;
	drom = kzalloc(BOB_ID_MAX_DROM, GFP_KERNEL);
	if (!drom)
		return -ENOMEM;
	ctx.deadline = ktime_get_boottime_ns() + 60ULL * NSEC_PER_SEC;
	ret = bob_id_tb3(&io, drom, &size);
	dev_info(tb->nhi->dev,
		 "attached-identity: route1 terminal status %d, bytes %u, operations %u, cleanup_failed %u; retained, no tunnel permit\n",
		 ret, size, io.operations, io.cleanup_failed);
	if (!ret)
		dev_info(tb->nhi->dev,
			 "attached-identity: UID %016llx DROM 0414:7a63 CRCs verified; identity only\n",
			 (unsigned long long)BOB_ID_UID);
	kfree(drom);
	return ret;
}
