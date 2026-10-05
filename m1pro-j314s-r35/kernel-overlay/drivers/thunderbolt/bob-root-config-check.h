/* SPDX-License-Identifier: GPL-2.0 */
/* Caller owns tb->lock and retains control DMA on every outcome. */
static int bob_root_configure_checked(struct tb *tb)
{
	struct tb_switch *sw = tb->root_switch;
	struct tb_regs_switch_header before, expected, after;
	int ret;

	lockdep_assert_held(&tb->lock);
	if (!bob_root_scope_valid(tb) || !sw || tb_route(sw))
		return -EPERM;
	/* tb_switch_alloc overwrites software enabled/depth/route fields. Read
	 * actual current hardware state, rather than trusting those reset fields.
	 */
	ret = tb_sw_read(sw, &before, TB_CFG_SWITCH, 0, 5);
	if (ret)
		return ret;
	if (before.vendor_id != 0x05ac || before.device_id != 0x2000 ||
	    before.thunderbolt_version != 0x20 || before.upstream_port_number != 7 ||
	    before.max_port_number != 7 || before.depth || before.route_lo ||
	    before.route_hi || before.enabled || before.cmuv ||
	    memcmp(&before, &sw->config, sizeof(before)))
		return -EPERM;
	/* Preserve every other header bit, including reserved bits and capabilities. */
	expected = before;
	expected.enabled = 1;
	expected.plug_events_delay = 0xff;
	expected.cmuv = ROUTER_CS_4_CMUV_V1;
	ret = tb_switch_configure(sw);
	if (ret)
		return ret;
	if (memcmp(&expected, &sw->config, sizeof(expected)))
		return -EIO;
	ret = tb_sw_read(sw, &after, TB_CFG_SWITCH, 0, 5);
	if (ret)
		return ret;
	if (memcmp(&after, &expected, sizeof(after)))
		return -EIO;
	dev_info(tb->nhi->dev,
		 "root-router-only: Apple USB4 root enumeration configured and exact header readback verified; no tunnel/scan\n");
	return 0;
}
