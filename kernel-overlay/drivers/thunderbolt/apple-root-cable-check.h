/* SPDX-License-Identifier: GPL-2.0 */
/* Only root SWITCH reads and one Apple cable-information write. */
static int apple_root_cable_cap(struct tb_switch *sw)
{
	unsigned int offset = sw->config.first_cap_offset, seen[64], n = 0, i;
	u32 words[2];
	int ret;

	while (offset) {
		if (offset < 5 || offset > 0x1ffe || n == ARRAY_SIZE(seen))
			return -EINVAL;
		for (i = 0; i < n; i++)
			if (seen[i] == offset)
				return -ELOOP;
		seen[n++] = offset;
		ret = tb_sw_read(sw, words, TB_CFG_SWITCH, offset, 2);
		if (ret)
			return ret;
		if (((words[0] >> 8) & 0xff) == TB_SWITCH_CAP_TMU) {
			offset = words[0] & 0xff;
			continue;
		}
		if (((words[0] >> 8) & 0xff) != TB_SWITCH_CAP_VSE)
			return -EOPNOTSUPP;
		if (!(words[0] >> 24)) {
			if ((words[0] & 0xff) || ((words[0] >> 16) & 0xff) == TB_VSE_CAP_APPLE)
				return -EOPNOTSUPP;
			offset = words[1] & 0xffff;
			continue;
		}
		if (((words[0] >> 16) & 0xff) == TB_VSE_CAP_APPLE) {
			if ((words[0] >> 24) < 2 ||
			    (words[0] >> 24) > 0x2000 - offset)
				return -EINVAL;
			return offset;
		}
		offset = words[0] & 0xff;
	}
	return -ENOENT;
}

static int apple_root_cable_handoff(struct apple_nhi *anhi)
{
	struct apple_cio *acio = anhi->acio;
	struct tb_switch *sw = anhi->tb->root_switch;
	u32 target, before, after;
	const u32 allowed = TB_VSE_CAP_APPLE_CABLE_INFO_PRESENT |
		TB_VSE_CAP_APPLE_CABLE_INFO_ORIENTATION_REVERSE |
		TB_VSE_CAP_APPLE_CABLE_INFO_ACTIVE_CABLE |
		TB_VSE_CAP_APPLE_CABLE_INFO_BIDIR_LSRX |
		TB_VSE_CAP_APPLE_CABLE_INFO_20_GBPS |
		TB_VSE_CAP_APPLE_CABLE_INFO_LEGACY_ADAPTER |
		TB_VSE_CAP_APPLE_CABLE_INFO_TBT2_3;
	int cap, ret;

	/* Called by parent after NHI completion, with original ACIO lock held.
	 * Target cannot change during the handoff. Never called from child probe.
	 */
	lockdep_assert_held(&acio->lock);
	lockdep_assert_held(&anhi->tb->lock);
	if (!apple_root_cable_scope(anhi) || !sw || tb_route(sw) ||
	    !acio->root_dma_retained || acio->root_probe_status ||
	    !smp_load_acquire(&acio->root_cable_snapshot_valid) ||
	    READ_ONCE(acio->root_stopping) || acio->current_cable_info ||
	    sw->config.vendor_id != 0x05ac || sw->config.device_id != 0x2000 ||
	    sw->config.thunderbolt_version != 0x20 || sw->config.max_port_number != 7 ||
	    sw->config.upstream_port_number != 7 || !sw->config.enabled ||
	    sw->config.cmuv != ROUTER_CS_4_CMUV_V1 ||
	    sw->ports[1].config.type != TB_TYPE_PORT ||
	    sw->ports[7].config.type != TB_TYPE_NHI)
		return -EPERM;
	target = READ_ONCE(acio->root_cable_snapshot);
	if (!(target & TB_VSE_CAP_APPLE_CABLE_INFO_PRESENT) || (target & ~allowed) ||
	    ((target & TB_VSE_CAP_APPLE_CABLE_INFO_BIDIR_LSRX) &&
	     !(target & TB_VSE_CAP_APPLE_CABLE_INFO_ACTIVE_CABLE)) ||
	    ((target & TB_VSE_CAP_APPLE_CABLE_INFO_LEGACY_ADAPTER) &&
	     !(target & TB_VSE_CAP_APPLE_CABLE_INFO_TBT2_3)))
		return -EINVAL;
	cap = apple_root_cable_cap(sw);
	if (cap < 0)
		return cap;
	ret = tb_sw_read(sw, &before, TB_CFG_SWITCH,
			 cap + TB_VSE_CAP_APPLE_CABLE_INFO, 1);
	if (ret)
		return ret;
	/* Observed r9 register was zero. Never replace an already active handoff. */
	if (before || target != READ_ONCE(acio->target_cable_info))
		return -EBUSY;
	ret = tb_sw_write(sw, &target, TB_CFG_SWITCH,
			  cap + TB_VSE_CAP_APPLE_CABLE_INFO, 1);
	if (ret)
		return ret;
	ret = tb_sw_read(sw, &after, TB_CFG_SWITCH,
			 cap + TB_VSE_CAP_APPLE_CABLE_INFO, 1);
	if (ret)
		return ret;
	if (after != target || target != READ_ONCE(acio->target_cable_info))
		return -EIO;
	dev_info(anhi->dev,
		 "root-cable-only: validated Type-C value %#x handed to Apple root, readback verified; no unlock/tunnel\n",
		 target);
	return 0;
}
