/* SPDX-License-Identifier: GPL-2.0 */
/* Root port1 only, read-only subset of cap.c and tb_wait_for_port().
 * No TMU access toggles, unlock, reset, child access or port initialization.
 */
static int apple_root_link_ready(struct apple_nhi *anhi)
{
	struct tb_switch *sw = anhi->tb->root_switch;
	struct tb_port *port = &sw->ports[1];
	unsigned int offset = port->config.first_cap_offset;
	unsigned int seen[64], n = 0, i, state, reads = 0;
	u64 deadline, remaining;
	u32 words[2];
	int ret;

	lockdep_assert_held(&anhi->acio->lock);
	lockdep_assert_held(&anhi->tb->lock);
	if (tb_route(sw) || port->config.type != TB_TYPE_PORT ||
	    sw->config.upstream_port_number == 1)
		return -EPERM;
	/* One cold-training observation, not another power/link attempt.
	 * Total cap+PHY requests <=100; never admit a read after 10 seconds.
	 * An in-flight tb_port_read retains its existing protocol timeout. */
	deadline = ktime_get_ns() + 10ULL * NSEC_PER_SEC;
	while (offset) {
		if (offset < 8 || offset > 0xff || n == ARRAY_SIZE(seen))
			return -EINVAL;
		for (i = 0; i < n; i++)
			if (seen[i] == offset)
				return -ELOOP;
		seen[n++] = offset;
		if (reads >= 100 || ktime_get_ns() >= deadline)
			return -ETIMEDOUT;
		reads++;
		ret = tb_port_read(port, words, TB_CFG_PORT, offset, 1);
		if (ret)
			return ret;
		if (ktime_get_ns() >= deadline)
			return -ETIMEDOUT;
		if (((words[0] >> 8) & 0xff) == TB_PORT_CAP_PHY)
			break;
		offset = words[0] & 0xff;
	}
	if (!offset)
		return -ENOENT;

	/* tb_cap_phy.state is bits26..29 of the second dword. Preserve
	 * upstream accepted states/100ms spacing, with bounded cold-training wait.
	 * Every read is of this root adapter; no downstream request until ready.
	 */
	for (i = 0; reads < 100; i++) {
		if (ktime_get_ns() >= deadline)
			return -ETIMEDOUT;
		reads++;
		ret = tb_port_read(port, words, TB_CFG_PORT, offset, 2);
		if (ret)
			return ret;
		if (ktime_get_ns() >= deadline)
			return -ETIMEDOUT;
		if (((words[0] >> 8) & 0xff) != TB_PORT_CAP_PHY)
			return -EIO;
		state = (words[1] >> 26) & 0xf;
		dev_info(anhi->dev,
			 "root-link-only: port1 PHY state %u, observation %u; read-only\n",
			 state, i + 1);
		if (state == TB_PORT_DISABLED)
			return -ENOLINK;
		if (state >= TB_PORT_UP && state <= TB_PORT_CL2) {
			dev_info(anhi->dev,
				 "root-link-only: port1 ready; no unlock/tunnel\n");
			return 0;
		}
		remaining = ktime_get_ns();
		if (reads >= 100 || remaining >= deadline)
			return -ETIMEDOUT;
		remaining = deadline - remaining;
		if (remaining < NSEC_PER_MSEC)
			return -ETIMEDOUT;
		msleep(min_t(u64, 100, remaining / NSEC_PER_MSEC));
	}
	return -ETIMEDOUT;
}
