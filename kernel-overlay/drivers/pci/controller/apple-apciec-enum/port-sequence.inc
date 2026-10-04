/* Apple 22G74 source-backed port sequence; never called by current probe.
 * Called only under sleeping lifecycle lock with supplier/PMGR power held.
 * No valid RID mappings, endpoint MSI, counters or tunables are invented.
 */
static u32 apple_apciec_logical_offset(struct apple_apciec *pcie, u32 reg)
{
	return pcie->rid_entries <= 16 && reg >= 0x928 ? reg - 0xc0 : reg;
}

static int __maybe_unused apple_apciec_prepare_port(struct apple_apciec *pcie)
{
	static const struct { u16 reg; u32 value; } reset[] = {
		{0x08c, 0x110}, {0x100, 0xffffffff}, {0x148, 0xffffffff},
		{0x210, 0xffffffff}, {0x080, 0}, {0x084, 0},
		{0x104, 0xffffffff}, {0x124, 0}, {0x128, 0}, {0x168, 0},
		{0x13c, 0x10}, {0x800, 0x100100}, {0x808, 0x100045},
		{0x810, 0x100}, {0x814, 0},
	};
	static const struct { u16 reg; u32 value; } tail[] = {
		{0x130, 0x208}, {0x140, 0x10}, {0x144, 0x253770},
		{0x21c, 0}, {0x81c, 0}, {0x824, 0},
	};
	unsigned int i;

	if (!pcie->power_ready || pcie->tunnel_ready || !pcie->port ||
	    (pcie->rid_entries != 16 && pcie->rid_entries != 64))
		return -EPERM;
	for (i = 0; i < ARRAY_SIZE(reset); i++)
		writel(reset[i].value, pcie->port + reset[i].reg);
	for (i = 0; i < pcie->rid_entries; i++)
		writel(0, pcie->port + APCIEC_RID2SID + i * 4);
	for (i = 0; i < ARRAY_SIZE(tail); i++)
		writel(tail[i].value, pcie->port + tail[i].reg);
	/* Leave PERST asserted, port disabled and LTSSM off until commit. */
	return 0;
}

static int __maybe_unused apple_apciec_release_and_wait(struct apple_apciec *pcie)
{
	u32 value;
	int ret;

	if (!pcie->power_ready || pcie->tunnel_ready)
		return -EPERM;
	/* This point requires BOTH root PCIe adapters already enabled. */
	/* PERST(false), port enabled, application clock auto-disable cleared. */
	value = readl(pcie->port + 0x814);
	writel(value | BIT(0), pcie->port + 0x814);
	value = readl(pcie->port + 0x800);
	writel((value | BIT(0)) & ~BIT(8), pcie->port + 0x800);
	writel(0, pcie->port + apple_apciec_logical_offset(pcie, 0x988));
	ret = readl_poll_timeout(pcie->port + apple_apciec_logical_offset(pcie, 0x98c),
				 value, !(value & BIT(0)), 1000, 100000);
	if (ret)
		return ret;
	value = readl(pcie->port + 0x80);
	writel(value | BIT(0), pcie->port + 0x80);
	/* Apple getLinkUp: portconfig 0x208 bit0. Budget is local policy. */
	return readl_poll_timeout(pcie->port + 0x208, value,
				  value & BIT(0), 1000, 100000);
}

static int __maybe_unused apple_apciec_isolate_port(struct apple_apciec *pcie)
{
	u32 value;
	unsigned int i;

	/* Config readiness must already be cleared under transaction lock and
	 * PCI children removed while ECAM remains powered. Failure means supplier
	 * power must remain retained; it is NOT permission to unmap or power off.
	 */
	if (!pcie->power_ready || pcie->tunnel_ready)
		return -EPERM;
	writel(0, pcie->port + APCIEC_MSICFG);
	for (i = 0; i < pcie->rid_entries; i++)
		writel(0, pcie->port + APCIEC_RID2SID + i * 4);
	value = readl(pcie->port + 0x80);
	writel(value & ~BIT(0), pcie->port + 0x80);
	value = readl(pcie->port + 0x814);
	writel(value & ~BIT(0), pcie->port + 0x814);
	value = readl(pcie->port + 0x800);
	writel(value & ~BIT(0), pcie->port + 0x800);
	return readl_poll_timeout(pcie->port + 0x804, value,
				  !(value & BIT(0)), 10, 100000);
}
