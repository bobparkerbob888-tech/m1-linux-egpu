/* Local enumeration-only candidate. Not deployed; NHI supplier glue required. */
int apple_apciec_enum_bind(struct device *dev, void *context,
	const struct apple_apciec_supplier_ops *ops, unsigned int root_down_port)
{
	struct apple_apciec *pcie = dev_get_drvdata(dev);
	int ret = 0;

	if (!pcie || !ops || !ops->get || !ops->put || !context ||
	    !root_down_port || root_down_port > 63)
		return -EINVAL;
	mutex_lock(&pcie->lifecycle);
	if (pcie->supplier || pcie->power_ready || pcie->attempted || pcie->retained)
		ret = -EBUSY;
	else {
		pcie->root_down_port = root_down_port;
		pcie->supplier = ops;
		pcie->supplier_context = context;
	}
	mutex_unlock(&pcie->lifecycle);
	return ret;
}
EXPORT_SYMBOL_GPL(apple_apciec_enum_bind);

static void apple_apciec_close_config(struct apple_apciec *pcie)
{
	unsigned long flags;
	raw_spin_lock_irqsave(&pcie->lock, flags);
	pcie->tunnel_ready = false;
	raw_spin_unlock_irqrestore(&pcie->lock, flags);
}

static void apple_apciec_shutdown_locked(struct apple_apciec *pcie)
{
	int ret;

	if (!pcie->power_ready || pcie->retained)
		return;
	apple_apciec_remove_quarantined(pcie);
	apple_apciec_close_config(pcie);
	ret = pcie->port_prepared ? apple_apciec_isolate_port(pcie) : 0;
	if (ret) {
		pcie->retained = true;
		dev_err(pcie->dev, "Isolation failed: retaining supplier power, refusing retry\n");
		return;
	}
	apple_apciec_stop_dart(pcie);
	pcie->prepared = false;
	pcie->power_ready = false;
	pcie->supplier->put(pcie->supplier_context);
}

int apple_apciec_enum_prepare(struct device *dev, unsigned int root_down_port)
{
	struct apple_apciec *pcie = dev_get_drvdata(dev);
	int ret;

	if (!pcie)
		return -ENODEV;
	/* J314s admission currently proves mappings only, never power or DMA. */
	if (apciec_profile_j314s(pcie->profile))
		return -EOPNOTSUPP;
	mutex_lock(&pcie->lifecycle);
	if (!pcie->supplier || root_down_port != pcie->root_down_port ||
	    pcie->retained) {
		ret = -EPERM;
		goto out;
	}
	if (pcie->prepared) {
		ret = 0;
		goto out;
	}
	if (pcie->attempted) {
		ret = -EPERM;
		goto out;
	}
	pcie->attempted = true;
	ret = pcie->supplier->get(pcie->supplier_context);
	if (ret)
		goto out;
	pcie->power_ready = true;
	ret = apple_apciec_start_dart(pcie);
	if (ret)
		goto shutdown;
	pcie->port_prepared = true;
	ret = apple_apciec_prepare_port(pcie);
	if (ret)
		goto shutdown;
	pcie->prepared = true;
	goto out;
 shutdown:
	apple_apciec_shutdown_locked(pcie);
 out:
	mutex_unlock(&pcie->lifecycle);
	return ret;
}
EXPORT_SYMBOL_GPL(apple_apciec_enum_prepare);

int apple_apciec_enum_enable(struct device *dev, unsigned int root_down_port)
{
	struct apple_apciec *pcie = dev_get_drvdata(dev);
	unsigned long flags;
	int ret;

	if (!pcie)
		return -ENODEV;
	mutex_lock(&pcie->lifecycle);
	if (!pcie->supplier || root_down_port != pcie->root_down_port ||
	    pcie->retained) {
		ret = -EPERM;
		goto out;
	}
	if (pcie->tunnel_ready) {
		ret = 0;
		goto out;
	}
	if (!pcie->prepared || !pcie->power_ready) {
		ret = -EPERM;
		goto out;
	}
	ret = apple_apciec_dart_blocked(pcie);
	if (ret)
		goto shutdown;
	ret = apple_apciec_release_and_wait(pcie);
	if (ret)
		goto shutdown;
	ret = apple_apciec_allocate_bridge(pcie);
	if (ret)
		goto shutdown;
	pcie->bus_resource = (struct resource) {
		.name = "APCIEC enumeration bus", .flags = IORESOURCE_BUS,
		.start = pcie->bus_start, .end = pcie->bus_end,
	};
	pci_add_resource(&pcie->bridge->windows, &pcie->bus_resource);
	/* No MEM/IO aperture exposed: only config discovery, no BAR enable. */
	raw_spin_lock_irqsave(&pcie->lock, flags);
	pcie->tunnel_ready = true;
	raw_spin_unlock_irqrestore(&pcie->lock, flags);
	ret = apple_apciec_scan_quarantined(pcie);
	if (!ret)
		ret = apple_apciec_dart_blocked(pcie);
	if (!ret)
		goto out;
 shutdown:
	apple_apciec_shutdown_locked(pcie);
 out:
	mutex_unlock(&pcie->lifecycle);
	return ret;
}
EXPORT_SYMBOL_GPL(apple_apciec_enum_enable);

void apple_apciec_enum_disable(struct device *dev, unsigned int root_down_port)
{
	struct apple_apciec *pcie = dev_get_drvdata(dev);

	if (!pcie || root_down_port != pcie->root_down_port)
		return;
	mutex_lock(&pcie->lifecycle);
	apple_apciec_shutdown_locked(pcie);
	mutex_unlock(&pcie->lifecycle);
}
EXPORT_SYMBOL_GPL(apple_apciec_enum_disable);

int apple_apciec_enum_unbind(struct device *dev)
{
	struct apple_apciec *pcie = dev_get_drvdata(dev);
	int ret = 0;

	if (!pcie)
		return -ENODEV;
	mutex_lock(&pcie->lifecycle);
	if (pcie->power_ready || pcie->retained)
		ret = -EBUSY;
	else {
		pcie->supplier = NULL;
		pcie->supplier_context = NULL;
	}
	mutex_unlock(&pcie->lifecycle);
	return ret;
}
EXPORT_SYMBOL_GPL(apple_apciec_enum_unbind);

/* Retained phases: power + isolated port attempted/ready, DART attempted/ready,
 * finish attempted/ready. Internal states, never caller-controlled proof. */
static int apple_apciec_retained_isolated(struct apple_apciec *pcie);
static int availability_port_contained(struct apple_apciec *p, u32 perst, u32 clock);
static int availability_prepare_provider_prefix(struct apple_apciec *p);
static int apple_apciec_retained_begin_mode(struct device *dev, unsigned int port, const void *ticket, bool probe, bool provider, bool raw_identity, u64 deadline)
{
	struct apple_apciec *pcie = dev_get_drvdata(dev);
	int ret;
	if (!retain_prepare)
		return -EOPNOTSUPP;
	if ((probe + provider + raw_identity > 1) || ((probe || provider) &&
	    (!apple_apciec_availability_probe_enabled() || port != 3)) ||
            (raw_identity && (!apple_apciec_raw_identity_enabled() || port != 3 ||
             !deadline || ktime_get_boottime_ns() >= deadline)))
		return -EPERM;
	if (!pcie || !ticket)
		return -EINVAL;
	/* A supplier binding must not inherit J293 power/reset sequencing. */
	if (apciec_profile_j314s(pcie->profile))
		return -EOPNOTSUPP;
	mutex_lock(&pcie->lifecycle);
	if (!pcie->supplier || !pcie->supplier->get_retained || port != pcie->root_down_port ||
	    pcie->attempted || pcie->prepared || pcie->retained) {
		ret = -EPERM;
		goto out;
	}
	pcie->retained_availability_probe = probe; /* Immutable before supplier action. */
	pcie->retained_provider_prepare = provider;
 pcie->retained_raw_identity = raw_identity;
 pcie->retained_identity_deadline = raw_identity ? deadline : 0;
	pcie->retained_ticket = ticket;
	pcie->attempted = pcie->retained = true;
	pcie->retained_phase = 1;
	dev_info(pcie->dev, "r22 retained PM domains begin\n");
	ret = pcie->supplier->get_retained(pcie->supplier_context);
	dev_info(pcie->dev, "r22 retained PM domains returned %d\n", ret);
	if (ret) {
		pcie->retained_failed = true;
		goto out;
	}
	pcie->power_ready = true;
	ret = apple_apciec_predart_apply(pcie);
	if (ret) {
		pcie->retained_failed = true;
		goto out;
	}
	/* Native _resetPortHardware precedes DART availability. Mark the port
	 * attempt before its first write; retain every partial failure. This is
	 * the unchanged isolated reset sequence, never PERST/LTSSM release. */
	pcie->port_prepared = true;
	dev_info(pcie->dev, "r25 retained isolated port preparation begin\n");
	ret = apple_apciec_prepare_port(pcie);
	dev_info(pcie->dev, "r25 retained isolated port preparation returned %d\n", ret);
	if (!ret)
		ret = apple_apciec_retained_isolated(pcie);
	dev_info(pcie->dev, "r25 retained pre-DART port isolation status %d\n", ret);
	if (ret) {
		pcie->retained_failed = true;
		goto out;
	}
	pcie->retained_phase = 2;
	if (provider || raw_identity) {
		ret = availability_prepare_provider_prefix(pcie);
		if (ret)
			pcie->retained_failed = true;
	}
 out:
	mutex_unlock(&pcie->lifecycle);
	return ret;
}
int apple_apciec_retained_begin_power(struct device *dev, unsigned int port, const void *ticket)
{
 return apple_apciec_retained_begin_mode(dev, port, ticket, false, false, false, 0);
}
EXPORT_SYMBOL_GPL(apple_apciec_retained_begin_power);
int apple_apciec_retained_begin_availability_probe(struct device *dev, unsigned int port, const void *ticket)
{
 return apple_apciec_retained_begin_mode(dev, port, ticket, true, false, false, 0);
}
EXPORT_SYMBOL_GPL(apple_apciec_retained_begin_availability_probe);

int apple_apciec_retained_begin_provider_prepare(struct device *dev, unsigned int port, const void *ticket)
{
 return apple_apciec_retained_begin_mode(dev, port, ticket, false, true, false, 0);
}
EXPORT_SYMBOL_GPL(apple_apciec_retained_begin_provider_prepare);
int apple_apciec_retained_begin_raw_identity(struct device *dev, unsigned int port,
                                            const void *ticket, u64 deadline)
{
 return apple_apciec_retained_begin_mode(dev, port, ticket, false, false, true, deadline);
}
EXPORT_SYMBOL_GPL(apple_apciec_retained_begin_raw_identity);

int apple_apciec_retained_populate_dart(struct device *dev, unsigned int port, const void *ticket)
{
	struct apple_apciec *pcie = dev_get_drvdata(dev);
	int ret;
	if (!retain_prepare)
		return -EOPNOTSUPP;
	if (!pcie || !ticket)
		return -EINVAL;
	mutex_lock(&pcie->lifecycle);
	if (ticket != pcie->retained_ticket || port != pcie->root_down_port ||
	    !pcie->retained || !pcie->power_ready || pcie->retained_failed ||
	    pcie->retained_phase != 2 || !pcie->port_prepared ||
	    pcie->retained_availability_probe) {
		ret = -EPERM;
		goto out;
	}
	pcie->retained_phase = 3;
	if ((pcie->retained_provider_prepare || pcie->retained_raw_identity) &&
	    (!retained_prefix_capability_valid(pcie) ||
	     !pcie->retained_prefix_attempted || !pcie->retained_prefix_ready ||
	     port != 3 || !pcie->port || pcie->rid_entries != 64 ||
	     pcie->retained_sample_attempted || pcie->retained_sample_regs ||
	     availability_port_contained(pcie, 1, 0x00100001))) {
		pcie->retained_failed = true;
		ret = -EPERM;
		goto out;
	}
	dev_info(pcie->dev, "r22 retained DART creation begin\n");
	ret = apple_apciec_create_retained_dart(pcie);
	dev_info(pcie->dev, "r22 retained DART creation returned %d\n", ret);
	if ((pcie->retained_provider_prepare || pcie->retained_raw_identity) &&
	    availability_port_contained(pcie, 1, 0x00100001))
		ret = -EIO;
	if (ret)
		pcie->retained_failed = true;
	else
		pcie->retained_phase = 4;
 out:
	mutex_unlock(&pcie->lifecycle);
	return ret;
}
EXPORT_SYMBOL_GPL(apple_apciec_retained_populate_dart);

static int apple_apciec_retained_isolated(struct apple_apciec *pcie)
{
	unsigned int i;
	/* Stable controls used by release_and_wait/isolate_port; no W1C/status
	 * equality and no assumptions about link-up status register contents. */
	if ((readl(pcie->port + 0x814) & BIT(0)) ||
	    (readl(pcie->port + 0x800) & BIT(0)) ||
	    (readl(pcie->port + 0x080) & BIT(0)) ||
	    readl(pcie->port + APCIEC_MSICFG))
		return -EIO;
	for (i = 0; i < pcie->rid_entries; i++)
		if (readl(pcie->port + APCIEC_RID2SID + i * 4))
			return -EIO;
	return 0;
}

int apple_apciec_retained_finish(struct device *dev, unsigned int port, const void *ticket)
{
	struct apple_apciec *pcie = dev_get_drvdata(dev);
	int ret;
	if (!retain_prepare)
		return -EOPNOTSUPP;
	if (!pcie || !ticket)
		return -EINVAL;
	mutex_lock(&pcie->lifecycle);
	if (ticket != pcie->retained_ticket || port != pcie->root_down_port ||
	    !pcie->retained || !pcie->power_ready || pcie->retained_failed ||
	    pcie->retained_phase != 4 || !pcie->dart || !pcie->port_prepared ||
	    pcie->retained_availability_probe) {
		ret = -EPERM;
		goto out;
	}
	pcie->retained_phase = 5;
	/* The sole port reset already completed before DART creation. Verify
	 * isolation again without repeating it, then audit the blocked provider. */
	if (pcie->retained_provider_prepare || pcie->retained_raw_identity) {
		ret = !retained_prefix_capability_valid(pcie) ||
		      !pcie->retained_prefix_ready || !pcie->retained_prefix_attempted ||
		      port != 3 || !pcie->port || pcie->rid_entries != 64 ||
		      pcie->retained_sample_attempted || pcie->retained_sample_regs ?
		      -EPERM : availability_port_contained(pcie, 1, 0x00100001);
	} else {
		ret = apple_apciec_retained_isolated(pcie);
	}
	if (ret)
		goto fail;
	ret = apple_apciec_dart_blocked(pcie);
	if ((pcie->retained_provider_prepare || pcie->retained_raw_identity) &&
	    availability_port_contained(pcie, 1, 0x00100001))
		ret = -EIO;
	if (ret)
		goto fail;
	pcie->prepared = true;
	pcie->retained_phase = 6;
	goto out;
 fail:
	pcie->retained_failed = true;
 out:
	mutex_unlock(&pcie->lifecycle);
	return ret;
}
EXPORT_SYMBOL_GPL(apple_apciec_retained_finish);
