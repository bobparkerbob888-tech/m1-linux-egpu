/* Real Linux apple-dart ownership while the PCIe path stays closed. DART is an
 * owned child and shares the parent's already-pinned power domains. No endpoint
 * iommu-map is installed, so no stream can acquire a mapping during enumeration.
 */
extern int apple_dart_enum_blocked(struct device *dev);

static int apple_apciec_start_dart(struct apple_apciec *pcie)
{
	struct device_node *np;
	struct resource res;
	int ret;

	/* The nested child only inherits its immediate bus MMIO policy. */
	if (!of_property_present(pcie->dev->of_node, "nonposted-mmio"))
		return -EINVAL;
	np = of_parse_phandle(pcie->dev->of_node, "research,external-dart", 0);
	if (!np)
		return -EINVAL;
	if (np->parent != pcie->dev->of_node ||
	    !of_device_is_compatible(np, "apple,t8103-usb4-dart")) {
		ret = -EINVAL;
		goto put_node;
	}
	if (of_address_to_resource(np, 0, &res) ||
	    !(res.flags & IORESOURCE_MEM_NONPOSTED) ||
	    res.start != pcie->profile->dart || resource_size(&res) != 0x4000) {
		ret = -EINVAL;
		goto put_node;
	}
	pcie->dart_populated = true; /* Failure may leave partially created children. */
	ret = of_platform_populate(pcie->dev->of_node, NULL, NULL, pcie->dev);
	if (ret)
		goto put_node;
	pcie->dart = of_find_device_by_node(np);
	if (!pcie->dart) {
		ret = -ENODEV;
		goto put_node;
	}
	ret = device_attach(&pcie->dart->dev);
	if (ret <= 0) {
		ret = ret ?: -EPROBE_DEFER;
		goto put_node;
	}
	/* Successful provider initialization is insufficient by itself: read back
	 * ALL TCRs/TTBRs and absence of clients through the provider's own API.
	 */
	ret = apple_dart_enum_blocked(&pcie->dart->dev);
 put_node:
	of_node_put(np);
	return ret;
}

static void apple_apciec_stop_dart(struct apple_apciec *pcie)
{
	if (pcie->dart) {
		put_device(&pcie->dart->dev);
		pcie->dart = NULL;
	}
	if (pcie->dart_populated) {
		of_platform_depopulate(pcie->dev);
		pcie->dart_populated = false;
	}
}

/* Only from split retained phase, outside ACIO/TB and device/probe locks.
 * Prepare-only may have root PERST off; LTSSM/USB4 PE and clients stay closed. */
static int apple_apciec_create_retained_dart(struct apple_apciec *pcie)
{
	struct device_node *np, *exact;
	struct platform_device *existing;
	struct resource res;
	struct property *prop, *once;
	int ret;

	/* The nested child only inherits its immediate bus MMIO policy. */
	prop = of_find_property(pcie->dev->of_node, "nonposted-mmio", NULL);
	if (!prop || prop->length)
		return -EINVAL;
	/* New prepare-only prefix already pins this exact disabled child. Never
	 * overwrite its reference or reuse a diagnostic region/map. */
	np = (pcie->retained_provider_prepare || pcie->retained_raw_identity) ? pcie->retained_dart_node :
	     of_parse_phandle(pcie->dev->of_node, "research,external-dart", 0);
	if (!np)
		return -EINVAL;
	pcie->retained_dart_node = np; /* Lifetime retained on every result. */
	exact = of_find_node_by_path(pcie->profile->dart_path);
	ret = exact == np ? 0 : -EINVAL;
	of_node_put(exact);
	if (ret || np->parent != pcie->dev->of_node ||
	    !of_device_is_compatible(np, "apple,t8103-usb4-dart") ||
	    of_device_is_available(np) || of_node_check_flag(np, OF_POPULATED) ||
	    of_node_check_flag(np, OF_POPULATED_BUS) ||
	    of_node_check_flag(np->parent, OF_POPULATED_BUS))
		return -EPERM;
	if (of_address_to_resource(np, 0, &res) ||
	    res.flags != (IORESOURCE_MEM | IORESOURCE_MEM_NONPOSTED) || res.start != pcie->profile->dart ||
	    resource_size(&res) != 0x4000)
		return -EINVAL;
	existing = of_find_device_by_node(np);
	if (existing) {
		put_device(&existing->dev);
		return -EBUSY;
	}
	prop = kzalloc(sizeof(*prop), GFP_KERNEL);
	if (!prop)
		return -ENOMEM;
	pcie->retained_dart_status = prop;
	prop->name = kstrdup("status", GFP_KERNEL);
	prop->value = kstrdup("okay", GFP_KERNEL);
	prop->length = 5;
	if (!prop->name || !prop->value)
		return -ENOMEM;
	once = kzalloc(sizeof(*once), GFP_KERNEL);
	if (!once)
		return -ENOMEM;
	once->name = kstrdup("research,retained-probe-once", GFP_KERNEL);
	if (!once->name)
		return -ENOMEM;
	of_changeset_init(&pcie->retained_dart_changeset);
	ret = of_changeset_add_property(&pcie->retained_dart_changeset, np, once);
	if (ret)
		return ret;
	ret = of_changeset_update_property(&pcie->retained_dart_changeset, np, prop);
	if (ret)
		return ret;
	/* Parent bus flag remains CLEAR during notification: platform notifier
	 * cannot create/probe this child as a side effect of status publication. */
	ret = of_changeset_apply(&pcie->retained_dart_changeset);
	if (ret)
		return ret;
	if (!of_device_is_available(np) || of_node_check_flag(np, OF_POPULATED))
		return -ESTALE;
	existing = of_find_device_by_node(np);
	if (existing) {
		put_device(&existing->dev);
		return -EBUSY;
	}
	pcie->dart_populated = true;
	of_node_set_flag(np->parent, OF_POPULATED_BUS);
	smp_store_release(&pcie->retained_dart_window, true);
	pcie->dart = of_platform_device_create(np, NULL, pcie->dev);
	if (!pcie->dart) {
		WRITE_ONCE(pcie->retained_dart_window, false);
		return -ENODEV;
	}
	get_device(&pcie->dart->dev);
	/* No device_attach: normal creation already invoked normal probe. */
	device_lock(&pcie->dart->dev);
	WRITE_ONCE(pcie->retained_dart_window, false);
	ret = pcie->dart->dev.driver &&
	      !strcmp(pcie->dart->dev.driver->name, "apple-dart") ? 0 : -ENODEV;
	device_unlock(&pcie->dart->dev);
	if (ret)
		return ret;
	ret = apple_dart_enum_blocked(&pcie->dart->dev);
	if (pcie->retained_provider_prepare)
		dev_info(pcie->dev, "dart-prepare-only: bound provider 64SID/256TTBR/no-client audit status %d\n", ret);
	return ret;
}
