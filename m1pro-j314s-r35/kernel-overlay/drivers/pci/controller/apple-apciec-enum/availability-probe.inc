/* R27 diagnostic only: exact native pre-RC port prefix, three DART reads.
 * All state, mappings and successful claims are retained until stock reboot.
 * No DART provider, reset, write, DMA mapping or automatic commit is created.
 * Root PERST is released; USB4 PE, LTSSM, MSI and RID mappings stay closed.
 * This is a register-availability experiment, not DART-backed DMA isolation. */
static int availability_link_closed(struct apple_apciec *p)
{
 unsigned int i;
 if (readl(p->port + 0x080) || readl(p->port + APCIEC_MSICFG))
  return -EIO;
 for (i = 0; i < p->rid_entries; i++)
  if (readl(p->port + APCIEC_RID2SID + 4*i))
   return -EIO;
 return 0;
}

static int availability_port_contained(struct apple_apciec *p,
                                      u32 expected_perst, u32 expected_clock)
{
 u32 perst = readl(p->port + 0x814);
 u32 clock = readl(p->port + 0x800);
 u32 ltssm = readl(p->port + 0x080);
 u32 msi = readl(p->port + APCIEC_MSICFG);
 dev_info(p->dev, "dart-availability-probe: controls PERST=%08x APPCLK=%08x LTSSM=%08x MSI=%08x\n",
          perst, clock, ltssm, msi);
 if (perst != expected_perst || clock != expected_clock || ltssm || msi ||
     readl(p->port + 0x140) != 0x11)
  return -EIO;
 return availability_link_closed(p);
}

static int availability_port_tunable(struct apple_apciec *p)
{
 static const unsigned char expected[] = {
  0, 0, 1, 0x40, 0, 0, 0, 1, 0, 0, 0, 1
 };
 const struct property *prop = of_find_property(p->dev->of_node,
                                  "apple,apcie-config-tunables", NULL);
 if (!prop || prop->length != sizeof(expected) ||
     !prop->value || memcmp(prop->value, expected, sizeof(expected)))
  return -EINVAL;
 return 0;
}

static int availability_prefix_write(struct apple_apciec *p, unsigned int off,
                                     u32 expected, u32 mask, u32 value, u32 *next)
{
 u32 before = readl(p->port + off), after;
 int ret = availability_link_closed(p);
 if (ret || before != expected)
  return -EIO;
 *next = (before & ~mask) | value;
 dev_info(p->dev, "dart-availability-probe: native-prefix RMW offset=%04x old=%08x next=%08x\n",
          off, before, *next);
 writel(*next, p->port + off);
 after = readl(p->port + off);
 if (off == 0x800 && value == BIT(0))
  udelay(10); /* Existing source-backed APPCLK readback settling interval. */
 dev_info(p->dev, "dart-availability-probe: native-prefix readback offset=%04x value=%08x\n",
          off, after);
 return after == *next ? 0 : -EIO;
}

static int availability_native_prefix(struct apple_apciec *p,
                                      u32 *perst, u32 *clock)
{
 u32 config;
 int ret;
 *perst = readl(p->port + 0x814);
 *clock = readl(p->port + 0x800);
 if (*perst != 0 || *clock != 0x00100100 ||
     readl(p->port + 0x140) != 0x10)
  return -EIO; /* Exact immediately preceding native reset state. */
 /* Native enablePortHardware order; fresh exact one-row port table first. */
 ret = availability_prefix_write(p, 0x140, 0x10, BIT(0), BIT(0), &config);
 if (ret || availability_port_contained(p, *perst, *clock))
  return -EIO;
 ret = availability_prefix_write(p, 0x814, *perst, BIT(0), BIT(0), perst);
 if (ret || availability_port_contained(p, *perst, *clock))
  return -EIO;
 ret = availability_prefix_write(p, 0x800, *clock, BIT(0), BIT(0), clock);
 if (ret || availability_port_contained(p, *perst, *clock))
  return -EIO;
 ret = availability_prefix_write(p, 0x800, *clock, BIT(8), 0, clock);
 if (ret || availability_port_contained(p, *perst, *clock))
  return -EIO;
 return 0;
}

static int availability_dart_resource(struct apple_apciec *p)
{
 struct device_node *np, *exact;
 struct platform_device *existing;
 const struct property *policy;
 struct resource res;
 int ret;

 if (p->retained_dart_node)
  return -EALREADY;
 policy = of_find_property(p->dev->of_node, "nonposted-mmio", NULL);
 if (!policy || policy->length)
  return -EINVAL;
 np = of_parse_phandle(p->dev->of_node, "research,external-dart", 0);
 if (!np)
  return -EINVAL;
 p->retained_dart_node = np; /* Retained on every result, never depopulated. */
 exact = of_find_node_by_path(p->profile->dart_path);
 ret = exact == np ? 0 : -EINVAL;
 of_node_put(exact);
 if (ret || np->parent != p->dev->of_node ||
     !apciec_dart_compatible(p->profile, np) ||
     of_device_is_available(np) || of_node_check_flag(np, OF_POPULATED) ||
     of_node_check_flag(np, OF_POPULATED_BUS) ||
     of_node_check_flag(np->parent, OF_POPULATED_BUS))
  return -EPERM;
 if (of_address_to_resource(np, 0, &res) || res.start != p->profile->dart ||
     resource_size(&res) != 0x4000 ||
     res.flags != (IORESOURCE_MEM | IORESOURCE_MEM_NONPOSTED))
  return -EINVAL;
 existing = of_find_device_by_node(np);
 if (existing) {
  put_device(&existing->dev);
  return -EBUSY;
 }
 p->retained_sample_resource = res;
 return 0;
}

/* R28's separate immutable capability reuses the proven prefix, but never
 * claims/maps/samples DART: the normal provider owns that mapping itself. */
static int availability_prepare_provider_prefix(struct apple_apciec *p)
{
 u32 perst = 0, clock = 0;
 bool started = false;
 int ret;
 if (!retained_prefix_capability_valid(p) || p->retained_phase != 2 ||
     !p->retained || !p->power_ready || !p->port_prepared ||
     p->retained_failed || !p->retained_ticket || !retained_provider_port_valid(p) ||
     p->retained_prefix_attempted || p->retained_prefix_ready ||
     p->retained_sample_attempted || p->retained_sample_regs ||
     p->prepared || p->dart || p->dart_populated || p->tunnel_ready ||
     p->iommu_ready || p->msi_domain_ready || !p->port || p->rid_entries != 64)
  return -EPERM;
 p->retained_prefix_attempted = true; /* Before validation or first write. */
 ret = availability_dart_resource(p);
 if (ret)
  goto out;
 ret = availability_port_tunable(p);
 if (ret)
  goto out;
 ret = apple_apciec_retained_isolated(p);
 if (ret)
  goto out;
 started = true;
 ret = availability_native_prefix(p, &perst, &clock);
 if (!ret)
  p->retained_prefix_ready = true;
 out:
 if (started && availability_link_closed(p))
  ret = -EIO;
 if (ret) {
  p->retained_prefix_ready = false;
  p->retained_failed = true;
 }
 dev_info(p->dev, "dart-prepare-only: native-prefix status %d; no DART region claimed\n", ret);
 return ret;
}

int apple_apciec_retained_sample_availability(struct device *dev, unsigned int port,
                                             const void *ticket)
{
 struct apple_apciec *p = dev_get_drvdata(dev);
 u32 perst = 0, clock = 0, params1, params2, config;
 bool prefix_started = false;
 int ret;

 if (!apple_apciec_availability_probe_enabled())
  return -EOPNOTSUPP;
 if (!p || !ticket)
  return -EINVAL;
 mutex_lock(&p->lifecycle);
 if (!p->retained_availability_probe || p->retained_provider_prepare || p->retained_raw_identity || ticket != p->retained_ticket ||
     port != 3 || port != p->root_down_port || !p->retained ||
     !p->power_ready || !p->port_prepared || p->retained_failed ||
     p->retained_phase != 2 || p->retained_sample_attempted ||
     p->prepared || p->dart || p->dart_populated || p->tunnel_ready ||
     p->iommu_ready || p->msi_domain_ready || !p->port || p->rid_entries != 64) {
  ret = -EPERM;
  goto out;
 }
 /* Consumed before resource validation and the first possible clock write. */
 p->retained_sample_attempted = true;
 p->retained_phase = 11;
 ret = availability_dart_resource(p);
 if (ret)
  goto fail;
 ret = availability_port_tunable(p);
 if (ret)
  goto fail;
 ret = apple_apciec_retained_isolated(p);
 if (ret)
  goto fail;
 prefix_started = true;
 ret = availability_native_prefix(p, &perst, &clock);
 if (ret)
  goto fail;
 if (!request_mem_region(p->retained_sample_resource.start,
                         resource_size(&p->retained_sample_resource),
                         "j293-retained-dart-availability")) {
  ret = -EBUSY;
  goto fail;
 }
 p->retained_sample_regs = ioremap_np(p->retained_sample_resource.start,
                                     resource_size(&p->retained_sample_resource));
 if (!p->retained_sample_regs) {
  ret = -ENOMEM;
  goto fail; /* The successful region claim stays retained too. */
 }
 dev_info(p->dev, "dart-availability-probe: PARAMS1 read begin offset=0000\n");
 params1 = readl(p->retained_sample_regs + 0x0);
 dev_info(p->dev, "dart-availability-probe: PARAMS1=%08x\n", params1);
 dev_info(p->dev, "dart-availability-probe: PARAMS2 read begin offset=0004\n");
 params2 = readl(p->retained_sample_regs + 0x4);
 dev_info(p->dev, "dart-availability-probe: PARAMS2=%08x\n", params2);
 dev_info(p->dev, "dart-availability-probe: CONFIG read begin offset=0060\n");
 config = readl(p->retained_sample_regs + 0x60);
 dev_info(p->dev, "dart-availability-probe: CONFIG=%08x; reads only, no DART-ready state\n", config);
 ret = availability_port_contained(p, perst, clock);
 if (ret)
  goto fail;
 if (params1 == ~0U || params2 == ~0U || config == ~0U) {
  ret = -EIO;
  goto fail;
 }
 p->retained_phase = 12; /* Diagnostic finished; prepared remains false. */
 goto out;
 fail:
 /* Partial prefixes are never rolled back. Audit remaining closed controls
  * even on a readback/map/sample failure; outer owner also rechecks USB4 PE. */
 if (prefix_started && availability_link_closed(p))
  ret = -EIO;
 p->retained_failed = true;
 /* No unmap, region release, clock clear, supplier put or retry on any result. */
 out:
 mutex_unlock(&p->lifecycle);
 return ret;
}
EXPORT_SYMBOL_GPL(apple_apciec_retained_sample_availability);
