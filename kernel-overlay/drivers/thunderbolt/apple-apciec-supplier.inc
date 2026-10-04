/* SPDX-License-Identifier: GPL-2.0 */
/* Research only: built-in, single root PCI-down adapter, no endpoint DMA claim. */
#if IS_ENABLED(CONFIG_PCIE_APPLE_APCIEC_ENUM_RESEARCH)
#ifdef MODULE
#error "APCIEC enumeration research requires built-in Apple NHI/CIO"
#endif
#include "apple-apciec-enum.h"
#include <linux/soc/apple/pmgr-diagnostic.h>

static int apple_nhi_enum_get(void *context)
{
	struct apple_nhi *anhi = context;
	int ret;

	lockdep_assert_held(&anhi->tb->lock);
	/* ACIO is already powered. Its stop path takes this same TB lock before
	 * depopulation. Never take acio->lock here: caller order is ACIO -> TB. */
	if (anhi->enum_stopping || !anhi->enum_bound)
		return -ESHUTDOWN;
	ret = pm_runtime_resume_and_get(anhi->enum_pd[0]);
	if (ret < 0)
		return ret;
	ret = pm_runtime_resume_and_get(anhi->enum_pd[1]);
	if (ret < 0) {
		pm_runtime_put_sync(anhi->enum_pd[0]);
		return ret;
	}
	return 0;
}

static int apple_nhi_enum_snapshot(struct apple_nhi *anhi, unsigned int domain,
				   const char *stage, int pm_result)
{
	u32 raw = 0;
	int ret = apple_pmgr_retained_snapshot(anhi->enum_pd[domain], domain, &raw);

	dev_info(anhi->dev, "r23 PMGR snapshot domain %u %s read-status %d pm-result %d raw %#x valid %u; no state write\n",
		 domain, stage, ret, pm_result, raw, !ret);
	return ret;
}

static int apple_nhi_enum_get_retained(void *context)
{
	struct apple_nhi *anhi = context;
	int ret, observed;
	unsigned int domain;
	lockdep_assert_held(&anhi->tb->lock);
	if (anhi->enum_stopping || !anhi->enum_bound || anhi->enum_retained_prepare)
		return -ESHUTDOWN;
	anhi->enum_retained_prepare = true;
	for (domain = 0; domain < 2; domain++) {
		ret = apple_nhi_enum_snapshot(anhi, domain, "before", 0);
		if (ret)
			return ret;
		ret = pm_runtime_resume_and_get(anhi->enum_pd[domain]);
		if (ret >= 0)
			anhi->enum_retained_pd[domain] = true;
		observed = apple_nhi_enum_snapshot(anhi, domain, "after", ret);
		if (ret < 0)
			return ret;
		if (observed)
			return observed; /* Keep every acquired reference; no retry. */
	}
	return 0;
}

static void apple_nhi_enum_put(void *context)
{
	struct apple_nhi *anhi = context;

	lockdep_assert_held(&anhi->tb->lock);
	if (WARN_ON(anhi->enum_retained_prepare))
		return;
	pm_runtime_put_sync(anhi->enum_pd[1]);
	pm_runtime_put_sync(anhi->enum_pd[0]);
}

static const struct apple_apciec_supplier_ops apple_nhi_enum_supplier = {
	.get = apple_nhi_enum_get,
	.get_retained = apple_nhi_enum_get_retained,
	.put = apple_nhi_enum_put,
};

static int apple_nhi_enum_prepare_tunnel(struct tb_nhi *nhi, unsigned int port)
{
	struct apple_nhi *anhi = nhi_to_anhi(nhi);

	lockdep_assert_held(&anhi->tb->lock);
	if (!anhi->enum_bound || anhi->enum_stopping || port != anhi->enum_port)
		return -ESHUTDOWN;
	return apple_apciec_enum_prepare(anhi->enum_host, port);
}

static int apple_nhi_enum_enable(struct tb_nhi *nhi, unsigned int port)
{
	struct apple_nhi *anhi = nhi_to_anhi(nhi);

	lockdep_assert_held(&anhi->tb->lock);
	if (!anhi->enum_bound || anhi->enum_stopping || port != anhi->enum_port)
		return -ESHUTDOWN;
	return apple_apciec_enum_enable(anhi->enum_host, port);
}

static void apple_nhi_enum_disable(struct tb_nhi *nhi, unsigned int port)
{
	struct apple_nhi *anhi = nhi_to_anhi(nhi);

	lockdep_assert_held(&anhi->tb->lock);
	if (anhi->enum_bound && port == anhi->enum_port)
		apple_apciec_enum_disable(anhi->enum_host, port);
}

static void apple_nhi_enum_release(struct apple_nhi *anhi)
{
	int i;

	/* Only after quiesce/unbind and domain work flush; never on retention. */
	if (WARN_ON(anhi->enum_bound || anhi->enum_retained_prepare))
		return;
	for (i = 1; i >= 0; i--) {
		if (anhi->enum_pd[i])
			dev_pm_domain_detach(anhi->enum_pd[i], false);
		anhi->enum_pd[i] = NULL;
	}
	if (anhi->enum_host)
		put_device(anhi->enum_host);
	anhi->enum_host = NULL;
}

static int apple_nhi_enum_prepare(struct apple_nhi *anhi)
{
	static const char * const names[] = { "apciec-core", "apciec-port" };
	struct device_node *np;
	struct platform_device *host;
	int i, ret;

	if (!of_property_present(anhi->np, "research,apciec-host"))
		return 0;
	if (!of_machine_is_compatible("apple,j293"))
		return -ENODEV;
	np = of_parse_phandle(anhi->np, "research,apciec-host", 0);
	if (!np)
		return -EINVAL;
	if (!of_device_is_compatible(np, "research-only,apple-t8103-apciec-disabled")) {
		of_node_put(np);
		return -EINVAL;
	}
	/* A disabled research host is not an opt-in. Preserve ordinary NHI
	 * behavior without waiting forever for a deliberately absent device. */
	if (!of_device_is_available(np)) {
		of_node_put(np);
		return 0;
	}
	host = of_find_device_by_node(np);
	of_node_put(np);
	if (!host)
		return -EPROBE_DEFER;
	anhi->enum_host = &host->dev; /* of_find_device_by_node owns this ref */
	if (!dev_get_drvdata(anhi->enum_host)) {
		ret = -EPROBE_DEFER;
		goto fail;
	}
	for (i = 0; i < ARRAY_SIZE(names); i++) {
		struct device *pd = dev_pm_domain_attach_by_name(anhi->enum_host, names[i]);

		if (IS_ERR_OR_NULL(pd)) {
			ret = pd ? PTR_ERR(pd) : -ENODEV;
			goto fail;
		}
		anhi->enum_pd[i] = pd;
	}
	anhi->enum_stopping = true;
	anhi->enum_ops = *anhi->nhi.ops;
	anhi->enum_ops.pcie_tunnel_prepare = apple_nhi_enum_prepare_tunnel;
	anhi->enum_ops.pcie_tunnel_enable = apple_nhi_enum_enable;
	anhi->enum_ops.pcie_tunnel_disable = apple_nhi_enum_disable;
	anhi->nhi.ops = &anhi->enum_ops;
	return 0;
fail:
	apple_nhi_enum_release(anhi);
	return ret;
}

static int apple_nhi_enum_bind(struct apple_nhi *anhi)
{
	struct tb_switch *sw = anhi->tb->root_switch;
	struct tb_port *port;
	unsigned int count = 0, index = 0;
	int ret;

	lockdep_assert_held(&anhi->tb->lock);
	if (!anhi->enum_host)
		return 0;
	if (!sw || tb_route(sw))
		return -EINVAL;
	tb_switch_for_each_port(sw, port) {
		if (tb_port_is_pcie_down(port)) {
			count++;
			index = port->port;
		}
	}
	/* Explicit research policy, not a guessed connector-to-adapter map. */
	if (count != 1 || !index || index > 63)
		return -EINVAL;
	ret = apple_apciec_enum_bind(anhi->enum_host, anhi,
				    &apple_nhi_enum_supplier, index);
	if (ret)
		return ret;
	anhi->enum_port = index;
	anhi->enum_bound = true;
	anhi->enum_stopping = false;
	return 0;
}

static int apple_nhi_enum_quiesce_locked(struct apple_nhi *anhi)
{
	int ret;

	lockdep_assert_held(&anhi->tb->lock);
	anhi->enum_stopping = true;
	if (anhi->enum_retained_prepare)
		return -EBUSY;
	if (!anhi->enum_bound)
		return 0;
	apple_apciec_enum_disable(anhi->enum_host, anhi->enum_port);
	ret = apple_apciec_enum_unbind(anhi->enum_host);
	if (ret)
		return ret; /* Keep child/context, PMGR refs and ACIO alive. */
	anhi->enum_bound = false;
	return 0;
}

static int apple_cio_enum_quiesce_child(struct device *dev, void *unused)
{
	struct apple_nhi *anhi;
	int ret = 0;

	if (!of_device_is_compatible(dev->of_node, "apple,t8103-usb4-nhi"))
		return 0;
	/* Wait for any probe, including the boot-timeout cleanup path. No
	 * callback takes this device lock or acio->lock under the TB mutex. */
	device_lock(dev);
	anhi = dev_get_drvdata(dev);
	if (dev->driver && anhi && anhi->tb) {
		mutex_lock(&anhi->tb->lock);
		ret = apple_nhi_enum_quiesce_locked(anhi);
		mutex_unlock(&anhi->tb->lock);
	}
	device_unlock(dev);
	return ret;
}

static int apple_cio_enum_quiesce(struct apple_cio *acio)
{
	lockdep_assert_held(&acio->lock);
	return device_for_each_child(acio->dev, NULL, apple_cio_enum_quiesce_child);
}
#else
static int apple_nhi_enum_prepare(struct apple_nhi *anhi)
{
	struct device_node *np;
	bool available;

	if (!of_property_present(anhi->np, "research,apciec-host"))
		return 0;
	np = of_parse_phandle(anhi->np, "research,apciec-host", 0);
	if (!np)
		return -EINVAL;
	available = of_device_is_available(np);
	of_node_put(np);
	return available ? -EOPNOTSUPP : 0;
}
static int apple_nhi_enum_bind(struct apple_nhi *anhi) { return 0; }
static int apple_nhi_enum_quiesce_locked(struct apple_nhi *anhi) { return 0; }
static void apple_nhi_enum_release(struct apple_nhi *anhi) { }
static int apple_cio_enum_quiesce(struct apple_cio *acio) { return 0; }
#endif
