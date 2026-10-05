/* SPDX-License-Identifier: GPL-2.0-only OR MIT */
#ifndef _LINUX_APPLE_PMGR_DIAGNOSTIC_H
#define _LINUX_APPLE_PMGR_DIAGNOSTIC_H

#include <linux/errno.h>
#include <linux/kconfig.h>
#include <linux/types.h>

struct device;

/* Diagnostic only. Caller owns a live virtual device returned by
 * dev_pm_domain_attach_by_name() for the retained J293 APCIEC host, and
 * serializes detach. domain is 0=apciec-core or 1=apciec-port. No state write.
 * The snapshot does not assert domain readiness or reset deassertion.
 */
#if IS_ENABLED(CONFIG_APPLE_PMGR_PWRSTATE)
int apple_pmgr_retained_snapshot(struct device *attached, unsigned int domain,
                               u32 *value);
#else
static inline int apple_pmgr_retained_snapshot(struct device *attached,
                                               unsigned int domain, u32 *value)
{
 return -EOPNOTSUPP;
}
#endif
#endif
