/* SPDX-License-Identifier: GPL-2.0 */
#ifndef APPLE_DART_J314S_SAMPLE_H
#define APPLE_DART_J314S_SAMPLE_H
/* Immutable pre-reset evidence from the ordinary retained provider attempt.
 * This snapshot is not an assertion of current translation/IRQ/DMA readiness. */
struct apple_dart_j314s_sample {
 unsigned int params[4], protect, ias, oas, sid_count, page_shift;
};
#ifdef __KERNEL__
struct device;
int apple_dart_j314s_sample_get(struct device *provider, struct device *host,
 struct apple_dart_j314s_sample *sample);
#endif
#endif
