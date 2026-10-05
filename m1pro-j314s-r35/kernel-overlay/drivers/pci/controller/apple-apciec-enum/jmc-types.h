/* SPDX-License-Identifier: GPL-2.0 */
struct jmc_context {
 struct resource*claim_objects[64*2+12],*claim_parents[64*2+12];
 unsigned index;
 bool attached,scope,failed,claims_attempted,claimed,mmio_attempted,mmio_complete;
 struct pd_probe probe;
 unsigned tuple_kind,tuple_index,tuple_off,tuple_width;
 u32 tuple_before,tuple_after;bool armed,pending;
 u64 enabled,status_consumed;bool acs_done[64];
 void __iomem*bar0[JM_MAX_GPUS];u32 boot0[JM_MAX_GPUS][2];
};
