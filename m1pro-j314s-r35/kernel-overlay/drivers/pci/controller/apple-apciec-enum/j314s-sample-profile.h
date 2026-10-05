/* SPDX-License-Identifier: GPL-2.0 */
/* Measured R8 boot00a8dd66 provider proof, before any endpoint admission.
 * This is an exact target hardware profile, not inferred from ADT vm-size. */
static bool j314s_measured_dma_sample(const struct apple_dart_j314s_sample*s)
{
 static const u32 params[4]={0xaed83020,0x30110003,0x2a200100,0x00100040};
 return s&&!memcmp(s->params,params,sizeof(params))&&!s->protect&&
  s->ias==32&&s->oas==42&&s->sid_count==64&&s->page_shift==14;
}
