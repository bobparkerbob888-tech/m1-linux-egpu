/* Endpoint planning consumes the already verified raw identity transaction.
 * Optional memory assignment does not grant PCI registration, decode or DMA. */
#include "endpoint-resource-types.h"
#include "endpoint-admission.h"
static int apple_endpoint_proof(struct external_ticket *t)
{
 int ret;
 mutex_lock(&t->acio->lock); mutex_lock(&t->tb->lock);
 ret = t->endpoint_resources && t->raw_identity && t->tunnel &&
       t->tunnel->phase == 6 && t->tunnel->programmed == 4 && t->tunnel->pe == 3 ?
       pt_gate(t->tunnel) : -EPERM;
 if (!ret) ret = apple_pt_proof(t, 3);
 if (!ret) ret = pt_verify(t->tunnel);
 mutex_unlock(&t->tb->lock); mutex_unlock(&t->acio->lock);
 return ret;
}
static int apple_retained_endpoint_plan(struct external_ticket *t)
{
 const struct ep_identity *records = NULL;
 const struct ep_snapshot *snapshot = NULL;
 unsigned count = 0, phase = 0;
 int ret, host_audit, proof;
 if (!t->endpoint_resources || !t->raw_identity || t->endpoint_attempted) return -EPERM;
 t->endpoint_attempted = true; /* Even an early proof failure cannot be retried. */
 ret = external_outside_gate(t);
 if (!ret) ret = apple_apciec_retained_raw_final_audit(t->host, 3, t);
 if (!ret) ret = apple_endpoint_proof(t);
 if (!ret) ret = apple_apciec_retained_records(t->host, 3, t, &records, &count);
 if (!ret) ret = endpoint_admit_records(records, count);
 if (!ret) {
  ret = apple_apciec_retained_endpoint_resources(t->host, 3, t,
                                                &endpoint_allowed, true, t->endpoint_memory_assign, &snapshot, &phase);
  t->endpoint_phase = phase;
  if (!ret && phase != (t->endpoint_memory_assign ? 14U : 12U)) ret = -EPERM;
  if (phase != 0 && phase != 11 && phase != 12 &&
      (!t->endpoint_memory_assign || (phase != 13 && phase != 14))) {
   if (!ret) ret = -EPERM;
  }
  if (!ret && (!snapshot || !snapshot->captured || !snapshot->sized ||
               !snapshot->planned || snapshot->memory_assigned != t->endpoint_memory_assign ||
               snapshot->selected >= snapshot->count ||
               !endpoint_identity_equal(&snapshot->functions[snapshot->selected].identity,
                                        &endpoint_allowed))) ret = -EPERM;
 }
 /* Always audit, including partial sizing/error. Preserve the original error. */
 host_audit = external_outside_gate(t);
 if (!host_audit) host_audit = apple_apciec_retained_raw_final_audit(t->host, 3, t);
 proof = apple_endpoint_proof(t);
 if (!ret) ret = host_audit;
 if (!ret) ret = proof;
 /* Preserve truthful host phase14 even if a later outer proof rejects it. */
 dev_info(t->anhi->dev,"%s: post-transaction status %d host audit %d context/PE/Hop proof %d phase %u; no decode or DMA permit\n",
          t->endpoint_memory_assign?"retained-memory-assignment":"retained-endpoint-plan",
          ret, host_audit, proof, t->endpoint_phase);
 /* Consume standard PCI discovery only after this boot's outer acceptance. */
 if (!ret && apple_apciec_endpoint_pci_enabled()) {
  if (!t->endpoint_memory_assign || t->endpoint_phase != 14) return -EPERM;
  ret = apple_apciec_retained_register_pci(t->host, 3, t, &t->endpoint_phase);
  host_audit = external_outside_gate(t);
  if (!host_audit) host_audit = apple_apciec_retained_raw_final_audit(t->host, 3, t);
  proof = apple_endpoint_proof(t);
  if (!ret) ret = host_audit;
  if (!ret) ret = proof;
  if (!ret && t->endpoint_phase != 16) ret = -EPERM;
  dev_info(t->anhi->dev, "retained-pci-register: outer status %d host audit %d context/PE/Hop proof %d phase %u\n",
           ret, host_audit, proof, t->endpoint_phase);
 }
 if (!ret && apple_apciec_endpoint_mmio_enabled()) {
  if (t->endpoint_phase != 16) return -EPERM;
  ret = apple_apciec_retained_probe_mmio(t->host, 3, t, &t->endpoint_phase);
  host_audit = external_outside_gate(t);
  if (!host_audit) host_audit = apple_apciec_retained_raw_final_audit(t->host, 3, t);
  proof = apple_endpoint_proof(t);
  if (!ret) ret = host_audit;
  if (!ret) ret = proof;
  if (!ret && t->endpoint_phase != 18) ret = -EPERM;
  dev_info(t->anhi->dev, "retained-mmio-probe: outer status %d host audit %d context/PE/Hop proof %d phase %u\n",
           ret, host_audit, proof, t->endpoint_phase);
 }
 if (!ret && apple_apciec_endpoint_native_enabled()) {
  if (t->endpoint_phase != 18) return -EPERM;
  ret = external_outside_gate(t);
  if (!ret) ret = apple_endpoint_proof(t);
  if (!ret) ret = apple_apciec_retained_native_prepare(t->host, 3, t, &t->endpoint_phase);
  /* Native state now has one paging client. Do not call the all-blocked audit. */
  host_audit = proof = -EINPROGRESS;
  if (!ret) ret = host_audit = apple_apciec_retained_native_audit(t->host, 3, t);
  if (!ret) ret = proof = apple_endpoint_proof(t);
  dev_info(t->anhi->dev, "native-final-audit: host%d context/PE/Hop%d phase%u\n", host_audit, proof, t->endpoint_phase);
  if (!ret && t->endpoint_phase != 20) ret = -EPERM;
  dev_info(t->anhi->dev, "retained-native-driver: outer status %d phase %u; selected native preparation only\n", ret, t->endpoint_phase);
 }
 return ret;
}
