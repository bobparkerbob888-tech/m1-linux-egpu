/* SPDX-License-Identifier: GPL-2.0 */
#include "transit-endpoint-admission.h"
/* Read both retained tunnels and enclosure identity after every stage. This
 * never invokes the phase8-only host audit and never writes Hop/PE state. */
static int apple_transit_tunnel_proof(struct external_ticket *t)
{
 struct chain_tunnel_context *c;
 int ret;
 if(t->controller!=1||bob_chain_count(t->controller)!=2||!t->tunnel||
    t->tunnel->phase!=6||t->tunnel->programmed!=4||t->tunnel->pe!=3)return -EPERM;
 c=READ_ONCE(chain_tunnel_owner[1][0]);
 if(!c||c->ticket!=t||c->child!=1||c->state.phase!=5||
    c->state.programmed!=4||c->state.pe!=3)return -EPERM;
 mutex_lock(&t->acio->lock);mutex_lock(&t->tb->lock);
 ret=pt_gate(t->tunnel);
 if(!ret)ret=apple_pt_proof(t,3);
 if(!ret)ret=pt_verify(t->tunnel);
 if(!ret)ret=chain_tunnel_identity_proof(c,3);
 if(!ret)ret=pt_verify(&c->state);
 mutex_unlock(&t->tb->lock);mutex_unlock(&t->acio->lock);
 return ret;
}
static int apple_retained_transit_endpoint_plan(struct external_ticket *t)
{
 const struct ep_identity *records=NULL,*allowed=NULL;
 const struct ep_snapshot *snapshot=NULL;
 unsigned count=0,phase=0;
 int ret,proof,audit;
 if(t->controller!=1||!t->endpoint_resources||!t->raw_identity||
    t->endpoint_attempted||t->endpoint_phase!=10)return -EPERM;
 t->endpoint_attempted=true; /* No retry after any result, including proof failure. */
 ret=external_outside_gate(t);
 if(!ret&&apple_apciec_controller_index(t->host)!=1)ret=-EPERM;
 if(!ret)ret=apple_transit_tunnel_proof(t);
 if(!ret)ret=apple_apciec_retained_records(t->host,3,t,&records,&count);
 if(!ret)ret=transit_endpoint_admit_records(records,count,&allowed);
 if(!ret) {
  ret=apple_apciec_retained_endpoint_resources(t->host,3,t,allowed,true,
       t->endpoint_memory_assign,&snapshot,&phase);
  t->endpoint_phase=phase;
  if(!ret&&phase!=(t->endpoint_memory_assign?14U:12U))ret=-EPERM;
  if(!ret)ret=transit_endpoint_admit_snapshot(snapshot,allowed,t->endpoint_memory_assign);
 }
 /* Resource API owns the all-blocked DART/config audit, including partial
  * failures. Independent outer proof cannot erase its truthful failure phase. */
 audit=external_outside_gate(t);
 proof=apple_transit_tunnel_proof(t);
 if(!ret)ret=audit;
 if(!ret)ret=proof;
 dev_info(t->anhi->dev,"transit-endpoint-resources: status%d context%d tunnel-proof%d phase%u; no native permit\n",
          ret,audit,proof,t->endpoint_phase);
 if(!ret&&apple_apciec_endpoint_native_enabled()) {
  if(!t->endpoint_memory_assign||t->endpoint_phase!=14||
     !apple_apciec_endpoint_pci_enabled()||!apple_apciec_endpoint_mmio_enabled())return -EPERM;
  ret=external_outside_gate(t);
  if(!ret)ret=apple_transit_tunnel_proof(t);
  if(!ret)ret=apple_apciec_retained_transit_native_prepare(t->host,3,t,&t->endpoint_phase);
  /* Native may own a paging domain now. Never run all-blocked DART audit. */
  audit=-EINPROGRESS;
  if(!ret)ret=audit=apple_apciec_retained_transit_native_audit(t->host,3,t);
  proof=apple_transit_tunnel_proof(t);
  if(!ret)ret=proof;
  if(!ret&&t->endpoint_phase!=20)ret=-EPERM;
  dev_info(t->anhi->dev,"transit-native-driver: outer status%d native-audit%d tunnel-proof%d phase%u; selected RID0600, excluded0300/0301 untouched\n",
           ret,audit,proof,t->endpoint_phase);
 }
 return ret;
}
