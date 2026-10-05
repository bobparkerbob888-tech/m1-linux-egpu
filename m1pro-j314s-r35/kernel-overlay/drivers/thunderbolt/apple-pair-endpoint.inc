/* SPDX-License-Identifier: GPL-2.0 */
#include "pair-endpoint-admission.h"
extern int apple_apciec_retained_pair_resources(struct device *,unsigned,const void *,
 const struct ep_snapshot **,const struct ep_snapshot **,unsigned *);
extern int apple_apciec_retained_pair_native_prepare(struct device *,unsigned,const void *,unsigned *);
extern int apple_apciec_retained_pair_native_audit(struct device *,unsigned,const void *);
static int apple_retained_pair_endpoint_plan(struct external_ticket *t)
{
 const struct ep_identity *records=NULL,*primary=NULL,*secondary=NULL;
 const struct ep_snapshot *s600=NULL,*s300=NULL;
 unsigned count=0,phase=0,j,k;
 int ret,audit,proof;
 if(t->controller!=1||!t->endpoint_pair||!t->endpoint_resources||!t->raw_identity||
    !t->endpoint_memory_assign||t->endpoint_attempted||t->endpoint_phase!=10||
    !apple_apciec_endpoint_pair_enabled()||!apple_apciec_endpoint_native_enabled()||
    !apple_apciec_endpoint_pci_enabled()||!apple_apciec_endpoint_mmio_enabled())return -EPERM;
 t->endpoint_attempted=true;
 ret=external_outside_gate(t);
 if(!ret&&apple_apciec_controller_index(t->host)!=1)ret=-EPERM;
 if(!ret)ret=apple_transit_tunnel_proof(t);
 if(!ret)ret=apple_apciec_retained_records(t->host,3,t,&records,&count);
 if(!ret)ret=pair_endpoint_admit_records(records,count,&primary,&secondary);
 if(!ret){
  ret=apple_apciec_retained_pair_resources(t->host,3,t,&s600,&s300,&phase);
  t->endpoint_phase=phase;
  if(!ret&&(phase!=14||!s600||!s300||s600==s300))ret=-EPERM;
  if(!ret)ret=pair_endpoint_admit_snapshot(s600,primary);
  if(!ret)ret=pair_endpoint_admit_snapshot(s300,secondary);
  /* Both independently selected snapshots must describe the retained graph. */
  for(j=0;!ret&&j<count;j++){
   for(k=0;k<count;k++)if(s600->functions[k].identity.rid==records[j].rid)break;
   if(k==count||!endpoint_identity_equal(&s600->functions[k].identity,&records[j]))ret=-EPERM;
   for(k=0;k<count;k++)if(s300->functions[k].identity.rid==records[j].rid)break;
   if(k==count||!endpoint_identity_equal(&s300->functions[k].identity,&records[j]))ret=-EPERM;
  }
 }
 /* Resources own blocked-DART/config auditing, including partial failure. */
 audit=external_outside_gate(t);proof=apple_transit_tunnel_proof(t);
 if(!ret)ret=audit;
 if(!ret)ret=proof;
 dev_info(t->anhi->dev,"pair-endpoint-resources: status%d context%d tunnel-proof%d phase%u; no native permit\n",ret,audit,proof,t->endpoint_phase);
 if(!ret){
  ret=external_outside_gate(t);
  if(!ret)ret=apple_transit_tunnel_proof(t);
  if(!ret)ret=apple_apciec_retained_pair_native_prepare(t->host,3,t,&t->endpoint_phase);
  audit=-EINPROGRESS;
  if(!ret)ret=audit=apple_apciec_retained_pair_native_audit(t->host,3,t);
  proof=apple_transit_tunnel_proof(t);
  if(!ret)ret=proof;
  if(!ret&&t->endpoint_phase!=30)ret=-EPERM;
  dev_info(t->anhi->dev,"pair-native-driver: outer status%d native-audit%d tunnel-proof%d phase%u; targets0600+0300 only\n",ret,audit,proof,t->endpoint_phase);
 }
 return ret;
}
