/* SPDX-License-Identifier: GPL-2.0 */
#ifndef J314S_OWNER_CORE_H
#define J314S_OWNER_CORE_H
#define J314S_NATIVE_PHASE_COMMITTED 40U
#define J314S_OWNER_MAX_CLIENTS 9U
/* Shape checks shared with host harness. Does not assert hardware ownership. */
static bool j314s_owner_shape(unsigned count,const unsigned *rids,
                             const unsigned *sids,unsigned ias,unsigned oas)
{
 unsigned i,j;
 if(!count||count>J314S_OWNER_MAX_CLIENTS||!rids||!sids||ias<32||ias>oas||
    (oas!=36&&oas!=42))return false;
 for(i=0;i<count;i++) {
  if(!rids[i]||rids[i]>0xffff||!sids[i]||sids[i]>=64||sids[i]==15)return false;
  for(j=0;j<i;j++)if(rids[i]==rids[j]||sids[i]==sids[j])return false;
 }
 return true;
}
#endif
