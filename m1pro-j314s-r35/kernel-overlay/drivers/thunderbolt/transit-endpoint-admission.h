/* SPDX-License-Identifier: GPL-2.0 */
#ifndef APPLE_TRANSIT_ENDPOINT_ADMISSION_H
#define APPLE_TRANSIT_ENDPOINT_ADMISSION_H
/* One recorded transit path, not a generic enumeration policy. The GPU serial
 * is captured on this boot beneath both exact physical enclosure identities. */
static int transit_endpoint_admit_records(const struct ep_identity *records,
 unsigned count, const struct ep_identity **selected)
{
 static const unsigned rids[]={0,0x100,0x200,0x208,0x400,0x500,0x600};
 unsigned seen=0,j,k;
 if(!selected)return -EPERM;
 *selected=NULL;
 if(!records||count!=7)return -EPERM;
 for(j=0;j<count;j++) {
  const struct ep_identity *id=&records[j];
  for(k=0;k<7&&id->rid!=rids[k];k++);
  if(k==7||(seen&(1U<<k)))return -EPERM;
  seen|=1U<<k;
  if(id->rid==0x600) {
   if(id->id!=0x2d0410de||id->class_rev!=0x030000a1||
      id->subsystem!=0x41cd1458||id->header!=0x80||
      !id->serial||id->serial==~0ULL)return -EPERM;
   *selected=id;
  } else {
   u64 serial=id->rid>=0x400?PROVISION_PRIVATE_ID_36:PROVISION_PRIVATE_ID_33;
   if(id->id!=(id->rid?0x57868086U:0x1010106bU)||
      id->class_rev!=(id->rid?0x06040085U:0x06040000U)||id->header!=1||
      (id->rid&&id->serial!=serial))return -EPERM;
  }
 }
 return seen==127&&*selected?0:-EPERM;
}
static int transit_endpoint_admit_snapshot(const struct ep_snapshot *s,
 const struct ep_identity *allowed,bool assigned)
{
 static const unsigned ancestors[]={0x500,0x400,0x208,0x100,0};
 struct ep_identity ids[7];const struct ep_identity *selected=NULL;
 unsigned j;
 if(!s||!allowed||s->count!=7||s->selected>=7||s->ancestor_count!=5||
    !s->captured||!s->sized||!s->planned||s->memory_assigned!=assigned)return -EPERM;
 for(j=0;j<7;j++)ids[j]=s->functions[j].identity;
 if(transit_endpoint_admit_records(ids,7,&selected)||
    !endpoint_identity_equal(&s->functions[s->selected].identity,allowed)||
    !endpoint_identity_equal(selected,allowed))return -EPERM;
 for(j=0;j<5;j++)
  if(s->ancestors[j]>=7||s->functions[s->ancestors[j]].identity.rid!=ancestors[j])return -EPERM;
 return 0;
}
#endif
