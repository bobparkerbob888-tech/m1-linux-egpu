/* SPDX-License-Identifier: GPL-2.0 */
#ifndef BOB_TB_PAIR_ADMISSION_H
#define BOB_TB_PAIR_ADMISSION_H
#define TB_PAIR_PRIMARY_SERIAL PROVISION_PRIVATE_ID_6
static int pair_endpoint_admit_records(const struct ep_identity *records,unsigned count,
 const struct ep_identity **primary,const struct ep_identity **secondary)
{
 static const unsigned rids[]={0,0x100,0x200,0x300,0x208,0x400,0x500,0x600};
 static const u64 known[]={PROVISION_PRIVATE_ID_5,PROVISION_PRIVATE_ID_24,
  PROVISION_PRIVATE_ID_20,TB_PAIR_PRIMARY_SERIAL};
 unsigned seen=0,j,k;
 if(!primary||!secondary)return -EPERM;
 *primary=*secondary=NULL;
 if(!records||count!=8)return -EPERM;
 for(j=0;j<count;j++){
  const struct ep_identity *id=&records[j];
  for(k=0;k<8&&id->rid!=rids[k];k++);
  if(k==8||(seen&(1U<<k)))return -EPERM;
  seen|=1U<<k;
  if(id->rid==0x600||id->rid==0x300){
   if(id->id!=0x2d0410de||id->class_rev!=0x030000a1||id->subsystem!=0x41cd1458||
      id->header!=0x80||!id->serial||id->serial==~0ULL)return -EPERM;
   if(id->rid==0x600){if(id->serial!=TB_PAIR_PRIMARY_SERIAL)return -EPERM;
 *primary=id;}
   else{for(k=0;k<4;k++)if(id->serial==known[k])return -EPERM;*secondary=id;}
  }else{
   u64 serial=id->rid>=0x400?PROVISION_PRIVATE_ID_36:PROVISION_PRIVATE_ID_33;
   if(id->id!=(id->rid?0x57868086U:0x1010106bU)||
      id->class_rev!=(id->rid?0x06040085U:0x06040000U)||id->header!=1||
      (id->rid&&id->serial!=serial))return -EPERM;
  }
 }
 return seen==255&&*primary&&*secondary?0:-EPERM;
}
static int pair_endpoint_admit_snapshot(const struct ep_snapshot *s,
 const struct ep_identity *allowed)
{
 static const unsigned primary_path[]={0x500,0x400,0x208,0x100,0};
 static const unsigned secondary_path[]={0x200,0x100,0};
 struct ep_identity ids[8];const struct ep_identity *primary,*secondary,*selected;
 const unsigned *path;unsigned count,j;
 if(!s||!allowed||s->count!=8||s->selected>=8||!s->captured||!s->sized||
    !s->planned||!s->memory_assigned||s->same_device_mask!=1)return -EPERM;
 for(j=0;j<8;j++)ids[j]=s->functions[j].identity;
 if(pair_endpoint_admit_records(ids,8,&primary,&secondary))return -EPERM;
 if(allowed->rid==0x600){path=primary_path;count=5;selected=primary;}
 else if(allowed->rid==0x300){path=secondary_path;count=3;selected=secondary;}
 else return -EPERM;
 if(s->ancestor_count!=count||!endpoint_identity_equal(selected,allowed)||
    !endpoint_identity_equal(&s->functions[s->selected].identity,allowed))return -EPERM;
 for(j=0;j<count;j++)if(s->ancestors[j]>=8||s->functions[s->ancestors[j]].identity.rid!=path[j])return -EPERM;
 return 0;
}
#endif
