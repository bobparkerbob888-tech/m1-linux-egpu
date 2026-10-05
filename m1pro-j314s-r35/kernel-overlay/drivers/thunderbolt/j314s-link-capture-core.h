/* SPDX-License-Identifier: GPL-2.0 */
#include "j314s-child-capture-core.h"
/* TARGET DRAFT: controller0 retained owner must bind callbacks and hold ACIO
 * and TB locks. Root descriptor is measured2001; child identity is unknown.
 * Writes are explicit: cable-information once, selected-lane unlock once. */
struct j314s_link_io {
 int (*read)(void *,unsigned,unsigned,bool,unsigned,unsigned,u32 *);
 int (*write)(void *,unsigned,bool,unsigned,u32); /* root route0 only */
 bool (*valid)(void *); /* ALSO exact immutable retained Type-C snapshot */
 bool (*expired)(void *);
 void (*poll_delay)(void *); /* bounded20ms, sleep allowed under owner locks */
 void *ctx;bool attempted;unsigned operations;
 unsigned primary,secondary;bool pair_verified;
};
struct j314s_link_result {
 u32 root[5],ports[8][8],phy[8][2],caps[64][2];
 u32 selected_after_training[8];bool selected_after_read;
 u32 pair_before_unlock[3][8],pair_unlock_before[3],pair_unlock_after[3];
 bool pair_header_read[3],pair_write_attempted[3],pair_unlock_verified[3];
 unsigned primary,secondary;
 unsigned cap_offsets[64],nr_caps,phy_offsets[8],lane;
 u32 cable_before,cable_after,unlock_before,unlock_after;
 bool cable_write_attempted,cable_verified,unlock_write_attempted,unlock_verified;
 struct j314s_child_observation child;
};
static int j314s_link_gate(struct j314s_link_io *io)
{
 if(!io->valid(io->ctx))return -EPERM;
 return io->expired(io->ctx)||io->operations>=512?-ETIMEDOUT:0;
}
static int j314s_link_read(void *ctx,unsigned route,unsigned port,bool sw,unsigned off,unsigned n,u32*v)
{
 struct j314s_link_io*io=ctx;int ret=j314s_link_gate(io);
 if(ret)return ret;
 if(!n||n>8||off>0x1fff||n>0x2000-off||route>7||port>7)return -EINVAL;
 io->operations++;ret=io->read(io->ctx,route,port,sw,off,n,v);
 return ret?ret:j314s_link_gate(io);
}
static int j314s_link_write(struct j314s_link_io *io,unsigned port,bool sw,unsigned off,u32 v)
{
 int ret=j314s_link_gate(io);if(ret)return ret;
 io->operations++;ret=io->write(io->ctx,port,sw,off,v);
 return ret?ret:j314s_link_gate(io);
}
static bool j314s_link_valid(void *ctx){struct j314s_link_io*io=ctx;return io->valid(io->ctx);}
static bool j314s_link_expired(void *ctx){struct j314s_link_io*io=ctx;return io->expired(io->ctx)||io->operations>=512;}
static int j314s_link_capture_once(struct j314s_link_io *io,u32 cable,struct j314s_link_result *r)
{
 static const u32 exact_root[5]={0x200105ac,0x0001c71b,0,0x80000000,0x200010ff};
 const u32 allowed=0x31f; /* PRESENT/orientation/active/bidirectional/20G/legacy/TBT3 */
 struct j314s_child_pins pins={0};struct j314s_child_io childio={0};
 unsigned seen[64],off,n=0,i,j,applecap=0,round;u32 words[2],before[8],root[5];int ret;
 if(!io||!r||!io->read||!io->write||!io->valid||!io->expired||!io->poll_delay)return -EINVAL;
 memset(r,0,sizeof(*r));if(io->attempted)return -EALREADY;io->attempted=true;
 if(!io->pair_verified||io->primary!=1||io->secondary!=2)return -EPERM;
 r->primary=io->primary;r->secondary=io->secondary;
 if(!(cable&1)||(cable&~allowed)||((cable&8)&&!(cable&4))||((cable&0x100)&&!(cable&0x200)))return -EINVAL;
 ret=j314s_link_read(io,0,0,true,0,5,r->root);if(ret)return ret;
 if(memcmp(r->root,exact_root,sizeof(exact_root)))return -ESTALE;
 off=r->root[1]&255;
 while(off) {
  if(off<5||off>0x1ffe||n==64)return -EINVAL;
  for(i=0;i<n;i++)if(seen[i]==off)return -ELOOP;
  seen[n]=off;ret=j314s_link_read(io,0,0,true,off,2,words);if(ret)return ret;
  r->cap_offsets[n]=off;memcpy(r->caps[n],words,8);r->nr_caps=++n;
  if(((words[0]>>8)&255)==3){off=words[0]&255;continue;}
  if(((words[0]>>8)&255)!=5)return -EOPNOTSUPP;
  if(!(words[0]>>24)) {
   if((words[0]&255)||!((words[0]>>16)&255))return -EOPNOTSUPP;
   off=words[1]&0xffff;continue;
  }
  if(!((words[0]>>16)&255)) {
   if((words[0]>>24)<2||(words[0]>>24)>0x2000-off)return -EINVAL;
   applecap=off;break;
  }
  off=words[0]&255;
 }
 if(!applecap)return -ENOENT;
 /* Capture ALL actual root adapter headers and bounded PHY capability offsets
  * before changing cable handoff. No literal lane1/route1/down3 mapping. */
 for(i=1;i<=7;i++) {
  ret=j314s_link_read(io,0,i,false,0,8,r->ports[i]);if(ret)return ret;
  if(((r->ports[i][3]>>20)&63)!=i)return -EPROTO;
  if((r->ports[i][2]&0xffffff)!=1)continue;
  off=r->ports[i][1]&255;n=0;
  while(off) {
   if(off<8||off>254||n==64)return -EINVAL;
   for(j=0;j<n;j++)if(seen[j]==off)return -ELOOP;
   seen[n++]=off;
   ret=j314s_link_read(io,0,i,false,off,2,words);if(ret)return ret;
   if(((words[0]>>8)&255)==1)break;
   off=words[0]&255;
  }
  if(!off)return -ENOENT;
  r->phy_offsets[i]=off;memcpy(r->phy[i],words,8);
 }
 ret=j314s_link_read(io,0,0,true,applecap+1,1,&r->cable_before);if(ret)return ret;
 if(r->cable_before)return -EBUSY; /* No replacement of an existing handoff. */
 ret=j314s_link_read(io,0,0,true,0,5,root);if(ret)return ret;
 if(memcmp(root,exact_root,sizeof(root)))return -ESTALE;
 r->cable_write_attempted=true;
 ret=j314s_link_write(io,0,true,applecap+1,cable);if(ret)return ret;
 ret=j314s_link_read(io,0,0,true,applecap+1,1,&r->cable_after);if(ret)return ret;
 if(r->cable_after!=cable)return -EIO;
 r->cable_verified=true;
 /* Native tb_start unlocks every downstream lane before scanning. Restrict
  * that operation to the exact pinned DROM pair1(primary)<->2(secondary). */
 for(i=r->primary;i<=r->secondary;i++) {
  if(!r->phy_offsets[i]||(r->ports[i][2]&0xffffff)!=1)return -EPERM;
  ret=j314s_link_read(io,0,i,false,0,8,r->pair_before_unlock[i]);if(ret)return ret;
  r->pair_header_read[i]=true;
  if(!j314s_lane_identity_equal(r->pair_before_unlock[i],r->ports[i]))return -ESTALE;
  r->pair_unlock_before[i]=r->pair_before_unlock[i][4];
  r->pair_unlock_after[i]=r->pair_unlock_before[i]&~0x80000000U;
  if(r->pair_unlock_after[i]!=r->pair_unlock_before[i]) {
   r->pair_write_attempted[i]=true;r->unlock_write_attempted=true;
   ret=j314s_link_write(io,i,false,4,r->pair_unlock_after[i]);if(ret)return ret;
  }
  ret=j314s_link_read(io,0,i,false,4,1,&words[0]);if(ret)return ret;
  if(words[0]!=r->pair_unlock_after[i])return -EIO;
  r->pair_unlock_verified[i]=true;
 }
 r->unlock_before=r->pair_unlock_before[r->primary];r->unlock_after=r->pair_unlock_after[r->primary];
 r->unlock_verified=true;
 /* Read both physical states. Logicalroute is always DROM primary; ready
  * physical lane may be primary, secondary, or both. State7 stays unplugged. */
 for(round=0;round<100;round++) {
  bool ready[3]={false};
  for(i=r->primary;i<=r->secondary;i++) {
   unsigned state;
   ret=j314s_link_read(io,0,i,false,r->phy_offsets[i],2,r->phy[i]);if(ret)return ret;
   if(((r->phy[i][0]>>8)&255)!=1)return -ESTALE;
   state=(r->phy[i][1]>>26)&15;
   ready[i]=state>=2&&state<=6&&!(r->phy[i][1]&(1U<<14));
  }
  if(ready[r->primary]){r->lane=r->primary;break;}
  /* Allow the native primary a bounded1second settling window even when
   * secondary trains first. Read-only observation is not a new attempt. */
  if(ready[r->secondary]&&round>=50){r->lane=r->secondary;break;}
  io->poll_delay(io->ctx);
 }
 if(!r->lane)return -ENOLINK;
 memcpy(r->selected_after_training,r->pair_before_unlock[r->lane],sizeof(before));r->selected_after_read=true;
 pins.lane=r->lane;pins.route=r->primary;memcpy(pins.root,r->root,sizeof(pins.root));
 memcpy(pins.lane_header,r->pair_before_unlock[r->lane],sizeof(pins.lane_header));pins.lane_header[4]=r->pair_unlock_after[r->lane];
 memcpy(pins.control_header,r->pair_before_unlock[r->primary],sizeof(pins.control_header));pins.control_header[4]=r->pair_unlock_after[r->primary];

 childio=(struct j314s_child_io){.read=j314s_link_read,.valid=j314s_link_valid,.expired=j314s_link_expired,.ctx=io};
 return j314s_child_capture_once(&childio,&pins,&r->child);
}
