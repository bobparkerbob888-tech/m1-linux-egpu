/* SPDX-License-Identifier: GPL-2.0 */
#ifndef J314S_BOOTSTRAP_PINS_H
#define J314S_BOOTSTRAP_PINS_H
#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/string.h>
#include <linux/errno.h>
#else
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
typedef uint32_t u32;
typedef uint64_t u64;
#endif
/* Immutable exact identity supplied by compiled profile, never userspace.
 * Child route is the actual captured root lane; transport uses logical0/1. */
struct j314s_bootstrap_pins {
 u32 root[5],child_before[5],child_after[5];u64 uid;
 unsigned lane,route,down,upstream,max_port;
};
/* Identity and LCK remain stable across inventory; live credits/status are
 * observations, not identity. PE is independently checked in its capability. */
static bool j314s_adapter_identity_equal(const u32*a,const u32*b)
{
 return a[0]==b[0]&&a[1]==b[1]&&a[2]==b[2]&&
  !((a[3]^b[3])&0x03f00000U)&&!((a[4]^b[4])&0x80000000U)&&
  !((a[5]^b[5])&0x003fffffU);
}
static bool j314s_bootstrap_pins_valid(const struct j314s_bootstrap_pins*p)
{
 static const u32 root[5]={0x200105ac,0x1c71b,0,0x80000000,0x200010ff};
 u32 desired[5];unsigned version;
 if(!p||memcmp(p->root,root,sizeof(root))||!p->uid||p->uid==~0ULL||
    (p->lane!=1&&p->lane!=2)||p->route!=1||p->down!=3||!p->upstream||p->upstream>p->max_port||
    !p->max_port||p->max_port>63||!p->child_before[0]||p->child_before[0]==~0U||
    ((p->child_before[1]>>14)&63)!=p->max_port||
    ((p->child_before[1]>>8)&63)!=p->upstream||
    ((p->child_before[1]>>20)&7)||p->child_before[2]||p->child_before[3])return false;
 version=p->child_before[4]>>29;if(version!=1&&version!=2)return false;
 memcpy(desired,p->child_before,sizeof(desired));
 desired[1]=(desired[1]&~(7U<<20))|(1U<<20);
 desired[2]=p->route;desired[3]=0x80000000;
 desired[4]=(desired[4]&~0xffffU)|(version==1?0x10ff:0x20ff);
 return !memcmp(desired,p->child_after,sizeof(desired));
}
/* Only the already implemented Intel5786 USB4v2 register schema is admitted.
 * UID is copied from the original retained sameboot stable observation. */
static bool j314s_bootstrap_bind_capture(struct j314s_bootstrap_pins*p,
 const u32*root,const u32*header,const u32*uid,unsigned physical,unsigned route)
{
 static const u32 intel[5]={0x57868087,0x8505c16b,0,0,0x4000000a};
 if(!p||!root||!header||!uid||memcmp(header,intel,sizeof(intel)))return false;
 memset(p,0,sizeof(*p));memcpy(p->root,root,20);memcpy(p->child_before,header,20);memcpy(p->child_after,header,20);
 p->uid=((u64)uid[0]<<32)|uid[1];p->lane=physical;p->route=route;p->down=3;p->upstream=1;p->max_port=23;
 p->child_after[1]|=1U<<20;p->child_after[2]=route;p->child_after[3]=0x80000000;p->child_after[4]=0x400020ff;
 return j314s_bootstrap_pins_valid(p);
}
#endif
