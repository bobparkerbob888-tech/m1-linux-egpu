/* SPDX-License-Identifier: GPL-2.0 */
#ifndef JPC5_PINS_H
#define JPC5_PINS_H
#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/string.h>
#include <linux/errno.h>
#else
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
typedef uint32_t u32;typedef uint64_t u64;
#endif
/* route is parent logical primary adapter (readiness core convention).
 * Wire routes are separate; never substitute physical secondary lane. */
struct jpc5_bootstrap_pins {
 u32 root[5],child_before[5],child_after[5];u64 uid;
 unsigned route,down,upstream,max_port,depth;u64 parent_route,child_route;
};
static bool jpc5_route_depth(u64 route,unsigned depth)
{
 if(!depth||depth>5)return false;
 for(unsigned j=0;j<depth;j++){unsigned p=route&255;if(!p||p>63)return false;route>>=8;}
 return !route;
}
static bool jpc5_bootstrap_pins_valid(const struct jpc5_bootstrap_pins*p)
{
 const u32 fresh[5]={0x57868087,0x8505c16b,0,0,0x4000000a};u32 after[5];
 if(!p||p->depth<2||p->depth>5||!jpc5_route_depth(p->parent_route,p->depth-1)||
    !jpc5_route_depth(p->child_route,p->depth)||!p->uid||p->uid==~0ULL||
    p->route<1||p->route>23||p->route==((p->root[1]>>8)&63)||
    !p->down||p->down>23||p->upstream!=1||p->max_port!=23||
    p->child_route!=(p->parent_route|((u64)p->route<<(8*(p->depth-1))))||
    p->root[0]!=fresh[0]||p->root[1]!=(fresh[1]|((p->depth-1)<<20))||
    p->root[2]!=(u32)p->parent_route||p->root[3]!=(0x80000000U|(u32)(p->parent_route>>32))||p->root[4]!=0x400020ff||
    memcmp(p->child_before,fresh,sizeof(fresh)))return false;
 memcpy(after,fresh,sizeof(after));after[1]|=p->depth<<20;after[2]=(u32)p->child_route;
 after[3]=0x80000000U|(u32)(p->child_route>>32);after[4]=0x400020ff;
 return !memcmp(after,p->child_after,sizeof(after));
}
#endif
