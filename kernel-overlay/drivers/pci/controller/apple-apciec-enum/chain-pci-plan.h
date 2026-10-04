/* SPDX-License-Identifier: GPL-2.0 */
#ifndef APPLE_CHAIN_PCI_PLAN_H
#define APPLE_CHAIN_PCI_PLAN_H
/* Fixed, bounded candidate topology, admitted only after each router's exact
 * DROM UID and each PCI bridge identity are verified. No broad bus scan. */
#define AM_FUNCTIONS 22
#define AM_GPU_COUNT 3
struct am_layout {
 unsigned rid, secondary, subordinate, gpu, enclosure;
 u64 pref_start, pref_end, mem_start, mem_end;
};
static const struct am_layout am_layout[AM_FUNCTIONS] = {
 {0,1,9,0,0,0x400000000ULL,0x451ffffffULL,0x480000000ULL,0x48bffffffULL},
 {0x100,2,9,0,0,0x400000000ULL,0x451ffffffULL,0x480000000ULL,0x48bffffffULL},
 {0x200,3,3,0,0,0x400000000ULL,0x411ffffffULL,0x480000000ULL,0x483ffffffULL},
 {0x300,0,0,1,0}, {0x301,0,0,0,0},
 {0x208,4,9,0,0,0x420000000ULL,0x451ffffffULL,0x484000000ULL,0x48bffffffULL},
 {0x210,0,0,0,0},{0x218,0,0,0,0},
 {0x400,5,9,0,1,0x420000000ULL,0x451ffffffULL,0x484000000ULL,0x48bffffffULL},
 {0x500,6,6,0,1,0x420000000ULL,0x431ffffffULL,0x484000000ULL,0x487ffffffULL},
 {0x600,0,0,2,1},{0x601,0,0,0,1},
 {0x508,7,9,0,1,0x440000000ULL,0x451ffffffULL,0x488000000ULL,0x48bffffffULL},
 {0x510,0,0,0,1},{0x518,0,0,0,1},
 {0x700,8,9,0,2,0x440000000ULL,0x451ffffffULL,0x488000000ULL,0x48bffffffULL},
 {0x800,9,9,0,2,0x440000000ULL,0x451ffffffULL,0x488000000ULL,0x48bffffffULL},
 {0x900,0,0,3,2},{0x901,0,0,0,2},
 {0x808,0,0,0,2},{0x810,0,0,0,2},{0x818,0,0,0,2},
};
static int am_index(unsigned rid)
{
 unsigned j;for(j=0;j<AM_FUNCTIONS;j++)if(am_layout[j].rid==rid)return j;return -1;
}
static u32 am_buses(unsigned j)
{
 const struct am_layout *a=&am_layout[j];
 return a->secondary ? (a->rid>>8)|(a->secondary<<8)|(a->subordinate<<16):0;
}
static bool am_window_value(unsigned j,unsigned off,u32 *value)
{
 const struct am_layout *a=&am_layout[j];u64 start,end;
 if(!a->secondary||j==2)return false; /* first card's private bridge stays intact */
 if(off==0x20){start=a->mem_start-0x400000000ULL;end=a->mem_end-0x400000000ULL;
  *value=((start>>16)&0xfff0)|(end&0xfff00000);return true;}
 if(off==0x24){*value=((a->pref_start>>16)&0xfff0)|(a->pref_end&0xfff00000)|0x10001;return true;}
 if(off==0x28){*value=a->pref_start>>32;return true;}
 if(off==0x2c){*value=a->pref_end>>32;return true;}
 return false;
}
#endif
