/* SPDX-License-Identifier: GPL-2.0 */
/* Exact controller1 selected-target graph. Excluded GPU0300/0301 never allowed. */
#ifndef BOB_TRANSIT_NATIVE_POLICY_H
#define BOB_TRANSIT_NATIVE_POLICY_H
#define TN_FUNCTIONS 7
#define TN_GPU_INDEX 6
struct tn_position { unsigned rid, parent, secondary, subordinate; bool forwarding; };
static const struct tn_position tn_positions[TN_FUNCTIONS] = {
 {0,~0U,1,6,true},{0x100,0,2,6,true},{0x200,1,0,0,false},
 {0x208,1,4,6,true},{0x400,3,5,6,true},{0x500,4,6,6,true},{0x600,5,0,0,false}
};
static int tn_index(unsigned rid)
{unsigned j;for(j=0;j<TN_FUNCTIONS;j++)if(tn_positions[j].rid==rid)return j;return -1;}
static unsigned tn_initial_command(unsigned rid)
{int i=tn_index(rid);return i<0?0:i==TN_GPU_INDEX?2:tn_positions[i].forwarding?6:0;}
static bool tn_command_ok(unsigned rid,unsigned value,bool before_driver)
{
 int i=tn_index(rid);unsigned want=tn_initial_command(rid);
 if(i<0||value>0xffff)return false;
 if(before_driver||!want)return value==want;
 return (value&want)==want && !(value&~(2U|4U|0x400U));
}
static bool tn_bar(unsigned bar,u64 *pci,u64 *cpu,u64 *size,unsigned *type)
{
 if(bar==0){*pci=0x04000000ULL;*cpu=0x604000000ULL;*size=0x04000000ULL;*type=0;return true;}
 if(bar==1){*pci=*cpu=0x580000000ULL;*size=0x10000000ULL;*type=12;return true;}
 if(bar==3){*pci=*cpu=0x590000000ULL;*size=0x02000000ULL;*type=12;return true;}
 return false;
}
static bool tn_window(unsigned rid,unsigned off,u32 *value)
{
 int i=tn_index(rid);
 if(i<0||!tn_positions[i].forwarding)return false;
 switch(off){
 case 0x20:*value=0x07f00400;return true;
 case 0x24:*value=0x91f18001;return true;
 case 0x28:case 0x2c:*value=5;return true;
 default:return false;
 }
}
static bool tn_expected_write(unsigned step,unsigned rid,unsigned off,u32 value)
{
 static const unsigned rr[5]={0,0x100,0x208,0x400,0x500};u32 want;
 if(step<20)return rid==rr[step/4] && off==0x20+4*(step%4) &&
  tn_window(rid,off,&want) && want==value;
 if(rid!=0x600)return false;
 switch(step){
 case 20:return off==0x10&&value==0x04000000;
 case 21:return off==0x18&&value==5;
 case 22:return off==0x14&&value==0x8000000c;
 case 23:return off==0x20&&value==5;
 case 24:return off==0x1c&&value==0x9000000c;
 default:return false;
 }
}
#endif
