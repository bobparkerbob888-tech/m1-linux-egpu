/* SPDX-License-Identifier: GPL-2.0 */
#ifndef BOB_PAIR_POLICY_H
#define BOB_PAIR_POLICY_H
/* Used only under the explicit controller1 R54 pair gate. */
#define PN_FUNCTIONS 8
#define PN_ASSIGN_WRITES 34
#define PN_FOURTH_DSN PROVISION_PRIVATE_ID_6
struct pn_position { unsigned rid, parent, secondary, subordinate; bool forwarding; };
static const struct pn_position pn_positions[PN_FUNCTIONS]={
 {0,~0U,1,6,true},{0x100,0,2,6,true},{0x200,1,3,3,true},{0x300,2,0,0,false},
 {0x208,1,4,6,true},{0x400,4,5,6,true},{0x500,5,6,6,true},{0x600,6,0,0,false}};
static int pn_index(unsigned rid)
{unsigned j;for(j=0;j<PN_FUNCTIONS;j++)if(pn_positions[j].rid==rid)return j;return -1;}
static bool pn_serial_ok(unsigned rid,u64 serial)
{
 if(rid==0x600)return serial==PN_FOURTH_DSN;
 return rid==0x300&&serial&&serial!=~0ULL&&serial!=PN_FOURTH_DSN&&
 serial!=PROVISION_PRIVATE_ID_5&&serial!=PROVISION_PRIVATE_ID_24&&serial!=PROVISION_PRIVATE_ID_20;
}
static unsigned pn_initial_command(unsigned rid)
{int i=pn_index(rid);return i<0?0:pn_positions[i].forwarding?6:2;}
static bool pn_command_ok(unsigned rid,unsigned value,bool before_driver)
{unsigned want=pn_initial_command(rid);if(!want||value>65535)return false;
 return before_driver?value==want:(value&want)==want&&!(value&~(2U|4U|0x400U));}
static bool pn_bar(unsigned rid,unsigned slot,u64 *pci,u64 *cpu,u64 *size,unsigned *type)
{
 if(rid!=0x300&&rid!=0x600)return false;
 if(slot==0){*pci=rid==0x600?0x4000000ULL:0x8000000ULL;*cpu=*pci+0x600000000ULL;*size=0x4000000;*type=0;return true;}
 if(slot==1){*pci=*cpu=rid==0x600?0x580000000ULL:0x5a0000000ULL;*size=0x10000000;*type=12;return true;}
 if(slot==3){*pci=*cpu=rid==0x600?0x590000000ULL:0x5b0000000ULL;*size=0x2000000;*type=12;return true;}
 return false;
}
static bool pn_window(unsigned rid,unsigned off,u32 *value)
{
 int i=pn_index(rid);if(i<0||!pn_positions[i].forwarding)return false;
 switch(off){case 0x20:*value=rid==0||rid==0x100?0x0bf00400:rid==0x200?0x0bf00800:0x07f00400;return true;
 case 0x24:*value=rid==0||rid==0x100?0xb1f18001:rid==0x200?0xb1f1a001:0x91f18001;return true;
 case 0x28:case 0x2c:*value=5;return true;default:return false;}
}
static bool pn_write_at(unsigned step,unsigned *rid,unsigned *off,u32 *value)
{
 static const unsigned bridges[6]={0,0x100,0x200,0x208,0x400,0x500};
 static const unsigned slots[5]={0,1,1,3,3};
 u64 pci,cpu,size;unsigned type,k;
 if(step>=PN_ASSIGN_WRITES)return false;
 if(step<24){*rid=bridges[step/4];*off=0x20+4*(step%4);return pn_window(*rid,*off,value);}
 k=(step-24)%5;*rid=step<29?0x600:0x300;
 if(!pn_bar(*rid,slots[k],&pci,&cpu,&size,&type))return false;
 *off=0x10+4*slots[k];
 if(k==1||k==3){*off+=4;*value=pci>>32;}else *value=(u32)pci|type;
 return true;
}
static bool pn_expected_write(unsigned step,unsigned rid,unsigned off,u32 value)
{unsigned r,o;u32 v;return pn_write_at(step,&r,&o,&v)&&r==rid&&o==off&&v==value;}
static bool pn_identity_config_allowed(unsigned rid,unsigned off,unsigned size,bool write,u32 value)
{
 int i=pn_index(rid);u32 buses;
 if(i<0||size!=4||off>0xffc||(off&3))return false;
 buses=(rid>>8)|(pn_positions[i].secondary<<8)|(pn_positions[i].subordinate<<16);
 if(write)return pn_positions[i].forwarding&&off==0x18&&(value&0xffffff)==buses;
 if(off>=0x40||off==0||off==4||off==8||off==12||off==0x34||off==0x3c)return true;
 return pn_positions[i].forwarding?off==0x18:off==0x2c;
}
#endif
