/* SPDX-License-Identifier: GPL-2.0 */
/* Caller additionally proves this is original root's profile-pinned DROM. */
static bool j314s_drom_pair_indexed(const unsigned char*d,unsigned length,unsigned controller)
{
 unsigned end,pos,seen[3]={0};
 if(controller>2||!d||length<22||d[13]!=1||(d[15]&0xf0))return false;
 end=13+d[14]+((unsigned)d[15]<<8);if(end<22||end>length)return false;
 for(pos=end;pos<length;pos++)if(d[pos])return false;
 for(pos=22;pos<end;){
  unsigned n=d[pos],desc,index;
  if(end-pos<2||n<2||n>end-pos)return false;
  desc=d[pos+1];index=desc&63;
  if((desc&128)&&(index==1||index==2)) {
   if(n!=8||(desc&64)||seen[index]++)return false;
   /* Exact target pair metadata: primary1->2, secondary2->1. */
   if(d[pos+2]!=((index==1?0x80:0x90)|controller)||d[pos+3]!=(index==1?2:1))return false;
  }
  pos+=n;
 }
 return seen[1]==1&&seen[2]==1;
}

/* Preserve the original C0 admission contract. */
static bool j314s_drom_pair(const unsigned char*d,unsigned length)
{
 return j314s_drom_pair_indexed(d,length,0);
}

/* Root switch UID is the profile-pinned TBT DROM UID (eeprom.c), not
 * emulated root SWITCH dwords7/8. Caller proves exact indexed profile. */
static bool j314s_drom_root_uid(const unsigned char*d,unsigned length,
 unsigned controller,unsigned uid[2])
{
 unsigned char crc=0xff;unsigned lo=0,hi=0;
 if(!uid||!j314s_drom_pair_indexed(d,length,controller))return false;
 for(unsigned i=0;i<8;i++){
  crc^=d[i+1];for(unsigned bit=0;bit<8;bit++)
   crc=(unsigned char)((crc<<1)^((crc&0x80)?7:0));
 }
 if(crc!=d[0])return false;
 for(unsigned i=0;i<4;i++){lo|=(unsigned)d[1+i]<<(8*i);hi|=(unsigned)d[5+i]<<(8*i);}
 if((!lo&&!hi)||(lo==~0U&&hi==~0U))return false;
 uid[0]=lo;uid[1]=hi;return true;
}
