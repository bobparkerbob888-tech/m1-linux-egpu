/* SPDX-License-Identifier: GPL-2.0 */
/* Input is the exact-length DROM already CRC/UID validated by jpc5_uid_identity.
 * Parse native eeprom.c dual-link metadata; disabled descriptors remain absent.
 * No fixed lane, downstream adapter or enclosure UID is inferred. */
struct jpc5_pairs {unsigned peer[64];bool secondary[64],present[64];u64 disabled;};
static int jpc5_pairs_parse(const unsigned char*d,unsigned n,unsigned max,struct jpc5_pairs*p)
{
 unsigned pos;memset(p,0,sizeof(*p));
 if(!d||!max||max>63||n<22||d[13]!=1||(d[15]&0xf0)||13+d[14]+((unsigned)d[15]<<8)!=n)return -EINVAL;
 for(pos=22;pos<n;){
  unsigned len=d[pos],desc,index;
  if(n-pos<2||len<2||len>n-pos)return -EINVAL;
  desc=d[pos+1];index=desc&63;
  if(desc&128){
   if(!index||index>max||p->present[index])return -EINVAL;
   p->present[index]=true;
   if(desc&64)p->disabled|=1ULL<<index;
   if(len==8&&(d[pos+2]&128)){
    p->peer[index]=d[pos+3]&63;p->secondary[index]=!!(d[pos+2]&16);
    if(!p->peer[index]||p->peer[index]>max||p->peer[index]==index)return -EINVAL;
   }
  }
  pos+=len;
 }
 for(unsigned j=1;j<=max;j++)if(p->peer[j]){
  unsigned k=p->peer[j];
  if(!p->present[k]||p->peer[k]!=j||p->secondary[j]==p->secondary[k]||
     !!(p->disabled&(1ULL<<j))!=!!(p->disabled&(1ULL<<k)))return -EINVAL;
 }
 return 0;
}
/* usb4_switch_map_pcie_down maps active downstream primary null adapters to
 * ascending PCIe DOWN adapters. Derive both lists from actual inventory. */
static int jpc5_down_map(const struct jpc5_pairs*p,const u32 ports[64][8],
 const bool read[64],unsigned max,unsigned upstream,unsigned lane,unsigned*down)
{
 unsigned nd=0,nl=0,ds[63],ls[63];*down=0;
 if(!max||max>63||!upstream||upstream>max||!lane||lane>max)return -EINVAL;
 for(unsigned j=1;j<=max;j++)if(read[j]&&!(p->disabled&(1ULL<<j))){
  if(((ports[j][3]>>20)&63)!=j)return -ESTALE;
  unsigned type=ports[j][2]&0xffffff;
  if(type==0x100101)ds[nd++]=j;
  if(type==1&&j!=upstream&&p->peer[j]&&p->peer[j]!=upstream&&!p->secondary[j])ls[nl++]=j;
 }
 if(!nl||nl!=nd)return -EOPNOTSUPP;
 for(unsigned j=0;j<nl;j++)if(ls[j]==lane){*down=ds[j];return 0;}
 return -ENOENT;
}
