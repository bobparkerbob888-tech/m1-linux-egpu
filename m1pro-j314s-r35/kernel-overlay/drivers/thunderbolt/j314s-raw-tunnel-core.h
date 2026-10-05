/* Bounded retained PCIe path transaction. Native encoding: path.c/tunnel.c.
 * u32/u64/bool/errno/memset supplied by kernel or test. Heap allocate state.
 * No ordinary CM objects, cleanup, retries, dynamic callbacks or route>1. */
#ifndef J314S_RAW_PCIE_TUNNEL_CORE_H
#define J314S_RAW_PCIE_TUNNEL_CORE_H
#define JRAW_PT_SW 0U
#define JRAW_PT_PORT 1U
#define JRAW_PT_HOPS 2U
#define JRAW_PT_MAX_PORT 63U
#define JRAW_PT_MAX_HOP 2047U
#define JRAW_PT_MAX_OPS 32768U
struct jraw_pt_port {u32 header[8];unsigned type,max_in,max_out,total,phy_cap,usb4_cap;bool present,path_space;};
struct jraw_pt_hop {unsigned route,port,id,out,next;u32 before[2],desired[2];};
struct jraw_pt_state {
 int (*read)(void*,unsigned,unsigned,unsigned,unsigned,unsigned,u32*);
 int (*write)(void*,unsigned,unsigned,unsigned,unsigned,unsigned,const u32*);
 bool (*valid)(void*);u64 (*now)(void*);void (*sleep)(void*);
 int (*proof)(void*,unsigned);int (*audit)(void*);int (*commit)(void*);
 void *ctx;u64 deadline,op_deadline;unsigned ops,phase,pe,attempted;
 u32 pe_word[2];
 /* Relative router indices remain0/1; wrapper maps this exact adjacent pair. */
 u32 target_root[5];
 unsigned chain_child_depth;
 u32 chain_header[2][5];
 unsigned usb4_version[2],max_port[2],phy[2],pcie[2],credits[2],existing[2],control[2];
 u64 disabled[2];
 struct jraw_pt_port ports[2][64];
 /* Four input tables: rootPCI/rootlane/childPCI/childlane. */
 bool in_used[4][2048];
 /* For each router, output namespace of lane1 and PCIadapter. */
 bool out_used[2][2][2048];
 struct jraw_pt_hop plan[4];
 unsigned programmed,pe_attempted;bool armed;
 unsigned last_route,last_port,last_space,last_offset,last_count;bool last_write;int last_result;
};
static unsigned jraw_pt_lane(const struct jraw_pt_state *s,unsigned r)
{return s->chain_child_depth && !r ? 3 : 1;}
static unsigned jraw_pt_adapter(const struct jraw_pt_state *s,unsigned r)
{return r ? 9 : s->chain_child_depth ? 10 : 3;}
static int jraw_pt_profile(struct jraw_pt_state *s)
{
 if(!s->chain_child_depth)return s->target_root[0]==0x200105ac &&
  ((s->target_root[1]>>14)&63)==7 ? 0 : -EPERM;
 if(s->chain_child_depth!=2 && s->chain_child_depth!=3)return -EPERM;
 for(unsigned r=0;r<2;r++){
  unsigned depth=s->chain_child_depth-1+r;
  u32 h[5]={0x57868087,0x8505c16b|(depth<<20),depth==1?1:depth==2?0x301:0x30301,0x80000000,0x400020ff};
  if(memcmp(h,s->chain_header[r],sizeof(h)))return -ESTALE;
 }
 return 0;
}
static int jraw_pt_gate(struct jraw_pt_state*s)
{if(!s->valid(s->ctx))return -EPERM;if(s->ops>=JRAW_PT_MAX_OPS||s->now(s->ctx)>=s->deadline||(s->op_deadline&&s->now(s->ctx)>=s->op_deadline))return -ETIMEDOUT;return 0;}
static int jraw_pt_io(struct jraw_pt_state*s,bool write,unsigned r,unsigned p,unsigned space,unsigned off,unsigned n,u32*v)
{
 int x=jraw_pt_gate(s);if(x)return x;
 if(r>1||!n||n>8||space>JRAW_PT_HOPS||off>8192-n||
    (space==JRAW_PT_SW?p!=0:(!p||p>JRAW_PT_MAX_PORT)))return -EINVAL;
 s->last_route=r;s->last_port=p;s->last_space=space;s->last_offset=off;s->last_count=n;s->last_write=write;
 s->ops++;x=write?s->write(s->ctx,r,p,space,off,n,v):s->read(s->ctx,r,p,space,off,n,v);
 /* Recheck deadline/context even for ENODEV: absent slots are not timeout permits. */
 int post=jraw_pt_gate(s);s->last_result=post?post:x;return s->last_result;
}
static int jraw_pt_read(struct jraw_pt_state*s,unsigned r,unsigned p,unsigned space,unsigned off,unsigned n,u32*v)
{return jraw_pt_io(s,false,r,p,space,off,n,v);}
static int jraw_pt_pe(struct jraw_pt_state*s,unsigned expected)
{
 for(unsigned r=0;r<2;r++){u32 v;int x=jraw_pt_read(s,r,jraw_pt_adapter(s,r),JRAW_PT_PORT,s->pcie[r],1,&v);if(x)return x;
  if((v>>31)!=((expected>>r)&1))return -EBUSY;}
 return 0;
}
static int jraw_pt_audit(struct jraw_pt_state*s)
{int x=jraw_pt_gate(s);if(x)return x;x=s->audit(s->ctx);return x?x:jraw_pt_gate(s);}
static bool jraw_pt_write_allowed(struct jraw_pt_state*s,unsigned r,unsigned p,unsigned space,unsigned off,unsigned n,const u32*v)
{
 if(r>1||!n||n>8||space>JRAW_PT_HOPS||off>8192-n||p>63)return false;
 if(space==JRAW_PT_SW&&!p&&!s->armed)return n==1&&((off==25&&!v[0])||(off==26&&v[0]==0x80000033));
 if(!s->armed)return false;
 if(space==JRAW_PT_HOPS&&n==2&&s->programmed<4){struct jraw_pt_hop*h=&s->plan[s->programmed];
  return r==h->route&&p==h->port&&off==h->id*2&&v[0]==h->desired[0]&&v[1]==h->desired[1];}
 if(space==JRAW_PT_PORT&&n==1&&s->programmed==4&&off==s->pcie[r]&&p==(jraw_pt_adapter(s,r)))
  return (v[0]&0x80000000U)&&v[0]==s->pe_word[r]&&((s->pe==0&&r==1)||(s->pe==2&&r==0));
 return false;
}
static int jraw_pt_write(struct jraw_pt_state*s,unsigned r,unsigned p,unsigned space,unsigned off,unsigned n,u32*v)
{
 int x;if(!jraw_pt_write_allowed(s,r,p,space,off,n,v))return -EPERM;
 x=jraw_pt_pe(s,s->pe);if(x)return x;x=jraw_pt_audit(s);if(x)return x;
 if(space==JRAW_PT_PORT)s->pe_attempted|=1U<<r;
 return jraw_pt_io(s,true,r,p,space,off,n,v);
}
/* Router operation BUFFER_ALLOC(0x33), native16DWORD reply; no NVM opcode. */
static int jraw_pt_preferences_inner(struct jraw_pt_state*s,unsigned r,int pref[6])
{
 u64 start=s->now(s->ctx);u32 v,meta,data[16];int x;unsigned polls;
 for(unsigned k=0;k<6;k++)pref[k]=-1;
 x=jraw_pt_read(s,r,0,JRAW_PT_SW,26,1,&v);if(x)return x;
 if(v&0x80000000U)return -EBUSY;
 if(s->now(s->ctx)-start>=500000000ULL)return -ETIMEDOUT;
 v=0;x=jraw_pt_write(s,r,0,JRAW_PT_SW,25,1,&v);if(x)return x;
 if(s->now(s->ctx)-start>=500000000ULL)return -ETIMEDOUT;
 v=0x80000033;x=jraw_pt_write(s,r,0,JRAW_PT_SW,26,1,&v);if(x)return x;
 for(polls=0;polls<512;polls++){
  if(s->now(s->ctx)-start>=500000000ULL)return -ETIMEDOUT;
  x=jraw_pt_read(s,r,0,JRAW_PT_SW,26,1,&v);if(x)return x;
  if(s->now(s->ctx)-start>=500000000ULL)return -ETIMEDOUT;
  if(!(v&0x80000000U))break;
  s->sleep(s->ctx);
 }
 if(polls==512)return -ETIMEDOUT;
 if((v&0xffff)!=0x33)return -EPROTO;
 if(v&0x40000000U)return -EOPNOTSUPP;
 if(v&0x3f000000U)return -EIO;
 x=jraw_pt_read(s,r,0,JRAW_PT_SW,25,1,&meta);if(x)return x;
 unsigned len=meta&255;if(len>16)return -EMSGSIZE;
 for(unsigned off=0;off<16;off+=8){x=jraw_pt_read(s,r,0,JRAW_PT_SW,9+off,8,&data[off]);if(x)return x;}
 if(s->now(s->ctx)-start>=500000000ULL)return -ETIMEDOUT;
 for(unsigned k=0;k<len;k++){unsigned index=data[k]&65535;if(index>=1&&index<=5)pref[index]=data[k]>>16;}
 return 0;
}
static int jraw_pt_preferences(struct jraw_pt_state*s,unsigned r,int pref[6])
{int x;s->op_deadline=s->now(s->ctx)+500000000ULL;
 x=jraw_pt_preferences_inner(s,r,pref);s->op_deadline=0;return x;}
/* USB4 lane1 has no addressable path space (switch.c reset_host).
 * usb4_switch_add_ports identifies primary adapters by capability6. Absence
 * is admissible only after this complete bounded read-only capability walk;
 * errors, malformed chains and duplicate relevant capabilities remain fatal. */
static int jraw_pt_lane_caps(struct jraw_pt_state*s,unsigned r,unsigned p)
{
 struct jraw_pt_port*q=&s->ports[r][p];bool seen[256]={false};
 unsigned off=q->header[1]&255,count=0;
 while(off){
  u32 v;unsigned id;int x;
  if(off<8||off>255||seen[off]||count++>=64)return -EINVAL;
  seen[off]=true;x=jraw_pt_read(s,r,p,JRAW_PT_PORT,off,1,&v);if(x)return x;
  if(v==0xffffffffU)return -EINVAL;
  id=(v>>8)&255;
  if(id==1){if(q->phy_cap)return -EINVAL;q->phy_cap=off;}
  if(id==6){if(q->usb4_cap)return -EINVAL;q->usb4_cap=off;}
  off=v&255;
 }
 if(!q->phy_cap)return -EINVAL;
 q->path_space=!s->usb4_version[r]||q->usb4_cap;
 return 0;
}
static int jraw_pt_ports(struct jraw_pt_state*s)
{
 for(unsigned r=0;r<2;r++){
  u32 sw[5];int x=jraw_pt_read(s,r,0,JRAW_PT_SW,0,5,sw);if(x)return x;
  if(s->chain_child_depth ? memcmp(sw,s->chain_header[r],sizeof(sw)) :
   (r?(sw[0]!=0x57868087||sw[1]!=0x8515c16b||sw[2]!=1||sw[3]!=0x80000000||sw[4]!=0x400020ff):
       memcmp(sw,s->target_root,sizeof(sw))))return -ESTALE;
  s->usb4_version[r]=(sw[4]>>29)&7;
  s->max_port[r]=(sw[1]>>14)&63;if(!s->max_port[r]||(r&&s->max_port[r]!=23))return -EINVAL;
  for(unsigned p=1;p<=s->max_port[r];p++){
   if(s->disabled[r]&(1ULL<<p))continue;
   struct jraw_pt_port*q=&s->ports[r][p];x=jraw_pt_read(s,r,p,JRAW_PT_PORT,0,8,q->header);
   if(x==-ENODEV)continue;
   if(x)return x;
   q->type=q->header[2]&0xffffff;if(!q->type)continue;
   if(((q->header[3]>>20)&63)!=p)return -ESTALE;
   q->present=true;q->max_in=q->header[5]&2047;q->max_out=(q->header[5]>>11)&2047;
   q->total=(q->header[4]>>20)&1023;
   if(q->type==1){x=jraw_pt_lane_caps(s,r,p);if(x)return x;}
   else q->path_space=true;
  }
  if(!s->ports[r][jraw_pt_lane(s,r)].present||s->ports[r][jraw_pt_lane(s,r)].type!=1||
     !s->ports[r][jraw_pt_lane(s,r)].path_space||!s->ports[r][jraw_pt_lane(s,r)].usb4_cap||
     !s->ports[r][jraw_pt_adapter(s,r)].present||s->ports[r][jraw_pt_adapter(s,r)].type!=(r?0x100102U:0x100101U))return -ESTALE;
 }
 return 0;
}
/* Account every enabled output collision, including paths from other protocol
 * adapters. Never alter them or infer their absence from PCIe PEclear. */
static int jraw_pt_hops(struct jraw_pt_state*s)
{
 for(unsigned r=0;r<2;r++)for(unsigned p=1;p<=s->max_port[r];p++){
  struct jraw_pt_port*q=&s->ports[r][p];if(!q->present||!q->path_space)continue;
  for(unsigned id=q->type==2?1:q->type==1?0:8;id<=q->max_in;){
   unsigned count=q->max_in-id+1;if(count>4)count=4;
   /* Lane controlHop0 is one entry. Hop1..7 are reserved, never swept. */
   if(q->type==1&&!id)count=1;
   u32 v[8];int x=jraw_pt_read(s,r,p,JRAW_PT_HOPS,id*2,count*2,v);if(x)return x;
   for(unsigned j=0;j<count;j++){
    u32 a=v[j*2],b=v[j*2+1];unsigned h=id+j;
    bool enabled=(a>>31)!=0,pending=(b&0x10000000U)!=0;
    if(p==jraw_pt_lane(s,r)&&h==0)s->control[r]=(a>>17)&127;
    if(enabled||pending){
     unsigned out=(a>>11)&63,next=a&2047;
     if(out==jraw_pt_lane(s,r))s->out_used[r][0][next]=true;
     if(out==(jraw_pt_adapter(s,r)))s->out_used[r][1][next]=true;
     if(p==jraw_pt_lane(s,r)){s->in_used[r?3:1][h]=true;if(h>=8)s->existing[r]+=(a>>17)&127;}
     if(p==(jraw_pt_adapter(s,r)))s->in_used[r?2:0][h]=true;
    }
   }
   id=q->type==1&&!id?8:id+count;
  }
 }
 return 0;
}
static int jraw_pt_credits(struct jraw_pt_state*s,unsigned r)
{
 int pref[6];u32 phy;unsigned lanes=0;bool need_dp=false,need_usb=false,need_pci=false;
 int x=jraw_pt_read(s,r,jraw_pt_lane(s,r),JRAW_PT_PORT,s->phy[r]+1,1,&phy);if(x)return x;
 unsigned width=(phy>>20)&63;if(width!=1&&width!=2)return -EOPNOTSUPP;
 if((phy&((1U<<14)|(1U<<11)))||((phy>>26)&15)<2||((phy>>26)&15)>5)return -ENOLINK;
 x=jraw_pt_preferences(s,r,pref);bool fallback=x==-EOPNOTSUPP;
 if(x&&!fallback)return x;
 for(unsigned p=1;p<=s->max_port[r];p++){
  unsigned t=s->ports[r][p].type;if(!s->ports[r][p].present)continue;
  lanes+=t==1;need_dp|=t==0xe0101||t==0xe0102;need_usb|=t==0x200101||t==0x200102;
  need_pci|=t==0x100101||t==0x100102;
 }
 if(!fallback)fallback=(!r&&pref[5]<0)||(lanes>2&&(pref[2]<0||pref[3]<0))||
   (need_dp&&(pref[2]<0||pref[3]<0))||(need_usb&&pref[1]<0)||(need_pci&&pref[4]<0);
 unsigned ctl=s->control[r]?s->control[r]:2,total=s->ports[r][jraw_pt_lane(s,r)].total;
 if(total<ctl||total-ctl<s->existing[r])return -ENOSPC;
 unsigned available=total-ctl-s->existing[r],credits;
 if(fallback)credits=width==2?32:16;
 else {
  /* Exclusive PCI experiment: no future USB/DP/XDomain allocation requested.
   * Existing lane consumers were measured above and deducted, never ignored.
   * This is native min(baMaxPCIe,available), with explicit experiment policy. */
  credits=(unsigned)pref[4];if(credits>available)credits=available;
 }
 if(credits<6||credits>127||credits>available)return -ENOSPC;
 s->credits[r]=credits;return 0;
}
static int jraw_pt_choose(struct jraw_pt_state*s)
{
 unsigned d=0,u=0;
 if(s->in_used[0][8]||s->in_used[2][8]||s->out_used[0][1][8]||s->out_used[1][1][8])return -EBUSY;
 if(s->ports[0][jraw_pt_adapter(s,0)].max_in<8||s->ports[0][jraw_pt_adapter(s,0)].max_out<8||s->ports[1][jraw_pt_adapter(s,1)].max_in<8||s->ports[1][jraw_pt_adapter(s,1)].max_out<8)return -ENOSPC;
 for(unsigned h=8;h<=2047;h++){
  if(!d&&h<=s->ports[0][jraw_pt_lane(s,0)].max_out&&h<=s->ports[1][jraw_pt_lane(s,1)].max_in&&!s->out_used[0][0][h]&&!s->in_used[3][h])d=h;
  if(!u&&h<=s->ports[1][jraw_pt_lane(s,1)].max_out&&h<=s->ports[0][jraw_pt_lane(s,0)].max_in&&!s->out_used[1][0][h]&&!s->in_used[1][h])u=h;
  if(d&&u)break;
 }
 if(!d||!u)return -ENOSPC;
 s->plan[0]=(struct jraw_pt_hop){.route=0,.port=jraw_pt_adapter(s,0),.id=8,.out=jraw_pt_lane(s,0),.next=d};
 s->plan[1]=(struct jraw_pt_hop){.route=1,.port=jraw_pt_lane(s,1),.id=d,.out=jraw_pt_adapter(s,1),.next=8};
 s->plan[2]=(struct jraw_pt_hop){.route=1,.port=jraw_pt_adapter(s,1),.id=8,.out=jraw_pt_lane(s,1),.next=u};
 s->plan[3]=(struct jraw_pt_hop){.route=0,.port=jraw_pt_lane(s,0),.id=u,.out=jraw_pt_adapter(s,0),.next=8};
 for(unsigned k=0;k<4;k++){
  struct jraw_pt_hop*h=&s->plan[k];int x=jraw_pt_read(s,h->route,h->port,JRAW_PT_HOPS,h->id*2,2,h->before);if(x)return x;
  if((h->before[0]&0x80000000U)||(h->before[1]&0x10000000U))return -EBUSY;
  /* Native protocol vendor fields: preserve credits[23:17] and IFC/ISE.
   * No counter, PMPS, drop or shared egress; unknown fields zero. */
  h->desired[0]=(h->before[0]&0x00fe0000U)|0x80000000U|(h->out<<11)|h->next;
  h->desired[1]=(h->before[1]&0x05000000U)|0x301U|(k%2==0?0x02000000U:0);
  /* counter disabled, native counter field -1 truncated to11bits. */
  h->desired[1]|=0x007ff000U;
  if(h->port==jraw_pt_lane(s,h->route)){h->desired[0]=(h->desired[0]&~0x00fe0000U)|(s->credits[h->route]<<17);
    h->desired[1]=(h->desired[1]&~0x05000000U)|0x01000000U;}
 }
 return 0;
}
static int jraw_pt_verify(struct jraw_pt_state*s)
{
 for(unsigned k=0;k<4;k++){struct jraw_pt_hop*h=&s->plan[k];u32 v[2];int x=jraw_pt_read(s,h->route,h->port,JRAW_PT_HOPS,h->id*2,2,v);if(x)return x;
  if(v[0]!=h->desired[0]||(v[1]&~0x10000000U)!=h->desired[1])return -EIO;}
 return 0;
}
static int jraw_pt_detect(struct jraw_pt_state*s)
{
 for(unsigned r=0;r<2;r++){u64 start=s->now(s->ctx);unsigned k;
  for(k=0;k<512;k++){u32 v;int x=jraw_pt_read(s,r,jraw_pt_adapter(s,r),JRAW_PT_PORT,s->pcie[r],1,&v);if(x)return x;
   if(s->now(s->ctx)-start>=500000000ULL)return -ETIMEDOUT;
   if(v&0x80000000U)return -EBUSY;
   if(((v>>25)&15)==0)break;
  s->sleep(s->ctx);}
  if(k==512)return -ETIMEDOUT;
 }
 return 0;
}
static int jraw_pt_once(struct jraw_pt_state*s)
{
 int x;if(s->attempted)return -EALREADY;s->attempted=1;s->phase=1;
 x=jraw_pt_profile(s);if(x)return x;
 x=s->proof(s->ctx,0);if(x)return x;x=jraw_pt_audit(s);if(x)return x;
 x=jraw_pt_ports(s);if(x)return x;x=jraw_pt_pe(s,0);if(x)return x;
 x=jraw_pt_hops(s);if(x)return x;
 for(unsigned r=0;r<2;r++){x=jraw_pt_credits(s,r);if(x)return x;}
 x=jraw_pt_choose(s);if(x)return x;x=jraw_pt_detect(s);if(x)return x;
 x=s->proof(s->ctx,0);if(x)return x;s->phase=2;s->armed=true;
 for(unsigned k=0;k<4;k++){
  struct jraw_pt_hop*h=&s->plan[k];u32 before[2];x=jraw_pt_read(s,h->route,h->port,JRAW_PT_HOPS,h->id*2,2,before);if(x)return x;
  if(before[0]!=h->before[0]||before[1]!=h->before[1])return -ESTALE;
  x=jraw_pt_write(s,h->route,h->port,JRAW_PT_HOPS,h->id*2,2,h->desired);if(x)return x;
  s->programmed++;u32 got[2];x=jraw_pt_read(s,h->route,h->port,JRAW_PT_HOPS,h->id*2,2,got);if(x)return x;
  if(got[0]!=h->desired[0]||(got[1]&~0x10000000U)!=h->desired[1])return -EIO;
 }
 x=jraw_pt_verify(s);if(x)return x;x=s->proof(s->ctx,0);if(x)return x;s->phase=3;
 for(unsigned k=0;k<2;k++){
  unsigned r=k?0:1;u32 v,got;x=jraw_pt_read(s,r,jraw_pt_adapter(s,r),JRAW_PT_PORT,s->pcie[r],1,&v);if(x)return x;
  v|=0x80000000U;s->pe_word[r]=v;x=jraw_pt_write(s,r,jraw_pt_adapter(s,r),JRAW_PT_PORT,s->pcie[r],1,&v);if(x)return x;
  /* Once a write may have reached hardware, no retry or rollback is possible. */
  s->pe|=1U<<r;x=jraw_pt_read(s,r,jraw_pt_adapter(s,r),JRAW_PT_PORT,s->pcie[r],1,&got);if(x)return x;
  if(!(got&0x80000000U))return -EIO;
  x=s->proof(s->ctx,s->pe);if(x)return x;x=jraw_pt_verify(s);if(x)return x;
 }
 s->phase=4;x=jraw_pt_audit(s);if(x)return x;x=jraw_pt_gate(s);if(x)return x;
 x=s->commit(s->ctx);if(x)return x;x=jraw_pt_gate(s);if(x)return x;s->phase=5;return 0;
}
#endif
