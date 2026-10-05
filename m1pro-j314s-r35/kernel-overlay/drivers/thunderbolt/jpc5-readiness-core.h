#ifndef JPC5_USB4_READINESS_CORE_H
#define JPC5_USB4_READINESS_CORE_H
/* Source-derived conservative USB4 readiness transaction, no Hop/PE API.
 * u32/u64/bool/errno supplied by kernel or actual-C test harness.
 */
struct jpc5_ready_io {
 const struct jpc5_bootstrap_pins *pins;
 int (*read)(void *,unsigned,unsigned,bool,unsigned,unsigned,u32 *);
 int (*write)(void *,unsigned,unsigned,bool,unsigned,unsigned,const u32 *);
 bool (*valid)(void *);u64 (*now)(void *);void (*sleep)(void *,bool);
 void *ctx;u64 deadline;unsigned ops,pe_expected;bool attempted;
 unsigned rt,ct,rtime,ctime,rphy,cphy,rpcie,cpcie,usb4,up;
 u32 root_ucap,child_ucap;int phase;u32 observed[16],observed_valid;
 unsigned chain_child_depth;u32 chain_header[2][5];
};
static unsigned jpc5_ready_lane(const struct jpc5_ready_io*i,unsigned r)
{return r?i->pins->upstream:i->pins->route;}
static unsigned jpc5_ready_down(const struct jpc5_ready_io*i)
{return i->pins->down;}
static int jpc5_ready_profile(struct jpc5_ready_io*i)
{return jpc5_bootstrap_pins_valid(i->pins)&&i->chain_child_depth==i->pins->depth?0:-EPERM;}
static int jpc5_ready_gate(struct jpc5_ready_io *i)
{if(!i->valid(i->ctx))return -EPERM;if(i->ops>=2048||i->now(i->ctx)>=i->deadline)return -ETIMEDOUT;i->ops++;return 0;}
static int jpc5_ready_read(struct jpc5_ready_io*i,unsigned r,unsigned p,bool sw,unsigned off,unsigned n,u32*v)
{int x=jpc5_ready_gate(i);if(x)return x;if(r>1||(sw&&p)||(!sw&&(!p||p>63))||!n||n>5||off>8192-n)return -EINVAL;x=i->read(i->ctx,r,p,sw,off,n,v);if(x)return x;if(i->now(i->ctx)>=i->deadline)return -ETIMEDOUT;return i->valid(i->ctx)?0:-EPERM;}
static int jpc5_ready_cap(struct jpc5_ready_io*i,unsigned r,unsigned p,bool sw,unsigned first,unsigned wanted,unsigned *result)
{
 unsigned seen[64],count=0;u32 v[2];int x;
 while(first){
  if((sw?first<27:first<8)||first>(sw?8190U:255U)||count>=64)return -EINVAL;
  for(unsigned k=0;k<count;k++)if(seen[k]==first)return -EINVAL;
  seen[count++]=first;x=jpc5_ready_read(i,r,p,sw,first,sw?2:1,v);if(x)return x;
  unsigned cap=(v[0]>>8)&255;
  if(cap==wanted){*result=first;return 0;}
  if(!sw||cap==3)first=v[0]&255;
  else if(cap==5)first=(v[0]>>24)?(v[0]&255):(v[1]&65535);
  else return -EINVAL;
  if(sw&&first>=8192)first=0;
 }
 return -ENOENT;
}

static int jpc5_ready_contained(struct jpc5_ready_io*i)
{u32 a,b;int x=jpc5_ready_read(i,0,jpc5_ready_down(i),false,i->rpcie,1,&a);if(x)return x;x=jpc5_ready_read(i,1,i->up,false,i->cpcie,1,&b);if(x)return x;return ((a>>31)|((b>>31)<<1))!=i->pe_expected?-EPERM:0;}
static bool jpc5_ready_write_allowed(struct jpc5_ready_io*i,unsigned r,unsigned p,bool sw,unsigned off,unsigned n)
{
 if(sw&&!p){
  if(r==0)return (off==i->rt||off==i->rt+3)&&n==1;
  if(r!=1)return false;
  return (n==1&&(off==5||off==i->ct||off==i->ct+3||off==i->ct+25))||(n==2&&(off==i->ct+22||off==i->ct+24));
 }
 return !sw&&r<=1&&p==jpc5_ready_lane(i,r)&&n==1&&(off==(r?i->ctime:i->rtime)+3||off==(r?i->ctime:i->rtime)+6);
}
static int jpc5_ready_write(struct jpc5_ready_io*i,unsigned r,unsigned p,bool sw,unsigned off,unsigned n,const u32*v)
{
 int x;if(r>1||!n||n>5||off>8192-n)return -EINVAL;if(!jpc5_ready_write_allowed(i,r,p,sw,off,n))return -EPERM;x=jpc5_ready_contained(i);if(x)return x;x=jpc5_ready_gate(i);if(x)return x;
 x=i->write(i->ctx,r,p,sw,off,n,v);if(x)return x;if(i->now(i->ctx)>=i->deadline)return -ETIMEDOUT;if(!i->valid(i->ctx))return -EPERM;return jpc5_ready_contained(i);
}
static int jpc5_ready_rmw(struct jpc5_ready_io*i,unsigned r,unsigned p,bool sw,unsigned off,u32 mask,u32 set)
{u32 v,got;int x=jpc5_ready_read(i,r,p,sw,off,1,&v);if(x)return x;v=(v&~mask)|set;x=jpc5_ready_write(i,r,p,sw,off,1,&v);if(x)return x;x=jpc5_ready_read(i,r,p,sw,off,1,&got);if(x)return x;return (got&(mask|set))==(v&(mask|set))?0:-EIO;}
static int jpc5_ready_poll(struct jpc5_ready_io*i,unsigned r,unsigned off,unsigned n,u32 mask,u32 expected)
{u64 start=i->now(i->ctx);u32 v[2];int x;for(unsigned k=0;k<(n==2?100U:512U);k++){if(i->now(i->ctx)-start>=500000000ULL)return -ETIMEDOUT;x=jpc5_ready_read(i,r,0,true,off,n,v);if(x)return x;if(i->now(i->ctx)-start>=500000000ULL)return -ETIMEDOUT;if(n==1?(v[0]&mask)==expected:!(v[0]|v[1]))return 0;i->sleep(i->ctx,n==2);}return -ETIMEDOUT;}
static int jpc5_ready_discover(struct jpc5_ready_io*i)
{
 u32 h[5],p[5];int x;unsigned rootfirst,childfirst;
 const u32 *child=i->pins->child_after;
 x=jpc5_ready_read(i,0,0,true,0,5,h);if(x)return x;if(memcmp(h,i->pins->root,sizeof(h)))return -EPERM;rootfirst=h[1]&255;
 x=jpc5_ready_read(i,1,0,true,0,5,h);if(x)return x;for(unsigned k=0;k<5;k++)if(h[k]!=(child[k]))return -ESTALE;childfirst=h[1]&255;
 x=jpc5_ready_cap(i,0,0,true,rootfirst,3,&i->rt);if(x)return x;x=jpc5_ready_cap(i,1,0,true,childfirst,3,&i->ct);if(x)return x;
 if(i->rt>8192-4||i->ct>8192-26)return -EINVAL;
 for(unsigned r=0;r<2;r++){
  x=jpc5_ready_read(i,r,jpc5_ready_lane(i,r),false,0,4,p);if(x)return x;if((p[2]&0xffffff)!=1||((p[3]>>20)&63)!=jpc5_ready_lane(i,r))return -EPERM;
  x=jpc5_ready_cap(i,r,jpc5_ready_lane(i,r),false,p[1]&255,3,r?&i->ctime:&i->rtime);if(x)return x;
  x=jpc5_ready_cap(i,r,jpc5_ready_lane(i,r),false,p[1]&255,1,r?&i->cphy:&i->rphy);if(x)return x;
  if(!r){x=jpc5_ready_cap(i,0,jpc5_ready_lane(i,0),false,p[1]&255,6,&i->usb4);if(x)return x;}
 }
 if(!i->up||i->up>i->pins->max_port||i->up==i->pins->upstream)return -EINVAL;
 for(unsigned r=0;r<2;r++){
  unsigned port=r?i->up:jpc5_ready_down(i);x=jpc5_ready_read(i,r,port,false,0,4,p);if(x)return x;
  if((p[2]&0xffffff)!=(r?0x100102U:0x100101U)||((p[3]>>20)&63)!=port)return -EPERM;
  x=jpc5_ready_cap(i,r,port,false,p[1]&255,4,r?&i->cpcie:&i->rpcie);if(x)return x;
 }
 return jpc5_ready_contained(i);
}
static int jpc5_ready_observe(struct jpc5_ready_io*i,unsigned slot,unsigned r,unsigned p,bool sw,unsigned off)
{int x=jpc5_ready_read(i,r,p,sw,off,1,&i->observed[slot]);if(!x)i->observed_valid|=1U<<slot;return x;}
static int jpc5_ready_once(struct jpc5_ready_io*i)
{
 u32 v[3],cs5,rootrate,childrate,rdts,cdts,rudm,cudm;int x;
 if(i->attempted)return -EALREADY;
 i->attempted=true;i->phase=1;x=jpc5_ready_profile(i);if(x)return x;x=jpc5_ready_discover(i);if(x)return x;
 /* Capture every preflight word before semantic validation. */
 for(unsigned r=0;r<2;r++){x=jpc5_ready_observe(i,r,r,jpc5_ready_lane(i,r),false,(r?i->cphy:i->rphy)+1);if(x)return x;}
 x=jpc5_ready_observe(i,2,0,jpc5_ready_lane(i,0),false,i->usb4+18);if(x)return x;
 x=jpc5_ready_observe(i,3,0,0,true,i->rt);if(x)return x;x=jpc5_ready_observe(i,4,1,0,true,i->ct);if(x)return x;
 i->root_ucap=i->observed[3];i->child_ucap=i->observed[4];
 x=jpc5_ready_observe(i,5,0,0,true,i->rt+3);if(x)return x;x=jpc5_ready_observe(i,6,1,0,true,i->ct+3);if(x)return x;
 rootrate=i->observed[5]>>16;childrate=i->observed[6]>>16;
 x=jpc5_ready_observe(i,7,1,jpc5_ready_lane(i,1),false,i->ctime+8);if(x)return x;
 x=jpc5_ready_observe(i,8,0,jpc5_ready_lane(i,0),false,i->rtime+3);if(x)return x;x=jpc5_ready_observe(i,9,1,jpc5_ready_lane(i,1),false,i->ctime+3);if(x)return x;
 x=jpc5_ready_observe(i,10,0,jpc5_ready_lane(i,0),false,i->rtime+6);if(x)return x;x=jpc5_ready_observe(i,11,1,jpc5_ready_lane(i,1),false,i->ctime+6);if(x)return x;
 rudm=i->observed[8];cudm=i->observed[9];rdts=i->observed[10];cdts=i->observed[11];
 x=jpc5_ready_observe(i,12,1,0,true,5);if(x)return x;x=jpc5_ready_observe(i,13,1,0,true,6);if(x)return x;cs5=i->observed[12];
 /* Native no-CL1 branch; enhanced mode remains an unsupported transition.
  * TD is disruption state, not an ownership lock. Intended PTO/CV and
  * unrelated UTO/HCO bits may already be set and are preserved. */
 if((i->observed[0]|i->observed[1])&(1U<<11))return -EOPNOTSUPP;
 if(i->observed[2]&(1U<<9))return -EOPNOTSUPP;
 if(i->observed[7]&(1U<<15))return -EOPNOTSUPP;
 if(rootrate!=(i->chain_child_depth?16U:1000U)&&!(i->root_ucap&(1U<<30)))return -EOPNOTSUPP;
 if(childrate!=0&&childrate!=16&&childrate!=1000)return -EOPNOTSUPP;
 if(cs5&1)return -EBUSY;
 bool desired=childrate==16&&
  !((i->root_ucap&(1U<<30))&&(rudm&(1U<<29)))&&
  !((i->child_ucap&(1U<<30))&&(cudm&(1U<<29)))&&!((rdts|cdts)&2);
 /* Bootstrap already configured CS1..4 and setup/RR before PORT access.
  * This stage verifies it; never repeats setup or root initialization. */
 if(rootrate!=(i->chain_child_depth?16U:1000U)||(i->root_ucap&(1U<<27))||(cs5&(1U<<23))||!(cs5&(1U<<24))||!(i->observed[13]&(1U<<24)))return -ESTALE;
 i->phase=3;
 if(!desired){
  if(childrate){
   /* Native disable of normal uni/bidirectional mode before OFF->HiFiBi.
    * No enhanced branch: the EUDM preflight above rejected it. */
   x=jpc5_ready_rmw(i,1,0,true,i->ct+3,0xffff0000U,0);if(x)return x;
   x=jpc5_ready_rmw(i,1,jpc5_ready_lane(i,1),false,i->ctime+6,2,2);if(x)return x;
   x=jpc5_ready_rmw(i,0,jpc5_ready_lane(i,0),false,i->rtime+6,2,2);if(x)return x;
   if((i->child_ucap&(1U<<30))&&(cudm&(1U<<29))){
    x=jpc5_ready_rmw(i,1,jpc5_ready_lane(i,1),false,i->ctime+3,1U<<29,0);if(x)return x;
    if(i->root_ucap&(1U<<30)){x=jpc5_ready_rmw(i,0,jpc5_ready_lane(i,0),false,i->rtime+3,1U<<29,0);if(x)return x;}
   }
  }
  /* OFF -> native time posting -> HiFiBi. TD remains set on uncertain failure. */
  x=jpc5_ready_read(i,0,0,true,i->rt+1,3,v);if(x)return x;
  u64 tm=((u64)(v[2]&65535)<<48)|((u64)v[1]<<16)|(v[0]>>16);u32 pair[2]={(u32)tm,(u32)(tm>>32)};
  x=jpc5_ready_rmw(i,1,0,true,i->ct,1U<<27,1U<<27);if(x)return x;
  x=jpc5_ready_write(i,1,0,true,i->ct+22,2,pair);if(x)return x;
  pair[0]=1;pair[1]=0xffffffffU;x=jpc5_ready_write(i,1,0,true,i->ct+24,2,pair);if(x)return x;
  pair[0]=0;x=jpc5_ready_write(i,1,0,true,i->ct+25,1,pair);if(x)return x;
  x=jpc5_ready_poll(i,1,i->ct+24,2,0,0);if(x)return x;
  x=jpc5_ready_rmw(i,1,0,true,i->ct,1U<<27,0);if(x)return x;
  x=jpc5_ready_rmw(i,1,0,true,i->ct,1U<<27,1U<<27);if(x)return x;
  if(i->child_ucap&(1U<<30)){x=jpc5_ready_rmw(i,1,jpc5_ready_lane(i,1),false,i->ctime+3,1U<<29,0);if(x)return x;}
  if(i->root_ucap&(1U<<30)){x=jpc5_ready_rmw(i,0,jpc5_ready_lane(i,0),false,i->rtime+3,1U<<29,0);if(x)return x;}
  x=jpc5_ready_rmw(i,1,0,true,i->ct+3,0xffff0000U,16U<<16);if(x)return x;
  x=jpc5_ready_rmw(i,1,jpc5_ready_lane(i,1),false,i->ctime+6,2,0);if(x)return x;x=jpc5_ready_rmw(i,0,jpc5_ready_lane(i,0),false,i->rtime+6,2,0);if(x)return x;
  x=jpc5_ready_rmw(i,1,0,true,i->ct,1U<<27,0);if(x)return x;
 }
 else if(i->child_ucap&(1U<<27)){x=jpc5_ready_rmw(i,1,0,true,i->ct,1U<<27,0);if(x)return x;}
 i->phase=4;x=jpc5_ready_read(i,1,0,true,5,1,v);if(x)return x;if(v[0]!=((cs5&~(1U<<23))|(1U<<24)))return -ESTALE;
 x=jpc5_ready_rmw(i,1,0,true,5,0,1U<<31);if(x)return x;x=jpc5_ready_poll(i,1,6,1,1U<<25,1U<<25);if(x)return x;i->phase=5;return jpc5_ready_contained(i);
}

#endif
