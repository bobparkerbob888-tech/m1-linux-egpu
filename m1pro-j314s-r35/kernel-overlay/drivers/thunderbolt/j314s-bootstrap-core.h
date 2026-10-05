#ifndef J314S_USB4_BOOTSTRAP_CORE_H
#define J314S_USB4_BOOTSTRAP_CORE_H
/* Native switch_configure -> setup/RR precedes any child PORT access.
 * j314s_ready_io bounds/context/cap walker and j314s_child_cfg_io exact upload are shared.
 * Only root DOWN3 PE is readable before RR. External host remains disabled.
 */
struct j314s_bootstrap_io {u64 expected_uid;struct j314s_ready_io io;bool header_done;u32 before[5],after[5];};
static int j314s_bootstrap_root_blocked(struct j314s_bootstrap_io*b)
{u32 v;int x=j314s_ready_read(&b->io,0,j314s_ready_down(&b->io),false,b->io.rpcie,1,&v);if(x)return x;return v&(1U<<31)?-EPERM:0;}
static int j314s_bootstrap_write(struct j314s_bootstrap_io*b,unsigned r,unsigned off,unsigned n,const u32*v)
{
 struct j314s_ready_io*i=&b->io;int x;
 if(!n||off>8192-n||!((r==0&&n==1&&(off==i->rt||off==i->rt+3))||(r==1&&((off==1&&n==4)||(off==5&&n==1)))))return -EPERM;
 x=j314s_bootstrap_root_blocked(b);if(x)return x;x=j314s_ready_gate(i);if(x)return x;
 x=i->write(i->ctx,r,0,true,off,n,v);if(x)return x;
 if(i->now(i->ctx)>=i->deadline)return -ETIMEDOUT;
 if(!i->valid(i->ctx))return -EPERM;
 return j314s_bootstrap_root_blocked(b);
}
static int j314s_bootstrap_rmw(struct j314s_bootstrap_io*b,unsigned r,unsigned off,u32 mask,u32 set)
{u32 v,w;int x=j314s_ready_read(&b->io,r,0,true,off,1,&v);if(x)return x;v=(v&~mask)|set;x=j314s_bootstrap_write(b,r,off,1,&v);if(x)return x;x=j314s_ready_read(&b->io,r,0,true,off,1,&w);if(x)return x;return (w&(mask|set))==(v&(mask|set))?0:-EIO;}
static int j314s_bootstrap_child_read(void*p,unsigned off,unsigned n,u32*v)
{struct j314s_bootstrap_io*b=p;return j314s_ready_read(&b->io,1,0,true,off,n,v);}
static int j314s_bootstrap_child_write(void*p,unsigned off,unsigned n,const u32*v)
{return j314s_bootstrap_write(p,1,off,n,v);}
static bool j314s_bootstrap_valid(void*p){struct j314s_bootstrap_io*b=p;return b->io.valid(b->io.ctx);}
static bool j314s_bootstrap_expired(void*p){struct j314s_bootstrap_io*b=p;return b->io.now(b->io.ctx)>=b->io.deadline;}
static int j314s_bootstrap_once(struct j314s_bootstrap_io*b)
{
 struct j314s_ready_io*i=&b->io;u32 h[5],v[2],uid[2],root_tmu,rate;int x;
 struct j314s_child_cfg_io c={.pins=i->pins,.read=j314s_bootstrap_child_read,.write=j314s_bootstrap_child_write,.valid=j314s_bootstrap_valid,.expired=j314s_bootstrap_expired,.ctx=b,.expected_uid=b->expected_uid};
 u64 target=b->expected_uid;
 if(!j314s_bootstrap_pins_valid(i->pins)||target!=i->pins->uid)return -EPERM;
 if(i->attempted)return -EALREADY;
 i->attempted=true;
 x=j314s_ready_read(i,1,0,true,0,5,h);if(x)return x;
 const u32 *old=i->pins->child_before;
 for(unsigned k=0;k<5;k++)if(h[k]!=old[k])return -ESTALE;
 x=j314s_ready_read(i,1,0,true,7,2,uid);if(x)return x;if(uid[0]!=(u32)(target>>32)||uid[1]!=(u32)target)return -EPERM;
 x=j314s_ready_read(i,0,0,true,0,5,h);if(x)return x;if(memcmp(h,i->pins->root,sizeof(h)))return -EPERM;
 x=j314s_ready_cap(i,0,0,true,h[1]&255,3,&i->rt);if(x)return x;if(i->rt>8192-4)return -EINVAL;
 x=j314s_ready_read(i,0,j314s_ready_down(&b->io),false,0,4,h);if(x)return x;if((h[2]&0xffffff)!=0x100101||((h[3]>>20)&63)!=i->pins->down)return -EPERM;
 x=j314s_ready_cap(i,0,j314s_ready_down(&b->io),false,h[1]&255,4,&i->rpcie);if(x)return x;x=j314s_bootstrap_root_blocked(b);if(x)return x;
 x=j314s_ready_read(i,0,j314s_ready_lane(i,0),false,0,4,h);if(x)return x;if((h[2]&0xffffff)!=1||((h[3]>>20)&63)!=i->pins->route)return -EPERM;
 x=j314s_ready_cap(i,0,j314s_ready_lane(i,0),false,h[1]&255,6,&i->usb4);if(x)return x;
 x=j314s_ready_cap(i,0,j314s_ready_lane(i,0),false,h[1]&255,1,&i->rphy);if(x)return x;
 x=j314s_ready_read(i,0,j314s_ready_lane(i,0),false,i->rphy+1,1,v);if(x)return x;
 unsigned state=(v[0]>>26)&15;if((v[0]&(1U<<14))||state<2||state>6)return -ENOLINK;
 x=j314s_ready_read(i,0,j314s_ready_lane(i,0),false,i->usb4+18,1,v);if(x)return x;if(v[0]&(1U<<9))return -EOPNOTSUPP;
 x=j314s_ready_read(i,0,0,true,i->rt,1,&root_tmu);if(x)return x;
 x=j314s_ready_read(i,0,0,true,i->rt+3,1,&rate);if(x)return x;
 if((rate>>16)!=1000&&!(root_tmu&(1U<<30)))return -EOPNOTSUPP;
 x=j314s_ready_read(i,1,0,true,5,2,v);if(x)return x;if(v[0]&1)return -EBUSY;
 /* Root's native startup rate precedes child configuration. */
 if((rate>>16)!=1000||(root_tmu&(1U<<27))){
  x=j314s_bootstrap_rmw(b,0,i->rt,1U<<27,1U<<27);if(x)return x;
  x=j314s_bootstrap_rmw(b,0,i->rt+3,0xffff0000U,1000U<<16);if(x)return x;
  x=j314s_bootstrap_rmw(b,0,i->rt,1U<<27,0);if(x)return x;
 }
 x=j314s_child_cfg_once(&c,b->before,b->after);if(x)return x;b->header_done=true;
 x=j314s_bootstrap_rmw(b,1,5,1U<<23,1U<<24);if(x)return x;
 x=j314s_ready_poll(i,1,6,1,1U<<24,1U<<24);if(x)return x;
 return j314s_bootstrap_root_blocked(b);
}
/* Called only on the immutable CRC/UID/fixture-validated DROM. Native port
 * entries set/clear disabled by index; entries beyond maxport are ignored. */
static int j314s_bootstrap_disabled_ports(const unsigned char*d,unsigned n,const struct j314s_bootstrap_pins *pin,u64*mask)
{
 unsigned p,seen[64]={0};*mask=0;
 if(n<16||(d[13]!=1&&d[13]!=3))return -EINVAL;
 p=d[13]==1?22:16;if(n<p)return -EINVAL;
 while(p<n){unsigned len=d[p];if(n-p<2||len<2||len>n-p)return -EINVAL;
  unsigned desc=d[p+1],index=desc&63;
  if(desc&128){
   if(index>pin->max_port||!index||seen[index]++)return -EINVAL;
   if(desc&64)*mask|=1ULL<<index;
  }
  p+=len;
 }
 return (*mask&(1ULL<<pin->upstream))?-EPERM:0;
}
#endif
