/* Local experimental core. Caller must supply reviewed fresh header constants.
 * No live integration: reads/writes must be bound to ACIO0 route1 SWITCH. */
#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/string.h>
typedef u32 uint32_t;
typedef u8 uint8_t;
typedef u64 uint64_t;
#else
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>
#endif
struct uid_io {
 int (*read)(void *, unsigned, unsigned, uint32_t *);
 int (*write)(void *, unsigned, uint32_t);
 bool (*valid)(void *);
 bool (*expired)(void *);
 void *ctx;
 unsigned operations;
 uint64_t expected_uid;
 uint64_t (*now_ns)(void *);
 bool (*protocol)(void *, const uint32_t *);
 void (*poll_delay)(void *); /* Kernel wrapper: bounded ~1ms sleep, no retry. */
};
static int uid_gate(struct uid_io *io)
{
 if (!io->valid(io->ctx)) return -EPERM;
 if (io->operations >= 4096 || io->expired(io->ctx)) return -ETIMEDOUT;
 io->operations++;
 return 0;
}
static int uid_read(struct uid_io *io,unsigned off,unsigned n,uint32_t *v)
{
 int r=uid_gate(io);if(r)return r;
 if(!n||n>13||off>26||n>27-off)return -EINVAL;
 r=io->read(io->ctx,off,n,v);if(r)return r;return io->expired(io->ctx)?-ETIMEDOUT:0;
}
static int uid_write(struct uid_io *io,unsigned off,uint32_t v)
{
 int r=uid_gate(io);if(r)return r;
 if(off==25) { if(v & ~0x000ffffcU)return -EINVAL; }
 else if(off!=26||v!=0x80000024U)return -EINVAL;
 r=io->write(io->ctx,off,v);if(r)return r;return io->expired(io->ctx)?-ETIMEDOUT:0;
}
static uint32_t uid_le32(const uint8_t *p)
{return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static uint32_t uid_crc(const uint8_t *p,unsigned n)
{
 uint32_t c=~0U;while(n--){c^=*p++;for(unsigned b=0;b<8;b++)c=(c>>1)^((0U-(c&1))&0x82f63b78U);}return ~c;
}
static uint8_t uid_crc8(const uint8_t *p)
{
 uint8_t c=0xff;for(unsigned i=0;i<8;i++){c^=p[i];for(unsigned j=0;j<8;j++)c=(uint8_t)((c<<1)^((c&0x80)?7:0));}return c;
}
static int uid_drom_validate_expected(const uint8_t *p,unsigned n,uint64_t expected_uid)
{
 unsigned pos,found=0;
 if(n<16||n>1036||(p[13]!=1&&p[13]!=3)||(p[15]&0xf0)||(((unsigned)p[14]|(unsigned)p[15]<<8)+13)!=n)return -EINVAL;
 if(uid_crc(p+13,n-13)!=uid_le32(p+9))return -EBADMSG;
 if(p[13]==1){
  if(n<22)return -EINVAL;
  if(uid_crc8(p+1)!=p[0])return -EBADMSG;
  if(uid_le32(p+1)!=(uint32_t)expected_uid||uid_le32(p+5)!=(uint32_t)(expected_uid>>32))return -EPERM;
  /* Observed legacy namespace, distinct from USB product descriptor IDs. */
  if(p[16]!=0xed||p[17]!=0||p[18]!=0xcd||p[19]!=0x41)return -EPERM;
  pos=22;
 }else pos=16;
 while(pos<n){unsigned len=p[pos];if(n-pos<2||len<2||len>n-pos)return -EINVAL;
  if(!(p[pos+1]&0x80)&&(p[pos+1]&0x3f)==9){
   if(++found!=1||len<15||p[pos+4]!=0x14||p[pos+5]!=0x04||p[pos+6]!=0x63||p[pos+7]!=0x7a)return -EPERM;
  }pos+=len;
 }
 return found==1?0:-ENOENT;
}
static int uid_drom_validate(const uint8_t *p,unsigned n)
{return uid_drom_validate_expected(p,n,PROVISION_PRIVATE_ID_1);}
static int uid_block(struct uid_io *io,unsigned address,unsigned n,uint8_t *out)
{
 uint32_t v,words[13],metadata;int r;uint64_t start,deadline;
 if(!io->now_ns)return -EINVAL;
 start=io->now_ns(io->ctx);if(start>~(uint64_t)0-500000000ULL)return -EINVAL;deadline=start+500000000ULL;
 if(!n||n>13||address>8191||n>8192-address)return -EINVAL;
 r=uid_read(io,26,1,&v);if(r)return r;if(v&0x80000000U)return -EBUSY;
 if(io->now_ns(io->ctx)>=deadline)return -ETIMEDOUT;
 metadata=(address<<2)|(n<<15);
 r=uid_write(io,25,metadata);if(r)return r;
 if(io->now_ns(io->ctx)>=deadline)return -ETIMEDOUT;
 r=uid_write(io,26,0x80000024U);if(r)return r;
 unsigned i;for(i=0;i<512;i++){if(io->now_ns(io->ctx)>=deadline)return -ETIMEDOUT;r=uid_read(io,26,1,&v);if(r)return r;if(io->now_ns(io->ctx)>=deadline)return -ETIMEDOUT;if(!(v&0x80000000U))break;if(io->poll_delay)io->poll_delay(io->ctx);}
 if(i==512)return -ETIMEDOUT;
 if(v&0x40000000U)return -EOPNOTSUPP;
 if((v&0xffff)!=0x24||(v&0x3f000000U))return -EIO;
 /* Native usb4.c reads returned metadata but imposes no equality rule. */
 r=uid_read(io,25,1,&v);if(r)return r;if(io->now_ns(io->ctx)>=deadline)return -ETIMEDOUT;
 r=uid_read(io,9,n,words);if(r)return r;if(io->now_ns(io->ctx)>=deadline)return -ETIMEDOUT;
 for(i=0;i<n;i++)for(unsigned j=0;j<4;j++)out[4*i+j]=(uint8_t)(words[i]>>(8*j));
 return 0;
}
/* Exact same-machine route1 DROM fixture, CRC/UID/product checked separately.
 * SHA2569b9a9387872339a196af1884baf844e5a2cc62f7a5372ab7b9134e30c7a5f9df. */
/* Private enclosure DROM contents require fresh target provisioning. */
static const uint8_t uid_expected_drom[196]={ PROVISION_PRIVATE_DROM_BYTES };
static int uid_identity(struct uid_io *io,const uint32_t expected[5],uint8_t out[1036],unsigned *size)
{
 uint32_t h[5],u[2];uint8_t first[16],block[52],fixture[sizeof(uid_expected_drom)];unsigned total,pos;int r;
 uint64_t target=io->expected_uid ? io->expected_uid : PROVISION_PRIVATE_ID_1;
 /* Exactly the two first-router identities; never use a caller-selected UID. */
 if(target!=PROVISION_PRIVATE_ID_1 && target!=PROVISION_PRIVATE_ID_4)return -EPERM;
 memcpy(fixture,uid_expected_drom,sizeof(fixture));
 for(pos=0;pos<8;pos++)fixture[1+pos]=(uint8_t)(target>>(8*pos));
 fixture[0]=uid_crc8(fixture+1);
 *size=0;if(!expected)return -EINVAL;
 r=uid_read(io,0,5,h);if(r)return r;if(memcmp(h,expected,sizeof(h)))return -ESTALE;
 if(!io->protocol||!io->protocol(io->ctx,h))return -EOPNOTSUPP;
 /* CS7 then CS8 preserve CPU-converted DWORD order. macOS display uses
  * CS7 as high word; do not reinterpret its text as native little-endian u64. */
 r=uid_read(io,7,2,u);if(r)return r;if(u[0]!=(uint32_t)(target>>32)||u[1]!=(uint32_t)target)return -EPERM;
 r=uid_block(io,0,4,first);if(r)return r;
 total=((unsigned)first[14]|((unsigned)first[15]&15)<<8)+13;
 if((first[13]!=1&&first[13]!=3)||(first[15]&0xf0)||total<(first[13]==1?22U:16U)||total>1036)return -EINVAL;
 memcpy(out,first,16);
 for(pos=16;pos<total;){unsigned bytes=total-pos;if(bytes>52)bytes=52;unsigned n=(bytes+3)/4;
  r=uid_block(io,pos/4,n,block);if(r)return r;memcpy(out+pos,block,bytes);pos+=bytes;
 }
 r=uid_drom_validate_expected(out,total,target);if(r)return r;
 if(total!=sizeof(uid_expected_drom)||memcmp(out,fixture,total))return -ESTALE;
 r=uid_read(io,7,2,u);if(r)return r;if(u[0]!=(uint32_t)(target>>32)||u[1]!=(uint32_t)target)return -ESTALE;
 r=uid_read(io,0,5,h);if(r)return r;if(memcmp(h,expected,sizeof(h)))return -ESTALE;
 r=uid_gate(io);if(r)return r;*size=total;return 0;
}
