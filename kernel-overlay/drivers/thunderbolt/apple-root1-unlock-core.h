/* SPDX-License-Identifier: GPL-2.0 */
/* Callbacks are fixed to root route0 SWITCH / port1 PORT; no child access. */
struct apple_unlock_io {
 int (*read)(void *, bool, unsigned int, unsigned int, u32 *);
 int (*write)(void *, unsigned int, u32);
 bool (*valid)(void *);
 void *ctx;
};
static int apple_unlock_phy(struct apple_unlock_io *io, unsigned int off)
{
 u32 w[2];
 int ret=io->read(io->ctx,false,off,2,w);
 unsigned int state;
 if(ret) return ret;
 if(((w[0]>>8)&255)!=1) return -EIO;
 state=(w[1]>>26)&15;
 return state>=2 && state<=6 && !(w[1] & (1U<<14)) ? 0 : -ENOLINK;
}
static int apple_unlock_once(struct apple_unlock_io *io,const u32 expected[5],u32 *before,u32 *after)
{
 u32 root[5],port[8],word;
 bool seen[256]={false};
 unsigned int off,n=0,i;
 int ret;
 if(!io->valid(io->ctx)) return -EPERM;
 ret=io->read(io->ctx,true,0,5,root);
 if(ret) return ret;
 for(i=0;i<5;i++) if(root[i]!=expected[i]) return -ESTALE;
 if(root[0]!=0x200005ac || ((root[1]>>8)&63)!=7 ||
    ((root[1]>>14)&63)!=7 || ((root[1]>>20)&7) || root[2] ||
    root[3]!=0x80000000 || (root[4]>>24)!=0x20 ||
    ((root[4]>>8)&255)!=0x10) return -EPERM;
 ret=io->read(io->ctx,false,0,8,port);
 if(ret) return ret;
 if(port[0]!=0x200005ac || (port[2]&0xffffff)!=1 ||
    ((port[3]>>20)&63)!=1) return -EPERM;
 off=port[1]&255;
 while(off) {
  if(off<8 || seen[off] || n++==64) return -EINVAL;
  seen[off]=true;
  ret=io->read(io->ctx,false,off,1,&word);
  if(ret) return ret;
  if(((word>>8)&255)==1) break;
  off=word&255;
 }
 if(!off) return -ENOENT;
 ret=apple_unlock_phy(io,off);
 if(ret) return ret;
 ret=io->read(io->ctx,false,4,1,before);
 if(ret) return ret;
 if(!io->valid(io->ctx)) return -EPERM;
 word=*before & ~(1U<<31);
 if(word!=*before) {
  /* One API call; standard ctl protocol may retransmit an unacknowledged write. */
  ret=io->write(io->ctx,4,word);
  if(ret) return ret;
 }
 ret=io->read(io->ctx,false,4,1,after);
 if(ret) return ret;
 if(*after!=word) return -EIO;
 ret=apple_unlock_phy(io,off);
 if(ret) return ret;
 return io->valid(io->ctx)?0:-EPERM;
}
