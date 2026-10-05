/* SPDX-License-Identifier: GPL-2.0 */
/* Draft read-only acquisition, NOT topology/UID authorization. The real owner
 * supplies current-boot root/lane pins and validity callback under both locks.
 * No write callback exists. An inaccessible lane is a failed retained attempt. */
#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/string.h>
#else
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
typedef uint32_t u32;
#endif
/* Adapter identity/capabilities remain fixed; control and credit state do not.
 * tb_regs_port_header DWORD4 is nfc_credits/LCK, DWORD5 bits28:22 LCA
 * and bit31 DHP; DWORD3 outside port_number and DWORD6/7 are not identities. */
static bool j314s_lane_identity_equal(const u32*a,const u32*b)
{
 return a[0]==b[0] && a[1]==b[1] && a[2]==b[2] &&
  !((a[3]^b[3])&0x03f00000U) && !((a[5]^b[5])&0x003fffffU);
}
struct j314s_child_pins {
 unsigned lane; /* physically ready lane, never used as logical route */
 unsigned route; /* pinned DROM primary control route */
 u32 root[5],lane_header[8],control_header[8];
};
struct j314s_child_observation {
 unsigned route,phy_cap,operations;
 u32 child_header[5],uid_words[2];
 bool header_read,usb4,uid_read,stable;
};
struct j314s_child_io {
 /* sw=true: SWITCH, false: PORT. Route0 or derived one-hop lane only. */
 int (*read)(void *,unsigned route,unsigned port,bool sw,unsigned off,unsigned n,u32 *data);
 bool (*valid)(void *); /* exact retained J314s controller0, same cable, endpoints disabled */
 bool (*expired)(void *);
 void *ctx;
 bool attempted; /* private retained owner's once-per-boot storage */
 unsigned operations;
};
static int j314s_child_read(struct j314s_child_io *io,unsigned route,unsigned port,
 bool sw,unsigned off,unsigned n,u32 *data)
{
 int ret;
 if(!n||n>8||off>255||n>256-off)return -EINVAL;
 if(!io->valid(io->ctx))return -EPERM;
 if(io->operations>=96||io->expired(io->ctx))return -ETIMEDOUT;
 io->operations++;
 ret=io->read(io->ctx,route,port,sw,off,n,data);
 if(ret)return ret;
 if(!io->valid(io->ctx))return -ESTALE;
 return io->expired(io->ctx)?-ETIMEDOUT:0;
}
static int j314s_child_capture_once(struct j314s_child_io *io,
 const struct j314s_child_pins *pins,struct j314s_child_observation *out)
{
 u32 root[5],port[8],phy[2],again[5],uid[2];bool seen[256]={false};
 unsigned max,up,off,n=0,state;int ret;
 if(!io||!pins||!out||!io->read||!io->valid||!io->expired)return -EINVAL;
 memset(out,0,sizeof(*out));
 if(io->attempted)return -EALREADY;
 io->attempted=true;
 max=(pins->root[1]>>14)&63;up=(pins->root[1]>>8)&63;
 if(!pins->lane||pins->lane>max||pins->lane==up||pins->route!=1||
    (pins->lane!=1&&pins->lane!=2)||max!=7||
    (pins->control_header[2]&0xffffff)!=1||((pins->control_header[3]>>20)&63)!=pins->route||
    ((pins->root[1]>>20)&7)||pins->root[2]||pins->root[3]!=0x80000000U||
    (pins->lane_header[2]&0xffffff)!=1||
    ((pins->lane_header[3]>>20)&63)!=pins->lane)return -EPERM;
 /* Root DROM primary controls routing; a separate paired physical lane proves link readiness. */
 out->route=pins->route;
 ret=j314s_child_read(io,0,0,true,0,5,root);if(ret)goto done;
 if(memcmp(root,pins->root,sizeof(root))){ret=-ESTALE;goto done;}
 ret=j314s_child_read(io,0,pins->route,false,0,8,port);if(ret)goto done;
 if(!j314s_lane_identity_equal(port,pins->control_header)){ret=-ESTALE;goto done;}
 if(port[4]&0x80000000U){ret=-EACCES;goto done;}
 ret=j314s_child_read(io,0,pins->lane,false,0,8,port);if(ret)goto done;
 if(!j314s_lane_identity_equal(port,pins->lane_header)){ret=-ESTALE;goto done;}
 if(port[4]&0x80000000U){ret=-EACCES;goto done;} /* No implicit config unlock. */
 off=port[1]&255;
 while(off) {
  if(off<8||off>254||seen[off]||n++==64){ret=-EINVAL;goto done;}
  seen[off]=true;
  if(port[4]&0x80000000U){ret=-EACCES;goto done;}
 ret=j314s_child_read(io,0,pins->lane,false,off,2,phy);if(ret)goto done;
  if(((phy[0]>>8)&255)==1)break;
  off=phy[0]&255;
 }
 if(!off){ret=-ENOENT;goto done;}
 state=(phy[1]>>26)&15;
 if(state<2||state>6||(phy[1]&(1U<<14))){ret=-ENOLINK;goto done;}
 out->phy_cap=off;
 ret=j314s_child_read(io,pins->route,0,true,0,5,out->child_header);if(ret)goto done;
 out->header_read=true;
 if(!(out->child_header[0]&0xffff)||(out->child_header[0]&0xffff)==0xffff||
    !(out->child_header[0]>>16)||(out->child_header[0]>>16)==0xffff||
    !((out->child_header[1]>>14)&63)) {ret=-EPROTO;goto done;}
 /* USB4 standard RouterCS7/8 UID words. TB3 UID/DROM needs separately
  * reviewed EEPROM/control writes; do not call old fixed-identity helpers. */
 out->usb4=!!(out->child_header[4]>>29);
 if(out->usb4) {
  ret=j314s_child_read(io,pins->route,0,true,7,2,out->uid_words);if(ret)goto done;
  out->uid_read=true;
  if((!out->uid_words[0]&&!out->uid_words[1])||
     (out->uid_words[0]==~0U&&out->uid_words[1]==~0U)){ret=-EPROTO;goto done;}
  ret=j314s_child_read(io,pins->route,0,true,7,2,uid);if(ret)goto done;
  if(memcmp(uid,out->uid_words,sizeof(uid))){ret=-ESTALE;goto done;}
 }
 ret=j314s_child_read(io,pins->route,0,true,0,5,again);if(ret)goto done;
 if(memcmp(again,out->child_header,sizeof(again))){ret=-ESTALE;goto done;}
 ret=j314s_child_read(io,0,pins->route,false,0,8,port);if(ret)goto done;
 if(!j314s_lane_identity_equal(port,pins->control_header)){ret=-ESTALE;goto done;}
 if(port[4]&0x80000000U){ret=-EACCES;goto done;}
 ret=j314s_child_read(io,0,pins->lane,false,0,8,port);if(ret)goto done;
 if(!j314s_lane_identity_equal(port,pins->lane_header)){ret=-ESTALE;goto done;}
 if(port[4]&0x80000000U){ret=-EACCES;goto done;}
 ret=j314s_child_read(io,0,pins->lane,false,off,2,phy);if(ret)goto done;
 state=(phy[1]>>26)&15;
 if(((phy[0]>>8)&255)!=1||state<2||state>6||(phy[1]&(1U<<14))){ret=-ENOLINK;goto done;}
 ret=j314s_child_read(io,0,0,true,0,5,root);if(ret)goto done;
 if(memcmp(root,pins->root,sizeof(root))){ret=-ESTALE;goto done;}
 out->stable=true;
done:
 out->operations=io->operations;return ret;
}
