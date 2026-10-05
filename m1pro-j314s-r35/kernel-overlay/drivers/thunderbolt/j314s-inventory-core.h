/* SPDX-License-Identifier: GPL-2.0 */
/* Read callbacks only: no topology creation, register writes or permits. */
#define J314S_INV_MAX_PORT 63
#define J314S_INV_MAX_CAP 64
#define J314S_INV_MAX_OPS 512
struct j314s_bob_inv_port {
 u32 header[8];
 unsigned int route, port, count;
 struct { unsigned int offset; u32 words[2]; } caps[J314S_INV_MAX_CAP];
};
struct j314s_bob_inv_result {
 u32 child_header[5];
 u32 child_ports[J314S_INV_MAX_PORT + 1][8];
 unsigned int max_port, upstream, pci_up;
 u64 disabled_ports;
 bool child_read[J314S_INV_MAX_PORT+1];
 int child_status[J314S_INV_MAX_PORT+1];
 struct j314s_bob_inv_port selected[4];
};
struct j314s_bob_inv_io {
 const struct j314s_bootstrap_pins *pins;
 int (*read)(void *, unsigned int, unsigned int, bool, unsigned int, unsigned int, u32 *);
 bool (*expired)(void *);
 bool (*valid)(void *);
 void *ctx;
 unsigned int operations;
};
static int j314s_bob_inv_read(struct j314s_bob_inv_io *io, unsigned int route, unsigned int port,
 bool sw, unsigned int off, unsigned int n, u32 *words)
{
 if (route > 1 || (!route && (sw || (port!=io->pins->route && port!=io->pins->down))) || port > (route?io->pins->max_port:7) || (sw && port) || !n || n > 8 || off > 8191 || n > 8192-off)
  return -EINVAL;
 if (!io->valid(io->ctx)) return -EPERM;
 if (io->operations >= J314S_INV_MAX_OPS || io->expired(io->ctx))
  return -ETIMEDOUT;
 io->operations++;
 int ret=io->read(io->ctx, route, port, sw, off, n, words);
 if(io->expired(io->ctx))return -ETIMEDOUT;
 if(!io->valid(io->ctx))return -EPERM;
 return ret;
}
static int j314s_bob_inv_caps(struct j314s_bob_inv_io *io, struct j314s_bob_inv_port *p, unsigned int wanted)
{
 bool seen[256] = { false };
 unsigned int off = p->header[1] & 255, found = 0;
 int ret;
 while (off) {
  u32 h;
  unsigned int id;
  if (off < 8 || seen[off] || p->count == J314S_INV_MAX_CAP)
   return -EINVAL;
  seen[off] = true;
  ret = j314s_bob_inv_read(io,p->route,p->port,false,off,1,&h);
  if (ret) return ret;
  p->caps[p->count].offset = off;
  p->caps[p->count].words[0] = h;
  id = (h >> 8) & 255;
  if (id == wanted) {
   if (found++) return -EINVAL;
   /* PHY requires two dwords. PCIe adapter enable is in cap DWORD0. */
   if (wanted == 1) {
    ret = j314s_bob_inv_read(io,p->route,p->port,false,off+1,1,
     &p->caps[p->count].words[1]);
    if (ret) return ret;
   }
  }
  p->count++;
  off = h & 255;
 }
 return found == 1 ? 0 : -ENOENT;
}
static int j314s_bob_inv_select(struct j314s_bob_inv_io *io, struct j314s_bob_inv_port *p,
 unsigned int route,unsigned int port,unsigned int type)
{
 int ret;
 p->route=route; p->port=port;
 ret=j314s_bob_inv_read(io,route,port,false,0,8,p->header);
 if (ret) return ret;
 if ((p->header[2]&0xffffff)!=type || ((p->header[3]>>20)&63)!=port)
  return -EINVAL;
 return j314s_bob_inv_caps(io,p,type==1?1:4);
}
static int j314s_bob_inv_collect(struct j314s_bob_inv_io *io,struct j314s_bob_inv_result *r)
{
 u32 fresh[5];
 unsigned int p,up_count=0;
 int ret;
 ret=j314s_bob_inv_read(io,1,0,true,0,5,r->child_header);
 if (ret) return ret;
 r->max_port=(r->child_header[1]>>14)&63;
 r->upstream=(r->child_header[1]>>8)&63;
 const u32 *expected=io->pins->child_after;
 for(p=0;p<5;p++)if(r->child_header[p]!=expected[p])return -ESTALE;
 if(r->max_port!=io->pins->max_port||r->upstream!=io->pins->upstream)return -EINVAL;
 for(p=1;p<=r->max_port;p++) {
  if(r->disabled_ports & (1ULL<<p)){r->child_status[p]=-ENODEV;continue;}
  ret=j314s_bob_inv_read(io,1,p,false,0,8,r->child_ports[p]);
  r->child_status[p]=ret;
  if(ret==-ENODEV)continue;
  if(ret)return ret;
  r->child_read[p]=true;
  if(!(r->child_ports[p][2]&0xffffff))continue;
  if (((r->child_ports[p][3]>>20)&63)!=p) return -EINVAL;
  if((r->child_ports[p][2]&0xffffff)==0x100102) {r->pci_up=p;up_count++;}
 }
 if(up_count!=1 || r->pci_up==r->upstream) return -EINVAL;
 ret=j314s_bob_inv_select(io,&r->selected[0],0,io->pins->route,1);
 if(ret) return ret;
 ret=j314s_bob_inv_select(io,&r->selected[1],0,io->pins->down,0x100101);
 if(ret) return ret;
 ret=j314s_bob_inv_select(io,&r->selected[2],1,r->upstream,1);
 if(ret) return ret;
 ret=j314s_bob_inv_select(io,&r->selected[3],1,r->pci_up,0x100102);
 if(ret) return ret;
 /* Reject topology/header changes across the bounded observation. */
 if(!j314s_adapter_identity_equal(r->selected[2].header,r->child_ports[r->upstream]) ||
    !j314s_adapter_identity_equal(r->selected[3].header,r->child_ports[r->pci_up]))return -ESTALE;
 ret=j314s_bob_inv_read(io,1,0,true,0,5,fresh);
 if(ret) return ret;
 for(p=0;p<5;p++) if(fresh[p]!=r->child_header[p]) return -ESTALE;
 return 0;
}
