/* SPDX-License-Identifier: GPL-2.0 */
/* Bounded control-plane preparation of the two historical ACIO0 descendants.
 * No PCIe enable, Hop programming, PCI configuration or GPU access here.
 * Call only before external-host activation, holding the ACIO and TB locks.
 * usb4_identity_core.h supplies the existing bounded DROM operation/CRC code.
 */
#ifndef BOB_CHAIN_PREPARE_CORE_H
#define BOB_CHAIN_PREPARE_CORE_H
struct chain_node {
 unsigned route, depth;
 u32 uid_hi, uid_lo, header[5], ports[24][8];
 u64 disabled;
 unsigned phy[4], pcie[4], pcie_down[3];
 bool configured, ready, identity, tmu_ready;
};
struct chain_io {
 int (*read)(void *, unsigned, unsigned, bool, unsigned, unsigned, u32 *);
 int (*write)(void *, unsigned, unsigned, bool, unsigned, unsigned, const u32 *);
 bool (*valid)(void *);
 u64 (*now)(void *);
 void (*delay)(void *);
 int (*link_ready)(void *, unsigned);
 void *ctx;
 u64 deadline;
 unsigned operations, root_pcie_cap, controller;
 bool attempted;
 struct chain_node node[3];
};
static int chain_gate(struct chain_io *c)
{
 if (!c->valid(c->ctx)) return -EPERM;
 if (c->operations >= 4096 || c->now(c->ctx) >= c->deadline) return -ETIMEDOUT;
 c->operations++;
 return 0;
}
static bool chain_route(unsigned r)
{ return r == 0 || r == 1 || r == 0x301 || r == 0x30301; }
static int chain_read(struct chain_io *c, unsigned r, unsigned p, bool sw,
 unsigned off, unsigned n, u32 *v)
{
 int x;
 if (c->controller >= 2 || (c->controller == 1 && r == 0x30301) || !chain_route(r) || !n || n > 13 || off > 8192-n ||
     (sw ? p != 0 : (!p || p > 23)) || (!r && (sw || p != 3))) return -EPERM;
 x = chain_gate(c); if (x) return x;
 x = c->read(c->ctx, r, p, sw, off, n, v); if (x) return x;
 return chain_gate(c);
}
static int chain_blocked(struct chain_io *c)
{
 u32 v; int x;
 if (c->root_pcie_cap < 8 || c->root_pcie_cap > 255) return -EPERM;
 x = chain_read(c, 0, 3, false, c->root_pcie_cap, 1, &v);
 if (x) return x;
 return v & (1U << 31) ? -EPERM : 0;
}
static int chain_write(struct chain_io *c, unsigned r, unsigned p, bool sw,
 unsigned off, unsigned n, const u32 *v)
{
 int x;
 /* Only downstream config-access unlock, DROM-read op, CS1..4 and RR.
  * In particular neither port PE nor Hop spaces are representable here. */
 if (c->controller >= 2 || (c->controller == 1 && (r == 0x30301 || (!sw && r == 0x301))) || !n || !v || !((!sw && p == 3 && (r == 1 || r == 0x301) && off == 4 && n == 1 && !(v[0] & (1U<<31))) ||
  (sw && !p && (r == 0x301 || r == 0x30301) &&
   ((off == 1 && n == 4) || (off == 5 && n == 1) ||
    (off == 25 && n == 1 && !(v[0] & ~0x000ffffcU)) ||
    (off == 26 && n == 1 && v[0] == 0x80000024U))))) return -EPERM;
 x = chain_blocked(c); if (x) return x;
 x = chain_gate(c); if (x) return x;
 x = c->write(c->ctx, r, p, sw, off, n, v); if (x) return x;
 return chain_blocked(c);
}
static int chain_caps(struct chain_io *c, unsigned r, unsigned p,
 unsigned start, unsigned wanted, unsigned *result)
{
 bool seen[256] = {false}; unsigned count=0; u32 v; int x;
 *result = 0;
 while (start) {
  if (start < 8 || start > 255 || seen[start] || count++ >= 64) return -EINVAL;
  seen[start] = true;
  x=chain_read(c,r,p,false,start,1,&v); if(x) return x;
  if (((v>>8)&255)==wanted) { if(*result) return -EINVAL; *result=start; }
  start=v&255;
 }
 return *result ? 0 : -ENOENT;
}
static void chain_expected(const struct chain_node *n, u32 h[5])
{
 h[0]=0x57868087; h[1]=0x8505c16b | (n->depth<<20);
 h[2]=n->route; h[3]=0x80000000; h[4]=0x400020ff;
}
static int chain_identity_read(struct chain_io *c, struct chain_node *n, bool configured)
{
 u32 h[5], expected[5], uid[2]; int x;
 const u32 fresh[5]={0x57868087,0x8505c16b,0,0,0x4000000a};
 chain_expected(n,expected);
 x=chain_read(c,n->route,0,true,0,5,h); if(x)return x;
 if(memcmp(h,configured?expected:fresh,sizeof(h)))return -ESTALE;
 x=chain_read(c,n->route,0,true,7,2,uid);if(x)return x;
 return uid[0]==n->uid_hi && uid[1]==n->uid_lo ? 0 : -ESTALE;
}
struct chain_drom_io {struct chain_io *chain;struct chain_node *node;};
static int chain_drom_read(void *p,unsigned off,unsigned n,u32 *v)
{struct chain_drom_io *d=p;return chain_read(d->chain,d->node->route,0,true,off,n,v);}
static int chain_drom_write(void *p,unsigned off,u32 v)
{struct chain_drom_io *d=p;return chain_write(d->chain,d->node->route,0,true,off,1,&v);}
static bool chain_drom_valid(void *p)
{struct chain_drom_io *d=p;return d->chain->valid(d->chain->ctx);}
static bool chain_drom_expired(void *p)
{struct chain_drom_io *d=p;return d->chain->now(d->chain->ctx)>=d->chain->deadline;}
static u64 chain_drom_now(void *p)
{struct chain_drom_io *d=p;return d->chain->now(d->chain->ctx);}
static void chain_drom_delay(void *p)
{struct chain_drom_io *d=p;d->chain->delay(d->chain->ctx);}
static int chain_drom(struct chain_io *c,struct chain_node *n)
{
 struct chain_drom_io d={c,n};
 struct uid_io io={.read=chain_drom_read,.write=chain_drom_write,.valid=chain_drom_valid,
  .expired=chain_drom_expired,.ctx=&d,.now_ns=chain_drom_now,.poll_delay=chain_drom_delay};
 u8 expected[sizeof(uid_expected_drom)], actual[sizeof(uid_expected_drom)], block[52];
 unsigned pos,bytes;int x;
 memcpy(expected,uid_expected_drom,sizeof(expected));
 for(pos=0;pos<4;pos++){expected[1+pos]=n->uid_lo>>(8*pos);expected[5+pos]=n->uid_hi>>(8*pos);}
 expected[0]=uid_crc8(expected+1);
 for(pos=0;pos<sizeof(actual);pos+=bytes){
  bytes=sizeof(actual)-pos;if(bytes>52)bytes=52;
  x=uid_block(&io,pos/4,(bytes+3)/4,block);if(x)return x;
  memcpy(actual+pos,block,bytes);
 }
 /* Same enclosure model/firmware DROM required; only UID+its CRC may vary. */
 if(memcmp(actual,expected,sizeof(actual)) || uid_crc(actual+13,sizeof(actual)-13)!=uid_le32(actual+9))return -ESTALE;
 x=bootstrap_disabled_ports(actual,sizeof(actual),&n->disabled);if(x)return x;
 n->identity=true;return chain_identity_read(c,n,false);
}
static int chain_inventory(struct chain_io *c,struct chain_node *n)
{
 unsigned p,up=0,down=0;int x;u32 fresh[8];
 x=chain_identity_read(c,n,true);if(x)return x;
 for(p=1;p<=23;p++) {
  if(n->disabled&(1ULL<<p))continue;
  x=chain_read(c,n->route,p,false,0,8,n->ports[p]);
  /* Intel 5786 model/firmware proven by the exact DROM: adapters13..16
   * are unimplemented and return ENODEV on the known working enclosure.
   * Only that exact absence is allowed; transport/other-port errors fail. */
  if(x == -ENODEV && p >= 13 && p <= 16)continue;
  if(x)return x;
  if(((n->ports[p][3]>>20)&63)!=p)return -ESTALE;
  switch(n->ports[p][2]&0xffffff){
   case 0x100102: if(p!=9 || up++)return -ESTALE;break;
   case 0x100101: if(down>=3)return -E2BIG;n->pcie_down[down++]=p;break;
   default:break;
  }
 }
 /* Linux usb4_switch_map_pcie_down: downstream primary lanes3,5,7 map
  * to PCIe DOWN10,17,18 in ascending adapter order for this exact DROM. */
 if(up!=1||down!=3||n->pcie_down[0]!=10||n->pcie_down[1]!=17||n->pcie_down[2]!=18)return -ESTALE;
 for(p=0;p<4;p++){
  unsigned lane=1+2*p, adapter=p?n->pcie_down[p-1]:9;
  if((n->ports[lane][2]&0xffffff)!=1)return -ESTALE;
  x=chain_caps(c,n->route,lane,n->ports[lane][1]&255,1,&n->phy[p]);if(x)return x;
  x=chain_caps(c,n->route,adapter,n->ports[adapter][1]&255,4,&n->pcie[p]);if(x)return x;
  x=chain_read(c,n->route,adapter,false,n->pcie[p],1,fresh);if(x)return x;
  if(fresh[0]&(1U<<31))return -EBUSY;
 }
 return chain_identity_read(c,n,true);
}
static int chain_unlock(struct chain_io *c,struct chain_node *parent)
{
 u32 phy[2],before,after,desired;unsigned state;int x;
 x=chain_identity_read(c,parent,true);if(x)return x;
 x=chain_read(c,parent->route,3,false,parent->phy[1],2,phy);if(x)return x;
 state=(phy[1]>>26)&15;
 if(((phy[0]>>8)&255)!=1||state<2||state>6||(phy[1]&(1U<<14)))return -ENOLINK;
 x=chain_read(c,parent->route,3,false,4,1,&before);if(x)return x;
 desired=before&~(1U<<31);
 if(desired!=before){x=chain_write(c,parent->route,3,false,4,1,&desired);if(x)return x;}
 x=chain_read(c,parent->route,3,false,4,1,&after);if(x)return x;
 return after==desired?0:-EIO;
}
static int chain_configure(struct chain_io *c,struct chain_node *n)
{
 u32 desired[5],v,after;int x;unsigned k;
 if(!n->identity)return -EPERM;
 x=chain_identity_read(c,n,false);if(x)return x;
 chain_expected(n,desired);
 x=chain_write(c,n->route,0,true,1,4,desired+1);if(x)return x;
 x=chain_identity_read(c,n,true);if(x)return x;n->configured=true;
 x=chain_read(c,n->route,0,true,5,1,&v);if(x)return x;
 if(v&1U)return -EBUSY;
 v=(v&~(1U<<23))|(1U<<24);
 x=chain_write(c,n->route,0,true,5,1,&v);if(x)return x;
 x=chain_read(c,n->route,0,true,5,1,&after);if(x)return x;
 if(after!=v)return -EIO;
 for(k=0;k<200;k++){
  x=chain_read(c,n->route,0,true,6,1,&v);if(x)return x;
  if(v&(1U<<24)){n->ready=true;return 0;}
  c->delay(c->ctx);
 }
 return -ETIMEDOUT;
}
static int chain_once(struct chain_io *c,u64 first_disabled)
{
 unsigned j;int x;
 if(c->attempted)return -EALREADY;
 c->attempted=true;
 if(!c->link_ready)return -EINVAL;
 if(!bob_chain_count(c->controller))return -EPERM;
 for(j=0;j<bob_chain_count(c->controller);j++) {
  u64 uid=bob_router_uid(c->controller,j);
  c->node[j]=(struct chain_node){.route=j==0?1:j==1?0x301:0x30301,.depth=j+1,
    .uid_hi=uid>>32,.uid_lo=uid};
 }
 c->node[0].disabled=first_disabled;
 c->node[0].configured=c->node[0].ready=c->node[0].identity=c->node[0].tmu_ready=true;
 x=chain_blocked(c);if(x)return x;
 x=chain_inventory(c,&c->node[0]);if(x)return x;
 for(j=1;j<bob_chain_count(c->controller);j++){
  x=chain_unlock(c,&c->node[j-1]);if(x)return x;
  x=chain_identity_read(c,&c->node[j],false);if(x)return x;
  x=chain_drom(c,&c->node[j]);if(x)return x;
  x=chain_configure(c,&c->node[j]);if(x)return x;
  x=chain_inventory(c,&c->node[j]);if(x)return x;
  x=c->link_ready(c->ctx,j);if(x)return x;
  x=chain_blocked(c);if(x)return x;
  c->node[j].tmu_ready=true;
 }
 return chain_blocked(c);
}
#endif
