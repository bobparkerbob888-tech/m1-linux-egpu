/* SPDX-License-Identifier: GPL-2.0 */
/* Narrow standard USB4 CS1..4 upload, NOT usb4_switch_setup/configuration_valid.
 * Wrapper must bind callbacks to route1 port0 SWITCH and hold ACIO+TB locks.
 * valid() must require fresh same-call identity plus exact retained ownership;
 * bootstrap write callback must enforce rootPE-clear/external-disabled before
 * and after every upload. Adapter inventory intentionally occurs after RR.
 */
struct jc_child_cfg_io {
 const struct jc_bootstrap_pins *pins;
 int (*read)(void *,unsigned,unsigned,u32 *);
 int (*write)(void *,unsigned,unsigned,const u32 *);
 bool (*valid)(void *);
 bool (*expired)(void *);
 void *ctx;
 unsigned operations;
 u64 expected_uid;
 bool attempted;
};
static int jc_child_cfg_gate(struct jc_child_cfg_io *io)
{
 if(!io->valid(io->ctx))return -EPERM;
 if(io->operations>=8||io->expired(io->ctx))return -ETIMEDOUT;
 io->operations++;return 0;
}
static int jc_child_cfg_read(struct jc_child_cfg_io *io,unsigned off,unsigned count,u32*v)
{
 int ret=jc_child_cfg_gate(io);if(ret)return ret;
 if(!((off==0&&count==5)||(off==7&&count==2)))return -EPERM;
 ret=io->read(io->ctx,off,count,v);if(ret)return ret;
 if(io->expired(io->ctx))return -ETIMEDOUT;
 return io->valid(io->ctx)?0:-EPERM;
}
static int jc_child_cfg_once(struct jc_child_cfg_io *io,u32 before[5],u32 after[5])
{
 const u32 *expected=io->pins->child_before;
 u32 desired[5],uid[2];unsigned i;int ret;
 u64 target=io->expected_uid;
 if(!jc_bootstrap_pins_valid(io->pins)||target!=io->pins->uid)return -EPERM;
 if(io->attempted)return -EALREADY;
 io->attempted=true;
 ret=jc_child_cfg_read(io,0,5,before);if(ret)return ret;
 for(i=0;i<5;i++)if(before[i]!=expected[i])return -ESTALE;
 ret=jc_child_cfg_read(io,7,2,uid);if(ret)return ret;
 if(uid[0]!=(u32)(target>>32)||uid[1]!=(u32)target)return -EPERM;
 memcpy(desired,io->pins->child_after,sizeof(desired));
 ret=jc_child_cfg_gate(io);if(ret)return ret;
 /* Exactly one native four-DWORD config request. Transport may retransmit. */
 ret=io->write(io->ctx,1,4,desired+1);if(ret)return ret;
 if(io->expired(io->ctx))return -ETIMEDOUT;
 if(!io->valid(io->ctx))return -EPERM;
 ret=jc_child_cfg_read(io,0,5,after);if(ret)return ret;
 for(i=0;i<5;i++)if(after[i]!=desired[i])return -EIO;
 ret=jc_child_cfg_read(io,7,2,uid);if(ret)return ret;
 if(uid[0]!=(u32)(target>>32)||uid[1]!=(u32)target)return -ESTALE;
 return 0;
}
