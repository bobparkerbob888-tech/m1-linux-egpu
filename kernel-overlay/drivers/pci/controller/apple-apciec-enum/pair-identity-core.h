/* SPDX-License-Identifier: GPL-2.0 */
#ifndef BOB_PAIR_IDENTITY_CORE_H
#define BOB_PAIR_IDENTITY_CORE_H
static int pn_identify_gpu(struct retained_raw_io *io,unsigned rid,u64 *serial)
{
 struct retained_raw_record rec={.bus=rid>>8,.devfn=0};u32 status,header,again;u64 dsn;int r;
 r=retained_raw_read(io,rec.bus,0,0,&rec.id);if(r)return r;
 r=retained_raw_read(io,rec.bus,0,4,&status);if(r)return r;
 r=retained_raw_read(io,rec.bus,0,8,&rec.class_rev);if(r)return r;
 r=retained_raw_read(io,rec.bus,0,12,&header);if(r)return r;
 r=retained_raw_read(io,rec.bus,0,0x2c,&rec.subsystem);if(r)return r;
 rec.header=header>>16;rec.command=status;
 if(rec.id!=0x2d0410de||rec.class_rev!=0x030000a1||rec.header!=0x80||rec.subsystem!=0x41cd1458||(status&65535))return -ESTALE;
 r=retained_raw_serial(io,rec.bus,0,&rec.serial);if(r)return r;
 if(!pn_serial_ok(rid,rec.serial))return -ESTALE;
 r=retained_raw_serial(io,rec.bus,0,&dsn);if(r)return r;if(dsn!=rec.serial)return -ESTALE;
 r=retained_raw_read(io,rec.bus,0,0,&again);if(r)return r;if(again!=rec.id)return -ESTALE;
 r=retained_raw_read(io,rec.bus,0,4,&again);if(r)return r;if(again!=status)return -ESTALE;
 io->record(io->ctx,&rec);io->devices++;io->nvidia++;*serial=rec.serial;return 0;
}
static int pn_identify(struct retained_raw_io *io)
{
 unsigned j;u32 got,want;u64 serial[2]={0},again;int r;
 if(!io->strict_identity||io->first||io->last<6)return -EPERM;
 r=retained_raw_initial_settle(io);if(r)return r;
 for(j=0;j<8;j++){
  unsigned rid=pn_positions[j].rid;
  if(pn_positions[j].forwarding){
   u64 box=j==0?0:j<=2||j==4?PROVISION_PRIVATE_ID_14:PROVISION_PRIVATE_ID_15;
   want=(rid>>8)|(pn_positions[j].secondary<<8)|(pn_positions[j].subordinate<<16);
   r=transit_bridge(io,rid,box,want);
  }else r=pn_identify_gpu(io,rid,&serial[rid==0x600]);
  if(r)return r;
 }
 for(j=0;j<8;j++){
  unsigned rid=pn_positions[j].rid;
  if(pn_positions[j].forwarding){
   want=(rid>>8)|(pn_positions[j].secondary<<8)|(pn_positions[j].subordinate<<16);
   r=retained_raw_read(io,rid>>8,rid&255,0x18,&got);if(r)return r;if((got&0xffffff)!=want)return -ESTALE;
  }else{r=retained_raw_serial(io,rid>>8,0,&again);if(r)return r;if(again!=serial[rid==0x600])return -ESTALE;}
  r=retained_raw_read(io,rid>>8,rid&255,4,&got);if(r)return r;if(got&65535)return -EPERM;
 }
 return 0;
}
#endif
