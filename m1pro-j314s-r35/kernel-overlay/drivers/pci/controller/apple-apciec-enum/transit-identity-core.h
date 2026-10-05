/* SPDX-License-Identifier: GPL-2.0 */
#ifndef APCIEC_TRANSIT_IDENTITY_CORE_H
#define APCIEC_TRANSIT_IDENTITY_CORE_H
/* Fixed route only. No config operation is issued to excluded0300/0301. */
static int transit_bridge(struct retained_raw_io *io,unsigned rid,u64 serial,u32 wanted)
{
 struct retained_raw_record rec={.bus=rid>>8,.devfn=rid&255};
 u32 status,header,buses;int ret;
 ret=retained_raw_read(io,rec.bus,rec.devfn,0,&rec.id);if(ret)return ret;
 ret=retained_raw_read(io,rec.bus,rec.devfn,4,&status);if(ret)return ret;
 ret=retained_raw_read(io,rec.bus,rec.devfn,8,&rec.class_rev);if(ret)return ret;
 ret=retained_raw_read(io,rec.bus,rec.devfn,12,&header);if(ret)return ret;
 rec.header=header>>16;rec.command=status;
 if(rec.id!=(rid?0x57868086U:0x1010106bU)||
    rec.class_rev!=(rid?0x06040085U:0x06040000U)||rec.header!=1||(status&7))return -ESTALE;
 if(rid){ret=retained_raw_serial(io,rec.bus,rec.devfn,&rec.serial);if(ret)return ret;
  if(rec.serial!=serial)return -ESTALE;}
 ret=retained_raw_read(io,rec.bus,rec.devfn,0x18,&buses);if(ret)return ret;
 if(buses&0x00ffffff)return -ESTALE; /* No inherited path is rewritten. */
 io->record(io->ctx,&rec);io->devices++;
 if(!wanted)return 0; /* First enclosure's local bridge remains unassigned. */
 ret=retained_raw_bridge_ready(io,rec.bus,rec.devfn,NULL);if(ret)return ret<0?ret:-ENOLINK;
 return retained_raw_write(io,rec.bus,rec.devfn,0x18,(buses&0xff000000)|wanted);
}
static int transit_identify(struct retained_raw_io *io)
{
 static const struct {unsigned rid;u64 serial;u32 buses;} path[]={
  {0,0,0x00060100},
  {0x100,PROVISION_PRIVATE_ID_33,0x00060201},
  {0x200,PROVISION_PRIVATE_ID_33,0},
  {0x208,PROVISION_PRIVATE_ID_33,0x00060402},
  {0x400,PROVISION_PRIVATE_ID_36,0x00060504},
  {0x500,PROVISION_PRIVATE_ID_36,0x00060605},
 };
 struct retained_raw_record rec={.bus=6,.devfn=0};
 u32 status,header,again;unsigned j;int ret;
 if(!io->strict_identity||io->first||io->last<6)return -EPERM;
 ret=retained_raw_initial_settle(io);if(ret)return ret;
 for(j=0;j<ARRAY_SIZE(path);j++){
  ret=transit_bridge(io,path[j].rid,path[j].serial,path[j].buses);if(ret)return ret;
 }
 ret=retained_raw_read(io,6,0,0,&rec.id);if(ret)return ret;
 ret=retained_raw_read(io,6,0,4,&status);if(ret)return ret;
 ret=retained_raw_read(io,6,0,8,&rec.class_rev);if(ret)return ret;
 ret=retained_raw_read(io,6,0,12,&header);if(ret)return ret;
 ret=retained_raw_read(io,6,0,0x2c,&rec.subsystem);if(ret)return ret;
 rec.header=header>>16;rec.command=status;
 if(rec.id!=0x2d0410de||rec.class_rev!=0x030000a1||rec.header!=0x80||
    rec.subsystem!=0x41cd1458||(status&7))return -ESTALE;
 ret=retained_raw_serial(io,6,0,&rec.serial);if(ret)return ret;
 if(!rec.serial||rec.serial==~0ULL)return -ENODATA;
 ret=retained_raw_read(io,6,0,0,&again);if(ret)return ret;
 if(again!=rec.id)return -ESTALE;
 ret=retained_raw_read(io,6,0,4,&again);if(ret)return ret;
 if(again!=status)return -ESTALE;
 io->record(io->ctx,&rec);io->devices++;io->nvidia++;
 /* Validate all bridge-number assignments and every path's closed decode. */
 for(j=0;j<ARRAY_SIZE(path);j++){
  ret=retained_raw_read(io,path[j].rid>>8,path[j].rid&255,0x18,&again);if(ret)return ret;
  if((again&0x00ffffff)!=path[j].buses)return -ESTALE;
  ret=retained_raw_read(io,path[j].rid>>8,path[j].rid&255,4,&again);if(ret)return ret;
  if(again&7)return -EPERM;
 }
 return 0;
}
#endif
