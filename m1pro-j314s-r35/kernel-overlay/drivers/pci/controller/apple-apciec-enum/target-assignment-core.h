/* SPDX-License-Identifier: GPL-2.0 */
/* LOCAL ONLY. Exact planned memory register transaction; no enable/DMA writes.
 * Caller must supply a consumed one-shot owner and deadline-bound I/O gate. */
#ifndef BOB_TARGET_ASSIGNMENT_CORE_H
#define BOB_TARGET_ASSIGNMENT_CORE_H
struct tn_assign_io {
 void *ctx; int (*audit)(void *);
 int (*read)(void *,unsigned,unsigned,u32 *);
 int (*write)(void *,unsigned,unsigned,u32);
};
static int tn_assign_register(struct tn_assign_io *io,unsigned rid,unsigned off,u32 val)
{
 u32 got;int r=io->audit(io->ctx);if(r)return r;
 r=io->write(io->ctx,rid,off,val);if(r)return r;
 r=io->audit(io->ctx);if(r)return r;
 r=io->read(io->ctx,rid,off,&got);if(r)return r;
 return got==val?0:-EIO;
}
static int tn_assign_memory(struct tn_assign_io *io,const struct ep_snapshot *s)
{
 unsigned j,k;int r;u32 v;u64 pci,cpu,size;unsigned type;
 if(!io||!io->audit||!io->read||!io->write||!s||!s->planned||s->memory_assigned)
  return -EINVAL;
 /* Validate the complete plan before emitting even the first write. */
 for(j=0;j<6;j++)if(tn_bar(j,&pci,&cpu,&size,&type))
  if(s->bars[j].pci!=pci||s->bars[j].cpu!=cpu||s->bars[j].size!=size)
   return -EINVAL;
 r=io->audit(io->ctx);if(r)return r;
 /* Every bridge remains COMMAND0 until publication's separate enable stage. */
 for(j=0;j<7;j++)if(tn_positions[j].forwarding)
  for(k=0x20;k<=0x2c;k+=4) {
   if(!tn_window(tn_positions[j].rid,k,&v))return -EINVAL;
   r=tn_assign_register(io,tn_positions[j].rid,k,v);if(r)return r;
  }
 for(j=0;j<6;j++)if(tn_bar(j,&pci,&cpu,&size,&type)) {
  if(type&4){r=tn_assign_register(io,0x600,0x14+4*j,pci>>32);if(r)return r;}
  r=tn_assign_register(io,0x600,0x10+4*j,(u32)pci|type);if(r)return r;
 }
 return io->audit(io->ctx);
}
#endif
