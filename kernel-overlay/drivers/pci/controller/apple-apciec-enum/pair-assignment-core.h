/* SPDX-License-Identifier: GPL-2.0 */
#ifndef BOB_PAIR_ASSIGNMENT_CORE_H
#define BOB_PAIR_ASSIGNMENT_CORE_H
struct pn_assign_io {
 void *ctx;int (*audit)(void *);int (*read)(void *,unsigned,unsigned,u32 *);
 int (*write)(void *,unsigned,unsigned,u32);
};
static int pn_saved_register(const struct ep_snapshot *s,unsigned rid,unsigned off,u32 *v)
{
 int i=pn_index(rid);unsigned j;bool found=false;
 if(!s||s->count!=8||i<0)return -EINVAL;
 for(j=0;j<s->functions[i].sample_count;j++)if(s->functions[i].samples[j].offset==off){
  if(found)return -EINVAL;
  *v=s->functions[i].samples[j].value;found=true;
 }
 return found?0:-EINVAL;
}
static int pn_assign_memory(struct pn_assign_io *io,const struct ep_snapshot *a,const struct ep_snapshot *b)
{
 unsigned step,rid,off;u32 want,before,got;int r;
 if(!a||!b||!a->planned||!b->planned||a->memory_assigned||b->memory_assigned||
  a->count!=8||b->count!=8||a->selected!=7||b->selected!=3)return -EPERM;
 /* Establish completeness before the first write. */
 for(step=0;step<PN_ASSIGN_WRITES;step++){
  if(!pn_write_at(step,&rid,&off,&want))return -EINVAL;
  r=pn_saved_register(a,rid,off,&before);if(r)return r;
  r=pn_saved_register(b,rid,off,&got);if(r)return r;if(before!=got)return -ESTALE;
 }
 for(step=0;step<PN_ASSIGN_WRITES;step++){
  pn_write_at(step,&rid,&off,&want);pn_saved_register(a,rid,off,&before);
  r=io->audit(io->ctx);if(r)return r;
  r=io->read(io->ctx,rid,off,&got);if(r)return r;if(got!=before)return -ESTALE;
  r=io->audit(io->ctx);if(r)return r;
  r=io->write(io->ctx,rid,off,want);if(r)return r;
  r=io->audit(io->ctx);if(r)return r;
  r=io->read(io->ctx,rid,off,&got);if(r)return r;if(got!=want)return -EIO;
 }
 return io->audit(io->ctx);
}
#endif
