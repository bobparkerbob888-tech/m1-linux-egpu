/* Single-use exact plan execution. All hardware capabilities remain in caller. */
#ifndef APCIEC_ASSIGNMENT_EXECUTE_CORE_H
#define APCIEC_ASSIGNMENT_EXECUTE_CORE_H
struct as_execution {
 bool attempted, complete, failed;
 unsigned next, attempted_writes, completed_writes, final_reads, last_ops;
};
struct as_execute_io {
 void *ctx;
 int (*observe)(void *, struct as_observation *);
 int (*read)(void *, unsigned, unsigned, u32 *);
 int (*write)(void *, unsigned, unsigned, u32);
};
static bool as_next_write_allowed(const struct as_plan *p, const struct as_execution *e,
 unsigned rid, unsigned off, unsigned width, u32 value)
{
 const struct as_step *step; const struct as_register *reg;
 if (!p || !p->built || !e || !e->attempted || e->complete || e->failed ||
     e->next >= p->step_count || e->completed_writes != e->next ||
     (e->attempted_writes != e->next && e->attempted_writes != e->next + 1) ||
     width != 4 || (off & 3)) return false;
 step = &p->steps[e->next]; if (step->reg >= p->count) return false;
 reg = &p->regs[step->reg];
 if (!reg->write_permitted || reg->rid != rid || reg->offset != off ||
     step->value != value) return false;
 return (rid == 0x300 && off >= 0x10 && off <= 0x20) ||
        ((rid == 0 || rid == 0x100 || rid == 0x200) && off >= 0x20 && off <= 0x2c);
}
static int as_execute_gate(const struct as_plan *p, struct as_execution *e,
                           const struct as_execute_io *io, u64 reserve, unsigned ops)
{
 struct as_observation observation = {0}; int ret;
 ret = io->observe(io->ctx, &observation); if (ret) return ret;
 ret = as_budget_check(&p->budget, &observation, reserve, ops);
 if (!ret && observation.observed.config_ops < e->last_ops) ret = -EPERM;
 if (!ret) e->last_ops = observation.observed.config_ops;
 return ret;
}
static int as_execute_read(const struct as_plan *p, struct as_execution *e,
 const struct as_execute_io *io, unsigned rid, unsigned off, u32 expected)
{
 u32 value; int ret, after;
 ret = as_execute_gate(p, e, io, 0, 0); if (ret) return ret;
 ret = io->read(io->ctx, rid, off, &value); if (ret) return ret;
 after = as_execute_gate(p, e, io, 0, 0);
 if (after) return after;
 return value == expected ? 0 : -EIO;
}
static int as_execute(const struct as_plan *p, struct as_execution *e,
 const struct as_execute_io *io, unsigned retained_ops)
{
 unsigned j; int ret;
 if (!p || !p->built || p->count != AS_MAX_REGS || p->step_count > AS_MAX_STEPS ||
     !e || !io || !io->observe || !io->read || !io->write) return -EINVAL;
 if (e->attempted || e->complete || e->failed) return -EALREADY;
 e->attempted = true; e->last_ops = retained_ops;
 ret = as_execute_gate(p, e, io, 2000000000ULL, 4608); if (ret) goto fail;
 /* Every register preimage, including read-only BAR5, before the first write. */
 for (j = 0; j < p->count; j++) {
  ret = as_execute_read(p, e, io, p->regs[j].rid, p->regs[j].offset, p->regs[j].before);
  if (ret) goto fail;
 }
 for (e->next = 0; e->next < p->step_count; e->next++) {
  const struct as_step *step = &p->steps[e->next]; const struct as_register *reg;
  if (step->reg >= p->count) {ret = -EPERM; goto fail;}
  reg = &p->regs[step->reg];
  if (!as_next_write_allowed(p, e, reg->rid, reg->offset, 4, step->value)) {
   ret = -EPERM; goto fail;
  }
  ret = as_execute_read(p, e, io, reg->rid, reg->offset, step->before); if (ret) goto fail;
  ret = as_execute_gate(p, e, io, 1000000000ULL, 256); if (ret) goto fail;
  e->attempted_writes++; /* Never repeat even if completion is uncertain. */
  ret = io->write(io->ctx, reg->rid, reg->offset, step->value); if (ret) goto fail;
  ret = as_execute_read(p, e, io, reg->rid, reg->offset, step->value); if (ret) goto fail;
  e->completed_writes++;
 }
 for (j = 0; j < p->count; j++) {
  ret = as_execute_read(p, e, io, p->regs[j].rid, p->regs[j].offset, p->regs[j].after);
  if (ret) goto fail;
  e->final_reads++;
 }
 ret = as_execute_gate(p, e, io, 0, 0); if (ret) goto fail;
 e->complete = true; return 0;
 fail:
 e->failed = true;
 return ret; /* No blind rollback, retry, resource or held-owner release. */
}
#endif
