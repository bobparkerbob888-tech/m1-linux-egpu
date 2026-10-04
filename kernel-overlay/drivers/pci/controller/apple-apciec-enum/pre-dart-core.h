/* Native _enableClocks table order and masked RMW; no inferred status bits. */
#ifndef APPLE_PRE_DART_CORE_H
#define APPLE_PRE_DART_CORE_H
struct apcie_tunable_row { unsigned int offset, mask, value; };
struct apcie_tunable_table {
 const struct apcie_tunable_row *rows;
 unsigned int count;
};
struct apcie_tunable_io {
 void *context;
 unsigned int (*read)(void *, unsigned int, unsigned int);
 void (*write)(void *, unsigned int, unsigned int, unsigned int);
};
static int apcie_tunables_validate(const struct apcie_tunable_table *t,
                                  int common_absent)
{
 unsigned int i, j;
 if (!common_absent || t[0].count || t[0].rows ||
     !t[1].rows || t[1].count != 1 || !t[2].rows || t[2].count != 27)
  return -22;
 for (i = 0; i < 3; i++)
  for (j = 0; j < t[i].count; j++) {
   const struct apcie_tunable_row *r = &t[i].rows[j];
   if ((r->offset & 3) || r->offset > 0x3ffc || !r->mask ||
       (r->value & ~r->mask))
    return -22;
  }
 return 0;
}
static int apcie_tunables_apply(const struct apcie_tunable_table *t,
                              int common_absent, const struct apcie_tunable_io *io)
{
 unsigned int i, j;
 int ret = apcie_tunables_validate(t, common_absent);
 if (ret)
  return ret;
 for (i = 0; i < 3; i++)
  for (j = 0; j < t[i].count; j++) {
   const struct apcie_tunable_row *r = &t[i].rows[j];
   unsigned int old = io->read(io->context, i, r->offset);
   if ((old & r->mask) != (r->value & r->mask))
    io->write(io->context, i, r->offset,
              (old & ~r->mask) | (r->value & r->mask));
  }
 return 0;
}
#endif
