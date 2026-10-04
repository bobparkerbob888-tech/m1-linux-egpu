/* Read-only checks against the original raw transaction budget. */
#ifndef APCIEC_ASSIGNMENT_BUDGET_H
#define APCIEC_ASSIGNMENT_BUDGET_H
struct as_aperture {u32 flags; u64 pci, cpu, size;};
static const struct as_aperture as_apertures[3] = {
 {0x43000000, 0x400000000ULL, 0x400000000ULL, 0x80000000ULL},
 {0x02000000, 0x80000000ULL, 0x480000000ULL, 0x40000000ULL},
 {0x42000000, 0xc0000000ULL, 0x4c0000000ULL, 0x40000000ULL},
};
struct as_budget {u64 raw_deadline, ticket_deadline; unsigned config_ops;};
struct as_observation {struct as_budget observed; u64 now; bool valid;};
static int as_apertures_gate(const struct as_aperture *a)
{
 unsigned j;
 if (!a) return -EINVAL;
 for (j = 0; j < 3; j++) if (a[j].flags != as_apertures[j].flags ||
     a[j].pci != as_apertures[j].pci || a[j].cpu != as_apertures[j].cpu ||
     a[j].size != as_apertures[j].size) return -EPERM;
 return 0;
}
static int as_budget_check(const struct as_budget *original,
                           const struct as_observation *obs,
                           u64 reserve_ns, unsigned reserve_ops)
{
 if (!original || !obs || !obs->valid || !original->raw_deadline ||
     original->raw_deadline > original->ticket_deadline ||
     obs->observed.raw_deadline != original->raw_deadline ||
     obs->observed.ticket_deadline != original->ticket_deadline ||
     obs->observed.config_ops < original->config_ops) return -EPERM;
 if (reserve_ops > 8192 || obs->observed.config_ops > 8192 - reserve_ops ||
     obs->now >= original->raw_deadline || original->raw_deadline - obs->now < reserve_ns)
  return -ETIMEDOUT;
 return 0;
}
#endif
