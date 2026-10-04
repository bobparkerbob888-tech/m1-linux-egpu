/* Private retained owner. It performs ONLY CPU resource bookkeeping.
 * Nothing is published to a pci_host_bridge, device_add, driver or sysfs.
 * No resource/free/put rollback: every attempted state lives until stock reboot.
 * The caller must own the authenticated ticket and supply read-only fresh
 * context/DART/COMMAND/budget observations; this file grants no config access. */
struct as_owner {
 bool attempted, ready, failed;
 struct as_plan plan;
 struct resource resources[3];
 struct resource_entry *entries[3];
 struct list_head private_windows;
 bool reserved[3];
 unsigned last_ops;
};
struct as_owner_io {void *ctx; int (*observe)(void *, struct as_observation *);};
/* Recheck strict retained ownership before any execution/config write. */
static int as_owner_validate(const struct as_owner *owner)
{
 const unsigned long flags[3] = {
  IORESOURCE_MEM | IORESOURCE_PREFETCH | IORESOURCE_MEM_64,
  IORESOURCE_MEM, IORESOURCE_MEM | IORESOURCE_PREFETCH};
 unsigned j;
 if (!owner || !owner->attempted || !owner->ready || owner->failed ||
     !owner->plan.built || as_apertures_gate(owner->plan.apertures)) return -EPERM;
 for (j = 0; j < 3; j++) {
  const struct as_aperture *a = &owner->plan.apertures[j];
  const struct resource *r = &owner->resources[j];
  const struct resource_entry *e = owner->entries[j];
  if (!owner->reserved[j] || !e || r->parent != &iomem_resource || r->child ||
      r->start != a->cpu || r->end != a->cpu + a->size - 1 || r->flags != flags[j] ||
      e->res != r || e->offset != a->cpu - a->pci) return -EPERM;
 }
 if (owner->private_windows.next != &owner->entries[0]->node ||
     owner->private_windows.prev != &owner->entries[2]->node) return -EPERM;
 for (j = 0; j < 3; j++) {
  const struct list_head *prev = j ? &owner->entries[j-1]->node : &owner->private_windows;
  const struct list_head *next = j == 2 ? &owner->private_windows : &owner->entries[j+1]->node;
  if (owner->entries[j]->node.prev != prev || owner->entries[j]->node.next != next)
   return -EPERM;
 }
 return 0;
}
static int as_owner_gate(struct as_owner *owner, const struct as_owner_io *io)
{
 struct as_observation obs = {0}; int ret;
 if (!owner->attempted || owner->failed || !io || !io->observe) return -EPERM;
 ret = io->observe(io->ctx, &obs); if (ret) return ret;
 ret = as_budget_check(&owner->plan.budget, &obs, 2000000000ULL, 2048);
 if (!ret && obs.observed.config_ops < owner->last_ops) ret = -EPERM;
 if (!ret) owner->last_ops = obs.observed.config_ops;
 return ret;
}
static int as_owner_prepare(struct as_owner *owner, const struct as_plan *plan,
                            const struct as_owner_io *io)
{
 const unsigned long flags[3] = {
  IORESOURCE_MEM | IORESOURCE_PREFETCH | IORESOURCE_MEM_64,
  IORESOURCE_MEM, IORESOURCE_MEM | IORESOURCE_PREFETCH};
 unsigned j; int ret;
 if (!owner || !plan || !plan->built || plan->count != AS_MAX_REGS ||
     plan->step_count > AS_MAX_STEPS || as_apertures_gate(plan->apertures)) return -EINVAL;
 if (owner->attempted || owner->ready || owner->failed) return -EALREADY;
 for (j = 0; j < 3; j++) if (owner->reserved[j] || owner->entries[j] ||
     owner->resources[j].parent || owner->resources[j].child || owner->resources[j].sibling) return -EPERM;
 owner->attempted = true; /* Consumed before allocation, reservation or callbacks. */
 owner->plan = *plan; owner->last_ops = plan->budget.config_ops;
 INIT_LIST_HEAD(&owner->private_windows);
 for (j = 0; j < 3; j++) {
  struct resource *res = &owner->resources[j];
  const struct as_aperture *a = &owner->plan.apertures[j];
  ret = as_owner_gate(owner, io); if (ret) goto fail;
  *res = (struct resource){.name = "J293 private retained aperture (unpublished)",
   .start = a->cpu, .end = a->cpu + a->size - 1, .flags = flags[j]};
  owner->entries[j] = resource_list_create_entry(res, 0);
  if (!owner->entries[j]) {ret = -ENOMEM; goto fail;}
  owner->entries[j]->offset = a->cpu - a->pci;
  resource_list_add_tail(owner->entries[j], &owner->private_windows);
  ret = as_owner_gate(owner, io); if (ret) goto fail;
 }
 for (j = 0; j < 3; j++) {
  ret = as_owner_gate(owner, io); if (ret) goto fail;
  if (request_resource_conflict(&iomem_resource, &owner->resources[j])) {
   ret = -EBUSY; goto fail;
  }
  owner->reserved[j] = true;
  ret = as_owner_gate(owner, io); if (ret) goto fail;
 }
 owner->ready = true; return 0;
 fail:
 owner->failed = true;
 /* No release_resource, free, reparenting, adoption, device removal or retry. */
 return ret;
}
