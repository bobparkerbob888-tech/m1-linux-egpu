/* Runs only inside the existing endpoint API/lifecycle lock and original task. */
struct retained_assignment_context {struct ep_context *ep; struct ep_io *io;};
static int retained_assignment_observe(void *arg, struct as_observation *observation)
{
 struct retained_assignment_context *a = arg; struct apple_apciec *p = a->ep->p;
 int ret;
 if (!endpoint_memory_assign || !p->endpoint_assignment_attempted ||
     a->ep->phase != 13 || !retained_ep_valid(a->ep)) return -EPERM;
 if (p->endpoint_owner && p->endpoint_owner->ready) {
  ret = as_owner_validate(p->endpoint_owner); if (ret) return ret;
 } else if (p->endpoint_execution.attempted || p->endpoint_assignment_armed) return -EPERM;
 ret = ep_selected_recheck(a->io, a->ep->rid); if (ret) return ret;
 ret = retained_ep_safe(a->ep, a->ep->rid); if (ret) return ret;
 /* Host-local read-only primitives; no recursive lifecycle or ACIO/TB locks. */
 ret = retained_identity_port_audit(p, true); if (ret) return ret;
 ret = retained_root_rc_audit(p); if (ret) return ret;
 *observation = (struct as_observation){
  .observed = {p->retained_scan_deadline, p->retained_identity_deadline,
               p->retained_scan_ops},
  .now = ktime_get_boottime_ns(), .valid = retained_ep_valid(a->ep)};
 return observation->valid ? 0 : -EPERM;
}
static int retained_assignment_read(void *arg, unsigned rid, unsigned off, u32 *value)
{
 struct retained_assignment_context *a = arg;
 int ret;
 dev_info(a->ep->p->dev, "retained-memory-read: begin RID %04x offset %03x step %u final-reads %u\n",
          rid, off, a->ep->p->endpoint_execution.next, a->ep->p->endpoint_execution.final_reads);
 ret = ep_read(a->io, rid, off, value);
 dev_info(a->ep->p->dev, "retained-memory-read: end RID %04x offset %03x status %d value %08x\n",
          rid, off, ret, ret ? 0 : *value);
 return ret;
}
static int retained_assignment_write(void *arg, unsigned rid, unsigned off, u32 value)
{
 struct retained_assignment_context *a = arg; struct apple_apciec *p = a->ep->p;
 struct pci_bus bus = {.number = rid >> 8, .sysdata = p, .ops = &apple_apciec_ops};
 bool pfm = rid == 0 && (off == 0x24 || off == 0x28 || off == 0x2c);
 unsigned long flags; u32 clock_before = 0, clock_after = 0;
 int ret = PCIBIOS_SET_FAILED;
 if (!retained_ep_valid(a->ep) || !p->endpoint_owner || !p->endpoint_owner->ready ||
     p->endpoint_owner->failed || as_owner_validate(p->endpoint_owner) || !as_next_write_allowed(&p->endpoint_owner->plan,
       &p->endpoint_execution, rid, off, 4, value)) return -EPERM;
 if (pfm && (!endpoint_memory_assign || a->ep->phase != 13 || p->retained_phase != 13 ||
     !p->power_ready || !p->port || p->rid_entries != 64 ||
     retained_ep_budget(p, NSEC_PER_SEC, 262))) return -EPERM;
 raw_spin_lock_irqsave(&p->lock, flags);
 if (p->endpoint_assignment_armed) {raw_spin_unlock_irqrestore(&p->lock, flags); return -EPERM;}
 p->endpoint_assignment_armed = true;
 raw_spin_unlock_irqrestore(&p->lock, flags);
 dev_info(p->dev, "retained-memory-write: begin step %u RID %04x offset %03x value %08x\n",
          p->endpoint_execution.next, rid, off, value);
 if (pfm) {
  /* AppleT8103PCIeCPort PFM early/late WAR: hold APPCLK across the
   * already-planned root PFM write, then write 1 to logical 0x994.
   * Corellium's M1 PCIEC config_write independently does the same latch.
   * Reserve all six port accesses in the ORIGINAL budget before MMIO;
   * failed paths never retry the config/latch and always restore APPCLK.
   * Latch semantics are not assumed readable (it may be a strobe).
   */
  p->retained_scan_ops += 6;
  clock_before = readl(p->port + 0x800);
  if (clock_before == ~0U || !(clock_before & BIT(0)) ||
      (clock_before & BIT(8))) goto unarm;
  writel(clock_before | BIT(8), p->port + 0x800);
  if (readl(p->port + 0x800) != (clock_before | BIT(8))) goto restore_clock;
 }
 ret = apple_apciec_config_write(&bus, rid & 255, off, 4, value);
 if (pfm && ret == PCIBIOS_SUCCESSFUL)
  writel(1, p->port + apple_apciec_logical_offset(p, 0x994));
 restore_clock:
 if (pfm) {
  writel(clock_before, p->port + 0x800);
  clock_after = readl(p->port + 0x800);
  if (clock_after != clock_before) ret = PCIBIOS_SET_FAILED;
  dev_info(p->dev, "retained-pfm-latch: root offset%03x APPCLK%08x->%08x pci-status%d\n",
           off, clock_before, clock_after, ret);
 }
 unarm:
 dev_info(p->dev, "retained-memory-write: end step %u RID %04x offset %03x pci-status %d\n",
          p->endpoint_execution.next, rid, off, ret);
 raw_spin_lock_irqsave(&p->lock, flags);
 p->endpoint_assignment_armed = false;
 raw_spin_unlock_irqrestore(&p->lock, flags);
 return ret == PCIBIOS_SUCCESSFUL ? 0 : -EIO;
}

static int retained_assign_memory(struct ep_context *c, struct ep_io *io)
{
 struct apple_apciec *p = c->p; struct retained_assignment_context context = {c, io};
 struct as_observation observation = {0};
 const struct as_owner_io owner_io = {&context, retained_assignment_observe};
 const struct as_execute_io execute_io = {&context, retained_assignment_observe,
                         retained_assignment_read, retained_assignment_write};
 int ret;
 if (!endpoint_memory_assign || !c->sizing || c->phase != 11 || !retained_ep_valid(c) ||
     p->endpoint_assignment_attempted || p->endpoint_owner ||
     !p->endpoint_snapshot->sized || !p->endpoint_snapshot->planned) return -EPERM;
 ret = retained_ep_budget(p, 2ULL * NSEC_PER_SEC, 5120); if (ret) return ret;
 p->endpoint_assignment_attempted = true; p->retained_phase = 13; c->phase = 13;
 /* The host phase latches BEFORE even this retained owner allocation. */
 p->endpoint_owner = kzalloc(sizeof(*p->endpoint_owner), GFP_KERNEL);
 if (!p->endpoint_owner) return -ENOMEM;
 ret = retained_assignment_observe(&context, &observation); if (ret) goto fail;
 ret = as_plan_build(p->endpoint_snapshot, as_apertures, &observation,
                     &p->endpoint_owner->plan); if (ret) goto fail;
 ret = as_owner_prepare(p->endpoint_owner, &p->endpoint_owner->plan, &owner_io);
 if (ret) goto fail;
 ret = as_execute(&p->endpoint_owner->plan, &p->endpoint_execution, &execute_io,
                  p->endpoint_owner->last_ops); if (ret) goto fail;
 return 0;
 fail:
 p->endpoint_owner->failed = true; /* Retain partial allocation/reservation/config. */
 return ret;
}
static void retained_assignment_dump(struct apple_apciec *p, int status)
{
 unsigned j;
 dev_info(p->dev,"retained-memory-assignment-host: status %d phase %u attempted %u owner %u ready %u failed %u writes-attempted %u writes-completed %u final-reads %u complete %u config-ops %u raw-deadline %llu ticket-deadline %llu; no decode or DMA permit\n",
  status,p->retained_phase,p->endpoint_assignment_attempted,!!p->endpoint_owner,
  p->endpoint_owner?p->endpoint_owner->ready:0,p->endpoint_owner?p->endpoint_owner->failed:0,
  p->endpoint_execution.attempted_writes,p->endpoint_execution.completed_writes,
  p->endpoint_execution.final_reads,p->endpoint_execution.complete,p->retained_scan_ops,
  (unsigned long long)p->retained_scan_deadline,(unsigned long long)p->retained_identity_deadline);
 if (!p->endpoint_owner) return;
 for (j = 0; j < 3; j++) dev_info(p->dev,"retained-memory-owner: window %u reserved %u cpu %016llx end %016llx; private/unpublished\n",j,p->endpoint_owner->reserved[j],
  (unsigned long long)p->endpoint_owner->resources[j].start,
  (unsigned long long)p->endpoint_owner->resources[j].end);
 for (j = 0; j < p->endpoint_owner->plan.count; j++) {
  const struct as_register *r = &p->endpoint_owner->plan.regs[j];
  dev_info(p->dev,"retained-memory-register: index %u RID %04x offset %03x before %08x after %08x writable %u\n",j,r->rid,r->offset,r->before,r->after,r->write_permitted);
 }
}
