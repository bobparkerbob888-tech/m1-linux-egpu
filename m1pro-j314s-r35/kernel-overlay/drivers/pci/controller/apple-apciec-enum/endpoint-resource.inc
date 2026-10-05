/* Ticket-scoped, single-consumption extension after raw discovery phase 10.
 * Optional private memory assignment only; no PCI core/driver/MSI/reset/RID/DMA. */
#include "endpoint-resource-core.h"
struct ep_context { struct apple_apciec *p; const void *ticket; unsigned rid; bool sizing; unsigned phase; };
static bool retained_ep_valid(void *arg)
{
 struct ep_context *c = arg;
 return endpoint_resources && c->p->retained_raw_identity &&
        (c->phase == 11 || (c->phase == 13 && endpoint_memory_assign &&
          c->p->endpoint_assignment_attempted)) &&
        !retained_commit_owner(c->p, 3, c->ticket, c->phase) && c->p->tunnel_ready &&
        c->p->retained_scan_task == current && c->p->endpoint_selected_rid == c->rid;
}
static int retained_ep_budget(struct apple_apciec *p, u64 reserve, unsigned operations)
{
 u64 now = ktime_get_boottime_ns();
 if (!p->retained_scan_deadline || p->retained_scan_deadline > p->retained_identity_deadline ||
     p->retained_scan_exhausted || now >= p->retained_scan_deadline ||
     p->retained_scan_deadline - now < reserve || !retained_scan_reserve(p, operations))
  return -ETIMEDOUT;
 return 0;
}
static int retained_ep_probe_ready(void *arg)
{
 struct ep_context *c = arg;
 if (!retained_ep_valid(c) || !c->sizing) return -EPERM;
 /* Admission for a complete BAR/pair, never a renewed deadline or restore. */
 return retained_ep_budget(c->p, NSEC_PER_SEC, 256);
}
static int retained_ep_read(void *arg, unsigned rid, unsigned off, u32 *v)
{
 struct ep_context *c = arg;
 struct pci_bus bus = {.number = rid >> 8, .sysdata = c->p, .ops = &apple_apciec_ops};
 return apple_apciec_config_read(&bus, rid & 255, off, 4, v) == PCIBIOS_SUCCESSFUL ? 0 : -EIO;
}
static int retained_ep_safe(void *arg, unsigned rid)
{
 struct ep_context *c = arg; unsigned j; u32 v; int ret;
 if (rid != c->rid || !retained_ep_valid(c)) return -EPERM;
 ret = retained_dma_blocked(c->p); if (ret) return ret;
 /* Decode and BME denial extends to EVERY raw function, not just the GPU. */
 for (j = 0; j < c->p->retained_record_count; j++) {
  ret = retained_ep_read(c, c->p->retained_records[j].rid, 4, &v);
  if (ret) return ret;
  if (v & (c->sizing ? 65535U : 7U)) return -EPERM;
 }
 return retained_ep_valid(c) ? 0 : -EPERM;
}
static int retained_ep_write(void *arg, unsigned rid, unsigned off, u32 v)
{
 struct ep_context *c = arg;
 struct pci_bus bus = {.number = rid >> 8, .sysdata = c->p, .ops = &apple_apciec_ops};
 if (!c->sizing || rid != c->rid || off < 0x10 || off > 0x24 || (off & 3)) return -EPERM;
 return apple_apciec_config_write(&bus, rid & 255, off, 4, v) == PCIBIOS_SUCCESSFUL ? 0 : -EIO;
}
#include "endpoint-aperture.h"
#include "target-resource-owner.inc"
#include "target-resource-plan.h"
#include "target-assignment.inc"
static int retained_ep_apertures(struct apple_apciec *p)
{ return p->profile && p->profile->index==1 ? tn_aperture_descriptor(p) : apple_endpoint_apertures(p->dev->of_node); }

#include "endpoint-assignment.inc"

static void retained_ep_dump(struct apple_apciec *p, int status)
{
 const struct ep_snapshot *s = p->endpoint_snapshot;
 unsigned j, k, n = s->count;
 if (n < EP_MAX_RECORDS && s->functions[n].sample_count) n++;
 dev_info(p->dev,"retained-resource: status %d phase %u captured %u sized %u planned %u functions %u selected %u same-device %02x ancestors %u config-ops %u deadline %llu\n",
  status,p->retained_phase,s->captured,s->sized,s->planned,s->count,s->selected,
  s->same_device_mask,s->ancestor_count,p->retained_scan_ops,(unsigned long long)p->retained_scan_deadline);
 for (j = 0; j < n; j++) {
  const struct ep_function *f = &s->functions[j];
  dev_info(p->dev,"retained-resource-function: RID %04x id %08x class %08x subsystem %08x serial %016llx header %02x command %04x samples %u PM %03x MSI %03x MSIX %03x PCIe %03x ACS %03x ReBAR %03x FLR %u ARI %u ATS %u PASID %u SRIOV %u\n",
   f->identity.rid,f->identity.id,f->identity.class_rev,f->identity.subsystem,
   (unsigned long long)f->identity.serial,f->identity.header,f->command,f->sample_count,
   f->pm,f->msi,f->msix,f->pcie,f->acs,f->rebar,f->flr_capable,f->ari,f->ats,f->pasid,f->sriov);
  for (k = 0; k < f->sample_count; k++)
   dev_info(p->dev,"retained-resource-raw: RID %04x offset %03x value %08x\n",
    f->identity.rid,f->samples[k].offset,f->samples[k].value);
 }
 for (j = 0; j < 6; j++) {
  const struct ep_bar *b = &s->bars[j];
  dev_info(p->dev,"retained-resource-bar: index %u saved %08x:%08x mask %08x:%08x size %016llx pci %016llx cpu %016llx flags %x window %u upper %u unsupported-io %u (I/O remains unsized/unassigned)\n",
   j,b->saved[1],b->saved[0],b->mask[1],b->mask[0],(unsigned long long)b->size,
   (unsigned long long)b->pci,(unsigned long long)b->cpu,b->flags,b->window,b->upper,b->unsupported_io);
 }
 for (j = 0; j < s->ancestor_count; j++) {
  dev_info(p->dev,"retained-resource-ancestor: index %u RID %04x\n",j,s->functions[s->ancestors[j]].identity.rid);
  for (k = 0; k < 3; k++)
   dev_info(p->dev,"retained-resource-window: ancestor %u window %u active %u start %016llx end %016llx; plan only\n",
    j,k,s->bridges[j].active[k],(unsigned long long)s->bridges[j].start[k],(unsigned long long)s->bridges[j].end[k]);
 }
}
int apple_apciec_retained_records(struct device *dev, unsigned port, const void *ticket,
 const struct ep_identity **records, unsigned *count)
{
 struct apple_apciec *p = dev_get_drvdata(dev); int ret;
 if (!records || !count) return -EINVAL;
 *records = NULL; *count = 0;
 if (!p) return -ENODEV;
 if ((!endpoint_resources && !p->j314s_raw_capability) || !p->retained_raw_identity) return -EPERM;
 mutex_lock(&p->lifecycle);
 ret = retained_commit_owner(p, port, ticket, 10);
 if (!ret && (!p->retained_record_count || p->retained_record_count > EP_MAX_RECORDS)) ret = -EPERM;
 if (!ret) { *records = p->retained_records; *count = p->retained_record_count; }
 mutex_unlock(&p->lifecycle); return ret;
}
EXPORT_SYMBOL_GPL(apple_apciec_retained_records);
int apple_apciec_retained_endpoint_resources(struct device *dev, unsigned port,
 const void *ticket, const struct ep_identity *allowed, bool size_bars, bool assign_memory,
 const struct ep_snapshot **result, unsigned *phase)
{
 struct apple_apciec *p = dev_get_drvdata(dev); struct ep_context c;
 struct ep_io io; unsigned long flags; int ret; bool consumed = false;
 if (result) *result = NULL;
 if (phase) *phase = 0;
 if (!p) return -ENODEV;
 if (!allowed || !result || !phase || !endpoint_resources || !p->retained_raw_identity ||
     assign_memory != endpoint_memory_assign || (assign_memory && !size_bars)) return -EINVAL;
 mutex_lock(&p->lifecycle);
 ret = retained_commit_owner(p, port, ticket, 10); if (ret) goto out;
 if (!p->tunnel_ready || p->bridge || p->endpoint_snapshot || !p->retained_record_count ||
     p->retained_record_count > EP_MAX_RECORDS) { ret = -EPERM; goto out; }
 if(p->profile->index==1) {
  unsigned j;
  if(!size_bars||!assign_memory||allowed->rid!=0x600||p->retained_record_count!=7){ret=-EPERM;goto out;}
  for(j=0;j<7;j++)if(p->retained_records[j].rid!=tn_positions[j].rid){ret=-EPERM;goto out;}
  if(!ep_identity_equal(allowed,&p->retained_records[6])){ret=-EPERM;goto out;}
 }
 consumed = true;
 p->retained_phase = 11; /* Consumed before allocation/admission/config; never retry. */
 ret = retained_ep_budget(p, 2ULL * NSEC_PER_SEC, 2048); if (ret) goto fail;
 p->endpoint_snapshot = kvzalloc(sizeof(*p->endpoint_snapshot), GFP_KERNEL);
 if (!p->endpoint_snapshot) { ret = -ENOMEM; goto fail; }
 p->endpoint_selected_rid = allowed->rid; p->endpoint_sizing = size_bars;
 c = (struct ep_context){p, ticket, allowed->rid, size_bars, 11};
 ret = retained_dma_blocked(p);
 dev_info(p->dev, "retained-endpoint-admission: blocked audit status %d\n", ret);
 if (ret) goto fail;
 ret = retained_ep_apertures(p);
 dev_info(p->dev, "retained-endpoint-admission: private aperture descriptor status %d\n", ret);
 if (ret) goto fail;
 io = (struct ep_io){.ctx = &c, .read = retained_ep_read, .write = retained_ep_write,
  .safe = retained_ep_safe, .probe_ready = retained_ep_probe_ready,
  .valid = retained_ep_valid, .now = retained_raw_clock,
  .deadline = p->retained_scan_deadline,
  .records = p->retained_records, .count = p->retained_record_count,
  .root_rid = (unsigned)p->bus_start << 8};
 raw_spin_lock_irqsave(&p->lock, flags);
 /* Continue original raw budget and deadline; only reopen this task aperture. */
 p->retained_scan_task = current;
 raw_spin_unlock_irqrestore(&p->lock, flags);
 ret = retained_ep_safe(&c, allowed->rid);
 if (!ret) ret = ep_capture(&io, allowed, p->endpoint_snapshot);
 if (!ret && size_bars) ret = p->profile->index==1 ? ep_size_bars_selected(&io,p->endpoint_snapshot,allowed) : ep_size_bars(&io,p->endpoint_snapshot);
 if (!ret && size_bars) ret = p->profile->index==1 ? tn_resource_plan(p->endpoint_snapshot,allowed->serial) : ep_plan(p->endpoint_snapshot);
 if (!ret && assign_memory) ret = p->profile->index==1 ? tn_assign_retained(&c,&io) : retained_assign_memory(&c,&io);
 if (!ret) ret = retained_ep_safe(&c, allowed->rid);
 raw_spin_lock_irqsave(&p->lock, flags);
 p->retained_scan_task = NULL; p->endpoint_sizing = false; p->endpoint_assignment_armed = false;
 raw_spin_unlock_irqrestore(&p->lock, flags);
 if (!ret && (p->retained_scan_exhausted || ktime_get_boottime_ns() >= io.deadline)) ret = -ETIMEDOUT;
 if (ret) goto fail;
 p->retained_phase = assign_memory ? 14 : 12;
 p->endpoint_snapshot->memory_assigned = assign_memory;
 *result = p->endpoint_snapshot;
 dev_info(p->dev, "retained-endpoint: RID %04x status 0 functions %u ancestors %u sizing %u host-memory-assigned %u; no decode/DMA/reset or outer acceptance implied\n",
  allowed->rid, p->endpoint_snapshot->count, p->endpoint_snapshot->ancestor_count, size_bars, assign_memory);
 goto out;
fail:
 raw_spin_lock_irqsave(&p->lock, flags);
 p->retained_scan_task = NULL; p->endpoint_sizing = false; p->endpoint_assignment_armed = false;
 raw_spin_unlock_irqrestore(&p->lock, flags);
 p->retained_failed = true;
 if (p->endpoint_owner) p->endpoint_owner->failed = true;
 /* Snapshot/partial writes stay owned; no kfree, config restoration or retries.
  * A subsequent controlled stock reboot is the recovery boundary. */
 dev_info(p->dev, "retained-endpoint: RID %04x status %d retained; no retry\n", allowed->rid, ret);
out:
 if (consumed) *phase = p->retained_phase;
 if (p->endpoint_snapshot) retained_ep_dump(p, ret);
 if (assign_memory && p->profile->index==0) retained_assignment_dump(p, ret);
 mutex_unlock(&p->lifecycle); return ret;
}
EXPORT_SYMBOL_GPL(apple_apciec_retained_endpoint_resources);
