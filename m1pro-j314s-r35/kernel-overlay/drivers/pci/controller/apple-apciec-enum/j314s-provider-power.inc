int apple_apciec_j314s_begin_provider(struct device*,unsigned,const void*,u64);
int apple_apciec_j314s_populate_provider(struct device*,unsigned,const void*,u64,
 struct apple_dart_j314s_sample*);
/* Local draft, no caller. Requires the owner proof described in CONTRACT.txt.
 * Begin runs under ACIO->TB->host lifecycle. Populate runs after releasing
 * ACIO/TB, retaining their one-way owner and exact ticket throughout. */
extern int apple_cio_j314s_provider_owner_validate(void *owner,
 const void *ticket, unsigned int port, u64 deadline, bool owner_locks_held);

static int j314s_provider_gate(struct apple_apciec *p, const void *ticket,
 unsigned port, u64 deadline, bool owner_locks_held)
{
 if (!p || !ticket || !of_machine_is_compatible("apple,j314s") ||
     !apciec_profile_j314s(p->profile) || j314s_node_index(p->dev->of_node,3) != 0 ||
     !j314s_profile_valid() || !enum_only || !retain_prepare || retain_commit ||
     endpoint_mmio_probe || endpoint_pci_register || endpoint_memory_assign ||
     endpoint_resources || endpoint_pair || endpoint_native_driver ||
     !p->supplier || !p->supplier->get_retained || !p->supplier_context ||
     !port || port > 63 || port != p->root_down_port ||
     !deadline || ktime_get_boottime_ns() >= deadline ||
     !p->port || !p->ecam || p->rid_entries != 64 || p->bus_start || p->bus_end != 255 ||
     p->bridge || p->tunnel_ready || p->iommu_ready || p->msi_domain_ready)
  return -EPERM;
 return apple_cio_j314s_provider_owner_validate(p->supplier_context,ticket,
                                               port,deadline,owner_locks_held);
}

/* No legacy target entry is enabled. This is the sole new power entry. */
int apple_apciec_j314s_begin_provider(struct device *dev,
 unsigned port, const void *ticket, u64 deadline)
{
 struct apple_apciec *p = dev_get_drvdata(dev);
 int ret;
 if (!p) return -ENODEV;
 mutex_lock(&p->lifecycle);
 ret = j314s_provider_gate(p,ticket,port,deadline,true);
 if (ret) goto out;
 if (p->attempted || p->prepared || p->retained || p->dart || p->dart_populated ||
     p->retained_ticket || p->retained_dart_node || p->predart_attempted) {
  ret = -EPERM; goto out;
 }
 /* No reset/put path after this point; all failures retain ownership. */
 p->attempted = p->retained = p->j314s_provider_capability = true;
 p->j314s_provider_port = port;
 p->j314s_provider_deadline = deadline;
 p->retained_ticket = ticket;
 p->retained_provider_prepare = true;
 p->retained_phase = 1;
 ret = p->supplier->get_retained(p->supplier_context);
 if (ret) goto fail;
 p->power_ready = true;
 ret = j314s_provider_gate(p,ticket,port,deadline,true);
 if (ret) goto fail;
 ret = apple_apciec_predart_apply(p);
 if (ret) goto fail;
 ret = j314s_provider_gate(p,ticket,port,deadline,true);
 if (ret) goto fail;
 p->port_prepared = true;
 ret = apple_apciec_prepare_port(p);
 if (!ret) ret = apple_apciec_retained_isolated(p);
 if (ret) goto fail;
 p->retained_phase = 2;
 ret = j314s_provider_gate(p,ticket,port,deadline,true);
 if (ret) goto fail;
 ret = availability_prepare_provider_prefix(p);
 if (ret) goto fail;
 ret = j314s_provider_gate(p,ticket,port,deadline,true);
 if (!ret) goto out;
fail:
 p->retained_failed = true;
out:
 mutex_unlock(&p->lifecycle);
 return ret;
}

/* Called outside ACIO/TB locks to avoid provider probe/device-lock inversion.
 * Validate retained owner proof without acquiring ACIO/TB under lifecycle. */
int apple_apciec_j314s_populate_provider(struct device *dev,
 unsigned port, const void *ticket, u64 deadline,
 struct apple_dart_j314s_sample *sample)
{
 struct apple_apciec *p = dev_get_drvdata(dev);
 int ret;
 if (!sample) return -EINVAL;
 memset(sample,0,sizeof(*sample));
 if (!p) return -ENODEV;
 mutex_lock(&p->lifecycle);
 ret = j314s_provider_gate(p,ticket,port,deadline,false);
 if (ret) goto out;
 if (!p->j314s_provider_capability || p->j314s_provider_deadline != deadline ||
     p->j314s_provider_port != port || p->retained_ticket != ticket ||
     !p->retained || !p->attempted || !p->power_ready || !p->port_prepared ||
     p->retained_failed || p->retained_phase != 2 || !p->retained_provider_prepare ||
     p->retained_availability_probe || p->retained_raw_identity || p->prepared ||
     !p->retained_prefix_attempted || !p->retained_prefix_ready ||
     p->retained_sample_attempted || p->retained_sample_regs || p->dart ||
     p->dart_populated) {ret=-EPERM;goto out;}
 ret = availability_port_contained(p,1,0x00100001);
 if (ret) goto fail;
 p->retained_phase = 3;
 ret = apple_apciec_create_retained_dart(p);
 if (ret) goto fail;
 ret = availability_port_contained(p,1,0x00100001);
 if (ret) goto fail;
 ret = j314s_provider_gate(p,ticket,port,deadline,false);
 if (ret) goto fail;
 ret = apple_apciec_dart_blocked(p);
 if (ret) goto fail;
 ret = apple_dart_j314s_sample_get(&p->dart->dev,dev,sample);
 if (ret) goto fail;
 ret = j314s_provider_gate(p,ticket,port,deadline,false);
 if (ret) goto fail;
 p->retained_phase = 4;
 /* Deliberately not prepared/phase6: no tunnel/config/native promotion. */
 goto out;
fail:
 p->retained_failed = true;
 memset(sample,0,sizeof(*sample));
out:
 mutex_unlock(&p->lifecycle);
 return ret;
}

EXPORT_SYMBOL_GPL(apple_apciec_j314s_begin_provider);
EXPORT_SYMBOL_GPL(apple_apciec_j314s_populate_provider);
