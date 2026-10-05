/* Called with host spinlock held, before legacy config admission. */
static int j314s_assignment_config_locked(struct pci_bus*bus,unsigned devfn,
 int where,int size,u32*value,bool write)
{
 struct apple_apciec*p=bus->sysdata;struct j314s_assignment_owner*o=p->j314s_assignment;
 unsigned rid=(bus->number<<8)|devfn,j;u64 offset=PCIE_ECAM_OFFSET(bus->number,devfn,where);
 lockdep_assert_held(&p->lock);
 if(!apciec_profile_j314s(p->profile)||p->profile->index||!p->j314s_raw_capability||
    !o||!o->attempted||!o->active||o->failed||o->complete||o->task!=current||
    o->ticket!=p->retained_ticket||o->deadline!=p->retained_scan_deadline||
    p->retained_phase!=13||p->retained_scan_task!=current||p->retained_failed||
    !p->retained||!p->power_ready||!p->tunnel_ready||!p->dart||!p->endpoint_snapshot||
    !p->endpoint_snapshot->planned||p->endpoint_snapshot->memory_assigned||
    p->retained_scan_exhausted||p->retained_scan_ops>=8192||
    !p->retained_record_count||p->retained_record_count>EP_MAX_RECORDS||
    ktime_get_boottime_ns()>=o->deadline||o->deadline>p->retained_identity_deadline||
    size!=4||where<0||where>0xffc||(where&3)||rid>65535||
    p->endpoint_selected_rid!=o->plan.selected.rid||offset+4>p->ecam_size||
    !apple_apciec_map_bus(bus,devfn,where))return PCIBIOS_DEVICE_NOT_FOUND;
 for(j=0;j<p->retained_record_count;j++)if(p->retained_records[j].rid==rid)break;
 if(j==p->retained_record_count)return PCIBIOS_DEVICE_NOT_FOUND;
 if(write){const struct ja_step*s;const struct ja_register*r;
  if(!o->ready||!o->armed||!o->plan.built||o->execution>=o->plan.step_count)return PCIBIOS_SET_FAILED;
  s=&o->plan.steps[o->execution];if(s->reg>=o->plan.count)return PCIBIOS_SET_FAILED;
  r=&o->plan.regs[s->reg];
  if(!r->writable||r->rid!=rid||r->offset!=where||s->value!=*value)return PCIBIOS_SET_FAILED;
  /* Consume before the hardware write; even a failing write is not retryable. */
  o->armed=false;o->execution++;
 }
 p->retained_scan_ops++;
 return write?pci_generic_config_write(bus,devfn,where,size,*value):
              pci_generic_config_read(bus,devfn,where,size,value);
}
