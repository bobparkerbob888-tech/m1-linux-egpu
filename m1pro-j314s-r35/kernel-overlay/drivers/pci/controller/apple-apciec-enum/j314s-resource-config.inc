/* Dedicated phase11 branch before generic/legacy target config dispatch.
 * Called under p->lock; never expands J293 or target phase9 permissions. */
static int j314s_resource_config_locked(struct pci_bus *bus,unsigned devfn,
 int where,int size,u32 *value,bool write)
{
 struct apple_apciec*p=bus->sysdata;
 struct j314s_resource_owner*o=p->j314s_resource;
 unsigned rid=(bus->number<<8)|devfn,j,bar;
 u64 offset=PCIE_ECAM_OFFSET(bus->number,devfn,where);
 lockdep_assert_held(&p->lock);
 if(!jmx_resource_scope(p)||
    !p->j314s_raw_capability||!o||!o->attempted||!o->active||o->failed||
    o->task!=current||o->ticket!=p->retained_ticket||o->deadline!=p->retained_scan_deadline||
    p->retained_phase!=11||p->retained_scan_task!=current||p->retained_failed||
    !p->retained||!p->power_ready||!p->tunnel_ready||!p->dart||!p->endpoint_snapshot||
    p->retained_scan_exhausted||p->retained_scan_ops>=retained_scan_limit(p)||
    !p->retained_record_count||p->retained_record_count>EP_MAX_RECORDS||
    ktime_get_boottime_ns()>=o->deadline||o->deadline>p->retained_identity_deadline||
    size!=4||where<0||where>0xffc||(where&3)||rid>65535||
    p->endpoint_selected_rid!=o->selected.rid||offset+4>p->ecam_size||
    !apple_apciec_map_bus(bus,devfn,where))return PCIBIOS_DEVICE_NOT_FOUND;
 for(j=0;j<p->retained_record_count;j++)if(p->retained_records[j].rid==rid)break;
 if(j==p->retained_record_count)return PCIBIOS_DEVICE_NOT_FOUND;
 if(write&&o->rebar_armed){
  if(!p->j314s_mixed_policy||!o->rebar_attempted||o->rebar_written||
     !p->endpoint_sizing||rid!=o->selected.rid||o->selected.id!=0x2c1810de||
     where!=o->rebar_offset||*value!=o->rebar_after||
     o->rebar_after!=((o->rebar_before&~0x1f00U)|0x800))return PCIBIOS_SET_FAILED;
  o->rebar_armed=false;o->rebar_written=true;
  p->retained_scan_ops++;
  return pci_generic_config_write(bus,devfn,where,size,*value);
 }
 if(write) {
  if(!p->endpoint_sizing||rid!=o->selected.rid||where<0x10||where>0x24||
     !p->endpoint_snapshot->captured)return PCIBIOS_SET_FAILED;
  bar=(where-0x10)/4;
  /* 64bit high DWORD is standard memory state, not a preserved I/O BAR.
   * Only a sizing all-ones or this boot's exact saved value is admissible. */
  if((p->endpoint_snapshot->bars[bar].saved[0]&1)&&
     !p->endpoint_snapshot->bars[bar].upper)
   return PCIBIOS_SET_FAILED;
  if(*value!=~0U&&*value!=p->endpoint_snapshot->bars[bar].saved[0])
   return PCIBIOS_SET_FAILED;
 }
 p->retained_scan_ops++;
 return write?pci_generic_config_write(bus,devfn,where,size,*value):
              pci_generic_config_read(bus,devfn,where,size,value);
}
