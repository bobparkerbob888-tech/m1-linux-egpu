/* One-way transition of the SAME provider owner. No reset or new deadline. */
extern int apple_cio_jpc_raw_owner_validate(void *,const void *,unsigned,u64);
int apple_apciec_jpc_begin_raw(struct device *,unsigned,const void *,u64);
int apple_apciec_jpc_begin_raw(struct device *dev,unsigned port,const void *ticket,u64 deadline)
{
 struct apple_apciec *p=dev_get_drvdata(dev);int ret;
 if(!p)return -ENODEV;
 mutex_lock(&p->lifecycle);
 ret=-EPERM;
 if(!apciec_profile_j314s(p->profile)||!jpc_host_mode(p)||port!=3||
    ticket!=p->retained_ticket||deadline!=p->j314s_provider_deadline||
    !p->j314s_provider_capability||p->j314s_raw_attempted||p->j314s_raw_capability||
    p->retained_failed||!p->retained||!p->retained_provider_prepare||
    p->retained_raw_identity||p->retained_availability_probe||p->retained_phase!=4||
    !p->power_ready||!p->port_prepared||p->prepared||!p->dart||!p->dart_populated||
    !p->retained_prefix_attempted||!p->retained_prefix_ready||
    p->retained_sample_attempted||p->retained_sample_regs||
    p->bridge||p->tunnel_ready||p->iommu_ready||p->msi_domain_ready||
    p->retained_scan_task||p->retained_record_count)goto out;
 p->j314s_raw_attempted=true;
 ret=apple_cio_jpc_raw_owner_validate(p->supplier_context,ticket,port,deadline);
 if(!ret)ret=availability_port_contained(p,1,0x00100001);
 if(!ret)ret=retained_dma_blocked(p);
 if(ret)goto fail;
 p->j314s_raw_capability=true;
 p->retained_provider_prepare=false;p->retained_raw_identity=true;
 p->retained_identity_deadline=deadline;p->prepared=true;p->retained_phase=6;
 ret=retained_identity_gate(p);
 if(!ret)goto out;
fail:p->retained_failed=true;
out:mutex_unlock(&p->lifecycle);return ret;
}
EXPORT_SYMBOL_GPL(apple_apciec_jpc_begin_raw);
