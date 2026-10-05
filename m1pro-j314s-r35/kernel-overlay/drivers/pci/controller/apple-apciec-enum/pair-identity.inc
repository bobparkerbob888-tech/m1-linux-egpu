#include "pair-identity-core.h"
int apple_apciec_retained_identify_pair(struct device *dev,unsigned port,
 const void *ticket,u64 deadline,unsigned *phase)
{
 struct apple_apciec *p=dev_get_drvdata(dev);struct retained_raw_io io={0};
 struct retained_raw_context context={p,ticket};unsigned long flags;int ret;
 if(!p||!phase)return -EINVAL;
 mutex_lock(&p->lifecycle);
 ret=retained_commit_owner(p,port,ticket,8);if(ret)goto out;
 if(!pn_mode(p)||!p->retained_raw_identity||
    !p->tunnel_ready||deadline!=p->retained_identity_deadline||
    p->retained_record_count||p->retained_scan_task||
    ktime_get_boottime_ns()>=deadline){ret=-EPERM;goto out;}
 p->retained_phase=9;
 ret=retained_dma_blocked(p);if(ret)goto fail;
 io=(struct retained_raw_io){.read=retained_raw_config_read,.write=retained_raw_config_write,
  .valid=retained_raw_valid,.now=retained_raw_clock,.record=retained_raw_record_device,
  .sleep=retained_raw_sleep,.audit=retained_raw_host_readiness_audit,
  .link_record=retained_raw_record_link,.ctx=&context,.first=0,.last=255,
  .strict_identity=true,.deadline=min(deadline,ktime_get_boottime_ns()+10ULL*NSEC_PER_SEC)};
 raw_spin_lock_irqsave(&p->lock,flags);
 p->retained_scan_task=current;p->retained_scan_ops=0;
 p->retained_scan_exhausted=false;p->retained_scan_deadline=io.deadline;
 raw_spin_unlock_irqrestore(&p->lock,flags);
 ret=pn_identify(&io);
 raw_spin_lock_irqsave(&p->lock,flags);p->retained_scan_task=NULL;raw_spin_unlock_irqrestore(&p->lock,flags);
 if(!ret&&(p->retained_scan_exhausted||p->retained_failed||io.devices!=8||io.nvidia!=2||
           (endpoint_resources&&p->retained_record_count!=8)))ret=-EPERM;
 {int audit=retained_identity_gate(p);
  if(!audit)audit=retained_dma_blocked(p);
  if(!audit)audit=retained_identity_port_audit(p,true);
  if(!audit)audit=retained_root_rc_audit(p);
  dev_info(p->dev,"pair-target-identity: status%d audit%d devices%u GPU%u ops%u; excluded0301/0601 untouched, no BAR/DMA/driver\n",
           ret,audit,io.devices,io.nvidia,p->retained_scan_ops);
  if(!ret)ret=audit;}
 if(ret)goto fail;
 p->retained_phase=10;goto out;
fail:
 p->retained_failed=true;
out:
 *phase=p->retained_phase;mutex_unlock(&p->lifecycle);return ret;
}
EXPORT_SYMBOL_GPL(apple_apciec_retained_identify_pair);
