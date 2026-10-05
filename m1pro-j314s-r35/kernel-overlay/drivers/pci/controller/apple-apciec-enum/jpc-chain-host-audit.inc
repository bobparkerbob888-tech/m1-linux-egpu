/* Dormant companion host API; include after retained-commit.inc.
 * Read-only cold phase8 scope, before PCI scan/native publication. */
int apple_apciec_jpc_chain_closed_audit(struct device*,unsigned,const void*,u64);
int apple_apciec_jpc_chain_closed_audit(struct device*dev,unsigned port,const void*ticket,u64 deadline)
{
 struct apple_apciec*p=dev_get_drvdata(dev);int ret;
 if(!p)return -ENODEV;
 mutex_lock(&p->lifecycle);
 ret=retained_commit_owner(p,port,ticket,8);
 if(!ret&&(!apciec_profile_j314s(p->profile)||!jpc_host_mode(p)||!p->j314s_raw_capability||
    deadline!=p->retained_identity_deadline||deadline!=p->j314s_provider_deadline||
    ktime_get_boottime_ns()>=deadline||!p->tunnel_ready||p->retained_scan_task||
    p->endpoint_snapshot||p->j314s_assignment||p->j314s_native||p->native))ret=-EPERM;
 if(!ret)ret=apple_cio_jpc_raw_owner_validate(p->supplier_context,ticket,port,deadline);
 if(!ret)ret=retained_identity_port_audit(p,true);
 if(!ret)ret=retained_root_rc_audit(p);
 if(!ret&&ktime_get_boottime_ns()>=deadline)ret=-ETIMEDOUT;
 mutex_unlock(&p->lifecycle);return ret;
}
EXPORT_SYMBOL_GPL(apple_apciec_jpc_chain_closed_audit);
