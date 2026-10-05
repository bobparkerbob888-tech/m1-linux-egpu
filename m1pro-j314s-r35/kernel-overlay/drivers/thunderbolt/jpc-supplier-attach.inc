/* Called only under retained ACIO -> TB owner locks after mapping-only host
 * activation. Software attachment plus exact PMGR snapshot reads: no PM resume or writes,
 * no tunnel operation.
 * One attempt per boot, including failures. Not exported or called yet. */
static atomic_t jpc_supplier_attach_attempt[3] = {ATOMIC_INIT(0),ATOMIC_INIT(0),ATOMIC_INIT(0)};
static int __maybe_unused jpc_supplier_attach(struct apple_nhi *anhi)
{
 static const char *const names[] = { "apciec-core", "apciec-port" };
 struct apple_cio *c;
 struct device_node *np;
 struct platform_device *host;
 const struct tb_nhi_ops *old_ops;
 unsigned i;
 int ret;
 if(!anhi || !anhi->tb || !(c=anhi->acio))return -EINVAL;
 lockdep_assert_held(&c->lock);
 lockdep_assert_held(&anhi->tb->lock);
 if(!of_machine_is_compatible("apple,j314s") ||
    j314s_node_index(anhi->np,1)!=jpc_boot_peer_controller() || !j314s_profile_valid() ||
    READ_ONCE(j314s_owned_cio[jpc_boot_peer_controller()])!=c || !j314s_arm_committed[jpc_boot_peer_controller()] ||
    READ_ONCE(c->root_stopping) || !READ_ONCE(c->root_dma_retained) ||
    READ_ONCE(c->root_cable_nhi)!=anhi || READ_ONCE(c->root_probe_status) ||
    anhi->enum_host || anhi->enum_pd[0] || anhi->enum_pd[1] ||
    anhi->enum_bound || anhi->enum_retained_prepare ||
    atomic_cmpxchg(&jpc_supplier_attach_attempt[jpc_boot_peer_controller()],0,1))return -EPERM;
 np=of_parse_phandle(anhi->np,"research,apciec-host",0);
 if(!np)return -EINVAL;
 if(j314s_node_index(np,3)!=jpc_boot_peer_controller() || !of_device_is_available(np) ||
    !of_device_is_compatible(np,"research-only,apple-t6000-apciec-disabled")) {
  of_node_put(np);return -EPERM;
 }
 host=of_find_device_by_node(np);of_node_put(np);
 if(!host)return -ENODEV;
 anhi->enum_host=&host->dev;
 if(!host->dev.driver || !dev_get_drvdata(anhi->enum_host)) {
  ret=-ENODEV;goto fail;
 }
 for(i=0;i<ARRAY_SIZE(names);i++) {
  struct device *pd=dev_pm_domain_attach_by_name(anhi->enum_host,names[i]);
  u32 raw;
  if(IS_ERR_OR_NULL(pd)){ret=pd?PTR_ERR(pd):-ENODEV;goto fail;}
  anhi->enum_pd[i]=pd;
  /* Read-only exact provider proof before any later PM resume admission. */
  ret=apple_pmgr_retained_snapshot(pd,i,&raw);if(ret)goto fail;
 }
 old_ops=anhi->nhi.ops;
 anhi->enum_stopping=true;
 anhi->enum_ops=*old_ops;
 anhi->enum_ops.pcie_tunnel_prepare=apple_nhi_enum_prepare_tunnel;
 anhi->enum_ops.pcie_tunnel_enable=apple_nhi_enum_enable;
 anhi->enum_ops.pcie_tunnel_disable=apple_nhi_enum_disable;
 anhi->nhi.ops=&anhi->enum_ops;
 ret=apple_nhi_enum_bind(anhi);
 if(!ret)return 0;
 anhi->nhi.ops=old_ops;
fail:
 /* No supplier get/power operation occurred; ACIO/TB DMA owner stays held. */
 apple_nhi_enum_release(anhi);
 return ret;
}
