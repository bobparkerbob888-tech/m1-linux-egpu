#include "jpc-boot-peer.h"
extern int apple_cio_jpc_inventory_state(unsigned,u32*,int*);
/* Exact target mapping admission. Power/PCI configuration remain separate. */
#include "j314s-host-profile.h"
extern int apple_cio_j314s_inventory_state(unsigned controller,u32 *flags,int *status);
static atomic_t j314s_host_probe_consumed[3]={ATOMIC_INIT(0),ATOMIC_INIT(0),ATOMIC_INIT(0)};
static int apciec_j314s_probe_admit(struct device_node *node)
{
 unsigned flags=0;int status=-EINPROGRESS,index,ret;
 index=j314s_node_index(node,3);
 if(index<0)return -EPERM;
 if(atomic_cmpxchg(&j314s_host_probe_consumed[index],0,1))return -EPERM;
 /* First measured target controller only. No J293 topology can be inherited. */
 if((index&&index!=jpc_boot_peer_controller())||!enum_only||!retain_prepare||retain_commit||endpoint_mmio_probe||
    endpoint_pci_register||endpoint_memory_assign||endpoint_resources||
    endpoint_pair||endpoint_native_driver||!j314s_profile_valid()||
    !of_device_is_compatible(node,"research-only,apple-t6000-apciec-disabled"))return -EPERM;
 ret=index?apple_cio_jpc_inventory_state(index,&flags,&status):apple_cio_j314s_inventory_state(index,&flags,&status);
 if(ret||flags!=0x1ff||status)return -EPERM;
 return 0;
}
