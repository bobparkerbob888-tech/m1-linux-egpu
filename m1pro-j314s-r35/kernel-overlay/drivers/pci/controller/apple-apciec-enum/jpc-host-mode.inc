#include "jpc-boot-peer.h"
static bool jpc_host_mode(struct apple_apciec*p)
{
 unsigned selected=jpc_boot_peer_controller();
 return p&&p->profile&&apciec_profile_j314s(p->profile)&&selected>=1&&selected<=2&&
  p->profile->index==selected&&j314s_node_index(p->dev->of_node,3)==selected;
}
extern int apple_cio_jpc_raw_owner_validate(void*,const void*,unsigned,u64);
extern int jpc_apple_cio_j314s_chain_owner_validate(void*,const void*,unsigned,u64,unsigned);
