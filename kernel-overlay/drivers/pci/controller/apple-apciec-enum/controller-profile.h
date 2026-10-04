/* SPDX-License-Identifier: GPL-2.0 */
#ifndef APPLE_APCIEC_CONTROLLER_PROFILE_H
#define APPLE_APCIEC_CONTROLLER_PROFILE_H
/* Two exact J293 controllers. Index1 is identification-only in this stage. */
struct apciec_controller_profile {
 unsigned index;
 const char *path, *dart_path;
 u64 ecam, port, dart, tunable_bases[3];
};
static const struct apciec_controller_profile apciec_profiles[] = {
 {0,"/soc/apciec@3b0000000","/soc/apciec@3b0000000/iommu@3a1008000",
  0x3b0000000ULL,0x3a1000000ULL,0x3a1008000ULL,
  {0x3a0000000ULL,0x3a0200000ULL,0x3a0004000ULL}},
 {1,"/soc/apciec@530000000","/soc/apciec@530000000/iommu@521008000",
  0x530000000ULL,0x521000000ULL,0x521008000ULL,
  {0x520000000ULL,0x520200000ULL,0x520004000ULL}},
};
/* device_node.full_name is the leaf name in the live unflattened tree.
 * Compare the node returned by an absolute lookup, never that display name. */
static const struct apciec_controller_profile *apciec_profile_node(const struct device_node *node)
{
 unsigned j;
 if (!node) return NULL;
 for (j=0;j<ARRAY_SIZE(apciec_profiles);j++) {
  struct device_node *exact=of_find_node_by_path(apciec_profiles[j].path);
  bool match=exact && exact==node;
  of_node_put(exact);
  if (match) return &apciec_profiles[j];
 }
 return NULL;
}
/* Exact transit bridge numbers; the first local GPU branch0200 stays closed. */
static bool apciec_transit_config_allowed(unsigned rid,unsigned off,unsigned width,
                                         bool write,u32 value)
{
 static const unsigned rids[]={0,0x100,0x200,0x208,0x400,0x500,0x600};
 static const u32 buses[]={0x00060100,0x00060201,0,0x00060402,0x00060504,0x00060605,0};
 unsigned j;
 if(width!=4||off>0xffc||(off&3))return false;
 for(j=0;j<ARRAY_SIZE(rids)&&rid!=rids[j];j++);
 if(j==ARRAY_SIZE(rids))return false;
 if(write)return buses[j]&&off==0x18&&(value&0x00ffffff)==buses[j];
 if(off>=0x40)return true; /* Read-only standard linked capabilities. */
 if(off==0||off==4||off==8||off==12||off==0x34||off==0x3c)return true;
 return rid==0x600?off==0x2c:off==0x18;
}
#endif
