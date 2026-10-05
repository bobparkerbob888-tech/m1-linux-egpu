/* SPDX-License-Identifier: GPL-2.0 */
/* Exact native firmware additions. Unknown properties remain immutable. */
static int external_native_index(const char *name)
{
 static const char *const names[] = { "iommu-map", "iommu-map-mask",
  "msi-ranges", "msi-controller", "dma-noncoherent",
  "research,native-endpoint-memory-only", "research,native-endpoint-pair" };
 unsigned i;
 for (i = 0; i < 7; i++) if (!strcmp(name, names[i])) return i;
 return -1;
}
static int external_native_property_profile(unsigned controller,bool pair,
                                    const char *name, const void *value,
                                    int len, u32 dart, u32 aic)
{
 __be32 expected[8]; unsigned count;
 int index = external_native_index(name);
 if (controller > 1 || (pair && controller!=1)) return -EPERM;
 if (index < 0) return 0;
 if (index == 6 && !pair) return -EPERM;
 if (!dart || !aic || len < 0) return -EPERM;
 if (index == 0) {
  expected[0] = cpu_to_be32(controller ? 0x600 : 0x300); expected[1] = cpu_to_be32(dart);
  expected[2] = cpu_to_be32(1); expected[3] = cpu_to_be32(1); count = 4;
  if(pair){expected[4]=cpu_to_be32(0x300);expected[5]=cpu_to_be32(dart);
   expected[6]=cpu_to_be32(2);expected[7]=cpu_to_be32(1);count=8;}
 } else if (index == 1) {
  expected[0] = cpu_to_be32(0xffff); count = 1;
 } else if (index == 2) {
  expected[0] = cpu_to_be32(aic); expected[1] = 0;
  expected[2] = cpu_to_be32(controller ? 818 : 738); expected[3] = cpu_to_be32(IRQ_TYPE_EDGE_RISING);
  expected[4] = cpu_to_be32(32); count = 5;
 } else count = 0;
 if ((unsigned)len != count * sizeof(__be32) ||
     (len && (!value || memcmp(value, expected, len)))) return -EPERM;
 return 1 << index;
}
static inline int external_native_property_controller(unsigned controller,
                                    const char *name,const void *value,int len,u32 dart,u32 aic)
{return external_native_property_profile(controller,false,name,value,len,dart,aic);}
/* Preserve the original controller0-only pure helper for its existing tests. */
static inline int external_native_property(const char *name, const void *value,
                                    int len, u32 dart, u32 aic)
{return external_native_property_controller(0,name,value,len,dart,aic);}
