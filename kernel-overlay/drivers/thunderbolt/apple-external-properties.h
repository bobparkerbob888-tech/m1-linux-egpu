#include "endpoint-aperture.h"
#include "apple-native-properties.h"
/* Deep immutable snapshots of the exact owned nodes; only two status changes
 * and the owned DART latch marker are permitted. No hash collision assumption. */
struct external_property {struct external_property*next;char*name;void*value;int len;};
struct external_node {struct device_node*np;struct external_property*properties;unsigned count;bool populated,bus;};
static bool external_property_mutable(unsigned n,const char*name)
{return (n>=7&&!strcmp(name,"status"))||(n==8&&!strcmp(name,"research,retained-probe-once"));}
static int external_capture_nodes(struct external_node*nodes,unsigned controller)
{
 unsigned n,total=0;
 if(controller>=BOB_CONTROLLERS)return -EPERM;
 for(n=0;n<BOB_OWNED_NODES;n++){
  struct property*p;struct external_node*e=&nodes[n];
  e->np=of_find_node_by_path(bob_controller_paths[controller][n]);if(!e->np)return -ENOENT;
  /* Runtime overlay must establish the immediate bus mapping policy before
   * this snapshot; retain its exact empty value through all later phases. */
  if(n==7){
   static const unsigned char row[]={0,0,1,0x40,0,0,0,1,0,0,0,1};
   static const unsigned char rc[]={0x0,0x0,0x7,0x18,0x0,0x7,0xc0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x8,0xbc,0x0,0x0,0x0,0x1,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x78,0x0,0x0,0x70,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x8,0x14,0xff,0xff,0xff,0xff,0x0,0x0,0xf0,0x60};
   p=of_find_property(e->np,"nonposted-mmio",NULL);if(!p||p->length)return -EINVAL;
   if(!controller && external_endpoint_resources && apple_endpoint_apertures(e->np))return -EINVAL;
   p=of_find_property(e->np,"apple,apcie-config-tunables",NULL);
   if(!p||p->length!=sizeof(row)||!p->value||memcmp(p->value,row,sizeof(row)))return -EINVAL;
   p=of_find_property(e->np,"apple,apcie-rc-tunables",NULL);
   if(!p||p->length!=sizeof(rc)||!p->value||memcmp(p->value,rc,sizeof(rc)))return -EINVAL;
  }
  e->populated=of_node_check_flag(e->np,OF_POPULATED);
  e->bus=of_node_check_flag(e->np,OF_POPULATED_BUS);
  for_each_property_of_node(e->np,p){
   struct external_property*q;
   if(n==7 && external_native_index(p->name)>=0)return -EPERM;
   if(external_property_mutable(n,p->name))continue;
   if(e->count>=128||p->length<0||p->length>65536||total>1048576U-(unsigned)p->length)return -E2BIG;
   q=kzalloc(sizeof(*q),GFP_KERNEL);if(!q)return -ENOMEM;
   q->name=kstrdup(p->name,GFP_KERNEL);q->len=p->length;
   if(p->length)q->value=kmemdup(p->value,p->length,GFP_KERNEL);
   if(!q->name||(q->len&&!q->value))return -ENOMEM;
   q->next=e->properties;e->properties=q;e->count++;total+=p->length;
  }
 }
 return 0;
}
static bool external_nodes_unchanged_profile(struct external_node*nodes,unsigned controller,unsigned phase,bool native,bool pair)
{
 unsigned n; u32 aic_phandle = 0;
 if(controller>=BOB_CONTROLLERS || phase>2 || (pair && controller!=1))return false;
 if (native) {
  struct device_node *aic;
  if (phase != 2 || !nodes[8].np || !nodes[8].np->phandle) return false;
  aic = of_find_node_by_path("/soc/interrupt-controller@23b100000");
  if (aic && of_device_is_compatible(aic, "apple,t8103-aic")) aic_phandle = aic->phandle;
  of_node_put(aic);
  if (!aic_phandle) return false;
 }
 for(n=0;n<BOB_OWNED_NODES;n++){
  struct external_node*e=&nodes[n];struct device_node*np=of_find_node_by_path(bob_controller_paths[controller][n]);
  struct external_property*q;struct property*p;unsigned count=0;bool same=np==e->np;
  of_node_put(np);if(!same)return false;
  if(n<7&&(of_node_check_flag(e->np,OF_POPULATED)!=e->populated||
    of_node_check_flag(e->np,OF_POPULATED_BUS)!=e->bus))return false;
  unsigned native_seen = 0;
  for_each_property_of_node(e->np,p) {
   int bit;
   if (external_property_mutable(n,p->name)) continue;
   bit = native && n == 7 ? external_native_property_profile(controller,pair,p->name, p->value,
                          p->length, nodes[8].np->phandle, aic_phandle) : 0;
   if (bit < 0 || (bit && (native_seen & bit))) return false;
   if (bit) native_seen |= bit;
   else count++;
  }
  if(count!=e->count || (native && n==7 && native_seen!=(pair?0x7f:0x3f)))return false;
  for(q=e->properties;q;q=q->next){
   int len;p=of_find_property(e->np,q->name,&len);
   if(!p||len!=q->len||(len&&memcmp(p->value,q->value,len)))return false;
  }
  if(n>=7){const char*status;bool on=n==7?phase>=1:phase>=2;
   if(of_property_read_string(e->np,"status",&status)||strcmp(status,on?"okay":"disabled"))return false;
  }
  if(n==8){int len;struct property*marker=of_find_property(e->np,"research,retained-probe-once",&len);
   if((marker!=NULL)!=(phase>=2)||(marker&&len))return false;
  }
 }
 return true;
}
static inline bool external_nodes_unchanged(struct external_node *nodes,unsigned controller,unsigned phase,bool native)
{return external_nodes_unchanged_profile(nodes,controller,phase,native,false);}
/* The peer may be active only under its exact retained one-shot owner.
 * Never follow/probe a peer controller and never admit a third controller. */
static bool external_other_controllers_owned(struct device_node*owned)
{
 struct device_node*np;
 for_each_compatible_node(np,NULL,"apple,t8103-usb4-acio"){
  if(np!=owned&&(of_device_is_available(np)||of_node_check_flag(np,OF_POPULATED)||
     of_node_check_flag(np,OF_POPULATED_BUS))){
   int peer=bob_controller_index(np);
   if(peer<0 || !apple_j293_peer_retained(peer)) {of_node_put(np);return false;}
  }
 }
 return true;
}
