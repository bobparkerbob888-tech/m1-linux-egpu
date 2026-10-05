/* Same allocation-free validator compiled by kernel and host regression tests. */
#ifdef __KERNEL__
#include <linux/libfdt.h>
#include <linux/string.h>
#else
#include <libfdt.h>
#include <string.h>
#include <stddef.h>

#endif
#define BOB_LIMIT (1024U * 1024U)
#define BOB_COUNT(a) (sizeof(a)/sizeof((a)[0]))
#include "bob_j293_data.h"
static int bob_member(const char *s, const char a[][BOB_PATH_WIDTH], unsigned int n)
{
 unsigned int i; for(i=0;i<n;i++) if(!strcmp(s,a[i])) return 1; return 0;
}
/* libfdt path lookup deliberately ignores unit addresses when omitted.
 * Preservation comparisons must distinguish "endpoint" from "endpoint@1". */
static int bob_exact_path(const void *f, const char *path)
{
 int parent=0, child, len; const char *p=path, *end, *name;
 if (*p++ != '/') return -FDT_ERR_BADPATH;
 while (*p) {
  end=strchr(p,'/'); if(!end) end=p+strlen(p);
  for(child=fdt_first_subnode(f,parent);child>=0;child=fdt_next_subnode(f,child)) {
   name=fdt_get_name(f,child,&len);
   if(name && len==end-p && !memcmp(name,p,len)) break;
  }
  if(child<0) return child;
  parent=child; p=(*end)?end+1:end;
 }
 return parent;
}
/* Validate every variable-length region before trusting traversal helpers. */
static int bob_bounds(const void *f, size_t available)
{
 unsigned int n, os, ss, ot, st, r; int off, depth=0, len, p, next, roots=0; unsigned int tag;
 const struct fdt_property *prop; const char *name;
 if(available < sizeof(struct fdt_header) || fdt_check_header(f)) return -1;
 n=fdt_totalsize(f); if(n>available || n>BOB_LIMIT || n<sizeof(struct fdt_header)) return -2;
 os=fdt_off_dt_struct(f); ss=fdt_size_dt_struct(f); ot=fdt_off_dt_strings(f); st=fdt_size_dt_strings(f); r=fdt_off_mem_rsvmap(f);
 if(fdt_version(f)!=17 || os>n || ss>n-os || ot>n || st>n-ot || (os&3) || (r&7) || r<sizeof(struct fdt_header)) return -3;
 if(os<sizeof(struct fdt_header) || ot<sizeof(struct fdt_header) || (os<ot+st && ot<os+ss)) return -4;
 for(;;r+=16) { const unsigned char *q=(const unsigned char *)f+r; unsigned int i; int zero=1;
  if(r>n || n-r<16 || (r<os+ss && os<r+16) || (r<ot+st && ot<r+16)) return -5;
  for(i=0;i<16;i++) if(q[i]) zero=0;
  if(zero) break;
 }
 /* Require a single balanced root followed by a real FDT_END, not merely
  * traversal stopping at the first closing root or a malformed token. */
 off=0;
 for (;;) {
  if ((unsigned int)off>=ss) return -14;
  tag=fdt_next_tag(f,off,&next); if(next<0 || next<=off) return -14;
  if(tag==FDT_BEGIN_NODE) { if(depth==0 && roots++) return -14; depth++; }
  else if(tag==FDT_END_NODE) { if(--depth<0) return -14; }
  else if(tag==FDT_PROP) { if(depth<=0) return -14; }
  else if(tag==FDT_END) { if(depth || roots!=1) return -14; break; }
  else if(tag!=FDT_NOP) return -14;
  off=next;
 }
 off=-1; depth=0;
 while((off=fdt_next_node(f,off,&depth))>=0 && depth>=0) {
  name=fdt_get_name(f,off,&len); if(!name || len<0) return -6;
  fdt_for_each_property_offset(p,f,off) { prop=fdt_get_property_by_offset(f,p,&len); if(!prop || len<0) return -7;
   if(fdt32_to_cpu(prop->nameoff)>=st) return -8;
   name=fdt_string(f,fdt32_to_cpu(prop->nameoff));
   if(!name || !memchr(name,0,st-fdt32_to_cpu(prop->nameoff))) return -8;
  }
  if(p!=-FDT_ERR_NOTFOUND) return -9;
 }
 if(off<0 && off!=-FDT_ERR_NOTFOUND) return -10;
 return 0;
}
static int bob_guards_check(const void *f)
{
 unsigned int i; int off,n; const void *v;
 for(i=0;i<BOB_COUNT(bob_guards);i++) { const struct bob_guard *g=&bob_guards[i];
  off=bob_exact_path(f,g->path); if(off<0) return -11;
  v=fdt_getprop(f,off,g->name,&n);
  if(g->len<0) { if(v || n!=-FDT_ERR_NOTFOUND) return -12; }
  else if(!v || n!=g->len || memcmp(v,g->value,n)) return -13;
 }
 return 0;
}
static int bob_preserved(const void *old, const void *new)
{
 int off=-1,depth=0,dst,p,len,n,rc,new_count=0,added=0; char path[512];
 const struct fdt_property *prop; const void *v; const char *name;
 int nr=fdt_num_mem_rsv(old), nn=fdt_num_mem_rsv(new), i; uint64_t a,b,c,d;
 if(nr<0 || nr!=nn || fdt_boot_cpuid_phys(old)!=fdt_boot_cpuid_phys(new)) return -20;
 for(i=0;i<nr;i++) if(fdt_get_mem_rsv(old,i,&a,&b) || fdt_get_mem_rsv(new,i,&c,&d) || a!=c || b!=d) return -21;
 while((off=fdt_next_node(old,off,&depth))>=0 && depth>=0) {
  if(fdt_get_path(old,off,path,sizeof(path))) return -22;
  dst=bob_exact_path(new,path); if(dst<0) return -23;
  fdt_for_each_property_offset(p,old,off) { prop=fdt_get_property_by_offset(old,p,&len); name=fdt_string(old,fdt32_to_cpu(prop->nameoff));
   v=fdt_getprop(new,dst,name,&n); if(!v || n!=len || memcmp(v,prop->data,len)) return -24;
  }
  fdt_for_each_property_offset(p,new,dst) { prop=fdt_get_property_by_offset(new,p,&len); name=fdt_string(new,fdt32_to_cpu(prop->nameoff));
   v=fdt_getprop(old,off,name,&n); if(v) continue;
   if(n!=-FDT_ERR_NOTFOUND || strcmp(name,"phandle") || len!=4 || !bob_member(path,bob_phandle_nodes,BOB_COUNT(bob_phandle_nodes))) return -25;
   { unsigned int ph=fdt32_to_cpu(*(const fdt32_t *)prop->data); if(!ph || ph==0xffffffffU || fdt_node_offset_by_phandle(new,ph)!=dst) return -26; }
   added++;
  }
 }
 off=-1; depth=0;
 while((off=fdt_next_node(new,off,&depth))>=0 && depth>=0) {
  if(fdt_get_path(new,off,path,sizeof(path))) return -27;
  if(bob_exact_path(old,path)>=0) continue;
  if(!bob_member(path,bob_new_nodes,BOB_COUNT(bob_new_nodes))) return -28;
  new_count++;
  v=fdt_getprop(new,off,"compatible",&n);
  if(v) { v=fdt_getprop(new,off,"status",&n); if(!v || n!=9 || memcmp(v,"disabled",9)) return -29; }
 }
 /* These four new metadata nodes have no compatible property, but their
  * disabled status is part of the reviewed cold-boot graph/pinctrl contract. */
 {
  static const char disabled_metadata[][BOB_PATH_WIDTH] = {
   "/soc/i2c@235010000/usb-pd@38/connector/ports/port@2",
   "/soc/pinctrl@24a820000/acio0-pins",
   "/soc/i2c@235010000/usb-pd@3f/connector/ports/port@2",
   "/soc/pinctrl@24a820000/acio1-pins",
  };
  unsigned int j;
  for (j=0;j<BOB_COUNT(disabled_metadata);j++) {
   dst=bob_exact_path(new,disabled_metadata[j]);
   if(dst<0) return -31;
   v=fdt_getprop(new,dst,"status",&n);
   if(!v || n!=9 || memcmp(v,"disabled",9)) return -31;
  }
 }
 rc=(new_count==BOB_COUNT(bob_new_nodes) && added==BOB_COUNT(bob_phandle_nodes))?0:-30;
 return rc;
}
