/* SPDX-License-Identifier: GPL-2.0 */
static int am_resources(struct apciec_multi*m)
{
 unsigned j,k;int ret;u32 value;
 for(j=0;j<AM_FUNCTIONS;j++){
  const struct am_layout*a=&am_layout[j];struct pci_dev*d=m->devices[j];
  if(!a->secondary||j==2)continue;
  for(k=0x20;k<=0x2c;k+=4){
   if(!am_window_value(j,k,&value))return -EINVAL;
   ret=am_exact_write(m,a->rid,k,4,value);if(ret)return ret;
  }
  for(k=0;k<2;k++){
   unsigned index=k?PCI_BRIDGE_PREF_MEM_WINDOW:PCI_BRIDGE_MEM_WINDOW;
   struct resource*r=&d->resource[index];
   u64 start=k?a->pref_start:a->mem_start,end=k?a->pref_end:a->mem_end;
   if(j<2){
    if(!r->parent||r->start!=start||r->end>end)return -ESTALE;
    if(adjust_resource(r,start,end-start+1))return -EBUSY;
   }else{
    if(r->parent||r->child)return -EPERM;
    r->start=start;r->end=end;
    r->flags=IORESOURCE_MEM|(k?(IORESOURCE_PREFETCH|IORESOURCE_MEM_64):0);
    ret=pci_claim_resource(d,index);if(ret)return ret;
   }
   if(!r->parent||r->parent->start>start||r->parent->end<end)return -EPERM;
  }
 }
 for(j=0;j<AM_FUNCTIONS;j++){
  const struct am_layout*a=&am_layout[j];struct pci_dev*d=m->devices[j];
  u64 pref,mem;
  if(a->gpu<2)continue;
  pref=0x400000000ULL+(a->gpu-1)*0x20000000ULL;
  mem=0x480000000ULL+(a->gpu-1)*0x04000000ULL;
  for(k=0;k<5;k++){
   struct resource*r=&d->resource[k];u64 cpu,pci,size;unsigned type;
   if(k==2||k==4){if(r->flags||r->parent)return -EPERM;continue;}
   cpu=k==0?mem:pref+(k==3?0x10000000ULL:0);
   pci=k==0?cpu-0x400000000ULL:cpu;
   size=k==0?0x4000000ULL:k==1?0x10000000ULL:0x2000000ULL;
   type=k==0?0:PCI_BASE_ADDRESS_MEM_TYPE_64|PCI_BASE_ADDRESS_MEM_PREFETCH;
   if(r->parent||r->child||resource_size(r)!=size||!(r->flags&IORESOURCE_MEM)||
      !!(r->flags&IORESOURCE_PREFETCH)!=(k!=0)||!!(r->flags&IORESOURCE_MEM_64)!=(k!=0))return -ESTALE;
   ret=am_read(m,a->rid,PCI_BASE_ADDRESS_0+4*k,&value);if(ret)return ret;
   if((value&15)!=type||(value&~15U))return -ESTALE;
   if(k){ret=am_read(m,a->rid,PCI_BASE_ADDRESS_0+4*(k+1),&value);if(ret||value)return ret?ret:-ESTALE;}
   ret=am_exact_write(m,a->rid,PCI_BASE_ADDRESS_0+4*k,4,(u32)pci|type);if(ret)return ret;
   if(k){ret=am_exact_write(m,a->rid,PCI_BASE_ADDRESS_0+4*(k+1),4,pci>>32);if(ret)return ret;}
   r->start=cpu;r->end=cpu+size-1;r->flags&=~(IORESOURCE_UNSET|IORESOURCE_DISABLED|IORESOURCE_STARTALIGN|IORESOURCE_SIZEALIGN);
   ret=pci_claim_resource(d,k);if(ret)return ret;
   if(!r->parent||r->parent->start>r->start||r->parent->end<r->end)return -EPERM;
  }
  if(d->resource[5].parent||d->resource[PCI_ROM_RESOURCE].parent)return -EPERM;
 }
 return 0;
}
