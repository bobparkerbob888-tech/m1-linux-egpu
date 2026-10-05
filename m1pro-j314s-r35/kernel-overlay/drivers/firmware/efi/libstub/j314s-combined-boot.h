/* SPDX-License-Identifier: GPL-2.0 */
#ifndef J314S_COMBINED_BOOT_H
#define J314S_COMBINED_BOOT_H
/* Immutable explicit two-controller mode. No active-controller variable. */
static unsigned j314s_combined_boot_mask(const char *p)
{
 const char keys[][32]={"bob_kernel_mode=","bob_kernel_trial=","bob_j314s_overlay=","bob_j314s_mask=","thunderbolt_apple."};
 const char values[][64]={"bob_kernel_mode=late-arm-j314s-all9","bob_kernel_trial=m1pro-j314s-all9-20261005","bob_j314s_overlay=efi-disabled-all9","","thunderbolt_apple.j314s_chain_inventory=1"};
 unsigned count[5]={0},mask=0;size_t n;
 if(!p)return 0;
 while(*p){
  while(*p==' '||*p=='\t'||*p=='\r'||*p=='\n')p++;
  for(n=0;p[n]&&p[n]!=' '&&p[n]!='\t'&&p[n]!='\r'&&p[n]!='\n';n++){}
  if(!n)break;
  if(!strncmp(p,"dtb=",4)||!strncmp(p,"bob_j314s_peer=",15))return 0;
  for(unsigned i=0;i<5;i++)if(!strncmp(p,keys[i],strlen(keys[i]))){
   if(++count[i]!=1)return 0;
   if(i==3){size_t k=strlen(keys[i]);if(n!=k+1||(p[k]!='3'&&p[k]!='5'))return 0;mask=p[k]-'0';}
   else if(n!=strlen(values[i])||strncmp(p,values[i],n))return 0;
  }
  p+=n;
 }
 for(unsigned i=0;i<5;i++)if(count[i]!=1)return 0;
 return mask;
}
#endif
