#ifndef J314S_BOOT_ADMISSION_H
#define J314S_BOOT_ADMISSION_H
#include "j314s-peer-boot.h"
#include "j314s-combined-boot.h"
static bool j314s_c0_boot_valid(const char *p)
{
 const char *keys[]={"bob_kernel_mode=","bob_kernel_trial=","bob_j314s_overlay="};
 const char *values[]={"bob_kernel_mode=late-arm-j314s-r22-inventory",
  "bob_kernel_trial=m1pro-j314s-r22-20261004","bob_j314s_overlay=efi-disabled-r22"};
 const char *chain="thunderbolt_apple.j314s_chain_inventory=1";
 unsigned counts[3]={0},chain_count=0;unsigned i;size_t n;
 while(*p) {
  p+=strspn(p," \t");n=strcspn(p," \t");if(!n)break;
  if(!strncmp(p,"dtb=",4)||!strncmp(p,"bob_j314s_peer=",15)||!strncmp(p,"bob_j314s_mask=",15))return false;
  if(!strncmp(p,"thunderbolt_apple.",18)) {
   if(n!=strlen(chain)||strncmp(p,chain,n)||++chain_count!=1)return false;
  }
  for(i=0;i<3;i++)if(!strncmp(p,keys[i],strlen(keys[i]))) {
   if(n!=strlen(values[i])||strncmp(p,values[i],n))return false;
   counts[i]++;
  }
  p+=n;
 }
 return counts[0]==1&&counts[1]==1&&counts[2]==1&&chain_count==1;
}
static unsigned j314s_boot_admission_mask(const char*p)
{
 unsigned mask=j314s_combined_boot_mask(p);int peer;
 if(mask)return mask;
 /* New mask tokens never fall back to an older mode. */
 if(!p)return 0;
 for(const char*q=p;*q;){q+=strspn(q," \t\r\n");size_t n=strcspn(q," \t\r\n");if(!n)break;if(!strncmp(q,"bob_j314s_mask=",15))return 0;q+=n;}
 peer=j314s_peer_boot_controller(p);if(peer)return 1U<<peer;
 return j314s_c0_boot_valid(p)?1:0;
}
static bool j314s_boot_controller_admitted(const char*p,unsigned index)
{return index<3&&(j314s_boot_admission_mask(p)&(1U<<index));}
#endif
