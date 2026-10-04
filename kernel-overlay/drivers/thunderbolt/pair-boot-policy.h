/* SPDX-License-Identifier: GPL-2.0 */
#ifndef BOB_TB_PAIR_BOOT_POLICY_H
#define BOB_TB_PAIR_BOOT_POLICY_H
/* Exact opt-in; no guessing from discovered devices or a vendor ID. */
static bool tb_pair_boot_valid(const char *kernel,const char *cmdline)
{
 static const char *const keys[]={"bob_kernel_mode=","bob_kernel_trial=","bob_j293_overlay=",
  "thunderbolt_apple.external_endpoint_pair=","pcie_apple_apciec_experimental.endpoint_pair="};
 static const char *const expected[]={"bob_kernel_mode=late-arm-r54-native-driver",
  "bob_kernel_trial=oldm1-r54-20261004","bob_j293_overlay=efi-disabled-r52",
  "thunderbolt_apple.external_endpoint_pair=1","pcie_apple_apciec_experimental.endpoint_pair=1"};
 unsigned seen=0;const char *p=cmdline;size_t len;unsigned k;
 if(!kernel||!cmdline||strcmp(kernel,"7.3.0-rc1-j293-router-r54"))return false;
 while(*p){
  p+=strspn(p," \t");len=strcspn(p," \t");if(!len)break;
  for(k=0;k<5;k++)if(len>=strlen(keys[k])&&!strncmp(p,keys[k],strlen(keys[k]))){
   if((seen&(1U<<k))||len!=strlen(expected[k])||strncmp(p,expected[k],len))return false;
   seen|=1U<<k;
  }
  p+=len;
 }
 return seen==31;
}
#endif
