#ifndef J314S_PEER_BOOT_H
#define J314S_PEER_BOOT_H
/* Return exactly the selected dormant peer, or zero on every malformed input. */
static int j314s_peer_boot_controller(const char *p)
{
 const char*keys[]={"bob_kernel_mode=","bob_kernel_trial=","bob_j314s_overlay=","bob_j314s_peer="};
 const char*values[]={"bob_kernel_mode=late-arm-j314s-peer-identity","bob_kernel_trial=m1pro-j314s-peer-identity-20261005","bob_j314s_overlay=efi-disabled-peer-identity"};
 unsigned count[4]={0},i,index=0;size_t n;
 if(!p)return 0;
 while(*p){p+=strspn(p," \t\r\n");n=strcspn(p," \t\r\n");if(!n)break;
  if(!strncmp(p,"dtb=",4)||!strncmp(p,"thunderbolt_apple.",18))return 0;
  for(i=0;i<4;i++)if(!strncmp(p,keys[i],strlen(keys[i]))){
   if(++count[i]!=1)return 0;
   if(i<3){if(n!=strlen(values[i])||strncmp(p,values[i],n))return 0;}
   else {size_t k=strlen(keys[i]);if(n!=k+1||(p[k]!='1'&&p[k]!='2'))return 0;index=p[k]-'0';}
  }
  p+=n;
 }
 return count[0]==1&&count[1]==1&&count[2]==1&&count[3]==1?index:0;
}
#endif
