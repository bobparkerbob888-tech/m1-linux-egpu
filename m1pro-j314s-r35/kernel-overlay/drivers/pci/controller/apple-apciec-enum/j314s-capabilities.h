/* SPDX-License-Identifier: GPL-2.0 */
#ifndef J314S_CAPABILITIES_H
#define J314S_CAPABILITIES_H
/* Frozen evidence only. Presence is not enablement. No config writes here. */
static bool j314s_cap_sample(const struct ep_function *f,unsigned off,u32 *v)
{
 unsigned j,n=0;
 if(f->sample_count>EP_MAX_SAMPLES)return false;
 for(j=0;j<f->sample_count;j++)if(f->samples[j].offset==off){*v=f->samples[j].value;n++;}
 return n==1;
}
static int j314s_cap_offsets(const struct ep_function *f,unsigned *ari,unsigned *sriov)
{
 unsigned off=0x100,n=0,j,seen[64];u32 h;
 *ari=*sriov=0;
 while(off){
  if(off<0x100||off>0xffc||(off&3)||n==64)return -EINVAL;
  for(j=0;j<n;j++)if(seen[j]==off)return -ELOOP;
  seen[n++]=off;
  if(!j314s_cap_sample(f,off,&h))return -EINVAL;
  if(!h||h==0xffffffff)break;
  if(!((h>>16)&15)||!(h&65535))return -EINVAL;
  if((h&65535)==0xe){if(*ari||off>0xff8)return -EINVAL;*ari=off;}
  if((h&65535)==0x10){if(*sriov||off>0xfc0)return -EINVAL;*sriov=off;}
  off=h>>20;
 }
 return (!!*ari!=f->ari||!!*sriov!=f->sriov)?-EINVAL:0;
}
static bool j314s_capabilities_disabled(const struct ep_function *f)
{
 unsigned ari,sriov;u32 v;
 if(!f||f->ats||f->pasid||(f->devctl2&(1U<<5))||
    j314s_cap_offsets(f,&ari,&sriov))return false;
 /* ARI Control is upper half of +4; capabilities in low half are allowed.
  * Conservative supported policy: all control bits zero, including groups. */
 if(ari&&(!j314s_cap_sample(f,ari+4,&v)||(v>>16)))return false;
 /* SR-IOV Control low half of +8: VF enable, migration, interrupts,
  * memory decode and ARI hierarchy all disabled. NumVFs must be zero. */
 if(sriov&&(!j314s_cap_sample(f,sriov+8,&v)||(v&65535)||
            !j314s_cap_sample(f,sriov+0x10,&v)||(v&65535)))return false;
 return true;
}
static int j314s_capture_disabled_capabilities(struct ep_io *io,struct ep_function *f)
{
 unsigned ari,sriov;u32 v;int ret;
 if(f->ats||f->pasid)return -EOPNOTSUPP;
 ret=j314s_cap_offsets(f,&ari,&sriov);if(ret)return ret;
 if(ari){ret=ep_sample_read(io,f,ari+4,&v);if(ret)return ret;}
 if(sriov){
  ret=ep_sample_read(io,f,sriov+8,&v);if(ret)return ret;
  ret=ep_sample_read(io,f,sriov+0x10,&v);if(ret)return ret;
 }
 return j314s_capabilities_disabled(f)?0:-EOPNOTSUPP;
}
#endif
