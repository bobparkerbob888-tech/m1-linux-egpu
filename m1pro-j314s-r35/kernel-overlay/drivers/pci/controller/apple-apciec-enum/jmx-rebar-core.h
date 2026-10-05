/* Typed5090M only. Complete ep_caps walk already proves payload ownership. */
static int jmx_rebar_sample(const struct ep_function*f,unsigned off,u32*v)
{
 unsigned count=0;
 for(unsigned j=0;j<f->sample_count;j++)if(f->samples[j].offset==off){*v=f->samples[j].value;count++;}
 return count==1?0:-EINVAL;
}
static int jmx_rebar_plan(const struct ep_function*f,unsigned*offset,u32*before,u32*after)
{
 u32 h,ctrl,cap;unsigned n,seen=0,found=0;int ret;
 if(!f||!offset||!before||!after||f->identity.id!=0x2c1810de||f->command||
    !f->rebar||f->rebar>0xff4)return -EPERM;
 ret=jmx_rebar_sample(f,f->rebar,&h);if(ret)return ret;
 if((h&0xffff)!=0x15||((h>>16)&15)!=1)return -EOPNOTSUPP;
 ret=jmx_rebar_sample(f,f->rebar+8,&ctrl);if(ret)return ret;
 n=(ctrl>>5)&7;if(!n||n>6||f->rebar+4+n*8>4096)return -EINVAL;
 for(unsigned j=0;j<n;j++){
  ret=jmx_rebar_sample(f,f->rebar+4+j*8,&cap);if(ret)return ret;
  ret=jmx_rebar_sample(f,f->rebar+8+j*8,&ctrl);if(ret)return ret;
  unsigned bar=ctrl&7,size=(ctrl>>8)&31;
  if(bar>5||bar==2||(seen&(1U<<bar)))return -EINVAL;
  seen|=1U<<bar;
  if(bar!=1)continue;
  if(++found!=1||!(cap&(1U<<12))||size>27||!(cap&(1U<<(size+4)))||
     (size!=8&&size!=15))return -EOPNOTSUPP;
  *offset=f->rebar+8+j*8;*before=ctrl;*after=(ctrl&~0x1f00U)|0x800;
 }
 return found==1?0:-EOPNOTSUPP;
}
