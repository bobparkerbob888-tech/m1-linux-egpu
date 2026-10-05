/* Standard PCI configuration only. No PCI-core object/quirk/retrain, BAR,
 * capability writes, MSI setup or GPU driver interaction. */
struct retained_raw_record {unsigned bus,devfn;u32 id,class_rev,subsystem;u64 serial;u16 command;u8 header;};
enum retained_link_state { RETAINED_LINK_SNAPSHOT, RETAINED_LINK_ACTIVE,
 RETAINED_LINK_TIME_ONLY, RETAINED_LINK_DOWN, RETAINED_LINK_ROOT_SETTLE,
 RETAINED_LINK_ERROR };
struct retained_link_record {unsigned bus,devfn,cap,flags,bridge_control,state,polls;
 u32 link_cap,link_control_status;u64 waited_ns;int status;
 unsigned diagnostic_valid,pm_cap;int diagnostic_status;bool diagnostic_attempted;
 u32 slot_cap,slot_control_status,pm_header,pm_control_status;
 unsigned aer_stage,aer_valid,aer_cap;int aer_status;u32 aer_header,aer_devctl,aer_data[10];};
struct retained_raw_io {
 int (*read)(void*,unsigned,unsigned,unsigned,u32*);
 int (*write)(void*,unsigned,unsigned,unsigned,u32);
 bool (*valid)(void*);u64(*now)(void*);void(*record)(void*,const struct retained_raw_record*);
 void(*sleep)(void*);int(*audit)(void*);void(*link_record)(void*,const struct retained_link_record*);
 void*ctx;u64 deadline;unsigned first,last,next,ops,devices,nvidia,buses,max_depth,max_buses;bool seen[256];bool strict_identity,j314s_multi_initial;
 unsigned leaf_count;struct retained_link_record leaf[5];
};
static int retained_raw_read(struct retained_raw_io*i,unsigned b,unsigned d,unsigned off,u32*v)
{
 int r;if(!i->valid(i->ctx))return -EPERM;
 if(i->ops>=8192||i->now(i->ctx)>=i->deadline)return -ETIMEDOUT;
 if(b<i->first||b>i->last||d>255||off>4092||(off&3))return -EINVAL;
 i->ops++;r=i->read(i->ctx,b,d,off,v);
 if(i->now(i->ctx)>=i->deadline)return -ETIMEDOUT;
 if(!i->valid(i->ctx))return -EPERM;
 return r;
}
static int retained_raw_write(struct retained_raw_io*i,unsigned b,unsigned d,unsigned off,u32 v)
{
 int r;u32 got;
 if(off!=4&&off!=0x18)return -EPERM;
 if(off==4&&(v&7))return -EPERM;
 if(!i->valid(i->ctx))return -EPERM;
 if(i->ops>=8192||i->now(i->ctx)>=i->deadline)return -ETIMEDOUT;
 if(b<i->first||b>i->last||d>255)return -EINVAL;
 i->ops++;r=i->write(i->ctx,b,d,off,v);
 if(i->now(i->ctx)>=i->deadline)return -ETIMEDOUT;
 if(!i->valid(i->ctx))return -EPERM;
 if(r)return r;
 r=retained_raw_read(i,b,d,off,&got);if(r)return r;
 /* PCI_COMMAND upper half is W1C status: caller writes only low command. */
 return off==4?(got&0xffff)==(v&0xffff)?0:-EIO:got==v?0:-EIO;
}
static int retained_raw_serial(struct retained_raw_io*i,unsigned b,unsigned d,u64*serial)
{
 unsigned off=0x100,seen[64],count=0;u32 v,lo,hi;int r;
 while(off){
  if(off<0x100||off>0xffc||(off&3)||count==64)return -EINVAL;
  for(unsigned k=0;k<count;k++)if(seen[k]==off)return -EINVAL;
  seen[count++]=off;r=retained_raw_read(i,b,d,off,&v);if(r)return r;
  if(!v||v==0xffffffff)return 0;
  if((v&0xffff)==3){
   if(off>0xff4)return -EINVAL;
   r=retained_raw_read(i,b,d,off+4,&lo);if(r)return r;
   r=retained_raw_read(i,b,d,off+8,&hi);if(r)return r;
   *serial=((u64)hi<<32)|lo;return 0;
  }
  off=v>>20;
 }
 return 0;
}
/* First access after link activation follows pci.c pcie_wait_for_link_delay.
 * Readiness polling is part of the initial transaction, never a reset/retrain
 * or vendor-ID retry. No capability/control register is written here. */
static int retained_raw_wait_gate(struct retained_raw_io*i)
{
 if(!i->valid(i->ctx))return -EPERM;
 if(i->ops>=8192||i->now(i->ctx)>=i->deadline)return -ETIMEDOUT;
 return 0;
}
static int retained_raw_wait(struct retained_raw_io*i,unsigned ms)
{
 u64 start=i->now(i->ctx),duration=(u64)ms*1000000ULL;unsigned polls=0;int r;
 if(!i->sleep||!i->audit||!i->link_record)return -EPERM;
 r=retained_raw_wait_gate(i);if(r)return r;
 if(duration>=i->deadline-start)return -ETIMEDOUT;
 while(i->now(i->ctx)-start<duration){
  r=retained_raw_wait_gate(i);if(r)return r;
  if(polls++>ms+1)return -ETIMEDOUT;
  i->sleep(i->ctx);
  r=retained_raw_wait_gate(i);if(r)return r;
 }
 return retained_raw_wait_gate(i);
}
static int retained_raw_readiness_audit(struct retained_raw_io*i)
{
 int r=retained_raw_wait_gate(i);if(r)return r;
 if(!i->audit)return -EPERM;
 r=i->audit(i->ctx);return r?r:retained_raw_wait_gate(i);
}
static int retained_raw_initial_settle(struct retained_raw_io*i)
{
 struct retained_link_record rec={.bus=i->first,.state=RETAINED_LINK_ROOT_SETTLE};
 u64 start=i->now(i->ctx);int r;
 if(!i->sleep||!i->audit||!i->link_record)return -EPERM;
 r=retained_raw_readiness_audit(i);
 if(!r)r=retained_raw_wait(i,100);
 if(!r)r=retained_raw_readiness_audit(i);
 rec.waited_ns=i->now(i->ctx)-start;rec.status=r;
 if(i->link_record)i->link_record(i->ctx,&rec);
 return r;
}
static int retained_raw_bridge_caps(struct retained_raw_io*i,unsigned b,unsigned d,
                                    struct retained_link_record*rec)
{
 unsigned off,seen[48],count=0;u32 v,pcie=0;int r;
 r=retained_raw_read(i,b,d,4,&v);if(r)return r;
 if(v==0xffffffffU)return -EIO;
 if(!(v&0x00100000U))return -EOPNOTSUPP;
 r=retained_raw_read(i,b,d,0x34,&v);if(r)return r;
 if(v==0xffffffffU)return -EIO;
 off=v&255;
 while(off){
  if(off<0x40||off>0xfc||(off&3)||count>=48)return -EINVAL;
  for(unsigned k=0;k<count;k++)if(seen[k]==off)return -EINVAL;
  seen[count++]=off;
  r=retained_raw_read(i,b,d,off,&v);if(r)return r;
  if(v==0xffffffffU)return -EIO;
  if((v&255)==0x10){if(pcie)return -EINVAL;pcie=off;rec->flags=v>>16;}
  off=(v>>8)&255;
 }
 if(!pcie||pcie>0xec)return -EINVAL;
 /* No other capability header may point into the PCIe fields we inspect. */
 for(unsigned k=0;k<count;k++)if(seen[k]>pcie&&seen[k]<pcie+0x14)return -EINVAL;
 if(!(rec->flags&15)||(rec->flags&15)>2)return -EOPNOTSUPP;
 unsigned type=(rec->flags>>4)&15;
 if(type!=4&&type!=5&&type!=6)return -EOPNOTSUPP;
 if((b==i->first&&d==0)!=(type==4))return -EPERM;
 rec->cap=pcie;
 r=retained_raw_read(i,b,d,0x3c,&v);if(r)return r;
 if(v==0xffffffffU)return -EIO;
 rec->bridge_control=v>>16;if(rec->bridge_control&0x40)return -EPERM;
 r=retained_raw_read(i,b,d,pcie+0x0c,&rec->link_cap);if(r)return r;
 r=retained_raw_read(i,b,d,pcie+0x10,&rec->link_control_status);if(r)return r;
 if(rec->link_cap==0xffffffffU||rec->link_control_status==0xffffffffU)return -EIO;
 if(rec->link_control_status&0x10)return -EPERM;
 return 0;
}
/* Read-only metadata; all reads use the original actor/deadline/8192 budget. */
static int retained_raw_power_diagnostic(struct retained_raw_io*i,
 unsigned b,unsigned d,struct retained_link_record*rec)
{
 unsigned seen[48],count=0,off,pm=0,pcie=0;u32 v;int r;
 if(((rec->flags>>4)&15)!=6)return -EPERM;
 r=retained_raw_read(i,b,d,0x34,&v);if(r)return r;if(v==~0U)return -EIO;off=v&255;
 while(off){
  if(off<0x40||off>0xfc||(off&3)||count>=48)return -EINVAL;
  for(unsigned k=0;k<count;k++)if(seen[k]==off)return -EINVAL;
  seen[count++]=off;r=retained_raw_read(i,b,d,off,&v);if(r)return r;
  if(v==~0U)return -EIO;
  if((v&255)==0x10){if(pcie||off!=rec->cap||(v>>16)!=rec->flags)return -ESTALE;pcie=off;}
  if((v&255)==1){if(pm)return -EINVAL;pm=off;rec->pm_header=v;}
  off=(v>>8)&255;
 }
 if(!pcie)return -ESTALE;
 if(rec->flags&0x100){
  if(pcie>0xe4)return -EINVAL;
  for(unsigned k=0;k<count;k++)if(seen[k]>pcie&&seen[k]<pcie+0x1c)return -EINVAL;
  r=retained_raw_read(i,b,d,pcie+0x14,&rec->slot_cap);if(r)return r;
  r=retained_raw_read(i,b,d,pcie+0x18,&rec->slot_control_status);if(r)return r;
  if(rec->slot_cap==~0U||rec->slot_control_status==~0U)return -EIO;
  rec->diagnostic_valid|=1;
 }
 if(pm){
  if(pm>0xf8)return -EINVAL;
  for(unsigned k=0;k<count;k++)if(seen[k]>pm&&seen[k]<pm+8)return -EINVAL;
  /* The PM payload must not alias the validated PCIe block. */
  if(pm<pcie+((rec->flags&0x100)?0x1c:0x14)&&pm+8>pcie)return -EINVAL;
  r=retained_raw_read(i,b,d,pm+4,&rec->pm_control_status);if(r)return r;
  if(rec->pm_control_status==~0U)return -EIO;
  rec->pm_cap=pm;rec->diagnostic_valid|=2;
 }
 return 0;
}
/* Temporal evidence only: pre-child-scan is not a power-on baseline.
 * All config transactions retain the original raw actor/30s/8192 limits. */
static int retained_raw_aer_snapshot(struct retained_raw_io*i,struct retained_link_record*rec,unsigned stage)
{
 unsigned seen[64],count=0,off=0x100,aer=0,j;u32 h;int r;
 rec->aer_stage=stage;rec->aer_valid=0;rec->aer_header=0;rec->aer_cap=0;
 r=retained_raw_read(i,rec->bus,rec->devfn,rec->cap+8,&rec->aer_devctl);if(r)return r;
 if(rec->aer_devctl==~0U)return -EIO;
 rec->aer_valid=1;
 while(off){
  if(off<0x100||off>0xffc||(off&3)||count==64)return -EINVAL;
  for(j=0;j<count;j++)if(seen[j]==off)return -EINVAL;
  r=retained_raw_read(i,rec->bus,rec->devfn,off,&h);if(r)return r;
  if(!h||h==~0U)break;
  if(!((h>>16)&15)||!(h&65535))return -EINVAL;
  seen[count++]=off;
  if((h&65535)==1){if(aer||off>0xfd4)return -EINVAL;aer=off;rec->aer_header=h;}
  off=h>>20;
 }
 if(!aer)return -ENOENT;
 for(j=0;j<count;j++)if(seen[j]>aer&&seen[j]<aer+0x2c)return -EINVAL;
 rec->aer_cap=aer;rec->aer_valid|=2;
 for(j=0;j<10;j++){
  r=retained_raw_read(i,rec->bus,rec->devfn,aer+4+4*j,&rec->aer_data[j]);if(r)return r;
  if(rec->aer_data[j]==~0U)return -EIO;
  rec->aer_valid|=1U<<(j+2);
 }
 return 0;
}
static int retained_raw_aer_finish(struct retained_raw_io*i)
{
 for(unsigned j=0;j<i->leaf_count;j++){
  struct retained_link_record*rec=&i->leaf[j];
  rec->diagnostic_attempted=false;
  rec->aer_status=retained_raw_aer_snapshot(i,rec,2);
  i->link_record(i->ctx,rec);
 }
 return i->leaf_count?retained_raw_wait_gate(i):0;
}
/* Return1 only for a clean reporting downstream that never became active.
 * Root link-down, active-to-down, and all errors are terminal. Upstream port
 * status describes its upstream link, not the switch's internal child bus. */
static int retained_raw_bridge_ready(struct retained_raw_io*i,unsigned b,unsigned d,const struct retained_raw_record*identity)
{
 struct retained_link_record rec={.bus=b,.devfn=d,.state=RETAINED_LINK_SNAPSHOT};
 u64 start=i->now(i->ctx),limit=1000000000ULL;u32 initial_control,v;bool active_seen=false;unsigned interval=1,poll_limit=1000;int r;
 if(!i->sleep||!i->audit||!i->link_record)return -EPERM;
 r=retained_raw_readiness_audit(i);if(r)goto fail;
 r=retained_raw_bridge_caps(i,b,d,&rec);if(r)goto fail;
 if(((rec.flags>>4)&15)==5){i->link_record(i->ctx,&rec);r=0;goto finish;}
 /* Exact measured Intel downstream schema, enabled only by a validated
  * J314s multi owner. This is the first readiness wait, not a link retry.
  * Original scan/provider deadline and 8192 transaction limit still apply. */
 if(i->j314s_multi_initial&&identity&&identity->id==0x57868086&&
    identity->class_rev==0x06040085&&identity->header==1&&identity->command==0&&
    rec.flags==0x0162&&rec.link_cap==0x00715844&&rec.bridge_control==0&&
    !(rec.link_control_status&0xffff)){
  limit=5000000000ULL;interval=20;poll_limit=250;
  rec.diagnostic_attempted=true;
  rec.diagnostic_status=retained_raw_power_diagnostic(i,b,d,&rec);
  rec.aer_status=retained_raw_aer_snapshot(i,&rec,1);
  if(i->leaf_count<5)i->leaf[i->leaf_count++]=rec;
 }
 i->link_record(i->ctx,&rec);
 initial_control=rec.link_control_status&0xffff;
 if(rec.link_cap&0x00100000U){
  for(unsigned poll=0;;poll++){
   unsigned status=rec.link_control_status>>16;
   active_seen|=!!(status&0x2000);
   if((status&0x2000)&&!(status&0x0800)&&(status&0x03f0))break;
   if(i->now(i->ctx)-start>=limit||poll>=poll_limit){
    if(!active_seen&&((rec.flags>>4)&15)==6){
     if(rec.diagnostic_attempted){rec.diagnostic_valid=0;rec.diagnostic_status=retained_raw_power_diagnostic(i,b,d,&rec);}
     rec.state=RETAINED_LINK_DOWN;r=1;goto finish;}
    r=-ETIMEDOUT;goto fail;
   }
   /* Total initial link wait remains bounded by the immutable scan ticket. */
   r=retained_raw_wait(i,interval);if(r)goto fail;
   r=retained_raw_read(i,b,d,rec.cap+0x10,&v);if(r)goto fail;
   rec.polls++;rec.link_control_status=v;
   if(v==0xffffffffU||(v&0xffff)!=initial_control){r=-EIO;goto fail;}
  }
  rec.state=RETAINED_LINK_ACTIVE;
  r=retained_raw_wait(i,100);if(r)goto fail;
 }else{
  rec.state=RETAINED_LINK_TIME_ONLY;
  r=retained_raw_wait(i,1100);if(r)goto fail;
 }
 r=retained_raw_read(i,b,d,rec.cap+0x10,&v);if(r)goto fail;
 rec.link_control_status=v;
 if(v==0xffffffffU||(v&0xffff)!=initial_control||(v&(0x0800U<<16))||!(v&(0x03f0U<<16))||
    ((rec.link_cap&0x00100000U)&&!(v&(0x2000U<<16)))){r=-EIO;goto fail;}
 r=0;
 finish:
 /* Reset/control mutation invalidates even a purported empty-branch result. */
 {int read=retained_raw_read(i,b,d,0x3c,&v);if(read){r=read;goto fail;}}
 if(v==0xffffffffU||(v>>16)!=rec.bridge_control){r=-EIO;goto fail;}
 {int audit=retained_raw_readiness_audit(i);if(audit){r=audit;goto fail;}}
 rec.waited_ns=i->now(i->ctx)-start;rec.status=r;i->link_record(i->ctx,&rec);return r;
 fail:
 rec.state=RETAINED_LINK_ERROR;rec.status=r;rec.waited_ns=i->now(i->ctx)-start;i->link_record(i->ctx,&rec);return r;
}

static int retained_raw_bus(struct retained_raw_io*,unsigned,unsigned,unsigned,unsigned*);
static int retained_raw_function(struct retained_raw_io*i,unsigned b,unsigned d,unsigned depth,unsigned limit,unsigned*highest,bool*multi)
{
 struct retained_raw_record rec={.bus=b,.devfn=d};u32 v,buses,again;int r;unsigned sec,sub,found;bool link_down=false;
 r=retained_raw_read(i,b,d,0,&rec.id);if(r)return r;
 if(rec.id==0xffffffff||rec.id==0||!(rec.id&0xffff)||(rec.id&0xffff)==0xffff)return 0;
 if((rec.id&0xffff)==1)return -EAGAIN; /* CRS/not-ready: never retry. */
 if(++i->devices>64)return -E2BIG;
 r=retained_raw_read(i,b,d,4,&v);if(r)return r;
 if(i->strict_identity&&v==0xffffffff)return -EIO;
 r=retained_raw_write(i,b,d,4,(v&0xffff)&~7U);if(r)return r;
 rec.command=(v&0xffff)&~7U;
 r=retained_raw_read(i,b,d,8,&rec.class_rev);if(r)return r;
 if(i->strict_identity&&rec.class_rev==0xffffffff)return -EIO;
 r=retained_raw_read(i,b,d,12,&v);if(r)return r;
 if(i->strict_identity&&v==0xffffffff)return -EIO;
 rec.header=v>>16;*multi=rec.header&0x80;
 if((rec.header&0x7f)>1)return -EOPNOTSUPP;
 if((rec.id&0xffff)==0x10de&&(rec.class_rev>>24)==3){
  r=retained_raw_read(i,b,d,0x2c,&rec.subsystem);if(r)return r;
  r=retained_raw_serial(i,b,d,&rec.serial);if(r)return r;
  i->nvidia++;
 }
 if(i->strict_identity){r=retained_raw_read(i,b,d,0,&again);if(r)return r;
  if(again!=rec.id)return -ESTALE;
  r=retained_raw_read(i,b,d,4,&again);if(r)return r;
  if(again==0xffffffff||(again&7)||(again&0xffff)!=rec.command)return -EIO;}
 i->record(i->ctx,&rec);
 if((rec.header&0x7f)!=1)return 0;
 if((rec.class_rev>>16)!=0x0604)return -EPERM;
 if(i->strict_identity){r=retained_raw_bridge_ready(i,b,d,&rec);if(r<0)return r;link_down=r==1;}
 r=retained_raw_read(i,b,d,0x18,&buses);if(r)return r;
 if(i->strict_identity&&buses==0xffffffff)return -EIO;
 sec=(buses>>8)&255;sub=(buses>>16)&255;
 if(sec||sub){
  if((buses&255)!=b||sec<=b||sub<sec||sub>limit||i->seen[sec])return -EINVAL;
 }else{
  if((buses&255)&&((buses&255)!=b))return -EINVAL;
  if(link_down)return 0; /* No invented range for a clean empty port. */
  if(i->next<=b)i->next=b+1;
  while(i->next<=limit&&i->seen[i->next])i->next++;
  if(i->next>limit)return -ENOSPC;
  sec=i->next++;sub=limit;
  /* Native primary/secondary/subordinate assignment, latency byte preserved. */
  r=retained_raw_write(i,b,d,0x18,(buses&0xff000000)|b|(sec<<8)|(sub<<16));if(r)return r;
 }
 /* Skipping a child never discards its existing subordinate reservation. */
 if(link_down){if(i->next<=sub)i->next=sub+1;if(sub>*highest)*highest=sub;return 0;}
 found=sec;r=retained_raw_bus(i,sec,depth+1,sub,&found);if(r)return r;
 if(found>sub)return -EINVAL;
 /* Preserve inherited subordinate reservations, even for unimplemented holes. */
 if((buses>>8)&255)found=sub;
 if(i->next<=found)i->next=found+1;
 if(!((buses>>8)&255)){
  r=retained_raw_write(i,b,d,0x18,(buses&0xff000000)|b|(sec<<8)|(found<<16));if(r)return r;
 }
 if(found>*highest)*highest=found;
 return 0;
}
/* Reserve no invented bridge windows. Preflight sibling ranges before any
 * bus-number assignment on this bus; mixed inherited/unconfigured siblings
 * fail closed. Ancestor assignments already made remain retained until reboot.
 */
static int retained_raw_preflight_bus(struct retained_raw_io*i,unsigned bus,unsigned limit)
{
 unsigned char lows[256], highs[256];unsigned count=0;bool configured=false,empty=false;
 for(unsigned slot=0;slot<32;slot++) {
  unsigned functions=1;
  for(unsigned f=0;f<functions;f++) {
   unsigned d=(slot<<3)|f;u32 id,header,b;int r;
   r=retained_raw_read(i,bus,d,0,&id);if(r)return r;
   if(id==0xffffffff||id==0||!(id&0xffff)||(id&0xffff)==0xffff)continue;
   if((id&0xffff)==1)return -EAGAIN;
   r=retained_raw_read(i,bus,d,12,&header);if(r)return r;
   header>>=16;if(!f&&(header&0x80))functions=8;
   if((header&0x7f)>1)return -EOPNOTSUPP;
   if((header&0x7f)!=1)continue;
   r=retained_raw_read(i,bus,d,0x18,&b);if(r)return r;
   unsigned sec=(b>>8)&255,sub=(b>>16)&255;
   if(!sec&&!sub) {
    if((b&255)&&(b&255)!=bus)return -EINVAL;
    empty=true;
   }else{
    if((b&255)!=bus||sec<=bus||sub<sec||sub>limit)return -EINVAL;
    for(unsigned k=0;k<count;k++)if(sec<=highs[k]&&sub>=lows[k])return -EINVAL;
    lows[count]=sec;highs[count++]=sub;configured=true;
   }
  }
 }
 return configured&&empty?-EOPNOTSUPP:0;
}
static int retained_raw_bus(struct retained_raw_io*i,unsigned bus,unsigned depth,unsigned limit,unsigned*highest)
{
 int r;bool multi;
 if(depth>(i->max_depth?i->max_depth:8)||i->buses>=(i->max_buses?i->max_buses:8)||bus<i->first||bus>i->last||i->seen[bus])return -ELOOP;
 r=retained_raw_preflight_bus(i,bus,limit);if(r)return r;
 i->seen[bus]=true;i->buses++;
 for(unsigned slot=0;slot<32;slot++){
  multi=false;r=retained_raw_function(i,bus,slot<<3,depth,limit,highest,&multi);if(r)return r;
  if(multi)for(unsigned f=1;f<8;f++){bool ignored=false;r=retained_raw_function(i,bus,(slot<<3)|f,depth,limit,highest,&ignored);if(r)return r;}
 }
 return 0;
}
static int retained_raw_discover(struct retained_raw_io*i)
{
 unsigned highest=i->first;bool multi=false;int r;
 if(i->first>=i->last||i->last>255)return -EINVAL;
 if((i->max_depth||i->max_buses)&&(i->max_depth!=16||i->max_buses!=32))return -EINVAL;
 if(i->strict_identity){r=retained_raw_initial_settle(i);if(r)return r;}
 i->next=i->first+1;i->seen[i->first]=true;i->buses=1;
 /* Exact root slot0 only; downstream bus numbers come from validated headers. */
 r=retained_raw_function(i,i->first,0,0,i->last,&highest,&multi);if(r)return r;
 r=retained_raw_aer_finish(i);if(r)return r;
 return i->nvidia?0:-ENODEV;
}
