#include "jmx-rebar-core.h"
/* All resizes precede every immutable full snapshot: no stale peer samples. */
static int jmx_rebar_prepass(struct apple_apciec*p,struct j314s_multi_resource_owner*m)
{
 const struct jmx_kernel_policy*b;int ret;unsigned long flags;
 if(!p->j314s_mixed_policy)return 0;
 b=jmx_binding(p,false);if(!b)return -EPERM;
 for(unsigned g=0;g<m->count;g++){
  struct j314s_resource_owner*o=m->owners[g];struct j314s_ep_context c={p,o};
  struct ep_io io={.ctx=&c,.read=j314s_ep_read,.write=j314s_ep_write,.safe=j314s_ep_safe,
   .valid=j314s_ep_valid,.now=retained_raw_clock,.deadline=m->deadline,.selected=&o->selected};
  u32 got;
  if(b->policy.model[g]!=JMX_GB203_5090M)continue;
  if(o->rebar_attempted)return -EALREADY;
  o->rebar_attempted=true;o->rebar_capture=kvzalloc(sizeof(*o->rebar_capture),GFP_KERNEL);
  if(!o->rebar_capture)return -ENOMEM;
  m->active_index=g;p->j314s_resource=o;p->endpoint_snapshot=m->snapshots[g];p->endpoint_selected_rid=o->selected.rid;
  raw_spin_lock_irqsave(&p->lock,flags);o->active=true;p->endpoint_sizing=true;p->retained_scan_task=current;raw_spin_unlock_irqrestore(&p->lock,flags);
  ret=jmx_native_owner(p,o->ticket,p->root_down_port,p->retained_identity_deadline,m->count,0);
  if(!ret)ret=j314s_ep_safe(&c,o->selected.rid);
  if(!ret)ret=ep_function_read(&io,&o->selected,o->rebar_capture);
  if(!ret)ret=j314s_capture_disabled_capabilities(&io,o->rebar_capture);
  if(!ret&&!j314s_capabilities_disabled(o->rebar_capture))ret=-EPERM;
  if(!ret)ret=ep_read(&io,o->selected.rid,0x14,&got);
  if(!ret&&(got&15)!=12)ret=-EOPNOTSUPP;
  if(!ret)ret=jmx_rebar_plan(o->rebar_capture,&o->rebar_offset,&o->rebar_before,&o->rebar_after);
  io.selected_serial_offset=o->rebar_capture->serial_offset;
  if(!ret)ret=ep_selected_recheck(&io,o->selected.rid);
  if(!ret)ret=j314s_ep_safe(&c,o->selected.rid);
  if(!ret)ret=ep_read(&io,o->selected.rid,o->rebar_offset,&got);
  if(!ret&&got!=o->rebar_before)ret=-ESTALE;
  if(!ret&&o->rebar_before!=o->rebar_after){
   ret=ep_gate(&io);
   if(!ret){o->rebar_armed=true;io.ops++;ret=io.write(io.ctx,o->selected.rid,o->rebar_offset,o->rebar_after);o->rebar_armed=false;}
  }
  if(!ret)ret=ep_read(&io,o->selected.rid,o->rebar_offset,&got);
  if(!ret&&got!=o->rebar_after)ret=-ESTALE;
  if(!ret)ret=j314s_ep_safe(&c,o->selected.rid);
  raw_spin_lock_irqsave(&p->lock,flags);o->rebar_armed=false;o->active=false;p->endpoint_sizing=false;p->retained_scan_task=NULL;raw_spin_unlock_irqrestore(&p->lock,flags);
  dev_info(p->dev,"jmx-rebar: RID%04x offset%x before%08x after%08x written%u status%d; cold command/DMA zero\n",o->selected.rid,o->rebar_offset,o->rebar_before,o->rebar_after,o->rebar_written,ret);
  if(ret){o->failed=true;o->status=ret;return ret;}
  o->rebar_complete=true;
 }
 return 0;
}
