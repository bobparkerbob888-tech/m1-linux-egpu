#include "apple-jpc-raw-report.h"
/* Copy only completed immutable observations; never read config or grant work. */
int apple_cio_jpc_raw_report(unsigned controller,u32*flags,int*status,struct apple_jpc_raw_report*r)
{
 typeof(jpc_provider_owner)*t=&jpc_provider_owner;struct j314s_peer_capture_owner*peer;
 if(!flags||!status||!r||controller<1||controller>2||controller!=jpc_boot_peer_controller())return -EINVAL;
 *flags=0;*status=-EINPROGRESS;memset(r,0,sizeof(*r));
 if(!mutex_trylock(&jpc_provider_action_lock))return -EAGAIN;
 if(t->failed||!jpc_raw_complete||jpc_raw_status||!jpc_provider_identity_valid()||
    !jpc_provider_sample_valid(&t->sample)||!jpc_raw_records||!jpc_raw_record_count||jpc_raw_record_count>64||
    !jpc_jct_receipt.sealed||jpc_jct_receipt.failed||jpc_jct_receipt.report.status||
    !jpc_jct_receipt.report.audits||jpc_jct_receipt.report.last_verified_ns>=t->deadline){
  *status=t->status?t->status:jpc_raw_status?jpc_raw_status:-ESTALE;goto out;
 }
 peer=j314s_peer_slot(t->a);if(!peer||!peer->lease.complete||peer->lease.failed){*status=-ESTALE;goto out;}
 r->version=1;r->controller=controller;r->count=jpc_raw_record_count;
 r->router_count=jpc_jct_receipt.report.count;r->original_deadline=t->deadline;
 r->completed_ns=jpc_jct_receipt.report.last_verified_ns;r->sample=t->sample;
 memcpy(r->root_uid,peer->root_uid,sizeof(r->root_uid));
 for(unsigned j=0;j<r->count;j++){
  const struct ep_identity*id=&jpc_raw_records[j];
  r->records[j]=(struct apple_jpc_raw_record){id->rid,id->id,id->class_rev,id->subsystem,id->header,id->serial};
 }
 *flags=31;*status=0;
 out:mutex_unlock(&jpc_provider_action_lock);return 0;
}
EXPORT_SYMBOL_GPL(apple_cio_jpc_raw_report);
