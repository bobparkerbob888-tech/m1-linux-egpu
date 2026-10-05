#include <linux/apple-j314s-native-report.h>
/* Immutable transition result. No I/O, no fresh permission, no expiry extension. */
int apple_apciec_j314s_native_state(struct device*dev,u32*flags,int*status,
 struct apple_j314s_native_report*report)
{
 struct apple_apciec*p=dev?dev_get_drvdata(dev):NULL;
 struct j314s_native_context*n;const struct ep_identity*id;u32 f=0;
 if(!flags||!status||!report)return -EINVAL;
 *flags=0;*status=-EINPROGRESS;memset(report,0,sizeof(*report));
 if(!p)return -ENODEV;
 if(!mutex_trylock(&p->lifecycle))return -EAGAIN;
 n=p->j314s_native;if(!n||!n->attempted)goto out;
 f|=1;*status=n->status;
 if(n->discovered)f|=2;
 if(n->mmio_complete)f|=4;
 if(p->native&&p->native->active&&p->native->dma_ready&&p->native->rid_ready)f|=8;
 if(p->native&&p->native->irq_ready)f|=16;
 if(n->sealed)f|=32;
 if(n->published)f|=64;
 if(f!=127||n->failed||n->status||n->task||p->retained_failed||
    !p->native||p->native->failed||p->retained_phase!=40||
    !j314s_native_target_identity(p)||!j314s_owner_published(p)||
    !pci_dev_is_added(j314s_native_selected(p))||!n->completed_ns||
    n->completed_ns>=p->retained_identity_deadline||
    n->deadline!=p->retained_identity_deadline)goto invalid;
 f|=128;*status=0;id=&p->j314s_resource->selected;
 report->rid=id->rid;report->id=id->id;report->class_rev=id->class_rev;
 report->subsystem=id->subsystem;report->header=id->header;report->serial=id->serial;
 report->boot0[0]=n->boot0[0];report->boot0[1]=n->boot0[1];report->phase=40;
 report->completed_ns=n->completed_ns;report->deadline=n->deadline;goto out;
invalid:if(!*status)*status=-ESTALE;
out:*flags=f;mutex_unlock(&p->lifecycle);return 0;
}
EXPORT_SYMBOL_GPL(apple_apciec_j314s_native_state);
