/* Include after raw frontend. Invoke j314s_native_continue() synchronously
 * inside the original raw continuation AFTER phase12 BARplan + PE/Hop proof,
 * BEFORE setting j314s_raw_complete; never expose a replay/late entry point. */
#include <linux/apple-j314s-native-report.h>
extern int apple_apciec_j314s_assign_resources(struct device *,unsigned,const void *,unsigned *);
extern int apple_apciec_j314s_discover(struct device *,unsigned,const void *,unsigned *);
extern int apple_apciec_j314s_probe_mmio(struct device *,unsigned,const void *,unsigned *);
extern int apple_apciec_j314s_native_prepare(struct device *,unsigned,const void *,unsigned *);
extern int apple_apciec_j314s_native_state(struct device *,u32 *,int *,struct apple_j314s_native_report *);
static bool j314s_native_continuation_consumed;
static unsigned j314s_native_continuation_phase;
static int j314s_native_continue(void)
{
 typeof(j314s_provider_owner)*t=&j314s_provider_owner;
 int ret,post;
 if(j314s_native_continuation_consumed||!j314s_raw_valid(t)||
    !j314s_raw_snapshot||!j314s_raw_snapshot->planned||
    j314s_raw_resource_phase!=12||j314s_raw_path->pe!=3||
    j314s_raw_path->programmed!=4)return -EPERM;
 j314s_native_continuation_consumed=true;
 /* Host operations run outside ACIO/TB locks, under their own lifecycle.
  * All retain the same private ticket and original global deadline. */
 ret=apple_apciec_j314s_assign_resources(t->host,3,t,&j314s_native_continuation_phase);
 if(!ret&&j314s_native_continuation_phase!=14)ret=-EPERM;
 if(!ret&&!j314s_raw_valid(t))ret=-ETIMEDOUT;
 if(!ret)ret=apple_apciec_j314s_discover(t->host,3,t,&j314s_native_continuation_phase);
 if(!ret&&j314s_native_continuation_phase!=16)ret=-EPERM;
 if(!ret&&!j314s_raw_valid(t))ret=-ETIMEDOUT;
 if(!ret)ret=apple_apciec_j314s_probe_mmio(t->host,3,t,&j314s_native_continuation_phase);
 if(!ret&&j314s_native_continuation_phase!=18)ret=-EPERM;
 if(!ret&&!j314s_raw_valid(t))ret=-ETIMEDOUT;
 if(!ret)ret=apple_apciec_j314s_native_prepare(t->host,3,t,&j314s_native_continuation_phase);
 if(!ret&&j314s_native_continuation_phase!=40)ret=-EPERM;
 mutex_lock(&t->c->lock);mutex_lock(&t->tb->lock);
 post=j314s_raw_proof(t,3);
 if(!post)post=jraw_pt_verify(j314s_raw_path);
 if(!ret)ret=post;
 mutex_unlock(&t->tb->lock);mutex_unlock(&t->c->lock);
 pr_info("j314s-native: status%d hostphase%u; one selected GPU, driver pending\n",ret,j314s_native_continuation_phase);
 return ret;
}
/* Historical owner-scoped report. No hardware access, fresh task permission,
 * deadline extension, late continuation, or interpretation of old BAR flags. */
int apple_cio_j314s_native_state(unsigned,u32 *,int *,struct apple_j314s_native_report *);
int apple_cio_j314s_native_state(unsigned controller,u32 *flags,int *status,
 struct apple_j314s_native_report *report)
{
 typeof(j314s_provider_owner)*t=&j314s_provider_owner;int ret=0;
 if(controller||!flags||!status||!report)return -EINVAL;
 *flags=0;*status=-EINPROGRESS;memset(report,0,sizeof(*report));
 if(!mutex_trylock(&j314s_provider_action_lock))return -EAGAIN;
 if(t->failed||!t->complete||t->status||!t->host||!j314s_provider_identity_valid()||
    !j314s_native_continuation_consumed||j314s_native_continuation_phase!=40)
  *status=t->failed?t->status:-EPERM;
 else ret=apple_apciec_j314s_native_state(t->host,flags,status,report);
 mutex_unlock(&j314s_provider_action_lock);return ret;
}
EXPORT_SYMBOL_GPL(apple_cio_j314s_native_state);
