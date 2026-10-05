/* Include after real endpoint-resource-core/j314s-endpoint-plan and jmx-schema.
 * This only admits a completed capture; existing safe BAR sizing operations,
 * zero-command controls and exact retained owner gates remain mandatory. */
static int jmx_capture_schema(const struct jmx_policy *policy,unsigned client,
 const struct ep_snapshot *snapshot,const struct ep_identity *raw)
{
 struct jm_identity identity;
 if(!raw)return 0;
 identity=(struct jm_identity){raw->rid,raw->id,raw->class_rev,raw->subsystem,raw->header,raw->serial};
 return jmx_identity(policy,client,&identity)&&
        j314s_ep_schema_limit(snapshot,raw,16);
}
/* Called before any sizing write, with raw records frozen by the controller's
 * actual provider owner. No policy is minted from a requested product ID. */
static int jmx_raw_selection(const struct jmx_policy *policy,
 const struct ep_identity *raw,unsigned count,unsigned selected[JM_MAX_GPUS])
{
 struct jm_identity identity;unsigned j,g,found[JM_MAX_GPUS]={0},out[JM_MAX_GPUS]={0},displays=0;
 if(!jmx_policy_valid(policy)||!raw||!selected||!count||count>JM_MAX_RECORDS)return -EINVAL;
 for(j=0;j<count;j++){
  if((raw[j].class_rev>>24)!=3)continue;
  identity=(struct jm_identity){raw[j].rid,raw[j].id,raw[j].class_rev,
    raw[j].subsystem,raw[j].header,raw[j].serial};
  for(g=0;g<policy->count;g++)if(jmx_identity(policy,g,&identity))break;
  if(g==policy->count||found[g]++)return -EPERM;
  out[g]=j;displays++;
 }
 if(displays!=policy->count)return -EPERM;
 for(g=0;g<policy->count;g++){if(!found[g])return -EPERM;selected[g]=out[g];}
 return 0;
}
