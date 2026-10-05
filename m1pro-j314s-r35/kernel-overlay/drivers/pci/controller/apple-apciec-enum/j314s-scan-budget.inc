/* Metadata only: callers retain their existing config/owner/phase gates.
 * Zero-initialized legacy owners retain 8192. A malformed consumed multi
 * receipt denies operations instead of falling back to the legacy allowance. */
static unsigned retained_scan_limit(struct apple_apciec *p)
{
 unsigned limit;
 if(p->j314s_mixed_policy)return jmx_capture_budget(p);
 if (!p->j314s_scan_expected && !p->j314s_scan_limit &&
     !p->j314s_scan_ticket && !p->j314s_scan_actor &&
     !p->j314s_scan_original_deadline) return 8192;
 limit = p->j314s_scan_expected == 2 ? 32768 :
         p->j314s_scan_expected == 4 ? 65536 : 0;
 if (!limit || p->j314s_scan_limit != limit ||
     !apciec_profile_j314s(p->profile) || p->profile->index ||
     !p->j314s_raw_capability || !p->retained_raw_identity ||
     !p->j314s_scan_ticket || p->j314s_scan_ticket != p->retained_ticket ||
     p->j314s_scan_actor != current ||
     !p->j314s_scan_original_deadline ||
     p->j314s_scan_original_deadline != p->retained_identity_deadline ||
     p->j314s_scan_original_deadline != p->j314s_provider_deadline ||
     p->retained_scan_deadline != p->j314s_scan_original_deadline)
  return 0;
 return limit;
}
static bool retained_scan_reserve(struct apple_apciec *p, unsigned operations)
{
 unsigned limit = retained_scan_limit(p);
 return limit && operations <= limit && p->retained_scan_ops <= limit - operations;
}
/* Called only after exact chain_owner_validate and phase8 admission, with
 * lifecycle held. Failure consumes no new allowance; success cannot rearm. */
static int j314s_scan_budget_freeze(struct apple_apciec *p, const void *ticket,
                                   unsigned expected)
{
 if ((expected != 2 && expected != 4) ||
     !apciec_profile_j314s(p->profile) || p->profile->index ||
     !p->j314s_raw_capability || !p->retained_raw_identity ||
     !ticket || ticket != p->retained_ticket || p->retained_phase != 8 ||
     p->retained_failed || p->retained_scan_task || p->retained_scan_ops ||
     p->retained_record_count || p->retained_scan_exhausted ||
     p->j314s_scan_expected || p->j314s_scan_limit || p->j314s_scan_ticket ||
     p->j314s_scan_actor || p->j314s_scan_original_deadline ||
     !p->retained_identity_deadline ||
     p->retained_identity_deadline != p->j314s_provider_deadline ||
     ktime_get_boottime_ns() >= p->retained_identity_deadline)
  return -EPERM;
 p->j314s_scan_expected = expected;
 p->j314s_scan_limit = expected == 2 ? 32768 : 65536;
 p->j314s_scan_ticket = ticket;
 p->j314s_scan_actor = current;
 p->j314s_scan_original_deadline = p->retained_identity_deadline;
 p->retained_scan_deadline = p->retained_identity_deadline;
 return 0;
}
