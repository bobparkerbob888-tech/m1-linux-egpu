/* Exact R31 proven branch; every new boot must reproduce these cached identities.
 * A selected BDF alone is not identity. Caller already proved enclosure/cable. */
#ifndef APPLE_ENDPOINT_ADMISSION_H
#define APPLE_ENDPOINT_ADMISSION_H
static const struct ep_identity endpoint_allowed = {
 .rid = 0x0300, .id = 0x2d0410de, .class_rev = 0x030000a1,
 .subsystem = 0x41cd1458, .serial = PROVISION_PRIVATE_ID_5, .header = 0x80
};
static bool endpoint_identity_equal(const struct ep_identity *a, const struct ep_identity *b)
{
 return a->rid == b->rid && a->id == b->id && a->class_rev == b->class_rev &&
        a->subsystem == b->subsystem && a->serial == b->serial && a->header == b->header;
}
static int endpoint_admit_records(const struct ep_identity *records, unsigned count)
{
 static const unsigned rids[] = {0, 0x100, 0x200, 0x300, 0x301, 0x208, 0x210, 0x218};
 unsigned seen = 0, j, k;
 if (!records || count != 8) return -EPERM;
 for (j = 0; j < count; j++) {
  const struct ep_identity *id = &records[j];
  for (k = 0; k < 8 && id->rid != rids[k]; k++);
  if (k == 8 || (seen & (1U << k))) return -EPERM;
  seen |= 1U << k;
  if (id->rid == endpoint_allowed.rid) {
   if (!endpoint_identity_equal(id, &endpoint_allowed)) return -EPERM;
  } else if (id->rid == 0x301) {
   if (id->id != 0x22eb10de || id->class_rev != 0x040300a1 ||
       (id->header & 0x7f)) return -EPERM;
  } else if (id->id != (id->rid ? 0x57868086 : 0x1010106b) ||
             id->class_rev != (id->rid ? 0x06040085 : 0x06040000) ||
             (id->header & 0x7f) != 1) return -EPERM;
 }
 return seen == 255 ? 0 : -EPERM;
}
#endif
