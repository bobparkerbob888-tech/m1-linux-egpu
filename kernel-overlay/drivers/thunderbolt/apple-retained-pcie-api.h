/* Same opaque retained ticket; companion external-retained-commit owns APIs. */
#ifndef APPLE_RETAINED_PCIE_API_H
#define APPLE_RETAINED_PCIE_API_H
struct device;
int apple_apciec_retained_prepared_audit(struct device *,unsigned int,const void *);
int apple_apciec_retained_commit(struct device *,unsigned int,const void *);
int apple_apciec_retained_scan_quarantined(struct device *,unsigned int,const void *);
int apple_apciec_retained_root_rc_prepare(struct device *,unsigned int,const void *);
int apple_apciec_retained_raw_final_audit(struct device *,unsigned int,const void *);
#endif
