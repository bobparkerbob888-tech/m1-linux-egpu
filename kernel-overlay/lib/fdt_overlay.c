#include <linux/libfdt_env.h>
#include <linux/kstrtox.h>
/* dtc emits nonnegative decimal byte offsets. Kernel simple_strtoul provides
 * the end pointer used by libfdt to reject empty/trailing-junk offsets.
 * This mapping is private to the imported implementation, not a global API.
 * The embedded J293 overlay has no external __fixups__ entries. */
#define strtoul simple_strtoul
#include "../scripts/dtc/libfdt/fdt_overlay.c"
#undef strtoul
