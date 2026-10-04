/* SPDX-License-Identifier: GPL-2.0 */
/* Allocation-free shared EFI/host core; never accesses controller hardware. */
#include "bob_j293_validate.h"

static int bob_efi_requested(const char *cmdline)
{
 const char *p = cmdline ? cmdline : "";
 unsigned int count = 0;
 int external_dtb = 0;
 size_t n;
 while (*p) {
  while (*p == ' ' || *p == '\t') p++;
  for (n = 0; p[n] && p[n] != ' ' && p[n] != '\t'; n++) { }
  if (!n) break;
  if (!strncmp(p, "dtb=", 4)) external_dtb = 1;
  if (!strncmp(p, "bob_j293_overlay=", 17)) {
   if (n != sizeof("bob_j293_overlay=efi-disabled-r52") - 1 ||
       strncmp(p, "bob_j293_overlay=efi-disabled-r52", n)) return -1;
   count++;
  }
  p += n;
 }
 if (count > 1 || (count && external_dtb)) return -1;
 return count;
}

/* fdt is the caller's freshly opened EFI destination, capacity >= BOB_LIMIT.
 * scratch belongs to caller. A failed destination must never reach kernel. */
static int bob_efi_merge(const void *original, unsigned long original_size,
                        void *fdt, unsigned long capacity,
                        void *scratch, unsigned long scratch_size)
{
 int ret, chosen, len;
 if (!original || original_size < sizeof(struct fdt_header) ||
     original_size > BOB_LIMIT || capacity < BOB_LIMIT ||
     capacity > 2U * BOB_LIMIT || !scratch || scratch_size != sizeof(bob_overlay))
  return -1;
 ret = bob_bounds(original, original_size);
 if (ret) return ret;
 ret = bob_guards_check(original);
 if (ret) return ret;
 chosen = bob_exact_path(original, "/chosen");
 if (chosen < 0 || fdt_getprop(original, chosen, "bob,j293-efi-overlay", &len) ||
     len != -FDT_ERR_NOTFOUND) return -2;
 /* Restrict merge to reviewed 1MiB bound even though EFI owns2MiB. */
 ret = fdt_open_into(original, fdt, BOB_LIMIT);
 if (ret) return ret;
 memcpy(scratch, bob_overlay, sizeof(bob_overlay));
 ret = bob_bounds(scratch, sizeof(bob_overlay));
 if (ret) return ret;
 ret = fdt_overlay_apply(fdt, scratch);
 if (ret) return ret;
 ret = fdt_pack(fdt);
 if (ret) return ret;
 ret = bob_bounds(fdt, BOB_LIMIT);
 if (ret) return ret;
 ret = bob_preserved(original, fdt);
 if (ret) return ret;
 /* Standard EFI chosen edits still need spare space after packing. */
 ret = fdt_open_into(fdt, fdt, capacity);
 if (ret) return ret;
 chosen = bob_exact_path(fdt, "/chosen");
 if (chosen < 0) return chosen;
 return fdt_setprop_string(fdt, chosen, "bob,j293-efi-overlay", "disabled-r52");
}
