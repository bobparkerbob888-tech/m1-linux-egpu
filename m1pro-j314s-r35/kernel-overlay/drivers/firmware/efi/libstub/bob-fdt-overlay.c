// SPDX-License-Identifier: GPL-2.0
#include <linux/libfdt_env.h>
#include "efistub.h"
/* libstub has no strchr implementation; both overlay and strict validator use it. */
char *strchr(const char *s, int c)
{
 do {
  if (*s == (char)c) return (char *)s;
 } while (*s++);
 return NULL;
}
/* libstub supplies simple_strtoull, not the kernel simple_strtoul symbol. */
static unsigned long bob_stub_strtoul(const char *s, char **end, int base)
{
 return (unsigned long)simple_strtoull(s, end, base);
}
#define strtoul bob_stub_strtoul
#include "../../../../scripts/dtc/libfdt/fdt_overlay.c"
#undef strtoul
