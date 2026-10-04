/* SPDX-License-Identifier: GPL-2.0 */
#ifndef APPLE_ENDPOINT_APERTURE_H
#define APPLE_ENDPOINT_APERTURE_H
/* Parent bus remains the existing 2/2 identity map for its physical DART child.
 * BAR apertures are a separate, freshly ADT-authenticated private descriptor. */
static int apple_endpoint_aperture_cell(struct device_node *np, const char *name, u32 expected)
{
 const struct property *prop = of_find_property(np, name, NULL);
 if (!prop || !prop->value || prop->length != sizeof(__be32) ||
     be32_to_cpup(prop->value) != expected) return -EPERM;
 return 0;
}
static int apple_endpoint_apertures(struct device_node *np)
{
 static const u32 expected[3][7] = {
  {0x43000000, 4, 0, 4, 0, 0, 0x80000000},
  {0x02000000, 0, 0x80000000, 4, 0x80000000, 0, 0x40000000},
  {0x42000000, 0, 0xc0000000, 4, 0xc0000000, 0, 0x40000000},
 };
 const struct property *prop;
 struct device_node *expected_np; bool exact;
 const __be32 *cells; unsigned row, col;
 expected_np = of_find_node_by_path("/soc/apciec@3b0000000");
 exact = expected_np && np == expected_np;
 of_node_put(expected_np); /* Temporary lookup only; owner already retains np. */
 if (!exact ||
     of_find_property(np, "device_type", NULL) ||
     apple_endpoint_aperture_cell(np, "#address-cells", 2) || apple_endpoint_aperture_cell(np, "#size-cells", 2))
  return -EPERM;
 prop = of_find_property(np, "ranges", NULL);
 if (!prop || prop->length != 0) return -EPERM;
 prop = of_find_property(np, "research,apciec-bar-windows", NULL);
 if (!prop || !prop->value || prop->length != sizeof(expected)) return -EPERM;
 cells = prop->value;
 for (row = 0; row < 3; row++) for (col = 0; col < 7; col++)
  if (be32_to_cpup(cells + 7*row + col) != expected[row][col]) return -EPERM;
 return 0;
}

#endif
