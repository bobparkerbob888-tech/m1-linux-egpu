/* Future schema candidate only. Not integrated or hardware validated.
 * Caller must supply immutable current-boot PCI identity, not a requested ID.
 * This is a register-schema predicate, not topology/DMA/device authorization.
 */
#ifndef J314S_BOOT0_SCHEMA_H
#define J314S_BOOT0_SCHEMA_H
static unsigned j314s_boot0_implementation(unsigned id)
{
 switch (id) {
 case 0x2d0410deU: return 6; /* GB206 */
 case 0x2c0210deU: /* desktop RTX 5080: excluded until separate branch review */
 case 0x2c1810deU: return 3; /* GB203 */
 default: return 0;
 }
}
static int j314s_boot0_schema_valid(unsigned id, unsigned first, unsigned second)
{
 unsigned implementation = j314s_boot0_implementation(id);
 return implementation && first == second && first && first != 0xffffffffU &&
        ((first >> 24) & 0x1f) == 0x1b && !(first & (1U << 8)) &&
        ((first >> 20) & 0xf) == implementation;
}
#endif
