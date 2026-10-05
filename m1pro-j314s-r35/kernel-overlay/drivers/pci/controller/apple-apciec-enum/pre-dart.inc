/* Only retained preparation uses these exact firmware tables. Mapping and
 * copying precede power/MMIO; all ownership survives the consumed attempt.
 * No readback assumption: native tables provide no stable-status masks.
 */
static void apple_apciec_predart_free(struct apple_apciec *pcie)
{
 unsigned int i;
 for (i = 0; i < 3; i++) {
  if (pcie->tunable_regs[i]) {
   iounmap(pcie->tunable_regs[i]);
   release_mem_region(pcie->tunable_resource[i].start, 0x4000);
   pcie->tunable_regs[i] = NULL;
  }
  kfree(pcie->tunable_tables[i].rows);
  pcie->tunable_tables[i].rows = NULL;
 }
}
static int apple_apciec_predart_load(struct platform_device *pdev,
                                   struct apple_apciec *pcie)
{
 static const char * const names[] = {
  "apple,apcie-common-tunables", "apple,apcie-debug-tunables",
  "apple,apcie-fabric-tunables"
 };
 static const unsigned int indices[] = { APCIEC_COMMON, APCIEC_DEBUG, APCIEC_FABRIC };
 struct device_node *np = pdev->dev.of_node;
 struct property *marker;
 unsigned int i, j;
 int len, ret = -EINVAL;
 marker = of_find_property(np, "research,apcie-common-absent", NULL);
 if (!marker || marker->length || of_find_property(np, names[0], NULL))
  return -EINVAL;
 for (i = 1; i < 3; i++) {
  const __be32 *data = of_get_property(np, names[i], &len);
  struct apcie_tunable_row *rows;
  unsigned int count = i == 1 ? 1 : 27;
  if (!data || len != count * 12)
   goto fail;
  rows = kcalloc(count, sizeof(*rows), GFP_KERNEL);
  if (!rows) { ret = -ENOMEM; goto fail; }
  pcie->tunable_tables[i].rows = rows;
  pcie->tunable_tables[i].count = count;
  for (j = 0; j < count; j++) {
   rows[j].offset = be32_to_cpu(data[3*j]);
   rows[j].mask = be32_to_cpu(data[3*j+1]);
   rows[j].value = be32_to_cpu(data[3*j+2]);
  }
 }
 ret = apcie_tunables_validate(pcie->tunable_tables, 1);
 if (ret)
  goto fail;
 for (i = 0; i < 3; i++) {
  struct resource *res = platform_get_resource(pdev, IORESOURCE_MEM, indices[i]);
  if (!res || !(res->flags & IORESOURCE_MEM_NONPOSTED) ||
      res->start != pcie->profile->tunable_bases[i] || resource_size(res) != 0x4000) {
   ret = -EINVAL; goto fail;
  }
  if (!pcie->tunable_tables[i].count)
   continue;
  if (!request_mem_region(res->start, 0x4000, dev_name(pcie->dev))) {
   ret = -EBUSY; goto fail;
  }
  pcie->tunable_resource[i] = *res;
  pcie->tunable_regs[i] = ioremap_np(res->start, 0x4000);
  if (!pcie->tunable_regs[i]) {
   release_mem_region(res->start, 0x4000);
   ret = -ENOMEM; goto fail;
  }
 }
 return 0;
fail:
 apple_apciec_predart_free(pcie);
 return ret;
}
struct apple_apciec_tunable_context {
 struct apple_apciec *pcie;
 unsigned int first_read_banks;
};
static unsigned int apple_apciec_tunable_read(void *context, unsigned int bank,
                                            unsigned int offset)
{
 struct apple_apciec_tunable_context *ctx = context;
 struct apple_apciec *pcie = ctx->pcie;
 unsigned int value;
 unsigned int pause = (ctx->first_read_banks & BIT(bank)) ? 1000 : 20;
 ctx->first_read_banks &= ~BIT(bank);
 dev_info(pcie->dev, "r22 pre-DART read begin bank %u offset %#x\n", bank, offset);
 msleep(pause); /* First bank marker gets time to drain the logger backlog. */
 value = readl(pcie->tunable_regs[bank] + offset);
 dev_info(pcie->dev, "r22 pre-DART read complete bank %u offset %#x value %#x\n", bank, offset, value);
 return value;
}
static void apple_apciec_tunable_write(void *context, unsigned int bank,
                                      unsigned int offset, unsigned int value)
{
 struct apple_apciec_tunable_context *ctx = context;
 struct apple_apciec *pcie = ctx->pcie;
 dev_info(pcie->dev, "r22 pre-DART write begin bank %u offset %#x value %#x\n", bank, offset, value);
 msleep(20);
 writel(value, pcie->tunable_regs[bank] + offset);
 dev_info(pcie->dev, "r22 pre-DART write issued bank %u offset %#x\n", bank, offset);
}
static int apple_apciec_predart_apply(struct apple_apciec *pcie)
{
 struct apple_apciec_tunable_context ctx = { pcie, BIT(1) | BIT(2) };
 const struct apcie_tunable_io io = { &ctx, apple_apciec_tunable_read,
                                    apple_apciec_tunable_write };
 int ret;
 lockdep_assert_held(&pcie->lifecycle);
 if (!pcie->retained || !pcie->power_ready || pcie->retained_phase != 1 ||
     pcie->predart_attempted || pcie->retained_failed)
  return -EPERM;
 pcie->predart_attempted = true;
 ret = apcie_tunables_apply(pcie->tunable_tables, 1, &io);
 if (!ret)
  dev_info(pcie->dev, "retained pre-DART native tunables applied: common absent, debug 1, fabric 27; no port enable\n");
 return ret;
}
