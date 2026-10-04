// SPDX-License-Identifier: GPL-2.0-only

#include <linux/mm.h>
#include <linux/io.h>
#include <linux/atomic.h>
#include <linux/printk.h>

static ioremap_prot_hook_t ioremap_prot_hook;

int arm64_ioremap_prot_hook_register(ioremap_prot_hook_t hook)
{
	if (WARN_ON(ioremap_prot_hook))
		return -EBUSY;

	ioremap_prot_hook = hook;
	return 0;
}

void __iomem *__ioremap_prot(phys_addr_t phys_addr, size_t size,
			     pgprot_t pgprot)
{
	unsigned long last_addr = phys_addr + size - 1;

	/* Don't allow outside PHYS_MASK */
	if (last_addr & ~PHYS_MASK)
		return NULL;

	/* Don't allow RAM to be mapped. */
	if (WARN_ONCE(pfn_is_map_memory(__phys_to_pfn(phys_addr)),
		      "ioremap attempted on RAM pfn\n"))
		return NULL;

	/*
	 * If a hook is registered (e.g. for confidential computing
	 * purposes), call that now and barf if it fails.
	 */
	if (unlikely(ioremap_prot_hook) &&
	    WARN_ON(ioremap_prot_hook(phys_addr, size, &pgprot))) {
		return NULL;
	}

	/* Bounded observation of the port0 aperture; no access or mapping change. */
	if (phys_addr >= 0x400000000ULL && last_addr < 0x500000000ULL) {
		static atomic_t port0_map_records = ATOMIC_INIT(0);
		void __iomem *mapped;
		mapped = generic_ioremap_prot(phys_addr, size, pgprot);
		if (atomic_inc_return(&port0_map_records) <= 16)
			pr_info("native-bar-map: PA%llx size%zx prot%llx mapped%u\n",
				(unsigned long long)phys_addr, size,
				(unsigned long long)pgprot_val(pgprot), !!mapped);
		return mapped;
	}
	return generic_ioremap_prot(phys_addr, size, pgprot);
}
EXPORT_SYMBOL(__ioremap_prot);

/*
 * Must be called after early_fixmap_init
 */
void __init early_ioremap_init(void)
{
	early_ioremap_setup();
}

bool arch_memremap_can_ram_remap(resource_size_t offset, size_t size,
				 unsigned long flags)
{
	unsigned long pfn = PHYS_PFN(offset);

	return pfn_is_map_memory(pfn);
}
