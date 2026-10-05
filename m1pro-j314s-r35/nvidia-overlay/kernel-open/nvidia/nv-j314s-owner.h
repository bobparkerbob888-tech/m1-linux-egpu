/* J314s retained owner proof; missing/rejected exports never fall back. */
#include <linux/of.h>
#include <linux/module.h>
extern int apple_apciec_j314s_native_admit(struct pci_dev *);
extern int apple_apciec_j314s_native_irq_admit(struct pci_dev *);
static int nv_j314s_owner_admit(struct pci_dev *pdev, bool irq)
{
    int (*admit)(struct pci_dev *);
    int ret;
    if (!of_machine_is_compatible("apple,j314s"))
        return 0;
    if (!pdev)
        return -ENODEV;
    if (irq) {
        admit = symbol_get(apple_apciec_j314s_native_irq_admit);
        if (!admit)
            return -EOPNOTSUPP;
        ret = admit(pdev);
        symbol_put(apple_apciec_j314s_native_irq_admit);
    } else {
        admit = symbol_get(apple_apciec_j314s_native_admit);
        if (!admit)
            return -EOPNOTSUPP;
        ret = admit(pdev);
        symbol_put(apple_apciec_j314s_native_admit);
    }
    return ret;
}

/* Initial mode only: 1 is standard MSI; 8 preserves ordinary C0 MSI-X. */
extern int apple_apciec_j314s_native_irq_limit(struct pci_dev *);
static inline int nv_j314s_irq_mode(struct pci_dev *pdev)
{
    int (*mode)(struct pci_dev *);
    int ret;
    if (!of_machine_is_compatible("apple,j314s"))
        return 0;
    if (!pdev)
        return -ENODEV;
    mode = symbol_get(apple_apciec_j314s_native_irq_limit);
    if (!mode)
        return -EOPNOTSUPP;
    ret = mode(pdev);
    symbol_put(apple_apciec_j314s_native_irq_limit);
    if (ret < 0)
        return ret;
    if ((ret == 1 && pdev->msi_cap) || (ret == 8 && pdev->msix_cap))
        return ret;
    return -EPERM;
}
