/* J314s collective owner audits share the host lifecycle and MSI domain.
 * Serialize whole probe bodies, not merely individual admission calls. Keep
 * kernel lock-order trylocks and exact per-client admission proofs unchanged.
 * A failed body consumes this module's target attempt before waking a peer;
 * the host notifier independently retains the failed collective owner.
 */
static DEFINE_MUTEX(nv_j314s_probe_lock);
static bool nv_j314s_probe_failed;
static struct task_struct *nv_j314s_probe_task;
static int nv_pci_probe_serialized(struct pci_dev *pdev,
                                    const struct pci_device_id *id_table)
{
    int ret;

    if (!of_machine_is_compatible("apple,j314s"))
        return nv_pci_probe_body(pdev, id_table);

    /* A recursive driver callback must refuse instead of self-deadlocking. */
    if (READ_ONCE(nv_j314s_probe_task) == current)
        return -EDEADLK;
    mutex_lock(&nv_j314s_probe_lock);
    WRITE_ONCE(nv_j314s_probe_task, current);
    if (nv_j314s_probe_failed)
        ret = -ENODEV;
    else {
        ret = nv_pci_probe_body(pdev, id_table);
        if (ret)
            nv_j314s_probe_failed = true;
    }
    WRITE_ONCE(nv_j314s_probe_task, NULL);
    mutex_unlock(&nv_j314s_probe_lock);
    return ret;
}
