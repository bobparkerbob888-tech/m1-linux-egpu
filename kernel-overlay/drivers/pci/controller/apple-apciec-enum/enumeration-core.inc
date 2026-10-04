/* Actual PCI-core enumeration/quarantine lifecycle; local candidate only.
 * Call with lifecycle mutex held, supplier power pinned, link confirmed, all
 * RID entries invalid, and MSI masked. No pci_host_probe(): it binds drivers.
 * Before invoking this, caller must supply parsed host windows/bus range and
 * its PRIVATE bridge->sysdata. This does not initialize Apple hardware.
 */
static int apple_apciec_quarantine(struct pci_dev *dev, void *data)
{
	int ret;
	int *error = data;
	u16 command;

	ret = device_set_driver_override(&dev->dev,
					"apple-apciec-enumeration-only");
	if (ret)
		goto fail;
	pci_clear_master(dev);
	ret = pci_read_config_word(dev, PCI_COMMAND, &command);
	if (ret || (command & PCI_COMMAND_MASTER)) {
		ret = -EIO;
		goto fail;
	}
	if (dev->driver) {
		ret = -EBUSY;
		goto fail;
	}
	return 0;
 fail:
	*error = ret;
	return ret;
}

/* Split from pci_bus_add_devices so a failed quarantine never permits binding.
 * PCI core device_add occurs during scan, but pci_dev_allow_binding is deferred
 * until pci_bus_add_device. The low-level command-write filter independently
 * prohibits bus-master enable, including scan quirks and later sysfs writes.
 */
static int __maybe_unused apple_apciec_scan_quarantined(struct apple_apciec *pcie)
{
	int ret;

	if (!pcie->power_ready || !pcie->tunnel_ready || !pcie->bridge ||
	    pcie->iommu_ready || pcie->msi_domain_ready)
		return -EPERM;
	pci_lock_rescan_remove();
	ret = pci_scan_root_bus_bridge(pcie->bridge);
	if (ret) {
		pci_free_host_bridge(pcie->bridge);
		pcie->bridge = NULL;
		goto out;
	}
	pci_walk_bus(pcie->bridge->bus, apple_apciec_quarantine, &ret);
	if (ret) {
		pci_stop_root_bus(pcie->bridge->bus);
		pci_remove_root_bus(pcie->bridge->bus);
		pci_free_host_bridge(pcie->bridge);
		pcie->bridge = NULL;
		goto out;
	}
	/* No endpoint BAR assignment/enabling, no MSI domain, no DMA mappings.
	 * Root bridge and endpoints become inspectable but no matching driver exists.
	 */
	/* Intentionally do not call pci_bus_add_devices: binding remains forbidden. */
 out:
	pci_unlock_rescan_remove();
	return ret;
}

static void __maybe_unused apple_apciec_remove_quarantined(struct apple_apciec *pcie)
{
	/* Supplier must retain ECAM power until this completes. No TB work waits.
	 * Called BEFORE down/up adapter teardown, and before clearing tunnel_ready.
	 */
	pci_lock_rescan_remove();
	if (pcie->bridge && pcie->bridge->bus) {
		pci_stop_root_bus(pcie->bridge->bus);
		pci_remove_root_bus(pcie->bridge->bus);
		pci_free_host_bridge(pcie->bridge);
		pcie->bridge = NULL;
	}
	pci_unlock_rescan_remove();
}
