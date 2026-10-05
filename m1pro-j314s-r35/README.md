# M1 Pro native Linux NVIDIA eGPU compute — R35 source review

5 October 2026. Nine GPUs on an M1 Pro MacBookPro18,3 (J314s/T6000) submitted accepted PRL shares using native Ubuntu ARM64, custom Asahi-derived Linux 7.3.0-rc1-j314s-all9-r35 with 16 KiB pages, adapted NVIDIA 615.71.09 and unmodified official KRig 1.5.6 ARM64.

The tested layout is four RTX 5060 Ti GPUs on one USB4 controller, plus one desktop RTX 5080 and four RTX 5090 Laptop GPUs on a second controller, including daisy chains. The third controller was unused. This extends the earlier M1 J293 five-GPU result; it does not turn that result into universal Apple Silicon support.

## Measured result

All nine cards submitted accepted shares: approximately **1.044 PH/s**, **33 accepted, zero rejected and zero stale**, maximum **79°C**, in a roughly 270-second mining snapshot. This is PRL algorithm throughput, not a general GPU benchmark or long-duration stability certification. Thermal cutoff and fail-closed VPN routing were active. See VERIFIED-RESULT.json.

## What is published

Actual kernel and adapted NVIDIA source overlays (including the archived BAR2 diagnostic source matched to the reused R35 core build), exact upstream references, reference kernel configuration, licenses, offline reconstruction helper and sanitized results. Private hardware identities use explicit provisioning placeholders. Machine-specific generated device-tree/guard bytes are replaced by deliberate compilation errors.

This is **reviewable source, not a ready-to-boot kernel, installer, or plug-and-play driver**. The working private binary has not been made portable by removing identifiers. The sanitized source has not been compiled or live-tested after redaction. Follow BUILD-AND-RECOVERY.txt and IDENTITY-PROVISIONING.txt for reconstruction and limits; do not replace identity checks with zeroes or disable admission checks.

## Main changes

- T6000 controller-specific power mapping, C0-first combined activation and five-enclosure peer-chain routing using 64-bit routes and actual DROM identity.
- PCIe resource assignment and GB203 resizable-BAR preparation from 32 GiB to 256 MiB before immutable capture, retaining blocked DART ownership until admission.
- Serialized NVIDIA initialization; one standard MSI vector per GPU on the five-card controller instead of eight MSI-X vectors each, avoiding exhaustion of its 32-vector pool. The four-card controller retains eight MSI-X vectors per GPU.
- Standard MSI capability validation distinguishes extended-message-data capability from enable bits.
- Bounded link readiness and read-only AER diagnostics retain fatal-error refusal; they do not reset GPUs or suppress faults.

Display output, gaming, suspend, hotplug, AMD cards, arbitrary enclosure layouts and other Mac models are unverified. Cards were attached before boot. Early boot failures may still require physical recovery. Mining accounts, credentials, VPN configuration, private firmware, miner binaries and device snapshots are not distributed.
