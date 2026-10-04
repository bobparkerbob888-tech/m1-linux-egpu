M1 J293 native Linux NVIDIA eGPU compute — public source review release
4 October 2026

Five RTX 5060 Ti GPUs, three on one USB4 controller and two on the other,
including daisy chains, initialized and submitted accepted shares on native
Ubuntu ARM64. The verified baseline used custom Asahi-derived Linux R54 with
16 KiB pages, adapted NVIDIA 615.71.09 kernel modules and unmodified official
Kryptex KRig 1.5.6 ARM64. See VERIFIED-RESULT.txt for measured evidence.

This archive contains ACTUAL source changes from the experiment, sanitized for
publication. It is not a general installer or evidence that every Apple Silicon
Mac supports eGPUs. The M1 Pro target is a separate, unfinished port. Display,
gaming, hotplug and suspend are not established by this compute result.

Contents
- kernel-overlay: complete changed/new kernel source files against pinned
  AsahiLinux/linux upstream, including PCIe host, USB4, DART and MSI work.
- nvidia-overlay: changed source against pinned official NVIDIA open modules.
- controller-and-miner-policy: hardware admission, activation and guarded
  validation source. It does not include any pool account or miner binary.
- corrected-readiness: causal asynchronous completion parser correction.
- UPSTREAM.json: exact upstream references and original archive hashes.
- reconstruct.py: offline checksum verification and source reconstruction.

Private device identities are replaced with named provisioning placeholders.
Generated machine-specific DT/guard byte arrays are withheld and replaced by
explicit #error stubs. This deliberately prevents accidental compilation into
a kernel with dummy hardware identities. See IDENTITY-PROVISIONING.txt.
All substantive host-controller/DMA/resource/MSI logic remains reviewable.
The measured mining result belongs to the original private build. This sanitized
public source has NOT been compiled or live-validated after redaction.
Do not remove the safety checks or fill identity fields with zeroes.

Nothing here changes boot settings, loads a module or starts mining. Reproduce
the source, review it and provision a target-specific policy before developing
a guarded one-shot installation. The original experiment retained stock
m1n1/U-Boot, macOS, Ubuntu and SSH fallback; it did not flash generic firmware.

No proprietary runtime, firmware, initramfs, GPU kernel binary or miner binary
is included. Obtain matching runtime/firmware/miner from their official sources
separately and follow their licenses. This release is source review material,
not an upstream-supported distribution release.
