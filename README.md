# Native Linux NVIDIA eGPU compute on Apple M1 and M1 Pro

Experimental Asahi-based source from two working native ARM64 CUDA compute setups. The workload is Pearl (PRL) mining using the unmodified official ARM64 Kryptex KRig 1.5.6 miner and NVIDIA 615.71.09.

## Latest: M1 Pro, nine mixed NVIDIA GPUs

The **MacBookPro18,3 / J314s / T6000** port reached accepted shares on **all nine GPUs**: four RTX 5060 Ti cards on one USB4 controller, plus a desktop RTX 5080 and four RTX 5090 Laptop GPU cards on a second controller.

- Approximately **1.044 PH/s** combined PRL hashrate.
- **33 accepted, zero rejected, zero stale** shares at verification; every card accepted shares.
- **60–79°C** and approximately **1,258 W combined GPU telemetry**, not wall power.
- Custom Asahi-derived Linux **7.3.0-rc1 R35**, native 16 KiB pages, no VM.
- Short-run verification, not an endurance test or a general CUDA/AI benchmark.

Read the [M1 Pro source and build notes](m1pro-j314s-r35/README.md), [sanitized verification result](m1pro-j314s-r35/VERIFIED-RESULT.json), and [downloadable source release](https://github.com/bobparkerbob888-tech/m1-linux-egpu/releases/tag/j314s-r35-20261005).

The port includes T6000 controller/power mapping, mixed-chain resource handling, GB203 BAR sizing, serialized NVIDIA initialization and interrupt allocation changes. The five-card controller uses one standard MSI vector per GPU; the four-card controller retains eight MSI-X vectors per GPU.

## Earlier: base M1, five RTX 5060 Ti GPUs

The original **MacBookPro17,1 / J293** setup ran five RTX 5060 Ti cards in three-card and two-card chains. Its tuned snapshot reached approximately **440 TH/s at 575 W GPU telemetry**, with temperatures **70–73°C** and accepted shares from every miner device.

The files at the repository root retain that historical J293 release: [scope](README.txt), [build and recovery](BUILD-AND-RECOVERY.txt), [identity provisioning](IDENTITY-PROVISIONING.txt), and [measured result](VERIFIED-RESULT.txt). The newer M1 Pro port has its own subtree; do not apply the J293 instructions to J314s.

## What this release is

This is developer source-review material. The original private builds produced the measured results. Published source has private hardware identifiers removed and generated machine-specific headers withheld behind explicit compile-time guards. The sanitized source has **not** been compiled or boot-tested after redaction.

There is no generic ready-to-boot image or one-click installer. Target-specific hardware provisioning, review, building and guarded boot validation remain necessary. Do not remove safety checks or use dummy identity values.

Automatic detection across arbitrary GPU/enclosure arrangements is a development goal, not a released capability. Display output, gaming, hotplug, suspend/resume, other Mac models and arbitrary GPU support are unverified.

## Source, provenance and licenses

Both packages contain kernel source overlays, NVIDIA open-module changes, checksums and pinned upstream references. Follow the reconstruction instructions in the selected package. Proprietary NVIDIA userspace/firmware, miner binaries, credentials and private hardware records are not distributed.

This work builds on [Asahi Linux](https://github.com/AsahiLinux/linux) and [NVIDIA's open GPU kernel modules](https://github.com/NVIDIA/open-gpu-kernel-modules). Preserve original copyright notices, SPDX identifiers and the applicable licenses in each package. This is not an upstream-supported distribution release.
