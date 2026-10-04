# Native Linux NVIDIA eGPU compute on Apple M1

Experimental source from a five-RTX-5060-Ti setup on a **2020 M1 MacBook Pro (J293)** running Ubuntu Asahi. The workload is **Pearl (PRL) mining on the Kryptex pool**, using the official ARM64 KRig 1.5.6 miner.

**This is a developer source-review release, not a one-click installer.** The working private build produced the results below. The public source has hardware identifiers and generated machine-specific headers removed; it has not been compiled or boot-tested after that redaction.

## Measured result

- Five physical NVIDIA GPUs running the unmodified official ARM64 Kryptex KRig 1.5.6 miner, with accepted Pearl (PRL) shares on every miner device.
- Approximately **440 TH/s at 575 W combined GPU telemetry**, with temperatures **70–73°C** after tuning. GPU consumption is not wall power.
- Short-run verification, not an endurance test.
- Three GPUs on one USB4 controller and two on the other, including daisy chains.

## Start here

1. Read [scope and limitations](README.txt), [build and recovery instructions](BUILD-AND-RECOVERY.txt), and [identity provisioning](IDENTITY-PROVISIONING.txt).
2. Run `python3 reconstruct.py` to verify the published source manifest (Python 3.12+).
3. Obtain the pinned upstream archives described in [UPSTREAM.json](UPSTREAM.json). The reconstruction tool applies the included source overlays offline.
4. Target-specific identity provisioning, building, and a reviewed guarded boot procedure remain necessary. Do not remove the compile-time identity guards or substitute dummy values.

## Source included

- Kernel changes for external PCIe, USB4 controller/tunnel setup, resource allocation, DART DMA mappings, and MSI handling.
- NVIDIA open-module source changes for the host’s 16 KiB pages and DMA behavior.
- Controller admission and validation code, plus corrected asynchronous readiness handling.
- Pinned upstream references, licenses, checksums, and measured-result notes.

The NVIDIA userspace version used was **615.71.09**. Proprietary firmware, userspace libraries, miners, credentials, and private machine data are not distributed here.

## Scope

Only the original J293 five-card arrangement has demonstrated the reported result. The newer M1 Pro is not supported by this release. Display output, gaming, hotplug, suspend/resume, other enclosure layouts, and other Apple Silicon models remain unverified. This is not an upstream-supported distribution release.

## Upstream and licenses

This work builds on [Asahi Linux](https://github.com/AsahiLinux/linux) and [NVIDIA’s open GPU kernel modules](https://github.com/NVIDIA/open-gpu-kernel-modules). Preserve the original copyright notices, file SPDX identifiers, and the applicable licenses in [licenses/](licenses/). No single blanket license replaces the upstream file licenses.
