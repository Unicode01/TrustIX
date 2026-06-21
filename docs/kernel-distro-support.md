# Kernel and distro support

This file records what TrustIX can reasonably claim for the first release. The
short version is: userspace TrustIX is broadly portable across normal Linux
distributions, but kernel modules are target-kernel artifacts. There is no
universal `.ko`.

## Support tiers

| Tier | Requirements | Current status |
| --- | --- | --- |
| Userspace IX/control plane | Linux `amd64` or `arm64`, Go-built release binary, no kernel headers or BTF | Default release path. Works without `.ko`, TC/XDP, or kernel crypto. |
| Linux dataplane TC/eBPF | Linux root/CAP_NET_ADMIN, TC/eBPF/XDP support, suitable BTF or external BTF when CO-RE relocation needs it | Supported as the main Linux dataplane path with automatic fallback and diagnostics. |
| Kernel crypto, device-only | Matching kernel build tree/KDIR and loadable modules | Compatibility fallback for older kernels. Provides `/dev/trustix_crypto` batched AES-GCM; no BPF crypto kfunc provider. |
| Kernel crypto, full | Matching KDIR plus kernel/BTF support for BPF crypto kfuncs; upstream Linux 6.12+ is the intended full provider target | Builds where headers allow it, but runtime must still pass BTF/kfunc and selftest probes. Older kernels can load but may only provide device/ioctl crypto. |
| Datapath helpers, basic | Matching KDIR | Build fallback when helper kfunc/BTF support is not available. Does not provide route-GSO/kfunc fast path. |
| Datapath helpers, full | Matching KDIR plus module BTF/kfunc usability | Provides safe skb/GSO and route-TCP helper capability. Panic-risk route-TCP XMIT/async families are first-release hard-disabled unless separately validated. |
| Full plaintext datapath module | Matching KDIR; selected full-plaintext policy plus `enable_features=128 rx_worker_inject=1 tx_plaintext=1`; passing module selftests and cross-host production gate | Selected plaintext performance path for the validated Debian 6.12 and OpenWrt 5.15/6.6 x86_64 targets. Daemon defaults still keep RX worker and TX plaintext disabled unless the selected policy/runtime config requires them. Modules remain target-kernel artifacts; secure full-kernel datapath and GSO LAN TX are not complete first-release guarantees. |

## Kernel module ABI boundary

Linux kernel modules are tied to the target kernel ABI and `vermagic`. A module
built for one distro kernel or OpenWrt SDK must not be presented as a generic
artifact for another kernel. Use one of these paths:

```bash
KDIR=/lib/modules/$(uname -r)/build sudo -E bash scripts/build-release-linux.sh
TRUSTIX_KERNEL_MODULE_KDIRS=/path/to/k1/build,/path/to/k2/build bash scripts/build-kernel-modules-linux.sh
```

`scripts/trustix-build.sh --build-ko auto` only embeds `.ko` files when it is
running on Linux and a matching KDIR is available. The normal GitHub release
packages intentionally ship kernel module source/Makefiles, not generic
prebuilt `.ko` files.

With `--build-ko 1`, the build scripts first check the target KDIR and then make
a best-effort attempt to install matching headers through the host package
manager. Proxmox kernels use exact-match packages such as
`proxmox-headers-$(uname -r)` or, on older repositories,
`pve-headers-$(uname -r)`. If those packages are unavailable, the kernel and
repository are out of sync for local `.ko` builds; either install matching
headers manually, boot a kernel that has headers available, or build without
embedded `.ko` assets. Kbuild may also require `pahole` for module BTF; Debian,
Ubuntu, and Proxmox provide it through the `dwarves` package, which the scripts
now install for kernel module builds when dependency installation is enabled.

## Current validation snapshot

The latest PVE compatibility audits were run on 2026-06-19, 2026-06-20, and
2026-06-21 against current source and selected production transport defaults.
They covered Debian 13 `6.12.90+deb13.1-amd64`, OpenWrt 23.05.5 x86_64
`5.15.167`, OpenWrt 24.10.2 x86_64 `6.6.93`, and OpenWrt 24.10.7 x86_64
`6.6.141` guests with disposable PVE VM IDs 200+.
The OpenWrt SDK compile matrix defaults were refreshed on 2026-06-21 to cover
the current stable patch releases `23.05.6`, `24.10.7`, and `25.12.4`.
OpenWrt 24.10.7 x86_64 has since passed an SDK module build and a 900s
OpenWrt-to-Debian full-kmod production gate. OpenWrt 24.10.7 route-GSO and
secure-kUDP route-GSO both failed closed at the runtime capability gate because
the tested image did not expose usable route-TCP kfunc capability.

Generic Linux Kbuild on Ubuntu 22.04.5:

| Header/KDIR | Kernel ABI | `trustix_crypto` | `trustix_datapath` | `trustix_datapath_helpers` |
| --- | --- | --- | --- | --- |
| `/lib/modules/5.15.0-179-generic/build` | `5.15.0-179-generic` | pass, `device-only` | pass, `full` | pass, `basic` |
| `/lib/modules/5.15.0-181-generic/build` | `5.15.0-181-generic` | pass, `device-only` | pass, `full` | pass, `basic` |
| `/lib/modules/6.1.0-1036-oem/build` | `6.1.0-1036-oem` | pass, `device-only` | pass, `full` | pass, `basic` |
| `/lib/modules/6.8.0-124-generic/build` | `6.8.0-124-generic` | pass, `full` | pass, `full` | pass, `full` |

Runtime smoke on Ubuntu `6.8.0-124-generic`:

| Module | Result | Notes |
| --- | --- | --- |
| `trustix_crypto` | pass | `/dev/trustix_crypto` ioctl batch/session/prepared-pool tests passed. BPF crypto kfunc tests skipped correctly because this kernel BTF lacks `bpf_crypto_*`. |
| `trustix_datapath_helpers` | pass | Full helper loaded, selftests passed, `gso_skb` active, route-TCP XMIT worker stayed disabled. |
| `trustix_datapath` | pass | Loaded with full plaintext feature gate; `features=128 safe=128 unsafe=0`; panic-risk parameters forced disabled. |

PVE A/B full datapath retest on 2026-06-10 used VM101/VM102 on Ubuntu
`6.8.0-124-generic` with current rebuilt modules and real TCP traffic over the
PVE underlay pair. The no-outer route-GSO baseline, RX-worker queue-skb,
coalesced-GSO full-checksum, hold-skb/pair-coalesce, receive/batchqueue, stolen
xmit compatibility, and selected p8/8s high-risk cases all completed without a
VM reboot, kernel panic, Oops, watchdog, or pstore record. A longer p8/30s
high-risk soak then reproduced a VM101/A reboot in
`build/pve/pve-datapath-risk-p8-30s-20260610.json` while VM102/B stayed up; no
pstore record or previous-boot kernel stack was captured. At that point the
full plaintext datapath was not a production claim; the later 2026-06-19 matrix
below is the updated production-gate evidence for the selected safe profile.

Follow-up PVE multitransport isolation narrowed the earlier hard reboot to the
full datapath RX_STAGE hook attachment, not module load by itself. Runs with all
TrustIX modules disabled, helper-only modules, and `trustix_datapath` loaded
with `kernel_modules.datapath.rx_stage: disabled` stayed up. A datapath-only run
with the daemon's previous default RX_STAGE hook reproduced a reboot. The daemon
therefore defaults RX_STAGE/RX_WORKER hook attachment off; explicit
`kernel_modules.datapath.rx_stage: stage|worker` or the matching environment
override is required unless a selected production policy enables the full
plaintext datapath. TC/eBPF plus `trustix_datapath_helpers` remains the selected
secure performance path.

The 2026-06-19 selected cross-host matrix passed these 900s gates on Debian to
Debian:

| Family | Policy | Minimum received | Gate |
| --- | --- | ---: | ---: |
| Full-kmod plaintext | `udp` / `plaintext` / `performance` / `kernel_module` / `userspace` | 3.566969 Gbps | 3 Gbps |
| Secure kernel UDP | `kernel_udp` / `secure` / `performance` / `tc_xdp` / `kernel` | 1.744620 Gbps | 1.5 Gbps |
| Route-GSO fallback | `experimental_tcp` / `plaintext` / `performance` / `kernel_module` / `userspace` | 2.696084 Gbps | 2.5 Gbps |

A 2026-06-21 current-head Debian-to-Debian full-kmod recheck on
`6.12.90+deb13.1-amd64` also passed the 900s production gate. It used commit
`5155854d5077af628c776d586d5b735e4447b123`, minimum received throughput was
3.550158 Gbps against the 3 Gbps gate, the full plaintext datapath provider and
RX worker were active on both peers, plaintext outer-GSO, cached destination
MAC, and RX-worker GSO xmit counters were nonzero, covered RX/TX/module error
counters were zero, and the production verifier reported no kernel log crash
findings.

A 2026-06-21 current-head Debian-to-Debian TC-direct recheck on
`6.12.90+deb13.1-amd64` also passed the 900s production gate. It used commit
`a3805571d930`, minimum received throughput was 3.915829 Gbps against the
3 Gbps gate, both peers reported `kernel_udp.provider=tc_direct`,
`kernel_udp.fast_path=true`, `kernel_udp.direct_only=true`, and eight active
kernel UDP flows, no TrustIX kernel modules were loaded, and the production
verifier reported no kernel log crash findings.

A 2026-06-21 current-head Debian-to-Debian route-GSO recheck on
`6.12.90+deb13.1-amd64` also passed the 900s production gate. It used commit
`2366d99167457bf18de7e98a5d5e6e9af3fa55b2`, minimum received throughput was
2.653735 Gbps against the 2.5 Gbps gate, route-GSO outer-GSO and xmit counters
were nonzero on both peers, the covered helper error counters were zero, and
the production verifier reported no kernel log crash findings.

A 2026-06-21 current-head Debian-to-Debian secure-kUDP recheck on
`6.12.90+deb13.1-amd64` also passed the 900s production gate. It used commit
`ad28f0cc80205f119e32a6bc3fe4958ec144b7c1`, minimum received throughput was
1.613567 Gbps against the 1.5 Gbps gate, TC secure direct and route-GSO kfunc
stats were active on both peers, crypto module seal/open counters were
nonzero, helper route-GSO xmit counters were nonzero, and the production
verifier reported no kernel log crash findings. The run did observe two
bounded direct-kfunc/decrypt errors on one peer and bounded replay/drop noise,
both within the secure-kUDP production gate budget.

A 2026-06-21 current-head Debian-to-Debian userspace recheck on
`6.12.90+deb13.1-amd64` passed every current 900s cross-host userspace
production default with no TrustIX kernel modules loaded. It used commit
`a260eb71dcef`; minimum received throughput was 1.918875 Gbps for secure UDP,
2.158972 Gbps for plaintext UDP, 0.851568 Gbps for secure TCP, 1.283958 Gbps
for plaintext TCP, 0.977368 Gbps for secure QUIC, 1.405338 Gbps for plaintext
QUIC, 0.796914 Gbps for secure WebSocket, 1.248432 Gbps for plaintext
WebSocket, 0.879747 Gbps for secure HTTP CONNECT, 1.353923 Gbps for plaintext
HTTP CONNECT, and 1.550296 Gbps for secure experimental TCP. The verifier
reported no log findings, no errors, and zero session dial or heartbeat
failures.

A 2026-06-21 current-head Debian-to-Debian userspace-TC tunnel recheck on
`6.12.90+deb13.1-cloud-amd64` passed every current 900s cross-host
GRE/IPIP/VXLAN secure and plaintext production default with no TrustIX kernel
modules loaded. It used commit `51e6831bf50d`; minimum received throughput was
1.224643 Gbps for secure GRE, 4.012349 Gbps for plaintext GRE, 1.178779 Gbps
for secure IPIP, 4.523007 Gbps for plaintext IPIP, 1.050624 Gbps for secure
VXLAN, and 4.696775 Gbps for plaintext VXLAN. The verifier reported no log
findings, no errors, and zero session dial or heartbeat failures.

The same audit passed OpenWrt-to-Debian full-kmod plaintext for 900s with a
minimum received throughput of 3.495550 Gbps against a 3 Gbps gate. Final boot
ID checks were stable and kernel log scans found no panic, Oops, BUG, call
trace, page fault, watchdog, lockup, hung-task, or `tx_queue_len` signature.

The 2026-06-20 OpenWrt 24.10.2 follow-up used VM202 OpenWrt x86_64 kernel
`6.6.93` and VM200 Debian 13 `6.12.90+deb13.1-cloud-amd64` on an isolated
PVE `vmbr3` underlay. The OpenWrt 24.10.2 SDK build passed with
`crypto=full,datapath=full,helpers=full`; the datapath module SHA256 was
`09339f3e18f0f536908736fb08cd6f91728ff8c6dcfd2b8d9cd1cfd7677fbe10`.
The 900s bidirectional full-kmod production gate passed with minimum received
throughput of 3.435125 Gbps against a 3 Gbps gate. The gate required matching
binary identity, full plaintext provider status, RX worker injection, eight
session records/wires, nonzero GSO/cached-destination counters, and zero
covered RX/TX/module error counters. Kernel log scans on both guests found no
panic, Oops, BUG, call trace, page fault, watchdog, lockup, hung-task, or
`tx_queue_len` signature.

The same OpenWrt 24.10.2 guest was then checked for the route-TCP kfunc paths
used by secure-kUDP route-GSO and experimental TCP route-GSO. OpenWrt had no
`/sys/kernel/btf/vmlinux`, while the paired Debian guest exposed kernel and
module BTF. The SDK-built `trustix_datapath_helpers.ko` loaded on OpenWrt, but
runtime capability detection reported no safe route-TCP kfunc features. Both
OpenWrt-to-Debian secure-kUDP route-GSO and experimental TCP route-GSO failed
closed before traffic with missing `route_tcp_kfunc` and
`route_tcp_xmit_kfunc`. Do not promote OpenWrt 24.10.2 secure-kUDP route-GSO or
OpenWrt route-GSO defaults until an OpenWrt kernel with usable BTF/kfunc support
passes the runtime route-TCP gate. The selected OpenWrt 24.10.2 production
kernel path remains UDP plaintext full-kmod.

The 2026-06-21 OpenWrt 24.10.7 follow-up used VM201 OpenWrt x86_64 kernel
`6.6.141` and VM200 Debian 13 `6.12.90+deb13.1-cloud-amd64` on the same PVE
host with isolated `vmbr3`. The OpenWrt 24.10.7 SDK build passed with
`crypto=full,datapath=full,helpers=full`; the OpenWrt module SHA256 values
were `f8be71eddc0bc09f38b0499a7dba81cfffb9a9e47f202e595358778aea2e2b88`
for `trustix_crypto.ko`,
`005fee841ca6cb82b030bd31abac799f9e9dbd7ce7d2b5ceda340612c0c91fce` for
`trustix_datapath.ko`, and
`450e91c29b8d825788bf58291582a967a39b6eaa590d6b33eb39c8adcf12e773` for
`trustix_datapath_helpers.ko`.
The 900s bidirectional full-kmod production gate passed with minimum received
throughput of 3.276205 Gbps against a 3 Gbps gate. The gate required matching
binary and build identity, full plaintext provider status, RX worker injection,
eight session records/wires, nonzero GSO/cached-destination counters, and zero
covered RX/TX/module error counters. Kernel log scans on both guests found no
panic, Oops, BUG, call trace, page fault, watchdog, lockup, hung-task,
`tx_queue_len`, or TrustIX datapath crash signature. The same guest still had
no `/sys/kernel/btf/vmlinux`, and both secure-kUDP route-GSO and experimental
TCP route-GSO failed closed before traffic with missing `route_tcp_kfunc` and
`route_tcp_xmit_kfunc`. The selected OpenWrt production kernel path therefore
remains UDP plaintext full-kmod with exact-version runtime evidence.

OpenWrt SDK compile spot check for `kernel/trustix_datapath`:

| OpenWrt target | Kernel | Result |
| --- | --- | --- |
| `21.02.7 x86/64` | `5.4.238` | pass |
| `23.05.5 x86/64` | `5.15.167` | pass |
| `24.10.2 x86/64` | `6.6.93` | pass |
| `24.10.7 x86/64` | `6.6.141` | pass |
| `23.05.5 armsr/armv8` | `5.15.167` | pass |

Older performance-log runs also covered a wider OpenWrt compile matrix, but the
table above is the current-source spot check. Runtime full-kmod coverage now
includes OpenWrt 23.05.5, 24.10.2, and 24.10.7 x86_64 with matching SDK-built
modules. OpenWrt 24.10.7 also has route-GSO fail-closed coverage, but no
OpenWrt route-GSO production default is selected until a tested OpenWrt kernel
exposes usable route-TCP kfunc capability.

OpenWrt `23.05.5 x86_64` runtime status was promoted after a cross-host PVE
stress run on 2026-06-16. OpenWrt kernel `5.15.167` loaded an OpenWrt SDK-built
`trustix_datapath.ko` and passed OpenWrt-to-Debian full plaintext traffic at
12.15 / 7.28 Gbps for 120s, then 14.038 / 4.676 Gbps for a 900s mixed soak.
The verifier required build/binary identity and the full plaintext provider
stat, and captured no panic, Oops, watchdog, lockup, RX-worker drops, or
plaintext TX xmit errors. This result applies to matching SDK-built OpenWrt
modules only. OpenWrt 23.05.5 has no `/sys/kernel/btf/vmlinux`, so TC/eBPF
CO-RE is not the primary OpenWrt performance path for that release.

Follow-up PVE OpenWrt-to-Debian route-GSO probes on 2026-06-20 used OpenWrt
23.05.5 x86_64 kernel `5.15.167` and Debian 13
`6.12.90+deb13.1-cloud-amd64`. The OpenWrt SDK build produced device-only
crypto, full plaintext datapath, and basic datapath helpers. The helper module
loaded and passed selftests, but it did not provide
`route_tcp_kfunc`/`route_tcp_xmit_kfunc`. Both secure-kUDP route-GSO and
experimental TCP route-GSO failed closed before traffic with the expected
missing-capability diagnostic. Do not select OpenWrt 23.05.5, 24.10.2, or
24.10.7 route-GSO or secure-kUDP route-GSO as production defaults; use the
validated UDP plaintext full-kmod path until a newer OpenWrt kernel/helper
combination passes the runtime route-TCP kfunc gate.

OpenWrt deployment is fail-closed for module ABI. Do not use release-embedded
Debian/PVE `.ko` payloads on OpenWrt. Build the module with the matching
OpenWrt SDK, copy it to `/etc/trustix/modules/trustix_datapath.ko`, and point
`kernel_modules.trustix_datapath.path` there. Auto-mode embedded modules are
disabled on OpenWrt, and required OpenWrt modules with an embedded or empty path
are rejected unless `TRUSTIX_KERNEL_MODULE_ALLOW_OPENWRT_EMBEDDED=1` is set as
an explicit ABI override.

## Distribution notes

Systemd-based distributions such as Debian, Ubuntu, and Proxmox guests are the
best-supported deployment target for the current scripts. `trustix-deploy.sh`,
`trustix-update.sh`, and `install-systemd-linux.sh` install systemd units and
restart `trustixd@*.service` instances.

OpenWrt and soft-router systems should prefer release tarballs plus target-side
module builds using the OpenWrt SDK or matching KDIR. The deployment scripts
install an OpenWrt `/etc/init.d` service. BTF may still be missing or helper
kfuncs may be unavailable on a given release; in that case TrustIX should fall
back to userspace/device/basic-helper capabilities instead of pretending full
kfunc offload is available.

Non-Linux hosts are not dataplane targets. The non-Linux code paths report TC/XDP
and kernel module lifecycle as unsupported; use them only for development of
userspace/control-plane pieces.

## Compatibility commands

Generic Linux module matrix:

```bash
TRUSTIX_CRYPTO_BUILD_MODE=auto \
TRUSTIX_DATAPATH_HELPERS_BUILD_MODE=auto \
TRUSTIX_KERNEL_MODULE_KDIRS=/path/to/k1/build,/path/to/k2/build \
bash scripts/build-kernel-modules-linux.sh
```

OpenWrt datapath module matrix:

```bash
bash scripts/openwrt-full-datapath-kmod-matrix.sh
```

The OpenWrt script validates SDK archive integrity before reuse and requires GNU
awk, which is an OpenWrt SDK prerequisite. Use `TRUSTIX_OPENWRT_KMOD_MATRIX` to
run a narrower target list during development.
