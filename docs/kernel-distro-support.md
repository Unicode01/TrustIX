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

The latest PVE compatibility audits were run on 2026-06-19, 2026-06-20,
2026-06-21, 2026-06-22, 2026-06-23, 2026-06-24, and 2026-06-25 against current
source and selected production transport defaults. They covered Debian 13
`6.12.90+deb13.1-amd64`, Debian 13 `6.12.90+deb13.1-cloud-amd64`, Debian 13
`6.12.94+deb13-cloud-amd64`, Debian 13 `6.12.94+deb13-amd64`, OpenWrt 23.05.5 x86_64 `5.15.167`,
OpenWrt 24.10.2 x86_64 `6.6.93`, OpenWrt 24.10.7 x86_64 `6.6.141`,
and OpenWrt 25.12.4 x86_64 `6.12.87`
guests with disposable PVE VM IDs 200+.
The OpenWrt SDK compile matrix defaults were refreshed on 2026-06-21 to cover
the current stable patch releases `23.05.6`, `24.10.7`, and `25.12.4`.
OpenWrt 24.10.7 x86_64 has since passed an SDK module build and 3600s
OpenWrt-to-Debian full-kmod production gates, most recently on 2026-06-25
against Debian `6.12.94+deb13-cloud-amd64` at commit `395b2ba05013`.
OpenWrt 24.10.7 route-GSO, secure-kUDP route-GSO, and secure experimental TCP
kernel crypto all failed closed at the runtime capability gate because the
tested image did not expose usable route-TCP kfunc capability. OpenWrt 25.12.4
x86_64 SDK modules also built in forced full mode, but the official runtime
image used APK package feeds, did not expose `/sys/kernel/btf/vmlinux`, and
route-GSO, secure-kUDP route-GSO, plus secure experimental TCP kernel crypto
failed closed with missing `route_tcp_kfunc` and `route_tcp_xmit_kfunc`.

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

The 2026-06-19 selected cross-host matrix first promoted these Debian-to-Debian
safe-profile gates, and later 3600s manifest-backed rechecks now provide the
current production evidence boundary:

| Family | Policy | Current minimum received | Gate | Evidence |
| --- | --- | ---: | ---: | --- |
| Full-kmod plaintext | `udp` / `plaintext` / `performance` / `kernel_module` / `userspace` | 3.518886 Gbps | 3 Gbps | 3600s per direction on Debian `6.12.90+deb13.1-cloud-amd64`, 2026-06-25 |
| Secure kernel UDP | `kernel_udp` / `secure` / `performance` / `tc_xdp` / `kernel` | 1.634107 Gbps | 1.5 Gbps | 3600s per direction on Debian `6.12.94+deb13-cloud-amd64`, 2026-06-22 |
| Plaintext experimental TCP route-GSO | `experimental_tcp` / `plaintext` / `performance` / `kernel_module` / `userspace` | 2.829761 Gbps | 2.5 Gbps | 3600s per direction on Debian `6.12.94+deb13-cloud-amd64`, 2026-06-22 |
| Secure experimental TCP kernel crypto | `experimental_tcp` / `secure` / `performance` / `kernel_module` / `kernel` | 1.599325 Gbps | 1.5 Gbps | 3600s per direction on Debian `6.12.90+deb13.1-cloud-amd64`, 2026-06-25 |

A 2026-06-21 current-head Debian-to-Debian full-kmod recheck on
`6.12.90+deb13.1-amd64` also passed the 900s production gate. It used commit
`5155854d5077af628c776d586d5b735e4447b123`, minimum received throughput was
3.550158 Gbps against the 3 Gbps gate, the full plaintext datapath provider and
RX worker were active on both peers, plaintext outer-GSO, cached destination
MAC, and RX-worker GSO xmit counters were nonzero, covered RX/TX/module error
counters were zero, and the production verifier reported no kernel log crash
findings.

A 2026-06-22 current-head Debian-to-Debian full-kmod long recheck on
`6.12.94+deb13-cloud-amd64` passed a stricter 3600s-per-direction production
gate. It used commit `24c7e17fc582`, minimum received throughput was
3.533778 Gbps against the 3 Gbps gate, both peers kept stable boot IDs, pstore
and kernel log scans were clean, the full plaintext datapath provider and RX
worker were active on both peers, and covered RX/TX/module error counters were
zero. A separate simultaneous bidirectional 3600s diagnostic on the same guests
also stayed stable with clean logs and zero covered module errors, but was not
promoted as throughput evidence because it reached 2.028861 Gbps minimum
received throughput, below the 3 Gbps production gate.

A 2026-06-23 current-head Debian-to-Debian full-kmod recheck on
`6.12.94+deb13-amd64` passed the same 3600s-per-direction production gate. It
used commit `1a72df194383d74fef5b03f68878f72734addb39`, minimum received
throughput was 3.445860 Gbps against the 3 Gbps gate, both peers kept stable
boot IDs, pstore and kernel log scans were clean, and covered datapath error
counters were zero.

A 2026-06-25 current-head Debian-to-Debian full-kmod recheck on
`6.12.90+deb13.1-cloud-amd64` passed the same 3600s-per-direction production
gate. It used commit `b01a10dff63a`, minimum received throughput was
3.508709 Gbps against the 3 Gbps gate, both peers kept stable boot IDs, pstore
was mounted and empty, the soak-window kernel journal had no entries,
`tix-lan` kept `tx_queue_len=1000`, and covered datapath error counters were
zero with full plaintext provider, RX worker, TX plaintext, and eight warmed
sessions active. Later commits `5ee74be` and `0fb27b8` only changed soak log
collection, tests, and documentation; no daemon or kernel module runtime code
changed.

A 2026-06-21 current-head Debian-to-Debian TC-direct recheck on
`6.12.90+deb13.1-amd64` also passed the 900s production gate. It used commit
`a3805571d930`, minimum received throughput was 3.915829 Gbps against the
3 Gbps gate, both peers reported `kernel_udp.provider=tc_direct`,
`kernel_udp.fast_path=true`, `kernel_udp.direct_only=true`, and eight active
kernel UDP flows, no TrustIX kernel modules were loaded, and the production
verifier reported no kernel log crash findings.

A 2026-06-22 Debian-to-Debian route-GSO long recheck on
`6.12.94+deb13-cloud-amd64` passed the 3600s-per-direction production gate.
Minimum received throughput was 2.829761 Gbps against the 2.5 Gbps gate,
route-GSO outer-GSO and xmit counters were nonzero on both peers, covered
helper error counters were zero, session dial errors stayed within the current
budget, and the production verifier reported stable boot IDs, clean pstore
coverage, and no kernel log crash findings.

A 2026-06-22 Debian-to-Debian secure-kUDP long recheck on
`6.12.94+deb13-cloud-amd64` passed the 3600s-per-direction production gate.
Minimum received throughput was 1.634107 Gbps against the 1.5 Gbps gate, TC
secure direct and route-GSO kfunc stats were active on both peers, crypto
module seal/open counters were nonzero, helper route-GSO xmit counters were
nonzero, and the production verifier reported stable boot IDs, clean pstore
coverage, and no kernel log crash findings. The current gate separately
requires zero `replay_old` drops and bounds `replay_seen/open` plus total
secure-direct drop ratios at `<= 0.00002`, replacing the older absolute replay
budget.

A 2026-06-25 Debian-to-Debian secure experimental TCP kernel crypto recheck on
`6.12.90+deb13.1-cloud-amd64` passed the 3600s-per-direction production gate.
Minimum received throughput was 1.599325 Gbps against the 1.5 Gbps gate,
`experimental_tcp` used `datapath=kernel_module` and `crypto_placement=kernel`
with direct kfunc crypto plus route TCP GSO async, both peers loaded
`trustix_crypto` and `trustix_datapath_helpers`, FPU-unavailable direct-kfunc
fallback counters were nonzero, and the production verifier reported stable
boot IDs, clean pstore coverage, and no kernel log crash findings. This is a
dedicated `secure_exp_tcp_kernel` production default and must not reuse
secure-kUDP evidence.

A 2026-06-23 to 2026-06-24 current-head Debian-to-Debian userspace recheck on
`6.12.69+deb13-amd64` passed every current 3600s cross-host userspace
production default with no TrustIX kernel modules loaded. It used commit
`efa9887c763c47a7a9b37483c54909fffdc7a65b`; minimum received throughput was
1.672798 Gbps for secure UDP, 1.754013 Gbps for plaintext UDP, 0.777460 Gbps
for secure TCP, 1.032665 Gbps for plaintext TCP, 0.954547 Gbps for secure
QUIC, 1.249522 Gbps for plaintext QUIC, 0.592369 Gbps for secure WebSocket,
1.125059 Gbps for plaintext WebSocket, 0.839874 Gbps for secure HTTP CONNECT,
1.237984 Gbps for plaintext HTTP CONNECT, and 1.246138 Gbps for secure
experimental TCP. The verifier reported no log findings, no errors, stable
boot IDs, clean pstore coverage, and zero session dial or heartbeat failures.

A 2026-06-24 current-head Debian-to-Debian userspace-TC tunnel recheck on
`6.12.69+deb13-amd64` passed every current 3600s cross-host GRE/IPIP/VXLAN
secure and plaintext production default with no TrustIX kernel modules loaded.
It used commit `efa9887c763c47a7a9b37483c54909fffdc7a65b`; minimum received
throughput was 1.376135 Gbps for secure GRE, 5.110725 Gbps for plaintext GRE,
1.383353 Gbps for secure IPIP, 5.231286 Gbps for plaintext IPIP, 1.361865 Gbps
for secure VXLAN, and 5.286772 Gbps for plaintext VXLAN. The verifier reported
no log findings, no errors, stable boot IDs, clean pstore coverage, and zero
session dial or heartbeat failures.

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
passes the runtime route-TCP gate. Secure experimental TCP kernel crypto shares
the same route-TCP prerequisite, so it remains fail-closed on OpenWrt 24.10.2
as well. The selected OpenWrt 24.10.2 production kernel path remains UDP
plaintext full-kmod.

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
`route_tcp_xmit_kfunc`; secure experimental TCP kernel crypto is blocked by the
same route-TCP prerequisite. The selected OpenWrt production kernel path
therefore remains UDP plaintext full-kmod with exact-version runtime evidence.

A 2026-06-24 OpenWrt 25.12.4 follow-up used VM201 OpenWrt x86_64 kernel
`6.12.87` and VM200 Debian 13 `6.12.94+deb13-amd64` on isolated `vmbr3`.
OpenWrt 25.12.4 uses APK package feeds. The official image still did not
expose `/sys/kernel/btf/vmlinux`. After fixing the SDK matrix helper to parse
`include/kernel-version.mk`, forced full OpenWrt modules built successfully
with `crypto=full,datapath=full,helpers=full`; the OpenWrt module SHA256
values were `8652ba0b78af1e7845e5adc466ef48654aeb68c675574652bc39fbd7f8febdac`
for `trustix_crypto.ko`,
`f7b9d3a00f9f90e44863bba514b8563a14312c0bc16990d34daddb08e490ed3c` for
`trustix_datapath.ko`, and
`d9990877dfdc431023d7c26b89924a47e070f537c5b0e94e76ed9bf263e28abe` for
`trustix_datapath_helpers.ko`. Both secure-kUDP route-GSO and experimental TCP
route-GSO failed closed before traffic with missing `route_tcp_kfunc` and
`route_tcp_xmit_kfunc`; secure experimental TCP kernel crypto is blocked by the
same route-TCP prerequisite, so upgrading to the official 25.12.4 image does
not change the OpenWrt production default selection.

A 2026-06-23 current-head OpenWrt 24.10.7-to-Debian full-kmod recheck paired
OpenWrt kernel `6.6.141` with Debian 13 `6.12.94+deb13-amd64` and passed the
3600s-per-direction production gate. It used commit
`1a72df194383d74fef5b03f68878f72734addb39`, minimum received throughput was
3.507421 Gbps against the 3 Gbps gate, before/after boot IDs stayed stable,
pstore and kernel log scans were clean, and covered datapath error counters
were zero. A concurrent direct underlay probe while full-kmod was loaded reached
3.752 Gbps from OpenWrt to Debian. OpenWrt route-GSO, secure-kUDP route-GSO,
and secure experimental TCP kernel crypto remain unselected because the tested
OpenWrt kernel still lacks usable route-TCP kfunc capability.

A 2026-06-24 current-head OpenWrt 24.10.7-to-Debian full-kmod recheck paired
OpenWrt kernel `6.6.141` with Debian 13
`6.12.90+deb13.1-cloud-amd64` and passed the same 3600s production gate. It
used commit `01ca47e`; minimum received throughput was 3.438634 Gbps from
OpenWrt to Debian and 5.000735 Gbps from Debian to OpenWrt against the 3 Gbps
gate. Before/after boot IDs stayed stable, pstore and kernel log scans were
clean, `tix-lan` kept `tx_queue_len=1000`, and covered datapath error counters
were zero with full plaintext provider, RX worker, and TX plaintext active. A
simultaneous bidirectional diagnostic stayed stable without crash evidence but
was not promoted as throughput evidence because one direction fell below the
3 Gbps production gate.

A 2026-06-25 current-head OpenWrt 24.10.7-to-Debian full-kmod recheck paired
OpenWrt kernel `6.6.141` with Debian 13
`6.12.94+deb13-cloud-amd64` and passed the same 3600s-per-direction production
gate. It used commit `395b2ba05013`; minimum received throughput was
3.493808 Gbps from OpenWrt to Debian and 5.108514 Gbps from Debian to OpenWrt
against the 3 Gbps gate. Before/after boot IDs stayed stable, pstore and
kernel log scans were clean, `tix-lan` kept `tx_queue_len=1000`, and covered
datapath error counters were zero with full plaintext provider, RX worker, TX
plaintext, and eight warmed sessions active.

OpenWrt SDK compile spot check for `kernel/trustix_datapath`:

| OpenWrt target | Kernel | Result |
| --- | --- | --- |
| `21.02.7 x86/64` | `5.4.238` | pass |
| `23.05.5 x86/64` | `5.15.167` | pass |
| `24.10.2 x86/64` | `6.6.93` | pass |
| `24.10.7 x86/64` | `6.6.141` | pass |
| `25.12.4 x86/64` | `6.12.87` | pass |
| `23.05.5 armsr/armv8` | `5.15.167` | pass |

Older performance-log runs also covered a wider OpenWrt compile matrix, but the
table above is the current-source spot check. Runtime full-kmod coverage now
includes OpenWrt 23.05.5, 24.10.2, and 24.10.7 x86_64 with matching SDK-built
modules. OpenWrt 24.10.7 also has route-GSO fail-closed coverage, but no
OpenWrt route-GSO, secure-kUDP route-GSO, or secure experimental TCP kernel
production default is selected until a tested OpenWrt kernel exposes usable
route-TCP kfunc capability.

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
24.10.7 route-GSO or secure-kUDP route-GSO as production defaults. Secure
experimental TCP kernel crypto shares the same route-TCP prerequisite. The later
OpenWrt 25.12.4 official x86_64 image also failed closed for the same
capability boundary. Use the validated UDP plaintext full-kmod path until a
newer OpenWrt kernel/helper combination passes the runtime route-TCP kfunc
gate.

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
