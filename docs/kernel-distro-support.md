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
| Full plaintext datapath module | Matching KDIR; explicit crash-risk gates plus `enable_features=128 rx_worker_inject=1 tx_plaintext=1`; passing module selftests | Crash-risk experimental only. Daemon defaults keep RX worker and TX plaintext disabled with explicit `rx_worker_inject=0 tx_plaintext=0`; OpenWrt requires an additional OpenWrt-specific opt-in gate. Secure full-kernel datapath and GSO LAN TX are not complete first-release guarantees. |

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

The latest PVE compatibility audit was run on 2026-06-09 against current source.

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
pstore record or previous-boot kernel stack was captured. This validates only
the short PVE matrix. Full plaintext datapath remains crash-risk experimental
and must not be described as production-safe until the route-GSO/RX-worker
corner is isolated and a longer A/B soak passes with crash capture enabled.

Follow-up PVE multitransport isolation narrowed the later hard reboot to the
full datapath RX_STAGE hook attachment, not module load by itself. Runs with all
TrustIX modules disabled, helper-only modules, and `trustix_datapath` loaded
with `kernel_modules.datapath.rx_stage: disabled` stayed up. A datapath-only run
with the daemon's previous default RX_STAGE hook reproduced a reboot. The daemon
therefore defaults RX_STAGE/RX_WORKER hook attachment off; explicit
`kernel_modules.datapath.rx_stage: stage|worker` or the matching environment
override is required, and RX_WORKER/full plaintext still need their crash-risk
gates. TC/eBPF plus `trustix_datapath_helpers` remains the recommended
performance path.

OpenWrt SDK compile spot check for `kernel/trustix_datapath`:

| OpenWrt target | Kernel | Result |
| --- | --- | --- |
| `21.02.7 x86/64` | `5.4.238` | pass |
| `23.05.5 x86/64` | `5.15.167` | pass |
| `24.10.2 x86/64` | `6.6.93` | pass |
| `23.05.5 armsr/armv8` | `5.15.167` | pass |

Older performance-log runs also covered a wider OpenWrt compile matrix, but the
table above is the current-source spot check. Runtime load/function coverage is
strongest for Ubuntu `6.8.0-124-generic`.

OpenWrt `23.05.5 x86_64` runtime status is deliberately narrower than the
Ubuntu/PVE row: module load/unload, `RX_WORKER`, `TX_PLAINTEXT`, RX-worker plus
`clsact` TC coexistence, and single-host TCP-stream smoke pass on kernel
`5.15.167` without reboot. This is not a formal OpenWrt A/B traffic stress
result. Treat OpenWrt full plaintext datapath as an explicit opt-in production
risk until longer A/B traffic stress passes on the same OpenWrt kernel. TC-only,
userspace fallback, and helper-module paths are separate from this full
plaintext `.ko` path.

## Distribution notes

Systemd-based distributions such as Debian, Ubuntu, and Proxmox guests are the
best-supported deployment target for the current scripts. `trustix-deploy.sh`,
`trustix-update.sh`, and `install-systemd-linux.sh` install systemd units and
restart `trustixd@*.service` instances.

OpenWrt and soft-router systems should prefer release tarballs plus target-side
module builds using the OpenWrt SDK or matching KDIR. The current deployment
scripts do not install an OpenWrt `/etc/init.d` service, and BTF may be missing;
in that case TrustIX should fall back to userspace/device/basic-helper
capabilities instead of pretending full kfunc offload is available.

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
