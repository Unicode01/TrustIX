# TrustIX deployment scripts

The stable automation entry points are:

- `scripts/trustix-build.sh`
- `scripts/trustix-deploy.sh`
- `scripts/trustix-update.sh`
- `scripts/trustix-uninstall.sh`
- `scripts/trustix-bootstrap-ix.sh`
- `scripts/trustix-wizard.sh`
- `scripts/trustix-latency-history-summary.py`

The scripts target Linux with GNU Bash. They are intended to be callable from the Web UI or another provisioner.

## First-Run Wizard

For a new operator, start here:

```bash
curl -fsSL https://raw.githubusercontent.com/Unicode01/TrustIX/main/scripts/trustix-wizard.sh | sudo bash
```

The same command can be generated from a browser at
[https://unicode01.github.io/TrustIX/](https://unicode01.github.io/TrustIX/).
The page is static and only assembles shell commands locally.

The wizard has two modes:

- `Create a new domain and first IX`: prompts for the first IX basics, creates
  the local CA/cert directory when needed, then calls `trustix-bootstrap-ix.sh`
  to build, install, and start the first IX.
- `Join an existing domain with a WebUI provision token`: prompts for the
  provision URL and one-time token, then calls `trustix-bootstrap-ix.sh` in
  token mode.

The wizard is intentionally a thin interactive wrapper. Automation, WebUI, and
CI should call `trustix-bootstrap-ix.sh`, `trustix-build.sh`, `trustix-deploy.sh`,
and `trustix-update.sh` directly.

The WebUI one-time provision flow supports transit-only IX bootstrap without a
local advertised prefix. In that mode the issued target config omits local LAN
route authorization; the new IX joins the control fabric and can add LANs or
downstream prefixes later through the config page.

## Build

```bash
scripts/trustix-build.sh --goarch amd64 --build-ko auto --json
```

Important options:

- `--goarch amd64|arm64|arm`
- `--kdir /path/to/kernel/build` for target-kernel `.ko` builds
- `--build-ko auto|0|1`
- `--skip-webui` when embedded assets are already built

The script wraps `scripts/build-release-linux.sh` and prints the tarball path when `--json` is used.

When `--build-ko 1` is used, the build needs a matching kernel build tree for
the running kernel or the `--kdir` target. The scripts try to install the
matching headers automatically when package installation is enabled. On Proxmox,
that normally means `proxmox-headers-$(uname -r)`; older repositories may use
`pve-headers-$(uname -r)`. If the package is not available, install the matching
headers from the host's kernel repository or use `--build-ko 0` /
`--kernel-modules auto` for a userspace/eBPF-only install. Kernel module BTF
finalization also needs `pahole`; on Debian, Ubuntu, and Proxmox the automation
installs it through the `dwarves` package.

## Deploy

```bash
scripts/trustix-deploy.sh \
  --target root@example.com \
  --tarball build/release/trustix-linux-amd64.tar.gz \
  --instance ix-new \
  --config build/bootstrap/ix-new/config/ix-new.json \
  --cert-dir build/bootstrap/ix-new/deploy-certs \
  --api 127.0.0.1:8787 \
  --peer-api 0.0.0.0:9443 \
  --dataplane auto \
  --admin-auth
```

Omit `--target` for local deployment. SSH options are `--ssh-port`, `--ssh-key`, and repeated `--ssh-option`.

Deployment installs binaries, config, certificates, and an `/etc/trustix/<instance>.env` file. `--service-manager auto` detects systemd on normal Linux and OpenWrt procd on OpenWrt. Systemd installs `trustixd@.service`; OpenWrt installs `/etc/init.d/trustix`.

OpenWrt defaults are deliberately different from general Linux: binaries go under `/opt/trustix/bin`, persistent runtime state under `/etc/trustix/state/<instance>`, and certificates/config still live under `/etc/trustix`. Use `--service-manager openwrt` to force this path:

```bash
scripts/trustix-deploy.sh \
  --target root@openwrt.example \
  --service-manager openwrt \
  --tarball build/release/trustix-linux-amd64.tar.gz \
  --instance ix-router \
  --config build/bootstrap/ix-router/config/ix-router.json \
  --cert-dir build/bootstrap/ix-router/deploy-certs \
  --dataplane auto \
  --admin-auth
```

The service wrappers support `TRUSTIX_EXTRA_ARGS`, used by `--admin-auth` and repeated `--extra-arg`.

After deploying to OpenWrt, a read-only smoke check can verify the procd wrapper,
instance env, binary/config paths, and optional dnsmasq rule:

```bash
scripts/openwrt-procd-dns-smoke.sh \
  --target root@openwrt.example \
  --instance ix-router \
  --dns-domain trust.ix
```

## Update

```bash
curl -fsSL https://raw.githubusercontent.com/Unicode01/TrustIX/main/scripts/trustix-update.sh | \
  sudo bash -s -- \
    --release-url https://github.com/Unicode01/TrustIX/releases/download/v0.1.0/trustix-linux-amd64.tar.gz
```

`trustix-update.sh` is for in-place upgrades of an existing systemd or OpenWrt install. It replaces the binaries and service wrapper, preserves `/etc/trustix`, certificates, and data directories, then restarts detected instances. Pass `--instance ix-a` one or more times to choose instances explicitly, or `--no-restart` to only install files.

When no `--release-url` or `--tarball` is provided, the script clones the repo and builds a release locally:

```bash
curl -fsSL https://raw.githubusercontent.com/Unicode01/TrustIX/main/scripts/trustix-update.sh | \
  sudo bash -s -- --repo https://github.com/Unicode01/TrustIX.git --ref main --build-ko auto
```

Prefer release tarballs for small OpenWrt/soft-router machines. Source-build update needs Go and, when `.ko` is desired, matching kernel headers on the target.

## Uninstall

```bash
curl -fsSL https://raw.githubusercontent.com/Unicode01/TrustIX/main/scripts/trustix-uninstall.sh | \
  sudo bash -s -- --all
```

`trustix-uninstall.sh` stops detected TrustIX instances, runs
`trustixd -cleanup-dataplane`, removes the systemd/OpenWrt service wrapper, and
removes installed binaries. By default it preserves `/etc/trustix`,
`/etc/trustix/certs`, and runtime state under `/var/lib/trustix/<instance>` or
`/etc/trustix/state/<instance>` on OpenWrt.

Remove one instance but leave shared binaries and service files:

```bash
sudo bash scripts/trustix-uninstall.sh --instance ix-a --purge
```

Remove all instances, binaries, service files, instance config/data, and
instance certificate/key files:

```bash
curl -fsSL https://raw.githubusercontent.com/Unicode01/TrustIX/main/scripts/trustix-uninstall.sh | \
  sudo bash -s -- --all --purge
```

`--purge` removes only instance files. `--purge-certs-dir` removes the whole
configured cert directory and is intended for disposable lab installs. Full
uninstall attempts to unload `trustix_datapath`, `trustix_datapath_helpers`, and
`trustix_crypto` after dataplane cleanup; use `--keep-kernel-modules` to leave
loaded modules in place. Remote cleanup is available with `--target USER@HOST`
plus `--ssh-port`, `--ssh-key`, and repeated `--ssh-option`.

## GitHub Workflows

The default GitHub release workflow intentionally does not build generic `.ko` artifacts:

- `.github/workflows/ci.yml` runs Go tests, WebUI checks, shell syntax checks, and a userspace release build with embedded eBPF but `--build-ko 0`.
- `.github/workflows/release.yml` publishes `trustix-linux-amd64.tar.gz` and `trustix-linux-arm64.tar.gz` for tags matching `v*`. These packages include kernel module source and Makefiles, not universal prebuilt `.ko` files.
- `.github/workflows/kernel-release.yml` is manual-only. Use it with a runner/KDIR that matches the target kernel when a prebuilt `.ko` package is actually wanted.

This keeps normal CI/release cheap and avoids shipping kernel modules with misleading ABI compatibility. For target-specific kernels, use the manual workflow, a self-hosted runner, or `trustix-update.sh --build-ko auto` directly on the target.

## Bootstrap A New IX

```bash
scripts/trustix-bootstrap-ix.sh \
  --ix ix-new \
  --domain example.net \
  --source-certs certs \
  --control-api https://ix-new.example.net:9443 \
  --lan-iface br-lan \
  --lan-gateway 10.44.0.1/24 \
  --underlay-iface eth0 \
  --advertise 10.44.0.0/24 \
  --endpoint 'name=ix-new-udp;transport=udp;mode=passive;listen=0.0.0.0:7000;address=ix-new.example.net:7000' \
  --bootstrap-control-api https://ix-a.example.net:9443 \
  --target root@ix-new.example.net \
  --json
```

Bootstrap requires the Domain CA key to issue the IX certificate and the Config CA key to issue route authorization. It writes the target config as JSON, stages deployable certs, optionally builds a release tarball, and optionally deploys it.

Use semicolon-separated endpoint specs when a value contains commas, such as GRE/IPIP/VXLAN endpoint strings.
For OpenWrt, add `--service-manager openwrt --dns-enabled 1 --openwrt-dnsmasq 1` when you want the target IX to answer TrustIX DNS names through dnsmasq conditional forwarding. This keeps dnsmasq on LAN port 53 and forwards only the TrustIX DNS suffix to the built-in resolver.
The wizard/bootstrap scripts automatically install missing source-build
dependencies through the host package manager when possible. Set
`TRUSTIX_BOOTSTRAP_INSTALL_DEPS=0` to disable package installation in locked-down
environments.
For a single interface with multiple underlay IPs, bind ingress with the
endpoint `listen` address and bind egress with endpoint `source_ip` and optional
`bind_iface`:

```bash
scripts/trustix-bootstrap-ix.sh \
  --ix ix-new \
  --domain example.net \
  --source-certs certs \
  --control-api https://ix-new.example.net:9443 \
  --lan-iface br-lan \
  --lan-gateway 10.44.0.1/24 \
  --advertise 10.44.0.0/24 \
  --endpoint 'name=ix-new-udp;transport=udp;mode=passive;listen=198.51.100.10:7000;address=ix-new.example.net:7000;source_ip=198.51.100.10;bind_iface=vmbr0' \
  --no-deploy
```

## Latency Matrix History

`scripts/public-production-sim-latency.py` appends one compact JSONL row per completed case by default:

```bash
python scripts/public-production-sim-latency.py \
  --production-sim \
  --require-production-session \
  --quick \
  --history build/latency-history.jsonl
```

Pass `--history ""` to disable history writes. Each row includes the case metadata, RTT summary, overlay-underlay overhead, and compact kernel UDP direct-path counters. The full run JSON remains in the `--out` path.

Summarize the latest rows:

```bash
python scripts/trustix-latency-history-summary.py --last 20
python scripts/trustix-latency-history-summary.py --transport udp --encryption secure --last 10
```

The table columns use milliseconds. `a->b avg/p95` and `b->a avg/p95` are overlay RTTs; `a->b ovh p95` and `b->a ovh p95` are overlay p95 minus underlay p95. The `kernel_udp` column shows `tx/rx` direct attachment, TX secure-direct seal successes, and userspace session packet counts, which makes fallback regressions visible without opening the full JSON.

## Multi-NIC And Multi-IP Boundary

Current config supports:

- `lan` plus `lans[]` for multiple local or trusted-public LANs.
- Per-LAN `iface`, `underlay_iface`, `gateway`, `advertise`, `attach_mode`, and management flags.
- Multiple endpoint listeners by binding each endpoint `listen` to a specific IP and publishing a separate `address`.
- Per-endpoint `local_bind.source_ip` and `local_bind.iface` for outbound underlay selection. `source_ip` is supported by UDP/TCP/QUIC/WebSocket/HTTP CONNECT and is carried into `kernel_udp`/`experimental_tcp` kernel flows. `iface` uses Linux `SO_BINDTODEVICE` on socket-based dials and experimental TCP primer/control connections.
- GRE/IPIP/VXLAN endpoint strings with explicit `local`, `remote`, carrier addresses, and optional `underlay_if`.

Current dataplane boundary:

- Linux dataplane receives all LAN attach specs and manages address/qdisc/cleanup for multiple LANs.
- LAN reinject chooses the matching LAN by destination prefix.
- TC/eBPF and kernel fast-path underlay selection still have a primary-LAN bias for `kernel_udp`, `experimental_tcp`, and negotiated tunnel defaults.
- `local_bind.iface` is not currently serialized into full-kernel TX route templates; use `local_bind.source_ip`, endpoint `listen`, explicit tunnel `underlay_if`, or OS routing when a pure kernel path must pick a specific uplink.

Example JSON endpoint:

```json
{
  "name": "ix-b-tcp-via-wan2",
  "mode": "active",
  "transport": "tcp",
  "address": "ix-b.example.net:7000",
  "local_bind": {
    "source_ip": "198.51.100.10",
    "iface": "wan2"
  },
  "enabled": true
}
```
