# TrustIX

TrustIX is an experimental certificate-based IX mesh for connecting trusted LANs and devices through authenticated overlay transports. It includes a Go control plane, a Web UI, userspace transports, Linux TC/XDP/AF_XDP dataplane paths, and optional Linux kernel modules for crypto and full/plaintext datapath experiments.

This repository is still first-release quality. Treat kernel datapath features as experimental and test them on disposable hosts or VMs before enabling them on a router or production machine.

## Current Scope

- Root/Domain/Admin/IX/Device certificate tooling through `trustix-ca`.
- Signed desired config, config log, trust policy, admission, endpoint grants, route authorization, and device-access control plane.
- UDP, QUIC, TCP, WebSocket, HTTP CONNECT, GRE/IPIP carrier, `kernel_udp`, and experimental ACKless TCP transport paths.
- Userspace secure envelope with AES-GCM and ChaCha20-Poly1305 support; optional kernel crypto placement where supported.
- Embedded Web UI served by `trustixd`.
- Linux dataplane automation for managed LAN interfaces, routes, TC/eBPF capture, AF_XDP paths, and kernel module capability reporting.
- Fallback paths for systems without the full kernel module capability set.

## Repository Layout

- `cmd/`: command-line entry points: `trustixd`, `trustixctl`, `trustix-ca`, and `trustix-device`.
- `internal/`: daemon, control plane, transport, dataplane, PKI, Web UI embed, and kernel module management code.
- `kernel/`: Linux kernel module source for TrustIX crypto/datapath helpers/full datapath.
- `webui/`: React/Vite Web UI source. Built assets are embedded under `internal/webui/assets`.
- `configs/`: local lab config examples. They reference generated `./certs` files, which must not be committed.
- `scripts/`: Linux build, smoke test, release, and benchmark helpers.
- `docs/`: design notes, first-run guide, implementation boundaries, performance log, and release checklist.

## Quick Start

For a first real deployment, use the interactive wizard:

```bash
curl -fsSL https://raw.githubusercontent.com/Unicode01/TrustIX/main/scripts/trustix-wizard.sh | sudo bash
```

If you prefer filling a form first, use the static command generator:
[https://unicode01.github.io/TrustIX/](https://unicode01.github.io/TrustIX/).

Choose **Create a new domain and first IX**. The wizard asks for the domain ID,
IX ID, published control API URL, LAN interface/gateway, advertised LAN prefix,
and data endpoint, then calls the stable bootstrap script to generate certs,
build a release, install the systemd service, and start the first IX.

After the first IX is running, add more IX nodes from the Web UI:

1. Open the first IX Web UI.
2. Go to the access/bootstrap page and issue a one-time IX provision token.
3. Run the generated command on the new machine. It has this shape:

```bash
curl -fsSL https://raw.githubusercontent.com/Unicode01/TrustIX/main/scripts/trustix-bootstrap-ix.sh | \
  sudo bash -s -- --provision-url https://ix-a.example.net:8787 --token TOKEN
```

This token mode keeps CA private keys on the issuing IX/provisioner. The target
machine only receives the deployable IX certs/config needed for that node.

More deployment details are in [docs/deployment-scripts.md](docs/deployment-scripts.md).

## Local Development

The development path is for local lab testing only. It uses `configs/lab-a.yaml`,
serves the management API on `http://127.0.0.1:8787`, and defaults to `noop`
dataplane unless you pass `-dataplane auto`.

Generate local lab certificates:

```bash
go run ./cmd/trustix-ca quickstart -out certs -domain lab.local -ix ix-a,ix-b
```

Start a development daemon:

```bash
go run ./cmd/trustixd
```

On Linux test hosts:

```bash
go run ./cmd/trustixd -config configs/lab-a.yaml -dataplane auto
```

Query status:

```bash
go run ./cmd/trustixctl status
go run ./cmd/trustixctl doctor
go run ./cmd/trustixctl datapath
```

More local runtime details are in [docs/first-run.md](docs/first-run.md).

## Build And Test

Web UI:

```bash
npm install
npm run webui:check
npm run webui:build
```

Go packages used by the daemon and tools:

```bash
go test -count=1 ./cmd/... ./internal/...
```

Linux release package and kernel modules:

```bash
sudo -E bash scripts/build-release-linux.sh
```

For source release gates and Linux smoke tests, use [docs/release-checklist.md](docs/release-checklist.md).

For one-command build, deploy, and new-IX bootstrap automation, use [docs/deployment-scripts.md](docs/deployment-scripts.md).

For kernel version, OpenWrt, and distribution support boundaries, use [docs/kernel-distro-support.md](docs/kernel-distro-support.md).

For large-domain control-plane discovery, recovery, and anti-storm architecture, use [docs/control-fabric-architecture.md](docs/control-fabric-architecture.md).

## Security Notes

Do not commit generated PKI material, runtime state, logs, or benchmark artifacts. The repository `.gitignore` intentionally excludes `certs/`, `*.key`, `.trustix/`, `build/`, and local state files.

Management API write operations should run with Admin signed-request authentication. Do not expose a temporary Web UI or API listener on a public address without TLS and admin auth.

See [SECURITY.md](SECURITY.md) for the current first-release security policy.

## License

No license file is present yet. Add the intended project license before making the repository public.
