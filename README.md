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

Generate local lab certificates:

```bash
go run ./cmd/trustix-ca quickstart -out certs -domain lab.local -ix ix-a,ix-b
```

Start a development daemon with the default config:

```bash
go run ./cmd/trustixd
```

The default config is `configs/lab-a.yaml`, the default local management API is `http://127.0.0.1:8787`, and the default dataplane mode is `noop`. On Linux test hosts, use:

```bash
go run ./cmd/trustixd -config configs/lab-a.yaml -dataplane auto
```

Query status:

```bash
go run ./cmd/trustixctl status
go run ./cmd/trustixctl doctor
go run ./cmd/trustixctl datapath
```

More details are in [docs/first-run.md](docs/first-run.md).

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

## Security Notes

Do not commit generated PKI material, runtime state, logs, or benchmark artifacts. The repository `.gitignore` intentionally excludes `certs/`, `*.key`, `.trustix/`, `build/`, and local state files.

Management API write operations should run with Admin signed-request authentication. Do not expose a temporary Web UI or API listener on a public address without TLS and admin auth.

See [SECURITY.md](SECURITY.md) for the current first-release security policy.

## License

No license file is present yet. Add the intended project license before making the repository public.
