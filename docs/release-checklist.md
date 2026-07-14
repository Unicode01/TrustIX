# TrustIX Release Checklist

## GitHub Source Publish Gate

- Confirm a license has been selected and added before making the repository public.
- Do not commit generated PKI material, remote deployment artifacts, benchmark output, VM images, pprof files, or local runtime state.
- Confirm `certs/`, `build/`, `node_modules/`, `.trustix/`, `*.key`, `*.qcow2`, and `*.pprof` are excluded from the candidate commit.
- Keep `internal/webui/assets/**`, `internal/dataplane/ebpf/bpf/*_bpfel.o`, and the small `internal/kernelmodule/assets/*.ko` placeholders unless the release build pipeline is changed to regenerate them in clean clones.
- Run the local checks below from a clean checkout when possible. A dirty local workspace with historical `build/` packages may make `go test ./...` discover stale generated code that is not part of the source release.

Use this checklist before cutting a Linux release tarball.

## Local Code Checks

- `go test -count=1 ./...`
- `bash -n scripts/linux-e2e-smoke.sh scripts/linux-device-access-smoke.sh scripts/linux-kernel-module-smoke.sh scripts/linux-full-datapath-module-smoke.sh scripts/linux-datapath-module-smoke.sh scripts/release-smoke-linux.sh scripts/linux-clean-release-smoke.sh scripts/build-release-linux.sh scripts/build-kernel-modules-linux.sh`

## Source Linux E2E

- `sudo -E bash scripts/linux-e2e-smoke.sh`
- `TRUSTIX_E2E_NAT_REVERSE=1 sudo -E bash scripts/linux-e2e-smoke.sh`
- `TRUSTIX_E2E_NAT_REVERSE=1 TRUSTIX_E2E_TRANSPORT=tcp sudo -E bash scripts/linux-e2e-smoke.sh`
- `TRUSTIX_E2E_NAT_REVERSE=1 TRUSTIX_E2E_TRANSPORT=kernel_udp sudo -E bash scripts/linux-e2e-smoke.sh`
- `TRUSTIX_E2E_NAT_REVERSE=1 TRUSTIX_E2E_TRANSPORT=tix_tcp sudo -E bash scripts/linux-e2e-smoke.sh`
- `TRUSTIX_E2E_TRANSPORT=tcp sudo -E bash scripts/linux-e2e-smoke.sh`
- `TRUSTIX_E2E_TRANSPORT=kernel_udp sudo -E bash scripts/linux-e2e-smoke.sh`
- `TRUSTIX_E2E_TRANSPORT=gre sudo -E bash scripts/linux-e2e-smoke.sh`
- `TRUSTIX_E2E_TRANSPORT=ipip sudo -E bash scripts/linux-e2e-smoke.sh`
- `TRUSTIX_E2E_TRANSPORT=tix_tcp sudo -E bash scripts/linux-e2e-smoke.sh`
- With kernel crypto provider ready: `TRUSTIX_E2E_TRANSPORT=tix_tcp TRUSTIX_E2E_CRYPTO_PLACEMENT=kernel sudo -E bash scripts/linux-e2e-smoke.sh`
- Device certificate access: `sudo -E bash scripts/linux-device-access-smoke.sh`
- Kernel module ABI gates: `sudo -E TRUSTIX_KERNEL_KEEP_LOADED=0 bash scripts/linux-kernel-module-smoke.sh`, `sudo -E TRUSTIX_FULL_DATAPATH_KEEP_LOADED=0 bash scripts/linux-full-datapath-module-smoke.sh`, and `sudo -E TRUSTIX_DATAPATH_KEEP_LOADED=0 bash scripts/linux-datapath-module-smoke.sh`

## Control Plane

- `TRUSTIX_MEMBERSHIP_SMOKE_BIN_DIR=/opt/trustix/bin bash scripts/linux-membership-smoke.sh`
- `TRUSTIX_POLICY_SMOKE_BIN_DIR=/opt/trustix/bin bash scripts/linux-trust-policy-smoke.sh`
- Optional root transit matrix: `TRUSTIX_3IX_E2E_BIN_DIR=/opt/trustix/bin sudo -E bash scripts/linux-three-ix-e2e-smoke.sh`
- Optional kernel UDP transit: `TRUSTIX_3IX_E2E_BIN_DIR=/opt/trustix/bin TRUSTIX_3IX_E2E_TRANSPORT=kernel_udp sudo -E bash scripts/linux-three-ix-e2e-smoke.sh`

## Release Package

- Transactional updater smoke: `bash scripts/trustix-update-smoke.sh`
- Verify an old configuration rejected by the candidate leaves binaries and services untouched.
- Verify a candidate startup failure restores the previous binaries, systemd/OpenWrt service definition, and listening management API.
- On disposable hosts, upgrade with TrustIX kernel modules already loaded and confirm the old version is restored if the new service fails health checks.
- Coordinate a two-node breaking upgrade and confirm traffic recovers after both configurations and binaries are migrated.
- Build on target kernel or with matching `KDIR`: `sudo -E bash scripts/build-release-linux.sh`
- Optional multi-kernel module bundle: `TRUSTIX_KERNEL_MODULE_KDIRS=/path/to/k1/build,/path/to/k2/build ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- bash scripts/build-kernel-modules-linux.sh`
- Package smoke: `arch=$(go env GOARCH); sudo -E TRUSTIX_RELEASE_TARBALL=build/release/trustix-linux-${arch}.tar.gz bash scripts/release-smoke-linux.sh`
- Full clean host smoke: `sudo -E bash scripts/linux-clean-release-smoke.sh`

## Post-Test Cleanup

- `ip netns list | grep '^tix-'` should return nothing.
- `pgrep -af trustix` should return no test daemon.
- `lsmod | grep -E '^(trustix_crypto|trustix_datapath|trustix_datapath_helpers)'` should return nothing unless the modules were intentionally preloaded.
- `/tmp` and `/var/tmp` should not contain stale `trustix-*`, `trustix.*`, or `trustix_*` test directories.

## Release Notes Gate

- Mention any skipped optional smoke and why.
- Record target kernel version, `KDIR`, release version, commit, and whether embedded `trustix_crypto.ko` / `trustix_datapath.ko` / `trustix_datapath_helpers.ko` were built.
- Record `ARCH`, `CROSS_COMPILE`, and any crypto/helpers compatibility downgrade (`device-only` or `basic`) used for ARM/OpenWrt builds.
- Record whether NAT/no-public reverse e2e, TCP TLS exporter e2e, device-access e2e, kernel UDP e2e, GRE/IPIP e2e, kernel crypto e2e, and datapath module selftest passed.
