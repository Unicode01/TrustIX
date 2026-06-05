#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ]; then
  echo "ERROR: scripts/build-release-linux.sh requires GNU bash 4+" >&2
  exit 2
fi
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

normalize_goarch() {
  case "${1:-}" in
    amd64|x86_64) printf 'amd64\n' ;;
    arm64|aarch64) printf 'arm64\n' ;;
    arm|armv6l|armv7l|armhf) printf 'arm\n' ;;
    *) printf '%s\n' "$1" ;;
  esac
}

host_goarch() {
  normalize_goarch "$(uname -m)"
}

goarch_to_kernel_arch() {
  case "${1:-}" in
    amd64) printf 'x86\n' ;;
    arm64) printf 'arm64\n' ;;
    arm) printf 'arm\n' ;;
    *) printf '%s\n' "$1" ;;
  esac
}

goos="${GOOS:-linux}"
goarch="$(normalize_goarch "${GOARCH:-$(host_goarch)}")"
kernel_arch="${TRUSTIX_RELEASE_KERNEL_ARCH:-${ARCH:-$(goarch_to_kernel_arch "$goarch")}}"
kernel_cross_compile="${TRUSTIX_RELEASE_KERNEL_CROSS_COMPILE:-${CROSS_COMPILE:-}}"
crypto_build_mode="${TRUSTIX_RELEASE_CRYPTO_BUILD_MODE:-${TRUSTIX_CRYPTO_BUILD_MODE:-full}}"
datapath_helpers_build_mode="${TRUSTIX_RELEASE_DATAPATH_HELPERS_BUILD_MODE:-${TRUSTIX_DATAPATH_HELPERS_BUILD_MODE:-auto}}"
release_name="${TRUSTIX_RELEASE_NAME:-trustix-${goos}-${goarch}}"
out_root="${TRUSTIX_RELEASE_OUT:-${repo_root}/build/release}"
workdir="${out_root}/${release_name}"
obj_dir="${workdir}/obj"
bin_dir="${workdir}/bin"
pkg_dir="${workdir}/package"
overlay_file="${obj_dir}/go-overlay.json"
overlay_pairs_file="${obj_dir}/go-overlay-pairs.txt"
clang_bin="${CLANG:-}"
go_bin="${TRUSTIX_RELEASE_GO:-go}"
crypto_module_dir="${TRUSTIX_CRYPTO_MODULE_DIR:-${repo_root}/kernel/trustix_crypto}"
datapath_module_dir="${TRUSTIX_DATAPATH_MODULE_DIR:-${repo_root}/kernel/trustix_datapath}"
datapath_helpers_module_dir="${TRUSTIX_DATAPATH_HELPERS_MODULE_DIR:-${repo_root}/kernel/trustix_datapath_helpers}"
kernel_build_dir="${KDIR:-/lib/modules/$(uname -r)/build}"
build_bpf="${TRUSTIX_RELEASE_BUILD_BPF:-1}"
build_ko="${TRUSTIX_RELEASE_BUILD_KO:-1}"
embed_ko="${TRUSTIX_RELEASE_EMBED_KO:-1}"
build_tests="${TRUSTIX_RELEASE_BUILD_TESTS:-1}"
include_ko_source="${TRUSTIX_RELEASE_INCLUDE_KO_SOURCE:-1}"

default_commit() {
  if command -v git >/dev/null 2>&1 && git -C "$repo_root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git -C "$repo_root" rev-parse --short=12 HEAD
    return
  fi
  printf 'unknown'
}

release_version="${TRUSTIX_RELEASE_VERSION:-${release_name}}"
release_commit="${TRUSTIX_RELEASE_COMMIT:-$(default_commit)}"
release_built_at="${TRUSTIX_RELEASE_BUILT_AT:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
go_ldflags="-X trustix.local/trustix/internal/buildinfo.Version=${release_version} -X trustix.local/trustix/internal/buildinfo.Commit=${release_commit} -X trustix.local/trustix/internal/buildinfo.BuiltAt=${release_built_at}"
crypto_build_variant=""
datapath_helpers_build_variant=""

log() {
  printf '[trustix-release] %s\n' "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

select_clang() {
  local candidate
  for candidate in clang-22 clang-21 clang-20 clang-19 clang-18 clang-17 clang-16 clang-15 clang; do
    if command -v "$candidate" >/dev/null 2>&1; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

copy_file() {
  install -D -m "${3:-0644}" "$1" "$2"
}

compile_bpf_object() {
  local src="$1"
  local dst="$2"
  shift 2
  mkdir -p "$(dirname "$dst")"
  log "compile eBPF $(realpath --relative-to "$repo_root" "$src")"
  "$clang_bin" -target bpfel -O2 -g -Wall -Werror "$@" -c "$src" -o "$dst"
}

json_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf '%s' "$value"
}

write_overlay() {
  mkdir -p "$(dirname "$overlay_file")"
  {
    printf '{\n  "Replace": {\n'
    local first=1
    local pair from to
    while IFS= read -r pair; do
      [[ -n "$pair" ]] || continue
      from="${pair%%=*}"
      to="${pair#*=}"
      if [[ "$first" == "0" ]]; then
        printf ',\n'
      fi
      first=0
      printf '    "%s": "%s"' "$(json_escape "$from")" "$(json_escape "$to")"
    done <"$overlay_pairs_file"
    printf '\n  }\n}\n'
  } >"$overlay_file"
}

add_overlay_pair() {
  printf '%s=%s\n' "$1" "$2" >>"$overlay_pairs_file"
}

go_build() {
  local output="$1"
  local package="$2"
  local overlay="$3"
  log "go build ${package}"
  if [[ -n "$overlay" ]]; then
    GOOS="$goos" GOARCH="$goarch" "$go_bin" build -overlay "$overlay" -trimpath -ldflags "$go_ldflags" -o "$output" "$package"
    return
  fi
  GOOS="$goos" GOARCH="$goarch" "$go_bin" build -trimpath -ldflags "$go_ldflags" -o "$output" "$package"
}

sha256_file() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    printf ''
    return
  fi
  sha256sum "$path" | cut -d ' ' -f 1
}

make_kernel_module() {
  local module_dir="$1"
  local target="${2:-}"
  if [[ -n "$target" && -n "$kernel_cross_compile" ]]; then
    make -C "$module_dir" "$target" KDIR="$kernel_build_dir" ARCH="$kernel_arch" CROSS_COMPILE="$kernel_cross_compile" V=0
  elif [[ -n "$target" ]]; then
    make -C "$module_dir" "$target" KDIR="$kernel_build_dir" ARCH="$kernel_arch" V=0
  elif [[ -n "$kernel_cross_compile" ]]; then
    make -C "$module_dir" KDIR="$kernel_build_dir" ARCH="$kernel_arch" CROSS_COMPILE="$kernel_cross_compile" V=0
  else
    make -C "$module_dir" KDIR="$kernel_build_dir" ARCH="$kernel_arch" V=0
  fi
}

clean_kernel_module() {
  local module_dir="$1"
  if [[ -n "$kernel_cross_compile" ]]; then
    make -C "$module_dir" KDIR="$kernel_build_dir" ARCH="$kernel_arch" CROSS_COMPILE="$kernel_cross_compile" V=0 clean >/dev/null 2>&1 || true
  else
    make -C "$module_dir" KDIR="$kernel_build_dir" ARCH="$kernel_arch" V=0 clean >/dev/null 2>&1 || true
  fi
}

write_manifest() {
  local manifest="${pkg_dir}/manifest.json"
  local bpf_asset_dir="${repo_root}/internal/dataplane/ebpf/bpf"
  local name src_path hash first
  {
    printf '{\n'
    printf '  "version": "%s",\n' "$(json_escape "$release_version")"
    printf '  "commit": "%s",\n' "$(json_escape "$release_commit")"
    printf '  "built_at": "%s",\n' "$(json_escape "$release_built_at")"
    printf '  "target": {"goos": "%s", "goarch": "%s"},\n' "$(json_escape "$goos")" "$(json_escape "$goarch")"
    printf '  "kernel": {"uname": "%s", "kdir": "%s", "arch": "%s", "cross_compile": "%s", "crypto_build_mode": "%s", "crypto_build_variant": "%s", "datapath_helpers_build_mode": "%s", "datapath_helpers_build_variant": "%s"},\n' "$(json_escape "$(uname -r)")" "$(json_escape "$kernel_build_dir")" "$(json_escape "$kernel_arch")" "$(json_escape "$kernel_cross_compile")" "$(json_escape "$crypto_build_mode")" "$(json_escape "$crypto_build_variant")" "$(json_escape "$datapath_helpers_build_mode")" "$(json_escape "$datapath_helpers_build_variant")"
    printf '  "options": {"build_bpf": "%s", "build_ko": "%s", "embed_ko": "%s", "include_ko_source": "%s"},\n' "$(json_escape "$build_bpf")" "$(json_escape "$build_ko")" "$(json_escape "$embed_ko")" "$(json_escape "$include_ko_source")"
    printf '  "binaries": {\n'
    first=1
    for name in trustixd trustixctl trustix-ca trustix-device trustix-iptunnel-smoke ebpf.test kernelmodule.test; do
      src_path="${bin_dir}/${name}"
      [[ -f "$src_path" ]] || continue
      hash="$(sha256_file "$src_path")"
      if [[ "$first" == "0" ]]; then
        printf ',\n'
      fi
      first=0
      printf '    "%s": {"sha256": "%s", "size": %s}' "$(json_escape "$name")" "$hash" "$(stat -c %s "$src_path")"
    done
    printf '\n  },\n'
    printf '  "embedded_assets": {\n'
    printf '    "ebpf": {\n'
    first=1
    for name in experimental_tcp_xdp experimental_tcp_kernel_crypto_xdp experimental_tcp_kernel_crypto_xdp_direct experimental_tcp_kernel_crypto_tx_xdp kernel_udp_xdp kernel_udp_tx_kernel_crypto_tc kernel_udp_rx_kernel_crypto_tc skb_kfunc_tc kernel_crypto_provider kernel_crypto_selftest; do
      src_path="${obj_dir}/bpf/${name}_bpfel.o"
      if [[ ! -f "$src_path" ]]; then
        src_path="${bpf_asset_dir}/${name}_bpfel.o"
      fi
      [[ -f "$src_path" ]] || continue
      hash="$(sha256_file "$src_path")"
      if [[ "$first" == "0" ]]; then
        printf ',\n'
      fi
      first=0
      printf '      "%s_bpfel.o": {"sha256": "%s", "size": %s}' "$(json_escape "$name")" "$hash" "$(stat -c %s "$src_path")"
    done
    printf '\n    },\n'
    printf '    "embedded_kos": {\n'
    first=1
    for name in trustix_crypto trustix_datapath trustix_datapath_helpers; do
      src_path="${obj_dir}/kernel/${name}.ko"
      if [[ "$first" == "0" ]]; then
        printf ',\n'
      fi
      first=0
      if [[ -f "$src_path" ]]; then
        printf '      "%s.ko": {"sha256": "%s", "size": %s}' "$(json_escape "$name")" "$(sha256_file "$src_path")" "$(stat -c %s "$src_path")"
      else
        printf '      "%s.ko": {"sha256": "", "size": 0}' "$(json_escape "$name")"
      fi
    done
    printf '\n    }\n'
    printf '  }\n'
    printf '}\n'
  } >"$manifest"
}

main() {
  [[ "$(uname -s)" == "Linux" ]] || die "release build must run on Linux because .ko is target-kernel specific"
  [[ "$goos" == "linux" ]] || die "GOOS must be linux for this release script"
  need_cmd "$go_bin"
  need_cmd install
  need_cmd realpath
  need_cmd sha256sum
  need_cmd stat
  log "$("$go_bin" version)"
  log "version=${release_version} commit=${release_commit} built_at=${release_built_at}"
  rm -rf "$workdir"
  mkdir -p "$obj_dir/bpf" "$obj_dir/kernel" "$bin_dir" "$pkg_dir"
  : >"$overlay_pairs_file"

  if [[ "$build_bpf" == "1" ]]; then
    if [[ -z "$clang_bin" ]]; then
      clang_bin="$(select_clang)" || die "missing required command: clang"
    fi
    need_cmd "$clang_bin"
    log "clang=$("$clang_bin" --version | { read -r line; printf '%s' "$line"; })"
    local bpf_src_dir="${repo_root}/kernel/bpf/dataplane"
    local bpf_asset_dir="${repo_root}/internal/dataplane/ebpf/bpf"
    local name src dst package_asset
    for name in experimental_tcp_xdp experimental_tcp_kernel_crypto_xdp experimental_tcp_kernel_crypto_tx_xdp kernel_udp_xdp kernel_udp_tx_kernel_crypto_tc kernel_udp_rx_kernel_crypto_tc skb_kfunc_tc kernel_crypto_provider kernel_crypto_selftest; do
      src="${bpf_src_dir}/${name}.c"
      dst="${obj_dir}/bpf/${name}_bpfel.o"
      package_asset="${bpf_asset_dir}/${name}_bpfel.o"
      if [[ "$name" == "experimental_tcp_xdp" ]]; then
        compile_bpf_object "$src" "$dst" -DTRUSTIX_EXPERIMENTAL_TCP_XDP_RX_DIRECT_FIX_CONTROL_CHECKSUM=1
      else
        compile_bpf_object "$src" "$dst"
      fi
      add_overlay_pair "$package_asset" "$dst"
    done
    src="${bpf_src_dir}/experimental_tcp_kernel_crypto_xdp.c"
    dst="${obj_dir}/bpf/experimental_tcp_kernel_crypto_xdp_direct_bpfel.o"
    package_asset="${bpf_asset_dir}/experimental_tcp_kernel_crypto_xdp_direct_bpfel.o"
    compile_bpf_object "$src" "$dst" -DTRUSTIX_EXP_TCP_DIRECT_OPEN=1
    add_overlay_pair "$package_asset" "$dst"
  fi

  local crypto_ko=""
  if [[ "$build_ko" == "1" ]]; then
    need_cmd make
    [[ -d "$kernel_build_dir" ]] || die "kernel build directory not found: $kernel_build_dir"
    log "build crypto kernel module KDIR=${kernel_build_dir} ARCH=${kernel_arch} CROSS_COMPILE=${kernel_cross_compile:-none} mode=${crypto_build_mode}"
    case "$crypto_build_mode" in
      full)
        make_kernel_module "$crypto_module_dir"
        crypto_build_variant="full"
        ;;
      device-only)
        make_kernel_module "$crypto_module_dir" device-only
        crypto_build_variant="device-only"
        ;;
      auto)
        if make_kernel_module "$crypto_module_dir"; then
          crypto_build_variant="full"
        else
          log "crypto full build failed; retrying device-only"
          clean_kernel_module "$crypto_module_dir"
          make_kernel_module "$crypto_module_dir" device-only
          crypto_build_variant="device-only"
        fi
        ;;
      *)
        die "TRUSTIX_RELEASE_CRYPTO_BUILD_MODE must be full, device-only, or auto"
        ;;
    esac
    crypto_ko="${obj_dir}/kernel/trustix_crypto.ko"
    copy_file "${crypto_module_dir}/trustix_crypto.ko" "$crypto_ko" 0644
    copy_file "$crypto_ko" "${pkg_dir}/kernel/trustix_crypto.ko" 0644
    if [[ "$embed_ko" == "1" ]]; then
      add_overlay_pair "${repo_root}/internal/kernelmodule/assets/trustix_crypto.ko" "$crypto_ko"
    fi
    log "build full datapath kernel module KDIR=${kernel_build_dir} ARCH=${kernel_arch} CROSS_COMPILE=${kernel_cross_compile:-none}"
    make_kernel_module "$datapath_module_dir"
    local datapath_ko="${obj_dir}/kernel/trustix_datapath.ko"
    copy_file "${datapath_module_dir}/trustix_datapath.ko" "$datapath_ko" 0644
    copy_file "$datapath_ko" "${pkg_dir}/kernel/trustix_datapath.ko" 0644
    if [[ "$embed_ko" == "1" ]]; then
      add_overlay_pair "${repo_root}/internal/kernelmodule/assets/trustix_datapath.ko" "$datapath_ko"
    fi
    log "build datapath helper kernel module KDIR=${kernel_build_dir} ARCH=${kernel_arch} CROSS_COMPILE=${kernel_cross_compile:-none} mode=${datapath_helpers_build_mode}"
    case "$datapath_helpers_build_mode" in
      full)
        make_kernel_module "$datapath_helpers_module_dir"
        datapath_helpers_build_variant="full"
        ;;
      basic)
        make_kernel_module "$datapath_helpers_module_dir" basic
        datapath_helpers_build_variant="basic"
        ;;
      auto)
        if make_kernel_module "$datapath_helpers_module_dir"; then
          datapath_helpers_build_variant="full"
        else
          log "datapath helpers full build failed; retrying basic"
          clean_kernel_module "$datapath_helpers_module_dir"
          make_kernel_module "$datapath_helpers_module_dir" basic
          datapath_helpers_build_variant="basic"
        fi
        ;;
      *)
        die "TRUSTIX_RELEASE_DATAPATH_HELPERS_BUILD_MODE must be full, basic, or auto"
        ;;
    esac
    local datapath_helpers_ko="${obj_dir}/kernel/trustix_datapath_helpers.ko"
    copy_file "${datapath_helpers_module_dir}/trustix_datapath_helpers.ko" "$datapath_helpers_ko" 0644
    copy_file "$datapath_helpers_ko" "${pkg_dir}/kernel/trustix_datapath_helpers.ko" 0644
    if [[ "$embed_ko" == "1" ]]; then
      add_overlay_pair "${repo_root}/internal/kernelmodule/assets/trustix_datapath_helpers.ko" "$datapath_helpers_ko"
    fi
  fi
  if [[ "$include_ko_source" == "1" ]]; then
    log "package kernel module source"
    mkdir -p "${pkg_dir}/kernel/trustix_crypto"
    copy_file "${crypto_module_dir}/Makefile" "${pkg_dir}/kernel/trustix_crypto/Makefile" 0644
    copy_file "${crypto_module_dir}/trustix_crypto.c" "${pkg_dir}/kernel/trustix_crypto/trustix_crypto.c" 0644
    [[ -f "${crypto_module_dir}/dkms.conf" ]] && copy_file "${crypto_module_dir}/dkms.conf" "${pkg_dir}/kernel/trustix_crypto/dkms.conf" 0644
    [[ -f "${crypto_module_dir}/README.md" ]] && copy_file "${crypto_module_dir}/README.md" "${pkg_dir}/kernel/trustix_crypto/README.md" 0644
    mkdir -p "${pkg_dir}/kernel/trustix_datapath"
    copy_file "${datapath_module_dir}/Makefile" "${pkg_dir}/kernel/trustix_datapath/Makefile" 0644
    copy_file "${datapath_module_dir}/trustix_datapath.c" "${pkg_dir}/kernel/trustix_datapath/trustix_datapath.c" 0644
    [[ -f "${datapath_module_dir}/dkms.conf" ]] && copy_file "${datapath_module_dir}/dkms.conf" "${pkg_dir}/kernel/trustix_datapath/dkms.conf" 0644
    [[ -f "${datapath_module_dir}/README.md" ]] && copy_file "${datapath_module_dir}/README.md" "${pkg_dir}/kernel/trustix_datapath/README.md" 0644
    mkdir -p "${pkg_dir}/kernel/trustix_datapath_helpers"
    copy_file "${datapath_helpers_module_dir}/Makefile" "${pkg_dir}/kernel/trustix_datapath_helpers/Makefile" 0644
    copy_file "${datapath_helpers_module_dir}/trustix_datapath_helpers_internal.h" "${pkg_dir}/kernel/trustix_datapath_helpers/trustix_datapath_helpers_internal.h" 0644
    copy_file "${datapath_helpers_module_dir}/trustix_datapath_helpers_main.c" "${pkg_dir}/kernel/trustix_datapath_helpers/trustix_datapath_helpers_main.c" 0644
    copy_file "${datapath_helpers_module_dir}/trustix_datapath_helpers_kfuncs.c" "${pkg_dir}/kernel/trustix_datapath_helpers/trustix_datapath_helpers_kfuncs.c" 0644
    [[ -f "${datapath_helpers_module_dir}/dkms.conf" ]] && copy_file "${datapath_helpers_module_dir}/dkms.conf" "${pkg_dir}/kernel/trustix_datapath_helpers/dkms.conf" 0644
    [[ -f "${datapath_helpers_module_dir}/README.md" ]] && copy_file "${datapath_helpers_module_dir}/README.md" "${pkg_dir}/kernel/trustix_datapath_helpers/README.md" 0644
    mkdir -p "${pkg_dir}/kernel/bpf/dataplane"
    local bpf_src
    for bpf_src in "${repo_root}"/kernel/bpf/dataplane/*.c; do
      [[ -f "$bpf_src" ]] || continue
      copy_file "$bpf_src" "${pkg_dir}/kernel/bpf/dataplane/$(basename "$bpf_src")" 0644
    done
  fi

  local overlay_arg=""
  if [[ -s "$overlay_pairs_file" ]]; then
    write_overlay
    overlay_arg="$overlay_file"
  fi

  go_build "${bin_dir}/trustixd" ./cmd/trustixd "$overlay_arg"
  go_build "${bin_dir}/trustixctl" ./cmd/trustixctl "$overlay_arg"
  go_build "${bin_dir}/trustix-ca" ./cmd/trustix-ca "$overlay_arg"
  go_build "${bin_dir}/trustix-device" ./cmd/trustix-device "$overlay_arg"
  go_build "${bin_dir}/trustix-iptunnel-smoke" ./cmd/trustix-iptunnel-smoke "$overlay_arg"
  if [[ "$build_tests" == "1" ]]; then
    log "go test -c internal/dataplane/ebpf"
    if [[ -n "$overlay_arg" ]]; then
      GOOS="$goos" GOARCH="$goarch" "$go_bin" test -c -overlay "$overlay_arg" -ldflags "$go_ldflags" -o "${bin_dir}/ebpf.test" ./internal/dataplane/ebpf
    else
      GOOS="$goos" GOARCH="$goarch" "$go_bin" test -c -ldflags "$go_ldflags" -o "${bin_dir}/ebpf.test" ./internal/dataplane/ebpf
    fi
    log "go test -c internal/kernelmodule"
    if [[ -n "$overlay_arg" ]]; then
      GOOS="$goos" GOARCH="$goarch" "$go_bin" test -c -overlay "$overlay_arg" -ldflags "$go_ldflags" -o "${bin_dir}/kernelmodule.test" ./internal/kernelmodule
    else
      GOOS="$goos" GOARCH="$goarch" "$go_bin" test -c -ldflags "$go_ldflags" -o "${bin_dir}/kernelmodule.test" ./internal/kernelmodule
    fi
  fi

  copy_file "${repo_root}/configs/lab-a.yaml" "${pkg_dir}/configs/lab-a.yaml" 0644
  copy_file "${repo_root}/configs/lab-b.yaml" "${pkg_dir}/configs/lab-b.yaml" 0644
  cp -R "${repo_root}/docs" "${pkg_dir}/docs"
  cp -R "${repo_root}/packaging" "${pkg_dir}/packaging"
  mkdir -p "${pkg_dir}/scripts"
  local script_src script_name
  for script_src in "${repo_root}"/scripts/*.sh; do
    [[ -f "$script_src" ]] || continue
    script_name="$(basename "$script_src")"
    case "$script_name" in
      linux-iperf3-crypto-bench.sh|linux-transport-matrix-bench.sh|openwrt-full-datapath-kmod-matrix.sh)
        continue
        ;;
    esac
    copy_file "$script_src" "${pkg_dir}/scripts/${script_name}" 0755
  done
  cp -R "$bin_dir" "${pkg_dir}/bin"
  write_manifest

  cat >"${pkg_dir}/README.release.md" <<EOF
# TrustIX Linux release

Version: ${release_version}
Commit: ${release_commit}
Built on: ${release_built_at}
Target: ${goos}/${goarch}
Kernel module KDIR: ${kernel_build_dir}

The trustixd binary embeds the eBPF .o files. If TRUSTIX_RELEASE_BUILD_KO=1 and
TRUSTIX_RELEASE_EMBED_KO=1 were used, it also embeds trustix_crypto.ko,
trustix_datapath.ko, and trustix_datapath_helpers.ko.

To use the embedded .ko:

\`\`\`yaml
kernel_modules:
  trustix_crypto:
    mode: required
    path: embedded
    reload_on_upgrade: auto
    unload_on_exit: false
  trustix_datapath:
    mode: auto
    path: embedded
    reload_on_upgrade: auto
    unload_on_exit: false
  trustix_datapath_helpers:
    mode: auto
    path: embedded
    reload_on_upgrade: auto
    unload_on_exit: false
\`\`\`

The package also includes kernel/trustix_crypto.ko, kernel/trustix_datapath.ko,
and kernel/trustix_datapath_helpers.ko for hosts that prefer explicit module deployment.
Kernel modules are tied to the target kernel's symbol versions; if the packaged
.ko vermagic does not match the host kernel, rebuild from kernel/trustix_crypto
kernel/trustix_datapath, and kernel/trustix_datapath_helpers on the target host.

For systemd deployment, run:

\`\`\`bash
sudo scripts/install-systemd-linux.sh
sudo systemctl enable --now trustixd@ix-a
\`\`\`

For an existing systemd install, update in place without rewriting config,
certificates, or data directories:

\`\`\`bash
sudo scripts/trustix-update.sh --tarball /path/to/${release_name}.tar.gz --instance ix-a
\`\`\`

The template unit reads /etc/trustix/ix-a.yaml and optional
/etc/trustix/ix-a.env by default. Its ExecStartPre/ExecStopPost invoke
trustixd -cleanup-dataplane so crash restarts repair stale TrustIX-managed
TC/eBPF/VIP/sysctl/XDP state before the daemon comes back.

Run scripts/release-smoke-linux.sh against the tarball on the target Linux host
to verify startup, status/doctor metadata, embedded eBPF objects, embedded .ko
metadata, NAT/no-public reverse data-session smoke, GRE/IPIP kernel tunnel
carrier smoke, and transport TLS diagnostics. When run as root, the release
smoke also runs the packaged linux-e2e-smoke.sh TCP TLS exporter/custom-cert
path and NAT reverse path by default; set TRUSTIX_RELEASE_SMOKE_TLS=0 or
TRUSTIX_RELEASE_SMOKE_NAT_REVERSE=0 to skip those heavier netns smokes.
Run scripts/linux-clean-release-smoke.sh from a source checkout on a clean target
host to build the release, verify embedded .ko load/unload, verify the packaged
.ko through the TrustIX kernel module smoke, run packaged kernel transport e2e smokes, and
assert that no TrustIX module/netns/tmp artifacts remain.
Set TRUSTIX_RELEASE_SMOKE_CONTROL=1 to include membership and trust-policy
control-plane smokes, TRUSTIX_RELEASE_SMOKE_3IX=1 to include the three-IX
experimental_tcp data-plane smoke, and TRUSTIX_RELEASE_SMOKE_EXP_TCP_BENCH=1
to include the experimental_tcp benchmark/smoke counter summary.
EOF

  local tar_path="${out_root}/${release_name}.tar.gz"
  log "package ${tar_path}"
  tar -C "$pkg_dir" -czf "$tar_path" .
  log "done: ${tar_path}"
}

main "$@"
