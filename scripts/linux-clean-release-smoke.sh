#!/usr/bin/env bash
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

release_goarch="$(normalize_goarch "${GOARCH:-$(host_goarch)}")"
workdir="${TRUSTIX_CLEAN_RELEASE_SMOKE_WORKDIR:-$(mktemp -d /tmp/trustix-clean-release.XXXXXX)}"
keep="${TRUSTIX_CLEAN_RELEASE_SMOKE_KEEP:-0}"
release_name="${TRUSTIX_CLEAN_RELEASE_SMOKE_RELEASE_NAME:-trustix-clean-linux-${release_goarch}}"
run_tls="${TRUSTIX_CLEAN_RELEASE_SMOKE_TLS:-1}"
run_nat_reverse="${TRUSTIX_CLEAN_RELEASE_SMOKE_NAT_REVERSE:-1}"
run_kernel="${TRUSTIX_CLEAN_RELEASE_SMOKE_KERNEL:-1}"
run_kernel_udp="${TRUSTIX_CLEAN_RELEASE_SMOKE_KERNEL_UDP:-1}"
run_kernel_udp_3ix="${TRUSTIX_CLEAN_RELEASE_SMOKE_3IX_KERNEL_UDP:-1}"
run_tix_tcp_kernel="${TRUSTIX_CLEAN_RELEASE_SMOKE_TIX_TCP_KERNEL:-1}"
tix_tcp_kernel_capable=1
ping_count="${TRUSTIX_CLEAN_RELEASE_SMOKE_PING_COUNT:-1}"
ping_size="${TRUSTIX_CLEAN_RELEASE_SMOKE_PING_SIZE:-56}"
ping_parallel="${TRUSTIX_CLEAN_RELEASE_SMOKE_PING_PARALLEL:-1}"
ping_rounds="${TRUSTIX_CLEAN_RELEASE_SMOKE_PING_ROUNDS:-1}"
udp_burst_packets="${TRUSTIX_CLEAN_RELEASE_SMOKE_UDP_BURST_PACKETS:-16}"
udp_burst_size="${TRUSTIX_CLEAN_RELEASE_SMOKE_UDP_BURST_SIZE:-256}"
udp_burst_parallel="${TRUSTIX_CLEAN_RELEASE_SMOKE_UDP_BURST_PARALLEL:-1}"
udp_burst_rounds="${TRUSTIX_CLEAN_RELEASE_SMOKE_UDP_BURST_ROUNDS:-1}"
burst_timeout="${TRUSTIX_CLEAN_RELEASE_SMOKE_BURST_TIMEOUT:-10}"

log() {
  printf '[trustix-clean-release] %s\n' "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

truthy() {
  case "${1:-0}" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

cleanup_trustix_state() {
  local kernel
  local repo_path
  local keep_path
  kernel="$(uname -r)"
  repo_path="$(realpath -m "$repo_root" 2>/dev/null || printf '%s' "$repo_root")"
  keep_path="$(realpath -m "$workdir" 2>/dev/null || printf '%s' "$workdir")"
  set +e
  mapfile -t pids < <(ps -eo pid=,comm=,args= | awk '$2 ~ /^trustix/ || $0 ~ /\/tmp\/trustix/ {print $1}')
  if ((${#pids[@]})); then
    kill -INT "${pids[@]}" 2>/dev/null || true
    sleep 1
    kill -TERM "${pids[@]}" 2>/dev/null || true
  fi
  for ns in $(ip netns list 2>/dev/null | awk '/^tix-/ {print $1}'); do
    ip netns del "$ns" 2>/dev/null || true
  done
  for module in trustix_datapath trustix_datapath_helpers trustix_crypto; do
    if grep -q "^${module} " /proc/modules 2>/dev/null; then
      for _ in 1 2 3 4 5 6 7 8 9 10; do
        rmmod "$module" 2>/dev/null && break || true
        sleep 0.2
      done
    fi
    rm -f "/lib/modules/${kernel}/extra/${module}.ko"
  done
  rmdir "/lib/modules/${kernel}/extra" 2>/dev/null || true
  find /etc/modules-load.d /etc/modprobe.d -maxdepth 1 -type f -iname '*trustix*' -delete 2>/dev/null || true
  find /tmp /var/tmp -mindepth 1 -maxdepth 1 \( -name 'trustix-*' -o -name 'trustix.*' -o -name 'trustix_*' \) -printf '%p\n' 2>/dev/null | while IFS= read -r path; do
    local real_path
    real_path="$(realpath -m "$path" 2>/dev/null || printf '%s' "$path")"
    [[ "$real_path" == "$repo_path" || "$real_path" == "$keep_path" ]] && continue
    rm -rf -- "$path"
  done
  if command -v depmod >/dev/null 2>&1; then
    depmod -a "$kernel" 2>/dev/null || true
  fi
  set -e
}

assert_clean_trustix_state() {
  local leftovers
  local repo_path
  local keep_path
  repo_path="$(realpath -m "$repo_root" 2>/dev/null || printf '%s' "$repo_root")"
  keep_path="$(realpath -m "$workdir" 2>/dev/null || printf '%s' "$workdir")"
  for module in trustix_datapath trustix_datapath_helpers trustix_crypto; do
    if grep -q "^${module} " /proc/modules 2>/dev/null; then
      lsmod | awk -v module="$module" '$1==module{print}' >&2 || true
      die "${module} is still loaded"
    fi
    if modinfo -n "$module" >/dev/null 2>&1; then
      modinfo -n "$module" >&2 || true
      die "${module} is still present in the module tree"
    fi
  done
  leftovers="$(find /tmp /var/tmp -mindepth 1 -maxdepth 1 \( -name 'trustix-*' -o -name 'trustix.*' -o -name 'trustix_*' \) -printf '%p\n' 2>/dev/null | while IFS= read -r path; do
    local real_path
    real_path="$(realpath -m "$path" 2>/dev/null || printf '%s' "$path")"
    [[ "$real_path" == "$repo_path" || "$real_path" == "$keep_path" ]] && continue
    printf '%s\n' "$path"
  done | sort || true)"
  if [[ -n "$leftovers" ]]; then
    printf '%s\n' "$leftovers" >&2
    die "TrustIX temp artifacts remain"
  fi
  leftovers="$(ip netns list 2>/dev/null | awk '/^tix-/ {print $1}' || true)"
  if [[ -n "$leftovers" ]]; then
    printf '%s\n' "$leftovers" >&2
    die "TrustIX netns artifacts remain"
  fi
}

cleanup() {
  set +e
  for module in trustix_datapath trustix_datapath_helpers trustix_crypto; do
    if grep -q "^${module} " /proc/modules 2>/dev/null; then
      for _ in 1 2 3 4 5 6 7 8 9 10; do
        rmmod "$module" 2>/dev/null && break || true
        sleep 0.2
      done
    fi
  done
  for ns in $(ip netns list 2>/dev/null | awk '/^tix-/ {print $1}'); do
    ip netns del "$ns" 2>/dev/null || true
  done
  if [[ "$keep" != "1" ]]; then
    rm -rf "$workdir"
  else
    log "kept workdir: $workdir"
  fi
}
trap cleanup EXIT

run_kernel_udp_e2e() {
  local package_dir="$1"
  log "run packaged kernel_udp e2e"
  env \
    TRUSTIX_E2E_BIN_DIR="${package_dir}/bin" \
    TRUSTIX_E2E_WORKDIR="${workdir}/kernel-udp-e2e" \
    TRUSTIX_E2E_TRANSPORT=kernel_udp \
    TRUSTIX_E2E_CRASH_RESTART=0 \
    TRUSTIX_E2E_PING_COUNT="$ping_count" \
    TRUSTIX_E2E_PING_SIZE="$ping_size" \
    TRUSTIX_E2E_PING_PARALLEL="$ping_parallel" \
    TRUSTIX_E2E_PING_ROUNDS="$ping_rounds" \
    TRUSTIX_E2E_UDP_BURST_PACKETS="$udp_burst_packets" \
    TRUSTIX_E2E_UDP_BURST_SIZE="$udp_burst_size" \
    TRUSTIX_E2E_UDP_BURST_PARALLEL="$udp_burst_parallel" \
    TRUSTIX_E2E_UDP_BURST_ROUNDS="$udp_burst_rounds" \
    TRUSTIX_E2E_BURST_TIMEOUT="$burst_timeout" \
    bash "${package_dir}/scripts/linux-e2e-smoke.sh"
}

run_nat_reverse_kernel_udp_e2e() {
  local package_dir="$1"
  log "run packaged NAT/no-public reverse kernel_udp e2e"
  env \
    TRUSTIX_E2E_BIN_DIR="${package_dir}/bin" \
    TRUSTIX_E2E_WORKDIR="${workdir}/nat-reverse-kernel-udp-e2e" \
    TRUSTIX_E2E_TRANSPORT=kernel_udp \
    TRUSTIX_E2E_NAT_REVERSE=1 \
    TRUSTIX_E2E_CRASH_RESTART=0 \
    TRUSTIX_E2E_PING_COUNT="$ping_count" \
    TRUSTIX_E2E_PING_SIZE="$ping_size" \
    TRUSTIX_E2E_PING_PARALLEL="$ping_parallel" \
    TRUSTIX_E2E_PING_ROUNDS="$ping_rounds" \
    TRUSTIX_E2E_UDP_BURST_PACKETS="$udp_burst_packets" \
    TRUSTIX_E2E_UDP_BURST_SIZE="$udp_burst_size" \
    TRUSTIX_E2E_UDP_BURST_PARALLEL="$udp_burst_parallel" \
    TRUSTIX_E2E_UDP_BURST_ROUNDS="$udp_burst_rounds" \
    TRUSTIX_E2E_BURST_TIMEOUT="$burst_timeout" \
    bash "${package_dir}/scripts/linux-e2e-smoke.sh"
}

run_kernel_udp_3ix_e2e() {
  local package_dir="$1"
  log "run packaged 3-IX kernel_udp e2e"
  env \
    TRUSTIX_3IX_E2E_BIN_DIR="${package_dir}/bin" \
    TRUSTIX_3IX_E2E_WORKDIR="${workdir}/kernel-udp-3ix-e2e" \
    TRUSTIX_3IX_E2E_TRANSPORT=kernel_udp \
    TRUSTIX_3IX_E2E_CRASH_RESTART=0 \
    TRUSTIX_3IX_E2E_PING_COUNT="$ping_count" \
    TRUSTIX_3IX_E2E_PING_SIZE="$ping_size" \
    TRUSTIX_3IX_E2E_PING_PARALLEL="$ping_parallel" \
    TRUSTIX_3IX_E2E_PING_ROUNDS="$ping_rounds" \
    TRUSTIX_3IX_E2E_UDP_BURST_PACKETS="$udp_burst_packets" \
    TRUSTIX_3IX_E2E_UDP_BURST_SIZE="$udp_burst_size" \
    TRUSTIX_3IX_E2E_UDP_BURST_PARALLEL="$udp_burst_parallel" \
    TRUSTIX_3IX_E2E_UDP_BURST_ROUNDS="$udp_burst_rounds" \
    TRUSTIX_3IX_E2E_BURST_TIMEOUT="$burst_timeout" \
    bash "${package_dir}/scripts/linux-three-ix-e2e-smoke.sh"
}

run_tix_tcp_kernel_e2e() {
  local package_dir="$1"
  local ko="${package_dir}/kernel/trustix_crypto.ko"
  [[ -f "$ko" ]] || die "release package has no kernel/trustix_crypto.ko"
  log "load packaged .ko for tix_tcp kernel e2e"
  insmod "$ko"
  trap 'cleanup' EXIT
  env \
    TRUSTIX_E2E_BIN_DIR="${package_dir}/bin" \
    TRUSTIX_E2E_WORKDIR="${workdir}/tix-tcp-kernel-e2e" \
    TRUSTIX_E2E_TRANSPORT=tix_tcp \
    TRUSTIX_E2E_CRYPTO_PLACEMENT=kernel \
    TRUSTIX_E2E_CRASH_RESTART=0 \
    TRUSTIX_E2E_PING_COUNT="$ping_count" \
    TRUSTIX_E2E_PING_SIZE="$ping_size" \
    TRUSTIX_E2E_PING_PARALLEL="$ping_parallel" \
    TRUSTIX_E2E_PING_ROUNDS="$ping_rounds" \
    TRUSTIX_E2E_UDP_BURST_PACKETS="$udp_burst_packets" \
    TRUSTIX_E2E_UDP_BURST_SIZE="$udp_burst_size" \
    TRUSTIX_E2E_UDP_BURST_PARALLEL="$udp_burst_parallel" \
    TRUSTIX_E2E_UDP_BURST_ROUNDS="$udp_burst_rounds" \
    TRUSTIX_E2E_BURST_TIMEOUT="$burst_timeout" \
    bash "${package_dir}/scripts/linux-e2e-smoke.sh"
  rmmod trustix_crypto
}

main() {
  [[ "$(uname -s)" == "Linux" ]] || die "clean release smoke must run on Linux"
  [[ "${EUID:-$(id -u)}" == "0" ]] || die "clean release smoke must run as root"
  need_cmd go
  need_cmd clang
  need_cmd make
  need_cmd tar
  need_cmd ip
  need_cmd insmod
  need_cmd rmmod
  need_cmd modinfo

  log "workdir: $workdir"
  cleanup_trustix_state
  assert_clean_trustix_state

  mkdir -p "$workdir"
  log "build release from clean host state"
  env \
    GOARCH="$release_goarch" \
    TRUSTIX_RELEASE_OUT="${workdir}/release" \
    TRUSTIX_RELEASE_NAME="$release_name" \
    TRUSTIX_RELEASE_BUILD_BPF=1 \
    TRUSTIX_RELEASE_BUILD_KO=1 \
    TRUSTIX_RELEASE_EMBED_KO=1 \
    TRUSTIX_RELEASE_BUILD_TESTS=1 \
    bash "${repo_root}/scripts/build-release-linux.sh"

  local tarball="${workdir}/release/${release_name}.tar.gz"
  [[ -f "$tarball" ]] || die "release tarball was not produced: $tarball"

  log "run release smoke with embedded .ko load/unload"
  env \
    TRUSTIX_RELEASE_SMOKE_WORKDIR="${workdir}/release-smoke" \
    TRUSTIX_RELEASE_SMOKE_TLS="$run_tls" \
    TRUSTIX_RELEASE_SMOKE_NAT_REVERSE="$run_nat_reverse" \
    TRUSTIX_RELEASE_SMOKE_REQUIRE_MODULES=1 \
    TRUSTIX_RELEASE_SMOKE_UNLOAD_MODULES_ON_EXIT=1 \
    TRUSTIX_E2E_PING_COUNT="$ping_count" \
    TRUSTIX_E2E_PING_SIZE="$ping_size" \
    TRUSTIX_E2E_PING_PARALLEL="$ping_parallel" \
    TRUSTIX_E2E_PING_ROUNDS="$ping_rounds" \
    TRUSTIX_E2E_UDP_BURST_PACKETS="$udp_burst_packets" \
    TRUSTIX_E2E_UDP_BURST_SIZE="$udp_burst_size" \
    TRUSTIX_E2E_UDP_BURST_PARALLEL="$udp_burst_parallel" \
    TRUSTIX_E2E_UDP_BURST_ROUNDS="$udp_burst_rounds" \
    TRUSTIX_E2E_BURST_TIMEOUT="$burst_timeout" \
    bash "${repo_root}/scripts/release-smoke-linux.sh" "$tarball"
  assert_clean_trustix_state

  local package_dir="${workdir}/package"
  mkdir -p "$package_dir"
  tar -C "$package_dir" -xzf "$tarball"

  if truthy "$run_kernel"; then
    log "run TrustIX kernel module smoke with release-packaged .ko"
    set +e
    env \
      TRUSTIX_KERNEL_KO="${package_dir}/kernel/trustix_crypto.ko" \
      TRUSTIX_KERNEL_TEST_BIN="${package_dir}/bin/ebpf.test" \
      TRUSTIX_KERNEL_KERNELMODULE_TEST_BIN="${package_dir}/bin/kernelmodule.test" \
      TRUSTIX_KERNEL_EXPERIMENTAL_VAES=1 \
      TRUSTIX_KERNEL_EXPECT_VAES=auto \
      TRUSTIX_KERNEL_ALLOW_UNSUPPORTED_KERNEL=1 \
      TRUSTIX_KERNEL_KEEP_LOADED=0 \
      bash "${package_dir}/scripts/linux-kernel-module-smoke.sh"
    local kernel_rc=$?
    set -e
    if [[ "$kernel_rc" == "2" ]]; then
      log "kernel AEAD kfunc provider unsupported on this kernel; strict kernel crypto e2e will be skipped"
      tix_tcp_kernel_capable=0
    elif [[ "$kernel_rc" != "0" ]]; then
      die "TrustIX kernel module smoke failed with exit code ${kernel_rc}"
    fi
    cleanup_trustix_state
    assert_clean_trustix_state

    log "run TrustIX full datapath module smoke with release-packaged .ko"
    env \
      TRUSTIX_FULL_DATAPATH_KO="${package_dir}/kernel/trustix_datapath.ko" \
      TRUSTIX_FULL_DATAPATH_KERNELMODULE_TEST_BIN="${package_dir}/bin/kernelmodule.test" \
      TRUSTIX_FULL_DATAPATH_KEEP_LOADED=0 \
      bash "${package_dir}/scripts/linux-full-datapath-module-smoke.sh"
    cleanup_trustix_state
    assert_clean_trustix_state

    log "run TrustIX datapath module smoke with release-packaged .ko"
    env \
      TRUSTIX_DATAPATH_KO="${package_dir}/kernel/trustix_datapath_helpers.ko" \
      TRUSTIX_DATAPATH_KERNELMODULE_TEST_BIN="${package_dir}/bin/kernelmodule.test" \
      TRUSTIX_DATAPATH_KEEP_LOADED=0 \
      bash "${package_dir}/scripts/linux-datapath-module-smoke.sh"
    cleanup_trustix_state
    assert_clean_trustix_state
  fi

  if truthy "$run_kernel_udp"; then
    run_kernel_udp_e2e "$package_dir"
    assert_clean_trustix_state
    if truthy "$run_nat_reverse"; then
      run_nat_reverse_kernel_udp_e2e "$package_dir"
      assert_clean_trustix_state
    fi
  fi

  if truthy "$run_kernel_udp_3ix"; then
    run_kernel_udp_3ix_e2e "$package_dir"
    assert_clean_trustix_state
  fi

  if truthy "$run_tix_tcp_kernel" && [[ "$tix_tcp_kernel_capable" == "1" ]]; then
    run_tix_tcp_kernel_e2e "$package_dir"
    assert_clean_trustix_state
  elif truthy "$run_tix_tcp_kernel"; then
    log "skip tix_tcp kernel crypto e2e: kernel AEAD kfunc provider unsupported on this kernel"
  fi

  log "ok: clean release build, embedded .ko lifecycle, packaged .ko smoke, e2e cleanup checks passed"
}

main "$@"
