#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
module_dir="${TRUSTIX_FULL_DATAPATH_MODULE_DIR:-${repo_root}/kernel/trustix_datapath}"
module_ko="${TRUSTIX_FULL_DATAPATH_KO:-}"
module_kdir="${TRUSTIX_FULL_DATAPATH_KDIR:-${KDIR:-}}"
module_arch="${TRUSTIX_FULL_DATAPATH_ARCH:-${ARCH:-}}"
module_cross_compile="${TRUSTIX_FULL_DATAPATH_CROSS_COMPILE:-${CROSS_COMPILE:-}}"
kernelmodule_test_bin="${TRUSTIX_FULL_DATAPATH_KERNELMODULE_TEST_BIN:-${TRUSTIX_KERNEL_KERNELMODULE_TEST_BIN:-}}"
keep_loaded="${TRUSTIX_FULL_DATAPATH_KEEP_LOADED:-1}"
enable_features="${TRUSTIX_FULL_DATAPATH_ENABLE_FEATURES:-128}"
extra_module_params="${TRUSTIX_FULL_DATAPATH_EXTRA_PARAMS:-}"
expect_active="${TRUSTIX_FULL_DATAPATH_EXPECT_ACTIVE:-1}"
loaded_by_script=0
clean_legacy_modules="${TRUSTIX_FULL_DATAPATH_CLEAN_LEGACY_MODULES:-1}"

log() {
  printf '[trustix-full-datapath] %s\n' "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

host_kernel_arch() {
  case "$(uname -m)" in
    x86_64|amd64) printf 'x86\n' ;;
    aarch64|arm64) printf 'arm64\n' ;;
    armv7l|armv6l|armhf|arm) printf 'arm\n' ;;
    *) uname -m ;;
  esac
}

read_module_param() {
  local name="$1"
  local path="/sys/module/trustix_datapath/parameters/${name}"
  [[ -r "$path" ]] || return 1
  cat "$path"
}

truthy() {
  case "${1:-0}" in
    1|true|yes|on|enabled) return 0 ;;
    *) return 1 ;;
  esac
}

append_module_param_if_missing() {
  local params="$1"
  local assignment="$2"
  local key="${assignment%%=*}"
  local field existing
  for field in $params; do
    existing="${field%%=*}"
    if [[ "$existing" == "$key" ]]; then
      printf '%s\n' "$params"
      return
    fi
  done
  if [[ -n "$params" ]]; then
    printf '%s %s\n' "$params" "$assignment"
  else
    printf '%s\n' "$assignment"
  fi
}

has_full_datapath_bit() {
  local value="$1"
  [[ "$value" =~ ^[0-9]+$ ]] || return 1
  [[ "$(( (value / 128) % 2 ))" -eq 1 ]]
}

has_feature_active_flag() {
  local value="$1"
  [[ "$value" =~ ^[0-9]+$ ]] || return 1
  [[ "$(( (value / 2) % 2 ))" -eq 1 ]]
}

cleanup() {
  if [[ "$loaded_by_script" == "1" && "$keep_loaded" != "1" ]]; then
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      rmmod trustix_datapath >/dev/null 2>&1 && break || true
      sleep 0.2
    done
  fi
}
trap cleanup EXIT

require_linux_root() {
  [[ "$(uname -s)" == "Linux" ]] || die "linux-full-datapath-module-smoke must run on Linux"
  [[ "${EUID:-$(id -u)}" == "0" ]] || die "linux-full-datapath-module-smoke must run as root to load kernel modules"
}

cleanup_legacy_modules() {
  [[ "$clean_legacy_modules" == "1" ]] || return 0
  rmmod trustix_kernel >/dev/null 2>&1 || true
  rmmod trustix_bpf_aead >/dev/null 2>&1 || true
}

make_module_source() {
  if [[ -n "$module_cross_compile" ]]; then
    make -C "$module_dir" KDIR="$module_kdir" ARCH="$module_arch" CROSS_COMPILE="$module_cross_compile" V=0
  else
    make -C "$module_dir" KDIR="$module_kdir" ARCH="$module_arch" V=0
  fi
}

build_and_load_module() {
  need_cmd insmod
  need_cmd lsmod
  if lsmod | awk '{print $1}' | grep -qx trustix_datapath; then
    log "trustix_datapath is already loaded"
    return 0
  fi
  local ko_path="$module_ko"
  if [[ -n "$ko_path" ]]; then
    [[ -f "$ko_path" ]] || die "TRUSTIX_FULL_DATAPATH_KO does not exist: $ko_path"
    log "using prebuilt TrustIX full datapath module $ko_path"
  else
    [[ -d "$module_dir" ]] || die "module directory not found: $module_dir"
    [[ -f "$module_dir/Makefile" ]] || die "module Makefile not found: $module_dir/Makefile"
    need_cmd make
    module_kdir="${module_kdir:-/lib/modules/$(uname -r)/build}"
    module_arch="${module_arch:-$(host_kernel_arch)}"
    log "building TrustIX full datapath module in $module_dir KDIR=${module_kdir:-default} ARCH=${module_arch:-default} CROSS_COMPILE=${module_cross_compile:-none}"
    make_module_source
    ko_path="$module_dir/trustix_datapath.ko"
  fi
  if has_full_datapath_bit "$enable_features"; then
    extra_module_params="$(append_module_param_if_missing "$extra_module_params" "rx_worker_inject=1")"
    extra_module_params="$(append_module_param_if_missing "$extra_module_params" "tx_plaintext=1")"
  fi
  log "loading trustix_datapath.ko enable_features=${enable_features} extra=${extra_module_params:-none}"
  # shellcheck disable=SC2086
  insmod "$ko_path" enable_features="$enable_features" $extra_module_params
  loaded_by_script=1
  lsmod | grep trustix_datapath >/dev/null || die "trustix_datapath did not appear in lsmod"
}

verify_sysfs() {
  [[ -e /dev/trustix_datapath ]] || die "trustix_datapath device ioctl node is missing"
  local abi features safe unsafe selftests failures flags
  abi="$(read_module_param abi_version || true)"
  features="$(read_module_param features || true)"
  safe="$(read_module_param safe_features || true)"
  unsafe="$(read_module_param unsafe_features || true)"
  selftests="$(read_module_param selftests || true)"
  failures="$(read_module_param selftest_failures || true)"
  flags="$(read_module_param flags || true)"
  [[ "$abi" == "1" ]] || die "unexpected abi_version=${abi:-missing}"
  [[ "$selftests" == "1023" ]] || die "expected selftests=1023, got ${selftests:-missing}"
  [[ "$failures" == "0" ]] || die "expected selftest_failures=0, got ${failures:-missing}"
  [[ "$features" =~ ^[0-9]+$ ]] || die "unexpected features=${features:-missing}"
  [[ "$safe" =~ ^[0-9]+$ ]] || die "unexpected safe_features=${safe:-missing}"
  [[ "$unsafe" =~ ^[0-9]+$ ]] || die "unexpected unsafe_features=${unsafe:-missing}"
  [[ "$flags" =~ ^[0-9]+$ ]] || die "unexpected flags=${flags:-missing}"
  if [[ "$(( flags % 2 ))" -eq 0 ]]; then
    die "TIXT selftest OK flag is missing: flags=${flags:-missing}"
  fi
  if truthy "$expect_active"; then
    if ! has_full_datapath_bit "$enable_features"; then
      die "TRUSTIX_FULL_DATAPATH_EXPECT_ACTIVE=1 requires enable_features bit 128"
    fi
    if ! has_full_datapath_bit "$features"; then
      die "full datapath feature did not become active: features=${features} safe=${safe} unsafe=${unsafe} flags=${flags}"
    fi
    if ! has_full_datapath_bit "$safe"; then
      die "full datapath feature is not marked safe: features=${features} safe=${safe} unsafe=${unsafe} flags=${flags}"
    fi
    if has_full_datapath_bit "$unsafe"; then
      die "full datapath feature is still marked unsafe: features=${features} safe=${safe} unsafe=${unsafe} flags=${flags}"
    fi
    if ! has_feature_active_flag "$flags"; then
      die "feature-active flag is missing: flags=${flags}"
    fi
  else
    if has_full_datapath_bit "$features" || has_full_datapath_bit "$safe" || has_feature_active_flag "$flags"; then
      die "full datapath feature unexpectedly active: features=${features} safe=${safe} flags=${flags}"
    fi
  fi
  log "verified sysfs abi=${abi} selftests=${selftests} failures=${failures} features=${features} safe=${safe} unsafe=${unsafe} flags=${flags}"
}

run_ioctl_test() {
  if [[ -n "$kernelmodule_test_bin" ]]; then
    [[ -x "$kernelmodule_test_bin" ]] || die "TRUSTIX_FULL_DATAPATH_KERNELMODULE_TEST_BIN is not executable: $kernelmodule_test_bin"
    log "running prebuilt full datapath ioctl selftest"
    "$kernelmodule_test_bin" -test.run '^TestTrustIXFullDatapathDeviceQueryAndSelftest$' -test.v
    return 0
  fi
  need_cmd go
  log "running full datapath ioctl selftest through go test"
  (cd "$repo_root" && go test ./internal/kernelmodule -run '^TestTrustIXFullDatapathDeviceQueryAndSelftest$' -v)
}

main() {
  require_linux_root
  cleanup_legacy_modules
  build_and_load_module
  verify_sysfs
  run_ioctl_test
  log "ok: trustix_datapath loaded and verified"
}

main "$@"
