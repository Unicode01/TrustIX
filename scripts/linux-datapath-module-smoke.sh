#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
module_dir="${TRUSTIX_DATAPATH_MODULE_DIR:-${repo_root}/kernel/trustix_datapath_helpers}"
module_ko="${TRUSTIX_DATAPATH_KO:-}"
module_kdir="${TRUSTIX_DATAPATH_KDIR:-${KDIR:-}}"
module_arch="${TRUSTIX_DATAPATH_ARCH:-${ARCH:-}}"
module_cross_compile="${TRUSTIX_DATAPATH_CROSS_COMPILE:-${CROSS_COMPILE:-}}"
module_build_mode="${TRUSTIX_DATAPATH_BUILD_MODE:-${TRUSTIX_DATAPATH_HELPERS_BUILD_MODE:-full}}"
kernelmodule_test_bin="${TRUSTIX_DATAPATH_KERNELMODULE_TEST_BIN:-${TRUSTIX_KERNEL_KERNELMODULE_TEST_BIN:-}}"
keep_loaded="${TRUSTIX_DATAPATH_KEEP_LOADED:-1}"
enable_features="${TRUSTIX_DATAPATH_ENABLE_FEATURES:-832}"
extra_module_params="${TRUSTIX_DATAPATH_EXTRA_MODULE_PARAMS:-}"
loaded_by_script=0
loaded_variant=""
reload_loaded_module=0

if [[ -z "$kernelmodule_test_bin" && -x "${repo_root}/bin/kernelmodule.test" ]]; then
  kernelmodule_test_bin="${repo_root}/bin/kernelmodule.test"
fi

log() {
  printf '[trustix-datapath] %s\n' "$*" >&2
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

truthy() {
  case "${1:-0}" in
    1|true|yes|on|Y|y) return 0 ;;
    *) return 1 ;;
  esac
}

read_module_param() {
  local name="$1"
  local path="/sys/module/trustix_datapath_helpers/parameters/${name}"
  [[ -r "$path" ]] || return 1
  cat "$path"
}

param_is_yes() {
  local name="$1"
  local value
  value="$(read_module_param "$name")" || return 1
  printf '%s\n' "$value" | grep -qi '^Y'
}

request_loaded_module_reload() {
  local reason="$1"
  reload_loaded_module=1
  log "loaded trustix_datapath_helpers needs reload: ${reason}"
}

apply_loaded_bool_param() {
  local name="$1"
  local raw="$2"
  local param="/sys/module/trustix_datapath_helpers/parameters/${name}"
  [[ -w "$param" ]] || die "trustix_datapath_helpers is loaded but ${name} parameter is not writable"
  if truthy "$raw"; then
    if ! param_is_yes "$name"; then
      printf '1\n' >"$param" || die "failed to enable ${name} on the loaded trustix_datapath_helpers module"
    fi
    param_is_yes "$name" || die "trustix_datapath_helpers is already loaded without ${name}=1; unload it or set ${name}=0"
    return 0
  fi
  if param_is_yes "$name"; then
    printf '0\n' >"$param" || die "failed to disable ${name} on the loaded trustix_datapath_helpers module"
  fi
  if param_is_yes "$name"; then
    die "trustix_datapath_helpers is already loaded with ${name}=1; unload it or set ${name}=1"
  fi
}

assert_loaded_bool_param_disabled() {
  local name="$1"
  local raw="$2"
  if truthy "$raw"; then
    die "${name}=1 is hard-disabled for the first release"
  fi
  if param_is_yes "$name"; then
    die "trustix_datapath_helpers is already loaded with hard-disabled ${name}=1"
  fi
}

apply_loaded_extra_params() {
  local token name value param
  for token in $extra_module_params; do
    case "$token" in
      *=*)
        name="${token%%=*}"
        value="${token#*=}"
        ;;
      *)
        die "invalid TRUSTIX_DATAPATH_EXTRA_MODULE_PARAMS token: $token"
        ;;
    esac
    case "$name" in
      tixt_tx_plain_skip_sequence|tixt_tx_plain_ack_only)
        apply_loaded_bool_param "$name" "$value"
        ;;
      route_tcp_gso)
        if truthy "$value"; then
          param="/sys/module/trustix_datapath_helpers/parameters/${name}"
          [[ -r "$param" ]] || die "trustix_datapath_helpers is loaded but ${name} parameter is missing"
          param_is_yes "$name" || request_loaded_module_reload "${name}=1 requested but loaded module has ${name}=0"
        elif param_is_yes "$name"; then
          request_loaded_module_reload "${name}=0 requested but loaded module has ${name}=1"
        fi
        ;;
      route_tcp_gso_async|route_tcp_gso_async_dev_xmit)
        if truthy "$value"; then
          param="/sys/module/trustix_datapath_helpers/parameters/${name}"
          [[ -r "$param" ]] || die "trustix_datapath_helpers is loaded but ${name} parameter is missing"
          param_is_yes "$name" || request_loaded_module_reload "${name}=1 requested but loaded module has ${name}=0"
        elif param_is_yes "$name"; then
          request_loaded_module_reload "${name}=0 requested but loaded module has ${name}=1"
        fi
        ;;
      route_tcp_xmit_worker)
        if truthy "$value"; then
          param="/sys/module/trustix_datapath_helpers/parameters/${name}"
          [[ -r "$param" ]] || die "trustix_datapath_helpers is loaded but ${name} parameter is missing"
          param_is_yes "$name" || request_loaded_module_reload "${name}=1 requested but loaded module has ${name}=0"
        elif param_is_yes "$name"; then
          request_loaded_module_reload "${name}=0 requested but loaded module has ${name}=1"
        fi
        ;;
      route_tcp_xmit_worker_steal)
        assert_loaded_bool_param_disabled "$name" "$value"
        ;;
      *)
        param="/sys/module/trustix_datapath_helpers/parameters/${name}"
        [[ -w "$param" ]] || die "trustix_datapath_helpers is loaded but ${name} parameter is not writable"
        printf '%s\n' "$value" >"$param" || die "failed to set ${name} on the loaded trustix_datapath_helpers module"
        ;;
    esac
  done
}

make_module_source() {
  local target="${1:-}"
  if [[ -n "$target" && -n "$module_cross_compile" ]]; then
    make -C "$module_dir" "$target" KDIR="$module_kdir" ARCH="$module_arch" CROSS_COMPILE="$module_cross_compile" V=0
  elif [[ -n "$target" ]]; then
    make -C "$module_dir" "$target" KDIR="$module_kdir" ARCH="$module_arch" V=0
  elif [[ -n "$module_cross_compile" ]]; then
    make -C "$module_dir" KDIR="$module_kdir" ARCH="$module_arch" CROSS_COMPILE="$module_cross_compile" V=0
  else
    make -C "$module_dir" KDIR="$module_kdir" ARCH="$module_arch" V=0
  fi
}

clean_module_source() {
  if [[ -n "$module_cross_compile" ]]; then
    make -C "$module_dir" KDIR="$module_kdir" ARCH="$module_arch" CROSS_COMPILE="$module_cross_compile" V=0 clean >/dev/null 2>&1 || true
  else
    make -C "$module_dir" KDIR="$module_kdir" ARCH="$module_arch" V=0 clean >/dev/null 2>&1 || true
  fi
}

cleanup() {
  if [[ "$loaded_by_script" == "1" && "$keep_loaded" != "1" ]]; then
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      rmmod trustix_datapath_helpers >/dev/null 2>&1 && break || true
      sleep 0.2
    done
  fi
}
trap cleanup EXIT

unload_loaded_module_for_reload() {
  local reason="$1"
  log "unloading trustix_datapath_helpers for reload: ${reason}"
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if rmmod trustix_datapath_helpers >/dev/null 2>&1; then
      reload_loaded_module=0
      return 0
    fi
    sleep 0.2
  done
  die "failed to unload trustix_datapath_helpers for reload; module may still be in use"
}

require_linux_root() {
  [[ "$(uname -s)" == "Linux" ]] || die "linux-datapath-module-smoke must run on Linux"
  [[ "${EUID:-$(id -u)}" == "0" ]] || die "linux-datapath-module-smoke must run as root to load kernel modules"
}

build_and_load_module() {
  need_cmd insmod
  need_cmd lsmod

  if lsmod | awk '{print $1}' | grep -qx trustix_datapath_helpers; then
    log "trustix_datapath_helpers is already loaded"
    apply_loaded_extra_params
    if [[ "$reload_loaded_module" != "1" ]]; then
      return 0
    fi
    unload_loaded_module_for_reload "load-time parameter mismatch"
  fi

  local ko_path="$module_ko"
  if [[ -n "$ko_path" ]]; then
    [[ -f "$ko_path" ]] || die "TRUSTIX_DATAPATH_KO does not exist: $ko_path"
    log "using prebuilt TrustIX datapath module $ko_path"
  else
    [[ -d "$module_dir" ]] || die "module directory not found: $module_dir"
    [[ -f "$module_dir/Makefile" ]] || die "module Makefile not found: $module_dir/Makefile"
    need_cmd make
    module_kdir="${module_kdir:-/lib/modules/$(uname -r)/build}"
    module_arch="${module_arch:-$(host_kernel_arch)}"
    log "building TrustIX datapath module in $module_dir KDIR=${module_kdir:-default} ARCH=${module_arch:-default} CROSS_COMPILE=${module_cross_compile:-none} mode=${module_build_mode}"
    case "$module_build_mode" in
      full)
        make_module_source
        loaded_variant="full"
        ;;
      basic)
        make_module_source basic
        loaded_variant="basic"
        ;;
      auto)
        if make_module_source; then
          loaded_variant="full"
        else
          log "full datapath helper build failed; retrying basic"
          clean_module_source
          make_module_source basic
          loaded_variant="basic"
        fi
        ;;
      *)
        die "TRUSTIX_DATAPATH_BUILD_MODE must be full, basic, or auto"
        ;;
    esac
    ko_path="$module_dir/trustix_datapath_helpers.ko"
  fi

  log "loading trustix_datapath_helpers.ko variant=${loaded_variant:-prebuilt} enable_features=${enable_features} extra=${extra_module_params:-none}"
  # shellcheck disable=SC2086 # module parameters are fixed key=value tokens.
  insmod "$ko_path" enable_features="$enable_features" $extra_module_params
  loaded_by_script=1
  lsmod | grep trustix_datapath_helpers >/dev/null || die "trustix_datapath_helpers did not appear in lsmod"
}

verify_sysfs() {
  [[ -e /dev/trustix_datapath_helpers ]] || die "trustix_datapath_helpers device ioctl node is missing"
  local abi features safe unsafe selftests failures flags
  abi="$(read_module_param abi_version || true)"
  features="$(read_module_param features || true)"
  safe="$(read_module_param safe_features || true)"
  unsafe="$(read_module_param unsafe_features || true)"
  selftests="$(read_module_param selftests || true)"
  failures="$(read_module_param selftest_failures || true)"
  flags="$(read_module_param flags || true)"
  [[ "$abi" == "1" ]] || die "unexpected abi_version=${abi:-missing}"
  [[ "$flags" =~ ^[0-9]+$ ]] || die "unexpected flags=${flags:-missing}"
  [[ "$selftests" == "3" ]] || die "expected selftests=3, got ${selftests:-missing}"
  [[ "$failures" == "0" ]] || die "expected selftest_failures=0, got ${failures:-missing}"
  [[ "$features" =~ ^[0-9]+$ ]] || die "unexpected features=${features:-missing}"
  [[ "$safe" =~ ^[0-9]+$ ]] || die "unexpected safe_features=${safe:-missing}"
  [[ "$unsafe" =~ ^[0-9]+$ ]] || die "unexpected unsafe_features=${unsafe:-missing}"
  if [[ "$((flags & 1))" == "0" ]]; then
    die "TIXT selftest OK flag is missing: flags=${flags:-missing}"
  fi
  if [[ "${loaded_variant:-}" == "basic" ]]; then
    [[ "$features" == "0" ]] || die "basic helpers reported active features: ${features}"
    [[ "$safe" == "0" ]] || die "basic helpers reported safe features: ${safe}"
    if [[ "$((flags & 2))" != "0" ]]; then
      die "feature-active flag set for basic helpers: flags=${flags}"
    fi
  elif [[ "$enable_features" == "0" ]]; then
    [[ "$features" == "0" ]] || die "features active with enable_features=0: ${features}"
    [[ "$safe" == "0" ]] || die "safe_features active with enable_features=0: ${safe}"
    if [[ "$((flags & 2))" != "0" ]]; then
      die "feature-active flag set with enable_features=0: flags=${flags}"
    fi
  else
    if [[ "$((safe & 64))" == "0" ]]; then
      die "datapath did not report safe gso_skb feature: safe_features=${safe}"
    fi
    if [[ "$((flags & 2))" == "0" ]]; then
      die "datapath feature-active flag is missing: flags=${flags}"
    fi
  fi
  log "verified sysfs abi=${abi} selftests=${selftests} failures=${failures} flags=${flags}"
  verify_route_tcp_xmit_worker_params
}

verify_route_tcp_xmit_worker_params() {
  local worker steal depth enqueued cloned stolen no_dev queue_full alloc_errors header_errors xmit_ok xmit_errors flush_drops
  worker="$(read_module_param route_tcp_xmit_worker || true)"
  steal="$(read_module_param route_tcp_xmit_worker_steal || true)"
  depth="$(read_module_param route_tcp_xmit_worker_depth || true)"
  enqueued="$(read_module_param route_tcp_xmit_worker_enqueued || true)"
  cloned="$(read_module_param route_tcp_xmit_worker_cloned || true)"
  stolen="$(read_module_param route_tcp_xmit_worker_stolen || true)"
  no_dev="$(read_module_param route_tcp_xmit_worker_no_dev || true)"
  queue_full="$(read_module_param route_tcp_xmit_worker_queue_full || true)"
  alloc_errors="$(read_module_param route_tcp_xmit_worker_alloc_errors || true)"
  header_errors="$(read_module_param route_tcp_xmit_worker_header_errors || true)"
  xmit_ok="$(read_module_param route_tcp_xmit_worker_xmit_ok || true)"
  xmit_errors="$(read_module_param route_tcp_xmit_worker_xmit_errors || true)"
  flush_drops="$(read_module_param route_tcp_xmit_worker_flush_drops || true)"
  [[ "$worker" =~ ^[YN]$ ]] || die "unexpected route_tcp_xmit_worker=${worker:-missing}"
  [[ "$steal" =~ ^[YN]$ ]] || die "unexpected route_tcp_xmit_worker_steal=${steal:-missing}"
  [[ "$steal" == "N" ]] || die "route_tcp_xmit_worker_steal must stay disabled in the first release"
  for value in "$depth" "$enqueued" "$cloned" "$stolen" "$no_dev" "$queue_full" "$alloc_errors" "$header_errors" "$xmit_ok" "$xmit_errors" "$flush_drops"; do
    [[ "$value" =~ ^[0-9]+$ ]] || die "unexpected route TCP xmit worker counter value: ${value:-missing}"
  done
  [[ "$depth" == "0" ]] || die "route TCP xmit worker queue not empty during smoke: depth=${depth}"
  log "verified route_tcp_xmit_worker params worker=${worker} steal=${steal} depth=${depth}"
}

run_ioctl_test() {
  if [[ -n "$kernelmodule_test_bin" ]]; then
    [[ -x "$kernelmodule_test_bin" ]] || die "TRUSTIX_DATAPATH_KERNELMODULE_TEST_BIN is not executable: $kernelmodule_test_bin"
    log "running prebuilt datapath ioctl selftest"
    "$kernelmodule_test_bin" -test.run '^TestTrustIXDatapathHelpersDeviceQueryAndSelftest$' -test.v
    return 0
  fi
  need_cmd go
  log "running datapath ioctl selftest through go test"
  (cd "$repo_root" && go test -count=1 ./internal/kernelmodule -run '^TestTrustIXDatapathHelpersDeviceQueryAndSelftest$' -v)
}

main() {
  require_linux_root
  build_and_load_module
  verify_sysfs
  run_ioctl_test
  log "ok: trustix_datapath_helpers loaded and datapath ABI/selftest gate passed"
}

main "$@"
