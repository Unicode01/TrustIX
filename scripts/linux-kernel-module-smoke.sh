#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
module_name="trustix_crypto"
module_dir="${TRUSTIX_CRYPTO_MODULE_DIR:-${repo_root}/kernel/trustix_crypto}"
module_ko="${TRUSTIX_KERNEL_KO:-}"
module_kdir="${TRUSTIX_KERNEL_KDIR:-${KDIR:-}}"
module_arch="${TRUSTIX_KERNEL_ARCH:-${ARCH:-}}"
module_cross_compile="${TRUSTIX_KERNEL_CROSS_COMPILE:-${CROSS_COMPILE:-}}"
module_build_mode="${TRUSTIX_KERNEL_BUILD_MODE:-${TRUSTIX_CRYPTO_BUILD_MODE:-full}}"
test_bin="${TRUSTIX_KERNEL_TEST_BIN:-}"
kernelmodule_test_bin="${TRUSTIX_KERNEL_KERNELMODULE_TEST_BIN:-}"
keep_loaded="${TRUSTIX_KERNEL_KEEP_LOADED:-1}"
prefer_software="${TRUSTIX_KERNEL_PREFER_SOFTWARE:-0}"
experimental_vaes="${TRUSTIX_KERNEL_EXPERIMENTAL_VAES:-0}"
experimental_vaes_kfunc="${TRUSTIX_KERNEL_EXPERIMENTAL_VAES_KFUNC:-0}"
extra_module_params="${TRUSTIX_KERNEL_EXTRA_MODULE_PARAMS:-}"
expect_vaes="${TRUSTIX_KERNEL_EXPECT_VAES:-auto}"
run_vaes_bench="${TRUSTIX_KERNEL_VAES_BENCH:-0}"
allow_unsupported_kernel="${TRUSTIX_KERNEL_ALLOW_UNSUPPORTED_KERNEL:-0}"
kfunc_fastpath_wipe="${TRUSTIX_KERNEL_FASTPATH_WIPE:-}"
load_only="${TRUSTIX_KERNEL_LOAD_ONLY:-0}"
loaded_by_script=0
loaded_variant=""
roundtrip_tests="${TRUSTIX_KERNEL_ROUNDTRIP_TESTS:-TestKernelCryptoProviderObjectSyntheticContextLifecycle|TestKernelCryptoProviderFrameSealOpenAndReplay|TestKernelCryptoProviderFrameSealOpenAES128|TestKernelCryptoProviderFrameSealOpenVariableSizes|TestExperimentalTCPKernelCryptoXDPOpensFrameAndRejectsReplay|TestExperimentalTCPKernelCryptoXDPDirectOpenObjectOpensFrame}"

log() {
  printf '[trustix-kernel] %s\n' "$*" >&2
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
  case "$1" in
    1|true|yes|on|Y|y) return 0 ;;
    *) return 1 ;;
  esac
}

extra_module_param_value() {
  local name="$1"
  local token
  for token in $extra_module_params; do
    case "$token" in
      "${name}="*) printf '%s\n' "${token#*=}"; return 0 ;;
    esac
  done
  return 1
}

read_module_param() {
  local name="$1"
  local path="/sys/module/${module_name}/parameters/${name}"
  [[ -r "$path" ]] || return 1
  cat "$path"
}

param_is_yes() {
  local name="$1"
  local value
  value="$(read_module_param "$name")" || return 1
  printf '%s\n' "$value" | grep -qi '^Y'
}

apply_loaded_bool_param() {
  local name="$1"
  local raw="$2"
  local param="/sys/module/${module_name}/parameters/${name}"
  [[ -n "$raw" ]] || return 0
  [[ -w "$param" ]] || die "${module_name} is loaded but ${name} parameter is not writable"
  if truthy "$raw"; then
    if ! param_is_yes "$name"; then
      printf '1\n' >"$param" || die "failed to enable ${name} on the loaded ${module_name} module"
    fi
    param_is_yes "$name" || die "${module_name} is already loaded without ${name}=1; unload it or set ${name}=0"
    return 0
  fi
  if param_is_yes "$name"; then
    printf '0\n' >"$param" || die "failed to disable ${name} on the loaded ${module_name} module"
  fi
  if param_is_yes "$name"; then
    die "${module_name} is already loaded with ${name}=1; unload it or set ${name}=1"
  fi
  return 0
}

verify_simd_fastpath_disabled() {
  local value
  value="$(read_module_param kfunc_simd_fastpath || true)"
  [[ -z "$value" || "$value" =~ ^[Nn]$ ]] || die "kfunc_simd_fastpath must stay disabled in the first release"
}

roundtrip_skip_is_unsupported_kernel() {
  local output="$1"
  truthy "$allow_unsupported_kernel" || return 1
  if printf '%s\n' "$output" | grep -qi 'requires root'; then
    return 1
  fi
  printf '%s\n' "$output" | grep -qiE 'kernel crypto (provider|direct provider) is not ready|kernel crypto verifier selftest is not available|kernel BPF crypto does not expose AEAD-GCM|kernel BPF crypto verifier selftest failed'
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
      rmmod "$module_name" >/dev/null 2>&1 && break || true
      sleep 0.2
    done
  fi
}
trap cleanup EXIT

require_linux_root() {
  [[ "$(uname -s)" == "Linux" ]] || die "linux-kernel-module-smoke must run on Linux"
  [[ "${EUID:-$(id -u)}" == "0" ]] || die "linux-kernel-module-smoke must run as root to load kernel modules"
  if [[ -z "$kfunc_fastpath_wipe" ]]; then
    kfunc_fastpath_wipe="$(extra_module_param_value kfunc_fastpath_wipe || true)"
  fi
}

build_and_load_module() {
  need_cmd insmod
  need_cmd lsmod

  if lsmod | awk '{print $1}' | grep -qx "$module_name"; then
    log "${module_name} is already loaded"
    if truthy "$prefer_software"; then
      local param="/sys/module/${module_name}/parameters/prefer_software"
      [[ -r "$param" ]] || die "${module_name} is loaded but prefer_software parameter is not readable"
      grep -qi '^Y' "$param" || die "${module_name} is already loaded without prefer_software=1; unload it or set TRUSTIX_KERNEL_PREFER_SOFTWARE=0"
    fi
    if truthy "$experimental_vaes"; then
      param_is_yes experimental_vaes || die "${module_name} is already loaded without experimental_vaes=1; unload it or set TRUSTIX_KERNEL_EXPERIMENTAL_VAES=0"
    fi
    apply_loaded_bool_param experimental_vaes_kfunc "$experimental_vaes_kfunc"
    apply_loaded_bool_param kfunc_fastpath_wipe "$kfunc_fastpath_wipe"
    verify_simd_fastpath_disabled
    return 0
  fi

  local ko_path="$module_ko"
  if [[ -n "$ko_path" ]]; then
    [[ -f "$ko_path" ]] || die "TRUSTIX_KERNEL_KO does not exist: $ko_path"
    log "using prebuilt TrustIX kernel module $ko_path"
  else
    [[ -d "$module_dir" ]] || die "module directory not found: $module_dir"
    [[ -f "$module_dir/Makefile" ]] || die "module Makefile not found: $module_dir/Makefile"
    need_cmd make
    module_kdir="${module_kdir:-/lib/modules/$(uname -r)/build}"
    module_arch="${module_arch:-$(host_kernel_arch)}"
    log "building TrustIX kernel module in $module_dir KDIR=${module_kdir:-default} ARCH=${module_arch:-default} CROSS_COMPILE=${module_cross_compile:-none} mode=${module_build_mode}"
    case "$module_build_mode" in
      full)
        make_module_source
        loaded_variant="full"
        ;;
      device-only)
        make_module_source device-only
        loaded_variant="device-only"
        ;;
      auto)
        if make_module_source; then
          loaded_variant="full"
        else
          log "full crypto module build failed; retrying device-only"
          clean_module_source
          make_module_source device-only
          loaded_variant="device-only"
        fi
        ;;
      *)
        die "TRUSTIX_KERNEL_BUILD_MODE must be full, device-only, or auto"
        ;;
    esac
    ko_path="$module_dir/${module_name}.ko"
  fi

  log "loading ${module_name}.ko variant=${loaded_variant:-prebuilt} prefer_software=${prefer_software} experimental_vaes=${experimental_vaes} experimental_vaes_kfunc=${experimental_vaes_kfunc} extra=${extra_module_params:-none}"
  local insmod_params=""
  if truthy "$prefer_software"; then
    insmod_params="${insmod_params} prefer_software=1"
  fi
  if truthy "$experimental_vaes"; then
    insmod_params="${insmod_params} experimental_vaes=1"
  fi
  if truthy "$experimental_vaes_kfunc"; then
    insmod_params="${insmod_params} experimental_vaes_kfunc=1"
  fi
  if [[ -n "$kfunc_fastpath_wipe" ]] && ! truthy "$kfunc_fastpath_wipe"; then
    insmod_params="${insmod_params} kfunc_fastpath_wipe=0"
  fi
  if [[ -n "$extra_module_params" ]]; then
    insmod_params="${insmod_params} ${extra_module_params}"
  fi
  # shellcheck disable=SC2086 # module parameters are fixed key=value tokens.
  insmod "$ko_path" $insmod_params
  loaded_by_script=1
  lsmod | grep "$module_name" >/dev/null || die "${module_name} did not appear in lsmod"
  verify_simd_fastpath_disabled
  if truthy "$prefer_software"; then
    grep -qi '^Y' "/sys/module/${module_name}/parameters/prefer_software" || die "prefer_software=1 was not applied"
    log "verified ${module_name} prefer_software=1"
  fi
  if truthy "$experimental_vaes"; then
    param_is_yes experimental_vaes || die "experimental_vaes=1 was not applied"
    log "verified ${module_name} experimental_vaes=1"
  fi
  if truthy "$experimental_vaes_kfunc"; then
    param_is_yes experimental_vaes_kfunc || die "experimental_vaes_kfunc=1 was not applied"
    log "verified ${module_name} experimental_vaes_kfunc=1"
  fi
}

run_roundtrip_test() {
  local output
  if [[ -n "$test_bin" ]]; then
    [[ -x "$test_bin" ]] || die "TRUSTIX_KERNEL_TEST_BIN is not executable: $test_bin"
    log "running prebuilt eBPF provider roundtrip/frame/RX-open tests"
    output="$("$test_bin" -test.run "$roundtrip_tests" -test.v 2>&1)" || {
      printf '%s\n' "$output"
      return 1
    }
    printf '%s\n' "$output"
    if printf '%s\n' "$output" | grep -q '^--- SKIP:'; then
      if roundtrip_skip_is_unsupported_kernel "$output"; then
        log "BPF crypto kfunc provider is unsupported on this kernel; required roundtrip tests were skipped"
        return 2
      fi
      die "one or more required kernel AEAD tests were skipped"
    fi
    return 0
  fi
  need_cmd go
  log "running eBPF provider roundtrip/frame/RX-open tests through go test"
  output="$(cd "$repo_root" && go test ./internal/dataplane/ebpf -run "$roundtrip_tests" -v 2>&1)" || {
    printf '%s\n' "$output"
    return 1
  }
  printf '%s\n' "$output"
  if printf '%s\n' "$output" | grep -q '^--- SKIP:'; then
    if roundtrip_skip_is_unsupported_kernel "$output"; then
      log "BPF crypto kfunc provider is unsupported on this kernel; required roundtrip tests were skipped"
      return 2
    fi
    die "one or more required kernel AEAD tests were skipped"
  fi
}

run_device_ioctl_test() {
  if [[ -z "$kernelmodule_test_bin" ]]; then
    return 0
  fi
  [[ -x "$kernelmodule_test_bin" ]] || die "TRUSTIX_KERNEL_KERNELMODULE_TEST_BIN is not executable: $kernelmodule_test_bin"
  [[ -e /dev/trustix_crypto ]] || die "trustix_crypto device ioctl node is missing"
  local output
  log "running TrustIX kernel AEAD device ioctl batch tests"
  output="$("$kernelmodule_test_bin" -test.run 'TestTrustIXAEADDevice(BatchSealOpen|SessionBatchSealOpen|SessionPoolBatchSealOpen|KernelPreparedPoolBatchSealOpen)' -test.v 2>&1)" || {
    printf '%s\n' "$output"
    return 1
  }
  printf '%s\n' "$output"
  if printf '%s\n' "$output" | grep -q '^--- SKIP:'; then
    die "TrustIX kernel AEAD device ioctl test was skipped"
  fi
}

run_vaes_device_test() {
  if ! truthy "$experimental_vaes"; then
    return 0
  fi
  if [[ -z "$kernelmodule_test_bin" ]]; then
    case "$expect_vaes" in
      1|true|yes|on) die "TRUSTIX_KERNEL_EXPECT_VAES requires TRUSTIX_KERNEL_KERNELMODULE_TEST_BIN" ;;
      *) log "skip VAES prepared-batch ioctl check: no TRUSTIX_KERNEL_KERNELMODULE_TEST_BIN" ; return 0 ;;
    esac
  fi
  [[ -x "$kernelmodule_test_bin" ]] || die "TRUSTIX_KERNEL_KERNELMODULE_TEST_BIN is not executable: $kernelmodule_test_bin"
  [[ -e /dev/trustix_crypto ]] || die "trustix_crypto device ioctl node is missing"

  local available attempts_before fallbacks_before attempts_after fallbacks_after output
  available="$(read_module_param vaes_available || true)"
  log "${module_name} vaes_available=${available:-unknown} vaes_agg_ghash=$(read_module_param vaes_agg_ghash || true) vaes_fused_ghash=$(read_module_param vaes_fused_ghash || true)"
  case "$expect_vaes" in
    1|true|yes|on)
      printf '%s\n' "$available" | grep -qi '^Y' || die "experimental VAES was required but vaes_available=${available:-missing}"
      param_is_yes vaes_agg_ghash || die "vaes_agg_ghash is not enabled by default"
      ;;
    auto|0|false|no|off) ;;
    *) die "TRUSTIX_KERNEL_EXPECT_VAES must be auto, 1, or 0" ;;
  esac
  if ! printf '%s\n' "$available" | grep -qi '^Y'; then
    log "skip VAES prepared-batch ioctl check: CPU/kernel does not report vaes_available=Y"
    return 0
  fi

  attempts_before="$(read_module_param vaes_attempts || echo 0)"
  fallbacks_before="$(read_module_param vaes_fallbacks || echo 0)"
  output="$("$kernelmodule_test_bin" -test.run '^TestTrustIXAEADDeviceKernelPreparedPoolBatchSealOpen$' -test.v 2>&1)" || {
    printf '%s\n' "$output"
    return 1
  }
  printf '%s\n' "$output"
  if printf '%s\n' "$output" | grep -q '^--- SKIP:'; then
    die "TrustIX VAES prepared-batch ioctl test was skipped"
  fi
  attempts_after="$(read_module_param vaes_attempts || echo 0)"
  fallbacks_after="$(read_module_param vaes_fallbacks || echo 0)"
  if (( attempts_after <= attempts_before )); then
    die "VAES attempts did not increase: before=${attempts_before} after=${attempts_after}"
  fi
  if (( fallbacks_after != fallbacks_before )); then
    die "VAES fallbacks changed: before=${fallbacks_before} after=${fallbacks_after}"
  fi
  log "verified VAES prepared-batch path attempts=${attempts_after} fallbacks=${fallbacks_after}"

  if truthy "$run_vaes_bench"; then
    log "running TrustIX kernel AEAD VAES prepared-pool microbench"
    "$kernelmodule_test_bin" -test.run '^$' \
      -test.bench 'BenchmarkTrustIXAEADDeviceSessionPoolSeal1200Batch4096|BenchmarkTrustIXAEADDeviceSessionPoolSeal16KBatch64|BenchmarkTrustIXAEADDeviceSessionPoolSeal1200Parallel$' \
      -test.benchtime="${TRUSTIX_KERNEL_VAES_BENCHTIME:-1s}" \
      -test.count=1 -test.cpu=1,4
  fi
}

main() {
  require_linux_root
  build_and_load_module
  if truthy "$load_only"; then
    log "ok: ${module_name} loaded in load-only mode"
    return 0
  fi
  local unsupported_kernel=0
  set +e
  run_roundtrip_test
  local roundtrip_rc=$?
  set -e
  case "$roundtrip_rc" in
    0) ;;
    2) unsupported_kernel=1 ;;
    *) exit "$roundtrip_rc" ;;
  esac
  run_device_ioctl_test
  run_vaes_device_test
  if [[ "$unsupported_kernel" == "1" ]]; then
    log "ok: ${module_name} loaded and device ioctl tests passed; BPF kfunc AEAD provider is unsupported by this kernel"
    exit 0
  fi
  if truthy "$prefer_software"; then
    log "ok: ${module_name} loaded with software AES-GCM preference and kernel AEAD-GCM roundtrip/frame/RX-open tests passed"
  else
    log "ok: ${module_name} loaded and kernel AEAD-GCM roundtrip/frame/RX-open tests passed"
  fi
}

main "$@"
