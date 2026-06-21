#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workdir="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_WORKDIR:-$(mktemp -d /tmp/trustix-production-transport-matrix.XXXXXX)}"
workdir="$(mkdir -p "$workdir" && cd "$workdir" && pwd -P)"
keep="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_KEEP:-0}"
smoke_script="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_E2E_SCRIPT:-${repo_root}/scripts/linux-e2e-smoke.sh}"
bin_dir="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_BIN_DIR:-}"
datapath_module_dir="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_DATAPATH_MODULE_DIR:-}"
datapath_script="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_DATAPATH_SCRIPT:-}"
datapath_ko="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_DATAPATH_KO:-}"
datapath_kernelmodule_test_bin="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_DATAPATH_KERNELMODULE_TEST_BIN:-}"
defaults_file="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_DEFAULTS:-${repo_root}/scripts/production-transport-defaults.tsv}"
matrix_scope="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_SCOPE:-single_host}"
full_datapath_module="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_FULL_DATAPATH_MODULE:-auto}"
full_datapath_rx_worker="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_FULL_DATAPATH_RX_WORKER:-auto}"
full_datapath_script="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_FULL_DATAPATH_SCRIPT:-${repo_root}/scripts/linux-full-datapath-module-smoke.sh}"
full_datapath_module_dir="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_FULL_DATAPATH_MODULE_DIR:-${repo_root}/kernel/trustix_datapath}"
full_datapath_ko="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_FULL_DATAPATH_KO:-}"
full_datapath_enable_features="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_FULL_DATAPATH_ENABLE_FEATURES:-128}"
full_datapath_extra_module_params="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_FULL_DATAPATH_EXTRA_MODULE_PARAMS:-rx_worker_inject=1 tx_plaintext=1 rx_worker_xmit=1 rx_worker_inline_xmit=1 rx_worker_inline_xmit_copy_csum=1 rx_worker_direct_xmit=1 rx_worker_inline_coalesce_max_frames=16 rx_worker_single_coalesce=1 rx_worker_single_coalesce_max_frames=32 rx_worker_tcp=1 rx_worker_stream_tcp=1 rx_worker_stream_batch_queue=1 rx_worker_stream_coalesce_gso=1 rx_worker_stream_coalesce_software_segment=0 rx_worker_xmit_more=1 rx_worker_xmit_dst_mac_cache=1 tx_plaintext_inline_xmit=1 tx_plaintext_direct_xmit=1 tx_plaintext_skip_inner_tcp_checksum=0 tx_plaintext_stream_coalesce=0 tx_plaintext_stream_coalesce_max_frames=16 tx_plaintext_slots=8192 rx_worker_budget=1024 rx_worker_slots=8192 rx_worker_hot_stats=0}"
full_datapath_kernelmodule_test_bin="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_FULL_DATAPATH_KERNELMODULE_TEST_BIN:-}"
full_datapath_ioctl_selftest="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_FULL_DATAPATH_IOCTL_SELFTEST:-0}"
full_datapath_verify_safe_defaults="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_FULL_DATAPATH_VERIFY_SAFE_DEFAULTS:-0}"
single_host_full_datapath="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_SINGLE_HOST_FULL_DATAPATH:-0}"
single_host_route_gso="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_SINGLE_HOST_ROUTE_GSO:-0}"
cases_raw="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_CASES:-}"
include_kernel="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_INCLUDE_KERNEL:-auto}"
kernel_module="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_KERNEL_MODULE:-0}"
perf_fast="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_PERF_FAST:-1}"
case_timeout="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_CASE_TIMEOUT:-}"
iperf3="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_IPERF3:-1}"
iperf3_seconds="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_IPERF3_SECONDS:-30}"
iperf3_parallel="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_IPERF3_PARALLEL:-2}"
iperf3_directions="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_IPERF3_DIRECTIONS:-both}"
iperf3_min_gbps="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_IPERF3_MIN_GBPS:-0}"
iperf3_min_sent_gbps="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_IPERF3_MIN_SENT_GBPS:-$iperf3_min_gbps}"
iperf3_min_received_gbps="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_IPERF3_MIN_RECEIVED_GBPS:-$iperf3_min_gbps}"
af_xdp_tx_backpressure_wait="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_AF_XDP_TX_BACKPRESSURE_WAIT:-50ms}"
full_datapath_min_gbps="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_FULL_DATAPATH_MIN_GBPS:-3}"
route_gso_min_gbps="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_ROUTE_GSO_MIN_GBPS:-2.5}"
ping_count="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_PING_COUNT:-3}"
udp_burst_packets="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_UDP_BURST_PACKETS:-64}"
udp_burst_size="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_UDP_BURST_SIZE:-512}"
tcp_burst_connections="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_TCP_BURST_CONNECTIONS:-8}"
tcp_burst_size="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_TCP_BURST_SIZE:-4096}"
summary_path="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_SUMMARY:-${workdir}/summary.jsonl}"
if [[ -z "$datapath_kernelmodule_test_bin" && -n "$bin_dir" && -x "${bin_dir}/kernelmodule.test" ]]; then
  datapath_kernelmodule_test_bin="${bin_dir}/kernelmodule.test"
fi

log() {
  printf '[trustix-production-transport-matrix] %s\n' "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

truthy() {
  case "${1:-0}" in
    1|true|yes|on|enabled) return 0 ;;
    *) return 1 ;;
  esac
}

run_case_smoke() {
  if [[ -n "$case_timeout" ]]; then
    timeout --foreground "$case_timeout" bash "$smoke_script"
    return
  fi
  bash "$smoke_script"
}

kernel_provider_available() {
  grep -q '^trustix_crypto ' /proc/modules 2>/dev/null || truthy "$kernel_module"
}

default_cases() {
  [[ -f "$defaults_file" ]] || die "production defaults file not found: $defaults_file"
  awk -v scope="$matrix_scope" -F '\t' '
    BEGIN { OFS = ":" }
    /^[[:space:]]*#/ || NF == 0 { next }
    NF < 9 { printf "invalid production defaults row: %s\n", $0 >"/dev/stderr"; exit 2 }
    scope != "all" && $6 != scope { next }
    {
      key = $1 SUBSEP $2 SUBSEP $3 SUBSEP $4 SUBSEP $5
      if (seen[key]++) next
      print $1, $2, $3, $4, $5, $8, $9
    }
  ' "$defaults_file"
}

validate_case() {
  local transport="$1" encryption="$2" profile="$3" datapath="$4" placement="$5"
  case "$transport" in
    udp|tcp|quic|websocket|http_connect|gre|ipip|vxlan|kernel_udp|experimental_tcp) ;;
    *) die "unsupported transport in production case: $transport" ;;
  esac
  case "$encryption" in
    secure|plaintext) ;;
    *) die "unsupported encryption in production case: $encryption" ;;
  esac
  case "$profile" in
    stable|performance|latency) ;;
    *) die "unsupported profile in production case: $profile" ;;
  esac
  case "$datapath" in
    userspace|auto|tc_xdp|kernel_module) ;;
    *) die "unsupported datapath in production case: $datapath" ;;
  esac
  case "$placement" in
    userspace|auto|kernel) ;;
    *) die "unsupported crypto placement in production case: $placement" ;;
  esac
}

case_should_skip() {
  local transport="$1" encryption="$2" profile="$3" datapath="$4" placement="$5"
  if case_is_full_datapath "$transport" "$encryption" "$profile" "$datapath" "$placement" &&
    ! truthy "$single_host_full_datapath"; then
    log "skip ${transport}/${encryption}/${profile}/${datapath}/${placement}: full datapath module requires a cross-host harness; set TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_SINGLE_HOST_FULL_DATAPATH=1 for explicit single-host diagnostics"
    return 0
  fi
  if case_is_route_gso "$transport" "$encryption" "$profile" "$datapath" "$placement" &&
    ! truthy "$single_host_route_gso"; then
    log "skip ${transport}/${encryption}/${profile}/${datapath}/${placement}: route-GSO throughput requires a cross-host harness; set TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_SINGLE_HOST_ROUTE_GSO=1 for explicit single-host diagnostics"
    return 0
  fi
  if case_is_full_datapath "$transport" "$encryption" "$profile" "$datapath" "$placement" &&
    ! full_datapath_case_available; then
    log "skip ${transport}/${encryption}/${profile}/${datapath}/${placement}: full datapath module is unavailable"
    return 0
  fi
  if [[ "$placement" == "kernel" && "$transport" != "kernel_udp" && "$transport" != "experimental_tcp" ]]; then
    log "skip ${transport}/${encryption}/${placement}: transport has no kernel crypto placement"
    return 0
  fi
  if [[ "$placement" == "kernel" && "$encryption" == "plaintext" ]]; then
    log "skip ${transport}/${encryption}/${placement}: plaintext has no kernel crypto placement"
    return 0
  fi
  if [[ "$placement" == "kernel" ]]; then
    case "$include_kernel" in
      1|true|yes|on|enabled) return 1 ;;
      auto)
        if kernel_provider_available; then
          return 1
        fi
        log "skip ${transport}/${encryption}/${placement}: kernel provider is unavailable"
        return 0
        ;;
      0|false|no|off|disabled)
        log "skip ${transport}/${encryption}/${placement}: kernel cases disabled"
        return 0
        ;;
      *) die "TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_INCLUDE_KERNEL must be auto, 1, or 0" ;;
    esac
  fi
  return 1
}

case_is_full_datapath() {
  local transport="$1" encryption="$2" profile="$3" datapath="$4" placement="$5"
  [[ "$transport" == "udp" &&
    "$encryption" == "plaintext" &&
    "$profile" == "performance" &&
    "$datapath" == "kernel_module" &&
    "$placement" == "userspace" ]]
}

case_is_route_gso() {
  local transport="$1" encryption="$2" profile="$3" datapath="$4" placement="$5"
  [[ "$transport" == "experimental_tcp" &&
    "$encryption" == "plaintext" &&
    "$profile" == "performance" &&
    "$datapath" == "kernel_module" &&
    "$placement" == "userspace" ]]
}

full_datapath_case_available() {
  case "$full_datapath_module" in
    1|true|yes|on|enabled) return 0 ;;
    0|false|no|off|disabled) return 1 ;;
    auto)
      if grep -q '^trustix_datapath ' /proc/modules 2>/dev/null; then
        return 0
      fi
      if [[ -n "$full_datapath_ko" && -f "$full_datapath_ko" ]]; then
        return 0
      fi
      [[ -f "$full_datapath_script" &&
        -d "$full_datapath_module_dir" &&
        -f "${full_datapath_module_dir}/Makefile" &&
        -e "/lib/modules/$(uname -r)/build" ]]
      return
      ;;
    *) die "TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_FULL_DATAPATH_MODULE must be auto, 1, or 0" ;;
  esac
}

case_min_sent_gbps() {
  if case_is_full_datapath "$@"; then
    printf '%s' "$full_datapath_min_gbps"
    return
  fi
  if case_is_route_gso "$@"; then
    printf '%s' "$route_gso_min_gbps"
    return
  fi
  printf '%s' "$iperf3_min_sent_gbps"
}

case_min_received_gbps() {
  if case_is_full_datapath "$@"; then
    printf '%s' "$full_datapath_min_gbps"
    return
  fi
  if case_is_route_gso "$@"; then
    printf '%s' "$route_gso_min_gbps"
    return
  fi
  printf '%s' "$iperf3_min_received_gbps"
}

case_full_datapath_module_value() {
  if case_is_full_datapath "$@"; then
    printf '1'
  else
    printf '0'
  fi
}

case_full_datapath_rx_worker_value() {
  if ! case_is_full_datapath "$@"; then
    printf '0'
    return
  fi
  case "$full_datapath_rx_worker" in
    auto|"") printf '1' ;;
    1|true|yes|on|enabled) printf '1' ;;
    0|false|no|off|disabled) printf '0' ;;
    *) die "TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_FULL_DATAPATH_RX_WORKER must be auto, 1, or 0" ;;
  esac
}

record_result() {
  local status="$1" name="$2" transport="$3" encryption="$4" profile="$5" datapath="$6" placement="$7" elapsed="$8" dir="$9" rc="${10}"
  printf '{"status":"%s","case":"%s","transport":"%s","encryption":"%s","profile":"%s","datapath":"%s","crypto_placement":"%s","elapsed_seconds":%s,"exit_code":%s,"workdir":"%s"}\n' \
    "$status" "$name" "$transport" "$encryption" "$profile" "$datapath" "$placement" "$elapsed" "$rc" "$dir" >>"$summary_path"
}

run_case() {
  local transport="$1" encryption="$2" profile="$3" datapath="$4" placement="$5"
  local default_min_gbps="${6:-}" default_seconds="${7:-}"
  local name="${transport}-${encryption}-${profile}-${datapath}-${placement}"
  local dir="${workdir}/${name}"
  local start end elapsed rc case_kernel_module case_full_datapath_module case_full_datapath_rx_worker case_min_sent case_min_received case_iperf3_seconds
  validate_case "$transport" "$encryption" "$profile" "$datapath" "$placement"
  if [[ -n "$default_min_gbps" ]]; then
    [[ "$default_min_gbps" =~ ^[0-9]+([.][0-9]+)?$ ]] || die "invalid min_gbps in production matrix case: ${transport}/${encryption}/${profile}/${datapath}/${placement}: ${default_min_gbps}"
  fi
  if [[ -n "$default_seconds" ]]; then
    [[ "$default_seconds" =~ ^[1-9][0-9]*$ ]] || die "invalid min_seconds in production matrix case: ${transport}/${encryption}/${profile}/${datapath}/${placement}: ${default_seconds}"
  fi
  if case_should_skip "$transport" "$encryption" "$profile" "$datapath" "$placement"; then
    record_result "skipped" "$name" "$transport" "$encryption" "$profile" "$datapath" "$placement" 0 "$dir" 0
    return 0
  fi
  case_kernel_module="$kernel_module"
  if [[ "$placement" == "kernel" ]]; then
    case_kernel_module=1
  fi
  case_full_datapath_module="$(case_full_datapath_module_value "$transport" "$encryption" "$profile" "$datapath" "$placement")"
  case_full_datapath_rx_worker="$(case_full_datapath_rx_worker_value "$transport" "$encryption" "$profile" "$datapath" "$placement")"
  if [[ -n "$default_min_gbps" ]]; then
    case_min_sent="$default_min_gbps"
    case_min_received="$default_min_gbps"
  else
    case_min_sent="$(case_min_sent_gbps "$transport" "$encryption" "$profile" "$datapath" "$placement")"
    case_min_received="$(case_min_received_gbps "$transport" "$encryption" "$profile" "$datapath" "$placement")"
  fi
  case_iperf3_seconds="${default_seconds:-$iperf3_seconds}"
  rm -rf "$dir"
  mkdir -p "$dir"
  log "run ${name} min_gbps=${case_min_received} seconds=${case_iperf3_seconds}"
  start="$(date +%s)"
  set +e
  (
    if [[ -n "$bin_dir" ]]; then
      export TRUSTIX_E2E_BIN_DIR="$bin_dir"
    fi
    if [[ -n "$datapath_module_dir" ]]; then
      export TRUSTIX_E2E_DATAPATH_MODULE_DIR="$datapath_module_dir"
    fi
    if [[ -n "$datapath_script" ]]; then
      export TRUSTIX_E2E_DATAPATH_SCRIPT="$datapath_script"
    fi
    if [[ -n "$datapath_ko" ]]; then
      export TRUSTIX_DATAPATH_KO="$datapath_ko"
    fi
    if [[ -n "$datapath_kernelmodule_test_bin" ]]; then
      export TRUSTIX_E2E_DATAPATH_KERNELMODULE_TEST_BIN="$datapath_kernelmodule_test_bin"
    fi
    export TRUSTIX_E2E_WORKDIR="$dir"
    export TRUSTIX_E2E_KEEP="$keep"
    export TRUSTIX_E2E_CRASH_RESTART=0
    export TRUSTIX_E2E_PERF_FAST="$perf_fast"
    export TRUSTIX_E2E_ROUTE_KIND_PROBE=0
    export TRUSTIX_E2E_TRANSPORT="$transport"
    export TRUSTIX_E2E_TRANSPORT_ENCRYPTION="$encryption"
    export TRUSTIX_E2E_TRANSPORT_PROFILE="$profile"
    export TRUSTIX_E2E_TRANSPORT_DATAPATH="$datapath"
    export TRUSTIX_E2E_CRYPTO_PLACEMENT="$placement"
    export TRUSTIX_E2E_KERNEL_MODULE="$case_kernel_module"
    export TRUSTIX_E2E_FULL_DATAPATH_MODULE="$case_full_datapath_module"
    export TRUSTIX_E2E_FULL_DATAPATH_RX_WORKER="$case_full_datapath_rx_worker"
    export TRUSTIX_E2E_FULL_DATAPATH_SCRIPT="$full_datapath_script"
    export TRUSTIX_E2E_FULL_DATAPATH_MODULE_DIR="$full_datapath_module_dir"
    export TRUSTIX_E2E_FULL_DATAPATH_KO="$full_datapath_ko"
    export TRUSTIX_E2E_FULL_DATAPATH_ENABLE_FEATURES="$full_datapath_enable_features"
    export TRUSTIX_E2E_FULL_DATAPATH_EXTRA_MODULE_PARAMS="$full_datapath_extra_module_params"
    export TRUSTIX_E2E_FULL_DATAPATH_KERNELMODULE_TEST_BIN="$full_datapath_kernelmodule_test_bin"
    export TRUSTIX_E2E_FULL_DATAPATH_IOCTL_SELFTEST="$full_datapath_ioctl_selftest"
    export TRUSTIX_E2E_FULL_DATAPATH_VERIFY_SAFE_DEFAULTS="$full_datapath_verify_safe_defaults"
    export TRUSTIX_E2E_IPERF3="$iperf3"
    export TRUSTIX_E2E_IPERF3_SECONDS="$case_iperf3_seconds"
    export TRUSTIX_E2E_IPERF3_PARALLEL="$iperf3_parallel"
    export TRUSTIX_E2E_IPERF3_DIRECTIONS="$iperf3_directions"
    export TRUSTIX_E2E_IPERF3_MIN_SENT_GBPS="$case_min_sent"
    export TRUSTIX_E2E_IPERF3_MIN_RECEIVED_GBPS="$case_min_received"
    export TRUSTIX_E2E_AF_XDP_TX_BACKPRESSURE_WAIT="$af_xdp_tx_backpressure_wait"
    export TRUSTIX_E2E_PING_COUNT="$ping_count"
    export TRUSTIX_E2E_UDP_BURST_PACKETS="$udp_burst_packets"
    export TRUSTIX_E2E_UDP_BURST_SIZE="$udp_burst_size"
    export TRUSTIX_E2E_TCP_BURST_CONNECTIONS="$tcp_burst_connections"
    export TRUSTIX_E2E_TCP_BURST_SIZE="$tcp_burst_size"
    run_case_smoke
  ) >"${dir}.log" 2>&1
  rc=$?
  set -e
  end="$(date +%s)"
  elapsed="$((end - start))"
  if [[ "$rc" == "0" ]]; then
    record_result "pass" "$name" "$transport" "$encryption" "$profile" "$datapath" "$placement" "$elapsed" "$dir" "$rc"
    return 0
  fi
  record_result "fail" "$name" "$transport" "$encryption" "$profile" "$datapath" "$placement" "$elapsed" "$dir" "$rc"
  log "case failed: ${name}; see ${dir}.log"
  return "$rc"
}

run_cases() {
  local source="$1"
  local case_file="${workdir}/cases.txt"
  local line old_ifs transport encryption profile datapath placement min_gbps min_seconds extra failures=0
  printf '%s\n' "$source" >"$case_file"
  while IFS= read -r line; do
    line="${line%%#*}"
    line="${line//[[:space:]]/}"
    [[ -n "$line" ]] || continue
    old_ifs="$IFS"
    IFS=:
    set -- $line
    IFS="$old_ifs"
    transport="${1:-}"
    encryption="${2:-}"
    profile="${3:-}"
    datapath="${4:-}"
    placement="${5:-}"
    min_gbps="${6:-}"
    min_seconds="${7:-}"
    extra="${8:-}"
    if [[ -z "$transport" || -z "$encryption" || -z "$profile" || -z "$datapath" || -z "$placement" || -n "$extra" ]]; then
      die "invalid production matrix case: $line"
    fi
    run_case "$transport" "$encryption" "$profile" "$datapath" "$placement" "$min_gbps" "$min_seconds" || failures=$((failures + 1))
  done <"$case_file"
  return "$failures"
}

main() {
  [[ "$(uname -s)" == "Linux" ]] || die "matrix must run on Linux"
  [[ "${EUID:-$(id -u)}" == "0" ]] || die "matrix must run as root"
  [[ -f "$smoke_script" ]] || die "linux e2e smoke script not found: $smoke_script"
  case "$include_kernel" in
    auto|1|true|yes|on|enabled|0|false|no|off|disabled) ;;
    *) die "TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_INCLUDE_KERNEL must be auto, 1, or 0" ;;
  esac
  case "$full_datapath_module" in
    auto|1|true|yes|on|enabled|0|false|no|off|disabled) ;;
    *) die "TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_FULL_DATAPATH_MODULE must be auto, 1, or 0" ;;
  esac
  case "$matrix_scope" in
    single_host|cross_host|all) ;;
    *) die "TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_SCOPE must be single_host, cross_host, or all" ;;
  esac
  case "$full_datapath_ioctl_selftest" in
    0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_FULL_DATAPATH_IOCTL_SELFTEST must be truthy or falsey" ;;
  esac
  case "$full_datapath_verify_safe_defaults" in
    0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_FULL_DATAPATH_VERIFY_SAFE_DEFAULTS must be truthy or falsey" ;;
  esac
  case "$single_host_full_datapath" in
    0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_SINGLE_HOST_FULL_DATAPATH must be truthy or falsey" ;;
  esac
  case "$single_host_route_gso" in
    0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_SINGLE_HOST_ROUTE_GSO must be truthy or falsey" ;;
  esac
  case "$perf_fast" in
    0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_PERF_FAST must be truthy or falsey" ;;
  esac
  local timeout_duration_re='^[1-9][0-9]*(s|m|h|d)?$'
  [[ -z "$case_timeout" || "$case_timeout" =~ $timeout_duration_re ]] || die "TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_CASE_TIMEOUT must be a coreutils timeout duration"
  if [[ -n "$case_timeout" ]] && ! command -v timeout >/dev/null 2>&1; then
    die "TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_CASE_TIMEOUT requires timeout"
  fi
  local nonnegative_decimal_re='^[0-9]+([.][0-9]+)?$'
  [[ "$iperf3_min_sent_gbps" =~ $nonnegative_decimal_re ]] || die "TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_IPERF3_MIN_SENT_GBPS/TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_IPERF3_MIN_GBPS must be a non-negative number"
  [[ "$iperf3_min_received_gbps" =~ $nonnegative_decimal_re ]] || die "TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_IPERF3_MIN_RECEIVED_GBPS/TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_IPERF3_MIN_GBPS must be a non-negative number"
  local go_duration_re='^[0-9]+(ns|us|ms|s|m|h)$'
  [[ "$af_xdp_tx_backpressure_wait" == "0" || "$af_xdp_tx_backpressure_wait" =~ $go_duration_re ]] || die "TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_AF_XDP_TX_BACKPRESSURE_WAIT must be a Go duration or 0"
  [[ "$full_datapath_min_gbps" =~ $nonnegative_decimal_re ]] || die "TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_FULL_DATAPATH_MIN_GBPS must be a non-negative number"
  [[ "$route_gso_min_gbps" =~ $nonnegative_decimal_re ]] || die "TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_ROUTE_GSO_MIN_GBPS must be a non-negative number"
  : >"$summary_path"
  log "workdir=${workdir}"
  log "summary=${summary_path}"
  if [[ -n "$cases_raw" ]]; then
    run_cases "$cases_raw"
  else
    run_cases "$(default_cases)"
  fi
  log "summary=${summary_path}"
}

main "$@"
