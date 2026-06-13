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
cases_raw="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_CASES:-}"
include_kernel="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_INCLUDE_KERNEL:-auto}"
kernel_module="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_KERNEL_MODULE:-0}"
iperf3="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_IPERF3:-1}"
iperf3_seconds="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_IPERF3_SECONDS:-30}"
iperf3_parallel="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_IPERF3_PARALLEL:-2}"
iperf3_directions="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_IPERF3_DIRECTIONS:-both}"
iperf3_min_gbps="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_IPERF3_MIN_GBPS:-0}"
iperf3_min_sent_gbps="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_IPERF3_MIN_SENT_GBPS:-$iperf3_min_gbps}"
iperf3_min_received_gbps="${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_IPERF3_MIN_RECEIVED_GBPS:-$iperf3_min_gbps}"
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

kernel_provider_available() {
  grep -q '^trustix_crypto ' /proc/modules 2>/dev/null || truthy "$kernel_module"
}

default_cases() {
  cat <<'CASES'
udp:secure:stable:userspace:userspace
udp:plaintext:stable:userspace:userspace
tcp:secure:stable:userspace:userspace
tcp:plaintext:stable:userspace:userspace
quic:secure:stable:userspace:userspace
quic:plaintext:stable:userspace:userspace
websocket:secure:stable:userspace:userspace
websocket:plaintext:stable:userspace:userspace
http_connect:secure:stable:userspace:userspace
http_connect:plaintext:stable:userspace:userspace
gre:secure:stable:tc_xdp:userspace
gre:plaintext:performance:tc_xdp:userspace
ipip:secure:stable:tc_xdp:userspace
ipip:plaintext:performance:tc_xdp:userspace
vxlan:secure:stable:tc_xdp:userspace
vxlan:plaintext:performance:tc_xdp:userspace
kernel_udp:plaintext:performance:tc_xdp:userspace
kernel_udp:secure:stable:tc_xdp:userspace
kernel_udp:secure:performance:tc_xdp:kernel
experimental_tcp:plaintext:performance:kernel_module:userspace
experimental_tcp:secure:stable:kernel_module:userspace
experimental_tcp:secure:performance:kernel_module:kernel
CASES
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
  local transport="$1" encryption="$2" placement="$5"
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

record_result() {
  local status="$1" name="$2" transport="$3" encryption="$4" profile="$5" datapath="$6" placement="$7" elapsed="$8" dir="$9" rc="${10}"
  printf '{"status":"%s","case":"%s","transport":"%s","encryption":"%s","profile":"%s","datapath":"%s","crypto_placement":"%s","elapsed_seconds":%s,"exit_code":%s,"workdir":"%s"}\n' \
    "$status" "$name" "$transport" "$encryption" "$profile" "$datapath" "$placement" "$elapsed" "$rc" "$dir" >>"$summary_path"
}

run_case() {
  local transport="$1" encryption="$2" profile="$3" datapath="$4" placement="$5"
  local name="${transport}-${encryption}-${profile}-${datapath}-${placement}"
  local dir="${workdir}/${name}"
  local start end elapsed rc case_kernel_module
  validate_case "$transport" "$encryption" "$profile" "$datapath" "$placement"
  if case_should_skip "$transport" "$encryption" "$profile" "$datapath" "$placement"; then
    record_result "skipped" "$name" "$transport" "$encryption" "$profile" "$datapath" "$placement" 0 "$dir" 0
    return 0
  fi
  case_kernel_module="$kernel_module"
  if [[ "$placement" == "kernel" ]]; then
    case_kernel_module=1
  fi
  rm -rf "$dir"
  mkdir -p "$dir"
  log "run ${name}"
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
    export TRUSTIX_E2E_ROUTE_KIND_PROBE=0
    export TRUSTIX_E2E_TRANSPORT="$transport"
    export TRUSTIX_E2E_TRANSPORT_ENCRYPTION="$encryption"
    export TRUSTIX_E2E_TRANSPORT_PROFILE="$profile"
    export TRUSTIX_E2E_TRANSPORT_DATAPATH="$datapath"
    export TRUSTIX_E2E_CRYPTO_PLACEMENT="$placement"
    export TRUSTIX_E2E_KERNEL_MODULE="$case_kernel_module"
    export TRUSTIX_E2E_IPERF3="$iperf3"
    export TRUSTIX_E2E_IPERF3_SECONDS="$iperf3_seconds"
    export TRUSTIX_E2E_IPERF3_PARALLEL="$iperf3_parallel"
    export TRUSTIX_E2E_IPERF3_DIRECTIONS="$iperf3_directions"
    export TRUSTIX_E2E_IPERF3_MIN_SENT_GBPS="$iperf3_min_sent_gbps"
    export TRUSTIX_E2E_IPERF3_MIN_RECEIVED_GBPS="$iperf3_min_received_gbps"
    export TRUSTIX_E2E_PING_COUNT="$ping_count"
    export TRUSTIX_E2E_UDP_BURST_PACKETS="$udp_burst_packets"
    export TRUSTIX_E2E_UDP_BURST_SIZE="$udp_burst_size"
    export TRUSTIX_E2E_TCP_BURST_CONNECTIONS="$tcp_burst_connections"
    export TRUSTIX_E2E_TCP_BURST_SIZE="$tcp_burst_size"
    bash "$smoke_script"
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
  local line old_ifs transport encryption profile datapath placement extra failures=0
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
    extra="${6:-}"
    if [[ -z "$transport" || -z "$encryption" || -z "$profile" || -z "$datapath" || -z "$placement" || -n "$extra" ]]; then
      die "invalid production matrix case: $line"
    fi
    run_case "$transport" "$encryption" "$profile" "$datapath" "$placement" || failures=$((failures + 1))
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
  local nonnegative_decimal_re='^[0-9]+([.][0-9]+)?$'
  [[ "$iperf3_min_sent_gbps" =~ $nonnegative_decimal_re ]] || die "TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_IPERF3_MIN_SENT_GBPS/TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_IPERF3_MIN_GBPS must be a non-negative number"
  [[ "$iperf3_min_received_gbps" =~ $nonnegative_decimal_re ]] || die "TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_IPERF3_MIN_RECEIVED_GBPS/TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_IPERF3_MIN_GBPS must be a non-negative number"
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
