#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workdir="${TRUSTIX_PRODUCTION_SOAK_WORKDIR:-$(mktemp -d /tmp/trustix-production-soak.XXXXXX)}"
workdir="$(mkdir -p "$workdir" && cd "$workdir" && pwd -P)"
matrix_script="${TRUSTIX_PRODUCTION_SOAK_MATRIX_SCRIPT:-${repo_root}/scripts/linux-production-transport-matrix.sh}"
duration_seconds="${TRUSTIX_PRODUCTION_SOAK_DURATION_SECONDS:-3600}"
iterations="${TRUSTIX_PRODUCTION_SOAK_ITERATIONS:-0}"
continue_on_fail="${TRUSTIX_PRODUCTION_SOAK_CONTINUE_ON_FAIL:-0}"
summary_path="${TRUSTIX_PRODUCTION_SOAK_SUMMARY:-${workdir}/summary.jsonl}"
matrix_iperf3_seconds="${TRUSTIX_PRODUCTION_SOAK_IPERF3_SECONDS:-120}"
matrix_iperf3_parallel="${TRUSTIX_PRODUCTION_SOAK_IPERF3_PARALLEL:-4}"
matrix_iperf3_directions="${TRUSTIX_PRODUCTION_SOAK_IPERF3_DIRECTIONS:-both}"
matrix_perf_fast="${TRUSTIX_PRODUCTION_SOAK_PERF_FAST:-1}"
matrix_scope="${TRUSTIX_PRODUCTION_SOAK_MATRIX_SCOPE:-single_host}"
matrix_case_timeout="${TRUSTIX_PRODUCTION_SOAK_CASE_TIMEOUT:-15m}"
matrix_ping_count="${TRUSTIX_PRODUCTION_SOAK_PING_COUNT:-5}"
matrix_udp_burst_packets="${TRUSTIX_PRODUCTION_SOAK_UDP_BURST_PACKETS:-512}"
matrix_tcp_burst_connections="${TRUSTIX_PRODUCTION_SOAK_TCP_BURST_CONNECTIONS:-32}"

log() {
  printf '[trustix-production-soak] %s\n' "$*" >&2
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

json_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  printf '%s' "$value"
}

record_result() {
  local status="$1" iteration="$2" elapsed="$3" rc="$4" dir="$5"
  printf '{"status":"%s","iteration":%s,"elapsed_seconds":%s,"exit_code":%s,"workdir":"%s"}\n' \
    "$status" "$iteration" "$elapsed" "$rc" "$(json_escape "$dir")" >>"$summary_path"
}

validate_positive_int() {
  local name="$1" value="$2"
  [[ "$value" =~ ^[1-9][0-9]*$ ]] || die "${name} must be a positive integer"
}

validate_nonnegative_int() {
  local name="$1" value="$2"
  [[ "$value" =~ ^[0-9]+$ ]] || die "${name} must be a non-negative integer"
}

run_iteration() {
  local iteration="$1"
  local dir="${workdir}/iter-${iteration}"
  local start end elapsed rc
  rm -rf "$dir"
  mkdir -p "$dir"
  log "iteration=${iteration} workdir=${dir}"
  start="$(date +%s)"
  set +e
  (
    export TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_WORKDIR="$dir"
    export TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_KEEP="${TRUSTIX_PRODUCTION_SOAK_KEEP_ITER_WORKDIRS:-1}"
    export TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_IPERF3=1
    export TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_IPERF3_SECONDS="$matrix_iperf3_seconds"
    export TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_IPERF3_PARALLEL="$matrix_iperf3_parallel"
    export TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_IPERF3_DIRECTIONS="$matrix_iperf3_directions"
    export TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_PERF_FAST="$matrix_perf_fast"
    export TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_SCOPE="$matrix_scope"
    export TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_CASE_TIMEOUT="$matrix_case_timeout"
    export TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_PING_COUNT="$matrix_ping_count"
    export TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_UDP_BURST_PACKETS="$matrix_udp_burst_packets"
    export TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_TCP_BURST_CONNECTIONS="$matrix_tcp_burst_connections"
    if [[ -n "${TRUSTIX_PRODUCTION_SOAK_CASES:-}" ]]; then
      export TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_CASES="$TRUSTIX_PRODUCTION_SOAK_CASES"
    fi
    bash "$matrix_script"
  ) >"${dir}.log" 2>&1
  rc=$?
  set -e
  end="$(date +%s)"
  elapsed="$((end - start))"
  if [[ "$rc" == "0" ]]; then
    record_result pass "$iteration" "$elapsed" "$rc" "$dir"
    return 0
  fi
  record_result fail "$iteration" "$elapsed" "$rc" "$dir"
  log "iteration=${iteration} failed; see ${dir}.log"
  return "$rc"
}

main() {
  [[ "$(uname -s)" == "Linux" ]] || die "soak must run on Linux"
  [[ "${EUID:-$(id -u)}" == "0" ]] || die "soak must run as root"
  [[ -f "$matrix_script" ]] || die "matrix script not found: $matrix_script"
  validate_positive_int TRUSTIX_PRODUCTION_SOAK_DURATION_SECONDS "$duration_seconds"
  validate_nonnegative_int TRUSTIX_PRODUCTION_SOAK_ITERATIONS "$iterations"
  validate_positive_int TRUSTIX_PRODUCTION_SOAK_IPERF3_SECONDS "$matrix_iperf3_seconds"
  validate_positive_int TRUSTIX_PRODUCTION_SOAK_IPERF3_PARALLEL "$matrix_iperf3_parallel"
  case "$matrix_perf_fast" in
    0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_PRODUCTION_SOAK_PERF_FAST must be truthy or falsey" ;;
  esac
  case "$matrix_scope" in
    single_host|cross_host|all) ;;
    *) die "TRUSTIX_PRODUCTION_SOAK_MATRIX_SCOPE must be single_host, cross_host, or all" ;;
  esac
  local timeout_duration_re='^[1-9][0-9]*(s|m|h|d)?$'
  [[ -z "$matrix_case_timeout" || "$matrix_case_timeout" =~ $timeout_duration_re ]] || die "TRUSTIX_PRODUCTION_SOAK_CASE_TIMEOUT must be a coreutils timeout duration"
  validate_positive_int TRUSTIX_PRODUCTION_SOAK_PING_COUNT "$matrix_ping_count"
  validate_nonnegative_int TRUSTIX_PRODUCTION_SOAK_UDP_BURST_PACKETS "$matrix_udp_burst_packets"
  validate_nonnegative_int TRUSTIX_PRODUCTION_SOAK_TCP_BURST_CONNECTIONS "$matrix_tcp_burst_connections"

  mkdir -p "$workdir"
  : >"$summary_path"
  log "workdir=${workdir}"
  log "summary=${summary_path}"

  local start now deadline iteration failures
  start="$(date +%s)"
  deadline="$((start + duration_seconds))"
  iteration=1
  failures=0
  while true; do
    now="$(date +%s)"
    if [[ "$iterations" != "0" && "$iteration" -gt "$iterations" ]]; then
      break
    fi
    if [[ "$iterations" == "0" && "$now" -ge "$deadline" ]]; then
      break
    fi
    if ! run_iteration "$iteration"; then
      failures="$((failures + 1))"
      truthy "$continue_on_fail" || break
    fi
    iteration="$((iteration + 1))"
  done

  log "summary=${summary_path}"
  if [[ "$failures" -gt 0 ]]; then
    log "completed with ${failures} failed iteration(s)"
    return 1
  fi
}

main "$@"
