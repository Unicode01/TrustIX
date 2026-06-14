#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
verifier="${TRUSTIX_CROSS_HOST_GATE_VERIFIER:-${repo_root}/scripts/linux-cross-host-soak-verify.py}"
summary_dir="${TRUSTIX_CROSS_HOST_GATE_SUMMARY_DIR:-}"
min_gbps="${TRUSTIX_CROSS_HOST_GATE_MIN_GBPS:-4}"
min_seconds="${TRUSTIX_CROSS_HOST_GATE_MIN_SECONDS:-120}"
seconds_slop="${TRUSTIX_CROSS_HOST_GATE_SECONDS_SLOP:-1}"
require_binary_identity="${TRUSTIX_CROSS_HOST_GATE_REQUIRE_BINARY_IDENTITY:-1}"

dd_full_kmod="${TRUSTIX_CROSS_HOST_DD_FULL_KMOD:-}"
owdeb_full_kmod="${TRUSTIX_CROSS_HOST_OWDEB_FULL_KMOD:-}"
dd_route_gso="${TRUSTIX_CROSS_HOST_DD_ROUTE_GSO:-}"
full_kmod_cases_raw="${TRUSTIX_CROSS_HOST_FULL_KMOD_CASES:-}"
route_gso_cases_raw="${TRUSTIX_CROSS_HOST_ROUTE_GSO_CASES:-}"

log() {
  printf '[trustix-cross-host-gate] %s\n' "$*" >&2
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

validate_number() {
  local name="$1" value="$2"
  local re='^[0-9]+([.][0-9]+)?$'
  [[ "$value" =~ $re ]] || die "${name} must be a non-negative number"
}

validate_case_token() {
  local token="$1"
  [[ "$token" == *=* ]] || die "case must be NAME=PATH, got ${token}"
  [[ -n "${token%%=*}" ]] || die "case must be NAME=PATH, got ${token}"
  [[ -n "${token#*=}" ]] || die "case must be NAME=PATH, got ${token}"
}

run_gate() {
  local label="$1"
  shift
  set -- --min-gbps "$min_gbps" --min-seconds "$min_seconds" --seconds-slop "$seconds_slop" "$@"
  if truthy "$require_binary_identity"; then
    set -- "$@" --require-binary-identity
  fi
  if [[ -n "$summary_dir" ]]; then
    mkdir -p "$summary_dir"
    set -- "$@" --summary "${summary_dir}/${label}.jsonl"
  fi
  log "run ${label}"
  python3 "$verifier" "$@"
}

main() {
  [[ -f "$verifier" ]] || die "verifier not found: ${verifier}"
  validate_number TRUSTIX_CROSS_HOST_GATE_MIN_GBPS "$min_gbps"
  validate_number TRUSTIX_CROSS_HOST_GATE_MIN_SECONDS "$min_seconds"
  validate_number TRUSTIX_CROSS_HOST_GATE_SECONDS_SLOP "$seconds_slop"

  local full_kmod_args=""
  local route_gso_args=""
  local full_kmod_case_count=0
  local route_gso_case_count=0
  if [[ -n "$dd_full_kmod" ]]; then
    full_kmod_args="${full_kmod_args} --case dd-fullkmod=${dd_full_kmod}"
    full_kmod_case_count=$((full_kmod_case_count + 1))
  fi
  if [[ -n "$owdeb_full_kmod" ]]; then
    full_kmod_args="${full_kmod_args} --case owdeb-fullkmod=${owdeb_full_kmod}"
    full_kmod_case_count=$((full_kmod_case_count + 1))
  fi
  local token
  for token in $full_kmod_cases_raw; do
    validate_case_token "$token"
    full_kmod_args="${full_kmod_args} --case ${token}"
    full_kmod_case_count=$((full_kmod_case_count + 1))
  done
  if [[ -n "$dd_route_gso" ]]; then
    route_gso_args="${route_gso_args} --case dd-routegso=${dd_route_gso}"
    route_gso_case_count=$((route_gso_case_count + 1))
  fi
  for token in $route_gso_cases_raw; do
    validate_case_token "$token"
    route_gso_args="${route_gso_args} --case ${token}"
    route_gso_case_count=$((route_gso_case_count + 1))
  done

  if [[ "$full_kmod_case_count" -eq 0 && "$route_gso_case_count" -eq 0 ]]; then
    die "set TRUSTIX_CROSS_HOST_DD_FULL_KMOD/TRUSTIX_CROSS_HOST_OWDEB_FULL_KMOD/TRUSTIX_CROSS_HOST_DD_ROUTE_GSO or *_CASES"
  fi

  if [[ "$full_kmod_case_count" -gt 0 ]]; then
    run_gate full-kmod $full_kmod_args \
      --require-datapath-stat kernel_udp.provider_stats.kernel_datapath_full_plaintext_provider=1
  fi

  if [[ "$route_gso_case_count" -gt 0 ]]; then
    run_gate route-gso $route_gso_args \
      --require-datapath-stat kernel_udp.provider_stats.tc_experimental_tcp_tx_direct_route_tcp_gso_async_kfunc=1 \
      --require-datapath-stat kernel_udp.provider_stats.tc_experimental_tcp_tx_direct_route_tcp_gso_async_kfunc_requested=1 \
      --require-datapath-stat kernel_udp.provider_stats.tc_kernel_udp_tx_direct_experimental_tcp_only=1
  fi
}

main "$@"
