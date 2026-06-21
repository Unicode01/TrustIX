#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
verifier="${TRUSTIX_CROSS_HOST_GATE_VERIFIER:-${repo_root}/scripts/linux-cross-host-soak-verify.py}"
summary_dir="${TRUSTIX_CROSS_HOST_GATE_SUMMARY_DIR:-}"
gate_min_gbps="${TRUSTIX_CROSS_HOST_GATE_MIN_GBPS:-}"
userspace_min_gbps="${TRUSTIX_CROSS_HOST_USERSPACE_MIN_GBPS:-${gate_min_gbps:-0}}"
userspace_tc_min_gbps="${TRUSTIX_CROSS_HOST_USERSPACE_TC_MIN_GBPS:-${gate_min_gbps:-0}}"
tc_direct_min_gbps="${TRUSTIX_CROSS_HOST_TC_DIRECT_MIN_GBPS:-${gate_min_gbps:-0}}"
full_kmod_min_gbps="${TRUSTIX_CROSS_HOST_FULL_KMOD_MIN_GBPS:-${gate_min_gbps:-3}}"
secure_kudp_min_gbps="${TRUSTIX_CROSS_HOST_SECURE_KUDP_MIN_GBPS:-${gate_min_gbps:-1.5}}"
route_gso_min_gbps="${TRUSTIX_CROSS_HOST_ROUTE_GSO_MIN_GBPS:-${gate_min_gbps:-2.5}}"
min_seconds="${TRUSTIX_CROSS_HOST_GATE_MIN_SECONDS:-900}"
seconds_slop="${TRUSTIX_CROSS_HOST_GATE_SECONDS_SLOP:-1}"
require_binary_identity="${TRUSTIX_CROSS_HOST_GATE_REQUIRE_BINARY_IDENTITY:-1}"
full_kmod_min_sessions="${TRUSTIX_CROSS_HOST_FULL_KMOD_MIN_SESSIONS:-8}"
secure_kudp_min_sessions="${TRUSTIX_CROSS_HOST_SECURE_KUDP_MIN_SESSIONS:-8}"
secure_kudp_min_crypto_flows="${TRUSTIX_CROSS_HOST_SECURE_KUDP_MIN_CRYPTO_FLOWS:-1}"
secure_kudp_direct_error_budget="${TRUSTIX_CROSS_HOST_SECURE_KUDP_DIRECT_ERROR_BUDGET:-64}"
secure_kudp_replay_budget="${TRUSTIX_CROSS_HOST_SECURE_KUDP_REPLAY_BUDGET:-4096}"
route_gso_min_sessions="${TRUSTIX_CROSS_HOST_ROUTE_GSO_MIN_SESSIONS:-8}"
route_gso_session_error_budget="${TRUSTIX_CROSS_HOST_ROUTE_GSO_SESSION_ERROR_BUDGET:-2}"
compat_min_sessions="${TRUSTIX_CROSS_HOST_COMPAT_MIN_SESSIONS:-1}"

userspace_cases_raw="${TRUSTIX_CROSS_HOST_USERSPACE_CASES:-}"
userspace_tc_cases_raw="${TRUSTIX_CROSS_HOST_USERSPACE_TC_CASES:-}"
tc_direct_cases_raw="${TRUSTIX_CROSS_HOST_TC_DIRECT_CASES:-}"
userspace_case_min_gbps_raw="${TRUSTIX_CROSS_HOST_USERSPACE_CASE_MIN_GBPS:-}"
userspace_tc_case_min_gbps_raw="${TRUSTIX_CROSS_HOST_USERSPACE_TC_CASE_MIN_GBPS:-}"
tc_direct_case_min_gbps_raw="${TRUSTIX_CROSS_HOST_TC_DIRECT_CASE_MIN_GBPS:-}"
dd_full_kmod="${TRUSTIX_CROSS_HOST_DD_FULL_KMOD:-}"
owdeb_full_kmod="${TRUSTIX_CROSS_HOST_OWDEB_FULL_KMOD:-}"
dd_secure_kudp="${TRUSTIX_CROSS_HOST_DD_SECURE_KUDP:-}"
owdeb_secure_kudp="${TRUSTIX_CROSS_HOST_OWDEB_SECURE_KUDP:-}"
dd_route_gso="${TRUSTIX_CROSS_HOST_DD_ROUTE_GSO:-}"
owdeb_route_gso="${TRUSTIX_CROSS_HOST_OWDEB_ROUTE_GSO:-}"
full_kmod_cases_raw="${TRUSTIX_CROSS_HOST_FULL_KMOD_CASES:-}"
secure_kudp_cases_raw="${TRUSTIX_CROSS_HOST_SECURE_KUDP_CASES:-}"
route_gso_cases_raw="${TRUSTIX_CROSS_HOST_ROUTE_GSO_CASES:-}"
full_kmod_case_min_gbps_raw="${TRUSTIX_CROSS_HOST_FULL_KMOD_CASE_MIN_GBPS:-}"
secure_kudp_case_min_gbps_raw="${TRUSTIX_CROSS_HOST_SECURE_KUDP_CASE_MIN_GBPS:-}"
route_gso_case_min_gbps_raw="${TRUSTIX_CROSS_HOST_ROUTE_GSO_CASE_MIN_GBPS:-}"

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

validate_case_min_token() {
  local env_name="$1" token="$2"
  [[ "$token" == *=* ]] || die "${env_name} entries must be NAME=MIN_GBPS, got ${token}"
  [[ -n "${token%%=*}" ]] || die "${env_name} entries must be NAME=MIN_GBPS, got ${token}"
  [[ -n "${token#*=}" ]] || die "${env_name} entries must be NAME=MIN_GBPS, got ${token}"
  validate_number "$env_name" "${token#*=}"
}

validate_case_min_map() {
  local env_name="$1" raw="$2" token
  for token in $raw; do
    validate_case_min_token "$env_name" "$token"
  done
}

append_case_token() {
  local var_name="$1" token="$2" current
  current="${!var_name:-}"
  if [[ -n "$current" ]]; then
    printf -v "$var_name" '%s %s' "$current" "$token"
  else
    printf -v "$var_name" '%s' "$token"
  fi
}

case_min_gbps() {
  local case_token="$1" default_min_gbps="$2" min_map_raw="$3"
  local case_name="${case_token%%=*}" token
  for token in $min_map_raw; do
    if [[ "${token%%=*}" == "$case_name" ]]; then
      printf '%s\n' "${token#*=}"
      return 0
    fi
  done
  printf '%s\n' "$default_min_gbps"
}

case_name_exists() {
  local name="$1" cases="$2" token
  for token in $cases; do
    [[ "${token%%=*}" == "$name" ]] && return 0
  done
  return 1
}

case_min_exists() {
  local name="$1" min_map_raw="$2" token
  for token in $min_map_raw; do
    [[ "${token%%=*}" == "$name" ]] && return 0
  done
  return 1
}

validate_case_min_map_matches_cases() {
  local env_name="$1" min_map_raw="$2" cases="$3" token name
  [[ -n "$min_map_raw" ]] || return 0
  for token in $min_map_raw; do
    name="${token%%=*}"
    case_name_exists "$name" "$cases" || die "${env_name} references unknown case ${name}"
  done
  for token in $cases; do
    name="${token%%=*}"
    case_min_exists "$name" "$min_map_raw" || die "${env_name} missing min_gbps for case ${name}"
  done
}

case_label_name() {
  local prefix="$1" case_token="$2" case_name
  case_name="${case_token%%=*}"
  printf '%s-%s\n' "$prefix" "$(printf '%s' "$case_name" | tr -c 'A-Za-z0-9_.-' '_')"
}

run_gate() {
  local label="$1"
  local category_min_gbps="$2"
  shift 2
  set -- --min-gbps "$category_min_gbps" --min-seconds "$min_seconds" --seconds-slop "$seconds_slop" "$@"
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

run_gate_case_list() {
  local label="$1" category_min_gbps="$2" cases="$3" min_map_raw="$4"
  shift 4
  local token min_gbps case_label
  for token in $cases; do
    min_gbps="$(case_min_gbps "$token" "$category_min_gbps" "$min_map_raw")"
    case_label="$(case_label_name "$label" "$token")"
    run_gate "$case_label" "$min_gbps" --case "$token" "$@"
  done
}

main() {
  [[ -f "$verifier" ]] || die "verifier not found: ${verifier}"
  if [[ -n "$gate_min_gbps" ]]; then
    validate_number TRUSTIX_CROSS_HOST_GATE_MIN_GBPS "$gate_min_gbps"
  fi
  validate_number TRUSTIX_CROSS_HOST_USERSPACE_MIN_GBPS "$userspace_min_gbps"
  validate_number TRUSTIX_CROSS_HOST_USERSPACE_TC_MIN_GBPS "$userspace_tc_min_gbps"
  validate_number TRUSTIX_CROSS_HOST_TC_DIRECT_MIN_GBPS "$tc_direct_min_gbps"
  validate_number TRUSTIX_CROSS_HOST_FULL_KMOD_MIN_GBPS "$full_kmod_min_gbps"
  validate_number TRUSTIX_CROSS_HOST_SECURE_KUDP_MIN_GBPS "$secure_kudp_min_gbps"
  validate_number TRUSTIX_CROSS_HOST_ROUTE_GSO_MIN_GBPS "$route_gso_min_gbps"
  validate_number TRUSTIX_CROSS_HOST_GATE_MIN_SECONDS "$min_seconds"
  validate_number TRUSTIX_CROSS_HOST_GATE_SECONDS_SLOP "$seconds_slop"
  validate_number TRUSTIX_CROSS_HOST_FULL_KMOD_MIN_SESSIONS "$full_kmod_min_sessions"
  validate_number TRUSTIX_CROSS_HOST_SECURE_KUDP_MIN_SESSIONS "$secure_kudp_min_sessions"
  validate_number TRUSTIX_CROSS_HOST_SECURE_KUDP_MIN_CRYPTO_FLOWS "$secure_kudp_min_crypto_flows"
  validate_number TRUSTIX_CROSS_HOST_SECURE_KUDP_DIRECT_ERROR_BUDGET "$secure_kudp_direct_error_budget"
  validate_number TRUSTIX_CROSS_HOST_SECURE_KUDP_REPLAY_BUDGET "$secure_kudp_replay_budget"
  validate_number TRUSTIX_CROSS_HOST_ROUTE_GSO_MIN_SESSIONS "$route_gso_min_sessions"
  validate_number TRUSTIX_CROSS_HOST_ROUTE_GSO_SESSION_ERROR_BUDGET "$route_gso_session_error_budget"
  validate_number TRUSTIX_CROSS_HOST_COMPAT_MIN_SESSIONS "$compat_min_sessions"
  validate_case_min_map TRUSTIX_CROSS_HOST_USERSPACE_CASE_MIN_GBPS "$userspace_case_min_gbps_raw"
  validate_case_min_map TRUSTIX_CROSS_HOST_USERSPACE_TC_CASE_MIN_GBPS "$userspace_tc_case_min_gbps_raw"
  validate_case_min_map TRUSTIX_CROSS_HOST_TC_DIRECT_CASE_MIN_GBPS "$tc_direct_case_min_gbps_raw"
  validate_case_min_map TRUSTIX_CROSS_HOST_FULL_KMOD_CASE_MIN_GBPS "$full_kmod_case_min_gbps_raw"
  validate_case_min_map TRUSTIX_CROSS_HOST_SECURE_KUDP_CASE_MIN_GBPS "$secure_kudp_case_min_gbps_raw"
  validate_case_min_map TRUSTIX_CROSS_HOST_ROUTE_GSO_CASE_MIN_GBPS "$route_gso_case_min_gbps_raw"

  local userspace_cases=""
  local userspace_tc_cases=""
  local tc_direct_cases=""
  local full_kmod_cases=""
  local secure_kudp_cases=""
  local route_gso_cases=""
  local userspace_case_count=0
  local userspace_tc_case_count=0
  local tc_direct_case_count=0
  local full_kmod_case_count=0
  local secure_kudp_case_count=0
  local route_gso_case_count=0
  local token
  for token in $userspace_cases_raw; do
    validate_case_token "$token"
    append_case_token userspace_cases "$token"
    userspace_case_count=$((userspace_case_count + 1))
  done
  for token in $userspace_tc_cases_raw; do
    validate_case_token "$token"
    append_case_token userspace_tc_cases "$token"
    userspace_tc_case_count=$((userspace_tc_case_count + 1))
  done
  for token in $tc_direct_cases_raw; do
    validate_case_token "$token"
    append_case_token tc_direct_cases "$token"
    tc_direct_case_count=$((tc_direct_case_count + 1))
  done
  if [[ -n "$dd_full_kmod" ]]; then
    append_case_token full_kmod_cases "dd-fullkmod=${dd_full_kmod}"
    full_kmod_case_count=$((full_kmod_case_count + 1))
  fi
  if [[ -n "$owdeb_full_kmod" ]]; then
    append_case_token full_kmod_cases "owdeb-fullkmod=${owdeb_full_kmod}"
    full_kmod_case_count=$((full_kmod_case_count + 1))
  fi
  for token in $full_kmod_cases_raw; do
    validate_case_token "$token"
    append_case_token full_kmod_cases "$token"
    full_kmod_case_count=$((full_kmod_case_count + 1))
  done
  if [[ -n "$dd_secure_kudp" ]]; then
    append_case_token secure_kudp_cases "dd-secure-kudp=${dd_secure_kudp}"
    secure_kudp_case_count=$((secure_kudp_case_count + 1))
  fi
  if [[ -n "$owdeb_secure_kudp" ]]; then
    append_case_token secure_kudp_cases "owdeb-secure-kudp=${owdeb_secure_kudp}"
    secure_kudp_case_count=$((secure_kudp_case_count + 1))
  fi
  for token in $secure_kudp_cases_raw; do
    validate_case_token "$token"
    append_case_token secure_kudp_cases "$token"
    secure_kudp_case_count=$((secure_kudp_case_count + 1))
  done
  if [[ -n "$dd_route_gso" ]]; then
    append_case_token route_gso_cases "dd-routegso=${dd_route_gso}"
    route_gso_case_count=$((route_gso_case_count + 1))
  fi
  if [[ -n "$owdeb_route_gso" ]]; then
    append_case_token route_gso_cases "owdeb-routegso=${owdeb_route_gso}"
    route_gso_case_count=$((route_gso_case_count + 1))
  fi
  for token in $route_gso_cases_raw; do
    validate_case_token "$token"
    append_case_token route_gso_cases "$token"
    route_gso_case_count=$((route_gso_case_count + 1))
  done
  validate_case_min_map_matches_cases TRUSTIX_CROSS_HOST_USERSPACE_CASE_MIN_GBPS "$userspace_case_min_gbps_raw" "$userspace_cases"
  validate_case_min_map_matches_cases TRUSTIX_CROSS_HOST_USERSPACE_TC_CASE_MIN_GBPS "$userspace_tc_case_min_gbps_raw" "$userspace_tc_cases"
  validate_case_min_map_matches_cases TRUSTIX_CROSS_HOST_TC_DIRECT_CASE_MIN_GBPS "$tc_direct_case_min_gbps_raw" "$tc_direct_cases"
  validate_case_min_map_matches_cases TRUSTIX_CROSS_HOST_FULL_KMOD_CASE_MIN_GBPS "$full_kmod_case_min_gbps_raw" "$full_kmod_cases"
  validate_case_min_map_matches_cases TRUSTIX_CROSS_HOST_SECURE_KUDP_CASE_MIN_GBPS "$secure_kudp_case_min_gbps_raw" "$secure_kudp_cases"
  validate_case_min_map_matches_cases TRUSTIX_CROSS_HOST_ROUTE_GSO_CASE_MIN_GBPS "$route_gso_case_min_gbps_raw" "$route_gso_cases"

  if [[ "$userspace_case_count" -eq 0 && "$userspace_tc_case_count" -eq 0 && "$tc_direct_case_count" -eq 0 && "$full_kmod_case_count" -eq 0 && "$secure_kudp_case_count" -eq 0 && "$route_gso_case_count" -eq 0 ]]; then
    die "set TRUSTIX_CROSS_HOST_USERSPACE_CASES/TRUSTIX_CROSS_HOST_USERSPACE_TC_CASES/TRUSTIX_CROSS_HOST_TC_DIRECT_CASES/TRUSTIX_CROSS_HOST_DD_FULL_KMOD/TRUSTIX_CROSS_HOST_OWDEB_FULL_KMOD/TRUSTIX_CROSS_HOST_DD_SECURE_KUDP/TRUSTIX_CROSS_HOST_OWDEB_SECURE_KUDP/TRUSTIX_CROSS_HOST_DD_ROUTE_GSO/TRUSTIX_CROSS_HOST_OWDEB_ROUTE_GSO or *_CASES"
  fi

  if [[ "$userspace_case_count" -gt 0 ]]; then
    run_gate_case_list userspace "$userspace_min_gbps" "$userspace_cases" "$userspace_case_min_gbps_raw" \
      --require-transport-sessions-min "${compat_min_sessions}" \
      --require-status-max data_path.counters.session_dial_errors=0 \
      --require-status-max data_path.counters.session_heartbeat_timeouts=0
  fi

  if [[ "$userspace_tc_case_count" -gt 0 ]]; then
    run_gate_case_list userspace-tc "$userspace_tc_min_gbps" "$userspace_tc_cases" "$userspace_tc_case_min_gbps_raw" \
      --require-transport-sessions-min "${compat_min_sessions}" \
      --require-status-max data_path.counters.session_dial_errors=0 \
      --require-status-max data_path.counters.session_heartbeat_timeouts=0
  fi

  if [[ "$tc_direct_case_count" -gt 0 ]]; then
    run_gate_case_list tc-direct "$tc_direct_min_gbps" "$tc_direct_cases" "$tc_direct_case_min_gbps_raw" \
      --require-transport-policy-stat encryption=plaintext \
      --require-transport-policy-stat profile=performance \
      --require-transport-policy-stat datapath=tc_xdp \
      --require-transport-policy-stat crypto_placement=userspace \
      --require-transport-sessions-min "${compat_min_sessions}" \
      --require-status-max data_path.counters.session_dial_errors=0 \
      --require-status-max data_path.counters.session_heartbeat_timeouts=0 \
      --require-datapath-stat kernel_udp.provider=tc_direct \
      --require-datapath-stat kernel_udp.fast_path=true \
      --require-datapath-stat kernel_udp.direct_only=true \
      --require-datapath-any-min kernel_udp.active_flows=1
  fi

  if [[ "$full_kmod_case_count" -gt 0 ]]; then
    run_gate_case_list full-kmod "$full_kmod_min_gbps" "$full_kmod_cases" "$full_kmod_case_min_gbps_raw" \
      --require-transport-policy-stat encryption=plaintext \
      --require-transport-policy-stat profile=performance \
      --require-transport-policy-stat datapath=kernel_module \
      --require-transport-policy-stat crypto_placement=userspace \
      --require-transport-policy-min session_pool_size="${full_kmod_min_sessions}" \
      --require-transport-policy-stat session_pool_strategy=flow \
      --require-transport-policy-stat session_pool_warmup=true \
      --require-status-max data_path.counters.session_dial_errors=0 \
      --require-status-max data_path.counters.session_heartbeat_timeouts=0 \
      --require-datapath-stat kernel_udp.provider_stats.kernel_datapath_full_plaintext_provider=1 \
      --require-datapath-min kernel_rx_stage.rx_worker_injected=1 \
      --require-datapath-min counters.session_dials="${full_kmod_min_sessions}" \
      --require-datapath-max counters.session_dial_errors=0 \
      --require-module-param-min trustix_datapath.session_records="${full_kmod_min_sessions}" \
      --require-module-param-min trustix_datapath.session_wire_records="${full_kmod_min_sessions}" \
      --require-module-param-min trustix_datapath.rx_worker_single_coalesce_max_frames=32 \
      --require-module-param-any-min trustix_datapath.tx_plaintext_outer_gso_segments=1 \
      --require-module-param-any-min trustix_datapath.tx_plaintext_direct_xmit_dst_mac_cache_hits=1 \
      --require-module-param-any-min trustix_datapath.rx_worker_gso_xmit_segments=1 \
      --require-module-param-max trustix_datapath.rx_worker_alloc_errors=0 \
      --require-module-param-max trustix_datapath.rx_worker_deliver_errors=0 \
      --require-module-param-max trustix_datapath.rx_worker_gso_xmit_errors=0 \
      --require-module-param-max trustix_datapath.rx_worker_xmit_ret_errors=0 \
      --require-module-param-max trustix_datapath.rx_worker_xmit_other_ret_errors=0 \
      --require-module-param-max trustix_datapath.rx_worker_xmit_dev_forward_errors=0 \
      --require-module-param-max trustix_datapath.rx_worker_xmit_peer_forward_errors=0 \
      --require-module-param-max trustix_datapath.tx_plaintext_build_errors=0 \
      --require-module-param-max trustix_datapath.tx_plaintext_no_sessions=0 \
      --require-module-param-max trustix_datapath.tx_plaintext_no_wires=0 \
      --require-module-param-max trustix_datapath.tx_plaintext_stale_wires=0 \
      --require-module-param-max trustix_datapath.tx_plaintext_xmit_errors=0 \
      --require-module-param-max trustix_datapath.tx_plaintext_outer_gso_errors=0 \
      --require-module-param-max trustix_datapath.tx_plaintext_queue_drops=0
  fi

  if [[ "$secure_kudp_case_count" -gt 0 ]]; then
    run_gate_case_list secure-kudp "$secure_kudp_min_gbps" "$secure_kudp_cases" "$secure_kudp_case_min_gbps_raw" \
      --require-transport-policy-stat encryption=secure \
      --require-transport-policy-stat crypto_placement=kernel \
      --require-transport-policy-stat datapath=tc_xdp \
      --require-transport-policy-min session_pool_size="${secure_kudp_min_sessions}" \
      --require-transport-policy-stat session_pool_strategy=flow \
      --require-transport-policy-stat session_pool_warmup=true \
      --require-status-max data_path.counters.session_dial_errors=0 \
      --require-status-max data_path.counters.session_heartbeat_timeouts=0 \
      --require-datapath-stat kernel_udp.kernel_crypto=true \
      --require-datapath-stat kernel_udp.requested_crypto=kernel \
      --require-datapath-stat kernel_udp.effective_crypto=kernel \
      --require-datapath-stat kernel_udp.provider_stats.kernel_crypto_flow_map_ready=1 \
      --require-datapath-min kernel_udp.provider_stats.kernel_crypto_flow_map_entries="${secure_kudp_min_crypto_flows}" \
      --require-datapath-min kernel_udp.provider_stats.kernel_crypto_flow_map_updates="${secure_kudp_min_crypto_flows}" \
      --require-datapath-stat kernel_udp.provider_stats.kernel_crypto_direct_slot_provider_ready=1 \
      --require-datapath-stat kernel_udp.provider_stats.kernel_crypto_direct_kfunc_fastpath_ready=1 \
      --require-datapath-stat kernel_udp.provider_stats.kernel_crypto_tc_direct_ready=1 \
      --require-datapath-stat kernel_udp.provider_stats.tc_kernel_udp_tx_direct_only_enabled=1 \
      --require-datapath-stat kernel_udp.provider_stats.tc_kernel_udp_tx_secure_direct_attached=1 \
      --require-datapath-stat kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_attached=1 \
      --require-datapath-stat kernel_udp.provider_stats.tc_kernel_udp_tx_secure_direct_trust_inner_checksums=1 \
      --require-datapath-stat kernel_udp.provider_stats.tc_kernel_udp_tx_secure_direct_kfunc_seal_enabled=1 \
      --require-datapath-stat kernel_udp.provider_stats.tc_kernel_udp_tx_secure_direct_route_tcp_gso_kfunc=1 \
      --require-datapath-stat kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_kfunc_open_enabled=1 \
      --require-datapath-stat kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_skb_open_kfunc=0 \
      --require-datapath-max kernel_udp.provider_stats.kernel_crypto_provider_unavailable_errors=0 \
      --require-datapath-max kernel_udp.provider_stats.kernel_crypto_flow_rejects=0 \
      --require-datapath-max kernel_udp.provider_stats.kernel_crypto_frame_rejects=0 \
      --require-datapath-max kernel_udp.provider_stats.kernel_crypto_frame_seal_errors=0 \
      --require-datapath-max kernel_udp.provider_stats.kernel_crypto_frame_open_errors=0 \
      --require-datapath-max kernel_udp.provider_stats.kernel_crypto_frame_replay_drops=0 \
      --require-datapath-max kernel_udp.provider_stats.tc_kernel_udp_tx_secure_direct_encrypt_errors=0 \
      --require-datapath-max kernel_udp.provider_stats.tc_kernel_udp_tx_secure_direct_sequence_errors=0 \
      --require-datapath-max kernel_udp.provider_stats.tc_kernel_udp_tx_secure_direct_drops=0 \
      --require-datapath-max kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_header_errors=0 \
      --require-datapath-max kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_decrypt_errors="${secure_kudp_direct_error_budget}" \
      --require-datapath-max kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_replay_drops="${secure_kudp_replay_budget}" \
      --require-datapath-max kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_drops="${secure_kudp_replay_budget}" \
      --require-module-param-min trustix_crypto.kfunc_simd_fastpath=1 \
      --require-module-param-min trustix_crypto.kfunc_simd_irq_fpu_fastpath=1 \
      --require-module-param-any-min trustix_crypto.direct_kfunc_seal_calls=1 \
      --require-module-param-any-min trustix_crypto.direct_kfunc_open_calls=1 \
      --require-module-param-max trustix_crypto.direct_kfunc_errors="${secure_kudp_direct_error_budget}" \
      --require-module-param-min trustix_datapath_helpers.route_tcp_gso_async_secure_seal_batch=1 \
      --require-module-param-any-min trustix_datapath_helpers.route_tcp_gso_async_xmit_packets=1 \
      --require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_flow_errors=0 \
      --require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_plan_errors=0 \
      --require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_mtu_errors=0 \
      --require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_queue_full=0 \
      --require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_queue_bytes_full=0 \
      --require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_alloc_errors=0 \
      --require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_clone_errors=0 \
      --require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_segment_errors=0 \
      --require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_prepare_errors=0 \
      --require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_txq_stopped_drops=0 \
      --require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_xmit_errors=0 \
      --require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_stream_errors=0 \
      --require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_stream_xmit_errors=0 \
      --require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_stream_direct_errors=0 \
      --require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_stream_outer_gso_errors=0 \
      --require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_stream_outer_gso_blocked=0 \
      --require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_stream_outer_gso_verify_errors=0 \
      --require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_stream_cross_item_errors=0 \
      --require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_stream_cross_item_tail_stitch_errors=0
  fi

  if [[ "$route_gso_case_count" -gt 0 ]]; then
    run_gate_case_list route-gso "$route_gso_min_gbps" "$route_gso_cases" "$route_gso_case_min_gbps_raw" \
      --require-transport-policy-stat encryption=plaintext \
      --require-transport-policy-stat profile=performance \
      --require-transport-policy-stat datapath=kernel_module \
      --require-transport-policy-stat crypto_placement=userspace \
      --require-transport-policy-min session_pool_size="${route_gso_min_sessions}" \
      --require-transport-policy-stat session_pool_strategy=flow \
      --require-transport-policy-stat session_pool_warmup=true \
      --require-transport-sessions-min "${route_gso_min_sessions}" \
      --require-status-min data_path.active_sessions="${route_gso_min_sessions}" \
      --require-status-max data_path.counters.session_dial_errors="${route_gso_session_error_budget}" \
      --require-status-max data_path.counters.session_heartbeat_timeouts=0 \
      --require-datapath-stat kernel_udp.provider_stats.tc_experimental_tcp_tx_direct_route_tcp_gso_async_kfunc=1 \
      --require-datapath-stat kernel_udp.provider_stats.tc_experimental_tcp_tx_direct_route_tcp_gso_async_kfunc_requested=1 \
      --require-datapath-stat kernel_udp.provider_stats.tc_kernel_udp_tx_direct_experimental_tcp_only=1 \
      --require-module-param-min trustix_datapath_helpers.route_tcp_gso_async_hash_tx_queue=1 \
      --require-module-param-any-min trustix_datapath_helpers.route_tcp_gso_async_stream_outer_gso_frames=1 \
      --require-module-param-any-min trustix_datapath_helpers.route_tcp_gso_async_xmit_packets=1 \
      --require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_flow_errors=0 \
      --require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_plan_errors=0 \
      --require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_mtu_errors=0 \
      --require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_queue_full=0 \
      --require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_queue_bytes_full=0 \
      --require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_alloc_errors=0 \
      --require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_clone_errors=0 \
      --require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_segment_errors=0 \
      --require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_prepare_errors=0 \
      --require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_txq_stopped_drops=0 \
      --require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_xmit_errors=0 \
      --require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_stream_errors=0 \
      --require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_stream_xmit_errors=0 \
      --require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_stream_direct_errors=0 \
      --require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_stream_outer_gso_errors=0 \
      --require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_stream_outer_gso_blocked=0 \
      --require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_stream_outer_gso_verify_errors=0 \
      --require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_stream_cross_item_errors=0 \
      --require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_stream_cross_item_tail_stitch_errors=0
  fi
}

main "$@"
