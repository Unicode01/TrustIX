#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

runner="${TRUSTIX_CROSS_HOST_CONCURRENT_RUNNER:-${repo_root}/scripts/linux-cross-host-soak-runner.sh}"
verifier="${TRUSTIX_CROSS_HOST_CONCURRENT_VERIFIER:-${repo_root}/scripts/linux-cross-host-soak-verify.py}"
workdir="${TRUSTIX_CROSS_HOST_CONCURRENT_WORKDIR:-$(mktemp -d /tmp/trustix-cross-host-concurrent.XXXXXX)}"
workdir="$(mkdir -p "$workdir" && cd "$workdir" && pwd -P)"
cases_raw="${TRUSTIX_CROSS_HOST_CONCURRENT_CASES:-userspace-udp-secure userspace-tcp-secure userspace-tix-tcp-secure}"
seconds="${TRUSTIX_CROSS_HOST_CONCURRENT_SECONDS:-600}"
timeout_slop="${TRUSTIX_CROSS_HOST_CONCURRENT_TIMEOUT_SLOP:-120}"
min_gbps="${TRUSTIX_CROSS_HOST_CONCURRENT_MIN_GBPS:-0}"
verify="${TRUSTIX_CROSS_HOST_CONCURRENT_VERIFY:-1}"
dry_run="${TRUSTIX_CROSS_HOST_CONCURRENT_DRY_RUN:-0}"
summary_path="${TRUSTIX_CROSS_HOST_CONCURRENT_SUMMARY:-${workdir}/summary.jsonl}"
remote_parent="${TRUSTIX_CROSS_HOST_REMOTE_BASE:-/tmp}"
remote_base="${TRUSTIX_CROSS_HOST_CONCURRENT_REMOTE_BASE:-${remote_parent}/trustix-cross-host-concurrent-$(date +%Y%m%d-%H%M%S)-$$}"
default_keep_remote="${TRUSTIX_CROSS_HOST_KEEP_REMOTE:-0}"
keep_remote="${TRUSTIX_CROSS_HOST_CONCURRENT_KEEP_REMOTE:-$default_keep_remote}"
keep_local="${TRUSTIX_CROSS_HOST_CONCURRENT_KEEP_LOCAL:-1}"
unload_modules="${TRUSTIX_CROSS_HOST_CONCURRENT_UNLOAD_MODULES:-0}"
base_api_port="${TRUSTIX_CROSS_HOST_CONCURRENT_API_BASE:-28787}"
base_peer_port="${TRUSTIX_CROSS_HOST_CONCURRENT_PEER_BASE:-29443}"
base_data_port="${TRUSTIX_CROSS_HOST_CONCURRENT_DATA_BASE:-29700}"
base_iperf_port="${TRUSTIX_CROSS_HOST_CONCURRENT_IPERF_BASE:-35201}"
base_lan_octet="${TRUSTIX_CROSS_HOST_CONCURRENT_LAN_OCTET_BASE:-80}"
base_carrier_octet="${TRUSTIX_CROSS_HOST_CONCURRENT_CARRIER_OCTET_BASE:-100}"
base_iptunnel_port="${TRUSTIX_CROSS_HOST_CONCURRENT_IPTUNNEL_PORT_BASE:-47829}"
base_vxlan_vni="${TRUSTIX_CROSS_HOST_CONCURRENT_VXLAN_VNI_BASE:-700}"
base_vxlan_port="${TRUSTIX_CROSS_HOST_CONCURRENT_VXLAN_PORT_BASE:-4789}"
port_stride="${TRUSTIX_CROSS_HOST_CONCURRENT_PORT_STRIDE:-10}"
transport_snapshot_delay="${TRUSTIX_CROSS_HOST_CONCURRENT_TRANSPORT_SNAPSHOT_DELAY:-5}"
forbid_trustix_modules="${TRUSTIX_CROSS_HOST_CONCURRENT_FORBID_TRUSTIX_MODULES:-1}"
require_binary_identity="${TRUSTIX_CROSS_HOST_CONCURRENT_REQUIRE_BINARY_IDENTITY:-1}"
node_a="${TRUSTIX_CROSS_HOST_CONCURRENT_A:-${TRUSTIX_CROSS_HOST_A:-local}}"
node_b="${TRUSTIX_CROSS_HOST_CONCURRENT_B:-${TRUSTIX_CROSS_HOST_B:-}}"
ssh_opts="${TRUSTIX_CROSS_HOST_CONCURRENT_SSH_OPTS:-${TRUSTIX_CROSS_HOST_SSH_OPTS:-}}"
bin_dir="${TRUSTIX_CROSS_HOST_CONCURRENT_BIN_DIR:-${TRUSTIX_CROSS_HOST_BIN_DIR:-}}"
bin_dir_a="${TRUSTIX_CROSS_HOST_CONCURRENT_BIN_DIR_A:-${TRUSTIX_CROSS_HOST_BIN_DIR_A:-$bin_dir}}"
bin_dir_b="${TRUSTIX_CROSS_HOST_CONCURRENT_BIN_DIR_B:-${TRUSTIX_CROSS_HOST_BIN_DIR_B:-$bin_dir}}"
trustix_ca="${TRUSTIX_CROSS_HOST_CONCURRENT_TRUSTIX_CA:-${TRUSTIX_CROSS_HOST_TRUSTIX_CA:-}}"
underlay_a_ip="${TRUSTIX_CROSS_HOST_CONCURRENT_A_UNDERLAY_IP:-${TRUSTIX_CROSS_HOST_A_UNDERLAY_IP:-}}"
underlay_b_ip="${TRUSTIX_CROSS_HOST_CONCURRENT_B_UNDERLAY_IP:-${TRUSTIX_CROSS_HOST_B_UNDERLAY_IP:-}}"
underlay_a_if="${TRUSTIX_CROSS_HOST_CONCURRENT_A_UNDERLAY_IF:-${TRUSTIX_CROSS_HOST_A_UNDERLAY_IF:-}}"
underlay_b_if="${TRUSTIX_CROSS_HOST_CONCURRENT_B_UNDERLAY_IF:-${TRUSTIX_CROSS_HOST_B_UNDERLAY_IF:-}}"
iperf_parallel="${TRUSTIX_CROSS_HOST_CONCURRENT_IPERF_PARALLEL:-${TRUSTIX_CROSS_HOST_IPERF_PARALLEL:-8}}"
session_pool_size="${TRUSTIX_CROSS_HOST_CONCURRENT_SESSION_POOL_SIZE:-${TRUSTIX_CROSS_HOST_SESSION_POOL_SIZE:-$iperf_parallel}}"
endpoint_transports_raw="${TRUSTIX_CROSS_HOST_CONCURRENT_ENDPOINT_TRANSPORTS:-${TRUSTIX_CROSS_HOST_ENDPOINT_TRANSPORTS:-}}"

log() {
  printf '[trustix-cross-host-concurrent] %s\n' "$*" >&2
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
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

require_integer() {
  local name="$1" value="$2"
  case "$value" in
    ''|*[!0-9]*) die "${name} must be a non-negative integer, got ${value}" ;;
  esac
}

require_positive_integer() {
  local name="$1" value="$2"
  require_integer "$name" "$value"
  [[ "$value" -gt 0 ]] || die "${name} must be > 0"
}

require_decimal() {
  local name="$1" value="$2"
  case "$value" in
    ''|.*|*..*|*[!0-9.]*)
      die "${name} must be a non-negative decimal, got ${value}"
      ;;
  esac
}

write_optional_env() {
  local env_file="$1" name="$2" value="$3"
  [[ -n "$value" ]] || return 0
  printf '%s=%q\n' "$name" "$value" >>"$env_file"
}

case_label() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9_.-]/_/g'
}

case_transport_token() {
  local raw="$1"
  raw="${raw#crosshost-}"
  raw="${raw#userspace-}"
  raw="${raw#tc-}"
  raw="${raw%-secure}"
  raw="${raw%-plaintext}"
  raw="$(printf '%s' "$raw" | tr '[:upper:]' '[:lower:]' | tr '-' '_')"
  case "$raw" in
    httpconnect) raw="http_connect" ;;
    tixtcp) raw="tix_tcp" ;;
  esac
  printf '%s\n' "$raw"
}

case_encryption_token() {
  case "$1" in
    *-secure) printf 'secure\n' ;;
    *-plaintext) printf 'plaintext\n' ;;
    *) printf '\n' ;;
  esac
}

case_kind_token() {
  case "$1" in
    userspace-*-secure|userspace-*-plaintext|crosshost-userspace-*-secure|crosshost-userspace-*-plaintext) printf 'userspace\n' ;;
    tc-*-secure|tc-*-plaintext|crosshost-tc-*-secure|crosshost-tc-*-plaintext) printf 'tc_xdp\n' ;;
    *) die "cannot infer concurrent case kind from ${1}" ;;
  esac
}

case_profile_token() {
  local kind encryption
  kind="$(case_kind_token "$1")"
  encryption="$(case_encryption_token "$1")"
  if [[ "$kind" == "tc_xdp" && "$encryption" == "plaintext" ]]; then
    printf 'performance\n'
  else
    printf 'stable\n'
  fi
}

case_datapath_token() {
  case_kind_token "$1"
}

record_summary() {
  local status="$1" name="$2" dir="$3" pid="$4" rc="$5" verify_rc="$6"
  printf '{"status":"%s","case":"%s","workdir":"%s","pid":%s,"exit_code":%s,"verify_exit_code":%s}\n' \
    "$(json_escape "$status")" "$(json_escape "$name")" "$(json_escape "$dir")" "$pid" "$rc" "$verify_rc" >>"$summary_path"
}

write_case_env() {
  local index="$1" name="$2" dir="$3" env_file="$4"
  local port_offset api_a api_b peer_a peer_b data_a data_b iperf health lan_a_octet lan_b_octet carrier_octet iptunnel_port vxlan_vni vxlan_port label transport encryption profile datapath
  label="$(case_label "$name")"
  transport="$(case_transport_token "$name")"
  encryption="$(case_encryption_token "$name")"
  profile="$(case_profile_token "$name")"
  datapath="$(case_datapath_token "$name")"
  [[ -n "$transport" ]] || die "cannot infer transport from case ${name}"
  [[ -n "$encryption" ]] || die "cannot infer encryption from case ${name}; use userspace-TRANSPORT-secure/plaintext style"
  port_offset=$((index * port_stride))
  api_a=$((base_api_port + port_offset))
  api_b=$((base_api_port + port_offset + 1))
  peer_a=$((base_peer_port + port_offset))
  peer_b=$((base_peer_port + port_offset + 1))
  data_a=$((base_data_port + port_offset))
  data_b=$((base_data_port + port_offset + 1))
  iperf=$((base_iperf_port + port_offset))
  health=$((base_iperf_port + port_offset + 1))
  lan_a_octet=$((base_lan_octet + index * 2))
  lan_b_octet=$((lan_a_octet + 1))
  carrier_octet=$((base_carrier_octet + index))
  iptunnel_port=$((base_iptunnel_port + index))
  vxlan_vni=$((base_vxlan_vni + index))
  vxlan_port=$((base_vxlan_port + index))
  [[ "$lan_b_octet" -le 254 ]] || die "LAN octet ${lan_b_octet} is out of range; lower TRUSTIX_CROSS_HOST_CONCURRENT_LAN_OCTET_BASE or use fewer cases"
  [[ "$carrier_octet" -le 254 ]] || die "carrier octet ${carrier_octet} is out of range; lower TRUSTIX_CROSS_HOST_CONCURRENT_CARRIER_OCTET_BASE or use fewer cases"
  [[ "$iptunnel_port" -le 65535 ]] || die "IP tunnel port ${iptunnel_port} is out of range; lower TRUSTIX_CROSS_HOST_CONCURRENT_IPTUNNEL_PORT_BASE"
  [[ "$vxlan_vni" -le 16777215 ]] || die "VXLAN VNI ${vxlan_vni} is out of range; lower TRUSTIX_CROSS_HOST_CONCURRENT_VXLAN_VNI_BASE"
  [[ "$vxlan_port" -le 65535 ]] || die "VXLAN port ${vxlan_port} is out of range; lower TRUSTIX_CROSS_HOST_CONCURRENT_VXLAN_PORT_BASE"
  cat >"$env_file" <<EOF
TRUSTIX_CROSS_HOST_CASE=${name}
TRUSTIX_CROSS_HOST_TRANSPORT=${transport}
TRUSTIX_CROSS_HOST_ENCRYPTION=${encryption}
TRUSTIX_CROSS_HOST_PROFILE=${profile}
TRUSTIX_CROSS_HOST_TRANSPORT_DATAPATH=${datapath}
TRUSTIX_CROSS_HOST_CRYPTO_PLACEMENT=userspace
TRUSTIX_CROSS_HOST_WORKDIR=${dir}
TRUSTIX_CROSS_HOST_KEEP_LOCAL=${keep_local}
TRUSTIX_CROSS_HOST_KEEP_REMOTE=${keep_remote}
TRUSTIX_CROSS_HOST_UNLOAD_MODULES=${unload_modules}
TRUSTIX_CROSS_HOST_REMOTE_A=${remote_base}/${label}/a
TRUSTIX_CROSS_HOST_REMOTE_B=${remote_base}/${label}/b
TRUSTIX_CROSS_HOST_DOMAIN=concurrent-${index}.lab.local
TRUSTIX_CROSS_HOST_IX_A=ix-a-${index}
TRUSTIX_CROSS_HOST_IX_B=ix-b-${index}
TRUSTIX_CROSS_HOST_API_A_PORT=${api_a}
TRUSTIX_CROSS_HOST_API_B_PORT=${api_b}
TRUSTIX_CROSS_HOST_PEER_A_PORT=${peer_a}
TRUSTIX_CROSS_HOST_PEER_B_PORT=${peer_b}
TRUSTIX_CROSS_HOST_DATA_A_PORT=${data_a}
TRUSTIX_CROSS_HOST_DATA_B_PORT=${data_b}
TRUSTIX_CROSS_HOST_IPERF_PORT=${iperf}
TRUSTIX_CROSS_HOST_HEALTH_PORT=${health}
TRUSTIX_CROSS_HOST_IPERF_SECONDS=${seconds}
TRUSTIX_CROSS_HOST_IPERF_TIMEOUT=$((seconds + timeout_slop))
TRUSTIX_CROSS_HOST_IPERF_PARALLEL=${iperf_parallel}
TRUSTIX_CROSS_HOST_SESSION_POOL_SIZE=${session_pool_size}
TRUSTIX_CROSS_HOST_TRANSPORT_SNAPSHOT_DELAY=${transport_snapshot_delay}
TRUSTIX_CROSS_HOST_LAN_IF_A=tix-lan-c${index}a
TRUSTIX_CROSS_HOST_LAN_IF_B=tix-lan-c${index}b
TRUSTIX_CROSS_HOST_HOST_IF_A=tix-host-c${index}a
TRUSTIX_CROSS_HOST_HOST_IF_B=tix-host-c${index}b
TRUSTIX_CROSS_HOST_HOST_NS_A=tix-host-c${index}a
TRUSTIX_CROSS_HOST_HOST_NS_B=tix-host-c${index}b
TRUSTIX_CROSS_HOST_LAN_A_CIDR=10.74.${lan_a_octet}.0/24
TRUSTIX_CROSS_HOST_LAN_B_CIDR=10.74.${lan_b_octet}.0/24
TRUSTIX_CROSS_HOST_LAN_A_GATEWAY=10.74.${lan_a_octet}.1/24
TRUSTIX_CROSS_HOST_LAN_B_GATEWAY=10.74.${lan_b_octet}.1/24
TRUSTIX_CROSS_HOST_HOST_A_ADDR=10.74.${lan_a_octet}.2/24
TRUSTIX_CROSS_HOST_HOST_B_ADDR=10.74.${lan_b_octet}.2/24
TRUSTIX_CROSS_HOST_IPTUNNEL_A_CARRIER=10.75.${carrier_octet}.1/30
TRUSTIX_CROSS_HOST_IPTUNNEL_B_CARRIER=10.75.${carrier_octet}.2/30
TRUSTIX_CROSS_HOST_IPTUNNEL_PORT=${iptunnel_port}
TRUSTIX_CROSS_HOST_VXLAN_VNI=${vxlan_vni}
TRUSTIX_CROSS_HOST_VXLAN_PORT=${vxlan_port}
EOF
  write_optional_env "$env_file" TRUSTIX_CROSS_HOST_A "$node_a"
  write_optional_env "$env_file" TRUSTIX_CROSS_HOST_B "$node_b"
  write_optional_env "$env_file" TRUSTIX_CROSS_HOST_SSH_OPTS "$ssh_opts"
  write_optional_env "$env_file" TRUSTIX_CROSS_HOST_BIN_DIR_A "$bin_dir_a"
  write_optional_env "$env_file" TRUSTIX_CROSS_HOST_BIN_DIR_B "$bin_dir_b"
  write_optional_env "$env_file" TRUSTIX_CROSS_HOST_TRUSTIX_CA "$trustix_ca"
  write_optional_env "$env_file" TRUSTIX_CROSS_HOST_A_UNDERLAY_IP "$underlay_a_ip"
  write_optional_env "$env_file" TRUSTIX_CROSS_HOST_B_UNDERLAY_IP "$underlay_b_ip"
  write_optional_env "$env_file" TRUSTIX_CROSS_HOST_A_UNDERLAY_IF "$underlay_a_if"
  write_optional_env "$env_file" TRUSTIX_CROSS_HOST_B_UNDERLAY_IF "$underlay_b_if"
  if [[ "$transport" == "mixed" ]]; then
    [[ -n "$endpoint_transports_raw" ]] || die "${name} requires TRUSTIX_CROSS_HOST_CONCURRENT_ENDPOINT_TRANSPORTS"
    write_optional_env "$env_file" TRUSTIX_CROSS_HOST_ENDPOINT_TRANSPORTS "$endpoint_transports_raw"
  fi
}

run_one() {
  local name="$1" dir="$2" env_file="$3"
  unset TRUSTIX_CROSS_HOST_ENDPOINT_TRANSPORTS
  set -a
  # shellcheck disable=SC1090
  source "$env_file"
  set +a
  exec bash "$runner"
}

verify_one() {
  local name="$1" dir="$2" summary="$3"
  local encryption profile datapath transport item transport_summary index
  encryption="$(case_encryption_token "$name")"
  profile="$(case_profile_token "$name")"
  datapath="$(case_datapath_token "$name")"
  local args=(
    "--case" "${name}=${dir}"
    "--min-gbps" "$min_gbps"
    "--min-seconds" "$seconds"
    "--seconds-slop" "1"
    "--require-run-timing"
    "--require-run-timing-stat" "iperf_mode=forward"
    "--require-run-timing-stat" "iperf_directions=both"
    "--require-iperf-pair-directions"
    "--require-stable-boot-id"
    "--require-uname-artifacts" "--min-uname-nodes" "2"
    "--require-os-release-artifacts" "--min-os-release-nodes" "2"
    "--require-kernel-log-artifacts" "--min-kernel-log-nodes" "2"
    "--require-pstore-artifacts" "--min-pstore-nodes" "2"
    "--require-lsmod-artifacts" "--min-lsmod-nodes" "2"
    "--require-lan-state-artifacts" "--min-lan-state-nodes" "2" "--min-lan-tx-queue-len" "1"
    "--require-host-state-artifacts" "--min-host-state-nodes" "2"
    "--require-status-max" "data_path.counters.session_dial_errors=0"
    "--require-status-max" "data_path.counters.session_heartbeat_timeouts=0"
    "--require-status-max" "data_path.counters.send_errors=0"
    "--require-status-max" "data_path.counters.receive_errors=0"
    "--require-status-max" "data_path.counters.listener_accept_errors=0"
    "--require-status-max" "data_path.counters.stale_sessions_dropped=0"
    "--require-status-max" "data_path.drop_reasons.FLOW_NOT_INSTALLED=0"
    "--require-transport-policy-stat" "profile=${profile}"
    "--require-transport-policy-stat" "datapath=${datapath}"
    "--require-transport-policy-stat" "encryption=${encryption}"
    "--require-transport-policy-stat" "crypto_placement=userspace"
    "--require-transport-sessions-min" "1"
    "--summary" "$summary"
  )
  if truthy "$require_binary_identity"; then
    args+=("--require-binary-identity" "--require-strong-build-identity")
  fi
  if truthy "$forbid_trustix_modules"; then
    args+=("--forbid-lsmod-prefix" "trustix_")
  fi
  python3 "$verifier" "${args[@]}" || return
  transport="$(case_transport_token "$name")"
  [[ "$transport" == "mixed" ]] || return 0
  index=0
  while IFS= read -r item; do
    [[ -n "$item" ]] || continue
    transport="$(case_transport_token "userspace-${item}-secure")"
    transport_summary="${dir}/verify-transport-${index}-${transport}.jsonl"
    python3 "$verifier" \
      --case "${name}=${dir}" \
      --min-gbps "$min_gbps" \
      --min-seconds "$seconds" \
      --seconds-slop 1 \
      --require-transport-local-endpoint-stat "transport=${transport}" \
      --require-transport-local-endpoint-stat "usable=true" \
      --require-transport-peer-endpoint-stat "transport=${transport}" \
      --require-transport-peer-endpoint-stat "usable=true" \
      --require-transport-session-stat "transport=${transport}" \
      --require-transport-session-any-min "stats.bytes_sent=1" \
      --require-transport-session-any-min "stats.bytes_received=1" \
      --summary "$transport_summary" || return
    index=$((index + 1))
  done < <(printf '%s\n' "$endpoint_transports_raw" | tr ',\t ' '\n')
}

main() {
  [[ -f "$runner" ]] || die "runner not found: ${runner}"
  [[ -f "$verifier" ]] || die "verifier not found: ${verifier}"
  require_positive_integer TRUSTIX_CROSS_HOST_CONCURRENT_SECONDS "$seconds"
  require_positive_integer TRUSTIX_CROSS_HOST_CONCURRENT_TIMEOUT_SLOP "$timeout_slop"
  require_positive_integer TRUSTIX_CROSS_HOST_CONCURRENT_PORT_STRIDE "$port_stride"
  require_integer TRUSTIX_CROSS_HOST_CONCURRENT_LAN_OCTET_BASE "$base_lan_octet"
  require_integer TRUSTIX_CROSS_HOST_CONCURRENT_CARRIER_OCTET_BASE "$base_carrier_octet"
  require_positive_integer TRUSTIX_CROSS_HOST_CONCURRENT_IPTUNNEL_PORT_BASE "$base_iptunnel_port"
  require_positive_integer TRUSTIX_CROSS_HOST_CONCURRENT_VXLAN_VNI_BASE "$base_vxlan_vni"
  require_positive_integer TRUSTIX_CROSS_HOST_CONCURRENT_VXLAN_PORT_BASE "$base_vxlan_port"
  require_positive_integer TRUSTIX_CROSS_HOST_CONCURRENT_IPERF_PARALLEL "$iperf_parallel"
  require_positive_integer TRUSTIX_CROSS_HOST_CONCURRENT_SESSION_POOL_SIZE "$session_pool_size"
  require_decimal TRUSTIX_CROSS_HOST_CONCURRENT_MIN_GBPS "$min_gbps"
  case "$verify" in 0|1|true|false|yes|no|on|off|enabled|disabled) ;; *) die "TRUSTIX_CROSS_HOST_CONCURRENT_VERIFY must be truthy or falsey" ;; esac
  case "$dry_run" in 0|1|true|false|yes|no|on|off|enabled|disabled) ;; *) die "TRUSTIX_CROSS_HOST_CONCURRENT_DRY_RUN must be truthy or falsey" ;; esac
  case "$keep_remote" in 0|1|true|false|yes|no|on|off|enabled|disabled) ;; *) die "TRUSTIX_CROSS_HOST_CONCURRENT_KEEP_REMOTE must be truthy or falsey" ;; esac
  case "$keep_local" in 0|1|true|false|yes|no|on|off|enabled|disabled) ;; *) die "TRUSTIX_CROSS_HOST_CONCURRENT_KEEP_LOCAL must be truthy or falsey" ;; esac
  case "$unload_modules" in 0|1|true|false|yes|no|on|off|enabled|disabled) ;; *) die "TRUSTIX_CROSS_HOST_CONCURRENT_UNLOAD_MODULES must be truthy or falsey" ;; esac
  : >"$summary_path"

  local -a cases=()
  local item
  while IFS= read -r item; do
    [[ -n "$item" ]] || continue
    cases+=("$item")
  done < <(printf '%s\n' "$cases_raw" | tr ',\t ' '\n')
  [[ "${#cases[@]}" -gt 0 ]] || die "no concurrent cases selected"

  log "workdir=${workdir}"
  log "summary=${summary_path}"
  log "cases=${cases[*]}"

  local -a pids=()
  local -a names=()
  local -a dirs=()
  local -a envs=()
  local index=0 name label dir env_file
  for name in "${cases[@]}"; do
    label="$(case_label "$name")"
    dir="${workdir}/${label}"
    case "$dir" in "$workdir"/*) ;; *) die "refusing case workdir outside concurrent workdir: ${dir}" ;; esac
    rm -rf "$dir"
    mkdir -p "$dir"
    env_file="${dir}/case.env"
    write_case_env "$index" "$name" "$dir" "$env_file"
    names+=("$name")
    dirs+=("$dir")
    envs+=("$env_file")
    if truthy "$dry_run"; then
      record_summary "dry_run" "$name" "$dir" 0 0 0
      index=$((index + 1))
      continue
    fi
    log "start ${name} dir=${dir}"
    run_one "$name" "$dir" "$env_file" >"${dir}.out" 2>"${dir}.err" &
    pids+=("$!")
    index=$((index + 1))
  done

  if truthy "$dry_run"; then
    log "dry-run complete"
    return 0
  fi

  local failures=0 rc verify_rc status verify_summary pid
  for index in "${!names[@]}"; do
    name="${names[$index]}"
    dir="${dirs[$index]}"
    pid="${pids[$index]}"
    set +e
    wait "$pid"
    rc=$?
    set -e
    verify_rc=0
    status="pass"
    if [[ "$rc" -ne 0 ]]; then
      status="fail"
      failures=$((failures + 1))
    elif truthy "$verify"; then
      verify_summary="${dir}/verify-summary.jsonl"
      set +e
      verify_one "$name" "$dir" "$verify_summary" >"${dir}.verify.out" 2>"${dir}.verify.err"
      verify_rc=$?
      set -e
      if [[ "$verify_rc" -ne 0 ]]; then
        status="fail"
        failures=$((failures + 1))
      fi
    fi
    record_summary "$status" "$name" "$dir" "$pid" "$rc" "$verify_rc"
    log "${status} ${name} rc=${rc} verify_rc=${verify_rc}"
  done

  if [[ "$failures" -ne 0 ]]; then
    log "failed cases=${failures}"
    return 1
  fi
  log "pass all cases=${#names[@]}"
}

main "$@"
