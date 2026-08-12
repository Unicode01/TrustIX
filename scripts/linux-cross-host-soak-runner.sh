#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

case_name="${TRUSTIX_CROSS_HOST_CASE:-dd-fullkmod}"
case_transport_override="${TRUSTIX_CROSS_HOST_TRANSPORT:-}"
case_encryption_override="${TRUSTIX_CROSS_HOST_ENCRYPTION:-}"
case_profile_override="${TRUSTIX_CROSS_HOST_PROFILE:-}"
case_datapath_override="${TRUSTIX_CROSS_HOST_TRANSPORT_DATAPATH:-}"
case_crypto_placement_override="${TRUSTIX_CROSS_HOST_CRYPTO_PLACEMENT:-}"
case_crypto_suites_override="${TRUSTIX_CROSS_HOST_CRYPTO_SUITES:-}"
case_tls_data_plane_override="${TRUSTIX_CROSS_HOST_TLS_DATA_PLANE:-}"
endpoint_transports_raw="${TRUSTIX_CROSS_HOST_ENDPOINT_TRANSPORTS:-}"
workdir="${TRUSTIX_CROSS_HOST_WORKDIR:-$(mktemp -d /tmp/trustix-cross-host.XXXXXX)}"
workdir="$(mkdir -p "$workdir" && cd "$workdir" && pwd -P)"
keep_remote="${TRUSTIX_CROSS_HOST_KEEP_REMOTE:-0}"
keep_local="${TRUSTIX_CROSS_HOST_KEEP_LOCAL:-1}"
unload_modules="${TRUSTIX_CROSS_HOST_UNLOAD_MODULES:-1}"
preserve_on_failure="${TRUSTIX_CROSS_HOST_PRESERVE_ON_FAILURE:-0}"
dry_run_config="${TRUSTIX_CROSS_HOST_DRY_RUN_CONFIG:-0}"
pair_lock_hold_seconds="${TRUSTIX_CROSS_HOST_PAIR_LOCK_HOLD_SECONDS:-0}"
cleanup_timeout="${TRUSTIX_CROSS_HOST_CLEANUP_TIMEOUT:-20}"
daemon_supervisor="${TRUSTIX_CROSS_HOST_DAEMON_SUPERVISOR:-process}"
daemon_restart_sec="${TRUSTIX_CROSS_HOST_DAEMON_RESTART_SEC:-1}"

node_a="${TRUSTIX_CROSS_HOST_A:-local}"
node_b="${TRUSTIX_CROSS_HOST_B:-}"
ssh_opts_raw="${TRUSTIX_CROSS_HOST_SSH_OPTS:-}"
scp_opts_raw="${TRUSTIX_CROSS_HOST_SCP_OPTS:-$ssh_opts_raw}"

default_bin_dir="${TRUSTIX_CROSS_HOST_BIN_DIR:-${repo_root}/build/release/trustix-linux-amd64/bin}"
bin_dir_a="${TRUSTIX_CROSS_HOST_BIN_DIR_A:-$default_bin_dir}"
bin_dir_b="${TRUSTIX_CROSS_HOST_BIN_DIR_B:-$default_bin_dir}"
trustixd_a="${TRUSTIX_CROSS_HOST_TRUSTIXD_A:-${bin_dir_a}/trustixd}"
trustixd_b="${TRUSTIX_CROSS_HOST_TRUSTIXD_B:-${bin_dir_b}/trustixd}"
trustixctl_a="${TRUSTIX_CROSS_HOST_TRUSTIXCTL_A:-${bin_dir_a}/trustixctl}"
trustixctl_b="${TRUSTIX_CROSS_HOST_TRUSTIXCTL_B:-${bin_dir_b}/trustixctl}"
trustix_ca="${TRUSTIX_CROSS_HOST_TRUSTIX_CA:-${bin_dir_a}/trustix-ca}"

remote_base="${TRUSTIX_CROSS_HOST_REMOTE_BASE:-/tmp}"
remote_a="${TRUSTIX_CROSS_HOST_REMOTE_A:-${remote_base}/trustix-cross-host-a}"
remote_b="${TRUSTIX_CROSS_HOST_REMOTE_B:-${remote_base}/trustix-cross-host-b}"
pair_lock_root="${TRUSTIX_CROSS_HOST_PAIR_LOCK_ROOT:-${TMPDIR:-/tmp}}"
pair_lock_dir=""
pair_lock_acquired=0

full_kmod_datapath_path="${TRUSTIX_CROSS_HOST_FULL_KMOD_DATAPATH_PATH:-embedded}"
full_kmod_datapath_path_a="${TRUSTIX_CROSS_HOST_FULL_KMOD_DATAPATH_PATH_A:-$full_kmod_datapath_path}"
full_kmod_datapath_path_b="${TRUSTIX_CROSS_HOST_FULL_KMOD_DATAPATH_PATH_B:-$full_kmod_datapath_path}"
route_gso_helpers_path="${TRUSTIX_CROSS_HOST_ROUTE_GSO_HELPERS_PATH:-embedded}"
route_gso_helpers_path_a="${TRUSTIX_CROSS_HOST_ROUTE_GSO_HELPERS_PATH_A:-$route_gso_helpers_path}"
route_gso_helpers_path_b="${TRUSTIX_CROSS_HOST_ROUTE_GSO_HELPERS_PATH_B:-$route_gso_helpers_path}"
secure_kudp_crypto_path="${TRUSTIX_CROSS_HOST_SECURE_KUDP_CRYPTO_PATH:-embedded}"
secure_kudp_crypto_path_a="${TRUSTIX_CROSS_HOST_SECURE_KUDP_CRYPTO_PATH_A:-$secure_kudp_crypto_path}"
secure_kudp_crypto_path_b="${TRUSTIX_CROSS_HOST_SECURE_KUDP_CRYPTO_PATH_B:-$secure_kudp_crypto_path}"
secure_kudp_helpers_path="${TRUSTIX_CROSS_HOST_SECURE_KUDP_HELPERS_PATH:-}"
secure_kudp_helpers_path_a="${TRUSTIX_CROSS_HOST_SECURE_KUDP_HELPERS_PATH_A:-$secure_kudp_helpers_path}"
secure_kudp_helpers_path_b="${TRUSTIX_CROSS_HOST_SECURE_KUDP_HELPERS_PATH_B:-$secure_kudp_helpers_path}"
secure_tix_tcp_crypto_path="${TRUSTIX_CROSS_HOST_SECURE_TIX_TCP_CRYPTO_PATH:-embedded}"
secure_tix_tcp_crypto_path_a="${TRUSTIX_CROSS_HOST_SECURE_TIX_TCP_CRYPTO_PATH_A:-$secure_tix_tcp_crypto_path}"
secure_tix_tcp_crypto_path_b="${TRUSTIX_CROSS_HOST_SECURE_TIX_TCP_CRYPTO_PATH_B:-$secure_tix_tcp_crypto_path}"
secure_tix_tcp_datapath_path="${TRUSTIX_CROSS_HOST_SECURE_TIX_TCP_DATAPATH_PATH:-embedded}"
secure_tix_tcp_datapath_path_a="${TRUSTIX_CROSS_HOST_SECURE_TIX_TCP_DATAPATH_PATH_A:-$secure_tix_tcp_datapath_path}"
secure_tix_tcp_datapath_path_b="${TRUSTIX_CROSS_HOST_SECURE_TIX_TCP_DATAPATH_PATH_B:-$secure_tix_tcp_datapath_path}"

domain_id="${TRUSTIX_CROSS_HOST_DOMAIN:-lab.local}"
ix_a="${TRUSTIX_CROSS_HOST_IX_A:-ix-a}"
ix_b="${TRUSTIX_CROSS_HOST_IX_B:-ix-b}"

api_a_port="${TRUSTIX_CROSS_HOST_API_A_PORT:-18787}"
api_b_port="${TRUSTIX_CROSS_HOST_API_B_PORT:-18788}"
peer_a_port="${TRUSTIX_CROSS_HOST_PEER_A_PORT:-19443}"
peer_b_port="${TRUSTIX_CROSS_HOST_PEER_B_PORT:-19444}"
data_a_port="${TRUSTIX_CROSS_HOST_DATA_A_PORT:-}"
data_b_port="${TRUSTIX_CROSS_HOST_DATA_B_PORT:-}"
iperf_port="${TRUSTIX_CROSS_HOST_IPERF_PORT:-25201}"
iperf_client_port="${TRUSTIX_CROSS_HOST_IPERF_CLIENT_PORT:-0}"
mixed_iperf_port="${TRUSTIX_CROSS_HOST_MIXED_IPERF_PORT:-}"
health_port="${TRUSTIX_CROSS_HOST_HEALTH_PORT:-}"
iperf_seconds="${TRUSTIX_CROSS_HOST_IPERF_SECONDS:-3600}"
iperf_parallel_explicit="${TRUSTIX_CROSS_HOST_IPERF_PARALLEL+x}"
iperf_parallel="${TRUSTIX_CROSS_HOST_IPERF_PARALLEL:-8}"
iperf_tcp_buffer_bytes="${TRUSTIX_CROSS_HOST_IPERF_TCP_BUFFER_BYTES:-0}"
transport_mtu="${TRUSTIX_CROSS_HOST_MTU:-1500}"
iptunnel_iperf_parallel="${TRUSTIX_CROSS_HOST_IPTUNNEL_IPERF_PARALLEL:-4}"
iperf_timeout="${TRUSTIX_CROSS_HOST_IPERF_TIMEOUT:-}"
iperf_mode="${TRUSTIX_CROSS_HOST_IPERF_MODE:-forward}"
iperf_directions="${TRUSTIX_CROSS_HOST_IPERF_DIRECTIONS:-both}"
max_consecutive_zero_intervals="${TRUSTIX_CROSS_HOST_MAX_CONSECUTIVE_ZERO_INTERVALS:-0}"
mixed_min_gbps="${TRUSTIX_CROSS_HOST_MIXED_MIN_GBPS:-0}"
mixed_udp_min_gbps="${TRUSTIX_CROSS_HOST_MIXED_UDP_MIN_GBPS:-$mixed_min_gbps}"
mixed_tix_tcp_min_gbps="${TRUSTIX_CROSS_HOST_MIXED_TIX_TCP_MIN_GBPS:-$mixed_min_gbps}"
transport_snapshot_delay="${TRUSTIX_CROSS_HOST_TRANSPORT_SNAPSHOT_DELAY:-5}"
session_pool_size_explicit="${TRUSTIX_CROSS_HOST_SESSION_POOL_SIZE+x}"
session_pool_size="${TRUSTIX_CROSS_HOST_SESSION_POOL_SIZE:-$iperf_parallel}"
session_pool_strategy="${TRUSTIX_CROSS_HOST_SESSION_POOL_STRATEGY:-flow}"
session_pool_warmup="${TRUSTIX_CROSS_HOST_SESSION_POOL_WARMUP:-true}"
session_pool_heartbeat_mode="${TRUSTIX_CROSS_HOST_SESSION_POOL_HEARTBEAT_MODE:-enabled}"
session_pool_heartbeat_interval="${TRUSTIX_CROSS_HOST_SESSION_POOL_HEARTBEAT_INTERVAL:-10s}"
session_pool_heartbeat_timeout="${TRUSTIX_CROSS_HOST_SESSION_POOL_HEARTBEAT_TIMEOUT:-10s}"
capture_forwarder_workers="${TRUSTIX_CROSS_HOST_CAPTURE_FORWARDER_WORKERS:-auto}"
capture_forwarder_buffer="${TRUSTIX_CROSS_HOST_CAPTURE_FORWARDER_BUFFER:-65536}"
capture_forwarder_batch="${TRUSTIX_CROSS_HOST_CAPTURE_FORWARDER_BATCH:-1024}"
capture_forwarder_batch_delay="${TRUSTIX_CROSS_HOST_CAPTURE_FORWARDER_BATCH_DELAY:-0}"
cpu_profile_dir="${TRUSTIX_CROSS_HOST_CPU_PROFILE_DIR:-}"
secure_tix_tcp_inner_checksum_partial="${TRUSTIX_CROSS_HOST_SECURE_TIX_TCP_INNER_CHECKSUM_PARTIAL:-}"
tix_tcp_inner_gso="${TRUSTIX_CROSS_HOST_TIX_TCP_INNER_GSO:-}"
netem_targets="${TRUSTIX_CROSS_HOST_NETEM_TARGETS:-both}"
netem_placement="${TRUSTIX_CROSS_HOST_NETEM_PLACEMENT:-egress}"
netem_loss_pct="${TRUSTIX_CROSS_HOST_NETEM_LOSS_PCT:-0}"
netem_delay_ms="${TRUSTIX_CROSS_HOST_NETEM_DELAY_MS:-0}"
netem_jitter_ms="${TRUSTIX_CROSS_HOST_NETEM_JITTER_MS:-0}"
netem_reorder_pct="${TRUSTIX_CROSS_HOST_NETEM_REORDER_PCT:-0}"
netem_duplicate_pct="${TRUSTIX_CROSS_HOST_NETEM_DUPLICATE_PCT:-0}"
netem_corrupt_pct="${TRUSTIX_CROSS_HOST_NETEM_CORRUPT_PCT:-0}"
netem_rate_mbit="${TRUSTIX_CROSS_HOST_NETEM_RATE_MBIT:-0}"
netem_limit_packets_explicit="${TRUSTIX_CROSS_HOST_NETEM_LIMIT_PACKETS+x}"
netem_limit_packets="${TRUSTIX_CROSS_HOST_NETEM_LIMIT_PACKETS:-262144}"
netem_disable_gro="${TRUSTIX_CROSS_HOST_NETEM_DISABLE_GRO:-1}"
netem_active_seconds="${TRUSTIX_CROSS_HOST_NETEM_ACTIVE_SECONDS:-0}"
inner_gso_latched_fallback_observe_seconds="${TRUSTIX_CROSS_HOST_INNER_GSO_LATCHED_FALLBACK_OBSERVE_SECONDS:-0}"
require_inner_gso_latched_fallback="${TRUSTIX_CROSS_HOST_REQUIRE_INNER_GSO_LATCHED_FALLBACK:-0}"
netem_handle="7e10:"
netem_transition_pid=""
iptunnel_port="${TRUSTIX_CROSS_HOST_IPTUNNEL_PORT:-47829}"
iptunnel_mtu="${TRUSTIX_CROSS_HOST_IPTUNNEL_MTU:-1400}"
iptunnel_a_carrier="${TRUSTIX_CROSS_HOST_IPTUNNEL_A_CARRIER:-10.255.10.1/30}"
iptunnel_b_carrier="${TRUSTIX_CROSS_HOST_IPTUNNEL_B_CARRIER:-10.255.10.2/30}"
vxlan_vni="${TRUSTIX_CROSS_HOST_VXLAN_VNI:-7}"
vxlan_port="${TRUSTIX_CROSS_HOST_VXLAN_PORT:-4789}"

lan_if_a="${TRUSTIX_CROSS_HOST_LAN_IF_A:-tix-lan}"
lan_if_b="${TRUSTIX_CROSS_HOST_LAN_IF_B:-tix-lan}"
host_if_a="${TRUSTIX_CROSS_HOST_HOST_IF_A:-tix-host}"
host_if_b="${TRUSTIX_CROSS_HOST_HOST_IF_B:-tix-host}"
host_ns_a="${TRUSTIX_CROSS_HOST_HOST_NS_A:-tix-host-a}"
host_ns_b="${TRUSTIX_CROSS_HOST_HOST_NS_B:-tix-host-b}"
lan_a_cidr="${TRUSTIX_CROSS_HOST_LAN_A_CIDR:-10.64.0.0/24}"
lan_b_cidr="${TRUSTIX_CROSS_HOST_LAN_B_CIDR:-10.64.1.0/24}"
lan_a_gateway="${TRUSTIX_CROSS_HOST_LAN_A_GATEWAY:-10.64.0.1/24}"
lan_b_gateway="${TRUSTIX_CROSS_HOST_LAN_B_GATEWAY:-10.64.1.1/24}"
host_a_addr="${TRUSTIX_CROSS_HOST_HOST_A_ADDR:-10.64.0.2/24}"
host_b_addr="${TRUSTIX_CROSS_HOST_HOST_B_ADDR:-10.64.1.2/24}"
host_a_ip="${host_a_addr%/*}"
host_b_ip="${host_b_addr%/*}"
mixed_udp_lan_a_cidr="${TRUSTIX_CROSS_HOST_MIXED_UDP_LAN_A_CIDR:-}"
mixed_udp_lan_b_cidr="${TRUSTIX_CROSS_HOST_MIXED_UDP_LAN_B_CIDR:-}"
mixed_tix_tcp_lan_a_cidr="${TRUSTIX_CROSS_HOST_MIXED_TIX_TCP_LAN_A_CIDR:-}"
mixed_tix_tcp_lan_b_cidr="${TRUSTIX_CROSS_HOST_MIXED_TIX_TCP_LAN_B_CIDR:-}"
mixed_host_a_addr="${TRUSTIX_CROSS_HOST_MIXED_HOST_A_ADDR:-}"
mixed_host_b_addr="${TRUSTIX_CROSS_HOST_MIXED_HOST_B_ADDR:-}"
mixed_host_a_ip=""
mixed_host_b_ip=""

underlay_a_ip="${TRUSTIX_CROSS_HOST_A_UNDERLAY_IP:-}"
underlay_b_ip="${TRUSTIX_CROSS_HOST_B_UNDERLAY_IP:-}"
underlay_a_if="${TRUSTIX_CROSS_HOST_A_UNDERLAY_IF:-}"
underlay_b_if="${TRUSTIX_CROSS_HOST_B_UNDERLAY_IF:-}"

dataplane_mode="${TRUSTIX_CROSS_HOST_DATAPLANE:-linux}"
endpoint_transport_override="${TRUSTIX_CROSS_HOST_ENDPOINT_TRANSPORT:-}"
daemon_ready_attempts="${TRUSTIX_CROSS_HOST_READY_ATTEMPTS:-80}"
daemon_ready_sleep="${TRUSTIX_CROSS_HOST_READY_SLEEP:-1}"

ssh_opts=()
scp_opts=()
endpoint_transports=()
if [[ -n "$ssh_opts_raw" ]]; then
  # shellcheck disable=SC2206
  ssh_opts=($ssh_opts_raw)
fi
if [[ -n "$scp_opts_raw" ]]; then
  # shellcheck disable=SC2206
  scp_opts=($scp_opts_raw)
fi

log() {
  printf '[trustix-cross-host-runner] %s\n' "$*" >&2
}

nonnegative_decimal() {
  [[ "${1:-}" =~ ^([0-9]+([.][0-9]*)?|[.][0-9]+)$ ]]
}

decimal_is_zero() {
  [[ "${1:-}" =~ ^0+([.]0*)?$ ]]
}

netem_enabled() {
  ! decimal_is_zero "$netem_loss_pct" ||
    [[ "$netem_delay_ms" != "0" ]] ||
    [[ "$netem_jitter_ms" != "0" ]] ||
    ! decimal_is_zero "$netem_reorder_pct" ||
    ! decimal_is_zero "$netem_duplicate_pct" ||
    ! decimal_is_zero "$netem_corrupt_pct" ||
    [[ "$netem_rate_mbit" != "0" ]]
}

netem_targets_node() {
  case "${netem_targets}:$1" in
    both:a|both:b|a:a|b:b) return 0 ;;
    *) return 1 ;;
  esac
}

validate_netem_percentage() {
  local name="$1"
  local value="$2"
  nonnegative_decimal "$value" || die "${name} must be a decimal percentage in 0..100"
  awk -v value="$value" 'BEGIN { exit !(value >= 0 && value <= 100) }' ||
    die "${name} must be a decimal percentage in 0..100"
}

scheduled_iperf_traffic_seconds() {
  case "$iperf_directions" in
    both) printf '%s\n' "$((iperf_seconds * 2))" ;;
    *) printf '%s\n' "$iperf_seconds" ;;
  esac
}

validate_netem_config() {
  local scheduled_traffic_seconds
  case "$iperf_seconds" in *[!0-9]*|"") die "TRUSTIX_CROSS_HOST_IPERF_SECONDS must be an integer" ;; esac
  if [[ -z "$iperf_timeout" ]]; then
    iperf_timeout=$((iperf_seconds + 60))
  fi
  case "$iperf_timeout" in *[!0-9]*|"") die "TRUSTIX_CROSS_HOST_IPERF_TIMEOUT must be an integer" ;; esac
  [[ "$iperf_timeout" -gt 0 ]] || die "TRUSTIX_CROSS_HOST_IPERF_TIMEOUT must be positive"
  case "$netem_targets" in
    both|a|b) ;;
    *) die "TRUSTIX_CROSS_HOST_NETEM_TARGETS must be both, a, or b" ;;
  esac
  case "$netem_placement" in
    egress|ingress) ;;
    *) die "TRUSTIX_CROSS_HOST_NETEM_PLACEMENT must be egress or ingress" ;;
  esac
  validate_netem_percentage TRUSTIX_CROSS_HOST_NETEM_LOSS_PCT "$netem_loss_pct"
  validate_netem_percentage TRUSTIX_CROSS_HOST_NETEM_REORDER_PCT "$netem_reorder_pct"
  validate_netem_percentage TRUSTIX_CROSS_HOST_NETEM_DUPLICATE_PCT "$netem_duplicate_pct"
  validate_netem_percentage TRUSTIX_CROSS_HOST_NETEM_CORRUPT_PCT "$netem_corrupt_pct"
  [[ "$netem_delay_ms" =~ ^(0|[1-9][0-9]*)$ ]] ||
    die "TRUSTIX_CROSS_HOST_NETEM_DELAY_MS must be a non-negative integer"
  [[ "$netem_jitter_ms" =~ ^(0|[1-9][0-9]*)$ ]] ||
    die "TRUSTIX_CROSS_HOST_NETEM_JITTER_MS must be a non-negative integer"
  [[ "$netem_rate_mbit" =~ ^(0|[1-9][0-9]*)$ ]] ||
    die "TRUSTIX_CROSS_HOST_NETEM_RATE_MBIT must be a non-negative integer"
  [[ "$netem_rate_mbit" -le 1000000 ]] ||
    die "TRUSTIX_CROSS_HOST_NETEM_RATE_MBIT must be in 0..1000000"
  if [[ -z "$netem_limit_packets_explicit" && "$netem_rate_mbit" != "0" ]]; then
    # Bound an unconfigured rate queue to roughly 100 ms of full-size packets.
    netem_limit_packets=$(( (netem_rate_mbit * 100000 + 11999) / 12000 ))
    [[ "$netem_limit_packets" -ge 1024 ]] || netem_limit_packets=1024
    [[ "$netem_limit_packets" -le 262144 ]] || netem_limit_packets=262144
  fi
  [[ "$netem_limit_packets" =~ ^[1-9][0-9]*$ ]] ||
    die "TRUSTIX_CROSS_HOST_NETEM_LIMIT_PACKETS must be a positive integer"
  [[ "$netem_limit_packets" -ge 1 && "$netem_limit_packets" -le 1048576 ]] ||
    die "TRUSTIX_CROSS_HOST_NETEM_LIMIT_PACKETS must be in 1..1048576"
  case "$netem_disable_gro" in
    0|1) ;;
    *) die "TRUSTIX_CROSS_HOST_NETEM_DISABLE_GRO must be 0 or 1" ;;
  esac
  case "$netem_active_seconds" in *[!0-9]*|"") die "TRUSTIX_CROSS_HOST_NETEM_ACTIVE_SECONDS must be a non-negative integer" ;; esac
  case "$inner_gso_latched_fallback_observe_seconds" in *[!0-9]*|"") die "TRUSTIX_CROSS_HOST_INNER_GSO_LATCHED_FALLBACK_OBSERVE_SECONDS must be a non-negative integer" ;; esac
  case "$require_inner_gso_latched_fallback" in
    0|1) ;;
    *) die "TRUSTIX_CROSS_HOST_REQUIRE_INNER_GSO_LATCHED_FALLBACK must be 0 or 1" ;;
  esac
  if [[ "$netem_jitter_ms" != "0" && "$netem_delay_ms" == "0" ]]; then
    die "TRUSTIX_CROSS_HOST_NETEM_JITTER_MS requires TRUSTIX_CROSS_HOST_NETEM_DELAY_MS > 0"
  fi
  if ! decimal_is_zero "$netem_reorder_pct" && [[ "$netem_delay_ms" == "0" ]]; then
    die "TRUSTIX_CROSS_HOST_NETEM_REORDER_PCT requires TRUSTIX_CROSS_HOST_NETEM_DELAY_MS > 0"
  fi
  if [[ "$netem_active_seconds" -gt 0 ]] && ! netem_enabled; then
    die "TRUSTIX_CROSS_HOST_NETEM_ACTIVE_SECONDS requires an enabled netem impairment"
  fi
  scheduled_traffic_seconds="$(scheduled_iperf_traffic_seconds)"
  if [[ "$netem_active_seconds" -ge "$scheduled_traffic_seconds" && "$netem_active_seconds" -gt 0 ]]; then
    die "TRUSTIX_CROSS_HOST_NETEM_ACTIVE_SECONDS must be less than scheduled iperf traffic seconds (${scheduled_traffic_seconds})"
  fi
  if [[ "$require_inner_gso_latched_fallback" == "1" ]]; then
    [[ "$netem_active_seconds" -gt 0 ]] ||
      die "TRUSTIX_CROSS_HOST_REQUIRE_INNER_GSO_LATCHED_FALLBACK requires TRUSTIX_CROSS_HOST_NETEM_ACTIVE_SECONDS > 0"
    [[ "$inner_gso_latched_fallback_observe_seconds" -gt 0 ]] ||
      die "TRUSTIX_CROSS_HOST_REQUIRE_INNER_GSO_LATCHED_FALLBACK requires TRUSTIX_CROSS_HOST_INNER_GSO_LATCHED_FALLBACK_OBSERVE_SECONDS > 0"
    if [[ -n "$tix_tcp_inner_gso" ]] && ! truthy "$tix_tcp_inner_gso"; then
      die "TRUSTIX_CROSS_HOST_REQUIRE_INNER_GSO_LATCHED_FALLBACK cannot run when TRUSTIX_CROSS_HOST_TIX_TCP_INNER_GSO is explicitly disabled"
    fi
    [[ $((netem_active_seconds + inner_gso_latched_fallback_observe_seconds)) -lt "$scheduled_traffic_seconds" ]] ||
      die "inner-GSO latched-fallback observation must finish before scheduled iperf traffic seconds (${scheduled_traffic_seconds})"
  elif [[ "$inner_gso_latched_fallback_observe_seconds" -gt 0 ]]; then
    die "TRUSTIX_CROSS_HOST_INNER_GSO_LATCHED_FALLBACK_OBSERVE_SECONDS requires TRUSTIX_CROSS_HOST_REQUIRE_INNER_GSO_LATCHED_FALLBACK=1"
  fi
}

validate_transport_tuning_config() {
  case "$transport_mtu" in *[!0-9]*|"") die "TRUSTIX_CROSS_HOST_MTU must be an integer" ;; esac
  [[ "$transport_mtu" -ge 576 && "$transport_mtu" -le 65535 ]] ||
    die "TRUSTIX_CROSS_HOST_MTU must be in 576..65535"
  [[ "$iperf_tcp_buffer_bytes" =~ ^(0|[1-9][0-9]*)$ ]] ||
    die "TRUSTIX_CROSS_HOST_IPERF_TCP_BUFFER_BYTES must be a non-negative integer"
  [[ "$iperf_tcp_buffer_bytes" -le 2147483647 ]] ||
    die "TRUSTIX_CROSS_HOST_IPERF_TCP_BUFFER_BYTES must be in 0..2147483647"
  case "$tix_tcp_inner_gso" in
    ""|true|false|1|0|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_CROSS_HOST_TIX_TCP_INNER_GSO must be boolean" ;;
  esac
}

write_iperf_tcp_buffer_contract() {
  local enabled=0
  [[ "$iperf_tcp_buffer_bytes" -gt 0 ]] && enabled=1
  cat >"$workdir/iperf-tcp-buffer-config.txt" <<EOF
format=trustix-cross-host-iperf-tcp-buffer-v1
requested_bytes=${iperf_tcp_buffer_bytes}
enabled=${enabled}
scope=temporary-host-network-namespace
host_namespace_a=${host_ns_a}
host_namespace_b=${host_ns_b}
socket_window=autotune
settings=net.ipv4.tcp_rmem[2],net.ipv4.tcp_wmem[2]
read_only_settings=net.core.rmem_max,net.core.wmem_max
EOF
}

netem_qdisc_args() {
  local args="limit ${netem_limit_packets}"
  if [[ "$netem_delay_ms" != "0" ]]; then
    args+=" delay ${netem_delay_ms}ms"
    if [[ "$netem_jitter_ms" != "0" ]]; then
      args+=" ${netem_jitter_ms}ms"
    fi
  fi
  decimal_is_zero "$netem_loss_pct" || args+=" loss ${netem_loss_pct}%"
  decimal_is_zero "$netem_duplicate_pct" || args+=" duplicate ${netem_duplicate_pct}%"
  decimal_is_zero "$netem_corrupt_pct" || args+=" corrupt ${netem_corrupt_pct}%"
  decimal_is_zero "$netem_reorder_pct" || args+=" reorder ${netem_reorder_pct}%"
  [[ "$netem_rate_mbit" == "0" ]] || args+=" rate ${netem_rate_mbit}mbit"
  printf '%s\n' "$args"
}

write_netem_contract() {
  local enabled=0
  netem_enabled && enabled=1
  cat >"$workdir/netem-config.txt" <<EOF
format=trustix-cross-host-netem-v1
enabled=${enabled}
targets=${netem_targets}
placement=${netem_placement}
loss_pct=${netem_loss_pct}
delay_ms=${netem_delay_ms}
jitter_ms=${netem_jitter_ms}
reorder_pct=${netem_reorder_pct}
duplicate_pct=${netem_duplicate_pct}
corrupt_pct=${netem_corrupt_pct}
rate_mbit=${netem_rate_mbit}
limit_packets=${netem_limit_packets}
limit_packets_explicit=$([[ -n "$netem_limit_packets_explicit" ]] && printf 1 || printf 0)
disable_gro=${netem_disable_gro}
active_seconds=${netem_active_seconds}
require_inner_gso_latched_fallback=${require_inner_gso_latched_fallback}
inner_gso_latched_fallback_observe_seconds=${inner_gso_latched_fallback_observe_seconds}
handle=${netem_handle}
underlay_a_if=${underlay_a_if}
underlay_b_if=${underlay_b_if}
qdisc_args=$(netem_qdisc_args)
EOF
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

acquire_pair_lock() {
  local first second pair_key owner_pid owner_start current_start attempt
  first="$node_a"
  second="$node_b"
  if [[ "$second" < "$first" ]]; then
    first="$node_b"
    second="$node_a"
  fi
  pair_key="$(printf '%s\n%s\n' "$first" "$second" | cksum | awk '{print $1}')"
  mkdir -p "$pair_lock_root"
  pair_lock_root="$(cd "$pair_lock_root" && pwd -P)"
  pair_lock_dir="${pair_lock_root}/trustix-cross-host-pair-${pair_key}.lock"

  for attempt in 1 2 3; do
    if mkdir "$pair_lock_dir" 2>/dev/null; then
      printf '%s\n' "$$" >"${pair_lock_dir}/owner.pid"
      if [[ -r "/proc/$$/stat" ]]; then
        awk '{print $22}' "/proc/$$/stat" >"${pair_lock_dir}/owner.start"
      fi
      {
        printf 'case=%s\n' "$case_name"
        printf 'workdir=%s\n' "$workdir"
        printf 'node_a=%s\n' "$node_a"
        printf 'node_b=%s\n' "$node_b"
        printf 'started=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
      } >"${pair_lock_dir}/owner.txt"
      pair_lock_acquired=1
      log "acquired VM-pair lock ${pair_lock_dir}"
      return 0
    fi

    owner_pid="$(cat "${pair_lock_dir}/owner.pid" 2>/dev/null || true)"
    owner_start="$(cat "${pair_lock_dir}/owner.start" 2>/dev/null || true)"
    current_start=""
    if [[ "$owner_pid" =~ ^[0-9]+$ && -r "/proc/${owner_pid}/stat" ]]; then
      current_start="$(awk '{print $22}' "/proc/${owner_pid}/stat" 2>/dev/null || true)"
    fi
    if [[ "$owner_pid" =~ ^[0-9]+$ ]] && kill -0 "$owner_pid" 2>/dev/null &&
      { [[ -z "$owner_start" ]] || [[ "$owner_start" == "$current_start" ]]; }; then
      log "VM pair is already in use by runner pid=${owner_pid}"
      cat "${pair_lock_dir}/owner.txt" >&2 2>/dev/null || true
      return 1
    fi

    log "removing stale VM-pair lock ${pair_lock_dir}"
    rm -f "${pair_lock_dir}/owner.pid" "${pair_lock_dir}/owner.start" "${pair_lock_dir}/owner.txt"
    rmdir "$pair_lock_dir" 2>/dev/null || true
  done
  log "VM pair lock remains unavailable: ${pair_lock_dir}"
  return 1
}

release_pair_lock() {
  local owner_pid
  [[ "$pair_lock_acquired" == "1" && -n "$pair_lock_dir" ]] || return 0
  owner_pid="$(cat "${pair_lock_dir}/owner.pid" 2>/dev/null || true)"
  if [[ "$owner_pid" == "$$" ]]; then
    rm -f "${pair_lock_dir}/owner.pid" "${pair_lock_dir}/owner.start" "${pair_lock_dir}/owner.txt"
    rmdir "$pair_lock_dir" 2>/dev/null || true
  fi
  pair_lock_acquired=0
}

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

soak_start_epoch=""
soak_start_iso=""
kernel_log_start_iso=""

mark_kernel_log_start() {
  local node dir
  kernel_log_start_iso="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  for node in a b; do
    dir="$(remote_dir "$node")"
    run_node "$node" "set +e
mkdir -p $(remote_quote "$dir")
if [ -r /proc/uptime ]; then
  awk '{print \$1}' /proc/uptime >$(remote_quote "${dir}.kernel-log-start-uptime")
fi
"
  done
}

write_run_timing_start() {
  soak_start_epoch="$(date +%s)"
  soak_start_iso="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
}

write_run_timing_end() {
  local end_epoch end_iso elapsed tmp
  [[ -n "$soak_start_epoch" ]] || return 0
  end_epoch="$(date +%s)"
  end_iso="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  elapsed=$((end_epoch - soak_start_epoch))
  tmp="${workdir}/run-timing.json.tmp"
  cat >"$tmp" <<EOF
{"case":"$(json_escape "$case_name")","transport":"$(json_escape "$(case_transport)")","encryption":"$(json_escape "$(case_encryption)")","profile":"$(json_escape "$(case_transport_profile)")","datapath":"$(json_escape "$(case_transport_datapath)")","crypto_placement":"$(json_escape "$(case_crypto_placement)")","mtu":${transport_mtu},"iperf_mode":"$(json_escape "$iperf_mode")","iperf_directions":"$(json_escape "$iperf_directions")","iperf_parallel":${iperf_parallel},"iperf_client_port":${iperf_client_port},"iperf_seconds_requested":${iperf_seconds},"start_epoch":${soak_start_epoch},"end_epoch":${end_epoch},"elapsed_seconds":${elapsed},"start_time":"${soak_start_iso}","end_time":"${end_iso}"}
EOF
  mv "$tmp" "${workdir}/run-timing.json"
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

node_dest() {
  case "$1" in
    a) printf '%s\n' "$node_a" ;;
    b) printf '%s\n' "$node_b" ;;
    *) die "unknown node $1" ;;
  esac
}

node_is_local() {
  case "$(node_dest "$1")" in
    local|localhost|127.0.0.1|"") return 0 ;;
    *) return 1 ;;
  esac
}

run_node() {
  local node="$1"
  local script="$2"
  local dest
  dest="$(node_dest "$node")"
  if node_is_local "$node"; then
    bash -s <<<"$script"
    return
  fi
  ssh -n "${ssh_opts[@]}" "$dest" "bash -c $(remote_quote "$script")"
}

ssh_no_stdin() {
  local dest="$1"
  shift
  ssh -n "${ssh_opts[@]}" "$dest" "$@"
}

copy_to_node() {
  local node="$1"
  local src="$2"
  local dest_path="$3"
  local dest dest_dir
  dest="$(node_dest "$node")"
  if node_is_local "$node"; then
    mkdir -p "$(dirname "$dest_path")"
    cp -a "$src" "$dest_path"
    return
  fi
  if [[ -d "$src" ]]; then
    ssh_no_stdin "$dest" "mkdir -p $(remote_quote "$dest_path")"
    (cd "$src" && tar -czf - .) | ssh "${ssh_opts[@]}" "$dest" "tar -xzf - -C $(remote_quote "$dest_path")"
    return
  fi
  dest_dir="$(dirname "$dest_path")"
  ssh_no_stdin "$dest" "mkdir -p $(remote_quote "$dest_dir")"
  cat "$src" | ssh "${ssh_opts[@]}" "$dest" "cat >$(remote_quote "$dest_path")"
}

fetch_from_node() {
  local node="$1"
  local src="$2"
  local dest_path="$3"
  local dest
  dest="$(node_dest "$node")"
  mkdir -p "$dest_path"
  if node_is_local "$node"; then
    cp -a "$src"/. "$dest_path"/ 2>/dev/null || true
    return
  fi
  if ssh_no_stdin "$dest" "test -d $(remote_quote "$src")" >/dev/null 2>&1; then
    ssh_no_stdin "$dest" "cd $(remote_quote "$src") && tar -czf - ." | tar -xzf - -C "$dest_path" 2>/dev/null || true
  fi
}

node_value() {
  local node="$1"
  local value_a="$2"
  local value_b="$3"
  if [[ "$node" == "a" ]]; then
    printf '%s\n' "$value_a"
  else
    printf '%s\n' "$value_b"
  fi
}

infer_helpers_path_from_module_path() {
  local path="${1:-}"
  case "$path" in
    "") return 0 ;;
    embedded)
      printf 'embedded\n'
      return 0
      ;;
    embedded://trustix_crypto.ko|embedded://trustix_datapath.ko)
      printf 'embedded://trustix_datapath_helpers.ko\n'
      return 0
      ;;
    *trustix_crypto.ko)
      printf '%strustix_datapath_helpers.ko\n' "${path%trustix_crypto.ko}"
      return 0
      ;;
    *trustix_datapath.ko)
      printf '%strustix_datapath_helpers.ko\n' "${path%trustix_datapath.ko}"
      return 0
      ;;
  esac
  return 0
}

remote_dir() {
  node_value "$1" "$remote_a" "$remote_b"
}

daemon_unit_name() {
  local node="$1"
  local dir checksum
  dir="$(remote_dir "$node")"
  checksum="$(printf '%s' "$dir" | cksum | awk '{print $1}')"
  printf 'trustix-cross-host-%s-%s.service\n' "$node" "$checksum"
}

node_bin() {
  local node="$1"
  local name="$2"
  case "$node:$name" in
    a:trustixd) printf '%s\n' "$trustixd_a" ;;
    b:trustixd) printf '%s\n' "$trustixd_b" ;;
    a:trustixctl) printf '%s\n' "$trustixctl_a" ;;
    b:trustixctl) printf '%s\n' "$trustixctl_b" ;;
    *) die "unknown binary $node/$name" ;;
  esac
}

remote_quote() {
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

yaml_single_quote() {
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/''/g")"
}

normalize_case_transport_token() {
  local value="$1"
  value="$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]' | tr '-' '_')"
  case "$value" in
    httpconnect) value="http_connect" ;;
    tixtcp) value="tix_tcp" ;;
  esac
  printf '%s\n' "$value"
}

parse_endpoint_transports() {
  local raw item normalized
  [[ -n "$endpoint_transports_raw" ]] || return 0
  while IFS= read -r item; do
    [[ -n "$item" ]] || continue
    normalized="$(normalize_case_transport_token "$item")"
    case "$normalized" in
      udp|tcp|quic|websocket|http_connect|tix_tcp) ;;
      *) die "unsupported TRUSTIX_CROSS_HOST_ENDPOINT_TRANSPORTS item ${item}" ;;
    esac
    for raw in "${endpoint_transports[@]}"; do
      [[ "$raw" != "$normalized" ]] || die "duplicate TRUSTIX_CROSS_HOST_ENDPOINT_TRANSPORTS item ${normalized}"
    done
    endpoint_transports+=("$normalized")
  done < <(printf '%s\n' "$endpoint_transports_raw" | tr ',\t ' '\n')
  [[ "${#endpoint_transports[@]}" -ge 2 ]] || die "TRUSTIX_CROSS_HOST_ENDPOINT_TRANSPORTS requires at least two transports"
}

case_is_multi_endpoint() {
  [[ "${#endpoint_transports[@]}" -gt 0 ]]
}

case_uses_pinned_mixed_routes() {
  case "$case_name" in
    mixed-plaintext-full-kmod|mixed_plaintext_full_kmod|mixed-secure-kernel|mixed_secure_kernel) return 0 ;;
    *) return 1 ;;
  esac
}

case_is_mixed_secure_kernel() {
  case "$case_name" in
    mixed-secure-kernel|mixed_secure_kernel) return 0 ;;
    *) return 1 ;;
  esac
}

mixed_ipv4_24_default() {
  local cidr="$1"
  local kind="$2"
  local address prefix a b c d octet
  address="${cidr%/*}"
  prefix="${cidr##*/}"
  [[ "$prefix" == "24" ]] || die "pinned mixed routes require a /24 LAN or explicit TRUSTIX_CROSS_HOST_MIXED_* overrides: ${cidr}"
  IFS=. read -r a b c d <<<"$address"
  for octet in "$a" "$b" "$c" "$d"; do
    [[ "$octet" =~ ^[0-9]+$ ]] || die "pinned mixed routes require an IPv4 /24 LAN: ${cidr}"
    [[ "$((10#$octet))" -le 255 ]] || die "pinned mixed routes require an IPv4 /24 LAN: ${cidr}"
  done
  [[ "$((10#$d))" -eq 0 ]] || die "pinned mixed route LAN must use its canonical /24 network address: ${cidr}"
  a=$((10#$a))
  b=$((10#$b))
  c=$((10#$c))
  case "$kind" in
    udp_prefix) printf '%s.%s.%s.0/25\n' "$a" "$b" "$c" ;;
    tix_tcp_prefix) printf '%s.%s.%s.128/25\n' "$a" "$b" "$c" ;;
    tix_tcp_host) printf '%s.%s.%s.130/24\n' "$a" "$b" "$c" ;;
    *) die "unknown pinned mixed IPv4 default kind: ${kind}" ;;
  esac
}

resolve_pinned_mixed_lan() {
  case_uses_pinned_mixed_routes || return 0
  case "$iperf_port" in *[!0-9]*|"") die "TRUSTIX_CROSS_HOST_IPERF_PORT must be an integer" ;; esac
  if [[ -z "$mixed_iperf_port" ]]; then
    mixed_iperf_port=$((iperf_port + 2))
  fi
  if [[ -z "$mixed_udp_lan_a_cidr" ]]; then
    mixed_udp_lan_a_cidr="$(mixed_ipv4_24_default "$lan_a_cidr" udp_prefix)"
  fi
  if [[ -z "$mixed_udp_lan_b_cidr" ]]; then
    mixed_udp_lan_b_cidr="$(mixed_ipv4_24_default "$lan_b_cidr" udp_prefix)"
  fi
  if [[ -z "$mixed_tix_tcp_lan_a_cidr" ]]; then
    mixed_tix_tcp_lan_a_cidr="$(mixed_ipv4_24_default "$lan_a_cidr" tix_tcp_prefix)"
  fi
  if [[ -z "$mixed_tix_tcp_lan_b_cidr" ]]; then
    mixed_tix_tcp_lan_b_cidr="$(mixed_ipv4_24_default "$lan_b_cidr" tix_tcp_prefix)"
  fi
  if [[ -z "$mixed_host_a_addr" ]]; then
    mixed_host_a_addr="$(mixed_ipv4_24_default "$lan_a_cidr" tix_tcp_host)"
  fi
  if [[ -z "$mixed_host_b_addr" ]]; then
    mixed_host_b_addr="$(mixed_ipv4_24_default "$lan_b_cidr" tix_tcp_host)"
  fi
  mixed_host_a_ip="${mixed_host_a_addr%/*}"
  mixed_host_b_ip="${mixed_host_b_addr%/*}"
}

write_pinned_mixed_contract() {
  case_uses_pinned_mixed_routes || return 0
  cat >"$workdir/pinned-mixed-routes.txt" <<EOF
udp.a_prefix=${mixed_udp_lan_a_cidr}
udp.b_prefix=${mixed_udp_lan_b_cidr}
udp.a_host=${host_a_ip}
udp.b_host=${host_b_ip}
udp.iperf_port=${iperf_port}
tix_tcp.a_prefix=${mixed_tix_tcp_lan_a_cidr}
tix_tcp.b_prefix=${mixed_tix_tcp_lan_b_cidr}
tix_tcp.a_host=${mixed_host_a_ip}
tix_tcp.b_host=${mixed_host_b_ip}
tix_tcp.iperf_port=${mixed_iperf_port}
EOF
}

first_endpoint_transport() {
  case_is_multi_endpoint || return 1
  printf '%s\n' "${endpoint_transports[0]}"
}

transport_uses_link_tls() {
  case "$(normalize_case_transport_token "$1")" in
    tcp|quic|websocket|http_connect) return 0 ;;
    *) return 1 ;;
  esac
}

generic_case_kind() {
  case "$case_name" in
    userspace-*-secure|userspace-*-plaintext|crosshost-userspace-*-secure|crosshost-userspace-*-plaintext) printf 'userspace\n' ;;
    tc-*-secure|tc-*-plaintext|crosshost-tc-*-secure|crosshost-tc-*-plaintext) printf 'userspace_tc\n' ;;
  esac
}

generic_case_encryption() {
  case "$case_name" in
    *-secure) printf 'secure\n' ;;
    *-plaintext) printf 'plaintext\n' ;;
  esac
}

generic_case_transport() {
  local raw="$case_name"
  raw="${raw#crosshost-}"
  raw="${raw#userspace-}"
  raw="${raw#tc-}"
  raw="${raw%-secure}"
  raw="${raw%-plaintext}"
  normalize_case_transport_token "$raw"
}

supported_case_transport() {
  case "$(normalize_case_transport_token "$1")" in
    udp|tcp|quic|websocket|http_connect|gre|ipip|vxlan|tix_tcp) return 0 ;;
    *) return 1 ;;
  esac
}

case_is_iptunnel_transport() {
  case "$(case_endpoint_transport)" in
    gre|ipip|vxlan) return 0 ;;
    *) return 1 ;;
  esac
}

case_is_generic() {
  [[ -n "$(generic_case_kind)" ]]
}

validate_case() {
  validate_case_crypto_suites
  validate_case_tls_data_plane
  if case_is_generic; then
    if case_is_multi_endpoint; then
      [[ "$(generic_case_kind)" == "userspace" ]] || die "multi-endpoint soak currently requires a userspace case"
      [[ "$(generic_case_transport)" == "mixed" ]] || die "multi-endpoint soak case must use userspace-mixed-secure/plaintext"
    else
      supported_case_transport "$(generic_case_transport)" || die "unsupported generic TRUSTIX_CROSS_HOST_CASE transport in ${case_name}"
    fi
    case "$(generic_case_encryption)" in secure|plaintext) ;; *) die "unsupported generic TRUSTIX_CROSS_HOST_CASE encryption in ${case_name}" ;; esac
    return
  fi
  case "$case_name" in
    dd-fullkmod|owdeb-fullkmod|full-kmod|udp-plaintext-full-kmod|udp_plaintext_full_kmod) ;;
    tix-tcp-full-kmod|tix_tcp_full_kmod|tix-tcp-full-kmod|tix_tcp_full_kmod|dd-tix-tcp-full-kmod|dd_tix_tcp_full_kmod|owdeb-tix-tcp-full-kmod|owdeb_tix_tcp_full_kmod) ;;
    mixed-plaintext-full-kmod|mixed_plaintext_full_kmod|mixed-secure-kernel|mixed_secure_kernel)
      [[ "${#endpoint_transports[@]}" -eq 2 ]] || die "${case_name} requires exactly udp,tix_tcp endpoints"
      case_has_endpoint_transport udp || die "${case_name} requires a UDP endpoint"
      case_has_endpoint_transport tix_tcp || die "${case_name} requires a tix_tcp endpoint"
      ;;
    dd-secure-kudp|owdeb-secure-kudp|secure-kudp|kernel-udp-secure-kernel|kernel_udp_secure_kernel|udp-secure-kernel|udp_secure_kernel) ;;
    secure-tix-tcp-kernel|secure_tix_tcp_kernel|tix-tcp-secure-kernel|tix_tcp_secure_kernel|secure-tix-tcp-kernel|secure_tix_tcp_kernel) ;;
    dd-routegso|owdeb-routegso|route-gso|tix-tcp-route-gso|tix_tcp_route_gso) ;;
    ow-tc-direct|tc-direct|tix-tcp-tc-direct|tix_tcp_tc_direct) ;;
    *) die "unsupported TRUSTIX_CROSS_HOST_CASE=${case_name}" ;;
  esac
}

case_transport() {
  if [[ -n "$case_transport_override" ]]; then
    normalize_case_transport_token "$case_transport_override"
    return
  fi
  if case_is_generic; then
    generic_case_transport
    return
  fi
  case "$case_name" in
    mixed-plaintext-full-kmod|mixed_plaintext_full_kmod|mixed-secure-kernel|mixed_secure_kernel) printf 'mixed\n' ;;
    dd-fullkmod|owdeb-fullkmod|full-kmod|udp-plaintext-full-kmod|udp_plaintext_full_kmod|dd-secure-kudp|owdeb-secure-kudp|secure-kudp|kernel-udp-secure-kernel|kernel_udp_secure_kernel|udp-secure-kernel|udp_secure_kernel) printf 'udp\n' ;;
    tix-tcp-full-kmod|tix_tcp_full_kmod|tix-tcp-full-kmod|tix_tcp_full_kmod|dd-tix-tcp-full-kmod|dd_tix_tcp_full_kmod|owdeb-tix-tcp-full-kmod|owdeb_tix_tcp_full_kmod) printf 'tix_tcp\n' ;;
    ow-tc-direct|tc-direct) printf 'udp\n' ;;
    tix-tcp-tc-direct|tix_tcp_tc_direct) printf 'tix_tcp\n' ;;
    *) printf 'tix_tcp\n' ;;
  esac
}

case_fast_path() {
  if case_is_generic; then
    generic_case_kind
    return
  fi
  case "$case_name" in
    dd-fullkmod|owdeb-fullkmod|full-kmod|udp-plaintext-full-kmod|udp_plaintext_full_kmod|tix-tcp-full-kmod|tix_tcp_full_kmod|tix-tcp-full-kmod|tix_tcp_full_kmod|dd-tix-tcp-full-kmod|dd_tix_tcp_full_kmod|owdeb-tix-tcp-full-kmod|owdeb_tix_tcp_full_kmod|mixed-plaintext-full-kmod|mixed_plaintext_full_kmod) printf 'full_kmod\n' ;;
    mixed-secure-kernel|mixed_secure_kernel) printf 'secure_tix_tcp_kernel\n' ;;
    dd-secure-kudp|owdeb-secure-kudp|secure-kudp|kernel-udp-secure-kernel|kernel_udp_secure_kernel|udp-secure-kernel|udp_secure_kernel) printf 'secure_kudp\n' ;;
    secure-tix-tcp-kernel|secure_tix_tcp_kernel|tix-tcp-secure-kernel|tix_tcp_secure_kernel|secure-tix-tcp-kernel|secure_tix_tcp_kernel) printf 'secure_tix_tcp_kernel\n' ;;
    dd-routegso|owdeb-routegso|route-gso|tix-tcp-route-gso|tix_tcp_route_gso) printf 'route_gso\n' ;;
    ow-tc-direct|tc-direct|tix-tcp-tc-direct|tix_tcp_tc_direct) printf 'tc_direct\n' ;;
    *) die "unsupported TRUSTIX_CROSS_HOST_CASE=${case_name}" ;;
  esac
}

case_encryption() {
  if [[ -n "$case_encryption_override" ]]; then
    printf '%s\n' "$case_encryption_override"
    return
  fi
  if case_is_generic; then
    generic_case_encryption
    return
  fi
  case "$(case_fast_path)" in
    secure_kudp|secure_tix_tcp_kernel) printf 'secure\n' ;;
    *) printf 'plaintext\n' ;;
  esac
}

case_crypto_placement() {
  if [[ -n "$case_crypto_placement_override" ]]; then
    printf '%s\n' "$case_crypto_placement_override"
    return
  fi
  if case_uses_secure_kudp_fast_path; then
    printf 'kernel\n'
    return
  fi
  case "$(case_fast_path)" in
    secure_tix_tcp_kernel) printf 'kernel\n' ;;
    *) printf 'userspace\n' ;;
  esac
}

case_endpoint_transport() {
  if case_is_multi_endpoint; then
    first_endpoint_transport
    return
  fi
  if [[ -n "$endpoint_transport_override" ]]; then
    normalize_case_transport_token "$endpoint_transport_override"
    return
  fi
  case_transport
}

case_has_endpoint_transport() {
  local wanted transport
  wanted="$(normalize_case_transport_token "$1")"
  if case_is_multi_endpoint; then
    for transport in "${endpoint_transports[@]}"; do
      [[ "$transport" != "$wanted" ]] || return 0
    done
    return 1
  fi
  [[ "$(case_endpoint_transport)" == "$wanted" ]]
}

case_capability_profile() {
  case "$(case_fast_path)" in
    full_kmod) printf 'full_plaintext\n' ;;
    tc_direct|userspace|userspace_tc) printf 'disabled\n' ;;
    *) printf 'performance\n' ;;
  esac
}

case_transport_profile() {
  if [[ -n "$case_profile_override" ]]; then
    printf '%s\n' "$case_profile_override"
    return
  fi
  if case_uses_secure_kudp_fast_path; then
    printf 'performance\n'
    return
  fi
  case "$(case_fast_path)" in
    userspace) printf 'stable\n' ;;
    userspace_tc)
      if case_uses_tc_direct_fast_path; then
        printf 'performance\n'
      else
        printf 'stable\n'
      fi
      ;;
    *) printf 'performance\n' ;;
  esac
}

case_crypto_suites_yaml() {
  local raw suite
  raw="${case_crypto_suites_override//,/ }"
  [[ -n "${raw//[[:space:]]/}" ]] || return 0
  printf '  crypto_suites:\n'
  for suite in $raw; do
    printf '    - %s\n' "$suite"
  done
}

case_tls_data_plane_yaml() {
  [[ -n "$case_tls_data_plane_override" ]] || return 0
  printf '  tls_data_plane: %s\n' "$case_tls_data_plane_override"
}

validate_case_crypto_suites() {
  local raw suite
  raw="${case_crypto_suites_override//,/ }"
  [[ -n "${raw//[[:space:]]/}" ]] || return 0
  for suite in $raw; do
    case "$suite" in
      AES-256-GCM-X25519|AES-128-GCM-X25519|CHACHA20-POLY1305-X25519) ;;
      *) die "TRUSTIX_CROSS_HOST_CRYPTO_SUITES contains unsupported suite: $suite" ;;
    esac
  done
}

validate_case_tls_data_plane() {
  case "$case_tls_data_plane_override" in
    ""|auto|full_tls) ;;
    *) die "TRUSTIX_CROSS_HOST_TLS_DATA_PLANE must be auto or full_tls" ;;
  esac
}

case_transport_datapath() {
  if [[ -n "$case_datapath_override" ]]; then
    printf '%s\n' "$case_datapath_override"
    return
  fi
  case "$(case_fast_path)" in
    userspace) printf 'userspace\n' ;;
    userspace_tc)
      if case_uses_tc_direct_fast_path; then
        printf 'tc_xdp\n'
      else
        printf 'userspace\n'
      fi
      ;;
    secure_kudp|tc_direct) printf 'tc_xdp\n' ;;
    secure_tix_tcp_kernel) printf 'kernel_module\n' ;;
    *) printf 'kernel_module\n' ;;
  esac
}

case_kernel_transport_mode() {
  if case_is_iptunnel_transport; then
    printf 'require_kernel\n'
    return
  fi
  case "$(case_fast_path)" in
    userspace) printf '\n' ;;
    userspace_tc)
      if case_uses_tc_direct_fast_path; then
        printf 'require_kernel\n'
      else
        printf '\n'
      fi
      ;;
    *) printf 'require_kernel\n' ;;
  esac
}

case_uses_secure_kudp_fast_path() {
  if case_is_mixed_secure_kernel; then
    return 0
  fi
  case "$(case_fast_path)" in
    secure_kudp) return 0 ;;
    userspace_tc)
      [[ "$(case_endpoint_transport)" == "udp" && "$(case_encryption)" == "secure" ]] &&
        truthy "${TRUSTIX_CROSS_HOST_SECURE_KUDP_KERNEL_CRYPTO:-0}"
      ;;
    *) return 1 ;;
  esac
}

case_uses_tc_direct_fast_path() {
  case "$(case_fast_path)" in
    secure_kudp|tc_direct) return 0 ;;
    userspace_tc)
      if case_uses_secure_kudp_fast_path; then
        return 0
      fi
      case "$(case_endpoint_transport):$(case_encryption)" in
        udp:plaintext|tix_tcp:plaintext) return 0 ;;
        *) return 1 ;;
      esac
      ;;
    *) return 1 ;;
  esac
}

case_tc_requested_but_falls_back_to_userspace() {
  [[ "$(case_fast_path)" == "userspace_tc" ]] && ! case_uses_tc_direct_fast_path
}

apply_case_runtime_defaults() {
  case "$case_name" in
    tix-tcp-full-kmod|tix_tcp_full_kmod|tix-tcp-full-kmod|tix_tcp_full_kmod|dd-tix-tcp-full-kmod|dd_tix_tcp_full_kmod|owdeb-tix-tcp-full-kmod|owdeb_tix_tcp_full_kmod)
      if [[ -z "$iperf_parallel_explicit" ]]; then
        iperf_parallel=16
      fi
      if [[ -z "$session_pool_size_explicit" ]]; then
        session_pool_size="$iperf_parallel"
      fi
      ;;
  esac
  if case_is_iptunnel_transport && [[ -z "$iperf_parallel_explicit" ]]; then
    iperf_parallel="$iptunnel_iperf_parallel"
    if [[ -z "$session_pool_size_explicit" ]]; then
      session_pool_size="$iperf_parallel"
    fi
  fi
}

case_secure_kudp_route_gso() {
  if case_is_mixed_secure_kernel; then
    return 0
  fi
  case "$(case_fast_path)" in
    secure_kudp) return 0 ;;
  esac
  truthy "${TRUSTIX_CROSS_HOST_SECURE_KUDP_ROUTE_GSO:-0}"
}

case_link_tls_transport() {
  local transport
  if case_is_multi_endpoint; then
    for transport in "${endpoint_transports[@]}"; do
      transport_uses_link_tls "$transport" && return 0
    done
    return 1
  fi
  case "$(case_endpoint_transport)" in
    tcp|quic|websocket|http_connect) return 0 ;;
    *) return 1 ;;
  esac
}

endpoint_security_yaml() {
  local indent="$1"
  local encryption="$2"
  local endpoint_transport="${3:-$(case_endpoint_transport)}"
  printf '%ssecurity:\n' "$indent"
  if transport_uses_link_tls "$endpoint_transport"; then
    printf '%s  link_tls: required\n' "$indent"
  fi
  printf '%s  encryption: %s\n' "$indent" "$encryption"
}

case_endpoint_name() {
  local node="$1"
  local transport
  transport="$(case_endpoint_transport)"
  case_endpoint_name_for_transport "$node" "$transport"
}

case_endpoint_name_for_transport() {
  local node="$1"
  local transport="$2"
  case "$transport" in
    udp) node_value "$node" a-udp b-udp ;;
    tix_tcp) node_value "$node" a-tix-tcp b-tix-tcp ;;
    *) node_value "$node" "a-${transport//_/-}" "b-${transport//_/-}" ;;
  esac
}

case_endpoint_port_for_index() {
  local node="$1"
  local index="$2"
  local base
  base="$(node_value "$node" "$data_a_port" "$data_b_port")"
  printf '%s\n' "$((base + index))"
}

tunnel_config_for_node() {
  local node="$1"
  local transport underlay_local underlay_remote underlay_if local_carrier remote_carrier remote_addr fields
  transport="$(case_endpoint_transport)"
  underlay_local="$(node_value "$node" "$underlay_a_ip" "$underlay_b_ip")"
  underlay_remote="$(node_value "$node" "$underlay_b_ip" "$underlay_a_ip")"
  underlay_if="$(node_value "$node" "$underlay_a_if" "$underlay_b_if")"
  local_carrier="$(node_value "$node" "$iptunnel_a_carrier" "$iptunnel_b_carrier")"
  remote_carrier="$(node_value "$node" "${iptunnel_b_carrier%/*}" "${iptunnel_a_carrier%/*}")"
  fields="local=${underlay_local},remote=${underlay_remote},underlay_if=${underlay_if},local_carrier=${local_carrier},remote_carrier=${remote_carrier},port=${iptunnel_port},mtu=${iptunnel_mtu}"
  if [[ "$transport" == "vxlan" ]]; then
    fields="${fields},vni=${vxlan_vni},vxlan_port=${vxlan_port}"
  fi
  printf '%s\n' "$fields"
}

default_data_port() {
  local node="$1"
  node_value "$node" 13000 13001
}

resolve_data_ports() {
  if [[ -z "$data_a_port" ]]; then
    data_a_port="$(default_data_port a)"
  fi
  if [[ -z "$data_b_port" ]]; then
    data_b_port="$(default_data_port b)"
  fi
}

validate_multi_endpoint_data_ports() {
  local max_a max_b
  case_is_multi_endpoint || return 0
  case "$data_a_port" in *[!0-9]*|"") die "TRUSTIX_CROSS_HOST_DATA_A_PORT must be an integer" ;; esac
  case "$data_b_port" in *[!0-9]*|"") die "TRUSTIX_CROSS_HOST_DATA_B_PORT must be an integer" ;; esac
  [[ "$data_a_port" -gt 0 && "$data_b_port" -gt 0 ]] || die "multi-endpoint data ports must be greater than zero"
  max_a=$((data_a_port + ${#endpoint_transports[@]} - 1))
  max_b=$((data_b_port + ${#endpoint_transports[@]} - 1))
  [[ "$max_a" -le 65535 && "$max_b" -le 65535 ]] || die "multi-endpoint data port range exceeds 65535"
}

secure_kudp_module_yaml() {
  local node="${1:-a}"
  local params="${TRUSTIX_CROSS_HOST_SECURE_KUDP_CRYPTO_PARAMETERS:-}"
  local helper_params="${TRUSTIX_CROSS_HOST_SECURE_KUDP_HELPER_PARAMETERS:-}"
  local path
  local helper_path
  path="$(node_value "$node" "$secure_kudp_crypto_path_a" "$secure_kudp_crypto_path_b")"
  helper_path="$(node_value "$node" "$secure_kudp_helpers_path_a" "$secure_kudp_helpers_path_b")"
  if [[ -z "$helper_path" ]]; then
    helper_path="$(infer_helpers_path_from_module_path "$path")"
  fi
  cat <<'EOF'
kernel_modules:
  capability_profile: performance
  trustix_crypto:
    mode: required
    reload_on_upgrade: auto
    unload_on_exit: true
EOF
  printf '    path: %s\n' "$(yaml_single_quote "$path")"
  if [[ -n "$params" ]]; then
    printf '    parameters: %s\n' "$(yaml_single_quote "$params")"
  fi
  cat <<'EOF'
  trustix_datapath:
    mode: disabled
  trustix_datapath_helpers:
EOF
  if case_secure_kudp_route_gso && [[ -n "$helper_path" ]]; then
    cat <<'EOF'
    mode: required
    reload_on_upgrade: auto
    unload_on_exit: true
EOF
    printf '    path: %s\n' "$(yaml_single_quote "$helper_path")"
    if [[ -n "$helper_params" ]]; then
      printf '    parameters: %s\n' "$(yaml_single_quote "$helper_params")"
    fi
  else
    cat <<'EOF'
    mode: disabled
EOF
  fi
}

secure_tix_tcp_module_yaml() {
  local node="${1:-a}"
  local crypto_params="${TRUSTIX_CROSS_HOST_SECURE_TIX_TCP_CRYPTO_PARAMETERS:-}"
  local datapath_params="${TRUSTIX_CROSS_HOST_SECURE_TIX_TCP_DATAPATH_PARAMETERS:-}"
  local crypto_path
  local datapath_path
  crypto_path="$(node_value "$node" "$secure_tix_tcp_crypto_path_a" "$secure_tix_tcp_crypto_path_b")"
  datapath_path="$(node_value "$node" "$secure_tix_tcp_datapath_path_a" "$secure_tix_tcp_datapath_path_b")"
  cat <<'EOF'
kernel_modules:
  capability_profile: performance
  trustix_crypto:
    mode: required
    reload_on_upgrade: auto
    unload_on_exit: true
EOF
  printf '    path: %s\n' "$(yaml_single_quote "$crypto_path")"
  if [[ -n "$crypto_params" ]]; then
    printf '    parameters: %s\n' "$(yaml_single_quote "$crypto_params")"
  fi
  cat <<'EOF'
  trustix_datapath:
    mode: required
    reload_on_upgrade: auto
    unload_on_exit: true
EOF
  printf '    path: %s\n' "$(yaml_single_quote "$datapath_path")"
  if [[ -n "$datapath_params" ]]; then
    printf '    parameters: %s\n' "$(yaml_single_quote "$datapath_params")"
  fi
  cat <<'EOF'
  trustix_datapath_helpers:
    mode: disabled
EOF
}

mixed_secure_kernel_module_yaml() {
  local node="${1:-a}"
  local crypto_params="${TRUSTIX_CROSS_HOST_SECURE_TIX_TCP_CRYPTO_PARAMETERS:-${TRUSTIX_CROSS_HOST_SECURE_KUDP_CRYPTO_PARAMETERS:-}}"
  local datapath_params="${TRUSTIX_CROSS_HOST_SECURE_TIX_TCP_DATAPATH_PARAMETERS:-}"
  local helper_params="${TRUSTIX_CROSS_HOST_SECURE_KUDP_HELPER_PARAMETERS:-}"
  local crypto_path
  local datapath_path
  local helper_path
  crypto_path="$(node_value "$node" "$secure_tix_tcp_crypto_path_a" "$secure_tix_tcp_crypto_path_b")"
  datapath_path="$(node_value "$node" "$secure_tix_tcp_datapath_path_a" "$secure_tix_tcp_datapath_path_b")"
  helper_path="$(node_value "$node" "$secure_kudp_helpers_path_a" "$secure_kudp_helpers_path_b")"
  if [[ -z "$helper_path" ]]; then
    helper_path="$(infer_helpers_path_from_module_path "$crypto_path")"
  fi
  [[ -n "$helper_path" ]] || die "mixed secure kernel mode requires a trustix_datapath_helpers module path"
  cat <<'EOF'
kernel_modules:
  capability_profile: performance
  trustix_crypto:
    mode: required
    reload_on_upgrade: auto
    unload_on_exit: true
EOF
  printf '    path: %s\n' "$(yaml_single_quote "$crypto_path")"
  if [[ -n "$crypto_params" ]]; then
    printf '    parameters: %s\n' "$(yaml_single_quote "$crypto_params")"
  fi
  cat <<'EOF'
  trustix_datapath:
    mode: required
    reload_on_upgrade: auto
    unload_on_exit: true
EOF
  printf '    path: %s\n' "$(yaml_single_quote "$datapath_path")"
  if [[ -n "$datapath_params" ]]; then
    printf '    parameters: %s\n' "$(yaml_single_quote "$datapath_params")"
  fi
  cat <<'EOF'
  trustix_datapath_helpers:
    mode: required
    reload_on_upgrade: auto
    unload_on_exit: true
EOF
  printf '    path: %s\n' "$(yaml_single_quote "$helper_path")"
  if [[ -n "$helper_params" ]]; then
    printf '    parameters: %s\n' "$(yaml_single_quote "$helper_params")"
  fi
}

case_module_yaml() {
  local node="${1:-a}"
  if case_is_mixed_secure_kernel; then
    mixed_secure_kernel_module_yaml "$node"
    return
  fi
  if [[ "$(case_fast_path)" == "secure_tix_tcp_kernel" ]]; then
    secure_tix_tcp_module_yaml "$node"
    return
  fi
  if case_uses_secure_kudp_fast_path; then
    secure_kudp_module_yaml "$node"
    return
  fi
  case "$(case_fast_path)" in
    full_kmod)
      local params="${TRUSTIX_CROSS_HOST_FULL_KMOD_DATAPATH_PARAMETERS:-}"
      local path
      path="$(node_value "$node" "$full_kmod_datapath_path_a" "$full_kmod_datapath_path_b")"
      cat <<'EOF'
kernel_modules:
  capability_profile: full_plaintext
  datapath:
    rx_stage: worker
    rx_worker: true
    tx_plaintext: true
    full_plaintext: true
  trustix_crypto:
    mode: disabled
  trustix_datapath:
    mode: required
    reload_on_upgrade: auto
    unload_on_exit: true
EOF
      printf '    path: %s\n' "$(yaml_single_quote "$path")"
      if [[ -n "$params" ]]; then
        printf '    parameters: %s\n' "$(yaml_single_quote "$params")"
      fi
      cat <<'EOF'
  trustix_datapath_helpers:
    mode: disabled
EOF
      ;;
    route_gso)
      local params="${TRUSTIX_CROSS_HOST_ROUTE_GSO_HELPER_PARAMETERS:-}"
      local path
      path="$(node_value "$node" "$route_gso_helpers_path_a" "$route_gso_helpers_path_b")"
      cat <<'EOF'
kernel_modules:
  capability_profile: performance
  trustix_crypto:
    mode: disabled
  trustix_datapath:
    mode: disabled
  trustix_datapath_helpers:
    mode: required
    reload_on_upgrade: auto
    unload_on_exit: true
EOF
      printf '    path: %s\n' "$(yaml_single_quote "$path")"
      if [[ -n "$params" ]]; then
        printf '    parameters: %s\n' "$(yaml_single_quote "$params")"
      fi
      ;;
    tc_direct)
      cat <<'EOF'
kernel_modules:
  capability_profile: disabled
  trustix_crypto:
    mode: disabled
  trustix_datapath:
    mode: disabled
  trustix_datapath_helpers:
    mode: disabled
EOF
      ;;
    userspace|userspace_tc)
      cat <<'EOF'
kernel_modules:
  capability_profile: disabled
  trustix_crypto:
    mode: disabled
  trustix_datapath:
    mode: disabled
  trustix_datapath_helpers:
    mode: disabled
EOF
      ;;
    secure_kudp)
      local params="${TRUSTIX_CROSS_HOST_SECURE_KUDP_CRYPTO_PARAMETERS:-}"
      local helper_params="${TRUSTIX_CROSS_HOST_SECURE_KUDP_HELPER_PARAMETERS:-}"
      local path
      local helper_path
      path="$(node_value "$node" "$secure_kudp_crypto_path_a" "$secure_kudp_crypto_path_b")"
      helper_path="$(node_value "$node" "$secure_kudp_helpers_path_a" "$secure_kudp_helpers_path_b")"
      if [[ -z "$helper_path" ]]; then
        helper_path="$(infer_helpers_path_from_module_path "$path")"
      fi
      cat <<'EOF'
kernel_modules:
  capability_profile: performance
  trustix_crypto:
    mode: required
    reload_on_upgrade: auto
    unload_on_exit: true
EOF
      printf '    path: %s\n' "$(yaml_single_quote "$path")"
      if [[ -n "$params" ]]; then
        printf '    parameters: %s\n' "$(yaml_single_quote "$params")"
      fi
      cat <<'EOF'
  trustix_datapath:
    mode: disabled
  trustix_datapath_helpers:
EOF
      if [[ -n "$helper_path" ]]; then
        cat <<'EOF'
    mode: required
    reload_on_upgrade: auto
    unload_on_exit: true
EOF
        printf '    path: %s\n' "$(yaml_single_quote "$helper_path")"
        if [[ -n "$helper_params" ]]; then
          printf '    parameters: %s\n' "$(yaml_single_quote "$helper_params")"
        fi
      else
        cat <<'EOF'
    mode: disabled
EOF
      fi
      ;;
  esac
}

check_local_inputs() {
  [[ -n "$node_b" ]] || die "TRUSTIX_CROSS_HOST_B is required unless node B is local"
  [[ -x "$trustix_ca" ]] || die "trustix-ca is not executable: $trustix_ca"
  case "$iperf_seconds" in *[!0-9]*|"") die "TRUSTIX_CROSS_HOST_IPERF_SECONDS must be an integer" ;; esac
  case "$iperf_parallel" in *[!0-9]*|"") die "TRUSTIX_CROSS_HOST_IPERF_PARALLEL must be an integer" ;; esac
  case "$iptunnel_iperf_parallel" in *[!0-9]*|"") die "TRUSTIX_CROSS_HOST_IPTUNNEL_IPERF_PARALLEL must be an integer" ;; esac
  case "$iperf_port" in *[!0-9]*|"") die "TRUSTIX_CROSS_HOST_IPERF_PORT must be an integer" ;; esac
  case "$iperf_client_port" in *[!0-9]*|"") die "TRUSTIX_CROSS_HOST_IPERF_CLIENT_PORT must be an integer" ;; esac
  case "$max_consecutive_zero_intervals" in *[!0-9]*|"") die "TRUSTIX_CROSS_HOST_MAX_CONSECUTIVE_ZERO_INTERVALS must be a non-negative integer" ;; esac
  if [[ -z "$mixed_iperf_port" ]]; then
    mixed_iperf_port=$((iperf_port + 2))
  fi
  case "$mixed_iperf_port" in *[!0-9]*|"") die "TRUSTIX_CROSS_HOST_MIXED_IPERF_PORT must be an integer" ;; esac
  if [[ -z "$health_port" ]]; then
    health_port=$((iperf_port + 1))
  fi
  case "$health_port" in *[!0-9]*|"") die "TRUSTIX_CROSS_HOST_HEALTH_PORT must be an integer" ;; esac
  [[ "$health_port" -ne "$iperf_port" ]] || die "TRUSTIX_CROSS_HOST_HEALTH_PORT must differ from TRUSTIX_CROSS_HOST_IPERF_PORT"
  [[ "$iperf_port" -ge 1 && "$iperf_port" -le 65535 ]] || die "TRUSTIX_CROSS_HOST_IPERF_PORT must be in 1..65535"
  [[ "$mixed_iperf_port" -ge 1 && "$mixed_iperf_port" -le 65535 ]] || die "TRUSTIX_CROSS_HOST_MIXED_IPERF_PORT must be in 1..65535"
  [[ "$health_port" -ge 1 && "$health_port" -le 65535 ]] || die "TRUSTIX_CROSS_HOST_HEALTH_PORT must be in 1..65535"
  if case_uses_pinned_mixed_routes; then
    [[ "$mixed_iperf_port" -ne "$iperf_port" ]] || die "TRUSTIX_CROSS_HOST_MIXED_IPERF_PORT must differ from TRUSTIX_CROSS_HOST_IPERF_PORT"
    [[ "$mixed_iperf_port" -ne "$health_port" ]] || die "TRUSTIX_CROSS_HOST_MIXED_IPERF_PORT must differ from TRUSTIX_CROSS_HOST_HEALTH_PORT"
  fi
  case "$transport_snapshot_delay" in *[!0-9]*|"") die "TRUSTIX_CROSS_HOST_TRANSPORT_SNAPSHOT_DELAY must be an integer" ;; esac
  case "$pair_lock_hold_seconds" in *[!0-9]*|"") die "TRUSTIX_CROSS_HOST_PAIR_LOCK_HOLD_SECONDS must be an integer" ;; esac
  case "$session_pool_size" in *[!0-9]*|"") die "TRUSTIX_CROSS_HOST_SESSION_POOL_SIZE must be an integer" ;; esac
  case "$capture_forwarder_workers" in auto) ;; *[!0-9]*|"") die "TRUSTIX_CROSS_HOST_CAPTURE_FORWARDER_WORKERS must be auto or a positive integer" ;; esac
  case "$capture_forwarder_buffer" in *[!0-9]*|"") die "TRUSTIX_CROSS_HOST_CAPTURE_FORWARDER_BUFFER must be a positive integer" ;; esac
  case "$capture_forwarder_batch" in *[!0-9]*|"") die "TRUSTIX_CROSS_HOST_CAPTURE_FORWARDER_BATCH must be a positive integer" ;; esac
  if [[ -n "$cpu_profile_dir" && ! "$cpu_profile_dir" =~ ^[A-Za-z0-9_./:-]+$ ]]; then
    die "TRUSTIX_CROSS_HOST_CPU_PROFILE_DIR must be a shell-safe path without whitespace"
  fi
  case "$secure_tix_tcp_inner_checksum_partial" in
    ""|true|false|1|0|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_CROSS_HOST_SECURE_TIX_TCP_INNER_CHECKSUM_PARTIAL must be boolean" ;;
  esac
  case "$iptunnel_port" in *[!0-9]*|"") die "TRUSTIX_CROSS_HOST_IPTUNNEL_PORT must be an integer" ;; esac
  case "$iptunnel_mtu" in *[!0-9]*|"") die "TRUSTIX_CROSS_HOST_IPTUNNEL_MTU must be an integer" ;; esac
  case "$vxlan_vni" in *[!0-9]*|"") die "TRUSTIX_CROSS_HOST_VXLAN_VNI must be an integer" ;; esac
  case "$vxlan_port" in *[!0-9]*|"") die "TRUSTIX_CROSS_HOST_VXLAN_PORT must be an integer" ;; esac
  case "$cleanup_timeout" in *[!0-9]*|"") die "TRUSTIX_CROSS_HOST_CLEANUP_TIMEOUT must be an integer" ;; esac
  case "$daemon_supervisor" in process|systemd) ;; *) die "TRUSTIX_CROSS_HOST_DAEMON_SUPERVISOR must be process or systemd" ;; esac
  case "$daemon_restart_sec" in *[!0-9]*|"") die "TRUSTIX_CROSS_HOST_DAEMON_RESTART_SEC must be an integer" ;; esac
  [[ "$iperf_parallel" -ge 1 ]] || die "TRUSTIX_CROSS_HOST_IPERF_PARALLEL must be >= 1"
  [[ "$iptunnel_iperf_parallel" -ge 1 ]] || die "TRUSTIX_CROSS_HOST_IPTUNNEL_IPERF_PARALLEL must be >= 1"
  [[ "$iperf_client_port" -ge 0 && "$iperf_client_port" -le 65535 ]] || die "TRUSTIX_CROSS_HOST_IPERF_CLIENT_PORT must be 0 or in 1..65535"
  if [[ "$iperf_client_port" -gt 0 ]]; then
    [[ $((iperf_client_port + iperf_parallel - 1)) -le 65535 ]] || die "TRUSTIX_CROSS_HOST_IPERF_CLIENT_PORT plus parallel streams exceeds 65535"
  fi
  [[ "$transport_snapshot_delay" -ge 0 ]] || die "TRUSTIX_CROSS_HOST_TRANSPORT_SNAPSHOT_DELAY must be >= 0"
  [[ "$session_pool_size" -ge 1 ]] || die "TRUSTIX_CROSS_HOST_SESSION_POOL_SIZE must be >= 1"
  if [[ "$capture_forwarder_workers" != "auto" ]]; then
    [[ "$capture_forwarder_workers" -ge 1 ]] || die "TRUSTIX_CROSS_HOST_CAPTURE_FORWARDER_WORKERS must be >= 1"
  fi
  [[ "$capture_forwarder_buffer" -ge 1 ]] || die "TRUSTIX_CROSS_HOST_CAPTURE_FORWARDER_BUFFER must be >= 1"
  [[ "$capture_forwarder_batch" -ge 1 ]] || die "TRUSTIX_CROSS_HOST_CAPTURE_FORWARDER_BATCH must be >= 1"
  [[ "$capture_forwarder_batch" -le 4096 ]] || die "TRUSTIX_CROSS_HOST_CAPTURE_FORWARDER_BATCH must be <= 4096"
  [[ "$iptunnel_port" -ge 1 && "$iptunnel_port" -le 65535 ]] || die "TRUSTIX_CROSS_HOST_IPTUNNEL_PORT must be in 1..65535"
  [[ "$iptunnel_mtu" -ge 17 && "$iptunnel_mtu" -le 65535 ]] || die "TRUSTIX_CROSS_HOST_IPTUNNEL_MTU must be in 17..65535"
  [[ "$vxlan_vni" -ge 1 && "$vxlan_vni" -le 16777215 ]] || die "TRUSTIX_CROSS_HOST_VXLAN_VNI must be in 1..16777215"
  [[ "$vxlan_port" -ge 1 && "$vxlan_port" -le 65535 ]] || die "TRUSTIX_CROSS_HOST_VXLAN_PORT must be in 1..65535"
  [[ "$cleanup_timeout" -ge 1 ]] || die "TRUSTIX_CROSS_HOST_CLEANUP_TIMEOUT must be >= 1"
  [[ "$daemon_restart_sec" -ge 1 ]] || die "TRUSTIX_CROSS_HOST_DAEMON_RESTART_SEC must be >= 1"
  resolve_data_ports
  case "$data_a_port" in *[!0-9]*|"") die "TRUSTIX_CROSS_HOST_DATA_A_PORT must be an integer" ;; esac
  case "$data_b_port" in *[!0-9]*|"") die "TRUSTIX_CROSS_HOST_DATA_B_PORT must be an integer" ;; esac
  validate_multi_endpoint_data_ports
  case "$iperf_mode" in bidir|forward|reverse) ;; *) die "TRUSTIX_CROSS_HOST_IPERF_MODE must be bidir, forward, or reverse" ;; esac
  case "$iperf_directions" in both|a2b|b2a|a-to-b|b-to-a) ;; *) die "TRUSTIX_CROSS_HOST_IPERF_DIRECTIONS must be both, a2b, or b2a" ;; esac
  need_cmd python3
  nonnegative_decimal "$mixed_udp_min_gbps" || die "TRUSTIX_CROSS_HOST_MIXED_UDP_MIN_GBPS/TRUSTIX_CROSS_HOST_MIXED_MIN_GBPS must be a non-negative number"
  nonnegative_decimal "$mixed_tix_tcp_min_gbps" || die "TRUSTIX_CROSS_HOST_MIXED_TIX_TCP_MIN_GBPS/TRUSTIX_CROSS_HOST_MIXED_MIN_GBPS must be a non-negative number"
  if case_uses_pinned_mixed_routes && [[ "$iperf_mode" != "forward" ]]; then
    die "pinned mixed routes require TRUSTIX_CROSS_HOST_IPERF_MODE=forward so each carrier uses its matching source and destination prefix"
  fi
  if case_uses_pinned_mixed_routes &&
    { ! decimal_is_zero "$mixed_udp_min_gbps" || ! decimal_is_zero "$mixed_tix_tcp_min_gbps"; }; then
    need_cmd python3
  fi
  if [[ "$require_inner_gso_latched_fallback" == "1" ]]; then
    need_cmd python3
  fi
  if [[ -n "$endpoint_transport_override" ]]; then
    supported_case_transport "$endpoint_transport_override" || die "TRUSTIX_CROSS_HOST_ENDPOINT_TRANSPORT is unsupported: ${endpoint_transport_override}"
  fi
  if [[ -n "$case_transport_override" ]]; then
    if ! case_is_multi_endpoint || [[ "$(normalize_case_transport_token "$case_transport_override")" != "mixed" ]]; then
      supported_case_transport "$case_transport_override" || die "TRUSTIX_CROSS_HOST_TRANSPORT is unsupported: ${case_transport_override}"
    fi
  fi
  case "$(case_encryption)" in secure|plaintext) ;; *) die "TRUSTIX_CROSS_HOST_ENCRYPTION/case encryption must be secure or plaintext" ;; esac
  case "$(case_transport_profile)" in stable|performance|latency) ;; *) die "TRUSTIX_CROSS_HOST_PROFILE/case profile must be stable, performance, or latency" ;; esac
  case "$(case_transport_datapath)" in userspace|tc_xdp|kernel_module|auto) ;; *) die "TRUSTIX_CROSS_HOST_TRANSPORT_DATAPATH/case datapath must be userspace, tc_xdp, kernel_module, or auto" ;; esac
  case "$(case_crypto_placement)" in userspace|kernel|auto) ;; *) die "TRUSTIX_CROSS_HOST_CRYPTO_PLACEMENT/case crypto placement must be userspace, kernel, or auto" ;; esac
  case "$session_pool_strategy" in flow|five_tuple|5tuple|packet|round_robin) ;; *) die "TRUSTIX_CROSS_HOST_SESSION_POOL_STRATEGY must be flow, five_tuple, 5tuple, packet, or round_robin" ;; esac
  case "$session_pool_warmup" in true|false|1|0|yes|no|on|off|enabled|disabled) ;; *) die "TRUSTIX_CROSS_HOST_SESSION_POOL_WARMUP must be boolean" ;; esac
  case "$session_pool_heartbeat_mode" in auto|enabled|on|disabled|off) ;; *) die "TRUSTIX_CROSS_HOST_SESSION_POOL_HEARTBEAT_MODE must be auto, enabled, on, disabled, or off" ;; esac
}

check_node_prereqs() {
  local node="$1"
  local trustixd trustixctl netem_required=0 tcp_buffer_required=0
  trustixd="$(node_bin "$node" trustixd)"
  trustixctl="$(node_bin "$node" trustixctl)"
  netem_enabled && netem_required=1
  [[ "$iperf_tcp_buffer_bytes" -gt 0 ]] && tcp_buffer_required=1
  run_node "$node" "set -Eeuo pipefail
missing=0
required_commands='ip iperf3 curl'
if [ ${netem_required} = 1 ]; then
  required_commands=\"\${required_commands} tc\"
fi
if [ ${netem_required} = 1 ] && [ $(remote_quote "$netem_placement") = ingress ]; then
  required_commands=\"\${required_commands} ethtool modprobe rmmod\"
fi
if [ ${tcp_buffer_required} = 1 ]; then
  required_commands=\"\${required_commands} sysctl\"
fi
if [ $(remote_quote "$daemon_supervisor") = systemd ]; then
  required_commands=\"\${required_commands} systemctl systemd-run\"
fi
for cmd in \$required_commands; do
  if ! command -v \"\$cmd\" >/dev/null 2>&1; then
    printf '%s\n' \"missing required command on node ${node}: \$cmd\" >&2
    missing=1
  fi
done
if [[ ! -x $(remote_quote "$trustixd") ]]; then
  printf '%s\n' \"missing required executable on node ${node}: trustixd ${trustixd}\" >&2
  missing=1
fi
if [[ ! -x $(remote_quote "$trustixctl") ]]; then
  printf '%s\n' \"missing required executable on node ${node}: trustixctl ${trustixctl}\" >&2
  missing=1
fi
[[ \"\$missing\" -eq 0 ]]
"
}

configure_iperf_tcp_buffer_node() {
  local node="$1"
  local dir host_ns
  dir="$(remote_dir "$node")"
  host_ns="$(node_value "$node" "$host_ns_a" "$host_ns_b")"
  run_node "$node" "set -Eeuo pipefail
dir=$(remote_quote "$dir")
host_ns=$(remote_quote "$host_ns")
requested=$(remote_quote "$iperf_tcp_buffer_bytes")
out=\"\${dir}/iperf-tcp-buffer-state.txt\"
{
  printf 'format=trustix-cross-host-iperf-tcp-buffer-state-v1\\n'
  printf 'requested_bytes=%s\\n' \"\$requested\"
  printf 'scope=temporary-host-network-namespace\\n'
  printf 'host_namespace=%s\\n' \"\$host_ns\"
  if [ \"\$requested\" -eq 0 ]; then
    printf 'enabled=0\\nstatus=unchanged\\n'
    exit 0
  fi

  printf 'enabled=1\\n'
  ip_cmd=\$(command -v ip)
  sysctl_cmd=\$(command -v sysctl)
  read_ns_sysctl() {
    \"\$ip_cmd\" netns exec \"\$host_ns\" \"\$sysctl_cmd\" -n \"\$1\"
  }
  write_ns_sysctl() {
    \"\$ip_cmd\" netns exec \"\$host_ns\" \"\$sysctl_cmd\" -q -w \"\$1=\$2\"
  }

  before_core_rmem=\$(read_ns_sysctl net.core.rmem_max)
  before_core_wmem=\$(read_ns_sysctl net.core.wmem_max)
  before_tcp_rmem=\$(read_ns_sysctl net.ipv4.tcp_rmem)
  before_tcp_wmem=\$(read_ns_sysctl net.ipv4.tcp_wmem)
  printf 'before_net_core_rmem_max=%s\\n' \"\$before_core_rmem\"
  printf 'before_net_core_wmem_max=%s\\n' \"\$before_core_wmem\"
  printf 'before_net_ipv4_tcp_rmem=%s\\n' \"\$before_tcp_rmem\"
  printf 'before_net_ipv4_tcp_wmem=%s\\n' \"\$before_tcp_wmem\"

  set -- \$before_tcp_rmem
  [ \"\$#\" -eq 3 ]
  tcp_rmem_min=\$1
  tcp_rmem_default=\$2
  set -- \$before_tcp_wmem
  [ \"\$#\" -eq 3 ]
  tcp_wmem_min=\$1
  tcp_wmem_default=\$2
  [ \"\$requested\" -ge \"\$tcp_rmem_default\" ]
  [ \"\$requested\" -ge \"\$tcp_wmem_default\" ]

  write_ns_sysctl net.ipv4.tcp_rmem \"\$tcp_rmem_min \$tcp_rmem_default \$requested\"
  write_ns_sysctl net.ipv4.tcp_wmem \"\$tcp_wmem_min \$tcp_wmem_default \$requested\"

  actual_core_rmem=\$(read_ns_sysctl net.core.rmem_max)
  actual_core_wmem=\$(read_ns_sysctl net.core.wmem_max)
  actual_tcp_rmem=\$(read_ns_sysctl net.ipv4.tcp_rmem)
  actual_tcp_wmem=\$(read_ns_sysctl net.ipv4.tcp_wmem)
  printf 'actual_net_core_rmem_max=%s\\n' \"\$actual_core_rmem\"
  printf 'actual_net_core_wmem_max=%s\\n' \"\$actual_core_wmem\"
  printf 'actual_net_ipv4_tcp_rmem=%s\\n' \"\$actual_tcp_rmem\"
  printf 'actual_net_ipv4_tcp_wmem=%s\\n' \"\$actual_tcp_wmem\"
  [ \"\$actual_core_rmem\" = \"\$before_core_rmem\" ]
  [ \"\$actual_core_wmem\" = \"\$before_core_wmem\" ]
  set -- \$actual_tcp_rmem
  [ \"\$#\" -eq 3 ] && [ \"\$3\" = \"\$requested\" ]
  set -- \$actual_tcp_wmem
  [ \"\$#\" -eq 3 ] && [ \"\$3\" = \"\$requested\" ]
  printf 'status=applied\\n'
} >\"\$out\"
"
}

detect_underlay_ip() {
  local node="$1"
  local peer_ip="$2"
  run_node "$node" "set -Eeuo pipefail
ip -4 route get $(remote_quote "$peer_ip") | awk '
  {
    for (i = 1; i <= NF; i++) {
      if (\$i == \"src\" && i < NF) {
        print \$(i + 1)
        exit
      }
    }
  }
'
"
}

detect_underlay_if() {
  local node="$1"
  local peer_ip="$2"
  run_node "$node" "set -Eeuo pipefail
ip -4 route get $(remote_quote "$peer_ip") | awk '
  {
    for (i = 1; i <= NF; i++) {
      if (\$i == \"dev\" && i < NF) {
        print \$(i + 1)
        exit
      }
    }
  }
'
"
}

resolve_underlay() {
  if [[ -z "$underlay_a_ip" || -z "$underlay_b_ip" ]]; then
    die "set TRUSTIX_CROSS_HOST_A_UNDERLAY_IP and TRUSTIX_CROSS_HOST_B_UNDERLAY_IP"
  fi
  local route_a_if route_b_if route_a_src route_b_src
  route_a_if="$(detect_underlay_if a "$underlay_b_ip" | tail -n 1 || true)"
  route_b_if="$(detect_underlay_if b "$underlay_a_ip" | tail -n 1 || true)"
  if [[ -z "$underlay_a_if" ]]; then
    underlay_a_if="$route_a_if"
  elif [[ -n "$route_a_if" && "$underlay_a_if" != "$route_a_if" ]]; then
    route_a_src="$(detect_underlay_ip a "$underlay_b_ip" | tail -n 1 || true)"
    if [[ "$route_a_src" == "$underlay_a_ip" ]]; then
      log "WARNING: node A configured underlay interface ${underlay_a_if} does not match route to peer ${underlay_b_ip} dev ${route_a_if}; using route interface"
      underlay_a_if="$route_a_if"
    else
      die "node A configured underlay interface ${underlay_a_if} does not match route to peer ${underlay_b_ip} dev ${route_a_if} src ${route_a_src:-unknown}; configured underlay IP is ${underlay_a_ip}"
    fi
  fi
  if [[ -z "$underlay_b_if" ]]; then
    underlay_b_if="$route_b_if"
  elif [[ -n "$route_b_if" && "$underlay_b_if" != "$route_b_if" ]]; then
    route_b_src="$(detect_underlay_ip b "$underlay_a_ip" | tail -n 1 || true)"
    if [[ "$route_b_src" == "$underlay_b_ip" ]]; then
      log "WARNING: node B configured underlay interface ${underlay_b_if} does not match route to peer ${underlay_a_ip} dev ${route_b_if}; using route interface"
      underlay_b_if="$route_b_if"
    else
      die "node B configured underlay interface ${underlay_b_if} does not match route to peer ${underlay_a_ip} dev ${route_b_if} src ${route_b_src:-unknown}; configured underlay IP is ${underlay_b_ip}"
    fi
  fi
  [[ -n "$underlay_a_if" ]] || die "could not detect node A underlay interface"
  [[ -n "$underlay_b_if" ]] || die "could not detect node B underlay interface"
}

apply_netem_egress_node() {
  local node="$1"
  local dir underlay_if qdisc_args
  netem_enabled || return 0
  netem_targets_node "$node" || return 0
  dir="$(remote_dir "$node")"
  underlay_if="$(node_value "$node" "$underlay_a_if" "$underlay_b_if")"
  qdisc_args="$(netem_qdisc_args)"
  run_node "$node" "set -Eeuo pipefail
tc_cmd=\$(command -v tc)
dir=$(remote_quote "$dir")
underlay_if=$(remote_quote "$underlay_if")
mkdir -p \"\$dir\"
\"\$tc_cmd\" -s qdisc show dev \"\$underlay_if\" >\"\${dir}/netem-qdisc-before.txt\"
\"\$tc_cmd\" qdisc replace dev \"\$underlay_if\" root handle ${netem_handle} netem ${qdisc_args}
printf 'handle=%s interface=%s\n' $(remote_quote "$netem_handle") \"\$underlay_if\" >\"\${dir}/netem-owned.txt\"
\"\$tc_cmd\" -s qdisc show dev \"\$underlay_if\" >\"\${dir}/netem-qdisc-applied.txt\"
grep -Eq '^qdisc netem ${netem_handle}' \"\${dir}/netem-qdisc-applied.txt\"
"
}

apply_netem() {
  netem_enabled || return 0
  log "applying netem placement=${netem_placement} targets=${netem_targets} args=$(netem_qdisc_args)"
  apply_netem_node a
  apply_netem_node b
}

collect_netem_egress_state_node() {
  local node="$1"
  local label="${2:-}"
  local dir underlay_if suffix
  netem_enabled || return 0
  netem_targets_node "$node" || return 0
  dir="$(remote_dir "$node")"
  underlay_if="$(node_value "$node" "$underlay_a_if" "$underlay_b_if")"
  suffix="$(netem_snapshot_suffix "$label")" || return
  run_node "$node" "set +e
tc_cmd=\$(command -v tc 2>/dev/null || true)
[ -n \"\$tc_cmd\" ] || exit 0
mkdir -p $(remote_quote "$dir")
\"\$tc_cmd\" -s qdisc show dev $(remote_quote "$underlay_if") >$(remote_quote "${dir}/netem-qdisc${suffix}.txt") 2>&1
exit 0
"
}

clear_netem_egress_node() {
  local node="$1"
  local dir underlay_if
  netem_enabled || return 0
  netem_targets_node "$node" || return 0
  dir="$(remote_dir "$node")"
  underlay_if="$(node_value "$node" "$underlay_a_if" "$underlay_b_if")"
  [[ -n "$underlay_if" ]] || return 0
  run_node "$node" "set +e
tc_cmd=\$(command -v tc 2>/dev/null || true)
[ -n \"\$tc_cmd\" ] || exit 1
dir=$(remote_quote "$dir")
underlay_if=$(remote_quote "$underlay_if")
mkdir -p \"\$dir\"
current=\"\${dir}/.netem-qdisc-before-clear.tmp\"
\"\$tc_cmd\" -s qdisc show dev \"\$underlay_if\" >\"\$current\" 2>&1
owned=0
[ -f \"\${dir}/netem-owned.txt\" ] && owned=1
grep -Eq '^qdisc netem ${netem_handle}' \"\$current\" && owned=1
rc=0
if [ \"\$owned\" -eq 1 ]; then
  mv \"\$current\" \"\${dir}/netem-qdisc-before-clear.txt\"
  if grep -Eq '^qdisc netem ${netem_handle}' \"\${dir}/netem-qdisc-before-clear.txt\"; then
    \"\$tc_cmd\" qdisc del dev \"\$underlay_if\" root || rc=1
  fi
else
  rm -f \"\$current\"
fi
rm -f \"\${dir}/netem-owned.txt\"
\"\$tc_cmd\" -s qdisc show dev \"\$underlay_if\" >\"\${dir}/netem-qdisc-after-clear.txt\" 2>&1 || rc=1
exit \"\$rc\"
"
}

netem_ifb_name() {
  printf 'tix-ifb-%s\n' "$1"
}

netem_snapshot_suffix() {
  local label="${1:-}"
  if [[ -z "$label" ]]; then
    printf '%s\n' '-current'
    return 0
  fi
  [[ "$label" =~ ^[A-Za-z0-9_.-]+$ ]] || return 1
  printf -- '-%s\n' "$label"
}

apply_netem_ingress_node() {
  local node="$1"
  local dir underlay_if qdisc_args ifb_if corrupt_enabled
  netem_enabled || return 0
  netem_targets_node "$node" || return 0
  dir="$(remote_dir "$node")"
  underlay_if="$(node_value "$node" "$underlay_a_if" "$underlay_b_if")"
  qdisc_args="$(netem_qdisc_args)"
  ifb_if="$(netem_ifb_name "$node")"
  corrupt_enabled=0
  decimal_is_zero "$netem_corrupt_pct" || corrupt_enabled=1
  run_node "$node" "set -Eeuo pipefail
tc_cmd=\$(command -v tc)
ip_cmd=\$(command -v ip)
ethtool_cmd=\$(command -v ethtool)
dir=$(remote_quote "$dir")
underlay_if=$(remote_quote "$underlay_if")
ifb_if=$(remote_quote "$ifb_if")
mkdir -p \"\$dir\"
\"\$tc_cmd\" -s qdisc show dev \"\$underlay_if\" >\"\${dir}/netem-qdisc-before.txt\"
\"\$ethtool_cmd\" -k \"\$underlay_if\" >\"\${dir}/netem-offload-before.txt\"
gro=\$(awk '\$1 == \"generic-receive-offload:\" { print \$2; exit }' \"\${dir}/netem-offload-before.txt\")
rx_gro_hw=\$(awk '\$1 == \"rx-gro-hw:\" { print \$2; exit }' \"\${dir}/netem-offload-before.txt\")
lro=\$(awk '\$1 == \"large-receive-offload:\" { print \$2; exit }' \"\${dir}/netem-offload-before.txt\")
rx_checksum=\$(awk '\$1 == \"rx-checksumming:\" { print \$2; exit }' \"\${dir}/netem-offload-before.txt\")
rx_checksum_fixed=\$(awk '\$1 == \"rx-checksumming:\" { for (i = 3; i <= NF; i++) if (\$i == \"[fixed]\") { print 1; exit }; print 0; exit }' \"\${dir}/netem-offload-before.txt\")
ifb_loaded=0
grep -q '^ifb ' /proc/modules 2>/dev/null && ifb_loaded=1
case \"\$gro\" in on|off) ;; *) echo 'cannot read generic-receive-offload state' >&2; exit 1 ;; esac
case \"\$rx_gro_hw\" in ''|on|off) ;; *) echo 'cannot read rx-gro-hw state' >&2; exit 1 ;; esac
case \"\$lro\" in ''|on|off) ;; *) echo 'cannot read large-receive-offload state' >&2; exit 1 ;; esac
case \"\$rx_checksum\" in on|off) ;; *) echo 'cannot read rx-checksumming state' >&2; exit 1 ;; esac
case \"\$rx_checksum_fixed\" in 0|1) ;; *) echo 'cannot read rx-checksumming mutability' >&2; exit 1 ;; esac
if \"\$ip_cmd\" link show dev \"\$ifb_if\" >/dev/null 2>&1; then
  echo \"refusing to replace existing IFB \$ifb_if\" >&2
  exit 1
fi
if \"\$tc_cmd\" qdisc show dev \"\$underlay_if\" | grep -Eq '^qdisc (ingress|clsact) ffff:'; then
  echo \"refusing to replace existing ingress qdisc on \$underlay_if\" >&2
  exit 1
fi
rx_checksum_changed=0
if [ $(remote_quote "$corrupt_enabled") = 1 ] && [ \"\$rx_checksum\" = on ]; then
  if [ \"\$rx_checksum_fixed\" = 1 ]; then
    echo \"ingress netem corruption cannot disable fixed RX checksum offload on \$underlay_if; use packet loss to model detected wire corruption\" >&2
    exit 1
  fi
  rx_checksum_changed=1
fi
printf 'placement=ingress\nhandle=%s\ninterface=%s\nifb=%s\ndisable_gro=%s\ngro=%s\nrx_gro_hw=%s\nlro=%s\ncorrupt_enabled=%s\nrx_checksum=%s\nrx_checksum_fixed=%s\nrx_checksum_changed=%s\nifb_loaded=%s\n' $(remote_quote "$netem_handle") \"\$underlay_if\" \"\$ifb_if\" $(remote_quote "$netem_disable_gro") \"\$gro\" \"\$rx_gro_hw\" \"\$lro\" $(remote_quote "$corrupt_enabled") \"\$rx_checksum\" \"\$rx_checksum_fixed\" \"\$rx_checksum_changed\" \"\$ifb_loaded\" >\"\${dir}/netem-owned.txt\"
if [ \"\$rx_checksum_changed\" = 1 ]; then
  if ! \"\$ethtool_cmd\" -K \"\$underlay_if\" rx off; then
    echo \"ingress netem corruption failed to disable RX checksum offload on \$underlay_if\" >&2
    exit 1
  fi
  \"\$ethtool_cmd\" -k \"\$underlay_if\" >\"\${dir}/netem-offload-rx-disabled.txt\"
  rx_checksum_after=\$(awk '\$1 == \"rx-checksumming:\" { print \$2; exit }' \"\${dir}/netem-offload-rx-disabled.txt\")
  if [ \"\$rx_checksum_after\" != off ]; then
    echo \"ingress netem corruption could not verify disabled RX checksum offload on \$underlay_if\" >&2
    exit 1
  fi
fi
modprobe ifb numifbs=0
\"\$ip_cmd\" link add name \"\$ifb_if\" type ifb
\"\$ip_cmd\" link set dev \"\$ifb_if\" up
if [ $(remote_quote "$netem_disable_gro") = 1 ]; then
  if [ \"\$gro\" = on ]; then \"\$ethtool_cmd\" -K \"\$underlay_if\" gro off; fi
  if [ \"\$rx_gro_hw\" = on ]; then \"\$ethtool_cmd\" -K \"\$underlay_if\" rx-gro-hw off; fi
  if [ \"\$lro\" = on ]; then \"\$ethtool_cmd\" -K \"\$underlay_if\" lro off; fi
fi
\"\$tc_cmd\" qdisc add dev \"\$underlay_if\" handle ffff: ingress
\"\$tc_cmd\" filter add dev \"\$underlay_if\" parent ffff: protocol all pref 49152 u32 match u32 0 0 action mirred egress redirect dev \"\$ifb_if\"
\"\$tc_cmd\" qdisc replace dev \"\$ifb_if\" root handle ${netem_handle} netem ${qdisc_args}
\"\$tc_cmd\" -s qdisc show dev \"\$ifb_if\" >\"\${dir}/netem-qdisc-applied.txt\"
\"\$tc_cmd\" -s filter show dev \"\$underlay_if\" parent ffff: >\"\${dir}/netem-ingress-filter-applied.txt\"
\"\$ethtool_cmd\" -k \"\$underlay_if\" >\"\${dir}/netem-offload-applied.txt\"
grep -Eq '^qdisc netem ${netem_handle}' \"\${dir}/netem-qdisc-applied.txt\"
"
}

apply_netem_node() {
  case "$netem_placement" in
    egress) apply_netem_egress_node "$1" ;;
    ingress) apply_netem_ingress_node "$1" ;;
  esac
}

collect_netem_ingress_state_node() {
  local node="$1"
  local label="${2:-}"
  local dir underlay_if ifb_if suffix
  netem_enabled || return 0
  netem_targets_node "$node" || return 0
  dir="$(remote_dir "$node")"
  underlay_if="$(node_value "$node" "$underlay_a_if" "$underlay_b_if")"
  ifb_if="$(netem_ifb_name "$node")"
  suffix="$(netem_snapshot_suffix "$label")" || return
  run_node "$node" "set +e
tc_cmd=\$(command -v tc 2>/dev/null || true)
ethtool_cmd=\$(command -v ethtool 2>/dev/null || true)
[ -n \"\$tc_cmd\" ] || exit 0
mkdir -p $(remote_quote "$dir")
\"\$tc_cmd\" -s qdisc show dev $(remote_quote "$ifb_if") >$(remote_quote "${dir}/netem-qdisc${suffix}.txt") 2>&1
\"\$tc_cmd\" -s filter show dev $(remote_quote "$underlay_if") parent ffff: >$(remote_quote "${dir}/netem-ingress-filter${suffix}.txt") 2>&1
if [ -n \"\$ethtool_cmd\" ]; then
  \"\$ethtool_cmd\" -k $(remote_quote "$underlay_if") >$(remote_quote "${dir}/netem-offload${suffix}.txt") 2>&1
fi
exit 0
"
}

collect_netem_state_node() {
  case "$netem_placement" in
    egress) collect_netem_egress_state_node "$1" "${2:-}" ;;
    ingress) collect_netem_ingress_state_node "$1" "${2:-}" ;;
  esac
}

clear_netem_ingress_node() {
  local node="$1"
  local dir underlay_if ifb_if
  netem_enabled || return 0
  netem_targets_node "$node" || return 0
  dir="$(remote_dir "$node")"
  underlay_if="$(node_value "$node" "$underlay_a_if" "$underlay_b_if")"
  ifb_if="$(netem_ifb_name "$node")"
  [[ -n "$underlay_if" ]] || return 0
  run_node "$node" "set +e
tc_cmd=\$(command -v tc 2>/dev/null || true)
ip_cmd=\$(command -v ip 2>/dev/null || true)
ethtool_cmd=\$(command -v ethtool 2>/dev/null || true)
dir=$(remote_quote "$dir")
underlay_if=$(remote_quote "$underlay_if")
ifb_if=$(remote_quote "$ifb_if")
mkdir -p \"\$dir\"
marker=\"\${dir}/netem-owned.txt\"
rc=0
if [ -f \"\$marker\" ] && grep -Fq 'placement=ingress' \"\$marker\"; then
  gro=\$(sed -n 's/^gro=//p' \"\$marker\" | head -n 1)
  rx_gro_hw=\$(sed -n 's/^rx_gro_hw=//p' \"\$marker\" | head -n 1)
  lro=\$(sed -n 's/^lro=//p' \"\$marker\" | head -n 1)
  rx_checksum=\$(sed -n 's/^rx_checksum=//p' \"\$marker\" | head -n 1)
  rx_checksum_changed=\$(sed -n 's/^rx_checksum_changed=//p' \"\$marker\" | head -n 1)
  ifb_loaded=\$(sed -n 's/^ifb_loaded=//p' \"\$marker\" | head -n 1)
  disable_gro=\$(sed -n 's/^disable_gro=//p' \"\$marker\" | head -n 1)
  if [ -n \"\$tc_cmd\" ]; then
    \"\$tc_cmd\" -s qdisc show dev \"\$ifb_if\" >\"\${dir}/netem-qdisc-before-clear.txt\" 2>&1 || rc=1
    \"\$tc_cmd\" -s filter show dev \"\$underlay_if\" parent ffff: >\"\${dir}/netem-ingress-filter-before-clear.txt\" 2>&1 || rc=1
  fi
  if [ -n \"\$tc_cmd\" ]; then \"\$tc_cmd\" qdisc del dev \"\$underlay_if\" ingress >/dev/null 2>&1 || true; fi
  if [ -n \"\$ip_cmd\" ]; then \"\$ip_cmd\" link del dev \"\$ifb_if\" >/dev/null 2>&1 || true; fi
  case \"\$ifb_loaded\" in
    0) rmmod ifb >/dev/null 2>&1 || rc=1 ;;
    1) ;;
    *) rc=1 ;;
  esac
  if [ \"\$rx_checksum_changed\" = 1 ] && [ -n \"\$ethtool_cmd\" ]; then
    case \"\$rx_checksum\" in on) \"\$ethtool_cmd\" -K \"\$underlay_if\" rx on || rc=1 ;; *) rc=1 ;; esac
  elif [ \"\$rx_checksum_changed\" = 1 ]; then
    rc=1
  elif [ \"\$rx_checksum_changed\" != 0 ]; then
    rc=1
  fi
  if [ \"\$disable_gro\" = 1 ] && [ -n \"\$ethtool_cmd\" ]; then
    case \"\$gro\" in on) \"\$ethtool_cmd\" -K \"\$underlay_if\" gro on || rc=1 ;; off) ;; *) rc=1 ;; esac
    case \"\$rx_gro_hw\" in on) \"\$ethtool_cmd\" -K \"\$underlay_if\" rx-gro-hw on || rc=1 ;; off|'') ;; *) rc=1 ;; esac
    case \"\$lro\" in on) \"\$ethtool_cmd\" -K \"\$underlay_if\" lro on || rc=1 ;; off|'') ;; *) rc=1 ;; esac
  elif [ \"\$disable_gro\" = 1 ]; then
    rc=1
  elif [ \"\$disable_gro\" != 0 ]; then
    rc=1
  fi
fi
rm -f \"\$marker\"
if [ -n \"\$tc_cmd\" ]; then
  \"\$tc_cmd\" -s qdisc show dev \"\$underlay_if\" >\"\${dir}/netem-qdisc-after-clear.txt\" 2>&1 || rc=1
fi
if [ -n \"\$ethtool_cmd\" ]; then
  \"\$ethtool_cmd\" -k \"\$underlay_if\" >\"\${dir}/netem-offload-after-clear.txt\" 2>&1 || rc=1
fi
exit \"\$rc\"
"
}

clear_netem_node() {
  case "$netem_placement" in
    egress) clear_netem_egress_node "$1" ;;
    ingress) clear_netem_ingress_node "$1" ;;
  esac
}

netem_qdisc_counters() {
  local node="$1"
  local label="$2"
  local dir suffix values packets drops extra
  dir="$(remote_dir "$node")"
  suffix="$(netem_snapshot_suffix "$label")" || return
  values="$(run_node "$node" "set -Eeuo pipefail
file=$(remote_quote "${dir}/netem-qdisc${suffix}.txt")
grep -Eq '^qdisc netem ${netem_handle}' \"\$file\"
awk '/^ Sent / { gsub(/,/, \"\", \$7); print \$4, \$7; found=1; exit } END { if (!found) exit 1 }' \"\$file\"
")" || return
  read -r packets drops extra <<<"$values"
  [[ "$packets" =~ ^[0-9]+$ && "$drops" =~ ^[0-9]+$ && -z "$extra" ]] || return 1
  printf '%s %s\n' "$packets" "$drops"
}

record_netem_evidence() {
  local label="$1"
  local output tmp node targeted counters packets drops extra status=pass
  [[ "$label" =~ ^[A-Za-z0-9_.-]+$ ]] || return 1
  output="${workdir}/netem-evidence-${label}.txt"
  tmp="${output}.tmp"
  {
    printf 'format=trustix-cross-host-netem-evidence-v1\n'
    printf 'label=%s\n' "$label"
    printf 'loss_pct=%s\n' "$netem_loss_pct"
    printf 'delay_ms=%s\n' "$netem_delay_ms"
    printf 'jitter_ms=%s\n' "$netem_jitter_ms"
    printf 'rate_mbit=%s\n' "$netem_rate_mbit"
  } >"$tmp"
  for node in a b; do
    targeted=0
    netem_targets_node "$node" && targeted=1
    printf '%s_targeted=%s\n' "$node" "$targeted" >>"$tmp"
    if [[ "$targeted" != "1" ]]; then
      printf '%s_packets=0\n%s_drops=0\n' "$node" "$node" >>"$tmp"
      continue
    fi
    counters="$(netem_qdisc_counters "$node" "$label")" || counters=""
    read -r packets drops extra <<<"$counters"
    if [[ ! "$packets" =~ ^[0-9]+$ || ! "$drops" =~ ^[0-9]+$ || -n "$extra" ]]; then
      packets=0
      drops=0
      status=fail
    fi
    printf '%s_packets=%s\n%s_drops=%s\n' "$node" "$packets" "$node" "$drops" >>"$tmp"
    [[ "$packets" -gt 0 ]] || status=fail
    if ! decimal_is_zero "$netem_loss_pct"; then
      [[ "$drops" -gt 0 ]] || status=fail
    fi
  done
  printf 'status=%s\n' "$status" >>"$tmp"
  mv "$tmp" "$output"
  [[ "$status" == "pass" ]]
}

transport_snapshot_counter() {
  local node="$1"
  local label="$2"
  local name="$3"
  local dir value
  dir="$(remote_dir "$node")"
  value="$(run_node "$node" "cat $(remote_quote "${dir}/transports-${label}.json")" | python3 -c '
import json
import sys

name = sys.argv[1]
value = (json.load(sys.stdin).get("counters") or {}).get(name)
if isinstance(value, bool) or not isinstance(value, int) or value < 0:
    raise SystemExit(1)
print(value)
' "$name")" || return
  [[ "$value" =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "$value"
}

transport_snapshot_extra_sum() {
  local node="$1"
  local label="$2"
  local name="$3"
  local dir value
  dir="$(remote_dir "$node")"
  value="$(run_node "$node" "cat $(remote_quote "${dir}/transports-${label}.json")" | python3 -c '
import json
import sys

name = sys.argv[1]
total = 0

def visit(value):
    global total
    if isinstance(value, dict):
        extra = value.get("extra")
        if isinstance(extra, dict):
            counter = extra.get(name)
            if isinstance(counter, int) and not isinstance(counter, bool) and counter >= 0:
                total += counter
        for child in value.values():
            visit(child)
    elif isinstance(value, list):
        for child in value:
            visit(child)

visit(json.load(sys.stdin))
print(total)
' "$name")" || return
  [[ "$value" =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "$value"
}

inner_gso_module_param() {
  local node="$1"
  local name="$2"
  run_node "$node" "cat $(remote_quote "/sys/module/trustix_datapath/parameters/${name}")" |
    tr -d '\r\n'
}

inner_gso_module_param_uint() {
  local value
  value="$(inner_gso_module_param "$1" "$2")" || return
  [[ "$value" =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "$value"
}

inner_gso_module_param_sum() {
  local name="$1"
  local a_value b_value
  a_value="$(inner_gso_module_param_uint a "$name")" || return
  b_value="$(inner_gso_module_param_uint b "$name")" || return
  printf '%s\n' "$((a_value + b_value))"
}

inner_gso_runtime_ready_state_on_both_nodes() {
  local expected="$1"
  local a_ready b_ready
  a_ready="$(inner_gso_module_param a inner_gso_runtime_ready)" || return
  b_ready="$(inner_gso_module_param b inner_gso_runtime_ready)" || return
  [[ "$a_ready" == "$expected" && "$b_ready" == "$expected" ]]
}

inner_gso_auto_recover_disabled_on_both_nodes() {
  local a_auto_recover b_auto_recover
  a_auto_recover="$(inner_gso_module_param a inner_gso_auto_recover)" || return
  b_auto_recover="$(inner_gso_module_param b inner_gso_auto_recover)" || return
  [[ "$a_auto_recover" == "N" && "$b_auto_recover" == "N" ]]
}

collect_inner_gso_transition_snapshot() {
  local label="$1"
  collect_transport_snapshot "netem-${label}" || true
  collect_module_parameters a "netem-${label}" || true
  collect_module_parameters b "netem-${label}" || true
  collect_netem_state_node a "$label" || true
  collect_netem_state_node b "$label" || true
}

run_netem_transition() {
  local contract="${workdir}/inner-gso-latched-fallback-contract.txt"
  local before_inner=0 before_outer=0 before_plaintext=0 before_trips=0
  local clear_inner=0 clear_outer=0 clear_plaintext=0 clear_recoveries=0
  local current_inner=0 current_outer=0 current_plaintext=0 current_recoveries=0
  local deadline=0 latched=1
  local a_trips_before_clear=0 b_trips_before_clear=0
  local a_recoveries_before_clear=0 b_recoveries_before_clear=0
  local a_recoveries_after_clear=0 b_recoveries_after_clear=0
  local a_recoveries_after_observe=0 b_recoveries_after_observe=0
  local a_ready_before_clear="" b_ready_before_clear=""
  local a_ready_after_clear="" b_ready_after_clear=""
  local a_ready_after_observe="" b_ready_after_observe=""
  local a_auto_recover_before_clear="" b_auto_recover_before_clear=""
  local a_auto_recover_after_clear="" b_auto_recover_after_clear=""
  local a_auto_recover_after_observe="" b_auto_recover_after_observe=""
  local a_dials_before_apply=0 b_dials_before_apply=0
  local a_dials_before_clear=0 b_dials_before_clear=0
  local a_dials_after_clear=0 b_dials_after_clear=0
  local a_dials_after_observe=0 b_dials_after_observe=0
  local a_withdrawals=0 b_withdrawals=0 a_withdrawal_acks=0 b_withdrawal_acks=0
  local a_withdrawal_ack_timeouts=0 b_withdrawal_ack_timeouts=0
  local before_ok=1 netem_ok=1 clear_ok=1 after_ok=1

  sleep "$netem_active_seconds"
  collect_inner_gso_transition_snapshot before-clear
  if [[ "$require_inner_gso_latched_fallback" == "1" ]]; then
    before_inner="$(inner_gso_module_param_sum tx_plaintext_inner_gso_packets)" || before_ok=0
    before_outer="$(inner_gso_module_param_sum tx_plaintext_outer_gso_packets)" || before_ok=0
    before_plaintext="$(inner_gso_module_param_sum tx_plaintext_packets)" || before_ok=0
    before_trips="$(inner_gso_module_param_sum inner_gso_circuit_trips)" || before_ok=0
    a_trips_before_clear="$(inner_gso_module_param_uint a inner_gso_circuit_trips)" || before_ok=0
    b_trips_before_clear="$(inner_gso_module_param_uint b inner_gso_circuit_trips)" || before_ok=0
    a_recoveries_before_clear="$(inner_gso_module_param_uint a inner_gso_circuit_recoveries)" || before_ok=0
    b_recoveries_before_clear="$(inner_gso_module_param_uint b inner_gso_circuit_recoveries)" || before_ok=0
    a_ready_before_clear="$(inner_gso_module_param a inner_gso_runtime_ready)" || before_ok=0
    b_ready_before_clear="$(inner_gso_module_param b inner_gso_runtime_ready)" || before_ok=0
    a_auto_recover_before_clear="$(inner_gso_module_param a inner_gso_auto_recover)" || before_ok=0
    b_auto_recover_before_clear="$(inner_gso_module_param b inner_gso_auto_recover)" || before_ok=0
    a_dials_before_apply="$(transport_snapshot_counter a netem-before-apply session_dials)" || before_ok=0
    b_dials_before_apply="$(transport_snapshot_counter b netem-before-apply session_dials)" || before_ok=0
    a_dials_before_clear="$(transport_snapshot_counter a netem-before-clear session_dials)" || before_ok=0
    b_dials_before_clear="$(transport_snapshot_counter b netem-before-clear session_dials)" || before_ok=0
    a_withdrawals="$(transport_snapshot_extra_sum a netem-before-clear tix_tcp_capability_withdrawals)" || before_ok=0
    b_withdrawals="$(transport_snapshot_extra_sum b netem-before-clear tix_tcp_capability_withdrawals)" || before_ok=0
    a_withdrawal_acks="$(transport_snapshot_extra_sum a netem-before-clear tix_tcp_capability_withdrawal_acks)" || before_ok=0
    b_withdrawal_acks="$(transport_snapshot_extra_sum b netem-before-clear tix_tcp_capability_withdrawal_acks)" || before_ok=0
    a_withdrawal_ack_timeouts="$(transport_snapshot_extra_sum a netem-before-clear tix_tcp_capability_withdrawal_ack_timeouts)" || before_ok=0
    b_withdrawal_ack_timeouts="$(transport_snapshot_extra_sum b netem-before-clear tix_tcp_capability_withdrawal_ack_timeouts)" || before_ok=0
    [[ "$before_inner" -gt 0 && "$before_outer" -gt 0 && "$before_plaintext" -gt 0 && "$before_trips" -gt 0 ]] || before_ok=0
    [[ "$a_trips_before_clear" -gt 0 && "$b_trips_before_clear" -gt 0 ]] || before_ok=0
    [[ "$a_recoveries_before_clear" -eq 0 && "$b_recoveries_before_clear" -eq 0 ]] || before_ok=0
    [[ "$a_ready_before_clear" == "N" && "$b_ready_before_clear" == "N" ]] || before_ok=0
    [[ "$a_auto_recover_before_clear" == "N" && "$b_auto_recover_before_clear" == "N" ]] || before_ok=0
    [[ "$a_dials_before_apply" -eq "$a_dials_before_clear" ]] || before_ok=0
    [[ "$b_dials_before_apply" -eq "$b_dials_before_clear" ]] || before_ok=0
    [[ "$a_withdrawals" -gt 0 && "$a_withdrawal_acks" -ge "$a_withdrawals" && "$a_withdrawal_ack_timeouts" -eq 0 ]] || before_ok=0
    [[ "$b_withdrawals" -gt 0 && "$b_withdrawal_acks" -ge "$b_withdrawals" && "$b_withdrawal_ack_timeouts" -eq 0 ]] || before_ok=0
    {
      printf 'format=trustix-inner-gso-latched-fallback-v1\n'
      printf 'netem_active_seconds=%s\n' "$netem_active_seconds"
      printf 'fallback_observe_seconds=%s\n' "$inner_gso_latched_fallback_observe_seconds"
      printf 'inner_gso_packets_before_clear=%s\n' "$before_inner"
      printf 'outer_gso_packets_before_clear=%s\n' "$before_outer"
      printf 'plaintext_packets_before_clear=%s\n' "$before_plaintext"
      printf 'circuit_trips_before_clear=%s\n' "$before_trips"
      printf 'a_circuit_trips_before_clear=%s\n' "$a_trips_before_clear"
      printf 'b_circuit_trips_before_clear=%s\n' "$b_trips_before_clear"
      printf 'a_circuit_recoveries_before_clear=%s\n' "$a_recoveries_before_clear"
      printf 'b_circuit_recoveries_before_clear=%s\n' "$b_recoveries_before_clear"
      printf 'a_runtime_ready_before_clear=%s\n' "$a_ready_before_clear"
      printf 'b_runtime_ready_before_clear=%s\n' "$b_ready_before_clear"
      printf 'a_auto_recover_before_clear=%s\n' "$a_auto_recover_before_clear"
      printf 'b_auto_recover_before_clear=%s\n' "$b_auto_recover_before_clear"
      printf 'a_session_dials_before_apply=%s\n' "$a_dials_before_apply"
      printf 'b_session_dials_before_apply=%s\n' "$b_dials_before_apply"
      printf 'a_session_dials_before_clear=%s\n' "$a_dials_before_clear"
      printf 'b_session_dials_before_clear=%s\n' "$b_dials_before_clear"
      printf 'a_capability_withdrawals_before_clear=%s\n' "$a_withdrawals"
      printf 'b_capability_withdrawals_before_clear=%s\n' "$b_withdrawals"
      printf 'a_capability_withdrawal_acks_before_clear=%s\n' "$a_withdrawal_acks"
      printf 'b_capability_withdrawal_acks_before_clear=%s\n' "$b_withdrawal_acks"
      printf 'a_capability_withdrawal_ack_timeouts_before_clear=%s\n' "$a_withdrawal_ack_timeouts"
      printf 'b_capability_withdrawal_ack_timeouts_before_clear=%s\n' "$b_withdrawal_ack_timeouts"
    } >"$contract"
  fi

  clear_netem_node a
  clear_netem_node b
  record_netem_evidence before-clear || netem_ok=0
  printf 'cleared_at=%s\n' "$(date -Is)" >>"${workdir}/netem-transition.txt"

  if [[ "$require_inner_gso_latched_fallback" != "1" ]]; then
    [[ "$netem_ok" == "1" ]]
    return
  fi
  [[ "$netem_ok" == "1" ]] || before_ok=0
  if [[ "$before_ok" != "1" ]]; then
    printf 'status=fail\nreason=netem, circuit trip, latch, or capability-withdrawal contract was not observed before clear\n' >>"$contract"
    return 1
  fi

  collect_inner_gso_transition_snapshot after-clear
  clear_inner="$(inner_gso_module_param_sum tx_plaintext_inner_gso_packets)" || clear_ok=0
  clear_outer="$(inner_gso_module_param_sum tx_plaintext_outer_gso_packets)" || clear_ok=0
  clear_plaintext="$(inner_gso_module_param_sum tx_plaintext_packets)" || clear_ok=0
  clear_recoveries="$(inner_gso_module_param_sum inner_gso_circuit_recoveries)" || clear_ok=0
  a_recoveries_after_clear="$(inner_gso_module_param_uint a inner_gso_circuit_recoveries)" || clear_ok=0
  b_recoveries_after_clear="$(inner_gso_module_param_uint b inner_gso_circuit_recoveries)" || clear_ok=0
  a_ready_after_clear="$(inner_gso_module_param a inner_gso_runtime_ready)" || clear_ok=0
  b_ready_after_clear="$(inner_gso_module_param b inner_gso_runtime_ready)" || clear_ok=0
  a_auto_recover_after_clear="$(inner_gso_module_param a inner_gso_auto_recover)" || clear_ok=0
  b_auto_recover_after_clear="$(inner_gso_module_param b inner_gso_auto_recover)" || clear_ok=0
  a_dials_after_clear="$(transport_snapshot_counter a netem-after-clear session_dials)" || clear_ok=0
  b_dials_after_clear="$(transport_snapshot_counter b netem-after-clear session_dials)" || clear_ok=0
  [[ "$a_recoveries_after_clear" -eq "$a_recoveries_before_clear" && "$b_recoveries_after_clear" -eq "$b_recoveries_before_clear" ]] || clear_ok=0
  [[ "$a_ready_after_clear" == "N" && "$b_ready_after_clear" == "N" ]] || clear_ok=0
  [[ "$a_auto_recover_after_clear" == "N" && "$b_auto_recover_after_clear" == "N" ]] || clear_ok=0
  [[ "$a_dials_after_clear" -eq "$a_dials_before_clear" && "$b_dials_after_clear" -eq "$b_dials_before_clear" ]] || clear_ok=0
  {
    printf 'inner_gso_packets_after_clear=%s\n' "$clear_inner"
    printf 'outer_gso_packets_after_clear=%s\n' "$clear_outer"
    printf 'plaintext_packets_after_clear=%s\n' "$clear_plaintext"
    printf 'circuit_recoveries_after_clear=%s\n' "$clear_recoveries"
    printf 'a_circuit_recoveries_after_clear=%s\n' "$a_recoveries_after_clear"
    printf 'b_circuit_recoveries_after_clear=%s\n' "$b_recoveries_after_clear"
    printf 'a_runtime_ready_after_clear=%s\n' "$a_ready_after_clear"
    printf 'b_runtime_ready_after_clear=%s\n' "$b_ready_after_clear"
    printf 'a_auto_recover_after_clear=%s\n' "$a_auto_recover_after_clear"
    printf 'b_auto_recover_after_clear=%s\n' "$b_auto_recover_after_clear"
    printf 'a_session_dials_after_clear=%s\n' "$a_dials_after_clear"
    printf 'b_session_dials_after_clear=%s\n' "$b_dials_after_clear"
  } >>"$contract"
  if [[ "$clear_ok" != "1" ]]; then
    printf 'status=fail\nreason=inner-GSO circuit did not remain latched immediately after netem clear\n' >>"$contract"
    return 1
  fi

  deadline=$((SECONDS + inner_gso_latched_fallback_observe_seconds))
  while [[ "$SECONDS" -lt "$deadline" ]]; do
    current_recoveries="$(inner_gso_module_param_sum inner_gso_circuit_recoveries)" || {
      latched=0
      break
    }
    if [[ "$current_recoveries" -ne "$clear_recoveries" ]] ||
      ! inner_gso_runtime_ready_state_on_both_nodes N ||
      ! inner_gso_auto_recover_disabled_on_both_nodes; then
      latched=0
      break
    fi
    sleep 1
  done
  collect_inner_gso_transition_snapshot after-latched-fallback
  a_recoveries_after_observe="$(inner_gso_module_param_uint a inner_gso_circuit_recoveries)" || after_ok=0
  b_recoveries_after_observe="$(inner_gso_module_param_uint b inner_gso_circuit_recoveries)" || after_ok=0
  current_recoveries="$(inner_gso_module_param_sum inner_gso_circuit_recoveries)" || after_ok=0
  current_inner="$(inner_gso_module_param_sum tx_plaintext_inner_gso_packets)" || after_ok=0
  current_outer="$(inner_gso_module_param_sum tx_plaintext_outer_gso_packets)" || after_ok=0
  current_plaintext="$(inner_gso_module_param_sum tx_plaintext_packets)" || after_ok=0
  a_ready_after_observe="$(inner_gso_module_param a inner_gso_runtime_ready)" || after_ok=0
  b_ready_after_observe="$(inner_gso_module_param b inner_gso_runtime_ready)" || after_ok=0
  a_auto_recover_after_observe="$(inner_gso_module_param a inner_gso_auto_recover)" || after_ok=0
  b_auto_recover_after_observe="$(inner_gso_module_param b inner_gso_auto_recover)" || after_ok=0
  a_dials_after_observe="$(transport_snapshot_counter a netem-after-latched-fallback session_dials)" || after_ok=0
  b_dials_after_observe="$(transport_snapshot_counter b netem-after-latched-fallback session_dials)" || after_ok=0
  [[ "$current_inner" -eq "$clear_inner" ]] || after_ok=0
  [[ "$current_outer" -gt "$clear_outer" && "$current_plaintext" -gt "$clear_plaintext" ]] || after_ok=0
  [[ "$a_recoveries_after_observe" -eq "$a_recoveries_before_clear" && "$b_recoveries_after_observe" -eq "$b_recoveries_before_clear" ]] || after_ok=0
  [[ "$a_ready_after_observe" == "N" && "$b_ready_after_observe" == "N" ]] || after_ok=0
  [[ "$a_auto_recover_after_observe" == "N" && "$b_auto_recover_after_observe" == "N" ]] || after_ok=0
  [[ "$a_dials_after_observe" -eq "$a_dials_after_clear" && "$b_dials_after_observe" -eq "$b_dials_after_clear" ]] || after_ok=0
  {
    printf 'inner_gso_packets_after_observe=%s\n' "$current_inner"
    printf 'outer_gso_packets_after_observe=%s\n' "$current_outer"
    printf 'plaintext_packets_after_observe=%s\n' "$current_plaintext"
    printf 'circuit_recoveries_after_observe=%s\n' "$current_recoveries"
    printf 'a_circuit_recoveries_after_observe=%s\n' "$a_recoveries_after_observe"
    printf 'b_circuit_recoveries_after_observe=%s\n' "$b_recoveries_after_observe"
    printf 'a_runtime_ready_after_observe=%s\n' "$a_ready_after_observe"
    printf 'b_runtime_ready_after_observe=%s\n' "$b_ready_after_observe"
    printf 'a_auto_recover_after_observe=%s\n' "$a_auto_recover_after_observe"
    printf 'b_auto_recover_after_observe=%s\n' "$b_auto_recover_after_observe"
    printf 'a_session_dials_after_observe=%s\n' "$a_dials_after_observe"
    printf 'b_session_dials_after_observe=%s\n' "$b_dials_after_observe"
  } >>"$contract"
  if [[ "$latched" != "1" || "$after_ok" != "1" ]]; then
    printf 'status=fail\nreason=inner-GSO restarted, sessions re-dialed, or reliable outer-GSO fallback stopped after netem clear\n' >>"$contract"
    return 1
  fi
  printf 'status=pass\n' >>"$contract"
}

schedule_netem_transition() {
  [[ "$netem_active_seconds" -gt 0 ]] || return 0
  (
    set -Eeuo pipefail
    run_netem_transition
  ) >"${workdir}/netem-transition.log" 2>&1 &
  netem_transition_pid=$!
}

wait_netem_transition() {
  local rc=0
  [[ -n "$netem_transition_pid" ]] || return 0
  wait "$netem_transition_pid" || rc=$?
  netem_transition_pid=""
  if [[ "$rc" -ne 0 ]]; then
    log "netem transition failed; see ${workdir}/netem-transition.log"
    return "$rc"
  fi
}

verify_netem_evidence_after_traffic() {
  netem_enabled || return 0
  if [[ "$netem_active_seconds" -gt 0 ]]; then
    grep -Fqx 'status=pass' "${workdir}/netem-evidence-before-clear.txt"
    return
  fi
  collect_netem_state_node a final
  collect_netem_state_node b final
  record_netem_evidence final
}

cancel_netem_transition() {
  [[ -n "$netem_transition_pid" ]] || return 0
  if kill -0 "$netem_transition_pid" >/dev/null 2>&1; then
    kill "$netem_transition_pid" >/dev/null 2>&1 || true
  fi
  wait "$netem_transition_pid" >/dev/null 2>&1 || true
  netem_transition_pid=""
}

prepare_node_topology() {
  local node="$1"
  local dir lan_if host_if host_ns host_addr secondary_host_addr host_gw trustixd api_port peer_port env_exports unit
  dir="$(remote_dir "$node")"
  lan_if="$(node_value "$node" "$lan_if_a" "$lan_if_b")"
  host_if="$(node_value "$node" "$host_if_a" "$host_if_b")"
  host_ns="$(node_value "$node" "$host_ns_a" "$host_ns_b")"
  host_addr="$(node_value "$node" "$host_a_addr" "$host_b_addr")"
  secondary_host_addr=""
  if case_uses_pinned_mixed_routes; then
    secondary_host_addr="$(node_value "$node" "$mixed_host_a_addr" "$mixed_host_b_addr")"
  fi
  host_gw="$(node_value "$node" "${lan_a_gateway%/*}" "${lan_b_gateway%/*}")"
  trustixd="$(node_bin "$node" trustixd)"
  api_port="$(node_value "$node" "$api_a_port" "$api_b_port")"
  peer_port="$(node_value "$node" "$peer_a_port" "$peer_b_port")"
  env_exports="$(daemon_env_exports)"
  unit="$(daemon_unit_name "$node")"
  run_node "$node" "set -Eeuo pipefail
ip_cmd=\$(command -v ip)
dir=$(remote_quote "$dir")
secondary_host_addr=$(remote_quote "$secondary_host_addr")
target_data=\"\${dir}/data\"
if command -v systemctl >/dev/null 2>&1; then
  systemctl stop $(remote_quote "$unit") >/dev/null 2>&1 || true
  systemctl reset-failed $(remote_quote "$unit") >/dev/null 2>&1 || true
fi
if [ -f \"\${dir}/trustixd.pid\" ]; then
  old_pid=\$(cat \"\${dir}/trustixd.pid\" 2>/dev/null || true)
  if [ -n \"\$old_pid\" ]; then
    kill \"\$old_pid\" >/dev/null 2>&1 || true
  fi
fi
for proc in /proc/[0-9]*; do
  [ -d \"\$proc\" ] || continue
  pid=\"\${proc##*/}\"
  [ \"\$pid\" = \"\$\$\" ] && continue
  [ -r \"\$proc/cmdline\" ] || continue
  cmdline=\$(tr '\000' ' ' 2>/dev/null <\"\$proc/cmdline\" || true)
  case \" \$cmdline \" in
    *\" -data-dir \$target_data \"*|*\" -data-dir=\$target_data \"*)
      kill \"\$pid\" >/dev/null 2>&1 || true
      ;;
  esac
done
for pid in \$(\"\$ip_cmd\" netns pids $(remote_quote "$host_ns") 2>/dev/null || true); do kill \"\$pid\" >/dev/null 2>&1 || true; done
for _ in \$(seq 1 5); do
  live=0
  if [ -f \"\${dir}/trustixd.pid\" ]; then
    old_pid=\$(cat \"\${dir}/trustixd.pid\" 2>/dev/null || true)
    [ -n \"\$old_pid\" ] && kill -0 \"\$old_pid\" >/dev/null 2>&1 && live=1
  fi
  [ \"\$live\" -eq 0 ] && break
  sleep 1
done
if [ -f \"\${dir}/trustixd.pid\" ]; then
  old_pid=\$(cat \"\${dir}/trustixd.pid\" 2>/dev/null || true)
  [ -n \"\$old_pid\" ] && kill -KILL \"\$old_pid\" >/dev/null 2>&1 || true
fi
if [ -x $(remote_quote "$trustixd") ] && [ -f \"\${dir}/config.yaml\" ]; then
  mkdir -p \"\${dir}/logs\"
  env ${env_exports} $(remote_quote "$trustixd") -config \"\${dir}/config.yaml\" -data-dir \"\${dir}/data\" -api 127.0.0.1:${api_port} -peer-api 0.0.0.0:${peer_port} -dataplane $(remote_quote "$dataplane_mode") -cleanup-dataplane >>\"\${dir}/logs/prepare-cleanup.log\" 2>&1 || true
fi
rm -rf \"\$dir\"
mkdir -p \"\$dir\"/logs \"\$dir\"/certs \"\$dir\"/data
if command -v modprobe >/dev/null 2>&1; then modprobe veth >/dev/null 2>&1 || true; fi
\"\$ip_cmd\" netns del $(remote_quote "$host_ns") >/dev/null 2>&1 || true
\"\$ip_cmd\" link del $(remote_quote "$lan_if") >/dev/null 2>&1 || true
\"\$ip_cmd\" link del $(remote_quote "$host_if") >/dev/null 2>&1 || true
\"\$ip_cmd\" link add $(remote_quote "$lan_if") type veth peer name $(remote_quote "$host_if")
\"\$ip_cmd\" netns add $(remote_quote "$host_ns")
\"\$ip_cmd\" link set $(remote_quote "$host_if") netns $(remote_quote "$host_ns")
\"\$ip_cmd\" link set $(remote_quote "$lan_if") up
\"\$ip_cmd\" netns exec $(remote_quote "$host_ns") \"\$ip_cmd\" link set lo up
\"\$ip_cmd\" netns exec $(remote_quote "$host_ns") \"\$ip_cmd\" addr add $(remote_quote "$host_addr") dev $(remote_quote "$host_if")
if [ -n \"\$secondary_host_addr\" ]; then
  \"\$ip_cmd\" netns exec $(remote_quote "$host_ns") \"\$ip_cmd\" addr add \"\$secondary_host_addr\" dev $(remote_quote "$host_if")
fi
\"\$ip_cmd\" netns exec $(remote_quote "$host_ns") \"\$ip_cmd\" link set $(remote_quote "$host_if") up
\"\$ip_cmd\" netns exec $(remote_quote "$host_ns") \"\$ip_cmd\" route replace default via $(remote_quote "$host_gw")
"
}

generate_certs() {
  rm -rf "$workdir/certs"
  mkdir -p "$workdir/certs"
  "$trustix_ca" quickstart -out "$workdir/certs" -domain "$domain_id" -ix "${ix_a},${ix_b}" >/dev/null
  "$trustix_ca" route authorize -out "$workdir/certs" -domain "$domain_id" -ix "$ix_a" -prefix "$lan_a_cidr" >/dev/null
  "$trustix_ca" route authorize -out "$workdir/certs" -domain "$domain_id" -ix "$ix_b" -prefix "$lan_b_cidr" >/dev/null
  if case_link_tls_transport; then
    "$trustix_ca" ix issue -out "$workdir/certs" -domain "$domain_id" -ix "${ix_a}-transport" -ip "$underlay_a_ip" -ca-cert "$workdir/certs/domain-ca.pem" -ca-key "$workdir/certs/domain-ca.key" >/dev/null
    "$trustix_ca" ix issue -out "$workdir/certs" -domain "$domain_id" -ix "${ix_b}-transport" -ip "$underlay_b_ip" -ca-cert "$workdir/certs/domain-ca.pem" -ca-key "$workdir/certs/domain-ca.key" >/dev/null
  fi
}

write_multi_endpoint_config() {
  local node="$1"
  local config_path="$2"
  local local_ix peer_ix local_lan remote_lan local_gateway local_lan_if local_underlay_if
  local local_peer_api remote_peer_api remote_dir_node encryption crypto_placement local_underlay remote_underlay
  local index transport local_endpoint remote_endpoint local_port remote_port kernel_mode
  local remote_udp_lan remote_tix_tcp_lan remote_udp_endpoint remote_tix_tcp_endpoint
  local_ix="$(node_value "$node" "$ix_a" "$ix_b")"
  peer_ix="$(node_value "$node" "$ix_b" "$ix_a")"
  local_lan="$(node_value "$node" "$lan_a_cidr" "$lan_b_cidr")"
  remote_lan="$(node_value "$node" "$lan_b_cidr" "$lan_a_cidr")"
  local_gateway="$(node_value "$node" "$lan_a_gateway" "$lan_b_gateway")"
  local_lan_if="$(node_value "$node" "$lan_if_a" "$lan_if_b")"
  local_underlay_if="$(node_value "$node" "$underlay_a_if" "$underlay_b_if")"
  local_underlay="$(node_value "$node" "$underlay_a_ip" "$underlay_b_ip")"
  remote_underlay="$(node_value "$node" "$underlay_b_ip" "$underlay_a_ip")"
  local_peer_api="$(node_value "$node" "${underlay_a_ip}:${peer_a_port}" "${underlay_b_ip}:${peer_b_port}")"
  remote_peer_api="$(node_value "$node" "${underlay_b_ip}:${peer_b_port}" "${underlay_a_ip}:${peer_a_port}")"
  remote_dir_node="$(remote_dir "$node")"
  encryption="$(case_encryption)"
  crypto_placement="$(case_crypto_placement)"

  cat >"$config_path" <<EOF
domain:
  id: ${domain_id}
  trust_roots:
    - ${remote_dir_node}/certs/root-ca.pem
    - ${remote_dir_node}/certs/domain-ca.pem
    - ${remote_dir_node}/certs/config-ca.pem

ix:
  id: ${local_ix}
  domain: ${domain_id}
  cert: ${remote_dir_node}/certs/${local_ix}.crt
  key: ${remote_dir_node}/certs/${local_ix}.key
  control_api: https://${local_peer_api}
  route_authorizations:
    - ${remote_dir_node}/certs/${local_ix}-route.crt

lan:
  iface: ${local_lan_if}
  underlay_iface: ${local_underlay_if}
  gateway: ${local_gateway}
  advertise:
    - ${local_lan}
  mode: routed
  manage_address: true
  manage_forwarding: true
  manage_rp_filter: true

endpoints:
EOF
  index=0
  for transport in "${endpoint_transports[@]}"; do
    local_endpoint="$(case_endpoint_name_for_transport "$node" "$transport")"
    local_port="$(case_endpoint_port_for_index "$node" "$index")"
    cat >>"$config_path" <<EOF
  - name: ${local_endpoint}
    mode: passive
    listen: ${local_underlay}:${local_port}
    address: ${local_underlay}:${local_port}
    transport: ${transport}
EOF
    endpoint_security_yaml "    " "$encryption" "$transport" >>"$config_path"
    printf '    enabled: true\n' >>"$config_path"
    index=$((index + 1))
  done

  cat >>"$config_path" <<EOF

peers:
  - id: ${peer_ix}
    domain: ${domain_id}
    control_api: https://${remote_peer_api}
    endpoints:
EOF
  index=0
  for transport in "${endpoint_transports[@]}"; do
    if [[ "$node" == "a" ]]; then
      remote_endpoint="$(case_endpoint_name_for_transport b "$transport")"
      remote_port="$(case_endpoint_port_for_index b "$index")"
    else
      remote_endpoint="$(case_endpoint_name_for_transport a "$transport")"
      remote_port="$(case_endpoint_port_for_index a "$index")"
    fi
    cat >>"$config_path" <<EOF
      - name: ${remote_endpoint}
        address: ${remote_underlay}:${remote_port}
        transport: ${transport}
EOF
    endpoint_security_yaml "        " "$encryption" "$transport" >>"$config_path"
    printf '        enabled: true\n' >>"$config_path"
    index=$((index + 1))
  done

  cat >>"$config_path" <<EOF
    allowed_prefixes:
      - ${remote_lan}

EOF
  if case_uses_pinned_mixed_routes; then
    remote_udp_lan="$(node_value "$node" "$mixed_udp_lan_b_cidr" "$mixed_udp_lan_a_cidr")"
    remote_tix_tcp_lan="$(node_value "$node" "$mixed_tix_tcp_lan_b_cidr" "$mixed_tix_tcp_lan_a_cidr")"
    if [[ "$node" == "a" ]]; then
      remote_udp_endpoint="$(case_endpoint_name_for_transport b udp)"
      remote_tix_tcp_endpoint="$(case_endpoint_name_for_transport b tix_tcp)"
    else
      remote_udp_endpoint="$(case_endpoint_name_for_transport a udp)"
      remote_tix_tcp_endpoint="$(case_endpoint_name_for_transport a tix_tcp)"
    fi
    cat >>"$config_path" <<EOF
routes:
  - prefix: ${remote_udp_lan}
    next_hop: ${peer_ix}
    endpoint: ${remote_udp_endpoint}
    policy: default-routed
    metric: 100
  - prefix: ${remote_tix_tcp_lan}
    next_hop: ${peer_ix}
    endpoint: ${remote_tix_tcp_endpoint}
    policy: default-routed
    metric: 100

EOF
  else
    cat >>"$config_path" <<EOF
routes:
  - prefix: ${remote_lan}
    next_hop: ${peer_ix}
    policy: default-routed
    metric: 100

EOF
  fi
  cat >>"$config_path" <<EOF
policies:
  - name: default-routed
    route_selection: longest_prefix
    load_balance: least_conn
    flow_stickiness: true
    rewrite: preserve_source

transport_policy:
  mode: user_defined
  profile: $(case_transport_profile)
  datapath: $(case_transport_datapath)
  mtu: ${transport_mtu}
  candidates:
EOF
  for transport in "${endpoint_transports[@]}"; do
    local_endpoint="$(case_endpoint_name_for_transport "$node" "$transport")"
    printf '    - %s\n' "$local_endpoint" >>"$config_path"
  done
  cat >>"$config_path" <<EOF
  failover: health_based
  load_balance: least_conn
  encryption: ${encryption}
  crypto_placement: ${crypto_placement}
$(case_crypto_suites_yaml)
$(case_tls_data_plane_yaml)
  session_pool:
    size: ${session_pool_size}
    strategy: ${session_pool_strategy}
    warmup: ${session_pool_warmup}
    heartbeat:
      mode: ${session_pool_heartbeat_mode}
      interval: ${session_pool_heartbeat_interval}
      timeout: ${session_pool_heartbeat_timeout}
EOF
  kernel_mode="$(case_kernel_transport_mode)"
  if [[ -n "$kernel_mode" ]]; then
    cat >>"$config_path" <<EOF
  kernel_transport:
    mode: ${kernel_mode}
EOF
  fi
  cat >>"$config_path" <<EOF
  crypto_key_source: auto
EOF
  if case_link_tls_transport; then
    cat >>"$config_path" <<EOF
  tls_identity:
    mode: custom_cert
    cert: ${remote_dir_node}/certs/${local_ix}-transport.crt
    key: ${remote_dir_node}/certs/${local_ix}-transport.key
    trust_roots:
      - ${remote_dir_node}/certs/domain-ca.pem
EOF
  fi
  printf '\n' >>"$config_path"
  case_module_yaml "$node" >>"$config_path"
}

write_config() {
  local node="$1"
  local config_path="$2"
  if case_is_multi_endpoint; then
    write_multi_endpoint_config "$node" "$config_path"
    return
  fi
  local local_ix peer_ix local_lan remote_lan local_gateway local_lan_if local_underlay_if
  local local_peer_api remote_peer_api local_endpoint remote_endpoint local_data remote_data endpoint_transport
  local remote_dir_node encryption crypto_placement
  local_ix="$(node_value "$node" "$ix_a" "$ix_b")"
  peer_ix="$(node_value "$node" "$ix_b" "$ix_a")"
  local_lan="$(node_value "$node" "$lan_a_cidr" "$lan_b_cidr")"
  remote_lan="$(node_value "$node" "$lan_b_cidr" "$lan_a_cidr")"
  local_gateway="$(node_value "$node" "$lan_a_gateway" "$lan_b_gateway")"
  local_lan_if="$(node_value "$node" "$lan_if_a" "$lan_if_b")"
  local_underlay_if="$(node_value "$node" "$underlay_a_if" "$underlay_b_if")"
  local_peer_api="$(node_value "$node" "${underlay_a_ip}:${peer_a_port}" "${underlay_b_ip}:${peer_b_port}")"
  remote_peer_api="$(node_value "$node" "${underlay_b_ip}:${peer_b_port}" "${underlay_a_ip}:${peer_a_port}")"
  local_data="$(node_value "$node" "${underlay_a_ip}:${data_a_port}" "${underlay_b_ip}:${data_b_port}")"
  remote_data="$(node_value "$node" "${underlay_b_ip}:${data_b_port}" "${underlay_a_ip}:${data_a_port}")"
  if case_is_iptunnel_transport; then
    local_data="$(tunnel_config_for_node "$node")"
    remote_data="$local_data"
  fi
  local_endpoint="$(case_endpoint_name "$node")"
  if [[ "$node" == "a" ]]; then
    remote_endpoint="$(case_endpoint_name b)"
  else
    remote_endpoint="$(case_endpoint_name a)"
  fi
  endpoint_transport="$(case_endpoint_transport)"
  encryption="$(case_encryption)"
  crypto_placement="$(case_crypto_placement)"
  remote_dir_node="$(remote_dir "$node")"
  {
    cat <<EOF
domain:
  id: ${domain_id}
  trust_roots:
    - ${remote_dir_node}/certs/root-ca.pem
    - ${remote_dir_node}/certs/domain-ca.pem
    - ${remote_dir_node}/certs/config-ca.pem

ix:
  id: ${local_ix}
  domain: ${domain_id}
  cert: ${remote_dir_node}/certs/${local_ix}.crt
  key: ${remote_dir_node}/certs/${local_ix}.key
  control_api: https://${local_peer_api}
  route_authorizations:
    - ${remote_dir_node}/certs/${local_ix}-route.crt

lan:
  iface: ${local_lan_if}
  underlay_iface: ${local_underlay_if}
  gateway: ${local_gateway}
  advertise:
    - ${local_lan}
  mode: routed
  manage_address: true
  manage_forwarding: true
  manage_rp_filter: true

endpoints:
  - name: ${local_endpoint}
    mode: passive
    listen: ${local_data}
    address: ${local_data}
    transport: ${endpoint_transport}
EOF
    if ! case_is_iptunnel_transport; then
      endpoint_security_yaml "    " "$encryption"
    fi
    cat <<EOF
    enabled: true

peers:
  - id: ${peer_ix}
    domain: ${domain_id}
    control_api: https://${remote_peer_api}
    endpoints:
      - name: ${remote_endpoint}
        address: ${remote_data}
        transport: ${endpoint_transport}
EOF
    if ! case_is_iptunnel_transport; then
      endpoint_security_yaml "        " "$encryption"
    fi
    cat <<EOF
        enabled: true
    allowed_prefixes:
      - ${remote_lan}

routes:
  - prefix: ${remote_lan}
    next_hop: ${peer_ix}
    endpoint: ${remote_endpoint}
    policy: default-routed
    metric: 100

policies:
  - name: default-routed
    route_selection: longest_prefix
    load_balance: least_conn
    flow_stickiness: true
    rewrite: preserve_source

transport_policy:
  mode: user_defined
  profile: $(case_transport_profile)
  datapath: $(case_transport_datapath)
  mtu: ${transport_mtu}
  candidates:
    - ${local_endpoint}
  failover: health_based
  load_balance: least_conn
  encryption: ${encryption}
  crypto_placement: ${crypto_placement}
$(case_crypto_suites_yaml)
$(case_tls_data_plane_yaml)
  session_pool:
    size: ${session_pool_size}
    strategy: ${session_pool_strategy}
    warmup: ${session_pool_warmup}
    heartbeat:
      mode: ${session_pool_heartbeat_mode}
      interval: ${session_pool_heartbeat_interval}
      timeout: ${session_pool_heartbeat_timeout}
EOF
    local kernel_mode
    kernel_mode="$(case_kernel_transport_mode)"
    if [[ -n "$kernel_mode" ]]; then
      cat <<EOF
  kernel_transport:
    mode: ${kernel_mode}
EOF
    fi
    if case_link_tls_transport; then
      cat <<EOF
  crypto_key_source: tls_exporter
  tls_identity:
    mode: custom_cert
    cert: ${remote_dir_node}/certs/${local_ix}-transport.crt
    key: ${remote_dir_node}/certs/${local_ix}-transport.key
    trust_roots:
      - ${remote_dir_node}/certs/domain-ca.pem
EOF
    fi
    printf '\n'
    case_module_yaml "$node"
  } >"$config_path"
}

push_inputs() {
  copy_to_node a "$workdir/certs/." "${remote_a}/certs"
  copy_to_node b "$workdir/certs/." "${remote_b}/certs"
  copy_to_node a "$workdir/config-a.yaml" "${remote_a}/config.yaml"
  copy_to_node b "$workdir/config-b.yaml" "${remote_b}/config.yaml"
}

secure_kudp_daemon_env() {
  local route_gso=0
  if case_secure_kudp_route_gso; then
    route_gso=1
  fi
  cat <<'EOF'
TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY=1
TRUSTIX_KERNEL_UDP_TC_SECURE_DIRECT_ONLY=1
TRUSTIX_KERNEL_UDP_TC_ONLY=1
TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT=1
TRUSTIX_KERNEL_UDP_TC_RX_SECURE_DIRECT=1
TRUSTIX_KERNEL_UDP_XDP_RX_DIRECT=1
TRUSTIX_KERNEL_UDP_XDP_RX_SECURE_DIRECT=1
TRUSTIX_KERNEL_UDP_XDP_RX_DIRECT_TRUST_INNER_CHECKSUMS=1
TRUSTIX_KERNEL_CRYPTO_ALLOW_SIMD_KFUNC_FASTPATH=1
TRUSTIX_KERNEL_CRYPTO_ALLOW_SIMD_IRQ_FPU_KFUNC_FASTPATH=1
TRUSTIX_KERNEL_CRYPTO_KFUNC_FASTPATH_STATS=1
TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_KFUNC_SEAL=1
TRUSTIX_KERNEL_UDP_TC_RX_SECURE_DIRECT_KFUNC_OPEN=1
TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_SKB_SEAL_KFUNC=0
TRUSTIX_KERNEL_UDP_TC_RX_SECURE_DIRECT_SKB_OPEN_KFUNC=0
TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_TRUST_INNER_CHECKSUMS=1
TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_FIX_INNER_CHECKSUMS=0
TRUSTIX_TIX_TCP_ROUTE_GSO=0
TRUSTIX_TIX_TCP_ROUTE_GSO_ASYNC=0
EOF
  printf 'TRUSTIX_KERNEL_UDP_TC_TX_SECURE_ROUTE_GSO_KFUNC=%s\n' "$route_gso"
  printf 'TRUSTIX_KERNEL_UDP_TC_TX_SECURE_ROUTE_GSO=%s\n' "$route_gso"
}

secure_tix_tcp_kernel_daemon_env() {
  cat <<'EOF'
TRUSTIX_TIX_TCP_ROUTE_GSO=0
TRUSTIX_TIX_TCP_ROUTE_GSO_ASYNC=0
TRUSTIX_TIX_TCP_TC_TX_DIRECT=0
TRUSTIX_TIX_TCP_TC_TX_DIRECT_ONLY=0
TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_GSO_ASYNC_KFUNC=0
TRUSTIX_TIX_TCP_ALLOW_CRASH_RISK_ROUTE_TCP_GSO_ASYNC=0
TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT=0
TRUSTIX_KERNEL_UDP_TC_RX_SECURE_DIRECT=0
TRUSTIX_KERNEL_UDP_XDP_RX_DIRECT=0
TRUSTIX_KERNEL_UDP_XDP_RX_SECURE_DIRECT=0
TRUSTIX_KERNEL_UDP_XDP_RX_DIRECT_TRUST_INNER_CHECKSUMS=0
TRUSTIX_KERNEL_CRYPTO_ALLOW_SIMD_KFUNC_FASTPATH=0
TRUSTIX_KERNEL_CRYPTO_ALLOW_SIMD_IRQ_FPU_KFUNC_FASTPATH=0
TRUSTIX_KERNEL_CRYPTO_KFUNC_FASTPATH_STATS=1
TRUSTIX_KERNEL_CRYPTO_DATAPATH_VAES=1
TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_KFUNC_SEAL=0
TRUSTIX_KERNEL_UDP_TC_RX_SECURE_DIRECT_KFUNC_OPEN=0
TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_SKB_SEAL_KFUNC=0
TRUSTIX_KERNEL_UDP_TC_RX_SECURE_DIRECT_SKB_OPEN_KFUNC=0
TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_TRUST_INNER_CHECKSUMS=0
TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_FIX_INNER_CHECKSUMS=0
TRUSTIX_KERNEL_UDP_TC_TX_SECURE_ROUTE_TCP_GSO_KFUNC=0
TRUSTIX_KERNEL_UDP_TC_TX_SECURE_ROUTE_GSO_KFUNC=0
TRUSTIX_KERNEL_UDP_TC_TX_SECURE_ROUTE_GSO=0
EOF
}

mixed_secure_kernel_daemon_env() {
  secure_kudp_daemon_env
  cat <<'EOF'
TRUSTIX_TIX_TCP_TC_TX_DIRECT=0
TRUSTIX_TIX_TCP_TC_TX_DIRECT_ONLY=0
TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_GSO_ASYNC_KFUNC=0
TRUSTIX_TIX_TCP_ALLOW_CRASH_RISK_ROUTE_TCP_GSO_ASYNC=0
TRUSTIX_KERNEL_CRYPTO_DATAPATH_VAES=1
EOF
}

common_daemon_env() {
  printf 'TRUSTIX_CAPTURE_FORWARDER_WORKERS=%s\n' "$capture_forwarder_workers"
  printf 'TRUSTIX_CAPTURE_FORWARDER_BUFFER=%s\n' "$capture_forwarder_buffer"
  printf 'TRUSTIX_CAPTURE_FORWARDER_BATCH=%s\n' "$capture_forwarder_batch"
  printf 'TRUSTIX_CAPTURE_FORWARDER_BATCH_DELAY=%s\n' "$capture_forwarder_batch_delay"
  if [[ -n "$cpu_profile_dir" ]]; then
    printf 'TRUSTIX_CPU_PROFILE_DIR=%s\n' "$cpu_profile_dir"
  fi
  if [[ -n "$secure_tix_tcp_inner_checksum_partial" ]]; then
    printf 'TRUSTIX_TIX_TCP_SECURE_INNER_CHECKSUM_PARTIAL=%s\n' "$secure_tix_tcp_inner_checksum_partial"
  fi
  if [[ -n "$tix_tcp_inner_gso" ]]; then
    printf 'TRUSTIX_TIX_TCP_INNER_GSO=%s\n' "$tix_tcp_inner_gso"
  fi
}

plaintext_tc_direct_daemon_env() {
  case "$(case_endpoint_transport)" in
    udp)
      cat <<'EOF'
TRUSTIX_KERNEL_UDP_TC_TX_DIRECT=1
TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY=1
TRUSTIX_KERNEL_UDP_TC_ONLY=1
TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_KERNEL_UDP_ONLY=1
TRUSTIX_TIX_TCP_ROUTE_GSO=0
TRUSTIX_TIX_TCP_ROUTE_GSO_ASYNC=0
TRUSTIX_TIX_TCP_TC_TX_DIRECT=0
EOF
      ;;
    tix_tcp)
      cat <<'EOF'
TRUSTIX_TIX_TCP_ROUTE_GSO=0
TRUSTIX_TIX_TCP_ROUTE_GSO_ASYNC=0
TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_GSO_KFUNC=0
TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_GSO_ASYNC_KFUNC=0
TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_XMIT_KFUNC=0
TRUSTIX_TIX_TCP_TC_TX_DIRECT=1
TRUSTIX_TIX_TCP_TC_TX_DIRECT_ONLY=1
TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY=1
TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_TIX_TCP_ONLY=1
TRUSTIX_TIX_TCP_ALLOW_CRASH_RISK_ROUTE_TCP_GSO_ASYNC=0
EOF
      ;;
    *)
      die "plaintext TC-direct requires udp or tix_tcp endpoint transport"
      ;;
  esac
}

daemon_env() {
  common_daemon_env
  if case_is_mixed_secure_kernel; then
    mixed_secure_kernel_daemon_env
    return
  fi
  if [[ "$(case_fast_path)" == "secure_tix_tcp_kernel" ]]; then
    secure_tix_tcp_kernel_daemon_env
    return
  fi
  if case_uses_secure_kudp_fast_path; then
    secure_kudp_daemon_env
    return
  fi
  case "$(case_fast_path)" in
    userspace)
      if case_has_endpoint_transport tix_tcp; then
        cat <<'EOF'
TRUSTIX_TIX_TCP_RAW_FALLBACK=1
EOF
      fi
      ;;
    full_kmod)
      local rx_worker_tix_tcp=0
      if case_has_endpoint_transport tix_tcp; then
        rx_worker_tix_tcp=1
      fi
      cat <<'EOF'
TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_FULL_PLAINTEXT=1
TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_RX_WORKER=1
TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_RX_WORKER_EXPERIMENTS=1
TRUSTIX_KERNEL_DATAPATH_ALLOW_UNSAFE_RX_WORKER_EXPERIMENTS=1
TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_OPENWRT_FULL_DATAPATH=1
TRUSTIX_KERNEL_DATAPATH_FULL_PLAINTEXT=1
TRUSTIX_KERNEL_DATAPATH_RX_WORKER=1
EOF
      if truthy "${TRUSTIX_CROSS_HOST_ENABLE_OPENWRT_RX_SINGLE_COALESCE:-0}"; then
        printf 'TRUSTIX_KERNEL_DATAPATH_ENABLE_OPENWRT_RX_SINGLE_COALESCE=1\n'
      fi
      if [[ -n "${TRUSTIX_CROSS_HOST_OPENWRT_RX_SINGLE_COALESCE:-}" ]]; then
        printf 'TRUSTIX_KERNEL_DATAPATH_OPENWRT_RX_SINGLE_COALESCE=%s\n' "$TRUSTIX_CROSS_HOST_OPENWRT_RX_SINGLE_COALESCE"
      fi
      if truthy "${TRUSTIX_CROSS_HOST_ENABLE_OPENWRT_RX_STREAM_COALESCE_NONLINEAR:-0}"; then
        printf 'TRUSTIX_KERNEL_DATAPATH_ENABLE_OPENWRT_RX_STREAM_COALESCE_NONLINEAR=1\n'
      fi
      printf 'TRUSTIX_KERNEL_DATAPATH_RX_WORKER_ALLOW_TIX_TCP=%s\n' "$rx_worker_tix_tcp"
      if [[ "$rx_worker_tix_tcp" == "1" ]]; then
        printf 'TRUSTIX_TIX_TCP_ALLOW_MIXED_TCP_FAST_PATH=1\n'
      fi
      ;;
    route_gso)
      cat <<'EOF'
TRUSTIX_TIX_TCP_ROUTE_GSO_ASYNC=1
TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_GSO_ASYNC_KFUNC=1
TRUSTIX_TIX_TCP_TC_TX_DIRECT=1
TRUSTIX_TIX_TCP_TC_TX_DIRECT_ONLY=1
TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_TIX_TCP_ONLY=1
TRUSTIX_TIX_TCP_ALLOW_CRASH_RISK_ROUTE_TCP_GSO_ASYNC=0
EOF
      ;;
    tc_direct)
      plaintext_tc_direct_daemon_env
      ;;
    userspace_tc)
      case "$(case_endpoint_transport):$(case_encryption)" in
        udp:plaintext)
          plaintext_tc_direct_daemon_env
          ;;
        tix_tcp:plaintext)
          plaintext_tc_direct_daemon_env
          ;;
      esac
      ;;
    secure_kudp)
      secure_kudp_daemon_env
      ;;
  esac
}

daemon_env_exports() {
  local env_lines env_exports=""
  env_lines="$(daemon_env)"
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    env_exports="${env_exports} ${line}"
  done <<<"$env_lines"
  if [[ -n "${TRUSTIX_CROSS_HOST_EXTRA_DAEMON_ENV:-}" ]]; then
    env_exports="${env_exports} ${TRUSTIX_CROSS_HOST_EXTRA_DAEMON_ENV}"
  fi
  printf '%s\n' "${env_exports# }"
}

start_daemon() {
  local node="$1"
  local dir api_port peer_port trustixd env_exports unit
  dir="$(remote_dir "$node")"
  api_port="$(node_value "$node" "$api_a_port" "$api_b_port")"
  peer_port="$(node_value "$node" "$peer_a_port" "$peer_b_port")"
  trustixd="$(node_bin "$node" trustixd)"
  env_exports="$(daemon_env_exports)"
  unit="$(daemon_unit_name "$node")"
run_node "$node" "set -Eeuo pipefail
cd $(remote_quote "$dir")
rm -f trustixd.pid trustixd.unit logs/trustixd.log
if [ $(remote_quote "$daemon_supervisor") = systemd ]; then
  systemctl stop $(remote_quote "$unit") >/dev/null 2>&1 || true
  systemctl reset-failed $(remote_quote "$unit") >/dev/null 2>&1 || true
  systemd-run --quiet --collect \
    --unit $(remote_quote "$unit") \
    --property=Restart=always \
    --property=RestartSec=${daemon_restart_sec}s \
    --property=$(remote_quote "StandardOutput=append:${dir}/logs/trustixd.log") \
    --property=$(remote_quote "StandardError=append:${dir}/logs/trustixd.log") \
    env ${env_exports} $(remote_quote "$trustixd") \
      -config $(remote_quote "${dir}/config.yaml") \
      -data-dir $(remote_quote "${dir}/data") \
      -api 127.0.0.1:${api_port} \
      -peer-api 0.0.0.0:${peer_port} \
      -dataplane $(remote_quote "$dataplane_mode")
  printf '%s\n' $(remote_quote "$unit") >trustixd.unit
  pid=0
  for _ in \$(seq 1 40); do
    pid=\$(systemctl show --property=MainPID --value $(remote_quote "$unit") 2>/dev/null || true)
    case \"\$pid\" in ''|0|*[!0-9]*) sleep 0.25 ;; *) break ;; esac
  done
  case \"\$pid\" in
    ''|0|*[!0-9]*)
      systemctl --no-pager --full status $(remote_quote "$unit") >&2 || true
      exit 1
      ;;
  esac
  printf '%s\n' \"\$pid\" >trustixd.pid
elif command -v nohup >/dev/null 2>&1; then
  nohup env ${env_exports} $(remote_quote "$trustixd") \\
    -config $(remote_quote "${dir}/config.yaml") \\
    -data-dir $(remote_quote "${dir}/data") \\
    -api 127.0.0.1:${api_port} \\
    -peer-api 0.0.0.0:${peer_port} \\
    -dataplane $(remote_quote "$dataplane_mode") \\
    >$(remote_quote "${dir}/logs/trustixd.log") 2>&1 </dev/null &
elif command -v setsid >/dev/null 2>&1; then
  setsid env ${env_exports} $(remote_quote "$trustixd") \\
    -config $(remote_quote "${dir}/config.yaml") \\
    -data-dir $(remote_quote "${dir}/data") \\
    -api 127.0.0.1:${api_port} \\
    -peer-api 0.0.0.0:${peer_port} \\
    -dataplane $(remote_quote "$dataplane_mode") \\
    >$(remote_quote "${dir}/logs/trustixd.log") 2>&1 </dev/null &
else
  env ${env_exports} $(remote_quote "$trustixd") \\
    -config $(remote_quote "${dir}/config.yaml") \\
    -data-dir $(remote_quote "${dir}/data") \\
    -api 127.0.0.1:${api_port} \\
    -peer-api 0.0.0.0:${peer_port} \\
    -dataplane $(remote_quote "$dataplane_mode") \\
    >$(remote_quote "${dir}/logs/trustixd.log") 2>&1 </dev/null &
fi
if [ $(remote_quote "$daemon_supervisor") != systemd ]; then
  echo \$! >$(remote_quote "${dir}/trustixd.pid")
fi
"
}

wait_for_api() {
  local node="$1"
  local dir api_port unit
  dir="$(remote_dir "$node")"
  api_port="$(node_value "$node" "$api_a_port" "$api_b_port")"
  unit="$(daemon_unit_name "$node")"
  run_node "$node" "set -Eeuo pipefail
pid=\$(cat $(remote_quote "${dir}/trustixd.pid"))
for _ in \$(seq 1 ${daemon_ready_attempts}); do
  if curl -fsS http://127.0.0.1:${api_port}/v1/status >/dev/null 2>&1; then
    if [ $(remote_quote "$daemon_supervisor") = systemd ]; then
      pid=\$(systemctl show --property=MainPID --value $(remote_quote "$unit") 2>/dev/null || true)
      case \"\$pid\" in ''|0|*[!0-9]*) ;; *) printf '%s\n' \"\$pid\" >$(remote_quote "${dir}/trustixd.pid") ;; esac
    fi
    exit 0
  fi
  if [ $(remote_quote "$daemon_supervisor") = systemd ]; then
    if ! systemctl is-active --quiet $(remote_quote "$unit"); then
      systemctl --no-pager --full status $(remote_quote "$unit") >&2 || true
      exit 1
    fi
    pid=\$(systemctl show --property=MainPID --value $(remote_quote "$unit") 2>/dev/null || true)
    case \"\$pid\" in ''|0|*[!0-9]*) ;; *) printf '%s\n' \"\$pid\" >$(remote_quote "${dir}/trustixd.pid") ;; esac
  elif ! kill -0 \"\$pid\" >/dev/null 2>&1; then
    sed -n '1,240p' $(remote_quote "${dir}/logs/trustixd.log") >&2 || true
    exit 1
  fi
  sleep ${daemon_ready_sleep}
done
sed -n '1,240p' $(remote_quote "${dir}/logs/trustixd.log") >&2 || true
exit 1
"
}

case_requires_tix_tcp_full_kmod_readiness() {
  [[ "$(case_fast_path)" == "full_kmod" &&
    "$(case_encryption)" == "plaintext" ]] &&
    case_has_endpoint_transport tix_tcp
}

tix_tcp_full_kmod_ready_node() {
  local node="$1"
  local api_port trustixctl peer endpoint payload module_values
  local runtime_ready inner_flow_hash_sets shard_sequence_fallbacks
  api_port="$(node_value "$node" "$api_a_port" "$api_b_port")"
  trustixctl="$(node_bin "$node" trustixctl)"
  peer="$(node_value "$node" "$ix_b" "$ix_a")"
  if [[ "$node" == "a" ]]; then
    endpoint="$(case_endpoint_name_for_transport b tix_tcp)"
  else
    endpoint="$(case_endpoint_name_for_transport a tix_tcp)"
  fi
  payload="$(run_node "$node" "$(remote_quote "$trustixctl") -api http://127.0.0.1:${api_port} transports")" || return
  printf '%s\n' "$payload" | python3 -c '
import json
import sys

peer, endpoint, pool_size_raw = sys.argv[1:]
pool_size = int(pool_size_raw)
payload = json.load(sys.stdin)
status = payload.get("tix_tcp") or {}
if status.get("provider") != "kernel_datapath_full_plaintext":
    raise SystemExit(1)
for key in ("available", "fast_path", "inner_gso", "port_sharding"):
    if status.get(key) is not True:
        raise SystemExit(1)

sessions = [
    item for item in payload.get("sessions") or []
    if item.get("transport") == "tix_tcp"
    and item.get("peer") == peer
    and item.get("endpoint") == endpoint
]
outbound = [item for item in sessions if item.get("direction") == "outbound"]
inbound = [item for item in sessions if item.get("direction") == "inbound_reverse"]
if len(outbound) < pool_size or len(inbound) < pool_size:
    raise SystemExit(1)

required = (
    "tix_tcp_full_plaintext_kernel_datapath",
    "tix_tcp_kernel_datapath_ready_local",
    "tix_tcp_kernel_datapath_ready_peer",
    "tix_tcp_kernel_datapath_ready_negotiated",
    "tix_tcp_inner_gso_local",
    "tix_tcp_inner_gso_peer",
    "tix_tcp_inner_gso_negotiated",
    "tix_tcp_port_sharding_local",
    "tix_tcp_port_sharding_peer",
    "tix_tcp_port_sharding_negotiated",
)
for item in sessions:
    stats = item.get("stats") or {}
    if stats.get("encryption") != "plaintext":
        raise SystemExit(1)
    extra = stats.get("extra") or {}
    if any(extra.get(key) != 1 for key in required):
        raise SystemExit(1)
' "$peer" "$endpoint" "$session_pool_size" || return
  module_values="$(run_node "$node" "set -Eeuo pipefail
base=/sys/module/trustix_datapath/parameters
printf '%s %s %s\n' \"\$(cat \"\${base}/inner_gso_runtime_ready\")\" \"\$(cat \"\${base}/tx_plaintext_inner_flow_hash_sets\")\" \"\$(cat \"\${base}/tx_plaintext_tix_tcp_shard_sequence_fallbacks\")\"")" || return
  read -r runtime_ready inner_flow_hash_sets shard_sequence_fallbacks <<<"$module_values"
  [[ "$runtime_ready" == "Y" &&
    "$inner_flow_hash_sets" == "0" &&
    "$shard_sequence_fallbacks" == "0" ]]
}

wait_for_tix_tcp_full_kmod_readiness() {
  local attempt stable_polls=0
  case_requires_tix_tcp_full_kmod_readiness || return 0
  for attempt in $(seq 1 "$daemon_ready_attempts"); do
    if tix_tcp_full_kmod_ready_node a && tix_tcp_full_kmod_ready_node b; then
      stable_polls=$((stable_polls + 1))
      if [[ "$stable_polls" -ge 2 ]]; then
        collect_transport_snapshot startup-ready
        {
          printf 'format=trustix-tix-tcp-full-kmod-readiness-v1\n'
          printf 'status=pass\n'
          printf 'attempts=%s\n' "$attempt"
          printf 'stable_polls=%s\n' "$stable_polls"
          printf 'session_pool_size=%s\n' "$session_pool_size"
        } >"${workdir}/tix-tcp-full-kmod-readiness.txt"
        return 0
      fi
    else
      stable_polls=0
    fi
    sleep "$daemon_ready_sleep"
  done
  collect_transport_snapshot startup-not-ready || true
  collect_module_parameters a startup-not-ready || true
  collect_module_parameters b startup-not-ready || true
  {
    printf 'format=trustix-tix-tcp-full-kmod-readiness-v1\n'
    printf 'status=fail\n'
    printf 'attempts=%s\n' "$daemon_ready_attempts"
    printf 'stable_polls=%s\n' "$stable_polls"
    printf 'session_pool_size=%s\n' "$session_pool_size"
  } >"${workdir}/tix-tcp-full-kmod-readiness.txt"
  return 1
}

collect_node_api() {
  local node="$1"
  local prefix="${2:-}"
  local dir api_port trustixctl suffix
  dir="$(remote_dir "$node")"
  api_port="$(node_value "$node" "$api_a_port" "$api_b_port")"
  trustixctl="$(node_bin "$node" trustixctl)"
  suffix=""
  if [[ -n "$prefix" ]]; then
    suffix="-${prefix}"
  fi
  run_node "$node" "set +e
dir=$(remote_quote "$dir")
trustixctl=$(remote_quote "$trustixctl")
api=http://127.0.0.1:${api_port}
suffix=$(remote_quote "$suffix")
collect_one() {
  name=\"\$1\"
  shift
  out=\"\${dir}/\${name}\${suffix}.json\"
  tmp=\"\${dir}/.\${name}\${suffix}.json.tmp\"
  if \"\$trustixctl\" -api \"\$api\" \"\$@\" >\"\$tmp\" 2>\"\${dir}/\${name}\${suffix}.err\" && [ -s \"\$tmp\" ]; then
    mv \"\$tmp\" \"\$out\"
  else
    rm -f \"\$tmp\"
  fi
}
collect_one status status
collect_one datapath datapath
collect_one transports transports
collect_one doctor doctor
collect_one bpf bpf maps
"
}

collect_transport_snapshot() {
  local label="$1"
  collect_node_api a "$label" || true
  collect_node_api b "$label" || true
}

collect_failure_snapshot() {
  local label="$1"
  collect_transport_snapshot "failed-${label}" || true
  collect_module_parameters a || true
  collect_module_parameters b || true
  collect_host_state a || true
  collect_host_state b || true
  collect_lan_state a || true
  collect_lan_state b || true
  collect_netem_state_node a || true
  collect_netem_state_node b || true
  collect_kernel_logs a || true
  collect_kernel_logs b || true
  fetch_from_node a "$remote_a" "$workdir/a" || true
  fetch_from_node b "$remote_b" "$workdir/b" || true
}

collect_boot_id() {
  local node="$1"
  local phase="$2"
  local dir
  dir="$(remote_dir "$node")"
  run_node "$node" "set +e
mkdir -p $(remote_quote "$dir")
boot_id=\$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || true)
[ -n \"\$boot_id\" ] || boot_id=\$(sysctl -n kernel.random.boot_id 2>/dev/null || true)
printf '%s\\n' \"\$boot_id\" >$(remote_quote "${dir}/boot-id-${phase}.txt")
uname -a >$(remote_quote "${dir}/uname-${phase}.txt") 2>&1
if [ -r /etc/os-release ]; then
  cat /etc/os-release >$(remote_quote "${dir}/os-release-${phase}.txt") 2>&1
else
  printf 'NAME=unknown\\nID=unknown\\nVERSION_ID=unknown\\n' >$(remote_quote "${dir}/os-release-${phase}.txt")
fi
"
}

collect_binary_identity() {
  local node="$1"
  local dir trustixd
  dir="$(remote_dir "$node")"
  trustixd="$(node_bin "$node" trustixd)"
  run_node "$node" "set -Eeuo pipefail
sha=\$(sha256sum $(remote_quote "$trustixd") | awk '{print \$1}')
if command -v stat >/dev/null 2>&1; then
  size=\$(stat -c %s $(remote_quote "$trustixd"))
else
  size=\$(wc -c <$(remote_quote "$trustixd") | awk '{print \$1}')
fi
version_output=\$($(remote_quote "$trustixd") -version 2>/dev/null || true)
version=\$(printf '%s\n' \"\$version_output\" | awk -F= '/^version=/ && !found {print \$2; found=1}')
commit=\$(printf '%s\n' \"\$version_output\" | awk -F= '/^commit=/ && !found {print \$2; found=1}')
built_at=\$(printf '%s\n' \"\$version_output\" | awk -F= '/^built_at=/ && !found {print \$2; found=1}')
printf '{\"path\":\"%s\",\"sha256\":\"%s\",\"size\":%s,\"version\":\"%s\",\"commit\":\"%s\",\"built_at\":\"%s\"}\\n' $(remote_quote "$trustixd") \"\$sha\" \"\$size\" \"\$version\" \"\$commit\" \"\$built_at\" >$(remote_quote "${dir}/binary-identity.json")
"
}

collect_kernel_logs() {
	local node="$1"
	local dir prefix since
	dir="$(remote_dir "$node")"
	prefix="$(node_value "$node" "$ix_a" "$ix_b")"
	since="$kernel_log_start_iso"
	run_node "$node" "set +e
dir=$(remote_quote "$dir")
prefix=$(remote_quote "$prefix")
since=$(remote_quote "$since")
baseline_file=\"\${dir}.kernel-log-start-uptime\"
mkdir -p \"\$dir\"
if command -v journalctl >/dev/null 2>&1; then
  tmp=\"\${dir}/.\${prefix}-kernel.log.tmp\"
  journal_since=\"\$since\"
  [ -n \"\$journal_since\" ] || journal_since='1 hour ago'
  if journalctl -k -b --since \"\$journal_since\" --no-pager -o short-iso >\"\$tmp\" 2>&1 && [ -s \"\$tmp\" ]; then
    mv \"\$tmp\" \"\${dir}/\${prefix}-kernel.log\"
  else
    rm -f \"\$tmp\"
  fi
fi
if command -v dmesg >/dev/null 2>&1; then
  tmp=\"\${dir}/.\${prefix}-dmesg.log.tmp\"
  dmesg_since=\"\$since\"
  if [ -n \"\$since\" ] && command -v date >/dev/null 2>&1; then
    parsed_since=\$(date -d \"\$since\" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || true)
    [ -z \"\$parsed_since\" ] || dmesg_since=\"\$parsed_since\"
  fi
  if [ -n \"\$dmesg_since\" ] && dmesg --since \"\$dmesg_since\" >\"\$tmp\" 2>&1 && [ -s \"\$tmp\" ]; then
    mv \"\$tmp\" \"\${dir}/\${prefix}-dmesg.log\"
  elif [ -s \"\$baseline_file\" ]; then
    baseline=\$(cat \"\$baseline_file\" 2>/dev/null || true)
    dmesg 2>/dev/null | awk -v start=\"\$baseline\" '
      {
        stamp=\$1
        if (stamp == \"[\") stamp=\$2
        gsub(/^\\[/, \"\", stamp)
        gsub(/\\].*\$/, \"\", stamp)
        if (stamp ~ /^[0-9]+([.][0-9]+)?\$/ && stamp + 0 >= start + 0) print
      }
    ' >\"\$tmp\"
    if [ ! -s \"\$tmp\" ]; then
      printf 'trustix-soak: no dmesg entries since uptime %s\\n' \"\$baseline\" >\"\$tmp\"
    fi
    mv \"\$tmp\" \"\${dir}/\${prefix}-dmesg.log\"
  elif dmesg -T >\"\$tmp\" 2>&1 && [ -s \"\$tmp\" ]; then
    mv \"\$tmp\" \"\${dir}/\${prefix}-dmesg.log\"
  elif dmesg >\"\$tmp\" 2>&1 && [ -s \"\$tmp\" ]; then
    mv \"\$tmp\" \"\${dir}/\${prefix}-dmesg.log\"
  else
    rm -f \"\$tmp\"
  fi
fi
lsmod | awk '/^trustix_/ {print}' >$(remote_quote "${dir}/${prefix}-lsmod.txt") 2>&1
{
  if [ -d /sys/fs/pstore ]; then
    echo 'status=mounted'
    found=0
    for f in /sys/fs/pstore/*; do
      [ -f \"\$f\" ] || continue
      found=1
      echo \"===== \$f =====\"
      sed -n '1,220p' \"\$f\" 2>&1
    done
    [ \"\$found\" -eq 1 ] || echo 'status=empty'
  else
    echo 'status=unavailable'
  fi
} >$(remote_quote "${dir}/${prefix}-pstore.txt") 2>&1
"
}

collect_module_parameters() {
  local node="$1"
  local label="${2:-}"
  local dir output
  dir="$(remote_dir "$node")"
  if [[ -n "$label" ]]; then
    [[ "$label" =~ ^[A-Za-z0-9_.-]+$ ]] || return 1
    output="${dir}/module-parameters-${label}.txt"
  else
    output="${dir}/module-parameters.txt"
  fi
  run_node "$node" "set +e
out=$(remote_quote "$output")
: >\"\$out\"
for module_dir in /sys/module/trustix_*/parameters; do
  [ -d \"\$module_dir\" ] || continue
  module=\"\${module_dir#/sys/module/}\"
  module=\"\${module%/parameters}\"
  printf '===== %s =====\\n' \"\$module\" >>\"\$out\"
  for param in \"\$module_dir\"/*; do
    [ -f \"\$param\" ] || continue
    name=\"\${param##*/}\"
    value=\$(cat \"\$param\" 2>/dev/null || true)
    printf '%s=%s\\n' \"\$name\" \"\$value\" >>\"\$out\"
  done
done
"
}

collect_host_state() {
  local node="$1"
  local dir prefix underlay_if
  dir="$(remote_dir "$node")"
  prefix="$(node_value "$node" "$ix_a" "$ix_b")"
  underlay_if="$(node_value "$node" "$underlay_a_if" "$underlay_b_if")"
  run_node "$node" "set +e
out=$(remote_quote "${dir}/${prefix}-host-state.txt")
underlay_if=$(remote_quote "$underlay_if")
{
  cpu_count=''
  if command -v nproc >/dev/null 2>&1; then
    cpu_count=\$(nproc 2>/dev/null || true)
  fi
  case \"\$cpu_count\" in ''|*[!0-9]*)
    if command -v getconf >/dev/null 2>&1; then
      cpu_count=\$(getconf _NPROCESSORS_ONLN 2>/dev/null || true)
    fi
    ;;
  esac
  case \"\$cpu_count\" in ''|*[!0-9]*)
    if [ -r /proc/cpuinfo ]; then
      cpu_count=\$(awk '/^processor[[:space:]]*:/{n++} END{if (n > 0) print n}' /proc/cpuinfo 2>/dev/null || true)
    fi
    ;;
  esac
  [ -n \"\$cpu_count\" ] || cpu_count=unknown
  printf 'cpu_count=%s\\n' \"\$cpu_count\"
  printf 'machine=%s\\n' \"\$(uname -m 2>/dev/null || true)\"
  printf 'kernel_release=%s\\n' \"\$(uname -r 2>/dev/null || true)\"
  printf 'underlay_interface=%s\\n' \"\$underlay_if\"
  driver_for_iface() {
    iface=\"\$1\"
    driver=''
    if [ -n \"\$iface\" ] && [ -e \"/sys/class/net/\$iface/device/driver\" ]; then
      driver_path=\$(readlink -f \"/sys/class/net/\$iface/device/driver\" 2>/dev/null || readlink \"/sys/class/net/\$iface/device/driver\" 2>/dev/null || true)
      driver=\"\${driver_path##*/}\"
    fi
    [ -n \"\$driver\" ] || driver=none
    printf '%s\\n' \"\$driver\"
  }
  if [ -n \"\$underlay_if\" ]; then
    printf 'underlay_driver=%s\\n' \"\$(driver_for_iface \"\$underlay_if\")\"
  else
    printf 'underlay_driver=unknown\\n'
  fi
  echo '===== ip-route ====='
  ip route show table main 2>&1 || true
  echo '===== tcp-listeners ====='
  if command -v ss >/dev/null 2>&1; then
    ss -ltnup 2>&1 || true
    echo '===== tcp-sockets ====='
    ss -tanp 2>&1 || true
  elif command -v netstat >/dev/null 2>&1; then
    netstat -ltnp 2>&1 || true
    echo '===== tcp-sockets ====='
    netstat -tanp 2>&1 || true
  else
    echo 'ss/netstat unavailable'
  fi
  echo '===== net-drivers ====='
  for iface_path in /sys/class/net/*; do
    [ -e \"\$iface_path\" ] || continue
    iface=\"\${iface_path##*/}\"
    [ -n \"\$iface\" ] || continue
    printf 'net_driver[%s]=%s\\n' \"\$iface\" \"\$(driver_for_iface \"\$iface\")\"
  done
} >\"\$out\" 2>&1
"
}

collect_lan_state() {
  local node="$1"
  local dir prefix lan_if
  dir="$(remote_dir "$node")"
  prefix="$(node_value "$node" "$ix_a" "$ix_b")"
  lan_if="$(node_value "$node" "$lan_if_a" "$lan_if_b")"
  run_node "$node" "set +e
out=$(remote_quote "${dir}/${prefix}-lan-state.txt")
lan_if=$(remote_quote "$lan_if")
{
  printf 'interface=%s\\n' \"\$lan_if\"
  if [ -r \"/sys/class/net/\$lan_if/tx_queue_len\" ]; then
    printf 'tx_queue_len=%s\\n' \"\$(cat \"/sys/class/net/\$lan_if/tx_queue_len\" 2>/dev/null || true)\"
  else
    printf 'tx_queue_len=missing\\n'
  fi
  echo '===== ip-link ====='
  ip -d link show \"\$lan_if\" 2>&1 || true
  if command -v ethtool >/dev/null 2>&1; then
    echo '===== ethtool-features ====='
    ethtool -k \"\$lan_if\" 2>&1 || true
  fi
} >\"\$out\" 2>&1
"
}

run_ping_checks() {
  run_node a "set -Eeuo pipefail
ip_cmd=\$(command -v ip)
for _ in \$(seq 1 20); do
  if \"\$ip_cmd\" netns exec $(remote_quote "$host_ns_a") ping -c 1 -W 1 $(remote_quote "$host_b_ip") >/dev/null 2>&1; then exit 0; fi
  sleep 1
done
exit 1
"
  run_node b "set -Eeuo pipefail
ip_cmd=\$(command -v ip)
for _ in \$(seq 1 20); do
  if \"\$ip_cmd\" netns exec $(remote_quote "$host_ns_b") ping -c 1 -W 1 $(remote_quote "$host_a_ip") >/dev/null 2>&1; then exit 0; fi
  sleep 1
done
exit 1
"
}

case_endpoint_needs_tcp_listener() {
  local transport="${1:-$(case_endpoint_transport)}"
  case "$transport" in
    tcp|websocket|http_connect|tix_tcp) return 0 ;;
    *) return 1 ;;
  esac
}

wait_for_tcp_listener() {
  local node="$1"
  local port="${2:-$(node_value "$node" "$data_a_port" "$data_b_port")}"
  run_node "$node" "set -Eeuo pipefail
port_hex=\$(printf '%04X' ${port})
proc_tcp_listening() {
  local file=\"\$1\"
  [ -r \"\$file\" ] || return 1
  awk -v p=\"\$port_hex\" '
    NR > 1 {
      split(\$2, local_addr, \":\")
      if (local_addr[2] == p && \$4 == \"0A\") {
        found = 1
      }
    }
    END { exit found ? 0 : 1 }
  ' \"\$file\"
}
for _ in \$(seq 1 80); do
  if command -v ss >/dev/null 2>&1; then
    if ss -ltnH 2>/dev/null | awk '{print \$4}' | grep -Eq '(^|[.:])${port}$'; then
      exit 0
    fi
  elif command -v netstat >/dev/null 2>&1; then
    if netstat -ltn 2>/dev/null | awk 'NR > 2 {print \$4}' | grep -Eq '(^|[.:])${port}$'; then
      exit 0
    fi
  fi
  if proc_tcp_listening /proc/net/tcp || proc_tcp_listening /proc/net/tcp6; then
    exit 0
  fi
  sleep 1
done
{
  echo 'listener wait failed for tcp port ${port}'
  echo '===== ss ====='
  ss -ltnp 2>&1 || true
  echo '===== netstat ====='
  netstat -ltnp 2>&1 || true
  echo '===== proc tcp ====='
  cat /proc/net/tcp 2>/dev/null || true
  echo '===== proc tcp6 ====='
  cat /proc/net/tcp6 2>/dev/null || true
} >&2
exit 1
"
}

wait_for_endpoint_listeners() {
  local index transport
  if case_is_multi_endpoint; then
    index=0
    for transport in "${endpoint_transports[@]}"; do
      if case_endpoint_needs_tcp_listener "$transport"; then
        wait_for_tcp_listener a "$(case_endpoint_port_for_index a "$index")"
        wait_for_tcp_listener b "$(case_endpoint_port_for_index b "$index")"
      fi
      index=$((index + 1))
    done
    return 0
  fi
  if ! case_endpoint_needs_tcp_listener; then
    return 0
  fi
  wait_for_tcp_listener a
  wait_for_tcp_listener b
}

run_tcp_health_direction() {
  local client="$1"
  local server="$2"
  local dst_ip="$3"
  local label="$4"
  local server_dir client_dir server_ns client_ns
  server_dir="$(remote_dir "$server")"
  client_dir="$(remote_dir "$client")"
  server_ns="$(node_value "$server" "$host_ns_a" "$host_ns_b")"
  client_ns="$(node_value "$client" "$host_ns_a" "$host_ns_b")"
  run_node "$server" "set -Eeuo pipefail
ip_cmd=\$(command -v ip)
rm -f $(remote_quote "${server_dir}/health-${label}-server.pid") $(remote_quote "${server_dir}/health-${label}-server.json")
\"\$ip_cmd\" netns exec $(remote_quote "$server_ns") iperf3 -s -1 -p ${health_port} -J >$(remote_quote "${server_dir}/health-${label}-server.json") 2>$(remote_quote "${server_dir}/health-${label}-server.err") </dev/null &
echo \$! >$(remote_quote "${server_dir}/health-${label}-server.pid")
"
  sleep 1
  run_node "$client" "set -Eeuo pipefail
ip_cmd=\$(command -v ip)
if command -v timeout >/dev/null 2>&1; then
  timeout 20s \"\$ip_cmd\" netns exec $(remote_quote "$client_ns") iperf3 -c $(remote_quote "$dst_ip") -p ${health_port} -t 1 -P 1 -J >$(remote_quote "${client_dir}/health-${label}-client.json") 2>$(remote_quote "${client_dir}/health-${label}-client.err")
else
  \"\$ip_cmd\" netns exec $(remote_quote "$client_ns") iperf3 -c $(remote_quote "$dst_ip") -p ${health_port} -t 1 -P 1 -J >$(remote_quote "${client_dir}/health-${label}-client.json") 2>$(remote_quote "${client_dir}/health-${label}-client.err")
fi
"
  run_node "$server" "set +e
pid=\$(cat $(remote_quote "${server_dir}/health-${label}-server.pid") 2>/dev/null || true)
[ -z \"\$pid\" ] && exit 0
for _ in \$(seq 1 20); do
  kill -0 \"\$pid\" >/dev/null 2>&1 || exit 0
  sleep 1
done
kill \"\$pid\" >/dev/null 2>&1 || true
exit 0
"
}

run_tcp_health_checks() {
  run_tcp_health_direction a b "$host_b_ip" "a-to-b"
  run_tcp_health_direction b a "$host_a_ip" "b-to-a"
}

run_pinned_mixed_health_checks() {
  run_tcp_health_direction a b "$host_b_ip" "a-to-b-udp"
  run_tcp_health_direction a b "$mixed_host_b_ip" "a-to-b-tix-tcp"
  run_tcp_health_direction b a "$host_a_ip" "b-to-a-udp"
  run_tcp_health_direction b a "$mixed_host_a_ip" "b-to-a-tix-tcp"
}

run_pinned_mixed_ping_checks() {
  run_node a "set -Eeuo pipefail
ip_cmd=\$(command -v ip)
for pair in $(remote_quote "${host_a_ip},${host_b_ip}") $(remote_quote "${mixed_host_a_ip},${mixed_host_b_ip}"); do
  src=\${pair%%,*}
  dst=\${pair#*,}
  ok=0
  for _ in \$(seq 1 20); do
    if \"\$ip_cmd\" netns exec $(remote_quote "$host_ns_a") ping -I \"\$src\" -c 1 -W 1 \"\$dst\" >/dev/null 2>&1; then ok=1; break; fi
    sleep 1
  done
  [ \"\$ok\" -eq 1 ]
done
"
  run_node b "set -Eeuo pipefail
ip_cmd=\$(command -v ip)
for pair in $(remote_quote "${host_b_ip},${host_a_ip}") $(remote_quote "${mixed_host_b_ip},${mixed_host_a_ip}"); do
  src=\${pair%%,*}
  dst=\${pair#*,}
  ok=0
  for _ in \$(seq 1 20); do
    if \"\$ip_cmd\" netns exec $(remote_quote "$host_ns_b") ping -I \"\$src\" -c 1 -W 1 \"\$dst\" >/dev/null 2>&1; then ok=1; break; fi
    sleep 1
  done
  [ \"\$ok\" -eq 1 ]
done
"
}

run_connectivity_checks() {
  if case_uses_pinned_mixed_routes; then
    if [[ "$(case_fast_path)" == "full_kmod" ]]; then
      run_pinned_mixed_ping_checks
    fi
    run_pinned_mixed_health_checks
    return
  fi
  case "$(case_fast_path)" in
    route_gso|secure_kudp|secure_tix_tcp_kernel)
      run_tcp_health_checks
      return
      ;;
  esac
  if case_uses_secure_kudp_fast_path; then
    run_tcp_health_checks
    return
  fi
  case "$(case_fast_path)" in
    *) run_ping_checks ;;
  esac
}

start_iperf_server() {
  local node="$1"
  local port="${2:-$iperf_port}"
  local label="${3:-}"
  local bind_ip="${4:-}"
  local dir host_ns artifact_suffix bind_args
  dir="$(remote_dir "$node")"
  host_ns="$(node_value "$node" "$host_ns_a" "$host_ns_b")"
  artifact_suffix=""
  if [[ -n "$label" ]]; then
    artifact_suffix="-${label}"
  fi
  bind_args=""
  if [[ -n "$bind_ip" ]]; then
    bind_args="-B $(remote_quote "$bind_ip")"
  fi
  run_node "$node" "set -Eeuo pipefail
ip_cmd=\$(command -v ip)
pid_file=$(remote_quote "${dir}/iperf3-server${artifact_suffix}.pid")
json_file=$(remote_quote "${dir}/iperf3-server${artifact_suffix}.json")
err_file=$(remote_quote "${dir}/iperf3-server${artifact_suffix}.err")
if [ -f \"\$pid_file\" ]; then
  old_pid=\$(cat \"\$pid_file\" 2>/dev/null || true)
  if [ -n \"\$old_pid\" ]; then
    kill \"\$old_pid\" >/dev/null 2>&1 || true
  fi
fi
if command -v ss >/dev/null 2>&1; then
  for old_pid in \$(\"\$ip_cmd\" netns exec $(remote_quote "$host_ns") ss -ltnp \"sport = :${port}\" 2>/dev/null | sed -n 's/.*pid=\\([0-9][0-9]*\\).*/\\1/p' | sort -u); do
    kill \"\$old_pid\" >/dev/null 2>&1 || true
  done
fi
rm -f \"\$pid_file\" \"\$json_file\" \"\$err_file\"
if command -v nohup >/dev/null 2>&1; then
  nohup \"\$ip_cmd\" netns exec $(remote_quote "$host_ns") sh -c 'echo \$\$ >\"\$1\"; shift; exec iperf3 \"\$@\"' sh \"\$pid_file\" ${bind_args} -s -1 -p ${port} -J >\"\$json_file\" 2>\"\$err_file\" </dev/null &
elif command -v setsid >/dev/null 2>&1; then
  setsid \"\$ip_cmd\" netns exec $(remote_quote "$host_ns") sh -c 'echo \$\$ >\"\$1\"; shift; exec iperf3 \"\$@\"' sh \"\$pid_file\" ${bind_args} -s -1 -p ${port} -J >\"\$json_file\" 2>\"\$err_file\" </dev/null &
else
  \"\$ip_cmd\" netns exec $(remote_quote "$host_ns") sh -c 'echo \$\$ >\"\$1\"; shift; exec iperf3 \"\$@\"' sh \"\$pid_file\" ${bind_args} -s -1 -p ${port} -J >\"\$json_file\" 2>\"\$err_file\" </dev/null &
fi
for _ in \$(seq 1 10); do
  [ -s \"\$pid_file\" ] && break
  sleep 1
done
pid=\$(cat \"\$pid_file\" 2>/dev/null || true)
if [ -z \"\$pid\" ]; then
  printf '%s\n' 'trustix-cross-host-runner: iperf server did not write pid' >>\"\$err_file\"
  exit 1
fi
if ! kill -0 \"\$pid\" >/dev/null 2>&1; then
  printf '%s\n' 'trustix-cross-host-runner: iperf server exited during startup' >>\"\$err_file\"
  exit 1
fi
if grep -Fq '\"error\"' \"\$json_file\" 2>/dev/null || grep -iq 'address already in use\\|unable to start listener' \"\$err_file\" \"\$json_file\" 2>/dev/null; then
  printf '%s\n' 'trustix-cross-host-runner: iperf server startup failed' >>\"\$err_file\"
  exit 1
fi
"
}

run_iperf_client() {
  local node="$1"
  local dst_ip="$2"
  local out_name="$3"
  local port="${4:-$iperf_port}"
  local source_ip="${5:-}"
  local dir host_ns mode_args bind_args client_port_args
  dir="$(remote_dir "$node")"
  host_ns="$(node_value "$node" "$host_ns_a" "$host_ns_b")"
  case "$iperf_mode" in
    bidir) mode_args="--bidir" ;;
    forward) mode_args="" ;;
    reverse) mode_args="-R" ;;
  esac
  bind_args=""
  if [[ -n "$source_ip" ]]; then
    bind_args="-B $(remote_quote "$source_ip")"
  fi
  client_port_args=""
  if [[ "$iperf_client_port" -gt 0 ]]; then
    client_port_args="--cport ${iperf_client_port}"
  fi
  run_node "$node" "set -Eeuo pipefail
ip_cmd=\$(command -v ip)
out=$(remote_quote "${dir}/${out_name}")
err=$(remote_quote "${dir}/${out_name%.json}.err")
rc=0
if command -v timeout >/dev/null 2>&1; then
  timeout ${iperf_timeout}s \"\$ip_cmd\" netns exec $(remote_quote "$host_ns") iperf3 ${bind_args} ${client_port_args} -c $(remote_quote "$dst_ip") -p ${port} -t ${iperf_seconds} -P ${iperf_parallel} ${mode_args} -J >\"\$out\" 2>\"\$err\" || rc=\$?
else
  \"\$ip_cmd\" netns exec $(remote_quote "$host_ns") iperf3 ${bind_args} ${client_port_args} -c $(remote_quote "$dst_ip") -p ${port} -t ${iperf_seconds} -P ${iperf_parallel} ${mode_args} -J >\"\$out\" 2>\"\$err\" || rc=\$?
fi
if [ \"\$rc\" -eq 0 ]; then
  json_error_pattern='\"error\"'
  json_sum_sent_pattern='\"sum_sent\"'
  json_sum_received_pattern='\"sum_received\"'
  if grep -Fq \"\$json_error_pattern\" \"\$out\" 2>/dev/null; then
    printf '%s\\n' 'trustix-cross-host-runner: iperf JSON contains error' >>\"\$err\"
    rc=1
  elif ! grep -Fq \"\$json_sum_sent_pattern\" \"\$out\" 2>/dev/null && ! grep -Fq \"\$json_sum_received_pattern\" \"\$out\" 2>/dev/null; then
    printf '%s\\n' 'trustix-cross-host-runner: iperf JSON missing final summary' >>\"\$err\"
    rc=1
  fi
fi
exit \"\$rc\"
"
}

assert_iperf_continuity() {
  local node="$1"
  local out_name="$2"
  local label="$3"
  local dir
  dir="$(remote_dir "$node")"
  run_node "$node" "cat $(remote_quote "${dir}/${out_name}")" | python3 -c '
import json
import sys

label = sys.argv[1]
mode = sys.argv[2]
max_allowed = int(sys.argv[3])
payload = json.load(sys.stdin)
intervals = payload.get("intervals") or []
if not isinstance(intervals, list) or not intervals:
    raise SystemExit(f"{label}: iperf JSON has no throughput intervals")
directions = [("reverse" if mode == "reverse" else "forward", "sum")]
if mode == "bidir":
    directions.append(("reverse", "sum_bidir_reverse"))
rows = []
failed = False
for direction, key in directions:
    missing = 0
    zero = 0
    run = 0
    max_run = 0
    for interval in intervals:
        summary = interval.get(key) if isinstance(interval, dict) else None
        if not isinstance(summary, dict):
            missing += 1
            run += 1
            max_run = max(max_run, run)
            continue
        value = summary.get("bits_per_second")
        if not isinstance(value, (int, float)) or value <= 0:
            zero += 1
            run += 1
            max_run = max(max_run, run)
        else:
            run = 0
    status = "pass" if missing == 0 and max_run <= max_allowed else "fail"
    rows.append({
        "direction": direction,
        "intervals": len(intervals),
        "missing_intervals": missing,
        "zero_intervals": zero,
        "max_consecutive_zero_intervals": max_run,
        "allowed": max_allowed,
        "status": status,
    })
    failed = failed or status != "pass"
print(json.dumps({"label": label, "directions": rows, "status": "fail" if failed else "pass"}, sort_keys=True))
if failed:
    details = ", ".join(
        "{direction}:missing={missing_intervals},zero={zero_intervals},max_run={max_consecutive_zero_intervals}".format(**row)
        for row in rows
    )
    raise SystemExit(
        f"{label}: iperf continuity failed ({details}); allowed consecutive zero intervals={max_allowed}"
    )
' "$label" "$iperf_mode" "$max_consecutive_zero_intervals" | tee -a "$workdir/iperf-continuity-gates.jsonl"
}

run_iperf_client_with_snapshot() {
  local node="$1"
  local dst_ip="$2"
  local out_name="$3"
  local port="${4:-$iperf_port}"
  local source_ip="${5:-}"
  local client_pid snapshot_label rc
  run_iperf_client "$node" "$dst_ip" "$out_name" "$port" "$source_ip" &
  client_pid=$!
  if [[ "$transport_snapshot_delay" -gt 0 ]]; then
    sleep "$transport_snapshot_delay"
  fi
  snapshot_label="${out_name%.json}"
  snapshot_label="${snapshot_label#iperf3-}"
  collect_transport_snapshot "during-${snapshot_label}"
  if wait "$client_pid"; then
    if assert_iperf_continuity "$node" "$out_name" "$snapshot_label"; then
      return 0
    else
      rc=$?
    fi
  else
    rc=$?
  fi
  collect_failure_snapshot "$snapshot_label"
  return "$rc"
}

assert_iperf_min_gbps() {
  local node="$1"
  local out_name="$2"
  local label="$3"
  local minimum="$4"
  local dir
  decimal_is_zero "$minimum" && return 0
  dir="$(remote_dir "$node")"
  run_node "$node" "cat $(remote_quote "${dir}/${out_name}")" | python3 -c '
import json
import sys

label = sys.argv[1]
minimum = float(sys.argv[2])
payload = json.load(sys.stdin)
end = payload.get("end") or {}
sent = (end.get("sum_sent") or {}).get("bits_per_second")
received = (end.get("sum_received") or {}).get("bits_per_second")
if not isinstance(sent, (int, float)) or not isinstance(received, (int, float)):
    raise SystemExit(f"{label}: iperf JSON is missing numeric end.sum_sent/end.sum_received throughput")
sent_gbps = sent / 1_000_000_000
received_gbps = received / 1_000_000_000
status = "pass" if sent_gbps >= minimum and received_gbps >= minimum else "fail"
print(json.dumps({
    "label": label,
    "sent_gbps": round(sent_gbps, 6),
    "received_gbps": round(received_gbps, 6),
    "min_gbps": minimum,
    "status": status,
}, sort_keys=True))
if status != "pass":
    raise SystemExit(
        f"{label}: sent/received {sent_gbps:.3f}/{received_gbps:.3f} Gbps "
        f"is below minimum {minimum:.3f} Gbps"
    )
' "$label" "$minimum" | tee -a "$workdir/mixed-throughput-gates.jsonl"
}

iperf_client_missing_server_results_only() {
  local node="$1"
  local out_name="$2"
  local dir
  dir="$(remote_dir "$node")"
  run_node "$node" "set -Eeuo pipefail
out=$(remote_quote "${dir}/${out_name}")
[ -s \"\$out\" ]
grep -Fq '\"error\"' \"\$out\"
grep -Fq 'unable to receive results' \"\$out\"
grep -Fq '\"intervals\"' \"\$out\"
"
}

iperf_server_has_final_summary() {
  local node="$1"
  local dir
  dir="$(remote_dir "$node")"
  run_node "$node" "set -Eeuo pipefail
out=$(remote_quote "${dir}/iperf3-server.json")
[ -s \"\$out\" ]
grep -Eq '\"sum_(sent|received|sent_bidir_reverse|received_bidir_reverse)\"' \"\$out\"
"
}

accept_iperf_server_summary_artifact() {
  local node="$1"
  local label="$2"
  local dir
  dir="$(remote_dir "$node")"
  run_node "$node" "set -Eeuo pipefail
out=$(remote_quote "${dir}/iperf3-server.json")
raw=$(remote_quote "${dir}/server-control-error-${label}.raw.json")
marker=$(remote_quote "${dir}/iperf3-server-${label}.accepted-control-error.txt")
tmp=\${out}.accepted
[ -s \"\$out\" ]
if ! grep -Fq '\"error\"' \"\$out\"; then
  exit 0
fi
grep -Fq 'unable to receive control message' \"\$out\"
grep -Fq 'Bad file descriptor' \"\$out\"
grep -Eq '\"sum_(sent|received|sent_bidir_reverse|received_bidir_reverse)\"' \"\$out\"
cp \"\$out\" \"\$raw\"
awk '
  /\"error\"[[:space:]]*:/ && /unable to receive control message/ && /Bad file descriptor/ {
    if (n > 0 && lines[n] ~ /^[[:space:]]*},[[:space:]]*$/) {
      sub(/,[[:space:]]*$/, \"\", lines[n])
    }
    next
  }
  { lines[++n] = \$0 }
  END {
    for (i = 1; i <= n; i++) print lines[i]
  }
' \"\$raw\" >\"\$tmp\"
mv \"\$tmp\" \"\$out\"
{
  printf 'accepted_server_summary=1\\n'
  printf 'raw_artifact=%s\\n' \"\$raw\"
  printf 'reason=client_missing_server_results_only\\n'
} >\"\$marker\"
"
}

iperf_artifact_suffix() {
  case "$iperf_mode" in
    bidir) printf 'bidir\n' ;;
    forward) printf 'forward\n' ;;
    reverse) printf 'reverse\n' ;;
  esac
}

wait_iperf_server_exit() {
  local node="$1"
  local port="${2:-$iperf_port}"
  local label="${3:-}"
  local dir host_ns artifact_suffix
  dir="$(remote_dir "$node")"
  host_ns="$(node_value "$node" "$host_ns_a" "$host_ns_b")"
  artifact_suffix=""
  if [[ -n "$label" ]]; then
    artifact_suffix="-${label}"
  fi
  run_node "$node" "set +e
ip_cmd=\$(command -v ip)
pid_file=$(remote_quote "${dir}/iperf3-server${artifact_suffix}.pid")
pid=\$(cat \"\$pid_file\" 2>/dev/null || true)
if [ -n \"\$pid\" ]; then
  for _ in \$(seq 1 40); do
    kill -0 \"\$pid\" >/dev/null 2>&1 || break
    sleep 1
  done
  kill \"\$pid\" >/dev/null 2>&1 || true
  sleep 1
  kill -9 \"\$pid\" >/dev/null 2>&1 || true
fi
if command -v ss >/dev/null 2>&1; then
  for old_pid in \$(\"\$ip_cmd\" netns exec $(remote_quote "$host_ns") ss -ltnp \"sport = :${port}\" 2>/dev/null | sed -n 's/.*pid=\\([0-9][0-9]*\\).*/\\1/p' | sort -u); do
    kill \"\$old_pid\" >/dev/null 2>&1 || true
  done
  sleep 1
fi
rm -f \"\$pid_file\"
exit 0
"
}

run_pinned_mixed_iperf_direction() {
  local client="$1"
  local server="$2"
  local pair_label="$3"
  local suffix udp_dst tix_tcp_dst udp_src tix_tcp_src
  local udp_out tix_tcp_out udp_pid tix_tcp_pid udp_rc=0 tix_tcp_rc=0
  suffix="$(iperf_artifact_suffix)"
  udp_dst="$(node_value "$server" "$host_a_ip" "$host_b_ip")"
  tix_tcp_dst="$(node_value "$server" "$mixed_host_a_ip" "$mixed_host_b_ip")"
  udp_src="$(node_value "$client" "$host_a_ip" "$host_b_ip")"
  tix_tcp_src="$(node_value "$client" "$mixed_host_a_ip" "$mixed_host_b_ip")"
  udp_out="iperf3-${pair_label}-udp-${suffix}.json"
  tix_tcp_out="iperf3-${pair_label}-tix-tcp-${suffix}.json"

  start_iperf_server "$server" "$iperf_port" udp "$udp_dst"
  start_iperf_server "$server" "$mixed_iperf_port" tix-tcp "$tix_tcp_dst"
  sleep 1
  run_iperf_client "$client" "$udp_dst" "$udp_out" "$iperf_port" "$udp_src" &
  udp_pid=$!
  run_iperf_client "$client" "$tix_tcp_dst" "$tix_tcp_out" "$mixed_iperf_port" "$tix_tcp_src" &
  tix_tcp_pid=$!
  if [[ "$transport_snapshot_delay" -gt 0 ]]; then
    sleep "$transport_snapshot_delay"
  fi
  collect_transport_snapshot "during-${pair_label}-mixed-${suffix}"
  if wait "$udp_pid"; then
    :
  else
    udp_rc=$?
  fi
  if wait "$tix_tcp_pid"; then
    :
  else
    tix_tcp_rc=$?
  fi
  wait_iperf_server_exit "$server" "$iperf_port" udp
  wait_iperf_server_exit "$server" "$mixed_iperf_port" tix-tcp
  if [[ "$udp_rc" -eq 0 ]] && ! assert_iperf_continuity "$client" "$udp_out" "${pair_label}-udp-${suffix}"; then
    udp_rc=1
  fi
  if [[ "$tix_tcp_rc" -eq 0 ]] && ! assert_iperf_continuity "$client" "$tix_tcp_out" "${pair_label}-tix-tcp-${suffix}"; then
    tix_tcp_rc=1
  fi
  if [[ "$udp_rc" -eq 0 ]] && ! assert_iperf_min_gbps "$client" "$udp_out" "${pair_label}-udp-${suffix}" "$mixed_udp_min_gbps"; then
    udp_rc=1
  fi
  if [[ "$tix_tcp_rc" -eq 0 ]] && ! assert_iperf_min_gbps "$client" "$tix_tcp_out" "${pair_label}-tix-tcp-${suffix}" "$mixed_tix_tcp_min_gbps"; then
    tix_tcp_rc=1
  fi
  if [[ "$udp_rc" -ne 0 || "$tix_tcp_rc" -ne 0 ]]; then
    collect_failure_snapshot "${pair_label}-mixed-${suffix}"
    return 1
  fi
}

assert_pinned_mixed_sessions_node() {
  local node="$1"
  local dir api_port trustixctl peer_node udp_endpoint tix_tcp_endpoint
  dir="$(remote_dir "$node")"
  api_port="$(node_value "$node" "$api_a_port" "$api_b_port")"
  trustixctl="$(node_bin "$node" trustixctl)"
  peer_node="$(node_value "$node" b a)"
  udp_endpoint="$(case_endpoint_name_for_transport "$peer_node" udp)"
  tix_tcp_endpoint="$(case_endpoint_name_for_transport "$peer_node" tix_tcp)"
  run_node "$node" "set -Eeuo pipefail
out=$(remote_quote "${dir}/pinned-mixed-session-assert.json")
$(remote_quote "$trustixctl") -api http://127.0.0.1:${api_port} transports >\"\$out\"
grep -Eq '\"endpoint\"[[:space:]]*:[[:space:]]*\"${udp_endpoint}\"' \"\$out\"
grep -Eq '\"endpoint\"[[:space:]]*:[[:space:]]*\"${tix_tcp_endpoint}\"' \"\$out\"
"
}

assert_pinned_mixed_sessions() {
  case_uses_pinned_mixed_routes || return 0
  assert_pinned_mixed_sessions_node a
  assert_pinned_mixed_sessions_node b
}

run_iperf_bidirectional_artifacts() {
  local suffix rc=0 client_rc out_name
  if case_uses_pinned_mixed_routes; then
    case "$iperf_directions" in
      both|a2b|a-to-b) run_pinned_mixed_iperf_direction a b a-to-b || rc=$? ;;
    esac
    case "$iperf_directions" in
      both|b2a|b-to-a) run_pinned_mixed_iperf_direction b a b-to-a || rc=$? ;;
    esac
    return "$rc"
  fi
  suffix="$(iperf_artifact_suffix)"
  case "$iperf_directions" in
    both|a2b|a-to-b)
      start_iperf_server b
      sleep 1
      out_name="iperf3-a-to-b-${suffix}.json"
      client_rc=0
      run_iperf_client_with_snapshot a "$host_b_ip" "$out_name" || client_rc=$?
      wait_iperf_server_exit b
      if [[ "$client_rc" -ne 0 ]]; then
        if iperf_client_missing_server_results_only a "$out_name" && iperf_server_has_final_summary b; then
          accept_iperf_server_summary_artifact b "a-to-b-${suffix}"
          if assert_iperf_continuity b "iperf3-server.json" "a-to-b-${suffix}-server"; then
            log "iperf a-to-b client missed server results; accepting server-side summary artifact"
          else
            rc=1
          fi
        else
          rc=$client_rc
        fi
      fi
      ;;
  esac

  case "$iperf_directions" in
    both|b2a|b-to-a)
      start_iperf_server a
      sleep 1
      out_name="iperf3-b-to-a-${suffix}.json"
      client_rc=0
      run_iperf_client_with_snapshot b "$host_a_ip" "$out_name" || client_rc=$?
      wait_iperf_server_exit a
      if [[ "$client_rc" -ne 0 ]]; then
        if iperf_client_missing_server_results_only b "$out_name" && iperf_server_has_final_summary a; then
          accept_iperf_server_summary_artifact a "b-to-a-${suffix}"
          if assert_iperf_continuity a "iperf3-server.json" "b-to-a-${suffix}-server"; then
            log "iperf b-to-a client missed server results; accepting server-side summary artifact"
          else
            rc=1
          fi
        else
          rc=$client_rc
        fi
      fi
      ;;
  esac
  return "$rc"
}

stop_daemon() {
  local node="$1"
  local dir unit
  dir="$(remote_dir "$node")"
  unit="$(daemon_unit_name "$node")"
  run_node "$node" "set +e
pid_file=$(remote_quote "${dir}/trustixd.pid")
log_file=$(remote_quote "${dir}/logs/trustixd.log")
shutdown_file=$(remote_quote "${dir}/logs/trustixd-shutdown.txt")
status=0
reason=clean
pid=
daemon_alive() {
  [ -n \"\$pid\" ] || return 1
  kill -0 \"\$pid\" >/dev/null 2>&1 || return 1
  state=\$(awk '{print \$3}' \"/proc/\${pid}/stat\" 2>/dev/null || true)
  [ \"\$state\" != Z ]
}
if [ $(remote_quote "$daemon_supervisor") = systemd ]; then
  active_state=\$(systemctl show --property=ActiveState --value $(remote_quote "$unit") 2>/dev/null || true)
  pid=\$(systemctl show --property=MainPID --value $(remote_quote "$unit") 2>/dev/null || true)
  case \"\$pid\" in 0|*[!0-9]*) pid= ;; esac
  if [ \"\$active_state\" != active ]; then
    status=1
    reason=unexpected-exit
  fi
  systemctl stop $(remote_quote "$unit") >/dev/null 2>&1 || {
    status=1
    reason=term-failed
  }
  for _ in \$(seq 1 40); do
    systemctl is-active --quiet $(remote_quote "$unit") || break
    sleep 1
  done
  if systemctl is-active --quiet $(remote_quote "$unit"); then
    systemctl kill --kill-who=all --signal=KILL $(remote_quote "$unit") >/dev/null 2>&1 || true
    status=124
    reason=forced-kill
  fi
  systemctl reset-failed $(remote_quote "$unit") >/dev/null 2>&1 || true
elif [ ! -s \"\$pid_file\" ]; then
  status=1
  reason=missing-pid
else
  pid=\$(cat \"\$pid_file\" 2>/dev/null || true)
  case \"\$pid\" in
    *[!0-9]*|'') status=1; reason=invalid-pid ;;
  esac
fi
if [ $(remote_quote "$daemon_supervisor") != systemd ] && [ \"\$status\" -eq 0 ]; then
  if ! daemon_alive; then
    status=1
    reason=unexpected-exit
  else
    kill \"\$pid\" >/dev/null 2>&1 || {
      status=1
      reason=term-failed
    }
  fi
fi
if [ $(remote_quote "$daemon_supervisor") != systemd ] && [ \"\$status\" -eq 0 ]; then
  for _ in \$(seq 1 40); do
    daemon_alive || break
    sleep 1
  done
  if daemon_alive; then
    kill -KILL \"\$pid\" >/dev/null 2>&1 || true
    status=124
    reason=forced-kill
  fi
fi
if [ -f \"\$log_file\" ] && grep -Eiq 'SIGSEGV|segmentation violation|unexpected fault address|fatal error:|runtime: unexpected return pc|^panic:' \"\$log_file\"; then
  status=139
  reason=fatal-runtime-log
fi
printf 'status=%s reason=%s pid=%s\n' \"\$status\" \"\$reason\" \"\$pid\" >\"\$shutdown_file\"
exit \"\$status\"
"
}

cleanup_node() {
  local node="$1"
  local dir lan_if host_ns trustixd api_port peer_port env_exports unit
  dir="$(remote_dir "$node")"
  lan_if="$(node_value "$node" "$lan_if_a" "$lan_if_b")"
  host_ns="$(node_value "$node" "$host_ns_a" "$host_ns_b")"
  trustixd="$(node_bin "$node" trustixd)"
  api_port="$(node_value "$node" "$api_a_port" "$api_b_port")"
  peer_port="$(node_value "$node" "$peer_a_port" "$peer_b_port")"
  env_exports="$(daemon_env_exports)"
  unit="$(daemon_unit_name "$node")"
  clear_netem_node "$node" || true
  run_node "$node" "set +e
ip_cmd=\$(command -v ip)
cleanup_timeout=$(remote_quote "$cleanup_timeout")
cleanup_timed_out=0
mkdir -p $(remote_quote "${dir}/logs")
cleanup_step() {
  label=\$1
  shift
  \"\$@\" &
  child=\$!
  deadline=\$((SECONDS + cleanup_timeout))
  while kill -0 \"\$child\" >/dev/null 2>&1; do
    state=\$(awk '{print \$3}' \"/proc/\${child}/stat\" 2>/dev/null || true)
    [ \"\$state\" = Z ] && break
    if [ \"\$SECONDS\" -ge \"\$deadline\" ]; then
      printf '%s label=%s pid=%s command=%s\\n' \"\$(date -u '+%Y-%m-%dT%H:%M:%SZ')\" \"\$label\" \"\$child\" \"\$*\" >>$(remote_quote "${dir}/logs/cleanup-timeouts.log")
      kill -TERM \"\$child\" >/dev/null 2>&1 || true
      sleep 1
      kill -KILL \"\$child\" >/dev/null 2>&1 || true
      disown \"\$child\" >/dev/null 2>&1 || true
      cleanup_timed_out=1
      return 124
    fi
    sleep 1
  done
  wait \"\$child\"
}
if command -v systemctl >/dev/null 2>&1; then
  cleanup_step systemd-stop systemctl stop $(remote_quote "$unit") >/dev/null 2>&1 || true
  systemctl reset-failed $(remote_quote "$unit") >/dev/null 2>&1 || true
fi
if [ -x $(remote_quote "$trustixd") ] && [ -f $(remote_quote "${dir}/config.yaml") ]; then
  cleanup_step trustixd-cleanup env ${env_exports} $(remote_quote "$trustixd") -config $(remote_quote "${dir}/config.yaml") -data-dir $(remote_quote "${dir}/data") -api 127.0.0.1:${api_port} -peer-api 0.0.0.0:${peer_port} -dataplane $(remote_quote "$dataplane_mode") -cleanup-dataplane >>$(remote_quote "${dir}/logs/cleanup.log") 2>&1 || true
fi
for pid in \$(\"\$ip_cmd\" netns pids $(remote_quote "$host_ns") 2>/dev/null || true); do kill \"\$pid\" >/dev/null 2>&1 || true; done
if [ \"\$cleanup_timed_out\" -eq 0 ] && [ $(remote_quote "$unload_modules") = '1' ]; then
  cleanup_step rmmod-trustix-datapath rmmod trustix_datapath >/dev/null 2>&1 || true
  [ \"\$cleanup_timed_out\" -ne 0 ] || cleanup_step rmmod-trustix-datapath-helpers rmmod trustix_datapath_helpers >/dev/null 2>&1 || true
  [ \"\$cleanup_timed_out\" -ne 0 ] || cleanup_step rmmod-trustix-crypto rmmod trustix_crypto >/dev/null 2>&1 || true
fi
if [ \"\$cleanup_timed_out\" -eq 0 ]; then
  cleanup_step netns-del \"\$ip_cmd\" netns del $(remote_quote "$host_ns") >/dev/null 2>&1 || true
fi
if [ \"\$cleanup_timed_out\" -eq 0 ]; then
  cleanup_step link-del \"\$ip_cmd\" link del $(remote_quote "$lan_if") >/dev/null 2>&1 || true
fi
if [ \"\$cleanup_timed_out\" -eq 0 ] && [ $(remote_quote "$keep_remote") != '1' ]; then
  rm -rf $(remote_quote "$dir")
  rm -f $(remote_quote "${dir}.kernel-log-start-uptime")
fi
[ \"\$cleanup_timed_out\" -eq 0 ]
"
}

collect_all() {
  collect_boot_id a after || true
  collect_boot_id b after || true
  collect_node_api a || true
  collect_node_api b || true
  collect_module_parameters a || true
  collect_module_parameters b || true
  collect_host_state a || true
  collect_host_state b || true
  collect_lan_state a || true
  collect_lan_state b || true
  collect_netem_state_node a || true
  collect_netem_state_node b || true
  collect_binary_identity a || true
  collect_binary_identity b || true
  collect_kernel_logs a || true
  collect_kernel_logs b || true
}

fetch_all() {
  fetch_from_node a "$remote_a" "$workdir/a"
  fetch_from_node b "$remote_b" "$workdir/b"
}

cleanup_all() {
  local rc=$? cleanup_rc=0 node_cleanup_rc stop_rc netem_rc
  set +e
  cancel_netem_transition
  collect_all
  stop_daemon a || {
    stop_rc=$?
    [[ "$rc" != "0" ]] || rc=$stop_rc
  }
  stop_daemon b || {
    stop_rc=$?
    [[ "$rc" != "0" ]] || rc=$stop_rc
  }
  clear_netem_node a || {
    netem_rc=$?
    [[ "$rc" != "0" ]] || rc=$netem_rc
  }
  clear_netem_node b || {
    netem_rc=$?
    [[ "$rc" != "0" ]] || rc=$netem_rc
  }
  fetch_all
  if [[ "$rc" != "0" && -n "${workdir:-}" && -d "$workdir" ]]; then
    rm -f "$workdir/${case_name}.result"
  fi
  if [[ "$rc" != "0" ]] && truthy "$preserve_on_failure"; then
    log "preserving remote state after failure because TRUSTIX_CROSS_HOST_PRESERVE_ON_FAILURE=1"
    release_pair_lock
    return "$rc"
  fi
  cleanup_node a || cleanup_rc=$?
  cleanup_node b || {
    node_cleanup_rc=$?
    [[ "$cleanup_rc" != "0" ]] || cleanup_rc=$node_cleanup_rc
  }
  if [[ "$cleanup_rc" != "0" ]]; then
    log "cleanup failed with status ${cleanup_rc}; preserving and fetching remote diagnostics"
    fetch_all
    [[ "$rc" != "0" ]] || rc=$cleanup_rc
  fi
  if [[ "$keep_local" != "1" && -d "$workdir" ]]; then
    rm -rf "$workdir"
  fi
  release_pair_lock
  return "$rc"
}

main() {
  parse_endpoint_transports
  validate_case
  validate_netem_config
  validate_transport_tuning_config
  resolve_pinned_mixed_lan
  apply_case_runtime_defaults
  case "$(case_fast_path)" in
    route_gso|secure_tix_tcp_kernel)
      if [[ -z "${TRUSTIX_CROSS_HOST_SESSION_POOL_HEARTBEAT_MODE+x}" ]]; then
        session_pool_heartbeat_mode=disabled
      fi
      ;;
  esac
  if truthy "$dry_run_config"; then
    resolve_data_ports
    validate_multi_endpoint_data_ports
    mkdir -p "$workdir"
    write_config a "$workdir/config-a.yaml"
    write_config b "$workdir/config-b.yaml"
    daemon_env >"$workdir/daemon-env.txt"
    write_pinned_mixed_contract
    write_netem_contract
    write_iperf_tcp_buffer_contract
    printf 'dry_run_config\n' >"$workdir/${case_name}.result"
    log "dry-run-config result=${workdir}"
    return
  fi
  need_cmd ssh
  need_cmd tar
  need_cmd cp
  need_cmd find
  need_cmd cksum
  check_local_inputs
  acquire_pair_lock || die "another soak runner owns this VM pair"
  trap release_pair_lock EXIT
  if [[ "$pair_lock_hold_seconds" -gt 0 ]]; then
    log "holding VM-pair lock for ${pair_lock_hold_seconds}s"
    sleep "$pair_lock_hold_seconds"
  fi
  log "case=${case_name} workdir=${workdir}"
  if case_tc_requested_but_falls_back_to_userspace; then
    log "WARNING: ${case_name} has no safe TC direct fast path with this configuration; using userspace datapath"
  fi
  if [[ "$(case_transport)" == "udp" && "$(case_endpoint_transport)" == "tix_tcp" ]]; then
    log "full-kmod transport override selected with tix_tcp endpoint; require explicit tix_tcp_full_kmod gate evidence before treating this mix as production"
  fi
  check_node_prereqs a
  check_node_prereqs b
  resolve_underlay
  log "underlay a=${underlay_a_ip}/${underlay_a_if} b=${underlay_b_ip}/${underlay_b_if}"
  daemon_env >"$workdir/daemon-env.txt"
  write_netem_contract
  write_iperf_tcp_buffer_contract
  trap cleanup_all EXIT
  mark_kernel_log_start
  prepare_node_topology a
  prepare_node_topology b
  configure_iperf_tcp_buffer_node a
  configure_iperf_tcp_buffer_node b
  collect_boot_id a before
  collect_boot_id b before
  generate_certs
  write_pinned_mixed_contract
  if case_is_multi_endpoint; then
    printf '%s\n' "${endpoint_transports[@]}" >"$workdir/endpoint-transports.txt"
  fi
  write_config a "$workdir/config-a.yaml"
  write_config b "$workdir/config-b.yaml"
  push_inputs
  start_daemon a
  start_daemon b
  wait_for_api a
  wait_for_api b
  wait_for_endpoint_listeners
  wait_for_tix_tcp_full_kmod_readiness ||
    die "TIX-TCP full-kmod sessions did not become stably ready before connectivity traffic"
  run_connectivity_checks
  if [[ "$require_inner_gso_latched_fallback" == "1" ]]; then
    collect_transport_snapshot netem-before-apply
  fi
  apply_netem
  write_run_timing_start
  schedule_netem_transition
  run_iperf_bidirectional_artifacts
  wait_netem_transition
  verify_netem_evidence_after_traffic
  assert_pinned_mixed_sessions
  write_run_timing_end
  collect_all
  printf 'pass\n' >"$workdir/${case_name}.result"
  log "pass result=${workdir}"
}

main "$@"
