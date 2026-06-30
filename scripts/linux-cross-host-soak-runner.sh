#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

case_name="${TRUSTIX_CROSS_HOST_CASE:-dd-fullkmod}"
case_transport_override="${TRUSTIX_CROSS_HOST_TRANSPORT:-}"
case_encryption_override="${TRUSTIX_CROSS_HOST_ENCRYPTION:-}"
case_profile_override="${TRUSTIX_CROSS_HOST_PROFILE:-}"
case_datapath_override="${TRUSTIX_CROSS_HOST_TRANSPORT_DATAPATH:-}"
case_crypto_placement_override="${TRUSTIX_CROSS_HOST_CRYPTO_PLACEMENT:-}"
workdir="${TRUSTIX_CROSS_HOST_WORKDIR:-$(mktemp -d /tmp/trustix-cross-host.XXXXXX)}"
workdir="$(mkdir -p "$workdir" && cd "$workdir" && pwd -P)"
keep_remote="${TRUSTIX_CROSS_HOST_KEEP_REMOTE:-0}"
keep_local="${TRUSTIX_CROSS_HOST_KEEP_LOCAL:-1}"
unload_modules="${TRUSTIX_CROSS_HOST_UNLOAD_MODULES:-1}"
preserve_on_failure="${TRUSTIX_CROSS_HOST_PRESERVE_ON_FAILURE:-0}"
dry_run_config="${TRUSTIX_CROSS_HOST_DRY_RUN_CONFIG:-0}"

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
health_port="${TRUSTIX_CROSS_HOST_HEALTH_PORT:-}"
iperf_seconds="${TRUSTIX_CROSS_HOST_IPERF_SECONDS:-3600}"
iperf_parallel_explicit="${TRUSTIX_CROSS_HOST_IPERF_PARALLEL+x}"
iperf_parallel="${TRUSTIX_CROSS_HOST_IPERF_PARALLEL:-8}"
iptunnel_iperf_parallel="${TRUSTIX_CROSS_HOST_IPTUNNEL_IPERF_PARALLEL:-4}"
iperf_timeout="${TRUSTIX_CROSS_HOST_IPERF_TIMEOUT:-$((iperf_seconds + 60))}"
iperf_mode="${TRUSTIX_CROSS_HOST_IPERF_MODE:-forward}"
iperf_directions="${TRUSTIX_CROSS_HOST_IPERF_DIRECTIONS:-both}"
transport_snapshot_delay="${TRUSTIX_CROSS_HOST_TRANSPORT_SNAPSHOT_DELAY:-5}"
session_pool_size_explicit="${TRUSTIX_CROSS_HOST_SESSION_POOL_SIZE+x}"
session_pool_size="${TRUSTIX_CROSS_HOST_SESSION_POOL_SIZE:-$iperf_parallel}"
session_pool_strategy="${TRUSTIX_CROSS_HOST_SESSION_POOL_STRATEGY:-flow}"
session_pool_warmup="${TRUSTIX_CROSS_HOST_SESSION_POOL_WARMUP:-true}"
session_pool_heartbeat_mode="${TRUSTIX_CROSS_HOST_SESSION_POOL_HEARTBEAT_MODE:-enabled}"
session_pool_heartbeat_interval="${TRUSTIX_CROSS_HOST_SESSION_POOL_HEARTBEAT_INTERVAL:-10s}"
session_pool_heartbeat_timeout="${TRUSTIX_CROSS_HOST_SESSION_POOL_HEARTBEAT_TIMEOUT:-10s}"
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

soak_start_epoch=""
soak_start_iso=""

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
{"case":"$(json_escape "$case_name")","transport":"$(json_escape "$(case_transport)")","encryption":"$(json_escape "$(case_encryption)")","profile":"$(json_escape "$(case_transport_profile)")","datapath":"$(json_escape "$(case_transport_datapath)")","crypto_placement":"$(json_escape "$(case_crypto_placement)")","iperf_mode":"$(json_escape "$iperf_mode")","iperf_directions":"$(json_escape "$iperf_directions")","iperf_parallel":${iperf_parallel},"iperf_seconds_requested":${iperf_seconds},"start_epoch":${soak_start_epoch},"end_epoch":${end_epoch},"elapsed_seconds":${elapsed},"start_time":"${soak_start_iso}","end_time":"${end_iso}"}
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
    experimentaltcp) value="experimental_tcp" ;;
  esac
  printf '%s\n' "$value"
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
    udp|tcp|quic|websocket|http_connect|gre|ipip|vxlan|experimental_tcp) return 0 ;;
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
  if case_is_generic; then
    supported_case_transport "$(generic_case_transport)" || die "unsupported generic TRUSTIX_CROSS_HOST_CASE transport in ${case_name}"
    case "$(generic_case_encryption)" in secure|plaintext) ;; *) die "unsupported generic TRUSTIX_CROSS_HOST_CASE encryption in ${case_name}" ;; esac
    return
  fi
  case "$case_name" in
    dd-fullkmod|owdeb-fullkmod|full-kmod|udp-plaintext-full-kmod|udp_plaintext_full_kmod) ;;
    experimental-tcp-full-kmod|experimental_tcp_full_kmod|exp-tcp-full-kmod|exp_tcp_full_kmod|dd-experimental-tcp-full-kmod|dd_experimental_tcp_full_kmod|owdeb-experimental-tcp-full-kmod|owdeb_experimental_tcp_full_kmod) ;;
    dd-secure-kudp|owdeb-secure-kudp|secure-kudp|kernel-udp-secure-kernel|kernel_udp_secure_kernel|udp-secure-kernel|udp_secure_kernel) ;;
    secure-exp-tcp-kernel|secure_exp_tcp_kernel|experimental-tcp-secure-kernel|experimental_tcp_secure_kernel|secure-experimental-tcp-kernel|secure_experimental_tcp_kernel) ;;
    dd-routegso|owdeb-routegso|route-gso|experimental-tcp-route-gso|experimental_tcp_route_gso) ;;
    ow-tc-direct|tc-direct|experimental-tcp-tc-direct|experimental_tcp_tc_direct) ;;
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
    dd-fullkmod|owdeb-fullkmod|full-kmod|udp-plaintext-full-kmod|udp_plaintext_full_kmod|dd-secure-kudp|owdeb-secure-kudp|secure-kudp|kernel-udp-secure-kernel|kernel_udp_secure_kernel|udp-secure-kernel|udp_secure_kernel) printf 'udp\n' ;;
    experimental-tcp-full-kmod|experimental_tcp_full_kmod|exp-tcp-full-kmod|exp_tcp_full_kmod|dd-experimental-tcp-full-kmod|dd_experimental_tcp_full_kmod|owdeb-experimental-tcp-full-kmod|owdeb_experimental_tcp_full_kmod) printf 'experimental_tcp\n' ;;
    *) printf 'experimental_tcp\n' ;;
  esac
}

case_fast_path() {
  if case_is_generic; then
    generic_case_kind
    return
  fi
  case "$case_name" in
    dd-fullkmod|owdeb-fullkmod|full-kmod|udp-plaintext-full-kmod|udp_plaintext_full_kmod|experimental-tcp-full-kmod|experimental_tcp_full_kmod|exp-tcp-full-kmod|exp_tcp_full_kmod|dd-experimental-tcp-full-kmod|dd_experimental_tcp_full_kmod|owdeb-experimental-tcp-full-kmod|owdeb_experimental_tcp_full_kmod) printf 'full_kmod\n' ;;
    dd-secure-kudp|owdeb-secure-kudp|secure-kudp|kernel-udp-secure-kernel|kernel_udp_secure_kernel|udp-secure-kernel|udp_secure_kernel) printf 'secure_kudp\n' ;;
    secure-exp-tcp-kernel|secure_exp_tcp_kernel|experimental-tcp-secure-kernel|experimental_tcp_secure_kernel|secure-experimental-tcp-kernel|secure_experimental_tcp_kernel) printf 'secure_exp_tcp_kernel\n' ;;
    dd-routegso|owdeb-routegso|route-gso|experimental-tcp-route-gso|experimental_tcp_route_gso) printf 'route_gso\n' ;;
    ow-tc-direct|tc-direct|experimental-tcp-tc-direct|experimental_tcp_tc_direct) printf 'tc_direct\n' ;;
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
    secure_kudp|secure_exp_tcp_kernel) printf 'secure\n' ;;
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
    *) printf 'userspace\n' ;;
  esac
}

case_endpoint_transport() {
  if [[ -n "$endpoint_transport_override" ]]; then
    normalize_case_transport_token "$endpoint_transport_override"
    return
  fi
  case_transport
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
    secure_exp_tcp_kernel) printf 'kernel_module\n' ;;
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
  case "$(case_fast_path)" in
    secure_kudp|secure_exp_tcp_kernel) return 0 ;;
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
        udp:plaintext|experimental_tcp:plaintext) return 0 ;;
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
  if case_is_iptunnel_transport && [[ -z "$iperf_parallel_explicit" ]]; then
    iperf_parallel="$iptunnel_iperf_parallel"
    if [[ -z "$session_pool_size_explicit" ]]; then
      session_pool_size="$iperf_parallel"
    fi
  fi
}

case_secure_kudp_route_gso() {
  case "$(case_fast_path)" in
    secure_kudp|secure_exp_tcp_kernel) return 0 ;;
  esac
  truthy "${TRUSTIX_CROSS_HOST_SECURE_KUDP_ROUTE_GSO:-0}"
}

case_link_tls_transport() {
  case "$(case_endpoint_transport)" in
    tcp|quic|websocket|http_connect) return 0 ;;
    *) return 1 ;;
  esac
}

endpoint_security_yaml() {
  local indent="$1"
  local encryption="$2"
  printf '%ssecurity:\n' "$indent"
  if case_link_tls_transport; then
    printf '%s  link_tls: required\n' "$indent"
  fi
  printf '%s  encryption: %s\n' "$indent" "$encryption"
}

case_endpoint_name() {
  local node="$1"
  local transport
  transport="$(case_endpoint_transport)"
  case "$(case_endpoint_transport)" in
    udp) node_value "$node" a-udp b-udp ;;
    experimental_tcp) node_value "$node" a-experimental-tcp b-experimental-tcp ;;
    *) node_value "$node" "a-${transport//_/-}" "b-${transport//_/-}" ;;
  esac
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
    reload_on_upgrade: always
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
    reload_on_upgrade: always
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

case_module_yaml() {
  local node="${1:-a}"
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
    reload_on_upgrade: always
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
    reload_on_upgrade: always
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
    reload_on_upgrade: always
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
    reload_on_upgrade: always
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
  if [[ -z "$health_port" ]]; then
    health_port=$((iperf_port + 1))
  fi
  case "$health_port" in *[!0-9]*|"") die "TRUSTIX_CROSS_HOST_HEALTH_PORT must be an integer" ;; esac
  [[ "$health_port" -ne "$iperf_port" ]] || die "TRUSTIX_CROSS_HOST_HEALTH_PORT must differ from TRUSTIX_CROSS_HOST_IPERF_PORT"
  case "$transport_snapshot_delay" in *[!0-9]*|"") die "TRUSTIX_CROSS_HOST_TRANSPORT_SNAPSHOT_DELAY must be an integer" ;; esac
  case "$session_pool_size" in *[!0-9]*|"") die "TRUSTIX_CROSS_HOST_SESSION_POOL_SIZE must be an integer" ;; esac
  case "$iptunnel_port" in *[!0-9]*|"") die "TRUSTIX_CROSS_HOST_IPTUNNEL_PORT must be an integer" ;; esac
  case "$iptunnel_mtu" in *[!0-9]*|"") die "TRUSTIX_CROSS_HOST_IPTUNNEL_MTU must be an integer" ;; esac
  case "$vxlan_vni" in *[!0-9]*|"") die "TRUSTIX_CROSS_HOST_VXLAN_VNI must be an integer" ;; esac
  case "$vxlan_port" in *[!0-9]*|"") die "TRUSTIX_CROSS_HOST_VXLAN_PORT must be an integer" ;; esac
  [[ "$iperf_parallel" -ge 1 ]] || die "TRUSTIX_CROSS_HOST_IPERF_PARALLEL must be >= 1"
  [[ "$iptunnel_iperf_parallel" -ge 1 ]] || die "TRUSTIX_CROSS_HOST_IPTUNNEL_IPERF_PARALLEL must be >= 1"
  [[ "$transport_snapshot_delay" -ge 0 ]] || die "TRUSTIX_CROSS_HOST_TRANSPORT_SNAPSHOT_DELAY must be >= 0"
  [[ "$session_pool_size" -ge 1 ]] || die "TRUSTIX_CROSS_HOST_SESSION_POOL_SIZE must be >= 1"
  [[ "$iptunnel_port" -ge 1 && "$iptunnel_port" -le 65535 ]] || die "TRUSTIX_CROSS_HOST_IPTUNNEL_PORT must be in 1..65535"
  [[ "$iptunnel_mtu" -ge 17 && "$iptunnel_mtu" -le 65535 ]] || die "TRUSTIX_CROSS_HOST_IPTUNNEL_MTU must be in 17..65535"
  [[ "$vxlan_vni" -ge 1 && "$vxlan_vni" -le 16777215 ]] || die "TRUSTIX_CROSS_HOST_VXLAN_VNI must be in 1..16777215"
  [[ "$vxlan_port" -ge 1 && "$vxlan_port" -le 65535 ]] || die "TRUSTIX_CROSS_HOST_VXLAN_PORT must be in 1..65535"
  resolve_data_ports
  case "$data_a_port" in *[!0-9]*|"") die "TRUSTIX_CROSS_HOST_DATA_A_PORT must be an integer" ;; esac
  case "$data_b_port" in *[!0-9]*|"") die "TRUSTIX_CROSS_HOST_DATA_B_PORT must be an integer" ;; esac
  case "$iperf_mode" in bidir|forward|reverse) ;; *) die "TRUSTIX_CROSS_HOST_IPERF_MODE must be bidir, forward, or reverse" ;; esac
  case "$iperf_directions" in both|a2b|b2a|a-to-b|b-to-a) ;; *) die "TRUSTIX_CROSS_HOST_IPERF_DIRECTIONS must be both, a2b, or b2a" ;; esac
  if [[ -n "$endpoint_transport_override" ]]; then
    supported_case_transport "$endpoint_transport_override" || die "TRUSTIX_CROSS_HOST_ENDPOINT_TRANSPORT is unsupported: ${endpoint_transport_override}"
  fi
  if [[ -n "$case_transport_override" ]]; then
    supported_case_transport "$case_transport_override" || die "TRUSTIX_CROSS_HOST_TRANSPORT is unsupported: ${case_transport_override}"
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
  local trustixd trustixctl
  trustixd="$(node_bin "$node" trustixd)"
  trustixctl="$(node_bin "$node" trustixctl)"
  run_node "$node" "set -Eeuo pipefail
missing=0
for cmd in ip iperf3 curl; do
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
  if [[ -z "$underlay_a_if" ]]; then
    underlay_a_if="$(detect_underlay_if a "$underlay_b_ip" | tail -n 1)"
  fi
  if [[ -z "$underlay_b_if" ]]; then
    underlay_b_if="$(detect_underlay_if b "$underlay_a_ip" | tail -n 1)"
  fi
  [[ -n "$underlay_a_if" ]] || die "could not detect node A underlay interface"
  [[ -n "$underlay_b_if" ]] || die "could not detect node B underlay interface"
}

prepare_node_topology() {
  local node="$1"
  local dir lan_if host_if host_ns host_addr host_gw
  dir="$(remote_dir "$node")"
  lan_if="$(node_value "$node" "$lan_if_a" "$lan_if_b")"
  host_if="$(node_value "$node" "$host_if_a" "$host_if_b")"
  host_ns="$(node_value "$node" "$host_ns_a" "$host_ns_b")"
  host_addr="$(node_value "$node" "$host_a_addr" "$host_b_addr")"
  host_gw="$(node_value "$node" "${lan_a_gateway%/*}" "${lan_b_gateway%/*}")"
  run_node "$node" "set -Eeuo pipefail
ip_cmd=\$(command -v ip)
rm -rf $(remote_quote "$dir")
mkdir -p $(remote_quote "$dir")/logs $(remote_quote "$dir")/certs $(remote_quote "$dir")/data
if command -v modprobe >/dev/null 2>&1; then modprobe veth >/dev/null 2>&1 || true; fi
for pid in \$(\"\$ip_cmd\" netns pids $(remote_quote "$host_ns") 2>/dev/null || true); do kill \"\$pid\" >/dev/null 2>&1 || true; done
\"\$ip_cmd\" netns del $(remote_quote "$host_ns") >/dev/null 2>&1 || true
\"\$ip_cmd\" link del $(remote_quote "$lan_if") >/dev/null 2>&1 || true
\"\$ip_cmd\" link del $(remote_quote "$host_if") >/dev/null 2>&1 || true
\"\$ip_cmd\" link add $(remote_quote "$lan_if") type veth peer name $(remote_quote "$host_if")
\"\$ip_cmd\" netns add $(remote_quote "$host_ns")
\"\$ip_cmd\" link set $(remote_quote "$host_if") netns $(remote_quote "$host_ns")
\"\$ip_cmd\" link set $(remote_quote "$lan_if") up
\"\$ip_cmd\" netns exec $(remote_quote "$host_ns") \"\$ip_cmd\" link set lo up
\"\$ip_cmd\" netns exec $(remote_quote "$host_ns") \"\$ip_cmd\" addr add $(remote_quote "$host_addr") dev $(remote_quote "$host_if")
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

write_config() {
  local node="$1"
  local config_path="$2"
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
  mtu: 1500
  candidates:
    - ${local_endpoint}
  failover: health_based
  load_balance: least_conn
  encryption: ${encryption}
  crypto_placement: ${crypto_placement}
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
TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO=0
TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC=0
EOF
  printf 'TRUSTIX_KERNEL_UDP_TC_TX_SECURE_ROUTE_GSO_KFUNC=%s\n' "$route_gso"
  printf 'TRUSTIX_KERNEL_UDP_TC_TX_SECURE_ROUTE_GSO=%s\n' "$route_gso"
}

secure_exp_tcp_kernel_daemon_env() {
  cat <<'EOF'
TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO=1
TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC=1
TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT=1
TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_ONLY=1
TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_ASYNC_KFUNC=1
TRUSTIX_EXPERIMENTAL_TCP_ALLOW_CRASH_RISK_ROUTE_TCP_GSO_ASYNC=0
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
TRUSTIX_KERNEL_UDP_TC_TX_SECURE_ROUTE_TCP_GSO_KFUNC=1
TRUSTIX_KERNEL_UDP_TC_TX_SECURE_ROUTE_GSO_KFUNC=1
TRUSTIX_KERNEL_UDP_TC_TX_SECURE_ROUTE_GSO=1
EOF
}

daemon_env() {
  if [[ "$(case_fast_path)" == "secure_exp_tcp_kernel" ]]; then
    secure_exp_tcp_kernel_daemon_env
    return
  fi
  if case_uses_secure_kudp_fast_path; then
    secure_kudp_daemon_env
    return
  fi
  case "$(case_fast_path)" in
    userspace)
      if [[ "$(case_endpoint_transport)" == "experimental_tcp" ]]; then
        cat <<'EOF'
TRUSTIX_EXPERIMENTAL_TCP_RAW_FALLBACK=1
EOF
      fi
      ;;
    full_kmod)
      local rx_worker_experimental_tcp=0
      if [[ "$(case_endpoint_transport)" == "experimental_tcp" ]]; then
        rx_worker_experimental_tcp=1
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
      printf 'TRUSTIX_KERNEL_DATAPATH_RX_WORKER_ALLOW_EXPERIMENTAL_TCP=%s\n' "$rx_worker_experimental_tcp"
      if [[ "$rx_worker_experimental_tcp" == "1" ]]; then
        printf 'TRUSTIX_EXPERIMENTAL_TCP_ALLOW_MIXED_TCP_FAST_PATH=1\n'
      fi
      ;;
    route_gso)
      cat <<'EOF'
TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC=1
TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_ASYNC_KFUNC=1
TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT=1
TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_ONLY=1
TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_EXPERIMENTAL_TCP_ONLY=1
TRUSTIX_EXPERIMENTAL_TCP_ALLOW_CRASH_RISK_ROUTE_TCP_GSO_ASYNC=0
EOF
      ;;
    tc_direct)
      cat <<'EOF'
TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO=0
TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC=0
TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_KFUNC=0
TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_ASYNC_KFUNC=0
TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_XMIT_KFUNC=0
TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT=1
TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_ONLY=1
TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY=1
TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_EXPERIMENTAL_TCP_ONLY=1
TRUSTIX_EXPERIMENTAL_TCP_ALLOW_CRASH_RISK_ROUTE_TCP_GSO_ASYNC=0
EOF
      ;;
    userspace_tc)
      case "$(case_endpoint_transport):$(case_encryption)" in
        udp:plaintext)
          cat <<'EOF'
TRUSTIX_KERNEL_UDP_TC_TX_DIRECT=1
TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY=1
TRUSTIX_KERNEL_UDP_TC_ONLY=1
TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_KERNEL_UDP_ONLY=1
TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO=0
TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC=0
TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT=0
EOF
          ;;
        experimental_tcp:plaintext)
          cat <<'EOF'
TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO=0
TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC=0
TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_KFUNC=0
TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_ASYNC_KFUNC=0
TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_XMIT_KFUNC=0
TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT=1
TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_ONLY=1
TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY=1
TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_EXPERIMENTAL_TCP_ONLY=1
TRUSTIX_EXPERIMENTAL_TCP_ALLOW_CRASH_RISK_ROUTE_TCP_GSO_ASYNC=0
EOF
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
  local dir api_port peer_port trustixd env_exports
  dir="$(remote_dir "$node")"
  api_port="$(node_value "$node" "$api_a_port" "$api_b_port")"
  peer_port="$(node_value "$node" "$peer_a_port" "$peer_b_port")"
  trustixd="$(node_bin "$node" trustixd)"
  env_exports="$(daemon_env_exports)"
run_node "$node" "set -Eeuo pipefail
cd $(remote_quote "$dir")
rm -f trustixd.pid logs/trustixd.log
if command -v nohup >/dev/null 2>&1; then
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
echo \$! >$(remote_quote "${dir}/trustixd.pid")
"
}

wait_for_api() {
  local node="$1"
  local dir api_port
  dir="$(remote_dir "$node")"
  api_port="$(node_value "$node" "$api_a_port" "$api_b_port")"
  run_node "$node" "set -Eeuo pipefail
pid=\$(cat $(remote_quote "${dir}/trustixd.pid"))
for _ in \$(seq 1 ${daemon_ready_attempts}); do
  if curl -fsS http://127.0.0.1:${api_port}/v1/status >/dev/null 2>&1; then
    exit 0
  fi
  if ! kill -0 \"\$pid\" >/dev/null 2>&1; then
    sed -n '1,240p' $(remote_quote "${dir}/logs/trustixd.log") >&2 || true
    exit 1
  fi
  sleep ${daemon_ready_sleep}
done
sed -n '1,240p' $(remote_quote "${dir}/logs/trustixd.log") >&2 || true
exit 1
"
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
	since="$soak_start_iso"
	run_node "$node" "set +e
dir=$(remote_quote "$dir")
prefix=$(remote_quote "$prefix")
since=$(remote_quote "$since")
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
  if [ -n \"\$since\" ] && dmesg --since \"\$since\" >\"\$tmp\" 2>&1 && [ -s \"\$tmp\" ]; then
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
  local dir
  dir="$(remote_dir "$node")"
  run_node "$node" "set +e
out=$(remote_quote "${dir}/module-parameters.txt")
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
  case "$(case_endpoint_transport)" in
    tcp|websocket|http_connect|experimental_tcp) return 0 ;;
    *) return 1 ;;
  esac
}

wait_for_tcp_listener() {
  local node="$1"
  local port
  port="$(node_value "$node" "$data_a_port" "$data_b_port")"
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

run_connectivity_checks() {
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
  local dir host_ns
  dir="$(remote_dir "$node")"
  host_ns="$(node_value "$node" "$host_ns_a" "$host_ns_b")"
run_node "$node" "set -Eeuo pipefail
ip_cmd=\$(command -v ip)
rm -f $(remote_quote "${dir}/iperf3-server.pid") $(remote_quote "${dir}/iperf3-server.json")
if command -v nohup >/dev/null 2>&1; then
  nohup \"\$ip_cmd\" netns exec $(remote_quote "$host_ns") iperf3 -s -1 -p ${iperf_port} -J >$(remote_quote "${dir}/iperf3-server.json") 2>$(remote_quote "${dir}/iperf3-server.err") </dev/null &
elif command -v setsid >/dev/null 2>&1; then
  setsid \"\$ip_cmd\" netns exec $(remote_quote "$host_ns") iperf3 -s -1 -p ${iperf_port} -J >$(remote_quote "${dir}/iperf3-server.json") 2>$(remote_quote "${dir}/iperf3-server.err") </dev/null &
else
  \"\$ip_cmd\" netns exec $(remote_quote "$host_ns") iperf3 -s -1 -p ${iperf_port} -J >$(remote_quote "${dir}/iperf3-server.json") 2>$(remote_quote "${dir}/iperf3-server.err") </dev/null &
fi
echo \$! >$(remote_quote "${dir}/iperf3-server.pid")
"
}

run_iperf_client() {
  local node="$1"
  local dst_ip="$2"
  local out_name="$3"
  local dir host_ns mode_args
  dir="$(remote_dir "$node")"
  host_ns="$(node_value "$node" "$host_ns_a" "$host_ns_b")"
  case "$iperf_mode" in
    bidir) mode_args="--bidir" ;;
    forward) mode_args="" ;;
    reverse) mode_args="-R" ;;
  esac
  run_node "$node" "set -Eeuo pipefail
ip_cmd=\$(command -v ip)
out=$(remote_quote "${dir}/${out_name}")
err=$(remote_quote "${dir}/${out_name%.json}.err")
rc=0
if command -v timeout >/dev/null 2>&1; then
  timeout ${iperf_timeout}s \"\$ip_cmd\" netns exec $(remote_quote "$host_ns") iperf3 -c $(remote_quote "$dst_ip") -p ${iperf_port} -t ${iperf_seconds} -P ${iperf_parallel} ${mode_args} -J >\"\$out\" 2>\"\$err\" || rc=\$?
else
  \"\$ip_cmd\" netns exec $(remote_quote "$host_ns") iperf3 -c $(remote_quote "$dst_ip") -p ${iperf_port} -t ${iperf_seconds} -P ${iperf_parallel} ${mode_args} -J >\"\$out\" 2>\"\$err\" || rc=\$?
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

run_iperf_client_with_snapshot() {
  local node="$1"
  local dst_ip="$2"
  local out_name="$3"
  local client_pid snapshot_label rc
  run_iperf_client "$node" "$dst_ip" "$out_name" &
  client_pid=$!
  if [[ "$transport_snapshot_delay" -gt 0 ]]; then
    sleep "$transport_snapshot_delay"
  fi
  snapshot_label="${out_name%.json}"
  snapshot_label="${snapshot_label#iperf3-}"
  collect_transport_snapshot "during-${snapshot_label}"
  if wait "$client_pid"; then
    return 0
  else
    rc=$?
  fi
  collect_failure_snapshot "$snapshot_label"
  return "$rc"
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
  local dir
  dir="$(remote_dir "$node")"
  run_node "$node" "set +e
pid=\$(cat $(remote_quote "${dir}/iperf3-server.pid") 2>/dev/null || true)
[ -z \"\$pid\" ] && exit 0
for _ in \$(seq 1 40); do
  kill -0 \"\$pid\" >/dev/null 2>&1 || exit 0
  sleep 1
done
kill \"\$pid\" >/dev/null 2>&1 || true
exit 0
"
}

run_iperf_bidirectional_artifacts() {
  local suffix rc=0 client_rc out_name
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
          log "iperf a-to-b client missed server results; accepting server-side summary artifact"
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
          log "iperf b-to-a client missed server results; accepting server-side summary artifact"
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
  local dir
  dir="$(remote_dir "$node")"
  run_node "$node" "set +e
if [ -s $(remote_quote "${dir}/trustixd.pid") ]; then
  pid=\$(cat $(remote_quote "${dir}/trustixd.pid"))
  kill \"\$pid\" >/dev/null 2>&1 || true
  for _ in \$(seq 1 40); do
    kill -0 \"\$pid\" >/dev/null 2>&1 || break
    sleep 1
  done
  kill -KILL \"\$pid\" >/dev/null 2>&1 || true
fi
"
}

cleanup_node() {
  local node="$1"
  local dir lan_if host_ns trustixd api_port peer_port env_exports
  dir="$(remote_dir "$node")"
  lan_if="$(node_value "$node" "$lan_if_a" "$lan_if_b")"
  host_ns="$(node_value "$node" "$host_ns_a" "$host_ns_b")"
  trustixd="$(node_bin "$node" trustixd)"
  api_port="$(node_value "$node" "$api_a_port" "$api_b_port")"
  peer_port="$(node_value "$node" "$peer_a_port" "$peer_b_port")"
  env_exports="$(daemon_env_exports)"
  run_node "$node" "set +e
ip_cmd=\$(command -v ip)
if [ -x $(remote_quote "$trustixd") ] && [ -f $(remote_quote "${dir}/config.yaml") ]; then
  env ${env_exports} $(remote_quote "$trustixd") -config $(remote_quote "${dir}/config.yaml") -data-dir $(remote_quote "${dir}/data") -api 127.0.0.1:${api_port} -peer-api 0.0.0.0:${peer_port} -dataplane $(remote_quote "$dataplane_mode") -cleanup-dataplane >>$(remote_quote "${dir}/logs/cleanup.log") 2>&1
fi
for pid in \$(\"\$ip_cmd\" netns pids $(remote_quote "$host_ns") 2>/dev/null || true); do kill \"\$pid\" >/dev/null 2>&1 || true; done
\"\$ip_cmd\" netns del $(remote_quote "$host_ns") >/dev/null 2>&1 || true
\"\$ip_cmd\" link del $(remote_quote "$lan_if") >/dev/null 2>&1 || true
if [ $(remote_quote "$unload_modules") = '1' ]; then
  rmmod trustix_datapath >/dev/null 2>&1 || true
  rmmod trustix_datapath_helpers >/dev/null 2>&1 || true
  rmmod trustix_crypto >/dev/null 2>&1 || true
fi
if [ $(remote_quote "$keep_remote") != '1' ]; then
  rm -rf $(remote_quote "$dir")
fi
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
  collect_binary_identity a || true
  collect_binary_identity b || true
  collect_kernel_logs a || true
  collect_kernel_logs b || true
  fetch_from_node a "$remote_a" "$workdir/a"
  fetch_from_node b "$remote_b" "$workdir/b"
}

cleanup_all() {
  local rc=$?
  set +e
  collect_all
  if [[ "$rc" != "0" ]] && truthy "$preserve_on_failure"; then
    log "preserving remote state after failure because TRUSTIX_CROSS_HOST_PRESERVE_ON_FAILURE=1"
    return "$rc"
  fi
  stop_daemon a
  stop_daemon b
  cleanup_node a
  cleanup_node b
  if [[ "$keep_local" != "1" && -d "$workdir" ]]; then
    rm -rf "$workdir"
  fi
  return "$rc"
}

main() {
  validate_case
  apply_case_runtime_defaults
  case "$(case_fast_path)" in
    route_gso|secure_exp_tcp_kernel)
      if [[ -z "${TRUSTIX_CROSS_HOST_SESSION_POOL_HEARTBEAT_MODE+x}" ]]; then
        session_pool_heartbeat_mode=disabled
      fi
      ;;
  esac
  if truthy "$dry_run_config"; then
    resolve_data_ports
    mkdir -p "$workdir"
    write_config a "$workdir/config-a.yaml"
    write_config b "$workdir/config-b.yaml"
    printf 'dry_run_config\n' >"$workdir/${case_name}.result"
    log "dry-run-config result=${workdir}"
    return
  fi
  need_cmd ssh
  need_cmd tar
  need_cmd cp
  need_cmd find
  check_local_inputs
  log "case=${case_name} workdir=${workdir}"
  if case_tc_requested_but_falls_back_to_userspace; then
    log "WARNING: ${case_name} has no safe TC direct fast path with this configuration; using userspace datapath"
  fi
  if [[ "$(case_transport)" == "udp" && "$(case_endpoint_transport)" == "experimental_tcp" ]]; then
    log "full-kmod transport override selected with experimental_tcp endpoint; require explicit exp_tcp_full_kmod gate evidence before treating this mix as production"
  fi
  check_node_prereqs a
  check_node_prereqs b
  resolve_underlay
  log "underlay a=${underlay_a_ip}/${underlay_a_if} b=${underlay_b_ip}/${underlay_b_if}"
  trap cleanup_all EXIT
  prepare_node_topology a
  prepare_node_topology b
  collect_boot_id a before
  collect_boot_id b before
  generate_certs
  write_config a "$workdir/config-a.yaml"
  write_config b "$workdir/config-b.yaml"
  push_inputs
  start_daemon a
  start_daemon b
  wait_for_api a
  wait_for_api b
  wait_for_endpoint_listeners
  run_connectivity_checks
  write_run_timing_start
  run_iperf_bidirectional_artifacts
  write_run_timing_end
  collect_all
  printf 'pass\n' >"$workdir/${case_name}.result"
  log "pass result=${workdir}"
}

main "$@"
