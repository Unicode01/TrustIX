#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workdir="${TRUSTIX_3IX_E2E_WORKDIR:-$(mktemp -d /tmp/trustix-3ix-e2e.XXXXXX)}"
keep="${TRUSTIX_3IX_E2E_KEEP:-0}"
bin_dir="${TRUSTIX_3IX_E2E_BIN_DIR:-$workdir/bin}"
dataplane="${TRUSTIX_3IX_E2E_DATAPLANE:-linux}"
transport="${TRUSTIX_3IX_E2E_TRANSPORT:-tix_tcp}"
transport_profile="${TRUSTIX_3IX_E2E_TRANSPORT_PROFILE:-}"
transport_datapath="${TRUSTIX_3IX_E2E_TRANSPORT_DATAPATH:-}"
transport_encryption="${TRUSTIX_3IX_E2E_TRANSPORT_ENCRYPTION:-${TRUSTIX_3IX_E2E_ENCRYPTION:-secure}}"
crypto_placement="${TRUSTIX_3IX_E2E_CRYPTO_PLACEMENT:-userspace}"
dynamic_metric="${TRUSTIX_3IX_E2E_DYNAMIC_METRIC:-900}"
af_xdp_queues="${TRUSTIX_3IX_E2E_AF_XDP_QUEUES:-1}"
xdp_mode="${TRUSTIX_3IX_E2E_XDP_MODE:-auto}"
af_xdp_bind_mode="${TRUSTIX_3IX_E2E_AF_XDP_BIND_MODE:-auto}"
af_xdp_tx_backpressure_wait="${TRUSTIX_3IX_E2E_AF_XDP_TX_BACKPRESSURE_WAIT:-2ms}"
hot_stats="${TRUSTIX_3IX_E2E_HOT_STATS:-1}"
kernel_module="${TRUSTIX_3IX_E2E_KERNEL_MODULE:-0}"
kernel_script="${TRUSTIX_3IX_E2E_KERNEL_SCRIPT:-${repo_root}/scripts/linux-kernel-module-smoke.sh}"
kernel_module_dir="${TRUSTIX_3IX_E2E_KERNEL_MODULE_DIR:-${repo_root}/kernel/trustix_crypto}"
kernel_test_bin="${TRUSTIX_3IX_E2E_KERNEL_TEST_BIN:-}"
control_client_timeout="${TRUSTIX_3IX_E2E_CONTROL_CLIENT_TIMEOUT:-15s}"
control_wait_attempts="${TRUSTIX_3IX_E2E_CONTROL_WAIT_ATTEMPTS:-160}"

ping_count="${TRUSTIX_3IX_E2E_PING_COUNT:-1}"
ping_size="${TRUSTIX_3IX_E2E_PING_SIZE:-56}"
ping_parallel="${TRUSTIX_3IX_E2E_PING_PARALLEL:-1}"
ping_rounds="${TRUSTIX_3IX_E2E_PING_ROUNDS:-1}"
udp_burst_packets="${TRUSTIX_3IX_E2E_UDP_BURST_PACKETS:-8}"
udp_burst_size="${TRUSTIX_3IX_E2E_UDP_BURST_SIZE:-512}"
udp_burst_parallel="${TRUSTIX_3IX_E2E_UDP_BURST_PARALLEL:-1}"
udp_burst_rounds="${TRUSTIX_3IX_E2E_UDP_BURST_ROUNDS:-1}"
udp_burst_port="${TRUSTIX_3IX_E2E_UDP_BURST_PORT:-}"
tcp_burst_connections="${TRUSTIX_3IX_E2E_TCP_BURST_CONNECTIONS:-3}"
tcp_burst_size="${TRUSTIX_3IX_E2E_TCP_BURST_SIZE:-1024}"
tcp_burst_parallel="${TRUSTIX_3IX_E2E_TCP_BURST_PARALLEL:-1}"
tcp_burst_rounds="${TRUSTIX_3IX_E2E_TCP_BURST_ROUNDS:-1}"
tcp_burst_port="${TRUSTIX_3IX_E2E_TCP_BURST_PORT:-}"
burst_timeout="${TRUSTIX_3IX_E2E_BURST_TIMEOUT:-15}"

ns_ix_a="${TRUSTIX_3IX_E2E_NS_IX_A:-tix3-ix-a}"
ns_ix_b="${TRUSTIX_3IX_E2E_NS_IX_B:-tix3-ix-b}"
ns_ix_c="${TRUSTIX_3IX_E2E_NS_IX_C:-tix3-ix-c}"
ns_lan_a="${TRUSTIX_3IX_E2E_NS_LAN_A:-tix3-lan-a}"
ns_lan_b="${TRUSTIX_3IX_E2E_NS_LAN_B:-tix3-lan-b}"
ns_lan_c="${TRUSTIX_3IX_E2E_NS_LAN_C:-tix3-lan-c}"
bridge="${TRUSTIX_3IX_E2E_BRIDGE:-tix3br0}"

lan_a="${TRUSTIX_3IX_E2E_LAN_A:-tix3a0}"
lan_b="${TRUSTIX_3IX_E2E_LAN_B:-tix3b0}"
lan_c="${TRUSTIX_3IX_E2E_LAN_C:-tix3c0}"
host_a="${TRUSTIX_3IX_E2E_HOST_A:-tix3ah0}"
host_b="${TRUSTIX_3IX_E2E_HOST_B:-tix3bh0}"
host_c="${TRUSTIX_3IX_E2E_HOST_C:-tix3ch0}"
underlay_a="${TRUSTIX_3IX_E2E_UNDERLAY_A:-tix3ua0}"
underlay_b="${TRUSTIX_3IX_E2E_UNDERLAY_B:-tix3ub0}"
underlay_c="${TRUSTIX_3IX_E2E_UNDERLAY_C:-tix3uc0}"
underlay_root_a="${TRUSTIX_3IX_E2E_UNDERLAY_ROOT_A:-tix3ur0a}"
underlay_root_b="${TRUSTIX_3IX_E2E_UNDERLAY_ROOT_B:-tix3ur0b}"
underlay_root_c="${TRUSTIX_3IX_E2E_UNDERLAY_ROOT_C:-tix3ur0c}"

underlay_ip_a="${TRUSTIX_3IX_E2E_UNDERLAY_IP_A:-198.18.0.1}"
underlay_ip_b="${TRUSTIX_3IX_E2E_UNDERLAY_IP_B:-198.18.0.2}"
underlay_ip_c="${TRUSTIX_3IX_E2E_UNDERLAY_IP_C:-198.18.0.3}"
underlay_cidr_a="${TRUSTIX_3IX_E2E_UNDERLAY_CIDR_A:-${underlay_ip_a}/24}"
underlay_cidr_b="${TRUSTIX_3IX_E2E_UNDERLAY_CIDR_B:-${underlay_ip_b}/24}"
underlay_cidr_c="${TRUSTIX_3IX_E2E_UNDERLAY_CIDR_C:-${underlay_ip_c}/24}"

api_port="${TRUSTIX_3IX_E2E_API_PORT:-}"
peer_api_port="${TRUSTIX_3IX_E2E_PEER_API_PORT:-}"
transport_port="${TRUSTIX_3IX_E2E_TRANSPORT_PORT:-${TRUSTIX_3IX_E2E_TIX_TCP_PORT:-}}"
api_url=""
allocated_ports=""

pid_a=""
pid_b=""
pid_c=""
success=0
bridge_filter_comment="trustix-3ix-e2e:${bridge}:$$"
bridge_filter_rule_keys=""

log() {
  printf '[trustix-3ix-e2e] %s\n' "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

kernel_provider_expected() {
  [[ "$kernel_module" == "1" ]] || grep -q '^trustix_crypto ' /proc/modules 2>/dev/null
}

transport_endpoint_suffix() {
  printf '%s\n' "${transport//_/-}"
}

transport_endpoint_name() {
  local ix="$1"
  printf '%s-%s\n' "$ix" "$(transport_endpoint_suffix)"
}

transport_endpoint_protocol() {
  case "$transport" in
    kernel_udp) printf 'udp\n' ;;
    *) printf '%s\n' "$transport" ;;
  esac
}

transport_uses_required_link_tls() {
  case "$transport" in
    tcp|websocket|http_connect) return 0 ;;
    *) return 1 ;;
  esac
}

transport_policy_profile() {
  if [[ -n "$transport_profile" ]]; then
    printf '%s\n' "$transport_profile"
    return 0
  fi
  case "$transport" in
    tix_tcp|kernel_udp|gre|ipip|vxlan) printf 'performance\n' ;;
    *) printf 'stable\n' ;;
  esac
}

transport_policy_datapath() {
  if [[ -n "$transport_datapath" ]]; then
    printf '%s\n' "$transport_datapath"
    return 0
  fi
  case "$transport" in
    tix_tcp|kernel_udp|gre|ipip|vxlan) printf 'tc_xdp\n' ;;
    *) printf 'userspace\n' ;;
  esac
}

transport_policy_encryption() {
  printf '%s\n' "${transport_encryption:-secure}"
}

is_iptunnel_transport() {
  case "$transport" in
    gre|ipip|vxlan) return 0 ;;
    *) return 1 ;;
  esac
}

tunnel_endpoint_config() {
  local local_ip="$1"
  local remote_ip="$2"
  local local_carrier="$3"
  local remote_carrier="$4"
  local underlay_iface="$5"
  local vni="${6:-5527625}"
  local extra=""
  if [[ "$transport" == "vxlan" ]]; then
    extra=",underlay_if=${underlay_iface},vni=${vni},vxlan_port=4789"
  fi
  printf 'local=%s,remote=%s%s,local_carrier=%s/30,remote_carrier=%s,port=%s,mtu=1400' "$local_ip" "$remote_ip" "$extra" "$local_carrier" "$remote_carrier" "$transport_port"
}

native_tunnel_endpoint_name() {
  local ix="$1"
  local peer="$2"
  printf '%s-%s-%s\n' "$ix" "$(transport_endpoint_suffix)" "$peer"
}

native_tunnel_config_for() {
  local ix="$1"
  local peer="$2"
  case "${ix}:${peer}" in
    ix-a:ix-b) tunnel_endpoint_config "$underlay_ip_a" "$underlay_ip_b" 10.255.30.1 10.255.30.2 "$underlay_a" 5527625 ;;
    ix-b:ix-a) tunnel_endpoint_config "$underlay_ip_b" "$underlay_ip_a" 10.255.30.2 10.255.30.1 "$underlay_b" 5527625 ;;
    ix-b:ix-c) tunnel_endpoint_config "$underlay_ip_b" "$underlay_ip_c" 10.255.31.1 10.255.31.2 "$underlay_b" 5527626 ;;
    ix-c:ix-b) tunnel_endpoint_config "$underlay_ip_c" "$underlay_ip_b" 10.255.31.2 10.255.31.1 "$underlay_c" 5527626 ;;
    ix-a:ix-c) tunnel_endpoint_config "$underlay_ip_a" "$underlay_ip_c" 10.255.32.1 10.255.32.2 "$underlay_a" 5527627 ;;
    ix-c:ix-a) tunnel_endpoint_config "$underlay_ip_c" "$underlay_ip_a" 10.255.32.2 10.255.32.1 "$underlay_c" 5527627 ;;
    *) die "unsupported native tunnel pair ${ix}:${peer}" ;;
  esac
}

native_tunnel_peers_for() {
  case "$1" in
    ix-a) printf 'ix-b ix-c\n' ;;
    ix-b) printf 'ix-a ix-c\n' ;;
    ix-c) printf 'ix-b ix-a\n' ;;
    *) die "unknown IX for native tunnel peers: $1" ;;
  esac
}

choose_port() {
  local env_name="$1"
  local preferred="$2"
  local configured="${!env_name:-}"
  local port
  if [[ -n "$configured" ]]; then
    printf '%s\n' "${configured##*:}"
    return 0
  fi
  port="$(python3 - "$preferred" "$allocated_ports" <<'PY'
import socket
import sys

preferred = int(sys.argv[1])
used = {int(value) for value in sys.argv[2].split() if value}

def available(port):
    if port in used or port < 1 or port > 65535:
        return False
    sockets = []
    try:
        for sock_type in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            sock = socket.socket(socket.AF_INET, sock_type)
            sockets.append(sock)
            sock.bind(("127.0.0.1", port))
    except OSError:
        return False
    finally:
        for sock in sockets:
            sock.close()
    return True

if available(preferred):
    print(preferred)
    raise SystemExit(0)

for _ in range(100):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    finally:
        sock.close()
    if available(port):
        print(port)
        raise SystemExit(0)

raise SystemExit("could not allocate a free local port")
PY
)"
  printf '%s\n' "$port"
}

choose_port_pair_base() {
  local env_name="$1"
  local preferred="$2"
  local configured="${!env_name:-}"
  local port
  if [[ -n "$configured" ]]; then
    printf '%s\n' "${configured##*:}"
    return 0
  fi
  port="$(python3 - "$preferred" "$allocated_ports" <<'PY'
import socket
import sys

preferred = int(sys.argv[1])
used = {int(value) for value in sys.argv[2].split() if value}

def one_available(port):
    if port in used or port < 1 or port > 65535:
        return False
    sockets = []
    try:
        for sock_type in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            sock = socket.socket(socket.AF_INET, sock_type)
            sockets.append(sock)
            sock.bind(("127.0.0.1", port))
    except OSError:
        return False
    finally:
        for sock in sockets:
            sock.close()
    return True

def available_pair(port):
    return port < 65535 and one_available(port) and one_available(port + 1)

if available_pair(preferred):
    print(preferred)
    raise SystemExit(0)

for _ in range(100):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    finally:
        sock.close()
    if available_pair(port):
        print(port)
        raise SystemExit(0)

raise SystemExit("could not allocate a free local port pair")
PY
)"
  printf '%s\n' "$port"
}

remember_port() {
  allocated_ports="${allocated_ports} $1"
}

allocate_ports() {
  api_port="$(choose_port TRUSTIX_3IX_E2E_API_PORT 18787)"
  remember_port "$api_port"
  peer_api_port="$(choose_port TRUSTIX_3IX_E2E_PEER_API_PORT 19443)"
  remember_port "$peer_api_port"
  if [[ -n "$transport_port" ]]; then
    transport_port="${transport_port##*:}"
  else
    transport_port="$(choose_port TRUSTIX_3IX_E2E_TRANSPORT_PORT 17041)"
  fi
  remember_port "$transport_port"
  udp_burst_port="$(choose_port_pair_base TRUSTIX_3IX_E2E_UDP_BURST_PORT 28100)"
  remember_port "$udp_burst_port"
  remember_port "$((udp_burst_port + 1))"
  tcp_burst_port="$(choose_port_pair_base TRUSTIX_3IX_E2E_TCP_BURST_PORT 28200)"
  remember_port "$tcp_burst_port"
  remember_port "$((tcp_burst_port + 1))"
  api_url="http://127.0.0.1:${api_port}"
}

run_in_netns() {
  local ns="$1"
  shift
  ip netns exec "$ns" "$@"
}

stop_daemon_pid_with_signal() {
  local pid="$1"
  local signal="${2:-INT}"
  [[ -n "$pid" ]] || return 0
  kill -0 "$pid" >/dev/null 2>&1 || return 0
  kill "-${signal}" "$pid" >/dev/null 2>&1 || true
  for _ in $(seq 1 50); do
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      wait "$pid" >/dev/null 2>&1 || true
      return 0
    fi
    sleep 0.1
  done
  kill "$pid" >/dev/null 2>&1 || true
  wait "$pid" >/dev/null 2>&1 || true
}

stop_daemon_pid() {
  stop_daemon_pid_with_signal "$1" INT
}

stop_daemons_by_workdir() {
  local pids
  pids="$(ps -eo pid=,comm=,args= | awk -v wd="$workdir" '$2 == "trustixd" && index($0, wd) { print $1 }')"
  [[ -n "$pids" ]] || return 0
  log "stopping orphaned trustixd processes for ${workdir}: $(printf '%s\n' "$pids" | tr '\n' ' ')"
  printf '%s\n' "$pids" | while read -r pid; do
    [[ -n "$pid" ]] || continue
    kill -INT "$pid" >/dev/null 2>&1 || true
  done
  sleep 1
  printf '%s\n' "$pids" | while read -r pid; do
    [[ -n "$pid" ]] || continue
    kill -0 "$pid" >/dev/null 2>&1 || continue
    kill "$pid" >/dev/null 2>&1 || true
  done
}

cleanup() {
  local exit_code=$?
  set +e
  stop_daemon_pid "$pid_a"
  stop_daemon_pid "$pid_b"
  stop_daemon_pid "$pid_c"
  stop_daemons_by_workdir
  if [[ "$keep" != "1" ]]; then
    remove_underlay_bridge_forwarding
  else
    log "preserving temporary bridge forwarding rules for kept topology: ${bridge_filter_comment}"
  fi
  if [[ "$keep" != "1" ]]; then
    ip netns del "$ns_ix_a" >/dev/null 2>&1
    ip netns del "$ns_ix_b" >/dev/null 2>&1
    ip netns del "$ns_ix_c" >/dev/null 2>&1
    ip netns del "$ns_lan_a" >/dev/null 2>&1
    ip netns del "$ns_lan_b" >/dev/null 2>&1
    ip netns del "$ns_lan_c" >/dev/null 2>&1
    ip link del "$bridge" >/dev/null 2>&1
    ip link del "$underlay_root_a" >/dev/null 2>&1
    ip link del "$underlay_root_b" >/dev/null 2>&1
    ip link del "$underlay_root_c" >/dev/null 2>&1
    ip link del "$lan_a" >/dev/null 2>&1
    ip link del "$lan_b" >/dev/null 2>&1
    ip link del "$lan_c" >/dev/null 2>&1
  fi
  if [[ "$success" == "1" && "$keep" != "1" && -z "${TRUSTIX_3IX_E2E_WORKDIR:-}" ]]; then
    rm -rf "$workdir"
  else
    log "workdir preserved: $workdir"
  fi
  exit "$exit_code"
}
trap cleanup EXIT

require_linux_root() {
  [[ "$(uname -s)" == "Linux" ]] || die "linux-three-ix-e2e-smoke must run on Linux"
  [[ "${EUID:-$(id -u)}" == "0" ]] || die "linux-three-ix-e2e-smoke must run as root for netns, TC/eBPF, and AF_XDP"
}

clean_previous_topology() {
  remove_underlay_bridge_forwarding
  ip netns del "$ns_ix_a" >/dev/null 2>&1 || true
  ip netns del "$ns_ix_b" >/dev/null 2>&1 || true
  ip netns del "$ns_ix_c" >/dev/null 2>&1 || true
  ip netns del "$ns_lan_a" >/dev/null 2>&1 || true
  ip netns del "$ns_lan_b" >/dev/null 2>&1 || true
  ip netns del "$ns_lan_c" >/dev/null 2>&1 || true
  ip link del "$bridge" >/dev/null 2>&1 || true
  ip link del "$underlay_root_a" >/dev/null 2>&1 || true
  ip link del "$underlay_root_b" >/dev/null 2>&1 || true
  ip link del "$underlay_root_c" >/dev/null 2>&1 || true
  ip link del "$lan_a" >/dev/null 2>&1 || true
  ip link del "$lan_b" >/dev/null 2>&1 || true
  ip link del "$lan_c" >/dev/null 2>&1 || true
}

insert_underlay_bridge_forward_rule() {
  local in_port="$1"
  local out_port="$2"
  if ! iptables -w -I FORWARD 1 \
    -m physdev --physdev-in "$in_port" --physdev-out "$out_port" \
    -m comment --comment "$bridge_filter_comment" \
    -j ACCEPT >/dev/null 2>&1; then
    return 1
  fi
  bridge_filter_rule_keys="${bridge_filter_rule_keys}${in_port}|${out_port}
"
}

remove_underlay_bridge_forwarding() {
  local key
  local in_port
  local out_port
  if [[ -z "$bridge_filter_rule_keys" ]]; then
    return 0
  fi
  if ! command -v iptables >/dev/null 2>&1; then
    bridge_filter_rule_keys=""
    return 0
  fi
  while IFS= read -r key; do
    [[ -n "$key" ]] || continue
    in_port="${key%%|*}"
    out_port="${key##*|}"
    while iptables -w -D FORWARD \
      -m physdev --physdev-in "$in_port" --physdev-out "$out_port" \
      -m comment --comment "$bridge_filter_comment" \
      -j ACCEPT >/dev/null 2>&1; do
      :
    done
  done <<EOF
$bridge_filter_rule_keys
EOF
  bridge_filter_rule_keys=""
}

maybe_allow_underlay_bridge_forwarding() {
  local ports="${underlay_root_a} ${underlay_root_b} ${underlay_root_c}"
  local in_port
  local out_port
  if ! command -v iptables >/dev/null 2>&1; then
    log "iptables unavailable; underlay bridge forwarding will rely on host defaults"
    return 0
  fi
  log "installing temporary physdev FORWARD accepts for underlay bridge ${bridge}"
  for in_port in $ports; do
    for out_port in $ports; do
      [[ "$in_port" != "$out_port" ]] || continue
      if ! insert_underlay_bridge_forward_rule "$in_port" "$out_port"; then
        log "warning: could not insert physdev FORWARD rule ${in_port}->${out_port}; host firewall defaults must allow bridge forwarding"
        return 0
      fi
    done
  done
}

assert_underlay_ping() {
  local src_ns="$1"
  local dst="$2"
  local label="$3"
  local attempt
  for attempt in $(seq 1 5); do
    if run_in_netns "$src_ns" ping -c 1 -W 1 "$dst" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.2
  done
  log "underlay bridge forwarding failed while probing ${label}"
  log "bridge netfilter sysctls:"
  for sysctl_key in net.bridge.bridge-nf-call-iptables net.bridge.bridge-nf-call-ip6tables net.bridge.bridge-nf-call-arptables; do
    sysctl "$sysctl_key" 2>/dev/null || true
  done >&2
  if command -v iptables >/dev/null 2>&1; then
    log "iptables FORWARD rules:"
    iptables -S FORWARD >&2 || true
  fi
  die "underlay bridge cannot forward ${label}; host firewall is blocking test netns traffic"
}

assert_underlay_bridge_forwarding() {
  log "validating underlay bridge forwarding before starting daemons"
  assert_underlay_ping "$ns_ix_a" "$underlay_ip_b" "ix-a -> ix-b"
  assert_underlay_ping "$ns_ix_a" "$underlay_ip_c" "ix-a -> ix-c"
  assert_underlay_ping "$ns_ix_b" "$underlay_ip_a" "ix-b -> ix-a"
  assert_underlay_ping "$ns_ix_b" "$underlay_ip_c" "ix-b -> ix-c"
  assert_underlay_ping "$ns_ix_c" "$underlay_ip_a" "ix-c -> ix-a"
  assert_underlay_ping "$ns_ix_c" "$underlay_ip_b" "ix-c -> ix-b"
}

setup_lan_pair() {
  local ix_ns="$1"
  local lan_ns="$2"
  local ix_iface="$3"
  local host_iface="$4"
  local host_cidr="$5"
  local gateway="$6"

  ip link add "$ix_iface" type veth peer name "$host_iface"
  ip link set "$ix_iface" netns "$ix_ns"
  ip link set "$host_iface" netns "$lan_ns"
  ip netns exec "$ix_ns" ip link set "$ix_iface" up
  ip netns exec "$lan_ns" ip link set "$host_iface" up
  ip netns exec "$lan_ns" ip addr add "$host_cidr" dev "$host_iface"
  ip netns exec "$lan_ns" ip route replace default via "$gateway"
}

setup_underlay_peer() {
  local ix_ns="$1"
  local root_iface="$2"
  local ix_iface="$3"
  local cidr="$4"

  ip link add "$root_iface" type veth peer name "$ix_iface"
  ip link set "$ix_iface" netns "$ix_ns"
  ip link set "$root_iface" master "$bridge"
  ip link set "$root_iface" up
  ip netns exec "$ix_ns" ip link set "$ix_iface" up
  ip netns exec "$ix_ns" ip addr add "$cidr" dev "$ix_iface"
}

setup_topology() {
  log "creating 3-IX router namespaces, LAN namespaces, and shared underlay bridge"
  clean_previous_topology
  ip netns add "$ns_ix_a"
  ip netns add "$ns_ix_b"
  ip netns add "$ns_ix_c"
  ip netns add "$ns_lan_a"
  ip netns add "$ns_lan_b"
  ip netns add "$ns_lan_c"

  for ns in "$ns_ix_a" "$ns_ix_b" "$ns_ix_c" "$ns_lan_a" "$ns_lan_b" "$ns_lan_c"; do
    ip netns exec "$ns" ip link set lo up
  done

  ip link add "$bridge" type bridge
  ip link set "$bridge" up

  setup_underlay_peer "$ns_ix_a" "$underlay_root_a" "$underlay_a" "$underlay_cidr_a"
  setup_underlay_peer "$ns_ix_b" "$underlay_root_b" "$underlay_b" "$underlay_cidr_b"
  setup_underlay_peer "$ns_ix_c" "$underlay_root_c" "$underlay_c" "$underlay_cidr_c"
  maybe_allow_underlay_bridge_forwarding
  assert_underlay_bridge_forwarding

  setup_lan_pair "$ns_ix_a" "$ns_lan_a" "$lan_a" "$host_a" "10.0.0.2/24" "10.0.0.1"
  setup_lan_pair "$ns_ix_b" "$ns_lan_b" "$lan_b" "$host_b" "10.0.1.2/24" "10.0.1.1"
  setup_lan_pair "$ns_ix_c" "$ns_lan_c" "$lan_c" "$host_c" "10.0.2.2/24" "10.0.2.1"
}

build_binaries() {
  if [[ -n "${TRUSTIX_3IX_E2E_BIN_DIR:-}" ]]; then
    log "using prebuilt binaries from ${bin_dir}"
    [[ -x "$bin_dir/trustixd" ]] || die "missing executable: ${bin_dir}/trustixd"
    [[ -x "$bin_dir/trustixctl" ]] || die "missing executable: ${bin_dir}/trustixctl"
    [[ -x "$bin_dir/trustix-ca" ]] || die "missing executable: ${bin_dir}/trustix-ca"
    return 0
  fi
  log "building trustix binaries"
  mkdir -p "$bin_dir"
  (cd "$repo_root" && go build -o "$bin_dir/trustixd" ./cmd/trustixd)
  (cd "$repo_root" && go build -o "$bin_dir/trustixctl" ./cmd/trustixctl)
  (cd "$repo_root" && go build -o "$bin_dir/trustix-ca" ./cmd/trustix-ca)
}

generate_certs() {
  log "generating three IX certificates"
  mkdir -p "$workdir/certs"
  "$bin_dir/trustix-ca" quickstart -out "$workdir/certs" -domain lab.local -ix ix-a,ix-b,ix-c >/dev/null
  "$bin_dir/trustix-ca" route authorize \
    -out "$workdir/certs" \
    -domain lab.local \
    -ix ix-c \
    -prefix 10.0.2.0/24 \
    -ca-cert "$workdir/certs/config-ca.pem" \
    -ca-key "$workdir/certs/config-ca.key" >/dev/null
}

prefix_list_yaml() {
  local raw="$1"
  if [[ -z "$raw" ]]; then
    printf ' []\n'
    return 0
  fi
  local old_ifs="$IFS"
  local part
  printf '\n'
  IFS=','
  for part in $raw; do
    part="${part#"${part%%[![:space:]]*}"}"
    part="${part%"${part##*[![:space:]]}"}"
    [[ -z "$part" ]] || printf '    - %s\n' "$part"
  done
  IFS="$old_ifs"
}

bootstrap_yaml() {
  local raw="$1"
  if [[ -z "$raw" ]]; then
    printf 'bootstrap: {}\n'
    return 0
  fi
  local old_ifs="$IFS"
  local target
  printf 'bootstrap:\n'
  printf '  peers:\n'
  IFS=','
  for target in $raw; do
    target="${target#"${target%%[![:space:]]*}"}"
    target="${target%"${target##*[![:space:]]}"}"
    [[ -z "$target" ]] || printf '    - control_api: https://%s:%s\n' "$target" "$peer_api_port"
  done
  IFS="$old_ifs"
}

write_endpoint_yaml() {
  local output="$1"
  local indent="$2"
  local name="$3"
  local listen="$4"
  local address="$5"
  local protocol="$6"
  cat >>"$output" <<EOF
${indent}- name: ${name}
${indent}  mode: passive
${indent}  listen: ${listen}
${indent}  address: ${address}
${indent}  transport: ${protocol}
EOF
  if transport_uses_required_link_tls; then
    cat >>"$output" <<EOF
${indent}  security:
${indent}    link_tls: required
EOF
  fi
  cat >>"$output" <<EOF
${indent}  enabled: true
EOF
}

write_local_endpoints_yaml() {
  local output="$1"
  local ix="$2"
  local underlay_ip="$3"
  local endpoint_name="$4"
  local endpoint_transport="$5"
  if is_iptunnel_transport; then
    local peer
    for peer in $(native_tunnel_peers_for "$ix"); do
      write_endpoint_yaml "$output" "  " "$(native_tunnel_endpoint_name "$ix" "$peer")" "$(native_tunnel_config_for "$ix" "$peer")" "$(native_tunnel_config_for "$ix" "$peer")" "$endpoint_transport"
    done
    return 0
  fi
  write_endpoint_yaml "$output" "  " "$endpoint_name" "${underlay_ip}:${transport_port}" "${underlay_ip}:${transport_port}" "$endpoint_transport"
}

transport_candidates_yaml() {
  local ix="$1"
  if is_iptunnel_transport; then
    local peer
    for peer in $(native_tunnel_peers_for "$ix"); do
      printf '    - %s\n' "$(native_tunnel_endpoint_name "$ix" "$peer")"
    done
    return 0
  fi
  printf '    - %s\n' "$(transport_endpoint_name "$ix")"
}

generate_config() {
  local ix="$1"
  local underlay_ip="$2"
  local lan_iface="$3"
  local underlay_iface="$4"
  local gateway="$5"
  local prefix="$6"
  local bootstrap_targets="$7"
  local import_prefixes="$8"
  local export_prefixes="$9"
  local output="${10}"
  local peers_block="${11:-peers: []}"
  local routes_block="${12:-routes: []}"

  local endpoint_name
  local endpoint_transport
  endpoint_name="$(transport_endpoint_name "$ix")"
  endpoint_transport="$(transport_endpoint_protocol)"
  local bootstrap_block
  bootstrap_block="$(bootstrap_yaml "$bootstrap_targets")"

  cat >"$output" <<EOF
domain:
  id: lab.local
  trust_roots:
    - $workdir/certs/root-ca.pem
    - $workdir/certs/domain-ca.pem
    - $workdir/certs/config-ca.pem

ix:
  id: $ix
  domain: lab.local
  cert: $workdir/certs/$ix.crt
  key: $workdir/certs/$ix.key
  control_api: https://${underlay_ip}:${peer_api_port}
  route_authorizations:
    - $workdir/certs/$ix-route.crt

lan:
  iface: $lan_iface
  underlay_iface: $underlay_iface
  gateway: $gateway
  advertise:
    - $prefix
  mode: routed
  manage_address: true
  manage_forwarding: true
  manage_rp_filter: true

endpoints:
EOF
  write_local_endpoints_yaml "$output" "$ix" "$underlay_ip" "$endpoint_name" "$endpoint_transport"

  cat >>"$output" <<EOF

$peers_block

$routes_block

route_policy:
  import_prefixes:$import_prefixes
  export_prefixes:$export_prefixes
  dynamic_metric: $dynamic_metric

policies:
  - name: default-routed
    route_selection: longest_prefix
    load_balance: least_conn
    flow_stickiness: true
    rewrite: preserve_source

transport_policy:
  mode: user_defined
  profile: $(transport_policy_profile)
  datapath: $(transport_policy_datapath)
  candidates:
EOF
  transport_candidates_yaml "$ix" >>"$output"
  cat >>"$output" <<EOF
  failover: health_based
  load_balance: least_conn
  encryption: $(transport_policy_encryption)
  crypto_key_source: auto
EOF

  if [[ "$transport" == "kernel_udp" ]]; then
    cat >>"$output" <<EOF
  kernel_transport:
    mode: require_kernel
EOF
  fi

  cat >>"$output" <<EOF
  crypto_placement: $crypto_placement

$bootstrap_block
EOF
  log "$ix config: $output"
}

write_configs() {
  local a_import="$1"
  local c_export="$2"
  generate_config ix-a "$underlay_ip_a" "$lan_a" "$underlay_a" "10.0.0.1/24" "10.0.0.0/24" "$underlay_ip_b" "$(prefix_list_yaml "$a_import")" "$(prefix_list_yaml "")" "$workdir/a.yaml"
  generate_config ix-b "$underlay_ip_b" "$lan_b" "$underlay_b" "10.0.1.1/24" "10.0.1.0/24" "$underlay_ip_c" "$(prefix_list_yaml "")" "$(prefix_list_yaml "")" "$workdir/b.yaml"
  generate_config ix-c "$underlay_ip_c" "$lan_c" "$underlay_c" "10.0.2.1/24" "10.0.2.0/24" "$underlay_ip_b" "$(prefix_list_yaml "")" "$(prefix_list_yaml "$c_export")" "$workdir/c.yaml"
}

append_static_peer_endpoint() {
  local output="$1"
  local endpoint_name="$2"
  local endpoint_address="$3"
  local endpoint_transport="$4"
  cat >>"$output" <<EOF
      - name: ${endpoint_name}
        address: ${endpoint_address}
        transport: ${endpoint_transport}
EOF
  if transport_uses_required_link_tls; then
    cat >>"$output" <<EOF
        security:
          link_tls: required
EOF
  fi
}

write_a_transit_config() {
  local peers_block routes_block peers_file
  local endpoint_name
  local endpoint_transport
  local endpoint_address
  endpoint_name="$(transport_endpoint_name ix-b)"
  endpoint_transport="$(transport_endpoint_protocol)"
  endpoint_address="${underlay_ip_b}:${transport_port}"
  if is_iptunnel_transport; then
    endpoint_name="$(native_tunnel_endpoint_name ix-b ix-a)"
    endpoint_address="$(native_tunnel_config_for ix-a ix-b)"
  fi
  peers_file="$workdir/a-transit-peers.yaml"
  cat >"$peers_file" <<EOF
peers:
  - id: ix-b
    domain: lab.local
    control_api: https://${underlay_ip_b}:${peer_api_port}
    endpoints:
EOF
  append_static_peer_endpoint "$peers_file" "$endpoint_name" "$endpoint_address" "$endpoint_transport"
  cat >>"$peers_file" <<EOF
    allowed_prefixes:
      - 10.0.1.0/24
  - id: ix-c
    domain: lab.local
    control_api: https://${underlay_ip_c}:${peer_api_port}
    endpoints: []
    allowed_prefixes:
      - 10.0.2.0/24
EOF
  peers_block="$(cat "$peers_file")"
  routes_block="$(cat <<EOF
routes:
  - prefix: 10.0.2.0/24
    owner: ix-c
    next_hop: ix-b
    endpoint: ${endpoint_name}
    policy: default-routed
    metric: 50
EOF
)"
  generate_config ix-a "$underlay_ip_a" "$lan_a" "$underlay_a" "10.0.0.1/24" "10.0.0.0/24" "$underlay_ip_b" "$(prefix_list_yaml "10.0.0.0/8")" "$(prefix_list_yaml "")" "$workdir/a-transit.yaml" "$peers_block" "$routes_block"
}

write_c_transit_config() {
  local peers_block routes_block peers_file
  local endpoint_name
  local endpoint_transport
  local endpoint_address
  endpoint_name="$(transport_endpoint_name ix-b)"
  endpoint_transport="$(transport_endpoint_protocol)"
  endpoint_address="${underlay_ip_b}:${transport_port}"
  if is_iptunnel_transport; then
    endpoint_name="$(native_tunnel_endpoint_name ix-b ix-c)"
    endpoint_address="$(native_tunnel_config_for ix-c ix-b)"
  fi
  peers_file="$workdir/c-transit-peers.yaml"
  cat >"$peers_file" <<EOF
peers:
  - id: ix-b
    domain: lab.local
    control_api: https://${underlay_ip_b}:${peer_api_port}
    endpoints:
EOF
  append_static_peer_endpoint "$peers_file" "$endpoint_name" "$endpoint_address" "$endpoint_transport"
  cat >>"$peers_file" <<EOF
    allowed_prefixes:
      - 10.0.1.0/24
  - id: ix-a
    domain: lab.local
    control_api: https://${underlay_ip_a}:${peer_api_port}
    endpoints: []
    allowed_prefixes:
      - 10.0.0.0/24
EOF
  peers_block="$(cat "$peers_file")"
  routes_block="$(cat <<EOF
routes:
  - prefix: 10.0.0.0/24
    owner: ix-a
    next_hop: ix-b
    endpoint: ${endpoint_name}
    policy: default-routed
    metric: 50
EOF
)"
  generate_config ix-c "$underlay_ip_c" "$lan_c" "$underlay_c" "10.0.2.1/24" "10.0.2.0/24" "$underlay_ip_b" "$(prefix_list_yaml "")" "$(prefix_list_yaml "10.0.2.0/24")" "$workdir/c-transit.yaml" "$peers_block" "$routes_block"
}

start_daemon() {
  local node="$1"
  local config_path="$2"
  local data_dir="$3"
  local ns="$4"
  local peer_ip="$5"
  local log_path="$workdir/${node}.log"

  mkdir -p "$data_dir"
  log "starting ${node}"
  run_in_netns "$ns" env \
    "TRUSTIX_AF_XDP_QUEUES=${af_xdp_queues}" \
    "TRUSTIX_XDP_MODE=${xdp_mode}" \
    "TRUSTIX_AF_XDP_BIND_MODE=${af_xdp_bind_mode}" \
    "TRUSTIX_AF_XDP_TX_BACKPRESSURE_WAIT=${af_xdp_tx_backpressure_wait}" \
    "TRUSTIX_TC_HOT_STATS=${hot_stats}" \
    "TRUSTIX_CONTROL_CLIENT_TIMEOUT=${control_client_timeout}" \
    "$bin_dir/trustixd" \
      -config "$config_path" \
      -data-dir "$data_dir" \
      -api "127.0.0.1:${api_port}" \
      -peer-api "${peer_ip}:${peer_api_port}" \
      -dataplane "$dataplane" \
      >"$log_path" 2>&1 &
  printf '%s\n' "$!"
}

wait_for_api() {
  local node="$1"
  local pid="$2"
  local ns="$3"
  for _ in $(seq 1 "$control_wait_attempts"); do
    if run_in_netns "$ns" curl -fsS "${api_url}/v1/status" >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      log "${node} exited early; log follows"
      sed -n '1,240p' "$workdir/${node}.log" >&2 || true
      return 1
    fi
    sleep 0.25
  done
  log "${node} did not become ready; log follows"
  sed -n '1,260p' "$workdir/${node}.log" >&2 || true
  return 1
}

ctl_ns() {
  local ns="$1"
  shift
  run_in_netns "$ns" "$bin_dir/trustixctl" -api "$api_url" "$@"
}

wait_ctl_grep() {
  local label="$1"
  local ns="$2"
  local output="$3"
  local pattern="$4"
  shift 4
  for _ in $(seq 1 100); do
    ctl_ns "$ns" "$@" >"$output" 2>"$output.err" || true
    if grep -q "$pattern" "$output"; then
      return 0
    fi
    sleep 0.25
  done
  cat "$output" >&2 || true
  cat "$output.err" >&2 || true
  collect_api_all || true
  die "timed out waiting for $label"
}

assert_not_grep() {
  local pattern="$1"
  local file="$2"
  if grep -q "$pattern" "$file"; then
    cat "$file" >&2 || true
    die "unexpected pattern $pattern in $file"
  fi
}

assert_data_dir_lock_rejects_duplicate() {
  local node="$1"
  local config_path="$2"
  local data_dir="$3"
  local ns="$4"
  local peer_ip="$5"
  local log_path="$workdir/${node}-duplicate-lock.log"

  log "validating ${node} data-dir lock"
  set +e
  run_in_netns "$ns" env \
    "TRUSTIX_AF_XDP_QUEUES=${af_xdp_queues}" \
    "TRUSTIX_XDP_MODE=${xdp_mode}" \
    "TRUSTIX_AF_XDP_BIND_MODE=${af_xdp_bind_mode}" \
    "TRUSTIX_AF_XDP_TX_BACKPRESSURE_WAIT=${af_xdp_tx_backpressure_wait}" \
    timeout 5s "$bin_dir/trustixd" \
      -config "$config_path" \
      -data-dir "$data_dir" \
      -api "127.0.0.1:${api_port}" \
      -peer-api "${peer_ip}:${peer_api_port}" \
      -dataplane "$dataplane" \
      >"$log_path" 2>&1
  local rc=$?
  set -e
  if [[ "$rc" == "0" ]]; then
    die "${node} duplicate daemon unexpectedly exited successfully"
  fi
  if ! grep -q "already locked" "$log_path"; then
    sed -n '1,160p' "$log_path" >&2 || true
    die "${node} duplicate daemon did not fail on data-dir lock (exit=${rc})"
  fi
}

assert_tix_tcp_kernel_crypto_rejects() {
  if [[ "$transport" != "tix_tcp" ]]; then
    return 0
  fi
  if [[ "$crypto_placement" == "kernel" || "$kernel_module" == "1" ]]; then
    return 0
  fi
  if kernel_provider_expected; then
    log "skipping unavailable-kernel-crypto rejection check because trustix_crypto is already loaded"
    return 0
  fi

  local kernel_config="$workdir/ix-a-kernel-crypto.yaml"
  local data_dir="$workdir/state-kernel-reject"
  local log_path="$workdir/ix-a-kernel-crypto-reject.log"
  sed 's/crypto_placement: userspace/crypto_placement: kernel/' "$workdir/a.yaml" >"$kernel_config"
  mkdir -p "$data_dir"
  log "validating strict kernel crypto rejects when the kernel AEAD provider is unavailable"
  set +e
  run_in_netns "$ns_ix_a" env \
    "TRUSTIX_AF_XDP_QUEUES=${af_xdp_queues}" \
    "TRUSTIX_XDP_MODE=${xdp_mode}" \
    "TRUSTIX_AF_XDP_BIND_MODE=${af_xdp_bind_mode}" \
    "TRUSTIX_AF_XDP_TX_BACKPRESSURE_WAIT=${af_xdp_tx_backpressure_wait}" \
    timeout 8s "$bin_dir/trustixd" \
      -config "$kernel_config" \
      -data-dir "$data_dir" \
      -api "127.0.0.1:${api_port}" \
      -peer-api "${underlay_ip_a}:${peer_api_port}" \
      -dataplane "$dataplane" \
      >"$log_path" 2>&1
  local rc=$?
  set -e
  if [[ "$rc" == "0" ]]; then
    die "kernel crypto daemon unexpectedly started successfully"
  fi
  if [[ "$rc" == "124" ]]; then
    sed -n '1,180p' "$log_path" >&2 || true
    die "kernel crypto daemon timed out instead of rejecting unavailable provider"
  fi
  if ! grep -q "kernel crypto requested but unavailable" "$log_path"; then
    sed -n '1,180p' "$log_path" >&2 || true
    die "kernel crypto daemon did not report strict placement rejection (exit=${rc})"
  fi
}

assert_sigterm_releases_data_dir_lock() {
  log "validating ix-a SIGTERM cleanup and data-dir lock release"
  stop_daemon_pid_with_signal "$pid_a" TERM
  pid_a=""
  pid_a="$(start_daemon ix-a-sigterm-restart "$workdir/a.yaml" "$workdir/state-a" "$ns_ix_a" "$underlay_ip_a")"
  wait_for_api ix-a-sigterm-restart "$pid_a" "$ns_ix_a"
  assert_data_dir_lock_rejects_duplicate ix-a "$workdir/a.yaml" "$workdir/state-a" "$ns_ix_a" "$underlay_ip_a"
}

warm_neighbors() {
  log "warming LAN and underlay neighbor cache"
  run_in_netns "$ns_ix_a" ping -c 1 -W 1 10.0.0.2 >/dev/null 2>&1 || true
  run_in_netns "$ns_ix_b" ping -c 1 -W 1 10.0.1.2 >/dev/null 2>&1 || true
  run_in_netns "$ns_ix_c" ping -c 1 -W 1 10.0.2.2 >/dev/null 2>&1 || true
  run_in_netns "$ns_ix_a" ping -c 1 -W 1 "$underlay_ip_b" >/dev/null 2>&1 || true
  run_in_netns "$ns_ix_a" ping -c 1 -W 1 "$underlay_ip_c" >/dev/null 2>&1 || true
  run_in_netns "$ns_ix_b" ping -c 1 -W 1 "$underlay_ip_a" >/dev/null 2>&1 || true
  run_in_netns "$ns_ix_b" ping -c 1 -W 1 "$underlay_ip_c" >/dev/null 2>&1 || true
  run_in_netns "$ns_ix_c" ping -c 1 -W 1 "$underlay_ip_a" >/dev/null 2>&1 || true
  run_in_netns "$ns_ix_c" ping -c 1 -W 1 "$underlay_ip_b" >/dev/null 2>&1 || true
}

run_ping_pressure() {
  local src_ns="$1"
  local dst="$2"
  local round
  local worker
  local pids
  local pid
  local rc
  for round in $(seq 1 "$ping_rounds"); do
    pids=""
    for worker in $(seq 1 "$ping_parallel"); do
      ip netns exec "$src_ns" ping -c "$ping_count" -s "$ping_size" -W 1 "$dst" >/dev/null 2>&1 &
      pids="${pids} $!"
    done
    rc=0
    for pid in $pids; do
      wait "$pid" || rc=1
    done
    [[ "$rc" == "0" ]] || return 1
  done
  return 0
}

retry_ping() {
  local src_ns="$1"
  local dst="$2"
  local label="$3"
  for attempt in $(seq 1 30); do
    if run_ping_pressure "$src_ns" "$dst"; then
      log "${label} ping ok on attempt ${attempt} count=${ping_count} size=${ping_size} parallel=${ping_parallel} rounds=${ping_rounds}"
      return 0
    fi
    sleep 0.5
  done
  collect_api_all || true
  die "${label} ping failed"
}

run_payload_bursts() {
  if [[ "$udp_burst_packets" -gt 0 ]]; then
    run_udp_payload_burst "$ns_lan_a" "$ns_lan_c" "10.0.2.2" "$udp_burst_port" "LAN A -> LAN C UDP burst"
    run_udp_payload_burst "$ns_lan_c" "$ns_lan_a" "10.0.0.2" "$((udp_burst_port + 1))" "LAN C -> LAN A UDP burst"
  fi
  if [[ "$tcp_burst_connections" -gt 0 ]]; then
    run_tcp_payload_burst "$ns_lan_a" "$ns_lan_c" "10.0.2.2" "$tcp_burst_port" "LAN A -> LAN C TCP burst"
    run_tcp_payload_burst "$ns_lan_c" "$ns_lan_a" "10.0.0.2" "$((tcp_burst_port + 1))" "LAN C -> LAN A TCP burst"
  fi
}

run_udp_payload_burst() {
  local src_ns="$1"
  local dst_ns="$2"
  local dst_ip="$3"
  local port="$4"
  local label="$5"
  local expected=$((udp_burst_packets * udp_burst_parallel * udp_burst_rounds))
  local safe_label
  safe_label="$(printf '%s' "$label" | sed 's/[^A-Za-z0-9_.-]/_/g')"
  local recv_log="$workdir/${safe_label}-udp-recv.log"
  local send_log="$workdir/${safe_label}-udp-send.log"
  log "${label}: packets=${udp_burst_packets} size=${udp_burst_size} parallel=${udp_burst_parallel} rounds=${udp_burst_rounds}"
  run_in_netns "$dst_ns" python3 - "$dst_ip" "$port" "$expected" "$burst_timeout" >"$recv_log" 2>&1 <<'PY' &
import socket
import sys
import time

bind_ip = sys.argv[1]
port = int(sys.argv[2])
expected = int(sys.argv[3])
timeout = float(sys.argv[4])

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, max(4 * 1024 * 1024, expected * 2048))
sock.bind((bind_ip, port))
sock.settimeout(0.1)
deadline = time.monotonic() + timeout
count = 0
received = 0
while count < expected and time.monotonic() < deadline:
    try:
        payload, _ = sock.recvfrom(65535)
    except socket.timeout:
        continue
    count += 1
    received += len(payload)
print(f"received={count} bytes={received} expected={expected}", flush=True)
if count != expected:
    sys.exit(1)
PY
  local server_pid=$!
  sleep 0.2
  if ! run_in_netns "$src_ns" python3 - "$dst_ip" "$port" "$udp_burst_packets" "$udp_burst_size" "$udp_burst_parallel" "$udp_burst_rounds" >"$send_log" 2>&1 <<'PY'; then
import socket
import sys
import threading

dst_ip = sys.argv[1]
port = int(sys.argv[2])
packets = int(sys.argv[3])
size = int(sys.argv[4])
parallel = int(sys.argv[5])
rounds = int(sys.argv[6])
prefix = b"TIX3-UDP-BURST"
payload = (prefix + bytes(max(0, size - len(prefix))))[:size]
errors = []
sent_total = 0
lock = threading.Lock()

def send_worker(worker_id):
    global sent_total
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
        for _ in range(packets):
            sock.sendto(payload, (dst_ip, port))
            with lock:
                sent_total += 1
        sock.close()
    except Exception as exc:
        with lock:
            errors.append(f"worker={worker_id}: {exc}")

for _ in range(rounds):
    threads = [threading.Thread(target=send_worker, args=(worker,)) for worker in range(parallel)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

print(f"sent={sent_total} expected={packets * parallel * rounds}", flush=True)
if errors:
    print("\n".join(errors), file=sys.stderr)
    sys.exit(1)
PY
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" >/dev/null 2>&1 || true
    sed -n '1,120p' "$send_log" >&2 || true
    collect_api_all || true
    die "${label} sender failed"
  fi
  if ! wait "$server_pid"; then
    sed -n '1,120p' "$send_log" >&2 || true
    sed -n '1,120p' "$recv_log" >&2 || true
    collect_api_all || true
    die "${label} receiver did not observe all packets"
  fi
}

run_tcp_payload_burst() {
  local src_ns="$1"
  local dst_ns="$2"
  local dst_ip="$3"
  local port="$4"
  local label="$5"
  local expected=$((tcp_burst_connections * tcp_burst_parallel * tcp_burst_rounds))
  local safe_label
  safe_label="$(printf '%s' "$label" | sed 's/[^A-Za-z0-9_.-]/_/g')"
  local recv_log="$workdir/${safe_label}-tcp-recv.log"
  local send_log="$workdir/${safe_label}-tcp-send.log"
  log "${label}: connections=${tcp_burst_connections} size=${tcp_burst_size} parallel=${tcp_burst_parallel} rounds=${tcp_burst_rounds}"
  run_in_netns "$dst_ns" python3 - "$dst_ip" "$port" "$expected" "$tcp_burst_size" "$burst_timeout" >"$recv_log" 2>&1 <<'PY' &
import socket
import sys
import time

bind_ip = sys.argv[1]
port = int(sys.argv[2])
expected = int(sys.argv[3])
payload_size = int(sys.argv[4])
timeout = float(sys.argv[5])

listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind((bind_ip, port))
listener.listen(max(128, expected))
listener.settimeout(0.1)
deadline = time.monotonic() + timeout
accepted = 0
received = 0
short_reads = 0
while accepted < expected and time.monotonic() < deadline:
    try:
        conn, _ = listener.accept()
    except socket.timeout:
        continue
    conn.settimeout(min(timeout, 5))
    current = 0
    try:
        while current < payload_size:
            try:
                chunk = conn.recv(min(65536, payload_size - current))
            except socket.timeout:
                break
            if not chunk:
                break
            current += len(chunk)
    finally:
        conn.close()
    if current == payload_size:
        accepted += 1
        received += current
    else:
        short_reads += 1
print(f"accepted={accepted} bytes={received} short_reads={short_reads} expected={expected}", flush=True)
if accepted != expected:
    sys.exit(1)
PY
  local server_pid=$!
  sleep 0.2
  if ! run_in_netns "$src_ns" python3 - "$dst_ip" "$port" "$tcp_burst_connections" "$tcp_burst_size" "$tcp_burst_parallel" "$tcp_burst_rounds" >"$send_log" 2>&1 <<'PY'; then
import socket
import sys
import threading

dst_ip = sys.argv[1]
port = int(sys.argv[2])
connections = int(sys.argv[3])
size = int(sys.argv[4])
parallel = int(sys.argv[5])
rounds = int(sys.argv[6])
prefix = b"TIX3-TCP-BURST"
payload = (prefix + bytes(max(0, size - len(prefix))))[:size]
errors = []
sent_total = 0
lock = threading.Lock()

def send_worker(worker_id):
    global sent_total
    try:
        for _ in range(connections):
            sock = socket.create_connection((dst_ip, port), timeout=5)
            sock.sendall(payload)
            sock.shutdown(socket.SHUT_WR)
            sock.close()
            with lock:
                sent_total += 1
    except Exception as exc:
        with lock:
            errors.append(f"worker={worker_id}: {exc}")

for _ in range(rounds):
    threads = [threading.Thread(target=send_worker, args=(worker,)) for worker in range(parallel)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

print(f"sent_connections={sent_total} expected={connections * parallel * rounds}", flush=True)
if errors:
    print("\n".join(errors), file=sys.stderr)
    sys.exit(1)
PY
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" >/dev/null 2>&1 || true
    sed -n '1,120p' "$send_log" >&2 || true
    collect_api_all || true
    die "${label} sender failed"
  fi
  if ! wait "$server_pid"; then
    sed -n '1,120p' "$send_log" >&2 || true
    sed -n '1,120p' "$recv_log" >&2 || true
    collect_api_all || true
    die "${label} receiver did not observe all connections"
  fi
}

collect_api() {
  local name="$1"
  local ns="$2"
  ctl_ns "$ns" status >"$workdir/${name}-status.json"
  ctl_ns "$ns" members >"$workdir/${name}-members.json"
  ctl_ns "$ns" routes >"$workdir/${name}-routes.json"
  ctl_ns "$ns" flows >"$workdir/${name}-flows.json"
  ctl_ns "$ns" peers >"$workdir/${name}-peers.json"
  ctl_ns "$ns" route-policy >"$workdir/${name}-route-policy.json"
  ctl_ns "$ns" endpoints >"$workdir/${name}-endpoints.json"
  ctl_ns "$ns" datapath >"$workdir/${name}-datapath.json"
  ctl_ns "$ns" capture >"$workdir/${name}-capture.json"
  ctl_ns "$ns" bpf maps >"$workdir/${name}-bpf.json"
  ctl_ns "$ns" doctor >"$workdir/${name}-doctor.json"
}

collect_api_all() {
  collect_api ix-a "$ns_ix_a"
  collect_api ix-b "$ns_ix_b"
  collect_api ix-c "$ns_ix_c"
}

counter_value() {
  local file="$1"
  local name="$2"
  awk -v needle="\"name\": \"${name}\"" '
    index($0, needle) { found=1 }
    found && /"value":/ {
      gsub(/[^0-9]/, "", $0)
      print $0
      exit
    }
  ' "$file"
}

assert_counter_positive() {
  local file="$1"
  local name="$2"
  local value
  value="$(counter_value "$file" "$name")"
  if [[ -z "$value" || "$value" -le 0 ]]; then
    die "counter ${name} in ${file} is not positive (value=${value:-missing})"
  fi
}

datapath_counter_value() {
  local file="$1"
  local name="$2"
  awk -v needle="\"${name}\":" '
    index($0, needle) {
      gsub(/[^0-9]/, "", $0)
      print $0
      exit
    }
  ' "$file"
}

assert_datapath_counter_positive() {
  local file="$1"
  local name="$2"
  local value
  value="$(datapath_counter_value "$file" "$name")"
  if [[ -z "$value" || "$value" -le 0 ]]; then
    die "datapath counter ${name} in ${file} is not positive (value=${value:-missing})"
  fi
}

assert_datapath_counter_zero() {
  local file="$1"
  local name="$2"
  local value
  value="$(datapath_counter_value "$file" "$name")"
  if [[ -z "$value" || "$value" != "0" ]]; then
    die "datapath counter ${name} in ${file} is not zero (value=${value:-missing})"
  fi
}

assert_datapath_any_counter_positive() {
  local file="$1"
  shift
  local name
  local value
  for name in "$@"; do
    value="$(datapath_counter_value "$file" "$name")"
    if [[ -n "$value" && "$value" -gt 0 ]]; then
      return 0
    fi
  done
  die "none of datapath counters [$*] in ${file} is positive"
}

assert_kernel_udp_status() {
  local node="$1"
  local datapath_path="$workdir/${node}-datapath.json"
  local doctor_path="$workdir/${node}-doctor.json"
  local bpf_path="$workdir/${node}-bpf.json"

  python3 - "$datapath_path" "$doctor_path" "$node" <<'PY'
import json
import sys

datapath_path, doctor_path, node = sys.argv[1:4]

def fail(message):
    raise SystemExit(f"{node} {message}")

with open(datapath_path, "r", encoding="utf-8") as handle:
    datapath = json.load(handle)
with open(doctor_path, "r", encoding="utf-8") as handle:
    doctor = json.load(handle)

udp = datapath.get("kernel_udp")
if not isinstance(udp, dict):
    fail("datapath has no kernel_udp status")
for key in ("available", "fast_path", "reinject", "userspace_crypto"):
    if udp.get(key) is not True:
        fail(f"kernel_udp {key} is not true: {udp!r}")
if udp.get("provider") != "af_xdp":
    fail(f"kernel_udp provider is not af_xdp: {udp.get('provider')!r}")
for key in ("xdp_attach_mode", "af_xdp_bind_mode"):
    if not udp.get(key):
        fail(f"kernel_udp has no {key}")
if "zerocopy_enabled" not in udp:
    fail("kernel_udp has no zerocopy_enabled")
for key in ("active_flows", "submitted_frames", "received_frames"):
    if int(udp.get(key) or 0) <= 0:
        fail(f"kernel_udp {key} is not positive: {udp.get(key)!r}")
stats = udp.get("provider_stats") or {}
for key in ("allowed_ports", "submitted_frames", "received_frames"):
    if int(stats.get(key) or 0) <= 0:
        fail(f"kernel_udp provider_stats.{key} is not positive: {stats!r}")

kernel_transport = datapath.get("kernel_transport") or {}
if kernel_transport.get("mode") != "require_kernel":
    fail(f"kernel_transport mode is not require_kernel: {kernel_transport.get('mode')!r}")
udp_protocol = next((item for item in kernel_transport.get("protocols") or [] if item.get("protocol") == "udp"), None)
if not udp_protocol:
    fail("kernel_transport has no UDP protocol entry")
if udp_protocol.get("available") is not True or udp_protocol.get("placement") not in ("hybrid", "kernel"):
    fail(f"kernel_transport UDP entry is not available hybrid/kernel: {udp_protocol!r}")

placements = (datapath.get("kernel_offload") or {}).get("placements") or []
kernel_udp_placement = next((item for item in placements if item.get("name") == "kernel_udp"), None)
if not kernel_udp_placement:
    fail("kernel_offload has no kernel_udp placement")
if kernel_udp_placement.get("placement") not in ("hybrid", "kernel"):
    fail(f"kernel_udp placement is not hybrid/kernel: {kernel_udp_placement!r}")

doctor_check = next((item for item in doctor if item.get("name") == "kernel_udp"), None)
if not doctor_check:
    fail("doctor has no kernel_udp check")
if doctor_check.get("status") != "ok":
    fail(f"kernel_udp doctor is not ok: {doctor_check!r}")
detail = doctor_check.get("detail", "")
for token in ("provider=af_xdp", "fast_path=true", "reinject=true"):
    if token not in detail:
        fail(f"kernel_udp doctor detail missing {token!r}: {detail!r}")
PY

  assert_counter_positive "$bpf_path" "kernel_udp_allowed_ports"
  assert_counter_positive "$bpf_path" "kernel_udp_active_flows"
  assert_counter_positive "$bpf_path" "kernel_udp_submitted_frames"
  assert_counter_positive "$bpf_path" "kernel_udp_received_frames"
}

datapath_peer_packets_sent() {
  local file="$1"
  local peer="$2"
  python3 - "$file" "$peer" <<'PY'
import json
import sys

path, peer = sys.argv[1], sys.argv[2]
with open(path, "r", encoding="utf-8") as fh:
    payload = json.load(fh)
for item in payload.get("peer_stats", []):
    if item.get("peer") == peer:
        print(int(item.get("packets_sent", 0)))
        break
else:
    print(0)
PY
}

assert_peer_packets_sent_increased() {
  local before_file="$1"
  local after_file="$2"
  local peer="$3"
  local before after
  before="$(datapath_peer_packets_sent "$before_file" "$peer")"
  after="$(datapath_peer_packets_sent "$after_file" "$peer")"
  if [[ -z "$before" || -z "$after" || "$after" -le "$before" ]]; then
    die "peer ${peer} packets_sent did not increase: before=${before:-missing} after=${after:-missing}"
  fi
}

assert_route_trace_hops() {
  local ns="$1"
  local dst="$2"
  shift 2
  local output="$workdir/trace-${ns}-${dst//[^A-Za-z0-9_.-]/_}.json"
  ctl_ns "$ns" trace "$dst" -max-hops 8 >"$output"
  python3 - "$output" "$@" <<'PY'
import json
import sys

path = sys.argv[1]
want = sys.argv[2:]
with open(path, "r", encoding="utf-8") as fh:
    payload = json.load(fh)
if not payload.get("ok"):
    raise SystemExit(f"route trace is not ok: {payload!r}")
if not payload.get("complete"):
    raise SystemExit(f"route trace is incomplete: {payload!r}")
got = [hop.get("ix_id") for hop in payload.get("hops") or []]
if got != want:
    raise SystemExit(f"route trace hops = {got!r}, want {want!r}")
terminal = (payload.get("hops") or [{}])[-1]
if not terminal.get("terminal"):
    raise SystemExit(f"route trace terminal hop is not marked terminal: {terminal!r}")
PY
}

assert_ttl_probe_generates_time_exceeded() {
  local transit_ns="$1"
  local src_lan_ns="$2"
  local dst="$3"
  local label="$4"
  local ttl="${5:-2}"
  local before="$workdir/${label//[^A-Za-z0-9_.-]/_}-ttl-before.json"
  local after="$workdir/${label//[^A-Za-z0-9_.-]/_}-ttl-after.json"
  local before_value after_value

  ctl_ns "$transit_ns" datapath >"$before"
  before_value="$(datapath_counter_value "$before" "ttl_icmp_generated")"
  before_value="${before_value:-0}"
  if run_in_netns "$src_lan_ns" ping -c 1 -W 1 -t "$ttl" "$dst" >"$workdir/${label//[^A-Za-z0-9_.-]/_}-ttl-ping.log" 2>&1; then
    die "${label} TTL=${ttl} ping unexpectedly reached ${dst}"
  fi
  ctl_ns "$transit_ns" datapath >"$after"
  after_value="$(datapath_counter_value "$after" "ttl_icmp_generated")"
  after_value="${after_value:-0}"
  if [[ "$after_value" -le "$before_value" ]]; then
    cat "$workdir/${label//[^A-Za-z0-9_.-]/_}-ttl-ping.log" >&2 || true
    die "${label} did not generate ttl_icmp_generated: before=${before_value} after=${after_value}"
  fi
  python3 - "$after" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    payload = json.load(fh)
drop_reasons = payload.get("drop_reasons") or {}
if int(drop_reasons.get("TTL_EXPIRED", 0)) <= 0:
    raise SystemExit(f"TTL_EXPIRED drop reason did not increase: {drop_reasons!r}")
PY
}

maybe_prepare_kernel_module() {
  if [[ "$kernel_module" != "1" ]]; then
    return 0
  fi
  [[ -f "$kernel_script" ]] || die "TrustIX kernel module smoke script not found: $kernel_script"
  log "preparing TrustIX kernel module through ${kernel_script}"
  if [[ -n "$kernel_test_bin" ]]; then
    env \
      TRUSTIX_CRYPTO_MODULE_DIR="$kernel_module_dir" \
      TRUSTIX_KERNEL_KEEP_LOADED=1 \
      TRUSTIX_KERNEL_TEST_BIN="$kernel_test_bin" \
      bash "$kernel_script"
    return 0
  fi
  env \
    TRUSTIX_CRYPTO_MODULE_DIR="$kernel_module_dir" \
    TRUSTIX_KERNEL_KEEP_LOADED=1 \
    bash "$kernel_script"
}

validate_observability() {
  log "validating dataplane counters, capture output, and ${transport} status"
  local expected_crypto="userspace"
  if [[ "$crypto_placement" == "kernel" ]]; then
    expected_crypto="kernel"
  elif [[ "$crypto_placement" == "auto" ]] && kernel_provider_expected; then
    expected_crypto="kernel"
  fi

  for node in ix-a ix-b ix-c; do
    grep -q '"runtime":' "$workdir/${node}-status.json" || die "${node} status has no runtime resource block"
    grep -q '"data_dir_lock_held": true' "$workdir/${node}-status.json" || die "${node} status does not report held data-dir lock"
    grep -q '"go_heap_alloc_bytes":' "$workdir/${node}-status.json" || die "${node} status has no Go heap resource gauge"
    grep -q '"rss_bytes":' "$workdir/${node}-status.json" || die "${node} status has no RSS resource gauge"
    grep -q '"open_fds":' "$workdir/${node}-status.json" || die "${node} status has no FD resource gauge"
    grep -q '"capture_forwarder_active": true' "$workdir/${node}-datapath.json" || die "${node} capture forwarder is not active"
    grep -q '"hook": "lan_ingress_route_hit"' "$workdir/${node}-capture.json" || die "${node} capture has no LAN route-hit event"
    grep -q '"name": "runtime_resources"' "$workdir/${node}-doctor.json" || die "${node} doctor has no runtime resource check"
    assert_counter_positive "$workdir/${node}-bpf.json" "tc_ingress_route_hits"
    assert_counter_positive "$workdir/${node}-bpf.json" "tc_capture_events"
    assert_datapath_counter_positive "$workdir/${node}-datapath.json" "packets_sent"
    assert_datapath_counter_positive "$workdir/${node}-datapath.json" "packets_received"
    assert_datapath_counter_positive "$workdir/${node}-datapath.json" "packets_injected"

    grep -q '"route_stats":' "$workdir/${node}-datapath.json" || die "${node} datapath has no route_stats"
    grep -q '"endpoint_stats":' "$workdir/${node}-datapath.json" || die "${node} datapath has no endpoint_stats"

    if [[ "$transport" == "tix_tcp" ]]; then
      grep -q '"provider": "af_xdp"' "$workdir/${node}-datapath.json" || die "${node} tix_tcp provider is not af_xdp"
      grep -q '"fast_path": true' "$workdir/${node}-datapath.json" || die "${node} tix_tcp fast_path is not true"
      grep -q '"reinject": true' "$workdir/${node}-datapath.json" || die "${node} tix_tcp reinject is not true"
      grep -q '"raw_socket_fallback": false' "$workdir/${node}-datapath.json" || die "${node} raw socket fallback is enabled"
      grep -q '"xdp_attach_mode":' "$workdir/${node}-datapath.json" || die "${node} tix_tcp status has no xdp_attach_mode"
      grep -q '"af_xdp_bind_mode":' "$workdir/${node}-datapath.json" || die "${node} tix_tcp status has no af_xdp_bind_mode"
      grep -q '"zerocopy_enabled":' "$workdir/${node}-datapath.json" || die "${node} tix_tcp status has no zerocopy_enabled"
      assert_datapath_any_counter_positive "$workdir/${node}-datapath.json" "xdp_attach_native" "xdp_attach_skb"
      assert_datapath_any_counter_positive "$workdir/${node}-datapath.json" "af_xdp_bind_zerocopy" "af_xdp_bind_copy"
      if kernel_provider_expected; then
        grep -q '"kernel_crypto": true' "$workdir/${node}-datapath.json" || die "${node} kernel crypto provider is not visible"
        grep -q '"provider_ready": true' "$workdir/${node}-datapath.json" || die "${node} kernel crypto provider is not ready"
        assert_datapath_counter_positive "$workdir/${node}-datapath.json" "kernel_crypto_ctx_provider_loaded"
        assert_datapath_counter_positive "$workdir/${node}-datapath.json" "kernel_crypto_aead_gcm_ctx_create_successes"
        assert_datapath_counter_positive "$workdir/${node}-datapath.json" "kernel_crypto_aead_gcm_roundtrip_successes"
        grep -q '"kernel_crypto_ctx_provider_load_errors": 0' "$workdir/${node}-datapath.json" || die "${node} kernel AEAD provider load errors are non-zero"
        grep -q '"kernel_crypto_aead_gcm_ctx_create_errors": 0' "$workdir/${node}-datapath.json" || die "${node} kernel AEAD ctx create errors are non-zero"
        grep -q '"kernel_crypto_aead_gcm_roundtrip_errors": 0' "$workdir/${node}-datapath.json" || die "${node} kernel AEAD roundtrip errors are non-zero"
      else
        grep -q '"kernel_crypto": false' "$workdir/${node}-datapath.json" || die "${node} kernel crypto is unexpectedly enabled"
        grep -q '"provider_ready": false' "$workdir/${node}-datapath.json" || die "${node} kernel crypto provider is unexpectedly ready"
      fi
      grep -q '"kernel_crypto_probe":' "$workdir/${node}-datapath.json" || die "${node} datapath has no kernel crypto probe"
      grep -q '"self_test":' "$workdir/${node}-datapath.json" || die "${node} datapath has no kernel crypto selftest status"
      grep -q '"map_schema":' "$workdir/${node}-datapath.json" || die "${node} datapath has no kernel crypto map schema"
      grep -q '"kernel_crypto_map_key_size": 16' "$workdir/${node}-datapath.json" || die "${node} provider stats has no kernel crypto key size"
      grep -q '"kernel_crypto_map_value_size": 112' "$workdir/${node}-datapath.json" || die "${node} provider stats has no kernel crypto value size"
      grep -q '"kernel_crypto_provider_unavailable_errors": 0' "$workdir/${node}-datapath.json" || die "${node} kernel crypto provider rejection counter is unexpected"
      grep -q "\"requested_crypto\": \"${crypto_placement}\"" "$workdir/${node}-datapath.json" || die "${node} requested crypto is not ${crypto_placement}"
      if [[ "$expected_crypto" == "kernel" ]]; then
        grep -q '"effective_crypto": "kernel"' "$workdir/${node}-datapath.json" || die "${node} effective crypto is not kernel"
        assert_datapath_counter_positive "$workdir/${node}-datapath.json" "kernel_crypto_install_attempts"
        assert_datapath_counter_positive "$workdir/${node}-datapath.json" "kernel_crypto_flow_map_updates"
        assert_datapath_counter_positive "$workdir/${node}-datapath.json" "kernel_crypto_frame_seal_successes"
        assert_datapath_counter_positive "$workdir/${node}-datapath.json" "kernel_crypto_frame_open_successes"
        assert_datapath_counter_positive "$workdir/${node}-datapath.json" "kernel_crypto_rx_attached"
        assert_datapath_counter_positive "$workdir/${node}-datapath.json" "kernel_crypto_tx_packet"
        assert_datapath_counter_positive "$workdir/${node}-datapath.json" "xdp_kernel_crypto_open_attempts"
        assert_datapath_counter_positive "$workdir/${node}-datapath.json" "xdp_kernel_crypto_open_successes"
        assert_datapath_counter_positive "$workdir/${node}-datapath.json" "tx_kernel_crypto_packet_seal_attempts"
        assert_datapath_counter_positive "$workdir/${node}-datapath.json" "tx_kernel_crypto_packet_seal_successes"
        assert_datapath_counter_positive "$workdir/${node}-datapath.json" "tx_umem_direct_build_frames"
        grep -q '"kernel_crypto_frame_seal_errors": 0' "$workdir/${node}-datapath.json" || die "${node} kernel frame seal errors are non-zero"
        grep -q '"kernel_crypto_frame_open_errors": 0' "$workdir/${node}-datapath.json" || die "${node} kernel frame open errors are non-zero"
        assert_datapath_counter_zero "$workdir/${node}-datapath.json" "xdp_kernel_crypto_open_errors"
        assert_datapath_counter_zero "$workdir/${node}-datapath.json" "xdp_kernel_crypto_replay_drops"
        assert_datapath_counter_zero "$workdir/${node}-datapath.json" "xdp_kernel_crypto_no_context_drops"
        assert_datapath_counter_zero "$workdir/${node}-datapath.json" "xdp_kernel_crypto_header_errors"
        assert_datapath_counter_zero "$workdir/${node}-datapath.json" "tx_kernel_crypto_packet_seal_errors"
        assert_datapath_counter_zero "$workdir/${node}-datapath.json" "tx_kernel_crypto_packet_seal_no_context_errors"
        assert_datapath_counter_zero "$workdir/${node}-datapath.json" "tx_kernel_crypto_packet_seal_header_errors"
        assert_datapath_counter_zero "$workdir/${node}-datapath.json" "tx_kernel_crypto_packet_seal_encrypt_errors"
        assert_datapath_counter_zero "$workdir/${node}-datapath.json" "tx_kernel_crypto_packet_seal_sequence_errors"
      else
        grep -q '"effective_crypto": "userspace"' "$workdir/${node}-datapath.json" || die "${node} effective crypto is not userspace"
        assert_datapath_counter_zero "$workdir/${node}-datapath.json" "xdp_kernel_crypto_open_attempts"
        assert_datapath_counter_zero "$workdir/${node}-datapath.json" "xdp_kernel_crypto_open_successes"
        assert_datapath_counter_zero "$workdir/${node}-datapath.json" "tx_kernel_crypto_packet_seal_attempts"
        assert_datapath_counter_zero "$workdir/${node}-datapath.json" "tx_kernel_crypto_packet_seal_successes"
        assert_datapath_counter_positive "$workdir/${node}-datapath.json" "tx_umem_direct_build_frames"
      fi
      grep -q '"name": "tix_tcp"' "$workdir/${node}-doctor.json" || die "${node} doctor has no tix_tcp check"
      grep -q 'selftest_attempted=' "$workdir/${node}-doctor.json" || die "${node} doctor has no kernel crypto selftest state"
      grep -q 'crypto_map_key_size=16' "$workdir/${node}-doctor.json" || die "${node} doctor has no kernel crypto map schema detail"
      assert_counter_positive "$workdir/${node}-bpf.json" "tix_tcp_allowed_ports"
      assert_counter_positive "$workdir/${node}-bpf.json" "tix_tcp_umem_bytes_total"
      assert_counter_positive "$workdir/${node}-bpf.json" "tix_tcp_xdp_redirected"
      assert_counter_positive "$workdir/${node}-bpf.json" "tix_tcp_tx_frames"
      assert_counter_positive "$workdir/${node}-bpf.json" "tix_tcp_rx_frames"
      assert_counter_positive "$workdir/${node}-bpf.json" "tix_tcp_rx_umem_direct_frames"
    elif [[ "$transport" == "kernel_udp" ]]; then
      assert_kernel_udp_status "$node"
      assert_datapath_any_counter_positive "$workdir/${node}-datapath.json" "xdp_attach_native" "xdp_attach_skb"
      assert_datapath_any_counter_positive "$workdir/${node}-datapath.json" "af_xdp_bind_zerocopy" "af_xdp_bind_copy"
    fi
    assert_datapath_counter_zero "$workdir/${node}-datapath.json" "tx_pool_exhausted"
    assert_datapath_counter_zero "$workdir/${node}-datapath.json" "tx_ring_full"
    assert_datapath_counter_zero "$workdir/${node}-datapath.json" "tx_kick_errors"
    grep -q '"tx_backpressure_waits":' "$workdir/${node}-datapath.json" || die "${node} datapath has no TX backpressure wait counter"
    grep -q '"tx_backpressure_reclaims":' "$workdir/${node}-datapath.json" || die "${node} datapath has no TX backpressure reclaim counter"
    assert_datapath_counter_zero "$workdir/${node}-datapath.json" "tx_backpressure_timeouts"
    assert_datapath_counter_zero "$workdir/${node}-datapath.json" "rx_invalid"
    assert_datapath_counter_zero "$workdir/${node}-datapath.json" "rx_recycle_errors"
  done
}

validate_settings() {
  case "$dataplane" in
    linux) ;;
    *) die "TRUSTIX_3IX_E2E_DATAPLANE currently supports linux only" ;;
  esac
  case "$transport" in
    udp|kernel_udp|tcp|quic|websocket|http_connect|tix_tcp|gre|ipip|vxlan) ;;
    *) die "TRUSTIX_3IX_E2E_TRANSPORT must be one of udp, kernel_udp, tcp, quic, websocket, http_connect, tix_tcp, gre, ipip, or vxlan" ;;
  esac
  case "$(transport_policy_profile)" in
    stable|performance|latency) ;;
    *) die "TRUSTIX_3IX_E2E_TRANSPORT_PROFILE must be stable, performance, or latency when set" ;;
  esac
  case "$(transport_policy_datapath)" in
    auto|userspace|tc_xdp|kernel_module) ;;
    *) die "TRUSTIX_3IX_E2E_TRANSPORT_DATAPATH must be auto, userspace, tc_xdp, or kernel_module when set" ;;
  esac
  case "$(transport_policy_encryption)" in
    secure|plaintext|send_encrypted|receive_encrypted) ;;
    *) die "TRUSTIX_3IX_E2E_TRANSPORT_ENCRYPTION must be secure, plaintext, send_encrypted, or receive_encrypted when set" ;;
  esac
  case "$crypto_placement" in
    userspace|kernel|auto) ;;
    *) die "TRUSTIX_3IX_E2E_CRYPTO_PLACEMENT must be userspace, kernel, or auto" ;;
  esac
  [[ "$dynamic_metric" =~ ^[0-9]+$ ]] || die "TRUSTIX_3IX_E2E_DYNAMIC_METRIC must be a non-negative integer"
  [[ "$ping_count" =~ ^[1-9][0-9]*$ ]] || die "TRUSTIX_3IX_E2E_PING_COUNT must be a positive integer"
  [[ "$ping_size" =~ ^[0-9]+$ ]] || die "TRUSTIX_3IX_E2E_PING_SIZE must be a non-negative integer"
  [[ "$ping_parallel" =~ ^[1-9][0-9]*$ ]] || die "TRUSTIX_3IX_E2E_PING_PARALLEL must be a positive integer"
  [[ "$ping_rounds" =~ ^[1-9][0-9]*$ ]] || die "TRUSTIX_3IX_E2E_PING_ROUNDS must be a positive integer"
  [[ "$udp_burst_packets" =~ ^[0-9]+$ ]] || die "TRUSTIX_3IX_E2E_UDP_BURST_PACKETS must be a non-negative integer"
  [[ "$udp_burst_size" =~ ^[0-9]+$ ]] || die "TRUSTIX_3IX_E2E_UDP_BURST_SIZE must be a non-negative integer"
  [[ "$udp_burst_parallel" =~ ^[1-9][0-9]*$ ]] || die "TRUSTIX_3IX_E2E_UDP_BURST_PARALLEL must be a positive integer"
  [[ "$udp_burst_rounds" =~ ^[1-9][0-9]*$ ]] || die "TRUSTIX_3IX_E2E_UDP_BURST_ROUNDS must be a positive integer"
  [[ "$udp_burst_port" =~ ^[1-9][0-9]*$ && "$udp_burst_port" -le 65534 ]] || die "TRUSTIX_3IX_E2E_UDP_BURST_PORT must be in 1..65534"
  [[ "$tcp_burst_connections" =~ ^[0-9]+$ ]] || die "TRUSTIX_3IX_E2E_TCP_BURST_CONNECTIONS must be a non-negative integer"
  [[ "$tcp_burst_size" =~ ^[0-9]+$ ]] || die "TRUSTIX_3IX_E2E_TCP_BURST_SIZE must be a non-negative integer"
  [[ "$tcp_burst_parallel" =~ ^[1-9][0-9]*$ ]] || die "TRUSTIX_3IX_E2E_TCP_BURST_PARALLEL must be a positive integer"
  [[ "$tcp_burst_rounds" =~ ^[1-9][0-9]*$ ]] || die "TRUSTIX_3IX_E2E_TCP_BURST_ROUNDS must be a positive integer"
  [[ "$tcp_burst_port" =~ ^[1-9][0-9]*$ && "$tcp_burst_port" -le 65534 ]] || die "TRUSTIX_3IX_E2E_TCP_BURST_PORT must be in 1..65534"
  [[ "$burst_timeout" =~ ^[1-9][0-9]*$ ]] || die "TRUSTIX_3IX_E2E_BURST_TIMEOUT must be a positive integer"
  case "$xdp_mode" in
    auto|native|driver|drv|skb) ;;
    *) die "TRUSTIX_3IX_E2E_XDP_MODE must be auto, native, driver, drv, or skb" ;;
  esac
  case "$af_xdp_bind_mode" in
    auto|zerocopy|copy) ;;
    *) die "TRUSTIX_3IX_E2E_AF_XDP_BIND_MODE must be auto, zerocopy, or copy" ;;
  esac
  case "$hot_stats" in
    0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_3IX_E2E_HOT_STATS must be truthy or falsey" ;;
  esac
  if [[ "$udp_burst_packets" -gt 0 || "$tcp_burst_connections" -gt 0 ]]; then
    need_cmd python3
  fi
  if [[ "$crypto_placement" == "kernel" && "$kernel_module" != "1" ]] && ! kernel_provider_expected; then
    die "TRUSTIX_3IX_E2E_CRYPTO_PLACEMENT=kernel requires TRUSTIX_3IX_E2E_KERNEL_MODULE=1 or a loaded trustix_crypto module"
  fi
  if [[ "$kernel_module" == "1" && "$transport" != "tix_tcp" ]]; then
    die "TRUSTIX_3IX_E2E_KERNEL_MODULE=1 currently requires TRUSTIX_3IX_E2E_TRANSPORT=tix_tcp"
  fi
  [[ "$transport_port" =~ ^[0-9]*$ ]] || die "TRUSTIX_3IX_E2E_TRANSPORT_PORT must be numeric when set"
}

main() {
  require_linux_root
  need_cmd ip
  need_cmd curl
  need_cmd grep
  need_cmd awk
  need_cmd sed
  need_cmd ping
  need_cmd python3
  need_cmd timeout
  if [[ -z "${TRUSTIX_3IX_E2E_BIN_DIR:-}" ]]; then
    need_cmd go
  fi
  allocate_ports
  validate_settings

  mkdir -p "$workdir"
  log "workdir: $workdir"
  log "dataplane=${dataplane} transport=${transport} profile=$(transport_policy_profile) datapath=$(transport_policy_datapath) encryption=$(transport_policy_encryption) crypto=${crypto_placement} af_xdp_queues=${af_xdp_queues} hot_stats=${hot_stats}"
  log "ports: api=${api_port} peer_api=${peer_api_port} ${transport}=${transport_port} udp_burst=${udp_burst_port},$((udp_burst_port + 1)) tcp_burst=${tcp_burst_port},$((tcp_burst_port + 1))"

  maybe_prepare_kernel_module
  build_binaries
  generate_certs
  setup_topology
  write_configs "10.0.1.0/24" "10.99.0.0/16"
  assert_tix_tcp_kernel_crypto_rejects

  pid_a="$(start_daemon ix-a "$workdir/a.yaml" "$workdir/state-a" "$ns_ix_a" "$underlay_ip_a")"
  wait_for_api ix-a "$pid_a" "$ns_ix_a"
  assert_data_dir_lock_rejects_duplicate ix-a "$workdir/a.yaml" "$workdir/state-a" "$ns_ix_a" "$underlay_ip_a"
  pid_b="$(start_daemon ix-b "$workdir/b.yaml" "$workdir/state-b" "$ns_ix_b" "$underlay_ip_b")"
  wait_for_api ix-b "$pid_b" "$ns_ix_b"
  pid_c="$(start_daemon ix-c "$workdir/c.yaml" "$workdir/state-c" "$ns_ix_c" "$underlay_ip_c")"
  wait_for_api ix-c "$pid_c" "$ns_ix_c"

  warm_neighbors
  log "waiting for ix-a to learn ix-b and ix-c membership through bootstrap gossip"
  wait_ctl_grep "ix-a route to ix-b" "$ns_ix_a" "$workdir/a-routes-initial.json" '"prefix": "10.0.1.0/24"' routes
  wait_ctl_grep "ix-b route to ix-a" "$ns_ix_b" "$workdir/b-routes-initial-a.json" '"prefix": "10.0.0.0/24"' routes
  wait_ctl_grep "ix-a member ix-c through ix-b gossip" "$ns_ix_a" "$workdir/a-members-initial.json" '"ix_id": "ix-c"' members
  assert_not_grep '"prefix": "10.0.2.0/24"' "$workdir/a-routes-initial.json"
  ctl_ns "$ns_ix_c" route-policy >"$workdir/c-route-policy-initial.json"
  grep -q '"reason": "export_prefix_denied"' "$workdir/c-route-policy-initial.json" || die "ix-c did not record export_prefix_denied"
  ctl_ns "$ns_ix_b" routes >"$workdir/b-routes-initial.json"
  assert_not_grep '"prefix": "10.0.2.0/24"' "$workdir/b-routes-initial.json"

  retry_ping "$ns_lan_a" 10.0.1.2 "LAN A -> LAN B"
  retry_ping "$ns_lan_b" 10.0.0.2 "LAN B -> LAN A"

  log "allowing ix-c export and waiting for ix-b to import ix-c"
  write_configs "10.0.1.0/24" "10.0.2.0/24"
  ctl_ns "$ns_ix_c" config apply "$workdir/c.yaml" >/dev/null
  wait_ctl_grep "ix-b route to ix-c after export policy update" "$ns_ix_b" "$workdir/b-routes-after-c-export.json" '"prefix": "10.0.2.0/24"' routes
  wait_ctl_grep "ix-c route to ix-b" "$ns_ix_c" "$workdir/c-routes-to-b.json" '"prefix": "10.0.1.0/24"' routes
  wait_ctl_grep "ix-a import policy rejects ix-c" "$ns_ix_a" "$workdir/a-route-policy-after-c-export.json" '"reason": "import_prefix_denied"' route-policy
  ctl_ns "$ns_ix_a" routes >"$workdir/a-routes-after-c-export.json"
  assert_not_grep '"prefix": "10.0.2.0/24"' "$workdir/a-routes-after-c-export.json"

  retry_ping "$ns_lan_b" 10.0.2.2 "LAN B -> LAN C"
  retry_ping "$ns_lan_c" 10.0.1.2 "LAN C -> LAN B"

  log "allowing ix-a import and waiting for ix-a to route to ix-c through gossip"
  write_configs "10.0.0.0/8" "10.0.2.0/24"
  ctl_ns "$ns_ix_a" config apply "$workdir/a.yaml" >/dev/null
  wait_ctl_grep "ix-a route to ix-c after import policy update" "$ns_ix_a" "$workdir/a-routes-after-import.json" '"prefix": "10.0.2.0/24"' routes
  wait_ctl_grep "ix-c route to ix-a after gossip" "$ns_ix_c" "$workdir/c-routes-to-a.json" '"prefix": "10.0.0.0/24"' routes
  ctl_ns "$ns_ix_a" route-policy >"$workdir/a-route-policy-after-import.json"
  grep -q '"reason": "import_prefix_match"' "$workdir/a-route-policy-after-import.json" || die "ix-a did not record import_prefix_match"
  grep -q "\"metric\": ${dynamic_metric}" "$workdir/a-routes-after-import.json" || die "dynamic metric was not applied"

  log "forcing ix-a route to ix-c via ix-b and verifying transit forwarding"
  write_a_transit_config
  ctl_ns "$ns_ix_a" config apply "$workdir/a-transit.yaml" >/dev/null
  write_c_transit_config
  ctl_ns "$ns_ix_c" config apply "$workdir/c-transit.yaml" >/dev/null
  wait_ctl_grep "ix-a static owner ix-c via ix-b route" "$ns_ix_a" "$workdir/a-routes-transit.json" '"next_hop": "ix-b"' routes
  grep -q '"owner": "ix-c"' "$workdir/a-routes-transit.json" || die "ix-a transit route owner is not ix-c"
  wait_ctl_grep "ix-c static owner ix-a via ix-b route" "$ns_ix_c" "$workdir/c-routes-transit.json" '"next_hop": "ix-b"' routes
  grep -q '"owner": "ix-a"' "$workdir/c-routes-transit.json" || die "ix-c transit route owner is not ix-a"
  local transit_endpoint_a transit_endpoint_c
  transit_endpoint_a="$(transport_endpoint_name ix-b)"
  transit_endpoint_c="$transit_endpoint_a"
  if is_iptunnel_transport; then
    transit_endpoint_a="$(native_tunnel_endpoint_name ix-b ix-a)"
    transit_endpoint_c="$(native_tunnel_endpoint_name ix-b ix-c)"
  fi
  grep -q "\"endpoint\": \"${transit_endpoint_a}\"" "$workdir/a-routes-transit.json" || die "ix-a transit route endpoint is not ${transit_endpoint_a}"
  grep -q "\"endpoint\": \"${transit_endpoint_c}\"" "$workdir/c-routes-transit.json" || die "ix-c transit route endpoint is not ${transit_endpoint_c}"
  ctl_ns "$ns_ix_b" datapath >"$workdir/b-datapath-before-transit.json"
  retry_ping "$ns_lan_a" 10.0.2.2 "LAN A -> LAN C via IX B"
  ctl_ns "$ns_ix_b" datapath >"$workdir/b-datapath-after-transit.json"
  assert_peer_packets_sent_increased "$workdir/b-datapath-before-transit.json" "$workdir/b-datapath-after-transit.json" "ix-c"
  assert_route_trace_hops "$ns_ix_a" 10.0.2.2 ix-a ix-b ix-c
  assert_route_trace_hops "$ns_ix_c" 10.0.0.2 ix-c ix-b ix-a
  assert_ttl_probe_generates_time_exceeded "$ns_ix_b" "$ns_lan_a" 10.0.2.2 "LAN A -> LAN C TTL through IX B" 2
  retry_ping "$ns_lan_c" 10.0.0.2 "LAN C -> LAN A"

  run_payload_bursts

  collect_api_all
  validate_observability
  assert_sigterm_releases_data_dir_lock

  log "ok: three IX membership gossip, route import/export policy, dynamic metric, ${transport} dataplane, and crypto placement are active"
  success=1
}

main "$@"
