#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workdir="${TRUSTIX_E2E_WORKDIR:-$(mktemp -d /tmp/trustix-e2e.XXXXXX)}"
workdir="$(mkdir -p "$workdir" && cd "$workdir" && pwd -P)"
keep="${TRUSTIX_E2E_KEEP:-0}"
perf_fast="${TRUSTIX_E2E_PERF_FAST:-0}"
transport="${TRUSTIX_E2E_TRANSPORT:-udp}"
tls_only="${TRUSTIX_E2E_TLS_ONLY:-0}"
direct_management_vip="${TRUSTIX_E2E_DIRECT_MANAGEMENT_VIP:-auto}"
transport_encryption="${TRUSTIX_E2E_TRANSPORT_ENCRYPTION:-${TRUSTIX_E2E_ENCRYPTION:-}}"
transport_profile="${TRUSTIX_E2E_TRANSPORT_PROFILE:-stable}"
transport_datapath="${TRUSTIX_E2E_TRANSPORT_DATAPATH:-auto}"
dataplane="${TRUSTIX_E2E_DATAPLANE:-linux}"
manage_forwarding="${TRUSTIX_E2E_MANAGE_FORWARDING:-true}"
lan_mode="${TRUSTIX_E2E_LAN_MODE:-routed}"
route_kind_probe="${TRUSTIX_E2E_ROUTE_KIND_PROBE:-1}"
tcp_probe="${TRUSTIX_E2E_TCP_PROBE:-0}"
bin_dir="${TRUSTIX_E2E_BIN_DIR:-$workdir/bin}"
router_netns="${TRUSTIX_E2E_ROUTER_NETNS:-0}"
nat_reverse="${TRUSTIX_E2E_NAT_REVERSE:-0}"
af_xdp_queues="${TRUSTIX_E2E_AF_XDP_QUEUES:-1}"
xdp_mode="${TRUSTIX_E2E_XDP_MODE:-auto}"
af_xdp_bind_mode="${TRUSTIX_E2E_AF_XDP_BIND_MODE:-auto}"
af_xdp_need_wakeup="${TRUSTIX_E2E_AF_XDP_NEED_WAKEUP:-0}"
af_xdp_tx_backpressure_wait="${TRUSTIX_E2E_AF_XDP_TX_BACKPRESSURE_WAIT:-50ms}"
af_xdp_tx_kick_batch="${TRUSTIX_E2E_AF_XDP_TX_KICK_BATCH:-256}"
af_xdp_tx_flush_interval="${TRUSTIX_E2E_AF_XDP_TX_FLUSH_INTERVAL:-0}"
af_xdp_tx_soft_kick_backoff="${TRUSTIX_E2E_AF_XDP_TX_SOFT_KICK_BACKOFF:-${TRUSTIX_AF_XDP_TX_SOFT_KICK_BACKOFF:-0}}"
af_xdp_tx_defer_flush="${TRUSTIX_E2E_AF_XDP_TX_DEFER_FLUSH:-${TRUSTIX_AF_XDP_TX_DEFER_FLUSH:-0}}"
af_xdp_tx_defer_flush_delay="${TRUSTIX_E2E_AF_XDP_TX_DEFER_FLUSH_DELAY:-${TRUSTIX_AF_XDP_TX_DEFER_FLUSH_DELAY:-50us}}"
af_xdp_tx_coalesce_copy_mode="${TRUSTIX_E2E_AF_XDP_TX_COALESCE_COPY_MODE:-${TRUSTIX_AF_XDP_TX_COALESCE_COPY_MODE:-0}}"
af_xdp_rx_burst="${TRUSTIX_E2E_AF_XDP_RX_BURST:-256}"
af_xdp_ring_entries="${TRUSTIX_E2E_AF_XDP_RING_ENTRIES:-4096}"
af_xdp_umem_frames="${TRUSTIX_E2E_AF_XDP_UMEM_FRAMES:-8192}"
af_xdp_umem_frame_size="${TRUSTIX_E2E_AF_XDP_UMEM_FRAME_SIZE:-2048}"
hot_stats="${TRUSTIX_E2E_HOT_STATS:-1}"
kernel_udp_session_buffer="${TRUSTIX_E2E_KERNEL_UDP_SESSION_BUFFER:-512}"
capture_forwarder_workers="${TRUSTIX_E2E_CAPTURE_FORWARDER_WORKERS:-4}"
capture_forwarder_buffer="${TRUSTIX_E2E_CAPTURE_FORWARDER_BUFFER:-262144}"
capture_forwarder_batch="${TRUSTIX_E2E_CAPTURE_FORWARDER_BATCH:-256}"
capture_forwarder_batch_delay="${TRUSTIX_E2E_CAPTURE_FORWARDER_BATCH_DELAY:-0}"
data_session_encrypted_tixb="${TRUSTIX_E2E_DATA_SESSION_ENCRYPTED_TIXB:-${TRUSTIX_DATA_SESSION_ENCRYPTED_TIXB:-auto}}"
data_session_rx_gso_coalesce_userspace_encrypted="${TRUSTIX_E2E_DATA_SESSION_RX_GSO_COALESCE_USERSPACE_ENCRYPTED:-${TRUSTIX_DATA_SESSION_RX_GSO_COALESCE_USERSPACE_ENCRYPTED:-auto}}"
kernel_module="${TRUSTIX_E2E_KERNEL_MODULE:-0}"
kernel_script="${TRUSTIX_E2E_KERNEL_SCRIPT:-${repo_root}/scripts/linux-kernel-module-smoke.sh}"
kernel_module_dir="${TRUSTIX_E2E_KERNEL_MODULE_DIR:-${repo_root}/kernel/trustix_crypto}"
kernel_test_bin="${TRUSTIX_E2E_KERNEL_TEST_BIN:-}"
kernel_experimental_vaes="${TRUSTIX_E2E_KERNEL_EXPERIMENTAL_VAES:-0}"
kernel_experimental_vaes_kfunc="${TRUSTIX_E2E_KERNEL_EXPERIMENTAL_VAES_KFUNC:-auto}"
kernel_load_only="${TRUSTIX_E2E_KERNEL_LOAD_ONLY:-${TRUSTIX_KERNEL_LOAD_ONLY:-auto}}"
datapath_module="${TRUSTIX_E2E_DATAPATH_MODULE:-auto}"
datapath_script="${TRUSTIX_E2E_DATAPATH_SCRIPT:-${repo_root}/scripts/linux-datapath-module-smoke.sh}"
datapath_module_dir="${TRUSTIX_E2E_DATAPATH_MODULE_DIR:-${repo_root}/kernel/trustix_datapath_helpers}"
datapath_enable_features="${TRUSTIX_E2E_DATAPATH_ENABLE_FEATURES:-832}"
full_datapath_module="${TRUSTIX_E2E_FULL_DATAPATH_MODULE:-0}"
full_datapath_script="${TRUSTIX_E2E_FULL_DATAPATH_SCRIPT:-${repo_root}/scripts/linux-full-datapath-module-smoke.sh}"
full_datapath_module_dir="${TRUSTIX_E2E_FULL_DATAPATH_MODULE_DIR:-${repo_root}/kernel/trustix_datapath}"
full_datapath_ko="${TRUSTIX_E2E_FULL_DATAPATH_KO:-}"
full_datapath_enable_features="${TRUSTIX_E2E_FULL_DATAPATH_ENABLE_FEATURES:-128}"
full_datapath_rx_worker="${TRUSTIX_E2E_FULL_DATAPATH_RX_WORKER:-0}"
crypto_placement="${TRUSTIX_E2E_CRYPTO_PLACEMENT:-userspace}"
ping_count="${TRUSTIX_E2E_PING_COUNT:-1}"
ping_size="${TRUSTIX_E2E_PING_SIZE:-56}"
ping_parallel="${TRUSTIX_E2E_PING_PARALLEL:-1}"
ping_rounds="${TRUSTIX_E2E_PING_ROUNDS:-1}"
udp_burst_packets="${TRUSTIX_E2E_UDP_BURST_PACKETS:-0}"
udp_burst_size="${TRUSTIX_E2E_UDP_BURST_SIZE:-256}"
udp_burst_parallel="${TRUSTIX_E2E_UDP_BURST_PARALLEL:-1}"
udp_burst_rounds="${TRUSTIX_E2E_UDP_BURST_ROUNDS:-1}"
udp_burst_rate_pps="${TRUSTIX_E2E_UDP_BURST_RATE_PPS:-0}"
udp_burst_allow_loss="${TRUSTIX_E2E_UDP_BURST_ALLOW_LOSS:-0}"
udp_burst_port="${TRUSTIX_E2E_UDP_BURST_PORT:-18100}"
tcp_burst_connections="${TRUSTIX_E2E_TCP_BURST_CONNECTIONS:-0}"
tcp_burst_size="${TRUSTIX_E2E_TCP_BURST_SIZE:-1024}"
tcp_burst_parallel="${TRUSTIX_E2E_TCP_BURST_PARALLEL:-1}"
tcp_burst_rounds="${TRUSTIX_E2E_TCP_BURST_ROUNDS:-1}"
tcp_burst_port="${TRUSTIX_E2E_TCP_BURST_PORT:-18200}"
iperf3_probe="${TRUSTIX_E2E_IPERF3:-0}"
iperf3_seconds="${TRUSTIX_E2E_IPERF3_SECONDS:-5}"
iperf3_parallel="${TRUSTIX_E2E_IPERF3_PARALLEL:-1}"
iperf3_port="${TRUSTIX_E2E_IPERF3_PORT:-25201}"
iperf3_reverse="${TRUSTIX_E2E_IPERF3_REVERSE:-0}"
iperf3_directions="${TRUSTIX_E2E_IPERF3_DIRECTIONS:-both}"
iperf3_timeout="${TRUSTIX_E2E_IPERF3_TIMEOUT:-}"
iperf3_min_sent_gbps="${TRUSTIX_E2E_IPERF3_MIN_SENT_GBPS:-${TRUSTIX_E2E_IPERF3_MIN_GBPS:-0}}"
iperf3_min_received_gbps="${TRUSTIX_E2E_IPERF3_MIN_RECEIVED_GBPS:-${TRUSTIX_E2E_IPERF3_MIN_GBPS:-0}}"
iperf3_pre_hook="${TRUSTIX_E2E_IPERF3_PRE_HOOK:-}"
iperf3_post_hook="${TRUSTIX_E2E_IPERF3_POST_HOOK:-}"
trustixctl_timeout="${TRUSTIX_E2E_TRUSTIXCTL_TIMEOUT:-8s}"
api_ready_attempts="${TRUSTIX_E2E_API_READY_ATTEMPTS:-80}"
api_ready_sleep="${TRUSTIX_E2E_API_READY_SLEEP:-0.25}"
cpu_profile_dir="${TRUSTIX_E2E_CPU_PROFILE_DIR:-}"
burst_timeout="${TRUSTIX_E2E_BURST_TIMEOUT:-10}"
tcp_connect_timeout="${TRUSTIX_E2E_TCP_CONNECT_TIMEOUT:-5}"
crash_restart="${TRUSTIX_E2E_CRASH_RESTART:-1}"
experimental_tcp_skip_checksum="${TRUSTIX_E2E_EXPERIMENTAL_TCP_SKIP_TCP_CHECKSUM:-${TRUSTIX_E2E_EXPERIMENTAL_TCP_SKIP_CHECKSUM:-${TRUSTIX_EXPERIMENTAL_TCP_SKIP_CHECKSUM:-${TRUSTIX_EXPERIMENTAL_TCP_SKIP_TCP_CHECKSUM:-0}}}}"
experimental_tcp_skip_outer_checksum="${TRUSTIX_E2E_EXPERIMENTAL_TCP_SKIP_OUTER_TCP_CHECKSUM:-${TRUSTIX_EXPERIMENTAL_TCP_SKIP_OUTER_TCP_CHECKSUM:-$experimental_tcp_skip_checksum}}"
experimental_tcp_tc_tx_direct="${TRUSTIX_E2E_EXPERIMENTAL_TCP_TC_TX_DIRECT:-${TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT:-}}"
experimental_tcp_tc_tx_direct_only="${TRUSTIX_E2E_EXPERIMENTAL_TCP_TC_TX_DIRECT_ONLY:-${TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_ONLY:-}}"
experimental_tcp_route_gso_sync="${TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_GSO_SYNC:-${TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_KFUNC:-${TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_SYNC:-0}}}"
experimental_tcp_route_gso_sync_stream="${TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_GSO_SYNC_STREAM:-${TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO_SYNC_STREAM:-${TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_SYNC_STREAM:-0}}}"
experimental_tcp_route_gso_sync_stream_outer_gso="${TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_GSO_SYNC_STREAM_OUTER_GSO:-${TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO_SYNC_STREAM_OUTER_GSO:-1}}"
experimental_tcp_route_gso_sync_stream_max_frames="${TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_GSO_SYNC_STREAM_MAX_FRAMES:-${TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO_SYNC_STREAM_MAX_FRAMES:-8}}"
experimental_tcp_route_gso_async="${TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC:-${TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_ASYNC_KFUNC:-${TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_ASYNC:-0}}}"
experimental_tcp_route_gso_async_crash_risk_ack="${TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_CRASH_RISK_ACK:-${TRUSTIX_EXPERIMENTAL_TCP_ALLOW_CRASH_RISK_ROUTE_TCP_GSO_ASYNC:-${TRUSTIX_EXPERIMENTAL_TCP_ROUTE_TCP_GSO_ASYNC_CRASH_RISK_ACK:-0}}}"
experimental_tcp_route_gso_async_dev_xmit="${TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_DEV_XMIT:-${TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_DEV_XMIT:-${experimental_tcp_route_gso_async}}}"
experimental_tcp_route_xmit_worker="${TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_XMIT_WORKER:-${TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_XMIT_KFUNC:-0}}"
experimental_tcp_route_xmit_worker_crash_risk_ack="${TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_XMIT_WORKER_CRASH_RISK_ACK:-${TRUSTIX_EXPERIMENTAL_TCP_ALLOW_CRASH_RISK_ROUTE_TCP_XMIT:-${TRUSTIX_EXPERIMENTAL_TCP_ROUTE_TCP_XMIT_CRASH_RISK_ACK:-0}}}"
experimental_tcp_route_xmit_worker_steal="${TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_XMIT_WORKER_STEAL:-${TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_XMIT_STEAL:-0}}"
experimental_tcp_route_xmit_worker_steal_crash_risk_ack="${TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_XMIT_WORKER_STEAL_CRASH_RISK_ACK:-${TRUSTIX_EXPERIMENTAL_TCP_ALLOW_CRASH_RISK_ROUTE_TCP_XMIT_STEAL:-0}}"
experimental_tcp_route_gso_async_limit="${TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_LIMIT:-${TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_LIMIT:-256}}"
experimental_tcp_route_gso_async_worker_item_budget="${TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_WORKER_ITEM_BUDGET:-${TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_WORKER_ITEM_BUDGET:-64}}"
experimental_tcp_route_gso_async_worker_segment_budget="${TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_WORKER_SEGMENT_BUDGET:-${TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_WORKER_SEGMENT_BUDGET:-2048}}"
experimental_tcp_route_gso_async_max_segments_per_item="${TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_MAX_SEGMENTS_PER_ITEM:-${TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_MAX_SEGMENTS_PER_ITEM:-64}}"
experimental_tcp_route_gso_async_stream="${TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_STREAM:-${TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_STREAM:-0}}"
experimental_tcp_route_gso_async_stream_direct_build="${TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_STREAM_DIRECT_BUILD:-${TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_STREAM_DIRECT_BUILD:-0}}"
experimental_tcp_route_gso_async_stream_outer_gso="${TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_STREAM_OUTER_GSO:-${TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_STREAM_OUTER_GSO:-0}}"
experimental_tcp_route_gso_async_stream_max_frames="${TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_STREAM_MAX_FRAMES:-${TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_STREAM_MAX_FRAMES:-8}}"
experimental_tcp_route_gso_trust_partial_inner_checksum="${TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_GSO_TRUST_PARTIAL_INNER_CHECKSUM:-${TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_TRUST_PARTIAL_INNER_CHECKSUM:-0}}"
experimental_tcp_route_header_kfunc="${TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_HEADER_KFUNC:-${TRUSTIX_EXPERIMENTAL_TCP_TC_TX_PUSH_ROUTE_TCP_HEADER_KFUNC:-0}}"
experimental_tcp_plain_skip_sequence="${TRUSTIX_E2E_EXPERIMENTAL_TCP_PLAIN_SKIP_SEQUENCE:-${TRUSTIX_EXPERIMENTAL_TCP_TX_PLAIN_SKIP_SEQUENCE:-${TRUSTIX_TIXT_TX_PLAIN_SKIP_SEQUENCE:-0}}}"
experimental_tcp_plain_ack_only="${TRUSTIX_E2E_EXPERIMENTAL_TCP_PLAIN_ACK_ONLY:-${TRUSTIX_EXPERIMENTAL_TCP_TX_PLAIN_ACK_ONLY:-${TRUSTIX_TIXT_TX_PLAIN_ACK_ONLY:-0}}}"
experimental_tcp_auto_umem_jumbo="${TRUSTIX_E2E_EXPERIMENTAL_TCP_AUTO_UMEM_JUMBO:-${TRUSTIX_EXPERIMENTAL_TCP_AUTO_UMEM_JUMBO:-0}}"
kernel_udp_xdp_open="${TRUSTIX_E2E_KERNEL_UDP_XDP_OPEN:-${TRUSTIX_KERNEL_UDP_XDP_OPEN:-0}}"
kernel_udp_xdp_pass_opened="${TRUSTIX_E2E_KERNEL_UDP_XDP_PASS_OPENED:-${TRUSTIX_KERNEL_UDP_XDP_PASS_OPENED:-0}}"
kernel_udp_xdp_rx_direct="${TRUSTIX_E2E_KERNEL_UDP_XDP_RX_DIRECT:-${TRUSTIX_KERNEL_UDP_XDP_RX_DIRECT:-0}}"
kernel_udp_xdp_rx_secure_direct="${TRUSTIX_E2E_KERNEL_UDP_XDP_RX_SECURE_DIRECT:-${TRUSTIX_KERNEL_UDP_XDP_RX_SECURE_DIRECT:-0}}"
kernel_udp_xdp_rx_direct_ifindex="${TRUSTIX_E2E_KERNEL_UDP_XDP_RX_DIRECT_IFINDEX:-${TRUSTIX_KERNEL_UDP_XDP_RX_DIRECT_IFINDEX:-0}}"
kernel_udp_xdp_rx_direct_mode="${TRUSTIX_E2E_KERNEL_UDP_XDP_RX_DIRECT_MODE:-${TRUSTIX_KERNEL_UDP_XDP_RX_DIRECT_MODE:-}}"
kernel_udp_tc_rx_secure_direct="${TRUSTIX_E2E_KERNEL_UDP_TC_RX_SECURE_DIRECT:-${TRUSTIX_KERNEL_UDP_TC_RX_SECURE_DIRECT:-0}}"
kernel_udp_tc_tx_secure_direct_kfunc_seal="${TRUSTIX_E2E_KERNEL_UDP_TC_TX_SECURE_DIRECT_KFUNC_SEAL:-${TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_KFUNC_SEAL:-0}}"
kernel_udp_tc_tx_secure_direct_skb_seal_kfunc="${TRUSTIX_E2E_KERNEL_UDP_TC_TX_SECURE_DIRECT_SKB_SEAL_KFUNC:-${TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_SKB_SEAL_KFUNC:-0}}"
kernel_udp_tc_tx_secure_direct_outer_tcp_checksum_kfunc="${TRUSTIX_E2E_KERNEL_UDP_TC_TX_SECURE_DIRECT_OUTER_TCP_CHECKSUM_KFUNC:-${TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_OUTER_TCP_CHECKSUM_KFUNC:-0}}"
kernel_udp_tc_tx_secure_direct_outer_tcp_partial_checksum_kfunc="${TRUSTIX_E2E_KERNEL_UDP_TC_TX_SECURE_DIRECT_OUTER_TCP_PARTIAL_CHECKSUM_KFUNC:-${TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_OUTER_TCP_PARTIAL_CHECKSUM_KFUNC:-0}}"
kernel_udp_tc_rx_secure_direct_kfunc_open="${TRUSTIX_E2E_KERNEL_UDP_TC_RX_SECURE_DIRECT_KFUNC_OPEN:-${TRUSTIX_KERNEL_UDP_TC_RX_SECURE_DIRECT_KFUNC_OPEN:-0}}"
kernel_udp_tc_rx_secure_direct_skb_open_kfunc="${TRUSTIX_E2E_KERNEL_UDP_TC_RX_SECURE_DIRECT_SKB_OPEN_KFUNC:-${TRUSTIX_KERNEL_UDP_TC_RX_SECURE_DIRECT_SKB_OPEN_KFUNC:-0}}"
kernel_udp_tc_tx_secure_direct_trust_inner_checksums="${TRUSTIX_E2E_KERNEL_UDP_TC_TX_SECURE_DIRECT_TRUST_INNER_CHECKSUMS:-${TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_TRUST_INNER_CHECKSUMS:-${TRUSTIX_E2E_TRUST_CAPTURED_CHECKSUMS:-${TRUSTIX_TRUST_CAPTURED_CHECKSUMS:-0}}}}"
kernel_udp_tc_tx_secure_direct_fix_inner_checksums="${TRUSTIX_E2E_KERNEL_UDP_TC_TX_SECURE_DIRECT_FIX_INNER_CHECKSUMS:-${TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_FIX_INNER_CHECKSUMS:-0}}"
kernel_udp_tc_adj_room_no_csum_reset="${TRUSTIX_E2E_KERNEL_UDP_TC_ADJ_ROOM_NO_CSUM_RESET:-${TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_NO_CSUM_RESET:-}}"
kernel_udp_tc_adj_room_tunnel_gso="${TRUSTIX_E2E_KERNEL_UDP_TC_ADJ_ROOM_TUNNEL_GSO:-${TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_TUNNEL_GSO:-}}"
kernel_udp_tc_adj_room_encap_l2_len="${TRUSTIX_E2E_KERNEL_UDP_TC_ADJ_ROOM_ENCAP_L2_LEN:-${TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_ENCAP_L2_LEN:-}}"
kernel_udp_tc_direct_active_gso="${TRUSTIX_E2E_KERNEL_UDP_TC_DIRECT_ACTIVE_GSO:-${TRUSTIX_KERNEL_UDP_TC_DIRECT_ACTIVE_GSO:-}}"
session_pool_size="${TRUSTIX_E2E_SESSION_POOL_SIZE:-0}"
session_pool_strategy="${TRUSTIX_E2E_SESSION_POOL_STRATEGY:-flow}"
session_pool_warmup="${TRUSTIX_E2E_SESSION_POOL_WARMUP:-false}"
iptunnel_port="${TRUSTIX_E2E_IPTUNNEL_PORT:-47829}"
iptunnel_mtu="${TRUSTIX_E2E_IPTUNNEL_MTU:-1400}"
underlay_mtu="${TRUSTIX_E2E_UNDERLAY_MTU:-1500}"
lan_mtu="${TRUSTIX_E2E_LAN_MTU:-1500}"
disable_veth_offloads="${TRUSTIX_E2E_DISABLE_VETH_OFFLOADS:-auto}"

ns_a="${TRUSTIX_E2E_NS_A:-tix-lan-a}"
ns_b="${TRUSTIX_E2E_NS_B:-tix-lan-b}"
ns_ix_a="${TRUSTIX_E2E_NS_IX_A:-tix-ix-a}"
ns_ix_b="${TRUSTIX_E2E_NS_IX_B:-tix-ix-b}"
lan_a="${TRUSTIX_E2E_LAN_A:-tixa0}"
lan_b="${TRUSTIX_E2E_LAN_B:-tixb0}"
host_a="${TRUSTIX_E2E_HOST_A:-tixah0}"
host_b="${TRUSTIX_E2E_HOST_B:-tixbh0}"
underlay_a="${TRUSTIX_E2E_UNDERLAY_A:-tixua0}"
underlay_b="${TRUSTIX_E2E_UNDERLAY_B:-tixub0}"
underlay_ip_a="${TRUSTIX_E2E_UNDERLAY_IP_A:-198.18.0.1}"
underlay_ip_b="${TRUSTIX_E2E_UNDERLAY_IP_B:-198.18.0.2}"
underlay_cidr_a="${TRUSTIX_E2E_UNDERLAY_CIDR_A:-${underlay_ip_a}/30}"
underlay_cidr_b="${TRUSTIX_E2E_UNDERLAY_CIDR_B:-${underlay_ip_b}/30}"

api_a_port="${TRUSTIX_E2E_API_A_PORT:-}"
api_b_port="${TRUSTIX_E2E_API_B_PORT:-}"
peer_api_a_port="${TRUSTIX_E2E_PEER_API_A_PORT:-}"
peer_api_b_port="${TRUSTIX_E2E_PEER_API_B_PORT:-}"
udp_a_port="${TRUSTIX_E2E_UDP_A_PORT:-}"
udp_b_port="${TRUSTIX_E2E_UDP_B_PORT:-}"
tcp_a_port="${TRUSTIX_E2E_TCP_A_PORT:-}"
tcp_b_port="${TRUSTIX_E2E_TCP_B_PORT:-}"
exp_tcp_a_port="${TRUSTIX_E2E_EXP_TCP_A_PORT:-}"
exp_tcp_b_port="${TRUSTIX_E2E_EXP_TCP_B_PORT:-}"

api_a=""
api_b=""
iperf3_post_hook_armed=0
peer_api_a=""
peer_api_b=""
udp_a=""
udp_b=""
tcp_a=""
tcp_b=""
exp_tcp_a=""
exp_tcp_b=""
iptunnel_a=""
iptunnel_b=""
allocated_ports=""

pid_a=""
pid_b=""
success=0

log() {
  printf '[trustix-e2e] %s\n' "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

truthy() {
  case "${1:-0}" in
    1|true|yes|on|enabled) return 0 ;;
    *) return 1 ;;
  esac
}

falsey() {
  case "${1:-0}" in
    0|false|no|off|disabled) return 0 ;;
    *) return 1 ;;
  esac
}

kernel_cpu_has_flag() {
  local flag="$1"
  [[ -r /proc/cpuinfo ]] || return 1
  awk -v flag="$flag" '
    /^flags[[:space:]]*:/ || /^Features[[:space:]]*:/ {
      for (i = 2; i <= NF; i++) {
        if ($i == flag) {
          found = 1
        }
      }
    }
    END { exit found ? 0 : 1 }
  ' /proc/cpuinfo
}

kernel_cpu_vaes_capable() {
  kernel_cpu_has_flag aes &&
    kernel_cpu_has_flag avx2 &&
    kernel_cpu_has_flag vaes &&
    kernel_cpu_has_flag vpclmulqdq
}

hot_stats_enabled() {
  truthy "$hot_stats"
}

capture_history_enabled() {
  case "${TRUSTIX_CAPTURE_HISTORY:-1}" in
    0|false|no|off|disabled) return 1 ;;
    *) return 0 ;;
  esac
}

kernel_provider_expected() {
  [[ "$kernel_module" == "1" ]] || grep -q '^trustix_crypto ' /proc/modules 2>/dev/null
}

is_af_xdp_transport() {
  [[ "$transport" == "experimental_tcp" || "$transport" == "kernel_udp" ]]
}

kernel_udp_secure_direct_enabled() {
  [[ "$transport" == "kernel_udp" ]] &&
    [[ "$crypto_placement" == "kernel" || "$crypto_placement" == "auto" ]] &&
    truthy "${TRUSTIX_E2E_KERNEL_UDP_TC_TX_SECURE_DIRECT:-0}"
}

experimental_tcp_direct_enabled() {
  [[ "$transport" == "experimental_tcp" ]] &&
    truthy "$experimental_tcp_tc_tx_direct" &&
    (truthy "$experimental_tcp_skip_checksum" || experimental_tcp_route_tcp_kfunc_enabled || experimental_tcp_secure_direct_enabled)
}

experimental_tcp_route_gso_async_enabled() {
  [[ "$transport" == "experimental_tcp" ]] &&
    truthy "$experimental_tcp_route_gso_async"
}

experimental_tcp_route_gso_sync_enabled() {
  [[ "$transport" == "experimental_tcp" ]] &&
    truthy "$experimental_tcp_route_gso_sync"
}

experimental_tcp_route_xmit_worker_enabled() {
  [[ "$transport" == "experimental_tcp" ]] &&
    truthy "$experimental_tcp_route_xmit_worker"
}

experimental_tcp_route_tcp_kfunc_enabled() {
  [[ "$transport" == "experimental_tcp" ]] &&
    (experimental_tcp_route_gso_sync_enabled || experimental_tcp_route_gso_async_enabled || experimental_tcp_route_xmit_worker_enabled)
}

experimental_tcp_route_tcp_kfunc_value() {
  experimental_tcp_route_tcp_kfunc_enabled && printf '1' || printf '0'
}

experimental_tcp_route_header_kfunc_enabled() {
  [[ "$transport" == "experimental_tcp" ]] &&
    (truthy "$experimental_tcp_route_header_kfunc" || experimental_tcp_route_tcp_kfunc_enabled)
}

experimental_tcp_secure_direct_enabled() {
  [[ "$transport" == "experimental_tcp" ]] &&
    [[ "$crypto_placement" == "kernel" || "$crypto_placement" == "auto" ]] &&
    truthy "${TRUSTIX_E2E_KERNEL_UDP_TC_TX_SECURE_DIRECT:-0}"
}

kernel_plaintext_direct_fastpath_enabled() {
  is_plaintext_encryption "$(effective_transport_encryption)" || return 1
  [[ "$crypto_placement" == "auto" || "$crypto_placement" == "userspace" ]] || return 1
  case "$transport" in
    kernel_udp)
      return 0
      ;;
    experimental_tcp)
      truthy "$experimental_tcp_tc_tx_direct" && truthy "$experimental_tcp_tc_tx_direct_only"
      ;;
    *)
      return 1
      ;;
  esac
}

experimental_tcp_direct_active_gso_enabled() {
  [[ "$transport" == "experimental_tcp" ]] || return 1
  truthy "${TRUSTIX_E2E_KERNEL_UDP_TC_DIRECT_ACTIVE_GSO:-${TRUSTIX_KERNEL_UDP_TC_DIRECT_ACTIVE_GSO:-0}}" || return 1
  truthy "${TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_ACTIVE_GSO_SAFE:-${TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_SAFE_ACTIVE_GSO:-0}}"
}

experimental_tcp_plaintext_linear_direct_only_enabled() {
  [[ "$transport" == "experimental_tcp" ]] || return 1
  is_plaintext_encryption "$(effective_transport_encryption)" || return 1
  [[ "$crypto_placement" == "auto" || "$crypto_placement" == "userspace" ]] || return 1
  truthy "$experimental_tcp_tc_tx_direct" || return 1
  truthy "$(experimental_tcp_kernel_udp_direct_only_value)" || return 1
  experimental_tcp_route_tcp_kfunc_enabled && return 1
  experimental_tcp_direct_active_gso_enabled && return 1
  return 0
}

native_tunnel_plaintext_route_offload_enabled() {
  is_iptunnel_transport || return 1
  is_plaintext_encryption "$(effective_transport_encryption)" || return 1
  case "${TRUSTIX_NATIVE_TUNNEL_ROUTE_OFFLOAD:-1}" in
    0|false|no|off|disabled) return 1 ;;
    *) return 0 ;;
  esac
}

effective_disable_veth_offloads() {
  if [[ "$disable_veth_offloads" == "auto" ]]; then
    experimental_tcp_plaintext_linear_direct_only_enabled && return 0
    experimental_tcp_route_tcp_kfunc_enabled && return 1
    kernel_plaintext_direct_fastpath_enabled && return 1
    kernel_udp_secure_direct_enabled || experimental_tcp_direct_enabled ||
      ([[ "$transport" == "kernel_udp" ]] && is_plaintext_encryption "$(effective_transport_encryption)")
    return
  fi
  truthy "$disable_veth_offloads"
}

effective_kernel_experimental_vaes_kfunc() {
  if [[ "$kernel_experimental_vaes_kfunc" == "auto" ]]; then
    kernel_cpu_vaes_capable
    return
  fi
  truthy "$kernel_experimental_vaes_kfunc"
}

effective_kernel_experimental_vaes() {
  if [[ "$kernel_experimental_vaes" == "auto" ]]; then
    kernel_cpu_vaes_capable
    return
  fi
  truthy "$kernel_experimental_vaes"
}

effective_kernel_load_only() {
  case "$kernel_load_only" in
    auto) return 0 ;;
    *) truthy "$kernel_load_only" ;;
  esac
}

kernel_extra_module_params() {
	local vaes_kfunc=0
	if effective_kernel_experimental_vaes_kfunc; then
		vaes_kfunc=1
	fi
	if [[ -n "${TRUSTIX_E2E_KERNEL_EXTRA_MODULE_PARAMS+x}" ]]; then
		printf '%s\n' "$TRUSTIX_E2E_KERNEL_EXTRA_MODULE_PARAMS"
		return
	fi
	local params="experimental_aesni_kfunc=1 experimental_vaes_kfunc=${vaes_kfunc} kfunc_fastpath_stats=0 kfunc_fastpath_wipe=${TRUSTIX_E2E_KERNEL_FASTPATH_WIPE:-1}"
	if truthy "${TRUSTIX_E2E_KERNEL_ALLOW_SIMD_KFUNC_FASTPATH:-${TRUSTIX_KERNEL_CRYPTO_ALLOW_SIMD_KFUNC_FASTPATH:-0}}"; then
		params="kfunc_simd_fastpath=1 ${params}"
	fi
	printf '%s\n' "$params"
}

datapath_extra_module_params() {
  if [[ -n "${TRUSTIX_E2E_DATAPATH_EXTRA_MODULE_PARAMS+x}" ]]; then
    printf '%s\n' "$TRUSTIX_E2E_DATAPATH_EXTRA_MODULE_PARAMS"
    return
  fi
  local params=""
  local add_param
  add_param() {
    local assignment="$1"
    local key="${assignment%%=*}"
    [[ -n "$key" ]] || return 0
    case " ${params} " in
      *" ${key}="*) return 0 ;;
    esac
    params="${params:+${params} }${assignment}"
  }
  if experimental_tcp_route_header_kfunc_enabled; then
    add_param "tixt_tx_plain_skip_sequence=${experimental_tcp_plain_skip_sequence}"
    add_param "tixt_tx_plain_ack_only=${experimental_tcp_plain_ack_only}"
  fi
  if experimental_tcp_route_gso_sync_enabled || truthy "$experimental_tcp_route_gso_sync_stream"; then
    add_param "route_tcp_gso=1"
  fi
  if experimental_tcp_route_gso_async_enabled; then
    add_param "route_tcp_gso=1"
    add_param "route_tcp_gso_async=1"
    add_param "route_tcp_gso_async_dev_xmit=${experimental_tcp_route_gso_async_dev_xmit}"
    add_param "route_tcp_gso_async_limit=${experimental_tcp_route_gso_async_limit}"
    add_param "route_tcp_gso_async_worker_item_budget=${experimental_tcp_route_gso_async_worker_item_budget}"
    add_param "route_tcp_gso_async_worker_segment_budget=${experimental_tcp_route_gso_async_worker_segment_budget}"
    add_param "route_tcp_gso_async_max_segments_per_item=${experimental_tcp_route_gso_async_max_segments_per_item}"
    if truthy "$experimental_tcp_route_gso_async_stream"; then
      add_param "route_tcp_gso_async_stream=1"
      add_param "route_tcp_gso_async_stream_max_frames=${experimental_tcp_route_gso_async_stream_max_frames}"
    fi
    if truthy "$experimental_tcp_route_gso_async_stream_direct_build"; then
      add_param "route_tcp_gso_async_stream_direct_build=1"
    fi
    if truthy "$experimental_tcp_route_gso_async_stream_outer_gso"; then
      add_param "route_tcp_gso_async_stream_outer_gso=1"
      add_param "route_tcp_gso_async_stream_outer_gso_hard_enable=1"
    fi
  fi
  if truthy "$experimental_tcp_route_gso_sync_stream"; then
    add_param "route_tcp_gso_sync_stream=1"
    add_param "route_tcp_gso_sync_stream_outer_gso=${experimental_tcp_route_gso_sync_stream_outer_gso}"
    add_param "route_tcp_gso_sync_stream_max_frames=${experimental_tcp_route_gso_sync_stream_max_frames}"
  fi
  if experimental_tcp_route_xmit_worker_enabled; then
    add_param "route_tcp_xmit_worker=1"
  fi
  if experimental_tcp_profile_route_gso_default_enabled; then
    add_param "route_tcp_gso_async_prefer=1"
    add_param "route_tcp_gso_async_bytes_limit=33554432"
    add_param "route_tcp_gso_async_worker_emit_budget=0"
    add_param "route_tcp_gso_async_worker_resched_stride=0"
    add_param "route_tcp_gso_async_worker_dequeue_batch=32"
    add_param "route_tcp_gso_async_worker_min_queue_depth=0"
    add_param "route_tcp_gso_async_worker_schedule_delay_usecs=0"
    add_param "route_tcp_gso_async_unbound_worker=1"
    add_param "route_tcp_gso_async_sharded_queue=1"
    add_param "route_tcp_gso_async_queue_shards=8"
    add_param "route_tcp_gso_async_flow_shard_queue=1"
    add_param "route_tcp_gso_async_hash_tx_queue=0"
    add_param "route_tcp_gso_async_txq_stopped_backoff_retries=1"
    add_param "route_tcp_gso_async_txq_stopped_backoff_sleep_usecs=50"
    add_param "route_tcp_gso_async_stream_direct_build_inner_csum=1"
    add_param "route_tcp_gso_async_stream_direct_build_fast_copy=1"
    add_param "route_tcp_gso_async_stream_direct_build_frag_fast_copy=1"
    add_param "route_tcp_gso_async_stream_outer_gso_hard_enable=1"
    add_param "route_tcp_gso_async_stream_cross_item_batch=1"
    add_param "route_tcp_gso_async_stream_cross_item_dequeue_batch=1"
    add_param "route_tcp_gso_async_stream_cross_item_max_frames=128"
    add_param "route_tcp_gso_async_stream_cross_item_dynamic_cap=0"
    add_param "tixt_rx_coalesce_segment_gso=0"
    add_param "tixt_rx_backlog_worker_budget=2048"
    add_param "tixt_rx_backlog_worker_queue_limit=65536"
  fi
  printf '%s\n' "$params"
}

datapath_module_needed() {
  case "$datapath_module" in
    1|true|yes|on|enabled|required) return 0 ;;
    0|false|no|off|disabled) return 1 ;;
  esac
  experimental_tcp_route_header_kfunc_enabled && return 0
  if [[ "$transport" == "kernel_udp" ]] || experimental_tcp_direct_enabled || kernel_plaintext_direct_fastpath_enabled; then
    return 0
  fi
  return 1
}

full_datapath_module_needed() {
  case "$full_datapath_module" in
    1|true|yes|on|enabled|required) return 0 ;;
    0|false|no|off|disabled) return 1 ;;
    *) die "TRUSTIX_E2E_FULL_DATAPATH_MODULE must be 0 or 1" ;;
  esac
}

full_datapath_rx_worker_enabled() {
  truthy "$full_datapath_rx_worker"
}

full_datapath_rx_worker_value() {
  full_datapath_rx_worker_enabled && printf '1' || printf '0'
}

full_datapath_extra_module_params() {
  local params=""
  if [[ -n "${TRUSTIX_E2E_FULL_DATAPATH_EXTRA_MODULE_PARAMS+x}" ]]; then
    params="$TRUSTIX_E2E_FULL_DATAPATH_EXTRA_MODULE_PARAMS"
  fi
  if full_datapath_rx_worker_enabled; then
    params="$(append_module_param_if_missing "$params" "rx_worker_inject=1")"
  fi
  printf '%s\n' "$params"
}

append_module_param_if_missing() {
  local params="$1"
  local assignment="$2"
  local key="${assignment%%=*}"
  local field existing
  for field in $params; do
    existing="${field%%=*}"
    if [[ "$existing" == "$key" ]]; then
      printf '%s\n' "$params"
      return
    fi
  done
  if [[ -n "$params" ]]; then
    printf '%s %s\n' "$params" "$assignment"
  else
    printf '%s\n' "$assignment"
  fi
}

experimental_tcp_effective_skip_outer_checksum() {
  if experimental_tcp_route_tcp_kfunc_enabled; then
    printf '0\n'
    return
  fi
  printf '%s\n' "$experimental_tcp_skip_outer_checksum"
}

experimental_tcp_route_gso_pre_outer_inner_checksum() {
  if experimental_tcp_route_tcp_kfunc_enabled; then
    printf '0\n'
    return
  fi
  printf '%s\n' "${TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_PRE_OUTER_INNER_CHECKSUM:-}"
}

experimental_tcp_route_gso_outer_partial_checksum() {
  if experimental_tcp_route_tcp_kfunc_enabled; then
    printf '1\n'
    return
  fi
  printf '%s\n' "${TRUSTIX_EXPERIMENTAL_TCP_TC_TX_OUTER_TCP_HEADER_KFUNC_PARTIAL_CSUM:-0}"
}

experimental_tcp_kernel_udp_direct_only_value() {
  if [[ -n "${TRUSTIX_E2E_KERNEL_UDP_TC_TX_DIRECT_ONLY+x}" ]]; then
    printf '%s\n' "$TRUSTIX_E2E_KERNEL_UDP_TC_TX_DIRECT_ONLY"
    return
  fi
  if [[ -n "${TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY+x}" ]]; then
    printf '%s\n' "$TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY"
    return
  fi
  if [[ "$transport" == "experimental_tcp" ]] &&
    is_plaintext_encryption "$(effective_transport_encryption)" &&
    truthy "$experimental_tcp_tc_tx_direct_only"; then
    printf '1\n'
    return
  fi
  printf '\n'
}

kernel_udp_tc_tx_secure_direct_fix_inner_checksums_effective() {
  if [[ -n "${TRUSTIX_E2E_KERNEL_UDP_TC_TX_SECURE_DIRECT_FIX_INNER_CHECKSUMS+x}" ||
        -n "${TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_FIX_INNER_CHECKSUMS+x}" ]]; then
    printf '%s\n' "$kernel_udp_tc_tx_secure_direct_fix_inner_checksums"
    return
  fi
  if (kernel_udp_secure_direct_enabled || experimental_tcp_secure_direct_enabled) &&
      falsey "$kernel_udp_tc_tx_secure_direct_trust_inner_checksums"; then
    printf '1\n'
    return
  fi
  printf '%s\n' "$kernel_udp_tc_tx_secure_direct_fix_inner_checksums"
}

is_kernel_udp_transport() {
  [[ "$transport" == "kernel_udp" ]]
}

is_iptunnel_transport() {
  [[ "$transport" == "gre" || "$transport" == "ipip" || "$transport" == "vxlan" ]]
}

is_link_tls_transport() {
  [[ "$transport" == "tcp" || "$transport" == "quic" || "$transport" == "websocket" || "$transport" == "http_connect" ]]
}

is_tls_only() {
  [[ "$tls_only" == "1" ]]
}

effective_transport_encryption() {
  if is_tls_only; then
    printf 'plaintext\n'
    return
  fi
  printf '%s\n' "$transport_encryption"
}

is_plaintext_encryption() {
  case "$1" in
    plaintext|none|disabled|off) return 0 ;;
    *) return 1 ;;
  esac
}

transport_profile_is_performance() {
  case "$(printf '%s' "${transport_profile:-}" | tr '[:upper:]' '[:lower:]' | tr '-' '_')" in
    performance|perf|throughput|fast) return 0 ;;
    *) return 1 ;;
  esac
}

transport_datapath_is_userspace() {
  case "$(printf '%s' "${transport_datapath:-}" | tr '[:upper:]' '[:lower:]' | tr '-' '_')" in
    userspace|user|raw_socket|rawsocket) return 0 ;;
    *) return 1 ;;
  esac
}

experimental_tcp_profile_route_gso_default_enabled() {
  [[ "$transport" == "experimental_tcp" ]] || return 1
  transport_profile_is_performance || return 1
  transport_datapath_is_userspace && return 1
  is_plaintext_encryption "$(effective_transport_encryption)" || return 1
  [[ "$crypto_placement" == "auto" || "$crypto_placement" == "userspace" ]] || return 1
  return 0
}

apply_transport_profile_fastpath_defaults() {
  experimental_tcp_profile_route_gso_default_enabled || return 0

  if [[ -z "${TRUSTIX_E2E_EXPERIMENTAL_TCP_TC_TX_DIRECT+x}" && -z "${TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT+x}" ]]; then
    experimental_tcp_tc_tx_direct=1
  fi
  if [[ -z "${TRUSTIX_E2E_EXPERIMENTAL_TCP_TC_TX_DIRECT_ONLY+x}" && -z "${TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_ONLY+x}" ]]; then
    experimental_tcp_tc_tx_direct_only=1
  fi
  if [[ -z "${TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_GSO_SYNC+x}" && -z "${TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_KFUNC+x}" && -z "${TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_SYNC+x}" ]]; then
    experimental_tcp_route_gso_sync=1
  fi
  if [[ -z "${TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC+x}" && -z "${TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_ASYNC_KFUNC+x}" && -z "${TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_ASYNC+x}" ]]; then
    experimental_tcp_route_gso_async=1
  fi
  if [[ -z "${TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_DEV_XMIT+x}" && -z "${TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_DEV_XMIT+x}" ]]; then
    experimental_tcp_route_gso_async_dev_xmit=1
  fi
  if [[ -z "${TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_XMIT_WORKER+x}" && -z "${TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_XMIT_KFUNC+x}" ]]; then
    experimental_tcp_route_xmit_worker=1
  fi
  if [[ -z "${TRUSTIX_E2E_EXPERIMENTAL_TCP_PLAIN_SKIP_SEQUENCE+x}" && -z "${TRUSTIX_EXPERIMENTAL_TCP_TX_PLAIN_SKIP_SEQUENCE+x}" && -z "${TRUSTIX_TIXT_TX_PLAIN_SKIP_SEQUENCE+x}" ]]; then
    experimental_tcp_plain_skip_sequence=1
  fi
  if [[ -z "${TRUSTIX_E2E_EXPERIMENTAL_TCP_PLAIN_ACK_ONLY+x}" && -z "${TRUSTIX_EXPERIMENTAL_TCP_TX_PLAIN_ACK_ONLY+x}" && -z "${TRUSTIX_TIXT_TX_PLAIN_ACK_ONLY+x}" ]]; then
    experimental_tcp_plain_ack_only=1
  fi
  if [[ -z "${TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_LIMIT+x}" && -z "${TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_LIMIT+x}" ]]; then
    experimental_tcp_route_gso_async_limit=2048
  fi
  if [[ -z "${TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_WORKER_ITEM_BUDGET+x}" && -z "${TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_WORKER_ITEM_BUDGET+x}" ]]; then
    experimental_tcp_route_gso_async_worker_item_budget=64
  fi
  if [[ -z "${TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_WORKER_SEGMENT_BUDGET+x}" && -z "${TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_WORKER_SEGMENT_BUDGET+x}" ]]; then
    experimental_tcp_route_gso_async_worker_segment_budget=2048
  fi
  if [[ -z "${TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_MAX_SEGMENTS_PER_ITEM+x}" && -z "${TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_MAX_SEGMENTS_PER_ITEM+x}" ]]; then
    experimental_tcp_route_gso_async_max_segments_per_item=128
  fi
  if [[ -z "${TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_STREAM+x}" && -z "${TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_STREAM+x}" ]]; then
    experimental_tcp_route_gso_async_stream=1
  fi
  if [[ -z "${TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_STREAM_DIRECT_BUILD+x}" && -z "${TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_STREAM_DIRECT_BUILD+x}" ]]; then
    experimental_tcp_route_gso_async_stream_direct_build=1
  fi
  if [[ -z "${TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_STREAM_OUTER_GSO+x}" && -z "${TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_STREAM_OUTER_GSO+x}" ]]; then
    experimental_tcp_route_gso_async_stream_outer_gso=1
  fi
  if [[ -z "${TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_STREAM_MAX_FRAMES+x}" && -z "${TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_STREAM_MAX_FRAMES+x}" ]]; then
    experimental_tcp_route_gso_async_stream_max_frames=64
  fi
  if [[ -z "${TRUSTIX_E2E_DATAPATH_MODULE+x}" ]]; then
    datapath_module=1
  fi
}

append_endpoint_encryption_security() {
  local indent="$1"
  local encryption="$2"
  [[ -n "$encryption" ]] || return 0
  cat >>"$config_path" <<EOF
${indent}security:
${indent}  encryption: ${encryption}
EOF
}

choose_port() {
  local env_name="$1"
  local preferred="$2"
  local configured="${!env_name:-}"
  local port
  if [[ -n "$configured" ]]; then
    printf '%s\n' "$configured"
    return 0
  fi
  port="$(python3 - "$preferred" "$allocated_ports" <<'PY'
import socket
import sys

preferred = int(sys.argv[1])
used = {int(value) for value in sys.argv[2].split() if value}

def available(port):
    if port in used:
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

remember_port() {
  allocated_ports="${allocated_ports} $1"
}

allocate_ports() {
  api_a_port="$(choose_port TRUSTIX_E2E_API_A_PORT 18787)"
  remember_port "$api_a_port"
  api_b_port="$(choose_port TRUSTIX_E2E_API_B_PORT 18788)"
  remember_port "$api_b_port"
  peer_api_a_port="$(choose_port TRUSTIX_E2E_PEER_API_A_PORT 19443)"
  remember_port "$peer_api_a_port"
  peer_api_b_port="$(choose_port TRUSTIX_E2E_PEER_API_B_PORT 19444)"
  remember_port "$peer_api_b_port"
  udp_a_port="$(choose_port TRUSTIX_E2E_UDP_A_PORT 17001)"
  remember_port "$udp_a_port"
  udp_b_port="$(choose_port TRUSTIX_E2E_UDP_B_PORT 17002)"
  remember_port "$udp_b_port"
  tcp_a_port="$(choose_port TRUSTIX_E2E_TCP_A_PORT 17021)"
  remember_port "$tcp_a_port"
  tcp_b_port="$(choose_port TRUSTIX_E2E_TCP_B_PORT 17022)"
  remember_port "$tcp_b_port"
  exp_tcp_a_port="$(choose_port TRUSTIX_E2E_EXP_TCP_A_PORT 17041)"
  remember_port "$exp_tcp_a_port"
  exp_tcp_b_port="$(choose_port TRUSTIX_E2E_EXP_TCP_B_PORT 17042)"
  remember_port "$exp_tcp_b_port"
}

configure_addresses() {
  api_a="http://127.0.0.1:${api_a_port}"
  api_b="http://127.0.0.1:${api_b_port}"
  peer_api_a="127.0.0.1:${peer_api_a_port}"
  peer_api_b="127.0.0.1:${peer_api_b_port}"
  udp_a="127.0.0.1:${udp_a_port}"
  udp_b="127.0.0.1:${udp_b_port}"
  tcp_a="127.0.0.1:${tcp_a_port}"
  tcp_b="127.0.0.1:${tcp_b_port}"
  exp_tcp_a="127.0.0.1:${exp_tcp_a_port}"
  exp_tcp_b="127.0.0.1:${exp_tcp_b_port}"
  if is_af_xdp_transport; then
    router_netns=1
  fi
  if is_iptunnel_transport; then
    router_netns=1
  fi
  if [[ "$nat_reverse" == "1" ]]; then
    router_netns=1
  fi
  if [[ "$router_netns" == "1" ]]; then
    peer_api_a="${underlay_ip_a}:${peer_api_a_port}"
    peer_api_b="${underlay_ip_b}:${peer_api_b_port}"
    udp_a="${underlay_ip_a}:${udp_a_port}"
    udp_b="${underlay_ip_b}:${udp_b_port}"
    tcp_a="${underlay_ip_a}:${tcp_a_port}"
    tcp_b="${underlay_ip_b}:${tcp_b_port}"
    exp_tcp_a="${underlay_ip_a}:${exp_tcp_a_port}"
    exp_tcp_b="${underlay_ip_b}:${exp_tcp_b_port}"
  fi
  iptunnel_a="local=${underlay_ip_a},remote=${underlay_ip_b},local_carrier=10.255.30.1/30,remote_carrier=10.255.30.2,port=${iptunnel_port},mtu=${iptunnel_mtu}"
  iptunnel_b="local=${underlay_ip_b},remote=${underlay_ip_a},local_carrier=10.255.30.2/30,remote_carrier=10.255.30.1,port=${iptunnel_port},mtu=${iptunnel_mtu}"
}

run_in_netns() {
  local ns="$1"
  shift
  if [[ -n "$ns" ]]; then
    ip netns exec "$ns" "$@"
  else
    "$@"
  fi
}

run_iperf3_hook() {
  local hook="$1"
  local phase="$2"
  local src_ns="$3"
  local dst_ns="$4"
  local dst_ip="$5"
  local port="$6"
  local label="$7"
  [[ -n "$hook" ]] || return 0
  TRUSTIX_E2E_IPERF3_HOOK_PHASE="$phase" \
    TRUSTIX_E2E_IPERF3_HOOK_SRC_NS="$src_ns" \
    TRUSTIX_E2E_IPERF3_HOOK_DST_NS="$dst_ns" \
    TRUSTIX_E2E_IPERF3_HOOK_DST_IP="$dst_ip" \
    TRUSTIX_E2E_IPERF3_HOOK_PORT="$port" \
    TRUSTIX_E2E_IPERF3_HOOK_LABEL="$label" \
    TRUSTIX_E2E_IPERF3_HOOK_WORKDIR="$workdir" \
    bash -c "$hook"
}

run_iperf3_post_hook_if_armed() {
  local src_ns="$1"
  local dst_ns="$2"
  local dst_ip="$3"
  local port="$4"
  local label="$5"
  if [[ "$iperf3_post_hook_armed" == "1" ]]; then
    iperf3_post_hook_armed=0
    run_iperf3_hook "$iperf3_post_hook" post "$src_ns" "$dst_ns" "$dst_ip" "$port" "$label" || true
  fi
}

run_ctl() {
  local ns="$1"
  shift
  run_in_netns "$ns" timeout --foreground "$trustixctl_timeout" "$bin_dir/trustixctl" "$@"
}

perf_fast_enabled() {
  case "$perf_fast" in
    1|true|yes|on|enabled) return 0 ;;
    *) return 1 ;;
  esac
}

direct_management_vip_enabled() {
  case "$direct_management_vip" in
    1|true|yes|on|enabled) return 0 ;;
    0|false|no|off|disabled) return 1 ;;
    auto)
      [[ "$router_netns" != "1" ]]
      return
      ;;
    *) die "TRUSTIX_E2E_DIRECT_MANAGEMENT_VIP must be auto, 1, or 0" ;;
  esac
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
  sleep 1
  pids="$(ps -eo pid=,comm=,args= | awk -v wd="$workdir" '$2 == "trustixd" && index($0, wd) { print $1 }')"
  printf '%s\n' "$pids" | while read -r pid; do
    [[ -n "$pid" ]] || continue
    kill -9 "$pid" >/dev/null 2>&1 || true
  done
}

cleanup_iptunnel_links_in_ns() {
  local ns="$1"
  [[ -n "$ns" ]] || return 0
  ip netns exec "$ns" sh -c 'for path in /sys/class/net/tixgr* /sys/class/net/tixip* /sys/class/net/tixvx*; do [ -e "$path" ] || continue; ip link del "$(basename "$path")" 2>/dev/null || true; done' >/dev/null 2>&1 || true
}

cleanup_netdev_dataplane_state_in_ns() {
  local ns="$1"
  shift
  local dev
  for dev in "$@"; do
    [[ -n "$dev" ]] || continue
    run_in_netns "$ns" sh -c '
      dev="$1"
      ip link show dev "$dev" >/dev/null 2>&1 || exit 0
      tc qdisc del dev "$dev" clsact >/dev/null 2>&1 || true
      ip link set dev "$dev" xdp off >/dev/null 2>&1 || true
      ip link set dev "$dev" xdpgeneric off >/dev/null 2>&1 || true
    ' sh "$dev" >/dev/null 2>&1 || true
  done
}

cleanup_topology_dataplane_state() {
  if [[ "$router_netns" == "1" ]]; then
    cleanup_netdev_dataplane_state_in_ns "$ns_ix_a" "$lan_a" "$underlay_a"
    cleanup_netdev_dataplane_state_in_ns "$ns_ix_b" "$lan_b" "$underlay_b"
  else
    cleanup_netdev_dataplane_state_in_ns "" "$lan_a" "$lan_b"
  fi
}

trustixd_pids_for_data_dir() {
  local data_dir="$1"
  ps -eo pid=,comm=,args= | awk -v dd="$data_dir" '$2 == "trustixd" && index($0, "-data-dir " dd) { print $1 }'
}

wait_for_pids_gone() {
  local pids="$1"
  local pid
  local alive
  [[ -n "$pids" ]] || return 0
  for _ in $(seq 1 50); do
    alive=0
    for pid in $pids; do
      if kill -0 "$pid" >/dev/null 2>&1; then
        alive=1
      fi
    done
    [[ "$alive" == "0" ]] && return 0
    sleep 0.1
  done
  return 1
}

cleanup() {
  local exit_code=$?
  set +e
  stop_daemon_pid "$pid_a"
  stop_daemon_pid "$pid_b"
  stop_daemons_by_workdir
  cleanup_topology_dataplane_state
  cleanup_iptunnel_links_in_ns "$ns_ix_a"
  cleanup_iptunnel_links_in_ns "$ns_ix_b"
  if [[ "$keep" != "1" ]]; then
    ip netns del "$ns_ix_a" >/dev/null 2>&1
    ip netns del "$ns_ix_b" >/dev/null 2>&1
    ip netns del "$ns_a" >/dev/null 2>&1
    ip netns del "$ns_b" >/dev/null 2>&1
    ip link del "$lan_a" >/dev/null 2>&1
    ip link del "$lan_b" >/dev/null 2>&1
    ip link del "$underlay_a" >/dev/null 2>&1
    ip link del "$underlay_b" >/dev/null 2>&1
  fi
  if [[ "$success" == "1" && "$keep" != "1" && -z "${TRUSTIX_E2E_WORKDIR:-}" ]]; then
    rm -rf "$workdir"
  else
    log "workdir preserved: $workdir"
  fi
  exit "$exit_code"
}
trap cleanup EXIT

require_linux_root() {
  [[ "$(uname -s)" == "Linux" ]] || die "linux-e2e-smoke must run on Linux"
  [[ "${EUID:-$(id -u)}" == "0" ]] || die "linux-e2e-smoke must run as root for netns, TC/eBPF, and AF_PACKET"
}

clean_previous_topology() {
  cleanup_topology_dataplane_state
  ip netns del "$ns_ix_a" >/dev/null 2>&1 || true
  ip netns del "$ns_ix_b" >/dev/null 2>&1 || true
  ip netns del "$ns_a" >/dev/null 2>&1 || true
  ip netns del "$ns_b" >/dev/null 2>&1 || true
  ip link del "$lan_a" >/dev/null 2>&1 || true
  ip link del "$lan_b" >/dev/null 2>&1 || true
  ip link del "$underlay_a" >/dev/null 2>&1 || true
  ip link del "$underlay_b" >/dev/null 2>&1 || true
}

setup_topology() {
  if [[ "$router_netns" == "1" ]]; then
    setup_router_netns_topology
  else
    setup_root_topology
  fi
}

disable_offloads_in_netns() {
  local ns="$1"
  local iface="$2"
  [[ -n "$iface" ]] || return 0
  if ! effective_disable_veth_offloads; then
    return 0
  fi
  if [[ -n "$ns" ]]; then
    ip netns exec "$ns" ethtool -K "$iface" rx off tx off sg off tso off ufo off gso off gro off lro off >/dev/null 2>&1 || true
  else
    ethtool -K "$iface" rx off tx off sg off tso off ufo off gso off gro off lro off >/dev/null 2>&1 || true
  fi
}

disable_topology_offloads() {
  if ! effective_disable_veth_offloads; then
    return 0
  fi
  log "disabling veth offloads where supported"
  if [[ "$router_netns" == "1" ]]; then
    disable_offloads_in_netns "$ns_ix_a" "$lan_a"
    disable_offloads_in_netns "$ns_ix_b" "$lan_b"
    disable_offloads_in_netns "$ns_a" "$host_a"
    disable_offloads_in_netns "$ns_b" "$host_b"
    disable_offloads_in_netns "$ns_ix_a" "$underlay_a"
    disable_offloads_in_netns "$ns_ix_b" "$underlay_b"
  else
    disable_offloads_in_netns "" "$lan_a"
    disable_offloads_in_netns "" "$lan_b"
    disable_offloads_in_netns "$ns_a" "$host_a"
    disable_offloads_in_netns "$ns_b" "$host_b"
  fi
}

setup_root_topology() {
  log "creating LAN namespaces and veth pairs"
  clean_previous_topology
  ip netns add "$ns_a"
  ip netns add "$ns_b"
  ip link add "$lan_a" numtxqueues "$af_xdp_queues" numrxqueues "$af_xdp_queues" type veth peer name "$host_a" numtxqueues "$af_xdp_queues" numrxqueues "$af_xdp_queues"
  ip link add "$lan_b" numtxqueues "$af_xdp_queues" numrxqueues "$af_xdp_queues" type veth peer name "$host_b" numtxqueues "$af_xdp_queues" numrxqueues "$af_xdp_queues"
  ip link set "$host_a" netns "$ns_a"
  ip link set "$host_b" netns "$ns_b"
  ip link set "$lan_a" mtu "$lan_mtu"
  ip link set "$lan_b" mtu "$lan_mtu"
  ip netns exec "$ns_a" ip link set "$host_a" mtu "$lan_mtu"
  ip netns exec "$ns_b" ip link set "$host_b" mtu "$lan_mtu"
  ip link set "$lan_a" up
  ip link set "$lan_b" up
  ip netns exec "$ns_a" ip link set lo up
  ip netns exec "$ns_b" ip link set lo up
  ip netns exec "$ns_a" ip link set "$host_a" up
  ip netns exec "$ns_b" ip link set "$host_b" up
  ip netns exec "$ns_a" ip addr add 10.0.0.2/24 dev "$host_a"
  ip netns exec "$ns_b" ip addr add 10.0.1.2/24 dev "$host_b"
  ip netns exec "$ns_a" ip route replace default via 10.0.0.1
  ip netns exec "$ns_b" ip route replace default via 10.0.1.1
  disable_topology_offloads
}

setup_router_netns_topology() {
  log "creating IX router namespaces, LAN namespaces, and underlay veth pairs"
  clean_previous_topology
  ip netns add "$ns_ix_a"
  ip netns add "$ns_ix_b"
  ip netns add "$ns_a"
  ip netns add "$ns_b"

  ip link add "$lan_a" numtxqueues "$af_xdp_queues" numrxqueues "$af_xdp_queues" type veth peer name "$host_a" numtxqueues "$af_xdp_queues" numrxqueues "$af_xdp_queues"
  ip link add "$lan_b" numtxqueues "$af_xdp_queues" numrxqueues "$af_xdp_queues" type veth peer name "$host_b" numtxqueues "$af_xdp_queues" numrxqueues "$af_xdp_queues"
  ip link set "$lan_a" netns "$ns_ix_a"
  ip link set "$lan_b" netns "$ns_ix_b"
  ip link set "$host_a" netns "$ns_a"
  ip link set "$host_b" netns "$ns_b"

  ip link add "$underlay_a" numtxqueues "$af_xdp_queues" numrxqueues "$af_xdp_queues" type veth peer name "$underlay_b" numtxqueues "$af_xdp_queues" numrxqueues "$af_xdp_queues"
  ip link set "$underlay_a" netns "$ns_ix_a"
  ip link set "$underlay_b" netns "$ns_ix_b"

  for ns in "$ns_ix_a" "$ns_ix_b" "$ns_a" "$ns_b"; do
    ip netns exec "$ns" ip link set lo up
  done

  ip netns exec "$ns_ix_a" ip link set "$lan_a" mtu "$lan_mtu"
  ip netns exec "$ns_ix_b" ip link set "$lan_b" mtu "$lan_mtu"
  ip netns exec "$ns_a" ip link set "$host_a" mtu "$lan_mtu"
  ip netns exec "$ns_b" ip link set "$host_b" mtu "$lan_mtu"
  ip netns exec "$ns_ix_a" ip link set "$lan_a" up
  ip netns exec "$ns_ix_b" ip link set "$lan_b" up
  ip netns exec "$ns_ix_a" ip link set "$underlay_a" mtu "$underlay_mtu"
  ip netns exec "$ns_ix_b" ip link set "$underlay_b" mtu "$underlay_mtu"
  ip netns exec "$ns_ix_a" ip link set "$underlay_a" up
  ip netns exec "$ns_ix_b" ip link set "$underlay_b" up
  ip netns exec "$ns_a" ip link set "$host_a" up
  ip netns exec "$ns_b" ip link set "$host_b" up

  ip netns exec "$ns_ix_a" ip addr add "$underlay_cidr_a" dev "$underlay_a"
  ip netns exec "$ns_ix_b" ip addr add "$underlay_cidr_b" dev "$underlay_b"
  ip netns exec "$ns_a" ip addr add 10.0.0.2/24 dev "$host_a"
  ip netns exec "$ns_b" ip addr add 10.0.1.2/24 dev "$host_b"
  ip netns exec "$ns_a" ip route replace default via 10.0.0.1
  ip netns exec "$ns_b" ip route replace default via 10.0.1.1
  disable_topology_offloads
}

generate_config() {
  local node="$1"
  local peer="$2"
  local local_lan="$3"
  local local_gateway="$4"
  local remote_lan="$5"
  local local_iface="$6"
  local local_udp="$7"
  local remote_udp="$8"
  local local_tcp="$9"
  local remote_tcp="${10}"
  local local_exp_tcp="${11}"
  local remote_exp_tcp="${12}"
  local local_tunnel="${13}"
  local remote_tunnel="${14}"
  local local_control="${15}"
  local remote_control="${16}"
  local local_api="${17}"
  local remote_endpoint_name="${18}"
  local local_endpoint_name="${19}"
  local remote_exp_name="${20}"
  local local_exp_name="${21}"
  local local_underlay_iface="${22:-}"
  local config_path="$workdir/config-${node}.yaml"
  local certs="$workdir/certs"
  local route_endpoint="$remote_endpoint_name"
  local transport_candidate="$local_endpoint_name"
  local remote_tcp_name="${remote_endpoint_name%-udp}-tcp"
  local local_tcp_name="${local_endpoint_name%-udp}-tcp"
  local remote_link_tls_name="${remote_endpoint_name%-udp}-${transport}"
  local local_link_tls_name="${local_endpoint_name%-udp}-${transport}"
  local remote_tunnel_name="${remote_endpoint_name%-udp}-${transport}"
  local local_tunnel_name="${local_endpoint_name%-udp}-${transport}"
  local underlay_yaml=""
  local local_address="$local_udp"
  local remote_address="$remote_udp"
  local policy_encryption endpoint_encryption=""
  policy_encryption="$(effective_transport_encryption)"
  if is_plaintext_encryption "$policy_encryption"; then
    endpoint_encryption="plaintext"
  fi

  if [[ "$transport" == "tcp" ]]; then
    route_endpoint="$remote_tcp_name"
    transport_candidate="$local_tcp_name"
    local_address="$local_tcp"
    remote_address="$remote_tcp"
  elif [[ "$transport" == "quic" || "$transport" == "websocket" || "$transport" == "http_connect" ]]; then
    route_endpoint="$remote_link_tls_name"
    transport_candidate="$local_link_tls_name"
    local_address="$local_tcp"
    remote_address="$remote_tcp"
  elif [[ "$transport" == "experimental_tcp" ]]; then
    route_endpoint="$remote_exp_name"
    transport_candidate="$local_exp_name"
    local_address="$local_exp_tcp"
    remote_address="$remote_exp_tcp"
    if [[ -z "$local_underlay_iface" ]]; then
      die "experimental_tcp requires a local underlay iface for ${node}"
    fi
    underlay_yaml="  underlay_iface: ${local_underlay_iface}"
  elif is_kernel_udp_transport; then
    if [[ -z "$local_underlay_iface" ]]; then
      die "kernel_udp requires a local underlay iface for ${node}"
    fi
    underlay_yaml="  underlay_iface: ${local_underlay_iface}"
  elif is_iptunnel_transport; then
    route_endpoint="$remote_tunnel_name"
    transport_candidate="$local_tunnel_name"
    local_address="$local_tunnel"
    remote_address="$local_tunnel"
    if [[ -z "$local_underlay_iface" ]]; then
      die "${transport} requires a local underlay iface for ${node}"
    fi
    if [[ -z "$local_tunnel" || -z "$remote_tunnel" ]]; then
      die "${transport} requires local and remote tunnel endpoint configs for ${node}"
    fi
    underlay_yaml="  underlay_iface: ${local_underlay_iface}"
  fi

  if [[ "$nat_reverse" == "1" ]]; then
    if [[ "$node" == "ix-b" ]]; then
      local_address=""
    fi
    if [[ "$peer" == "ix-b" ]]; then
      remote_address=""
      route_endpoint=""
    fi
  fi

  cat >"$config_path" <<EOF
domain:
  id: lab.local
  trust_roots:
    - ${certs}/root-ca.pem
    - ${certs}/domain-ca.pem
    - ${certs}/config-ca.pem

ix:
  id: ${node}
  domain: lab.local
  cert: ${certs}/${node}.crt
  key: ${certs}/${node}.key
  control_api: https://${local_control}
  route_authorizations:
    - ${certs}/${node}-route.crt

lan:
  iface: ${local_iface}
${underlay_yaml}
  gateway: ${local_gateway}
  advertise:
    - ${local_lan}
  mode: ${lan_mode}
  manage_address: true
  manage_forwarding: ${manage_forwarding}
  manage_rp_filter: true

management:
  host_api:
    enabled: true
    require_read_auth: true

endpoints:
EOF

  case "$transport" in
    udp)
      cat >>"$config_path" <<EOF
  - name: ${local_endpoint_name}
    mode: passive
    listen: ${local_udp}
EOF
      if [[ -n "$local_address" ]]; then
        cat >>"$config_path" <<EOF
    address: ${local_address}
EOF
      fi
      cat >>"$config_path" <<EOF
    transport: udp
EOF
      append_endpoint_encryption_security "    " "$endpoint_encryption"
      cat >>"$config_path" <<EOF
    enabled: true
EOF
      ;;
    kernel_udp)
      cat >>"$config_path" <<EOF
  - name: ${local_endpoint_name}
    mode: passive
    listen: ${local_udp}
EOF
      if [[ -n "$local_address" ]]; then
        cat >>"$config_path" <<EOF
    address: ${local_address}
EOF
      fi
      cat >>"$config_path" <<EOF
    transport: udp
EOF
      append_endpoint_encryption_security "    " "$endpoint_encryption"
      cat >>"$config_path" <<EOF
    enabled: true
EOF
      ;;
    tcp)
      cat >>"$config_path" <<EOF
  - name: ${local_tcp_name}
    mode: passive
    listen: ${local_tcp}
EOF
      if [[ -n "$local_address" ]]; then
        cat >>"$config_path" <<EOF
    address: ${local_address}
EOF
      fi
      cat >>"$config_path" <<EOF
    transport: tcp
    security:
      link_tls: required
EOF
      if [[ -n "$endpoint_encryption" ]]; then
        cat >>"$config_path" <<EOF
      encryption: ${endpoint_encryption}
EOF
      fi
      cat >>"$config_path" <<EOF
    enabled: true
EOF
      ;;
    quic|websocket|http_connect)
      cat >>"$config_path" <<EOF
  - name: ${local_link_tls_name}
    mode: passive
    listen: ${local_tcp}
EOF
      if [[ -n "$local_address" ]]; then
        cat >>"$config_path" <<EOF
    address: ${local_address}
EOF
      fi
      cat >>"$config_path" <<EOF
    transport: ${transport}
    security:
      link_tls: required
EOF
      if [[ -n "$endpoint_encryption" ]]; then
        cat >>"$config_path" <<EOF
      encryption: ${endpoint_encryption}
EOF
      fi
      cat >>"$config_path" <<EOF
    enabled: true
EOF
      ;;
    experimental_tcp)
      cat >>"$config_path" <<EOF
  - name: ${local_exp_name}
    mode: passive
    listen: ${local_exp_tcp}
EOF
      if [[ -n "$local_address" ]]; then
        cat >>"$config_path" <<EOF
    address: ${local_address}
EOF
      fi
      cat >>"$config_path" <<EOF
    transport: experimental_tcp
EOF
      append_endpoint_encryption_security "    " "$endpoint_encryption"
      cat >>"$config_path" <<EOF
    enabled: true
EOF
      ;;
    gre|ipip|vxlan)
      cat >>"$config_path" <<EOF
  - name: ${local_tunnel_name}
    mode: passive
    listen: ${local_tunnel}
EOF
      if [[ -n "$local_address" ]]; then
        cat >>"$config_path" <<EOF
    address: ${local_address}
EOF
      fi
      cat >>"$config_path" <<EOF
    transport: ${transport}
    enabled: true
EOF
      ;;
  esac

  cat >>"$config_path" <<EOF
peers:
  - id: ${peer}
    domain: lab.local
    control_api: https://${remote_control}
    endpoints:
EOF

  case "$transport" in
    udp|kernel_udp)
      cat >>"$config_path" <<EOF
      - name: ${remote_endpoint_name}
EOF
      if [[ -n "$remote_address" ]]; then
        cat >>"$config_path" <<EOF
        address: ${remote_address}
EOF
      else
        cat >>"$config_path" <<EOF
        mode: passive
EOF
      fi
      cat >>"$config_path" <<EOF
        transport: udp
EOF
      append_endpoint_encryption_security "        " "$endpoint_encryption"
      cat >>"$config_path" <<EOF
        enabled: true
EOF
      ;;
    tcp)
      cat >>"$config_path" <<EOF
      - name: ${remote_tcp_name}
EOF
      if [[ -n "$remote_address" ]]; then
        cat >>"$config_path" <<EOF
        address: ${remote_address}
EOF
      else
        cat >>"$config_path" <<EOF
        mode: passive
EOF
      fi
      cat >>"$config_path" <<EOF
        transport: tcp
        security:
          link_tls: required
EOF
      if [[ -n "$endpoint_encryption" ]]; then
        cat >>"$config_path" <<EOF
          encryption: ${endpoint_encryption}
EOF
      fi
      cat >>"$config_path" <<EOF
        enabled: true
EOF
      ;;
    quic|websocket|http_connect)
      cat >>"$config_path" <<EOF
      - name: ${remote_link_tls_name}
EOF
      if [[ -n "$remote_address" ]]; then
        cat >>"$config_path" <<EOF
        address: ${remote_address}
EOF
      else
        cat >>"$config_path" <<EOF
        mode: passive
EOF
      fi
      cat >>"$config_path" <<EOF
        transport: ${transport}
        security:
          link_tls: required
EOF
      if [[ -n "$endpoint_encryption" ]]; then
        cat >>"$config_path" <<EOF
          encryption: ${endpoint_encryption}
EOF
      fi
      cat >>"$config_path" <<EOF
        enabled: true
EOF
      ;;
    experimental_tcp)
      cat >>"$config_path" <<EOF
      - name: ${remote_exp_name}
EOF
      if [[ -n "$remote_address" ]]; then
        cat >>"$config_path" <<EOF
        address: ${remote_address}
EOF
      else
        cat >>"$config_path" <<EOF
        mode: passive
EOF
      fi
      cat >>"$config_path" <<EOF
        transport: experimental_tcp
EOF
      append_endpoint_encryption_security "        " "$endpoint_encryption"
      cat >>"$config_path" <<EOF
        enabled: true
EOF
      ;;
    gre|ipip|vxlan)
      cat >>"$config_path" <<EOF
      - name: ${remote_tunnel_name}
        address: ${local_tunnel}
        transport: ${transport}
EOF
      ;;
  esac

  cat >>"$config_path" <<EOF
    allowed_prefixes:
      - ${remote_lan}

routes:
  - prefix: ${remote_lan}
    next_hop: ${peer}
    endpoint: ${route_endpoint}
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
  profile: ${transport_profile}
  datapath: ${transport_datapath}
  mtu: ${underlay_mtu}
  candidates:
    - ${transport_candidate}
  failover: health_based
  load_balance: least_conn
EOF

  if [[ "$session_pool_size" != "0" ]]; then
    cat >>"$config_path" <<EOF
  session_pool:
    size: ${session_pool_size}
    strategy: ${session_pool_strategy}
    warmup: ${session_pool_warmup}
EOF
  fi

  if is_kernel_udp_transport || is_iptunnel_transport || experimental_tcp_direct_enabled || kernel_plaintext_direct_fastpath_enabled; then
    cat >>"$config_path" <<EOF
  kernel_transport:
    mode: require_kernel
EOF
  fi

  if is_link_tls_transport; then
    cat >>"$config_path" <<EOF
  crypto_key_source: tls_exporter
EOF
    cat >>"$config_path" <<EOF
  tls_identity:
    mode: custom_cert
    cert: ${certs}/${node}-transport.crt
    key: ${certs}/${node}-transport.key
    trust_roots:
      - ${certs}/domain-ca.pem
EOF
  fi

  if [[ -n "$policy_encryption" ]]; then
    cat >>"$config_path" <<EOF
  encryption: ${policy_encryption}
EOF
  fi

  cat >>"$config_path" <<EOF
  crypto_placement: ${crypto_placement}
EOF

  printf '%s\n' "$config_path"
  log "${node} config: ${config_path} api=${local_api}"
}

build_binaries() {
  if [[ -n "${TRUSTIX_E2E_BIN_DIR:-}" ]]; then
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
  log "generating quickstart certificates"
  mkdir -p "$workdir/certs"
  "$bin_dir/trustix-ca" quickstart -out "$workdir/certs" -domain lab.local -ix ix-a,ix-b >/dev/null
  if is_link_tls_transport; then
    log "generating custom transport TLS certificates"
    "$bin_dir/trustix-ca" ix issue -out "$workdir/certs" -domain lab.local -ix ix-a-transport -ip "${tcp_a%:*}" -ca-cert "$workdir/certs/domain-ca.pem" -ca-key "$workdir/certs/domain-ca.key" >/dev/null
    "$bin_dir/trustix-ca" ix issue -out "$workdir/certs" -domain lab.local -ix ix-b-transport -ip "${tcp_b%:*}" -ca-cert "$workdir/certs/domain-ca.pem" -ca-key "$workdir/certs/domain-ca.key" >/dev/null
  fi
}

start_daemon() {
  local node="$1"
  local config_path="$2"
  local data_dir="$3"
  local api_addr="$4"
  local peer_api_addr="$5"
  local ns="${6:-}"
  shift 6 || true
  local extra_args="$*"
  local log_path="$workdir/${node}.log"
  local node_profile_dir=""
  if [[ -n "$cpu_profile_dir" ]]; then
    node_profile_dir="${cpu_profile_dir}/${node}"
    mkdir -p "$node_profile_dir"
  fi

  mkdir -p "$data_dir"
  log "starting ${node}"
  if is_af_xdp_transport; then
    run_in_netns "$ns" env "TRUSTIX_CPU_PROFILE_DIR=${node_profile_dir}" "TRUSTIX_TC_HOT_STATS=${hot_stats}" "TRUSTIX_NATIVE_TUNNEL_ROUTE_OFFLOAD=${TRUSTIX_NATIVE_TUNNEL_ROUTE_OFFLOAD:-1}" "TRUSTIX_NATIVE_TUNNEL_AUTO_TCP_MSS_CLAMP=${TRUSTIX_NATIVE_TUNNEL_AUTO_TCP_MSS_CLAMP:-0}" "TRUSTIX_KERNEL_DATAPATH_RX_WORKER=$(full_datapath_rx_worker_value)" "TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_RX_WORKER=$(full_datapath_rx_worker_value)" "TRUSTIX_AF_XDP_QUEUES=${af_xdp_queues}" "TRUSTIX_XDP_MODE=${xdp_mode}" "TRUSTIX_AF_XDP_BIND_MODE=${af_xdp_bind_mode}" "TRUSTIX_AF_XDP_NEED_WAKEUP=${af_xdp_need_wakeup}" "TRUSTIX_AF_XDP_TX_BACKPRESSURE_WAIT=${af_xdp_tx_backpressure_wait}" "TRUSTIX_AF_XDP_TX_KICK_BATCH=${af_xdp_tx_kick_batch}" "TRUSTIX_AF_XDP_TX_FLUSH_INTERVAL=${af_xdp_tx_flush_interval}" "TRUSTIX_AF_XDP_TX_SOFT_KICK_BACKOFF=${af_xdp_tx_soft_kick_backoff}" "TRUSTIX_AF_XDP_TX_DEFER_FLUSH=${af_xdp_tx_defer_flush}" "TRUSTIX_AF_XDP_TX_DEFER_FLUSH_DELAY=${af_xdp_tx_defer_flush_delay}" "TRUSTIX_AF_XDP_TX_COALESCE_COPY_MODE=${af_xdp_tx_coalesce_copy_mode}" "TRUSTIX_AF_XDP_RX_BURST=${af_xdp_rx_burst}" "TRUSTIX_AF_XDP_RING_ENTRIES=${af_xdp_ring_entries}" "TRUSTIX_AF_XDP_UMEM_FRAMES=${af_xdp_umem_frames}" "TRUSTIX_AF_XDP_UMEM_FRAME_SIZE=${af_xdp_umem_frame_size}" "TRUSTIX_AF_XDP_AUTO_UMEM_JUMBO=${experimental_tcp_auto_umem_jumbo}" "TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT=${experimental_tcp_tc_tx_direct}" "TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_ONLY=${experimental_tcp_tc_tx_direct_only}" "TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY=$(experimental_tcp_kernel_udp_direct_only_value)" "TRUSTIX_EXPERIMENTAL_TCP_SKIP_TCP_CHECKSUM=${experimental_tcp_skip_checksum}" "TRUSTIX_EXPERIMENTAL_TCP_SKIP_OUTER_TCP_CHECKSUM=$(experimental_tcp_effective_skip_outer_checksum)" "TRUSTIX_EXPERIMENTAL_TCP_TC_TX_PUSH_ROUTE_TCP_HEADER_KFUNC=$(experimental_tcp_route_header_kfunc_enabled && printf 1 || printf 0)" "TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_KFUNC=$(experimental_tcp_route_tcp_kfunc_value)" "TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_ASYNC_KFUNC=${experimental_tcp_route_gso_async}" "TRUSTIX_EXPERIMENTAL_TCP_ALLOW_CRASH_RISK_ROUTE_TCP_GSO_ASYNC=0" "TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_XMIT_KFUNC=${experimental_tcp_route_xmit_worker}" "TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_XMIT_STEAL=${experimental_tcp_route_xmit_worker_steal}" "TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_PRE_OUTER_INNER_CHECKSUM=$(experimental_tcp_route_gso_pre_outer_inner_checksum)" "TRUSTIX_EXPERIMENTAL_TCP_TC_TX_OUTER_TCP_HEADER_KFUNC_PARTIAL_CSUM=$(experimental_tcp_route_gso_outer_partial_checksum)" "TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_TRUST_PARTIAL_INNER_CHECKSUM=${experimental_tcp_route_gso_trust_partial_inner_checksum}" "TRUSTIX_EXPERIMENTAL_TCP_TX_PLAIN_SKIP_SEQUENCE=${experimental_tcp_plain_skip_sequence}" "TRUSTIX_EXPERIMENTAL_TCP_TX_PLAIN_ACK_ONLY=${experimental_tcp_plain_ack_only}" "TRUSTIX_KERNEL_UDP_SESSION_BUFFER=${kernel_udp_session_buffer}" "TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT=${TRUSTIX_E2E_KERNEL_UDP_TC_TX_SECURE_DIRECT:-0}" "TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_TRUST_INNER_CHECKSUMS=${kernel_udp_tc_tx_secure_direct_trust_inner_checksums}" "TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_FIX_INNER_CHECKSUMS=$(kernel_udp_tc_tx_secure_direct_fix_inner_checksums_effective)" "TRUSTIX_TRUST_CAPTURED_CHECKSUMS=${TRUSTIX_E2E_TRUST_CAPTURED_CHECKSUMS:-${TRUSTIX_TRUST_CAPTURED_CHECKSUMS:-0}}" "TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_KFUNC_SEAL=${kernel_udp_tc_tx_secure_direct_kfunc_seal}" "TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_SKB_SEAL_KFUNC=${kernel_udp_tc_tx_secure_direct_skb_seal_kfunc}" "TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_OUTER_TCP_CHECKSUM_KFUNC=${kernel_udp_tc_tx_secure_direct_outer_tcp_checksum_kfunc}" "TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_OUTER_TCP_PARTIAL_CHECKSUM_KFUNC=${kernel_udp_tc_tx_secure_direct_outer_tcp_partial_checksum_kfunc}" "TRUSTIX_KERNEL_UDP_TC_RX_SECURE_DIRECT=${kernel_udp_tc_rx_secure_direct}" "TRUSTIX_KERNEL_UDP_TC_RX_SECURE_DIRECT_KFUNC_OPEN=${kernel_udp_tc_rx_secure_direct_kfunc_open}" "TRUSTIX_KERNEL_UDP_TC_RX_SECURE_DIRECT_SKB_OPEN_KFUNC=${kernel_udp_tc_rx_secure_direct_skb_open_kfunc}" "TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_NO_CSUM_RESET=${kernel_udp_tc_adj_room_no_csum_reset}" "TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_TUNNEL_GSO=${kernel_udp_tc_adj_room_tunnel_gso}" "TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_ENCAP_L2_LEN=${kernel_udp_tc_adj_room_encap_l2_len}" "TRUSTIX_KERNEL_UDP_TC_DIRECT_ACTIVE_GSO=${kernel_udp_tc_direct_active_gso}" "TRUSTIX_KERNEL_UDP_SEAL_BEFORE_FRAGMENT=${TRUSTIX_E2E_KERNEL_UDP_SEAL_BEFORE_FRAGMENT:-1}" "TRUSTIX_KERNEL_UDP_XDP_OPEN=${kernel_udp_xdp_open}" "TRUSTIX_KERNEL_UDP_XDP_PASS_OPENED=${kernel_udp_xdp_pass_opened}" "TRUSTIX_KERNEL_UDP_XDP_RX_DIRECT=${kernel_udp_xdp_rx_direct}" "TRUSTIX_KERNEL_UDP_XDP_RX_SECURE_DIRECT=${kernel_udp_xdp_rx_secure_direct}" "TRUSTIX_KERNEL_UDP_XDP_RX_DIRECT_IFINDEX=${kernel_udp_xdp_rx_direct_ifindex}" "TRUSTIX_KERNEL_UDP_XDP_RX_DIRECT_MODE=${kernel_udp_xdp_rx_direct_mode}" "TRUSTIX_CAPTURE_FORWARDER_WORKERS=${capture_forwarder_workers}" "TRUSTIX_CAPTURE_FORWARDER_BUFFER=${capture_forwarder_buffer}" "TRUSTIX_CAPTURE_FORWARDER_BATCH=${capture_forwarder_batch}" "TRUSTIX_CAPTURE_FORWARDER_BATCH_DELAY=${capture_forwarder_batch_delay}" "TRUSTIX_DATA_SESSION_ENCRYPTED_TIXB=${data_session_encrypted_tixb}" "TRUSTIX_DATA_SESSION_RX_GSO_COALESCE_USERSPACE_ENCRYPTED=${data_session_rx_gso_coalesce_userspace_encrypted}" "$bin_dir/trustixd" \
      -config "$config_path" \
      -data-dir "$data_dir" \
      -api "$api_addr" \
      -peer-api "$peer_api_addr" \
      -dataplane "$dataplane" \
      $extra_args \
      >"$log_path" 2>&1 &
  else
    run_in_netns "$ns" env "TRUSTIX_CPU_PROFILE_DIR=${node_profile_dir}" "TRUSTIX_TC_HOT_STATS=${hot_stats}" "TRUSTIX_NATIVE_TUNNEL_ROUTE_OFFLOAD=${TRUSTIX_NATIVE_TUNNEL_ROUTE_OFFLOAD:-1}" "TRUSTIX_NATIVE_TUNNEL_AUTO_TCP_MSS_CLAMP=${TRUSTIX_NATIVE_TUNNEL_AUTO_TCP_MSS_CLAMP:-0}" "TRUSTIX_KERNEL_DATAPATH_RX_WORKER=$(full_datapath_rx_worker_value)" "TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_RX_WORKER=$(full_datapath_rx_worker_value)" "TRUSTIX_CAPTURE_FORWARDER_WORKERS=${capture_forwarder_workers}" "TRUSTIX_CAPTURE_FORWARDER_BUFFER=${capture_forwarder_buffer}" "TRUSTIX_CAPTURE_FORWARDER_BATCH=${capture_forwarder_batch}" "TRUSTIX_CAPTURE_FORWARDER_BATCH_DELAY=${capture_forwarder_batch_delay}" "TRUSTIX_DATA_SESSION_ENCRYPTED_TIXB=${data_session_encrypted_tixb}" "TRUSTIX_DATA_SESSION_RX_GSO_COALESCE_USERSPACE_ENCRYPTED=${data_session_rx_gso_coalesce_userspace_encrypted}" "$bin_dir/trustixd" \
      -config "$config_path" \
      -data-dir "$data_dir" \
      -api "$api_addr" \
      -peer-api "$peer_api_addr" \
      -dataplane "$dataplane" \
      $extra_args \
      >"$log_path" 2>&1 &
  fi
  printf '%s\n' "$!"
}

wait_for_api() {
  local node="$1"
  local api="$2"
  local pid="$3"
  local ns="${4:-}"
  for _ in $(seq 1 "$api_ready_attempts"); do
    if run_in_netns "$ns" curl -fsS "${api}/v1/status" >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      log "${node} exited early; log follows"
      sed -n '1,200p' "$workdir/${node}.log" >&2 || true
      return 1
    fi
    sleep "$api_ready_sleep"
  done
  log "${node} did not become ready; log follows"
  sed -n '1,240p' "$workdir/${node}.log" >&2 || true
  return 1
}

assert_host_management_api() {
  local node="$1"
  local host_ns="$2"
  local gateway_ip="$3"
  local port="$4"
  local api="https://${gateway_ip}:${port}"
  local api_tls_ca="$workdir/certs/domain-ca.pem"
  local api_tls_server_name="lab.local"
  local status_path="$workdir/${node}-host-management-status.json"
  local doctor_path="$workdir/${node}-host-management-doctor.json"
  log "validating ${node} host management API from ${host_ns} at ${api}"
  for _ in $(seq 1 40); do
    if run_ctl "$host_ns" -api "$api" -api-tls-ca "$api_tls_ca" -api-tls-server-name "$api_tls_server_name" -admin-cert "$workdir/certs/admin-1.crt" -admin-key "$workdir/certs/admin-1.key" status >"$status_path" 2>"$workdir/${node}-host-management-status.err"; then
      break
    fi
    sleep 0.25
  done
  if [[ ! -s "$status_path" ]]; then
    sed -n '1,120p' "$workdir/${node}-host-management-status.err" >&2 || true
    die "${node} signed host management API status failed"
  fi
  if run_in_netns "$host_ns" curl -kfsS "${api}/v1/status" >/dev/null 2>&1; then
    die "${node} host management API allowed unsigned read despite require_read_auth"
  fi
  run_ctl "$host_ns" -api "$api" -api-tls-ca "$api_tls_ca" -api-tls-server-name "$api_tls_server_name" -admin-cert "$workdir/certs/admin-1.crt" -admin-key "$workdir/certs/admin-1.key" doctor >"$doctor_path"
  grep -q '"host":' "$status_path" || die "${node} status has no host management block"
  grep -q "\"listen\": \"${gateway_ip}:${port}\"" "$status_path" || die "${node} host management listen is unexpected"
  grep -q '"scheme": "https"' "$status_path" || die "${node} host management scheme is not https"
  grep -q '"tls": true' "$status_path" || die "${node} host management TLS is not enabled"
  grep -q '"write_auth": true' "$status_path" || die "${node} host management write auth is not enabled"
  grep -q '"read_auth": true' "$status_path" || die "${node} host management read auth is not enabled"
  awk '
    /"name": "management_host_api"/ { found=1 }
    found && /"status": "ok"/ { ok=1 }
    found && /^  }/ { exit !(found && ok) }
    END { exit !(found && ok) }
  ' "$doctor_path" || die "${node} host management doctor check is not ok"
}

assert_cross_ix_management_proxy() {
  local source_node="$1"
  local host_ns="$2"
  local source_gateway_ip="$3"
  local source_port="$4"
  local target_ix="$5"
  local api="https://${source_gateway_ip}:${source_port}"
  local api_tls_ca="$workdir/certs/domain-ca.pem"
  local api_tls_server_name="lab.local"
  local status_path="$workdir/${source_node}-proxy-${target_ix}-status.json"
  log "validating ${source_node} host management proxy to ${target_ix}"
  run_ctl "$host_ns" -api "$api" -api-tls-ca "$api_tls_ca" -api-tls-server-name "$api_tls_server_name" -target-ix "$target_ix" -admin-cert "$workdir/certs/admin-1.crt" -admin-key "$workdir/certs/admin-1.key" status >"$status_path"
  grep -q "\"ix_id\": \"${target_ix}\"" "$status_path" || die "${source_node} proxy status did not return ${target_ix}"
}

route_table_covers_management_vip() {
  local route_path="$1"
  local target_gateway_ip="$2"
  local target_ix="$3"
  python3 - "$route_path" "$target_gateway_ip" "$target_ix" <<'PY'
import ipaddress
import json
import sys

path, target_ip, target_ix = sys.argv[1:4]
target = ipaddress.ip_address(target_ip)
try:
    routes = json.load(open(path, encoding="utf-8"))
except Exception:
    sys.exit(1)
for route in routes:
    prefix = route.get("prefix")
    if not prefix:
        continue
    try:
        network = ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        continue
    if target not in network:
        continue
    if network.prefixlen == network.max_prefixlen:
        if route.get("source") == "management_vip" or route.get("kind") == "local":
            sys.exit(0)
        continue
    if route.get("next_hop") == target_ix or route.get("owner") == target_ix:
        sys.exit(0)
sys.exit(1)
PY
}

wait_for_management_vip_route() {
  local source_node="$1"
  local host_ns="$2"
  local source_gateway_ip="$3"
  local source_port="$4"
  local target_gateway_ip="$5"
  local target_ix="$6"
  local api="https://${source_gateway_ip}:${source_port}"
  local api_tls_ca="$workdir/certs/domain-ca.pem"
  local api_tls_server_name="lab.local"
  local route_path="$workdir/${source_node}-management-vip-routes.json"
  for _ in $(seq 1 60); do
    if run_ctl "$host_ns" -api "$api" -api-tls-ca "$api_tls_ca" -api-tls-server-name "$api_tls_server_name" -admin-cert "$workdir/certs/admin-1.crt" -admin-key "$workdir/certs/admin-1.key" routes >"$route_path" 2>/dev/null &&
      route_table_covers_management_vip "$route_path" "$target_gateway_ip" "$target_ix"; then
      return 0
    fi
    sleep 0.25
  done
  sed -n '1,160p' "$route_path" >&2 || true
  die "${source_node} has no route covering management VIP ${target_gateway_ip} for ${target_ix}"
}

assert_direct_management_vip() {
  local source_node="$1"
  local host_ns="$2"
  local source_gateway_ip="$3"
  local source_port="$4"
  local target_gateway_ip="$5"
  local target_port="$6"
  local target_ix="$7"
  local api="https://${target_gateway_ip}:${target_port}"
  local api_tls_ca="$workdir/certs/domain-ca.pem"
  local api_tls_server_name="lab.local"
  local status_path="$workdir/${source_node}-direct-vip-${target_ix}-status.json"
  local attempts="${TRUSTIX_E2E_DIRECT_MANAGEMENT_VIP_ATTEMPTS:-40}"
  log "validating ${source_node} direct management VIP to ${target_ix} at ${api}"
  wait_for_management_vip_route "$source_node" "$host_ns" "$source_gateway_ip" "$source_port" "$target_gateway_ip" "$target_ix"
  [[ "$attempts" =~ ^[1-9][0-9]*$ ]] || attempts=40
  for _ in $(seq 1 "$attempts"); do
    if run_ctl "$host_ns" -api "$api" -api-tls-ca "$api_tls_ca" -api-tls-server-name "$api_tls_server_name" -admin-cert "$workdir/certs/admin-1.crt" -admin-key "$workdir/certs/admin-1.key" status >"$status_path" 2>"$workdir/${source_node}-direct-vip-${target_ix}.err"; then
      break
    fi
    sleep 0.25
  done
  if [[ ! -s "$status_path" ]]; then
    sed -n '1,120p' "$workdir/${source_node}-direct-vip-${target_ix}.err" >&2 || true
    collect_api_pair || true
    die "${source_node} direct management VIP status to ${target_ix} failed"
  fi
  grep -q "\"ix_id\": \"${target_ix}\"" "$status_path" || die "${source_node} direct VIP status did not return ${target_ix}"
  if run_in_netns "$host_ns" curl -kfsS --max-time 2 "${api}/v1/status" >/dev/null 2>&1; then
    die "${source_node} direct management VIP allowed unsigned read to ${target_ix}"
  fi
}

assert_data_dir_lock_rejects_duplicate() {
  local node="$1"
  local config_path="$2"
  local data_dir="$3"
  local api_addr="$4"
  local peer_api_addr="$5"
  local ns="${6:-}"
  local log_path="$workdir/${node}-duplicate-lock.log"
  log "validating ${node} data-dir lock"
  set +e
  if is_af_xdp_transport; then
    run_in_netns "$ns" env "TRUSTIX_AF_XDP_QUEUES=${af_xdp_queues}" "TRUSTIX_XDP_MODE=${xdp_mode}" "TRUSTIX_AF_XDP_BIND_MODE=${af_xdp_bind_mode}" "TRUSTIX_AF_XDP_NEED_WAKEUP=${af_xdp_need_wakeup}" "TRUSTIX_AF_XDP_TX_BACKPRESSURE_WAIT=${af_xdp_tx_backpressure_wait}" "TRUSTIX_AF_XDP_TX_KICK_BATCH=${af_xdp_tx_kick_batch}" "TRUSTIX_AF_XDP_TX_FLUSH_INTERVAL=${af_xdp_tx_flush_interval}" "TRUSTIX_AF_XDP_RX_BURST=${af_xdp_rx_burst}" "TRUSTIX_AF_XDP_RING_ENTRIES=${af_xdp_ring_entries}" "TRUSTIX_AF_XDP_UMEM_FRAMES=${af_xdp_umem_frames}" "TRUSTIX_AF_XDP_UMEM_FRAME_SIZE=${af_xdp_umem_frame_size}" "TRUSTIX_AF_XDP_AUTO_UMEM_JUMBO=${experimental_tcp_auto_umem_jumbo}" "TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT=${experimental_tcp_tc_tx_direct}" "TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_ONLY=${experimental_tcp_tc_tx_direct_only}" "TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY=$(experimental_tcp_kernel_udp_direct_only_value)" "TRUSTIX_EXPERIMENTAL_TCP_SKIP_TCP_CHECKSUM=${experimental_tcp_skip_checksum}" "TRUSTIX_EXPERIMENTAL_TCP_SKIP_OUTER_TCP_CHECKSUM=$(experimental_tcp_effective_skip_outer_checksum)" "TRUSTIX_EXPERIMENTAL_TCP_TC_TX_PUSH_ROUTE_TCP_HEADER_KFUNC=$(experimental_tcp_route_header_kfunc_enabled && printf 1 || printf 0)" "TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_KFUNC=$(experimental_tcp_route_tcp_kfunc_value)" "TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_ASYNC_KFUNC=${experimental_tcp_route_gso_async}" "TRUSTIX_EXPERIMENTAL_TCP_ALLOW_CRASH_RISK_ROUTE_TCP_GSO_ASYNC=0" "TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_XMIT_KFUNC=${experimental_tcp_route_xmit_worker}" "TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_XMIT_STEAL=${experimental_tcp_route_xmit_worker_steal}" "TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_PRE_OUTER_INNER_CHECKSUM=$(experimental_tcp_route_gso_pre_outer_inner_checksum)" "TRUSTIX_EXPERIMENTAL_TCP_TC_TX_OUTER_TCP_HEADER_KFUNC_PARTIAL_CSUM=$(experimental_tcp_route_gso_outer_partial_checksum)" "TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_TRUST_PARTIAL_INNER_CHECKSUM=${experimental_tcp_route_gso_trust_partial_inner_checksum}" "TRUSTIX_EXPERIMENTAL_TCP_TX_PLAIN_SKIP_SEQUENCE=${experimental_tcp_plain_skip_sequence}" "TRUSTIX_EXPERIMENTAL_TCP_TX_PLAIN_ACK_ONLY=${experimental_tcp_plain_ack_only}" "TRUSTIX_KERNEL_UDP_SESSION_BUFFER=${kernel_udp_session_buffer}" "TRUSTIX_CAPTURE_FORWARDER_WORKERS=${capture_forwarder_workers}" "TRUSTIX_CAPTURE_FORWARDER_BUFFER=${capture_forwarder_buffer}" timeout 5s "$bin_dir/trustixd" \
      -config "$config_path" \
      -data-dir "$data_dir" \
      -api "$api_addr" \
      -peer-api "$peer_api_addr" \
      -dataplane "$dataplane" \
      >"$log_path" 2>&1
  else
    run_in_netns "$ns" timeout 5s "$bin_dir/trustixd" \
      -config "$config_path" \
      -data-dir "$data_dir" \
      -api "$api_addr" \
      -peer-api "$peer_api_addr" \
      -dataplane "$dataplane" \
      >"$log_path" 2>&1
  fi
  local rc=$?
  set -e
  if [[ "$rc" == "0" ]]; then
    die "${node} duplicate daemon unexpectedly exited successfully"
  fi
  if ! grep -q "already locked" "$log_path"; then
    sed -n '1,120p' "$log_path" >&2 || true
    die "${node} duplicate daemon did not fail on data-dir lock (exit=${rc})"
  fi
}

assert_experimental_tcp_kernel_crypto_rejects() {
  if [[ "$transport" != "experimental_tcp" ]]; then
    return 0
  fi
  if is_plaintext_encryption "$(effective_transport_encryption)"; then
    return 0
  fi
  if [[ "$crypto_placement" == "kernel" || "$kernel_module" == "1" ]]; then
    return 0
  fi
  if kernel_provider_expected; then
    log "skipping unavailable-kernel-crypto rejection check because trustix_crypto is already loaded"
    return 0
  fi
  local node="$1"
  local config_path="$2"
  local data_dir="$3"
  local api_addr="$4"
  local peer_api_addr="$5"
  local ns="${6:-}"
  local kernel_config="$workdir/${node}-kernel-crypto.yaml"
  local log_path="$workdir/${node}-kernel-crypto-reject.log"

  sed 's/crypto_placement: userspace/crypto_placement: kernel/' "$config_path" >"$kernel_config"
  mkdir -p "$data_dir"
  log "validating ${node} rejects unavailable experimental_tcp kernel crypto"
  set +e
  run_in_netns "$ns" env "TRUSTIX_AF_XDP_QUEUES=${af_xdp_queues}" "TRUSTIX_XDP_MODE=${xdp_mode}" "TRUSTIX_AF_XDP_BIND_MODE=${af_xdp_bind_mode}" "TRUSTIX_AF_XDP_NEED_WAKEUP=${af_xdp_need_wakeup}" "TRUSTIX_AF_XDP_TX_BACKPRESSURE_WAIT=${af_xdp_tx_backpressure_wait}" "TRUSTIX_AF_XDP_TX_KICK_BATCH=${af_xdp_tx_kick_batch}" "TRUSTIX_AF_XDP_TX_FLUSH_INTERVAL=${af_xdp_tx_flush_interval}" "TRUSTIX_AF_XDP_RX_BURST=${af_xdp_rx_burst}" "TRUSTIX_AF_XDP_RING_ENTRIES=${af_xdp_ring_entries}" "TRUSTIX_AF_XDP_UMEM_FRAMES=${af_xdp_umem_frames}" "TRUSTIX_AF_XDP_UMEM_FRAME_SIZE=${af_xdp_umem_frame_size}" "TRUSTIX_AF_XDP_AUTO_UMEM_JUMBO=${experimental_tcp_auto_umem_jumbo}" "TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT=${experimental_tcp_tc_tx_direct}" "TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_ONLY=${experimental_tcp_tc_tx_direct_only}" "TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY=$(experimental_tcp_kernel_udp_direct_only_value)" "TRUSTIX_EXPERIMENTAL_TCP_SKIP_TCP_CHECKSUM=${experimental_tcp_skip_checksum}" "TRUSTIX_EXPERIMENTAL_TCP_SKIP_OUTER_TCP_CHECKSUM=$(experimental_tcp_effective_skip_outer_checksum)" "TRUSTIX_EXPERIMENTAL_TCP_TC_TX_PUSH_ROUTE_TCP_HEADER_KFUNC=$(experimental_tcp_route_header_kfunc_enabled && printf 1 || printf 0)" "TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_KFUNC=$(experimental_tcp_route_tcp_kfunc_value)" "TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_ASYNC_KFUNC=${experimental_tcp_route_gso_async}" "TRUSTIX_EXPERIMENTAL_TCP_ALLOW_CRASH_RISK_ROUTE_TCP_GSO_ASYNC=0" "TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_XMIT_KFUNC=${experimental_tcp_route_xmit_worker}" "TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_XMIT_STEAL=${experimental_tcp_route_xmit_worker_steal}" "TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_PRE_OUTER_INNER_CHECKSUM=$(experimental_tcp_route_gso_pre_outer_inner_checksum)" "TRUSTIX_EXPERIMENTAL_TCP_TC_TX_OUTER_TCP_HEADER_KFUNC_PARTIAL_CSUM=$(experimental_tcp_route_gso_outer_partial_checksum)" "TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_TRUST_PARTIAL_INNER_CHECKSUM=${experimental_tcp_route_gso_trust_partial_inner_checksum}" "TRUSTIX_EXPERIMENTAL_TCP_TX_PLAIN_SKIP_SEQUENCE=${experimental_tcp_plain_skip_sequence}" "TRUSTIX_EXPERIMENTAL_TCP_TX_PLAIN_ACK_ONLY=${experimental_tcp_plain_ack_only}" "TRUSTIX_KERNEL_UDP_SESSION_BUFFER=${kernel_udp_session_buffer}" "TRUSTIX_CAPTURE_FORWARDER_WORKERS=${capture_forwarder_workers}" "TRUSTIX_CAPTURE_FORWARDER_BUFFER=${capture_forwarder_buffer}" timeout 8s "$bin_dir/trustixd" \
    -config "$kernel_config" \
    -data-dir "$data_dir" \
    -api "$api_addr" \
    -peer-api "$peer_api_addr" \
    -dataplane "$dataplane" \
    >"$log_path" 2>&1
  local rc=$?
  set -e
  if [[ "$rc" == "0" ]]; then
    die "${node} kernel crypto daemon unexpectedly started successfully"
  fi
  if [[ "$rc" == "124" ]]; then
    sed -n '1,160p' "$log_path" >&2 || true
    die "${node} kernel crypto daemon timed out instead of rejecting provider"
  fi
  if ! grep -q "kernel crypto requested but unavailable" "$log_path"; then
    sed -n '1,160p' "$log_path" >&2 || true
    die "${node} kernel crypto daemon did not report strict placement rejection (exit=${rc})"
  fi
}

assert_sigterm_releases_data_dir_lock() {
  local config_path="$1"
  local data_dir="$2"
  local api_url="$3"
  local api_addr="$4"
  local peer_api_addr="$5"
  local ns="${6:-}"

  log "validating ix-a SIGTERM cleanup and data-dir lock release"
  stop_daemon_pid_with_signal "$pid_a" TERM
  pid_a=""
  pid_a="$(start_daemon ix-a-sigterm-restart "$config_path" "$data_dir" "$api_addr" "$peer_api_addr" "$ns")"
  wait_for_api ix-a-sigterm-restart "$api_url" "$pid_a" "$ns"
  assert_data_dir_lock_rejects_duplicate ix-a "$config_path" "$data_dir" "$api_addr" "$peer_api_addr" "$ns"
}

run_dataplane_cleanup() {
  local node="$1"
  local config_path="$2"
  local data_dir="$3"
  local api_addr="$4"
  local peer_api_addr="$5"
  local ns="${6:-}"
  local log_path="$workdir/${node}-cleanup.log"

  log "cleaning ${node} dataplane"
  if is_af_xdp_transport; then
    run_in_netns "$ns" env "TRUSTIX_AF_XDP_QUEUES=${af_xdp_queues}" "TRUSTIX_XDP_MODE=${xdp_mode}" "TRUSTIX_AF_XDP_BIND_MODE=${af_xdp_bind_mode}" "TRUSTIX_AF_XDP_NEED_WAKEUP=${af_xdp_need_wakeup}" "TRUSTIX_AF_XDP_TX_BACKPRESSURE_WAIT=${af_xdp_tx_backpressure_wait}" "TRUSTIX_AF_XDP_TX_KICK_BATCH=${af_xdp_tx_kick_batch}" "TRUSTIX_AF_XDP_TX_FLUSH_INTERVAL=${af_xdp_tx_flush_interval}" "TRUSTIX_AF_XDP_RX_BURST=${af_xdp_rx_burst}" "TRUSTIX_AF_XDP_RING_ENTRIES=${af_xdp_ring_entries}" "TRUSTIX_AF_XDP_UMEM_FRAMES=${af_xdp_umem_frames}" "TRUSTIX_AF_XDP_UMEM_FRAME_SIZE=${af_xdp_umem_frame_size}" "TRUSTIX_AF_XDP_AUTO_UMEM_JUMBO=${experimental_tcp_auto_umem_jumbo}" "TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT=${experimental_tcp_tc_tx_direct}" "TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_ONLY=${experimental_tcp_tc_tx_direct_only}" "TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY=$(experimental_tcp_kernel_udp_direct_only_value)" "TRUSTIX_EXPERIMENTAL_TCP_SKIP_TCP_CHECKSUM=${experimental_tcp_skip_checksum}" "TRUSTIX_EXPERIMENTAL_TCP_SKIP_OUTER_TCP_CHECKSUM=$(experimental_tcp_effective_skip_outer_checksum)" "TRUSTIX_EXPERIMENTAL_TCP_TC_TX_PUSH_ROUTE_TCP_HEADER_KFUNC=$(experimental_tcp_route_header_kfunc_enabled && printf 1 || printf 0)" "TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_KFUNC=$(experimental_tcp_route_tcp_kfunc_value)" "TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_ASYNC_KFUNC=${experimental_tcp_route_gso_async}" "TRUSTIX_EXPERIMENTAL_TCP_ALLOW_CRASH_RISK_ROUTE_TCP_GSO_ASYNC=0" "TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_XMIT_KFUNC=${experimental_tcp_route_xmit_worker}" "TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_XMIT_STEAL=${experimental_tcp_route_xmit_worker_steal}" "TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_PRE_OUTER_INNER_CHECKSUM=$(experimental_tcp_route_gso_pre_outer_inner_checksum)" "TRUSTIX_EXPERIMENTAL_TCP_TC_TX_OUTER_TCP_HEADER_KFUNC_PARTIAL_CSUM=$(experimental_tcp_route_gso_outer_partial_checksum)" "TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_TRUST_PARTIAL_INNER_CHECKSUM=${experimental_tcp_route_gso_trust_partial_inner_checksum}" "TRUSTIX_EXPERIMENTAL_TCP_TX_PLAIN_SKIP_SEQUENCE=${experimental_tcp_plain_skip_sequence}" "TRUSTIX_EXPERIMENTAL_TCP_TX_PLAIN_ACK_ONLY=${experimental_tcp_plain_ack_only}" "TRUSTIX_KERNEL_UDP_SESSION_BUFFER=${kernel_udp_session_buffer}" "TRUSTIX_CAPTURE_FORWARDER_WORKERS=${capture_forwarder_workers}" "TRUSTIX_CAPTURE_FORWARDER_BUFFER=${capture_forwarder_buffer}" "$bin_dir/trustixd" \
      -config "$config_path" \
      -data-dir "$data_dir" \
      -api "$api_addr" \
      -peer-api "$peer_api_addr" \
      -dataplane "$dataplane" \
      -cleanup-dataplane \
      >"$log_path" 2>&1
  else
    run_in_netns "$ns" "$bin_dir/trustixd" \
      -config "$config_path" \
      -data-dir "$data_dir" \
      -api "$api_addr" \
      -peer-api "$peer_api_addr" \
      -dataplane "$dataplane" \
      -cleanup-dataplane \
      >"$log_path" 2>&1
  fi
}

assert_cleanup_dry_run_plan() {
  local node="$1"
  local config_path="$2"
  local data_dir="$3"
  local api_addr="$4"
  local peer_api_addr="$5"
  local ns="${6:-}"
  local plan_path="$workdir/${node}-cleanup-plan.json"

  log "validating ${node} cleanup dry-run plan"
  run_in_netns "$ns" "$bin_dir/trustixd" \
    -config "$config_path" \
    -data-dir "$data_dir" \
    -api "$api_addr" \
    -peer-api "$peer_api_addr" \
    -dataplane "$dataplane" \
    -cleanup-dataplane-dry-run \
    >"$plan_path"
  local native_no_tc=0
  if native_tunnel_plaintext_route_offload_enabled; then
    native_no_tc=1
  fi
  python3 - "$plan_path" "$data_dir" "$native_no_tc" <<'PY'
import json
import sys

plan_path, data_dir, native_no_tc = sys.argv[1:4]
native_no_tc = native_no_tc == "1"
with open(plan_path, "r", encoding="utf-8") as handle:
    plan = json.load(handle)
spec = plan.get("spec") or {}
steps = plan.get("steps") or []
if not spec.get("pin_path", "").startswith(data_dir):
    raise SystemExit(f"cleanup plan pin_path {spec.get('pin_path')!r} is not under {data_dir!r}")
actions = {step.get("action") for step in steps}
required = ["load_state", "close_bpf_objects"]
if not native_no_tc:
    required.extend(["remove_tc_filters", "delete_clsact_qdisc"])
for action in required:
    if action not in actions:
        raise SystemExit(f"cleanup plan missing action {action}: {steps!r}")
if native_no_tc:
    for action in ("remove_tc_filters", "delete_clsact_qdisc"):
        if action in actions:
            raise SystemExit(f"cleanup plan unexpectedly includes {action} for native no-TC route offload: {steps!r}")
PY
  if is_iptunnel_transport; then
    grep -q '"action": "delete_ip_tunnel"' "$plan_path" || die "${node} cleanup plan missing GRE/IPIP tunnel delete step"
  fi
}

assert_iptunnel_state_empty() {
  local node="$1"
  local data_dir="$2"
  local state_path="${data_dir}/iptunnel/state.json"
  [[ -f "$state_path" ]] || return 0
  python3 - "$state_path" "$node" <<'PY'
import json
import sys

state_path, node = sys.argv[1:3]
with open(state_path, "r", encoding="utf-8") as handle:
    state = json.load(handle)
tunnels = state.get("tunnels") or []
if tunnels:
    raise SystemExit(f"{node} iptunnel state still has records: {tunnels!r}")
PY
}

assert_no_iptunnel_links() {
  local ns="$1"
  local node="$2"
  [[ -n "$ns" ]] || return 0
  if run_in_netns "$ns" ip -o link show | grep -q 'tix\(gr\|ip\|vx\)'; then
    run_in_netns "$ns" ip -o link show >&2 || true
    die "${node} has leftover TrustIX GRE/IPIP/VXLAN tunnel links"
  fi
}

assert_crash_cleanup_restart() {
  local config_path="$1"
  local data_dir="$2"
  local api_url="$3"
  local api_addr="$4"
  local peer_api_addr="$5"
  local ns="${6:-}"

  [[ "$crash_restart" == "1" ]] || return 0
  log "validating ix-a crash cleanup and restart"
  local crash_pids
  crash_pids="$(trustixd_pids_for_data_dir "$data_dir")"
  if [[ -z "$crash_pids" && -n "$pid_a" ]]; then
    crash_pids="$pid_a"
  fi
  for pid in $crash_pids; do
    kill -KILL "$pid" >/dev/null 2>&1 || true
  done
  if [[ -n "$pid_a" ]]; then
    kill -KILL "$pid_a" >/dev/null 2>&1 || true
    wait "$pid_a" >/dev/null 2>&1 || true
  fi
  pid_a=""
  wait_for_pids_gone "$crash_pids" || die "ix-a crash process did not exit after SIGKILL"

  assert_cleanup_dry_run_plan ix-a "$config_path" "$data_dir" "$api_addr" "$peer_api_addr" "$ns"
  run_dataplane_cleanup ix-a "$config_path" "$data_dir" "$api_addr" "$peer_api_addr" "$ns"
  grep -q '"attached": false' "$data_dir/bpf/state.json" || die "ix-a dataplane cleanup did not persist detached state"
  if is_iptunnel_transport; then
    assert_iptunnel_state_empty ix-a "$data_dir"
    assert_no_iptunnel_links "$ns" ix-a
  fi

  pid_a="$(start_daemon ix-a-crash-restart "$config_path" "$data_dir" "$api_addr" "$peer_api_addr" "$ns" -repair-dataplane)"
  wait_for_api ix-a-crash-restart "$api_url" "$pid_a" "$ns"
  assert_data_dir_lock_rejects_duplicate ix-a "$config_path" "$data_dir" "$api_addr" "$peer_api_addr" "$ns"
  assert_host_management_api ix-a "$ns_a" 10.0.0.1 "$api_a_port"
  assert_cross_ix_management_proxy ix-a "$ns_a" 10.0.0.1 "$api_a_port" ix-b
  if direct_management_vip_enabled; then
    assert_direct_management_vip ix-a "$ns_a" 10.0.0.1 "$api_a_port" 10.0.1.1 "$api_b_port" ix-b
  else
    log "skip direct management VIP after crash restart for router-netns transport"
  fi
  warm_neighbors
  if [[ "$nat_reverse" == "1" ]]; then
    if ! retry_ping "$ns_b" 10.0.0.2 "LAN B -> LAN A after ix-a crash restart reverse warmup"; then
      collect_api ix-a "$api_a" "$ns" || true
      collect_api ix-b "$api_b" "$daemon_ns_b" || true
      die "LAN B -> LAN A ping failed after ix-a crash restart reverse warmup"
    fi
  fi
  if ! retry_ping "$ns_a" 10.0.1.2 "LAN A -> LAN B after ix-a crash restart"; then
    collect_api ix-a "$api_a" "$ns" || true
    collect_api ix-b "$api_b" "$daemon_ns_b" || true
    die "LAN A -> LAN B ping failed after ix-a crash restart"
  fi
  if ! retry_ping "$ns_b" 10.0.0.2 "LAN B -> LAN A after ix-a crash restart"; then
    collect_api ix-a "$api_a" "$ns" || true
    collect_api ix-b "$api_b" "$daemon_ns_b" || true
    die "LAN B -> LAN A ping failed after ix-a crash restart"
  fi
  collect_api ix-a "$api_a" "$ns" || true
  collect_api ix-b "$api_b" "$daemon_ns_b" || true
  assert_nat_reverse_status
  validate_secure_reset_recovery_counters "$workdir/ix-a-datapath.json" "$workdir/ix-b-datapath.json"
}

validate_secure_reset_recovery_counters() {
  local a_file="$1"
  local b_file="$2"
  python3 - "$a_file" "$b_file" "$transport" <<'PY'
import json
import sys

a_file, b_file, transport = sys.argv[1:4]
if transport not in {"udp", "kernel_udp", "gre", "ipip", "vxlan", "experimental_tcp"}:
    raise SystemExit(0)

def counters(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh).get("counters", {})

a = counters(a_file)
b = counters(b_file)
sent = int(a.get("session_resets_sent", 0)) + int(b.get("session_resets_sent", 0))
received = int(a.get("session_resets_received", 0)) + int(b.get("session_resets_received", 0))
stale = int(a.get("stale_sessions_dropped", 0)) + int(b.get("stale_sessions_dropped", 0))
print(
    f"[trustix-e2e] secure restart recovery counters: sent={sent} received={received} stale={stale}",
    file=sys.stderr,
)
PY
}

warm_neighbors() {
  log "warming LAN neighbor cache"
  if [[ "$router_netns" == "1" ]]; then
    ip netns exec "$ns_ix_a" ping -c 1 -W 1 10.0.0.2 >/dev/null 2>&1 || true
    ip netns exec "$ns_ix_b" ping -c 1 -W 1 10.0.1.2 >/dev/null 2>&1 || true
    ip netns exec "$ns_ix_a" ping -c 1 -W 1 "$underlay_ip_b" >/dev/null 2>&1 || true
    ip netns exec "$ns_ix_b" ping -c 1 -W 1 "$underlay_ip_a" >/dev/null 2>&1 || true
  else
    ping -c 1 -W 1 10.0.0.2 >/dev/null 2>&1 || true
    ping -c 1 -W 1 10.0.1.2 >/dev/null 2>&1 || true
  fi
}

retry_ping() {
  local src_ns="$1"
  local dst="$2"
  local label="$3"
  for attempt in $(seq 1 20); do
    if run_ping_pressure "$src_ns" "$dst"; then
      log "${label} ping ok on attempt ${attempt} count=${ping_count} size=${ping_size} parallel=${ping_parallel} rounds=${ping_rounds}"
      return 0
    fi
    sleep 0.5
  done
  return 1
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

run_payload_bursts() {
  if [[ "$udp_burst_packets" -gt 0 ]]; then
    run_udp_payload_burst "$ns_a" "$ns_b" "10.0.1.2" "$udp_burst_port" "LAN A -> LAN B UDP burst"
    run_udp_payload_burst "$ns_b" "$ns_a" "10.0.0.2" "$((udp_burst_port + 1))" "LAN B -> LAN A UDP burst"
  fi
  if [[ "$tcp_burst_connections" -gt 0 ]]; then
    run_tcp_payload_burst "$ns_a" "$ns_b" "10.0.1.2" "$tcp_burst_port" "LAN A -> LAN B TCP burst"
    run_tcp_payload_burst "$ns_b" "$ns_a" "10.0.0.2" "$((tcp_burst_port + 1))" "LAN B -> LAN A TCP burst"
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
  log "${label}: packets=${udp_burst_packets} size=${udp_burst_size} parallel=${udp_burst_parallel} rounds=${udp_burst_rounds} rate_pps=${udp_burst_rate_pps} allow_loss=${udp_burst_allow_loss}"
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
target_rcvbuf = max(16 * 1024 * 1024, expected * 4096)
for option in (getattr(socket, "SO_RCVBUFFORCE", 33), socket.SO_RCVBUF):
    try:
        sock.setsockopt(socket.SOL_SOCKET, option, target_rcvbuf)
        break
    except OSError:
        continue
sock.bind((bind_ip, port))
sock.settimeout(0.1)
actual_rcvbuf = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
deadline = time.monotonic() + timeout
count = 0
received = 0
first_seen = None
last_seen = None
while count < expected and time.monotonic() < deadline:
    try:
        payload, _ = sock.recvfrom(65535)
    except socket.timeout:
        continue
    now = time.monotonic()
    if first_seen is None:
        first_seen = now
    last_seen = now
    count += 1
    received += len(payload)
duration = max((last_seen - first_seen) if first_seen is not None and last_seen is not None else 0.0, 1e-9)
pps = count / duration if count else 0.0
mbps = (received * 8 / duration / 1_000_000) if received else 0.0
loss = max(expected - count, 0)
print(f"received={count} bytes={received} expected={expected} lost={loss} rcvbuf={actual_rcvbuf} duration_seconds={duration:.6f} pps={pps:.2f} mbps={mbps:.2f}", flush=True)
if count != expected:
    sys.exit(1)
PY
  local server_pid=$!
  sleep 0.2
  if ! run_in_netns "$src_ns" python3 - "$dst_ip" "$port" "$udp_burst_packets" "$udp_burst_size" "$udp_burst_parallel" "$udp_burst_rounds" "$udp_burst_rate_pps" >"$send_log" 2>&1 <<'PY'; then
import socket
import sys
import threading
import time

dst_ip = sys.argv[1]
port = int(sys.argv[2])
packets = int(sys.argv[3])
size = int(sys.argv[4])
parallel = int(sys.argv[5])
rounds = int(sys.argv[6])
rate_pps = float(sys.argv[7])
prefix = b"TIX-UDP-BURST"
payload = (prefix + bytes(max(0, size - len(prefix))))[:size]
errors = []
sent_total = 0
bytes_total = 0
lock = threading.Lock()
worker_interval = 0.0
if rate_pps > 0 and parallel > 0:
    worker_interval = parallel / rate_pps

def send_worker(worker_id):
    global sent_total, bytes_total
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        target_sndbuf = 16 * 1024 * 1024
        for option in (getattr(socket, "SO_SNDBUFFORCE", 32), socket.SO_SNDBUF):
            try:
                sock.setsockopt(socket.SOL_SOCKET, option, target_sndbuf)
                break
            except OSError:
                continue
        next_send = time.monotonic()
        for _ in range(packets):
            if worker_interval > 0:
                now = time.monotonic()
                if next_send > now:
                    time.sleep(next_send - now)
                next_send += worker_interval
            sock.sendto(payload, (dst_ip, port))
            with lock:
                sent_total += 1
                bytes_total += len(payload)
        sock.close()
    except Exception as exc:
        with lock:
            errors.append(f"worker={worker_id}: {exc}")

start = time.monotonic()
for _ in range(rounds):
    threads = [threading.Thread(target=send_worker, args=(worker,)) for worker in range(parallel)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
end = time.monotonic()

duration = max(end - start, 1e-9)
pps = sent_total / duration if sent_total else 0.0
mbps = bytes_total * 8 / duration / 1_000_000 if bytes_total else 0.0
print(f"sent={sent_total} bytes={bytes_total} expected={packets * parallel * rounds} duration_seconds={duration:.6f} pps={pps:.2f} mbps={mbps:.2f} rate_pps={rate_pps:.2f}", flush=True)
if errors:
    print("\n".join(errors), file=sys.stderr)
    sys.exit(1)
PY
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" >/dev/null 2>&1 || true
    sed -n '1,120p' "$send_log" >&2 || true
    collect_api_pair || true
    die "${label} sender failed"
  fi
  if ! wait "$server_pid"; then
    sed -n '1,120p' "$send_log" >&2 || true
    sed -n '1,120p' "$recv_log" >&2 || true
    if [[ "$udp_burst_allow_loss" == "1" ]]; then
      log "${label} receiver observed loss; continuing because TRUSTIX_E2E_UDP_BURST_ALLOW_LOSS=1"
      return 0
    fi
    collect_api_pair || true
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
first_seen = None
last_seen = None
while accepted < expected and time.monotonic() < deadline:
    try:
        conn, _ = listener.accept()
    except socket.timeout:
        continue
    now = time.monotonic()
    if first_seen is None:
        first_seen = now
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
        last_seen = time.monotonic()
    else:
        short_reads += 1
duration = max((last_seen - first_seen) if first_seen is not None and last_seen is not None else 0.0, 1e-9)
cps = accepted / duration if accepted else 0.0
mbps = (received * 8 / duration / 1_000_000) if received else 0.0
print(f"accepted={accepted} bytes={received} short_reads={short_reads} expected={expected} duration_seconds={duration:.6f} cps={cps:.2f} mbps={mbps:.2f}", flush=True)
if accepted != expected:
    sys.exit(1)
PY
  local server_pid=$!
  sleep 0.2
  if ! run_in_netns "$src_ns" python3 - "$dst_ip" "$port" "$tcp_burst_connections" "$tcp_burst_size" "$tcp_burst_parallel" "$tcp_burst_rounds" "$tcp_connect_timeout" >"$send_log" 2>&1 <<'PY'; then
import socket
import sys
import threading
import time

dst_ip = sys.argv[1]
port = int(sys.argv[2])
connections = int(sys.argv[3])
size = int(sys.argv[4])
parallel = int(sys.argv[5])
rounds = int(sys.argv[6])
connect_timeout = float(sys.argv[7])
prefix = b"TIX-TCP-BURST"
payload = (prefix + bytes(max(0, size - len(prefix))))[:size]
errors = []
sent_total = 0
bytes_total = 0
lock = threading.Lock()

def send_worker(worker_id):
    global sent_total, bytes_total
    try:
        for _ in range(connections):
            sock = socket.create_connection((dst_ip, port), timeout=connect_timeout)
            sock.sendall(payload)
            sock.shutdown(socket.SHUT_WR)
            sock.close()
            with lock:
                sent_total += 1
                bytes_total += len(payload)
    except Exception as exc:
        with lock:
            errors.append(f"worker={worker_id}: {exc}")

start = time.monotonic()
for _ in range(rounds):
    threads = [threading.Thread(target=send_worker, args=(worker,)) for worker in range(parallel)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
end = time.monotonic()

duration = max(end - start, 1e-9)
cps = sent_total / duration if sent_total else 0.0
mbps = bytes_total * 8 / duration / 1_000_000 if bytes_total else 0.0
print(f"sent_connections={sent_total} bytes={bytes_total} expected={connections * parallel * rounds} duration_seconds={duration:.6f} cps={cps:.2f} mbps={mbps:.2f} connect_timeout_seconds={connect_timeout:.3f}", flush=True)
if errors:
    print("\n".join(errors), file=sys.stderr)
    sys.exit(1)
PY
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" >/dev/null 2>&1 || true
    sed -n '1,120p' "$send_log" >&2 || true
    collect_api_pair || true
    die "${label} sender failed"
  fi
  if ! wait "$server_pid"; then
    sed -n '1,120p' "$send_log" >&2 || true
    sed -n '1,120p' "$recv_log" >&2 || true
    collect_api_pair || true
    die "${label} receiver did not observe all connections"
  fi
}

run_iperf3_probe() {
  local src_ns="$1"
  local dst_ns="$2"
  local dst_ip="$3"
  local port="$4"
  local label="$5"
  local safe_label
  safe_label="$(printf '%s' "$label" | sed 's/[^A-Za-z0-9_.-]/_/g')"
  local server_json="$workdir/${safe_label}-iperf3-server.json"
  local server_log="$workdir/${safe_label}-iperf3-server.log"
  local client_json="$workdir/${safe_label}-iperf3-client.json"
  local client_log="$workdir/${safe_label}-iperf3-client.log"
  local client_timeout="${iperf3_timeout:-$((iperf3_seconds + 20))s}"
  log "${label}: iperf3 seconds=${iperf3_seconds} parallel=${iperf3_parallel} reverse=${iperf3_reverse}"
  run_iperf3_hook "$iperf3_pre_hook" pre "$src_ns" "$dst_ns" "$dst_ip" "$port" "$label"
  iperf3_post_hook_armed=1
  run_in_netns "$dst_ns" iperf3 -s -1 -p "$port" --json >"$server_json" 2>"$server_log" &
  local server_pid=$!
  sleep 0.5
  local client_rc=0
  if [[ "$iperf3_reverse" == "1" ]]; then
    run_in_netns "$src_ns" timeout "$client_timeout" iperf3 -c "$dst_ip" -p "$port" -t "$iperf3_seconds" -P "$iperf3_parallel" -R --json >"$client_json" 2>"$client_log" || client_rc=$?
  else
    run_in_netns "$src_ns" timeout "$client_timeout" iperf3 -c "$dst_ip" -p "$port" -t "$iperf3_seconds" -P "$iperf3_parallel" --json >"$client_json" 2>"$client_log" || client_rc=$?
  fi
  if [[ "$client_rc" != "0" ]]; then
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" >/dev/null 2>&1 || true
    run_iperf3_post_hook_if_armed "$src_ns" "$dst_ns" "$dst_ip" "$port" "$label"
    sed -n '1,120p' "$client_log" >&2 || true
    sed -n '1,120p' "$server_log" >&2 || true
    collect_api_pair || true
    die "${label} iperf3 client failed"
  fi
  if ! wait "$server_pid"; then
    run_iperf3_post_hook_if_armed "$src_ns" "$dst_ns" "$dst_ip" "$port" "$label"
    sed -n '1,120p' "$client_log" >&2 || true
    sed -n '1,120p' "$server_log" >&2 || true
    collect_api_pair || true
    die "${label} iperf3 server failed"
  fi
  run_iperf3_post_hook_if_armed "$src_ns" "$dst_ns" "$dst_ip" "$port" "$label"
  if ! python3 - "$client_json" "$label" "$iperf3_min_sent_gbps" "$iperf3_min_received_gbps" <<'PY'
import json
import sys

path, label, min_sent_gbps, min_received_gbps = sys.argv[1:5]
with open(path, "r", encoding="utf-8") as handle:
    payload = json.load(handle)
end = payload.get("end") or {}
sent = end.get("sum_sent") or {}
received = end.get("sum_received") or {}
sent_bps = float(sent.get("bits_per_second") or 0.0)
recv_bps = float(received.get("bits_per_second") or 0.0)
retransmits = int(sent.get("retransmits") or 0)
sent_gbps = sent_bps / 1_000_000_000
received_gbps = recv_bps / 1_000_000_000
min_sent = float(min_sent_gbps or 0.0)
min_received = float(min_received_gbps or 0.0)
print(f"[trustix-e2e] {label}: iperf3 sent_gbps={sent_gbps:.3f} received_gbps={received_gbps:.3f} retransmits={retransmits}", file=sys.stderr)
if min_sent > 0 and sent_gbps < min_sent:
    raise SystemExit(f"{label} iperf3 sent_gbps {sent_gbps:.3f} is below minimum {min_sent:.3f}")
if min_received > 0 and received_gbps < min_received:
    raise SystemExit(f"{label} iperf3 received_gbps {received_gbps:.3f} is below minimum {min_received:.3f}")
PY
  then
    collect_api_pair || true
    die "${label} iperf3 throughput gate failed"
  fi
}

run_iperf3_probes() {
  if [[ "$iperf3_probe" != "1" ]]; then
    return 0
  fi
  case "$iperf3_directions" in
    a_to_b)
      run_iperf3_probe "$ns_a" "$ns_b" "10.0.1.2" "$iperf3_port" "LAN A -> LAN B iperf3"
      ;;
    b_to_a)
      run_iperf3_probe "$ns_b" "$ns_a" "10.0.0.2" "$((iperf3_port + 1))" "LAN B -> LAN A iperf3"
      ;;
    both)
      run_iperf3_probe "$ns_a" "$ns_b" "10.0.1.2" "$iperf3_port" "LAN A -> LAN B iperf3"
      run_iperf3_probe "$ns_b" "$ns_a" "10.0.0.2" "$((iperf3_port + 1))" "LAN B -> LAN A iperf3"
      ;;
  esac
}

collect_binary_identity() {
  local name="$1"
  python3 - "$bin_dir/trustixd" "$workdir/${name}-binary-identity.json" <<'PY'
import hashlib
import json
import subprocess
import sys
from pathlib import Path

binary = Path(sys.argv[1])
out = Path(sys.argv[2])
sha256 = ""
try:
    digest = hashlib.sha256()
    with binary.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    sha256 = digest.hexdigest()
except OSError:
    pass

version = {}
try:
    proc = subprocess.run(
        [str(binary), "-version"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=5,
    )
    for line in proc.stdout.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            version[key.strip()] = value.strip()
except Exception as exc:  # noqa: BLE001 - best-effort artifact collection.
    version["error"] = str(exc)

out.write_text(
    json.dumps(
        {
            "path": str(binary),
            "sha256": sha256,
            "version": version,
        },
        sort_keys=True,
    )
    + "\n",
    encoding="utf-8",
)
PY
}

collect_api() {
  local name="$1"
  local api="$2"
  local ns="${3:-}"
  collect_binary_identity "$name" || true
  run_ctl "$ns" -api "$api" status >"$workdir/${name}-status.json"
  run_ctl "$ns" -api "$api" routes >"$workdir/${name}-routes.json"
  run_ctl "$ns" -api "$api" flows >"$workdir/${name}-flows.json"
  run_ctl "$ns" -api "$api" peers >"$workdir/${name}-peers.json"
  run_ctl "$ns" -api "$api" transports >"$workdir/${name}-transports.json"
  run_ctl "$ns" -api "$api" datapath >"$workdir/${name}-datapath.json"
  run_ctl "$ns" -api "$api" capture >"$workdir/${name}-capture.json"
  run_ctl "$ns" -api "$api" bpf maps >"$workdir/${name}-bpf.json"
  run_ctl "$ns" -api "$api" doctor >"$workdir/${name}-doctor.json"
}

collect_api_pair() {
  local daemon_ns_a=""
  local daemon_ns_b=""
  if [[ "$router_netns" == "1" ]]; then
    daemon_ns_a="$ns_ix_a"
    daemon_ns_b="$ns_ix_b"
  fi
  collect_api ix-a "$api_a" "$daemon_ns_a"
  collect_api ix-b "$api_b" "$daemon_ns_b"
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

assert_any_counter_positive() {
  local file="$1"
  shift
  local name
  local value
  for name in "$@"; do
    value="$(counter_value "$file" "$name")"
    if [[ -n "$value" && "$value" -gt 0 ]]; then
      return 0
    fi
  done
  die "none of counters [$*] in ${file} is positive"
}

assert_hot_counter_positive() {
  hot_stats_enabled || return 0
  assert_counter_positive "$@"
}

assert_hot_any_counter_positive() {
  hot_stats_enabled || return 0
  assert_any_counter_positive "$@"
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

assert_datapath_or_bpf_counter_positive() {
  local datapath_file="$1"
  local datapath_name="$2"
  local bpf_file="$3"
  shift 3
  local value
  value="$(datapath_counter_value "$datapath_file" "$datapath_name")"
  if [[ -n "$value" && "$value" -gt 0 ]]; then
    return 0
  fi
  local name
  for name in "$@"; do
    value="$(counter_value "$bpf_file" "$name")"
    if [[ -n "$value" && "$value" -gt 0 ]]; then
      return 0
    fi
  done
  die "datapath counter ${datapath_name} in ${datapath_file} and BPF counters [$*] in ${bpf_file} are not positive"
}

assert_datapath_or_hot_bpf_counter_positive() {
  local datapath_file="$1"
  local datapath_name="$2"
  local bpf_file="$3"
  shift 3
  local value
  value="$(datapath_counter_value "$datapath_file" "$datapath_name")"
  if [[ -n "$value" && "$value" -gt 0 ]]; then
    return 0
  fi
  hot_stats_enabled || return 0
  local name
  for name in "$@"; do
    value="$(counter_value "$bpf_file" "$name")"
    if [[ -n "$value" && "$value" -gt 0 ]]; then
      return 0
    fi
  done
  die "datapath counter ${datapath_name} in ${datapath_file} and hot BPF counters [$*] in ${bpf_file} are not positive"
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

datapath_counter_value_or_zero() {
  local file="$1"
  local name="$2"
  local value
  value="$(datapath_counter_value "$file" "$name")"
  printf '%s' "${value:-0}"
}

assert_xdp_kernel_crypto_open_health() {
  local file="$1"
  local node="$2"
  local open_errors replay_drops seal_successes budget serious name value
  open_errors="$(datapath_counter_value_or_zero "$file" "xdp_kernel_crypto_open_errors")"
  replay_drops="$(datapath_counter_value_or_zero "$file" "xdp_kernel_crypto_replay_drops")"
  if [[ "$open_errors" == "0" && "$replay_drops" == "0" ]]; then
    return 0
  fi

  serious=0
  for name in \
    xdp_kernel_crypto_no_context_drops \
    xdp_kernel_crypto_header_errors \
    xdp_kernel_crypto_payload_len_errors \
    xdp_kernel_crypto_secure_header_errors \
    xdp_kernel_crypto_frame_header_errors \
    xdp_kernel_crypto_epoch_sequence_mismatches \
    xdp_kernel_crypto_cipher_len_errors \
    xdp_kernel_crypto_cipher_load_errors \
    xdp_kernel_crypto_context_unavailable \
    xdp_kernel_crypto_epoch_mismatches \
    xdp_kernel_crypto_suite_mismatches \
    xdp_kernel_crypto_dynptr_errors \
    xdp_kernel_crypto_decrypt_errors \
    xdp_kernel_crypto_replay_commit_errors \
    xdp_kernel_crypto_store_errors \
    xdp_kernel_crypto_zero_plain_errors; do
    value="$(datapath_counter_value_or_zero "$file" "$name")"
    serious=$((serious + value))
  done

  seal_successes="$(datapath_counter_value_or_zero "$file" "kernel_crypto_frame_seal_successes")"
  if [[ "$seal_successes" == "0" ]]; then
    seal_successes="$(datapath_counter_value_or_zero "$file" "tx_kernel_crypto_packet_seal_successes")"
  fi
  budget=$((seal_successes / 1000))
  if [[ "$budget" -lt 64 ]]; then
    budget=64
  fi

  if [[ "$transport" == "experimental_tcp" && "$serious" == "0" && "$open_errors" -le "$replay_drops" && "$replay_drops" -le "$budget" ]]; then
    log "${node} experimental_tcp XDP kernel crypto saw ${replay_drops} replay drops within budget ${budget}; treating as duplicate-carrier noise"
    return 0
  fi

  die "${node} XDP kernel crypto open health failed: open_errors=${open_errors} replay_drops=${replay_drops} serious_errors=${serious} budget=${budget}"
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

module_param_value() {
  local name="$1"
  local path="/sys/module/trustix_datapath_helpers/parameters/${name}"
  [[ -r "$path" ]] || return 1
  cat "$path"
}

assert_datapath_module_param_positive() {
  local name="$1"
  local value
  value="$(module_param_value "$name" || true)"
  if [[ -z "$value" || "$value" -le 0 ]]; then
    die "trustix_datapath_helpers module parameter ${name} is not positive (value=${value:-missing})"
  fi
}

assert_experimental_tcp_route_xmit_worker_hit() {
  experimental_tcp_route_xmit_worker_enabled || return 0
  assert_datapath_module_param_positive "route_tcp_xmit_worker_enqueued"
  assert_datapath_module_param_positive "route_tcp_xmit_worker_xmit_ok"
}

assert_kernel_crypto_tx_path() {
  local node="$1"
  local datapath_file="$workdir/${node}-datapath.json"
  local bpf_file="$workdir/${node}-bpf.json"
  python3 - "$node" "$datapath_file" "$bpf_file" "$expect_tc_secure_direct" "$transport" <<'PY'
import json
import sys

node, datapath_path, bpf_path, expect_tc_direct, transport = sys.argv[1:6]

def load_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)

def fail(message):
    raise SystemExit(f"{node} {message}")

def datapath_counter(stats, key):
    try:
        return int(stats.get(key) or 0)
    except (TypeError, ValueError):
        return 0

def bpf_counter(payload, key):
    if isinstance(payload, dict):
        counters = payload.get("counters")
        if not isinstance(counters, list):
            stats = payload.get("stats")
            counters = stats.get("counters") if isinstance(stats, dict) else []
    else:
        counters = payload
    if not isinstance(counters, list):
        return 0
    for item in counters:
        if not isinstance(item, dict):
            continue
        if item.get("name") == key:
            try:
                return int(item.get("value") or 0)
            except (TypeError, ValueError):
                return 0
    return 0

datapath = load_json(datapath_path)
bpf = load_json(bpf_path)
selected = datapath.get("experimental_tcp") if transport == "experimental_tcp" else datapath.get("kernel_udp")
if not isinstance(selected, dict):
    selected = datapath
provider_stats = selected.get("provider_stats") if isinstance(selected, dict) else None
if not isinstance(provider_stats, dict):
    provider_stats = datapath.get("provider_stats") if isinstance(datapath.get("provider_stats"), dict) else {}
tc_direct = bpf_counter(bpf, "tc_kernel_udp_tx_secure_direct_packets")
af_xdp_tx = datapath_counter(provider_stats, "tx_kernel_crypto_packet_seal_successes")
device_tx = datapath_counter(provider_stats, "kernel_crypto_device_seal_successes")
frame_tx = datapath_counter(provider_stats, "kernel_crypto_frame_seal_successes")
frame_rx = datapath_counter(provider_stats, "kernel_crypto_frame_open_successes")
xdp_open = datapath_counter(provider_stats, "xdp_kernel_crypto_open_successes")
experimental_tx = bpf_counter(bpf, "experimental_tcp_tx_frames")
if expect_tc_direct == "1" and tc_direct > 0:
    if transport == "experimental_tcp" and xdp_open <= 0:
        fail("TC secure-direct TX succeeded but XDP kernel open did not")
    sys.exit(0)
if af_xdp_tx > 0:
    if xdp_open <= 0:
        fail("AF_XDP TX kernel_crypto sealed packets but XDP kernel open did not")
    sys.exit(0)
if device_tx > 0 and frame_tx > 0:
    if transport == "experimental_tcp":
        if xdp_open <= 0:
            fail("kernel device crypto sealed packets but XDP kernel open did not")
        if experimental_tx <= 0:
            fail("kernel device crypto sealed packets but experimental_tcp TX frames stayed zero")
    elif frame_rx <= 0:
        fail("kernel device crypto sealed packets but kernel frame open stayed zero")
    sys.exit(0)
if frame_tx > 0 and frame_rx > 0:
    sys.exit(0)
fail(
    "has no kernel crypto TX path: "
    f"tc_direct={tc_direct} af_xdp_tx={af_xdp_tx} device_tx={device_tx} "
    f"frame_tx={frame_tx} frame_rx={frame_rx} xdp_open={xdp_open}"
)
PY
}

assert_nat_reverse_status() {
  [[ "$nat_reverse" == "1" ]] || return 0
  log "validating NAT/no-public reverse data session"
  local reverse_transport="$transport"
  local reverse_endpoint="hk-udp"
  case "$transport" in
    tcp)
      reverse_endpoint="hk-tcp"
      ;;
    experimental_tcp)
      reverse_endpoint="hk-experimental-tcp"
      ;;
    kernel_udp)
      reverse_transport="udp"
      reverse_endpoint="hk-udp"
      ;;
  esac
  python3 - "$workdir/ix-a-datapath.json" "$workdir/ix-a-transports.json" "$reverse_transport" "$reverse_endpoint" <<'PY'
import json
import sys

datapath_path, transports_path, want_transport, want_endpoint = sys.argv[1:5]

def fail(message):
    raise SystemExit(message)

with open(datapath_path, "r", encoding="utf-8") as handle:
    datapath = json.load(handle)
with open(transports_path, "r", encoding="utf-8") as handle:
    transports = json.load(handle)

sessions = datapath.get("sessions") or []
reverse = [
    item for item in sessions
    if item.get("peer") == "ix-b"
    and item.get("transport") == want_transport
    and item.get("address") == "reverse://inbound"
    and item.get("reverse") is True
    and item.get("direction") == "inbound_reverse"
]
if not reverse:
    fail(f"ix-a datapath has no ix-b reverse://inbound {want_transport} session")

peer_endpoints = transports.get("peer_endpoints") or []
ix_b = [
    item for item in peer_endpoints
    if item.get("peer") == "ix-b" and item.get("name") == want_endpoint
]
if not ix_b:
    fail(f"ix-a transports has no ix-b {want_endpoint} peer endpoint")
endpoint = ix_b[0]
if endpoint.get("address"):
    fail(f"ix-a ix-b endpoint unexpectedly has public address {endpoint.get('address')!r}")
if not endpoint.get("reverse_only"):
    fail(f"ix-a ix-b endpoint is not marked reverse_only: {endpoint!r}")
if not endpoint.get("active_reverse_sessions"):
    fail(f"ix-a ix-b endpoint has no active reverse session: {endpoint!r}")
PY
}

assert_kernel_udp_status() {
  local node="$1"
  local datapath_path="$workdir/${node}-datapath.json"
  local doctor_path="$workdir/${node}-doctor.json"
  local bpf_path="$workdir/${node}-bpf.json"
  local direct_fastpath=0
  if kernel_plaintext_direct_fastpath_enabled || kernel_udp_secure_direct_enabled; then
    direct_fastpath=1
  fi

  python3 - "$datapath_path" "$doctor_path" "$node" "$direct_fastpath" <<'PY'
import json
import sys

datapath_path, doctor_path, node, direct_fastpath = sys.argv[1:5]
direct_fastpath = direct_fastpath == "1"

def fail(message):
    raise SystemExit(f"{node} {message}")

with open(datapath_path, "r", encoding="utf-8") as handle:
    datapath = json.load(handle)
with open(doctor_path, "r", encoding="utf-8") as handle:
    doctor = json.load(handle)

udp = datapath.get("kernel_udp")
if not isinstance(udp, dict):
    fail("datapath has no kernel_udp status")
for key in ("available", "fast_path", "reinject"):
    if udp.get(key) is not True:
        fail(f"kernel_udp {key} is not true: {udp!r}")
provider = udp.get("provider")
direct_only = udp.get("direct_only") is True or udp.get("tc_only") is True or provider == "tc_direct"
if provider not in ("af_xdp", "tc_direct"):
    fail(f"kernel_udp provider is not af_xdp/tc_direct: {provider!r}")
if provider == "af_xdp":
    if udp.get("userspace_crypto") is not True:
        fail(f"kernel_udp userspace_crypto is not true: {udp!r}")
    for key in ("xdp_attach_mode", "af_xdp_bind_mode"):
        if not udp.get(key):
            fail(f"kernel_udp has no {key}")
    if "zerocopy_enabled" not in udp:
        fail("kernel_udp has no zerocopy_enabled")
    if not direct_fastpath:
        for key in ("submitted_frames", "received_frames"):
            if int(udp.get(key) or 0) <= 0:
                fail(f"kernel_udp {key} is not positive: {udp.get(key)!r}")
elif not direct_only:
    fail(f"kernel_udp tc_direct provider is not direct-only: {udp!r}")
if int(udp.get("active_flows") or 0) <= 0:
    fail(f"kernel_udp active_flows is not positive: {udp.get('active_flows')!r}")
stats = udp.get("provider_stats") or {}
provider_stat_keys = ["allowed_ports"]
if provider == "af_xdp" and not direct_fastpath:
    provider_stat_keys.extend(["submitted_frames", "received_frames"])
for key in provider_stat_keys:
    if int(stats.get(key) or 0) <= 0:
        fail(f"kernel_udp provider_stats.{key} is not positive: {stats!r}")

kernel_transport = datapath.get("kernel_transport") or {}
if kernel_transport.get("mode") != "require_kernel":
    fail(f"kernel_transport mode is not require_kernel: {kernel_transport.get('mode')!r}")
udp_protocol = None
for item in kernel_transport.get("protocols") or []:
    if item.get("protocol") == "udp":
        udp_protocol = item
        break
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
for token in (f"provider={provider}", "fast_path=true", "reinject=true"):
    if token not in detail:
        fail(f"kernel_udp doctor detail missing {token!r}: {detail!r}")
PY

  assert_counter_positive "$bpf_path" "kernel_udp_allowed_ports"
  assert_counter_positive "$bpf_path" "kernel_udp_active_flows"
  if grep -q '"provider": "tc_direct"' "$datapath_path" || [[ "$direct_fastpath" == "1" ]]; then
    assert_hot_any_counter_positive "$bpf_path" "tc_kernel_udp_tx_direct_packets" "tc_kernel_udp_rx_direct_packets" "tc_kernel_udp_tx_secure_direct_packets" "tc_kernel_udp_rx_secure_direct_packets"
  else
    assert_counter_positive "$bpf_path" "kernel_udp_submitted_frames"
    assert_counter_positive "$bpf_path" "kernel_udp_received_frames"
  fi
}

assert_iptunnel_status() {
  local node="$1"
  local datapath_path="$workdir/${node}-datapath.json"
  local doctor_path="$workdir/${node}-doctor.json"
  local bpf_state_path="$workdir/state-${node#ix-}/bpf/state.json"
  local native_plaintext=0
  if is_plaintext_encryption "$(effective_transport_encryption)"; then
    native_plaintext=1
  fi

  python3 - "$datapath_path" "$doctor_path" "$bpf_state_path" "$node" "$transport" "$iptunnel_mtu" "$native_plaintext" <<'PY'
import json
import sys
from pathlib import Path

datapath_path, doctor_path, bpf_state_path, node, transport, want_mtu, native_plaintext = sys.argv[1:8]
want_mtu = int(want_mtu)
native_plaintext = native_plaintext == "1"

def fail(message):
    raise SystemExit(f"{node} {message}")

with open(datapath_path, "r", encoding="utf-8") as handle:
    datapath = json.load(handle)
with open(doctor_path, "r", encoding="utf-8") as handle:
    doctor = json.load(handle)

kernel_transport = datapath.get("kernel_transport") or {}
if kernel_transport.get("mode") != "require_kernel":
    fail(f"kernel_transport mode is not require_kernel: {kernel_transport.get('mode')!r}")
protocol = next((item for item in kernel_transport.get("protocols") or [] if item.get("protocol") == transport), None)
if not protocol:
    fail(f"kernel_transport has no {transport} protocol entry")
if protocol.get("available") is not True or protocol.get("capability_ready") is not True:
    fail(f"{transport} capability is not ready: {protocol!r}")
if protocol.get("placement") != "kernel" or protocol.get("userspace_fallback") is not False:
    fail(f"{transport} placement/fallback is unexpected: {protocol!r}")
if protocol.get("contract") != "trustix-kernel-tunnel-carrier-v1":
    fail(f"{transport} contract is unexpected: {protocol!r}")
if "mtu" not in (protocol.get("required_config") or []):
    fail(f"{transport} required_config has no mtu: {protocol!r}")
stats = kernel_transport.get("statistics") or {}
native_count = int(stats.get("native_tunnel_routes") or 0)
native_proto_count = int(stats.get(f"native_tunnel_routes_{transport}") or 0)
if native_plaintext and (native_count <= 0 or native_proto_count <= 0):
    fail(f"{transport} native route offload stats are missing: {stats!r}")
if native_plaintext:
    state_path = Path(bpf_state_path)
    if not state_path.exists():
        fail(f"native route offload has no persisted dataplane state: {state_path}")
    with state_path.open("r", encoding="utf-8") as handle:
        state = json.load(handle)
    native_routes = [
        item for item in state.get("native_tunnel_routes") or []
        if item.get("protocol") == transport and item.get("routeable") is True
    ]
    if not native_routes:
        fail(f"native route offload has no persisted {transport} route: {state.get('native_tunnel_routes')!r}")
    for item in native_routes:
        if int(item.get("mtu") or 0) != want_mtu:
            fail(f"{transport} native route mtu is unexpected: {item!r}")
for session in datapath.get("sessions") or []:
    if session.get("transport") != transport:
        continue
    extra = (session.get("stats") or {}).get("extra") or {}
    if int(extra.get("iptunnel_mtu") or 0) != want_mtu:
        fail(f"{transport} session mtu extra is unexpected: {extra!r}")
    for key in ("iptunnel_mtu_drops", "iptunnel_decode_errors"):
        if int(extra.get(key) or 0) != 0:
            fail(f"{transport} session {key} is not zero: {extra!r}")
    break
else:
    if not native_plaintext:
        fail(f"datapath has no active {transport} session")

doctor_check = next((item for item in doctor if item.get("name") == "kernel_transport"), None)
if not doctor_check:
    fail("doctor has no kernel_transport check")
if doctor_check.get("status") != "ok":
    fail(f"kernel_transport doctor is not ok: {doctor_check!r}")
detail = doctor_check.get("detail", "")
for token in (f"{transport}=kernel/true", "capability=true", "fallback=false"):
    if token not in detail:
        fail(f"kernel_transport doctor detail missing {token!r}: {detail!r}")
PY
}

assert_json_number_positive() {
  local file="$1"
  local name="$2"
  local value
  value="$(json_number_value "$file" "$name")"
  if [[ -z "$value" || "$value" -le 0 ]]; then
    die "json number ${name} in ${file} is not positive (value=${value:-missing})"
  fi
}

assert_json_number_zero() {
  local file="$1"
  local name="$2"
  local value
  value="$(json_number_value "$file" "$name")"
  if [[ -z "$value" || "$value" != "0" ]]; then
    die "json number ${name} in ${file} is not zero (value=${value:-missing})"
  fi
}

assert_tls_only_datapath_session() {
  local file="$1"
  python3 - "$file" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as handle:
    data = json.load(handle)
sessions = data.get("sessions") or []
for session in sessions:
    stats = session.get("stats") or {}
    if session.get("transport") != "tcp" or not stats.get("link_tls"):
        continue
    errors = []
    if stats.get("encryption") != "plaintext":
        errors.append(f"encryption={stats.get('encryption')!r}")
    for key in ("encrypted", "send_encrypted", "receive_encrypted"):
        if stats.get(key, False):
            errors.append(f"{key}={stats.get(key)!r}")
    for key in ("crypto_suite", "crypto_key_source", "crypto_placement"):
        if stats.get(key):
            errors.append(f"{key}={stats.get(key)!r}")
    if errors:
        raise SystemExit(f"TLS-only session still reports TrustIX data crypto: {', '.join(errors)}")
    raise SystemExit(0)
raise SystemExit("datapath has no TCP LinkTLS session for TLS-only assertion")
PY
}

json_number_value() {
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

assert_route_kind_probe() {
  [[ "$route_kind_probe" == "1" ]] || return 0
  [[ "$dataplane" == "linux" || "$dataplane" == "auto" ]] || return 0
  if native_tunnel_plaintext_route_offload_enabled; then
    log "skipping TC blackhole/reject route-kind probe: native plaintext tunnel route offload bypasses LAN TC"
    return 0
  fi
  local config_path="$1"
  local data_dir="$2"
  local api_url="$3"
  local api_addr="$4"
  local peer_api_addr="$5"
  local ns="${6:-}"

  log "validating TC blackhole/reject route kinds"
  local probe_config="$workdir/config-ix-a-route-kind-probe.yaml"
  local baseline_config="$workdir/config-ix-a-route-kind-baseline.yaml"
  run_ctl "$ns" -api "$api_url" config desired >"$baseline_config"
  awk '
    /^policies:/ && !inserted {
      print "  - prefix: 10.250.1.0/24"
      print "    kind: blackhole"
      print "    metric: 1"
      print "  - prefix: 10.250.2.0/24"
      print "    kind: reject"
      print "    metric: 1"
      inserted=1
    }
    { print }
  ' "$config_path" >"$probe_config"
  grep -q '10.250.1.0/24' "$probe_config" || die "route kind probe config was not generated"
  run_ctl "$ns" -api "$api_url" config apply "$probe_config" >"$workdir/ix-a-route-kind-apply.json"
  for _ in $(seq 1 40); do
    run_ctl "$ns" -api "$api_url" routes >"$workdir/ix-a-route-kind-routes.json"
    grep -q '10.250.1.0/24' "$workdir/ix-a-route-kind-routes.json" && break
    sleep 0.1
  done
  grep -q '10.250.1.0/24' "$workdir/ix-a-route-kind-routes.json" || die "route kind probe route was not applied"
  run_in_netns "$ns_a" ping -c 1 -W 1 10.250.1.2 >/dev/null 2>&1 || true
  run_in_netns "$ns_a" ping -c 1 -W 1 10.250.2.2 >/dev/null 2>&1 || true
  collect_api ix-a-route-kind "$api_url" "$ns"
  assert_counter_positive "$workdir/ix-a-route-kind-bpf.json" "tc_ingress_blackhole_routes"
  assert_counter_positive "$workdir/ix-a-route-kind-bpf.json" "tc_ingress_reject_routes"
  assert_counter_positive "$workdir/ix-a-route-kind-bpf.json" "tc_reject_icmp_generated"
  grep -q '"BLACKHOLE_ROUTE":' "$workdir/ix-a-route-kind-datapath.json" || die "route kind probe has no BLACKHOLE_ROUTE drop reason"
  grep -q '"REJECT_ROUTE":' "$workdir/ix-a-route-kind-datapath.json" || die "route kind probe has no REJECT_ROUTE drop reason"
  run_ctl "$ns" -api "$api_url" config apply "$baseline_config" >"$workdir/ix-a-route-kind-restore.json"
}

maybe_prepare_kernel_module() {
  if [[ "$kernel_module" != "1" ]]; then
    return 0
  fi
  if [[ "$transport" != "experimental_tcp" && "$transport" != "kernel_udp" ]]; then
    die "TRUSTIX_E2E_KERNEL_MODULE=1 requires TRUSTIX_E2E_TRANSPORT=experimental_tcp or kernel_udp"
  fi
  [[ -f "$kernel_script" ]] || die "TrustIX kernel module smoke script not found: $kernel_script"

  log "preparing TrustIX kernel module through ${kernel_script}"
  local vaes_kfunc=0
  local extra_module_params
  if effective_kernel_experimental_vaes_kfunc; then
    vaes_kfunc=1
  fi
  extra_module_params="$(kernel_extra_module_params)"
  if [[ -n "$kernel_test_bin" ]]; then
    env \
      TRUSTIX_CRYPTO_MODULE_DIR="$kernel_module_dir" \
      TRUSTIX_KERNEL_KEEP_LOADED=1 \
      TRUSTIX_KERNEL_LOAD_ONLY="$(effective_kernel_load_only && printf 1 || printf 0)" \
      TRUSTIX_KERNEL_TEST_BIN="$kernel_test_bin" \
      TRUSTIX_KERNEL_EXPERIMENTAL_VAES="$(effective_kernel_experimental_vaes && printf 1 || printf 0)" \
      TRUSTIX_KERNEL_EXPERIMENTAL_VAES_KFUNC="$vaes_kfunc" \
      TRUSTIX_KERNEL_ALLOW_UNSUPPORTED_KERNEL="${TRUSTIX_E2E_KERNEL_ALLOW_UNSUPPORTED_KERNEL:-1}" \
      TRUSTIX_KERNEL_EXTRA_MODULE_PARAMS="$extra_module_params" \
      TRUSTIX_EXPERIMENTAL_TCP_SKIP_TCP_CHECKSUM=0 \
      TRUSTIX_EXPERIMENTAL_TCP_SKIP_CHECKSUM=0 \
      bash "$kernel_script"
    return 0
  fi
  env \
    TRUSTIX_CRYPTO_MODULE_DIR="$kernel_module_dir" \
    TRUSTIX_KERNEL_KEEP_LOADED=1 \
    TRUSTIX_KERNEL_LOAD_ONLY="$(effective_kernel_load_only && printf 1 || printf 0)" \
    TRUSTIX_KERNEL_EXPERIMENTAL_VAES="$(effective_kernel_experimental_vaes && printf 1 || printf 0)" \
    TRUSTIX_KERNEL_EXPERIMENTAL_VAES_KFUNC="$vaes_kfunc" \
    TRUSTIX_KERNEL_ALLOW_UNSUPPORTED_KERNEL="${TRUSTIX_E2E_KERNEL_ALLOW_UNSUPPORTED_KERNEL:-1}" \
    TRUSTIX_KERNEL_EXTRA_MODULE_PARAMS="$extra_module_params" \
    TRUSTIX_EXPERIMENTAL_TCP_SKIP_TCP_CHECKSUM=0 \
    TRUSTIX_EXPERIMENTAL_TCP_SKIP_CHECKSUM=0 \
    bash "$kernel_script"
}

maybe_prepare_datapath_module() {
  datapath_module_needed || return 0
  [[ -f "$datapath_script" ]] || die "TrustIX datapath module smoke script not found: $datapath_script"

  local extra_module_params
  extra_module_params="$(datapath_extra_module_params)"
  log "preparing TrustIX datapath module through ${datapath_script}"
  env \
    TRUSTIX_DATAPATH_MODULE_DIR="$datapath_module_dir" \
    TRUSTIX_DATAPATH_KEEP_LOADED=1 \
    TRUSTIX_DATAPATH_ENABLE_FEATURES="$datapath_enable_features" \
    TRUSTIX_DATAPATH_EXTRA_MODULE_PARAMS="$extra_module_params" \
    TRUSTIX_DATAPATH_KERNELMODULE_TEST_BIN="${TRUSTIX_E2E_DATAPATH_KERNELMODULE_TEST_BIN:-${TRUSTIX_KERNEL_KERNELMODULE_TEST_BIN:-}}" \
    bash "$datapath_script"
}

maybe_prepare_full_datapath_module() {
  full_datapath_module_needed || return 0
  [[ -f "$full_datapath_script" ]] || die "TrustIX full datapath module smoke script not found: $full_datapath_script"

  local extra_module_params
  extra_module_params="$(full_datapath_extra_module_params)"
  log "preparing TrustIX full datapath module through ${full_datapath_script}"
  env \
    TRUSTIX_FULL_DATAPATH_MODULE_DIR="$full_datapath_module_dir" \
    TRUSTIX_FULL_DATAPATH_KO="$full_datapath_ko" \
    TRUSTIX_FULL_DATAPATH_KEEP_LOADED=1 \
    TRUSTIX_FULL_DATAPATH_ENABLE_FEATURES="$full_datapath_enable_features" \
    TRUSTIX_FULL_DATAPATH_EXTRA_PARAMS="$extra_module_params" \
    TRUSTIX_FULL_DATAPATH_IOCTL_SELFTEST="${TRUSTIX_E2E_FULL_DATAPATH_IOCTL_SELFTEST:-${TRUSTIX_FULL_DATAPATH_IOCTL_SELFTEST:-1}}" \
    TRUSTIX_FULL_DATAPATH_VERIFY_SAFE_DEFAULTS="${TRUSTIX_E2E_FULL_DATAPATH_VERIFY_SAFE_DEFAULTS:-${TRUSTIX_FULL_DATAPATH_VERIFY_SAFE_DEFAULTS:-1}}" \
    TRUSTIX_FULL_DATAPATH_KERNELMODULE_TEST_BIN="${TRUSTIX_E2E_FULL_DATAPATH_KERNELMODULE_TEST_BIN:-${TRUSTIX_KERNEL_KERNELMODULE_TEST_BIN:-}}" \
    bash "$full_datapath_script"
}

run_experimental_tcp_negative_probes() {
  if [[ "$transport" != "experimental_tcp" ]]; then
    return 0
  fi
  need_cmd perl
  log "injecting experimental_tcp unauthorized-port and bad-checksum probes"
  run_in_netns "$ns_ix_a" perl - "$underlay_ip_a" "$underlay_ip_b" "$exp_tcp_b_port" <<'PL'
use strict;
use warnings;
use Socket qw(AF_INET SOCK_RAW IPPROTO_RAW IPPROTO_TCP IPPROTO_IP sockaddr_in inet_aton);

my ($src_ip, $dst_ip, $allowed_port) = @ARGV;
my $unauthorized_port = $allowed_port + 97;
$unauthorized_port = $allowed_port - 97 if $unauthorized_port > 65535;

sub checksum {
  my ($payload) = @_;
  $payload .= "\0" if length($payload) % 2;
  my $sum = 0;
  for (my $i = 0; $i < length($payload); $i += 2) {
    $sum += unpack("n", substr($payload, $i, 2));
    $sum = ($sum & 0xffff) + ($sum >> 16);
  }
  while ($sum >> 16) {
    $sum = ($sum & 0xffff) + ($sum >> 16);
  }
  return (~$sum) & 0xffff;
}

sub frame_payload {
  my ($seq) = @_;
  return "TIXT" .
    pack("CCn", 1, 0, 40) .
    pack("NN", 0x12345678, 0x9abcdef0) .
    pack("NN", 0, 0) .
    pack("NN", 0, $seq) .
    pack("N", 0) .
    ("\0" x 4);
}

sub packet {
  my ($dst_port, $seq, $corrupt_tcp) = @_;
  my $payload = frame_payload($seq);
  my $src = inet_aton($src_ip);
  my $dst = inet_aton($dst_ip);
  my $total_len = 20 + 20 + length($payload);
  my $ip = pack("CCnnnCCna4a4", 0x45, 0, $total_len, 0, 0x4000, 64, IPPROTO_TCP, 0, $src, $dst);
  substr($ip, 10, 2) = pack("n", checksum($ip));

  my $tcp = pack("nnNNCCnnn", 43000 + ($seq % 1000), $dst_port, $seq, 1, 0x50, 0x18, 0xffff, 0, 0) . $payload;
  my $pseudo = $src . $dst . pack("CCn", 0, IPPROTO_TCP, length($tcp));
  my $tcp_sum = checksum($pseudo . $tcp);
  $tcp_sum ^= 0xffff if $corrupt_tcp;
  substr($tcp, 16, 2) = pack("n", $tcp_sum);
  return $ip . $tcp;
}

socket(my $sock, AF_INET, SOCK_RAW, IPPROTO_RAW) or die "socket: $!";
setsockopt($sock, IPPROTO_IP, 3, pack("i", 1)) or die "IP_HDRINCL: $!";
for my $i (0..4) {
  send($sock, packet($unauthorized_port, 1000 + $i, 0), 0, sockaddr_in($unauthorized_port, inet_aton($dst_ip))) or die "send unauthorized: $!";
}
for my $i (0..4) {
  send($sock, packet($allowed_port, 2000 + $i, 1), 0, sockaddr_in($allowed_port, inet_aton($dst_ip))) or die "send checksum: $!";
}
select(undef, undef, undef, 0.2);
PL
}

validate_observability() {
  log "validating dataplane counters and capture output"
  local expected_crypto="userspace"
  local expect_tc_secure_direct=0
  assert_experimental_tcp_route_xmit_worker_hit
  if [[ "$crypto_placement" == "kernel" ]]; then
    expected_crypto="kernel"
  elif [[ "$crypto_placement" == "auto" ]] && kernel_provider_expected; then
    expected_crypto="kernel"
  fi
  if [[ "$expected_crypto" == "kernel" ]] && truthy "${TRUSTIX_E2E_KERNEL_UDP_TC_TX_SECURE_DIRECT:-0}" && [[ "$transport" == "experimental_tcp" || "$transport" == "kernel_udp" ]]; then
    expect_tc_secure_direct=1
  fi
  if native_tunnel_plaintext_route_offload_enabled; then
    :
  elif kernel_plaintext_direct_fastpath_enabled; then
    assert_hot_any_counter_positive "$workdir/ix-a-bpf.json" "tc_ingress_route_hits" "tc_kernel_udp_tx_direct_packets" "tc_kernel_udp_rx_direct_packets"
    assert_hot_any_counter_positive "$workdir/ix-b-bpf.json" "tc_ingress_route_hits" "tc_kernel_udp_tx_direct_packets" "tc_kernel_udp_rx_direct_packets"
  elif [[ "$expect_tc_secure_direct" == "1" ]]; then
    assert_hot_any_counter_positive "$workdir/ix-a-bpf.json" "tc_ingress_route_hits" "tc_kernel_udp_tx_secure_direct_packets" "tc_kernel_udp_rx_secure_direct_packets"
    assert_hot_any_counter_positive "$workdir/ix-b-bpf.json" "tc_ingress_route_hits" "tc_kernel_udp_tx_secure_direct_packets" "tc_kernel_udp_rx_secure_direct_packets"
  else
    assert_hot_counter_positive "$workdir/ix-a-bpf.json" "tc_ingress_route_hits"
    assert_hot_counter_positive "$workdir/ix-b-bpf.json" "tc_ingress_route_hits"
  fi
  if ! native_tunnel_plaintext_route_offload_enabled; then
    assert_hot_any_counter_positive "$workdir/ix-a-bpf.json" "tc_capture_events" "tc_kernel_udp_tx_direct_packets" "tc_kernel_udp_tx_secure_direct_packets" "tc_kernel_udp_rx_direct_packets" "tc_kernel_udp_rx_secure_direct_packets"
    assert_hot_any_counter_positive "$workdir/ix-b-bpf.json" "tc_capture_events" "tc_kernel_udp_tx_direct_packets" "tc_kernel_udp_tx_secure_direct_packets" "tc_kernel_udp_rx_direct_packets" "tc_kernel_udp_rx_secure_direct_packets"
    assert_datapath_or_hot_bpf_counter_positive "$workdir/ix-a-datapath.json" "packets_sent" "$workdir/ix-a-bpf.json" "tc_kernel_udp_tx_direct_packets" "tc_kernel_udp_tx_secure_direct_packets"
    assert_datapath_or_hot_bpf_counter_positive "$workdir/ix-b-datapath.json" "packets_sent" "$workdir/ix-b-bpf.json" "tc_kernel_udp_tx_direct_packets" "tc_kernel_udp_tx_secure_direct_packets"
    assert_datapath_or_hot_bpf_counter_positive "$workdir/ix-a-datapath.json" "packets_received" "$workdir/ix-a-bpf.json" "tc_kernel_udp_rx_direct_packets" "tc_kernel_udp_rx_secure_direct_packets"
    assert_datapath_or_hot_bpf_counter_positive "$workdir/ix-b-datapath.json" "packets_received" "$workdir/ix-b-bpf.json" "tc_kernel_udp_rx_direct_packets" "tc_kernel_udp_rx_secure_direct_packets"
    assert_datapath_or_hot_bpf_counter_positive "$workdir/ix-a-datapath.json" "packets_injected" "$workdir/ix-a-bpf.json" "tc_kernel_udp_rx_direct_packets" "tc_kernel_udp_rx_secure_direct_packets"
    assert_datapath_or_hot_bpf_counter_positive "$workdir/ix-b-datapath.json" "packets_injected" "$workdir/ix-b-bpf.json" "tc_kernel_udp_rx_direct_packets" "tc_kernel_udp_rx_secure_direct_packets"
  fi
  grep -q '"name": "firewall_compat"' "$workdir/ix-a-doctor.json" || die "ix-a doctor has no firewall_compat check"
  grep -q '"name": "firewall_compat"' "$workdir/ix-b-doctor.json" || die "ix-b doctor has no firewall_compat check"
  if [[ "$lan_mode" == "nat" ]]; then
    grep -q '"nat": {' "$workdir/ix-a-datapath.json" || die "ix-a datapath has no NAT status"
    grep -q '"nat": {' "$workdir/ix-b-datapath.json" || die "ix-b datapath has no NAT status"
    assert_counter_positive "$workdir/ix-a-bpf.json" "tc_nat_snat_translations"
    assert_counter_positive "$workdir/ix-b-bpf.json" "tc_nat_snat_translations"
    assert_counter_positive "$workdir/ix-a-bpf.json" "tc_nat_dnat_translations"
    assert_counter_positive "$workdir/ix-b-bpf.json" "tc_nat_dnat_translations"
    assert_counter_positive "$workdir/ix-a-bpf.json" "tc_nat_bindings"
    assert_counter_positive "$workdir/ix-b-bpf.json" "tc_nat_bindings"
    grep -A1 '"name": "tc_nat_errors"' "$workdir/ix-a-bpf.json" | grep -q '"value": 0' || die "ix-a TC NAT errors are non-zero"
    grep -A1 '"name": "tc_nat_errors"' "$workdir/ix-b-bpf.json" | grep -q '"value": 0' || die "ix-b TC NAT errors are non-zero"
    grep -A1 '"name": "tc_nat_binding_sync_errors"' "$workdir/ix-a-bpf.json" | grep -q '"value": 0' || die "ix-a TC NAT binding sync errors are non-zero"
    grep -A1 '"name": "tc_nat_binding_sync_errors"' "$workdir/ix-b-bpf.json" | grep -q '"value": 0' || die "ix-b TC NAT binding sync errors are non-zero"
    assert_datapath_counter_positive "$workdir/ix-a-datapath.json" "nat_translations"
    assert_datapath_counter_positive "$workdir/ix-b-datapath.json" "nat_translations"
    assert_datapath_counter_positive "$workdir/ix-a-datapath.json" "nat_reverse_hits"
    assert_datapath_counter_positive "$workdir/ix-b-datapath.json" "nat_reverse_hits"
  fi
  if native_tunnel_plaintext_route_offload_enabled; then
    :
  elif kernel_plaintext_direct_fastpath_enabled && grep -q '"capture_forwarder_suppressed": true' "$workdir/ix-a-datapath.json"; then
    grep -q '"capture_forwarder_suppressed": true' "$workdir/ix-b-datapath.json" || die "ix-b capture forwarder suppression does not match ix-a"
  else
    grep -q '"capture_forwarder_active": true' "$workdir/ix-a-datapath.json" || die "ix-a capture forwarder is not active"
    grep -q '"capture_forwarder_active": true' "$workdir/ix-b-datapath.json" || die "ix-b capture forwarder is not active"
  fi
  for node in ix-a ix-b; do
    grep -q '"runtime":' "$workdir/${node}-status.json" || die "${node} status has no runtime resource block"
    grep -q '"data_dir_lock_held": true' "$workdir/${node}-status.json" || die "${node} status does not report held data-dir lock"
    grep -q '"data_dir_lock_path":' "$workdir/${node}-status.json" || die "${node} status has no data-dir lock path"
    grep -q '"go_heap_alloc_bytes":' "$workdir/${node}-status.json" || die "${node} status has no Go heap resource gauge"
    grep -q '"rss_bytes":' "$workdir/${node}-status.json" || die "${node} status has no RSS resource gauge"
    grep -q '"open_fds":' "$workdir/${node}-status.json" || die "${node} status has no FD resource gauge"
    grep -q '"name": "runtime_resources"' "$workdir/${node}-doctor.json" || die "${node} doctor has no runtime resource check"
  done
  if capture_history_enabled && ! native_tunnel_plaintext_route_offload_enabled; then
    if ! grep -q '"hook": "lan_ingress_route_hit"' "$workdir/ix-a-capture.json"; then
      assert_hot_any_counter_positive "$workdir/ix-a-bpf.json" "tc_kernel_udp_tx_direct_packets" "tc_kernel_udp_tx_secure_direct_packets" "tc_kernel_udp_rx_direct_packets"
    fi
    if ! grep -q '"hook": "lan_ingress_route_hit"' "$workdir/ix-b-capture.json"; then
      assert_hot_any_counter_positive "$workdir/ix-b-bpf.json" "tc_kernel_udp_tx_direct_packets" "tc_kernel_udp_tx_secure_direct_packets" "tc_kernel_udp_rx_direct_packets"
    fi
  fi
  route_table_covers_management_vip "$workdir/ix-a-routes.json" "10.0.1.1" "ix-b" || die "ix-a routes do not cover ix-b management VIP"
  route_table_covers_management_vip "$workdir/ix-b-routes.json" "10.0.0.1" "ix-a" || die "ix-b routes do not cover ix-a management VIP"
  if [[ "$transport" == "experimental_tcp" ]]; then
    for node in ix-a ix-b; do
      grep -q '"provider": "af_xdp"' "$workdir/${node}-datapath.json" || die "${node} experimental_tcp provider is not af_xdp"
      grep -q '"fast_path": true' "$workdir/${node}-datapath.json" || die "${node} experimental_tcp fast_path is not true"
      grep -q '"reinject": true' "$workdir/${node}-datapath.json" || die "${node} experimental_tcp reinject is not true"
      grep -q '"raw_socket_fallback": false' "$workdir/${node}-datapath.json" || die "${node} raw socket fallback is enabled"
      grep -q '"xdp_attach_mode":' "$workdir/${node}-datapath.json" || die "${node} experimental_tcp status has no xdp_attach_mode"
      grep -q '"af_xdp_bind_mode":' "$workdir/${node}-datapath.json" || die "${node} experimental_tcp status has no af_xdp_bind_mode"
      grep -q '"zerocopy_enabled":' "$workdir/${node}-datapath.json" || die "${node} experimental_tcp status has no zerocopy_enabled"
      assert_datapath_any_counter_positive "$workdir/${node}-datapath.json" "xdp_attach_native" "xdp_attach_skb"
      assert_datapath_any_counter_positive "$workdir/${node}-datapath.json" "af_xdp_bind_zerocopy" "af_xdp_bind_copy"
      if [[ "$expected_crypto" == "kernel" ]]; then
        assert_datapath_counter_positive "$workdir/${node}-datapath.json" "kernel_udp_xdp_open"
        assert_datapath_counter_positive "$workdir/${node}-datapath.json" "kernel_udp_xdp_pass_opened"
        if truthy "$kernel_udp_xdp_rx_direct"; then
          assert_any_counter_positive "$workdir/${node}-bpf.json" "xdp_kernel_udp_rx_direct_attached" "xdp_kernel_udp_rx_direct_veth_fallback"
        fi
      fi
      if kernel_provider_expected; then
        grep -q '"kernel_crypto": true' "$workdir/${node}-datapath.json" || die "${node} kernel crypto is not enabled with trustix_crypto"
      else
        grep -q '"kernel_crypto": false' "$workdir/${node}-datapath.json" || die "${node} kernel crypto is unexpectedly enabled"
      fi
      grep -q '"kernel_crypto_probe":' "$workdir/${node}-datapath.json" || die "${node} datapath has no kernel crypto probe"
      grep -q '"self_test":' "$workdir/${node}-datapath.json" || die "${node} datapath has no kernel crypto selftest status"
      grep -q '"map_schema":' "$workdir/${node}-datapath.json" || die "${node} datapath has no kernel crypto map schema"
      if kernel_provider_expected; then
        grep -q '"provider_ready": true' "$workdir/${node}-datapath.json" || die "${node} kernel crypto provider is not ready with trustix_crypto"
      else
        grep -q '"provider_ready": false' "$workdir/${node}-datapath.json" || die "${node} kernel crypto provider is unexpectedly ready"
      fi
      grep -q '"kernel_crypto_map_key_size": 16' "$workdir/${node}-datapath.json" || die "${node} provider stats has no kernel crypto key size"
      grep -q '"kernel_crypto_map_value_size": 112' "$workdir/${node}-datapath.json" || die "${node} provider stats has no kernel crypto value size"
      grep -q '"kernel_crypto_flow_map_ready":' "$workdir/${node}-datapath.json" || die "${node} provider stats has no kernel crypto flow map readiness"
      if [[ "$crypto_placement" == "kernel" ]]; then
        assert_datapath_counter_positive "$workdir/${node}-datapath.json" "kernel_crypto_flow_map_entries"
      else
        grep -q '"kernel_crypto_flow_map_entries": 0' "$workdir/${node}-datapath.json" || die "${node} kernel crypto flow map should not retain key entries"
      fi
      grep -q '"kernel_crypto_ctx_provider_loaded":' "$workdir/${node}-datapath.json" || die "${node} provider stats has no kernel crypto ctx provider load state"
      grep -q '"kernel_crypto_aead_gcm_ctx_create_attempts":' "$workdir/${node}-datapath.json" || die "${node} provider stats has no AEAD-GCM ctx create probe"
      grep -q '"kernel_crypto_aead_gcm_roundtrip_attempts":' "$workdir/${node}-datapath.json" || die "${node} provider stats has no AEAD-GCM roundtrip probe"
      grep -q '"kernel_crypto_frame_seal_attempts":' "$workdir/${node}-datapath.json" || die "${node} provider stats has no frame seal probe"
      grep -q '"kernel_crypto_frame_open_attempts":' "$workdir/${node}-datapath.json" || die "${node} provider stats has no frame open probe"
      if kernel_provider_expected; then
        assert_datapath_counter_positive "$workdir/${node}-datapath.json" "kernel_crypto_ctx_provider_loaded"
        assert_datapath_counter_positive "$workdir/${node}-datapath.json" "kernel_crypto_aead_gcm_ctx_create_successes"
        assert_datapath_counter_positive "$workdir/${node}-datapath.json" "kernel_crypto_aead_gcm_roundtrip_successes"
        grep -q '"kernel_crypto_ctx_provider_load_errors": 0' "$workdir/${node}-datapath.json" || die "${node} kernel AEAD provider load errors are non-zero"
        grep -q '"kernel_crypto_aead_gcm_ctx_create_errors": 0' "$workdir/${node}-datapath.json" || die "${node} kernel AEAD ctx create errors are non-zero"
        grep -q '"kernel_crypto_aead_gcm_roundtrip_errors": 0' "$workdir/${node}-datapath.json" || die "${node} kernel AEAD roundtrip errors are non-zero"
      fi
      grep -q '"kernel_crypto_provider_unavailable_errors": 0' "$workdir/${node}-datapath.json" || die "${node} kernel crypto provider rejection counter is unexpected"
      grep -q "\"requested_crypto\": \"${crypto_placement}\"" "$workdir/${node}-datapath.json" || die "${node} requested crypto is not ${crypto_placement}"
      if [[ "$expected_crypto" == "kernel" ]]; then
        grep -q '"effective_crypto": "kernel"' "$workdir/${node}-datapath.json" || die "${node} effective crypto is not kernel"
        assert_datapath_counter_positive "$workdir/${node}-datapath.json" "kernel_crypto_install_attempts"
        assert_datapath_counter_positive "$workdir/${node}-datapath.json" "kernel_crypto_flow_map_updates"
        if [[ "$expect_tc_secure_direct" != "1" ]]; then
          assert_datapath_counter_positive "$workdir/${node}-datapath.json" "kernel_crypto_frame_seal_successes"
        fi
        assert_datapath_counter_positive "$workdir/${node}-datapath.json" "kernel_crypto_rx_attached"
        if hot_stats_enabled; then
          assert_datapath_any_counter_positive "$workdir/${node}-datapath.json" "kernel_crypto_frame_open_successes" "xdp_kernel_crypto_open_successes"
          assert_kernel_crypto_tx_path "$node"
          assert_datapath_counter_positive "$workdir/${node}-datapath.json" "xdp_kernel_crypto_open_attempts"
          assert_datapath_counter_positive "$workdir/${node}-datapath.json" "xdp_kernel_crypto_open_successes"
        fi
        if [[ "$expect_tc_secure_direct" != "1" ]]; then
          assert_datapath_counter_positive "$workdir/${node}-datapath.json" "tx_umem_direct_build_frames"
        fi
        grep -q '"kernel_crypto_frame_seal_errors": 0' "$workdir/${node}-datapath.json" || die "${node} kernel frame seal errors are non-zero"
        grep -q '"kernel_crypto_frame_open_errors": 0' "$workdir/${node}-datapath.json" || die "${node} kernel frame open errors are non-zero"
        assert_xdp_kernel_crypto_open_health "$workdir/${node}-datapath.json" "$node"
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
        if ! kernel_plaintext_direct_fastpath_enabled; then
          assert_datapath_counter_positive "$workdir/${node}-datapath.json" "tx_umem_direct_build_frames"
        fi
      fi
      grep -q '"name": "experimental_tcp"' "$workdir/${node}-doctor.json" || die "${node} doctor has no experimental_tcp check"
      grep -q 'selftest_attempted=' "$workdir/${node}-doctor.json" || die "${node} doctor has no kernel crypto selftest state"
      grep -q 'crypto_map_key_size=16' "$workdir/${node}-doctor.json" || die "${node} doctor has no kernel crypto map schema detail"
      assert_counter_positive "$workdir/${node}-bpf.json" "experimental_tcp_allowed_ports"
      assert_datapath_counter_positive "$workdir/${node}-datapath.json" "umem_bytes_total"
      if ! kernel_plaintext_direct_fastpath_enabled; then
        assert_datapath_counter_positive "$workdir/${node}-datapath.json" "rx_frames"
      fi
      if [[ "$node" == "ix-b" ]]; then
        assert_hot_counter_positive "$workdir/${node}-bpf.json" "experimental_tcp_xdp_unauthorized_drops"
        if [[ "$experimental_tcp_skip_checksum" == "1" ]]; then
          assert_datapath_counter_positive "$workdir/${node}-datapath.json" "skip_tcp_checksum"
          if [[ "$expected_crypto" == "kernel" ]]; then
            assert_hot_counter_positive "$workdir/${node}-bpf.json" "experimental_tcp_xdp_kernel_crypto_tcp_checksum_skipped"
          fi
        else
          assert_hot_counter_positive "$workdir/${node}-bpf.json" "experimental_tcp_rx_checksum_errors"
          grep -q '"CHECKSUM_ERROR":' "$workdir/${node}-datapath.json" || die "${node} datapath has no CHECKSUM_ERROR drop reason"
        fi
      fi
      if [[ "$expect_tc_secure_direct" == "1" ]]; then
        assert_datapath_or_hot_bpf_counter_positive "$workdir/${node}-datapath.json" "tx_umem_direct_build_frames" "$workdir/${node}-bpf.json" "tc_kernel_udp_tx_secure_direct_packets" "experimental_tcp_tx_frames"
      elif kernel_plaintext_direct_fastpath_enabled; then
        assert_datapath_or_hot_bpf_counter_positive "$workdir/${node}-datapath.json" "tx_umem_direct_build_frames" "$workdir/${node}-bpf.json" "tc_kernel_udp_tx_direct_packets" "experimental_tcp_tx_frames"
      else
        assert_datapath_counter_positive "$workdir/${node}-datapath.json" "tx_umem_direct_build_frames"
      fi
      if kernel_plaintext_direct_fastpath_enabled; then
        assert_datapath_or_hot_bpf_counter_positive "$workdir/${node}-datapath.json" "rx_frames" "$workdir/${node}-bpf.json" "tc_kernel_udp_rx_direct_packets" "experimental_tcp_rx_frames"
      else
        assert_datapath_counter_positive "$workdir/${node}-datapath.json" "rx_frames"
        assert_datapath_counter_positive "$workdir/${node}-datapath.json" "rx_umem_direct_frames"
      fi
      assert_datapath_counter_zero "$workdir/${node}-datapath.json" "tx_pool_exhausted"
      assert_datapath_counter_zero "$workdir/${node}-datapath.json" "tx_ring_full"
      assert_datapath_counter_zero "$workdir/${node}-datapath.json" "tx_kick_errors"
      grep -q '"tx_backpressure_waits":' "$workdir/${node}-datapath.json" || die "${node} datapath has no TX backpressure wait counter"
      grep -q '"tx_backpressure_reclaims":' "$workdir/${node}-datapath.json" || die "${node} datapath has no TX backpressure reclaim counter"
      assert_datapath_counter_zero "$workdir/${node}-datapath.json" "tx_backpressure_timeouts"
      assert_datapath_counter_zero "$workdir/${node}-datapath.json" "rx_invalid"
      assert_datapath_counter_zero "$workdir/${node}-datapath.json" "rx_recycle_errors"
      if ! grep -q '"route_stats":' "$workdir/${node}-datapath.json"; then
        assert_hot_any_counter_positive "$workdir/${node}-bpf.json" "tc_kernel_udp_tx_direct_packets" "tc_kernel_udp_rx_direct_packets" "tc_kernel_udp_tx_secure_direct_packets"
      fi
      if ! grep -q '"endpoint_stats":' "$workdir/${node}-datapath.json"; then
        assert_hot_any_counter_positive "$workdir/${node}-bpf.json" "tc_kernel_udp_tx_direct_packets" "tc_kernel_udp_rx_direct_packets" "tc_kernel_udp_tx_secure_direct_packets"
      fi
    done
  fi
  if is_kernel_udp_transport; then
    for node in ix-a ix-b; do
      assert_kernel_udp_status "$node"
      if ! grep -q '"provider": "tc_direct"' "$workdir/${node}-datapath.json"; then
        assert_datapath_any_counter_positive "$workdir/${node}-datapath.json" "xdp_attach_native" "xdp_attach_skb"
        assert_datapath_any_counter_positive "$workdir/${node}-datapath.json" "af_xdp_bind_zerocopy" "af_xdp_bind_copy"
        assert_datapath_counter_zero "$workdir/${node}-datapath.json" "tx_pool_exhausted"
        assert_datapath_counter_zero "$workdir/${node}-datapath.json" "tx_ring_full"
        assert_datapath_counter_zero "$workdir/${node}-datapath.json" "tx_kick_errors"
        grep -q '"tx_backpressure_waits":' "$workdir/${node}-datapath.json" || die "${node} datapath has no TX backpressure wait counter"
        grep -q '"tx_backpressure_reclaims":' "$workdir/${node}-datapath.json" || die "${node} datapath has no TX backpressure reclaim counter"
        assert_datapath_counter_zero "$workdir/${node}-datapath.json" "tx_backpressure_timeouts"
        assert_datapath_counter_zero "$workdir/${node}-datapath.json" "rx_invalid"
        assert_datapath_counter_zero "$workdir/${node}-datapath.json" "rx_recycle_errors"
      fi
      if ! grep -q '"route_stats":' "$workdir/${node}-datapath.json"; then
        assert_hot_any_counter_positive "$workdir/${node}-bpf.json" "tc_kernel_udp_tx_direct_packets" "tc_kernel_udp_rx_direct_packets" "tc_kernel_udp_tx_secure_direct_packets" "tc_kernel_udp_rx_secure_direct_packets"
      fi
      if ! grep -q '"endpoint_stats":' "$workdir/${node}-datapath.json"; then
        assert_hot_any_counter_positive "$workdir/${node}-bpf.json" "tc_kernel_udp_tx_direct_packets" "tc_kernel_udp_rx_direct_packets" "tc_kernel_udp_tx_secure_direct_packets" "tc_kernel_udp_rx_secure_direct_packets"
      fi
    done
  fi
  if is_iptunnel_transport; then
    for node in ix-a ix-b; do
      assert_iptunnel_status "$node"
      if ! native_tunnel_plaintext_route_offload_enabled; then
        grep -q '"route_stats":' "$workdir/${node}-datapath.json" || die "${node} datapath has no route_stats"
        grep -q '"endpoint_stats":' "$workdir/${node}-datapath.json" || die "${node} datapath has no endpoint_stats"
      fi
    done
  fi
  if is_link_tls_transport; then
    for node in ix-a ix-b; do
      grep -q '"transport_tls":' "$workdir/${node}-status.json" || die "${node} status has no transport_tls block"
      grep -q '"crypto_key_source": "tls_exporter"' "$workdir/${node}-status.json" || die "${node} status does not report tls_exporter key source"
      grep -q '"tls_identity_mode": "custom_cert"' "$workdir/${node}-status.json" || die "${node} status does not report custom transport TLS identity"
      grep -q '"wire_format": "trustix-secure-data-v1"' "$workdir/${node}-status.json" || die "${node} status does not report TrustIX secure wire format"
      grep -q '"exporter_capable_endpoints": 2' "$workdir/${node}-status.json" || die "${node} status has unexpected TLS exporter endpoint count"
      grep -q '"non_exporter_endpoints": 0' "$workdir/${node}-status.json" || die "${node} status reports non-exporter endpoints in TCP TLS smoke"
      grep -q '"required_link_tls_endpoints": 2' "$workdir/${node}-status.json" || die "${node} status has unexpected required link TLS endpoint count"
      grep -q '"required_link_tls_missing": 0' "$workdir/${node}-status.json" || die "${node} status reports missing required link TLS"
      assert_json_number_positive "$workdir/${node}-status.json" "link_tls_sessions_seen"
      if is_tls_only; then
        grep -q '"encryption": "plaintext"' "$workdir/${node}-status.json" || die "${node} status does not report TLS-only plaintext encryption"
        grep -q '"tls_only_endpoints": 2' "$workdir/${node}-status.json" || die "${node} status has unexpected TLS-only endpoint count"
        grep -q '"tls_only_missing_link_tls": 0' "$workdir/${node}-status.json" || die "${node} status reports TLS-only session without link TLS"
        assert_tls_only_datapath_session "$workdir/${node}-datapath.json"
      else
        assert_json_number_positive "$workdir/${node}-status.json" "tls_exporter_key_sessions_seen"
      fi
      grep -q '"tls_exporter_without_link_tls": 0' "$workdir/${node}-status.json" || die "${node} status reports TLS exporter without link TLS"
      assert_json_number_zero "$workdir/${node}-status.json" "tls_exporter_without_link_tls_seen"
      assert_json_number_positive "$workdir/${node}-datapath.json" "link_tls_sessions_seen"
      if ! is_tls_only; then
        assert_json_number_positive "$workdir/${node}-datapath.json" "tls_exporter_key_sessions_seen"
      fi
      assert_json_number_zero "$workdir/${node}-datapath.json" "tls_exporter_without_link_tls_seen"
      grep -q '"last_link_tls_version": "TLS 1.3"' "$workdir/${node}-status.json" || die "${node} status has no observed TLS 1.3 state"
      grep -q '"last_link_tls_cipher_suite":' "$workdir/${node}-status.json" || die "${node} status has no observed TLS cipher suite"
      grep -q '"last_link_tls_version": "TLS 1.3"' "$workdir/${node}-datapath.json" || die "${node} datapath has no observed TLS 1.3 state"
      grep -q '"last_link_tls_cipher_suite":' "$workdir/${node}-datapath.json" || die "${node} datapath has no observed TLS cipher suite"
      if grep -q '"link_tls": true' "$workdir/${node}-datapath.json"; then
        if ! is_tls_only; then
          grep -q '"crypto_key_source": "tls_exporter"' "$workdir/${node}-datapath.json" || die "${node} active datapath session is not using TLS exporter keys"
        fi
        grep -q '"tls_version": "TLS 1.3"' "$workdir/${node}-datapath.json" || die "${node} active datapath session has no TLS 1.3 state"
        grep -q '"tls_cipher_suite":' "$workdir/${node}-datapath.json" || die "${node} active datapath session has no TLS cipher suite"
      fi
      grep -q '"name": "transport_tls"' "$workdir/${node}-doctor.json" || die "${node} doctor has no transport_tls check"
      awk '
        /"name": "transport_tls"/ { found=1 }
        found && /"status": "ok"/ { ok=1 }
        END { exit !(found && ok) }
      ' "$workdir/${node}-doctor.json" || die "${node} transport_tls doctor check is not ok"
    done
  fi
}

run_optional_tcp_probe() {
  if [[ "$tcp_probe" != "1" ]]; then
    return 0
  fi
  if ! command -v nc >/dev/null 2>&1; then
    die "TRUSTIX_E2E_TCP_PROBE=1 requires nc"
  fi
  log "running optional TCP payload probe"
  ip netns exec "$ns_b" sh -c 'printf trustix-e2e | nc -l -p 18080 -q 1 >/tmp/trustix-e2e-nc.out' &
  local server_pid=$!
  sleep 0.5
  if ! ip netns exec "$ns_a" sh -c 'printf ping | nc -w 3 10.0.1.2 18080 >/dev/null'; then
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" >/dev/null 2>&1 || true
    die "optional TCP payload probe failed"
  fi
  wait "$server_pid" >/dev/null 2>&1 || true
}

main() {
  require_linux_root
  need_cmd ip
  if [[ -z "${TRUSTIX_E2E_BIN_DIR:-}" ]]; then
    need_cmd go
  fi
  need_cmd python3
  need_cmd curl
  need_cmd sed
  need_cmd awk
  need_cmd ping
  need_cmd timeout
  if effective_disable_veth_offloads; then
    need_cmd ethtool
  fi

  allocate_ports
  configure_addresses
  apply_transport_profile_fastpath_defaults
  mkdir -p "$workdir"
log "workdir: $workdir"
log "dataplane=${dataplane} transport=${transport} profile=${transport_profile} datapath=${transport_datapath} router_netns=${router_netns} nat_reverse=${nat_reverse} crypto=${crypto_placement} encryption=$(effective_transport_encryption) tls_only=${tls_only} direct_vip=${direct_management_vip} hot_stats=${hot_stats} perf_fast=${perf_fast}"
if full_datapath_module_needed; then
  log "full datapath module: enabled rx_worker=${full_datapath_rx_worker} module_dir=${full_datapath_module_dir}"
fi
if is_af_xdp_transport; then
  log "af_xdp tuning: queues=${af_xdp_queues} need_wakeup=${af_xdp_need_wakeup} tx_backpressure=${af_xdp_tx_backpressure_wait} tx_kick_batch=${af_xdp_tx_kick_batch} tx_flush_interval=${af_xdp_tx_flush_interval} tx_soft_kick_backoff=${af_xdp_tx_soft_kick_backoff} tx_defer_flush=${af_xdp_tx_defer_flush}/${af_xdp_tx_defer_flush_delay} tx_coalesce_copy=${af_xdp_tx_coalesce_copy_mode} rx_burst=${af_xdp_rx_burst} ring=${af_xdp_ring_entries} umem=${af_xdp_umem_frames}x${af_xdp_umem_frame_size} encrypted_tixb=${data_session_encrypted_tixb} rx_gso_userspace_encrypted=${data_session_rx_gso_coalesce_userspace_encrypted}"
fi
if experimental_tcp_route_gso_async_enabled; then
  log "experimental_tcp route-GSO async tuning: limit=${experimental_tcp_route_gso_async_limit} stream=${experimental_tcp_route_gso_async_stream}/${experimental_tcp_route_gso_async_stream_direct_build}/${experimental_tcp_route_gso_async_stream_outer_gso}/${experimental_tcp_route_gso_async_stream_max_frames} trust_partial_inner_checksum=${experimental_tcp_route_gso_trust_partial_inner_checksum} plain_skip_sequence=${experimental_tcp_plain_skip_sequence} plain_ack_only=${experimental_tcp_plain_ack_only}"
fi
if experimental_tcp_route_gso_sync_enabled; then
  log "experimental_tcp route-GSO sync tuning: trust_partial_inner_checksum=${experimental_tcp_route_gso_trust_partial_inner_checksum} plain_skip_sequence=${experimental_tcp_plain_skip_sequence} plain_ack_only=${experimental_tcp_plain_ack_only}"
fi
if kernel_udp_secure_direct_enabled; then
  log "kernel_udp secure-direct tuning: disable_veth_offloads=${disable_veth_offloads} effective=$(effective_disable_veth_offloads && printf 1 || printf 0) vaes_kfunc=${kernel_experimental_vaes_kfunc} effective=$(effective_kernel_experimental_vaes_kfunc && printf 1 || printf 0) kfunc_seal=${kernel_udp_tc_tx_secure_direct_kfunc_seal} skb_seal=${kernel_udp_tc_tx_secure_direct_skb_seal_kfunc} outer_tcp_checksum_kfunc=${kernel_udp_tc_tx_secure_direct_outer_tcp_checksum_kfunc} outer_tcp_partial_checksum_kfunc=${kernel_udp_tc_tx_secure_direct_outer_tcp_partial_checksum_kfunc} kfunc_open=${kernel_udp_tc_rx_secure_direct_kfunc_open} skb_open=${kernel_udp_tc_rx_secure_direct_skb_open_kfunc} trust_inner_checksums=${kernel_udp_tc_tx_secure_direct_trust_inner_checksums} fix_inner_checksums=$(kernel_udp_tc_tx_secure_direct_fix_inner_checksums_effective)"
fi
  case "$transport" in
    udp|tcp|quic|websocket|http_connect|experimental_tcp|kernel_udp|gre|ipip|vxlan) ;;
    *) die "TRUSTIX_E2E_TRANSPORT must be udp, tcp, quic, websocket, http_connect, experimental_tcp, kernel_udp, gre, ipip, or vxlan" ;;
  esac
  case "$lan_mode" in
    routed|nat) ;;
    *) die "TRUSTIX_E2E_LAN_MODE must be routed or nat" ;;
  esac
  case "$nat_reverse" in
    0|1) ;;
    *) die "TRUSTIX_E2E_NAT_REVERSE must be 0 or 1" ;;
  esac
  case "$tls_only" in
    0|1) ;;
    *) die "TRUSTIX_E2E_TLS_ONLY must be 0 or 1" ;;
  esac
  case "$direct_management_vip" in
    auto|0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_E2E_DIRECT_MANAGEMENT_VIP must be auto, 1, or 0" ;;
  esac
  if is_tls_only && ! is_link_tls_transport; then
    die "TRUSTIX_E2E_TLS_ONLY=1 requires TRUSTIX_E2E_TRANSPORT=tcp, quic, websocket, or http_connect"
  fi
  case "$(effective_transport_encryption)" in
    ""|secure|encrypted|trustix_secure|trustix-secure|plaintext|none|disabled|off|send_encrypted|outbound_encrypted|encrypt_outbound|send_only|receive_encrypted|inbound_encrypted|encrypt_inbound|receive_only) ;;
    *) die "TRUSTIX_E2E_TRANSPORT_ENCRYPTION must be secure, plaintext, send_encrypted, receive_encrypted, or empty" ;;
  esac
  if [[ "$nat_reverse" == "1" ]]; then
    case "$transport" in
      udp|tcp|kernel_udp|experimental_tcp) ;;
      *) die "TRUSTIX_E2E_NAT_REVERSE=1 supports TRUSTIX_E2E_TRANSPORT=udp, tcp, kernel_udp, or experimental_tcp" ;;
    esac
  fi
  if [[ "$nat_reverse" == "1" && "$session_pool_size" != "0" && "$session_pool_size" != "1" ]]; then
    die "TRUSTIX_E2E_NAT_REVERSE=1 currently requires TRUSTIX_E2E_SESSION_POOL_SIZE=0 or 1"
  fi
  [[ "$route_kind_probe" == "0" || "$route_kind_probe" == "1" ]] || die "TRUSTIX_E2E_ROUTE_KIND_PROBE must be 0 or 1"
  case "$perf_fast" in
    0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_E2E_PERF_FAST must be truthy or falsey" ;;
  esac
  case "$full_datapath_rx_worker" in
    0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_E2E_FULL_DATAPATH_RX_WORKER must be 0 or 1" ;;
  esac
  if full_datapath_rx_worker_enabled && ! full_datapath_module_needed; then
    die "TRUSTIX_E2E_FULL_DATAPATH_RX_WORKER=1 requires TRUSTIX_E2E_FULL_DATAPATH_MODULE=1"
  fi
  if full_datapath_rx_worker_enabled && [[ "$router_netns" == "1" ]]; then
    die "TRUSTIX_E2E_FULL_DATAPATH_RX_WORKER=1 cannot run with TRUSTIX_E2E_ROUTER_NETNS=1 until trustix_datapath is netns-scoped"
  fi
  if full_datapath_rx_worker_enabled && is_af_xdp_transport; then
    die "TRUSTIX_E2E_FULL_DATAPATH_RX_WORKER=1 needs a real one-daemon host; ${transport} e2e auto-uses router namespaces with the current global trustix_datapath hook"
  fi
  case "$crypto_placement" in
    userspace|kernel|auto) ;;
    *) die "TRUSTIX_E2E_CRYPTO_PLACEMENT must be userspace, kernel, or auto" ;;
  esac
  [[ "$ping_count" =~ ^[1-9][0-9]*$ ]] || die "TRUSTIX_E2E_PING_COUNT must be a positive integer"
  [[ "$ping_size" =~ ^[0-9]+$ ]] || die "TRUSTIX_E2E_PING_SIZE must be a non-negative integer"
  [[ "$ping_parallel" =~ ^[1-9][0-9]*$ ]] || die "TRUSTIX_E2E_PING_PARALLEL must be a positive integer"
  [[ "$ping_rounds" =~ ^[1-9][0-9]*$ ]] || die "TRUSTIX_E2E_PING_ROUNDS must be a positive integer"
  [[ "$udp_burst_packets" =~ ^[0-9]+$ ]] || die "TRUSTIX_E2E_UDP_BURST_PACKETS must be a non-negative integer"
  [[ "$udp_burst_size" =~ ^[0-9]+$ ]] || die "TRUSTIX_E2E_UDP_BURST_SIZE must be a non-negative integer"
  [[ "$udp_burst_parallel" =~ ^[1-9][0-9]*$ ]] || die "TRUSTIX_E2E_UDP_BURST_PARALLEL must be a positive integer"
  [[ "$udp_burst_rounds" =~ ^[1-9][0-9]*$ ]] || die "TRUSTIX_E2E_UDP_BURST_ROUNDS must be a positive integer"
  local non_negative_number_re='^[0-9]+([.][0-9]+)?$'
  local timeout_duration_re='^[1-9][0-9]*(s|m|h|d)?$'
  [[ "$udp_burst_rate_pps" =~ $non_negative_number_re ]] || die "TRUSTIX_E2E_UDP_BURST_RATE_PPS must be a non-negative number"
  case "$udp_burst_allow_loss" in
    0|1) ;;
    *) die "TRUSTIX_E2E_UDP_BURST_ALLOW_LOSS must be 0 or 1" ;;
  esac
  [[ "$udp_burst_port" =~ ^[1-9][0-9]*$ && "$udp_burst_port" -le 65534 ]] || die "TRUSTIX_E2E_UDP_BURST_PORT must be in 1..65534"
  [[ "$tcp_burst_connections" =~ ^[0-9]+$ ]] || die "TRUSTIX_E2E_TCP_BURST_CONNECTIONS must be a non-negative integer"
  [[ "$tcp_burst_size" =~ ^[0-9]+$ ]] || die "TRUSTIX_E2E_TCP_BURST_SIZE must be a non-negative integer"
  [[ "$tcp_burst_parallel" =~ ^[1-9][0-9]*$ ]] || die "TRUSTIX_E2E_TCP_BURST_PARALLEL must be a positive integer"
  [[ "$tcp_burst_rounds" =~ ^[1-9][0-9]*$ ]] || die "TRUSTIX_E2E_TCP_BURST_ROUNDS must be a positive integer"
  [[ "$tcp_burst_port" =~ ^[1-9][0-9]*$ && "$tcp_burst_port" -le 65534 ]] || die "TRUSTIX_E2E_TCP_BURST_PORT must be in 1..65534"
  case "$iperf3_probe" in
    0|1) ;;
    *) die "TRUSTIX_E2E_IPERF3 must be 0 or 1" ;;
  esac
  [[ "$iperf3_seconds" =~ ^[1-9][0-9]*$ ]] || die "TRUSTIX_E2E_IPERF3_SECONDS must be a positive integer"
  [[ "$iperf3_parallel" =~ ^[1-9][0-9]*$ ]] || die "TRUSTIX_E2E_IPERF3_PARALLEL must be a positive integer"
  [[ "$iperf3_port" =~ ^[1-9][0-9]*$ && "$iperf3_port" -le 65534 ]] || die "TRUSTIX_E2E_IPERF3_PORT must be in 1..65534"
  [[ -z "$iperf3_timeout" || "$iperf3_timeout" =~ $timeout_duration_re ]] || die "TRUSTIX_E2E_IPERF3_TIMEOUT must be a coreutils timeout duration"
  local nonnegative_decimal_re='^[0-9]+([.][0-9]+)?$'
  [[ "$iperf3_min_sent_gbps" =~ $nonnegative_decimal_re ]] || die "TRUSTIX_E2E_IPERF3_MIN_SENT_GBPS/TRUSTIX_E2E_IPERF3_MIN_GBPS must be a non-negative number"
  [[ "$iperf3_min_received_gbps" =~ $nonnegative_decimal_re ]] || die "TRUSTIX_E2E_IPERF3_MIN_RECEIVED_GBPS/TRUSTIX_E2E_IPERF3_MIN_GBPS must be a non-negative number"
  case "$iperf3_reverse" in
    0|1) ;;
    *) die "TRUSTIX_E2E_IPERF3_REVERSE must be 0 or 1" ;;
  esac
  case "$iperf3_directions" in
    both|a_to_b|b_to_a) ;;
    *) die "TRUSTIX_E2E_IPERF3_DIRECTIONS must be both, a_to_b, or b_to_a" ;;
  esac
  case "$disable_veth_offloads" in
    auto|0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_E2E_DISABLE_VETH_OFFLOADS must be auto, 0, or 1" ;;
  esac
  case "$kernel_experimental_vaes" in
    auto|0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_E2E_KERNEL_EXPERIMENTAL_VAES must be auto, 0, or 1" ;;
  esac
  case "$kernel_experimental_vaes_kfunc" in
    auto|0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_E2E_KERNEL_EXPERIMENTAL_VAES_KFUNC must be auto, 0, or 1" ;;
  esac
  [[ "$burst_timeout" =~ ^[1-9][0-9]*$ ]] || die "TRUSTIX_E2E_BURST_TIMEOUT must be a positive integer"
  [[ "$tcp_connect_timeout" =~ $non_negative_number_re ]] || die "TRUSTIX_E2E_TCP_CONNECT_TIMEOUT must be a non-negative number"
  [[ "$crash_restart" == "0" || "$crash_restart" == "1" ]] || die "TRUSTIX_E2E_CRASH_RESTART must be 0 or 1"
  [[ "$iptunnel_port" =~ ^[1-9][0-9]*$ && "$iptunnel_port" -le 65535 ]] || die "TRUSTIX_E2E_IPTUNNEL_PORT must be in 1..65535"
  [[ "$iptunnel_mtu" =~ ^[1-9][0-9]*$ && "$iptunnel_mtu" -ge 17 && "$iptunnel_mtu" -le 65535 ]] || die "TRUSTIX_E2E_IPTUNNEL_MTU must be in 17..65535"
  [[ "$underlay_mtu" =~ ^[1-9][0-9]*$ && "$underlay_mtu" -ge 1500 && "$underlay_mtu" -le 65535 ]] || die "TRUSTIX_E2E_UNDERLAY_MTU must be in 1500..65535"
  [[ "$lan_mtu" =~ ^[1-9][0-9]*$ && "$lan_mtu" -ge 576 && "$lan_mtu" -le 65535 ]] || die "TRUSTIX_E2E_LAN_MTU must be in 576..65535"
  if [[ "$udp_burst_packets" -gt 0 || "$tcp_burst_connections" -gt 0 ]]; then
    need_cmd python3
  fi
  if [[ "$iperf3_probe" == "1" ]]; then
    need_cmd iperf3
  fi
  case "$xdp_mode" in
    auto|native|driver|drv|skb) ;;
    *) die "TRUSTIX_E2E_XDP_MODE must be auto, native, driver, drv, or skb" ;;
  esac
  case "$af_xdp_bind_mode" in
    auto|zerocopy|copy) ;;
    *) die "TRUSTIX_E2E_AF_XDP_BIND_MODE must be auto, zerocopy, or copy" ;;
  esac
  case "$hot_stats" in
    0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_E2E_HOT_STATS must be truthy or falsey" ;;
  esac
  case "$af_xdp_need_wakeup" in
    auto|0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_E2E_AF_XDP_NEED_WAKEUP must be auto, 0, or 1" ;;
  esac
  case "$kernel_udp_tc_rx_secure_direct" in
    0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_E2E_KERNEL_UDP_TC_RX_SECURE_DIRECT must be 0 or 1" ;;
  esac
  case "$kernel_udp_tc_tx_secure_direct_kfunc_seal" in
    0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_E2E_KERNEL_UDP_TC_TX_SECURE_DIRECT_KFUNC_SEAL must be 0 or 1" ;;
  esac
  case "$kernel_udp_tc_tx_secure_direct_skb_seal_kfunc" in
    0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_E2E_KERNEL_UDP_TC_TX_SECURE_DIRECT_SKB_SEAL_KFUNC must be 0 or 1" ;;
  esac
  case "$kernel_udp_tc_tx_secure_direct_outer_tcp_checksum_kfunc" in
    0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_E2E_KERNEL_UDP_TC_TX_SECURE_DIRECT_OUTER_TCP_CHECKSUM_KFUNC must be 0 or 1" ;;
  esac
  case "$kernel_udp_tc_tx_secure_direct_outer_tcp_partial_checksum_kfunc" in
    0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_E2E_KERNEL_UDP_TC_TX_SECURE_DIRECT_OUTER_TCP_PARTIAL_CHECKSUM_KFUNC must be 0 or 1" ;;
  esac
  case "$kernel_udp_tc_tx_secure_direct_trust_inner_checksums" in
    0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_E2E_KERNEL_UDP_TC_TX_SECURE_DIRECT_TRUST_INNER_CHECKSUMS must be 0 or 1" ;;
  esac
  case "$kernel_udp_tc_tx_secure_direct_fix_inner_checksums" in
    0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_E2E_KERNEL_UDP_TC_TX_SECURE_DIRECT_FIX_INNER_CHECKSUMS must be 0 or 1" ;;
  esac
  case "$kernel_udp_tc_rx_secure_direct_kfunc_open" in
    0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_E2E_KERNEL_UDP_TC_RX_SECURE_DIRECT_KFUNC_OPEN must be 0 or 1" ;;
  esac
  case "$kernel_udp_tc_rx_secure_direct_skb_open_kfunc" in
    0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_E2E_KERNEL_UDP_TC_RX_SECURE_DIRECT_SKB_OPEN_KFUNC must be 0 or 1" ;;
  esac
  [[ "$af_xdp_tx_kick_batch" =~ ^[1-9][0-9]*$ ]] || die "TRUSTIX_E2E_AF_XDP_TX_KICK_BATCH must be a positive integer"
  local duration_re='^[0-9]+(ns|us|ms|s|m|h)$'
  [[ "$af_xdp_tx_backpressure_wait" == "0" || "$af_xdp_tx_backpressure_wait" =~ $duration_re ]] || die "TRUSTIX_E2E_AF_XDP_TX_BACKPRESSURE_WAIT must be a Go duration or 0"
  [[ "$af_xdp_tx_flush_interval" == "0" || "$af_xdp_tx_flush_interval" =~ $duration_re ]] || die "TRUSTIX_E2E_AF_XDP_TX_FLUSH_INTERVAL must be a Go duration or 0"
  [[ "$af_xdp_tx_soft_kick_backoff" == "0" || "$af_xdp_tx_soft_kick_backoff" =~ $duration_re ]] || die "TRUSTIX_E2E_AF_XDP_TX_SOFT_KICK_BACKOFF must be a Go duration or 0"
  case "$af_xdp_tx_defer_flush" in
    0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_E2E_AF_XDP_TX_DEFER_FLUSH must be 0 or 1" ;;
  esac
  [[ "$af_xdp_tx_defer_flush_delay" == "0" || "$af_xdp_tx_defer_flush_delay" =~ $duration_re ]] || die "TRUSTIX_E2E_AF_XDP_TX_DEFER_FLUSH_DELAY must be a Go duration or 0"
  case "$af_xdp_tx_coalesce_copy_mode" in
    0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_E2E_AF_XDP_TX_COALESCE_COPY_MODE must be 0 or 1" ;;
  esac
  [[ "$af_xdp_rx_burst" =~ ^[1-9][0-9]*$ ]] || die "TRUSTIX_E2E_AF_XDP_RX_BURST must be a positive integer"
  [[ "$af_xdp_ring_entries" =~ ^[1-9][0-9]*$ ]] || die "TRUSTIX_E2E_AF_XDP_RING_ENTRIES must be a positive integer"
  [[ "$af_xdp_umem_frames" =~ ^[1-9][0-9]*$ ]] || die "TRUSTIX_E2E_AF_XDP_UMEM_FRAMES must be a positive integer"
  if [[ "$af_xdp_umem_frame_size" == "auto" ]]; then
    af_xdp_umem_frame_size=2048
    if [[ "$transport" == "experimental_tcp" ]] && truthy "$experimental_tcp_auto_umem_jumbo"; then
      af_xdp_umem_frame_size=4096
    fi
  fi
  [[ "$af_xdp_umem_frame_size" =~ ^[1-9][0-9]*$ ]] || die "TRUSTIX_E2E_AF_XDP_UMEM_FRAME_SIZE must be auto or a positive integer"
  case "$experimental_tcp_tc_tx_direct" in
    ""|0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_E2E_EXPERIMENTAL_TCP_TC_TX_DIRECT must be empty or 0/1" ;;
  esac
  case "$experimental_tcp_tc_tx_direct_only" in
    ""|0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_E2E_EXPERIMENTAL_TCP_TC_TX_DIRECT_ONLY must be empty or 0/1" ;;
  esac
  case "$experimental_tcp_route_gso_sync" in
    0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_GSO_SYNC must be 0 or 1" ;;
  esac
  case "$experimental_tcp_route_gso_async" in
    0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC must be 0 or 1" ;;
  esac
  case "$experimental_tcp_route_gso_async_crash_risk_ack" in
    0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_CRASH_RISK_ACK must be 0 or 1" ;;
  esac
  case "$experimental_tcp_route_gso_async_dev_xmit" in
    0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_DEV_XMIT must be 0 or 1" ;;
  esac
  if experimental_tcp_route_gso_async_enabled && ! truthy "$experimental_tcp_route_gso_async_dev_xmit"; then
    die "route-GSO async requires TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_DEV_XMIT=1 for the validated clone-worker profile"
  fi
  for pair in \
    "TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_STREAM:$experimental_tcp_route_gso_async_stream" \
    "TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_STREAM_DIRECT_BUILD:$experimental_tcp_route_gso_async_stream_direct_build" \
    "TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_STREAM_OUTER_GSO:$experimental_tcp_route_gso_async_stream_outer_gso"; do
    name="${pair%%:*}"
    value="${pair#*:}"
    case "$value" in
      0|1|true|false|yes|no|on|off|enabled|disabled) ;;
      *) die "${name} must be 0 or 1" ;;
    esac
  done
  case "$experimental_tcp_route_xmit_worker" in
    0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_XMIT_WORKER must be 0 or 1" ;;
  esac
  case "$experimental_tcp_route_xmit_worker_crash_risk_ack" in
    0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_XMIT_WORKER_CRASH_RISK_ACK must be 0 or 1" ;;
  esac
  case "$experimental_tcp_route_xmit_worker_steal" in
    0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_XMIT_WORKER_STEAL must be 0 or 1" ;;
  esac
  case "$experimental_tcp_route_xmit_worker_steal_crash_risk_ack" in
    0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_XMIT_WORKER_STEAL_CRASH_RISK_ACK must be 0 or 1" ;;
  esac
  [[ "$experimental_tcp_route_gso_async_limit" =~ ^[1-9][0-9]*$ ]] || die "TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_LIMIT must be a positive integer"
  [[ "$experimental_tcp_route_gso_async_worker_item_budget" =~ ^[0-9]+$ ]] || die "TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_WORKER_ITEM_BUDGET must be a non-negative integer"
  [[ "$experimental_tcp_route_gso_async_worker_segment_budget" =~ ^[0-9]+$ ]] || die "TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_WORKER_SEGMENT_BUDGET must be a non-negative integer"
  [[ "$experimental_tcp_route_gso_async_max_segments_per_item" =~ ^[0-9]+$ ]] || die "TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_MAX_SEGMENTS_PER_ITEM must be a non-negative integer"
  [[ "$experimental_tcp_route_gso_async_stream_max_frames" =~ ^[0-9]+$ ]] || die "TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_STREAM_MAX_FRAMES must be a non-negative integer"
  case "$experimental_tcp_route_gso_trust_partial_inner_checksum" in
    0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_GSO_TRUST_PARTIAL_INNER_CHECKSUM must be 0 or 1" ;;
  esac
  case "$experimental_tcp_route_header_kfunc" in
    0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_E2E_EXPERIMENTAL_TCP_ROUTE_HEADER_KFUNC must be 0 or 1" ;;
  esac
  case "$experimental_tcp_plain_skip_sequence" in
    0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_E2E_EXPERIMENTAL_TCP_PLAIN_SKIP_SEQUENCE must be 0 or 1" ;;
  esac
  case "$experimental_tcp_plain_ack_only" in
    0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_E2E_EXPERIMENTAL_TCP_PLAIN_ACK_ONLY must be 0 or 1" ;;
  esac
  case "$experimental_tcp_auto_umem_jumbo" in
    0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_E2E_EXPERIMENTAL_TCP_AUTO_UMEM_JUMBO must be 0 or 1" ;;
  esac
  case "$experimental_tcp_skip_checksum" in
    0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_EXPERIMENTAL_TCP_SKIP_TCP_CHECKSUM must be 0 or 1" ;;
  esac
  case "$experimental_tcp_skip_outer_checksum" in
    0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_E2E_EXPERIMENTAL_TCP_SKIP_OUTER_TCP_CHECKSUM must be 0 or 1" ;;
  esac
  case "$kernel_udp_xdp_open" in
    0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_E2E_KERNEL_UDP_XDP_OPEN must be 0 or 1" ;;
  esac
  case "$kernel_udp_xdp_pass_opened" in
    0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_E2E_KERNEL_UDP_XDP_PASS_OPENED must be 0 or 1" ;;
  esac
  case "$kernel_udp_xdp_rx_direct" in
    0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_E2E_KERNEL_UDP_XDP_RX_DIRECT must be 0 or 1" ;;
  esac
  case "$kernel_udp_xdp_rx_secure_direct" in
    0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_E2E_KERNEL_UDP_XDP_RX_SECURE_DIRECT must be 0 or 1" ;;
  esac
  case "$kernel_udp_xdp_rx_direct_ifindex" in
    0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_E2E_KERNEL_UDP_XDP_RX_DIRECT_IFINDEX must be 0 or 1" ;;
  esac
  case "$kernel_udp_xdp_rx_direct_mode" in
    ""|devmap|ifindex) ;;
    *) die "TRUSTIX_E2E_KERNEL_UDP_XDP_RX_DIRECT_MODE must be empty, devmap, or ifindex" ;;
  esac
  [[ "$kernel_udp_session_buffer" =~ ^[1-9][0-9]*$ ]] || die "TRUSTIX_E2E_KERNEL_UDP_SESSION_BUFFER must be a positive integer"
  [[ "$capture_forwarder_workers" =~ ^[1-9][0-9]*$ ]] || die "TRUSTIX_E2E_CAPTURE_FORWARDER_WORKERS must be a positive integer"
  [[ "$capture_forwarder_buffer" =~ ^[1-9][0-9]*$ ]] || die "TRUSTIX_E2E_CAPTURE_FORWARDER_BUFFER must be a positive integer"
  [[ "$capture_forwarder_batch" =~ ^[1-9][0-9]*$ ]] || die "TRUSTIX_E2E_CAPTURE_FORWARDER_BATCH must be a positive integer"
  [[ "$capture_forwarder_batch_delay" == "0" || "$capture_forwarder_batch_delay" =~ $duration_re ]] || die "TRUSTIX_E2E_CAPTURE_FORWARDER_BATCH_DELAY must be a Go duration or 0"
  case "$data_session_encrypted_tixb" in
    auto|0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_E2E_DATA_SESSION_ENCRYPTED_TIXB must be auto or 0/1" ;;
  esac
  case "$data_session_rx_gso_coalesce_userspace_encrypted" in
    auto|0|1|true|false|yes|no|on|off|enabled|disabled) ;;
    *) die "TRUSTIX_E2E_DATA_SESSION_RX_GSO_COALESCE_USERSPACE_ENCRYPTED must be auto or 0/1" ;;
  esac
  if [[ "$transport" == "experimental_tcp" && "$crypto_placement" == "kernel" && "$kernel_module" != "1" ]] && ! kernel_provider_expected; then
    die "TRUSTIX_E2E_CRYPTO_PLACEMENT=kernel requires TRUSTIX_E2E_KERNEL_MODULE=1"
  fi

  maybe_prepare_kernel_module
  maybe_prepare_full_datapath_module
  maybe_prepare_datapath_module
  build_binaries
  generate_certs
  setup_topology

  local config_a
  local config_b
  config_a="$(generate_config ix-a ix-b 10.0.0.0/24 10.0.0.1/24 10.0.1.0/24 "$lan_a" "$udp_a" "$udp_b" "$tcp_a" "$tcp_b" "$exp_tcp_a" "$exp_tcp_b" "$iptunnel_a" "$iptunnel_b" "$peer_api_a" "$peer_api_b" "$api_a" hk-udp sh-udp hk-experimental-tcp sh-experimental-tcp "$underlay_a")"
  config_b="$(generate_config ix-b ix-a 10.0.1.0/24 10.0.1.1/24 10.0.0.0/24 "$lan_b" "$udp_b" "$udp_a" "$tcp_b" "$tcp_a" "$exp_tcp_b" "$exp_tcp_a" "$iptunnel_b" "$iptunnel_a" "$peer_api_b" "$peer_api_a" "$api_b" sh-udp hk-udp sh-experimental-tcp hk-experimental-tcp "$underlay_b")"

  local daemon_ns_a=""
  local daemon_ns_b=""
  if [[ "$router_netns" == "1" ]]; then
    daemon_ns_a="$ns_ix_a"
    daemon_ns_b="$ns_ix_b"
  fi

  if ! perf_fast_enabled; then
    assert_experimental_tcp_kernel_crypto_rejects ix-a "$config_a" "$workdir/state-kernel-reject" "${api_a#http://}" "$peer_api_a" "$daemon_ns_a"
  fi
  pid_a="$(start_daemon ix-a "$config_a" "$workdir/state-a" "${api_a#http://}" "$peer_api_a" "$daemon_ns_a")"
  wait_for_api ix-a "$api_a" "$pid_a" "$daemon_ns_a"
  if ! perf_fast_enabled; then
    assert_host_management_api ix-a "$ns_a" 10.0.0.1 "$api_a_port"
    assert_data_dir_lock_rejects_duplicate ix-a "$config_a" "$workdir/state-a" "${api_a#http://}" "$peer_api_a" "$daemon_ns_a"
  fi
  pid_b="$(start_daemon ix-b "$config_b" "$workdir/state-b" "${api_b#http://}" "$peer_api_b" "$daemon_ns_b")"
  wait_for_api ix-b "$api_b" "$pid_b" "$daemon_ns_b"
  if ! perf_fast_enabled; then
    assert_host_management_api ix-b "$ns_b" 10.0.1.1 "$api_b_port"
    assert_cross_ix_management_proxy ix-a "$ns_a" 10.0.0.1 "$api_a_port" ix-b
    assert_cross_ix_management_proxy ix-b "$ns_b" 10.0.1.1 "$api_b_port" ix-a
  fi

  warm_neighbors
  if [[ "$nat_reverse" == "1" ]]; then
    if ! retry_ping "$ns_b" 10.0.0.2 "LAN B -> LAN A reverse warmup"; then
      collect_api ix-a "$api_a" "$daemon_ns_a" || true
      collect_api ix-b "$api_b" "$daemon_ns_b" || true
      die "LAN B -> LAN A reverse warmup ping failed"
    fi
  fi
  if ! perf_fast_enabled; then
    if direct_management_vip_enabled; then
      assert_direct_management_vip ix-a "$ns_a" 10.0.0.1 "$api_a_port" 10.0.1.1 "$api_b_port" ix-b
      assert_direct_management_vip ix-b "$ns_b" 10.0.1.1 "$api_b_port" 10.0.0.1 "$api_a_port" ix-a
    else
      log "skip direct management VIP for router-netns transport"
    fi
  fi
  if ! retry_ping "$ns_a" 10.0.1.2 "LAN A -> LAN B"; then
    collect_api ix-a "$api_a" "$daemon_ns_a" || true
    collect_api ix-b "$api_b" "$daemon_ns_b" || true
    die "LAN A -> LAN B ping failed"
  fi
  if ! retry_ping "$ns_b" 10.0.0.2 "LAN B -> LAN A"; then
    collect_api ix-a "$api_a" "$daemon_ns_a" || true
    collect_api ix-b "$api_b" "$daemon_ns_b" || true
    die "LAN B -> LAN A ping failed"
  fi
  run_payload_bursts
  run_iperf3_probes
  if ! perf_fast_enabled; then
    run_optional_tcp_probe
    run_experimental_tcp_negative_probes
  fi

  collect_api ix-a "$api_a" "$daemon_ns_a"
  collect_api ix-b "$api_b" "$daemon_ns_b"
  if ! perf_fast_enabled; then
    assert_nat_reverse_status
    validate_observability
    assert_route_kind_probe "$config_a" "$workdir/state-a" "$api_a" "${api_a#http://}" "$peer_api_a" "$daemon_ns_a"
    assert_crash_cleanup_restart "$config_a" "$workdir/state-a" "$api_a" "${api_a#http://}" "$peer_api_a" "$daemon_ns_a"
    collect_api ix-a "$api_a" "$daemon_ns_a"
    collect_api ix-b "$api_b" "$daemon_ns_b"
    assert_sigterm_releases_data_dir_lock "$config_a" "$workdir/state-a" "$api_a" "${api_a#http://}" "$peer_api_a" "$daemon_ns_a"
  fi

  log "ok: bidirectional LAN traffic crossed TrustIX TC/eBPF capture, secure transport, and LAN reinject"
  success=1
}

main "$@"
