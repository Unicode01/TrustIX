#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workdir="${TRUSTIX_TIX_TCP_BENCH_WORKDIR:-$(mktemp -d /tmp/trustix-tix-tcp-bench.XXXXXX)}"
keep="${TRUSTIX_TIX_TCP_BENCH_KEEP:-0}"
bin_dir="${TRUSTIX_TIX_TCP_BENCH_BIN_DIR:-}"
default_smoke_script="${repo_root}/scripts/linux-e2e-smoke.sh"
smoke_script="${TRUSTIX_TIX_TCP_BENCH_E2E_SCRIPT:-$default_smoke_script}"
run_kernel="${TRUSTIX_TIX_TCP_BENCH_KERNEL:-auto}"
kernel_module="${TRUSTIX_TIX_TCP_BENCH_KERNEL_MODULE:-0}"
e2e_crash_restart="${TRUSTIX_TIX_TCP_BENCH_E2E_CRASH_RESTART:-0}"

ping_count="${TRUSTIX_TIX_TCP_BENCH_PING_COUNT:-5}"
ping_parallel="${TRUSTIX_TIX_TCP_BENCH_PING_PARALLEL:-1}"
ping_rounds="${TRUSTIX_TIX_TCP_BENCH_PING_ROUNDS:-1}"
udp_burst_packets="${TRUSTIX_TIX_TCP_BENCH_UDP_BURST_PACKETS:-64}"
udp_burst_size="${TRUSTIX_TIX_TCP_BENCH_UDP_BURST_SIZE:-512}"
udp_burst_parallel="${TRUSTIX_TIX_TCP_BENCH_UDP_BURST_PARALLEL:-1}"
udp_burst_rounds="${TRUSTIX_TIX_TCP_BENCH_UDP_BURST_ROUNDS:-1}"
udp_burst_rate_pps="${TRUSTIX_TIX_TCP_BENCH_UDP_BURST_RATE_PPS:-0}"
udp_burst_allow_loss="${TRUSTIX_TIX_TCP_BENCH_UDP_BURST_ALLOW_LOSS:-0}"
tcp_burst_connections="${TRUSTIX_TIX_TCP_BENCH_TCP_BURST_CONNECTIONS:-16}"
tcp_burst_size="${TRUSTIX_TIX_TCP_BENCH_TCP_BURST_SIZE:-1024}"
tcp_burst_parallel="${TRUSTIX_TIX_TCP_BENCH_TCP_BURST_PARALLEL:-1}"
tcp_burst_rounds="${TRUSTIX_TIX_TCP_BENCH_TCP_BURST_ROUNDS:-1}"
burst_timeout="${TRUSTIX_TIX_TCP_BENCH_BURST_TIMEOUT:-15}"
tcp_connect_timeout="${TRUSTIX_TIX_TCP_BENCH_TCP_CONNECT_TIMEOUT:-5}"
session_pool_size="${TRUSTIX_TIX_TCP_BENCH_SESSION_POOL_SIZE:-0}"
session_pool_strategy="${TRUSTIX_TIX_TCP_BENCH_SESSION_POOL_STRATEGY:-flow}"
session_pool_warmup="${TRUSTIX_TIX_TCP_BENCH_SESSION_POOL_WARMUP:-false}"
capture_forwarder_workers="${TRUSTIX_TIX_TCP_BENCH_CAPTURE_FORWARDER_WORKERS:-1}"
capture_forwarder_buffer="${TRUSTIX_TIX_TCP_BENCH_CAPTURE_FORWARDER_BUFFER:-65536}"
af_xdp_queues="${TRUSTIX_TIX_TCP_BENCH_AF_XDP_QUEUES:-1}"
af_xdp_tx_backpressure_wait="${TRUSTIX_TIX_TCP_BENCH_AF_XDP_TX_BACKPRESSURE_WAIT:-2ms}"
af_xdp_tx_kick_batch="${TRUSTIX_TIX_TCP_BENCH_AF_XDP_TX_KICK_BATCH:-256}"

log() {
  printf '[trustix-tix-tcp-bench] %s\n' "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

cleanup() {
  local exit_code=$?
  stop_bench_processes
  if [[ "$keep" != "1" && "$exit_code" == "0" && -z "${TRUSTIX_TIX_TCP_BENCH_WORKDIR:-}" ]]; then
    rm -rf "$workdir"
  else
    log "workdir preserved: $workdir"
  fi
  exit "$exit_code"
}
trap cleanup EXIT

stop_bench_processes() {
  local pids
  pids="$(ps -eo pid=,comm=,args= | awk -v wd="$workdir" '$2 == "trustixd" && index($0, wd) { print $1 }')"
  if [[ -n "$pids" ]]; then
    log "stopping orphaned trustixd processes for ${workdir}: $(printf '%s\n' "$pids" | tr '\n' ' ')"
    printf '%s\n' "$pids" | while read -r pid; do
      [[ -n "$pid" ]] || continue
      kill -INT "$pid" >/dev/null 2>&1 || true
    done
    sleep 1
    pids="$(ps -eo pid=,comm=,args= | awk -v wd="$workdir" '$2 == "trustixd" && index($0, wd) { print $1 }')"
    printf '%s\n' "$pids" | while read -r pid; do
      [[ -n "$pid" ]] || continue
      kill "$pid" >/dev/null 2>&1 || true
    done
    sleep 1
    pids="$(ps -eo pid=,comm=,args= | awk -v wd="$workdir" '$2 == "trustixd" && index($0, wd) { print $1 }')"
    printf '%s\n' "$pids" | while read -r pid; do
      [[ -n "$pid" ]] || continue
      kill -9 "$pid" >/dev/null 2>&1 || true
    done
  fi
  if [[ "$keep" != "1" ]]; then
    ip netns list 2>/dev/null | awk '/^tix-/ {print $1}' | while read -r ns; do
      ip netns delete "$ns" >/dev/null 2>&1 || true
    done
  fi
}

kernel_provider_loaded() {
  grep -q '^trustix_crypto ' /proc/modules 2>/dev/null
}

bool_enabled() {
  case "$1" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

run_one() {
  local placement="$1"
  local dir="$workdir/$placement"
  local start end elapsed
  local e2e_kernel_module="0"
  if [[ "$placement" == "kernel" ]]; then
    e2e_kernel_module="$kernel_module"
  fi
  rm -rf "$dir"
  mkdir -p "$dir"
  log "run placement=${placement}"
  start="$(date +%s%N)"
  set +e
  if [[ -n "$bin_dir" ]]; then
    env \
      TRUSTIX_E2E_BIN_DIR="$bin_dir" \
      TRUSTIX_E2E_WORKDIR="$dir" \
      TRUSTIX_E2E_CRASH_RESTART="$e2e_crash_restart" \
      TRUSTIX_E2E_TRANSPORT=tix_tcp \
      TRUSTIX_E2E_CRYPTO_PLACEMENT="$placement" \
      TRUSTIX_E2E_KERNEL_MODULE="$e2e_kernel_module" \
      TRUSTIX_E2E_AF_XDP_QUEUES="$af_xdp_queues" \
      TRUSTIX_E2E_AF_XDP_TX_BACKPRESSURE_WAIT="$af_xdp_tx_backpressure_wait" \
      TRUSTIX_E2E_AF_XDP_TX_KICK_BATCH="$af_xdp_tx_kick_batch" \
      TRUSTIX_E2E_CAPTURE_FORWARDER_WORKERS="$capture_forwarder_workers" \
      TRUSTIX_E2E_CAPTURE_FORWARDER_BUFFER="$capture_forwarder_buffer" \
      TRUSTIX_E2E_SESSION_POOL_SIZE="$session_pool_size" \
      TRUSTIX_E2E_SESSION_POOL_STRATEGY="$session_pool_strategy" \
      TRUSTIX_E2E_SESSION_POOL_WARMUP="$session_pool_warmup" \
      TRUSTIX_E2E_PING_COUNT="$ping_count" \
      TRUSTIX_E2E_PING_PARALLEL="$ping_parallel" \
      TRUSTIX_E2E_PING_ROUNDS="$ping_rounds" \
      TRUSTIX_E2E_UDP_BURST_PACKETS="$udp_burst_packets" \
      TRUSTIX_E2E_UDP_BURST_SIZE="$udp_burst_size" \
      TRUSTIX_E2E_UDP_BURST_PARALLEL="$udp_burst_parallel" \
      TRUSTIX_E2E_UDP_BURST_ROUNDS="$udp_burst_rounds" \
      TRUSTIX_E2E_UDP_BURST_RATE_PPS="$udp_burst_rate_pps" \
      TRUSTIX_E2E_UDP_BURST_ALLOW_LOSS="$udp_burst_allow_loss" \
      TRUSTIX_E2E_TCP_BURST_CONNECTIONS="$tcp_burst_connections" \
      TRUSTIX_E2E_TCP_BURST_SIZE="$tcp_burst_size" \
      TRUSTIX_E2E_TCP_BURST_PARALLEL="$tcp_burst_parallel" \
      TRUSTIX_E2E_TCP_BURST_ROUNDS="$tcp_burst_rounds" \
      TRUSTIX_E2E_BURST_TIMEOUT="$burst_timeout" \
      TRUSTIX_E2E_TCP_CONNECT_TIMEOUT="$tcp_connect_timeout" \
      bash "$smoke_script"
  else
    env \
      TRUSTIX_E2E_WORKDIR="$dir" \
      TRUSTIX_E2E_CRASH_RESTART="$e2e_crash_restart" \
      TRUSTIX_E2E_TRANSPORT=tix_tcp \
      TRUSTIX_E2E_CRYPTO_PLACEMENT="$placement" \
      TRUSTIX_E2E_KERNEL_MODULE="$e2e_kernel_module" \
      TRUSTIX_E2E_AF_XDP_QUEUES="$af_xdp_queues" \
      TRUSTIX_E2E_AF_XDP_TX_BACKPRESSURE_WAIT="$af_xdp_tx_backpressure_wait" \
      TRUSTIX_E2E_AF_XDP_TX_KICK_BATCH="$af_xdp_tx_kick_batch" \
      TRUSTIX_E2E_CAPTURE_FORWARDER_WORKERS="$capture_forwarder_workers" \
      TRUSTIX_E2E_CAPTURE_FORWARDER_BUFFER="$capture_forwarder_buffer" \
      TRUSTIX_E2E_SESSION_POOL_SIZE="$session_pool_size" \
      TRUSTIX_E2E_SESSION_POOL_STRATEGY="$session_pool_strategy" \
      TRUSTIX_E2E_SESSION_POOL_WARMUP="$session_pool_warmup" \
      TRUSTIX_E2E_PING_COUNT="$ping_count" \
      TRUSTIX_E2E_PING_PARALLEL="$ping_parallel" \
      TRUSTIX_E2E_PING_ROUNDS="$ping_rounds" \
      TRUSTIX_E2E_UDP_BURST_PACKETS="$udp_burst_packets" \
      TRUSTIX_E2E_UDP_BURST_SIZE="$udp_burst_size" \
      TRUSTIX_E2E_UDP_BURST_PARALLEL="$udp_burst_parallel" \
      TRUSTIX_E2E_UDP_BURST_ROUNDS="$udp_burst_rounds" \
      TRUSTIX_E2E_UDP_BURST_RATE_PPS="$udp_burst_rate_pps" \
      TRUSTIX_E2E_UDP_BURST_ALLOW_LOSS="$udp_burst_allow_loss" \
      TRUSTIX_E2E_TCP_BURST_CONNECTIONS="$tcp_burst_connections" \
      TRUSTIX_E2E_TCP_BURST_SIZE="$tcp_burst_size" \
      TRUSTIX_E2E_TCP_BURST_PARALLEL="$tcp_burst_parallel" \
      TRUSTIX_E2E_TCP_BURST_ROUNDS="$tcp_burst_rounds" \
      TRUSTIX_E2E_BURST_TIMEOUT="$burst_timeout" \
      TRUSTIX_E2E_TCP_CONNECT_TIMEOUT="$tcp_connect_timeout" \
      bash "$smoke_script"
  fi
  local rc=$?
  set -e
  end="$(date +%s%N)"
  elapsed="$(python3 - "$start" "$end" <<'PY'
import sys
start = int(sys.argv[1])
end = int(sys.argv[2])
print(f"{(end - start) / 1_000_000_000:.6f}")
PY
)"
  summarize_run "$placement" "$elapsed" "$dir" "$rc"
  if [[ "$rc" != "0" ]]; then
    die "placement=${placement} benchmark failed"
  fi
}

summarize_run() {
  local placement="$1"
  local elapsed="$2"
  local dir="$3"
  local rc="${4:-0}"
  python3 - "$placement" "$elapsed" "$dir" "$rc" <<'PY'
import json
import os
import sys

placement, elapsed, directory, rc = sys.argv[1:5]

def load(name):
    path = os.path.join(directory, name)
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)

def try_load(name):
    path = os.path.join(directory, name)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return None

def counters(payload):
    return payload.get("counters") or {}

def bpf_counters(payload):
    stats = payload.get("stats") or {}
    return {item.get("name"): item.get("value") for item in stats.get("counters", []) if isinstance(item, dict)}

def exp(payload):
    return payload.get("tix_tcp") or {}

def pick(counter_map, names):
    return {name: int(counter_map.get(name, 0) or 0) for name in names}

def parse_kv(line):
    result = {}
    for field in line.strip().split():
        if "=" not in field:
            continue
        key, value = field.split("=", 1)
        try:
            if "." in value:
                result[key] = float(value)
            else:
                result[key] = int(value)
        except ValueError:
            result[key] = value
    return result

def payload_bursts():
    runs = {}
    stat_keys = ("sent=", "received=", "sent_connections=", "accepted=")
    for filename in os.listdir(directory):
        if not filename.endswith(".log"):
            continue
        if "-udp-" not in filename and "-tcp-" not in filename:
            continue
        path = os.path.join(directory, filename)
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            lines = [line.strip() for line in handle if line.strip()]
        if not lines:
            continue
        stat_line = ""
        for line in reversed(lines):
            if any(key in line for key in stat_keys):
                stat_line = line
                break
        if not stat_line:
            stat_line = lines[-1]
        runs[filename] = parse_kv(stat_line)
    return runs

def burst_summary(runs):
    summary = {
        "udp_recv_mbps": [],
        "udp_send_mbps": [],
        "tcp_recv_mbps": [],
        "tcp_send_mbps": [],
        "udp_lost": 0,
        "tcp_short_reads": 0,
        "total_payload_bytes": 0,
    }
    for name, values in runs.items():
        mbps = values.get("mbps")
        if isinstance(values.get("bytes"), int):
            summary["total_payload_bytes"] += values["bytes"]
        if isinstance(values.get("lost"), int):
            summary["udp_lost"] += values["lost"]
        if isinstance(values.get("short_reads"), int):
            summary["tcp_short_reads"] += values["short_reads"]
        if not isinstance(mbps, (int, float)):
            continue
        if "-udp-recv" in name:
            summary["udp_recv_mbps"].append(float(mbps))
        elif "-udp-send" in name:
            summary["udp_send_mbps"].append(float(mbps))
        elif "-tcp-recv" in name:
            summary["tcp_recv_mbps"].append(float(mbps))
        elif "-tcp-send" in name:
            summary["tcp_send_mbps"].append(float(mbps))
    for key in ("udp_recv_mbps", "udp_send_mbps", "tcp_recv_mbps", "tcp_send_mbps"):
        values = summary[key]
        if values:
            summary[key] = {
                "min": min(values),
                "max": max(values),
                "avg": sum(values) / len(values),
                "samples": len(values),
            }
        else:
            summary[key] = None
    return summary

def nonzero(counter_groups, names):
    result = {}
    for group in counter_groups:
        for name in names:
            value = int(group.get(name, 0) or 0)
            if value:
                result[name] = result.get(name, 0) + value
    return result

def bottleneck_hints(nodes, bursts):
    hints = []
    ring_pressure = nonzero(
        [node.get("ring_pressure", {}) for node in nodes.values()],
        [
            "tx_pool_exhausted",
            "tx_ring_full",
            "tx_kick_errors",
            "tx_backpressure_waits",
            "tx_backpressure_timeouts",
            "rx_invalid",
            "rx_recycle_errors",
        ],
    )
    if ring_pressure:
        hints.append({"area": "af_xdp_ring_or_umem", "counters": ring_pressure})
    capture_pressure = nonzero(
        [node.get("capture_pressure", {}) for node in nodes.values()],
        ["tc_capture_lost", "tc_capture_subscriber_drops", "tix_tcp_subscriber_drops"],
    )
    if capture_pressure:
        hints.append({"area": "capture_or_userspace_backpressure", "counters": capture_pressure})
    crypto_errors = nonzero(
        [node.get("kernel_crypto", {}) for node in nodes.values()],
        [
            "kernel_crypto_frame_seal_errors",
            "kernel_crypto_frame_open_errors",
            "kernel_crypto_frame_replay_drops",
            "xdp_kernel_crypto_open_errors",
            "tx_kernel_crypto_packet_seal_errors",
        ],
    )
    if crypto_errors:
        hints.append({"area": "kernel_crypto_errors", "counters": crypto_errors})
    if bursts.get("udp_lost"):
        hints.append({"area": "udp_payload_loss", "lost_packets": bursts["udp_lost"]})
    if bursts.get("tcp_short_reads"):
        hints.append({"area": "tcp_payload_short_reads", "short_reads": bursts["tcp_short_reads"]})
    if not hints:
        hints.append({"area": "none_obvious", "note": "no ring, capture, crypto, or payload-loss counters were non-zero"})
    return hints

nodes = {}
for node in ("ix-a", "ix-b"):
    datapath = try_load(f"{node}-datapath.json")
    bpf = try_load(f"{node}-bpf.json")
    if not isinstance(datapath, dict) or not isinstance(bpf, dict):
        continue
    node_counters = counters(datapath)
    node_bpf_counters = bpf_counters(bpf)
    experimental = exp(datapath)
    provider_stats = experimental.get("provider_stats") or {}
    kernel_probe = experimental.get("kernel_crypto_probe") or {}
    nodes[node] = {
        "provider": experimental.get("provider"),
        "fast_path": bool(experimental.get("fast_path")),
        "requested_crypto": experimental.get("requested_crypto"),
        "effective_crypto": experimental.get("effective_crypto"),
        "kernel_crypto_capable": bool(experimental.get("kernel_crypto")),
        "provider_ready": bool(kernel_probe.get("provider_ready")),
        "xdp_attach_mode": experimental.get("xdp_attach_mode"),
        "af_xdp_bind_mode": experimental.get("af_xdp_bind_mode"),
        "zerocopy_enabled": bool(experimental.get("zerocopy_enabled")),
        "traffic": {
            **pick(node_counters, [
                "packets_sent",
                "packets_received",
                "packets_injected",
            ]),
            **pick(provider_stats, [
                "tx_umem_direct_build_frames",
                "tx_frames",
                "rx_frames",
                "rx_umem_direct_frames",
                "xdp_redirected",
            ]),
        },
        "kernel_crypto": pick(provider_stats, [
            "kernel_crypto_frame_seal_successes",
            "kernel_crypto_frame_open_successes",
            "kernel_crypto_frame_seal_errors",
            "kernel_crypto_frame_open_errors",
            "kernel_crypto_frame_replay_drops",
            "xdp_kernel_crypto_open_attempts",
            "xdp_kernel_crypto_open_successes",
            "xdp_kernel_crypto_open_errors",
            "tx_kernel_crypto_packet_seal_attempts",
            "tx_kernel_crypto_packet_seal_successes",
            "tx_kernel_crypto_packet_seal_errors",
        ]),
        "ring_pressure": pick(provider_stats, [
            "tx_pool_exhausted",
            "tx_ring_full",
            "tx_kick_errors",
            "tx_backpressure_waits",
            "tx_backpressure_reclaims",
            "tx_backpressure_timeouts",
            "rx_invalid",
            "rx_recycle_errors",
        ]),
        "capture_pressure": pick(node_bpf_counters, [
            "tc_capture_events",
            "tc_capture_lost",
            "tc_capture_subscriber_drops",
            "tix_tcp_subscriber_drops",
        ]),
    }

payload_runs = payload_bursts()
payload_summary = burst_summary(payload_runs)
summary = {
    "placement": placement,
    "exit_code": int(rc),
    "elapsed_seconds": float(elapsed),
    "payload_bursts": payload_runs,
    "payload_summary": payload_summary,
    "bottleneck_hints": bottleneck_hints(nodes, payload_summary),
    "workdir": directory,
    "nodes": nodes,
}
print(json.dumps(summary, indent=2, sort_keys=True))
PY
}

main() {
  [[ "$(uname -s)" == "Linux" ]] || die "benchmark must run on Linux"
  [[ "${EUID:-$(id -u)}" == "0" ]] || die "benchmark must run as root for netns, TC/eBPF, and AF_XDP"
  [[ -f "$smoke_script" ]] || die "linux e2e smoke script not found: $smoke_script"
  need_cmd bash
  need_cmd date
  need_cmd grep
  need_cmd python3
  case "$run_kernel" in
    auto|1|true|yes|on|0|false|no|off) ;;
    *) die "TRUSTIX_TIX_TCP_BENCH_KERNEL must be auto, 1, or 0" ;;
  esac

  mkdir -p "$workdir"
  log "workdir: $workdir"
  run_one userspace

  case "$run_kernel" in
    1|true|yes|on)
      run_one kernel
      ;;
    auto)
      if kernel_provider_loaded || bool_enabled "$kernel_module"; then
        run_one kernel
      else
        log "skip kernel placement benchmark: trustix_crypto is not loaded and TRUSTIX_TIX_TCP_BENCH_KERNEL_MODULE is not enabled"
      fi
      ;;
    0|false|no|off)
      ;;
  esac
}

main "$@"
