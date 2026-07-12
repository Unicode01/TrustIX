#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"

normalize_goarch() {
  case "${1:-}" in
    amd64|x86_64) printf 'amd64\n' ;;
    arm64|aarch64) printf 'arm64\n' ;;
    arm|armv6l|armv7l|armhf) printf 'arm\n' ;;
    *) printf '%s\n' "$1" ;;
  esac
}

host_goarch() {
  normalize_goarch "$(uname -m)"
}

release_goarch="$(normalize_goarch "${GOARCH:-$(host_goarch)}")"
default_tarball="${repo_root}/build/release/trustix-linux-${release_goarch}.tar.gz"
tarball="${1:-${TRUSTIX_RELEASE_TARBALL:-$default_tarball}}"
workdir="${TRUSTIX_RELEASE_SMOKE_WORKDIR:-/tmp/trustix-release-smoke}"
keep="${TRUSTIX_RELEASE_SMOKE_KEEP:-0}"
api_addr="${TRUSTIX_RELEASE_SMOKE_API:-}"
peer_api_addr="${TRUSTIX_RELEASE_SMOKE_PEER_API:-}"
require_embedded_modules="${TRUSTIX_RELEASE_SMOKE_REQUIRE_MODULES:-1}"
module_unload_on_exit="${TRUSTIX_RELEASE_SMOKE_UNLOAD_MODULES_ON_EXIT:-1}"
tls_smoke="${TRUSTIX_RELEASE_SMOKE_TLS:-auto}"
nat_reverse_smoke="${TRUSTIX_RELEASE_SMOKE_NAT_REVERSE:-auto}"
control_smoke="${TRUSTIX_RELEASE_SMOKE_CONTROL:-0}"
three_ix_smoke="${TRUSTIX_RELEASE_SMOKE_3IX:-0}"
three_ix_kernel_udp_smoke="${TRUSTIX_RELEASE_SMOKE_3IX_KERNEL_UDP:-0}"
exp_tcp_bench_smoke="${TRUSTIX_RELEASE_SMOKE_EXP_TCP_BENCH:-0}"
iptunnel_smoke="${TRUSTIX_RELEASE_SMOKE_IPTUNNEL:-auto}"
device_access_smoke="${TRUSTIX_RELEASE_SMOKE_DEVICE_ACCESS:-auto}"
allocated_ports=""
preexisting_crypto=0
preexisting_datapath=0
preexisting_helpers=0

grep -q '^trustix_crypto ' /proc/modules 2>/dev/null && preexisting_crypto=1
grep -q '^trustix_datapath ' /proc/modules 2>/dev/null && preexisting_datapath=1
grep -q '^trustix_datapath_helpers ' /proc/modules 2>/dev/null && preexisting_helpers=1

log() {
  printf '[trustix-smoke] %s\n' "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
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
  printf '127.0.0.1:%s\n' "$port"
}

remember_addr_port() {
  local addr="$1"
  allocated_ports="${allocated_ports} ${addr##*:}"
}

allocate_ports() {
  api_addr="$(choose_port TRUSTIX_RELEASE_SMOKE_API 18787)"
  remember_addr_port "$api_addr"
  peer_api_addr="$(choose_port TRUSTIX_RELEASE_SMOKE_PEER_API 19443)"
  remember_addr_port "$peer_api_addr"
}

stop_daemon() {
  if [[ -n "$daemon_pid" ]] && kill -0 "$daemon_pid" >/dev/null 2>&1; then
    kill "$daemon_pid" >/dev/null 2>&1 || true
    wait "$daemon_pid" >/dev/null 2>&1 || true
  fi
  daemon_pid=""
}

daemon_pid=""
cleanup_leaked_release_processes() {
  local proc exe pid
  local -a leaked=()
  for proc in /proc/[0-9]*; do
    [[ -e "$proc/exe" ]] || continue
    exe="$(readlink "$proc/exe" 2>/dev/null || true)"
    case "$exe" in
      "$workdir"/extract/bin/*)
        leaked+=("${proc##*/}")
        ;;
    esac
  done
  ((${#leaked[@]} > 0)) || return 0

  log "ERROR: release smoke leaked packaged process(es): ${leaked[*]}"
  kill "${leaked[@]}" >/dev/null 2>&1 || true
  for _ in {1..50}; do
    local alive=0
    for pid in "${leaked[@]}"; do
      if kill -0 "$pid" >/dev/null 2>&1; then
        alive=1
        break
      fi
    done
    [[ "$alive" == "1" ]] || return 1
    sleep 0.1
  done
  kill -9 "${leaked[@]}" >/dev/null 2>&1 || true
  return 1
}

unload_new_module() {
  local module_name="$1" preexisting="$2"
  [[ "$preexisting" == "0" ]] || return 0
  grep -q "^${module_name} " /proc/modules 2>/dev/null || return 0
  local attempt
  for attempt in {1..50}; do
    rmmod "$module_name" >/dev/null 2>&1 || true
    grep -q "^${module_name} " /proc/modules 2>/dev/null || return 0
    sleep 0.1
  done
  log "ERROR: ${module_name} remained loaded after release smoke cleanup"
  return 1
}

cleanup() {
  local exit_code=$?
  trap - EXIT
  set +e
  stop_daemon
  if ! cleanup_leaked_release_processes && [[ "$exit_code" == "0" ]]; then
    exit_code=1
  fi
  case "$module_unload_on_exit" in
    1|true|yes|on)
      if ! unload_new_module trustix_datapath "$preexisting_datapath" && [[ "$exit_code" == "0" ]]; then
        exit_code=1
      fi
      if ! unload_new_module trustix_datapath_helpers "$preexisting_helpers" && [[ "$exit_code" == "0" ]]; then
        exit_code=1
      fi
      if ! unload_new_module trustix_crypto "$preexisting_crypto" && [[ "$exit_code" == "0" ]]; then
        exit_code=1
      fi
      ;;
  esac
  if [[ "$keep" != "1" ]]; then
    rm -rf "$workdir"
  else
    log "kept workdir: $workdir"
  fi
  exit "$exit_code"
}
trap cleanup EXIT

main() {
  [[ "$(uname -s)" == "Linux" ]] || die "release smoke must run on Linux"
  [[ -f "$tarball" ]] || die "release tarball not found: $tarball"
  need_cmd tar
  need_cmd python3
  need_cmd readlink
  need_cmd realpath

  allocate_ports
  case "$tls_smoke" in
    auto|1|true|yes|on|0|false|no|off) ;;
    *) die "TRUSTIX_RELEASE_SMOKE_TLS must be auto, 1, or 0" ;;
  esac
  case "$nat_reverse_smoke" in
    auto|1|true|yes|on|0|false|no|off) ;;
    *) die "TRUSTIX_RELEASE_SMOKE_NAT_REVERSE must be auto, 1, or 0" ;;
  esac
  case "$control_smoke" in
    1|true|yes|on|0|false|no|off) ;;
    *) die "TRUSTIX_RELEASE_SMOKE_CONTROL must be 1 or 0" ;;
  esac
  case "$three_ix_smoke" in
    1|true|yes|on|0|false|no|off) ;;
    *) die "TRUSTIX_RELEASE_SMOKE_3IX must be 1 or 0" ;;
  esac
  case "$three_ix_kernel_udp_smoke" in
    1|true|yes|on|0|false|no|off) ;;
    *) die "TRUSTIX_RELEASE_SMOKE_3IX_KERNEL_UDP must be 1 or 0" ;;
  esac
  case "$exp_tcp_bench_smoke" in
    1|true|yes|on|0|false|no|off) ;;
    *) die "TRUSTIX_RELEASE_SMOKE_EXP_TCP_BENCH must be 1 or 0" ;;
  esac
  case "$iptunnel_smoke" in
    auto|1|true|yes|on|0|false|no|off) ;;
    *) die "TRUSTIX_RELEASE_SMOKE_IPTUNNEL must be auto, 1, or 0" ;;
  esac
  case "$device_access_smoke" in
    auto|1|true|yes|on|0|false|no|off) ;;
    *) die "TRUSTIX_RELEASE_SMOKE_DEVICE_ACCESS must be auto, 1, or 0" ;;
  esac
  case "$module_unload_on_exit" in
    1|true|yes|on|0|false|no|off) ;;
    *) die "TRUSTIX_RELEASE_SMOKE_UNLOAD_MODULES_ON_EXIT must be 1 or 0" ;;
  esac
  local module_unload_on_exit_yaml="false"
  case "$module_unload_on_exit" in
    1|true|yes|on) module_unload_on_exit_yaml="true" ;;
  esac
  rm -rf "$workdir"
  mkdir -p "$workdir/extract" "$workdir/runtime" "$workdir/certs"
  log "extract $(realpath "$tarball")"
  tar -C "$workdir/extract" -xzf "$tarball"

  local bin_dir="${workdir}/extract/bin"
  [[ -x "${bin_dir}/trustixd" ]] || die "missing executable bin/trustixd"
  [[ -x "${bin_dir}/trustixctl" ]] || die "missing executable bin/trustixctl"
  [[ -x "${bin_dir}/trustix-ca" ]] || die "missing executable bin/trustix-ca"
  [[ -x "${bin_dir}/trustix-device" ]] || die "missing executable bin/trustix-device"
  [[ -x "${bin_dir}/trustix-iptunnel-smoke" ]] || die "missing executable bin/trustix-iptunnel-smoke"

  log "generate smoke certificates"
  "${bin_dir}/trustix-ca" quickstart -out "$workdir/certs" -domain lab.local -ix ix-a >/dev/null

  local module_mode="auto"
  local module_preloaded="0"
  if [[ "$require_embedded_modules" == "1" && "$(id -u)" == "0" ]]; then
    module_mode="required"
    if grep -q '^trustix_crypto ' /proc/modules 2>/dev/null; then
      module_preloaded="1"
    fi
  fi

  local config_path="${workdir}/smoke.yaml"
  cat >"$config_path" <<EOF
domain:
  id: lab.local
  trust_roots:
    - ${workdir}/certs/root-ca.pem
    - ${workdir}/certs/domain-ca.pem
    - ${workdir}/certs/config-ca.pem

ix:
  id: ix-a
  domain: lab.local
  cert: ${workdir}/certs/ix-a.crt
  key: ${workdir}/certs/ix-a.key
  control_api: https://${peer_api_addr}
  config_log: ${workdir}/runtime/config.log
  route_authorizations: []

lan:
  iface: ""
  gateway: ""
  advertise: []
  mode: routed
  manage_address: false
  manage_forwarding: false
  manage_rp_filter: false

kernel_modules:
  trustix_crypto:
    mode: ${module_mode}
    path: embedded
    reload_on_upgrade: auto
    unload_on_exit: ${module_unload_on_exit_yaml}
  trustix_datapath:
    mode: auto
    path: embedded
    reload_on_upgrade: auto
    unload_on_exit: ${module_unload_on_exit_yaml}
  trustix_datapath_helpers:
    mode: auto
    path: embedded
    reload_on_upgrade: auto
    unload_on_exit: ${module_unload_on_exit_yaml}

endpoints: []
peers: []
routes: []
route_policy:
  import_prefixes: []
  export_prefixes: []
  dynamic_metric: 1000
policies: []
transport_policy:
  mode: user_defined
  profile: stable
  datapath: userspace
  candidates: []
  failover: health_based
  encryption: secure
  crypto_key_source: auto
  crypto_placement: userspace
  kernel_transport:
    mode: disabled
EOF

  log "start trustixd api=${api_addr} peer-api=${peer_api_addr} dataplane=noop module_mode=${module_mode}"
  "${bin_dir}/trustixd" -config "$config_path" -data-dir "$workdir/runtime" -api "$api_addr" -peer-api "$peer_api_addr" -dataplane noop >"$workdir/trustixd.log" 2>&1 &
  daemon_pid=$!

  local status_path="${workdir}/status.json"
  local doctor_path="${workdir}/doctor.json"
  local config_verify_path="${workdir}/config-verify.json"
  local config_rejoin_path="${workdir}/config-rejoin.json"
  local status_after_rejoin_path="${workdir}/status-after-rejoin.json"
  local config_verify_after_rejoin_path="${workdir}/config-verify-after-rejoin.json"
  local api_url="http://${api_addr}"
  local ready=0
  for _ in {1..80}; do
    if "${bin_dir}/trustixctl" -api "$api_url" status >"$status_path" 2>"$workdir/status.err"; then
      ready=1
      break
    fi
    if ! kill -0 "$daemon_pid" >/dev/null 2>&1; then
      die "trustixd exited before status was ready; see $workdir/trustixd.log"
    fi
    sleep 0.25
  done
  [[ "$ready" == "1" ]] || die "status endpoint did not become ready; see $workdir/trustixd.log"

  "${bin_dir}/trustixctl" -api "$api_url" doctor >"$doctor_path"
  "${bin_dir}/trustixctl" -api "$api_url" config verify >"$config_verify_path"
  "${bin_dir}/trustixctl" -api "$api_url" config rejoin "https://${peer_api_addr}" ix-a >"$config_rejoin_path"
  "${bin_dir}/trustixctl" -api "$api_url" status >"$status_after_rejoin_path"
  "${bin_dir}/trustixctl" -api "$api_url" config verify >"$config_verify_after_rejoin_path"
  python3 - "$status_path" "$doctor_path" "$config_verify_path" "$status_after_rejoin_path" "$config_verify_after_rejoin_path" "$module_mode" "$require_embedded_modules" <<'PY'
import json
import sys

status_path, doctor_path, verify_path, status_after_rejoin_path, verify_after_rejoin_path, module_mode, require_embedded_modules = sys.argv[1:8]
with open(status_path, "r", encoding="utf-8") as handle:
    status = json.load(handle)
with open(doctor_path, "r", encoding="utf-8") as handle:
    doctor = json.load(handle)
with open(verify_path, "r", encoding="utf-8") as handle:
    verify = json.load(handle)
with open(status_after_rejoin_path, "r", encoding="utf-8") as handle:
    status_after_rejoin = json.load(handle)
with open(verify_after_rejoin_path, "r", encoding="utf-8") as handle:
    verify_after_rejoin = json.load(handle)

build = status.get("build") or {}
missing_build = [key for key in ("version", "commit", "built_at", "go_version", "goos", "goarch") if not build.get(key)]
if missing_build:
    raise SystemExit(f"missing build fields: {', '.join(missing_build)}")

assets = build.get("assets") or {}
ebpf = assets.get("ebpf") or {}
required_ebpf = [
    "experimental_tcp_xdp_bpfel.o",
    "experimental_tcp_kernel_crypto_xdp_bpfel.o",
    "experimental_tcp_kernel_crypto_xdp_direct_bpfel.o",
    "experimental_tcp_kernel_crypto_tx_xdp_bpfel.o",
    "kernel_udp_xdp_bpfel.o",
    "kernel_udp_tx_kernel_crypto_tc_bpfel.o",
    "kernel_udp_tx_kernel_crypto_tc_routegso_bpfel.o",
    "kernel_udp_rx_kernel_crypto_tc_bpfel.o",
    "kernel_udp_rx_kernel_crypto_tc_skbopen_bpfel.o",
    "kernel_udp_rx_kernel_crypto_tc_skbopen_decap_l2_bpfel.o",
    "skb_kfunc_tc_bpfel.o",
    "kernel_crypto_provider_bpfel.o",
    "kernel_crypto_selftest_bpfel.o",
]
bad_ebpf = []
for name in required_ebpf:
    asset = ebpf.get(name) or {}
    if not asset.get("present") or not asset.get("sha256") or not asset.get("elf"):
        bad_ebpf.append(name)
if bad_ebpf:
    raise SystemExit(f"embedded eBPF metadata is incomplete: {', '.join(bad_ebpf)}")

embedded_kos = assets.get("embedded_kos") or {}
ko = embedded_kos.get("trustix_crypto.ko") or {}
if require_embedded_modules == "1" and (not ko.get("present") or not ko.get("sha256") or not ko.get("elf")):
    raise SystemExit("embedded trustix_crypto.ko metadata is incomplete")
datapath_ko = embedded_kos.get("trustix_datapath_helpers.ko") or {}
full_datapath_ko = embedded_kos.get("trustix_datapath.ko") or {}
if require_embedded_modules == "1" and (not datapath_ko.get("present") or not datapath_ko.get("sha256") or not datapath_ko.get("elf")):
    raise SystemExit("embedded trustix_datapath_helpers.ko metadata is incomplete")
if require_embedded_modules == "1" and (not full_datapath_ko.get("present") or not full_datapath_ko.get("sha256") or not full_datapath_ko.get("elf")):
    raise SystemExit("embedded trustix_datapath.ko metadata is incomplete")

modules = {module.get("name"): module for module in status.get("kernel_modules") or []}
module = modules.get("trustix_crypto")
if not module:
    raise SystemExit("kernel_modules.trustix_crypto is missing from status")
if module_mode == "required" and not module.get("loaded"):
    raise SystemExit("kernel module was required but status does not report it loaded")
datapath_module = modules.get("trustix_datapath_helpers")
if not datapath_module:
    raise SystemExit("kernel_modules.trustix_datapath_helpers is missing from status")
full_datapath_module = modules.get("trustix_datapath")
if not full_datapath_module:
    raise SystemExit("kernel_modules.trustix_datapath is missing from status")

transport_tls = status.get("transport_tls") or {}
if transport_tls.get("wire_format") != "trustix-secure-data-v1":
    raise SystemExit("transport_tls wire_format is missing or unexpected")

transport_tls_check = next((check for check in doctor if check.get("name") == "transport_tls"), None)
if not transport_tls_check:
    raise SystemExit("transport_tls doctor check is missing")
if transport_tls_check.get("status") != "ok":
    raise SystemExit(f"transport_tls doctor check is not ok: {transport_tls_check.get('status')}")
if not any(check.get("name") == "firewall_compat" for check in doctor):
    raise SystemExit("firewall_compat doctor check is missing")

if verify.get("valid") is not True:
    raise SystemExit("config verify did not report a valid log before rejoin")
if verify.get("events", 0) < 1:
    raise SystemExit("config verify did not report any events")
if "/domain/genesis" not in (verify.get("resources") or {}):
    raise SystemExit("config verify did not report /domain/genesis")

state_files = status.get("state_files") or {}
state_file_map = {entry.get("name"): entry for entry in state_files.get("files") or []}
config_log_state = state_file_map.get("config_log")
if not config_log_state:
    raise SystemExit("status state_files has no config_log entry")
if config_log_state.get("backup_keep", 0) < 1:
    raise SystemExit("config_log state file did not expose backup retention")

state_files_after = status_after_rejoin.get("state_files") or {}
state_file_map_after = {entry.get("name"): entry for entry in state_files_after.get("files") or []}
config_log_state_after = state_file_map_after.get("config_log") or {}
if config_log_state_after.get("backups", 0) < 1:
    raise SystemExit("config rejoin did not create a config log backup visible in status")
if verify_after_rejoin.get("valid") is not True:
    raise SystemExit("config verify did not report a valid log after rejoin")
if len(verify_after_rejoin.get("backups") or []) < 1:
    raise SystemExit("config verify did not list the config log backup created by rejoin")
PY

  stop_daemon
  if [[ "$module_mode" == "required" && "$module_unload_on_exit_yaml" == "true" && "$module_preloaded" == "0" ]]; then
    if grep -q '^trustix_crypto ' /proc/modules 2>/dev/null; then
      die "embedded trustix_crypto module remained loaded after daemon exit with unload_on_exit=${module_unload_on_exit}"
    fi
    if grep -q '^trustix_datapath_helpers ' /proc/modules 2>/dev/null; then
      die "embedded trustix_datapath_helpers module remained loaded after daemon exit with unload_on_exit=${module_unload_on_exit}"
    fi
    if grep -q '^trustix_datapath ' /proc/modules 2>/dev/null; then
      die "embedded trustix_datapath module remained loaded after daemon exit with unload_on_exit=${module_unload_on_exit}"
    fi
    log "verified embedded TrustIX modules unloaded on daemon exit"
  fi
  "${bin_dir}/trustixd" -config "$config_path" -data-dir "$workdir/runtime" -dataplane noop -cleanup-dataplane-dry-run >"$workdir/cleanup-plan.json"
  python3 - "$workdir/cleanup-plan.json" <<'PY'
import json
import sys
with open(sys.argv[1], "r", encoding="utf-8") as handle:
    plan = json.load(handle)
if not plan.get("spec"):
    raise SystemExit("cleanup dry-run plan has no spec")
steps = plan.get("steps") or []
if not steps:
    raise SystemExit("cleanup dry-run plan has no steps")
PY

  if [[ "$require_embedded_modules" == "1" && "$(id -u)" == "0" ]]; then
    local full_datapath_smoke="${workdir}/extract/scripts/linux-full-datapath-module-smoke.sh"
    [[ -x "$full_datapath_smoke" || -f "$full_datapath_smoke" ]] || die "release package is missing scripts/linux-full-datapath-module-smoke.sh"
    env \
      TRUSTIX_FULL_DATAPATH_KO="${workdir}/extract/kernel/trustix_datapath.ko" \
      TRUSTIX_FULL_DATAPATH_KERNELMODULE_TEST_BIN="${bin_dir}/kernelmodule.test" \
      TRUSTIX_FULL_DATAPATH_KEEP_LOADED=0 \
      bash "$full_datapath_smoke"

    local datapath_smoke="${workdir}/extract/scripts/linux-datapath-module-smoke.sh"
    [[ -x "$datapath_smoke" || -f "$datapath_smoke" ]] || die "release package is missing scripts/linux-datapath-module-smoke.sh"
    env \
      TRUSTIX_DATAPATH_KO="${workdir}/extract/kernel/trustix_datapath_helpers.ko" \
      TRUSTIX_DATAPATH_KERNELMODULE_TEST_BIN="${bin_dir}/kernelmodule.test" \
      TRUSTIX_DATAPATH_KEEP_LOADED=0 \
      bash "$datapath_smoke"
  fi

  run_optional_tls_release_smoke "$bin_dir"
  run_optional_nat_reverse_release_smoke "$bin_dir"
  run_optional_iptunnel_release_smoke "$bin_dir"
  run_optional_device_access_release_smoke "$bin_dir"
  run_optional_control_release_smoke "$bin_dir"
  run_optional_3ix_release_smoke "$bin_dir"
  run_optional_3ix_kernel_udp_release_smoke "$bin_dir"
  run_optional_exp_tcp_bench_release_smoke "$bin_dir"

  log "ok: status, doctor, config verify, config backup retention, cleanup dry-run, build metadata, embedded eBPF metadata, embedded .ko metadata"
}

run_optional_tls_release_smoke() {
  local bin_dir="$1"
  case "$tls_smoke" in
    1|true|yes|on)
      stop_daemon
      run_tls_release_smoke "$bin_dir"
      ;;
    auto)
      if [[ "$(id -u)" == "0" ]]; then
        stop_daemon
        run_tls_release_smoke "$bin_dir"
      else
        log "skip release TLS exporter/custom-cert smoke: not root"
      fi
      ;;
    0|false|no|off)
      ;;
  esac
}

run_tls_release_smoke() {
  local bin_dir="$1"
  local smoke_script="${workdir}/extract/scripts/linux-e2e-smoke.sh"
  [[ "$(id -u)" == "0" ]] || die "release TLS exporter/custom-cert smoke requires root because linux-e2e-smoke creates netns and TC/eBPF state"
  [[ -x "$smoke_script" || -f "$smoke_script" ]] || die "release package is missing scripts/linux-e2e-smoke.sh"
  log "run release TLS exporter/custom-cert smoke"
  env \
    TRUSTIX_E2E_BIN_DIR="$bin_dir" \
    TRUSTIX_E2E_WORKDIR="${workdir}/tls-e2e" \
    TRUSTIX_E2E_TRANSPORT=tcp \
    bash "$smoke_script"
}

run_optional_nat_reverse_release_smoke() {
  local bin_dir="$1"
  case "$nat_reverse_smoke" in
    1|true|yes|on)
      stop_daemon
      run_nat_reverse_release_smoke "$bin_dir"
      ;;
    auto)
      if [[ "$(id -u)" == "0" ]]; then
        stop_daemon
        run_nat_reverse_release_smoke "$bin_dir"
      else
        log "skip release NAT/no-public reverse smoke: not root"
      fi
      ;;
    0|false|no|off)
      ;;
  esac
}

run_nat_reverse_release_smoke() {
  local bin_dir="$1"
  local smoke_script="${workdir}/extract/scripts/linux-e2e-smoke.sh"
  [[ "$(id -u)" == "0" ]] || die "release NAT/no-public reverse smoke requires root because linux-e2e-smoke creates netns and TC/eBPF state"
  [[ -x "$smoke_script" || -f "$smoke_script" ]] || die "release package is missing scripts/linux-e2e-smoke.sh"
  local protocol
  for protocol in udp tcp kernel_udp experimental_tcp; do
    log "run release NAT/no-public reverse ${protocol} data-session smoke"
    env \
      TRUSTIX_E2E_BIN_DIR="$bin_dir" \
      TRUSTIX_E2E_WORKDIR="${workdir}/nat-reverse-${protocol}-e2e" \
      TRUSTIX_E2E_NAT_REVERSE=1 \
      TRUSTIX_E2E_TRANSPORT="$protocol" \
      TRUSTIX_E2E_CRASH_RESTART=0 \
      bash "$smoke_script"
  done
}

run_optional_iptunnel_release_smoke() {
  local bin_dir="$1"
  case "$iptunnel_smoke" in
    1|true|yes|on)
      stop_daemon
      run_iptunnel_release_smoke "$bin_dir"
      ;;
    auto)
      if [[ "$(id -u)" == "0" ]]; then
        stop_daemon
        run_iptunnel_release_smoke "$bin_dir"
      else
        log "skip release GRE/IPIP tunnel carrier smoke: not root"
      fi
      ;;
    0|false|no|off)
      ;;
  esac
}

run_iptunnel_release_smoke() {
  local bin_dir="$1"
  local smoke_script="${workdir}/extract/scripts/linux-iptunnel-smoke.sh"
  [[ "$(id -u)" == "0" ]] || die "release GRE/IPIP tunnel carrier smoke requires root because it creates netns and tunnel links"
  [[ -f "$smoke_script" ]] || die "release package is missing scripts/linux-iptunnel-smoke.sh"
  for protocol in gre ipip; do
    log "run release ${protocol} tunnel carrier smoke"
    env \
      TRUSTIX_IPTUNNEL_SMOKE_BIN_DIR="$bin_dir" \
      TRUSTIX_IPTUNNEL_SMOKE_WORKDIR="${workdir}/iptunnel-${protocol}" \
      TRUSTIX_IPTUNNEL_SMOKE_PROTOCOL="$protocol" \
      bash "$smoke_script"
  done
}

run_optional_device_access_release_smoke() {
  local bin_dir="$1"
  case "$device_access_smoke" in
    1|true|yes|on)
      stop_daemon
      run_device_access_release_smoke "$bin_dir"
      ;;
    auto)
      if [[ "$(id -u)" == "0" ]]; then
        stop_daemon
        run_device_access_release_smoke "$bin_dir"
      else
        log "skip release device-access smoke: not root"
      fi
      ;;
    0|false|no|off)
      ;;
  esac
}

run_device_access_release_smoke() {
  local bin_dir="$1"
  local smoke_script="${workdir}/extract/scripts/linux-device-access-smoke.sh"
  [[ "$(id -u)" == "0" ]] || die "release device-access smoke requires root because it creates netns, TUN, and TC/eBPF state"
  [[ -f "$smoke_script" ]] || die "release package is missing scripts/linux-device-access-smoke.sh"
  log "run release device-access smoke"
  env \
    TRUSTIX_DEVICE_ACCESS_SMOKE_BIN_DIR="$bin_dir" \
    TRUSTIX_DEVICE_ACCESS_SMOKE_WORKDIR="${workdir}/device-access-smoke" \
    bash "$smoke_script"
}

run_optional_control_release_smoke() {
  local bin_dir="$1"
  case "$control_smoke" in
    1|true|yes|on)
      stop_daemon
      run_control_release_smoke "$bin_dir"
      ;;
    0|false|no|off)
      ;;
  esac
}

run_control_release_smoke() {
  local bin_dir="$1"
  local membership_script="${workdir}/extract/scripts/linux-membership-smoke.sh"
  local policy_script="${workdir}/extract/scripts/linux-trust-policy-smoke.sh"
  [[ -f "$membership_script" ]] || die "release package is missing scripts/linux-membership-smoke.sh"
  [[ -f "$policy_script" ]] || die "release package is missing scripts/linux-trust-policy-smoke.sh"
  log "run release control-plane membership smoke"
  env \
    TRUSTIX_MEMBERSHIP_SMOKE_BIN_DIR="$bin_dir" \
    TRUSTIX_MEMBERSHIP_SMOKE_WORKDIR="${workdir}/membership-smoke" \
    bash "$membership_script"
  log "run release trust-policy smoke"
  env \
    TRUSTIX_POLICY_SMOKE_BIN_DIR="$bin_dir" \
    TRUSTIX_POLICY_SMOKE_WORKDIR="${workdir}/trust-policy-smoke" \
    bash "$policy_script"
}

run_optional_3ix_release_smoke() {
  local bin_dir="$1"
  case "$three_ix_smoke" in
    1|true|yes|on)
      stop_daemon
      run_3ix_release_smoke "$bin_dir"
      ;;
    0|false|no|off)
      ;;
  esac
}

run_3ix_release_smoke() {
  local bin_dir="$1"
  local smoke_script="${workdir}/extract/scripts/linux-three-ix-e2e-smoke.sh"
  [[ "$(id -u)" == "0" ]] || die "TRUSTIX_RELEASE_SMOKE_3IX=1 requires root because linux-three-ix-e2e-smoke creates netns and TC/eBPF state"
  [[ -f "$smoke_script" ]] || die "release package is missing scripts/linux-three-ix-e2e-smoke.sh"
  log "run release 3-IX experimental_tcp smoke"
  env \
    TRUSTIX_3IX_E2E_BIN_DIR="$bin_dir" \
    TRUSTIX_3IX_E2E_WORKDIR="${workdir}/three-ix-e2e" \
    bash "$smoke_script"
}

run_optional_3ix_kernel_udp_release_smoke() {
  local bin_dir="$1"
  case "$three_ix_kernel_udp_smoke" in
    1|true|yes|on)
      stop_daemon
      run_3ix_kernel_udp_release_smoke "$bin_dir"
      ;;
    0|false|no|off)
      ;;
  esac
}

run_3ix_kernel_udp_release_smoke() {
  local bin_dir="$1"
  local smoke_script="${workdir}/extract/scripts/linux-three-ix-e2e-smoke.sh"
  [[ "$(id -u)" == "0" ]] || die "TRUSTIX_RELEASE_SMOKE_3IX_KERNEL_UDP=1 requires root because linux-three-ix-e2e-smoke creates netns and TC/eBPF state"
  [[ -f "$smoke_script" ]] || die "release package is missing scripts/linux-three-ix-e2e-smoke.sh"
  log "run release 3-IX kernel_udp smoke"
  env \
    TRUSTIX_3IX_E2E_BIN_DIR="$bin_dir" \
    TRUSTIX_3IX_E2E_WORKDIR="${workdir}/three-ix-kernel-udp-e2e" \
    TRUSTIX_3IX_E2E_TRANSPORT=kernel_udp \
    bash "$smoke_script"
}

run_optional_exp_tcp_bench_release_smoke() {
  local bin_dir="$1"
  case "$exp_tcp_bench_smoke" in
    1|true|yes|on)
      stop_daemon
      run_exp_tcp_bench_release_smoke "$bin_dir"
      ;;
    0|false|no|off)
      ;;
  esac
}

run_exp_tcp_bench_release_smoke() {
  local bin_dir="$1"
  local bench_script="${workdir}/extract/scripts/linux-experimental-tcp-bench.sh"
  [[ "$(id -u)" == "0" ]] || die "TRUSTIX_RELEASE_SMOKE_EXP_TCP_BENCH=1 requires root because linux-experimental-tcp-bench creates netns and TC/eBPF state"
  [[ -f "$bench_script" ]] || die "release package is missing scripts/linux-experimental-tcp-bench.sh"
  log "run release experimental_tcp benchmark smoke"
  env \
    TRUSTIX_EXP_TCP_BENCH_BIN_DIR="$bin_dir" \
    TRUSTIX_EXP_TCP_BENCH_WORKDIR="${workdir}/experimental-tcp-bench" \
    bash "$bench_script"
}

main "$@"
