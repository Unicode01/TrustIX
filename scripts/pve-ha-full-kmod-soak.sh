#!/usr/bin/env bash
set -Eeuo pipefail

log() {
  printf '[trustix-pve-ha-soak] %s\n' "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

require_file() {
  [[ -f "$1" ]] || die "required file not found: $1"
}

require_positive_integer() {
  local name="$1" value="$2"
  [[ "$value" =~ ^[1-9][0-9]*$ ]] || die "${name} must be a positive integer"
}

require_test_vmid() {
  local name="$1" value="$2"
  require_positive_integer "$name" "$value"
  (( value >= 200 )) || die "${name} must be >= 200, got ${value}"
}

duration="${TRUSTIX_HA_SOAK_DURATION:-3600}"
offsets_raw="${TRUSTIX_HA_SOAK_FAILOVER_OFFSETS:-300 900 1500 2100 2700 3300}"
output="${TRUSTIX_HA_SOAK_OUTPUT:-}"
allowed_root="${TRUSTIX_HA_SOAK_ALLOWED_ROOT:-/root/trustix-pve-work}"
ssh_key="${TRUSTIX_HA_SOAK_SSH_KEY:-}"
known_hosts="${TRUSTIX_HA_SOAK_KNOWN_HOSTS:-}"
guest_prefix="${TRUSTIX_HA_SOAK_GUEST_PREFIX:-192.168.100.}"
vm_a="${TRUSTIX_HA_SOAK_VM_A:-200}"
vm_b="${TRUSTIX_HA_SOAK_VM_B:-201}"
vm_remote="${TRUSTIX_HA_SOAK_VM_REMOTE:-202}"
vm_client="${TRUSTIX_HA_SOAK_VM_CLIENT:-203}"
instance="${TRUSTIX_HA_SOAK_INSTANCE:-ix-ha}"
api_port="${TRUSTIX_HA_SOAK_API_PORT:-18787}"
remote_api_port="${TRUSTIX_HA_SOAK_REMOTE_API_PORT:-18788}"
endpoint_vip="${TRUSTIX_HA_SOAK_ENDPOINT_VIP:-10.203.3.210}"
endpoint_iface="${TRUSTIX_HA_SOAK_ENDPOINT_IFACE:-eth1}"
target_ip="${TRUSTIX_HA_SOAK_TARGET_IP:-10.220.0.2}"
remote_netns="${TRUSTIX_HA_SOAK_REMOTE_NETNS:-tix-host-b}"
tcp_forward_port="${TRUSTIX_HA_SOAK_TCP_FORWARD_PORT:-25201}"
tcp_reverse_port="${TRUSTIX_HA_SOAK_TCP_REVERSE_PORT:-25202}"
udp_forward_port="${TRUSTIX_HA_SOAK_UDP_FORWARD_PORT:-25203}"
udp_reverse_port="${TRUSTIX_HA_SOAK_UDP_REVERSE_PORT:-25204}"
tcp_parallel="${TRUSTIX_HA_SOAK_TCP_PARALLEL:-4}"
udp_rate="${TRUSTIX_HA_SOAK_UDP_RATE:-200M}"
traffic_seconds="${TRUSTIX_HA_SOAK_TRAFFIC_SECONDS:-8}"
traffic_pause="${TRUSTIX_HA_SOAK_TRAFFIC_PAUSE:-1}"
server_settle_seconds="${TRUSTIX_HA_SOAK_SERVER_SETTLE_SECONDS:-1}"
expected_module_sha256="${TRUSTIX_HA_SOAK_MODULE_SHA256:-}"
expected_module_srcversion="${TRUSTIX_HA_SOAK_MODULE_SRCVERSION:-}"
module_path="${TRUSTIX_HA_SOAK_MODULE_PATH:-/usr/local/lib/trustix/trustix_datapath.ko}"
transition_timeout="${TRUSTIX_HA_SOAK_TRANSITION_TIMEOUT:-60}"
rejoin_timeout="${TRUSTIX_HA_SOAK_REJOIN_TIMEOUT:-90}"
run_id="${TRUSTIX_HA_SOAK_RUN_ID:-trustix-ha-soak-$(date +%s)-$$}"

require_positive_integer TRUSTIX_HA_SOAK_DURATION "$duration"
require_positive_integer TRUSTIX_HA_SOAK_API_PORT "$api_port"
require_positive_integer TRUSTIX_HA_SOAK_REMOTE_API_PORT "$remote_api_port"
require_positive_integer TRUSTIX_HA_SOAK_TCP_PARALLEL "$tcp_parallel"
require_positive_integer TRUSTIX_HA_SOAK_TRAFFIC_SECONDS "$traffic_seconds"
require_positive_integer TRUSTIX_HA_SOAK_TRAFFIC_PAUSE "$traffic_pause"
require_positive_integer TRUSTIX_HA_SOAK_SERVER_SETTLE_SECONDS "$server_settle_seconds"
require_positive_integer TRUSTIX_HA_SOAK_TRANSITION_TIMEOUT "$transition_timeout"
require_positive_integer TRUSTIX_HA_SOAK_REJOIN_TIMEOUT "$rejoin_timeout"
for item in \
  "TRUSTIX_HA_SOAK_TCP_FORWARD_PORT:$tcp_forward_port" \
  "TRUSTIX_HA_SOAK_TCP_REVERSE_PORT:$tcp_reverse_port" \
  "TRUSTIX_HA_SOAK_UDP_FORWARD_PORT:$udp_forward_port" \
  "TRUSTIX_HA_SOAK_UDP_REVERSE_PORT:$udp_reverse_port"; do
  require_positive_integer "${item%%:*}" "${item#*:}"
done
for item in \
  "TRUSTIX_HA_SOAK_VM_A:$vm_a" \
  "TRUSTIX_HA_SOAK_VM_B:$vm_b" \
  "TRUSTIX_HA_SOAK_VM_REMOTE:$vm_remote" \
  "TRUSTIX_HA_SOAK_VM_CLIENT:$vm_client"; do
  require_test_vmid "${item%%:*}" "${item#*:}"
done
[[ -n "$output" ]] || die "TRUSTIX_HA_SOAK_OUTPUT is required"
[[ -n "$ssh_key" ]] || die "TRUSTIX_HA_SOAK_SSH_KEY is required"
[[ -n "$known_hosts" ]] || die "TRUSTIX_HA_SOAK_KNOWN_HOSTS is required"
[[ "$expected_module_sha256" =~ ^[0-9a-f]{64}$ ]] || \
  die "TRUSTIX_HA_SOAK_MODULE_SHA256 must be a lowercase SHA256"
[[ "$expected_module_srcversion" =~ ^[0-9A-F]+$ ]] || \
  die "TRUSTIX_HA_SOAK_MODULE_SRCVERSION is required"
[[ "$instance" =~ ^[A-Za-z0-9._-]+$ ]] || die "invalid instance: $instance"
[[ "$endpoint_vip" =~ ^[0-9.]+$ ]] || die "endpoint VIP must be IPv4"
[[ "$target_ip" =~ ^[0-9.]+$ ]] || die "target IP must be IPv4"
[[ "$guest_prefix" =~ ^[0-9.]+$ ]] || die "guest prefix must contain only IPv4 characters"
[[ "$endpoint_iface" =~ ^[A-Za-z0-9._-]+$ ]] || die "invalid endpoint interface"
[[ "$remote_netns" =~ ^[A-Za-z0-9._-]+$ ]] || die "invalid remote namespace"
[[ "$udp_rate" =~ ^[1-9][0-9]*[KMG]?$ ]] || die "invalid UDP rate: $udp_rate"
[[ "$run_id" =~ ^trustix-ha-soak-[A-Za-z0-9._-]+$ ]] || die "invalid run ID: $run_id"

require_command qm
require_command ssh
require_command awk
require_command sha256sum
require_command flock
require_command env
require_file "$ssh_key"
require_file "$known_hosts"
mkdir -p "$allowed_root"
allowed_root="$(cd "$allowed_root" && pwd -P)"
case "$output" in
  /*) ;;
  *) output="${PWD}/${output}" ;;
esac
output_parent="$(cd "$(dirname "$output")" && pwd -P)"
output="${output_parent}/$(basename "$output")"
case "$output" in
  "$allowed_root"/*) ;;
  *) die "output must stay under ${allowed_root}, got ${output}" ;;
esac
[[ ! -e "$output" ]] || die "output already exists: $output"
lock_file="${allowed_root}/.ha-full-kmod-soak.lock"
if [[ "${TRUSTIX_HA_SOAK_LOCKED_INTERNAL:-0}" != 1 ]]; then
  set +e
  flock -n -o -E 75 "$lock_file" env TRUSTIX_HA_SOAK_LOCKED_INTERNAL=1 bash "$0" "$@"
  lock_status=$?
  set -e
  (( lock_status != 75 )) || die "another full-kmod HA soak is already running"
  exit "$lock_status"
fi
unset TRUSTIX_HA_SOAK_LOCKED_INTERNAL
mkdir -p "$output"

ssh_opts=(
  -i "$ssh_key"
  -o "UserKnownHostsFile=${known_hosts}"
  -o StrictHostKeyChecking=yes
  -o BatchMode=yes
  -o ConnectTimeout=5
)

guest_ip() {
  printf '%s%s\n' "$guest_prefix" "$1"
}

gssh() {
  local vmid="$1"
  shift
  ssh -n "${ssh_opts[@]}" "root@$(guest_ip "$vmid")" "$@"
}

remote_cleanup_script="$(cat <<'REMOTE_CLEANUP'
set -Eeuo pipefail
root=/run/trustix-ha-soak
scope="${RUN_ID:-}"
if [[ -n "$scope" && ! "$scope" =~ ^trustix-ha-soak-[A-Za-z0-9._-]+$ ]]; then
  printf 'invalid TrustIX HA soak run ID: %s\n' "$scope" >&2
  exit 2
fi

collect_tagged_pids() {
  local env_file pid
  for env_file in /proc/[0-9]*/environ; do
    [[ -r "$env_file" ]] || continue
    if [[ -n "$scope" ]]; then
      tr '\0' '\n' 2>/dev/null <"$env_file" | \
        grep -Fxq "TRUSTIX_HA_SOAK_RUN_ID=$scope" || continue
    else
      tr '\0' '\n' 2>/dev/null <"$env_file" | \
        grep -Eq '^TRUSTIX_HA_SOAK_RUN_ID=trustix-ha-soak-[A-Za-z0-9._-]+$' || continue
    fi
    pid="${env_file#/proc/}"
    printf '%s\n' "${pid%/environ}"
  done
}

mapfile -t pids < <(collect_tagged_pids)
if (( ${#pids[@]} > 0 )); then
  kill -TERM "${pids[@]}" 2>/dev/null || true
  sleep 1
fi
mapfile -t pids < <(collect_tagged_pids)
if (( ${#pids[@]} > 0 )); then
  kill -KILL "${pids[@]}" 2>/dev/null || true
fi

if [[ -n "$scope" ]]; then
  rm -rf -- "$root/$scope"
elif [[ -d "$root" ]]; then
  shopt -s nullglob
  for dir in "$root"/trustix-ha-soak-*; do
    [[ -d "$dir" ]] || continue
    rm -rf -- "$dir"
  done
fi
rmdir "$root" 2>/dev/null || true
REMOTE_CLEANUP
)"

run_remote_cleanup() {
  local vmid="$1"
  local scope="$2"
  printf '%s\n' "$remote_cleanup_script" | ssh "${ssh_opts[@]}" \
    "root@$(guest_ip "$vmid")" "RUN_ID=$scope bash -s"
}

cleanup_stale_remote_load() {
  run_remote_cleanup "$vm_client" ""
  run_remote_cleanup "$vm_remote" ""
}

cleanup_remote_load() {
  local failed=0
  run_remote_cleanup "$vm_client" "$run_id" >/dev/null 2>&1 || failed=1
  run_remote_cleanup "$vm_remote" "$run_id" >/dev/null 2>&1 || failed=1
  return "$failed"
}

vm_status() {
  qm status "$1" | awk '{print $2}'
}

ha_state() {
  gssh "$1" "cut -d' ' -f1 /run/trustix-ha/${instance}.state 2>/dev/null || true"
}

master_ready() {
  local vmid="$1"
  gssh "$vmid" \
    "grep -q '^MASTER ' /run/trustix-ha/${instance}.state && curl -fsS --max-time 1 http://127.0.0.1:${api_port}/readyz >/dev/null"
}

backup_healthy() {
  local vmid="$1"
  gssh "$vmid" \
    "grep -q '^BACKUP ' /run/trustix-ha/${instance}.state && ! systemctl is-active --quiet trustixd@${instance}.service && ! ip -4 -o addr show dev ${endpoint_iface} | grep -q ' ${endpoint_vip}/'"
}

wait_guest_ssh() {
  local vmid="$1"
  local timeout="$2"
  local deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    if gssh "$vmid" true >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

wait_master_ready() {
  local vmid="$1"
  local timeout="$2"
  local deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    if master_ready "$vmid" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

wait_backup_healthy() {
  local vmid="$1"
  local timeout="$2"
  local deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    if backup_healthy "$vmid" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

verify_module_file() {
  local vmid="$1"
  gssh "$vmid" \
    "test \"\$(sha256sum '$module_path' | cut -d' ' -f1)\" = '$expected_module_sha256'"
}

verify_loaded_module() {
  local vmid="$1"
  gssh "$vmid" \
    "test \"\$(cat /sys/module/trustix_datapath/srcversion)\" = '$expected_module_srcversion' && test \"\$(cat /sys/module/trustix_datapath/parameters/selftest_failures)\" = 0 && test \"\$(cat /sys/module/trustix_datapath/parameters/selftests)\" = 1023"
}

capture_previous_kernel() {
  local vmid="$1" index="$2"
  gssh "$vmid" \
    "journalctl -k -b -1 --no-pager -o short-iso 2>/dev/null | egrep -i 'panic|oops|BUG:|Call Trace|RIP:|general protection|page fault|watchdog|soft lockup|hard LOCKUP|use-after-free|KASAN|rcu.*stall|blocked for more than|hung task|NETDEV WATCHDOG|workqueue lockup|scheduling while atomic|refcount_t:|list_del corruption|slab-out-of-bounds|double free' || true" \
    >"$output/kernel-vm${vmid}-transition-${index}-previous.log"
  gssh "$vmid" \
    'for f in /sys/fs/pstore/*; do [[ -f "$f" ]] || continue; printf "===== %s =====\n" "$f"; sed -n "1,240p" "$f"; done' \
    >"$output/pstore-vm${vmid}-transition-${index}.log"
}

background_pids=()
stop_background() {
  local pid
  for pid in "${background_pids[@]}"; do
    kill "$pid" >/dev/null 2>&1 || true
  done
  for pid in "${background_pids[@]}"; do
    wait "$pid" >/dev/null 2>&1 || true
  done
  background_pids=()
}

cleanup_on_exit() {
  local status=$?
  trap - EXIT
  cleanup_remote_load || true
  stop_background
  exit "$status"
}
trap cleanup_on_exit EXIT

traffic_script="$(cat <<'TRAFFIC'
set -Eeuo pipefail
: "${TRUSTIX_HA_SOAK_RUN_ID:?}"
: "${TRUSTIX_HA_SOAK_ROLE:?}"
[[ "$TRUSTIX_HA_SOAK_RUN_ID" =~ ^trustix-ha-soak-[A-Za-z0-9._-]+$ ]]
[[ "$TRUSTIX_HA_SOAK_ROLE" =~ ^[A-Za-z0-9._-]+$ ]]
run_dir="/run/trustix-ha-soak/$TRUSTIX_HA_SOAK_RUN_ID"
mkdir -p "$run_dir"
pid_file="$run_dir/$TRUSTIX_HA_SOAK_ROLE.pid"
tmp="$(mktemp /tmp/trustix-ha-traffic.XXXXXX)"
cleanup_worker() {
  rm -f "$tmp" "$pid_file"
}
trap cleanup_worker EXIT
trap 'exit 0' TERM INT
printf '%s\n' "$$" >"$pid_file"
deadline=$((SECONDS + DURATION))
while (( SECONDS + TEST_SECONDS + TRAFFIC_PAUSE + 1 < deadline )); do
  started="$(date +%s.%N)"
  args=(-c "$TARGET" -p "$PORT" -t "$TEST_SECONDS" -J)
  case "$MODE" in
    tcp_forward) args+=(-P "$PARALLEL") ;;
    tcp_reverse) args+=(-P "$PARALLEL" -R) ;;
    udp_forward) args+=(-P 1 -u -b "$UDP_RATE") ;;
    udp_reverse) args+=(-P 1 -u -b "$UDP_RATE" -R) ;;
    *) exit 2 ;;
  esac
  set +e
  timeout "$TEST_TIMEOUT" iperf3 "${args[@]}" >"$tmp" 2>&1
  rc=$?
  set -e
  finished="$(date +%s.%N)"
  sent=0
  received=0
  error=""
  if jq -e . "$tmp" >/dev/null 2>&1; then
    sent="$(jq -r '.end.sum_sent.bits_per_second // 0' "$tmp")"
    received="$(jq -r '.end.sum_received.bits_per_second // 0' "$tmp")"
    error="$(jq -r '.error // ""' "$tmp")"
  else
    error="$(tail -n 4 "$tmp" 2>/dev/null || true)"
  fi
  error="$(printf '%s' "$error" | tr '\t\r\n' '   ' | cut -c1-300)"
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$started" "$finished" "$rc" "$sent" "$received" "$error"
  sleep "$TRAFFIC_PAUSE"
done
TRAFFIC
)"

start_traffic() {
  local mode="$1" port="$2" log_file="$3"
  local stderr_file="${log_file%.tsv}.stderr.log"
  (
    printf '%s\n' "$traffic_script" | ssh "${ssh_opts[@]}" \
      "root@$(guest_ip "$vm_client")" \
      "TRUSTIX_HA_SOAK_RUN_ID=$run_id TRUSTIX_HA_SOAK_ROLE=traffic-$mode MODE=$mode PORT=$port TARGET=$target_ip PARALLEL=$tcp_parallel UDP_RATE=$udp_rate DURATION=$duration TEST_SECONDS=$traffic_seconds TEST_TIMEOUT=$((traffic_seconds + 12)) TRAFFIC_PAUSE=$traffic_pause bash -s"
  ) >"$log_file" 2>"$stderr_file" &
  background_pids+=("$!")
}

ping_script="$(cat <<'PING'
set -Eeuo pipefail
: "${TRUSTIX_HA_SOAK_RUN_ID:?}"
: "${TRUSTIX_HA_SOAK_ROLE:?}"
[[ "$TRUSTIX_HA_SOAK_RUN_ID" =~ ^trustix-ha-soak-[A-Za-z0-9._-]+$ ]]
[[ "$TRUSTIX_HA_SOAK_ROLE" =~ ^[A-Za-z0-9._-]+$ ]]
run_dir="/run/trustix-ha-soak/$TRUSTIX_HA_SOAK_RUN_ID"
mkdir -p "$run_dir"
pid_file="$run_dir/$TRUSTIX_HA_SOAK_ROLE.pid"
trap 'rm -f "$pid_file"' EXIT
trap 'exit 0' TERM INT
printf '%s\n' "$$" >"$pid_file"
timeout "$DURATION" ping -D -i 0.2 -W 1 "$TARGET"
PING
)"

monitor_script="$(cat <<'MONITOR'
set -Eeuo pipefail
: "${TRUSTIX_HA_SOAK_RUN_ID:?}"
: "${TRUSTIX_HA_SOAK_ROLE:?}"
[[ "$TRUSTIX_HA_SOAK_RUN_ID" =~ ^trustix-ha-soak-[A-Za-z0-9._-]+$ ]]
[[ "$TRUSTIX_HA_SOAK_ROLE" =~ ^[A-Za-z0-9._-]+$ ]]
run_dir="/run/trustix-ha-soak/$TRUSTIX_HA_SOAK_RUN_ID"
mkdir -p "$run_dir"
pid_file="$run_dir/$TRUSTIX_HA_SOAK_ROLE.pid"
trap 'rm -f "$pid_file"' EXIT
trap 'exit 0' TERM INT
printf '%s\n' "$$" >"$pid_file"
deadline=$((SECONDS + DURATION))
base=/sys/module/trustix_datapath/parameters
while (( SECONDS < deadline )); do
  row="$(date +%s.%N)"
  for name in \
    tx_plaintext_direct_xmit_packets \
    tx_plaintext_direct_xmit_dst_mac_cache_hits \
    tx_plaintext_direct_xmit_dst_mac_cache_misses \
    tx_plaintext_direct_xmit_dst_mac_cache_invalidations \
    tx_plaintext_direct_xmit_neigh_misses \
    tx_plaintext_stale_wires \
    rx_worker_injected; do
    row+=$'\t'"$(cat "$base/$name" 2>/dev/null || echo NA)"
  done
  row+=$'\t'"$(ip neigh show "$VIP" | tr ' ' '_')"
  printf '%s\n' "$row"
  sleep 1
done
MONITOR
)"

log "preflight"
for vmid in "$vm_a" "$vm_b" "$vm_remote" "$vm_client"; do
  [[ "$(vm_status "$vmid")" == running ]] || die "VM ${vmid} is not running"
done
cleanup_stale_remote_load || die "failed to clean stale tagged load processes"
state_a="$(ha_state "$vm_a")"
state_b="$(ha_state "$vm_b")"
if [[ "$state_a" == MASTER && "$state_b" == BACKUP ]]; then
  active="$vm_a"
  standby="$vm_b"
elif [[ "$state_b" == MASTER && "$state_a" == BACKUP ]]; then
  active="$vm_b"
  standby="$vm_a"
else
  die "expected one MASTER and one BACKUP, got vm${vm_a}=${state_a} vm${vm_b}=${state_b}"
fi
master_ready "$active" || die "initial MASTER vm${active} is not ready"
backup_healthy "$standby" || die "initial BACKUP vm${standby} is not healthy"
for vmid in "$vm_a" "$vm_b" "$vm_remote"; do
  verify_module_file "$vmid" || die "VM ${vmid} module file identity mismatch"
done
verify_loaded_module "$active" || die "initial MASTER loaded module mismatch"
verify_loaded_module "$vm_remote" || die "remote IX loaded module mismatch"
gssh "$vm_remote" "curl -fsS http://127.0.0.1:${remote_api_port}/readyz >/dev/null" || \
  die "remote IX is not ready"
gssh "$vm_client" "command -v iperf3 >/dev/null && command -v jq >/dev/null" || \
  die "client requires iperf3 and jq"
gssh "$vm_remote" "command -v iperf3 >/dev/null && ip netns list | grep -q '^${remote_netns}'" || \
  die "remote IX namespace or iperf3 is unavailable"
for port in "$tcp_forward_port" "$tcp_reverse_port" "$udp_forward_port" "$udp_reverse_port"; do
  gssh "$vm_remote" \
    "ip netns exec '$remote_netns' sh -c \"ss -lnt | grep -q ':${port} ' || env TRUSTIX_HA_SOAK_RUN_ID='$run_id' TRUSTIX_HA_SOAK_ROLE='server-${port}' iperf3 -s -D -p '${port}'\"" || \
    die "failed to start iperf3 server on port ${port}"
done
sleep "$server_settle_seconds"
gssh "$vm_client" "ping -c 5 -W 1 '$target_ip' >/dev/null" || die "initial overlay ping failed"

remote_boot_before="$(gssh "$vm_remote" 'cat /proc/sys/kernel/random/boot_id')"
client_boot_before="$(gssh "$vm_client" 'cat /proc/sys/kernel/random/boot_id')"
printf 'schema\ttrustix-pve-ha-full-kmod-soak-v1\n' >"$output/manifest.tsv"
printf 'duration\t%s\nrun_id\t%s\nmodule_sha256\t%s\nmodule_srcversion\t%s\n' \
  "$duration" "$run_id" "$expected_module_sha256" "$expected_module_srcversion" >>"$output/manifest.tsv"
printf 'vm_a\t%s\nvm_b\t%s\nvm_remote\t%s\nvm_client\t%s\n' \
  "$vm_a" "$vm_b" "$vm_remote" "$vm_client" >>"$output/manifest.tsv"
printf 'remote_boot_before\t%s\nclient_boot_before\t%s\ninitial_master\t%s\n' \
  "$remote_boot_before" "$client_boot_before" "$active" >>"$output/manifest.tsv"
printf 'index\ttype\told_master\tnew_master\ttrigger_epoch\tready_epoch\trecovery_seconds\trejoin_epoch\n' \
  >"$output/transitions.tsv"

(
  printf '%s\n' "$ping_script" | ssh "${ssh_opts[@]}" \
    "root@$(guest_ip "$vm_client")" \
    "TRUSTIX_HA_SOAK_RUN_ID=$run_id TRUSTIX_HA_SOAK_ROLE=ping DURATION=$((duration + 120)) TARGET=$target_ip bash -s"
) >"$output/ping.log" 2>"$output/ping.stderr.log" &
background_pids+=("$!")
start_traffic tcp_forward "$tcp_forward_port" "$output/tcp-forward.tsv"
start_traffic tcp_reverse "$tcp_reverse_port" "$output/tcp-reverse.tsv"
start_traffic udp_forward "$udp_forward_port" "$output/udp-forward.tsv"
start_traffic udp_reverse "$udp_reverse_port" "$output/udp-reverse.tsv"
(
  printf '%s\n' "$monitor_script" | ssh "${ssh_opts[@]}" \
    "root@$(guest_ip "$vm_remote")" \
    "TRUSTIX_HA_SOAK_RUN_ID=$run_id TRUSTIX_HA_SOAK_ROLE=module-monitor DURATION=$((duration + 120)) VIP=$endpoint_vip bash -s"
) >"$output/remote-module.tsv" 2>"$output/remote-module.stderr.log" &
background_pids+=("$!")
(
  deadline=$((SECONDS + duration + 120))
  while (( SECONDS < deadline )); do
    printf '%s\t%s\t%s\n' "$(date +%s.%N)" \
      "$(vm_status "$vm_a")" "$(vm_status "$vm_b")"
    sleep 1
  done
) >"$output/pve-state.tsv" 2>"$output/pve-state.stderr.log" &
background_pids+=("$!")

start_epoch="$(date +%s.%N)"
start_seconds="${start_epoch%%.*}"
printf '%s\n' "$start_epoch" >"$output/start.epoch"
index=0
for offset in $offsets_raw; do
  require_positive_integer TRUSTIX_HA_SOAK_FAILOVER_OFFSETS "$offset"
  (( offset < duration )) || die "failover offset ${offset} must be less than duration ${duration}"
  target_seconds=$((start_seconds + offset))
  while (( $(date +%s) < target_seconds )); do
    sleep 1
  done
  index=$((index + 1))
  master_ready "$active" || die "transition ${index}: vm${active} is not a ready MASTER"
  backup_healthy "$standby" || die "transition ${index}: vm${standby} is not a healthy BACKUP"
  trigger_epoch="$(date +%s.%N)"
  if (( index % 2 == 1 )); then
    event_type="host_stop"
    log "transition ${index}: stop vm${active}, expect vm${standby}"
    qm stop "$active" --timeout 10
  else
    event_type="vrrp_partition"
    log "transition ${index}: partition VRRP from vm${active}, expect fenced takeover by vm${standby}"
    standby_ip="$(guest_ip "$standby")"
    gssh "$active" \
      "iptables -I OUTPUT 1 -p 112 -d '$standby_ip' -m comment --comment trustix-ha-soak-vrrp -j DROP"
  fi
  if ! wait_master_ready "$standby" "$transition_timeout"; then
    die "transition ${index}: vm${standby} did not become ready MASTER"
  fi
  ready_epoch="$(date +%s.%N)"
  recovery="$(awk -v start="$trigger_epoch" -v end="$ready_epoch" 'BEGIN { printf "%.6f", end - start }')"
  verify_loaded_module "$standby" || die "transition ${index}: promoted module identity mismatch"
  verify_module_file "$standby" || die "transition ${index}: promoted module file mismatch"
  deadline=$((SECONDS + 20))
  while [[ "$(vm_status "$active")" != stopped && "$SECONDS" -lt "$deadline" ]]; do
    sleep 0.5
  done
  [[ "$(vm_status "$active")" == stopped ]] || \
    die "transition ${index}: old MASTER vm${active} was not fenced"
  qm start "$active"
  wait_guest_ssh "$active" "$rejoin_timeout" || \
    die "transition ${index}: old MASTER vm${active} did not boot"
  wait_backup_healthy "$active" "$rejoin_timeout" || \
    die "transition ${index}: old MASTER vm${active} did not rejoin as BACKUP"
  verify_module_file "$active" || die "transition ${index}: rejoined module file mismatch"
  gssh "$active" "sha256sum -c /etc/trustix/${instance}-state.sha256 >/dev/null" || \
    die "transition ${index}: rejoined HA state checksum mismatch"
  sleep 3
  master_ready "$standby" || die "transition ${index}: automatic failback changed the MASTER"
  backup_healthy "$active" || die "transition ${index}: rejoined node is not BACKUP"
  capture_previous_kernel "$active" "$index"
  rejoin_epoch="$(date +%s.%N)"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$index" "$event_type" "$active" "$standby" "$trigger_epoch" \
    "$ready_epoch" "$recovery" "$rejoin_epoch" >>"$output/transitions.tsv"
  old_active="$active"
  active="$standby"
  standby="$old_active"
done

end_target=$((start_seconds + duration))
while (( $(date +%s) < end_target )); do
  sleep 1
done
end_epoch="$(date +%s.%N)"
printf '%s\n' "$end_epoch" >"$output/end.epoch"
cleanup_remote_load || die "failed to clean remote load processes"
stop_background
trap - EXIT

remote_boot_after="$(gssh "$vm_remote" 'cat /proc/sys/kernel/random/boot_id')"
client_boot_after="$(gssh "$vm_client" 'cat /proc/sys/kernel/random/boot_id')"
[[ "$remote_boot_after" == "$remote_boot_before" ]] || die "remote IX rebooted during soak"
[[ "$client_boot_after" == "$client_boot_before" ]] || die "client rebooted during soak"
master_ready "$active" || die "final MASTER vm${active} is not ready"
backup_healthy "$standby" || die "final BACKUP vm${standby} is not healthy"
verify_loaded_module "$active" || die "final MASTER module identity mismatch"
verify_loaded_module "$vm_remote" || die "final remote module identity mismatch"
for vmid in "$vm_a" "$vm_b" "$vm_remote" "$vm_client"; do
  gssh "$vmid" \
      "journalctl -k -b --no-pager -o short-iso | egrep -i 'panic|oops|BUG:|Call Trace|RIP:|general protection|page fault|watchdog|soft lockup|hard LOCKUP|use-after-free|KASAN|rcu.*stall|blocked for more than|hung task|NETDEV WATCHDOG|workqueue lockup|scheduling while atomic|refcount_t:|list_del corruption|slab-out-of-bounds|double free' || true" \
    >"$output/kernel-vm${vmid}-current.log"
  gssh "$vmid" \
    'for f in /sys/fs/pstore/*; do [[ -f "$f" ]] || continue; printf "===== %s =====\n" "$f"; sed -n "1,240p" "$f"; done' \
    >"$output/pstore-vm${vmid}-current.log"
done
gssh "$active" 'grep -H . /sys/module/trustix_datapath/parameters/*' \
  >"$output/module-master-after.txt"
gssh "$vm_remote" 'grep -H . /sys/module/trustix_datapath/parameters/*' \
  >"$output/module-remote-after.txt"
gssh "$active" "curl -fsS http://127.0.0.1:${api_port}/readyz" \
  >"$output/master-ready-after.json"
gssh "$vm_remote" "curl -fsS http://127.0.0.1:${remote_api_port}/readyz" \
  >"$output/remote-ready-after.json"
printf 'remote_boot_after\t%s\nclient_boot_after\t%s\nfinal_master\t%s\nfinal_backup\t%s\n' \
  "$remote_boot_after" "$client_boot_after" "$active" "$standby" >>"$output/manifest.tsv"
printf 'runner_pass\n' >"$output/result"
log "runner completed: $output"
