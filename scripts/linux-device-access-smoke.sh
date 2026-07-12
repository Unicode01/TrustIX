#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workdir="${TRUSTIX_DEVICE_ACCESS_SMOKE_WORKDIR:-$(mktemp -d /tmp/trustix-device-access.XXXXXX)}"
keep="${TRUSTIX_DEVICE_ACCESS_SMOKE_KEEP:-0}"
bin_dir="${TRUSTIX_DEVICE_ACCESS_SMOKE_BIN_DIR:-${workdir}/bin}"
port_base="${TRUSTIX_DEVICE_ACCESS_SMOKE_PORT_BASE:-$((28000 + (RANDOM % 20000)))}"

ns_ix="${TRUSTIX_DEVICE_ACCESS_SMOKE_NS_IX:-tix-device-ix}"
ns_host="${TRUSTIX_DEVICE_ACCESS_SMOKE_NS_HOST:-tix-device-host}"
ns_dev="${TRUSTIX_DEVICE_ACCESS_SMOKE_NS_DEV:-tix-device-client}"
lan_ix="${TRUSTIX_DEVICE_ACCESS_SMOKE_LAN_IX:-tixdix0}"
lan_host="${TRUSTIX_DEVICE_ACCESS_SMOKE_LAN_HOST:-tixdh0}"
underlay_ix="${TRUSTIX_DEVICE_ACCESS_SMOKE_UNDERLAY_IX:-tixdui0}"
underlay_dev="${TRUSTIX_DEVICE_ACCESS_SMOKE_UNDERLAY_DEV:-tixdud0}"
api_addr="${TRUSTIX_DEVICE_ACCESS_SMOKE_API:-127.0.0.1:$port_base}"
peer_api_addr="${TRUSTIX_DEVICE_ACCESS_SMOKE_PEER_API:-127.0.0.1:$((port_base + 1))}"
udp_addr="${TRUSTIX_DEVICE_ACCESS_SMOKE_UDP:-198.18.88.1:$((port_base + 2))}"

trustixd="${bin_dir}/trustixd"
trustixca="${bin_dir}/trustix-ca"
trustixdevice="${bin_dir}/trustix-device"
trustixctl="${bin_dir}/trustixctl"
daemon_pid=""
device_pid=""
success=0

log() {
  printf '[trustix-device-smoke] %s\n' "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

run_ns() {
  ip netns exec "$1" "${@:2}"
}

stop_pid() {
  local pid="${1:-}"
  [[ -n "$pid" ]] || return 0
  kill -0 "$pid" >/dev/null 2>&1 || return 0
  kill "$pid" >/dev/null 2>&1 || true
  for _ in $(seq 1 40); do
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      wait "$pid" >/dev/null 2>&1 || true
      return 0
    fi
    sleep 0.1
  done
  kill -9 "$pid" >/dev/null 2>&1 || true
  wait "$pid" >/dev/null 2>&1 || true
}

cleanup() {
  local rc=$?
  set +e
  stop_pid "$device_pid"
  stop_pid "$daemon_pid"
  ip netns del "$ns_ix" >/dev/null 2>&1 || true
  ip netns del "$ns_host" >/dev/null 2>&1 || true
  ip netns del "$ns_dev" >/dev/null 2>&1 || true
  if [[ "$keep" != "1" && "$success" == "1" && -z "${TRUSTIX_DEVICE_ACCESS_SMOKE_WORKDIR:-}" ]]; then
    rm -rf "$workdir"
  else
    log "workdir preserved: $workdir"
  fi
  exit "$rc"
}
trap cleanup EXIT

build_or_check_binaries() {
  if [[ -n "${TRUSTIX_DEVICE_ACCESS_SMOKE_BIN_DIR:-}" ]]; then
    [[ -x "$trustixd" ]] || die "missing executable: $trustixd"
    [[ -x "$trustixca" ]] || die "missing executable: $trustixca"
    [[ -x "$trustixdevice" ]] || die "missing executable: $trustixdevice"
    [[ -x "$trustixctl" ]] || die "missing executable: $trustixctl"
    return 0
  fi
  need_cmd go
  mkdir -p "$bin_dir"
  log "building trustixd/trustix-ca/trustix-device/trustixctl"
  (cd "$repo_root" && go build -o "$trustixd" ./cmd/trustixd)
  (cd "$repo_root" && go build -o "$trustixca" ./cmd/trustix-ca)
  (cd "$repo_root" && go build -o "$trustixdevice" ./cmd/trustix-device)
  (cd "$repo_root" && go build -o "$trustixctl" ./cmd/trustixctl)
}

setup_netns() {
  ip netns del "$ns_ix" >/dev/null 2>&1 || true
  ip netns del "$ns_host" >/dev/null 2>&1 || true
  ip netns del "$ns_dev" >/dev/null 2>&1 || true
  ip netns add "$ns_ix"
  ip netns add "$ns_host"
  ip netns add "$ns_dev"
  ip link add "$lan_ix" type veth peer name "$lan_host"
  ip link add "$underlay_ix" type veth peer name "$underlay_dev"
  ip link set "$lan_ix" netns "$ns_ix"
  ip link set "$lan_host" netns "$ns_host"
  ip link set "$underlay_ix" netns "$ns_ix"
  ip link set "$underlay_dev" netns "$ns_dev"
  for ns in "$ns_ix" "$ns_host" "$ns_dev"; do
    run_ns "$ns" ip link set lo up
  done
  run_ns "$ns_ix" ip link set "$lan_ix" up
  run_ns "$ns_host" ip link set "$lan_host" up
  run_ns "$ns_ix" ip link set "$underlay_ix" up
  run_ns "$ns_dev" ip link set "$underlay_dev" up
  run_ns "$ns_host" ip addr add 10.0.0.2/24 dev "$lan_host"
  run_ns "$ns_host" ip route replace default via 10.0.0.1
  run_ns "$ns_ix" ip addr add 198.18.88.1/30 dev "$underlay_ix"
  run_ns "$ns_dev" ip addr add 198.18.88.2/30 dev "$underlay_dev"
  run_ns "$ns_dev" ip route replace 198.18.88.0/30 dev "$underlay_dev"
}

write_configs() {
  mkdir -p "$workdir/certs" "$workdir/state-ix"
  "$trustixca" quickstart -out "$workdir/certs" -domain lab.local -ix ix-a >/dev/null
  "$trustixca" device issue -out "$workdir/certs" -domain lab.local -ix ix-a -device laptop-1 >/dev/null

  cat >"$workdir/ix.yaml" <<EOF
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
  config_log: ${workdir}/state-ix/config.log
  route_authorizations:
    - ${workdir}/certs/ix-a-route.crt
lan:
  iface: ${lan_ix}
  gateway: 10.0.0.1/24
  advertise:
    - 10.0.0.0/24
  mode: routed
  manage_address: true
  manage_forwarding: true
  manage_rp_filter: true
  device_access:
    enabled: true
    address_pool: 10.0.0.240/28
    lease_ttl: 1h
endpoints:
  - name: ix-a-udp
    listen: ${udp_addr}
    address: ${udp_addr}
    transport: udp
    enabled: true
peers: []
routes: []
route_policy:
  import_prefixes: []
  export_prefixes: []
policies: []
transport_policy:
  mode: user_defined
  profile: stable
  datapath: userspace
  candidates: []
  failover: health_based
  encryption: secure
  crypto_key_source: trustix_x25519
  crypto_placement: userspace
  kernel_transport:
    mode: disabled
EOF

  cat >"$workdir/device.yaml" <<EOF
domain: lab.local
ix: ix-a
endpoint:
  name: ix-a-udp
  address: ${udp_addr}
  transport: udp
cert: ${workdir}/certs/ix-a-laptop-1.crt
key: ${workdir}/certs/ix-a-laptop-1.key
trust_roots:
  - ${workdir}/certs/root-ca.pem
  - ${workdir}/certs/domain-ca.pem
encryption: secure
crypto_key_source: trustix_x25519
interface:
  name: trustix0
  mtu: 1400
  routes:
    - 10.0.0.0/24
stats_every: 0s
EOF
}

wait_for_udp_listener() {
  for _ in $(seq 1 80); do
    if run_ns "$ns_dev" ping -c 1 -W 1 198.18.88.1 >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  die "IX underlay did not become reachable"
}

wait_for_device_lease() {
  for _ in $(seq 1 80); do
    if run_ns "$ns_dev" ip -4 addr show dev trustix0 2>/dev/null | grep -q '10\.0\.0\.240/32'; then
      return 0
    fi
    if ! kill -0 "$device_pid" >/dev/null 2>&1; then
      die "trustix-device exited early; see ${workdir}/device.log"
    fi
    sleep 0.25
  done
  run_ns "$ns_dev" ip addr show >&2 || true
  die "device did not receive expected lease"
}

assert_ping() {
  local src_ns="$1"
  local dst="$2"
  local label="$3"
  for _ in $(seq 1 40); do
    if run_ns "$src_ns" ping -c 1 -W 1 "$dst" >/dev/null 2>&1; then
      log "$label ok"
      return 0
    fi
    sleep 0.25
  done
  die "$label failed"
}

ctl() {
  run_ns "$ns_ix" "$trustixctl" -api "http://${api_addr}" "$@"
}

ctl_signed() {
  run_ns "$ns_ix" "$trustixctl" -api "http://${api_addr}" \
    -admin-cert "$workdir/certs/admin-1.crt" \
    -admin-key "$workdir/certs/admin-1.key" \
    "$@"
}

assert_control_plane() {
  local list_file="$workdir/device-access-list.json"
  local show_file="$workdir/device-access-show.json"
  local revoke_file="$workdir/device-access-revoke.json"
  local post_file="$workdir/device-access-after-revoke.json"

  ctl device-access >"$list_file"
  grep -q '"enabled": true' "$list_file" || die "device-access list did not report enabled=true"
  grep -q '"leased": 1' "$list_file" || die "device-access list did not report one lease"
  grep -q '"online": 1' "$list_file" || die "device-access list did not report one online lease"
  grep -q '"device": "laptop-1"' "$list_file" || die "device-access list did not include laptop-1"
  grep -q '"address": "10.0.0.240"' "$list_file" || die "device-access list did not include expected lease address"
  grep -q '"cert_fingerprint": "' "$list_file" || die "device-access list did not include certificate fingerprint"

  ctl device-access show laptop-1 >"$show_file"
  grep -q '"device": "laptop-1"' "$show_file" || die "device-access show did not return laptop-1"
  grep -q '"online": true' "$show_file" || die "device-access show did not report online=true"

  ctl_signed device-access revoke laptop-1 >"$revoke_file"
  grep -q '"changed": true' "$revoke_file" || die "device-access revoke did not change state"
  grep -q '"dropped_sessions": 1' "$revoke_file" || die "device-access revoke did not drop one session"
  grep -q '"fingerprint": "' "$revoke_file" || die "device-access revoke did not return fingerprint"

  for _ in $(seq 1 40); do
    ctl device-access >"$post_file"
    if grep -q '"leased": 0' "$post_file" && grep -q '"online": 0' "$post_file" && grep -q '"revoked": 1' "$post_file"; then
      log "device-access control-plane revoke ok"
      return 0
    fi
    sleep 0.25
  done
  die "device-access revoke did not remove active lease"
}

assert_no_ping() {
  local src_ns="$1"
  local dst="$2"
  local label="$3"
  if run_ns "$src_ns" ping -c 1 -W 1 "$dst" >/dev/null 2>&1; then
    die "$label unexpectedly succeeded"
  fi
  log "$label blocked as expected"
}

main() {
  [[ "$(uname -s)" == "Linux" ]] || die "linux-device-access-smoke must run on Linux"
  [[ "${EUID:-$(id -u)}" == "0" ]] || die "linux-device-access-smoke must run as root for netns, TUN, and TC"
  need_cmd ip
  need_cmd ping
  build_or_check_binaries
  setup_netns
  write_configs

  log "starting IX daemon"
  ip netns exec "$ns_ix" "$trustixd" -config "$workdir/ix.yaml" -data-dir "$workdir/state-ix" -api "$api_addr" -peer-api "$peer_api_addr" -dataplane linux -api-admin-auth >"$workdir/ix.log" 2>&1 &
  daemon_pid=$!
  wait_for_udp_listener

  log "starting device client"
  ip netns exec "$ns_dev" "$trustixdevice" -config "$workdir/device.yaml" >"$workdir/device.log" 2>&1 &
  device_pid=$!
  wait_for_device_lease

  assert_ping "$ns_host" 10.0.0.240 "LAN host -> device"
  assert_ping "$ns_dev" 10.0.0.2 "device -> LAN host"
  assert_control_plane
  assert_no_ping "$ns_host" 10.0.0.240 "LAN host -> revoked device"
  success=1
  log "ok: device certificate, lease, TUN config, bidirectional LAN reachability, control-plane list/show/revoke"
}

main "$@"
