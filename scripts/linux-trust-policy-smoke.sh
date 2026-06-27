#!/usr/bin/env bash
set -euo pipefail

BIN_DIR="${TRUSTIX_POLICY_SMOKE_BIN_DIR:-}"
if [[ -z "$BIN_DIR" ]]; then
  BIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi

TRUSTIXD="$BIN_DIR/trustixd"
TRUSTIXCTL="$BIN_DIR/trustixctl"
TRUSTIXCA="$BIN_DIR/trustix-ca"

for bin in "$TRUSTIXD" "$TRUSTIXCTL" "$TRUSTIXCA"; do
  [[ -x "$bin" ]] || { echo "missing executable: $bin" >&2; exit 1; }
done

WORKDIR="${TRUSTIX_POLICY_SMOKE_WORKDIR:-$(mktemp -d /tmp/trustix-policy-smoke.XXXXXX)}"
KEEP="${TRUSTIX_POLICY_SMOKE_KEEP:-0}"
PORT_BASE="${TRUSTIX_POLICY_SMOKE_PORT_BASE:-$((22000 + (RANDOM % 20000)))}"
API_A="${TRUSTIX_POLICY_SMOKE_API_A:-}"
API_B="${TRUSTIX_POLICY_SMOKE_API_B:-}"
PEER_A="${TRUSTIX_POLICY_SMOKE_PEER_A:-}"
PEER_B="${TRUSTIX_POLICY_SMOKE_PEER_B:-}"
ALLOCATED_PORTS=""

PIDS=""
LAST_DAEMON_PID=""
SUCCESS=0

log() {
  printf '[trustix-policy-smoke] %s\n' "$*" >&2
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
    printf '%s\n' "${configured##*:}"
    return 0
  fi
  port="$(python3 - "$preferred" "$ALLOCATED_PORTS" <<'PY'
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
  ALLOCATED_PORTS="${ALLOCATED_PORTS} $1"
}

allocate_ports() {
  API_A="$(choose_port TRUSTIX_POLICY_SMOKE_API_A "$PORT_BASE")"
  remember_port "$API_A"
  API_B="$(choose_port TRUSTIX_POLICY_SMOKE_API_B "$((PORT_BASE + 1))")"
  remember_port "$API_B"
  PEER_A="$(choose_port TRUSTIX_POLICY_SMOKE_PEER_A "$((PORT_BASE + 2))")"
  remember_port "$PEER_A"
  PEER_B="$(choose_port TRUSTIX_POLICY_SMOKE_PEER_B "$((PORT_BASE + 3))")"
  remember_port "$PEER_B"
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
  pids="$(ps -eo pid=,comm=,args= | awk -v wd="$WORKDIR" '$2 == "trustixd" && index($0, wd) { print $1 }')"
  [[ -n "$pids" ]] || return 0
  log "stopping orphaned trustixd processes for ${WORKDIR}: $(printf '%s\n' "$pids" | tr '\n' ' ')"
  printf '%s\n' "$pids" | while read -r pid; do
    [[ -n "$pid" ]] || continue
    stop_daemon_pid "$pid"
  done
}

cleanup() {
  local exit_code=$?
  set +e
  for pid in $PIDS; do
    stop_daemon_pid "$pid"
  done
  stop_daemons_by_workdir
  if [[ "$KEEP" != "1" && "$SUCCESS" == "1" && -z "${TRUSTIX_POLICY_SMOKE_WORKDIR:-}" ]]; then
    rm -rf "$WORKDIR"
  else
    log "workdir preserved: $WORKDIR"
  fi
  exit "$exit_code"
}
trap cleanup EXIT

need_cmd curl
need_cmd grep
need_cmd python3
need_cmd timeout
allocate_ports
log "ports: api=${API_A},${API_B} peer=${PEER_A},${PEER_B}"

mkdir -p "$WORKDIR/certs" "$WORKDIR/rotated" "$WORKDIR/a" "$WORKDIR/b"

"$TRUSTIXCA" quickstart -out "$WORKDIR/certs" -domain lab.local -ix ix-a,ix-b >/dev/null
"$TRUSTIXCA" admin issue -out "$WORKDIR/certs" -domain lab.local -admin admin-2 -ca-cert "$WORKDIR/certs/config-ca.pem" -ca-key "$WORKDIR/certs/config-ca.key" >/dev/null
"$TRUSTIXCA" root init -out "$WORKDIR/rotated" -name "TrustIX Rotated Root" >/dev/null
"$TRUSTIXCA" admin issue -out "$WORKDIR/rotated" -domain lab.local -admin rotated-admin -ca-cert "$WORKDIR/rotated/root-ca.pem" -ca-key "$WORKDIR/rotated/root-ca.key" >/dev/null

fingerprint() {
  "$TRUSTIXCA" verify -cert "$1" | awk -F= '/fingerprint_sha256=/{print $2}'
}

ADMIN1_FP="$(fingerprint "$WORKDIR/certs/admin-1.crt")"
ADMIN2_FP="$(fingerprint "$WORKDIR/certs/admin-2.crt")"
ROTATED_ADMIN_FP="$(fingerprint "$WORKDIR/rotated/rotated-admin.crt")"
ROUTE_FP="$(fingerprint "$WORKDIR/certs/ix-a-route.crt")"

cat > "$WORKDIR/a.yaml" <<EOF
domain:
  id: lab.local
  trust_roots:
    - $WORKDIR/certs/root-ca.pem
    - $WORKDIR/certs/domain-ca.pem
    - $WORKDIR/certs/config-ca.pem

ix:
  id: ix-a
  domain: lab.local
  cert: $WORKDIR/certs/ix-a.crt
  key: $WORKDIR/certs/ix-a.key
  control_api: https://127.0.0.1:$PEER_A
  route_authorizations: []

lan:
  iface: ""
  gateway: ""
  advertise: []

endpoints: []

peers:
  - id: ix-b
    domain: lab.local
    control_api: https://127.0.0.1:$PEER_B
    endpoints: []
    allowed_prefixes: []

routes: []
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

cat > "$WORKDIR/b.yaml" <<EOF
domain:
  id: lab.local
  trust_roots:
    - $WORKDIR/certs/root-ca.pem
    - $WORKDIR/certs/domain-ca.pem
    - $WORKDIR/certs/config-ca.pem

ix:
  id: ix-b
  domain: lab.local
  cert: $WORKDIR/certs/ix-b.crt
  key: $WORKDIR/certs/ix-b.key
  control_api: https://127.0.0.1:$PEER_B
  route_authorizations: []

lan:
  iface: ""
  gateway: ""
  advertise: []

endpoints: []

peers:
  - id: ix-a
    domain: lab.local
    control_api: https://127.0.0.1:$PEER_A
    endpoints: []
    allowed_prefixes: []

routes: []
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

start_daemon() {
  local ix="$1"
  local config_path="$2"
  local data_dir="$3"
  local api_port="$4"
  local peer_port="$5"
  "$TRUSTIXD" \
    -config "$config_path" \
    -data-dir "$data_dir" \
    -api "127.0.0.1:$api_port" \
    -peer-api "127.0.0.1:$peer_port" \
    -api-admin-auth \
    >"$WORKDIR/$ix.log" 2>&1 &
  LAST_DAEMON_PID="$!"
  PIDS="$PIDS $LAST_DAEMON_PID"
}

start_daemon a "$WORKDIR/a.yaml" "$WORKDIR/a" "$API_A" "$PEER_A"
PID_A="$LAST_DAEMON_PID"
start_daemon b "$WORKDIR/b.yaml" "$WORKDIR/b" "$API_B" "$PEER_B"
PID_B="$LAST_DAEMON_PID"

wait_api() {
  local port="$1"
  for _ in $(seq 1 80); do
    if curl -fsS "http://127.0.0.1:$port/v1/status" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  echo "API on port $port did not become ready" >&2
  return 1
}
wait_api "$API_A"
wait_api "$API_B"

assert_data_dir_lock_rejects_duplicate() {
  local ix="$1"
  local config_path="$2"
  local data_dir="$3"
  local api_port="$4"
  local peer_port="$5"
  local log_path="$WORKDIR/$ix-duplicate-lock.log"
  log "validating $ix data-dir lock"
  set +e
  timeout 5s "$TRUSTIXD" \
    -config "$config_path" \
    -data-dir "$data_dir" \
    -api "127.0.0.1:$api_port" \
    -peer-api "127.0.0.1:$peer_port" \
    -api-admin-auth \
    >"$log_path" 2>&1
  local rc=$?
  set -e
  if [[ "$rc" == "0" ]]; then
    die "$ix duplicate daemon unexpectedly exited successfully"
  fi
  if ! grep -q "already locked" "$log_path"; then
    sed -n '1,120p' "$log_path" >&2 || true
    die "$ix duplicate daemon did not fail on data-dir lock (exit=$rc)"
  fi
}

assert_status_runtime_lock() {
  local name="$1"
  local file="$WORKDIR/$name-status.json"
  grep -q '"data_dir_lock_held": true' "$file" || die "$name status does not report held data-dir lock"
  grep -q '"data_dir_lock_path":' "$file" || die "$name status has no data-dir lock path"
}

assert_sigterm_releases_data_dir_lock() {
  log "validating a SIGTERM cleanup and data-dir lock release"
  stop_daemon_pid_with_signal "$PID_A" TERM
  start_daemon a-sigterm-restart "$WORKDIR/a.yaml" "$WORKDIR/a" "$API_A" "$PEER_A"
  PID_A="$LAST_DAEMON_PID"
  wait_api "$API_A"
  assert_data_dir_lock_rejects_duplicate a "$WORKDIR/a.yaml" "$WORKDIR/a" "$API_A" "$PEER_A"
}

assert_data_dir_lock_rejects_duplicate a "$WORKDIR/a.yaml" "$WORKDIR/a" "$API_A" "$PEER_A"

ctl_a() {
  "$TRUSTIXCTL" -api "http://127.0.0.1:$API_A" "$@"
}

ctl_b() {
  "$TRUSTIXCTL" -api "http://127.0.0.1:$API_B" "$@"
}

cat > "$WORKDIR/policy-2.json" <<EOF
{"threshold":2,"allowed_fingerprints":["sha256:$ADMIN1_FP","sha256:$ADMIN2_FP"]}
EOF

ctl_a -admin-cert "$WORKDIR/certs/admin-1.crt" -admin-key "$WORKDIR/certs/admin-1.key" trust apply-policy "$WORKDIR/policy-2.json" >/dev/null

if ctl_a -admin-cert "$WORKDIR/certs/admin-1.crt" -admin-key "$WORKDIR/certs/admin-1.key" trust revoke "$WORKDIR/certs/ix-a-route.crt" >"$WORKDIR/single-admin-revoke.out" 2>&1; then
  echo "single-admin trust revoke unexpectedly succeeded under threshold=2" >&2
  exit 1
fi

ctl_a -admin-cert "$WORKDIR/certs/admin-1.crt" -admin-key "$WORKDIR/certs/admin-1.key" -admin-cert "$WORKDIR/certs/admin-2.crt" -admin-key "$WORKDIR/certs/admin-2.key" trust revoke "$WORKDIR/certs/ix-a-route.crt" >/dev/null
ctl_a -admin-cert "$WORKDIR/certs/admin-1.crt" -admin-key "$WORKDIR/certs/admin-1.key" -admin-cert "$WORKDIR/certs/admin-2.crt" -admin-key "$WORKDIR/certs/admin-2.key" trust roots add "$WORKDIR/rotated/root-ca.pem" >/dev/null

cat > "$WORKDIR/policy-rotated.json" <<EOF
{"threshold":1,"allowed_fingerprints":["sha256:$ROTATED_ADMIN_FP"]}
EOF

ctl_a -admin-cert "$WORKDIR/certs/admin-1.crt" -admin-key "$WORKDIR/certs/admin-1.key" -admin-cert "$WORKDIR/certs/admin-2.crt" -admin-key "$WORKDIR/certs/admin-2.key" trust apply-policy "$WORKDIR/policy-rotated.json" >/dev/null
ctl_a -admin-cert "$WORKDIR/rotated/rotated-admin.crt" -admin-key "$WORKDIR/rotated/rotated-admin.key" trust unrevoke "$ROUTE_FP" >/dev/null

ctl_b -admin-cert "$WORKDIR/rotated/rotated-admin.crt" -admin-key "$WORKDIR/rotated/rotated-admin.key" config rejoin "https://127.0.0.1:$PEER_A" ix-a >/dev/null

ctl_b trust show > "$WORKDIR/b-trust.json"
ctl_b trust roots > "$WORKDIR/b-roots.json"
ctl_b trust policy > "$WORKDIR/b-policy.json"
ctl_a status > "$WORKDIR/a-status.json"
ctl_b status > "$WORKDIR/b-status.json"

grep -q "$ROTATED_ADMIN_FP" "$WORKDIR/b-policy.json"
grep -q "domain_trust" "$WORKDIR/b-roots.json"
grep -q "trust_roots_pem" "$WORKDIR/b-trust.json"
assert_status_runtime_lock a
assert_status_runtime_lock b
assert_sigterm_releases_data_dir_lock

echo "trust policy smoke passed"
SUCCESS=1
