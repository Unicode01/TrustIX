#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="${TRUSTIX_MEMBERSHIP_SMOKE_WORKDIR:-$(mktemp -d /tmp/trustix-membership-smoke.XXXXXX)}"
KEEP="${TRUSTIX_MEMBERSHIP_SMOKE_KEEP:-0}"
BIN_DIR="${TRUSTIX_MEMBERSHIP_SMOKE_BIN_DIR:-$WORKDIR/bin}"
PORT_BASE="${TRUSTIX_MEMBERSHIP_SMOKE_PORT_BASE:-$((26000 + (RANDOM % 20000)))}"
PEER_POLL_INTERVAL="${TRUSTIX_MEMBERSHIP_SMOKE_PEER_POLL_INTERVAL:-1s}"

API_A="${TRUSTIX_MEMBERSHIP_SMOKE_API_A:-}"
API_B="${TRUSTIX_MEMBERSHIP_SMOKE_API_B:-}"
API_C="${TRUSTIX_MEMBERSHIP_SMOKE_API_C:-}"
PEER_A="${TRUSTIX_MEMBERSHIP_SMOKE_PEER_A:-}"
PEER_B="${TRUSTIX_MEMBERSHIP_SMOKE_PEER_B:-}"
PEER_C="${TRUSTIX_MEMBERSHIP_SMOKE_PEER_C:-}"
UDP_A="${TRUSTIX_MEMBERSHIP_SMOKE_UDP_A:-}"
UDP_B="${TRUSTIX_MEMBERSHIP_SMOKE_UDP_B:-}"
UDP_C="${TRUSTIX_MEMBERSHIP_SMOKE_UDP_C:-}"
ALLOCATED_PORTS=""

TRUSTIXD="$BIN_DIR/trustixd"
TRUSTIXCTL="$BIN_DIR/trustixctl"
TRUSTIXCA="$BIN_DIR/trustix-ca"
PIDS=""
LAST_DAEMON_PID=""
SUCCESS=0

log() {
  printf '[trustix-membership-smoke] %s\n' "$*" >&2
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
  API_A="$(choose_port TRUSTIX_MEMBERSHIP_SMOKE_API_A "$PORT_BASE")"
  remember_port "$API_A"
  API_B="$(choose_port TRUSTIX_MEMBERSHIP_SMOKE_API_B "$((PORT_BASE + 1))")"
  remember_port "$API_B"
  API_C="$(choose_port TRUSTIX_MEMBERSHIP_SMOKE_API_C "$((PORT_BASE + 2))")"
  remember_port "$API_C"
  PEER_A="$(choose_port TRUSTIX_MEMBERSHIP_SMOKE_PEER_A "$((PORT_BASE + 3))")"
  remember_port "$PEER_A"
  PEER_B="$(choose_port TRUSTIX_MEMBERSHIP_SMOKE_PEER_B "$((PORT_BASE + 4))")"
  remember_port "$PEER_B"
  PEER_C="$(choose_port TRUSTIX_MEMBERSHIP_SMOKE_PEER_C "$((PORT_BASE + 5))")"
  remember_port "$PEER_C"
  UDP_A="$(choose_port TRUSTIX_MEMBERSHIP_SMOKE_UDP_A "$((PORT_BASE + 6))")"
  remember_port "$UDP_A"
  UDP_B="$(choose_port TRUSTIX_MEMBERSHIP_SMOKE_UDP_B "$((PORT_BASE + 7))")"
  remember_port "$UDP_B"
  UDP_C="$(choose_port TRUSTIX_MEMBERSHIP_SMOKE_UDP_C "$((PORT_BASE + 8))")"
  remember_port "$UDP_C"
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
  if [[ "$KEEP" != "1" && "$SUCCESS" == "1" && -z "${TRUSTIX_MEMBERSHIP_SMOKE_WORKDIR:-}" ]]; then
    rm -rf "$WORKDIR"
  else
    log "workdir preserved: $WORKDIR"
  fi
  exit "$exit_code"
}
trap cleanup EXIT

build_or_check_binaries() {
  if [[ -n "${TRUSTIX_MEMBERSHIP_SMOKE_BIN_DIR:-}" ]]; then
    [[ -x "$TRUSTIXD" ]] || die "missing executable: $TRUSTIXD"
    [[ -x "$TRUSTIXCTL" ]] || die "missing executable: $TRUSTIXCTL"
    [[ -x "$TRUSTIXCA" ]] || die "missing executable: $TRUSTIXCA"
    return 0
  fi
  need_cmd go
  mkdir -p "$BIN_DIR"
  log "building trustix binaries"
  (cd "$REPO_ROOT" && go build -o "$TRUSTIXD" ./cmd/trustixd)
  (cd "$REPO_ROOT" && go build -o "$TRUSTIXCTL" ./cmd/trustixctl)
  (cd "$REPO_ROOT" && go build -o "$TRUSTIXCA" ./cmd/trustix-ca)
}

generate_certs() {
  mkdir -p "$WORKDIR/certs"
  log "generating three IX certificates"
  "$TRUSTIXCA" quickstart -out "$WORKDIR/certs" -domain lab.local -ix ix-a,ix-b,ix-c >/dev/null
  "$TRUSTIXCA" route authorize \
    -out "$WORKDIR/certs" \
    -domain lab.local \
    -ix ix-c \
    -prefix 10.0.2.0/24 \
    -ca-cert "$WORKDIR/certs/config-ca.pem" \
    -ca-key "$WORKDIR/certs/config-ca.key" >/dev/null
}

generate_config() {
  local ix="$1"
  local api_port="$2"
  local peer_port="$3"
  local udp_port="$4"
  local prefix="$5"
  local gateway="$6"
  local bootstrap="$7"
  local import_prefixes="$8"
  local export_prefixes="$9"
  local output="${10}"

  local bootstrap_yaml=""
  if [[ -n "$bootstrap" ]]; then
    bootstrap_yaml=$(cat <<EOF
bootstrap:
  peers:
    - control_api: https://127.0.0.1:${bootstrap}
EOF
)
  else
    bootstrap_yaml="bootstrap: {}"
  fi

  cat >"$output" <<EOF
domain:
  id: lab.local
  trust_roots:
    - $WORKDIR/certs/root-ca.pem
    - $WORKDIR/certs/domain-ca.pem
    - $WORKDIR/certs/config-ca.pem

ix:
  id: $ix
  domain: lab.local
  cert: $WORKDIR/certs/$ix.crt
  key: $WORKDIR/certs/$ix.key
  control_api: https://127.0.0.1:$peer_port
  route_authorizations:
    - $WORKDIR/certs/$ix-route.crt

lan:
  iface: br-lan-$ix
  gateway: $gateway
  advertise:
    - $prefix
  mode: routed
  manage_address: false
  manage_forwarding: false
  manage_rp_filter: false

endpoints:
  - name: $ix-udp
    mode: passive
    listen: 127.0.0.1:$udp_port
    address: 127.0.0.1:$udp_port
    transport: udp
    enabled: true

peers: []

routes: []

route_policy:
  import_prefixes:$import_prefixes
  export_prefixes:$export_prefixes
  dynamic_metric: 900

policies:
  - name: default-routed
    route_selection: longest_prefix
    flow_stickiness: true
    rewrite: preserve_source

transport_policy:
  mode: user_defined
  profile: stable
  datapath: userspace
  candidates:
    - $ix-udp
  failover: health_based
  encryption: secure
  crypto_key_source: auto
  crypto_placement: userspace
  kernel_transport:
    mode: disabled

$bootstrap_yaml
EOF
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

write_all_configs() {
  local a_import="$1"
  local c_export="$2"
  generate_config ix-a "$API_A" "$PEER_A" "$UDP_A" 10.0.0.0/24 10.0.0.1/24 "$PEER_B" "$(prefix_list_yaml "$a_import")" "$(prefix_list_yaml "")" "$WORKDIR/a.yaml"
  generate_config ix-b "$API_B" "$PEER_B" "$UDP_B" 10.0.1.0/24 10.0.1.1/24 "$PEER_A" "$(prefix_list_yaml "")" "$(prefix_list_yaml "")" "$WORKDIR/b.yaml"
  generate_config ix-c "$API_C" "$PEER_C" "$UDP_C" 10.0.2.0/24 10.0.2.1/24 "$PEER_B" "$(prefix_list_yaml "")" "$(prefix_list_yaml "$c_export")" "$WORKDIR/c.yaml"
}

start_daemon() {
  local ix="$1"
  local api_port="$2"
  local peer_port="$3"
  local config_path="$4"
  local data_dir="$WORKDIR/state-$ix"
  mkdir -p "$data_dir"
  TRUSTIX_PEER_POLL_INTERVAL="$PEER_POLL_INTERVAL" "$TRUSTIXD" \
    -config "$config_path" \
    -data-dir "$data_dir" \
    -api "127.0.0.1:$api_port" \
    -peer-api "127.0.0.1:$peer_port" \
    -dataplane noop \
    >"$WORKDIR/$ix.log" 2>&1 &
  LAST_DAEMON_PID="$!"
  PIDS="$PIDS $LAST_DAEMON_PID"
}

wait_api() {
  local ix="$1"
  local port="$2"
  for _ in $(seq 1 80); do
    if curl -fsS "http://127.0.0.1:$port/v1/status" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  sed -n '1,200p' "$WORKDIR/$ix.log" >&2 || true
  die "$ix API did not become ready"
}

ctl() {
  local port="$1"
  shift
  "$TRUSTIXCTL" -api "http://127.0.0.1:$port" "$@"
}

admin_ctl() {
  local port="$1"
  shift
  "$TRUSTIXCTL" \
    -api "http://127.0.0.1:$port" \
    -admin-cert "$WORKDIR/certs/admin-1.crt" \
    -admin-key "$WORKDIR/certs/admin-1.key" \
    "$@"
}

collect() {
  local name="$1"
  local port="$2"
  ctl "$port" status >"$WORKDIR/$name-status.json"
  ctl "$port" doctor >"$WORKDIR/$name-doctor.json"
  ctl "$port" members >"$WORKDIR/$name-members.json"
  ctl "$port" routes >"$WORKDIR/$name-routes.json"
  ctl "$port" route-policy >"$WORKDIR/$name-route-policy.json"
  ctl "$port" peers >"$WORKDIR/$name-peers.json"
}

assert_data_dir_lock_rejects_duplicate() {
  local ix="$1"
  local api_port="$2"
  local peer_port="$3"
  local config_path="$4"
  local data_dir="$WORKDIR/state-$ix"
  local log_path="$WORKDIR/$ix-duplicate-lock.log"
  log "validating $ix data-dir lock"
  set +e
  timeout 5s "$TRUSTIXD" \
    -config "$config_path" \
    -data-dir "$data_dir" \
    -api "127.0.0.1:$api_port" \
    -peer-api "127.0.0.1:$peer_port" \
    -dataplane noop \
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

assert_state_files_status() {
  local name="$1"
  local port="$2"
  local status_file="$WORKDIR/$name-status.json"
  local doctor_file="$WORKDIR/$name-doctor.json"
  ctl "$port" config verify >"$WORKDIR/$name-config-verify.json"
  grep -q '"state_files":' "$status_file" || die "$name status does not report state_files"
  grep -q '"name": "members"' "$status_file" || die "$name status has no members state file block"
  grep -q '"name": "pending_members"' "$status_file" || die "$name status has no pending_members state file block"
  grep -q '"name": "config_log"' "$status_file" || die "$name status has no config_log state file block"
  grep -q '"name": "state_files"' "$doctor_file" || die "$name doctor has no state_files check"
  grep -q '"valid": true' "$WORKDIR/$name-config-verify.json" || die "$name config verify did not report valid log"
}

assert_sigterm_releases_data_dir_lock() {
  local ix="$1"
  local api_port="$2"
  local peer_port="$3"
  local config_path="$4"
  local pid="$5"
  log "validating $ix SIGTERM cleanup and data-dir lock release"
  stop_daemon_pid_with_signal "$pid" TERM
  start_daemon "$ix" "$api_port" "$peer_port" "$config_path"
  wait_api "$ix" "$api_port"
  assert_data_dir_lock_rejects_duplicate "$ix" "$api_port" "$peer_port" "$config_path"
}

wait_grep() {
  local label="$1"
  local command="$2"
  local pattern="$3"
  local output="$4"
  for _ in $(seq 1 80); do
    eval "$command" >"$output" 2>"$output.err" || true
    if grep -q "$pattern" "$output"; then
      return 0
    fi
    sleep 0.25
  done
  cat "$output" >&2 || true
  cat "$output.err" >&2 || true
  die "timed out waiting for $label"
}

assert_not_grep() {
  local pattern="$1"
  local file="$2"
  if grep -q "$pattern" "$file"; then
    cat "$file" >&2
    die "unexpected pattern $pattern in $file"
  fi
}

wait_not_grep() {
  local label="$1"
  local command="$2"
  local pattern="$3"
  local output="$4"
  for _ in $(seq 1 80); do
    if eval "$command" >"$output" 2>"$output.err" && ! grep -q "$pattern" "$output"; then
      return 0
    fi
    sleep 0.25
  done
  cat "$output" >&2 || true
  cat "$output.err" >&2 || true
  die "timed out waiting for $label"
}

main() {
  need_cmd curl
  need_cmd grep
  need_cmd python3
  need_cmd timeout
  allocate_ports
  mkdir -p "$WORKDIR"
  log "workdir: $WORKDIR"
  log "ports: api=${API_A},${API_B},${API_C} peer=${PEER_A},${PEER_B},${PEER_C} udp=${UDP_A},${UDP_B},${UDP_C}"
  build_or_check_binaries
  generate_certs

  write_all_configs "10.0.1.0/24" "10.99.0.0/16"
  start_daemon ix-a "$API_A" "$PEER_A" "$WORKDIR/a.yaml"
  PID_A="$LAST_DAEMON_PID"
  start_daemon ix-b "$API_B" "$PEER_B" "$WORKDIR/b.yaml"
  PID_B="$LAST_DAEMON_PID"
  wait_api ix-a "$API_A"
  wait_api ix-b "$API_B"
  assert_data_dir_lock_rejects_duplicate ix-a "$API_A" "$PEER_A" "$WORKDIR/a.yaml"

  log "waiting for ix-a to observe ix-b as pending through bootstrap"
  wait_grep "ix-a pending ix-b admission" "ctl $API_A admissions pending" '"ix_id": "ix-b"' "$WORKDIR/a-pending-ix-b.json"
  ctl "$API_A" routes >"$WORKDIR/a-routes-before-b-approve.json"
  assert_not_grep '"prefix": "10.0.1.0/24"' "$WORKDIR/a-routes-before-b-approve.json"

  log "enabling chain admission by approving observed ix-b on ix-a"
  admin_ctl "$API_A" admissions approve-pending ix-b -prefix 10.0.1.0/24 >/dev/null
  wait_grep "ix-a route to ix-b after admission" "ctl $API_A routes" '"prefix": "10.0.1.0/24"' "$WORKDIR/a-routes-initial.json"
  admin_ctl "$API_B" config rejoin "https://127.0.0.1:$PEER_A" ix-a >/dev/null
  wait_grep "ix-b synced chain admission mode" "ctl $API_B admissions" '"ix_id": "ix-b"' "$WORKDIR/b-admissions-after-b-approve.json"

  log "starting unapproved ix-c and waiting for pending admission"
  start_daemon ix-c "$API_C" "$PEER_C" "$WORKDIR/c.yaml"
  PID_C="$LAST_DAEMON_PID"
  wait_api ix-c "$API_C"
  wait_grep "ix-b pending ix-c admission" "ctl $API_B admissions pending" '"ix_id": "ix-c"' "$WORKDIR/b-pending-ix-c.json"
  ctl "$API_B" routes >"$WORKDIR/b-routes-pending-c.json"
  assert_not_grep '"prefix": "10.0.2.0/24"' "$WORKDIR/b-routes-pending-c.json"

  log "restarting ix-b and validating pending admission persistence"
  stop_daemon_pid "$PID_B"
  start_daemon ix-b "$API_B" "$PEER_B" "$WORKDIR/b.yaml"
  PID_B="$LAST_DAEMON_PID"
  wait_api ix-b "$API_B"
  wait_grep "ix-b restored pending ix-c admission after restart" "ctl $API_B admissions pending" '"ix_id": "ix-c"' "$WORKDIR/b-pending-ix-c-after-restart.json"
  grep -q '"expires_at":' "$WORKDIR/b-pending-ix-c-after-restart.json" || die "ix-b pending admission does not expose expires_at after restart"
  grep -q '"ttl_seconds":' "$WORKDIR/b-pending-ix-c-after-restart.json" || die "ix-b pending admission does not expose ttl_seconds after restart"

  log "approving pending ix-c from observed advertisement"
  admin_ctl "$API_B" admissions approve-pending ix-c -prefix 10.0.2.0/24 >/dev/null
  wait_grep "ix-b admitted ix-c member" "ctl $API_B members" '"ix_id": "ix-c"' "$WORKDIR/b-members-after-c-approve.json"
  admin_ctl "$API_A" config rejoin "https://127.0.0.1:$PEER_B" ix-b >/dev/null
  wait_grep "ix-a member ix-c through ix-b gossip" "ctl $API_A members" '"ix_id": "ix-c"' "$WORKDIR/a-members-initial.json"
  assert_not_grep '"prefix": "10.0.2.0/24"' "$WORKDIR/a-routes-initial.json"

  ctl "$API_C" route-policy >"$WORKDIR/c-route-policy-initial.json"
  grep -q '"reason": "export_prefix_denied"' "$WORKDIR/c-route-policy-initial.json" || die "ix-c did not record export_prefix_denied"
  ctl "$API_B" routes >"$WORKDIR/b-routes-initial.json"
  assert_not_grep '"prefix": "10.0.2.0/24"' "$WORKDIR/b-routes-initial.json"

  log "allowing ix-c export and waiting for ix-b to import it"
  write_all_configs "10.0.1.0/24" "10.0.2.0/24"
  ctl "$API_C" config apply "$WORKDIR/c.yaml" >/dev/null
  wait_grep "ix-b route to ix-c after export policy update" "ctl $API_B routes" '"prefix": "10.0.2.0/24"' "$WORKDIR/b-routes-after-c-export.json"
  wait_grep "ix-a import policy rejects ix-c" "ctl $API_A route-policy" '"reason": "import_prefix_denied"' "$WORKDIR/a-route-policy-after-c-export.json"
  ctl "$API_A" routes >"$WORKDIR/a-routes-after-c-export.json"
  assert_not_grep '"prefix": "10.0.2.0/24"' "$WORKDIR/a-routes-after-c-export.json"

  log "allowing ix-a import and waiting for ix-c route through ix-b gossip"
  write_all_configs "10.0.0.0/8" "10.0.2.0/24"
  ctl "$API_A" config apply "$WORKDIR/a.yaml" >/dev/null
  wait_grep "ix-a route to ix-c after import policy update" "ctl $API_A routes" '"prefix": "10.0.2.0/24"' "$WORKDIR/a-routes-after-import.json"
  ctl "$API_A" route-policy >"$WORKDIR/a-route-policy-after-import.json"
  grep -q '"reason": "import_prefix_match"' "$WORKDIR/a-route-policy-after-import.json" || die "ix-a did not record import_prefix_match"
  grep -q '"metric": 900' "$WORKDIR/a-routes-after-import.json" || die "dynamic metric was not applied"

  log "revoking ix-c admission and waiting for dynamic routes to be pruned"
  admin_ctl "$API_A" admissions revoke ix-c >/dev/null
  wait_not_grep "ix-b member ix-c removed after revoke" "ctl $API_B members" '"ix_id": "ix-c"' "$WORKDIR/b-members-after-c-revoke.json"
  wait_not_grep "ix-a route to ix-c removed after revoke sync" "ctl $API_A routes" '"prefix": "10.0.2.0/24"' "$WORKDIR/a-routes-after-c-revoke.json"

  collect ix-a "$API_A"
  collect ix-b "$API_B"
  collect ix-c "$API_C"
  assert_status_runtime_lock ix-a
  assert_status_runtime_lock ix-b
  assert_status_runtime_lock ix-c
  assert_state_files_status ix-a "$API_A"
  assert_state_files_status ix-b "$API_B"
  assert_state_files_status ix-c "$API_C"
  assert_sigterm_releases_data_dir_lock ix-a "$API_A" "$PEER_A" "$WORKDIR/a.yaml" "$PID_A"
  log "ok: three IX membership gossip, route import/export policy, and dynamic metric are active"
  SUCCESS=1
}

main "$@"
