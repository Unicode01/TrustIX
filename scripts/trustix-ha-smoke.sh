#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ha_script="${repo_root}/scripts/trustix-ha.sh"
deploy_script="${repo_root}/scripts/trustix-deploy.sh"
workdir="$(mktemp -d /tmp/trustix-ha-smoke.XXXXXX)"
base_port="$((25000 + $$ % 10000))"

log() {
  printf '[trustix-ha-smoke] %s\n' "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

cleanup() {
  set +e
  if [[ -f "$workdir/api.pid" ]]; then
    pid="$(cat "$workdir/api.pid" 2>/dev/null || true)"
    [[ -n "$pid" ]] && kill "$pid" >/dev/null 2>&1 || true
    [[ -n "$pid" ]] && wait "$pid" >/dev/null 2>&1 || true
  fi
  rm -rf "$workdir"
}
trap cleanup EXIT

command -v go >/dev/null 2>&1 || die "go is required"
[[ "$(uname -s)" == "Linux" ]] || die "this smoke test requires Linux"
mkdir -p "$workdir/fake-bin" "$workdir/etc" "$workdir/state"

cat >"$workdir/fake-api.go" <<'EOF'
package main

import (
	"flag"
	"net"
	"net/http"
	"os"
)

func main() {
	listen := flag.String("listen", "", "")
	notReady := flag.String("not-ready", "", "")
	flag.Parse()
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		panic(err)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/readyz" {
			http.NotFound(w, r)
			return
		}
		if _, err := os.Stat(*notReady); err == nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ready","ready":true}`))
	})
	if err := http.Serve(listener, handler); err != nil {
		panic(err)
	}
}
EOF
go build -o "$workdir/fake-api" "$workdir/fake-api.go"

cat >"$workdir/fake-trustixd" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
config=""
check=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    -config) config="$2"; shift 2 ;;
    -config=*) config="${1#*=}"; shift ;;
    -check-config) check=1; shift ;;
    *) shift ;;
  esac
done
[[ "$check" == "1" ]] || exit 2
[[ -f "$config" ]] || exit 3
! grep -q '^invalid$' "$config"
EOF
chmod 0755 "$workdir/fake-trustixd"

cat >"$workdir/fake-bin/systemctl" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
root="${TRUSTIX_FAKE_HA_ROOT:?}"
action="${1:-}"
case "$action" in
  start|restart)
    [[ ! -f "$root/fail-start" ]] || exit 1
    if [[ -f "$root/api.pid" ]]; then
      pid="$(cat "$root/api.pid")"
      if kill -0 "$pid" >/dev/null 2>&1; then
        exit 0
      fi
    fi
    "$root/fake-api" -listen "${TRUSTIX_FAKE_HA_API_ADDR:?}" -not-ready "$root/not-ready" >"$root/api.log" 2>&1 &
    printf '%s\n' "$!" >"$root/api.pid"
    ;;
  stop)
    [[ ! -f "$root/fail-stop" ]] || exit 1
    if [[ -f "$root/api.pid" ]]; then
      pid="$(cat "$root/api.pid")"
      kill "$pid" >/dev/null 2>&1 || true
      for _ in {1..50}; do
        kill -0 "$pid" >/dev/null 2>&1 || break
        sleep 0.02
      done
      rm -f "$root/api.pid"
    fi
    ;;
  is-active)
    [[ -f "$root/api.pid" ]] || exit 3
    kill -0 "$(cat "$root/api.pid")" >/dev/null 2>&1
    ;;
  *) exit 2 ;;
esac
EOF
chmod 0755 "$workdir/fake-bin/systemctl"

cat >"$workdir/fake-openwrt-init" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
action="${1:-}"
case "$action" in
  start|stop)
    shift
    systemctl "$action" "trustixd@${1:-}.service"
    ;;
  running)
    shift
    systemctl is-active --quiet "trustixd@${1:-}.service"
    ;;
  *) exit 2 ;;
esac
EOF
chmod 0755 "$workdir/fake-openwrt-init"

cat >"$workdir/fence-hook" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s %s\n' "${TRUSTIX_HA_INSTANCE:?}" "${TRUSTIX_HA_TARGET_STATE:?}" >>"${TRUSTIX_FAKE_HA_ROOT:?}/fence.log"
EOF
cat >"$workdir/sync-hook" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s %s\n' "${TRUSTIX_HA_INSTANCE:?}" "${TRUSTIX_HA_TARGET_STATE:?}" >>"${TRUSTIX_FAKE_HA_ROOT:?}/sync.log"
EOF
chmod 0700 "$workdir/fence-hook" "$workdir/sync-hook"

printf 'valid\n' >"$workdir/etc/ix-test.yaml"
cat >"$workdir/etc/ix-test.env" <<EOF
TRUSTIX_BIN=$workdir/fake-trustixd
TRUSTIX_CONFIG=$workdir/etc/ix-test.yaml
TRUSTIX_DATA_DIR=$workdir/data
TRUSTIX_API_ADDR=127.0.0.1:$base_port
TRUSTIX_PEER_API_ADDR=127.0.0.1:$((base_port + 1))
TRUSTIX_DATAPLANE=noop
TRUSTIX_FAKE_HA_ROOT=$workdir
TRUSTIX_FAKE_HA_API_ADDR=127.0.0.1:$base_port
EOF
cat >"$workdir/etc/ix-test.ha.env" <<EOF
TRUSTIX_HA_SERVICE_MANAGER=systemd
TRUSTIX_HA_STATE_DIR=$workdir/state
TRUSTIX_HA_READY_URL=http://127.0.0.1:$base_port
TRUSTIX_HA_START_TIMEOUT=3
TRUSTIX_HA_STOP_TIMEOUT=2
TRUSTIX_HA_PROMOTION_GRACE=5
TRUSTIX_HA_LOCK_TIMEOUT=8
TRUSTIX_HA_REQUIRE_FENCE=1
TRUSTIX_HA_FENCE_HOOK=$workdir/fence-hook
TRUSTIX_HA_PRE_PROMOTE_HOOK=$workdir/sync-hook
TRUSTIX_HA_TEST_ALLOW_NONROOT_HOOKS=1
TRUSTIX_HA_LOGGER=0
EOF
chmod 0600 "$workdir/etc/ix-test.ha.env"

log "generic deploy cannot enable or start an HA-managed instance"
if bash "$deploy_script" \
  --service-manager systemd \
  --instance ix-test \
  --bin-dir "$workdir/missing-bin" \
  --prefix "$workdir/deploy" \
  --sysconfdir "$workdir/etc" \
  --unitdir "$workdir/systemd" \
  --state-root "$workdir/deploy-state" \
  --no-sudo \
  >"$workdir/deploy-guard.out" 2>"$workdir/deploy-guard.err"; then
  die "generic deploy started an HA-managed instance"
fi
grep -q 'managed by active-standby HA' "$workdir/deploy-guard.err" || \
  die "HA deploy rejection was not explained"
[[ ! -e "$workdir/deploy" ]] || die "HA deploy guard modified the installation"

run_ha() {
  PATH="$workdir/fake-bin:$PATH" bash "$ha_script" "$@" \
    --instance ix-test \
    --instance-env "$workdir/etc/ix-test.env" \
    --ha-env "$workdir/etc/ix-test.ha.env"
}

log "standby preflight succeeds without running trustixd"
run_ha notify --state BACKUP
run_ha check
[[ ! -f "$workdir/api.pid" ]] || die "BACKUP left trustixd running"

log "standby health rejects a rogue running daemon"
PATH="$workdir/fake-bin:$PATH" \
  TRUSTIX_FAKE_HA_ROOT="$workdir" \
  TRUSTIX_FAKE_HA_API_ADDR="127.0.0.1:$base_port" \
  systemctl start trustixd@ix-test.service
if run_ha check; then
  die "BACKUP health check accepted a running daemon"
fi
PATH="$workdir/fake-bin:$PATH" TRUSTIX_FAKE_HA_ROOT="$workdir" \
  systemctl stop trustixd@ix-test.service

log "stale notification lock is recovered"
mkdir -p "$workdir/state/ix-test.notify.lock"
printf '99999999 1\n' >"$workdir/state/ix-test.notify.lock/pid"
run_ha notify --state BACKUP
[[ ! -d "$workdir/state/ix-test.notify.lock" ]] || die "stale notification lock was not removed"

log "promotion fences, synchronizes, starts, and reaches readiness"
run_ha notify --state MASTER
run_ha check
grep -q '^MASTER ' "$workdir/state/ix-test.state" || die "promotion state is not MASTER"
grep -q '^ix-test MASTER$' "$workdir/fence.log" || die "fencing hook did not run"
grep -q '^ix-test MASTER$' "$workdir/sync.log" || die "pre-promote hook did not run"
PATH="$workdir/fake-bin:$PATH" TRUSTIX_FAKE_HA_ROOT="$workdir" systemctl is-active trustixd@ix-test.service

log "runtime readiness loss fails the keepalived health check"
touch "$workdir/not-ready"
if run_ha check; then
  die "MASTER health check accepted readiness failure"
fi
rm -f "$workdir/not-ready"
run_ha check

log "demotion stops the daemon and returns to offline preflight"
run_ha notify --state BACKUP
run_ha check
[[ ! -f "$workdir/api.pid" ]] || die "demotion left trustixd running"

log "a concurrent demotion cancels an in-flight promotion"
touch "$workdir/not-ready"
run_ha notify --state MASTER >"$workdir/promote.out" 2>"$workdir/promote.err" &
promote_pid=$!
for _ in {1..100}; do
  grep -q '^PROMOTING ' "$workdir/state/ix-test.state" 2>/dev/null && \
    [[ -f "$workdir/api.pid" ]] && break
  kill -0 "$promote_pid" >/dev/null 2>&1 || die "in-flight promotion exited before cancellation"
  sleep 0.05
done
[[ -f "$workdir/api.pid" ]] || die "in-flight promotion never started the daemon"
run_ha notify --state BACKUP
wait "$promote_pid"
rm -f "$workdir/not-ready"
grep -q '^BACKUP ' "$workdir/state/ix-test.state" || die "cancelled promotion did not settle in BACKUP"
[[ ! -f "$workdir/api.pid" ]] || die "cancelled promotion left trustixd running"

log "service start and stop failures enter FAULT"
touch "$workdir/fail-start"
if run_ha notify --state MASTER; then
  die "promotion succeeded after the service start failed"
fi
rm -f "$workdir/fail-start"
grep -q '^FAULT ' "$workdir/state/ix-test.state" || die "start failure did not enter FAULT"
[[ ! -f "$workdir/api.pid" ]] || die "start failure left trustixd running"

run_ha notify --state BACKUP
run_ha notify --state MASTER
touch "$workdir/fail-stop"
if run_ha notify --state BACKUP; then
  die "demotion succeeded after the service stop failed"
fi
grep -q '^FAULT ' "$workdir/state/ix-test.state" || die "stop failure did not enter FAULT"
[[ -f "$workdir/api.pid" ]] || die "stop failure fixture did not leave the daemon running"
rm -f "$workdir/fail-stop"
run_ha notify --state BACKUP

log "OpenWrt service adapter follows the same lifecycle"
cp "$workdir/etc/ix-test.ha.env" "$workdir/etc/openwrt.ha.env"
sed -i 's/TRUSTIX_HA_SERVICE_MANAGER=systemd/TRUSTIX_HA_SERVICE_MANAGER=openwrt/' "$workdir/etc/openwrt.ha.env"
printf 'TRUSTIX_HA_OPENWRT_INIT=%s\n' "$workdir/fake-openwrt-init" >>"$workdir/etc/openwrt.ha.env"
chmod 0600 "$workdir/etc/openwrt.ha.env"
PATH="$workdir/fake-bin:$PATH" bash "$ha_script" notify \
  --instance ix-test --state MASTER \
  --instance-env "$workdir/etc/ix-test.env" \
  --ha-env "$workdir/etc/openwrt.ha.env"
PATH="$workdir/fake-bin:$PATH" bash "$ha_script" check \
  --instance ix-test \
  --instance-env "$workdir/etc/ix-test.env" \
  --ha-env "$workdir/etc/openwrt.ha.env"
PATH="$workdir/fake-bin:$PATH" bash "$ha_script" notify \
  --instance ix-test --state BACKUP \
  --instance-env "$workdir/etc/ix-test.env" \
  --ha-env "$workdir/etc/openwrt.ha.env"
[[ ! -f "$workdir/api.pid" ]] || die "OpenWrt demotion left trustixd running"

log "required fencing and invalid config fail closed"
cp "$workdir/etc/ix-test.ha.env" "$workdir/etc/no-fence.ha.env"
sed -i '/TRUSTIX_HA_FENCE_HOOK=/d' "$workdir/etc/no-fence.ha.env"
chmod 0600 "$workdir/etc/no-fence.ha.env"
if PATH="$workdir/fake-bin:$PATH" bash "$ha_script" notify \
  --instance ix-test --state MASTER \
  --instance-env "$workdir/etc/ix-test.env" \
  --ha-env "$workdir/etc/no-fence.ha.env"; then
  die "promotion succeeded without required fencing"
fi
grep -q '^FAULT ' "$workdir/state/ix-test.state" || die "missing-fence failure did not enter FAULT"

run_ha notify --state BACKUP
printf 'invalid\n' >"$workdir/etc/ix-test.yaml"
if run_ha notify --state MASTER; then
  die "promotion succeeded with invalid config"
fi
grep -q '^FAULT ' "$workdir/state/ix-test.state" || die "invalid config did not enter FAULT"
[[ ! -f "$workdir/api.pid" ]] || die "failed promotion left trustixd running"

log "insecure HA env and failed synchronization are rejected"
printf 'valid\n' >"$workdir/etc/ix-test.yaml"
cp "$workdir/etc/ix-test.ha.env" "$workdir/etc/insecure.ha.env"
chmod 0666 "$workdir/etc/insecure.ha.env"
if PATH="$workdir/fake-bin:$PATH" bash "$ha_script" check \
  --instance ix-test \
  --instance-env "$workdir/etc/ix-test.env" \
  --ha-env "$workdir/etc/insecure.ha.env" \
  >"$workdir/insecure.out" 2>"$workdir/insecure.err"; then
  die "world-writable HA env was accepted"
fi
grep -q 'must not be group/world writable' "$workdir/insecure.err" || \
  die "insecure HA env rejection did not explain the file mode"

cat >"$workdir/fail-sync-hook" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
chmod 0700 "$workdir/fail-sync-hook"
cp "$workdir/etc/ix-test.ha.env" "$workdir/etc/fail-sync.ha.env"
sed -i "s|TRUSTIX_HA_PRE_PROMOTE_HOOK=.*|TRUSTIX_HA_PRE_PROMOTE_HOOK=$workdir/fail-sync-hook|" "$workdir/etc/fail-sync.ha.env"
chmod 0600 "$workdir/etc/fail-sync.ha.env"
if PATH="$workdir/fake-bin:$PATH" bash "$ha_script" notify \
  --instance ix-test --state MASTER \
  --instance-env "$workdir/etc/ix-test.env" \
  --ha-env "$workdir/etc/fail-sync.ha.env"; then
  die "promotion succeeded after state synchronization failed"
fi
grep -q '^FAULT ' "$workdir/state/ix-test.state" || die "sync failure did not enter FAULT"
[[ ! -f "$workdir/api.pid" ]] || die "sync failure left trustixd running"

log "all active-standby lifecycle scenarios passed"
