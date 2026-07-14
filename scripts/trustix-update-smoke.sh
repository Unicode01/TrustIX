#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
update_script="${script_dir}/trustix-update.sh"
workdir="$(mktemp -d /tmp/trustix-update-smoke.XXXXXX)"
base_port="$((22000 + $$ % 10000))"
scenario_roots=()
scenario_root=""

log() {
  printf '[trustix-update-smoke] %s\n' "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

cleanup() {
  local root pid_file pid
  set +e
  for root in "${scenario_roots[@]}"; do
    for pid_file in "${root}"/run/*.pid; do
      [[ -f "$pid_file" ]] || continue
      pid="$(cat "$pid_file" 2>/dev/null || true)"
      [[ -n "$pid" ]] && kill "$pid" >/dev/null 2>&1 || true
    done
  done
  rm -rf "$workdir"
}
trap cleanup EXIT

command -v go >/dev/null 2>&1 || die "go is required"
command -v tar >/dev/null 2>&1 || die "tar is required"
[[ "$(uname -s)" == "Linux" ]] || die "this smoke test requires Linux"

cat >"${workdir}/fake-trustixd.go" <<'EOF'
package main

import (
	"bytes"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

var version = "dev"

func main() {
	configPath := flag.String("config", "", "")
	_ = flag.String("data-dir", "", "")
	apiAddr := flag.String("api", "127.0.0.1:8787", "")
	_ = flag.String("peer-api", "", "")
	_ = flag.String("dataplane", "auto", "")
	_ = flag.Bool("api-admin-auth", false, "")
	showVersion := flag.Bool("version", false, "")
	checkConfig := flag.Bool("check-config", false, "")
	cleanupDataplane := flag.Bool("cleanup-dataplane", false, "")
	_ = flag.Bool("cleanup-dataplane-dry-run", false, "")
	_ = flag.Bool("repair-dataplane", false, "")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	if *checkConfig {
		payload, err := os.ReadFile(*configPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		for _, legacy := range [][]byte{[]byte("experimental_tcp"), []byte("experimental-tcp"), []byte("ackless_tcp")} {
			if bytes.Contains(payload, legacy) {
				fmt.Fprintf(os.Stderr, "unsupported legacy transport %q\n", legacy)
				os.Exit(1)
			}
		}
		fmt.Printf("config valid: %s\n", *configPath)
		return
	}
	if *cleanupDataplane {
		return
	}
	if version == "new" && os.Getenv("TRUSTIX_FAKE_FAIL_NEW") == "1" {
		fmt.Fprintln(os.Stderr, "injected new-version startup failure")
		os.Exit(42)
	}
	listener, err := net.Listen("tcp", *apiAddr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer listener.Close()
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if version == "old" && os.Getenv("TRUSTIX_FAKE_OLD_LEGACY") == "1" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Path != "/readyz" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if version == "new" && os.Getenv("TRUSTIX_FAKE_NOT_READY_NEW") == "1" {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"not_ready","ready":false}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"ready","ready":true}`))
	})}
	defer server.Close()
	go func() {
		_ = server.Serve(listener)
	}()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	<-signals
}
EOF

go build -o "${workdir}/trustixd-old" -ldflags '-X main.version=old' "${workdir}/fake-trustixd.go"
go build -o "${workdir}/trustixd-new" -ldflags '-X main.version=new' "${workdir}/fake-trustixd.go"

write_fake_init() {
  local path="$1"
  local root="$2"
  local marker="$3"
  cat >"$path" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
# FIXTURE_VERSION=__MARKER__
root="__ROOT__"
sysconf="${root}/etc/trustix"
run_dir="${root}/run"

load_instance() {
  local instance="$1"
  TRUSTIX_BIN="${root}/bin/trustixd"
  TRUSTIX_CONFIG="${sysconf}/${instance}.yaml"
  TRUSTIX_DATA_DIR="${root}/state/${instance}"
  TRUSTIX_API_ADDR="127.0.0.1:8787"
  TRUSTIX_PEER_API_ADDR="127.0.0.1:9443"
  TRUSTIX_DATAPLANE="noop"
  TRUSTIX_EXTRA_ARGS=""
  set -a
  # shellcheck disable=SC1090
  . "${sysconf}/${instance}.env"
  set +a
}

stop_one() {
  local instance="$1"
  local pid_file="${run_dir}/${instance}.pid"
  local pid=""
  if [[ -f "$pid_file" ]]; then
    pid="$(cat "$pid_file")"
    kill "$pid" >/dev/null 2>&1 || true
    for _ in {1..50}; do
      kill -0 "$pid" >/dev/null 2>&1 || break
      sleep 0.02
    done
    rm -f "$pid_file"
  fi
}

start_one() {
  local instance="$1"
  local -a extra=()
  load_instance "$instance"
  [[ -n "$TRUSTIX_EXTRA_ARGS" ]] && read -r -a extra <<<"$TRUSTIX_EXTRA_ARGS"
  mkdir -p "$run_dir" "$TRUSTIX_DATA_DIR"
  "$TRUSTIX_BIN" \
    -config "$TRUSTIX_CONFIG" \
    -data-dir "$TRUSTIX_DATA_DIR" \
    -api "$TRUSTIX_API_ADDR" \
    -peer-api "$TRUSTIX_PEER_API_ADDR" \
    -dataplane "$TRUSTIX_DATAPLANE" \
    "${extra[@]}" \
    >"${run_dir}/${instance}.log" 2>&1 &
  local pid=$!
  printf '%s\n' "$pid" >"${run_dir}/${instance}.pid"
  sleep 0.2
  kill -0 "$pid" >/dev/null 2>&1 || {
    wait "$pid" || true
    return 1
  }
}

instance="${2:-ix-test}"
case "${1:-}" in
  start) start_one "$instance" ;;
  stop) stop_one "$instance" ;;
  restart) stop_one "$instance"; start_one "$instance" ;;
  status)
    pid_file="${run_dir}/${instance}.pid"
    [[ -f "$pid_file" ]] && kill -0 "$(cat "$pid_file")"
    ;;
  enable) ;;
  *) exit 2 ;;
esac
EOF
  sed -i "s|__ROOT__|${root}|g; s|__MARKER__|${marker}|g" "$path"
  chmod 0755 "$path"
}

write_fake_systemctl() {
  local path="$1"
  cat >"$path" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
root="${TRUSTIX_FAKE_ROOT:?}"
while [[ "${1:-}" == --no-pager || "${1:-}" == --full || "${1:-}" == --plain ]]; do shift; done
command_name="${1:-}"
shift || true

instance_from_unit() {
  local unit="$1"
  unit="${unit#trustixd@}"
  printf '%s\n' "${unit%.service}"
}

active_state() {
  local instance="$1"
  local pid_file="${root}/run/${instance}.pid"
  [[ -f "$pid_file" ]] && kill -0 "$(cat "$pid_file")" >/dev/null 2>&1
}

case "$command_name" in
  list-units|list-unit-files)
    printf 'trustixd@ix-test.service enabled\n'
    ;;
  daemon-reload) ;;
  restart)
    instance="$(instance_from_unit "${1:?}")"
    "${root}/etc/init.d/trustix" restart "$instance"
    ;;
  stop)
    instance="$(instance_from_unit "${1:?}")"
    "${root}/etc/init.d/trustix" stop "$instance"
    ;;
  is-active)
    instance="$(instance_from_unit "${1:?}")"
    if active_state "$instance"; then printf 'active\n'; else printf 'failed\n'; exit 3; fi
    ;;
  show)
    unit="${1:?}"
    shift
    instance="$(instance_from_unit "$unit")"
    property=""
    value_only=0
    for arg in "$@"; do
      case "$arg" in
        --property=*) property="${arg#*=}" ;;
        --value) value_only=1 ;;
      esac
    done
    if active_state "$instance"; then state=active; result=success; status=0; else state=failed; result=exit-code; status=42; fi
    case "$property" in
      Result) printf '%s\n' "$result" ;;
      ExecMainStatus) printf '%s\n' "$status" ;;
      NRestarts) printf '0\n' ;;
      *) printf 'ActiveState=%s\nSubState=%s\nResult=%s\nExecMainCode=exited\nExecMainStatus=%s\nNRestarts=0\n' "$state" "$state" "$result" "$status" ;;
    esac
    ;;
  status)
    unit="${1:?}"
    instance="$(instance_from_unit "$unit")"
    "${root}/etc/init.d/trustix" status "$instance"
    ;;
  *)
    printf 'unsupported fake systemctl command: %s\n' "$command_name" >&2
    exit 2
    ;;
esac
EOF
  chmod 0755 "$path"
}

create_package() {
  local root="$1"
  local manager="$2"
  local package="${root}/package"
  mkdir -p "${package}/bin" "${package}/packaging/${manager}"
  cp "${workdir}/trustixd-new" "${package}/bin/trustixd"
  cp "${workdir}/trustixd-new" "${package}/bin/trustixctl"
  cp "${workdir}/trustixd-new" "${package}/bin/trustix-ca"
  if [[ "$manager" == "systemd" ]]; then
    printf '# FIXTURE_VERSION=new\n' >"${package}/packaging/systemd/trustixd@.service"
  else
    write_fake_init "${package}/packaging/openwrt/trustix.init" "$root" new
  fi
  tar -C "$package" -czf "${root}/package.tar.gz" .
}

setup_scenario() {
  local name="$1"
  local manager="$2"
  local config_transport="$3"
  local fail_new="$4"
  local port="$5"
  local not_ready_new="${6:-0}"
  local old_legacy="${7:-0}"
  local root="${workdir}/${name}"
  scenario_roots+=("$root")
  mkdir -p "${root}/bin" "${root}/etc/trustix" "${root}/etc/init.d" "${root}/etc/systemd" "${root}/fake-bin" "${root}/run" "${root}/state"
  cp "${workdir}/trustixd-old" "${root}/bin/trustixd"
  chmod 0755 "${root}/bin/trustixd"
  write_fake_init "${root}/etc/init.d/trustix" "$root" old
  printf '# FIXTURE_VERSION=old\n' >"${root}/etc/systemd/trustixd@.service"
  cat >"${root}/etc/trustix/ix-test.yaml" <<EOF
domain:
  id: lab.local
ix:
  id: ix-test
endpoints:
  - name: endpoint
    transport: ${config_transport}
    listen: 127.0.0.1:17001
EOF
  cat >"${root}/etc/trustix/ix-test.env" <<EOF
TRUSTIX_BIN=${root}/bin/trustixd
TRUSTIX_CONFIG=${root}/etc/trustix/ix-test.yaml
TRUSTIX_DATA_DIR=${root}/state/ix-test
TRUSTIX_API_ADDR=127.0.0.1:${port}
TRUSTIX_PEER_API_ADDR=127.0.0.1:$((port + 1000))
TRUSTIX_DATAPLANE=noop
TRUSTIX_EXTRA_ARGS=
TRUSTIX_FAKE_FAIL_NEW=${fail_new}
TRUSTIX_FAKE_NOT_READY_NEW=${not_ready_new}
TRUSTIX_FAKE_OLD_LEGACY=${old_legacy}
EOF
  write_fake_systemctl "${root}/fake-bin/systemctl"
  printf '#!/usr/bin/env bash\nexit 0\n' >"${root}/fake-bin/journalctl"
  chmod 0755 "${root}/fake-bin/journalctl"
  create_package "$root" "$manager"
  "${root}/etc/init.d/trustix" start ix-test
  scenario_root="$root"
}

run_update() {
  local root="$1"
  local manager="$2"
  shift 2
  PATH="${root}/fake-bin:${PATH}" \
    TRUSTIX_FAKE_ROOT="$root" \
    bash "$update_script" \
      --tarball "${root}/package.tar.gz" \
      --service-manager "$manager" \
      --bindir "${root}/bin" \
      --unitdir "${root}/etc/systemd" \
      --initdir "${root}/etc/init.d" \
      --sysconfdir "${root}/etc/trustix" \
      --docdir "${root}/docs" \
      --backup-dir "${root}/backup" \
      --work-dir "${root}/update-work" \
      --no-sudo \
      "$@"
}

assert_version() {
  local root="$1"
  local want="$2"
  local got
  got="$("${root}/bin/trustixd" -version)"
  [[ "$got" == "$want" ]] || die "${root} version=${got}, want ${want}"
}

assert_running() {
  local root="$1"
  "${root}/etc/init.d/trustix" status ix-test || die "${root} instance is not running"
}

log "systemd preflight rejection leaves the running installation untouched"
setup_scenario systemd-preflight systemd experimental_tcp 0 "$base_port"
root="$scenario_root"
pid_before="$(cat "${root}/run/ix-test.pid")"
if run_update "$root" systemd >"${root}/update.out" 2>"${root}/update.err"; then
  die "legacy systemd config unexpectedly passed preflight"
fi
assert_version "$root" old
assert_running "$root"
[[ "$(cat "${root}/run/ix-test.pid")" == "$pid_before" ]] || die "preflight rejection restarted the old service"
[[ ! -e "${root}/bin/trustixctl" ]] || die "preflight rejection installed a new binary"
grep -q 'installation was not modified' "${root}/update.err" || die "preflight rejection did not explain the unchanged installation"
"${root}/etc/init.d/trustix" stop ix-test

log "systemd startup failure restores binaries, unit, and old service"
setup_scenario systemd-rollback systemd tix_tcp 1 "$((base_port + 1))"
root="$scenario_root"
if run_update "$root" systemd >"${root}/update.out" 2>"${root}/update.err"; then
  die "injected systemd startup failure unexpectedly succeeded"
fi
assert_version "$root" old
assert_running "$root"
grep -q 'FIXTURE_VERSION=old' "${root}/etc/systemd/trustixd@.service" || die "systemd unit was not rolled back"
[[ ! -e "${root}/bin/trustixctl" ]] || die "new systemd binary was not removed during rollback"
grep -q 'rollback complete' "${root}/update.err" || die "systemd rollback did not complete"
"${root}/etc/init.d/trustix" stop ix-test

log "operational flags in extra args cannot bypass candidate preflight"
setup_scenario systemd-extra-args systemd tix_tcp 0 "$((base_port + 2))"
root="$scenario_root"
printf 'TRUSTIX_EXTRA_ARGS=-check-config=false\n' >>"${root}/etc/trustix/ix-test.env"
pid_before="$(cat "${root}/run/ix-test.pid")"
if run_update "$root" systemd >"${root}/update.out" 2>"${root}/update.err"; then
  die "operational flag in extra args unexpectedly bypassed preflight"
fi
assert_version "$root" old
assert_running "$root"
[[ "$(cat "${root}/run/ix-test.pid")" == "$pid_before" ]] || die "rejected extra args restarted the old service"
grep -q 'operational flag -check-config=false is not valid' "${root}/update.err" || die "extra-args rejection was not reported"
"${root}/etc/init.d/trustix" stop ix-test

log "OpenWrt successful update commits the candidate"
setup_scenario openwrt-success openwrt tix_tcp 0 "$((base_port + 3))"
root="$scenario_root"
run_update "$root" openwrt --json >"${root}/update.out" 2>"${root}/update.err"
assert_version "$root" new
assert_running "$root"
grep -q 'FIXTURE_VERSION=new' "${root}/etc/init.d/trustix" || die "OpenWrt init script was not updated"
grep -q '"restarted":\["trustix:ix-test"\]' "${root}/update.out" || die "OpenWrt JSON summary is missing restarted instance"
"${root}/etc/init.d/trustix" stop ix-test

log "OpenWrt startup failure rolls back even with persistent backups disabled"
setup_scenario openwrt-rollback openwrt tix_tcp 1 "$((base_port + 4))"
root="$scenario_root"
if run_update "$root" openwrt --no-backup >"${root}/update.out" 2>"${root}/update.err"; then
  die "injected OpenWrt startup failure unexpectedly succeeded"
fi
assert_version "$root" old
assert_running "$root"
grep -q 'FIXTURE_VERSION=old' "${root}/etc/init.d/trustix" || die "OpenWrt init script was not rolled back"
[[ ! -e "${root}/bin/trustixctl" ]] || die "new OpenWrt binary was not removed during rollback"
[[ ! -e "${root}/backup" ]] || die "--no-backup unexpectedly kept a persistent backup"
grep -q 'rollback complete' "${root}/update.err" || die "OpenWrt rollback did not complete"
"${root}/etc/init.d/trustix" stop ix-test

log "semantic readiness failure rolls back to a legacy daemon without /readyz"
setup_scenario systemd-not-ready systemd tix_tcp 0 "$((base_port + 5))" 1 1
root="$scenario_root"
if run_update "$root" systemd >"${root}/update.out" 2>"${root}/update.err"; then
  die "not-ready systemd candidate unexpectedly succeeded"
fi
assert_version "$root" old
assert_running "$root"
grep -q 'FIXTURE_VERSION=old' "${root}/etc/systemd/trustixd@.service" || die "legacy systemd unit was not rolled back"
[[ ! -e "${root}/bin/trustixctl" ]] || die "not-ready candidate binary was not removed during rollback"
grep -q 'readiness is not healthy' "${root}/update.err" || die "candidate readiness failure was not reported"
grep -q 'rollback complete' "${root}/update.err" || die "legacy rollback after readiness failure did not complete"
"${root}/etc/init.d/trustix" stop ix-test

log "all transactional update scenarios passed"
