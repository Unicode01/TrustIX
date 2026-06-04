#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workdir="${TRUSTIX_IPTUNNEL_SMOKE_WORKDIR:-$(mktemp -d /tmp/trustix-iptunnel-smoke.XXXXXX)}"
keep="${TRUSTIX_IPTUNNEL_SMOKE_KEEP:-0}"
protocol="${TRUSTIX_IPTUNNEL_SMOKE_PROTOCOL:-gre}"
bin_dir="${TRUSTIX_IPTUNNEL_SMOKE_BIN_DIR:-}"

ns_a="${TRUSTIX_IPTUNNEL_SMOKE_NS_A:-tix-it-a}"
ns_b="${TRUSTIX_IPTUNNEL_SMOKE_NS_B:-tix-it-b}"
veth_a="${TRUSTIX_IPTUNNEL_SMOKE_VETH_A:-tixita0}"
veth_b="${TRUSTIX_IPTUNNEL_SMOKE_VETH_B:-tixitb0}"
underlay_a="${TRUSTIX_IPTUNNEL_SMOKE_UNDERLAY_A:-198.18.20.1}"
underlay_b="${TRUSTIX_IPTUNNEL_SMOKE_UNDERLAY_B:-198.18.20.2}"
carrier_a="${TRUSTIX_IPTUNNEL_SMOKE_CARRIER_A:-10.255.20.1}"
carrier_b="${TRUSTIX_IPTUNNEL_SMOKE_CARRIER_B:-10.255.20.2}"
carrier_prefix="${TRUSTIX_IPTUNNEL_SMOKE_CARRIER_PREFIX:-30}"
carrier_port="${TRUSTIX_IPTUNNEL_SMOKE_PORT:-47829}"
timeout="${TRUSTIX_IPTUNNEL_SMOKE_TIMEOUT:-12s}"

server_pid=""
smoke_bin=""

log() {
  printf '[trustix-iptunnel-smoke] %s\n' "$*" >&2
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
  if [[ -n "$server_pid" ]]; then
    kill -TERM "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" >/dev/null 2>&1 || true
  fi
  ip netns delete "$ns_a" >/dev/null 2>&1 || true
  ip netns delete "$ns_b" >/dev/null 2>&1 || true
  if [[ "$keep" != "1" && "$exit_code" == "0" && -z "${TRUSTIX_IPTUNNEL_SMOKE_WORKDIR:-}" ]]; then
    rm -rf "$workdir"
  else
    log "workdir preserved: $workdir"
  fi
  exit "$exit_code"
}
trap cleanup EXIT

wait_ready() {
  local ready_file="$1"
  local deadline=$((SECONDS + 10))
  while [[ ! -f "$ready_file" ]]; do
    if ! kill -0 "$server_pid" >/dev/null 2>&1; then
      cat "$workdir/server.log" >&2 || true
      die "server exited before ready"
    fi
    if (( SECONDS >= deadline )); then
      cat "$workdir/server.log" >&2 || true
      die "server did not become ready"
    fi
    sleep 0.1
  done
}

main() {
  [[ "$(id -u)" == "0" ]] || die "must run as root"
  case "$protocol" in
    gre|ipip|vxlan) ;;
    *) die "TRUSTIX_IPTUNNEL_SMOKE_PROTOCOL must be gre, ipip, or vxlan" ;;
  esac
  need_cmd ip
  need_cmd grep
  need_cmd cat
  mkdir -p "$workdir"

  prepare_smoke_binary

  ip netns delete "$ns_a" >/dev/null 2>&1 || true
  ip netns delete "$ns_b" >/dev/null 2>&1 || true
  ip netns add "$ns_a"
  ip netns add "$ns_b"
  ip link add "$veth_a" type veth peer name "$veth_b"
  ip link set "$veth_a" netns "$ns_a"
  ip link set "$veth_b" netns "$ns_b"
  ip -n "$ns_a" addr add "$underlay_a/30" dev "$veth_a"
  ip -n "$ns_b" addr add "$underlay_b/30" dev "$veth_b"
  ip -n "$ns_a" link set lo up
  ip -n "$ns_b" link set lo up
  ip -n "$ns_a" link set "$veth_a" up
  ip -n "$ns_b" link set "$veth_b" up

  local endpoint_a endpoint_b ready_file
  endpoint_a="local=${underlay_a},remote=${underlay_b},local_carrier=${carrier_a}/${carrier_prefix},remote_carrier=${carrier_b},port=${carrier_port}"
  endpoint_b="local=${underlay_b},remote=${underlay_a},local_carrier=${carrier_b}/${carrier_prefix},remote_carrier=${carrier_a},port=${carrier_port}"
  ready_file="$workdir/server.ready"

  log "starting ${protocol} listener in ${ns_b}"
  ip netns exec "$ns_b" "$smoke_bin" \
    -mode listen \
    -protocol "$protocol" \
    -endpoint "$endpoint_b" \
    -expect "hello-${protocol}" \
    -reply "ok-${protocol}" \
    -ready-file "$ready_file" \
    -timeout "$timeout" >"$workdir/server.json" 2>"$workdir/server.log" &
  server_pid="$!"
  wait_ready "$ready_file"

  log "dialing ${protocol} carrier from ${ns_a}"
  ip netns exec "$ns_a" "$smoke_bin" \
    -mode dial \
    -protocol "$protocol" \
    -endpoint "$endpoint_a" \
    -message "hello-${protocol}" \
    -expect-reply "ok-${protocol}" \
    -timeout "$timeout" >"$workdir/client.json" 2>"$workdir/client.log"

  wait "$server_pid"
  server_pid=""

  grep -q '"carrier_only": true' "$workdir/client.json" || die "client result did not report carrier_only"
  grep -q '"packets_sent": 1' "$workdir/client.json" || die "client did not send one packet"
  grep -q '"packets_received": 1' "$workdir/client.json" || die "client did not receive one packet"
  grep -q '"packets_sent": 1' "$workdir/server.json" || die "server did not send one packet"
  grep -q '"packets_received": 1' "$workdir/server.json" || die "server did not receive one packet"
  if ip -n "$ns_a" link show type "$protocol" 2>/dev/null | grep -q 'tix'; then
    die "client tunnel link was not cleaned up"
  fi
  if ip -n "$ns_b" link show type "$protocol" 2>/dev/null | grep -q 'tix'; then
    die "server tunnel link was not cleaned up"
  fi

  log "ok: ${protocol} kernel tunnel netdev + inner UDP carrier passed"
  cat "$workdir/client.json"
  cat "$workdir/server.json"
}

prepare_smoke_binary() {
  if [[ -n "$bin_dir" && -x "${bin_dir}/trustix-iptunnel-smoke" ]]; then
    smoke_bin="${bin_dir}/trustix-iptunnel-smoke"
    return
  fi
  if [[ -x "${repo_root}/bin/trustix-iptunnel-smoke" ]]; then
    smoke_bin="${repo_root}/bin/trustix-iptunnel-smoke"
    return
  fi
  need_cmd go
  bin_dir="$workdir/bin"
  mkdir -p "$bin_dir"
  log "building trustix-iptunnel-smoke"
  (cd "$repo_root" && go build -o "$bin_dir/trustix-iptunnel-smoke" ./cmd/trustix-iptunnel-smoke)
  smoke_bin="${bin_dir}/trustix-iptunnel-smoke"
}

main "$@"
