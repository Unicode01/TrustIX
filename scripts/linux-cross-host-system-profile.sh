#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
runner="${TRUSTIX_CROSS_HOST_SYSTEM_PROFILE_RUNNER:-${repo_root}/scripts/linux-cross-host-soak-runner.sh}"
profile_dir="${TRUSTIX_CROSS_HOST_SYSTEM_PROFILE_DIR:-}"
profile_label="${TRUSTIX_CROSS_HOST_SYSTEM_PROFILE_LABEL:-profile}"
profile_seconds="${TRUSTIX_CROSS_HOST_SYSTEM_PROFILE_SECONDS:-45}"
profile_frequency="${TRUSTIX_CROSS_HOST_SYSTEM_PROFILE_FREQUENCY:-199}"
node_a="${TRUSTIX_CROSS_HOST_A:-local}"
node_b="${TRUSTIX_CROSS_HOST_B:-}"
ssh_opts_raw="${TRUSTIX_CROSS_HOST_SSH_OPTS:-}"
underlay_if_a="${TRUSTIX_CROSS_HOST_A_UNDERLAY_IF:-}"
underlay_if_b="${TRUSTIX_CROSS_HOST_B_UNDERLAY_IF:-}"
iperf_seconds="${TRUSTIX_CROSS_HOST_IPERF_SECONDS:-3600}"
iperf_parallel="${TRUSTIX_CROSS_HOST_IPERF_PARALLEL:-8}"
iperf_directions="${TRUSTIX_CROSS_HOST_IPERF_DIRECTIONS:-a2b}"
workdir="${TRUSTIX_CROSS_HOST_WORKDIR:-}"
remote_parent="${TRUSTIX_CROSS_HOST_SYSTEM_PROFILE_REMOTE_PARENT:-${TRUSTIX_CROSS_HOST_REMOTE_BASE:-/tmp}}"
remote_profile_dir=""
runner_pid=""
ssh_opts=()

log() {
  printf '[trustix-system-profile] %s\n' "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

positive_integer() {
  [[ "${1:-}" =~ ^[1-9][0-9]*$ ]]
}

shell_safe_path() {
  [[ "${1:-}" =~ ^[A-Za-z0-9_./:-]+$ ]]
}

snapshot_link() {
  local iface="$1"
  local label="$2"
  printf '%s rx_bytes=%s tx_bytes=%s rx_packets=%s tx_packets=%s rx_dropped=%s tx_dropped=%s\n' \
    "$label" \
    "$(<"/sys/class/net/${iface}/statistics/rx_bytes")" \
    "$(<"/sys/class/net/${iface}/statistics/tx_bytes")" \
    "$(<"/sys/class/net/${iface}/statistics/rx_packets")" \
    "$(<"/sys/class/net/${iface}/statistics/tx_packets")" \
    "$(<"/sys/class/net/${iface}/statistics/rx_dropped")" \
    "$(<"/sys/class/net/${iface}/statistics/tx_dropped")"
}

save_local_symbols() {
  cat /proc/kallsyms >"${profile_dir}/kallsyms-a"
  cat /proc/modules >"${profile_dir}/modules-a"
  {
    local module section
    for module in trustix_crypto trustix_datapath trustix_datapath_helpers; do
      [[ -d "/sys/module/${module}" ]] || continue
      printf '[%s]\n' "$module"
      while IFS= read -r section; do
        printf '%s=' "${section##*/}"
        cat "$section"
      done < <(find "/sys/module/${module}/sections" -maxdepth 1 -type f -print 2>/dev/null | sort)
    done
  } >"${profile_dir}/module-sections-a"
}

main_iperf_active() {
  local pid cmd
  while IFS= read -r pid; do
    [[ -n "$pid" ]] || continue
    [[ -r "/proc/${pid}/cmdline" ]] || continue
    cmd="$(tr '\0' ' ' 2>/dev/null <"/proc/${pid}/cmdline" || true)"
    if [[ "$cmd" == *" -c "* && "$cmd" == *" -t ${iperf_seconds} "* && "$cmd" == *" -P ${iperf_parallel} "* ]]; then
      return 0
    fi
  done < <(pgrep -x iperf3 2>/dev/null || true)
  return 1
}

cleanup() {
  local rc=$?
  set +e
  if [[ -n "$runner_pid" ]] && kill -0 "$runner_pid" 2>/dev/null; then
    kill -TERM "$runner_pid" >/dev/null 2>&1 || true
    wait "$runner_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "$remote_profile_dir" ]]; then
    case "$remote_profile_dir" in
      */trustix-system-profile-*)
        ssh "${ssh_opts[@]}" "$node_b" "rm -rf -- '${remote_profile_dir}'" >/dev/null 2>&1 || true
        ;;
    esac
  fi
  trap - EXIT
  exit "$rc"
}

main() {
  local wait_limit traffic_ready remote_capture_pid stat_pid record_pid runner_rc bps iperf_json

  need_cmd bash
  need_cmd find
  need_cmd iperf3
  need_cmd jq
  need_cmd perf
  need_cmd pgrep
  need_cmd ssh
  need_cmd tar

  [[ "$node_a" == "local" ]] || die "system profiling currently requires TRUSTIX_CROSS_HOST_A=local"
  [[ -n "$node_b" ]] || die "TRUSTIX_CROSS_HOST_B is required"
  [[ -n "$profile_dir" ]] || die "TRUSTIX_CROSS_HOST_SYSTEM_PROFILE_DIR is required"
  [[ "$profile_label" =~ ^[A-Za-z0-9_.-]+$ ]] || die "profile label must be shell-safe"
  positive_integer "$profile_seconds" || die "profile seconds must be a positive integer"
  positive_integer "$profile_frequency" || die "profile frequency must be a positive integer"
  positive_integer "$iperf_seconds" || die "TRUSTIX_CROSS_HOST_IPERF_SECONDS must be a positive integer"
  positive_integer "$iperf_parallel" || die "TRUSTIX_CROSS_HOST_IPERF_PARALLEL must be a positive integer"
  case "$iperf_directions" in
    a2b|a-to-b) ;;
    *) die "system profiling requires TRUSTIX_CROSS_HOST_IPERF_DIRECTIONS=a2b" ;;
  esac
  (( profile_seconds < iperf_seconds )) || die "profile seconds must be shorter than the iperf run"
  [[ -n "$underlay_if_a" && -d "/sys/class/net/${underlay_if_a}" ]] || die "local underlay interface is missing"
  [[ -n "$underlay_if_b" ]] || die "TRUSTIX_CROSS_HOST_B_UNDERLAY_IF is required"
  shell_safe_path "$profile_dir" || die "profile directory must be a shell-safe absolute path"
  shell_safe_path "$remote_parent" || die "remote profile parent must be shell-safe"
  [[ "$profile_dir" == /* ]] || die "profile directory must be absolute"
  [[ "$remote_parent" == /* ]] || die "remote profile parent must be absolute"
  [[ -f "$runner" && -r "$runner" ]] || die "runner is not readable: $runner"
  [[ ! -e "$profile_dir" ]] || die "profile output already exists: $profile_dir"

  if [[ -n "$ssh_opts_raw" ]]; then
    # shellcheck disable=SC2206
    ssh_opts=($ssh_opts_raw)
  fi
  remote_profile_dir="${remote_parent%/}/trustix-system-profile-${profile_label}-$$"
  shell_safe_path "$remote_profile_dir" || die "derived remote profile directory is unsafe"
  workdir="${workdir:-${profile_dir}/soak}"
  export TRUSTIX_CROSS_HOST_WORKDIR="$workdir"
  export TRUSTIX_CROSS_HOST_IPERF_DIRECTIONS="a2b"

  trap cleanup EXIT
  mkdir -p "$workdir" "${profile_dir}/b"
  env | LC_ALL=C sort | grep '^TRUSTIX_' >"${profile_dir}/profile-env.txt" || true
  {
    date -u '+captured_at=%Y-%m-%dT%H:%M:%SZ'
    uname -a
    perf version
  } >"${profile_dir}/metadata-a.txt"
  ssh "${ssh_opts[@]}" "$node_b" bash -s -- "$remote_profile_dir" "$underlay_if_b" <<'REMOTE_PREFLIGHT'
set -Eeuo pipefail
dir=$1
iface=$2
for command_name in bash cat find perf tar; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf 'missing required remote command: %s\n' "$command_name" >&2
    exit 1
  }
done
[[ -d "/sys/class/net/${iface}" ]] || {
  printf 'remote underlay interface is missing: %s\n' "$iface" >&2
  exit 1
}
[[ ! -e "$dir" ]] || {
  printf 'remote profile output already exists: %s\n' "$dir" >&2
  exit 1
}
mkdir -p "$dir"
REMOTE_PREFLIGHT

  log "start runner label=${profile_label} workdir=${workdir}"
  bash "$runner" >"${profile_dir}/runner.out" 2>"${profile_dir}/runner.err" &
  runner_pid=$!

  wait_limit=$((iperf_seconds + 120))
  traffic_ready=0
  for ((i = 0; i < wait_limit; i++)); do
    if ! kill -0 "$runner_pid" 2>/dev/null; then
      wait "$runner_pid" || true
      runner_pid=""
      tail -n 120 "${profile_dir}/runner.err" >&2 || true
      die "runner exited before main iperf traffic"
    fi
    if main_iperf_active; then
      traffic_ready=1
      break
    fi
    sleep 1
  done
  [[ "$traffic_ready" == 1 ]] || die "timed out waiting for main iperf traffic"

  log "main traffic active; save runtime module symbols"
  save_local_symbols
  ssh "${ssh_opts[@]}" "$node_b" bash -s -- "$remote_profile_dir" <<'REMOTE_SYMBOLS'
set -Eeuo pipefail
dir=$1
cat /proc/kallsyms >"${dir}/kallsyms"
cat /proc/modules >"${dir}/modules"
{
  for module in trustix_crypto trustix_datapath trustix_datapath_helpers; do
    [[ -d "/sys/module/${module}" ]] || continue
    printf '[%s]\n' "$module"
    while IFS= read -r section; do
      printf '%s=' "${section##*/}"
      cat "$section"
    done < <(find "/sys/module/${module}/sections" -maxdepth 1 -type f -print 2>/dev/null | sort)
  done
} >"${dir}/module-sections"
REMOTE_SYMBOLS

  snapshot_link "$underlay_if_a" before >"${profile_dir}/link-a.txt"
  ssh "${ssh_opts[@]}" "$node_b" bash -s -- "$remote_profile_dir" "$underlay_if_b" "$profile_seconds" "$profile_frequency" <<'REMOTE_CAPTURE' >"${profile_dir}/remote-capture.out" 2>"${profile_dir}/remote-capture.err" &
set -Eeuo pipefail
dir=$1
iface=$2
seconds=$3
frequency=$4
snapshot() {
  local label=$1
  printf '%s rx_bytes=%s tx_bytes=%s rx_packets=%s tx_packets=%s rx_dropped=%s tx_dropped=%s\n' \
    "$label" \
    "$(<"/sys/class/net/${iface}/statistics/rx_bytes")" \
    "$(<"/sys/class/net/${iface}/statistics/tx_bytes")" \
    "$(<"/sys/class/net/${iface}/statistics/rx_packets")" \
    "$(<"/sys/class/net/${iface}/statistics/tx_packets")" \
    "$(<"/sys/class/net/${iface}/statistics/rx_dropped")" \
    "$(<"/sys/class/net/${iface}/statistics/tx_dropped")"
}
snapshot before >"${dir}/link.txt"
perf stat -a -x, -e cycles,instructions,task-clock -o "${dir}/perf.stat" -- sleep "$seconds" &
stat_pid=$!
perf record -a -F "$frequency" --call-graph fp -o "${dir}/perf.data" -- sleep "$seconds" >"${dir}/perf-record.out" 2>"${dir}/perf-record.err" &
record_pid=$!
wait "$stat_pid"
wait "$record_pid"
snapshot after >>"${dir}/link.txt"
REMOTE_CAPTURE
  remote_capture_pid=$!

  perf stat -a -x, -e cycles,instructions,task-clock -o "${profile_dir}/perf-a.stat" -- sleep "$profile_seconds" &
  stat_pid=$!
  perf record -a -F "$profile_frequency" --call-graph fp -o "${profile_dir}/perf-a.data" -- sleep "$profile_seconds" >"${profile_dir}/perf-a-record.out" 2>"${profile_dir}/perf-a-record.err" &
  record_pid=$!
  wait "$stat_pid"
  wait "$record_pid"
  wait "$remote_capture_pid"
  snapshot_link "$underlay_if_a" after >>"${profile_dir}/link-a.txt"

  log "profile capture complete; wait for runner cleanup"
  runner_rc=0
  wait "$runner_pid" || runner_rc=$?
  runner_pid=""
  if ((runner_rc != 0)); then
    tail -n 160 "${profile_dir}/runner.err" >&2 || true
    die "runner failed with status ${runner_rc}"
  fi

  perf report -i "${profile_dir}/perf-a.data" --kallsyms "${profile_dir}/kallsyms-a" --stdio --no-children -g none --percent-limit 0.05 --sort overhead,comm,dso,symbol >"${profile_dir}/perf-a-flat.txt" 2>"${profile_dir}/perf-a-report.err"
  ssh "${ssh_opts[@]}" "$node_b" "perf report -i '${remote_profile_dir}/perf.data' --kallsyms '${remote_profile_dir}/kallsyms' --stdio --no-children -g none --percent-limit 0.05 --sort overhead,comm,dso,symbol" >"${profile_dir}/perf-b-flat.txt" 2>"${profile_dir}/perf-b-report.err"
  ssh "${ssh_opts[@]}" "$node_b" "tar -C '${remote_profile_dir}' -cf - ." | tar -C "${profile_dir}/b" -xf -

  iperf_json="$(find "$workdir/a" -maxdepth 1 -name 'iperf3-a-to-b-*.json' -type f -print -quit)"
  if [[ -n "$iperf_json" ]]; then
    bps="$(jq -r '.end.sum_received.bits_per_second // .end.sum.bits_per_second // 0' "$iperf_json")"
  else
    bps=0
  fi
  printf '%s\n' "${bps:-0}" >"${profile_dir}/throughput-bps.txt"
  log "pass label=${profile_label} throughput_bps=${bps:-0}"
}

main "$@"
