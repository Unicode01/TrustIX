#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workspace="${TRUSTIX_PVE_WORKSPACE:-/root/trustix-pve-work}"
run_root=""
tail_lines=120
latest_selection=1
latest_mode="userspace"
check_nodes="${TRUSTIX_PVE_STATUS_CHECK_NODES:-0}"
node_a="${TRUSTIX_PVE_STATUS_NODE_A:-${TRUSTIX_PVE_USERSPACE_A:-root@192.168.100.204}}"
node_b="${TRUSTIX_PVE_STATUS_NODE_B:-${TRUSTIX_PVE_USERSPACE_B:-root@192.168.100.203}}"
node_ssh_opts_raw="${TRUSTIX_PVE_STATUS_SSH_OPTS:-${TRUSTIX_PVE_USERSPACE_SSH_OPTS:--i /root/.ssh/trustix-cross-run -o BatchMode=yes -o StrictHostKeyChecking=accept-new}}"
node_since="${TRUSTIX_PVE_STATUS_NODE_SINCE:-2 hours ago}"

usage() {
  cat <<'EOF'
usage: pve-current-run-status.sh [options]

Inspect a scoped PVE production run without writing files or touching loose
/root state. Defaults to the latest current userspace production run under
/root/trustix-pve-work/results.

Options:
  --workspace DIR        PVE workspace root. Default: /root/trustix-pve-work
  --run-root DIR         Exact result directory to inspect
  --latest-userspace     Inspect latest current-*-userspace-*-production-* run
  --latest-production    Inspect latest *-production-* run
  --tail N               Lines of matrix stderr/stdout to show. Default: 120
  --check-nodes          Also SSH to the cross-host nodes and print read-only state
  --node-a USER@HOST     Node A for --check-nodes. Default: root@192.168.100.204
  --node-b USER@HOST     Node B for --check-nodes. Default: root@192.168.100.203
  --ssh-opts OPTS        SSH options for --check-nodes
  --node-since WHEN      Kernel log window for --check-nodes. Default: 2 hours ago
  -h, --help             Show this help
EOF
}

die() {
  printf '[trustix-pve-run-status] ERROR: %s\n' "$*" >&2
  exit 1
}

abs_path_existing() {
  local path="$1" dir base
  case "$path" in
    /*) ;;
    *) path="${PWD}/${path}" ;;
  esac
  dir="$(dirname "$path")"
  base="$(basename "$path")"
  [[ -d "$dir" ]] || die "parent directory does not exist: $dir"
  cd "$dir" && printf '%s/%s\n' "$(pwd -P)" "$base"
}

latest_run_root() {
  local pattern="$1"
  find "${workspace}/results" -mindepth 1 -maxdepth 1 -type d -name "$pattern" \
    -printf '%T@\t%p\n' 2>/dev/null | sort -n | tail -n 1 | cut -f2-
}

latest_pattern() {
  case "$latest_mode" in
    userspace) printf 'current-*-userspace-*-production-*' ;;
    production) printf '*-production-*' ;;
    *) die "unknown latest mode: $latest_mode" ;;
  esac
}

print_file_if_present() {
  local label="$1" path="$2"
  printf '== %s ==\n' "$label"
  if [[ -f "$path" ]]; then
    sed -n '1,220p' "$path"
  else
    printf 'missing: %s\n' "$path"
  fi
}

count_data_rows() {
  local path="$1"
  if [[ -f "$path" ]]; then
    awk 'BEGIN{count=0} /^[[:space:]]*#/ || NF==0 {next} {count++} END{print count}' "$path"
  else
    printf '0\n'
  fi
}

truthy() {
  case "${1:-0}" in
    1|true|yes|on|enabled) return 0 ;;
    *) return 1 ;;
  esac
}

shell_quote() {
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

print_node_status() {
  local label="$1" node="$2" since="$3" remote_script
  printf '== node %s status ==\n' "$label"
  if [[ -z "$node" ]]; then
    printf 'status=skipped-empty-node\n'
    return
  fi
  if ! command -v ssh >/dev/null 2>&1; then
    printf 'status=skipped-missing-ssh\n'
    return
  fi

  remote_script=$(cat <<EOF
set -u
printf 'status=reachable\n'
printf 'date=%s\n' "\$(date -Is 2>/dev/null || date)"
printf 'hostname=%s\n' "\$(hostname 2>/dev/null || printf unknown)"
printf 'kernel=%s\n' "\$(uname -r 2>/dev/null || printf unknown)"
printf 'boot_id='
cat /proc/sys/kernel/random/boot_id 2>/dev/null || printf 'missing\n'
printf 'trustix_modules:\n'
lsmod 2>/dev/null | grep '^trustix_' || true
printf 'trustix_processes:\n'
ps -eo pid,ppid,etime,cmd 2>/dev/null | grep -E 'trustixd|iperf3|linux-cross-host|soak' | grep -v grep || true
printf 'trustix_listeners:\n'
(ss -lntup 2>/dev/null || netstat -lntup 2>/dev/null || true) | grep -E '1878|1944|2520|8787|9443' || true
printf 'kernel_suspicious:\n'
if command -v journalctl >/dev/null 2>&1; then
  journalctl -k -b --since $(shell_quote "$since") --no-pager -o short-iso 2>/dev/null | grep -E -i 'panic|oops|BUG|Call Trace|RIP:|general protection|page fault|watchdog|lockup|trustix|datapath|rx_worker|xmit|gso|tx_queue_len' || true
else
  dmesg 2>/dev/null | grep -E -i 'panic|oops|BUG|Call Trace|RIP:|general protection|page fault|watchdog|lockup|trustix|datapath|rx_worker|xmit|gso|tx_queue_len' || true
fi
EOF
)

  if ! ssh -n "${node_ssh_opts[@]}" "$node" "bash -c $(shell_quote "$remote_script")"; then
    printf 'status=unreachable\nnode=%s\n' "$node"
  fi
}

print_progress_summary() {
  local cases_path="${run_root}/matrix/cases.tsv"
  local summary_path="${run_root}/summary.jsonl"
  local matrix_stderr="${run_root}/matrix.stderr"
  local cases completed active_line

  printf '== progress ==\n'
  cases="$(count_data_rows "$cases_path")"
  completed="$(count_data_rows "$summary_path")"
  printf 'cases_total=%s\n' "$cases"
  printf 'summary_rows=%s\n' "$completed"
  if [[ -f "$matrix_stderr" ]]; then
    active_line="$(awk '/\[trustix-cross-host-transport-matrix\] run /{line=$0} END{print line}' "$matrix_stderr")"
    if [[ -n "$active_line" ]]; then
      active_line="${active_line#*] run }"
      printf 'active_case=%s\n' "$active_line"
    fi
  fi
}

print_host_health_summary() {
  local health_log="${run_root}/host-health.log"
  local latest_sample latest_boot latest_kernel latest_warning

  printf '== host health ==\n'
  if [[ ! -f "$health_log" ]]; then
    printf 'missing: %s\n' "$health_log"
    return
  fi

  latest_sample="$(grep '^===== ' "$health_log" 2>/dev/null | tail -n 1 || true)"
  if [[ -n "$latest_sample" ]]; then
    latest_sample="${latest_sample#===== }"
    latest_sample="${latest_sample% =====}"
    printf 'latest_sample=%s\n' "$latest_sample"
  fi
  latest_boot="$(awk -F= '/^boot_id=/{value=$2} END{print value}' "$health_log" 2>/dev/null || true)"
  [[ -n "$latest_boot" ]] && printf 'latest_boot_id=%s\n' "$latest_boot"
  latest_kernel="$(awk -F= '/^kernel=/{value=$2} END{print value}' "$health_log" 2>/dev/null || true)"
  [[ -n "$latest_kernel" ]] && printf 'latest_kernel=%s\n' "$latest_kernel"

  latest_warning="$(awk '
    /^===== / { in_sample = 1; in_warnings = 0; warning = "" }
    /^--- kernel warnings tail ---/ { in_warnings = 1; next }
    in_sample && in_warnings && NF > 0 { warning = warning (warning ? "\n" : "") $0 }
    END { print warning }
  ' "$health_log" 2>/dev/null || true)"
  if [[ -n "$latest_warning" ]]; then
    printf 'latest_kernel_warnings_tail:\n%s\n' "$latest_warning"
  else
    printf 'latest_kernel_warnings_tail=empty\n'
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workspace)
      [[ $# -ge 2 ]] || die "--workspace requires DIR"
      workspace="$2"
      shift 2
      ;;
    --run-root)
      [[ $# -ge 2 ]] || die "--run-root requires DIR"
      run_root="$2"
      latest_selection=0
      shift 2
      ;;
    --latest-userspace)
      latest_selection=1
      latest_mode="userspace"
      shift
      ;;
    --latest-production)
      latest_selection=1
      latest_mode="production"
      shift
      ;;
    --tail)
      [[ $# -ge 2 ]] || die "--tail requires N"
      tail_lines="$2"
      shift 2
      ;;
    --check-nodes)
      check_nodes=1
      shift
      ;;
    --node-a)
      [[ $# -ge 2 ]] || die "--node-a requires USER@HOST"
      node_a="$2"
      shift 2
      ;;
    --node-b)
      [[ $# -ge 2 ]] || die "--node-b requires USER@HOST"
      node_b="$2"
      shift 2
      ;;
    --ssh-opts)
      [[ $# -ge 2 ]] || die "--ssh-opts requires OPTS"
      node_ssh_opts_raw="$2"
      shift 2
      ;;
    --node-since)
      [[ $# -ge 2 ]] || die "--node-since requires WHEN"
      node_since="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

case "$tail_lines" in
  ''|*[!0-9]*) die "--tail must be a non-negative integer" ;;
esac

node_ssh_opts=()
if [[ -n "$node_ssh_opts_raw" ]]; then
  # shellcheck disable=SC2206
  node_ssh_opts=($node_ssh_opts_raw)
fi

workspace="$(abs_path_existing "$workspace")"
case "$workspace" in
  /|/root|/tmp|/var|/usr|/etc|/home|/opt) die "refusing unsafe workspace: $workspace" ;;
esac
[[ -d "$workspace" ]] || die "workspace does not exist: $workspace"

if [[ "$latest_selection" == "1" && -z "$run_root" ]]; then
  pattern="$(latest_pattern)"
  run_root="$(latest_run_root "$pattern")"
  [[ -n "$run_root" ]] || die "no $latest_mode production run found under ${workspace}/results"
fi
[[ -n "$run_root" ]] || die "--run-root is required unless latest selection can find a run"
run_root="$(abs_path_existing "$run_root")"
case "$run_root" in
  "${workspace}/results/"*) ;;
  *) die "run root must be under ${workspace}/results, got $run_root" ;;
esac
[[ -d "$run_root" ]] || die "run root does not exist: $run_root"

run_name="$(basename "$run_root")"
pid_file="${workspace}/_scratch/pids/${run_name}.pid"

printf '== host ==\n'
printf 'date=%s\n' "$(date -Is)"
printf 'host=%s\n' "$(hostname)"
printf 'repo=%s\n' "$repo_root"
printf 'workspace=%s\n' "$workspace"
printf 'run_root=%s\n' "$run_root"

printf '== root hygiene ==\n'
if [[ -x "${repo_root}/scripts/pve-workspace-hygiene.sh" && "$workspace" == /root/* ]]; then
  if "${repo_root}/scripts/pve-workspace-hygiene.sh" --workspace "$workspace" --check; then
    printf 'status=clean\n'
  else
    printf 'status=loose-artifacts-detected\n'
  fi
else
  printf 'status=skipped\n'
fi

printf '== root top trustix-like entries ==\n'
while IFS= read -r -d '' entry; do
  entry_abs="$(abs_path_existing "$entry")"
  [[ "$entry_abs" == "$workspace" ]] && continue
  find "$entry_abs" -maxdepth 0 -printf '%M %s %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null || true
done < <(find /root -mindepth 1 -maxdepth 1 \( -name 'trustix*' -o -name 'current-*' -o -name '*.tar' -o -name '*.tsv' \) -print0 2>/dev/null) || true

printf '== run tree ==\n'
find "$run_root" -maxdepth 2 -printf '%M %s %TY-%Tm-%Td %TH:%TM %p\n' | sort || true

print_file_if_present "run.meta" "${run_root}/run.meta"

print_progress_summary

print_host_health_summary

if truthy "$check_nodes"; then
  print_node_status "a" "$node_a" "$node_since"
  print_node_status "b" "$node_b" "$node_since"
fi

printf '== pid ==\n'
pid_status="missing"
if [[ -f "$pid_file" ]]; then
  pid="$(sed -n '1p' "$pid_file")"
  printf 'pid_file=%s\npid=%s\n' "$pid_file" "$pid"
  if [[ "$pid" =~ ^[0-9]+$ ]] && ps -p "$pid" >/dev/null 2>&1; then
    pid_status="alive"
    ps -fp "$pid" || true
  else
    pid_status="stale"
    printf 'pid_status=stale\n'
  fi
else
  printf 'missing: %s\n' "$pid_file"
fi

printf '== evidence ==\n'
if [[ -f "${run_root}/evidence.tsv" ]]; then
  printf 'rows=%s\n' "$(count_data_rows "${run_root}/evidence.tsv")"
  sed -n '1,80p' "${run_root}/evidence.tsv"
else
  printf 'missing: %s\n' "${run_root}/evidence.tsv"
fi

printf '== summary tail ==\n'
if [[ -f "${run_root}/summary.jsonl" ]]; then
  tail -n "$tail_lines" "${run_root}/summary.jsonl"
else
  printf 'missing: %s\n' "${run_root}/summary.jsonl"
fi

printf '== matrix stderr tail ==\n'
if [[ -f "${run_root}/matrix.stderr" ]]; then
  tail -n "$tail_lines" "${run_root}/matrix.stderr"
else
  printf 'missing: %s\n' "${run_root}/matrix.stderr"
fi

printf '== matrix stdout tail ==\n'
if [[ -f "${run_root}/matrix.stdout" ]]; then
  tail -n "$tail_lines" "${run_root}/matrix.stdout"
else
  printf 'missing: %s\n' "${run_root}/matrix.stdout"
fi

printf '== verdict ==\n'
exit_code="$(awk -F= '$1=="exit_code"{print $2}' "${run_root}/run.meta" 2>/dev/null | tail -n 1)"
if [[ "$exit_code" == "0" && -s "${run_root}/evidence.tsv" ]]; then
  printf 'status=ready_to_review_or_promote\n'
elif [[ -n "$exit_code" ]]; then
  printf 'status=finished_nonzero\nexit_code=%s\n' "$exit_code"
elif [[ "$pid_status" == "stale" ]]; then
  printf 'status=interrupted_or_stale\n'
else
  printf 'status=running_or_incomplete\n'
fi
