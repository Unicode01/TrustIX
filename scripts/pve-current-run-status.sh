#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workspace="${TRUSTIX_PVE_WORKSPACE:-/root/trustix-pve-work}"
run_root=""
tail_lines=120
latest_selection=1
latest_mode="userspace"

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
  awk 'BEGIN{count=0} /^[[:space:]]*#/ || NF==0 {next} {count++} END{printf "rows=%d\n", count}' "${run_root}/evidence.tsv"
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
