#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workspace="${TRUSTIX_PVE_WORKSPACE:-/root/trustix-pve-work}"
run_root=""
latest_userspace=1
write=0

usage() {
  cat <<'EOF'
usage: pve-promote-run-evidence.sh [options]

Validate a scoped PVE production run and feed its evidence.tsv into
promote-production-evidence.py. The default mode is dry-run; pass --write to
update scripts/production-transport-evidence.tsv and
scripts/production-transport-current-evidence.tsv.

Options:
  --workspace DIR        PVE workspace root. Default: /root/trustix-pve-work
  --run-root DIR         Exact result directory to promote
  --latest-userspace     Promote latest current-*-userspace-*-production-* run
  --write                Modify repo evidence TSVs after validation
  --dry-run              Validate only. This is the default
  -h, --help             Show this help
EOF
}

die() {
  printf '[trustix-pve-promote-evidence] ERROR: %s\n' "$*" >&2
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
  local pattern
  pattern="current-*-userspace-*-production-*"
  find "${workspace}/results" -mindepth 1 -maxdepth 1 -type d -name "$pattern" \
    -printf '%T@\t%p\n' 2>/dev/null | sort -n | tail -n 1 | cut -f2-
}

python_bin() {
  if command -v python3 >/dev/null 2>&1; then
    command -v python3
    return
  fi
  if command -v python >/dev/null 2>&1; then
    command -v python
    return
  fi
  die "python3 or python is required"
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
      latest_userspace=0
      shift 2
      ;;
    --latest-userspace)
      latest_userspace=1
      shift
      ;;
    --write)
      write=1
      shift
      ;;
    --dry-run)
      write=0
      shift
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

workspace="$(abs_path_existing "$workspace")"
case "$workspace" in
  /|/root|/tmp|/var|/usr|/etc|/home|/opt) die "refusing unsafe workspace: $workspace" ;;
esac
[[ -d "$workspace" ]] || die "workspace does not exist: $workspace"

if [[ "$latest_userspace" == "1" && -z "$run_root" ]]; then
  run_root="$(latest_run_root)"
  [[ -n "$run_root" ]] || die "no current userspace production run found under ${workspace}/results"
fi
[[ -n "$run_root" ]] || die "--run-root is required unless --latest-userspace can find a run"
run_root="$(abs_path_existing "$run_root")"
case "$run_root" in
  "${workspace}/results/"*) ;;
  *) die "run root must be under ${workspace}/results, got $run_root" ;;
esac
[[ -d "$run_root" ]] || die "run root does not exist: $run_root"

run_meta="${run_root}/run.meta"
evidence="${run_root}/evidence.tsv"
[[ -f "$run_meta" ]] || die "missing run meta: $run_meta"
[[ -s "$evidence" ]] || die "missing or empty evidence TSV: $evidence"

exit_code="$(awk -F= '$1=="exit_code"{print $2}' "$run_meta" | tail -n 1)"
[[ "$exit_code" == "0" ]] || die "run exit_code must be 0 before promotion, got ${exit_code:-missing}"

row_count="$(awk 'BEGIN{count=0} /^[[:space:]]*#/ || NF==0 {next} {count++} END{print count}' "$evidence")"
[[ "$row_count" -gt 0 ]] || die "evidence TSV contains no data rows: $evidence"

if [[ "$write" == "1" ]]; then
  git -C "$repo_root" diff --quiet -- scripts/production-transport-evidence.tsv scripts/production-transport-current-evidence.tsv || \
    die "refusing --write with dirty production evidence TSVs"
fi

py="$(python_bin)"
args=(
  "$py"
  "${repo_root}/scripts/promote-production-evidence.py"
  --generated "$evidence"
  --defaults "${repo_root}/scripts/production-transport-defaults.tsv"
  --evidence "${repo_root}/scripts/production-transport-evidence.tsv"
  --current "${repo_root}/scripts/production-transport-current-evidence.tsv"
)
if [[ "$write" != "1" ]]; then
  args+=(--dry-run)
fi

printf 'RUN_ROOT=%s\n' "$run_root"
printf 'EVIDENCE=%s\n' "$evidence"
printf 'ROWS=%s\n' "$row_count"
printf 'MODE=%s\n' "$([[ "$write" == "1" ]] && printf write || printf dry-run)"
"${args[@]}"

if [[ "$write" == "1" ]]; then
  printf '== git status ==\n'
  git -C "$repo_root" status --short -- scripts/production-transport-evidence.tsv scripts/production-transport-current-evidence.tsv
fi
