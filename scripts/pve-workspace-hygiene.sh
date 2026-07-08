#!/usr/bin/env bash
set -Eeuo pipefail

root_dir="/root"
workspace="${TRUSTIX_PVE_WORKSPACE:-/root/trustix-pve-work}"
mode="check"
stamp="${TRUSTIX_PVE_WORKSPACE_HYGIENE_STAMP:-$(date +%Y%m%d-%H%M%S)}"

usage() {
  cat <<'EOF'
usage: pve-workspace-hygiene.sh [--check|--quarantine] [--workspace DIR] [--root DIR]

Audits TrustIX test leftovers placed directly under the PVE host root
directory. Quarantine mode moves matching top-level entries into:

  WORKSPACE/_scratch/root-loose-STAMP

The script never recursively scans /root and never deletes data.
EOF
}

die() {
  printf '[trustix-pve-hygiene] ERROR: %s\n' "$*" >&2
  exit 1
}

log() {
  printf '[trustix-pve-hygiene] %s\n' "$*" >&2
}

abs_path() {
  local path="$1" dir base
  case "$path" in
    /*) ;;
    *) path="${PWD}/${path}" ;;
  esac
  dir="$(dirname "$path")"
  base="$(basename "$path")"
  if [[ -d "$path" ]]; then
    cd "$path" && pwd -P
  else
    cd "$dir" && printf '%s/%s\n' "$(pwd -P)" "$base"
  fi
}

is_candidate_name() {
  local name="$1"
  case "$name" in
    trustix-pve-work) return 1 ;;
    trustix-*|TrustIX-*|current-*|owdeb-*|dd-*)
      return 0
      ;;
    *.trustix|trustix*.tar|trustix*.tar.gz|TrustIX*.tar|TrustIX*.tar.gz|current-*.tar|current-*.tar.gz)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --check)
      mode="check"
      shift
      ;;
    --quarantine)
      mode="quarantine"
      shift
      ;;
    --workspace)
      [[ $# -ge 2 ]] || die "--workspace requires DIR"
      workspace="$2"
      shift 2
      ;;
    --root)
      [[ $# -ge 2 ]] || die "--root requires DIR"
      root_dir="$2"
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

[[ -d "$root_dir" ]] || die "root directory not found: $root_dir"
root_abs="$(abs_path "$root_dir")"
case "$root_abs" in
  /|/tmp|/var|/usr|/etc|/home|/opt) die "refusing unsafe root directory: $root_abs" ;;
esac

mkdir -p "$workspace"
workspace_abs="$(abs_path "$workspace")"
case "$workspace_abs" in
  "$root_abs") die "workspace must not be the root directory itself: $workspace_abs" ;;
  "$root_abs"/*) ;;
  *) die "workspace must be inside $root_abs, got $workspace_abs" ;;
esac

mapfile -d '' entries < <(find "$root_abs" -mindepth 1 -maxdepth 1 -print0)
candidates=()
for entry in "${entries[@]}"; do
  entry_abs="$(abs_path "$entry")"
  [[ "$entry_abs" == "$workspace_abs" ]] && continue
  name="$(basename "$entry_abs")"
  if is_candidate_name "$name"; then
    candidates+=("$entry_abs")
  fi
done

if [[ "${#candidates[@]}" -eq 0 ]]; then
  log "ok: no loose TrustIX test artifacts under $root_abs"
  exit 0
fi

printf '%s\n' "${candidates[@]}"
if [[ "$mode" == "check" ]]; then
  log "found ${#candidates[@]} loose artifact(s); rerun with --quarantine to move them under $workspace_abs/_scratch"
  exit 1
fi

archive="${workspace_abs}/_scratch/root-loose-${stamp}"
mkdir -p "$archive"
for entry in "${candidates[@]}"; do
  name="$(basename "$entry")"
  target="${archive}/${name}"
  if [[ -e "$target" ]]; then
    n=1
    while [[ -e "${target}.${n}" ]]; do
      n=$((n + 1))
    done
    target="${target}.${n}"
  fi
  mv -- "$entry" "$target"
  log "moved $entry -> $target"
done

log "quarantined ${#candidates[@]} loose artifact(s) under $archive"
