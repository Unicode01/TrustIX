#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

out_root="${TRUSTIX_KERNEL_MODULE_OUT:-${repo_root}/build/kernel-modules}"
module_list="${TRUSTIX_KERNEL_MODULES:-crypto datapath helpers}"
helper_mode="${TRUSTIX_DATAPATH_HELPERS_BUILD_MODE:-${TRUSTIX_KERNEL_MODULE_HELPERS_MODE:-auto}}"
crypto_mode="${TRUSTIX_CRYPTO_BUILD_MODE:-${TRUSTIX_KERNEL_MODULE_CRYPTO_MODE:-full}}"
kernel_arch="${TRUSTIX_KERNEL_MODULE_ARCH:-${ARCH:-}}"
cross_compile="${TRUSTIX_KERNEL_MODULE_CROSS_COMPILE:-${CROSS_COMPILE:-}}"
make_v="${V:-0}"
tmp_files=""

crypto_module_dir="${TRUSTIX_CRYPTO_MODULE_DIR:-${repo_root}/kernel/trustix_crypto}"
datapath_module_dir="${TRUSTIX_DATAPATH_MODULE_DIR:-${repo_root}/kernel/trustix_datapath}"
helpers_module_dir="${TRUSTIX_DATAPATH_HELPERS_MODULE_DIR:-${repo_root}/kernel/trustix_datapath_helpers}"

log() {
  printf '[trustix-kmods] %s\n' "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

host_kernel_arch() {
  case "$(uname -m)" in
    x86_64|amd64) printf 'x86\n' ;;
    aarch64|arm64) printf 'arm64\n' ;;
    armv7l|armv6l|armhf|arm) printf 'arm\n' ;;
    *) uname -m ;;
  esac
}

json_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  printf '%s' "$value"
}

sha256_file() {
  local path="$1"
  [[ -f "$path" ]] || return 0
  sha256sum "$path" | cut -d ' ' -f 1
}

file_size() {
  local path="$1"
  [[ -f "$path" ]] || { printf '0'; return; }
  stat -c %s "$path"
}

module_vermagic() {
  local path="$1"
  if command -v modinfo >/dev/null 2>&1 && [[ -f "$path" ]]; then
    modinfo -F vermagic "$path" 2>/dev/null || true
  fi
}

cleanup_tmp() {
  local file
  for file in $tmp_files; do
    rm -f "$file" >/dev/null 2>&1 || true
  done
}
trap cleanup_tmp EXIT

new_tmp_file() {
  local file
  file="$(mktemp)"
  tmp_files="${tmp_files} ${file}"
  printf '%s\n' "$file"
}

collect_kdirs() {
  if [[ "$#" -gt 0 ]]; then
    printf '%s\n' "$@"
    return
  fi
  if [[ -n "${TRUSTIX_KERNEL_MODULE_KDIRS:-}" ]]; then
    printf '%s\n' "$TRUSTIX_KERNEL_MODULE_KDIRS" | tr ',:' '\n' | sed '/^[[:space:]]*$/d'
    return
  fi
  if [[ -n "${KDIR:-}" ]]; then
    printf '%s\n' "$KDIR"
    return
  fi
  printf '/lib/modules/%s/build\n' "$(uname -r)"
}

kernel_release_for_kdir() {
  local kdir="$1"
  kdir="${kdir%/}"
  case "$kdir" in
    /lib/modules/*/build|/lib/modules/*/source)
      basename "$(dirname "$kdir")"
      return
      ;;
  esac
  make -s -C "$kdir" kernelrelease 2>/dev/null || basename "$(dirname "$kdir")"
}

clean_module_dir() {
  local module_dir="$1"
  local kdir="$2"
  if [[ -n "$cross_compile" ]]; then
    make -C "$module_dir" KDIR="$kdir" ARCH="$kernel_arch" CROSS_COMPILE="$cross_compile" V="$make_v" clean >/dev/null 2>&1 || true
  else
    make -C "$module_dir" KDIR="$kdir" ARCH="$kernel_arch" V="$make_v" clean >/dev/null 2>&1 || true
  fi
}

run_make_logged() {
  local log_path="$1"
  shift
  mkdir -p "$(dirname "$log_path")"
  "$@" >"$log_path" 2>&1
}

copy_module_result() {
  local module_name="$1"
  local variant="$2"
  local module_dir="$3"
  local dst_dir="$4"
  local ko_src="${module_dir}/${module_name}.ko"
  local ko_dst="${dst_dir}/${module_name}.ko"
  [[ -f "$ko_src" ]] || die "module build did not produce ${ko_src}"
  mkdir -p "$dst_dir"
  install -m 0644 "$ko_src" "$ko_dst"
  printf '%s\n' "$variant"
}

build_target() {
  local module_name="$1"
  local module_dir="$2"
  local target="$3"
  local variant="$4"
  local kdir="$5"
  local dst_dir="$6"
  local log_path="${dst_dir}/build-${variant}.log"
  clean_module_dir "$module_dir" "$kdir"
  if [[ "$target" == "all" && -n "$cross_compile" ]]; then
    run_make_logged "$log_path" make -C "$module_dir" KDIR="$kdir" ARCH="$kernel_arch" CROSS_COMPILE="$cross_compile" V="$make_v" || return 1
  elif [[ "$target" == "all" ]]; then
    run_make_logged "$log_path" make -C "$module_dir" KDIR="$kdir" ARCH="$kernel_arch" V="$make_v" || return 1
  elif [[ -n "$cross_compile" ]]; then
    run_make_logged "$log_path" make -C "$module_dir" "$target" KDIR="$kdir" ARCH="$kernel_arch" CROSS_COMPILE="$cross_compile" V="$make_v" || return 1
  else
    run_make_logged "$log_path" make -C "$module_dir" "$target" KDIR="$kdir" ARCH="$kernel_arch" V="$make_v" || return 1
  fi
  copy_module_result "$module_name" "$variant" "$module_dir" "$dst_dir" >/dev/null
  printf '%s\n' "$variant"
}

build_crypto() {
  local kdir="$1"
  local dst_dir="$2"
  case "$crypto_mode" in
    full)
      build_target trustix_crypto "$crypto_module_dir" all full "$kdir" "$dst_dir"
      ;;
    device-only)
      build_target trustix_crypto "$crypto_module_dir" device-only device-only "$kdir" "$dst_dir"
      ;;
    auto)
      if build_target trustix_crypto "$crypto_module_dir" all full "$kdir" "$dst_dir"; then
        return 0
      fi
      log "trustix_crypto full build failed for ${kdir}; retrying device-only"
      build_target trustix_crypto "$crypto_module_dir" device-only device-only "$kdir" "$dst_dir"
      ;;
    *)
      die "TRUSTIX_CRYPTO_BUILD_MODE must be full, device-only, or auto"
      ;;
  esac
}

build_datapath() {
  local kdir="$1"
  local dst_dir="$2"
  build_target trustix_datapath "$datapath_module_dir" all full "$kdir" "$dst_dir"
}

build_helpers() {
  local kdir="$1"
  local dst_dir="$2"
  case "$helper_mode" in
    full)
      build_target trustix_datapath_helpers "$helpers_module_dir" all full "$kdir" "$dst_dir"
      ;;
    basic)
      build_target trustix_datapath_helpers "$helpers_module_dir" basic basic "$kdir" "$dst_dir"
      ;;
    auto)
      if build_target trustix_datapath_helpers "$helpers_module_dir" all full "$kdir" "$dst_dir"; then
        return 0
      fi
      log "trustix_datapath_helpers full build failed for ${kdir}; retrying basic"
      build_target trustix_datapath_helpers "$helpers_module_dir" basic basic "$kdir" "$dst_dir"
      ;;
    *)
      die "TRUSTIX_DATAPATH_HELPERS_BUILD_MODE must be full, basic, or auto"
      ;;
  esac
}

write_manifest() {
  local manifest="$1"
  local entries_file="$2"
  local first=1
  {
    printf '{\n'
    printf '  "built_at": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '  "arch": "%s",\n' "$(json_escape "$kernel_arch")"
    printf '  "cross_compile": "%s",\n' "$(json_escape "$cross_compile")"
    printf '  "crypto_mode": "%s",\n' "$(json_escape "$crypto_mode")"
    printf '  "helpers_mode": "%s",\n' "$(json_escape "$helper_mode")"
    printf '  "modules": [\n'
    local entry module kernel_release kdir variant ko_path hash size vermagic out_dir old_ifs
    while IFS= read -r entry; do
      [[ -n "$entry" ]] || continue
      old_ifs="$IFS"
      IFS='|'
      set -- $entry
      IFS="$old_ifs"
      module="$1"
      kernel_release="$2"
      kdir="$3"
      variant="$4"
      ko_path="$5"
      out_dir="$6"
      hash="$(sha256_file "$ko_path")"
      size="$(file_size "$ko_path")"
      vermagic="$(module_vermagic "$ko_path")"
      if [[ "$first" == "0" ]]; then
        printf ',\n'
      fi
      first=0
      printf '    {"name": "%s", "kernelrelease": "%s", "kdir": "%s", "variant": "%s", "ko": "%s", "output_dir": "%s", "sha256": "%s", "size": %s, "vermagic": "%s"}' \
        "$(json_escape "$module")" \
        "$(json_escape "$kernel_release")" \
        "$(json_escape "$kdir")" \
        "$(json_escape "$variant")" \
        "$(json_escape "$ko_path")" \
        "$(json_escape "$out_dir")" \
        "$hash" "$size" "$(json_escape "$vermagic")"
    done <"$entries_file"
    printf '\n  ]\n'
    printf '}\n'
  } >"$manifest"
}

main() {
  [[ "$(uname -s)" == "Linux" ]] || die "build-kernel-modules-linux must run on Linux"
  need_cmd make
  need_cmd install
  need_cmd sha256sum
  need_cmd stat
  if [[ -z "$kernel_arch" ]]; then
    kernel_arch="$(host_kernel_arch)"
  fi

  mkdir -p "$out_root"
  local kdirs_file entries_file have_kdir
  kdirs_file="$(new_tmp_file)"
  entries_file="$(new_tmp_file)"
  collect_kdirs "$@" >"$kdirs_file"
  have_kdir=0
  local kdir kernel_release kernel_out module variant module_out ko_path
  while IFS= read -r kdir; do
    kdir="${kdir#"${kdir%%[![:space:]]*}"}"
    kdir="${kdir%"${kdir##*[![:space:]]}"}"
    [[ -n "$kdir" ]] || continue
    have_kdir=1
    [[ -d "$kdir" ]] || die "kernel build directory not found: $kdir"
    kernel_release="$(kernel_release_for_kdir "$kdir")"
    kernel_out="${out_root}/${kernel_release}/${kernel_arch}"
    mkdir -p "$kernel_out"
    log "build kernel=${kernel_release} arch=${kernel_arch} kdir=${kdir} cross_compile=${cross_compile:-none}"
    for module in $module_list; do
      case "$module" in
        crypto|trustix_crypto)
          module_out="${kernel_out}/trustix_crypto"
          variant="$(build_crypto "$kdir" "$module_out")"
          ko_path="${module_out}/trustix_crypto.ko"
          printf '%s|%s|%s|%s|%s|%s\n' "trustix_crypto" "$kernel_release" "$kdir" "$variant" "$ko_path" "$module_out" >>"$entries_file"
          ;;
        datapath|trustix_datapath)
          module_out="${kernel_out}/trustix_datapath"
          variant="$(build_datapath "$kdir" "$module_out")"
          ko_path="${module_out}/trustix_datapath.ko"
          printf '%s|%s|%s|%s|%s|%s\n' "trustix_datapath" "$kernel_release" "$kdir" "$variant" "$ko_path" "$module_out" >>"$entries_file"
          ;;
        helpers|datapath_helpers|trustix_datapath_helpers)
          module_out="${kernel_out}/trustix_datapath_helpers"
          variant="$(build_helpers "$kdir" "$module_out")"
          ko_path="${module_out}/trustix_datapath_helpers.ko"
          printf '%s|%s|%s|%s|%s|%s\n' "trustix_datapath_helpers" "$kernel_release" "$kdir" "$variant" "$ko_path" "$module_out" >>"$entries_file"
          ;;
        *)
          die "unknown module in TRUSTIX_KERNEL_MODULES: $module"
          ;;
      esac
      log "built ${module} variant=${variant} output=${module_out}"
    done
  done <"$kdirs_file"
  [[ "$have_kdir" == "1" ]] || die "no KDIRs provided"

  write_manifest "${out_root}/manifest.json" "$entries_file"
  log "manifest ${out_root}/manifest.json"
}

main "$@"
