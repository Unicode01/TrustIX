#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out_root="${TRUSTIX_OPENWRT_KMOD_MATRIX_OUT:-${repo_root}/build/openwrt-kmod-matrix}"
download_root="${TRUSTIX_OPENWRT_KMOD_MATRIX_DOWNLOADS:-${out_root}/downloads}"
sdk_root="${TRUSTIX_OPENWRT_KMOD_MATRIX_SDKS:-${out_root}/sdks}"
result_jsonl="${TRUSTIX_OPENWRT_KMOD_MATRIX_JSONL:-${out_root}/results.jsonl}"
result_tsv="${TRUSTIX_OPENWRT_KMOD_MATRIX_TSV:-${out_root}/results.tsv}"
base_url="${TRUSTIX_OPENWRT_DOWNLOAD_BASE:-https://downloads.openwrt.org/releases}"
matrix_raw="${TRUSTIX_OPENWRT_KMOD_MATRIX:-}"
keep_sdks="${TRUSTIX_OPENWRT_KMOD_MATRIX_KEEP_SDKS:-1}"
make_v="${V:-s}"
export TERM="${TERM:-xterm}"

module_src="${TRUSTIX_OPENWRT_KMOD_MATRIX_DATAPATH_C:-${repo_root}/kernel/trustix_datapath/trustix_datapath.c}"

log() {
  printf '[trustix-openwrt-kmod-matrix] %s\n' "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

need_gnu_awk() {
  if command -v gawk >/dev/null 2>&1; then
    return 0
  fi
  if awk --version 2>/dev/null | grep -q 'GNU Awk'; then
    return 0
  fi
  die "missing required command: gawk (OpenWrt SDK prerequisite)"
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
  sha256sum "$path" | awk '{print $1}'
}

download_file() {
  local url="$1"
  local dst="$2"
  if [[ -s "$dst" ]]; then
    if archive_integrity_ok "$dst"; then
      return 0
    fi
    log "cached SDK archive is incomplete or corrupt; re-downloading ${dst}"
    rm -f "$dst" "${dst}.tmp"
  fi
  mkdir -p "$(dirname "$dst")"
  if command -v curl >/dev/null 2>&1; then
    curl -fL --retry 3 --connect-timeout 20 -o "${dst}.tmp" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "${dst}.tmp" "$url"
  else
    die "missing required command: curl or wget"
  fi
  mv "${dst}.tmp" "$dst"
  archive_integrity_ok "$dst" || die "downloaded SDK archive failed integrity check: $dst"
}

fetch_index() {
  local url="$1"
  if command -v curl >/dev/null 2>&1; then
    curl -fsL --retry 3 --connect-timeout 20 "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO- "$url"
  else
    die "missing required command: curl or wget"
  fi
}

discover_sdk_url() {
  local release="$1"
  local target="$2"
  local target_url="${base_url}/${release}/targets/${target}/"
  local index
  index="$(fetch_index "$target_url")"
  local name
  name="$(printf '%s\n' "$index" |
    grep -Eo 'openwrt-sdk-[^"<>[:space:]]+Linux-x86_64\.tar\.(xz|zst)' |
    head -n 1 || true)"
  [[ -n "$name" ]] || return 1
  printf '%s%s\n' "$target_url" "$name"
}

archive_dir_name() {
  local archive="$1"
  basename "$archive" | sed -E 's/\.tar\.(xz|zst)$//'
}

archive_integrity_ok() {
  local archive="$1"
  [[ -s "$archive" ]] || return 1
  case "$archive" in
    *.tar.xz|*.tar.zst)
      tar -tf "$archive" >/dev/null 2>&1
      ;;
    *)
      return 1
      ;;
  esac
}

extract_sdk() {
  local archive="$1"
  local sdk_dir="$2"
  if [[ -d "$sdk_dir" ]]; then
    return 0
  fi
  mkdir -p "$sdk_root"
  case "$archive" in
    *.tar.xz)
      tar -C "$sdk_root" -xf "$archive"
      ;;
    *.tar.zst)
      if tar --help 2>/dev/null | grep -q -- '--zstd'; then
        tar --zstd -C "$sdk_root" -xf "$archive"
      else
        need_cmd zstd
        zstd -dc "$archive" | tar -C "$sdk_root" -xf -
      fi
      ;;
    *)
      die "unsupported SDK archive format: $archive"
      ;;
  esac
}

prepare_package() {
  local sdk_dir="$1"
  local pkg_dir="${sdk_dir}/package/trustix-datapath"
  rm -rf "$pkg_dir"
  mkdir -p "${pkg_dir}/src"
  cp "$module_src" "${pkg_dir}/src/trustix_datapath.c"
  cat >"${pkg_dir}/src/Makefile" <<'MAKEFILE'
obj-m += trustix_datapath.o
MAKEFILE
  cat >"${pkg_dir}/Makefile" <<'MAKEFILE'
include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=trustix-datapath
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define KernelPackage/trustix-datapath
  SUBMENU:=Network Support
  TITLE:=TrustIX full plaintext datapath module
  FILES:=$(PKG_BUILD_DIR)/trustix_datapath.ko
endef

define KernelPackage/trustix-datapath/description
  TrustIX full plaintext datapath kernel module.
endef

define Build/Prepare
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(KERNEL_MAKE) M="$(PKG_BUILD_DIR)" modules
endef

$(eval $(call KernelPackage,trustix-datapath))
MAKEFILE
}

find_artifact() {
  local sdk_dir="$1"
  local pattern="$2"
  find "$sdk_dir" -path "$pattern" -type f | sort | tail -n 1
}

kernel_release_from_artifact() {
  local ko="$1"
  local release=""
  if command -v modinfo >/dev/null 2>&1 && [[ -f "$ko" ]]; then
    release="$(modinfo -F vermagic "$ko" 2>/dev/null | awk '{print $1}' || true)"
  fi
  if [[ -z "$release" ]]; then
    release="$(printf '%s\n' "$ko" | sed -nE 's#^.*/lib/modules/([^/]+)/trustix_datapath\.ko$#\1#p')"
  fi
  printf '%s' "$release"
}

write_result() {
  local status="$1"
  local name="$2"
  local release="$3"
  local target="$4"
  local sdk_url="$5"
  local sdk_dir="$6"
  local log_path="$7"
  local ko_path="${8:-}"
  local ipk_path="${9:-}"
  local kernel_release="${10:-}"
  local error="${11:-}"
  local ko_sha=""
  local ipk_sha=""
  [[ -n "$ko_path" && -f "$ko_path" ]] && ko_sha="$(sha256_file "$ko_path")"
  [[ -n "$ipk_path" && -f "$ipk_path" ]] && ipk_sha="$(sha256_file "$ipk_path")"
  printf '{"status":"%s","name":"%s","release":"%s","target":"%s","kernel_release":"%s","sdk_url":"%s","sdk_dir":"%s","log":"%s","ko":"%s","ko_sha256":"%s","ipk":"%s","ipk_sha256":"%s","error":"%s"}\n' \
    "$(json_escape "$status")" \
    "$(json_escape "$name")" \
    "$(json_escape "$release")" \
    "$(json_escape "$target")" \
    "$(json_escape "$kernel_release")" \
    "$(json_escape "$sdk_url")" \
    "$(json_escape "$sdk_dir")" \
    "$(json_escape "$log_path")" \
    "$(json_escape "$ko_path")" \
    "$(json_escape "$ko_sha")" \
    "$(json_escape "$ipk_path")" \
    "$(json_escape "$ipk_sha")" \
    "$(json_escape "$error")" >>"$result_jsonl"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$status" "$name" "$release" "$target" "${kernel_release:-unknown}" "${ko_sha:-}" "$ko_path" "$error" >>"$result_tsv"
}

default_matrix() {
  cat <<'MATRIX'
21.02.7-x86_64|21.02.7|x86/64
21.02.7-arm64|21.02.7|armvirt/64
22.03.7-x86_64|22.03.7|x86/64
22.03.7-arm64|22.03.7|armvirt/64
23.05.5-x86_64|23.05.5|x86/64
23.05.5-arm64|23.05.5|armsr/armv8
24.10.2-x86_64|24.10.2|x86/64
24.10.2-arm64|24.10.2|armsr/armv8
25.12.1-x86_64|25.12.1|x86/64
25.12.1-arm64|25.12.1|armsr/armv8
MATRIX
}

run_one() {
  local name="$1"
  local release="$2"
  local target="$3"
  local sdk_url="${4:-}"
  local target_safe="${target//\//-}"
  local archive
  local sdk_dir
  local log_path="${out_root}/logs/${name}.log"
  local ko_path=""
  local ipk_path=""
  local kernel_release=""
  local error=""

  mkdir -p "${out_root}/logs" "$download_root" "$sdk_root"
  if [[ -z "$sdk_url" ]]; then
    log "discovering SDK for ${name} (${release} ${target})"
    if ! sdk_url="$(discover_sdk_url "$release" "$target")"; then
      error="sdk_not_found"
      write_result failed "$name" "$release" "$target" "" "" "$log_path" "" "" "" "$error"
      log "${name}: SDK not found"
      return 1
    fi
  fi

  archive="${download_root}/$(basename "$sdk_url")"
  sdk_dir="${sdk_root}/$(archive_dir_name "$archive")"
  log "${name}: SDK ${sdk_url}"
  download_file "$sdk_url" "$archive"
  extract_sdk "$archive" "$sdk_dir"
  [[ -d "$sdk_dir" ]] || die "SDK directory missing after extract: $sdk_dir"
  prepare_package "$sdk_dir"

  log "${name}: building kmod-trustix-datapath"
  (
    cd "$sdk_dir"
    make defconfig V="$make_v"
    make package/trustix-datapath/clean V="$make_v"
    make package/trustix-datapath/compile V="$make_v"
  ) >"$log_path" 2>&1 || {
    error="build_failed"
    write_result failed "$name" "$release" "$target" "$sdk_url" "$sdk_dir" "$log_path" "" "" "" "$error"
    log "${name}: build failed; see $log_path"
    return 1
  }

  ko_path="$(find_artifact "$sdk_dir" "*/lib/modules/*/trustix_datapath.ko")"
  ipk_path="$(find_artifact "$sdk_dir" "*/bin/targets/${target}/packages/kmod-trustix-datapath_*.ipk")"
  if [[ -z "$ko_path" || ! -f "$ko_path" ]]; then
    error="ko_missing"
    write_result failed "$name" "$release" "$target" "$sdk_url" "$sdk_dir" "$log_path" "" "$ipk_path" "" "$error"
    log "${name}: build did not produce trustix_datapath.ko"
    return 1
  fi
  kernel_release="$(kernel_release_from_artifact "$ko_path")"
  write_result passed "$name" "$release" "$target" "$sdk_url" "$sdk_dir" "$log_path" "$ko_path" "$ipk_path" "$kernel_release" ""
  log "${name}: passed kernel=${kernel_release:-unknown}"

  if [[ "$keep_sdks" != "1" ]]; then
    rm -rf "$sdk_dir"
  fi
}

main() {
  need_cmd grep
  need_cmd sed
  need_cmd awk
  need_gnu_awk
  need_cmd sha256sum
  [[ -f "$module_src" ]] || die "missing module source: $module_src"
  mkdir -p "$out_root"
  : >"$result_jsonl"
  printf 'status\tname\trelease\ttarget\tkernel_release\tko_sha256\tko\terror\n' >"$result_tsv"

  local failures=0
  local line name release target sdk_url rest
  while IFS= read -r line; do
    line="${line%%#*}"
    [[ -n "${line//[[:space:]]/}" ]] || continue
    name="${line%%|*}"
    rest="${line#*|}"
    release="${rest%%|*}"
    rest="${rest#*|}"
    target="${rest%%|*}"
    if [[ "$rest" == *"|"* ]]; then
      sdk_url="${rest#*|}"
    else
      sdk_url=""
    fi
    if [[ -z "${name:-}" || -z "${release:-}" || -z "${target:-}" ]]; then
      log "skipping invalid matrix entry: $line"
      failures=$((failures + 1))
      continue
    fi
    run_one "$name" "$release" "$target" "${sdk_url:-}" || failures=$((failures + 1))
  done < <(if [[ -n "$matrix_raw" ]]; then printf '%s\n' "$matrix_raw"; else default_matrix; fi)

  log "results: $result_tsv"
  if [[ "$failures" -gt 0 ]]; then
    log "completed with ${failures} failed matrix entries"
    return 1
  fi
}

main "$@"
