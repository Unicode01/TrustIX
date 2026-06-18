#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out_root="${TRUSTIX_OPENWRT_KMOD_MATRIX_OUT:-${repo_root}/build/openwrt-kmod-matrix}"
download_root="${TRUSTIX_OPENWRT_KMOD_MATRIX_DOWNLOADS:-${out_root}/downloads}"
sdk_root="${TRUSTIX_OPENWRT_KMOD_MATRIX_SDKS:-${out_root}/sdks}"
result_jsonl="${TRUSTIX_OPENWRT_KMOD_MATRIX_JSONL:-${out_root}/results.jsonl}"
result_tsv="${TRUSTIX_OPENWRT_KMOD_MATRIX_TSV:-${out_root}/results.tsv}"
if [[ -n "${TRUSTIX_OPENWRT_DOWNLOAD_BASES:-}" ]]; then
  base_urls="${TRUSTIX_OPENWRT_DOWNLOAD_BASES}"
elif [[ -n "${TRUSTIX_OPENWRT_DOWNLOAD_BASE:-}" ]]; then
  base_urls="${TRUSTIX_OPENWRT_DOWNLOAD_BASE}"
else
  base_urls="https://mirrors.tuna.tsinghua.edu.cn/openwrt/releases https://mirrors.ustc.edu.cn/openwrt/releases https://mirrors.aliyun.com/openwrt/releases https://downloads.openwrt.org/releases"
fi
matrix_raw="${TRUSTIX_OPENWRT_KMOD_MATRIX:-}"
keep_sdks="${TRUSTIX_OPENWRT_KMOD_MATRIX_KEEP_SDKS:-1}"
make_v="${V:-s}"
export TERM="${TERM:-xterm}"

modules_raw="${TRUSTIX_OPENWRT_KMOD_MATRIX_MODULES:-datapath}"
crypto_mode="${TRUSTIX_OPENWRT_KMOD_MATRIX_CRYPTO_MODE:-${TRUSTIX_CRYPTO_BUILD_MODE:-auto}}"
helpers_mode="${TRUSTIX_OPENWRT_KMOD_MATRIX_HELPERS_MODE:-${TRUSTIX_DATAPATH_HELPERS_BUILD_MODE:-auto}}"
crypto_src="${TRUSTIX_OPENWRT_KMOD_MATRIX_CRYPTO_C:-${repo_root}/kernel/trustix_crypto/trustix_crypto.c}"
datapath_src="${TRUSTIX_OPENWRT_KMOD_MATRIX_DATAPATH_C:-${repo_root}/kernel/trustix_datapath/trustix_datapath.c}"
helpers_src_dir="${TRUSTIX_OPENWRT_KMOD_MATRIX_HELPERS_DIR:-${repo_root}/kernel/trustix_datapath_helpers}"

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

discover_sdk_url_from_base() {
  local base_url="$1"
  local release="$2"
  local target="$3"
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

discover_sdk_url() {
  local release="$1"
  local target="$2"
  local base_url
  for base_url in $base_urls; do
    [[ -n "$base_url" ]] || continue
    if discover_sdk_url_from_base "$base_url" "$release" "$target"; then
      return 0
    fi
  done
  return 1
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

sdk_kernel_patchver() {
  local sdk_dir="$1"
  local kernel_file
  kernel_file="$(find "${sdk_dir}/include" -maxdepth 1 -type f -name 'kernel-[0-9]*' 2>/dev/null | sort -V | tail -n 1 || true)"
  [[ -n "$kernel_file" ]] || return 0
  basename "$kernel_file" | sed -E 's/^kernel-//'
}

kernel_patchver_major() {
  local patchver="$1"
  patchver="${patchver%%[^0-9.]*}"
  patchver="${patchver%%.*}"
  printf '%s' "$patchver"
}

sdk_supports_bpf_kfunc_modules() {
  local patchver="$1"
  local major
  major="$(kernel_patchver_major "$patchver")"
  [[ -n "$major" ]] || return 1
  [[ "$major" -ge 6 ]]
}

prepare_package() {
  local sdk_dir="$1"
  local name="$2"
  local effective_crypto_mode="${3:-$crypto_mode}"
  local effective_helpers_mode="${4:-$helpers_mode}"
  local pkg_dir="${sdk_dir}/package/trustix-kmods"
  local variant_manifest="${out_root}/variants/${name}.tsv"
  rm -rf "$pkg_dir"
  mkdir -p "${pkg_dir}/src/crypto" "${pkg_dir}/src/datapath" "${pkg_dir}/src/datapath_helpers"
  cp "$crypto_src" "${pkg_dir}/src/crypto/trustix_crypto.c"
  cp "$datapath_src" "${pkg_dir}/src/datapath/trustix_datapath.c"
  cp "${helpers_src_dir}/trustix_datapath_helpers_main.c" "${pkg_dir}/src/datapath_helpers/trustix_datapath_helpers_main.c"
  cp "${helpers_src_dir}/trustix_datapath_helpers_kfuncs.c" "${pkg_dir}/src/datapath_helpers/trustix_datapath_helpers_kfuncs.c"
  cp "${helpers_src_dir}/trustix_datapath_helpers_internal.h" "${pkg_dir}/src/datapath_helpers/trustix_datapath_helpers_internal.h"
  cat >"${pkg_dir}/src/crypto/Makefile" <<'MAKEFILE'
obj-m += trustix_crypto.o
ifeq ($(DEVICE_ONLY),1)
ccflags-y += -DTRUSTIX_DEVICE_ONLY=1
endif
MAKEFILE
  cat >"${pkg_dir}/src/datapath/Makefile" <<'MAKEFILE'
obj-m += trustix_datapath.o
MAKEFILE
  cat >"${pkg_dir}/src/datapath_helpers/Makefile" <<'MAKEFILE'
obj-m += trustix_datapath_helpers.o
ifeq ($(BASIC),1)
trustix_datapath_helpers-y := trustix_datapath_helpers_main.o
ccflags-y += -DTRUSTIX_DATAPATH_HELPERS_BASIC=1
else
trustix_datapath_helpers-y := trustix_datapath_helpers_main.o trustix_datapath_helpers_kfuncs.o
endif
MAKEFILE
  cat >"${pkg_dir}/trustix-build-modes.mk" <<MAKEFILE
TRUSTIX_CRYPTO_MODE:=${effective_crypto_mode}
TRUSTIX_HELPERS_MODE:=${effective_helpers_mode}
TRUSTIX_VARIANT_MANIFEST:=${variant_manifest}
MAKEFILE
  cat >"${pkg_dir}/Makefile" <<'MAKEFILE'
TRUSTIX_KMOD_PACKAGE_DIR:=$(dir $(lastword $(MAKEFILE_LIST)))
include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk
include $(TRUSTIX_KMOD_PACKAGE_DIR)/trustix-build-modes.mk

PKG_NAME:=trustix-kmods
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define KernelPackage/trustix-crypto
  SUBMENU:=Network Support
  TITLE:=TrustIX crypto module
  FILES:=$(PKG_BUILD_DIR)/crypto/trustix_crypto.ko
  DEPENDS:=+kmod-crypto-gcm +kmod-crypto-aead
endef

define KernelPackage/trustix-crypto/description
  TrustIX kernel crypto module.
endef

define KernelPackage/trustix-datapath
  SUBMENU:=Network Support
  TITLE:=TrustIX full plaintext datapath module
  FILES:=$(PKG_BUILD_DIR)/datapath/trustix_datapath.ko
endef

define KernelPackage/trustix-datapath/description
  TrustIX full plaintext datapath kernel module.
endef

define KernelPackage/trustix-datapath-helpers
  SUBMENU:=Network Support
  TITLE:=TrustIX datapath helper module
  FILES:=$(PKG_BUILD_DIR)/datapath_helpers/trustix_datapath_helpers.ko
  DEPENDS:=+kmod-trustix-crypto
endef

define KernelPackage/trustix-datapath-helpers/description
  TrustIX datapath helper kfunc module.
endef

define Build/Prepare
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	mkdir -p "$(dir $(TRUSTIX_VARIANT_MANIFEST))"
	rm -f "$(TRUSTIX_VARIANT_MANIFEST)"
	case "$(TRUSTIX_CRYPTO_MODE)" in \
		full) \
			$(KERNEL_MAKE) M="$(PKG_BUILD_DIR)/crypto" modules && printf 'crypto\tfull\n' >>"$(TRUSTIX_VARIANT_MANIFEST)";; \
		device-only) \
			$(KERNEL_MAKE) M="$(PKG_BUILD_DIR)/crypto" DEVICE_ONLY=1 modules && printf 'crypto\tdevice-only\n' >>"$(TRUSTIX_VARIANT_MANIFEST)";; \
		auto) \
			($(KERNEL_MAKE) M="$(PKG_BUILD_DIR)/crypto" modules && printf 'crypto\tfull\n' >>"$(TRUSTIX_VARIANT_MANIFEST)") || { \
				$(KERNEL_MAKE) M="$(PKG_BUILD_DIR)/crypto" clean; \
				$(KERNEL_MAKE) M="$(PKG_BUILD_DIR)/crypto" DEVICE_ONLY=1 modules && printf 'crypto\tdevice-only\n' >>"$(TRUSTIX_VARIANT_MANIFEST)"; \
			};; \
		*) echo "invalid TRUSTIX_CRYPTO_MODE=$(TRUSTIX_CRYPTO_MODE)" >&2; exit 2;; \
	esac
	$(KERNEL_MAKE) M="$(PKG_BUILD_DIR)/datapath" modules
	printf 'datapath\tfull\n' >>"$(TRUSTIX_VARIANT_MANIFEST)"
	case "$(TRUSTIX_HELPERS_MODE)" in \
		full) \
			$(KERNEL_MAKE) M="$(PKG_BUILD_DIR)/datapath_helpers" KBUILD_EXTRA_SYMBOLS="$(PKG_BUILD_DIR)/crypto/Module.symvers" modules && printf 'helpers\tfull\n' >>"$(TRUSTIX_VARIANT_MANIFEST)";; \
		basic) \
			$(KERNEL_MAKE) M="$(PKG_BUILD_DIR)/datapath_helpers" KBUILD_EXTRA_SYMBOLS="$(PKG_BUILD_DIR)/crypto/Module.symvers" BASIC=1 modules && printf 'helpers\tbasic\n' >>"$(TRUSTIX_VARIANT_MANIFEST)";; \
		auto) \
			($(KERNEL_MAKE) M="$(PKG_BUILD_DIR)/datapath_helpers" KBUILD_EXTRA_SYMBOLS="$(PKG_BUILD_DIR)/crypto/Module.symvers" modules && printf 'helpers\tfull\n' >>"$(TRUSTIX_VARIANT_MANIFEST)") || { \
				$(KERNEL_MAKE) M="$(PKG_BUILD_DIR)/datapath_helpers" KBUILD_EXTRA_SYMBOLS="$(PKG_BUILD_DIR)/crypto/Module.symvers" clean; \
				$(KERNEL_MAKE) M="$(PKG_BUILD_DIR)/datapath_helpers" KBUILD_EXTRA_SYMBOLS="$(PKG_BUILD_DIR)/crypto/Module.symvers" BASIC=1 modules && printf 'helpers\tbasic\n' >>"$(TRUSTIX_VARIANT_MANIFEST)"; \
			};; \
		*) echo "invalid TRUSTIX_HELPERS_MODE=$(TRUSTIX_HELPERS_MODE)" >&2; exit 2;; \
	esac
endef

$(eval $(call KernelPackage,trustix-crypto))
$(eval $(call KernelPackage,trustix-datapath))
$(eval $(call KernelPackage,trustix-datapath-helpers))
MAKEFILE
}

module_enabled() {
  local want="$1"
  local token
  local modules_spaced="${modules_raw//,/ }"
  for token in $modules_spaced; do
    token="${token//[[:space:]]/}"
    case "$token" in
      all) return 0 ;;
      crypto|trustix_crypto)
        [[ "$want" == "crypto" ]] && return 0
        ;;
      datapath|trustix_datapath)
        [[ "$want" == "datapath" ]] && return 0
        ;;
      helpers|datapath_helpers|trustix_datapath_helpers)
        [[ "$want" == "helpers" ]] && return 0
        ;;
    esac
  done
  return 1
}

find_artifact() {
  local sdk_dir="$1"
  local pattern="$2"
  find "$sdk_dir" -path "$pattern" -type f | sort | tail -n 1
}

module_variants_from_manifest() {
  local manifest="$1"
  [[ -r "$manifest" ]] || return 0
  awk 'NF >= 2 { if (out != "") out = out ","; out = out $1 "=" $2 } END { print out }' "$manifest"
}

kernel_release_from_artifact() {
  local ko="$1"
  local release=""
  if command -v modinfo >/dev/null 2>&1 && [[ -f "$ko" ]]; then
    release="$(modinfo -F vermagic "$ko" 2>/dev/null | awk '{print $1}' || true)"
  fi
  if [[ -z "$release" ]]; then
    release="$(printf '%s\n' "$ko" | sed -nE 's#^.*/lib/modules/([^/]+)/trustix_(crypto|datapath|datapath_helpers)\.ko$#\1#p')"
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
  local variant="${12:-}"
  local module_variants="${13:-}"
  local ko_sha=""
  local ipk_sha=""
  [[ -n "$ko_path" && -f "$ko_path" ]] && ko_sha="$(sha256_file "$ko_path")"
  [[ -n "$ipk_path" && -f "$ipk_path" ]] && ipk_sha="$(sha256_file "$ipk_path")"
  printf '{"status":"%s","name":"%s","release":"%s","target":"%s","kernel_release":"%s","variant":"%s","module_variants":"%s","sdk_url":"%s","sdk_dir":"%s","log":"%s","ko":"%s","ko_sha256":"%s","ipk":"%s","ipk_sha256":"%s","error":"%s"}\n' \
    "$(json_escape "$status")" \
    "$(json_escape "$name")" \
    "$(json_escape "$release")" \
    "$(json_escape "$target")" \
    "$(json_escape "$kernel_release")" \
    "$(json_escape "$variant")" \
    "$(json_escape "$module_variants")" \
    "$(json_escape "$sdk_url")" \
    "$(json_escape "$sdk_dir")" \
    "$(json_escape "$log_path")" \
    "$(json_escape "$ko_path")" \
    "$(json_escape "$ko_sha")" \
    "$(json_escape "$ipk_path")" \
    "$(json_escape "$ipk_sha")" \
    "$(json_escape "$error")" >>"$result_jsonl"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$status" "$name" "$release" "$target" "${kernel_release:-unknown}" "${variant:-unknown}" "${module_variants:-}" "${ko_sha:-}" "$ko_path" "$error" >>"$result_tsv"
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
  local variant=""
  local module_variants=""
  local error=""
  local kernel_patchver=""
  local effective_crypto_mode="$crypto_mode"
  local effective_helpers_mode="$helpers_mode"

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
  kernel_patchver="$(sdk_kernel_patchver "$sdk_dir")"
  if ! sdk_supports_bpf_kfunc_modules "$kernel_patchver"; then
    if [[ "$effective_crypto_mode" == "auto" ]]; then
      effective_crypto_mode="device-only"
    fi
    if [[ "$effective_helpers_mode" == "auto" ]]; then
      effective_helpers_mode="basic"
    fi
    log "${name}: kernel ${kernel_patchver:-unknown} does not support TrustIX BPF kfunc modules; using crypto=${effective_crypto_mode} helpers=${effective_helpers_mode}"
  fi
  prepare_package "$sdk_dir" "$name" "$effective_crypto_mode" "$effective_helpers_mode"

  log "${name}: building TrustIX kmods (${modules_raw})"
  (
    cd "$sdk_dir"
    make defconfig V="$make_v"
    make package/trustix-kmods/clean V="$make_v"
    make package/trustix-kmods/compile V="$make_v"
  ) >"$log_path" 2>&1 || {
    error="build_failed"
    write_result failed "$name" "$release" "$target" "$sdk_url" "$sdk_dir" "$log_path" "" "" "" "$error"
    log "${name}: build failed; see $log_path"
    return 1
  }

  ko_path="$(find_artifact "$sdk_dir" "*/lib/modules/*/trustix_datapath.ko")"
  if ! module_enabled datapath; then
    if module_enabled crypto; then
      ko_path="$(find_artifact "$sdk_dir" "*/lib/modules/*/trustix_crypto.ko")"
    elif module_enabled helpers; then
      ko_path="$(find_artifact "$sdk_dir" "*/lib/modules/*/trustix_datapath_helpers.ko")"
    fi
  fi
  ipk_path="$(find_artifact "$sdk_dir" "*/bin/targets/${target}/packages/kmod-trustix-datapath_*.ipk")"
  if [[ -z "$ko_path" || ! -f "$ko_path" ]]; then
    error="ko_missing"
    write_result failed "$name" "$release" "$target" "$sdk_url" "$sdk_dir" "$log_path" "" "$ipk_path" "" "$error"
    log "${name}: build did not produce trustix_datapath.ko"
    return 1
  fi
  kernel_release="$(kernel_release_from_artifact "$ko_path")"
  module_variants="$(module_variants_from_manifest "${out_root}/variants/${name}.tsv")"
  case "$ko_path" in
    *trustix_crypto.ko) variant="$(printf '%s\n' "$module_variants" | tr ',' '\n' | sed -n 's/^crypto=//p')" ;;
    *trustix_datapath_helpers.ko) variant="$(printf '%s\n' "$module_variants" | tr ',' '\n' | sed -n 's/^helpers=//p')" ;;
    *trustix_datapath.ko) variant="$(printf '%s\n' "$module_variants" | tr ',' '\n' | sed -n 's/^datapath=//p')" ;;
  esac
  write_result passed "$name" "$release" "$target" "$sdk_url" "$sdk_dir" "$log_path" "$ko_path" "$ipk_path" "$kernel_release" "" "$variant" "$module_variants"
  log "${name}: passed kernel=${kernel_release:-unknown} variant=${variant:-unknown} modules=${module_variants:-unknown}"

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
  [[ -f "$crypto_src" ]] || die "missing module source: $crypto_src"
  [[ -f "$datapath_src" ]] || die "missing module source: $datapath_src"
  [[ -f "${helpers_src_dir}/trustix_datapath_helpers_main.c" ]] || die "missing module source: ${helpers_src_dir}/trustix_datapath_helpers_main.c"
  [[ -f "${helpers_src_dir}/trustix_datapath_helpers_kfuncs.c" ]] || die "missing module source: ${helpers_src_dir}/trustix_datapath_helpers_kfuncs.c"
  mkdir -p "$out_root"
  : >"$result_jsonl"
  printf 'status\tname\trelease\ttarget\tkernel_release\tvariant\tmodule_variants\tko_sha256\tko\terror\n' >"$result_tsv"

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
