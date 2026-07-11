#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ]; then
  echo "ERROR: scripts/trustix-prereqs.sh requires GNU bash 4+" >&2
  exit 2
fi

trustix_prereqs_log() {
  printf '[trustix-prereqs] %s\n' "$*" >&2
}

trustix_prereqs_lower_ascii() {
  local value="$1"
  printf '%s' "${value,,}"
}

trustix_prereqs_install_enabled() {
  case "$(trustix_prereqs_lower_ascii "${TRUSTIX_BOOTSTRAP_INSTALL_DEPS:-auto}")" in
    0|false|no|off|disabled) return 1 ;;
    *) return 0 ;;
  esac
}

trustix_prereqs_run_root() {
  if [[ "${EUID:-$(id -u)}" == "0" ]]; then
    "$@"
    return
  fi
  if command -v sudo >/dev/null 2>&1; then
    sudo "$@"
    return
  fi
  return 1
}

trustix_prereqs_package_manager() {
  local candidate
  for candidate in apt-get dnf yum zypper apk pacman opkg; do
    if command -v "$candidate" >/dev/null 2>&1; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

trustix_prereqs_required_go_version() {
  local version=""
  if [[ -n "${TRUSTIX_BOOTSTRAP_GO_VERSION:-}" ]]; then
    version="$TRUSTIX_BOOTSTRAP_GO_VERSION"
  elif [[ -n "${TRUSTIX_REPO_ROOT:-}" && -f "${TRUSTIX_REPO_ROOT}/go.mod" ]]; then
    local key value
    while read -r key value _; do
      if [[ "$key" == "go" && -n "$value" ]]; then
        version="$value"
        break
      fi
    done <"${TRUSTIX_REPO_ROOT}/go.mod"
  fi
  [[ -n "$version" ]] || version="1.25.12"
  case "$version" in
    *.*.*) ;;
    *.*) version="${version}.0" ;;
  esac
  printf '%s\n' "$version"
}

trustix_prereqs_go_version_at_least() {
  local actual="${1#go}"
  local required="${2#go}"
  local actual_major actual_minor actual_patch
  local required_major required_minor required_patch

  [[ "$actual" =~ ^([0-9]+)[.]([0-9]+)([.]([0-9]+))?$ ]] || return 1
  actual_major="${BASH_REMATCH[1]}"
  actual_minor="${BASH_REMATCH[2]}"
  actual_patch="${BASH_REMATCH[4]:-0}"
  [[ "$required" =~ ^([0-9]+)[.]([0-9]+)([.]([0-9]+))?$ ]] || return 1
  required_major="${BASH_REMATCH[1]}"
  required_minor="${BASH_REMATCH[2]}"
  required_patch="${BASH_REMATCH[4]:-0}"

  if (( 10#$actual_major != 10#$required_major )); then
    (( 10#$actual_major > 10#$required_major ))
    return
  fi
  if (( 10#$actual_minor != 10#$required_minor )); then
    (( 10#$actual_minor > 10#$required_minor ))
    return
  fi
  (( 10#$actual_patch >= 10#$required_patch ))
}

trustix_prereqs_go_bootstrap_ok() {
  command -v go >/dev/null 2>&1 || return 1
  local raw version required
  raw="$(go env GOVERSION 2>/dev/null || true)"
  if [[ -z "$raw" ]]; then
    raw="$(go version 2>/dev/null || true)"
    raw="${raw#* go}"
    raw="${raw%% *}"
  fi
  version="${raw#go}"
  required="$(trustix_prereqs_required_go_version)"
  trustix_prereqs_go_version_at_least "$version" "$required"
}

trustix_prereqs_go_arch() {
  case "$(uname -m)" in
    x86_64|amd64) printf 'amd64\n' ;;
    aarch64|arm64) printf 'arm64\n' ;;
    armv6l|armv7l|armhf|arm) printf 'armv6l\n' ;;
    i386|i686) printf '386\n' ;;
    riscv64) printf 'riscv64\n' ;;
    ppc64le) printf 'ppc64le\n' ;;
    s390x) printf 's390x\n' ;;
    *) return 1 ;;
  esac
}

trustix_prereqs_mirrors_enabled() {
  case "${TRUSTIX_BOOTSTRAP_MIRRORS:-auto}" in
    0|false|no|off|disabled) return 1 ;;
    *) return 0 ;;
  esac
}

trustix_prereqs_go_url_candidates() {
  local version="$1"
  local arch="$2"
  if [[ -n "${TRUSTIX_BOOTSTRAP_GO_URL:-}" ]]; then
    printf '%s\n' "$TRUSTIX_BOOTSTRAP_GO_URL"
    return
  fi
  printf '%s\n' "https://go.dev/dl/go${version}.linux-${arch}.tar.gz"
  trustix_prereqs_mirrors_enabled || return 0
  printf '%s\n' "https://golang.google.cn/dl/go${version}.linux-${arch}.tar.gz"
  printf '%s\n' "https://mirrors.aliyun.com/golang/go${version}.linux-${arch}.tar.gz"
  printf '%s\n' "https://mirrors.ustc.edu.cn/golang/go${version}.linux-${arch}.tar.gz"
  printf '%s\n' "https://mirrors.tuna.tsinghua.edu.cn/golang/go${version}.linux-${arch}.tar.gz"
}

trustix_prereqs_download_file() {
  local out="$1"
  shift
  local url
  local connect_timeout="${TRUSTIX_BOOTSTRAP_CONNECT_TIMEOUT:-8}"
  local download_timeout="${TRUSTIX_BOOTSTRAP_DOWNLOAD_TIMEOUT:-600}"
  local stall_timeout="${TRUSTIX_BOOTSTRAP_STALL_TIMEOUT:-20}"
  local min_speed="${TRUSTIX_BOOTSTRAP_MIN_DOWNLOAD_SPEED:-1024}"
  case "$connect_timeout" in *[!0-9]*|"") connect_timeout=8 ;; esac
  case "$download_timeout" in *[!0-9]*|"") download_timeout=600 ;; esac
  case "$stall_timeout" in *[!0-9]*|"") stall_timeout=20 ;; esac
  case "$min_speed" in *[!0-9]*|"") min_speed=1024 ;; esac
  for url in "$@"; do
    [[ -n "$url" ]] || continue
    rm -f "$out"
    trustix_prereqs_log "download ${url}"
    if command -v curl >/dev/null 2>&1 && curl -fsSL \
      --connect-timeout "$connect_timeout" \
      --max-time "$download_timeout" \
      --speed-time "$stall_timeout" \
      --speed-limit "$min_speed" \
      "$url" -o "$out"; then
      return 0
    fi
    if command -v wget >/dev/null 2>&1 && wget -T "$stall_timeout" -qO "$out" "$url"; then
      return 0
    fi
  done
  rm -f "$out"
  return 1
}

trustix_prereqs_install_official_go() {
  local version arch tmp stage install_root install_dir
  local -a go_urls=()
  version="$(trustix_prereqs_required_go_version)"
  arch="$(trustix_prereqs_go_arch)" || return 1
  install_root="${TRUSTIX_BOOTSTRAP_GO_ROOT:-/usr/local/trustix-go}"
  install_dir="${install_root}/go${version}"
  tmp="$(mktemp /tmp/trustix-go.XXXXXX 2>/dev/null || mktemp -t trustix-go.XXXXXX 2>/dev/null || true)"
  if [[ -z "$tmp" ]]; then
    tmp="${TMPDIR:-/tmp}/trustix-go.$$"
    rm -f "$tmp"
    : >"$tmp" || return 1
  fi
  stage="$(mktemp -d /tmp/trustix-go.XXXXXX 2>/dev/null || mktemp -d -t trustix-go.XXXXXX 2>/dev/null || true)"
  if [[ -z "$stage" ]]; then
    stage="${TMPDIR:-/tmp}/trustix-go-stage.$$"
    rm -rf "$stage"
    mkdir -p "$stage" || {
      rm -f "$tmp"
      return 1
    }
  fi

  trustix_prereqs_log "install Go ${version}"
  if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    trustix_prereqs_ensure_commands curl || return 1
  fi
  if ! command -v tar >/dev/null 2>&1; then
    trustix_prereqs_ensure_commands tar gzip || return 1
  fi
  mapfile -t go_urls < <(trustix_prereqs_go_url_candidates "$version" "$arch")
  trustix_prereqs_download_file "$tmp" "${go_urls[@]}" || {
    rm -rf "$tmp" "$stage"
    return 1
  }
  tar -xzf "$tmp" -C "$stage" || {
    rm -rf "$tmp" "$stage"
    return 1
  }
  trustix_prereqs_run_root mkdir -p "$install_root" /usr/local/bin || {
    rm -rf "$tmp" "$stage"
    return 1
  }
  trustix_prereqs_run_root rm -rf "$install_dir"
  trustix_prereqs_run_root mv "${stage}/go" "$install_dir" || {
    rm -rf "$tmp" "$stage"
    return 1
  }
  trustix_prereqs_run_root ln -sf "${install_dir}/bin/go" /usr/local/bin/go
  trustix_prereqs_run_root ln -sf "${install_dir}/bin/gofmt" /usr/local/bin/gofmt
  rm -rf "$tmp" "$stage"
  export PATH="/usr/local/bin:${PATH}"
  hash -r 2>/dev/null || true
}

trustix_prereqs_add_unique() {
  local name="$1"
  shift
  local existing
  [[ -n "$name" ]] || return 0
  for existing in "$@"; do
    [[ "$existing" == "$name" ]] && return 1
  done
  printf '%s\n' "$name"
}

trustix_prereqs_packages_for() {
  local manager="$1"
  local command_name="$2"
  case "$manager:$command_name" in
    apt-get:base) printf '%s\n' ca-certificates ;;
    apt-get:go) printf '%s\n' golang-go ;;
    apt-get:git) printf '%s\n' git ;;
    apt-get:curl) printf '%s\n' curl ;;
    apt-get:clang) printf '%s\n' clang llvm ;;
    apt-get:make) printf '%s\n' make ;;
    apt-get:gcc) printf '%s\n' gcc libc6-dev ;;
    apt-get:npm) printf '%s\n' npm ;;
    apt-get:pahole) printf '%s\n' dwarves ;;
    apt-get:install|apt-get:realpath|apt-get:sha256sum|apt-get:stat) printf '%s\n' coreutils ;;
    apt-get:tar) printf '%s\n' tar ;;
    apt-get:gzip) printf '%s\n' gzip ;;

    dnf:base|yum:base|zypper:base) printf '%s\n' ca-certificates ;;
    dnf:go|yum:go) printf '%s\n' golang ;;
    zypper:go) printf '%s\n' go ;;
    dnf:git|yum:git|zypper:git) printf '%s\n' git ;;
    dnf:curl|yum:curl|zypper:curl) printf '%s\n' curl ;;
    dnf:clang|yum:clang|zypper:clang) printf '%s\n' clang llvm ;;
    dnf:make|yum:make|zypper:make) printf '%s\n' make ;;
    dnf:gcc|yum:gcc|zypper:gcc) printf '%s\n' gcc glibc-devel ;;
    dnf:npm|yum:npm|zypper:npm) printf '%s\n' npm ;;
    dnf:pahole|yum:pahole|zypper:pahole) printf '%s\n' dwarves ;;
    dnf:install|dnf:realpath|dnf:sha256sum|dnf:stat|yum:install|yum:realpath|yum:sha256sum|yum:stat|zypper:install|zypper:realpath|zypper:sha256sum|zypper:stat) printf '%s\n' coreutils ;;
    dnf:tar|yum:tar|zypper:tar) printf '%s\n' tar ;;
    dnf:gzip|yum:gzip|zypper:gzip) printf '%s\n' gzip ;;

    apk:base) printf '%s\n' ca-certificates ;;
    apk:go) printf '%s\n' go ;;
    apk:git) printf '%s\n' git ;;
    apk:curl) printf '%s\n' curl ;;
    apk:clang) printf '%s\n' clang llvm ;;
    apk:make) printf '%s\n' make ;;
    apk:gcc) printf '%s\n' gcc musl-dev ;;
    apk:npm) printf '%s\n' npm ;;
    apk:pahole) printf '%s\n' pahole ;;
    apk:install|apk:realpath|apk:sha256sum|apk:stat) printf '%s\n' coreutils ;;
    apk:tar) printf '%s\n' tar ;;
    apk:gzip) printf '%s\n' gzip ;;

    pacman:base) printf '%s\n' ca-certificates ;;
    pacman:go) printf '%s\n' go ;;
    pacman:git) printf '%s\n' git ;;
    pacman:curl) printf '%s\n' curl ;;
    pacman:clang) printf '%s\n' clang llvm ;;
    pacman:make) printf '%s\n' make ;;
    pacman:gcc) printf '%s\n' gcc glibc ;;
    pacman:npm) printf '%s\n' npm ;;
    pacman:pahole) printf '%s\n' pahole ;;
    pacman:install|pacman:realpath|pacman:sha256sum|pacman:stat) printf '%s\n' coreutils ;;
    pacman:tar) printf '%s\n' tar ;;
    pacman:gzip) printf '%s\n' gzip ;;

    opkg:base) printf '%s\n' ca-bundle ca-certificates ;;
    opkg:go) ;;
    opkg:git) printf '%s\n' git git-http ;;
    opkg:curl) printf '%s\n' curl ;;
    opkg:clang) printf '%s\n' clang llvm ;;
    opkg:make) printf '%s\n' make ;;
    opkg:gcc) printf '%s\n' gcc ;;
    opkg:npm) printf '%s\n' node-npm npm ;;
    opkg:pahole) printf '%s\n' pahole ;;
    opkg:install) printf '%s\n' coreutils-install coreutils ;;
    opkg:realpath) printf '%s\n' coreutils-realpath coreutils ;;
    opkg:sha256sum) printf '%s\n' coreutils-sha256sum coreutils ;;
    opkg:stat) printf '%s\n' coreutils-stat coreutils ;;
    opkg:tar) printf '%s\n' tar ;;
    opkg:gzip) printf '%s\n' gzip ;;
  esac
}

trustix_prereqs_install_packages() {
  local manager="$1"
  shift
  local -a packages=()
  local package added
  for package in "$@"; do
    added="$(trustix_prereqs_add_unique "$package" "${packages[@]}" || true)"
    [[ -n "$added" ]] && packages+=("$added")
  done
  [[ ${#packages[@]} -gt 0 ]] || return 0

  trustix_prereqs_log "install packages with ${manager}: ${packages[*]}"
  case "$manager" in
    apt-get)
      trustix_prereqs_run_root apt-get update
      trustix_prereqs_run_root env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${packages[@]}"
      ;;
    dnf)
      trustix_prereqs_run_root dnf install -y "${packages[@]}"
      ;;
    yum)
      trustix_prereqs_run_root yum install -y "${packages[@]}"
      ;;
    zypper)
      trustix_prereqs_run_root zypper --non-interactive install --no-recommends "${packages[@]}"
      ;;
    apk)
      trustix_prereqs_run_root apk add --no-cache "${packages[@]}"
      ;;
    pacman)
      trustix_prereqs_run_root pacman -Sy --noconfirm --needed "${packages[@]}"
      ;;
    opkg)
      trustix_prereqs_run_root opkg update
      trustix_prereqs_run_root opkg install "${packages[@]}"
      ;;
    *)
      return 1
      ;;
  esac
}

trustix_prereqs_coreutils_need_package() {
  if command -v realpath >/dev/null 2>&1 && ! realpath --relative-to / / >/dev/null 2>&1; then
    printf '%s\n' realpath
  fi
  if command -v stat >/dev/null 2>&1 && ! stat -c %s "$0" >/dev/null 2>&1; then
    printf '%s\n' stat
  fi
}

trustix_prereqs_ensure_commands() {
  local -a requested=("$@")
  local -a missing=()
  local -a packages=()
  local manager command_name package coreutils_command added

  for command_name in "${requested[@]}"; do
    if [[ "$command_name" == "go" ]]; then
      if ! trustix_prereqs_go_bootstrap_ok; then
        missing+=("$command_name")
      fi
    elif ! command -v "$command_name" >/dev/null 2>&1; then
      missing+=("$command_name")
    fi
  done
  while IFS= read -r coreutils_command; do
    [[ -n "$coreutils_command" ]] && missing+=("$coreutils_command")
  done < <(trustix_prereqs_coreutils_need_package)

  [[ ${#missing[@]} -gt 0 ]] || return 0
  trustix_prereqs_log "missing build commands: ${missing[*]}"
  trustix_prereqs_install_enabled || return 1
  manager="$(trustix_prereqs_package_manager)" || return 1

  while IFS= read -r package; do
    added="$(trustix_prereqs_add_unique "$package" "${packages[@]}" || true)"
    [[ -n "$added" ]] && packages+=("$added")
  done < <(trustix_prereqs_packages_for "$manager" base)

  for command_name in "${missing[@]}"; do
    while IFS= read -r package; do
      added="$(trustix_prereqs_add_unique "$package" "${packages[@]}" || true)"
      [[ -n "$added" ]] && packages+=("$added")
    done < <(trustix_prereqs_packages_for "$manager" "$command_name")
  done

  trustix_prereqs_install_packages "$manager" "${packages[@]}" || return 1
  hash -r 2>/dev/null || true

  local needs_go=0
  for command_name in "${requested[@]}"; do
    [[ "$command_name" == "go" ]] && needs_go=1
  done
  if [[ "$needs_go" == "1" ]] && ! trustix_prereqs_go_bootstrap_ok; then
    trustix_prereqs_install_official_go || return 1
  fi

  local -a still_missing=()
  for command_name in "${requested[@]}"; do
    if [[ "$command_name" == "go" ]]; then
      if ! trustix_prereqs_go_bootstrap_ok; then
        still_missing+=("$command_name")
      fi
    elif ! command -v "$command_name" >/dev/null 2>&1; then
      still_missing+=("$command_name")
    fi
  done
  if [[ ${#still_missing[@]} -gt 0 ]]; then
    trustix_prereqs_log "commands still missing after package install: ${still_missing[*]}"
    return 1
  fi
}

trustix_prereqs_ensure_ca_deps() {
  trustix_prereqs_ensure_commands git go
}

trustix_prereqs_ensure_network_deps() {
  trustix_prereqs_ensure_commands curl
}

trustix_prereqs_ensure_openwrt_dataplane_runtime_deps() {
  local manager
  manager="$(trustix_prereqs_package_manager 2>/dev/null || true)"
  [[ "$manager" == "opkg" ]] || return 0
  [[ -f /etc/openwrt_release ]] || return 0
  trustix_prereqs_install_enabled || return 1

  # TrustIX attaches sched_cls BPF programs directly through netlink. Minimal
  # OpenWrt images often have clsact but not the BPF classifier module, which
  # makes TC attach fail with ENOENT and prevents the fast path from loading.
  trustix_prereqs_install_packages opkg \
    ca-bundle ca-certificates \
    kmod-sched-core kmod-sched kmod-sched-bpf kmod-veth \
    ip-full tc-bpf
}

trustix_prereqs_ensure_source_build_deps() {
  trustix_prereqs_ensure_commands git go clang make gcc install realpath sha256sum stat tar gzip
}

trustix_prereqs_ensure_kernel_module_build_deps() {
  trustix_prereqs_ensure_commands make gcc install realpath sha256sum stat pahole
}

trustix_prereqs_kernel_release_for_kdir() {
  local kdir="$1"
  kdir="${kdir%/}"
  case "$kdir" in
    /lib/modules/*/build|/lib/modules/*/source)
      basename "$(dirname "$kdir")"
      return
      ;;
  esac
  uname -r
}

trustix_prereqs_kernel_header_hint() {
  local kdir="$1"
  local release
  release="$(trustix_prereqs_kernel_release_for_kdir "$kdir")"
  case "$release" in
    *-pve)
      trustix_prereqs_log "install matching Proxmox headers, for example: apt-get update && apt-get install -y proxmox-headers-${release}"
      trustix_prereqs_log "older Proxmox repositories may use: apt-get install -y pve-headers-${release}"
      ;;
    *)
      trustix_prereqs_log "install matching kernel headers for ${release}; Debian/Ubuntu example: apt-get update && apt-get install -y linux-headers-${release}"
      ;;
  esac
}

trustix_prereqs_apt_kernel_header_meta() {
  case "$(uname -m)" in
    x86_64|amd64) printf '%s\n' linux-headers-amd64 ;;
    aarch64|arm64) printf '%s\n' linux-headers-arm64 ;;
    armv7l|armv6l|armhf|arm) printf '%s\n' linux-headers-armmp ;;
  esac
}

trustix_prereqs_kernel_header_packages_for() {
  local manager="$1"
  local release="$2"
  case "$manager" in
    apt-get)
      if [[ "$release" == *-pve ]]; then
        printf '%s\n' \
          "proxmox-headers-${release}" \
          "pve-headers-${release}" \
          "linux-headers-${release}" \
          proxmox-default-headers \
          pve-headers
      else
        printf '%s\n' "linux-headers-${release}"
        trustix_prereqs_apt_kernel_header_meta
      fi
      ;;
    dnf|yum)
      printf '%s\n' "kernel-devel-${release}" kernel-devel
      ;;
    zypper)
      printf '%s\n' kernel-default-devel kernel-devel
      ;;
    apk)
      printf '%s\n' linux-headers
      ;;
    pacman)
      printf '%s\n' linux-headers linux-lts-headers
      ;;
  esac
}

trustix_prereqs_ensure_kernel_build_dir() {
  local kdir="${1:-/lib/modules/$(uname -r)/build}"
  [[ -d "$kdir" ]] && return 0

  local release manager package attempted=0
  release="$(trustix_prereqs_kernel_release_for_kdir "$kdir")"
  trustix_prereqs_log "kernel build directory missing: ${kdir}"

  if ! trustix_prereqs_install_enabled; then
    trustix_prereqs_log "automatic dependency installation is disabled by TRUSTIX_BOOTSTRAP_INSTALL_DEPS"
    trustix_prereqs_kernel_header_hint "$kdir"
    return 1
  fi

  manager="$(trustix_prereqs_package_manager)" || {
    trustix_prereqs_log "could not detect a supported package manager for kernel headers"
    trustix_prereqs_kernel_header_hint "$kdir"
    return 1
  }

  if [[ "$manager" == "opkg" ]]; then
    trustix_prereqs_log "opkg targets normally need kernel modules built with the matching OpenWrt SDK, not on-device headers"
    trustix_prereqs_kernel_header_hint "$kdir"
    return 1
  fi

  while IFS= read -r package; do
    [[ -n "$package" ]] || continue
    attempted=1
    trustix_prereqs_log "try kernel header package for ${release}: ${package}"
    if trustix_prereqs_install_packages "$manager" "$package"; then
      hash -r 2>/dev/null || true
      if [[ -d "$kdir" ]]; then
        trustix_prereqs_log "kernel build directory is available: ${kdir}"
        return 0
      fi
      trustix_prereqs_log "installed ${package}, but ${kdir} is still missing"
    fi
  done < <(trustix_prereqs_kernel_header_packages_for "$manager" "$release")

  if [[ "$attempted" == "0" ]]; then
    trustix_prereqs_log "no known kernel header package mapping for package manager: ${manager}"
  fi
  if [[ -d "$kdir" ]]; then
    trustix_prereqs_log "kernel build directory is available: ${kdir}"
    return 0
  fi
  trustix_prereqs_log "could not install matching kernel headers for ${release}"
  trustix_prereqs_kernel_header_hint "$kdir"
  return 1
}

trustix_prereqs_ensure_webui_deps() {
  trustix_prereqs_ensure_commands npm
}
