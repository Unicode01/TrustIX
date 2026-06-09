#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ]; then
  echo "ERROR: scripts/trustix-prereqs.sh requires GNU bash 4+" >&2
  exit 2
fi

trustix_prereqs_log() {
  printf '[trustix-prereqs] %s\n' "$*" >&2
}

trustix_prereqs_install_enabled() {
  case "$(printf '%s' "${TRUSTIX_BOOTSTRAP_INSTALL_DEPS:-auto}" | tr '[:upper:]' '[:lower:]')" in
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
  [[ -n "$version" ]] || version="1.25.0"
  case "$version" in
    *.*.*) ;;
    *.*) version="${version}.0" ;;
  esac
  printf '%s\n' "$version"
}

trustix_prereqs_go_bootstrap_ok() {
  command -v go >/dev/null 2>&1 || return 1
  local raw version major rest minor
  raw="$(go env GOVERSION 2>/dev/null || true)"
  if [[ -z "$raw" ]]; then
    raw="$(go version 2>/dev/null || true)"
    raw="${raw#* go}"
    raw="${raw%% *}"
  fi
  version="${raw#go}"
  major="${version%%.*}"
  rest="${version#*.}"
  minor="${rest%%.*}"
  [[ "$major" =~ ^[0-9]+$ && "$minor" =~ ^[0-9]+$ ]] || return 1
  if (( major > 1 )); then
    return 0
  fi
  (( major == 1 && minor >= 21 ))
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

trustix_prereqs_install_official_go() {
  local version arch url tmp stage install_root install_dir
  version="$(trustix_prereqs_required_go_version)"
  arch="$(trustix_prereqs_go_arch)" || return 1
  url="${TRUSTIX_BOOTSTRAP_GO_URL:-https://go.dev/dl/go${version}.linux-${arch}.tar.gz}"
  install_root="${TRUSTIX_BOOTSTRAP_GO_ROOT:-/usr/local/trustix-go}"
  install_dir="${install_root}/go${version}"
  tmp="$(mktemp /tmp/trustix-go.XXXXXX.tar.gz)"
  stage="$(mktemp -d /tmp/trustix-go.XXXXXX)"

  trustix_prereqs_log "install Go ${version} from ${url}"
  if ! command -v curl >/dev/null 2>&1; then
    trustix_prereqs_ensure_commands curl || return 1
  fi
  if ! command -v tar >/dev/null 2>&1; then
    trustix_prereqs_ensure_commands tar gzip || return 1
  fi
  curl -fsSL "$url" -o "$tmp" || {
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
    pacman:install|pacman:realpath|pacman:sha256sum|pacman:stat) printf '%s\n' coreutils ;;
    pacman:tar) printf '%s\n' tar ;;
    pacman:gzip) printf '%s\n' gzip ;;

    opkg:base) printf '%s\n' ca-bundle ca-certificates ;;
    opkg:go) printf '%s\n' go golang ;;
    opkg:git) printf '%s\n' git git-http ;;
    opkg:curl) printf '%s\n' curl ;;
    opkg:clang) printf '%s\n' clang llvm ;;
    opkg:make) printf '%s\n' make ;;
    opkg:gcc) printf '%s\n' gcc ;;
    opkg:npm) printf '%s\n' node-npm npm ;;
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

trustix_prereqs_ensure_source_build_deps() {
  trustix_prereqs_ensure_commands git go clang make gcc install realpath sha256sum stat tar gzip
}

trustix_prereqs_ensure_webui_deps() {
  trustix_prereqs_ensure_commands npm
}
