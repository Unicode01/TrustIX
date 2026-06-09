#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ]; then
  echo "ERROR: scripts/trustix-update.sh requires GNU bash 4+" >&2
  exit 2
fi
set -Eeuo pipefail

script_repo_root() {
  local source_path="${BASH_SOURCE[0]:-}"
  if [[ -n "$source_path" && -f "$source_path" ]]; then
    local candidate
    candidate="$(cd "$(dirname "$source_path")/.." && pwd)"
    if [[ -f "${candidate}/go.mod" && -d "${candidate}/scripts" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  fi
  return 1
}

usage() {
  cat <<'EOF'
usage: scripts/trustix-update.sh [options]

Updates an existing TrustIX systemd/OpenWrt installation without rewriting config,
certificates, or data directories.

Package input:
  --release-url URL         download a TrustIX release tarball
  --tarball PATH            use a local TrustIX release tarball

Source-build input, used when no release tarball is provided:
  --repo URL                git repo (default: https://github.com/Unicode01/TrustIX.git)
  --ref REF                 git ref/branch/tag (default: main)
  --work-dir DIR            staging/build work dir
  --goarch ARCH             build target arch: amd64, arm64, arm (default: host)
  --kdir DIR                target kernel build dir for .ko build
  --build-bpf 0|1           rebuild embedded eBPF objects (default: 1)
  --build-ko auto|0|1       build/embed kernel modules (default: auto)
  --build-webui             run npm WebUI check/build before release build

Install/restart:
  --instance NAME           trustixd@NAME instance to restart; repeatable
  --service-manager MODE    auto, systemd, or openwrt (default: auto)
  --no-restart              install only; do not restart service instances
  --prefix DIR              install prefix (default: /usr/local, OpenWrt: /opt/trustix)
  --bindir DIR              binary dir (default: PREFIX/bin)
  --unitdir DIR             systemd unit dir (default: /etc/systemd/system)
  --initdir DIR             OpenWrt init dir (default: /etc/init.d)
  --sysconfdir DIR          config dir for OpenWrt instance detection (default: /etc/trustix)
  --docdir DIR              docs dir (default: /usr/share/doc/trustix)
  --backup-dir DIR          backup dir (default: /var/backups/trustix/update-TIMESTAMP)
  --no-backup               do not copy old binaries/unit before replacing
  --no-sudo                 run install commands without sudo
  --json                    print machine-readable summary
  -h, --help                show this help

Examples:
  curl -fsSL https://raw.githubusercontent.com/Unicode01/TrustIX/main/scripts/trustix-update.sh | \
    sudo bash -s -- --release-url https://github.com/Unicode01/TrustIX/releases/download/v0.1.0/trustix-linux-amd64.tar.gz

  curl -fsSL https://raw.githubusercontent.com/Unicode01/TrustIX/main/scripts/trustix-update.sh | \
    sudo bash -s -- --repo https://github.com/Unicode01/TrustIX.git --ref main --build-ko auto

Environment:
  TRUSTIX_UPDATE_MIRRORS=0 disables GitHub mirror fallbacks.
  TRUSTIX_UPDATE_GITHUB_MIRRORS="https://proxy/" overrides GitHub mirrors.
EOF
}

log() {
  printf '[trustix-update] %s\n' "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

json_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  printf '%s' "$value"
}

shell_quote() {
  local value="$1"
  printf "'%s'" "${value//\'/\'\\\'\'}"
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

lower_ascii() {
  local value="$1"
  printf '%s' "${value,,}"
}

normalize_goarch() {
  case "${1:-}" in
    amd64|x86_64) printf 'amd64\n' ;;
    arm64|aarch64) printf 'arm64\n' ;;
    arm|armv6l|armv7l|armhf) printf 'arm\n' ;;
    *) printf '%s\n' "$1" ;;
  esac
}

host_goarch() {
  normalize_goarch "$(uname -m)"
}

run_root() {
  if [[ -n "$sudo_cmd" && "${EUID:-$(id -u)}" != "0" ]]; then
    command -v "$sudo_cmd" >/dev/null 2>&1 || die "${sudo_cmd} is required for non-root install commands; rerun as root or pass --no-sudo"
    "$sudo_cmd" "$@"
  else
    "$@"
  fi
}

wait_systemd_unit_active() {
  local unit="$1"
  local state=""
  local result=""
  local exec_status=""
  local restarts=""
  local baseline_restarts=""
  local i
  for i in {1..10}; do
    state="$(run_root systemctl is-active "$unit" 2>/dev/null || true)"
    case "$state" in
      active) break ;;
      failed) break ;;
    esac
    result="$(run_root systemctl show "$unit" --property=Result --value 2>/dev/null || true)"
    exec_status="$(run_root systemctl show "$unit" --property=ExecMainStatus --value 2>/dev/null || true)"
    if [[ -n "$result" && "$result" != "success" && "$result" != "exit-code" ]]; then
      break
    fi
    if [[ "${exec_status:-0}" != "0" ]]; then
      break
    fi
    sleep 1
  done
  if [[ "$state" == "active" ]]; then
    baseline_restarts="$(run_root systemctl show "$unit" --property=NRestarts --value 2>/dev/null || true)"
    for i in {1..5}; do
      sleep 1
      state="$(run_root systemctl is-active "$unit" 2>/dev/null || true)"
      result="$(run_root systemctl show "$unit" --property=Result --value 2>/dev/null || true)"
      exec_status="$(run_root systemctl show "$unit" --property=ExecMainStatus --value 2>/dev/null || true)"
      restarts="$(run_root systemctl show "$unit" --property=NRestarts --value 2>/dev/null || true)"
      if [[ "$state" != "active" ]]; then
        break
      fi
      if [[ -n "$baseline_restarts" && -n "$restarts" && "$restarts" != "$baseline_restarts" ]]; then
        break
      fi
      if [[ "${exec_status:-0}" != "0" ]]; then
        break
      fi
    done
    if [[ "$state" == "active" && ( -z "$baseline_restarts" || -z "$restarts" || "$restarts" == "$baseline_restarts" ) && "${exec_status:-0}" == "0" ]]; then
      return 0
    fi
  fi
  run_root systemctl show "$unit" --property=ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,NRestarts >&2 || true
  run_root systemctl --no-pager --full status "$unit" >&2 || true
  run_root journalctl -u "$unit" --no-pager -n 80 >&2 || true
  run_root systemctl stop "$unit" >/dev/null 2>&1 || true
  die "systemd unit did not stay active: ${unit} (state=${state:-unknown}, result=${result:-unknown}, exec_status=${exec_status:-unknown}, restarts=${restarts:-unknown}, baseline_restarts=${baseline_restarts:-unknown})"
}

copy_file_with_mode() {
  local src="$1"
  local dst="$2"
  local mode="$3"
  local dir="${dst%/*}"
  [[ "$dir" != "$dst" ]] && run_root mkdir -p "$dir"
  if command -v install >/dev/null 2>&1; then
    run_root install -m "$mode" "$src" "$dst"
  else
    run_root cp "$src" "$dst"
    run_root chmod "$mode" "$dst"
  fi
}

detect_service_manager() {
  if [[ "$service_manager" != "auto" ]]; then
    printf '%s\n' "$service_manager"
    return
  fi
  if [[ -f /etc/openwrt_release && ( -x /sbin/procd || -d /etc/init.d ) ]]; then
    printf 'openwrt\n'
    return
  fi
  if command -v systemctl >/dev/null 2>&1 || [[ -d /run/systemd/system ]]; then
    printf 'systemd\n'
    return
  fi
  die "could not auto-detect service manager; pass --service-manager systemd|openwrt or --no-restart"
}

apply_target_defaults() {
  service_manager="$(detect_service_manager)"
  if [[ -z "$prefix" ]]; then
    case "$service_manager" in
      openwrt) prefix="/opt/trustix" ;;
      *) prefix="/usr/local" ;;
    esac
  fi
  if [[ -z "$bindir" ]]; then
    bindir="${prefix}/bin"
  fi
  if [[ -z "$unitdir" ]]; then
    unitdir="/etc/systemd/system"
  fi
  if [[ -z "$initdir" ]]; then
    initdir="/etc/init.d"
  fi
  if [[ -z "$sysconfdir" ]]; then
    sysconfdir="/etc/trustix"
  fi
}

download_file() {
  local url="$1"
  local out="$2"
  local candidate
  local -a candidates=()
  if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    die "curl or wget is required to download release tarballs"
  fi
  mapfile -t candidates < <(github_url_candidates "$url")
  for candidate in "${candidates[@]}"; do
    [[ -n "$candidate" ]] || continue
    rm -f "$out"
    log "download ${candidate}"
    if command -v curl >/dev/null 2>&1 && curl -fsSL --connect-timeout 8 "$candidate" -o "$out"; then
      return 0
    fi
    if command -v wget >/dev/null 2>&1 && wget -T 12 -qO "$out" "$candidate"; then
      return 0
    fi
  done
  rm -f "$out"
  return 1
}

mirrors_enabled() {
  case "${TRUSTIX_UPDATE_MIRRORS:-${TRUSTIX_BOOTSTRAP_MIRRORS:-auto}}" in
    0|false|no|off|disabled) return 1 ;;
    *) return 0 ;;
  esac
}

github_url_candidates() {
  local url="$1"
  local mirror mirrors
  printf '%s\n' "$url"
  mirrors_enabled || return 0
  case "$url" in
    https://github.com/*|https://raw.githubusercontent.com/*) ;;
    *) return 0 ;;
  esac
  mirrors="${TRUSTIX_UPDATE_GITHUB_MIRRORS:-${TRUSTIX_BOOTSTRAP_GITHUB_MIRRORS:-https://ghproxy.net/ https://gh-proxy.com/ https://ghfast.top/ https://gh.ddlc.top/ https://gh.llkk.cc/ https://mirror.ghproxy.com/}}"
  for mirror in $mirrors; do
    [[ -n "$mirror" ]] || continue
    printf '%s%s\n' "${mirror%/}/" "$url"
  done
}

extract_source_archive() {
  local archive_path="$1"
  local dest="$2"
  local stage archive_root candidate
  stage="$(mktemp -d /tmp/trustix-update-src.XXXXXX)"
  if ! tar -xzf "$archive_path" -C "$stage"; then
    rm -rf "$stage"
    return 1
  fi
  archive_root=""
  for candidate in "$stage"/*; do
    if [[ -d "$candidate" ]]; then
      archive_root="$candidate"
      break
    fi
  done
  if [[ -z "$archive_root" ]]; then
    rm -rf "$stage"
    return 1
  fi
  rm -rf "$dest"
  mkdir -p "$dest"
  if ! cp -R "$archive_root"/. "$dest"/; then
    rm -rf "$stage"
    return 1
  fi
  rm -rf "$stage"
}

repo_root="$(script_repo_root || true)"
repo_url="${TRUSTIX_UPDATE_REPO:-https://github.com/Unicode01/TrustIX.git}"
repo_ref="${TRUSTIX_UPDATE_REF:-main}"
release_url="${TRUSTIX_UPDATE_RELEASE_URL:-}"
tarball="${TRUSTIX_UPDATE_TARBALL:-}"
work_dir="${TRUSTIX_UPDATE_WORKDIR:-}"
goarch="$(normalize_goarch "${GOARCH:-$(host_goarch)}")"
kdir="${KDIR:-}"
build_bpf="${TRUSTIX_UPDATE_BUILD_BPF:-1}"
build_ko="${TRUSTIX_UPDATE_BUILD_KO:-auto}"
build_webui=0
instances=()
restart=1
service_manager="${TRUSTIX_UPDATE_SERVICE_MANAGER:-auto}"
prefix="${TRUSTIX_UPDATE_PREFIX:-}"
bindir="${TRUSTIX_UPDATE_BINDIR:-}"
unitdir="${TRUSTIX_UPDATE_UNITDIR:-}"
initdir="${TRUSTIX_UPDATE_INITDIR:-}"
sysconfdir="${TRUSTIX_UPDATE_SYSCONFDIR:-}"
docdir="${TRUSTIX_UPDATE_DOCDIR:-/usr/share/doc/trustix}"
backup_dir="${TRUSTIX_UPDATE_BACKUP_DIR:-}"
backup=1
sudo_cmd="${TRUSTIX_UPDATE_SUDO:-sudo}"
json=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --release-url) [[ $# -ge 2 ]] || die "--release-url requires a value"; release_url="$2"; shift 2 ;;
    --tarball) [[ $# -ge 2 ]] || die "--tarball requires a value"; tarball="$2"; shift 2 ;;
    --repo) [[ $# -ge 2 ]] || die "--repo requires a value"; repo_url="$2"; shift 2 ;;
    --ref) [[ $# -ge 2 ]] || die "--ref requires a value"; repo_ref="$2"; shift 2 ;;
    --work-dir) [[ $# -ge 2 ]] || die "--work-dir requires a value"; work_dir="$2"; shift 2 ;;
    --goarch) [[ $# -ge 2 ]] || die "--goarch requires a value"; goarch="$(normalize_goarch "$2")"; shift 2 ;;
    --kdir) [[ $# -ge 2 ]] || die "--kdir requires a value"; kdir="$2"; shift 2 ;;
    --build-bpf) [[ $# -ge 2 ]] || die "--build-bpf requires a value"; build_bpf="$2"; shift 2 ;;
    --build-ko) [[ $# -ge 2 ]] || die "--build-ko requires a value"; build_ko="$2"; shift 2 ;;
    --build-webui) build_webui=1; shift ;;
    --instance) [[ $# -ge 2 ]] || die "--instance requires a value"; instances+=("$2"); shift 2 ;;
    --service-manager) [[ $# -ge 2 ]] || die "--service-manager requires a value"; service_manager="$2"; shift 2 ;;
    --no-restart) restart=0; shift ;;
    --prefix) [[ $# -ge 2 ]] || die "--prefix requires a value"; prefix="$2"; shift 2 ;;
    --bindir) [[ $# -ge 2 ]] || die "--bindir requires a value"; bindir="$2"; shift 2 ;;
    --unitdir) [[ $# -ge 2 ]] || die "--unitdir requires a value"; unitdir="$2"; shift 2 ;;
    --initdir) [[ $# -ge 2 ]] || die "--initdir requires a value"; initdir="$2"; shift 2 ;;
    --sysconfdir) [[ $# -ge 2 ]] || die "--sysconfdir requires a value"; sysconfdir="$2"; shift 2 ;;
    --docdir) [[ $# -ge 2 ]] || die "--docdir requires a value"; docdir="$2"; shift 2 ;;
    --backup-dir) [[ $# -ge 2 ]] || die "--backup-dir requires a value"; backup_dir="$2"; shift 2 ;;
    --no-backup) backup=0; shift ;;
    --no-sudo) sudo_cmd=""; shift ;;
    --json) json=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ "$(uname -s)" == "Linux" ]] || die "update script must run on Linux"
service_manager="$(lower_ascii "$service_manager")"
case "$service_manager" in
  auto|systemd|openwrt) ;;
  *) die "--service-manager must be auto, systemd, or openwrt" ;;
esac
case "$build_bpf" in 0|1) ;; *) die "--build-bpf must be 0 or 1" ;; esac
case "$build_ko" in auto|0|1) ;; *) die "--build-ko must be auto, 0, or 1" ;; esac
case "$build_webui" in 0|1) ;; *) die "--build-webui must be 0 or 1" ;; esac
if [[ -n "$release_url" && -n "$tarball" ]]; then
  die "--release-url and --tarball are mutually exclusive"
fi
apply_target_defaults
if [[ -z "$work_dir" ]]; then
  work_dir="$(mktemp -d /tmp/trustix-update.XXXXXX)"
else
  mkdir -p "$work_dir"
fi
if [[ -z "$backup_dir" ]]; then
  backup_dir="/var/backups/trustix/update-$(date -u +%Y%m%dT%H%M%SZ)"
fi
if [[ "${EUID:-$(id -u)}" == "0" && -z "${TRUSTIX_UPDATE_SUDO+x}" ]]; then
  sudo_cmd=""
fi

ensure_source_repo() {
  if [[ -n "$repo_root" && -f "${repo_root}/go.mod" ]]; then
    return
  fi
  repo_root="${work_dir}/src"
  if [[ ! -f "${repo_root}/go.mod" ]]; then
    local cloned=0
    if command -v git >/dev/null 2>&1; then
      log "clone ${repo_url}#${repo_ref}"
      if git clone --depth 1 --branch "$repo_ref" "$repo_url" "$repo_root" >&2; then
        cloned=1
      else
        log "git clone failed, trying GitHub archive mirrors"
        rm -rf "$repo_root"
        mkdir -p "$repo_root"
      fi
    fi
    if [[ "$cloned" != "1" && "$repo_url" == https://github.com/* ]]; then
      need_cmd tar
      local archive_url archive_path
      archive_url="${repo_url%.git}/archive/${repo_ref}.tar.gz"
      archive_path="${work_dir}/src.tar.gz"
      download_file "$archive_url" "$archive_path"
      extract_source_archive "$archive_path" "$repo_root"
      cloned=1
    fi
    if [[ "$cloned" != "1" ]]; then
      die "git is required to clone ${repo_url}; alternatively use a GitHub repo URL with curl/wget+tar available"
    fi
  fi
}

build_source_tarball() {
  ensure_source_repo
  local out="${work_dir}/release"
  local name="trustix-linux-${goarch}"
  local args=(--out "$out" --name "$name" --goarch "$goarch" --build-bpf "$build_bpf" --build-ko "$build_ko" --build-tests 0)
  if [[ "$build_webui" == "0" ]]; then
    args+=(--skip-webui)
  fi
  if [[ -n "$kdir" ]]; then
    args+=(--kdir "$kdir")
  fi
  log "build release from source"
  bash "${repo_root}/scripts/trustix-build.sh" "${args[@]}"
  tarball="${out}/${name}.tar.gz"
  [[ -f "$tarball" ]] || die "release tarball was not created: $tarball"
}

prepare_tarball() {
  if [[ -n "$release_url" ]]; then
    tarball="${work_dir}/package.tar.gz"
    download_file "$release_url" "$tarball"
  elif [[ -z "$tarball" ]]; then
    build_source_tarball
  fi
  [[ -f "$tarball" ]] || die "tarball not found: $tarball"
}

extract_package() {
  need_cmd tar
  local package_dir="${work_dir}/package"
  rm -rf "$package_dir"
  mkdir -p "$package_dir"
  tar -xzf "$tarball" -C "$package_dir"
  [[ -f "${package_dir}/bin/trustixd" ]] || die "package is missing bin/trustixd"
  [[ -f "${package_dir}/bin/trustixctl" ]] || die "package is missing bin/trustixctl"
  [[ -f "${package_dir}/bin/trustix-ca" ]] || die "package is missing bin/trustix-ca"
  printf '%s\n' "$package_dir"
}

backup_path() {
  local path="$1"
  local rel="${path#/}"
  printf '%s/%s\n' "$backup_dir" "$rel"
}

backup_file_if_present() {
  local path="$1"
  [[ "$backup" == "1" ]] || return 0
  [[ -e "$path" ]] || return 0
  local dst
  dst="$(backup_path "$path")"
  copy_file_with_mode "$path" "$dst" 0644
}

install_binary() {
  local src="$1"
  local dst="${bindir}/$(basename "$src")"
  local tmp="${dst}.trustix-update.$$"
  backup_file_if_present "$dst"
  run_root mkdir -p "$bindir"
  copy_file_with_mode "$src" "$tmp" 0755
  run_root mv -f "$tmp" "$dst"
}

install_regular_file() {
  local src="$1"
  local dst="$2"
  local mode="$3"
  local tmp="${dst}.trustix-update.$$"
  backup_file_if_present "$dst"
  copy_file_with_mode "$src" "$tmp" "$mode"
  run_root mv -f "$tmp" "$dst"
}

install_package() {
  local package_dir="$1"
  local name
  for name in trustixd trustixctl trustix-ca trustix-device trustix-iptunnel-smoke; do
    if [[ -f "${package_dir}/bin/${name}" ]]; then
      log "install ${name}"
      install_binary "${package_dir}/bin/${name}"
    fi
  done
  if [[ -f "${package_dir}/packaging/systemd/trustixd@.service" ]]; then
    if [[ "$service_manager" == "systemd" ]]; then
      log "install systemd unit"
      install_regular_file "${package_dir}/packaging/systemd/trustixd@.service" "${unitdir}/trustixd@.service" 0644
    fi
  fi
  if [[ "$service_manager" == "openwrt" ]]; then
    if [[ -f "${package_dir}/packaging/openwrt/trustix.init" ]]; then
      log "install OpenWrt init script"
      install_regular_file "${package_dir}/packaging/openwrt/trustix.init" "${initdir}/trustix" 0755
    else
      die "package is missing packaging/openwrt/trustix.init"
    fi
  fi
  if [[ -d "${package_dir}/docs" ]]; then
    run_root mkdir -p "$docdir"
    if command -v rsync >/dev/null 2>&1; then
      run_root rsync -a --delete "${package_dir}/docs/" "${docdir}/"
    else
      run_root cp -R "${package_dir}/docs/." "$docdir/"
    fi
  fi
}

detect_instances() {
  [[ ${#instances[@]} -eq 0 ]] || return 0
  if [[ "$service_manager" == "openwrt" ]]; then
    local env_file name
    for env_file in "${sysconfdir}"/*.env; do
      [[ -f "$env_file" ]] || continue
      name="$(basename "$env_file")"
      name="${name%.env}"
      [[ -n "$name" ]] && instances+=("$name")
    done
    return 0
  fi
  command -v systemctl >/dev/null 2>&1 || return 0
  local units unit name
  units="$(systemctl list-units --full --all --plain --no-legend 'trustixd@*.service' 2>/dev/null || true)"
  while IFS= read -r unit; do
    [[ -n "$unit" ]] || continue
    unit="${unit%% *}"
    [[ "$unit" == trustixd@*.service ]] || continue
    name="${unit#trustixd@}"
    name="${name%.service}"
    [[ -n "$name" ]] && instances+=("$name")
  done <<<"$units"
}

restart_instances() {
  [[ "$restart" == "1" ]] || return 0
  detect_instances
  case "$service_manager" in
    systemd)
      command -v systemctl >/dev/null 2>&1 || die "systemctl not found; rerun with --no-restart"
      run_root systemctl daemon-reload
      if [[ ${#instances[@]} -eq 0 ]]; then
        log "no trustixd@*.service instance detected; installed binaries only"
        return 0
      fi
      local instance
      for instance in "${instances[@]}"; do
        log "restart trustixd@${instance}.service"
        run_root systemctl restart "trustixd@${instance}.service"
        wait_systemd_unit_active "trustixd@${instance}.service"
      done
      ;;
    openwrt)
      [[ -x "${initdir}/trustix" ]] || die "OpenWrt init script not found: ${initdir}/trustix"
      if [[ ${#instances[@]} -eq 0 ]]; then
        log "no ${sysconfdir}/*.env instance detected; installed binaries only"
        return 0
      fi
      local instance
      for instance in "${instances[@]}"; do
        log "restart trustix:${instance}"
        run_root "${initdir}/trustix" restart "$instance"
      done
      ;;
  esac
}

package_dir=""
prepare_tarball
package_dir="$(extract_package)"
install_package "$package_dir"
restart_instances

if [[ "$json" == "1" ]]; then
  printf '{'
  printf '"tarball":"%s",' "$(json_escape "$tarball")"
  printf '"service_manager":"%s",' "$(json_escape "$service_manager")"
  printf '"bindir":"%s",' "$(json_escape "$bindir")"
  if [[ "$service_manager" == "openwrt" ]]; then
    printf '"init":"%s",' "$(json_escape "${initdir}/trustix")"
  else
    printf '"unit":"%s",' "$(json_escape "${unitdir}/trustixd@.service")"
  fi
  printf '"backup_dir":"%s",' "$(json_escape "$backup_dir")"
  printf '"restarted":['
  first=1
  for instance in "${instances[@]}"; do
    if [[ "$first" == "0" ]]; then printf ','; fi
    first=0
    if [[ "$service_manager" == "openwrt" ]]; then
      printf '"trustix:%s"' "$(json_escape "$instance")"
    else
      printf '"trustixd@%s.service"' "$(json_escape "$instance")"
    fi
  done
  printf ']'
  printf '}\n'
else
  log "update complete"
  if [[ "$backup" == "1" ]]; then
    log "backup: ${backup_dir}"
  fi
fi
