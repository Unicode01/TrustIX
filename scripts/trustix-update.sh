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
certificates, or data directories. Every discovered instance is checked with the
candidate trustixd before files are replaced. Failed restarts are rolled back.

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
  --libexecdir DIR          helper script dir (default: PREFIX/libexec/trustix)
  --unitdir DIR             systemd unit dir (default: /etc/systemd/system)
  --initdir DIR             OpenWrt init dir (default: /etc/init.d)
  --sysconfdir DIR          config dir for OpenWrt instance detection (default: /etc/trustix)
  --docdir DIR              docs dir (default: /usr/share/doc/trustix)
  --backup-dir DIR          backup dir (default: /var/backups/trustix/update-TIMESTAMP)
  --no-backup               do not keep a persistent backup (temporary rollback snapshot remains enabled)
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
    if [[ "$state" == "active" && "${exec_status:-0}" == "0" ]]; then
      if [[ -z "$baseline_restarts" || -z "$restarts" || "$restarts" == "$baseline_restarts" ]]; then
        return 0
      fi
    fi
  fi
  run_root systemctl show "$unit" --property=ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,NRestarts >&2 || true
  run_root systemctl --no-pager --full status "$unit" >&2 || true
  run_root journalctl -u "$unit" --no-pager -n 80 >&2 || true
  log "ERROR: systemd unit did not stay active: ${unit} (state=${state:-unknown}, result=${result:-unknown}, exec_status=${exec_status:-unknown}, restarts=${restarts:-unknown}, baseline_restarts=${baseline_restarts:-unknown})"
  return 1
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
  if [[ -z "$libexecdir" ]]; then
    libexecdir="${prefix}/libexec/trustix"
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
work_dir_owned=0
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
libexecdir="${TRUSTIX_UPDATE_LIBEXECDIR:-}"
unitdir="${TRUSTIX_UPDATE_UNITDIR:-}"
initdir="${TRUSTIX_UPDATE_INITDIR:-}"
sysconfdir="${TRUSTIX_UPDATE_SYSCONFDIR:-}"
docdir="${TRUSTIX_UPDATE_DOCDIR:-/usr/share/doc/trustix}"
backup_dir="${TRUSTIX_UPDATE_BACKUP_DIR:-}"
backup=1
sudo_cmd="${TRUSTIX_UPDATE_SUDO:-sudo}"
json=0
configured_instances=()
preflight_instances=()
restarted_instances=()
declare -A configured_instance_seen=()
declare -A preflight_instance_seen=()
transaction_started=0
transaction_committed=0
transaction_rolling_back=0
rollback_failed=0
services_touched=0
transaction_paths=()
transaction_modes=()
transaction_existed=()
transaction_snapshots=()

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
    --libexecdir) [[ $# -ge 2 ]] || die "--libexecdir requires a value"; libexecdir="$2"; shift 2 ;;
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
  work_dir_owned=1
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
  local mode="$2"
  [[ "$backup" == "1" ]] || return 0
  [[ -e "$path" ]] || return 0
  local dst
  dst="$(backup_path "$path")"
  copy_file_with_mode "$path" "$dst" "$mode"
}

install_binary() {
  local src="$1"
  local dst="${bindir}/$(basename "$src")"
  local tmp="${dst}.trustix-update.$$"
  backup_file_if_present "$dst" 0755
  run_root mkdir -p "$bindir"
  copy_file_with_mode "$src" "$tmp" 0755
  run_root mv -f "$tmp" "$dst"
}

install_regular_file() {
  local src="$1"
  local dst="$2"
  local mode="$3"
  local tmp="${dst}.trustix-update.$$"
  backup_file_if_present "$dst" "$mode"
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
  if [[ -f "${package_dir}/scripts/trustix-backup.sh" ]]; then
    log "install encrypted backup helper"
    install_regular_file "${package_dir}/scripts/trustix-backup.sh" "${libexecdir}/trustix-backup.sh" 0755
  fi
  if [[ -f "${package_dir}/packaging/systemd/trustixd@.service" ]]; then
    if [[ "$service_manager" == "systemd" ]]; then
      log "install systemd unit"
      install_regular_file "${package_dir}/packaging/systemd/trustixd@.service" "${unitdir}/trustixd@.service" 0644
    fi
  fi
  if [[ "$service_manager" == "systemd" ]]; then
    if [[ -f "${package_dir}/packaging/systemd/trustix-backup@.service" ]]; then
      install_regular_file "${package_dir}/packaging/systemd/trustix-backup@.service" "${unitdir}/trustix-backup@.service" 0644
    fi
    if [[ -f "${package_dir}/packaging/systemd/trustix-backup@.timer" ]]; then
      install_regular_file "${package_dir}/packaging/systemd/trustix-backup@.timer" "${unitdir}/trustix-backup@.timer" 0644
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
}

install_docs() {
  local package_dir="$1"
  [[ -d "${package_dir}/docs" ]] || return 0
  run_root mkdir -p "$docdir"
  if command -v rsync >/dev/null 2>&1; then
    run_root rsync -a --delete "${package_dir}/docs/" "${docdir}/"
  else
    run_root cp -R "${package_dir}/docs/." "$docdir/"
  fi
}

add_configured_instance() {
  local name="$1"
  [[ -n "$name" ]] || return 0
  if [[ -z "${configured_instance_seen[$name]+x}" ]]; then
    configured_instance_seen["$name"]=1
    configured_instances+=("$name")
  fi
}

add_preflight_instance() {
  local name="$1"
  [[ -n "$name" ]] || return 0
  if [[ -z "${preflight_instance_seen[$name]+x}" ]]; then
    preflight_instance_seen["$name"]=1
    preflight_instances+=("$name")
  fi
}

discover_instances() {
  local env_file name units unit
  for env_file in "${sysconfdir}"/*.env; do
    [[ -f "$env_file" ]] || continue
    name="$(basename "$env_file")"
    add_configured_instance "${name%.env}"
  done
  if [[ "$service_manager" == "systemd" ]] && command -v systemctl >/dev/null 2>&1; then
    units="$(systemctl list-units --full --all --plain --no-legend 'trustixd@*.service' 2>/dev/null || true)"
    units+=$'\n'
    units+="$(systemctl list-unit-files --full --no-legend 'trustixd@*.service' 2>/dev/null || true)"
  else
    units=""
  fi
  while IFS= read -r unit; do
    [[ -n "$unit" ]] || continue
    unit="${unit%% *}"
    [[ "$unit" == trustixd@*.service ]] || continue
    name="${unit#trustixd@}"
    name="${name%.service}"
    add_configured_instance "$name"
  done <<<"$units"

  if [[ ${#instances[@]} -eq 0 ]]; then
    instances=("${configured_instances[@]}")
  fi
  for name in "${configured_instances[@]}"; do
    add_preflight_instance "$name"
  done
  for name in "${instances[@]}"; do
    add_preflight_instance "$name"
  done
}

loaded_config=""
loaded_data_dir=""
loaded_api_addr=""
loaded_peer_api_addr=""
loaded_dataplane=""
loaded_extra_args_text=""
loaded_extra_args=()

apply_extra_arg_overrides() {
  local i arg
  for ((i = 0; i < ${#loaded_extra_args[@]}; i++)); do
    arg="${loaded_extra_args[$i]}"
    case "$arg" in
      -config|-data-dir|-api|-peer-api|-dataplane)
        ((i + 1 < ${#loaded_extra_args[@]})) || {
          log "ERROR: ${arg} in TRUSTIX_EXTRA_ARGS requires a value"
          return 1
        }
        case "$arg" in
          -config) loaded_config="${loaded_extra_args[$((i + 1))]}" ;;
          -data-dir) loaded_data_dir="${loaded_extra_args[$((i + 1))]}" ;;
          -api) loaded_api_addr="${loaded_extra_args[$((i + 1))]}" ;;
          -peer-api) loaded_peer_api_addr="${loaded_extra_args[$((i + 1))]}" ;;
          -dataplane) loaded_dataplane="${loaded_extra_args[$((i + 1))]}" ;;
        esac
        ((i += 1))
        ;;
      -config=*) loaded_config="${arg#*=}" ;;
      -data-dir=*) loaded_data_dir="${arg#*=}" ;;
      -api=*) loaded_api_addr="${arg#*=}" ;;
      -peer-api=*) loaded_peer_api_addr="${arg#*=}" ;;
      -dataplane=*) loaded_dataplane="${arg#*=}" ;;
      -version|--version|-version=*|--version=*|-check-config|--check-config|-check-config=*|--check-config=*|-cleanup-dataplane|--cleanup-dataplane|-cleanup-dataplane=*|--cleanup-dataplane=*|-cleanup-dataplane-dry-run|--cleanup-dataplane-dry-run|-cleanup-dataplane-dry-run=*|--cleanup-dataplane-dry-run=*|-repair-dataplane|--repair-dataplane|-repair-dataplane=*|--repair-dataplane=*)
        log "ERROR: operational flag ${arg} is not valid in TRUSTIX_EXTRA_ARGS"
        return 1
        ;;
    esac
  done
}

load_instance_settings() {
  local instance="$1"
  local env_file="${sysconfdir}/${instance}.env"
  local TRUSTIX_CONFIG="${sysconfdir}/${instance}.yaml"
  local TRUSTIX_DATA_DIR
  local TRUSTIX_API_ADDR="127.0.0.1:8787"
  local TRUSTIX_PEER_API_ADDR="0.0.0.0:9443"
  local TRUSTIX_DATAPLANE="auto"
  local TRUSTIX_EXTRA_ARGS=""
  if [[ "$service_manager" == "openwrt" ]]; then
    TRUSTIX_DATA_DIR="${sysconfdir}/state/${instance}"
  else
    TRUSTIX_DATA_DIR="/var/lib/trustix/${instance}"
  fi
  if [[ -f "$env_file" ]]; then
    set +u
    # shellcheck disable=SC1090
    . "$env_file"
    set -u
  fi
  loaded_config="$TRUSTIX_CONFIG"
  loaded_data_dir="$TRUSTIX_DATA_DIR"
  loaded_api_addr="$TRUSTIX_API_ADDR"
  loaded_peer_api_addr="$TRUSTIX_PEER_API_ADDR"
  loaded_dataplane="$TRUSTIX_DATAPLANE"
  loaded_extra_args_text="$TRUSTIX_EXTRA_ARGS"
  loaded_extra_args=()
  if [[ -n "$loaded_extra_args_text" ]]; then
    read -r -a loaded_extra_args <<<"$loaded_extra_args_text"
  fi
  apply_extra_arg_overrides
}

check_instance_config() (
  set -Eeuo pipefail
  set -a
  load_instance_settings "$1"
  set +a
  local candidate="$2"
  [[ -f "$loaded_config" ]] || {
    log "ERROR: instance $1 config not found: ${loaded_config}"
    return 1
  }
  log "preflight instance=$1 config=${loaded_config}"
  "$candidate" \
    -config "$loaded_config" \
    -data-dir "$loaded_data_dir" \
    -api "$loaded_api_addr" \
    -peer-api "$loaded_peer_api_addr" \
    -dataplane "$loaded_dataplane" \
    -check-config \
    "${loaded_extra_args[@]}"
)

preflight_candidate() {
  local candidate="$1"
  local instance
  [[ -x "$candidate" ]] || {
    log "ERROR: candidate trustixd is not executable: ${candidate}"
    return 1
  }
  "$candidate" -version >/dev/null
  for instance in "${preflight_instances[@]}"; do
    if ! check_instance_config "$instance" "$candidate"; then
      log "ERROR: candidate configuration preflight failed for instance ${instance}; installation was not modified"
      return 1
    fi
  done
}

transaction_snapshot_path() {
  local index="$1"
  printf '%s/transaction/files/%s\n' "$work_dir" "$index"
}

snapshot_transaction_file() {
  local path="$1"
  local mode="$2"
  local index="${#transaction_paths[@]}"
  local snapshot
  snapshot="$(transaction_snapshot_path "$index")"
  transaction_paths+=("$path")
  transaction_modes+=("$mode")
  transaction_snapshots+=("$snapshot")
  if [[ -e "$path" ]]; then
    transaction_existed+=(1)
    copy_file_with_mode "$path" "$snapshot" 0600
  else
    transaction_existed+=(0)
  fi
}

prepare_transaction_snapshot() {
  local package_dir="$1"
  local name
  run_root mkdir -p "${work_dir}/transaction/files"
  for name in trustixd trustixctl trustix-ca trustix-device trustix-iptunnel-smoke; do
    if [[ -f "${package_dir}/bin/${name}" ]]; then
      snapshot_transaction_file "${bindir}/${name}" 0755
    fi
  done
  if [[ -f "${package_dir}/scripts/trustix-backup.sh" ]]; then
    snapshot_transaction_file "${libexecdir}/trustix-backup.sh" 0755
  fi
  case "$service_manager" in
    systemd)
      if [[ -f "${package_dir}/packaging/systemd/trustixd@.service" ]]; then
        snapshot_transaction_file "${unitdir}/trustixd@.service" 0644
      fi
      if [[ -f "${package_dir}/packaging/systemd/trustix-backup@.service" ]]; then
        snapshot_transaction_file "${unitdir}/trustix-backup@.service" 0644
      fi
      if [[ -f "${package_dir}/packaging/systemd/trustix-backup@.timer" ]]; then
        snapshot_transaction_file "${unitdir}/trustix-backup@.timer" 0644
      fi
      ;;
    openwrt)
      snapshot_transaction_file "${initdir}/trustix" 0755
      ;;
  esac
}

restore_transaction_files() {
  local i path mode snapshot failed=0
  for ((i = ${#transaction_paths[@]} - 1; i >= 0; i--)); do
    path="${transaction_paths[$i]}"
    mode="${transaction_modes[$i]}"
    snapshot="${transaction_snapshots[$i]}"
    run_root rm -f "${path}.trustix-update.$$" >/dev/null 2>&1 || true
    if [[ "${transaction_existed[$i]}" == "1" ]]; then
      local tmp="${path}.trustix-rollback.$$"
      if copy_file_with_mode "$snapshot" "$tmp" "$mode" && run_root mv -f "$tmp" "$path"; then
        :
      else
        log "ERROR: could not restore ${path}"
        failed=1
      fi
    elif ! run_root rm -f "$path"; then
      log "ERROR: could not remove newly installed ${path}"
      failed=1
    fi
  done
  return "$failed"
}

listener_probe() {
  local address="$1"
  local host port port_number port_hex table
  if [[ "$address" == \[*\]:* ]]; then
    host="${address#\[}"
    host="${host%%\]*}"
    port="${address##*]:}"
  else
    host="${address%:*}"
    port="${address##*:}"
  fi
  [[ -n "$port" && "$port" != "$address" && "$port" =~ ^[0-9]+$ ]] || return 1
  port_number=$((10#$port))
  ((port_number >= 1 && port_number <= 65535)) || return 1
  printf -v port_hex '%04X' "$port_number"
  for table in /proc/net/tcp /proc/net/tcp6; do
    [[ -r "$table" ]] || continue
    if awk -v suffix=":${port_hex}" '
      NR > 1 && toupper($4) == "0A" && toupper($2) ~ suffix "$" { found = 1 }
      END { exit found ? 0 : 1 }
    ' "$table"; then
      return 0
    fi
  done
  return 1
}

api_probe_base_urls() {
  local address="$1"
  local host port url_host
  if [[ "$address" == \[*\]:* ]]; then
    host="${address#\[}"
    host="${host%%\]*}"
    port="${address##*]:}"
  else
    host="${address%:*}"
    port="${address##*:}"
  fi
  [[ -n "$port" && "$port" != "$address" ]] || return 1
  case "$host" in
    ""|0.0.0.0) host="127.0.0.1" ;;
    ::) host="::1" ;;
  esac
  if [[ "$host" == *:* ]]; then
    url_host="[${host}]"
  else
    url_host="$host"
  fi
  case "$host" in
    127.*|::1|localhost)
      printf 'http://%s:%s\nhttps://%s:%s\n' "$url_host" "$port" "$url_host" "$port"
      ;;
    *)
      printf 'https://%s:%s\nhttp://%s:%s\n' "$url_host" "$port" "$url_host" "$port"
      ;;
  esac
}

probe_readiness_url() {
  local base_url="$1"
  if command -v curl >/dev/null 2>&1; then
    curl -kfsS --connect-timeout 1 --max-time 2 "${base_url}/readyz" >/dev/null 2>&1 && return 0
  fi
  if command -v wget >/dev/null 2>&1; then
    wget --no-check-certificate -q -T 2 -O /dev/null "${base_url}/readyz" >/dev/null 2>&1 && return 0
  fi
  if [[ -x "${bindir}/trustixctl" ]]; then
    "${bindir}/trustixctl" -api "$base_url" -api-tls-insecure-skip-verify ready >/dev/null 2>&1 && return 0
  fi
  return 1
}

api_readiness_probe() {
  local address="$1"
  local base_url
  if [[ -n "${loaded_readiness_url:-}" ]]; then
    probe_readiness_url "$loaded_readiness_url"
    return
  fi
  while IFS= read -r base_url; do
    [[ -n "$base_url" ]] || continue
    if probe_readiness_url "$base_url"; then
      loaded_readiness_url="$base_url"
      return 0
    fi
  done < <(api_probe_base_urls "$address")
  return 1
}

process_matches_instance_config() {
  local config_path="$1"
  local expected_binary="${bindir}/trustixd"
  local proc first arg expect_config config_matches
  [[ -x "$expected_binary" ]] || return 1
  for proc in /proc/[0-9]*; do
    [[ -r "${proc}/cmdline" ]] || continue
    first=""
    expect_config=0
    config_matches=0
    while IFS= read -r -d '' arg; do
      if [[ -z "$first" ]]; then
        first="$arg"
        [[ "${first##*/}" == "trustixd" ]] || break
      fi
      if [[ "$expect_config" == "1" ]]; then
        if [[ "$arg" == "$config_path" ]]; then
          config_matches=1
          break
        fi
        expect_config=0
      fi
      case "$arg" in
        -config) expect_config=1 ;;
        -config=*)
          if [[ "${arg#*=}" == "$config_path" ]]; then
            config_matches=1
            break
          fi
          ;;
      esac
    done <"${proc}/cmdline"
    if [[ "$config_matches" == "1" && -e "${proc}/exe" && "${proc}/exe" -ef "$expected_binary" ]]; then
      return 0
    fi
  done
  return 1
}

wait_instance_api() (
  local instance="$1"
  local health_mode="${2:-required}"
  local i
  local loaded_readiness_url=""
  load_instance_settings "$instance"
  for i in {1..15}; do
    if process_matches_instance_config "$loaded_config" && listener_probe "$loaded_api_addr"; then
      if [[ "$health_mode" == "legacy" ]] || api_readiness_probe "$loaded_api_addr"; then
        return 0
      fi
    fi
    sleep 1
  done
  log "ERROR: installed daemon process or management API readiness is not healthy for instance ${instance}: ${loaded_api_addr}"
  return 1
)

wait_openwrt_instance_healthy() (
  local instance="$1"
  local health_mode="${2:-required}"
  local i
  local loaded_readiness_url=""
  load_instance_settings "$instance"
  for i in {1..15}; do
    if process_matches_instance_config "$loaded_config" && listener_probe "$loaded_api_addr"; then
      if [[ "$health_mode" == "legacy" ]] || api_readiness_probe "$loaded_api_addr"; then
        break
      fi
    fi
    sleep 1
  done
  if ! process_matches_instance_config "$loaded_config" || ! listener_probe "$loaded_api_addr" || { [[ "$health_mode" != "legacy" ]] && ! api_readiness_probe "$loaded_api_addr"; }; then
    log "ERROR: OpenWrt instance did not start or become ready: ${instance} api=${loaded_api_addr}"
    run_root "${initdir}/trustix" status "$instance" >&2 || true
    command -v logread >/dev/null 2>&1 && logread | grep -i 'trustix' | tail -n 80 >&2 || true
    return 1
  fi
  for i in {1..5}; do
    sleep 1
    if ! process_matches_instance_config "$loaded_config" || ! listener_probe "$loaded_api_addr" || { [[ "$health_mode" != "legacy" ]] && ! api_readiness_probe "$loaded_api_addr"; }; then
      log "ERROR: OpenWrt instance did not remain healthy: ${instance} api=${loaded_api_addr}"
      return 1
    fi
  done
)

restart_instances() {
  [[ "$restart" == "1" ]] || return 0
  case "$service_manager" in
    systemd)
      command -v systemctl >/dev/null 2>&1 || {
        log "ERROR: systemctl not found; rerun with --no-restart"
        return 1
      }
      run_root systemctl daemon-reload
      if [[ ${#instances[@]} -eq 0 ]]; then
        log "no trustixd@*.service instance detected; installed binaries only"
        return 0
      fi
      local instance
      for instance in "${instances[@]}"; do
        services_touched=1
        log "restart trustixd@${instance}.service"
        if ! run_root systemctl restart "trustixd@${instance}.service"; then
          run_root systemctl --no-pager --full status "trustixd@${instance}.service" >&2 || true
          return 1
        fi
        wait_systemd_unit_active "trustixd@${instance}.service" || return 1
        wait_instance_api "$instance" || return 1
        restarted_instances+=("$instance")
      done
      ;;
    openwrt)
      [[ -x "${initdir}/trustix" ]] || {
        log "ERROR: OpenWrt init script not found: ${initdir}/trustix"
        return 1
      }
      if [[ ${#instances[@]} -eq 0 ]]; then
        log "no ${sysconfdir}/*.env instance detected; installed binaries only"
        return 0
      fi
      local instance
      for instance in "${instances[@]}"; do
        services_touched=1
        log "restart trustix:${instance}"
        run_root "${initdir}/trustix" restart "$instance" || return 1
        wait_openwrt_instance_healthy "$instance" || return 1
        restarted_instances+=("$instance")
      done
      ;;
  esac
}

rollback_transaction() {
  [[ "$transaction_started" == "1" && "$transaction_committed" != "1" ]] || return 0
  [[ "$transaction_rolling_back" != "1" ]] || return 1
  transaction_rolling_back=1
  local failed=0 instance
  log "update failed; restoring previous TrustIX installation"
  restore_transaction_files || failed=1
  if [[ "$service_manager" == "systemd" ]]; then
    run_root systemctl daemon-reload || failed=1
  fi
  if [[ "$services_touched" == "1" ]]; then
    for instance in "${instances[@]}"; do
      case "$service_manager" in
        systemd)
          log "rollback restart trustixd@${instance}.service"
          run_root systemctl restart "trustixd@${instance}.service" || {
            failed=1
            continue
          }
          wait_systemd_unit_active "trustixd@${instance}.service" || failed=1
          wait_instance_api "$instance" legacy || failed=1
          ;;
        openwrt)
          log "rollback restart trustix:${instance}"
          run_root "${initdir}/trustix" restart "$instance" || {
            failed=1
            continue
          }
          wait_openwrt_instance_healthy "$instance" legacy || failed=1
          ;;
      esac
    done
  fi
  if [[ "$failed" == "0" ]]; then
    log "rollback complete; previous version is running"
  else
    log "ERROR: rollback was incomplete; transaction snapshot kept at ${work_dir}/transaction"
    if [[ "$backup" == "1" ]]; then
      log "persistent backup: ${backup_dir}"
    fi
  fi
  return "$failed"
}

cleanup_update_workdir() {
  [[ "$work_dir_owned" == "1" ]] || return 0
  case "$work_dir" in
    /tmp/trustix-update.*) run_root rm -rf -- "$work_dir" ;;
    *) log "ERROR: refusing to remove unexpected update work dir: ${work_dir}"; return 1 ;;
  esac
}

update_exit_trap() {
  local rc=$?
  trap - EXIT
  set +e
  if [[ "$transaction_started" == "1" && "$transaction_committed" != "1" ]]; then
    rollback_transaction || rollback_failed=1
    [[ "$rc" != "0" ]] || rc=1
  fi
  if [[ "$rollback_failed" == "1" ]]; then
    log "preserving update work dir for manual recovery: ${work_dir}"
  else
    cleanup_update_workdir || true
  fi
  exit "$rc"
}

package_dir=""
trap update_exit_trap EXIT
prepare_tarball
package_dir="$(extract_package)"
discover_instances
preflight_candidate "${package_dir}/bin/trustixd"
prepare_transaction_snapshot "$package_dir"
transaction_started=1
install_package "$package_dir"
restart_instances
transaction_committed=1
if ! install_docs "$package_dir"; then
  log "WARNING: runtime update succeeded but documentation installation failed"
fi

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
  printf '"preflighted":['
  first=1
  for instance in "${preflight_instances[@]}"; do
    if [[ "$first" == "0" ]]; then printf ','; fi
    first=0
    printf '"%s"' "$(json_escape "$instance")"
  done
  printf '],'
  printf '"restarted":['
  first=1
  for instance in "${restarted_instances[@]}"; do
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
