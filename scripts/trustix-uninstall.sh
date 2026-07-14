#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ]; then
  echo "ERROR: scripts/trustix-uninstall.sh requires GNU bash 4+" >&2
  exit 2
fi
set -Eeuo pipefail

usage() {
  cat <<'EOF'
usage: scripts/trustix-uninstall.sh [options]

Stops TrustIX instances, runs dataplane cleanup, and removes installed service
wrappers/binaries. Configuration, certificates, and data are preserved unless a
purge option is passed.

Scope:
  --instance NAME           uninstall one instance; repeatable
  --all                     uninstall all instances discovered from /etc/trustix/*.env
  --service-manager MODE    auto, systemd, or openwrt (default: auto)

Paths:
  --prefix DIR              install prefix (default: /usr/local, OpenWrt: /opt/trustix)
  --bindir DIR              binary dir (default: PREFIX/bin)
  --libexecdir DIR          helper dir (default: PREFIX/libexec/trustix)
  --sysconfdir DIR          config/env dir (default: /etc/trustix)
  --unitdir DIR             systemd unit dir (default: /etc/systemd/system)
  --initdir DIR             OpenWrt init dir (default: /etc/init.d)
  --state-root DIR          state root (default: /var/lib/trustix, OpenWrt: /etc/trustix/state)
  --target-cert-dir DIR     installed cert dir (default: SYSCONFDIR/certs)

Removal:
  --purge                   also remove instance env/config/data and instance certs
  --purge-config            remove instance env/config only
  --purge-data              remove instance data dir only
  --purge-certs             remove instance cert/key/route cert files only
  --purge-certs-dir         remove the whole target cert dir; dangerous on shared installs
  --keep-binaries           keep trustixd/trustixctl/trustix-ca/trustix-device
  --remove-binaries         remove binaries even when uninstalling selected instances
  --keep-service            keep systemd/OpenWrt service wrapper
  --remove-service          remove service wrapper even when uninstalling selected instances
  --no-cleanup-dataplane    skip trustixd -cleanup-dataplane
  --unload-kernel-modules   unload TrustIX kernel modules after cleanup
  --keep-kernel-modules     leave loaded TrustIX kernel modules in place
  --ha-offline              confirm selected HA instances are demoted and detached from keepalived

Remote:
  --target USER@HOST        copy this script to target and run it there
  --ssh-port PORT
  --ssh-key PATH
  --ssh-option OPTION       repeatable
  --script-url URL          fallback URL used when --target is run from stdin

Other:
  --no-sudo                 run local commands without sudo
  --json                    print machine-readable summary
  -h, --help                show this help

Examples:
  sudo bash scripts/trustix-uninstall.sh --all
  sudo bash scripts/trustix-uninstall.sh --instance ix-a --purge
  curl -fsSL https://raw.githubusercontent.com/Unicode01/TrustIX/main/scripts/trustix-uninstall.sh | sudo bash -s -- --all --purge
EOF
}

log() {
  printf '[trustix-uninstall] %s\n' "$*" >&2
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

lower_ascii() {
  local value="$1"
  printf '%s' "${value,,}"
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

run_root() {
  if [[ -n "$sudo_cmd" && "${EUID:-$(id -u)}" != "0" ]]; then
    command -v "$sudo_cmd" >/dev/null 2>&1 || die "${sudo_cmd} is required for non-root uninstall commands; rerun as root or pass --no-sudo"
    "$sudo_cmd" "$@"
  else
    "$@"
  fi
}

script_self_path() {
  local source_path="${BASH_SOURCE[0]:-${0:-}}"
  case "$source_path" in
    ""|bash|-bash|/dev/fd/*|/proc/*/fd/*) return 1 ;;
  esac
  if [[ -f "$source_path" ]]; then
    case "$source_path" in
      /*) printf '%s\n' "$source_path" ;;
      *) printf '%s/%s\n' "$(cd "$(dirname "$source_path")" && pwd)" "$(basename "$source_path")" ;;
    esac
    return 0
  fi
  return 1
}

target=""
ssh_port=""
ssh_key=""
ssh_options=()
instances=()
all_instances=0
service_manager="${TRUSTIX_UNINSTALL_SERVICE_MANAGER:-auto}"
prefix=""
bindir=""
libexecdir=""
sysconfdir=""
unitdir=""
initdir=""
state_root=""
target_cert_dir=""
sudo_cmd="sudo"
cleanup_dataplane=1
unload_kernel_modules=""
purge_config=0
purge_data=0
purge_certs=0
purge_certs_dir=0
remove_binaries=""
remove_service=""
json=0
ha_offline=0
script_url="${TRUSTIX_UNINSTALL_SCRIPT_URL:-https://raw.githubusercontent.com/Unicode01/TrustIX/main/scripts/trustix-uninstall.sh}"
unloaded_modules=()
failed_modules=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) [[ $# -ge 2 ]] || die "--target requires a value"; target="$2"; shift 2 ;;
    --ssh-port) [[ $# -ge 2 ]] || die "--ssh-port requires a value"; ssh_port="$2"; shift 2 ;;
    --ssh-key) [[ $# -ge 2 ]] || die "--ssh-key requires a value"; ssh_key="$2"; shift 2 ;;
    --ssh-option) [[ $# -ge 2 ]] || die "--ssh-option requires a value"; ssh_options+=("$2"); shift 2 ;;
    --script-url) [[ $# -ge 2 ]] || die "--script-url requires a value"; script_url="$2"; shift 2 ;;
    --instance) [[ $# -ge 2 ]] || die "--instance requires a value"; instances+=("$2"); shift 2 ;;
    --all) all_instances=1; shift ;;
    --service-manager) [[ $# -ge 2 ]] || die "--service-manager requires a value"; service_manager="$2"; shift 2 ;;
    --prefix) [[ $# -ge 2 ]] || die "--prefix requires a value"; prefix="$2"; shift 2 ;;
    --bindir) [[ $# -ge 2 ]] || die "--bindir requires a value"; bindir="$2"; shift 2 ;;
    --libexecdir) [[ $# -ge 2 ]] || die "--libexecdir requires a value"; libexecdir="$2"; shift 2 ;;
    --sysconfdir) [[ $# -ge 2 ]] || die "--sysconfdir requires a value"; sysconfdir="$2"; shift 2 ;;
    --unitdir) [[ $# -ge 2 ]] || die "--unitdir requires a value"; unitdir="$2"; shift 2 ;;
    --initdir) [[ $# -ge 2 ]] || die "--initdir requires a value"; initdir="$2"; shift 2 ;;
    --state-root) [[ $# -ge 2 ]] || die "--state-root requires a value"; state_root="$2"; shift 2 ;;
    --target-cert-dir) [[ $# -ge 2 ]] || die "--target-cert-dir requires a value"; target_cert_dir="$2"; shift 2 ;;
    --purge) purge_config=1; purge_data=1; purge_certs=1; shift ;;
    --purge-config) purge_config=1; shift ;;
    --purge-data) purge_data=1; shift ;;
    --purge-certs) purge_certs=1; shift ;;
    --purge-certs-dir) purge_certs_dir=1; purge_certs=1; shift ;;
    --keep-binaries) remove_binaries=0; shift ;;
    --remove-binaries) remove_binaries=1; shift ;;
    --keep-service) remove_service=0; shift ;;
    --remove-service) remove_service=1; shift ;;
    --no-cleanup-dataplane) cleanup_dataplane=0; shift ;;
    --unload-kernel-modules) unload_kernel_modules=1; shift ;;
    --keep-kernel-modules) unload_kernel_modules=0; shift ;;
    --ha-offline) ha_offline=1; shift ;;
    --no-sudo) sudo_cmd=""; shift ;;
    --json) json=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

if [[ "$all_instances" == "1" && ${#instances[@]} -gt 0 ]]; then
  die "--all and --instance are mutually exclusive"
fi

service_manager="$(lower_ascii "$service_manager")"
case "$service_manager" in
  auto|systemd|openwrt) ;;
  *) die "--service-manager must be auto, systemd, or openwrt" ;;
esac

remote_uninstall() {
  need_cmd ssh
  need_cmd scp
  local ssh_cmd=(ssh)
  local scp_cmd=(scp)
  if [[ -n "$ssh_port" ]]; then
    ssh_cmd+=(-p "$ssh_port")
    scp_cmd+=(-P "$ssh_port")
  fi
  if [[ -n "$ssh_key" ]]; then
    ssh_cmd+=(-i "$ssh_key")
    scp_cmd+=(-i "$ssh_key")
  fi
  local opt
  for opt in "${ssh_options[@]}"; do
    ssh_cmd+=(-o "$opt")
    scp_cmd+=(-o "$opt")
  done
  local stage
  stage="$("${ssh_cmd[@]}" "$target" 'mktemp -d /tmp/trustix-uninstall.XXXXXX')"
  [[ -n "$stage" ]] || die "failed to create remote staging dir"
  local self_path
  if self_path="$(script_self_path)"; then
    "${scp_cmd[@]}" "$self_path" "${target}:${stage}/trustix-uninstall.sh"
  else
    local fetch_command
    fetch_command="if command -v curl >/dev/null 2>&1; then curl -fsSL $(shell_quote "$script_url") -o $(shell_quote "${stage}/trustix-uninstall.sh"); elif command -v wget >/dev/null 2>&1; then wget -qO $(shell_quote "${stage}/trustix-uninstall.sh") $(shell_quote "$script_url"); else echo 'curl or wget is required to fetch trustix-uninstall.sh' >&2; exit 127; fi"
    "${ssh_cmd[@]}" "$target" "$fetch_command"
  fi

  local remote_args=()
  [[ "$all_instances" == "1" ]] && remote_args+=(--all)
  local instance
  for instance in "${instances[@]}"; do
    remote_args+=(--instance "$instance")
  done
  remote_args+=(--service-manager "$service_manager")
  [[ -n "$prefix" ]] && remote_args+=(--prefix "$prefix")
  [[ -n "$bindir" ]] && remote_args+=(--bindir "$bindir")
  [[ -n "$libexecdir" ]] && remote_args+=(--libexecdir "$libexecdir")
  [[ -n "$sysconfdir" ]] && remote_args+=(--sysconfdir "$sysconfdir")
  [[ -n "$unitdir" ]] && remote_args+=(--unitdir "$unitdir")
  [[ -n "$initdir" ]] && remote_args+=(--initdir "$initdir")
  [[ -n "$state_root" ]] && remote_args+=(--state-root "$state_root")
  [[ -n "$target_cert_dir" ]] && remote_args+=(--target-cert-dir "$target_cert_dir")
  [[ "$purge_config" == "1" ]] && remote_args+=(--purge-config)
  [[ "$purge_data" == "1" ]] && remote_args+=(--purge-data)
  [[ "$purge_certs" == "1" ]] && remote_args+=(--purge-certs)
  [[ "$purge_certs_dir" == "1" ]] && remote_args+=(--purge-certs-dir)
  [[ "$cleanup_dataplane" == "0" ]] && remote_args+=(--no-cleanup-dataplane)
  [[ "$remove_binaries" == "0" ]] && remote_args+=(--keep-binaries)
  [[ "$remove_binaries" == "1" ]] && remote_args+=(--remove-binaries)
  [[ "$remove_service" == "0" ]] && remote_args+=(--keep-service)
  [[ "$remove_service" == "1" ]] && remote_args+=(--remove-service)
  [[ "$unload_kernel_modules" == "0" ]] && remote_args+=(--keep-kernel-modules)
  [[ "$unload_kernel_modules" == "1" ]] && remote_args+=(--unload-kernel-modules)
  [[ "$ha_offline" == "1" ]] && remote_args+=(--ha-offline)
  [[ -z "$sudo_cmd" ]] && remote_args+=(--no-sudo)
  [[ "$json" == "1" ]] && remote_args+=(--json)

  local command="bash $(shell_quote "${stage}/trustix-uninstall.sh")"
  local arg
  for arg in "${remote_args[@]}"; do
    command+=" $(shell_quote "$arg")"
  done
  local remote_status=0
  "${ssh_cmd[@]}" "$target" "$command" || remote_status=$?
  "${ssh_cmd[@]}" "$target" "rm -rf $(shell_quote "$stage")" >/dev/null 2>&1 || true
  return "$remote_status"
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
  if [[ -d /etc/init.d && -f /etc/openwrt_release ]]; then
    printf 'openwrt\n'
    return
  fi
  printf 'systemd\n'
}

apply_defaults() {
  service_manager="$(detect_service_manager)"
  [[ -n "$sysconfdir" ]] || sysconfdir="/etc/trustix"
  if [[ -z "$prefix" ]]; then
    case "$service_manager" in
      openwrt) prefix="/opt/trustix" ;;
      *) prefix="/usr/local" ;;
    esac
  fi
  [[ -n "$bindir" ]] || bindir="${prefix}/bin"
  [[ -n "$libexecdir" ]] || libexecdir="${prefix}/libexec/trustix"
  [[ -n "$unitdir" ]] || unitdir="/etc/systemd/system"
  [[ -n "$initdir" ]] || initdir="/etc/init.d"
  if [[ -z "$state_root" ]]; then
    case "$service_manager" in
      openwrt) state_root="${sysconfdir}/state" ;;
      *) state_root="/var/lib/trustix" ;;
    esac
  fi
  [[ -n "$target_cert_dir" ]] || target_cert_dir="${sysconfdir}/certs"

  if [[ -z "$remove_binaries" ]]; then
    if [[ ${#instances[@]} -gt 0 && "$all_instances" != "1" ]]; then
      remove_binaries=0
    else
      remove_binaries=1
    fi
  fi
  if [[ -z "$remove_service" ]]; then
    if [[ ${#instances[@]} -gt 0 && "$all_instances" != "1" ]]; then
      remove_service=0
    else
      remove_service=1
    fi
  fi
  if [[ -z "$unload_kernel_modules" ]]; then
    if [[ "$remove_binaries" == "1" ]]; then
      unload_kernel_modules=1
    else
      unload_kernel_modules=0
    fi
  fi
}

discover_instances() {
  if [[ ${#instances[@]} -gt 0 ]]; then
    printf '%s\n' "${instances[@]}"
    return
  fi
  local found=0 file base
  if [[ -d "$sysconfdir" ]]; then
    for file in "$sysconfdir"/*.env; do
      [[ -f "$file" ]] || continue
      base="${file##*/}"
      base="${base%.env}"
      case "$base" in
        *.backup|*.ha) continue ;;
      esac
      [[ -n "$base" ]] || continue
      found=1
      printf '%s\n' "$base"
    done
  fi
  if [[ "$found" == "0" && "$all_instances" != "1" ]]; then
    for base in ix; do
      if [[ -f "${sysconfdir}/${base}.yaml" || -f "${sysconfdir}/${base}.json" ]]; then
        printf '%s\n' "$base"
      fi
    done
  fi
}

trim_ascii() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

decode_env_value() {
  local value="$1"
  value="$(trim_ascii "$value")"
  if [[ ${#value} -ge 2 && "${value:0:1}" == '"' && "${value: -1}" == '"' ]]; then
    value="${value:1:${#value}-2}"
    value="${value//\\\"/\"}"
    value="${value//\\\\/\\}"
  elif [[ ${#value} -ge 2 && "${value:0:1}" == "'" && "${value: -1}" == "'" ]]; then
    value="${value:1:${#value}-2}"
  fi
  printf '%s' "$value"
}

load_env_file() {
  local env_file="$1"
  [[ -f "$env_file" ]] || return 0
  local line key value
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="$(trim_ascii "$line")"
    [[ -z "$line" || "${line:0:1}" == "#" ]] && continue
    case "$line" in
      export[[:space:]]*) line="$(trim_ascii "${line#export}")" ;;
    esac
    [[ "$line" == *=* ]] || continue
    key="$(trim_ascii "${line%%=*}")"
    value="$(decode_env_value "${line#*=}")"
    case "$key" in
      TRUSTIX_CONFIG|TRUSTIX_BIN|TRUSTIX_DATA_DIR|TRUSTIX_API_ADDR|TRUSTIX_PEER_API_ADDR|TRUSTIX_DATAPLANE|TRUSTIX_EXTRA_ARGS)
        printf -v "$key" '%s' "$value"
        ;;
    esac
  done <"$env_file"
}

load_instance_env() {
  local instance="$1"
  TRUSTIX_CONFIG="${sysconfdir}/${instance}.yaml"
  if [[ ! -f "$TRUSTIX_CONFIG" && -f "${sysconfdir}/${instance}.json" ]]; then
    TRUSTIX_CONFIG="${sysconfdir}/${instance}.json"
  fi
  TRUSTIX_BIN="${bindir}/trustixd"
  TRUSTIX_DATA_DIR="${state_root}/${instance}"
  TRUSTIX_API_ADDR="127.0.0.1:8787"
  TRUSTIX_PEER_API_ADDR="0.0.0.0:9443"
  TRUSTIX_DATAPLANE="auto"
  TRUSTIX_EXTRA_ARGS=""
  load_env_file "${sysconfdir}/${instance}.env"
  if [[ -z "${TRUSTIX_BIN:-}" ]]; then
    TRUSTIX_BIN="${bindir}/trustixd"
  fi
}

stop_systemd_instance() {
  local instance="$1"
  if command -v systemctl >/dev/null 2>&1; then
    run_root systemctl stop "trustixd@${instance}.service" >/dev/null 2>&1 || true
    run_root systemctl disable "trustixd@${instance}.service" >/dev/null 2>&1 || true
    run_root systemctl reset-failed "trustixd@${instance}.service" >/dev/null 2>&1 || true
  fi
}

stop_openwrt_instance() {
  local instance="$1"
  if [[ -x "${initdir}/trustix" ]]; then
    run_root "${initdir}/trustix" stop "$instance" >/dev/null 2>&1 || true
  fi
}

disable_instance_backup_schedule() {
  local instance="$1"
  case "$service_manager" in
    systemd)
      if command -v systemctl >/dev/null 2>&1; then
        run_root systemctl disable --now "trustix-backup@${instance}.timer" >/dev/null 2>&1 || true
      fi
      ;;
    openwrt)
      if [[ -x "${libexecdir}/trustix-backup.sh" && -f "${sysconfdir}/${instance}.backup.env" ]]; then
        run_root "${libexecdir}/trustix-backup.sh" remove-schedule \
          --instance "$instance" \
          --instance-env "${sysconfdir}/${instance}.env" \
          --backup-env "${sysconfdir}/${instance}.backup.env" >/dev/null 2>&1 || true
      fi
      ;;
  esac
}

cleanup_instance_dataplane() {
  local instance="$1"
  load_instance_env "$instance"
  if [[ "$cleanup_dataplane" != "1" ]]; then
    return
  fi
  if [[ ! -x "${TRUSTIX_BIN:-}" || ! -f "${TRUSTIX_CONFIG:-}" ]]; then
    return
  fi
  log "cleanup dataplane for ${instance}"
  run_root "$TRUSTIX_BIN" \
    -config "$TRUSTIX_CONFIG" \
    -data-dir "$TRUSTIX_DATA_DIR" \
    -api "$TRUSTIX_API_ADDR" \
    -peer-api "$TRUSTIX_PEER_API_ADDR" \
    -dataplane "$TRUSTIX_DATAPLANE" \
    -cleanup-dataplane >/dev/null 2>&1 || true
}

path_under() {
  local path_value="$1"
  local root="$2"
  [[ -n "$path_value" && -n "$root" ]] || return 1
  local path_abs root_abs
  path_abs="$(canonical_path "$path_value")" || return 1
  root_abs="$(canonical_path "$root")" || return 1
  case "$path_abs" in
    "$root_abs"|"$root_abs"/*) return 0 ;;
    *) return 1 ;;
  esac
}

canonical_path() {
  local path_value="$1"
  [[ -n "$path_value" ]] || return 1
  if command -v realpath >/dev/null 2>&1; then
    realpath -m -- "$path_value" 2>/dev/null && return 0
    realpath "$path_value" 2>/dev/null && return 0
  fi
  if command -v readlink >/dev/null 2>&1; then
    readlink -f -- "$path_value" 2>/dev/null && return 0
  fi
  case "$path_value" in
    /*) printf '%s\n' "$path_value" ;;
    *) printf '%s/%s\n' "$(pwd -P)" "$path_value" ;;
  esac
}

safe_rm_rf() {
  local path_value="$1"
  local label="$2"
  [[ -n "$path_value" ]] || die "refusing to remove empty ${label} path"
  local path_abs
  path_abs="$(canonical_path "$path_value")" || die "could not resolve ${label} path: $path_value"
  case "$path_abs" in
    /|/bin|/boot|/dev|/etc|/home|/lib|/lib64|/opt|/proc|/root|/run|/sbin|/sys|/tmp|/usr|/usr/bin|/usr/local|/var|/var/lib)
      die "refusing to recursively remove unsafe ${label} path: $path_abs"
      ;;
  esac
  run_root rm -rf "$path_abs"
}

remove_instance_files() {
  local instance="$1"
  load_instance_env "$instance"
  if [[ "$purge_config" == "1" ]]; then
    run_root rm -f \
      "${sysconfdir}/${instance}.env" \
      "${sysconfdir}/${instance}.backup.env" \
      "${sysconfdir}/${instance}.ha.env"
    if path_under "$TRUSTIX_CONFIG" "$sysconfdir"; then
      run_root rm -f "$TRUSTIX_CONFIG"
    else
      log "skip external config path during purge: $TRUSTIX_CONFIG"
    fi
    run_root rm -f "${sysconfdir}/${instance}.yaml" "${sysconfdir}/${instance}.yml" "${sysconfdir}/${instance}.json"
  fi
  if [[ "$purge_data" == "1" ]]; then
    if path_under "$TRUSTIX_DATA_DIR" "$state_root"; then
      safe_rm_rf "$TRUSTIX_DATA_DIR" "instance data"
    else
      log "skip external data path during purge: $TRUSTIX_DATA_DIR"
    fi
  fi
  if [[ "$purge_certs" == "1" ]]; then
    run_root rm -f \
      "${target_cert_dir}/${instance}.crt" \
      "${target_cert_dir}/${instance}.key" \
      "${target_cert_dir}/${instance}-route.crt"
  fi
}

remove_shared_service() {
  case "$service_manager" in
    systemd)
      run_root rm -f \
        "${unitdir}/trustixd@.service" \
        "${unitdir}/trustix-backup@.service" \
        "${unitdir}/trustix-backup@.timer"
      if command -v systemctl >/dev/null 2>&1; then
        run_root systemctl daemon-reload >/dev/null 2>&1 || true
      fi
      ;;
    openwrt)
      if [[ -x "${initdir}/trustix" ]]; then
        run_root "${initdir}/trustix" disable >/dev/null 2>&1 || true
      fi
      run_root rm -f "${initdir}/trustix"
      ;;
  esac
}

remove_shared_binaries() {
  local name
  for name in trustixd trustixctl trustix-ca trustix-device trustix-iptunnel-smoke; do
    run_root rm -f "${bindir}/${name}"
  done
  run_root rm -f "${libexecdir}/trustix-backup.sh" "${libexecdir}/trustix-ha.sh"
  run_root rmdir "$libexecdir" >/dev/null 2>&1 || true
  run_root rmdir "$bindir" >/dev/null 2>&1 || true
  case "$prefix" in
    /opt/trustix|/usr/local/trustix)
      run_root rmdir "$prefix" >/dev/null 2>&1 || true
      ;;
  esac
}

module_loaded() {
  local name="$1"
  [[ -r /proc/modules ]] || return 1
  grep -q "^${name}[[:space:]]" /proc/modules
}

unload_shared_kernel_modules() {
  [[ "$unload_kernel_modules" == "1" ]] || return 0
  local rmmod_cmd=""
  rmmod_cmd="$(command -v rmmod || true)"
  if [[ -z "$rmmod_cmd" && -x /sbin/rmmod ]]; then
    rmmod_cmd="/sbin/rmmod"
  fi
  if [[ -z "$rmmod_cmd" ]]; then
    log "skip kernel module unload: rmmod not found"
    return 0
  fi
  local name
  for name in trustix_datapath trustix_datapath_helpers trustix_crypto; do
    if ! module_loaded "$name"; then
      continue
    fi
    if run_root "$rmmod_cmd" "$name" >/dev/null 2>&1; then
      unloaded_modules+=("$name")
      log "unloaded kernel module ${name}"
    else
      failed_modules+=("$name")
      log "kernel module still loaded or in use: ${name}"
    fi
  done
}

local_uninstall() {
  [[ "$(uname -s)" == "Linux" ]] || die "uninstall must run on Linux"
  apply_defaults

  local resolved_instances=()
  local instance
  while IFS= read -r instance; do
    [[ -n "$instance" ]] && resolved_instances+=("$instance")
  done < <(discover_instances)

  for instance in "${resolved_instances[@]}"; do
    if [[ -f "${sysconfdir}/${instance}.ha.env" && "$ha_offline" != "1" ]]; then
      die "instance $instance is managed by active-standby HA; detach it from keepalived, demote it, and rerun with --ha-offline"
    fi
  done

  for instance in "${resolved_instances[@]}"; do
    log "stop instance ${instance}"
    disable_instance_backup_schedule "$instance"
    case "$service_manager" in
      openwrt) stop_openwrt_instance "$instance" ;;
      *) stop_systemd_instance "$instance" ;;
    esac
    cleanup_instance_dataplane "$instance"
    remove_instance_files "$instance"
  done

  if [[ "$remove_service" == "1" ]]; then
    remove_shared_service
  fi
  unload_shared_kernel_modules
  if [[ "$remove_binaries" == "1" ]]; then
    remove_shared_binaries
  fi
  if [[ "$purge_certs_dir" == "1" ]]; then
    safe_rm_rf "$target_cert_dir" "cert dir"
  fi
  if [[ "$purge_config" == "1" ]]; then
    run_root rmdir "$sysconfdir" >/dev/null 2>&1 || true
  fi
  if [[ "$purge_data" == "1" ]]; then
    run_root rmdir "$state_root" >/dev/null 2>&1 || true
  fi

  if [[ "$json" == "1" ]]; then
    printf '{'
    printf '"service_manager":"%s",' "$(json_escape "$service_manager")"
    printf '"instances":['
    local first=1
    for instance in "${resolved_instances[@]}"; do
      if [[ "$first" == "0" ]]; then printf ','; fi
      first=0
      printf '"%s"' "$(json_escape "$instance")"
    done
    printf '],'
    printf '"removed_service":%s,' "$remove_service"
    printf '"removed_binaries":%s,' "$remove_binaries"
    printf '"unload_kernel_modules":%s,' "$unload_kernel_modules"
    printf '"unloaded_kernel_modules":['
    first=1
    for instance in "${unloaded_modules[@]}"; do
      if [[ "$first" == "0" ]]; then printf ','; fi
      first=0
      printf '"%s"' "$(json_escape "$instance")"
    done
    printf '],'
    printf '"failed_kernel_modules":['
    first=1
    for instance in "${failed_modules[@]}"; do
      if [[ "$first" == "0" ]]; then printf ','; fi
      first=0
      printf '"%s"' "$(json_escape "$instance")"
    done
    printf '],'
    printf '"purged_config":%s,' "$purge_config"
    printf '"purged_data":%s,' "$purge_data"
    printf '"purged_certs":%s' "$purge_certs"
    printf '}\n'
  else
    log "uninstall complete"
    if [[ "$purge_config" != "1" || "$purge_data" != "1" ]]; then
      log "kept config/data by default; rerun with --purge to remove instance files"
    fi
  fi
}

if [[ -n "$target" ]]; then
  remote_uninstall
else
  local_uninstall
fi
