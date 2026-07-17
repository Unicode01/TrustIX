#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ]; then
  echo "ERROR: scripts/trustix-deploy.sh requires GNU bash 4+" >&2
  exit 2
fi
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
usage: scripts/trustix-deploy.sh [options]

Deploys a TrustIX release tarball or bin dir to a local or SSH target.

Options:
  --target USER@HOST         SSH target; omit for local deployment
  --ssh-port PORT            SSH port
  --ssh-key PATH             SSH private key
  --ssh-option OPTION        extra ssh/scp -o option; repeatable
  --tarball PATH             release tarball from trustix-build.sh
  --bin-dir DIR              directory containing trustixd/trustixctl/trustix-ca
  --instance NAME            systemd instance name (default: ix)
  --config PATH              config file to install
  --cert-dir DIR             cert directory to install
  --target-cert-dir DIR      target cert dir (default: /etc/trustix/certs)
  --service-manager MODE     auto, systemd, or openwrt (default: auto)
  --prefix DIR               install prefix (default: /usr/local, OpenWrt: /opt/trustix)
  --sysconfdir DIR           config dir (default: /etc/trustix)
  --unitdir DIR              systemd unit dir (default: /etc/systemd/system)
  --initdir DIR              OpenWrt init dir (default: /etc/init.d)
  --state-root DIR           state root (default: /var/lib/trustix, OpenWrt: /etc/trustix/state)
  --api ADDR                 management API listen (default: 127.0.0.1:8787)
  --peer-api ADDR            peer API listen (default: 0.0.0.0:9443)
  --dataplane MODE           noop, linux, or auto (default: auto)
  --admin-auth               add -api-admin-auth to service args
  --extra-arg ARG            append extra trustixd arg; repeatable
  --env KEY=VALUE            append service environment; repeatable
  --no-openwrt-firewall      do not install OpenWrt firewall allow rules
  --no-sudo                  run install commands without sudo
  --no-enable                do not enable service
  --no-start                 do not start/restart service
  --json                     print machine-readable summary
  -h, --help                 show this help
EOF
}

log() {
  printf '[trustix-deploy] %s\n' "$*" >&2
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

env_quote() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf '"%s"' "$value"
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

lower_ascii() {
  local value="$1"
  printf '%s' "${value,,}"
}

target=""
ssh_port=""
ssh_key=""
ssh_options=()
tarball=""
bin_dir=""
instance="ix"
config_path=""
cert_dir=""
target_cert_dir=""
api_addr="127.0.0.1:8787"
peer_api_addr="0.0.0.0:9443"
dataplane="auto"
extra_args=()
runtime_env=()
sudo_cmd="sudo"
enable_service=1
start_service=1
json=0
openwrt_firewall_rules="${TRUSTIX_OPENWRT_FIREWALL_RULES:-auto}"
service_manager="${TRUSTIX_DEPLOY_SERVICE_MANAGER:-auto}"
prefix=""
sysconfdir=""
unitdir=""
initdir=""
state_root=""
installed_config_path=""
backup_root="${TRUSTIX_BACKUP_ROOT:-/var/backups/trustix}"
deploy_transaction_started=0
deploy_transaction_committed=0
deploy_transaction_dir=""
deploy_transaction_paths=()
deploy_transaction_backups=()
deploy_transaction_existed=()
deploy_temp_paths=()
deploy_service_was_active=0
deploy_service_was_enabled=0
deploy_rollback_failed=0
deploy_remote_stage=""
deploy_remote_target=""
deploy_remote_ssh_cmd=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) [[ $# -ge 2 ]] || die "--target requires a value"; target="$2"; shift 2 ;;
    --ssh-port) [[ $# -ge 2 ]] || die "--ssh-port requires a value"; ssh_port="$2"; shift 2 ;;
    --ssh-key) [[ $# -ge 2 ]] || die "--ssh-key requires a value"; ssh_key="$2"; shift 2 ;;
    --ssh-option) [[ $# -ge 2 ]] || die "--ssh-option requires a value"; ssh_options+=("$2"); shift 2 ;;
    --tarball) [[ $# -ge 2 ]] || die "--tarball requires a value"; tarball="$2"; shift 2 ;;
    --bin-dir) [[ $# -ge 2 ]] || die "--bin-dir requires a value"; bin_dir="$2"; shift 2 ;;
    --instance) [[ $# -ge 2 ]] || die "--instance requires a value"; instance="$2"; shift 2 ;;
    --config) [[ $# -ge 2 ]] || die "--config requires a value"; config_path="$2"; shift 2 ;;
    --cert-dir) [[ $# -ge 2 ]] || die "--cert-dir requires a value"; cert_dir="$2"; shift 2 ;;
    --target-cert-dir) [[ $# -ge 2 ]] || die "--target-cert-dir requires a value"; target_cert_dir="$2"; shift 2 ;;
    --service-manager) [[ $# -ge 2 ]] || die "--service-manager requires a value"; service_manager="$2"; shift 2 ;;
    --prefix) [[ $# -ge 2 ]] || die "--prefix requires a value"; prefix="$2"; shift 2 ;;
    --sysconfdir) [[ $# -ge 2 ]] || die "--sysconfdir requires a value"; sysconfdir="$2"; shift 2 ;;
    --unitdir) [[ $# -ge 2 ]] || die "--unitdir requires a value"; unitdir="$2"; shift 2 ;;
    --initdir) [[ $# -ge 2 ]] || die "--initdir requires a value"; initdir="$2"; shift 2 ;;
    --state-root) [[ $# -ge 2 ]] || die "--state-root requires a value"; state_root="$2"; shift 2 ;;
    --api) [[ $# -ge 2 ]] || die "--api requires a value"; api_addr="$2"; shift 2 ;;
    --peer-api) [[ $# -ge 2 ]] || die "--peer-api requires a value"; peer_api_addr="$2"; shift 2 ;;
    --dataplane) [[ $# -ge 2 ]] || die "--dataplane requires a value"; dataplane="$2"; shift 2 ;;
    --admin-auth) extra_args+=("-api-admin-auth"); shift ;;
    --extra-arg) [[ $# -ge 2 ]] || die "--extra-arg requires a value"; extra_args+=("$2"); shift 2 ;;
    --env) [[ $# -ge 2 ]] || die "--env requires a value"; runtime_env+=("$2"); shift 2 ;;
    --no-openwrt-firewall) openwrt_firewall_rules="0"; shift ;;
    --no-sudo) sudo_cmd=""; shift ;;
    --no-enable) enable_service=0; shift ;;
    --no-start) start_service=0; shift ;;
    --json) json=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

if [[ -n "$tarball" && -n "$bin_dir" ]]; then
  die "--tarball and --bin-dir are mutually exclusive"
fi
if [[ -z "$tarball" && -z "$bin_dir" ]]; then
  die "either --tarball or --bin-dir is required"
fi
service_manager="$(lower_ascii "$service_manager")"
case "$service_manager" in
  auto|systemd|openwrt) ;;
  *) die "--service-manager must be auto, systemd, or openwrt" ;;
esac
for item in "${runtime_env[@]}"; do
  key="${item%%=*}"
  [[ "$item" == *=* && "$key" =~ ^TRUSTIX_[A-Za-z0-9_]+$ ]] || die "--env must be TRUSTIX_NAME=value"
  [[ "$item" != *$'\n'* ]] || die "--env value must not contain newlines"
done

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

wait_openwrt_instance_started() {
  local instance="$1"
  local i
  if ! command -v pgrep >/dev/null 2>&1; then
    return 0
  fi
  for i in {1..10}; do
    if pgrep -f "trustixd.*${instance}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  log "OpenWrt instance did not show a trustixd process quickly: ${instance}"
  run_root "${initdir}/trustix" status "$instance" >&2 || true
  command -v logread >/dev/null 2>&1 && logread | grep -i 'trustix' | tail -n 80 >&2 || true
  return 1
}

openwrt_runtime_deps_install_enabled() {
  case "$(lower_ascii "${TRUSTIX_DEPLOY_INSTALL_DEPS:-${TRUSTIX_BOOTSTRAP_INSTALL_DEPS:-auto}}")" in
    0|false|no|off|disabled) return 1 ;;
    *) return 0 ;;
  esac
}

ensure_openwrt_dataplane_runtime_deps() {
  [[ -f /etc/openwrt_release ]] || return 0
  command -v opkg >/dev/null 2>&1 || return 0
  openwrt_runtime_deps_install_enabled || return 0

  log "install OpenWrt dataplane runtime packages"
  run_root opkg update
  run_root opkg install \
    ca-bundle ca-certificates \
    kmod-sched-core kmod-sched kmod-sched-bpf \
    ip-full tc-bpf
}

openwrt_firewall_rules_enabled() {
  case "$(lower_ascii "$openwrt_firewall_rules")" in
    0|false|no|off|disabled) return 1 ;;
    *) return 0 ;;
  esac
}

sanitize_openwrt_firewall_rule_part() {
  local value="$1"
  value="${value//[^A-Za-z0-9_.-]/-}"
  value="${value##-}"
  value="${value%%-}"
  [[ -n "$value" ]] || value="ix"
  printf '%s' "$value"
}

address_port() {
  local value="$1"
  value="${value%%/*}"
  value="${value##*,}"
  value="${value##*=}"
  value="${value%\"}"
  value="${value#\"}"
  value="${value%\'}"
  value="${value#\'}"
  value="${value%]}"
  value="${value##*:}"
  [[ "$value" =~ ^[0-9]+$ ]] || return 1
  [[ "$value" -ge 1 && "$value" -le 65535 ]] || return 1
  printf '%s\n' "$value"
}

addr_is_loopback_only() {
  local value="$1" host
  host="${value%:*}"
  host="${host#[}"
  host="${host%]}"
  case "$host" in
    ""|127.*|localhost|::1) return 0 ;;
    *) return 1 ;;
  esac
}

config_listen_ports() {
  [[ -n "${installed_config_path:-}" && -f "$installed_config_path" ]] || return 0
  sed -n \
    -e 's/.*"listen"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
    -e 's/^[[:space:]]*listen:[[:space:]]*["'\'']\{0,1\}\([^"'\'']*\).*/\1/p' \
    "$installed_config_path" |
    while IFS= read -r listen; do
      printf '%s\n' "$listen" | tr ',' '\n' | while IFS= read -r part; do
        part="${part#"${part%%[![:space:]]*}"}"
        part="${part%"${part##*[![:space:]]}"}"
        case "$part" in
          port=*|vxlan_port=*) address_port "$part" || true ;;
          *:*) address_port "$part" || true ;;
        esac
      done
    done | sort -n -u
}

config_has_transport() {
  local name="$1"
  [[ -n "${installed_config_path:-}" && -f "$installed_config_path" ]] || return 1
  grep -Eq "\"transport\"[[:space:]]*:[[:space:]]*\"${name}\"|^[[:space:]]*transport:[[:space:]]*[\"']?${name}([\"']?([[:space:]]|#|$))" "$installed_config_path"
}

openwrt_firewall_rule_exists() {
  local name="$1"
  run_root uci -q show firewall 2>/dev/null | grep -F ".name='${name}'" >/dev/null 2>&1
}

openwrt_add_firewall_rule() {
  local name="$1" proto="$2" port="${3:-}" section
  openwrt_firewall_rule_exists "$name" && return 0
  section="$(run_root uci add firewall rule)"
  [[ -n "$section" ]] || return 1
  run_root uci set "firewall.${section}.name=${name}"
  run_root uci set "firewall.${section}.src=*"
  run_root uci set "firewall.${section}.proto=${proto}"
  if [[ -n "$port" ]]; then
    run_root uci set "firewall.${section}.dest_port=${port}"
  fi
  run_root uci set "firewall.${section}.target=ACCEPT"
  run_root uci set "firewall.${section}.family=ipv4"
}

install_openwrt_firewall_rules() {
  [[ "$service_manager" == "openwrt" ]] || return 0
  [[ -f /etc/openwrt_release ]] || return 0
  openwrt_firewall_rules_enabled || return 0
  command -v uci >/dev/null 2>&1 || return 0
  [[ -x "${initdir}/firewall" || -x /etc/init.d/firewall ]] || return 0

  local rule_prefix safe_instance port
  safe_instance="$(sanitize_openwrt_firewall_rule_part "$instance")"
  rule_prefix="trustix-${safe_instance}"

  if port="$(address_port "$peer_api_addr" 2>/dev/null)"; then
    openwrt_add_firewall_rule "${rule_prefix}-peer-api-${port}" tcp "$port"
  fi
  if ! addr_is_loopback_only "$api_addr"; then
    if port="$(address_port "$api_addr" 2>/dev/null)"; then
      openwrt_add_firewall_rule "${rule_prefix}-api-${port}" tcp "$port"
    fi
  fi
  while IFS= read -r port; do
    [[ -n "$port" ]] || continue
    openwrt_add_firewall_rule "${rule_prefix}-endpoint-udp-${port}" udp "$port"
    openwrt_add_firewall_rule "${rule_prefix}-endpoint-tcp-${port}" tcp "$port"
  done < <(config_listen_ports)
  if config_has_transport gre; then
    openwrt_add_firewall_rule "${rule_prefix}-gre" gre
  fi
  if config_has_transport ipip; then
    openwrt_add_firewall_rule "${rule_prefix}-ipip" 4
  fi

  run_root uci commit firewall
  if [[ -x "${initdir}/firewall" ]]; then
    run_root "${initdir}/firewall" reload
  else
    run_root /etc/init.d/firewall reload
  fi
}

install_file() {
  local src="$1"
  local dst="$2"
  local mode="$3"
  local dir="${dst%/*}"
  [[ "$dir" != "$dst" ]] && run_root mkdir -p "$dir"
	if [[ "$deploy_transaction_started" == "1" ]]; then
		snapshot_deploy_file "$dst"
	fi
	local tmp="${dst}.trustix-deploy.$$"
	run_root rm -f "$tmp"
  if command -v install >/dev/null 2>&1; then
		if ! run_root install -m "$mode" "$src" "$tmp"; then
			run_root rm -f "$tmp" >/dev/null 2>&1 || true
			return 1
		fi
  else
		if ! run_root cp "$src" "$tmp" || ! run_root chmod "$mode" "$tmp"; then
			run_root rm -f "$tmp" >/dev/null 2>&1 || true
			return 1
		fi
  fi
	if ! run_root mv -f "$tmp" "$dst"; then
		run_root rm -f "$tmp" >/dev/null 2>&1 || true
		return 1
	fi
}

snapshot_deploy_file() {
	local path="$1" i backup
	for ((i = 0; i < ${#deploy_transaction_paths[@]}; i++)); do
		[[ "${deploy_transaction_paths[$i]}" == "$path" ]] && return 0
	done
	if run_root test -L "$path"; then
		die "refusing to replace symlink during deploy: $path"
	fi
	deploy_transaction_paths+=("$path")
	backup="${deploy_transaction_dir}/file.${#deploy_transaction_paths[@]}"
	deploy_transaction_backups+=("$backup")
	if run_root test -e "$path"; then
		run_root test -f "$path" || die "refusing to replace non-regular deploy target: $path"
		run_root cp -p "$path" "$backup"
		deploy_transaction_existed+=(1)
	else
		deploy_transaction_existed+=(0)
	fi
}

begin_deploy_transaction() {
	deploy_transaction_dir="$(mktemp -d)"
	deploy_temp_paths+=("$deploy_transaction_dir")
	case "$service_manager" in
		systemd)
			if command -v systemctl >/dev/null 2>&1; then
				run_root systemctl is-active --quiet "trustixd@${instance}.service" && deploy_service_was_active=1 || true
				run_root systemctl is-enabled --quiet "trustixd@${instance}.service" && deploy_service_was_enabled=1 || true
			fi
			;;
		openwrt)
			if [[ -x "${initdir}/trustix" ]] && run_root "${initdir}/trustix" status "$instance" >/dev/null 2>&1; then
				deploy_service_was_active=1
			fi
			;;
	esac
	deploy_transaction_started=1
}

rollback_deploy_transaction() {
	[[ "$deploy_transaction_started" == "1" && "$deploy_transaction_committed" != "1" ]] || return 0
	local i path backup failed=0 tmp
	log "deploy failed; restoring previous installation"
	for ((i = ${#deploy_transaction_paths[@]} - 1; i >= 0; i--)); do
		path="${deploy_transaction_paths[$i]}"
		backup="${deploy_transaction_backups[$i]}"
		tmp="${path}.trustix-rollback.$$"
		run_root rm -f "$tmp" >/dev/null 2>&1 || true
		if [[ "${deploy_transaction_existed[$i]}" == "1" ]]; then
			if run_root cp -p "$backup" "$tmp" && run_root mv -f "$tmp" "$path"; then
				:
			else
				log "ERROR: failed to restore deploy target $path"
				failed=1
			fi
		elif ! run_root rm -f "$path"; then
			log "ERROR: failed to remove new deploy target $path"
			failed=1
		fi
	done
	case "$service_manager" in
		systemd)
			if command -v systemctl >/dev/null 2>&1; then
				run_root systemctl daemon-reload || failed=1
				if [[ "$deploy_service_was_enabled" == "1" ]]; then
					run_root systemctl enable "trustixd@${instance}.service" || failed=1
				else
					run_root systemctl disable "trustixd@${instance}.service" || failed=1
				fi
				if [[ "$deploy_service_was_active" == "1" ]]; then
					run_root systemctl restart "trustixd@${instance}.service" || failed=1
				else
					run_root systemctl stop "trustixd@${instance}.service" || failed=1
				fi
			fi
			;;
		openwrt)
			if run_root test -f /etc/config/firewall; then
				if [[ -x "${initdir}/firewall" ]]; then
					run_root "${initdir}/firewall" reload || failed=1
				elif [[ -x /etc/init.d/firewall ]]; then
					run_root /etc/init.d/firewall reload || failed=1
				fi
			fi
			if [[ -x "${initdir}/trustix" ]]; then
				if [[ "$deploy_service_was_active" == "1" ]]; then
					run_root "${initdir}/trustix" restart "$instance" || failed=1
				else
					run_root "${initdir}/trustix" stop "$instance" || failed=1
				fi
			fi
			;;
	esac
	return "$failed"
}

cleanup_deploy_temp_paths() {
	local path
	for path in "${deploy_temp_paths[@]}"; do
		[[ -n "$path" ]] || continue
		case "$path" in
			/tmp/*|/var/tmp/*) run_root rm -rf -- "$path" ;;
			*) log "ERROR: refusing to remove unexpected deploy temp path: $path"; return 1 ;;
		esac
	done
}

cleanup_remote_deploy_stage() {
	[[ -n "$deploy_remote_stage" && -n "$deploy_remote_target" ]] || return 0
	if ! "${deploy_remote_ssh_cmd[@]}" "$deploy_remote_target" "rm -rf $(shell_quote "$deploy_remote_stage")"; then
		log "ERROR: failed to remove remote staging directory ${deploy_remote_target}:${deploy_remote_stage}"
		return 1
	fi
	deploy_remote_stage=""
	deploy_remote_target=""
	deploy_remote_ssh_cmd=()
}

deploy_exit_trap() {
	local rc=$?
	trap - EXIT
	set +e
	if [[ "$deploy_transaction_started" == "1" && "$deploy_transaction_committed" != "1" ]]; then
		rollback_deploy_transaction || deploy_rollback_failed=1
		[[ "$rc" != "0" ]] || rc=1
	fi
	if [[ "$deploy_rollback_failed" == "1" ]]; then
		log "ERROR: deploy rollback incomplete; transaction snapshot kept at ${deploy_transaction_dir}"
	else
		cleanup_deploy_temp_paths || rc=1
	fi
	cleanup_remote_deploy_stage || rc=1
	exit "$rc"
}

trap deploy_exit_trap EXIT

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
  die "could not auto-detect service manager; pass --service-manager systemd|openwrt or --no-start"
}

apply_target_defaults() {
  service_manager="$(detect_service_manager)"
  if [[ -z "$sysconfdir" ]]; then
    sysconfdir="/etc/trustix"
  fi
  if [[ -z "$prefix" ]]; then
    case "$service_manager" in
      openwrt) prefix="/opt/trustix" ;;
      *) prefix="/usr/local" ;;
    esac
  fi
  if [[ -z "$unitdir" ]]; then
    unitdir="/etc/systemd/system"
  fi
  if [[ -z "$initdir" ]]; then
    initdir="/etc/init.d"
  fi
  if [[ -z "$state_root" ]]; then
    case "$service_manager" in
      openwrt) state_root="${sysconfdir}/state" ;;
      *) state_root="/var/lib/trustix" ;;
    esac
  fi
  if [[ -z "$target_cert_dir" ]]; then
    target_cert_dir="${sysconfdir}/certs"
  fi
}

remote_deploy() {
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

  local remote_manager="$service_manager"
  if [[ "$remote_manager" == "auto" ]]; then
    remote_manager="$("${ssh_cmd[@]}" "$target" 'if [ -f /etc/openwrt_release ] && { [ -x /sbin/procd ] || [ -d /etc/init.d ]; }; then echo openwrt; elif command -v systemctl >/dev/null 2>&1 || [ -d /run/systemd/system ]; then echo systemd; else echo auto; fi')"
  fi
  if [[ "$remote_manager" == "openwrt" ]]; then
    scp_cmd+=(-O)
  fi

	local stage stage_suffix
	stage="$("${ssh_cmd[@]}" "$target" 'mktemp -d /tmp/trustix-deploy.XXXXXX')"
	[[ -n "$stage" ]] || die "failed to create remote staging dir"
	stage_suffix="${stage#/tmp/trustix-deploy.}"
	[[ "$stage" == /tmp/trustix-deploy.* && -n "$stage_suffix" && "$stage_suffix" != */* ]] || \
		die "remote returned unsafe deploy staging dir: $stage"
	deploy_remote_stage="$stage"
	deploy_remote_target="$target"
	deploy_remote_ssh_cmd=("${ssh_cmd[@]}")
  log "remote stage: ${target}:${stage}"

  "${scp_cmd[@]}" "$0" "${target}:${stage}/trustix-deploy.sh"
	if [[ -n "$tarball" ]]; then
    "${scp_cmd[@]}" "$tarball" "${target}:${stage}/package.tar.gz"
  fi
  if [[ -n "$bin_dir" ]]; then
    "${ssh_cmd[@]}" "$target" "mkdir -p $(shell_quote "${stage}/bin")"
    "${scp_cmd[@]}" "${bin_dir}/trustixd" "${bin_dir}/trustixctl" "${bin_dir}/trustix-ca" "${target}:${stage}/bin/"
    if [[ -f "${bin_dir}/trustix-device" ]]; then
      "${scp_cmd[@]}" "${bin_dir}/trustix-device" "${target}:${stage}/bin/"
    fi
    if [[ -f "${repo_root}/packaging/systemd/trustixd@.service" ]]; then
      "${ssh_cmd[@]}" "$target" "mkdir -p $(shell_quote "${stage}/packaging/systemd")"
      "${scp_cmd[@]}" "${repo_root}/packaging/systemd/trustixd@.service" "${target}:${stage}/packaging/systemd/trustixd@.service"
    fi
    if [[ -f "${repo_root}/packaging/openwrt/trustix.init" ]]; then
      "${ssh_cmd[@]}" "$target" "mkdir -p $(shell_quote "${stage}/packaging/openwrt")"
      "${scp_cmd[@]}" "${repo_root}/packaging/openwrt/trustix.init" "${target}:${stage}/packaging/openwrt/trustix.init"
    fi
  fi
  if [[ -n "$config_path" ]]; then
    "${scp_cmd[@]}" "$config_path" "${target}:${stage}/config"
  fi
  if [[ -n "$cert_dir" ]]; then
    "${scp_cmd[@]}" -r "$cert_dir" "${target}:${stage}/certs"
  fi

	"${ssh_cmd[@]}" "$target" 'command -v bash >/dev/null 2>&1 || { echo "bash is required on remote target" >&2; exit 127; }'

  local remote_args=()
  if [[ -n "$tarball" ]]; then
    remote_args+=(--tarball "${stage}/package.tar.gz")
  else
    remote_args+=(--bin-dir "${stage}/bin")
  fi
  remote_args+=(--instance "$instance" --service-manager "$remote_manager")
  [[ -n "$prefix" ]] && remote_args+=(--prefix "$prefix")
  [[ -n "$sysconfdir" ]] && remote_args+=(--sysconfdir "$sysconfdir")
  [[ -n "$state_root" ]] && remote_args+=(--state-root "$state_root")
  [[ -n "$unitdir" ]] && remote_args+=(--unitdir "$unitdir")
  [[ -n "$initdir" ]] && remote_args+=(--initdir "$initdir")
  [[ -n "$target_cert_dir" ]] && remote_args+=(--target-cert-dir "$target_cert_dir")
  remote_args+=(--api "$api_addr" --peer-api "$peer_api_addr" --dataplane "$dataplane")
  if [[ -n "$config_path" ]]; then
    remote_args+=(--config "${stage}/config")
  fi
  if [[ -n "$cert_dir" ]]; then
    remote_args+=(--cert-dir "${stage}/certs")
  fi
  if [[ -z "$sudo_cmd" ]]; then
    remote_args+=(--no-sudo)
  fi
  if [[ "$enable_service" == "0" ]]; then
    remote_args+=(--no-enable)
  fi
  if [[ "$start_service" == "0" ]]; then
    remote_args+=(--no-start)
  fi
  if [[ "$json" == "1" ]]; then
    remote_args+=(--json)
  fi
  for opt in "${extra_args[@]}"; do
    remote_args+=(--extra-arg "$opt")
  done
  for item in "${runtime_env[@]}"; do
    remote_args+=(--env "$item")
  done

  local command="TRUSTIX_DEPLOY_REMOTE_CHILD=1 bash $(shell_quote "${stage}/trustix-deploy.sh")"
  local arg
  for arg in "${remote_args[@]}"; do
    command+=" $(shell_quote "$arg")"
  done
	local remote_status=0
	"${ssh_cmd[@]}" "$target" "$command" || remote_status=$?
	if ! cleanup_remote_deploy_stage; then
		[[ "$remote_status" != "0" ]] || remote_status=1
	fi
	return "$remote_status"
}

install_from_package() {
  local package_dir="$1"
  local bindir="${prefix}/bin"
  local unit_src=""
  local init_src=""

  for name in trustixd trustixctl trustix-ca trustix-device; do
    if [[ -f "${package_dir}/bin/${name}" ]]; then
      install_file "${package_dir}/bin/${name}" "${bindir}/${name}" 0755
    elif [[ "$name" == "trustix-device" ]]; then
      continue
    else
      die "missing binary: ${package_dir}/bin/${name}"
    fi
  done
  if [[ -f "${package_dir}/scripts/trustix-backup.sh" ]]; then
    install_file "${package_dir}/scripts/trustix-backup.sh" "${prefix}/libexec/trustix/trustix-backup.sh" 0755
  elif [[ -f "${repo_root}/scripts/trustix-backup.sh" ]]; then
    install_file "${repo_root}/scripts/trustix-backup.sh" "${prefix}/libexec/trustix/trustix-backup.sh" 0755
  fi
  if [[ -f "${package_dir}/scripts/trustix-ha.sh" ]]; then
    install_file "${package_dir}/scripts/trustix-ha.sh" "${prefix}/libexec/trustix/trustix-ha.sh" 0755
  elif [[ -f "${repo_root}/scripts/trustix-ha.sh" ]]; then
    install_file "${repo_root}/scripts/trustix-ha.sh" "${prefix}/libexec/trustix/trustix-ha.sh" 0755
  fi
  case "$service_manager" in
    systemd)
      if [[ -f "${package_dir}/packaging/systemd/trustixd@.service" ]]; then
        unit_src="${package_dir}/packaging/systemd/trustixd@.service"
      elif [[ -f "${repo_root}/packaging/systemd/trustixd@.service" ]]; then
        unit_src="${repo_root}/packaging/systemd/trustixd@.service"
      else
        die "missing trustixd@.service"
      fi
      install_file "$unit_src" "${unitdir}/trustixd@.service" 0644
      if [[ -f "${package_dir}/packaging/systemd/trustix-backup@.service" ]]; then
        install_file "${package_dir}/packaging/systemd/trustix-backup@.service" "${unitdir}/trustix-backup@.service" 0644
      fi
      if [[ -f "${package_dir}/packaging/systemd/trustix-backup@.timer" ]]; then
        install_file "${package_dir}/packaging/systemd/trustix-backup@.timer" "${unitdir}/trustix-backup@.timer" 0644
      fi
		run_root mkdir -p "$backup_root"
		run_root chmod 0700 "$backup_root"
      ;;
    openwrt)
      if [[ -f "${package_dir}/packaging/openwrt/trustix.init" ]]; then
        init_src="${package_dir}/packaging/openwrt/trustix.init"
      elif [[ -f "${repo_root}/packaging/openwrt/trustix.init" ]]; then
        init_src="${repo_root}/packaging/openwrt/trustix.init"
      else
        die "missing OpenWrt init script"
      fi
      install_file "$init_src" "${initdir}/trustix" 0755
      ;;
  esac
  run_root mkdir -p "$sysconfdir" "$state_root"
}

install_config() {
  local installed_config="${sysconfdir}/${instance}.yaml"
  if [[ -n "$config_path" ]]; then
    local ext="${config_path##*.}"
    case "$ext" in
      json) installed_config="${sysconfdir}/${instance}.json" ;;
      yaml|yml) installed_config="${sysconfdir}/${instance}.yaml" ;;
    esac
    install_file "$config_path" "$installed_config" 0644
  fi
  installed_config_path="$installed_config"

  if [[ -n "$cert_dir" ]]; then
    run_root mkdir -p "$target_cert_dir"
		local file rel mode cert_list
		cert_list="$(mktemp /tmp/trustix-deploy-certs.XXXXXX)"
		deploy_temp_paths+=("$cert_list")
		if ! find "$cert_dir" -type f -print0 >"$cert_list"; then
			return 1
		fi
    while IFS= read -r -d '' file; do
      rel="${file#${cert_dir}/}"
      mode=0644
      case "$file" in
        *.key|*.p12|*.pfx) mode=0600 ;;
      esac
      install_file "$file" "${target_cert_dir}/${rel}" "$mode"
		done <"$cert_list"
  fi

	local env_tmp
	env_tmp="$(mktemp)"
	deploy_temp_paths+=("$env_tmp")
  {
    printf 'TRUSTIX_CONFIG=%s\n' "$installed_config"
    printf 'TRUSTIX_BIN=%s/bin/trustixd\n' "$prefix"
    printf 'TRUSTIX_DATA_DIR=%s/%s\n' "$state_root" "$instance"
    printf 'TRUSTIX_API_ADDR=%s\n' "$api_addr"
    printf 'TRUSTIX_PEER_API_ADDR=%s\n' "$peer_api_addr"
    printf 'TRUSTIX_DATAPLANE=%s\n' "$dataplane"
    local first=1 arg joined_extra=""
    for arg in "${extra_args[@]}"; do
      if [[ "$first" == "0" ]]; then
        joined_extra+=" "
      fi
      first=0
      joined_extra+="$arg"
    done
    printf 'TRUSTIX_EXTRA_ARGS='
    env_quote "$joined_extra"
    printf '\n'
    if [[ "$service_manager" == "openwrt" ]] && openwrt_firewall_rules_enabled; then
      printf 'TRUSTIX_OPENWRT_FIREWALL_RULES=1\n'
    fi
    local env_item key value
    for env_item in "${runtime_env[@]}"; do
      key="${env_item%%=*}"
      value="${env_item#*=}"
      printf '%s=' "$key"
      env_quote "$value"
      printf '\n'
    done
  } >"$env_tmp"
  install_file "$env_tmp" "${sysconfdir}/${instance}.env" 0644
  rm -f "$env_tmp"
}

local_deploy() {
  [[ "$(uname -s)" == "Linux" ]] || die "deployment must run on Linux"
  apply_target_defaults
  if [[ -f "${sysconfdir}/${instance}.ha.env" && ( "$enable_service" == "1" || "$start_service" == "1" ) ]]; then
    die "instance $instance is managed by active-standby HA; rerun with --no-enable --no-start so keepalived remains the only service owner"
  fi
  if [[ "$service_manager" == "openwrt" ]]; then
    ensure_openwrt_dataplane_runtime_deps || die "OpenWrt dataplane runtime dependencies are missing; automatic dependency install failed"
  fi
  local stage=""
  local package_dir=""
  if [[ -n "$tarball" ]]; then
    [[ -f "$tarball" ]] || die "tarball not found: $tarball"
    need_cmd tar
		stage="$(mktemp -d)"
		deploy_temp_paths+=("$stage")
		tar -xzf "$tarball" -C "$stage"
    package_dir="$stage"
  else
    [[ -d "$bin_dir" ]] || die "bin dir not found: $bin_dir"
		package_dir="$(mktemp -d)"
		deploy_temp_paths+=("$package_dir")
    mkdir -p "${package_dir}/bin"
    cp -a "${bin_dir}/." "${package_dir}/bin/"
    if [[ -d "${repo_root}/packaging" ]]; then
      cp -R "${repo_root}/packaging" "${package_dir}/packaging"
    fi
	fi

	begin_deploy_transaction
	install_from_package "$package_dir"
	install_config
	if [[ "$service_manager" == "openwrt" ]] && run_root test -f /etc/config/firewall; then
		snapshot_deploy_file /etc/config/firewall
	fi
	install_openwrt_firewall_rules
  case "$service_manager" in
    systemd)
      if command -v systemctl >/dev/null 2>&1 && { [[ "$enable_service" == "1" ]] || [[ "$start_service" == "1" ]]; }; then
        run_root systemctl daemon-reload
        if [[ "$enable_service" == "1" ]]; then
          run_root systemctl enable "trustixd@${instance}.service"
        fi
        if [[ "$start_service" == "1" ]]; then
          run_root systemctl restart "trustixd@${instance}.service"
          wait_systemd_unit_active "trustixd@${instance}.service"
        fi
      elif [[ "$start_service" == "1" ]]; then
        die "systemctl not found; rerun with --no-start or start trustixd manually"
      fi
      ;;
    openwrt)
      if [[ ! -x "${initdir}/trustix" ]]; then
        die "OpenWrt init script not installed: ${initdir}/trustix"
      fi
      if [[ "$enable_service" == "1" ]]; then
        run_root "${initdir}/trustix" enable
      fi
      if [[ "$start_service" == "1" ]]; then
				if [[ "$deploy_service_was_active" == "1" ]]; then
					run_root "${initdir}/trustix" stop "$instance"
				else
					run_root "${initdir}/trustix" stop "$instance" >/dev/null 2>&1 || true
				fi
        run_root "${initdir}/trustix" start "$instance"
        wait_openwrt_instance_started "$instance" || die "OpenWrt instance did not start: ${instance}"
      fi
      ;;
	esac
	deploy_transaction_committed=1

	if [[ "$json" == "1" ]]; then
    printf '{'
    printf '"instance":"%s",' "$(json_escape "$instance")"
    printf '"service_manager":"%s",' "$(json_escape "$service_manager")"
    printf '"config":"%s",' "$(json_escape "$installed_config_path")"
    printf '"cert_dir":"%s",' "$(json_escape "$target_cert_dir")"
    if [[ "$service_manager" == "openwrt" ]]; then
      printf '"service":"%s trustix:%s",' "$(json_escape "${initdir}/trustix")" "$(json_escape "$instance")"
    else
      printf '"service":"trustixd@%s.service",' "$(json_escape "$instance")"
    fi
    printf '"started":%s' "$start_service"
    printf '}\n'
  else
    log "deployed instance: $instance (${service_manager})"
  fi

}

if [[ -n "$target" && -z "${TRUSTIX_DEPLOY_REMOTE_CHILD:-}" ]]; then
  remote_deploy
else
  local_deploy
fi
