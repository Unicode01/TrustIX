#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ]; then
  echo "ERROR: trustix-backup.sh requires GNU bash" >&2
  exit 2
fi
set -Eeuo pipefail

mode="${1:-}"
[[ -n "$mode" ]] && shift || true

instance=""
instance_env=""
backup_env=""
backup_dir=""
recipient=""
identity=""
archive=""
keep=""
ctl=""
api=""
verify_after=0
cron_schedule=""
admin_certs=()
admin_keys=()

usage() {
  cat <<'EOF'
Usage:
  trustix-backup.sh backup --instance IX [options]
  trustix-backup.sh verify --instance IX --identity FILE [--archive FILE] [options]
  trustix-backup.sh install-schedule --instance IX [--cron '17 3 * * *']
  trustix-backup.sh remove-schedule --instance IX

Backup options:
  --recipient FILE       recipient public key (required)
  --backup-dir DIR       encrypted archive directory
  --keep N               keep newest N archives; 0 keeps all
  --verify-identity FILE decrypt and verify the new archive after writing

Common options:
  --instance-env FILE    TrustIX instance env file
  --backup-env FILE      backup-specific env file
  --ctl FILE             trustixctl path
  --api URL              management API URL
  --admin-cert FILE      Admin certificate; repeat for threshold policies
  --admin-key FILE       matching Admin private key; repeat as needed
  --cron SCHEDULE        OpenWrt five-field cron schedule (default: 17 3 * * *)

Environment defaults use TRUSTIX_BACKUP_* variables. The source IX only needs
the public recipient key. Keep the identity offline unless running a recovery
drill or restore.
EOF
}

log() {
  printf '[trustix-backup] %s\n' "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --instance) [[ $# -ge 2 ]] || die "--instance requires a value"; instance="$2"; shift 2 ;;
    --instance-env) [[ $# -ge 2 ]] || die "--instance-env requires a value"; instance_env="$2"; shift 2 ;;
    --backup-env) [[ $# -ge 2 ]] || die "--backup-env requires a value"; backup_env="$2"; shift 2 ;;
    --backup-dir) [[ $# -ge 2 ]] || die "--backup-dir requires a value"; backup_dir="$2"; shift 2 ;;
    --recipient) [[ $# -ge 2 ]] || die "--recipient requires a value"; recipient="$2"; shift 2 ;;
    --identity|--verify-identity) [[ $# -ge 2 ]] || die "$1 requires a value"; identity="$2"; verify_after=1; shift 2 ;;
    --archive) [[ $# -ge 2 ]] || die "--archive requires a value"; archive="$2"; shift 2 ;;
    --keep) [[ $# -ge 2 ]] || die "--keep requires a value"; keep="$2"; shift 2 ;;
    --ctl) [[ $# -ge 2 ]] || die "--ctl requires a value"; ctl="$2"; shift 2 ;;
    --api) [[ $# -ge 2 ]] || die "--api requires a value"; api="$2"; shift 2 ;;
    --admin-cert) [[ $# -ge 2 ]] || die "--admin-cert requires a value"; admin_certs+=("$2"); shift 2 ;;
    --admin-key) [[ $# -ge 2 ]] || die "--admin-key requires a value"; admin_keys+=("$2"); shift 2 ;;
    --cron) [[ $# -ge 2 ]] || die "--cron requires a value"; cron_schedule="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

case "$mode" in
  backup|verify|drill|install-schedule|remove-schedule) ;;
  "") usage; exit 2 ;;
  *) die "mode must be backup, verify, install-schedule, or remove-schedule" ;;
esac
[[ -n "$instance" ]] || die "--instance is required"
[[ "$instance" =~ ^[A-Za-z0-9._-]+$ ]] || die "invalid instance name: $instance"

sysconfdir="${TRUSTIX_SYSCONFDIR:-/etc/trustix}"
[[ -n "$instance_env" ]] || instance_env="${sysconfdir}/${instance}.env"
[[ -n "$backup_env" ]] || backup_env="${sysconfdir}/${instance}.backup.env"

load_env_file() {
  local path="$1"
  [[ -f "$path" ]] || return 0
  [[ ! -L "$path" ]] || die "refusing symlink env file: $path"
  set -a
  # shellcheck disable=SC1090
  source "$path"
  set +a
}

load_env_file "$instance_env"
load_env_file "$backup_env"

[[ -n "$backup_dir" ]] || backup_dir="${TRUSTIX_BACKUP_DIR:-/var/backups/trustix/config}"
[[ -n "$recipient" ]] || recipient="${TRUSTIX_BACKUP_RECIPIENT:-}"
[[ -n "$identity" ]] || identity="${TRUSTIX_BACKUP_IDENTITY:-}"
[[ -n "$keep" ]] || keep="${TRUSTIX_BACKUP_KEEP:-14}"
[[ -n "$cron_schedule" ]] || cron_schedule="${TRUSTIX_BACKUP_CRON_SCHEDULE:-17 3 * * *}"
[[ -n "$ctl" ]] || ctl="${TRUSTIX_BACKUP_CTL:-}"
if [[ -z "$ctl" && -n "${TRUSTIX_BIN:-}" ]]; then
  ctl="$(dirname "$TRUSTIX_BIN")/trustixctl"
fi
[[ -n "$ctl" ]] || ctl="/usr/local/bin/trustixctl"
[[ -x "$ctl" ]] || die "trustixctl is not executable: $ctl"
[[ "$keep" =~ ^[0-9]+$ ]] || die "--keep must be a non-negative integer"

normalize_api_host() {
  local address="$1"
  local host port
  if [[ "$address" == \[*\]:* ]]; then
    host="${address#\[}"
    host="${host%%\]*}"
    port="${address##*]:}"
  else
    host="${address%:*}"
    port="${address##*:}"
  fi
  case "$host" in
    ""|0.0.0.0) host="127.0.0.1" ;;
    ::) host="::1" ;;
  esac
  if [[ "$host" == *:* ]]; then
    host="[$host]"
  fi
  printf '%s:%s\n' "$host" "$port"
}

if [[ -z "$api" ]]; then
  api="${TRUSTIX_BACKUP_API:-${TRUSTIX_API:-}}"
fi
if [[ -z "$api" ]]; then
  api_address="${TRUSTIX_API_ADDR:-127.0.0.1:8787}"
  api_scheme="${TRUSTIX_BACKUP_API_SCHEME:-http}"
  api="${api_scheme}://$(normalize_api_host "$api_address")"
fi

append_list_env() {
  local raw="$1"
  local kind="$2"
  local value
  raw="${raw//;/,}"
  local old_ifs="$IFS"
  IFS=','
  read -r -a values <<<"$raw"
  IFS="$old_ifs"
  for value in "${values[@]}"; do
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    [[ -n "$value" ]] || continue
    if [[ "$kind" == "cert" ]]; then
      admin_certs+=("$value")
    else
      admin_keys+=("$value")
    fi
  done
}

append_list_env "${TRUSTIX_BACKUP_ADMIN_CERT:-${TRUSTIX_ADMIN_CERT:-}}" cert
append_list_env "${TRUSTIX_BACKUP_ADMIN_KEY:-${TRUSTIX_ADMIN_KEY:-}}" key
[[ ${#admin_certs[@]} -eq ${#admin_keys[@]} ]] || die "Admin certificate/key counts do not match"

ctl_args=(-api "$api")
if [[ -n "${TRUSTIX_BACKUP_API_TLS_CA:-${TRUSTIX_API_TLS_CA:-}}" ]]; then
  ctl_args+=(-api-tls-ca "${TRUSTIX_BACKUP_API_TLS_CA:-${TRUSTIX_API_TLS_CA}}")
fi
if [[ -n "${TRUSTIX_BACKUP_API_TLS_SERVER_NAME:-${TRUSTIX_API_TLS_SERVER_NAME:-}}" ]]; then
  ctl_args+=(-api-tls-server-name "${TRUSTIX_BACKUP_API_TLS_SERVER_NAME:-${TRUSTIX_API_TLS_SERVER_NAME}}")
fi
case "${TRUSTIX_BACKUP_API_TLS_INSECURE_SKIP_VERIFY:-0}" in
  1|true|yes|on) ctl_args+=(-api-tls-insecure-skip-verify) ;;
esac
for ((i = 0; i < ${#admin_certs[@]}; i++)); do
  ctl_args+=(-admin-cert "${admin_certs[i]}" -admin-key "${admin_keys[i]}")
done

read -r -a schedule_cron_fields <<<"$cron_schedule"
[[ ${#schedule_cron_fields[@]} -eq 5 ]] || die "cron schedule must contain exactly five fields"
for field in "${schedule_cron_fields[@]}"; do
  [[ "$field" =~ ^[0-9*/,-]+$ ]] || die "invalid cron schedule field: $field"
done

shell_quote() {
  printf "'%s'" "${1//\'/\'\\\'\'}"
}

manage_schedule() {
  local action="$1"
  local scheduler="${TRUSTIX_BACKUP_SCHEDULER:-auto}"
  case "$scheduler" in
    auto|systemd|cron) ;;
    *) die "TRUSTIX_BACKUP_SCHEDULER must be auto, systemd, or cron" ;;
  esac
  if [[ "$scheduler" != "cron" ]] && command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    if [[ "$action" == "install" ]]; then
      [[ -f "$backup_env" ]] || die "create backup env before enabling the timer: $backup_env"
      systemctl enable --now "trustix-backup@${instance}.timer"
      log "enabled trustix-backup@${instance}.timer"
    else
      systemctl disable --now "trustix-backup@${instance}.timer"
      log "disabled trustix-backup@${instance}.timer"
    fi
    return
  fi
  [[ "$scheduler" != "systemd" ]] || die "systemd is not available"

  command -v crontab >/dev/null 2>&1 || die "neither systemd nor crontab is available"
  if [[ "${EUID:-$(id -u)}" != "0" ]]; then
    [[ "${TRUSTIX_BACKUP_TEST_ALLOW_NONROOT_SCHEDULE:-0}" == "1" ]] || \
      die "OpenWrt schedule management must run as root"
  fi
  local marker="# trustix-backup:${instance}"
  local script_path current filtered job
  script_path="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
  current="$(mktemp /tmp/trustix-backup-cron.XXXXXX)"
  filtered="${current}.filtered"
  crontab -l >"$current" 2>/dev/null || :
  if ! awk -v marker="$marker" 'index($0, marker) == 0 { print }' "$current" >"$filtered"; then
    rm -f "$current" "$filtered"
    die "could not filter existing crontab"
  fi
  if [[ "$action" == "install" ]]; then
    if [[ ! -f "$backup_env" ]]; then
      rm -f "$current" "$filtered"
      die "create backup env before installing cron: $backup_env"
    fi
    job="${cron_schedule} $(shell_quote "$script_path") backup --instance $(shell_quote "$instance") ${marker}"
    printf '%s\n' "$job" >>"$filtered"
  fi
  if ! crontab "$filtered"; then
    rm -f "$current" "$filtered"
    die "could not install updated crontab"
  fi
  rm -f "$current" "$filtered"
  if [[ -f /etc/openwrt_release && -x /etc/init.d/cron ]]; then
    /etc/init.d/cron restart >/dev/null
  fi
  if [[ "$action" == "install" ]]; then
    log "installed OpenWrt backup schedule for $instance"
  else
    log "removed OpenWrt backup schedule for $instance"
  fi
}

case "$mode" in
  install-schedule) manage_schedule install; exit 0 ;;
  remove-schedule) manage_schedule remove; exit 0 ;;
esac

verify_archive() {
  local path="$1"
  local output
  [[ -n "$identity" ]] || die "verify requires --identity or TRUSTIX_BACKUP_IDENTITY"
  [[ -f "$path" ]] || die "backup archive not found: $path"
  output="$($ctl "${ctl_args[@]}" config verify-backup -identity "$identity" "$path")"
  printf '%s\n' "$output"
  grep -Eq '"valid"[[:space:]]*:[[:space:]]*true' <<<"$output" || die "backup validation did not report valid=true"
  grep -Eq '"recovery_complete"[[:space:]]*:[[:space:]]*true' <<<"$output" || die "backup is valid but incomplete for disaster recovery"
  log "recovery drill passed: $path"
}

if [[ "$mode" == "verify" || "$mode" == "drill" ]]; then
  if [[ -z "$archive" ]]; then
    shopt -s nullglob
    candidates=("$backup_dir/trustix-${instance}-"*.tixbak)
    shopt -u nullglob
    [[ ${#candidates[@]} -gt 0 ]] || die "no encrypted backup found for instance $instance in $backup_dir"
    archive="${candidates[${#candidates[@]}-1]}"
  fi
  verify_archive "$archive"
  exit 0
fi

[[ -n "$recipient" ]] || die "backup requires --recipient or TRUSTIX_BACKUP_RECIPIENT"
[[ -f "$recipient" ]] || die "backup recipient not found: $recipient"
umask 077
mkdir -p "$backup_dir"
chmod 0700 "$backup_dir" || die "could not secure backup directory: $backup_dir"
lock_dir="${backup_dir}/.${instance}.backup.lock"
lock_pid_file="${lock_dir}/owner"
archive=""
backup_archive_complete=0
acquire_backup_lock() {
	local owner="" attempt
	for attempt in 1 2; do
		if mkdir "$lock_dir" 2>/dev/null; then
			if ! printf '%s %s\n' "$$" "$(date +%s)" >"$lock_pid_file" || ! chmod 0600 "$lock_pid_file"; then
				rm -f "$lock_pid_file"
				rmdir "$lock_dir" 2>/dev/null || true
				return 1
			fi
			return 0
		fi
		[[ -d "$lock_dir" && ! -L "$lock_dir" ]] || die "backup lock is not a safe directory: $lock_dir"
		if [[ -f "$lock_pid_file" && ! -L "$lock_pid_file" ]]; then
			read -r owner _ <"$lock_pid_file" || owner=""
		fi
		if [[ "$owner" =~ ^[1-9][0-9]*$ ]] && kill -0 "$owner" >/dev/null 2>&1; then
			return 1
		fi
		rm -f "$lock_pid_file" || return 1
		rmdir "$lock_dir" || return 1
	done
	return 1
}
if ! acquire_backup_lock; then
	die "another backup is running for instance $instance or its lock could not be recovered"
fi
cleanup() {
	local owner=""
	if [[ -f "$lock_pid_file" && ! -L "$lock_pid_file" ]]; then
		read -r owner _ <"$lock_pid_file" || owner=""
	fi
	if [[ "$owner" != "$$" ]]; then
		log "ERROR: refusing to release backup lock owned by ${owner:-unknown}"
		return 1
	fi
	rm -f "$lock_pid_file" || return 1
	rmdir "$lock_dir"
}
backup_exit_trap() {
	local rc=$?
	trap - EXIT
	set +e
	if [[ "$backup_archive_complete" != "1" && -n "$archive" && -e "$archive" ]]; then
		if ! rm -f -- "$archive"; then
			log "ERROR: failed to remove incomplete backup archive: $archive"
			[[ "$rc" != "0" ]] || rc=1
		fi
	fi
	if ! cleanup; then
		log "ERROR: failed to release backup lock: $lock_dir"
		[[ "$rc" != "0" ]] || rc=1
	fi
	exit "$rc"
}
trap backup_exit_trap EXIT

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
archive="${backup_dir}/trustix-${instance}-${stamp}.tixbak"
log "create encrypted backup for $instance"
$ctl "${ctl_args[@]}" config backup -include-private-keys -recipient "$recipient" -out "$archive"
[[ -s "$archive" ]] || die "encrypted backup was not created: $archive"

if [[ "$verify_after" == "1" ]]; then
  verify_archive "$archive"
fi
backup_archive_complete=1

if ((keep > 0)); then
  shopt -s nullglob
  backups=("$backup_dir/trustix-${instance}-"*.tixbak)
  shopt -u nullglob
  remove_count=$((${#backups[@]} - keep))
  if ((remove_count > 0)); then
    for ((i = 0; i < remove_count; i++)); do
      [[ "${backups[i]}" != "$archive" ]] || die "retention attempted to remove the new backup"
      rm -f -- "${backups[i]}"
    done
  fi
fi

log "encrypted backup complete: $archive"
