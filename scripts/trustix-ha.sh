#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ]; then
  echo "ERROR: trustix-ha.sh requires GNU bash" >&2
  exit 2
fi
set -Eeuo pipefail

command_name="${1:-}"
[[ -n "$command_name" ]] && shift || true
instance=""
target_state=""
instance_env=""
ha_env=""

usage() {
  cat <<'EOF'
Usage:
  trustix-ha.sh check --instance IX
  trustix-ha.sh notify --instance IX --state MASTER|BACKUP|FAULT|STOP
  trustix-ha.sh status --instance IX

The helper is intended for keepalived notify/track_script integration. Two
nodes may share one logical IX identity only while fencing guarantees that at
most one trustixd instance is active.
EOF
}

log() {
  printf '[trustix-ha] %s\n' "$*" >&2
  if [[ "${TRUSTIX_HA_LOGGER:-1}" != "0" ]] && command -v logger >/dev/null 2>&1; then
    logger -t trustix-ha -- "$*" 2>/dev/null || true
  fi
}

die() {
  log "ERROR: $*"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --instance) [[ $# -ge 2 ]] || die "--instance requires a value"; instance="$2"; shift 2 ;;
    --state) [[ $# -ge 2 ]] || die "--state requires a value"; target_state="$2"; shift 2 ;;
    --instance-env) [[ $# -ge 2 ]] || die "--instance-env requires a value"; instance_env="$2"; shift 2 ;;
    --ha-env) [[ $# -ge 2 ]] || die "--ha-env requires a value"; ha_env="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

case "$command_name" in
  check|notify|status) ;;
  "") usage; exit 2 ;;
  *) die "command must be check, notify, or status" ;;
esac
[[ -n "$instance" ]] || die "--instance is required"
[[ "$instance" =~ ^[A-Za-z0-9._-]+$ ]] || die "invalid instance name: $instance"

sysconfdir="${TRUSTIX_SYSCONFDIR:-/etc/trustix}"
[[ -n "$instance_env" ]] || instance_env="${sysconfdir}/${instance}.env"
[[ -n "$ha_env" ]] || ha_env="${sysconfdir}/${instance}.ha.env"

load_env_file() {
  local path="$1"
  local purpose="$2"
  local private_file="$3"
  [[ -f "$path" ]] || return 0
  [[ ! -L "$path" ]] || die "refusing symlink env file: $path"
  if [[ "${TRUSTIX_HA_TEST_ALLOW_INSECURE_FILES:-0}" != "1" ]]; then
    command -v stat >/dev/null 2>&1 || die "stat is required to validate $purpose env file: $path"
    local owner mode permissions current_uid
    owner="$(stat -c '%u' "$path" 2>/dev/null || true)"
    mode="$(stat -c '%a' "$path" 2>/dev/null || true)"
    current_uid="${EUID:-$(id -u)}"
    [[ "$owner" =~ ^[0-9]+$ && "$mode" =~ ^[0-7]{3,4}$ ]] || \
      die "could not validate $purpose env file ownership and mode: $path"
    if [[ "$current_uid" == "0" ]]; then
      [[ "$owner" == "0" ]] || die "$purpose env file must be owned by root: $path"
    else
      [[ "$owner" == "$current_uid" ]] || die "$purpose env file must be owned by the current user: $path"
    fi
    permissions=$((8#$mode))
    (( (permissions & 0022) == 0 )) || die "$purpose env file must not be group/world writable: $path"
    if [[ "$private_file" == "1" ]]; then
      (( (permissions & 0077) == 0 )) || die "$purpose env file must have mode 0600 or stricter: $path"
    fi
  fi
  set -a
  # shellcheck disable=SC1090
  source "$path"
  set +a
}

load_env_file "$instance_env" instance 0
load_env_file "$ha_env" HA 1

trustix_bin="${TRUSTIX_BIN:-/usr/local/bin/trustixd}"
config_path="${TRUSTIX_CONFIG:-${sysconfdir}/${instance}.yaml}"
data_dir="${TRUSTIX_DATA_DIR:-/var/lib/trustix/${instance}}"
api_addr="${TRUSTIX_API_ADDR:-127.0.0.1:8787}"
peer_api_addr="${TRUSTIX_PEER_API_ADDR:-0.0.0.0:9443}"
dataplane="${TRUSTIX_DATAPLANE:-auto}"
state_dir="${TRUSTIX_HA_STATE_DIR:-/run/trustix-ha}"
state_file="${state_dir}/${instance}.state"
request_file="${state_dir}/${instance}.request"
lock_dir="${state_dir}/${instance}.notify.lock"
lock_pid_file="${lock_dir}/pid"
start_timeout="${TRUSTIX_HA_START_TIMEOUT:-30}"
stop_timeout="${TRUSTIX_HA_STOP_TIMEOUT:-15}"
promotion_grace="${TRUSTIX_HA_PROMOTION_GRACE:-45}"
lock_timeout="${TRUSTIX_HA_LOCK_TIMEOUT:-$((start_timeout + promotion_grace + 30))}"
service_manager="${TRUSTIX_HA_SERVICE_MANAGER:-auto}"
require_fence="${TRUSTIX_HA_REQUIRE_FENCE:-1}"
pre_promote_hook="${TRUSTIX_HA_PRE_PROMOTE_HOOK:-}"
fence_hook="${TRUSTIX_HA_FENCE_HOOK:-}"
openwrt_init="${TRUSTIX_HA_OPENWRT_INIT:-/etc/init.d/trustix}"
notify_lock_held=0

[[ -x "$trustix_bin" ]] || die "trustixd is not executable: $trustix_bin"
[[ "$start_timeout" =~ ^[1-9][0-9]*$ ]] || die "TRUSTIX_HA_START_TIMEOUT must be a positive integer"
[[ "$stop_timeout" =~ ^[1-9][0-9]*$ ]] || die "TRUSTIX_HA_STOP_TIMEOUT must be a positive integer"
[[ "$promotion_grace" =~ ^[1-9][0-9]*$ ]] || die "TRUSTIX_HA_PROMOTION_GRACE must be a positive integer"
[[ "$lock_timeout" =~ ^[1-9][0-9]*$ ]] || die "TRUSTIX_HA_LOCK_TIMEOUT must be a positive integer"
case "$require_fence" in
  0|false|no|off|1|true|yes|on) ;;
  *) die "TRUSTIX_HA_REQUIRE_FENCE must be a boolean" ;;
esac

detect_service_manager() {
  case "$service_manager" in
    systemd|openwrt) printf '%s\n' "$service_manager"; return ;;
    auto) ;;
    *) die "TRUSTIX_HA_SERVICE_MANAGER must be auto, systemd, or openwrt" ;;
  esac
  if [[ -f /etc/openwrt_release && -x "$openwrt_init" ]]; then
    printf 'openwrt\n'
  elif command -v systemctl >/dev/null 2>&1; then
    printf 'systemd\n'
  else
    die "could not detect service manager"
  fi
}
service_manager="$(detect_service_manager)"
if [[ "$service_manager" == "openwrt" ]]; then
  [[ "$openwrt_init" == /* && -x "$openwrt_init" ]] || \
    die "TRUSTIX_HA_OPENWRT_INIT must be an absolute executable file: $openwrt_init"
fi

normalize_state() {
  case "${1^^}" in
    MASTER) printf 'MASTER\n' ;;
    BACKUP) printf 'BACKUP\n' ;;
    FAULT) printf 'FAULT\n' ;;
    STOP|STOPPED) printf 'STOP\n' ;;
    PROMOTING) printf 'PROMOTING\n' ;;
    *) return 1 ;;
  esac
}

ensure_state_dir() {
  [[ ! -L "$state_dir" ]] || die "HA state directory must not be a symlink: $state_dir"
  mkdir -p "$state_dir"
  [[ -d "$state_dir" && ! -L "$state_dir" ]] || die "could not create HA state directory: $state_dir"
  chmod 0700 "$state_dir" 2>/dev/null || true
}

write_record() {
  local path="$1"
  local state="$2"
  local now tmp
  ensure_state_dir
  [[ ! -L "$path" ]] || die "refusing symlink HA state file: $path"
  now="$(date +%s)"
  tmp="${path}.tmp.$$"
  printf '%s %s\n' "$state" "$now" >"$tmp"
  chmod 0600 "$tmp"
  mv -f "$tmp" "$path"
}

write_state() {
  write_record "$state_file" "$1"
}

write_request() {
  write_record "$request_file" "$1"
}

read_state() {
  local state="BACKUP" changed_at="0"
  if [[ -f "$state_file" && ! -L "$state_file" ]]; then
    read -r state changed_at <"$state_file" || true
  fi
  state="$(normalize_state "$state" 2>/dev/null || printf 'FAULT\n')"
  [[ "$changed_at" =~ ^[0-9]+$ ]] || changed_at=0
  printf '%s %s\n' "$state" "$changed_at"
}

read_request() {
  local state="FAULT" changed_at="0"
  if [[ -f "$request_file" && ! -L "$request_file" ]]; then
    read -r state changed_at <"$request_file" || true
  fi
  state="$(normalize_state "$state" 2>/dev/null || printf 'FAULT\n')"
  [[ "$changed_at" =~ ^[0-9]+$ ]] || changed_at=0
  printf '%s %s\n' "$state" "$changed_at"
}

offline_preflight() {
  "$trustix_bin" \
    -config "$config_path" \
    -data-dir "$data_dir" \
    -api "$api_addr" \
    -peer-api "$peer_api_addr" \
    -dataplane "$dataplane" \
    -check-config >/dev/null
}

api_base_urls() {
  local address="$1"
  local host port url_host
  if [[ -n "${TRUSTIX_HA_READY_URL:-}" ]]; then
    printf '%s\n' "${TRUSTIX_HA_READY_URL%/}"
    return
  fi
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
  if [[ "$host" == *:* ]]; then url_host="[$host]"; else url_host="$host"; fi
  case "${TRUSTIX_HA_API_SCHEME:-auto}" in
    http) printf 'http://%s:%s\n' "$url_host" "$port" ;;
    https) printf 'https://%s:%s\n' "$url_host" "$port" ;;
    auto)
      printf 'http://%s:%s\nhttps://%s:%s\n' "$url_host" "$port" "$url_host" "$port"
      ;;
    *) die "TRUSTIX_HA_API_SCHEME must be auto, http, or https" ;;
  esac
}

probe_ready_url() {
  local base="$1"
  if command -v curl >/dev/null 2>&1; then
    curl -kfsS --connect-timeout 1 --max-time 2 "${base}/readyz" >/dev/null 2>&1 && return 0
  fi
  if command -v wget >/dev/null 2>&1; then
    wget --no-check-certificate -q -T 2 -O /dev/null "${base}/readyz" >/dev/null 2>&1 && return 0
  fi
  return 1
}

ready_probe() {
  local base
  while IFS= read -r base; do
    [[ -n "$base" ]] || continue
    probe_ready_url "$base" && return 0
  done < <(api_base_urls "$api_addr")
  return 1
}

service_start() {
  case "$service_manager" in
    systemd) systemctl start "trustixd@${instance}.service" ;;
    openwrt) "$openwrt_init" start "$instance" ;;
  esac
}

service_stop() {
  case "$service_manager" in
    systemd) systemctl stop "trustixd@${instance}.service" ;;
    openwrt) "$openwrt_init" stop "$instance" ;;
  esac
}

openwrt_process_active() {
  local name pid cmdline
  name="${trustix_bin##*/}"
  if command -v pidof >/dev/null 2>&1; then
    for pid in $(pidof "$name" 2>/dev/null || true); do
      cmdline="/proc/${pid}/cmdline"
      [[ -r "$cmdline" ]] || continue
      if tr '\000' '\n' <"$cmdline" 2>/dev/null | grep -Fqx -- "$config_path"; then
        return 0
      fi
    done
  fi
  return 1
}

service_is_active() {
  case "$service_manager" in
    systemd)
      systemctl is-active --quiet "trustixd@${instance}.service"
      ;;
    openwrt)
      "$openwrt_init" running "$instance" >/dev/null 2>&1 || openwrt_process_active
      ;;
  esac
}

service_stop_verified() {
  local deadline=$((SECONDS + stop_timeout))
  service_stop >/dev/null 2>&1 || true
  while ((SECONDS < deadline)); do
    service_is_active || return 0
    sleep 1
  done
  ! service_is_active
}

secure_hook() {
  local path="$1"
  local purpose="$2"
  [[ -n "$path" ]] || return 0
  if [[ "$path" != /* || ! -f "$path" || -L "$path" || ! -x "$path" ]]; then
    log "ERROR: $purpose hook must be an absolute executable regular file: $path"
    return 1
  fi
  if command -v stat >/dev/null 2>&1; then
    local owner mode current_uid
    owner="$(stat -c '%u' "$path" 2>/dev/null || true)"
    mode="$(stat -c '%a' "$path" 2>/dev/null || true)"
    current_uid="${EUID:-$(id -u)}"
    if [[ ! "$owner" =~ ^[0-9]+$ || ! "$mode" =~ ^[0-7]{3,4}$ ]]; then
      log "ERROR: could not validate $purpose hook ownership and mode: $path"
      return 1
    fi
    if [[ "$current_uid" == "0" && "$owner" != "0" && "${TRUSTIX_HA_TEST_ALLOW_NONROOT_HOOKS:-0}" != "1" ]]; then
      log "ERROR: $purpose hook must be owned by root: $path"
      return 1
    fi
    if [[ "$current_uid" != "0" && "$owner" != "$current_uid" ]]; then
      log "ERROR: $purpose hook must be owned by the current user: $path"
      return 1
    fi
    local permissions=$((8#$mode))
    if (( (permissions & 0022) != 0 )); then
      log "ERROR: $purpose hook must not be group/world writable: $path"
      return 1
    fi
  else
    log "ERROR: stat is required to validate $purpose hook: $path"
    return 1
  fi
  TRUSTIX_HA_INSTANCE="$instance" TRUSTIX_HA_TARGET_STATE="MASTER" "$path"
}

wait_ready() {
  local deadline=$((SECONDS + start_timeout))
  while ((SECONDS < deadline)); do
    if ! promotion_still_requested; then
      return 2
    fi
    if service_is_active && ready_probe; then
      return 0
    fi
    sleep 1
  done
  return 1
}

promotion_still_requested() {
  local requested _
  read -r requested _ < <(read_request)
  [[ "$requested" == "MASTER" ]]
}

release_notify_lock() {
  local owner=""
  [[ "$notify_lock_held" == "1" ]] || return 0
  if [[ -f "$lock_pid_file" && ! -L "$lock_pid_file" ]]; then
    read -r owner _ <"$lock_pid_file" || true
  fi
  if [[ "$owner" == "$$" ]]; then
    rm -f "$lock_pid_file"
    rmdir "$lock_dir" 2>/dev/null || true
  fi
  notify_lock_held=0
}

acquire_notify_lock() {
  local deadline=$((SECONDS + lock_timeout))
  local owner=""
  ensure_state_dir
  while ((SECONDS < deadline)); do
    if mkdir "$lock_dir" 2>/dev/null; then
      printf '%s %s\n' "$$" "$(date +%s)" >"$lock_pid_file"
      chmod 0600 "$lock_pid_file"
      notify_lock_held=1
      return 0
    fi
    [[ -d "$lock_dir" && ! -L "$lock_dir" ]] || \
      die "HA notification lock is not a safe directory: $lock_dir"
    owner=""
    if [[ -f "$lock_pid_file" && ! -L "$lock_pid_file" ]]; then
      read -r owner _ <"$lock_pid_file" || true
    fi
    if [[ ! "$owner" =~ ^[1-9][0-9]*$ ]] || ! kill -0 "$owner" >/dev/null 2>&1; then
      rm -f "$lock_pid_file"
      rmdir "$lock_dir" 2>/dev/null || true
      continue
    fi
    sleep 1
  done
  return 1
}

complete_cancelled_promotion() {
  local requested _
  read -r requested _ < <(read_request)
  case "$requested" in
    BACKUP|FAULT|STOP) ;;
    *) requested="FAULT" ;;
  esac
  if ! service_stop_verified; then
    write_state FAULT
    die "promotion was cancelled but trustixd could not be confirmed stopped"
  fi
  write_state "$requested"
  log "cancelled promotion of $instance and settled in $requested"
}

fail_promotion() {
  local message="$1"
  write_state FAULT
  if ! service_stop_verified; then
    die "$message; trustixd could not be confirmed stopped"
  fi
  die "$message"
}

run_check() {
  local state changed_at now requested _
  read -r state changed_at < <(read_state)
  case "$state" in
    BACKUP|STOP)
      service_is_active && return 1
      offline_preflight
      ;;
    PROMOTING)
      read -r requested _ < <(read_request)
      [[ "$requested" == "MASTER" ]] || return 1
      now="$(date +%s)"
      if ((now >= changed_at && now - changed_at <= promotion_grace)); then
        offline_preflight
      else
        service_is_active && ready_probe
      fi
      ;;
    MASTER)
      service_is_active && ready_probe
      ;;
    FAULT)
      return 1
      ;;
    *)
      return 1
      ;;
  esac
}

run_notify() {
  local state="$1"
  local wait_status
  write_request "$state"
  if ! acquire_notify_lock; then
    if [[ "$state" != "MASTER" ]]; then
      service_stop_verified >/dev/null 2>&1 || true
      write_state FAULT
    fi
    die "timed out waiting for another HA notification for $instance"
  fi
  trap release_notify_lock EXIT

  case "$state" in
    MASTER)
      case "$require_fence" in
        1|true|yes|on)
          if [[ -z "$fence_hook" ]]; then
            fail_promotion "fencing is required but TRUSTIX_HA_FENCE_HOOK is empty"
          fi
          ;;
      esac
      write_state PROMOTING
      if ! service_stop_verified; then
        fail_promotion "candidate trustixd could not be stopped before promotion"
      fi
      if ! promotion_still_requested; then
        complete_cancelled_promotion
        return
      fi
      if ! secure_hook "$fence_hook" fencing; then
        fail_promotion "fencing hook failed; refusing promotion"
      fi
      if ! promotion_still_requested; then
        complete_cancelled_promotion
        return
      fi
      if ! secure_hook "$pre_promote_hook" pre-promote; then
        fail_promotion "pre-promote hook failed; refusing promotion"
      fi
      if ! promotion_still_requested; then
        complete_cancelled_promotion
        return
      fi
      if ! offline_preflight; then
        fail_promotion "candidate config preflight failed; refusing promotion"
      fi
      if ! promotion_still_requested; then
        complete_cancelled_promotion
        return
      fi
      if ! service_start; then
        fail_promotion "failed to start trustixd for promotion"
      fi
      if wait_ready; then
        wait_status=0
      else
        wait_status=$?
      fi
      if [[ "$wait_status" == "2" ]]; then
        complete_cancelled_promotion
        return
      fi
      if [[ "$wait_status" != "0" ]]; then
        fail_promotion "trustixd did not become ready within ${start_timeout}s"
      fi
      if ! promotion_still_requested; then
        complete_cancelled_promotion
        return
      fi
      write_state MASTER
      log "promoted $instance to MASTER and readiness passed"
      ;;
    BACKUP|FAULT|STOP)
      if ! service_stop_verified; then
        write_state FAULT
        die "could not confirm trustixd stopped while entering $state"
      fi
      write_state "$state"
      log "demoted $instance to $state and stopped trustixd"
      ;;
  esac
}

case "$command_name" in
  check)
    run_check
    ;;
  status)
    read_state
    if ready_probe; then printf 'ready=true\n'; else printf 'ready=false\n'; fi
    if service_is_active; then printf 'service_active=true\n'; else printf 'service_active=false\n'; fi
    ;;
  notify)
    [[ -n "$target_state" ]] || die "notify requires --state"
    target_state="$(normalize_state "$target_state")" || die "invalid HA state: $target_state"
    run_notify "$target_state"
    ;;
esac
