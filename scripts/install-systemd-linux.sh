#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

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

install_goarch="$(normalize_goarch "${TRUSTIX_INSTALL_GOARCH:-${GOARCH:-$(host_goarch)}}")"
prefix="${TRUSTIX_INSTALL_PREFIX:-/usr/local}"
bindir="${TRUSTIX_INSTALL_BINDIR:-${prefix}/bin}"
sysconfdir="${TRUSTIX_INSTALL_SYSCONFDIR:-/etc/trustix}"
unitdir="${TRUSTIX_INSTALL_SYSTEMD_DIR:-/etc/systemd/system}"
state_root="${TRUSTIX_INSTALL_STATE_ROOT:-/var/lib/trustix}"
docdir="${TRUSTIX_INSTALL_DOCDIR:-/usr/share/doc/trustix}"
unit_src="${TRUSTIX_INSTALL_UNIT:-${repo_root}/packaging/systemd/trustixd@.service}"
backup_unit_src="${TRUSTIX_INSTALL_BACKUP_UNIT:-${repo_root}/packaging/systemd/trustix-backup@.service}"
backup_timer_src="${TRUSTIX_INSTALL_BACKUP_TIMER:-${repo_root}/packaging/systemd/trustix-backup@.timer}"
backup_script_src="${TRUSTIX_INSTALL_BACKUP_SCRIPT:-${repo_root}/scripts/trustix-backup.sh}"

log() {
  printf '[trustix-install] %s\n' "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

find_bin_dir() {
  local candidate
  for candidate in "${TRUSTIX_INSTALL_BIN_DIR:-}" "${repo_root}/bin" "${repo_root}/build/linux-${install_goarch}"; do
    [[ -n "$candidate" ]] || continue
    if [[ -x "${candidate}/trustixd" && -x "${candidate}/trustixctl" && -x "${candidate}/trustix-ca" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

main() {
  [[ "$(uname -s)" == "Linux" ]] || die "systemd install script must run on Linux"
  [[ "${EUID:-$(id -u)}" == "0" ]] || die "systemd install script must run as root"
  need_cmd install

  local bin_src
  bin_src="$(find_bin_dir)" || die "could not find trustix binaries; set TRUSTIX_INSTALL_BIN_DIR"
  [[ -f "$unit_src" ]] || die "missing systemd unit: $unit_src"

  log "install binaries from ${bin_src} to ${bindir}"
  install -D -m 0755 "${bin_src}/trustixd" "${bindir}/trustixd"
  install -D -m 0755 "${bin_src}/trustixctl" "${bindir}/trustixctl"
  install -D -m 0755 "${bin_src}/trustix-ca" "${bindir}/trustix-ca"
  if [[ -f "$backup_script_src" ]]; then
    install -D -m 0755 "$backup_script_src" "${prefix}/libexec/trustix/trustix-backup.sh"
  fi

  log "install systemd unit to ${unitdir}"
  install -D -m 0644 "$unit_src" "${unitdir}/trustixd@.service"
  if [[ -f "$backup_unit_src" && -f "$backup_timer_src" ]]; then
    install -D -m 0644 "$backup_unit_src" "${unitdir}/trustix-backup@.service"
    install -D -m 0644 "$backup_timer_src" "${unitdir}/trustix-backup@.timer"
  fi
  mkdir -p "$sysconfdir" "$state_root" "$docdir" /var/backups/trustix
  chmod 0700 /var/backups/trustix
  if [[ -d "${repo_root}/docs" ]]; then
    cp -R "${repo_root}/docs/." "$docdir/"
  fi

  if [[ ! -f "${sysconfdir}/example.env" ]]; then
    cat >"${sysconfdir}/example.env" <<EOF
TRUSTIX_CONFIG=${sysconfdir}/example.yaml
TRUSTIX_DATA_DIR=${state_root}/example
TRUSTIX_API_ADDR=127.0.0.1:8787
TRUSTIX_PEER_API_ADDR=0.0.0.0:9443
TRUSTIX_DATAPLANE=auto
TRUSTIX_EXTRA_ARGS=
EOF
    chmod 0644 "${sysconfdir}/example.env"
  fi

  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    log "installed. create ${sysconfdir}/<name>.yaml and optional ${sysconfdir}/<name>.env, then run: systemctl enable --now trustixd@<name>"
    log "encrypted backup timer is available after creating ${sysconfdir}/<name>.backup.env: systemctl enable --now trustix-backup@<name>.timer"
  else
    log "installed, but systemctl was not found; reload systemd manually if needed"
  fi
}

main "$@"
