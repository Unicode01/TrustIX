#!/usr/bin/env bash
set -Eeuo pipefail

unitdir="${TRUSTIX_INSTALL_SYSTEMD_DIR:-/etc/systemd/system}"
prefix="${TRUSTIX_INSTALL_PREFIX:-/usr/local}"
bindir="${TRUSTIX_INSTALL_BINDIR:-${prefix}/bin}"

log() {
  printf '[trustix-uninstall] %s\n' "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

main() {
  [[ "$(uname -s)" == "Linux" ]] || die "systemd uninstall script must run on Linux"
  [[ "${EUID:-$(id -u)}" == "0" ]] || die "systemd uninstall script must run as root"

  if command -v systemctl >/dev/null 2>&1 && [[ "${TRUSTIX_UNINSTALL_STOP:-0}" == "1" ]]; then
    local units
    units="$(systemctl list-units 'trustixd@*.service' --all --no-legend 2>/dev/null | awk '{print $1}')"
    if [[ -n "$units" ]]; then
      log "stop and disable: $(printf '%s\n' "$units" | tr '\n' ' ')"
      printf '%s\n' "$units" | xargs -r systemctl disable --now
    fi
  fi

  rm -f "${unitdir}/trustixd@.service"
  if [[ "${TRUSTIX_UNINSTALL_BINARIES:-0}" == "1" ]]; then
    rm -f "${bindir}/trustixd" "${bindir}/trustixctl" "${bindir}/trustix-ca" "${bindir}/trustix-device"
  fi
  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
  fi
  log "removed systemd unit. configs under /etc/trustix and state under /var/lib/trustix are left intact"
}

main "$@"
