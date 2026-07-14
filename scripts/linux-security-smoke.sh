#!/usr/bin/env bash
set -Eeuo pipefail

script_path="$0"
case "$script_path" in
  */*) ;;
  *) script_path="$(command -v -- "$script_path")" ;;
esac
script_dir="$(cd "$(dirname "$script_path")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
workdir="${TRUSTIX_SECURITY_SMOKE_WORKDIR:-$(mktemp -d /tmp/trustix-security-smoke.XXXXXX)}"
keep="${TRUSTIX_SECURITY_SMOKE_KEEP:-0}"
bin_dir="${TRUSTIX_SECURITY_SMOKE_BIN_DIR:-${workdir}/bin}"
run_go_tests="${TRUSTIX_SECURITY_SMOKE_GO_TESTS:-1}"
run_control="${TRUSTIX_SECURITY_SMOKE_CONTROL:-auto}"
run_root="${TRUSTIX_SECURITY_SMOKE_ROOT:-auto}"
run_heavy="${TRUSTIX_SECURITY_SMOKE_HEAVY:-0}"
success=0

log() {
  printf '[trustix-security-smoke] %s\n' "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

enabled() {
  case "${1:-}" in
    1|true|yes|on) return 0 ;;
    0|false|no|off) return 1 ;;
    *) return 2 ;;
  esac
}

cleanup() {
  local rc=$?
  if [[ "$keep" != "1" && "$success" == "1" && -z "${TRUSTIX_SECURITY_SMOKE_WORKDIR:-}" ]]; then
    rm -rf "$workdir"
  else
    log "workdir preserved: $workdir"
  fi
  exit "$rc"
}
trap cleanup EXIT

build_common_binaries() {
  if [[ -x "${bin_dir}/trustixd" && -x "${bin_dir}/trustixctl" && -x "${bin_dir}/trustix-ca" && -x "${bin_dir}/trustix-device" ]]; then
    return 0
  fi
  need_cmd go
  mkdir -p "$bin_dir"
  log "building trustixd/trustixctl/trustix-ca/trustix-device"
  (cd "$repo_root" && go build -o "${bin_dir}/trustixd" ./cmd/trustixd)
  (cd "$repo_root" && go build -o "${bin_dir}/trustixctl" ./cmd/trustixctl)
  (cd "$repo_root" && go build -o "${bin_dir}/trustix-ca" ./cmd/trustix-ca)
  (cd "$repo_root" && go build -o "${bin_dir}/trustix-device" ./cmd/trustix-device)
}

run_security_go_tests() {
  need_cmd go
  local daemon_tests
  daemon_tests='TestHTTPServersSetResourceTimeouts|TestConfigExportAPIRequiresAdminProofWhenEnabled|TestConfigRestoreArchive|TestDeviceAccess|TestEndpointGrant|TestIXProvision|TestManagementWebUI|TestTrustRevokeDropsDeviceAccessSession|TestInboundDeviceSession'
  log "running security-focused Go tests"
  (cd "$repo_root" && go test ./internal/daemon -run "$daemon_tests" -count=1)
  (cd "$repo_root" && go test ./internal/config -count=1)
}

should_run_auto_linux() {
  [[ "$(uname -s)" == "Linux" ]]
}

should_run_root_smoke() {
  case "$run_root" in
    auto)
      [[ "$(uname -s)" == "Linux" && "${EUID:-$(id -u)}" == "0" ]]
      ;;
    1|true|yes|on)
      [[ "$(uname -s)" == "Linux" ]] || die "root smoke requires Linux"
      [[ "${EUID:-$(id -u)}" == "0" ]] || die "root smoke requires root"
      ;;
    0|false|no|off)
      return 1
      ;;
    *)
      die "TRUSTIX_SECURITY_SMOKE_ROOT must be auto, 1, or 0"
      ;;
  esac
}

run_control_smokes() {
  build_common_binaries
  log "running membership smoke"
  TRUSTIX_MEMBERSHIP_SMOKE_BIN_DIR="$bin_dir" \
    TRUSTIX_MEMBERSHIP_SMOKE_WORKDIR="${workdir}/membership" \
    bash "${repo_root}/scripts/linux-membership-smoke.sh"
  log "running trust-policy smoke"
  TRUSTIX_POLICY_SMOKE_BIN_DIR="$bin_dir" \
    TRUSTIX_POLICY_SMOKE_WORKDIR="${workdir}/trust-policy" \
    bash "${repo_root}/scripts/linux-trust-policy-smoke.sh"
}

run_root_smokes() {
  build_common_binaries
  log "running device-access root smoke"
  TRUSTIX_DEVICE_ACCESS_SMOKE_BIN_DIR="$bin_dir" \
    TRUSTIX_DEVICE_ACCESS_SMOKE_WORKDIR="${workdir}/device-access" \
    bash "${repo_root}/scripts/linux-device-access-smoke.sh"

  log "running UDP data-plane root smoke"
  TRUSTIX_E2E_BIN_DIR="$bin_dir" \
    TRUSTIX_E2E_WORKDIR="${workdir}/e2e-udp" \
    TRUSTIX_E2E_TRANSPORT=udp \
    TRUSTIX_E2E_CRASH_RESTART=0 \
    bash "${repo_root}/scripts/linux-e2e-smoke.sh"

  if enabled "$run_heavy"; then
    log "running TCP TLS data-plane root smoke"
    TRUSTIX_E2E_BIN_DIR="$bin_dir" \
      TRUSTIX_E2E_WORKDIR="${workdir}/e2e-tcp" \
      TRUSTIX_E2E_TRANSPORT=tcp \
      TRUSTIX_E2E_CRASH_RESTART=0 \
      bash "${repo_root}/scripts/linux-e2e-smoke.sh"

    log "running tix_tcp data-plane root smoke"
    TRUSTIX_E2E_BIN_DIR="$bin_dir" \
      TRUSTIX_E2E_WORKDIR="${workdir}/e2e-tix-tcp" \
      TRUSTIX_E2E_TRANSPORT=tix_tcp \
      TRUSTIX_E2E_CRASH_RESTART=0 \
      bash "${repo_root}/scripts/linux-e2e-smoke.sh"
  fi
}

main() {
  mkdir -p "$workdir"
  if enabled "$run_go_tests"; then
    run_security_go_tests
  elif [[ "$run_go_tests" != "auto" ]]; then
    case "$run_go_tests" in
      0|false|no|off) ;;
      *) die "TRUSTIX_SECURITY_SMOKE_GO_TESTS must be 1 or 0" ;;
    esac
  fi

  case "$run_control" in
    auto)
      if should_run_auto_linux; then
        run_control_smokes
      else
        log "skip control smokes: not Linux"
      fi
      ;;
    1|true|yes|on)
      should_run_auto_linux || die "control smoke requires Linux"
      run_control_smokes
      ;;
    0|false|no|off)
      log "skip control smokes"
      ;;
    *)
      die "TRUSTIX_SECURITY_SMOKE_CONTROL must be auto, 1, or 0"
      ;;
  esac

  if should_run_root_smoke; then
    run_root_smokes
  else
    log "skip root data-plane smokes"
  fi

  success=1
  log "ok"
}

main "$@"
