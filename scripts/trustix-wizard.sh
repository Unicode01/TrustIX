#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ]; then
  echo "ERROR: scripts/trustix-wizard.sh requires GNU bash 4+" >&2
  exit 2
fi
set -Eeuo pipefail

wizard_repo_root() {
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

if ! repo_root="$(wizard_repo_root)"; then
  repo_url="${TRUSTIX_BOOTSTRAP_REPO:-https://github.com/Unicode01/TrustIX.git}"
  repo_ref="${TRUSTIX_BOOTSTRAP_REF:-main}"
  repo_root="${TRUSTIX_BOOTSTRAP_WORKDIR:-}"
  if [[ -z "$repo_root" ]]; then
    repo_root="$(mktemp -d /tmp/trustix-wizard-src.XXXXXX)"
  fi
  if [[ ! -f "${repo_root}/go.mod" ]]; then
    command -v git >/dev/null 2>&1 || {
      echo "ERROR: git is required when running the wizard from curl" >&2
      exit 127
    }
    mkdir -p "$repo_root"
    if [[ -n "$(find "$repo_root" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
      echo "ERROR: TRUSTIX_BOOTSTRAP_WORKDIR is not a TrustIX repo and is not empty: ${repo_root}" >&2
      exit 1
    fi
    git clone --depth 1 --branch "$repo_ref" "$repo_url" "$repo_root" >&2
  fi
  exec bash "${repo_root}/scripts/trustix-wizard.sh" "$@"
fi

usage() {
  cat <<'EOF'
usage: scripts/trustix-wizard.sh [--first-ix|--join-token]

Interactive first-run helper for new TrustIX users.

Modes:
  --first-ix       Create a new domain and first IX on this machine
  --join-token     Join an existing domain with a WebUI-issued provision token

The wizard calls the stable automation scripts underneath:
  scripts/trustix-bootstrap-ix.sh

Curl usage:
  curl -fsSL https://raw.githubusercontent.com/Unicode01/TrustIX/main/scripts/trustix-wizard.sh | sudo bash

EOF
}

log() {
  printf '[trustix-wizard] %s\n' "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

need_tty() {
  [[ -r /dev/tty && -w /dev/tty ]] || die "interactive terminal is required"
}

prompt() {
  local label="$1"
  local default_value="${2:-}"
  local value=""
  need_tty
  if [[ -n "$default_value" ]]; then
    printf '%s [%s]: ' "$label" "$default_value" > /dev/tty
  else
    printf '%s: ' "$label" > /dev/tty
  fi
  IFS= read -r value < /dev/tty || true
  if [[ -z "$value" ]]; then
    value="$default_value"
  fi
  printf '%s\n' "$value"
}

prompt_required() {
  local label="$1"
  local default_value="${2:-}"
  local value=""
  while [[ -z "$value" ]]; do
    value="$(prompt "$label" "$default_value")"
  done
  printf '%s\n' "$value"
}

prompt_yes_no() {
  local label="$1"
  local default_value="${2:-Y}"
  local value=""
  while :; do
    value="$(prompt "$label (y/n)" "$default_value")"
    case "$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')" in
      y|yes|1|true|on) return 0 ;;
      n|no|0|false|off) return 1 ;;
      *) log "Please answer y or n" ;;
    esac
  done
}

default_host() {
  local host=""
  host="$(hostname -f 2>/dev/null || hostname 2>/dev/null || true)"
  [[ -n "$host" ]] || host="ix.example.net"
  printf '%s\n' "$host"
}

host_from_url() {
  local value="$1"
  value="${value#*://}"
  value="${value%%/*}"
  value="${value%%:*}"
  printf '%s\n' "$value"
}

prefix_from_gateway() {
  local value="$1"
  local ip="${value%%/*}"
  local mask="${value##*/}"
  if [[ "$mask" == "24" && "$ip" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)\.[0-9]+$ ]]; then
    printf '%s.%s.%s.0/24\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"
    return
  fi
  printf '10.44.0.0/24\n'
}

find_trustix_ca_cmd() {
  if [[ -n "${TRUSTIX_CA_BIN:-}" ]]; then
    printf '%s\n' "$TRUSTIX_CA_BIN"
    return 0
  fi
  if command -v trustix-ca >/dev/null 2>&1; then
    command -v trustix-ca
    return 0
  fi
  if command -v go >/dev/null 2>&1; then
    printf 'go run ./cmd/trustix-ca\n'
    return 0
  fi
  return 1
}

run_trustix_ca() {
  local cmd="$1"
  shift
  if [[ "$cmd" == go\ run* ]]; then
    (cd "$repo_root" && go run ./cmd/trustix-ca "$@")
  else
    "$cmd" "$@"
  fi
}

ensure_first_domain_certs() {
  local domain_id="$1"
  local ix_id="$2"
  local cert_dir="$3"
  if [[ -f "${cert_dir}/domain-ca.pem" && -f "${cert_dir}/domain-ca.key" && -f "${cert_dir}/config-ca.pem" && -f "${cert_dir}/config-ca.key" ]]; then
    log "reuse existing CA material in ${cert_dir}"
    return
  fi
  local ca_cmd
  ca_cmd="$(find_trustix_ca_cmd)" || die "trustix-ca or Go is required to create the first domain"
  mkdir -p "$cert_dir"
  log "create domain CA, config CA, admin cert, and initial IX certs in ${cert_dir}"
  run_trustix_ca "$ca_cmd" quickstart -out "$cert_dir" -domain "$domain_id" -ix "$ix_id" >/dev/null
}

run_first_ix() {
  local host default_control_api domain_id ix_id cert_dir control_api lan_iface lan_gateway advertise underlay_iface endpoint_transport endpoint_listen endpoint_address api_addr peer_api_addr dataplane kernel_modules
  host="$(default_host)"
  default_control_api="https://${host}:9443"

  domain_id="$(prompt_required "Domain ID" "trustix.local")"
  ix_id="$(prompt_required "First IX ID" "ix-a")"
  cert_dir="$(prompt_required "Local CA/cert directory" "certs")"
  control_api="$(prompt_required "Published IX control API URL" "$default_control_api")"
  host="$(host_from_url "$control_api")"
  lan_iface="$(prompt_required "LAN interface" "br-lan")"
  lan_gateway="$(prompt_required "LAN gateway CIDR managed by this IX" "10.44.0.1/24")"
  advertise="$(prompt_required "LAN prefix to advertise" "$(prefix_from_gateway "$lan_gateway")")"
  underlay_iface="$(prompt "Underlay/WAN interface for kernel fast paths" "")"
  endpoint_transport="$(prompt_required "Default data transport" "udp")"
  endpoint_listen="$(prompt_required "Data endpoint listen address" "0.0.0.0:7000")"
  endpoint_address="$(prompt_required "Published data endpoint address" "${host}:7000")"
  api_addr="$(prompt_required "Management/WebUI listen address" "127.0.0.1:8787")"
  peer_api_addr="$(prompt_required "Peer control listen address" "0.0.0.0:9443")"
  dataplane="$(prompt_required "Dataplane mode" "auto")"
  kernel_modules="$(prompt_required "Kernel module mode" "auto")"

  ensure_first_domain_certs "$domain_id" "$ix_id" "$cert_dir"

  local args=(
    --ix "$ix_id"
    --domain "$domain_id"
    --source-certs "$cert_dir"
    --control-api "$control_api"
    --lan-iface "$lan_iface"
    --lan-gateway "$lan_gateway"
    --advertise "$advertise"
    --endpoint "name=${ix_id}-${endpoint_transport};transport=${endpoint_transport};mode=passive;listen=${endpoint_listen};address=${endpoint_address}"
    --api "$api_addr"
    --peer-api "$peer_api_addr"
    --dataplane "$dataplane"
    --kernel-modules "$kernel_modules"
    --json
  )
  if [[ -n "$underlay_iface" ]]; then
    args+=(--underlay-iface "$underlay_iface")
  fi
  if prompt_yes_no "Build, install, and start this IX on the local host" "Y"; then
    args+=(--local-install)
  else
    args+=(--no-deploy)
  fi

  log "run bootstrap for ${ix_id}"
  "${repo_root}/scripts/trustix-bootstrap-ix.sh" "${args[@]}"
}

run_join_token() {
  local provision_url token
  provision_url="$(prompt_required "Existing IX provision URL" "https://ix-a.example.net:8787")"
  token="$(prompt_required "One-time provision token" "")"
  log "join domain with provision token"
  "${repo_root}/scripts/trustix-bootstrap-ix.sh" --provision-url "$provision_url" --token "$token"
}

mode=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --first-ix) mode="first"; shift ;;
    --join-token) mode="join-token"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

if [[ -z "$mode" ]]; then
  need_tty
  log "Select setup mode:"
  printf '  1) Create a new domain and first IX on this machine\n' > /dev/tty
  printf '  2) Join an existing domain with a WebUI provision token\n' > /dev/tty
  choice="$(prompt_required "Mode" "1")"
  case "$choice" in
    1|first|first-ix) mode="first" ;;
    2|join|join-token) mode="join-token" ;;
    *) die "unknown mode: $choice" ;;
  esac
fi

case "$mode" in
  first) run_first_ix ;;
  join-token) run_join_token ;;
  *) die "unknown mode: $mode" ;;
esac
