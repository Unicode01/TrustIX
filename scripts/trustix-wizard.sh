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
    mkdir -p "$repo_root"
    if [[ -n "$(find "$repo_root" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
      echo "ERROR: TRUSTIX_BOOTSTRAP_WORKDIR is not a TrustIX repo and is not empty: ${repo_root}" >&2
      exit 1
    fi
    if command -v git >/dev/null 2>&1; then
      git clone --depth 1 --branch "$repo_ref" "$repo_url" "$repo_root" >&2
    elif { command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1; } && command -v tar >/dev/null 2>&1 && [[ "$repo_url" == https://github.com/* ]]; then
      archive_url="${repo_url%.git}/archive/${repo_ref}.tar.gz"
      archive_path="$(mktemp /tmp/trustix-wizard-src.XXXXXX.tar.gz)"
      if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$archive_url" -o "$archive_path"
      else
        wget -qO "$archive_path" "$archive_url"
      fi
      tar -xzf "$archive_path" -C "$repo_root" --strip-components=1
      rm -f "$archive_path"
    else
      echo "ERROR: git is required to clone ${repo_url}; alternatively install curl/wget+tar for GitHub archive bootstrap" >&2
      exit 127
    fi
  fi
  exec bash "${repo_root}/scripts/trustix-wizard.sh" "$@"
fi

usage() {
  cat <<'EOF'
usage: scripts/trustix-wizard.sh [--first-ix|--join-token] [options]

Interactive first-run helper for new TrustIX users.

Modes:
  --first-ix       Create a new domain and first IX on this machine
  --join-token     Join an existing domain with a WebUI-issued provision token

Non-interactive:
  --yes, --non-interactive
                   Use defaults for omitted optional fields; fail if a required
                   field has no value

First IX options:
  --domain DOMAIN
  --ix ID
  --source-certs DIR, --cert-dir DIR
  --control-api URL
  --lan-iface IFACE
  --lan-gateway CIDR
  --advertise CIDR
  --underlay-iface IFACE
  --endpoint-transport TRANSPORT
  --endpoint-listen ADDR
  --endpoint-address ADDR
  --endpoint-source-ip IP
  --endpoint-bind-iface IFACE
  --api ADDR
  --peer-api ADDR
  --dataplane auto|linux|noop
  --service-manager auto|systemd|openwrt
  --dns-enabled 0|1
  --dns-domain DOMAIN
  --openwrt-dnsmasq 0|1
  --kernel-modules auto|disabled|required
  --local-install
  --no-deploy, --no-install

Join token options:
  --provision-url URL
  --token TOKEN

The wizard calls the stable automation scripts underneath:
  scripts/trustix-bootstrap-ix.sh

Curl usage:
  curl -fsSL https://raw.githubusercontent.com/Unicode01/TrustIX/main/scripts/trustix-wizard.sh | sudo bash

Environment:
  TRUSTIX_BOOTSTRAP_INSTALL_DEPS=0 disables automatic package installation.

EOF
}

log() {
  printf '[trustix-wizard] %s\n' "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

export TRUSTIX_REPO_ROOT="${TRUSTIX_REPO_ROOT:-$repo_root}"
# shellcheck source=scripts/trustix-prereqs.sh
source "${repo_root}/scripts/trustix-prereqs.sh"

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

lower_ascii() {
  local value="$1"
  printf '%s' "${value,,}"
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
    case "$(lower_ascii "$value")" in
      y|yes|1|true|on) return 0 ;;
      n|no|0|false|off) return 1 ;;
      *) log "Please answer y or n" ;;
    esac
  done
}

value_or_prompt() {
  local value="$1"
  local label="$2"
  local default_value="${3:-}"
  if [[ -n "$value" ]]; then
    printf '%s\n' "$value"
    return
  fi
  if [[ "${assume_defaults:-0}" == "1" ]]; then
    printf '%s\n' "$default_value"
    return
  fi
  prompt "$label" "$default_value"
}

value_or_prompt_required() {
  local value="$1"
  local label="$2"
  local default_value="${3:-}"
  if [[ -n "$value" ]]; then
    printf '%s\n' "$value"
    return
  fi
  if [[ "${assume_defaults:-0}" == "1" ]]; then
    [[ -n "$default_value" ]] || die "${label} is required"
    printf '%s\n' "$default_value"
    return
  fi
  prompt_required "$label" "$default_value"
}

flag_or_prompt_yes_no() {
  local value="$1"
  local label="$2"
  local default_value="${3:-Y}"
  case "$(lower_ascii "$value")" in
    1|true|yes|y|on) return 0 ;;
    0|false|no|n|off) return 1 ;;
  esac
  if [[ "${assume_defaults:-0}" == "1" ]]; then
    case "$(lower_ascii "$default_value")" in
      1|true|yes|y|on) return 0 ;;
      *) return 1 ;;
    esac
  fi
  prompt_yes_no "$label" "$default_value"
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

absolute_path() {
  local value="$1"
  [[ -n "$value" ]] || return 0
  case "$value" in
    /*) printf '%s\n' "$value" ;;
    *) printf '%s/%s\n' "$(pwd -P)" "$value" ;;
  esac
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
  if ! ca_cmd="$(find_trustix_ca_cmd)"; then
    trustix_prereqs_ensure_ca_deps || die "trustix-ca or Go is required to create the first domain; automatic dependency install failed"
    ca_cmd="$(find_trustix_ca_cmd)" || die "trustix-ca or Go is required to create the first domain"
  fi
  mkdir -p "$cert_dir"
  log "create domain CA, config CA, admin cert, and initial IX certs in ${cert_dir}"
  run_trustix_ca "$ca_cmd" quickstart -out "$cert_dir" -domain "$domain_id" -ix "$ix_id" >/dev/null
}

run_first_ix() {
  local host default_control_api domain_id ix_id cert_dir control_api lan_iface lan_gateway advertise underlay_iface endpoint_transport endpoint_listen endpoint_address endpoint_source_ip endpoint_bind_iface api_addr peer_api_addr dataplane service_manager dns_enabled dns_domain openwrt_dnsmasq dnsmasq_default kernel_modules endpoint_spec
  host="$(default_host)"
  default_control_api="https://${host}:9443"

  domain_id="$(value_or_prompt_required "$first_domain_id" "Domain ID" "trustix.local")"
  ix_id="$(value_or_prompt_required "$first_ix_id" "First IX ID" "ix-a")"
  cert_dir="$(value_or_prompt_required "$first_cert_dir" "Local CA/cert directory" "certs")"
  cert_dir="$(absolute_path "$cert_dir")"
  control_api="$(value_or_prompt_required "$first_control_api" "Published IX control API URL" "$default_control_api")"
  host="$(host_from_url "$control_api")"
  lan_iface="$(value_or_prompt_required "$first_lan_iface" "LAN interface" "br-lan")"
  lan_gateway="$(value_or_prompt_required "$first_lan_gateway" "LAN gateway CIDR managed by this IX" "10.44.0.1/24")"
  advertise="$(value_or_prompt_required "$first_advertise" "LAN prefix to advertise" "$(prefix_from_gateway "$lan_gateway")")"
  underlay_iface="$(value_or_prompt "$first_underlay_iface" "Underlay/WAN interface for kernel fast paths" "")"
  endpoint_transport="$(value_or_prompt_required "$first_endpoint_transport" "Default data transport" "udp")"
  endpoint_listen="$(value_or_prompt_required "$first_endpoint_listen" "Data endpoint listen address" "0.0.0.0:7000")"
  endpoint_address="$(value_or_prompt_required "$first_endpoint_address" "Published data endpoint address" "${host}:7000")"
  endpoint_source_ip="$(value_or_prompt "$first_endpoint_source_ip" "Outbound source IP for this data endpoint" "")"
  endpoint_bind_iface="$(value_or_prompt "$first_endpoint_bind_iface" "Outbound bind interface for this data endpoint" "")"
  api_addr="$(value_or_prompt_required "$first_api_addr" "Management/WebUI listen address" "127.0.0.1:8787")"
  peer_api_addr="$(value_or_prompt_required "$first_peer_api_addr" "Peer control listen address" "0.0.0.0:9443")"
  dataplane="$(value_or_prompt_required "$first_dataplane" "Dataplane mode" "auto")"
  service_manager="$(value_or_prompt_required "$first_service_manager" "Service manager (auto/systemd/openwrt)" "auto")"
  dns_enabled=0
  openwrt_dnsmasq=0
  dns_domain=""
  case "$(lower_ascii "$first_openwrt_dnsmasq")" in
    1|true|yes|y|on) first_dns_enabled=1 ;;
  esac
  if flag_or_prompt_yes_no "$first_dns_enabled" "Enable TrustIX DNS resolver" "N"; then
    dns_enabled=1
    dns_domain="$(value_or_prompt "$first_dns_domain" "TrustIX DNS domain" "$domain_id")"
    dnsmasq_default="N"
    if [[ "$(lower_ascii "$service_manager")" == "openwrt" ]]; then
      dnsmasq_default="Y"
    fi
    if flag_or_prompt_yes_no "$first_openwrt_dnsmasq" "Enable OpenWrt dnsmasq conditional forwarding" "$dnsmasq_default"; then
      openwrt_dnsmasq=1
      dns_enabled=1
    fi
  fi
  kernel_modules="$(value_or_prompt_required "$first_kernel_modules" "Kernel module mode" "auto")"

  ensure_first_domain_certs "$domain_id" "$ix_id" "$cert_dir"

  endpoint_spec="name=${ix_id}-${endpoint_transport};transport=${endpoint_transport};mode=passive;listen=${endpoint_listen};address=${endpoint_address}"
  if [[ -n "$endpoint_source_ip" ]]; then
    endpoint_spec+=";source_ip=${endpoint_source_ip}"
  fi
  if [[ -n "$endpoint_bind_iface" ]]; then
    endpoint_spec+=";bind_iface=${endpoint_bind_iface}"
  fi

  local args=(
    --ix "$ix_id"
    --domain "$domain_id"
    --source-certs "$cert_dir"
    --control-api "$control_api"
    --lan-iface "$lan_iface"
    --lan-gateway "$lan_gateway"
    --advertise "$advertise"
    --endpoint "$endpoint_spec"
    --api "$api_addr"
    --peer-api "$peer_api_addr"
    --dataplane "$dataplane"
    --service-manager "$service_manager"
    --dns-enabled "$dns_enabled"
    --openwrt-dnsmasq "$openwrt_dnsmasq"
    --kernel-modules "$kernel_modules"
    --json
  )
  if [[ -n "$dns_domain" ]]; then
    args+=(--dns-domain "$dns_domain")
  fi
  if [[ -n "$underlay_iface" ]]; then
    args+=(--underlay-iface "$underlay_iface")
  fi
  if flag_or_prompt_yes_no "$first_local_install" "Build, install, and start this IX on the local host" "Y"; then
    args+=(--local-install)
  else
    args+=(--no-deploy)
  fi

  log "run bootstrap for ${ix_id}"
  "${repo_root}/scripts/trustix-bootstrap-ix.sh" "${args[@]}"
}

run_join_token() {
  local provision_url token
  provision_url="$(value_or_prompt_required "$join_provision_url" "Existing IX provision URL" "https://ix-a.example.net:8787")"
  token="$(value_or_prompt_required "$join_token" "One-time provision token" "")"
  log "join domain with provision token"
  "${repo_root}/scripts/trustix-bootstrap-ix.sh" --provision-url "$provision_url" --token "$token"
}

mode=""
assume_defaults=0
first_domain_id=""
first_ix_id=""
first_cert_dir=""
first_control_api=""
first_lan_iface=""
first_lan_gateway=""
first_advertise=""
first_underlay_iface=""
first_endpoint_transport=""
first_endpoint_listen=""
first_endpoint_address=""
first_endpoint_source_ip=""
first_endpoint_bind_iface=""
first_api_addr=""
first_peer_api_addr=""
first_dataplane=""
first_service_manager=""
first_dns_enabled=""
first_dns_domain=""
first_openwrt_dnsmasq=""
first_kernel_modules=""
first_local_install=""
join_provision_url=""
join_token=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --first-ix) mode="first"; shift ;;
    --join-token) mode="join-token"; shift ;;
    --yes|--non-interactive) assume_defaults=1; shift ;;
    --domain) [[ $# -ge 2 ]] || die "--domain requires a value"; first_domain_id="$2"; shift 2 ;;
    --ix) [[ $# -ge 2 ]] || die "--ix requires a value"; first_ix_id="$2"; shift 2 ;;
    --source-certs|--cert-dir) [[ $# -ge 2 ]] || die "$1 requires a value"; first_cert_dir="$2"; shift 2 ;;
    --control-api) [[ $# -ge 2 ]] || die "--control-api requires a value"; first_control_api="$2"; shift 2 ;;
    --lan-iface) [[ $# -ge 2 ]] || die "--lan-iface requires a value"; first_lan_iface="$2"; shift 2 ;;
    --lan-gateway) [[ $# -ge 2 ]] || die "--lan-gateway requires a value"; first_lan_gateway="$2"; shift 2 ;;
    --advertise) [[ $# -ge 2 ]] || die "--advertise requires a value"; first_advertise="$2"; shift 2 ;;
    --underlay-iface) [[ $# -ge 2 ]] || die "--underlay-iface requires a value"; first_underlay_iface="$2"; shift 2 ;;
    --endpoint-transport) [[ $# -ge 2 ]] || die "--endpoint-transport requires a value"; first_endpoint_transport="$2"; shift 2 ;;
    --endpoint-listen) [[ $# -ge 2 ]] || die "--endpoint-listen requires a value"; first_endpoint_listen="$2"; shift 2 ;;
    --endpoint-address) [[ $# -ge 2 ]] || die "--endpoint-address requires a value"; first_endpoint_address="$2"; shift 2 ;;
    --endpoint-source-ip) [[ $# -ge 2 ]] || die "--endpoint-source-ip requires a value"; first_endpoint_source_ip="$2"; shift 2 ;;
    --endpoint-bind-iface) [[ $# -ge 2 ]] || die "--endpoint-bind-iface requires a value"; first_endpoint_bind_iface="$2"; shift 2 ;;
    --api) [[ $# -ge 2 ]] || die "--api requires a value"; first_api_addr="$2"; shift 2 ;;
    --peer-api) [[ $# -ge 2 ]] || die "--peer-api requires a value"; first_peer_api_addr="$2"; shift 2 ;;
    --dataplane) [[ $# -ge 2 ]] || die "--dataplane requires a value"; first_dataplane="$2"; shift 2 ;;
    --service-manager) [[ $# -ge 2 ]] || die "--service-manager requires a value"; first_service_manager="$2"; shift 2 ;;
    --dns-enabled) [[ $# -ge 2 ]] || die "--dns-enabled requires a value"; first_dns_enabled="$2"; shift 2 ;;
    --dns-domain) [[ $# -ge 2 ]] || die "--dns-domain requires a value"; first_dns_domain="$2"; shift 2 ;;
    --openwrt-dnsmasq) [[ $# -ge 2 ]] || die "--openwrt-dnsmasq requires a value"; first_openwrt_dnsmasq="$2"; shift 2 ;;
    --kernel-modules) [[ $# -ge 2 ]] || die "--kernel-modules requires a value"; first_kernel_modules="$2"; shift 2 ;;
    --local-install) first_local_install=1; shift ;;
    --no-deploy|--no-install) first_local_install=0; shift ;;
    --provision-url) [[ $# -ge 2 ]] || die "--provision-url requires a value"; join_provision_url="$2"; shift 2 ;;
    --token|--provision-token) [[ $# -ge 2 ]] || die "$1 requires a value"; join_token="$2"; shift 2 ;;
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
