#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ]; then
  echo "ERROR: scripts/trustix-bootstrap-ix.sh requires GNU bash 4+" >&2
  exit 2
fi
set -Eeuo pipefail

trustix_bootstrap_log() {
  printf '[trustix-bootstrap] %s\n' "$*" >&2
}

trustix_bootstrap_mktemp_dir() {
  local prefix="${1:-trustix-bootstrap}"
  local dir
  dir="$(mktemp -d "${TMPDIR:-/tmp}/${prefix}.XXXXXX" 2>/dev/null || mktemp -d -t "${prefix}.XXXXXX" 2>/dev/null || true)"
  if [[ -z "$dir" ]]; then
    dir="${TMPDIR:-/tmp}/${prefix}.$$"
    rm -rf "$dir"
    mkdir -p "$dir" || return 1
  fi
  printf '%s\n' "$dir"
}

trustix_bootstrap_mktemp_file() {
  local prefix="${1:-trustix-bootstrap}"
  local file
  file="$(mktemp "${TMPDIR:-/tmp}/${prefix}.XXXXXX" 2>/dev/null || mktemp -t "${prefix}.XXXXXX" 2>/dev/null || true)"
  if [[ -z "$file" ]]; then
    file="${TMPDIR:-/tmp}/${prefix}.$$"
    rm -f "$file"
    : >"$file" || return 1
  fi
  printf '%s\n' "$file"
}

bootstrap_repo_root() {
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

trustix_bootstrap_temp_repo=0

trustix_bootstrap_cleanup_temp_repo() {
  if [[ "${trustix_bootstrap_temp_repo:-0}" == "1" && "${repo_root:-}" == /tmp/trustix-bootstrap-src.* ]]; then
    case "${TRUSTIX_BOOTSTRAP_KEEP_WORKDIR:-0}" in
      1|true|yes|on)
        trustix_bootstrap_log "workdir preserved: ${repo_root}"
        ;;
      *)
        rm -rf "$repo_root" || true
        ;;
    esac
  fi
  return 0
}

trustix_bootstrap_dir_has_entries() {
  local dir="$1"
  local entry
  for entry in "$dir"/* "$dir"/.[!.]* "$dir"/..?*; do
    [[ -e "$entry" || -L "$entry" ]] && return 0
  done
  return 1
}

trustix_bootstrap_extract_archive() {
  local archive_path="$1"
  local dest="$2"
  local stage archive_root candidate
  stage="$(trustix_bootstrap_mktemp_dir trustix-bootstrap-archive)" || return 1
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
  if ! cp -R "$archive_root"/. "$dest"/; then
    rm -rf "$stage"
    return 1
  fi
  rm -rf "$stage"
}

trustix_bootstrap_mirrors_enabled() {
  case "${TRUSTIX_BOOTSTRAP_MIRRORS:-auto}" in
    0|false|no|off|disabled) return 1 ;;
    *) return 0 ;;
  esac
}

trustix_bootstrap_github_url_candidates() {
  local url="$1"
  local mirror mirrors
  printf '%s\n' "$url"
  trustix_bootstrap_mirrors_enabled || return 0
  case "$url" in
    https://github.com/*|https://raw.githubusercontent.com/*) ;;
    *) return 0 ;;
  esac
  mirrors="${TRUSTIX_BOOTSTRAP_GITHUB_MIRRORS:-https://ghproxy.net/ https://gh-proxy.com/ https://gh-proxy.net/ https://ghfast.top/ https://gh.ddlc.top/ https://gh.llkk.cc/ https://github.moeyy.xyz/ https://mirror.ghproxy.com/}"
  for mirror in $mirrors; do
    [[ -n "$mirror" ]] || continue
    printf '%s%s\n' "${mirror%/}/" "$url"
  done
}

trustix_bootstrap_download_file() {
  local out="$1"
  shift
  local url
  for url in "$@"; do
    [[ -n "$url" ]] || continue
    rm -f "$out"
    trustix_bootstrap_log "download ${url}"
    if command -v curl >/dev/null 2>&1 && curl -fsSL --connect-timeout 8 "$url" -o "$out"; then
      return 0
    fi
    if command -v wget >/dev/null 2>&1 && wget -T 12 -qO "$out" "$url"; then
      return 0
    fi
  done
  rm -f "$out"
  return 1
}

if ! repo_root="$(bootstrap_repo_root)"; then
  repo_url="${TRUSTIX_BOOTSTRAP_REPO:-https://github.com/Unicode01/TrustIX.git}"
  repo_ref="${TRUSTIX_BOOTSTRAP_REF:-main}"
  repo_root="${TRUSTIX_BOOTSTRAP_WORKDIR:-}"
  if [[ -z "$repo_root" ]]; then
    repo_root="$(trustix_bootstrap_mktemp_dir trustix-bootstrap-src)"
    trustix_bootstrap_temp_repo=1
  fi
  trap 'trustix_bootstrap_cleanup_temp_repo "$?"' EXIT
  if [[ ! -f "${repo_root}/go.mod" ]]; then
    mkdir -p "$repo_root"
    if trustix_bootstrap_dir_has_entries "$repo_root"; then
      echo "ERROR: TRUSTIX_BOOTSTRAP_WORKDIR is not a TrustIX repo and is not empty: ${repo_root}" >&2
      exit 1
    fi
    cloned=0
    if command -v git >/dev/null 2>&1; then
      if git clone --depth 1 --branch "$repo_ref" "$repo_url" "$repo_root" >&2; then
        cloned=1
      else
        trustix_bootstrap_log "git clone failed, trying GitHub archive mirrors"
        rm -rf "$repo_root"
        mkdir -p "$repo_root"
      fi
    fi
    if [[ "$cloned" != "1" ]] && { command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1; } && command -v tar >/dev/null 2>&1 && [[ "$repo_url" == https://github.com/* ]]; then
      archive_url="${repo_url%.git}/archive/${repo_ref}.tar.gz"
      archive_path="$(trustix_bootstrap_mktemp_file trustix-bootstrap-src)" || exit 1
      mapfile -t archive_urls < <(trustix_bootstrap_github_url_candidates "$archive_url")
      trustix_bootstrap_download_file "$archive_path" "${archive_urls[@]}"
      trustix_bootstrap_extract_archive "$archive_path" "$repo_root"
      rm -f "$archive_path"
      cloned=1
    fi
    if [[ "$cloned" != "1" ]]; then
      echo "ERROR: git is required to clone ${repo_url}; alternatively install curl/wget+tar for GitHub archive bootstrap" >&2
      exit 127
    fi
  fi
  child_status=0
  bash "${repo_root}/scripts/trustix-bootstrap-ix.sh" "$@" || child_status=$?
  trustix_bootstrap_cleanup_temp_repo "$child_status"
  trap - EXIT
  exit "$child_status"
fi

usage() {
  cat <<'EOF'
usage: scripts/trustix-bootstrap-ix.sh [options]

Issues a new IX certificate, writes a JSON config, optionally builds a release,
and optionally deploys the new IX to a local or SSH target.

Provision token mode:
  --provision-url URL       existing IX management URL that issued the token
  --token TOKEN             one-time IX provision token

Required:
  --ix ID
  --domain DOMAIN
  --control-api URL
  --advertise CIDR           repeatable; route auth prefixes for the primary LAN

Common options:
  --source-certs DIR         CA input dir (default: certs)
  --work-dir DIR             output work dir (default: build/bootstrap/<ix>)
  --target-cert-dir DIR      cert path written into generated config
  --domain-ca-cert PATH      Domain CA cert
  --domain-ca-key PATH       Domain CA key; required to issue IX cert
  --config-ca-cert PATH      Config CA cert
  --config-ca-key PATH       Config CA key; required to issue route auth
  --trust-root PATH          trust root cert copied to deploy cert dir; repeatable
  --dns NAME                 IX cert DNS SAN; repeatable or comma-separated
  --ip ADDR                  IX cert IP SAN; repeatable or comma-separated
  --lan-iface IFACE          primary LAN iface
  --lan-gateway CIDR         primary LAN gateway
  --underlay-iface IFACE     primary underlay iface for kernel fast paths
  --attach-mode MODE         managed or existing (default: managed)
  --manage-address 0|1       default: 1
  --endpoint SPEC            endpoint key=value spec; repeatable
  --endpoint-source-ip IP    outbound source IP for the generated default endpoint
  --endpoint-bind-iface IFACE
                             outbound Linux interface bind for the generated default endpoint
  --profile PROFILE          stable, performance, latency, compatibility, or
                             plaintext_performance (default: plaintext_performance)
  --bootstrap-peer SPEC      id=ix-a,domain=lab.local,control_api=https://...
  --bootstrap-control-api URL
  --api ADDR                 deployed management API listen
  --peer-api ADDR            deployed peer API listen
  --dataplane MODE           deployed dataplane mode
  --service-manager MODE     auto, systemd, or openwrt for deployment (default: auto)
  --dns-enabled 0|1          enable built-in TrustIX DNS in generated config
  --dns-domain DOMAIN        DNS suffix; empty uses --domain
  --openwrt-dnsmasq 0|1      enable OpenWrt dnsmasq conditional forwarding
  --kernel-modules MODE      disabled, auto, or required (default: auto)
  --target USER@HOST         deploy through SSH after build
  --ssh-port PORT
  --ssh-key PATH
  --ssh-option OPTION        repeatable
  --goarch ARCH              build target arch
  --kdir DIR                 target kernel build dir
  --build-bpf 0|1            recompile embedded eBPF objects on the target (default: 0)
  --build-ko auto|0|1        default: auto
  --build-webui 0|1          run npm WebUI rebuild during release build (default: 0)
  --local-install            install and start this IX on the current Linux host after build
  --no-build                 skip release build
  --no-deploy                skip deployment
  --json                     print machine-readable summary
  -h, --help                 show this help

Curl bootstrap:
  curl -fsSL https://raw.githubusercontent.com/Unicode01/TrustIX/main/scripts/trustix-bootstrap-ix.sh | bash -s -- [options]

  Token mode keeps CA private keys on the issuing IX/provisioner:
  curl -fsSL https://raw.githubusercontent.com/Unicode01/TrustIX/main/scripts/trustix-bootstrap-ix.sh | bash -s -- --provision-url https://ix-a.example:18787 --token TOKEN

  When run from curl, the script clones https://github.com/Unicode01/TrustIX.git
  into a temporary directory before building. Override with
  TRUSTIX_BOOTSTRAP_REPO, TRUSTIX_BOOTSTRAP_REF, or TRUSTIX_BOOTSTRAP_WORKDIR.

Existing installs should be upgraded with scripts/trustix-update.sh. It preserves
config/certs/data and replaces only release files plus the systemd unit:
  curl -fsSL https://raw.githubusercontent.com/Unicode01/TrustIX/main/scripts/trustix-update.sh | bash -s -- --release-url URL

Environment:
  TRUSTIX_BOOTSTRAP_INSTALL_DEPS=0 disables automatic package installation.
  TRUSTIX_BOOTSTRAP_MIRRORS=0 disables GitHub/Go mirror fallbacks.
  TRUSTIX_BOOTSTRAP_GITHUB_MIRRORS="https://proxy/" overrides GitHub mirrors.
  TRUSTIX_BOOTSTRAP_GO_URL=URL pins the Go toolchain download URL.
  TRUSTIX_BOOTSTRAP_PROVISION_INSECURE=0 enables normal TLS verification for
  the one-time provision payload fetch; default is insecure for new nodes.

Endpoint SPEC fields are comma-separated or semicolon-separated:
  name=ix-new-udp,transport=udp,mode=passive,listen=0.0.0.0:7000,address=ddns.example:7000
  Optional local bind fields: source_ip=192.0.2.10,bind_iface=wan2
Use semicolons when a value itself contains commas, for example GRE/IPIP/VXLAN
endpoint address strings.
If no endpoint is supplied, one UDP passive endpoint is generated from
--listen/--address/--endpoint-name/--endpoint-transport and optional
--endpoint-source-ip/--endpoint-bind-iface. The default profile is the
manifest-backed plaintext performance UDP full-kmod profile; use
--profile stable or --profile compatibility for secure userspace defaults.
EOF
}

log() {
  printf '[trustix-bootstrap] %s\n' "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

export TRUSTIX_REPO_ROOT="${TRUSTIX_REPO_ROOT:-$repo_root}"
# shellcheck source=scripts/trustix-prereqs.sh
source "${repo_root}/scripts/trustix-prereqs.sh"

json_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  printf '%s' "$value"
}

json_string_array() {
  local first=1 item
  printf '['
  for item in "$@"; do
    [[ -n "$item" ]] || continue
    if [[ "$first" == "0" ]]; then
      printf ','
    fi
    first=0
    printf '"%s"' "$(json_escape "$item")"
  done
  printf ']'
}

csv_join() {
  local first=1 item
  for item in "$@"; do
    [[ -n "$item" ]] || continue
    if [[ "$first" == "0" ]]; then
      printf ','
    fi
    first=0
    printf '%s' "$item"
  done
}

split_values() {
  local raw="$1"
  raw="${raw//,/;}"
  raw="${raw//+/;}"
  raw="${raw//|/;}"
  local item rest="$raw"
  while :; do
    if [[ "$rest" == *";"* ]]; then
      item="${rest%%;*}"
      rest="${rest#*;}"
    else
      item="$rest"
      rest=""
    fi
    item="${item#"${item%%[![:space:]]*}"}"
    item="${item%"${item##*[![:space:]]}"}"
    [[ -n "$item" ]] && printf '%s\n' "$item"
    [[ -z "$rest" ]] && break
  done
}

lower_ascii() {
  local value="$1"
  printf '%s' "${value,,}"
}

absolute_path() {
  local value="$1"
  [[ -n "$value" ]] || return 0
  case "$value" in
    /*) printf '%s\n' "$value" ;;
    *) printf '%s/%s\n' "$(pwd -P)" "$value" ;;
  esac
}

field_value() {
  local spec="$1"
  local key="$2"
  local default_value="${3:-}"
  local delimiter=","
  if [[ "$spec" == *";"* ]]; then
    delimiter=";"
  fi
  local field k v rest="$spec"
  while :; do
    if [[ "$delimiter" == ";" && "$rest" == *";"* ]]; then
      field="${rest%%;*}"
      rest="${rest#*;}"
    elif [[ "$delimiter" == "," && "$rest" == *","* ]]; then
      field="${rest%%,*}"
      rest="${rest#*,}"
    else
      field="$rest"
      rest=""
    fi
    k="${field%%=*}"
    v="${field#*=}"
    k="${k#"${k%%[![:space:]]*}"}"
    k="${k%"${k##*[![:space:]]}"}"
    v="${v#"${v%%[![:space:]]*}"}"
    v="${v%"${v##*[![:space:]]}"}"
    if [[ "$k" == "$key" ]]; then
      printf '%s' "$v"
      return
    fi
    [[ -z "$rest" ]] && break
  done
  printf '%s' "$default_value"
}

json_bool() {
  case "$(lower_ascii "$1")" in
    1|true|yes|on|enabled) printf 'true' ;;
    0|false|no|off|disabled|"") printf 'false' ;;
    *) die "invalid boolean value: $1" ;;
  esac
}

normalize_bootstrap_profile() {
  local value
  value="$(lower_ascii "${1:-plaintext_performance}")"
  value="${value//-/_}"
  case "$value" in
    ""|plain|plaintext|plaintext_perf|performance_plaintext)
      printf 'plaintext_performance'
      ;;
    stable|performance|latency|compatibility|plaintext_performance)
      printf '%s' "$value"
      ;;
    compat|compatible)
      printf 'compatibility'
      ;;
    *)
      die "--profile must be stable, performance, latency, compatibility, or plaintext_performance"
      ;;
  esac
}

bootstrap_profile_defaults() {
  local selected="$1"
  case "$selected" in
    stable)
      profile_transport_profile="stable"
      profile_datapath="userspace"
      profile_encryption="secure"
      profile_crypto_placement="userspace"
      profile_kernel_transport="disabled"
      profile_kernel_capability="disabled"
      ;;
    performance)
      profile_transport_profile="performance"
      profile_datapath="tc_xdp"
      profile_encryption="secure"
      profile_crypto_placement="kernel"
      profile_kernel_transport="require_kernel"
      profile_kernel_capability="performance"
      ;;
    latency)
      profile_transport_profile="stable"
      profile_datapath="userspace"
      profile_encryption="secure"
      profile_crypto_placement="userspace"
      profile_kernel_transport="disabled"
      profile_kernel_capability="disabled"
      ;;
    compatibility)
      profile_transport_profile="stable"
      profile_datapath="userspace"
      profile_encryption="secure"
      profile_crypto_placement="userspace"
      profile_kernel_transport="disabled"
      profile_kernel_capability="disabled"
      ;;
    plaintext_performance)
      profile_transport_profile="performance"
      profile_datapath="kernel_module"
      profile_encryption="plaintext"
      profile_crypto_placement="userspace"
      profile_kernel_transport="require_kernel"
      profile_kernel_capability="full_plaintext"
      ;;
    *)
      die "unsupported profile: $selected"
      ;;
  esac
}

bootstrap_kernel_module_modes() {
  local selected="$1"
  crypto_module_mode="$kernel_modules"
  datapath_module_mode="$kernel_modules"
  helpers_module_mode="$kernel_modules"
  if [[ "$kernel_modules" != "auto" ]]; then
    return 0
  fi
  case "$selected" in
    plaintext_performance)
      crypto_module_mode="disabled"
      datapath_module_mode="required"
      helpers_module_mode="disabled"
      ;;
    performance)
      crypto_module_mode="required"
      datapath_module_mode="disabled"
      helpers_module_mode="required"
      ;;
  esac
}

trustix_bootstrap_provision_insecure_enabled() {
  case "$(lower_ascii "${TRUSTIX_BOOTSTRAP_PROVISION_INSECURE:-1}")" in
    0|false|no|off|disabled) return 1 ;;
    *) return 0 ;;
  esac
}

trustix_bootstrap_fetch_provision_payload() {
  local url="$1"
  local out="$2"
  local -a curl_args=(-fsSL --connect-timeout 8)
  local -a wget_args=(-T 12 -qO "$out")
  if trustix_bootstrap_provision_insecure_enabled; then
    curl_args+=(-k)
    wget_args=(--no-check-certificate "${wget_args[@]}")
    log "WARNING: fetching provision payload with TLS verification disabled"
  fi
  rm -f "$out"
  if command -v curl >/dev/null 2>&1 && curl "${curl_args[@]}" "$url" -o "$out"; then
    return 0
  fi
  if command -v wget >/dev/null 2>&1 && wget "${wget_args[@]}" "$url"; then
    return 0
  fi
  rm -f "$out"
  return 1
}

run_provision_token() {
  [[ -n "$provision_url" ]] || die "--provision-url is required in token mode"
  [[ -n "$provision_token" ]] || die "--token is required in token mode"
  if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    trustix_prereqs_ensure_network_deps || die "curl or wget is required in token mode; automatic dependency install failed"
  fi
  local base_url="${provision_url%/}"
  local payload_url="${base_url}/v1/provision/ix/${provision_token}/bootstrap.sh"
  local payload
  payload="$(trustix_bootstrap_mktemp_file trustix-provision-payload)" || die "create provision payload path failed"
  log "fetch provision payload"
  if ! trustix_bootstrap_fetch_provision_payload "$payload_url" "$payload"; then
    log "failed to fetch provision payload from ${payload_url}"
    log "provision payload fetch uses TLS verification disabled by default because new nodes do not have TrustIX CA material yet"
    log "set TRUSTIX_BOOTSTRAP_PROVISION_INSECURE=0 only when the provision URL is already covered by a trusted certificate"
    die "provision payload download failed"
  fi
  chmod 0700 "$payload"
  TRUSTIX_BOOTSTRAP_REPO_ROOT="$repo_root" bash "$payload"
  rm -f "$payload"
}

find_trustix_ca_cmd() {
  if [[ -n "${TRUSTIX_CA_BIN:-}" ]]; then
    printf '%s\n' "$TRUSTIX_CA_BIN"
    return
  fi
  if [[ -x "${repo_root}/bin/trustix-ca" ]]; then
    printf '%s\n' "${repo_root}/bin/trustix-ca"
    return
  fi
  if command -v trustix-ca >/dev/null 2>&1; then
    command -v trustix-ca
    return
  fi
  if command -v go >/dev/null 2>&1 && [[ -d "${repo_root}/cmd/trustix-ca" ]]; then
    printf 'go run ./cmd/trustix-ca\n'
    return
  fi
  return 1
}

run_trustix_ca() {
  if [[ "$trustix_ca_cmd" == go\ run* ]]; then
    (cd "$repo_root" && go run ./cmd/trustix-ca "$@") >&2
  else
    "$trustix_ca_cmd" "$@" >&2
  fi
}

ensure_trustix_ca_cmd() {
  local cmd
  if ! cmd="$(find_trustix_ca_cmd)"; then
    trustix_prereqs_ensure_ca_deps || return 1
    cmd="$(find_trustix_ca_cmd)" || return 1
  fi
  printf '%s\n' "$cmd"
}

ix_id=""
domain_id=""
source_certs="certs"
work_dir=""
target_cert_dir="/etc/trustix/certs"
domain_ca_cert=""
domain_ca_key=""
config_ca_cert=""
config_ca_key=""
trust_roots=()
dns_sans=()
ip_sans=()
lan_id="lan"
lan_type="local"
lan_iface=""
lan_gateway=""
underlay_iface=""
attach_mode="managed"
manage_address=1
manage_forwarding=1
manage_rp_filter=1
advertise=()
lan_specs=()
endpoint_specs=()
endpoint_name=""
endpoint_transport="udp"
endpoint_mode="passive"
endpoint_listen="0.0.0.0:7000"
endpoint_address=""
endpoint_source_ip=""
endpoint_bind_iface=""
profile="plaintext_performance"
control_api=""
bootstrap_peers=()
bootstrap_control_apis=()
api_addr="127.0.0.1:8787"
peer_api_addr="0.0.0.0:9443"
dataplane="auto"
service_manager="auto"
dns_enabled="0"
dns_domain=""
openwrt_dnsmasq="0"
kernel_modules="auto"
target=""
ssh_port=""
ssh_key=""
ssh_options=()
goarch=""
kdir=""
build_bpf="${TRUSTIX_RELEASE_BUILD_BPF:-0}"
build_ko="auto"
build_webui="${TRUSTIX_BOOTSTRAP_BUILD_WEBUI:-0}"
do_build=1
do_deploy=1
local_install=0
json=0
provision_url=""
provision_token=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --provision-url) [[ $# -ge 2 ]] || die "--provision-url requires a value"; provision_url="$2"; shift 2 ;;
    --token|--provision-token) [[ $# -ge 2 ]] || die "$1 requires a value"; provision_token="$2"; shift 2 ;;
    --ix) [[ $# -ge 2 ]] || die "--ix requires a value"; ix_id="$2"; shift 2 ;;
    --domain) [[ $# -ge 2 ]] || die "--domain requires a value"; domain_id="$2"; shift 2 ;;
    --source-certs) [[ $# -ge 2 ]] || die "--source-certs requires a value"; source_certs="$2"; shift 2 ;;
    --work-dir) [[ $# -ge 2 ]] || die "--work-dir requires a value"; work_dir="$2"; shift 2 ;;
    --target-cert-dir) [[ $# -ge 2 ]] || die "--target-cert-dir requires a value"; target_cert_dir="$2"; shift 2 ;;
    --domain-ca-cert) [[ $# -ge 2 ]] || die "--domain-ca-cert requires a value"; domain_ca_cert="$2"; shift 2 ;;
    --domain-ca-key) [[ $# -ge 2 ]] || die "--domain-ca-key requires a value"; domain_ca_key="$2"; shift 2 ;;
    --config-ca-cert) [[ $# -ge 2 ]] || die "--config-ca-cert requires a value"; config_ca_cert="$2"; shift 2 ;;
    --config-ca-key) [[ $# -ge 2 ]] || die "--config-ca-key requires a value"; config_ca_key="$2"; shift 2 ;;
    --trust-root) [[ $# -ge 2 ]] || die "--trust-root requires a value"; trust_roots+=("$2"); shift 2 ;;
    --dns) [[ $# -ge 2 ]] || die "--dns requires a value"; while IFS= read -r split_item; do dns_sans+=("$split_item"); done < <(split_values "$2"); shift 2 ;;
    --ip) [[ $# -ge 2 ]] || die "--ip requires a value"; while IFS= read -r split_item; do ip_sans+=("$split_item"); done < <(split_values "$2"); shift 2 ;;
    --lan-id) [[ $# -ge 2 ]] || die "--lan-id requires a value"; lan_id="$2"; shift 2 ;;
    --lan-type) [[ $# -ge 2 ]] || die "--lan-type requires a value"; lan_type="$2"; shift 2 ;;
    --lan-iface) [[ $# -ge 2 ]] || die "--lan-iface requires a value"; lan_iface="$2"; shift 2 ;;
    --lan-gateway) [[ $# -ge 2 ]] || die "--lan-gateway requires a value"; lan_gateway="$2"; shift 2 ;;
    --underlay-iface) [[ $# -ge 2 ]] || die "--underlay-iface requires a value"; underlay_iface="$2"; shift 2 ;;
    --attach-mode) [[ $# -ge 2 ]] || die "--attach-mode requires a value"; attach_mode="$2"; shift 2 ;;
    --manage-address) [[ $# -ge 2 ]] || die "--manage-address requires a value"; manage_address="$2"; shift 2 ;;
    --manage-forwarding) [[ $# -ge 2 ]] || die "--manage-forwarding requires a value"; manage_forwarding="$2"; shift 2 ;;
    --manage-rp-filter) [[ $# -ge 2 ]] || die "--manage-rp-filter requires a value"; manage_rp_filter="$2"; shift 2 ;;
    --advertise|--route-prefix) [[ $# -ge 2 ]] || die "$1 requires a value"; while IFS= read -r split_item; do advertise+=("$split_item"); done < <(split_values "$2"); shift 2 ;;
    --lan) [[ $# -ge 2 ]] || die "--lan requires a value"; lan_specs+=("$2"); shift 2 ;;
    --endpoint) [[ $# -ge 2 ]] || die "--endpoint requires a value"; endpoint_specs+=("$2"); shift 2 ;;
    --endpoint-name) [[ $# -ge 2 ]] || die "--endpoint-name requires a value"; endpoint_name="$2"; shift 2 ;;
    --endpoint-transport) [[ $# -ge 2 ]] || die "--endpoint-transport requires a value"; endpoint_transport="$2"; shift 2 ;;
    --listen) [[ $# -ge 2 ]] || die "--listen requires a value"; endpoint_listen="$2"; shift 2 ;;
    --address) [[ $# -ge 2 ]] || die "--address requires a value"; endpoint_address="$2"; shift 2 ;;
    --endpoint-source-ip) [[ $# -ge 2 ]] || die "--endpoint-source-ip requires a value"; endpoint_source_ip="$2"; shift 2 ;;
    --endpoint-bind-iface) [[ $# -ge 2 ]] || die "--endpoint-bind-iface requires a value"; endpoint_bind_iface="$2"; shift 2 ;;
    --profile) [[ $# -ge 2 ]] || die "--profile requires a value"; profile="$2"; shift 2 ;;
    --control-api) [[ $# -ge 2 ]] || die "--control-api requires a value"; control_api="$2"; shift 2 ;;
    --bootstrap-peer) [[ $# -ge 2 ]] || die "--bootstrap-peer requires a value"; bootstrap_peers+=("$2"); shift 2 ;;
    --bootstrap-control-api) [[ $# -ge 2 ]] || die "--bootstrap-control-api requires a value"; bootstrap_control_apis+=("$2"); shift 2 ;;
    --api) [[ $# -ge 2 ]] || die "--api requires a value"; api_addr="$2"; shift 2 ;;
    --peer-api) [[ $# -ge 2 ]] || die "--peer-api requires a value"; peer_api_addr="$2"; shift 2 ;;
    --dataplane) [[ $# -ge 2 ]] || die "--dataplane requires a value"; dataplane="$2"; shift 2 ;;
    --service-manager) [[ $# -ge 2 ]] || die "--service-manager requires a value"; service_manager="$2"; shift 2 ;;
    --dns-enabled) [[ $# -ge 2 ]] || die "--dns-enabled requires a value"; dns_enabled="$2"; shift 2 ;;
    --dns-domain) [[ $# -ge 2 ]] || die "--dns-domain requires a value"; dns_domain="$2"; shift 2 ;;
    --openwrt-dnsmasq) [[ $# -ge 2 ]] || die "--openwrt-dnsmasq requires a value"; openwrt_dnsmasq="$2"; shift 2 ;;
    --kernel-modules) [[ $# -ge 2 ]] || die "--kernel-modules requires a value"; kernel_modules="$2"; shift 2 ;;
    --target) [[ $# -ge 2 ]] || die "--target requires a value"; target="$2"; shift 2 ;;
    --ssh-port) [[ $# -ge 2 ]] || die "--ssh-port requires a value"; ssh_port="$2"; shift 2 ;;
    --ssh-key) [[ $# -ge 2 ]] || die "--ssh-key requires a value"; ssh_key="$2"; shift 2 ;;
    --ssh-option) [[ $# -ge 2 ]] || die "--ssh-option requires a value"; ssh_options+=("$2"); shift 2 ;;
    --goarch) [[ $# -ge 2 ]] || die "--goarch requires a value"; goarch="$2"; shift 2 ;;
    --kdir) [[ $# -ge 2 ]] || die "--kdir requires a value"; kdir="$2"; shift 2 ;;
    --build-bpf) [[ $# -ge 2 ]] || die "--build-bpf requires a value"; build_bpf="$2"; shift 2 ;;
    --build-ko) [[ $# -ge 2 ]] || die "--build-ko requires a value"; build_ko="$2"; shift 2 ;;
    --build-webui) [[ $# -ge 2 ]] || die "--build-webui requires a value"; build_webui="$2"; shift 2 ;;
    --local-install) local_install=1; shift ;;
    --no-build) do_build=0; shift ;;
    --no-deploy) do_deploy=0; shift ;;
    --json) json=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

if [[ -n "$provision_url" || -n "$provision_token" ]]; then
  run_provision_token
  exit 0
fi

[[ -n "$ix_id" ]] || die "--ix is required"
[[ -n "$domain_id" ]] || die "--domain is required"
[[ -n "$control_api" ]] || die "--control-api is required"
case "$build_bpf" in 0|1) ;; *) die "--build-bpf must be 0 or 1" ;; esac
case "$build_ko" in auto|0|1) ;; *) die "--build-ko must be auto, 0, or 1" ;; esac
case "$build_webui" in 0|1) ;; *) die "--build-webui must be 0 or 1" ;; esac
kernel_modules="$(lower_ascii "$kernel_modules")"
case "$kernel_modules" in disabled|auto|required) ;; *) die "--kernel-modules must be disabled, auto, or required" ;; esac
service_manager="$(lower_ascii "$service_manager")"
case "$service_manager" in auto|systemd|openwrt) ;; *) die "--service-manager must be auto, systemd, or openwrt" ;; esac
profile="$(normalize_bootstrap_profile "$profile")"
profile_transport_profile=""
profile_datapath=""
profile_encryption=""
profile_crypto_placement=""
profile_kernel_transport=""
profile_kernel_capability=""
bootstrap_profile_defaults "$profile"
crypto_module_mode=""
datapath_module_mode=""
helpers_module_mode=""
bootstrap_kernel_module_modes "$profile"
openwrt_service_target=0
if [[ "$service_manager" == "openwrt" || ( "$service_manager" == "auto" && -f /etc/openwrt_release ) ]]; then
  openwrt_service_target=1
fi
if [[ "$openwrt_service_target" == "1" && "$profile" == "performance" ]]; then
  die "OpenWrt secure performance route-GSO is not a production default yet; use --profile stable for secure userspace or --profile plaintext_performance for validated OpenWrt full-kmod"
fi
if [[ "$kernel_modules" == "required" ]]; then
  if [[ "$openwrt_service_target" == "1" ]]; then
    if [[ "$build_ko" == "auto" ]]; then
      log "OpenWrt required kernel modules use SDK-built .ko files under /etc/trustix/modules; leaving --build-ko auto"
    fi
  elif [[ "$build_ko" == "0" ]]; then
    die "--kernel-modules required cannot be combined with --build-ko 0"
  elif [[ "$build_ko" == "auto" ]]; then
    log "--kernel-modules required: forcing --build-ko 1 so embedded .ko assets are present"
    build_ko=1
  fi
fi
bootstrap_kernel_module_modes "$profile"
case "$(json_bool "$dns_enabled")" in true) dns_enabled=1 ;; false) dns_enabled=0 ;; esac
case "$(json_bool "$openwrt_dnsmasq")" in true) openwrt_dnsmasq=1; dns_enabled=1 ;; false) openwrt_dnsmasq=0 ;; esac
if [[ -n "$target" && "$local_install" == "1" ]]; then
  die "--target and --local-install are mutually exclusive"
fi
if [[ ${#advertise[@]} -eq 0 && ${#lan_specs[@]} -eq 0 ]]; then
  die "at least one --advertise CIDR or --lan advertise=... spec is required"
fi

if [[ -z "$work_dir" ]]; then
  work_dir="${repo_root}/build/bootstrap/${ix_id}"
else
  work_dir="$(absolute_path "$work_dir")"
fi
source_certs="$(absolute_path "$source_certs")"
domain_ca_cert="${domain_ca_cert:-${source_certs}/domain-ca.pem}"
domain_ca_key="${domain_ca_key:-${source_certs}/domain-ca.key}"
config_ca_cert="${config_ca_cert:-${source_certs}/config-ca.pem}"
config_ca_key="${config_ca_key:-${source_certs}/config-ca.key}"
domain_ca_cert="$(absolute_path "$domain_ca_cert")"
domain_ca_key="$(absolute_path "$domain_ca_key")"
config_ca_cert="$(absolute_path "$config_ca_cert")"
config_ca_key="$(absolute_path "$config_ca_key")"
if [[ -n "$kdir" ]]; then
  kdir="$(absolute_path "$kdir")"
fi
for i in "${!trust_roots[@]}"; do
  trust_roots[$i]="$(absolute_path "${trust_roots[$i]}")"
done
[[ -f "$domain_ca_cert" ]] || die "domain CA cert not found: $domain_ca_cert"
[[ -f "$domain_ca_key" ]] || die "domain CA key not found: $domain_ca_key"
[[ -f "$config_ca_cert" ]] || die "config CA cert not found: $config_ca_cert"
[[ -f "$config_ca_key" ]] || die "config CA key not found: $config_ca_key"

if [[ ${#trust_roots[@]} -eq 0 ]]; then
  for candidate in "${source_certs}/root-ca.pem" "${source_certs}/domain-ca.pem" "${source_certs}/config-ca.pem"; do
    [[ -f "$candidate" ]] && trust_roots+=("$candidate")
  done
fi
[[ ${#trust_roots[@]} -gt 0 ]] || die "no trust roots found; pass --trust-root"

trustix_ca_cmd="$(ensure_trustix_ca_cmd)" || die "could not find trustix-ca or go toolchain; automatic dependency install failed"
issue_dir="${work_dir}/issued"
deploy_cert_dir="${work_dir}/deploy-certs"
config_dir="${work_dir}/config"
config_path="${config_dir}/${ix_id}.json"
mkdir -p "$issue_dir" "$deploy_cert_dir" "$config_dir"

openwrt_embedded_kmod=0
case "$(lower_ascii "${TRUSTIX_PROVISION_OPENWRT_ALLOW_EMBEDDED_KMOD:-0}")" in
  1|true|yes|on) openwrt_embedded_kmod=1 ;;
esac

kernel_module_path_for_config() {
  local module_name="$1"
  local mode="${2:-$kernel_modules}"
  if [[ "$openwrt_service_target" == "1" && ( "$mode" == "auto" || "$mode" == "required" ) && "$openwrt_embedded_kmod" != "1" ]]; then
    printf '/etc/trustix/modules/%s.ko' "$module_name"
    return 0
  fi
  printf 'embedded'
}

dns_csv="$(csv_join "${dns_sans[@]}")"
ip_csv="$(csv_join "${ip_sans[@]}")"
log "issue IX cert for ${ix_id}"
run_trustix_ca ix issue -out "$issue_dir" -domain "$domain_id" -ix "$ix_id" -ca-cert "$domain_ca_cert" -ca-key "$domain_ca_key" -dns "$dns_csv" -ip "$ip_csv"

all_prefixes=("${advertise[@]}")
for spec in "${lan_specs[@]}"; do
  raw_adv="$(field_value "$spec" advertise "")"
  if [[ -n "$raw_adv" ]]; then
    while IFS= read -r split_item; do
      all_prefixes+=("$split_item")
    done < <(split_values "$raw_adv")
  fi
done
route_csv="$(csv_join "${all_prefixes[@]}")"
log "issue route authorization for ${route_csv}"
run_trustix_ca route authorize -out "$issue_dir" -domain "$domain_id" -ix "$ix_id" -prefix "$route_csv" -ca-cert "$config_ca_cert" -ca-key "$config_ca_key"

cp "$issue_dir/${ix_id}.crt" "$deploy_cert_dir/${ix_id}.crt"
cp "$issue_dir/${ix_id}.key" "$deploy_cert_dir/${ix_id}.key"
cp "$issue_dir/${ix_id}-route.crt" "$deploy_cert_dir/${ix_id}-route.crt"
for root in "${trust_roots[@]}"; do
  cp "$root" "$deploy_cert_dir/$(basename "$root")"
done
chmod 0600 "$deploy_cert_dir/${ix_id}.key"

target_trust_roots=()
for root in "${trust_roots[@]}"; do
  target_trust_roots+=("${target_cert_dir}/$(basename "$root")")
done

if [[ ${#endpoint_specs[@]} -eq 0 ]]; then
  if [[ -z "$endpoint_name" ]]; then
    endpoint_name="${ix_id}-${endpoint_transport}"
  fi
  generated_endpoint_spec="name=${endpoint_name},transport=${endpoint_transport},mode=${endpoint_mode},listen=${endpoint_listen},address=${endpoint_address},encryption=${profile_encryption},profile=${profile_transport_profile},datapath=${profile_datapath},crypto_placement=${profile_crypto_placement}"
  if [[ -n "$endpoint_source_ip" ]]; then
    generated_endpoint_spec+=",source_ip=${endpoint_source_ip}"
  fi
  if [[ -n "$endpoint_bind_iface" ]]; then
    generated_endpoint_spec+=",bind_iface=${endpoint_bind_iface}"
  fi
  endpoint_specs+=("$generated_endpoint_spec")
fi

write_lan_object() {
  local spec="$1"
  local id type iface underlay gateway attach manage_addr manage_fwd manage_rpf raw_adv split_item
  local -a adv=()
  id="$(field_value "$spec" id "$lan_id")"
  type="$(field_value "$spec" type "$lan_type")"
  iface="$(field_value "$spec" iface "$lan_iface")"
  underlay="$(field_value "$spec" underlay_iface "$(field_value "$spec" underlay "$underlay_iface")")"
  gateway="$(field_value "$spec" gateway "$lan_gateway")"
  attach="$(field_value "$spec" attach_mode "$(field_value "$spec" attach "$attach_mode")")"
  manage_addr="$(field_value "$spec" manage_address "$manage_address")"
  manage_fwd="$(field_value "$spec" manage_forwarding "$manage_forwarding")"
  manage_rpf="$(field_value "$spec" manage_rp_filter "$manage_rp_filter")"
  if [[ "$(lower_ascii "$attach")" == "existing" ]]; then
    manage_addr=0
  fi
  raw_adv="$(field_value "$spec" advertise "")"
  if [[ -n "$raw_adv" ]]; then
    while IFS= read -r split_item; do
      adv+=("$split_item")
    done < <(split_values "$raw_adv")
  else
    adv=("${advertise[@]}")
  fi
  printf '{'
  printf '"id":"%s",' "$(json_escape "$id")"
  printf '"type":"%s",' "$(json_escape "$type")"
  printf '"iface":"%s",' "$(json_escape "$iface")"
  if [[ -n "$underlay" ]]; then
    printf '"underlay_iface":"%s",' "$(json_escape "$underlay")"
  fi
  printf '"gateway":"%s",' "$(json_escape "$gateway")"
  printf '"advertise":'
  json_string_array "${adv[@]}"
  printf ','
  printf '"mode":"routed",'
  printf '"attach_mode":"%s",' "$(json_escape "$attach")"
  printf '"manage_address":%s,' "$(json_bool "$manage_addr")"
  printf '"manage_forwarding":%s,' "$(json_bool "$manage_fwd")"
  printf '"manage_rp_filter":%s' "$(json_bool "$manage_rpf")"
  printf '}'
}

write_endpoint_object() {
  local spec="$1"
  local name transport mode listen address source_ip bind_iface priority link_tls encryption profile datapath crypto first_bind
  name="$(field_value "$spec" name "")"
  transport="$(field_value "$spec" transport "udp")"
  mode="$(field_value "$spec" mode "passive")"
  listen="$(field_value "$spec" listen "")"
  address="$(field_value "$spec" address "")"
  source_ip="$(field_value "$spec" source_ip "$(field_value "$spec" local_bind_source_ip "")")"
  bind_iface="$(field_value "$spec" bind_iface "$(field_value "$spec" local_bind_iface "")")"
  priority="$(field_value "$spec" priority "0")"
  link_tls="$(field_value "$spec" link_tls "")"
  encryption="$(field_value "$spec" encryption "")"
  profile="$(field_value "$spec" profile "")"
  datapath="$(field_value "$spec" datapath "")"
  crypto="$(field_value "$spec" crypto_placement "")"
  [[ -n "$name" ]] || die "endpoint spec is missing name"
  printf '{'
  printf '"name":"%s",' "$(json_escape "$name")"
  printf '"mode":"%s",' "$(json_escape "$mode")"
  if [[ -n "$listen" ]]; then
    printf '"listen":"%s",' "$(json_escape "$listen")"
  fi
  if [[ -n "$address" ]]; then
    printf '"address":"%s",' "$(json_escape "$address")"
  fi
  printf '"transport":"%s",' "$(json_escape "$transport")"
  printf '"priority":%s,' "$priority"
  printf '"security":{'
  printf '"link_tls":"%s",' "$(json_escape "$link_tls")"
  printf '"encryption":"%s"' "$(json_escape "$encryption")"
  printf '},'
  printf '"transport_profile":{'
  printf '"profile":"%s",' "$(json_escape "$profile")"
  printf '"datapath":"%s",' "$(json_escape "$datapath")"
  printf '"encryption":"%s",' "$(json_escape "$encryption")"
  printf '"crypto_placement":"%s"' "$(json_escape "$crypto")"
  printf '},'
  if [[ -n "$source_ip" || -n "$bind_iface" ]]; then
    printf '"local_bind":{'
    first_bind=1
    if [[ -n "$source_ip" ]]; then
      printf '"source_ip":"%s"' "$(json_escape "$source_ip")"
      first_bind=0
    fi
    if [[ -n "$bind_iface" ]]; then
      if [[ "$first_bind" == "0" ]]; then printf ','; fi
      printf '"iface":"%s"' "$(json_escape "$bind_iface")"
    fi
    printf '},'
  fi
  printf '"enabled":true'
  printf '}'
}

endpoint_names=()
for spec in "${endpoint_specs[@]}"; do
  endpoint_names+=("$(field_value "$spec" name "")")
done

{
  printf '{\n'
  printf '  "domain":{"id":"%s","trust_roots":' "$(json_escape "$domain_id")"
  json_string_array "${target_trust_roots[@]}"
  printf '},\n'
  printf '  "ix":{"id":"%s","domain":"%s","cert":"%s/%s.crt","key":"%s/%s.key","control_api":"%s","route_authorizations":["%s/%s-route.crt"]},\n' \
    "$(json_escape "$ix_id")" "$(json_escape "$domain_id")" "$(json_escape "$target_cert_dir")" "$(json_escape "$ix_id")" "$(json_escape "$target_cert_dir")" "$(json_escape "$ix_id")" "$(json_escape "$control_api")" "$(json_escape "$target_cert_dir")" "$(json_escape "$ix_id")"
  printf '  "lan":'
  if [[ ${#lan_specs[@]} -gt 0 ]]; then
    write_lan_object "${lan_specs[0]}"
  else
    primary_spec="id=${lan_id},type=${lan_type},iface=${lan_iface},underlay_iface=${underlay_iface},gateway=${lan_gateway},advertise=$(csv_join "${advertise[@]}"),attach_mode=${attach_mode},manage_address=${manage_address},manage_forwarding=${manage_forwarding},manage_rp_filter=${manage_rp_filter}"
    write_lan_object "$primary_spec"
  fi
  printf ',\n'
  printf '  "lans":['
  first=1
  if [[ ${#lan_specs[@]} -gt 1 ]]; then
    for ((i=1; i<${#lan_specs[@]}; i++)); do
      if [[ "$first" == "0" ]]; then printf ','; fi
      first=0
      write_lan_object "${lan_specs[$i]}"
    done
  fi
  printf '],\n'
  printf '  "management":{"tls":{"mode":"auto","identity":"ix_cert"},"host_api":{"enabled":true,"allow_unauthenticated_reads":false},"web_ui":{"enabled":true}},\n'
  if [[ "$dns_enabled" == "1" ]]; then
    printf '  "dns":{"enabled":true'
    if [[ -n "$dns_domain" ]]; then
      printf ',"domain":"%s"' "$(json_escape "$dns_domain")"
    fi
    if [[ "$openwrt_dnsmasq" == "1" ]]; then
      printf ',"dnsmasq":{"enabled":true}'
    fi
    printf '},\n'
  fi
  crypto_module_path="$(kernel_module_path_for_config trustix_crypto "$crypto_module_mode")"
  datapath_module_path="$(kernel_module_path_for_config trustix_datapath "$datapath_module_mode")"
  helpers_module_path="$(kernel_module_path_for_config trustix_datapath_helpers "$helpers_module_mode")"
  printf '  "kernel_modules":{"capability_profile":"%s",' "$(json_escape "$profile_kernel_capability")"
  if [[ "$profile" == "plaintext_performance" ]]; then
    printf '"datapath":{"rx_stage":"worker","rx_worker":true,"tx_plaintext":true,"full_plaintext":true,"rx_worker_allow_experimental_tcp":true},'
  fi
  printf '"trustix_crypto":{"mode":"%s","path":"%s","reload_on_upgrade":"auto","unload_on_exit":false},"trustix_datapath":{"mode":"%s","path":"%s","reload_on_upgrade":"auto","unload_on_exit":false},"trustix_datapath_helpers":{"mode":"%s","path":"%s","reload_on_upgrade":"auto","unload_on_exit":false}},\n' \
    "$(json_escape "$crypto_module_mode")" "$(json_escape "$crypto_module_path")" \
    "$(json_escape "$datapath_module_mode")" "$(json_escape "$datapath_module_path")" \
    "$(json_escape "$helpers_module_mode")" "$(json_escape "$helpers_module_path")"
  printf '  "endpoints":['
  first=1
  for spec in "${endpoint_specs[@]}"; do
    if [[ "$first" == "0" ]]; then printf ','; fi
    first=0
    write_endpoint_object "$spec"
  done
  printf '],\n'
  printf '  "bootstrap":{"peers":['
  first=1
  for spec in "${bootstrap_peers[@]}"; do
    if [[ "$first" == "0" ]]; then printf ','; fi
    first=0
    printf '{"id":"%s","domain":"%s","control_api":"%s"}' \
      "$(json_escape "$(field_value "$spec" id "")")" \
      "$(json_escape "$(field_value "$spec" domain "$domain_id")")" \
      "$(json_escape "$(field_value "$spec" control_api "")")"
  done
  for api in "${bootstrap_control_apis[@]}"; do
    if [[ "$first" == "0" ]]; then printf ','; fi
    first=0
    printf '{"control_api":"%s"}' "$(json_escape "$api")"
  done
  printf ']},\n'
  printf '  "peers":[],\n'
  printf '  "routes":[],\n'
  printf '  "route_policy":{"import_prefixes":[],"export_prefixes":[],"dynamic_metric":1000},\n'
  printf '  "policies":[{"name":"default-routed","route_selection":"longest_prefix","flow_stickiness":true,"rewrite":"preserve_source"}],\n'
  printf '  "transport_policy":{"mode":"user_defined","candidates":'
  json_string_array "${endpoint_names[@]}"
  printf ',"failover":"health_based","profile":"%s","datapath":"%s","encryption":"%s","crypto_key_source":"auto","crypto_placement":"%s","kernel_transport":{"mode":"%s"},"session_pool":{"warmup":true}}\n' \
    "$(json_escape "$profile_transport_profile")" \
    "$(json_escape "$profile_datapath")" \
    "$(json_escape "$profile_encryption")" \
    "$(json_escape "$profile_crypto_placement")" \
    "$(json_escape "$profile_kernel_transport")"
  printf '}\n'
} >"$config_path"

tarball=""
if [[ "$do_build" == "1" ]]; then
  if [[ "$service_manager" == "openwrt" || ( "$service_manager" == "auto" && -f /etc/openwrt_release ) ]]; then
    trustix_prereqs_ensure_openwrt_dataplane_runtime_deps || die "OpenWrt dataplane runtime dependencies are missing; automatic dependency install failed"
  fi
  trustix_prereqs_ensure_source_build_deps || die "source build dependencies are missing; automatic dependency install failed"
  if [[ "$build_webui" == "1" ]]; then
    trustix_prereqs_ensure_webui_deps || die "npm is required for WebUI build; automatic dependency install failed"
  fi
  build_args=(--out "${repo_root}/build/release" --version "bootstrap-${ix_id}" --build-bpf "$build_bpf" --build-ko "$build_ko" --json)
  [[ "$build_webui" == "0" ]] && build_args+=(--skip-webui)
  [[ -n "$goarch" ]] && build_args+=(--goarch "$goarch")
  [[ -n "$kdir" ]] && build_args+=(--kdir "$kdir")
  log "build release"
  build_json="$("${repo_root}/scripts/trustix-build.sh" "${build_args[@]}")"
  tarball="$(printf '%s' "$build_json" | sed -n 's/.*"tarball":"\([^"]*\)".*/\1/p')"
  [[ -n "$tarball" ]] || die "could not parse build tarball path"
fi

if [[ "$do_deploy" == "1" && ( -n "$target" || "$local_install" == "1" ) ]]; then
  [[ -n "$tarball" ]] || die "deployment requires a tarball; do not combine --no-build with --target unless deploying separately"
  deploy_args=(--tarball "$tarball" --instance "$ix_id" --config "$config_path" --cert-dir "$deploy_cert_dir" --target-cert-dir "$target_cert_dir" --api "$api_addr" --peer-api "$peer_api_addr" --dataplane "$dataplane" --service-manager "$service_manager" --admin-auth)
  if [[ "$profile" == "plaintext_performance" ]]; then
    deploy_args+=(--env TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_OPENWRT_FULL_DATAPATH=1)
  fi
  if [[ "$service_manager" == "openwrt" || ( "$service_manager" == "auto" && -f /etc/openwrt_release ) ]]; then
    deploy_args+=(--env TRUSTIX_EXPERIMENTAL_TCP_COMPAT_STREAM=1)
  fi
  if [[ -n "$target" ]]; then
    deploy_args=(--target "$target" "${deploy_args[@]}")
    [[ -n "$ssh_port" ]] && deploy_args+=(--ssh-port "$ssh_port")
    [[ -n "$ssh_key" ]] && deploy_args+=(--ssh-key "$ssh_key")
    for opt in "${ssh_options[@]}"; do
      deploy_args+=(--ssh-option "$opt")
    done
  fi
  [[ "$json" == "1" ]] && deploy_args+=(--json)
  if [[ -n "$target" ]]; then
    log "deploy ${ix_id} to ${target}"
  else
    log "install ${ix_id} on local host"
  fi
  deploy_json="$("${repo_root}/scripts/trustix-deploy.sh" "${deploy_args[@]}")"
else
  deploy_json=""
fi

if [[ "$json" == "1" ]]; then
  printf '{'
  printf '"ix":"%s",' "$(json_escape "$ix_id")"
  printf '"config":"%s",' "$(json_escape "$config_path")"
  printf '"cert_dir":"%s",' "$(json_escape "$deploy_cert_dir")"
  printf '"tarball":"%s",' "$(json_escape "$tarball")"
  printf '"deployed":%s' "$( [[ -n "$deploy_json" ]] && printf 'true' || printf 'false' )"
  if [[ -n "$deploy_json" ]]; then
    printf ',"deploy":%s' "$deploy_json"
  fi
  printf '}\n'
else
  log "config: $config_path"
  log "deploy certs: $deploy_cert_dir"
  [[ -n "$tarball" ]] && log "tarball: $tarball"
fi
