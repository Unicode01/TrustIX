#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ]; then
  echo "ERROR: scripts/openwrt-procd-dns-smoke.sh requires GNU bash 4+" >&2
  exit 2
fi
set -Eeuo pipefail

usage() {
  cat <<'EOF'
usage: scripts/openwrt-procd-dns-smoke.sh --target USER@HOST [options]

Checks an existing TrustIX OpenWrt/procd install without modifying config.

Options:
  --target USER@HOST       SSH target
  --ssh-port PORT          SSH port
  --ssh-key PATH           SSH private key
  --ssh-option OPTION      extra ssh -o option; repeatable
  --instance NAME          instance env to check (default: ix)
  --sysconfdir DIR         config dir (default: /etc/trustix)
  --init PATH              init script path (default: /etc/init.d/trustix)
  --dns-domain DOMAIN      also check dnsmasq conditional forward for DOMAIN
  -h, --help               show this help
EOF
}

log() {
  printf '[trustix-openwrt-smoke] %s\n' "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

shell_quote() {
  local value="$1"
  printf "'%s'" "${value//\'/\'\\\'\'}"
}

target=""
ssh_port=""
ssh_key=""
ssh_options=()
instance="ix"
sysconfdir="/etc/trustix"
init="/etc/init.d/trustix"
dns_domain=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) [[ $# -ge 2 ]] || die "--target requires a value"; target="$2"; shift 2 ;;
    --ssh-port) [[ $# -ge 2 ]] || die "--ssh-port requires a value"; ssh_port="$2"; shift 2 ;;
    --ssh-key) [[ $# -ge 2 ]] || die "--ssh-key requires a value"; ssh_key="$2"; shift 2 ;;
    --ssh-option) [[ $# -ge 2 ]] || die "--ssh-option requires a value"; ssh_options+=("$2"); shift 2 ;;
    --instance) [[ $# -ge 2 ]] || die "--instance requires a value"; instance="$2"; shift 2 ;;
    --sysconfdir) [[ $# -ge 2 ]] || die "--sysconfdir requires a value"; sysconfdir="$2"; shift 2 ;;
    --init) [[ $# -ge 2 ]] || die "--init requires a value"; init="$2"; shift 2 ;;
    --dns-domain) [[ $# -ge 2 ]] || die "--dns-domain requires a value"; dns_domain="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ -n "$target" ]] || die "--target is required"
command -v ssh >/dev/null 2>&1 || die "missing required command: ssh"

ssh_cmd=(ssh)
if [[ -n "$ssh_port" ]]; then
  ssh_cmd+=(-p "$ssh_port")
fi
if [[ -n "$ssh_key" ]]; then
  ssh_cmd+=(-i "$ssh_key")
fi
for opt in "${ssh_options[@]}"; do
  ssh_cmd+=(-o "$opt")
done

remote_script='
set -eu
instance=$1
sysconfdir=$2
init=$3
dns_domain=$4
env_file="${sysconfdir}/${instance}.env"

[ -f /etc/openwrt_release ] || { echo "not OpenWrt"; exit 1; }
[ -x "$init" ] || { echo "missing init: $init"; exit 1; }
[ -f "$env_file" ] || { echo "missing env: $env_file"; exit 1; }

TRUSTIX_BIN=
TRUSTIX_CONFIG="${sysconfdir}/${instance}.yaml"
TRUSTIX_DATA_DIR="${sysconfdir}/state/${instance}"
TRUSTIX_API_ADDR=127.0.0.1:8787
TRUSTIX_PEER_API_ADDR=0.0.0.0:9443
TRUSTIX_DATAPLANE=auto
TRUSTIX_EXTRA_ARGS=
. "$env_file"

[ -x "$TRUSTIX_BIN" ] || { echo "missing binary: $TRUSTIX_BIN"; exit 1; }
[ -f "$TRUSTIX_CONFIG" ] || { echo "missing config: $TRUSTIX_CONFIG"; exit 1; }

if [ -n "$dns_domain" ]; then
  command -v uci >/dev/null 2>&1 || { echo "uci missing"; exit 1; }
  server="/${dns_domain}/127.0.0.1#1053"
  uci -q show dhcp | grep -F "$server" >/dev/null || { echo "missing dnsmasq server: $server"; exit 1; }
  uci -q show dhcp | grep -F "rebind_domain" | grep -F "$dns_domain" >/dev/null || { echo "missing dnsmasq rebind_domain: $dns_domain"; exit 1; }
fi

echo "ok instance=${instance} bin=${TRUSTIX_BIN} config=${TRUSTIX_CONFIG}"
'

log "check ${target}:${instance}"
"${ssh_cmd[@]}" "$target" "sh -s -- $(shell_quote "$instance") $(shell_quote "$sysconfdir") $(shell_quote "$init") $(shell_quote "$dns_domain")" <<<"$remote_script"
