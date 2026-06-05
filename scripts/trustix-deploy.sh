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
  --prefix DIR               install prefix (default: /usr/local)
  --sysconfdir DIR           config dir (default: /etc/trustix)
  --unitdir DIR              systemd unit dir (default: /etc/systemd/system)
  --state-root DIR           state root (default: /var/lib/trustix)
  --api ADDR                 management API listen (default: 127.0.0.1:8787)
  --peer-api ADDR            peer API listen (default: 0.0.0.0:9443)
  --dataplane MODE           noop, linux, or auto (default: auto)
  --admin-auth               add -api-admin-auth to service args
  --extra-arg ARG            append extra trustixd arg; repeatable
  --no-sudo                  run install commands without sudo
  --no-enable                do not enable systemd service
  --no-start                 do not start/restart systemd service
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

target=""
ssh_port=""
ssh_key=""
ssh_options=()
tarball=""
bin_dir=""
instance="ix"
config_path=""
cert_dir=""
prefix="/usr/local"
sysconfdir="/etc/trustix"
unitdir="/etc/systemd/system"
state_root="/var/lib/trustix"
target_cert_dir=""
api_addr="127.0.0.1:8787"
peer_api_addr="0.0.0.0:9443"
dataplane="auto"
extra_args=()
sudo_cmd="sudo"
enable_service=1
start_service=1
json=0

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
    --prefix) [[ $# -ge 2 ]] || die "--prefix requires a value"; prefix="$2"; shift 2 ;;
    --sysconfdir) [[ $# -ge 2 ]] || die "--sysconfdir requires a value"; sysconfdir="$2"; shift 2 ;;
    --unitdir) [[ $# -ge 2 ]] || die "--unitdir requires a value"; unitdir="$2"; shift 2 ;;
    --state-root) [[ $# -ge 2 ]] || die "--state-root requires a value"; state_root="$2"; shift 2 ;;
    --api) [[ $# -ge 2 ]] || die "--api requires a value"; api_addr="$2"; shift 2 ;;
    --peer-api) [[ $# -ge 2 ]] || die "--peer-api requires a value"; peer_api_addr="$2"; shift 2 ;;
    --dataplane) [[ $# -ge 2 ]] || die "--dataplane requires a value"; dataplane="$2"; shift 2 ;;
    --admin-auth) extra_args+=("-api-admin-auth"); shift ;;
    --extra-arg) [[ $# -ge 2 ]] || die "--extra-arg requires a value"; extra_args+=("$2"); shift 2 ;;
    --no-sudo) sudo_cmd=""; shift ;;
    --no-enable) enable_service=0; shift ;;
    --no-start) start_service=0; shift ;;
    --json) json=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

if [[ -z "$target_cert_dir" ]]; then
  target_cert_dir="${sysconfdir}/certs"
fi
if [[ -n "$tarball" && -n "$bin_dir" ]]; then
  die "--tarball and --bin-dir are mutually exclusive"
fi
if [[ -z "$tarball" && -z "$bin_dir" ]]; then
  die "either --tarball or --bin-dir is required"
fi

run_root() {
  if [[ -n "$sudo_cmd" ]]; then
    "$sudo_cmd" "$@"
  else
    "$@"
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

  local stage
  stage="$("${ssh_cmd[@]}" "$target" 'mktemp -d /tmp/trustix-deploy.XXXXXX')"
  [[ -n "$stage" ]] || die "failed to create remote staging dir"
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
  fi
  if [[ -n "$config_path" ]]; then
    "${scp_cmd[@]}" "$config_path" "${target}:${stage}/config"
  fi
  if [[ -n "$cert_dir" ]]; then
    "${scp_cmd[@]}" -r "$cert_dir" "${target}:${stage}/certs"
  fi

  local remote_args=()
  if [[ -n "$tarball" ]]; then
    remote_args+=(--tarball "${stage}/package.tar.gz")
  else
    remote_args+=(--bin-dir "${stage}/bin")
  fi
  remote_args+=(--instance "$instance" --prefix "$prefix" --sysconfdir "$sysconfdir" --state-root "$state_root")
  remote_args+=(--unitdir "$unitdir")
  remote_args+=(--target-cert-dir "$target_cert_dir" --api "$api_addr" --peer-api "$peer_api_addr" --dataplane "$dataplane")
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

  local command="TRUSTIX_DEPLOY_REMOTE_CHILD=1 bash $(shell_quote "${stage}/trustix-deploy.sh")"
  local arg
  for arg in "${remote_args[@]}"; do
    command+=" $(shell_quote "$arg")"
  done
  "${ssh_cmd[@]}" "$target" "$command"
}

install_from_package() {
  local package_dir="$1"
  local bindir="${prefix}/bin"
  local unit_src=""
  if [[ -f "${package_dir}/packaging/systemd/trustixd@.service" ]]; then
    unit_src="${package_dir}/packaging/systemd/trustixd@.service"
  elif [[ -f "${repo_root}/packaging/systemd/trustixd@.service" ]]; then
    unit_src="${repo_root}/packaging/systemd/trustixd@.service"
  else
    die "missing trustixd@.service"
  fi

  for name in trustixd trustixctl trustix-ca trustix-device; do
    if [[ -x "${package_dir}/bin/${name}" ]]; then
      run_root install -D -m 0755 "${package_dir}/bin/${name}" "${bindir}/${name}"
    elif [[ "$name" == "trustix-device" ]]; then
      continue
    else
      die "missing binary: ${package_dir}/bin/${name}"
    fi
  done
  run_root install -D -m 0644 "$unit_src" "${unitdir}/trustixd@.service"
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
    run_root install -D -m 0644 "$config_path" "$installed_config"
  fi

  if [[ -n "$cert_dir" ]]; then
    run_root mkdir -p "$target_cert_dir"
    local file rel mode
    while IFS= read -r -d '' file; do
      rel="${file#${cert_dir}/}"
      mode=0644
      case "$file" in
        *.key|*.p12|*.pfx) mode=0600 ;;
      esac
      run_root install -D -m "$mode" "$file" "${target_cert_dir}/${rel}"
    done < <(find "$cert_dir" -type f -print0)
  fi

  local env_tmp
  env_tmp="$(mktemp)"
  {
    printf 'TRUSTIX_CONFIG=%s\n' "$installed_config"
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
  } >"$env_tmp"
  run_root install -D -m 0644 "$env_tmp" "${sysconfdir}/${instance}.env"
  rm -f "$env_tmp"
}

local_deploy() {
  [[ "$(uname -s)" == "Linux" ]] || die "deployment must run on Linux"
  need_cmd install
  local stage=""
  local package_dir=""
  if [[ -n "$tarball" ]]; then
    [[ -f "$tarball" ]] || die "tarball not found: $tarball"
    need_cmd tar
    stage="$(mktemp -d)"
    tar -xzf "$tarball" -C "$stage"
    package_dir="$stage"
  else
    [[ -d "$bin_dir" ]] || die "bin dir not found: $bin_dir"
    package_dir="$(mktemp -d)"
    mkdir -p "${package_dir}/bin"
    cp -a "${bin_dir}/." "${package_dir}/bin/"
    if [[ -f "${repo_root}/packaging/systemd/trustixd@.service" ]]; then
      mkdir -p "${package_dir}/packaging/systemd"
      cp "${repo_root}/packaging/systemd/trustixd@.service" "${package_dir}/packaging/systemd/trustixd@.service"
    fi
  fi

  install_from_package "$package_dir"
  install_config
  if command -v systemctl >/dev/null 2>&1 && { [[ "$enable_service" == "1" ]] || [[ "$start_service" == "1" ]]; }; then
    run_root systemctl daemon-reload
    if [[ "$enable_service" == "1" ]]; then
      run_root systemctl enable "trustixd@${instance}.service"
    fi
    if [[ "$start_service" == "1" ]]; then
      run_root systemctl restart "trustixd@${instance}.service"
    fi
  elif [[ "$start_service" == "1" ]]; then
    die "systemctl not found; rerun with --no-start or start trustixd manually"
  fi

  if [[ "$json" == "1" ]]; then
    printf '{'
    printf '"instance":"%s",' "$(json_escape "$instance")"
    printf '"config":"%s/%s.%s",' "$(json_escape "$sysconfdir")" "$(json_escape "$instance")" "$( [[ "${config_path##*.}" == "json" ]] && printf 'json' || printf 'yaml' )"
    printf '"cert_dir":"%s",' "$(json_escape "$target_cert_dir")"
    printf '"service":"trustixd@%s.service",' "$(json_escape "$instance")"
    printf '"started":%s' "$start_service"
    printf '}\n'
  else
    log "deployed instance: $instance"
  fi

  if [[ -n "$stage" ]]; then
    rm -rf "$stage"
  fi
}

if [[ -n "$target" && -z "${TRUSTIX_DEPLOY_REMOTE_CHILD:-}" ]]; then
  remote_deploy
else
  local_deploy
fi
