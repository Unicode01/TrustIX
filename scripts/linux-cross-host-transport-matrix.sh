#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
defaults_file="${TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_DEFAULTS:-${repo_root}/scripts/production-transport-defaults.tsv}"
runner="${TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_RUNNER:-${repo_root}/scripts/linux-cross-host-soak-runner.sh}"
verifier="${TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_VERIFIER:-${repo_root}/scripts/linux-cross-host-soak-verify.py}"
production_gate="${TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_PRODUCTION_GATE:-${repo_root}/scripts/linux-cross-host-production-gate.sh}"
evidence_generator="${TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_EVIDENCE_GENERATOR:-${repo_root}/scripts/production-evidence-from-gate-summary.py}"
workdir="${TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_WORKDIR:-$(mktemp -d /tmp/trustix-cross-host-transport-matrix.XXXXXX)}"
workdir="$(mkdir -p "$workdir" && cd "$workdir" && pwd -P)"
cases_raw="${TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_CASES:-}"
scope="${TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SCOPE:-all}"
keep_remote="${TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_KEEP_REMOTE:-0}"
verify="${TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_VERIFY:-1}"
selected_gate="${TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SELECTED_GATE:-1}"
require_binary_identity="${TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_REQUIRE_BINARY_IDENTITY:-1}"
dry_run="${TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_DRY_RUN:-0}"
seconds_override="${TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SECONDS:-}"
min_gbps_override="${TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_MIN_GBPS:-}"
seconds_slop="${TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SECONDS_SLOP:-1}"
timeout_slop="${TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_TIMEOUT_SLOP:-120}"
route_gso_session_error_budget="${TRUSTIX_CROSS_HOST_ROUTE_GSO_SESSION_ERROR_BUDGET:-2}"
secure_exp_tcp_kernel_session_error_budget="${TRUSTIX_CROSS_HOST_SECURE_EXP_TCP_KERNEL_SESSION_ERROR_BUDGET:-2}"
summary_path="${TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SUMMARY:-${workdir}/summary.jsonl}"
selected_gate_summary_dir="${TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_GATE_SUMMARY_DIR:-${TRUSTIX_CROSS_HOST_GATE_SUMMARY_DIR:-${workdir}/selected-production-gate}}"
evidence_out="${TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_EVIDENCE_OUT:-}"
evidence_os_matrix="${TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_EVIDENCE_OS_MATRIX:-}"
evidence_kernel_matrix="${TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_EVIDENCE_KERNEL_MATRIX:-}"
evidence_artifact="${TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_EVIDENCE_ARTIFACT:-}"
evidence_note_template="${TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_EVIDENCE_NOTE_TEMPLATE:-}"
evidence_include_fail="${TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_EVIDENCE_INCLUDE_FAIL:-0}"
runner_sha256=""
transport_matrix_sha256=""
if [[ -z "$evidence_note_template" ]]; then
  evidence_note_template='{transport} {encryption} {gate_family} production gate evidence'
fi

log() {
  printf '[trustix-cross-host-transport-matrix] %s\n' "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

truthy() {
  case "${1:-0}" in
    1|true|yes|on|enabled) return 0 ;;
    *) return 1 ;;
  esac
}

file_sha256() {
  local path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$path" | awk '{print $1}'
  else
    die "missing sha256sum or shasum for tool identity: ${path}"
  fi
}

validate_nonnegative_decimal() {
  local name="$1" value="$2"
  local re='^[0-9]+([.][0-9]+)?$'
  [[ "$value" =~ $re ]] || die "${name} must be a non-negative number"
}

validate_nonnegative_integer() {
  local name="$1" value="$2"
  [[ "$value" =~ ^[0-9]+$ ]] || die "${name} must be a non-negative integer"
}

validate_positive_integer() {
  local name="$1" value="$2"
  [[ "$value" =~ ^[1-9][0-9]*$ ]] || die "${name} must be a positive integer"
}

max_decimal() {
  local a="$1" b="$2"
  awk -v a="$a" -v b="$b" 'BEGIN { if ((a + 0) >= (b + 0)) print a; else print b }'
}

min_decimal() {
  local a="$1" b="$2"
  awk -v a="$a" -v b="$b" 'BEGIN { if ((a + 0) <= (b + 0)) print a; else print b }'
}

max_integer() {
  local a="$1" b="$2"
  if (( a >= b )); then
    printf '%s\n' "$a"
  else
    printf '%s\n' "$b"
  fi
}

transport_token() {
  case "$1" in
    kernel_udp) printf 'udp\n' ;;
    *) printf '%s\n' "$1" ;;
  esac
}

runner_case_name() {
  local transport="$1" encryption="$2" datapath="$3" gate_family="$4"
  local token kind
  case "$gate_family" in
    full_kmod|dd_full_kmod) printf 'dd-fullkmod\n'; return ;;
    owdeb_full_kmod) printf 'owdeb-fullkmod\n'; return ;;
    exp_tcp_full_kmod|dd_exp_tcp_full_kmod) printf 'experimental-tcp-full-kmod\n'; return ;;
    owdeb_exp_tcp_full_kmod) printf 'owdeb-experimental-tcp-full-kmod\n'; return ;;
    secure_kudp|dd_secure_kudp) printf 'secure-kudp\n'; return ;;
    owdeb_secure_kudp) printf 'owdeb-secure-kudp\n'; return ;;
    secure_exp_tcp_kernel|dd_secure_exp_tcp_kernel|owdeb_secure_exp_tcp_kernel) printf 'secure-exp-tcp-kernel\n'; return ;;
    route_gso|dd_route_gso) printf 'dd-routegso\n'; return ;;
    owdeb_route_gso) printf 'owdeb-routegso\n'; return ;;
  esac
  token="$(transport_token "$transport")"
  kind="userspace"
  if [[ "$datapath" == "tc_xdp" || "$transport" == "kernel_udp" ]]; then
    kind="tc"
  fi
  printf '%s-%s-%s\n' "$kind" "$token" "$encryption"
}

gate_family_class() {
  case "$1" in
    full_kmod|dd_full_kmod|owdeb_full_kmod) printf 'full_kmod\n' ;;
    exp_tcp_full_kmod|dd_exp_tcp_full_kmod|owdeb_exp_tcp_full_kmod) printf 'exp_tcp_full_kmod\n' ;;
    secure_kudp|dd_secure_kudp|owdeb_secure_kudp) printf 'secure_kudp\n' ;;
    secure_exp_tcp_kernel|dd_secure_exp_tcp_kernel|owdeb_secure_exp_tcp_kernel) printf 'secure_exp_tcp_kernel\n' ;;
    route_gso|dd_route_gso|owdeb_route_gso) printf 'route_gso\n' ;;
    *) printf '%s\n' "$1" ;;
  esac
}

require_case_value() {
  local field="$1" got="$2" want="$3" gate_family="$4"
  [[ "$got" == "$want" ]] || die "gate_family=${gate_family} requires ${field}=${want}; got ${field}=${got}"
}

validate_gate_family_semantics() {
  local transport="$1" encryption="$2" datapath="$3" placement="$4" gate_family="$5"
  local gate_class
  gate_class="$(gate_family_class "$gate_family")"
  case "$gate_class" in
    custom)
      return 0
      ;;
    userspace)
      case "$transport" in
        udp|tcp|quic|websocket|http_connect|experimental_tcp) ;;
        *) die "gate_family=${gate_family} requires a userspace transport; got transport=${transport}" ;;
      esac
      require_case_value datapath "$datapath" userspace "$gate_family"
      require_case_value crypto_placement "$placement" userspace "$gate_family"
      ;;
    userspace_tc)
      case "$transport" in
        gre|ipip|vxlan) ;;
        *) die "gate_family=${gate_family} requires a tunnel transport; got transport=${transport}" ;;
      esac
      require_case_value datapath "$datapath" tc_xdp "$gate_family"
      require_case_value crypto_placement "$placement" userspace "$gate_family"
      ;;
    tc_direct)
      require_case_value transport "$transport" kernel_udp "$gate_family"
      require_case_value encryption "$encryption" plaintext "$gate_family"
      require_case_value datapath "$datapath" tc_xdp "$gate_family"
      require_case_value crypto_placement "$placement" userspace "$gate_family"
      ;;
    full_kmod)
      require_case_value transport "$transport" udp "$gate_family"
      require_case_value encryption "$encryption" plaintext "$gate_family"
      require_case_value datapath "$datapath" kernel_module "$gate_family"
      require_case_value crypto_placement "$placement" userspace "$gate_family"
      ;;
    exp_tcp_full_kmod)
      case "$gate_family" in
        exp_tcp_full_kmod|dd_exp_tcp_full_kmod|owdeb_exp_tcp_full_kmod)
          require_case_value transport "$transport" experimental_tcp "$gate_family"
          ;;
        *)
          die "unsupported experimental TCP full-kmod gate family: ${gate_family}"
          ;;
      esac
      require_case_value encryption "$encryption" plaintext "$gate_family"
      require_case_value datapath "$datapath" kernel_module "$gate_family"
      require_case_value crypto_placement "$placement" userspace "$gate_family"
      ;;
    secure_kudp)
      require_case_value transport "$transport" kernel_udp "$gate_family"
      require_case_value encryption "$encryption" secure "$gate_family"
      require_case_value datapath "$datapath" tc_xdp "$gate_family"
      require_case_value crypto_placement "$placement" kernel "$gate_family"
      ;;
    secure_exp_tcp_kernel)
      require_case_value transport "$transport" experimental_tcp "$gate_family"
      require_case_value encryption "$encryption" secure "$gate_family"
      require_case_value datapath "$datapath" kernel_module "$gate_family"
      require_case_value crypto_placement "$placement" kernel "$gate_family"
      ;;
    route_gso)
      require_case_value transport "$transport" experimental_tcp "$gate_family"
      require_case_value encryption "$encryption" plaintext "$gate_family"
      require_case_value datapath "$datapath" kernel_module "$gate_family"
      require_case_value crypto_placement "$placement" userspace "$gate_family"
      ;;
    *)
      die "unsupported gate family class in matrix case: ${gate_class}"
      ;;
  esac
}

matrix_case_name() {
  local token="$1" encryption="$2" profile="$3" datapath="$4" placement="$5" gate_family="$6"
  local base="${token}-${encryption}-${profile}-${datapath}-${placement}"
  case "$gate_family" in
    owdeb_*) printf '%s-owdeb\n' "$base" ;;
    dd_*) printf '%s-dd\n' "$base" ;;
    *) printf '%s\n' "$base" ;;
  esac
}

case_selected_for_scope() {
  local validation_scope="$1" gate_family="$2"
  local gate_class
  gate_class="$(gate_family_class "$gate_family")"
  case "$scope" in
    all) return 0 ;;
    cross_host|selected) [[ "$validation_scope" == "cross_host" ]] ;;
    compat|baseline) [[ "$validation_scope" != "cross_host" && "$gate_class" != "full_kmod" && "$gate_class" != "exp_tcp_full_kmod" && "$gate_class" != "secure_kudp" && "$gate_class" != "secure_exp_tcp_kernel" && "$gate_class" != "route_gso" ]] ;;
    *) die "TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SCOPE must be all, cross_host, selected, compat, or baseline" ;;
  esac
}

default_cases() {
  [[ -f "$defaults_file" ]] || die "defaults file not found: ${defaults_file}"
  awk -F '\t' '
    BEGIN { OFS = "\t" }
    /^[[:space:]]*#/ || NF == 0 { next }
    NF < 9 { printf "invalid production defaults row: %s\n", $0 >"/dev/stderr"; exit 2 }
    { print $1, $2, $3, $4, $5, $6, $7, $8, $9 }
  ' "$defaults_file"
}

normalize_case_line() {
  local line="$1"
  line="${line%%#*}"
  line="${line//[[:space:]]/}"
  [[ -n "$line" ]] || return 1
  local old_ifs="$IFS"
  IFS=:
  set -- $line
  IFS="$old_ifs"
  if [[ $# -lt 5 || $# -gt 7 ]]; then
    die "invalid matrix case ${line}; expected transport:encryption:profile:datapath:crypto_placement[:min_gbps[:min_seconds]]"
  fi
  printf '%s\t%s\t%s\t%s\t%s\tcustom\tcustom\t%s\t%s\n' \
    "${1:-}" "${2:-}" "${3:-}" "${4:-}" "${5:-}" "${6:-0}" "${7:-30}"
}

validate_case_values() {
  local transport="$1" encryption="$2" profile="$3" datapath="$4" placement="$5" validation_scope="$6" gate_family="$7" min_gbps="$8" min_seconds="$9"
  case "$transport" in
    udp|tcp|quic|websocket|http_connect|gre|ipip|vxlan|kernel_udp|experimental_tcp) ;;
    *) die "unsupported transport in matrix case: ${transport}" ;;
  esac
  case "$encryption" in
    secure|plaintext) ;;
    *) die "unsupported encryption in matrix case: ${encryption}" ;;
  esac
  case "$profile" in
    stable|performance|latency) ;;
    *) die "unsupported profile in matrix case: ${profile}" ;;
  esac
  case "$datapath" in
    userspace|auto|tc_xdp|kernel_module) ;;
    *) die "unsupported datapath in matrix case: ${datapath}" ;;
  esac
  case "$placement" in
    userspace|auto|kernel) ;;
    *) die "unsupported crypto placement in matrix case: ${placement}" ;;
  esac
  case "$validation_scope" in
    single_host|cross_host|custom) ;;
    *) die "unsupported validation scope in matrix case: ${validation_scope}" ;;
  esac
  case "$gate_family" in
    userspace|userspace_tc|tc_direct|full_kmod|dd_full_kmod|owdeb_full_kmod|exp_tcp_full_kmod|dd_exp_tcp_full_kmod|owdeb_exp_tcp_full_kmod|secure_kudp|dd_secure_kudp|owdeb_secure_kudp|secure_exp_tcp_kernel|dd_secure_exp_tcp_kernel|owdeb_secure_exp_tcp_kernel|route_gso|dd_route_gso|owdeb_route_gso|custom) ;;
    *) die "unsupported gate family in matrix case: ${gate_family}" ;;
  esac
  validate_gate_family_semantics "$transport" "$encryption" "$datapath" "$placement" "$gate_family"
  validate_nonnegative_decimal "case min_gbps" "$min_gbps"
  validate_positive_integer "case min_seconds" "$min_seconds"
}

append_selected_gate_case() {
  local gate_family="$1" name="$2" dir="$3" min_gbps="$4" min_seconds="$5"
  local gate_class appended=0
  gate_class="$(gate_family_class "$gate_family")"
  case "$gate_class" in
    userspace)
      append_case_token userspace_cases "${name}=${dir}"
      append_case_token userspace_case_min_gbps "${name}=${min_gbps}"
      append_case_token userspace_case_min_seconds "${name}=${min_seconds}"
      appended=1
      ;;
    userspace_tc)
      append_case_token userspace_tc_cases "${name}=${dir}"
      append_case_token userspace_tc_case_min_gbps "${name}=${min_gbps}"
      append_case_token userspace_tc_case_min_seconds "${name}=${min_seconds}"
      appended=1
      ;;
    tc_direct)
      append_case_token tc_direct_cases "${name}=${dir}"
      append_case_token tc_direct_case_min_gbps "${name}=${min_gbps}"
      append_case_token tc_direct_case_min_seconds "${name}=${min_seconds}"
      appended=1
      ;;
    full_kmod)
      append_case_token full_kmod_cases "${name}=${dir}"
      append_case_token full_kmod_case_min_gbps "${name}=${min_gbps}"
      append_case_token full_kmod_case_min_seconds "${name}=${min_seconds}"
      appended=1
      ;;
    exp_tcp_full_kmod)
      append_case_token exp_tcp_full_kmod_cases "${name}=${dir}"
      append_case_token exp_tcp_full_kmod_case_min_gbps "${name}=${min_gbps}"
      append_case_token exp_tcp_full_kmod_case_min_seconds "${name}=${min_seconds}"
      appended=1
      ;;
    secure_kudp)
      append_case_token secure_kudp_cases "${name}=${dir}"
      append_case_token secure_kudp_case_min_gbps "${name}=${min_gbps}"
      append_case_token secure_kudp_case_min_seconds "${name}=${min_seconds}"
      appended=1
      ;;
    secure_exp_tcp_kernel)
      append_case_token secure_exp_tcp_kernel_cases "${name}=${dir}"
      append_case_token secure_exp_tcp_kernel_case_min_gbps "${name}=${min_gbps}"
      append_case_token secure_exp_tcp_kernel_case_min_seconds "${name}=${min_seconds}"
      appended=1
      ;;
    route_gso)
      append_case_token route_gso_cases "${name}=${dir}"
      append_case_token route_gso_case_min_gbps "${name}=${min_gbps}"
      append_case_token route_gso_case_min_seconds "${name}=${min_seconds}"
      appended=1
      ;;
  esac
  if [[ "$appended" -eq 1 ]]; then
    selected_gate_case_count=$((selected_gate_case_count + 1))
  else
    selected_gate_unmapped_case_count=$((selected_gate_unmapped_case_count + 1))
  fi
  selected_gate_min_seconds="$(max_integer "$selected_gate_min_seconds" "$min_seconds")"
}

append_case_token() {
  local var_name="$1" token="$2" current
  current="${!var_name:-}"
  if [[ -n "$current" ]]; then
    printf -v "$var_name" '%s %s' "$current" "$token"
  else
    printf -v "$var_name" '%s' "$token"
  fi
}

run_verify() {
  local name="$1" dir="$2" min_gbps="$3" min_seconds="$4" encryption="$5" profile="$6" datapath="$7" placement="$8" validation_scope="$9" gate_family="${10}"
  local family_class=""
  local session_dial_error_budget="0"
  local args=(
    "--case" "${name}=${dir}"
    "--min-gbps" "$min_gbps"
    "--min-seconds" "$min_seconds"
    "--seconds-slop" "$seconds_slop"
    "--require-transport-policy-stat" "encryption=${encryption}"
    "--require-transport-policy-stat" "profile=${profile}"
    "--require-transport-policy-stat" "datapath=${datapath}"
    "--require-transport-policy-stat" "crypto_placement=${placement}"
  )
  if [[ "$validation_scope" == "cross_host" ]]; then
    family_class="$(gate_family_class "$gate_family")"
    if [[ "$family_class" == "route_gso" ]]; then
      session_dial_error_budget="$route_gso_session_error_budget"
    elif [[ "$family_class" == "secure_exp_tcp_kernel" ]]; then
      session_dial_error_budget="$secure_exp_tcp_kernel_session_error_budget"
    fi
    args+=(
      "--require-status-max" "data_path.counters.session_dial_errors=${session_dial_error_budget}"
      "--require-status-max" "data_path.counters.session_heartbeat_timeouts=0"
    )
    if [[ "$family_class" == "tc_direct" ]]; then
      args+=("--require-datapath-any-min" "kernel_udp.active_flows=1")
    else
      args+=("--require-transport-sessions-min" "1")
    fi
  fi
  if truthy "$require_binary_identity"; then
    args+=("--require-binary-identity")
  fi
  python3 "$verifier" "${args[@]}"
}

record_result() {
  local status="$1" name="$2" runner_case="$3" transport="$4" encryption="$5" profile="$6" datapath="$7" placement="$8" validation_scope="$9" gate_family="${10}" min_gbps="${11}" min_seconds="${12}" dir="${13}" rc="${14}"
  printf '{"status":"%s","case":"%s","runner_case":"%s","transport":"%s","encryption":"%s","profile":"%s","datapath":"%s","crypto_placement":"%s","validation_scope":"%s","gate_family":"%s","min_gbps":%s,"min_seconds":%s,"exit_code":%s,"workdir":"%s","runner_sha256":"%s","transport_matrix_sha256":"%s"}\n' \
    "$status" "$name" "$runner_case" "$transport" "$encryption" "$profile" "$datapath" "$placement" "$validation_scope" "$gate_family" "$min_gbps" "$min_seconds" "$rc" "$dir" "$runner_sha256" "$transport_matrix_sha256" >>"$summary_path"
}

run_case() {
  local transport="$1" encryption="$2" profile="$3" datapath="$4" placement="$5" validation_scope="$6" gate_family="$7" default_min_gbps="$8" default_min_seconds="$9"
  validate_case_values "$transport" "$encryption" "$profile" "$datapath" "$placement" "$validation_scope" "$gate_family" "$default_min_gbps" "$default_min_seconds"
  case_selected_for_scope "$validation_scope" "$gate_family" || return 0

  local min_gbps min_seconds token name dir timeout_seconds rc status runner_case
  min_gbps="$default_min_gbps"
  if [[ -n "$min_gbps_override" ]]; then
    min_gbps="$(max_decimal "$min_gbps_override" "$default_min_gbps")"
  fi
  min_seconds="$default_min_seconds"
  if [[ -n "$seconds_override" ]]; then
    min_seconds="$(max_integer "$seconds_override" "$default_min_seconds")"
  fi
  validate_nonnegative_decimal "effective min_gbps" "$min_gbps"
  validate_positive_integer "effective min_seconds" "$min_seconds"
  token="$(transport_token "$transport")"
  name="$(matrix_case_name "$token" "$encryption" "$profile" "$datapath" "$placement" "$gate_family")"
  runner_case="$(runner_case_name "$transport" "$encryption" "$datapath" "$gate_family")"
  dir="${workdir}/${name}"
  timeout_seconds=$((min_seconds + timeout_slop))
  if truthy "$dry_run"; then
    log "dry-run ${name} runner_case=${runner_case} min_gbps=${min_gbps} seconds=${min_seconds}"
    record_result "dry_run" "$name" "$runner_case" "$transport" "$encryption" "$profile" "$datapath" "$placement" "$validation_scope" "$gate_family" "$min_gbps" "$min_seconds" "$dir" 0
    return 0
  fi
  rm -rf "$dir"
  mkdir -p "$dir"

  log "run ${name} runner_case=${runner_case} min_gbps=${min_gbps} seconds=${min_seconds}"
  set +e
  env \
    TRUSTIX_CROSS_HOST_CASE="$runner_case" \
    TRUSTIX_CROSS_HOST_TRANSPORT="$token" \
    TRUSTIX_CROSS_HOST_ENCRYPTION="$encryption" \
    TRUSTIX_CROSS_HOST_PROFILE="$profile" \
    TRUSTIX_CROSS_HOST_TRANSPORT_DATAPATH="$datapath" \
    TRUSTIX_CROSS_HOST_CRYPTO_PLACEMENT="$placement" \
    TRUSTIX_CROSS_HOST_WORKDIR="$dir" \
    TRUSTIX_CROSS_HOST_KEEP_LOCAL=1 \
    TRUSTIX_CROSS_HOST_KEEP_REMOTE="$keep_remote" \
    TRUSTIX_CROSS_HOST_IPERF_SECONDS="$min_seconds" \
    TRUSTIX_CROSS_HOST_IPERF_TIMEOUT="$timeout_seconds" \
    bash "$runner" >"${dir}.out" 2>"${dir}.err"
  rc=$?
  set -e
  status="fail"
  if [[ "$rc" == "0" ]]; then
    status="pass"
    if truthy "$verify"; then
      local verify_rc=0
      set +e
      run_verify "$name" "$dir" "$min_gbps" "$min_seconds" "$encryption" "$profile" "$datapath" "$placement" "$validation_scope" "$gate_family"
      verify_rc=$?
      set -e
      if [[ "$verify_rc" -ne 0 ]]; then
        status="fail"
        rc="$verify_rc"
        log "verification failed: ${name}"
      fi
    fi
    if [[ "$status" == "pass" && "$validation_scope" == "cross_host" ]]; then
      append_selected_gate_case "$gate_family" "$name" "$dir" "$min_gbps" "$min_seconds"
    fi
  else
    log "case failed: ${name}; see ${dir}.err"
  fi
  record_result "$status" "$name" "$runner_case" "$transport" "$encryption" "$profile" "$datapath" "$placement" "$validation_scope" "$gate_family" "$min_gbps" "$min_seconds" "$dir" "$rc"
  return "$rc"
}

run_selected_gate() {
  truthy "$verify" || return 0
  truthy "$selected_gate" || return 0
  local gate_env=()
  if [[ -n "$userspace_cases" ]]; then
    gate_env+=("TRUSTIX_CROSS_HOST_USERSPACE_CASES=${userspace_cases}")
    gate_env+=("TRUSTIX_CROSS_HOST_USERSPACE_CASE_MIN_GBPS=${userspace_case_min_gbps}")
    gate_env+=("TRUSTIX_CROSS_HOST_USERSPACE_CASE_MIN_SECONDS=${userspace_case_min_seconds}")
  fi
  if [[ -n "$userspace_tc_cases" ]]; then
    gate_env+=("TRUSTIX_CROSS_HOST_USERSPACE_TC_CASES=${userspace_tc_cases}")
    gate_env+=("TRUSTIX_CROSS_HOST_USERSPACE_TC_CASE_MIN_GBPS=${userspace_tc_case_min_gbps}")
    gate_env+=("TRUSTIX_CROSS_HOST_USERSPACE_TC_CASE_MIN_SECONDS=${userspace_tc_case_min_seconds}")
  fi
  if [[ -n "$tc_direct_cases" ]]; then
    gate_env+=("TRUSTIX_CROSS_HOST_TC_DIRECT_CASES=${tc_direct_cases}")
    gate_env+=("TRUSTIX_CROSS_HOST_TC_DIRECT_CASE_MIN_GBPS=${tc_direct_case_min_gbps}")
    gate_env+=("TRUSTIX_CROSS_HOST_TC_DIRECT_CASE_MIN_SECONDS=${tc_direct_case_min_seconds}")
  fi
  if [[ -n "$full_kmod_cases" ]]; then
    gate_env+=("TRUSTIX_CROSS_HOST_FULL_KMOD_CASES=${full_kmod_cases}")
    gate_env+=("TRUSTIX_CROSS_HOST_FULL_KMOD_CASE_MIN_GBPS=${full_kmod_case_min_gbps}")
    gate_env+=("TRUSTIX_CROSS_HOST_FULL_KMOD_CASE_MIN_SECONDS=${full_kmod_case_min_seconds}")
  fi
  if [[ -n "$exp_tcp_full_kmod_cases" ]]; then
    gate_env+=("TRUSTIX_CROSS_HOST_EXP_TCP_FULL_KMOD_CASES=${exp_tcp_full_kmod_cases}")
    gate_env+=("TRUSTIX_CROSS_HOST_EXP_TCP_FULL_KMOD_CASE_MIN_GBPS=${exp_tcp_full_kmod_case_min_gbps}")
    gate_env+=("TRUSTIX_CROSS_HOST_EXP_TCP_FULL_KMOD_CASE_MIN_SECONDS=${exp_tcp_full_kmod_case_min_seconds}")
  fi
  if [[ -n "$secure_kudp_cases" ]]; then
    gate_env+=("TRUSTIX_CROSS_HOST_SECURE_KUDP_CASES=${secure_kudp_cases}")
    gate_env+=("TRUSTIX_CROSS_HOST_SECURE_KUDP_CASE_MIN_GBPS=${secure_kudp_case_min_gbps}")
    gate_env+=("TRUSTIX_CROSS_HOST_SECURE_KUDP_CASE_MIN_SECONDS=${secure_kudp_case_min_seconds}")
  fi
  if [[ -n "$secure_exp_tcp_kernel_cases" ]]; then
    gate_env+=("TRUSTIX_CROSS_HOST_SECURE_EXP_TCP_KERNEL_CASES=${secure_exp_tcp_kernel_cases}")
    gate_env+=("TRUSTIX_CROSS_HOST_SECURE_EXP_TCP_KERNEL_CASE_MIN_GBPS=${secure_exp_tcp_kernel_case_min_gbps}")
    gate_env+=("TRUSTIX_CROSS_HOST_SECURE_EXP_TCP_KERNEL_CASE_MIN_SECONDS=${secure_exp_tcp_kernel_case_min_seconds}")
  fi
  if [[ -n "$route_gso_cases" ]]; then
    gate_env+=("TRUSTIX_CROSS_HOST_ROUTE_GSO_CASES=${route_gso_cases}")
    gate_env+=("TRUSTIX_CROSS_HOST_ROUTE_GSO_CASE_MIN_GBPS=${route_gso_case_min_gbps}")
    gate_env+=("TRUSTIX_CROSS_HOST_ROUTE_GSO_CASE_MIN_SECONDS=${route_gso_case_min_seconds}")
  fi
  if [[ "$selected_gate_unmapped_case_count" -gt 0 ]]; then
    die "selected production gate cannot represent ${selected_gate_unmapped_case_count} cross-host case(s); use a production gate family in ${defaults_file} instead of custom cases"
  fi
  if [[ "${#gate_env[@]}" -eq 0 ]]; then
    if [[ "$selected_gate_min_seconds" -gt 0 ]]; then
      die "selected production gate has no mapped cross-host cases"
    fi
    return 0
  fi
  gate_env+=("TRUSTIX_CROSS_HOST_GATE_SUMMARY_DIR=${selected_gate_summary_dir}")
  gate_env+=("TRUSTIX_CROSS_HOST_GATE_SECONDS_SLOP=${seconds_slop}")
  log "run selected production gate"
  env "${gate_env[@]}" bash "$production_gate"
}

emit_selected_gate_evidence() {
  [[ -n "$evidence_out" ]] || return 0
  [[ -f "$evidence_generator" ]] || die "production evidence generator not found: ${evidence_generator}"
  [[ -n "$evidence_artifact" ]] || die "TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_EVIDENCE_ARTIFACT is required when EVIDENCE_OUT is set"
  [[ "$selected_gate_case_count" -gt 0 ]] || die "production evidence output requires at least one selected production gate case"
  local args=(
    "--matrix-summary" "$summary_path"
    "--gate-summary-dir" "$selected_gate_summary_dir"
    "--artifact" "$evidence_artifact"
    "--note-template" "$evidence_note_template"
  )
  if [[ -n "$evidence_os_matrix" ]]; then
    args+=("--os-matrix" "$evidence_os_matrix")
  fi
  if [[ -n "$evidence_kernel_matrix" ]]; then
    args+=("--kernel-matrix" "$evidence_kernel_matrix")
  fi
  if truthy "$evidence_include_fail"; then
    args+=("--include-fail")
  fi
  mkdir -p "$(dirname "$evidence_out")"
  local tmp rc
  tmp="${evidence_out}.tmp"
  rm -f "$tmp"
  set +e
  python3 "$evidence_generator" "${args[@]}" >"$tmp"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    rm -f "$tmp"
    return "$rc"
  fi
  mv "$tmp" "$evidence_out"
  log "evidence=${evidence_out}"
}

main() {
  [[ -f "$runner" ]] || die "runner not found: ${runner}"
  [[ -f "$verifier" ]] || die "verifier not found: ${verifier}"
  [[ -f "$production_gate" ]] || die "production gate not found: ${production_gate}"
  runner_sha256="$(file_sha256 "$runner")"
  transport_matrix_sha256="$(file_sha256 "${BASH_SOURCE[0]}")"
  case "$scope" in all|cross_host|selected|compat|baseline) ;; *) die "TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SCOPE must be all, cross_host, selected, compat, or baseline" ;; esac
  case "$keep_remote" in 0|1|true|false|yes|no|on|off|enabled|disabled) ;; *) die "TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_KEEP_REMOTE must be truthy or falsey" ;; esac
  case "$verify" in 0|1|true|false|yes|no|on|off|enabled|disabled) ;; *) die "TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_VERIFY must be truthy or falsey" ;; esac
  case "$selected_gate" in 0|1|true|false|yes|no|on|off|enabled|disabled) ;; *) die "TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SELECTED_GATE must be truthy or falsey" ;; esac
  case "$require_binary_identity" in 0|1|true|false|yes|no|on|off|enabled|disabled) ;; *) die "TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_REQUIRE_BINARY_IDENTITY must be truthy or falsey" ;; esac
  case "$dry_run" in 0|1|true|false|yes|no|on|off|enabled|disabled) ;; *) die "TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_DRY_RUN must be truthy or falsey" ;; esac
  case "$evidence_include_fail" in 0|1|true|false|yes|no|on|off|enabled|disabled) ;; *) die "TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_EVIDENCE_INCLUDE_FAIL must be truthy or falsey" ;; esac
  [[ -z "$seconds_override" ]] || validate_positive_integer TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SECONDS "$seconds_override"
  [[ -z "$min_gbps_override" ]] || validate_nonnegative_decimal TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_MIN_GBPS "$min_gbps_override"
  validate_nonnegative_decimal TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SECONDS_SLOP "$seconds_slop"
  seconds_slop="$(min_decimal "$seconds_slop" "1")"
  validate_positive_integer TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_TIMEOUT_SLOP "$timeout_slop"
  validate_nonnegative_integer TRUSTIX_CROSS_HOST_ROUTE_GSO_SESSION_ERROR_BUDGET "$route_gso_session_error_budget"
  validate_nonnegative_integer TRUSTIX_CROSS_HOST_SECURE_EXP_TCP_KERNEL_SESSION_ERROR_BUDGET "$secure_exp_tcp_kernel_session_error_budget"
  if [[ -n "$evidence_out" ]]; then
    truthy "$dry_run" && die "TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_EVIDENCE_OUT cannot be used with DRY_RUN=1"
    truthy "$verify" || die "TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_EVIDENCE_OUT requires VERIFY=1"
    truthy "$selected_gate" || die "TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_EVIDENCE_OUT requires SELECTED_GATE=1"
  fi
  if ! truthy "$dry_run"; then
    truthy "$verify" || die "TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_VERIFY=0 is only allowed with DRY_RUN=1"
    case "$scope" in
      all|cross_host|selected)
        truthy "$selected_gate" || die "TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SELECTED_GATE=0 is only allowed for dry-run or non-production scopes"
        [[ -z "$cases_raw" ]] || die "TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_CASES is diagnostic-only for production scopes; add selected rows to ${defaults_file} with a production gate family"
        ;;
    esac
  fi

  : >"$summary_path"
  log "workdir=${workdir}"
  log "summary=${summary_path}"

  local line failures=0
  if [[ -n "$cases_raw" ]]; then
    while IFS= read -r line; do
      normalize_case_line "$line" || continue
    done <<<"$cases_raw" >"${workdir}/cases.tsv"
  else
    default_cases >"${workdir}/cases.tsv"
  fi

  while IFS=$'\t' read -r transport encryption profile datapath placement validation_scope gate_family min_gbps min_seconds; do
    [[ -n "${transport:-}" ]] || continue
    run_case "$transport" "$encryption" "$profile" "$datapath" "$placement" "$validation_scope" "$gate_family" "$min_gbps" "$min_seconds" || failures=$((failures + 1))
  done <"${workdir}/cases.tsv"

  if [[ "$failures" -eq 0 ]]; then
    run_selected_gate || failures=$((failures + 1))
  fi
  if [[ "$failures" -eq 0 ]]; then
    emit_selected_gate_evidence || failures=$((failures + 1))
  fi
  log "summary=${summary_path}"
  return "$failures"
}

userspace_cases=""
userspace_tc_cases=""
tc_direct_cases=""
full_kmod_cases=""
exp_tcp_full_kmod_cases=""
secure_kudp_cases=""
secure_exp_tcp_kernel_cases=""
route_gso_cases=""
userspace_case_min_gbps=""
userspace_tc_case_min_gbps=""
tc_direct_case_min_gbps=""
full_kmod_case_min_gbps=""
exp_tcp_full_kmod_case_min_gbps=""
secure_kudp_case_min_gbps=""
secure_exp_tcp_kernel_case_min_gbps=""
route_gso_case_min_gbps=""
userspace_case_min_seconds=""
userspace_tc_case_min_seconds=""
tc_direct_case_min_seconds=""
full_kmod_case_min_seconds=""
exp_tcp_full_kmod_case_min_seconds=""
secure_kudp_case_min_seconds=""
secure_exp_tcp_kernel_case_min_seconds=""
route_gso_case_min_seconds=""
selected_gate_min_seconds=0
selected_gate_case_count=0
selected_gate_unmapped_case_count=0

main "$@"
