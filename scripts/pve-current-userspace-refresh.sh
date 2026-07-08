#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workspace="${TRUSTIX_PVE_WORKSPACE:-/root/trustix-pve-work}"
transports="${TRUSTIX_PVE_USERSPACE_TRANSPORTS:-udp}"
run_root=""
background=1
dry_run=0
refresh_gaps=0
next_refresh_gap=0
skip_hygiene="${TRUSTIX_PVE_SKIP_HYGIENE_CHECK:-0}"
quarantine_loose_root_artifacts="${TRUSTIX_PVE_QUARANTINE_LOOSE_ROOT_ARTIFACTS:-0}"

usage() {
  cat <<'EOF'
usage: pve-current-userspace-refresh.sh [options]

Start a current-head Debian-to-Debian userspace production refresh from a PVE
source checkout without writing loose files under /root.

Options:
  --workspace DIR        PVE workspace root. Default: /root/trustix-pve-work
  --run-root DIR         Exact result directory. Must be under WORKSPACE/results
  --transports LIST      Comma-separated userspace transports. Default: udp
  --refresh-gaps         Run only userspace transports whose current evidence is stale
  --next-refresh-gap     Run only the first stale userspace transport
  --all-userspace        Run all cross-host userspace defaults
  --foreground           Run the matrix in the foreground
  --dry-run              Generate the selected defaults and print the command
  --skip-hygiene-check   Do not run pve-workspace-hygiene.sh before starting
  --quarantine-loose-root-artifacts
                         Move TrustIX-like /root leftovers into WORKSPACE/_scratch first

Required or defaulted environment:
  TRUSTIX_PVE_USERSPACE_A              default root@192.168.100.204
  TRUSTIX_PVE_USERSPACE_B              default root@192.168.100.203
  TRUSTIX_PVE_USERSPACE_SSH_OPTS       default -i /root/.ssh/trustix-cross-run ...
  TRUSTIX_PVE_USERSPACE_BIN_DIR_A      default /opt/trustix-COMMIT/bin
  TRUSTIX_PVE_USERSPACE_BIN_DIR_B      default /opt/trustix-COMMIT/bin
  TRUSTIX_PVE_USERSPACE_A_UNDERLAY_IP  default 10.203.3.204
  TRUSTIX_PVE_USERSPACE_B_UNDERLAY_IP  default 10.203.3.203
  TRUSTIX_PVE_USERSPACE_EVIDENCE_KERNEL_MATRIX
                                      default auto, collected with uname -r
EOF
}

die() {
  printf '[trustix-pve-userspace-refresh] ERROR: %s\n' "$*" >&2
  exit 1
}

log() {
  printf '[trustix-pve-userspace-refresh] %s\n' "$*" >&2
}

truthy() {
  case "${1:-0}" in
    1|true|yes|on|enabled) return 0 ;;
    *) return 1 ;;
  esac
}

abs_path() {
  local path="$1" dir base
  case "$path" in
    /*) ;;
    *) path="${PWD}/${path}" ;;
  esac
  dir="$(dirname "$path")"
  base="$(basename "$path")"
  if [[ -d "$path" ]]; then
    cd "$path" && pwd -P
  else
    mkdir -p "$dir"
    cd "$dir" && printf '%s/%s\n' "$(pwd -P)" "$base"
  fi
}

transport_label() {
  printf '%s' "$transports" | tr ',[:space:]' '-' | tr -cs 'A-Za-z0-9_.-' '-'
}

first_csv_item() {
  local list="$1"
  printf '%s' "$list" | awk -F, '{gsub(/^[[:space:]]+|[[:space:]]+$/, "", $1); print $1}'
}

validate_list() {
  local list="$1" item old_ifs
  [[ -n "$list" ]] || die "transport list is empty"
  old_ifs="$IFS"
  IFS=,
  set -- $list
  IFS="$old_ifs"
  for item in "$@"; do
    item="$(printf '%s' "$item" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    case "$item" in
      udp|tcp|quic|websocket|http_connect|experimental_tcp) ;;
      *) die "unsupported userspace transport for this refresh: $item" ;;
    esac
  done
}

generate_defaults() {
  local defaults_in="$1" defaults_out="$2" list="$3"
  awk -F '\t' -v list="$list" '
    BEGIN {
      OFS = "\t"
      split(list, raw, ",")
      for (i in raw) {
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", raw[i])
        if (raw[i] != "") want[raw[i]] = 1
      }
      print "# transport", "encryption", "profile", "datapath", "crypto_placement", "validation_scope", "gate_family", "min_gbps", "min_seconds", "note"
    }
    /^[[:space:]]*#/ || NF == 0 { next }
    NF < 9 { printf "invalid production defaults row: %s\n", $0 >"/dev/stderr"; exit 2 }
    $6 == "cross_host" && $7 == "userspace" && ($1 in want) {
      print $0
      count++
    }
    END {
      if (count < 1) {
        printf "no matching cross-host userspace defaults for %s\n", list >"/dev/stderr"
        exit 3
      }
    }
  ' "$defaults_in" >"$defaults_out"
}

detect_refresh_gap_transports() {
  local py output rc
  if command -v python3 >/dev/null 2>&1; then
    py=python3
  elif command -v python >/dev/null 2>&1; then
    py=python
  else
    die "--refresh-gaps requires python3 or python"
  fi

  set +e
  output="$("$py" - "$repo_root" <<'PY'
import json
import subprocess
import sys
from pathlib import Path

repo = Path(sys.argv[1])
cmd = [
    sys.executable,
    str(repo / "scripts" / "production-transport-audit.py"),
    "--scope",
    "cross_host",
    "--require-manifest",
    "--require-current",
    "--require-artifact-reference",
    "--require-current-build-ancestor",
    "--require-current-gate-tools",
    "--require-current-runtime-tree",
    "--fail-on-missing",
    "--report-refresh-gaps",
    "--json",
]
try:
    completed = subprocess.run(
        cmd,
        cwd=str(repo),
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
except subprocess.CalledProcessError as exc:
    if exc.stdout:
        print(exc.stdout, file=sys.stderr, end="")
    raise

rows = json.loads(completed.stdout)
transports = []
for row in rows:
    refresh = row.get("current_refresh") or {}
    default = row.get("default") or {}
    if refresh.get("status") != "refresh_needed":
        continue
    if default.get("gate_family") != "userspace":
        continue
    transport = default.get("transport") or ""
    if transport and transport not in transports:
        transports.append(transport)

if not transports:
    raise SystemExit(2)
print(",".join(transports))
PY
  )"
  rc=$?
  set -e
  case "$rc" in
    0)
      printf '%s\n' "$output"
      ;;
    2)
      die "no cross-host userspace current refresh gaps detected"
      ;;
    *)
      die "failed to detect current userspace refresh gaps"
      ;;
  esac
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workspace)
      [[ $# -ge 2 ]] || die "--workspace requires DIR"
      workspace="$2"
      shift 2
      ;;
    --run-root)
      [[ $# -ge 2 ]] || die "--run-root requires DIR"
      run_root="$2"
      shift 2
      ;;
    --transports)
      [[ $# -ge 2 ]] || die "--transports requires LIST"
      transports="$2"
      shift 2
      ;;
    --refresh-gaps)
      refresh_gaps=1
      shift
      ;;
    --next-refresh-gap)
      refresh_gaps=1
      next_refresh_gap=1
      shift
      ;;
    --all-userspace)
      transports="udp,tcp,quic,websocket,http_connect,experimental_tcp"
      shift
      ;;
    --foreground)
      background=0
      shift
      ;;
    --dry-run)
      dry_run=1
      shift
      ;;
    --skip-hygiene-check)
      skip_hygiene=1
      shift
      ;;
    --quarantine-loose-root-artifacts)
      quarantine_loose_root_artifacts=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

if truthy "$refresh_gaps"; then
  transports="$(detect_refresh_gap_transports)"
  if truthy "$next_refresh_gap"; then
    transports="$(first_csv_item "$transports")"
  fi
  log "selected refresh-gap userspace transports: $transports"
fi
validate_list "$transports"
mkdir -p "$workspace"
workspace="$(abs_path "$workspace")"
case "$workspace" in
  /|/root|/tmp|/var|/usr|/etc|/home|/opt) die "refusing unsafe workspace: $workspace" ;;
esac

if ! truthy "$skip_hygiene" && [[ -x "${repo_root}/scripts/pve-workspace-hygiene.sh" && "$workspace" == /root/* ]]; then
  hygiene_mode="--check"
  if truthy "$quarantine_loose_root_artifacts"; then
    hygiene_mode="--quarantine"
  fi
  "${repo_root}/scripts/pve-workspace-hygiene.sh" --workspace "$workspace" "$hygiene_mode"
fi

commit_short="$(git -C "$repo_root" rev-parse --short HEAD 2>/dev/null || printf 'current')"
stamp="$(date +%Y%m%d-%H%M%S)"
label="$(transport_label)"
if [[ -z "$run_root" ]]; then
  run_root="${workspace}/results/current-${commit_short}-userspace-${label}-production-${stamp}"
fi
run_root="$(abs_path "$run_root")"
case "$run_root" in
  "${workspace}/results/"*) ;;
  *) die "run root must be under ${workspace}/results, got $run_root" ;;
esac

scratch="${workspace}/_scratch"
mkdir -p "$run_root" "$scratch/scripts" "$scratch/pids"
defaults_file="${run_root}/userspace-defaults.tsv"
generate_defaults "${repo_root}/scripts/production-transport-defaults.tsv" "$defaults_file" "$transports"

node_a="${TRUSTIX_PVE_USERSPACE_A:-root@192.168.100.204}"
node_b="${TRUSTIX_PVE_USERSPACE_B:-root@192.168.100.203}"
ssh_opts="${TRUSTIX_PVE_USERSPACE_SSH_OPTS:--i /root/.ssh/trustix-cross-run -o BatchMode=yes -o StrictHostKeyChecking=accept-new}"
bin_dir_a="${TRUSTIX_PVE_USERSPACE_BIN_DIR_A:-/opt/trustix-${commit_short}/bin}"
bin_dir_b="${TRUSTIX_PVE_USERSPACE_BIN_DIR_B:-/opt/trustix-${commit_short}/bin}"
ca_bin="${TRUSTIX_PVE_USERSPACE_TRUSTIX_CA:-${repo_root}/build/release/trustix-linux-amd64/bin/trustix-ca}"
underlay_a_ip="${TRUSTIX_PVE_USERSPACE_A_UNDERLAY_IP:-10.203.3.204}"
underlay_b_ip="${TRUSTIX_PVE_USERSPACE_B_UNDERLAY_IP:-10.203.3.203}"
underlay_a_if="${TRUSTIX_PVE_USERSPACE_A_UNDERLAY_IF:-eth1}"
underlay_b_if="${TRUSTIX_PVE_USERSPACE_B_UNDERLAY_IF:-eth1}"
os_matrix="${TRUSTIX_PVE_USERSPACE_EVIDENCE_OS_MATRIX:-debian13-debian13}"
kernel_matrix="${TRUSTIX_PVE_USERSPACE_EVIDENCE_KERNEL_MATRIX:-auto}"
artifact="${TRUSTIX_PVE_USERSPACE_EVIDENCE_ARTIFACT:-docs/trustix-performance-log.md#$(date +%Y-%m-%d)-zaozhuang-pve-${commit_short}-userspace-${label}-production}"
note_template="${TRUSTIX_PVE_USERSPACE_EVIDENCE_NOTE_TEMPLATE:-current ${commit_short} Debian {transport} {encryption} userspace 3600s production gate evidence}"

runner_script="${scratch}/scripts/start-current-${commit_short}-userspace-${label}-production-${stamp}.sh"
pid_file="${scratch}/pids/current-${commit_short}-userspace-${label}-production-${stamp}.pid"

cat >"$runner_script" <<RUN
#!/usr/bin/env bash
set -euo pipefail
cd $(printf '%q' "$repo_root")
{
  echo "started_at=\$(date -Is)"
  echo "host=\$(hostname)"
  echo "repo=$(printf '%q' "$repo_root")"
  echo "commit=${commit_short}"
  echo "transports=${transports}"
} >$(printf '%q' "${run_root}/run.meta")

kernel_matrix=$(printf '%q' "$kernel_matrix")
node_a=$(printf '%q' "$node_a")
node_b=$(printf '%q' "$node_b")
ssh_opts=$(printf '%q' "$ssh_opts")
if [[ "\$kernel_matrix" == "auto" ]]; then
  ssh_args=()
  # shellcheck disable=SC2206
  ssh_args=(\${ssh_opts})
  kernel_a="\$(ssh -n "\${ssh_args[@]}" "\$node_a" uname -r)"
  kernel_b="\$(ssh -n "\${ssh_args[@]}" "\$node_b" uname -r)"
  [[ -n "\$kernel_a" && -n "\$kernel_b" ]] || {
    echo "failed to collect guest kernel matrix" >&2
    exit 1
  }
  kernel_matrix="\${kernel_a}_to_\${kernel_b}"
fi
echo "kernel_matrix=\$kernel_matrix" >>$(printf '%q' "${run_root}/run.meta")

set +e
env \\
  TRUSTIX_CROSS_HOST_A=$(printf '%q' "$node_a") \\
  TRUSTIX_CROSS_HOST_B=$(printf '%q' "$node_b") \\
  TRUSTIX_CROSS_HOST_SSH_OPTS=$(printf '%q' "$ssh_opts") \\
  TRUSTIX_CROSS_HOST_BIN_DIR_A=$(printf '%q' "$bin_dir_a") \\
  TRUSTIX_CROSS_HOST_BIN_DIR_B=$(printf '%q' "$bin_dir_b") \\
  TRUSTIX_CROSS_HOST_TRUSTIX_CA=$(printf '%q' "$ca_bin") \\
  TRUSTIX_CROSS_HOST_A_UNDERLAY_IP=$(printf '%q' "$underlay_a_ip") \\
  TRUSTIX_CROSS_HOST_B_UNDERLAY_IP=$(printf '%q' "$underlay_b_ip") \\
  TRUSTIX_CROSS_HOST_A_UNDERLAY_IF=$(printf '%q' "$underlay_a_if") \\
  TRUSTIX_CROSS_HOST_B_UNDERLAY_IF=$(printf '%q' "$underlay_b_if") \\
  TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_DEFAULTS=$(printf '%q' "$defaults_file") \\
  TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SCOPE=selected \\
  TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_WORKDIR=$(printf '%q' "${run_root}/matrix") \\
  TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SUMMARY=$(printf '%q' "${run_root}/summary.jsonl") \\
  TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_GATE_SUMMARY_DIR=$(printf '%q' "${run_root}/selected-production-gate") \\
  TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_EVIDENCE_OUT=$(printf '%q' "${run_root}/evidence.tsv") \\
  TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_EVIDENCE_OS_MATRIX=$(printf '%q' "$os_matrix") \\
  TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_EVIDENCE_KERNEL_MATRIX="\$kernel_matrix" \\
  TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_EVIDENCE_ARTIFACT=$(printf '%q' "$artifact") \\
  TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_EVIDENCE_NOTE_TEMPLATE=$(printf '%q' "$note_template") \\
  TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_KEEP_REMOTE=0 \\
  TRUSTIX_CROSS_HOST_KEEP_LOCAL=1 \\
  TRUSTIX_CROSS_HOST_KEEP_REMOTE=0 \\
  bash scripts/linux-cross-host-transport-matrix.sh >$(printf '%q' "${run_root}/matrix.stdout") 2>$(printf '%q' "${run_root}/matrix.stderr")
rc=\$?
set -e
echo "finished_at=\$(date -Is)" >>$(printf '%q' "${run_root}/run.meta")
echo "exit_code=\$rc" >>$(printf '%q' "${run_root}/run.meta")
exit "\$rc"
RUN
chmod +x "$runner_script"

printf 'RUN_ROOT=%s\nDEFAULTS=%s\nSCRIPT=%s\n' "$run_root" "$defaults_file" "$runner_script"
if truthy "$dry_run"; then
  printf 'DRY_RUN=1\n'
  exit 0
fi

if [[ "$background" == "1" ]]; then
  nohup "$runner_script" >"${run_root}/nohup.out" 2>"${run_root}/nohup.err" &
  pid=$!
  echo "$pid" >"$pid_file"
  printf 'PID=%s\nPID_FILE=%s\n' "$pid" "$pid_file"
else
  "$runner_script"
fi
