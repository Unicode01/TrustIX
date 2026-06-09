#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ]; then
  echo "ERROR: scripts/trustix-build.sh requires GNU bash 4+" >&2
  exit 2
fi
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export TRUSTIX_REPO_ROOT="${TRUSTIX_REPO_ROOT:-$repo_root}"
# shellcheck source=scripts/trustix-prereqs.sh
source "${repo_root}/scripts/trustix-prereqs.sh"

usage() {
  cat <<'EOF'
usage: scripts/trustix-build.sh [options]

Builds a TrustIX Linux release tarball with a stable CLI for automation.

Options:
  --out DIR                 release output dir (default: build/release)
  --name NAME               release name (default: trustix-linux-<goarch>)
  --version VERSION         build version string
  --commit COMMIT           build commit string
  --goarch ARCH             target Go arch: amd64, arm64, arm (default: host)
  --goos OS                 target Go OS (default: linux)
  --kdir DIR                target kernel build dir for .ko build
  --build-bpf 0|1           recompile embedded eBPF objects on this host (default: 1)
  --build-ko auto|0|1       build kernel modules (default: auto)
  --embed-ko 0|1            embed built .ko into trustixd (default: 1)
  --build-tests 0|1         build ebpf.test/kernelmodule.test (default: 1)
  --skip-webui              skip npm WebUI check/build
  --json                    print machine-readable summary
  -h, --help                show this help
EOF
}

log() {
  printf '[trustix-build] %s\n' "$*" >&2
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

goos="${GOOS:-linux}"
goarch="$(normalize_goarch "${GOARCH:-$(host_goarch)}")"
out_dir="${TRUSTIX_BUILD_OUT:-${repo_root}/build/release}"
release_name=""
version="${TRUSTIX_RELEASE_VERSION:-}"
commit="${TRUSTIX_RELEASE_COMMIT:-}"
kdir="${KDIR:-}"
build_bpf="${TRUSTIX_RELEASE_BUILD_BPF:-1}"
build_ko="${TRUSTIX_BUILD_KO:-auto}"
embed_ko="${TRUSTIX_RELEASE_EMBED_KO:-1}"
build_tests="${TRUSTIX_RELEASE_BUILD_TESTS:-1}"
build_webui=1
json=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out)
      [[ $# -ge 2 ]] || die "--out requires a value"
      out_dir="$2"; shift 2 ;;
    --name)
      [[ $# -ge 2 ]] || die "--name requires a value"
      release_name="$2"; shift 2 ;;
    --version)
      [[ $# -ge 2 ]] || die "--version requires a value"
      version="$2"; shift 2 ;;
    --commit)
      [[ $# -ge 2 ]] || die "--commit requires a value"
      commit="$2"; shift 2 ;;
    --goarch)
      [[ $# -ge 2 ]] || die "--goarch requires a value"
      goarch="$(normalize_goarch "$2")"; shift 2 ;;
    --goos)
      [[ $# -ge 2 ]] || die "--goos requires a value"
      goos="$2"; shift 2 ;;
    --kdir)
      [[ $# -ge 2 ]] || die "--kdir requires a value"
      kdir="$2"; shift 2 ;;
    --build-bpf)
      [[ $# -ge 2 ]] || die "--build-bpf requires a value"
      build_bpf="$2"; shift 2 ;;
    --build-ko)
      [[ $# -ge 2 ]] || die "--build-ko requires a value"
      build_ko="$2"; shift 2 ;;
    --no-ko)
      build_ko=0; shift ;;
    --embed-ko)
      [[ $# -ge 2 ]] || die "--embed-ko requires a value"
      embed_ko="$2"; shift 2 ;;
    --build-tests)
      [[ $# -ge 2 ]] || die "--build-tests requires a value"
      build_tests="$2"; shift 2 ;;
    --skip-webui)
      build_webui=0; shift ;;
    --json)
      json=1; shift ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      die "unknown argument: $1" ;;
  esac
done

case "$build_ko" in
  auto|0|1) ;;
  *) die "--build-ko must be auto, 0, or 1" ;;
esac
case "$build_bpf" in 0|1) ;; *) die "--build-bpf must be 0 or 1" ;; esac
case "$embed_ko" in 0|1) ;; *) die "--embed-ko must be 0 or 1" ;; esac
case "$build_tests" in 0|1) ;; *) die "--build-tests must be 0 or 1" ;; esac

if [[ -z "$release_name" ]]; then
  release_name="trustix-${goos}-${goarch}"
fi
if [[ -z "$version" ]]; then
  version="$release_name"
fi

trustix_prereqs_ensure_commands go install realpath sha256sum stat tar gzip || die "source build dependencies are missing; automatic dependency install failed"
if [[ "$build_bpf" == "1" ]]; then
  manager="$(trustix_prereqs_package_manager 2>/dev/null || true)"
  bpf_strict="$(trustix_prereqs_lower_ascii "${TRUSTIX_RELEASE_BPF_STRICT:-0}")"
  if [[ "$manager" == "opkg" && "$bpf_strict" != "1" && "$bpf_strict" != "true" && "$bpf_strict" != "yes" && "$bpf_strict" != "on" ]]; then
    log "OpenWrt/opkg does not normally provide clang/LLVM; using embedded eBPF objects from the source tree (build_bpf=0)"
    build_bpf=0
  else
    if ! trustix_prereqs_ensure_commands clang make gcc; then
      die "BPF rebuild dependencies are missing; automatic dependency install failed"
    fi
  fi
fi
if [[ -z "${GOPROXY:-}" ]] && trustix_prereqs_mirrors_enabled; then
  export GOPROXY="https://goproxy.cn,https://goproxy.io,direct"
fi

if [[ "$build_webui" == "1" ]]; then
  trustix_prereqs_ensure_webui_deps || die "npm is required for WebUI build; automatic dependency install failed; use --skip-webui to bypass"
  log "check WebUI"
  (cd "$repo_root" && npm run webui:check)
  log "build WebUI"
  (cd "$repo_root" && npm run webui:build)
fi

effective_build_ko="$build_ko"
if [[ "$effective_build_ko" == "auto" ]]; then
  effective_build_ko=0
  if [[ "$(uname -s)" == "Linux" ]]; then
    if [[ -n "$kdir" && -d "$kdir" ]]; then
      effective_build_ko=1
    elif [[ -d "/lib/modules/$(uname -r)/build" ]]; then
      effective_build_ko=1
    fi
  fi
fi

if [[ "$effective_build_ko" == "1" && "$(uname -s)" != "Linux" ]]; then
  die "kernel module release builds must run on Linux; use --build-ko 0 for userspace-only cross builds"
fi

log "release name=${release_name} target=${goos}/${goarch} build_bpf=${build_bpf} build_ko=${effective_build_ko}"

export GOOS="$goos"
export GOARCH="$goarch"
export TRUSTIX_RELEASE_NAME="$release_name"
export TRUSTIX_RELEASE_OUT="$out_dir"
export TRUSTIX_RELEASE_VERSION="$version"
export TRUSTIX_RELEASE_BUILD_BPF="$build_bpf"
export TRUSTIX_RELEASE_BUILD_KO="$effective_build_ko"
export TRUSTIX_RELEASE_EMBED_KO="$embed_ko"
export TRUSTIX_RELEASE_BUILD_TESTS="$build_tests"
if [[ -n "$commit" ]]; then
  export TRUSTIX_RELEASE_COMMIT="$commit"
fi
if [[ -n "$kdir" ]]; then
  export KDIR="$kdir"
fi

bash "${repo_root}/scripts/build-release-linux.sh"

tarball="${out_dir}/${release_name}.tar.gz"
manifest="${out_dir}/${release_name}/package/manifest.json"
bin_dir="${out_dir}/${release_name}/bin"
[[ -f "$tarball" ]] || die "release tarball was not created: $tarball"

if [[ "$json" == "1" ]]; then
  printf '{'
  printf '"tarball":"%s",' "$(json_escape "$tarball")"
  printf '"manifest":"%s",' "$(json_escape "$manifest")"
  printf '"bin_dir":"%s",' "$(json_escape "$bin_dir")"
  printf '"name":"%s",' "$(json_escape "$release_name")"
  printf '"target":{"goos":"%s","goarch":"%s"},' "$(json_escape "$goos")" "$(json_escape "$goarch")"
  printf '"build_bpf":%s,' "$build_bpf"
  printf '"build_ko":%s' "$effective_build_ko"
  printf '}\n'
else
  log "tarball: $tarball"
  log "bin_dir: $bin_dir"
fi
