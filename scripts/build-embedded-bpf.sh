#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ]; then
  echo "ERROR: scripts/build-embedded-bpf.sh requires GNU bash 4+" >&2
  exit 2
fi
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
clang_bin="${CLANG:-}"
out_dir=""
print_specs=0

usage() {
  cat <<'EOF'
usage: scripts/build-embedded-bpf.sh --out DIR [--clang CLANG]
       scripts/build-embedded-bpf.sh --print-specs

Builds the embedded eBPF ELF objects used by TrustIX.
EOF
}

log() {
  printf '[trustix-bpf] %s\n' "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

select_clang() {
  local candidate
  for candidate in clang-22 clang-21 clang-20 clang-19 clang-18 clang-17 clang-16 clang-15 clang; do
    if command -v "$candidate" >/dev/null 2>&1; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

emit_specs() {
  cat <<'EOF'
experimental_tcp_xdp_bpfel.o|kernel/bpf/dataplane/experimental_tcp_xdp.c|-DTRUSTIX_EXPERIMENTAL_TCP_XDP_RX_DIRECT_FIX_CONTROL_CHECKSUM=1
experimental_tcp_kernel_crypto_xdp_bpfel.o|kernel/bpf/dataplane/experimental_tcp_kernel_crypto_xdp.c|
experimental_tcp_kernel_crypto_tx_xdp_bpfel.o|kernel/bpf/dataplane/experimental_tcp_kernel_crypto_tx_xdp.c|
kernel_udp_xdp_bpfel.o|kernel/bpf/dataplane/kernel_udp_xdp.c|
kernel_udp_tx_kernel_crypto_tc_bpfel.o|kernel/bpf/dataplane/kernel_udp_tx_kernel_crypto_tc.c|
kernel_udp_rx_kernel_crypto_tc_bpfel.o|kernel/bpf/dataplane/kernel_udp_rx_kernel_crypto_tc.c|
skb_kfunc_tc_bpfel.o|kernel/bpf/dataplane/skb_kfunc_tc.c|
kernel_crypto_provider_bpfel.o|kernel/bpf/dataplane/kernel_crypto_provider.c|
kernel_crypto_selftest_bpfel.o|kernel/bpf/dataplane/kernel_crypto_selftest.c|
experimental_tcp_kernel_crypto_xdp_direct_bpfel.o|kernel/bpf/dataplane/experimental_tcp_kernel_crypto_xdp.c|-DTRUSTIX_EXP_TCP_DIRECT_OPEN=1
EOF
}

compile_spec() {
  local out_abs="$1"
  local object="$2"
  local source="$3"
  local extra_flags="$4"
  local -a flags=()
  if [[ -n "$extra_flags" ]]; then
    read -r -a flags <<<"$extra_flags"
  fi
  [[ -f "${repo_root}/${source}" ]] || die "missing eBPF source: ${source}"
  log "compile eBPF ${source}"
  (
    cd "$repo_root"
    "$clang_bin" \
      -target bpfel \
      -O2 \
      -g \
      -Wall \
      -Werror \
      -ffile-prefix-map="${repo_root}=." \
      -fdebug-prefix-map="${repo_root}=." \
      -fmacro-prefix-map="${repo_root}=." \
      -fdebug-compilation-dir=. \
      "${flags[@]}" \
      -c "$source" \
      -o "${out_abs}/${object}"
  )
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out)
      [[ $# -ge 2 ]] || die "--out requires a value"
      out_dir="$2"; shift 2 ;;
    --clang)
      [[ $# -ge 2 ]] || die "--clang requires a value"
      clang_bin="$2"; shift 2 ;;
    --print-specs)
      print_specs=1; shift ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      die "unknown argument: $1" ;;
  esac
done

if [[ "$print_specs" == "1" ]]; then
  emit_specs
  exit 0
fi

[[ -n "$out_dir" ]] || die "--out is required"
if [[ -z "$clang_bin" ]]; then
  clang_bin="$(select_clang)" || die "missing required command: clang"
fi
need_cmd "$clang_bin"

case "$out_dir" in
  /*) ;;
  *) out_dir="${repo_root}/${out_dir}" ;;
esac
mkdir -p "$out_dir"
out_abs="$(cd "$out_dir" && pwd -P)"

while IFS='|' read -r object source flags; do
  [[ -n "$object" ]] || continue
  compile_spec "$out_abs" "$object" "$source" "$flags"
done < <(emit_specs)
