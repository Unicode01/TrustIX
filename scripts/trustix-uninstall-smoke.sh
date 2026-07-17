#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
uninstall_script="${script_dir}/trustix-uninstall.sh"
workdir="$(mktemp -d /tmp/trustix-uninstall-smoke.XXXXXX)"
root="${workdir}/root"

log() {
  printf '[trustix-uninstall-smoke] %s\n' "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

cleanup() {
  rm -rf "$workdir"
}
trap cleanup EXIT

[[ "$(uname -s)" == "Linux" ]] || die "this smoke test requires Linux"
mkdir -p \
  "$root/bin" \
  "$root/libexec" \
  "$root/etc/trustix" \
  "$root/etc/systemd" \
  "$root/fake-bin" \
  "$root/state" \
  "$root/certs"

cat >"$root/bin/trustixd" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
config=""
cleanup=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    -config) config="$2"; shift 2 ;;
    -cleanup-dataplane) cleanup=1; shift ;;
    *) shift ;;
  esac
done
if [[ "$cleanup" == "1" ]]; then
	if [[ "${TRUSTIX_FAKE_FAIL_CLEANUP:-0}" == "1" ]]; then
		echo "injected cleanup failure" >&2
		exit 42
	fi
	printf '%s\n' "$config" >>"${TRUSTIX_FAKE_UNINSTALL_ROOT:?}/cleanup.log"
fi
EOF
chmod 0755 "$root/bin/trustixd"
for name in trustixctl trustix-ca trustix-device trustix-iptunnel-smoke; do
  cp "$root/bin/trustixd" "$root/bin/$name"
done

cat >"$root/libexec/trustix-backup.sh" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' "$*" >>"${TRUSTIX_FAKE_UNINSTALL_ROOT:?}/backup-helper.log"
EOF
cp "$root/libexec/trustix-backup.sh" "$root/libexec/trustix-ha.sh"
chmod 0755 "$root/libexec/trustix-backup.sh" "$root/libexec/trustix-ha.sh"

cat >"$root/fake-bin/systemctl" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' "$*" >>"${TRUSTIX_FAKE_UNINSTALL_ROOT:?}/systemctl.log"
if [[ "${1:-}" == "show" ]]; then
	case "${2:-}" in
		trustix-backup@missing.timer) printf 'not-found\n' ;;
		*) printf 'loaded\n' ;;
	esac
fi
EOF
chmod 0755 "$root/fake-bin/systemctl"

for unit in trustixd@.service trustix-backup@.service trustix-backup@.timer; do
  printf 'fixture\n' >"$root/etc/systemd/$unit"
done

write_instance() {
  local instance="$1"
  mkdir -p "$root/etc/trustix" "$root/state/${instance}"
  cat >"$root/etc/trustix/${instance}.yaml" <<EOF
domain:
  id: lab.local
ix:
  id: ${instance}
EOF
  cat >"$root/etc/trustix/${instance}.env" <<EOF
TRUSTIX_BIN=$root/bin/trustixd
TRUSTIX_CONFIG=$root/etc/trustix/${instance}.yaml
TRUSTIX_DATA_DIR=$root/state/${instance}
TRUSTIX_API_ADDR=127.0.0.1:8787
TRUSTIX_PEER_API_ADDR=127.0.0.1:9443
TRUSTIX_DATAPLANE=noop
EOF
}

run_uninstall() {
  PATH="$root/fake-bin:$PATH" \
    TRUSTIX_FAKE_UNINSTALL_ROOT="$root" \
    bash "$uninstall_script" \
      --all \
      --service-manager systemd \
      --prefix "$root" \
      --bindir "$root/bin" \
      --libexecdir "$root/libexec" \
      --sysconfdir "$root/etc/trustix" \
      --unitdir "$root/etc/systemd" \
      --state-root "$root/state" \
      --target-cert-dir "$root/certs" \
      --no-sudo \
      --keep-kernel-modules \
      "$@"
}

log "HA guard rejects uninstall before any mutation"
write_instance ix-a
printf 'TRUSTIX_BACKUP_RECIPIENT=/offline/key\n' >"$root/etc/trustix/ix-a.backup.env"
printf 'TRUSTIX_HA_REQUIRE_FENCE=1\n' >"$root/etc/trustix/ix-a.ha.env"
chmod 0600 "$root/etc/trustix/ix-a.backup.env" "$root/etc/trustix/ix-a.ha.env"
if run_uninstall --purge-config --keep-binaries --keep-service \
  >"$root/guard.out" 2>"$root/guard.err"; then
  die "HA-managed uninstall succeeded without --ha-offline"
fi
grep -q 'managed by active-standby HA' "$root/guard.err" || die "HA guard rejection was not explained"
[[ -f "$root/etc/trustix/ix-a.env" ]] || die "HA guard removed the instance env"
[[ ! -e "$root/systemctl.log" ]] || die "HA guard touched systemd before rejecting uninstall"

log "dataplane cleanup failure aborts before removing instance files"
if TRUSTIX_FAKE_FAIL_CLEANUP=1 run_uninstall --ha-offline --purge-config --keep-binaries --keep-service \
	>"$root/cleanup-failure.out" 2>"$root/cleanup-failure.err"; then
	die "uninstall succeeded despite dataplane cleanup failure"
fi
grep -q 'dataplane cleanup failed' "$root/cleanup-failure.err" || die "cleanup failure was not explained"
[[ -f "$root/etc/trustix/ix-a.env" ]] || die "cleanup failure removed the instance env"
[[ -f "$root/etc/trustix/ix-a.yaml" ]] || die "cleanup failure removed the instance config"

log "sidecars are not instances and purge removes their schedules and files"
run_uninstall --ha-offline --purge-config --keep-binaries --keep-service --json \
  >"$root/purge.out" 2>"$root/purge.err"
grep -q '"instances":\["ix-a"\]' "$root/purge.out" || die "sidecar env files were treated as instances"
grep -q 'disable --now trustix-backup@ix-a.timer' "$root/systemctl.log" || die "backup timer was not disabled"
grep -Fxq "$root/etc/trustix/ix-a.yaml" "$root/cleanup.log" || die "dataplane cleanup did not run for ix-a"
[[ "$(wc -l <"$root/cleanup.log")" == "1" ]] || die "dataplane cleanup ran for a sidecar pseudo-instance"
for path in \
  "$root/etc/trustix/ix-a.env" \
  "$root/etc/trustix/ix-a.backup.env" \
  "$root/etc/trustix/ix-a.ha.env" \
  "$root/etc/trustix/ix-a.yaml"; do
  [[ ! -e "$path" ]] || die "purge left $path"
done
[[ -x "$root/bin/trustixd" ]] || die "selective purge removed shared binaries"
[[ -f "$root/etc/systemd/trustixd@.service" ]] || die "selective purge removed shared units"

log "missing systemd timer is treated as already removed"
write_instance missing
run_uninstall --purge-config --keep-binaries --keep-service \
	>"$root/missing.out" 2>"$root/missing.err"
grep -q 'not installed; schedule removal skipped' "$root/missing.err" || die "missing timer was not reported as already removed"

log "shared removal deletes runtime binaries, helpers, units, and instance data"
: >"$root/systemctl.log"
write_instance ix-b
run_uninstall --purge --remove-binaries --remove-service --json \
  >"$root/remove.out" 2>"$root/remove.err"
grep -q '"instances":\["ix-b"\]' "$root/remove.out" || die "shared removal reported the wrong instance set"
[[ ! -e "$root/state/ix-b" ]] || die "shared removal left instance data"
for path in \
  "$root/bin/trustixd" \
  "$root/bin/trustix-iptunnel-smoke" \
  "$root/libexec/trustix-backup.sh" \
  "$root/libexec/trustix-ha.sh" \
  "$root/etc/systemd/trustixd@.service" \
  "$root/etc/systemd/trustix-backup@.service" \
  "$root/etc/systemd/trustix-backup@.timer"; do
  [[ ! -e "$path" ]] || die "shared removal left $path"
done

log "all uninstall lifecycle scenarios passed"
