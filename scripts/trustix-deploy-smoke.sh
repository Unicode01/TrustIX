#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
deploy_script="${script_dir}/trustix-deploy.sh"
workdir="$(mktemp -d /tmp/trustix-deploy-smoke.XXXXXX)"
root="${workdir}/root"

log() {
  printf '[trustix-deploy-smoke] %s\n' "$*" >&2
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
  "$root/etc" \
  "$root/certs" \
  "$root/systemd" \
  "$root/state" \
  "$root/backups" \
  "$root/fake-bin" \
	"$root/init" \
  "$workdir/candidate-bin" \
	"$workdir/openwrt-package/bin" \
	"$workdir/openwrt-package/packaging/openwrt" \
  "$workdir/source-certs"

for name in trustixd trustixctl trustix-ca; do
  printf 'old-%s\n' "$name" >"$root/bin/$name"
  printf '#!/usr/bin/env bash\nprintf "new-%s\\n"\n' "$name" >"$workdir/candidate-bin/$name"
  chmod 0755 "$root/bin/$name" "$workdir/candidate-bin/$name"
done
printf 'old-unit\n' >"$root/systemd/trustixd@.service"
printf 'old-config\n' >"$root/etc/ix-test.json"
printf 'old-env\n' >"$root/etc/ix-test.env"
printf 'old-cert\n' >"$root/certs/ix-test.crt"
printf '{"domain":{"id":"lab.local"},"ix":{"id":"ix-test"}}\n' >"$workdir/config.json"
printf 'new-cert\n' >"$workdir/source-certs/ix-test.crt"

cat >"$root/fake-bin/systemctl" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' "$*" >>"${TRUSTIX_FAKE_DEPLOY_ROOT:?}/systemctl.log"
case "${1:-}" in
  is-active|is-enabled) exit 0 ;;
  restart)
    marker="${TRUSTIX_FAKE_DEPLOY_ROOT}/restart-failed-once"
    if [[ ! -e "$marker" ]]; then
      : >"$marker"
      echo 'injected restart failure' >&2
      exit 42
    fi
    ;;
esac
EOF
chmod 0755 "$root/fake-bin/systemctl"

log "failed health transition restores every overwritten file"
if PATH="$root/fake-bin:$PATH" \
  TRUSTIX_FAKE_DEPLOY_ROOT="$root" \
  TRUSTIX_BACKUP_ROOT="$root/backups" \
  bash "$deploy_script" \
    --bin-dir "$workdir/candidate-bin" \
    --instance ix-test \
    --config "$workdir/config.json" \
    --cert-dir "$workdir/source-certs" \
    --target-cert-dir "$root/certs" \
    --service-manager systemd \
    --prefix "$root" \
    --sysconfdir "$root/etc" \
    --unitdir "$root/systemd" \
    --state-root "$root/state" \
    --no-sudo \
    >"$workdir/deploy.out" 2>"$workdir/deploy.err"; then
  die "deploy succeeded despite injected restart failure"
fi
grep -q 'restoring previous installation' "$workdir/deploy.err" || die "rollback was not reported"
for name in trustixd trustixctl trustix-ca; do
  grep -Fxq "old-${name}" "$root/bin/$name" || die "binary $name was not rolled back"
done
grep -Fxq 'old-unit' "$root/systemd/trustixd@.service" || die "systemd unit was not rolled back"
grep -Fxq 'old-config' "$root/etc/ix-test.json" || die "config was not rolled back"
grep -Fxq 'old-env' "$root/etc/ix-test.env" || die "env file was not rolled back"
grep -Fxq 'old-cert' "$root/certs/ix-test.crt" || die "certificate was not rolled back"
[[ ! -e "$root/bin/trustix-device" ]] || die "new optional binary survived rollback"
grep -q '^restart trustixd@ix-test.service$' "$root/systemctl.log" || die "previous service was not restarted"

log "active OpenWrt stop failure aborts and restores the previous init script"
cat >"$root/init/trustix" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' "$*" >>"${TRUSTIX_FAKE_DEPLOY_ROOT:?}/openwrt-init.log"
EOF
chmod 0755 "$root/init/trustix"
for name in trustixd trustixctl trustix-ca; do
	cp "$workdir/candidate-bin/$name" "$workdir/openwrt-package/bin/$name"
done
cat >"$workdir/openwrt-package/packaging/openwrt/trustix.init" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
case "${1:-}" in
	status|enable|start|restart) exit 0 ;;
	stop) echo 'injected active stop failure' >&2; exit 42 ;;
esac
EOF
chmod 0755 "$workdir/openwrt-package/packaging/openwrt/trustix.init"
tar -czf "$workdir/openwrt-package.tar.gz" -C "$workdir/openwrt-package" .

if TRUSTIX_FAKE_DEPLOY_ROOT="$root" \
	bash "$deploy_script" \
		--tarball "$workdir/openwrt-package.tar.gz" \
		--instance ix-test \
		--config "$workdir/config.json" \
		--cert-dir "$workdir/source-certs" \
		--target-cert-dir "$root/certs" \
		--service-manager openwrt \
		--prefix "$root" \
		--sysconfdir "$root/etc" \
		--initdir "$root/init" \
		--state-root "$root/state" \
		--no-openwrt-firewall \
		--no-sudo \
		>"$workdir/openwrt-deploy.out" 2>"$workdir/openwrt-deploy.err"; then
	die "OpenWrt deploy succeeded despite active instance stop failure"
fi
grep -q 'injected active stop failure' "$workdir/openwrt-deploy.err" || die "OpenWrt stop failure was not surfaced"
grep -q 'TRUSTIX_FAKE_DEPLOY_ROOT' "$root/init/trustix" || die "previous OpenWrt init script was not restored"
grep -Fxq 'restart ix-test' "$root/openwrt-init.log" || die "previous OpenWrt instance was not restarted"

log "deploy rollback smoke passed"
