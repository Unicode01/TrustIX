#!/bin/sh
set -eu

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
workdir="$(mktemp -d /tmp/trustix-openwrt-init-smoke.XXXXXX)"

cleanup() {
	rm -rf "$workdir"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$workdir/etc"
printf 'TRUSTIX_CONFIG=/etc/trustix/ix-main.yaml\n' >"$workdir/etc/ix-main.env"
printf 'TRUSTIX_BACKUP_RECIPIENT=/offline/key\n' >"$workdir/etc/ix-main.backup.env"
printf 'TRUSTIX_HA_REQUIRE_FENCE=1\n' >"$workdir/etc/ix-main.ha.env"

TRUSTIX_SYSCONFDIR="$workdir/etc"
export TRUSTIX_SYSCONFDIR
# shellcheck disable=SC1091
. "$repo_root/packaging/openwrt/trustix.init"

record_instance() {
	printf '%s\n' "$1" >>"$workdir/instances"
}

trustix_for_each_instance record_instance ""
[ "$(cat "$workdir/instances")" = "ix-main" ] || {
	echo "OpenWrt init treated sidecar env files as instances" >&2
	exit 1
}

if trustix_for_each_instance record_instance ix-main.backup >/dev/null 2>&1; then
	echo "OpenWrt init accepted an explicit backup sidecar instance" >&2
	exit 1
fi
if trustix_for_each_instance record_instance ix-main.ha >/dev/null 2>&1; then
	echo "OpenWrt init accepted an explicit HA sidecar instance" >&2
	exit 1
fi

printf '[trustix-openwrt-init-smoke] sidecar discovery guards passed\n' >&2
