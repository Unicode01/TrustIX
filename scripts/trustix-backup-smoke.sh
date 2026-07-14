#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
backup_script="${repo_root}/scripts/trustix-backup.sh"
workdir="$(mktemp -d /tmp/trustix-backup-smoke.XXXXXX)"
server_pid=""

log() {
  printf '[trustix-backup-smoke] %s\n' "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

cleanup() {
  set +e
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" >/dev/null 2>&1 || true
  fi
  rm -rf "$workdir"
}
trap cleanup EXIT

command -v go >/dev/null 2>&1 || die "go is required"
[[ "$(uname -s)" == "Linux" ]] || die "this smoke test requires Linux"

mkdir -p "$workdir/bin" "$workdir/etc" "$workdir/backups" "$workdir/fake-bin"
cat >"$workdir/fake-api.go" <<'EOF'
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
)

var archive = []byte("fake TrustIX recovery archive with PRIVATE KEY material")

func main() {
	addressFile := flag.String("address-file", "", "")
	flag.Parse()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(*addressFile, []byte(listener.Addr().String()), 0o600); err != nil {
		panic(err)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/config/export":
			w.Header().Set("Content-Type", "application/gzip")
			w.Header().Set("Content-Disposition", `attachment; filename="trustix-lab-ix-test.tar.gz"`)
			_, _ = w.Write(archive)
		case "/v1/config/validate-archive":
			payload, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			if err != nil || !bytes.Equal(payload, archive) {
				http.Error(w, "archive mismatch", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintln(w, `{"valid":true,"restorable":true,"recovery_complete":true}`)
		default:
			http.NotFound(w, r)
		}
	})
	if err := http.Serve(listener, handler); err != nil {
		panic(err)
	}
}
EOF

log "build trustixctl and fake API"
if [[ -n "${TRUSTIX_BACKUP_SMOKE_CTL:-}" ]]; then
  cp "$TRUSTIX_BACKUP_SMOKE_CTL" "$workdir/bin/trustixctl"
  chmod 0755 "$workdir/bin/trustixctl"
else
  (cd "$repo_root" && go build -o "$workdir/bin/trustixctl" ./cmd/trustixctl)
fi
go build -o "$workdir/bin/fake-api" "$workdir/fake-api.go"
"$workdir/bin/fake-api" -address-file "$workdir/api.addr" >"$workdir/api.log" 2>&1 &
server_pid=$!
for _ in {1..50}; do
  [[ -s "$workdir/api.addr" ]] && break
  kill -0 "$server_pid" >/dev/null 2>&1 || die "fake API exited"
  sleep 0.05
done
[[ -s "$workdir/api.addr" ]] || die "fake API did not publish its address"
api="http://$(cat "$workdir/api.addr")"

log "generate offline recovery key pair"
"$workdir/bin/trustixctl" config backup-keygen \
  -public "$workdir/backup.pub" \
  -identity "$workdir/backup.key" >"$workdir/keygen.json"
"$workdir/bin/trustixctl" config backup-keygen \
  -public "$workdir/wrong.pub" \
  -identity "$workdir/wrong.key" >"$workdir/wrong-keygen.json"

cat >"$workdir/etc/ix-test.env" <<EOF
TRUSTIX_BACKUP_CTL=$workdir/bin/trustixctl
TRUSTIX_BACKUP_API=$api
EOF
cat >"$workdir/etc/ix-test.backup.env" <<EOF
TRUSTIX_BACKUP_RECIPIENT=$workdir/backup.pub
TRUSTIX_BACKUP_DIR=$workdir/backups
TRUSTIX_BACKUP_KEEP=2
EOF

cat >"$workdir/fake-bin/crontab" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
store="${TRUSTIX_FAKE_CRONTAB:?}"
if [[ "${1:-}" == "-l" ]]; then
  [[ -f "$store" ]] && cat "$store"
  exit 0
fi
[[ $# -eq 1 ]] || exit 2
cp "$1" "$store"
EOF
chmod 0755 "$workdir/fake-bin/crontab"

log "install and remove idempotent OpenWrt cron schedule"
if [[ "${EUID:-$(id -u)}" != "0" ]]; then
  if PATH="$workdir/fake-bin:$PATH" \
    TRUSTIX_BACKUP_SCHEDULER=cron \
    TRUSTIX_FAKE_CRONTAB="$workdir/crontab" \
    bash "$backup_script" install-schedule \
      --instance ix-test \
      --instance-env "$workdir/etc/ix-test.env" \
      --backup-env "$workdir/etc/ix-test.backup.env" \
      >"$workdir/nonroot.out" 2>"$workdir/nonroot.err"; then
    die "cron schedule management allowed non-root without the test override"
  fi
  grep -q 'must run as root' "$workdir/nonroot.err" || \
    die "cron schedule management did not report the root requirement"
fi
for _ in 1 2; do
  PATH="$workdir/fake-bin:$PATH" \
    TRUSTIX_BACKUP_SCHEDULER=cron \
    TRUSTIX_BACKUP_TEST_ALLOW_NONROOT_SCHEDULE=1 \
    TRUSTIX_FAKE_CRONTAB="$workdir/crontab" \
    bash "$backup_script" install-schedule \
      --instance ix-test \
      --instance-env "$workdir/etc/ix-test.env" \
      --backup-env "$workdir/etc/ix-test.backup.env" >/dev/null
done
[[ "$(grep -c '# trustix-backup:ix-test' "$workdir/crontab")" == "1" ]] || die "cron schedule was duplicated"
PATH="$workdir/fake-bin:$PATH" \
  TRUSTIX_BACKUP_SCHEDULER=cron \
  TRUSTIX_BACKUP_TEST_ALLOW_NONROOT_SCHEDULE=1 \
  TRUSTIX_FAKE_CRONTAB="$workdir/crontab" \
  bash "$backup_script" remove-schedule \
    --instance ix-test \
    --instance-env "$workdir/etc/ix-test.env" \
    --backup-env "$workdir/etc/ix-test.backup.env" >/dev/null
if grep -q '# trustix-backup:ix-test' "$workdir/crontab"; then
  die "cron schedule was not removed"
fi

log "create and rotate encrypted backups"
for _ in 1 2 3; do
  bash "$backup_script" backup \
    --instance ix-test \
    --instance-env "$workdir/etc/ix-test.env" \
    --backup-env "$workdir/etc/ix-test.backup.env" \
    >"$workdir/backup.out"
  sleep 1
done
shopt -s nullglob
backups=("$workdir/backups/trustix-ix-test-"*.tixbak)
shopt -u nullglob
[[ ${#backups[@]} -eq 2 ]] || die "retention kept ${#backups[@]} backups, want 2"
latest="${backups[${#backups[@]}-1]}"
if grep -a -q 'PRIVATE KEY' "$latest"; then
  die "encrypted backup leaked plaintext private key marker"
fi

log "run no-mutation recovery drill"
bash "$backup_script" verify \
  --instance ix-test \
  --instance-env "$workdir/etc/ix-test.env" \
  --backup-env "$workdir/etc/ix-test.backup.env" \
  --identity "$workdir/backup.key" \
  --archive "$latest" >"$workdir/verify.json"
grep -Eq '"recovery_complete"[[:space:]]*:[[:space:]]*true' "$workdir/verify.json" || die "recovery drill response is incomplete"

if bash "$backup_script" verify \
  --instance ix-test \
  --instance-env "$workdir/etc/ix-test.env" \
  --backup-env "$workdir/etc/ix-test.backup.env" \
  --identity "$workdir/wrong.key" \
  --archive "$latest" >"$workdir/wrong.out" 2>"$workdir/wrong.err"; then
  die "recovery drill accepted the wrong identity"
fi

cp "$latest" "$workdir/tampered.tixbak"
printf '\001' >>"$workdir/tampered.tixbak"
if bash "$backup_script" verify \
  --instance ix-test \
  --instance-env "$workdir/etc/ix-test.env" \
  --backup-env "$workdir/etc/ix-test.backup.env" \
  --identity "$workdir/backup.key" \
  --archive "$workdir/tampered.tixbak" >"$workdir/tampered.out" 2>"$workdir/tampered.err"; then
  die "recovery drill accepted a tampered backup"
fi

log "all encrypted backup and recovery drill scenarios passed"
