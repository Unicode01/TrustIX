# TrustIX Encrypted Backup and Recovery

TrustIX configuration backups can contain IX private keys, TLS identities,
route-authorization material, trust roots, the signed config log, and the
current desired configuration. A production backup must therefore be encrypted
before it reaches persistent storage.

## Key model

TrustIX uses an anonymous X25519 sealed box for backup encryption. The source IX
needs only the public recipient key. Keep the identity on an offline recovery
system or in a separate secrets manager; do not place it in the source IX
backup environment.

Generate a key pair once on the recovery system:

```bash
trustixctl config backup-keygen \
  -public trustix-backup.pub \
  -identity trustix-backup.key
chmod 0600 trustix-backup.key
```

Copy only `trustix-backup.pub` to the IX. Key generation refuses to overwrite
either output file. The encrypted `.tixbak` envelope is authenticated, so a
wrong identity or any ciphertext modification fails closed.

## Instance setup

Create `/etc/trustix/<instance>.backup.env` with mode `0600`:

```bash
TRUSTIX_BACKUP_RECIPIENT=/etc/trustix/backup/trustix-backup.pub
TRUSTIX_BACKUP_DIR=/var/backups/trustix/config
TRUSTIX_BACKUP_KEEP=14
TRUSTIX_BACKUP_API=http://127.0.0.1:8787
```

If the management API requires Admin proofs, add matching certificate/key
lists. Threshold policies require the corresponding number of proof pairs:

```bash
TRUSTIX_BACKUP_ADMIN_CERT=/etc/trustix/admin/backup-admin.crt
TRUSTIX_BACKUP_ADMIN_KEY=/etc/trustix/admin/backup-admin.key
```

For HTTPS, set `TRUSTIX_BACKUP_API`, `TRUSTIX_BACKUP_API_TLS_CA`, and optionally
`TRUSTIX_BACKUP_API_TLS_SERVER_NAME`. Do not enable
`TRUSTIX_BACKUP_API_TLS_INSECURE_SKIP_VERIFY` in a scheduled production job.

Create and verify one backup manually before enabling a schedule:

```bash
/usr/local/libexec/trustix/trustix-backup.sh backup --instance ix-a

# Run on a controlled system that has the offline identity and can reach the IX.
/usr/local/libexec/trustix/trustix-backup.sh verify \
  --instance ix-a \
  --identity /secure/trustix-backup.key \
  --archive /path/to/trustix-ix-a-YYYYMMDDTHHMMSSZ.tixbak
```

`verify` decrypts in memory and calls `POST /v1/config/validate-archive`. The
daemon checks archive bounds, file allowlists and hashes, private-key markings,
domain/IX identity, the complete signed config-log chain, Admin proofs, and
runtime config validity. It does not write certificate files, replace the
config log, or switch runtime state. A complete disaster-recovery archive must
report both `valid: true` and `recovery_complete: true`.

## Scheduling

Systemd packages include `trustix-backup@.service` and
`trustix-backup@.timer`. After the backup env exists:

```bash
sudo /usr/local/libexec/trustix/trustix-backup.sh install-schedule --instance ix-a
systemctl list-timers 'trustix-backup@*'
```

On OpenWrt, the same command installs one idempotent root crontab entry using
the default `17 3 * * *` schedule and restarts cron. Override it with
`--cron 'MIN HOUR * * *'` or `TRUSTIX_BACKUP_CRON_SCHEDULE`. Remove either
platform's schedule with:

```bash
sudo /usr/local/libexec/trustix/trustix-backup.sh remove-schedule --instance ix-a
```

OpenWrt deployments normally install the helper below the selected TrustIX
prefix, for example `/opt/trustix/libexec/trustix/trustix-backup.sh`.

## Restore

Always run `verify-backup` first. A restore replaces configured files and the
signed config log transactionally, then switches the runtime. Existing files
and the current config log receive local backup copies.

```bash
trustixctl -api http://127.0.0.1:8787 \
  config verify-backup -identity /secure/trustix-backup.key backup.tixbak

trustixctl -api http://127.0.0.1:8787 \
  config restore -identity /secure/trustix-backup.key backup.tixbak
```

For a lost host, first install the same TrustIX release and recreate the
expected target paths and minimal local IX identity needed to start the
management API. Restore only to the same domain and IX ID. Keep a second copy
of the encrypted archive off-host and periodically run the no-mutation drill
from a separate recovery machine.
