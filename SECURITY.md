# Security Policy

TrustIX is currently pre-1.0 experimental software. The Linux dataplane and kernel modules are not yet hardened for production use; test them on disposable machines or VMs first.

## Secrets

Never publish generated TrustIX PKI material or runtime state:

- `certs/`
- `*.key`, `*.p12`, `*.pfx`
- `.trustix/`
- `config.log*`
- `members.json`
- `pending-members.json`
- benchmark/deployment artifacts under `build/`

If any CA, Admin, IX, endpoint, or device private key has been exposed, rotate it before using the domain again.

## Management API

Management writes should require Admin signed requests. Public listeners should use TLS and admin auth. Temporary lab Web UI/API listeners should be removed after testing.

## Kernel Datapath

Kernel module support is kernel-ABI specific. Build modules for the exact target kernel and run smoke tests before enabling required kernel placement. Keep unsafe or hard-enable datapath experiments disabled unless the host can reboot without impact.

## Reporting

For the first public version, use private issue reports or direct maintainer contact for security-sensitive findings until a formal disclosure address is published.
