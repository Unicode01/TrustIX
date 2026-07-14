# TrustIX Security Model

This document describes the first-version security boundary that TrustIX intends
to enforce. It is a release checklist and operator guide, not a formal proof.

## Trust Roots And Roles

- Domain trust roots issue IX, Device, Route Authorization, Domain Config CA and
  Admin certificates. Removing or revoking a root affects future validation and
  can invalidate existing members when their chain no longer verifies.
- Admin certificates authorize management API mutations. When
  `api_admin_auth` or host API read/write auth is enabled, mutation requests must
  carry signed Admin proof headers. Config events store the proof material needed
  for peer replay verification.
- IX certificates identify IX nodes on peer mTLS, secure data sessions and
  membership advertisements. An IX certificate only authorizes that IX identity;
  domain-level resources still require Admin proof.
- Route Authorization certificates bind an IX to advertised prefixes. Dynamic
  route import must pass certificate, trust, admission and local route-policy
  checks before a prefix enters runtime routing.
- Device certificates are issued by an IX CA for device access. A device can
  receive a leased address and advertise only the prefixes accepted by the
  issuing IX policy.
- IX provision tokens are one-time bootstrap credentials. They have bounded TTL,
  are persisted in the local data dir, are consumed on first successful download,
  and must be treated as secret until used or expired.

## Management Surface

- The management and peer HTTP servers set bounded header read, write and idle
  timeouts. This is intended to reduce slowloris-style resource pinning without
  limiting large config restore uploads by total body read time.
- API JSON responses set `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer` and a restrictive permissions policy.
- Responses that contain private keys, bootstrap tokens or config backup
  archives set `Cache-Control: no-store`, `Pragma: no-cache` and `Expires: 0`.
- The embedded WebUI runs on the same origin as the management API. A configured
  `management.web_ui.custom_dir` is trusted same-origin code and can access
  browser-held Admin proof material, so doctor reports it as a warning.
- Host API should keep read and write authentication enabled on untrusted LANs.
  Anonymous host API writes are intentionally diagnosed as degraded.

## Data Plane Boundary

- `transport_policy.encryption: secure` uses TrustIX secure envelope with IX
  certificate authentication, AEAD and anti-replay. `plaintext` and directional
  encryption modes are operational compatibility settings, not confidentiality
  modes.
- `plaintext + security.link_tls: required` is TLS-only data mode. It still
  keeps TrustIX hello authentication and fails closed when the selected session
  does not actually use LinkTLS.
- Kernel crypto placement must be explicit or selected by `auto` only when the
  provider reports ready. A requested `kernel` placement fails closed instead of
  silently falling back to unauthenticated plaintext.
- TC/eBPF and kernel-module paths are performance paths. Userspace secure
  transport remains the compatibility fallback unless policy requests
  `require_kernel`.
- TrustIX does not manage firewall policy. Firewall doctor only reports kernel
  nftables/iptables compatibility state.

## Runtime Lifecycle

- The daemon holds a data-dir lock to prevent two processes from writing the same
  config log, members state, provision token store or dataplane state.
- Endpoint grants and device leases are runtime-authoritative. Expiry/revocation
  closes matching sessions and refreshes dataplane state.
- Config backup restore validates tar paths, rejects symlink/hardlink targets,
  limits archive entries and refuses private-key material that is not marked as
  private in the manifest.
- Normal shutdown detaches dataplane state and unloads modules only according to
  the configured module lifecycle. Crash cleanup is handled by
  `-cleanup-dataplane` and `-repair-dataplane`.

## Risky Configuration

- Binding the primary management API to `0.0.0.0` without TLS and Admin proof is
  unsafe.
- Custom WebUI assets are trusted operator code. Do not point `custom_dir` at a
  writable or untrusted path.
- Endpoint `plaintext` modes should only be used on trusted underlays or with
  `link_tls: required`.
- `route_policy.transit_forwarding` turns an IX into a transit node. Disable it
  when the IX must not forward traffic between other IXs.
- `import_transit_routes` lets an IX learn non-direct prefixes. Keep it disabled
  unless the domain routing model intentionally uses transit.

## Release Security Smoke

Run the focused local checks:

```bash
bash scripts/linux-security-smoke.sh
```

On a dedicated root Linux/PVE test host, include root data-plane checks:

```bash
sudo -E TRUSTIX_SECURITY_SMOKE_ROOT=1 bash scripts/linux-security-smoke.sh
```

For heavier pre-release validation, add TCP TLS and TIX-TCP data-plane
coverage:

```bash
sudo -E TRUSTIX_SECURITY_SMOKE_ROOT=1 TRUSTIX_SECURITY_SMOKE_HEAVY=1 bash scripts/linux-security-smoke.sh
```

The script runs security-focused Go tests, membership/trust-policy control-plane
smokes, and root-only device/data-plane smokes when enabled.
