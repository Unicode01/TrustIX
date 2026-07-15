# TrustIX Active-Standby Gateway

TrustIX supports an operational active-standby topology in which two hosts
carry one logical IX identity. Keepalived/VRRP owns the floating addresses and
`trustix-ha.sh` ensures that only the selected host starts `trustixd`.

This is not active-active routing between two independent IX IDs. Do not run
the same IX certificate and data directory on two daemons at once.

## Topology contract

Both nodes need:

- The same TrustIX release, desired config, IX certificate/private key, trust
  material, and signed config-log state.
- A shared L2 segment or correctly configured unicast VRRP reachability.
- The same interface names expected by the TrustIX config, or per-node configs
  that normalize to the same logical IX state.
- Every address used as a LAN gateway, public data endpoint, control endpoint,
  or remotely reachable management endpoint included in keepalived's
  `virtual_ipaddress` set.
- A fencing mechanism that can prove the old active node cannot continue
  serving before the standby starts. Without fencing, a network partition can
  produce dual masters; VRRP is not consensus.

Configure the TrustIX LAN as `attach_mode: existing`. Keepalived adds the
gateway VIP before its `notify_master` hook starts TrustIX, so startup can
validate that the existing interface owns the configured gateway. The BACKUP
node has no gateway VIP and does not run `trustixd`.

## Install

Install keepalived using the operating system package manager. TrustIX release
installation places the helper at
`/usr/local/libexec/trustix/trustix-ha.sh` by default. Start from:

- `packaging/keepalived/trustix-ha.conf.example`
- `packaging/keepalived/trustix-ha.env.example`

Install the node-specific HA environment as
`/etc/trustix/<instance>.ha.env` with mode `0600`. Set different keepalived
priorities on the two hosts, for example 150 and 100. The health script must
remain unweighted: a sustained failure then moves the local VRRP instance to
`FAULT` and releases its VIPs. Combining `nopreempt` with a negative script
weight can suppress readiness-triggered takeover and must not be used.

The helper requires GNU Bash, `stat`, and either `curl` or `wget`. It rejects
symlinked, incorrectly owned, writable, or non-private HA environment files
before sourcing them. Fencing is required by default; an empty fencing hook
makes promotion fail closed unless a non-production deployment explicitly sets
`TRUSTIX_HA_REQUIRE_FENCE=0`.

Both keepalived instances should start in `BACKUP` and use `nopreempt`. Disable
normal boot activation of the daemon because keepalived owns its lifecycle:

```bash
sudo systemctl disable --now trustixd@ix-a.service
sudo keepalived -t -f /etc/keepalived/keepalived.conf
sudo systemctl enable --now keepalived
```

OpenWrt uses `/etc/init.d/trustix start|stop <instance>` through the same helper.
Do not enable the TrustIX instance independently in procd when HA owns it.

## Promotion sequence

For a MASTER notification, the helper performs these steps under a local
notification lock:

1. Stop and confirm the local daemon is inactive, so stale boot activation
   cannot bypass synchronization or fencing.
2. Require and run `TRUSTIX_HA_FENCE_HOOK` when
   `TRUSTIX_HA_REQUIRE_FENCE=1`.
3. Run the optional root-owned `TRUSTIX_HA_PRE_PROMOTE_HOOK` to atomically pull
   current config, certificates, and signed state.
4. Run `trustixd -check-config` without starting or loading dataplane modules.
5. Start the systemd/OpenWrt service.
6. Require `/readyz` to become HTTP 200 before recording `MASTER`.

Any fencing, synchronization, config, service, or readiness failure stops the
daemon and records `FAULT`. BACKUP, FAULT, and STOP notifications stop the
daemon and verify it is inactive before recording the target state. The
notification lock records its owner PID, recovers stale locks, and lets a newer
demotion cancel an in-flight promotion. The keepalived tracking check treats
BACKUP as healthy only when no daemon is running and the offline config
preflight passes; MASTER must keep passing semantic readiness.
A bounded `PROMOTING` grace period prevents the health weight from flapping
during normal startup.

Hooks must be absolute executable regular files, must not be symlinks or
group/world writable, and are required to be root-owned in production. The
helper exports `TRUSTIX_HA_INSTANCE` and `TRUSTIX_HA_TARGET_STATE=MASTER`.

## State synchronization

The helper deliberately does not invent a replication protocol for private
keys or local files. Use a storage/fencing system appropriate to the failure
domain, or use the pre-promote hook to install a previously staged snapshot
atomically. The signed config log is still verified at startup, so stale or
conflicting state fails closed.

The encrypted backup flow in [backup-recovery.md](backup-recovery.md) is the
disaster-recovery layer, not a substitute for low-latency standby state
replication. Periodically test both the state-sync hook and an offline encrypted
restore.

## Rolling upgrades

Keepalived is the only service owner for an HA-managed instance. The
transactional updater therefore refuses to restart an instance that has an
`/etc/trustix/<instance>.ha.env` file. Upgrade one node at a time:

1. Confirm the node is BACKUP, its daemon is stopped, and the peer is healthy.
2. Run `trustix-update.sh ... --instance <name> --no-restart`; candidate config
   preflight and transactional file rollback still run.
3. Rejoin the updated node as BACKUP and verify its offline HA check.
4. Perform a controlled failover, verify traffic and readiness on the updated
   node, then repeat for the other node.

For a breaking config or wire-format change, stage compatible config/state on
both nodes before failover. Do not use `systemctl restart trustixd@...` or the
OpenWrt init script directly on an HA-managed node. Before uninstalling one,
remove it from keepalived and demote it, then pass `--ha-offline` to the
uninstaller. Generic redeployment of an existing HA instance likewise requires
`--no-enable --no-start`; use the transactional updater for normal upgrades.

## Verification

Before production, verify all of the following on disposable nodes:

- Initial election starts exactly one daemon and moves every configured VIP.
- LAN hosts retain gateway reachability and established/new TrustIX traffic
  recovers within the intended failover budget.
- Killing the active daemon makes `/readyz` fail, lowers VRRP priority, and
  promotes the standby.
- Losing the active host entirely promotes the standby without shared-disk
  corruption.
- Returning the old node does not preempt the current master.
- A broken sync hook, invalid config, missing fence hook, and readiness 503 all
  leave the candidate in `FAULT` with no daemon running.
- Reconnecting the VRRP network after a partition cannot leave two unfenced
  masters. This requires testing the actual fencing system, not only
  keepalived.

Use `trustix-ha.sh status --instance <name>`, `/readyz`, Prometheus
`trustix_ready`, keepalived state, and the fencing system's audit log as the
minimum alerting surface.

For a disposable PVE topology that uses full plaintext kernel datapaths, run
`scripts/pve-ha-full-kmod-soak.sh` and gate its evidence with
`scripts/pve-ha-full-kmod-soak-verify.py`. The runner refuses VM IDs below 200,
requires a pinned module SHA256 and srcversion, serializes runs with a
non-inherited host lock, and tags every remote load process for bounded cleanup.
The default one-hour matrix alternates three complete active-VM stops with
three fenced VRRP partitions while 5 Hz ping, bidirectional TCP, and
bidirectional UDP remain active. The verifier requires continuous traffic,
module-counter, and PVE-state coverage; both failure kinds; bounded readiness
and ping outages; destination-MAC cache invalidation after each takeover;
stable remote/client boot IDs; matching module selftests and identity; and
empty kernel-fault and pstore artifacts. This is a destructive lab gate, not a
script to run against production VM IDs.

## Validation record

On 2026-07-15, the candidate helper was validated on two disposable Debian 13
VMs (`6.12.90+deb13.1-cloud-amd64`) with keepalived 2.3.3 and a real TrustIX
daemon. Both nodes used the same IX identity, desired config, signed route
authorization, and binary SHA256
`d95cd4d7957e4b820456698f2e60e3ac6129219893c1de89c1fd1a313c74cee9`.
The helper SHA256 was
`1ca480ed2372b9067e0dd245dcdb9c166f1c2ff7d6010dec01eea4f601238938`.

The verified matrix covered:

- Initial election with exactly one daemon plus management, peer, data, and LAN
  gateway VIP ownership.
- Semantic-readiness failure with PVE-API fencing and state synchronization;
  externally measured `/readyz` outage was 5.261 seconds.
- Unicast VRRP partition while the external fencing path remained reachable;
  the candidate powered off the old master before starting TrustIX.
- Complete active-VM loss; externally measured `/readyz` outage was 3.497
  seconds.
- Old-node return with no automatic failback.
- Corrupted staged-state checksum; the candidate fenced the old node, entered
  `FAULT`, kept its daemon stopped, released all VIPs, and required an explicit
  repaired BACKUP reset before promotion.
- A 180-iteration, 187-second steady-state gate with zero failures across
  `/readyz`, LAN gateway ping, data listener, peer listener, MASTER invariants,
  and BACKUP exclusivity invariants.

This run used `dataplane=noop` to isolate HA ownership and failure semantics. It
does not replace the separately recorded kernel-dataplane performance and soak
evidence.

The full plaintext kernel datapath was then exercised in the same fenced
active-standby topology. An initial run measured a 21.217-second traffic black
hole after takeover: the datapath's destination-MAC cache still held the
fenced master's MAC until its 30-second TTL expired. The candidate fix
subscribes to IPv4 neighbour updates and invalidates the bounded cache for the
affected interface when VRRP/GARP changes the neighbour entry.

The fixed module had SHA256
`b9157cc21430601fa693c9fb3ae1fb73034fe7ef2a15bdceb8621715a878d75b`,
srcversion `5E5AF38085790EBCCBB0F89`, and passed all module selftests. The final
3600.417-second verifier run alternated three complete host stops with three
fenced VRRP partitions. All 392 forward and 392 reverse TCP samples and all
392 forward and 392 reverse UDP samples passed. Maximum readiness recovery
was 7.744 seconds and maximum 5 Hz ping outage was 4.282 seconds. The module
processed 173,766,777 packets, recorded 55 destination-MAC cache
invalidations, and recorded zero neighbour misses or stale wires. Remote and
client boot IDs remained stable; all 14 kernel-fault artifacts and all 10
pstore artifacts were empty. The structured verifier returned `errors=[]`.

This validates full-kmod HA only with the documented external fencing and
state-sync contract. It does not permit two daemons with the same IX identity
to run concurrently and does not turn VRRP into a consensus protocol.
