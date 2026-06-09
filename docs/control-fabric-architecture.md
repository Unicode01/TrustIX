# TrustIX Control Fabric

This document defines the control-plane architecture TrustIX should converge to
before it is called suitable for very large IX domains.

## Current boundary

The current implementation is an eventually consistent signed-control system,
not a global consensus system.

It already has useful building blocks:

- Signed config log with hash-chain verification.
- Domain admissions, route authorization certificates, and trust resources.
- Membership advertisements signed by each IX.
- Peer polling with ETag caching, membership TTL, persisted member cache, and
  config-log rejoin.
- Route-policy controls for transit import/export and prefix conflicts.

That is enough for small and medium domains, and for controlled clusters where
the number of IX nodes and bootstrap peers is bounded. It is not enough by
itself for a very large IX fabric because full membership gossip can become
`O(N^2)` in bandwidth and CPU when every node learns every other node and then
polls every learned control endpoint.

## Target architecture

TrustIX should use a bounded anti-entropy fabric:

1. **Authority plane**

   Domain authority is a signed append-only resource log. It holds admissions,
   trust roots, revocations, route authorization state, and policy. It is not
   sent through data-plane broadcast. Nodes sync missing log ranges by hash head.

   The default first-release model is single-writer or admin-threshold
   multi-signer, not Raft/Paxos. Conflicts are fail-closed and require explicit
   `config rejoin`. If a future deployment requires automatic multi-writer
   ordering, that belongs in a small set of configured authority replicas, not
   every IX.

2. **Discovery plane**

   Discovery is route-reflector style. Public/core IX nodes, or configured
   reflectors, accept member advertisements and expose summaries. Edge IX nodes
   should poll a small reflector set instead of polling every learned IX.

   Learned members remain valid runtime candidates, but learned control
   endpoints must be subject to fanout limits, jitter, and policy. This prevents
   a newly reconnected node from causing every node to immediately contact every
   other node.

3. **Routing plane**

   Route advertisements are signed and scoped. A route carries origin, next hop,
   metric, source, and path. Import policy decides whether direct routes,
   transit routes, default routes, and overlapping prefixes are accepted.

   Large domains should prefer summary exchange:

   - Reflectors publish direct member routes and selected transit routes.
   - Edge nodes import selected routes, not all raw member state.
   - Route withdrawals are explicit when possible, with TTL pruning as the
     safety net.

4. **Data plane**

   Data sessions and route warmup are derived from the selected route set. They
   must not drive membership flooding. Endpoint health affects route candidate
   selection but does not mutate authority state.

## Recovery model

After an outage, recovery must be anti-entropy based:

1. Reconnect to a bounded set of bootstrap/static/reflector control APIs.
2. Compare config-log heads and pull/push only missing signed events.
3. Fetch membership summaries using ETag or delta/page APIs.
4. If the remote summary does not contain the local IX, push the local
   advertisement immediately even if the local unchanged-advertisement cache has
   not expired.
5. Recompute runtime routes, close stale data sessions only when the endpoint
   surface changed, and schedule route warmup with bounded concurrency.

This gives fast recovery without a full-domain broadcast.

## Anti-storm rules

Large deployments must obey these rules:

- Static/bootstrap/reflector targets are the primary sync set.
- Dynamic learned targets are optional and bounded by fanout.
- Member list responses must support ETag and should move to pagination/delta
  before very large domains.
- Advertisement push must be rate-limited, but the rate limiter must be bypassed
  when a remote peer demonstrably forgot the local IX.
- Config mutation preflight may skip unreachable peers, but must fail closed on
  hash conflicts.
- Route import/export policy must reject loops, default routes unless explicit,
  unauthorized prefixes, revoked signers, and disabled transit.

## Configuration

The first implementation exposes the beginning of this model through
`control_fabric`:

```json
{
  "control_fabric": {
    "profile": "edge",
    "dynamic_control_fanout": 32,
    "member_page_size": 128,
    "member_import_limit": 128
  }
}
```

Profiles set the default dynamic control fanout when
`dynamic_control_fanout`, `member_page_size`, and `member_import_limit` are not
explicitly configured:

- `small`: unlimited, intended for lab and small domains
- `edge`: 32 learned control targets per poll, 128 remote members per page/import
- `reflector`/`route_reflector`: 256 learned control targets per poll, 512 remote members per page/import
- `authority`/`core`: 512 learned control targets per poll, 1024 remote members per page/import
- unset/default: 128 learned control targets per poll, 256 remote members per page/import

The explicit enforcement knobs are:

- unset: use the profile-derived default, or the release default of 128 when no profile is set
- `0`: unlimited, mainly for lab/small domains
- positive value: deterministic rotating window over learned control targets

`member_page_size` limits how many remote IX advertisements a single
`/v1/control/members` response returns. The responder's local advertisement is
always included on every page so the caller can still confirm the target IX.

`member_import_limit` limits how many remote IX advertisements one poll imports
from one control target. When a response is truncated, the caller stores
`next_cursor` and resumes from that point on the next poll. This keeps very large
domains from creating a single long JSON decode/validation burst.

Static peers and bootstrap peers are never dropped by this dynamic fanout limit.
`TRUSTIX_DYNAMIC_CONTROL_TARGET_FANOUT`,
`TRUSTIX_CONTROL_MEMBER_PAGE_SIZE`, `TRUSTIX_CONTROL_MEMBER_IMPORT_LIMIT`, and
`TRUSTIX_CONTROL_MEMBER_MAX_PAGES` remain operational overrides.

Management API pagination is intentionally opt-in for compatibility. Existing
callers that omit `limit` still receive full arrays. The embedded WebUI uses
bounded runtime queries by default (`/peers`, `/links`, `/routes`, and
`/route-policy`) so a large domain does not force a full diagnostic payload into
the browser on every refresh.

## Required implementation stages

### P0: First-release hardening

- Keep the signed config log as the authority boundary.
- Preserve ETag-based membership fetch.
- Force repush local advertisement when a reachable peer's member summary lacks
  the local IX.
- Keep indirect gossip from refreshing liveness unless the target is directly
  observed.
- Keep transit import/export explicit and diagnosable.
- Add tests for hub outage, pruned membership, reconnect, and route restoration.

### P1: Bounded fabric mode

- Add explicit control-plane profile: `edge`, `reflector`, `authority`.
- Add dynamic control-target fanout with jitter and deterministic rotation.
- Add member summary pagination or delta sync.
- Add route-reflector summaries so edge nodes can avoid full member expansion.
- Add route warmup concurrency limits after large topology changes.

### P2: Large-domain authority replication

- Add an optional small authority replica set for ordered domain resources.
- Keep data IX nodes out of consensus.
- Use signed snapshots plus incremental ranges for bootstrap and disaster
  recovery.

## What can be guaranteed now

With the P0 behavior, a core/bootstrap IX can go offline and later recover in a
small or bounded topology: peers will retry, pull membership/config state, and
repush their local advertisements if the recovered node no longer remembers
them.

What is not guaranteed yet:

- No broadcast storm in an unbounded full-mesh learned-control topology.
- Sub-second convergence for thousands of IX nodes.
- Automatic multi-writer conflict resolution.
- Full route-reflector summary scaling.

Those require the P1/P2 stages above.
