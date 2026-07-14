# TrustIX datapath module

`trustix_datapath` is the first-release landing point for the complete TrustIX
kernel datapath. It is intentionally separate from the helper modules:

- `trustix_crypto` owns AEAD and `/dev/trustix_crypto`.
- `trustix_datapath_helpers` owns skb/header/GSO/route-TCP helper kfuncs and
  `/dev/trustix_datapath_helpers`.
- `trustix_datapath` owns the full route/session/queue datapath and
  `/dev/trustix_datapath`.

This module exposes the datapath query/selftest ABI,
route/session/session-wire/flow state batch ioctl tables, a route/flow/session
classify path, a dry-run IPv4 packet classify path with counters, and a
pass-through IPv4 prerouting hook that can classify real skb traffic without
modifying or forwarding it. The hook also keeps pass-through counters for outer
IPv4 UDP or TIX-TCP TIXT packets that match session-wire state. It also
has controlled TIXT encap/decap ioctls plus outer-packet build/parse ioctls. The
build path uses the same route/session/flow plus session-wire state to produce
an IPv4 UDP or TIX-TCP packet containing TIXT and the accepted inner
IPv4 payload. The parse path validates a single outer IPv4 UDP or
TIX-TCP packet against session-wire state and copies the inner IPv4
payload back out. When attached with `TX_PLAINTEXT`, the prerouting hook can
classify plaintext LAN IPv4 ingress, skip encrypted sessions, build an outer
TIXT UDP or TIX-TCP packet from session-wire state, send it through the
configured underlay target with `ip_local_out`, and drop the original inner skb
after successful encapsulation. GSO ingress is currently skipped and counted so
large-frame TX can be added separately. When attached with `RX_STAGE`, the
prerouting hook can also
validate an ingress outer TIXT packet, copy the inner IPv4 payload into a
bounded preallocated staging ring, and expose it through the RX-stage peek/pop
ioctl. RX_STAGE is a bounded staging path by itself; it does not call
`dev_queue_xmit`, inject into the protocol stack, or own skb forwarding. The
daemon may synchronize accepted IPv4
route/session/session-wire/flow records into `/dev/trustix_datapath` as a
control-plane landing point. When the module is loaded and an underlay interface
is configured, the daemon can attach the hook with `RX_STAGE` and poll the
staging ring in bounded batches, then feed popped inner IPv4 packets through the
existing daemon receive path. This is still a hybrid path: kernel validates and
copies ingress TrustIX frames, while daemon owns LAN reinjection and transit
routing. Tune it with `TRUSTIX_KERNEL_DATAPATH_RX_STAGE=0|1`,
`TRUSTIX_KERNEL_DATAPATH_RX_STAGE_BATCH`,
`TRUSTIX_KERNEL_DATAPATH_RX_STAGE_IDLE_DELAY`, and
`TRUSTIX_KERNEL_DATAPATH_RX_STAGE_ERROR_DELAY`. The module also contains a
default-off experimental `RX_WORKER` hook flag, gated by the
`rx_worker_inject=1` module parameter, that queues copied inner IPv4 packets
from the hook and injects them from a workqueue instead of directly from the
hook context. The daemon enables this only when
`TRUSTIX_KERNEL_DATAPATH_RX_WORKER=1` is set and a LAN target interface can be
resolved; the worker builds an Ethernet RX skb for that target and then calls
`netif_rx`. This exists only as a controlled step toward in-kernel RX ownership;
by default it still uses copied packets and needs explicit testing before use.
First-release production safety is fail-closed. The historical stolen-skb,
direct/inline XMIT, TCP stream parsing, RX coalesce, checksum-trust, MAC-cache,
queue-skb, and related tuning parameters remain visible for ABI and diagnostic
continuity, but they are read-only and forced back to safe defaults during
module init even if passed to `insmod`. The daemon also strips those raw module
parameters and ignores the old environment variables. Current production
`RX_WORKER` ownership is limited to the copied `netif_rx` reinjection path; any
path that could own or transmit borrowed skbs is unavailable until it has a
separate crash-free implementation and validation matrix.
The module reports `full_datapath` only when the packet ownership path is
explicitly enabled and self-tested: load with `enable_features=128`, keep all
first-release datapath selftests passing, and set `rx_worker_inject=1` and
`tx_plaintext=1`.
Without those conditions it stays loaded as a control-plane state/hook module
and marks the requested feature unsafe.

Build and inspect:

```sh
make -C kernel/trustix_datapath
sudo insmod kernel/trustix_datapath/trustix_datapath.ko enable_features=128 rx_worker_inject=1 tx_plaintext=1
cat /sys/module/trustix_datapath/parameters/abi_version
cat /sys/module/trustix_datapath/parameters/features
cat /sys/module/trustix_datapath/parameters/selftests
cat /sys/module/trustix_datapath/parameters/selftest_failures
cat /sys/module/trustix_datapath/parameters/route_records
cat /sys/module/trustix_datapath/parameters/session_records
cat /sys/module/trustix_datapath/parameters/session_wire_records
cat /sys/module/trustix_datapath/parameters/flow_records
```
