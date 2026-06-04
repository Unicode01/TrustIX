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
IPv4 UDP or experimental-TCP TIXT packets that match session-wire state. It also
has controlled TIXT encap/decap ioctls plus outer-packet build/parse ioctls. The
build path uses the same route/session/flow plus session-wire state to produce
an IPv4 UDP or experimental-TCP packet containing TIXT and the accepted inner
IPv4 payload. The parse path validates a single outer IPv4 UDP or
experimental-TCP packet against session-wire state and copies the inner IPv4
payload back out. When attached with `TX_PLAINTEXT`, the prerouting hook can
classify plaintext LAN IPv4 ingress, skip encrypted sessions, build an outer
TIXT UDP or experimental-TCP packet from session-wire state, send it through the
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
For performance experiments, `rx_worker_steal_skb=1` makes the hook return
`NF_STOLEN` for validated linear ingress skbs and lets the worker retarget the
same skb as an inner IPv4 Ethernet RX packet. Non-linear or otherwise unsuitable
packets fall back to the copied worker path. Inspect
`rx_worker_stolen`, `rx_worker_steal_fallbacks`, and
`rx_worker_steal_errors` in sysfs when testing this path. The default stolen
path still queues into the worker. `rx_worker_inline_stolen=1` is a more
aggressive experiment that retargets suitable stolen skbs and calls `netif_rx`
directly from the hook path before returning `NF_STOLEN`; inspect
`rx_worker_inline_injected` and `rx_worker_inline_errors` alongside the normal
worker counters when testing it. When `rx_worker_xmit=1` is enabled, stolen
underlay skbs are not retargeted into `dev_queue_xmit` unless the explicitly
unsafe `rx_worker_steal_xmit=1` parameter is also set; the default xmit path
uses copied inner packets. The daemon additionally requires
`TRUSTIX_KERNEL_DATAPATH_RX_WORKER_ALLOW_UNSAFE_XMIT=1` before it will pass
`rx_worker_xmit=1`, because sustained veth LAN xmit remains an isolated
crash-risk experiment. `rx_worker_inline_receive=1` keeps the same
stolen-skb ownership model but uses `netif_receive_skb` instead of the
`netif_rx` backlog. TCP transport frames
are not claimed by `RX_WORKER` unless `rx_worker_tcp=1` is set, so the
experimental-TCP route/GSO RX path can keep owning stream parsing by default.
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
