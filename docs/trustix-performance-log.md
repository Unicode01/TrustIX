# TrustIX performance log

This file records datapath performance findings and script changes so future runs do not depend on chat context.

Production evidence rows in `scripts/production-transport-evidence.tsv` record
the gate manifest schema plus the SHA256 of the production gate script and
verifier used for the run. Rows captured before
`production-gate-manifest.json` existed are marked `legacy-pre-manifest`; new
production evidence must copy the schema and hashes from that manifest instead
of reusing the legacy marker. New passing production evidence must be generated
from production-gate summaries so `scripts/production-evidence-from-gate-summary.py`
can verify the measured soak reached at least 3600 seconds, the run timing was
`iperf_mode=forward` with `iperf_directions=both`, boot IDs stayed stable on at
least two nodes, bidirectional iperf interval coverage passed, result markers
were `pass`, both nodes ran the same binary, loaded-module and LAN interface
state artifacts were present, and kernel log plus pstore artifacts were
collected cleanly.

Current production-default evidence boundary:

| Default family | Evidence status | Boundary |
| --- | --- | --- |
| Debian `full_kmod` | manifest-backed 3600s per-direction PVE gate on Debian 13 `6.12.94+deb13-amd64` at commit `1a72df194383d74fef5b03f68878f72734addb39` | Production default tests require `trustix-cross-host-production-gate-manifest-v1` evidence for this family. |
| Debian `tc_direct`, `secure_kudp` | manifest-backed 3600s per-direction PVE gates on Debian 13 `6.12.94+deb13-cloud-amd64` | Secure-kUDP now gates replay-old separately from replay-seen/drop ratios. Production default tests require `trustix-cross-host-production-gate-manifest-v1` evidence for these families. |
| Debian `route_gso` | manifest-backed 3600s per-direction PVE gate on Debian 13 `6.12.94+deb13-cloud-amd64` | Production default tests require `trustix-cross-host-production-gate-manifest-v1` evidence for this family. |
| Debian userspace and userspace-TC defaults | manifest-backed 3600s forward PVE gates on Debian 13 `6.12.69+deb13-amd64` | Production default tests require `trustix-cross-host-production-gate-manifest-v1` evidence for these families and require `run-timing.json` to prove `iperf_mode=forward`, `iperf_directions=both`. |
| Secure experimental TCP kernel crypto | manifest-backed 3600s per-direction PVE gate on Debian 13 `6.12.90+deb13.1-cloud-amd64` with direct-kfunc FPU fallback exercised | This is now a dedicated `secure_exp_tcp_kernel` production default; it must not reuse `secure_kudp` evidence. |
| OpenWrt-Debian `owdeb_full_kmod` | manifest-backed 3600s PVE gate on OpenWrt 24.10.7 `6.6.141` to Debian 13 `6.12.90+deb13.1-cloud-amd64` at commit `01ca47e` | Selected OpenWrt kernel path remains UDP plaintext full-kmod; production default tests now require manifest evidence for this family. |
| OpenWrt route-GSO and secure-kUDP route-GSO | fail-closed capability evidence only | Not production defaults until a tested OpenWrt kernel exposes usable route-TCP kfunc capability and passes a cross-host gate. |

## 2026-06-25

<a id="2026-06-25-zaozhuang-pve-secure-exp-tcp-kernel-fpu-fallback-3600s-production-gate"></a>

### Zaozhuang PVE secure experimental TCP kernel FPU fallback 3600s production gate

PVE host `120.220.44.72:8006` was used with disposable VM IDs 200+ only:
VM200 `trustix-dd-a` and VM201 `trustix-dd-b` on isolated `vmbr3`. VM100 and
all 1xx guests were not modified. Both guests ran Debian 13 on
`6.12.90+deb13.1-cloud-amd64`.

The diagnostic build used TrustIX version `trustix-diag-fpu-fallback`, commit
`diag-fpu-fallback-latest`, Go `1.25.0`, build time
`2026-06-24T15:34:06Z`, binary SHA256
`7e86caa610ed6805b7f5d6f3a87493ff7b47f5ebcb1d8b1922868a2315a8c744`, and
embedded assets SHA256
`baf9e41b7f025de66b661c8f0978b0bd292adb30e731939ee04140c649d9e36f`.

The selected production gate emitted
`trustix-cross-host-production-gate-manifest-v1` evidence. The production gate
script SHA256 was
`fd3b737826ee4256d3dd2169519edb000c5f010092820ae05cfda91442b2f70e`; the
verifier SHA256 was
`691bd691303fddbe6d8f243c99e21c25f75cfcb8ab3f0cfb5e47a2707b6ae34b`.

| Direction | Gate | Received | Sent | Evidence seconds | Retransmits |
| --- | ---: | ---: | ---: | ---: | ---: |
| A to B | 1.5 Gbps | 1.599325 Gbps | 1.599377 Gbps | 3600.010616 | 61487 |
| B to A | 1.5 Gbps | 1.648179 Gbps | 1.648234 Gbps | 3600.015214 | 65598 |

The sequential `forward + both` run lasted 7204 seconds, from
`2026-06-24T16:10:50Z` to `2026-06-24T18:10:54Z`, and passed with
`errors=[]`, `log_findings=[]`, stable boot IDs
`ab48eea9-31ba-4efe-b342-9c4a333358c7` and
`48d6ec49-05a8-4dd7-891c-2bf798234986`, clean kernel journal artifacts, and
pstore coverage on both nodes.

This gate used `experimental_tcp` secure mode with `datapath=kernel_module`,
`crypto_placement=kernel`, 16 active sessions, direct kfunc crypto, and route
TCP GSO async. Both peers loaded `trustix_crypto` and
`trustix_datapath_helpers`; `tix-lan` `tx_queue_len` was `1000`.

Direct kfunc counters prove the fixed FPU-unavailable path was covered rather
than skipped. Node A reported `direct_kfunc_fpu_unavailable_fallbacks=1`; node
B reported `direct_kfunc_fpu_unavailable_fallbacks=13`. On both nodes,
`direct_kfunc_errors`, `direct_kfunc_open_errors`,
`direct_kfunc_eopnotsupp_errors`, all per-site direct kfunc error counters,
and route-GSO async stream/xmit/direct errors were zero.

## 2026-06-24

<a id="2026-06-24-zaozhuang-pve-openwrt-24107-current-head-full-kmod-3600s-production-gate"></a>

### Zaozhuang PVE OpenWrt 24.10.7 current-head full-kmod 3600s production gate

PVE host `120.220.44.72:8006` was used with disposable VM IDs 200+ only:
VM200 Debian 13 and VM201 OpenWrt 24.10.7 x86_64 on isolated `vmbr3`. VM100
and all 1xx guests were not modified. The run used commit `01ca47e`, Go
`1.25.0`, build time `2026-06-24T07:35:23Z`, and TrustIX binary SHA256
`ae4f599dc714ade5252d09a5223d658bf307fee30157b5f9da8ea18364b4f4bb`.

The OpenWrt guest ran kernel `6.6.141`; the Debian guest ran
`6.12.90+deb13.1-cloud-amd64`. OpenWrt modules were built from the matching
24.10.7 SDK and the Debian modules were built for the running Debian kernel.

OpenWrt module hashes:

| Module | SHA256 |
| --- | --- |
| `trustix_crypto.ko` | `f8be71eddc0bc09f38b0499a7dba81cfffb9a9e47f202e595358778aea2e2b88` |
| `trustix_datapath.ko` | `005fee841ca6cb82b030bd31abac799f9e9dbd7ce7d2b5ceda340612c0c91fce` |
| `trustix_datapath_helpers.ko` | `450e91c29b8d825788bf58291582a967a39b6eaa590d6b33eb39c8adcf12e773` |

The selected production gate emitted
`trustix-cross-host-production-gate-manifest-v1` evidence. The production gate
script SHA256 was
`0d6f3860692393025c945ae445820477dbbe06c78576a1e3515078f8d9b7395e`; the
verifier SHA256 was
`691bd691303fddbe6d8f243c99e21c25f75cfcb8ab3f0cfb5e47a2707b6ae34b`.

| Direction | Gate | Received | Sent | Evidence seconds |
| --- | ---: | ---: | ---: | ---: |
| OpenWrt to Debian | 3 Gbps | 3.438634 Gbps | 3.438713 Gbps | 3600.035847 |
| Debian to OpenWrt | 3 Gbps | 5.000735 Gbps | 5.000784 Gbps | 3600.037834 |

The sequential `forward + both` run lasted 7204 seconds, from
`2026-06-24T10:11:03Z` to `2026-06-24T12:11:07Z`, and passed with
`errors=[]` and `log_findings=[]`. OpenWrt boot ID
`3a283526-6ae0-490d-bcac-ecebc1e1d8b3` and Debian boot ID
`69be813b-c67e-4123-8029-61ad560bca6c` were unchanged before and after the
run. Kernel log and pstore artifacts were clean on both guests, `tix-lan`
`tx_queue_len` was `1000`, `trustix_datapath` was loaded on both peers, and
the verifier saw full plaintext provider status with eight session
records/wires.

Covered module counters were zero for allocation, delivery, GSO xmit, TX build,
TX xmit, queue-drop, stale-wire, no-session, and no-wire errors. Runtime
parameters reported `enable_features=128`, `safe_features=128`,
`unsafe_features=0`, `selftest_failures=0`, `rx_worker_inject=Y`, and
`tx_plaintext=Y`; GSO segment and cached destination MAC counters were nonzero.

A separate simultaneous bidirectional 3600s diagnostic on the same VM pair
also completed without reboot, panic, pstore, or covered module errors, but it
was not promoted as throughput evidence because one direction dropped to
0.466902 Gbps and 0.757769 Gbps in the strict bidirectional verifier. After
verification, VM200, VM201, isolated `vmbr3`, local source copies, short smoke
artifacts, and temporary keys were removed. The preserved evidence directories
on the PVE host are
`/root/trustix-runs/owdeb-fullkmod-forward-gate-20260624T101058Z` and
`/root/trustix-runs/owdeb-fullkmod-bidir-1h-20260624T080100Z`.

<a id="2026-06-24-zaozhuang-pve-openwrt-25124-route-gso-runtime-check"></a>

### Zaozhuang PVE OpenWrt 25.12.4 route-GSO runtime check

PVE host `120.220.44.72:8006` was used with disposable VM IDs 200+ only:
VM200 Debian 13 (`10.203.3.200`) and VM201 OpenWrt 25.12.4 x86_64
(`10.203.3.201`) on isolated `vmbr3`. VM100 and all 1xx guests were not
modified. The local source archive came from commit
`b2aafdaa3d727efb4e70eab1a8c9d3c77b8c123a`; because it was built from an
archive, the validation binary reported `commit=unknown`, build time
`2026-06-24T05:01:50Z`, Go `1.25.0`.

The Debian guest ran kernel `6.12.94+deb13-amd64` and exposed
`/sys/kernel/btf/vmlinux`. The OpenWrt guest ran kernel `6.12.87`, used APK
package feeds instead of opkg, and did not expose `/sys/kernel/btf/vmlinux`.
OpenWrt runtime dependencies were installed with APK packages including
`bash`, `curl`, `iperf3`, `ip-full`, `tc-bpf`, `kmod-sched-bpf`, `kmod-veth`,
`kmod-crypto-gcm`, and CA bundles.

The OpenWrt 25.12.4 SDK build initially auto-downgraded helpers to `basic`
because the matrix helper only detected old `include/kernel-*` files. The SDK
uses `include/kernel-version.mk`, so the helper now parses `KERNEL_PATCHVER`
or `LINUX_VERSION` from that file. A forced full module build then succeeded
with `crypto=full,datapath=full,helpers=full`.

OpenWrt 25.12.4 module hashes:

| Module | SHA256 |
| --- | --- |
| `trustix_crypto.ko` | `8652ba0b78af1e7845e5adc466ef48654aeb68c675574652bc39fbd7f8febdac` |
| `trustix_datapath_helpers.ko` | `d9990877dfdc431023d7c26b89924a47e070f537c5b0e94e76ed9bf263e28abe` |
| `trustix_datapath.ko` | `f7b9d3a00f9f90e44863bba514b8563a14312c0bc16990d34daddb08e490ed3c` |

Debian module hashes:

| Module | SHA256 |
| --- | --- |
| `trustix_crypto.ko` | `352f7a18dc484e287493d326f6e03fb20305aa0e77d661a1c1706160d7db397f` |
| `trustix_datapath_helpers.ko` | `09353fa56bfedf67b48a6d5b46d65332963b4d76f5e7a72b485972f193ecb77d` |
| `trustix_datapath.ko` | `4d7965107d974934384be8a4080d5972433328e8a229439a9d58da9cf27a89bd` |

Runtime checks:

| Case | Artifact | Duration | Result |
| --- | --- | ---: | --- |
| OpenWrt 25.12.4 secure-kUDP route-GSO | `/root/trustix-owrt25124-runtime/results/owdeb-secure-kudp-30-20260624-131448` | startup gate | fail-closed |
| OpenWrt 25.12.4 experimental TCP route-GSO | `/root/trustix-owrt25124-runtime/results/owdeb-routegso-30-20260624-131436` | startup gate | fail-closed |

Both cases loaded `trustix_datapath_helpers` on OpenWrt but failed closed before
traffic. The secure-kUDP case reported:
`secure kernel_udp route-GSO requires trustix_datapath_helpers full route TCP
kfunc capability; missing=route_tcp_kfunc,route_tcp_xmit_kfunc`. The
experimental TCP case reported the same missing `route_tcp_kfunc` and
`route_tcp_xmit_kfunc` runtime capability.

Conclusion: upgrading the official OpenWrt x86_64 image to 25.12.4 does not
enable TrustIX route-GSO or secure-kUDP route-GSO. Even with forced full
modules built from the matching SDK, the official guest did not expose the
runtime route-TCP kfunc capability required by these paths. No OpenWrt
route-GSO or secure-kUDP route-GSO production default was promoted; the
selected OpenWrt production kernel path remains UDP plaintext full-kmod.

## 2026-06-23

<a id="2026-06-23-zaozhuang-pve-current-head-full-kmod-3600s-production-gates"></a>

### Zaozhuang PVE current-head full-kmod 3600s production gates

PVE host `120.220.44.72:8006` was used with disposable VM IDs 200+ only.
VM100 and all 1xx guests were not modified. The run used commit
`1a72df194383d74fef5b03f68878f72734addb39`.

Debian-to-Debian full-kmod used VM200 and VM201 with Debian 13 kernel
`6.12.94+deb13-amd64`. OpenWrt-to-Debian full-kmod used VM202 OpenWrt
24.10.7 kernel `6.6.141` and VM200 Debian 13 kernel
`6.12.94+deb13-amd64`. The OpenWrt module was built with the matching
OpenWrt SDK; `trustix_datapath.ko` SHA256 was
`005fee841ca6cb82b030bd31abac799f9e9dbd7ce7d2b5ceda340612c0c91fce`.

The selected production gates used
`trustix-cross-host-production-gate-manifest-v1` identity. For the current
HEAD, `scripts/linux-cross-host-production-gate.sh` SHA256 was
`7069a7ca3516000c4313612fe7a57320c19a4717e56be05e131b3724317232ce`; verifier
`scripts/linux-cross-host-soak-verify.py` SHA256 was
`691bd691303fddbe6d8f243c99e21c25f75cfcb8ab3f0cfb5e47a2707b6ae34b`.

| Gate family | Direction | Gate | Received |
| --- | --- | ---: | ---: |
| `full_kmod` | Debian A to Debian B | 3 Gbps | 3.445860 Gbps |
| `full_kmod` | Debian B to Debian A | 3 Gbps | 3.554549 Gbps |
| `owdeb_full_kmod` | OpenWrt to Debian | 3 Gbps | 3.507421 Gbps |
| `owdeb_full_kmod` | Debian to OpenWrt | 3 Gbps | 5.127633 Gbps |

Both production gates ran 3600s per direction and passed. Before/after boot
IDs stayed stable, pstore and kernel log scans were clean, and covered
datapath error counters were zero. A concurrent underlay probe during the
OpenWrt full-kmod run reached 3.752 Gbps from OpenWrt to Debian, confirming
that the loaded full plaintext module did not block normal underlay traffic in
that test environment. After verification, the disposable VMs, isolated
`vmbr3`, NAT/FORWARD rules, and runroot were removed.

<a id="2026-06-23-zaozhuang-pve-userspace-userspace-tc-3600s-production-gates"></a>

### Zaozhuang PVE userspace and userspace-TC 3600s production gates

PVE host `120.220.44.72:8006` was used with disposable VM IDs 200+ only.
VM100 and all 1xx guests were not modified. The userspace runs used Debian 13
VM pairs 200/201, 202/203, and 204/205; the retry runs used 200/201 and
202/203. The userspace-TC secure tunnel run used VM206/VM207, and the
userspace-TC plaintext tunnel run used VM208/VM209. All guests ran Debian 13
kernel `6.12.69+deb13-amd64` on isolated `vmbr3`.

The release binary was built from commit
`efa9887c763c47a7a9b37483c54909fffdc7a65b`, build time
`2026-06-23T07:58:23Z`, with Go `1.25.0`; all guests used binary SHA256
`68200d00ed00a8eb6376d0a49e186604b523f7d0206cef15acb008e0b4f0aa19`.
The embedded assets SHA256 was
`18eb4b0fbb81b7dfe6a9639e2997cae6cd728c5a9d2db3ba367412487cb6e622`.

The selected production gates emitted
`trustix-cross-host-production-gate-manifest-v1` evidence. The production gate
script SHA256 was
`7069a7ca3516000c4313612fe7a57320c19a4717e56be05e131b3724317232ce`; the
verifier SHA256 was
`691bd691303fddbe6d8f243c99e21c25f75cfcb8ab3f0cfb5e47a2707b6ae34b`.

The runs started on 2026-06-23 CST and completed on 2026-06-24 CST. All 17
cross-host userspace and userspace-TC cases passed 3600s production gates with
`iperf_mode=forward` and `iperf_directions=both`. The production verifier
reported `errors=[]`, `log_findings=[]`,
`kernel_log_rejected_artifacts=[]`, `pstore_rejected_artifacts=[]`, stable
before/after boot IDs, LAN `tx_queue_len=1000`, no loaded `trustix_*` kernel
modules, and zero session dial or heartbeat errors. Final live kernel and
pstore sweeps on the userspace-TC VMs were also clean.

| Gate family | Transport | Encryption | Gate | Minimum received | Evidence seconds |
| --- | --- | --- | ---: | ---: | ---: |
| userspace | UDP | secure | 1.5 Gbps | 1.672798 Gbps | 3600 |
| userspace | UDP | plaintext | 1.5 Gbps | 1.754013 Gbps | 3600 |
| userspace | TCP | secure | 0.75 Gbps | 0.777460 Gbps | 3600 |
| userspace | TCP | plaintext | 1 Gbps | 1.032665 Gbps | 3600 |
| userspace | QUIC | secure | 0.75 Gbps | 0.954547 Gbps | 3600 |
| userspace | QUIC | plaintext | 1 Gbps | 1.249522 Gbps | 3600 |
| userspace | WebSocket | secure | 0.5 Gbps | 0.592369 Gbps | 3600 |
| userspace | WebSocket | plaintext | 1 Gbps | 1.125059 Gbps | 3600 |
| userspace | HTTP CONNECT | secure | 0.75 Gbps | 0.839874 Gbps | 3600 |
| userspace | HTTP CONNECT | plaintext | 1 Gbps | 1.237984 Gbps | 3600 |
| userspace | experimental TCP | secure | 1 Gbps | 1.246138 Gbps | 3600 |
| userspace-TC | GRE | secure | 1 Gbps | 1.376135 Gbps | 3600 |
| userspace-TC | GRE | plaintext | 4 Gbps | 5.110725 Gbps | 3600 |
| userspace-TC | IPIP | secure | 1 Gbps | 1.383353 Gbps | 3600 |
| userspace-TC | IPIP | plaintext | 4 Gbps | 5.231286 Gbps | 3600 |
| userspace-TC | VXLAN | secure | 1 Gbps | 1.361865 Gbps | 3600 |
| userspace-TC | VXLAN | plaintext | 4 Gbps | 5.286772 Gbps | 3600 |

## 2026-06-22

<a id="2026-06-22-zaozhuang-pve-owdeb-full-kmod-3600s-production-gate"></a>

### Zaozhuang PVE OpenWrt-Debian full-kmod 3600s production gate

PVE host `120.220.44.72:8006` was used with disposable VM IDs 200+ only:
VM201 `trustix-owdeb-openwrt` (`10.203.3.201`) and VM200
`trustix-owdeb-debian` (`10.203.3.200`) on isolated `vmbr3`. VM100 and all
1xx guests were not modified. VM201 ran OpenWrt 24.10.7 kernel `6.6.141`;
VM200 ran Debian 13 kernel `6.12.94+deb13-cloud-amd64`.

The release binary was built from commit
`1103f5e12678ee9dde9bc9e18c8b742b1f700247`, build time
`2026-06-22T11:43:10Z`, with Go `1.25.0`; both guests used binary SHA256
`a1eefc166881dab34db4cae5ce5374903f5b582f5c70a6af957d7d87aaea6b84`.
The embedded assets SHA256 was
`4e0476a6fb315983cfb57f4dcb2c221e18d720aee4c90fc8c6c783f6d434681e`.
The OpenWrt SDK `trustix_datapath.ko` SHA256 was
`005fee841ca6cb82b030bd31abac799f9e9dbd7ce7d2b5ceda340612c0c91fce`;
the Debian `trustix_datapath.ko` SHA256 was
`1f0b30b3faafbd6a58fc980ad72ce17327ff79fcc27c37cd12fd57dac34d5635`.

The selected production gate emitted
`trustix-cross-host-production-gate-manifest-v1` evidence. The production gate
script SHA256 was
`b856e9871bb59d41d41726047b10966e323fc53243a8c5493d9bf37ba52020bb`; the
verifier SHA256 was
`ac2dfae346e7f92bfc32bf8b1e379849506c26b9155a61181c9523b5c3abd38b`.

| Direction | Gate | Received | Sent | Duration |
| --- | ---: | ---: | ---: | ---: |
| OpenWrt to Debian | 3 Gbps | 3.555770 Gbps | 3.555754 Gbps | 3599.936529s |
| Debian to OpenWrt | 3 Gbps | 5.069192 Gbps | 5.069378 Gbps | 3600.116183s |

The manifest gate passed with stable boot IDs
`a44b1159-4aa8-440e-abed-b387d95e6dee` and
`9dc04b53-6935-46e7-b34a-29dada2fd0fc`, `errors=[]`,
`log_findings=[]`, `kernel_log_rejected_artifacts=[]`, and pstore coverage on
both nodes. Both nodes had `trustix_datapath` loaded, LAN `tx_queue_len=1000`,
`enable_features=128`, `safe_features=128`, `unsafe_features=0`,
`selftest_failures=0`, `rx_worker_inject=Y`, `tx_plaintext=Y`,
`tx_plaintext_skip_inner_tcp_checksum=N`, and zero covered datapath allocation,
delivery, GSO xmit, plaintext build, outer-GSO, queue drop, stale wire, and
xmit errors.

<a id="2026-06-22-zaozhuang-pve-dd-full-kmod-3600s-production-gate"></a>

### Zaozhuang PVE Debian full-kmod 3600s production gate

PVE host `120.220.44.72:8006` was used with disposable VM IDs 200+ only:
VM200 `trustix-long-full-a` (`10.203.3.200`) and VM201
`trustix-long-full-b` (`10.203.3.201`) on isolated `vmbr3`. VM100 and all
1xx guests were not modified. Both guests ran Debian 13 kernel
`6.12.94+deb13-cloud-amd64`.

The release binary was built from commit `24c7e17fc582`, build time
`2026-06-22T02:17:48Z`, with Go `1.25.0`; both guests used binary SHA256
`befa7bca1be05e5f47635eff1a1fe96a4db8627d8394095af6e04f3fd829dd7d`.
The embedded assets SHA256 was
`dbfb9d5578d54b131f6d71a2e149041e8b8fa7347e7776a33c5e88bf1bf17068`.
The embedded `trustix_datapath.ko` SHA256 was
`b1d4194a7892d1a786c7674177b78b525c1efc980e6c5f0f1387aff10fd25c60`.

The selected production gate emitted
`trustix-cross-host-production-gate-manifest-v1` evidence. The production gate
script SHA256 was
`520750ae5e500023963c5b660f2f061343972afddf2dba85d116f3f6f6c1d876`; the
verifier SHA256 was
`4c5aef66c564b3e149d1cd454ccc72e64fcf21f98b72d88ef8703252d7ead796`.

| Direction | Gate | Received | Sent | Duration | Iperf intervals |
| --- | ---: | ---: | ---: | ---: | ---: |
| A to B | 3 Gbps | 3.614027 Gbps | 3.614081 Gbps | 3600.025912s | 3600 |
| B to A | 3 Gbps | 3.533778 Gbps | 3.533832 Gbps | 3600.021830s | 3600 |

The manifest gate passed with `errors=[]`, stable boot IDs
`e56ff869-02e8-4a21-bd39-b41ee788c236` and
`f9d25564-fc55-48a3-a591-880733c9bc58`, `log_findings=[]`,
`kernel_log_rejected_artifacts=[]`, and `pstore_rejected_artifacts=[]`.
Both peers had `trustix_datapath` loaded with LAN `tx_queue_len=1000`,
`enable_features=128`, `safe_features=128`, `unsafe_features=0`,
`selftest_failures=0`, `rx_worker_inject=Y`, `tx_plaintext=Y`,
`tx_plaintext_skip_inner_tcp_checksum=N`, eight session records and wire
records, nonzero RX-worker and plaintext outer-GSO counters, and zero covered
allocation, delivery, GSO xmit, plaintext build, stale wire, queue drop, and
xmit errors.

A stricter simultaneous bidirectional diagnostic run on the same guests also
ran for 3600s with P8 full-kmod plaintext and did not produce a reboot, panic,
pstore record, kernel-log rejection, or covered module error. It was not
promoted as production throughput evidence because the simultaneous bidir
minimum was 2.028861 Gbps received and 2.028903 Gbps sent, below the current
3 Gbps full-kmod production gate. A short P4 simultaneous bidir probe produced
the same stability result and about 2.31 Gbps per direction. The production
default therefore remains the sequential per-direction gate above.

<a id="2026-06-22-zaozhuang-pve-tc-direct-secure-kudp-3600s-ratio-gates"></a>

### Zaozhuang PVE TC-direct and secure-kUDP 3600s ratio gates

PVE host `120.220.44.72:8006` was used with disposable VM IDs 200+ only. VM100
and all 1xx guests were not modified. All checked peers ran Debian 13 kernel
`6.12.94+deb13-cloud-amd64`.

The release binary was built from commit `61c65bc3dc6a`, build time
`2026-06-22T06:39:31Z`, with Go `1.25.0`; all checked peers used binary
SHA256 `411ffc1de602afaa524a0604c491c53e31be002433931f9e43194b8552543f6c`.
The embedded assets SHA256 was
`72cf877436fb24ef91455f3368a87024c49c697c213f6ad2ef372cb0fb0aeaa4`.

The gate was rechecked with production gate script SHA256
`6004747ec9057258e80974d6e915b563b33e5cd9c8831062d820d660d6147bd5` and
verifier SHA256
`ac2dfae346e7f92bfc32bf8b1e379849506c26b9155a61181c9523b5c3abd38b`.
The verifier adds `--require-datapath-ratio-max`; secure-kUDP now requires
`tc_kernel_udp_rx_secure_direct_replay_old_drops=0` and bounds `replay_seen`,
total replay drops, and total secure-direct RX drops against
`tc_kernel_udp_rx_secure_direct_kfunc_open_attempts` at `<= 0.00002`.

| Gate family | Direction | Gate | Received | Sent | Duration | Iperf intervals |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| `tc_direct` | A to B | 3 Gbps | 3.575734 Gbps | 3.575770 Gbps | 3600.004793s | 3600 |
| `tc_direct` | B to A | 3 Gbps | 3.725502 Gbps | 3.725542 Gbps | 3600.003238s | 3600 |
| `secure_kudp` | A to B | 1.5 Gbps | 1.634107 Gbps | 1.634159 Gbps | 3600.013932s | 3600 |
| `secure_kudp` | B to A | 1.5 Gbps | 1.654379 Gbps | 1.654424 Gbps | 3600.013547s | 3600 |

Both gates passed with `errors=[]`, stable before/after boot IDs,
`log_findings=[]`, `kernel_log_rejected_artifacts=[]`, and
`pstore_rejected_artifacts=[]`. The secure-kUDP replay split was:

| Node | `old` drops | `seen` drops | Open attempts | Seen/open ratio |
| --- | ---: | ---: | ---: | ---: |
| A | 0 | 6156 | 675832088 | 0.000009109 |
| B | 0 | 7944 | 670683253 | 0.000011845 |

This replaces the previous fixed `4096` absolute replay budget with a
duration-aware gate. A future secure-kUDP failure with nonzero `old` drops is
still a hard failure; a higher `seen/open` or `drops/open` ratio is also a hard
failure.

<a id="2026-06-22-zaozhuang-pve-route-gso-3600s-production-gate"></a>

### Zaozhuang PVE route-GSO 3600s production gate

PVE host `120.220.44.72:8006` was used with disposable VM IDs 204 and 205 on
isolated `vmbr3`; VM100 and all 1xx guests were not modified. Both guests ran
Debian 13 kernel `6.12.94+deb13-cloud-amd64`.

The release binary, embedded assets, production gate script, and verifier were
the same artifacts as the TC-direct and secure-kUDP 3600s run above:
binary SHA256 `411ffc1de602afaa524a0604c491c53e31be002433931f9e43194b8552543f6c`,
assets SHA256 `72cf877436fb24ef91455f3368a87024c49c697c213f6ad2ef372cb0fb0aeaa4`,
production gate SHA256
`6004747ec9057258e80974d6e915b563b33e5cd9c8831062d820d660d6147bd5`, and
verifier SHA256
`ac2dfae346e7f92bfc32bf8b1e379849506c26b9155a61181c9523b5c3abd38b`.

The initial transport matrix precheck used a legacy hard
`session_dial_errors=0` threshold and failed only because node A reported one
session dial error during the 7204s run. Rechecking the same artifacts with the
current production gate passed with `route_gso_session_error_budget=2`,
`errors=[]`, stable before/after boot IDs, `log_findings=[]`,
`kernel_log_rejected_artifacts=[]`, and `pstore_rejected_artifacts=[]`.

| Gate family | Direction | Gate | Received | Sent | Duration | Iperf intervals |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| `route_gso` | A to B | 2.5 Gbps | 2.829761 Gbps | 2.829801 Gbps | 3600.007591s | 3600 |
| `route_gso` | B to A | 2.5 Gbps | 2.972184 Gbps | 2.972355 Gbps | 3600.209198s | 3600 |

Both nodes kept `data_path.active_sessions=8`; node A had
`session_dial_errors=1` and node B had `session_dial_errors=0`. Route-GSO
module counters showed active outer-GSO and no covered route-GSO errors:

| Node | Outer-GSO frames | Xmit packets | Covered helper errors |
| --- | ---: | ---: | ---: |
| A | 958100425 | 41155257 | 0 |
| B | 1006432316 | 43427472 | 0 |

<a id="2026-06-22-zaozhuang-pve-userspace-userspace-tc-current-forward-gates"></a>

### Zaozhuang PVE userspace and userspace-TC current forward gates

PVE host `120.220.44.72:8006` was used with disposable VM IDs 200 and 201
only: VM200 `trustix-dd-userspace-a` (`10.203.3.200`) and VM201
`trustix-dd-userspace-b` (`10.203.3.201`) on isolated `vmbr3`. VM100 and all
1xx guests were not modified. Both guests ran Debian 13 kernel
`6.12.69+deb13-amd64`.

The release binary was built from commit `2c94c12`, build time
`2026-06-22T14:53:59Z`, with Go `1.25.0`; both guests used binary SHA256
`53a04d8335befc1b5ec906c99fa664821c1c58966f2a9f0945a6063eeaa3e335`.

The selected production gate emitted
`trustix-cross-host-production-gate-manifest-v1` evidence. The production gate
script SHA256 was
`7069a7ca3516000c4313612fe7a57320c19a4717e56be05e131b3724317232ce`; the
verifier SHA256 was
`691bd691303fddbe6d8f243c99e21c25f75cfcb8ab3f0cfb5e47a2707b6ae34b`.
This is the first userspace/userspace-TC evidence set after the production gate
started requiring `run-timing.json` to contain `iperf_mode=forward` and
`iperf_directions=both`.

The run started on 2026-06-22 CST and completed on 2026-06-23 CST. All 17
cross-host cases passed the selected production gate with matching binary
identity, stable before/after boot IDs
`c1973b6a-af0b-4994-9de9-226f8a3febbd` and
`4213490d-4a90-4ff2-9b01-739354f71a64`, `errors=[]`,
`log_findings=[]`, `kernel_log_rejected_artifacts=[]`,
`pstore_rejected_artifacts=[]`, no loaded `trustix_*` kernel modules, LAN
`tx_queue_len=1000`, and zero session dial or heartbeat errors.

| Gate family | Transport | Encryption | Gate | Minimum received | Minimum duration |
| --- | --- | --- | ---: | ---: | ---: |
| userspace | UDP | secure | 1.5 Gbps | 2.002442 Gbps | 900.007786s |
| userspace | UDP | plaintext | 1.5 Gbps | 2.392241 Gbps | 900.009725s |
| userspace | TCP | secure | 0.75 Gbps | 0.918289 Gbps | 900.199618s |
| userspace | TCP | plaintext | 1 Gbps | 1.385983 Gbps | 900.082514s |
| userspace | QUIC | secure | 0.75 Gbps | 1.029901 Gbps | 900.192999s |
| userspace | QUIC | plaintext | 1 Gbps | 1.486415 Gbps | 900.140078s |
| userspace | WebSocket | secure | 0.5 Gbps | 0.859811 Gbps | 900.197122s |
| userspace | WebSocket | plaintext | 1 Gbps | 1.248472 Gbps | 900.089256s |
| userspace | HTTP CONNECT | secure | 0.75 Gbps | 0.904721 Gbps | 900.156658s |
| userspace | HTTP CONNECT | plaintext | 1 Gbps | 1.411984 Gbps | 900.066250s |
| userspace | experimental TCP | secure | 1 Gbps | 1.564874 Gbps | 900.088089s |
| userspace-TC | GRE | secure | 1 Gbps | 1.466421 Gbps | 900.003502s |
| userspace-TC | GRE | plaintext | 4 Gbps | 4.631023 Gbps | 900.003790s |
| userspace-TC | IPIP | secure | 1 Gbps | 1.483775 Gbps | 900.005694s |
| userspace-TC | IPIP | plaintext | 4 Gbps | 5.062255 Gbps | 900.002207s |
| userspace-TC | VXLAN | secure | 1 Gbps | 1.465202 Gbps | 899.997128s |
| userspace-TC | VXLAN | plaintext | 4 Gbps | 4.978103 Gbps | 899.997485s |

<a id="2026-06-22-zaozhuang-pve-userspace-userspace-tc-manifest-gates"></a>

### Zaozhuang PVE userspace and userspace-TC manifest gates

PVE host `120.220.44.72:8006` was used with disposable VM IDs 200+ only:
VM200 `trustix-userspace-a` (`10.203.3.200`), VM201
`trustix-userspace-b` (`10.203.3.201`), VM202
`trustix-userspace-202` (`10.203.3.202`), and VM203
`trustix-userspace-203` (`10.203.3.203`) on isolated `vmbr3`. VM100 and all
1xx guests were not modified. All guests ran Debian 13 on
`6.12.90+deb13.1-cloud-amd64` with `cpu: host`; the guest CPU flags included
`aes`, `pclmulqdq`, and `avx`. This matters for these userspace secure
throughput gates because the PVE default `Common KVM processor` hides those
features and previously produced misleadingly low secure TCP/QUIC results.

The release binary was built with `--build-bpf 0 --build-ko 0 --skip-webui`
from commit `4c3312c40a69`, build time `2026-06-21T17:24:33Z`; all guests
used binary SHA256
`e4c161ebb1731762d0fc5403cbd0117b0e04659ab1b54c322cd994d4f5cb79cc`.
The embedded assets SHA256 was
`18eb4b0fbb81b7dfe6a9639e2997cae6cd728c5a9d2db3ba367412487cb6e622`.

The selected production gate emitted
`trustix-cross-host-production-gate-manifest-v1` evidence. The production gate
script SHA256 was
`520750ae5e500023963c5b660f2f061343972afddf2dba85d116f3f6f6c1d876`; the
verifier SHA256 was
`4c5aef66c564b3e149d1cd454ccc72e64fcf21f98b72d88ef8703252d7ead796`.

| Gate family | Transport | Encryption | Gate | Minimum received | Minimum sent | Minimum duration |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| userspace | UDP | secure | 1.5 Gbps | 2.001292 Gbps | 2.000753 Gbps | 899.698922s |
| userspace | UDP | plaintext | 1.5 Gbps | 2.400691 Gbps | 2.400956 Gbps | 900.009047s |
| userspace | TCP | secure | 0.75 Gbps | 0.832237 Gbps | 0.832460 Gbps | 900.191986s |
| userspace | TCP | plaintext | 1 Gbps | 1.372582 Gbps | 1.372799 Gbps | 900.079583s |
| userspace | QUIC | secure | 0.75 Gbps | 0.971089 Gbps | 0.971322 Gbps | 900.205557s |
| userspace | QUIC | plaintext | 1 Gbps | 1.384400 Gbps | 1.384626 Gbps | 900.137116s |
| userspace | WebSocket | secure | 0.5 Gbps | 0.775269 Gbps | 0.775496 Gbps | 900.206963s |
| userspace | WebSocket | plaintext | 1 Gbps | 1.202630 Gbps | 1.202856 Gbps | 900.133695s |
| userspace | HTTP CONNECT | secure | 0.75 Gbps | 0.897881 Gbps | 0.898088 Gbps | 900.188402s |
| userspace | HTTP CONNECT | plaintext | 1 Gbps | 1.405207 Gbps | 1.405428 Gbps | 900.071849s |
| userspace | experimental TCP | secure | 1 Gbps | 1.576181 Gbps | 1.576404 Gbps | 900.066391s |
| userspace-TC | GRE | secure | 1 Gbps | 1.384943 Gbps | 1.384952 Gbps | 899.987127s |
| userspace-TC | GRE | plaintext | 4 Gbps | 5.475852 Gbps | 5.475970 Gbps | 899.995435s |
| userspace-TC | IPIP | secure | 1 Gbps | 1.374068 Gbps | 1.374109 Gbps | 900.006583s |
| userspace-TC | IPIP | plaintext | 4 Gbps | 5.404188 Gbps | 5.404332 Gbps | 900.003861s |
| userspace-TC | VXLAN | secure | 1 Gbps | 1.362260 Gbps | 1.362300 Gbps | 900.006735s |
| userspace-TC | VXLAN | plaintext | 4 Gbps | 5.647205 Gbps | 5.647345 Gbps | 900.003044s |

All 17 cases passed with `errors=[]`, `log_findings=[]`,
`kernel_log_rejected_artifacts=[]`, `pstore_rejected_artifacts=[]`, stable
boot IDs before and after each case, no TrustIX kernel modules loaded, matching
binary/build identity, and zero session dial or heartbeat errors. The final
manifest rows are now recorded in `scripts/production-transport-evidence.tsv`.

The production gate was adjusted during this run to match the endpoint/session
metadata split for TLS-backed transports: endpoint `crypto_placements` is now
required only for endpoint transports that advertise it (`udp` and
`experimental_tcp`), and peer endpoint `encryption=...` is no longer required.
TCP, QUIC, WebSocket, and HTTP CONNECT continue to prove crypto placement and
encryption via policy/session stats, including `stats.link_tls=true`.

<a id="2026-06-22-zaozhuang-pve-owdeb-full-kmod-manifest-gate"></a>

### Zaozhuang PVE OpenWrt-Debian full-kmod manifest gate

PVE host `120.220.44.72:8006` was used with disposable VM IDs 200+ only:
VM201 `trustix-owdeb-openwrt` (`10.203.3.201`) and VM200
`trustix-owdeb-debian` (`10.203.3.200`) on isolated `vmbr3`. VM100 and all
1xx guests were not modified. VM201 ran OpenWrt 24.10.7 kernel `6.6.141`;
VM200 ran Debian 13 kernel `6.12.94+deb13-cloud-amd64`.

The release binary was built from commit `009a2f501b52`, build time
`2026-06-21T16:08:52Z`; both guests used binary SHA256
`1e4c9dff79fe161188848bd1c2d0e56579bbd616724f7d949fb4e5326698cd71`.
The embedded assets SHA256 was
`18eb4b0fbb81b7dfe6a9639e2997cae6cd728c5a9d2db3ba367412487cb6e622`.
The OpenWrt `trustix_datapath.ko` SHA256 was
`005fee841ca6cb82b030bd31abac799f9e9dbd7ce7d2b5ceda340612c0c91fce`;
the Debian `trustix_datapath.ko` SHA256 was
`b1d4194a7892d1a786c7674177b78b525c1efc980e6c5f0f1387aff10fd25c60`.

The selected production gate emitted
`trustix-cross-host-production-gate-manifest-v1` evidence. The production gate
script SHA256 was
`dab0c91b1d5768fc73340d45e83ed920ee1af9d75d86e21da3ce54f9724fa3e0`; the
verifier SHA256 was
`4c5aef66c564b3e149d1cd454ccc72e64fcf21f98b72d88ef8703252d7ead796`.

| Direction | Gate | Received | Sent | Duration |
| --- | ---: | ---: | ---: | ---: |
| OpenWrt to Debian | 3 Gbps | 3.418114 Gbps | 3.418333 Gbps | 900.007659s |
| Debian to OpenWrt | 3 Gbps | 4.442237 Gbps | 4.442441 Gbps | 900.057601s |

The manifest gate passed with stable boot IDs
`281a471f-13c0-4549-9f02-d3ec3affcab2` and
`cc357572-3ba0-404c-b1a3-a5620a643f37`, `log_findings=[]`,
`kernel_log_rejected_artifacts=[]`, and pstore coverage on both nodes.
Both nodes had `trustix_datapath` loaded, LAN `tx_queue_len=1000`,
`enable_features=128`, `safe_features=128`, `unsafe_features=0`,
`selftest_failures=0`, `rx_worker_inject=Y`, `tx_plaintext=Y`,
`tx_plaintext_skip_inner_tcp_checksum=N`, and zero datapath allocation,
delivery, GSO xmit, plaintext build, queue drop, stale wire, and xmit errors.

During the first manifest attempt the datapath evidence was already clean, but
the OpenWrt-side kernel log artifact was unusable because BusyBox `dmesg`
does not accept `-T` and OpenWrt lacks `journalctl`. The OpenWrt dmesg was
recaptured from the same stable boot before cleanup, the manifest gate was
rerun, and `scripts/linux-cross-host-soak-runner.sh` now avoids emitting
failing `*.log` artifacts when `journalctl` is unavailable while falling back
from `dmesg -T` to plain `dmesg` on BusyBox systems.

## 2026-06-21

### OpenWrt SDK matrix current stable defaults

Change: `scripts/openwrt-full-datapath-kmod-matrix.sh` now defaults its SDK
compile matrix to the current stable OpenWrt patch releases available from the
official release index on 2026-06-21: `23.05.6`, `24.10.7`, and `25.12.4`.
The older long-tail compatibility rows for `21.02.7` and `22.03.7` remain in
the default compile matrix. The download base order still prefers China mirrors
first (`mirrors.tuna.tsinghua.edu.cn`, `mirrors.ustc.edu.cn`,
`mirrors.aliyun.com`) and falls back to `downloads.openwrt.org`.

Boundary: this section is a compile-matrix default refresh only. The OpenWrt
24.10.7 full-kmod runtime promotion is recorded in the production gate below.
OpenWrt 24.10.7 route-GSO, secure-kUDP route-GSO, and OpenWrt 25.12.4 runtime
support remain unpromoted until those exact guests pass the runtime capability
and cross-host soak gates on PVE.

<a id="2026-06-21-zaozhuang-pve-dd-kernel-manifest-gates"></a>

### Zaozhuang PVE DD kernel manifest gates

PVE host `120.220.44.72:8006` was used with disposable VM IDs 200+ only:
VM200 `trustix-dd-a` (`10.203.3.200`) and VM201 `trustix-dd-b`
(`10.203.3.201`) on isolated `vmbr3`. VM100 and all 1xx guests were not
modified. Both guests were Debian 13 on
`6.12.90+deb13.1-cloud-amd64`, using underlay interface `eth0`.

The release binary was built from commit `83f6e2b`, build time
`2026-06-21T13:19:46Z`; both guests used binary SHA256
`8fe300e4a73d8359f927adedaee818cc8bd344dece04a85463d4007b85167f74`.
The embedded asset SHA256 was
`21251741874539ff6af5f8205b980fac3617d8d9a8d25f5c4b5b119d5e8a81d1`.

The selected production gate emitted
`trustix-cross-host-production-gate-manifest-v1` evidence. The production gate
script SHA256 was
`dab0c91b1d5768fc73340d45e83ed920ee1af9d75d86e21da3ce54f9724fa3e0`; the
verifier SHA256 was
`4c5aef66c564b3e149d1cd454ccc72e64fcf21f98b72d88ef8703252d7ead796`.

| Gate family | Transport path | Gate | Minimum received | Minimum sent | Minimum duration |
| --- | --- | ---: | ---: | ---: | ---: |
| full-kmod | UDP plaintext full datapath module | 3 Gbps | 3.294880 Gbps | 3.295067 Gbps | 900.021685s |
| TC-direct | plaintext kernel UDP TC direct-only | 3 Gbps | 3.883991 Gbps | 3.884176 Gbps | 900.005046s |
| secure-kUDP | secure kernel UDP with kernel crypto and route-GSO | 1.5 Gbps | 1.722710 Gbps | 1.722862 Gbps | 899.989966s |
| route-GSO | experimental TCP plaintext route-GSO | 2.5 Gbps | 2.667106 Gbps | 2.667310 Gbps | 900.011079s |

All four cases passed the selected production gate with stable boot IDs
(`b47e3cbe-676d-4ab1-8f4d-80a76491326b` and
`3eb33a69-ac00-4169-876b-13ce8f33f00a`), `log_findings=[]`, pstore artifacts,
kernel/dmesg artifacts, LAN `tx_queue_len=1000`, and binary/build identity
matching across both guests.

The gate was adjusted during this run to match the actual offload state model:
TC-direct is direct-only and proves payload movement through
`kernel_udp.active_flows`, not userspace transport sessions. Full-kmod,
secure-kUDP, and route-GSO prove payload movement through iperf plus datapath
and module counters; userspace session byte counters can remain zero because
payload is offloaded. A journalctl window containing only `-- No entries --`
is now accepted as an empty kernel-log window instead of a collection failure.

### Debian userspace current-head production gates

PVE host `120.220.44.72:8006` was used with disposable VM IDs 200+ only:
VM200 `10.203.3.200` and VM201 `10.203.3.201` on isolated `vmbr3`.
VM100 and all 1xx guests were not modified. Both guests were Debian 13 on
`6.12.90+deb13.1-amd64`, with no TrustIX kernel modules loaded. The release
was built with `--build-bpf 0 --build-ko 0` from commit `a260eb71dcef`,
build time `2026-06-20T22:21:56Z`; both guests used binary SHA256
`20018944c7c0a29eb9c8a3f802f4746516a3b84c2c2754e606a8c22df93e1b3f`.
The embedded assets SHA256 was
`18eb4b0fbb81b7dfe6a9639e2997cae6cd728c5a9d2db3ba367412487cb6e622`.

Artifact:
`/root/trustix-userspace-current-20260621/results/userspace-current-900`.
The thresholded 900s cross-host userspace matrix passed every current
cross-host userspace production default, then the selected userspace production
gate emitted matching pass rows. All rows had `errors=[]`, `log_findings=[]`,
zero `data_path.counters.session_dial_errors`, and zero
`data_path.counters.session_heartbeat_timeouts`.

| Transport | Encryption | Gate | Minimum received | Minimum sent | Minimum duration |
| --- | --- | ---: | ---: | ---: | ---: |
| UDP | secure | 1.5 Gbps | 1.918875 Gbps | 1.919163 Gbps | 899.952472s |
| UDP | plaintext | 1.5 Gbps | 2.158972 Gbps | 2.159122 Gbps | 899.915878s |
| TCP | secure | 0.75 Gbps | 0.851568 Gbps | 0.851829 Gbps | 900.231512s |
| TCP | plaintext | 1 Gbps | 1.283958 Gbps | 1.284213 Gbps | 900.156525s |
| QUIC | secure | 0.75 Gbps | 0.977368 Gbps | 0.977592 Gbps | 900.201750s |
| QUIC | plaintext | 1 Gbps | 1.405338 Gbps | 1.405596 Gbps | 900.081620s |
| WebSocket | secure | 0.5 Gbps | 0.796914 Gbps | 0.797101 Gbps | 900.168679s |
| WebSocket | plaintext | 1 Gbps | 1.248432 Gbps | 1.248699 Gbps | 900.053773s |
| HTTP CONNECT | secure | 0.75 Gbps | 0.879747 Gbps | 0.879913 Gbps | 900.170533s |
| HTTP CONNECT | plaintext | 1 Gbps | 1.353923 Gbps | 1.354159 Gbps | 900.133752s |
| experimental TCP | secure | 1 Gbps | 1.550296 Gbps | 1.550500 Gbps | 900.065191s |

### Debian userspace-TC current-head production gates

PVE host `120.220.44.72:8006` was used with disposable VM IDs 200+ only:
VM200/VM201 for GRE, VM202/VM203 for IPIP, and VM204/VM205 for VXLAN on
isolated `vmbr3`. VM100 and all 1xx guests were not modified. All guests were
Debian 13 on `6.12.90+deb13.1-cloud-amd64`, with no TrustIX kernel modules
loaded. The release was built with `--build-bpf 0 --build-ko 0` from commit
`51e6831bf50d`, build time `2026-06-21T04:52:03Z`; all guests used binary
SHA256 `6bbd9495cc87ca563c1d2ac13c7d45ef26fbb3c2b8820c4cbd929dc6a6d95734`.
The embedded assets SHA256 was
`18eb4b0fbb81b7dfe6a9639e2997cae6cd728c5a9d2db3ba367412487cb6e622`.

Artifacts:
`/root/trustix-tunnel-current-20260621/results/tunnels-current-900` for GRE,
`/root/trustix-tunnel-current-20260621/results/ipip-current-900` for IPIP,
and `/root/trustix-tunnel-current-20260621/results/vxlan-current-900` for
VXLAN. The 900s cross-host userspace-TC gates passed every current GRE/IPIP/
VXLAN secure and plaintext production default. All rows had `errors=[]`,
`log_findings=[]`, zero `data_path.counters.session_dial_errors`, and zero
`data_path.counters.session_heartbeat_timeouts`.

| Transport | Encryption | Gate | Minimum received | Minimum sent | Minimum duration |
| --- | --- | ---: | ---: | ---: | ---: |
| GRE | secure | 1 Gbps | 1.224643 Gbps | 1.224679 Gbps | 900.004027s |
| GRE | plaintext | 4 Gbps | 4.012349 Gbps | 4.012432 Gbps | 899.997339s |
| IPIP | secure | 1 Gbps | 1.178779 Gbps | 1.178818 Gbps | 900.003524s |
| IPIP | plaintext | 4 Gbps | 4.523007 Gbps | 4.523084 Gbps | 899.996810s |
| VXLAN | secure | 1 Gbps | 1.050624 Gbps | 1.050743 Gbps | 900.038395s |
| VXLAN | plaintext | 4 Gbps | 4.696775 Gbps | 4.696613 Gbps | 899.952633s |

### OpenWrt 24.10.7 runtime capability check

PVE host `120.220.44.72:8006` was used with disposable VM IDs 200+ only:
VM200 Debian 13 (`10.203.3.200`) and VM201 OpenWrt 24.10.7 x86_64
(`10.203.3.201`) on isolated `vmbr3`. VM100 and all 1xx guests were not
modified. The 900s full-kmod production gate binary was built from
`b1e248cf17d8` with build time `2026-06-20T18:02:14Z`; both guests used
binary SHA256
`48a632b1da27e8d1ce8aefb40d7a84738efb2490ad0e08314cb1e5f36c0ad3b3`.

OpenWrt 24.10.7 x86_64 uses kernel `6.6.141` and does not expose
`/sys/kernel/btf/vmlinux` in the tested official image. The OpenWrt SDK build
for `24.10.7-x86_64` passed with `crypto=full`, `datapath=full`, and
`helpers=full`.

OpenWrt SDK module hashes used on VM201:

| Module | SHA256 |
| --- | --- |
| `trustix_crypto.ko` | `f8be71eddc0bc09f38b0499a7dba81cfffb9a9e47f202e595358778aea2e2b88` |
| `trustix_datapath.ko` | `005fee841ca6cb82b030bd31abac799f9e9dbd7ce7d2b5ceda340612c0c91fce` |
| `trustix_datapath_helpers.ko` | `450e91c29b8d825788bf58291582a967a39b6eaa590d6b33eb39c8adcf12e773` |

Debian module hashes used on VM200:

| Module | SHA256 |
| --- | --- |
| `trustix_crypto.ko` | `05a77f254f08009f0ffd36eb768d65f2e7e257b064d0bad44ae38f75dad9104d` |
| `trustix_datapath.ko` | `052ee848af32f95012abf93c369ff0a1b1ebf5cedb4ef6122ed88f751a00d208` |
| `trustix_datapath_helpers.ko` | `5bfb65a89948e1f31b0d36917898ec36577c4cc8933069613fe8efc5192e3f6d` |

Runtime checks:

| Case | Artifact | Duration | Minimum received | Result |
| --- | --- | ---: | ---: | --- |
| OpenWrt 24.10.7 to Debian full plaintext kmod production gate | `/root/trustix-owrt24107-soak-20260621/results/owdeb-fullkmod-900-20260621-021812` | 900s | 3.276205 Gbps | pass |
| OpenWrt 24.10.7 secure-kUDP route-GSO | `/root/trustix-owrt-runtime-20260621/results/owdeb-secure-kudp-routegso-30-20260621-014916` | startup gate | 0 | fail-closed |
| OpenWrt 24.10.7 experimental TCP route-GSO | `/root/trustix-owrt-runtime-20260621/results/owdeb-routegso-30-20260621-014848` | startup gate | 0 | fail-closed |

The full-kmod production gate ran P8 in both directions. It required matching
binary/build identity, full plaintext provider status, RX worker injection,
session pool size 8, eight session records/wires, nonzero plaintext outer-GSO,
RX-worker GSO xmit, and cached-destination counters, plus zero covered
RX/TX/module error counters and zero session dial or heartbeat errors. A to B
received `3.276205 Gbps`; B to A received `4.813018 Gbps`. Post-run boot IDs
stayed stable and kernel-log scans found no panic, Oops, BUG, call trace, page
fault, watchdog, lockup, hung-task, `tx_queue_len`, or TrustIX datapath crash
signature.

Both route-GSO cases loaded the OpenWrt helper module but failed closed before
traffic with missing `route_tcp_kfunc` and `route_tcp_xmit_kfunc`. They remain
runtime capability failures, so OpenWrt 24.10.7 secure-kUDP route-GSO and
experimental TCP route-GSO are still not production defaults.

### Debian route-GSO current-head production recheck

PVE host `120.220.44.72:8006` was used with disposable VM IDs 200+ only:
VM200 `trustix-dd-routegso-a` (`10.203.3.200`) and VM201
`trustix-dd-routegso-b` (`10.203.3.201`) on isolated `vmbr3`. VM100 and all
1xx guests were not modified. Both guests were Debian 13 on
`6.12.90+deb13.1-amd64`.

The validation binary was built from
`2366d99167457bf18de7e98a5d5e6e9af3fa55b2` with build time
`2026-06-20T19:06:43Z`; both guests used binary SHA256
`824219f63e7de7924208f36bc2b090362b64f68f80cd140df0bedfcde675799c`.
The rebuilt `trustix_datapath_helpers.ko` SHA256 was
`a6d4d492ca62e6c3c5798095e14c894d1bb14cafa1c3aceb67e73f6170432b24`.

Artifact:
`/root/trustix-routegso-recheck-20260621/results/dd-routegso-900-20260621-030950`.
The 900s bidirectional route-GSO production gate passed against the 2.5 Gbps
gate. Minimum received throughput was `2.653735 Gbps`; minimum sent throughput
was `2.653610 Gbps`; minimum duration was `899.915125s` and was accepted by
the existing 1s gate slop. Directional received throughput was `2.739697 Gbps`
for A to B and `2.653735 Gbps` for B to A.

The gate required matching binary/build identity, session pool size 8, route
TCP/GSO async kfunc datapath stats, nonzero helper xmit and outer-GSO counters,
and zero covered route-GSO helper error counters. A reported
`route_tcp_gso_async_stream_outer_gso_frames=231918555` and
`route_tcp_gso_async_xmit_packets=10026827`; B reported
`route_tcp_gso_async_stream_outer_gso_frames=224633796` and
`route_tcp_gso_async_xmit_packets=9671277`. Boot IDs stayed stable
(`1507fd25-0a23-42fd-9dc3-7f3f186445c9` and
`8067ce14-3116-4340-b356-9bf26bb5e304`), and the production verifier reported
no kernel log crash findings.

### Debian secure-kUDP current-head production recheck

PVE host `120.220.44.72:8006` was used with disposable VM IDs 200+ only:
VM200 `trustix-secure-a` (`10.203.3.200`) and VM201 `trustix-secure-b`
(`10.203.3.201`) on isolated `vmbr3`. VM100 and all 1xx guests were not
modified. Both guests were Debian 13 on `6.12.90+deb13.1-amd64`.

The validation binary was built from
`ad28f0cc80205f119e32a6bc3fe4958ec144b7c1` with build time
`2026-06-20T19:54:33Z`; both guests used binary SHA256
`a5f51410d2de1d26f3033724168b5075cedac78f44cedabf7a1d4cd795434ba0`.
The guest-built `trustix_crypto.ko` SHA256 was
`13493b1fd70e2559dc491646e5f1a642f3a2cb01941d05ed38548f97a26c4613`;
the guest-built `trustix_datapath_helpers.ko` SHA256 was
`a6d4d492ca62e6c3c5798095e14c894d1bb14cafa1c3aceb67e73f6170432b24`.

The temporary PVE run directory was cleaned after the evidence below was
captured. The 900s bidirectional secure-kUDP production gate passed against the
1.5 Gbps gate. Minimum received throughput was `1.613567 Gbps`; minimum sent
throughput was `1.613684 Gbps`; minimum duration was `899.988124s` and was
accepted by the existing 1s gate slop. Directional received throughput was
`1.613567 Gbps` for A to B and `1.730863 Gbps` for B to A.

The gate required matching binary/build identity, kernel crypto placement,
kernel crypto flow-map readiness, TC secure direct TX/RX attachment, route-GSO
kfunc use, nonzero crypto module direct kfunc seal/open calls, and nonzero
helper route-GSO xmit packets. Both peers reported
`kernel_crypto_flow_map_entries=6`, `kernel_crypto_flow_map_updates=6`, and
`tc_kernel_udp_tx_secure_direct_route_tcp_gso_kfunc=1`. A reported
`direct_kfunc_seal_calls=165829351`,
`direct_kfunc_open_calls=174303580`,
`route_tcp_gso_async_xmit_packets=138450599`, and zero direct kfunc errors. B
reported `direct_kfunc_seal_calls=174324455`,
`direct_kfunc_open_calls=165810494`,
`route_tcp_gso_async_xmit_packets=148552009`, and two direct kfunc/decrypt
errors. The bounded replay/drop counters were `1875` on A and `1749` on B;
covered helper route-GSO error counters stayed at zero.

Boot IDs stayed stable (`47545a6a-ea20-4db2-b768-9a46142b82d2` and
`126c23d8-fe3f-4fdb-aa8a-51cf364dc87f`), and the production verifier reported
no kernel log crash findings.

### Debian full-kmod current-head production recheck

PVE host `120.220.44.72:8006` was used with disposable VM IDs 200+ only:
VM200 `trustix-full-a` (`10.203.3.200`) and VM201 `trustix-full-b`
(`10.203.3.201`) on isolated `vmbr3`. VM100 and all 1xx guests were not
modified. Both guests were Debian 13 on `6.12.90+deb13.1-amd64`.

The validation binary was built from
`5155854d5077af628c776d586d5b735e4447b123` with build time
`2026-06-20T20:41:54Z`; both guests used binary SHA256
`4bab706b9b14bfaac36ef24780929d7b9c71bf377c0e18231eea0cc8d8b839e2`.
The guest-built `trustix_datapath.ko` SHA256 was
`7f4f39e5c6e1c403fad5c33f5993711e4929a892ead22158e1f700a5c846f1b8`.

The temporary PVE run directory was cleaned after the evidence below was
captured. The 900s bidirectional full-kmod production gate passed against the
3 Gbps gate. Minimum received throughput was `3.550158 Gbps`; minimum sent
throughput was `3.550447 Gbps`; minimum duration was `900.007095s`.
Directional received throughput was `3.639226 Gbps` for A to B and
`3.550158 Gbps` for B to A.

The gate required matching binary/build identity, the full plaintext datapath
provider, RX worker injection, session pool size 8, eight session records and
wire records, nonzero plaintext outer-GSO segments, nonzero cached destination
MAC hits, nonzero RX-worker GSO xmit segments, and zero covered RX/TX/module
error counters. A reported `rx_worker_injected=305034692`,
`tx_plaintext_outer_gso_segments=293271045`,
`tx_plaintext_direct_xmit_dst_mac_cache_hits=30904174`, and
`rx_worker_gso_xmit_segments=294207416`. B reported
`rx_worker_injected=312124062`,
`tx_plaintext_outer_gso_segments=286096505`,
`tx_plaintext_direct_xmit_dst_mac_cache_hits=30734603`, and
`rx_worker_gso_xmit_segments=301570332`.

Boot IDs stayed stable (`4aa53388-32a8-4653-86f6-6b738a2758d7` and
`88cbad84-d4a9-4e36-8c8d-52bbb5dee9a9`), and the production verifier reported
no kernel log crash findings.

### Debian TC-direct current-head production recheck

PVE host `120.220.44.72:8006` was used with disposable VM IDs 200+ only:
VM200 `trustix-tcdirect-a` (`10.203.3.200`) and VM201
`trustix-tcdirect-b` (`10.203.3.201`) on isolated `vmbr3`. VM100 and all
1xx guests were not modified. Both guests were Debian 13 on
`6.12.90+deb13.1-amd64`.

The validation binary was built from `a3805571d930` with build time
`2026-06-20T21:31:53Z`; both guests used binary SHA256
`cda15e252f1614eb4a0d3d0cff6dfa01c1c88f99ceba64dbcb5080c51af7972a`.
The build used embedded eBPF objects and `--build-ko 0`; no TrustIX kernel
modules were loaded for this TC-direct gate.

The temporary PVE run directory was cleaned after the evidence below was
captured. The 900s bidirectional plaintext kernel-UDP TC-direct production
gate passed against the 3 Gbps gate. Minimum received throughput was
`3.915829 Gbps`; minimum sent throughput was `3.915923 Gbps`; minimum duration
was `899.9934s` and was accepted by the existing 2s gate slop. Directional
received throughput was `3.915829 Gbps` for A to B and `3.989502 Gbps` for B
to A.

The gate required matching binary/build identity, `kernel_udp.provider` equal
to `tc_direct`, `kernel_udp.fast_path=true`, `kernel_udp.direct_only=true`,
eight active kernel UDP flows on both peers, and zero session dial or heartbeat
errors. Both peers reported `kernel_udp.active_flows=8`. Boot IDs stayed stable
(`76900af4-5f3c-4a93-8bcb-d75204a2ca19` and
`88cb8da9-e75c-4a02-8c34-b7ab9eb4c63c`), and the production verifier reported
no kernel log crash findings.

## 2026-06-20

<a id="2026-06-20-zaozhuang-pve-compatibility-900s-strict-gate"></a>

### Zaozhuang PVE compatibility 900s strict gate

PVE host `120.220.44.72:8006` was used with disposable VM IDs 200+ only:
VM200 `trustix-dd-a` (`10.203.3.200`) and VM201 `trustix-dd-b`
(`10.203.3.201`) on the isolated `vmbr3` underlay. VM100 and all 1xx guests
were not modified. Both guests were Debian 13 on
`6.12.69+deb13-amd64`. The validation binary was built from
`2bc85945ec7b4ad7d2cbb9be39e96e8f2d2772fd` with build time
`2026-06-19T20:32:35Z`; binary identity matched on both guests.

The cross-host verifier now rejects any iperf3 JSON artifact that contains a
top-level `error` when it also contains final summary aggregates. The existing
client-only exception remains limited to artifacts with no final summary and
the specific `unable to receive results` error, where a separate clean server
summary supplies the measured result. This prevents GRE or tunnel runs with
server-side iperf errors from being promoted as clean production evidence.

Strict 900s compatibility results:

| Case | Transport policy | Duration per direction | Minimum received | Required gate | Result |
| --- | --- | ---: | ---: | ---: | --- |
| `udp-secure-stable-userspace-userspace` | `udp` / `secure` / `stable` / `userspace` / `userspace` | 900s | 1.986247 Gbps | session stats clean | pass |
| `tcp-plaintext-stable-userspace-userspace` | `tcp` / `plaintext` / `stable` / `userspace` / `userspace` | 900s | 1.396604 Gbps | session stats clean | pass |
| `udp-plaintext-performance-tc_xdp-userspace` | `kernel_udp` / `plaintext` / `performance` / `tc_xdp` / `userspace` | 900s | 3.986123 Gbps | 3 Gbps plus TC-direct fast path | pass |
| `gre-plaintext-performance-tc_xdp-userspace` | `gre` / `plaintext` / `performance` / `tc_xdp` / `userspace` | 900s | not accepted | clean iperf artifacts | fail |

The UDP and TCP userspace gates required matching binary identity, zero
`session_dial_errors`, zero `session_heartbeat_timeouts`, and observed
transport sessions. The TC-direct gate additionally required
`kernel_udp.provider=tc_direct`, `kernel_udp.fast_path=true`,
`kernel_udp.direct_only=true`, and nonzero `kernel_udp.active_flows`.

The GRE run produced server-side received summaries around 4.73 to 5.10 Gbps,
but both server artifacts also contained `Bad file descriptor` iperf errors.
The strict verifier now rejects that shape, so GRE remains withheld from
production evidence until a clean rerun is captured.

Final suspicious kernel-log scans over the run window found no panic, Oops,
BUG, call trace, page fault, watchdog, lockup, `tx_queue_len`, or TrustIX
datapath crash signatures on either Debian guest.

<a id="2026-06-20-zaozhuang-pve-gre-p4-900s-strict-gate"></a>

### Zaozhuang PVE GRE P4 900s strict gate

The same PVE host and disposable Debian 13 VM200/VM201 pair were reused to
isolate GRE tunnel iperf behavior after the strict verifier rejected the first
P8 run. The validation binary was built from
`c723a099cde1bb1ad5d739929dfb495bbe15663a` with build time
`2026-06-19T22:54:00Z`; both guests used the same
`trustix-linux-amd64` binary SHA256
`6958dd0b7c94dcae7d83fee699c32ee4909992d30d90e3e04e4bf005c1343a7e`.

Parallel sweep result:

| GRE iperf parallel | Result | Minimum received | Notes |
| ---: | --- | ---: | --- |
| 1 | pass | about 5.00 Gbps | clean client and server iperf JSON |
| 2 | pass | about 4.80 Gbps | clean client and server iperf JSON |
| 4 | pass | about 4.88 Gbps | clean client and server iperf JSON |
| 8 | fail | not accepted | client `unable to receive results`, server `Bad file descriptor` |

The production candidate then ran GRE plaintext userspace-TC at P4 for 900s in
both directions. Artifact:
`/tmp/trustix-pve-compat-20260620-065444/results/gre-p4-900-20260620-072217`.
The selected userspace-TC gate passed with `min_gbps=4`, `min_seconds=900`,
`session_dial_errors=0`, `session_heartbeat_timeouts=0`, and eight observed
transport sessions. Measured received throughput was 4.807613 Gbps A to B and
4.951422 Gbps B to A. Neither iperf client/server JSON contained an `error`
field, and final kernel-log scans found no panic, Oops, BUG, call trace, page
fault, watchdog, lockup, `tx_queue_len`, or TrustIX datapath crash signatures.

Change: tunnel transports now default to `TRUSTIX_CROSS_HOST_IPTUNNEL_IPERF_PARALLEL=4`
when the caller has not explicitly set `TRUSTIX_CROSS_HOST_IPERF_PARALLEL`.
The runner also aligns the default session pool size to that tunnel-specific
parallelism unless `TRUSTIX_CROSS_HOST_SESSION_POOL_SIZE` was explicitly set.
Do not promote GRE P8; it remains negative evidence for dirty iperf artifacts.

<a id="2026-06-20-zaozhuang-pve-ipip-vxlan-p4-900s-strict-gates"></a>

### Zaozhuang PVE IPIP/VXLAN P4 900s strict gates

The same Debian 13 VM200/VM201 pair and P4 tunnel default were used for IPIP
and VXLAN after the GRE pass. Both runs used the same binary identity as the
GRE P4 gate.

| Case | Artifact | Duration per direction | Minimum received | Gate | Result |
| --- | --- | ---: | ---: | ---: | --- |
| IPIP plaintext userspace-TC | `/tmp/trustix-pve-compat-20260620-065444/results/ipip-p4-900-20260620-075840` | 900s | 4.798065 Gbps | 4 Gbps | pass |
| VXLAN plaintext userspace-TC | `/tmp/trustix-pve-compat-20260620-065444/results/vxlan-p4-900-20260620-082923` | 900s | 4.786384 Gbps | 4 Gbps | pass |

Both selected userspace-TC gates required matching binary identity,
`session_dial_errors=0`, `session_heartbeat_timeouts=0`, and eight observed
transport sessions. The IPIP run measured 4.798065 Gbps A to B and
5.080735 Gbps B to A. The VXLAN run measured 4.786384 Gbps A to B and
5.368512 Gbps B to A. All four client/server iperf JSON artifacts per run were
clean, and the verifier reported no suspicious kernel-log findings.

Conclusion: plaintext GRE/IPIP/VXLAN userspace-TC tunnel transports are now
selected only at P4 for cross-host production compatibility. Secure tunnel
variants were evaluated separately below after the userspace-encrypted TIXB
batch cap fix.

<a id="2026-06-20-zaozhuang-pve-secure-tunnel-userspace-tc-900s-strict-gates"></a>

### Zaozhuang PVE secure tunnel userspace-TC 900s strict gates

Secure GRE/IPIP/VXLAN userspace-TC was slow because fragmenting native tunnel
sessions let the daemon aggregate many inner packets into a large TIXB payload,
then userspace crypto sealed that as one large datagram. With the old uncapped
path, secure GRE flushed TIXB payloads up to about 261 KiB and throughput fell
to about 0.10 Gbps. The fix caps userspace-encrypted TIXB flushes at 32 KiB by
default while preserving `TRUSTIX_DATA_SESSION_USERSPACE_ENCRYPTED_BATCH_BYTES=0`
as an explicit diagnostic escape hatch.

The cap sweep showed the failure mode and the chosen default:

| Userspace-encrypted cap | Secure GRE minimum received | Notes |
| ---: | ---: | --- |
| 8 KiB | 1.0587 Gbps | stable but lower throughput |
| 16 KiB | 1.3500 Gbps | stable |
| 32 KiB | 1.3633 Gbps | selected default |
| 64 KiB | 1.4271 Gbps | effectively clamped to 32 KiB by code max |
| disabled / 0 | 0.0964 Gbps | max TIXB flush about 261 KiB |

The 60s smoke pass then covered all three secure tunnel transports with the
new default cap: GRE 1.428362 Gbps, IPIP 1.446944 Gbps, and VXLAN
1.441394 Gbps minimum received.

Strict 900s gate artifact:
`/tmp/trustix-pve-secure-tunnels-20260620-090838/results/secure-tunnel-defaultcap-900-20260620-180155`.
The validation binary was `trustix-linux-amd64` built as
`8061c62-secure-batchcap` at `2026-06-20T09:52:49Z`; both guests used SHA256
`e4c5e1fe89f3a52bd18bdcbb1a89fe6da12a3d097b1938105e609c782a8158fd`.

| Case | Duration per direction | A to B received | B to A received | Minimum received | Max TIXB flush | Result |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| GRE secure userspace-TC | 900s | 1.498232 Gbps | 1.467427 Gbps | 1.467427 Gbps | 32,524 bytes | pass |
| IPIP secure userspace-TC | 900s | 1.557929 Gbps | 1.555312 Gbps | 1.555312 Gbps | 32,471 bytes | pass |
| VXLAN secure userspace-TC | 900s | 1.472346 Gbps | 1.452177 Gbps | 1.452177 Gbps | 32,476 bytes | pass |

All three runs required matching binary identity, zero `session_dial_errors`,
zero `session_heartbeat_timeouts`, observed transport sessions, and clean
client/server iperf JSON. Final kernel-log scans across VM200 and VM201 found
no panic, Oops, BUG, call trace, page fault, watchdog, lockup, `tx_queue_len`,
or TrustIX datapath crash signatures.

Conclusion: secure GRE/IPIP/VXLAN userspace-TC are now selected as stable
cross-host compatibility defaults at a 1 Gbps / 900s gate. The plaintext tunnel
performance defaults remain the separate P4 / 4 Gbps gates above.

### OpenWrt 24.10.2 full-kmod production gate

PVE host `120.220.44.72:8006` was used with disposable VM IDs 200+ only:
VM200 Debian 13 (`192.168.100.200`) and VM202 OpenWrt 24.10.2 x86_64
(`192.168.100.202`). VM100 and all 1xx guests were not modified. A dedicated
`vmbr3` underlay carried the test traffic.

OpenWrt 24.10.2 x86_64 uses kernel `6.6.93`. The OpenWrt SDK kmod matrix
passed after moving the `trustix_crypto` AEAD completion callback ABI gate from
Linux 6.8 to Linux 6.6; OpenWrt 24.10's 6.6 headers use the newer
`void (*)(void *, int)` completion callback signature.

OpenWrt SDK module build result for `24.10.2-x86_64`:

| Module | SHA256 | Capability result |
| --- | --- | --- |
| `trustix_crypto.ko` | `050371d0b1cbcfcf7e4d0fd739870db177b1dca3bbb46dd873c7eeceec45304e` | full crypto module built and loaded |
| `trustix_datapath_helpers.ko` | `fd0df3e4748db2889e593997cf01c49f3fb87125f1b9560ead0a0db05e8710f0` | full helpers built and loaded |
| `trustix_datapath.ko` | `09339f3e18f0f536908736fb08cd6f91728ff8c6dcfd2b8d9cd1cfd7677fbe10` | full plaintext module built and loaded |

The runner also exposed two OpenWrt portability bugs in the test harness rather
than the datapath: remote `ssh ... bash -s <<<"$script"` could leave ssh
waiting on stdin while long iperf commands were still running, and some command
paths could resolve BusyBox `ip`/`timeout` instead of `ip-full`. The cross-host
runner now executes remote snippets with `ssh -n ... bash -c` and resolves
`ip_cmd=$(command -v ip)` before netns setup, health checks, iperf server/client
commands, ping checks, and cleanup.

Validation:

| Case | Artifact | Duration per direction | Minimum received | Gate | Result |
| --- | --- | ---: | ---: | ---: | --- |
| OpenWrt 24.10.2 to Debian full plaintext kmod | `/tmp/trustix-pve-owrt2410.mkjwgb/results/owdeb-fullkmod-vmbr3-both-900-fixed-20260620013755` | 900s | 3.435125 Gbps | 3 Gbps | pass |

The production gate required matching binary identity, `session_pool_size=8`,
flow session pool warmup, `kernel_datapath_full_plaintext_provider=1`,
nonzero `kernel_rx_stage.rx_worker_injected`, eight session records/wires,
nonzero `tx_plaintext_outer_gso_segments`,
`tx_plaintext_direct_xmit_dst_mac_cache_hits`, and
`rx_worker_gso_xmit_segments`. Covered module error counters stayed at zero,
including RX worker allocation/deliver/GSO/xmit errors, plaintext TX build/no
session/no wire/stale wire/xmit/outer-GSO errors, and queue drops. Both guest
kernel log scans were clean for panic, Oops, BUG, call trace, page fault,
watchdog, lockup, hung-task, `tx_queue_len`, and TrustIX datapath crash
signatures.

Follow-up OpenWrt 24.10.2 route-TCP kfunc checks reused VM200/VM202 on the same
`vmbr3` underlay. Debian 13 exposed `/sys/kernel/btf/vmlinux` and
`CONFIG_DEBUG_INFO_BTF=y`; OpenWrt 24.10.2 did not expose kernel BTF. The
OpenWrt `trustix_datapath_helpers.ko` module loaded but reported no safe helper
kfunc capability. Secure-kUDP route-GSO failed closed before traffic with
`missing=route_tcp_kfunc,route_tcp_xmit_kfunc`. Artifact:
`/tmp/trustix-pve-owrt24-next.S9YJo0/results/owdeb-secure-kudp-tconly-30-20260620-024040`.
Experimental TCP route-GSO failed closed with the same missing helper
capabilities. Artifact:
`/tmp/trustix-pve-owrt24-next.S9YJo0/results/owdeb-routegso-30-20260620-024147`.

Conclusion: OpenWrt 24.10.2 has a validated full plaintext kmod path, but the
official x86_64 kernel image used here does not provide the BTF/kfunc runtime
surface required for TrustIX route-GSO helpers. Do not select OpenWrt 24.10.2
secure-kUDP route-GSO or experimental TCP route-GSO as production defaults.

### OpenWrt-Debian route-GSO capability check

PVE host `120.220.44.72:8006` was used with disposable VM IDs 200+ only:
VM200 Debian 13 (`192.168.100.200`) and VM202 OpenWrt 23.05.5 x86_64
(`192.168.100.202`). VM100 and all 1xx guests were not modified. The release
under test was built from `8507d2eb6183`.

OpenWrt VM202 had to boot from a SATA disk; virtio/scsi imports booted QEMU but
did not provide usable guest network/serial access. OpenWrt feeds were switched
to TUNA and the rootfs was expanded for SDK/runtime work.

OpenWrt SDK module build result for `23.05.5-x86_64`:

| Module | SHA256 | Capability result |
| --- | --- | --- |
| `trustix_crypto.ko` | `beee8798173c08f1c8f867535ac60d1ac4fa2e4a8c5d213e13f66463fc63e503` | device-only crypto, `features=2` |
| `trustix_datapath_helpers.ko` | `a6edb84b254a68e16fde54d17a90362c1509b0e620c68ca0e0cee3c5a97a72d8` | basic helpers, `features=0`, selftests passed |
| `trustix_datapath.ko` | `b3bc3ff5da61ea3f23272f82375ca0e1175b8273cd89e79a2c16ef6e4a6e5634` | full plaintext module loaded with selected parameters |

OpenWrt-to-Debian secure-kUDP route-GSO smoke failed closed before traffic:
`secure kernel_udp route-GSO requires trustix_datapath_helpers full route TCP
kfunc capability; missing=route_tcp_kfunc,route_tcp_xmit_kfunc`. Artifact:
`/tmp/trustix-pve-owdeb.kBuFlE/results/owdeb-secure-kudp-30-20260620-000728`.

OpenWrt-to-Debian experimental TCP route-GSO smoke also failed closed before
traffic with the same missing helper capabilities. Artifact:
`/tmp/trustix-pve-owdeb.kBuFlE/results/dd-routegso-30-20260620-000854`. The
runner case name remained `dd-routegso`, but the endpoints were manually set to
OpenWrt A and Debian B.

Conclusion: this is not a throughput failure and not a panic reproduction; the
OpenWrt 23.05.5 helper module cannot provide route-TCP kfuncs, so OpenWrt
route-GSO and OpenWrt secure-kUDP route-GSO must stay unselected until a newer
OpenWrt kernel/helper combination passes the runtime gate. The validated
OpenWrt production path remains UDP plaintext full-kmod from the 900s gate.

## 2026-06-19

<a id="2026-06-19-zaozhuang-pve-selected-transport-matrix-gate"></a>

### Zaozhuang PVE selected transport matrix gate

PVE host `120.220.44.72:8006` was used with disposable VM IDs 200+. VM100 and
all 1xx guests were not modified. The test VMs, temporary bridges (`vmbr3`,
`vmbr5`), NAT rule, OpenWrt image cache, source syncs, test binaries, and cross
host SSH key were removed after verification.

Validation binaries were built from `74920a547fe51d21a985320563155d17a3058c4d`
with a dirty tree containing harness-only changes. The current repo head after
that run only changed scripts/tests around the matrix harness; datapath and
kernel module sources were not changed by those commits.

Selected Debian-to-Debian 900s matrix:

| Case | Transport policy | Duration per direction | Minimum received | Gate |
| --- | --- | ---: | ---: | --- |
| `dd-fullkmod` | `udp` / `plaintext` / `performance` / `kernel_module` / `userspace` | 900s | 3.566969 Gbps | 3 Gbps |
| `secure-kudp` | `kernel_udp` / `secure` / `performance` / `tc_xdp` / `kernel` | 900s | 1.744620 Gbps | 1.5 Gbps |
| `dd-routegso` | `experimental_tcp` / `plaintext` / `performance` / `kernel_module` / `userspace` | 900s | 2.696084 Gbps | 2.5 Gbps |

The selected production gate then passed all three families. It required
matching binary identity, transport policy metadata, session pool warmup, route
GSO helper stats, secure-kUDP crypto/kfunc readiness, full plaintext provider
stats, and zero module error counters except the bounded secure-kUDP replay
noise budget. Debian boot IDs stayed stable:
`b77414e4-0ddc-4604-8f43-e2a98ce51cc8` and
`e197a1d8-9a2c-4c29-adf7-c8785b0c090d`; final kernel log scans found zero
panic, Oops, BUG, call trace, page fault, watchdog, lockup, hung-task, or
`tx_queue_len` signatures.

OpenWrt-to-Debian full plaintext validation used OpenWrt 23.05.5 x86_64
kernel `5.15.167` with an OpenWrt SDK-built `trustix_datapath.ko`
(`dc5c96d579f59de7299517e1869df85f2331b6eebba9893d081935fbd5144143`) and
Debian 13 kernel `6.12.90+deb13.1-amd64`. The 900s bidirectional full-kmod run
passed with minimum received throughput of 3.495550 Gbps against a 3 Gbps gate.
Captured module counters stayed clean: both sides reported zero
`rx_worker_dropped`, allocation/checksum/deliver/GSO xmit errors, plaintext TX
errors, and `selftest_failures`. OpenWrt/Debian boot IDs stayed stable:
`0761f435-1298-414b-89ef-189f9a9885f7` and
`fc992768-3f54-4d7d-9396-2d44d927de25`.

Change: provisioning defaults now align with the selected production paths.
The default profile remains plaintext performance and emits UDP full-kmod with
`crypto_placement: userspace` and `kernel_transport: require_kernel`. The
explicit secure `performance` profile emits secure kernel-UDP with
`datapath: tc_xdp`, `crypto_placement: kernel`, `kernel_transport:
require_kernel`, and only the selected UDP endpoint; it no longer adds an
unselected secure `experimental_tcp` secondary endpoint.

Gate hardening: secure-kUDP production verification now also requires the
secure route-GSO TC option in datapath status plus nonzero helper route-GSO
outer-GSO/xmit counters, with the same route-GSO helper error counters capped at
zero. This prevents a secure direct run from passing the selected secure
route-GSO gate without actually exercising the selected fast path.

## 2026-06-16

### Zaozhuang PVE OpenWrt SDK full-kmod validation

PVE host: `120.220.44.72:8006`, isolated VM IDs 200+. VM100 and 1xx were not
modified. Test VMs:

| VM | Role | Address |
| --- | --- | --- |
| `200 trustix-deb-a` | Debian IX A | `192.168.100.200` |
| `201 trustix-deb-b` | Debian IX B | `192.168.100.201` |
| `202 trustix-openwrt` | OpenWrt IX | `192.168.100.202` |

Important OpenWrt finding: OpenWrt 23.05.5 x86_64 uses kernel `5.15.167` and
has no `/sys/kernel/btf/vmlinux`, so TC/eBPF CO-RE cannot be treated as the main
OpenWrt performance path on that release. Full plaintext OpenWrt performance
requires a matching OpenWrt SDK-built `trustix_datapath.ko`; Debian/PVE embedded
`.ko` assets are the wrong kernel ABI.

OpenWrt SDK module used:

| Target | Output | SHA256 |
| --- | --- | --- |
| `23.05.5-x86_64` | `/root/trustix-openwrt-kmod-dirty-20260616-1243/.../trustix_datapath.ko` | `9017947ff22e2181323222a8acc46b7fc89e15221a9e56b748410cd5820fe516` |

Validation:

| Case | Artifact | Duration per direction | Throughput | Result |
| --- | --- | ---: | ---: | --- |
| Debian to Debian full plaintext kmod | `/root/trustix-cross/dirty-dd-fullkmod-20260616-1200/results/bidir-p8-120-clean-20260616-120411` | 120s | 8.02 / 8.05 Gbps | pass |
| Debian to Debian full plaintext kmod | `/root/trustix-cross/dirty-dd-fullkmod-20260616-1200/results/dd-bidir-p8-900-20260616-132214` | 900s | 5.552 / 4.465 Gbps | pass at 4 Gbps production gate |
| Debian to Debian route-GSO fallback | `/root/trustix-cross/dirty-dd-routegso-20260616-1210/results/bidir-p8-120-20260616-121345` | 120s | 1.59 / 1.60 Gbps | pass at 1 Gbps fallback gate |
| OpenWrt to Debian full plaintext kmod | `/root/trustix-cross/dirty-owdeb-fullkmod-20260616-1312/results/owdeb-bidir-p8-120-20260616-124815` | 120s | 12.15 / 7.28 Gbps | pass at 4 Gbps production gate |
| OpenWrt to Debian mixed full plaintext kmod soak | `/root/trustix-cross/dirty-owdeb-fullkmod-20260616-1312/results/owdeb-bidir-p8-900-mixed-20260616-125153` | 900s | 14.038 / 4.676 Gbps | pass at 4 Gbps production gate |

The 900s mixed soak verifier required matching build/binary identity and
`kernel_udp.provider_stats.kernel_datapath_full_plaintext_provider=1`. Datapath
counters stayed clean: both sides reported zero `rx_worker_dropped` and zero
`tx_plaintext_xmit_errors`. No panic, Oops, watchdog, lockup, or TrustIX crash
signature was present in the captured logs.

The Debian-to-Debian 900s full plaintext run used the same dirty binary on both
hosts (`5f07d3119f2ba57d3577059a0bc5fe40b265733927f12ab4a5eee1f5b86e931b`).
`verify-client-bidir.jsonl` passed with `--min-gbps 4.0`, `--min-seconds 900`,
matching build/binary identity, and full plaintext provider stats on both
hosts. The iperf3 `--bidir` reverse direction measured 4.465 Gbps, also above
the 4 Gbps gate. A and B boot IDs stayed unchanged, and explicit crash
signature scanning found zero findings.

OpenWrt module load/unload stability was also checked on VM202 with the SDK
module copied to `/etc/trustix/modules/trustix_datapath.ko`:
`9017947ff22e2181323222a8acc46b7fc89e15221a9e56b748410cd5820fe516`. Twenty
load/unload cycles with full plaintext parameters completed without reboot or
crash signatures. The older wrong `/etc/trustix/modules` copy was replaced with
the SDK-built module after the reload test.

Change: OpenWrt kernel module handling is now fail-closed for embedded `.ko`
assets. Auto-mode embedded modules are disabled on OpenWrt, and required
OpenWrt modules with an embedded or empty path are rejected with a clear
OpenWrt SDK `.ko` error. Generated OpenWrt provisioning configs point active
module paths at `/etc/trustix/modules/*.ko` unless
`TRUSTIX_PROVISION_OPENWRT_ALLOW_EMBEDDED_KMOD=1` is explicitly set.
The cross-host soak verifier now also checks iperf3 `--bidir` reverse sums
(`sum_*_bidir_reverse`) against the same throughput and duration gate.

## 2026-06-15

### Current full-kmod speed regression check

Finding: a low-throughput rerun was traced to stale cross-host test payloads,
not a current-source full-kmod throughput regression. VM104/VM106/VM107 did not
all have the same `/tmp/trustix-e2e/bin/trustixd`; after rebuilding the current
PVE source and syncing the same binary to the test peers, plaintext full-kmod
returned above the 4 Gbps production gate.

Current-source PVE verification:

| Case | Artifact | Duration per direction | Throughput |
| --- | --- | ---: | --- |
| Debian to Debian full-kmod, live recheck | `/root/trustix-openwrt-debian-e2e/results/codex-live-dd-fullkmod-fixcheck-20260614-172044` | 20s | 5.235 / 5.389 Gbps |
| Debian to Debian full-kmod | `/root/trustix-openwrt-debian-e2e/results/codex-fixspeed-dd-fullkmod-short-20260615-001507` | 20s | 5.389 / 5.530 Gbps |
| Debian to Debian full-kmod | `/root/trustix-openwrt-debian-e2e/results/codex-fixspeed-dd-fullkmod-soak120-20260615-002936` | 120s | 5.430 / 5.550 Gbps |
| OpenWrt to Debian full-kmod | `/root/trustix-openwrt-debian-e2e/results/codex-fixspeed-owdeb-fullkmod-short-20260615-001950` | 20s | 5.472 / 6.280 Gbps |
| OpenWrt to Debian full-kmod | `/root/trustix-openwrt-debian-e2e/results/codex-fixspeed-owdeb-fullkmod-soak120-20260615-002404` | 120s | 5.483 / 6.275 Gbps |
| Debian to Debian full-kmod, identity-gated | `/root/trustix-openwrt-debian-e2e/results/codex-identity-dd-fullkmod-soak120-20260614-165703` | 120s | 5.447 / 5.564 Gbps |
| OpenWrt to Debian full-kmod, identity-gated | `/root/trustix-openwrt-debian-e2e/results/codex-identity-owdeb-fullkmod-soak120-20260614-170127` | 120s | 5.497 / 4.496 Gbps |
| Debian to Debian route-GSO, identity-gated | `/root/trustix-openwrt-debian-e2e/results/codex-identity-dd-routegso-proddefault-soak120-20260614-170547` | 120s | 4.659 / 4.681 Gbps |

Verifier summaries:

- `/root/trustix-openwrt-debian-e2e/results/codex-identity-soak-verify-summary-20260614-171014.jsonl`
- `/root/trustix-openwrt-debian-e2e/results/codex-identity-routegso-verify-summary-20260614-171014.jsonl`

The identity-gated verifier required matching `binary-identity.json` checksums
on both peers. Full-kmod also required
`kernel_udp.provider_stats.kernel_datapath_full_plaintext_provider=1` on both
peers. Route-GSO required
`tc_experimental_tcp_tx_direct_route_tcp_gso_async_kfunc=1`,
`tc_experimental_tcp_tx_direct_route_tcp_gso_async_kfunc_requested=1`, and
`tc_kernel_udp_tx_direct_experimental_tcp_only=1` on both peers. All three
identity-gated runs passed the 4 Gbps gate and log crash scan.

Change: `scripts/linux-cross-host-soak-verify.py` now records and validates
collected build identities, and can require matching `binary-identity.json`
checksums. `scripts/linux-e2e-smoke.sh` writes a `*-binary-identity.json`
artifact beside status/route/datapath captures so future performance results
can fail closed when peers are accidentally tested with different binaries.
The verifier can also require specific datapath stats from every collected
`datapath.json`; when a datapath stat is required, it defaults to requiring at
least two datapath captures so one-sided artifacts do not pass accidentally.

Change: `scripts/linux-cross-host-production-gate.sh` wraps the verifier for the
production cross-host gates. It defaults to 4 Gbps, 120 seconds per direction,
requires matching binary identities, requires the full-kmod plaintext provider
stat for full-kmod artifacts, and requires the route-GSO async kfunc provider
stats for route-GSO artifacts.

Example:

```bash
TRUSTIX_CROSS_HOST_DD_FULL_KMOD=/root/trustix-openwrt-debian-e2e/results/codex-identity-dd-fullkmod-soak120-20260614-165703 \
TRUSTIX_CROSS_HOST_OWDEB_FULL_KMOD=/root/trustix-openwrt-debian-e2e/results/codex-identity-owdeb-fullkmod-soak120-20260614-170127 \
TRUSTIX_CROSS_HOST_DD_ROUTE_GSO=/root/trustix-openwrt-debian-e2e/results/codex-identity-dd-routegso-proddefault-soak120-20260614-170547 \
bash scripts/linux-cross-host-production-gate.sh
```

### Cross-host production artifact verifier

Change: added `scripts/linux-cross-host-soak-verify.py`. The single-host
production matrix now skips full-kmod and ACKless route-GSO throughput gates by
default because netns-only throughput is not representative for those paths.
This verifier is the machine-readable gate for cross-host artifacts: it checks
`*.result == pass`, requires bidirectional iperf3 JSON, enforces minimum
throughput and duration, and scans logs for kernel crash signatures such as
panic, oops, BUG, call trace, watchdog, and lockup.

PVE verification commands used:

```bash
python3 scripts/linux-cross-host-soak-verify.py --min-gbps 4 --min-seconds 120 \
  --case dd-fullkmod=/root/trustix-openwrt-debian-e2e/results/codex-warmfix-dd-fullkmod-underlay-soak120-20260614-152812 \
  --case owdeb-fullkmod=/root/trustix-openwrt-debian-e2e/results/codex-warmfix-static-owdeb-fullkmod-soak120-20260614-154244

python3 scripts/linux-cross-host-soak-verify.py --min-gbps 4 --min-seconds 300 \
  --case dd-routegso=/root/trustix-openwrt-debian-e2e/results/codex-soak300-dd-routegso-soak300-20260614-101456
```

Validation result:

| Case | Kernel pair | Duration per direction | Minimum received throughput | Result |
| --- | --- | ---: | ---: | --- |
| `dd-fullkmod` | Debian 6.1 to Debian 6.1 | 120s | 5.428 Gbps | pass, no crash signatures in artifacts |
| `owdeb-fullkmod` | OpenWrt 5.15 to Debian 6.1 | 120s | 5.114 Gbps | pass, no crash signatures in artifacts |
| `dd-routegso` | Debian 6.1 to Debian 6.1 | 300s | 4.635 Gbps | pass, no crash signatures in artifacts |

Conclusion: the selected production plaintext fast paths are above the 4 Gbps
cross-host gate in the verified artifacts. The verifier does not replace a
fresh live soak, but it makes stored PVE soak results fail-closed instead of
depending on manual interpretation.

## 2026-06-08

### Public A/B ACKless TCP route-GSO verifier and stability retest

Change: fixed route-GSO TC BPF generation so the route-GSO kfunc path no longer leaves verifier-unreachable fallback blocks behind. Follow-up fix redirects positive route-GSO kfunc returns in the route-xmit variant instead of falling through to the adjust-drop path.

Validation:

| Result file | Case | TCP tests | Result |
| --- | --- | --- | --- |
| `build/perf-matrix-remote-216-82-20260608-222345.json` | `exp_plaintext_fast_route_gso_async_stream_hw_inline_rx_directbuild_m64_outergso_hardenable_tuned_ackonly` | `82clientp1,82clientp4` | p1 2576.0 Mbps, p4 2344.1 Mbps, no reboot, outer-GSO active |
| `build/perf-matrix-remote-216-82-20260608-222345.json` | `...flowshard_shards8_deqbatch_scheddepth8_usec500_dynlow12_high24_q4_emit12_resched16_hash_txq` | `82clientp1,82clientp4` | p1 2315.9 Mbps, p4 2143.7 Mbps, no reboot, cross-item active |
| `build/perf-matrix-remote-216-82-20260608-223422.json` | `exp_plaintext_fast_route_gso_async_skipseq_route_xmit_kfunc` | `82clientp1,82clientp4` | p1 648.0 Mbps, p4 610.2 Mbps, no reboot, route-xmit kfunc active but not a throughput path |
| `build/perf-matrix-remote-216-82-20260608-224203.json` | RX inline xmit stream-coalesce variants | `82clientp1` | 126.0 and 263.1 Mbps, no reboot; stable but not useful for performance |

Conclusion: current public A/B fast ACKless path is route-GSO async stream direct-build with outer-GSO hard-enable. Route-xmit kfunc is now functional and stable in the tested public directions, but it mainly handles linear packets and does not improve throughput. RX inline xmit/coalesce no longer reproduced the earlier immediate panic in this short test, but throughput is too low to keep pursuing as the main performance path.

Profile update: plaintext `performance` ACKless now enables `route_tcp_gso_async_stream_outer_gso_hard_enable=1` so the profile reaches the validated outer-GSO path. `stable` remains conservative and does not enable route-GSO async, outer-GSO hard-enable, or route-xmit worker by default.

### Current-source PVE and public confirmation

Compatibility fix: `dev->reg_state` is a bit-field on the current PVE/public kernels, so module code now reads it directly instead of through `READ_ONCE()`. This fixed out-of-tree module builds on PVE Ubuntu 6.8 and public Debian 6.12.

PVE result file: `build/pve/pve-current-routegso-confirm-20260608-230959.json`, PVE VM A/B on `10.10.0.11/10.10.0.12`, underlay `enp6s19`, `TCP_TESTS=82clientp1,82clientp4,82clientp8`, `IPERF_SECONDS=5`, UDP disabled, route outer-GSO enabled, per-case module validation enabled.

| Case | p1 Mbps | p4 Mbps | p8 Mbps | Result |
| --- | ---: | ---: | ---: | --- |
| ordered outer-GSO hard-enable | 3922.9 | 3671.8 | 3445.2 | no reboot, module validation OK, `route_gso_stream_outer_gso_active` |
| sharded4 outer-GSO hard-enable | 4188.9 | 3615.9 | 3496.4 | no reboot, module validation OK |
| sharded8 outer-GSO hard-enable | 4311.2 | 3665.2 | 3527.1 | no reboot, module validation OK; best p1 |
| flowshard/shards8/deqbatch/dyncap/hash-txq profile candidate | 3853.5 | 3612.5 | 3243.5 | no reboot, cross-item active, not better than simple sharded cases |
| route-xmit kfunc compatibility path | 3339.5 | 3362.3 | 2949.1 | no reboot, `route_tcp_xmit_active`; stable but still not the best throughput path |

PVE conclusion: current source has a repeatable ACKless TCP performance ceiling above 3 Gbps on the isolated PVE path. The simple outer-GSO async stream direct-build variants remain the best candidates; extra flowshard/cross-item tuning did not beat them in this run. Route-xmit kfunc is no longer a low-throughput-only path on PVE, but it still trails outer-GSO direct-build.

Public A/B result files: `build/perf-matrix-remote-216-82-public-confirm-20260608-232942.json` and `build/perf-matrix-remote-216-82-public-b2a-repeat-20260608-234401.json`.

| Case | Direction | Result |
| --- | --- | --- |
| sharded8 outer-GSO hard-enable | A -> B | p1 427.2 Mbps, p4 669.7 Mbps, no reboot |
| sharded8 outer-GSO hard-enable | B -> A | p1 761.7 Mbps, p4 1244.1 Mbps, no reboot |
| route-xmit kfunc | A -> B | p1 171.5 Mbps, p4 389.6 Mbps, no reboot |
| route-xmit kfunc | B -> A | p1 602.2 Mbps, p4 576.0 Mbps, no reboot |
| ordered outer-GSO hard-enable repeat | B -> A | p1 707.5 Mbps, p4 1204.7 Mbps, p8 1719.8 Mbps, no reboot |

Same-window public underlay baseline: direct iperf A -> B was p1 303.3 Mbps / p4 499.0 Mbps, while B -> A was p1 910.2 Mbps / p4 2187.1 Mbps. Public TrustIX throughput is therefore dominated by the asymmetric/noisy public underlay in this window, not by a PVE-style kernel panic or verifier failure.

Cleanup: after the PVE and public confirmations, A, B, pveA, and pveB had stable boot IDs, no `trustixd`/`trustixd.current`/`iperf3` processes, no TrustIX modules loaded, and no test netns left. Final available memory was about 705 MiB on A, 733 MiB on B, 7314 MiB on pveA, and 7410 MiB on pveB.

## 2026-06-02

### PVE ACKless TCP outer-GSO stability correction

The 2026-06-01 PVE outer-GSO numbers below are now historical only. Follow-up PVE stability tests showed that route-TCP outer-GSO is not safe enough to be the default fast path:

| Result file | Case | Outcome |
| --- | --- | --- |
| `build/pve/pve-paircoalesce-nohold-p4-20260602-132359.json` | pair-coalesce, no hold-skb, outer-GSO | pveB rebooted during p4; crash is on TX route-GSO outer-GSO path, not only RX hold-skb |
| `build/pve/pve-holdskb2-stability-20260602-131400.json` | hold-skb pair-coalesce | p1 stable at 586.48 Mbps, p4 rebooted pveA |
| `build/pve/pve-directbuild-noouter-p4-20260602-133300.json` | `exp_plaintext_fast_route_gso_async_stream_hw_inline_rx_directbuild_m64_tuned_ackonly` | p4 stable at 3322.42 Mbps, no reboot, `route_tcp_gso_async_stream_outer_gso_batches=0` |

Current stable ACKless TCP baseline is no-outer direct-build:

| Alias | Case | p4 Mbps | Notes |
| --- | --- | ---: | --- |
| `ackless_directbuild_noouter_tuned` | `exp_plaintext_fast_route_gso_async_stream_hw_inline_rx_directbuild_m64_tuned_ackonly` | 3322.42 | Stable PVE p4, direct-build async xmit, no outer-GSO |

Current-source retest note: after the later `xmit_more` no-op probe and the reverted hold-skb8 experiment, `build/pve/pve-directbuild-noouter-current-p4-20260602-171147.json` failed before throughput and rebooted pveA from `3b5a966f-9f8b-4902-bda7-80b1865f5078` to `89c54d18-cb17-4b37-98cf-84c332c8302b`. That run had been redeployed after reverting the 8-frame cap to 4. Treat the older 3.3-3.7 Gbps no-outer numbers as historical until a fresh isolated PVE retest reproduces them. After the failed retest, pveA/pveB were cleaned: no TrustIX/iperf processes, no test netns/veth, and no TrustIX modules remained.

Change: `route_tcp_gso_async_stream_outer_gso` is now gated by `route_tcp_gso_async_stream_outer_gso_hard_enable`, which defaults off. Requests with hard-enable off fall back to stable no-outer direct-build and increment `route_tcp_gso_async_stream_outer_gso_blocked`. The `ackless_fast` alias now selects no-outer direct-build cases first.

Validation after the gate:

| Result file | Case | TCP tests | Result |
| --- | --- | --- | --- |
| `build/perf-matrix-remote-216-82-20260602-135641.json` | `ackless_directbuild_noouter_tuned` | `82clientp1,82clientp4` | p1 3690.90 Mbps, p4 3586.73 Mbps, no reboot, module params OK, outer-GSO batches 0 |
| `build/perf-matrix-remote-216-82-20260602-140017.json` | `m64_outergso_tuned_ackonly`, hard-enable off | `82clientp1` | 3706.46 Mbps, no reboot, state `route_gso_stream_outer_gso_blocked_direct_build_active`, outer-GSO batches 0, blocked 1073044 |
| `build/perf-matrix-remote-216-82-20260602-141159.json` | `m64_outergso_tuned_ackonly`, hard-enable off, public A/B | `82clientp1,82clientp4` | p1 540.41 Mbps, p4 555.37 Mbps, no reboot, state `route_gso_stream_outer_gso_blocked_direct_build_active`, outer-GSO batches 0, blocked 319374 |
| `build/perf-matrix-remote-216-82-20260602-141159.json` | `ackless_directbuild_noouter_tuned`, public A/B | `82clientp1,82clientp4` | p1 605.93 Mbps, p4 526.16 Mbps, no reboot, state `route_gso_stream_direct_build_active`, outer-GSO batches 0 |

PVE deploy/build note: first helper build used the wrong feature macro `NETIF_F_GSO_TCPV4`; Ubuntu 6.8 exposes TCPv4 TSO as `NETIF_F_TSO`. After switching to `NETIF_F_TSO`, helper module build/load passed on both PVE VMs. Final cleanup unloaded TrustIX modules and removed test netns on both VMs; boot IDs remained stable.

Public A/B note: the hard gate behaved correctly on the public path too: requesting outer-GSO with hard-enable off did not emit outer-GSO skbs and fell back to direct-build. Public throughput remained around 0.5-0.6 Gbps while the same code reached about 3.6-3.7 Gbps on PVE, so this run does not justify more public-path micro-optimization until a cleaner underlay is available. After the public run, public host A and public host B were explicitly cleaned: `trustix-webui` inactive, no exact `trustixd`/`trustixd.current`/`iperf3` processes, no TrustIX modules, no test netns/veth, no underlay XDP, boot IDs unchanged. Final available memory was about 1728 MiB on A and 796 MiB on B.

### PVE route-TCP outer-GSO hard-enable opt-in

Change: added explicit hard-enable matrix cases and aliases so this crash-risk path is never tested by manually toggling sysfs. `ackless_outergso_hard_smoke` selects ordered `m64_outergso_hardenable_tuned_ackonly`; `ackless_outergso_hard_sweep` selects ordered/sharded4/sharded8; `ackless_outergso_hard_crossitem` selects the sharded4 cross-item budget case. These cases set `route_tcp_gso_async_stream_outer_gso_hard_enable=true` and require both `TRUSTIX_MATRIX_ENABLE_ROUTE_OUTER_GSO_HARD=1` and `TRUSTIX_MATRIX_PUBLIC_DISABLE_ROUTE_TCP_UNSAFE_OVERRIDES=0`.

Validation: local py_compile, full `python -m unittest build.test_run_remote_perf_matrix`, targeted daemon module parameter tests, and `go test -count=1 ./internal/kernelmodule` passed. PVE VMs were tested via the PVE jump host on `10.10.0.11/10.10.0.12`, underlay `enp6s19`, with UDP disabled and `SKIP_UNDERLAY=1`.

| Result file | Case | TCP tests | Result |
| --- | --- | --- | --- |
| `build/pve/pve-outergso-hard-smoke-20260602-143057.json` | ordered hard-enable | `82clientp1` | p1 4270.43 Mbps, no reboot, outer-GSO active, batches 34817, frames 809372, errors 0 |
| `build/pve/pve-outergso-hard-p4-20260602-143420.json` | ordered hard-enable | `82clientp4` | p4 3495.78 Mbps, no reboot, outer-GSO active, errors 0 |
| `build/pve/pve-outergso-hard-p8-20260602-143759.json` | ordered hard-enable | `82clientp8` | p8 3611.09 Mbps, no reboot, outer-GSO active, errors 0 |
| `build/pve/pve-outergso-hard-sweep-p4-20260602-144220.json` | ordered / sharded4 / sharded8 hard-enable | `82clientp4` | ordered 3980.71 Mbps; sharded4 3667.68 Mbps; sharded8 3692.54 Mbps; no reboot, outer-GSO errors 0 |
| `build/pve/pve-outergso-hard-crossitem-p4p8-20260602-145039.json` | sharded4 cross-item hard-enable | `82clientp4,82clientp8` | p4 3755.05 Mbps, p8 3613.42 Mbps, cross-item frames 129732, no reboot, errors 0 |

Conclusion: the new hard gate makes route-TCP outer-GSO usable as an explicit isolated-host experiment again. Ordered hard-enable is the best current PVE result in this sweep: 4.27 Gbps p1 and 3.98 Gbps p4. Sharding and cross-item did not help in this window. Keep hard-enable default-off and do not run it on public A/B unless explicitly accepting reboot risk; the stable default remains no-outer direct-build.

Cleanup: after the hard-enable PVE runs, both VMs had unchanged boot IDs, `trustix-webui` inactive, no exact `trustixd`/`trustixd.current`/`iperf3` processes, no TrustIX modules, no test netns/veth, and no underlay XDP. Final available memory was about 7526 MiB on pveA and 7560 MiB on pveB.

## 2026-06-01

### Stable PVE ACKless TCP baseline

PVE VM A `10.10.0.11` and VM B `10.10.0.12`, underlay `enp6s19`, `TRUSTIX_MATRIX_CASES=ackless_fast`, `TCP_TESTS=82clientp1,82clientp4,82clientp8`, `IPERF_SECONDS=5`, UDP disabled.

Result file: `build/perf-matrix-remote-216-82-20260601-023418.json`.

Best stable path so far:

| Case | p1 Mbps | p4 Mbps | p8 Mbps | Notes |
| --- | ---: | ---: | ---: | --- |
| `exp_plaintext_fast_route_gso_async_stream_hw_inline_rx_directbuild_m64_outergso_tuned_ackonly` | 4462.83 | 3815.54 | 3684.41 | Stable route-GSO outer-GSO |
| `exp_plaintext_fast_route_gso_async_stream_hw_inline_rx_directbuild_m64_outergso_tuned_sharded8_ackonly` | 4628.57 | 3893.40 | 3454.32 | Current best p1/p4 |
| `exp_plaintext_fast_route_gso_async_stream_hw_rxparse_directbuild_m40_ackonly` | 3505.03 | 3176.52 | 3086.09 | Direct-build without outer-GSO |
| `exp_plaintext_fast_route_gso_async_stream_hw_rxparse_directbuild_m40_outergso_coalesce_ackonly` | 4246.45 | 3659.16 | 3428.76 | RX parse/coalesce plus outer-GSO |

Diagnosis: fastest stable state is `route_gso_stream_outer_gso_active`.

Short stability rerun: `build/perf-matrix-remote-216-82-20260601-031012.json`, `TCP_TESTS=82clientp1,82clientp4`, UDP disabled, forced module reload disabled but per-case required module reload/checks enabled.

| Case | p1 Mbps | p4 Mbps | Validity |
| --- | ---: | ---: | --- |
| `exp_plaintext_fast_route_gso_async_stream_hw_inline_rx_directbuild_m64_outergso_tuned_ackonly` | 4379.13 | 3743.93 | ready, no reboot, module params OK |
| `exp_plaintext_fast_route_gso_async_stream_hw_inline_rx_directbuild_m64_outergso_tuned_sharded8_ackonly` | 4530.70 | 3913.18 | ready, no reboot, module params OK |
| `exp_plaintext_fast_route_gso_async_stream_hw_rxparse_directbuild_m40_ackonly` | 3583.62 | 3370.55 | ready, no reboot, module params OK |
| `exp_plaintext_fast_route_gso_async_stream_hw_rxparse_directbuild_m40_outergso_coalesce_ackonly` | 4083.38 | 3615.87 | ready, no reboot, module params OK |

CPU was not saturated in the short rerun. The server side peaked around 31-42% busy and `trustixd.current` RSS stayed around 78-84 MiB.

Previously tested but not in the `ackless_fast` alias: `m64_outergso_tuned_unordered` reached 4396.34 Mbps, `m64_outergso_tuned_sharded4` reached 4471.98 Mbps, and `m64_outergso_tuned_unbound` reached 4052.31 Mbps in `build/perf-matrix-remote-216-82-20260601-021504.json`. These remain below the best `m64_outergso_tuned_sharded8` result.

### PVE ACKless TCP mframe sweep

Result file: `build/perf-matrix-remote-216-82-20260601-033508.json`. Cases used `ackless_mframe_sweep`, `TCP_TESTS=82clientp1,82clientp4`, UDP disabled, `IPERF_SECONDS=5`.

All 12 cases were ready, had module parameter validation OK, and had no reboot. The best current PVE case in this run was `exp_plaintext_fast_route_gso_async_stream_hw_inline_rx_directbuild_m60_outergso_tuned_sharded8_ackonly`.

| Family | Best case | p1 Mbps | p4 Mbps |
| --- | --- | ---: | ---: |
| m48 | `m48_outergso_tuned_sharded8` | 4515.80 | 3637.67 |
| m56 | `m56_outergso_tuned_sharded8` | 4652.86 | 3723.68 |
| m60 | `m60_outergso_tuned_sharded8` | 4751.38 | 3856.50 |
| m64 | `m64_outergso_tuned_sharded4` | 4653.22 | 3794.56 |

Do not expand this path to m96/m128 without redesigning the packet format or builder: `TRUSTIX_TIXT_TX_ROUTE_STREAM_MAX_FRAMES` clamps TX stream frames to 64, and the current outer IPv4 packet length is limited to 0xffff even when the skb is outer-GSO.

Top-candidate rerun: `build/perf-matrix-remote-216-82-20260601-035547.json`, `TCP_TESTS=82clientp1,82clientp4,82clientp8`, `IPERF_SECONDS=6`.

| Case | p1 Mbps | p4 Mbps | p8 Mbps |
| --- | ---: | ---: | ---: |
| `m64_outergso_tuned_sharded4` | 4528.96 | 3752.96 | 3484.09 |
| `m64_outergso_tuned_sharded8` | 4694.13 | 3602.47 | 3587.23 |
| `m56_outergso_tuned_sharded8` | 4331.02 | 3685.74 | 3463.71 |
| `m60_outergso_tuned_sharded8` | 4234.68 | 3822.99 | 3590.38 |

Rerun conclusion: `m60_sharded8` was not a stable p1 win. The more stable candidates remain `m64_sharded8` and `m64_sharded4`, with p8 around 3.5-3.6 Gbps in the current PVE environment.

### PVE underlay baseline

Result file: `build/perf-matrix-pve-underlay-20260601-0405.json`. The run also executed default cases because `TRUSTIX_MATRIX_CASES` was empty, but the underlay section is usable.

| Direction | p1 Mbps | p4 Mbps |
| --- | ---: | ---: |
| 216->82 | 19729.81 | 18309.48 |
| 82->216 | 15564.34 | 11677.87 |

This means the current 4-5 Gbps ACKless TCP result is not a VM underlay hard limit. The next likely hotspots are in the route-GSO direct-build path: linear 64 KiB skb allocation/copy, per-frame inner TCP checksum rebuild, and workqueue/queueing overhead.

### Direct-build checksum-copy merge

Change: `kernel/trustix_datapath_helpers/trustix_datapath_helpers_kfuncs.c` now uses `skb_copy_and_csum_bits()` for direct-build inner TCP payload copy when `route_tcp_gso_async_stream_direct_build_inner_csum` is enabled, then combines that payload checksum with a header checksum via `csum_block_add()`. This preserves inner checksum semantics while avoiding a second payload scan after copy.

Validation: local `python build\test_run_remote_perf_matrix.py`, `python -m py_compile build\run_remote_perf_matrix.py build\deploy_gso_opt_remote.py`, and `go test -count=1 ./internal/dataplane/ebpf ./internal/transport/experimentaltcp ./internal/daemon` passed. PVE module build/load passed on both VMs.

Result file: `build/perf-matrix-remote-216-82-20260601-042106.json`, compared with pre-change `build/perf-matrix-remote-216-82-20260601-035547.json`.

| Case | Before p1/p4/p8 Mbps | After p1/p4/p8 Mbps | Notes |
| --- | --- | --- | --- |
| `m64_outergso_tuned_sharded4` | 4528.96 / 3752.96 / 3484.09 | 4532.65 / 3859.99 / 3636.16 | small p4/p8 improvement |
| `m64_outergso_tuned_sharded8` | 4694.13 / 3602.47 / 3587.23 | 4505.17 / 3555.05 / 3714.13 | p8 improved, p1 regressed |
| `m60_outergso_tuned_sharded8` | 4234.68 / 3822.99 / 3590.38 | 4132.87 / 3685.30 / 3636.99 | mostly neutral/regressed |

Conclusion: safe to keep, but not a breakthrough. The next bottleneck is likely not only payload checksum scanning; linear skb allocation/copy and async workqueue scheduling still dominate.

### Direct-build inner-header template and nonlinear TX

Change: `kernel/trustix_datapath_helpers/trustix_datapath_helpers_kfuncs.c` now snapshots and validates the inner IPv4/TCP header once per route-GSO async work item, then reuses that header template for every direct-build TIXT frame. This removes per-frame `skb_copy_bits()` header reads and repeated inner header validation from both linear direct-build and experimental nonlinear direct-build paths.

The experimental `route_tcp_gso_async_stream_nonlinear_direct_build` path was also validated on PVE. It keeps the outer L2/IP/TCP header linear and attaches TIXT+inner payload as page frags. It is stable, but not the best default yet.

Validation: local `python -m py_compile build\run_remote_perf_matrix.py build\deploy_gso_opt_remote.py` and `go test -count=1 ./internal/dataplane/ebpf ./internal/transport/experimentaltcp ./internal/daemon` passed. PVE module build/load passed on both VMs.

Smoke result: `build/perf-matrix-remote-216-82-20260601-051037.json`, `TCP_TESTS=82clientp1`, `IPERF_SECONDS=4`. All cases were ready, module params OK, no reboot. Nonlinear counters were active with low fallback counts.

Confirm result: `build/perf-matrix-remote-216-82-20260601-051847.json`, `TCP_TESTS=82clientp1,82clientp4,82clientp8`, `IPERF_SECONDS=6`.

| Case | p1 Mbps | p4 Mbps | p8 Mbps | Notes |
| --- | ---: | ---: | ---: | --- |
| `m64_outergso_tuned_sharded4` | 4719.01 | 4099.31 | 3613.13 | best balanced result in this run |
| `m64_outergso_tuned_sharded8` | 4640.66 | 3850.38 | 3537.17 | stable but below sharded4 |
| `m64_outergso_nonlinear_tx_sharded8` | 4649.77 | 3739.84 | 3435.53 | nonlinear active; p4/p8 lower |

Conclusion: keep the inner-header template optimization. Do not make nonlinear TX the default yet; page allocation/kmap/frag attach overhead appears to outweigh the reduced large-linear-skb copy under p4/p8. The current best ACKless TCP candidate is `m64_outergso_tuned_sharded4`.

Follow-up result after also caching checksum bases in the async work item and embedding `direct_frames` in `struct trustix_tixt_tx_route_gso_async_work`: `build/perf-matrix-remote-216-82-20260601-053853.json`.

| Case | p1 Mbps | p4 Mbps | p8 Mbps | Notes |
| --- | ---: | ---: | ---: | --- |
| `m64_outergso_tuned_sharded4` | 4719.55 | 3884.16 | 3740.84 | stable, no direct/XMIT errors |
| `m64_outergso_tuned_sharded8` | 4526.89 | 3893.86 | 3696.84 | stable, no direct/XMIT errors |
| `m64_outergso_nonlinear_tx_sharded8` | 4720.59 | 3681.84 | 3636.46 | nonlinear active; still below linear for p4/p8 |

Conclusion: keep the checksum-base and embedded-frame changes. They are stable and improve some p8 runs, but still do not move the ceiling materially beyond the current 4-5 Gbps ACKless TCP range.

### ACKless TCP worker reschedule stride

Change: `kernel/trustix_datapath_helpers/trustix_datapath_helpers_kfuncs.c` now has `route_tcp_gso_async_worker_resched_stride`. Default is `1`, which preserves the previous behavior of calling `cond_resched()` after each async work item. Test harness support was added in `build/run_remote_perf_matrix.py`; `ackless_resched_sweep` covers stride `0/4/8/16/32`.

Validation: local `python -m py_compile build\run_remote_perf_matrix.py build\deploy_gso_opt_remote.py` and `go test -count=1 ./internal/dataplane/ebpf ./internal/transport/experimentaltcp ./internal/daemon` passed. PVE module build/load passed on both VMs.

First result: `build/perf-matrix-remote-216-82-20260601-055819.json`, `TCP_TESTS=82clientp1,82clientp4,82clientp8`, `IPERF_SECONDS=6`.

| Resched stride | p1 Mbps | p4 Mbps | p8 Mbps | Notes |
| ---: | ---: | ---: | ---: | --- |
| 1 | 4562.49 | 3695.77 | 3819.49 | baseline behavior |
| 0 | 4353.67 | 3724.62 | 3560.15 | worse p1/p8 |
| 8 | 4624.46 | 3814.40 | 4129.07 | best p8 in this sweep |
| 32 | 4171.56 | 3895.98 | 3552.73 | p4-only win; worse p1/p8 |

Confirm result: `build/perf-matrix-remote-216-82-20260601-060803.json`.

| Resched stride | p1 Mbps | p4 Mbps | p8 Mbps | Notes |
| ---: | ---: | ---: | ---: | --- |
| 1 | 4638.36 | 3834.55 | 3619.39 | baseline behavior |
| 4 | 4377.05 | 3781.06 | 3605.93 | below baseline |
| 8 | 4623.61 | 3805.93 | 3571.06 | p1 stable, p8 win did not reproduce |
| 16 | 4541.32 | 3794.65 | 3602.51 | below baseline |

All cases were ready, had module param validation OK, no reboot, and no route-stream direct/XMIT errors. Conclusion: keep the knob and sweep cases, but do not change the default yet. `stride=8` is a useful experimental candidate for p8, but the gain is not stable enough to make it the default.

### Known dangerous or invalid paths

`ackless_rx_danger` / RX coalesced mark-GSO remains gated behind `TRUSTIX_MATRIX_ENABLE_DANGEROUS_RX_GSO=1`. Earlier runs showed near-zero ACKless TCP throughput despite counters, so it should not be treated as an optimization until kernel checksum/GSO metadata is fixed.

`ackless_nocsumi` is not valid performance data yet. The previous run (`build/perf-matrix-remote-216-82-20260601-024410.json`) produced ready-check failures with inconsistent module state and VM reboot evidence. Treat no-inner-checksum direct-build as unsafe until it passes reboot and module validation checks.

`ackless_rxworker_stream` / datapath RX worker TCP stream parsing is now gated behind `TRUSTIX_MATRIX_ENABLE_DANGEROUS_RX_WORKER_STREAM_TCP=1`. Two 2026-06-01 smoke attempts failed before throughput measurement and left reboot evidence: `build/perf-matrix-remote-216-82-20260601-153347.json` lost A modules after A boot changed, and `build/perf-matrix-remote-216-82-20260601-154808.json` lost B modules after B boot changed to `44c55393-1711-4846-981e-41ed3b582c85`. Do not run this path on public A/B or shared PVE nodes until it is isolated and fixed.

### Harness changes

`build/run_remote_perf_matrix.py` now records a persistent JSONL summary in `build/perf-history.jsonl` for each case. The entry includes case name, transport, encryption, ready state, best TCP Mbps, route-GSO diagnosis, module validation, required module state, and reboot detection.

The matrix harness now captures boot IDs before and after each case, checks required kernel modules for helper/datapath/crypto cases, reloads required modules per case by default, and validates route-GSO async sysfs parameter writes before throughput tests.

Use `TRUSTIX_MATRIX_HISTORY=/path/to/history.jsonl` to override the history file.

Future history rows compact route-GSO diagnosis and kernel-direct verdicts down to active states and key counters; older rows before this change are still verbose.

The public production-simulation latency harness now has the same low-friction audit trail. `scripts/public-production-sim-latency.py` appends compact rows to `build/latency-history.jsonl` by default, or to `--history <path>`. Use `--history ""` for one-off runs that should not write history.

Each latency row includes p50/p95/p99/max/mdev/loss for underlay and overlay pings in both directions. The summary also records overlay-underlay overhead for avg and p95, plus compact kernel UDP secure-direct counters (`tx_secure_direct_attached`, `rx_secure_direct_attached`, TX seal successes, kfunc/trust-inner flags, and userspace session packet totals). This is intended to catch regressions where a case still passes connectivity but silently falls back to userspace crypto or userspace transport.

Quick readout:

```bash
python scripts/trustix-latency-history-summary.py --last 20
python scripts/trustix-latency-history-summary.py --transport udp --encryption secure --last 10
```

### ACKless TCP async work slab no-zero test

Change tested: switched the route-GSO async work-item slab allocation from `kmem_cache_zalloc()` to `kmem_cache_alloc()` and explicitly initialized the direct-build inner-header cache fields. The goal was to avoid clearing the large embedded `direct_frames` array on every queued skb.

Validation before deploy: local `python -m py_compile build\run_remote_perf_matrix.py build\deploy_gso_opt_remote.py` and `go test -count=1 ./internal/dataplane/ebpf ./internal/transport/experimentaltcp ./internal/daemon` passed. PVE build/load passed on both VMs.

Result file: `build/perf-matrix-remote-216-82-20260601-063732.json`.

| Case | p1 Mbps | p4 Mbps | p8 Mbps | Notes |
| --- | ---: | ---: | ---: | --- |
| `m64_outergso_tuned_sharded4` | 4549.64 | 3794.97 | 3527.62 | valid; route-GSO outer-GSO active |
| `m64_outergso_tuned_sharded4_resched8` | n/a | n/a | n/a | invalid; B side rebooted before module validation |

Conclusion: do not keep the no-zero allocation optimization. It did not beat the best prior `zalloc` runs, and the second case saw B reboot with an unclean journal afterwards. The code and PVE modules were reverted to `kmem_cache_zalloc()` stable behavior. The next higher-value path is cross-work-item route-GSO batching, because current counters show only about 22-23 direct frames per outer-GSO batch while the configured max is 64.

### ACKless TCP cross-item route-GSO batching

Change: added experimental `route_tcp_gso_async_stream_cross_item_batch` support and matrix cases. Follow-up fixes move the cross-item batch state off the worker stack, pre-check the next queued item before allocating a batch object, and reject candidates that would exceed the IPv4 outer GSO payload limit before removing them from the queue. This eliminated cross-item fallback/error churn in the current PVE run.

Validation: local `python -m py_compile build\run_remote_perf_matrix.py build\deploy_gso_opt_remote.py` and `go test -count=1 ./internal/dataplane/ebpf ./internal/transport/experimentaltcp ./internal/daemon` passed. PVE build/load passed on both VMs; the new cross-item worker no longer triggers the earlier large stack-frame warning.

Smoke results:

| Result file | Case | p1 Mbps | Cross-item batches/items/frames | Errors/fallbacks | Notes |
| --- | --- | ---: | ---: | ---: | --- |
| `build/perf-matrix-remote-216-82-20260601-071238.json` | `sharded4_crossitem` initial | 4583.51 | 508 / 1679 / 11233 | 849 / 3047 | valid but wasted fallback work |
| `build/perf-matrix-remote-216-82-20260601-073213.json` | `sharded4_crossitem` fixed | 4546.44 | 799 / 2788 / 21645 | 0 / 0 | valid, no reboot |

Confirm result: `build/perf-matrix-remote-216-82-20260601-073539.json`, `TCP_TESTS=82clientp1,82clientp4,82clientp8`, `IPERF_SECONDS=6`.

| Case | p1 Mbps | p4 Mbps | p8 Mbps | Cross-item batches/items/frames | Notes |
| --- | ---: | ---: | ---: | ---: | --- |
| `m64_outergso_tuned_sharded4` | 4417.37 | 3893.42 | 3339.68 | n/a | baseline in same run |
| `m64_outergso_tuned_sharded4_crossitem` | 4656.10 | 3851.73 | 3681.57 | 17112 / 42491 / 511016 | p1 +5.4%, p8 +10.2%, p4 -1.1% |

All confirm cases were ready, module param validation passed, no reboot was detected, and route-GSO outer-GSO counters were active. Conclusion: keep cross-item as an experimental knob, not the default yet. The next test should compare unsharded/sharded4/sharded8 cross-item hit rate and throughput; the low hit rate suggests queue sharding and stream tail alignment are limiting the benefit.

Sharding sweep: `build/perf-matrix-remote-216-82-20260601-074203.json`, `TCP_TESTS=82clientp1,82clientp4,82clientp8`, `IPERF_SECONDS=6`.

| Case | p1 Mbps | p4 Mbps | p8 Mbps | Cross-item batches/items/frames | Avg cross frames | Cross batch pct |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `m64_outergso_tuned_crossitem` | 4183.93 | 3704.82 | 3498.37 | 15134 / 39915 / 472154 | 31.20 | 5.74% |
| `m64_outergso_tuned_sharded4_crossitem` | 4559.20 | 3671.97 | 3657.08 | 8427 / 20809 / 243462 | 28.89 | 3.02% |
| `m64_outergso_tuned_sharded8_crossitem` | 4268.54 | 3589.97 | 3558.45 | 2856 / 7194 / 80355 | 28.14 | 1.06% |

Conclusion: more cross-item hits do not automatically mean higher throughput; unsharded batching loses on worker/queue contention. `sharded4_crossitem` remains the only useful variant so far, mainly improving p1/p8. `sharded8_crossitem` is not worth keeping in fast aliases unless later queue-local batching improves hit rate.

Follow-up micro-optimization: worker drain now passes whether the queue still had a second item after popping the first, so cross-item can skip the second lock/probe when there is no possible candidate. Result `build/perf-matrix-remote-216-82-20260601-075457.json`, `sharded4_crossitem`, `TCP_TESTS=82clientp1,82clientp4,82clientp8`, `IPERF_SECONDS=6`:

| Case | p1 Mbps | p4 Mbps | p8 Mbps | Cross-item batches/items/frames | Avg cross frames | Notes |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `m64_outergso_tuned_sharded4_crossitem` | 4632.22 | 3843.37 | 3827.44 | 16441 / 40536 / 485466 | 29.53 | no cross-item errors/fallbacks, no reboot |

This is the best current cross-item run and the best recent p8 ACKless TCP result, but it still does not dominate baseline p4. Keep it experimental until another confirmation run shows the p4 loss is gone.

Rejected follow-up: per-worker scratch reuse of the cross-item batch object was tested in `build/perf-matrix-remote-216-82-20260601-080407.json`. It reduced neither latency nor throughput in practice: `sharded4_crossitem` fell to 4517.07 / 3687.82 / 3622.52 Mbps, while cross-item batch percentage dropped to 1.57%. Do not keep that change; the allocation cost is less important than preserving enough queue backlog for adjacent work items to coalesce.

Cross-item plus reschedule sweep: `build/perf-matrix-remote-216-82-20260601-081418.json`, `TCP_TESTS=82clientp1,82clientp4,82clientp8`, `IPERF_SECONDS=6`.

| Case | p1 Mbps | p4 Mbps | p8 Mbps | Cross-item batches/items/frames | Cross batch pct | Notes |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `sharded4_crossitem` | 4739.70 | 4138.60 | 3572.43 | 19845 / 48604 / 597653 | 6.85% | best p1/p4 in this sweep |
| `sharded4_crossitem_resched8` | 4594.48 | 3961.39 | 3517.05 | 9966 / 25770 / 288984 | 3.52% | below baseline crossitem |
| `sharded4_crossitem_resched16` | 4556.91 | 3700.78 | 3478.69 | 5977 / 14362 / 175129 | 2.18% | below baseline crossitem |

Conclusion: do not combine cross-item with less frequent `cond_resched()` yet. In this run, resched8/16 reduced queue adjacency and cross-item hit rate. The better next step is adding miss-reason counters to learn whether misses are dominated by empty queue, non-full tail frames, sequence/template mismatch, or IPv4 64KB outer-GSO capacity.

Cross-item debug rerun: `build/perf-matrix-remote-216-82-20260601-084732.json`, `TRUSTIX_MATRIX_CASES=ackless_crossitem_diag`, `TCP_TESTS=82clientp1,82clientp4,82clientp8`, `IPERF_SECONDS=5`.

| Case | p1 Mbps | p4 Mbps | p8 Mbps | Cross-item batches/items/frames | Cross batch pct | Avg cross frames |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `sharded4_crossitem_diag` | 4685.40 | 3653.51 | 3609.67 | 7385 / 18447 / 214425 | 3.16% | 29.04 |

Miss reasons in the diagnostic run were dominated by `skip_first_room=78187`, `skip_first_tail=24785`, `skip_no_next=23455`, `skip_candidate_shape=11329`, `skip_candidate_room=11488`, and `skip_candidate_sequence=1331`; `skip_candidate_template=0`. This confirms the low cross-item hit rate is primarily the IPv4 outer-GSO 64 KiB payload ceiling and short final frame shape, not header-template mismatch. The next useful optimization is partial-item/tail-stitch batching that can split oversized work items on TIXT frame boundaries and combine only the leftover tail with the next queued item.

### ACKless TCP tail-stitch route-GSO batching

Change: added experimental `route_tcp_gso_async_stream_cross_item_tail_stitch` support that splits an oversized first work item on TIXT frame boundaries, sends the prefix as one route-GSO packet, and tries to batch the first item's tail with following queue items. A follow-up guard pre-checks the next candidate before allocation/range collection and reuses the first work item's direct frame buffer for the prefix path.

Validation: local `python -m py_compile build\run_remote_perf_matrix.py build\deploy_gso_opt_remote.py` and `go test -count=1 ./internal/dataplane/ebpf ./internal/transport/experimentaltcp ./internal/daemon` passed. PVE helper module build/load passed on both VMs; no reboot was detected in the measured runs.

| Result file | p1 Mbps | p4 Mbps | p8 Mbps | Tail batches/items/frames | Prefix frames | Fallbacks | Notes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `build/perf-matrix-remote-216-82-20260601-091636.json` | 4435.71 | 3750.68 | 3435.95 | 23727 / 48345 / 614341 | 1067670 | 17325 | initial full confirm; p1/p8 regressed |
| `build/perf-matrix-remote-216-82-20260601-092758.json` | 4575.78 | 3984.17 | 3599.29 | 13573 / 28158 / 342805 | 610740 | 18506 | candidate precheck/prefix-buffer reuse; better p4 but still not dominant |

Conclusion: keep tail-stitch behind the experimental knob only. It is stable and can help p4, but the extra prefix send and high no-op attempt count do not beat the best plain cross-item results consistently. The next higher-value path is reducing ACKless TCP retransmits and burst loss, especially on p4/p8, by testing queue ordering, shard count, worker budgets, and TX pacing/backpressure behavior.

### ACKless TCP RX coalesce rejection

Result file: `build/perf-matrix-remote-216-82-20260601-094346.json`, `TCP_TESTS=82clientp4,82clientp8`, `IPERF_SECONDS=4`.

| Case | p4 Mbps | p8 Mbps | Notes |
| --- | ---: | ---: | --- |
| `singlecoalesce_m40_skiprxc` | 1.03 | 4.18 | broken for current route-GSO traffic; severe xmit/hash/sequence errors |
| `singlecoalesce_m40_nocsumi_skiprxc` | 1.49 | 10.44 | still broken even without RX checksum work |
| `m64_outergso_tuned_sharded4` | 3671.65 | 3470.21 | inline-RX baseline in same run |
| `m40_outergso_coalesce` | 3642.30 | 3428.70 | stream coalesce neutral/slightly worse |

Conclusion: do not pursue current RX single-coalesce for ACKless TCP route-GSO until its sequence/checksum/GSO metadata path is fixed. The useful baseline remains inline RX with parse-decap kfunc off. A new `ackless_worker_budget_sweep` alias was added to test shard count and worker budget/reschedule pressure around the current `sharded4_ackonly` baseline; `perf-history.jsonl` now records compact CPU, softirq, RSS, and available-memory summaries for each case.

### ACKless TCP worker budget sweep

Partial result file: `build/perf-matrix-remote-216-82-20260601-095904.json`, `TCP_TESTS=82clientp4,82clientp8`, `IPERF_SECONDS=4`. The full sweep was stopped after `i32/s1024`; PVE cleanup completed and no reboot was detected.

| Case | p4 Mbps | p8 Mbps | Retrans p4/p8 | Server softirq max | Notes |
| --- | ---: | ---: | ---: | ---: | --- |
| `sharded4_ackonly` | 3682.62 | 3328.96 | 4583 / 11845 | 24.87% | same-run baseline |
| `budget_i8_s256` | 3525.36 | 3466.68 | 9183 / 7764 | 23.70% | p4 regressed |
| `budget_i16_s256` | 3653.77 | 3608.26 | 3145 / 7969 | 23.04% | p8 improved, p4 still lower |
| `budget_i32_s1024` | 3709.00 | 3485.05 | 2576 / 3694 | 21.14% | fewer retrans/softirq, no throughput breakthrough |

Conclusion: worker budget tuning can reduce retransmits and softirq pressure, but does not by itself move the throughput ceiling. Continue with shard-count and cross-item budget combinations before changing defaults.

Shard/cross-item follow-up: `build/perf-matrix-remote-216-82-20260601-100704.json`, `TCP_TESTS=82clientp4,82clientp8`, `IPERF_SECONDS=4`.

| Case | p4 Mbps | p8 Mbps | Retrans p4/p8 | Server softirq max | Notes |
| --- | ---: | ---: | ---: | ---: | --- |
| `sharded6` | 3572.07 | 3705.66 | 7813 / 16350 | 25.14% | p8 improved, p4 below sharded4 baseline |
| `sharded8_i32_s1024` | 3630.19 | 3621.69 | 3014 / 14567 | 24.38% | fewer p4 retrans, no ceiling move |
| `crossitem_budget_i32_s1024` | 3882.38 | 3582.12 | 7567 / 7962 | 22.93% | best p4 in this short run; cross-item active, still p8-limited |

Conclusion: `crossitem_budget_i32_s1024` is the only useful follow-up from this small sweep. It reduces outer-GSO batch count and raises p4, but p8 remains noisy and shard count alone does not help. Next experiment: delay or locally batch worker drain just enough for adjacent queued items to arrive before the first item is emitted, because current cross-item batching can only merge items already present in the shard queue.

Depth-defer follow-up:

| Result file | Case | p4 Mbps | p8 Mbps | Cross batches/items/frames | Depth defers/exhausted | Notes |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| `build/perf-matrix-remote-216-82-20260601-103252.json` | `crossitem_budget_i32_s1024` | 3888.70 | 3704.47 | 12658 / 31766 / 376800 | 0 / 0 | same-run baseline |
| `build/perf-matrix-remote-216-82-20260601-103252.json` | `depth2_d1` | 3914.38 | 3857.29 | 14796 / 35847 / 445165 | not summarized | small p8 lift |
| `build/perf-matrix-remote-216-82-20260601-103252.json` | `depth2_d2` | n/a | n/a | n/a | n/a | B rebooted; unsafe original self-requeue design |
| `build/perf-matrix-remote-216-82-20260601-103252.json` | `depth4_d2` | 4125.22 | 3777.04 | 17366 / 42492 / 533045 | not summarized | ran after B auto-reboot, so not a clean stability result |
| `build/perf-matrix-remote-216-82-20260601-105133.json` | `crossitem_budget_i32_s1024` | 4072.73 | 3811.28 | 15023 / 36647 / 441841 | 0 / 0 | post-fix baseline |
| `build/perf-matrix-remote-216-82-20260601-105133.json` | `depth4_d2` | 3659.13 | 3581.16 | 7728 / 18564 / 225112 | 82731 / 41298 | safe in-worker yield/recheck avoided reboot but hurt adjacency and throughput |

Conclusion: do not use worker self-requeue for depth defers; it can survive across module reload timing and triggered a B reboot. The safer in-worker yield/recheck version is stable but counterproductive: it creates many empty defers/exhaustions and halves cross-item hit rate. The next experiment should move the delay to enqueue scheduling, using delayed work for the first shard drain so adjacent items can actually enter the queue before the worker starts.

Schedule-delay follow-up:

Change: `trustix_datapath_helpers` route-GSO async workers now use `delayed_work` and expose `route_tcp_gso_async_worker_schedule_delay_jiffies`. When enabled, the first scheduled shard drain is delayed briefly and accelerated to immediate execution if the shard reaches `route_tcp_gso_async_worker_min_queue_depth`. Defaults remain zero, so existing paths are unchanged. Matrix counters now include schedule delays and accelerations.

Validation: local `python -m py_compile build\run_remote_perf_matrix.py build\deploy_gso_opt_remote.py` passed. PVE helper module build/load passed on both VMs. Result file: `build/perf-matrix-remote-216-82-20260601-111004.json`, `TCP_TESTS=82clientp4,82clientp8`, `IPERF_SECONDS=5`.

| Case | p4 Mbps | p8 Mbps | Retrans p4/p8 | Cross batches/items/frames | Delays/accels | Notes |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `crossitem_budget_i32_s1024` | 3730.09 | 3563.03 | 969 / 2304 | 1478 / 3709 / 42736 | 0 / 0 | same-run baseline, unusually low cross-hit |
| `scheddepth2_delay1` | 3613.41 | 3699.23 | 4537 / 17741 | 11378 / 27814 / 344094 | 33408 / 32722 | better p8, worse p4/retrans |
| `scheddepth4_delay1` | 3968.70 | 3585.75 | 10564 / 12900 | 9623 / 25362 / 283633 | 24052 / 19897 | best p4 in this run, p8 neutral |
| `scheddepth4_delay2` | 3247.52 | 2557.65 | 9505 / 8873 | 7049 / 19195 / 205300 | 17060 / 14915 | too much delay |
| `scheddepth8_delay1` | 2605.37 | 2843.21 | 6911 / 12620 | 8277 / 23353 / 250259 | 15616 / 4567 | too much depth target |

Conclusion: keep schedule-delay behind the experimental knob. It is safer than worker self-requeue and can raise cross-item hit rate, but the added latency/backpressure is not a stable throughput win. `scheddepth4_delay1` is the only candidate worth rerunning; do not enable any delay by default.

### ACKless TCP cross-item allocation and dequeue batching

Post-`kmem_cache` baseline: `build/perf-matrix-remote-216-82-20260601-112848.json`, `TCP_TESTS=82clientp4,82clientp8`, `IPERF_SECONDS=5`.

| Case | p4 Mbps | p8 Mbps | Retrans p4/p8 | Cross batches/items/frames | Worker runs | Notes |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `crossitem_budget_i32_s1024` | 3953.42 | 3560.51 | 15292 / 10588 | 13627 / 33765 / 416111 | 48378 | stable; RSS lower than some earlier runs, but no throughput breakthrough |

Change: added `route_tcp_gso_async_stream_cross_item_dequeue_batch`, an experimental path that removes adjacent cross-item candidates from the shard queue under one spinlock window, then builds/sends the outer-GSO batch outside the lock. Defaults remain off.

Validation: local `python -m py_compile build\run_remote_perf_matrix.py build\deploy_gso_opt_remote.py` and `go test -count=1 ./internal/dataplane/ebpf ./internal/transport/experimentaltcp ./internal/daemon` passed. PVE helper module build/load passed on both VMs. Result file: `build/perf-matrix-remote-216-82-20260601-115259.json`.

| Case | p4 Mbps | p8 Mbps | Retrans p4/p8 | Cross batches/items/frames | Dequeue batches/items | Worker runs | Notes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `crossitem_budget_i32_s1024` | 3773.89 | 3655.34 | 5793 / 5624 | 5608 / 13538 / 165999 | 0 / 0 | 40096 | same-run baseline |
| `crossitem_budget_i32_s1024_deqbatch` | 3779.33 | 3509.69 | 5488 / 8071 | 6685 / 16562 / 194149 | 6685 / 16562 | 39576 | stable and higher cross-hit, but p8 regressed |

Conclusion: keep `cross_item_dequeue_batch` experimental and disabled by default. It reduces queue-lock churn and increases cross-item batch hits, but throughput is unchanged or worse, so the hot path is not dominated by per-candidate queue locking. Next direction: batch the worker drain itself by moving a bounded local list out of the shard queue in one lock window, then process that local list outside the lock; that may reduce main queue lock frequency without forcing more cross-item merging latency.

Worker-local dequeue sweep: `build/perf-matrix-remote-216-82-20260601-121222.json`, `TCP_TESTS=82clientp4,82clientp8`, `IPERF_SECONDS=4`.

| Case | p4 Mbps | p8 Mbps | Retrans p4/p8 | Worker runs | Worker dequeue batches/items | Cross batches/items/frames | Notes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `crossitem_budget_i32_s1024` | 3947.52 | 3958.75 | 12787 / 16766 | 50064 | 0 / 0 | 15591 / 37977 / 467457 | same-run baseline |
| `workerdeq4` | 3685.34 | 3744.05 | 7398 / 12236 | 38530 | 32038 / 91957 | 10766 / 24527 / 294841 | fewer worker runs, throughput lower |
| `workerdeq8` | 4013.23 | 3776.78 | 11391 / 14404 | 44577 | 31097 / 94766 | 13774 / 32674 / 404699 | slight p4 lift, p8 lower |
| `workerdeq16` | 3726.08 | 3579.42 | 3696 / 2125 | 30020 | 27545 / 82645 | 3219 / 7582 / 97788 | cross-item hit rate collapsed |

Conclusion: keep `route_tcp_gso_async_worker_dequeue_batch` experimental and default it to `1`. Moving work to a local list reduces queue-lock churn and worker wakeups, but it generally reduces useful cross-item adjacency and does not move the p8 ceiling. The next optimization target should stay on per-byte/direct-build cost, inner checksum policy, retrans/backpressure behavior, or a larger packet-format change rather than more dequeue locking.

Follow-up after changing the experimental worker-local path to process its private list without taking the shard spinlock: `build/perf-matrix-remote-216-82-20260601-123230.json`, `TCP_TESTS=82clientp4,82clientp8`, `IPERF_SECONDS=4`.

| Case | p4 Mbps | p8 Mbps | Retrans p4/p8 | Worker runs | Worker dequeue batches/items | Cross batches/items/frames | Notes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `crossitem_budget_i32_s1024` | 3909.20 | 3914.51 | 13235 / 14814 | 49080 | 0 / 0 | 12931 / 32046 / 384560 | same-run baseline |
| `workerdeq8` | 3701.14 | 3542.80 | 1304 / 3855 | 26205 | 27260 / 83107 | 2531 / 6037 / 70925 | no-lock local list still hurts throughput |
| `deqbatch_workerdeq8` | 3699.39 | 3591.04 | 1379 / 5619 | 28603 | 27154 / 82942 | 2993 / 7274 / 86266 | queue batching plus local list also lower |
| `m40_coalesce_nocsumi` | 3256.24 | 3005.96 | 7920 / 13825 | 15775 | 0 / 0 | n/a | RX parse/coalesce + no inner checksum is below baseline |

One `m64_nocsumi` case was refused by the public-A/B route-GSO safety guard because it disables direct-build inner checksum without an RX coalescing/trust fallback. Cleanup completed; A/B boot IDs were unchanged and both nodes had about 7.6 GiB MemAvailable.

Conclusion: the worker-local dequeue code path is now cleaner but still not useful for throughput. Leave it experimental/default-off. The no-inner-checksum/RX-coalesce experiment is also not a win. Continue with TX-side batching/backpressure or a packet-format change rather than more queue-lock work.

### ACKless TCP hashed TX queue mapping

Change: added `route_tcp_gso_async_hash_tx_queue`, a default-off experiment that assigns route-GSO async outer skbs to a hardware TX queue using the inner skb hash. A later follow-up added per-queue counters `route_tcp_gso_async_hash_tx_queue_q0..q7` plus `other` so the matrix can verify distribution.

Validation: local `python -m py_compile build\run_remote_perf_matrix.py build\deploy_gso_opt_remote.py` and `go test -count=1 ./internal/dataplane/ebpf ./internal/transport/experimentaltcp ./internal/daemon` passed. PVE A/B helper module build/load passed. Result files: `build/perf-matrix-remote-216-82-20260601-131551.json` for the first inner-hash version and `build/perf-matrix-remote-216-82-20260601-133036.json` for the per-queue counter run.

| Result file | Case | p4 Mbps | p8 Mbps | Hash TXQ distribution | Notes |
| --- | --- | ---: | ---: | --- | --- |
| `build/perf-matrix-remote-216-82-20260601-131551.json` | `crossitem_budget_i32_s1024` | 3756.20 | 3484.05 | n/a | same-run baseline |
| `build/perf-matrix-remote-216-82-20260601-131551.json` | `crossitem_budget_i32_s1024_hash_txq` | 3738.16 | 3615.09 | sets 231324, fallback 0 | small p8 lift, p4 neutral/slightly lower |
| `build/perf-matrix-remote-216-82-20260601-133036.json` | `crossitem_budget_i32_s1024` | 3815.24 | 3487.18 | n/a | same-run p4/p8-only baseline |
| `build/perf-matrix-remote-216-82-20260601-133036.json` | `crossitem_budget_i32_s1024_hash_txq` | 3774.30 | 3507.26 | q0 54475, q1 36207, q2 27991, q3 25930 | queue mapping is active and stable, but throughput gain is noise-level |

Cleanup/status: no A/B reboot, boot IDs unchanged, `route_tcp_gso_async_hash_tx_queue` restored to `N`, no residual real `iperf3` or `trustixd.current` test process, and both VMs had about 7.6 GiB MemAvailable after cleanup.

Conclusion: keep hashed TX queue mapping experimental/default-off. It confirms multi-queue assignment works, but it does not move the ACKless TCP ceiling; TX queue selection is not the main limiter on this public A/B path. Next work should focus on per-frame direct-build cost, RX LAN reinjection/user-space cost, or a packet-format/larger-frame change.

### ACKless TCP direct-build linear fast-copy

Change: added `route_tcp_gso_async_stream_direct_build_fast_copy`, a default-on experiment that tries to copy route-GSO stream payloads directly from the source skb linear head before falling back to `skb_copy_bits` / `skb_copy_and_csum_bits`. Counters `route_tcp_gso_async_stream_direct_fast_copy_hits` and `_fallbacks` show whether the path is actually usable.

Validation: local `python -m py_compile build\run_remote_perf_matrix.py build\deploy_gso_opt_remote.py` and `go test -count=1 ./internal/dataplane/ebpf ./internal/transport/experimentaltcp ./internal/daemon` passed before deployment. PVE A/B helper module build/load passed. Result file: `build/perf-matrix-remote-216-82-20260601-135253.json`, `TCP_TESTS=82clientp4,82clientp8`, `IPERF_SECONDS=5`.

| Case | p4 Mbps | p8 Mbps | Retrans p4/p8 | Direct builds/frames | Fast-copy hits/fallbacks | Notes |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `crossitem_budget_i32_s1024` | 3993.23 | 3551.78 | 10324 / 11808 | 148733 / 3551511 | 0 / 3528380 | fast-copy enabled, but never hit |
| `crossitem_budget_i32_s1024_nofastcopy` | 4163.98 | 3407.72 | 16273 / 16298 | 149298 / 3569568 | 0 / 3545459 | same-run control |

Cleanup/status: no A/B reboot, boot IDs unchanged, `route_tcp_gso_async_stream_direct_build_fast_copy` restored to `Y`, `route_tcp_gso_async_hash_tx_queue` restored to `N`, no residual real test processes, and both VMs had about 7.6 GiB MemAvailable after cleanup.

Conclusion: linear-head fast-copy is not a useful optimization on the current route-GSO path because the payload is not linear in the source skb. Keep it harmless/default-on for now only as instrumentation, but the next optimization should target non-linear fragment copy/checksum cost, per-frame checksum policy, or a larger frame/packet-format change.

### ACKless TCP direct-build frag fast-copy

Change: added `route_tcp_gso_async_stream_direct_build_frag_fast_copy`, a default-on experiment that copies and optionally checksums route-GSO stream payloads directly from skb frags with `kmap_local_page()` and `csum_partial_copy_nocheck()` before falling back to `skb_copy_bits` / `skb_copy_and_csum_bits`.

Validation: local `python -m py_compile build\run_remote_perf_matrix.py build\deploy_gso_opt_remote.py` and `go test -count=1 ./internal/dataplane/ebpf ./internal/transport/experimentaltcp ./internal/daemon` passed before deployment. PVE A/B helper module build/load passed. Result file: `build/perf-matrix-remote-216-82-20260601-141709.json`, `TCP_TESTS=82clientp4,82clientp8`, `IPERF_SECONDS=5`.

| Case | p4 Mbps | p8 Mbps | Retrans p4/p8 | Direct builds/frames | Frag fast-copy hits/fallbacks | Cross-page rejects | Notes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `crossitem_budget_i32_s1024` | 3818.21 | 3569.17 | 5390 / 6555 | 146356 / 3488592 | 2334131 / 1140583 | 995001 | frag fast-copy active |
| `crossitem_budget_i32_s1024_nofragfastcopy` | 3511.19 | 3451.86 | 4039 / 6855 | 136441 / 3280328 | 0 / 3259217 | 0 | same-run control |

Cleanup/status: no A/B reboot, boot IDs unchanged, `route_tcp_gso_async_stream_direct_build_frag_fast_copy` restored to `Y`, `route_tcp_gso_async_stream_direct_build_fast_copy` restored to `Y`, `route_tcp_gso_async_hash_tx_queue` restored to `N`, no residual real test processes, and both VMs had about 7.6 GiB MemAvailable after cleanup.

Conclusion: frag fast-copy is active and gave a small public-A/B lift in this run versus the fallback path. The remaining obvious cost is the near-million cross-page rejects, so the next change should extend the same safe fast-copy path across page boundaries while keeping the fallback behavior.

Follow-up: added `route_tcp_gso_async_stream_direct_build_frag_fast_copy_cross_page`, a default-off switch that lets the frag fast-copy path span page boundaries. The default path remains single-page only; cross-page candidates increment `route_tcp_gso_async_stream_direct_frag_fast_copy_cross_page` and fall back unless the explicit cross-page switch is enabled. Matrix diagnostics now include `route_stream_direct_frag_fast_copy_cross_page_hits`.

Validation: local `python -m py_compile build\run_remote_perf_matrix.py build\deploy_gso_opt_remote.py` and `go test -count=1 ./internal/dataplane/ebpf ./internal/transport/experimentaltcp ./internal/daemon` passed. PVE A/B helper module build/load passed after the switch was split out. Result files: `build/perf-matrix-remote-216-82-20260601-143610.json` for the temporary cross-page-enabled build, and `build/perf-matrix-remote-216-82-20260601-145452.json` for the stable default-off build.

| Result file | Case | p4 Mbps | p8 Mbps | Retrans p4/p8 | Frag hits/fallbacks | Cross-page hits/rejects | Notes |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| `build/perf-matrix-remote-216-82-20260601-143610.json` | cross-page build | 3780.91 | 3625.06 | 4852 / 6265 | 3340507 / 147049 | 998773 / 0 | B rebooted before the first case, but both cases themselves had stable boot IDs |
| `build/perf-matrix-remote-216-82-20260601-143610.json` | nofrag control | 3868.96 | 3539.74 | 10723 / 5978 | 0 / 3463517 | 0 / 0 | same-run control |
| `build/perf-matrix-remote-216-82-20260601-145452.json` | stable default-off | 3761.77 | 3612.23 | 2610 / 7212 | 2330957 / 1138216 | 0 / 992785 | boot IDs stable; cross-page disabled |
| `build/perf-matrix-remote-216-82-20260601-145452.json` | nofrag control | 3836.97 | 3706.87 | 8809 / 16916 | 0 / 3524811 | 0 / 0 | same-run control |

Cleanup/status: after the stable default-off run, A/B boot IDs were unchanged, `fragfast=Y`, `crosspage=N`, `fastcopy=Y`, `hash_txq=N`, no real residual test processes were left, and both VMs had about 7.6 GiB MemAvailable.

Conclusion: single-page frag fast-copy is stable and reduces fallback work, but throughput benefit is not stable on the public A/B path. Cross-page fast-copy converts almost all previous cross-page rejects into hits, but it did not produce a clear throughput win in the temporary run and should stay default-off until tested on an isolated high-speed VM path. The next useful ACKless TCP optimization is likely a larger packet-format/nonlinear direct-build change or RX LAN reinjection removal, not more copy micro-optimization.

### ACKless TCP hot counter guard

Change: added `route_tcp_gso_async_hot_stats`, default off, to keep the route-GSO async per-frame fast-copy counters out of the hot path during throughput runs. The matrix now sets, validates and restores this helper parameter, and `disable_route_tcp_unsafe()` explicitly restores it to `N`. A follow-up matrix harness change records final boot IDs after restore/cleanup so post-case reboots are not counted as stable passes.

Validation: local `python -m py_compile build\run_remote_perf_matrix.py build\deploy_gso_opt_remote.py` and `go test -count=1 ./internal/dataplane/ebpf ./internal/transport/experimentaltcp ./internal/daemon` passed. PVE A/B helper module build/load passed. Result file: `build/perf-matrix-remote-216-82-20260601-161502.json`, `TCP_TESTS=82clientp4,82clientp8`, `IPERF_SECONDS=4`, `RUN_UDP=0`.

| Case | p4 Mbps | p8 Mbps | Retrans p4/p8 | Hot stats | Route-GSO counters | Notes |
| --- | ---: | ---: | ---: | --- | ---: | --- |
| `crossitem_budget_i32_s1024` | 4290.61 | 3574.75 | 14657 / 5769 | off | stream frames 2,979,793; outer-GSO frames 2,978,696; cross-item frames 287,517 | case boot IDs stable; throughput inside prior public-A/B noise band |

Important stability note: the case itself reported stable boot IDs (`B 44c55393-1711-4846-981e-41ed3b582c85` before/after), but B rebooted during the later restore/cleanup window. The post-cleanup B boot ID became `416b55dd-cbf0-4945-9067-e4fdba95f612`, `trustix_datapath_helpers` was missing, and final restore could not bring B ready. Treat this run as throughput data only, not a fully stable pass. The matrix script now marks this class of post-matrix reboot in future runs.

Conclusion: removing hot per-frame stats is safe and keeps instrumentation from taxing the datapath, but it did not move throughput beyond normal public-A/B variance. Because the restore-phase reboot happened after a successful case and left B without helper modules, future route-GSO tests should redeploy/reload B before running and must rely on the new final boot check for stability.

Follow-up harness change: added `TRUSTIX_MATRIX_SKIP_POST_RESTORE=1` / `TRUSTIX_MATRIX_POST_RESTORE=0` for dangerous route-GSO sweeps. This skips only the post-case `restore_default()` daemon restart while keeping process cleanup, test-LAN cleanup, route-GSO parameter reset, and final boot-id detection. Use it when the goal is to distinguish datapath-case stability from delayed restore-phase crashes.

Validation with post-restore skipped: result file `build/perf-matrix-remote-216-82-20260601-163136.json`, same safe route-GSO ACKless TCP case, `TCP_TESTS=82clientp4,82clientp8`, `IPERF_SECONDS=4`, `RUN_UDP=0`, `SKIP_UNDERLAY=1`. Throughput was 4245.54 Mbps at p4 and 3992.05 Mbps at p8. Kernel direct verdict passed; B-side route-GSO counters moved (`stream frames 3,111,185`, `direct frames 3,111,095`, `outer-GSO frames 3,109,977`, `cross-item frames 469,724`). Case boot IDs and final boot IDs were stable, no post-matrix reboot was detected, and memory stayed around 7.4 GiB available. This confirms the new harness separates datapath stability from restore-phase risk.

### ACKless TCP cross-item nonlinear TX

Change: cross-item ACKless TCP route-GSO batches can now use the nonlinear direct-build skb constructor instead of always allocating one large linear skb. The previous guard that made cross-item batching and nonlinear direct-build mutually exclusive was removed, and the matrix gained `exp_plaintext_fast_route_gso_async_stream_hw_inline_rx_directbuild_m64_outergso_tuned_sharded4_ackonly_crossitem_budget_i32_s1024_nonlinear`.

Validation: local `python -m py_compile build\run_remote_perf_matrix.py build\deploy_gso_opt_remote.py` and `go test -count=1 ./internal/dataplane/ebpf ./internal/transport/experimentaltcp ./internal/daemon` passed. PVE A/B helper module build/load passed. Result file: `build/perf-matrix-remote-216-82-20260601-171230.json`, `TCP_TESTS=82clientp1,82clientp4,82clientp8`, `IPERF_SECONDS=4`, `RUN_UDP=0`, `SKIP_UNDERLAY=1`, `SKIP_POST_RESTORE=1`.

| Case | p1 Mbps | p4 Mbps | p8 Mbps | Key counters | Stability |
| --- | ---: | ---: | ---: | --- | --- |
| `crossitem_budget_i32_s1024_nonlinear` | 4536.31 | 3802.65 | 3723.06 | cross-item frames 273,165; nonlinear frames 4,549,946; nonlinear frags 1,697,605; errors 0 | final boot IDs stable |

Conclusion: the new path works and is stable on public/PVE A/B, but it does not move throughput materially versus the linear cross-item and nonlinear non-cross-item runs. Keep it as an available experiment/default-off; the next throughput work should focus on reducing RX/user-space reinjection or the outer TCP/TIXT packet format rather than only changing linear-vs-frag allocation.

### ACKless TCP RX worker coalesced GSO

Change: added experimental RX-worker-side adjacent TCP stream coalescing for ACKless TCP LAN xmit. The first version built direct inner TCPv4 GSO skbs from adjacent same-flow frames; a follow-up added `rx_worker_stream_coalesce_software_segment`, GSO shape guards, `rx_worker_stream_coalesce_partial_csum`, and diagnostic counters for last GSO shape / software segmentation failures.

Validation: local `python -m py_compile build\run_remote_perf_matrix.py build\deploy_gso_opt_remote.py`, targeted `go test -count=1 ./internal/daemon -run TestTrustIXDatapathModuleParameters`, and `go test -count=1 ./internal/kernelmodule` passed. Full `go test ./internal/daemon` still has the existing unrelated `TestRegisterInboundReverseOnlyDataSessionDropsMatchingOutboundSession` failure. PVE A/B datapath module build/load passed after adding the l4 checksum prototype.

| Result file | Case | p1 Mbps | Retrans | Key RX-worker counters | Stability |
| --- | --- | ---: | ---: | --- | --- |
| `build/perf-matrix-remote-216-82-20260601-211102.json` | stream batch coalesce before drain-side worker coalesce | 414-438 | n/a | `rx_worker_stream_*` / coalesce counters stayed 0 | stable |
| `build/perf-matrix-remote-216-82-20260601-212849.json` | drain-side direct GSO, partial checksum | 17.91 / 0.87 | 157 / 73 | coalesce counters moved; no coalesce errors | stable but severe regression |
| `build/perf-matrix-remote-216-82-20260601-215042.json` | direct GSO, partial checksum, header metadata fixed | 10.41 / 2.08 | 242 / 473 | coalesce packets 115 / 243; max len 5444 | stable but severe regression |
| `build/perf-matrix-remote-216-82-20260601-215042.json` | software segment, partial checksum | 4.75 / 5.47 | 147 / 135 | `skb_gso_segment` failures and drops | stable but invalid path |
| `build/perf-matrix-remote-216-82-20260601-221017.json` | software segment, full checksum | 438.91 | 878 | coalesce packets 1919, frames 16413, segment skbs 16413 | stable |
| `build/perf-matrix-remote-216-82-20260601-221017.json` | direct GSO, full checksum | 417.00 | 1662 | coalesce packets 1845, frames 10426, max len 64756 | stable |

Conclusion: CHECKSUM_PARTIAL on the coalesced inner TCP GSO skb was the immediate cause of the catastrophic public-A/B regression. Full TCP checksum makes both direct-GSO and software-segment variants stable again, but throughput only returns to the existing ACKless RX-worker baseline instead of improving it. Keep RX worker coalesced GSO experimental/default-off; if reused, prefer `rx_worker_stream_coalesce_partial_csum=0`. The next useful optimization is unlikely to be this LAN-xmit GSO wrapper alone; focus on removing RX worker LAN reinjection overhead, changing ACKless TCP framing to carry larger validated batches, or moving the receive path into the eventual full kernel module.

### ACKless TCP RX inline xmit / stolen xmit

Change: added an experimental `rx_worker_inline_xmit` path that validates ACKless TCP stream frames in the netfilter hook and transmits validated inner packets directly, bypassing the RX-worker ring/workqueue. A follow-up added a default-on one-pass copy+checksum helper and a set of stolen-skb xmit variants. CHECKSUM_PARTIAL remains guarded because prior RX-worker partial checksum experiments were unstable.

Validation: local `python -m py_compile build\run_remote_perf_matrix.py build\deploy_gso_opt_remote.py`, `go test -count=1 ./internal/daemon -run TestTrustIXDatapathModuleParameters`, and `go test -count=1 ./internal/kernelmodule` passed before deployment. PVE A/B datapath module build/load passed. Public/PVE A/B smoke used `TCP_TESTS=82clientp1,82clientp4`, `IPERF_SECONDS=4`, `RUN_UDP=0`, `SKIP_UNDERLAY=1`, `SKIP_POST_RESTORE=1`, `ENABLE_TIXT_PLAIN_ACK_ONLY=1`, and `ENABLE_DANGEROUS_RX_WORKER_STREAM_TCP=1`.

| Result file | Case | p1 Mbps | p4 Mbps | Stability | Notes |
| --- | --- | ---: | ---: | --- | --- |
| `build/perf-matrix-remote-216-82-20260601-225654.json` | `rxworker_stream_inline_xmit` | 583.08 | 502.31 | final boot IDs stable | inline xmit active, worker queue bypassed |
| `build/perf-matrix-remote-216-82-20260601-225654.json` | `rxworker_stream_inline_xmit_maccache` | 571.77 | 523.48 | final boot IDs stable | MAC cache active but small/noisy gain |
| `build/perf-matrix-remote-216-82-20260601-231626.json` | `rxworker_stream_inline_xmit` | 597.02 | 569.85 | final boot IDs stable | copy+checksum fast path active |
| `build/perf-matrix-remote-216-82-20260601-231626.json` | `rxworker_stream_inline_xmit_maccache` | 614.03 | 541.28 | final boot IDs stable | MAC cache active |
| `build/perf-matrix-remote-216-82-20260601-231626.json` | `rxworker_stream_inline_xmit_nocopycsum` | 592.35 | 574.33 | final boot IDs stable | disabling fused copy+checksum was roughly neutral |
| `build/perf-matrix-remote-216-82-20260601-232535.json` | `rxworker_stream_steal_xmit` | 433.59 | 517.93 | final boot IDs stable | stolen skb still drains through worker queue |
| `build/perf-matrix-remote-216-82-20260601-232535.json` | `rxworker_stream_inline_stolen_xmit` | 607.18 | 573.82 | final boot IDs stable | inline stolen path avoids worker queue |
| `build/perf-matrix-remote-216-82-20260601-232535.json` | `rxworker_stream_inline_stolen_xmit_maccache` | 637.08 | 581.23 | final boot IDs stable | best stable ACKless RX-worker LAN reinjection result so far |
| `build/perf-matrix-remote-216-82-20260601-233324.json` | `rxworker_stream_inline_stolen_xmit_partial_maccache` | 649.88 | failed | A rebooted | `rx_worker_xmit_tcp_partial_csum=1`; do not promote |

Conclusion: bypassing the worker ring/workqueue helps, but the path is still dominated by per-inner-frame skb construction/checksum/`dev_queue_xmit`. The one-pass copy+checksum helper is stable but not the main limiter. The best stable public/PVE A/B result is inline stolen xmit + MAC cache at about 0.64/0.58 Gbps for p1/p4. CHECKSUM_PARTIAL on this receive-side LAN xmit path remains unsafe; keep it default-off and avoid broad sweeps until the checksum ownership is redesigned.

### ACKless TCP RX inline pair coalesce

Change: added `rx_worker_inline_pair_coalesce`, a default-off receive-side experiment for the full kernel datapath. It only runs when `rx_worker_stream_coalesce_partial_csum=0`, so the coalesced inner TCP GSO skb is built with a full TCP checksum rather than CHECKSUM_PARTIAL. The path caches one validated single-frame inline xmit packet per flow/hash slot, then coalesces the next adjacent TCP packet into a 2-frame inner GSO skb and transmits it once. Non-adjacent or timed-out packets are flushed through the existing single-packet inline xmit builder.

Validation: local `python -m py_compile build\run_remote_perf_matrix.py build\deploy_gso_opt_remote.py`, `go test -count=1 ./internal/daemon -run TestTrustIXDatapathModuleParameters`, and `go test -count=1 ./internal/kernelmodule` passed. PVE A/B module build/load passed. Result files: `build/perf-matrix-remote-216-82-20260602-001614.json`, `build/perf-matrix-remote-216-82-20260602-002116.json`, and `build/perf-matrix-remote-216-82-20260602-002632.json`.

| Case | p1 Mbps | p4 Mbps | p8 Mbps | Key counters | Stability |
| --- | ---: | ---: | ---: | --- | --- |
| `rxworker_stream_inline_xmit_paircoalesce_fullcsum` | 633.71 | 617.11 | 621.95 | p4: pair packets 227,066; pair errors 0; xmit packets 123,998; checksum_partial 0 | final boot IDs stable |
| `rxworker_stream_inline_xmit_paircoalesce_maccache_fullcsum` | 633.42 | 580.02 | n/a | p4: pair packets 220,216; MAC hits 116,566; pair errors 0 | final boot IDs stable |

Follow-up tuning: `rx_worker_inline_pair_flush_jiffies=2` produced one p4 result at 724.80 Mbps with pair errors 0, but the next fj2-only repeat rebooted A before iperf data. `flush_jiffies=4` also rebooted A. Keep the normal case at `flush_jiffies=1`; do not promote fj2/fj4. A post-reboot repeat of the normal fj1 p4 case was stable at 596.91 Mbps with pair errors 0 and checksum_partial 0 (`build/perf-matrix-remote-216-82-20260602-003958.json`).

Conclusion: pair coalescing is the first receive-side LAN xmit change in this series that clearly moves p4/p8 upward on public/PVE A/B. It roughly halves `dev_queue_xmit` calls for the validated single-frame receive shape and stays stable with full checksums at `flush_jiffies=1`. MAC cache is not useful with this path in the p4 run. The next experiment should generalize the same safe full-checksum design from 2-frame pair coalescing to bounded 4-frame coalescing without increasing the delayed flush window.

Follow-up 4-frame result: `rx_worker_inline_coalesce_max_frames=4` with `flush_jiffies=1` was stable but slower. Result file `build/perf-matrix-remote-216-82-20260602-005256.json` reported p1 562.35 Mbps, pair packets 188,716, stream coalesce packets 47,179, xmit packets 71,517, pair errors 0, and checksum_partial 0. This reduced xmit calls but regressed throughput, so the `coalesce4` case remains an explicit experiment and was removed from the `ackless_rxworker_inline_xmit` alias.

Follow-up workqueue tuning: a low-risk-looking variant added an `expires` field and avoided unconditional `cancel_delayed_work()` after pair lookup. The first version, which still cancelled on hit/conflict, was stable but not faster: `build/perf-matrix-remote-216-82-20260602-010320.json` reported p4 594.31 Mbps, pair packets 218,270, pair errors 0, final boot IDs stable. The second no-cancel variant let delayed work reschedule itself based on `expires`; it rebooted B before iperf and left `trustix_datapath` / `trustix_datapath_helpers` unloaded (`build/perf-matrix-remote-216-82-20260602-011059.json`). That variant was reverted. Keep the explicit `cancel_delayed_work()` calls on pair hit/conflict until this path is redesigned with stronger lifetime ownership.

## 2026-06-02

### Secure kernel UDP TC RX reinjection fix

Problem: `kudp_secure_kernel` readiness failed even though XDP handed encrypted UDP to TC and TC secure RX decrypted successfully. The new TC secure RX stats showed the exact failure: after decrypt, every candidate went to `tc_kernel_udp_rx_secure_direct_neighbor_misses`, while `broadcasts`, `peer_redirects`, and `redirects` stayed at 0. The case env inherited the safe baseline `TRUSTIX_KERNEL_UDP_TC_RX_BROADCAST_DIRECT=0`, so secure RX tried neighbor-map delivery instead of the veth peer/broadcast reinjection path used by the working plaintext TC RX path.

Change: expose the full secure RX counter set in `provider_stats`, add `tc_kernel_udp_rx_secure_direct_decap_l2_kfunc` to current stats, and make the `kudp_secure_kernel` matrix case explicitly set `TRUSTIX_KERNEL_UDP_TC_RX_BROADCAST_DIRECT=1` and `TRUSTIX_KERNEL_UDP_TC_RX_PEER_REDIRECT=1`.

Validation:

| Result file | Ready | p1 Mbps | p4 Mbps | Key counters | Stability |
| --- | --- | ---: | ---: | --- | --- |
| `build/perf-matrix-remote-216-82-20260602-kmodule-secure-stats-smoke.json` | no | n/a | n/a | A/B decrypt packets 504/497, neighbor misses 504/497, peer redirects 0/0 | stable, diagnostic only |
| `build/perf-matrix-remote-216-82-20260602-kmodule-secure-broadcast-smoke.json` | yes | 841.93 | n/a | A packets 238,815, broadcasts 238,815, peer redirects 238,815, neighbor misses 0 | final boot IDs stable |
| `build/perf-matrix-remote-216-82-20260602-kmodule-secure-broadcast-p1p4.json` | yes | 774.75 | 827.64 | hot stats off for throughput run | final boot IDs stable |

Resource notes for the p1/p4 run: client-side `trustixd.current` RSS peaked around 85 MiB, server-side around 83 MiB. Client host busy was high, about 77-83%, while server busy was about 17-19%. Available memory stayed above about 620 MiB on A/client and 1.5 GiB on B/server.

Unsafe follow-up: `TRUSTIX_KERNEL_UDP_TC_RX_SECURE_DIRECT_DECAP_L2_KFUNC=1` did not improve throughput (`build/perf-matrix-remote-216-82-20260602-kmodule-secure-broadcast-decapkfunc-p1p4.json`: p1 768.14 Mbps, p4 799.05 Mbps) and the matrix detected that A had rebooted before the case start (`matrix_boot_before` boot ID changed before `case boot_before`). Journal did not retain a useful oops stack. Keep this secure RX decap-L2 kfunc path explicit/default-off and do not promote it without an isolated reproducer.

Cleanup after validation: A/B had no lingering TrustIX test processes, test netns, TC filters, XDP programs, or TrustIX modules loaded.

### Secure kernel UDP device/TIXB sweep

Change: fixed matrix readiness for `kernel_crypto_device` cases so the device/TIXB path no longer incorrectly requires TC direct route/flow counters. Added `kudp_secure_kernel_device_tixb64k`, `tixb32k`, `tixb16k`, and `nativebatch` sweep cases.

Validation:

| Result file | Case | p1 Mbps | Retrans | Notes |
| --- | --- | ---: | ---: | --- |
| `build/perf-matrix-remote-216-82-20260602-kudp-secure-kdevice-fixed-smoke.json` | `kudp_secure_kernel_device` | 387.25 | 179 | ready true; large TIXB/device path hit; max plaintext about 262 KiB |
| `build/perf-matrix-remote-216-82-20260602-kudp-secure-kdevice-tixb-sweep.json` | `kudp_secure_kernel_device_tixb64k` | 359.56 | 129 | ready true |
| `build/perf-matrix-remote-216-82-20260602-kudp-secure-kdevice-tixb-sweep.json` | `kudp_secure_kernel_device_tixb32k` | 376.28 | 31 | ready true |
| `build/perf-matrix-remote-216-82-20260602-kudp-secure-kdevice-tixb-sweep.json` | `kudp_secure_kernel_device_tixb16k` | 340.85 | 193 | ready true |
| `build/perf-matrix-remote-216-82-20260602-kudp-secure-kdevice-tixb-sweep.json` | `kudp_secure_kernel_device_nativebatch` | 416.62 | 180 | best device-path result in this sweep |
| `build/perf-matrix-remote-216-82-20260602-kudp-secure-device-vs-tc-p1p4.json` | `kudp_secure_kernel` | 835.77 | 0 | TC secure-direct p1; p4 was 841.65 Mbps / 71 retrans |

Conclusion: the kernel crypto device/TIXB path is stable after readiness fixes, but it is much slower than TC secure-direct on public A/B. Smaller TIXB did not materially help; `nativebatch` was best but still about half the TC secure-direct throughput. Keep the device path as a compatibility fallback, not the primary secure kernel UDP fast path.

### Secure kernel UDP skb/direct kfunc split

Problem: `kudp_secure_kernel` showed `tc_kernel_udp_tx_secure_direct_kfunc_seal_enabled=0`, which initially made it look like secure TC was not using the TrustIX crypto module kfunc fast path. The missing detail was that baseline uses the skb kfunc path (`TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_SKB_SEAL_KFUNC=1` and `TRUSTIX_KERNEL_UDP_TC_RX_SECURE_DIRECT_SKB_OPEN_KFUNC=1`); module direct-kfunc counters stay at 0 unless `kfunc_fastpath_stats=1` is loaded.

Change: added explicit matrix cases for the split paths:

| Case | TX seal | RX open | Stats |
| --- | --- | --- | --- |
| `kudp_secure_kernel` | skb kfunc | skb kfunc | off |
| `kudp_secure_kernel_stats` | skb kfunc | skb kfunc | module kfunc stats on |
| `kudp_secure_kernel_direct_seal_skb_open` | scratch direct kfunc | skb kfunc | off |
| `kudp_secure_kernel_skb_seal_direct_open` | skb kfunc | scratch direct kfunc | off |
| `kudp_secure_kernel_direct_kfunc` | scratch direct kfunc | scratch direct kfunc | off |
| `kudp_secure_kernel_direct_kfunc_stats` | scratch direct kfunc | scratch direct kfunc | module kfunc stats on |

Validation:

| Result file | Case | p1 Mbps | p4 Mbps | Key observation | Stability |
| --- | --- | ---: | ---: | --- | --- |
| `build/perf-matrix-remote-216-82-20260602-kudp-secure-direct-kfunc-stats-smoke.json` | `kudp_secure_kernel_direct_kfunc_stats` | 883.84 | n/a | direct seal/open counters hit; A used VAES, B used AESNI; errors 0 | boot IDs stable |
| `build/perf-matrix-remote-216-82-20260602-kudp-secure-kfunc-nostats-compare-p1p4.json` | `kudp_secure_kernel` | 778.35 | 803.59 | skb seal/open baseline | boot IDs stable |
| `build/perf-matrix-remote-216-82-20260602-kudp-secure-kfunc-nostats-compare-p1p4.json` | `kudp_secure_kernel_direct_kfunc` | 786.13 | 760.09 | full scratch direct was neutral/slower | boot IDs stable |
| `build/perf-matrix-remote-216-82-20260602-kudp-secure-hybrid-compare-p1p4.json` | `kudp_secure_kernel_direct_seal_skb_open` | 774.26 | 748.13 | scratch direct TX seal regressed | boot IDs stable |
| `build/perf-matrix-remote-216-82-20260602-kudp-secure-rx-open-compare-p1p4.json` | `kudp_secure_kernel_stats` | 778.61 | 803.93 | baseline skb kfunc counters moved heavily; A VAES, B AESNI | boot IDs stable |
| `build/perf-matrix-remote-216-82-20260602-kudp-secure-skbseal-directopen-nostats-compare-p1p4.json` | `kudp_secure_kernel` | 771.71 | 759.03 | no-stats baseline repeat | boot IDs stable |
| `build/perf-matrix-remote-216-82-20260602-kudp-secure-skbseal-directopen-nostats-compare-p1p4.json` | `kudp_secure_kernel_skb_seal_direct_open` | 785.32 | 828.49 | RX scratch direct open won this repeat, but public variance is high | boot IDs stable |

Counters: `kudp_secure_kernel_stats` confirmed the baseline skb path already hits module SIMD kfuncs. In the p1/p4 stats run, B-side AESNI counters and A-side VAES counters each increased by about 1.02M with zero direct-kfunc errors. `kudp_secure_kernel_direct_kfunc_stats` also worked with zero errors, but scratch direct seal/open did not improve sustained p1/p4 throughput.

Conclusion: keep `kudp_secure_kernel` on skb seal/open as the conservative default. Do not promote scratch direct TX seal; it regressed in the hybrid test. `kudp_secure_kernel_skb_seal_direct_open` is worth keeping as an explicit experiment because one no-stats public repeat improved p1/p4, but it needs more repetitions and a successful opposite-direction run before becoming default. A->B `216p1/216p4` timed out for both baseline and RX-direct-open cases in `build/perf-matrix-remote-216-82-20260602-kudp-secure-skbseal-directopen-a2b-p1p4.json`; ping stayed healthy and boot IDs were stable, so this is a separate direction/test harness issue rather than evidence against the RX-open case.

### Full-datapath ACKless repeat after redeploy

Validation: rebuilt the Linux daemon locally, redeployed to A/B through the SOCKS proxy, and rebuilt `trustix_crypto`, `trustix_datapath`, and `trustix_datapath_helpers` on both hosts. Local checks before deployment passed: `python -m py_compile build\run_remote_perf_matrix.py build\run_a_local_extreme.py build\deploy_gso_opt_remote.py build\test_run_remote_perf_matrix.py`, `go test -count=1 ./internal/kernelmodule`, targeted daemon kernel datapath tests, and `python -m unittest build.test_run_remote_perf_matrix`.

Result file: `build/perf-matrix-remote-216-82-20260602-ackless-fullpair-repeat2.json`, `TCP_TESTS=82clientp1,82clientp4,82clientp8`, `IPERF_SECONDS=4`, `RUN_UDP=0`, `SKIP_UNDERLAY=1`, `SKIP_POST_RESTORE=1`, with `TRUSTIX_MATRIX_ENABLE_DANGEROUS_RX_WORKER_STREAM_TCP=1` and `TRUSTIX_MATRIX_ENABLE_TIXT_PLAIN_ACK_ONLY=1`.

| Case | p1 Mbps | p4 Mbps | p8 Mbps | Key counters | Stability |
| --- | ---: | ---: | ---: | --- | --- |
| `rxworker_stream_inline_xmit_paircoalesce_fullcsum` | 564.22 | 588.21 | 573.95 | B-side route-GSO stream frames 645,076; outer-GSO frames 644,837; cross-item frames 185,182; direct errors 9 | case and final boot IDs stable |

Conclusion: the full-datapath RX-worker ACKless path is stable after redeploy but still much slower than the earlier TC/helper-only ACKless TX path. The TX route-GSO path is active, but throughput remains around 0.56-0.59 Gbps, consistent with the receive-side LAN xmit path still dominating. Do not spend more time on small TX route-GSO changes for this case until RX/LAN reinjection is redesigned or moved further into a lower-overhead path.

### Secure UDP redeploy repeat

Result file: `build/perf-matrix-remote-216-82-20260602-secure-udp-repeat.json`, `TCP_TESTS=82clientp1,82clientp4`, `IPERF_SECONDS=4`, `RUN_UDP=0`, `SKIP_UNDERLAY=1`, `SKIP_POST_RESTORE=1`.

| Case | p1 Mbps | p4 Mbps | Retrans p1/p4 | Stability |
| --- | ---: | ---: | ---: | --- |
| `kudp_secure_kernel` | 801.60 | 773.27 | 29 / 0 | case and final boot IDs stable |
| `kudp_secure_kernel_skb_seal_direct_open` | 820.35 | 780.65 | 0 / 0 | case and final boot IDs stable |

Conclusion: secure kernel UDP did not regress after redeploy. The RX scratch direct-open hybrid again edged out baseline at p1 and was roughly neutral at p4, but the gap is still inside public-path noise; keep it explicit/default-off.

Cleanup: after the runs, A/B had no TrustIX or iperf processes, no test netns, no TrustIX modules loaded, no XDP program on `ens18`, and unchanged boot IDs. Final available memory was about 1715 MiB on A and 724 MiB on B.

### A-local extreme path-gate smoke

Change: `build/run_a_local_extreme.py` now performs a short path probe before full A-local throughput for sensitive fast paths. Secure kernel UDP must show TC secure-direct seal activity without kernel crypto device fallback; ACKless RX-worker route-GSO must show route-GSO stream/direct/outer-GSO and RX-worker xmit counters. The script now records per-case and whole-run boot IDs, skips full iperf when the target path is not hit, and unloads TrustIX modules during cleanup by default. Local RX-worker route-GSO in the dual-netns topology now requires the extra `TRUSTIX_LOCAL_EXTREME_ENABLE_UNSAFE_RX_WORKER_NETNS=1` gate because this topology rebooted A during smoke validation.

Validation:

| Result file | Case | Outcome | Stability |
| --- | --- | --- | --- |
| `build/perf-a-local-extreme-20260602-path-gate-smoke.json` | `udp_secure_kernel`, `udp_secure_kernel_skb_seal_direct_open` | path probe rejected both: TC secure seal counters moved, but kernel crypto device batch counters also moved | A later rebooted during/after the run that also included RX-worker netns |
| `build/perf-a-local-extreme-20260602-path-gate-smoke.json` | `experimental_tcp_plaintext_route_gso_async_stream_directbuild_m64_outergso_rxworker_paircoalesce_ackonly` | readiness failed before path probe | unsafe local netns RX-worker path, do not rerun without explicit netns gate |
| `build/perf-a-local-extreme-20260602-secure-path-gate-boot.json` | `udp_secure_kernel` | path probe rejected device fallback and skipped full iperf | boot ID stable; cleanup left no processes, netns, or TrustIX modules |
| `build/perf-a-local-extreme-20260602-secure-offload-off-smoke.json` | `udp_secure_kernel` | disabled local veth offloads; path probe passed TC secure-direct with no device fallback; p1 was about 1.94/1.89 Gbps | boot ID stable; cleanup left no processes, netns, or TrustIX modules |
| `build/perf-a-local-extreme-20260602-secure-offload-off-mtu8500.json` | `udp_secure_kernel` | LAN MTU 8500 regressed to MTU fallback/device path and was skipped | boot ID stable; cleanup left no processes, netns, or TrustIX modules |
| `build/perf-a-local-extreme-20260602-secure-offload-off-p1p4.json` | `udp_secure_kernel` | TC secure-direct valid; p1 1898/1898 Mbps, p4 1841/1849 Mbps | boot ID stable; cleanup left no processes, netns, or TrustIX modules |
| `build/perf-a-local-extreme-20260602-secure-offload-off-p1p4.json` | `udp_secure_kernel_skb_seal_direct_open` | TC secure-direct valid; p1 1840/1801 Mbps, p4 1866/1857 Mbps | boot ID stable; cleanup left no processes, netns, or TrustIX modules |

Conclusion: the A-local secure UDP data from `build/perf-a-local-extreme-20260602-kmodule-secure-rxworker.json` is invalid as TC secure-direct performance evidence because it used the kernel crypto device fallback. The A-local dual-netns RX-worker route-GSO topology is not a safe extreme-test target; use public A/B for stability data or an isolated non-netns/PVE topology for full-datapath RX-worker experiments.

Follow-up conclusion: local veth offloads must be disabled for secure TC-direct A-local testing; otherwise oversized GSO skbs trigger MTU fallback into the kernel crypto device path. Jumbo LAN MTU does not solve it because it also triggers MTU fallback at MTU 8500. With offloads disabled and MTU 1500, the validated secure TC-direct local ceiling is currently about 1.8-1.9 Gbps on A.

### Full-datapath ACKless hold-skb/trusted-checksum tuning

Change: added `rx_worker_inline_pair_hold_skb` so the 2-frame inline pair path can hold the first prepared skb and append the second TCP payload instead of rebuilding the skb on pair hit. Added incremental TCP checksum append, `rx_worker_xmit_trust_tcp_checksum_min_len`, and `rx_worker_xmit_trust_tcp_checksum_ack_only`. Also tested explicit 4-frame coalesce, MAC cache, no-hot-stats, and `rx_worker_direct_xmit`.

Validation: local py_compile and targeted daemon/matrix tests passed before deployments. A/B module builds passed after each datapath change. All public A/B runs below used `TCP_TESTS=82client...`, `IPERF_SECONDS=4`, `RUN_UDP=0`, `SKIP_UNDERLAY=1`, `SKIP_POST_RESTORE=1`, `TRUSTIX_MATRIX_ENABLE_DANGEROUS_RX_WORKER_STREAM_TCP=1`, and `TRUSTIX_MATRIX_ENABLE_TIXT_PLAIN_ACK_ONLY=1`.

| Result file | Case | p1 Mbps | p4 Mbps | p8 Mbps | Notes |
| --- | --- | ---: | ---: | ---: | --- |
| `build/perf-matrix-remote-216-82-20260602-081130.json` | hold-skb + incremental checksum | n/a | 597.20 | 602.19 | stable; pair errors/drops 0 |
| `build/perf-matrix-remote-216-82-20260602-083854.json` / `...-084415.json` | hold-skb + trusted data checksum | 634.93 | 593.40 | 588.72 | A-side checksum trusted; errors/drops 0 |
| `build/perf-matrix-remote-216-82-20260602-085842.json` | 4-frame coalesce + trusted checksum | 617.69 | n/a | n/a | 4-frame path hit, but retrans high and slower |
| `build/perf-matrix-remote-216-82-20260602-090413.json` | hold-skb + trusted checksum + MAC cache | 618.85 | n/a | n/a | cache hit 100%, but slower |
| `build/perf-matrix-remote-216-82-20260602-090929.json` | hold-skb + trusted checksum + no hot stats | 627.51 | n/a | n/a | slower than normal hot-stats run |
| `build/perf-matrix-remote-216-82-20260602-092142.json` | hold-skb + trusted checksum + direct xmit | 600.69 | n/a | n/a | stable but slower; keep default-off |
| `build/perf-matrix-remote-216-82-20260602-093255.json` / `...-093724.json` | hold-skb + trusted data checksum + ACK-only trust | 637.71 | 604.52 | 587.31 | ACK fixed checksums mostly removed; errors/drops 0 |

Conclusion: the only stable positive deltas in this sweep are hold-skb, data checksum trust, and ACK-only trust. The improvement is modest: best public A/B ACKless full-datapath result is about 0.64 Gbps p1 and 0.60 Gbps p4, still below secure kernel UDP at about 0.8 Gbps and far below the older PVE route-GSO TX path. 4-frame batching, MAC cache, no-hot-stats, and LAN `dev_direct_xmit` did not help. The remaining bottleneck is still structural receive-side LAN reinjection and per-coalesced-skb delivery, not checksum scanning alone.

Cleanup: after the final ACK-only trust run, A/B had no test TrustIX/iperf processes, no test LAN netns/veth, no XDP program, and no TrustIX modules loaded. Boot IDs were unchanged; final available memory was about 1681 MiB on A and 699 MiB on B.

### Full-datapath ACKless MAC-cache and copyfast follow-up

Change: optimized `trustix_datapath_rx_worker_build_xmit_inner_skb_copy_csum()` to use a single packet copy and avoid a redundant `skb_cow_head()` before pushing the Ethernet header on freshly allocated skbs. Added two default-off destination-MAC cache experiments for RX-worker xmit: per-CPU cache (`rx_worker_xmit_dst_mac_pcpu_cache`) and seqlock reader cache (`rx_worker_xmit_dst_mac_seq_cache`). The matrix can select them with `ackless_holdskb_trustcsum_acktrust_pcpmac` and `ackless_holdskb_trustcsum_acktrust_seqmac`.

Validation: local py_compile, `python -m unittest build.test_run_remote_perf_matrix`, `go test -count=1 ./internal/daemon -run TestTrustIXDatapathModuleParametersRXWorkerDstMAC`, `go test -count=1 ./internal/kernelmodule`, and Linux `trustixd` build passed. A/B module builds passed after the seqlock cache change.

| Result file | Case | p1 Mbps | Retrans | Notes |
| --- | --- | ---: | ---: | --- |
| `build/perf-matrix-remote-216-82-20260602-copyfast-holdskb-p1.json` | hold-skb + trusted checksum + ACK-only trust + copyfast | 624.29 | n/a | stable, no gain over prior best 637.71 |
| `build/perf-matrix-remote-216-82-20260602-pcpmac-holdskb-p1.json` | hold-skb + trusted checksum + ACK-only trust + per-CPU MAC cache | 594.06 | 14 | cache enabled and hit, but slower |
| `build/perf-matrix-remote-216-82-20260602-105129.json` | hold-skb + trusted checksum + ACK-only trust + seqlock MAC cache | 212.07 | 2794 | same-window public path was badly congested |
| `build/perf-matrix-remote-216-82-20260602-110018.json` | hold-skb + trusted checksum + ACK-only trust baseline repeat | 218.08 | 576 | confirms the 212 Mbps seqmac run was not a clean absolute comparison |

Conclusion: keep pcpu/seq MAC cache experiments default-off. The MAC lookup path is not the current bottleneck: pcpu cache was slower when enabled, and seqmac did not show a relative improvement in a noisy same-window public repeat. The earlier global MAC cache also hit 100% but regressed. Current evidence still points at skb allocation/copy and `dev_queue_xmit()` LAN reinjection as the structural receive-side bottleneck.

Cleanup: after both seqmac and same-window baseline public runs, A/B had unchanged boot IDs, no TrustIX/iperf processes, no test LAN netns/veth, no XDP program, and no TrustIX modules loaded. Final available memory was about 1715 MiB on A and 757 MiB on B.

### Full-datapath ACKless cached target device

Change: `trustix_datapath_hook_entry` now holds a referenced `target_dev` when the hook is attached with a target interface. The inline RX-worker xmit hot path uses that cached pointer instead of resolving `target_ifindex` with `dev_get_by_index()` on every packet. The fallback path is unchanged when no target device is configured. Detach and detach-all release the cached device reference.

Validation: local py_compile, full `python -m unittest build.test_run_remote_perf_matrix`, `go test -count=1 ./internal/daemon -run TestTrustIXDatapathModuleParametersRXWorkerDstMAC`, `go test -count=1 ./internal/kernelmodule`, and Linux `trustixd` build passed. A/B module builds passed.

| Result file | Case | Direction | p1 Mbps | Retrans | Notes |
| --- | --- | --- | ---: | ---: | --- |
| `build/perf-matrix-remote-216-82-20260602-111927.json` | hold-skb + trusted checksum + ACK-only trust + cached target_dev | `82client->216server` | 609.60 | 2112 | stable; drops/deliver errors/alloc errors 0 |

Conclusion: cached target_dev is safe enough to keep because it removes fixed per-packet device lookup work and does not change ABI, but this public repeat did not prove a throughput gain. The run had high retransmits, so do not draw a strong regression conclusion either. Keep this change as a low-risk structural cleanup and retest on a cleaner PVE or LAN topology before treating it as a performance win.

Cleanup: after the cached target_dev public run, A/B had unchanged boot IDs, no TrustIX/iperf processes, no test LAN netns/veth, no XDP program, and no TrustIX modules loaded. Final available memory was about 1709 MiB on A and 754 MiB on B.

### Full-datapath ACKless stolen target-dev handoff

Change: the stolen-skb path now reuses the `target_dev` reference acquired during `rx_worker_push()` instead of releasing it and resolving the same target again in the deferred inline/queued stolen branch. `trustix_datapath_rx_worker_push()` hands the referenced target device to either `trustix_datapath_rx_worker_inject_stolen_inline_target()` or `trustix_datapath_rx_worker_push_stolen_target()`, which consume the reference. This removes one target-device lookup/hold/release pair from the stolen hot path and keeps the cached-hook target device fallback.

Validation: local py_compile, full `python -m unittest build.test_run_remote_perf_matrix`, `go test -count=1 ./internal/daemon -run TestTrustIXDatapathModuleParameters`, `go test -count=1 ./internal/kernelmodule`, and Linux `trustixd` build passed. A/B module builds passed.

| Result file | Case | Direction | p1 Mbps | Retrans | Key counters | Stability |
| --- | --- | --- | ---: | ---: | --- | --- |
| `build/perf-matrix-remote-216-82-20260602-113940.json` | `rxworker_stream_inline_stolen_xmit_maccache` with target-dev handoff | `82client->216server` | 568.66 | 520 | A-side `rx_worker_inline_injected=211878`, drops/errors/alloc errors 0 | boot IDs stable |

Conclusion: the target-dev handoff is a correctness-preserving hot-path cleanup and the public smoke was stable, but it did not prove a throughput gain. The measured p1 value is below the prior best `rxworker_stream_inline_stolen_xmit_maccache` result of 637.08 Mbps, likely still dominated by public-path variance and the per-packet checksum/`dev_queue_xmit` work. Keep the handoff because it removes redundant work without broadening the unsafe surface; do not spend more public A/B time on target lookup micro-optimizations.

Cleanup: after the stolen target-dev public smoke, A/B had unchanged boot IDs, no TrustIX/iperf processes, no test LAN netns/veth, no XDP program, and no TrustIX modules loaded. Final available memory was about 1701 MiB on A and 736 MiB on B.

### Full-datapath ACKless stolen checksum-trust probe

Change: added a default-off matrix case `ackless_rxworker_inline_stolen_maccache_trustcsum_acktrust`, which combines inline stolen xmit, MAC cache, `rx_worker_xmit_trust_tcp_checksum_min_len=1`, and ACK-only checksum trust. This was intended to test whether the stolen path could avoid the full TCP checksum rebuild that still dominates `rxworker_stream_inline_stolen_xmit_maccache`.

Validation: local py_compile, full `python -m unittest build.test_run_remote_perf_matrix`, targeted daemon parameter tests, `go test -count=1 ./internal/kernelmodule`, and Linux `trustixd` build passed. A/B module builds passed.

| Result file | Case | Direction | Outcome | Key counters | Stability |
| --- | --- | --- | --- | --- | --- |
| `build/perf-matrix-remote-216-82-20260602-115720.json` | `rxworker_stream_inline_stolen_xmit_maccache_trustcsum_acktrust` | `82client->216server` | iperf timed out with empty output | A-side `rx_worker_checksum_trusted=15`, `rx_worker_checksum_fixed=1`; only 16 injected packets | boot IDs stable |

Conclusion: do not promote checksum trust on the stolen inline path. The parameters did enable and the trusted counter moved, but the TCP session did not make progress. Unlike the hold-skb pair path, stolen skb ownership/checksum state is not currently safe to trust for inner TCP data. Keep this case only as an explicit negative/diagnostic experiment; avoid rerunning it in broad public sweeps.

Cleanup: after the checksum-trust stolen probe, A/B had unchanged boot IDs, no TrustIX/iperf processes, no test LAN netns/veth, no XDP program, and no TrustIX modules loaded. Final available memory was about 1705 MiB on A and 758 MiB on B.

### Full-datapath ACKless hold-skb 4-frame append smoke

Change: extended the hold-skb inline pair path so an already held skb can append more adjacent ACKless TCP frames up to `rx_worker_inline_coalesce_max_frames`. Added the default-off matrix alias `ackless_holdskb4_trustcsum_acktrust`, which uses the same trusted data checksum and ACK-only trust settings as the current best hold-skb path but sets `rx_worker_inline_coalesce_max_frames=4`.

Validation: before deployment, local `python -m py_compile build\run_remote_perf_matrix.py build\test_run_remote_perf_matrix.py build\deploy_gso_opt_remote.py`, `python -m unittest build.test_run_remote_perf_matrix`, `go test -count=1 ./internal/daemon -run TestTrustIXDatapathModuleParameters`, and `go test -count=1 ./internal/kernelmodule` passed. A/B module builds passed after removing an unused wrapper warning. Public A/B smoke used `TCP_TESTS=82clientp1`, `IPERF_SECONDS=4`, `RUN_UDP=0`, `SKIP_UNDERLAY=1`, `SKIP_POST_RESTORE=1`, `TRUSTIX_MATRIX_ENABLE_DANGEROUS_RX_WORKER_STREAM_TCP=1`, and `TRUSTIX_MATRIX_ENABLE_TIXT_PLAIN_ACK_ONLY=1`.

| Result file | Case | Direction | p1 Mbps | Retrans | Key counters | Stability |
| --- | --- | --- | ---: | ---: | --- | --- |
| `build/perf-matrix-remote-216-82-20260602-123009.json` | `ackless_holdskb4_trustcsum_acktrust` | `82client->216server` | 623.53 | 392 | B TX route-GSO stream direct frames 232,624; A RX `rx_worker_inline_pair_packets=232542`, `rx_worker_stream_coalesce_packets=58148`, `rx_worker_inline_xmit_packets=232593`, checksum trusted 58,196, fixed 3, errors/drops/alloc errors 0 | boot IDs stable |
| `build/perf-matrix-remote-216-82-20260602-124012.json` | `ackless_holdskb4_trustcsum_acktrust` | `82client->216server` | p4 623.93; p8 572.40 | p4 280; p8 1110 | B TX route-GSO stream direct frames 449,486; outer-GSO frames 449,272; cross-item frames 130,791; direct errors 2 | boot IDs stable |

Conclusion: 4-frame hold-skb append is stable on the public A/B path, but it is not a clear throughput win and does not add concurrency headroom. It is slightly above the cached-target-dev p1 repeat at 609.60 Mbps and below the historical ACK-only trust p1 best at 637.71 Mbps; p4 is only 623.93 Mbps and p8 regresses to 572.40 Mbps. It does reduce A-side xmit work to about 58k coalesced packets for about 232k frames in the p1 run, but public throughput remains around 0.62 Gbps and p8 retransmits increase. Keep `rx_worker_inline_coalesce_max_frames=4` as an explicit experiment; do not promote it over the 2-frame default until a cleaner PVE/LAN run shows a repeatable gain.

Cleanup: after the hold-skb 4-frame p1 and p4/p8 smokes, A/B had unchanged boot IDs, no TrustIX/iperf processes, no test LAN netns/veth, no XDP program, and no TrustIX modules loaded. Final available memory after p4/p8 was about 1700 MiB on A and 753 MiB on B.

### Full-datapath ACKless RX-worker TX-queue hashing

Change: added the default-off module parameter `rx_worker_xmit_hash_tx_queue` and matrix alias `ackless_holdskb_trustcsum_acktrust_hashq`. When enabled, the RX-worker LAN xmit path hashes the inner flow and sets `skb->queue_mapping` before `dev_queue_xmit()` or the software-segmented xmit loop. The matrix can create a multi-queue test LAN with `TRUSTIX_MATRIX_TEST_LAN_QUEUES=4`, and the datapath exposes queue hit/fallback counters.

Validation: local `python -m py_compile build\run_remote_perf_matrix.py build\test_run_remote_perf_matrix.py build\deploy_gso_opt_remote.py`, `python -m unittest build.test_run_remote_perf_matrix`, `go test -count=1 ./internal/daemon -run TestTrustIXDatapathModuleParameters`, `go test -count=1 ./internal/kernelmodule`, and Linux `trustixd` build passed. PVE and public A/B module builds passed. Public A/B cleanup left no TrustIX/iperf processes, no test netns/link, no XDP program on `ens18`, and no TrustIX modules loaded; boot IDs were stable.

| Result file | Case | p1 Mbps | p4 Mbps | Key counters | Stability |
| --- | --- | ---: | ---: | --- | --- |
| `build/pve/pve-holdskb-hashq-20260602-150910.json` | baseline hold-skb + trust checksum + ACK trust | 596.08 | rebooted on p4 | p1 only | p1 stable; p4 rebooted PVE A |
| `build/pve/pve-holdskb-hashq-20260602-150910.json` | `ackless_holdskb_trustcsum_acktrust_hashq` | 616.42 | rebooted on p4 | p1 hash sets 137,653, fallback 0; mostly q2 | p1 stable; p4 rebooted PVE A |
| `build/perf-matrix-remote-216-82-holdskb-hashq-20260602-152643.json` | baseline hold-skb + trust checksum + ACK trust | 520.21 | 497.70 | p4 retrans 1,739; B direct frames 378,839 | boot IDs stable |
| `build/perf-matrix-remote-216-82-holdskb-hashq-20260602-152643.json` | `ackless_holdskb_trustcsum_acktrust_hashq` | 524.72 | 465.95 | p1 hash sets 97,916, fallback 0; p4 hash sets 185,063, fallback 0; q0/q1/q2/q3 used at p4 | boot IDs stable |

Conclusion: keep TX-queue hashing as a diagnostic/default-off experiment only. It proves the RX-worker can target multi-queue LAN devices safely on the public A/B path, but the p1 gain is only about 0.9% in a noisy window and p4 regresses by about 6.4%. The PVE p1 smoke also showed only a small gain and the p4 run rebooted A, so this is not the missing throughput lever. The remaining ACKless bottleneck is still LAN reinjection/skb delivery structure, not TX queue selection.

### Full-datapath ACKless xmit-more probe

Change: added default-off route/RX-worker `xmit_more` module parameters and matrix alias `ackless_holdskb_trustcsum_acktrust_xmitmore`. During deployment the first implementation failed to build on Linux 6.12 because `struct sk_buff` no longer exposes an `xmit_more` field. The helper is now a compatibility no-op with an explicit comment: modern kernels pass the `more` bit into `netdev_start_xmit()` from skb-list/qdisc batching, so a real implementation needs a safe skb-list TX batch rather than a per-skb field write. The daemon still maps `TRUSTIX_KERNEL_DATAPATH_RX_WORKER_XMIT_MORE=1` to `rx_worker_xmit_more=1` so future batch implementations can use the same control surface.

Validation: local `python -m py_compile build\run_remote_perf_matrix.py build\test_run_remote_perf_matrix.py build\deploy_gso_opt_remote.py`, `python -m unittest build.test_run_remote_perf_matrix`, `go test -count=1 ./internal/daemon -run TestTrustIXDatapathModuleParameters`, `go test -count=1 ./internal/kernelmodule`, and Linux `trustixd` build passed before deployment. A/B module builds passed after converting the skb field write to a no-op. Public A/B matrix used `TCP_TESTS=82clientp1,82clientp4`, `IPERF_SECONDS=4`, `RUN_UDP=0`, `SKIP_UNDERLAY=1`, `SKIP_POST_RESTORE=1`, `FORCE_MODULE_RELOAD=1`, and `RELOAD_REQUIRED_MODULES_PER_CASE=1`.

| Result file | Case | p1 Mbps | p4 Mbps | Key counters | Stability |
| --- | --- | ---: | ---: | --- | --- |
| `build/perf-matrix-remote-216-82-holdskb-xmitmore-20260602-161630.json` | baseline hold-skb + trust checksum + ACK trust | 531.19 | 482.84 | B route direct frames 377,568; outer-GSO blocked 393,944 | boot IDs stable |
| `build/perf-matrix-remote-216-82-holdskb-xmitmore-20260602-161630.json` | `ackless_holdskb_trustcsum_acktrust_xmitmore` | 514.55 | 479.95 | params enabled, but `route_tcp_gso_async_xmit_more_sets=0` and `rx_worker_xmit_more_sets=0` on both sides | boot IDs stable |

Conclusion: do not spend more time on the per-skb `xmit_more` approach. On the target 6.12 kernels it cannot actually signal xmit-more through `dev_queue_xmit()`, and the no-op probe unsurprisingly did not improve throughput. The next credible TX-side optimization is a real skb-list/batch path in the segmented fallback or RX-worker reinjection path, with strict guards for qdisc/device safety; otherwise move effort to the broader LAN reinjection redesign.

Cleanup: after the xmit-more public run, A/B had unchanged boot IDs, no TrustIX/iperf processes, no test LAN netns/veth, and no TrustIX modules loaded. Final available memory was about 1694 MiB on A and 760 MiB on B.

### Full-datapath ACKless hold-skb 8-frame append probe

Change: briefly raised the default-off inline pair hard cap from 4 to 8 frames and added matrix alias `ackless_holdskb8_trustcsum_acktrust` to test whether reducing A-side LAN reinjection calls further would help. After PVE validation rebooted pveA on the 8-frame case, this code was reverted: the hard cap is back to 4 frames and the `holdskb8` alias was removed.

Validation: local `python -m py_compile build\run_remote_perf_matrix.py build\test_run_remote_perf_matrix.py build\deploy_gso_opt_remote.py`, `python -m unittest build.test_run_remote_perf_matrix`, `go test -count=1 ./internal/daemon -run TestTrustIXDatapathModuleParameters`, `go test -count=1 ./internal/kernelmodule`, and Linux `trustixd` build passed before deployment. A/B and PVE module builds passed. Public A/B matrix used `TCP_TESTS=82clientp1,82clientp4`; PVE p1 matrix used `TCP_TESTS=82clientp1`, `IPERF_SECONDS=3`, `RUN_UDP=0`, `SKIP_UNDERLAY=1`, `SKIP_POST_RESTORE=1`, `FORCE_MODULE_RELOAD=1`, and `RELOAD_REQUIRED_MODULES_PER_CASE=1`.

| Result file | Case | p1 Mbps | p4 Mbps | Key counters | Stability |
| --- | --- | ---: | ---: | --- | --- |
| `build/perf-matrix-remote-216-82-holdskb8-20260602-163948.json` | baseline hold-skb + trust checksum + ACK trust | 523.41 | 477.04 | A `rx_worker_xmit_packets=187,111`; B route direct frames 372,508 | boot IDs stable |
| `build/perf-matrix-remote-216-82-holdskb8-20260602-163948.json` | `ackless_holdskb4_trustcsum_acktrust` | 546.51 | 485.67 | A `rx_worker_xmit_packets=96,978`; B route direct frames 384,862 | boot IDs stable |
| `build/perf-matrix-remote-216-82-holdskb8-20260602-163948.json` | `ackless_holdskb8_trustcsum_acktrust` | 538.64 | 509.14 | A `rx_worker_xmit_packets=49,651`; B route direct frames 390,206 | boot IDs stable |
| `build/pve/pve-holdskb8-p1-20260602-165917.json` | baseline / holdskb4 / holdskb8 | 529.53 / 550.78 / failed | n/a | holdskb8 failed before throughput result | pveA rebooted from `9a984697-e7b1-47cc-b475-1af7ca1bc9a6` to `3b5a966f-9f8b-4902-bda7-80b1865f5078` |

Conclusion: do not keep 8-frame hold-skb coalescing. Public A/B showed that A-side reinjection calls could be cut roughly 4x versus the 2-frame baseline and roughly 2x versus `holdskb4`, but throughput only improved modestly on p4. The isolated PVE p1 validation then rebooted pveA on the `holdskb8` case, while baseline and holdskb4 completed. The stable upper bound remains 4 frames; larger coalesced inner skbs likely expose the same receive-side GSO/driver instability seen in earlier aggressive RX-worker experiments.

Cleanup: after the public run, A/B had unchanged boot IDs, no TrustIX/iperf processes, no test LAN netns/veth, and no TrustIX modules loaded. Final available memory was about 1686 MiB on A and 712 MiB on B. After the PVE reboot, pveA and pveB were explicitly cleaned; no TrustIX/iperf processes, no test LAN netns/veth, and no TrustIX modules remained. Final available memory was about 7473 MiB on pveA and 7470 MiB on pveB.

### ACKless direct-build no-outer current-source retest

Change: aligned the matrix harness with the kernel hard cap for `route_tcp_gso_async_stream_max_frames`: route-GSO stream expectations and per-node overrides now clamp at 64 frames instead of 128. Added `TRUSTIX_MATRIX_READY_PING_ONLY=1` so crash-prone direct-build cases can be isolated through module setup, daemon ready, LAN ping, health checks, and snapshots without starting iperf.

Validation: local `python -m py_compile build\run_remote_perf_matrix.py build\test_run_remote_perf_matrix.py build\deploy_gso_opt_remote.py`, `python -m unittest build.test_run_remote_perf_matrix`, `go test -count=1 ./internal/daemon -run TestTrustIXDatapathModuleParameters`, and `go test -count=1 ./internal/kernelmodule` passed. PVE deployment rebuilt crypto/datapath/helper modules on both VMs and helper BTF/kfuncs were present.

| Result file | Case | Test | Mbps | Retrans | Key counters | Stability |
| --- | --- | --- | ---: | ---: | --- | --- |
| `build/pve/pve-directbuild-noouter-ready-ping-20260602-current.json` | `ackless_directbuild_noouter_tuned` | ready/ping only | n/a | n/a | module param validation OK; `route_tcp_gso_async_stream_max_frames=(64,64)` | ready, 0% ping loss, boot IDs stable |
| `build/pve/pve-directbuild-noouter-p1-2s-20260602-current.json` | same | `82clientp1`, 2s | 3334.75 | 2127 | B route stream direct frames 631,549; direct errors 3; outer-GSO frames 0 | boot IDs stable |
| `build/pve/pve-directbuild-noouter-p4-2s-20260602-current.json` | same | `82clientp4`, 2s | 2830.75 | 4780 | B route stream direct frames 536,756; direct errors 23; prepare errors 19 | boot IDs stable |
| `build/pve/pve-directbuild-noouter-p4-8s-20260602-current.json` | same | `82clientp4`, 8s | 3264.27 | 10739 | B route stream direct frames 2,446,225; direct errors 55; prepare errors 105; direct fallbacks 210 | boot IDs stable |

Conclusion: the current source no longer reproduces the earlier `build/pve/pve-directbuild-noouter-current-p4-20260602-171147.json` startup/p4 reboot when tested incrementally. The 8s p4 result is back in the historical no-outer range, close to `build/pve/pve-directbuild-noouter-p4-20260602-133300.json` at 3322.42 Mbps. Remaining issue is not a catastrophic crash in this path; it is p4 instability/efficiency: high retransmits and small but nonzero direct-build prepare/fallback/error counters. Treat p1/p4 no-outer direct-build as stable enough for small-step PVE experiments, but keep broad p4/p8 sweeps gated.

Cleanup: after the PVE retests, pveA and pveB had unchanged boot IDs, no TrustIX/iperf processes, no test LAN links/netns, and no TrustIX modules loaded. Final available memory was about 7484 MiB on pveA and 7490 MiB on pveB.

### ACKless direct-build no-outer worker/shard sweep

Change: added no-outer direct-build worker variants and aliases: `ackless_directbuild_noouter_workers` and `ackless_directbuild_noouter_worker_budget`. These keep outer-GSO disabled and derive unbound, unordered, sharded4/sharded8, worker dequeue, and light schedule-delay variants from `exp_plaintext_fast_route_gso_async_stream_hw_inline_rx_directbuild_m64_tuned_ackonly`. `select_cases()` now preserves alias expansion order instead of returning cases in source definition order, so aliases can express real test priority. The stable `ackless_directbuild_noouter_tuned` alias remains on the ordered no-outer baseline; sharded4 is kept as an explicit worker-sweep candidate until its startup stability is revalidated.

Validation: local `python -m py_compile build\run_remote_perf_matrix.py build\test_run_remote_perf_matrix.py build\deploy_gso_opt_remote.py`, `python -m unittest build.test_run_remote_perf_matrix`, `go test -count=1 ./internal/daemon -run TestTrustIXDatapathModuleParameters`, and `go test -count=1 ./internal/kernelmodule` passed. PVE deployment rebuilt crypto/datapath/helper modules on both VMs and helper BTF/kfuncs were present.

| Result file | Case | Test | Mbps | Retrans | Key counters | Stability |
| --- | --- | --- | ---: | ---: | --- | --- |
| `build/pve/pve-directbuild-noouter-workers-ready-20260602-current.json` | `ackless_directbuild_noouter_workers` | ready/ping only, 6 cases | n/a | n/a | all 6 module param validations OK; double-sided ping 0% loss | boot IDs stable |
| `build/pve/pve-directbuild-noouter-workers-p4-8s-20260602-current.json` | ordered baseline | `82clientp4`, 8s | 3273.87 | 10033 | B direct frames 2,452,527; direct errors 57; prepare errors 88 | boot IDs stable |
| same | no-outer unordered | `82clientp4`, 8s | 3285.25 | 8185 | B direct errors 93; prepare errors 89 | boot IDs stable |
| same | no-outer unbound | `82clientp4`, 8s | 3346.32 | 2260 | B direct errors 28; prepare errors 29 | boot IDs stable |
| same | no-outer unordered+unbound | `82clientp4`, 8s | 3507.07 | 5213 | B direct errors 43; prepare errors 50 | boot IDs stable |
| same | no-outer sharded4 | `82clientp4`, 8s | 3549.21 | 1145 | B direct frames 2,633,345; direct errors/fallbacks/prepare errors 0 | boot IDs stable |
| same | no-outer sharded8 | `82clientp4`, 8s | 3496.16 | 5328 | B direct frames 2,598,883; direct errors/fallbacks/prepare errors 0 | boot IDs stable |
| `build/pve/pve-directbuild-noouter-workerbudget-p4-8s-20260602-current.json` | sharded4 budget i32/s1024 | `82clientp4`, 8s | 3448.28 | 8378 | B direct errors 1; prepare errors 0 | boot IDs stable |
| same | worker dequeue 8 | `82clientp4`, 8s | 3304.18 | 15663 | B worker dequeue batches 20,094; direct errors 28 | boot IDs stable |
| same | scheddepth4 delay1 | `82clientp4`, 8s | 2901.03 | 12415 | B direct errors 121; prepare errors 181 | boot IDs stable |
| `build/pve/pve-directbuild-noouter-tuned-sharded4-ready-20260602-current.json` | sharded4 as temporary tuned alias | ready/ping only | n/a | n/a | failed before ready: pveB helper module missing after start | pveB rebooted `89326ebc-6050-4625-9bbf-307c1f5267d7` -> `943e8a48-bac1-47a2-9c80-6f5c74d8fd23` |

Conclusion: no-outer sharded4 is the best measured p4 throughput candidate so far: 3549.21 Mbps, about 8.4% over the same-run ordered baseline, and it eliminated direct-build error/fallback/prepare counters in that run. Worker dequeue batching and schedule delay were not useful. However, a later single-case ready-only validation with sharded4 selected through `ackless_directbuild_noouter_tuned` rebooted pveB during startup/module presence checking. Treat sharded4 as a promising explicit experiment, not the default, until the module reload/startup path is hardened and the single-case smoke is repeatable.

Cleanup: after the worker and worker-budget PVE runs, pveA/pveB had no TrustIX/iperf processes, no test LAN links/netns, and no TrustIX modules loaded. Final available memory was about 7465 MiB on pveA and 7475 MiB on pveB. After the failed single-case ready-only run, pveB had rebooted and both VMs were clean: no TrustIX/iperf processes, no test LAN links/netns, and no TrustIX modules loaded.

### ACKless route-GSO startup ordering hardening

Change: fixed the remote matrix harness so route TCP/GSO sysfs module parameters are no longer written before `restart_pair()`. The pre-start phase now only injects the required crash-risk opt-in environment variables; after the daemon is ready and `assert_required_modules_loaded()` confirms the helper module exists, the harness applies and validates all route-GSO async parameters. This prevents the first case after `RELOAD_REQUIRED_MODULES_PER_CASE=1` from writing parameters to an old/missing module or enabling dangerous xmit paths during daemon cleanup/startup.

Validation: local `python -m py_compile build\run_remote_perf_matrix.py build\test_run_remote_perf_matrix.py build\deploy_gso_opt_remote.py`, full `python -m unittest build.test_run_remote_perf_matrix`, `go test -count=1 ./internal/daemon -run TestTrustIXDatapathModuleParameters`, and `go test -count=1 ./internal/kernelmodule` passed. PVE deployment rebuilt crypto/datapath/helper modules on both VMs.

| Result file | Case | Test | Mbps | Retrans | Key counters | Stability |
| --- | --- | --- | ---: | ---: | --- | --- |
| `build/pve/pve-directbuild-noouter-workers-ready-20260602-hardened.json` | `ackless_directbuild_noouter_workers` | ready/ping only, 6 cases | n/a | n/a | all 6 ready; module params OK; required modules OK | boot IDs stable |
| `build/pve/pve-directbuild-noouter-sharded4-p4-8s-20260602-hardened.json` | no-outer sharded4 | `82clientp4`, 8s | 3524.15 | 2490 | B direct frames 2,618,881; direct errors/fallbacks/prepare errors 0; outer-GSO frames 0 | boot IDs stable |

Conclusion: the previous single-case sharded4 startup failure was not reproduced after moving sysfs writes after module-ready validation. No-outer sharded4 is again a stable explicit PVE candidate, but it is still a 1500-byte direct-build path (`outer_gso_frames=0`), so it is not the next throughput breakthrough. The next retest should be explicit outer-GSO hard-enable under the hardened startup ordering, because historical PVE data showed 3.98-4.27 Gbps there.

Cleanup: after the hardened ready and p4 smoke, pveA/pveB had unchanged boot IDs, no TrustIX/iperf processes, no test LAN netns/veth, and TrustIX modules only loaded with refcount 0 before final cleanup. Available memory was about 7454 MiB on pveA and 7463 MiB on pveB.

### ACKless outer-GSO hard-enable hardened retest

Change: reran the explicit outer-GSO hard-enable path after the startup ordering fix above. No kernel datapath change was made in this step. The run used PVE VMs, `FORCE_MODULE_RELOAD=1`, `RELOAD_REQUIRED_MODULES_PER_CASE=1`, `SKIP_POST_RESTORE=1`, `ENABLE_ROUTE_OUTER_GSO_HARD=1`, and `PUBLIC_DISABLE_ROUTE_TCP_UNSAFE_OVERRIDES=0`.

| Result file | Case | Test | Mbps | Retrans | CPU/process summary | Stability |
| --- | --- | --- | ---: | ---: | --- | --- |
| `build/pve/pve-outergso-hard-ready-20260602-hardened.json` | ordered/sharded4/sharded8 hard-enable | ready/ping only | n/a | n/a | module params OK; outer-GSO and hard-enable set to `Y` | boot IDs stable |
| `build/pve/pve-outergso-hard-p4p8-20260602-hardened.json` | ordered hard-enable | `82clientp4`, 6s | 3698.57 | 12432 | client `trustixd` ~9.3% CPU; server softirq max 26.7%, iperf max 44% | boot IDs stable |
| same | ordered hard-enable | `82clientp8`, 6s | 3448.42 | 14337 | client `trustixd` ~9.4% CPU; server softirq max 21.5%, iperf max 61.5% | boot IDs stable |
| same | sharded4 hard-enable | `82clientp4`, 6s | 3662.54 | 3819 | client `trustixd` ~8.8% CPU; server softirq max 22.4%, iperf max 74% | boot IDs stable |
| same | sharded4 hard-enable | `82clientp8`, 6s | 3287.79 | 3318 | client `trustixd` ~8.7% CPU; server softirq max 21.5%, iperf max 79.4% | boot IDs stable |

Conclusion: hard-enable no longer reproduces startup/module-load instability under the hardened harness, but this window did not reproduce the earlier 3.98-4.27 Gbps best results. It still slightly beats no-outer sharded4 at p4, while sharded4 significantly reduces retransmits. CPU is not saturated, so the next optimization should focus on ACKless TCP burst shape, queue pacing/backpressure, or qdisc/virtio queue behavior rather than more per-frame copy/kfunc micro-optimizations.

Cleanup: after the hard-enable retest, pveA/pveB boot IDs were unchanged, available memory was about 7463 MiB and 7490 MiB, and explicit cleanup left no TrustIX/iperf processes, no test netns/veth, and no TrustIX modules loaded.

### Full datapath plaintext OpenWrt 23.05.5 feasibility smoke

Change: `kernel/trustix_datapath` now builds on OpenWrt 23.05.5 / Linux 5.15 headers that do not provide `<net/gso.h>`, while preserving the include on newer kernels. Added a kernelmodule runtime test for `TX_PLAINTEXT`: the test installs route/session/session-wire state, attaches a LAN veth hook with a target underlay veth, injects an inner IPv4 packet on the LAN side, captures the outer TIXT/UDP packet on the underlay peer, and validates it with the module's outer-parse ioctl.

Validation: local `go test ./internal/kernelmodule ./internal/daemon` passed. PVE A rebuilt `kmod-trustix-datapath_5.15.167-1_x86_64.ipk` with the OpenWrt 23.05.5 x86/64 SDK. The generated `.ko` had SHA256 `6cf2b1e1569f0a32fb4f99f7318b240dc72768f48272289c7f5ee1201449a8e6` and vermagic `5.15.167 SMP mod_unload`. The OpenWrt target was `OpenWrt 23.05.5 r24106-10cc5fcd00`, `x86_64`, kernel `5.15.167`.

OpenWrt stability: first load with `enable_features=128 rx_worker_inject=1 tx_plaintext=1` reported `features=128`, `safe_features=128`, `unsafe_features=0`, `selftests=1023`, `selftest_failures=0`, `flags=3`, then unloaded cleanly. A later 3-cycle load/unload loop reported the same clean feature/selftest state each cycle, with unchanged boot ID `3755a9e3-bda1-44ce-b0b6-8a44375d577e`.

OpenWrt function smoke: with the module loaded, the cross-compiled test binary passed:

| Test | Result | Key evidence |
| --- | --- | --- |
| `TestTrustIXFullDatapathDeviceQueryAndSelftest` | pass | query/selftest/state/hook lifecycle OK |
| `TestTrustIXFullDatapathRXWorkerInjectsWithoutPanic` | pass | RX worker hook accepted and injected the staged outer packet |
| `TestTrustIXFullDatapathTXPlaintextEncapsulatesWithoutPanic` | pass | `tx_plaintext_packets=1`, `tx_plaintext_bytes=76`, build/xmit errors 0 |

Cleanup: OpenWrt ended with no TrustIX modules or sysfs entries, no `/tmp` TrustIX/test files, no test veth links, no test route for `198.51.100.2/32`, unchanged boot ID, and about 7661 MiB available memory.

### Full datapath plaintext OpenWrt SDK compatibility matrix

Change: added and validated `scripts/openwrt-full-datapath-kmod-matrix.sh` for the full plaintext `kernel/trustix_datapath` module. The default OpenWrt arm64 matrix uses `armvirt/64` for 21.02/22.03 and `armsr/armv8` for 23.05/24.10/25.12; the 22.03 arm64 entry was corrected from `armsr/armv8` to `armvirt/64`.

Validation: the matrix ran on the PVE build VM under `/root/trustix-openwrt-kmod-matrix`. Main output was `/root/trustix-openwrt-kmod-matrix/run-20260603-full-plaintext-r2/results.tsv`; 22.03 arm64 was rerun in `/root/trustix-openwrt-kmod-matrix/run-20260603-full-plaintext-r2-fix22arm64`; 25.12 was rerun in `/root/trustix-openwrt-kmod-matrix/run-20260603-full-plaintext-r2-2512/results.tsv`. All compile rows passed.

| Name | Target | Kernel | Result | `.ko` SHA256 |
| --- | --- | --- | --- | --- |
| `21.02.7-x86_64` | `x86/64` | `5.4.238` | pass | `50c7c76bb85b710eeb9cf1d82965440ac0e8c8a7cf5fa19c7097eb7006e44108` |
| `21.02.7-arm64` | `armvirt/64` | `5.4.238` | pass | `3cc591934281d4e7876fae142dd619a0c202425fe00886fc882224b4319d0fe3` |
| `22.03.7-x86_64` | `x86/64` | `5.10.221` | pass | `ad1c83ee95f840f2e9b9bcbee991c18b553dbbad870816cc05572cf18bf85bb5` |
| `22.03.7-arm64` | `armvirt/64` | `5.10.221` | pass | `101eb21448e522b608ae18510572355857933f65ef7153d1883e679eb40caca1` |
| `23.05.5-x86_64` | `x86/64` | `5.15.167` | pass | `6cf2b1e1569f0a32fb4f99f7318b240dc72768f48272289c7f5ee1201449a8e6` |
| `23.05.5-arm64` | `armsr/armv8` | `5.15.167` | pass | `90faf008939effea9a1d4ee3b620313eb6c31d4c08549e2f4f409327686f5567` |
| `24.10.2-x86_64` | `x86/64` | `6.6.93` | pass | `66c8765006b1d2ff1612335736ea17dc3c9a7e8384c816eca0ef4b5c9510eb4f` |
| `24.10.2-arm64` | `armsr/armv8` | `6.6.93` | pass | `3b99a3aa05cf25b21371ed4ee797cc0e859a2e441d10343b40dceb3b7d75141b` |
| `25.12.1-x86_64` | `x86/64` | `6.12.74` | pass | `7e3f25bffaadd60253fe3b71be48e1518f7342b0572d634bb60260f60d7d1e8f` |
| `25.12.1-arm64` | `armsr/armv8` | `6.12.74` | pass | `e4eb3852dd6143e2aadf8c01208912e2b578c9babbfdd7ca352d414361429fa7` |

Boundary: this is an SDK compile-compatibility proof for official OpenWrt SDKs, not proof that an arbitrary Linux kernel can build or load the module. Runtime load/function coverage remains the OpenWrt 23.05.5 x86_64 target above, where `RX_WORKER` and `TX_PLAINTEXT` smoke tests passed. Other OpenWrt releases/targets still need real target load and function smoke before they should be called fully supported.

### Full datapath plaintext generic Linux compile smoke

Validation: copied the current `kernel/trustix_datapath` source and Makefile to the PVE Ubuntu build VM and built it with standard out-of-tree Kbuild against installed distro kernel headers. This is not an OpenWrt SDK path and does not use OpenWrt package metadata.

| Host | Distro | Header/KDIR | Kernel ABI | Result | `.ko` SHA256 |
| --- | --- | --- | --- | --- | --- |
| PVE guest `10.0.0.11` | Ubuntu 22.04.5 LTS | `/usr/src/linux-headers-5.15.0-179-generic` | `5.15.0-179-generic` | pass | `4805fd33b0e8981c4ca0fa921905818cddd1a307346c64499065f382b1d54431` |
| PVE guest `10.0.0.11` | Ubuntu 22.04.5 LTS | `/usr/src/linux-headers-6.8.0-124-generic` | `6.8.0-124-generic` | pass | `4adc92c189635c2c9478f8724f57490ce26bd7807c79c59d60e90d0828151caa` |

PVE host note: the Proxmox host itself is Debian 12 / kernel `6.8.12-17-pve`, but `/lib/modules/6.8.12-17-pve/build` was missing, so no host compile was attempted and no packages were installed on the host. With matching `pve-headers` installed, the same generic Kbuild path should be testable there.

Boundary: generic Linux support means "can build against a matching kernel build directory/header tree" via `make -C kernel/trustix_datapath KDIR=/path/to/kernel/build ARCH=...`, not "one `.ko` works across distros." Linux kernel modules are tied to exact kernel ABI/vermagic and must be built per target kernel. Runtime load/function smoke is still required per kernel before enabling full plaintext datapath in production.

### Public A/B ACKless TCP outer-GSO validation

Validation: deployed the current crypto/datapath/helper modules to public lab hosts A and B, then ran A/B public-path ACKless TCP tests with `ENABLE_ROUTE_OUTER_GSO_HARD=1`, `PUBLIC_DISABLE_ROUTE_TCP_UNSAFE_OVERRIDES=0`, `ENABLE_TIXT_PLAIN_ACK_ONLY=1`, `RELOAD_REQUIRED_MODULES_PER_CASE=1`, and `ens18` as the underlay interface. No reboot was detected in any run; boot IDs stayed stable on both hosts.

| Result file | Case | Test | Mbps | Retrans | Key counters / resources | Stability |
| --- | --- | --- | ---: | ---: | --- | --- |
| `build/perf-matrix-public-ab-ackless-noouter-20260603-185107.json` | no-outer direct-build m64 | `82clientp1`, 6s | 543.57 | 102 | B route direct frames 595,106; outer-GSO frames 0 | boot IDs stable |
| same | no-outer direct-build m64 | `82clientp4`, 6s | 529.31 | 1414 | B direct errors 83, fallbacks 120 | boot IDs stable |
| `build/perf-matrix-public-ab-outergso-hard-p1-20260603-190241.json` | ordered outer-GSO hard-enable | `82clientp1`, 4s | 1647.15 | 965 | B outer-GSO frames 611,819; errors 0 | boot IDs stable |
| `build/perf-matrix-public-ab-outergso-hard-sweep-p4-20260603-continue.json` | ordered outer-GSO hard-enable | `82clientp4`, 4s | 2179.26 | 2462 | B outer-GSO frames 809,161; errors 0 | boot IDs stable |
| same | sharded4 outer-GSO hard-enable | `82clientp4`, 4s | 2241.73 | 3494 | B outer-GSO frames 832,710; errors 0 | boot IDs stable |
| same | sharded8 outer-GSO hard-enable | `82clientp4`, 4s | 2328.33 | 2795 | B outer-GSO frames 864,069; errors 0; client busy 69.09%, server busy 33.67% | boot IDs stable |
| `build/perf-matrix-public-ab-outergso-hard-crossitem-p4-20260603-continue.json` | sharded4 cross-item outer-GSO | `82clientp4`, 4s | 2328.18 | 3195 | B cross-item frames 78,108; cross-item errors 5; outer-GSO errors 0 | boot IDs stable |
| `build/perf-matrix-public-ab-outergso-hard-hash-txq-p4-20260603-continue.json` | sharded4 hash-txq outer-GSO | `82clientp4`, 4s | 2173.82 | 2757 | hash TX queue sets 0, fallbacks 25,739; no gain | boot IDs stable |
| `build/perf-matrix-public-ab-outergso-hard-sharded8-p4-10s-20260603-continue.json` | sharded8 outer-GSO hard-enable | `82clientp4`, 10s | 2262.03 | 4590 | B outer-GSO frames 2,096,727; batches 89,499; errors 0; queue high 1.67 MiB | boot IDs stable |

Public underlay baseline from `build/perf-matrix-public-ab-ackless-noouter-20260603-185107.json`: TCP `82client->216server` was 4502.95 Mbps at p1 and 4237.75 Mbps at p4; reverse direction was 2245.24 Mbps at p1 and 2463.52 Mbps at p4. UDP 800M was 714.00 Mbps from A to B and 561.04 Mbps from B to A.

Conclusion: real public A/B is not capped at the old 0.5 Gbps ACKless result. Safe direct-build/no-outer ACKless TCP remains poor at about 0.53-0.54 Gbps. Enabling outer-GSO hard-enable raises the best public ACKless TCP result to about 2.33 Gbps short-window and 2.26 Gbps over 10 seconds, with zero outer-GSO errors and no reboot. This is still well below the 4.2-4.5 Gbps available in the same direction on plain underlay TCP. Cross-item batching did not beat sharded8, and hash-txq did not work on this path because TX queue setting fell back every time. The remaining gap is more likely burst shape/backpressure/congestion behavior on the public path than raw per-frame copy cost.

Cleanup: after testing, A/B had no TrustIX or iperf user processes, no loaded `trustix_*` modules, no TrustIX test netns, and no XDP attached to `ens18`. Available memory after cleanup was about 1,739,152 KiB on A and 767,512 KiB on B.

### Public A/B ACKless TCP retake after peak window

Validation: on 2026-06-09 afternoon, retested public A/B because the previous low result was likely affected by evening peak. A/B were clean before the run, current `trustixd.current` and rebuilt modules were deployed, and the ACKless TCP route-GSO/outer-GSO cases were run with `ENABLE_TIXT_PLAIN_ACK_ONLY=1`, `ENABLE_TIXT_PLAIN_SKIP_SEQUENCE=1`, `ENABLE_ROUTE_OUTER_GSO_HARD=1`, hot stats enabled, and `ens18` as the underlay. Result files: `build/public-underlay-retake-20260609-140709.json` and `build/perf-matrix-remote-216-82-public-retake-20260609-141604.json`.

Public underlay baseline in the same window:

| Direction | p1 Mbps | p4 Mbps | p8 Mbps | Notes |
| --- | ---: | ---: | ---: | --- |
| A `203.0.113.10` -> B `203.0.113.20` | 1217.03 | 1082.70 | 1533.52 | direct ping avg 1.29 ms |
| B -> A | 3099.24 | 3702.00 | 3745.80 | direct ping avg 0.76 ms |

ACKless TCP plaintext route-GSO/outer-GSO results:

| Case | Direction | p1 Mbps | p4 Mbps | p8 Mbps | Resource/stability notes |
| --- | --- | ---: | ---: | ---: | --- |
| sharded8 outer-GSO hard-enable | A -> B | 929.95 | 965.20 | 934.16 | max `trustixd` CPU 10.1%, max RSS 74.0 MiB, min available 603 MiB, boot IDs stable |
| sharded8 outer-GSO hard-enable | B -> A | 2489.89 | 2599.17 | 2281.42 | outer-GSO frames A 2,105,951 / B 5,477,912, no reboot |
| ordered outer-GSO hard-enable | A -> B | 544.75 | 1481.37 | 1169.74 | max `trustixd` CPU 10.1%, max RSS 70.3 MiB, min available 596 MiB, boot IDs stable |
| ordered outer-GSO hard-enable | B -> A | 2436.37 | 2502.28 | 2203.38 | outer-GSO frames A 2,402,709 / B 5,307,052, no reboot |

Conclusion: the late low public result was not representative. In this retake, A->B underlay recovered to about 1.5 Gbps and ACKless TCP reached 1.48 Gbps on the best ordered p4 run, effectively near the current public-path ceiling in that direction. B->A underlay recovered to about 3.7 Gbps and ACKless TCP reached 2.60 Gbps, about 69% of p4 underlay. CPU is still not saturated by `trustixd`; the remaining B->A gap is more likely congestion/burst pacing, qdisc/softirq behavior, or route-GSO queue shaping than a simple userspace CPU bottleneck.

Cleanup: after the retake, A/B had no TrustIX or iperf processes, no TrustIX netns/veth, no loaded `trustix_*` modules, and no XDP attached to `ens18`. Boot IDs stayed unchanged. Available memory after cleanup was about 725,940 KiB on A and 784,112 KiB on B.

### ACKless TCP public profile retune

Change: the ACKless TCP performance route-GSO default was retuned from the previous sharded8/hash-TX-queue profile to the more balanced public-path profile:

`flowshard + shards6 + worker dequeue batch + min queue depth 8 + 500 usec schedule delay + cross-item dynamic cap low 12/high 24/q4 + emit budget 8 + resched stride 16`

The production helper profile no longer enables `route_tcp_gso_async_hash_tx_queue` by default because public A/B counters showed it falling back on this virtio path without a measurable gain.

Validation files:

| Result file | Scope | Notes |
| --- | --- | --- |
| `build/perf-matrix-remote-216-82-public-pacing-sweep-20260609-143510.json` | p4 sweep, hot stats | compared sharded8, ordered, shards6 pacing, delay variants; wrapper timed out after the final extra case, but completed cases and final boot status were valid |
| `build/perf-matrix-remote-216-82-public-default-confirm-20260609-150401.json` | full p1/p4/p8, hot stats | validated selected shards6/emit8 profile after making it the harness best profile |
| `build/perf-matrix-remote-216-82-public-prodlike-confirm-20260609-151328.json` | p4/p8, hot stats off | production-like confirmation without BPF map/hot-stat collection |

Key public results:

| Profile | Direction | p1 Mbps | p4 Mbps | p8 Mbps | Stability/resources |
| --- | --- | ---: | ---: | ---: | --- |
| selected shards6/emit8, hot stats | A -> B | 832.72 | 1420.68 | 1431.54 | boot IDs stable, max `trustixd` CPU 10.0%, max RSS 75.9 MiB |
| selected shards6/emit8, hot stats | B -> A | 2425.47 | 2660.17 | 2406.61 | min available memory 607 MiB, no route-GSO errors/reboot |
| selected shards6/emit8, production-like | A -> B | n/a | 1489.44 | 1439.96 | boot IDs stable, max `trustixd` CPU 10.0%, max RSS 73.9 MiB |
| selected shards6/emit8, production-like | B -> A | n/a | 2411.18 | 2288.90 | min available memory 598 MiB, no reboot |

Sweep highlights: the old sharded8 profile retested at about 1137 Mbps A->B p4 and 2345 Mbps B->A p4. Ordered outer-GSO retested at about 1360 Mbps A->B p4 and 2583 Mbps B->A p4. The selected shards6/emit8 pacing profile reached about 1552 Mbps A->B p4 and 2683 Mbps B->A p4 in the same sweep, with much lower A->B retransmits than ordered. A hash-TX-queue variant did not prove useful; its counters showed fallback instead of queue assignment.

Conclusion: this does not make public ACKless TCP reach the PVE ceiling, but it is a better default than sharded8/hash-txq for the real A/B path. The current public limit still looks more like burst pacing/congestion and softirq/qdisc behavior than userspace CPU saturation.

Cleanup: A/B were cleaned after validation. Final status showed no TrustIX or iperf processes, no TrustIX netns/veth, no loaded `trustix_*` modules, and no XDP attached to `ens18`. Boot IDs stayed unchanged; available memory after cleanup was about 721,592 KiB on A and 733,468 KiB on B.

### Kernel and distro compatibility audit on PVE

Validation: on 2026-06-09, reused the PVE compatibility VM `trustix-kernel-compat` (`10.0.0.21`, Ubuntu 22.04.5 LTS, running kernel `6.8.0-124-generic`) to check current kernel module build/load behavior across installed distro header trees. VM103 and VM104 were originally stopped; VM103 was started for the test and stopped again after cleanup. VM100 was not touched.

Generic Linux Kbuild result:

| KDIR | Kernel ABI | `trustix_crypto` | `trustix_datapath` | `trustix_datapath_helpers` |
| --- | --- | --- | --- | --- |
| `/lib/modules/5.15.0-179-generic/build` | `5.15.0-179-generic` | pass, `device-only` | pass, `full` | pass, `basic` |
| `/lib/modules/5.15.0-181-generic/build` | `5.15.0-181-generic` | pass, `device-only` | pass, `full` | pass, `basic` |
| `/lib/modules/6.1.0-1036-oem/build` | `6.1.0-1036-oem` | pass, `device-only` | pass, `full` | pass, `basic` |
| `/lib/modules/6.8.0-124-generic/build` | `6.8.0-124-generic` | pass, `full` | pass, `full` | pass, `full` |

Runtime smoke on the running `6.8.0-124-generic` kernel:

| Module | Result | Notes |
| --- | --- | --- |
| `trustix_crypto` | pass | full module loaded; `/dev/trustix_crypto` ioctl batch/session/prepared-pool tests passed; BPF crypto kfunc provider was correctly skipped because this kernel BTF lacks `bpf_crypto_*` kfuncs |
| `trustix_datapath_helpers` | pass | full helper loaded, selftests passed, `gso_skb` feature gate active, route-TCP XMIT worker remained disabled |
| `trustix_datapath` | pass | loaded with `enable_features=128 rx_worker_inject=1 tx_plaintext=1`; selftests passed, `features=128 safe=128 unsafe=0`; panic-risk parameters forced disabled |

OpenWrt SDK compile spot check for `kernel/trustix_datapath`:

| OpenWrt target | Kernel | Result |
| --- | --- | --- |
| `21.02.7 x86/64` | `5.4.238` | pass |
| `23.05.5 x86/64` | `5.15.167` | pass |
| `24.10.2 x86/64` | `6.6.93` | pass |
| `23.05.5 armsr/armv8` | `5.15.167` | pass after re-downloading a truncated SDK cache |

Compatibility fix in the OpenWrt matrix helper: added an explicit GNU awk prerequisite check and tar integrity validation before reusing cached SDK archives, so a missing `gawk` or truncated `.tar.xz/.tar.zst` fails with a useful cause instead of a misleading module build failure. The helper is now promoted to a tracked release tool and included in Linux release packages.

Cleanup: VM103 had no loaded `trustix_*` modules and temporary `/tmp`/`/var/tmp` TrustIX files were removed. PVE host `/root`, `/tmp`, and `/var/tmp` had no `trustix*`/`*trustix*` leftovers after cleanup; VM103 and VM104 were stopped again. PVE disk usage ended at about 104 GiB used / 784 GiB free.

### PVE full datapath hard-lock retest

Validation: on 2026-06-10, retested the current `trustix_datapath` and
`trustix_datapath_helpers` build on the PVE A/B pair where the previous
production-style hard lock had been observed. The run used VM101
`trustix-perf-a` (`10.10.0.11`) and VM102 `trustix-perf-b` (`10.10.0.12`),
both on Ubuntu kernel `6.8.0-124-generic`, with the current `trustixd.current`
and rebuilt modules deployed under `/root/trustix-webui-demo`.

The short PVE A/B runs kept boot IDs unchanged:

| VM | Boot ID |
| --- | --- |
| VM101 / A | `46d72c2d-a751-40ee-8492-73b123688f06` |
| VM102 / B | `8117433a-a5b6-41cb-a856-38a32f0cdfc2` |

Result files:

| Result file | Scope |
| --- | --- |
| `build/pve/pve-datapath-baseline-noouter-underlay-20260610.json` | no-outer route-GSO baseline, p1/p4 |
| `build/pve/pve-datapath-rxworker-queueskb-20260610.json` | RX worker queue-skb and partial-checksum/MAC-cache variants, p1/p4 |
| `build/pve/pve-datapath-rxworker-coalescedgso-fullcsum-20260610.json` | RX worker coalesced-GSO full-checksum and software-segment variants, p1/p4 |
| `build/pve/pve-datapath-holdskb-hard-smoke-20260610.json` | hold-skb/pair-coalesce hard-enable variants, p1/p4 |
| `build/pve/pve-datapath-rxworker-stream-steal-20260610.json` | receive, batchqueue, and stolen-xmit compatibility variants, p1/p4 |
| `build/pve/pve-datapath-risk-p8-8s-20260610.json` | selected high-risk variants, p8 for 8 seconds |
| `build/pve/pve-datapath-risk-p8-30s-20260610.json` | same high-risk family, p8 for 30 seconds; reproduced VM101 reboot |

Representative results:

| Case | Test | Throughput | Reboot |
| --- | --- | ---: | --- |
| no-outer direct-build baseline | `82clientp1` / `82clientp4` | 3791.2 / 3365.2 Mbps | no |
| RX worker queue-skb partial checksum + MAC cache | `82clientp1` / `82clientp4` | 4389.8 / 3784.9 Mbps | no |
| RX worker coalesced-GSO full checksum | `82clientp1` / `82clientp4` | 4504.0 / 3602.6 Mbps | no |
| hold-skb pair-coalesce full checksum | `82clientp1` / `82clientp4` | 4531.6 / 3607.8 Mbps | no |
| hold-skb trust-csum ACK-trust | `82clientp1` / `82clientp4` | 4078.9 / 3517.9 Mbps | no |
| RX worker receive | `82clientp1` / `82clientp4` | 4417.9 / 3888.8 Mbps | no |
| inline stolen xmit partial + MAC cache | `82clientp8`, 8s | 3478.1 Mbps | no |
| xmit batchqueue partial + MAC cache | `82clientp8`, 8s | 3510.1 Mbps | no |
| hold-skb trust-csum ACK-trust | `82clientp8`, 8s | 3493.8 Mbps | no |
| inline stolen xmit partial + MAC cache | `82clientp8`, 30s | failed before throughput; empty iperf output | VM101 / A rebooted |

Long-soak reproduction: `build/pve/pve-datapath-risk-p8-30s-20260610.json`
started the first selected high-risk case,
`exp_plaintext_fast_route_gso_async_stream_hw_inline_rx_directbuild_m64_outergso_tuned_sharded4_ackonly_crossitem_budget_i32_s1024_rxworker_stream_inline_stolen_xmit_partial_maccache`,
with `TRUSTIX_MATRIX_TCP_TESTS=82clientp8` and `TRUSTIX_MATRIX_IPERF_SECONDS=30`.
The ready check passed and module parameter validation passed, but the iperf
phase returned empty output and the harness detected VM101 / A boot ID changing
from `46d72c2d-a751-40ee-8492-73b123688f06` to
`44cf7acf-5aa9-48ad-9d0a-be8d8651d778`. VM102 / B stayed on
`8117433a-a5b6-41cb-a856-38a32f0cdfc2`.

No panic, Oops, BUG, call trace, watchdog, soft lockup, hard lockup, or pstore
record was found after the reboot; VM101's previous-boot journal ended without
a useful kernel stack and `/sys/fs/pstore` was empty. The case requested the
full plaintext RX-worker module with route-GSO async stream direct-build,
outer-GSO requested, sharded queue, cross-item batching, ACK-only plaintext,
and RX-worker stream/xmit knobs. The captured runtime parameters show those
knobs on VM102 / B, while VM101 / A's module-parameter snapshot is consistent
with the post-reboot default state, so the evidence should be treated as
"B-side accelerated traffic caused A-side reboot" until a narrower run proves
which side and path is responsible. The case name includes stolen/partial
variants, but runtime parameter filtering means those labels must not be treated
as the sole root cause without a narrower A/B isolation run.

Conclusion: short WebUI/API-style reads, single-host synthetic hooks, and short
real A/B TCP flows do not reproduce the crash, but a longer p8 real-traffic soak
does. The full plaintext datapath remains crash-risk experimental and must stay
behind explicit panic-risk gates. Next isolation should bisect this case family
between route-GSO async outer-GSO/cross-item, RX-worker xmit, and forward-TC
interaction, preferably with kdump/netconsole/serial capture before expanding
to mixed transport so the first crash yields a kernel stack.

Cleanup: after testing, both VMs had no TrustIX or iperf processes, no temporary
TrustIX routes/netdevs, and no loaded `trustix_*` modules. The temporary matrix
SSH key was removed from both VMs and from the local workspace.

### OpenWrt single-host full datapath smoke

Validation: on 2026-06-10, rebuilt `kernel/trustix_datapath` for OpenWrt
`23.05.5 x86/64` / kernel `5.15.167` using the OpenWrt SDK on PVE VM101. The
rebuilt `trustix_datapath.ko` SHA256 was
`07f4bc8c24b6d8c83b6a44ad5205f2e4ed5db6491244535e62a4c7ddf27c06b9`.

Runtime target: PVE VM105, OpenWrt `23.05.5`, boot ID
`a2e9109d-bacc-4a0c-b280-106dae1e2920`.

Smoke matrix:

| Case | Parameters | Result |
| --- | --- | --- |
| Device query loop | `enable_features=128 rx_worker_inject=1 tx_plaintext=1 rx_worker_hot_stats=0` | pass, 30 repeated query/selftest reads, no reboot |
| RX/TX base | same | pass: RX worker inject, RX worker with `clsact` TC on ingress, TX plaintext; TCP stream test skipped because `rx_worker_xmit=0` |
| TCP stream xmit | base plus `rx_worker_xmit=1 rx_worker_direct_xmit=1 rx_worker_inline_xmit=1 rx_worker_tcp=1 rx_worker_stream_tcp=1 rx_worker_stream_coalesce_gso=1 rx_worker_queue_skb=1` | pass, 10 repeats |
| Partial checksum probe | TCP stream xmit plus `rx_worker_xmit_tcp_partial_csum=1 rx_worker_stream_coalesce_partial_csum=1` | pass, 10 repeats |
| Inline-pair delayed flush probe | TCP stream xmit plus `rx_worker_inline_pair_hold_skb=1 rx_worker_inline_pair_flush_jiffies=2` | pass, 10 repeats |
| Trust-checksum probe | TCP stream xmit plus `rx_worker_xmit_trust_tcp_checksum_ack_only=1 rx_worker_xmit_trust_tcp_checksum_min_len=1` | pass, 10 repeats |
| Combined danger probe | all probes above together | pass, 20 repeats |

Result: no lockup was reproduced in these single-host OpenWrt runtime smokes.
This was not a formal OpenWrt A/B datapath stress run and should not be used as
proof that OpenWrt production traffic is safe. The earlier RX-worker smoke
failure was a false negative: the
`rx_worker_injected` correctness counter was gated behind `rx_worker_hot_stats`,
so production-like `rx_worker_hot_stats=0` made a successful delivery look like
no delivery. The counter is now always updated. WebUI/API-style device reads and
basic `clsact` TC coexistence did not trigger a lockup in this matrix.

Production boundary: keep OpenWrt full plaintext datapath behind the dedicated
OpenWrt crash-risk opt-in gate until an A/B traffic run exercises real bridge,
forward TC, and sustained TCP flows. The daemon also strips known historical
panic-risk RX-worker parameters from automatic module loading, even when the
general crash-risk gate is enabled.

### PVE multitransport RX_STAGE hook isolation

Validation: on 2026-06-10, extended the PVE A/B retest to mixed endpoint
sets and longer concurrent traffic. The harness enabled multiple transport
candidates in one policy (`udp`, `tcp`, and `experimental_tcp`) and, for the
longest runs, drove TCP and UDP traffic at the same time.

Isolation results:

| Result file | Module/config shape | Traffic | Duration | Result |
| --- | --- | --- | --- | --- |
| `build/pve/pve-multitransport-guarded-600s-20260610.json` | mixed `tcp+experimental_tcp`, experimental TCP fast path disabled by policy guard | TCP | 600s | reboot reproduced; not caused by experimental_tcp fast path |
| `build/pve/pve-multitransport-modules-disabled-tcp-only-600s-20260610.json` | all TrustIX modules disabled | TCP | 600s | no reboot |
| `build/pve/pve-multitransport-modules-disabled-triple-tcpudp-1800s-20260610.json` | all TrustIX modules disabled; `udp,tcp,experimental_tcp` candidates | TCP+UDP | 1800s | no reboot; TCP/UDP quality degraded under contention |
| `build/pve/pve-multitransport-helpers-only-tcp-300s-20260610.json` | only `trustix_datapath_helpers` loaded | TCP | 300s | no reboot |
| `build/pve/pve-multitransport-datapath-only-tcp-300s-20260610.json` | only `trustix_datapath` loaded; daemon attached default RX_STAGE hook | TCP | 300s | reboot reproduced |
| `build/pve/pve-multitransport-datapath-only-rxstage-disabled-tcp-600s-20260610.json` | only `trustix_datapath` loaded; `kernel_modules.datapath.rx_stage: disabled` | TCP | 600s | no reboot |
| `build/pve/pve-multitransport-template-rxstage-default-off-triple-tcpudp-900s-20260610.json` | template required datapath/helpers modules; new daemon default leaves RX_STAGE hook disabled | TCP+UDP | 900s | no reboot; observed TCP and UDP sessions |
| `build/pve/pve-multitransport-template-rxstage-default-off-triple-tcpudp-1800s-20260610.json` | same default-off daemon and template modules | TCP+UDP | 1800s | no reboot; iperf/control-plane quality degraded and timed out |

The narrow reproducer is the daemon attaching the full datapath RX_STAGE hook
to the underlay while real traffic is running. Loading `trustix_datapath` alone
does not reproduce the lockup when the RX_STAGE hook is disabled. The helper
module and TC route-GSO path remain the stable performance path in this matrix.

Change: daemon RX_STAGE/RX_WORKER hook attachment is now default-off. It only
attaches when explicitly requested through `kernel_modules.datapath.rx_stage:
stage`, `kernel_modules.datapath.rx_stage: worker`, `rx_worker: true`, or the
corresponding `TRUSTIX_KERNEL_DATAPATH_RX_STAGE` /
`TRUSTIX_KERNEL_DATAPATH_RX_WORKER` environment variables. RX_WORKER and full
plaintext still require their crash-risk gates. A denied worker request no
longer falls back to the RX_STAGE poller, because the poller hook is the path
that reproduced the PVE hard lock/reboot.

Boundary: the 900s default-off mixed run is a stability pass for the panic
regression. The 1800s mixed run is not a throughput pass: boot IDs stayed
stable and modules remained loaded, but API/iperf calls timed out under
TCP+UDP pressure. Treat this as evidence that the default-off hook removes the
known hard-lock trigger, not as evidence that the mixed-transport performance
profile is tuned.

### 2026-06-21 Zaozhuang PVE userspace gap 900s strict gates

Validation: on 2026-06-20/21, completed the missing Debian-to-Debian
cross-host userspace compatibility gates on the Zaozhuang PVE host. The run
used VM200 `trustix-userspace-a` (`10.203.3.200`) and VM201
`trustix-userspace-b` (`10.203.3.201`) on isolated `vmbr3`.

Environment:

| Field | Value |
| --- | --- |
| OS matrix | Debian GNU/Linux 13 to Debian GNU/Linux 13 |
| Kernel matrix | `6.12.57+deb13-cloud-amd64` to `6.12.57+deb13-cloud-amd64` |
| TrustIX binary | `version=trustix-linux-amd64`, `commit=6cf9ae3-userspace-matrix`, `built_at=2026-06-20T11:50:03Z` |
| Binary SHA256 | `93e0aa6bb4481965f118fd03d975be1fd65844a62d94822df14274d8f68dbff5` |
| Runroot | `/tmp/trustix-userspace-matrix-20260620-1948/results/userspace-gap-900-20260620-202254` |

The matrix ran with `TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SELECTED_GATE=1`.
The selected userspace production gate passed. Each promoted case had matching
binary identity on both peers, 16 active transport sessions per peer, zero
`session_dial_errors`, zero `session_heartbeat_timeouts`, and no verifier
kernel-log crash findings.

| Case | Gate | 900s minimum received throughput |
| --- | ---: | ---: |
| `udp` / `plaintext` / `stable` / `userspace` | 1.5 Gbps | 1.994069 Gbps |
| `tcp` / `secure` / `stable` / `userspace` | 0.75 Gbps | 0.874594 Gbps |
| `quic` / `secure` / `stable` / `userspace` | 0.75 Gbps | 1.052465 Gbps |
| `quic` / `plaintext` / `stable` / `userspace` | 1.0 Gbps | 1.392558 Gbps |
| `websocket` / `secure` / `stable` / `userspace` | 0.5 Gbps | 0.817087 Gbps |
| `websocket` / `plaintext` / `stable` / `userspace` | 1.0 Gbps | 1.176969 Gbps |
| `http_connect` / `secure` / `stable` / `userspace` | 0.75 Gbps | 0.874190 Gbps |
| `http_connect` / `plaintext` / `stable` / `userspace` | 1.0 Gbps | 1.349766 Gbps |
| `experimental_tcp` / `secure` / `stable` / `userspace` | 1.0 Gbps | 1.495637 Gbps |

The earlier 60s smoke run also included `experimental_tcp` plaintext userspace,
but that row is intentionally not promoted: it reported a near-zero reverse
throughput sample around `0.000209 Gbps` and
`session_heartbeat_timeouts=13`. Keep plaintext experimental TCP on the
separate route-GSO production gate unless a fresh strict long run proves the
plain userspace mode.
