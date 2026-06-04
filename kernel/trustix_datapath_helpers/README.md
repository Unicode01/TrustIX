# TrustIX datapath kernel module

`trustix_datapath_helpers` is the first-release landing point for the future complete
TrustIX kernel datapath. It is intentionally separate from `trustix_crypto`:

- `trustix_crypto` owns AEAD, BPF crypto type registration, direct crypto
  kfuncs, and `/dev/trustix_crypto`.
- `trustix_datapath_helpers` owns skb/header/GSO datapath helper kfuncs and
  `/dev/trustix_datapath_helpers`.

The current module exposes the shared feature bit vocabulary through read-only
sysfs parameters and a query ioctl, plus a selftest ioctl for the TIXT frame
parser. Requested features must be passed through `enable_features=...`,
implemented by the module, and covered by a clean selftest before they appear in
`features`/`safe_features`. The first implemented packet capability is
`gso_skb`, with safe TC skb/header helpers and linear route-TCP header helpers.
Full route/session/queue ownership and direct XMIT are still intentionally not
reported as `full_datapath`.

Build and load on the target kernel:

```bash
make -C kernel/trustix_datapath_helpers
sudo insmod kernel/trustix_datapath_helpers/trustix_datapath_helpers.ko
cat /sys/module/trustix_datapath_helpers/parameters/abi_version
cat /sys/module/trustix_datapath_helpers/parameters/features
cat /sys/module/trustix_datapath_helpers/parameters/selftests
cat /sys/module/trustix_datapath_helpers/parameters/selftest_failures
```
