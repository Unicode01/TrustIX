# TrustIX kernel module

This out-of-tree module registers the missing BPF crypto type `aead` on kernels
that already expose the BPF crypto kfuncs but only register `skcipher`. It also
exposes `/dev/trustix_crypto` for TrustIX-owned batched AES-GCM seal/open tests.
Packet routing, session queues, GSO, and XMIT helpers belong in
`kernel/trustix_datapath_helpers`, not this crypto module.

It delegates `gcm(aes)` to the kernel crypto API. x86_64 hosts with
`aesni_intel` prefer the direct synchronous `__gcm(aes)` AES-NI provider so BPF
and ioctl callers do not pay the public async/cryptd scheduling path; arm64 and
other architectures use their kernel crypto provider selection. Hosts without a
usable hardware provider fall back to the kernel's synchronous generic
`gcm(aes)` / `__gcm(aes)` software implementation instead of disabling TrustIX
kernel crypto.

Build and load on the target kernel:

```bash
make -C kernel/trustix_crypto
sudo insmod kernel/trustix_crypto/trustix_crypto.ko
lsmod | grep trustix_crypto
```

Kernels without the BPF crypto/kfunc headers can build the ioctl-only
compatibility module:

```bash
make -C kernel/trustix_crypto DEVICE_ONLY=1
sudo insmod kernel/trustix_crypto/trustix_crypto.ko experimental_vaes=1
```

That variant only reports `device_aead` plus detected direct AES features. It
does not register BPF crypto types or TC crypto kfuncs, but it is enough
for TrustIX to use `/dev/trustix_crypto` as the secure packet batch engine on
older OpenWrt-style kernels.

To force the software path on a host that also has AES-NI, load with:

```bash
sudo insmod kernel/trustix_crypto/trustix_crypto.ko prefer_software=1
```

TrustIX still requires its runtime probes to pass before it enables kernel
crypto placement. Loading this module alone is not enough to mark the provider
ready.

The module exposes a small capability ABI through
`/sys/module/trustix_crypto/parameters/abi_version` and `features`.
TrustIX treats the currently implemented module as `crypto_only`: AEAD type,
AEAD device, TC/XDP crypto-only direct kfuncs, and optional AES-NI/VAES direct
crypto can be reported. `gso_skb` and `full_datapath` belong to
`trustix_datapath_helpers` and are reserved here; TrustIX will only select those higher
fallback tiers after the datapath module actually reports them, otherwise it
automatically downgrades to TC/XDP direct crypto, the AEAD device, or userspace
AEAD.

The device ioctl path is root-only (`0600`) and currently supports AES-128-GCM
and AES-256-GCM with 12-byte nonces and 16-byte tags. It supports both the
original stateless batch ioctl and a file-private session mode where TrustIX
sets the key once, reuses the kernel AEAD transform, and reuses per-file scratch
buffers across batches. Session mode can use the kernel's direct synchronous
`__gcm(aes)` AES-NI provider when present, while the BPF-facing provider remains
on the verifier-safe synchronous `gcm(aes)` path. It is intentionally a
TrustIX-private ABI for
benchmarking and fast-path plumbing, not a general kernel crypto userspace API.
For high-throughput staging, the device also supports a file-private `mmap`
pool: userspace places nonces, buffers, and op descriptors in the shared pool,
then submits a pool-batch ioctl so the module can run AEAD directly on mapped
memory without per-packet `copy_from_user()` / `copy_to_user()` copies. Pool
batches accept up to 4096 ops; large batches reuse the file-private request and
worker pools and auto-scale internal workers up to 16 CPUs unless
`pool_parallelism=<n>` is set. The Go wrapper exposes both checked prepared
pool calls and fast prepared calls for trusted hot paths that only need the
aggregate ioctl result on success. For the hottest packet paths, userspace can
also ask the module to resolve and cache a prepared pool descriptor set; the
subsequent prepared-batch ioctl runs directly over cached kernel pointers. On
x86 hosts with AES, AVX2, VAES, and VPCLMULQDQ, loading with
`experimental_vaes=1` enables the TrustIX FPU-backed prepared-batch engine. The
default experimental path uses multi-buffer VAES AES-CTR/XOR plus a 4-block
aggregated GHASH reduction (`vaes_agg_ghash=1`) for AES-128-GCM and
AES-256-GCM seal batches. `vaes_agg_ghash=0` keeps the older split GHASH loop
for comparison. `vaes_fused_ghash=1` enables an alternate fused AES/GHASH test
path; it is correct but not the default because it has measured slower than the
aggregated split path. `/sys/module/trustix_crypto/parameters/` exposes
`vaes_available`, `vaes_attempts`, and `vaes_fallbacks` so target hosts can be
screened and release smokes can assert that the experimental path did not fall
back to kernel crypto.

The one-packet kfunc AES-NI/VAES paths wipe temporary stack buffers before
returning by default. Trusted throughput tests can load with
`kfunc_fastpath_wipe=0` to measure the hot-path cost of that wipe while keeping
key/context cleanup and decrypt-failure plaintext cleanup intact.

`kfunc_simd_fastpath` is hard-disabled for the first release. The parameter is
read-only and forced to `N` during module init even if passed to `insmod`,
because TC/XDP callbacks can execute in contexts where explicit FPU/SIMD use is
not safe enough for production. Prepared-pool VAES device batches remain the
supported high-throughput SIMD path.

To run the experimental VAES prepared-batch checks through the smoke script:

```bash
sudo TRUSTIX_KERNEL_EXPERIMENTAL_VAES=1 \
  TRUSTIX_KERNEL_EXPECT_VAES=1 \
  TRUSTIX_KERNEL_KERNELMODULE_TEST_BIN=/path/to/kernelmodule.test \
  TRUSTIX_KERNEL_KEEP_LOADED=0 \
  bash scripts/linux-kernel-module-smoke.sh
```

Add `TRUSTIX_KERNEL_VAES_BENCH=1` to include the prepared-pool microbench.

The smoke script can verify the software AES-GCM path explicitly:

```bash
sudo TRUSTIX_KERNEL_PREFER_SOFTWARE=1 TRUSTIX_KERNEL_KEEP_LOADED=0 bash scripts/linux-kernel-module-smoke.sh
```
