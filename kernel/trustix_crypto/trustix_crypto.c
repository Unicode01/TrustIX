// SPDX-License-Identifier: GPL-2.0
// TrustIX kernel crypto capability module.
//
// Upstream Linux 6.12 exposes BPF crypto kfuncs and a built-in skcipher BPF
// crypto type, but it doesn't register an AEAD BPF crypto type. TrustIX needs
// AEAD-GCM contexts for packet authentication, so this module registers
// type="aead" and delegates gcm(aes) to the kernel crypto API. The actual AES
// implementation remains the kernel provider: hardware AES where the kernel has
// a synchronous provider for the architecture, or generic software when
// hardware AES is unavailable or prefer_software=1 is set.
#include <crypto/aead.h>
#ifndef TRUSTIX_DEVICE_ONLY
#define TRUSTIX_DEVICE_ONLY 0
#endif

#include <linux/completion.h>
#include <linux/cpumask.h>
#include <linux/crypto.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/atomic.h>
#include <linux/fs.h>
#if !TRUSTIX_DEVICE_ONLY
#include <linux/if_ether.h>
#endif
#include <linux/ip.h>
#include <linux/ioctl.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#if !TRUSTIX_DEVICE_ONLY
#include <linux/netdevice.h>
#endif
#include <linux/overflow.h>
#include <linux/percpu.h>
#include <linux/preempt.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/scatterlist.h>
#include <linux/smp.h>
#include <linux/spinlock.h>
#if !TRUSTIX_DEVICE_ONLY
#include <linux/skbuff.h>
#endif
#include <linux/slab.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/version.h>

#ifndef TRUSTIX_ENABLE_BPF_CRYPTO
#if !TRUSTIX_DEVICE_ONLY && defined(__has_include)
#if __has_include(<linux/bpf_crypto.h>) && LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#define TRUSTIX_ENABLE_BPF_CRYPTO 1
#else
#define TRUSTIX_ENABLE_BPF_CRYPTO 0
#endif
#else
#define TRUSTIX_ENABLE_BPF_CRYPTO 0
#endif
#endif

#if !TRUSTIX_DEVICE_ONLY
#include <linux/bpf.h>
#if TRUSTIX_ENABLE_BPF_CRYPTO
#include <linux/bpf_crypto.h>
#endif
#include <linux/btf.h>
#include <linux/btf_ids.h>
#ifndef BTF_KFUNCS_START
#define BTF_KFUNCS_START(name) BTF_SET8_START(name)
#define BTF_KFUNCS_END(name) BTF_SET8_END(name)
#endif
#ifndef __bpf_kfunc
#define __bpf_kfunc
#endif
#ifndef __bpf_kfunc_start_defs
#define __bpf_kfunc_start_defs()
#endif
#ifndef __bpf_kfunc_end_defs
#define __bpf_kfunc_end_defs()
#endif

static __always_inline struct sk_buff *
trustix_bpf_ctx_skb(struct __sk_buff *ctx)
{
	return (struct sk_buff *)ctx;
}
#endif
#if !TRUSTIX_DEVICE_ONLY
#include <linux/tcp.h>
#endif
#include <linux/types.h>
#include <linux/uaccess.h>
#if !TRUSTIX_DEVICE_ONLY
#include <linux/udp.h>
#endif
#if defined(__has_include)
#if __has_include(<linux/unaligned.h>)
#include <linux/unaligned.h>
#else
#include <asm/unaligned.h>
#endif
#else
#include <asm/unaligned.h>
#endif
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include <net/checksum.h>
#if !TRUSTIX_DEVICE_ONLY
#include <net/dst.h>
#include <net/ip.h>
#endif
#if defined(CONFIG_X86) && defined(CONFIG_X86_64)
#define TRUSTIX_X86_SIMD 1
#else
#define TRUSTIX_X86_SIMD 0
#endif

static bool trustix_kfunc_simd_irq_fpu_fastpath;

#if TRUSTIX_X86_SIMD
#include <asm/cpufeature.h>
#include <asm/fpu/api.h>
#endif

#define TRUSTIX_AEAD_NAME "aead"
#define TRUSTIX_GCM_AES "gcm(aes)"
#define TRUSTIX_INTERNAL_GCM_AES "__gcm(aes)"
#define TRUSTIX_X86_GCM_AESNI_AVX "__generic-gcm-aesni-avx"
#define TRUSTIX_X86_GCM_AESNI "__generic-gcm-aesni"
#define TRUSTIX_AEAD_IOC_MAGIC 'T'
#define TRUSTIX_AEAD_IOC_VERSION 1
#define TRUSTIX_AEAD_IOC_FLAG_DECRYPT BIT(0)
#define TRUSTIX_AEAD_IOC_TAG_LEN 16
#define TRUSTIX_AEAD_IOC_NONCE_LEN 12
#define TRUSTIX_AEAD_IOC_KEY_MAX 32
#define TRUSTIX_AEAD_IOC_INPUT_MAX (512 * 1024)
#define TRUSTIX_AEAD_IOC_BATCH_MAX_OPS 4096
#define TRUSTIX_AEAD_IOC_POOL_MAX (64UL * 1024UL * 1024UL)
#define TRUSTIX_AEAD_IOC_DIRECT_MAX_SLOTS 16384
#define TRUSTIX_AEAD_IOC_DIRECT_ANY_SLOT 0xffffffffU
#define TRUSTIX_AEAD_IOC_DIRECT_FLAG_DECRYPT TRUSTIX_AEAD_IOC_FLAG_DECRYPT
#define TRUSTIX_AEAD_IOC_DIRECT_FLAG_AESNI BIT(1)
#define TRUSTIX_AEAD_IOC_DIRECT_FLAG_READY BIT(31)
#define TRUSTIX_AEAD_MODULE_ABI_VERSION 4
#define TRUSTIX_AEAD_FEATURE_CRYPTO_AEAD BIT_ULL(0)
#define TRUSTIX_AEAD_FEATURE_DEVICE_AEAD BIT_ULL(1)
#define TRUSTIX_AEAD_FEATURE_KFUNC_TC BIT_ULL(2)
#define TRUSTIX_AEAD_FEATURE_KFUNC_XDP BIT_ULL(3)
#define TRUSTIX_AEAD_FEATURE_DIRECT_AESNI BIT_ULL(4)
#define TRUSTIX_AEAD_FEATURE_DIRECT_VAES BIT_ULL(5)
#define TRUSTIX_SKB_CB_RX_NEXT_HOP 0

#if TRUSTIX_X86_SIMD
static bool trustix_aead_fpu_begin(void)
{
	if (!in_task() && !READ_ONCE(trustix_kfunc_simd_irq_fpu_fastpath))
		return false;
	if (!irq_fpu_usable())
		return false;
	local_bh_disable();
	if (!irq_fpu_usable()) {
		local_bh_enable();
		return false;
	}
	kernel_fpu_begin();
	return true;
}

static void trustix_aead_fpu_end(void)
{
	kernel_fpu_end();
	local_bh_enable();
}
#endif

struct trustix_aead_ioc_crypt {
	__u32 version;
	__u32 flags;
	__u32 key_len;
	__u32 nonce_len;
	__u32 in_len;
	__u32 out_len;
	__s32 result;
	__u32 reserved;
	__u64 key_ptr;
	__u64 nonce_ptr;
	__u64 in_ptr;
	__u64 out_ptr;
};

struct trustix_aead_ioc_op {
	__u64 nonce_ptr;
	__u64 in_ptr;
	__u64 out_ptr;
	__u32 nonce_len;
	__u32 in_len;
	__u32 out_len;
	__s32 result;
};

struct trustix_aead_ioc_batch {
	__u32 version;
	__u32 flags;
	__u32 key_len;
	__u32 op_count;
	__s32 result;
	__u32 reserved;
	__u64 key_ptr;
	__u64 ops_ptr;
};

struct trustix_aead_ioc_key {
	__u32 version;
	__u32 flags;
	__u32 key_len;
	__s32 result;
	__u64 key_ptr;
};

struct trustix_aead_ioc_pool {
	__u32 version;
	__u32 flags;
	__u64 size;
	__s32 result;
	__u32 reserved;
};

struct trustix_aead_ioc_pool_op {
	__u64 nonce_off;
	__u64 in_off;
	__u64 out_off;
	__u32 nonce_len;
	__u32 in_len;
	__u32 out_len;
	__s32 result;
};

struct trustix_aead_ioc_pool_batch {
	__u32 version;
	__u32 flags;
	__u32 op_count;
	__s32 result;
	__u64 ops_off;
};

struct trustix_aead_ioc_pool_prepared_batch {
	__u32 version;
	__u32 flags;
	__u32 op_count;
	__s32 result;
	__u32 start;
	__u32 reserved;
};

#if !TRUSTIX_DEVICE_ONLY
struct trustix_aead_skb_direct_open_args {
	u32 slot_id;
	u32 cipher_offset;
	u32 cipher_len;
};

struct trustix_aead_skb_direct_seal_args {
	u32 slot_id;
	u32 plain_offset;
	u32 cipher_offset;
	u32 plain_len;
};

struct trustix_aead_direct_batch_op {
	const u8 *src;
	u8 *dst;
	u32 plain_len;
	u8 nonce[12];
};

int trustix_kernel_direct_seal_batch(u32 slot_id,
				     const struct trustix_aead_direct_batch_op *ops,
				     u32 count);

#endif

#if !TRUSTIX_DEVICE_ONLY
static __always_inline int
trustix_skb_ensure_writable_head(struct sk_buff *skb, u32 len)
{
	if (likely(len <= skb_headlen(skb) && !skb_cloned(skb)))
		return 0;
	if (unlikely(!pskb_may_pull(skb, len)))
		return -EINVAL;
	if (skb_ensure_writable(skb, len))
		return -EFAULT;
	if (len > skb_headlen(skb))
		return -EINVAL;
	return 0;
}

#endif /* !TRUSTIX_DEVICE_ONLY */

struct trustix_aead_ioc_direct_key {
	__u32 version;
	__u32 flags;
	__u32 slot;
	__u32 key_len;
	__s32 result;
	__u32 reserved;
	__u64 key_ptr;
};

#define TRUSTIX_AEAD_IOC_CRYPT \
	_IOWR(TRUSTIX_AEAD_IOC_MAGIC, 1, struct trustix_aead_ioc_crypt)
#define TRUSTIX_AEAD_IOC_BATCH \
	_IOWR(TRUSTIX_AEAD_IOC_MAGIC, 2, struct trustix_aead_ioc_batch)
#define TRUSTIX_AEAD_IOC_SET_KEY \
	_IOWR(TRUSTIX_AEAD_IOC_MAGIC, 3, struct trustix_aead_ioc_key)
#define TRUSTIX_AEAD_IOC_CLEAR_KEY \
	_IO(TRUSTIX_AEAD_IOC_MAGIC, 4)
#define TRUSTIX_AEAD_IOC_CONFIG_POOL \
	_IOWR(TRUSTIX_AEAD_IOC_MAGIC, 5, struct trustix_aead_ioc_pool)
#define TRUSTIX_AEAD_IOC_POOL_BATCH \
	_IOWR(TRUSTIX_AEAD_IOC_MAGIC, 6, struct trustix_aead_ioc_pool_batch)
#define TRUSTIX_AEAD_IOC_PREPARE_POOL_BATCH \
	_IOWR(TRUSTIX_AEAD_IOC_MAGIC, 7, struct trustix_aead_ioc_pool_batch)
#define TRUSTIX_AEAD_IOC_POOL_PREPARED_BATCH \
	_IOWR(TRUSTIX_AEAD_IOC_MAGIC, 8, struct trustix_aead_ioc_pool_prepared_batch)
#define TRUSTIX_AEAD_IOC_POOL_PREPARE_RUN_BATCH \
	_IOWR(TRUSTIX_AEAD_IOC_MAGIC, 9, struct trustix_aead_ioc_pool_batch)
#define TRUSTIX_AEAD_IOC_DIRECT_SET_KEY \
	_IOWR(TRUSTIX_AEAD_IOC_MAGIC, 10, struct trustix_aead_ioc_direct_key)
#define TRUSTIX_AEAD_IOC_DIRECT_CLEAR_KEY \
	_IOWR(TRUSTIX_AEAD_IOC_MAGIC, 11, struct trustix_aead_ioc_direct_key)

static bool trustix_prefer_software;
module_param_named(prefer_software, trustix_prefer_software, bool, 0644);
MODULE_PARM_DESC(prefer_software,
		 "Prefer the kernel's synchronous generic __gcm(aes) provider over hardware-backed gcm(aes)");

static unsigned int trustix_pool_parallelism;
module_param_named(pool_parallelism, trustix_pool_parallelism, uint, 0644);
MODULE_PARM_DESC(pool_parallelism,
		 "Maximum workers for /dev/trustix_crypto mmap pool batches; 0 selects an automatic CPU-capped default");

static bool trustix_experimental_vaes;
module_param_named(experimental_vaes, trustix_experimental_vaes, bool, 0644);
MODULE_PARM_DESC(experimental_vaes,
		 "Try the TrustIX experimental VAES/VPCLMUL prepared-batch engine before falling back to kernel crypto");

static bool trustix_experimental_vaes_kfunc;
module_param_named(experimental_vaes_kfunc, trustix_experimental_vaes_kfunc, bool, 0644);
MODULE_PARM_DESC(experimental_vaes_kfunc,
		 "Also try the TrustIX VAES/VPCLMUL engine for one-packet BPF crypto callbacks; off by default because per-packet FPU setup can be slower than kernel crypto");

static bool trustix_device_direct_aead = true;
module_param_named(device_direct_aead, trustix_device_direct_aead, bool, 0644);
MODULE_PARM_DESC(device_direct_aead,
		 "Use TrustIX synchronous AES-NI/VAES AEAD for the misc-device ioctl path before falling back to kernel crypto");

static bool trustix_experimental_aesni_kfunc;
module_param_named(experimental_aesni_kfunc, trustix_experimental_aesni_kfunc, bool, 0644);
MODULE_PARM_DESC(experimental_aesni_kfunc,
		 "Try the TrustIX AES-NI/PCLMUL one-packet engine for BPF crypto callbacks when VAES is unavailable or disabled");

static bool trustix_aesni_agg_ghash = true;
module_param_named(aesni_agg_ghash, trustix_aesni_agg_ghash, bool, 0644);
MODULE_PARM_DESC(aesni_agg_ghash,
		 "Use 4-block aggregated GHASH in the AES-NI one-packet BPF path; set to 0 for the older serial GHASH loop");

static bool trustix_kfunc_fastpath_stats;
module_param_named(kfunc_fastpath_stats, trustix_kfunc_fastpath_stats, bool, 0644);
MODULE_PARM_DESC(kfunc_fastpath_stats,
		 "Count every experimental one-packet BPF VAES/AES-NI attempt/fallback; off by default to avoid hot-path cacheline contention");

static bool trustix_kfunc_fastpath_wipe = true;
module_param_named(kfunc_fastpath_wipe, trustix_kfunc_fastpath_wipe, bool, 0644);
MODULE_PARM_DESC(kfunc_fastpath_wipe,
		 "Wipe one-packet BPF AES-GCM temporary buffers before returning; disable only for trusted performance tests");

static bool trustix_kfunc_simd_fastpath;
module_param_named(kfunc_simd_fastpath, trustix_kfunc_simd_fastpath, bool, 0644);
MODULE_PARM_DESC(kfunc_simd_fastpath,
		 "Allow TrustIX one-packet BPF crypto callbacks to use explicit SIMD/FPU fast paths; off by default because TC/XDP callbacks can run in contexts where kernel_fpu_begin is unsafe");

module_param_named(kfunc_simd_irq_fpu_fastpath,
		   trustix_kfunc_simd_irq_fpu_fastpath, bool, 0644);
MODULE_PARM_DESC(kfunc_simd_irq_fpu_fastpath,
		 "Allow TrustIX one-packet BPF crypto callbacks to enter explicit SIMD/FPU outside task context when irq_fpu_usable permits it; off by default and intended only for controlled TC/XDP soak validation");

static bool trustix_kfunc_direct_slot_fastpath = true;
module_param_named(kfunc_direct_slot_fastpath,
		   trustix_kfunc_direct_slot_fastpath, bool, 0644);
MODULE_PARM_DESC(kfunc_direct_slot_fastpath,
		 "Use direct slot key schedules in TrustIX one-packet BPF crypto callbacks; set to 0 to force the older snapshot path");

static bool trustix_vaes_fused_ghash;
module_param_named(vaes_fused_ghash, trustix_vaes_fused_ghash, bool, 0644);
MODULE_PARM_DESC(vaes_fused_ghash,
		 "Use the experimental fused VAES/CTR/GHASH prepared-batch path; default keeps the faster split VAES/GHASH path");

static bool trustix_vaes_agg_ghash = true;
module_param_named(vaes_agg_ghash, trustix_vaes_agg_ghash, bool, 0644);
MODULE_PARM_DESC(vaes_agg_ghash,
		 "Use 4-block aggregated GHASH in the VAES prepared-batch path; set to 0 for the older split GHASH loop");


static inline void trustix_aead_wipe_fastpath(void *ptr, size_t len)
{
	if (trustix_kfunc_fastpath_wipe)
		memzero_explicit(ptr, len);
}

static unsigned int trustix_module_abi_version = TRUSTIX_AEAD_MODULE_ABI_VERSION;
module_param_named(abi_version, trustix_module_abi_version, uint, 0444);
MODULE_PARM_DESC(abi_version,
		 "TrustIX kernel module capability ABI version");

static char *trustix_build_sha256 = "";
module_param_named(build_sha256, trustix_build_sha256, charp, 0444);
MODULE_PARM_DESC(build_sha256,
		 "SHA256 fingerprint of the TrustIX .ko payload passed by trustixd at load time");

static unsigned long trustix_feature_mask;
module_param_named(features, trustix_feature_mask, ulong, 0444);
MODULE_PARM_DESC(features,
		 "TrustIX kernel module capability feature mask");

static bool trustix_vaes_available;
module_param_named(vaes_available, trustix_vaes_available, bool, 0444);
MODULE_PARM_DESC(vaes_available,
		 "Runtime CPU/kernel capability probe for the TrustIX experimental VAES/VPCLMUL engine");

static bool trustix_aesni_available;
module_param_named(aesni_available, trustix_aesni_available, bool, 0444);
MODULE_PARM_DESC(aesni_available,
		 "Runtime CPU/kernel capability probe for the TrustIX AES-NI/PCLMUL engine");

static unsigned long trustix_vaes_attempts;
module_param_named(vaes_attempts, trustix_vaes_attempts, ulong, 0444);
MODULE_PARM_DESC(vaes_attempts,
		 "Prepared batches offered to the TrustIX experimental VAES/VPCLMUL engine");

static unsigned long trustix_vaes_fallbacks;
module_param_named(vaes_fallbacks, trustix_vaes_fallbacks, ulong, 0444);
MODULE_PARM_DESC(vaes_fallbacks,
		 "Prepared batches that fell back from the TrustIX experimental VAES/VPCLMUL engine to kernel crypto");

#if !TRUSTIX_DEVICE_ONLY
static unsigned long trustix_aesni_attempts;
module_param_named(aesni_attempts, trustix_aesni_attempts, ulong, 0444);
MODULE_PARM_DESC(aesni_attempts,
		 "One-packet BPF callbacks offered to the TrustIX AES-NI/PCLMUL engine");

static unsigned long trustix_aesni_fallbacks;
module_param_named(aesni_fallbacks, trustix_aesni_fallbacks, ulong, 0444);
MODULE_PARM_DESC(aesni_fallbacks,
		 "One-packet BPF callbacks that fell back from the TrustIX AES-NI/PCLMUL engine to kernel crypto");

static DEFINE_PER_CPU(unsigned long, trustix_direct_kfunc_seal_calls);
static DEFINE_PER_CPU(unsigned long, trustix_direct_kfunc_open_calls);
static DEFINE_PER_CPU(unsigned long, trustix_direct_kfunc_errors);
static DEFINE_PER_CPU(unsigned long, trustix_direct_kfunc_batch_seal_errors);
static DEFINE_PER_CPU(unsigned long, trustix_direct_kfunc_seal_errors);
static DEFINE_PER_CPU(unsigned long, trustix_direct_kfunc_open_errors);
static DEFINE_PER_CPU(unsigned long, trustix_direct_kfunc_skb_seal_errors);
static DEFINE_PER_CPU(unsigned long, trustix_direct_kfunc_skb_open_errors);
static DEFINE_PER_CPU(unsigned long, trustix_direct_kfunc_einval_errors);
static DEFINE_PER_CPU(unsigned long, trustix_direct_kfunc_eopnotsupp_errors);
static DEFINE_PER_CPU(unsigned long, trustix_direct_kfunc_efault_errors);
static DEFINE_PER_CPU(unsigned long, trustix_direct_kfunc_enoent_errors);
static DEFINE_PER_CPU(unsigned long, trustix_direct_kfunc_ebadmsg_errors);
static DEFINE_PER_CPU(unsigned long, trustix_direct_kfunc_other_errors);
static DEFINE_PER_CPU(unsigned long, trustix_direct_kfunc_fpu_unavailable_fallbacks);
static DEFINE_PER_CPU(unsigned long, trustix_direct_kfunc_vaes_calls);
static DEFINE_PER_CPU(unsigned long, trustix_direct_kfunc_aesni_calls);


static bool trustix_direct_xdp_available;
module_param_named(direct_xdp_available, trustix_direct_xdp_available, bool, 0444);
MODULE_PARM_DESC(direct_xdp_available,
		 "TrustIX direct AEAD kfuncs registered for XDP programs");

struct trustix_percpu_ulong_param {
	unsigned long __percpu *counter;
};

static int trustix_percpu_ulong_param_get(char *buffer,
					  const struct kernel_param *kp)
{
	const struct trustix_percpu_ulong_param *param = kp ? kp->arg : NULL;
	unsigned long __percpu *counter = param ? param->counter : NULL;
	unsigned long total = 0;
	unsigned int cpu;

	if (!counter)
		return -EINVAL;
	for_each_possible_cpu(cpu)
		total += *per_cpu_ptr(counter, cpu);
	return scnprintf(buffer, PAGE_SIZE, "%lu\n", total);
}

static const struct kernel_param_ops trustix_percpu_ulong_param_ops = {
	.get = trustix_percpu_ulong_param_get,
};

#define TRUSTIX_DEFINE_PERCPU_ULONG_PARAM(param_name, counter_name) \
	static struct trustix_percpu_ulong_param trustix_param_##param_name = { \
		.counter = &counter_name \
	}

TRUSTIX_DEFINE_PERCPU_ULONG_PARAM(direct_kfunc_seal_calls,
				  trustix_direct_kfunc_seal_calls);
TRUSTIX_DEFINE_PERCPU_ULONG_PARAM(direct_kfunc_open_calls,
				  trustix_direct_kfunc_open_calls);
TRUSTIX_DEFINE_PERCPU_ULONG_PARAM(direct_kfunc_errors,
				  trustix_direct_kfunc_errors);
TRUSTIX_DEFINE_PERCPU_ULONG_PARAM(direct_kfunc_batch_seal_errors,
				  trustix_direct_kfunc_batch_seal_errors);
TRUSTIX_DEFINE_PERCPU_ULONG_PARAM(direct_kfunc_seal_errors,
				  trustix_direct_kfunc_seal_errors);
TRUSTIX_DEFINE_PERCPU_ULONG_PARAM(direct_kfunc_open_errors,
				  trustix_direct_kfunc_open_errors);
TRUSTIX_DEFINE_PERCPU_ULONG_PARAM(direct_kfunc_skb_seal_errors,
				  trustix_direct_kfunc_skb_seal_errors);
TRUSTIX_DEFINE_PERCPU_ULONG_PARAM(direct_kfunc_skb_open_errors,
				  trustix_direct_kfunc_skb_open_errors);
TRUSTIX_DEFINE_PERCPU_ULONG_PARAM(direct_kfunc_einval_errors,
				  trustix_direct_kfunc_einval_errors);
TRUSTIX_DEFINE_PERCPU_ULONG_PARAM(direct_kfunc_eopnotsupp_errors,
				  trustix_direct_kfunc_eopnotsupp_errors);
TRUSTIX_DEFINE_PERCPU_ULONG_PARAM(direct_kfunc_efault_errors,
				  trustix_direct_kfunc_efault_errors);
TRUSTIX_DEFINE_PERCPU_ULONG_PARAM(direct_kfunc_enoent_errors,
				  trustix_direct_kfunc_enoent_errors);
TRUSTIX_DEFINE_PERCPU_ULONG_PARAM(direct_kfunc_ebadmsg_errors,
				  trustix_direct_kfunc_ebadmsg_errors);
TRUSTIX_DEFINE_PERCPU_ULONG_PARAM(direct_kfunc_other_errors,
				  trustix_direct_kfunc_other_errors);
TRUSTIX_DEFINE_PERCPU_ULONG_PARAM(direct_kfunc_fpu_unavailable_fallbacks,
				  trustix_direct_kfunc_fpu_unavailable_fallbacks);
TRUSTIX_DEFINE_PERCPU_ULONG_PARAM(direct_kfunc_vaes_calls,
				  trustix_direct_kfunc_vaes_calls);
TRUSTIX_DEFINE_PERCPU_ULONG_PARAM(direct_kfunc_aesni_calls,
				  trustix_direct_kfunc_aesni_calls);

module_param_cb(direct_kfunc_seal_calls, &trustix_percpu_ulong_param_ops,
		&trustix_param_direct_kfunc_seal_calls, 0444);
MODULE_PARM_DESC(direct_kfunc_seal_calls,
		 "TrustIX direct AEAD seal kfunc calls from BPF programs");

module_param_cb(direct_kfunc_open_calls, &trustix_percpu_ulong_param_ops,
		&trustix_param_direct_kfunc_open_calls, 0444);
MODULE_PARM_DESC(direct_kfunc_open_calls,
		 "TrustIX direct AEAD open kfunc calls from BPF programs");

module_param_cb(direct_kfunc_errors, &trustix_percpu_ulong_param_ops,
		&trustix_param_direct_kfunc_errors, 0444);
MODULE_PARM_DESC(direct_kfunc_errors,
		 "TrustIX direct AEAD kfunc failures");

module_param_cb(direct_kfunc_batch_seal_errors, &trustix_percpu_ulong_param_ops,
		&trustix_param_direct_kfunc_batch_seal_errors, 0444);
MODULE_PARM_DESC(direct_kfunc_batch_seal_errors,
		 "TrustIX direct AEAD batch seal kfunc failures");

module_param_cb(direct_kfunc_seal_errors, &trustix_percpu_ulong_param_ops,
		&trustix_param_direct_kfunc_seal_errors, 0444);
MODULE_PARM_DESC(direct_kfunc_seal_errors,
		 "TrustIX direct AEAD seal kfunc failures");

module_param_cb(direct_kfunc_open_errors, &trustix_percpu_ulong_param_ops,
		&trustix_param_direct_kfunc_open_errors, 0444);
MODULE_PARM_DESC(direct_kfunc_open_errors,
		 "TrustIX direct AEAD open kfunc failures");

module_param_cb(direct_kfunc_skb_seal_errors, &trustix_percpu_ulong_param_ops,
		&trustix_param_direct_kfunc_skb_seal_errors, 0444);
MODULE_PARM_DESC(direct_kfunc_skb_seal_errors,
		 "TrustIX direct AEAD skb seal kfunc failures");

module_param_cb(direct_kfunc_skb_open_errors, &trustix_percpu_ulong_param_ops,
		&trustix_param_direct_kfunc_skb_open_errors, 0444);
MODULE_PARM_DESC(direct_kfunc_skb_open_errors,
		 "TrustIX direct AEAD skb open kfunc failures");

module_param_cb(direct_kfunc_einval_errors, &trustix_percpu_ulong_param_ops,
		&trustix_param_direct_kfunc_einval_errors, 0444);
MODULE_PARM_DESC(direct_kfunc_einval_errors,
		 "TrustIX direct AEAD kfunc -EINVAL failures");

module_param_cb(direct_kfunc_eopnotsupp_errors, &trustix_percpu_ulong_param_ops,
		&trustix_param_direct_kfunc_eopnotsupp_errors, 0444);
MODULE_PARM_DESC(direct_kfunc_eopnotsupp_errors,
		 "TrustIX direct AEAD kfunc -EOPNOTSUPP failures");

module_param_cb(direct_kfunc_efault_errors, &trustix_percpu_ulong_param_ops,
		&trustix_param_direct_kfunc_efault_errors, 0444);
MODULE_PARM_DESC(direct_kfunc_efault_errors,
		 "TrustIX direct AEAD kfunc -EFAULT failures");

module_param_cb(direct_kfunc_enoent_errors, &trustix_percpu_ulong_param_ops,
		&trustix_param_direct_kfunc_enoent_errors, 0444);
MODULE_PARM_DESC(direct_kfunc_enoent_errors,
		 "TrustIX direct AEAD kfunc -ENOENT failures");

module_param_cb(direct_kfunc_ebadmsg_errors, &trustix_percpu_ulong_param_ops,
		&trustix_param_direct_kfunc_ebadmsg_errors, 0444);
MODULE_PARM_DESC(direct_kfunc_ebadmsg_errors,
		 "TrustIX direct AEAD kfunc -EBADMSG failures");

module_param_cb(direct_kfunc_other_errors, &trustix_percpu_ulong_param_ops,
		&trustix_param_direct_kfunc_other_errors, 0444);
MODULE_PARM_DESC(direct_kfunc_other_errors,
		 "TrustIX direct AEAD kfunc failures with uncategorized errno");

module_param_cb(direct_kfunc_fpu_unavailable_fallbacks,
		&trustix_percpu_ulong_param_ops,
		&trustix_param_direct_kfunc_fpu_unavailable_fallbacks, 0444);
MODULE_PARM_DESC(direct_kfunc_fpu_unavailable_fallbacks,
		 "TrustIX direct AEAD kfunc scalar fallbacks because kernel FPU/SIMD was unavailable in the current context");

module_param_cb(direct_kfunc_vaes_calls, &trustix_percpu_ulong_param_ops,
		&trustix_param_direct_kfunc_vaes_calls, 0444);
MODULE_PARM_DESC(direct_kfunc_vaes_calls,
		 "TrustIX direct AEAD kfunc calls served by the VAES one-packet engine");

module_param_cb(direct_kfunc_aesni_calls, &trustix_percpu_ulong_param_ops,
		&trustix_param_direct_kfunc_aesni_calls, 0444);
MODULE_PARM_DESC(direct_kfunc_aesni_calls,
		 "TrustIX direct AEAD kfunc calls served by the AES-NI one-packet engine");

enum trustix_direct_kfunc_error_site {
	TRUSTIX_DIRECT_KFUNC_ERROR_BATCH_SEAL,
	TRUSTIX_DIRECT_KFUNC_ERROR_SEAL,
	TRUSTIX_DIRECT_KFUNC_ERROR_OPEN,
	TRUSTIX_DIRECT_KFUNC_ERROR_SKB_SEAL,
	TRUSTIX_DIRECT_KFUNC_ERROR_SKB_OPEN,
};

static void trustix_direct_kfunc_record_error(
	int ret, enum trustix_direct_kfunc_error_site site)
{
	if (!trustix_kfunc_fastpath_stats)
		return;

	this_cpu_inc(trustix_direct_kfunc_errors);
	switch (site) {
	case TRUSTIX_DIRECT_KFUNC_ERROR_BATCH_SEAL:
		this_cpu_inc(trustix_direct_kfunc_batch_seal_errors);
		break;
	case TRUSTIX_DIRECT_KFUNC_ERROR_SEAL:
		this_cpu_inc(trustix_direct_kfunc_seal_errors);
		break;
	case TRUSTIX_DIRECT_KFUNC_ERROR_OPEN:
		this_cpu_inc(trustix_direct_kfunc_open_errors);
		break;
	case TRUSTIX_DIRECT_KFUNC_ERROR_SKB_SEAL:
		this_cpu_inc(trustix_direct_kfunc_skb_seal_errors);
		break;
	case TRUSTIX_DIRECT_KFUNC_ERROR_SKB_OPEN:
		this_cpu_inc(trustix_direct_kfunc_skb_open_errors);
		break;
	}
	switch (ret) {
	case -EINVAL:
		this_cpu_inc(trustix_direct_kfunc_einval_errors);
		break;
	case -EOPNOTSUPP:
		this_cpu_inc(trustix_direct_kfunc_eopnotsupp_errors);
		break;
	case -EFAULT:
		this_cpu_inc(trustix_direct_kfunc_efault_errors);
		break;
	case -ENOENT:
		this_cpu_inc(trustix_direct_kfunc_enoent_errors);
		break;
	case -EBADMSG:
		this_cpu_inc(trustix_direct_kfunc_ebadmsg_errors);
		break;
	default:
		this_cpu_inc(trustix_direct_kfunc_other_errors);
		break;
	}
}

static void trustix_direct_kfunc_record_fpu_unavailable(void)
{
	if (!trustix_kfunc_fastpath_stats)
		return;
	this_cpu_inc(trustix_direct_kfunc_fpu_unavailable_fallbacks);
}

#endif

struct trustix_aead_tfm {
	struct crypto_aead *tfm;
	void __percpu *req;
	struct aead_request *sleep_req;
	unsigned int req_size;
	bool may_async;
#if TRUSTIX_ENABLE_BPF_CRYPTO
	bool bpf_tfm;
#endif
	u8 raw_key[TRUSTIX_AEAD_IOC_KEY_MAX];
	unsigned int raw_key_len;
#if TRUSTIX_X86_SIMD
	u8 vaes_rk[15][16] __aligned(16);
	u8 vaes_shash[16] __aligned(16);
	u8 vaes_shash4[4][16] __aligned(16);
	int vaes_rounds;
	bool vaes_ready;
#endif
};

struct trustix_aead_direct_slot {
	struct rcu_head rcu;
	u32 slot;
	u32 flags;
	u32 key_len;
#if TRUSTIX_X86_SIMD
	u8 rk[15][16] __aligned(16);
	u8 h[16] __aligned(16);
	u8 shash[16] __aligned(16);
	u8 shash4[4][16] __aligned(16);
	int rounds;
	bool aesni_ready;
	bool vaes_ready;
#endif
};

#if TRUSTIX_X86_SIMD
struct trustix_aead_direct_snapshot {
	u8 rk[15][16] __aligned(16);
	u8 h[16] __aligned(16);
	u8 shash[16] __aligned(16);
	u8 shash4[4][16] __aligned(16);
	int rounds;
	bool aesni_ready;
	bool vaes_ready;
};
#endif

struct trustix_aead_ioc_scratch {
	u8 *src;
	u8 *dst;
	__u32 src_cap;
	__u32 dst_cap;
};

struct trustix_aead_file {
	struct mutex lock;
	void *ctx;
	struct trustix_aead_ioc_scratch scratch;
	void *pool;
	size_t pool_size;
	unsigned int pool_mappings;
	struct trustix_aead_pool_async_op *async_ops;
	void *async_req_mem;
	__u32 async_cap;
	size_t async_req_stride;
	struct trustix_aead_pool_worker *pool_workers;
	__u32 pool_worker_cap;
	struct trustix_aead_prepared_op *prepared_ops;
	__u32 prepared_cap;
	__u32 prepared_count;
	__u32 prepared_flags;
};

static DEFINE_MUTEX(trustix_direct_slots_lock);
static struct trustix_aead_direct_slot __rcu *trustix_direct_slots[TRUSTIX_AEAD_IOC_DIRECT_MAX_SLOTS];

struct trustix_aead_wait {
	struct completion completion;
	int err;
};

struct trustix_aead_pool_async_op {
	struct aead_request *req;
	struct scatterlist src_sg;
	struct scatterlist dst_sg;
	struct trustix_aead_wait wait;
	__u32 out_len;
	int ret;
	bool needs_wait;
};

struct trustix_aead_pool_worker {
	struct work_struct work;
	struct completion done;
	struct trustix_aead_file *state;
	struct trustix_aead_tfm *ctx;
	struct trustix_aead_ioc_pool_op *ops;
	struct trustix_aead_prepared_op *prepared;
	struct trustix_aead_pool_async_op *async;
	size_t req_stride;
	__u32 start;
	__u32 count;
	__u32 flags;
	__u32 successes;
	int ret;
	bool vaes;
	bool aesni;
};

struct trustix_aead_prepared_op {
	u8 *nonce;
	u8 *src;
	u8 *dst;
	__u32 in_len;
	__u32 out_len;
	__u32 *pool_out_len;
	__s32 *pool_result;
};

static void trustix_aead_prepared_set_result(struct trustix_aead_prepared_op *op,
					     int ret)
{
	if (!op)
		return;
	if (op->pool_result)
		*op->pool_result = ret;
	if (!ret && op->pool_out_len)
		*op->pool_out_len = op->out_len;
}

static void trustix_aead_direct_free_rcu(struct rcu_head *rcu)
{
	struct trustix_aead_direct_slot *slot;

	slot = container_of(rcu, struct trustix_aead_direct_slot, rcu);
	memzero_explicit(slot, sizeof(*slot));
	kfree(slot);
}

static __maybe_unused struct trustix_aead_direct_slot *
trustix_aead_direct_lookup_rcu(u32 slot_id)
{
	if (slot_id >= TRUSTIX_AEAD_IOC_DIRECT_MAX_SLOTS)
		return NULL;
	return rcu_dereference(trustix_direct_slots[slot_id]);
}

static int trustix_aead_try_direct_prepared_batch(struct trustix_aead_tfm *ctx,
						  __u32 flags,
						  struct trustix_aead_file *state,
						  struct trustix_aead_prepared_op *ops,
						  __u32 op_count,
						  __u32 *successes);

#if TRUSTIX_X86_SIMD
static int trustix_aead_vaes_prepare_ctx(struct trustix_aead_tfm *ctx);
static int trustix_aead_vaes_prepared_slice(struct trustix_aead_tfm *ctx,
					    __u32 flags,
					    struct trustix_aead_prepared_op *ops,
					    __u32 start, __u32 count,
					    __u32 *successes);
static int trustix_aead_aesni_seal_one(const u8 rk[15][16], int rounds,
				       const u8 shash[16],
				       const u8 shash4[4][16],
				       struct trustix_aead_prepared_op *op);
static int trustix_aead_aesni_seal4_prepared(const u8 rk[15][16], int rounds,
					     const u8 shash[16],
					     const u8 shash4[4][16],
					     struct trustix_aead_prepared_op *ops);
static int trustix_aead_aesni_open_one(const u8 rk[15][16], int rounds,
				       const u8 shash[16],
				       const u8 shash4[4][16],
				       struct trustix_aead_prepared_op *op);
static int trustix_aead_aesni_prepared_slice(struct trustix_aead_tfm *ctx,
					     __u32 flags,
					     struct trustix_aead_prepared_op *ops,
					     __u32 start, __u32 count,
					     __u32 *successes);
static bool trustix_aead_aesni_capable(void);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
static void trustix_aead_complete(void *data, int err)
{
	struct trustix_aead_wait *wait = data;

	if (err == -EINPROGRESS)
		return;
	if (!wait)
		return;
	wait->err = err;
	complete(&wait->completion);
}
#else
static void trustix_aead_complete(struct crypto_async_request *req, int err)
{
	struct trustix_aead_wait *wait;

	if (err == -EINPROGRESS)
		return;
	if (!req)
		return;
	wait = req->data;
	if (!wait)
		return;
	wait->err = err;
	complete(&wait->completion);
}
#endif

static struct crypto_aead *trustix_alloc_sync_aead(const char *algo)
{
	struct crypto_aead *tfm;

	/* BPF program contexts can't wait for async crypto completion. */
	if (!trustix_prefer_software && !strcmp(algo, TRUSTIX_GCM_AES)) {
#if TRUSTIX_X86_SIMD
		tfm = crypto_alloc_aead(TRUSTIX_X86_GCM_AESNI_AVX, 0, 0);
		if (!IS_ERR(tfm))
			return tfm;
		tfm = crypto_alloc_aead(TRUSTIX_X86_GCM_AESNI, 0, 0);
		if (!IS_ERR(tfm))
			return tfm;
#endif
		tfm = crypto_alloc_aead(TRUSTIX_INTERNAL_GCM_AES, 0,
					CRYPTO_ALG_ASYNC);
		if (!IS_ERR(tfm))
			return tfm;
	}

	if (trustix_prefer_software && !strcmp(algo, TRUSTIX_GCM_AES)) {
		tfm = crypto_alloc_aead(algo, 0, CRYPTO_ALG_ASYNC);
		if (!IS_ERR(tfm))
			return tfm;
	}

	tfm = crypto_alloc_aead(algo, 0, CRYPTO_ALG_ASYNC);
	if (!IS_ERR(tfm))
		return tfm;

	if (!strcmp(algo, TRUSTIX_GCM_AES)) {
		tfm = crypto_alloc_aead(TRUSTIX_INTERNAL_GCM_AES, 0, CRYPTO_ALG_ASYNC);
		if (!IS_ERR(tfm))
			return tfm;
	}
	return tfm;
}

#if TRUSTIX_ENABLE_BPF_CRYPTO
static struct crypto_aead *trustix_alloc_kernel(const char *algo)
{
	struct crypto_aead *tfm;

	/*
	 * BPF program contexts cannot wait for async completion, and explicit
	 * x86 SIMD/FPU use is not safe on every TC/XDP call path. Prefer the
	 * internal synchronous AES-GCM implementation for BPF crypto contexts.
	 */
	if (!strcmp(algo, TRUSTIX_GCM_AES))
		return crypto_alloc_aead(TRUSTIX_INTERNAL_GCM_AES, 0,
					 CRYPTO_ALG_ASYNC);

	tfm = crypto_alloc_aead(algo, 0, CRYPTO_ALG_ASYNC);
	if (!IS_ERR(tfm))
		return tfm;
	return tfm;
}
#endif

static struct crypto_aead *trustix_alloc_waitable_aead(const char *algo)
{
	struct crypto_aead *tfm;

	if (!trustix_prefer_software && !strcmp(algo, TRUSTIX_GCM_AES)) {
#if TRUSTIX_X86_SIMD
		tfm = crypto_alloc_aead(TRUSTIX_X86_GCM_AESNI_AVX, 0, 0);
		if (!IS_ERR(tfm))
			return tfm;
		tfm = crypto_alloc_aead(TRUSTIX_X86_GCM_AESNI, 0, 0);
		if (!IS_ERR(tfm))
			return tfm;
#endif
		tfm = crypto_alloc_aead(TRUSTIX_INTERNAL_GCM_AES, 0,
					CRYPTO_ALG_ASYNC);
		if (!IS_ERR(tfm))
			return tfm;
		tfm = crypto_alloc_aead(algo, CRYPTO_ALG_ASYNC,
					CRYPTO_ALG_ASYNC);
		if (!IS_ERR(tfm))
			return tfm;
		tfm = crypto_alloc_aead(TRUSTIX_INTERNAL_GCM_AES, 0,
					CRYPTO_ALG_ASYNC);
		if (!IS_ERR(tfm))
			return tfm;
		tfm = crypto_alloc_aead(algo, 0, 0);
		if (!IS_ERR(tfm))
			return tfm;
	}

	if (trustix_prefer_software && !strcmp(algo, TRUSTIX_GCM_AES)) {
		tfm = crypto_alloc_aead(algo, 0, CRYPTO_ALG_ASYNC);
		if (!IS_ERR(tfm))
			return tfm;
	}

	tfm = crypto_alloc_aead(algo, 0, 0);
	if (!IS_ERR(tfm))
		return tfm;

	if (!strcmp(algo, TRUSTIX_GCM_AES)) {
		tfm = crypto_alloc_aead(TRUSTIX_INTERNAL_GCM_AES, 0, 0);
		if (!IS_ERR(tfm))
			return tfm;
	}
	return tfm;
}

static void *trustix_aead_alloc_from_crypto_tfm(struct crypto_aead *tfm,
						bool waitable)
{
	struct trustix_aead_tfm *ctx;

	if (IS_ERR(tfm))
		return tfm;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		crypto_free_aead(tfm);
		return ERR_PTR(-ENOMEM);
	}
	ctx->tfm = tfm;
	ctx->req_size = sizeof(struct aead_request) + crypto_aead_reqsize(tfm);
	ctx->may_async = !!(crypto_aead_alg(tfm)->base.cra_flags &
			    CRYPTO_ALG_ASYNC);
	if (waitable)
		ctx->sleep_req = kzalloc(ctx->req_size, GFP_KERNEL);
	else
		ctx->req = __alloc_percpu(ctx->req_size,
					  __alignof__(struct aead_request));
	if (!ctx->req && !ctx->sleep_req) {
		crypto_free_aead(tfm);
		kfree(ctx);
		return ERR_PTR(-ENOMEM);
	}
	return ctx;
}

static void *trustix_aead_alloc_tfm_mode(const char *algo, bool waitable)
{
	struct crypto_aead *tfm;

	tfm = waitable ? trustix_alloc_waitable_aead(algo) :
			 trustix_alloc_sync_aead(algo);
	return trustix_aead_alloc_from_crypto_tfm(tfm, waitable);
}

static void *trustix_aead_alloc_tfm(const char *algo)
{
	return trustix_aead_alloc_tfm_mode(algo, false);
}

#if TRUSTIX_ENABLE_BPF_CRYPTO
static void *trustix_aead_alloc_bpf_tfm(const char *algo)
{
	void *tfm;

	tfm = trustix_aead_alloc_from_crypto_tfm(trustix_alloc_kernel(algo),
						 false);
	if (!IS_ERR(tfm))
		((struct trustix_aead_tfm *)tfm)->bpf_tfm = true;
	return tfm;
}
#endif

static void *trustix_aead_alloc_waitable_tfm(const char *algo)
{
	return trustix_aead_alloc_tfm_mode(algo, true);
}

static void trustix_aead_free_tfm(void *tfm)
{
	struct trustix_aead_tfm *ctx = tfm;

	if (!ctx)
		return;
	if (ctx->req)
		free_percpu(ctx->req);
	if (ctx->sleep_req) {
		memzero_explicit(ctx->sleep_req, ctx->req_size);
		kfree(ctx->sleep_req);
	}
	if (ctx->tfm)
		crypto_free_aead(ctx->tfm);
	memzero_explicit(ctx->raw_key, sizeof(ctx->raw_key));
#if TRUSTIX_X86_SIMD
	memzero_explicit(ctx->vaes_rk, sizeof(ctx->vaes_rk));
	memzero_explicit(ctx->vaes_shash, sizeof(ctx->vaes_shash));
	memzero_explicit(ctx->vaes_shash4, sizeof(ctx->vaes_shash4));
#endif
	kfree(ctx);
}

#if TRUSTIX_ENABLE_BPF_CRYPTO
static int trustix_aead_has_algo(const char *algo)
{
	struct crypto_aead *tfm = trustix_alloc_sync_aead(algo);

	if (IS_ERR(tfm))
		return 0;
	crypto_free_aead(tfm);
	return 1;
}
#endif

static int trustix_aead_setkey(void *tfm, const u8 *key, unsigned int keylen)
{
	struct trustix_aead_tfm *ctx = tfm;
	int ret;

	if (!ctx || !ctx->tfm)
		return -EINVAL;
	ret = crypto_aead_setkey(ctx->tfm, key, keylen);
	if (ret)
		return ret;
	if (key && (keylen == 16 || keylen == 32)) {
		memcpy(ctx->raw_key, key, keylen);
		ctx->raw_key_len = keylen;
#if TRUSTIX_X86_SIMD
		ctx->vaes_ready = false;
#endif
	} else {
		memzero_explicit(ctx->raw_key, sizeof(ctx->raw_key));
		ctx->raw_key_len = 0;
#if TRUSTIX_X86_SIMD
		ctx->vaes_ready = false;
#endif
	}
	return 0;
}

static int trustix_aead_setauthsize(void *tfm, unsigned int authsize)
{
	struct trustix_aead_tfm *ctx = tfm;

	if (!ctx || !ctx->tfm)
		return -EINVAL;
	return crypto_aead_setauthsize(ctx->tfm, authsize);
}

static int trustix_aead_crypt(void *tfm, const u8 *src, u8 *dst, unsigned int len,
			      u8 *iv, bool encrypt)
{
	struct trustix_aead_tfm *ctx = tfm;
	struct aead_request *req;
	struct scatterlist src_sg, dst_sg;
	unsigned int authsize;
	unsigned int cryptlen;
	int ret;

	if (!ctx || !ctx->tfm || !src || !dst || !iv)
		return -EINVAL;

	authsize = crypto_aead_authsize(ctx->tfm);
	if (!authsize || len < authsize)
		return -EINVAL;

	/*
	 * bpf_crypto_* only passes one length, so TrustIX AEAD buffers reserve
	 * tag space in both source and destination dynptrs. Encrypt consumes
	 * len-authsize plaintext bytes and emits len bytes. Decrypt consumes len
	 * ciphertext+tag bytes and emits len-authsize plaintext bytes.
	 */
	cryptlen = encrypt ? len - authsize : len;

#if TRUSTIX_X86_SIMD && TRUSTIX_DEVICE_ONLY
	if (trustix_device_direct_aead) {
		struct trustix_aead_prepared_op op = {
			.nonce = iv,
			.src = (u8 *)src,
			.dst = dst,
			.in_len = encrypt ? cryptlen : len,
			.out_len = encrypt ? len : len - authsize,
		};
		__u32 successes = 0;

		ret = trustix_aead_try_direct_prepared_batch(
			ctx, encrypt ? 0 : TRUSTIX_AEAD_IOC_FLAG_DECRYPT,
			NULL, &op, 1, &successes);
		if (!ret && successes == 1)
			return 0;
		if (ret && ret != -EOPNOTSUPP)
			return ret;
	}
	if (ctx->may_async)
		return -EOPNOTSUPP;
#endif

#if TRUSTIX_X86_SIMD && !TRUSTIX_DEVICE_ONLY
	if (trustix_kfunc_simd_fastpath && trustix_experimental_vaes_kfunc) {
		struct trustix_aead_prepared_op op = {
			.nonce = iv,
			.src = (u8 *)src,
			.dst = dst,
			.in_len = encrypt ? cryptlen : len,
			.out_len = encrypt ? len : len - authsize,
		};
		__u32 successes = 0;

		if (trustix_kfunc_fastpath_stats)
			trustix_vaes_attempts++;
		if (trustix_vaes_available &&
		    (ctx->raw_key_len == 16 || ctx->raw_key_len == 32) &&
		    !trustix_aead_vaes_prepare_ctx(ctx)) {
			ret = trustix_aead_vaes_prepared_slice(
				ctx, encrypt ? 0 : TRUSTIX_AEAD_IOC_FLAG_DECRYPT,
				&op, 0, 1, &successes);
			if (!ret && successes == 1)
				return 0;
			if (ret && ret != -EOPNOTSUPP)
				return ret;
		}
		if (trustix_kfunc_fastpath_stats)
			trustix_vaes_fallbacks++;
	}
	if (trustix_kfunc_simd_fastpath && trustix_experimental_aesni_kfunc) {
		struct trustix_aead_prepared_op op = {
			.nonce = iv,
			.src = (u8 *)src,
			.dst = dst,
			.in_len = encrypt ? cryptlen : len,
			.out_len = encrypt ? len : len - authsize,
		};

		if (trustix_kfunc_fastpath_stats)
			trustix_aesni_attempts++;
		if (trustix_aesni_available &&
		    (ctx->raw_key_len == 16 || ctx->raw_key_len == 32) &&
		    !trustix_aead_vaes_prepare_ctx(ctx)) {
			if (!trustix_aead_fpu_begin())
				goto aesni_kfunc_fallback;
			ret = encrypt ?
				trustix_aead_aesni_seal_one(ctx->vaes_rk,
							    ctx->vaes_rounds,
							    ctx->vaes_shash,
							    ctx->vaes_shash4,
							    &op) :
				trustix_aead_aesni_open_one(ctx->vaes_rk,
							    ctx->vaes_rounds,
							    ctx->vaes_shash,
							    ctx->vaes_shash4,
							    &op);
			trustix_aead_fpu_end();
			if (!ret)
				return 0;
			if (ret != -EOPNOTSUPP)
				return ret;
		}
aesni_kfunc_fallback:
		if (trustix_kfunc_fastpath_stats)
			trustix_aesni_fallbacks++;
	}
#endif

#if TRUSTIX_ENABLE_BPF_CRYPTO
	if (ctx->bpf_tfm && ctx->may_async)
		return -EOPNOTSUPP;
#endif

	if (!ctx->req_size)
		return -EINVAL;

	if (ctx->sleep_req) {
		struct trustix_aead_wait wait;

		req = ctx->sleep_req;
		memset(req, 0, ctx->req_size);
		aead_request_set_tfm(req, ctx->tfm);
		sg_init_one(&src_sg, src, encrypt ? len - authsize : len);
		sg_init_one(&dst_sg, dst, encrypt ? len : len - authsize);
		init_completion(&wait.completion);
		wait.err = 0;
		aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
					  trustix_aead_complete, &wait);
		aead_request_set_ad(req, 0);
		aead_request_set_crypt(req, &src_sg, &dst_sg, cryptlen, iv);

		ret = encrypt ? crypto_aead_encrypt(req) :
				crypto_aead_decrypt(req);
		if (ret == -EINPROGRESS || ret == -EBUSY) {
			wait_for_completion(&wait.completion);
			ret = wait.err;
		}
		return ret;
	}

	if (!ctx->req)
		return -EINVAL;

	req = get_cpu_ptr(ctx->req);
	memset(req, 0, ctx->req_size);
	aead_request_set_tfm(req, ctx->tfm);
	sg_init_one(&src_sg, src, encrypt ? len - authsize : len);
	sg_init_one(&dst_sg, dst, encrypt ? len : len - authsize);
	aead_request_set_callback(req, 0, NULL, NULL);
	aead_request_set_ad(req, 0);
	aead_request_set_crypt(req, &src_sg, &dst_sg, cryptlen, iv);

	ret = encrypt ? crypto_aead_encrypt(req) : crypto_aead_decrypt(req);
	put_cpu_ptr(ctx->req);
	return ret;
}

static int trustix_aead_copy_key(__u64 key_ptr, __u32 key_len, u8 **key)
{
	if (!key_ptr || !key)
		return -EINVAL;
	if (key_len != 16 && key_len != 32)
		return -EINVAL;
	if (key_len > TRUSTIX_AEAD_IOC_KEY_MAX)
		return -EINVAL;

	*key = memdup_user((const void __user *)(unsigned long)key_ptr, key_len);
	if (IS_ERR(*key))
		return PTR_ERR(*key);
	return 0;
}

static void *trustix_aead_ioc_alloc_ctx(__u64 key_ptr, __u32 key_len,
					bool waitable)
{
	void *ctx;
	u8 *key;
	int ret;

	ret = trustix_aead_copy_key(key_ptr, key_len, &key);
	if (ret)
		return ERR_PTR(ret);

	ctx = waitable ? trustix_aead_alloc_waitable_tfm(TRUSTIX_GCM_AES) :
			 trustix_aead_alloc_tfm(TRUSTIX_GCM_AES);
	if (IS_ERR(ctx)) {
		ret = PTR_ERR(ctx);
		goto out_key;
	}

	ret = trustix_aead_setkey(ctx, key, key_len);
	if (ret)
		goto out_ctx;
	ret = trustix_aead_setauthsize(ctx, TRUSTIX_AEAD_IOC_TAG_LEN);
	if (ret)
		goto out_ctx;
	memcpy(((struct trustix_aead_tfm *)ctx)->raw_key, key, key_len);
	((struct trustix_aead_tfm *)ctx)->raw_key_len = key_len;
#if TRUSTIX_X86_SIMD
	((struct trustix_aead_tfm *)ctx)->vaes_ready = false;
#endif

	memzero_explicit(key, key_len);
	kfree(key);
	return ctx;

out_ctx:
	trustix_aead_free_tfm(ctx);
out_key:
	memzero_explicit(key, key_len);
	kfree(key);
	return ERR_PTR(ret);
}

static void trustix_aead_ioc_scratch_free(struct trustix_aead_ioc_scratch *scratch)
{
	if (!scratch)
		return;
	if (scratch->src) {
		memzero_explicit(scratch->src, scratch->src_cap);
		kfree(scratch->src);
	}
	if (scratch->dst) {
		memzero_explicit(scratch->dst, scratch->dst_cap);
		kfree(scratch->dst);
	}
	scratch->src = NULL;
	scratch->dst = NULL;
	scratch->src_cap = 0;
	scratch->dst_cap = 0;
}

static void trustix_aead_async_pool_free(struct trustix_aead_file *state)
{
	if (!state)
		return;
	if (state->async_req_mem) {
		memzero_explicit(state->async_req_mem,
				 state->async_req_stride * state->async_cap);
		kfree(state->async_req_mem);
	}
	kfree(state->async_ops);
	state->async_ops = NULL;
	state->async_req_mem = NULL;
	state->async_cap = 0;
	state->async_req_stride = 0;
}

static void trustix_aead_worker_pool_free(struct trustix_aead_file *state)
{
	if (!state)
		return;
	kfree(state->pool_workers);
	state->pool_workers = NULL;
	state->pool_worker_cap = 0;
}

static void trustix_aead_prepared_pool_free(struct trustix_aead_file *state)
{
	if (!state)
		return;
	kfree(state->prepared_ops);
	state->prepared_ops = NULL;
	state->prepared_cap = 0;
	state->prepared_count = 0;
	state->prepared_flags = 0;
}

static __u32 trustix_aead_next_op_cap(__u32 current_cap, __u32 need)
{
	__u32 cap = current_cap ? current_cap : 64;

	while (cap < need && cap < TRUSTIX_AEAD_IOC_BATCH_MAX_OPS / 2)
		cap *= 2;
	if (cap < need)
		cap = need;
	return cap;
}

static __u32 trustix_aead_ioc_next_cap(__u32 current_cap, __u32 need)
{
	__u32 cap = current_cap ? current_cap : 2048;
	__u32 max = TRUSTIX_AEAD_IOC_INPUT_MAX + TRUSTIX_AEAD_IOC_TAG_LEN;

	if (!need)
		need = 1;
	while (cap < need && cap < max / 2)
		cap *= 2;
	if (cap < need)
		cap = need;
	return cap;
}

static int trustix_aead_ioc_ensure_buf(u8 **buf, __u32 *cap, __u32 need)
{
	u8 *next;
	__u32 next_cap;

	if (!buf || !cap)
		return -EINVAL;
	if (!need)
		need = 1;
	if (*buf && *cap >= need)
		return 0;

	next_cap = trustix_aead_ioc_next_cap(*cap, need);
	next = kmalloc(next_cap, GFP_KERNEL);
	if (!next)
		return -ENOMEM;
	if (*buf) {
		memzero_explicit(*buf, *cap);
		kfree(*buf);
	}
	*buf = next;
	*cap = next_cap;
	return 0;
}

static int trustix_aead_ioc_validate_lengths(__u32 flags, __u32 in_len,
					     __u32 out_capacity,
					     __u32 *crypt_len,
					     __u32 *out_len)
{
	bool decrypt = flags & TRUSTIX_AEAD_IOC_FLAG_DECRYPT;

	if (flags & ~TRUSTIX_AEAD_IOC_FLAG_DECRYPT)
		return -EINVAL;
	if (in_len > TRUSTIX_AEAD_IOC_INPUT_MAX)
		return -EINVAL;
	if (decrypt) {
		if (in_len < TRUSTIX_AEAD_IOC_TAG_LEN)
			return -EINVAL;
		*out_len = in_len - TRUSTIX_AEAD_IOC_TAG_LEN;
		*crypt_len = in_len;
	} else {
		if (in_len > TRUSTIX_AEAD_IOC_INPUT_MAX - TRUSTIX_AEAD_IOC_TAG_LEN)
			return -EINVAL;
		*out_len = in_len + TRUSTIX_AEAD_IOC_TAG_LEN;
		*crypt_len = *out_len;
	}
	if (out_capacity < *out_len)
		return -ENOSPC;
	return 0;
}

static int trustix_aead_ioc_run(void *ctx,
				struct trustix_aead_ioc_scratch *scratch,
				__u32 flags, __u64 nonce_ptr, __u32 nonce_len,
				__u64 in_ptr, __u32 in_len, __u64 out_ptr,
				__u32 out_capacity, __u32 *actual_out_len)
{
	bool decrypt = flags & TRUSTIX_AEAD_IOC_FLAG_DECRYPT;
	u8 nonce[TRUSTIX_AEAD_IOC_NONCE_LEN];
	__u32 crypt_len;
	__u32 out_len;
	int ret;

	if (!ctx || !scratch || !nonce_ptr || !in_ptr || !out_ptr ||
	    !actual_out_len)
		return -EINVAL;
	if (nonce_len != TRUSTIX_AEAD_IOC_NONCE_LEN)
		return -EINVAL;
	ret = trustix_aead_ioc_validate_lengths(flags, in_len, out_capacity,
						&crypt_len, &out_len);
	if (ret)
		return ret;
	if (copy_from_user(nonce, (const void __user *)(unsigned long)nonce_ptr,
			   sizeof(nonce)))
		return -EFAULT;
	ret = trustix_aead_ioc_ensure_buf(&scratch->src, &scratch->src_cap,
					  in_len);
	if (ret)
		goto out;
	ret = trustix_aead_ioc_ensure_buf(&scratch->dst, &scratch->dst_cap,
					  out_len);
	if (ret)
		goto out;
	if (copy_from_user(scratch->src,
			   (const void __user *)(unsigned long)in_ptr, in_len)) {
		ret = -EFAULT;
		goto out;
	}

	ret = trustix_aead_crypt(ctx, scratch->src, scratch->dst, crypt_len,
				 nonce, !decrypt);
	if (ret)
		goto out;
	if (copy_to_user((void __user *)(unsigned long)out_ptr, scratch->dst,
			 out_len)) {
		ret = -EFAULT;
		goto out;
	}
	*actual_out_len = out_len;

out:
	memzero_explicit(nonce, sizeof(nonce));
	return ret;
}

static int trustix_aead_pool_ptr(struct trustix_aead_file *state, __u64 off,
				 __u32 len, u8 **ptr)
{
	if (!state || !state->pool || !ptr)
		return -EINVAL;
	if (off > state->pool_size)
		return -EINVAL;
	if ((__u64)len > (__u64)state->pool_size - off)
		return -EINVAL;
	*ptr = (u8 *)state->pool + off;
	return 0;
}

static int trustix_aead_pool_validate_overlap(__u64 in_off, __u32 in_len,
					      __u64 out_off, __u32 out_len)
{
	__u64 in_end = in_off + in_len;
	__u64 out_end = out_off + out_len;

	if (in_off == out_off)
		return 0;
	if (in_end <= out_off || out_end <= in_off)
		return 0;
	return -EINVAL;
}

static int trustix_aead_ioc_pool_prepare_async(struct trustix_aead_tfm *ctx,
					       struct trustix_aead_file *state,
					       __u32 flags,
					       struct trustix_aead_ioc_pool_op *op,
					       struct trustix_aead_pool_async_op *async)
{
	bool decrypt = flags & TRUSTIX_AEAD_IOC_FLAG_DECRYPT;
	u8 *nonce;
	u8 *src;
	u8 *dst;
	__u32 crypt_len;
	__u32 out_len;
	int ret;

	if (!ctx || !ctx->tfm || !state || !op || !async || !async->req)
		return -EINVAL;
	if (op->nonce_len != TRUSTIX_AEAD_IOC_NONCE_LEN)
		return -EINVAL;
	ret = trustix_aead_ioc_validate_lengths(flags, op->in_len, op->out_len,
						&crypt_len, &out_len);
	if (ret)
		return ret;
	(void)crypt_len;
	(void)crypt_len;
	ret = trustix_aead_pool_ptr(state, op->nonce_off, op->nonce_len, &nonce);
	if (ret)
		return ret;
	ret = trustix_aead_pool_ptr(state, op->in_off, op->in_len, &src);
	if (ret)
		return ret;
	ret = trustix_aead_pool_ptr(state, op->out_off, out_len, &dst);
	if (ret)
		return ret;
	ret = trustix_aead_pool_validate_overlap(op->in_off, op->in_len,
						 op->out_off, out_len);
	if (ret)
		return ret;

	sg_init_one(&async->src_sg, src, op->in_len);
	sg_init_one(&async->dst_sg, dst, out_len);
	init_completion(&async->wait.completion);
	async->wait.err = 0;
	async->out_len = out_len;
	async->ret = 0;
	async->needs_wait = false;

	aead_request_set_tfm(async->req, ctx->tfm);
	aead_request_set_callback(async->req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				  trustix_aead_complete, &async->wait);
	aead_request_set_ad(async->req, 0);
	aead_request_set_crypt(async->req, &async->src_sg, &async->dst_sg,
			       op->in_len, nonce);
	async->ret = decrypt ? crypto_aead_decrypt(async->req) :
			       crypto_aead_encrypt(async->req);
	if (async->ret == -EINPROGRESS || async->ret == -EBUSY)
		async->needs_wait = true;
	return 0;
}

static int trustix_aead_ioc_pool_run_sync_one(struct trustix_aead_tfm *ctx,
					      struct trustix_aead_file *state,
					      __u32 flags,
					      struct trustix_aead_ioc_pool_op *op,
					      struct aead_request *req)
{
	bool decrypt = flags & TRUSTIX_AEAD_IOC_FLAG_DECRYPT;
	struct scatterlist src_sg, dst_sg;
	u8 *nonce;
	u8 *src;
	u8 *dst;
	__u32 crypt_len;
	__u32 out_len;
	int ret;

	if (!ctx || !ctx->tfm || !state || !op || !req)
		return -EINVAL;
	if (op->nonce_len != TRUSTIX_AEAD_IOC_NONCE_LEN)
		return -EINVAL;
	ret = trustix_aead_ioc_validate_lengths(flags, op->in_len, op->out_len,
						&crypt_len, &out_len);
	if (ret)
		return ret;
	ret = trustix_aead_pool_ptr(state, op->nonce_off, op->nonce_len, &nonce);
	if (ret)
		return ret;
	ret = trustix_aead_pool_ptr(state, op->in_off, op->in_len, &src);
	if (ret)
		return ret;
	ret = trustix_aead_pool_ptr(state, op->out_off, out_len, &dst);
	if (ret)
		return ret;
	ret = trustix_aead_pool_validate_overlap(op->in_off, op->in_len,
						 op->out_off, out_len);
	if (ret)
		return ret;

	sg_init_one(&src_sg, src, op->in_len);
	sg_init_one(&dst_sg, dst, out_len);
	aead_request_set_tfm(req, ctx->tfm);
	aead_request_set_callback(req, 0, NULL, NULL);
	aead_request_set_ad(req, 0);
	aead_request_set_crypt(req, &src_sg, &dst_sg, op->in_len, nonce);

	ret = decrypt ? crypto_aead_decrypt(req) : crypto_aead_encrypt(req);
	if (!ret)
		op->out_len = out_len;
	return ret;
}

static int trustix_aead_ioc_prepare_pool_one(struct trustix_aead_file *state,
					     __u32 flags,
					     struct trustix_aead_ioc_pool_op *op,
					     struct trustix_aead_prepared_op *prepared)
{
	u8 *nonce;
	u8 *src;
	u8 *dst;
	__u32 crypt_len;
	__u32 out_len;
	int ret;

	if (!state || !op || !prepared)
		return -EINVAL;
	if (op->nonce_len != TRUSTIX_AEAD_IOC_NONCE_LEN)
		return -EINVAL;
	ret = trustix_aead_ioc_validate_lengths(flags, op->in_len, op->out_len,
						&crypt_len, &out_len);
	if (ret)
		return ret;
	(void)crypt_len;
	ret = trustix_aead_pool_ptr(state, op->nonce_off, op->nonce_len, &nonce);
	if (ret)
		return ret;
	ret = trustix_aead_pool_ptr(state, op->in_off, op->in_len, &src);
	if (ret)
		return ret;
	ret = trustix_aead_pool_ptr(state, op->out_off, out_len, &dst);
	if (ret)
		return ret;
	ret = trustix_aead_pool_validate_overlap(op->in_off, op->in_len,
						 op->out_off, out_len);
	if (ret)
		return ret;

	prepared->nonce = nonce;
	prepared->src = src;
	prepared->dst = dst;
	prepared->in_len = op->in_len;
	prepared->out_len = out_len;
	prepared->pool_out_len = &op->out_len;
	prepared->pool_result = &op->result;
	op->out_len = out_len;
	op->result = 0;
	return 0;
}

static int trustix_aead_ioc_pool_run_prepared_sync_one(struct trustix_aead_tfm *ctx,
						       __u32 flags,
						       struct trustix_aead_prepared_op *op,
						       struct aead_request *req)
{
	bool decrypt = flags & TRUSTIX_AEAD_IOC_FLAG_DECRYPT;
	struct scatterlist src_sg, dst_sg;

	if (!ctx || !ctx->tfm || !op || !req || !op->nonce || !op->src ||
	    !op->dst)
		return -EINVAL;

	sg_init_one(&src_sg, op->src, op->in_len);
	sg_init_one(&dst_sg, op->dst, op->out_len);
	aead_request_set_tfm(req, ctx->tfm);
	aead_request_set_callback(req, 0, NULL, NULL);
	aead_request_set_ad(req, 0);
	aead_request_set_crypt(req, &src_sg, &dst_sg, op->in_len, op->nonce);

	return decrypt ? crypto_aead_decrypt(req) : crypto_aead_encrypt(req);
}

static int trustix_aead_ioc_pool_prepare_prepared_async(struct trustix_aead_tfm *ctx,
							__u32 flags,
							struct trustix_aead_prepared_op *op,
							struct trustix_aead_pool_async_op *async)
{
	bool decrypt = flags & TRUSTIX_AEAD_IOC_FLAG_DECRYPT;

	if (!ctx || !ctx->tfm || !op || !async || !async->req || !op->nonce ||
	    !op->src || !op->dst)
		return -EINVAL;

	sg_init_one(&async->src_sg, op->src, op->in_len);
	sg_init_one(&async->dst_sg, op->dst, op->out_len);
	init_completion(&async->wait.completion);
	async->wait.err = 0;
	async->out_len = op->out_len;
	async->ret = 0;
	async->needs_wait = false;

	aead_request_set_tfm(async->req, ctx->tfm);
	aead_request_set_callback(async->req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				  trustix_aead_complete, &async->wait);
	aead_request_set_ad(async->req, 0);
	aead_request_set_crypt(async->req, &async->src_sg, &async->dst_sg,
			       op->in_len, op->nonce);
	async->ret = decrypt ? crypto_aead_decrypt(async->req) :
			       crypto_aead_encrypt(async->req);
	if (async->ret == -EINPROGRESS || async->ret == -EBUSY)
		async->needs_wait = true;
	return 0;
}

static int trustix_aead_ioc_ensure_async_pool(struct trustix_aead_file *state,
					      struct trustix_aead_tfm *ctx,
					      __u32 op_count)
{
	struct trustix_aead_pool_async_op *ops;
	void *req_mem;
	__u32 cap;
	size_t stride;

	if (!state || !ctx || !ctx->req_size || !op_count ||
	    op_count > TRUSTIX_AEAD_IOC_BATCH_MAX_OPS)
		return -EINVAL;
	stride = ALIGN(ctx->req_size, __alignof__(struct aead_request));
	if (state->async_ops && state->async_req_mem &&
	    state->async_cap >= op_count && state->async_req_stride == stride)
		return 0;

	cap = trustix_aead_next_op_cap(state->async_cap, op_count);
	ops = kcalloc(cap, sizeof(*ops), GFP_KERNEL);
	if (!ops)
		return -ENOMEM;
	req_mem = kcalloc(cap, stride, GFP_KERNEL);
	if (!req_mem) {
		kfree(ops);
		return -ENOMEM;
	}

	trustix_aead_async_pool_free(state);
	state->async_ops = ops;
	state->async_req_mem = req_mem;
	state->async_cap = cap;
	state->async_req_stride = stride;
	return 0;
}

static int trustix_aead_ioc_ensure_worker_pool(struct trustix_aead_file *state,
					       __u32 worker_count)
{
	struct trustix_aead_pool_worker *workers;
	__u32 cap;

	if (!state || worker_count > TRUSTIX_AEAD_IOC_BATCH_MAX_OPS)
		return -EINVAL;
	if (worker_count <= 1)
		return 0;
	if (state->pool_workers && state->pool_worker_cap >= worker_count)
		return 0;

	cap = trustix_aead_next_op_cap(state->pool_worker_cap, worker_count);
	workers = kcalloc(cap, sizeof(*workers), GFP_KERNEL);
	if (!workers)
		return -ENOMEM;
	kfree(state->pool_workers);
	state->pool_workers = workers;
	state->pool_worker_cap = cap;
	return 0;
}

static int trustix_aead_ioc_ensure_prepared_pool(struct trustix_aead_file *state,
						 __u32 op_count)
{
	struct trustix_aead_prepared_op *ops;
	__u32 cap;

	if (!state || !op_count || op_count > TRUSTIX_AEAD_IOC_BATCH_MAX_OPS)
		return -EINVAL;
	if (state->prepared_ops && state->prepared_cap >= op_count)
		return 0;

	cap = trustix_aead_next_op_cap(state->prepared_cap, op_count);
	ops = kcalloc(cap, sizeof(*ops), GFP_KERNEL);
	if (!ops)
		return -ENOMEM;
	kfree(state->prepared_ops);
	state->prepared_ops = ops;
	state->prepared_cap = cap;
	state->prepared_count = 0;
	state->prepared_flags = 0;
	return 0;
}

static int trustix_aead_ioc_pool_run_async_slice(struct trustix_aead_tfm *ctx,
						 struct trustix_aead_file *state,
						 __u32 flags,
						 struct trustix_aead_ioc_pool_op *ops,
						 struct trustix_aead_pool_async_op *async,
						 __u32 start, __u32 count,
						 size_t req_stride,
						 __u32 *successes)
{
	int first_err = 0;
	__u32 ok = 0;
	__u32 i;
	__u32 end = start + count;

	if (!ctx || !ctx->tfm || !state || !ops || !async || !successes ||
	    !ctx->req_size)
		return -EINVAL;

	for (i = start; i < end; i++) {
		async[i].req = (struct aead_request *)((u8 *)state->async_req_mem +
						       i * req_stride);
		ops[i].result = trustix_aead_ioc_pool_prepare_async(ctx, state,
								    flags,
								    &ops[i],
								    &async[i]);
		if (ops[i].result && !first_err)
			first_err = ops[i].result;
	}

	for (i = start; i < end; i++) {
		if (ops[i].result)
			continue;
		if (async[i].needs_wait) {
			wait_for_completion(&async[i].wait.completion);
			async[i].ret = async[i].wait.err;
		}
		ops[i].result = async[i].ret;
		if (!ops[i].result) {
			ops[i].out_len = async[i].out_len;
			ok++;
		} else if (!first_err) {
			first_err = ops[i].result;
		}
	}

	*successes = ok;
	return first_err;
}

static int trustix_aead_ioc_pool_run_sync_slice(struct trustix_aead_tfm *ctx,
						struct trustix_aead_file *state,
						__u32 flags,
						struct trustix_aead_ioc_pool_op *ops,
						__u32 start, __u32 count,
						size_t req_stride,
						__u32 *successes)
{
	struct aead_request *req;
	int first_err = 0;
	__u32 ok = 0;
	__u32 i;
	__u32 end = start + count;

	if (!ctx || !ctx->tfm || !state || !ops || !successes ||
	    !state->async_req_mem || !ctx->req_size)
		return -EINVAL;

	req = (struct aead_request *)((u8 *)state->async_req_mem +
				      start * req_stride);
	for (i = start; i < end; i++) {
		ops[i].result = trustix_aead_ioc_pool_run_sync_one(ctx, state,
								   flags,
								   &ops[i],
								   req);
		if (!ops[i].result) {
			ok++;
		} else if (!first_err) {
			first_err = ops[i].result;
		}
	}

	*successes = ok;
	return first_err;
}

static int trustix_aead_ioc_pool_run_prepared_sync_slice(struct trustix_aead_tfm *ctx,
							 struct trustix_aead_file *state,
							 __u32 flags,
							 struct trustix_aead_prepared_op *ops,
							 __u32 start, __u32 count,
							 size_t req_stride,
							 __u32 *successes)
{
	struct aead_request *req;
	int first_err = 0;
	__u32 ok = 0;
	__u32 i;
	__u32 end = start + count;

	if (!ctx || !ctx->tfm || !state || !ops || !successes ||
	    !state->async_req_mem || !ctx->req_size)
		return -EINVAL;

	req = (struct aead_request *)((u8 *)state->async_req_mem +
				      start * req_stride);
	for (i = start; i < end; i++) {
		int ret = trustix_aead_ioc_pool_run_prepared_sync_one(ctx,
								      flags,
								      &ops[i],
								      req);
		trustix_aead_prepared_set_result(&ops[i], ret);

		if (!ret) {
			ok++;
		} else if (!first_err) {
			first_err = ret;
		}
	}

	*successes = ok;
	return first_err;
}

static int trustix_aead_ioc_pool_run_prepared_async_slice(struct trustix_aead_tfm *ctx,
							  struct trustix_aead_file *state,
							  __u32 flags,
							  struct trustix_aead_prepared_op *ops,
							  struct trustix_aead_pool_async_op *async,
							  __u32 start, __u32 count,
							  size_t req_stride,
							  __u32 *successes)
{
	int first_err = 0;
	__u32 ok = 0;
	__u32 i;
	__u32 end = start + count;

	if (!ctx || !ctx->tfm || !state || !ops || !async || !successes ||
	    !state->async_req_mem || !ctx->req_size)
		return -EINVAL;

	for (i = start; i < end; i++) {
		async[i].req = (struct aead_request *)((u8 *)state->async_req_mem +
						       i * req_stride);
		async[i].ret = trustix_aead_ioc_pool_prepare_prepared_async(
			ctx, flags, &ops[i], &async[i]);
		trustix_aead_prepared_set_result(&ops[i], async[i].ret);
		if (async[i].ret && !first_err)
			first_err = async[i].ret;
	}

	for (i = start; i < end; i++) {
		if (async[i].ret && async[i].ret != -EINPROGRESS &&
		    async[i].ret != -EBUSY)
			continue;
		if (async[i].needs_wait) {
			wait_for_completion(&async[i].wait.completion);
			async[i].ret = async[i].wait.err;
		}
		trustix_aead_prepared_set_result(&ops[i], async[i].ret);
		if (!async[i].ret) {
			ok++;
		} else if (!first_err) {
			first_err = async[i].ret;
		}
	}

	*successes = ok;
	return first_err;
}

#if TRUSTIX_X86_SIMD
static int trustix_aead_vaes_prepared_slice(struct trustix_aead_tfm *ctx,
					    __u32 flags,
					    struct trustix_aead_prepared_op *ops,
					    __u32 start, __u32 count,
					    __u32 *successes);
#endif

static void trustix_aead_ioc_pool_worker(struct work_struct *work)
{
	struct trustix_aead_pool_worker *worker =
		container_of(work, struct trustix_aead_pool_worker, work);

#if TRUSTIX_X86_SIMD
	if (worker->vaes)
		worker->ret =
			trustix_aead_vaes_prepared_slice(worker->ctx,
							 worker->flags,
							 worker->prepared,
							 worker->start,
							 worker->count,
							 &worker->successes);
	else if (worker->aesni)
		worker->ret =
			trustix_aead_aesni_prepared_slice(worker->ctx,
							  worker->flags,
							  worker->prepared,
							  worker->start,
							  worker->count,
							  &worker->successes);
	else
#endif
	if (worker->prepared && worker->ctx && worker->ctx->may_async)
		worker->ret =
			trustix_aead_ioc_pool_run_prepared_async_slice(worker->ctx,
								       worker->state,
								       worker->flags,
								       worker->prepared,
								       worker->async,
								       worker->start,
								       worker->count,
								  worker->req_stride,
								  &worker->successes);
	else if (worker->prepared)
		worker->ret =
			trustix_aead_ioc_pool_run_prepared_sync_slice(worker->ctx,
								      worker->state,
								      worker->flags,
								      worker->prepared,
								      worker->start,
								      worker->count,
								      worker->req_stride,
								      &worker->successes);
	else if (worker->ctx && worker->ctx->may_async)
		worker->ret = trustix_aead_ioc_pool_run_async_slice(worker->ctx,
								    worker->state,
								    worker->flags,
								    worker->ops,
								    worker->async,
								    worker->start,
								    worker->count,
								    worker->req_stride,
								    &worker->successes);
	else
		worker->ret = trustix_aead_ioc_pool_run_sync_slice(worker->ctx,
								   worker->state,
								   worker->flags,
								   worker->ops,
								   worker->start,
								   worker->count,
								   worker->req_stride,
								   &worker->successes);
	complete(&worker->done);
}

static __u32 trustix_aead_pool_worker_count(__u32 op_count)
{
	unsigned int cpus = num_online_cpus();
	unsigned int max_workers = trustix_pool_parallelism;
	unsigned int workers;

	if (op_count < 128 || cpus <= 1)
		return 1;
	if (!max_workers) {
		if (op_count >= 2048)
			max_workers = 16;
		else if (op_count >= 512)
			max_workers = 8;
		else
			max_workers = 4;
	}
	if (max_workers > cpus)
		max_workers = cpus;
	if (max_workers > 16)
		max_workers = 16;
	workers = op_count / 32;
	if (!workers)
		workers = 1;
	if (workers > max_workers)
		workers = max_workers;
	if (workers > op_count)
		workers = op_count;
	return workers ? workers : 1;
}

static int trustix_aead_ioc_pool_run_async_batch(void *raw_ctx,
						 struct trustix_aead_file *state,
						 __u32 flags,
						 struct trustix_aead_ioc_pool_op *ops,
						 __u32 op_count,
						 __u32 *successes)
{
	struct trustix_aead_tfm *ctx = raw_ctx;
	struct trustix_aead_pool_async_op *async;
	struct trustix_aead_pool_worker *workers = NULL;
	size_t req_stride;
	__u32 worker_count;
	__u32 base;
	__u32 rem;
	__u32 offset = 0;
	__u32 ok = 0;
	int first_err = 0;
	int ret;
	__u32 i;

	if (!ctx || !ctx->tfm || !ops || !successes || !ctx->req_size)
		return -EINVAL;
	ret = trustix_aead_ioc_ensure_async_pool(state, ctx, op_count);
	if (ret)
		return ret;
	async = state->async_ops;
	req_stride = state->async_req_stride;
	worker_count = trustix_aead_pool_worker_count(op_count);
	if (worker_count <= 1) {
		if (ctx->may_async)
			ret = trustix_aead_ioc_pool_run_async_slice(ctx, state,
								    flags, ops,
								    async, 0,
								    op_count,
								    req_stride,
								    successes);
		else
			ret = trustix_aead_ioc_pool_run_sync_slice(ctx, state,
								   flags, ops,
								   0,
								   op_count,
								   req_stride,
								   successes);
		return ret;
	}

	ret = trustix_aead_ioc_ensure_worker_pool(state, worker_count);
	if (ret) {
		if (ctx->may_async)
			return trustix_aead_ioc_pool_run_async_slice(ctx, state,
								     flags, ops,
								     async, 0,
								     op_count,
								     req_stride,
								     successes);
		return trustix_aead_ioc_pool_run_sync_slice(ctx, state, flags,
							    ops, 0, op_count,
							    req_stride,
							    successes);
	}
	workers = state->pool_workers;
	base = op_count / worker_count;
	rem = op_count % worker_count;
	for (i = 0; i < worker_count; i++) {
		__u32 count = base + (i < rem ? 1 : 0);

		workers[i].state = state;
		workers[i].ctx = ctx;
		workers[i].ops = ops;
		workers[i].prepared = NULL;
		workers[i].async = async;
		workers[i].req_stride = req_stride;
		workers[i].start = offset;
		workers[i].count = count;
		workers[i].flags = flags;
		workers[i].successes = 0;
		workers[i].ret = 0;
		workers[i].vaes = false;
		workers[i].aesni = false;
		init_completion(&workers[i].done);
		INIT_WORK(&workers[i].work, trustix_aead_ioc_pool_worker);
		queue_work(system_unbound_wq, &workers[i].work);
		offset += count;
	}

	for (i = 0; i < worker_count; i++) {
		wait_for_completion(&workers[i].done);
		ok += workers[i].successes;
		if (workers[i].ret && !first_err)
			first_err = workers[i].ret;
	}
	*successes = ok;
	return first_err;
}

static int trustix_aead_ioc_pool_run_prepared_batch(void *raw_ctx,
						    struct trustix_aead_file *state,
						    __u32 flags,
						    struct trustix_aead_prepared_op *ops,
						    __u32 op_count,
						    __u32 *successes)
{
	struct trustix_aead_tfm *ctx = raw_ctx;
	struct trustix_aead_pool_async_op *async;
	struct trustix_aead_pool_worker *workers = NULL;
	size_t req_stride;
	__u32 worker_count;
	__u32 base;
	__u32 rem;
	__u32 offset = 0;
	__u32 ok = 0;
	int first_err = 0;
	int ret;
	__u32 i;

	if (!ctx || !ctx->tfm || !state || !ops || !successes ||
	    !ctx->req_size)
		return -EINVAL;

	ret = trustix_aead_try_direct_prepared_batch(ctx, flags, state, ops,
						    op_count, successes);
	if (ret != -EOPNOTSUPP)
		return ret;
#if TRUSTIX_DEVICE_ONLY
	if (ctx->may_async)
		return -EOPNOTSUPP;
#endif

	ret = trustix_aead_ioc_ensure_async_pool(state, ctx, op_count);
	if (ret)
		return ret;
	async = state->async_ops;
	req_stride = state->async_req_stride;
	worker_count = trustix_aead_pool_worker_count(op_count);
	if (worker_count <= 1) {
		if (ctx->may_async)
			return trustix_aead_ioc_pool_run_prepared_async_slice(
				ctx, state, flags, ops, async, 0, op_count,
				req_stride, successes);
		return trustix_aead_ioc_pool_run_prepared_sync_slice(ctx, state,
								     flags, ops,
								     0,
								     op_count,
								     req_stride,
								     successes);
	}

	ret = trustix_aead_ioc_ensure_worker_pool(state, worker_count);
	if (ret) {
		if (ctx->may_async)
			return trustix_aead_ioc_pool_run_prepared_async_slice(
				ctx, state, flags, ops, async, 0, op_count,
				req_stride, successes);
		return trustix_aead_ioc_pool_run_prepared_sync_slice(ctx, state,
								     flags, ops,
								     0,
								     op_count,
								     req_stride,
								     successes);
	}
	workers = state->pool_workers;
	base = op_count / worker_count;
	rem = op_count % worker_count;
	for (i = 0; i < worker_count; i++) {
		__u32 count = base + (i < rem ? 1 : 0);

		workers[i].state = state;
		workers[i].ctx = ctx;
		workers[i].ops = NULL;
		workers[i].prepared = ops;
		workers[i].async = async;
		workers[i].req_stride = req_stride;
		workers[i].start = offset;
		workers[i].count = count;
		workers[i].flags = flags;
		workers[i].successes = 0;
		workers[i].ret = 0;
		workers[i].vaes = false;
		workers[i].aesni = false;
		init_completion(&workers[i].done);
		INIT_WORK(&workers[i].work, trustix_aead_ioc_pool_worker);
		queue_work(system_unbound_wq, &workers[i].work);
		offset += count;
	}

	for (i = 0; i < worker_count; i++) {
		wait_for_completion(&workers[i].done);
		ok += workers[i].successes;
		if (workers[i].ret && !first_err)
			first_err = workers[i].ret;
		workers[i].prepared = NULL;
		workers[i].vaes = false;
		workers[i].aesni = false;
	}
	*successes = ok;
	return first_err;
}

#if TRUSTIX_X86_SIMD
#define TRUSTIX_VAES_ASM_TARGET \
	__attribute__((__target__("sse2,aes,pclmul,avx2,vaes,vpclmulqdq"), __noinline__))

struct trustix_u128_be {
	u64 hi;
	u64 lo;
};

static const u8 trustix_aes_sbox[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
	0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
	0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
	0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
	0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
	0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
	0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
	0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
	0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
	0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
	0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
	0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
	0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
	0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
	0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
	0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
	0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

static const u8 trustix_clmul_bswap[16] __aligned(16) = {
	0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
	0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
};

static const u8 trustix_clmul_poly[16] __aligned(16) = {
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc2,
};

static const u8 trustix_clmul_two_one[16] __aligned(16) = {
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
};

static u64 trustix_load_be64(const u8 *p)
{
	return ((u64)p[0] << 56) | ((u64)p[1] << 48) |
	       ((u64)p[2] << 40) | ((u64)p[3] << 32) |
	       ((u64)p[4] << 24) | ((u64)p[5] << 16) |
	       ((u64)p[6] << 8) | (u64)p[7];
}

static void trustix_store_be64(u8 *p, u64 v)
{
	p[0] = (u8)(v >> 56);
	p[1] = (u8)(v >> 48);
	p[2] = (u8)(v >> 40);
	p[3] = (u8)(v >> 32);
	p[4] = (u8)(v >> 24);
	p[5] = (u8)(v >> 16);
	p[6] = (u8)(v >> 8);
	p[7] = (u8)v;
}

static void trustix_store_le64(u8 *p, u64 v)
{
	p[0] = (u8)v;
	p[1] = (u8)(v >> 8);
	p[2] = (u8)(v >> 16);
	p[3] = (u8)(v >> 24);
	p[4] = (u8)(v >> 32);
	p[5] = (u8)(v >> 40);
	p[6] = (u8)(v >> 48);
	p[7] = (u8)(v >> 56);
}

static __maybe_unused void trustix_store_u128_be(u8 *p,
						 struct trustix_u128_be v)
{
	trustix_store_be64(p, v.hi);
	trustix_store_be64(p + 8, v.lo);
}

static void trustix_load_u128_be(struct trustix_u128_be *v, const u8 *p)
{
	v->hi = trustix_load_be64(p);
	v->lo = trustix_load_be64(p + 8);
}

static __maybe_unused void trustix_gf128_mul(struct trustix_u128_be *z,
					     struct trustix_u128_be x,
					     struct trustix_u128_be h)
{
	struct trustix_u128_be v = h;
	u64 zh = 0;
	u64 zl = 0;
	int i;

	for (i = 0; i < 128; i++) {
		bool bit;
		bool lsb;

		if (i < 64)
			bit = (x.hi >> (63 - i)) & 1;
		else
			bit = (x.lo >> (127 - i)) & 1;
		if (bit) {
			zh ^= v.hi;
			zl ^= v.lo;
		}
		lsb = v.lo & 1;
		v.lo = (v.lo >> 1) | (v.hi << 63);
		v.hi >>= 1;
		if (lsb)
			v.hi ^= 0xe100000000000000ULL;
	}
	z->hi = zh;
	z->lo = zl;
}

static __maybe_unused void trustix_ghash_block(struct trustix_u128_be *y,
					       struct trustix_u128_be h,
					       const u8 *block)
{
	struct trustix_u128_be x;

	trustix_load_u128_be(&x, block);
	y->hi ^= x.hi;
	y->lo ^= x.lo;
	trustix_gf128_mul(y, *y, h);
}

static __maybe_unused void trustix_ghash_partial(struct trustix_u128_be *y,
						 struct trustix_u128_be h,
						 const u8 *block,
						 unsigned int len)
{
	u8 tmp[16] = {};

	memcpy(tmp, block, len);
	trustix_ghash_block(y, h, tmp);
	memzero_explicit(tmp, sizeof(tmp));
}

static __maybe_unused void
trustix_ghash_build_table(struct trustix_u128_be table[32][16],
			  struct trustix_u128_be h)
{
	unsigned int pos;
	unsigned int nibble;

	for (pos = 0; pos < 32; pos++) {
		for (nibble = 1; nibble < 16; nibble++) {
			struct trustix_u128_be x = {};

			if (pos < 16)
				x.hi = (u64)nibble << (60 - 4 * pos);
			else
				x.lo = (u64)nibble << (60 - 4 * (pos - 16));
			trustix_gf128_mul(&table[pos][nibble], x, h);
		}
	}
}

static __maybe_unused void
trustix_ghash_block_table(struct trustix_u128_be *y,
			  struct trustix_u128_be table[32][16],
			  const u8 *block)
{
	u64 hi = y->hi ^ trustix_load_be64(block);
	u64 lo = y->lo ^ trustix_load_be64(block + 8);
	struct trustix_u128_be z = {};
	unsigned int pos;

	for (pos = 0; pos < 16; pos++) {
		unsigned int nibble = (hi >> (60 - 4 * pos)) & 0xf;

		z.hi ^= table[pos][nibble].hi;
		z.lo ^= table[pos][nibble].lo;
	}
	for (pos = 0; pos < 16; pos++) {
		unsigned int nibble = (lo >> (60 - 4 * pos)) & 0xf;

		z.hi ^= table[pos + 16][nibble].hi;
		z.lo ^= table[pos + 16][nibble].lo;
	}
	*y = z;
}

static __maybe_unused void
trustix_ghash_partial_table(struct trustix_u128_be *y,
			    struct trustix_u128_be table[32][16],
			    const u8 *block,
			    unsigned int len)
{
	u8 tmp[16] = {};

	memcpy(tmp, block, len);
	trustix_ghash_block_table(y, table, tmp);
	memzero_explicit(tmp, sizeof(tmp));
}

static u32 trustix_aes_load_word(const u8 *p)
{
	return ((u32)p[0] << 24) | ((u32)p[1] << 16) |
	       ((u32)p[2] << 8) | (u32)p[3];
}

static void trustix_aes_store_word(u8 *p, u32 v)
{
	p[0] = (u8)(v >> 24);
	p[1] = (u8)(v >> 16);
	p[2] = (u8)(v >> 8);
	p[3] = (u8)v;
}

static u32 trustix_aes_sub_word(u32 w)
{
	return ((u32)trustix_aes_sbox[(w >> 24) & 0xff] << 24) |
	       ((u32)trustix_aes_sbox[(w >> 16) & 0xff] << 16) |
	       ((u32)trustix_aes_sbox[(w >> 8) & 0xff] << 8) |
	       (u32)trustix_aes_sbox[w & 0xff];
}

static u32 trustix_aes_rot_word(u32 w)
{
	return (w << 8) | (w >> 24);
}

static int trustix_aes_expand_key(const u8 *key, unsigned int key_len,
					  u8 rk[15][16], int *rounds)
{
	static const u32 rcon[10] = {
		0x01000000, 0x02000000, 0x04000000, 0x08000000,
		0x10000000, 0x20000000, 0x40000000, 0x80000000,
		0x1b000000, 0x36000000,
	};
	u32 w[60];
	unsigned int nk;
	unsigned int nr;
	unsigned int words;
	unsigned int i;

	if (key_len == 16) {
		nk = 4;
		nr = 10;
	} else if (key_len == 32) {
		nk = 8;
		nr = 14;
	} else {
		return -EINVAL;
	}
	words = 4 * (nr + 1);
	for (i = 0; i < nk; i++)
		w[i] = trustix_aes_load_word(key + 4 * i);
	for (i = nk; i < words; i++) {
		u32 temp = w[i - 1];

		if (i % nk == 0)
			temp = trustix_aes_sub_word(trustix_aes_rot_word(temp)) ^
			       rcon[(i / nk) - 1];
		else if (nk > 6 && i % nk == 4)
			temp = trustix_aes_sub_word(temp);
		w[i] = w[i - nk] ^ temp;
	}
	for (i = 0; i < words; i++)
		trustix_aes_store_word(&rk[i / 4][(i % 4) * 4], w[i]);
	*rounds = nr;
	memzero_explicit(w, sizeof(w));
	return 0;
}

static u8 trustix_aes_xtime(u8 x)
{
	return (u8)((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));
}

static void trustix_aes_add_round_key(u8 state[16], const u8 round_key[16])
{
	unsigned int i;

	for (i = 0; i < 16; i++)
		state[i] ^= round_key[i];
}

static void trustix_aes_sub_shift_rows(u8 state[16])
{
	u8 tmp[16];

	tmp[0] = trustix_aes_sbox[state[0]];
	tmp[4] = trustix_aes_sbox[state[4]];
	tmp[8] = trustix_aes_sbox[state[8]];
	tmp[12] = trustix_aes_sbox[state[12]];

	tmp[1] = trustix_aes_sbox[state[5]];
	tmp[5] = trustix_aes_sbox[state[9]];
	tmp[9] = trustix_aes_sbox[state[13]];
	tmp[13] = trustix_aes_sbox[state[1]];

	tmp[2] = trustix_aes_sbox[state[10]];
	tmp[6] = trustix_aes_sbox[state[14]];
	tmp[10] = trustix_aes_sbox[state[2]];
	tmp[14] = trustix_aes_sbox[state[6]];

	tmp[3] = trustix_aes_sbox[state[15]];
	tmp[7] = trustix_aes_sbox[state[3]];
	tmp[11] = trustix_aes_sbox[state[7]];
	tmp[15] = trustix_aes_sbox[state[11]];

	memcpy(state, tmp, sizeof(tmp));
	memzero_explicit(tmp, sizeof(tmp));
}

static void trustix_aes_mix_columns(u8 state[16])
{
	unsigned int c;

	for (c = 0; c < 4; c++) {
		u8 *col = &state[c * 4];
		u8 a0 = col[0];
		u8 a1 = col[1];
		u8 a2 = col[2];
		u8 a3 = col[3];
		u8 t = a0 ^ a1 ^ a2 ^ a3;

		col[0] ^= t ^ trustix_aes_xtime(a0 ^ a1);
		col[1] ^= t ^ trustix_aes_xtime(a1 ^ a2);
		col[2] ^= t ^ trustix_aes_xtime(a2 ^ a3);
		col[3] ^= t ^ trustix_aes_xtime(a3 ^ a0);
	}
}

static void trustix_aes_encrypt1_soft(const u8 rk[15][16], int rounds,
				      const u8 in[16], u8 out[16])
{
	u8 state[16];
	int round;

	memcpy(state, in, sizeof(state));
	trustix_aes_add_round_key(state, rk[0]);
	for (round = 1; round < rounds; round++) {
		trustix_aes_sub_shift_rows(state);
		trustix_aes_mix_columns(state);
		trustix_aes_add_round_key(state, rk[round]);
	}
	trustix_aes_sub_shift_rows(state);
	trustix_aes_add_round_key(state, rk[rounds]);
	memcpy(out, state, sizeof(state));
	memzero_explicit(state, sizeof(state));
}

static void trustix_xor16_soft(u8 *dst, const u8 *src, const u8 stream[16])
{
	unsigned int i;

	for (i = 0; i < 16; i++)
		dst[i] = src[i] ^ stream[i];
}

static TRUSTIX_VAES_ASM_TARGET void
trustix_aes_encrypt1_asm(const u8 rk[15][16], int rounds,
			 const u8 in[16], u8 out[16])
{
	if (rounds == 10) {
		asm volatile(
			"movdqu 0(%[in]), %%xmm0\n\t"
			"pxor 0(%[rk]), %%xmm0\n\t"
			"aesenc 16(%[rk]), %%xmm0\n\t"
			"aesenc 32(%[rk]), %%xmm0\n\t"
			"aesenc 48(%[rk]), %%xmm0\n\t"
			"aesenc 64(%[rk]), %%xmm0\n\t"
			"aesenc 80(%[rk]), %%xmm0\n\t"
			"aesenc 96(%[rk]), %%xmm0\n\t"
			"aesenc 112(%[rk]), %%xmm0\n\t"
			"aesenc 128(%[rk]), %%xmm0\n\t"
			"aesenc 144(%[rk]), %%xmm0\n\t"
			"aesenclast 160(%[rk]), %%xmm0\n\t"
			"movdqu %%xmm0, 0(%[out])\n\t"
			:
			: [in] "r" (in), [out] "r" (out), [rk] "r" (rk)
			: "xmm0", "memory");
		return;
	}
	asm volatile(
		"movdqu 0(%[in]), %%xmm0\n\t"
		"pxor 0(%[rk]), %%xmm0\n\t"
		"aesenc 16(%[rk]), %%xmm0\n\t"
		"aesenc 32(%[rk]), %%xmm0\n\t"
		"aesenc 48(%[rk]), %%xmm0\n\t"
		"aesenc 64(%[rk]), %%xmm0\n\t"
		"aesenc 80(%[rk]), %%xmm0\n\t"
		"aesenc 96(%[rk]), %%xmm0\n\t"
		"aesenc 112(%[rk]), %%xmm0\n\t"
		"aesenc 128(%[rk]), %%xmm0\n\t"
		"aesenc 144(%[rk]), %%xmm0\n\t"
		"aesenc 160(%[rk]), %%xmm0\n\t"
		"aesenc 176(%[rk]), %%xmm0\n\t"
		"aesenc 192(%[rk]), %%xmm0\n\t"
		"aesenc 208(%[rk]), %%xmm0\n\t"
		"aesenclast 224(%[rk]), %%xmm0\n\t"
		"movdqu %%xmm0, 0(%[out])\n\t"
		:
		: [in] "r" (in), [out] "r" (out), [rk] "r" (rk)
		: "xmm0", "memory");
}

static TRUSTIX_VAES_ASM_TARGET void
trustix_aes_xor4_aesni_asm(const u8 rk[15][16], int rounds,
			   const u8 in[64], const u8 *src, u8 *dst)
{
	if (rounds == 10) {
		asm volatile(
			"movdqu 0(%[in]), %%xmm0\n\t"
			"movdqu 16(%[in]), %%xmm1\n\t"
			"movdqu 32(%[in]), %%xmm2\n\t"
			"movdqu 48(%[in]), %%xmm3\n\t"
			"movdqu 0(%[rk]), %%xmm4\n\t"
			"pxor %%xmm4, %%xmm0\n\t"
			"pxor %%xmm4, %%xmm1\n\t"
			"pxor %%xmm4, %%xmm2\n\t"
			"pxor %%xmm4, %%xmm3\n\t"
			"movdqu 16(%[rk]), %%xmm4\n\t"
			"aesenc %%xmm4, %%xmm0\n\t"
			"aesenc %%xmm4, %%xmm1\n\t"
			"aesenc %%xmm4, %%xmm2\n\t"
			"aesenc %%xmm4, %%xmm3\n\t"
			"movdqu 32(%[rk]), %%xmm4\n\t"
			"aesenc %%xmm4, %%xmm0\n\t"
			"aesenc %%xmm4, %%xmm1\n\t"
			"aesenc %%xmm4, %%xmm2\n\t"
			"aesenc %%xmm4, %%xmm3\n\t"
			"movdqu 48(%[rk]), %%xmm4\n\t"
			"aesenc %%xmm4, %%xmm0\n\t"
			"aesenc %%xmm4, %%xmm1\n\t"
			"aesenc %%xmm4, %%xmm2\n\t"
			"aesenc %%xmm4, %%xmm3\n\t"
			"movdqu 64(%[rk]), %%xmm4\n\t"
			"aesenc %%xmm4, %%xmm0\n\t"
			"aesenc %%xmm4, %%xmm1\n\t"
			"aesenc %%xmm4, %%xmm2\n\t"
			"aesenc %%xmm4, %%xmm3\n\t"
			"movdqu 80(%[rk]), %%xmm4\n\t"
			"aesenc %%xmm4, %%xmm0\n\t"
			"aesenc %%xmm4, %%xmm1\n\t"
			"aesenc %%xmm4, %%xmm2\n\t"
			"aesenc %%xmm4, %%xmm3\n\t"
			"movdqu 96(%[rk]), %%xmm4\n\t"
			"aesenc %%xmm4, %%xmm0\n\t"
			"aesenc %%xmm4, %%xmm1\n\t"
			"aesenc %%xmm4, %%xmm2\n\t"
			"aesenc %%xmm4, %%xmm3\n\t"
			"movdqu 112(%[rk]), %%xmm4\n\t"
			"aesenc %%xmm4, %%xmm0\n\t"
			"aesenc %%xmm4, %%xmm1\n\t"
			"aesenc %%xmm4, %%xmm2\n\t"
			"aesenc %%xmm4, %%xmm3\n\t"
			"movdqu 128(%[rk]), %%xmm4\n\t"
			"aesenc %%xmm4, %%xmm0\n\t"
			"aesenc %%xmm4, %%xmm1\n\t"
			"aesenc %%xmm4, %%xmm2\n\t"
			"aesenc %%xmm4, %%xmm3\n\t"
			"movdqu 144(%[rk]), %%xmm4\n\t"
			"aesenc %%xmm4, %%xmm0\n\t"
			"aesenc %%xmm4, %%xmm1\n\t"
			"aesenc %%xmm4, %%xmm2\n\t"
			"aesenc %%xmm4, %%xmm3\n\t"
			"movdqu 160(%[rk]), %%xmm4\n\t"
			"aesenclast %%xmm4, %%xmm0\n\t"
			"aesenclast %%xmm4, %%xmm1\n\t"
			"aesenclast %%xmm4, %%xmm2\n\t"
			"aesenclast %%xmm4, %%xmm3\n\t"
			"movdqu 0(%[src]), %%xmm4\n\t"
			"pxor %%xmm4, %%xmm0\n\t"
			"movdqu 16(%[src]), %%xmm4\n\t"
			"pxor %%xmm4, %%xmm1\n\t"
			"movdqu 32(%[src]), %%xmm4\n\t"
			"pxor %%xmm4, %%xmm2\n\t"
			"movdqu 48(%[src]), %%xmm4\n\t"
			"pxor %%xmm4, %%xmm3\n\t"
			"movdqu %%xmm0, 0(%[dst])\n\t"
			"movdqu %%xmm1, 16(%[dst])\n\t"
			"movdqu %%xmm2, 32(%[dst])\n\t"
			"movdqu %%xmm3, 48(%[dst])\n\t"
			:
			: [in] "r" (in), [src] "r" (src),
			  [dst] "r" (dst), [rk] "r" (rk)
			: "xmm0", "xmm1", "xmm2", "xmm3", "xmm4",
			  "memory");
		return;
	}
	asm volatile(
		"movdqu 0(%[in]), %%xmm0\n\t"
		"movdqu 16(%[in]), %%xmm1\n\t"
		"movdqu 32(%[in]), %%xmm2\n\t"
		"movdqu 48(%[in]), %%xmm3\n\t"
		"movdqu 0(%[rk]), %%xmm4\n\t"
		"pxor %%xmm4, %%xmm0\n\t"
		"pxor %%xmm4, %%xmm1\n\t"
		"pxor %%xmm4, %%xmm2\n\t"
		"pxor %%xmm4, %%xmm3\n\t"
		"movdqu 16(%[rk]), %%xmm4\n\t"
		"aesenc %%xmm4, %%xmm0\n\t"
		"aesenc %%xmm4, %%xmm1\n\t"
		"aesenc %%xmm4, %%xmm2\n\t"
		"aesenc %%xmm4, %%xmm3\n\t"
		"movdqu 32(%[rk]), %%xmm4\n\t"
		"aesenc %%xmm4, %%xmm0\n\t"
		"aesenc %%xmm4, %%xmm1\n\t"
		"aesenc %%xmm4, %%xmm2\n\t"
		"aesenc %%xmm4, %%xmm3\n\t"
		"movdqu 48(%[rk]), %%xmm4\n\t"
		"aesenc %%xmm4, %%xmm0\n\t"
		"aesenc %%xmm4, %%xmm1\n\t"
		"aesenc %%xmm4, %%xmm2\n\t"
		"aesenc %%xmm4, %%xmm3\n\t"
		"movdqu 64(%[rk]), %%xmm4\n\t"
		"aesenc %%xmm4, %%xmm0\n\t"
		"aesenc %%xmm4, %%xmm1\n\t"
		"aesenc %%xmm4, %%xmm2\n\t"
		"aesenc %%xmm4, %%xmm3\n\t"
		"movdqu 80(%[rk]), %%xmm4\n\t"
		"aesenc %%xmm4, %%xmm0\n\t"
		"aesenc %%xmm4, %%xmm1\n\t"
		"aesenc %%xmm4, %%xmm2\n\t"
		"aesenc %%xmm4, %%xmm3\n\t"
		"movdqu 96(%[rk]), %%xmm4\n\t"
		"aesenc %%xmm4, %%xmm0\n\t"
		"aesenc %%xmm4, %%xmm1\n\t"
		"aesenc %%xmm4, %%xmm2\n\t"
		"aesenc %%xmm4, %%xmm3\n\t"
		"movdqu 112(%[rk]), %%xmm4\n\t"
		"aesenc %%xmm4, %%xmm0\n\t"
		"aesenc %%xmm4, %%xmm1\n\t"
		"aesenc %%xmm4, %%xmm2\n\t"
		"aesenc %%xmm4, %%xmm3\n\t"
		"movdqu 128(%[rk]), %%xmm4\n\t"
		"aesenc %%xmm4, %%xmm0\n\t"
		"aesenc %%xmm4, %%xmm1\n\t"
		"aesenc %%xmm4, %%xmm2\n\t"
		"aesenc %%xmm4, %%xmm3\n\t"
		"movdqu 144(%[rk]), %%xmm4\n\t"
		"aesenc %%xmm4, %%xmm0\n\t"
		"aesenc %%xmm4, %%xmm1\n\t"
		"aesenc %%xmm4, %%xmm2\n\t"
		"aesenc %%xmm4, %%xmm3\n\t"
		"movdqu 160(%[rk]), %%xmm4\n\t"
		"aesenc %%xmm4, %%xmm0\n\t"
		"aesenc %%xmm4, %%xmm1\n\t"
		"aesenc %%xmm4, %%xmm2\n\t"
		"aesenc %%xmm4, %%xmm3\n\t"
		"movdqu 176(%[rk]), %%xmm4\n\t"
		"aesenc %%xmm4, %%xmm0\n\t"
		"aesenc %%xmm4, %%xmm1\n\t"
		"aesenc %%xmm4, %%xmm2\n\t"
		"aesenc %%xmm4, %%xmm3\n\t"
		"movdqu 192(%[rk]), %%xmm4\n\t"
		"aesenc %%xmm4, %%xmm0\n\t"
		"aesenc %%xmm4, %%xmm1\n\t"
		"aesenc %%xmm4, %%xmm2\n\t"
		"aesenc %%xmm4, %%xmm3\n\t"
		"movdqu 208(%[rk]), %%xmm4\n\t"
		"aesenc %%xmm4, %%xmm0\n\t"
		"aesenc %%xmm4, %%xmm1\n\t"
		"aesenc %%xmm4, %%xmm2\n\t"
		"aesenc %%xmm4, %%xmm3\n\t"
		"movdqu 224(%[rk]), %%xmm4\n\t"
		"aesenclast %%xmm4, %%xmm0\n\t"
		"aesenclast %%xmm4, %%xmm1\n\t"
		"aesenclast %%xmm4, %%xmm2\n\t"
		"aesenclast %%xmm4, %%xmm3\n\t"
		"movdqu 0(%[src]), %%xmm4\n\t"
		"pxor %%xmm4, %%xmm0\n\t"
		"movdqu 16(%[src]), %%xmm4\n\t"
		"pxor %%xmm4, %%xmm1\n\t"
		"movdqu 32(%[src]), %%xmm4\n\t"
		"pxor %%xmm4, %%xmm2\n\t"
		"movdqu 48(%[src]), %%xmm4\n\t"
		"pxor %%xmm4, %%xmm3\n\t"
		"movdqu %%xmm0, 0(%[dst])\n\t"
		"movdqu %%xmm1, 16(%[dst])\n\t"
		"movdqu %%xmm2, 32(%[dst])\n\t"
		"movdqu %%xmm3, 48(%[dst])\n\t"
		:
		: [in] "r" (in), [src] "r" (src),
		  [dst] "r" (dst), [rk] "r" (rk)
		: "xmm0", "xmm1", "xmm2", "xmm3", "xmm4",
		  "memory");
}

#define TRUSTIX_AESNI_XOR8_LOADS \
	"movdqu 0(%[in]), %%xmm0\n\t" \
	"movdqu 16(%[in]), %%xmm1\n\t" \
	"movdqu 32(%[in]), %%xmm2\n\t" \
	"movdqu 48(%[in]), %%xmm3\n\t" \
	"movdqu 64(%[in]), %%xmm4\n\t" \
	"movdqu 80(%[in]), %%xmm5\n\t" \
	"movdqu 96(%[in]), %%xmm6\n\t" \
	"movdqu 112(%[in]), %%xmm7\n\t"

#define TRUSTIX_AESNI_XOR8_XOR_KEY(off) \
	"movdqu " #off "(%[rk]), %%xmm8\n\t" \
	"pxor %%xmm8, %%xmm0\n\t" \
	"pxor %%xmm8, %%xmm1\n\t" \
	"pxor %%xmm8, %%xmm2\n\t" \
	"pxor %%xmm8, %%xmm3\n\t" \
	"pxor %%xmm8, %%xmm4\n\t" \
	"pxor %%xmm8, %%xmm5\n\t" \
	"pxor %%xmm8, %%xmm6\n\t" \
	"pxor %%xmm8, %%xmm7\n\t"

#define TRUSTIX_AESNI_XOR8_AESENC(off) \
	"movdqu " #off "(%[rk]), %%xmm8\n\t" \
	"aesenc %%xmm8, %%xmm0\n\t" \
	"aesenc %%xmm8, %%xmm1\n\t" \
	"aesenc %%xmm8, %%xmm2\n\t" \
	"aesenc %%xmm8, %%xmm3\n\t" \
	"aesenc %%xmm8, %%xmm4\n\t" \
	"aesenc %%xmm8, %%xmm5\n\t" \
	"aesenc %%xmm8, %%xmm6\n\t" \
	"aesenc %%xmm8, %%xmm7\n\t"

#define TRUSTIX_AESNI_XOR8_AESLAST(off) \
	"movdqu " #off "(%[rk]), %%xmm8\n\t" \
	"aesenclast %%xmm8, %%xmm0\n\t" \
	"aesenclast %%xmm8, %%xmm1\n\t" \
	"aesenclast %%xmm8, %%xmm2\n\t" \
	"aesenclast %%xmm8, %%xmm3\n\t" \
	"aesenclast %%xmm8, %%xmm4\n\t" \
	"aesenclast %%xmm8, %%xmm5\n\t" \
	"aesenclast %%xmm8, %%xmm6\n\t" \
	"aesenclast %%xmm8, %%xmm7\n\t"

#define TRUSTIX_AESNI_XOR8_STORE \
	"movdqu 0(%[src]), %%xmm9\n\t" \
	"pxor %%xmm9, %%xmm0\n\t" \
	"movdqu %%xmm0, 0(%[dst])\n\t" \
	"movdqu 16(%[src]), %%xmm9\n\t" \
	"pxor %%xmm9, %%xmm1\n\t" \
	"movdqu %%xmm1, 16(%[dst])\n\t" \
	"movdqu 32(%[src]), %%xmm9\n\t" \
	"pxor %%xmm9, %%xmm2\n\t" \
	"movdqu %%xmm2, 32(%[dst])\n\t" \
	"movdqu 48(%[src]), %%xmm9\n\t" \
	"pxor %%xmm9, %%xmm3\n\t" \
	"movdqu %%xmm3, 48(%[dst])\n\t" \
	"movdqu 64(%[src]), %%xmm9\n\t" \
	"pxor %%xmm9, %%xmm4\n\t" \
	"movdqu %%xmm4, 64(%[dst])\n\t" \
	"movdqu 80(%[src]), %%xmm9\n\t" \
	"pxor %%xmm9, %%xmm5\n\t" \
	"movdqu %%xmm5, 80(%[dst])\n\t" \
	"movdqu 96(%[src]), %%xmm9\n\t" \
	"pxor %%xmm9, %%xmm6\n\t" \
	"movdqu %%xmm6, 96(%[dst])\n\t" \
	"movdqu 112(%[src]), %%xmm9\n\t" \
	"pxor %%xmm9, %%xmm7\n\t" \
	"movdqu %%xmm7, 112(%[dst])\n\t"

static TRUSTIX_VAES_ASM_TARGET void
trustix_aes_xor8_aesni_asm(const u8 rk[15][16], int rounds,
			   const u8 in[128], const u8 *src, u8 *dst)
{
	if (rounds == 10) {
		asm volatile(
			TRUSTIX_AESNI_XOR8_LOADS
			TRUSTIX_AESNI_XOR8_XOR_KEY(0)
			TRUSTIX_AESNI_XOR8_AESENC(16)
			TRUSTIX_AESNI_XOR8_AESENC(32)
			TRUSTIX_AESNI_XOR8_AESENC(48)
			TRUSTIX_AESNI_XOR8_AESENC(64)
			TRUSTIX_AESNI_XOR8_AESENC(80)
			TRUSTIX_AESNI_XOR8_AESENC(96)
			TRUSTIX_AESNI_XOR8_AESENC(112)
			TRUSTIX_AESNI_XOR8_AESENC(128)
			TRUSTIX_AESNI_XOR8_AESENC(144)
			TRUSTIX_AESNI_XOR8_AESLAST(160)
			TRUSTIX_AESNI_XOR8_STORE
			:
			: [in] "r" (in), [src] "r" (src),
			  [dst] "r" (dst), [rk] "r" (rk)
			: "xmm0", "xmm1", "xmm2", "xmm3", "xmm4",
			  "xmm5", "xmm6", "xmm7", "xmm8", "xmm9",
			  "memory");
		return;
	}
	asm volatile(
		TRUSTIX_AESNI_XOR8_LOADS
		TRUSTIX_AESNI_XOR8_XOR_KEY(0)
		TRUSTIX_AESNI_XOR8_AESENC(16)
		TRUSTIX_AESNI_XOR8_AESENC(32)
		TRUSTIX_AESNI_XOR8_AESENC(48)
		TRUSTIX_AESNI_XOR8_AESENC(64)
		TRUSTIX_AESNI_XOR8_AESENC(80)
		TRUSTIX_AESNI_XOR8_AESENC(96)
		TRUSTIX_AESNI_XOR8_AESENC(112)
		TRUSTIX_AESNI_XOR8_AESENC(128)
		TRUSTIX_AESNI_XOR8_AESENC(144)
		TRUSTIX_AESNI_XOR8_AESENC(160)
		TRUSTIX_AESNI_XOR8_AESENC(176)
		TRUSTIX_AESNI_XOR8_AESENC(192)
		TRUSTIX_AESNI_XOR8_AESENC(208)
		TRUSTIX_AESNI_XOR8_AESLAST(224)
		TRUSTIX_AESNI_XOR8_STORE
		:
		: [in] "r" (in), [src] "r" (src),
		  [dst] "r" (dst), [rk] "r" (rk)
		: "xmm0", "xmm1", "xmm2", "xmm3", "xmm4",
		  "xmm5", "xmm6", "xmm7", "xmm8", "xmm9",
		  "memory");
}

#undef TRUSTIX_AESNI_XOR8_STORE
#undef TRUSTIX_AESNI_XOR8_AESLAST
#undef TRUSTIX_AESNI_XOR8_AESENC
#undef TRUSTIX_AESNI_XOR8_XOR_KEY
#undef TRUSTIX_AESNI_XOR8_LOADS

static __maybe_unused TRUSTIX_VAES_ASM_TARGET void
trustix_aes_encrypt2_vaes_asm(const u8 rk[15][16], int rounds,
			      const u8 in[32], u8 out[32])
{
	if (rounds == 10) {
		asm volatile(
			"vmovdqu 0(%[in]), %%ymm0\n\t"
			"vbroadcasti128 0(%[rk]), %%ymm1\n\t"
			"vpxor %%ymm1, %%ymm0, %%ymm0\n\t"
			"vbroadcasti128 16(%[rk]), %%ymm1\n\t"
			"vaesenc %%ymm1, %%ymm0, %%ymm0\n\t"
			"vbroadcasti128 32(%[rk]), %%ymm1\n\t"
			"vaesenc %%ymm1, %%ymm0, %%ymm0\n\t"
			"vbroadcasti128 48(%[rk]), %%ymm1\n\t"
			"vaesenc %%ymm1, %%ymm0, %%ymm0\n\t"
			"vbroadcasti128 64(%[rk]), %%ymm1\n\t"
			"vaesenc %%ymm1, %%ymm0, %%ymm0\n\t"
			"vbroadcasti128 80(%[rk]), %%ymm1\n\t"
			"vaesenc %%ymm1, %%ymm0, %%ymm0\n\t"
			"vbroadcasti128 96(%[rk]), %%ymm1\n\t"
			"vaesenc %%ymm1, %%ymm0, %%ymm0\n\t"
			"vbroadcasti128 112(%[rk]), %%ymm1\n\t"
			"vaesenc %%ymm1, %%ymm0, %%ymm0\n\t"
			"vbroadcasti128 128(%[rk]), %%ymm1\n\t"
			"vaesenc %%ymm1, %%ymm0, %%ymm0\n\t"
			"vbroadcasti128 144(%[rk]), %%ymm1\n\t"
			"vaesenc %%ymm1, %%ymm0, %%ymm0\n\t"
			"vbroadcasti128 160(%[rk]), %%ymm1\n\t"
			"vaesenclast %%ymm1, %%ymm0, %%ymm0\n\t"
			"vmovdqu %%ymm0, 0(%[out])\n\t"
			"vzeroupper\n\t"
			:
			: [in] "r" (in), [out] "r" (out), [rk] "r" (rk)
			: "xmm0", "xmm1", "memory");
		return;
	}
	asm volatile(
		"vmovdqu 0(%[in]), %%ymm0\n\t"
		"vbroadcasti128 0(%[rk]), %%ymm1\n\t"
		"vpxor %%ymm1, %%ymm0, %%ymm0\n\t"
		"vbroadcasti128 16(%[rk]), %%ymm1\n\t"
		"vaesenc %%ymm1, %%ymm0, %%ymm0\n\t"
		"vbroadcasti128 32(%[rk]), %%ymm1\n\t"
		"vaesenc %%ymm1, %%ymm0, %%ymm0\n\t"
		"vbroadcasti128 48(%[rk]), %%ymm1\n\t"
		"vaesenc %%ymm1, %%ymm0, %%ymm0\n\t"
		"vbroadcasti128 64(%[rk]), %%ymm1\n\t"
		"vaesenc %%ymm1, %%ymm0, %%ymm0\n\t"
		"vbroadcasti128 80(%[rk]), %%ymm1\n\t"
		"vaesenc %%ymm1, %%ymm0, %%ymm0\n\t"
		"vbroadcasti128 96(%[rk]), %%ymm1\n\t"
		"vaesenc %%ymm1, %%ymm0, %%ymm0\n\t"
		"vbroadcasti128 112(%[rk]), %%ymm1\n\t"
		"vaesenc %%ymm1, %%ymm0, %%ymm0\n\t"
		"vbroadcasti128 128(%[rk]), %%ymm1\n\t"
		"vaesenc %%ymm1, %%ymm0, %%ymm0\n\t"
		"vbroadcasti128 144(%[rk]), %%ymm1\n\t"
		"vaesenc %%ymm1, %%ymm0, %%ymm0\n\t"
		"vbroadcasti128 160(%[rk]), %%ymm1\n\t"
		"vaesenc %%ymm1, %%ymm0, %%ymm0\n\t"
		"vbroadcasti128 176(%[rk]), %%ymm1\n\t"
		"vaesenc %%ymm1, %%ymm0, %%ymm0\n\t"
		"vbroadcasti128 192(%[rk]), %%ymm1\n\t"
		"vaesenc %%ymm1, %%ymm0, %%ymm0\n\t"
		"vbroadcasti128 208(%[rk]), %%ymm1\n\t"
		"vaesenc %%ymm1, %%ymm0, %%ymm0\n\t"
		"vbroadcasti128 224(%[rk]), %%ymm1\n\t"
		"vaesenclast %%ymm1, %%ymm0, %%ymm0\n\t"
		"vmovdqu %%ymm0, 0(%[out])\n\t"
		"vzeroupper\n\t"
		:
		: [in] "r" (in), [out] "r" (out), [rk] "r" (rk)
		: "xmm0", "xmm1", "memory");
}


static __maybe_unused TRUSTIX_VAES_ASM_TARGET void
trustix_ghash_prepare_shash_asm(const u8 h[16], u8 shash[16])
{
	asm volatile(
		"movdqu 0(%[h]), %%xmm0\n\t"
		"movdqa 0(%[bswap]), %%xmm5\n\t"
		"pshufb %%xmm5, %%xmm0\n\t"
		"movdqa %%xmm0, %%xmm1\n\t"
		"psllq $1, %%xmm0\n\t"
		"psrlq $63, %%xmm1\n\t"
		"movdqa %%xmm1, %%xmm2\n\t"
		"pslldq $8, %%xmm1\n\t"
		"psrldq $8, %%xmm2\n\t"
		"por %%xmm1, %%xmm0\n\t"
		"pshufd $0x24, %%xmm2, %%xmm1\n\t"
		"pcmpeqd 0(%[two_one]), %%xmm1\n\t"
		"pand 0(%[poly]), %%xmm1\n\t"
		"pxor %%xmm1, %%xmm0\n\t"
		"movdqu %%xmm0, 0(%[out])\n\t"
		:
		: [h] "r" (h), [out] "r" (shash),
		  [bswap] "r" (trustix_clmul_bswap),
		  [two_one] "r" (trustix_clmul_two_one),
		  [poly] "r" (trustix_clmul_poly)
		: "xmm0", "xmm1", "xmm2", "xmm5", "memory");
}

static void trustix_ghash_prepare_shash(const u8 h[16], u8 shash[16])
{
	u64 a = trustix_load_be64(h);
	u64 b = trustix_load_be64(h + 8);
	u64 lo = (b << 1) | (a >> 63);
	u64 hi = (a << 1) | (b >> 63);

	if (a >> 63)
		hi ^= 0xc2ULL << 56;
	trustix_store_le64(shash, lo);
	trustix_store_le64(shash + 8, hi);
}

static void trustix_ghash_prepare_shash4(const u8 h[16], u8 shash4[4][16])
{
	struct trustix_u128_be h_power[4];
	struct trustix_u128_be h_be;
	u8 block[16];
	int i;

	trustix_load_u128_be(&h_be, h);
	h_power[0] = h_be;
	for (i = 1; i < 4; i++)
		trustix_gf128_mul(&h_power[i], h_power[i - 1], h_be);
	for (i = 0; i < 4; i++) {
		trustix_store_u128_be(block, h_power[3 - i]);
		trustix_ghash_prepare_shash(block, shash4[i]);
	}

	memzero_explicit(block, sizeof(block));
}

static TRUSTIX_VAES_ASM_TARGET void
trustix_ghash_block_clmul_asm(u8 y[16], const u8 shash[16],
			      const u8 block[16])
{
	asm volatile(
		"movdqu 0(%[y]), %%xmm0\n\t"
		"movdqu 0(%[shash]), %%xmm1\n\t"
		"movdqa 0(%[bswap]), %%xmm5\n\t"
		"pshufb %%xmm5, %%xmm0\n\t"
		"movdqu 0(%[block]), %%xmm6\n\t"
		"pshufb %%xmm5, %%xmm6\n\t"
		"pxor %%xmm6, %%xmm0\n\t"
		"movaps %%xmm0, %%xmm2\n\t"
		"pshufd $0x4e, %%xmm0, %%xmm3\n\t"
		"pshufd $0x4e, %%xmm1, %%xmm4\n\t"
		"pxor %%xmm0, %%xmm3\n\t"
		"pxor %%xmm1, %%xmm4\n\t"
		"pclmulqdq $0x00, %%xmm1, %%xmm0\n\t"
		"pclmulqdq $0x11, %%xmm1, %%xmm2\n\t"
		"pclmulqdq $0x00, %%xmm4, %%xmm3\n\t"
		"pxor %%xmm0, %%xmm3\n\t"
		"pxor %%xmm2, %%xmm3\n\t"
		"movaps %%xmm3, %%xmm4\n\t"
		"pslldq $8, %%xmm4\n\t"
		"psrldq $8, %%xmm3\n\t"
		"pxor %%xmm4, %%xmm0\n\t"
		"pxor %%xmm3, %%xmm2\n\t"
		"movaps %%xmm0, %%xmm4\n\t"
		"psllq $1, %%xmm4\n\t"
		"pxor %%xmm0, %%xmm4\n\t"
		"psllq $5, %%xmm4\n\t"
		"pxor %%xmm0, %%xmm4\n\t"
		"psllq $57, %%xmm4\n\t"
		"movaps %%xmm4, %%xmm3\n\t"
		"pslldq $8, %%xmm3\n\t"
		"psrldq $8, %%xmm4\n\t"
		"pxor %%xmm3, %%xmm0\n\t"
		"pxor %%xmm4, %%xmm2\n\t"
		"movaps %%xmm0, %%xmm3\n\t"
		"psrlq $5, %%xmm3\n\t"
		"pxor %%xmm0, %%xmm3\n\t"
		"psrlq $1, %%xmm3\n\t"
		"pxor %%xmm0, %%xmm3\n\t"
		"psrlq $1, %%xmm3\n\t"
		"pxor %%xmm3, %%xmm2\n\t"
		"pxor %%xmm2, %%xmm0\n\t"
		"pshufb %%xmm5, %%xmm0\n\t"
		"movdqu %%xmm0, 0(%[y])\n\t"
		:
		: [y] "r" (y), [shash] "r" (shash),
		  [block] "r" (block), [bswap] "r" (trustix_clmul_bswap)
		: "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5",
		  "xmm6", "memory");
}

static TRUSTIX_VAES_ASM_TARGET void
trustix_ghash_blocks_clmul_asm(u8 y[16], const u8 shash[16],
			       const u8 *blocks, unsigned int count)
{
	asm volatile(
		"movdqu 0(%[y]), %%xmm0\n\t"
		"movdqu 0(%[shash]), %%xmm1\n\t"
		"movdqa 0(%[bswap]), %%xmm5\n\t"
		"movq %[blocks], %%rax\n\t"
		"movl %[count], %%ecx\n\t"
		"testl %%ecx, %%ecx\n\t"
		"jz 2f\n\t"
		"1:\n\t"
		"pshufb %%xmm5, %%xmm0\n\t"
		"movdqu 0(%%rax), %%xmm6\n\t"
		"pshufb %%xmm5, %%xmm6\n\t"
		"pxor %%xmm6, %%xmm0\n\t"
		"movaps %%xmm0, %%xmm2\n\t"
		"pshufd $0x4e, %%xmm0, %%xmm3\n\t"
		"pshufd $0x4e, %%xmm1, %%xmm4\n\t"
		"pxor %%xmm0, %%xmm3\n\t"
		"pxor %%xmm1, %%xmm4\n\t"
		"pclmulqdq $0x00, %%xmm1, %%xmm0\n\t"
		"pclmulqdq $0x11, %%xmm1, %%xmm2\n\t"
		"pclmulqdq $0x00, %%xmm4, %%xmm3\n\t"
		"pxor %%xmm0, %%xmm3\n\t"
		"pxor %%xmm2, %%xmm3\n\t"
		"movaps %%xmm3, %%xmm4\n\t"
		"pslldq $8, %%xmm4\n\t"
		"psrldq $8, %%xmm3\n\t"
		"pxor %%xmm4, %%xmm0\n\t"
		"pxor %%xmm3, %%xmm2\n\t"
		"movaps %%xmm0, %%xmm4\n\t"
		"psllq $1, %%xmm4\n\t"
		"pxor %%xmm0, %%xmm4\n\t"
		"psllq $5, %%xmm4\n\t"
		"pxor %%xmm0, %%xmm4\n\t"
		"psllq $57, %%xmm4\n\t"
		"movaps %%xmm4, %%xmm3\n\t"
		"pslldq $8, %%xmm3\n\t"
		"psrldq $8, %%xmm4\n\t"
		"pxor %%xmm3, %%xmm0\n\t"
		"pxor %%xmm4, %%xmm2\n\t"
		"movaps %%xmm0, %%xmm3\n\t"
		"psrlq $5, %%xmm3\n\t"
		"pxor %%xmm0, %%xmm3\n\t"
		"psrlq $1, %%xmm3\n\t"
		"pxor %%xmm0, %%xmm3\n\t"
		"psrlq $1, %%xmm3\n\t"
		"pxor %%xmm3, %%xmm2\n\t"
		"pxor %%xmm2, %%xmm0\n\t"
		"pshufb %%xmm5, %%xmm0\n\t"
		"addq $16, %%rax\n\t"
		"decl %%ecx\n\t"
		"jnz 1b\n\t"
		"2:\n\t"
		"movdqu %%xmm0, 0(%[y])\n\t"
		:
		: [y] "r" (y), [shash] "r" (shash),
		  [blocks] "r" (blocks), [count] "r" (count),
		  [bswap] "r" (trustix_clmul_bswap)
		: "rax", "rcx", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4",
		  "xmm5", "xmm6", "cc", "memory");
}

#define TRUSTIX_GHASH4_STEP(acc, ptr) \
	"pshufb %%xmm5, %%" acc "\n\t" \
	"movdqu 0(%[" ptr "]), %%xmm6\n\t" \
	"pshufb %%xmm5, %%xmm6\n\t" \
	"pxor %%xmm6, %%" acc "\n\t" \
	"movaps %%" acc ", %%xmm2\n\t" \
	"pshufd $0x4e, %%" acc ", %%xmm3\n\t" \
	"pshufd $0x4e, %%xmm1, %%xmm4\n\t" \
	"pxor %%" acc ", %%xmm3\n\t" \
	"pxor %%xmm1, %%xmm4\n\t" \
	"pclmulqdq $0x00, %%xmm1, %%" acc "\n\t" \
	"pclmulqdq $0x11, %%xmm1, %%xmm2\n\t" \
	"pclmulqdq $0x00, %%xmm4, %%xmm3\n\t" \
	"pxor %%" acc ", %%xmm3\n\t" \
	"pxor %%xmm2, %%xmm3\n\t" \
	"movaps %%xmm3, %%xmm4\n\t" \
	"pslldq $8, %%xmm4\n\t" \
	"psrldq $8, %%xmm3\n\t" \
	"pxor %%xmm4, %%" acc "\n\t" \
	"pxor %%xmm3, %%xmm2\n\t" \
	"movaps %%" acc ", %%xmm4\n\t" \
	"psllq $1, %%xmm4\n\t" \
	"pxor %%" acc ", %%xmm4\n\t" \
	"psllq $5, %%xmm4\n\t" \
	"pxor %%" acc ", %%xmm4\n\t" \
	"psllq $57, %%xmm4\n\t" \
	"movaps %%xmm4, %%xmm3\n\t" \
	"pslldq $8, %%xmm3\n\t" \
	"psrldq $8, %%xmm4\n\t" \
	"pxor %%xmm3, %%" acc "\n\t" \
	"pxor %%xmm4, %%xmm2\n\t" \
	"movaps %%" acc ", %%xmm3\n\t" \
	"psrlq $5, %%xmm3\n\t" \
	"pxor %%" acc ", %%xmm3\n\t" \
	"psrlq $1, %%xmm3\n\t" \
	"pxor %%" acc ", %%xmm3\n\t" \
	"psrlq $1, %%xmm3\n\t" \
	"pxor %%xmm3, %%xmm2\n\t" \
	"pxor %%xmm2, %%" acc "\n\t" \
	"pshufb %%xmm5, %%" acc "\n\t"

static TRUSTIX_VAES_ASM_TARGET void
trustix_ghash4_blocks_clmul_asm(u8 y0[16], u8 y1[16], u8 y2[16], u8 y3[16],
				const u8 shash[16],
				const u8 *blocks0, const u8 *blocks1,
				const u8 *blocks2, const u8 *blocks3,
				unsigned int count)
{
	const u8 *p0 = blocks0;
	const u8 *p1 = blocks1;
	const u8 *p2 = blocks2;
	const u8 *p3 = blocks3;

	asm volatile(
		"movdqu 0(%[y0]), %%xmm0\n\t"
		"movdqu 0(%[y1]), %%xmm7\n\t"
		"movdqu 0(%[y2]), %%xmm8\n\t"
		"movdqu 0(%[y3]), %%xmm9\n\t"
		"movdqu 0(%[shash]), %%xmm1\n\t"
		"movdqa 0(%[bswap]), %%xmm5\n\t"
		"testl %[count], %[count]\n\t"
		"jz 2f\n\t"
		"1:\n\t"
		TRUSTIX_GHASH4_STEP("xmm0", "p0")
		TRUSTIX_GHASH4_STEP("xmm7", "p1")
		TRUSTIX_GHASH4_STEP("xmm8", "p2")
		TRUSTIX_GHASH4_STEP("xmm9", "p3")
		"addq $16, %[p0]\n\t"
		"addq $16, %[p1]\n\t"
		"addq $16, %[p2]\n\t"
		"addq $16, %[p3]\n\t"
		"decl %[count]\n\t"
		"jnz 1b\n\t"
		"2:\n\t"
		"movdqu %%xmm0, 0(%[y0])\n\t"
		"movdqu %%xmm7, 0(%[y1])\n\t"
		"movdqu %%xmm8, 0(%[y2])\n\t"
		"movdqu %%xmm9, 0(%[y3])\n\t"
		: [p0] "+r" (p0), [p1] "+r" (p1), [p2] "+r" (p2),
		  [p3] "+r" (p3), [count] "+r" (count)
		: [y0] "r" (y0), [y1] "r" (y1), [y2] "r" (y2),
		  [y3] "r" (y3), [shash] "r" (shash),
		  [bswap] "r" (trustix_clmul_bswap)
		: "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5",
		  "xmm6", "xmm7", "xmm8", "xmm9", "cc", "memory");
}

#define TRUSTIX_GHASH_AGG4_MUL_ACCUM \
	"movaps %%xmm6, %%xmm7\n\t" \
	"pshufd $0x4e, %%xmm6, %%xmm3\n\t" \
	"pshufd $0x4e, %%xmm1, %%xmm4\n\t" \
	"pxor %%xmm6, %%xmm3\n\t" \
	"pxor %%xmm1, %%xmm4\n\t" \
	"pclmulqdq $0x00, %%xmm1, %%xmm6\n\t" \
	"pclmulqdq $0x11, %%xmm1, %%xmm7\n\t" \
	"pclmulqdq $0x00, %%xmm4, %%xmm3\n\t" \
	"pxor %%xmm6, %%xmm3\n\t" \
	"pxor %%xmm7, %%xmm3\n\t" \
	"movaps %%xmm3, %%xmm4\n\t" \
	"pslldq $8, %%xmm4\n\t" \
	"psrldq $8, %%xmm3\n\t" \
	"pxor %%xmm4, %%xmm6\n\t" \
	"pxor %%xmm3, %%xmm7\n\t" \
	"pxor %%xmm6, %%xmm0\n\t" \
	"pxor %%xmm7, %%xmm2\n\t"

#define TRUSTIX_GHASH_AGG4_REDUCE_STORE(y) \
	"movaps %%xmm0, %%xmm4\n\t" \
	"psllq $1, %%xmm4\n\t" \
	"pxor %%xmm0, %%xmm4\n\t" \
	"psllq $5, %%xmm4\n\t" \
	"pxor %%xmm0, %%xmm4\n\t" \
	"psllq $57, %%xmm4\n\t" \
	"movaps %%xmm4, %%xmm3\n\t" \
	"pslldq $8, %%xmm3\n\t" \
	"psrldq $8, %%xmm4\n\t" \
	"pxor %%xmm3, %%xmm0\n\t" \
	"pxor %%xmm4, %%xmm2\n\t" \
	"movaps %%xmm0, %%xmm3\n\t" \
	"psrlq $5, %%xmm3\n\t" \
	"pxor %%xmm0, %%xmm3\n\t" \
	"psrlq $1, %%xmm3\n\t" \
	"pxor %%xmm0, %%xmm3\n\t" \
	"psrlq $1, %%xmm3\n\t" \
	"pxor %%xmm3, %%xmm2\n\t" \
	"pxor %%xmm2, %%xmm0\n\t" \
	"pshufb %%xmm5, %%xmm0\n\t" \
	"movdqu %%xmm0, 0(%[" y "])\n\t"

#define TRUSTIX_GHASH_AGG4_STREAM(y, ptr) \
	"pxor %%xmm0, %%xmm0\n\t" \
	"pxor %%xmm2, %%xmm2\n\t" \
	"movdqu 0(%[" y "]), %%xmm6\n\t" \
	"pshufb %%xmm5, %%xmm6\n\t" \
	"movdqu 0(%[" ptr "]), %%xmm7\n\t" \
	"pshufb %%xmm5, %%xmm7\n\t" \
	"pxor %%xmm7, %%xmm6\n\t" \
	"movdqu 0(%[shash4]), %%xmm1\n\t" \
	TRUSTIX_GHASH_AGG4_MUL_ACCUM \
	"movdqu 16(%[" ptr "]), %%xmm6\n\t" \
	"pshufb %%xmm5, %%xmm6\n\t" \
	"movdqu 16(%[shash4]), %%xmm1\n\t" \
	TRUSTIX_GHASH_AGG4_MUL_ACCUM \
	"movdqu 32(%[" ptr "]), %%xmm6\n\t" \
	"pshufb %%xmm5, %%xmm6\n\t" \
	"movdqu 32(%[shash4]), %%xmm1\n\t" \
	TRUSTIX_GHASH_AGG4_MUL_ACCUM \
	"movdqu 48(%[" ptr "]), %%xmm6\n\t" \
	"pshufb %%xmm5, %%xmm6\n\t" \
	"movdqu 48(%[shash4]), %%xmm1\n\t" \
	TRUSTIX_GHASH_AGG4_MUL_ACCUM \
	TRUSTIX_GHASH_AGG4_REDUCE_STORE(y)

static TRUSTIX_VAES_ASM_TARGET void
trustix_ghash_agg4_blocks_clmul_asm(u8 y[16], const u8 shash4[4][16],
				    const u8 *blocks, unsigned int groups)
{
	const u8 *p = blocks;

	asm volatile(
		"movdqa 0(%[bswap]), %%xmm5\n\t"
		"testl %[groups], %[groups]\n\t"
		"jz 2f\n\t"
		"1:\n\t"
		TRUSTIX_GHASH_AGG4_STREAM("y", "p")
		"addq $64, %[p]\n\t"
		"decl %[groups]\n\t"
		"jnz 1b\n\t"
		"2:\n\t"
		: [p] "+r" (p), [groups] "+r" (groups)
		: [y] "r" (y), [shash4] "r" (shash4),
		  [bswap] "r" (trustix_clmul_bswap)
		: "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5",
		  "xmm6", "xmm7", "cc", "memory");
}

static TRUSTIX_VAES_ASM_TARGET void
trustix_ghash4_agg4_blocks_clmul_asm(u8 y0[16], u8 y1[16], u8 y2[16],
				     u8 y3[16], const u8 shash4[4][16],
				     const u8 *blocks0, const u8 *blocks1,
				     const u8 *blocks2, const u8 *blocks3,
				     unsigned int groups)
{
	const u8 *p0 = blocks0;
	const u8 *p1 = blocks1;
	const u8 *p2 = blocks2;
	const u8 *p3 = blocks3;

	asm volatile(
		"movdqa 0(%[bswap]), %%xmm5\n\t"
		"testl %[groups], %[groups]\n\t"
		"jz 2f\n\t"
		"1:\n\t"
		TRUSTIX_GHASH_AGG4_STREAM("y0", "p0")
		TRUSTIX_GHASH_AGG4_STREAM("y1", "p1")
		TRUSTIX_GHASH_AGG4_STREAM("y2", "p2")
		TRUSTIX_GHASH_AGG4_STREAM("y3", "p3")
		"addq $64, %[p0]\n\t"
		"addq $64, %[p1]\n\t"
		"addq $64, %[p2]\n\t"
		"addq $64, %[p3]\n\t"
		"decl %[groups]\n\t"
		"jnz 1b\n\t"
		"2:\n\t"
		: [p0] "+r" (p0), [p1] "+r" (p1), [p2] "+r" (p2),
		  [p3] "+r" (p3), [groups] "+r" (groups)
		: [y0] "r" (y0), [y1] "r" (y1), [y2] "r" (y2),
		  [y3] "r" (y3), [shash4] "r" (shash4),
		  [bswap] "r" (trustix_clmul_bswap)
		: "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5",
		  "xmm6", "xmm7", "cc", "memory");
}

#undef TRUSTIX_GHASH_AGG4_STREAM
#undef TRUSTIX_GHASH_AGG4_REDUCE_STORE
#undef TRUSTIX_GHASH_AGG4_MUL_ACCUM

#undef TRUSTIX_GHASH4_STEP

struct trustix_aes_xor4x4_ghash_args {
	const u8 *in0;
	const u8 *in1;
	const u8 *in2;
	const u8 *in3;
	const u8 *src0;
	const u8 *src1;
	const u8 *src2;
	const u8 *src3;
	u8 *dst0;
	u8 *dst1;
	u8 *dst2;
	u8 *dst3;
	u8 *y0;
	u8 *y1;
	u8 *y2;
	u8 *y3;
	const u8 *shash;
};

static TRUSTIX_VAES_ASM_TARGET void trustix_xor16_asm(u8 *dst,
						      const u8 *src,
						      const u8 *stream)
{
	asm volatile(
		"movdqu 0(%[src]), %%xmm0\n\t"
		"movdqu 0(%[stream]), %%xmm1\n\t"
		"pxor %%xmm1, %%xmm0\n\t"
		"movdqu %%xmm0, 0(%[dst])\n\t"
		:
		: [dst] "r" (dst), [src] "r" (src), [stream] "r" (stream)
		: "xmm0", "xmm1", "memory");
}

static __maybe_unused TRUSTIX_VAES_ASM_TARGET void trustix_xor32_asm(u8 *dst,
								     const u8 *src,
								     const u8 *stream)
{
	asm volatile(
		"vmovdqu 0(%[src]), %%ymm0\n\t"
		"vmovdqu 0(%[stream]), %%ymm1\n\t"
		"vpxor %%ymm1, %%ymm0, %%ymm0\n\t"
		"vmovdqu %%ymm0, 0(%[dst])\n\t"
		"vzeroupper\n\t"
		:
		: [dst] "r" (dst), [src] "r" (src), [stream] "r" (stream)
		: "xmm0", "xmm1", "memory");
}

static TRUSTIX_VAES_ASM_TARGET void
trustix_aes_xor2_vaes_asm(const u8 rk[15][16], int rounds,
			  const u8 in[32], const u8 *src, u8 *dst)
{
	if (rounds == 10) {
		asm volatile(
			"vmovdqu 0(%[in]), %%ymm0\n\t"
			"vbroadcasti128 0(%[rk]), %%ymm1\n\t"
			"vpxor %%ymm1, %%ymm0, %%ymm0\n\t"
			"vbroadcasti128 16(%[rk]), %%ymm1\n\t"
			"vaesenc %%ymm1, %%ymm0, %%ymm0\n\t"
			"vbroadcasti128 32(%[rk]), %%ymm1\n\t"
			"vaesenc %%ymm1, %%ymm0, %%ymm0\n\t"
			"vbroadcasti128 48(%[rk]), %%ymm1\n\t"
			"vaesenc %%ymm1, %%ymm0, %%ymm0\n\t"
			"vbroadcasti128 64(%[rk]), %%ymm1\n\t"
			"vaesenc %%ymm1, %%ymm0, %%ymm0\n\t"
			"vbroadcasti128 80(%[rk]), %%ymm1\n\t"
			"vaesenc %%ymm1, %%ymm0, %%ymm0\n\t"
			"vbroadcasti128 96(%[rk]), %%ymm1\n\t"
			"vaesenc %%ymm1, %%ymm0, %%ymm0\n\t"
			"vbroadcasti128 112(%[rk]), %%ymm1\n\t"
			"vaesenc %%ymm1, %%ymm0, %%ymm0\n\t"
			"vbroadcasti128 128(%[rk]), %%ymm1\n\t"
			"vaesenc %%ymm1, %%ymm0, %%ymm0\n\t"
			"vbroadcasti128 144(%[rk]), %%ymm1\n\t"
			"vaesenc %%ymm1, %%ymm0, %%ymm0\n\t"
			"vbroadcasti128 160(%[rk]), %%ymm1\n\t"
			"vaesenclast %%ymm1, %%ymm0, %%ymm0\n\t"
			"vmovdqu 0(%[src]), %%ymm1\n\t"
			"vpxor %%ymm1, %%ymm0, %%ymm0\n\t"
			"vmovdqu %%ymm0, 0(%[dst])\n\t"
			"vzeroupper\n\t"
			:
			: [in] "r" (in), [src] "r" (src),
			  [dst] "r" (dst), [rk] "r" (rk)
			: "xmm0", "xmm1", "memory");
		return;
	}
	asm volatile(
		"vmovdqu 0(%[in]), %%ymm0\n\t"
		"vbroadcasti128 0(%[rk]), %%ymm1\n\t"
		"vpxor %%ymm1, %%ymm0, %%ymm0\n\t"
		"vbroadcasti128 16(%[rk]), %%ymm1\n\t"
		"vaesenc %%ymm1, %%ymm0, %%ymm0\n\t"
		"vbroadcasti128 32(%[rk]), %%ymm1\n\t"
		"vaesenc %%ymm1, %%ymm0, %%ymm0\n\t"
		"vbroadcasti128 48(%[rk]), %%ymm1\n\t"
		"vaesenc %%ymm1, %%ymm0, %%ymm0\n\t"
		"vbroadcasti128 64(%[rk]), %%ymm1\n\t"
		"vaesenc %%ymm1, %%ymm0, %%ymm0\n\t"
		"vbroadcasti128 80(%[rk]), %%ymm1\n\t"
		"vaesenc %%ymm1, %%ymm0, %%ymm0\n\t"
		"vbroadcasti128 96(%[rk]), %%ymm1\n\t"
		"vaesenc %%ymm1, %%ymm0, %%ymm0\n\t"
		"vbroadcasti128 112(%[rk]), %%ymm1\n\t"
		"vaesenc %%ymm1, %%ymm0, %%ymm0\n\t"
		"vbroadcasti128 128(%[rk]), %%ymm1\n\t"
		"vaesenc %%ymm1, %%ymm0, %%ymm0\n\t"
		"vbroadcasti128 144(%[rk]), %%ymm1\n\t"
		"vaesenc %%ymm1, %%ymm0, %%ymm0\n\t"
		"vbroadcasti128 160(%[rk]), %%ymm1\n\t"
		"vaesenc %%ymm1, %%ymm0, %%ymm0\n\t"
		"vbroadcasti128 176(%[rk]), %%ymm1\n\t"
		"vaesenc %%ymm1, %%ymm0, %%ymm0\n\t"
		"vbroadcasti128 192(%[rk]), %%ymm1\n\t"
		"vaesenc %%ymm1, %%ymm0, %%ymm0\n\t"
		"vbroadcasti128 208(%[rk]), %%ymm1\n\t"
		"vaesenc %%ymm1, %%ymm0, %%ymm0\n\t"
		"vbroadcasti128 224(%[rk]), %%ymm1\n\t"
		"vaesenclast %%ymm1, %%ymm0, %%ymm0\n\t"
		"vmovdqu 0(%[src]), %%ymm1\n\t"
		"vpxor %%ymm1, %%ymm0, %%ymm0\n\t"
		"vmovdqu %%ymm0, 0(%[dst])\n\t"
		"vzeroupper\n\t"
		:
		: [in] "r" (in), [src] "r" (src),
		  [dst] "r" (dst), [rk] "r" (rk)
		: "xmm0", "xmm1", "memory");
}

#define TRUSTIX_VAES_XOR8_LOADS \
	"vmovdqu 0(%[in]), %%ymm0\n\t" \
	"vmovdqu 32(%[in]), %%ymm1\n\t" \
	"vmovdqu 64(%[in]), %%ymm2\n\t" \
	"vmovdqu 96(%[in]), %%ymm3\n\t"

#define TRUSTIX_VAES_XOR8_XOR_KEY(off) \
	"vbroadcasti128 " #off "(%[rk]), %%ymm4\n\t" \
	"vpxor %%ymm4, %%ymm0, %%ymm0\n\t" \
	"vpxor %%ymm4, %%ymm1, %%ymm1\n\t" \
	"vpxor %%ymm4, %%ymm2, %%ymm2\n\t" \
	"vpxor %%ymm4, %%ymm3, %%ymm3\n\t"

#define TRUSTIX_VAES_XOR8_AESENC(off) \
	"vbroadcasti128 " #off "(%[rk]), %%ymm4\n\t" \
	"vaesenc %%ymm4, %%ymm0, %%ymm0\n\t" \
	"vaesenc %%ymm4, %%ymm1, %%ymm1\n\t" \
	"vaesenc %%ymm4, %%ymm2, %%ymm2\n\t" \
	"vaesenc %%ymm4, %%ymm3, %%ymm3\n\t"

#define TRUSTIX_VAES_XOR8_AESLAST(off) \
	"vbroadcasti128 " #off "(%[rk]), %%ymm4\n\t" \
	"vaesenclast %%ymm4, %%ymm0, %%ymm0\n\t" \
	"vaesenclast %%ymm4, %%ymm1, %%ymm1\n\t" \
	"vaesenclast %%ymm4, %%ymm2, %%ymm2\n\t" \
	"vaesenclast %%ymm4, %%ymm3, %%ymm3\n\t"

#define TRUSTIX_VAES_XOR8_STORE \
	"vmovdqu 0(%[src]), %%ymm4\n\t" \
	"vpxor %%ymm4, %%ymm0, %%ymm0\n\t" \
	"vmovdqu %%ymm0, 0(%[dst])\n\t" \
	"vmovdqu 32(%[src]), %%ymm4\n\t" \
	"vpxor %%ymm4, %%ymm1, %%ymm1\n\t" \
	"vmovdqu %%ymm1, 32(%[dst])\n\t" \
	"vmovdqu 64(%[src]), %%ymm4\n\t" \
	"vpxor %%ymm4, %%ymm2, %%ymm2\n\t" \
	"vmovdqu %%ymm2, 64(%[dst])\n\t" \
	"vmovdqu 96(%[src]), %%ymm4\n\t" \
	"vpxor %%ymm4, %%ymm3, %%ymm3\n\t" \
	"vmovdqu %%ymm3, 96(%[dst])\n\t" \
	"vzeroupper\n\t"

static TRUSTIX_VAES_ASM_TARGET void
trustix_aes_xor8_vaes_asm(const u8 rk[15][16], int rounds,
			  const u8 in[128], const u8 *src, u8 *dst)
{
	if (rounds == 10) {
		asm volatile(
			TRUSTIX_VAES_XOR8_LOADS
			TRUSTIX_VAES_XOR8_XOR_KEY(0)
			TRUSTIX_VAES_XOR8_AESENC(16)
			TRUSTIX_VAES_XOR8_AESENC(32)
			TRUSTIX_VAES_XOR8_AESENC(48)
			TRUSTIX_VAES_XOR8_AESENC(64)
			TRUSTIX_VAES_XOR8_AESENC(80)
			TRUSTIX_VAES_XOR8_AESENC(96)
			TRUSTIX_VAES_XOR8_AESENC(112)
			TRUSTIX_VAES_XOR8_AESENC(128)
			TRUSTIX_VAES_XOR8_AESENC(144)
			TRUSTIX_VAES_XOR8_AESLAST(160)
			TRUSTIX_VAES_XOR8_STORE
			:
			: [in] "r" (in), [src] "r" (src),
			  [dst] "r" (dst), [rk] "r" (rk)
			: "xmm0", "xmm1", "xmm2", "xmm3", "xmm4",
			  "memory");
		return;
	}
	if (rounds != 14) {
		trustix_aes_xor2_vaes_asm(rk, rounds, in, src, dst);
		trustix_aes_xor2_vaes_asm(rk, rounds, in + 32, src + 32,
					   dst + 32);
		trustix_aes_xor2_vaes_asm(rk, rounds, in + 64, src + 64,
					   dst + 64);
		trustix_aes_xor2_vaes_asm(rk, rounds, in + 96, src + 96,
					   dst + 96);
		return;
	}

	asm volatile(
		TRUSTIX_VAES_XOR8_LOADS
		TRUSTIX_VAES_XOR8_XOR_KEY(0)
		TRUSTIX_VAES_XOR8_AESENC(16)
		TRUSTIX_VAES_XOR8_AESENC(32)
		TRUSTIX_VAES_XOR8_AESENC(48)
		TRUSTIX_VAES_XOR8_AESENC(64)
		TRUSTIX_VAES_XOR8_AESENC(80)
		TRUSTIX_VAES_XOR8_AESENC(96)
		TRUSTIX_VAES_XOR8_AESENC(112)
		TRUSTIX_VAES_XOR8_AESENC(128)
		TRUSTIX_VAES_XOR8_AESENC(144)
		TRUSTIX_VAES_XOR8_AESENC(160)
		TRUSTIX_VAES_XOR8_AESENC(176)
		TRUSTIX_VAES_XOR8_AESENC(192)
		TRUSTIX_VAES_XOR8_AESENC(208)
		TRUSTIX_VAES_XOR8_AESLAST(224)
		TRUSTIX_VAES_XOR8_STORE
		:
		: [in] "r" (in), [src] "r" (src),
		  [dst] "r" (dst), [rk] "r" (rk)
		: "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "memory");
}

#undef TRUSTIX_VAES_XOR8_STORE
#undef TRUSTIX_VAES_XOR8_AESLAST
#undef TRUSTIX_VAES_XOR8_AESENC
#undef TRUSTIX_VAES_XOR8_XOR_KEY
#undef TRUSTIX_VAES_XOR8_LOADS

#define TRUSTIX_VAES_XOR4X4_LOADS \
	"vmovdqu 0(%[in0]), %%ymm0\n\t" \
	"vmovdqu 32(%[in0]), %%ymm1\n\t" \
	"vmovdqu 0(%[in1]), %%ymm2\n\t" \
	"vmovdqu 32(%[in1]), %%ymm3\n\t" \
	"vmovdqu 0(%[in2]), %%ymm4\n\t" \
	"vmovdqu 32(%[in2]), %%ymm5\n\t" \
	"vmovdqu 0(%[in3]), %%ymm6\n\t" \
	"vmovdqu 32(%[in3]), %%ymm7\n\t"

#define TRUSTIX_VAES_XOR4X4_XOR_KEY(off) \
	"vbroadcasti128 " #off "(%[rk]), %%ymm8\n\t" \
	"vpxor %%ymm8, %%ymm0, %%ymm0\n\t" \
	"vpxor %%ymm8, %%ymm1, %%ymm1\n\t" \
	"vpxor %%ymm8, %%ymm2, %%ymm2\n\t" \
	"vpxor %%ymm8, %%ymm3, %%ymm3\n\t" \
	"vpxor %%ymm8, %%ymm4, %%ymm4\n\t" \
	"vpxor %%ymm8, %%ymm5, %%ymm5\n\t" \
	"vpxor %%ymm8, %%ymm6, %%ymm6\n\t" \
	"vpxor %%ymm8, %%ymm7, %%ymm7\n\t"

#define TRUSTIX_VAES_XOR4X4_AESENC(off) \
	"vbroadcasti128 " #off "(%[rk]), %%ymm8\n\t" \
	"vaesenc %%ymm8, %%ymm0, %%ymm0\n\t" \
	"vaesenc %%ymm8, %%ymm1, %%ymm1\n\t" \
	"vaesenc %%ymm8, %%ymm2, %%ymm2\n\t" \
	"vaesenc %%ymm8, %%ymm3, %%ymm3\n\t" \
	"vaesenc %%ymm8, %%ymm4, %%ymm4\n\t" \
	"vaesenc %%ymm8, %%ymm5, %%ymm5\n\t" \
	"vaesenc %%ymm8, %%ymm6, %%ymm6\n\t" \
	"vaesenc %%ymm8, %%ymm7, %%ymm7\n\t"

#define TRUSTIX_VAES_XOR4X4_AESLAST(off) \
	"vbroadcasti128 " #off "(%[rk]), %%ymm8\n\t" \
	"vaesenclast %%ymm8, %%ymm0, %%ymm0\n\t" \
	"vaesenclast %%ymm8, %%ymm1, %%ymm1\n\t" \
	"vaesenclast %%ymm8, %%ymm2, %%ymm2\n\t" \
	"vaesenclast %%ymm8, %%ymm3, %%ymm3\n\t" \
	"vaesenclast %%ymm8, %%ymm4, %%ymm4\n\t" \
	"vaesenclast %%ymm8, %%ymm5, %%ymm5\n\t" \
	"vaesenclast %%ymm8, %%ymm6, %%ymm6\n\t" \
	"vaesenclast %%ymm8, %%ymm7, %%ymm7\n\t"

#define TRUSTIX_VAES_XOR4X4_STORE \
	"vmovdqu 0(%[src0]), %%ymm8\n\t" \
	"vpxor %%ymm8, %%ymm0, %%ymm0\n\t" \
	"vmovdqu %%ymm0, 0(%[dst0])\n\t" \
	"vmovdqu 32(%[src0]), %%ymm8\n\t" \
	"vpxor %%ymm8, %%ymm1, %%ymm1\n\t" \
	"vmovdqu %%ymm1, 32(%[dst0])\n\t" \
	"vmovdqu 0(%[src1]), %%ymm8\n\t" \
	"vpxor %%ymm8, %%ymm2, %%ymm2\n\t" \
	"vmovdqu %%ymm2, 0(%[dst1])\n\t" \
	"vmovdqu 32(%[src1]), %%ymm8\n\t" \
	"vpxor %%ymm8, %%ymm3, %%ymm3\n\t" \
	"vmovdqu %%ymm3, 32(%[dst1])\n\t" \
	"vmovdqu 0(%[src2]), %%ymm8\n\t" \
	"vpxor %%ymm8, %%ymm4, %%ymm4\n\t" \
	"vmovdqu %%ymm4, 0(%[dst2])\n\t" \
	"vmovdqu 32(%[src2]), %%ymm8\n\t" \
	"vpxor %%ymm8, %%ymm5, %%ymm5\n\t" \
	"vmovdqu %%ymm5, 32(%[dst2])\n\t" \
	"vmovdqu 0(%[src3]), %%ymm8\n\t" \
	"vpxor %%ymm8, %%ymm6, %%ymm6\n\t" \
	"vmovdqu %%ymm6, 0(%[dst3])\n\t" \
	"vmovdqu 32(%[src3]), %%ymm8\n\t" \
	"vpxor %%ymm8, %%ymm7, %%ymm7\n\t" \
	"vmovdqu %%ymm7, 32(%[dst3])\n\t" \
	"vzeroupper\n\t"

static TRUSTIX_VAES_ASM_TARGET void
trustix_aes_xor4x4_vaes_asm(const u8 rk[15][16], int rounds,
			    const u8 in0[64], const u8 in1[64],
			    const u8 in2[64], const u8 in3[64],
			    const u8 *src0, const u8 *src1,
			    const u8 *src2, const u8 *src3,
			    u8 *dst0, u8 *dst1, u8 *dst2, u8 *dst3)
{
	if (rounds == 10) {
		asm volatile(
			TRUSTIX_VAES_XOR4X4_LOADS
			TRUSTIX_VAES_XOR4X4_XOR_KEY(0)
			TRUSTIX_VAES_XOR4X4_AESENC(16)
			TRUSTIX_VAES_XOR4X4_AESENC(32)
			TRUSTIX_VAES_XOR4X4_AESENC(48)
			TRUSTIX_VAES_XOR4X4_AESENC(64)
			TRUSTIX_VAES_XOR4X4_AESENC(80)
			TRUSTIX_VAES_XOR4X4_AESENC(96)
			TRUSTIX_VAES_XOR4X4_AESENC(112)
			TRUSTIX_VAES_XOR4X4_AESENC(128)
			TRUSTIX_VAES_XOR4X4_AESENC(144)
			TRUSTIX_VAES_XOR4X4_AESLAST(160)
			TRUSTIX_VAES_XOR4X4_STORE
			:
			: [in0] "r" (in0), [in1] "r" (in1),
			  [in2] "r" (in2), [in3] "r" (in3),
			  [src0] "r" (src0), [src1] "r" (src1),
			  [src2] "r" (src2), [src3] "r" (src3),
			  [dst0] "r" (dst0), [dst1] "r" (dst1),
			  [dst2] "r" (dst2), [dst3] "r" (dst3),
			  [rk] "r" (rk)
			: "xmm0", "xmm1", "xmm2", "xmm3", "xmm4",
			  "xmm5", "xmm6", "xmm7", "xmm8", "memory");
		return;
	}
	if (rounds != 14) {
		trustix_aes_xor2_vaes_asm(rk, rounds, in0, src0, dst0);
		trustix_aes_xor2_vaes_asm(rk, rounds, in0 + 32,
					   src0 + 32, dst0 + 32);
		trustix_aes_xor2_vaes_asm(rk, rounds, in1, src1, dst1);
		trustix_aes_xor2_vaes_asm(rk, rounds, in1 + 32,
					   src1 + 32, dst1 + 32);
		trustix_aes_xor2_vaes_asm(rk, rounds, in2, src2, dst2);
		trustix_aes_xor2_vaes_asm(rk, rounds, in2 + 32,
					   src2 + 32, dst2 + 32);
		trustix_aes_xor2_vaes_asm(rk, rounds, in3, src3, dst3);
		trustix_aes_xor2_vaes_asm(rk, rounds, in3 + 32,
					   src3 + 32, dst3 + 32);
		return;
	}

	asm volatile(
		TRUSTIX_VAES_XOR4X4_LOADS
		TRUSTIX_VAES_XOR4X4_XOR_KEY(0)
		TRUSTIX_VAES_XOR4X4_AESENC(16)
		TRUSTIX_VAES_XOR4X4_AESENC(32)
		TRUSTIX_VAES_XOR4X4_AESENC(48)
		TRUSTIX_VAES_XOR4X4_AESENC(64)
		TRUSTIX_VAES_XOR4X4_AESENC(80)
		TRUSTIX_VAES_XOR4X4_AESENC(96)
		TRUSTIX_VAES_XOR4X4_AESENC(112)
		TRUSTIX_VAES_XOR4X4_AESENC(128)
		TRUSTIX_VAES_XOR4X4_AESENC(144)
		TRUSTIX_VAES_XOR4X4_AESENC(160)
		TRUSTIX_VAES_XOR4X4_AESENC(176)
		TRUSTIX_VAES_XOR4X4_AESENC(192)
		TRUSTIX_VAES_XOR4X4_AESENC(208)
		TRUSTIX_VAES_XOR4X4_AESLAST(224)
		TRUSTIX_VAES_XOR4X4_STORE
		:
		: [in0] "r" (in0), [in1] "r" (in1),
		  [in2] "r" (in2), [in3] "r" (in3),
		  [src0] "r" (src0), [src1] "r" (src1),
		  [src2] "r" (src2), [src3] "r" (src3),
		  [dst0] "r" (dst0), [dst1] "r" (dst1),
		  [dst2] "r" (dst2), [dst3] "r" (dst3),
		  [rk] "r" (rk)
		: "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5",
		  "xmm6", "xmm7", "xmm8", "memory");
}

#undef TRUSTIX_VAES_XOR4X4_STORE
#undef TRUSTIX_VAES_XOR4X4_AESLAST
#undef TRUSTIX_VAES_XOR4X4_AESENC
#undef TRUSTIX_VAES_XOR4X4_XOR_KEY
#undef TRUSTIX_VAES_XOR4X4_LOADS

#define TRUSTIX_GHASH_STEP_REG(acc, block) \
	"vpshufb %%xmm15, %%" acc ", %%" acc "\n\t" \
	"vpshufb %%xmm15, %%" block ", %%" block "\n\t" \
	"vpxor %%" block ", %%" acc ", %%" acc "\n\t" \
	"vmovaps %%" acc ", %%xmm11\n\t" \
	"vpshufd $0x4e, %%" acc ", %%xmm12\n\t" \
	"vpxor %%" acc ", %%xmm12, %%xmm12\n\t" \
	"vpclmulqdq $0x00, %%xmm14, %%" acc ", %%" acc "\n\t" \
	"vpclmulqdq $0x11, %%xmm14, %%xmm11, %%xmm11\n\t" \
	"vpclmulqdq $0x00, %%xmm13, %%xmm12, %%xmm12\n\t" \
	"vpxor %%" acc ", %%xmm12, %%xmm12\n\t" \
	"vpxor %%xmm11, %%xmm12, %%xmm12\n\t" \
	"vmovaps %%xmm12, %%xmm9\n\t" \
	"vpslldq $8, %%xmm9, %%xmm9\n\t" \
	"vpsrldq $8, %%xmm12, %%xmm12\n\t" \
	"vpxor %%xmm9, %%" acc ", %%" acc "\n\t" \
	"vpxor %%xmm12, %%xmm11, %%xmm11\n\t" \
	"vmovaps %%" acc ", %%xmm9\n\t" \
	"vpsllq $1, %%xmm9, %%xmm9\n\t" \
	"vpxor %%" acc ", %%xmm9, %%xmm9\n\t" \
	"vpsllq $5, %%xmm9, %%xmm9\n\t" \
	"vpxor %%" acc ", %%xmm9, %%xmm9\n\t" \
	"vpsllq $57, %%xmm9, %%xmm9\n\t" \
	"vmovaps %%xmm9, %%xmm12\n\t" \
	"vpslldq $8, %%xmm12, %%xmm12\n\t" \
	"vpsrldq $8, %%xmm9, %%xmm9\n\t" \
	"vpxor %%xmm12, %%" acc ", %%" acc "\n\t" \
	"vpxor %%xmm9, %%xmm11, %%xmm11\n\t" \
	"vmovaps %%" acc ", %%xmm12\n\t" \
	"vpsrlq $5, %%xmm12, %%xmm12\n\t" \
	"vpxor %%" acc ", %%xmm12, %%xmm12\n\t" \
	"vpsrlq $1, %%xmm12, %%xmm12\n\t" \
	"vpxor %%" acc ", %%xmm12, %%xmm12\n\t" \
	"vpsrlq $1, %%xmm12, %%xmm12\n\t" \
	"vpxor %%xmm12, %%xmm11, %%xmm11\n\t" \
	"vpxor %%xmm11, %%" acc ", %%" acc "\n\t" \
	"vpshufb %%xmm15, %%" acc ", %%" acc "\n\t"

#define TRUSTIX_GHASH_STREAM4_REG(ymm_a, xmm_a, ymm_b, xmm_b, y_off) \
	"movq %c[" y_off "](%[args]), %%r10\n\t" \
	"vmovdqu 0(%%r10), %%xmm10\n\t" \
	"vmovaps %%" xmm_a ", %%xmm9\n\t" \
	TRUSTIX_GHASH_STEP_REG("xmm10", "xmm9") \
	"vextracti128 $1, %%" ymm_a ", %%xmm9\n\t" \
	TRUSTIX_GHASH_STEP_REG("xmm10", "xmm9") \
	"vmovaps %%" xmm_b ", %%xmm9\n\t" \
	TRUSTIX_GHASH_STEP_REG("xmm10", "xmm9") \
	"vextracti128 $1, %%" ymm_b ", %%xmm9\n\t" \
	TRUSTIX_GHASH_STEP_REG("xmm10", "xmm9") \
	"vmovdqu %%xmm10, 0(%%r10)\n\t"

static TRUSTIX_VAES_ASM_TARGET void
trustix_aes_xor4x4_ghash_vaes_asm(const u8 rk[15][16], int rounds,
				  const struct trustix_aes_xor4x4_ghash_args *args)
{
	if (rounds != 14) {
		trustix_aes_xor4x4_vaes_asm(
			rk, rounds, args->in0, args->in1, args->in2,
			args->in3, args->src0, args->src1, args->src2,
			args->src3, args->dst0, args->dst1, args->dst2,
			args->dst3);
		trustix_ghash4_blocks_clmul_asm(args->y0, args->y1, args->y2,
						 args->y3, args->shash,
						 args->dst0, args->dst1,
						 args->dst2, args->dst3, 4);
		return;
	}

	asm volatile(
		"movq %c[in0](%[args]), %%r10\n\t"
		"vmovdqu 0(%%r10), %%ymm0\n\t"
		"vmovdqu 32(%%r10), %%ymm1\n\t"
		"movq %c[in1](%[args]), %%r10\n\t"
		"vmovdqu 0(%%r10), %%ymm2\n\t"
		"vmovdqu 32(%%r10), %%ymm3\n\t"
		"movq %c[in2](%[args]), %%r10\n\t"
		"vmovdqu 0(%%r10), %%ymm4\n\t"
		"vmovdqu 32(%%r10), %%ymm5\n\t"
		"movq %c[in3](%[args]), %%r10\n\t"
		"vmovdqu 0(%%r10), %%ymm6\n\t"
		"vmovdqu 32(%%r10), %%ymm7\n\t"
		"vbroadcasti128 0(%[rk]), %%ymm8\n\t"
		"vpxor %%ymm8, %%ymm0, %%ymm0\n\t"
		"vpxor %%ymm8, %%ymm1, %%ymm1\n\t"
		"vpxor %%ymm8, %%ymm2, %%ymm2\n\t"
		"vpxor %%ymm8, %%ymm3, %%ymm3\n\t"
		"vpxor %%ymm8, %%ymm4, %%ymm4\n\t"
		"vpxor %%ymm8, %%ymm5, %%ymm5\n\t"
		"vpxor %%ymm8, %%ymm6, %%ymm6\n\t"
		"vpxor %%ymm8, %%ymm7, %%ymm7\n\t"
		"vbroadcasti128 16(%[rk]), %%ymm8\n\t"
		"vaesenc %%ymm8, %%ymm0, %%ymm0\n\t"
		"vaesenc %%ymm8, %%ymm1, %%ymm1\n\t"
		"vaesenc %%ymm8, %%ymm2, %%ymm2\n\t"
		"vaesenc %%ymm8, %%ymm3, %%ymm3\n\t"
		"vaesenc %%ymm8, %%ymm4, %%ymm4\n\t"
		"vaesenc %%ymm8, %%ymm5, %%ymm5\n\t"
		"vaesenc %%ymm8, %%ymm6, %%ymm6\n\t"
		"vaesenc %%ymm8, %%ymm7, %%ymm7\n\t"
		"vbroadcasti128 32(%[rk]), %%ymm8\n\t"
		"vaesenc %%ymm8, %%ymm0, %%ymm0\n\t"
		"vaesenc %%ymm8, %%ymm1, %%ymm1\n\t"
		"vaesenc %%ymm8, %%ymm2, %%ymm2\n\t"
		"vaesenc %%ymm8, %%ymm3, %%ymm3\n\t"
		"vaesenc %%ymm8, %%ymm4, %%ymm4\n\t"
		"vaesenc %%ymm8, %%ymm5, %%ymm5\n\t"
		"vaesenc %%ymm8, %%ymm6, %%ymm6\n\t"
		"vaesenc %%ymm8, %%ymm7, %%ymm7\n\t"
		"vbroadcasti128 48(%[rk]), %%ymm8\n\t"
		"vaesenc %%ymm8, %%ymm0, %%ymm0\n\t"
		"vaesenc %%ymm8, %%ymm1, %%ymm1\n\t"
		"vaesenc %%ymm8, %%ymm2, %%ymm2\n\t"
		"vaesenc %%ymm8, %%ymm3, %%ymm3\n\t"
		"vaesenc %%ymm8, %%ymm4, %%ymm4\n\t"
		"vaesenc %%ymm8, %%ymm5, %%ymm5\n\t"
		"vaesenc %%ymm8, %%ymm6, %%ymm6\n\t"
		"vaesenc %%ymm8, %%ymm7, %%ymm7\n\t"
		"vbroadcasti128 64(%[rk]), %%ymm8\n\t"
		"vaesenc %%ymm8, %%ymm0, %%ymm0\n\t"
		"vaesenc %%ymm8, %%ymm1, %%ymm1\n\t"
		"vaesenc %%ymm8, %%ymm2, %%ymm2\n\t"
		"vaesenc %%ymm8, %%ymm3, %%ymm3\n\t"
		"vaesenc %%ymm8, %%ymm4, %%ymm4\n\t"
		"vaesenc %%ymm8, %%ymm5, %%ymm5\n\t"
		"vaesenc %%ymm8, %%ymm6, %%ymm6\n\t"
		"vaesenc %%ymm8, %%ymm7, %%ymm7\n\t"
		"vbroadcasti128 80(%[rk]), %%ymm8\n\t"
		"vaesenc %%ymm8, %%ymm0, %%ymm0\n\t"
		"vaesenc %%ymm8, %%ymm1, %%ymm1\n\t"
		"vaesenc %%ymm8, %%ymm2, %%ymm2\n\t"
		"vaesenc %%ymm8, %%ymm3, %%ymm3\n\t"
		"vaesenc %%ymm8, %%ymm4, %%ymm4\n\t"
		"vaesenc %%ymm8, %%ymm5, %%ymm5\n\t"
		"vaesenc %%ymm8, %%ymm6, %%ymm6\n\t"
		"vaesenc %%ymm8, %%ymm7, %%ymm7\n\t"
		"vbroadcasti128 96(%[rk]), %%ymm8\n\t"
		"vaesenc %%ymm8, %%ymm0, %%ymm0\n\t"
		"vaesenc %%ymm8, %%ymm1, %%ymm1\n\t"
		"vaesenc %%ymm8, %%ymm2, %%ymm2\n\t"
		"vaesenc %%ymm8, %%ymm3, %%ymm3\n\t"
		"vaesenc %%ymm8, %%ymm4, %%ymm4\n\t"
		"vaesenc %%ymm8, %%ymm5, %%ymm5\n\t"
		"vaesenc %%ymm8, %%ymm6, %%ymm6\n\t"
		"vaesenc %%ymm8, %%ymm7, %%ymm7\n\t"
		"vbroadcasti128 112(%[rk]), %%ymm8\n\t"
		"vaesenc %%ymm8, %%ymm0, %%ymm0\n\t"
		"vaesenc %%ymm8, %%ymm1, %%ymm1\n\t"
		"vaesenc %%ymm8, %%ymm2, %%ymm2\n\t"
		"vaesenc %%ymm8, %%ymm3, %%ymm3\n\t"
		"vaesenc %%ymm8, %%ymm4, %%ymm4\n\t"
		"vaesenc %%ymm8, %%ymm5, %%ymm5\n\t"
		"vaesenc %%ymm8, %%ymm6, %%ymm6\n\t"
		"vaesenc %%ymm8, %%ymm7, %%ymm7\n\t"
		"vbroadcasti128 128(%[rk]), %%ymm8\n\t"
		"vaesenc %%ymm8, %%ymm0, %%ymm0\n\t"
		"vaesenc %%ymm8, %%ymm1, %%ymm1\n\t"
		"vaesenc %%ymm8, %%ymm2, %%ymm2\n\t"
		"vaesenc %%ymm8, %%ymm3, %%ymm3\n\t"
		"vaesenc %%ymm8, %%ymm4, %%ymm4\n\t"
		"vaesenc %%ymm8, %%ymm5, %%ymm5\n\t"
		"vaesenc %%ymm8, %%ymm6, %%ymm6\n\t"
		"vaesenc %%ymm8, %%ymm7, %%ymm7\n\t"
		"vbroadcasti128 144(%[rk]), %%ymm8\n\t"
		"vaesenc %%ymm8, %%ymm0, %%ymm0\n\t"
		"vaesenc %%ymm8, %%ymm1, %%ymm1\n\t"
		"vaesenc %%ymm8, %%ymm2, %%ymm2\n\t"
		"vaesenc %%ymm8, %%ymm3, %%ymm3\n\t"
		"vaesenc %%ymm8, %%ymm4, %%ymm4\n\t"
		"vaesenc %%ymm8, %%ymm5, %%ymm5\n\t"
		"vaesenc %%ymm8, %%ymm6, %%ymm6\n\t"
		"vaesenc %%ymm8, %%ymm7, %%ymm7\n\t"
		"vbroadcasti128 160(%[rk]), %%ymm8\n\t"
		"vaesenc %%ymm8, %%ymm0, %%ymm0\n\t"
		"vaesenc %%ymm8, %%ymm1, %%ymm1\n\t"
		"vaesenc %%ymm8, %%ymm2, %%ymm2\n\t"
		"vaesenc %%ymm8, %%ymm3, %%ymm3\n\t"
		"vaesenc %%ymm8, %%ymm4, %%ymm4\n\t"
		"vaesenc %%ymm8, %%ymm5, %%ymm5\n\t"
		"vaesenc %%ymm8, %%ymm6, %%ymm6\n\t"
		"vaesenc %%ymm8, %%ymm7, %%ymm7\n\t"
		"vbroadcasti128 176(%[rk]), %%ymm8\n\t"
		"vaesenc %%ymm8, %%ymm0, %%ymm0\n\t"
		"vaesenc %%ymm8, %%ymm1, %%ymm1\n\t"
		"vaesenc %%ymm8, %%ymm2, %%ymm2\n\t"
		"vaesenc %%ymm8, %%ymm3, %%ymm3\n\t"
		"vaesenc %%ymm8, %%ymm4, %%ymm4\n\t"
		"vaesenc %%ymm8, %%ymm5, %%ymm5\n\t"
		"vaesenc %%ymm8, %%ymm6, %%ymm6\n\t"
		"vaesenc %%ymm8, %%ymm7, %%ymm7\n\t"
		"vbroadcasti128 192(%[rk]), %%ymm8\n\t"
		"vaesenc %%ymm8, %%ymm0, %%ymm0\n\t"
		"vaesenc %%ymm8, %%ymm1, %%ymm1\n\t"
		"vaesenc %%ymm8, %%ymm2, %%ymm2\n\t"
		"vaesenc %%ymm8, %%ymm3, %%ymm3\n\t"
		"vaesenc %%ymm8, %%ymm4, %%ymm4\n\t"
		"vaesenc %%ymm8, %%ymm5, %%ymm5\n\t"
		"vaesenc %%ymm8, %%ymm6, %%ymm6\n\t"
		"vaesenc %%ymm8, %%ymm7, %%ymm7\n\t"
		"vbroadcasti128 208(%[rk]), %%ymm8\n\t"
		"vaesenc %%ymm8, %%ymm0, %%ymm0\n\t"
		"vaesenc %%ymm8, %%ymm1, %%ymm1\n\t"
		"vaesenc %%ymm8, %%ymm2, %%ymm2\n\t"
		"vaesenc %%ymm8, %%ymm3, %%ymm3\n\t"
		"vaesenc %%ymm8, %%ymm4, %%ymm4\n\t"
		"vaesenc %%ymm8, %%ymm5, %%ymm5\n\t"
		"vaesenc %%ymm8, %%ymm6, %%ymm6\n\t"
		"vaesenc %%ymm8, %%ymm7, %%ymm7\n\t"
		"vbroadcasti128 224(%[rk]), %%ymm8\n\t"
		"vaesenclast %%ymm8, %%ymm0, %%ymm0\n\t"
		"vaesenclast %%ymm8, %%ymm1, %%ymm1\n\t"
		"vaesenclast %%ymm8, %%ymm2, %%ymm2\n\t"
		"vaesenclast %%ymm8, %%ymm3, %%ymm3\n\t"
		"vaesenclast %%ymm8, %%ymm4, %%ymm4\n\t"
		"vaesenclast %%ymm8, %%ymm5, %%ymm5\n\t"
		"vaesenclast %%ymm8, %%ymm6, %%ymm6\n\t"
		"vaesenclast %%ymm8, %%ymm7, %%ymm7\n\t"
		"movq %c[src0](%[args]), %%r10\n\t"
		"vmovdqu 0(%%r10), %%ymm8\n\t"
		"vpxor %%ymm8, %%ymm0, %%ymm0\n\t"
		"vmovdqu 32(%%r10), %%ymm8\n\t"
		"vpxor %%ymm8, %%ymm1, %%ymm1\n\t"
		"movq %c[dst0](%[args]), %%r10\n\t"
		"vmovdqu %%ymm0, 0(%%r10)\n\t"
		"vmovdqu %%ymm1, 32(%%r10)\n\t"
		"movq %c[src1](%[args]), %%r10\n\t"
		"vmovdqu 0(%%r10), %%ymm8\n\t"
		"vpxor %%ymm8, %%ymm2, %%ymm2\n\t"
		"vmovdqu 32(%%r10), %%ymm8\n\t"
		"vpxor %%ymm8, %%ymm3, %%ymm3\n\t"
		"movq %c[dst1](%[args]), %%r10\n\t"
		"vmovdqu %%ymm2, 0(%%r10)\n\t"
		"vmovdqu %%ymm3, 32(%%r10)\n\t"
		"movq %c[src2](%[args]), %%r10\n\t"
		"vmovdqu 0(%%r10), %%ymm8\n\t"
		"vpxor %%ymm8, %%ymm4, %%ymm4\n\t"
		"vmovdqu 32(%%r10), %%ymm8\n\t"
		"vpxor %%ymm8, %%ymm5, %%ymm5\n\t"
		"movq %c[dst2](%[args]), %%r10\n\t"
		"vmovdqu %%ymm4, 0(%%r10)\n\t"
		"vmovdqu %%ymm5, 32(%%r10)\n\t"
		"movq %c[src3](%[args]), %%r10\n\t"
		"vmovdqu 0(%%r10), %%ymm8\n\t"
		"vpxor %%ymm8, %%ymm6, %%ymm6\n\t"
		"vmovdqu 32(%%r10), %%ymm8\n\t"
		"vpxor %%ymm8, %%ymm7, %%ymm7\n\t"
		"movq %c[dst3](%[args]), %%r10\n\t"
		"vmovdqu %%ymm6, 0(%%r10)\n\t"
		"vmovdqu %%ymm7, 32(%%r10)\n\t"
		"movq %c[shash](%[args]), %%r10\n\t"
		"vmovdqu 0(%%r10), %%xmm14\n\t"
		"vmovdqa 0(%[bswap]), %%xmm15\n\t"
		"vpshufd $0x4e, %%xmm14, %%xmm13\n\t"
		"vpxor %%xmm14, %%xmm13, %%xmm13\n\t"
		TRUSTIX_GHASH_STREAM4_REG("ymm0", "xmm0", "ymm1", "xmm1", "y0")
		TRUSTIX_GHASH_STREAM4_REG("ymm2", "xmm2", "ymm3", "xmm3", "y1")
		TRUSTIX_GHASH_STREAM4_REG("ymm4", "xmm4", "ymm5", "xmm5", "y2")
		TRUSTIX_GHASH_STREAM4_REG("ymm6", "xmm6", "ymm7", "xmm7", "y3")
		"vzeroupper\n\t"
		:
		: [args] "r" (args), [rk] "r" (rk),
		  [bswap] "r" (trustix_clmul_bswap),
		  [in0] "i" (offsetof(struct trustix_aes_xor4x4_ghash_args, in0)),
		  [in1] "i" (offsetof(struct trustix_aes_xor4x4_ghash_args, in1)),
		  [in2] "i" (offsetof(struct trustix_aes_xor4x4_ghash_args, in2)),
		  [in3] "i" (offsetof(struct trustix_aes_xor4x4_ghash_args, in3)),
		  [src0] "i" (offsetof(struct trustix_aes_xor4x4_ghash_args, src0)),
		  [src1] "i" (offsetof(struct trustix_aes_xor4x4_ghash_args, src1)),
		  [src2] "i" (offsetof(struct trustix_aes_xor4x4_ghash_args, src2)),
		  [src3] "i" (offsetof(struct trustix_aes_xor4x4_ghash_args, src3)),
		  [dst0] "i" (offsetof(struct trustix_aes_xor4x4_ghash_args, dst0)),
		  [dst1] "i" (offsetof(struct trustix_aes_xor4x4_ghash_args, dst1)),
		  [dst2] "i" (offsetof(struct trustix_aes_xor4x4_ghash_args, dst2)),
		  [dst3] "i" (offsetof(struct trustix_aes_xor4x4_ghash_args, dst3)),
		  [y0] "i" (offsetof(struct trustix_aes_xor4x4_ghash_args, y0)),
		  [y1] "i" (offsetof(struct trustix_aes_xor4x4_ghash_args, y1)),
		  [y2] "i" (offsetof(struct trustix_aes_xor4x4_ghash_args, y2)),
		  [y3] "i" (offsetof(struct trustix_aes_xor4x4_ghash_args, y3)),
		  [shash] "i" (offsetof(struct trustix_aes_xor4x4_ghash_args, shash))
		: "r10", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4",
		  "xmm5", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10",
		  "xmm11", "xmm12", "xmm13", "xmm14", "xmm15", "cc",
		  "memory");
}

#undef TRUSTIX_GHASH_STREAM4_REG
#undef TRUSTIX_GHASH_STEP_REG

static __always_inline void trustix_ctr_block_prefix(u8 block[16],
						     const u8 *nonce)
{
	memcpy(block, nonce, 8);
	memcpy(block + 8, nonce + 8, 4);
}

static __always_inline void trustix_ctr_block_suffix(u8 block[16], u32 ctr)
{
	block[12] = (u8)(ctr >> 24);
	block[13] = (u8)(ctr >> 16);
	block[14] = (u8)(ctr >> 8);
	block[15] = (u8)ctr;
}

static __always_inline void trustix_ctr_block(u8 block[16], const u8 *nonce,
					      u32 ctr)
{
	trustix_ctr_block_prefix(block, nonce);
	trustix_ctr_block_suffix(block, ctr);
}

static __always_inline void trustix_ctr2_blocks(u8 blocks[32],
						const u8 *nonce, u32 ctr)
{
	trustix_ctr_block_prefix(blocks, nonce);
	trustix_ctr_block_suffix(blocks, ctr);
	memcpy(blocks + 16, blocks, 12);
	trustix_ctr_block_suffix(blocks + 16, ctr + 1);
}

static __always_inline void trustix_ctr4_blocks(u8 blocks[64],
						const u8 *nonce, u32 ctr)
{
	trustix_ctr_block_prefix(blocks, nonce);
	trustix_ctr_block_suffix(blocks, ctr);
	memcpy(blocks + 16, blocks, 12);
	trustix_ctr_block_suffix(blocks + 16, ctr + 1);
	memcpy(blocks + 32, blocks, 12);
	trustix_ctr_block_suffix(blocks + 32, ctr + 2);
	memcpy(blocks + 48, blocks, 12);
	trustix_ctr_block_suffix(blocks + 48, ctr + 3);
}

static __always_inline void trustix_ctr8_blocks(u8 blocks[128],
						const u8 *nonce, u32 ctr)
{
	trustix_ctr4_blocks(blocks, nonce, ctr);
	memcpy(blocks + 64, blocks, 12);
	trustix_ctr_block_suffix(blocks + 64, ctr + 4);
	memcpy(blocks + 80, blocks, 12);
	trustix_ctr_block_suffix(blocks + 80, ctr + 5);
	memcpy(blocks + 96, blocks, 12);
	trustix_ctr_block_suffix(blocks + 96, ctr + 6);
	memcpy(blocks + 112, blocks, 12);
	trustix_ctr_block_suffix(blocks + 112, ctr + 7);
}

static bool trustix_consttime_memneq(const u8 *a, const u8 *b, size_t len)
{
	u8 diff = 0;
	size_t i;

	for (i = 0; i < len; i++)
		diff |= a[i] ^ b[i];
	return diff != 0;
}

static int trustix_aead_vaes_seal_one(const u8 rk[15][16], int rounds,
				      const u8 shash[16],
				      const u8 shash4[4][16],
				      struct trustix_aead_prepared_op *op)
{
	u8 y[16] = {};
	u8 tmp[128] __aligned(32);
	u8 stream[32] __aligned(32);
	u8 tag_mask[16];
	const u8 *src = op->src;
	u8 *dst = op->dst;
	unsigned int len = op->in_len;
	unsigned int off = 0;
	u32 ctr = 2;

	if (op->out_len != op->in_len + TRUSTIX_AEAD_IOC_TAG_LEN)
		return -EINVAL;

	trustix_ctr_block(tmp, op->nonce, 1);
	trustix_aes_encrypt1_asm(rk, rounds, tmp, tag_mask);

	while (len - off >= 128) {
		trustix_ctr8_blocks(tmp, op->nonce, ctr);
		trustix_aes_xor8_vaes_asm(rk, rounds, tmp, src + off,
					   dst + off);
		if (trustix_vaes_agg_ghash)
			trustix_ghash_agg4_blocks_clmul_asm(y, shash4,
							    dst + off, 2);
		else
			trustix_ghash_blocks_clmul_asm(y, shash,
						       dst + off, 8);
		off += 128;
		ctr = 2 + off / 16;
	}
	while (len - off >= 32) {
		trustix_ctr2_blocks(tmp, op->nonce, ctr);
		trustix_aes_xor2_vaes_asm(rk, rounds, tmp, src + off,
					   dst + off);
		trustix_ghash_blocks_clmul_asm(y, shash, dst + off, 2);
		off += 32;
		ctr = 2 + off / 16;
	}
	while (len - off >= 16) {
		trustix_ctr_block(tmp, op->nonce, ctr);
		trustix_aes_encrypt1_asm(rk, rounds, tmp, stream);
		trustix_xor16_asm(dst + off, src + off, stream);
		trustix_ghash_block_clmul_asm(y, shash, dst + off);
		off += 16;
		ctr = 2 + off / 16;
	}
	if (off < len) {
		unsigned int rem = len - off;

		trustix_ctr_block(tmp, op->nonce, ctr);
		trustix_aes_encrypt1_asm(rk, rounds, tmp, stream);
		for (ctr = 0; ctr < rem; ctr++)
			dst[off + ctr] = src[off + ctr] ^ stream[ctr];
		memset(tmp, 0, 16);
		memcpy(tmp, dst + off, rem);
		trustix_ghash_block_clmul_asm(y, shash, tmp);
	}

	memset(tmp, 0, 16);
	trustix_store_be64(tmp + 8, (u64)len * 8);
	trustix_ghash_block_clmul_asm(y, shash, tmp);
	memcpy(tmp, y, TRUSTIX_AEAD_IOC_TAG_LEN);
	for (off = 0; off < TRUSTIX_AEAD_IOC_TAG_LEN; off++)
		dst[len + off] = tmp[off] ^ tag_mask[off];

	trustix_aead_wipe_fastpath(tmp, sizeof(tmp));
	trustix_aead_wipe_fastpath(stream, sizeof(stream));
	trustix_aead_wipe_fastpath(tag_mask, sizeof(tag_mask));
	return 0;
}

static int trustix_aead_vaes_open_one(const u8 rk[15][16], int rounds,
				      const u8 shash[16],
				      const u8 shash4[4][16],
				      struct trustix_aead_prepared_op *op)
{
	u8 y[16] = {};
	u8 tmp[128] __aligned(32);
	u8 stream[32] __aligned(32);
	u8 tag_mask[16];
	u8 expected[16];
	const u8 *src = op->src;
	u8 *dst = op->dst;
	unsigned int cipher_len;
	unsigned int off = 0;
	u32 ctr = 2;
	int ret = 0;

	if (op->in_len < TRUSTIX_AEAD_IOC_TAG_LEN ||
	    op->out_len + TRUSTIX_AEAD_IOC_TAG_LEN != op->in_len)
		return -EINVAL;

	cipher_len = op->in_len - TRUSTIX_AEAD_IOC_TAG_LEN;
	trustix_ctr_block(tmp, op->nonce, 1);
	trustix_aes_encrypt1_asm(rk, rounds, tmp, tag_mask);

	while (cipher_len - off >= 128) {
		if (trustix_vaes_agg_ghash)
			trustix_ghash_agg4_blocks_clmul_asm(y, shash4,
							    src + off, 2);
		else
			trustix_ghash_blocks_clmul_asm(y, shash,
						       src + off, 8);
		trustix_ctr8_blocks(tmp, op->nonce, ctr);
		trustix_aes_xor8_vaes_asm(rk, rounds, tmp, src + off,
					   dst + off);
		off += 128;
		ctr = 2 + off / 16;
	}
	while (cipher_len - off >= 32) {
		trustix_ghash_blocks_clmul_asm(y, shash, src + off, 2);
		trustix_ctr2_blocks(tmp, op->nonce, ctr);
		trustix_aes_xor2_vaes_asm(rk, rounds, tmp, src + off,
					   dst + off);
		off += 32;
		ctr = 2 + off / 16;
	}
	while (cipher_len - off >= 16) {
		trustix_ghash_block_clmul_asm(y, shash, src + off);
		trustix_ctr_block(tmp, op->nonce, ctr);
		trustix_aes_encrypt1_asm(rk, rounds, tmp, stream);
		trustix_xor16_asm(dst + off, src + off, stream);
		off += 16;
		ctr = 2 + off / 16;
	}
	if (off < cipher_len) {
		unsigned int rem = cipher_len - off;
		unsigned int j;

		memset(tmp, 0, 16);
		memcpy(tmp, src + off, rem);
		trustix_ghash_block_clmul_asm(y, shash, tmp);
		trustix_ctr_block(tmp, op->nonce, ctr);
		trustix_aes_encrypt1_asm(rk, rounds, tmp, stream);
		for (j = 0; j < rem; j++)
			dst[off + j] = src[off + j] ^ stream[j];
	}

	memset(tmp, 0, 16);
	trustix_store_be64(tmp + 8, (u64)cipher_len * 8);
	trustix_ghash_block_clmul_asm(y, shash, tmp);
	memcpy(expected, y, TRUSTIX_AEAD_IOC_TAG_LEN);
	for (off = 0; off < TRUSTIX_AEAD_IOC_TAG_LEN; off++)
		expected[off] ^= tag_mask[off];
	if (trustix_consttime_memneq(expected, src + cipher_len,
				     TRUSTIX_AEAD_IOC_TAG_LEN))
		ret = -EBADMSG;

	trustix_aead_wipe_fastpath(tmp, sizeof(tmp));
	trustix_aead_wipe_fastpath(stream, sizeof(stream));
	trustix_aead_wipe_fastpath(tag_mask, sizeof(tag_mask));
	trustix_aead_wipe_fastpath(expected, sizeof(expected));
	if (ret)
		memzero_explicit(dst, op->out_len);
	return ret;
}

static __maybe_unused int
trustix_aead_aesni_seal_one(const u8 rk[15][16], int rounds,
			    const u8 shash[16],
			    const u8 shash4[4][16],
			    struct trustix_aead_prepared_op *op)
{
	u8 y[16] = {};
	u8 tmp[128] __aligned(16);
	u8 stream[16] __aligned(16);
	u8 tag_mask[16];
	const u8 *src = op->src;
	u8 *dst = op->dst;
	unsigned int len = op->in_len;
	unsigned int off = 0;
	u32 ctr = 2;

	if (op->out_len != op->in_len + TRUSTIX_AEAD_IOC_TAG_LEN)
		return -EINVAL;

	trustix_ctr_block(tmp, op->nonce, 1);
	trustix_aes_encrypt1_asm(rk, rounds, tmp, tag_mask);

	while (len - off >= 128) {
		trustix_ctr8_blocks(tmp, op->nonce, ctr);
		trustix_aes_xor8_aesni_asm(rk, rounds, tmp, src + off,
					    dst + off);
		if (trustix_aesni_agg_ghash)
			trustix_ghash_agg4_blocks_clmul_asm(y, shash4,
							    dst + off, 2);
		else
			trustix_ghash_blocks_clmul_asm(y, shash,
						       dst + off, 8);
		off += 128;
		ctr = 2 + off / 16;
	}
	while (len - off >= 64) {
		trustix_ctr4_blocks(tmp, op->nonce, ctr);
		trustix_aes_xor4_aesni_asm(rk, rounds, tmp, src + off,
					    dst + off);
		if (trustix_aesni_agg_ghash)
			trustix_ghash_agg4_blocks_clmul_asm(y, shash4,
							    dst + off, 1);
		else
			trustix_ghash_blocks_clmul_asm(y, shash,
						       dst + off, 4);
		off += 64;
		ctr = 2 + off / 16;
	}
	while (len - off >= 16) {
		trustix_ctr_block(tmp, op->nonce, ctr);
		trustix_aes_encrypt1_asm(rk, rounds, tmp, stream);
		trustix_xor16_asm(dst + off, src + off, stream);
		trustix_ghash_block_clmul_asm(y, shash, dst + off);
		off += 16;
		ctr = 2 + off / 16;
	}
	if (off < len) {
		unsigned int rem = len - off;

		trustix_ctr_block(tmp, op->nonce, ctr);
		trustix_aes_encrypt1_asm(rk, rounds, tmp, stream);
		for (ctr = 0; ctr < rem; ctr++)
			dst[off + ctr] = src[off + ctr] ^ stream[ctr];
		memset(tmp, 0, sizeof(tmp));
		memcpy(tmp, dst + off, rem);
		trustix_ghash_block_clmul_asm(y, shash, tmp);
	}

	memset(tmp, 0, sizeof(tmp));
	trustix_store_be64(tmp + 8, (u64)len * 8);
	trustix_ghash_block_clmul_asm(y, shash, tmp);
	memcpy(tmp, y, TRUSTIX_AEAD_IOC_TAG_LEN);
	for (off = 0; off < TRUSTIX_AEAD_IOC_TAG_LEN; off++)
		dst[len + off] = tmp[off] ^ tag_mask[off];

	trustix_aead_wipe_fastpath(tmp, sizeof(tmp));
	trustix_aead_wipe_fastpath(stream, sizeof(stream));
	trustix_aead_wipe_fastpath(tag_mask, sizeof(tag_mask));
	return 0;
}

static __maybe_unused int
trustix_aead_aesni_open_one(const u8 rk[15][16], int rounds,
			    const u8 shash[16],
			    const u8 shash4[4][16],
			    struct trustix_aead_prepared_op *op)
{
	u8 y[16] = {};
	u8 tmp[128] __aligned(16);
	u8 stream[16] __aligned(16);
	u8 tag_mask[16];
	u8 expected[16];
	const u8 *src = op->src;
	u8 *dst = op->dst;
	unsigned int cipher_len;
	unsigned int off = 0;
	u32 ctr = 2;
	int ret = 0;

	if (op->in_len < TRUSTIX_AEAD_IOC_TAG_LEN ||
	    op->out_len + TRUSTIX_AEAD_IOC_TAG_LEN != op->in_len)
		return -EINVAL;

	cipher_len = op->in_len - TRUSTIX_AEAD_IOC_TAG_LEN;
	trustix_ctr_block(tmp, op->nonce, 1);
	trustix_aes_encrypt1_asm(rk, rounds, tmp, tag_mask);

	while (cipher_len - off >= 128) {
		if (trustix_aesni_agg_ghash)
			trustix_ghash_agg4_blocks_clmul_asm(y, shash4,
							    src + off, 2);
		else
			trustix_ghash_blocks_clmul_asm(y, shash,
						       src + off, 8);
		trustix_ctr8_blocks(tmp, op->nonce, ctr);
		trustix_aes_xor8_aesni_asm(rk, rounds, tmp, src + off,
					    dst + off);
		off += 128;
		ctr = 2 + off / 16;
	}
	while (cipher_len - off >= 64) {
		if (trustix_aesni_agg_ghash)
			trustix_ghash_agg4_blocks_clmul_asm(y, shash4,
							    src + off, 1);
		else
			trustix_ghash_blocks_clmul_asm(y, shash,
						       src + off, 4);
		trustix_ctr4_blocks(tmp, op->nonce, ctr);
		trustix_aes_xor4_aesni_asm(rk, rounds, tmp, src + off,
					    dst + off);
		off += 64;
		ctr = 2 + off / 16;
	}
	while (cipher_len - off >= 16) {
		trustix_ghash_block_clmul_asm(y, shash, src + off);
		trustix_ctr_block(tmp, op->nonce, ctr);
		trustix_aes_encrypt1_asm(rk, rounds, tmp, stream);
		trustix_xor16_asm(dst + off, src + off, stream);
		off += 16;
		ctr = 2 + off / 16;
	}
	if (off < cipher_len) {
		unsigned int rem = cipher_len - off;
		unsigned int j;

		memset(tmp, 0, sizeof(tmp));
		memcpy(tmp, src + off, rem);
		trustix_ghash_block_clmul_asm(y, shash, tmp);
		trustix_ctr_block(tmp, op->nonce, ctr);
		trustix_aes_encrypt1_asm(rk, rounds, tmp, stream);
		for (j = 0; j < rem; j++)
			dst[off + j] = src[off + j] ^ stream[j];
	}

	memset(tmp, 0, sizeof(tmp));
	trustix_store_be64(tmp + 8, (u64)cipher_len * 8);
	trustix_ghash_block_clmul_asm(y, shash, tmp);
	memcpy(expected, y, TRUSTIX_AEAD_IOC_TAG_LEN);
	for (off = 0; off < TRUSTIX_AEAD_IOC_TAG_LEN; off++)
		expected[off] ^= tag_mask[off];
	if (trustix_consttime_memneq(expected, src + cipher_len,
				     TRUSTIX_AEAD_IOC_TAG_LEN))
		ret = -EBADMSG;

	trustix_aead_wipe_fastpath(tmp, sizeof(tmp));
	trustix_aead_wipe_fastpath(stream, sizeof(stream));
	trustix_aead_wipe_fastpath(tag_mask, sizeof(tag_mask));
	trustix_aead_wipe_fastpath(expected, sizeof(expected));
	if (ret)
		memzero_explicit(dst, op->out_len);
	return ret;
}

static int trustix_aead_aesni_seal4_prepared(const u8 rk[15][16], int rounds,
					     const u8 shash[16],
					     const u8 shash4[4][16],
					     struct trustix_aead_prepared_op *ops)
{
	u8 y0[16] = {};
	u8 y1[16] = {};
	u8 y2[16] = {};
	u8 y3[16] = {};
	u8 tmp0[128] __aligned(16);
	u8 tmp1[128] __aligned(16);
	u8 tmp2[128] __aligned(16);
	u8 tmp3[128] __aligned(16);
	u8 stream[16] __aligned(16);
	u8 tag_mask0[16];
	u8 tag_mask1[16];
	u8 tag_mask2[16];
	u8 tag_mask3[16];
	unsigned int len;
	unsigned int off = 0;
	u32 ctr = 2;

	if (!ops)
		return -EINVAL;
	len = ops[0].in_len;
	if (!len ||
	    ops[1].in_len != len || ops[2].in_len != len ||
	    ops[3].in_len != len ||
	    ops[0].out_len != len + TRUSTIX_AEAD_IOC_TAG_LEN ||
	    ops[1].out_len != len + TRUSTIX_AEAD_IOC_TAG_LEN ||
	    ops[2].out_len != len + TRUSTIX_AEAD_IOC_TAG_LEN ||
	    ops[3].out_len != len + TRUSTIX_AEAD_IOC_TAG_LEN)
		return -EOPNOTSUPP;

	trustix_ctr_block(tmp0, ops[0].nonce, 1);
	trustix_aes_encrypt1_asm(rk, rounds, tmp0, tag_mask0);
	trustix_ctr_block(tmp0, ops[1].nonce, 1);
	trustix_aes_encrypt1_asm(rk, rounds, tmp0, tag_mask1);
	trustix_ctr_block(tmp0, ops[2].nonce, 1);
	trustix_aes_encrypt1_asm(rk, rounds, tmp0, tag_mask2);
	trustix_ctr_block(tmp0, ops[3].nonce, 1);
	trustix_aes_encrypt1_asm(rk, rounds, tmp0, tag_mask3);

	while (len - off >= 128) {
		trustix_ctr8_blocks(tmp0, ops[0].nonce, ctr);
		trustix_aes_xor8_aesni_asm(rk, rounds, tmp0,
					    ops[0].src + off,
					    ops[0].dst + off);
		trustix_ctr8_blocks(tmp1, ops[1].nonce, ctr);
		trustix_aes_xor8_aesni_asm(rk, rounds, tmp1,
					    ops[1].src + off,
					    ops[1].dst + off);
		trustix_ctr8_blocks(tmp2, ops[2].nonce, ctr);
		trustix_aes_xor8_aesni_asm(rk, rounds, tmp2,
					    ops[2].src + off,
					    ops[2].dst + off);
		trustix_ctr8_blocks(tmp3, ops[3].nonce, ctr);
		trustix_aes_xor8_aesni_asm(rk, rounds, tmp3,
					    ops[3].src + off,
					    ops[3].dst + off);
		if (trustix_aesni_agg_ghash) {
			trustix_ghash4_agg4_blocks_clmul_asm(
				y0, y1, y2, y3, shash4,
				ops[0].dst + off, ops[1].dst + off,
				ops[2].dst + off, ops[3].dst + off, 2);
		} else {
			trustix_ghash4_blocks_clmul_asm(
				y0, y1, y2, y3, shash,
				ops[0].dst + off, ops[1].dst + off,
				ops[2].dst + off, ops[3].dst + off, 8);
		}
		off += 128;
		ctr = 2 + off / 16;
	}
	while (len - off >= 64) {
		trustix_ctr4_blocks(tmp0, ops[0].nonce, ctr);
		trustix_aes_xor4_aesni_asm(rk, rounds, tmp0,
					    ops[0].src + off,
					    ops[0].dst + off);
		trustix_ctr4_blocks(tmp1, ops[1].nonce, ctr);
		trustix_aes_xor4_aesni_asm(rk, rounds, tmp1,
					    ops[1].src + off,
					    ops[1].dst + off);
		trustix_ctr4_blocks(tmp2, ops[2].nonce, ctr);
		trustix_aes_xor4_aesni_asm(rk, rounds, tmp2,
					    ops[2].src + off,
					    ops[2].dst + off);
		trustix_ctr4_blocks(tmp3, ops[3].nonce, ctr);
		trustix_aes_xor4_aesni_asm(rk, rounds, tmp3,
					    ops[3].src + off,
					    ops[3].dst + off);
		if (trustix_aesni_agg_ghash) {
			trustix_ghash4_agg4_blocks_clmul_asm(
				y0, y1, y2, y3, shash4,
				ops[0].dst + off, ops[1].dst + off,
				ops[2].dst + off, ops[3].dst + off, 1);
		} else {
			trustix_ghash4_blocks_clmul_asm(
				y0, y1, y2, y3, shash,
				ops[0].dst + off, ops[1].dst + off,
				ops[2].dst + off, ops[3].dst + off, 4);
		}
		off += 64;
		ctr = 2 + off / 16;
	}
	while (len - off >= 16) {
		trustix_ctr_block(tmp0, ops[0].nonce, ctr);
		trustix_aes_encrypt1_asm(rk, rounds, tmp0, stream);
		trustix_xor16_asm(ops[0].dst + off, ops[0].src + off, stream);
		trustix_ghash_block_clmul_asm(y0, shash, ops[0].dst + off);

		trustix_ctr_block(tmp0, ops[1].nonce, ctr);
		trustix_aes_encrypt1_asm(rk, rounds, tmp0, stream);
		trustix_xor16_asm(ops[1].dst + off, ops[1].src + off, stream);
		trustix_ghash_block_clmul_asm(y1, shash, ops[1].dst + off);

		trustix_ctr_block(tmp0, ops[2].nonce, ctr);
		trustix_aes_encrypt1_asm(rk, rounds, tmp0, stream);
		trustix_xor16_asm(ops[2].dst + off, ops[2].src + off, stream);
		trustix_ghash_block_clmul_asm(y2, shash, ops[2].dst + off);

		trustix_ctr_block(tmp0, ops[3].nonce, ctr);
		trustix_aes_encrypt1_asm(rk, rounds, tmp0, stream);
		trustix_xor16_asm(ops[3].dst + off, ops[3].src + off, stream);
		trustix_ghash_block_clmul_asm(y3, shash, ops[3].dst + off);

		off += 16;
		ctr = 2 + off / 16;
	}
	if (off < len) {
		unsigned int rem = len - off;
		u32 tail_ctr = 2 + off / 16;
		unsigned int j;

		trustix_ctr_block(tmp0, ops[0].nonce, tail_ctr);
		trustix_aes_encrypt1_asm(rk, rounds, tmp0, stream);
		for (j = 0; j < rem; j++)
			ops[0].dst[off + j] = ops[0].src[off + j] ^ stream[j];
		memset(tmp0, 0, 16);
		memcpy(tmp0, ops[0].dst + off, rem);
		trustix_ghash_block_clmul_asm(y0, shash, tmp0);

		trustix_ctr_block(tmp0, ops[1].nonce, tail_ctr);
		trustix_aes_encrypt1_asm(rk, rounds, tmp0, stream);
		for (j = 0; j < rem; j++)
			ops[1].dst[off + j] = ops[1].src[off + j] ^ stream[j];
		memset(tmp0, 0, 16);
		memcpy(tmp0, ops[1].dst + off, rem);
		trustix_ghash_block_clmul_asm(y1, shash, tmp0);

		trustix_ctr_block(tmp0, ops[2].nonce, tail_ctr);
		trustix_aes_encrypt1_asm(rk, rounds, tmp0, stream);
		for (j = 0; j < rem; j++)
			ops[2].dst[off + j] = ops[2].src[off + j] ^ stream[j];
		memset(tmp0, 0, 16);
		memcpy(tmp0, ops[2].dst + off, rem);
		trustix_ghash_block_clmul_asm(y2, shash, tmp0);

		trustix_ctr_block(tmp0, ops[3].nonce, tail_ctr);
		trustix_aes_encrypt1_asm(rk, rounds, tmp0, stream);
		for (j = 0; j < rem; j++)
			ops[3].dst[off + j] = ops[3].src[off + j] ^ stream[j];
		memset(tmp0, 0, 16);
		memcpy(tmp0, ops[3].dst + off, rem);
		trustix_ghash_block_clmul_asm(y3, shash, tmp0);
	}

	memset(tmp0, 0, 16);
	trustix_store_be64(tmp0 + 8, (u64)len * 8);
	trustix_ghash_block_clmul_asm(y0, shash, tmp0);
	trustix_ghash_block_clmul_asm(y1, shash, tmp0);
	trustix_ghash_block_clmul_asm(y2, shash, tmp0);
	trustix_ghash_block_clmul_asm(y3, shash, tmp0);

	memcpy(tmp0, y0, TRUSTIX_AEAD_IOC_TAG_LEN);
	for (off = 0; off < TRUSTIX_AEAD_IOC_TAG_LEN; off++)
		ops[0].dst[len + off] = tmp0[off] ^ tag_mask0[off];
	memcpy(tmp0, y1, TRUSTIX_AEAD_IOC_TAG_LEN);
	for (off = 0; off < TRUSTIX_AEAD_IOC_TAG_LEN; off++)
		ops[1].dst[len + off] = tmp0[off] ^ tag_mask1[off];
	memcpy(tmp0, y2, TRUSTIX_AEAD_IOC_TAG_LEN);
	for (off = 0; off < TRUSTIX_AEAD_IOC_TAG_LEN; off++)
		ops[2].dst[len + off] = tmp0[off] ^ tag_mask2[off];
	memcpy(tmp0, y3, TRUSTIX_AEAD_IOC_TAG_LEN);
	for (off = 0; off < TRUSTIX_AEAD_IOC_TAG_LEN; off++)
		ops[3].dst[len + off] = tmp0[off] ^ tag_mask3[off];

	trustix_aead_wipe_fastpath(tmp0, sizeof(tmp0));
	trustix_aead_wipe_fastpath(tmp1, sizeof(tmp1));
	trustix_aead_wipe_fastpath(tmp2, sizeof(tmp2));
	trustix_aead_wipe_fastpath(tmp3, sizeof(tmp3));
	trustix_aead_wipe_fastpath(stream, sizeof(stream));
	trustix_aead_wipe_fastpath(tag_mask0, sizeof(tag_mask0));
	trustix_aead_wipe_fastpath(tag_mask1, sizeof(tag_mask1));
	trustix_aead_wipe_fastpath(tag_mask2, sizeof(tag_mask2));
	trustix_aead_wipe_fastpath(tag_mask3, sizeof(tag_mask3));
	return 0;
}

static int trustix_aead_vaes_open4_prepared(const u8 rk[15][16], int rounds,
					    const u8 shash[16],
					    const u8 shash4[4][16],
					    struct trustix_aead_prepared_op *ops)
{
	u8 y0[16] = {};
	u8 y1[16] = {};
	u8 y2[16] = {};
	u8 y3[16] = {};
	u8 tmp0[128] __aligned(32);
	u8 tmp1[128] __aligned(32);
	u8 tmp2[128] __aligned(32);
	u8 tmp3[128] __aligned(32);
	u8 stream[32] __aligned(32);
	u8 tag_mask0[16];
	u8 tag_mask1[16];
	u8 tag_mask2[16];
	u8 tag_mask3[16];
	u8 expected0[16];
	u8 expected1[16];
	u8 expected2[16];
	u8 expected3[16];
	unsigned int cipher_len;
	unsigned int off = 0;
	u32 ctr = 2;
	int ret = 0;

	if (!ops || ops[0].in_len < TRUSTIX_AEAD_IOC_TAG_LEN)
		return -EINVAL;
	cipher_len = ops[0].in_len - TRUSTIX_AEAD_IOC_TAG_LEN;
	if (!cipher_len ||
	    ops[1].in_len != ops[0].in_len ||
	    ops[2].in_len != ops[0].in_len ||
	    ops[3].in_len != ops[0].in_len ||
	    ops[0].out_len != cipher_len ||
	    ops[1].out_len != cipher_len ||
	    ops[2].out_len != cipher_len ||
	    ops[3].out_len != cipher_len)
		return -EOPNOTSUPP;

	trustix_ctr_block(tmp0, ops[0].nonce, 1);
	trustix_aes_encrypt1_asm(rk, rounds, tmp0, tag_mask0);
	trustix_ctr_block(tmp0, ops[1].nonce, 1);
	trustix_aes_encrypt1_asm(rk, rounds, tmp0, tag_mask1);
	trustix_ctr_block(tmp0, ops[2].nonce, 1);
	trustix_aes_encrypt1_asm(rk, rounds, tmp0, tag_mask2);
	trustix_ctr_block(tmp0, ops[3].nonce, 1);
	trustix_aes_encrypt1_asm(rk, rounds, tmp0, tag_mask3);

	while (cipher_len - off >= 128) {
		if (trustix_vaes_agg_ghash) {
			trustix_ghash4_agg4_blocks_clmul_asm(
				y0, y1, y2, y3, shash4,
				ops[0].src + off, ops[1].src + off,
				ops[2].src + off, ops[3].src + off, 2);
		} else {
			trustix_ghash4_blocks_clmul_asm(
				y0, y1, y2, y3, shash,
				ops[0].src + off, ops[1].src + off,
				ops[2].src + off, ops[3].src + off, 8);
		}

		trustix_ctr8_blocks(tmp0, ops[0].nonce, ctr);
		trustix_ctr8_blocks(tmp1, ops[1].nonce, ctr);
		trustix_ctr8_blocks(tmp2, ops[2].nonce, ctr);
		trustix_ctr8_blocks(tmp3, ops[3].nonce, ctr);
		trustix_aes_xor4x4_vaes_asm(
			rk, rounds, tmp0, tmp1, tmp2, tmp3,
			ops[0].src + off, ops[1].src + off,
			ops[2].src + off, ops[3].src + off,
			ops[0].dst + off, ops[1].dst + off,
			ops[2].dst + off, ops[3].dst + off);
		trustix_aes_xor4x4_vaes_asm(
			rk, rounds, tmp0 + 64, tmp1 + 64, tmp2 + 64,
			tmp3 + 64, ops[0].src + off + 64,
			ops[1].src + off + 64, ops[2].src + off + 64,
			ops[3].src + off + 64, ops[0].dst + off + 64,
			ops[1].dst + off + 64, ops[2].dst + off + 64,
			ops[3].dst + off + 64);

		off += 128;
		ctr = 2 + off / 16;
	}
	while (cipher_len - off >= 32) {
		trustix_ghash4_blocks_clmul_asm(y0, y1, y2, y3, shash,
						 ops[0].src + off,
						 ops[1].src + off,
						 ops[2].src + off,
						 ops[3].src + off, 2);

		trustix_ctr2_blocks(tmp0, ops[0].nonce, ctr);
		trustix_aes_xor2_vaes_asm(rk, rounds, tmp0,
					   ops[0].src + off,
					   ops[0].dst + off);

		trustix_ctr2_blocks(tmp0, ops[1].nonce, ctr);
		trustix_aes_xor2_vaes_asm(rk, rounds, tmp0,
					   ops[1].src + off,
					   ops[1].dst + off);

		trustix_ctr2_blocks(tmp0, ops[2].nonce, ctr);
		trustix_aes_xor2_vaes_asm(rk, rounds, tmp0,
					   ops[2].src + off,
					   ops[2].dst + off);

		trustix_ctr2_blocks(tmp0, ops[3].nonce, ctr);
		trustix_aes_xor2_vaes_asm(rk, rounds, tmp0,
					   ops[3].src + off,
					   ops[3].dst + off);

		off += 32;
		ctr = 2 + off / 16;
	}
	while (cipher_len - off >= 16) {
		trustix_ghash_block_clmul_asm(y0, shash, ops[0].src + off);
		trustix_ctr_block(tmp0, ops[0].nonce, ctr);
		trustix_aes_encrypt1_asm(rk, rounds, tmp0, stream);
		trustix_xor16_asm(ops[0].dst + off, ops[0].src + off, stream);

		trustix_ghash_block_clmul_asm(y1, shash, ops[1].src + off);
		trustix_ctr_block(tmp0, ops[1].nonce, ctr);
		trustix_aes_encrypt1_asm(rk, rounds, tmp0, stream);
		trustix_xor16_asm(ops[1].dst + off, ops[1].src + off, stream);

		trustix_ghash_block_clmul_asm(y2, shash, ops[2].src + off);
		trustix_ctr_block(tmp0, ops[2].nonce, ctr);
		trustix_aes_encrypt1_asm(rk, rounds, tmp0, stream);
		trustix_xor16_asm(ops[2].dst + off, ops[2].src + off, stream);

		trustix_ghash_block_clmul_asm(y3, shash, ops[3].src + off);
		trustix_ctr_block(tmp0, ops[3].nonce, ctr);
		trustix_aes_encrypt1_asm(rk, rounds, tmp0, stream);
		trustix_xor16_asm(ops[3].dst + off, ops[3].src + off, stream);

		off += 16;
		ctr = 2 + off / 16;
	}
	if (off < cipher_len) {
		unsigned int rem = cipher_len - off;
		u32 tail_ctr = 2 + off / 16;
		unsigned int j;

		memset(tmp0, 0, 16);
		memcpy(tmp0, ops[0].src + off, rem);
		trustix_ghash_block_clmul_asm(y0, shash, tmp0);
		trustix_ctr_block(tmp0, ops[0].nonce, tail_ctr);
		trustix_aes_encrypt1_asm(rk, rounds, tmp0, stream);
		for (j = 0; j < rem; j++)
			ops[0].dst[off + j] = ops[0].src[off + j] ^ stream[j];

		memset(tmp0, 0, 16);
		memcpy(tmp0, ops[1].src + off, rem);
		trustix_ghash_block_clmul_asm(y1, shash, tmp0);
		trustix_ctr_block(tmp0, ops[1].nonce, tail_ctr);
		trustix_aes_encrypt1_asm(rk, rounds, tmp0, stream);
		for (j = 0; j < rem; j++)
			ops[1].dst[off + j] = ops[1].src[off + j] ^ stream[j];

		memset(tmp0, 0, 16);
		memcpy(tmp0, ops[2].src + off, rem);
		trustix_ghash_block_clmul_asm(y2, shash, tmp0);
		trustix_ctr_block(tmp0, ops[2].nonce, tail_ctr);
		trustix_aes_encrypt1_asm(rk, rounds, tmp0, stream);
		for (j = 0; j < rem; j++)
			ops[2].dst[off + j] = ops[2].src[off + j] ^ stream[j];

		memset(tmp0, 0, 16);
		memcpy(tmp0, ops[3].src + off, rem);
		trustix_ghash_block_clmul_asm(y3, shash, tmp0);
		trustix_ctr_block(tmp0, ops[3].nonce, tail_ctr);
		trustix_aes_encrypt1_asm(rk, rounds, tmp0, stream);
		for (j = 0; j < rem; j++)
			ops[3].dst[off + j] = ops[3].src[off + j] ^ stream[j];
	}

	memset(tmp0, 0, 16);
	trustix_store_be64(tmp0 + 8, (u64)cipher_len * 8);
	trustix_ghash_block_clmul_asm(y0, shash, tmp0);
	trustix_ghash_block_clmul_asm(y1, shash, tmp0);
	trustix_ghash_block_clmul_asm(y2, shash, tmp0);
	trustix_ghash_block_clmul_asm(y3, shash, tmp0);

	memcpy(expected0, y0, TRUSTIX_AEAD_IOC_TAG_LEN);
	memcpy(expected1, y1, TRUSTIX_AEAD_IOC_TAG_LEN);
	memcpy(expected2, y2, TRUSTIX_AEAD_IOC_TAG_LEN);
	memcpy(expected3, y3, TRUSTIX_AEAD_IOC_TAG_LEN);
	for (off = 0; off < TRUSTIX_AEAD_IOC_TAG_LEN; off++) {
		expected0[off] ^= tag_mask0[off];
		expected1[off] ^= tag_mask1[off];
		expected2[off] ^= tag_mask2[off];
		expected3[off] ^= tag_mask3[off];
	}
	if (trustix_consttime_memneq(expected0, ops[0].src + cipher_len,
				     TRUSTIX_AEAD_IOC_TAG_LEN)) {
		memzero_explicit(ops[0].dst, ops[0].out_len);
		ret = -EBADMSG;
	}
	if (trustix_consttime_memneq(expected1, ops[1].src + cipher_len,
				     TRUSTIX_AEAD_IOC_TAG_LEN)) {
		memzero_explicit(ops[1].dst, ops[1].out_len);
		ret = -EBADMSG;
	}
	if (trustix_consttime_memneq(expected2, ops[2].src + cipher_len,
				     TRUSTIX_AEAD_IOC_TAG_LEN)) {
		memzero_explicit(ops[2].dst, ops[2].out_len);
		ret = -EBADMSG;
	}
	if (trustix_consttime_memneq(expected3, ops[3].src + cipher_len,
				     TRUSTIX_AEAD_IOC_TAG_LEN)) {
		memzero_explicit(ops[3].dst, ops[3].out_len);
		ret = -EBADMSG;
	}

	trustix_aead_wipe_fastpath(tmp0, sizeof(tmp0));
	trustix_aead_wipe_fastpath(tmp1, sizeof(tmp1));
	trustix_aead_wipe_fastpath(tmp2, sizeof(tmp2));
	trustix_aead_wipe_fastpath(tmp3, sizeof(tmp3));
	trustix_aead_wipe_fastpath(stream, sizeof(stream));
	trustix_aead_wipe_fastpath(tag_mask0, sizeof(tag_mask0));
	trustix_aead_wipe_fastpath(tag_mask1, sizeof(tag_mask1));
	trustix_aead_wipe_fastpath(tag_mask2, sizeof(tag_mask2));
	trustix_aead_wipe_fastpath(tag_mask3, sizeof(tag_mask3));
	trustix_aead_wipe_fastpath(expected0, sizeof(expected0));
	trustix_aead_wipe_fastpath(expected1, sizeof(expected1));
	trustix_aead_wipe_fastpath(expected2, sizeof(expected2));
	trustix_aead_wipe_fastpath(expected3, sizeof(expected3));
	return ret;
}

static int trustix_aead_vaes_seal4_prepared(const u8 rk[15][16], int rounds,
					    const u8 shash[16],
					    const u8 shash4[4][16],
					    struct trustix_aead_prepared_op *ops)
{
	u8 y0[16] = {};
	u8 y1[16] = {};
	u8 y2[16] = {};
	u8 y3[16] = {};
	u8 tmp0[128] __aligned(32);
	u8 tmp1[128] __aligned(32);
	u8 tmp2[128] __aligned(32);
	u8 tmp3[128] __aligned(32);
	u8 stream[32] __aligned(32);
	u8 tag_mask0[16];
	u8 tag_mask1[16];
	u8 tag_mask2[16];
	u8 tag_mask3[16];
	unsigned int len;
	unsigned int off = 0;
	u32 ctr = 2;

	if (!ops)
		return -EINVAL;
	len = ops[0].in_len;
	if (!len ||
	    ops[1].in_len != len || ops[2].in_len != len ||
	    ops[3].in_len != len ||
	    ops[0].out_len != len + TRUSTIX_AEAD_IOC_TAG_LEN ||
	    ops[1].out_len != len + TRUSTIX_AEAD_IOC_TAG_LEN ||
	    ops[2].out_len != len + TRUSTIX_AEAD_IOC_TAG_LEN ||
	    ops[3].out_len != len + TRUSTIX_AEAD_IOC_TAG_LEN)
		return -EOPNOTSUPP;

	trustix_ctr_block(tmp0, ops[0].nonce, 1);
	trustix_aes_encrypt1_asm(rk, rounds, tmp0, tag_mask0);
	trustix_ctr_block(tmp0, ops[1].nonce, 1);
	trustix_aes_encrypt1_asm(rk, rounds, tmp0, tag_mask1);
	trustix_ctr_block(tmp0, ops[2].nonce, 1);
	trustix_aes_encrypt1_asm(rk, rounds, tmp0, tag_mask2);
	trustix_ctr_block(tmp0, ops[3].nonce, 1);
	trustix_aes_encrypt1_asm(rk, rounds, tmp0, tag_mask3);

	while (len - off >= 128) {
		trustix_ctr8_blocks(tmp0, ops[0].nonce, ctr);
		trustix_ctr8_blocks(tmp1, ops[1].nonce, ctr);
		trustix_ctr8_blocks(tmp2, ops[2].nonce, ctr);
		trustix_ctr8_blocks(tmp3, ops[3].nonce, ctr);
		if (trustix_vaes_fused_ghash) {
			struct trustix_aes_xor4x4_ghash_args args0;
			struct trustix_aes_xor4x4_ghash_args args1;

			args0.in0 = tmp0;
			args0.in1 = tmp1;
			args0.in2 = tmp2;
			args0.in3 = tmp3;
			args0.src0 = ops[0].src + off;
			args0.src1 = ops[1].src + off;
			args0.src2 = ops[2].src + off;
			args0.src3 = ops[3].src + off;
			args0.dst0 = ops[0].dst + off;
			args0.dst1 = ops[1].dst + off;
			args0.dst2 = ops[2].dst + off;
			args0.dst3 = ops[3].dst + off;
			args0.y0 = y0;
			args0.y1 = y1;
			args0.y2 = y2;
			args0.y3 = y3;
			args0.shash = shash;
			args1 = args0;
			args1.in0 = tmp0 + 64;
			args1.in1 = tmp1 + 64;
			args1.in2 = tmp2 + 64;
			args1.in3 = tmp3 + 64;
			args1.src0 = ops[0].src + off + 64;
			args1.src1 = ops[1].src + off + 64;
			args1.src2 = ops[2].src + off + 64;
			args1.src3 = ops[3].src + off + 64;
			args1.dst0 = ops[0].dst + off + 64;
			args1.dst1 = ops[1].dst + off + 64;
			args1.dst2 = ops[2].dst + off + 64;
			args1.dst3 = ops[3].dst + off + 64;
			trustix_aes_xor4x4_ghash_vaes_asm(rk, rounds, &args0);
			trustix_aes_xor4x4_ghash_vaes_asm(rk, rounds, &args1);
		} else {
			trustix_aes_xor4x4_vaes_asm(
				rk, rounds, tmp0, tmp1, tmp2, tmp3,
				ops[0].src + off, ops[1].src + off,
				ops[2].src + off, ops[3].src + off,
				ops[0].dst + off, ops[1].dst + off,
				ops[2].dst + off, ops[3].dst + off);
			trustix_aes_xor4x4_vaes_asm(
				rk, rounds, tmp0 + 64, tmp1 + 64, tmp2 + 64,
				tmp3 + 64, ops[0].src + off + 64,
				ops[1].src + off + 64, ops[2].src + off + 64,
				ops[3].src + off + 64, ops[0].dst + off + 64,
				ops[1].dst + off + 64, ops[2].dst + off + 64,
				ops[3].dst + off + 64);

			if (trustix_vaes_agg_ghash) {
				trustix_ghash4_agg4_blocks_clmul_asm(
					y0, y1, y2, y3, shash4,
					ops[0].dst + off, ops[1].dst + off,
					ops[2].dst + off, ops[3].dst + off, 2);
			} else {
				trustix_ghash4_blocks_clmul_asm(
					y0, y1, y2, y3, shash,
					ops[0].dst + off, ops[1].dst + off,
					ops[2].dst + off, ops[3].dst + off, 8);
			}
		}

		off += 128;
		ctr = 2 + off / 16;
	}
	while (len - off >= 32) {
		trustix_ctr2_blocks(tmp0, ops[0].nonce, ctr);
		trustix_aes_xor2_vaes_asm(rk, rounds, tmp0,
					   ops[0].src + off,
					   ops[0].dst + off);

		trustix_ctr2_blocks(tmp0, ops[1].nonce, ctr);
		trustix_aes_xor2_vaes_asm(rk, rounds, tmp0,
					   ops[1].src + off,
					   ops[1].dst + off);

		trustix_ctr2_blocks(tmp0, ops[2].nonce, ctr);
		trustix_aes_xor2_vaes_asm(rk, rounds, tmp0,
					   ops[2].src + off,
					   ops[2].dst + off);

		trustix_ctr2_blocks(tmp0, ops[3].nonce, ctr);
		trustix_aes_xor2_vaes_asm(rk, rounds, tmp0,
					   ops[3].src + off,
					   ops[3].dst + off);

		trustix_ghash4_blocks_clmul_asm(y0, y1, y2, y3, shash,
						 ops[0].dst + off,
						 ops[1].dst + off,
						 ops[2].dst + off,
						 ops[3].dst + off, 2);

		off += 32;
		ctr = 2 + off / 16;
	}
	while (len - off >= 16) {
		trustix_ctr_block(tmp0, ops[0].nonce, ctr);
		trustix_aes_encrypt1_asm(rk, rounds, tmp0, stream);
		trustix_xor16_asm(ops[0].dst + off, ops[0].src + off, stream);
		trustix_ghash_block_clmul_asm(y0, shash, ops[0].dst + off);

		trustix_ctr_block(tmp0, ops[1].nonce, ctr);
		trustix_aes_encrypt1_asm(rk, rounds, tmp0, stream);
		trustix_xor16_asm(ops[1].dst + off, ops[1].src + off, stream);
		trustix_ghash_block_clmul_asm(y1, shash, ops[1].dst + off);

		trustix_ctr_block(tmp0, ops[2].nonce, ctr);
		trustix_aes_encrypt1_asm(rk, rounds, tmp0, stream);
		trustix_xor16_asm(ops[2].dst + off, ops[2].src + off, stream);
		trustix_ghash_block_clmul_asm(y2, shash, ops[2].dst + off);

		trustix_ctr_block(tmp0, ops[3].nonce, ctr);
		trustix_aes_encrypt1_asm(rk, rounds, tmp0, stream);
		trustix_xor16_asm(ops[3].dst + off, ops[3].src + off, stream);
		trustix_ghash_block_clmul_asm(y3, shash, ops[3].dst + off);

		off += 16;
		ctr = 2 + off / 16;
	}
	if (off < len) {
		unsigned int rem = len - off;
		u32 tail_ctr = 2 + off / 16;
		unsigned int j;

		trustix_ctr_block(tmp0, ops[0].nonce, tail_ctr);
		trustix_aes_encrypt1_asm(rk, rounds, tmp0, stream);
		for (j = 0; j < rem; j++)
			ops[0].dst[off + j] = ops[0].src[off + j] ^ stream[j];
		memset(tmp0, 0, 16);
		memcpy(tmp0, ops[0].dst + off, rem);
		trustix_ghash_block_clmul_asm(y0, shash, tmp0);

		trustix_ctr_block(tmp0, ops[1].nonce, tail_ctr);
		trustix_aes_encrypt1_asm(rk, rounds, tmp0, stream);
		for (j = 0; j < rem; j++)
			ops[1].dst[off + j] = ops[1].src[off + j] ^ stream[j];
		memset(tmp0, 0, 16);
		memcpy(tmp0, ops[1].dst + off, rem);
		trustix_ghash_block_clmul_asm(y1, shash, tmp0);

		trustix_ctr_block(tmp0, ops[2].nonce, tail_ctr);
		trustix_aes_encrypt1_asm(rk, rounds, tmp0, stream);
		for (j = 0; j < rem; j++)
			ops[2].dst[off + j] = ops[2].src[off + j] ^ stream[j];
		memset(tmp0, 0, 16);
		memcpy(tmp0, ops[2].dst + off, rem);
		trustix_ghash_block_clmul_asm(y2, shash, tmp0);

		trustix_ctr_block(tmp0, ops[3].nonce, tail_ctr);
		trustix_aes_encrypt1_asm(rk, rounds, tmp0, stream);
		for (j = 0; j < rem; j++)
			ops[3].dst[off + j] = ops[3].src[off + j] ^ stream[j];
		memset(tmp0, 0, 16);
		memcpy(tmp0, ops[3].dst + off, rem);
		trustix_ghash_block_clmul_asm(y3, shash, tmp0);
	}

	memset(tmp0, 0, 16);
	trustix_store_be64(tmp0 + 8, (u64)len * 8);
	trustix_ghash_block_clmul_asm(y0, shash, tmp0);
	trustix_ghash_block_clmul_asm(y1, shash, tmp0);
	trustix_ghash_block_clmul_asm(y2, shash, tmp0);
	trustix_ghash_block_clmul_asm(y3, shash, tmp0);

	memcpy(tmp0, y0, TRUSTIX_AEAD_IOC_TAG_LEN);
	for (off = 0; off < TRUSTIX_AEAD_IOC_TAG_LEN; off++)
		ops[0].dst[len + off] = tmp0[off] ^ tag_mask0[off];
	memcpy(tmp0, y1, TRUSTIX_AEAD_IOC_TAG_LEN);
	for (off = 0; off < TRUSTIX_AEAD_IOC_TAG_LEN; off++)
		ops[1].dst[len + off] = tmp0[off] ^ tag_mask1[off];
	memcpy(tmp0, y2, TRUSTIX_AEAD_IOC_TAG_LEN);
	for (off = 0; off < TRUSTIX_AEAD_IOC_TAG_LEN; off++)
		ops[2].dst[len + off] = tmp0[off] ^ tag_mask2[off];
	memcpy(tmp0, y3, TRUSTIX_AEAD_IOC_TAG_LEN);
	for (off = 0; off < TRUSTIX_AEAD_IOC_TAG_LEN; off++)
		ops[3].dst[len + off] = tmp0[off] ^ tag_mask3[off];

	trustix_aead_wipe_fastpath(tmp0, sizeof(tmp0));
	trustix_aead_wipe_fastpath(tmp1, sizeof(tmp1));
	trustix_aead_wipe_fastpath(tmp2, sizeof(tmp2));
	trustix_aead_wipe_fastpath(tmp3, sizeof(tmp3));
	trustix_aead_wipe_fastpath(stream, sizeof(stream));
	trustix_aead_wipe_fastpath(tag_mask0, sizeof(tag_mask0));
	trustix_aead_wipe_fastpath(tag_mask1, sizeof(tag_mask1));
	trustix_aead_wipe_fastpath(tag_mask2, sizeof(tag_mask2));
	trustix_aead_wipe_fastpath(tag_mask3, sizeof(tag_mask3));
	return 0;
}

static int trustix_aead_vaes_prepare_ctx(struct trustix_aead_tfm *ctx)
{
	u8 zero[16] = {};
	u8 h_bytes[16];
	int ret;

	if (!ctx)
		return -EINVAL;
	if (ctx->vaes_ready)
		return 0;
	if (ctx->raw_key_len != 16 && ctx->raw_key_len != 32)
		return -EOPNOTSUPP;

	ret = trustix_aes_expand_key(ctx->raw_key, ctx->raw_key_len,
				     ctx->vaes_rk, &ctx->vaes_rounds);
	if (ret)
		return ret;

	if (!trustix_aead_fpu_begin())
		return -EOPNOTSUPP;
	trustix_aes_encrypt1_asm(ctx->vaes_rk, ctx->vaes_rounds, zero, h_bytes);
	trustix_aead_fpu_end();
	trustix_ghash_prepare_shash(h_bytes, ctx->vaes_shash);
	trustix_ghash_prepare_shash4(h_bytes, ctx->vaes_shash4);
	ctx->vaes_ready = true;
	memzero_explicit(h_bytes, sizeof(h_bytes));
	return 0;
}

static int trustix_aead_direct_prepare(struct trustix_aead_direct_slot *slot,
				       const u8 *key, unsigned int key_len)
{
	u8 zero[16] = {};
	u8 h_bytes[16];
	int ret;

	if (!slot || !key)
		return -EINVAL;
	if (!trustix_aesni_available || (key_len != 16 && key_len != 32))
		return -EOPNOTSUPP;

	ret = trustix_aes_expand_key(key, key_len, slot->rk, &slot->rounds);
	if (ret)
		return ret;

	if (!trustix_aead_fpu_begin())
		return -EOPNOTSUPP;
	trustix_aes_encrypt1_asm(slot->rk, slot->rounds, zero, h_bytes);
	trustix_aead_fpu_end();
	memcpy(slot->h, h_bytes, sizeof(slot->h));
	trustix_ghash_prepare_shash(h_bytes, slot->shash);
	trustix_ghash_prepare_shash4(h_bytes, slot->shash4);
	slot->key_len = key_len;
	slot->aesni_ready = true;
	slot->vaes_ready = trustix_vaes_available;
	slot->flags |= TRUSTIX_AEAD_IOC_DIRECT_FLAG_AESNI |
		       TRUSTIX_AEAD_IOC_DIRECT_FLAG_READY;
	memzero_explicit(h_bytes, sizeof(h_bytes));
	return 0;
}

static int trustix_aead_vaes_seal_prepared_slice(struct trustix_aead_tfm *ctx,
						 struct trustix_aead_prepared_op *ops,
						 __u32 start, __u32 count,
						 __u32 *successes)
{
	__u32 i;
	__u32 end = start + count;
	__u32 ok = 0;
	int first_err = 0;
	int ret;

	if (!ctx || !ctx->vaes_ready || !ops || !successes)
		return -EINVAL;

	if (!trustix_aead_fpu_begin())
		return -EOPNOTSUPP;
	for (i = start; i < end;) {
		if (i + 4 <= end) {
			ret = trustix_aead_vaes_seal4_prepared(ctx->vaes_rk,
							      ctx->vaes_rounds,
							      ctx->vaes_shash,
							      ctx->vaes_shash4,
							      &ops[i]);
			if (!ret) {
				trustix_aead_prepared_set_result(&ops[i], 0);
				trustix_aead_prepared_set_result(&ops[i + 1], 0);
				trustix_aead_prepared_set_result(&ops[i + 2], 0);
				trustix_aead_prepared_set_result(&ops[i + 3], 0);
				ok += 4;
				i += 4;
				continue;
			}
			if (ret != -EOPNOTSUPP) {
				trustix_aead_prepared_set_result(&ops[i], ret);
				trustix_aead_prepared_set_result(&ops[i + 1], ret);
				trustix_aead_prepared_set_result(&ops[i + 2], ret);
				trustix_aead_prepared_set_result(&ops[i + 3], ret);
				if (!first_err)
					first_err = ret;
				i += 4;
				continue;
			}
		}
		ret = trustix_aead_vaes_seal_one(ctx->vaes_rk, ctx->vaes_rounds,
						 ctx->vaes_shash,
						 ctx->vaes_shash4, &ops[i]);
		trustix_aead_prepared_set_result(&ops[i], ret);
		if (!ret) {
			ok++;
		} else if (!first_err) {
			first_err = ret;
		}
		i++;
	}
	trustix_aead_fpu_end();
	*successes = ok;
	return first_err;
}

static int trustix_aead_vaes_open_prepared_slice(struct trustix_aead_tfm *ctx,
						struct trustix_aead_prepared_op *ops,
						__u32 start, __u32 count,
						__u32 *successes)
{
	__u32 i;
	__u32 end = start + count;
	__u32 ok = 0;
	int first_err = 0;
	int ret;

	if (!ctx || !ctx->vaes_ready || !ops || !successes)
		return -EINVAL;

	if (!trustix_aead_fpu_begin())
		return -EOPNOTSUPP;
	for (i = start; i < end;) {
		if (i + 4 <= end) {
			ret = trustix_aead_vaes_open4_prepared(ctx->vaes_rk,
							      ctx->vaes_rounds,
							      ctx->vaes_shash,
							      ctx->vaes_shash4,
							      &ops[i]);
			if (!ret) {
				trustix_aead_prepared_set_result(&ops[i], 0);
				trustix_aead_prepared_set_result(&ops[i + 1], 0);
				trustix_aead_prepared_set_result(&ops[i + 2], 0);
				trustix_aead_prepared_set_result(&ops[i + 3], 0);
				ok += 4;
				i += 4;
				continue;
			}
			if (ret != -EOPNOTSUPP) {
				trustix_aead_prepared_set_result(&ops[i], ret);
				trustix_aead_prepared_set_result(&ops[i + 1], ret);
				trustix_aead_prepared_set_result(&ops[i + 2], ret);
				trustix_aead_prepared_set_result(&ops[i + 3], ret);
				if (!first_err)
					first_err = ret;
				i += 4;
				continue;
			}
		}
		ret = trustix_aead_vaes_open_one(ctx->vaes_rk,
						 ctx->vaes_rounds,
						 ctx->vaes_shash,
						 ctx->vaes_shash4, &ops[i]);
		trustix_aead_prepared_set_result(&ops[i], ret);
		if (!ret) {
			ok++;
		} else if (!first_err) {
			first_err = ret;
		}
		i++;
	}
	trustix_aead_fpu_end();
	*successes = ok;
	return first_err;
}

static int trustix_aead_vaes_prepared_slice(struct trustix_aead_tfm *ctx,
					    __u32 flags,
					    struct trustix_aead_prepared_op *ops,
					    __u32 start, __u32 count,
					    __u32 *successes)
{
	if (flags & TRUSTIX_AEAD_IOC_FLAG_DECRYPT)
		return trustix_aead_vaes_open_prepared_slice(ctx, ops, start,
							     count, successes);
	return trustix_aead_vaes_seal_prepared_slice(ctx, ops, start, count,
						     successes);
}

static int trustix_aead_aesni_prepared_slice(struct trustix_aead_tfm *ctx,
					     __u32 flags,
					     struct trustix_aead_prepared_op *ops,
					     __u32 start, __u32 count,
					     __u32 *successes)
{
	bool decrypt = flags & TRUSTIX_AEAD_IOC_FLAG_DECRYPT;
	__u32 i;
	__u32 end = start + count;
	__u32 ok = 0;
	int first_err = 0;
	int ret;

	if (!ctx || !ctx->vaes_ready || !ops || !successes)
		return -EINVAL;

	if (!trustix_aead_fpu_begin())
		return -EOPNOTSUPP;
	for (i = start; i < end;) {
		if (!decrypt && i + 4 <= end) {
			ret = trustix_aead_aesni_seal4_prepared(
				ctx->vaes_rk, ctx->vaes_rounds,
				ctx->vaes_shash, ctx->vaes_shash4, &ops[i]);
			if (!ret) {
				trustix_aead_prepared_set_result(&ops[i], 0);
				trustix_aead_prepared_set_result(&ops[i + 1], 0);
				trustix_aead_prepared_set_result(&ops[i + 2], 0);
				trustix_aead_prepared_set_result(&ops[i + 3], 0);
				ok += 4;
				i += 4;
				continue;
			}
			if (ret != -EOPNOTSUPP) {
				trustix_aead_prepared_set_result(&ops[i], ret);
				trustix_aead_prepared_set_result(&ops[i + 1], ret);
				trustix_aead_prepared_set_result(&ops[i + 2], ret);
				trustix_aead_prepared_set_result(&ops[i + 3], ret);
				if (!first_err)
					first_err = ret;
				i += 4;
				continue;
			}
		}
		ret = decrypt ?
			trustix_aead_aesni_open_one(ctx->vaes_rk,
						    ctx->vaes_rounds,
						    ctx->vaes_shash,
						    ctx->vaes_shash4,
						    &ops[i]) :
			trustix_aead_aesni_seal_one(ctx->vaes_rk,
						    ctx->vaes_rounds,
						    ctx->vaes_shash,
						    ctx->vaes_shash4,
						    &ops[i]);
		trustix_aead_prepared_set_result(&ops[i], ret);
		if (!ret) {
			ok++;
		} else if (!first_err) {
			first_err = ret;
		}
		i++;
	}
	trustix_aead_fpu_end();
	*successes = ok;
	return first_err;
}
#endif

static bool trustix_aead_vaes_capable(void)
{
#if TRUSTIX_X86_SIMD
	return boot_cpu_has(X86_FEATURE_AES) &&
	       boot_cpu_has(X86_FEATURE_AVX2) &&
	       boot_cpu_has(X86_FEATURE_VAES) &&
	       boot_cpu_has(X86_FEATURE_VPCLMULQDQ);
#else
	return false;
#endif
}

static bool trustix_aead_aesni_capable(void)
{
#if TRUSTIX_X86_SIMD
	return boot_cpu_has(X86_FEATURE_AES) &&
	       boot_cpu_has(X86_FEATURE_PCLMULQDQ);
#else
	return false;
#endif
}

static int trustix_aead_direct_find_free_locked(u32 *slot_id)
{
	u32 i;

	if (!slot_id)
		return -EINVAL;
	for (i = 0; i < TRUSTIX_AEAD_IOC_DIRECT_MAX_SLOTS; i++) {
		if (!rcu_dereference_protected(
			    trustix_direct_slots[i],
			    lockdep_is_held(&trustix_direct_slots_lock))) {
			*slot_id = i;
			return 0;
		}
	}
	return -ENOSPC;
}

static int trustix_aead_direct_set_key(u32 *slot_id, const u8 *key,
				       unsigned int key_len, u32 flags)
{
#if TRUSTIX_X86_SIMD
	struct trustix_aead_direct_slot *slot;
	struct trustix_aead_direct_slot *old;
	u32 actual_slot;
	int ret;

	if (!slot_id)
		return -EINVAL;
	if (*slot_id != TRUSTIX_AEAD_IOC_DIRECT_ANY_SLOT &&
	    *slot_id >= TRUSTIX_AEAD_IOC_DIRECT_MAX_SLOTS)
		return -EINVAL;
	if (flags & ~(TRUSTIX_AEAD_IOC_DIRECT_FLAG_DECRYPT))
		return -EINVAL;
	if (!key || (key_len != 16 && key_len != 32))
		return -EINVAL;

	slot = kzalloc(sizeof(*slot), GFP_KERNEL);
	if (!slot)
		return -ENOMEM;
	slot->flags = flags;
	ret = trustix_aead_direct_prepare(slot, key, key_len);
	if (ret) {
		memzero_explicit(slot, sizeof(*slot));
		kfree(slot);
		return ret;
	}

	mutex_lock(&trustix_direct_slots_lock);
	actual_slot = *slot_id;
	if (actual_slot == TRUSTIX_AEAD_IOC_DIRECT_ANY_SLOT) {
		ret = trustix_aead_direct_find_free_locked(&actual_slot);
		if (ret) {
			mutex_unlock(&trustix_direct_slots_lock);
			memzero_explicit(slot, sizeof(*slot));
			kfree(slot);
			return ret;
		}
	}
	slot->slot = actual_slot;
	old = rcu_dereference_protected(
		trustix_direct_slots[actual_slot],
		lockdep_is_held(&trustix_direct_slots_lock));
	rcu_assign_pointer(trustix_direct_slots[actual_slot], slot);
	mutex_unlock(&trustix_direct_slots_lock);
	*slot_id = actual_slot;
	if (old)
		call_rcu(&old->rcu, trustix_aead_direct_free_rcu);
	return 0;
#else
	return -EOPNOTSUPP;
#endif
}

static int trustix_aead_direct_clear_key(u32 slot_id)
{
	struct trustix_aead_direct_slot *old;

	if (slot_id >= TRUSTIX_AEAD_IOC_DIRECT_MAX_SLOTS)
		return -EINVAL;
	mutex_lock(&trustix_direct_slots_lock);
	old = rcu_dereference_protected(
		trustix_direct_slots[slot_id],
		lockdep_is_held(&trustix_direct_slots_lock));
	RCU_INIT_POINTER(trustix_direct_slots[slot_id], NULL);
	mutex_unlock(&trustix_direct_slots_lock);
	if (old)
		call_rcu(&old->rcu, trustix_aead_direct_free_rcu);
	return 0;
}

static void trustix_aead_direct_clear_all(void)
{
	u32 i;

	mutex_lock(&trustix_direct_slots_lock);
	for (i = 0; i < TRUSTIX_AEAD_IOC_DIRECT_MAX_SLOTS; i++) {
		struct trustix_aead_direct_slot *old;

		old = rcu_dereference_protected(
			trustix_direct_slots[i],
			lockdep_is_held(&trustix_direct_slots_lock));
		if (!old)
			continue;
		RCU_INIT_POINTER(trustix_direct_slots[i], NULL);
		call_rcu(&old->rcu, trustix_aead_direct_free_rcu);
	}
	mutex_unlock(&trustix_direct_slots_lock);
	synchronize_rcu();
}

static int trustix_aead_vaes_try_prepared_batch(struct trustix_aead_tfm *ctx,
						__u32 flags,
						struct trustix_aead_file *state,
						struct trustix_aead_prepared_op *ops,
						__u32 op_count,
						__u32 *successes)
{
#if TRUSTIX_X86_SIMD
	struct trustix_aead_pool_worker *workers;
	__u32 worker_count;
	__u32 base;
	__u32 rem;
	__u32 offset = 0;
	__u32 ok = 0;
	int first_err = 0;
	int ret;
	__u32 i;
#endif

	if (!trustix_experimental_vaes)
		return -EOPNOTSUPP;
	if (!trustix_vaes_available)
		return -EOPNOTSUPP;
	trustix_vaes_attempts++;
	if (!ctx || !ctx->tfm || !ops || !state || !op_count || !successes) {
		trustix_vaes_fallbacks++;
		return -EOPNOTSUPP;
	}

#if TRUSTIX_X86_SIMD
	if (ctx->raw_key_len != 16 && ctx->raw_key_len != 32) {
		trustix_vaes_fallbacks++;
		return -EOPNOTSUPP;
	}
	ret = trustix_aead_vaes_prepare_ctx(ctx);
	if (ret) {
		trustix_vaes_fallbacks++;
		return -EOPNOTSUPP;
	}

	worker_count = trustix_aead_pool_worker_count(op_count);
	if (worker_count <= 1)
		return trustix_aead_vaes_prepared_slice(ctx, flags, ops, 0,
							op_count, successes);

	ret = trustix_aead_ioc_ensure_worker_pool(state, worker_count);
	if (ret)
		return trustix_aead_vaes_prepared_slice(ctx, flags, ops, 0,
							op_count, successes);

	workers = state->pool_workers;
	base = op_count / worker_count;
	rem = op_count % worker_count;
	for (i = 0; i < worker_count; i++) {
		__u32 count = base + (i < rem ? 1 : 0);

		workers[i].state = state;
		workers[i].ctx = ctx;
		workers[i].ops = NULL;
		workers[i].prepared = ops;
		workers[i].async = NULL;
		workers[i].req_stride = 0;
		workers[i].start = offset;
		workers[i].count = count;
		workers[i].flags = flags;
		workers[i].successes = 0;
		workers[i].ret = 0;
		workers[i].vaes = true;
		workers[i].aesni = false;
		init_completion(&workers[i].done);
		INIT_WORK(&workers[i].work, trustix_aead_ioc_pool_worker);
		queue_work(system_unbound_wq, &workers[i].work);
		offset += count;
	}

	for (i = 0; i < worker_count; i++) {
		wait_for_completion(&workers[i].done);
		ok += workers[i].successes;
		if (workers[i].ret && !first_err)
			first_err = workers[i].ret;
		workers[i].prepared = NULL;
		workers[i].vaes = false;
		workers[i].aesni = false;
	}
	*successes = ok;
	return first_err;
#else
	(void)flags;
	trustix_vaes_fallbacks++;
	return -EOPNOTSUPP;
#endif
}

static int trustix_aead_try_direct_prepared_batch(struct trustix_aead_tfm *ctx,
						  __u32 flags,
						  struct trustix_aead_file *state,
						  struct trustix_aead_prepared_op *ops,
						  __u32 op_count,
						  __u32 *successes)
{
#if TRUSTIX_X86_SIMD
	struct trustix_aead_pool_worker *workers;
	__u32 worker_count;
	__u32 base;
	__u32 rem;
	__u32 offset = 0;
	__u32 ok = 0;
	int first_err = 0;
	int ret;
	__u32 i;

	if (!trustix_device_direct_aead)
		return -EOPNOTSUPP;
	if (!ctx || !ops || !op_count || !successes)
		return -EOPNOTSUPP;
	if (!trustix_aesni_available ||
	    (ctx->raw_key_len != 16 && ctx->raw_key_len != 32))
		return -EOPNOTSUPP;

	ret = trustix_aead_vaes_prepare_ctx(ctx);
	if (ret)
		return -EOPNOTSUPP;

	if (trustix_experimental_vaes && trustix_vaes_available) {
		if (!state || op_count < 128) {
			trustix_vaes_attempts++;
			ret = trustix_aead_vaes_prepared_slice(ctx, flags, ops,
							       0, op_count,
							       successes);
			if (ret != -EOPNOTSUPP)
				return ret;
			trustix_vaes_fallbacks++;
		} else {
			ret = trustix_aead_vaes_try_prepared_batch(ctx, flags,
								   state, ops,
								   op_count,
								   successes);
			if (ret != -EOPNOTSUPP)
				return ret;
		}
	}

	if (!state || op_count < 128)
		return trustix_aead_aesni_prepared_slice(ctx, flags, ops, 0,
							 op_count, successes);

	worker_count = trustix_aead_pool_worker_count(op_count);
	if (worker_count <= 1)
		return trustix_aead_aesni_prepared_slice(ctx, flags, ops, 0,
							 op_count, successes);

	ret = trustix_aead_ioc_ensure_worker_pool(state, worker_count);
	if (ret)
		return trustix_aead_aesni_prepared_slice(ctx, flags, ops, 0,
							 op_count, successes);

	workers = state->pool_workers;
	base = op_count / worker_count;
	rem = op_count % worker_count;
	for (i = 0; i < worker_count; i++) {
		__u32 count = base + (i < rem ? 1 : 0);

		workers[i].state = state;
		workers[i].ctx = ctx;
		workers[i].ops = NULL;
		workers[i].prepared = ops;
		workers[i].async = NULL;
		workers[i].req_stride = 0;
		workers[i].start = offset;
		workers[i].count = count;
		workers[i].flags = flags;
		workers[i].successes = 0;
		workers[i].ret = 0;
		workers[i].vaes = false;
		workers[i].aesni = true;
		init_completion(&workers[i].done);
		INIT_WORK(&workers[i].work, trustix_aead_ioc_pool_worker);
		queue_work(system_unbound_wq, &workers[i].work);
		offset += count;
	}

	for (i = 0; i < worker_count; i++) {
		wait_for_completion(&workers[i].done);
		ok += workers[i].successes;
		if (workers[i].ret && !first_err)
			first_err = workers[i].ret;
		workers[i].prepared = NULL;
		workers[i].aesni = false;
	}
	*successes = ok;
	return first_err;
#else
	return -EOPNOTSUPP;
#endif
}

static long trustix_aead_ioc_crypt(struct file *file, unsigned long arg)
{
	struct trustix_aead_ioc_crypt req;
	struct trustix_aead_ioc_scratch local_scratch = {};
	struct trustix_aead_ioc_scratch *scratch = &local_scratch;
	struct trustix_aead_file *state = file ? file->private_data : NULL;
	bool state_locked = false;
	bool free_ctx = false;
	void *ctx;
	__u32 out_len = 0;
	int ret;

	if (copy_from_user(&req, (const void __user *)arg, sizeof(req)))
		return -EFAULT;
	if (req.version != TRUSTIX_AEAD_IOC_VERSION)
		return -EINVAL;

	if (req.key_len == 0 && req.key_ptr == 0) {
		if (!state)
			return -EINVAL;
		mutex_lock(&state->lock);
		state_locked = true;
		if (!state->ctx) {
			req.result = -ENOKEY;
			ret = req.result;
			goto out_copy;
		}
		ctx = state->ctx;
		scratch = &state->scratch;
	} else {
		/* Ioctl callers run in process context; providers may need to sleep. */
		ctx = trustix_aead_ioc_alloc_ctx(req.key_ptr, req.key_len, true);
		if (IS_ERR(ctx)) {
			req.result = PTR_ERR(ctx);
			if (copy_to_user((void __user *)arg, &req, sizeof(req)))
				return -EFAULT;
			return req.result;
		}
		free_ctx = true;
	}

	ret = trustix_aead_ioc_run(ctx, scratch, req.flags, req.nonce_ptr,
				   req.nonce_len, req.in_ptr, req.in_len, req.out_ptr,
				   req.out_len, &out_len);
	req.result = ret;
	if (!ret)
		req.out_len = out_len;

out_copy:
	if (free_ctx)
		trustix_aead_free_tfm(ctx);
	if (!state_locked)
		trustix_aead_ioc_scratch_free(&local_scratch);
	if (state_locked)
		mutex_unlock(&state->lock);
	if (copy_to_user((void __user *)arg, &req, sizeof(req)))
		return -EFAULT;
	return ret;
}

static long trustix_aead_ioc_batch(struct file *file, unsigned long arg)
{
	struct trustix_aead_ioc_batch batch;
	struct trustix_aead_ioc_op op;
	struct trustix_aead_ioc_scratch local_scratch = {};
	struct trustix_aead_ioc_scratch *scratch = &local_scratch;
	struct trustix_aead_file *state = file ? file->private_data : NULL;
	void __user *ops_user;
	void *ctx;
	__u32 out_len;
	__u32 successes = 0;
	bool state_locked = false;
	bool free_ctx = false;
	int ret = 0;
	__u32 i;

	if (copy_from_user(&batch, (const void __user *)arg, sizeof(batch)))
		return -EFAULT;
	if (batch.version != TRUSTIX_AEAD_IOC_VERSION)
		return -EINVAL;
	if (batch.flags & ~TRUSTIX_AEAD_IOC_FLAG_DECRYPT)
		return -EINVAL;
	if (!batch.ops_ptr || batch.op_count == 0 ||
	    batch.op_count > TRUSTIX_AEAD_IOC_BATCH_MAX_OPS)
		return -EINVAL;

	if (batch.key_len == 0 && batch.key_ptr == 0) {
		if (!state)
			return -EINVAL;
		mutex_lock(&state->lock);
		state_locked = true;
		if (!state->ctx) {
			batch.result = -ENOKEY;
			ret = batch.result;
			goto out_batch;
		}
		ctx = state->ctx;
		scratch = &state->scratch;
	} else {
		/* Avoid pinning a CPU across distro-specific crypto providers. */
		ctx = trustix_aead_ioc_alloc_ctx(batch.key_ptr, batch.key_len, true);
		if (IS_ERR(ctx)) {
			batch.result = PTR_ERR(ctx);
			if (copy_to_user((void __user *)arg, &batch, sizeof(batch)))
				return -EFAULT;
			return batch.result;
		}
		free_ctx = true;
	}

	ops_user = (void __user *)(unsigned long)batch.ops_ptr;
	for (i = 0; i < batch.op_count; i++) {
		if (copy_from_user(&op, ops_user + i * sizeof(op), sizeof(op))) {
			ret = -EFAULT;
			break;
		}
		out_len = 0;
		op.result = trustix_aead_ioc_run(ctx, scratch, batch.flags, op.nonce_ptr,
						 op.nonce_len, op.in_ptr,
						 op.in_len, op.out_ptr,
						 op.out_len, &out_len);
		if (!op.result) {
			op.out_len = out_len;
			successes++;
		}
		if (copy_to_user(ops_user + i * sizeof(op), &op, sizeof(op))) {
			ret = -EFAULT;
			break;
		}
		if (op.result && !ret)
			ret = op.result;
	}

out_batch:
	if (free_ctx)
		trustix_aead_free_tfm(ctx);
	if (!state_locked)
		trustix_aead_ioc_scratch_free(&local_scratch);
	if (state_locked)
		mutex_unlock(&state->lock);
	batch.result = ret ? ret : (__s32)successes;
	if (copy_to_user((void __user *)arg, &batch, sizeof(batch)))
		return -EFAULT;
	return ret;
}

static long trustix_aead_ioc_set_key(struct file *file, unsigned long arg)
{
	struct trustix_aead_ioc_key req;
	struct trustix_aead_file *state = file ? file->private_data : NULL;
	void *ctx;
	void *old_ctx;

	if (!state)
		return -EINVAL;
	if (copy_from_user(&req, (const void __user *)arg, sizeof(req)))
		return -EFAULT;
	if (req.version != TRUSTIX_AEAD_IOC_VERSION)
		return -EINVAL;
	if (req.flags)
		return -EINVAL;

	ctx = trustix_aead_ioc_alloc_ctx(req.key_ptr, req.key_len, true);
	if (IS_ERR(ctx)) {
		req.result = PTR_ERR(ctx);
		if (copy_to_user((void __user *)arg, &req, sizeof(req)))
			return -EFAULT;
		return req.result;
	}

	mutex_lock(&state->lock);
	old_ctx = state->ctx;
	state->ctx = ctx;
	mutex_unlock(&state->lock);

	trustix_aead_free_tfm(old_ctx);
	req.result = 0;
	if (copy_to_user((void __user *)arg, &req, sizeof(req)))
		return -EFAULT;
	return 0;
}

static long trustix_aead_ioc_clear_key(struct file *file)
{
	struct trustix_aead_file *state = file ? file->private_data : NULL;
	void *old_ctx;

	if (!state)
		return -EINVAL;
	mutex_lock(&state->lock);
	old_ctx = state->ctx;
	state->ctx = NULL;
	trustix_aead_ioc_scratch_free(&state->scratch);
	mutex_unlock(&state->lock);
	trustix_aead_free_tfm(old_ctx);
	return 0;
}

static long trustix_aead_ioc_config_pool(struct file *file, unsigned long arg)
{
	struct trustix_aead_ioc_pool req;
	struct trustix_aead_file *state = file ? file->private_data : NULL;
	void *old_pool = NULL;
	void *new_pool = NULL;
	size_t new_size;
	int ret = 0;

	if (!state)
		return -EINVAL;
	if (copy_from_user(&req, (const void __user *)arg, sizeof(req)))
		return -EFAULT;
	if (req.version != TRUSTIX_AEAD_IOC_VERSION)
		return -EINVAL;
	if (req.flags)
		return -EINVAL;
	if (req.size > TRUSTIX_AEAD_IOC_POOL_MAX)
		return -EINVAL;
	new_size = (size_t)req.size;
	if ((__u64)new_size != req.size)
		return -EINVAL;

	if (new_size) {
		new_pool = vmalloc_user(new_size);
		if (!new_pool) {
			req.result = -ENOMEM;
			if (copy_to_user((void __user *)arg, &req, sizeof(req)))
				return -EFAULT;
			return req.result;
		}
	}

	mutex_lock(&state->lock);
	if (state->pool_mappings) {
		ret = -EBUSY;
	} else {
		old_pool = state->pool;
		trustix_aead_prepared_pool_free(state);
		state->pool = new_pool;
		state->pool_size = new_size;
		new_pool = NULL;
	}
	mutex_unlock(&state->lock);

	if (old_pool)
		vfree(old_pool);
	if (new_pool)
		vfree(new_pool);
	req.result = ret;
	if (copy_to_user((void __user *)arg, &req, sizeof(req)))
		return -EFAULT;
	return ret;
}

static long trustix_aead_ioc_prepare_pool_batch(struct file *file,
						unsigned long arg)
{
	struct trustix_aead_ioc_pool_batch batch;
	struct trustix_aead_ioc_pool_op *ops;
	struct trustix_aead_file *state = file ? file->private_data : NULL;
	__u64 ops_len;
	int ret = 0;
	__u32 i;

	if (!state)
		return -EINVAL;
	if (copy_from_user(&batch, (const void __user *)arg, sizeof(batch)))
		return -EFAULT;
	if (batch.version != TRUSTIX_AEAD_IOC_VERSION)
		return -EINVAL;
	if (batch.flags & ~TRUSTIX_AEAD_IOC_FLAG_DECRYPT)
		return -EINVAL;
	if (batch.op_count == 0 || batch.op_count > TRUSTIX_AEAD_IOC_BATCH_MAX_OPS)
		return -EINVAL;

	mutex_lock(&state->lock);
	if (!state->pool || !state->pool_size) {
		batch.result = -ENOBUFS;
		ret = batch.result;
		goto out_prepare_pool_batch;
	}
	ops_len = (__u64)batch.op_count * sizeof(*ops);
	if (batch.ops_off > state->pool_size ||
	    ops_len > (__u64)state->pool_size - batch.ops_off) {
		batch.result = -EINVAL;
		ret = batch.result;
		goto out_prepare_pool_batch;
	}
	ret = trustix_aead_ioc_ensure_prepared_pool(state, batch.op_count);
	if (ret) {
		batch.result = ret;
		goto out_prepare_pool_batch;
	}

	ops = (struct trustix_aead_ioc_pool_op *)((u8 *)state->pool +
						  batch.ops_off);
	for (i = 0; i < batch.op_count; i++) {
		ops[i].result =
			trustix_aead_ioc_prepare_pool_one(state, batch.flags,
							  &ops[i],
							  &state->prepared_ops[i]);
		if (ops[i].result && !ret)
			ret = ops[i].result;
	}
	if (ret) {
		state->prepared_count = 0;
		state->prepared_flags = 0;
	} else {
		state->prepared_count = batch.op_count;
		state->prepared_flags = batch.flags;
	}

out_prepare_pool_batch:
	mutex_unlock(&state->lock);
	batch.result = ret ? ret : (__s32)batch.op_count;
	if (copy_to_user((void __user *)arg, &batch, sizeof(batch)))
		return -EFAULT;
	return ret;
}

static long trustix_aead_ioc_pool_batch(struct file *file, unsigned long arg)
{
	struct trustix_aead_ioc_pool_batch batch;
	struct trustix_aead_ioc_pool_op *ops;
	struct trustix_aead_file *state = file ? file->private_data : NULL;
	__u64 ops_len;
	__u32 successes = 0;
	int ret = 0;

	if (!state)
		return -EINVAL;
	if (copy_from_user(&batch, (const void __user *)arg, sizeof(batch)))
		return -EFAULT;
	if (batch.version != TRUSTIX_AEAD_IOC_VERSION)
		return -EINVAL;
	if (batch.flags & ~TRUSTIX_AEAD_IOC_FLAG_DECRYPT)
		return -EINVAL;
	if (batch.op_count == 0 || batch.op_count > TRUSTIX_AEAD_IOC_BATCH_MAX_OPS)
		return -EINVAL;

	mutex_lock(&state->lock);
	if (!state->ctx) {
		batch.result = -ENOKEY;
		ret = batch.result;
		goto out_pool_batch;
	}
	if (!state->pool || !state->pool_size) {
		batch.result = -ENOBUFS;
		ret = batch.result;
		goto out_pool_batch;
	}
	ops_len = (__u64)batch.op_count * sizeof(*ops);
	if (batch.ops_off > state->pool_size ||
	    ops_len > (__u64)state->pool_size - batch.ops_off) {
		batch.result = -EINVAL;
		ret = batch.result;
		goto out_pool_batch;
	}
	ops = (struct trustix_aead_ioc_pool_op *)((u8 *)state->pool +
						  batch.ops_off);
	ret = trustix_aead_ioc_ensure_prepared_pool(state, batch.op_count);
	if (!ret) {
		__u32 i;

		for (i = 0; i < batch.op_count; i++) {
			ops[i].result =
				trustix_aead_ioc_prepare_pool_one(
					state, batch.flags, &ops[i],
					&state->prepared_ops[i]);
			if (ops[i].result && !ret)
				ret = ops[i].result;
		}
		if (!ret) {
			state->prepared_count = batch.op_count;
			state->prepared_flags = batch.flags;
			ret = trustix_aead_try_direct_prepared_batch(
				state->ctx, batch.flags, state,
				state->prepared_ops, batch.op_count,
				&successes);
			if (ret != -EOPNOTSUPP)
				goto out_pool_batch;
		}
		state->prepared_count = 0;
		state->prepared_flags = 0;
	}
#if TRUSTIX_DEVICE_ONLY
	if (((struct trustix_aead_tfm *)state->ctx)->may_async) {
		if (!ret)
			ret = -EOPNOTSUPP;
		goto out_pool_batch;
	}
#endif
	ret = trustix_aead_ioc_pool_run_async_batch(state->ctx, state,
						    batch.flags, ops,
						    batch.op_count,
						    &successes);

out_pool_batch:
	mutex_unlock(&state->lock);
	batch.result = ret ? ret : (__s32)successes;
	if (copy_to_user((void __user *)arg, &batch, sizeof(batch)))
		return -EFAULT;
	return ret;
}

static long trustix_aead_ioc_pool_prepared_batch(struct file *file,
						 unsigned long arg)
{
	struct trustix_aead_ioc_pool_prepared_batch batch;
	struct trustix_aead_file *state = file ? file->private_data : NULL;
	__u32 successes = 0;
	int ret = 0;

	if (!state)
		return -EINVAL;
	if (copy_from_user(&batch, (const void __user *)arg, sizeof(batch)))
		return -EFAULT;
	if (batch.version != TRUSTIX_AEAD_IOC_VERSION)
		return -EINVAL;
	if (batch.flags & ~TRUSTIX_AEAD_IOC_FLAG_DECRYPT)
		return -EINVAL;
	if (batch.op_count == 0 || batch.op_count > TRUSTIX_AEAD_IOC_BATCH_MAX_OPS)
		return -EINVAL;

	mutex_lock(&state->lock);
	if (!state->ctx) {
		batch.result = -ENOKEY;
		ret = batch.result;
		goto out_pool_prepared_batch;
	}
	if (!state->prepared_ops || batch.flags != state->prepared_flags ||
	    batch.start > state->prepared_count ||
	    batch.op_count > state->prepared_count - batch.start) {
		batch.result = -EINVAL;
		ret = batch.result;
		goto out_pool_prepared_batch;
	}
	ret = trustix_aead_vaes_try_prepared_batch(
		state->ctx, batch.flags, state,
		state->prepared_ops + batch.start,
		batch.op_count, &successes);
	if (ret == -EOPNOTSUPP)
		ret = trustix_aead_try_direct_prepared_batch(
			state->ctx, batch.flags, state,
			state->prepared_ops + batch.start,
			batch.op_count, &successes);
	if (ret == -EOPNOTSUPP) {
#if TRUSTIX_DEVICE_ONLY
		if (((struct trustix_aead_tfm *)state->ctx)->may_async)
			goto out_pool_prepared_batch;
#endif
		ret = trustix_aead_ioc_pool_run_prepared_batch(
			state->ctx, state, batch.flags,
			state->prepared_ops + batch.start, batch.op_count,
			&successes);
	}

out_pool_prepared_batch:
	mutex_unlock(&state->lock);
	batch.result = ret ? ret : (__s32)successes;
	if (copy_to_user((void __user *)arg, &batch, sizeof(batch)))
		return -EFAULT;
	return ret;
}

static long trustix_aead_ioc_direct_set_key(unsigned long arg)
{
	struct trustix_aead_ioc_direct_key req;
	u8 key[TRUSTIX_AEAD_IOC_KEY_MAX];
	int ret;

	if (copy_from_user(&req, (const void __user *)arg, sizeof(req)))
		return -EFAULT;
	if (req.version != TRUSTIX_AEAD_IOC_VERSION)
		return -EINVAL;
	if (req.slot != TRUSTIX_AEAD_IOC_DIRECT_ANY_SLOT &&
	    req.slot >= TRUSTIX_AEAD_IOC_DIRECT_MAX_SLOTS)
		return -EINVAL;
	if (req.flags & ~(TRUSTIX_AEAD_IOC_DIRECT_FLAG_DECRYPT))
		return -EINVAL;
	if (req.key_len != 16 && req.key_len != 32)
		return -EINVAL;
	if (!req.key_ptr)
		return -EINVAL;
	if (copy_from_user(key, (const void __user *)(unsigned long)req.key_ptr,
			   req.key_len))
		return -EFAULT;
	ret = trustix_aead_direct_set_key(&req.slot, key, req.key_len, req.flags);
	memzero_explicit(key, sizeof(key));
	req.result = ret;
	if (copy_to_user((void __user *)arg, &req, sizeof(req)))
		return -EFAULT;
	return ret;
}

static long trustix_aead_ioc_direct_clear_key(unsigned long arg)
{
	struct trustix_aead_ioc_direct_key req;
	int ret;

	if (copy_from_user(&req, (const void __user *)arg, sizeof(req)))
		return -EFAULT;
	if (req.version != TRUSTIX_AEAD_IOC_VERSION)
		return -EINVAL;
	if (req.slot >= TRUSTIX_AEAD_IOC_DIRECT_MAX_SLOTS)
		return -EINVAL;
	ret = trustix_aead_direct_clear_key(req.slot);
	req.result = ret;
	if (copy_to_user((void __user *)arg, &req, sizeof(req)))
		return -EFAULT;
	return ret;
}

static long trustix_aead_ioc_pool_prepare_run_batch(struct file *file,
						    unsigned long arg)
{
	struct trustix_aead_ioc_pool_batch batch;
	struct trustix_aead_ioc_pool_op *ops;
	struct trustix_aead_file *state = file ? file->private_data : NULL;
	__u64 ops_len;
	__u32 successes = 0;
	int ret = 0;
	__u32 i;

	if (!state)
		return -EINVAL;
	if (copy_from_user(&batch, (const void __user *)arg, sizeof(batch)))
		return -EFAULT;
	if (batch.version != TRUSTIX_AEAD_IOC_VERSION)
		return -EINVAL;
	if (batch.flags & ~TRUSTIX_AEAD_IOC_FLAG_DECRYPT)
		return -EINVAL;
	if (batch.op_count == 0 || batch.op_count > TRUSTIX_AEAD_IOC_BATCH_MAX_OPS)
		return -EINVAL;

	mutex_lock(&state->lock);
	if (!state->ctx) {
		batch.result = -ENOKEY;
		ret = batch.result;
		goto out_pool_prepare_run_batch;
	}
	if (!state->pool || !state->pool_size) {
		batch.result = -ENOBUFS;
		ret = batch.result;
		goto out_pool_prepare_run_batch;
	}
	ops_len = (__u64)batch.op_count * sizeof(*ops);
	if (batch.ops_off > state->pool_size ||
	    ops_len > (__u64)state->pool_size - batch.ops_off) {
		batch.result = -EINVAL;
		ret = batch.result;
		goto out_pool_prepare_run_batch;
	}
	ret = trustix_aead_ioc_ensure_prepared_pool(state, batch.op_count);
	if (ret) {
		batch.result = ret;
		goto out_pool_prepare_run_batch;
	}

	ops = (struct trustix_aead_ioc_pool_op *)((u8 *)state->pool +
						  batch.ops_off);
	for (i = 0; i < batch.op_count; i++) {
		ops[i].result =
			trustix_aead_ioc_prepare_pool_one(state, batch.flags,
							  &ops[i],
							  &state->prepared_ops[i]);
		if (ops[i].result && !ret)
			ret = ops[i].result;
	}
	if (ret) {
		state->prepared_count = 0;
		state->prepared_flags = 0;
		goto out_pool_prepare_run_batch;
	}
	state->prepared_count = batch.op_count;
	state->prepared_flags = batch.flags;

	ret = trustix_aead_vaes_try_prepared_batch(
		state->ctx, batch.flags, state, state->prepared_ops,
		batch.op_count, &successes);
	if (ret == -EOPNOTSUPP)
		ret = trustix_aead_try_direct_prepared_batch(
			state->ctx, batch.flags, state, state->prepared_ops,
			batch.op_count, &successes);
	if (ret == -EOPNOTSUPP) {
#if TRUSTIX_DEVICE_ONLY
		if (((struct trustix_aead_tfm *)state->ctx)->may_async)
			goto out_pool_prepare_run_batch;
#endif
		ret = trustix_aead_ioc_pool_run_prepared_batch(
			state->ctx, state, batch.flags, state->prepared_ops,
			batch.op_count, &successes);
	}

out_pool_prepare_run_batch:
	if (ret) {
		state->prepared_count = 0;
		state->prepared_flags = 0;
	}
	mutex_unlock(&state->lock);
	batch.result = ret ? ret : (__s32)successes;
	if (copy_to_user((void __user *)arg, &batch, sizeof(batch)))
		return -EFAULT;
	return ret;
}

static long trustix_aead_ioctl(struct file *file, unsigned int cmd,
			       unsigned long arg)
{
	switch (cmd) {
	case TRUSTIX_AEAD_IOC_CRYPT:
		return trustix_aead_ioc_crypt(file, arg);
	case TRUSTIX_AEAD_IOC_BATCH:
		return trustix_aead_ioc_batch(file, arg);
	case TRUSTIX_AEAD_IOC_SET_KEY:
		return trustix_aead_ioc_set_key(file, arg);
	case TRUSTIX_AEAD_IOC_CLEAR_KEY:
		return trustix_aead_ioc_clear_key(file);
	case TRUSTIX_AEAD_IOC_CONFIG_POOL:
		return trustix_aead_ioc_config_pool(file, arg);
	case TRUSTIX_AEAD_IOC_POOL_BATCH:
		return trustix_aead_ioc_pool_batch(file, arg);
	case TRUSTIX_AEAD_IOC_PREPARE_POOL_BATCH:
		return trustix_aead_ioc_prepare_pool_batch(file, arg);
	case TRUSTIX_AEAD_IOC_POOL_PREPARED_BATCH:
		return trustix_aead_ioc_pool_prepared_batch(file, arg);
	case TRUSTIX_AEAD_IOC_POOL_PREPARE_RUN_BATCH:
		return trustix_aead_ioc_pool_prepare_run_batch(file, arg);
	case TRUSTIX_AEAD_IOC_DIRECT_SET_KEY:
		return trustix_aead_ioc_direct_set_key(arg);
	case TRUSTIX_AEAD_IOC_DIRECT_CLEAR_KEY:
		return trustix_aead_ioc_direct_clear_key(arg);
	default:
		return -ENOTTY;
	}
}

static int trustix_aead_open(struct inode *inode, struct file *file)
{
	struct trustix_aead_file *state;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;
	mutex_init(&state->lock);
	file->private_data = state;
	return 0;
}

static int trustix_aead_release(struct inode *inode, struct file *file)
{
	struct trustix_aead_file *state = file ? file->private_data : NULL;

	if (!state)
		return 0;
	trustix_aead_free_tfm(state->ctx);
	trustix_aead_ioc_scratch_free(&state->scratch);
	trustix_aead_async_pool_free(state);
	trustix_aead_worker_pool_free(state);
	trustix_aead_prepared_pool_free(state);
	if (state->pool)
		vfree(state->pool);
	kfree(state);
	file->private_data = NULL;
	return 0;
}

static void trustix_aead_vma_open(struct vm_area_struct *vma)
{
	struct trustix_aead_file *state = vma->vm_private_data;

	if (!state)
		return;
	mutex_lock(&state->lock);
	state->pool_mappings++;
	mutex_unlock(&state->lock);
}

static void trustix_aead_vma_close(struct vm_area_struct *vma)
{
	struct trustix_aead_file *state = vma->vm_private_data;

	if (!state)
		return;
	mutex_lock(&state->lock);
	if (state->pool_mappings)
		state->pool_mappings--;
	mutex_unlock(&state->lock);
}

static const struct vm_operations_struct trustix_aead_vm_ops = {
	.open = trustix_aead_vma_open,
	.close = trustix_aead_vma_close,
};

static int trustix_aead_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct trustix_aead_file *state = file ? file->private_data : NULL;
	unsigned long size = vma->vm_end - vma->vm_start;
	int ret;

	if (!state)
		return -EINVAL;
	mutex_lock(&state->lock);
	if (!state->pool || !state->pool_size || size > state->pool_size) {
		mutex_unlock(&state->lock);
		return -EINVAL;
	}
	ret = remap_vmalloc_range(vma, state->pool, 0);
	if (!ret) {
		vma->vm_ops = &trustix_aead_vm_ops;
		vma->vm_private_data = state;
		state->pool_mappings++;
	}
	mutex_unlock(&state->lock);
	return ret;
}

static const struct file_operations trustix_aead_fops = {
	.owner = THIS_MODULE,
	.open = trustix_aead_open,
	.release = trustix_aead_release,
	.unlocked_ioctl = trustix_aead_ioctl,
	.mmap = trustix_aead_mmap,
#ifdef CONFIG_COMPAT
	.compat_ioctl = trustix_aead_ioctl,
#endif
};

static struct miscdevice trustix_aead_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "trustix_crypto",
	.fops = &trustix_aead_fops,
	.mode = 0600,
};

#if TRUSTIX_ENABLE_BPF_CRYPTO
static int trustix_aead_encrypt(void *tfm, const u8 *src, u8 *dst,
				unsigned int len, u8 *iv)
{
	return trustix_aead_crypt(tfm, src, dst, len, iv, true);
}

static int trustix_aead_decrypt(void *tfm, const u8 *src, u8 *dst,
				unsigned int len, u8 *iv)
{
	return trustix_aead_crypt(tfm, src, dst, len, iv, false);
}

static unsigned int trustix_aead_ivsize(void *tfm)
{
	struct trustix_aead_tfm *ctx = tfm;

	if (!ctx || !ctx->tfm)
		return 0;
	return crypto_aead_ivsize(ctx->tfm);
}

static unsigned int trustix_aead_statesize(void *tfm)
{
	return 0;
}

static u32 trustix_aead_get_flags(void *tfm)
{
	struct trustix_aead_tfm *ctx = tfm;

	if (!ctx || !ctx->tfm)
		return 0;
	return crypto_aead_get_flags(ctx->tfm);
}
#endif

#if TRUSTIX_ENABLE_BPF_CRYPTO
static const struct bpf_crypto_type trustix_crypto = {
	.alloc_tfm = trustix_aead_alloc_bpf_tfm,
	.free_tfm = trustix_aead_free_tfm,
	.has_algo = trustix_aead_has_algo,
	.setkey = trustix_aead_setkey,
	.setauthsize = trustix_aead_setauthsize,
	.encrypt = trustix_aead_encrypt,
	.decrypt = trustix_aead_decrypt,
	.ivsize = trustix_aead_ivsize,
	.statesize = trustix_aead_statesize,
	.get_flags = trustix_aead_get_flags,
	.owner = THIS_MODULE,
	.name = TRUSTIX_AEAD_NAME,
};
#endif

#if !TRUSTIX_DEVICE_ONLY
#if TRUSTIX_X86_SIMD
static int
trustix_aead_direct_snapshot_slot(struct trustix_aead_direct_snapshot *snapshot,
				  u32 slot_id, bool decrypt)
{
	struct trustix_aead_direct_slot *slot;
	int ret;

	if (!snapshot)
		return -EINVAL;
	memset(snapshot, 0, sizeof(*snapshot));

	rcu_read_lock();
	slot = trustix_aead_direct_lookup_rcu(slot_id);
	if (!slot) {
		ret = -ENOENT;
	} else if (!slot->aesni_ready ||
		   (!!(slot->flags & TRUSTIX_AEAD_IOC_DIRECT_FLAG_DECRYPT) !=
		    decrypt)) {
		ret = -EOPNOTSUPP;
	} else {
		memcpy(snapshot->rk, slot->rk, sizeof(snapshot->rk));
		memcpy(snapshot->h, slot->h, sizeof(snapshot->h));
		memcpy(snapshot->shash, slot->shash, sizeof(snapshot->shash));
		memcpy(snapshot->shash4, slot->shash4,
		       sizeof(snapshot->shash4));
		snapshot->rounds = slot->rounds;
		snapshot->aesni_ready = slot->aesni_ready;
		snapshot->vaes_ready = slot->vaes_ready;
		ret = 0;
	}
	rcu_read_unlock();
	return ret;
}

static int trustix_aead_soft_seal_one(const u8 rk[15][16], int rounds,
				      const u8 h_raw[16],
				      struct trustix_aead_prepared_op *op)
{
	struct trustix_u128_be h;
	struct trustix_u128_be y = {};
	u8 tmp[16];
	u8 stream[16];
	u8 tag_mask[16];
	const u8 *src;
	u8 *dst;
	unsigned int len;
	unsigned int off = 0;
	u32 ctr = 2;

	if (!rk || !h_raw || !op || !op->nonce || !op->src || !op->dst)
		return -EINVAL;
	if (rounds != 10 && rounds != 14)
		return -EINVAL;
	if (op->out_len != op->in_len + TRUSTIX_AEAD_IOC_TAG_LEN)
		return -EINVAL;

	src = op->src;
	dst = op->dst;
	len = op->in_len;
	trustix_load_u128_be(&h, h_raw);

	trustix_ctr_block(tmp, op->nonce, 1);
	trustix_aes_encrypt1_soft(rk, rounds, tmp, tag_mask);

	while (off + 16 <= len) {
		trustix_ctr_block(tmp, op->nonce, ctr);
		trustix_aes_encrypt1_soft(rk, rounds, tmp, stream);
		trustix_xor16_soft(dst + off, src + off, stream);
		trustix_ghash_block(&y, h, dst + off);
		off += 16;
		ctr++;
	}
	if (off < len) {
		unsigned int rem = len - off;
		unsigned int i;

		trustix_ctr_block(tmp, op->nonce, ctr);
		trustix_aes_encrypt1_soft(rk, rounds, tmp, stream);
		memset(tmp, 0, sizeof(tmp));
		for (i = 0; i < rem; i++) {
			dst[off + i] = src[off + i] ^ stream[i];
			tmp[i] = dst[off + i];
		}
		trustix_ghash_block(&y, h, tmp);
	}

	memset(tmp, 0, sizeof(tmp));
	trustix_store_be64(tmp + 8, (u64)len * 8);
	trustix_ghash_block(&y, h, tmp);
	trustix_store_u128_be(tmp, y);
	for (off = 0; off < TRUSTIX_AEAD_IOC_TAG_LEN; off++)
		dst[len + off] = tmp[off] ^ tag_mask[off];

	trustix_aead_wipe_fastpath(tmp, sizeof(tmp));
	trustix_aead_wipe_fastpath(stream, sizeof(stream));
	trustix_aead_wipe_fastpath(tag_mask, sizeof(tag_mask));
	return 0;
}

static int trustix_aead_soft_open_one(const u8 rk[15][16], int rounds,
				      const u8 h_raw[16],
				      struct trustix_aead_prepared_op *op)
{
	struct trustix_u128_be h;
	struct trustix_u128_be y = {};
	u8 tmp[16];
	u8 stream[16];
	u8 tag_mask[16];
	u8 expected[16];
	const u8 *src;
	u8 *dst;
	unsigned int cipher_len;
	unsigned int off = 0;
	u32 ctr = 2;
	int ret = 0;

	if (!rk || !h_raw || !op || !op->nonce || !op->src || !op->dst)
		return -EINVAL;
	if (rounds != 10 && rounds != 14)
		return -EINVAL;
	if (op->in_len < TRUSTIX_AEAD_IOC_TAG_LEN ||
	    op->out_len + TRUSTIX_AEAD_IOC_TAG_LEN != op->in_len)
		return -EINVAL;

	src = op->src;
	dst = op->dst;
	cipher_len = op->in_len - TRUSTIX_AEAD_IOC_TAG_LEN;
	trustix_load_u128_be(&h, h_raw);

	trustix_ctr_block(tmp, op->nonce, 1);
	trustix_aes_encrypt1_soft(rk, rounds, tmp, tag_mask);

	while (off + 16 <= cipher_len) {
		trustix_ghash_block(&y, h, src + off);
		off += 16;
	}
	if (off < cipher_len) {
		unsigned int rem = cipher_len - off;

		memset(tmp, 0, sizeof(tmp));
		memcpy(tmp, src + off, rem);
		trustix_ghash_block(&y, h, tmp);
	}

	memset(tmp, 0, sizeof(tmp));
	trustix_store_be64(tmp + 8, (u64)cipher_len * 8);
	trustix_ghash_block(&y, h, tmp);
	trustix_store_u128_be(expected, y);
	for (off = 0; off < TRUSTIX_AEAD_IOC_TAG_LEN; off++)
		expected[off] ^= tag_mask[off];
	if (trustix_consttime_memneq(expected, src + cipher_len,
				     TRUSTIX_AEAD_IOC_TAG_LEN)) {
		ret = -EBADMSG;
		goto out_wipe;
	}

	off = 0;
	while (off + 16 <= cipher_len) {
		trustix_ctr_block(tmp, op->nonce, ctr);
		trustix_aes_encrypt1_soft(rk, rounds, tmp, stream);
		trustix_xor16_soft(dst + off, src + off, stream);
		off += 16;
		ctr++;
	}
	if (off < cipher_len) {
		unsigned int rem = cipher_len - off;
		unsigned int i;

		trustix_ctr_block(tmp, op->nonce, ctr);
		trustix_aes_encrypt1_soft(rk, rounds, tmp, stream);
		for (i = 0; i < rem; i++)
			dst[off + i] = src[off + i] ^ stream[i];
	}

out_wipe:
	trustix_aead_wipe_fastpath(tmp, sizeof(tmp));
	trustix_aead_wipe_fastpath(stream, sizeof(stream));
	trustix_aead_wipe_fastpath(tag_mask, sizeof(tag_mask));
	trustix_aead_wipe_fastpath(expected, sizeof(expected));
	if (ret)
		memzero_explicit(dst, op->out_len);
	return ret;
}

static int trustix_aead_direct_crypt_one_soft_fields(
					 const u8 rk[15][16], int rounds,
					 const u8 h_raw[16],
					 struct trustix_aead_prepared_op *op,
					 bool decrypt)
{
	if (decrypt)
		return trustix_aead_soft_open_one(rk, rounds, h_raw, op);
	return trustix_aead_soft_seal_one(rk, rounds, h_raw, op);
}

static int trustix_aead_direct_crypt_one_soft(
					 struct trustix_aead_direct_snapshot *slot,
					 struct trustix_aead_prepared_op *op,
					 bool decrypt)
{
	if (!slot || !op)
		return -EINVAL;
	if (!slot->aesni_ready)
		return -EOPNOTSUPP;
	return trustix_aead_direct_crypt_one_soft_fields(slot->rk, slot->rounds,
							 slot->h, op, decrypt);
}

static void
trustix_aead_prepare_direct_seal_batch_op(
				struct trustix_aead_prepared_op *op,
				const struct trustix_aead_direct_batch_op *batch)
{
	op->nonce = (u8 *)batch->nonce;
	op->src = (u8 *)batch->src;
	op->dst = batch->dst;
	op->in_len = batch->plain_len;
	op->out_len = batch->plain_len + TRUSTIX_AEAD_IOC_TAG_LEN;
	op->pool_out_len = NULL;
	op->pool_result = NULL;
}

static int trustix_aead_direct_crypt_one_nofpu(
					 struct trustix_aead_direct_snapshot *slot,
					 struct trustix_aead_prepared_op *op,
					 bool decrypt, bool *used_vaes)
{
	int ret;

	if (used_vaes)
		*used_vaes = false;
	if (!slot || !op)
		return -EINVAL;
	if (!slot->aesni_ready)
		return -EOPNOTSUPP;
	if (!trustix_kfunc_simd_fastpath)
		return -EOPNOTSUPP;
	if (trustix_experimental_vaes_kfunc && slot->vaes_ready) {
		ret = decrypt ?
			trustix_aead_vaes_open_one(slot->rk, slot->rounds,
						   slot->shash, slot->shash4,
						   op) :
			trustix_aead_vaes_seal_one(slot->rk, slot->rounds,
						   slot->shash, slot->shash4,
						   op);
		if (!ret) {
			if (used_vaes)
				*used_vaes = true;
			return 0;
		}
		if (ret != -EOPNOTSUPP)
			return ret;
	}
	ret = decrypt ?
		trustix_aead_aesni_open_one(slot->rk, slot->rounds,
					    slot->shash, slot->shash4, op) :
		trustix_aead_aesni_seal_one(slot->rk, slot->rounds,
					    slot->shash, slot->shash4, op);
	return ret;
}

static int trustix_aead_direct_seal4_nofpu(
				struct trustix_aead_direct_snapshot *slot,
				const struct trustix_aead_direct_batch_op *ops,
				bool *used_vaes)
{
	struct trustix_aead_prepared_op prepared[4];
	u32 i;
	int ret;

	if (used_vaes)
		*used_vaes = false;
	if (!slot || !ops)
		return -EINVAL;
	if (!slot->aesni_ready)
		return -EOPNOTSUPP;
	if (!trustix_kfunc_simd_fastpath)
		return -EOPNOTSUPP;
	if (!ops[0].plain_len ||
	    ops[1].plain_len != ops[0].plain_len ||
	    ops[2].plain_len != ops[0].plain_len ||
	    ops[3].plain_len != ops[0].plain_len)
		return -EOPNOTSUPP;

	for (i = 0; i < 4; i++) {
		trustix_aead_prepare_direct_seal_batch_op(&prepared[i],
							  &ops[i]);
	}

	if (trustix_experimental_vaes_kfunc && slot->vaes_ready) {
		ret = trustix_aead_vaes_seal4_prepared(
			slot->rk, slot->rounds, slot->shash, slot->shash4,
			prepared);
		if (!ret) {
			if (used_vaes)
				*used_vaes = true;
			return 0;
		}
		if (ret != -EOPNOTSUPP)
			return ret;
	}

	return trustix_aead_aesni_seal4_prepared(
		slot->rk, slot->rounds, slot->shash, slot->shash4, prepared);
}

static int trustix_aead_direct_crypt_one(
					 struct trustix_aead_direct_snapshot *slot,
					 struct trustix_aead_prepared_op *op,
					 bool decrypt)
{
	bool used_vaes = false;
	int ret;

	if (!trustix_kfunc_simd_fastpath)
		return -EOPNOTSUPP;
	if (!trustix_aead_fpu_begin()) {
		trustix_direct_kfunc_record_fpu_unavailable();
		return trustix_aead_direct_crypt_one_soft(slot, op, decrypt);
	}
	ret = trustix_aead_direct_crypt_one_nofpu(slot, op, decrypt,
						 &used_vaes);
	trustix_aead_fpu_end();
	if (!ret && trustix_kfunc_fastpath_stats) {
		if (used_vaes)
			this_cpu_inc(trustix_direct_kfunc_vaes_calls);
		else
			this_cpu_inc(trustix_direct_kfunc_aesni_calls);
	}
	return ret;
}

static int trustix_aead_direct_crypt_one_slot_rcu(
					 u32 slot_id,
					 struct trustix_aead_prepared_op *op,
					 bool decrypt)
{
	struct trustix_aead_direct_slot *slot;
	bool used_vaes = false;
	int ret;

	if (!op)
		return -EINVAL;
	if (!trustix_kfunc_direct_slot_fastpath)
		return -EOPNOTSUPP;

	rcu_read_lock();
	slot = trustix_aead_direct_lookup_rcu(slot_id);
	if (!slot) {
		ret = -ENOENT;
	} else if (!slot->aesni_ready ||
		   (!!(slot->flags & TRUSTIX_AEAD_IOC_DIRECT_FLAG_DECRYPT) !=
		    decrypt)) {
		ret = -EOPNOTSUPP;
	} else if (!trustix_kfunc_simd_fastpath) {
		ret = -EOPNOTSUPP;
	} else {
		if (!trustix_aead_fpu_begin()) {
			trustix_direct_kfunc_record_fpu_unavailable();
			ret = trustix_aead_direct_crypt_one_soft_fields(
				slot->rk, slot->rounds, slot->h, op, decrypt);
			goto out_unlock;
		}
		if (trustix_experimental_vaes_kfunc && slot->vaes_ready) {
			ret = decrypt ?
				trustix_aead_vaes_open_one(slot->rk,
							   slot->rounds,
							   slot->shash,
							   slot->shash4,
							   op) :
				trustix_aead_vaes_seal_one(slot->rk,
							   slot->rounds,
							   slot->shash,
							   slot->shash4,
							   op);
			if (!ret)
				used_vaes = true;
		} else {
			ret = -EOPNOTSUPP;
		}
		if (ret == -EOPNOTSUPP)
			ret = decrypt ?
				trustix_aead_aesni_open_one(slot->rk,
							    slot->rounds,
							    slot->shash,
							    slot->shash4,
							    op) :
				trustix_aead_aesni_seal_one(slot->rk,
							    slot->rounds,
							    slot->shash,
							    slot->shash4,
							    op);
		trustix_aead_fpu_end();
		if (!ret && trustix_kfunc_fastpath_stats) {
			if (used_vaes)
				this_cpu_inc(trustix_direct_kfunc_vaes_calls);
			else
				this_cpu_inc(trustix_direct_kfunc_aesni_calls);
		}
	}
out_unlock:
	rcu_read_unlock();
	return ret;
}
#endif

int trustix_kernel_direct_seal_batch(u32 slot_id,
				     const struct trustix_aead_direct_batch_op *ops,
				     u32 count)
{
#if TRUSTIX_X86_SIMD
	struct trustix_aead_direct_snapshot snapshot;
	struct trustix_aead_prepared_op op = {};
	u32 i;
	u32 j;
	int ret;

	if (!ops || !count || count > 128)
		return -EINVAL;
	for (i = 0; i < count; i++) {
		if (!ops[i].src || !ops[i].dst ||
		    ops[i].plain_len >
			    TRUSTIX_AEAD_IOC_INPUT_MAX - TRUSTIX_AEAD_IOC_TAG_LEN)
			return -EINVAL;
	}
	ret = trustix_aead_direct_snapshot_slot(&snapshot, slot_id, false);
	if (ret)
		goto out_error;
	if (!trustix_kfunc_simd_fastpath) {
		ret = -EOPNOTSUPP;
		goto out_wipe;
	}
	for (i = 0; i < count;) {
		bool used_vaes = false;

		if (i + 4 <= count) {
			if (!trustix_aead_fpu_begin()) {
				for (j = 0; j < 4; j++) {
					trustix_direct_kfunc_record_fpu_unavailable();
					trustix_aead_prepare_direct_seal_batch_op(
						&op, &ops[i + j]);
					ret = trustix_aead_direct_crypt_one_soft(
						&snapshot, &op, false);
					if (ret)
						break;
					if (trustix_kfunc_fastpath_stats)
						this_cpu_inc(
							trustix_direct_kfunc_seal_calls);
				}
				if (ret)
					break;
				i += 4;
				continue;
			}
			ret = trustix_aead_direct_seal4_nofpu(
				&snapshot, &ops[i], &used_vaes);
			trustix_aead_fpu_end();
			if (!ret) {
				if (trustix_kfunc_fastpath_stats) {
					for (j = 0; j < 4; j++) {
						this_cpu_inc(
							trustix_direct_kfunc_seal_calls);
						if (used_vaes)
							this_cpu_inc(
								trustix_direct_kfunc_vaes_calls);
						else
							this_cpu_inc(
								trustix_direct_kfunc_aesni_calls);
					}
				}
				i += 4;
				continue;
			}
			if (ret != -EOPNOTSUPP)
				break;
		}

		trustix_aead_prepare_direct_seal_batch_op(&op, &ops[i]);
		if (trustix_kfunc_fastpath_stats)
			this_cpu_inc(trustix_direct_kfunc_seal_calls);
		if (!trustix_aead_fpu_begin()) {
			trustix_direct_kfunc_record_fpu_unavailable();
			ret = trustix_aead_direct_crypt_one_soft(&snapshot, &op,
								 false);
			if (ret)
				break;
			i++;
			continue;
		}
		ret = trustix_aead_direct_crypt_one_nofpu(&snapshot, &op, false,
							 &used_vaes);
		trustix_aead_fpu_end();
		if (ret)
			break;
		if (trustix_kfunc_fastpath_stats) {
			if (used_vaes)
				this_cpu_inc(trustix_direct_kfunc_vaes_calls);
			else
				this_cpu_inc(trustix_direct_kfunc_aesni_calls);
		}
		i++;
	}
out_wipe:
	memzero_explicit(&snapshot, sizeof(snapshot));
	if (!ret)
		return 0;
out_error:
	trustix_direct_kfunc_record_error(
		ret, TRUSTIX_DIRECT_KFUNC_ERROR_BATCH_SEAL);
	return ret;
#else
	return -EOPNOTSUPP;
#endif
}
EXPORT_SYMBOL_GPL(trustix_kernel_direct_seal_batch);

__bpf_kfunc_start_defs();

__bpf_kfunc int trustix_kernel_direct_seal(u32 slot_id, const u8 *src,
					     u8 *dst, u32 plain_len,
					     const u8 *nonce)
{
#if TRUSTIX_X86_SIMD
	struct trustix_aead_direct_snapshot snapshot;
	struct trustix_aead_prepared_op op = {};
	int ret;

	if (!src || !dst || !nonce ||
	    plain_len > TRUSTIX_AEAD_IOC_INPUT_MAX - TRUSTIX_AEAD_IOC_TAG_LEN)
		return -EINVAL;
	op.nonce = (u8 *)nonce;
	op.src = (u8 *)src;
	op.dst = dst;
	op.in_len = plain_len;
	op.out_len = plain_len + TRUSTIX_AEAD_IOC_TAG_LEN;
	if (trustix_kfunc_fastpath_stats)
		this_cpu_inc(trustix_direct_kfunc_seal_calls);
	ret = trustix_aead_direct_crypt_one_slot_rcu(slot_id, &op, false);
	if (ret == -EOPNOTSUPP) {
		ret = trustix_aead_direct_snapshot_slot(&snapshot, slot_id,
							false);
		if (!ret) {
			ret = trustix_aead_direct_crypt_one(&snapshot, &op,
							   false);
			memzero_explicit(&snapshot, sizeof(snapshot));
		}
	}
	if (ret)
		trustix_direct_kfunc_record_error(
			ret, TRUSTIX_DIRECT_KFUNC_ERROR_SEAL);
	return ret;
#else
	return -EOPNOTSUPP;
#endif
}

__bpf_kfunc int trustix_kernel_direct_open(u32 slot_id, const u8 *src,
					    u8 *dst, u32 cipher_len,
					    const u8 *nonce)
{
#if TRUSTIX_X86_SIMD
	struct trustix_aead_direct_snapshot snapshot;
	struct trustix_aead_prepared_op op = {};
	int ret;

	if (!src || !dst || !nonce || cipher_len < TRUSTIX_AEAD_IOC_TAG_LEN ||
	    cipher_len > TRUSTIX_AEAD_IOC_INPUT_MAX)
		return -EINVAL;
	op.nonce = (u8 *)nonce;
	op.src = (u8 *)src;
	op.dst = dst;
	op.in_len = cipher_len;
	op.out_len = cipher_len - TRUSTIX_AEAD_IOC_TAG_LEN;
	if (trustix_kfunc_fastpath_stats)
		this_cpu_inc(trustix_direct_kfunc_open_calls);
	ret = trustix_aead_direct_crypt_one_slot_rcu(slot_id, &op, true);
	if (ret == -EOPNOTSUPP) {
		ret = trustix_aead_direct_snapshot_slot(&snapshot, slot_id,
							true);
		if (!ret) {
			ret = trustix_aead_direct_crypt_one(&snapshot, &op,
							   true);
			memzero_explicit(&snapshot, sizeof(snapshot));
		}
	}
	if (ret)
		trustix_direct_kfunc_record_error(
			ret, TRUSTIX_DIRECT_KFUNC_ERROR_OPEN);
	return ret;
#else
	return -EOPNOTSUPP;
#endif
}

__bpf_kfunc int
trustix_kernel_skb_direct_open(struct __sk_buff *ctx,
				 const struct trustix_aead_skb_direct_open_args *args,
				 const u8 *nonce)
{
#if TRUSTIX_X86_SIMD
	struct trustix_aead_direct_snapshot snapshot;
	struct trustix_aead_prepared_op op = {};
	struct sk_buff *skb = trustix_bpf_ctx_skb(ctx);
	struct iphdr *iph;
	u32 end;
	u32 plain_len;
	u32 tail_len;
	u8 *cipher;
	int ret;

	if (!skb || !args || !nonce ||
	    args->cipher_len < TRUSTIX_AEAD_IOC_TAG_LEN ||
	    args->cipher_len > TRUSTIX_AEAD_IOC_INPUT_MAX ||
	    check_add_overflow(args->cipher_offset, args->cipher_len, &end) ||
	    end > skb->len)
		return -EINVAL;
	ret = trustix_skb_ensure_writable_head(skb, end);
	if (ret)
		return ret;
	tail_len = skb->len - end;
	if (tail_len)
		return -EOPNOTSUPP;

	cipher = skb->data + args->cipher_offset;
	plain_len = args->cipher_len - TRUSTIX_AEAD_IOC_TAG_LEN;
	op.nonce = (u8 *)nonce;
	op.src = cipher;
	op.dst = cipher;
	op.in_len = args->cipher_len;
	op.out_len = plain_len;
	if (trustix_kfunc_fastpath_stats)
		this_cpu_inc(trustix_direct_kfunc_open_calls);
	ret = trustix_aead_direct_crypt_one_slot_rcu(args->slot_id, &op, true);
	if (ret == -EOPNOTSUPP) {
		ret = trustix_aead_direct_snapshot_slot(&snapshot,
							args->slot_id, true);
		if (!ret) {
			ret = trustix_aead_direct_crypt_one(&snapshot, &op,
							   true);
			memzero_explicit(&snapshot, sizeof(snapshot));
		}
	}
	if (ret) {
		trustix_direct_kfunc_record_error(
			ret, TRUSTIX_DIRECT_KFUNC_ERROR_SKB_OPEN);
		return ret;
	}
	if (plain_len < sizeof(*iph))
		return -EBADMSG;
	iph = (struct iphdr *)cipher;
	if (iph->version != 4 || iph->ihl != 5 ||
	    ntohs(iph->tot_len) != plain_len)
		return -EBADMSG;
	memcpy(skb->cb + TRUSTIX_SKB_CB_RX_NEXT_HOP, &iph->daddr,
	       sizeof(iph->daddr));
	skb_trim(skb, skb->len - TRUSTIX_AEAD_IOC_TAG_LEN);
	return (int)plain_len;
#else
	return -EOPNOTSUPP;
#endif
}

__bpf_kfunc int
trustix_kernel_skb_direct_seal(struct __sk_buff *ctx,
				 const struct trustix_aead_skb_direct_seal_args *args,
				 const u8 *nonce)
{
#if TRUSTIX_X86_SIMD
	struct trustix_aead_direct_snapshot snapshot;
	struct trustix_aead_prepared_op op = {};
	struct sk_buff *skb = trustix_bpf_ctx_skb(ctx);
	u32 plain_end;
	u32 cipher_end;
	u32 pull_len;
	u8 *plain;
	u8 *cipher;
	int ret;

	if (!skb || !args || !nonce ||
	    args->plain_len > TRUSTIX_AEAD_IOC_INPUT_MAX -
				      TRUSTIX_AEAD_IOC_TAG_LEN ||
	    check_add_overflow(args->plain_offset, args->plain_len,
			       &plain_end) ||
	    check_add_overflow(args->cipher_offset,
			       args->plain_len + TRUSTIX_AEAD_IOC_TAG_LEN,
			       &cipher_end) ||
	    plain_end > skb->len || cipher_end > skb->len)
		return -EINVAL;
	if (args->cipher_offset > args->plain_offset &&
	    args->cipher_offset < plain_end)
		return -EINVAL;

	pull_len = plain_end > cipher_end ? plain_end : cipher_end;
	ret = trustix_skb_ensure_writable_head(skb, pull_len);
	if (ret)
		return ret;

	plain = skb->data + args->plain_offset;
	cipher = skb->data + args->cipher_offset;
	op.nonce = (u8 *)nonce;
	op.src = plain;
	op.dst = cipher;
	op.in_len = args->plain_len;
	op.out_len = args->plain_len + TRUSTIX_AEAD_IOC_TAG_LEN;
	if (trustix_kfunc_fastpath_stats)
		this_cpu_inc(trustix_direct_kfunc_seal_calls);
	ret = trustix_aead_direct_crypt_one_slot_rcu(args->slot_id, &op, false);
	if (ret == -EOPNOTSUPP) {
		ret = trustix_aead_direct_snapshot_slot(&snapshot,
							args->slot_id, false);
		if (!ret) {
			ret = trustix_aead_direct_crypt_one(&snapshot, &op,
							   false);
			memzero_explicit(&snapshot, sizeof(snapshot));
		}
	}
	if (ret) {
		trustix_direct_kfunc_record_error(
			ret, TRUSTIX_DIRECT_KFUNC_ERROR_SKB_SEAL);
		return ret;
	}
	return (int)(args->plain_len + TRUSTIX_AEAD_IOC_TAG_LEN);
#else
	return -EOPNOTSUPP;
#endif
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(trustix_aead_tc_kfunc_ids)
BTF_ID_FLAGS(func, trustix_kernel_direct_seal)
BTF_ID_FLAGS(func, trustix_kernel_direct_open)
BTF_ID_FLAGS(func, trustix_kernel_skb_direct_open)
BTF_ID_FLAGS(func, trustix_kernel_skb_direct_seal)
BTF_KFUNCS_END(trustix_aead_tc_kfunc_ids)

BTF_KFUNCS_START(trustix_aead_xdp_kfunc_ids)
BTF_ID_FLAGS(func, trustix_kernel_direct_seal)
BTF_ID_FLAGS(func, trustix_kernel_direct_open)
BTF_KFUNCS_END(trustix_aead_xdp_kfunc_ids)

static const struct btf_kfunc_id_set trustix_aead_tc_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &trustix_aead_tc_kfunc_ids,
};

static const struct btf_kfunc_id_set trustix_aead_xdp_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &trustix_aead_xdp_kfunc_ids,
};
#endif

static int __init trustix_crypto_init(void)
{
	int ret;

#if TRUSTIX_DEVICE_ONLY
	trustix_vaes_available = trustix_aead_vaes_capable();
	trustix_aesni_available = trustix_aead_aesni_capable();
	if (!trustix_vaes_available) {
		trustix_experimental_vaes = false;
		trustix_experimental_vaes_kfunc = false;
	}
	ret = misc_register(&trustix_aead_miscdev);
	if (ret)
		return ret;
	trustix_feature_mask = TRUSTIX_AEAD_FEATURE_DEVICE_AEAD;
	if (trustix_aesni_available)
		trustix_feature_mask |= TRUSTIX_AEAD_FEATURE_DIRECT_AESNI;
	if (trustix_vaes_available)
		trustix_feature_mask |= TRUSTIX_AEAD_FEATURE_DIRECT_VAES;
	return 0;
#else
	trustix_vaes_available = trustix_aead_vaes_capable();
	trustix_aesni_available = trustix_aead_aesni_capable();
	if (!trustix_vaes_available) {
		trustix_experimental_vaes = false;
		trustix_experimental_vaes_kfunc = false;
	}
	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS,
					&trustix_aead_tc_kfunc_set);
	if (ret)
		return ret;
	trustix_feature_mask = TRUSTIX_AEAD_FEATURE_KFUNC_TC;
	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP,
					&trustix_aead_xdp_kfunc_set);
	if (!ret) {
		trustix_direct_xdp_available = true;
		trustix_feature_mask |= TRUSTIX_AEAD_FEATURE_KFUNC_XDP;
	}
#if TRUSTIX_ENABLE_BPF_CRYPTO
	ret = bpf_crypto_register_type(&trustix_crypto);
	if (ret)
		return ret;
	trustix_feature_mask |= TRUSTIX_AEAD_FEATURE_CRYPTO_AEAD;
#endif
	ret = misc_register(&trustix_aead_miscdev);
	if (ret) {
#if TRUSTIX_ENABLE_BPF_CRYPTO
		bpf_crypto_unregister_type(&trustix_crypto);
#endif
		return ret;
	}
	trustix_feature_mask |= TRUSTIX_AEAD_FEATURE_DEVICE_AEAD;
	if (trustix_aesni_available)
		trustix_feature_mask |= TRUSTIX_AEAD_FEATURE_DIRECT_AESNI;
	if (trustix_vaes_available)
		trustix_feature_mask |= TRUSTIX_AEAD_FEATURE_DIRECT_VAES;
	return 0;
#endif
}

static void __exit trustix_crypto_exit(void)
{
	misc_deregister(&trustix_aead_miscdev);
#if TRUSTIX_ENABLE_BPF_CRYPTO
	bpf_crypto_unregister_type(&trustix_crypto);
#endif
	trustix_aead_direct_clear_all();
}

module_init(trustix_crypto_init);
module_exit(trustix_crypto_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TrustIX BPF crypto AEAD provider");
MODULE_AUTHOR("TrustIX");
