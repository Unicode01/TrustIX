#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/limits.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#include "trustix_datapath_helpers_internal.h"

#define TRUSTIX_DATAPATH_ABI_VERSION 1U
#define TRUSTIX_DATAPATH_IOC_MAGIC 'T'
#define TRUSTIX_DATAPATH_IOC_VERSION 1U

#define TRUSTIX_DATAPATH_FEATURE_CRYPTO_AEAD BIT_ULL(0)
#define TRUSTIX_DATAPATH_FEATURE_DEVICE_AEAD BIT_ULL(1)
#define TRUSTIX_DATAPATH_FEATURE_KFUNC_TC BIT_ULL(2)
#define TRUSTIX_DATAPATH_FEATURE_KFUNC_XDP BIT_ULL(3)
#define TRUSTIX_DATAPATH_FEATURE_DIRECT_AESNI BIT_ULL(4)
#define TRUSTIX_DATAPATH_FEATURE_DIRECT_VAES BIT_ULL(5)
#define TRUSTIX_DATAPATH_FEATURE_GSO_SKB BIT_ULL(6)
#define TRUSTIX_DATAPATH_FEATURE_FULL_DATAPATH BIT_ULL(7)
#define TRUSTIX_DATAPATH_FEATURE_ROUTE_TCP_KFUNC BIT_ULL(8)
#define TRUSTIX_DATAPATH_FEATURE_ROUTE_TCP_XMIT_KFUNC BIT_ULL(9)
#define TRUSTIX_DATAPATH_KNOWN_FEATURES \
	(TRUSTIX_DATAPATH_FEATURE_CRYPTO_AEAD | \
	 TRUSTIX_DATAPATH_FEATURE_DEVICE_AEAD | \
	 TRUSTIX_DATAPATH_FEATURE_KFUNC_TC | \
	 TRUSTIX_DATAPATH_FEATURE_KFUNC_XDP | \
	 TRUSTIX_DATAPATH_FEATURE_DIRECT_AESNI | \
	 TRUSTIX_DATAPATH_FEATURE_DIRECT_VAES | \
	 TRUSTIX_DATAPATH_FEATURE_GSO_SKB | \
	 TRUSTIX_DATAPATH_FEATURE_FULL_DATAPATH | \
	 TRUSTIX_DATAPATH_FEATURE_ROUTE_TCP_KFUNC | \
	 TRUSTIX_DATAPATH_FEATURE_ROUTE_TCP_XMIT_KFUNC)

#define TRUSTIX_DATAPATH_FLAG_TIXT_SELFTEST_OK BIT(0)
#define TRUSTIX_DATAPATH_FLAG_FEATURES_ACTIVE BIT(1)

#define TRUSTIX_DATAPATH_SELFTEST_TIXT_FRAME BIT_ULL(0)
#define TRUSTIX_DATAPATH_SELFTEST_TIXT_STREAM BIT_ULL(1)
#define TRUSTIX_DATAPATH_SELFTEST_ALL \
	(TRUSTIX_DATAPATH_SELFTEST_TIXT_FRAME | \
	 TRUSTIX_DATAPATH_SELFTEST_TIXT_STREAM)

#define TRUSTIX_DATAPATH_TIXT_MAGIC 0x54495854U
#define TRUSTIX_DATAPATH_TIXT_VERSION 1U
#define TRUSTIX_DATAPATH_TIXT_HEADER_LEN 40U
#define TRUSTIX_DATAPATH_TIXT_MAX_PAYLOAD (64U * 1024U)
#define TRUSTIX_DATAPATH_TIXT_FLAG_ENCRYPTED BIT(0)
#define TRUSTIX_DATAPATH_TIXT_FLAG_KERNEL_OPENED BIT(1)
#define TRUSTIX_DATAPATH_TIXT_FLAG_CRYPTO_FRAGMENT BIT(2)
#define TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4 BIT(3)
#define TRUSTIX_DATAPATH_TIXT_KNOWN_FLAGS \
	(TRUSTIX_DATAPATH_TIXT_FLAG_ENCRYPTED | \
	 TRUSTIX_DATAPATH_TIXT_FLAG_KERNEL_OPENED | \
	 TRUSTIX_DATAPATH_TIXT_FLAG_CRYPTO_FRAGMENT | \
	 TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4)

#ifdef TRUSTIX_DATAPATH_HELPERS_BASIC
#define TRUSTIX_DATAPATH_COMPILED_FEATURES 0ULL
#else
#define TRUSTIX_DATAPATH_COMPILED_FEATURES \
	(TRUSTIX_DATAPATH_FEATURE_GSO_SKB | \
	 TRUSTIX_DATAPATH_FEATURE_ROUTE_TCP_KFUNC | \
	 TRUSTIX_DATAPATH_FEATURE_ROUTE_TCP_XMIT_KFUNC)
#endif

struct trustix_datapath_helpers_ioc_query {
	__u32 version;
	__s32 result;
	__u32 module_abi_version;
	__u32 datapath_abi_version;
	__u64 features;
	__u64 safe_features;
	__u64 unsafe_features;
	__u32 max_direct_slots;
	__u32 max_batch_ops;
	__u32 max_input_len;
	__u32 flags;
	__u64 reserved0;
	__u64 reserved1;
};

struct trustix_datapath_helpers_ioc_selftest {
	__u32 version;
	__s32 result;
	__u64 requested;
	__u64 passed;
	__u64 failed;
	__u64 features;
	__u32 flags;
	__u32 reserved;
};

#define TRUSTIX_DATAPATH_IOC_QUERY \
	_IOWR(TRUSTIX_DATAPATH_IOC_MAGIC, 12, struct trustix_datapath_helpers_ioc_query)

#define TRUSTIX_DATAPATH_IOC_SELFTEST \
	_IOWR(TRUSTIX_DATAPATH_IOC_MAGIC, 13, struct trustix_datapath_helpers_ioc_selftest)

static unsigned long long trustix_datapath_helpers_enable_features =
	TRUSTIX_DATAPATH_COMPILED_FEATURES;
module_param_named(enable_features, trustix_datapath_helpers_enable_features, ullong,
		   0444);
MODULE_PARM_DESC(enable_features,
		 "TrustIX datapath feature bitmask requested at load time; unimplemented or selftest-failed bits stay inactive");

static unsigned long long trustix_datapath_helpers_features;
module_param_named(features, trustix_datapath_helpers_features, ullong, 0444);
MODULE_PARM_DESC(features,
		 "TrustIX datapath active safe feature bitmask after module selftests");

static unsigned long long trustix_datapath_helpers_safe_features;
module_param_named(safe_features, trustix_datapath_helpers_safe_features, ullong, 0444);
MODULE_PARM_DESC(safe_features,
		 "TrustIX datapath active safe feature bitmask after module selftests");

static unsigned long long trustix_datapath_helpers_unsafe_features;
module_param_named(unsafe_features, trustix_datapath_helpers_unsafe_features, ullong,
		   0444);
MODULE_PARM_DESC(unsafe_features,
		 "TrustIX datapath feature bits known by the module but not safe to use");

static unsigned long long trustix_datapath_helpers_selftests;
module_param_named(selftests, trustix_datapath_helpers_selftests, ullong, 0444);
MODULE_PARM_DESC(selftests, "TrustIX datapath selftest bitmask that passed");

static unsigned long long trustix_datapath_helpers_selftest_failures;
module_param_named(selftest_failures, trustix_datapath_helpers_selftest_failures, ullong,
		   0444);
MODULE_PARM_DESC(selftest_failures,
		 "TrustIX datapath selftest bitmask that failed");

static unsigned int trustix_datapath_helpers_flags;
module_param_named(flags, trustix_datapath_helpers_flags, uint, 0444);
MODULE_PARM_DESC(flags,
		 "TrustIX datapath active status flags reported by the ioctl ABI");

static unsigned int trustix_datapath_helpers_abi_version =
	TRUSTIX_DATAPATH_ABI_VERSION;
module_param_named(abi_version, trustix_datapath_helpers_abi_version, uint, 0444);
MODULE_PARM_DESC(abi_version, "TrustIX datapath module ABI version");

static char *trustix_datapath_helpers_build_sha256 = "";
module_param_named(build_sha256, trustix_datapath_helpers_build_sha256, charp, 0444);
MODULE_PARM_DESC(build_sha256,
		 "SHA256 fingerprint of the TrustIX .ko payload passed by trustixd at load time");

struct trustix_datapath_helpers_tixt_frame {
	__u8 flags;
	__u64 flow_id;
	__u64 epoch;
	__u64 sequence;
	__u32 payload_len;
	__u16 fragment_index;
	__u16 fragment_count;
	__u32 wire_len;
};

static __u16 trustix_datapath_helpers_get_be16(const __u8 *ptr)
{
	return ((__u16)ptr[0] << 8) | (__u16)ptr[1];
}

static __u32 trustix_datapath_helpers_get_be32(const __u8 *ptr)
{
	return ((__u32)ptr[0] << 24) | ((__u32)ptr[1] << 16) |
	       ((__u32)ptr[2] << 8) | (__u32)ptr[3];
}

static __u64 trustix_datapath_helpers_get_be64(const __u8 *ptr)
{
	return ((__u64)trustix_datapath_helpers_get_be32(ptr) << 32) |
	       (__u64)trustix_datapath_helpers_get_be32(ptr + 4);
}

static void trustix_datapath_helpers_put_be16(__u8 *ptr, __u16 value)
{
	ptr[0] = (__u8)(value >> 8);
	ptr[1] = (__u8)value;
}

static void trustix_datapath_helpers_put_be32(__u8 *ptr, __u32 value)
{
	ptr[0] = (__u8)(value >> 24);
	ptr[1] = (__u8)(value >> 16);
	ptr[2] = (__u8)(value >> 8);
	ptr[3] = (__u8)value;
}

static void trustix_datapath_helpers_put_be64(__u8 *ptr, __u64 value)
{
	trustix_datapath_helpers_put_be32(ptr, (__u32)(value >> 32));
	trustix_datapath_helpers_put_be32(ptr + 4, (__u32)value);
}

static void
trustix_datapath_helpers_build_tixt(__u8 *wire, __u8 flags, __u64 flow_id,
			    __u64 epoch, __u64 sequence, __u32 payload_len,
			    __u16 fragment_index, __u16 fragment_count)
{
	memset(wire, 0, TRUSTIX_DATAPATH_TIXT_HEADER_LEN + payload_len);
	trustix_datapath_helpers_put_be32(wire, TRUSTIX_DATAPATH_TIXT_MAGIC);
	wire[4] = TRUSTIX_DATAPATH_TIXT_VERSION;
	wire[5] = flags;
	trustix_datapath_helpers_put_be16(wire + 6, TRUSTIX_DATAPATH_TIXT_HEADER_LEN);
	trustix_datapath_helpers_put_be64(wire + 8, flow_id);
	trustix_datapath_helpers_put_be64(wire + 16, epoch);
	trustix_datapath_helpers_put_be64(wire + 24, sequence);
	trustix_datapath_helpers_put_be32(wire + 32, payload_len);
	trustix_datapath_helpers_put_be16(wire + 36, fragment_index);
	trustix_datapath_helpers_put_be16(wire + 38, fragment_count);
}

static int
trustix_datapath_helpers_parse_tixt(const __u8 *wire, __u32 len,
			    struct trustix_datapath_helpers_tixt_frame *frame)
{
	__u32 header_len;
	__u32 payload_len;
	__u32 wire_len;
	__u16 fragment_index;
	__u16 fragment_count;
	__u8 flags;

	if (!wire || !frame)
		return -EINVAL;
	if (len < TRUSTIX_DATAPATH_TIXT_HEADER_LEN)
		return -ENODATA;
	if (trustix_datapath_helpers_get_be32(wire) != TRUSTIX_DATAPATH_TIXT_MAGIC)
		return -EPROTONOSUPPORT;
	if (wire[4] != TRUSTIX_DATAPATH_TIXT_VERSION)
		return -EPROTONOSUPPORT;
	header_len = trustix_datapath_helpers_get_be16(wire + 6);
	if (header_len != TRUSTIX_DATAPATH_TIXT_HEADER_LEN)
		return -EBADMSG;

	flags = wire[5];
	if (flags & ~TRUSTIX_DATAPATH_TIXT_KNOWN_FLAGS)
		return -EPROTONOSUPPORT;

	payload_len = trustix_datapath_helpers_get_be32(wire + 32);
	if (payload_len > TRUSTIX_DATAPATH_TIXT_MAX_PAYLOAD)
		return -EMSGSIZE;
	if (payload_len > UINT_MAX - TRUSTIX_DATAPATH_TIXT_HEADER_LEN)
		return -EMSGSIZE;
	wire_len = TRUSTIX_DATAPATH_TIXT_HEADER_LEN + payload_len;
	if (len < wire_len)
		return -EMSGSIZE;

	fragment_index = trustix_datapath_helpers_get_be16(wire + 36);
	fragment_count = trustix_datapath_helpers_get_be16(wire + 38);
	if (fragment_count == 0) {
		if (fragment_index != 0)
			return -EBADMSG;
		if (flags & TRUSTIX_DATAPATH_TIXT_FLAG_CRYPTO_FRAGMENT)
			return -EBADMSG;
	} else if (fragment_index >= fragment_count) {
		return -EBADMSG;
	}

	frame->flags = flags;
	frame->flow_id = trustix_datapath_helpers_get_be64(wire + 8);
	frame->epoch = trustix_datapath_helpers_get_be64(wire + 16);
	frame->sequence = trustix_datapath_helpers_get_be64(wire + 24);
	frame->payload_len = payload_len;
	frame->fragment_index = fragment_index;
	frame->fragment_count = fragment_count;
	frame->wire_len = wire_len;
	return 0;
}

static int trustix_datapath_helpers_selftest_tixt_frame(void)
{
	struct trustix_datapath_helpers_tixt_frame frame;
	__u8 wire[TRUSTIX_DATAPATH_TIXT_HEADER_LEN + 32];
	int ret;

	trustix_datapath_helpers_build_tixt(wire,
				    TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4,
				    0x1020304050607080ULL, 7, 11, 20, 0, 0);
	wire[TRUSTIX_DATAPATH_TIXT_HEADER_LEN] = 0x45;
	trustix_datapath_helpers_put_be16(wire + TRUSTIX_DATAPATH_TIXT_HEADER_LEN + 2,
				  20);
	ret = trustix_datapath_helpers_parse_tixt(wire, sizeof(wire), &frame);
	if (ret)
		return ret;
	if (frame.flags != TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4 ||
	    frame.flow_id != 0x1020304050607080ULL || frame.epoch != 7 ||
	    frame.sequence != 11 || frame.payload_len != 20 ||
	    frame.fragment_index != 0 || frame.fragment_count != 0 ||
	    frame.wire_len != TRUSTIX_DATAPATH_TIXT_HEADER_LEN + 20)
		return -EINVAL;

	wire[0] ^= 0xff;
	if (trustix_datapath_helpers_parse_tixt(wire, sizeof(wire), &frame) == 0)
		return -EINVAL;
	wire[0] ^= 0xff;
	wire[4] = 2;
	if (trustix_datapath_helpers_parse_tixt(wire, sizeof(wire), &frame) == 0)
		return -EINVAL;
	wire[4] = TRUSTIX_DATAPATH_TIXT_VERSION;
	trustix_datapath_helpers_put_be16(wire + 6,
				  TRUSTIX_DATAPATH_TIXT_HEADER_LEN + 8);
	if (trustix_datapath_helpers_parse_tixt(wire, sizeof(wire), &frame) == 0)
		return -EINVAL;
	trustix_datapath_helpers_put_be16(wire + 6, TRUSTIX_DATAPATH_TIXT_HEADER_LEN);
	trustix_datapath_helpers_put_be32(wire + 32,
				  TRUSTIX_DATAPATH_TIXT_MAX_PAYLOAD + 1);
	if (trustix_datapath_helpers_parse_tixt(wire, sizeof(wire), &frame) == 0)
		return -EINVAL;
	trustix_datapath_helpers_put_be32(wire + 32, 20);
	trustix_datapath_helpers_put_be16(wire + 36, 2);
	trustix_datapath_helpers_put_be16(wire + 38, 2);
	if (trustix_datapath_helpers_parse_tixt(wire, sizeof(wire), &frame) == 0)
		return -EINVAL;

	return 0;
}

static int trustix_datapath_helpers_selftest_tixt_stream(void)
{
	struct trustix_datapath_helpers_tixt_frame frame;
	__u8 stream[(TRUSTIX_DATAPATH_TIXT_HEADER_LEN + 24) * 2];
	__u32 cursor = 0;
	int ret;

	trustix_datapath_helpers_build_tixt(stream,
				    TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4,
				    1, 2, 3, 24, 0, 0);
	stream[TRUSTIX_DATAPATH_TIXT_HEADER_LEN] = 0x45;
	trustix_datapath_helpers_put_be16(stream + TRUSTIX_DATAPATH_TIXT_HEADER_LEN + 2,
				  24);
	cursor += TRUSTIX_DATAPATH_TIXT_HEADER_LEN + 24;

	trustix_datapath_helpers_build_tixt(stream + cursor,
				    TRUSTIX_DATAPATH_TIXT_FLAG_ENCRYPTED |
					    TRUSTIX_DATAPATH_TIXT_FLAG_CRYPTO_FRAGMENT,
				    4, 5, 6, 12, 0, 2);
	ret = trustix_datapath_helpers_parse_tixt(stream, sizeof(stream), &frame);
	if (ret || frame.wire_len != TRUSTIX_DATAPATH_TIXT_HEADER_LEN + 24)
		return ret ? ret : -EINVAL;
	cursor = frame.wire_len;
	ret = trustix_datapath_helpers_parse_tixt(stream + cursor,
					  sizeof(stream) - cursor, &frame);
	if (ret)
		return ret;
	if (frame.flow_id != 4 || frame.epoch != 5 || frame.sequence != 6 ||
	    frame.payload_len != 12 || frame.fragment_index != 0 ||
	    frame.fragment_count != 2 ||
	    frame.wire_len != TRUSTIX_DATAPATH_TIXT_HEADER_LEN + 12)
		return -EINVAL;
	return 0;
}

static void trustix_datapath_helpers_run_selftests(__u64 requested, __u64 *passed,
					   __u64 *failed)
{
	__u64 pass = 0;
	__u64 fail = 0;

	if (!requested)
		requested = TRUSTIX_DATAPATH_SELFTEST_ALL;
	if (requested & ~TRUSTIX_DATAPATH_SELFTEST_ALL)
		fail |= requested & ~TRUSTIX_DATAPATH_SELFTEST_ALL;
	if (requested & TRUSTIX_DATAPATH_SELFTEST_TIXT_FRAME) {
		if (trustix_datapath_helpers_selftest_tixt_frame())
			fail |= TRUSTIX_DATAPATH_SELFTEST_TIXT_FRAME;
		else
			pass |= TRUSTIX_DATAPATH_SELFTEST_TIXT_FRAME;
	}
	if (requested & TRUSTIX_DATAPATH_SELFTEST_TIXT_STREAM) {
		if (trustix_datapath_helpers_selftest_tixt_stream())
			fail |= TRUSTIX_DATAPATH_SELFTEST_TIXT_STREAM;
		else
			pass |= TRUSTIX_DATAPATH_SELFTEST_TIXT_STREAM;
	}

	if (passed)
		*passed = pass;
	if (failed)
		*failed = fail;
}

static void trustix_datapath_helpers_refresh_features(void)
{
	__u64 passed = 0;
	__u64 failed = 0;
	__u64 requested_features;
	__u64 active_features = 0;
	__u32 flags = 0;

	trustix_datapath_helpers_run_selftests(TRUSTIX_DATAPATH_SELFTEST_ALL, &passed,
				       &failed);
	if ((passed & TRUSTIX_DATAPATH_SELFTEST_ALL) ==
		    TRUSTIX_DATAPATH_SELFTEST_ALL &&
	    !failed) {
		flags |= TRUSTIX_DATAPATH_FLAG_TIXT_SELFTEST_OK;
		requested_features = READ_ONCE(trustix_datapath_helpers_enable_features);
		active_features = requested_features &
				  trustix_datapath_helpers_feature_mask();
		if (active_features)
			flags |= TRUSTIX_DATAPATH_FLAG_FEATURES_ACTIVE;
	}

	WRITE_ONCE(trustix_datapath_helpers_selftests, passed);
	WRITE_ONCE(trustix_datapath_helpers_selftest_failures, failed);
	WRITE_ONCE(trustix_datapath_helpers_features, active_features);
	WRITE_ONCE(trustix_datapath_helpers_safe_features,
		   active_features);
	WRITE_ONCE(trustix_datapath_helpers_unsafe_features,
		   (READ_ONCE(trustix_datapath_helpers_enable_features) &
		    TRUSTIX_DATAPATH_KNOWN_FEATURES) &
			   ~active_features);
	WRITE_ONCE(trustix_datapath_helpers_flags, flags);
}

static int trustix_datapath_helpers_open(struct inode *inode, struct file *file)
{
	return 0;
}

static long trustix_datapath_helpers_ioctl(struct file *file,
				   unsigned int cmd,
				   unsigned long arg)
{
	struct trustix_datapath_helpers_ioc_query query;
	struct trustix_datapath_helpers_ioc_selftest selftest;
	__u64 requested;
	__u64 passed;
	__u64 failed;

	switch (cmd) {
	case TRUSTIX_DATAPATH_IOC_QUERY:
		if (copy_from_user(&query, (void __user *)arg, sizeof(query)))
			return -EFAULT;
		if (query.version != TRUSTIX_DATAPATH_IOC_VERSION)
			return -EINVAL;

		trustix_datapath_helpers_refresh_features();
		memset(&query, 0, sizeof(query));
		query.version = TRUSTIX_DATAPATH_IOC_VERSION;
		query.module_abi_version = TRUSTIX_DATAPATH_ABI_VERSION;
		query.datapath_abi_version = TRUSTIX_DATAPATH_IOC_VERSION;
		query.features = READ_ONCE(trustix_datapath_helpers_features);
		query.safe_features = READ_ONCE(trustix_datapath_helpers_safe_features);
		query.unsafe_features = READ_ONCE(trustix_datapath_helpers_unsafe_features);
		query.flags = READ_ONCE(trustix_datapath_helpers_flags);
		query.reserved0 = READ_ONCE(trustix_datapath_helpers_selftests);
		query.reserved1 = READ_ONCE(trustix_datapath_helpers_selftest_failures);

		if (copy_to_user((void __user *)arg, &query, sizeof(query)))
			return -EFAULT;
		return 0;
	case TRUSTIX_DATAPATH_IOC_SELFTEST:
		if (copy_from_user(&selftest, (void __user *)arg,
				   sizeof(selftest)))
			return -EFAULT;
		if (selftest.version != TRUSTIX_DATAPATH_IOC_VERSION)
			return -EINVAL;
		requested = selftest.requested ? selftest.requested :
						 TRUSTIX_DATAPATH_SELFTEST_ALL;
		trustix_datapath_helpers_run_selftests(requested, &passed, &failed);
		trustix_datapath_helpers_refresh_features();
		memset(&selftest, 0, sizeof(selftest));
		selftest.version = TRUSTIX_DATAPATH_IOC_VERSION;
		selftest.result = failed ? -EINVAL : 0;
		selftest.requested = requested;
		selftest.passed = passed;
		selftest.failed = failed;
		selftest.features = READ_ONCE(trustix_datapath_helpers_features);
		selftest.flags = READ_ONCE(trustix_datapath_helpers_flags);
		if (copy_to_user((void __user *)arg, &selftest,
				 sizeof(selftest)))
			return -EFAULT;
		return 0;
	default:
		return -ENOTTY;
	}
}

static const struct file_operations trustix_datapath_helpers_fops = {
	.owner = THIS_MODULE,
	.open = trustix_datapath_helpers_open,
	.unlocked_ioctl = trustix_datapath_helpers_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = trustix_datapath_helpers_ioctl,
#endif
};

static struct miscdevice trustix_datapath_helpers_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "trustix_datapath_helpers",
	.fops = &trustix_datapath_helpers_fops,
	.mode = 0600,
};

#ifdef TRUSTIX_DATAPATH_HELPERS_BASIC
int trustix_datapath_helpers_register(void)
{
	return 0;
}

void trustix_datapath_helpers_unregister(void)
{
}

void trustix_datapath_helpers_disable_panic_risk_params(void)
{
}

__u64 trustix_datapath_helpers_feature_mask(void)
{
	return 0;
}
#endif

static int __init trustix_datapath_helpers_init(void)
{
	int ret;

	trustix_datapath_helpers_disable_panic_risk_params();
	ret = trustix_datapath_helpers_register();
	if (ret)
		return ret;
	trustix_datapath_helpers_refresh_features();
	return misc_register(&trustix_datapath_helpers_miscdev);
}

static void __exit trustix_datapath_helpers_module_exit(void)
{
	misc_deregister(&trustix_datapath_helpers_miscdev);
	trustix_datapath_helpers_unregister();
}

module_init(trustix_datapath_helpers_init);
module_exit(trustix_datapath_helpers_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TrustIX");
MODULE_DESCRIPTION("TrustIX datapath helper kernel module");
MODULE_VERSION("0.1.0");
