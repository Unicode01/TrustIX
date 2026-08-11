#include <linux/fs.h>
#include <linux/atomic.h>
#include <linux/bottom_half.h>
#include <linux/cpumask.h>
#include <linux/etherdevice.h>
#include <linux/err.h>
#include <linux/gfp.h>
#include <linux/highmem.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ioctl.h>
#include <linux/ip.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/math64.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/notifier.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/nsproxy.h>
#include <linux/overflow.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/seqlock.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/u64_stats_sync.h>
#include <linux/uaccess.h>
#include <linux/udp.h>
#include <linux/version.h>
#include <linux/workqueue.h>
#include <net/arp.h>
#include <net/checksum.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0) && \
	defined(CONFIG_PAGE_POOL)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
#include <net/page_pool/helpers.h>
#else
#include <net/page_pool.h>
#endif
#define TRUSTIX_DATAPATH_HAVE_TX_OUTER_GSO_PAGE_POOL 1
#else
#define TRUSTIX_DATAPATH_HAVE_TX_OUTER_GSO_PAGE_POOL 0
#endif
#if defined(__has_include)
#if __has_include(<net/gso.h>)
#include <net/gso.h>
#endif
#else
#include <net/gso.h>
#endif
#include <net/ip.h>
#include <net/netevent.h>
#include <net/net_namespace.h>
#include <net/neighbour.h>
#include <net/route.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
#define kmap_local_page(page) kmap_atomic(page)
#define kunmap_local(addr) kunmap_atomic(addr)
#endif

#ifndef ENOKEY
#define ENOKEY 126
#endif

#ifndef ESTALE
#define ESTALE 116
#endif

#define TRUSTIX_DATAPATH_ABI_VERSION 1U
#define TRUSTIX_DATAPATH_IOC_MAGIC 'T'
#define TRUSTIX_DATAPATH_IOC_VERSION 1U

#define TRUSTIX_DATAPATH_FEATURE_FULL_DATAPATH BIT_ULL(7)
#define TRUSTIX_DATAPATH_FEATURE_INNER_TCP_CHECKSUM_PARTIAL BIT_ULL(10)
#define TRUSTIX_DATAPATH_FEATURE_INNER_GSO BIT_ULL(11)
#define TRUSTIX_DATAPATH_FEATURE_TIX_TCP_PORT_SHARDING BIT_ULL(12)
#define TRUSTIX_DATAPATH_FEATURE_SECURE_TIX_TCP_FULL_DATAPATH BIT_ULL(13)
#define TRUSTIX_DATAPATH_FEATURE_SECURE_INNER_TCP_CHECKSUM_PARTIAL BIT_ULL(14)
#define TRUSTIX_DATAPATH_KNOWN_FEATURES \
	(TRUSTIX_DATAPATH_FEATURE_FULL_DATAPATH | \
	 TRUSTIX_DATAPATH_FEATURE_INNER_TCP_CHECKSUM_PARTIAL | \
	 TRUSTIX_DATAPATH_FEATURE_INNER_GSO | \
	 TRUSTIX_DATAPATH_FEATURE_TIX_TCP_PORT_SHARDING | \
	 TRUSTIX_DATAPATH_FEATURE_SECURE_TIX_TCP_FULL_DATAPATH | \
	 TRUSTIX_DATAPATH_FEATURE_SECURE_INNER_TCP_CHECKSUM_PARTIAL)

#define TRUSTIX_DATAPATH_FLAG_TIXT_SELFTEST_OK BIT(0)
#define TRUSTIX_DATAPATH_FLAG_FEATURES_ACTIVE BIT(1)

#define TRUSTIX_DATAPATH_SELFTEST_TIXT_FRAME BIT_ULL(0)
#define TRUSTIX_DATAPATH_SELFTEST_TIXT_STREAM BIT_ULL(1)
#define TRUSTIX_DATAPATH_SELFTEST_STATE_TABLE BIT_ULL(2)
#define TRUSTIX_DATAPATH_SELFTEST_CLASSIFY BIT_ULL(3)
#define TRUSTIX_DATAPATH_SELFTEST_PACKET_CLASSIFY BIT_ULL(4)
#define TRUSTIX_DATAPATH_SELFTEST_TIXT_ENCAP BIT_ULL(5)
#define TRUSTIX_DATAPATH_SELFTEST_TIXT_DECAP BIT_ULL(6)
#define TRUSTIX_DATAPATH_SELFTEST_SESSION_WIRE BIT_ULL(7)
#define TRUSTIX_DATAPATH_SELFTEST_OUTER_BUILD BIT_ULL(8)
#define TRUSTIX_DATAPATH_SELFTEST_OUTER_PARSE BIT_ULL(9)
#define TRUSTIX_DATAPATH_SELFTEST_INNER_TCP_CHECKSUM_PARTIAL BIT_ULL(10)
#define TRUSTIX_DATAPATH_SELFTEST_INNER_GSO BIT_ULL(11)
#define TRUSTIX_DATAPATH_SELFTEST_SECURE_TIX_TCP BIT_ULL(12)
#define TRUSTIX_DATAPATH_SELFTEST_SECURE_INNER_TCP_CHECKSUM_PARTIAL BIT_ULL(13)
#define TRUSTIX_DATAPATH_SELFTEST_FULL_DATAPATH \
	(TRUSTIX_DATAPATH_SELFTEST_TIXT_FRAME | \
	 TRUSTIX_DATAPATH_SELFTEST_TIXT_STREAM | \
	 TRUSTIX_DATAPATH_SELFTEST_STATE_TABLE | \
	 TRUSTIX_DATAPATH_SELFTEST_CLASSIFY | \
	 TRUSTIX_DATAPATH_SELFTEST_PACKET_CLASSIFY | \
	 TRUSTIX_DATAPATH_SELFTEST_TIXT_ENCAP | \
	 TRUSTIX_DATAPATH_SELFTEST_TIXT_DECAP | \
	 TRUSTIX_DATAPATH_SELFTEST_SESSION_WIRE | \
	 TRUSTIX_DATAPATH_SELFTEST_OUTER_BUILD | \
	 TRUSTIX_DATAPATH_SELFTEST_OUTER_PARSE)
#define TRUSTIX_DATAPATH_SELFTEST_ALL \
	(TRUSTIX_DATAPATH_SELFTEST_FULL_DATAPATH | \
	 TRUSTIX_DATAPATH_SELFTEST_INNER_TCP_CHECKSUM_PARTIAL | \
	 TRUSTIX_DATAPATH_SELFTEST_INNER_GSO | \
	 TRUSTIX_DATAPATH_SELFTEST_SECURE_TIX_TCP | \
	 TRUSTIX_DATAPATH_SELFTEST_SECURE_INNER_TCP_CHECKSUM_PARTIAL)

#define TRUSTIX_DATAPATH_STATE_KIND_ROUTE 1U
#define TRUSTIX_DATAPATH_STATE_KIND_SESSION 2U
#define TRUSTIX_DATAPATH_STATE_KIND_FLOW 3U
#define TRUSTIX_DATAPATH_STATE_KIND_SESSION_WIRE 4U
#define TRUSTIX_DATAPATH_STATE_KIND_SESSION_CRYPTO 5U

#define TRUSTIX_DATAPATH_STATE_OP_UPSERT 1U
#define TRUSTIX_DATAPATH_STATE_OP_GET 2U
#define TRUSTIX_DATAPATH_STATE_OP_DELETE 3U
#define TRUSTIX_DATAPATH_STATE_OP_CLEAR 4U

#define TRUSTIX_DATAPATH_STATE_DEFAULT_ROUTES 1024U
#define TRUSTIX_DATAPATH_STATE_DEFAULT_SESSIONS 4096U
#define TRUSTIX_DATAPATH_STATE_DEFAULT_FLOWS 4096U
#define TRUSTIX_DATAPATH_STATE_MAX_ENTRIES 65536U
#define TRUSTIX_DATAPATH_STATE_BATCH_MAX 4096U
#define TRUSTIX_DATAPATH_PACKET_MAX_LEN 65535U
#define TRUSTIX_DATAPATH_IPV4_L4_PREFIX_MAX 80U
#define TRUSTIX_DATAPATH_IFNAME_MAX 16U
#define TRUSTIX_DATAPATH_TIX_TCP_PORT_SHARDS 16U

#define TRUSTIX_DATAPATH_HOOK_OP_ATTACH 1U
#define TRUSTIX_DATAPATH_HOOK_OP_DETACH 2U
#define TRUSTIX_DATAPATH_HOOK_OP_QUERY 3U

#define TRUSTIX_DATAPATH_ENCAP_FLAG_NONE 0U

#define TRUSTIX_DATAPATH_ROUTE_FLAG_UNICAST 1U
#define TRUSTIX_DATAPATH_ROUTE_FLAG_LOCAL 2U
#define TRUSTIX_DATAPATH_ROUTE_FLAG_BLACKHOLE 3U
#define TRUSTIX_DATAPATH_ROUTE_FLAG_REJECT 4U

#define TRUSTIX_DATAPATH_SESSION_FLAG_REVERSE BIT(0)
#define TRUSTIX_DATAPATH_SESSION_FLAG_KERNEL_FLOW BIT(2)
#define TRUSTIX_DATAPATH_SESSION_FLAG_ENCRYPTED BIT(3)
#define TRUSTIX_DATAPATH_SESSION_FLAG_SEND_ENCRYPTED BIT(4)
#define TRUSTIX_DATAPATH_SESSION_FLAG_RECEIVE_ENCRYPTED BIT(5)
#define TRUSTIX_DATAPATH_SESSION_FLAG_CRYPTO_KERNEL BIT(6)
#define TRUSTIX_DATAPATH_SESSION_FLAG_SYNTHETIC_FALLBACK BIT(11)
#define TRUSTIX_DATAPATH_SESSION_FLAG_SEND_INNER_TCP_CHECKSUM_PARTIAL BIT(12)
#define TRUSTIX_DATAPATH_SESSION_FLAG_RECEIVE_INNER_TCP_CHECKSUM_PARTIAL BIT(13)
#define TRUSTIX_DATAPATH_SESSION_FLAG_SEND_INNER_GSO BIT(14)
#define TRUSTIX_DATAPATH_SESSION_FLAG_RECEIVE_INNER_GSO BIT(15)
#define TRUSTIX_DATAPATH_SESSION_FLAG_SEND_TIX_TCP_PORT_SHARDING BIT(16)
#define TRUSTIX_DATAPATH_SESSION_FLAG_RECEIVE_TIX_TCP_PORT_SHARDING BIT(17)
#define TRUSTIX_DATAPATH_SESSION_FLAG_SEND_SECURE_INNER_TCP_CHECKSUM_PARTIAL BIT(18)
#define TRUSTIX_DATAPATH_SESSION_FLAG_RECEIVE_SECURE_INNER_TCP_CHECKSUM_PARTIAL BIT(19)
#define TRUSTIX_DATAPATH_SESSION_FLAGS_ENCRYPTED \
	(TRUSTIX_DATAPATH_SESSION_FLAG_ENCRYPTED | \
	 TRUSTIX_DATAPATH_SESSION_FLAG_SEND_ENCRYPTED | \
	 TRUSTIX_DATAPATH_SESSION_FLAG_RECEIVE_ENCRYPTED)
#define TRUSTIX_DATAPATH_TRANSPORT_UDP 1U
#define TRUSTIX_DATAPATH_TRANSPORT_TIX_TCP 2U
#define TRUSTIX_DATAPATH_SESSION_CRYPTO_FLAG_SEND_READY BIT(0)
#define TRUSTIX_DATAPATH_SESSION_CRYPTO_FLAG_RECEIVE_READY BIT(1)
#define TRUSTIX_DATAPATH_SESSION_CRYPTO_FLAGS_READY \
	(TRUSTIX_DATAPATH_SESSION_CRYPTO_FLAG_SEND_READY | \
	 TRUSTIX_DATAPATH_SESSION_CRYPTO_FLAG_RECEIVE_READY)
#define TRUSTIX_DATAPATH_OUTER_PARSE_FLAG_REVERSE BIT(0)
#define TRUSTIX_DATAPATH_HOOK_FLAG_RX_PREVIEW BIT(0)
#define TRUSTIX_DATAPATH_HOOK_FLAG_RX_STAGE BIT(1)
#define TRUSTIX_DATAPATH_HOOK_FLAG_RX_WORKER BIT(2)
#define TRUSTIX_DATAPATH_HOOK_FLAG_TX_PLAINTEXT BIT(3)
#define TRUSTIX_DATAPATH_HOOK_FLAG_TX_SECURE_TIX_TCP BIT(4)
#define TRUSTIX_DATAPATH_HOOK_FLAG_RX_SECURE_TIX_TCP_ONLY BIT(5)

#define TRUSTIX_DATAPATH_RX_STAGE_OP_QUERY 1U
#define TRUSTIX_DATAPATH_RX_STAGE_OP_PEEK 2U
#define TRUSTIX_DATAPATH_RX_STAGE_OP_POP 3U
#define TRUSTIX_DATAPATH_RX_STAGE_OP_CLEAR 4U
#define TRUSTIX_DATAPATH_RX_STAGE_DEFAULT_SLOTS 16U
#define TRUSTIX_DATAPATH_RX_STAGE_MAX_SLOTS 1024U
#define TRUSTIX_DATAPATH_RX_WORKER_DEFAULT_SLOTS 16U
#define TRUSTIX_DATAPATH_RX_WORKER_MAX_SLOTS 8192U
#define TRUSTIX_DATAPATH_RX_WORKER_DEFAULT_BUDGET 64U
#define TRUSTIX_DATAPATH_RX_WORKER_STREAM_MAX_FRAMES 64U
#define TRUSTIX_DATAPATH_RX_WORKER_INLINE_PAIR_SLOTS 256U
#define TRUSTIX_DATAPATH_RX_WORKER_INLINE_PAIR_MAX_FRAMES 64U
#define TRUSTIX_DATAPATH_RX_WORKER_SINGLE_COALESCE_SLOTS 1024U
#define TRUSTIX_DATAPATH_RX_WORKER_SINGLE_COALESCE_MAX_FRAMES 32U
#define TRUSTIX_DATAPATH_TX_PLAINTEXT_DEFAULT_SLOTS 8192U
#define TRUSTIX_DATAPATH_TX_PLAINTEXT_MAX_SLOTS 8192U
#define TRUSTIX_DATAPATH_TX_PLAINTEXT_MAX_GSO_SEGS 64U
#define TRUSTIX_DATAPATH_SECURE_TX_SEAL_BATCH 32U

enum trustix_datapath_secure_rx_error_stage {
	TRUSTIX_DATAPATH_SECURE_RX_ERROR_NONE = 0,
	TRUSTIX_DATAPATH_SECURE_RX_ERROR_WRITABLE,
	TRUSTIX_DATAPATH_SECURE_RX_ERROR_FRAME_LIMIT,
	TRUSTIX_DATAPATH_SECURE_RX_ERROR_FRAME_PARSE,
	TRUSTIX_DATAPATH_SECURE_RX_ERROR_FRAME_VALIDATE,
	TRUSTIX_DATAPATH_SECURE_RX_ERROR_PLAN,
	TRUSTIX_DATAPATH_SECURE_RX_ERROR_HEADER,
	TRUSTIX_DATAPATH_SECURE_RX_ERROR_CRYPTO,
	TRUSTIX_DATAPATH_SECURE_RX_ERROR_CHECKSUM,
	TRUSTIX_DATAPATH_SECURE_RX_ERROR_LAYOUT,
	TRUSTIX_DATAPATH_SECURE_RX_ERROR_COPY,
	TRUSTIX_DATAPATH_SECURE_RX_ERROR_DELIVERY,
};
#define TRUSTIX_DATAPATH_TX_PLAINTEXT_COALESCE_SLOTS 256U
#define TRUSTIX_DATAPATH_TX_PLAINTEXT_COALESCE_MAX_FRAMES 32U
#define TRUSTIX_DATAPATH_TX_OUTER_GSO_PAGE_POOL_ORDER 4U
#define TRUSTIX_DATAPATH_TX_OUTER_GSO_PAGE_POOL_SIZE 64U
#define TRUSTIX_DATAPATH_LOOKUP_CACHE_MIN_SLOTS 1024U
#define TRUSTIX_DATAPATH_LOOKUP_CACHE_MAX_SLOTS 65536U
#define TRUSTIX_DATAPATH_WIRE_TUPLE_CACHE_MAX_SLOTS 2621440U
#define TRUSTIX_DATAPATH_OUTER_TCP_ORDER_LOCKS 256U
#define TRUSTIX_DATAPATH_INNER_GSO_FAULT_THRESHOLD_DEFAULT 8U
#define TRUSTIX_DATAPATH_INNER_GSO_FAULT_WINDOW_MS_DEFAULT 1000U
#define TRUSTIX_DATAPATH_INNER_GSO_TIMEOUT_THRESHOLD_DEFAULT 64U
#define TRUSTIX_DATAPATH_INNER_GSO_TIMEOUT_RATIO_PPM_DEFAULT 50000U
#define TRUSTIX_DATAPATH_INNER_GSO_RATIO_PPM_SCALE 1000000U
/* Count both timeout bursts and sustained incomplete-frame degradation. */
#define TRUSTIX_DATAPATH_INNER_GSO_TIMEOUT_WINDOW_MS_DEFAULT 60000U
#define TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_TIMEOUT_MS_DEFAULT 10000U
#define TRUSTIX_DATAPATH_INNER_GSO_NO_PROGRESS_MS_DEFAULT 5000U
#define TRUSTIX_DATAPATH_INNER_GSO_COOLDOWN_MS_DEFAULT 60000U
#define TRUSTIX_DATAPATH_INNER_GSO_MAX_COOLDOWN_MS_DEFAULT 900000U
#define TRUSTIX_DATAPATH_INNER_GSO_STABLE_MS_DEFAULT 600000U
#define TRUSTIX_DATAPATH_SKB_MARK_TX_PLAINTEXT BIT(31)
#define TRUSTIX_DATAPATH_SKB_MARK_RX_WORKER BIT(30)
#define TRUSTIX_DATAPATH_HOOK_MAX 16U

#define TRUSTIX_DATAPATH_TIXT_MAGIC 0x54495854U
#define TRUSTIX_DATAPATH_TIXU_MAGIC 0x54495855U
#define TRUSTIX_DATAPATH_TIXT_VERSION 1U
#define TRUSTIX_DATAPATH_TIXT_HEADER_LEN 40U
#define TRUSTIX_DATAPATH_TIXU_HEADER_LEN 32U
#define TRUSTIX_DATAPATH_MIN_FRAME_HEADER_LEN TRUSTIX_DATAPATH_TIXU_HEADER_LEN
#define TRUSTIX_DATAPATH_TIXT_MAX_PAYLOAD (64U * 1024U)
#define TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_SLOTS 128U
#define TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_PROBES \
	TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_SLOTS
#define TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_SETS \
	(TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_SLOTS / \
	 TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_PROBES)
#define TRUSTIX_DATAPATH_INNER_GSO_PROBATION_SLOTS 256U
#define TRUSTIX_DATAPATH_INNER_GSO_PROBATION_PROBES 4U
#define TRUSTIX_DATAPATH_INNER_GSO_PROBATION_SETS \
	(TRUSTIX_DATAPATH_INNER_GSO_PROBATION_SLOTS / \
	 TRUSTIX_DATAPATH_INNER_GSO_PROBATION_PROBES)
#define TRUSTIX_DATAPATH_INNER_GSO_PROBATION_MIN_CLAIMS 2U
#define TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_FRAME_MAX \
	(TRUSTIX_DATAPATH_TIXT_HEADER_LEN + TRUSTIX_DATAPATH_PACKET_MAX_LEN)
#define TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_MAX_RANGES 128U
#define TRUSTIX_DATAPATH_SECURE_HEADER_LEN 24U
#define TRUSTIX_DATAPATH_SECURE_TAG_LEN 16U
#define TRUSTIX_DATAPATH_SECURE_OVERHEAD \
	(TRUSTIX_DATAPATH_SECURE_HEADER_LEN + TRUSTIX_DATAPATH_SECURE_TAG_LEN)
#define TRUSTIX_DATAPATH_SECURE_MAGIC 0x54495844U
#define TRUSTIX_DATAPATH_SECURE_VERSION 1U
#define TRUSTIX_DATAPATH_SECURE_WIRE_FORMAT_V1 1U
#define TRUSTIX_DATAPATH_SECURE_SUITE_AES_256_GCM_X25519 1U
#define TRUSTIX_DATAPATH_SECURE_SUITE_AES_128_GCM_X25519 2U
#define TRUSTIX_DATAPATH_SECURE_REPLAY_MAX 65536U
#define TRUSTIX_DATAPATH_DIRECT_MAX_BATCH 128U
#define TRUSTIX_DATAPATH_TIXT_FLAG_ENCRYPTED BIT(0)
#define TRUSTIX_DATAPATH_TIXT_FLAG_KERNEL_OPENED BIT(1)
#define TRUSTIX_DATAPATH_TIXT_FLAG_CRYPTO_FRAGMENT BIT(2)
#define TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4 BIT(3)
#define TRUSTIX_DATAPATH_TIXT_FLAG_INNER_TCP_CHECKSUM_PARTIAL BIT(4)
#define TRUSTIX_DATAPATH_TIXT_FLAG_INNER_GSO BIT(5)
#define TRUSTIX_DATAPATH_TIXT_FLAG_INNER_L4_CHECKSUM_VALID \
	TRUSTIX_DATAPATH_TIXT_FLAG_KERNEL_OPENED
#define TRUSTIX_DATAPATH_TIXT_KNOWN_FLAGS \
	(TRUSTIX_DATAPATH_TIXT_FLAG_ENCRYPTED | \
	 TRUSTIX_DATAPATH_TIXT_FLAG_KERNEL_OPENED | \
	 TRUSTIX_DATAPATH_TIXT_FLAG_CRYPTO_FRAGMENT | \
	 TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4 | \
	 TRUSTIX_DATAPATH_TIXT_FLAG_INNER_TCP_CHECKSUM_PARTIAL | \
	 TRUSTIX_DATAPATH_TIXT_FLAG_INNER_GSO)

struct trustix_aead_direct_batch_op {
	const __u8 *src;
	__u8 *dst;
	__u32 plain_len;
	__u8 nonce[12];
};

struct trustix_aead_direct_open_replay_op {
	const __u8 *src;
	__u8 *dst;
	__u32 cipher_len;
	__u8 nonce[12];
	__u64 sequence;
};

typedef bool (*trustix_kernel_direct_datapath_ready_fn)(void);
typedef int (*trustix_kernel_direct_datapath_selftest_fn)(void);
typedef int (*trustix_kernel_direct_slot_generation_fn)(
	__u32 slot_id, bool decrypt, __u64 *generation);
typedef int (*trustix_kernel_direct_reserve_sequences_fn)(
	__u32 slot_id, __u64 floor, __u32 count, __u64 *first,
	__u64 *generation);
typedef int (*trustix_kernel_direct_seal_batch_generation_fn)(
	__u32 slot_id, __u64 generation,
	const struct trustix_aead_direct_batch_op *ops, __u32 count);
typedef int (*trustix_kernel_direct_open_replay_batch_fn)(
	__u32 slot_id, __u64 generation,
	const struct trustix_aead_direct_open_replay_op *ops, __u32 count,
	__u64 replay_floor, __u32 replay_window);

extern bool trustix_kernel_direct_datapath_ready(void);
extern int trustix_kernel_direct_datapath_selftest(void);
extern int trustix_kernel_direct_slot_generation(
	__u32 slot_id, bool decrypt, __u64 *generation);
extern int trustix_kernel_direct_reserve_sequences(
	__u32 slot_id, __u64 floor, __u32 count, __u64 *first,
	__u64 *generation);
extern int trustix_kernel_direct_seal_batch_generation(
	__u32 slot_id, __u64 generation,
	const struct trustix_aead_direct_batch_op *ops, __u32 count);
extern int trustix_kernel_direct_open_replay_batch(
	__u32 slot_id, __u64 generation,
	const struct trustix_aead_direct_open_replay_op *ops, __u32 count,
	__u64 replay_floor, __u32 replay_window);

struct trustix_datapath_ioc_query {
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

struct trustix_datapath_ioc_selftest {
	__u32 version;
	__s32 result;
	__u64 requested;
	__u64 passed;
	__u64 failed;
	__u64 features;
	__u32 flags;
	__u32 reserved;
};

struct trustix_datapath_ioc_state {
	__u32 version;
	__s32 result;
	__u32 kind;
	__u32 op;
	__u32 flags;
	__u32 reserved0;
	__u64 key[4];
	__u64 value[8];
};

struct trustix_datapath_ioc_state_stats {
	__u32 version;
	__s32 result;
	__u32 max_routes;
	__u32 routes;
	__u32 max_sessions;
	__u32 sessions;
	__u32 max_flows;
	__u32 flows;
	__u32 max_session_wires;
	__u32 session_wires;
	__u64 upserts;
	__u64 deletes;
	__u64 clears;
	__u64 get_hits;
	__u64 get_misses;
	__u64 table_full;
	__u64 reserved[3];
};

struct trustix_datapath_ioc_state_batch {
	__u32 version;
	__s32 result;
	__u32 count;
	__u32 applied;
	__u64 records_ptr;
	__u64 reserved[4];
};

struct trustix_datapath_ioc_classify {
	__u32 version;
	__s32 result;
	__u32 src_ipv4;
	__u32 dst_ipv4;
	__u16 src_port;
	__u16 dst_port;
	__u8 protocol;
	__u8 reserved0;
	__u16 reserved1;
	__u32 route_flags;
	__u32 prefix_len;
	__u64 flow_id;
	__u64 session_flags;
	__u64 reserved[4];
};

struct trustix_datapath_ioc_packet_classify {
	__u32 version;
	__s32 result;
	__u32 flags;
	__u32 packet_len;
	__u64 packet_ptr;
	__u32 src_ipv4;
	__u32 dst_ipv4;
	__u16 src_port;
	__u16 dst_port;
	__u8 protocol;
	__u8 ip_header_len;
	__u8 l4_header_len;
	__u8 reserved0;
	__u32 route_flags;
	__u32 prefix_len;
	__u64 flow_id;
	__u64 session_flags;
	__u64 packets_seen;
	__u64 bytes_seen;
	__u64 reserved[4];
};

struct trustix_datapath_ioc_packet_stats {
	__u32 version;
	__s32 result;
	__u64 packets;
	__u64 bytes;
	__u64 parse_errors;
	__u64 route_misses;
	__u64 session_misses;
	__u64 unicast_routes;
	__u64 local_routes;
	__u64 blackhole_routes;
	__u64 reject_routes;
	__u64 reserved[8];
};

struct trustix_datapath_ioc_hook {
	__u32 version;
	__s32 result;
	__u32 op;
	__u32 flags;
	char ifname[TRUSTIX_DATAPATH_IFNAME_MAX];
	char target_ifname[TRUSTIX_DATAPATH_IFNAME_MAX];
	__s32 ifindex;
	__s32 target_ifindex;
	__u32 attached;
	__u32 reserved0;
	__u64 seen;
	__u64 classified;
	__u64 parse_errors;
	__u64 route_misses;
	__u64 session_misses;
	__u64 pass;
	__u64 drop;
	__u64 outer_seen;
	__u64 outer_parsed;
	__u64 outer_parse_errors;
	__u64 outer_session_misses;
	__u64 rx_preview;
	__u64 rx_preview_errors;
	__u64 rx_stage;
	__u64 rx_stage_errors;
	__u64 rx_worker;
	__u64 rx_worker_errors;
	__u64 rx_worker_injected;
	__u64 rx_worker_dropped;
};

struct trustix_datapath_ioc_tixt_encap {
	__u32 version;
	__s32 result;
	__u32 flags;
	__u32 inner_len;
	__u64 inner_ptr;
	__u32 out_len;
	__u32 written_len;
	__u64 out_ptr;
	__u64 sequence;
	__u64 flow_id;
	__u64 epoch;
	__u32 route_flags;
	__u32 prefix_len;
	__u64 session_flags;
	__u64 reserved[6];
};

struct trustix_datapath_ioc_tixt_decap {
	__u32 version;
	__s32 result;
	__u32 flags;
	__u32 wire_len;
	__u64 wire_ptr;
	__u32 out_len;
	__u32 written_len;
	__u64 out_ptr;
	__u64 flow_id;
	__u64 epoch;
	__u64 sequence;
	__u32 payload_len;
	__u32 tixt_flags;
	__u64 session_flags;
	__u64 reserved[6];
};

struct trustix_datapath_ioc_outer_build {
	__u32 version;
	__s32 result;
	__u32 flags;
	__u32 inner_len;
	__u64 inner_ptr;
	__u32 out_len;
	__u32 written_len;
	__u64 out_ptr;
	__u64 sequence;
	__u64 flow_id;
	__u64 epoch;
	__u32 route_flags;
	__u32 prefix_len;
	__u64 session_flags;
	__u32 local_ipv4;
	__u32 remote_ipv4;
	__u16 local_port;
	__u16 remote_port;
	__u8 outer_protocol;
	__u8 reserved0;
	__u16 reserved1;
	__u32 tixt_len;
	__u32 reserved2;
	__u64 reserved[4];
};

struct trustix_datapath_ioc_outer_parse {
	__u32 version;
	__s32 result;
	__u32 flags;
	__u32 outer_len;
	__u64 outer_ptr;
	__u32 out_len;
	__u32 written_len;
	__u64 out_ptr;
	__u64 flow_id;
	__u64 epoch;
	__u64 sequence;
	__u32 payload_len;
	__u32 tixt_flags;
	__u64 session_flags;
	__u32 local_ipv4;
	__u32 remote_ipv4;
	__u16 local_port;
	__u16 remote_port;
	__u8 outer_protocol;
	__u8 reserved0;
	__u16 reserved1;
	__u32 tixt_len;
	__u32 reserved2;
	__u64 reserved[4];
};

struct trustix_datapath_ioc_rx_stage {
	__u32 version;
	__s32 result;
	__u32 op;
	__u32 flags;
	__u32 out_len;
	__u32 written_len;
	__u64 out_ptr;
	__u64 id;
	__u64 flow_id;
	__u64 epoch;
	__u64 sequence;
	__u32 payload_len;
	__u32 tixt_flags;
	__u64 session_flags;
	__u32 outer_src_ipv4;
	__u32 outer_dst_ipv4;
	__u16 outer_src_port;
	__u16 outer_dst_port;
	__u8 outer_protocol;
	__u8 inner_protocol;
	__u16 reserved0;
	__u32 inner_src_ipv4;
	__u32 inner_dst_ipv4;
	__u16 inner_src_port;
	__u16 inner_dst_port;
	__u8 inner_ip_header_len;
	__u8 inner_l4_header_len;
	__u16 reserved1;
	__u32 queue_len;
	__u32 capacity;
	__u32 slot_len;
	__u32 reserved2;
	__u64 staged;
	__u64 popped;
	__u64 dropped;
	__u64 overwritten;
	__u64 reserved[4];
};

struct trustix_datapath_tixt_frame {
	__u8 flags;
	__u8 header_len;
	__u64 flow_id;
	__u64 epoch;
	__u64 sequence;
	__u32 payload_len;
	__u16 fragment_index;
	__u16 fragment_count;
	__u32 wire_len;
};

struct trustix_datapath_state_slot {
	bool used;
	bool tombstone;
	__u32 flags;
	__u64 key[4];
	__u64 value[8];
	__u64 runtime[2];
};

struct trustix_datapath_state_table {
	struct trustix_datapath_state_slot *slots;
	__u32 capacity;
	__u32 count;
};

struct trustix_datapath_session_flow_cache_entry {
	bool used;
	__u64 flow_id;
	struct trustix_datapath_state_slot *slot;
};

struct trustix_datapath_route_dst_cache_entry {
	bool used;
	__u32 dst_ipv4;
	struct trustix_datapath_state_slot *slot;
};

struct trustix_datapath_session_route_cache_entry {
	bool used;
	struct trustix_datapath_state_slot *route;
	struct trustix_datapath_state_slot *flow;
	__u64 next_hop_hash;
	__u64 endpoint_hash;
	__u64 pool_index;
	struct trustix_datapath_state_slot *slot;
};

struct trustix_datapath_session_wire_tuple_cache_entry {
	bool used;
	bool reverse;
	__u8 shard;
	__u8 protocol;
	__u16 src_port;
	__u16 dst_port;
	__u32 src_ipv4;
	__u32 dst_ipv4;
	__u64 flow_id;
	struct trustix_datapath_state_slot *session;
	struct trustix_datapath_state_slot *slot;
};

struct trustix_datapath_rx_stage_slot {
	bool valid;
	__u32 len;
	__u64 id;
	__u64 flow_id;
	__u64 epoch;
	__u64 sequence;
	__u32 payload_len;
	__u32 tixt_flags;
	__u64 session_flags;
	__u32 outer_src_ipv4;
	__u32 outer_dst_ipv4;
	__u16 outer_src_port;
	__u16 outer_dst_port;
	__u8 outer_protocol;
	__u8 inner_protocol;
	__u32 inner_src_ipv4;
	__u32 inner_dst_ipv4;
	__u16 inner_src_port;
	__u16 inner_dst_port;
	__u8 inner_ip_header_len;
	__u8 inner_l4_header_len;
};

struct trustix_datapath_rx_worker_slot {
	bool valid;
	__u32 len;
	__u32 inner_offset;
	__u8 tixt_flags;
	unsigned int frames;
	int ifindex;
	int target_ifindex;
	struct net_device *target_dev;
	__u8 *packet;
	struct sk_buff *skb;
	bool skb_l2_ready;
	bool stolen_skb;
};

struct trustix_datapath_inner_gso_reassembly_key {
	const struct net *net;
	__u32 src_ipv4;
	__u32 dst_ipv4;
	__u16 src_port;
	__u16 dst_port;
	int ifindex;
	int target_ifindex;
};

struct trustix_datapath_inner_gso_reassembly_range {
	__u32 start;
	__u32 end;
};

struct trustix_datapath_inner_gso_reassembly_slot {
	bool active;
	__u64 flow_id;
	__u64 epoch;
	struct trustix_datapath_inner_gso_reassembly_key key;
	__u32 start_seq;
	__u32 next_seq;
	__u32 wire_len;
	__u32 buffered_len;
	__u32 received_len;
	__u16 range_count;
	unsigned long expires;
	unsigned long stream_last_progress;
	__u8 *data;
	struct trustix_datapath_inner_gso_reassembly_range ranges[
		TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_MAX_RANGES];
};

struct trustix_datapath_inner_gso_probation_slot {
	bool active;
	__u64 flow_id;
	__u64 epoch;
	struct trustix_datapath_inner_gso_reassembly_key key;
	unsigned long first_claim;
	unsigned long last_claim;
	unsigned long last_success;
	unsigned int claims_since_success;
};

struct trustix_datapath_rx_stage_view {
	struct trustix_datapath_tixt_frame frame;
	struct trustix_datapath_ioc_classify inner;
	const __u8 *inner_packet;
	__u32 tixt_len;
	__u32 inner_offset;
	__u8 inner_ip_header_len;
	__u8 inner_l4_header_len;
	bool reverse;
	__u64 session_flow_id;
	__u64 session_flags;
};

/* Scoped to one outer skb; keep this key aligned with validate_locked. */
struct trustix_datapath_rx_validation_cache {
	bool valid;
	bool reverse;
	__u8 header_len;
	__u64 flow_id;
	__u64 epoch;
	__u64 session_flow_id;
	__u64 session_flags;
};

struct trustix_datapath_tx_plan {
	bool secure;
	__u64 flow_id;
	__u64 epoch;
	__u64 session_flags;
	__u64 send_generation;
	__u32 inner_flow_hash;
	__u32 outer_tcp_sequence_flow_slot;
	__u32 send_slot;
	__u32 local_ipv4;
	__u32 remote_ipv4;
	__u16 local_port;
	__u16 remote_port;
	__u16 suite;
	__u16 wire_format;
	__u8 outer_protocol;
	__u8 outer_tcp_port_shard;
	__u8 send_iv[12];
	__u32 max_packet_size;
};

struct trustix_datapath_rx_crypto_plan {
	__u64 flow_id;
	__u64 epoch;
	__u64 session_flags;
	__u64 receive_generation;
	__u64 replay_floor;
	__u32 receive_slot;
	__u32 replay_window;
	__u16 suite;
	__u16 wire_format;
	__u8 receive_iv[12];
};

struct trustix_datapath_secure_rx_scratch {
	struct trustix_aead_direct_open_replay_op
		ops[TRUSTIX_DATAPATH_RX_WORKER_STREAM_MAX_FRAMES];
	__u8 *packet;
};

static struct trustix_datapath_secure_rx_scratch __percpu
	*trustix_datapath_secure_rx_scratch;

static int trustix_datapath_alloc_secure_rx_scratch(void)
{
	struct trustix_datapath_secure_rx_scratch *scratch;
	int cpu;

	trustix_datapath_secure_rx_scratch =
		alloc_percpu(struct trustix_datapath_secure_rx_scratch);
	if (!trustix_datapath_secure_rx_scratch)
		return -ENOMEM;
	for_each_possible_cpu(cpu) {
		scratch = per_cpu_ptr(trustix_datapath_secure_rx_scratch, cpu);
		memset(scratch, 0, sizeof(*scratch));
	}
	for_each_possible_cpu(cpu) {
		scratch = per_cpu_ptr(trustix_datapath_secure_rx_scratch, cpu);
		scratch->packet = kvzalloc(TRUSTIX_DATAPATH_PACKET_MAX_LEN,
					   GFP_KERNEL);
		if (!scratch->packet)
			goto error;
	}
	return 0;

error:
	for_each_possible_cpu(cpu) {
		scratch = per_cpu_ptr(trustix_datapath_secure_rx_scratch, cpu);
		if (scratch->packet)
			memzero_explicit(scratch->packet,
					 TRUSTIX_DATAPATH_PACKET_MAX_LEN);
		kvfree(scratch->packet);
		memset(scratch, 0, sizeof(*scratch));
	}
	free_percpu(trustix_datapath_secure_rx_scratch);
	trustix_datapath_secure_rx_scratch = NULL;
	return -ENOMEM;
}

static void trustix_datapath_free_secure_rx_scratch(void)
{
	struct trustix_datapath_secure_rx_scratch *scratch;
	int cpu;

	if (!trustix_datapath_secure_rx_scratch)
		return;
	for_each_possible_cpu(cpu) {
		scratch = per_cpu_ptr(trustix_datapath_secure_rx_scratch, cpu);
		if (scratch->packet)
			memzero_explicit(scratch->packet,
					 TRUSTIX_DATAPATH_PACKET_MAX_LEN);
		kvfree(scratch->packet);
		memset(scratch, 0, sizeof(*scratch));
	}
	free_percpu(trustix_datapath_secure_rx_scratch);
	trustix_datapath_secure_rx_scratch = NULL;
}

struct trustix_datapath_tx_plaintext_slot {
	bool valid;
	struct sk_buff *skb;
	struct net_device *target_dev;
	struct trustix_datapath_tx_plan plan;
	__u32 inner_len;
};

struct trustix_datapath_rx_worker_coalesce_state {
	bool active;
	__u32 total_len;
	__u32 payload_len;
	__u32 gso_size;
	__u32 last_payload_len;
	__u32 tcp_header_len;
	__u32 next_seq;
	__u32 ack_seq;
	__be32 saddr;
	__be32 daddr;
	__be16 source;
	__be16 dest;
	__be16 window;
	__be16 urg_ptr;
	__u8 tcp_flags;
	__u8 header[TRUSTIX_DATAPATH_IPV4_L4_PREFIX_MAX];
};

struct trustix_datapath_tx_plaintext_coalesce_slot {
	spinlock_t lock;
	struct delayed_work flush_work;
	bool valid;
	struct net_device *target_dev;
	int target_ifindex;
	__u32 hash;
	struct trustix_datapath_tx_plan plan;
	struct trustix_datapath_rx_worker_coalesce_state state;
	__u8 *packets[TRUSTIX_DATAPATH_TX_PLAINTEXT_COALESCE_MAX_FRAMES];
	__u32 lens[TRUSTIX_DATAPATH_TX_PLAINTEXT_COALESCE_MAX_FRAMES];
	unsigned int frames;
};

struct trustix_datapath_rx_worker_pending_copy {
	__u8 *packet;
	const __u8 *source_packet;
	const struct sk_buff *source_skb;
	struct sk_buff *skb;
	__u32 source_offset;
	__u32 len;
	__u8 tixt_flags;
};

struct trustix_datapath_rx_worker_inline_pair_slot {
	spinlock_t lock;
	struct delayed_work flush_work;
	bool valid;
	bool flush_reuse_blocked;
	struct net_device *target_dev;
	int target_ifindex;
	__u32 hash;
	struct trustix_datapath_rx_worker_coalesce_state state;
	struct sk_buff *skb;
	__u8 *packets[TRUSTIX_DATAPATH_RX_WORKER_INLINE_PAIR_MAX_FRAMES];
	__u32 lens[TRUSTIX_DATAPATH_RX_WORKER_INLINE_PAIR_MAX_FRAMES];
	unsigned int frames;
};

struct trustix_datapath_rx_worker_single_coalesce_slot {
	spinlock_t lock;
	struct delayed_work flush_work;
	bool valid;
	struct net_device *target_dev;
	int target_ifindex;
	__u32 hash;
	struct trustix_datapath_rx_worker_coalesce_state state;
	__u8 *packets[TRUSTIX_DATAPATH_RX_WORKER_SINGLE_COALESCE_MAX_FRAMES];
	__u32 lens[TRUSTIX_DATAPATH_RX_WORKER_SINGLE_COALESCE_MAX_FRAMES];
	__u8 tixt_flags[TRUSTIX_DATAPATH_RX_WORKER_SINGLE_COALESCE_MAX_FRAMES];
	unsigned int frames;
};

static void
trustix_datapath_rx_worker_fix_ipv4_header_checksum(struct iphdr *iph,
						    __u32 ip_header_len);
static __sum16
trustix_datapath_rx_worker_tcp_checksum_append_payload(
	struct tcphdr *tcph, __u32 old_tcp_len, __u32 new_tcp_len,
	const void *payload, __u32 payload_len);
static bool
trustix_datapath_rx_worker_trust_tcp_checksum(struct iphdr *iph,
					      __u32 ip_header_len,
					      __u32 l4_len,
					      struct tcphdr **tcph_out);
static int trustix_datapath_rx_worker_build_xmit_inner_skb(
	struct net_device *target_dev, const __u8 *packet, __u32 len,
	struct sk_buff **inner_skb_out);
static int trustix_datapath_rx_worker_build_xmit_inner_skb_flags(
	struct net_device *target_dev, const __u8 *packet, __u32 len,
	__u8 tixt_flags, struct sk_buff **inner_skb_out);
static bool trustix_datapath_rx_worker_build_xmit_inner_skb_hold(
	struct net_device *target_dev, const __u8 *packet, __u32 len,
	__u32 extra_tailroom, struct sk_buff **inner_skb_out);
static int trustix_datapath_rx_worker_inline_pair_xmit_skb_frames(
	struct net_device *target_dev, struct sk_buff *skb,
	bool inline_context, unsigned int frames);
static int trustix_datapath_rx_worker_xmit_inner_gso_segments(
	struct sk_buff *skb, struct net_device *dev);
static int trustix_datapath_rx_worker_xmit_inner_gso(
	struct sk_buff *skb, struct net_device *dev, bool xmit_more);
static bool trustix_datapath_rx_worker_dev_ready(struct net_device *dev);
static int trustix_datapath_rx_worker_enqueue_pending_skb(
	struct sk_buff *source_skb, struct net_device *target_dev,
	struct sk_buff *inner_skb, __u32 len, unsigned int frames,
	bool skb_l2_ready, unsigned int *queued_frames);
static bool trustix_datapath_ipv4_prefix_match(__u32 addr, __u32 prefix,
					       __u32 bits);
static struct trustix_datapath_state_slot *
trustix_datapath_session_for_flow_id_locked(__u64 flow_id);
static int trustix_datapath_rx_worker_queue_l2_skb_from_hook(
	struct sk_buff *source_skb, struct net_device *target_dev,
	struct sk_buff **inner_skb, __u32 len, unsigned int frames,
	unsigned int *queued_frames);
static int trustix_datapath_rx_worker_prepare_l2_gso_skb(
	struct sk_buff *skb, struct net_device *target_dev);
static __always_inline __u64
trustix_datapath_rx_worker_mac_to_u64(const __u8 *addr);
static __always_inline void
trustix_datapath_rx_worker_u64_to_mac(__u64 value, __u8 *addr);
static int trustix_datapath_rx_worker_inline_pair_append_held_skb(
	struct sk_buff *skb, struct net_device *target_dev,
	const struct trustix_datapath_rx_worker_coalesce_state *state,
	const __u8 *packet, __u32 len);
static void trustix_datapath_rx_worker_inline_pair_flush_work(
	struct work_struct *work);
static void trustix_datapath_rx_worker_inline_pair_drop_all(void);
static void trustix_datapath_rx_worker_single_coalesce_flush_work(
	struct work_struct *work);
static void trustix_datapath_rx_worker_single_coalesce_drop_all(void);
static void trustix_datapath_rx_worker_drop_pending_sync(void);
static void trustix_datapath_tx_plaintext_drop_pending_sync(void);
static void trustix_datapath_release_netdev_refs(struct net_device *dev);
static void trustix_datapath_tx_plaintext_run(struct work_struct *work);
static void trustix_datapath_tx_plaintext_coalesce_flush_work(
	struct work_struct *work);
static void trustix_datapath_tx_plaintext_coalesce_drop_all(void);
static int
trustix_datapath_tx_send_outer_skb(struct sk_buff *skb,
				   struct net_device *target_dev,
				   const struct trustix_datapath_tx_plan *plan);
static void
trustix_datapath_tx_plaintext_set_hash_tx_queue(
	struct sk_buff *skb, const struct net_device *dev,
	const struct trustix_datapath_tx_plan *plan);

#define TRUSTIX_DATAPATH_IOC_QUERY \
	_IOWR(TRUSTIX_DATAPATH_IOC_MAGIC, 12, struct trustix_datapath_ioc_query)

#define TRUSTIX_DATAPATH_IOC_SELFTEST \
	_IOWR(TRUSTIX_DATAPATH_IOC_MAGIC, 13, struct trustix_datapath_ioc_selftest)

#define TRUSTIX_DATAPATH_IOC_STATE \
	_IOWR(TRUSTIX_DATAPATH_IOC_MAGIC, 14, struct trustix_datapath_ioc_state)

#define TRUSTIX_DATAPATH_IOC_STATE_STATS \
	_IOWR(TRUSTIX_DATAPATH_IOC_MAGIC, 15, struct trustix_datapath_ioc_state_stats)

#define TRUSTIX_DATAPATH_IOC_STATE_BATCH \
	_IOWR(TRUSTIX_DATAPATH_IOC_MAGIC, 16, struct trustix_datapath_ioc_state_batch)

#define TRUSTIX_DATAPATH_IOC_CLASSIFY \
	_IOWR(TRUSTIX_DATAPATH_IOC_MAGIC, 17, struct trustix_datapath_ioc_classify)

#define TRUSTIX_DATAPATH_IOC_PACKET_CLASSIFY \
	_IOWR(TRUSTIX_DATAPATH_IOC_MAGIC, 18, struct trustix_datapath_ioc_packet_classify)

#define TRUSTIX_DATAPATH_IOC_PACKET_STATS \
	_IOWR(TRUSTIX_DATAPATH_IOC_MAGIC, 19, struct trustix_datapath_ioc_packet_stats)

#define TRUSTIX_DATAPATH_IOC_HOOK \
	_IOWR(TRUSTIX_DATAPATH_IOC_MAGIC, 20, struct trustix_datapath_ioc_hook)

#define TRUSTIX_DATAPATH_IOC_TIXT_ENCAP \
	_IOWR(TRUSTIX_DATAPATH_IOC_MAGIC, 21, struct trustix_datapath_ioc_tixt_encap)

#define TRUSTIX_DATAPATH_IOC_TIXT_DECAP \
	_IOWR(TRUSTIX_DATAPATH_IOC_MAGIC, 22, struct trustix_datapath_ioc_tixt_decap)

#define TRUSTIX_DATAPATH_IOC_OUTER_BUILD \
	_IOWR(TRUSTIX_DATAPATH_IOC_MAGIC, 23, struct trustix_datapath_ioc_outer_build)

#define TRUSTIX_DATAPATH_IOC_OUTER_PARSE \
	_IOWR(TRUSTIX_DATAPATH_IOC_MAGIC, 24, struct trustix_datapath_ioc_outer_parse)

#define TRUSTIX_DATAPATH_IOC_RX_STAGE \
	_IOWR(TRUSTIX_DATAPATH_IOC_MAGIC, 25, struct trustix_datapath_ioc_rx_stage)

static unsigned long long trustix_datapath_enable_features;
module_param_named(enable_features, trustix_datapath_enable_features, ullong,
		   0444);
MODULE_PARM_DESC(enable_features,
		 "TrustIX datapath feature bitmask requested at load time; unsafe or selftest-failed bits stay inactive");

static unsigned long long trustix_datapath_features;
module_param_named(features, trustix_datapath_features, ullong, 0444);
MODULE_PARM_DESC(features, "TrustIX datapath active safe feature bitmask");

static unsigned long long trustix_datapath_safe_features;
module_param_named(safe_features, trustix_datapath_safe_features, ullong, 0444);
MODULE_PARM_DESC(safe_features, "TrustIX datapath active safe feature bitmask");

static unsigned long long trustix_datapath_unsafe_features;
module_param_named(unsafe_features, trustix_datapath_unsafe_features, ullong,
		   0444);
MODULE_PARM_DESC(unsafe_features,
		 "TrustIX datapath feature bits known by the module but not safe to use");

enum trustix_datapath_inner_gso_runtime_event {
	TRUSTIX_DATAPATH_INNER_GSO_EVENT_FRAME_FAULT,
	TRUSTIX_DATAPATH_INNER_GSO_EVENT_REASSEMBLY_TIMEOUT,
	TRUSTIX_DATAPATH_INNER_GSO_EVENT_PROBATION_NO_PROGRESS,
};

static DEFINE_SPINLOCK(trustix_datapath_inner_gso_circuit_lock);
static bool trustix_datapath_inner_gso_circuit_open;
static bool trustix_datapath_inner_gso_circuit_recovering;
static unsigned long trustix_datapath_inner_gso_circuit_until;
static unsigned long trustix_datapath_inner_gso_fault_window_start;
static unsigned long trustix_datapath_inner_gso_timeout_window_start;
static unsigned long trustix_datapath_inner_gso_last_recovery;
static unsigned int trustix_datapath_inner_gso_fault_window_count;
static unsigned int trustix_datapath_inner_gso_timeout_window_count;
static unsigned int trustix_datapath_inner_gso_timeout_success_credit;
static unsigned int trustix_datapath_inner_gso_timeout_last_ratio_ppm;
static unsigned int trustix_datapath_inner_gso_backoff_level;
static unsigned int trustix_datapath_inner_gso_last_cooldown_ms;
static unsigned int trustix_datapath_inner_gso_fault_threshold =
	TRUSTIX_DATAPATH_INNER_GSO_FAULT_THRESHOLD_DEFAULT;
static unsigned int trustix_datapath_inner_gso_fault_window_ms =
	TRUSTIX_DATAPATH_INNER_GSO_FAULT_WINDOW_MS_DEFAULT;
static unsigned int trustix_datapath_inner_gso_timeout_threshold =
	TRUSTIX_DATAPATH_INNER_GSO_TIMEOUT_THRESHOLD_DEFAULT;
static unsigned int trustix_datapath_inner_gso_timeout_ratio_ppm =
	TRUSTIX_DATAPATH_INNER_GSO_TIMEOUT_RATIO_PPM_DEFAULT;
static unsigned int trustix_datapath_inner_gso_timeout_window_ms =
	TRUSTIX_DATAPATH_INNER_GSO_TIMEOUT_WINDOW_MS_DEFAULT;
static unsigned int trustix_datapath_inner_gso_reassembly_timeout_ms =
	TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_TIMEOUT_MS_DEFAULT;
static unsigned int trustix_datapath_inner_gso_no_progress_ms =
	TRUSTIX_DATAPATH_INNER_GSO_NO_PROGRESS_MS_DEFAULT;
static unsigned int trustix_datapath_inner_gso_cooldown_ms =
	TRUSTIX_DATAPATH_INNER_GSO_COOLDOWN_MS_DEFAULT;
static unsigned int trustix_datapath_inner_gso_max_cooldown_ms =
	TRUSTIX_DATAPATH_INNER_GSO_MAX_COOLDOWN_MS_DEFAULT;
static unsigned int trustix_datapath_inner_gso_stable_ms =
	TRUSTIX_DATAPATH_INNER_GSO_STABLE_MS_DEFAULT;
static bool trustix_datapath_inner_gso_auto_recover;
static unsigned long long trustix_datapath_inner_gso_runtime_faults;
static unsigned long long trustix_datapath_inner_gso_circuit_trips;
static unsigned long long trustix_datapath_inner_gso_timeout_circuit_trips;
static unsigned long long
	trustix_datapath_inner_gso_timeout_ratio_suppressions;
static unsigned long long
	trustix_datapath_inner_gso_no_progress_circuit_trips;
static unsigned long long trustix_datapath_inner_gso_circuit_recoveries;
static unsigned long long trustix_datapath_inner_gso_probation_arms;
static unsigned long long trustix_datapath_inner_gso_probation_claims;
static unsigned long long trustix_datapath_inner_gso_probation_successes;
static unsigned long long trustix_datapath_inner_gso_probation_failures;
static unsigned long long trustix_datapath_inner_gso_probation_idle_resets;
static unsigned long long trustix_datapath_inner_gso_probation_evictions;
static unsigned long long trustix_datapath_inner_gso_probation_collisions;
static unsigned int trustix_datapath_inner_gso_last_no_progress_ms;
static void trustix_datapath_clear_inner_gso_reassembly(void);
static void trustix_datapath_sweep_inner_gso_reassembly(void);
static void trustix_datapath_clear_inner_gso_probation_matching(
	bool all, __u64 flow_id, __u64 epoch);
static void trustix_datapath_inner_gso_probation_record_claim(
	const struct sk_buff *skb,
	const struct trustix_datapath_ioc_classify *outer,
	int target_ifindex, __u64 flow_id, __u64 epoch);
static void trustix_datapath_inner_gso_probation_record_success(
	const struct sk_buff *skb,
	const struct trustix_datapath_ioc_classify *outer,
	int target_ifindex, const struct trustix_datapath_tixt_frame *frame);

static __always_inline bool
trustix_datapath_inner_gso_runtime_permitted(void)
{
	if (smp_load_acquire(&trustix_datapath_inner_gso_circuit_open))
		return false;
	return !READ_ONCE(trustix_datapath_inner_gso_circuit_recovering);
}

static unsigned int
trustix_datapath_inner_gso_bounded_ms(unsigned int value,
				      unsigned int fallback)
{
	if (!value)
		value = fallback;
	return min_t(unsigned int, value, 3600000U);
}

static unsigned int
trustix_datapath_inner_gso_timeout_success_credit_cap(
	unsigned int threshold, unsigned int ratio_ppm)
{
	__u64 cap;

	ratio_ppm = min_t(unsigned int, ratio_ppm,
			  TRUSTIX_DATAPATH_INNER_GSO_RATIO_PPM_SCALE);
	if (!ratio_ppm)
		return 0;
	threshold = max_t(unsigned int, threshold, 1U);
	cap = div_u64((__u64)threshold *
			  TRUSTIX_DATAPATH_INNER_GSO_RATIO_PPM_SCALE,
			  ratio_ppm);
	return min_t(__u64, cap, UINT_MAX);
}

static bool trustix_datapath_inner_gso_timeout_ratio_trips(
	unsigned int failures, unsigned int successes,
	unsigned int ratio_ppm, unsigned int *observed_ppm)
{
	__u64 total = (__u64)failures + successes;
	unsigned int observed = failures && total ?
		min_t(__u64,
		      div64_u64((__u64)failures *
				TRUSTIX_DATAPATH_INNER_GSO_RATIO_PPM_SCALE,
				total),
		      TRUSTIX_DATAPATH_INNER_GSO_RATIO_PPM_SCALE) : 0;

	if (observed_ppm)
		*observed_ppm = observed;
	ratio_ppm = min_t(unsigned int, ratio_ppm,
			  TRUSTIX_DATAPATH_INNER_GSO_RATIO_PPM_SCALE);
	/* A zero ratio restores the legacy absolute-timeout threshold. */
	return !ratio_ppm || observed >= ratio_ppm;
}

static void trustix_datapath_inner_gso_record_reassembly_success(void)
{
	unsigned int cap;
	unsigned long flags;

	spin_lock_irqsave(&trustix_datapath_inner_gso_circuit_lock, flags);
	if (trustix_datapath_inner_gso_circuit_open)
		goto out;
	cap = trustix_datapath_inner_gso_timeout_success_credit_cap(
		READ_ONCE(trustix_datapath_inner_gso_timeout_threshold),
		READ_ONCE(trustix_datapath_inner_gso_timeout_ratio_ppm));
	if (trustix_datapath_inner_gso_timeout_success_credit < cap)
		trustix_datapath_inner_gso_timeout_success_credit++;
out:
	spin_unlock_irqrestore(&trustix_datapath_inner_gso_circuit_lock, flags);
}

static unsigned long trustix_datapath_inner_gso_reassembly_deadline(void)
{
	unsigned int timeout_ms = trustix_datapath_inner_gso_bounded_ms(
		READ_ONCE(trustix_datapath_inner_gso_reassembly_timeout_ms),
		TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_TIMEOUT_MS_DEFAULT);

	return jiffies + max_t(unsigned long, 1,
			       msecs_to_jiffies(timeout_ms));
}

static bool trustix_datapath_inner_gso_runtime_ready_now(void)
{
	unsigned long flags;
	bool recover = false;
	bool ready;

	if (likely(trustix_datapath_inner_gso_runtime_permitted())) {
		/* A stalled stream may have no later packet to reclaim its slot. */
		trustix_datapath_sweep_inner_gso_reassembly();
		if (likely(trustix_datapath_inner_gso_runtime_permitted()))
			return true;
	}
	spin_lock_irqsave(&trustix_datapath_inner_gso_circuit_lock, flags);
	if (READ_ONCE(trustix_datapath_inner_gso_auto_recover) &&
	    trustix_datapath_inner_gso_circuit_open &&
	    !trustix_datapath_inner_gso_circuit_recovering &&
	    time_after_eq(jiffies, trustix_datapath_inner_gso_circuit_until)) {
		trustix_datapath_inner_gso_circuit_recovering = true;
		recover = true;
	}
	ready = !trustix_datapath_inner_gso_circuit_open &&
		!trustix_datapath_inner_gso_circuit_recovering;
	spin_unlock_irqrestore(&trustix_datapath_inner_gso_circuit_lock, flags);
	if (!recover)
		return ready;

	/* Keep the circuit closed until every stale slot is gone. */
	trustix_datapath_clear_inner_gso_reassembly();
	spin_lock_irqsave(&trustix_datapath_inner_gso_circuit_lock, flags);
	if (trustix_datapath_inner_gso_circuit_open &&
	    trustix_datapath_inner_gso_circuit_recovering) {
		trustix_datapath_inner_gso_fault_window_start = jiffies;
		trustix_datapath_inner_gso_fault_window_count = 0;
		trustix_datapath_inner_gso_timeout_window_start = jiffies;
		trustix_datapath_inner_gso_timeout_window_count = 0;
		trustix_datapath_inner_gso_timeout_success_credit = 0;
		trustix_datapath_inner_gso_last_recovery = jiffies;
		trustix_datapath_inner_gso_circuit_recoveries++;
		trustix_datapath_inner_gso_circuit_recovering = false;
		smp_store_release(&trustix_datapath_inner_gso_circuit_open,
				  false);
	}
	ready = !trustix_datapath_inner_gso_circuit_open &&
		!trustix_datapath_inner_gso_circuit_recovering;
	spin_unlock_irqrestore(&trustix_datapath_inner_gso_circuit_lock, flags);
	return ready;
}

static void
trustix_datapath_inner_gso_record_runtime_event(
	enum trustix_datapath_inner_gso_runtime_event event,
	unsigned long stream_last_progress)
{
	unsigned int base_ms;
	unsigned int cooldown_ms;
	unsigned int max_ms;
	unsigned int stable_ms;
	unsigned int threshold;
	unsigned int timeout_ratio_ppm;
	unsigned int observed_timeout_ratio_ppm = 0;
	unsigned int window_ms;
	unsigned int level;
	unsigned int *window_count;
	unsigned long *window_start;
	unsigned long flags;
	unsigned long now = jiffies;
	bool no_progress_trip = false;

	if (event == TRUSTIX_DATAPATH_INNER_GSO_EVENT_REASSEMBLY_TIMEOUT) {
		threshold = max_t(unsigned int, 1,
			READ_ONCE(trustix_datapath_inner_gso_timeout_threshold));
		window_ms = trustix_datapath_inner_gso_bounded_ms(
			READ_ONCE(trustix_datapath_inner_gso_timeout_window_ms),
			TRUSTIX_DATAPATH_INNER_GSO_TIMEOUT_WINDOW_MS_DEFAULT);
	} else {
		threshold = max_t(unsigned int, 1,
			READ_ONCE(trustix_datapath_inner_gso_fault_threshold));
		window_ms = trustix_datapath_inner_gso_bounded_ms(
			READ_ONCE(trustix_datapath_inner_gso_fault_window_ms),
			TRUSTIX_DATAPATH_INNER_GSO_FAULT_WINDOW_MS_DEFAULT);
	}
	base_ms = trustix_datapath_inner_gso_bounded_ms(
		READ_ONCE(trustix_datapath_inner_gso_cooldown_ms),
		TRUSTIX_DATAPATH_INNER_GSO_COOLDOWN_MS_DEFAULT);
	max_ms = trustix_datapath_inner_gso_bounded_ms(
		READ_ONCE(trustix_datapath_inner_gso_max_cooldown_ms),
		TRUSTIX_DATAPATH_INNER_GSO_MAX_COOLDOWN_MS_DEFAULT);
	max_ms = max(max_ms, base_ms);
	stable_ms = trustix_datapath_inner_gso_bounded_ms(
		READ_ONCE(trustix_datapath_inner_gso_stable_ms),
		TRUSTIX_DATAPATH_INNER_GSO_STABLE_MS_DEFAULT);
	if (event == TRUSTIX_DATAPATH_INNER_GSO_EVENT_PROBATION_NO_PROGRESS)
		no_progress_trip = true;

	spin_lock_irqsave(&trustix_datapath_inner_gso_circuit_lock, flags);
	trustix_datapath_inner_gso_runtime_faults++;
	if (trustix_datapath_inner_gso_circuit_open)
		goto out;
	if (event == TRUSTIX_DATAPATH_INNER_GSO_EVENT_REASSEMBLY_TIMEOUT) {
		window_start = &trustix_datapath_inner_gso_timeout_window_start;
		window_count = &trustix_datapath_inner_gso_timeout_window_count;
	} else {
		window_start = &trustix_datapath_inner_gso_fault_window_start;
		window_count = &trustix_datapath_inner_gso_fault_window_count;
	}
	if (!*window_start ||
	    time_after(now, *window_start + msecs_to_jiffies(window_ms))) {
		*window_start = now;
		*window_count = 0;
	}
	(*window_count)++;
	if (!no_progress_trip && *window_count < threshold)
		goto out;
	if (event == TRUSTIX_DATAPATH_INNER_GSO_EVENT_REASSEMBLY_TIMEOUT) {
		timeout_ratio_ppm = READ_ONCE(
			trustix_datapath_inner_gso_timeout_ratio_ppm);
		if (!trustix_datapath_inner_gso_timeout_ratio_trips(
			    *window_count,
			    trustix_datapath_inner_gso_timeout_success_credit,
			    timeout_ratio_ppm,
			    &observed_timeout_ratio_ppm)) {
			trustix_datapath_inner_gso_timeout_last_ratio_ppm =
				observed_timeout_ratio_ppm;
			trustix_datapath_inner_gso_timeout_ratio_suppressions++;
			*window_start = now;
			*window_count = 0;
			trustix_datapath_inner_gso_timeout_success_credit = 0;
			goto out;
		}
		trustix_datapath_inner_gso_timeout_last_ratio_ppm =
			observed_timeout_ratio_ppm;
	}

	if (trustix_datapath_inner_gso_last_recovery &&
	    time_before(now, trustix_datapath_inner_gso_last_recovery +
			msecs_to_jiffies(stable_ms)))
		trustix_datapath_inner_gso_backoff_level = min_t(
			unsigned int,
			trustix_datapath_inner_gso_backoff_level + 1, 16U);
	else
		trustix_datapath_inner_gso_backoff_level = 0;

	cooldown_ms = base_ms;
	level = trustix_datapath_inner_gso_backoff_level;
	while (level-- && cooldown_ms < max_ms)
		cooldown_ms = min(max_ms, cooldown_ms * 2U);
	trustix_datapath_inner_gso_last_cooldown_ms = cooldown_ms;
	trustix_datapath_inner_gso_circuit_until =
		now + msecs_to_jiffies(cooldown_ms);
	trustix_datapath_inner_gso_circuit_open = true;
	trustix_datapath_inner_gso_circuit_trips++;
	if (event == TRUSTIX_DATAPATH_INNER_GSO_EVENT_REASSEMBLY_TIMEOUT)
		trustix_datapath_inner_gso_timeout_circuit_trips++;
	if (event == TRUSTIX_DATAPATH_INNER_GSO_EVENT_PROBATION_NO_PROGRESS)
		trustix_datapath_inner_gso_probation_failures++;
	if (no_progress_trip) {
		trustix_datapath_inner_gso_no_progress_circuit_trips++;
		trustix_datapath_inner_gso_last_no_progress_ms =
			min_t(unsigned long, UINT_MAX,
			      jiffies_to_msecs(now - stream_last_progress));
	}
out:
	spin_unlock_irqrestore(&trustix_datapath_inner_gso_circuit_lock, flags);
}

static void trustix_datapath_inner_gso_record_runtime_fault(void)
{
	trustix_datapath_inner_gso_record_runtime_event(
		TRUSTIX_DATAPATH_INNER_GSO_EVENT_FRAME_FAULT, 0);
}

static void trustix_datapath_inner_gso_record_reassembly_timeout(
	unsigned long stream_last_progress)
{
	trustix_datapath_inner_gso_record_runtime_event(
		TRUSTIX_DATAPATH_INNER_GSO_EVENT_REASSEMBLY_TIMEOUT,
		stream_last_progress);
}

static void trustix_datapath_inner_gso_record_probation_no_progress(
	unsigned long first_claim)
{
	trustix_datapath_inner_gso_record_runtime_event(
		TRUSTIX_DATAPATH_INNER_GSO_EVENT_PROBATION_NO_PROGRESS,
		first_claim);
}

static bool trustix_datapath_inner_gso_error_trips_circuit(int ret)
{
	switch (ret) {
	case 0:
	case -ETIMEDOUT:
		/* Slot expiration is accounted exactly once by reassembly. */
	case -ENOENT:
	case -EILSEQ:
		/* Continuations after one missing frame are secondary symptoms. */
	case -EAGAIN:
		/* The runtime circuit deliberately rejected this packet. */
		return false;
	default:
		return true;
	}
}

static int trustix_datapath_param_get_inner_gso_runtime_ready(
	char *buffer, const struct kernel_param *kp)
{
	struct kernel_param local = *kp;
	bool ready = trustix_datapath_inner_gso_runtime_ready_now();

	local.arg = &ready;
	return param_get_bool(buffer, &local);
}

static const struct kernel_param_ops
	trustix_datapath_inner_gso_runtime_ready_ops = {
		.get = trustix_datapath_param_get_inner_gso_runtime_ready,
	};

module_param_cb(inner_gso_runtime_ready,
		&trustix_datapath_inner_gso_runtime_ready_ops,
		&trustix_datapath_inner_gso_circuit_open, 0444);
MODULE_PARM_DESC(inner_gso_runtime_ready,
		 "Whether the inner-GSO receive circuit permits capability advertisement");
module_param_named(inner_gso_auto_recover,
		   trustix_datapath_inner_gso_auto_recover, bool, 0644);
MODULE_PARM_DESC(inner_gso_auto_recover,
		 "Automatically rearm inner-GSO after cooldown; disabled by default so a runtime fault stays on the reliable fallback until module reload or explicit opt-in");
module_param_named(inner_gso_fault_threshold,
		   trustix_datapath_inner_gso_fault_threshold, uint, 0644);
MODULE_PARM_DESC(inner_gso_fault_threshold,
		 "Inner-GSO failed frame or continuation events required to open the runtime circuit");
module_param_named(inner_gso_fault_window_ms,
		   trustix_datapath_inner_gso_fault_window_ms, uint, 0644);
MODULE_PARM_DESC(inner_gso_fault_window_ms,
		 "Inner-GSO runtime circuit fault counting window in milliseconds");
module_param_named(inner_gso_timeout_threshold,
		   trustix_datapath_inner_gso_timeout_threshold, uint, 0644);
MODULE_PARM_DESC(inner_gso_timeout_threshold,
		 "Incomplete inner-GSO frames required within the timeout window to open the runtime circuit");
module_param_named(inner_gso_timeout_ratio_ppm,
		   trustix_datapath_inner_gso_timeout_ratio_ppm, uint, 0644);
MODULE_PARM_DESC(inner_gso_timeout_ratio_ppm,
		 "Minimum incomplete partial-frame ratio in parts per million required to open the runtime circuit");
module_param_named(inner_gso_timeout_window_ms,
		   trustix_datapath_inner_gso_timeout_window_ms, uint, 0644);
MODULE_PARM_DESC(inner_gso_timeout_window_ms,
		 "Inner-GSO burst and sustained incomplete-frame circuit window in milliseconds");
module_param_named(inner_gso_reassembly_timeout_ms,
		   trustix_datapath_inner_gso_reassembly_timeout_ms, uint, 0644);
MODULE_PARM_DESC(inner_gso_reassembly_timeout_ms,
		 "Inner-GSO partial-frame reassembly timeout in milliseconds");
module_param_named(inner_gso_no_progress_ms,
		   trustix_datapath_inner_gso_no_progress_ms, uint, 0644);
MODULE_PARM_DESC(inner_gso_no_progress_ms,
		 "Claimed inner-GSO continuation activity without successful delivery required to open the runtime circuit");
module_param_named(inner_gso_cooldown_ms,
		   trustix_datapath_inner_gso_cooldown_ms, uint, 0644);
MODULE_PARM_DESC(inner_gso_cooldown_ms,
		 "Inner-GSO runtime circuit base cooldown in milliseconds");
module_param_named(inner_gso_max_cooldown_ms,
		   trustix_datapath_inner_gso_max_cooldown_ms, uint, 0644);
MODULE_PARM_DESC(inner_gso_max_cooldown_ms,
		 "Inner-GSO runtime circuit maximum backoff cooldown in milliseconds");
module_param_named(inner_gso_stable_ms,
		   trustix_datapath_inner_gso_stable_ms, uint, 0644);
MODULE_PARM_DESC(inner_gso_stable_ms,
		 "Inner-GSO healthy interval that resets runtime circuit backoff");
module_param_named(inner_gso_runtime_faults,
		   trustix_datapath_inner_gso_runtime_faults, ullong, 0444);
MODULE_PARM_DESC(inner_gso_runtime_faults,
		 "Inner-GSO failed frame and continuation events observed at runtime");
module_param_named(inner_gso_circuit_trips,
		   trustix_datapath_inner_gso_circuit_trips, ullong, 0444);
MODULE_PARM_DESC(inner_gso_circuit_trips,
		 "Inner-GSO runtime circuit open events");
module_param_named(inner_gso_timeout_circuit_trips,
		   trustix_datapath_inner_gso_timeout_circuit_trips, ullong, 0444);
MODULE_PARM_DESC(inner_gso_timeout_circuit_trips,
		 "Inner-GSO runtime circuit opens caused by concentrated incomplete frames");
module_param_named(inner_gso_timeout_success_credit,
		   trustix_datapath_inner_gso_timeout_success_credit, uint, 0444);
MODULE_PARM_DESC(inner_gso_timeout_success_credit,
		 "Bounded successful partial-frame credit in the current timeout observation window");
module_param_named(inner_gso_timeout_last_ratio_ppm,
		   trustix_datapath_inner_gso_timeout_last_ratio_ppm, uint, 0444);
MODULE_PARM_DESC(inner_gso_timeout_last_ratio_ppm,
		 "Incomplete partial-frame ratio observed at the most recent timeout threshold evaluation");
module_param_named(inner_gso_timeout_ratio_suppressions,
		   trustix_datapath_inner_gso_timeout_ratio_suppressions,
		   ullong, 0444);
MODULE_PARM_DESC(inner_gso_timeout_ratio_suppressions,
		 "Timeout threshold evaluations retained on inner-GSO because the incomplete-frame ratio remained healthy");
module_param_named(inner_gso_no_progress_circuit_trips,
		   trustix_datapath_inner_gso_no_progress_circuit_trips,
		   ullong, 0444);
MODULE_PARM_DESC(inner_gso_no_progress_circuit_trips,
		 "Inner-GSO runtime circuit opens caused by an expired stream with no successful frame progress");
module_param_named(inner_gso_circuit_recoveries,
		   trustix_datapath_inner_gso_circuit_recoveries, ullong, 0444);
MODULE_PARM_DESC(inner_gso_circuit_recoveries,
		 "Inner-GSO runtime circuit cooldown recoveries");
module_param_named(inner_gso_probation_arms,
		   trustix_datapath_inner_gso_probation_arms, ullong, 0444);
MODULE_PARM_DESC(inner_gso_probation_arms,
		 "Inner-GSO continuation liveness observation windows started");
module_param_named(inner_gso_probation_claims,
		   trustix_datapath_inner_gso_probation_claims, ullong, 0444);
MODULE_PARM_DESC(inner_gso_probation_claims,
		 "Claimed inner-GSO continuation packets observed by liveness probation");
module_param_named(inner_gso_probation_successes,
		   trustix_datapath_inner_gso_probation_successes, ullong, 0444);
MODULE_PARM_DESC(inner_gso_probation_successes,
		 "Successful inner-GSO deliveries that reset liveness probation");
module_param_named(inner_gso_probation_failures,
		   trustix_datapath_inner_gso_probation_failures, ullong, 0444);
MODULE_PARM_DESC(inner_gso_probation_failures,
		 "Inner-GSO liveness probation windows that reopened the runtime circuit");
module_param_named(inner_gso_probation_idle_resets,
		   trustix_datapath_inner_gso_probation_idle_resets, ullong, 0444);
MODULE_PARM_DESC(inner_gso_probation_idle_resets,
		 "Inner-GSO liveness windows reset after an idle receive interval");
module_param_named(inner_gso_probation_evictions,
		   trustix_datapath_inner_gso_probation_evictions, ullong, 0444);
MODULE_PARM_DESC(inner_gso_probation_evictions,
		 "Stale inner-GSO liveness slots recycled for a new tuple");
module_param_named(inner_gso_probation_collisions,
		   trustix_datapath_inner_gso_probation_collisions, ullong, 0444);
MODULE_PARM_DESC(inner_gso_probation_collisions,
		 "Inner-GSO liveness observations skipped because a bounded set was full");
module_param_named(inner_gso_last_no_progress_ms,
		   trustix_datapath_inner_gso_last_no_progress_ms, uint, 0444);
MODULE_PARM_DESC(inner_gso_last_no_progress_ms,
		 "Observed stream inactivity for the most recent no-progress circuit open");
module_param_named(inner_gso_backoff_level,
		   trustix_datapath_inner_gso_backoff_level, uint, 0444);
MODULE_PARM_DESC(inner_gso_backoff_level,
		 "Inner-GSO runtime circuit current cooldown backoff level");
module_param_named(inner_gso_last_cooldown_ms,
		   trustix_datapath_inner_gso_last_cooldown_ms, uint, 0444);
MODULE_PARM_DESC(inner_gso_last_cooldown_ms,
		 "Inner-GSO runtime circuit most recent cooldown in milliseconds");

static unsigned long long trustix_datapath_selftests;
module_param_named(selftests, trustix_datapath_selftests, ullong, 0444);
MODULE_PARM_DESC(selftests, "TrustIX datapath selftest bitmask that passed");

static unsigned long long trustix_datapath_selftest_failures;
module_param_named(selftest_failures, trustix_datapath_selftest_failures, ullong,
		   0444);
MODULE_PARM_DESC(selftest_failures,
		 "TrustIX datapath selftest bitmask that failed");

static unsigned int trustix_datapath_flags;
module_param_named(flags, trustix_datapath_flags, uint, 0444);
MODULE_PARM_DESC(flags, "TrustIX datapath active status flags");

static unsigned int trustix_datapath_abi_version =
	TRUSTIX_DATAPATH_ABI_VERSION;
module_param_named(abi_version, trustix_datapath_abi_version, uint, 0444);
MODULE_PARM_DESC(abi_version, "TrustIX datapath module ABI version");

static char *trustix_datapath_build_sha256 = "";
module_param_named(build_sha256, trustix_datapath_build_sha256, charp, 0444);
MODULE_PARM_DESC(build_sha256,
		 "SHA256 fingerprint of the TrustIX .ko payload passed by trustixd at load time");

static unsigned int trustix_datapath_max_routes =
	TRUSTIX_DATAPATH_STATE_DEFAULT_ROUTES;
module_param_named(max_routes, trustix_datapath_max_routes, uint, 0444);
MODULE_PARM_DESC(max_routes, "Maximum route records in the TrustIX datapath state table");

static unsigned int trustix_datapath_max_sessions =
	TRUSTIX_DATAPATH_STATE_DEFAULT_SESSIONS;
module_param_named(max_sessions, trustix_datapath_max_sessions, uint, 0444);
MODULE_PARM_DESC(max_sessions, "Maximum session records in the TrustIX datapath state table");

static unsigned int trustix_datapath_max_flows =
	TRUSTIX_DATAPATH_STATE_DEFAULT_FLOWS;
module_param_named(max_flows, trustix_datapath_max_flows, uint, 0444);
MODULE_PARM_DESC(max_flows, "Maximum flow records in the TrustIX datapath state table");

static unsigned int trustix_datapath_rx_stage_slots =
	TRUSTIX_DATAPATH_RX_STAGE_DEFAULT_SLOTS;
module_param_named(rx_stage_slots, trustix_datapath_rx_stage_slots, uint, 0444);
MODULE_PARM_DESC(rx_stage_slots,
		 "Number of preallocated TrustIX RX staging slots");

static unsigned int trustix_datapath_rx_worker_slots =
	TRUSTIX_DATAPATH_RX_WORKER_DEFAULT_SLOTS;
module_param_named(rx_worker_slots, trustix_datapath_rx_worker_slots, uint,
		   0444);
MODULE_PARM_DESC(rx_worker_slots,
		 "Number of preallocated TrustIX RX worker reinjection slots");

static unsigned int trustix_datapath_rx_worker_budget =
	TRUSTIX_DATAPATH_RX_WORKER_DEFAULT_BUDGET;
module_param_named(rx_worker_budget, trustix_datapath_rx_worker_budget, uint,
		   0644);
MODULE_PARM_DESC(rx_worker_budget,
		 "Maximum TrustIX RX worker packets processed per workqueue callback");

static bool trustix_datapath_rx_worker_param_live;
static unsigned long long
	trustix_datapath_rx_worker_steal_param_safe_fallbacks;
static unsigned long long
	trustix_datapath_rx_worker_unsafe_param_safe_fallbacks;

static void trustix_datapath_rx_worker_quiesce_for_param(void)
{
	if (READ_ONCE(trustix_datapath_rx_worker_param_live))
		trustix_datapath_rx_worker_drop_pending_sync();
}

static int trustix_datapath_rx_worker_param_set_bool(
	const char *val, const struct kernel_param *kp)
{
	int ret;

	trustix_datapath_rx_worker_quiesce_for_param();
	ret = param_set_bool(val, kp);
	if (!ret)
		trustix_datapath_rx_worker_quiesce_for_param();
	return ret;
}

static int trustix_datapath_rx_worker_param_set_uint(
	const char *val, const struct kernel_param *kp)
{
	int ret;

	trustix_datapath_rx_worker_quiesce_for_param();
	ret = param_set_uint(val, kp);
	if (!ret)
		trustix_datapath_rx_worker_quiesce_for_param();
	return ret;
}

static void trustix_datapath_tx_plaintext_quiesce_for_param(void)
{
	if (READ_ONCE(trustix_datapath_rx_worker_param_live))
		trustix_datapath_tx_plaintext_drop_pending_sync();
}

static int trustix_datapath_tx_plaintext_param_set_bool(
	const char *val, const struct kernel_param *kp)
{
	int ret;

	trustix_datapath_tx_plaintext_quiesce_for_param();
	ret = param_set_bool(val, kp);
	if (!ret)
		trustix_datapath_tx_plaintext_quiesce_for_param();
	return ret;
}

static int trustix_datapath_rx_worker_param_set_stolen_noop(
	const char *val, const struct kernel_param *kp)
{
	bool requested = false;
	int ret;

	ret = kstrtobool(val, &requested);
	if (ret)
		return ret;
	trustix_datapath_rx_worker_quiesce_for_param();
	if (requested)
		trustix_datapath_rx_worker_steal_param_safe_fallbacks++;
	if (kp && kp->arg)
		WRITE_ONCE(*(bool *)kp->arg, false);
	trustix_datapath_rx_worker_quiesce_for_param();
	return 0;
}

static int trustix_datapath_rx_worker_param_set_unsafe_bool_noop(
	const char *val, const struct kernel_param *kp)
{
	bool requested = false;
	int ret;

	ret = kstrtobool(val, &requested);
	if (ret)
		return ret;
	trustix_datapath_rx_worker_quiesce_for_param();
	if (requested)
		trustix_datapath_rx_worker_unsafe_param_safe_fallbacks++;
	if (kp && kp->arg)
		WRITE_ONCE(*(bool *)kp->arg, false);
	trustix_datapath_rx_worker_quiesce_for_param();
	return 0;
}

static int trustix_datapath_rx_worker_param_set_unsafe_uint_noop(
	const char *val, const struct kernel_param *kp)
{
	unsigned int requested = 0;
	int ret;

	ret = kstrtouint(val, 0, &requested);
	if (ret)
		return ret;
	trustix_datapath_rx_worker_quiesce_for_param();
	if (requested)
		trustix_datapath_rx_worker_unsafe_param_safe_fallbacks++;
	if (kp && kp->arg)
		WRITE_ONCE(*(unsigned int *)kp->arg, 0);
	trustix_datapath_rx_worker_quiesce_for_param();
	return 0;
}

static const struct kernel_param_ops trustix_datapath_rx_worker_bool_ops = {
	.set = trustix_datapath_rx_worker_param_set_bool,
	.get = param_get_bool,
};

static const struct kernel_param_ops trustix_datapath_tx_plaintext_bool_ops = {
	.set = trustix_datapath_tx_plaintext_param_set_bool,
	.get = param_get_bool,
};

static const struct kernel_param_ops
	trustix_datapath_rx_worker_stolen_noop_bool_ops = {
		.set = trustix_datapath_rx_worker_param_set_stolen_noop,
		.get = param_get_bool,
	};

static const struct kernel_param_ops
	trustix_datapath_rx_worker_unsafe_noop_bool_ops = {
		.set = trustix_datapath_rx_worker_param_set_unsafe_bool_noop,
		.get = param_get_bool,
	};

static const struct kernel_param_ops
	trustix_datapath_rx_worker_unsafe_noop_uint_ops = {
		.set = trustix_datapath_rx_worker_param_set_unsafe_uint_noop,
		.get = param_get_uint,
	};

static const struct kernel_param_ops trustix_datapath_rx_worker_uint_ops = {
	.set = trustix_datapath_rx_worker_param_set_uint,
	.get = param_get_uint,
};

static int trustix_datapath_param_get_percpu_ullong(
	char *buffer, const struct kernel_param *kp)
{
	unsigned long long total = 0;
	unsigned long long __percpu *counter;
	int cpu;

	if (!buffer || !kp || !kp->arg)
		return -EINVAL;
	counter = (unsigned long long __percpu *)kp->arg;
	for_each_possible_cpu(cpu)
		total += READ_ONCE(*per_cpu_ptr(counter, cpu));
	return scnprintf(buffer, PAGE_SIZE, "%llu\n", total);
}

static const struct kernel_param_ops trustix_datapath_percpu_ullong_ro_ops = {
	.get = trustix_datapath_param_get_percpu_ullong,
};

static void trustix_datapath_reset_percpu_ullong(
	unsigned long long __percpu *counter)
{
	int cpu;

	for_each_possible_cpu(cpu)
		WRITE_ONCE(*per_cpu_ptr(counter, cpu), 0);
}

static bool trustix_datapath_rx_worker_inject;
module_param_named(rx_worker_inject, trustix_datapath_rx_worker_inject, bool,
		   0644);
MODULE_PARM_DESC(rx_worker_inject,
		 "Enable experimental TrustIX RX worker netif_rx reinjection");

static bool trustix_datapath_tx_plaintext;
module_param_cb(tx_plaintext, &trustix_datapath_tx_plaintext_bool_ops,
		&trustix_datapath_tx_plaintext, 0644);
MODULE_PARM_DESC(tx_plaintext,
		 "Enable TrustIX plaintext LAN-to-underlay TX ownership");

static bool trustix_datapath_tx_plaintext_inline_xmit;
module_param_named(tx_plaintext_inline_xmit,
		   trustix_datapath_tx_plaintext_inline_xmit, bool, 0644);
MODULE_PARM_DESC(tx_plaintext_inline_xmit,
		 "Send TrustIX plaintext TX outer skbs directly from the hook path instead of queueing a work item");

static bool trustix_datapath_tx_plaintext_direct_xmit = true;
module_param_named(tx_plaintext_direct_xmit,
		   trustix_datapath_tx_plaintext_direct_xmit, bool, 0644);
MODULE_PARM_DESC(tx_plaintext_direct_xmit,
		 "Send plaintext TX outer skbs with a resolved Ethernet header through dev_queue_xmit, falling back to ip_local_out");

static bool trustix_datapath_tx_plaintext_direct_xmit_dst_mac_cache = true;
module_param_named(tx_plaintext_direct_xmit_dst_mac_cache,
		   trustix_datapath_tx_plaintext_direct_xmit_dst_mac_cache,
		   bool, 0644);
MODULE_PARM_DESC(tx_plaintext_direct_xmit_dst_mac_cache,
		 "Cache plaintext TX direct-xmit route/neighbour destination MAC for repeated outer flows");

static bool trustix_datapath_tx_plaintext_hash_tx_queue;
module_param_named(tx_plaintext_hash_tx_queue,
		   trustix_datapath_tx_plaintext_hash_tx_queue, bool, 0644);
MODULE_PARM_DESC(tx_plaintext_hash_tx_queue,
		 "Hash plaintext TX outer skbs across the underlay device TX queues");

static bool trustix_datapath_tx_plaintext_hash_tx_queue_partition_transport;
module_param_named(tx_plaintext_hash_tx_queue_partition_transport,
		   trustix_datapath_tx_plaintext_hash_tx_queue_partition_transport,
		   bool, 0644);
MODULE_PARM_DESC(tx_plaintext_hash_tx_queue_partition_transport,
		 "Reserve even plaintext TX queues for UDP by restricting TIX-TCP to odd queues when both transports are active");

static bool trustix_datapath_tx_plaintext_skip_inner_tcp_checksum;
module_param_named(tx_plaintext_skip_inner_tcp_checksum,
		   trustix_datapath_tx_plaintext_skip_inner_tcp_checksum, bool,
		   0644);
MODULE_PARM_DESC(tx_plaintext_skip_inner_tcp_checksum,
		 "Skip rebuilding encapsulated inner TCP checksums; TrustIX RX xmit repairs or marks checksums before LAN delivery");

static unsigned int trustix_datapath_tx_plaintext_outer_gso_max_frames;
module_param_named(tx_plaintext_outer_gso_max_frames,
		   trustix_datapath_tx_plaintext_outer_gso_max_frames, uint,
		   0644);
MODULE_PARM_DESC(tx_plaintext_outer_gso_max_frames,
		 "Maximum inner TCP segments carried by one plaintext TX outer GSO skb; 0 keeps the packet-size cap");

static bool trustix_datapath_tx_plaintext_outer_gso_page_pool = true;
module_param_named(tx_plaintext_outer_gso_page_pool,
		   trustix_datapath_tx_plaintext_outer_gso_page_pool, bool,
		   0644);
MODULE_PARM_DESC(tx_plaintext_outer_gso_page_pool,
		 "Reuse page-pool-backed linear storage for plaintext TX outer TCP GSO skbs when supported");

static bool trustix_datapath_tx_plaintext_outer_gso_page_pool_available;
module_param_named(tx_plaintext_outer_gso_page_pool_available,
		   trustix_datapath_tx_plaintext_outer_gso_page_pool_available,
		   bool, 0444);
MODULE_PARM_DESC(tx_plaintext_outer_gso_page_pool_available,
		 "Whether reusable plaintext TX outer TCP GSO page pools are available on every possible CPU");

static bool trustix_datapath_tx_plaintext_payload_fast_copy = true;
module_param_named(tx_plaintext_payload_fast_copy,
		   trustix_datapath_tx_plaintext_payload_fast_copy, bool,
		   0644);
MODULE_PARM_DESC(tx_plaintext_payload_fast_copy,
		 "Copy plaintext TX GSO payloads directly from linear skb data or single skb frags before falling back to skb_copy_bits");

static bool trustix_datapath_tx_plaintext_payload_copy_csum = true;
module_param_named(tx_plaintext_payload_copy_csum,
		   trustix_datapath_tx_plaintext_payload_copy_csum, bool,
		   0644);
MODULE_PARM_DESC(tx_plaintext_payload_copy_csum,
		 "Calculate inner TCP payload checksums while copying plaintext TX GSO payloads");

static bool trustix_datapath_tx_plaintext_stream_coalesce;
module_param_named(tx_plaintext_stream_coalesce,
		   trustix_datapath_tx_plaintext_stream_coalesce, bool,
		   0644);
MODULE_PARM_DESC(tx_plaintext_stream_coalesce,
		 "Coalesce adjacent plaintext TX TCP packets into outer TCP or UDP GSO");

static unsigned int trustix_datapath_tx_plaintext_stream_coalesce_max_frames = 16;
module_param_named(tx_plaintext_stream_coalesce_max_frames,
		   trustix_datapath_tx_plaintext_stream_coalesce_max_frames,
		   uint, 0644);
MODULE_PARM_DESC(tx_plaintext_stream_coalesce_max_frames,
		 "Maximum adjacent plaintext TX TCP packets coalesced before transmit");

static unsigned int trustix_datapath_tx_plaintext_stream_coalesce_flush_jiffies;
module_param_named(tx_plaintext_stream_coalesce_flush_jiffies,
		   trustix_datapath_tx_plaintext_stream_coalesce_flush_jiffies,
		   uint, 0644);
MODULE_PARM_DESC(tx_plaintext_stream_coalesce_flush_jiffies,
		 "Delayed flush interval for plaintext TX TCP stream coalescing");

static bool trustix_datapath_rx_worker_steal_skb;
module_param_cb(rx_worker_steal_skb,
		&trustix_datapath_rx_worker_stolen_noop_bool_ops,
		&trustix_datapath_rx_worker_steal_skb, 0644);
MODULE_PARM_DESC(rx_worker_steal_skb,
		 "Accept legacy stolen-skb requests; current safe implementation keeps the path disabled");

static bool trustix_datapath_rx_worker_inline_stolen;
module_param_cb(rx_worker_inline_stolen,
		&trustix_datapath_rx_worker_stolen_noop_bool_ops,
		&trustix_datapath_rx_worker_inline_stolen, 0644);
MODULE_PARM_DESC(rx_worker_inline_stolen,
		 "Accept legacy inline stolen-skb requests; current safe implementation keeps the path disabled");

static bool trustix_datapath_rx_worker_inline_receive;
module_param_cb(rx_worker_inline_receive,
		&trustix_datapath_rx_worker_bool_ops,
		&trustix_datapath_rx_worker_inline_receive, 0644);
MODULE_PARM_DESC(rx_worker_inline_receive,
		 "Accept legacy inline netif_receive requests; current safe implementation falls back to copy/worker reinjection");

static bool trustix_datapath_rx_worker_xmit;
module_param_cb(rx_worker_xmit, &trustix_datapath_rx_worker_bool_ops,
		&trustix_datapath_rx_worker_xmit, 0644);
MODULE_PARM_DESC(rx_worker_xmit,
		 "Transmit decapsulated TrustIX RX worker packets out the target LAN device instead of reinjecting them into local RX");

static bool trustix_datapath_rx_worker_xmit_dev_forward;
module_param_cb(rx_worker_xmit_dev_forward,
		&trustix_datapath_rx_worker_bool_ops,
		&trustix_datapath_rx_worker_xmit_dev_forward, 0644);
MODULE_PARM_DESC(rx_worker_xmit_dev_forward,
		 "Diagnostic: deliver TrustIX RX worker LAN-xmit packets with dev_forward_skb instead of dev_queue_xmit");

static bool trustix_datapath_rx_worker_xmit_veth_peer_forward;
module_param_cb(rx_worker_xmit_veth_peer_forward,
		&trustix_datapath_rx_worker_bool_ops,
		&trustix_datapath_rx_worker_xmit_veth_peer_forward, 0644);
MODULE_PARM_DESC(rx_worker_xmit_veth_peer_forward,
		 "Deliver TrustIX RX worker LAN-xmit packets directly to veth peers with dev_forward_skb; non-veth targets use dev_queue_xmit");

static bool trustix_datapath_rx_worker_direct_xmit;
module_param_named(rx_worker_direct_xmit,
		   trustix_datapath_rx_worker_direct_xmit, bool, 0644);
MODULE_PARM_DESC(rx_worker_direct_xmit,
		 "Request RX worker direct target-device transmission; safe implementation records the request and uses validated dev_queue_xmit");

static bool trustix_datapath_rx_worker_xmit_hash_tx_queue;
module_param_cb(rx_worker_xmit_hash_tx_queue,
		&trustix_datapath_rx_worker_bool_ops,
		&trustix_datapath_rx_worker_xmit_hash_tx_queue, 0644);
MODULE_PARM_DESC(rx_worker_xmit_hash_tx_queue,
		 "Hash RX worker LAN xmit skbs across target-device TX queues; experimental and off by default");

static bool trustix_datapath_rx_worker_xmit_more;
module_param_cb(rx_worker_xmit_more, &trustix_datapath_rx_worker_bool_ops,
		&trustix_datapath_rx_worker_xmit_more, 0644);
MODULE_PARM_DESC(rx_worker_xmit_more,
		 "Set skb xmit_more on consecutive RX worker dev_queue_xmit packets; experimental and off by default");

static bool trustix_datapath_rx_worker_tc_skip_classify;
module_param_cb(rx_worker_tc_skip_classify,
		&trustix_datapath_rx_worker_bool_ops,
		&trustix_datapath_rx_worker_tc_skip_classify, 0644);
MODULE_PARM_DESC(rx_worker_tc_skip_classify,
		 "Set skb->tc_skip_classify on RX worker xmit packets; off by default so other TC programs can still classify TrustIX-generated LAN packets");

static bool trustix_datapath_rx_worker_inline_xmit;
module_param_cb(rx_worker_inline_xmit, &trustix_datapath_rx_worker_bool_ops,
		&trustix_datapath_rx_worker_inline_xmit, 0644);
MODULE_PARM_DESC(rx_worker_inline_xmit,
		 "Transmit validated multi-frame RX worker TCP packets directly from the netfilter hook instead of queueing worker slots");

static bool trustix_datapath_rx_worker_inline_xmit_copy_csum = true;
module_param_cb(rx_worker_inline_xmit_copy_csum,
		&trustix_datapath_rx_worker_bool_ops,
		&trustix_datapath_rx_worker_inline_xmit_copy_csum, 0644);
MODULE_PARM_DESC(rx_worker_inline_xmit_copy_csum,
		 "Copy and checksum RX worker inline xmit TCP/UDP packets in one pass");

static bool trustix_datapath_rx_worker_hot_stats = true;
module_param_named(rx_worker_hot_stats,
		   trustix_datapath_rx_worker_hot_stats, bool, 0644);
MODULE_PARM_DESC(rx_worker_hot_stats,
		 "Update high-frequency RX worker success counters on datapath hot paths");

static bool trustix_datapath_rx_worker_inline_pair_coalesce;
module_param_cb(rx_worker_inline_pair_coalesce,
		&trustix_datapath_rx_worker_bool_ops,
		&trustix_datapath_rx_worker_inline_pair_coalesce, 0644);
MODULE_PARM_DESC(rx_worker_inline_pair_coalesce,
		 "Pair adjacent validated single-frame inline xmit TCP packets into full-checksum inner GSO skbs");

static bool trustix_datapath_rx_worker_single_coalesce;
module_param_cb(rx_worker_single_coalesce,
		&trustix_datapath_rx_worker_bool_ops,
		&trustix_datapath_rx_worker_single_coalesce, 0644);
MODULE_PARM_DESC(rx_worker_single_coalesce,
		 "Coalesce validated single-frame inline xmit TCP packets across outer skbs into inner GSO skbs");

static bool trustix_datapath_rx_worker_inline_pair_hold_skb;
module_param_cb(rx_worker_inline_pair_hold_skb,
		&trustix_datapath_rx_worker_bool_ops,
		&trustix_datapath_rx_worker_inline_pair_hold_skb, 0644);
MODULE_PARM_DESC(rx_worker_inline_pair_hold_skb,
		 "Cache first inline TCP pair frame as a prepared skb to avoid a second copy on pair hit");

static unsigned int trustix_datapath_rx_worker_inline_pair_flush_jiffies;
module_param_cb(rx_worker_inline_pair_flush_jiffies,
		&trustix_datapath_rx_worker_uint_ops,
		&trustix_datapath_rx_worker_inline_pair_flush_jiffies, 0644);
MODULE_PARM_DESC(rx_worker_inline_pair_flush_jiffies,
		 "Delayed flush interval for unmatched inline pair coalesce packets");

static unsigned int trustix_datapath_rx_worker_inline_coalesce_max_frames = 2;
module_param_cb(rx_worker_inline_coalesce_max_frames,
		&trustix_datapath_rx_worker_uint_ops,
		&trustix_datapath_rx_worker_inline_coalesce_max_frames, 0644);
MODULE_PARM_DESC(rx_worker_inline_coalesce_max_frames,
		 "Maximum adjacent inline xmit TCP packets coalesced before transmit; clamped to 2..4");

static unsigned int trustix_datapath_rx_worker_single_coalesce_max_frames = 32;
module_param_cb(rx_worker_single_coalesce_max_frames,
		&trustix_datapath_rx_worker_uint_ops,
		&trustix_datapath_rx_worker_single_coalesce_max_frames, 0644);
MODULE_PARM_DESC(rx_worker_single_coalesce_max_frames,
		 "Maximum validated single-frame inline TCP packets coalesced before transmit; clamped to 2..32");

static unsigned int trustix_datapath_rx_worker_single_coalesce_flush_jiffies = 1;
module_param_cb(rx_worker_single_coalesce_flush_jiffies,
		&trustix_datapath_rx_worker_uint_ops,
		&trustix_datapath_rx_worker_single_coalesce_flush_jiffies,
		0644);
MODULE_PARM_DESC(rx_worker_single_coalesce_flush_jiffies,
		 "Delayed flush interval for unmatched single-frame inline TCP coalesce packets");

static bool trustix_datapath_rx_worker_xmit_fix_checksums = true;
module_param_named(rx_worker_xmit_fix_checksums,
		   trustix_datapath_rx_worker_xmit_fix_checksums, bool,
		   0644);
MODULE_PARM_DESC(rx_worker_xmit_fix_checksums,
		 "Rebuild inner IPv4/TCP/UDP checksums before RX worker dev_queue_xmit delivery");

static unsigned int trustix_datapath_rx_worker_xmit_trust_tcp_checksum_min_len;
module_param_cb(rx_worker_xmit_trust_tcp_checksum_min_len,
		&trustix_datapath_rx_worker_unsafe_noop_uint_ops,
		&trustix_datapath_rx_worker_xmit_trust_tcp_checksum_min_len,
		0644);
MODULE_PARM_DESC(rx_worker_xmit_trust_tcp_checksum_min_len,
		 "Accept legacy RX worker TCP checksum-trust requests; current safe implementation keeps checksum rebuild enabled");

static bool trustix_datapath_rx_worker_xmit_trust_tcp_checksum_ack_only;
module_param_cb(rx_worker_xmit_trust_tcp_checksum_ack_only,
		&trustix_datapath_rx_worker_unsafe_noop_bool_ops,
		&trustix_datapath_rx_worker_xmit_trust_tcp_checksum_ack_only,
		0644);
MODULE_PARM_DESC(rx_worker_xmit_trust_tcp_checksum_ack_only,
		 "Accept legacy RX worker ACK-only checksum-trust requests; current safe implementation keeps checksum rebuild enabled");

static bool trustix_datapath_rx_worker_xmit_tcp_partial_csum;
module_param_cb(rx_worker_xmit_tcp_partial_csum,
		&trustix_datapath_rx_worker_unsafe_noop_bool_ops,
		&trustix_datapath_rx_worker_xmit_tcp_partial_csum, 0644);
MODULE_PARM_DESC(rx_worker_xmit_tcp_partial_csum,
		 "Accept legacy RX worker TCP CHECKSUM_PARTIAL requests; current safe implementation keeps complete checksum rebuilds");

static bool trustix_datapath_rx_worker_xmit_dst_mac_cache;
module_param_cb(rx_worker_xmit_dst_mac_cache,
		&trustix_datapath_rx_worker_bool_ops,
		&trustix_datapath_rx_worker_xmit_dst_mac_cache, 0644);
MODULE_PARM_DESC(rx_worker_xmit_dst_mac_cache,
		 "Cache recent RX worker xmit destination MAC lookups by output device and inner IPv4 destination");

static bool trustix_datapath_rx_worker_xmit_dst_mac_pcpu_cache;
module_param_cb(rx_worker_xmit_dst_mac_pcpu_cache,
		&trustix_datapath_rx_worker_bool_ops,
		&trustix_datapath_rx_worker_xmit_dst_mac_pcpu_cache, 0644);
MODULE_PARM_DESC(rx_worker_xmit_dst_mac_pcpu_cache,
		 "Cache recent RX worker xmit destination MAC lookups per CPU by output device and inner IPv4 destination");

static bool trustix_datapath_rx_worker_xmit_dst_mac_seq_cache;
module_param_cb(rx_worker_xmit_dst_mac_seq_cache,
		&trustix_datapath_rx_worker_bool_ops,
		&trustix_datapath_rx_worker_xmit_dst_mac_seq_cache, 0644);
MODULE_PARM_DESC(rx_worker_xmit_dst_mac_seq_cache,
		 "Cache recent RX worker xmit destination MAC lookups with seqlock readers by output device and inner IPv4 destination");

static bool trustix_datapath_rx_worker_queue_skb;
module_param_cb(rx_worker_queue_skb, &trustix_datapath_rx_worker_bool_ops,
		&trustix_datapath_rx_worker_queue_skb, 0644);
MODULE_PARM_DESC(rx_worker_queue_skb,
		 "Queue prebuilt inner skbs for RX worker delivery instead of queueing copied packet buffers");

static bool trustix_datapath_rx_worker_stream_coalesce_gso;
module_param_cb(rx_worker_stream_coalesce_gso,
		&trustix_datapath_rx_worker_bool_ops,
		&trustix_datapath_rx_worker_stream_coalesce_gso, 0644);
MODULE_PARM_DESC(rx_worker_stream_coalesce_gso,
		 "Coalesce verified RX worker TCP stream frames into one inner TCPv4 GSO skb before LAN xmit delivery");

static bool trustix_datapath_rx_worker_stream_coalesce_nonlinear;
module_param_named(rx_worker_stream_coalesce_nonlinear,
		   trustix_datapath_rx_worker_stream_coalesce_nonlinear, bool,
		   0644);
MODULE_PARM_DESC(rx_worker_stream_coalesce_nonlinear,
		 "Build RX worker coalesced TCPv4 GSO payloads in page frags when the LAN device supports SG, TSO, and hardware checksums");

static bool trustix_datapath_rx_worker_stream_coalesce_page_frag_cache = true;
module_param_named(rx_worker_stream_coalesce_page_frag_cache,
		   trustix_datapath_rx_worker_stream_coalesce_page_frag_cache,
		   bool, 0644);
MODULE_PARM_DESC(rx_worker_stream_coalesce_page_frag_cache,
		 "Allocate nonlinear RX worker GSO payload pages from per-CPU page-frag caches");

static bool trustix_datapath_rx_worker_stream_coalesce_software_segment;
module_param_cb(rx_worker_stream_coalesce_software_segment,
		&trustix_datapath_rx_worker_bool_ops,
		&trustix_datapath_rx_worker_stream_coalesce_software_segment,
		0644);
MODULE_PARM_DESC(rx_worker_stream_coalesce_software_segment,
		 "Software-segment RX worker coalesced TCPv4 GSO skbs before LAN xmit delivery");

static bool trustix_datapath_rx_worker_stream_coalesce_partial_csum;
module_param_cb(rx_worker_stream_coalesce_partial_csum,
		&trustix_datapath_rx_worker_unsafe_noop_bool_ops,
		&trustix_datapath_rx_worker_stream_coalesce_partial_csum,
		0644);
MODULE_PARM_DESC(rx_worker_stream_coalesce_partial_csum,
		 "Legacy compatibility request for partial checksums on RX worker coalesced TCPv4 GSO skbs; current safe path falls back to complete checksums");

static bool trustix_datapath_rx_worker_steal_xmit;
module_param_cb(rx_worker_steal_xmit,
		&trustix_datapath_rx_worker_stolen_noop_bool_ops,
		&trustix_datapath_rx_worker_steal_xmit, 0644);
MODULE_PARM_DESC(rx_worker_steal_xmit,
		 "Accept legacy stolen-skb xmit requests; current safe implementation falls back to copy/worker xmit");

static bool trustix_datapath_rx_worker_steal_tcp;
module_param_cb(rx_worker_steal_tcp,
		&trustix_datapath_rx_worker_stolen_noop_bool_ops,
		&trustix_datapath_rx_worker_steal_tcp, 0644);
MODULE_PARM_DESC(rx_worker_steal_tcp,
		 "Accept legacy stolen-skb TCP requests; current safe implementation falls back to copy/worker reinjection");

static bool trustix_datapath_rx_worker_tcp;
module_param_cb(rx_worker_tcp, &trustix_datapath_rx_worker_bool_ops,
		&trustix_datapath_rx_worker_tcp, 0644);
MODULE_PARM_DESC(rx_worker_tcp,
		 "Allow experimental TrustIX RX worker to claim TCP transport frames");

static bool trustix_datapath_rx_worker_stream_tcp;
module_param_cb(rx_worker_stream_tcp, &trustix_datapath_rx_worker_bool_ops,
		&trustix_datapath_rx_worker_stream_tcp, 0644);
MODULE_PARM_DESC(rx_worker_stream_tcp,
		 "Allow TrustIX RX worker to parse multi-frame TCP TIXT payloads");

static bool trustix_datapath_rx_worker_stream_batch_queue;
module_param_cb(rx_worker_stream_batch_queue,
		&trustix_datapath_rx_worker_bool_ops,
		&trustix_datapath_rx_worker_stream_batch_queue, 0644);
MODULE_PARM_DESC(rx_worker_stream_batch_queue,
		 "Batch queue copied frames from multi-frame TCP TIXT payloads");

static bool trustix_datapath_rx_worker_stream_offset_copy = true;
module_param_named(rx_worker_stream_offset_copy,
		   trustix_datapath_rx_worker_stream_offset_copy, bool, 0644);
MODULE_PARM_DESC(rx_worker_stream_offset_copy,
		 "Parse and copy nonlinear multi-frame TIX streams by skb offset without linearizing the outer skb");

static unsigned long long trustix_datapath_rx_worker_stolen;
module_param_named(rx_worker_stolen, trustix_datapath_rx_worker_stolen, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_stolen,
		 "TrustIX RX worker packets queued by stealing the ingress skb");

static unsigned long long trustix_datapath_rx_worker_steal_fallbacks;
module_param_named(rx_worker_steal_fallbacks,
		   trustix_datapath_rx_worker_steal_fallbacks, ullong, 0444);
MODULE_PARM_DESC(rx_worker_steal_fallbacks,
		 "TrustIX RX worker packets that fell back from stolen-skb to copy mode");

module_param_named(rx_worker_steal_param_safe_fallbacks,
		   trustix_datapath_rx_worker_steal_param_safe_fallbacks,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_steal_param_safe_fallbacks,
		 "TrustIX RX worker stolen-skb parameter requests accepted as safe no-op fallback");

module_param_named(rx_worker_unsafe_param_safe_fallbacks,
		   trustix_datapath_rx_worker_unsafe_param_safe_fallbacks,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_unsafe_param_safe_fallbacks,
		 "TrustIX RX worker unsafe checksum parameter requests accepted as safe no-op fallback");

static unsigned long long trustix_datapath_rx_worker_steal_errors;
module_param_named(rx_worker_steal_errors,
		   trustix_datapath_rx_worker_steal_errors, ullong, 0444);
MODULE_PARM_DESC(rx_worker_steal_errors,
		 "TrustIX RX worker stolen-skb queue or reinjection errors");

static unsigned long long trustix_datapath_rx_worker_inline_injected;
module_param_named(rx_worker_inline_injected,
		   trustix_datapath_rx_worker_inline_injected, ullong, 0444);
MODULE_PARM_DESC(rx_worker_inline_injected,
		 "TrustIX RX worker packets injected directly from stolen skbs");

static unsigned long long trustix_datapath_rx_worker_inline_errors;
module_param_named(rx_worker_inline_errors,
		   trustix_datapath_rx_worker_inline_errors, ullong, 0444);
MODULE_PARM_DESC(rx_worker_inline_errors,
		 "TrustIX RX worker direct stolen-skb reinjection errors");

static unsigned long long trustix_datapath_rx_worker_inline_xmit_packets;
module_param_named(rx_worker_inline_xmit_packets,
		   trustix_datapath_rx_worker_inline_xmit_packets, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_inline_xmit_packets,
		 "TrustIX RX worker packets directly transmitted from the netfilter hook");

static unsigned long long trustix_datapath_rx_worker_inline_xmit_errors;
module_param_named(rx_worker_inline_xmit_errors,
		   trustix_datapath_rx_worker_inline_xmit_errors, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_inline_xmit_errors,
		 "TrustIX RX worker direct netfilter-hook transmit failures");

static unsigned long long trustix_datapath_rx_worker_inline_xmit_hook_queue_fallbacks;
module_param_named(rx_worker_inline_xmit_hook_queue_fallbacks,
		   trustix_datapath_rx_worker_inline_xmit_hook_queue_fallbacks,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_inline_xmit_hook_queue_fallbacks,
		 "TrustIX RX worker inline xmit packets queued to worker context instead of dev_queue_xmit from a netfilter hook");

static unsigned long long trustix_datapath_rx_worker_inline_xmit_copy_csum_hits;
module_param_named(rx_worker_inline_xmit_copy_csum_hits,
		   trustix_datapath_rx_worker_inline_xmit_copy_csum_hits,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_inline_xmit_copy_csum_hits,
		 "TrustIX RX worker inline xmit packets built with one-pass copy/checksum");

static unsigned long long
	trustix_datapath_rx_worker_inline_xmit_copy_csum_fallbacks;
module_param_named(rx_worker_inline_xmit_copy_csum_fallbacks,
		   trustix_datapath_rx_worker_inline_xmit_copy_csum_fallbacks,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_inline_xmit_copy_csum_fallbacks,
		 "TrustIX RX worker inline xmit packets that fell back from one-pass copy/checksum");

static unsigned long long trustix_datapath_rx_worker_inline_pair_stored;
module_param_named(rx_worker_inline_pair_stored,
		   trustix_datapath_rx_worker_inline_pair_stored, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_inline_pair_stored,
		 "TrustIX RX worker inline xmit packets held for pair coalescing");

static unsigned long long trustix_datapath_rx_worker_inline_pair_packets;
module_param_named(rx_worker_inline_pair_packets,
		   trustix_datapath_rx_worker_inline_pair_packets, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_inline_pair_packets,
		 "TrustIX RX worker inline xmit packets delivered by pair coalescing");

static unsigned long long trustix_datapath_rx_worker_inline_pair_flushes;
module_param_named(rx_worker_inline_pair_flushes,
		   trustix_datapath_rx_worker_inline_pair_flushes, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_inline_pair_flushes,
		 "TrustIX RX worker inline pair coalesce held packets flushed singly");

static unsigned long long trustix_datapath_rx_worker_inline_pair_misses;
module_param_named(rx_worker_inline_pair_misses,
		   trustix_datapath_rx_worker_inline_pair_misses, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_inline_pair_misses,
		 "TrustIX RX worker inline pair coalesce flow or sequence misses");

static unsigned long long trustix_datapath_rx_worker_inline_pair_errors;
module_param_named(rx_worker_inline_pair_errors,
		   trustix_datapath_rx_worker_inline_pair_errors, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_inline_pair_errors,
		 "TrustIX RX worker inline pair coalesce allocation/build/xmit errors");

static struct trustix_datapath_rx_worker_inline_pair_slot
	trustix_datapath_rx_worker_inline_pair_slots[
		TRUSTIX_DATAPATH_RX_WORKER_INLINE_PAIR_SLOTS];

static unsigned long long trustix_datapath_rx_worker_single_coalesce_stored;
module_param_named(rx_worker_single_coalesce_stored,
		   trustix_datapath_rx_worker_single_coalesce_stored, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_single_coalesce_stored,
		 "TrustIX RX worker single-frame TCP packets held for coalescing");

static unsigned long long trustix_datapath_rx_worker_single_coalesce_packets;
module_param_named(rx_worker_single_coalesce_packets,
		   trustix_datapath_rx_worker_single_coalesce_packets, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_single_coalesce_packets,
		 "TrustIX RX worker single-frame TCP coalesced batches delivered");

static unsigned long long trustix_datapath_rx_worker_single_coalesce_frames;
module_param_named(rx_worker_single_coalesce_frames,
		   trustix_datapath_rx_worker_single_coalesce_frames, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_single_coalesce_frames,
		 "TrustIX RX worker single-frame TCP frames delivered in coalesced batches");

static unsigned long long trustix_datapath_rx_worker_single_coalesce_flushes;
module_param_named(rx_worker_single_coalesce_flushes,
		   trustix_datapath_rx_worker_single_coalesce_flushes, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_single_coalesce_flushes,
		 "TrustIX RX worker single-frame TCP coalesce held packets flushed singly");

static unsigned long long trustix_datapath_rx_worker_single_coalesce_misses;
module_param_named(rx_worker_single_coalesce_misses,
		   trustix_datapath_rx_worker_single_coalesce_misses, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_single_coalesce_misses,
		 "TrustIX RX worker single-frame TCP coalesce flow or sequence misses");

static unsigned long long trustix_datapath_rx_worker_single_coalesce_errors;
module_param_named(rx_worker_single_coalesce_errors,
		   trustix_datapath_rx_worker_single_coalesce_errors, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_single_coalesce_errors,
		 "TrustIX RX worker single-frame TCP coalesce allocation/build/xmit errors");

static struct trustix_datapath_rx_worker_single_coalesce_slot
	trustix_datapath_rx_worker_single_coalesce_slots[
		TRUSTIX_DATAPATH_RX_WORKER_SINGLE_COALESCE_SLOTS];

static unsigned long long trustix_datapath_rx_worker_stream_packets;
module_param_named(rx_worker_stream_packets,
		   trustix_datapath_rx_worker_stream_packets, ullong, 0444);
MODULE_PARM_DESC(rx_worker_stream_packets,
		 "TrustIX RX worker multi-frame TCP packets accepted");

static unsigned long long trustix_datapath_rx_worker_stream_frames;
module_param_named(rx_worker_stream_frames,
		   trustix_datapath_rx_worker_stream_frames, ullong, 0444);
MODULE_PARM_DESC(rx_worker_stream_frames,
		 "TrustIX RX worker frames accepted from multi-frame TCP packets");

static unsigned long long trustix_datapath_rx_worker_stream_errors;
module_param_named(rx_worker_stream_errors,
		   trustix_datapath_rx_worker_stream_errors, ullong, 0444);
MODULE_PARM_DESC(rx_worker_stream_errors,
		 "TrustIX RX worker multi-frame TCP parse or validation errors");

static unsigned long long trustix_datapath_rx_worker_stream_queue_errors;
module_param_named(rx_worker_stream_queue_errors,
		   trustix_datapath_rx_worker_stream_queue_errors, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_stream_queue_errors,
		 "TrustIX RX worker multi-frame TCP queue errors");

static unsigned long long trustix_datapath_rx_worker_stream_batch_packets;
module_param_named(rx_worker_stream_batch_packets,
		   trustix_datapath_rx_worker_stream_batch_packets, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_stream_batch_packets,
		 "TrustIX RX worker TCP stream packets queued through batch mode");

static unsigned long long trustix_datapath_rx_worker_stream_batch_frames;
module_param_named(rx_worker_stream_batch_frames,
		   trustix_datapath_rx_worker_stream_batch_frames, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_stream_batch_frames,
		 "TrustIX RX worker TCP stream frames queued through batch mode");

static unsigned long long trustix_datapath_rx_worker_stream_batch_errors;
module_param_named(rx_worker_stream_batch_errors,
		   trustix_datapath_rx_worker_stream_batch_errors, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_stream_batch_errors,
		 "TrustIX RX worker TCP stream batch queue errors");

static unsigned long long trustix_datapath_rx_worker_stream_inline_batch_fallbacks;
module_param_named(rx_worker_stream_inline_batch_fallbacks,
		   trustix_datapath_rx_worker_stream_inline_batch_fallbacks,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_stream_inline_batch_fallbacks,
		 "TrustIX RX worker TCP stream packets that used worker batch-copy instead of netfilter-hook inline xmit for unsafe skb shapes");

static DEFINE_PER_CPU(unsigned long long,
	trustix_datapath_rx_worker_stream_offset_copy_attempts);
module_param_cb(rx_worker_stream_offset_copy_attempts,
		&trustix_datapath_percpu_ullong_ro_ops,
		&trustix_datapath_rx_worker_stream_offset_copy_attempts, 0444);
MODULE_PARM_DESC(rx_worker_stream_offset_copy_attempts,
		 "Nonlinear TrustIX RX stream packets considered for offset-based parsing and copy");

static DEFINE_PER_CPU(unsigned long long,
	trustix_datapath_rx_worker_stream_offset_copy_hits);
module_param_cb(rx_worker_stream_offset_copy_hits,
		&trustix_datapath_percpu_ullong_ro_ops,
		&trustix_datapath_rx_worker_stream_offset_copy_hits, 0444);
MODULE_PARM_DESC(rx_worker_stream_offset_copy_hits,
		 "Nonlinear multi-frame TrustIX RX stream packets parsed without outer skb linearization");

static DEFINE_PER_CPU(unsigned long long,
	trustix_datapath_rx_worker_stream_offset_copy_bytes);
module_param_cb(rx_worker_stream_offset_copy_bytes,
		&trustix_datapath_percpu_ullong_ro_ops,
		&trustix_datapath_rx_worker_stream_offset_copy_bytes, 0444);
MODULE_PARM_DESC(rx_worker_stream_offset_copy_bytes,
		 "Outer bytes accepted by TrustIX RX stream offset-based parsing");

static DEFINE_PER_CPU(unsigned long long,
	trustix_datapath_rx_worker_stream_offset_copy_fallbacks);
module_param_cb(rx_worker_stream_offset_copy_fallbacks,
		&trustix_datapath_percpu_ullong_ro_ops,
		&trustix_datapath_rx_worker_stream_offset_copy_fallbacks, 0444);
MODULE_PARM_DESC(rx_worker_stream_offset_copy_fallbacks,
		 "Nonlinear TrustIX RX stream packets that retained the linear pull path");

static DEFINE_PER_CPU(unsigned long long,
	trustix_datapath_rx_worker_stream_offset_copy_errors);
module_param_cb(rx_worker_stream_offset_copy_errors,
		&trustix_datapath_percpu_ullong_ro_ops,
		&trustix_datapath_rx_worker_stream_offset_copy_errors, 0444);
MODULE_PARM_DESC(rx_worker_stream_offset_copy_errors,
		 "TrustIX RX stream offset header copy or parse failures");

static unsigned long long trustix_datapath_rx_worker_checksum_fixed;
module_param_named(rx_worker_checksum_fixed,
		   trustix_datapath_rx_worker_checksum_fixed, ullong, 0444);
MODULE_PARM_DESC(rx_worker_checksum_fixed,
		 "TrustIX RX worker xmit packets whose inner checksums were rebuilt");

static unsigned long long trustix_datapath_rx_worker_checksum_trusted;
module_param_named(rx_worker_checksum_trusted,
		   trustix_datapath_rx_worker_checksum_trusted, ullong, 0444);
MODULE_PARM_DESC(rx_worker_checksum_trusted,
		 "TrustIX RX worker xmit TCP packets whose existing L4 checksum was trusted");

static unsigned long long trustix_datapath_rx_worker_checksum_trust_fallbacks;
module_param_named(rx_worker_checksum_trust_fallbacks,
		   trustix_datapath_rx_worker_checksum_trust_fallbacks,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_checksum_trust_fallbacks,
		 "TrustIX RX worker TCP checksum trust requests that safely fell back after validation failed");

static unsigned long long trustix_datapath_rx_worker_checksum_ipv4_only;
module_param_named(rx_worker_checksum_ipv4_only,
		   trustix_datapath_rx_worker_checksum_ipv4_only, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_checksum_ipv4_only,
		 "TrustIX RX worker xmit packets whose IPv4 header checksum alone was rebuilt");

static unsigned long long trustix_datapath_rx_worker_checksum_partial;
module_param_named(rx_worker_checksum_partial,
		   trustix_datapath_rx_worker_checksum_partial, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_checksum_partial,
		 "TrustIX RX worker xmit TCP packets prepared with CHECKSUM_PARTIAL");

static unsigned long long trustix_datapath_rx_worker_checksum_errors;
module_param_named(rx_worker_checksum_errors,
		   trustix_datapath_rx_worker_checksum_errors, ullong, 0444);
MODULE_PARM_DESC(rx_worker_checksum_errors,
		 "TrustIX RX worker xmit packets dropped because checksum rebuild failed");

static unsigned long long
	trustix_datapath_rx_worker_inner_tcp_checksum_partial;
module_param_named(rx_worker_inner_tcp_checksum_partial,
		   trustix_datapath_rx_worker_inner_tcp_checksum_partial,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_inner_tcp_checksum_partial,
		 "Validated TrustIX RX inner TCP CHECKSUM_PARTIAL frames");

static unsigned long long
	trustix_datapath_rx_worker_inner_tcp_checksum_partial_errors;
module_param_named(rx_worker_inner_tcp_checksum_partial_errors,
		   trustix_datapath_rx_worker_inner_tcp_checksum_partial_errors,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_inner_tcp_checksum_partial_errors,
		 "Rejected TrustIX RX inner TCP CHECKSUM_PARTIAL frames");

static unsigned long long trustix_datapath_rx_worker_inner_gso_candidates;
module_param_named(rx_worker_inner_gso_candidates,
		   trustix_datapath_rx_worker_inner_gso_candidates, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_inner_gso_candidates,
		 "TrustIX RX packets carrying the negotiated inner-GSO flag");

static unsigned long long trustix_datapath_rx_worker_inner_gso_packets;
module_param_named(rx_worker_inner_gso_packets,
		   trustix_datapath_rx_worker_inner_gso_packets, ullong, 0444);
MODULE_PARM_DESC(rx_worker_inner_gso_packets,
		 "Complete TrustIX RX inner-GSO packets restored and queued");

static unsigned long long trustix_datapath_rx_worker_inner_gso_segments;
module_param_named(rx_worker_inner_gso_segments,
		   trustix_datapath_rx_worker_inner_gso_segments, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_inner_gso_segments,
		 "Inner TCP segments represented by restored TrustIX RX inner-GSO packets");

static unsigned long long
	trustix_datapath_rx_worker_inner_gso_partial_frames;
module_param_named(rx_worker_inner_gso_partial_frames,
		   trustix_datapath_rx_worker_inner_gso_partial_frames,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_inner_gso_partial_frames,
		 "TrustIX RX inner-GSO frames not completely reconstructed by GRO");

static unsigned long long trustix_datapath_rx_worker_inner_gso_malformed;
module_param_named(rx_worker_inner_gso_malformed,
		   trustix_datapath_rx_worker_inner_gso_malformed, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_inner_gso_malformed,
		 "TrustIX RX inner-GSO frames rejected for invalid wire or packet metadata");

static unsigned long long trustix_datapath_rx_worker_inner_gso_errors;
module_param_named(rx_worker_inner_gso_errors,
		   trustix_datapath_rx_worker_inner_gso_errors, ullong, 0444);
MODULE_PARM_DESC(rx_worker_inner_gso_errors,
		 "TrustIX RX inner-GSO allocation, target, preparation, or queue errors");

static unsigned long long
	trustix_datapath_rx_worker_inner_gso_stream_packets;
module_param_named(rx_worker_inner_gso_stream_packets,
		   trustix_datapath_rx_worker_inner_gso_stream_packets,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_inner_gso_stream_packets,
		 "GRO packets containing more than one complete TIX frame and at least one inner-GSO frame");

static unsigned long long
	trustix_datapath_rx_worker_inner_gso_stream_frames;
module_param_named(rx_worker_inner_gso_stream_frames,
		   trustix_datapath_rx_worker_inner_gso_stream_frames,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_inner_gso_stream_frames,
		 "Complete TIX frames consumed from mixed inner-GSO GRO packets");

static unsigned long long
	trustix_datapath_rx_worker_inner_gso_regular_frames;
module_param_named(rx_worker_inner_gso_regular_frames,
		   trustix_datapath_rx_worker_inner_gso_regular_frames,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_inner_gso_regular_frames,
		 "Non-inner-GSO TIX frames consumed from mixed inner-GSO GRO packets");

static unsigned long long
	trustix_datapath_rx_worker_inner_gso_continuation_drops;
module_param_named(rx_worker_inner_gso_continuation_drops,
		   trustix_datapath_rx_worker_inner_gso_continuation_drops,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_inner_gso_continuation_drops,
		 "Claimed TIX-TCP continuation packets dropped before the host TCP stack");

static unsigned long long
	trustix_datapath_rx_worker_inner_gso_session_clears;
module_param_named(rx_worker_inner_gso_session_clears,
		   trustix_datapath_rx_worker_inner_gso_session_clears,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_inner_gso_session_clears,
		 "Session state transitions that cleared bounded inner-GSO reassembly state");

static unsigned long long
	trustix_datapath_rx_worker_inner_gso_session_slots_cleared;
module_param_named(rx_worker_inner_gso_session_slots_cleared,
		   trustix_datapath_rx_worker_inner_gso_session_slots_cleared,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_inner_gso_session_slots_cleared,
		 "Inner-GSO reassembly slots cleared by session state transitions");

static struct trustix_datapath_inner_gso_reassembly_slot
	trustix_datapath_inner_gso_reassembly_slots[
		TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_SLOTS];
static spinlock_t trustix_datapath_inner_gso_reassembly_locks[
	TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_SETS];
static __u8 *trustix_datapath_inner_gso_reassembly_data;
static struct trustix_datapath_inner_gso_probation_slot
	trustix_datapath_inner_gso_probation_slots[
		TRUSTIX_DATAPATH_INNER_GSO_PROBATION_SLOTS];
static spinlock_t trustix_datapath_inner_gso_probation_locks[
	TRUSTIX_DATAPATH_INNER_GSO_PROBATION_SETS];

static unsigned long long
	trustix_datapath_rx_worker_inner_gso_reassembly_started;
module_param_named(rx_worker_inner_gso_reassembly_started,
		   trustix_datapath_rx_worker_inner_gso_reassembly_started,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_inner_gso_reassembly_started,
		 "Partial TIX frames admitted to bounded inner-GSO reassembly");

static unsigned long long
	trustix_datapath_rx_worker_inner_gso_reassembly_completed;
module_param_named(rx_worker_inner_gso_reassembly_completed,
		   trustix_datapath_rx_worker_inner_gso_reassembly_completed,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_inner_gso_reassembly_completed,
		 "Bounded inner-GSO reassemblies validated and queued");

static unsigned long long
	trustix_datapath_rx_worker_inner_gso_continuation_matched;
module_param_named(rx_worker_inner_gso_continuation_matched,
		   trustix_datapath_rx_worker_inner_gso_continuation_matched,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_inner_gso_continuation_matched,
		 "TIX-TCP continuation packets matched by tuple and TCP sequence");

static unsigned long long
	trustix_datapath_rx_worker_inner_gso_continuation_orphans;
module_param_named(rx_worker_inner_gso_continuation_orphans,
		   trustix_datapath_rx_worker_inner_gso_continuation_orphans,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_inner_gso_continuation_orphans,
		 "Claimed TIX-TCP continuation packets without active reassembly state");

static unsigned long long trustix_datapath_rx_worker_inner_gso_sequence_gaps;
module_param_named(rx_worker_inner_gso_sequence_gaps,
		   trustix_datapath_rx_worker_inner_gso_sequence_gaps,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_inner_gso_sequence_gaps,
		 "Inner-GSO reassemblies aborted by a TCP sequence gap or overlap");

static unsigned long long
	trustix_datapath_rx_worker_inner_gso_sequence_gap_ahead;
module_param_named(rx_worker_inner_gso_sequence_gap_ahead,
		   trustix_datapath_rx_worker_inner_gso_sequence_gap_ahead,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_inner_gso_sequence_gap_ahead,
		 "Unmatched continuations ahead of the nearest expected TCP sequence");

static unsigned long long
	trustix_datapath_rx_worker_inner_gso_sequence_gap_behind;
module_param_named(rx_worker_inner_gso_sequence_gap_behind,
		   trustix_datapath_rx_worker_inner_gso_sequence_gap_behind,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_inner_gso_sequence_gap_behind,
		 "Unmatched continuations behind the nearest expected TCP sequence");

static int trustix_datapath_rx_worker_inner_gso_last_sequence_gap;
module_param_named(rx_worker_inner_gso_last_sequence_gap,
		   trustix_datapath_rx_worker_inner_gso_last_sequence_gap,
		   int, 0444);
MODULE_PARM_DESC(rx_worker_inner_gso_last_sequence_gap,
		 "Signed TCP sequence delta for the most recent unmatched continuation");

static unsigned long long trustix_datapath_rx_worker_inner_gso_timeouts;
module_param_named(rx_worker_inner_gso_timeouts,
		   trustix_datapath_rx_worker_inner_gso_timeouts, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_inner_gso_timeouts,
		 "Inner-GSO reassembly states expired before completion");

static unsigned long long
	trustix_datapath_rx_worker_inner_gso_timeouts_on_start;
module_param_named(rx_worker_inner_gso_timeouts_on_start,
		   trustix_datapath_rx_worker_inner_gso_timeouts_on_start,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_inner_gso_timeouts_on_start,
		 "Expired inner-GSO states reclaimed while admitting a frame head");

static unsigned long long
	trustix_datapath_rx_worker_inner_gso_timeouts_on_append;
module_param_named(rx_worker_inner_gso_timeouts_on_append,
		   trustix_datapath_rx_worker_inner_gso_timeouts_on_append,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_inner_gso_timeouts_on_append,
		 "Expired inner-GSO states reclaimed while matching a continuation");

static unsigned long long
	trustix_datapath_rx_worker_inner_gso_timeouts_on_sweep;
module_param_named(rx_worker_inner_gso_timeouts_on_sweep,
		   trustix_datapath_rx_worker_inner_gso_timeouts_on_sweep,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_inner_gso_timeouts_on_sweep,
		 "Expired inner-GSO states reclaimed by the runtime capability sweep");

static unsigned long long
	trustix_datapath_rx_worker_inner_gso_timeout_missing_bytes;
module_param_named(rx_worker_inner_gso_timeout_missing_bytes,
		   trustix_datapath_rx_worker_inner_gso_timeout_missing_bytes,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_inner_gso_timeout_missing_bytes,
		 "Bytes absent from inner-GSO states when they expire");

static unsigned long long
	trustix_datapath_rx_worker_inner_gso_timeout_max_missing_bytes;
module_param_named(rx_worker_inner_gso_timeout_max_missing_bytes,
		   trustix_datapath_rx_worker_inner_gso_timeout_max_missing_bytes,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_inner_gso_timeout_max_missing_bytes,
		 "Largest byte deficit observed in one expired inner-GSO state");

static unsigned long long
	trustix_datapath_rx_worker_inner_gso_duplicate_starts;
module_param_named(rx_worker_inner_gso_duplicate_starts,
		   trustix_datapath_rx_worker_inner_gso_duplicate_starts,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_inner_gso_duplicate_starts,
		 "Repeated frame heads merged into an existing reassembly state");

static unsigned long long trustix_datapath_rx_worker_inner_gso_collisions;
module_param_named(rx_worker_inner_gso_collisions,
		   trustix_datapath_rx_worker_inner_gso_collisions, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_inner_gso_collisions,
		 "Inner-GSO reassembly starts rejected by a full bounded pool");

static unsigned long long
	trustix_datapath_rx_worker_inner_gso_reassembly_high_watermark;
module_param_named(rx_worker_inner_gso_reassembly_high_watermark,
		   trustix_datapath_rx_worker_inner_gso_reassembly_high_watermark,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_inner_gso_reassembly_high_watermark,
		 "Peak concurrent inner-GSO reassemblies since counter reset");

static unsigned long long trustix_datapath_rx_worker_inner_gso_oom;
module_param_named(rx_worker_inner_gso_oom,
		   trustix_datapath_rx_worker_inner_gso_oom, ullong, 0444);
MODULE_PARM_DESC(rx_worker_inner_gso_oom,
		 "Inner-GSO reassembly preallocation or completed-frame allocation failures");

static unsigned long long trustix_datapath_rx_worker_inner_gso_tail_frames;
module_param_named(rx_worker_inner_gso_tail_frames,
		   trustix_datapath_rx_worker_inner_gso_tail_frames, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_inner_gso_tail_frames,
		 "Complete TIX frames consumed after a reassembled frame in the same GRO packet");

static unsigned long long trustix_datapath_rx_worker_tix_tcp_claimed_drops;
module_param_named(rx_worker_tix_tcp_claimed_drops,
		   trustix_datapath_rx_worker_tix_tcp_claimed_drops, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_tix_tcp_claimed_drops,
		 "Claimed plaintext TIX-TCP packets dropped after framing or delivery failure");

static unsigned long long
	trustix_datapath_rx_worker_partial_checksum_software_fallbacks;
module_param_named(rx_worker_partial_checksum_software_fallbacks,
		   trustix_datapath_rx_worker_partial_checksum_software_fallbacks,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_partial_checksum_software_fallbacks,
		 "TrustIX RX CHECKSUM_PARTIAL skbs completed in software before virtual-link or RX handoff");

static unsigned long long
	trustix_datapath_rx_worker_partial_checksum_metadata_repairs;
module_param_named(rx_worker_partial_checksum_metadata_repairs,
		   trustix_datapath_rx_worker_partial_checksum_metadata_repairs,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_partial_checksum_metadata_repairs,
		 "TrustIX RX CHECKSUM_PARTIAL skbs whose checksum offsets were repaired before handoff");

static unsigned long long trustix_datapath_rx_worker_dst_mac_hits;
module_param_named(rx_worker_dst_mac_hits,
		   trustix_datapath_rx_worker_dst_mac_hits, ullong, 0444);
MODULE_PARM_DESC(rx_worker_dst_mac_hits,
		 "TrustIX RX worker xmit packets that found a valid destination MAC");

static unsigned long long trustix_datapath_rx_worker_dst_mac_veth_peer_hits;
module_param_named(rx_worker_dst_mac_veth_peer_hits,
		   trustix_datapath_rx_worker_dst_mac_veth_peer_hits, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_dst_mac_veth_peer_hits,
		 "TrustIX RX worker xmit destination MAC lookups resolved from a veth peer");

static unsigned long long trustix_datapath_rx_worker_dst_mac_cache_hits;
module_param_named(rx_worker_dst_mac_cache_hits,
		   trustix_datapath_rx_worker_dst_mac_cache_hits, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_dst_mac_cache_hits,
		 "TrustIX RX worker xmit destination MAC lookups served by the small kernel cache");

static unsigned long long trustix_datapath_rx_worker_dst_mac_cache_misses;
module_param_named(rx_worker_dst_mac_cache_misses,
		   trustix_datapath_rx_worker_dst_mac_cache_misses, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_dst_mac_cache_misses,
		 "TrustIX RX worker xmit destination MAC lookups that fell through to neighbour lookup");

static unsigned long long trustix_datapath_rx_worker_dst_mac_broadcast;
module_param_named(rx_worker_dst_mac_broadcast,
		   trustix_datapath_rx_worker_dst_mac_broadcast, ullong, 0444);
MODULE_PARM_DESC(rx_worker_dst_mac_broadcast,
		 "TrustIX RX worker xmit packets that fell back to Ethernet broadcast");

static unsigned long long trustix_datapath_rx_worker_queued_skb;
module_param_named(rx_worker_queued_skb,
		   trustix_datapath_rx_worker_queued_skb, ullong, 0444);
MODULE_PARM_DESC(rx_worker_queued_skb,
		 "TrustIX RX worker packets queued as prebuilt skbs");

static unsigned long long trustix_datapath_rx_worker_queued_skb_fallbacks;
module_param_named(rx_worker_queued_skb_fallbacks,
		   trustix_datapath_rx_worker_queued_skb_fallbacks, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_queued_skb_fallbacks,
		 "TrustIX RX worker packets that fell back from prebuilt skb queueing to packet-buffer queueing");

static unsigned long long trustix_datapath_rx_worker_mark_skips;
module_param_named(rx_worker_mark_skips,
		   trustix_datapath_rx_worker_mark_skips, ullong, 0444);
MODULE_PARM_DESC(rx_worker_mark_skips,
		 "TrustIX RX worker self-generated packets skipped by the hook mark guard");

static unsigned long long trustix_datapath_hook_ifindex_skips;
module_param_named(hook_ifindex_skips,
		   trustix_datapath_hook_ifindex_skips, ullong, 0444);
MODULE_PARM_DESC(hook_ifindex_skips,
		 "TrustIX datapath hook invocations skipped because the packet arrived on a different interface");

static unsigned long long trustix_datapath_hook_master_ifindex_matches;
module_param_named(hook_master_ifindex_matches,
		   trustix_datapath_hook_master_ifindex_matches, ullong, 0444);
MODULE_PARM_DESC(hook_master_ifindex_matches,
		 "TrustIX datapath hook packets accepted because their ingress device is enslaved to the hooked interface");

static unsigned long long trustix_datapath_rx_worker_self_marked;
module_param_named(rx_worker_self_marked,
		   trustix_datapath_rx_worker_self_marked, ullong, 0444);
MODULE_PARM_DESC(rx_worker_self_marked,
		 "TrustIX RX worker skbs marked as self-generated before reinjection");

static unsigned long long trustix_datapath_rx_worker_tc_skip_requests;
module_param_named(rx_worker_tc_skip_requests,
		   trustix_datapath_rx_worker_tc_skip_requests, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_tc_skip_requests,
		 "TrustIX RX worker dev_queue_xmit skbs requested to skip TC classify");

static unsigned long long trustix_datapath_rx_worker_xmit_scrubbed;
module_param_named(rx_worker_xmit_scrubbed,
		   trustix_datapath_rx_worker_xmit_scrubbed, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_xmit_scrubbed,
		 "TrustIX RX worker dev_queue_xmit skbs scrubbed before transmit");

static unsigned long long trustix_datapath_rx_worker_bridge_targets;
module_param_named(rx_worker_bridge_targets,
		   trustix_datapath_rx_worker_bridge_targets, ullong, 0444);
MODULE_PARM_DESC(rx_worker_bridge_targets,
		 "TrustIX RX worker dev_queue_xmit attempts whose target is a bridge device");

static unsigned int trustix_datapath_rx_worker_last_target_ifindex;
module_param_named(rx_worker_last_target_ifindex,
		   trustix_datapath_rx_worker_last_target_ifindex, uint,
		   0444);
MODULE_PARM_DESC(rx_worker_last_target_ifindex,
		 "Last TrustIX RX worker dev_queue_xmit target ifindex");

static unsigned int trustix_datapath_rx_worker_last_target_type;
module_param_named(rx_worker_last_target_type,
		   trustix_datapath_rx_worker_last_target_type, uint, 0444);
MODULE_PARM_DESC(rx_worker_last_target_type,
		 "Last TrustIX RX worker dev_queue_xmit target ARP hardware type");

static unsigned int trustix_datapath_rx_worker_last_target_priv_flags;
module_param_named(rx_worker_last_target_priv_flags,
		   trustix_datapath_rx_worker_last_target_priv_flags, uint,
		   0444);
MODULE_PARM_DESC(rx_worker_last_target_priv_flags,
		 "Last TrustIX RX worker dev_queue_xmit target private flags");

static unsigned long long trustix_datapath_rx_worker_stream_coalesce_packets;
module_param_named(rx_worker_stream_coalesce_packets,
		   trustix_datapath_rx_worker_stream_coalesce_packets, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_stream_coalesce_packets,
		 "TrustIX RX worker TCP stream packets coalesced into inner GSO skbs");

static unsigned long long trustix_datapath_rx_worker_stream_coalesce_frames;
module_param_named(rx_worker_stream_coalesce_frames,
		   trustix_datapath_rx_worker_stream_coalesce_frames, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_stream_coalesce_frames,
		 "TrustIX RX worker TCP stream frames included in inner GSO skbs");

static unsigned long long trustix_datapath_rx_worker_stream_coalesce_errors;
module_param_named(rx_worker_stream_coalesce_errors,
		   trustix_datapath_rx_worker_stream_coalesce_errors, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_stream_coalesce_errors,
		 "TrustIX RX worker TCP stream coalesce failures that fell back to per-frame queueing");

static DEFINE_PER_CPU(unsigned long long,
	trustix_datapath_rx_worker_stream_coalesce_nonlinear_attempts);
module_param_cb(rx_worker_stream_coalesce_nonlinear_attempts,
		&trustix_datapath_percpu_ullong_ro_ops,
		&trustix_datapath_rx_worker_stream_coalesce_nonlinear_attempts,
		0444);
MODULE_PARM_DESC(rx_worker_stream_coalesce_nonlinear_attempts,
		 "TrustIX RX worker nonlinear coalesced GSO build attempts");

static DEFINE_PER_CPU(unsigned long long,
	trustix_datapath_rx_worker_stream_coalesce_nonlinear_hits);
module_param_cb(rx_worker_stream_coalesce_nonlinear_hits,
		&trustix_datapath_percpu_ullong_ro_ops,
		&trustix_datapath_rx_worker_stream_coalesce_nonlinear_hits,
		0444);
MODULE_PARM_DESC(rx_worker_stream_coalesce_nonlinear_hits,
		 "TrustIX RX worker nonlinear coalesced GSO build successes");

static DEFINE_PER_CPU(unsigned long long,
	trustix_datapath_rx_worker_stream_coalesce_nonlinear_frags);
module_param_cb(rx_worker_stream_coalesce_nonlinear_frags,
		&trustix_datapath_percpu_ullong_ro_ops,
		&trustix_datapath_rx_worker_stream_coalesce_nonlinear_frags,
		0444);
MODULE_PARM_DESC(rx_worker_stream_coalesce_nonlinear_frags,
		 "Pages attached to successful TrustIX RX worker nonlinear coalesced GSO skbs");

static DEFINE_PER_CPU(unsigned long long,
	trustix_datapath_rx_worker_stream_coalesce_nonlinear_bytes);
module_param_cb(rx_worker_stream_coalesce_nonlinear_bytes,
		&trustix_datapath_percpu_ullong_ro_ops,
		&trustix_datapath_rx_worker_stream_coalesce_nonlinear_bytes,
		0444);
MODULE_PARM_DESC(rx_worker_stream_coalesce_nonlinear_bytes,
		 "Payload bytes attached to successful TrustIX RX worker nonlinear coalesced GSO skbs");

static DEFINE_PER_CPU(unsigned long long,
	trustix_datapath_rx_worker_stream_coalesce_nonlinear_fallbacks);
module_param_cb(rx_worker_stream_coalesce_nonlinear_fallbacks,
		&trustix_datapath_percpu_ullong_ro_ops,
		&trustix_datapath_rx_worker_stream_coalesce_nonlinear_fallbacks,
		0444);
MODULE_PARM_DESC(rx_worker_stream_coalesce_nonlinear_fallbacks,
		 "TrustIX RX worker nonlinear coalesced GSO attempts that safely used the linear builder");

static DEFINE_PER_CPU(unsigned long long,
	trustix_datapath_rx_worker_stream_coalesce_nonlinear_errors);
module_param_cb(rx_worker_stream_coalesce_nonlinear_errors,
		&trustix_datapath_percpu_ullong_ro_ops,
		&trustix_datapath_rx_worker_stream_coalesce_nonlinear_errors,
		0444);
MODULE_PARM_DESC(rx_worker_stream_coalesce_nonlinear_errors,
		 "TrustIX RX worker nonlinear coalesced GSO allocation or validation errors");

static DEFINE_PER_CPU(unsigned long long,
	trustix_datapath_rx_worker_stream_coalesce_page_frag_cache_attempts);
module_param_cb(rx_worker_stream_coalesce_page_frag_cache_attempts,
		&trustix_datapath_percpu_ullong_ro_ops,
		&trustix_datapath_rx_worker_stream_coalesce_page_frag_cache_attempts,
		0444);
MODULE_PARM_DESC(rx_worker_stream_coalesce_page_frag_cache_attempts,
		 "TrustIX RX worker nonlinear GSO page-frag cache allocation attempts");

static DEFINE_PER_CPU(unsigned long long,
	trustix_datapath_rx_worker_stream_coalesce_page_frag_cache_hits);
module_param_cb(rx_worker_stream_coalesce_page_frag_cache_hits,
		&trustix_datapath_percpu_ullong_ro_ops,
		&trustix_datapath_rx_worker_stream_coalesce_page_frag_cache_hits,
		0444);
MODULE_PARM_DESC(rx_worker_stream_coalesce_page_frag_cache_hits,
		 "TrustIX RX worker nonlinear GSO payload pages served by page-frag caches");

static DEFINE_PER_CPU(unsigned long long,
	trustix_datapath_rx_worker_stream_coalesce_page_frag_cache_fallbacks);
module_param_cb(rx_worker_stream_coalesce_page_frag_cache_fallbacks,
		&trustix_datapath_percpu_ullong_ro_ops,
		&trustix_datapath_rx_worker_stream_coalesce_page_frag_cache_fallbacks,
		0444);
MODULE_PARM_DESC(rx_worker_stream_coalesce_page_frag_cache_fallbacks,
		 "TrustIX RX worker nonlinear GSO payload pages that fell back to alloc_page");

static DEFINE_PER_CPU(unsigned long long,
	trustix_datapath_rx_worker_stream_coalesce_page_frag_cache_errors);
module_param_cb(rx_worker_stream_coalesce_page_frag_cache_errors,
		&trustix_datapath_percpu_ullong_ro_ops,
		&trustix_datapath_rx_worker_stream_coalesce_page_frag_cache_errors,
		0444);
MODULE_PARM_DESC(rx_worker_stream_coalesce_page_frag_cache_errors,
		 "TrustIX RX worker nonlinear GSO page-frag cache allocation errors before fallback");

static DEFINE_PER_CPU(struct page_frag_cache,
	trustix_datapath_rx_worker_stream_coalesce_page_frag_caches);

static unsigned long long trustix_datapath_rx_worker_stream_coalesce_segment_batches;
module_param_named(rx_worker_stream_coalesce_segment_batches,
		   trustix_datapath_rx_worker_stream_coalesce_segment_batches,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_stream_coalesce_segment_batches,
		 "TrustIX RX worker coalesced GSO batches software-segmented before LAN xmit");

static unsigned long long trustix_datapath_rx_worker_stream_coalesce_segment_skbs;
module_param_named(rx_worker_stream_coalesce_segment_skbs,
		   trustix_datapath_rx_worker_stream_coalesce_segment_skbs,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_stream_coalesce_segment_skbs,
		 "TrustIX RX worker software-segmented skbs transmitted from coalesced batches");

static unsigned long long trustix_datapath_rx_worker_stream_coalesce_segment_errors;
module_param_named(rx_worker_stream_coalesce_segment_errors,
		   trustix_datapath_rx_worker_stream_coalesce_segment_errors,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_stream_coalesce_segment_errors,
		 "TrustIX RX worker coalesced GSO software segmentation or xmit failures");

static unsigned long long trustix_datapath_rx_worker_gso_xmit_packets;
module_param_named(rx_worker_gso_xmit_packets,
		   trustix_datapath_rx_worker_gso_xmit_packets, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_gso_xmit_packets,
		 "TrustIX RX worker inner GSO skbs transmitted without software segmentation");

static unsigned long long trustix_datapath_rx_worker_gso_xmit_segments;
module_param_named(rx_worker_gso_xmit_segments,
		   trustix_datapath_rx_worker_gso_xmit_segments, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_gso_xmit_segments,
		 "TrustIX RX worker inner TCP segments preserved inside direct GSO xmit skbs");

static unsigned long long trustix_datapath_rx_worker_gso_xmit_fallbacks;
module_param_named(rx_worker_gso_xmit_fallbacks,
		   trustix_datapath_rx_worker_gso_xmit_fallbacks, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_gso_xmit_fallbacks,
		 "TrustIX RX worker inner GSO skbs that fell back to software segmentation");

static unsigned long long trustix_datapath_rx_worker_gso_xmit_errors;
module_param_named(rx_worker_gso_xmit_errors,
		   trustix_datapath_rx_worker_gso_xmit_errors, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_gso_xmit_errors,
		 "TrustIX RX worker direct inner GSO xmit failures");

static unsigned long long trustix_datapath_rx_worker_direct_gso_attempts;
module_param_named(rx_worker_direct_gso_attempts,
		   trustix_datapath_rx_worker_direct_gso_attempts, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_direct_gso_attempts,
		 "TrustIX RX worker direct single-frame GSO attempts");

static unsigned long long trustix_datapath_rx_worker_direct_gso_hits;
module_param_named(rx_worker_direct_gso_hits,
		   trustix_datapath_rx_worker_direct_gso_hits, ullong, 0444);
MODULE_PARM_DESC(rx_worker_direct_gso_hits,
		 "TrustIX RX worker direct single-frame GSO hits");

static unsigned long long trustix_datapath_rx_worker_direct_gso_parse_misses;
module_param_named(rx_worker_direct_gso_parse_misses,
		   trustix_datapath_rx_worker_direct_gso_parse_misses,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_direct_gso_parse_misses,
		 "TrustIX RX worker direct single-frame GSO parse misses");

static unsigned long long trustix_datapath_rx_worker_direct_gso_cap_misses;
module_param_named(rx_worker_direct_gso_cap_misses,
		   trustix_datapath_rx_worker_direct_gso_cap_misses, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_direct_gso_cap_misses,
		 "TrustIX RX worker direct single-frame GSO capability misses");

static unsigned long long trustix_datapath_rx_worker_direct_gso_mtu_misses;
module_param_named(rx_worker_direct_gso_mtu_misses,
		   trustix_datapath_rx_worker_direct_gso_mtu_misses, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_direct_gso_mtu_misses,
		 "TrustIX RX worker direct single-frame GSO MTU misses");

static unsigned long long trustix_datapath_rx_worker_direct_gso_xmit_errors;
module_param_named(rx_worker_direct_gso_xmit_errors,
		   trustix_datapath_rx_worker_direct_gso_xmit_errors, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_direct_gso_xmit_errors,
		 "TrustIX RX worker direct single-frame GSO xmit errors");

static unsigned long long trustix_datapath_rx_worker_stream_coalesce_partial_csum_fallbacks;
module_param_named(rx_worker_stream_coalesce_partial_csum_fallbacks,
		   trustix_datapath_rx_worker_stream_coalesce_partial_csum_fallbacks,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_stream_coalesce_partial_csum_fallbacks,
		 "TrustIX RX worker coalesced GSO skbs that ignored the legacy partial-csum request and used complete TCP checksums");

static unsigned long long trustix_datapath_rx_worker_stream_coalesce_checksum_fallbacks;
module_param_named(rx_worker_stream_coalesce_checksum_fallbacks,
		   trustix_datapath_rx_worker_stream_coalesce_checksum_fallbacks,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_stream_coalesce_checksum_fallbacks,
		 "TrustIX RX worker TCP stream coalesce attempts safely fell back because checksum trust/update was not available");

static unsigned long long trustix_datapath_rx_worker_stream_coalesce_inline_queue_fallbacks;
module_param_named(rx_worker_stream_coalesce_inline_queue_fallbacks,
		   trustix_datapath_rx_worker_stream_coalesce_inline_queue_fallbacks,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_stream_coalesce_inline_queue_fallbacks,
		 "TrustIX RX worker hook/inline coalesced TCP GSO requests safely degraded to per-frame worker queueing");

static unsigned long long trustix_datapath_rx_worker_stream_direct_gso_packets;
module_param_named(rx_worker_stream_direct_gso_packets,
		   trustix_datapath_rx_worker_stream_direct_gso_packets,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_stream_direct_gso_packets,
		 "TrustIX RX outer TCP stream batches queued as one inner GSO skb");

static unsigned long long trustix_datapath_rx_worker_stream_direct_gso_frames;
module_param_named(rx_worker_stream_direct_gso_frames,
		   trustix_datapath_rx_worker_stream_direct_gso_frames,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_stream_direct_gso_frames,
		 "TrustIX RX outer TCP stream frames queued through direct inner GSO");

static unsigned long long trustix_datapath_rx_worker_stream_direct_gso_fallbacks;
module_param_named(rx_worker_stream_direct_gso_fallbacks,
		   trustix_datapath_rx_worker_stream_direct_gso_fallbacks,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_stream_direct_gso_fallbacks,
		 "TrustIX RX outer TCP stream batches that fell back from direct inner GSO");

static unsigned long long trustix_datapath_rx_worker_stream_direct_gso_errors;
module_param_named(rx_worker_stream_direct_gso_errors,
		   trustix_datapath_rx_worker_stream_direct_gso_errors,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_stream_direct_gso_errors,
		 "TrustIX RX outer TCP stream direct inner GSO build or queue errors");

static unsigned int trustix_datapath_rx_worker_stream_coalesce_last_len;
module_param_named(rx_worker_stream_coalesce_last_len,
		   trustix_datapath_rx_worker_stream_coalesce_last_len, uint,
		   0444);

static unsigned int trustix_datapath_rx_worker_stream_coalesce_last_gso_size;
module_param_named(rx_worker_stream_coalesce_last_gso_size,
		   trustix_datapath_rx_worker_stream_coalesce_last_gso_size,
		   uint, 0444);

static unsigned int trustix_datapath_rx_worker_stream_coalesce_last_gso_segs;
module_param_named(rx_worker_stream_coalesce_last_gso_segs,
		   trustix_datapath_rx_worker_stream_coalesce_last_gso_segs,
		   uint, 0444);

static unsigned int trustix_datapath_rx_worker_stream_coalesce_last_gso_type;
module_param_named(rx_worker_stream_coalesce_last_gso_type,
		   trustix_datapath_rx_worker_stream_coalesce_last_gso_type,
		   uint, 0444);

static unsigned int trustix_datapath_rx_worker_stream_coalesce_max_len;
module_param_named(rx_worker_stream_coalesce_max_len,
		   trustix_datapath_rx_worker_stream_coalesce_max_len, uint,
		   0444);

static int trustix_datapath_rx_worker_stream_coalesce_last_segment_ret;
module_param_named(rx_worker_stream_coalesce_last_segment_ret,
		   trustix_datapath_rx_worker_stream_coalesce_last_segment_ret,
		   int, 0444);

static unsigned int trustix_datapath_route_records;
module_param_named(route_records, trustix_datapath_route_records, uint, 0444);
MODULE_PARM_DESC(route_records, "Active TrustIX datapath route records");

static unsigned int trustix_datapath_session_records;
module_param_named(session_records, trustix_datapath_session_records, uint, 0444);
MODULE_PARM_DESC(session_records, "Active TrustIX datapath session records");

static unsigned int trustix_datapath_flow_records;
module_param_named(flow_records, trustix_datapath_flow_records, uint, 0444);
MODULE_PARM_DESC(flow_records, "Active TrustIX datapath flow records");

static unsigned int trustix_datapath_session_wire_records;
module_param_named(session_wire_records, trustix_datapath_session_wire_records,
		   uint, 0444);
MODULE_PARM_DESC(session_wire_records,
		 "Active TrustIX datapath session underlay wire records");

static unsigned int trustix_datapath_session_crypto_records;
module_param_named(session_crypto_records,
		   trustix_datapath_session_crypto_records, uint, 0444);
MODULE_PARM_DESC(session_crypto_records,
		 "Active TrustIX datapath session crypto records");

static int trustix_datapath_debug_last_outer_stage;
module_param_named(debug_last_outer_stage,
		   trustix_datapath_debug_last_outer_stage, int, 0444);
MODULE_PARM_DESC(debug_last_outer_stage,
		 "Last TrustIX outer hook debug stage");

static int trustix_datapath_debug_last_outer_ret;
module_param_named(debug_last_outer_ret, trustix_datapath_debug_last_outer_ret,
		   int, 0444);
MODULE_PARM_DESC(debug_last_outer_ret,
		 "Last TrustIX outer hook parse return code");

static int trustix_datapath_debug_last_worker_ret;
module_param_named(debug_last_worker_ret,
		   trustix_datapath_debug_last_worker_ret, int, 0444);
MODULE_PARM_DESC(debug_last_worker_ret,
		 "Last TrustIX RX worker queue return code");

static unsigned int trustix_datapath_debug_last_outer_protocol;
module_param_named(debug_last_outer_protocol,
		   trustix_datapath_debug_last_outer_protocol, uint, 0444);
MODULE_PARM_DESC(debug_last_outer_protocol,
		 "Last TrustIX outer hook IPv4 protocol");

static unsigned int trustix_datapath_debug_last_outer_src_port;
module_param_named(debug_last_outer_src_port,
		   trustix_datapath_debug_last_outer_src_port, uint, 0444);
MODULE_PARM_DESC(debug_last_outer_src_port,
		 "Last TrustIX outer hook source port");

static unsigned int trustix_datapath_debug_last_outer_dst_port;
module_param_named(debug_last_outer_dst_port,
		   trustix_datapath_debug_last_outer_dst_port, uint, 0444);
MODULE_PARM_DESC(debug_last_outer_dst_port,
		 "Last TrustIX outer hook destination port");

static unsigned int trustix_datapath_debug_last_outer_skb_len;
module_param_named(debug_last_outer_skb_len,
		   trustix_datapath_debug_last_outer_skb_len, uint, 0444);
MODULE_PARM_DESC(debug_last_outer_skb_len,
		 "Last TrustIX outer hook skb length");

static unsigned int trustix_datapath_debug_last_outer_ip_len;
module_param_named(debug_last_outer_ip_len,
		   trustix_datapath_debug_last_outer_ip_len, uint, 0444);
MODULE_PARM_DESC(debug_last_outer_ip_len,
		 "Last TrustIX outer hook IPv4 total length");

static unsigned int trustix_datapath_debug_last_outer_l4_len;
module_param_named(debug_last_outer_l4_len,
		   trustix_datapath_debug_last_outer_l4_len, uint, 0444);
MODULE_PARM_DESC(debug_last_outer_l4_len,
		 "Last TrustIX outer hook L4 length");

static unsigned int trustix_datapath_debug_last_outer_frame_len;
module_param_named(debug_last_outer_frame_len,
		   trustix_datapath_debug_last_outer_frame_len, uint, 0444);
MODULE_PARM_DESC(debug_last_outer_frame_len,
		 "Last TrustIX outer hook TIXT/TIXU frame length");

static unsigned int trustix_datapath_debug_last_outer_magic;
module_param_named(debug_last_outer_magic,
		   trustix_datapath_debug_last_outer_magic, uint, 0444);
MODULE_PARM_DESC(debug_last_outer_magic,
		 "Last TrustIX outer hook frame magic");

static unsigned int trustix_datapath_debug_last_outer_frame_flags;
module_param_named(debug_last_outer_frame_flags,
		   trustix_datapath_debug_last_outer_frame_flags, uint, 0444);
MODULE_PARM_DESC(debug_last_outer_frame_flags,
		 "Last TrustIX outer hook frame flags");

static unsigned int trustix_datapath_debug_last_outer_header_len;
module_param_named(debug_last_outer_header_len,
		   trustix_datapath_debug_last_outer_header_len, uint, 0444);
MODULE_PARM_DESC(debug_last_outer_header_len,
		 "Last TrustIX outer hook frame header length");

static unsigned int trustix_datapath_debug_last_outer_payload_len;
module_param_named(debug_last_outer_payload_len,
		   trustix_datapath_debug_last_outer_payload_len, uint, 0444);
MODULE_PARM_DESC(debug_last_outer_payload_len,
		 "Last TrustIX outer hook frame payload length");

static unsigned long long trustix_datapath_debug_last_outer_flow_id;
module_param_named(debug_last_outer_flow_id,
		   trustix_datapath_debug_last_outer_flow_id, ullong, 0444);
MODULE_PARM_DESC(debug_last_outer_flow_id,
		 "Last TrustIX outer hook frame flow ID");

static unsigned long long trustix_datapath_debug_udp_seen;
module_param_named(debug_udp_seen, trustix_datapath_debug_udp_seen, ullong,
		   0444);
MODULE_PARM_DESC(debug_udp_seen,
		 "TrustIX outer hook UDP packets observed for diagnostics");

static unsigned long long trustix_datapath_debug_udp_tix_seen;
module_param_named(debug_udp_tix_seen, trustix_datapath_debug_udp_tix_seen,
		   ullong, 0444);
MODULE_PARM_DESC(debug_udp_tix_seen,
		 "TrustIX outer hook UDP packets whose payload starts with TIXT/TIXU");

static unsigned int trustix_datapath_debug_last_udp_src_port;
module_param_named(debug_last_udp_src_port,
		   trustix_datapath_debug_last_udp_src_port, uint, 0444);
MODULE_PARM_DESC(debug_last_udp_src_port,
		 "Last TrustIX outer hook UDP source port");

static unsigned int trustix_datapath_debug_last_udp_dst_port;
module_param_named(debug_last_udp_dst_port,
		   trustix_datapath_debug_last_udp_dst_port, uint, 0444);
MODULE_PARM_DESC(debug_last_udp_dst_port,
		 "Last TrustIX outer hook UDP destination port");

static unsigned int trustix_datapath_debug_last_udp_total_len;
module_param_named(debug_last_udp_total_len,
		   trustix_datapath_debug_last_udp_total_len, uint, 0444);
MODULE_PARM_DESC(debug_last_udp_total_len,
		 "Last TrustIX outer hook UDP IPv4 total length");

static unsigned int trustix_datapath_debug_last_udp_len;
module_param_named(debug_last_udp_len, trustix_datapath_debug_last_udp_len,
		   uint, 0444);
MODULE_PARM_DESC(debug_last_udp_len,
		 "Last TrustIX outer hook UDP header length field");

static unsigned int trustix_datapath_debug_last_udp_magic;
module_param_named(debug_last_udp_magic, trustix_datapath_debug_last_udp_magic,
		   uint, 0444);
MODULE_PARM_DESC(debug_last_udp_magic,
		 "Last TrustIX outer hook UDP payload magic");

static unsigned int trustix_datapath_debug_last_udp_payload_len;
module_param_named(debug_last_udp_payload_len,
		   trustix_datapath_debug_last_udp_payload_len, uint, 0444);
MODULE_PARM_DESC(debug_last_udp_payload_len,
		 "Last TrustIX outer hook UDP payload length");

static DEFINE_RWLOCK(trustix_datapath_state_lock);
static DEFINE_MUTEX(trustix_datapath_selftest_mutex);
static struct trustix_datapath_state_table trustix_datapath_routes;
static struct trustix_datapath_state_table trustix_datapath_sessions;
static struct trustix_datapath_state_table trustix_datapath_flows;
static struct trustix_datapath_state_table trustix_datapath_session_wires;
static struct trustix_datapath_state_table trustix_datapath_session_crypto;
static trustix_kernel_direct_datapath_ready_fn
	trustix_datapath_crypto_ready;
static trustix_kernel_direct_datapath_selftest_fn
	trustix_datapath_crypto_selftest;
static trustix_kernel_direct_slot_generation_fn
	trustix_datapath_crypto_slot_generation;
static trustix_kernel_direct_reserve_sequences_fn
	trustix_datapath_crypto_reserve_sequences;
static trustix_kernel_direct_seal_batch_generation_fn
	trustix_datapath_crypto_seal_batch;
static trustix_kernel_direct_open_replay_batch_fn
	trustix_datapath_crypto_open_replay_batch;
static struct trustix_datapath_route_dst_cache_entry
	*trustix_datapath_route_dst_cache;
static __u32 trustix_datapath_route_dst_cache_capacity;
static struct trustix_datapath_session_route_cache_entry
	*trustix_datapath_session_route_cache;
static __u32 trustix_datapath_session_route_cache_capacity;
static struct trustix_datapath_session_flow_cache_entry
	*trustix_datapath_session_flow_cache;
static __u32 trustix_datapath_session_flow_cache_capacity;
static struct trustix_datapath_session_wire_tuple_cache_entry
	*trustix_datapath_session_wire_tuple_cache;
static __u32 trustix_datapath_session_wire_tuple_cache_capacity;
static __u64 trustix_datapath_state_upserts;
static __u64 trustix_datapath_state_deletes;
static __u64 trustix_datapath_state_clears;
static __u64 trustix_datapath_state_get_hits;
static __u64 trustix_datapath_state_get_misses;
static __u64 trustix_datapath_state_table_full;
static __u64 trustix_datapath_packets_seen;
static __u64 trustix_datapath_bytes_seen;
static __u64 trustix_datapath_packet_parse_errors;
static __u64 trustix_datapath_packet_route_misses;
static __u64 trustix_datapath_packet_session_misses;
static __u64 trustix_datapath_packet_unicast_routes;
static __u64 trustix_datapath_packet_local_routes;
static __u64 trustix_datapath_packet_blackhole_routes;
static __u64 trustix_datapath_packet_reject_routes;

static unsigned long long trustix_datapath_tx_plaintext_packets;
module_param_named(tx_plaintext_packets,
		   trustix_datapath_tx_plaintext_packets, ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_packets,
		 "TrustIX plaintext TX packets encapsulated by the full datapath");

static unsigned long long trustix_datapath_tx_plaintext_bytes;
module_param_named(tx_plaintext_bytes,
		   trustix_datapath_tx_plaintext_bytes, ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_bytes,
		 "TrustIX plaintext TX inner IPv4 bytes encapsulated by the full datapath");

static unsigned long long trustix_datapath_secure_tx_packets;
module_param_named(secure_tx_packets, trustix_datapath_secure_tx_packets,
		   ullong, 0444);
MODULE_PARM_DESC(secure_tx_packets,
		 "Secure TIX-TCP TX packets encapsulated by the full datapath");

static unsigned long long trustix_datapath_secure_tx_frames;
module_param_named(secure_tx_frames, trustix_datapath_secure_tx_frames,
		   ullong, 0444);
MODULE_PARM_DESC(secure_tx_frames,
		 "Secure TIX-TCP frames sealed by the full datapath");

static unsigned long long trustix_datapath_secure_tx_bytes;
module_param_named(secure_tx_bytes, trustix_datapath_secure_tx_bytes,
		   ullong, 0444);
MODULE_PARM_DESC(secure_tx_bytes,
		 "Secure TIX-TCP inner IPv4 bytes sealed by the full datapath");

static unsigned long long trustix_datapath_secure_tx_batches;
module_param_named(secure_tx_batches, trustix_datapath_secure_tx_batches,
		   ullong, 0444);
MODULE_PARM_DESC(secure_tx_batches,
		 "Secure TIX-TCP AEAD TX batches completed by the full datapath");

static unsigned long long trustix_datapath_secure_tx_errors;
module_param_named(secure_tx_errors, trustix_datapath_secure_tx_errors,
		   ullong, 0444);
MODULE_PARM_DESC(secure_tx_errors,
		 "Secure TIX-TCP TX build, generation, or AEAD errors");

static unsigned long long trustix_datapath_secure_tx_stale;
module_param_named(secure_tx_stale, trustix_datapath_secure_tx_stale,
		   ullong, 0444);
MODULE_PARM_DESC(secure_tx_stale,
		 "Secure TIX-TCP TX attempts rejected after key generation changes");

static unsigned long long trustix_datapath_secure_rx_packets;
module_param_named(secure_rx_packets, trustix_datapath_secure_rx_packets,
		   ullong, 0444);
MODULE_PARM_DESC(secure_rx_packets,
		 "Secure TIX-TCP outer packets opened by the full datapath");

static unsigned long long trustix_datapath_secure_rx_frames;
module_param_named(secure_rx_frames, trustix_datapath_secure_rx_frames,
		   ullong, 0444);
MODULE_PARM_DESC(secure_rx_frames,
		 "Secure TIX-TCP frames opened by the full datapath");

static unsigned long long trustix_datapath_secure_rx_bytes;
module_param_named(secure_rx_bytes, trustix_datapath_secure_rx_bytes,
		   ullong, 0444);
MODULE_PARM_DESC(secure_rx_bytes,
		 "Secure TIX-TCP inner IPv4 bytes opened by the full datapath");

static unsigned long long trustix_datapath_secure_rx_errors;
module_param_named(secure_rx_errors, trustix_datapath_secure_rx_errors,
		   ullong, 0444);
MODULE_PARM_DESC(secure_rx_errors,
		 "Secure TIX-TCP RX parse, generation, replay, or AEAD errors");

static unsigned long long trustix_datapath_secure_rx_stale;
module_param_named(secure_rx_stale, trustix_datapath_secure_rx_stale,
		   ullong, 0444);
MODULE_PARM_DESC(secure_rx_stale,
		 "Secure TIX-TCP RX frames rejected as stale or replayed");

static unsigned long long trustix_datapath_secure_rx_writable_errors;
module_param_named(secure_rx_writable_errors,
		   trustix_datapath_secure_rx_writable_errors, ullong, 0444);
MODULE_PARM_DESC(secure_rx_writable_errors,
		 "Secure TIX-TCP RX skbs that could not be made writable");

static unsigned long long trustix_datapath_secure_rx_frame_limit_errors;
module_param_named(secure_rx_frame_limit_errors,
		   trustix_datapath_secure_rx_frame_limit_errors, ullong, 0444);
MODULE_PARM_DESC(secure_rx_frame_limit_errors,
		 "Secure TIX-TCP RX packets exceeding the per-skb frame limit");

static unsigned long long trustix_datapath_secure_rx_frame_parse_errors;
module_param_named(secure_rx_frame_parse_errors,
		   trustix_datapath_secure_rx_frame_parse_errors, ullong, 0444);
MODULE_PARM_DESC(secure_rx_frame_parse_errors,
		 "Secure TIX-TCP RX frame header parse failures");

static unsigned long long trustix_datapath_secure_rx_frame_validate_errors;
module_param_named(secure_rx_frame_validate_errors,
		   trustix_datapath_secure_rx_frame_validate_errors, ullong, 0444);
MODULE_PARM_DESC(secure_rx_frame_validate_errors,
		 "Secure TIX-TCP RX frame metadata validation failures");

static unsigned long long trustix_datapath_secure_rx_plan_errors;
module_param_named(secure_rx_plan_errors,
		   trustix_datapath_secure_rx_plan_errors, ullong, 0444);
MODULE_PARM_DESC(secure_rx_plan_errors,
		 "Secure TIX-TCP RX session or crypto-plan failures");

static unsigned long long trustix_datapath_secure_rx_header_errors;
module_param_named(secure_rx_header_errors,
		   trustix_datapath_secure_rx_header_errors, ullong, 0444);
MODULE_PARM_DESC(secure_rx_header_errors,
		 "Secure TIX-TCP RX secure-header validation failures");

static unsigned long long trustix_datapath_secure_rx_crypto_errors;
module_param_named(secure_rx_crypto_errors,
		   trustix_datapath_secure_rx_crypto_errors, ullong, 0444);
MODULE_PARM_DESC(secure_rx_crypto_errors,
		 "Secure TIX-TCP RX AEAD or replay-batch failures");

static unsigned long long trustix_datapath_secure_rx_checksum_errors;
module_param_named(secure_rx_checksum_errors,
		   trustix_datapath_secure_rx_checksum_errors, ullong, 0444);
MODULE_PARM_DESC(secure_rx_checksum_errors,
		 "Secure TIX-TCP RX inner checksum validation failures");

static unsigned long long trustix_datapath_secure_rx_layout_errors;
module_param_named(secure_rx_layout_errors,
		   trustix_datapath_secure_rx_layout_errors, ullong, 0444);
MODULE_PARM_DESC(secure_rx_layout_errors,
		 "Secure TIX-TCP RX compaction or skb layout failures");

static unsigned long long trustix_datapath_secure_rx_copy_errors;
module_param_named(secure_rx_copy_errors,
		   trustix_datapath_secure_rx_copy_errors, ullong, 0444);
MODULE_PARM_DESC(secure_rx_copy_errors,
		 "Secure TIX-TCP RX skb-to-scratch copy failures");

static unsigned long long trustix_datapath_secure_rx_delivery_errors;
module_param_named(secure_rx_delivery_errors,
		   trustix_datapath_secure_rx_delivery_errors, ullong, 0444);
MODULE_PARM_DESC(secure_rx_delivery_errors,
		 "Secure TIX-TCP RX plaintext worker delivery failures");

static unsigned long long trustix_datapath_secure_rx_other_errors;
module_param_named(secure_rx_other_errors,
		   trustix_datapath_secure_rx_other_errors, ullong, 0444);
MODULE_PARM_DESC(secure_rx_other_errors,
		 "Secure TIX-TCP RX failures without a classified stage");

static unsigned long long trustix_datapath_secure_rx_gso_packets;
module_param_named(secure_rx_gso_packets,
		   trustix_datapath_secure_rx_gso_packets, ullong, 0444);
MODULE_PARM_DESC(secure_rx_gso_packets,
		 "Secure TIX-TCP RX packets carrying GSO/GRO metadata");

static unsigned long long trustix_datapath_secure_rx_nonlinear_packets;
module_param_named(secure_rx_nonlinear_packets,
		   trustix_datapath_secure_rx_nonlinear_packets, ullong, 0444);
MODULE_PARM_DESC(secure_rx_nonlinear_packets,
		 "Secure TIX-TCP RX packets with nonlinear skb storage");

static unsigned long long trustix_datapath_secure_rx_cloned_packets;
module_param_named(secure_rx_cloned_packets,
		   trustix_datapath_secure_rx_cloned_packets, ullong, 0444);
MODULE_PARM_DESC(secure_rx_cloned_packets,
		 "Secure TIX-TCP RX packets with cloned skb storage");

static unsigned int trustix_datapath_secure_rx_max_frames;
module_param_named(secure_rx_max_frames,
		   trustix_datapath_secure_rx_max_frames, uint, 0444);
MODULE_PARM_DESC(secure_rx_max_frames,
		 "Largest successfully opened secure TIX-TCP frame batch");

static int trustix_datapath_secure_rx_last_error;
module_param_named(secure_rx_last_error,
		   trustix_datapath_secure_rx_last_error, int, 0444);
MODULE_PARM_DESC(secure_rx_last_error,
		 "Last secure TIX-TCP RX failure errno");

static unsigned int trustix_datapath_secure_rx_last_error_stage;
module_param_named(secure_rx_last_error_stage,
		   trustix_datapath_secure_rx_last_error_stage, uint, 0444);
MODULE_PARM_DESC(secure_rx_last_error_stage,
		 "Last secure TIX-TCP RX failure stage");

static void trustix_datapath_secure_rx_record_error(
	enum trustix_datapath_secure_rx_error_stage stage, int ret)
{
	WRITE_ONCE(trustix_datapath_secure_rx_last_error, ret ?: -EIO);
	WRITE_ONCE(trustix_datapath_secure_rx_last_error_stage, stage);
	switch (stage) {
	case TRUSTIX_DATAPATH_SECURE_RX_ERROR_WRITABLE:
		trustix_datapath_secure_rx_writable_errors++;
		break;
	case TRUSTIX_DATAPATH_SECURE_RX_ERROR_FRAME_LIMIT:
		trustix_datapath_secure_rx_frame_limit_errors++;
		break;
	case TRUSTIX_DATAPATH_SECURE_RX_ERROR_FRAME_PARSE:
		trustix_datapath_secure_rx_frame_parse_errors++;
		break;
	case TRUSTIX_DATAPATH_SECURE_RX_ERROR_FRAME_VALIDATE:
		trustix_datapath_secure_rx_frame_validate_errors++;
		break;
	case TRUSTIX_DATAPATH_SECURE_RX_ERROR_PLAN:
		trustix_datapath_secure_rx_plan_errors++;
		break;
	case TRUSTIX_DATAPATH_SECURE_RX_ERROR_HEADER:
		trustix_datapath_secure_rx_header_errors++;
		break;
	case TRUSTIX_DATAPATH_SECURE_RX_ERROR_CRYPTO:
		trustix_datapath_secure_rx_crypto_errors++;
		break;
	case TRUSTIX_DATAPATH_SECURE_RX_ERROR_CHECKSUM:
		trustix_datapath_secure_rx_checksum_errors++;
		break;
	case TRUSTIX_DATAPATH_SECURE_RX_ERROR_LAYOUT:
		trustix_datapath_secure_rx_layout_errors++;
		break;
	case TRUSTIX_DATAPATH_SECURE_RX_ERROR_COPY:
		trustix_datapath_secure_rx_copy_errors++;
		break;
	case TRUSTIX_DATAPATH_SECURE_RX_ERROR_DELIVERY:
		trustix_datapath_secure_rx_delivery_errors++;
		break;
	default:
		trustix_datapath_secure_rx_other_errors++;
		break;
	}
}

static unsigned long long
	trustix_datapath_secure_tx_inner_tcp_checksum_partial;
module_param_named(secure_tx_inner_tcp_checksum_partial,
		   trustix_datapath_secure_tx_inner_tcp_checksum_partial,
		   ullong, 0444);
MODULE_PARM_DESC(secure_tx_inner_tcp_checksum_partial,
		 "Secure TIX-TCP TX frames sealed with an inner TCP CHECKSUM_PARTIAL seed");

static unsigned long long
	trustix_datapath_secure_tx_inner_tcp_checksum_partial_fallbacks;
module_param_named(secure_tx_inner_tcp_checksum_partial_fallbacks,
		   trustix_datapath_secure_tx_inner_tcp_checksum_partial_fallbacks,
		   ullong, 0444);
MODULE_PARM_DESC(secure_tx_inner_tcp_checksum_partial_fallbacks,
		 "Negotiated secure TX frames that required a full-checksum fallback");

static unsigned long long
	trustix_datapath_secure_rx_inner_tcp_checksum_partial;
module_param_named(secure_rx_inner_tcp_checksum_partial,
		   trustix_datapath_secure_rx_inner_tcp_checksum_partial,
		   ullong, 0444);
MODULE_PARM_DESC(secure_rx_inner_tcp_checksum_partial,
		 "Secure TIX-TCP RX frames validated with an inner TCP CHECKSUM_PARTIAL seed");

static unsigned long long trustix_datapath_secure_rx_inner_tcp_checksum_full;
module_param_named(secure_rx_inner_tcp_checksum_full,
		   trustix_datapath_secure_rx_inner_tcp_checksum_full,
		   ullong, 0444);
MODULE_PARM_DESC(secure_rx_inner_tcp_checksum_full,
		 "Secure TIX-TCP RX frames validated with a complete inner TCP checksum");

static unsigned long long
	trustix_datapath_secure_rx_inner_tcp_checksum_errors;
module_param_named(secure_rx_inner_tcp_checksum_errors,
		   trustix_datapath_secure_rx_inner_tcp_checksum_errors,
		   ullong, 0444);
MODULE_PARM_DESC(secure_rx_inner_tcp_checksum_errors,
		 "Secure TIX-TCP RX frames rejected for invalid inner TCP checksum metadata");

static unsigned long long
	trustix_datapath_tx_plaintext_inner_tcp_checksum_partial;
module_param_named(tx_plaintext_inner_tcp_checksum_partial,
		   trustix_datapath_tx_plaintext_inner_tcp_checksum_partial,
		   ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_inner_tcp_checksum_partial,
		 "TrustIX plaintext TX frames emitted with inner TCP CHECKSUM_PARTIAL");

static unsigned long long
	trustix_datapath_tx_plaintext_inner_tcp_checksum_partial_fallbacks;
module_param_named(tx_plaintext_inner_tcp_checksum_partial_fallbacks,
		   trustix_datapath_tx_plaintext_inner_tcp_checksum_partial_fallbacks,
		   ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_inner_tcp_checksum_partial_fallbacks,
		 "Negotiated plaintext TX frames that required a full-checksum fallback");

static unsigned long long trustix_datapath_tx_plaintext_inner_gso_attempts;
module_param_named(tx_plaintext_inner_gso_attempts,
		   trustix_datapath_tx_plaintext_inner_gso_attempts, ullong,
		   0444);
MODULE_PARM_DESC(tx_plaintext_inner_gso_attempts,
		 "Negotiated plaintext TX GSO packets considered for inner-GSO preservation");

static unsigned long long trustix_datapath_tx_plaintext_inner_gso_packets;
module_param_named(tx_plaintext_inner_gso_packets,
		   trustix_datapath_tx_plaintext_inner_gso_packets, ullong,
		   0444);
MODULE_PARM_DESC(tx_plaintext_inner_gso_packets,
		 "Plaintext TX GSO packets emitted with inner-GSO metadata");

static unsigned long long trustix_datapath_tx_plaintext_inner_gso_segments;
module_param_named(tx_plaintext_inner_gso_segments,
		   trustix_datapath_tx_plaintext_inner_gso_segments, ullong,
		   0444);
MODULE_PARM_DESC(tx_plaintext_inner_gso_segments,
		 "Inner TCP segments preserved by plaintext TX inner-GSO packets");

static unsigned long long trustix_datapath_tx_plaintext_inner_gso_fallbacks;
module_param_named(tx_plaintext_inner_gso_fallbacks,
		   trustix_datapath_tx_plaintext_inner_gso_fallbacks, ullong,
		   0444);
MODULE_PARM_DESC(tx_plaintext_inner_gso_fallbacks,
		 "Negotiated plaintext TX inner-GSO attempts that used the existing segmentation path");

static unsigned long long trustix_datapath_tx_plaintext_inner_gso_errors;
module_param_named(tx_plaintext_inner_gso_errors,
		   trustix_datapath_tx_plaintext_inner_gso_errors, ullong,
		   0444);
MODULE_PARM_DESC(tx_plaintext_inner_gso_errors,
		 "Plaintext TX inner-GSO allocation, packet, or queue errors");

static unsigned long long
	trustix_datapath_tx_plaintext_inner_gso_metadata_scrubs;
module_param_named(tx_plaintext_inner_gso_metadata_scrubs,
		   trustix_datapath_tx_plaintext_inner_gso_metadata_scrubs,
		   ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_inner_gso_metadata_scrubs,
		 "Plaintext TX inner-GSO clones scrubbed before outer transmission");

static unsigned long long trustix_datapath_tx_plaintext_gso_skips;
module_param_named(tx_plaintext_gso_skips,
		   trustix_datapath_tx_plaintext_gso_skips, ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_gso_skips,
		 "TrustIX plaintext TX packets skipped because the ingress skb is GSO");

static unsigned long long trustix_datapath_tx_plaintext_gso_segments;
module_param_named(tx_plaintext_gso_segments,
		   trustix_datapath_tx_plaintext_gso_segments, ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_gso_segments,
		 "TrustIX plaintext TX software GSO segments encapsulated by the full datapath");

static unsigned long long trustix_datapath_tx_plaintext_gso_errors;
module_param_named(tx_plaintext_gso_errors,
		   trustix_datapath_tx_plaintext_gso_errors, ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_gso_errors,
		 "TrustIX plaintext TX GSO segmentation, queueing, or encapsulation errors");

static unsigned long long trustix_datapath_tx_plaintext_outer_gso_packets;
module_param_named(tx_plaintext_outer_gso_packets,
		   trustix_datapath_tx_plaintext_outer_gso_packets, ullong,
		   0444);
MODULE_PARM_DESC(tx_plaintext_outer_gso_packets,
		 "TrustIX plaintext TX outer TCP GSO skbs built by the full datapath");

static unsigned long long trustix_datapath_tx_plaintext_outer_gso_segments;
module_param_named(tx_plaintext_outer_gso_segments,
		   trustix_datapath_tx_plaintext_outer_gso_segments, ullong,
		   0444);
MODULE_PARM_DESC(tx_plaintext_outer_gso_segments,
		 "TrustIX plaintext TX inner TCP segments carried by outer TCP GSO skbs");

static unsigned long long trustix_datapath_tx_plaintext_ipv4_fragment_packets;
module_param_named(tx_plaintext_ipv4_fragment_packets,
		   trustix_datapath_tx_plaintext_ipv4_fragment_packets, ullong,
		   0444);
MODULE_PARM_DESC(tx_plaintext_ipv4_fragment_packets,
		 "TrustIX plaintext TX oversized inner IPv4 packets fragmented before encapsulation");

static unsigned long long trustix_datapath_tx_plaintext_ipv4_fragments;
module_param_named(tx_plaintext_ipv4_fragments,
		   trustix_datapath_tx_plaintext_ipv4_fragments, ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_ipv4_fragments,
		 "TrustIX plaintext TX inner IPv4 fragments emitted before encapsulation");

static unsigned long long trustix_datapath_tx_plaintext_ipv4_fragment_errors;
module_param_named(tx_plaintext_ipv4_fragment_errors,
		   trustix_datapath_tx_plaintext_ipv4_fragment_errors, ullong,
		   0444);
MODULE_PARM_DESC(tx_plaintext_ipv4_fragment_errors,
		 "TrustIX plaintext TX inner IPv4 fragmentation errors");

static unsigned long long trustix_datapath_tx_plaintext_outer_gso_fallbacks;
module_param_named(tx_plaintext_outer_gso_fallbacks,
		   trustix_datapath_tx_plaintext_outer_gso_fallbacks, ullong,
		   0444);
MODULE_PARM_DESC(tx_plaintext_outer_gso_fallbacks,
		 "TrustIX plaintext TX GSO skbs that fell back to legacy software segmentation");

static unsigned long long trustix_datapath_tx_plaintext_outer_gso_errors;
module_param_named(tx_plaintext_outer_gso_errors,
		   trustix_datapath_tx_plaintext_outer_gso_errors, ullong,
		   0444);
MODULE_PARM_DESC(tx_plaintext_outer_gso_errors,
		 "TrustIX plaintext TX outer TCP GSO build or xmit failures");

static DEFINE_PER_CPU(unsigned long long,
	trustix_datapath_tx_plaintext_outer_gso_page_pool_attempts);
module_param_cb(tx_plaintext_outer_gso_page_pool_attempts,
		&trustix_datapath_percpu_ullong_ro_ops,
		&trustix_datapath_tx_plaintext_outer_gso_page_pool_attempts,
		0444);
MODULE_PARM_DESC(tx_plaintext_outer_gso_page_pool_attempts,
		 "TrustIX plaintext TX outer TCP GSO page-pool allocation attempts");

static DEFINE_PER_CPU(unsigned long long,
	trustix_datapath_tx_plaintext_outer_gso_page_pool_hits);
module_param_cb(tx_plaintext_outer_gso_page_pool_hits,
		&trustix_datapath_percpu_ullong_ro_ops,
		&trustix_datapath_tx_plaintext_outer_gso_page_pool_hits,
		0444);
MODULE_PARM_DESC(tx_plaintext_outer_gso_page_pool_hits,
		 "TrustIX plaintext TX outer TCP GSO skbs backed by reusable page-pool pages");

static DEFINE_PER_CPU(unsigned long long,
	trustix_datapath_tx_plaintext_outer_gso_page_pool_fallbacks);
module_param_cb(tx_plaintext_outer_gso_page_pool_fallbacks,
		&trustix_datapath_percpu_ullong_ro_ops,
		&trustix_datapath_tx_plaintext_outer_gso_page_pool_fallbacks,
		0444);
MODULE_PARM_DESC(tx_plaintext_outer_gso_page_pool_fallbacks,
		 "TrustIX plaintext TX outer TCP GSO page-pool attempts that safely fell back to alloc_skb");

static DEFINE_PER_CPU(unsigned long long,
	trustix_datapath_tx_plaintext_outer_gso_page_pool_errors);
module_param_cb(tx_plaintext_outer_gso_page_pool_errors,
		&trustix_datapath_percpu_ullong_ro_ops,
		&trustix_datapath_tx_plaintext_outer_gso_page_pool_errors,
		0444);
MODULE_PARM_DESC(tx_plaintext_outer_gso_page_pool_errors,
		 "TrustIX plaintext TX outer TCP GSO page-pool allocation or skb build failures");

#if TRUSTIX_DATAPATH_HAVE_TX_OUTER_GSO_PAGE_POOL
static DEFINE_PER_CPU(struct page_pool *,
	trustix_datapath_tx_plaintext_outer_gso_page_pools);

static struct page_pool *
trustix_datapath_create_tx_outer_gso_page_pool(
	const struct page_pool_params *params, int cpu)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	return page_pool_create_percpu(params, cpu);
#else
	(void)cpu;
	return page_pool_create(params);
#endif
}
#endif

static unsigned long long trustix_datapath_tx_plaintext_payload_fast_copy_linear_hits;
module_param_named(tx_plaintext_payload_fast_copy_linear_hits,
		   trustix_datapath_tx_plaintext_payload_fast_copy_linear_hits,
		   ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_payload_fast_copy_linear_hits,
		 "TrustIX plaintext TX payload copies served from linear skb data");

static unsigned long long trustix_datapath_tx_plaintext_payload_fast_copy_frag_hits;
module_param_named(tx_plaintext_payload_fast_copy_frag_hits,
		   trustix_datapath_tx_plaintext_payload_fast_copy_frag_hits,
		   ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_payload_fast_copy_frag_hits,
		 "TrustIX plaintext TX payload copies served from one skb frag");

static unsigned long long trustix_datapath_tx_plaintext_payload_fast_copy_fallbacks;
module_param_named(tx_plaintext_payload_fast_copy_fallbacks,
		   trustix_datapath_tx_plaintext_payload_fast_copy_fallbacks,
		   ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_payload_fast_copy_fallbacks,
		 "TrustIX plaintext TX payload copies that fell back to skb_copy_bits");

static unsigned long long trustix_datapath_tx_plaintext_payload_fast_copy_errors;
module_param_named(tx_plaintext_payload_fast_copy_errors,
		   trustix_datapath_tx_plaintext_payload_fast_copy_errors,
		   ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_payload_fast_copy_errors,
		 "TrustIX plaintext TX payload copy errors after fast-copy fallback");

static DEFINE_PER_CPU(unsigned long long,
	trustix_datapath_tx_plaintext_payload_copy_csum_attempts);
module_param_cb(tx_plaintext_payload_copy_csum_attempts,
		&trustix_datapath_percpu_ullong_ro_ops,
		&trustix_datapath_tx_plaintext_payload_copy_csum_attempts,
		0444);
MODULE_PARM_DESC(tx_plaintext_payload_copy_csum_attempts,
		 "TrustIX plaintext TX payload copy-and-checksum attempts");

static DEFINE_PER_CPU(unsigned long long,
	trustix_datapath_tx_plaintext_payload_copy_csum_hits);
module_param_cb(tx_plaintext_payload_copy_csum_hits,
		&trustix_datapath_percpu_ullong_ro_ops,
		&trustix_datapath_tx_plaintext_payload_copy_csum_hits,
		0444);
MODULE_PARM_DESC(tx_plaintext_payload_copy_csum_hits,
		 "TrustIX plaintext TX payloads copied with checksum accumulation");

static DEFINE_PER_CPU(unsigned long long,
	trustix_datapath_tx_plaintext_payload_copy_csum_fallbacks);
module_param_cb(tx_plaintext_payload_copy_csum_fallbacks,
		&trustix_datapath_percpu_ullong_ro_ops,
		&trustix_datapath_tx_plaintext_payload_copy_csum_fallbacks,
		0444);
MODULE_PARM_DESC(tx_plaintext_payload_copy_csum_fallbacks,
		 "TrustIX plaintext TX copy-and-checksum attempts served by the generic skb helper");

static DEFINE_PER_CPU(unsigned long long,
	trustix_datapath_tx_plaintext_payload_copy_csum_errors);
module_param_cb(tx_plaintext_payload_copy_csum_errors,
		&trustix_datapath_percpu_ullong_ro_ops,
		&trustix_datapath_tx_plaintext_payload_copy_csum_errors,
		0444);
MODULE_PARM_DESC(tx_plaintext_payload_copy_csum_errors,
		 "TrustIX plaintext TX payload copy-and-checksum validation errors");

static unsigned long long trustix_datapath_tx_plaintext_encrypted_skips;
module_param_named(tx_plaintext_encrypted_skips,
		   trustix_datapath_tx_plaintext_encrypted_skips, ullong,
		   0444);
MODULE_PARM_DESC(tx_plaintext_encrypted_skips,
		 "TrustIX plaintext TX packets skipped because the selected session is encrypted");

static unsigned long long trustix_datapath_tx_plaintext_route_misses;
module_param_named(tx_plaintext_route_misses,
		   trustix_datapath_tx_plaintext_route_misses, ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_route_misses,
		 "TrustIX plaintext TX packets without a kernel route/session/wire match");

static unsigned long long trustix_datapath_tx_plaintext_no_routes;
module_param_named(tx_plaintext_no_routes,
		   trustix_datapath_tx_plaintext_no_routes, ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_no_routes,
		 "TrustIX plaintext TX packets without a matching route record");

static unsigned long long trustix_datapath_tx_plaintext_non_unicast_routes;
module_param_named(tx_plaintext_non_unicast_routes,
		   trustix_datapath_tx_plaintext_non_unicast_routes, ullong,
		   0444);
MODULE_PARM_DESC(tx_plaintext_non_unicast_routes,
		 "TrustIX plaintext TX packets whose matching route is not unicast");

static unsigned long long trustix_datapath_tx_plaintext_no_sessions;
module_param_named(tx_plaintext_no_sessions,
		   trustix_datapath_tx_plaintext_no_sessions, ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_no_sessions,
		 "TrustIX plaintext TX packets without a matching session record");

static unsigned long long trustix_datapath_tx_plaintext_no_wires;
module_param_named(tx_plaintext_no_wires,
		   trustix_datapath_tx_plaintext_no_wires, ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_no_wires,
		 "TrustIX plaintext TX packets without a matching session wire record");

static unsigned long long trustix_datapath_tx_plaintext_stale_wires;
module_param_named(tx_plaintext_stale_wires,
		   trustix_datapath_tx_plaintext_stale_wires, ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_stale_wires,
		 "TrustIX plaintext TX packets whose session wire was stale");

static unsigned long long trustix_datapath_tx_plaintext_unsupported_transports;
module_param_named(tx_plaintext_unsupported_transports,
		   trustix_datapath_tx_plaintext_unsupported_transports, ullong,
		   0444);
MODULE_PARM_DESC(tx_plaintext_unsupported_transports,
		 "TrustIX plaintext TX packets whose session wire transport is unsupported");

static unsigned long long trustix_datapath_tx_plaintext_invalid_plans;
module_param_named(tx_plaintext_invalid_plans,
		   trustix_datapath_tx_plaintext_invalid_plans, ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_invalid_plans,
		 "TrustIX plaintext TX packets whose selected TX plan is incomplete");

static int trustix_datapath_tx_plaintext_last_plan_ret;
module_param_named(tx_plaintext_last_plan_ret,
		   trustix_datapath_tx_plaintext_last_plan_ret, int, 0444);
MODULE_PARM_DESC(tx_plaintext_last_plan_ret,
		 "Last TrustIX plaintext TX plan error code");

static unsigned int trustix_datapath_tx_plaintext_last_src_ipv4;
module_param_named(tx_plaintext_last_src_ipv4,
		   trustix_datapath_tx_plaintext_last_src_ipv4, uint, 0444);
MODULE_PARM_DESC(tx_plaintext_last_src_ipv4,
		 "Last TrustIX plaintext TX source IPv4 in host byte order");

static unsigned int trustix_datapath_tx_plaintext_last_dst_ipv4;
module_param_named(tx_plaintext_last_dst_ipv4,
		   trustix_datapath_tx_plaintext_last_dst_ipv4, uint, 0444);
MODULE_PARM_DESC(tx_plaintext_last_dst_ipv4,
		 "Last TrustIX plaintext TX destination IPv4 in host byte order");

static unsigned int trustix_datapath_tx_plaintext_last_src_port;
module_param_named(tx_plaintext_last_src_port,
		   trustix_datapath_tx_plaintext_last_src_port, uint, 0444);
MODULE_PARM_DESC(tx_plaintext_last_src_port,
		 "Last TrustIX plaintext TX source port");

static unsigned int trustix_datapath_tx_plaintext_last_dst_port;
module_param_named(tx_plaintext_last_dst_port,
		   trustix_datapath_tx_plaintext_last_dst_port, uint, 0444);
MODULE_PARM_DESC(tx_plaintext_last_dst_port,
		 "Last TrustIX plaintext TX destination port");

static unsigned int trustix_datapath_tx_plaintext_last_protocol;
module_param_named(tx_plaintext_last_protocol,
		   trustix_datapath_tx_plaintext_last_protocol, uint, 0444);
MODULE_PARM_DESC(tx_plaintext_last_protocol,
		 "Last TrustIX plaintext TX IPv4 protocol");

static unsigned long long trustix_datapath_tx_plaintext_build_errors;
module_param_named(tx_plaintext_build_errors,
		   trustix_datapath_tx_plaintext_build_errors, ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_build_errors,
		 "TrustIX plaintext TX packet allocation, copy, or framing errors");

static int trustix_datapath_tx_plaintext_last_build_ret;
module_param_named(tx_plaintext_last_build_ret,
		   trustix_datapath_tx_plaintext_last_build_ret, int, 0444);
MODULE_PARM_DESC(tx_plaintext_last_build_ret,
		 "Last TrustIX plaintext TX packet build error code");

static unsigned int trustix_datapath_tx_plaintext_last_build_stage;
module_param_named(tx_plaintext_last_build_stage,
		   trustix_datapath_tx_plaintext_last_build_stage, uint, 0444);
MODULE_PARM_DESC(tx_plaintext_last_build_stage,
		 "Last TrustIX plaintext TX packet build error stage");

static unsigned int trustix_datapath_tx_plaintext_last_build_inner_len;
module_param_named(tx_plaintext_last_build_inner_len,
		   trustix_datapath_tx_plaintext_last_build_inner_len, uint,
		   0444);
MODULE_PARM_DESC(tx_plaintext_last_build_inner_len,
		 "Last TrustIX plaintext TX build-error inner packet length");

static unsigned int trustix_datapath_tx_plaintext_last_build_skb_len;
module_param_named(tx_plaintext_last_build_skb_len,
		   trustix_datapath_tx_plaintext_last_build_skb_len, uint,
		   0444);
MODULE_PARM_DESC(tx_plaintext_last_build_skb_len,
		 "Last TrustIX plaintext TX build-error skb length");

static unsigned int trustix_datapath_tx_plaintext_last_build_network_offset;
module_param_named(tx_plaintext_last_build_network_offset,
		   trustix_datapath_tx_plaintext_last_build_network_offset,
		   uint, 0444);
MODULE_PARM_DESC(tx_plaintext_last_build_network_offset,
		 "Last TrustIX plaintext TX build-error skb network offset");

static unsigned int trustix_datapath_tx_plaintext_last_build_protocol;
module_param_named(tx_plaintext_last_build_protocol,
		   trustix_datapath_tx_plaintext_last_build_protocol, uint,
		   0444);
MODULE_PARM_DESC(tx_plaintext_last_build_protocol,
		 "Last TrustIX plaintext TX build-error IPv4 protocol");

static unsigned long long trustix_datapath_tx_plaintext_xmit_errors;
module_param_named(tx_plaintext_xmit_errors,
		   trustix_datapath_tx_plaintext_xmit_errors, ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_xmit_errors,
		 "TrustIX plaintext TX underlay route or transmit errors");

static unsigned long long trustix_datapath_tx_plaintext_inline_xmit_packets;
module_param_named(tx_plaintext_inline_xmit_packets,
		   trustix_datapath_tx_plaintext_inline_xmit_packets, ullong,
		   0444);
MODULE_PARM_DESC(tx_plaintext_inline_xmit_packets,
		 "TrustIX plaintext TX packets sent directly from the hook path");

static unsigned long long trustix_datapath_tx_plaintext_inline_xmit_errors;
module_param_named(tx_plaintext_inline_xmit_errors,
		   trustix_datapath_tx_plaintext_inline_xmit_errors, ullong,
		   0444);
MODULE_PARM_DESC(tx_plaintext_inline_xmit_errors,
		 "TrustIX plaintext TX direct hook-path send failures");

static unsigned long long trustix_datapath_tx_plaintext_direct_xmit_packets;
module_param_named(tx_plaintext_direct_xmit_packets,
		   trustix_datapath_tx_plaintext_direct_xmit_packets, ullong,
		   0444);
MODULE_PARM_DESC(tx_plaintext_direct_xmit_packets,
		 "TrustIX plaintext TX outer skbs sent through dev_queue_xmit");

static unsigned long long trustix_datapath_tx_plaintext_direct_xmit_errors;
module_param_named(tx_plaintext_direct_xmit_errors,
		   trustix_datapath_tx_plaintext_direct_xmit_errors, ullong,
		   0444);
MODULE_PARM_DESC(tx_plaintext_direct_xmit_errors,
		 "TrustIX plaintext TX dev_queue_xmit failures");

static unsigned long long trustix_datapath_tx_plaintext_direct_xmit_fallbacks;
module_param_named(tx_plaintext_direct_xmit_fallbacks,
		   trustix_datapath_tx_plaintext_direct_xmit_fallbacks,
		   ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_direct_xmit_fallbacks,
		 "TrustIX plaintext TX outer skbs that fell back to ip_local_out");

static unsigned long long trustix_datapath_tx_plaintext_direct_xmit_neigh_misses;
module_param_named(tx_plaintext_direct_xmit_neigh_misses,
		   trustix_datapath_tx_plaintext_direct_xmit_neigh_misses,
		   ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_direct_xmit_neigh_misses,
		 "TrustIX plaintext TX direct xmit neighbour lookup misses");

static unsigned long long trustix_datapath_tx_plaintext_direct_xmit_dst_mac_cache_hits;
module_param_named(tx_plaintext_direct_xmit_dst_mac_cache_hits,
		   trustix_datapath_tx_plaintext_direct_xmit_dst_mac_cache_hits,
		   ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_direct_xmit_dst_mac_cache_hits,
		 "TrustIX plaintext TX direct xmit destination MAC cache hits");

static unsigned long long trustix_datapath_tx_plaintext_direct_xmit_dst_mac_cache_misses;
module_param_named(tx_plaintext_direct_xmit_dst_mac_cache_misses,
		   trustix_datapath_tx_plaintext_direct_xmit_dst_mac_cache_misses,
		   ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_direct_xmit_dst_mac_cache_misses,
		 "TrustIX plaintext TX direct xmit destination MAC cache misses");

static unsigned long long trustix_datapath_tx_plaintext_direct_xmit_dst_mac_cache_invalidations;
module_param_named(tx_plaintext_direct_xmit_dst_mac_cache_invalidations,
		   trustix_datapath_tx_plaintext_direct_xmit_dst_mac_cache_invalidations,
		   ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_direct_xmit_dst_mac_cache_invalidations,
		 "TrustIX plaintext TX destination MAC cache entries invalidated after IPv4 neighbour updates");

static unsigned long long trustix_datapath_tx_plaintext_hash_tx_queue_sets;
module_param_named(tx_plaintext_hash_tx_queue_sets,
		   trustix_datapath_tx_plaintext_hash_tx_queue_sets, ullong,
		   0444);
MODULE_PARM_DESC(tx_plaintext_hash_tx_queue_sets,
		 "TrustIX plaintext TX outer skbs assigned to a target device TX queue");

static unsigned long long
	trustix_datapath_tx_plaintext_inner_flow_hash_sets;
module_param_named(tx_plaintext_inner_flow_hash_sets,
		   trustix_datapath_tx_plaintext_inner_flow_hash_sets, ullong,
		   0444);
MODULE_PARM_DESC(tx_plaintext_inner_flow_hash_sets,
		 "TrustIX plaintext outer skbs assigned an inner-flow TX hash");

static unsigned long long
	trustix_datapath_tx_plaintext_outer_tuple_hash_sets;
module_param_named(tx_plaintext_outer_tuple_hash_sets,
		   trustix_datapath_tx_plaintext_outer_tuple_hash_sets,
		   ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_outer_tuple_hash_sets,
		 "TrustIX plaintext outer skbs assigned an outer-tuple TX hash");

static unsigned long long
	trustix_datapath_tx_plaintext_xps_sender_cpu_sets;
module_param_named(tx_plaintext_xps_sender_cpu_sets,
		   trustix_datapath_tx_plaintext_xps_sender_cpu_sets, ullong,
		   0444);
MODULE_PARM_DESC(tx_plaintext_xps_sender_cpu_sets,
		 "TrustIX plaintext outer skbs assigned a stable XPS sender CPU");

static unsigned long long
	trustix_datapath_tx_plaintext_xps_sender_cpu_fallbacks;
module_param_named(tx_plaintext_xps_sender_cpu_fallbacks,
		   trustix_datapath_tx_plaintext_xps_sender_cpu_fallbacks,
		   ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_xps_sender_cpu_fallbacks,
		 "TrustIX plaintext outer skbs without an available XPS sender CPU");

static unsigned long long
	trustix_datapath_tx_plaintext_tix_tcp_port_shard_sets;
module_param_named(tx_plaintext_tix_tcp_port_shard_sets,
		   trustix_datapath_tx_plaintext_tix_tcp_port_shard_sets,
		   ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_tix_tcp_port_shard_sets,
		 "TrustIX plaintext TIX-TCP packets assigned a negotiated outer source-port shard");

static DEFINE_PER_CPU(unsigned long long,
	trustix_datapath_tx_plaintext_tix_tcp_shard_tx_queue_sets);
module_param_cb(tx_plaintext_tix_tcp_shard_tx_queue_sets,
		&trustix_datapath_percpu_ullong_ro_ops,
		&trustix_datapath_tx_plaintext_tix_tcp_shard_tx_queue_sets,
		0444);
MODULE_PARM_DESC(tx_plaintext_tix_tcp_shard_tx_queue_sets,
		 "TrustIX plaintext TIX-TCP outer skbs assigned to a TX queue directly from the negotiated port shard");

static unsigned long long
	trustix_datapath_tx_plaintext_tix_tcp_shard_sequence_hits;
module_param_named(tx_plaintext_tix_tcp_shard_sequence_hits,
		   trustix_datapath_tx_plaintext_tix_tcp_shard_sequence_hits,
		   ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_tix_tcp_shard_sequence_hits,
		 "TrustIX plaintext TIX-TCP packets assigned a per-flow shard sequence");

static unsigned long long
	trustix_datapath_tx_plaintext_tix_tcp_shard_sequence_fallbacks;
module_param_named(tx_plaintext_tix_tcp_shard_sequence_fallbacks,
		   trustix_datapath_tx_plaintext_tix_tcp_shard_sequence_fallbacks,
		   ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_tix_tcp_shard_sequence_fallbacks,
		 "TrustIX plaintext TIX-TCP packets using the global outer sequence fallback");

static DEFINE_PER_CPU(unsigned long long,
	trustix_datapath_tx_plaintext_tix_tcp_ordered_xmits);
module_param_cb(tx_plaintext_tix_tcp_ordered_xmits,
		&trustix_datapath_percpu_ullong_ro_ops,
		&trustix_datapath_tx_plaintext_tix_tcp_ordered_xmits, 0444);
MODULE_PARM_DESC(tx_plaintext_tix_tcp_ordered_xmits,
		 "TrustIX TIX-TCP outer skbs sequenced in final transmit order");

static unsigned long long
	trustix_datapath_tx_plaintext_tix_tcp_sequence_assign_errors;
module_param_named(tx_plaintext_tix_tcp_sequence_assign_errors,
		   trustix_datapath_tx_plaintext_tix_tcp_sequence_assign_errors,
		   ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_tix_tcp_sequence_assign_errors,
		 "TrustIX TIX-TCP outer skbs rejected before final sequence assignment");

static unsigned long long
	trustix_datapath_rx_tix_tcp_port_shard_matches;
module_param_named(rx_tix_tcp_port_shard_matches,
		   trustix_datapath_rx_tix_tcp_port_shard_matches, ullong,
		   0444);
MODULE_PARM_DESC(rx_tix_tcp_port_shard_matches,
		 "TrustIX TIX-TCP receive tuples accepted on negotiated source-port shards");

static unsigned long long trustix_datapath_tx_plaintext_hash_tx_queue_fallbacks;
module_param_named(tx_plaintext_hash_tx_queue_fallbacks,
		   trustix_datapath_tx_plaintext_hash_tx_queue_fallbacks,
		   ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_hash_tx_queue_fallbacks,
		 "TrustIX plaintext TX outer skbs that could not be assigned to a target device TX queue");

static unsigned long long trustix_datapath_tx_plaintext_hash_tx_queue_partition_udp_sets;
module_param_named(tx_plaintext_hash_tx_queue_partition_udp_sets,
		   trustix_datapath_tx_plaintext_hash_tx_queue_partition_udp_sets,
		   ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_hash_tx_queue_partition_udp_sets,
		 "TrustIX plaintext UDP TX outer skbs assigned while mixed-transport queue partitioning is active");

static unsigned long long trustix_datapath_tx_plaintext_hash_tx_queue_partition_tcp_sets;
module_param_named(tx_plaintext_hash_tx_queue_partition_tcp_sets,
		   trustix_datapath_tx_plaintext_hash_tx_queue_partition_tcp_sets,
		   ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_hash_tx_queue_partition_tcp_sets,
		 "TrustIX plaintext TIX-TCP TX outer skbs assigned to the TCP queue partition");

static unsigned long long trustix_datapath_tx_plaintext_hash_tx_queue_partition_fallbacks;
module_param_named(tx_plaintext_hash_tx_queue_partition_fallbacks,
		   trustix_datapath_tx_plaintext_hash_tx_queue_partition_fallbacks,
		   ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_hash_tx_queue_partition_fallbacks,
		 "TrustIX plaintext TX outer skbs that used all queues while transport partitioning was enabled");

static unsigned long long trustix_datapath_tx_plaintext_hash_tx_queue_q0;
module_param_named(tx_plaintext_hash_tx_queue_q0,
		   trustix_datapath_tx_plaintext_hash_tx_queue_q0, ullong,
		   0444);
static unsigned long long trustix_datapath_tx_plaintext_hash_tx_queue_q1;
module_param_named(tx_plaintext_hash_tx_queue_q1,
		   trustix_datapath_tx_plaintext_hash_tx_queue_q1, ullong,
		   0444);
static unsigned long long trustix_datapath_tx_plaintext_hash_tx_queue_q2;
module_param_named(tx_plaintext_hash_tx_queue_q2,
		   trustix_datapath_tx_plaintext_hash_tx_queue_q2, ullong,
		   0444);
static unsigned long long trustix_datapath_tx_plaintext_hash_tx_queue_q3;
module_param_named(tx_plaintext_hash_tx_queue_q3,
		   trustix_datapath_tx_plaintext_hash_tx_queue_q3, ullong,
		   0444);
static unsigned long long trustix_datapath_tx_plaintext_hash_tx_queue_q4;
module_param_named(tx_plaintext_hash_tx_queue_q4,
		   trustix_datapath_tx_plaintext_hash_tx_queue_q4, ullong,
		   0444);
static unsigned long long trustix_datapath_tx_plaintext_hash_tx_queue_q5;
module_param_named(tx_plaintext_hash_tx_queue_q5,
		   trustix_datapath_tx_plaintext_hash_tx_queue_q5, ullong,
		   0444);
static unsigned long long trustix_datapath_tx_plaintext_hash_tx_queue_q6;
module_param_named(tx_plaintext_hash_tx_queue_q6,
		   trustix_datapath_tx_plaintext_hash_tx_queue_q6, ullong,
		   0444);
static unsigned long long trustix_datapath_tx_plaintext_hash_tx_queue_q7;
module_param_named(tx_plaintext_hash_tx_queue_q7,
		   trustix_datapath_tx_plaintext_hash_tx_queue_q7, ullong,
		   0444);
static unsigned long long trustix_datapath_tx_plaintext_hash_tx_queue_other;
module_param_named(tx_plaintext_hash_tx_queue_other,
		   trustix_datapath_tx_plaintext_hash_tx_queue_other, ullong,
		   0444);
MODULE_PARM_DESC(tx_plaintext_hash_tx_queue_other,
		 "TrustIX plaintext TX outer skbs assigned to target device TX queues beyond q7");

static unsigned long long trustix_datapath_tx_plaintext_stream_coalesce_packets;
module_param_named(tx_plaintext_stream_coalesce_packets,
		   trustix_datapath_tx_plaintext_stream_coalesce_packets,
		   ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_stream_coalesce_packets,
		 "TrustIX plaintext TX coalesced outer TCP GSO batches sent");

static unsigned long long trustix_datapath_tx_plaintext_stream_coalesce_frames;
module_param_named(tx_plaintext_stream_coalesce_frames,
		   trustix_datapath_tx_plaintext_stream_coalesce_frames,
		   ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_stream_coalesce_frames,
		 "TrustIX plaintext TX inner TCP frames sent through stream coalescing");

static unsigned long long trustix_datapath_tx_plaintext_stream_coalesce_stored;
module_param_named(tx_plaintext_stream_coalesce_stored,
		   trustix_datapath_tx_plaintext_stream_coalesce_stored,
		   ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_stream_coalesce_stored,
		 "TrustIX plaintext TX TCP frames stored for stream coalescing");

static unsigned long long trustix_datapath_tx_plaintext_stream_coalesce_misses;
module_param_named(tx_plaintext_stream_coalesce_misses,
		   trustix_datapath_tx_plaintext_stream_coalesce_misses,
		   ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_stream_coalesce_misses,
		 "TrustIX plaintext TX TCP frames that missed stream coalescing");

static unsigned long long trustix_datapath_tx_plaintext_stream_coalesce_attempts;
module_param_named(tx_plaintext_stream_coalesce_attempts,
		   trustix_datapath_tx_plaintext_stream_coalesce_attempts,
		   ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_stream_coalesce_attempts,
		 "TrustIX plaintext TX non-GSO TCP frames considered for stream coalescing");

static unsigned long long trustix_datapath_tx_plaintext_stream_coalesce_payload_frames;
module_param_named(tx_plaintext_stream_coalesce_payload_frames,
		   trustix_datapath_tx_plaintext_stream_coalesce_payload_frames,
		   ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_stream_coalesce_payload_frames,
		 "TrustIX plaintext TX non-GSO TCP frames with payload considered for stream coalescing");

static unsigned long long trustix_datapath_tx_plaintext_stream_coalesce_ack_only_frames;
module_param_named(tx_plaintext_stream_coalesce_ack_only_frames,
		   trustix_datapath_tx_plaintext_stream_coalesce_ack_only_frames,
		   ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_stream_coalesce_ack_only_frames,
		 "TrustIX plaintext TX non-GSO TCP ACK-only frames seen before stream coalescing");

static unsigned long long trustix_datapath_tx_plaintext_stream_coalesce_slot_hits;
module_param_named(tx_plaintext_stream_coalesce_slot_hits,
		   trustix_datapath_tx_plaintext_stream_coalesce_slot_hits,
		   ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_stream_coalesce_slot_hits,
		 "TrustIX plaintext TX stream coalesce slot hits");

static unsigned long long trustix_datapath_tx_plaintext_stream_coalesce_slot_conflicts;
module_param_named(tx_plaintext_stream_coalesce_slot_conflicts,
		   trustix_datapath_tx_plaintext_stream_coalesce_slot_conflicts,
		   ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_stream_coalesce_slot_conflicts,
		 "TrustIX plaintext TX stream coalesce hash slot conflicts");

static unsigned long long trustix_datapath_tx_plaintext_stream_coalesce_full_flushes;
module_param_named(tx_plaintext_stream_coalesce_full_flushes,
		   trustix_datapath_tx_plaintext_stream_coalesce_full_flushes,
		   ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_stream_coalesce_full_flushes,
		 "TrustIX plaintext TX stream coalesce batches flushed after reaching max frames");

static unsigned long long trustix_datapath_tx_plaintext_stream_coalesce_timer_flushes;
module_param_named(tx_plaintext_stream_coalesce_timer_flushes,
		   trustix_datapath_tx_plaintext_stream_coalesce_timer_flushes,
		   ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_stream_coalesce_timer_flushes,
		 "TrustIX plaintext TX stream coalesce batches flushed by delayed work");

static unsigned long long trustix_datapath_tx_plaintext_stream_coalesce_single_flushes;
module_param_named(tx_plaintext_stream_coalesce_single_flushes,
		   trustix_datapath_tx_plaintext_stream_coalesce_single_flushes,
		   ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_stream_coalesce_single_flushes,
		 "TrustIX plaintext TX stream coalesce flushes with a single frame");

static unsigned long long trustix_datapath_tx_plaintext_stream_coalesce_multi_flushes;
module_param_named(tx_plaintext_stream_coalesce_multi_flushes,
		   trustix_datapath_tx_plaintext_stream_coalesce_multi_flushes,
		   ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_stream_coalesce_multi_flushes,
		 "TrustIX plaintext TX stream coalesce flushes with two or more frames");

static unsigned long long trustix_datapath_tx_plaintext_stream_coalesce_errors;
module_param_named(tx_plaintext_stream_coalesce_errors,
		   trustix_datapath_tx_plaintext_stream_coalesce_errors,
		   ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_stream_coalesce_errors,
		 "TrustIX plaintext TX stream coalescing build or xmit errors");

static unsigned int trustix_datapath_tx_plaintext_slots =
	TRUSTIX_DATAPATH_TX_PLAINTEXT_DEFAULT_SLOTS;
module_param_named(tx_plaintext_slots, trustix_datapath_tx_plaintext_slots,
		   uint, 0444);
MODULE_PARM_DESC(tx_plaintext_slots,
		 "TrustIX plaintext TX async queue slots allocated at module load");

static unsigned int trustix_datapath_tx_plaintext_queue_len;
module_param_named(tx_plaintext_queue_len,
		   trustix_datapath_tx_plaintext_queue_len, uint, 0444);
MODULE_PARM_DESC(tx_plaintext_queue_len,
		 "TrustIX plaintext TX async queue current depth");

static unsigned long long trustix_datapath_tx_plaintext_queued;
module_param_named(tx_plaintext_queued, trustix_datapath_tx_plaintext_queued,
		   ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_queued,
		 "TrustIX plaintext TX packets accepted into the async queue");

static unsigned long long trustix_datapath_tx_plaintext_queue_drops;
module_param_named(tx_plaintext_queue_drops,
		   trustix_datapath_tx_plaintext_queue_drops, ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_queue_drops,
		 "TrustIX plaintext TX packets dropped before async queueing");

static unsigned long long trustix_datapath_tx_plaintext_queue_work_calls;
module_param_named(tx_plaintext_queue_work_calls,
		   trustix_datapath_tx_plaintext_queue_work_calls, ullong,
		   0444);
MODULE_PARM_DESC(tx_plaintext_queue_work_calls,
		 "TrustIX plaintext TX queue_work attempts");

static unsigned long long trustix_datapath_tx_plaintext_queue_work_enqueued;
module_param_named(tx_plaintext_queue_work_enqueued,
		   trustix_datapath_tx_plaintext_queue_work_enqueued, ullong,
		   0444);
MODULE_PARM_DESC(tx_plaintext_queue_work_enqueued,
		 "TrustIX plaintext TX queue_work calls that accepted a new work item");

static unsigned long long trustix_datapath_tx_plaintext_runs;
module_param_named(tx_plaintext_runs, trustix_datapath_tx_plaintext_runs,
		   ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_runs,
		 "TrustIX plaintext TX workqueue callbacks run");

static unsigned long long trustix_datapath_tx_plaintext_run_processed;
module_param_named(tx_plaintext_run_processed,
		   trustix_datapath_tx_plaintext_run_processed, ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_run_processed,
		 "TrustIX plaintext TX async queue slots processed");

static unsigned long long trustix_datapath_tx_plaintext_mark_skips;
module_param_named(tx_plaintext_mark_skips,
		   trustix_datapath_tx_plaintext_mark_skips, ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_mark_skips,
		 "TrustIX plaintext TX self-generated packets skipped by the hook mark guard");

static atomic64_t trustix_datapath_tx_sequence = ATOMIC64_INIT(0);
static atomic64_t trustix_datapath_outer_tcp_sequence = ATOMIC64_INIT(1);
static atomic64_t *trustix_datapath_outer_tcp_shard_sequences;
static __u32 trustix_datapath_outer_tcp_sequence_flow_slots;
static spinlock_t trustix_datapath_outer_tcp_order_locks[
	TRUSTIX_DATAPATH_OUTER_TCP_ORDER_LOCKS];

static DEFINE_SPINLOCK(trustix_datapath_tx_plaintext_lock);
static struct trustix_datapath_tx_plaintext_slot
	*trustix_datapath_tx_plaintext_ring;
static struct trustix_datapath_tx_plaintext_coalesce_slot
	trustix_datapath_tx_plaintext_coalesce_slots
		[TRUSTIX_DATAPATH_TX_PLAINTEXT_COALESCE_SLOTS];
static __u32 trustix_datapath_tx_plaintext_capacity;
static __u32 trustix_datapath_tx_plaintext_head;
static __u32 trustix_datapath_tx_plaintext_tail;
static __u32 trustix_datapath_tx_plaintext_count;
static bool trustix_datapath_tx_plaintext_work_active;
static struct workqueue_struct *trustix_datapath_tx_plaintext_wq;
static DECLARE_WORK(trustix_datapath_tx_plaintext_work,
		    trustix_datapath_tx_plaintext_run);

struct trustix_datapath_packet_hot_counters {
	__u64 packets;
	__u64 bytes;
	__u64 parse_errors;
	__u64 route_misses;
	__u64 session_misses;
	__u64 unicast_routes;
	__u64 local_routes;
	__u64 blackhole_routes;
	__u64 reject_routes;
};

struct trustix_datapath_hook_hot_counters {
	__u64 seen;
	__u64 classified;
	__u64 parse_errors;
	__u64 route_misses;
	__u64 session_misses;
	__u64 pass;
	__u64 drop;
	__u64 outer_seen;
	__u64 outer_parsed;
	__u64 outer_parse_errors;
	__u64 outer_session_misses;
	__u64 rx_preview;
	__u64 rx_preview_errors;
	__u64 rx_stage;
	__u64 rx_stage_errors;
	__u64 rx_worker;
	__u64 rx_worker_errors;
};

struct trustix_datapath_hook_entry {
	struct nf_hook_ops ops;
	bool in_use;
	bool registered;
	struct net *net;
	struct net_device *target_dev;
	__u32 flags;
	int ifindex;
	int target_ifindex;
	unsigned int stats_index;
	char ifname[TRUSTIX_DATAPATH_IFNAME_MAX];
	char target_ifname[TRUSTIX_DATAPATH_IFNAME_MAX];
	__u64 seen;
	__u64 classified;
	__u64 parse_errors;
	__u64 route_misses;
	__u64 session_misses;
	__u64 pass;
	__u64 drop;
	__u64 outer_seen;
	__u64 outer_parsed;
	__u64 outer_parse_errors;
	__u64 outer_session_misses;
	__u64 rx_preview;
	__u64 rx_preview_errors;
	__u64 rx_stage;
	__u64 rx_stage_errors;
	__u64 rx_worker;
	__u64 rx_worker_errors;
	struct trustix_datapath_hook_hot_counters hot_base;
};

static struct trustix_datapath_hook_entry
	trustix_datapath_hooks[TRUSTIX_DATAPATH_HOOK_MAX];

struct trustix_datapath_pcpu_hot_stats {
	struct u64_stats_sync syncp;
	struct trustix_datapath_packet_hot_counters packet;
	struct trustix_datapath_hook_hot_counters
		hooks[TRUSTIX_DATAPATH_HOOK_MAX];
};

static struct trustix_datapath_pcpu_hot_stats __percpu
	*trustix_datapath_pcpu_hot_stats;

static int trustix_datapath_alloc_pcpu_hot_stats(void)
{
	int cpu;

	trustix_datapath_pcpu_hot_stats =
		alloc_percpu(struct trustix_datapath_pcpu_hot_stats);
	if (!trustix_datapath_pcpu_hot_stats)
		return -ENOMEM;
	for_each_possible_cpu(cpu) {
		struct trustix_datapath_pcpu_hot_stats *stats =
			per_cpu_ptr(trustix_datapath_pcpu_hot_stats, cpu);

		memset(stats, 0, sizeof(*stats));
		u64_stats_init(&stats->syncp);
	}
	return 0;
}

static void trustix_datapath_free_pcpu_hot_stats(void)
{
	if (!trustix_datapath_pcpu_hot_stats)
		return;
	free_percpu(trustix_datapath_pcpu_hot_stats);
	trustix_datapath_pcpu_hot_stats = NULL;
}

static void
trustix_datapath_read_packet_hot_counters(
	struct trustix_datapath_packet_hot_counters *out)
{
	int cpu;

	if (!out)
		return;
	memset(out, 0, sizeof(*out));
	for_each_possible_cpu(cpu) {
		const struct trustix_datapath_pcpu_hot_stats *stats =
			per_cpu_ptr(trustix_datapath_pcpu_hot_stats, cpu);
		struct trustix_datapath_packet_hot_counters snapshot;
		unsigned int start;

		do {
			start = u64_stats_fetch_begin(&stats->syncp);
			snapshot = stats->packet;
		} while (u64_stats_fetch_retry(&stats->syncp, start));
		out->packets += snapshot.packets;
		out->bytes += snapshot.bytes;
		out->parse_errors += snapshot.parse_errors;
		out->route_misses += snapshot.route_misses;
		out->session_misses += snapshot.session_misses;
		out->unicast_routes += snapshot.unicast_routes;
		out->local_routes += snapshot.local_routes;
		out->blackhole_routes += snapshot.blackhole_routes;
		out->reject_routes += snapshot.reject_routes;
	}
}

static void
trustix_datapath_read_hook_hot_counters(
	unsigned int index, struct trustix_datapath_hook_hot_counters *out)
{
	int cpu;

	if (!out)
		return;
	memset(out, 0, sizeof(*out));
	if (index >= TRUSTIX_DATAPATH_HOOK_MAX)
		return;
	for_each_possible_cpu(cpu) {
		const struct trustix_datapath_pcpu_hot_stats *stats =
			per_cpu_ptr(trustix_datapath_pcpu_hot_stats, cpu);
		struct trustix_datapath_hook_hot_counters snapshot;
		unsigned int start;

		do {
			start = u64_stats_fetch_begin(&stats->syncp);
			snapshot = stats->hooks[index];
		} while (u64_stats_fetch_retry(&stats->syncp, start));
		out->seen += snapshot.seen;
		out->classified += snapshot.classified;
		out->parse_errors += snapshot.parse_errors;
		out->route_misses += snapshot.route_misses;
		out->session_misses += snapshot.session_misses;
		out->pass += snapshot.pass;
		out->drop += snapshot.drop;
		out->outer_seen += snapshot.outer_seen;
		out->outer_parsed += snapshot.outer_parsed;
		out->outer_parse_errors += snapshot.outer_parse_errors;
		out->outer_session_misses += snapshot.outer_session_misses;
		out->rx_preview += snapshot.rx_preview;
		out->rx_preview_errors += snapshot.rx_preview_errors;
		out->rx_stage += snapshot.rx_stage;
		out->rx_stage_errors += snapshot.rx_stage_errors;
		out->rx_worker += snapshot.rx_worker;
		out->rx_worker_errors += snapshot.rx_worker_errors;
	}
}

static void
trustix_datapath_subtract_hook_hot_counters(
	struct trustix_datapath_hook_hot_counters *counters,
	const struct trustix_datapath_hook_hot_counters *base)
{
	if (!counters || !base)
		return;
	counters->seen -= base->seen;
	counters->classified -= base->classified;
	counters->parse_errors -= base->parse_errors;
	counters->route_misses -= base->route_misses;
	counters->session_misses -= base->session_misses;
	counters->pass -= base->pass;
	counters->drop -= base->drop;
	counters->outer_seen -= base->outer_seen;
	counters->outer_parsed -= base->outer_parsed;
	counters->outer_parse_errors -= base->outer_parse_errors;
	counters->outer_session_misses -= base->outer_session_misses;
	counters->rx_preview -= base->rx_preview;
	counters->rx_preview_errors -= base->rx_preview_errors;
	counters->rx_stage -= base->rx_stage;
	counters->rx_stage_errors -= base->rx_stage_errors;
	counters->rx_worker -= base->rx_worker;
	counters->rx_worker_errors -= base->rx_worker_errors;
}

static __u32 trustix_datapath_clamp_tx_plaintext_slots(unsigned int slots)
{
	if (!slots)
		return TRUSTIX_DATAPATH_TX_PLAINTEXT_DEFAULT_SLOTS;
	if (slots > TRUSTIX_DATAPATH_TX_PLAINTEXT_MAX_SLOTS)
		return TRUSTIX_DATAPATH_TX_PLAINTEXT_MAX_SLOTS;
	return slots;
}

static void
trustix_datapath_tx_plaintext_release_slot(
	struct trustix_datapath_tx_plaintext_slot *slot)
{
	if (!slot)
		return;
	if (slot->skb)
		kfree_skb(slot->skb);
	if (slot->target_dev)
		dev_put(slot->target_dev);
	memset(slot, 0, sizeof(*slot));
}

static int
trustix_datapath_tx_send_outer_skb(struct sk_buff *skb,
				   struct net_device *target_dev,
				   const struct trustix_datapath_tx_plan *plan);

static void trustix_datapath_tx_plaintext_clear(void)
{
	struct trustix_datapath_tx_plaintext_slot slot = {};
	unsigned long irqflags;

	for (;;) {
		memset(&slot, 0, sizeof(slot));
		spin_lock_irqsave(&trustix_datapath_tx_plaintext_lock,
				  irqflags);
		if (!trustix_datapath_tx_plaintext_ring ||
		    !trustix_datapath_tx_plaintext_capacity ||
		    !trustix_datapath_tx_plaintext_count) {
			trustix_datapath_tx_plaintext_head = 0;
			trustix_datapath_tx_plaintext_tail = 0;
			trustix_datapath_tx_plaintext_count = 0;
			trustix_datapath_tx_plaintext_work_active = false;
			WRITE_ONCE(trustix_datapath_tx_plaintext_queue_len,
				   0);
			spin_unlock_irqrestore(
				&trustix_datapath_tx_plaintext_lock,
				irqflags);
			break;
		}
		slot = trustix_datapath_tx_plaintext_ring
			       [trustix_datapath_tx_plaintext_head];
		memset(&trustix_datapath_tx_plaintext_ring
			       [trustix_datapath_tx_plaintext_head],
		       0, sizeof(trustix_datapath_tx_plaintext_ring
					[trustix_datapath_tx_plaintext_head]));
		trustix_datapath_tx_plaintext_head =
			(trustix_datapath_tx_plaintext_head + 1) %
			trustix_datapath_tx_plaintext_capacity;
		trustix_datapath_tx_plaintext_count--;
		if (!trustix_datapath_tx_plaintext_count)
			trustix_datapath_tx_plaintext_tail =
				trustix_datapath_tx_plaintext_head;
		WRITE_ONCE(trustix_datapath_tx_plaintext_queue_len,
			   trustix_datapath_tx_plaintext_count);
		spin_unlock_irqrestore(&trustix_datapath_tx_plaintext_lock,
				       irqflags);
		trustix_datapath_tx_plaintext_release_slot(&slot);
		cond_resched();
	}
}

static void trustix_datapath_tx_plaintext_drop_pending_sync(void)
{
	trustix_datapath_tx_plaintext_coalesce_drop_all();
	if (trustix_datapath_tx_plaintext_wq)
		flush_workqueue(trustix_datapath_tx_plaintext_wq);
	trustix_datapath_tx_plaintext_clear();
	if (trustix_datapath_tx_plaintext_wq)
		flush_workqueue(trustix_datapath_tx_plaintext_wq);
	trustix_datapath_tx_plaintext_clear();
}

static __always_inline void trustix_datapath_tx_record_success(
	const struct trustix_datapath_tx_plan *plan, __u32 inner_len)
{
	if (plan && plan->secure) {
		trustix_datapath_secure_tx_packets++;
		trustix_datapath_secure_tx_bytes += inner_len;
		return;
	}
	trustix_datapath_tx_plaintext_packets++;
	trustix_datapath_tx_plaintext_bytes += inner_len;
}

static int trustix_datapath_tx_plaintext_enqueue(
	struct sk_buff *skb, struct net_device *target_dev,
	const struct trustix_datapath_tx_plan *plan, __u32 inner_len)
{
	struct trustix_datapath_tx_plaintext_slot *slot;
	struct workqueue_struct *wq = NULL;
	unsigned long irqflags;
	bool queue = false;
	int ret = 0;

	if (!skb || !target_dev || !plan || !inner_len)
		return -EINVAL;
	if (READ_ONCE(trustix_datapath_tx_plaintext_inline_xmit)) {
		ret = trustix_datapath_tx_send_outer_skb(skb, target_dev, plan);
		if (ret) {
			trustix_datapath_tx_plaintext_xmit_errors++;
			trustix_datapath_tx_plaintext_inline_xmit_errors++;
		} else {
			trustix_datapath_tx_record_success(plan, inner_len);
			trustix_datapath_tx_plaintext_inline_xmit_packets++;
		}
		dev_put(target_dev);
		return ret;
	}
	spin_lock_irqsave(&trustix_datapath_tx_plaintext_lock, irqflags);
	if (!trustix_datapath_tx_plaintext_ring ||
	    !trustix_datapath_tx_plaintext_capacity ||
	    !trustix_datapath_tx_plaintext_wq) {
		ret = -ENODEV;
	} else if (trustix_datapath_tx_plaintext_count >=
		   trustix_datapath_tx_plaintext_capacity) {
		trustix_datapath_tx_plaintext_queue_drops++;
		ret = -ENOSPC;
	} else {
		slot = &trustix_datapath_tx_plaintext_ring
				[trustix_datapath_tx_plaintext_tail];
		memset(slot, 0, sizeof(*slot));
		slot->valid = true;
		slot->skb = skb;
		slot->target_dev = target_dev;
		slot->plan = *plan;
		slot->inner_len = inner_len;
		trustix_datapath_tx_plaintext_tail =
			(trustix_datapath_tx_plaintext_tail + 1) %
			trustix_datapath_tx_plaintext_capacity;
		trustix_datapath_tx_plaintext_count++;
		WRITE_ONCE(trustix_datapath_tx_plaintext_queue_len,
			   trustix_datapath_tx_plaintext_count);
		trustix_datapath_tx_plaintext_queued++;
		if (!trustix_datapath_tx_plaintext_work_active &&
		    trustix_datapath_tx_plaintext_wq) {
			trustix_datapath_tx_plaintext_work_active = true;
			wq = trustix_datapath_tx_plaintext_wq;
			queue = true;
		}
	}
	spin_unlock_irqrestore(&trustix_datapath_tx_plaintext_lock, irqflags);
	if (ret)
		return ret;
	if (queue) {
		trustix_datapath_tx_plaintext_queue_work_calls++;
		if (queue_work(wq, &trustix_datapath_tx_plaintext_work))
			trustix_datapath_tx_plaintext_queue_work_enqueued++;
	}
	return 0;
}

static int trustix_datapath_tx_plaintext_enqueue_many(
	struct sk_buff **skbs, const __u32 *inner_lens, unsigned int count,
	struct net_device *target_dev, const struct trustix_datapath_tx_plan *plan)
{
	struct workqueue_struct *wq = NULL;
	unsigned long irqflags;
	bool queue = false;
	unsigned int i;
	int ret = 0;

	if (!skbs || !inner_lens || !count || !target_dev || !plan)
		return -EINVAL;
	if (count > TRUSTIX_DATAPATH_TX_PLAINTEXT_MAX_GSO_SEGS)
		return -E2BIG;
	for (i = 0; i < count; i++) {
		if (!skbs[i] || !inner_lens[i])
			return -EINVAL;
	}

	if (READ_ONCE(trustix_datapath_tx_plaintext_inline_xmit)) {
		int first_ret = 0;

		for (i = 0; i < count; i++) {
			ret = trustix_datapath_tx_send_outer_skb(skbs[i],
								target_dev, plan);
			skbs[i] = NULL;
			if (ret) {
				if (!first_ret)
					first_ret = ret;
				trustix_datapath_tx_plaintext_xmit_errors++;
				trustix_datapath_tx_plaintext_inline_xmit_errors++;
			} else {
				trustix_datapath_tx_record_success(
					plan, inner_lens[i]);
				trustix_datapath_tx_plaintext_inline_xmit_packets++;
			}
		}
		return first_ret;
	}

	spin_lock_irqsave(&trustix_datapath_tx_plaintext_lock, irqflags);
	if (!trustix_datapath_tx_plaintext_ring ||
	    !trustix_datapath_tx_plaintext_capacity ||
	    !trustix_datapath_tx_plaintext_wq) {
		ret = -ENODEV;
	} else if (count > trustix_datapath_tx_plaintext_capacity ||
		   trustix_datapath_tx_plaintext_count >
			   trustix_datapath_tx_plaintext_capacity - count) {
		trustix_datapath_tx_plaintext_queue_drops += count;
		ret = -ENOSPC;
	} else {
		for (i = 0; i < count; i++) {
			struct trustix_datapath_tx_plaintext_slot *slot =
				&trustix_datapath_tx_plaintext_ring
					 [trustix_datapath_tx_plaintext_tail];

			memset(slot, 0, sizeof(*slot));
			dev_hold(target_dev);
			slot->valid = true;
			slot->skb = skbs[i];
			slot->target_dev = target_dev;
			slot->plan = *plan;
			slot->inner_len = inner_lens[i];
			skbs[i] = NULL;
			trustix_datapath_tx_plaintext_tail =
				(trustix_datapath_tx_plaintext_tail + 1) %
				trustix_datapath_tx_plaintext_capacity;
		}
		trustix_datapath_tx_plaintext_count += count;
		WRITE_ONCE(trustix_datapath_tx_plaintext_queue_len,
			   trustix_datapath_tx_plaintext_count);
		trustix_datapath_tx_plaintext_queued += count;
		if (!trustix_datapath_tx_plaintext_work_active &&
		    trustix_datapath_tx_plaintext_wq) {
			trustix_datapath_tx_plaintext_work_active = true;
			wq = trustix_datapath_tx_plaintext_wq;
			queue = true;
		}
	}
	spin_unlock_irqrestore(&trustix_datapath_tx_plaintext_lock, irqflags);
	if (ret)
		return ret;
	if (queue) {
		trustix_datapath_tx_plaintext_queue_work_calls++;
		if (queue_work(wq, &trustix_datapath_tx_plaintext_work))
			trustix_datapath_tx_plaintext_queue_work_enqueued++;
	}
	return 0;
}

static int trustix_datapath_alloc_tx_plaintext(void)
{
	unsigned long irqflags;
	__u32 capacity;
	struct trustix_datapath_tx_plaintext_slot *ring;
	unsigned int i;

	capacity = trustix_datapath_clamp_tx_plaintext_slots(
		trustix_datapath_tx_plaintext_slots);
	ring = vzalloc(array_size(capacity, sizeof(*ring)));
	if (!ring)
		return -ENOMEM;
	trustix_datapath_tx_plaintext_wq =
		alloc_workqueue("trustix_dp_tx", WQ_UNBOUND | WQ_MEM_RECLAIM,
				1);
	if (!trustix_datapath_tx_plaintext_wq) {
		vfree(ring);
		return -ENOMEM;
	}
	for (i = 0; i < TRUSTIX_DATAPATH_TX_PLAINTEXT_COALESCE_SLOTS; i++) {
		spin_lock_init(
			&trustix_datapath_tx_plaintext_coalesce_slots[i].lock);
		INIT_DELAYED_WORK(
			&trustix_datapath_tx_plaintext_coalesce_slots[i].flush_work,
			trustix_datapath_tx_plaintext_coalesce_flush_work);
		trustix_datapath_tx_plaintext_coalesce_slots[i].valid = false;
		trustix_datapath_tx_plaintext_coalesce_slots[i].target_dev =
			NULL;
		trustix_datapath_tx_plaintext_coalesce_slots[i].frames = 0;
	}
	spin_lock_irqsave(&trustix_datapath_tx_plaintext_lock, irqflags);
	trustix_datapath_tx_plaintext_ring = ring;
	trustix_datapath_tx_plaintext_capacity = capacity;
	trustix_datapath_tx_plaintext_head = 0;
	trustix_datapath_tx_plaintext_tail = 0;
	trustix_datapath_tx_plaintext_count = 0;
	trustix_datapath_tx_plaintext_work_active = false;
	WRITE_ONCE(trustix_datapath_tx_plaintext_queue_len, 0);
	spin_unlock_irqrestore(&trustix_datapath_tx_plaintext_lock,
			       irqflags);
	return 0;
}

static void trustix_datapath_free_tx_plaintext(void)
{
	struct trustix_datapath_tx_plaintext_slot *ring;
	unsigned long irqflags;

	trustix_datapath_tx_plaintext_drop_pending_sync();
	if (trustix_datapath_tx_plaintext_wq) {
		flush_workqueue(trustix_datapath_tx_plaintext_wq);
		destroy_workqueue(trustix_datapath_tx_plaintext_wq);
		trustix_datapath_tx_plaintext_wq = NULL;
	}
	spin_lock_irqsave(&trustix_datapath_tx_plaintext_lock, irqflags);
	ring = trustix_datapath_tx_plaintext_ring;
	trustix_datapath_tx_plaintext_ring = NULL;
	trustix_datapath_tx_plaintext_capacity = 0;
	trustix_datapath_tx_plaintext_head = 0;
	trustix_datapath_tx_plaintext_tail = 0;
	trustix_datapath_tx_plaintext_count = 0;
	trustix_datapath_tx_plaintext_work_active = false;
	WRITE_ONCE(trustix_datapath_tx_plaintext_queue_len, 0);
	spin_unlock_irqrestore(&trustix_datapath_tx_plaintext_lock,
			       irqflags);
	vfree(ring);
}

static unsigned long long trustix_datapath_rx_worker_queued;
module_param_named(rx_worker_queued, trustix_datapath_rx_worker_queued, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_queued,
		 "TrustIX RX worker packets queued for kernel LAN injection");

static unsigned long long trustix_datapath_rx_worker_injected;
module_param_named(rx_worker_injected, trustix_datapath_rx_worker_injected,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_injected,
		 "TrustIX RX worker packets successfully injected to LAN");

static unsigned long long trustix_datapath_rx_worker_dropped;
module_param_named(rx_worker_dropped, trustix_datapath_rx_worker_dropped,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_dropped,
		 "TrustIX RX worker packets dropped during kernel LAN injection");

static unsigned long long trustix_datapath_rx_worker_overwritten;
module_param_named(rx_worker_overwritten,
		   trustix_datapath_rx_worker_overwritten, ullong, 0444);
MODULE_PARM_DESC(rx_worker_overwritten,
		 "TrustIX RX worker queued packets overwritten by ring pressure");

static unsigned long long trustix_datapath_rx_worker_queue_full_fallbacks;
module_param_named(rx_worker_queue_full_fallbacks,
		   trustix_datapath_rx_worker_queue_full_fallbacks, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_queue_full_fallbacks,
		 "TrustIX RX worker packets passed to the normal path because the async ring was full");

static unsigned long long trustix_datapath_rx_worker_alloc_errors;
module_param_named(rx_worker_alloc_errors,
		   trustix_datapath_rx_worker_alloc_errors, ullong, 0444);
MODULE_PARM_DESC(rx_worker_alloc_errors,
		 "TrustIX RX worker allocation failures");

static unsigned long long trustix_datapath_rx_worker_xmit_packets;
module_param_named(rx_worker_xmit_packets,
		   trustix_datapath_rx_worker_xmit_packets, ullong, 0444);
MODULE_PARM_DESC(rx_worker_xmit_packets,
		 "TrustIX RX worker packets delivered through dev_queue_xmit");

static unsigned long long trustix_datapath_rx_worker_xmit_ok;
module_param_named(rx_worker_xmit_ok, trustix_datapath_rx_worker_xmit_ok,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_xmit_ok,
		 "TrustIX RX worker dev_queue_xmit calls that returned NET_XMIT_SUCCESS");

static unsigned long long trustix_datapath_rx_worker_xmit_cn;
module_param_named(rx_worker_xmit_cn, trustix_datapath_rx_worker_xmit_cn,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_xmit_cn,
		 "TrustIX RX worker dev_queue_xmit calls that returned NET_XMIT_CN");

static unsigned long long trustix_datapath_rx_worker_xmit_ret_errors;
module_param_named(rx_worker_xmit_ret_errors,
		   trustix_datapath_rx_worker_xmit_ret_errors, ullong, 0444);
MODULE_PARM_DESC(rx_worker_xmit_ret_errors,
		 "TrustIX RX worker dev_queue_xmit calls that returned an error/drop status");

static unsigned long long trustix_datapath_rx_worker_xmit_drop;
module_param_named(rx_worker_xmit_drop, trustix_datapath_rx_worker_xmit_drop,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_xmit_drop,
		 "TrustIX RX worker dev_queue_xmit calls that returned NET_XMIT_DROP");

static unsigned long long trustix_datapath_rx_worker_xmit_other_ret_errors;
module_param_named(rx_worker_xmit_other_ret_errors,
		   trustix_datapath_rx_worker_xmit_other_ret_errors, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_xmit_other_ret_errors,
		 "TrustIX RX worker dev_queue_xmit calls that returned a non-DROP error status");

static unsigned long long trustix_datapath_rx_worker_xmit_dev_forward_packets;
module_param_named(rx_worker_xmit_dev_forward_packets,
		   trustix_datapath_rx_worker_xmit_dev_forward_packets, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_xmit_dev_forward_packets,
		 "TrustIX RX worker packets delivered through diagnostic dev_forward_skb path");

static unsigned long long trustix_datapath_rx_worker_xmit_dev_forward_errors;
module_param_named(rx_worker_xmit_dev_forward_errors,
		   trustix_datapath_rx_worker_xmit_dev_forward_errors, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_xmit_dev_forward_errors,
		 "TrustIX RX worker dev_forward_skb diagnostic delivery errors");

static unsigned long long trustix_datapath_rx_worker_xmit_peer_forward_packets;
module_param_named(rx_worker_xmit_peer_forward_packets,
		   trustix_datapath_rx_worker_xmit_peer_forward_packets,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_xmit_peer_forward_packets,
		 "TrustIX RX worker veth peer packets delivered through dev_forward_skb");

static unsigned long long trustix_datapath_rx_worker_xmit_peer_forward_errors;
module_param_named(rx_worker_xmit_peer_forward_errors,
		   trustix_datapath_rx_worker_xmit_peer_forward_errors,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_xmit_peer_forward_errors,
		 "TrustIX RX worker veth peer dev_forward_skb delivery errors");

static unsigned long long
	trustix_datapath_rx_worker_xmit_peer_forward_unsupported;
module_param_named(rx_worker_xmit_peer_forward_unsupported,
		   trustix_datapath_rx_worker_xmit_peer_forward_unsupported,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_xmit_peer_forward_unsupported,
		 "TrustIX RX worker dev_forward diagnostic requests without a same-namespace veth peer target");

static unsigned long long
	trustix_datapath_rx_worker_direct_xmit_safe_fallbacks;
module_param_named(rx_worker_direct_xmit_safe_fallbacks,
		   trustix_datapath_rx_worker_direct_xmit_safe_fallbacks,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_direct_xmit_safe_fallbacks,
		 "TrustIX RX worker direct-xmit requests safely sent through dev_queue_xmit");

static unsigned long long
	trustix_datapath_rx_worker_inline_receive_safe_fallbacks;
module_param_named(rx_worker_inline_receive_safe_fallbacks,
		   trustix_datapath_rx_worker_inline_receive_safe_fallbacks,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_inline_receive_safe_fallbacks,
		 "TrustIX RX worker inline receive requests safely sent through netif_rx backlog");

static unsigned long long trustix_datapath_rx_worker_receive_packets;
module_param_named(rx_worker_receive_packets,
		   trustix_datapath_rx_worker_receive_packets, ullong, 0444);
MODULE_PARM_DESC(rx_worker_receive_packets,
		 "TrustIX RX worker packets delivered through netif receive");

static unsigned long long trustix_datapath_rx_worker_deliver_errors;
module_param_named(rx_worker_deliver_errors,
		   trustix_datapath_rx_worker_deliver_errors, ullong, 0444);
MODULE_PARM_DESC(rx_worker_deliver_errors,
		 "TrustIX RX worker delivery errors after dequeue");

static unsigned long long trustix_datapath_rx_worker_xmit_hash_tx_queue_sets;
module_param_named(rx_worker_xmit_hash_tx_queue_sets,
		   trustix_datapath_rx_worker_xmit_hash_tx_queue_sets, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_xmit_hash_tx_queue_sets,
		 "TrustIX RX worker LAN xmit skbs assigned to a target-device TX queue");

static unsigned long long
	trustix_datapath_rx_worker_xmit_hash_tx_queue_fallbacks;
module_param_named(rx_worker_xmit_hash_tx_queue_fallbacks,
		   trustix_datapath_rx_worker_xmit_hash_tx_queue_fallbacks,
		   ullong, 0444);
MODULE_PARM_DESC(rx_worker_xmit_hash_tx_queue_fallbacks,
		 "TrustIX RX worker LAN xmit queue-hash attempts that could not set a queue");

static unsigned long long trustix_datapath_rx_worker_xmit_hash_tx_queue_q0;
module_param_named(rx_worker_xmit_hash_tx_queue_q0,
		   trustix_datapath_rx_worker_xmit_hash_tx_queue_q0, ullong,
		   0444);
static unsigned long long trustix_datapath_rx_worker_xmit_hash_tx_queue_q1;
module_param_named(rx_worker_xmit_hash_tx_queue_q1,
		   trustix_datapath_rx_worker_xmit_hash_tx_queue_q1, ullong,
		   0444);
static unsigned long long trustix_datapath_rx_worker_xmit_hash_tx_queue_q2;
module_param_named(rx_worker_xmit_hash_tx_queue_q2,
		   trustix_datapath_rx_worker_xmit_hash_tx_queue_q2, ullong,
		   0444);
static unsigned long long trustix_datapath_rx_worker_xmit_hash_tx_queue_q3;
module_param_named(rx_worker_xmit_hash_tx_queue_q3,
		   trustix_datapath_rx_worker_xmit_hash_tx_queue_q3, ullong,
		   0444);
static unsigned long long trustix_datapath_rx_worker_xmit_hash_tx_queue_q4;
module_param_named(rx_worker_xmit_hash_tx_queue_q4,
		   trustix_datapath_rx_worker_xmit_hash_tx_queue_q4, ullong,
		   0444);
static unsigned long long trustix_datapath_rx_worker_xmit_hash_tx_queue_q5;
module_param_named(rx_worker_xmit_hash_tx_queue_q5,
		   trustix_datapath_rx_worker_xmit_hash_tx_queue_q5, ullong,
		   0444);
static unsigned long long trustix_datapath_rx_worker_xmit_hash_tx_queue_q6;
module_param_named(rx_worker_xmit_hash_tx_queue_q6,
		   trustix_datapath_rx_worker_xmit_hash_tx_queue_q6, ullong,
		   0444);
static unsigned long long trustix_datapath_rx_worker_xmit_hash_tx_queue_q7;
module_param_named(rx_worker_xmit_hash_tx_queue_q7,
		   trustix_datapath_rx_worker_xmit_hash_tx_queue_q7, ullong,
		   0444);
static unsigned long long
	trustix_datapath_rx_worker_xmit_hash_tx_queue_other;
module_param_named(rx_worker_xmit_hash_tx_queue_other,
		   trustix_datapath_rx_worker_xmit_hash_tx_queue_other, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_xmit_hash_tx_queue_other,
		 "TrustIX RX worker LAN xmit queue-hash assignments above queue 7");

static unsigned long long trustix_datapath_rx_worker_xmit_more_sets;
module_param_named(rx_worker_xmit_more_sets,
		   trustix_datapath_rx_worker_xmit_more_sets, ullong, 0444);
MODULE_PARM_DESC(rx_worker_xmit_more_sets,
		 "TrustIX RX worker LAN xmit skbs sent with skb xmit_more set");

static int trustix_datapath_rx_worker_last_push_ret;
module_param_named(rx_worker_last_push_ret,
		   trustix_datapath_rx_worker_last_push_ret, int, 0444);
MODULE_PARM_DESC(rx_worker_last_push_ret,
		 "Last TrustIX RX worker enqueue return code");

static int trustix_datapath_rx_worker_last_deliver_ret;
module_param_named(rx_worker_last_deliver_ret,
		   trustix_datapath_rx_worker_last_deliver_ret, int, 0444);
MODULE_PARM_DESC(rx_worker_last_deliver_ret,
		 "Last TrustIX RX worker delivery return code");

static int trustix_datapath_rx_worker_last_xmit_ret;
module_param_named(rx_worker_last_xmit_ret,
		   trustix_datapath_rx_worker_last_xmit_ret, int, 0444);
MODULE_PARM_DESC(rx_worker_last_xmit_ret,
		 "Last raw TrustIX RX worker dev_queue_xmit return value");

static int trustix_datapath_rx_worker_last_xmit_error_ret;
module_param_named(rx_worker_last_xmit_error_ret,
		   trustix_datapath_rx_worker_last_xmit_error_ret, int, 0444);
MODULE_PARM_DESC(rx_worker_last_xmit_error_ret,
		 "Last non-success TrustIX RX worker dev_queue_xmit return value");

static DEFINE_SPINLOCK(trustix_datapath_rx_stage_lock);
static struct trustix_datapath_rx_stage_slot *trustix_datapath_rx_stage_ring;
static __u8 *trustix_datapath_rx_stage_data;
static __u32 trustix_datapath_rx_stage_capacity;
static __u32 trustix_datapath_rx_stage_head;
static __u32 trustix_datapath_rx_stage_tail;
static __u32 trustix_datapath_rx_stage_count;
static __u64 trustix_datapath_rx_stage_next_id;
static __u64 trustix_datapath_rx_stage_staged;
static __u64 trustix_datapath_rx_stage_popped;
static __u64 trustix_datapath_rx_stage_dropped;
static __u64 trustix_datapath_rx_stage_overwritten;

static DEFINE_SPINLOCK(trustix_datapath_rx_worker_lock);
static struct trustix_datapath_rx_worker_slot *trustix_datapath_rx_worker_ring;
static struct trustix_datapath_rx_worker_slot
	*trustix_datapath_rx_worker_coalesce_slots;
static struct trustix_datapath_rx_worker_pending_copy
	*trustix_datapath_rx_worker_coalesce_pending;
static unsigned int trustix_datapath_rx_worker_coalesce_scratch_capacity;
module_param_named(rx_worker_stream_coalesce_scratch_capacity,
		   trustix_datapath_rx_worker_coalesce_scratch_capacity, uint,
		   0444);
MODULE_PARM_DESC(rx_worker_stream_coalesce_scratch_capacity,
		 "Preallocated RX worker stream coalesce scratch frame capacity");
static __u32 trustix_datapath_rx_worker_capacity;
static __u32 trustix_datapath_rx_worker_head;
static __u32 trustix_datapath_rx_worker_tail;
static __u32 trustix_datapath_rx_worker_count;
static struct workqueue_struct *trustix_datapath_rx_worker_wq;
static void trustix_datapath_rx_worker_run(struct work_struct *work);
static DECLARE_WORK(trustix_datapath_rx_worker_work,
		    trustix_datapath_rx_worker_run);
static unsigned long long trustix_datapath_rx_worker_queue_work_calls;
module_param_named(rx_worker_queue_work_calls,
		   trustix_datapath_rx_worker_queue_work_calls, ullong, 0444);
MODULE_PARM_DESC(rx_worker_queue_work_calls,
		 "TrustIX RX worker queue_work attempts");
static unsigned long long trustix_datapath_rx_worker_queue_work_enqueued;
module_param_named(rx_worker_queue_work_enqueued,
		   trustix_datapath_rx_worker_queue_work_enqueued, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_queue_work_enqueued,
		 "TrustIX RX worker queue_work calls that accepted a new work item");
static unsigned long long trustix_datapath_rx_worker_runs;
module_param_named(rx_worker_runs, trustix_datapath_rx_worker_runs, ullong,
		   0444);
MODULE_PARM_DESC(rx_worker_runs, "TrustIX RX worker workqueue callbacks run");
static unsigned long long trustix_datapath_rx_worker_run_processed;
module_param_named(rx_worker_run_processed,
		   trustix_datapath_rx_worker_run_processed, ullong, 0444);
MODULE_PARM_DESC(rx_worker_run_processed,
		 "TrustIX RX worker slots processed by workqueue callbacks");

static void trustix_datapath_rx_worker_kick(void)
{
	if (!trustix_datapath_rx_worker_wq)
		return;
	trustix_datapath_rx_worker_queue_work_calls++;
	if (queue_work(trustix_datapath_rx_worker_wq,
		       &trustix_datapath_rx_worker_work))
		trustix_datapath_rx_worker_queue_work_enqueued++;
}

#define TRUSTIX_DATAPATH_RX_WORKER_MAC_CACHE_SETS 64
#define TRUSTIX_DATAPATH_RX_WORKER_MAC_CACHE_WAYS 4
#define TRUSTIX_DATAPATH_MAC_CACHE_TTL (30 * HZ)

struct trustix_datapath_rx_worker_mac_cache_entry {
	int ifindex;
	__be32 dst_ipv4;
	__u64 addr64;
	unsigned long expires;
	bool valid;
};

struct trustix_datapath_rx_worker_mac_cache {
	struct trustix_datapath_rx_worker_mac_cache_entry entries[
		TRUSTIX_DATAPATH_RX_WORKER_MAC_CACHE_SETS *
		TRUSTIX_DATAPATH_RX_WORKER_MAC_CACHE_WAYS];
	__u8 next[TRUSTIX_DATAPATH_RX_WORKER_MAC_CACHE_SETS];
};

#define TRUSTIX_DATAPATH_TX_PLAINTEXT_MAC_CACHE_SETS 16
#define TRUSTIX_DATAPATH_TX_PLAINTEXT_MAC_CACHE_WAYS 4

struct trustix_datapath_tx_plaintext_mac_cache_entry {
	int ifindex;
	__be32 local_ipv4;
	__be32 remote_ipv4;
	__be16 local_port;
	__be16 remote_port;
	__u8 protocol;
	__u64 addr64;
	unsigned long expires;
	bool valid;
};

struct trustix_datapath_tx_plaintext_mac_cache {
	struct trustix_datapath_tx_plaintext_mac_cache_entry entries[
		TRUSTIX_DATAPATH_TX_PLAINTEXT_MAC_CACHE_SETS *
		TRUSTIX_DATAPATH_TX_PLAINTEXT_MAC_CACHE_WAYS];
	__u8 next[TRUSTIX_DATAPATH_TX_PLAINTEXT_MAC_CACHE_SETS];
};

static DEFINE_SPINLOCK(trustix_datapath_rx_worker_mac_cache_lock);
static struct trustix_datapath_rx_worker_mac_cache
	trustix_datapath_rx_worker_mac_cache;
static struct trustix_datapath_rx_worker_mac_cache __percpu
	*trustix_datapath_rx_worker_pcpu_mac_cache;
static DEFINE_SEQLOCK(trustix_datapath_rx_worker_seq_mac_cache_lock);
static struct trustix_datapath_rx_worker_mac_cache
	trustix_datapath_rx_worker_seq_mac_cache;
static DEFINE_SEQLOCK(trustix_datapath_tx_plaintext_seq_mac_cache_lock);
static struct trustix_datapath_tx_plaintext_mac_cache
	trustix_datapath_tx_plaintext_seq_mac_cache;

static int trustix_datapath_alloc_rx_worker_pcpu_mac_cache(void)
{
	trustix_datapath_rx_worker_pcpu_mac_cache =
		alloc_percpu(struct trustix_datapath_rx_worker_mac_cache);
	if (!trustix_datapath_rx_worker_pcpu_mac_cache)
		return -ENOMEM;
	return 0;
}

static void trustix_datapath_free_rx_worker_pcpu_mac_cache(void)
{
	if (!trustix_datapath_rx_worker_pcpu_mac_cache)
		return;
	free_percpu(trustix_datapath_rx_worker_pcpu_mac_cache);
	trustix_datapath_rx_worker_pcpu_mac_cache = NULL;
}

static __always_inline unsigned int
trustix_datapath_rx_worker_mac_cache_set(int ifindex, __be32 dst_ipv4)
{
	__u32 hash = (__u32)ifindex;

	hash = (hash * 16777619U) ^ (__force __u32)dst_ipv4;
	hash ^= hash >> 16;
	hash *= 0x7feb352dU;
	hash ^= hash >> 15;
	hash *= 0x846ca68bU;
	hash ^= hash >> 16;
	return hash & (TRUSTIX_DATAPATH_RX_WORKER_MAC_CACHE_SETS - 1);
}

static bool trustix_datapath_rx_worker_mac_cache_lookup(
	const struct trustix_datapath_rx_worker_mac_cache *cache, int ifindex,
	__be32 dst_ipv4, __u8 *addr)
{
	unsigned int set;
	unsigned int start;
	unsigned int i;

	if (!cache || !addr)
		return false;
	set = trustix_datapath_rx_worker_mac_cache_set(ifindex, dst_ipv4);
	start = set * TRUSTIX_DATAPATH_RX_WORKER_MAC_CACHE_WAYS;
	for (i = 0; i < TRUSTIX_DATAPATH_RX_WORKER_MAC_CACHE_WAYS; i++) {
		const struct trustix_datapath_rx_worker_mac_cache_entry *entry =
			&cache->entries[start + i];

		if (!entry->valid || time_after_eq(jiffies, entry->expires) ||
		    entry->ifindex != ifindex ||
		    entry->dst_ipv4 != dst_ipv4)
			continue;
		trustix_datapath_rx_worker_u64_to_mac(entry->addr64, addr);
		return true;
	}
	return false;
}

static void trustix_datapath_rx_worker_mac_cache_store(
	struct trustix_datapath_rx_worker_mac_cache *cache, int ifindex,
	__be32 dst_ipv4, const __u8 *addr)
{
	struct trustix_datapath_rx_worker_mac_cache_entry *entry = NULL;
	struct trustix_datapath_rx_worker_mac_cache_entry *empty = NULL;
	unsigned int set;
	unsigned int start;
	unsigned int i;

	if (!cache || !addr)
		return;
	set = trustix_datapath_rx_worker_mac_cache_set(ifindex, dst_ipv4);
	start = set * TRUSTIX_DATAPATH_RX_WORKER_MAC_CACHE_WAYS;
	for (i = 0; i < TRUSTIX_DATAPATH_RX_WORKER_MAC_CACHE_WAYS; i++) {
		struct trustix_datapath_rx_worker_mac_cache_entry *candidate =
			&cache->entries[start + i];

		if (candidate->valid && candidate->ifindex == ifindex &&
		    candidate->dst_ipv4 == dst_ipv4) {
			entry = candidate;
			break;
		}
		if ((!candidate->valid ||
		     time_after_eq(jiffies, candidate->expires)) &&
		    !empty)
			empty = candidate;
	}
	if (!entry)
		entry = empty;
	if (!entry) {
		i = cache->next[set] %
		    TRUSTIX_DATAPATH_RX_WORKER_MAC_CACHE_WAYS;
		entry = &cache->entries[start + i];
		cache->next[set] =
			(i + 1) % TRUSTIX_DATAPATH_RX_WORKER_MAC_CACHE_WAYS;
	}
	entry->ifindex = ifindex;
	entry->dst_ipv4 = dst_ipv4;
	entry->addr64 = trustix_datapath_rx_worker_mac_to_u64(addr);
	entry->expires = jiffies + TRUSTIX_DATAPATH_MAC_CACHE_TTL;
	entry->valid = true;
}

static __u16 trustix_datapath_get_be16(const __u8 *ptr)
{
	return ((__u16)ptr[0] << 8) | (__u16)ptr[1];
}

static __u32 trustix_datapath_get_be32(const __u8 *ptr)
{
	return ((__u32)ptr[0] << 24) | ((__u32)ptr[1] << 16) |
	       ((__u32)ptr[2] << 8) | (__u32)ptr[3];
}

static __u64 trustix_datapath_get_be64(const __u8 *ptr)
{
	return ((__u64)trustix_datapath_get_be32(ptr) << 32) |
	       (__u64)trustix_datapath_get_be32(ptr + 4);
}

static void trustix_datapath_put_be16(__u8 *ptr, __u16 value)
{
	ptr[0] = (__u8)(value >> 8);
	ptr[1] = (__u8)value;
}

static void trustix_datapath_put_be32(__u8 *ptr, __u32 value)
{
	ptr[0] = (__u8)(value >> 24);
	ptr[1] = (__u8)(value >> 16);
	ptr[2] = (__u8)(value >> 8);
	ptr[3] = (__u8)value;
}

static void trustix_datapath_put_be64(__u8 *ptr, __u64 value)
{
	trustix_datapath_put_be32(ptr, (__u32)(value >> 32));
	trustix_datapath_put_be32(ptr + 4, (__u32)value);
}

static void trustix_datapath_unpack_bytes(__u64 value, __u8 *dst,
					 unsigned int count)
{
	unsigned int i;

	if (!dst)
		return;
	for (i = 0; i < count && i < sizeof(value); i++)
		dst[i] = (__u8)(value >> (i * 8));
}

static __always_inline void
trustix_datapath_secure_prepare_nonce(__u8 nonce[12], const __u8 iv[12],
				      __u64 sequence)
{
	memcpy(nonce, iv, 4);
	trustix_datapath_put_be64(nonce + 4, sequence);
}

static __always_inline void
trustix_datapath_secure_write_header(__u8 *dst, __u16 suite, __u64 epoch,
				     __u64 sequence)
{
	trustix_datapath_put_be32(dst, TRUSTIX_DATAPATH_SECURE_MAGIC);
	dst[4] = TRUSTIX_DATAPATH_SECURE_VERSION;
	dst[5] = (__u8)suite;
	dst[6] = 0;
	dst[7] = 0;
	trustix_datapath_put_be64(dst + 8, epoch);
	trustix_datapath_put_be64(dst + 16, sequence);
}

static int trustix_datapath_secure_validate_header(
	const __u8 *header, __u16 suite, __u64 epoch, __u64 sequence)
{
	if (!header)
		return -EINVAL;
	if (trustix_datapath_get_be32(header) !=
		    TRUSTIX_DATAPATH_SECURE_MAGIC ||
	    header[4] != TRUSTIX_DATAPATH_SECURE_VERSION ||
	    header[5] != (__u8)suite || header[6] || header[7])
		return -EBADMSG;
	if (trustix_datapath_get_be64(header + 8) != epoch ||
	    trustix_datapath_get_be64(header + 16) != sequence)
		return -ESTALE;
	return 0;
}

static int trustix_datapath_secure_tx_reserve(
	const struct trustix_datapath_tx_plan *plan, __u32 count,
	__u64 *first_sequence)
{
	__u64 generation = 0;
	int ret;

	if (!plan || !plan->secure || !first_sequence || !count ||
	    count > TRUSTIX_DATAPATH_DIRECT_MAX_BATCH ||
	    !trustix_datapath_crypto_reserve_sequences)
		return -EINVAL;
	*first_sequence = 0;
	ret = trustix_datapath_crypto_reserve_sequences(
		plan->send_slot, 1ULL << 63, count, first_sequence,
		&generation);
	if (ret == -ENOENT)
		ret = -ESTALE;
	if (ret == -ESTALE)
		trustix_datapath_secure_tx_stale++;
	if (ret)
		return ret;
	if (!generation || generation != plan->send_generation) {
		trustix_datapath_secure_tx_stale++;
		return -ESTALE;
	}
	return 0;
}

static int trustix_datapath_secure_tx_seal(
	const struct trustix_datapath_tx_plan *plan,
	const struct trustix_aead_direct_batch_op *ops, __u32 count)
{
	int ret;

	if (!plan || !plan->secure || !ops || !count ||
	    count > TRUSTIX_DATAPATH_DIRECT_MAX_BATCH ||
	    !trustix_datapath_crypto_seal_batch)
		return -EINVAL;
	ret = trustix_datapath_crypto_seal_batch(
		plan->send_slot, plan->send_generation, ops, count);
	if (ret == -ENOENT)
		ret = -ESTALE;
	if (ret == -ESTALE)
		trustix_datapath_secure_tx_stale++;
	if (ret)
		return ret;
	trustix_datapath_secure_tx_batches++;
	trustix_datapath_secure_tx_frames += count;
	return 0;
}

static bool trustix_datapath_dev_supports_tcpv4_gso(struct net_device *dev)
{
	netdev_features_t features;

	if (!dev)
		return false;
	features = READ_ONCE(dev->features);
	if (!(features & NETIF_F_TSO))
		return false;
	if (features & NETIF_F_HW_CSUM)
		return true;
#ifdef NETIF_F_IP_CSUM
	if (features & NETIF_F_IP_CSUM)
		return true;
#endif
	return false;
}

static void
trustix_datapath_debug_record_outer(int stage, int ret, int worker_ret,
				    struct sk_buff *skb,
				    const struct trustix_datapath_ioc_classify *classify,
				    __u8 ip_header_len, __u8 l4_header_len)
{
	const __u8 *network;
	const __u8 *frame;
	__u32 total_len = 0;
	__u32 l4_len = 0;
	__u32 frame_len = 0;
	__u32 frame_offset = 0;
	__u32 magic = 0;
	__u32 payload_len = 0;
	__u16 header_len = 0;
	__u64 flow_id = 0;
	__u8 flags = 0;

	if (skb) {
		WRITE_ONCE(trustix_datapath_debug_last_outer_skb_len,
			   (unsigned int)skb->len);
		network = skb_network_header(skb);
		if (network && ip_header_len >= 20 && skb->len >= ip_header_len) {
			total_len = trustix_datapath_get_be16(network + 2);
			if (total_len >= ip_header_len)
				l4_len = total_len - ip_header_len;
			if (classify) {
				if (classify->protocol == IPPROTO_UDP &&
				    l4_header_len == 8 && l4_len >= 8) {
					frame_offset = ip_header_len + 8;
					frame_len = l4_len - 8;
				} else if (classify->protocol == IPPROTO_TCP &&
					   l4_header_len >= 20 &&
					   l4_len >= l4_header_len) {
					frame_offset = ip_header_len +
						       l4_header_len;
					frame_len = l4_len - l4_header_len;
				}
			}
			if (frame_len >= TRUSTIX_DATAPATH_MIN_FRAME_HEADER_LEN &&
			    frame_offset <= skb_headlen(skb) &&
			    frame_len <= skb_headlen(skb) - frame_offset) {
				frame = network + frame_offset;
				magic = trustix_datapath_get_be32(frame);
				flags = frame[5];
				header_len = trustix_datapath_get_be16(frame + 6);
				flow_id = trustix_datapath_get_be64(frame + 8);
				if (magic == TRUSTIX_DATAPATH_TIXT_MAGIC &&
				    frame_len >= TRUSTIX_DATAPATH_TIXT_HEADER_LEN)
					payload_len =
						trustix_datapath_get_be32(frame + 32);
				else if (magic == TRUSTIX_DATAPATH_TIXU_MAGIC &&
					 frame_len >= TRUSTIX_DATAPATH_TIXU_HEADER_LEN)
					payload_len =
						trustix_datapath_get_be32(frame + 24);
			}
		}
	} else {
		WRITE_ONCE(trustix_datapath_debug_last_outer_skb_len, 0);
	}

	WRITE_ONCE(trustix_datapath_debug_last_outer_stage, stage);
	WRITE_ONCE(trustix_datapath_debug_last_outer_ret, ret);
	WRITE_ONCE(trustix_datapath_debug_last_worker_ret, worker_ret);
	WRITE_ONCE(trustix_datapath_debug_last_outer_protocol,
		   classify ? (unsigned int)classify->protocol : 0);
	WRITE_ONCE(trustix_datapath_debug_last_outer_src_port,
		   classify ? (unsigned int)classify->src_port : 0);
	WRITE_ONCE(trustix_datapath_debug_last_outer_dst_port,
		   classify ? (unsigned int)classify->dst_port : 0);
	WRITE_ONCE(trustix_datapath_debug_last_outer_ip_len, total_len);
	WRITE_ONCE(trustix_datapath_debug_last_outer_l4_len, l4_len);
	WRITE_ONCE(trustix_datapath_debug_last_outer_frame_len, frame_len);
	WRITE_ONCE(trustix_datapath_debug_last_outer_magic, magic);
	WRITE_ONCE(trustix_datapath_debug_last_outer_frame_flags,
		   (unsigned int)flags);
	WRITE_ONCE(trustix_datapath_debug_last_outer_header_len,
		   (unsigned int)header_len);
	WRITE_ONCE(trustix_datapath_debug_last_outer_payload_len, payload_len);
	WRITE_ONCE(trustix_datapath_debug_last_outer_flow_id, flow_id);
}

static void
trustix_datapath_debug_record_udp(struct sk_buff *skb,
				  const struct trustix_datapath_ioc_classify *classify,
				  __u8 ip_header_len)
{
	const __u8 *network;
	const __u8 *frame;
	__u32 total_len = 0;
	__u32 udp_len = 0;
	__u32 payload_len = 0;
	__u32 magic = 0;

	if (!skb || !classify || classify->protocol != IPPROTO_UDP ||
	    ip_header_len != 20)
		return;
	if (!pskb_may_pull(skb, 28))
		return;
	network = skb_network_header(skb);
	if (!network)
		return;
	total_len = trustix_datapath_get_be16(network + 2);
	udp_len = trustix_datapath_get_be16(network + 24);
	if (udp_len >= 8)
		payload_len = udp_len - 8;
	if (payload_len >= 4 && pskb_may_pull(skb, 32)) {
		network = skb_network_header(skb);
		frame = network + 28;
		magic = trustix_datapath_get_be32(frame);
		if (magic == TRUSTIX_DATAPATH_TIXT_MAGIC ||
		    magic == TRUSTIX_DATAPATH_TIXU_MAGIC)
			trustix_datapath_debug_udp_tix_seen++;
	}
	trustix_datapath_debug_udp_seen++;
	WRITE_ONCE(trustix_datapath_debug_last_udp_src_port,
		   (unsigned int)classify->src_port);
	WRITE_ONCE(trustix_datapath_debug_last_udp_dst_port,
		   (unsigned int)classify->dst_port);
	WRITE_ONCE(trustix_datapath_debug_last_udp_total_len, total_len);
	WRITE_ONCE(trustix_datapath_debug_last_udp_len, udp_len);
	WRITE_ONCE(trustix_datapath_debug_last_udp_payload_len, payload_len);
	WRITE_ONCE(trustix_datapath_debug_last_udp_magic, magic);
}

static void
trustix_datapath_build_tixt(__u8 *wire, __u8 flags, __u64 flow_id,
			    __u64 epoch, __u64 sequence, __u32 payload_len,
			    __u16 fragment_index, __u16 fragment_count);

static void
trustix_datapath_build_tixt_header(__u8 *wire, __u8 flags, __u64 flow_id,
				   __u64 epoch, __u64 sequence,
				   __u32 payload_len, __u16 fragment_index,
				   __u16 fragment_count);

static int
trustix_datapath_parse_tixt(const __u8 *wire, __u32 len,
			    struct trustix_datapath_tixt_frame *frame);

static int
trustix_datapath_parse_tixt_header(const __u8 *wire, __u32 len,
				   struct trustix_datapath_tixt_frame *frame);

static bool trustix_datapath_frame_magic_supported(const __u8 *wire)
{
	__u32 magic;

	if (!wire)
		return false;
	magic = trustix_datapath_get_be32(wire);
	return magic == TRUSTIX_DATAPATH_TIXT_MAGIC ||
	       magic == TRUSTIX_DATAPATH_TIXU_MAGIC;
}

static void trustix_datapath_crypto_api_put(void)
{
	if (trustix_datapath_crypto_selftest)
		symbol_put_addr(trustix_datapath_crypto_selftest);
	if (trustix_datapath_crypto_open_replay_batch)
		symbol_put_addr(trustix_datapath_crypto_open_replay_batch);
	if (trustix_datapath_crypto_seal_batch)
		symbol_put_addr(trustix_datapath_crypto_seal_batch);
	if (trustix_datapath_crypto_reserve_sequences)
		symbol_put_addr(trustix_datapath_crypto_reserve_sequences);
	if (trustix_datapath_crypto_slot_generation)
		symbol_put_addr(trustix_datapath_crypto_slot_generation);
	if (trustix_datapath_crypto_ready)
		symbol_put_addr(trustix_datapath_crypto_ready);
	trustix_datapath_crypto_open_replay_batch = NULL;
	trustix_datapath_crypto_seal_batch = NULL;
	trustix_datapath_crypto_reserve_sequences = NULL;
	trustix_datapath_crypto_slot_generation = NULL;
	trustix_datapath_crypto_ready = NULL;
	trustix_datapath_crypto_selftest = NULL;
}

static int trustix_datapath_crypto_api_get(void)
{
	if (!(READ_ONCE(trustix_datapath_enable_features) &
	      TRUSTIX_DATAPATH_FEATURE_SECURE_TIX_TCP_FULL_DATAPATH))
		return 0;

	trustix_datapath_crypto_ready =
		symbol_get(trustix_kernel_direct_datapath_ready);
	trustix_datapath_crypto_selftest =
		symbol_get(trustix_kernel_direct_datapath_selftest);
	trustix_datapath_crypto_slot_generation =
		symbol_get(trustix_kernel_direct_slot_generation);
	trustix_datapath_crypto_reserve_sequences =
		symbol_get(trustix_kernel_direct_reserve_sequences);
	trustix_datapath_crypto_seal_batch =
		symbol_get(trustix_kernel_direct_seal_batch_generation);
	trustix_datapath_crypto_open_replay_batch =
		symbol_get(trustix_kernel_direct_open_replay_batch);
	if (!trustix_datapath_crypto_ready ||
	    !trustix_datapath_crypto_selftest ||
	    !trustix_datapath_crypto_slot_generation ||
	    !trustix_datapath_crypto_reserve_sequences ||
	    !trustix_datapath_crypto_seal_batch ||
	    !trustix_datapath_crypto_open_replay_batch) {
		trustix_datapath_crypto_api_put();
		return -EOPNOTSUPP;
	}
	if (!trustix_datapath_crypto_ready()) {
		trustix_datapath_crypto_api_put();
		return -EOPNOTSUPP;
	}
	return 0;
}

static __u32 trustix_datapath_clamp_capacity(unsigned int requested)
{
	if (!requested)
		return 1;
	if (requested > TRUSTIX_DATAPATH_STATE_MAX_ENTRIES)
		return TRUSTIX_DATAPATH_STATE_MAX_ENTRIES;
	return requested;
}

static int
trustix_datapath_alloc_table(struct trustix_datapath_state_table *table,
			     unsigned int requested)
{
	table->capacity = trustix_datapath_clamp_capacity(requested);
	table->count = 0;
	table->slots = vzalloc(array_size(table->capacity,
					  sizeof(*table->slots)));
	if (!table->slots)
		return -ENOMEM;
	return 0;
}

static void trustix_datapath_free_table(struct trustix_datapath_state_table *table)
{
	vfree(table->slots);
	table->slots = NULL;
	table->capacity = 0;
	table->count = 0;
}

static __u32 trustix_datapath_clamp_lookup_cache_slots(unsigned int requested)
{
	if (requested < TRUSTIX_DATAPATH_LOOKUP_CACHE_MIN_SLOTS)
		return TRUSTIX_DATAPATH_LOOKUP_CACHE_MIN_SLOTS;
	if (requested > TRUSTIX_DATAPATH_LOOKUP_CACHE_MAX_SLOTS)
		return TRUSTIX_DATAPATH_LOOKUP_CACHE_MAX_SLOTS;
	return requested;
}

static __u32
trustix_datapath_clamp_wire_tuple_cache_slots(unsigned int requested)
{
	if (requested < TRUSTIX_DATAPATH_LOOKUP_CACHE_MIN_SLOTS)
		return TRUSTIX_DATAPATH_LOOKUP_CACHE_MIN_SLOTS;
	if (requested > TRUSTIX_DATAPATH_WIRE_TUPLE_CACHE_MAX_SLOTS)
		return TRUSTIX_DATAPATH_WIRE_TUPLE_CACHE_MAX_SLOTS;
	return requested;
}

static int trustix_datapath_alloc_lookup_caches(void)
{
	__u32 sessions = trustix_datapath_clamp_capacity(
		trustix_datapath_max_sessions);
	__u32 routes = trustix_datapath_clamp_capacity(
		trustix_datapath_max_routes);
	__u32 route_capacity =
		trustix_datapath_clamp_lookup_cache_slots(routes * 16U);
	__u32 session_route_capacity =
		trustix_datapath_clamp_lookup_cache_slots(sessions * 2U);
	__u32 flow_capacity =
		trustix_datapath_clamp_lookup_cache_slots(sessions * 2U);
	__u32 wire_capacity =
		trustix_datapath_clamp_wire_tuple_cache_slots(sessions * 40U);
	__u32 sequence_capacity =
		sessions * TRUSTIX_DATAPATH_TIX_TCP_PORT_SHARDS;

	trustix_datapath_route_dst_cache =
		vzalloc(array_size(route_capacity,
				   sizeof(*trustix_datapath_route_dst_cache)));
	if (!trustix_datapath_route_dst_cache)
		return -ENOMEM;
	trustix_datapath_route_dst_cache_capacity = route_capacity;
	trustix_datapath_session_route_cache =
		vzalloc(array_size(session_route_capacity,
				   sizeof(*trustix_datapath_session_route_cache)));
	if (!trustix_datapath_session_route_cache)
		goto free_route_cache;
	trustix_datapath_session_route_cache_capacity =
		session_route_capacity;
	trustix_datapath_session_flow_cache =
		vzalloc(array_size(flow_capacity,
				   sizeof(*trustix_datapath_session_flow_cache)));
	if (!trustix_datapath_session_flow_cache)
		goto free_session_route_cache;
	trustix_datapath_session_flow_cache_capacity = flow_capacity;
	trustix_datapath_session_wire_tuple_cache =
		vzalloc(array_size(
			wire_capacity,
			sizeof(*trustix_datapath_session_wire_tuple_cache)));
	if (!trustix_datapath_session_wire_tuple_cache) {
		goto free_session_flow_cache;
	}
	trustix_datapath_session_wire_tuple_cache_capacity = wire_capacity;
	trustix_datapath_outer_tcp_shard_sequences =
		vzalloc(array_size(sequence_capacity,
				   sizeof(*trustix_datapath_outer_tcp_shard_sequences)));
	if (!trustix_datapath_outer_tcp_shard_sequences)
		goto free_wire_cache;
	trustix_datapath_outer_tcp_sequence_flow_slots = sessions;
	return 0;

free_wire_cache:
	vfree(trustix_datapath_session_wire_tuple_cache);
	trustix_datapath_session_wire_tuple_cache = NULL;
	trustix_datapath_session_wire_tuple_cache_capacity = 0;
free_session_flow_cache:
	vfree(trustix_datapath_session_flow_cache);
	trustix_datapath_session_flow_cache = NULL;
	trustix_datapath_session_flow_cache_capacity = 0;
free_session_route_cache:
	vfree(trustix_datapath_session_route_cache);
	trustix_datapath_session_route_cache = NULL;
	trustix_datapath_session_route_cache_capacity = 0;
free_route_cache:
	vfree(trustix_datapath_route_dst_cache);
	trustix_datapath_route_dst_cache = NULL;
	trustix_datapath_route_dst_cache_capacity = 0;
	return -ENOMEM;
}

static void trustix_datapath_free_lookup_caches(void)
{
	vfree(trustix_datapath_session_wire_tuple_cache);
	vfree(trustix_datapath_session_flow_cache);
	vfree(trustix_datapath_session_route_cache);
	vfree(trustix_datapath_route_dst_cache);
	trustix_datapath_session_wire_tuple_cache = NULL;
	trustix_datapath_session_flow_cache = NULL;
	trustix_datapath_session_route_cache = NULL;
	trustix_datapath_route_dst_cache = NULL;
	trustix_datapath_session_wire_tuple_cache_capacity = 0;
	trustix_datapath_session_flow_cache_capacity = 0;
	trustix_datapath_session_route_cache_capacity = 0;
	trustix_datapath_route_dst_cache_capacity = 0;
}

static void
trustix_datapath_publish_state_counts_locked(void)
{
	WRITE_ONCE(trustix_datapath_route_records,
		   trustix_datapath_routes.count);
	WRITE_ONCE(trustix_datapath_session_records,
		   trustix_datapath_sessions.count);
	WRITE_ONCE(trustix_datapath_flow_records, trustix_datapath_flows.count);
	WRITE_ONCE(trustix_datapath_session_wire_records,
		   trustix_datapath_session_wires.count);
	WRITE_ONCE(trustix_datapath_session_crypto_records,
		   trustix_datapath_session_crypto.count);
}

static bool
trustix_datapath_table_usable_locked(
	const struct trustix_datapath_state_table *table)
{
	if (!table || !table->slots || !table->capacity)
		return false;
	if (table->capacity > TRUSTIX_DATAPATH_STATE_MAX_ENTRIES)
		return false;
	if (table->count > table->capacity)
		return false;
	return true;
}

static __u32 trustix_datapath_clamp_rx_stage_slots(unsigned int requested)
{
	if (!requested)
		return 1;
	if (requested > TRUSTIX_DATAPATH_RX_STAGE_MAX_SLOTS)
		return TRUSTIX_DATAPATH_RX_STAGE_MAX_SLOTS;
	return requested;
}

static __u32 trustix_datapath_clamp_rx_worker_slots(unsigned int requested)
{
	if (!requested)
		return 1;
	if (requested > TRUSTIX_DATAPATH_RX_WORKER_MAX_SLOTS)
		return TRUSTIX_DATAPATH_RX_WORKER_MAX_SLOTS;
	return requested;
}

static int trustix_datapath_alloc_inner_gso_reassembly(void)
{
	__u8 *data;
	unsigned int i;

	data = vzalloc(array3_size(
		TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_SLOTS,
		TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_FRAME_MAX,
		sizeof(*data)));
	for (i = 0; i < TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_SETS; i++)
		spin_lock_init(&trustix_datapath_inner_gso_reassembly_locks[i]);
	for (i = 0; i < TRUSTIX_DATAPATH_INNER_GSO_PROBATION_SETS; i++)
		spin_lock_init(&trustix_datapath_inner_gso_probation_locks[i]);
	memset(trustix_datapath_inner_gso_probation_slots, 0,
	       sizeof(trustix_datapath_inner_gso_probation_slots));
	for (i = 0; i < TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_SLOTS; i++) {
		struct trustix_datapath_inner_gso_reassembly_slot *slot =
			&trustix_datapath_inner_gso_reassembly_slots[i];

		memset(slot, 0, sizeof(*slot));
		if (data)
			slot->data = data +
				i * TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_FRAME_MAX;
	}
	trustix_datapath_inner_gso_reassembly_data = data;
	return data ? 0 : -ENOMEM;
}

static unsigned int trustix_datapath_clear_inner_gso_reassembly_matching(
	bool all, __u64 flow_id, __u64 epoch)
{
	unsigned long flags;
	unsigned int set;
	unsigned int cleared = 0;

	for (set = 0; set < TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_SETS;
	     set++) {
		unsigned int first =
			set * TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_PROBES;
		unsigned int i;

		spin_lock_irqsave(
			&trustix_datapath_inner_gso_reassembly_locks[set],
			flags);
		for (i = 0; i < TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_PROBES;
		     i++) {
			struct trustix_datapath_inner_gso_reassembly_slot *slot =
				&trustix_datapath_inner_gso_reassembly_slots[
					first + i];
			__u8 *data = slot->data;

			if (!all &&
			    (!slot->active || slot->flow_id != flow_id ||
			     (epoch && slot->epoch != epoch)))
				continue;
			if (slot->active)
				cleared++;
			memset(slot, 0, sizeof(*slot));
			slot->data = data;
		}
		spin_unlock_irqrestore(
			&trustix_datapath_inner_gso_reassembly_locks[set],
			flags);
	}
	return cleared;
}

static void trustix_datapath_clear_inner_gso_reassembly(void)
{
	trustix_datapath_clear_inner_gso_reassembly_matching(true, 0, 0);
}

static void trustix_datapath_clear_inner_gso_reassembly_for_session(
	__u64 flow_id, __u64 epoch)
{
	unsigned int cleared;

	if (!flow_id)
		return;
	cleared = trustix_datapath_clear_inner_gso_reassembly_matching(
		false, flow_id, epoch);
	trustix_datapath_clear_inner_gso_probation_matching(
		false, flow_id, epoch);
	trustix_datapath_rx_worker_inner_gso_session_clears++;
	trustix_datapath_rx_worker_inner_gso_session_slots_cleared += cleared;
}

static void trustix_datapath_clear_inner_gso_reassembly_for_all_sessions(void)
{
	unsigned int cleared =
		trustix_datapath_clear_inner_gso_reassembly_matching(true, 0, 0);

	trustix_datapath_clear_inner_gso_probation_matching(true, 0, 0);
	trustix_datapath_rx_worker_inner_gso_session_clears++;
	trustix_datapath_rx_worker_inner_gso_session_slots_cleared += cleared;
}

static void trustix_datapath_free_inner_gso_reassembly(void)
{
	__u8 *data = trustix_datapath_inner_gso_reassembly_data;
	unsigned int i;

	trustix_datapath_clear_inner_gso_reassembly();
	trustix_datapath_clear_inner_gso_probation_matching(true, 0, 0);
	trustix_datapath_inner_gso_reassembly_data = NULL;
	for (i = 0; i < TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_SLOTS; i++)
		trustix_datapath_inner_gso_reassembly_slots[i].data = NULL;
	vfree(data);
}

static int trustix_datapath_alloc_rx_worker(void)
{
	unsigned int i;

	trustix_datapath_rx_worker_capacity =
		trustix_datapath_clamp_rx_worker_slots(
			trustix_datapath_rx_worker_slots);
	trustix_datapath_rx_worker_ring =
		vzalloc(array_size(trustix_datapath_rx_worker_capacity,
				   sizeof(*trustix_datapath_rx_worker_ring)));
	if (!trustix_datapath_rx_worker_ring)
		return -ENOMEM;
	trustix_datapath_rx_worker_coalesce_slots =
		kcalloc(TRUSTIX_DATAPATH_RX_WORKER_STREAM_MAX_FRAMES,
			sizeof(*trustix_datapath_rx_worker_coalesce_slots),
			GFP_KERNEL);
	trustix_datapath_rx_worker_coalesce_pending =
		kcalloc(TRUSTIX_DATAPATH_RX_WORKER_STREAM_MAX_FRAMES,
			sizeof(*trustix_datapath_rx_worker_coalesce_pending),
			GFP_KERNEL);
	if (trustix_datapath_rx_worker_coalesce_slots &&
	    trustix_datapath_rx_worker_coalesce_pending) {
		trustix_datapath_rx_worker_coalesce_scratch_capacity =
			TRUSTIX_DATAPATH_RX_WORKER_STREAM_MAX_FRAMES;
	} else {
		kfree(trustix_datapath_rx_worker_coalesce_slots);
		kfree(trustix_datapath_rx_worker_coalesce_pending);
		trustix_datapath_rx_worker_coalesce_slots = NULL;
		trustix_datapath_rx_worker_coalesce_pending = NULL;
		trustix_datapath_rx_worker_coalesce_scratch_capacity = 0;
	}
	trustix_datapath_rx_worker_head = 0;
	trustix_datapath_rx_worker_tail = 0;
	trustix_datapath_rx_worker_count = 0;
	trustix_datapath_rx_worker_queued = 0;
	trustix_datapath_rx_worker_injected = 0;
	trustix_datapath_rx_worker_dropped = 0;
	trustix_datapath_rx_worker_overwritten = 0;
	trustix_datapath_rx_worker_queue_full_fallbacks = 0;
	trustix_datapath_rx_worker_alloc_errors = 0;
	trustix_datapath_rx_worker_xmit_packets = 0;
	trustix_datapath_rx_worker_xmit_ok = 0;
	trustix_datapath_rx_worker_xmit_cn = 0;
	trustix_datapath_rx_worker_xmit_ret_errors = 0;
	trustix_datapath_rx_worker_xmit_drop = 0;
	trustix_datapath_rx_worker_xmit_other_ret_errors = 0;
	trustix_datapath_rx_worker_xmit_dev_forward_packets = 0;
	trustix_datapath_rx_worker_xmit_dev_forward_errors = 0;
	trustix_datapath_rx_worker_xmit_peer_forward_packets = 0;
	trustix_datapath_rx_worker_xmit_peer_forward_errors = 0;
	trustix_datapath_rx_worker_xmit_peer_forward_unsupported = 0;
	trustix_datapath_rx_worker_direct_xmit_safe_fallbacks = 0;
	trustix_datapath_rx_worker_inline_receive_safe_fallbacks = 0;
	trustix_datapath_rx_worker_receive_packets = 0;
	trustix_datapath_rx_worker_deliver_errors = 0;
	trustix_datapath_rx_worker_xmit_hash_tx_queue_sets = 0;
	trustix_datapath_rx_worker_xmit_hash_tx_queue_fallbacks = 0;
	trustix_datapath_rx_worker_xmit_hash_tx_queue_q0 = 0;
	trustix_datapath_rx_worker_xmit_hash_tx_queue_q1 = 0;
	trustix_datapath_rx_worker_xmit_hash_tx_queue_q2 = 0;
	trustix_datapath_rx_worker_xmit_hash_tx_queue_q3 = 0;
	trustix_datapath_rx_worker_xmit_hash_tx_queue_q4 = 0;
	trustix_datapath_rx_worker_xmit_hash_tx_queue_q5 = 0;
	trustix_datapath_rx_worker_xmit_hash_tx_queue_q6 = 0;
	trustix_datapath_rx_worker_xmit_hash_tx_queue_q7 = 0;
	trustix_datapath_rx_worker_xmit_hash_tx_queue_other = 0;
	trustix_datapath_rx_worker_xmit_more_sets = 0;
	trustix_datapath_rx_worker_last_push_ret = 0;
	trustix_datapath_rx_worker_last_deliver_ret = 0;
	trustix_datapath_rx_worker_last_xmit_ret = 0;
	trustix_datapath_rx_worker_last_xmit_error_ret = 0;
	trustix_datapath_rx_worker_queue_work_calls = 0;
	trustix_datapath_rx_worker_queue_work_enqueued = 0;
	trustix_datapath_rx_worker_runs = 0;
	trustix_datapath_rx_worker_run_processed = 0;
	trustix_datapath_rx_worker_stolen = 0;
	trustix_datapath_rx_worker_steal_fallbacks = 0;
	trustix_datapath_rx_worker_steal_errors = 0;
	trustix_datapath_rx_worker_inline_injected = 0;
	trustix_datapath_rx_worker_inline_errors = 0;
	trustix_datapath_rx_worker_inline_xmit_packets = 0;
	trustix_datapath_rx_worker_inline_xmit_errors = 0;
	trustix_datapath_rx_worker_inline_xmit_hook_queue_fallbacks = 0;
	trustix_datapath_rx_worker_inline_xmit_copy_csum_hits = 0;
	trustix_datapath_rx_worker_inline_xmit_copy_csum_fallbacks = 0;
	trustix_datapath_rx_worker_stream_packets = 0;
	trustix_datapath_rx_worker_stream_frames = 0;
	trustix_datapath_rx_worker_stream_errors = 0;
	trustix_datapath_rx_worker_stream_queue_errors = 0;
	trustix_datapath_rx_worker_stream_batch_packets = 0;
	trustix_datapath_rx_worker_stream_batch_frames = 0;
	trustix_datapath_rx_worker_stream_batch_errors = 0;
	trustix_datapath_rx_worker_stream_inline_batch_fallbacks = 0;
	trustix_datapath_reset_percpu_ullong(
		&trustix_datapath_rx_worker_stream_offset_copy_attempts);
	trustix_datapath_reset_percpu_ullong(
		&trustix_datapath_rx_worker_stream_offset_copy_hits);
	trustix_datapath_reset_percpu_ullong(
		&trustix_datapath_rx_worker_stream_offset_copy_bytes);
	trustix_datapath_reset_percpu_ullong(
		&trustix_datapath_rx_worker_stream_offset_copy_fallbacks);
	trustix_datapath_reset_percpu_ullong(
		&trustix_datapath_rx_worker_stream_offset_copy_errors);
	trustix_datapath_rx_worker_checksum_fixed = 0;
	trustix_datapath_rx_worker_checksum_trusted = 0;
	trustix_datapath_rx_worker_checksum_trust_fallbacks = 0;
	trustix_datapath_rx_worker_checksum_ipv4_only = 0;
	trustix_datapath_rx_worker_checksum_partial = 0;
	trustix_datapath_rx_worker_checksum_errors = 0;
	trustix_datapath_rx_worker_inner_tcp_checksum_partial = 0;
	trustix_datapath_rx_worker_inner_tcp_checksum_partial_errors = 0;
	trustix_datapath_rx_worker_inner_gso_candidates = 0;
	trustix_datapath_rx_worker_inner_gso_packets = 0;
	trustix_datapath_rx_worker_inner_gso_segments = 0;
	trustix_datapath_rx_worker_inner_gso_partial_frames = 0;
	trustix_datapath_rx_worker_inner_gso_malformed = 0;
	trustix_datapath_rx_worker_inner_gso_errors = 0;
	trustix_datapath_rx_worker_inner_gso_stream_packets = 0;
	trustix_datapath_rx_worker_inner_gso_stream_frames = 0;
	trustix_datapath_rx_worker_inner_gso_regular_frames = 0;
	trustix_datapath_rx_worker_inner_gso_continuation_drops = 0;
	trustix_datapath_rx_worker_inner_gso_session_clears = 0;
	trustix_datapath_rx_worker_inner_gso_session_slots_cleared = 0;
	trustix_datapath_rx_worker_inner_gso_reassembly_started = 0;
	trustix_datapath_rx_worker_inner_gso_reassembly_completed = 0;
	trustix_datapath_rx_worker_inner_gso_continuation_matched = 0;
	trustix_datapath_rx_worker_inner_gso_continuation_orphans = 0;
	trustix_datapath_rx_worker_inner_gso_sequence_gaps = 0;
	trustix_datapath_rx_worker_inner_gso_sequence_gap_ahead = 0;
	trustix_datapath_rx_worker_inner_gso_sequence_gap_behind = 0;
	trustix_datapath_rx_worker_inner_gso_last_sequence_gap = 0;
	trustix_datapath_rx_worker_inner_gso_timeouts = 0;
	trustix_datapath_rx_worker_inner_gso_timeouts_on_start = 0;
	trustix_datapath_rx_worker_inner_gso_timeouts_on_append = 0;
	trustix_datapath_rx_worker_inner_gso_timeouts_on_sweep = 0;
	trustix_datapath_rx_worker_inner_gso_timeout_missing_bytes = 0;
	trustix_datapath_rx_worker_inner_gso_timeout_max_missing_bytes = 0;
	trustix_datapath_rx_worker_inner_gso_duplicate_starts = 0;
	trustix_datapath_rx_worker_inner_gso_collisions = 0;
	trustix_datapath_rx_worker_inner_gso_reassembly_high_watermark = 0;
	trustix_datapath_rx_worker_inner_gso_oom = 0;
	trustix_datapath_rx_worker_inner_gso_tail_frames = 0;
	trustix_datapath_rx_worker_tix_tcp_claimed_drops = 0;
	trustix_datapath_rx_worker_partial_checksum_software_fallbacks = 0;
	trustix_datapath_rx_worker_partial_checksum_metadata_repairs = 0;
	trustix_datapath_rx_worker_dst_mac_hits = 0;
	trustix_datapath_rx_worker_dst_mac_veth_peer_hits = 0;
	trustix_datapath_rx_worker_dst_mac_cache_hits = 0;
	trustix_datapath_rx_worker_dst_mac_cache_misses = 0;
	trustix_datapath_rx_worker_dst_mac_broadcast = 0;
	trustix_datapath_rx_worker_queued_skb = 0;
	trustix_datapath_rx_worker_queued_skb_fallbacks = 0;
	trustix_datapath_rx_worker_mark_skips = 0;
	trustix_datapath_hook_ifindex_skips = 0;
	trustix_datapath_hook_master_ifindex_matches = 0;
	trustix_datapath_rx_worker_self_marked = 0;
	trustix_datapath_rx_worker_tc_skip_requests = 0;
	trustix_datapath_rx_worker_xmit_scrubbed = 0;
	trustix_datapath_rx_worker_bridge_targets = 0;
	trustix_datapath_rx_worker_last_target_ifindex = 0;
	trustix_datapath_rx_worker_last_target_type = 0;
	trustix_datapath_rx_worker_last_target_priv_flags = 0;
	trustix_datapath_rx_worker_stream_coalesce_packets = 0;
	trustix_datapath_rx_worker_stream_coalesce_frames = 0;
	trustix_datapath_rx_worker_stream_coalesce_errors = 0;
	trustix_datapath_reset_percpu_ullong(
		&trustix_datapath_rx_worker_stream_coalesce_nonlinear_attempts);
	trustix_datapath_reset_percpu_ullong(
		&trustix_datapath_rx_worker_stream_coalesce_nonlinear_hits);
	trustix_datapath_reset_percpu_ullong(
		&trustix_datapath_rx_worker_stream_coalesce_nonlinear_frags);
	trustix_datapath_reset_percpu_ullong(
		&trustix_datapath_rx_worker_stream_coalesce_nonlinear_bytes);
	trustix_datapath_reset_percpu_ullong(
		&trustix_datapath_rx_worker_stream_coalesce_nonlinear_fallbacks);
	trustix_datapath_reset_percpu_ullong(
		&trustix_datapath_rx_worker_stream_coalesce_nonlinear_errors);
	trustix_datapath_reset_percpu_ullong(
		&trustix_datapath_rx_worker_stream_coalesce_page_frag_cache_attempts);
	trustix_datapath_reset_percpu_ullong(
		&trustix_datapath_rx_worker_stream_coalesce_page_frag_cache_hits);
	trustix_datapath_reset_percpu_ullong(
		&trustix_datapath_rx_worker_stream_coalesce_page_frag_cache_fallbacks);
	trustix_datapath_reset_percpu_ullong(
		&trustix_datapath_rx_worker_stream_coalesce_page_frag_cache_errors);
	trustix_datapath_rx_worker_stream_coalesce_segment_batches = 0;
	trustix_datapath_rx_worker_stream_coalesce_segment_skbs = 0;
	trustix_datapath_rx_worker_stream_coalesce_segment_errors = 0;
	trustix_datapath_rx_worker_gso_xmit_packets = 0;
	trustix_datapath_rx_worker_gso_xmit_segments = 0;
	trustix_datapath_rx_worker_gso_xmit_fallbacks = 0;
	trustix_datapath_rx_worker_gso_xmit_errors = 0;
	trustix_datapath_rx_worker_direct_gso_attempts = 0;
	trustix_datapath_rx_worker_direct_gso_hits = 0;
	trustix_datapath_rx_worker_direct_gso_parse_misses = 0;
	trustix_datapath_rx_worker_direct_gso_cap_misses = 0;
	trustix_datapath_rx_worker_direct_gso_mtu_misses = 0;
	trustix_datapath_rx_worker_direct_gso_xmit_errors = 0;
	trustix_datapath_rx_worker_stream_coalesce_partial_csum_fallbacks = 0;
	trustix_datapath_rx_worker_stream_coalesce_checksum_fallbacks = 0;
	trustix_datapath_rx_worker_stream_coalesce_inline_queue_fallbacks = 0;
	trustix_datapath_rx_worker_stream_direct_gso_packets = 0;
	trustix_datapath_rx_worker_stream_direct_gso_frames = 0;
	trustix_datapath_rx_worker_stream_direct_gso_fallbacks = 0;
	trustix_datapath_rx_worker_stream_direct_gso_errors = 0;
	trustix_datapath_rx_worker_stream_coalesce_last_len = 0;
	trustix_datapath_rx_worker_stream_coalesce_last_gso_size = 0;
	trustix_datapath_rx_worker_stream_coalesce_last_gso_segs = 0;
	trustix_datapath_rx_worker_stream_coalesce_last_gso_type = 0;
	trustix_datapath_rx_worker_stream_coalesce_max_len = 0;
	trustix_datapath_rx_worker_stream_coalesce_last_segment_ret = 0;
	trustix_datapath_rx_worker_inline_pair_stored = 0;
	trustix_datapath_rx_worker_inline_pair_packets = 0;
	trustix_datapath_rx_worker_inline_pair_flushes = 0;
	trustix_datapath_rx_worker_inline_pair_misses = 0;
	trustix_datapath_rx_worker_inline_pair_errors = 0;
	trustix_datapath_rx_worker_single_coalesce_stored = 0;
	trustix_datapath_rx_worker_single_coalesce_packets = 0;
	trustix_datapath_rx_worker_single_coalesce_frames = 0;
	trustix_datapath_rx_worker_single_coalesce_flushes = 0;
	trustix_datapath_rx_worker_single_coalesce_misses = 0;
	trustix_datapath_rx_worker_single_coalesce_errors = 0;
	for (i = 0; i < TRUSTIX_DATAPATH_RX_WORKER_INLINE_PAIR_SLOTS; i++) {
		spin_lock_init(&trustix_datapath_rx_worker_inline_pair_slots[i].lock);
		INIT_DELAYED_WORK(
			&trustix_datapath_rx_worker_inline_pair_slots[i].flush_work,
			trustix_datapath_rx_worker_inline_pair_flush_work);
		trustix_datapath_rx_worker_inline_pair_slots[i].valid = false;
		trustix_datapath_rx_worker_inline_pair_slots[i].flush_reuse_blocked =
			false;
		trustix_datapath_rx_worker_inline_pair_slots[i].target_dev = NULL;
		trustix_datapath_rx_worker_inline_pair_slots[i].frames = 0;
	}
	for (i = 0; i < TRUSTIX_DATAPATH_RX_WORKER_SINGLE_COALESCE_SLOTS; i++) {
		spin_lock_init(
			&trustix_datapath_rx_worker_single_coalesce_slots[i].lock);
		INIT_DELAYED_WORK(
			&trustix_datapath_rx_worker_single_coalesce_slots[i].flush_work,
			trustix_datapath_rx_worker_single_coalesce_flush_work);
		trustix_datapath_rx_worker_single_coalesce_slots[i].valid =
			false;
		trustix_datapath_rx_worker_single_coalesce_slots[i].target_dev =
			NULL;
		trustix_datapath_rx_worker_single_coalesce_slots[i].frames = 0;
	}
	if (trustix_datapath_alloc_inner_gso_reassembly())
		trustix_datapath_rx_worker_inner_gso_oom++;
	return 0;
}

static void trustix_datapath_rx_worker_release_slot(
	struct trustix_datapath_rx_worker_slot *slot)
{
	if (!slot)
		return;
	if (slot->target_dev)
		dev_put(slot->target_dev);
	if (slot->skb)
		kfree_skb(slot->skb);
	kfree(slot->packet);
	memset(slot, 0, sizeof(*slot));
}

static __sum16 trustix_datapath_rx_worker_l4_checksum(struct iphdr *iph,
						      void *l4, __u32 len,
						      __u8 protocol);
static int trustix_datapath_tx_plaintext_copy_payload(
	struct sk_buff *src, __u32 src_offset, __u8 *dst, __u32 len,
	bool copy_csum, __wsum *sum_out);
static __sum16 trustix_datapath_tx_plaintext_tcp_checksum(
	struct iphdr *iph, struct tcphdr *tcph, __u32 tcp_header_len,
	__u32 payload_len, bool payload_sum_ready, __wsum payload_sum);

static struct sk_buff *
trustix_datapath_rx_worker_build_inner_skb(struct net_device *target_dev,
					   const __u8 *packet, __u32 len)
{
	struct sk_buff *inner_skb;
	__u8 *dst;

	if (!target_dev || !packet || !len)
		return NULL;
	if (target_dev->type != ARPHRD_ETHER)
		return NULL;
	inner_skb = netdev_alloc_skb_ip_align(target_dev, ETH_HLEN + len);
	if (!inner_skb)
		return NULL;
	skb_reserve(inner_skb, ETH_HLEN);
	dst = skb_put(inner_skb, len);
	memcpy(dst, packet, len);
	return inner_skb;
}

static bool
trustix_datapath_rx_worker_tcp_flags_supported(const struct tcphdr *tcph)
{
	if (!tcph)
		return false;
	if (tcph->syn || tcph->fin || tcph->rst)
		return false;
	if (!tcph->ack || tcph->urg || tcph->ece || tcph->cwr)
		return false;
	return true;
}

static __u8 trustix_datapath_rx_worker_tcp_flags_byte(
	const struct tcphdr *tcph)
{
	return ((__u8)tcph->fin) | ((__u8)tcph->syn << 1) |
	       ((__u8)tcph->rst << 2) | ((__u8)tcph->psh << 3) |
	       ((__u8)tcph->ack << 4) | ((__u8)tcph->urg << 5) |
	       ((__u8)tcph->ece << 6) | ((__u8)tcph->cwr << 7);
}

static __u8 trustix_datapath_rx_worker_tcp_flags_class(__u8 flags)
{
	return flags & ~((__u8)0x08);
}

static bool
trustix_datapath_rx_worker_coalesce_match(
	const struct trustix_datapath_rx_worker_coalesce_state *state,
	const struct iphdr *iph, const struct tcphdr *tcph,
	__u32 tcp_header_len, __u32 payload_len)
{
	if (!state || !state->active || !iph || !tcph || !payload_len)
		return false;
	if (state->saddr != iph->saddr || state->daddr != iph->daddr ||
	    state->source != tcph->source || state->dest != tcph->dest ||
	    state->tcp_header_len != tcp_header_len ||
	    state->urg_ptr != tcph->urg_ptr ||
	    trustix_datapath_rx_worker_tcp_flags_class(state->tcp_flags) !=
		    trustix_datapath_rx_worker_tcp_flags_class(
			    trustix_datapath_rx_worker_tcp_flags_byte(tcph)))
		return false;
	return state->next_seq == ntohl(tcph->seq);
}

static int
trustix_datapath_rx_worker_coalesce_accept(
	struct trustix_datapath_rx_worker_coalesce_state *state,
	const __u8 *inner_packet, __u32 inner_len)
{
	const struct tcphdr *tcph;
	const struct iphdr *iph;
	__u32 ip_header_len;
	__u32 tcp_header_len;
	__u32 payload_len;
	__u32 total_len;

	if (!state || !inner_packet || inner_len < sizeof(*iph) + sizeof(*tcph))
		return -EINVAL;
	iph = (const struct iphdr *)inner_packet;
	if (iph->version != 4 || iph->ihl < 5 ||
	    iph->protocol != IPPROTO_TCP ||
	    (iph->frag_off & htons(0x3fff)))
		return -EPROTONOSUPPORT;
	ip_header_len = iph->ihl * 4;
	if (ip_header_len != sizeof(*iph) ||
	    inner_len < ip_header_len + sizeof(*tcph))
		return -EPROTONOSUPPORT;
	total_len = ntohs(iph->tot_len);
	if (total_len != inner_len)
		return -EMSGSIZE;
	tcph = (const struct tcphdr *)(inner_packet + ip_header_len);
	tcp_header_len = tcph->doff * 4;
	if (tcp_header_len < sizeof(*tcph) || tcp_header_len > 60 ||
	    inner_len < ip_header_len + tcp_header_len)
		return -EPROTONOSUPPORT;
	if (!trustix_datapath_rx_worker_tcp_flags_supported(tcph))
		return -EPROTONOSUPPORT;
	payload_len = inner_len - ip_header_len - tcp_header_len;
	if (!payload_len)
		return -EPROTONOSUPPORT;
	if (!state->active) {
		memcpy(state->header, inner_packet, ip_header_len + tcp_header_len);
		state->active = true;
		state->total_len = inner_len;
		state->payload_len = payload_len;
		state->gso_size = payload_len;
		state->last_payload_len = payload_len;
		state->tcp_header_len = tcp_header_len;
		state->next_seq = ntohl(tcph->seq) + payload_len;
		state->ack_seq = ntohl(tcph->ack_seq);
		state->saddr = iph->saddr;
		state->daddr = iph->daddr;
		state->source = tcph->source;
		state->dest = tcph->dest;
		state->window = tcph->window;
		state->urg_ptr = tcph->urg_ptr;
		state->tcp_flags =
			trustix_datapath_rx_worker_tcp_flags_byte(tcph);
		return 0;
	}
	if (!trustix_datapath_rx_worker_coalesce_match(
		    state, iph, tcph, tcp_header_len, payload_len))
		return -EOPNOTSUPP;
	if (state->last_payload_len != state->gso_size ||
	    payload_len > state->gso_size)
		return -EOPNOTSUPP;
	if (check_add_overflow(state->payload_len, payload_len,
			       &state->payload_len))
		return -EOVERFLOW;
	if (check_add_overflow((__u32)sizeof(*iph) + state->tcp_header_len,
			       state->payload_len, &state->total_len))
		return -EOVERFLOW;
	if (state->total_len > 0xffff)
		return -EMSGSIZE;
	state->next_seq += payload_len;
	state->last_payload_len = payload_len;
	return 0;
}

static int trustix_datapath_rx_worker_pending_copy_bits(
	const struct trustix_datapath_rx_worker_pending_copy *pending,
	__u32 offset, void *dst, __u32 len)
{
	const __u8 *source;

	if (!pending || !dst || !len || offset > pending->len ||
	    len > pending->len - offset)
		return -EINVAL;
	source = pending->packet ?: pending->source_packet;
	if (source) {
		memcpy(dst, source + offset, len);
		return 0;
	}
	if (!pending->source_skb ||
	    pending->source_offset > pending->source_skb->len ||
	    pending->len > pending->source_skb->len - pending->source_offset)
		return -EINVAL;
	return skb_copy_bits(pending->source_skb,
			     pending->source_offset + offset, dst, len) ?
		       -ENODATA : 0;
}

static int trustix_datapath_rx_worker_coalesce_accept_pending(
	struct trustix_datapath_rx_worker_coalesce_state *state,
	const struct trustix_datapath_rx_worker_pending_copy *pending)
{
	__u8 header[TRUSTIX_DATAPATH_IPV4_L4_PREFIX_MAX];
	__u32 copy_len;
	int ret;

	if (!state || !pending || !pending->len)
		return -EINVAL;
	copy_len = min_t(__u32, pending->len, sizeof(header));
	ret = trustix_datapath_rx_worker_pending_copy_bits(
		pending, 0, header, copy_len);
	if (ret)
		return ret;
	return trustix_datapath_rx_worker_coalesce_accept(
		state, header, pending->len);
}

static int trustix_datapath_rx_worker_coalesced_frame_payload_len(
	const struct trustix_datapath_rx_worker_pending_copy *pending,
	__u32 header_len, __u32 *payload_len)
{
	struct iphdr frame_iph;
	__u32 frame_len;
	int ret;

	if (payload_len)
		*payload_len = 0;
	if (!pending || !payload_len || !header_len ||
	    pending->len < header_len)
		return -EINVAL;
	ret = trustix_datapath_rx_worker_pending_copy_bits(
		pending, 0, &frame_iph, sizeof(frame_iph));
	if (ret)
		return ret;
	frame_len = ntohs(frame_iph.tot_len);
	if (frame_len < header_len || frame_len > pending->len)
		return -EINVAL;
	*payload_len = frame_len - header_len;
	return 0;
}

static bool trustix_datapath_rx_worker_nonlinear_gso_supported(
	const struct net_device *target_dev)
{
	netdev_features_t features;

	if (!target_dev)
		return false;
	features = READ_ONCE(target_dev->features);
	return (features & NETIF_F_SG) && (features & NETIF_F_TSO) &&
	       (features & NETIF_F_HW_CSUM);
}

static void *trustix_datapath_rx_worker_alloc_page_frag(
	struct page **page_out, unsigned int *offset_out)
{
	struct page_frag_cache *cache;
	struct page *page;
	unsigned int offset;
	void *addr;

	if (page_out)
		*page_out = NULL;
	if (offset_out)
		*offset_out = 0;
	if (!page_out || !offset_out)
		return NULL;
	local_bh_disable();
	this_cpu_inc(
		trustix_datapath_rx_worker_stream_coalesce_page_frag_cache_attempts);
	cache = this_cpu_ptr(
		&trustix_datapath_rx_worker_stream_coalesce_page_frag_caches);
	addr = page_frag_alloc(cache, PAGE_SIZE, GFP_ATOMIC);
	if (unlikely(!addr)) {
		this_cpu_inc(
			trustix_datapath_rx_worker_stream_coalesce_page_frag_cache_errors);
		this_cpu_inc(
			trustix_datapath_rx_worker_stream_coalesce_page_frag_cache_fallbacks);
		local_bh_enable();
		return NULL;
	}
	page = virt_to_page(addr);
	offset = offset_in_page(addr);
	if (unlikely(!page || offset + PAGE_SIZE > PAGE_SIZE)) {
		page_frag_free(addr);
		this_cpu_inc(
			trustix_datapath_rx_worker_stream_coalesce_page_frag_cache_errors);
		this_cpu_inc(
			trustix_datapath_rx_worker_stream_coalesce_page_frag_cache_fallbacks);
		local_bh_enable();
		return NULL;
	}
	*page_out = page;
	*offset_out = offset;
	this_cpu_inc(
		trustix_datapath_rx_worker_stream_coalesce_page_frag_cache_hits);
	local_bh_enable();
	return addr;
}

static void trustix_datapath_rx_worker_drain_page_frag_caches(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		struct page_frag_cache *cache = per_cpu_ptr(
			&trustix_datapath_rx_worker_stream_coalesce_page_frag_caches,
			cpu);

		if (!cache->va)
			continue;
		__page_frag_cache_drain(virt_to_head_page(cache->va),
					cache->pagecnt_bias);
		memset(cache, 0, sizeof(*cache));
	}
}

static int trustix_datapath_rx_worker_build_coalesced_gso_nonlinear(
	struct net_device *target_dev,
	const struct trustix_datapath_rx_worker_coalesce_state *state,
	struct trustix_datapath_rx_worker_pending_copy *pending,
	unsigned int frames, __u32 header_len, __u32 gso_segs,
	struct sk_buff **skb_out)
{
	struct skb_shared_info *shinfo;
	struct page *page = NULL;
	struct tcphdr *tcph;
	struct iphdr *iph;
	struct sk_buff *skb = NULL;
	bool page_from_frag_cache = false;
	bool page_mapped = false;
	void *page_addr = NULL;
	unsigned int page_offset = 0;
	unsigned int expected_frags;
	unsigned int i;
	__u8 *dst;
	__u32 copied_payload = 0;
	__u32 page_used = 0;
	int ret = 0;

	if (skb_out)
		*skb_out = NULL;
	if (!target_dev || !state || !pending || !frames || !header_len ||
	    !gso_segs || !skb_out)
		return -EINVAL;
	if (!trustix_datapath_rx_worker_nonlinear_gso_supported(target_dev))
		return -EOPNOTSUPP;
	expected_frags = DIV_ROUND_UP(state->payload_len, (__u32)PAGE_SIZE);
	if (!expected_frags || expected_frags > MAX_SKB_FRAGS)
		return -EMSGSIZE;
	for (i = 0; i < frames; i++) {
		__u32 frame_payload_len;

		ret = trustix_datapath_rx_worker_coalesced_frame_payload_len(
			&pending[i], header_len, &frame_payload_len);
		if (ret)
			return ret;
		if (check_add_overflow(copied_payload, frame_payload_len,
				       &copied_payload) ||
		    copied_payload > state->payload_len)
			return -EMSGSIZE;
	}
	if (copied_payload != state->payload_len)
		return -EINVAL;

	skb = netdev_alloc_skb_ip_align(target_dev, ETH_HLEN + header_len);
	if (!skb)
		return -ENOMEM;
	skb_reserve(skb, ETH_HLEN);
	dst = skb_put(skb, header_len);
	memcpy(dst, state->header, header_len);
	copied_payload = 0;
	for (i = 0; i < frames; i++) {
		__u32 frame_payload_offset = 0;
		__u32 frame_payload_len;

		ret = trustix_datapath_rx_worker_coalesced_frame_payload_len(
			&pending[i], header_len, &frame_payload_len);
		if (ret)
			goto error;
		while (frame_payload_len) {
			__u32 copy_len;

			if (!page) {
				if (READ_ONCE(
				    trustix_datapath_rx_worker_stream_coalesce_page_frag_cache)) {
					page_addr =
						trustix_datapath_rx_worker_alloc_page_frag(
							&page, &page_offset);
					page_from_frag_cache = page_addr != NULL;
				}
				if (!page) {
					page = alloc_page(GFP_ATOMIC);
					page_offset = 0;
				}
				if (!page) {
					ret = -ENOMEM;
					goto error;
				}
				if (!page_addr) {
					page_addr = kmap_local_page(page);
					page_mapped = true;
				}
				page_used = 0;
			}
			copy_len = min_t(__u32, frame_payload_len,
					 PAGE_SIZE - page_used);
			ret = trustix_datapath_rx_worker_pending_copy_bits(
				&pending[i], header_len + frame_payload_offset,
				(__u8 *)page_addr + page_used, copy_len);
			if (ret)
				goto error;
			page_used += copy_len;
			frame_payload_offset += copy_len;
			frame_payload_len -= copy_len;
			copied_payload += copy_len;
			if (page_used == PAGE_SIZE) {
				if (page_mapped)
					kunmap_local(page_addr);
				page_addr = NULL;
				skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags,
						page, page_offset, page_used,
						PAGE_SIZE);
				page = NULL;
				page_from_frag_cache = false;
				page_mapped = false;
				page_offset = 0;
				page_used = 0;
			}
		}
	}
	if (page) {
		if (page_mapped)
			kunmap_local(page_addr);
		page_addr = NULL;
		skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags, page,
				page_offset, page_used, PAGE_SIZE);
		page = NULL;
		page_from_frag_cache = false;
		page_mapped = false;
		page_offset = 0;
	}
	if (copied_payload != state->payload_len) {
		ret = -EINVAL;
		goto error;
	}
	iph = (struct iphdr *)skb->data;
	tcph = (struct tcphdr *)(skb->data + sizeof(*iph));
	iph->tot_len = htons((__u16)state->total_len);
	trustix_datapath_rx_worker_fix_ipv4_header_checksum(iph,
							   sizeof(*iph));
	tcph->check = ~csum_tcpudp_magic(iph->saddr, iph->daddr,
					 state->total_len - sizeof(*iph),
					 IPPROTO_TCP, 0);
	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum_start = (unsigned char *)tcph - skb->head;
	skb->csum_offset = offsetof(struct tcphdr, check);
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, sizeof(*iph));
	shinfo = skb_shinfo(skb);
	shinfo->gso_size = state->gso_size;
	shinfo->gso_segs = gso_segs;
	shinfo->gso_type = SKB_GSO_TCPV4;
	skb->mac_len = ETH_HLEN;
	skb_reset_inner_headers(skb);
	WRITE_ONCE(trustix_datapath_rx_worker_stream_coalesce_last_len,
		   skb->len);
	WRITE_ONCE(trustix_datapath_rx_worker_stream_coalesce_last_gso_size,
		   shinfo->gso_size);
	WRITE_ONCE(trustix_datapath_rx_worker_stream_coalesce_last_gso_segs,
		   shinfo->gso_segs);
	WRITE_ONCE(trustix_datapath_rx_worker_stream_coalesce_last_gso_type,
		   shinfo->gso_type);
	if (skb->len >
	    READ_ONCE(trustix_datapath_rx_worker_stream_coalesce_max_len))
		WRITE_ONCE(trustix_datapath_rx_worker_stream_coalesce_max_len,
			   skb->len);
	*skb_out = skb;
	return 0;

error:
	if (page_addr && page_mapped)
		kunmap_local(page_addr);
	if (page) {
		if (page_from_frag_cache)
			page_frag_free(page_addr);
		else
			__free_page(page);
	}
	kfree_skb(skb);
	return ret ? ret : -EIO;
}

static struct sk_buff *
trustix_datapath_rx_worker_build_coalesced_gso_skb(
	struct net_device *target_dev,
	const struct trustix_datapath_rx_worker_coalesce_state *state,
	struct trustix_datapath_rx_worker_pending_copy *pending,
	unsigned int frames, bool allow_nonlinear)
{
	struct skb_shared_info *shinfo;
	struct tcphdr *tcph;
	struct iphdr *iph;
	struct sk_buff *skb;
	unsigned int i;
	__u8 *dst;
	__u32 header_len;
	__u32 copied_payload = 0;
	__u32 payload_offset;
	__u32 gso_segs;
	int ret;

	if (!target_dev || !state || !state->active || !pending ||
	    frames < 2 || !state->gso_size || !state->payload_len ||
	    state->total_len > 0xffff)
		return NULL;
	gso_segs = DIV_ROUND_UP(state->payload_len, state->gso_size);
	if (!gso_segs || gso_segs > U16_MAX)
		return NULL;
	header_len = sizeof(struct iphdr) + state->tcp_header_len;
	skb = NULL;
	if (allow_nonlinear &&
	    READ_ONCE(trustix_datapath_rx_worker_stream_coalesce_nonlinear)) {
		this_cpu_inc(
			trustix_datapath_rx_worker_stream_coalesce_nonlinear_attempts);
		ret = trustix_datapath_rx_worker_build_coalesced_gso_nonlinear(
			target_dev, state, pending, frames, header_len, gso_segs,
			&skb);
		if (!ret) {
			this_cpu_inc(
				trustix_datapath_rx_worker_stream_coalesce_nonlinear_hits);
			this_cpu_add(
				trustix_datapath_rx_worker_stream_coalesce_nonlinear_frags,
				skb_shinfo(skb)->nr_frags);
			this_cpu_add(
				trustix_datapath_rx_worker_stream_coalesce_nonlinear_bytes,
				state->payload_len);
			return skb;
		}
		this_cpu_inc(
			trustix_datapath_rx_worker_stream_coalesce_nonlinear_fallbacks);
		if (ret != -EOPNOTSUPP)
			this_cpu_inc(
				trustix_datapath_rx_worker_stream_coalesce_nonlinear_errors);
	}
	if (!skb) {
		skb = netdev_alloc_skb_ip_align(target_dev,
						ETH_HLEN + state->total_len);
		if (!skb)
			return NULL;
		skb_reserve(skb, ETH_HLEN);
	}
	dst = skb_put(skb, state->total_len);
	memcpy(dst, state->header, header_len);
	payload_offset = header_len;
	for (i = 0; i < frames; i++) {
		__u32 frame_payload_len;

		ret = trustix_datapath_rx_worker_coalesced_frame_payload_len(
			&pending[i], header_len, &frame_payload_len);
		if (ret || payload_offset + copied_payload + frame_payload_len >
				   state->total_len) {
			kfree_skb(skb);
			return NULL;
		}
		ret = trustix_datapath_rx_worker_pending_copy_bits(
			&pending[i], header_len, dst + payload_offset + copied_payload,
			frame_payload_len);
		if (ret) {
			kfree_skb(skb);
			return NULL;
		}
		copied_payload += frame_payload_len;
	}
	if (copied_payload != state->payload_len) {
		kfree_skb(skb);
		return NULL;
	}
	iph = (struct iphdr *)skb->data;
	tcph = (struct tcphdr *)(skb->data + sizeof(*iph));
	iph->tot_len = htons((__u16)state->total_len);
	trustix_datapath_rx_worker_fix_ipv4_header_checksum(iph,
							   sizeof(*iph));
	tcph->check = ~csum_tcpudp_magic(iph->saddr, iph->daddr,
					 state->total_len - sizeof(*iph),
					 IPPROTO_TCP, 0);
	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum_start = (unsigned char *)tcph - skb->head;
	skb->csum_offset = offsetof(struct tcphdr, check);
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, sizeof(*iph));
	shinfo = skb_shinfo(skb);
	shinfo->gso_size = state->gso_size;
	shinfo->gso_segs = gso_segs;
	shinfo->gso_type = SKB_GSO_TCPV4;
	skb->mac_len = ETH_HLEN;
	skb_reset_inner_headers(skb);
	WRITE_ONCE(trustix_datapath_rx_worker_stream_coalesce_last_len,
		   skb->len);
	WRITE_ONCE(trustix_datapath_rx_worker_stream_coalesce_last_gso_size,
		   shinfo->gso_size);
	WRITE_ONCE(trustix_datapath_rx_worker_stream_coalesce_last_gso_segs,
		   shinfo->gso_segs);
	WRITE_ONCE(trustix_datapath_rx_worker_stream_coalesce_last_gso_type,
		   shinfo->gso_type);
	if (skb->len >
	    READ_ONCE(trustix_datapath_rx_worker_stream_coalesce_max_len))
		WRITE_ONCE(trustix_datapath_rx_worker_stream_coalesce_max_len,
			   skb->len);
	return skb;
}

static void trustix_datapath_rx_worker_clear(void)
{
	struct trustix_datapath_rx_worker_slot slot = {};
	unsigned long irqflags;

	for (;;) {
		memset(&slot, 0, sizeof(slot));
		spin_lock_irqsave(&trustix_datapath_rx_worker_lock, irqflags);
		if (!trustix_datapath_rx_worker_ring ||
		    !trustix_datapath_rx_worker_capacity ||
		    !trustix_datapath_rx_worker_count) {
			trustix_datapath_rx_worker_head = 0;
			trustix_datapath_rx_worker_tail = 0;
			trustix_datapath_rx_worker_count = 0;
			spin_unlock_irqrestore(&trustix_datapath_rx_worker_lock,
					       irqflags);
			break;
		}
		slot = trustix_datapath_rx_worker_ring
			       [trustix_datapath_rx_worker_head];
		memset(&trustix_datapath_rx_worker_ring
			       [trustix_datapath_rx_worker_head],
		       0, sizeof(trustix_datapath_rx_worker_ring
					[trustix_datapath_rx_worker_head]));
		trustix_datapath_rx_worker_head =
			(trustix_datapath_rx_worker_head + 1) %
			trustix_datapath_rx_worker_capacity;
		trustix_datapath_rx_worker_count--;
		if (!trustix_datapath_rx_worker_count)
			trustix_datapath_rx_worker_tail =
				trustix_datapath_rx_worker_head;
		spin_unlock_irqrestore(&trustix_datapath_rx_worker_lock,
				       irqflags);
		trustix_datapath_rx_worker_release_slot(&slot);
		cond_resched();
	}
}

static void trustix_datapath_rx_worker_drop_pending_sync(void)
{
	trustix_datapath_clear_inner_gso_reassembly();
	trustix_datapath_rx_worker_single_coalesce_drop_all();
	trustix_datapath_rx_worker_inline_pair_drop_all();
	trustix_datapath_rx_worker_clear();
	if (trustix_datapath_rx_worker_wq)
		flush_workqueue(trustix_datapath_rx_worker_wq);
	trustix_datapath_rx_worker_single_coalesce_drop_all();
	trustix_datapath_rx_worker_inline_pair_drop_all();
	trustix_datapath_rx_worker_clear();
}

static void trustix_datapath_free_rx_worker(void)
{
	struct trustix_datapath_rx_worker_slot *ring;
	unsigned long irqflags;

	trustix_datapath_rx_worker_drop_pending_sync();
	if (trustix_datapath_rx_worker_wq) {
		flush_workqueue(trustix_datapath_rx_worker_wq);
		destroy_workqueue(trustix_datapath_rx_worker_wq);
		trustix_datapath_rx_worker_wq = NULL;
	}
	spin_lock_irqsave(&trustix_datapath_rx_worker_lock, irqflags);
	ring = trustix_datapath_rx_worker_ring;
	trustix_datapath_rx_worker_ring = NULL;
	trustix_datapath_rx_worker_capacity = 0;
	trustix_datapath_rx_worker_head = 0;
	trustix_datapath_rx_worker_tail = 0;
	trustix_datapath_rx_worker_count = 0;
	spin_unlock_irqrestore(&trustix_datapath_rx_worker_lock, irqflags);
	vfree(ring);
	kfree(trustix_datapath_rx_worker_coalesce_pending);
	kfree(trustix_datapath_rx_worker_coalesce_slots);
	trustix_datapath_rx_worker_coalesce_pending = NULL;
	trustix_datapath_rx_worker_coalesce_slots = NULL;
	trustix_datapath_rx_worker_coalesce_scratch_capacity = 0;
	trustix_datapath_free_inner_gso_reassembly();
}

static int trustix_datapath_alloc_rx_stage(void)
{
	trustix_datapath_rx_stage_capacity =
		trustix_datapath_clamp_rx_stage_slots(
			trustix_datapath_rx_stage_slots);
	trustix_datapath_rx_stage_ring =
		vzalloc(array_size(trustix_datapath_rx_stage_capacity,
				   sizeof(*trustix_datapath_rx_stage_ring)));
	if (!trustix_datapath_rx_stage_ring)
		return -ENOMEM;
	trustix_datapath_rx_stage_data =
		vzalloc(array3_size(trustix_datapath_rx_stage_capacity,
				    TRUSTIX_DATAPATH_PACKET_MAX_LEN,
				    sizeof(__u8)));
	if (!trustix_datapath_rx_stage_data) {
		vfree(trustix_datapath_rx_stage_ring);
		trustix_datapath_rx_stage_ring = NULL;
		trustix_datapath_rx_stage_capacity = 0;
		return -ENOMEM;
	}
	trustix_datapath_rx_stage_head = 0;
	trustix_datapath_rx_stage_tail = 0;
	trustix_datapath_rx_stage_count = 0;
	trustix_datapath_rx_stage_next_id = 0;
	trustix_datapath_rx_stage_staged = 0;
	trustix_datapath_rx_stage_popped = 0;
	trustix_datapath_rx_stage_dropped = 0;
	trustix_datapath_rx_stage_overwritten = 0;
	return 0;
}

static void trustix_datapath_free_rx_stage(void)
{
	unsigned long irqflags;
	struct trustix_datapath_rx_stage_slot *ring;
	__u8 *data;

	spin_lock_irqsave(&trustix_datapath_rx_stage_lock, irqflags);
	data = trustix_datapath_rx_stage_data;
	ring = trustix_datapath_rx_stage_ring;
	trustix_datapath_rx_stage_data = NULL;
	trustix_datapath_rx_stage_ring = NULL;
	trustix_datapath_rx_stage_capacity = 0;
	trustix_datapath_rx_stage_head = 0;
	trustix_datapath_rx_stage_tail = 0;
	trustix_datapath_rx_stage_count = 0;
	spin_unlock_irqrestore(&trustix_datapath_rx_stage_lock, irqflags);
	vfree(data);
	vfree(ring);
}

static void trustix_datapath_rx_stage_clear(void)
{
	unsigned long irqflags;

	spin_lock_irqsave(&trustix_datapath_rx_stage_lock, irqflags);
	if (trustix_datapath_rx_stage_ring &&
	    trustix_datapath_rx_stage_capacity) {
		memset(trustix_datapath_rx_stage_ring, 0,
		       array_size(trustix_datapath_rx_stage_capacity,
				  sizeof(*trustix_datapath_rx_stage_ring)));
	}
	trustix_datapath_rx_stage_head = 0;
	trustix_datapath_rx_stage_tail = 0;
	trustix_datapath_rx_stage_count = 0;
	spin_unlock_irqrestore(&trustix_datapath_rx_stage_lock, irqflags);
}

static struct net *trustix_datapath_current_net(void)
{
	if (current->nsproxy && current->nsproxy->net_ns)
		return current->nsproxy->net_ns;
	return &init_net;
}

static int trustix_datapath_alloc_state(void)
{
	int ret;

	ret = trustix_datapath_alloc_rx_stage();
	if (ret)
		return ret;
	ret = trustix_datapath_alloc_rx_worker();
	if (ret)
		goto free_rx_stage;
	trustix_datapath_rx_worker_wq =
		alloc_workqueue("trustix_dp_rx", WQ_UNBOUND | WQ_MEM_RECLAIM,
				1);
	if (!trustix_datapath_rx_worker_wq) {
		ret = -ENOMEM;
		goto free_rx_worker;
	}
	ret = trustix_datapath_alloc_tx_plaintext();
	if (ret)
		goto free_rx_worker;
	ret = trustix_datapath_alloc_table(&trustix_datapath_routes,
					   trustix_datapath_max_routes);
	if (ret)
		goto free_tx_plaintext;
	ret = trustix_datapath_alloc_table(&trustix_datapath_sessions,
					   trustix_datapath_max_sessions);
	if (ret)
		goto free_routes;
	ret = trustix_datapath_alloc_table(&trustix_datapath_flows,
					   trustix_datapath_max_flows);
	if (ret)
		goto free_sessions;
	ret = trustix_datapath_alloc_table(&trustix_datapath_session_wires,
					   trustix_datapath_max_sessions);
	if (ret)
		goto free_flows;
	ret = trustix_datapath_alloc_table(&trustix_datapath_session_crypto,
					   trustix_datapath_max_sessions);
	if (ret)
		goto free_session_wires;
	ret = trustix_datapath_alloc_lookup_caches();
	if (ret)
		goto free_session_crypto;
	write_lock_bh(&trustix_datapath_state_lock);
	trustix_datapath_publish_state_counts_locked();
	write_unlock_bh(&trustix_datapath_state_lock);
	WRITE_ONCE(trustix_datapath_rx_worker_param_live, true);
	return 0;

free_session_crypto:
	trustix_datapath_free_table(&trustix_datapath_session_crypto);
free_session_wires:
	trustix_datapath_free_table(&trustix_datapath_session_wires);
free_flows:
	trustix_datapath_free_table(&trustix_datapath_flows);
free_sessions:
	trustix_datapath_free_table(&trustix_datapath_sessions);
free_routes:
	trustix_datapath_free_table(&trustix_datapath_routes);
free_tx_plaintext:
	trustix_datapath_free_tx_plaintext();
free_rx_worker:
	trustix_datapath_free_rx_worker();
free_rx_stage:
	trustix_datapath_free_rx_stage();
	return ret;
}

static void trustix_datapath_free_state(void)
{
	WRITE_ONCE(trustix_datapath_rx_worker_param_live, false);
	write_lock_bh(&trustix_datapath_state_lock);
	trustix_datapath_free_lookup_caches();
	trustix_datapath_free_table(&trustix_datapath_session_crypto);
	trustix_datapath_free_table(&trustix_datapath_session_wires);
	trustix_datapath_free_table(&trustix_datapath_flows);
	trustix_datapath_free_table(&trustix_datapath_sessions);
	trustix_datapath_free_table(&trustix_datapath_routes);
	trustix_datapath_publish_state_counts_locked();
	write_unlock_bh(&trustix_datapath_state_lock);
	trustix_datapath_free_tx_plaintext();
	vfree(trustix_datapath_outer_tcp_shard_sequences);
	trustix_datapath_outer_tcp_shard_sequences = NULL;
	trustix_datapath_outer_tcp_sequence_flow_slots = 0;
	trustix_datapath_free_rx_worker();
	trustix_datapath_free_rx_stage();
}

static bool trustix_datapath_key_equal(const __u64 left[4],
				       const __u64 right[4])
{
	return left[0] == right[0] && left[1] == right[1] &&
	       left[2] == right[2] && left[3] == right[3];
}

static __u32 trustix_datapath_key_hash(const __u64 key[4])
{
	__u64 hash = 1469598103934665603ULL;
	__u32 i;

	for (i = 0; i < 4; i++) {
		hash ^= key[i];
		hash *= 1099511628211ULL;
		hash ^= hash >> 32;
	}
	return (__u32)(hash ^ (hash >> 32));
}

static __always_inline __u32
trustix_datapath_rx_worker_mix_hash(__u32 hash)
{
	hash ^= hash >> 16;
	hash *= 0x7feb352dU;
	hash ^= hash >> 15;
	hash *= 0x846ca68bU;
	hash ^= hash >> 16;
	return hash ?: 1;
}

static __u32 trustix_datapath_session_flow_cache_hash(__u64 flow_id)
{
	__u64 key[4] = { flow_id, flow_id >> 32, 0, 0 };

	return trustix_datapath_key_hash(key);
}

static __always_inline bool
trustix_datapath_tix_tcp_port_sharding_feature_active(void)
{
	return READ_ONCE(trustix_datapath_features) &
	       TRUSTIX_DATAPATH_FEATURE_TIX_TCP_PORT_SHARDING;
}

static __always_inline bool
trustix_datapath_tx_plan_tix_tcp_port_sharding_active(
	const struct trustix_datapath_tx_plan *plan)
{
	return plan && plan->outer_protocol == IPPROTO_TCP &&
	       (plan->session_flags &
		TRUSTIX_DATAPATH_SESSION_FLAG_SEND_TIX_TCP_PORT_SHARDING) &&
	       plan->outer_tcp_port_shard <
		       TRUSTIX_DATAPATH_TIX_TCP_PORT_SHARDS &&
	       trustix_datapath_tix_tcp_port_sharding_feature_active();
}

static bool trustix_datapath_session_slot_index_locked(
	const struct trustix_datapath_state_slot *session, __u32 *index_out)
{
	const struct trustix_datapath_state_slot *slots =
		trustix_datapath_sessions.slots;
	__u32 capacity = trustix_datapath_sessions.capacity;

	if (index_out)
		*index_out = U32_MAX;
	if (!session || !index_out || !slots || !capacity || session < slots ||
	    session >= slots + capacity)
		return false;
	*index_out = (__u32)(session - slots);
	return true;
}

static __always_inline __u16
trustix_datapath_tix_tcp_port_for_shard(__u16 base_port, __u8 shard)
{
	shard &= TRUSTIX_DATAPATH_TIX_TCP_PORT_SHARDS - 1U;
	if (base_port <= U16_MAX -
			 TRUSTIX_DATAPATH_TIX_TCP_PORT_SHARDS + 1U)
		return base_port + shard;
	return base_port - shard;
}

static __always_inline __u8
trustix_datapath_tix_tcp_port_shard_for_hash(__u32 hash)
{
	/* Shard zero is the real compat TCP control connection. */
	return (__u8)(1U +
		      trustix_datapath_rx_worker_mix_hash(hash) %
			      (TRUSTIX_DATAPATH_TIX_TCP_PORT_SHARDS - 1U));
}

static bool trustix_datapath_tix_tcp_port_shard_match(
	__u16 base_port, __u16 candidate_port, __u8 *shard_out)
{
	unsigned int shard;

	if (shard_out)
		*shard_out = 0;
	if (!base_port || !candidate_port)
		return false;
	for (shard = 0; shard < TRUSTIX_DATAPATH_TIX_TCP_PORT_SHARDS;
	     shard++) {
		if (trustix_datapath_tix_tcp_port_for_shard(
			    base_port, (__u8)shard) != candidate_port)
			continue;
		if (shard_out)
			*shard_out = (__u8)shard;
		return true;
	}
	return false;
}

static __always_inline __u32
trustix_datapath_inner_flow_hash(
	const struct trustix_datapath_ioc_classify *classify)
{
	__u64 key[4];
	__u32 hash;

	if (!classify)
		return 0;
	key[0] = classify->src_ipv4;
	key[1] = classify->dst_ipv4;
	key[2] = ((__u64)classify->src_port << 16) | classify->dst_port;
	key[3] = classify->protocol;
	hash = trustix_datapath_key_hash(key);
	return hash ?: 1;
}

static __u32 trustix_datapath_route_dst_cache_hash(__u32 dst_ipv4)
{
	__u64 key[4] = { dst_ipv4, 0, 0, 0 };

	return trustix_datapath_key_hash(key);
}

static __u32
trustix_datapath_session_route_cache_hash(
	const struct trustix_datapath_state_slot *route,
	const struct trustix_datapath_state_slot *flow, __u64 next_hop_hash,
	__u64 endpoint_hash, __u64 pool_index)
{
	__u64 key[4];

	key[0] = (unsigned long)route;
	key[1] = (unsigned long)flow;
	key[2] = next_hop_hash ^ (endpoint_hash << 1);
	key[3] = pool_index;
	return trustix_datapath_key_hash(key);
}

static struct trustix_datapath_state_slot *
trustix_datapath_route_dst_cache_lookup_locked(__u32 dst_ipv4)
{
	__u32 start;
	__u32 i;

	if (!trustix_datapath_route_dst_cache ||
	    !trustix_datapath_route_dst_cache_capacity)
		return NULL;
	start = trustix_datapath_route_dst_cache_hash(dst_ipv4) %
		trustix_datapath_route_dst_cache_capacity;
	for (i = 0; i < trustix_datapath_route_dst_cache_capacity; i++) {
		struct trustix_datapath_route_dst_cache_entry *entry =
			&trustix_datapath_route_dst_cache[
				(start + i) %
				trustix_datapath_route_dst_cache_capacity];
		struct trustix_datapath_state_slot *slot;
		__u32 bits;

		if (!entry->used)
			return NULL;
		if (entry->dst_ipv4 != dst_ipv4)
			continue;
		slot = entry->slot;
		if (!slot || !slot->used)
			return NULL;
		bits = (__u32)slot->key[1];
		if (bits <= 32 &&
		    trustix_datapath_ipv4_prefix_match(
			    dst_ipv4, (__u32)slot->key[0], bits))
			return slot;
		return NULL;
	}
	return NULL;
}

static void
trustix_datapath_route_dst_cache_insert_locked(
	__u32 dst_ipv4, struct trustix_datapath_state_slot *slot)
{
	__u32 start;
	__u32 i;

	if (!slot || !slot->used || !trustix_datapath_route_dst_cache ||
	    !trustix_datapath_route_dst_cache_capacity)
		return;
	start = trustix_datapath_route_dst_cache_hash(dst_ipv4) %
		trustix_datapath_route_dst_cache_capacity;
	for (i = 0; i < trustix_datapath_route_dst_cache_capacity; i++) {
		struct trustix_datapath_route_dst_cache_entry *entry =
			&trustix_datapath_route_dst_cache[
				(start + i) %
				trustix_datapath_route_dst_cache_capacity];

		if (entry->used && entry->dst_ipv4 != dst_ipv4)
			continue;
		entry->used = true;
		entry->dst_ipv4 = dst_ipv4;
		entry->slot = slot;
		return;
	}
}

static struct trustix_datapath_state_slot *
trustix_datapath_session_route_cache_lookup_locked(
	struct trustix_datapath_state_slot *route,
	struct trustix_datapath_state_slot *flow, __u64 next_hop_hash,
	__u64 endpoint_hash, __u64 pool_index)
{
	__u32 start;
	__u32 i;

	if (!route || !trustix_datapath_session_route_cache ||
	    !trustix_datapath_session_route_cache_capacity)
		return NULL;
	start = trustix_datapath_session_route_cache_hash(
			route, flow, next_hop_hash, endpoint_hash,
			pool_index) %
		trustix_datapath_session_route_cache_capacity;
	for (i = 0; i < trustix_datapath_session_route_cache_capacity; i++) {
		struct trustix_datapath_session_route_cache_entry *entry =
			&trustix_datapath_session_route_cache[
				(start + i) %
				trustix_datapath_session_route_cache_capacity];
		struct trustix_datapath_state_slot *slot;

		if (!entry->used)
			return NULL;
		if (entry->route != route || entry->flow != flow ||
		    entry->next_hop_hash != next_hop_hash ||
		    entry->endpoint_hash != endpoint_hash ||
		    entry->pool_index != pool_index)
			continue;
		slot = entry->slot;
		if (slot && slot->used &&
		    (slot->flags & TRUSTIX_DATAPATH_SESSION_FLAG_KERNEL_FLOW) &&
		    (!next_hop_hash || slot->key[0] == next_hop_hash) &&
		    (!endpoint_hash || slot->key[1] == endpoint_hash) &&
		    (!flow || slot->value[7] == pool_index))
			return slot;
		return NULL;
	}
	return NULL;
}

static void
trustix_datapath_session_route_cache_insert_locked(
	struct trustix_datapath_state_slot *route,
	struct trustix_datapath_state_slot *flow, __u64 next_hop_hash,
	__u64 endpoint_hash, __u64 pool_index,
	struct trustix_datapath_state_slot *slot)
{
	__u32 start;
	__u32 i;

	if (!route || !slot || !slot->used ||
	    !trustix_datapath_session_route_cache ||
	    !trustix_datapath_session_route_cache_capacity)
		return;
	start = trustix_datapath_session_route_cache_hash(
			route, flow, next_hop_hash, endpoint_hash,
			pool_index) %
		trustix_datapath_session_route_cache_capacity;
	for (i = 0; i < trustix_datapath_session_route_cache_capacity; i++) {
		struct trustix_datapath_session_route_cache_entry *entry =
			&trustix_datapath_session_route_cache[
				(start + i) %
				trustix_datapath_session_route_cache_capacity];

		if (entry->used &&
		    (entry->route != route || entry->flow != flow ||
		     entry->next_hop_hash != next_hop_hash ||
		     entry->endpoint_hash != endpoint_hash ||
		     entry->pool_index != pool_index))
			continue;
		entry->used = true;
		entry->route = route;
		entry->flow = flow;
		entry->next_hop_hash = next_hop_hash;
		entry->endpoint_hash = endpoint_hash;
		entry->pool_index = pool_index;
		entry->slot = slot;
		return;
	}
}

static bool
trustix_datapath_wire_tuple_cache_match(
	const struct trustix_datapath_session_wire_tuple_cache_entry *entry,
	__u64 flow_id, __u32 src_ipv4, __u32 dst_ipv4, __u16 src_port,
	__u16 dst_port, __u8 protocol)
{
	return entry && entry->used && (!flow_id || entry->flow_id == flow_id) &&
	       entry->src_ipv4 == src_ipv4 && entry->dst_ipv4 == dst_ipv4 &&
	       entry->src_port == src_port && entry->dst_port == dst_port &&
	       entry->protocol == protocol;
}

static bool
trustix_datapath_wire_tuple_cache_match_exact(
	const struct trustix_datapath_session_wire_tuple_cache_entry *entry,
	__u64 flow_id, __u32 src_ipv4, __u32 dst_ipv4, __u16 src_port,
	__u16 dst_port, __u8 protocol)
{
	return entry && entry->used && entry->flow_id == flow_id &&
	       entry->src_ipv4 == src_ipv4 && entry->dst_ipv4 == dst_ipv4 &&
	       entry->src_port == src_port && entry->dst_port == dst_port &&
	       entry->protocol == protocol;
}

static __u32
trustix_datapath_wire_tuple_cache_hash(__u64 flow_id, __u32 src_ipv4,
				       __u32 dst_ipv4, __u16 src_port,
				       __u16 dst_port, __u8 protocol)
{
	__u64 key[4];

	key[0] = src_ipv4;
	key[1] = dst_ipv4;
	key[2] = ((__u64)src_port << 16) | (__u64)dst_port;
	key[3] = (__u64)protocol << 56;
	(void)flow_id;
	return trustix_datapath_key_hash(key);
}

static void
trustix_datapath_session_flow_cache_insert_locked(
	struct trustix_datapath_state_slot *slot)
{
	__u64 flow_id;
	__u32 start;
	__u32 i;

	if (!slot || !slot->used ||
	    !(slot->flags & TRUSTIX_DATAPATH_SESSION_FLAG_KERNEL_FLOW) ||
	    !trustix_datapath_session_flow_cache ||
	    !trustix_datapath_session_flow_cache_capacity)
		return;
	flow_id = slot->value[0];
	if (!flow_id)
		return;
	start = trustix_datapath_session_flow_cache_hash(flow_id) %
		trustix_datapath_session_flow_cache_capacity;
	for (i = 0; i < trustix_datapath_session_flow_cache_capacity; i++) {
		struct trustix_datapath_session_flow_cache_entry *entry =
			&trustix_datapath_session_flow_cache[
				(start + i) %
				trustix_datapath_session_flow_cache_capacity];

		if (entry->used && entry->flow_id != flow_id)
			continue;
		entry->used = true;
		entry->flow_id = flow_id;
		entry->slot = slot;
		return;
	}
}

static struct trustix_datapath_state_slot *
trustix_datapath_session_flow_cache_lookup_locked(__u64 flow_id)
{
	__u32 start;
	__u32 i;

	if (!flow_id || !trustix_datapath_session_flow_cache ||
	    !trustix_datapath_session_flow_cache_capacity)
		return NULL;
	start = trustix_datapath_session_flow_cache_hash(flow_id) %
		trustix_datapath_session_flow_cache_capacity;
	for (i = 0; i < trustix_datapath_session_flow_cache_capacity; i++) {
		struct trustix_datapath_session_flow_cache_entry *entry =
			&trustix_datapath_session_flow_cache[
				(start + i) %
				trustix_datapath_session_flow_cache_capacity];
		struct trustix_datapath_state_slot *slot;

		if (!entry->used)
			return NULL;
		if (entry->flow_id != flow_id)
			continue;
		slot = entry->slot;
		if (slot && slot->used &&
		    (slot->flags & TRUSTIX_DATAPATH_SESSION_FLAG_KERNEL_FLOW) &&
		    slot->value[0] == flow_id)
			return slot;
		return NULL;
	}
	return NULL;
}

static bool trustix_datapath_tix_tcp_port_sharding_allowed(
	const struct trustix_datapath_state_slot *session, bool reverse)
{
	__u32 required_flag;

	if (!session || !session->used ||
	    !trustix_datapath_tix_tcp_port_sharding_feature_active())
		return false;
	required_flag = reverse ?
		TRUSTIX_DATAPATH_SESSION_FLAG_RECEIVE_TIX_TCP_PORT_SHARDING :
		TRUSTIX_DATAPATH_SESSION_FLAG_SEND_TIX_TCP_PORT_SHARDING;
	return session->flags & required_flag;
}

static void
trustix_datapath_wire_tuple_cache_insert_one_locked(
	struct trustix_datapath_state_slot *slot,
	struct trustix_datapath_state_slot *session, __u64 flow_id,
	__u32 src_ipv4, __u32 dst_ipv4, __u16 src_port, __u16 dst_port,
	__u8 protocol, bool reverse, __u8 shard)
{
	__u32 start;
	__u32 i;

	if (!slot || !slot->used || !trustix_datapath_session_wire_tuple_cache ||
	    !trustix_datapath_session_wire_tuple_cache_capacity)
		return;
	start = trustix_datapath_wire_tuple_cache_hash(
			flow_id, src_ipv4, dst_ipv4, src_port, dst_port,
			protocol) %
		trustix_datapath_session_wire_tuple_cache_capacity;
	for (i = 0; i < trustix_datapath_session_wire_tuple_cache_capacity;
	     i++) {
		struct trustix_datapath_session_wire_tuple_cache_entry *entry =
			&trustix_datapath_session_wire_tuple_cache[
				(start + i) %
				trustix_datapath_session_wire_tuple_cache_capacity];

		if (entry->used &&
		    !trustix_datapath_wire_tuple_cache_match_exact(
			    entry, flow_id, src_ipv4, dst_ipv4, src_port,
			    dst_port, protocol))
			continue;
		entry->used = true;
		entry->reverse = reverse;
		entry->shard = shard;
		entry->protocol = protocol;
		entry->src_port = src_port;
		entry->dst_port = dst_port;
		entry->src_ipv4 = src_ipv4;
		entry->dst_ipv4 = dst_ipv4;
		entry->flow_id = flow_id;
		entry->session = session;
		entry->slot = slot;
		return;
	}
}

static void
trustix_datapath_session_wire_tuple_cache_insert_locked(
	struct trustix_datapath_state_slot *slot)
{
	__u64 flow_id;
	__u32 local_ipv4;
	__u32 remote_ipv4;
	__u16 local_port;
	__u16 remote_port;
	__u8 protocol;
	struct trustix_datapath_state_slot *session;
	unsigned int shard;

	if (!slot || !slot->used)
		return;
	flow_id = slot->value[0];
	local_ipv4 = (__u32)slot->value[1];
	remote_ipv4 = (__u32)slot->value[2];
	local_port = (__u16)(slot->value[3] >> 16);
	remote_port = (__u16)slot->value[3];
	if (!flow_id || !local_ipv4 || !remote_ipv4 || !local_port ||
	    !remote_port)
		return;
	switch ((__u32)slot->value[4]) {
	case TRUSTIX_DATAPATH_TRANSPORT_UDP:
		protocol = IPPROTO_UDP;
		break;
	case TRUSTIX_DATAPATH_TRANSPORT_TIX_TCP:
		protocol = IPPROTO_TCP;
		break;
	default:
		return;
	}
	session = trustix_datapath_session_for_flow_id_locked(flow_id);
	trustix_datapath_wire_tuple_cache_insert_one_locked(
		slot, session, flow_id, local_ipv4, remote_ipv4, local_port,
		remote_port, protocol, false, 0);
	trustix_datapath_wire_tuple_cache_insert_one_locked(
		slot, session, flow_id, remote_ipv4, local_ipv4, remote_port,
		local_port, protocol, true, 0);
	if (protocol == IPPROTO_TCP && session) {
		if (trustix_datapath_tix_tcp_port_sharding_allowed(
			    session, false)) {
			for (shard = 1;
			     shard < TRUSTIX_DATAPATH_TIX_TCP_PORT_SHARDS;
			     shard++)
				trustix_datapath_wire_tuple_cache_insert_one_locked(
					slot, session, flow_id, local_ipv4,
					remote_ipv4,
					trustix_datapath_tix_tcp_port_for_shard(
						local_port, (__u8)shard),
					remote_port, protocol, false,
					(__u8)shard);
		}
		if (trustix_datapath_tix_tcp_port_sharding_allowed(
			    session, true)) {
			for (shard = 1;
			     shard < TRUSTIX_DATAPATH_TIX_TCP_PORT_SHARDS;
			     shard++)
				trustix_datapath_wire_tuple_cache_insert_one_locked(
					slot, session, flow_id, remote_ipv4,
					local_ipv4,
					trustix_datapath_tix_tcp_port_for_shard(
						remote_port, (__u8)shard),
					local_port, protocol, true,
					(__u8)shard);
		}
	}
	if (protocol == IPPROTO_UDP) {
		trustix_datapath_wire_tuple_cache_insert_one_locked(
			slot, session, 0, local_ipv4, remote_ipv4, local_port,
			remote_port, protocol, false, 0);
		trustix_datapath_wire_tuple_cache_insert_one_locked(
			slot, session, 0, remote_ipv4, local_ipv4, remote_port,
			local_port, protocol, true, 0);
	}
}

static struct trustix_datapath_state_slot *
trustix_datapath_session_wire_tuple_cache_lookup_locked(
	__u64 flow_id, __u32 src_ipv4, __u32 dst_ipv4, __u16 src_port,
	__u16 dst_port, __u8 protocol, bool *reverse)
{
	__u32 start;
	__u32 i;

	if (reverse)
		*reverse = false;
	if (!trustix_datapath_session_wire_tuple_cache ||
	    !trustix_datapath_session_wire_tuple_cache_capacity)
		return NULL;
	start = trustix_datapath_wire_tuple_cache_hash(
			flow_id, src_ipv4, dst_ipv4, src_port, dst_port,
			protocol) %
		trustix_datapath_session_wire_tuple_cache_capacity;
	for (i = 0; i < trustix_datapath_session_wire_tuple_cache_capacity;
	     i++) {
		struct trustix_datapath_session_wire_tuple_cache_entry *entry =
			&trustix_datapath_session_wire_tuple_cache[
				(start + i) %
				trustix_datapath_session_wire_tuple_cache_capacity];
		struct trustix_datapath_state_slot *slot;

		if (!entry->used)
			return NULL;
		if (!trustix_datapath_wire_tuple_cache_match(
			    entry, flow_id, src_ipv4, dst_ipv4, src_port,
			    dst_port, protocol))
			continue;
		slot = entry->slot;
		if (!slot || !slot->used)
			return NULL;
		if (entry->protocol == IPPROTO_TCP && entry->session) {
			struct trustix_datapath_state_slot *session = entry->session;

			if (entry->shard &&
			    (!session->used ||
			     session->value[0] != entry->flow_id ||
			     !trustix_datapath_tix_tcp_port_sharding_allowed(
				     session, entry->reverse)))
				return NULL;
			if (session->used &&
			    session->value[0] == entry->flow_id &&
			    trustix_datapath_tix_tcp_port_sharding_allowed(
				    session, entry->reverse))
				trustix_datapath_rx_tix_tcp_port_shard_matches++;
		}
		if (reverse)
			*reverse = entry->reverse;
		return slot;
	}
	return NULL;
}

static void trustix_datapath_rebuild_lookup_caches_locked(void)
{
	__u32 i;

	if (trustix_datapath_route_dst_cache &&
	    trustix_datapath_route_dst_cache_capacity)
		memset(trustix_datapath_route_dst_cache, 0,
		       array_size(trustix_datapath_route_dst_cache_capacity,
				  sizeof(*trustix_datapath_route_dst_cache)));
	if (trustix_datapath_session_route_cache &&
	    trustix_datapath_session_route_cache_capacity)
		memset(trustix_datapath_session_route_cache, 0,
		       array_size(trustix_datapath_session_route_cache_capacity,
				  sizeof(*trustix_datapath_session_route_cache)));
	if (trustix_datapath_session_flow_cache &&
	    trustix_datapath_session_flow_cache_capacity)
		memset(trustix_datapath_session_flow_cache, 0,
		       array_size(trustix_datapath_session_flow_cache_capacity,
				  sizeof(*trustix_datapath_session_flow_cache)));
	if (trustix_datapath_session_wire_tuple_cache &&
	    trustix_datapath_session_wire_tuple_cache_capacity)
		memset(trustix_datapath_session_wire_tuple_cache, 0,
		       array_size(
			       trustix_datapath_session_wire_tuple_cache_capacity,
			       sizeof(*trustix_datapath_session_wire_tuple_cache)));
	if (trustix_datapath_table_usable_locked(&trustix_datapath_sessions)) {
		for (i = 0; i < trustix_datapath_sessions.capacity; i++)
			trustix_datapath_session_flow_cache_insert_locked(
				&trustix_datapath_sessions.slots[i]);
	}
	if (trustix_datapath_table_usable_locked(
		    &trustix_datapath_session_wires)) {
		for (i = 0; i < trustix_datapath_session_wires.capacity; i++)
			trustix_datapath_session_wire_tuple_cache_insert_locked(
				&trustix_datapath_session_wires.slots[i]);
	}
}

static struct trustix_datapath_state_table *
trustix_datapath_table_for_kind(__u32 kind)
{
	switch (kind) {
	case TRUSTIX_DATAPATH_STATE_KIND_ROUTE:
		return &trustix_datapath_routes;
	case TRUSTIX_DATAPATH_STATE_KIND_SESSION:
		return &trustix_datapath_sessions;
	case TRUSTIX_DATAPATH_STATE_KIND_FLOW:
		return &trustix_datapath_flows;
	case TRUSTIX_DATAPATH_STATE_KIND_SESSION_WIRE:
		return &trustix_datapath_session_wires;
	case TRUSTIX_DATAPATH_STATE_KIND_SESSION_CRYPTO:
		return &trustix_datapath_session_crypto;
	default:
		return NULL;
	}
}

static struct trustix_datapath_state_slot *
trustix_datapath_find_slot(struct trustix_datapath_state_table *table,
			   const __u64 key[4])
{
	__u32 start;
	__u32 i;

	if (!trustix_datapath_table_usable_locked(table))
		return NULL;
	start = trustix_datapath_key_hash(key) % table->capacity;
	for (i = 0; i < table->capacity; i++) {
		struct trustix_datapath_state_slot *slot =
			&table->slots[(start + i) % table->capacity];

		if (!slot->used) {
			if (!slot->tombstone)
				return NULL;
			continue;
		}
		if (trustix_datapath_key_equal(slot->key, key))
			return slot;
	}
	return NULL;
}

static struct trustix_datapath_state_slot *
trustix_datapath_first_free_slot(struct trustix_datapath_state_table *table,
				 const __u64 key[4])
{
	struct trustix_datapath_state_slot *first_tombstone = NULL;
	__u32 start;
	__u32 i;

	if (!trustix_datapath_table_usable_locked(table))
		return NULL;
	start = trustix_datapath_key_hash(key) % table->capacity;
	for (i = 0; i < table->capacity; i++) {
		struct trustix_datapath_state_slot *slot =
			&table->slots[(start + i) % table->capacity];

		if (slot->used)
			continue;
		if (slot->tombstone) {
			if (!first_tombstone)
				first_tombstone = slot;
			continue;
		}
		return first_tombstone ? first_tombstone : slot;
	}
	return first_tombstone;
}

static int trustix_datapath_validate_session_crypto_upsert(
	const struct trustix_datapath_ioc_state *state, __u64 runtime[2])
{
	struct trustix_datapath_state_slot *session;
	struct trustix_datapath_state_slot *wire;
	__u64 epoch;
	__u32 send_slot;
	__u32 receive_slot;
	__u32 replay_window;
	__u16 suite;
	__u16 wire_format;
	int ret;

	if (!state || !runtime)
		return -EINVAL;
	runtime[0] = 0;
	runtime[1] = 0;
	if ((state->flags & TRUSTIX_DATAPATH_SESSION_CRYPTO_FLAGS_READY) !=
		    TRUSTIX_DATAPATH_SESSION_CRYPTO_FLAGS_READY ||
	    state->flags & ~TRUSTIX_DATAPATH_SESSION_CRYPTO_FLAGS_READY)
		return -EINVAL;
	if (!(READ_ONCE(trustix_datapath_features) &
	      TRUSTIX_DATAPATH_FEATURE_SECURE_TIX_TCP_FULL_DATAPATH) ||
	    !trustix_datapath_crypto_slot_generation)
		return -EOPNOTSUPP;

	session = trustix_datapath_find_slot(&trustix_datapath_sessions,
					      state->key);
	wire = trustix_datapath_find_slot(&trustix_datapath_session_wires,
					   state->key);
	if (!session || !wire)
		return -ESTALE;
	if (!state->value[0] || session->value[0] != state->value[0] ||
	    (__u32)wire->value[4] != TRUSTIX_DATAPATH_TRANSPORT_TIX_TCP ||
	    wire->key[0] != session->key[0] ||
	    wire->key[1] != session->key[1] ||
	    wire->key[2] != session->key[2] ||
	    wire->key[3] != session->key[3])
		return -ESTALE;
	if ((session->flags &
	     (TRUSTIX_DATAPATH_SESSION_FLAG_SEND_ENCRYPTED |
	      TRUSTIX_DATAPATH_SESSION_FLAG_RECEIVE_ENCRYPTED)) !=
		    (TRUSTIX_DATAPATH_SESSION_FLAG_SEND_ENCRYPTED |
		     TRUSTIX_DATAPATH_SESSION_FLAG_RECEIVE_ENCRYPTED))
		return -EPROTONOSUPPORT;

	epoch = state->value[1];
	send_slot = (__u32)state->value[2];
	receive_slot = (__u32)(state->value[2] >> 32);
	suite = (__u16)state->value[3];
	wire_format = (__u16)(state->value[3] >> 16);
	replay_window = (__u32)(state->value[3] >> 32);
	if ((wire->value[6] && wire->value[6] != epoch) ||
	    (suite != TRUSTIX_DATAPATH_SECURE_SUITE_AES_256_GCM_X25519 &&
	     suite != TRUSTIX_DATAPATH_SECURE_SUITE_AES_128_GCM_X25519) ||
	    wire_format != TRUSTIX_DATAPATH_SECURE_WIRE_FORMAT_V1 ||
	    !replay_window || replay_window > TRUSTIX_DATAPATH_SECURE_REPLAY_MAX)
		return -EINVAL;

	ret = trustix_datapath_crypto_slot_generation(send_slot, false,
						      &runtime[0]);
	if (ret)
		return ret;
	ret = trustix_datapath_crypto_slot_generation(receive_slot, true,
						      &runtime[1]);
	if (ret) {
		runtime[0] = 0;
		return ret;
	}
	if (!runtime[0] || !runtime[1]) {
		runtime[0] = 0;
		runtime[1] = 0;
		return -ESTALE;
	}
	return 0;
}

static void trustix_datapath_clear_table(struct trustix_datapath_state_table *table)
{
	if (!trustix_datapath_table_usable_locked(table))
		return;
	memset(table->slots, 0, array_size(table->capacity,
					   sizeof(*table->slots)));
	table->count = 0;
}

static int
trustix_datapath_state_apply_to_table(struct trustix_datapath_state_table *table,
				      struct trustix_datapath_ioc_state *state,
				      bool account)
{
	struct trustix_datapath_state_slot *slot;

	if (!trustix_datapath_table_usable_locked(table))
		return -EINVAL;

	switch (state->op) {
	case TRUSTIX_DATAPATH_STATE_OP_UPSERT:
		slot = trustix_datapath_find_slot(table, state->key);
		if (!slot) {
			slot = trustix_datapath_first_free_slot(table,
							       state->key);
			if (!slot) {
				if (account)
					trustix_datapath_state_table_full++;
				return -ENOSPC;
			}
			slot->used = true;
			slot->tombstone = false;
			memcpy(slot->key, state->key, sizeof(slot->key));
			table->count++;
		}
		slot->flags = state->flags;
		memcpy(slot->value, state->value, sizeof(slot->value));
		if (account) {
			trustix_datapath_state_upserts++;
			trustix_datapath_publish_state_counts_locked();
		}
		return 0;
	case TRUSTIX_DATAPATH_STATE_OP_GET:
		slot = trustix_datapath_find_slot(table, state->key);
		if (!slot) {
			if (account)
				trustix_datapath_state_get_misses++;
			return -ENOENT;
		}
		state->flags = slot->flags;
		memcpy(state->value, slot->value, sizeof(state->value));
		if (account)
			trustix_datapath_state_get_hits++;
		return 0;
	case TRUSTIX_DATAPATH_STATE_OP_DELETE:
		slot = trustix_datapath_find_slot(table, state->key);
		if (!slot)
			return -ENOENT;
		memset(slot, 0, sizeof(*slot));
		slot->tombstone = true;
		if (table->count)
			table->count--;
		if (account) {
			trustix_datapath_state_deletes++;
			trustix_datapath_publish_state_counts_locked();
		}
		return 0;
	case TRUSTIX_DATAPATH_STATE_OP_CLEAR:
		trustix_datapath_clear_table(table);
		if (account) {
			trustix_datapath_state_clears++;
			trustix_datapath_publish_state_counts_locked();
		}
		return 0;
	default:
		return -EINVAL;
	}
}

static bool trustix_datapath_state_kind_affects_lookup_caches(__u32 kind)
{
	return kind == TRUSTIX_DATAPATH_STATE_KIND_ROUTE ||
	       kind == TRUSTIX_DATAPATH_STATE_KIND_SESSION ||
	       kind == TRUSTIX_DATAPATH_STATE_KIND_FLOW ||
	       kind == TRUSTIX_DATAPATH_STATE_KIND_SESSION_WIRE;
}

static int trustix_datapath_state_apply_locked_maybe_rebuild(
	struct trustix_datapath_ioc_state *state, bool rebuild)
{
	struct trustix_datapath_state_table *table;
	struct trustix_datapath_state_slot *slot;
	__u64 runtime[2] = {};
	__u64 stale_inner_gso_flow_id = 0;
	__u64 stale_inner_gso_epoch = 0;
	bool clear_inner_gso_session = false;
	bool clear_all_inner_gso_sessions = false;
	int ret;

	if (!state)
		return -EINVAL;
	if (state->kind == TRUSTIX_DATAPATH_STATE_KIND_SESSION_CRYPTO &&
	    state->op == TRUSTIX_DATAPATH_STATE_OP_UPSERT) {
		ret = trustix_datapath_validate_session_crypto_upsert(state,
							      runtime);
		if (ret)
			return ret;
	}
	table = trustix_datapath_table_for_kind(state->kind);
	if (state->kind == TRUSTIX_DATAPATH_STATE_KIND_SESSION &&
	    trustix_datapath_table_usable_locked(table)) {
		switch (state->op) {
		case TRUSTIX_DATAPATH_STATE_OP_UPSERT:
			slot = trustix_datapath_find_slot(table, state->key);
			if (slot &&
			    (slot->flags &
			     TRUSTIX_DATAPATH_SESSION_FLAG_RECEIVE_INNER_GSO) &&
			    (!(state->flags &
			       TRUSTIX_DATAPATH_SESSION_FLAG_RECEIVE_INNER_GSO) ||
			     slot->value[0] != state->value[0] ||
			     slot->value[2] != state->value[2])) {
				stale_inner_gso_flow_id = slot->value[0];
				stale_inner_gso_epoch = slot->value[2];
				clear_inner_gso_session = true;
			}
			break;
		case TRUSTIX_DATAPATH_STATE_OP_DELETE:
			slot = trustix_datapath_find_slot(table, state->key);
			if (slot &&
			    (slot->flags &
			     TRUSTIX_DATAPATH_SESSION_FLAG_RECEIVE_INNER_GSO)) {
				stale_inner_gso_flow_id = slot->value[0];
				stale_inner_gso_epoch = slot->value[2];
				clear_inner_gso_session = true;
			}
			break;
		case TRUSTIX_DATAPATH_STATE_OP_CLEAR:
			clear_all_inner_gso_sessions = true;
			break;
		default:
			break;
		}
	}
	ret = trustix_datapath_state_apply_to_table(table, state, true);
	if (!ret && clear_all_inner_gso_sessions)
		trustix_datapath_clear_inner_gso_reassembly_for_all_sessions();
	else if (!ret && clear_inner_gso_session)
		trustix_datapath_clear_inner_gso_reassembly_for_session(
			stale_inner_gso_flow_id, stale_inner_gso_epoch);
	if (!ret && state->kind == TRUSTIX_DATAPATH_STATE_KIND_SESSION_CRYPTO &&
	    state->op == TRUSTIX_DATAPATH_STATE_OP_UPSERT) {
		slot = trustix_datapath_find_slot(table, state->key);
		if (WARN_ON_ONCE(!slot))
			return -ESTALE;
		slot->runtime[0] = runtime[0];
		slot->runtime[1] = runtime[1];
	}
	if (!ret && rebuild &&
	    trustix_datapath_state_kind_affects_lookup_caches(state->kind))
		trustix_datapath_rebuild_lookup_caches_locked();
	return ret;
}

static int
trustix_datapath_state_apply_locked(struct trustix_datapath_ioc_state *state)
{
	return trustix_datapath_state_apply_locked_maybe_rebuild(state, true);
}

static bool trustix_datapath_ipv4_prefix_match(__u32 addr, __u32 prefix,
					       __u32 bits)
{
	__u32 mask;

	if (bits > 32)
		return false;
	if (bits == 0)
		return true;
	mask = bits == 32 ? 0xffffffffU : ~((1U << (32 - bits)) - 1U);
	return (addr & mask) == (prefix & mask);
}

static struct trustix_datapath_state_slot *
trustix_datapath_route_lookup_locked(__u32 dst_ipv4)
{
	struct trustix_datapath_state_slot *best = NULL;
	struct trustix_datapath_state_slot *cached;
	struct trustix_datapath_state_slot *slots;
	__u32 best_bits = 0;
	__u32 capacity;
	__u32 i;

	if (!trustix_datapath_table_usable_locked(&trustix_datapath_routes))
		return NULL;
	cached = trustix_datapath_route_dst_cache_lookup_locked(dst_ipv4);
	if (cached)
		return cached;
	slots = trustix_datapath_routes.slots;
	capacity = trustix_datapath_routes.capacity;
	for (i = 0; i < capacity; i++) {
		struct trustix_datapath_state_slot *slot = &slots[i];
		__u32 prefix;
		__u32 bits;

		if (!slot->used)
			continue;
		bits = (__u32)slot->key[1];
		if (bits > 32)
			continue;
		prefix = (__u32)slot->key[0];
		if (!trustix_datapath_ipv4_prefix_match(dst_ipv4, prefix, bits))
			continue;
		if (!best || bits > best_bits ||
		    (bits == best_bits && slot->value[0] < best->value[0])) {
			best = slot;
			best_bits = bits;
		}
	}
	if (best)
		trustix_datapath_route_dst_cache_insert_locked(dst_ipv4, best);
	return best;
}

static void trustix_datapath_flow_key(__u64 key[4], __u32 src_ipv4,
				      __u32 dst_ipv4, __u16 src_port,
				      __u16 dst_port, __u8 protocol)
{
	key[0] = src_ipv4;
	key[1] = dst_ipv4;
	key[2] = ((__u64)src_port << 16) | (__u64)dst_port;
	key[3] = protocol;
}

static int
trustix_datapath_session_route_rank(
	const struct trustix_datapath_state_slot *slot)
{
	if (!slot)
		return -1;
	/* Full-plaintext raw TCP must not share a negotiated TCP stream tuple. */
	if (slot->flags & TRUSTIX_DATAPATH_SESSION_FLAG_SYNTHETIC_FALLBACK)
		return 4;
	if (slot->flags & TRUSTIX_DATAPATH_SESSION_FLAG_REVERSE)
		return 2;
	return 3;
}

static struct trustix_datapath_state_slot *
trustix_datapath_session_for_route_locked(struct trustix_datapath_state_slot *route,
					  struct trustix_datapath_state_slot *flow)
{
	struct trustix_datapath_state_slot *best = NULL;
	struct trustix_datapath_state_slot *cached;
	struct trustix_datapath_state_slot *slots;
	__u64 next_hop_hash = 0;
	__u64 endpoint_hash = 0;
	__u64 pool_index = 0;
	__u32 capacity;
	__u32 i;
	int best_rank = -1;

	if (!route ||
	    !trustix_datapath_table_usable_locked(&trustix_datapath_sessions))
		return NULL;
	slots = trustix_datapath_sessions.slots;
	capacity = trustix_datapath_sessions.capacity;
	next_hop_hash = route->key[2];
	endpoint_hash = route->key[3];
	if (flow) {
		if (flow->value[0])
			next_hop_hash = flow->value[0];
		if (flow->value[1])
			endpoint_hash = flow->value[1];
		pool_index = flow->value[2];
	}
	cached = trustix_datapath_session_route_cache_lookup_locked(
		route, flow, next_hop_hash, endpoint_hash, pool_index);
	if (cached)
		return cached;
	for (i = 0; i < capacity; i++) {
		struct trustix_datapath_state_slot *slot = &slots[i];
		int rank;

		if (!slot->used)
			continue;
		if (!(slot->flags & TRUSTIX_DATAPATH_SESSION_FLAG_KERNEL_FLOW))
			continue;
		if (next_hop_hash && slot->key[0] != next_hop_hash)
			continue;
		if (endpoint_hash && slot->key[1] != endpoint_hash)
			continue;
		if (flow && slot->value[7] != pool_index)
			continue;
		rank = trustix_datapath_session_route_rank(slot);
		if (!best || rank > best_rank ||
		    (rank == best_rank && slot->key[3] < best->key[3])) {
			best = slot;
			best_rank = rank;
		}
	}
	if (best) {
		trustix_datapath_session_route_cache_insert_locked(
			route, flow, next_hop_hash, endpoint_hash, pool_index,
			best);
		return best;
	}
	if (!flow)
		return NULL;
	best = NULL;
	best_rank = -1;
	for (i = 0; i < capacity; i++) {
		struct trustix_datapath_state_slot *slot = &slots[i];
		int rank;

		if (!slot->used)
			continue;
		if (!(slot->flags & TRUSTIX_DATAPATH_SESSION_FLAG_KERNEL_FLOW))
			continue;
		if (next_hop_hash && slot->key[0] != next_hop_hash)
			continue;
		if (endpoint_hash && slot->key[1] != endpoint_hash)
			continue;
		rank = trustix_datapath_session_route_rank(slot);
		if (!best || rank > best_rank ||
		    (rank == best_rank && slot->key[3] < best->key[3])) {
			best = slot;
			best_rank = rank;
		}
	}
	if (!best)
		return NULL;
	trustix_datapath_session_route_cache_insert_locked(
		route, flow, next_hop_hash, endpoint_hash, pool_index, best);
	return best;
}

static struct trustix_datapath_state_slot *
trustix_datapath_session_for_flow_id_locked(__u64 flow_id)
{
	struct trustix_datapath_state_slot *slots;
	struct trustix_datapath_state_slot *cached;
	__u32 capacity;
	__u32 i;

	if (!flow_id ||
	    !trustix_datapath_table_usable_locked(&trustix_datapath_sessions))
		return NULL;
	cached = trustix_datapath_session_flow_cache_lookup_locked(flow_id);
	if (cached)
		return cached;
	slots = trustix_datapath_sessions.slots;
	capacity = trustix_datapath_sessions.capacity;
	for (i = 0; i < capacity; i++) {
		struct trustix_datapath_state_slot *slot = &slots[i];

		if (!slot->used)
			continue;
		if (!(slot->flags & TRUSTIX_DATAPATH_SESSION_FLAG_KERNEL_FLOW))
			continue;
		if (slot->value[0] == flow_id)
			return slot;
	}
	return NULL;
}

static struct trustix_datapath_state_slot *
trustix_datapath_session_wire_for_key_locked(const __u64 key[4])
{
	if (!key ||
	    !trustix_datapath_table_usable_locked(
		    &trustix_datapath_session_wires))
		return NULL;
	return trustix_datapath_find_slot(&trustix_datapath_session_wires, key);
}

static struct trustix_datapath_state_slot *
trustix_datapath_wire_for_session_locked(
	struct trustix_datapath_state_slot *session)
{
	struct trustix_datapath_state_slot *wire;

	if (!session)
		return NULL;
	wire = trustix_datapath_session_wire_for_key_locked(session->key);
	if (!wire || wire->value[0] != session->value[0])
		return NULL;
	return wire;
}

static bool trustix_datapath_session_matches_route_locked(
	struct trustix_datapath_state_slot *session, __u64 next_hop_hash,
	__u64 endpoint_hash, bool require_pool, __u64 pool_index)
{
	if (!session || !session->used)
		return false;
	if (!(session->flags & TRUSTIX_DATAPATH_SESSION_FLAG_KERNEL_FLOW))
		return false;
	if (next_hop_hash && session->key[0] != next_hop_hash)
		return false;
	if (endpoint_hash && session->key[1] != endpoint_hash)
		return false;
	if (require_pool && session->value[7] != pool_index)
		return false;
	return true;
}

static struct trustix_datapath_state_slot *
trustix_datapath_session_for_route_with_wire_locked(
	struct trustix_datapath_state_slot *route,
	struct trustix_datapath_state_slot *flow,
	struct trustix_datapath_state_slot **wire_out)
{
	struct trustix_datapath_state_slot *best = NULL;
	struct trustix_datapath_state_slot *best_wire = NULL;
	struct trustix_datapath_state_slot *cached;
	struct trustix_datapath_state_slot *slots;
	struct trustix_datapath_state_slot *wire;
	__u64 next_hop_hash = 0;
	__u64 endpoint_hash = 0;
	__u64 pool_index = 0;
	__u32 capacity;
	__u32 i;
	int best_rank = -1;

	if (wire_out)
		*wire_out = NULL;
	if (!route ||
	    !trustix_datapath_table_usable_locked(&trustix_datapath_sessions))
		return NULL;
	slots = trustix_datapath_sessions.slots;
	capacity = trustix_datapath_sessions.capacity;
	next_hop_hash = route->key[2];
	endpoint_hash = route->key[3];
	if (flow) {
		if (flow->value[0])
			next_hop_hash = flow->value[0];
		if (flow->value[1])
			endpoint_hash = flow->value[1];
		pool_index = flow->value[2];
	}

	cached = trustix_datapath_session_route_cache_lookup_locked(
		route, flow, next_hop_hash, endpoint_hash, pool_index);
	wire = trustix_datapath_wire_for_session_locked(cached);
	if (wire) {
		if (wire_out)
			*wire_out = wire;
		return cached;
	}

	for (i = 0; i < capacity; i++) {
		struct trustix_datapath_state_slot *slot = &slots[i];
		int rank;

		if (!trustix_datapath_session_matches_route_locked(
			    slot, next_hop_hash, endpoint_hash, !!flow,
			    pool_index))
			continue;
		wire = trustix_datapath_wire_for_session_locked(slot);
		if (!wire)
			continue;
		rank = trustix_datapath_session_route_rank(slot);
		if (!best || rank > best_rank ||
		    (rank == best_rank && slot->key[3] < best->key[3])) {
			best = slot;
			best_wire = wire;
			best_rank = rank;
		}
	}
	if (best) {
		trustix_datapath_session_route_cache_insert_locked(
			route, flow, next_hop_hash, endpoint_hash, pool_index,
			best);
		if (wire_out)
			*wire_out = best_wire;
		return best;
	}

	if (!flow)
		return NULL;
	best = NULL;
	best_wire = NULL;
	best_rank = -1;
	for (i = 0; i < capacity; i++) {
		struct trustix_datapath_state_slot *slot = &slots[i];
		int rank;

		if (!trustix_datapath_session_matches_route_locked(
			    slot, next_hop_hash, endpoint_hash, false,
			    pool_index))
			continue;
		wire = trustix_datapath_wire_for_session_locked(slot);
		if (!wire)
			continue;
		rank = trustix_datapath_session_route_rank(slot);
		if (!best || rank > best_rank ||
		    (rank == best_rank && slot->key[3] < best->key[3])) {
			best = slot;
			best_wire = wire;
			best_rank = rank;
		}
	}
	if (!best)
		return NULL;
	trustix_datapath_session_route_cache_insert_locked(
		route, flow, next_hop_hash, endpoint_hash, pool_index, best);
	if (wire_out)
		*wire_out = best_wire;
	return best;
}

static bool trustix_datapath_session_wire_tuple_matches_locked(
	const struct trustix_datapath_state_slot *wire,
	const struct trustix_datapath_state_slot *session, __u32 src_ipv4,
	__u32 dst_ipv4, __u16 src_port, __u16 dst_port, bool *reverse,
	__u8 *shard_out)
{
	__u32 local_ipv4;
	__u32 remote_ipv4;
	__u16 local_port;
	__u16 remote_port;
	__u8 shard = 0;

	if (reverse)
		*reverse = false;
	if (shard_out)
		*shard_out = 0;
	if (!wire || !wire->used || !session || !session->used ||
	    wire->value[0] != session->value[0])
		return false;
	local_ipv4 = (__u32)wire->value[1];
	remote_ipv4 = (__u32)wire->value[2];
	local_port = (__u16)(wire->value[3] >> 16);
	remote_port = (__u16)wire->value[3];

	if (local_ipv4 == src_ipv4 && remote_ipv4 == dst_ipv4 &&
	    remote_port == dst_port) {
		if (local_port == src_port)
			return true;
		if ((__u32)wire->value[4] !=
			    TRUSTIX_DATAPATH_TRANSPORT_TIX_TCP ||
		    !trustix_datapath_tix_tcp_port_sharding_allowed(
			    session, false) ||
		    !trustix_datapath_tix_tcp_port_shard_match(
			    local_port, src_port, &shard) || !shard)
			return false;
		if (shard_out)
			*shard_out = shard;
		return true;
	}
	if (remote_ipv4 == src_ipv4 && local_ipv4 == dst_ipv4 &&
	    local_port == dst_port) {
		if (remote_port != src_port) {
			if ((__u32)wire->value[4] !=
				    TRUSTIX_DATAPATH_TRANSPORT_TIX_TCP ||
			    !trustix_datapath_tix_tcp_port_sharding_allowed(
				    session, true) ||
			    !trustix_datapath_tix_tcp_port_shard_match(
				    remote_port, src_port, &shard) || !shard)
				return false;
		}
		if (reverse)
			*reverse = true;
		if (shard_out)
			*shard_out = shard;
		return true;
	}
	return false;
}

static struct trustix_datapath_state_slot *
trustix_datapath_session_wire_for_tuple_locked(__u64 flow_id,
					       __u32 src_ipv4, __u32 dst_ipv4,
					       __u16 src_port, __u16 dst_port,
					       __u8 protocol,
					       bool *reverse)
{
	struct trustix_datapath_state_slot *cached;
	struct trustix_datapath_state_slot *session;
	struct trustix_datapath_state_slot *wire;
	struct trustix_datapath_state_slot *slots;
	__u32 transport;
	__u32 capacity;
	__u32 i;
	__u8 shard = 0;

	if (reverse)
		*reverse = false;
	if (!flow_id ||
	    !trustix_datapath_table_usable_locked(
		    &trustix_datapath_session_wires))
		return NULL;
	slots = trustix_datapath_session_wires.slots;
	capacity = trustix_datapath_session_wires.capacity;
	switch (protocol) {
	case IPPROTO_UDP:
		transport = TRUSTIX_DATAPATH_TRANSPORT_UDP;
		break;
	case IPPROTO_TCP:
		transport = TRUSTIX_DATAPATH_TRANSPORT_TIX_TCP;
		break;
	default:
		return NULL;
	}
	cached = trustix_datapath_session_wire_tuple_cache_lookup_locked(
		flow_id, src_ipv4, dst_ipv4, src_port, dst_port, protocol,
		reverse);
	if (cached)
		return cached;
	session = trustix_datapath_session_for_flow_id_locked(flow_id);
	wire = trustix_datapath_wire_for_session_locked(session);
	if (wire && (__u32)wire->value[4] == transport &&
	    trustix_datapath_session_wire_tuple_matches_locked(
		    wire, session, src_ipv4, dst_ipv4, src_port, dst_port,
		    reverse, &shard)) {
		if (shard)
			trustix_datapath_rx_tix_tcp_port_shard_matches++;
		return wire;
	}
	for (i = 0; i < capacity; i++) {
		struct trustix_datapath_state_slot *slot = &slots[i];

		if (!slot->used)
			continue;
		if (slot->value[0] != flow_id ||
		    (__u32)slot->value[4] != transport)
			continue;
		session = trustix_datapath_session_for_flow_id_locked(
			slot->value[0]);
		if (trustix_datapath_session_wire_tuple_matches_locked(
			    slot, session, src_ipv4, dst_ipv4, src_port,
			    dst_port, reverse, &shard)) {
			if (shard)
				trustix_datapath_rx_tix_tcp_port_shard_matches++;
			return slot;
		}
	}
	return NULL;
}

static struct trustix_datapath_state_slot *
trustix_datapath_session_wire_for_tuple_any_flow_locked(
	__u32 src_ipv4, __u32 dst_ipv4, __u16 src_port, __u16 dst_port,
	__u8 protocol, bool *reverse)
{
	struct trustix_datapath_state_slot *cached;
	struct trustix_datapath_state_slot *slots;
	__u32 transport;
	__u32 capacity;
	__u32 i;

	if (reverse)
		*reverse = false;
	if (!trustix_datapath_table_usable_locked(
		    &trustix_datapath_session_wires))
		return NULL;
	slots = trustix_datapath_session_wires.slots;
	capacity = trustix_datapath_session_wires.capacity;
	switch (protocol) {
	case IPPROTO_UDP:
		transport = TRUSTIX_DATAPATH_TRANSPORT_UDP;
		break;
	case IPPROTO_TCP:
		transport = TRUSTIX_DATAPATH_TRANSPORT_TIX_TCP;
		break;
	default:
		return NULL;
	}
	cached = trustix_datapath_session_wire_tuple_cache_lookup_locked(
		0, src_ipv4, dst_ipv4, src_port, dst_port, protocol, reverse);
	if (cached)
		return cached;
	for (i = 0; i < capacity; i++) {
		struct trustix_datapath_state_slot *slot = &slots[i];
		struct trustix_datapath_state_slot *session;
		bool matched_reverse = false;
		__u8 shard = 0;

		if (!slot->used)
			continue;
		if ((__u32)slot->value[4] != transport)
			continue;
		session = trustix_datapath_session_for_flow_id_locked(
			slot->value[0]);
		if (!trustix_datapath_session_wire_tuple_matches_locked(
			    slot, session, src_ipv4, dst_ipv4, src_port,
			    dst_port, &matched_reverse, &shard))
			continue;
		if (reverse)
			*reverse = matched_reverse;
		if (shard)
			trustix_datapath_rx_tix_tcp_port_shard_matches++;
		return slot;
	}
	return NULL;
}

static int trustix_datapath_classify_locked(struct trustix_datapath_ioc_classify *request)
{
	struct trustix_datapath_state_slot *route;
	struct trustix_datapath_state_slot *flow;
	struct trustix_datapath_state_slot *session;
	__u64 flow_key[4];

	if (!request)
		return -EINVAL;
	route = trustix_datapath_route_lookup_locked(request->dst_ipv4);
	if (!route)
		return -ENOENT;
	request->route_flags = route->flags;
	request->prefix_len = (__u32)route->key[1];
	if (route->flags != TRUSTIX_DATAPATH_ROUTE_FLAG_UNICAST)
		return 0;

	trustix_datapath_flow_key(flow_key, request->src_ipv4, request->dst_ipv4,
				  request->src_port, request->dst_port,
				  request->protocol);
	flow = trustix_datapath_find_slot(&trustix_datapath_flows, flow_key);
	session = trustix_datapath_session_for_route_locked(route, flow);
	if (!session)
		return -EHOSTUNREACH;
	request->flow_id = session->value[0];
	request->session_flags = session->flags;
	return 0;
}

static int
trustix_datapath_parse_ipv4_packet(const __u8 *packet, __u32 len,
				   struct trustix_datapath_ioc_classify *classify,
				   __u8 *ip_header_len, __u8 *l4_header_len)
{
	__u32 ihl;
	__u32 total_len;
	__u32 l4_len;
	__u32 l4_offset;
	__u16 fragment;
	__u8 protocol;

	if (!packet || !classify || !ip_header_len || !l4_header_len)
		return -EINVAL;
	if (len < 20)
		return -ENODATA;
	if ((packet[0] >> 4) != 4)
		return -EPROTONOSUPPORT;
	ihl = (__u32)(packet[0] & 0x0f) * 4U;
	if (ihl < 20 || ihl > len)
		return -EBADMSG;
	total_len = trustix_datapath_get_be16(packet + 2);
	if (total_len < ihl || total_len > len)
		return -EMSGSIZE;

	fragment = trustix_datapath_get_be16(packet + 6);

	protocol = packet[9];
	l4_offset = ihl;
	l4_len = total_len - ihl;
	memset(classify, 0, sizeof(*classify));
	classify->version = TRUSTIX_DATAPATH_IOC_VERSION;
	classify->src_ipv4 = trustix_datapath_get_be32(packet + 12);
	classify->dst_ipv4 = trustix_datapath_get_be32(packet + 16);
	classify->protocol = protocol;
	*ip_header_len = (__u8)ihl;
	*l4_header_len = 0;
	if (fragment & 0x1fffU)
		return 0;

	switch (protocol) {
	case 6:
		if (l4_len < 20)
			return -ENODATA;
		*l4_header_len = (packet[l4_offset + 12] >> 4) * 4;
		if (*l4_header_len < 20 || *l4_header_len > l4_len)
			return -EBADMSG;
		classify->src_port =
			trustix_datapath_get_be16(packet + l4_offset);
		classify->dst_port =
			trustix_datapath_get_be16(packet + l4_offset + 2);
		break;
	case 17:
		if (l4_len < 8)
			return -ENODATA;
		*l4_header_len = 8;
		classify->src_port =
			trustix_datapath_get_be16(packet + l4_offset);
		classify->dst_port =
			trustix_datapath_get_be16(packet + l4_offset + 2);
		break;
	case 1:
		if (l4_len < 8)
			return -ENODATA;
		*l4_header_len = 8;
		break;
	default:
		break;
	}

	return 0;
}

static void
trustix_datapath_account_packet_classify_locked(__u32 packet_len,
						struct trustix_datapath_ioc_classify *classify,
						int ret)
{
	if (ret == -ENOENT) {
		trustix_datapath_packet_route_misses++;
		return;
	}
	if (ret == -EHOSTUNREACH)
		trustix_datapath_packet_session_misses++;

	switch (classify->route_flags) {
	case TRUSTIX_DATAPATH_ROUTE_FLAG_UNICAST:
		trustix_datapath_packet_unicast_routes++;
		break;
	case TRUSTIX_DATAPATH_ROUTE_FLAG_LOCAL:
		trustix_datapath_packet_local_routes++;
		break;
	case TRUSTIX_DATAPATH_ROUTE_FLAG_BLACKHOLE:
		trustix_datapath_packet_blackhole_routes++;
		break;
	case TRUSTIX_DATAPATH_ROUTE_FLAG_REJECT:
		trustix_datapath_packet_reject_routes++;
		break;
	default:
		break;
	}

	trustix_datapath_packets_seen++;
	trustix_datapath_bytes_seen += packet_len;
}

static int
trustix_datapath_packet_classify_locked(struct trustix_datapath_ioc_packet_classify *request,
					const __u8 *packet)
{
	struct trustix_datapath_ioc_classify classify = {};
	__u8 ip_header_len = 0;
	__u8 l4_header_len = 0;
	int ret;

	if (!request || !packet)
		return -EINVAL;
	ret = trustix_datapath_parse_ipv4_packet(packet, request->packet_len,
						 &classify, &ip_header_len,
						 &l4_header_len);
	if (ret) {
		trustix_datapath_packet_parse_errors++;
		return ret;
	}

	ret = trustix_datapath_classify_locked(&classify);
	request->src_ipv4 = classify.src_ipv4;
	request->dst_ipv4 = classify.dst_ipv4;
	request->src_port = classify.src_port;
	request->dst_port = classify.dst_port;
	request->protocol = classify.protocol;
	request->ip_header_len = ip_header_len;
	request->l4_header_len = l4_header_len;
	request->route_flags = classify.route_flags;
	request->prefix_len = classify.prefix_len;
	request->flow_id = classify.flow_id;
	request->session_flags = classify.session_flags;
	trustix_datapath_account_packet_classify_locked(request->packet_len,
							&classify, ret);
	request->packets_seen = trustix_datapath_packets_seen;
	request->bytes_seen = trustix_datapath_bytes_seen;
	return ret;
}

static __u32 trustix_datapath_ipv4_checksum(const __u8 *header, __u32 len)
{
	__u32 sum = 0;
	__u32 i;

	for (i = 0; i + 1 < len; i += 2)
		sum += ((__u32)header[i] << 8) | (__u32)header[i + 1];
	if (len & 1)
		sum += (__u32)header[len - 1] << 8;
	while (sum >> 16)
		sum = (sum & 0xffffU) + (sum >> 16);
	return (~sum) & 0xffffU;
}

static void
trustix_datapath_build_outer_ipv4(__u8 *packet, __u32 total_len,
				  __u8 protocol, __u32 src_ipv4,
				  __u32 dst_ipv4)
{
	memset(packet, 0, 20);
	packet[0] = 0x45;
	trustix_datapath_put_be16(packet + 2, (__u16)total_len);
	packet[8] = 64;
	packet[9] = protocol;
	trustix_datapath_put_be32(packet + 12, src_ipv4);
	trustix_datapath_put_be32(packet + 16, dst_ipv4);
	trustix_datapath_put_be16(packet + 10,
				  (__u16)trustix_datapath_ipv4_checksum(packet,
									20));
}

static int
trustix_datapath_outer_build_locked(struct trustix_datapath_ioc_outer_build *request,
				    const __u8 *inner, __u8 *out)
{
	struct trustix_datapath_ioc_classify classify = {};
	struct trustix_datapath_state_slot *route;
	struct trustix_datapath_state_slot *flow;
	struct trustix_datapath_state_slot *session;
	struct trustix_datapath_state_slot *wire;
	__u8 ip_header_len = 0;
	__u8 l4_header_len = 0;
	__u64 flow_key[4];
	__u32 local_ipv4;
	__u32 remote_ipv4;
	__u16 local_port;
	__u16 remote_port;
	__u32 transport;
	__u8 outer_protocol;
	__u32 tixt_len;
	__u32 outer_header_len;
	__u32 written_len;
	__u32 inner_flow_hash;
	__u8 outer_tcp_port_shard;
	__u8 *tixt;
	int ret;

	if (!request || !inner || !out)
		return -EINVAL;
	if (!request->inner_len || request->inner_len > TRUSTIX_DATAPATH_TIXT_MAX_PAYLOAD)
		return -EMSGSIZE;
	ret = trustix_datapath_parse_ipv4_packet(inner, request->inner_len,
						 &classify, &ip_header_len,
						 &l4_header_len);
	if (ret)
		return ret;
	route = trustix_datapath_route_lookup_locked(classify.dst_ipv4);
	if (!route)
		return -ENOENT;
	request->route_flags = route->flags;
	request->prefix_len = (__u32)route->key[1];
	if (route->flags != TRUSTIX_DATAPATH_ROUTE_FLAG_UNICAST)
		return -EHOSTUNREACH;
	trustix_datapath_flow_key(flow_key, classify.src_ipv4, classify.dst_ipv4,
				  classify.src_port, classify.dst_port,
				  classify.protocol);
	flow = trustix_datapath_find_slot(&trustix_datapath_flows, flow_key);
	session = trustix_datapath_session_for_route_locked(route, flow);
	if (!session)
		return -EHOSTUNREACH;
	wire = trustix_datapath_session_wire_for_key_locked(session->key);
	if (!wire)
		return -ENOKEY;
	if (wire->value[0] != session->value[0])
		return -ESTALE;

	local_ipv4 = (__u32)wire->value[1];
	remote_ipv4 = (__u32)wire->value[2];
	local_port = (__u16)(wire->value[3] >> 16);
	remote_port = (__u16)wire->value[3];
	transport = (__u32)wire->value[4];
	if (!local_ipv4 || !remote_ipv4 || !local_port || !remote_port)
		return -EINVAL;

	switch (transport) {
	case TRUSTIX_DATAPATH_TRANSPORT_UDP:
		outer_protocol = IPPROTO_UDP;
		outer_header_len = 20 + 8;
		break;
	case TRUSTIX_DATAPATH_TRANSPORT_TIX_TCP:
		outer_protocol = IPPROTO_TCP;
		outer_header_len = 20 + 20;
		inner_flow_hash = trustix_datapath_inner_flow_hash(&classify);
		if (trustix_datapath_tix_tcp_port_sharding_allowed(
			    session, false)) {
			outer_tcp_port_shard =
				trustix_datapath_tix_tcp_port_shard_for_hash(
					inner_flow_hash);
			local_port = trustix_datapath_tix_tcp_port_for_shard(
				local_port, outer_tcp_port_shard);
		}
		break;
	default:
		return -EPROTONOSUPPORT;
	}

	tixt_len = TRUSTIX_DATAPATH_TIXT_HEADER_LEN + request->inner_len;
	written_len = outer_header_len + tixt_len;
	if (written_len > 0xffffU)
		return -EMSGSIZE;
	if (request->out_len < written_len)
		return -ENOSPC;
	if (wire->value[5] && written_len > wire->value[5])
		return -EMSGSIZE;

	trustix_datapath_build_outer_ipv4(out, written_len, outer_protocol,
					  local_ipv4, remote_ipv4);
	if (outer_protocol == IPPROTO_UDP) {
		trustix_datapath_put_be16(out + 20, local_port);
		trustix_datapath_put_be16(out + 22, remote_port);
		trustix_datapath_put_be16(out + 24, (__u16)(8 + tixt_len));
		tixt = out + 28;
	} else {
		trustix_datapath_put_be16(out + 20, local_port);
		trustix_datapath_put_be16(out + 22, remote_port);
		out[32] = 0x50;
		out[33] = 0x18;
		trustix_datapath_put_be16(out + 34, 65535);
		tixt = out + 40;
	}
	trustix_datapath_build_tixt(tixt, TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4,
				    session->value[0], wire->value[6],
				    request->sequence, request->inner_len, 0, 0);
	memcpy(tixt + TRUSTIX_DATAPATH_TIXT_HEADER_LEN, inner,
	       request->inner_len);

	request->written_len = written_len;
	request->flow_id = session->value[0];
	request->epoch = wire->value[6];
	request->session_flags = session->flags;
	request->local_ipv4 = local_ipv4;
	request->remote_ipv4 = remote_ipv4;
	request->local_port = local_port;
	request->remote_port = remote_port;
	request->outer_protocol = outer_protocol;
	request->tixt_len = tixt_len;
	return 0;
}

static int
trustix_datapath_outer_parse_locked(struct trustix_datapath_ioc_outer_parse *request,
				    const __u8 *outer, __u8 *out)
{
	struct trustix_datapath_ioc_classify classify = {};
	struct trustix_datapath_tixt_frame frame = {};
	struct trustix_datapath_state_slot *session;
	struct trustix_datapath_state_slot *wire;
	const __u8 *tixt;
	__u8 ip_header_len = 0;
	__u8 l4_header_len = 0;
	__u32 total_len;
	__u32 tixt_len;
	__u16 transport_len;
	bool reverse = false;
	int ret;

	if (!request || !outer || !out)
		return -EINVAL;
	if (request->outer_len < 20 ||
	    request->outer_len > TRUSTIX_DATAPATH_PACKET_MAX_LEN)
		return -EMSGSIZE;
	ret = trustix_datapath_parse_ipv4_packet(outer, request->outer_len,
						 &classify, &ip_header_len,
						 &l4_header_len);
	if (ret)
		return ret;
	if (ip_header_len != 20)
		return -EOPNOTSUPP;
	total_len = trustix_datapath_get_be16(outer + 2);
	if (total_len != request->outer_len)
		return -EMSGSIZE;
	switch (classify.protocol) {
	case IPPROTO_UDP:
		if (l4_header_len != 8)
			return -EBADMSG;
		transport_len = trustix_datapath_get_be16(outer + 24);
		if (transport_len < 8)
			return -EMSGSIZE;
		if ((__u32)transport_len != total_len - ip_header_len)
			return -EMSGSIZE;
		tixt = outer + 28;
		tixt_len = (__u32)transport_len - 8;
		break;
	case IPPROTO_TCP:
		if (l4_header_len != 20)
			return -EOPNOTSUPP;
		total_len = trustix_datapath_get_be16(outer + 2);
		tixt = outer + 40;
		tixt_len = total_len - 40;
		break;
	default:
		return -EPROTONOSUPPORT;
	}

	ret = trustix_datapath_parse_tixt(tixt, tixt_len, &frame);
	if (ret)
		return ret;
	if (!(frame.flags & TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4))
		return -EPROTONOSUPPORT;
	if (frame.wire_len != tixt_len)
		return -EMSGSIZE;
	if (frame.payload_len > request->out_len)
		return -ENOSPC;

	wire = trustix_datapath_session_wire_for_tuple_locked(
		frame.flow_id, classify.src_ipv4, classify.dst_ipv4,
		classify.src_port, classify.dst_port, classify.protocol,
		&reverse);
	if (!wire && classify.protocol == IPPROTO_UDP &&
	    frame.header_len == TRUSTIX_DATAPATH_TIXU_HEADER_LEN)
		wire = trustix_datapath_session_wire_for_tuple_any_flow_locked(
			classify.src_ipv4, classify.dst_ipv4, classify.src_port,
			classify.dst_port, classify.protocol, &reverse);
	if (!wire)
		return -ENOKEY;
	session = trustix_datapath_session_for_flow_id_locked(wire->value[0]);
	if (!session)
		return -EHOSTUNREACH;
	if (wire->value[6] && frame.epoch != wire->value[6])
		return -ESTALE;
	if (wire->key[0] != session->key[0] ||
	    wire->key[1] != session->key[1] ||
	    wire->key[2] != session->key[2] ||
	    wire->key[3] != session->key[3])
		return -ESTALE;

	memcpy(out, tixt + frame.header_len, frame.payload_len);
	request->written_len = frame.payload_len;
	request->flow_id = frame.flow_id;
	request->epoch = frame.epoch;
	request->sequence = frame.sequence;
	request->payload_len = frame.payload_len;
	request->tixt_flags = frame.flags;
	request->session_flags = session->flags;
	request->local_ipv4 = (__u32)wire->value[1];
	request->remote_ipv4 = (__u32)wire->value[2];
	request->local_port = (__u16)(wire->value[3] >> 16);
	request->remote_port = (__u16)wire->value[3];
	request->outer_protocol = classify.protocol;
	request->tixt_len = tixt_len;
	if (reverse)
		request->flags |= TRUSTIX_DATAPATH_OUTER_PARSE_FLAG_REVERSE;
	else
		request->flags &= ~TRUSTIX_DATAPATH_OUTER_PARSE_FLAG_REVERSE;
	return 0;
}

static int
trustix_datapath_tixt_encap_locked(struct trustix_datapath_ioc_tixt_encap *request,
				   const __u8 *inner, __u8 *out)
{
	struct trustix_datapath_ioc_classify classify = {};
	__u8 ip_header_len = 0;
	__u8 l4_header_len = 0;
	__u32 written_len;
	int ret;

	if (!request || !inner || !out)
		return -EINVAL;
	if (!request->inner_len || request->inner_len > TRUSTIX_DATAPATH_TIXT_MAX_PAYLOAD)
		return -EMSGSIZE;
	if (request->out_len < TRUSTIX_DATAPATH_TIXT_HEADER_LEN ||
	    request->out_len - TRUSTIX_DATAPATH_TIXT_HEADER_LEN < request->inner_len)
		return -ENOSPC;
	ret = trustix_datapath_parse_ipv4_packet(inner, request->inner_len,
						 &classify, &ip_header_len,
						 &l4_header_len);
	if (ret)
		return ret;
	ret = trustix_datapath_classify_locked(&classify);
	if (ret)
		return ret;
	written_len = TRUSTIX_DATAPATH_TIXT_HEADER_LEN + request->inner_len;
	trustix_datapath_build_tixt(out, TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4,
				    classify.flow_id, 0, request->sequence,
				    request->inner_len, 0, 0);
	memcpy(out + TRUSTIX_DATAPATH_TIXT_HEADER_LEN, inner,
	       request->inner_len);
	request->written_len = written_len;
	request->flow_id = classify.flow_id;
	request->epoch = 0;
	request->route_flags = classify.route_flags;
	request->prefix_len = classify.prefix_len;
	request->session_flags = classify.session_flags;
	return 0;
}

static int
trustix_datapath_tixt_decap_locked(struct trustix_datapath_ioc_tixt_decap *request,
				   const __u8 *wire, __u8 *out)
{
	struct trustix_datapath_tixt_frame frame = {};
	struct trustix_datapath_state_slot *session;
	int ret;

	if (!request || !wire || !out)
		return -EINVAL;
	ret = trustix_datapath_parse_tixt(wire, request->wire_len, &frame);
	if (ret)
		return ret;
	if (!(frame.flags & TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4))
		return -EPROTONOSUPPORT;
	if (frame.payload_len > request->out_len)
		return -ENOSPC;
	session = trustix_datapath_session_for_flow_id_locked(frame.flow_id);
	if (!session)
		return -EHOSTUNREACH;
	memcpy(out, wire + frame.header_len, frame.payload_len);
	request->written_len = frame.payload_len;
	request->flow_id = frame.flow_id;
	request->epoch = frame.epoch;
	request->sequence = frame.sequence;
	request->payload_len = frame.payload_len;
	request->tixt_flags = frame.flags;
	request->session_flags = session->flags;
	return 0;
}

static int
trustix_datapath_parse_skb_ipv4(struct sk_buff *skb,
				struct trustix_datapath_ioc_classify *classify,
				__u8 *ip_header_len,
				__u8 *l4_header_len)
{
	const struct iphdr *iph;
	__u32 ihl;
	__u32 total_len;
	__u32 l4_len;
	__u32 l4_offset;
	__u16 fragment;
	__u8 tcp_header_byte;

	if (!skb || !classify || !ip_header_len || !l4_header_len)
		return -EINVAL;
	if (!pskb_may_pull(skb, sizeof(*iph)))
		return -ENODATA;
	iph = ip_hdr(skb);
	if (!iph || iph->version != 4)
		return -EPROTONOSUPPORT;
	ihl = (__u32)iph->ihl * 4U;
	if (ihl < 20)
		return -EBADMSG;
	if (!pskb_may_pull(skb, ihl))
		return -ENODATA;
	iph = ip_hdr(skb);
	total_len = ntohs(iph->tot_len);
	if (total_len < ihl || total_len > skb->len)
		return -EMSGSIZE;
	fragment = ntohs(iph->frag_off);
	if (fragment & 0x1fffU)
		return -EOPNOTSUPP;

	memset(classify, 0, sizeof(*classify));
	classify->version = TRUSTIX_DATAPATH_IOC_VERSION;
	classify->src_ipv4 = ntohl(iph->saddr);
	classify->dst_ipv4 = ntohl(iph->daddr);
	classify->protocol = iph->protocol;
	*ip_header_len = (__u8)ihl;
	*l4_header_len = 0;
	l4_offset = ihl;
	l4_len = total_len - ihl;

	switch (iph->protocol) {
	case IPPROTO_TCP:
		if (l4_len < 20 || !pskb_may_pull(skb, l4_offset + 20))
			return -ENODATA;
		classify->src_port =
			ntohs(*(__be16 *)(skb_network_header(skb) + l4_offset));
		classify->dst_port = ntohs(*(__be16 *)(skb_network_header(skb) +
						       l4_offset + 2));
		tcp_header_byte = *(skb_network_header(skb) + l4_offset + 12);
		*l4_header_len = (tcp_header_byte >> 4) * 4;
		if (*l4_header_len < 20 || *l4_header_len > l4_len)
			return -EBADMSG;
		if (!pskb_may_pull(skb, l4_offset + *l4_header_len))
			return -ENODATA;
		break;
	case IPPROTO_UDP:
		if (l4_len < 8 || !pskb_may_pull(skb, l4_offset + 8))
			return -ENODATA;
		classify->src_port =
			ntohs(*(__be16 *)(skb_network_header(skb) + l4_offset));
		classify->dst_port = ntohs(*(__be16 *)(skb_network_header(skb) +
						       l4_offset + 2));
		*l4_header_len = 8;
		break;
	case IPPROTO_ICMP:
		if (l4_len < 8 || !pskb_may_pull(skb, l4_offset + 8))
			return -ENODATA;
		*l4_header_len = 8;
		break;
	default:
		break;
	}

	return 0;
}

static int
trustix_datapath_rx_crypto_plan_locked(
	const struct trustix_datapath_ioc_classify *outer,
	const struct trustix_datapath_tixt_frame *frame,
	struct trustix_datapath_rx_crypto_plan *plan)
{
	struct trustix_datapath_state_slot *session;
	struct trustix_datapath_state_slot *crypto;
	struct trustix_datapath_state_slot *wire;
	__u64 packed;
	bool reverse = false;

	if (!outer || !frame || !plan)
		return -EINVAL;
	memset(plan, 0, sizeof(*plan));
	if (!(READ_ONCE(trustix_datapath_features) &
	      TRUSTIX_DATAPATH_FEATURE_SECURE_TIX_TCP_FULL_DATAPATH) ||
	    !trustix_datapath_crypto_open_replay_batch)
		return -EOPNOTSUPP;
	if (outer->protocol != IPPROTO_TCP ||
	    frame->header_len != TRUSTIX_DATAPATH_TIXT_HEADER_LEN ||
	    (frame->flags &
	     ~TRUSTIX_DATAPATH_TIXT_FLAG_INNER_TCP_CHECKSUM_PARTIAL) !=
		    (TRUSTIX_DATAPATH_TIXT_FLAG_ENCRYPTED |
		     TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4) ||
	    frame->fragment_index || frame->fragment_count)
		return -EPROTONOSUPPORT;

	wire = trustix_datapath_session_wire_for_tuple_locked(
		frame->flow_id, outer->src_ipv4, outer->dst_ipv4,
		outer->src_port, outer->dst_port, outer->protocol, &reverse);
	if (!wire)
		return -ESTALE;
	session = trustix_datapath_session_for_flow_id_locked(wire->value[0]);
	if (!session)
		return -ESTALE;
	if ((__u32)wire->value[4] != TRUSTIX_DATAPATH_TRANSPORT_TIX_TCP ||
	    (__u32)session->value[1] != TRUSTIX_DATAPATH_TRANSPORT_TIX_TCP ||
	    (session->flags &
	     (TRUSTIX_DATAPATH_SESSION_FLAGS_ENCRYPTED |
	      TRUSTIX_DATAPATH_SESSION_FLAG_CRYPTO_KERNEL)) !=
		    (TRUSTIX_DATAPATH_SESSION_FLAGS_ENCRYPTED |
		     TRUSTIX_DATAPATH_SESSION_FLAG_CRYPTO_KERNEL))
		return -EPROTONOSUPPORT;
	if ((frame->flags &
	     TRUSTIX_DATAPATH_TIXT_FLAG_INNER_TCP_CHECKSUM_PARTIAL) &&
	    (!(session->flags &
	       TRUSTIX_DATAPATH_SESSION_FLAG_RECEIVE_SECURE_INNER_TCP_CHECKSUM_PARTIAL) ||
	     !(READ_ONCE(trustix_datapath_features) &
	       TRUSTIX_DATAPATH_FEATURE_SECURE_INNER_TCP_CHECKSUM_PARTIAL)))
		return -EPROTONOSUPPORT;
	if (wire->key[0] != session->key[0] ||
	    wire->key[1] != session->key[1] ||
	    wire->key[2] != session->key[2] ||
	    wire->key[3] != session->key[3] ||
	    (wire->value[6] && wire->value[6] != frame->epoch))
		return -ESTALE;

	crypto = trustix_datapath_find_slot(
		&trustix_datapath_session_crypto, session->key);
	if (!crypto ||
	    (crypto->flags & TRUSTIX_DATAPATH_SESSION_CRYPTO_FLAGS_READY) !=
		    TRUSTIX_DATAPATH_SESSION_CRYPTO_FLAGS_READY)
		return -ESTALE;
	if (!crypto->value[0] || crypto->value[0] != session->value[0] ||
	    crypto->value[0] != frame->flow_id ||
	    crypto->value[1] != frame->epoch || !crypto->runtime[1])
		return -ESTALE;

	plan->flow_id = frame->flow_id;
	plan->epoch = frame->epoch;
	plan->session_flags = session->flags;
	plan->receive_slot = (__u32)(crypto->value[2] >> 32);
	plan->suite = (__u16)crypto->value[3];
	plan->wire_format = (__u16)(crypto->value[3] >> 16);
	plan->replay_window = (__u32)(crypto->value[3] >> 32);
	plan->receive_generation = crypto->runtime[1];
	plan->replay_floor = crypto->value[7];
	if ((plan->suite !=
		     TRUSTIX_DATAPATH_SECURE_SUITE_AES_256_GCM_X25519 &&
	     plan->suite !=
		     TRUSTIX_DATAPATH_SECURE_SUITE_AES_128_GCM_X25519) ||
	    plan->wire_format != TRUSTIX_DATAPATH_SECURE_WIRE_FORMAT_V1 ||
	    !plan->replay_window ||
	    plan->replay_window > TRUSTIX_DATAPATH_SECURE_REPLAY_MAX)
		return -EPROTONOSUPPORT;

	packed = crypto->value[5] >> 32;
	trustix_datapath_unpack_bytes(packed, plan->receive_iv, 4);
	trustix_datapath_unpack_bytes(crypto->value[6],
				      plan->receive_iv + 4, 8);
	return 0;
}

static int
trustix_datapath_tx_secure_plan_locked(
	const struct trustix_datapath_state_slot *session,
	const struct trustix_datapath_state_slot *wire,
	struct trustix_datapath_tx_plan *plan)
{
	struct trustix_datapath_state_slot *crypto;
	__u64 packed;

	if (!session || !wire || !plan)
		return -EINVAL;
	if (!(READ_ONCE(trustix_datapath_features) &
	      TRUSTIX_DATAPATH_FEATURE_SECURE_TIX_TCP_FULL_DATAPATH) ||
	    !trustix_datapath_crypto_reserve_sequences ||
	    !trustix_datapath_crypto_seal_batch)
		return -EOPNOTSUPP;
	if ((__u32)wire->value[4] != TRUSTIX_DATAPATH_TRANSPORT_TIX_TCP ||
	    (session->flags &
	     (TRUSTIX_DATAPATH_SESSION_FLAG_SEND_ENCRYPTED |
	      TRUSTIX_DATAPATH_SESSION_FLAG_RECEIVE_ENCRYPTED)) !=
		    (TRUSTIX_DATAPATH_SESSION_FLAG_SEND_ENCRYPTED |
		     TRUSTIX_DATAPATH_SESSION_FLAG_RECEIVE_ENCRYPTED))
		return -EPROTONOSUPPORT;

	crypto = trustix_datapath_find_slot(
		&trustix_datapath_session_crypto, session->key);
	if (!crypto ||
	    (crypto->flags & TRUSTIX_DATAPATH_SESSION_CRYPTO_FLAGS_READY) !=
		    TRUSTIX_DATAPATH_SESSION_CRYPTO_FLAGS_READY)
		return -ENOKEY;
	if (!crypto->value[0] || crypto->value[0] != session->value[0] ||
	    (wire->value[6] && crypto->value[1] != wire->value[6]) ||
	    !crypto->runtime[0])
		return -ESTALE;

	plan->send_slot = (__u32)crypto->value[2];
	plan->suite = (__u16)crypto->value[3];
	plan->wire_format = (__u16)(crypto->value[3] >> 16);
	if ((plan->suite !=
		     TRUSTIX_DATAPATH_SECURE_SUITE_AES_256_GCM_X25519 &&
	     plan->suite !=
		     TRUSTIX_DATAPATH_SECURE_SUITE_AES_128_GCM_X25519) ||
	    plan->wire_format != TRUSTIX_DATAPATH_SECURE_WIRE_FORMAT_V1)
		return -EPROTONOSUPPORT;

	plan->epoch = crypto->value[1];
	plan->send_generation = crypto->runtime[0];
	trustix_datapath_unpack_bytes(crypto->value[4], plan->send_iv, 8);
	packed = crypto->value[5];
	trustix_datapath_unpack_bytes(packed, plan->send_iv + 8, 4);
	plan->secure = true;
	return 0;
}

static int
trustix_datapath_tx_plan_locked(struct trustix_datapath_ioc_classify *classify,
				struct trustix_datapath_tx_plan *plan)
{
	struct trustix_datapath_state_slot *route;
	struct trustix_datapath_state_slot *flow;
	struct trustix_datapath_state_slot *session;
	struct trustix_datapath_state_slot *wire;
	__u64 flow_key[4];
	__u32 transport;

	if (!classify || !plan)
		return -EINVAL;
	memset(plan, 0, sizeof(*plan));
	plan->outer_tcp_sequence_flow_slot = U32_MAX;
	plan->inner_flow_hash = trustix_datapath_inner_flow_hash(classify);

	route = trustix_datapath_route_lookup_locked(classify->dst_ipv4);
	if (!route)
		return -ENOENT;
	classify->route_flags = route->flags;
	classify->prefix_len = (__u32)route->key[1];
	if (route->flags != TRUSTIX_DATAPATH_ROUTE_FLAG_UNICAST)
		return -ENETUNREACH;

	trustix_datapath_flow_key(flow_key, classify->src_ipv4,
				  classify->dst_ipv4, classify->src_port,
				  classify->dst_port, classify->protocol);
	flow = trustix_datapath_find_slot(&trustix_datapath_flows, flow_key);
	session = trustix_datapath_session_for_route_with_wire_locked(route,
								     flow,
								     &wire);
	if (!session)
		return -EHOSTUNREACH;
	classify->flow_id = session->value[0];
	classify->session_flags = session->flags;

	transport = (__u32)wire->value[4];
	switch (transport) {
	case TRUSTIX_DATAPATH_TRANSPORT_UDP:
		plan->outer_protocol = IPPROTO_UDP;
		break;
	case TRUSTIX_DATAPATH_TRANSPORT_TIX_TCP:
		plan->outer_protocol = IPPROTO_TCP;
		break;
	default:
		return -EPROTONOSUPPORT;
	}

	plan->local_ipv4 = (__u32)wire->value[1];
	plan->remote_ipv4 = (__u32)wire->value[2];
	plan->local_port = (__u16)(wire->value[3] >> 16);
	plan->remote_port = (__u16)wire->value[3];
	plan->max_packet_size = (__u32)wire->value[5];
	plan->epoch = wire->value[6];
	plan->flow_id = session->value[0];
	plan->session_flags = session->flags;
	if (!plan->local_ipv4 || !plan->remote_ipv4 || !plan->local_port ||
	    !plan->remote_port)
		return -EINVAL;
	if (session->flags & TRUSTIX_DATAPATH_SESSION_FLAGS_ENCRYPTED) {
		int ret = trustix_datapath_tx_secure_plan_locked(session, wire,
							 plan);

		if (ret)
			return ret;
	}
	if (plan->outer_protocol == IPPROTO_TCP &&
	    trustix_datapath_tix_tcp_port_sharding_allowed(session, false)) {
		if (!trustix_datapath_session_slot_index_locked(
			    session, &plan->outer_tcp_sequence_flow_slot))
			return -ESTALE;
		plan->outer_tcp_port_shard =
			trustix_datapath_tix_tcp_port_shard_for_hash(
				plan->inner_flow_hash);
		plan->local_port = trustix_datapath_tix_tcp_port_for_shard(
			plan->local_port, plan->outer_tcp_port_shard);
		trustix_datapath_tx_plaintext_tix_tcp_port_shard_sets++;
	}
	return 0;
}

static void trustix_datapath_tx_plaintext_record_plan_error(
	int ret, const struct trustix_datapath_ioc_classify *classify)
{
	WRITE_ONCE(trustix_datapath_tx_plaintext_last_plan_ret, ret);
	if (classify) {
		WRITE_ONCE(trustix_datapath_tx_plaintext_last_src_ipv4,
			   classify->src_ipv4);
		WRITE_ONCE(trustix_datapath_tx_plaintext_last_dst_ipv4,
			   classify->dst_ipv4);
		WRITE_ONCE(trustix_datapath_tx_plaintext_last_src_port,
			   classify->src_port);
		WRITE_ONCE(trustix_datapath_tx_plaintext_last_dst_port,
			   classify->dst_port);
		WRITE_ONCE(trustix_datapath_tx_plaintext_last_protocol,
			   classify->protocol);
	}
	switch (ret) {
	case -ENOENT:
		trustix_datapath_tx_plaintext_no_routes++;
		break;
	case -ENETUNREACH:
		trustix_datapath_tx_plaintext_non_unicast_routes++;
		break;
	case -EHOSTUNREACH:
		trustix_datapath_tx_plaintext_no_sessions++;
		break;
	case -ENOKEY:
		trustix_datapath_tx_plaintext_no_wires++;
		break;
	case -ESTALE:
		trustix_datapath_tx_plaintext_stale_wires++;
		break;
	case -EPROTONOSUPPORT:
		trustix_datapath_tx_plaintext_unsupported_transports++;
		break;
	case -EINVAL:
		trustix_datapath_tx_plaintext_invalid_plans++;
		break;
	default:
		break;
	}
}

static void trustix_datapath_tx_plaintext_record_build_error(
	int ret, unsigned int stage, const struct sk_buff *skb,
	const struct trustix_datapath_ioc_classify *classify, __u32 inner_len)
{
	WRITE_ONCE(trustix_datapath_tx_plaintext_last_build_ret, ret);
	WRITE_ONCE(trustix_datapath_tx_plaintext_last_build_stage, stage);
	WRITE_ONCE(trustix_datapath_tx_plaintext_last_build_inner_len,
		   inner_len);
	if (skb) {
		WRITE_ONCE(trustix_datapath_tx_plaintext_last_build_skb_len,
			   skb->len);
		WRITE_ONCE(
			trustix_datapath_tx_plaintext_last_build_network_offset,
			skb_network_offset(skb));
	} else {
		WRITE_ONCE(trustix_datapath_tx_plaintext_last_build_skb_len, 0);
		WRITE_ONCE(
			trustix_datapath_tx_plaintext_last_build_network_offset,
			0);
	}
	WRITE_ONCE(trustix_datapath_tx_plaintext_last_build_protocol,
		   classify ? classify->protocol : 0);
	if (ret == -ESTALE) {
		trustix_datapath_tx_plaintext_stale_wires++;
		return;
	}
	trustix_datapath_tx_plaintext_build_errors++;
}

static __always_inline __u8
trustix_datapath_tx_plaintext_tixt_flags(bool inner_l4_checksum_valid,
					 bool inner_tcp_checksum_partial)
{
	__u8 flags = TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4;

	if (inner_tcp_checksum_partial)
		flags |= TRUSTIX_DATAPATH_TIXT_FLAG_INNER_TCP_CHECKSUM_PARTIAL;
	else if (inner_l4_checksum_valid)
		flags |= TRUSTIX_DATAPATH_TIXT_FLAG_INNER_L4_CHECKSUM_VALID;
	return flags;
}

static __always_inline bool
trustix_datapath_tx_plaintext_inner_tcp_checksum_partial_enabled(
	const struct trustix_datapath_tx_plan *plan)
{
	if (!plan ||
	    plan->secure ||
	    !(plan->session_flags &
	      TRUSTIX_DATAPATH_SESSION_FLAG_SEND_INNER_TCP_CHECKSUM_PARTIAL) ||
	    (plan->session_flags &
	     TRUSTIX_DATAPATH_SESSION_FLAG_SEND_ENCRYPTED))
		return false;
	return READ_ONCE(trustix_datapath_features) &
	       TRUSTIX_DATAPATH_FEATURE_INNER_TCP_CHECKSUM_PARTIAL;
}

static __always_inline bool
trustix_datapath_tx_secure_inner_tcp_checksum_partial_enabled(
	const struct trustix_datapath_tx_plan *plan)
{
	if (!plan || !plan->secure ||
	    !(plan->session_flags &
	      TRUSTIX_DATAPATH_SESSION_FLAG_SEND_ENCRYPTED) ||
	    !(plan->session_flags &
	      TRUSTIX_DATAPATH_SESSION_FLAG_SEND_SECURE_INNER_TCP_CHECKSUM_PARTIAL))
		return false;
	return READ_ONCE(trustix_datapath_features) &
	       TRUSTIX_DATAPATH_FEATURE_SECURE_INNER_TCP_CHECKSUM_PARTIAL;
}

static bool trustix_datapath_tx_plaintext_prepare_inner_tcp_checksum_partial(
	__u8 *packet, __u32 len)
{
	struct tcphdr *tcph;
	struct iphdr *iph;
	__u32 ip_header_len;
	__u32 tcp_header_len;
	__u32 total_len;
	__u32 tcp_len;

	if (!packet || len < sizeof(*iph) + sizeof(*tcph))
		return false;
	iph = (struct iphdr *)packet;
	if (iph->version != 4 || iph->ihl < 5 ||
	    iph->protocol != IPPROTO_TCP ||
	    (iph->frag_off & htons(0x3fff)))
		return false;
	ip_header_len = iph->ihl * 4;
	if (ip_header_len < sizeof(*iph) ||
	    len < ip_header_len + sizeof(*tcph))
		return false;
	total_len = ntohs(iph->tot_len);
	if (total_len != len || total_len < ip_header_len + sizeof(*tcph))
		return false;
	tcph = (struct tcphdr *)(packet + ip_header_len);
	tcp_header_len = tcph->doff * 4;
	if (tcp_header_len < sizeof(*tcph) ||
	    total_len < ip_header_len + tcp_header_len)
		return false;
	tcp_len = total_len - ip_header_len;
	trustix_datapath_rx_worker_fix_ipv4_header_checksum(iph,
						   ip_header_len);
	tcph->check = ~csum_tcpudp_magic(iph->saddr, iph->daddr, tcp_len,
					 IPPROTO_TCP, 0);
	return true;
}

static int trustix_datapath_secure_validate_inner_tcp_checksum(
	const __u8 *packet, __u32 len, bool partial)
{
	const struct tcphdr *tcph;
	const struct iphdr *iph;
	__sum16 expected;
	__u32 ip_header_len;
	__u32 tcp_header_len;
	__u32 total_len;
	__u32 tcp_len;

	if (!packet || len < sizeof(*iph))
		return -EBADMSG;
	iph = (const struct iphdr *)packet;
	if (iph->version != 4 || iph->ihl < 5 ||
	    (iph->frag_off & htons(0x3fff)))
		return -EBADMSG;
	ip_header_len = iph->ihl * 4;
	if (ip_header_len < sizeof(*iph) || len < ip_header_len)
		return -EBADMSG;
	total_len = ntohs(iph->tot_len);
	if (total_len != len || total_len < ip_header_len)
		return -EBADMSG;
	if (iph->protocol != IPPROTO_TCP)
		return partial ? -EBADMSG : 0;
	if (total_len < ip_header_len + sizeof(*tcph))
		return -EBADMSG;
	tcph = (const struct tcphdr *)(packet + ip_header_len);
	tcp_header_len = tcph->doff * 4;
	if (tcp_header_len < sizeof(*tcph) ||
	    total_len < ip_header_len + tcp_header_len)
		return -EBADMSG;
	tcp_len = total_len - ip_header_len;
	if (partial) {
		expected = ~csum_tcpudp_magic(iph->saddr, iph->daddr, tcp_len,
					       IPPROTO_TCP, 0);
		return tcph->check == expected ? 0 : -EBADMSG;
	}
	return trustix_datapath_rx_worker_l4_checksum(
		(struct iphdr *)iph, (void *)tcph, tcp_len, IPPROTO_TCP) ?
		       -EBADMSG : 0;
}

static bool
trustix_datapath_tx_plaintext_fix_inner_l4_checksum(__u8 *packet, __u32 len)
{
	struct udphdr *udph;
	struct tcphdr *tcph;
	struct iphdr *iph;
	__u32 ip_header_len;
	__u32 total_len;
	__u32 l4_len;

	if (!packet || len < sizeof(*iph))
		return false;
	iph = (struct iphdr *)packet;
	if (iph->version != 4 || iph->ihl < 5 ||
	    (iph->frag_off & htons(0x3fff)))
		return false;
	ip_header_len = iph->ihl * 4;
	if (ip_header_len < sizeof(*iph) || len < ip_header_len)
		return false;
	total_len = ntohs(iph->tot_len);
	if (total_len < ip_header_len || total_len > len)
		return false;
	trustix_datapath_rx_worker_fix_ipv4_header_checksum(iph,
							   ip_header_len);
	l4_len = total_len - ip_header_len;
	switch (iph->protocol) {
	case IPPROTO_TCP:
		if (l4_len < sizeof(*tcph))
			return false;
		tcph = (struct tcphdr *)(packet + ip_header_len);
		if (tcph->doff < 5 || l4_len < (__u32)tcph->doff * 4)
			return false;
		tcph->check = 0;
		tcph->check = trustix_datapath_rx_worker_l4_checksum(
			iph, tcph, l4_len, IPPROTO_TCP);
		return true;
	case IPPROTO_UDP:
		if (l4_len < sizeof(*udph))
			return false;
		udph = (struct udphdr *)(packet + ip_header_len);
		if (ntohs(udph->len) < sizeof(*udph) ||
		    ntohs(udph->len) > l4_len)
			return false;
		udph->check = 0;
		udph->check = trustix_datapath_rx_worker_l4_checksum(
			iph, udph, ntohs(udph->len), IPPROTO_UDP);
		if (!udph->check)
			udph->check = CSUM_MANGLED_0;
		return true;
	default:
		return false;
	}
}

static __u32 trustix_datapath_tx_outer_tcp_next_seq(
	const struct trustix_datapath_tx_plan *plan, __u32 payload_len)
{
	atomic64_t *sequence = &trustix_datapath_outer_tcp_sequence;
	atomic64_t *shard_sequences;
	__u64 end;
	__u32 step = payload_len ?: 1;
	__u32 flow_slots;
	__u32 sequence_slot;

	shard_sequences = READ_ONCE(
		trustix_datapath_outer_tcp_shard_sequences);
	flow_slots = READ_ONCE(
		trustix_datapath_outer_tcp_sequence_flow_slots);
	if (trustix_datapath_tx_plan_tix_tcp_port_sharding_active(plan) &&
	    shard_sequences && flow_slots &&
	    plan->outer_tcp_sequence_flow_slot < flow_slots) {
		sequence_slot =
			plan->outer_tcp_sequence_flow_slot *
				TRUSTIX_DATAPATH_TIX_TCP_PORT_SHARDS +
			plan->outer_tcp_port_shard;
		sequence = &shard_sequences[sequence_slot];
		trustix_datapath_tx_plaintext_tix_tcp_shard_sequence_hits++;
	} else {
		trustix_datapath_tx_plaintext_tix_tcp_shard_sequence_fallbacks++;
	}

	end = atomic64_add_return(step, sequence);
	return (__u32)(end - step);
}

static spinlock_t *trustix_datapath_tx_outer_tcp_order_lock(
	const struct trustix_datapath_tx_plan *plan)
{
	__u32 hash;

	if (!plan)
		return &trustix_datapath_outer_tcp_order_locks[0];
	hash = plan->local_ipv4 ^
	       ((plan->remote_ipv4 << 7) | (plan->remote_ipv4 >> 25)) ^
	       ((__u32)plan->local_port << 16) ^ plan->remote_port ^
	       ((__u32)plan->outer_tcp_port_shard << 24);
	hash ^= hash >> 16;
	hash *= 0x7feb352dU;
	hash ^= hash >> 15;
	return &trustix_datapath_outer_tcp_order_locks[
		hash & (TRUSTIX_DATAPATH_OUTER_TCP_ORDER_LOCKS - 1U)];
}

static int trustix_datapath_tx_assign_outer_tcp_sequence(
	struct sk_buff *skb, const struct trustix_datapath_tx_plan *plan)
{
	__wsum sum;
	struct tcphdr *tcph;
	struct iphdr *iph;
	__u32 network_offset;
	__u32 ip_header_len;
	__u32 tcp_header_len;
	__u32 total_len;
	__u32 payload_len;

	if (!skb || !plan || plan->outer_protocol != IPPROTO_TCP)
		return -EINVAL;
	network_offset = skb_network_offset(skb);
	if (network_offset > skb->len ||
	    !pskb_may_pull(skb, network_offset + sizeof(*iph)))
		return -EMSGSIZE;
	iph = (struct iphdr *)skb_network_header(skb);
	if (!iph || iph->version != 4 || iph->ihl < 5 ||
	    iph->protocol != IPPROTO_TCP)
		return -EPROTONOSUPPORT;
	ip_header_len = iph->ihl * 4;
	if (ip_header_len < sizeof(*iph) ||
	    !pskb_may_pull(skb, network_offset + ip_header_len +
				  sizeof(*tcph)))
		return -EMSGSIZE;
	iph = (struct iphdr *)skb_network_header(skb);
	tcph = (struct tcphdr *)((__u8 *)iph + ip_header_len);
	tcp_header_len = tcph->doff * 4;
	total_len = ntohs(iph->tot_len);
	if (tcp_header_len < sizeof(*tcph) ||
	    total_len <= ip_header_len + tcp_header_len ||
	    total_len > skb->len - network_offset)
		return -EMSGSIZE;
	payload_len = total_len - ip_header_len - tcp_header_len;
	tcph->seq = htonl(
		trustix_datapath_tx_outer_tcp_next_seq(plan, payload_len));
	if (skb->ip_summed != CHECKSUM_PARTIAL) {
		tcph->check = 0;
		sum = skb_checksum(skb, network_offset + ip_header_len,
				   total_len - ip_header_len, 0);
		tcph->check = csum_tcpudp_magic(
			iph->saddr, iph->daddr, total_len - ip_header_len,
			IPPROTO_TCP, sum);
		skb->ip_summed = CHECKSUM_NONE;
	}
	return 0;
}

static __always_inline unsigned int
trustix_datapath_tx_plaintext_dst_mac_cache_set(
	const struct net_device *target_dev,
	const struct trustix_datapath_tx_plan *plan)
{
	__u32 hash = (__u32)target_dev->ifindex;

	hash = (hash * 16777619U) ^ plan->local_ipv4;
	hash = (hash * 16777619U) ^ plan->remote_ipv4;
	hash = (hash * 16777619U) ^
	       (((__u32)plan->local_port << 16) | plan->remote_port);
	hash = (hash * 16777619U) ^ plan->outer_protocol;
	hash ^= hash >> 16;
	hash *= 0x7feb352dU;
	hash ^= hash >> 15;
	hash *= 0x846ca68bU;
	hash ^= hash >> 16;
	return hash & (TRUSTIX_DATAPATH_TX_PLAINTEXT_MAC_CACHE_SETS - 1);
}

static bool trustix_datapath_tx_plaintext_mac_cache_lookup(
	const struct trustix_datapath_tx_plaintext_mac_cache *cache,
	const struct net_device *target_dev,
	const struct trustix_datapath_tx_plan *plan, __u8 *addr)
{
	unsigned int set;
	unsigned int start;
	unsigned int i;

	if (!cache || !target_dev || !plan || !addr)
		return false;
	set = trustix_datapath_tx_plaintext_dst_mac_cache_set(target_dev,
							    plan);
	start = set * TRUSTIX_DATAPATH_TX_PLAINTEXT_MAC_CACHE_WAYS;
	for (i = 0; i < TRUSTIX_DATAPATH_TX_PLAINTEXT_MAC_CACHE_WAYS; i++) {
		const struct trustix_datapath_tx_plaintext_mac_cache_entry *entry =
			&cache->entries[start + i];

		if (!entry->valid || time_after_eq(jiffies, entry->expires) ||
		    entry->ifindex != target_dev->ifindex ||
		    entry->local_ipv4 != htonl(plan->local_ipv4) ||
		    entry->remote_ipv4 != htonl(plan->remote_ipv4) ||
		    entry->local_port != htons(plan->local_port) ||
		    entry->remote_port != htons(plan->remote_port) ||
		    entry->protocol != plan->outer_protocol)
			continue;
		trustix_datapath_rx_worker_u64_to_mac(entry->addr64, addr);
		return true;
	}
	return false;
}

static void trustix_datapath_tx_plaintext_mac_cache_store(
	struct trustix_datapath_tx_plaintext_mac_cache *cache,
	const struct net_device *target_dev,
	const struct trustix_datapath_tx_plan *plan, const __u8 *addr)
{
	struct trustix_datapath_tx_plaintext_mac_cache_entry *entry = NULL;
	struct trustix_datapath_tx_plaintext_mac_cache_entry *empty = NULL;
	unsigned int set;
	unsigned int start;
	unsigned int i;

	if (!cache || !target_dev || !plan || !addr)
		return;
	set = trustix_datapath_tx_plaintext_dst_mac_cache_set(target_dev,
							    plan);
	start = set * TRUSTIX_DATAPATH_TX_PLAINTEXT_MAC_CACHE_WAYS;
	for (i = 0; i < TRUSTIX_DATAPATH_TX_PLAINTEXT_MAC_CACHE_WAYS; i++) {
		struct trustix_datapath_tx_plaintext_mac_cache_entry *candidate =
			&cache->entries[start + i];

		if (candidate->valid &&
		    candidate->ifindex == target_dev->ifindex &&
		    candidate->local_ipv4 == htonl(plan->local_ipv4) &&
		    candidate->remote_ipv4 == htonl(plan->remote_ipv4) &&
		    candidate->local_port == htons(plan->local_port) &&
		    candidate->remote_port == htons(plan->remote_port) &&
		    candidate->protocol == plan->outer_protocol) {
			entry = candidate;
			break;
		}
		if ((!candidate->valid ||
		     time_after_eq(jiffies, candidate->expires)) &&
		    !empty)
			empty = candidate;
	}
	if (!entry)
		entry = empty;
	if (!entry) {
		i = cache->next[set] %
		    TRUSTIX_DATAPATH_TX_PLAINTEXT_MAC_CACHE_WAYS;
		entry = &cache->entries[start + i];
		cache->next[set] =
			(i + 1) % TRUSTIX_DATAPATH_TX_PLAINTEXT_MAC_CACHE_WAYS;
	}
	entry->ifindex = target_dev->ifindex;
	entry->local_ipv4 = htonl(plan->local_ipv4);
	entry->remote_ipv4 = htonl(plan->remote_ipv4);
	entry->local_port = htons(plan->local_port);
	entry->remote_port = htons(plan->remote_port);
	entry->protocol = (__u8)plan->outer_protocol;
	entry->addr64 = trustix_datapath_rx_worker_mac_to_u64(addr);
	entry->expires = jiffies + TRUSTIX_DATAPATH_MAC_CACHE_TTL;
	entry->valid = true;
}

static bool trustix_datapath_tx_plaintext_dst_mac_cache_lookup(
	const struct net_device *target_dev,
	const struct trustix_datapath_tx_plan *plan, __u8 *addr)
{
	unsigned int seq;
	bool cached;

	if (!target_dev || !plan || !addr ||
	    !READ_ONCE(trustix_datapath_tx_plaintext_direct_xmit_dst_mac_cache))
		return false;
	do {
		seq = read_seqbegin(
			&trustix_datapath_tx_plaintext_seq_mac_cache_lock);
		cached = trustix_datapath_tx_plaintext_mac_cache_lookup(
			&trustix_datapath_tx_plaintext_seq_mac_cache, target_dev,
			plan, addr);
	} while (read_seqretry(
		&trustix_datapath_tx_plaintext_seq_mac_cache_lock, seq));
	if (!cached) {
		trustix_datapath_tx_plaintext_direct_xmit_dst_mac_cache_misses++;
		return false;
	}
	trustix_datapath_tx_plaintext_direct_xmit_dst_mac_cache_hits++;
	return true;
}

static void trustix_datapath_tx_plaintext_dst_mac_cache_store(
	const struct net_device *target_dev,
	const struct trustix_datapath_tx_plan *plan, const __u8 *addr)
{
	unsigned long flags;

	if (!target_dev || !plan || !addr ||
	    !READ_ONCE(trustix_datapath_tx_plaintext_direct_xmit_dst_mac_cache))
		return;
	write_seqlock_irqsave(
		&trustix_datapath_tx_plaintext_seq_mac_cache_lock, flags);
	trustix_datapath_tx_plaintext_mac_cache_store(
		&trustix_datapath_tx_plaintext_seq_mac_cache, target_dev, plan,
		addr);
	write_sequnlock_irqrestore(
		&trustix_datapath_tx_plaintext_seq_mac_cache_lock, flags);
}

static unsigned int trustix_datapath_tx_plaintext_mac_cache_invalidate(
	struct trustix_datapath_tx_plaintext_mac_cache *cache, int ifindex)
{
	unsigned int i;
	unsigned int invalidated = 0;

	if (!cache)
		return 0;
	if (ifindex <= 0) {
		for (i = 0; i < ARRAY_SIZE(cache->entries); i++)
			invalidated += cache->entries[i].valid;
		memset(cache, 0, sizeof(*cache));
		return invalidated;
	}
	for (i = 0; i < ARRAY_SIZE(cache->entries); i++) {
		struct trustix_datapath_tx_plaintext_mac_cache_entry *entry =
			&cache->entries[i];

		if (!entry->valid || entry->ifindex != ifindex)
			continue;
		entry->valid = false;
		invalidated++;
	}
	return invalidated;
}

static void trustix_datapath_tx_plaintext_dst_mac_cache_invalidate(void)
{
	unsigned long flags;

	write_seqlock_irqsave(
		&trustix_datapath_tx_plaintext_seq_mac_cache_lock, flags);
	trustix_datapath_tx_plaintext_mac_cache_invalidate(
		&trustix_datapath_tx_plaintext_seq_mac_cache, 0);
	write_sequnlock_irqrestore(
		&trustix_datapath_tx_plaintext_seq_mac_cache_lock, flags);
}

static unsigned int
trustix_datapath_tx_plaintext_dst_mac_cache_invalidate_ifindex(int ifindex)
{
	unsigned long flags;
	unsigned int invalidated;

	write_seqlock_irqsave(
		&trustix_datapath_tx_plaintext_seq_mac_cache_lock, flags);
	invalidated = trustix_datapath_tx_plaintext_mac_cache_invalidate(
		&trustix_datapath_tx_plaintext_seq_mac_cache, ifindex);
	write_sequnlock_irqrestore(
		&trustix_datapath_tx_plaintext_seq_mac_cache_lock, flags);
	return invalidated;
}

static int
trustix_datapath_tx_build_outer_skb(struct sk_buff *inner_skb,
				    const struct trustix_datapath_tx_plan *plan,
				    __u32 inner_len, struct sk_buff **out_skb)
{
	struct trustix_aead_direct_batch_op seal_op = {};
	struct sk_buff *skb;
	struct tcphdr *tcph;
	struct iphdr *iph;
	__u8 *packet;
	__u8 *tixt;
	__u8 *inner_packet;
	__u32 outer_header_len;
	__u32 tixt_len;
	__u32 outer_len;
	__u32 tcp_len;
	__u64 sequence;
	bool inner_l4_checksum_valid = false;
	bool inner_tcp_checksum_partial = false;
	bool inner_tcp_checksum_partial_requested;
	int ret;

	if (!inner_skb || !plan || !out_skb)
		return -EINVAL;
	*out_skb = NULL;
	if (!inner_len || inner_len > TRUSTIX_DATAPATH_TIXT_MAX_PAYLOAD)
		return -EMSGSIZE;
	if (plan->secure && plan->outer_protocol != IPPROTO_TCP)
		return -EPROTONOSUPPORT;
	inner_tcp_checksum_partial_requested = plan->secure ?
		trustix_datapath_tx_secure_inner_tcp_checksum_partial_enabled(
			plan) :
		trustix_datapath_tx_plaintext_inner_tcp_checksum_partial_enabled(
			plan);

	switch (plan->outer_protocol) {
	case IPPROTO_UDP:
		outer_header_len = 20 + 8;
		break;
	case IPPROTO_TCP:
		outer_header_len = 20 + 20;
		break;
	default:
		return -EPROTONOSUPPORT;
	}
	if (check_add_overflow((__u32)TRUSTIX_DATAPATH_TIXT_HEADER_LEN,
			       inner_len, &tixt_len) ||
	    (plan->secure &&
	     check_add_overflow(tixt_len,
				(__u32)TRUSTIX_DATAPATH_SECURE_OVERHEAD,
				&tixt_len)))
		return -EOVERFLOW;
	outer_len = outer_header_len + tixt_len;
	if (outer_len > 0xffffU)
		return -EMSGSIZE;
	if (plan->max_packet_size && outer_len > plan->max_packet_size)
		return -EMSGSIZE;

	skb = alloc_skb(LL_MAX_HEADER + outer_len, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;
	skb_reserve(skb, LL_MAX_HEADER);
	packet = skb_put(skb, outer_len);
	memset(packet, 0, outer_header_len);

	trustix_datapath_build_outer_ipv4(packet, outer_len,
					  plan->outer_protocol,
					  plan->local_ipv4,
					  plan->remote_ipv4);
	if (plan->outer_protocol == IPPROTO_UDP) {
		trustix_datapath_put_be16(packet + 20, plan->local_port);
		trustix_datapath_put_be16(packet + 22, plan->remote_port);
		trustix_datapath_put_be16(packet + 24, (__u16)(8 + tixt_len));
		tixt = packet + 28;
	} else {
		trustix_datapath_put_be16(packet + 20, plan->local_port);
		trustix_datapath_put_be16(packet + 22, plan->remote_port);
		trustix_datapath_put_be32(packet + 24, 0);
		packet[32] = 0x50;
		packet[33] = 0x18;
		trustix_datapath_put_be16(packet + 34, 65535);
		tixt = packet + 40;
	}

	if (plan->secure) {
		ret = trustix_datapath_secure_tx_reserve(plan, 1, &sequence);
		if (ret)
			goto error;
		trustix_datapath_build_tixt_header(
			tixt,
			TRUSTIX_DATAPATH_TIXT_FLAG_ENCRYPTED |
				TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4,
			plan->flow_id, plan->epoch, sequence,
			inner_len + TRUSTIX_DATAPATH_SECURE_OVERHEAD, 0, 0);
		trustix_datapath_secure_write_header(
			tixt + TRUSTIX_DATAPATH_TIXT_HEADER_LEN, plan->suite,
			plan->epoch, sequence);
		inner_packet = tixt + TRUSTIX_DATAPATH_TIXT_HEADER_LEN +
			       TRUSTIX_DATAPATH_SECURE_HEADER_LEN;
	} else {
		sequence = (__u64)atomic64_inc_return(
			&trustix_datapath_tx_sequence);
		inner_packet = tixt + TRUSTIX_DATAPATH_TIXT_HEADER_LEN;
	}
	ret = skb_copy_bits(inner_skb, skb_network_offset(inner_skb),
			    inner_packet, inner_len);
	if (ret)
		goto error;
	if (plan->secure) {
		if (inner_tcp_checksum_partial_requested)
			inner_tcp_checksum_partial =
				trustix_datapath_tx_plaintext_prepare_inner_tcp_checksum_partial(
					inner_packet, inner_len);
		if (inner_tcp_checksum_partial_requested &&
		    !inner_tcp_checksum_partial)
			trustix_datapath_secure_tx_inner_tcp_checksum_partial_fallbacks++;
		if (inner_tcp_checksum_partial)
			tixt[5] |=
				TRUSTIX_DATAPATH_TIXT_FLAG_INNER_TCP_CHECKSUM_PARTIAL;
		else
			inner_l4_checksum_valid =
				trustix_datapath_tx_plaintext_fix_inner_l4_checksum(
					inner_packet, inner_len);
		trustix_datapath_secure_prepare_nonce(
			seal_op.nonce, plan->send_iv, sequence);
		seal_op.src = inner_packet;
		seal_op.dst = inner_packet;
		seal_op.plain_len = inner_len;
		ret = trustix_datapath_secure_tx_seal(plan, &seal_op, 1);
		if (ret)
			goto error;
		if (inner_tcp_checksum_partial)
			trustix_datapath_secure_tx_inner_tcp_checksum_partial++;
		goto finish_outer;
	}
	if (inner_tcp_checksum_partial_requested)
		inner_tcp_checksum_partial =
			trustix_datapath_tx_plaintext_prepare_inner_tcp_checksum_partial(
				tixt + TRUSTIX_DATAPATH_TIXT_HEADER_LEN,
				inner_len);
	if (inner_tcp_checksum_partial_requested &&
	    !inner_tcp_checksum_partial)
		trustix_datapath_tx_plaintext_inner_tcp_checksum_partial_fallbacks++;
	if (!inner_tcp_checksum_partial &&
	    !READ_ONCE(trustix_datapath_tx_plaintext_skip_inner_tcp_checksum))
		inner_l4_checksum_valid =
			trustix_datapath_tx_plaintext_fix_inner_l4_checksum(
				tixt + TRUSTIX_DATAPATH_TIXT_HEADER_LEN,
				inner_len);
	trustix_datapath_build_tixt_header(
		tixt,
		trustix_datapath_tx_plaintext_tixt_flags(
			inner_l4_checksum_valid,
			inner_tcp_checksum_partial),
		plan->flow_id, plan->epoch, sequence, inner_len, 0, 0);
	if (inner_tcp_checksum_partial)
		trustix_datapath_tx_plaintext_inner_tcp_checksum_partial++;

finish_outer:
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, 20);
	skb->protocol = htons(ETH_P_IP);
	if (plan->outer_protocol == IPPROTO_TCP) {
		iph = (struct iphdr *)skb_network_header(skb);
		tcph = (struct tcphdr *)skb_transport_header(skb);
		tcp_len = outer_len - 20;
		tcph->check = 0;
		tcph->check = trustix_datapath_rx_worker_l4_checksum(
			iph, tcph, tcp_len, IPPROTO_TCP);
	}
	skb->ip_summed = CHECKSUM_NONE;
	skb->pkt_type = PACKET_OUTGOING;
	*out_skb = skb;
	return 0;

error:
	if (plan->secure && ret != -ESTALE)
		trustix_datapath_secure_tx_errors++;
	kfree_skb(skb);
	return ret;
}

static int trustix_datapath_tx_validate_outer_skb_mtu(
	struct sk_buff *skb, const struct net_device *target_dev)
{
	const struct skb_shared_info *shinfo;
	const struct tcphdr *tcph;
	const struct iphdr *iph;
	__u32 network_offset;
	__u32 ip_header_len;
	__u32 tcp_header_len;
	__u32 segment_len;
	__u32 mtu;

	if (!skb || !target_dev)
		return -EINVAL;
	mtu = READ_ONCE(target_dev->mtu);
	if (!mtu)
		return 0;
	if (!skb_is_gso(skb))
		return skb->len <= mtu ? 0 : -EMSGSIZE;

	network_offset = skb_network_offset(skb);
	if (network_offset > skb->len ||
	    !pskb_may_pull(skb, network_offset + sizeof(*iph)))
		return -EINVAL;
	iph = (const struct iphdr *)skb_network_header(skb);
	if (!iph || iph->version != 4 || iph->ihl < 5 ||
	    iph->protocol != IPPROTO_TCP)
		return -EPROTONOSUPPORT;
	ip_header_len = iph->ihl * 4;
	if (ip_header_len < sizeof(*iph) ||
	    !pskb_may_pull(skb, network_offset + ip_header_len +
				  sizeof(*tcph)))
		return -EINVAL;
	iph = (const struct iphdr *)skb_network_header(skb);
	tcph = (const struct tcphdr *)((const __u8 *)iph + ip_header_len);
	tcp_header_len = tcph->doff * 4;
	if (tcp_header_len < sizeof(*tcph) ||
	    network_offset + ip_header_len + tcp_header_len > skb->len)
		return -EINVAL;
	shinfo = skb_shinfo(skb);
	if (!shinfo->gso_size ||
	    check_add_overflow(ip_header_len, tcp_header_len, &segment_len) ||
	    check_add_overflow(segment_len, (__u32)shinfo->gso_size,
			       &segment_len))
		return -EINVAL;
	return segment_len <= mtu ? 0 : -EMSGSIZE;
}

static int
trustix_datapath_tx_send_outer_skb_direct(struct sk_buff *skb,
					  struct net_device *target_dev,
					  const struct trustix_datapath_tx_plan *plan)
{
	spinlock_t *order_lock = NULL;
	struct neighbour *neigh = NULL;
	struct ethhdr *eth;
	struct flowi4 fl4 = {};
	struct rtable *rt;
	struct net *net;
	__be32 nexthop;
	__u8 daddr[ETH_ALEN];
	int ret;

	if (!skb || !target_dev || !plan)
		return -EINVAL;
	ret = trustix_datapath_tx_validate_outer_skb_mtu(skb, target_dev);
	if (ret)
		return ret;
	if (!READ_ONCE(trustix_datapath_tx_plaintext_direct_xmit))
		return -EOPNOTSUPP;
	if (target_dev->type != ARPHRD_ETHER ||
	    !is_valid_ether_addr(target_dev->dev_addr))
		return -EOPNOTSUPP;
	if (!trustix_datapath_rx_worker_dev_ready(target_dev))
		return -ENETDOWN;
	if (skb_headroom(skb) < ETH_HLEN || skb_header_cloned(skb)) {
		ret = skb_cow_head(skb, ETH_HLEN);
		if (ret)
			return ret;
	}

	if (!trustix_datapath_tx_plaintext_dst_mac_cache_lookup(
		    target_dev, plan, daddr)) {
		net = dev_net(target_dev);
		fl4.flowi4_oif = target_dev->ifindex;
		fl4.flowi4_proto = plan->outer_protocol;
		fl4.saddr = htonl(plan->local_ipv4);
		fl4.daddr = htonl(plan->remote_ipv4);
		fl4.fl4_sport = htons(plan->local_port);
		fl4.fl4_dport = htons(plan->remote_port);
		rt = ip_route_output_key(net, &fl4);
		if (IS_ERR(rt))
			return PTR_ERR(rt);
		if (rt->dst.dev != target_dev) {
			ip_rt_put(rt);
			return -EOPNOTSUPP;
		}
		nexthop = rt_nexthop(rt, fl4.daddr);
		neigh = neigh_lookup(&arp_tbl, &nexthop, target_dev);
		if (!neigh) {
			ip_rt_put(rt);
			trustix_datapath_tx_plaintext_direct_xmit_neigh_misses++;
			return -EHOSTUNREACH;
		}
		if (!(READ_ONCE(neigh->nud_state) & NUD_VALID) ||
		    !is_valid_ether_addr(neigh->ha)) {
			neigh_release(neigh);
			ip_rt_put(rt);
			trustix_datapath_tx_plaintext_direct_xmit_neigh_misses++;
			return -EHOSTUNREACH;
		}
		ether_addr_copy(daddr, neigh->ha);
		neigh_release(neigh);
		ip_rt_put(rt);
		trustix_datapath_tx_plaintext_dst_mac_cache_store(
			target_dev, plan, daddr);
	}

	skb->dev = target_dev;
	skb->mark |= TRUSTIX_DATAPATH_SKB_MARK_TX_PLAINTEXT;
	skb->protocol = htons(ETH_P_IP);
	skb->pkt_type = PACKET_OUTGOING;
	if (plan->outer_protocol == IPPROTO_TCP) {
		order_lock = trustix_datapath_tx_outer_tcp_order_lock(plan);
		spin_lock_bh(order_lock);
		ret = trustix_datapath_tx_assign_outer_tcp_sequence(skb, plan);
		if (ret) {
			trustix_datapath_tx_plaintext_tix_tcp_sequence_assign_errors++;
			spin_unlock_bh(order_lock);
			return -EMSGSIZE;
		}
		this_cpu_inc(
			trustix_datapath_tx_plaintext_tix_tcp_ordered_xmits);
	}
	skb_push(skb, ETH_HLEN);
	skb_reset_mac_header(skb);
	skb_set_network_header(skb, ETH_HLEN);
	skb_set_transport_header(skb, ETH_HLEN + sizeof(struct iphdr));
	skb->mac_len = ETH_HLEN;
	eth = eth_hdr(skb);
	ether_addr_copy(eth->h_dest, daddr);
	ether_addr_copy(eth->h_source, target_dev->dev_addr);
	eth->h_proto = htons(ETH_P_IP);
	trustix_datapath_tx_plaintext_set_hash_tx_queue(skb, target_dev,
							plan);
	ret = dev_queue_xmit(skb);
	if (order_lock)
		spin_unlock_bh(order_lock);
	if (ret == NET_XMIT_SUCCESS || ret == NET_XMIT_CN) {
		trustix_datapath_tx_plaintext_direct_xmit_packets++;
		return 0;
	}
	trustix_datapath_tx_plaintext_direct_xmit_errors++;
	return -ENOBUFS;
}

static int
trustix_datapath_tx_send_outer_skb(struct sk_buff *skb,
				   struct net_device *target_dev,
				   const struct trustix_datapath_tx_plan *plan)
{
	spinlock_t *order_lock = NULL;
	struct flowi4 fl4 = {};
	struct rtable *rt;
	struct net *net;
	int ret;

	if (!skb || !target_dev || !plan)
		return -EINVAL;
	ret = trustix_datapath_tx_send_outer_skb_direct(skb, target_dev, plan);
	if (!ret)
		return 0;
	if (ret == -EMSGSIZE) {
		kfree_skb(skb);
		return ret;
	}
	if (ret != -ENOBUFS) {
		trustix_datapath_tx_plaintext_direct_xmit_fallbacks++;
	} else {
		return ret;
	}
	net = dev_net(target_dev);
	fl4.flowi4_oif = target_dev->ifindex;
	fl4.flowi4_proto = plan->outer_protocol;
	fl4.saddr = htonl(plan->local_ipv4);
	fl4.daddr = htonl(plan->remote_ipv4);
	fl4.fl4_sport = htons(plan->local_port);
	fl4.fl4_dport = htons(plan->remote_port);
	rt = ip_route_output_key(net, &fl4);
	if (IS_ERR(rt)) {
		kfree_skb(skb);
		return PTR_ERR(rt);
	}
	skb_dst_set(skb, &rt->dst);
	skb->dev = target_dev;
	skb->mark |= TRUSTIX_DATAPATH_SKB_MARK_TX_PLAINTEXT;
	if (plan->outer_protocol == IPPROTO_TCP) {
		order_lock = trustix_datapath_tx_outer_tcp_order_lock(plan);
		spin_lock_bh(order_lock);
		ret = trustix_datapath_tx_assign_outer_tcp_sequence(skb, plan);
		if (ret) {
			trustix_datapath_tx_plaintext_tix_tcp_sequence_assign_errors++;
			spin_unlock_bh(order_lock);
			kfree_skb(skb);
			return -EMSGSIZE;
		}
		this_cpu_inc(
			trustix_datapath_tx_plaintext_tix_tcp_ordered_xmits);
	}
	ret = ip_local_out(net, NULL, skb);
	if (order_lock)
		spin_unlock_bh(order_lock);
	if (ret)
		return ret;
	return 0;
}

static void trustix_datapath_tx_plaintext_run(struct work_struct *work)
{
	struct trustix_datapath_tx_plaintext_slot slot = {};
	struct sk_buff *skb;
	unsigned long irqflags;
	int ret;

	(void)work;
	trustix_datapath_tx_plaintext_runs++;
	for (;;) {
		memset(&slot, 0, sizeof(slot));
		spin_lock_irqsave(&trustix_datapath_tx_plaintext_lock,
				  irqflags);
		if (!trustix_datapath_tx_plaintext_ring ||
		    !trustix_datapath_tx_plaintext_capacity ||
		    !trustix_datapath_tx_plaintext_count) {
			trustix_datapath_tx_plaintext_work_active = false;
			WRITE_ONCE(trustix_datapath_tx_plaintext_queue_len,
				   0);
			spin_unlock_irqrestore(
				&trustix_datapath_tx_plaintext_lock,
				irqflags);
			break;
		}
		slot = trustix_datapath_tx_plaintext_ring
			       [trustix_datapath_tx_plaintext_head];
		memset(&trustix_datapath_tx_plaintext_ring
			       [trustix_datapath_tx_plaintext_head],
		       0, sizeof(trustix_datapath_tx_plaintext_ring
					[trustix_datapath_tx_plaintext_head]));
		trustix_datapath_tx_plaintext_head =
			(trustix_datapath_tx_plaintext_head + 1) %
			trustix_datapath_tx_plaintext_capacity;
		trustix_datapath_tx_plaintext_count--;
		if (!trustix_datapath_tx_plaintext_count)
			trustix_datapath_tx_plaintext_tail =
				trustix_datapath_tx_plaintext_head;
		WRITE_ONCE(trustix_datapath_tx_plaintext_queue_len,
			   trustix_datapath_tx_plaintext_count);
		spin_unlock_irqrestore(&trustix_datapath_tx_plaintext_lock,
				       irqflags);

		if (!slot.valid || !slot.skb || !slot.target_dev) {
			trustix_datapath_tx_plaintext_release_slot(&slot);
			continue;
		}
		skb = slot.skb;
		slot.skb = NULL;
		ret = trustix_datapath_tx_send_outer_skb(skb, slot.target_dev,
							 &slot.plan);
		if (ret)
			trustix_datapath_tx_plaintext_xmit_errors++;
		else {
			trustix_datapath_tx_record_success(
				&slot.plan, slot.inner_len);
		}
		trustix_datapath_tx_plaintext_run_processed++;
		trustix_datapath_tx_plaintext_release_slot(&slot);
		cond_resched();
	}
}

static int trustix_datapath_tx_build_outer_tcp_segment_skb(
	struct sk_buff *inner_skb, const struct trustix_datapath_tx_plan *plan,
	__u32 network_offset, __u32 ip_header_len, __u32 tcp_header_len,
	__u32 payload_offset, __u32 payload_len, __u32 seq, __u16 ip_id,
	unsigned int seg_index, bool last_segment, struct sk_buff **out_skb)
{
	struct trustix_aead_direct_batch_op seal_op = {};
	struct sk_buff *skb;
	struct tcphdr *outer_tcph;
	struct iphdr *outer_iph;
	struct iphdr *seg_iph;
	struct tcphdr *seg_tcph;
	__u8 *packet;
	__u8 *tixt;
	__u8 *inner_packet;
	__u32 inner_header_len;
	__u32 inner_len;
	__u32 outer_header_len;
	__u32 tixt_len;
	__u32 outer_len;
	__u32 outer_tcp_len;
	__u64 sequence;
	__wsum payload_sum = 0;
	bool copy_payload_csum;
	bool fix_inner_tcp_checksum;
	bool inner_tcp_checksum_partial;
	int ret;

	if (!inner_skb || !plan || !out_skb)
		return -EINVAL;
	*out_skb = NULL;
	inner_tcp_checksum_partial = plan->secure ?
		trustix_datapath_tx_secure_inner_tcp_checksum_partial_enabled(
			plan) :
		trustix_datapath_tx_plaintext_inner_tcp_checksum_partial_enabled(
			plan);
	fix_inner_tcp_checksum = !inner_tcp_checksum_partial &&
		(plan->secure ||
		!READ_ONCE(
			trustix_datapath_tx_plaintext_skip_inner_tcp_checksum));
	copy_payload_csum = fix_inner_tcp_checksum && payload_len &&
		plan->outer_protocol == IPPROTO_TCP && READ_ONCE(
			trustix_datapath_tx_plaintext_payload_copy_csum);
	if (check_add_overflow(ip_header_len, tcp_header_len,
			       &inner_header_len) ||
	    check_add_overflow(inner_header_len, payload_len, &inner_len))
		return -EOVERFLOW;
	if (!inner_len || inner_len > TRUSTIX_DATAPATH_TIXT_MAX_PAYLOAD)
		return -EMSGSIZE;
	if (plan->secure && plan->outer_protocol != IPPROTO_TCP)
		return -EPROTONOSUPPORT;

	switch (plan->outer_protocol) {
	case IPPROTO_UDP:
		outer_header_len = 20 + 8;
		break;
	case IPPROTO_TCP:
		outer_header_len = 20 + 20;
		break;
	default:
		return -EPROTONOSUPPORT;
	}
	if (check_add_overflow((__u32)TRUSTIX_DATAPATH_TIXT_HEADER_LEN,
			       inner_len, &tixt_len) ||
	    (plan->secure &&
	     check_add_overflow(tixt_len,
				(__u32)TRUSTIX_DATAPATH_SECURE_OVERHEAD,
				&tixt_len)))
		return -EOVERFLOW;
	outer_len = outer_header_len + tixt_len;
	if (outer_len > 0xffffU)
		return -EMSGSIZE;
	if (plan->max_packet_size && outer_len > plan->max_packet_size)
		return -EMSGSIZE;

	skb = alloc_skb(LL_MAX_HEADER + outer_len, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;
	skb_reserve(skb, LL_MAX_HEADER);
	packet = skb_put(skb, outer_len);
	memset(packet, 0, outer_header_len);

	trustix_datapath_build_outer_ipv4(packet, outer_len,
					  plan->outer_protocol,
					  plan->local_ipv4,
					  plan->remote_ipv4);
	if (plan->outer_protocol == IPPROTO_UDP) {
		trustix_datapath_put_be16(packet + 20, plan->local_port);
		trustix_datapath_put_be16(packet + 22, plan->remote_port);
		trustix_datapath_put_be16(packet + 24, (__u16)(8 + tixt_len));
		tixt = packet + 28;
	} else {
		trustix_datapath_put_be16(packet + 20, plan->local_port);
		trustix_datapath_put_be16(packet + 22, plan->remote_port);
		trustix_datapath_put_be32(packet + 24, 0);
		packet[32] = 0x50;
		packet[33] = 0x18;
		trustix_datapath_put_be16(packet + 34, 65535);
		tixt = packet + 40;
	}

	if (plan->secure) {
		ret = trustix_datapath_secure_tx_reserve(plan, 1, &sequence);
		if (ret)
			goto error;
		trustix_datapath_build_tixt_header(
			tixt,
			TRUSTIX_DATAPATH_TIXT_FLAG_ENCRYPTED |
				TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4 |
				(inner_tcp_checksum_partial ?
				 TRUSTIX_DATAPATH_TIXT_FLAG_INNER_TCP_CHECKSUM_PARTIAL :
				 0),
			plan->flow_id, plan->epoch, sequence,
			inner_len + TRUSTIX_DATAPATH_SECURE_OVERHEAD, 0, 0);
		trustix_datapath_secure_write_header(
			tixt + TRUSTIX_DATAPATH_TIXT_HEADER_LEN, plan->suite,
			plan->epoch, sequence);
		inner_packet = tixt + TRUSTIX_DATAPATH_TIXT_HEADER_LEN +
			       TRUSTIX_DATAPATH_SECURE_HEADER_LEN;
	} else {
		sequence = (__u64)atomic64_inc_return(
			&trustix_datapath_tx_sequence);
		trustix_datapath_build_tixt_header(
			tixt,
			trustix_datapath_tx_plaintext_tixt_flags(
				fix_inner_tcp_checksum,
				inner_tcp_checksum_partial),
			plan->flow_id, plan->epoch, sequence, inner_len, 0, 0);
		inner_packet = tixt + TRUSTIX_DATAPATH_TIXT_HEADER_LEN;
	}
	ret = skb_copy_bits(inner_skb, network_offset,
			    inner_packet, inner_header_len);
	if (ret)
		goto error;
	if (payload_len) {
		if (plan->outer_protocol == IPPROTO_TCP)
			ret = trustix_datapath_tx_plaintext_copy_payload(
				inner_skb,
				network_offset + inner_header_len + payload_offset,
				inner_packet + inner_header_len,
				payload_len, copy_payload_csum, &payload_sum);
		else
			ret = skb_copy_bits(
				inner_skb,
				network_offset + inner_header_len + payload_offset,
				inner_packet + inner_header_len,
				payload_len);
		if (ret)
			goto error;
	}

	seg_iph = (struct iphdr *)inner_packet;
	seg_tcph = (struct tcphdr *)((__u8 *)seg_iph + ip_header_len);
	seg_iph->tot_len = htons((__u16)inner_len);
	seg_iph->id = htons(ip_id + seg_index);
	trustix_datapath_rx_worker_fix_ipv4_header_checksum(seg_iph,
							   ip_header_len);
	seg_tcph->seq = htonl(seq + payload_offset);
	if (!last_segment) {
		seg_tcph->fin = 0;
		seg_tcph->psh = 0;
	}
	seg_tcph->check = 0;
	if (inner_tcp_checksum_partial)
		seg_tcph->check = ~csum_tcpudp_magic(
			seg_iph->saddr, seg_iph->daddr,
			tcp_header_len + payload_len, IPPROTO_TCP, 0);
	else if (fix_inner_tcp_checksum)
		seg_tcph->check =
			trustix_datapath_tx_plaintext_tcp_checksum(
				seg_iph, seg_tcph, tcp_header_len, payload_len,
				copy_payload_csum, payload_sum);
	if (plan->secure) {
		trustix_datapath_secure_prepare_nonce(
			seal_op.nonce, plan->send_iv, sequence);
		seal_op.src = inner_packet;
		seal_op.dst = inner_packet;
		seal_op.plain_len = inner_len;
		ret = trustix_datapath_secure_tx_seal(plan, &seal_op, 1);
		if (ret)
			goto error;
	}

	skb_reset_network_header(skb);
	skb_set_transport_header(skb, 20);
	skb->protocol = htons(ETH_P_IP);
	if (plan->outer_protocol == IPPROTO_TCP) {
		outer_iph = (struct iphdr *)skb_network_header(skb);
		outer_tcph = (struct tcphdr *)skb_transport_header(skb);
		outer_tcp_len = outer_len - 20;
		outer_tcph->check = 0;
		outer_tcph->check = trustix_datapath_rx_worker_l4_checksum(
			outer_iph, outer_tcph, outer_tcp_len, IPPROTO_TCP);
	}
	skb->ip_summed = CHECKSUM_NONE;
	skb->pkt_type = PACKET_OUTGOING;
	if (inner_tcp_checksum_partial) {
		if (plan->secure)
			trustix_datapath_secure_tx_inner_tcp_checksum_partial++;
		else
			trustix_datapath_tx_plaintext_inner_tcp_checksum_partial++;
	}
	*out_skb = skb;
	return 0;

error:
	if (plan->secure && ret != -ESTALE)
		trustix_datapath_secure_tx_errors++;
	kfree_skb(skb);
	return ret;
}

static int trustix_datapath_tx_plaintext_outer_header_len(
	const struct trustix_datapath_tx_plan *plan, __u32 *header_len)
{
	if (!plan || !header_len)
		return -EINVAL;
	switch (plan->outer_protocol) {
	case IPPROTO_UDP:
		*header_len = 20 + 8;
		return 0;
	case IPPROTO_TCP:
		*header_len = 20 + 20;
		return 0;
	default:
		return -EPROTONOSUPPORT;
	}
}

static __u32 trustix_datapath_tx_packet_limit(
	const struct trustix_datapath_tx_plan *plan,
	const struct net_device *target_dev)
{
	__u32 limit = plan ? plan->max_packet_size : 0;
	__u32 mtu = target_dev ? READ_ONCE(target_dev->mtu) : 0;

	if (!limit || (mtu && mtu < limit))
		limit = mtu;
	return limit;
}

static int trustix_datapath_tx_plaintext_gso_payload_size(
	const struct trustix_datapath_tx_plan *plan, struct net_device *target_dev,
	__u32 ip_header_len, __u32 tcp_header_len, __u32 requested_gso_size,
	__u32 *payload_size)
{
	__u32 outer_header_len;
	__u32 inner_header_len;
	__u32 outer_overhead;
	__u32 packet_limit;
	__u32 max_payload;
	int ret;

	if (!plan || !payload_size || !requested_gso_size)
		return -EINVAL;
	ret = trustix_datapath_tx_plaintext_outer_header_len(
		plan, &outer_header_len);
	if (ret)
		return ret;
	if (check_add_overflow(ip_header_len, tcp_header_len,
			       &inner_header_len) ||
	    check_add_overflow(outer_header_len,
			       (__u32)TRUSTIX_DATAPATH_TIXT_HEADER_LEN,
			       &outer_overhead))
		return -EOVERFLOW;
	if (plan->secure &&
	    check_add_overflow(outer_overhead,
			       (__u32)TRUSTIX_DATAPATH_SECURE_OVERHEAD,
			       &outer_overhead))
		return -EOVERFLOW;

	packet_limit = trustix_datapath_tx_packet_limit(plan, target_dev);
	if (!packet_limit) {
		*payload_size = requested_gso_size;
		return 0;
	}
	if (packet_limit <= outer_overhead + inner_header_len)
		return -EMSGSIZE;
	max_payload = packet_limit - outer_overhead - inner_header_len;
	if (!max_payload)
		return -EMSGSIZE;
	*payload_size = min(requested_gso_size, max_payload);
	return 0;
}

static int trustix_datapath_tx_plaintext_copy_inner_tcp_header(
	const struct sk_buff *skb, __u32 network_offset, __u32 inner_header_len,
	__u8 *header, size_t header_size)
{
	if (!skb || !header || !inner_header_len ||
	    inner_header_len > header_size)
		return -EINVAL;
	return skb_copy_bits(skb, network_offset, header, inner_header_len);
}

static int trustix_datapath_tx_plaintext_outer_exceeds_packet_limit(
	const struct trustix_datapath_tx_plan *plan,
	const struct net_device *target_dev, __u32 inner_len, bool *exceeds)
{
	__u32 outer_header_len;
	__u32 tixt_len;
	__u32 outer_len;
	__u32 packet_limit;
	int ret;

	if (!plan || !exceeds)
		return -EINVAL;
	*exceeds = false;
	packet_limit = trustix_datapath_tx_packet_limit(plan, target_dev);
	if (!packet_limit)
		return 0;
	ret = trustix_datapath_tx_plaintext_outer_header_len(
		plan, &outer_header_len);
	if (ret)
		return ret;
	if (check_add_overflow((__u32)TRUSTIX_DATAPATH_TIXT_HEADER_LEN,
			       inner_len, &tixt_len) ||
	    check_add_overflow(outer_header_len, tixt_len, &outer_len))
		return -EOVERFLOW;
	if (plan->secure &&
	    check_add_overflow(outer_len,
			       (__u32)TRUSTIX_DATAPATH_SECURE_OVERHEAD,
			       &outer_len))
		return -EOVERFLOW;
	*exceeds = outer_len > packet_limit;
	return 0;
}

static int trustix_datapath_tx_plaintext_fragment_ipv4_skb(
	struct sk_buff *skb, const struct trustix_datapath_tx_plan *plan,
	struct net_device *target_dev)
{
	struct sk_buff *fragments[TRUSTIX_DATAPATH_TX_PLAINTEXT_MAX_GSO_SEGS] = {};
	__u32 inner_lens[TRUSTIX_DATAPATH_TX_PLAINTEXT_MAX_GSO_SEGS] = {};
	const struct iphdr *iph;
	__u32 network_offset;
	__u32 ip_header_len;
	__u32 total_len;
	__u32 payload_len;
	__u32 payload_offset = 0;
	__u32 outer_header_len;
	__u32 packet_limit;
	__u32 max_inner_len;
	__u32 max_fragment_payload;
	__u8 *full_packet = NULL;
	unsigned int fragment_count;
	unsigned int i = 0;
	int ret;

	if (!skb || !plan || !target_dev)
		return -EINVAL;
	if (skb_is_gso(skb))
		return -EINVAL;
	network_offset = skb_network_offset(skb);
	if (network_offset > TRUSTIX_DATAPATH_PACKET_MAX_LEN ||
	    !pskb_may_pull(skb, network_offset + sizeof(*iph)))
		return -ENODATA;
	iph = (const struct iphdr *)skb_network_header(skb);
	if (!iph || iph->version != 4 || iph->ihl < 5)
		return -EPROTONOSUPPORT;
	ip_header_len = iph->ihl * 4;
	if (ip_header_len < sizeof(*iph) ||
	    !pskb_may_pull(skb, network_offset + ip_header_len))
		return -ENODATA;
	iph = (const struct iphdr *)skb_network_header(skb);
	total_len = ntohs(iph->tot_len);
	if (total_len < ip_header_len ||
	    total_len > skb->len - network_offset)
		return -EINVAL;
	if (iph->frag_off & htons(0x3fff))
		return -EOPNOTSUPP;
	payload_len = total_len - ip_header_len;
	if (!payload_len)
		return -EINVAL;
	if (iph->protocol == IPPROTO_UDP) {
		full_packet = kmalloc(total_len, GFP_ATOMIC);
		if (!full_packet)
			return -ENOMEM;
		ret = skb_copy_bits(skb, network_offset, full_packet,
				    total_len);
		if (ret)
			goto error;
		if (!trustix_datapath_tx_plaintext_fix_inner_l4_checksum(
			    full_packet, total_len)) {
			ret = -EINVAL;
			goto error;
		}
	}

	ret = trustix_datapath_tx_plaintext_outer_header_len(
		plan, &outer_header_len);
	if (ret)
		goto error;
	packet_limit = trustix_datapath_tx_packet_limit(plan, target_dev);
	if (!packet_limit) {
		ret = -EMSGSIZE;
		goto error;
	}
	if (packet_limit <= outer_header_len +
				    TRUSTIX_DATAPATH_TIXT_HEADER_LEN +
				    ip_header_len) {
		ret = -EMSGSIZE;
		goto error;
	}
	max_inner_len = packet_limit - outer_header_len -
			TRUSTIX_DATAPATH_TIXT_HEADER_LEN;
	if (max_inner_len <= ip_header_len) {
		ret = -EMSGSIZE;
		goto error;
	}
	max_fragment_payload = (max_inner_len - ip_header_len) & ~7U;
	if (!max_fragment_payload) {
		ret = -EMSGSIZE;
		goto error;
	}
	fragment_count = DIV_ROUND_UP(payload_len, max_fragment_payload);
	if (!fragment_count ||
	    fragment_count > TRUSTIX_DATAPATH_TX_PLAINTEXT_MAX_GSO_SEGS) {
		ret = -EMSGSIZE;
		goto error;
	}

	while (payload_offset < payload_len) {
		struct sk_buff *inner_skb = NULL;
		struct sk_buff *outer_skb = NULL;
		struct iphdr *frag_iph;
		__u8 *packet;
		__u32 remaining = payload_len - payload_offset;
		__u32 fragment_payload_len =
			min_t(__u32, remaining, max_fragment_payload);
		__u32 fragment_inner_len = ip_header_len + fragment_payload_len;
		__u16 frag_off = (__u16)(payload_offset >> 3);

		if (i >= TRUSTIX_DATAPATH_TX_PLAINTEXT_MAX_GSO_SEGS) {
			ret = -EMSGSIZE;
			goto error;
		}
		if (remaining > fragment_payload_len)
			frag_off |= 0x2000U;

		inner_skb = alloc_skb(LL_MAX_HEADER + fragment_inner_len,
				      GFP_ATOMIC);
		if (!inner_skb) {
			ret = -ENOMEM;
			goto error;
		}
		skb_reserve(inner_skb, LL_MAX_HEADER);
		packet = skb_put(inner_skb, fragment_inner_len);
		if (full_packet) {
			memcpy(packet, full_packet, ip_header_len);
			memcpy(packet + ip_header_len,
			       full_packet + ip_header_len + payload_offset,
			       fragment_payload_len);
		} else {
			ret = skb_copy_bits(skb, network_offset, packet,
					    ip_header_len);
			if (ret) {
				kfree_skb(inner_skb);
				goto error;
			}
			ret = skb_copy_bits(skb,
					    network_offset + ip_header_len +
						    payload_offset,
					    packet + ip_header_len,
					    fragment_payload_len);
			if (ret) {
				kfree_skb(inner_skb);
				goto error;
			}
		}
		frag_iph = (struct iphdr *)packet;
		frag_iph->tot_len = htons((__u16)fragment_inner_len);
		frag_iph->frag_off = htons(frag_off);
		trustix_datapath_rx_worker_fix_ipv4_header_checksum(
			frag_iph, ip_header_len);
		skb_reset_network_header(inner_skb);
		skb_set_transport_header(inner_skb, ip_header_len);

		ret = trustix_datapath_tx_build_outer_skb(
			inner_skb, plan, fragment_inner_len, &outer_skb);
		kfree_skb(inner_skb);
		if (ret)
			goto error;
		fragments[i] = outer_skb;
		inner_lens[i] = fragment_inner_len;
		i++;
		payload_offset += fragment_payload_len;
	}

	ret = trustix_datapath_tx_plaintext_enqueue_many(
		fragments, inner_lens, i, target_dev, plan);
	if (ret)
		goto error;
	trustix_datapath_tx_plaintext_ipv4_fragment_packets++;
	trustix_datapath_tx_plaintext_ipv4_fragments += i;
	kfree(full_packet);
	return 0;

error:
	kfree(full_packet);
	while (i > 0) {
		i--;
		kfree_skb(fragments[i]);
		fragments[i] = NULL;
	}
	if (ret != -ESTALE)
		trustix_datapath_tx_plaintext_ipv4_fragment_errors++;
	return ret;
}

static int trustix_datapath_tx_plaintext_segment_tcp_skb(
	struct sk_buff *skb, const struct trustix_datapath_tx_plan *plan,
	struct net_device *target_dev, __u32 requested_gso_size,
	bool require_gso)
{
	struct sk_buff *segments[TRUSTIX_DATAPATH_TX_PLAINTEXT_MAX_GSO_SEGS] = {};
	__u32 inner_lens[TRUSTIX_DATAPATH_TX_PLAINTEXT_MAX_GSO_SEGS] = {};
	struct skb_shared_info *shinfo;
	const struct tcphdr *tcph;
	const struct iphdr *iph;
	__u32 network_offset;
	__u32 ip_header_len;
	__u32 tcp_header_len;
	__u32 total_len;
	__u32 tcp_len;
	__u32 payload_len;
	__u32 payload_offset = 0;
	__u32 gso_size;
	__u32 wire_gso_size;
	__u32 seq;
	__u16 ip_id;
	unsigned int expected_segs;
	unsigned int seg_index = 0;
	int ret = 0;
	bool gso;

	if (!skb || !plan || !target_dev)
		return -EINVAL;
	gso = skb_is_gso(skb);
	if (require_gso && !gso)
		return -EINVAL;
	network_offset = skb_network_offset(skb);
	if (network_offset > TRUSTIX_DATAPATH_PACKET_MAX_LEN ||
	    !pskb_may_pull(skb, network_offset + sizeof(*iph)))
		return -ENODATA;
	iph = (const struct iphdr *)skb_network_header(skb);
	if (!iph || iph->version != 4 || iph->ihl < 5 ||
	    iph->protocol != IPPROTO_TCP ||
	    (iph->frag_off & htons(0x3fff)))
		return -EPROTONOSUPPORT;
	ip_header_len = iph->ihl * 4;
	if (ip_header_len < sizeof(*iph) ||
	    !pskb_may_pull(skb, network_offset + ip_header_len + sizeof(*tcph)))
		return -ENODATA;
	iph = (const struct iphdr *)skb_network_header(skb);
	tcph = (const struct tcphdr *)((const __u8 *)iph + ip_header_len);
	tcp_header_len = tcph->doff * 4;
	total_len = ntohs(iph->tot_len);
	if (tcp_header_len < sizeof(*tcph) ||
	    total_len < ip_header_len + tcp_header_len ||
	    total_len > skb->len - network_offset ||
	    !pskb_may_pull(skb, network_offset + ip_header_len +
				  tcp_header_len))
		return -EINVAL;
	tcp_len = total_len - ip_header_len;
	payload_len = tcp_len - tcp_header_len;
	if (!payload_len)
		return -EINVAL;
	if (gso) {
		shinfo = skb_shinfo(skb);
		gso_size = shinfo->gso_size;
	} else {
		shinfo = NULL;
		gso_size = requested_gso_size ?: payload_len;
	}
	if (!gso_size || gso_size > payload_len)
		return -EINVAL;
	ret = trustix_datapath_tx_plaintext_gso_payload_size(
		plan, target_dev, ip_header_len, tcp_header_len, gso_size,
		&wire_gso_size);
	if (ret)
		return ret;
	if (!wire_gso_size)
		return -EINVAL;
	if (wire_gso_size >= payload_len)
		return -EOPNOTSUPP;
	expected_segs = DIV_ROUND_UP(payload_len, wire_gso_size);
	if (expected_segs < 2 ||
	    expected_segs > TRUSTIX_DATAPATH_TX_PLAINTEXT_MAX_GSO_SEGS)
		return -E2BIG;
	seq = ntohl(tcph->seq);
	ip_id = ntohs(iph->id);

	while (payload_offset < payload_len) {
		__u32 seg_payload_len = min_t(__u32,
					      payload_len - payload_offset,
					      wire_gso_size);
		__u32 inner_len;
		bool last = payload_offset + seg_payload_len >= payload_len;

		if (seg_index >= expected_segs) {
			ret = -E2BIG;
			goto error;
		}
		inner_len = ip_header_len + tcp_header_len + seg_payload_len;
		ret = trustix_datapath_tx_build_outer_tcp_segment_skb(
			skb, plan, network_offset, ip_header_len,
			tcp_header_len, payload_offset, seg_payload_len, seq,
			ip_id, seg_index, last, &segments[seg_index]);
		if (ret)
			goto error;
		inner_lens[seg_index] = inner_len;
		payload_offset += seg_payload_len;
		seg_index++;
	}
	if (seg_index != expected_segs) {
		ret = -EINVAL;
		goto error;
	}
	ret = trustix_datapath_tx_plaintext_enqueue_many(
		segments, inner_lens, seg_index, target_dev, plan);
	if (ret)
		goto error;
	trustix_datapath_tx_plaintext_gso_segments += seg_index;
	return 0;

error:
	while (seg_index > 0) {
		seg_index--;
		kfree_skb(segments[seg_index]);
		segments[seg_index] = NULL;
	}
	if (ret != -ESTALE)
		trustix_datapath_tx_plaintext_gso_errors++;
	return ret;
}

static int trustix_datapath_tx_plaintext_copy_payload(
	struct sk_buff *src, __u32 src_offset, __u8 *dst, __u32 len,
	bool copy_csum, __wsum *sum_out)
{
	const struct skb_shared_info *shinfo;
	const skb_frag_t *frag;
	__u32 frag_start;
	__u32 frag_end;
	__u32 page_offset;
	__u32 copied;
	__wsum chunk_sum;
	__wsum sum = 0;
	unsigned int i;
	int ret;

	if (copy_csum)
		this_cpu_inc(
			trustix_datapath_tx_plaintext_payload_copy_csum_attempts);
	if (!src || !dst || !len || (copy_csum && !sum_out) ||
	    src_offset > src->len || len > src->len - src_offset) {
		if (copy_csum)
			this_cpu_inc(
				trustix_datapath_tx_plaintext_payload_copy_csum_errors);
		trustix_datapath_tx_plaintext_payload_fast_copy_errors++;
		return -EINVAL;
	}
	if (copy_csum)
		*sum_out = 0;
	if (READ_ONCE(trustix_datapath_tx_plaintext_payload_fast_copy)) {
		if (src_offset <= skb_headlen(src) &&
		    len <= skb_headlen(src) - src_offset) {
			if (copy_csum)
				sum = csum_partial_copy_nocheck(
					src->data + src_offset, dst, len);
			else
				memcpy(dst, src->data + src_offset, len);
			trustix_datapath_tx_plaintext_payload_fast_copy_linear_hits++;
			goto copied;
		}
		if (src_offset >= skb_headlen(src)) {
			shinfo = skb_shinfo(src);
			frag_start = skb_headlen(src);
			for (i = 0; i < shinfo->nr_frags; i++) {
				frag = &shinfo->frags[i];
				if (check_add_overflow(frag_start,
						       (__u32)skb_frag_size(frag),
						       &frag_end))
					break;
				if (src_offset >= frag_end) {
					frag_start = frag_end;
					continue;
				}
				if (src_offset < frag_start ||
				    len > frag_end - src_offset)
					break;
				page_offset = skb_frag_off(frag) +
					      (src_offset - frag_start);
				copied = 0;
				while (copied < len) {
					__u32 page_in_frag = page_offset + copied;
					__u32 page_in_frag_offset =
						page_in_frag & (PAGE_SIZE - 1);
					__u32 copy_len = min_t(
						__u32, len - copied,
						PAGE_SIZE - page_in_frag_offset);
					void *addr = kmap_local_page(
						skb_frag_page(frag) +
						(page_in_frag >> PAGE_SHIFT));

					if (copy_csum) {
						chunk_sum = csum_partial_copy_nocheck(
							(__u8 *)addr +
								page_in_frag_offset,
							dst + copied, copy_len);
						sum = csum_block_add(
							sum, chunk_sum, copied);
					} else {
						memcpy(dst + copied,
						       (__u8 *)addr +
							       page_in_frag_offset,
						       copy_len);
					}
					kunmap_local(addr);
					copied += copy_len;
				}
				trustix_datapath_tx_plaintext_payload_fast_copy_frag_hits++;
				goto copied;
			}
		}
		trustix_datapath_tx_plaintext_payload_fast_copy_fallbacks++;
	}
	if (copy_csum) {
		this_cpu_inc(
			trustix_datapath_tx_plaintext_payload_copy_csum_fallbacks);
		sum = skb_copy_and_csum_bits(src, src_offset, dst, len);
		goto copied;
	}
	ret = skb_copy_bits(src, src_offset, dst, len);
	if (ret) {
		trustix_datapath_tx_plaintext_payload_fast_copy_errors++;
		return ret;
	}
	return 0;

copied:
	if (copy_csum) {
		*sum_out = sum;
		this_cpu_inc(
			trustix_datapath_tx_plaintext_payload_copy_csum_hits);
	}
	return 0;
}

static __sum16 trustix_datapath_tx_plaintext_tcp_checksum(
	struct iphdr *iph, struct tcphdr *tcph, __u32 tcp_header_len,
	__u32 payload_len, bool payload_sum_ready, __wsum payload_sum)
{
	__wsum header_sum;
	__wsum sum;

	if (!payload_sum_ready)
		return trustix_datapath_rx_worker_l4_checksum(
			iph, tcph, tcp_header_len + payload_len, IPPROTO_TCP);
	header_sum = csum_partial(tcph, tcp_header_len, 0);
	sum = csum_block_add(header_sum, payload_sum, tcp_header_len);
	return csum_tcpudp_magic(iph->saddr, iph->daddr,
				 tcp_header_len + payload_len, IPPROTO_TCP, sum);
}

static void trustix_datapath_destroy_tx_outer_gso_page_pools(void)
{
	WRITE_ONCE(trustix_datapath_tx_plaintext_outer_gso_page_pool_available,
		   false);
#if TRUSTIX_DATAPATH_HAVE_TX_OUTER_GSO_PAGE_POOL
	{
		int cpu;

		for_each_possible_cpu(cpu) {
			struct page_pool *pool = per_cpu(
				trustix_datapath_tx_plaintext_outer_gso_page_pools,
				cpu);

			if (!pool)
				continue;
			per_cpu(
				trustix_datapath_tx_plaintext_outer_gso_page_pools,
				cpu) = NULL;
			page_pool_destroy(pool);
		}
	}
#endif
}

static void trustix_datapath_init_tx_outer_gso_page_pools(void)
{
	WRITE_ONCE(trustix_datapath_tx_plaintext_outer_gso_page_pool_available,
		   false);
#if TRUSTIX_DATAPATH_HAVE_TX_OUTER_GSO_PAGE_POOL
	{
		struct page_pool_params params = {
			.order = TRUSTIX_DATAPATH_TX_OUTER_GSO_PAGE_POOL_ORDER,
			.pool_size = TRUSTIX_DATAPATH_TX_OUTER_GSO_PAGE_POOL_SIZE,
			.nid = NUMA_NO_NODE,
		};
		int cpu;

		for_each_possible_cpu(cpu) {
			struct page_pool *pool =
				trustix_datapath_create_tx_outer_gso_page_pool(
					&params, cpu);

			if (IS_ERR(pool)) {
				trustix_datapath_destroy_tx_outer_gso_page_pools();
				return;
			}
			per_cpu(
				trustix_datapath_tx_plaintext_outer_gso_page_pools,
				cpu) = pool;
		}
		WRITE_ONCE(
			trustix_datapath_tx_plaintext_outer_gso_page_pool_available,
			true);
	}
#endif
}

static struct sk_buff *
trustix_datapath_alloc_tx_outer_gso_page_pool_skb_locked(
	unsigned int alloc_len, bool *allocation_error)
{
	struct sk_buff *skb = NULL;

#if TRUSTIX_DATAPATH_HAVE_TX_OUTER_GSO_PAGE_POOL
	if (allocation_error)
		*allocation_error = false;
	if (READ_ONCE(
		    trustix_datapath_tx_plaintext_outer_gso_page_pool_available) &&
	    alloc_len <= SKB_WITH_OVERHEAD(
				 PAGE_SIZE <<
				 TRUSTIX_DATAPATH_TX_OUTER_GSO_PAGE_POOL_ORDER)) {
		struct page_pool *pool = this_cpu_read(
			trustix_datapath_tx_plaintext_outer_gso_page_pools);
		struct page *page;
		void *data;

		if (!pool) {
			if (allocation_error)
				*allocation_error = true;
			return NULL;
		}
		page = page_pool_dev_alloc_pages(pool);
		if (!page) {
			if (allocation_error)
				*allocation_error = true;
			return NULL;
		}
		data = page_address(page);
		if (!data) {
			page_pool_put_full_page(pool, page, false);
			if (allocation_error)
				*allocation_error = true;
			return NULL;
		}
		skb = build_skb(
			data,
			PAGE_SIZE <<
				TRUSTIX_DATAPATH_TX_OUTER_GSO_PAGE_POOL_ORDER);
		if (!skb) {
			page_pool_put_full_page(pool, page, false);
			if (allocation_error)
				*allocation_error = true;
			return NULL;
		}
		skb_mark_for_recycle(skb);
		return skb;
	}
#else
	(void)alloc_len;
	if (allocation_error)
		*allocation_error = false;
#endif
	return NULL;
}

static struct sk_buff *
trustix_datapath_tx_alloc_outer_gso_page_pool_skb(unsigned int alloc_len)
{
	bool allocation_error = false;
	struct sk_buff *skb;

	local_bh_disable();
	this_cpu_inc(
		trustix_datapath_tx_plaintext_outer_gso_page_pool_attempts);
	skb = trustix_datapath_alloc_tx_outer_gso_page_pool_skb_locked(
		alloc_len, &allocation_error);
	if (skb)
		this_cpu_inc(
			trustix_datapath_tx_plaintext_outer_gso_page_pool_hits);
	else {
		this_cpu_inc(
			trustix_datapath_tx_plaintext_outer_gso_page_pool_fallbacks);
		if (allocation_error)
			this_cpu_inc(
				trustix_datapath_tx_plaintext_outer_gso_page_pool_errors);
	}
	local_bh_enable();
	return skb;
}

static unsigned int
trustix_datapath_tx_plaintext_outer_gso_max_frames_value(void);

static __always_inline bool
trustix_datapath_tx_plaintext_inner_gso_enabled(
	const struct trustix_datapath_tx_plan *plan)
{
	__u64 required_features =
		TRUSTIX_DATAPATH_FEATURE_INNER_TCP_CHECKSUM_PARTIAL |
		TRUSTIX_DATAPATH_FEATURE_INNER_GSO;
	__u32 required_flags =
		TRUSTIX_DATAPATH_SESSION_FLAG_SEND_INNER_TCP_CHECKSUM_PARTIAL |
		TRUSTIX_DATAPATH_SESSION_FLAG_SEND_INNER_GSO;

	if (!plan || plan->outer_protocol != IPPROTO_TCP ||
	    (plan->session_flags & TRUSTIX_DATAPATH_SESSION_FLAGS_ENCRYPTED) ||
	    (plan->session_flags & required_flags) != required_flags)
		return false;
	return (READ_ONCE(trustix_datapath_features) & required_features) ==
	       required_features;
}

static int trustix_datapath_tx_build_inner_gso_skb(
	struct sk_buff *inner_skb, const struct trustix_datapath_tx_plan *plan,
	struct net_device *target_dev, struct sk_buff **out_skb,
	unsigned int *inner_gso_segs)
{
	struct skb_shared_info *outer_shinfo;
	struct sk_buff *skb;
	struct tcphdr *inner_tcph;
	struct tcphdr *outer_tcph;
	struct iphdr *inner_iph;
	struct iphdr *outer_iph;
	__u32 network_offset;
	__u32 ip_header_len;
	__u32 tcp_header_len;
	__u32 total_len;
	__u32 tcp_len;
	__u32 payload_len;
	__u32 gso_size;
	__u32 gso_segs;
	__u32 source_gso_segs;
	__u32 source_gso_type;
	__u32 tixt_len;
	__u32 outer_len;
	__u32 outer_tcp_len;
	__u32 packet_limit;
	__u32 outer_gso_size;
	__u32 outer_gso_segs;
	__u64 sequence;
	__u8 *packet;
	__u8 *tixt;
	int ret;

	if (out_skb)
		*out_skb = NULL;
	if (inner_gso_segs)
		*inner_gso_segs = 0;
	if (!inner_skb || !plan || !target_dev || !out_skb ||
	    !inner_gso_segs ||
	    !trustix_datapath_tx_plaintext_inner_gso_enabled(plan))
		return -EOPNOTSUPP;
	if (!skb_is_gso(inner_skb) ||
	    !trustix_datapath_dev_supports_tcpv4_gso(target_dev))
		return -EOPNOTSUPP;
	source_gso_type = skb_shinfo(inner_skb)->gso_type;
	gso_size = skb_shinfo(inner_skb)->gso_size;
	source_gso_segs = skb_shinfo(inner_skb)->gso_segs;
	if ((source_gso_type & SKB_GSO_TCPV4) != SKB_GSO_TCPV4 ||
	    (source_gso_type & SKB_GSO_TCP_ECN))
		return -EOPNOTSUPP;

	network_offset = skb_network_offset(inner_skb);
	if (network_offset > TRUSTIX_DATAPATH_PACKET_MAX_LEN ||
	    !pskb_may_pull(inner_skb, network_offset + sizeof(*inner_iph)))
		return -ENODATA;
	inner_iph = (struct iphdr *)skb_network_header(inner_skb);
	if (!inner_iph || inner_iph->version != 4 || inner_iph->ihl < 5 ||
	    inner_iph->protocol != IPPROTO_TCP ||
	    (inner_iph->frag_off & htons(0x3fff)))
		return -EPROTONOSUPPORT;
	ip_header_len = inner_iph->ihl * 4;
	if (ip_header_len < sizeof(*inner_iph) ||
	    !pskb_may_pull(inner_skb, network_offset + ip_header_len +
					  sizeof(*inner_tcph)))
		return -ENODATA;
	inner_iph = (struct iphdr *)skb_network_header(inner_skb);
	inner_tcph = (struct tcphdr *)((__u8 *)inner_iph + ip_header_len);
	tcp_header_len = inner_tcph->doff * 4;
	total_len = ntohs(inner_iph->tot_len);
	if (tcp_header_len < sizeof(*inner_tcph) || tcp_header_len > 60 ||
	    total_len < ip_header_len + tcp_header_len ||
	    total_len > inner_skb->len - network_offset ||
	    total_len > TRUSTIX_DATAPATH_TIXT_MAX_PAYLOAD ||
	    !pskb_may_pull(inner_skb, network_offset + ip_header_len +
					  tcp_header_len))
		return -EINVAL;
	inner_iph = (struct iphdr *)skb_network_header(inner_skb);
	inner_tcph = (struct tcphdr *)((__u8 *)inner_iph + ip_header_len);
	if (!trustix_datapath_rx_worker_tcp_flags_supported(inner_tcph))
		return -EINVAL;
	tcp_len = total_len - ip_header_len;
	payload_len = tcp_len - tcp_header_len;
	if (!payload_len || !gso_size || gso_size > payload_len ||
	    gso_size > U16_MAX)
		return -EINVAL;
	gso_segs = DIV_ROUND_UP(payload_len, gso_size);
	if (gso_segs < 2 || gso_segs > U16_MAX ||
	    (source_gso_segs && source_gso_segs != gso_segs))
		return -EINVAL;
	if (check_add_overflow((__u32)TRUSTIX_DATAPATH_TIXT_HEADER_LEN,
			       total_len, &tixt_len) ||
	    check_add_overflow((__u32)(sizeof(struct iphdr) +
					 sizeof(struct tcphdr)),
			       tixt_len, &outer_len) ||
	    outer_len > U16_MAX)
		return -EMSGSIZE;
	if (target_dev->gso_max_size && outer_len > target_dev->gso_max_size)
		return -EMSGSIZE;

	packet_limit = trustix_datapath_tx_packet_limit(plan, target_dev);
	if (packet_limit <= sizeof(struct iphdr) + sizeof(struct tcphdr))
		return -EMSGSIZE;
	outer_gso_size = packet_limit - sizeof(struct iphdr) -
			 sizeof(struct tcphdr);
	outer_gso_segs = DIV_ROUND_UP(tixt_len, outer_gso_size);
	if (outer_gso_segs < 2 || outer_gso_segs > U16_MAX ||
	    (target_dev->gso_max_segs &&
	     outer_gso_segs > target_dev->gso_max_segs))
		return -EMSGSIZE;

	skb = skb_clone(inner_skb, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;
	/* The outer packet must not retain the inner socket or routing state. */
	skb_scrub_packet(skb, true);
	trustix_datapath_tx_plaintext_inner_gso_metadata_scrubs++;
	ret = skb_cow_head(skb, LL_MAX_HEADER + sizeof(struct iphdr) +
					 sizeof(struct tcphdr) +
					 TRUSTIX_DATAPATH_TIXT_HEADER_LEN);
	if (ret)
		goto error;
	if (network_offset && !skb_pull(skb, network_offset)) {
		ret = -ENODATA;
		goto error;
	}
	ret = pskb_trim(skb, total_len);
	if (ret)
		goto error;
	packet = skb_push(skb, sizeof(struct iphdr) + sizeof(struct tcphdr) +
				       TRUSTIX_DATAPATH_TIXT_HEADER_LEN);
	memset(packet, 0, sizeof(struct iphdr) + sizeof(struct tcphdr));
	tixt = packet + sizeof(struct iphdr) + sizeof(struct tcphdr);
	sequence = (__u64)atomic64_inc_return(&trustix_datapath_tx_sequence);
	trustix_datapath_build_tixt_header(
		tixt, TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4 |
			      TRUSTIX_DATAPATH_TIXT_FLAG_INNER_TCP_CHECKSUM_PARTIAL |
			      TRUSTIX_DATAPATH_TIXT_FLAG_INNER_GSO,
		plan->flow_id, plan->epoch, sequence, total_len, (__u16)gso_size,
		(__u16)gso_segs);

	inner_iph = (struct iphdr *)(tixt + TRUSTIX_DATAPATH_TIXT_HEADER_LEN);
	inner_tcph = (struct tcphdr *)((__u8 *)inner_iph + ip_header_len);
	trustix_datapath_rx_worker_fix_ipv4_header_checksum(inner_iph,
						   ip_header_len);
	inner_tcph->check = ~csum_tcpudp_magic(
		inner_iph->saddr, inner_iph->daddr, tcp_len, IPPROTO_TCP, 0);

	trustix_datapath_build_outer_ipv4(packet, outer_len, IPPROTO_TCP,
					  plan->local_ipv4,
					  plan->remote_ipv4);
	trustix_datapath_put_be16(packet + 20, plan->local_port);
	trustix_datapath_put_be16(packet + 22, plan->remote_port);
	trustix_datapath_put_be32(packet + 24, 0);
	packet[32] = 0x50;
	packet[33] = 0x18;
	trustix_datapath_put_be16(packet + 34, 65535);

	skb_reset_network_header(skb);
	skb_set_transport_header(skb, sizeof(struct iphdr));
	skb->protocol = htons(ETH_P_IP);
	skb->pkt_type = PACKET_OUTGOING;
	skb->encapsulation = 0;
	skb->csum = 0;
	skb->csum_level = 0;
	outer_iph = ip_hdr(skb);
	outer_tcph = tcp_hdr(skb);
	outer_tcp_len = outer_len - sizeof(*outer_iph);
	outer_tcph->check = ~csum_tcpudp_magic(
		outer_iph->saddr, outer_iph->daddr, outer_tcp_len,
		IPPROTO_TCP, 0);
	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum_start = skb_transport_header(skb) - skb->head;
	skb->csum_offset = offsetof(struct tcphdr, check);
	outer_shinfo = skb_shinfo(skb);
	outer_shinfo->gso_size = outer_gso_size;
	outer_shinfo->gso_segs = outer_gso_segs;
	outer_shinfo->gso_type = SKB_GSO_TCPV4;
	*out_skb = skb;
	*inner_gso_segs = gso_segs;
	return 0;

error:
	kfree_skb(skb);
	return ret;
}

static int trustix_datapath_tx_plaintext_inner_gso_skb(
	struct sk_buff *skb, const struct trustix_datapath_tx_plan *plan,
	struct net_device *target_dev)
{
	struct sk_buff *out = NULL;
	struct sk_buff *batch[1];
	__u32 inner_lens[1];
	unsigned int inner_gso_segs = 0;
	int ret;

	if (!trustix_datapath_tx_plaintext_inner_gso_enabled(plan))
		return -EOPNOTSUPP;
	trustix_datapath_tx_plaintext_inner_gso_attempts++;
	ret = trustix_datapath_tx_build_inner_gso_skb(
		skb, plan, target_dev, &out, &inner_gso_segs);
	if (ret) {
		if (ret == -ESTALE)
			return ret;
		trustix_datapath_tx_plaintext_inner_gso_fallbacks++;
		if (ret != -EOPNOTSUPP && ret != -EMSGSIZE && ret != -EINVAL)
			trustix_datapath_tx_plaintext_inner_gso_errors++;
		return ret;
	}
	batch[0] = out;
	inner_lens[0] = ntohs(ip_hdr(skb)->tot_len);
	ret = trustix_datapath_tx_plaintext_enqueue_many(
		batch, inner_lens, ARRAY_SIZE(batch), target_dev, plan);
	if (ret) {
		kfree_skb(batch[0]);
		if (ret == -ESTALE)
			return ret;
		trustix_datapath_tx_plaintext_inner_gso_fallbacks++;
		trustix_datapath_tx_plaintext_inner_gso_errors++;
		return ret;
	}
	trustix_datapath_tx_plaintext_inner_gso_packets++;
	trustix_datapath_tx_plaintext_inner_gso_segments += inner_gso_segs;
	trustix_datapath_tx_plaintext_gso_segments += inner_gso_segs;
	trustix_datapath_tx_plaintext_inner_tcp_checksum_partial++;
	return 0;
}

static int trustix_datapath_tx_build_outer_tcp_gso_skb(
	struct sk_buff *inner_skb, const struct trustix_datapath_tx_plan *plan,
	__u32 network_offset, __u32 ip_header_len, __u32 tcp_header_len,
	__u32 payload_offset, __u32 payload_len, __u32 wire_gso_size,
	__u32 seq, __u16 ip_id, unsigned int seg_index,
	unsigned int frame_count, struct sk_buff **out_skb,
	__u32 *inner_bytes_out)
{
	struct trustix_aead_direct_batch_op
		seal_ops[TRUSTIX_DATAPATH_SECURE_TX_SEAL_BATCH] = {};
	struct skb_shared_info *shinfo;
	struct sk_buff *skb;
	struct tcphdr *outer_tcph;
	struct iphdr *outer_iph;
	__u8 *packet;
	__u8 *pos;
	__u32 inner_header_len;
	__u32 outer_header_len = 20 + 20;
	__u32 outer_gso_size;
	__u32 full_inner_len;
	__u32 stream_payload_len = 0;
	__u32 inner_bytes = 0;
	__u32 cursor_payload_offset;
	__u32 outer_len;
	__u32 tcp_len;
	__u64 outer_sequence;
	__u64 first_secure_sequence = 0;
	__u32 frame_secure_overhead;
	__u8 inner_header[TRUSTIX_DATAPATH_IPV4_L4_PREFIX_MAX];
	unsigned int i;
	unsigned int seal_count = 0;
	bool copy_payload_csum;
	bool fix_inner_tcp_checksum;
	bool inner_tcp_checksum_partial;
	int ret;

	if (!inner_skb || !plan || !out_skb || !inner_bytes_out)
		return -EINVAL;
	*out_skb = NULL;
	*inner_bytes_out = 0;
	inner_tcp_checksum_partial = plan->secure ?
		trustix_datapath_tx_secure_inner_tcp_checksum_partial_enabled(
			plan) :
		trustix_datapath_tx_plaintext_inner_tcp_checksum_partial_enabled(
			plan);
	fix_inner_tcp_checksum = !inner_tcp_checksum_partial &&
		(plan->secure ||
		!READ_ONCE(
			trustix_datapath_tx_plaintext_skip_inner_tcp_checksum));
	copy_payload_csum = fix_inner_tcp_checksum && READ_ONCE(
		trustix_datapath_tx_plaintext_payload_copy_csum);
	if (plan->outer_protocol != IPPROTO_TCP || frame_count < 2 ||
	    !wire_gso_size)
		return -EOPNOTSUPP;
	frame_secure_overhead = plan->secure ?
		TRUSTIX_DATAPATH_SECURE_OVERHEAD : 0;
	if (check_add_overflow(ip_header_len, tcp_header_len,
			       &inner_header_len) ||
	    check_add_overflow(inner_header_len, wire_gso_size,
			       &full_inner_len) ||
	    check_add_overflow((__u32)TRUSTIX_DATAPATH_TIXT_HEADER_LEN,
			       full_inner_len, &outer_gso_size) ||
	    check_add_overflow(outer_gso_size, frame_secure_overhead,
			       &outer_gso_size))
		return -EOVERFLOW;
	if (!outer_gso_size)
		return -EINVAL;

	cursor_payload_offset = payload_offset;
	for (i = 0; i < frame_count; i++) {
		__u32 seg_payload_len;
		__u32 inner_len;
		__u32 frame_len;

		if (cursor_payload_offset >= payload_len)
			return -EINVAL;
		seg_payload_len = min_t(__u32,
					payload_len - cursor_payload_offset,
					wire_gso_size);
		if (check_add_overflow(inner_header_len, seg_payload_len,
				       &inner_len) ||
		    check_add_overflow((__u32)TRUSTIX_DATAPATH_TIXT_HEADER_LEN,
				       inner_len, &frame_len) ||
		    check_add_overflow(frame_len, frame_secure_overhead,
				       &frame_len) ||
		    check_add_overflow(stream_payload_len, frame_len,
				       &stream_payload_len) ||
		    check_add_overflow(inner_bytes, inner_len,
				       &inner_bytes))
			return -EOVERFLOW;
		if (i + 1 < frame_count && frame_len != outer_gso_size)
			return -EINVAL;
		if (i + 1 == frame_count && frame_len > outer_gso_size)
			return -EINVAL;
		cursor_payload_offset += seg_payload_len;
	}
	if (check_add_overflow(outer_header_len, stream_payload_len,
			       &outer_len) ||
	    check_add_overflow((__u32)sizeof(struct tcphdr),
			       stream_payload_len, &tcp_len))
		return -EOVERFLOW;
	if (outer_len > 0xffffU)
		return -EMSGSIZE;
	ret = trustix_datapath_tx_plaintext_copy_inner_tcp_header(
		inner_skb, network_offset, inner_header_len, inner_header,
		sizeof(inner_header));
	if (ret)
		return ret;

	skb = NULL;
	if (likely(READ_ONCE(
		    trustix_datapath_tx_plaintext_outer_gso_page_pool)))
		skb = trustix_datapath_tx_alloc_outer_gso_page_pool_skb(
			LL_MAX_HEADER + outer_len);
	if (!skb)
		skb = alloc_skb(LL_MAX_HEADER + outer_len, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;
	skb_reserve(skb, LL_MAX_HEADER);
	packet = skb_put(skb, outer_len);
	memset(packet, 0, outer_header_len);
	if (plan->secure) {
		ret = trustix_datapath_secure_tx_reserve(
			plan, frame_count, &first_secure_sequence);
		if (ret)
			goto error;
	}

	trustix_datapath_build_outer_ipv4(packet, outer_len, IPPROTO_TCP,
					  plan->local_ipv4,
					  plan->remote_ipv4);
	trustix_datapath_put_be16(packet + 20, plan->local_port);
	trustix_datapath_put_be16(packet + 22, plan->remote_port);
	packet[32] = 0x50;
	packet[33] = 0x18;
	trustix_datapath_put_be16(packet + 34, 65535);
	outer_sequence = 0;
	trustix_datapath_put_be32(packet + 24, (__u32)outer_sequence);

	pos = packet + outer_header_len;
	cursor_payload_offset = payload_offset;
	for (i = 0; i < frame_count; i++) {
		struct trustix_aead_direct_batch_op *seal_op;
		struct tcphdr *seg_tcph;
		struct iphdr *seg_iph;
		__u8 *tixt = pos;
		__u8 *inner_packet;
		__u32 seg_payload_len;
		__u32 inner_len;
		__wsum payload_sum = 0;
		bool last_segment;
		__u64 sequence;

		seg_payload_len = min_t(__u32,
					payload_len - cursor_payload_offset,
					wire_gso_size);
		inner_len = inner_header_len + seg_payload_len;
		last_segment = cursor_payload_offset + seg_payload_len >=
			       payload_len;
		if (plan->secure) {
			sequence = first_secure_sequence + i;
			trustix_datapath_build_tixt_header(
				tixt,
				TRUSTIX_DATAPATH_TIXT_FLAG_ENCRYPTED |
					TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4 |
					(inner_tcp_checksum_partial ?
					 TRUSTIX_DATAPATH_TIXT_FLAG_INNER_TCP_CHECKSUM_PARTIAL :
					 0),
				plan->flow_id, plan->epoch, sequence,
				inner_len + TRUSTIX_DATAPATH_SECURE_OVERHEAD,
				0, 0);
			trustix_datapath_secure_write_header(
				tixt + TRUSTIX_DATAPATH_TIXT_HEADER_LEN,
				plan->suite, plan->epoch, sequence);
			inner_packet = tixt + TRUSTIX_DATAPATH_TIXT_HEADER_LEN +
				       TRUSTIX_DATAPATH_SECURE_HEADER_LEN;
		} else {
			sequence = (__u64)atomic64_inc_return(
				&trustix_datapath_tx_sequence);
			trustix_datapath_build_tixt_header(
				tixt,
				trustix_datapath_tx_plaintext_tixt_flags(
					fix_inner_tcp_checksum,
					inner_tcp_checksum_partial),
				plan->flow_id, plan->epoch, sequence, inner_len,
				0, 0);
			inner_packet = tixt + TRUSTIX_DATAPATH_TIXT_HEADER_LEN;
		}
		memcpy(inner_packet, inner_header, inner_header_len);
		ret = trustix_datapath_tx_plaintext_copy_payload(
			inner_skb, network_offset + inner_header_len +
					   cursor_payload_offset,
			inner_packet + inner_header_len,
			seg_payload_len, copy_payload_csum, &payload_sum);
		if (ret)
			goto error;

		seg_iph = (struct iphdr *)inner_packet;
		seg_tcph = (struct tcphdr *)((__u8 *)seg_iph +
					     ip_header_len);
		seg_iph->tot_len = htons((__u16)inner_len);
		seg_iph->id = htons(ip_id + seg_index + i);
		trustix_datapath_rx_worker_fix_ipv4_header_checksum(
			seg_iph, ip_header_len);
		seg_tcph->seq = htonl(seq + cursor_payload_offset);
		if (!last_segment) {
			seg_tcph->fin = 0;
			seg_tcph->psh = 0;
		}
		seg_tcph->check = 0;
		if (inner_tcp_checksum_partial)
			seg_tcph->check = ~csum_tcpudp_magic(
				seg_iph->saddr, seg_iph->daddr,
				tcp_header_len + seg_payload_len,
				IPPROTO_TCP, 0);
		else if (fix_inner_tcp_checksum)
			seg_tcph->check =
				trustix_datapath_tx_plaintext_tcp_checksum(
					seg_iph, seg_tcph, tcp_header_len,
					seg_payload_len, copy_payload_csum,
					payload_sum);
		if (plan->secure) {
			seal_op = &seal_ops[seal_count++];
			trustix_datapath_secure_prepare_nonce(
				seal_op->nonce, plan->send_iv, sequence);
			seal_op->src = inner_packet;
			seal_op->dst = inner_packet;
			seal_op->plain_len = inner_len;
			if (seal_count == ARRAY_SIZE(seal_ops) ||
			    i + 1 == frame_count) {
				ret = trustix_datapath_secure_tx_seal(
					plan, seal_ops, seal_count);
				if (ret)
					goto error;
				seal_count = 0;
			}
		}

		pos += TRUSTIX_DATAPATH_TIXT_HEADER_LEN + inner_len +
		       frame_secure_overhead;
		cursor_payload_offset += seg_payload_len;
	}
	if (pos != packet + outer_len) {
		ret = -EINVAL;
		goto error;
	}
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, 20);
	skb->protocol = htons(ETH_P_IP);
	skb->pkt_type = PACKET_OUTGOING;
	skb->encapsulation = 0;
	skb->csum = 0;
	skb->csum_level = 0;
	outer_iph = (struct iphdr *)skb_network_header(skb);
	outer_tcph = (struct tcphdr *)skb_transport_header(skb);
	outer_tcph->check = ~csum_tcpudp_magic(outer_iph->saddr,
					       outer_iph->daddr, tcp_len,
					       IPPROTO_TCP, 0);
	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum_start = skb_transport_header(skb) - skb->head;
	skb->csum_offset = offsetof(struct tcphdr, check);
	shinfo = skb_shinfo(skb);
	shinfo->gso_size = outer_gso_size;
	shinfo->gso_segs = frame_count;
	shinfo->gso_type = SKB_GSO_TCPV4;
	if (inner_tcp_checksum_partial) {
		if (plan->secure)
			trustix_datapath_secure_tx_inner_tcp_checksum_partial +=
				frame_count;
		else
			trustix_datapath_tx_plaintext_inner_tcp_checksum_partial +=
				frame_count;
	}
	*out_skb = skb;
	*inner_bytes_out = inner_bytes;
	return 0;

error:
	if (plan->secure && ret != -ESTALE)
		trustix_datapath_secure_tx_errors++;
	kfree_skb(skb);
	return ret;
}

static int trustix_datapath_tx_plaintext_outer_tcp_gso_skb(
	struct sk_buff *skb, const struct trustix_datapath_tx_plan *plan,
	struct net_device *target_dev)
{
	struct sk_buff *batches[TRUSTIX_DATAPATH_TX_PLAINTEXT_MAX_GSO_SEGS] = {};
	__u32 inner_lens[TRUSTIX_DATAPATH_TX_PLAINTEXT_MAX_GSO_SEGS] = {};
	const struct tcphdr *tcph;
	const struct iphdr *iph;
	__u32 network_offset;
	__u32 ip_header_len;
	__u32 tcp_header_len;
	__u32 inner_header_len;
	__u32 total_len;
	__u32 tcp_len;
	__u32 payload_len;
	__u32 payload_offset = 0;
	__u32 gso_size;
	__u32 wire_gso_size;
	__u32 seq;
	__u16 ip_id;
	__u8 inner_header[sizeof(struct iphdr) + 60];
	unsigned int expected_segs;
	unsigned int seg_index = 0;
	unsigned int batch_count = 0;
	unsigned int outer_gso_batches = 0;
	unsigned int outer_gso_segments = 0;
	unsigned int max_outer_gso_frames;
	int ret = 0;

	if (!skb || !plan || !target_dev)
		return -EINVAL;
	if (plan->outer_protocol != IPPROTO_TCP)
		return -EPROTONOSUPPORT;
	if (!trustix_datapath_dev_supports_tcpv4_gso(target_dev))
		return -EOPNOTSUPP;
	if (!skb_is_gso(skb))
		return -EINVAL;
	gso_size = skb_shinfo(skb)->gso_size;
	if ((skb_shinfo(skb)->gso_type & SKB_GSO_TCPV4) != SKB_GSO_TCPV4)
		return -EPROTONOSUPPORT;
	network_offset = skb_network_offset(skb);
	if (network_offset > TRUSTIX_DATAPATH_PACKET_MAX_LEN ||
	    !pskb_may_pull(skb, network_offset + sizeof(*iph)))
		return -ENODATA;
	iph = (const struct iphdr *)skb_network_header(skb);
	if (!iph || iph->version != 4 || iph->ihl < 5 ||
	    iph->protocol != IPPROTO_TCP ||
	    (iph->frag_off & htons(0x3fff)))
		return -EPROTONOSUPPORT;
	ip_header_len = iph->ihl * 4;
	if (ip_header_len < sizeof(*iph) ||
	    !pskb_may_pull(skb, network_offset + ip_header_len + sizeof(*tcph)))
		return -ENODATA;
	iph = (const struct iphdr *)skb_network_header(skb);
	tcph = (const struct tcphdr *)((const __u8 *)iph + ip_header_len);
	tcp_header_len = tcph->doff * 4;
	total_len = ntohs(iph->tot_len);
	if (tcp_header_len < sizeof(*tcph) ||
	    total_len < ip_header_len + tcp_header_len ||
	    total_len > skb->len - network_offset ||
	    !pskb_may_pull(skb, network_offset + ip_header_len +
				  tcp_header_len))
		return -EINVAL;
	if (check_add_overflow(ip_header_len, tcp_header_len,
			       &inner_header_len))
		return -EOVERFLOW;
	tcp_len = total_len - ip_header_len;
	payload_len = tcp_len - tcp_header_len;
	if (!payload_len)
		return -EINVAL;
	if (!gso_size || gso_size > payload_len)
		return -EINVAL;
	ret = trustix_datapath_tx_plaintext_gso_payload_size(
		plan, target_dev, ip_header_len, tcp_header_len, gso_size,
		&wire_gso_size);
	if (ret)
		return ret;
	if (!wire_gso_size || wire_gso_size > payload_len)
		return -EINVAL;
	if (wire_gso_size >= payload_len)
		return -EOPNOTSUPP;
	expected_segs = DIV_ROUND_UP(payload_len, wire_gso_size);
	if (expected_segs < 2 ||
	    expected_segs > TRUSTIX_DATAPATH_TX_PLAINTEXT_MAX_GSO_SEGS)
		return -E2BIG;
	ret = trustix_datapath_tx_plaintext_copy_inner_tcp_header(
		skb, network_offset, inner_header_len, inner_header,
		sizeof(inner_header));
	if (ret)
		return ret;
	max_outer_gso_frames =
		trustix_datapath_tx_plaintext_outer_gso_max_frames_value();
	seq = ntohl(tcph->seq);
	ip_id = ntohs(iph->id);

	while (payload_offset < payload_len) {
		__u32 batch_payload_offset = payload_offset;
		__u32 batch_stream_payload_len = 0;
		__u32 batch_inner_bytes = 0;
		unsigned int batch_seg_index = seg_index;
		unsigned int frame_count = 0;
		struct sk_buff *out = NULL;

		while (payload_offset < payload_len) {
			__u32 seg_payload_len;
			__u32 inner_len;
			__u32 frame_len;

			seg_payload_len = min_t(__u32,
						payload_len - payload_offset,
						wire_gso_size);
			if (check_add_overflow(inner_header_len,
					       seg_payload_len, &inner_len) ||
			    check_add_overflow(
				    (__u32)TRUSTIX_DATAPATH_TIXT_HEADER_LEN,
				    inner_len, &frame_len)) {
				ret = -EOVERFLOW;
				goto error;
			}
			if (plan->secure &&
			    check_add_overflow(
				    frame_len,
				    (__u32)TRUSTIX_DATAPATH_SECURE_OVERHEAD,
				    &frame_len)) {
				ret = -EOVERFLOW;
				goto error;
			}
			if (frame_count &&
			    40 + batch_stream_payload_len + frame_len > 0xffffU)
				break;
			if (!frame_count && 40 + frame_len > 0xffffU) {
				ret = -EMSGSIZE;
				goto error;
			}
			if (check_add_overflow(batch_stream_payload_len,
					       frame_len,
					       &batch_stream_payload_len) ||
			    check_add_overflow(batch_inner_bytes, inner_len,
					       &batch_inner_bytes)) {
				ret = -EOVERFLOW;
				goto error;
			}
			frame_count++;
			payload_offset += seg_payload_len;
			seg_index++;
			if (max_outer_gso_frames &&
			    frame_count >= max_outer_gso_frames)
				break;
			if (batch_count + 1 >=
			    TRUSTIX_DATAPATH_TX_PLAINTEXT_MAX_GSO_SEGS)
				break;
		}
		if (!frame_count) {
			ret = -EINVAL;
			goto error;
		}
		if (batch_count >= TRUSTIX_DATAPATH_TX_PLAINTEXT_MAX_GSO_SEGS) {
			ret = -E2BIG;
			goto error;
		}
		if (frame_count >= 2) {
			ret = trustix_datapath_tx_build_outer_tcp_gso_skb(
				skb, plan, network_offset, ip_header_len,
				tcp_header_len, batch_payload_offset,
				payload_len, wire_gso_size, seq, ip_id,
				batch_seg_index, frame_count, &out,
				&batch_inner_bytes);
			if (ret)
				goto error;
			outer_gso_batches++;
			outer_gso_segments += frame_count;
		} else {
			__u32 seg_payload_len = min_t(
				__u32, payload_len - batch_payload_offset,
				wire_gso_size);
			bool last = batch_payload_offset + seg_payload_len >=
				    payload_len;

			ret = trustix_datapath_tx_build_outer_tcp_segment_skb(
				skb, plan, network_offset, ip_header_len,
				tcp_header_len, batch_payload_offset,
				seg_payload_len, seq, ip_id, batch_seg_index,
				last, &out);
			if (ret)
				goto error;
			batch_inner_bytes = inner_header_len + seg_payload_len;
		}
		batches[batch_count] = out;
		inner_lens[batch_count] = batch_inner_bytes;
		batch_count++;
	}
	if (seg_index != expected_segs) {
		ret = -EINVAL;
		goto error;
	}
	ret = trustix_datapath_tx_plaintext_enqueue_many(
		batches, inner_lens, batch_count, target_dev, plan);
	if (ret)
		goto error;
	trustix_datapath_tx_plaintext_gso_segments += seg_index;
	trustix_datapath_tx_plaintext_outer_gso_packets += outer_gso_batches;
	trustix_datapath_tx_plaintext_outer_gso_segments +=
		outer_gso_segments;
	return 0;

error:
	while (batch_count > 0) {
		batch_count--;
		kfree_skb(batches[batch_count]);
		batches[batch_count] = NULL;
	}
	if (ret != -ESTALE)
		trustix_datapath_tx_plaintext_outer_gso_errors++;
	return ret;
}

static int trustix_datapath_tx_plaintext_outer_udp_gso_skb(
	struct sk_buff *skb, const struct trustix_datapath_tx_plan *plan,
	struct net_device *target_dev)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
	struct sk_buff *batches[TRUSTIX_DATAPATH_TX_PLAINTEXT_MAX_GSO_SEGS] = {};
	__u32 inner_lens[TRUSTIX_DATAPATH_TX_PLAINTEXT_MAX_GSO_SEGS] = {};
	struct skb_shared_info *shinfo;
	const struct tcphdr *tcph;
	const struct iphdr *iph;
	__u32 network_offset;
	__u32 ip_header_len;
	__u32 tcp_header_len;
	__u32 inner_header_len;
	__u32 total_len;
	__u32 tcp_len;
	__u32 payload_len;
	__u32 payload_offset = 0;
	__u32 gso_size;
	__u32 wire_gso_size;
	__u32 seq;
	__u16 ip_id;
	__u8 inner_header[sizeof(struct iphdr) + 60];
	unsigned int expected_segs;
	unsigned int seg_index = 0;
	unsigned int batch_count = 0;
	unsigned int outer_gso_batches = 0;
	unsigned int outer_gso_segments = 0;
	unsigned int max_outer_gso_frames;
	bool fix_inner_tcp_checksum;
	bool inner_tcp_checksum_partial;
	int ret = 0;

	if (!skb || !plan || !target_dev)
		return -EINVAL;
	if (plan->outer_protocol != IPPROTO_UDP)
		return -EPROTONOSUPPORT;
	inner_tcp_checksum_partial =
		trustix_datapath_tx_plaintext_inner_tcp_checksum_partial_enabled(
			plan);
	fix_inner_tcp_checksum = !inner_tcp_checksum_partial &&
		!READ_ONCE(
			trustix_datapath_tx_plaintext_skip_inner_tcp_checksum);
	if (!skb_is_gso(skb))
		return -EINVAL;
	gso_size = skb_shinfo(skb)->gso_size;
	if ((skb_shinfo(skb)->gso_type & SKB_GSO_TCPV4) != SKB_GSO_TCPV4)
		return -EPROTONOSUPPORT;
	network_offset = skb_network_offset(skb);
	if (network_offset > TRUSTIX_DATAPATH_PACKET_MAX_LEN ||
	    !pskb_may_pull(skb, network_offset + sizeof(*iph)))
		return -ENODATA;
	iph = (const struct iphdr *)skb_network_header(skb);
	if (!iph || iph->version != 4 || iph->ihl < 5 ||
	    iph->protocol != IPPROTO_TCP ||
	    (iph->frag_off & htons(0x3fff)))
		return -EPROTONOSUPPORT;
	ip_header_len = iph->ihl * 4;
	if (ip_header_len < sizeof(*iph) ||
	    !pskb_may_pull(skb, network_offset + ip_header_len + sizeof(*tcph)))
		return -ENODATA;
	iph = (const struct iphdr *)skb_network_header(skb);
	tcph = (const struct tcphdr *)((const __u8 *)iph + ip_header_len);
	tcp_header_len = tcph->doff * 4;
	total_len = ntohs(iph->tot_len);
	if (tcp_header_len < sizeof(*tcph) ||
	    total_len < ip_header_len + tcp_header_len ||
	    total_len > skb->len - network_offset ||
	    !pskb_may_pull(skb, network_offset + ip_header_len +
				  tcp_header_len))
		return -EINVAL;
	if (check_add_overflow(ip_header_len, tcp_header_len,
			       &inner_header_len))
		return -EOVERFLOW;
	tcp_len = total_len - ip_header_len;
	payload_len = tcp_len - tcp_header_len;
	if (!payload_len)
		return -EINVAL;
	if (!gso_size || gso_size > payload_len)
		return -EINVAL;
	ret = trustix_datapath_tx_plaintext_gso_payload_size(
		plan, target_dev, ip_header_len, tcp_header_len, gso_size,
		&wire_gso_size);
	if (ret)
		return ret;
	if (!wire_gso_size || wire_gso_size > payload_len)
		return -EINVAL;
	if (wire_gso_size >= payload_len)
		return -EOPNOTSUPP;
	expected_segs = DIV_ROUND_UP(payload_len, wire_gso_size);
	if (expected_segs < 2 ||
	    expected_segs > TRUSTIX_DATAPATH_TX_PLAINTEXT_MAX_GSO_SEGS)
		return -E2BIG;
	ret = trustix_datapath_tx_plaintext_copy_inner_tcp_header(
		skb, network_offset, inner_header_len, inner_header,
		sizeof(inner_header));
	if (ret)
		return ret;
	max_outer_gso_frames =
		trustix_datapath_tx_plaintext_outer_gso_max_frames_value();
	seq = ntohl(tcph->seq);
	ip_id = ntohs(iph->id);

	while (payload_offset < payload_len) {
		struct sk_buff *out = NULL;
		struct udphdr *outer_udph;
		struct iphdr *outer_iph;
		__u8 *packet;
		__u8 *pos;
		__u32 batch_payload_offset = payload_offset;
		__u32 batch_stream_payload_len = 0;
		__u32 batch_inner_bytes = 0;
		__u32 outer_len;
		__u32 udp_len;
		__u32 outer_gso_size;
		unsigned int batch_seg_index = seg_index;
		unsigned int frame_count = 0;
		unsigned int i;

		if (check_add_overflow(inner_header_len, wire_gso_size,
				       &outer_gso_size) ||
		    check_add_overflow((__u32)TRUSTIX_DATAPATH_TIXT_HEADER_LEN,
				       outer_gso_size, &outer_gso_size)) {
			ret = -EOVERFLOW;
			goto error;
		}
		while (payload_offset < payload_len) {
			__u32 seg_payload_len;
			__u32 inner_len;
			__u32 frame_len;

			seg_payload_len = min_t(__u32,
						payload_len - payload_offset,
						wire_gso_size);
			if (check_add_overflow(inner_header_len,
					       seg_payload_len, &inner_len) ||
			    check_add_overflow(
				    (__u32)TRUSTIX_DATAPATH_TIXT_HEADER_LEN,
				    inner_len, &frame_len)) {
				ret = -EOVERFLOW;
				goto error;
			}
			if (frame_count &&
			    28 + batch_stream_payload_len + frame_len > 0xffffU)
				break;
			if (!frame_count && 28 + frame_len > 0xffffU) {
				ret = -EMSGSIZE;
				goto error;
			}
			if (frame_count && frame_len != outer_gso_size)
				break;
			if (check_add_overflow(batch_stream_payload_len,
					       frame_len,
					       &batch_stream_payload_len) ||
			    check_add_overflow(batch_inner_bytes, inner_len,
					       &batch_inner_bytes)) {
				ret = -EOVERFLOW;
				goto error;
			}
			frame_count++;
			payload_offset += seg_payload_len;
			seg_index++;
			if (max_outer_gso_frames &&
			    frame_count >= max_outer_gso_frames)
				break;
			if (batch_count + 1 >=
			    TRUSTIX_DATAPATH_TX_PLAINTEXT_MAX_GSO_SEGS)
				break;
		}
		if (!frame_count) {
			ret = -EINVAL;
			goto error;
		}
		if (batch_count >= TRUSTIX_DATAPATH_TX_PLAINTEXT_MAX_GSO_SEGS) {
			ret = -E2BIG;
			goto error;
		}
		if (frame_count < 2) {
			__u32 seg_payload_len = min_t(
				__u32, payload_len - batch_payload_offset,
				wire_gso_size);
			bool last = batch_payload_offset + seg_payload_len >=
				    payload_len;

			ret = trustix_datapath_tx_build_outer_tcp_segment_skb(
				skb, plan, network_offset, ip_header_len,
				tcp_header_len, batch_payload_offset,
				seg_payload_len, seq, ip_id, batch_seg_index,
				last, &out);
			if (ret)
				goto error;
			batch_inner_bytes = inner_header_len + seg_payload_len;
			batches[batch_count] = out;
			inner_lens[batch_count] = batch_inner_bytes;
			batch_count++;
			continue;
		}
		if (check_add_overflow((__u32)sizeof(struct iphdr) +
					       sizeof(struct udphdr),
				       batch_stream_payload_len, &outer_len) ||
		    check_add_overflow((__u32)sizeof(struct udphdr),
				       batch_stream_payload_len, &udp_len)) {
			ret = -EOVERFLOW;
			goto error;
		}
		if (outer_len > 0xffffU) {
			ret = -EMSGSIZE;
			goto error;
		}
		out = alloc_skb(LL_MAX_HEADER + outer_len, GFP_ATOMIC);
		if (!out) {
			ret = -ENOMEM;
			goto error;
		}
		skb_reserve(out, LL_MAX_HEADER);
		packet = skb_put(out, outer_len);
		memset(packet, 0, sizeof(struct iphdr) + sizeof(struct udphdr));
		trustix_datapath_build_outer_ipv4(packet, outer_len,
						  IPPROTO_UDP,
						  plan->local_ipv4,
						  plan->remote_ipv4);
		trustix_datapath_put_be16(packet + 20, plan->local_port);
		trustix_datapath_put_be16(packet + 22, plan->remote_port);
		trustix_datapath_put_be16(packet + 24, udp_len);
		pos = packet + sizeof(struct iphdr) + sizeof(struct udphdr);
		payload_offset = batch_payload_offset;
		for (i = 0; i < frame_count; i++) {
			struct tcphdr *seg_tcph;
			struct iphdr *seg_iph;
			__u8 *tixt = pos;
			__u32 seg_payload_len;
			__u32 inner_len;
			bool last_segment;
			__u64 sequence;

			seg_payload_len = min_t(__u32,
						payload_len - payload_offset,
						wire_gso_size);
			inner_len = inner_header_len + seg_payload_len;
			last_segment = payload_offset + seg_payload_len >=
				       payload_len;
			sequence = (__u64)atomic64_inc_return(
				&trustix_datapath_tx_sequence);
			trustix_datapath_build_tixt_header(
				tixt,
				trustix_datapath_tx_plaintext_tixt_flags(
					fix_inner_tcp_checksum,
					inner_tcp_checksum_partial),
				plan->flow_id, plan->epoch, sequence,
				inner_len, 0, 0);
			memcpy(tixt + TRUSTIX_DATAPATH_TIXT_HEADER_LEN,
			       inner_header, inner_header_len);
			ret = trustix_datapath_tx_plaintext_copy_payload(
				skb, network_offset + inner_header_len +
					     payload_offset,
				tixt + TRUSTIX_DATAPATH_TIXT_HEADER_LEN +
					inner_header_len,
				seg_payload_len, false, NULL);
			if (ret) {
				kfree_skb(out);
				goto error;
			}
			seg_iph = (struct iphdr *)(tixt +
						   TRUSTIX_DATAPATH_TIXT_HEADER_LEN);
			seg_tcph = (struct tcphdr *)((__u8 *)seg_iph +
						     ip_header_len);
			seg_iph->tot_len = htons((__u16)inner_len);
			seg_iph->id = htons(ip_id + batch_seg_index + i);
			trustix_datapath_rx_worker_fix_ipv4_header_checksum(
				seg_iph, ip_header_len);
			seg_tcph->seq = htonl(seq + payload_offset);
			if (!last_segment) {
				seg_tcph->fin = 0;
				seg_tcph->psh = 0;
			}
			seg_tcph->check = 0;
			if (inner_tcp_checksum_partial)
				seg_tcph->check = ~csum_tcpudp_magic(
					seg_iph->saddr, seg_iph->daddr,
					tcp_header_len + seg_payload_len,
					IPPROTO_TCP, 0);
			else if (fix_inner_tcp_checksum)
				seg_tcph->check =
					trustix_datapath_rx_worker_l4_checksum(
						seg_iph, seg_tcph,
						tcp_header_len + seg_payload_len,
						IPPROTO_TCP);
			pos += TRUSTIX_DATAPATH_TIXT_HEADER_LEN + inner_len;
			payload_offset += seg_payload_len;
		}
		if (pos != packet + outer_len) {
			kfree_skb(out);
			ret = -EINVAL;
			goto error;
		}
		skb_reset_network_header(out);
		skb_set_transport_header(out, sizeof(struct iphdr));
		out->protocol = htons(ETH_P_IP);
		out->pkt_type = PACKET_OUTGOING;
		out->encapsulation = 0;
		out->csum = 0;
		out->csum_level = 0;
		outer_iph = (struct iphdr *)skb_network_header(out);
		outer_udph = (struct udphdr *)skb_transport_header(out);
		outer_udph->check = ~csum_tcpudp_magic(
			outer_iph->saddr, outer_iph->daddr, udp_len,
			IPPROTO_UDP, 0);
		out->ip_summed = CHECKSUM_PARTIAL;
		out->csum_start = skb_transport_header(out) - out->head;
		out->csum_offset = offsetof(struct udphdr, check);
		shinfo = skb_shinfo(out);
		shinfo->gso_size = outer_gso_size;
		shinfo->gso_segs = frame_count;
		shinfo->gso_type = SKB_GSO_UDP_L4;
		if (inner_tcp_checksum_partial)
			trustix_datapath_tx_plaintext_inner_tcp_checksum_partial +=
				frame_count;
		batches[batch_count] = out;
		inner_lens[batch_count] = batch_inner_bytes;
		batch_count++;
		outer_gso_batches++;
		outer_gso_segments += frame_count;
	}
	if (seg_index != expected_segs) {
		ret = -EINVAL;
		goto error;
	}
	ret = trustix_datapath_tx_plaintext_enqueue_many(
		batches, inner_lens, batch_count, target_dev, plan);
	if (ret)
		goto error;
	trustix_datapath_tx_plaintext_gso_segments += seg_index;
	trustix_datapath_tx_plaintext_outer_gso_packets += outer_gso_batches;
	trustix_datapath_tx_plaintext_outer_gso_segments +=
		outer_gso_segments;
	return 0;

error:
	while (batch_count > 0) {
		batch_count--;
		kfree_skb(batches[batch_count]);
		batches[batch_count] = NULL;
	}
	if (ret != -ESTALE)
		trustix_datapath_tx_plaintext_outer_gso_errors++;
	return ret;
#else
	return -EOPNOTSUPP;
#endif
}

static int trustix_datapath_tx_plaintext_gso_skb(
	struct sk_buff *skb, const struct trustix_datapath_tx_plan *plan,
	struct net_device *target_dev)
{
	int ret;

	if (plan && plan->outer_protocol == IPPROTO_TCP) {
		ret = trustix_datapath_tx_plaintext_inner_gso_skb(
			skb, plan, target_dev);
		if (!ret)
			return 0;
		if (ret == -ESTALE)
			return ret;
	}
	if (plan && plan->outer_protocol == IPPROTO_UDP)
		ret = trustix_datapath_tx_plaintext_outer_udp_gso_skb(
			skb, plan, target_dev);
	else
		ret = trustix_datapath_tx_plaintext_outer_tcp_gso_skb(
			skb, plan, target_dev);
	if (!ret)
		return 0;
	if (ret == -ESTALE)
		return ret;
	trustix_datapath_tx_plaintext_outer_gso_fallbacks++;
	return trustix_datapath_tx_plaintext_segment_tcp_skb(
		skb, plan, target_dev, 0, true);
}

static unsigned int
trustix_datapath_tx_plaintext_coalesce_max_frames_value(void)
{
	unsigned int value = READ_ONCE(
		trustix_datapath_tx_plaintext_stream_coalesce_max_frames);

	if (value < 2)
		return 2;
	if (value > TRUSTIX_DATAPATH_TX_PLAINTEXT_COALESCE_MAX_FRAMES)
		return TRUSTIX_DATAPATH_TX_PLAINTEXT_COALESCE_MAX_FRAMES;
	return value;
}

static unsigned int
trustix_datapath_tx_plaintext_outer_gso_max_frames_value(void)
{
	unsigned int value = READ_ONCE(
		trustix_datapath_tx_plaintext_outer_gso_max_frames);

	if (!value)
		return 0;
	if (value < 2)
		return 2;
	if (value > TRUSTIX_DATAPATH_TX_PLAINTEXT_MAX_GSO_SEGS)
		return TRUSTIX_DATAPATH_TX_PLAINTEXT_MAX_GSO_SEGS;
	return value;
}

static unsigned long
trustix_datapath_tx_plaintext_coalesce_flush_delay(void)
{
	unsigned int value = READ_ONCE(
		trustix_datapath_tx_plaintext_stream_coalesce_flush_jiffies);

	if (value > HZ)
		return HZ;
	return value;
}

static bool trustix_datapath_tx_plaintext_stream_coalesce_supported(
	const struct trustix_datapath_tx_plan *plan, struct net_device *target_dev)
{
	if (!plan)
		return false;
	switch (plan->outer_protocol) {
	case IPPROTO_TCP:
		return trustix_datapath_dev_supports_tcpv4_gso(target_dev);
	case IPPROTO_UDP:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
		return true;
#else
		return false;
#endif
	default:
		return false;
	}
}

static bool trustix_datapath_tx_plaintext_plan_equal(
	const struct trustix_datapath_tx_plan *left,
	const struct trustix_datapath_tx_plan *right)
{
	if (!left || !right)
		return false;
	return left->flow_id == right->flow_id &&
	       left->secure == right->secure &&
	       left->epoch == right->epoch &&
	       left->session_flags == right->session_flags &&
	       left->send_generation == right->send_generation &&
	       left->inner_flow_hash == right->inner_flow_hash &&
	       left->outer_tcp_sequence_flow_slot ==
		       right->outer_tcp_sequence_flow_slot &&
	       left->send_slot == right->send_slot &&
	       left->local_ipv4 == right->local_ipv4 &&
	       left->remote_ipv4 == right->remote_ipv4 &&
	       left->local_port == right->local_port &&
	       left->remote_port == right->remote_port &&
	       left->suite == right->suite &&
	       left->wire_format == right->wire_format &&
	       left->outer_protocol == right->outer_protocol &&
	       left->outer_tcp_port_shard == right->outer_tcp_port_shard &&
	       !memcmp(left->send_iv, right->send_iv,
		       sizeof(left->send_iv)) &&
	       left->max_packet_size == right->max_packet_size;
}

static __u32 trustix_datapath_tx_plaintext_coalesce_hash(
	const struct trustix_datapath_rx_worker_coalesce_state *state,
	const struct trustix_datapath_tx_plan *plan, int target_ifindex)
{
	__u32 hash;

	if (!state || !plan)
		return 0;
	hash = (__force __u32)state->saddr ^
	       ((__force __u32)state->daddr << 7) ^
	       ((__force __u32)state->daddr >> 9) ^
	       ((__force __u16)state->source << 16) ^
	       (__force __u16)state->dest ^ (__u32)target_ifindex ^
	       (__u32)plan->flow_id ^ ((__u32)(plan->flow_id >> 32) << 3) ^
	       ((__u32)plan->epoch << 11) ^ plan->local_ipv4 ^
	       (plan->remote_ipv4 << 5) ^ ((__u32)plan->local_port << 16) ^
	       plan->remote_port;
	hash ^= hash >> 16;
	hash *= 0x7feb352dU;
	hash ^= hash >> 15;
	return hash ?: 1;
}

static void
trustix_datapath_tx_plaintext_coalesce_detach_locked(
	struct trustix_datapath_tx_plaintext_coalesce_slot *slot,
	struct net_device **target_dev, __u8 **packets, __u32 *lens,
	unsigned int *frames, struct trustix_datapath_tx_plan *plan,
	struct trustix_datapath_rx_worker_coalesce_state *state)
{
	unsigned int i;

	if (target_dev)
		*target_dev = NULL;
	if (packets) {
		for (i = 0; i < TRUSTIX_DATAPATH_TX_PLAINTEXT_COALESCE_MAX_FRAMES;
		     i++)
			packets[i] = NULL;
	}
	if (lens)
		memset(lens, 0, sizeof(__u32) *
				  TRUSTIX_DATAPATH_TX_PLAINTEXT_COALESCE_MAX_FRAMES);
	if (frames)
		*frames = 0;
	if (plan)
		memset(plan, 0, sizeof(*plan));
	if (state)
		memset(state, 0, sizeof(*state));
	if (!slot || !slot->valid)
		return;

	if (target_dev)
		*target_dev = slot->target_dev;
	else if (slot->target_dev)
		dev_put(slot->target_dev);
	if (packets) {
		for (i = 0; i < TRUSTIX_DATAPATH_TX_PLAINTEXT_COALESCE_MAX_FRAMES;
		     i++)
			packets[i] = slot->packets[i];
	} else {
		for (i = 0; i < TRUSTIX_DATAPATH_TX_PLAINTEXT_COALESCE_MAX_FRAMES;
		     i++)
			kfree(slot->packets[i]);
	}
	if (lens)
		memcpy(lens, slot->lens,
		       sizeof(__u32) *
			       TRUSTIX_DATAPATH_TX_PLAINTEXT_COALESCE_MAX_FRAMES);
	if (frames)
		*frames = slot->frames;
	if (plan)
		*plan = slot->plan;
	if (state)
		*state = slot->state;

	slot->valid = false;
	slot->target_dev = NULL;
	slot->target_ifindex = 0;
	slot->hash = 0;
	memset(&slot->plan, 0, sizeof(slot->plan));
	memset(&slot->state, 0, sizeof(slot->state));
	for (i = 0; i < TRUSTIX_DATAPATH_TX_PLAINTEXT_COALESCE_MAX_FRAMES;
	     i++) {
		slot->packets[i] = NULL;
		slot->lens[i] = 0;
	}
	slot->frames = 0;
}

static bool trustix_datapath_tx_plaintext_coalesce_store_locked(
	struct trustix_datapath_tx_plaintext_coalesce_slot *slot,
	struct net_device *target_dev, int target_ifindex, __u32 hash,
	const struct trustix_datapath_tx_plan *plan,
	const struct trustix_datapath_rx_worker_coalesce_state *state,
	__u8 **packet, __u32 len)
{
	if (!slot || slot->valid || !target_dev || !plan || !state ||
	    !state->active || !packet || !*packet || !len)
		return false;

	dev_hold(target_dev);
	slot->valid = true;
	slot->target_dev = target_dev;
	slot->target_ifindex = target_ifindex;
	slot->hash = hash;
	slot->plan = *plan;
	slot->state = *state;
	slot->packets[0] = *packet;
	slot->lens[0] = len;
	slot->frames = 1;
	*packet = NULL;
	trustix_datapath_tx_plaintext_stream_coalesce_stored++;
	return true;
}

static struct sk_buff *
trustix_datapath_tx_plaintext_inner_packet_skb(
	struct net_device *target_dev, const __u8 *packet, __u32 len)
{
	struct sk_buff *skb;
	struct iphdr *iph;

	skb = trustix_datapath_rx_worker_build_inner_skb(target_dev, packet,
							 len);
	if (!skb)
		return NULL;
	if (!pskb_may_pull(skb, sizeof(*iph))) {
		kfree_skb(skb);
		return NULL;
	}
	iph = (struct iphdr *)skb->data;
	if (iph->version != 4 || iph->ihl < 5 || len < iph->ihl * 4) {
		kfree_skb(skb);
		return NULL;
	}
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, iph->ihl * 4);
	return skb;
}

static int trustix_datapath_tx_plaintext_coalesce_xmit_singles(
	struct net_device *target_dev, const struct trustix_datapath_tx_plan *plan,
	__u8 **packets, const __u32 *lens, unsigned int frames)
{
	struct sk_buff *outer_skbs[TRUSTIX_DATAPATH_TX_PLAINTEXT_COALESCE_MAX_FRAMES];
	__u32 inner_lens[TRUSTIX_DATAPATH_TX_PLAINTEXT_COALESCE_MAX_FRAMES];
	unsigned int outer_count = 0;
	unsigned int i;
	int ret = 0;

	memset(outer_skbs, 0, sizeof(outer_skbs));
	memset(inner_lens, 0, sizeof(inner_lens));
	if (!target_dev || !plan || !packets || !lens || !frames)
		return -EINVAL;

	for (i = 0; i < frames; i++) {
		struct sk_buff *inner_skb;
		bool outer_exceeds = false;

		if (!packets[i] || !lens[i])
			continue;
		inner_skb = trustix_datapath_tx_plaintext_inner_packet_skb(
			target_dev, packets[i], lens[i]);
		if (!inner_skb) {
			ret = -ENOMEM;
			goto error;
		}
		ret = trustix_datapath_tx_plaintext_outer_exceeds_packet_limit(
			plan, target_dev, lens[i], &outer_exceeds);
		if (!ret && outer_exceeds) {
			ret = trustix_datapath_tx_plaintext_segment_tcp_skb(
				inner_skb, plan, target_dev, 0, false);
			kfree_skb(inner_skb);
			if (ret)
				goto error;
			continue;
		}
		if (ret) {
			kfree_skb(inner_skb);
			goto error;
		}
		ret = trustix_datapath_tx_build_outer_skb(
			inner_skb, plan, lens[i], &outer_skbs[outer_count]);
		kfree_skb(inner_skb);
		if (ret)
			goto error;
		inner_lens[outer_count] = lens[i];
		outer_count++;
	}

	if (outer_count) {
		ret = trustix_datapath_tx_plaintext_enqueue_many(
			outer_skbs, inner_lens, outer_count, target_dev, plan);
		if (ret)
			goto error;
	}
	return 0;

error:
	while (outer_count > 0) {
		outer_count--;
		kfree_skb(outer_skbs[outer_count]);
		outer_skbs[outer_count] = NULL;
	}
	if (ret != -ESTALE)
		trustix_datapath_tx_plaintext_stream_coalesce_errors++;
	return ret;
}

static int trustix_datapath_tx_plaintext_coalesce_xmit_packets(
	struct net_device *target_dev, __u8 **packets, __u32 *lens,
	unsigned int frames,
	const struct trustix_datapath_rx_worker_coalesce_state *state,
	const struct trustix_datapath_tx_plan *plan)
{
	struct trustix_datapath_rx_worker_pending_copy
		pending[TRUSTIX_DATAPATH_TX_PLAINTEXT_COALESCE_MAX_FRAMES];
	struct sk_buff *inner_skb;
	unsigned int i;
	int ret;

	if (!target_dev || !packets || !lens || !state || !state->active ||
	    !plan || frames < 1 ||
	    frames > TRUSTIX_DATAPATH_TX_PLAINTEXT_COALESCE_MAX_FRAMES)
		return -EINVAL;
	if (frames < 2)
		return trustix_datapath_tx_plaintext_coalesce_xmit_singles(
			target_dev, plan, packets, lens, frames);

	memset(pending, 0, sizeof(pending));
	for (i = 0; i < frames; i++) {
		if (!packets[i] || !lens[i])
			return -EINVAL;
		pending[i].source_packet = packets[i];
		pending[i].len = lens[i];
	}
	inner_skb = trustix_datapath_rx_worker_build_coalesced_gso_skb(
		target_dev, state, pending, frames, false);
	if (!inner_skb) {
		trustix_datapath_tx_plaintext_stream_coalesce_errors++;
		return trustix_datapath_tx_plaintext_coalesce_xmit_singles(
			target_dev, plan, packets, lens, frames);
	}
	ret = trustix_datapath_tx_plaintext_gso_skb(inner_skb, plan,
						   target_dev);
	kfree_skb(inner_skb);
	if (!ret) {
		trustix_datapath_tx_plaintext_stream_coalesce_packets++;
		trustix_datapath_tx_plaintext_stream_coalesce_frames += frames;
		return 0;
	}
	if (ret == -ESTALE)
		return ret;
	trustix_datapath_tx_plaintext_stream_coalesce_errors++;
	return trustix_datapath_tx_plaintext_coalesce_xmit_singles(
		target_dev, plan, packets, lens, frames);
}

static void
trustix_datapath_tx_plaintext_coalesce_free_detached(
	struct net_device *target_dev, __u8 **packets, unsigned int frames)
{
	unsigned int i;

	if (packets) {
		for (i = 0; i < frames &&
			    i < TRUSTIX_DATAPATH_TX_PLAINTEXT_COALESCE_MAX_FRAMES;
		     i++) {
			kfree(packets[i]);
			packets[i] = NULL;
		}
	}
	if (target_dev)
		dev_put(target_dev);
}

static void
trustix_datapath_tx_plaintext_coalesce_flush_slot(
	struct trustix_datapath_tx_plaintext_coalesce_slot *slot)
{
	struct net_device *target_dev = NULL;
	unsigned long flags;
	__u8 *packets[TRUSTIX_DATAPATH_TX_PLAINTEXT_COALESCE_MAX_FRAMES];
	__u32 lens[TRUSTIX_DATAPATH_TX_PLAINTEXT_COALESCE_MAX_FRAMES];
	struct trustix_datapath_tx_plan plan = {};
	struct trustix_datapath_rx_worker_coalesce_state state = {};
	unsigned int frames = 0;

	if (!slot)
		return;
	spin_lock_irqsave(&slot->lock, flags);
	trustix_datapath_tx_plaintext_coalesce_detach_locked(
		slot, &target_dev, packets, lens, &frames, &plan, &state);
	spin_unlock_irqrestore(&slot->lock, flags);
	if (frames && target_dev) {
		trustix_datapath_tx_plaintext_stream_coalesce_timer_flushes++;
		if (frames < 2)
			trustix_datapath_tx_plaintext_stream_coalesce_single_flushes++;
		else
			trustix_datapath_tx_plaintext_stream_coalesce_multi_flushes++;
		trustix_datapath_tx_plaintext_coalesce_xmit_packets(
			target_dev, packets, lens, frames, &state, &plan);
	}
	trustix_datapath_tx_plaintext_coalesce_free_detached(target_dev,
							    packets, frames);
}

static void trustix_datapath_tx_plaintext_coalesce_flush_work(
	struct work_struct *work)
{
	struct delayed_work *dwork = to_delayed_work(work);
	struct trustix_datapath_tx_plaintext_coalesce_slot *slot =
		container_of(dwork,
			     struct trustix_datapath_tx_plaintext_coalesce_slot,
			     flush_work);

	trustix_datapath_tx_plaintext_coalesce_flush_slot(slot);
}

static void trustix_datapath_tx_plaintext_coalesce_drop_all(void)
{
	struct net_device *target_dev = NULL;
	unsigned long flags;
	__u8 *packets[TRUSTIX_DATAPATH_TX_PLAINTEXT_COALESCE_MAX_FRAMES];
	__u32 lens[TRUSTIX_DATAPATH_TX_PLAINTEXT_COALESCE_MAX_FRAMES];
	unsigned int frames = 0;
	unsigned int i;

	for (i = 0; i < TRUSTIX_DATAPATH_TX_PLAINTEXT_COALESCE_SLOTS; i++) {
		struct trustix_datapath_tx_plaintext_coalesce_slot *slot =
			&trustix_datapath_tx_plaintext_coalesce_slots[i];

		cancel_delayed_work_sync(&slot->flush_work);
		spin_lock_irqsave(&slot->lock, flags);
		trustix_datapath_tx_plaintext_coalesce_detach_locked(
			slot, &target_dev, packets, lens, &frames, NULL, NULL);
		spin_unlock_irqrestore(&slot->lock, flags);
		trustix_datapath_tx_plaintext_coalesce_free_detached(
			target_dev, packets, frames);
		target_dev = NULL;
		frames = 0;
	}
}

static bool trustix_datapath_tx_plaintext_coalesce_skb(
	struct sk_buff *skb,
	const struct trustix_datapath_ioc_classify *classify,
	int target_ifindex, struct net_device *target_dev,
	const struct trustix_datapath_tx_plan *plan, __u32 inner_len)
{
	struct trustix_datapath_rx_worker_coalesce_state cur_state = {};
	struct trustix_datapath_rx_worker_coalesce_state merged = {};
	struct trustix_datapath_tx_plaintext_coalesce_slot *slot;
	struct net_device *held_dev = NULL;
	__u8 *held_packets[TRUSTIX_DATAPATH_TX_PLAINTEXT_COALESCE_MAX_FRAMES];
	__u32 held_lens[TRUSTIX_DATAPATH_TX_PLAINTEXT_COALESCE_MAX_FRAMES];
	struct trustix_datapath_tx_plan held_plan = {};
	struct trustix_datapath_rx_worker_coalesce_state held_state = {};
	unsigned int held_frames = 0;
	unsigned int max_frames;
	unsigned long flags;
	__u8 *packet = NULL;
	__u32 hash;
	bool appended = false;
	bool stored = false;
	bool flush_with_current = false;
	int ret;

	if (!READ_ONCE(trustix_datapath_tx_plaintext_stream_coalesce) ||
	    !skb || !classify || !target_dev || !plan ||
	    classify->protocol != IPPROTO_TCP ||
	    !trustix_datapath_tx_plaintext_stream_coalesce_supported(
		    plan, target_dev) ||
	    !inner_len ||
	    skb_is_gso(skb))
		return false;
	trustix_datapath_tx_plaintext_stream_coalesce_attempts++;
	packet = kmalloc(inner_len, GFP_ATOMIC);
	if (!packet)
		return false;
	ret = skb_copy_bits(skb, skb_network_offset(skb), packet, inner_len);
	if (ret)
		goto miss;
	ret = trustix_datapath_rx_worker_coalesce_accept(&cur_state, packet,
							 inner_len);
	if (ret) {
		if (ret == -EPROTONOSUPPORT && inner_len >= sizeof(struct iphdr) +
			    sizeof(struct tcphdr)) {
			const struct iphdr *miss_iph =
				(const struct iphdr *)packet;
			if (miss_iph->version == 4 && miss_iph->ihl >= 5 &&
			    miss_iph->protocol == IPPROTO_TCP &&
			    inner_len >= (__u32)miss_iph->ihl * 4 +
					    sizeof(struct tcphdr)) {
				const struct tcphdr *miss_tcph =
					(const struct tcphdr *)(packet +
						miss_iph->ihl * 4);
				__u32 miss_total_len = ntohs(miss_iph->tot_len);
				__u32 miss_tcp_header_len = miss_tcph->doff * 4;
				if (miss_total_len >= (__u32)miss_iph->ihl * 4 +
						       miss_tcp_header_len &&
				    miss_total_len <= inner_len &&
				    miss_tcp_header_len >= sizeof(*miss_tcph) &&
				    miss_tcp_header_len <= 60) {
					__u32 miss_payload_len =
						miss_total_len -
						(__u32)miss_iph->ihl * 4 -
						miss_tcp_header_len;
					if (!miss_payload_len && miss_tcph->ack &&
					    !miss_tcph->syn && !miss_tcph->fin &&
					    !miss_tcph->rst)
						trustix_datapath_tx_plaintext_stream_coalesce_ack_only_frames++;
				}
			}
		}
		goto miss;
	}
	trustix_datapath_tx_plaintext_stream_coalesce_payload_frames++;

	hash = trustix_datapath_tx_plaintext_coalesce_hash(&cur_state, plan,
							   target_ifindex);
	slot = &trustix_datapath_tx_plaintext_coalesce_slots
			[hash & (TRUSTIX_DATAPATH_TX_PLAINTEXT_COALESCE_SLOTS - 1)];
	max_frames = trustix_datapath_tx_plaintext_coalesce_max_frames_value();

	spin_lock_irqsave(&slot->lock, flags);
	if (slot->valid) {
		merged = slot->state;
		if (slot->target_dev == target_dev &&
		    slot->target_ifindex == target_ifindex &&
		    slot->hash == hash &&
		    trustix_datapath_tx_plaintext_plan_equal(&slot->plan,
							     plan) &&
		    !trustix_datapath_rx_worker_coalesce_accept(&merged,
								packet,
								inner_len)) {
			trustix_datapath_tx_plaintext_stream_coalesce_slot_hits++;
			if (slot->frames + 1 >= max_frames) {
				trustix_datapath_tx_plaintext_coalesce_detach_locked(
					slot, &held_dev, held_packets,
					held_lens, &held_frames, &held_plan,
					&held_state);
				held_state = merged;
				flush_with_current = true;
				trustix_datapath_tx_plaintext_stream_coalesce_full_flushes++;
			} else {
				slot->state = merged;
				slot->packets[slot->frames] = packet;
				slot->lens[slot->frames] = inner_len;
				slot->frames++;
				packet = NULL;
				appended = true;
				trustix_datapath_tx_plaintext_stream_coalesce_stored++;
			}
		} else {
			trustix_datapath_tx_plaintext_stream_coalesce_slot_conflicts++;
			trustix_datapath_tx_plaintext_stream_coalesce_misses++;
			trustix_datapath_tx_plaintext_coalesce_detach_locked(
				slot, &held_dev, held_packets, held_lens,
				&held_frames, &held_plan, &held_state);
			stored = trustix_datapath_tx_plaintext_coalesce_store_locked(
				slot, target_dev, target_ifindex, hash, plan,
				&cur_state, &packet, inner_len);
		}
	} else {
		stored = trustix_datapath_tx_plaintext_coalesce_store_locked(
			slot, target_dev, target_ifindex, hash, plan, &cur_state,
			&packet, inner_len);
	}
	spin_unlock_irqrestore(&slot->lock, flags);

	if (appended || stored) {
		mod_delayed_work(system_wq, &slot->flush_work,
				 trustix_datapath_tx_plaintext_coalesce_flush_delay());
		if (held_frames && held_dev) {
			trustix_datapath_tx_plaintext_coalesce_xmit_packets(
				held_dev, held_packets, held_lens, held_frames,
				&held_state, &held_plan);
			trustix_datapath_tx_plaintext_coalesce_free_detached(
				held_dev, held_packets, held_frames);
		}
		kfree(packet);
		return true;
	}

	if (flush_with_current) {
		if (held_frames <
		    TRUSTIX_DATAPATH_TX_PLAINTEXT_COALESCE_MAX_FRAMES) {
			held_packets[held_frames] = packet;
			held_lens[held_frames] = inner_len;
			held_frames++;
			packet = NULL;
			trustix_datapath_tx_plaintext_stream_coalesce_stored++;
		}
		if (held_dev && held_frames)
			trustix_datapath_tx_plaintext_coalesce_xmit_packets(
				held_dev, held_packets, held_lens, held_frames,
				&held_state, &held_plan);
		trustix_datapath_tx_plaintext_coalesce_free_detached(
			held_dev, held_packets, held_frames);
		kfree(packet);
		return true;
	}

miss:
	kfree(packet);
	trustix_datapath_tx_plaintext_stream_coalesce_misses++;
	return false;
}

static int
trustix_datapath_tx_plaintext_skb(struct sk_buff *skb,
				  struct trustix_datapath_ioc_classify *classify,
				  int target_ifindex,
				  struct net_device *target_dev_hint,
				  __u32 tx_hook_flags)
{
	struct trustix_datapath_tx_plan plan;
	struct net_device *target_dev = NULL;
	struct sk_buff *outer_skb = NULL;
	const struct iphdr *iph;
	__u32 inner_len;
	int ret;
	bool outer_exceeds = false;

	if (!READ_ONCE(trustix_datapath_tx_plaintext))
		return -EPROTONOSUPPORT;
	if (!skb || !classify)
		return -EINVAL;
	if (target_dev_hint) {
		dev_hold(target_dev_hint);
		target_dev = target_dev_hint;
	} else if (target_ifindex > 0 && skb->dev) {
		target_dev = dev_get_by_index(dev_net(skb->dev), target_ifindex);
	}
	if (!target_dev)
		return -ENODEV;

	read_lock_bh(&trustix_datapath_state_lock);
	ret = trustix_datapath_tx_plan_locked(classify, &plan);
	read_unlock_bh(&trustix_datapath_state_lock);
	if (ret) {
		trustix_datapath_tx_plaintext_record_plan_error(ret,
								classify);
		if (ret == -EOPNOTSUPP)
			trustix_datapath_tx_plaintext_encrypted_skips++;
		else
			trustix_datapath_tx_plaintext_route_misses++;
		goto out_dev;
	}
	if ((plan.secure &&
	     !(tx_hook_flags &
	       TRUSTIX_DATAPATH_HOOK_FLAG_TX_SECURE_TIX_TCP)) ||
	    (!plan.secure &&
	     !(tx_hook_flags & TRUSTIX_DATAPATH_HOOK_FLAG_TX_PLAINTEXT))) {
		ret = -EOPNOTSUPP;
		goto out_dev;
	}

	if (skb_is_gso(skb)) {
		ret = trustix_datapath_tx_plaintext_gso_skb(skb, &plan,
							   target_dev);
		if (ret) {
			trustix_datapath_tx_plaintext_gso_skips++;
			if (ret == -EOPNOTSUPP || ret == -EPROTONOSUPPORT)
				trustix_datapath_tx_plaintext_unsupported_transports++;
			else if (ret == -ENOSPC)
				trustix_datapath_tx_plaintext_xmit_errors++;
			else
				trustix_datapath_tx_plaintext_record_build_error(
					ret, 1, skb, classify, 0);
		}
		goto out_dev;
	}

	if (!pskb_may_pull(skb, skb_network_offset(skb) + sizeof(*iph))) {
		ret = -ENODATA;
		trustix_datapath_tx_plaintext_record_build_error(
			ret, 2, skb, classify, 0);
		goto out_dev;
	}
	iph = ip_hdr(skb);
	if (!iph || iph->version != 4 || iph->ihl < 5) {
		ret = -EPROTONOSUPPORT;
		trustix_datapath_tx_plaintext_record_build_error(
			ret, 3, skb, classify, 0);
		goto out_dev;
	}
	inner_len = ntohs(iph->tot_len);
	if (!inner_len || inner_len > skb->len - skb_network_offset(skb)) {
		ret = -EMSGSIZE;
		trustix_datapath_tx_plaintext_record_build_error(
			ret, 4, skb, classify, inner_len);
		goto out_dev;
	}
	if (trustix_datapath_tx_plaintext_coalesce_skb(
		    skb, classify, target_ifindex, target_dev, &plan,
		    inner_len)) {
		ret = 0;
		goto out_dev;
	}
	ret = trustix_datapath_tx_plaintext_outer_exceeds_packet_limit(
		&plan, target_dev, inner_len, &outer_exceeds);
	if (ret) {
		trustix_datapath_tx_plaintext_record_build_error(
			ret, 5, skb, classify, inner_len);
		goto out_dev;
	}
	if (outer_exceeds) {
		if (classify->protocol == IPPROTO_TCP)
			ret = trustix_datapath_tx_plaintext_segment_tcp_skb(
				skb, &plan, target_dev, 0, false);
		else
			ret = trustix_datapath_tx_plaintext_fragment_ipv4_skb(
				skb, &plan, target_dev);
		if (ret) {
			if (ret == -ENOSPC)
				trustix_datapath_tx_plaintext_xmit_errors++;
			else
				trustix_datapath_tx_plaintext_record_build_error(
					ret, 6, skb, classify, inner_len);
		}
		goto out_dev;
	}

	ret = trustix_datapath_tx_build_outer_skb(skb, &plan, inner_len,
						 &outer_skb);
	if (ret) {
		trustix_datapath_tx_plaintext_record_build_error(
			ret, 7, skb, classify, inner_len);
		goto out_dev;
	}
	ret = trustix_datapath_tx_plaintext_enqueue(outer_skb, target_dev,
						   &plan, inner_len);
	if (READ_ONCE(trustix_datapath_tx_plaintext_inline_xmit)) {
		outer_skb = NULL;
		target_dev = NULL;
	}
	if (ret) {
		if (ret != -ENOSPC)
			trustix_datapath_tx_plaintext_xmit_errors++;
		goto out_dev;
	}
	outer_skb = NULL;
	target_dev = NULL;
out_dev:
	if (outer_skb)
		kfree_skb(outer_skb);
	if (target_dev)
		dev_put(target_dev);
	return ret;
}

static int
trustix_datapath_plaintext_session_for_frame_locked(
	__u64 flow_id, __u64 epoch, __u8 protocol,
	struct trustix_datapath_state_slot **session_out)
{
	struct trustix_datapath_state_slot *session;
	__u32 transport;

	if (!session_out)
		return -EINVAL;
	*session_out = NULL;
	switch (protocol) {
	case IPPROTO_UDP:
		transport = TRUSTIX_DATAPATH_TRANSPORT_UDP;
		break;
	case IPPROTO_TCP:
		transport = TRUSTIX_DATAPATH_TRANSPORT_TIX_TCP;
		break;
	default:
		return -EPROTONOSUPPORT;
	}
	session = trustix_datapath_session_for_flow_id_locked(flow_id);
	if (!session)
		return -ENOKEY;
	if (session->flags & TRUSTIX_DATAPATH_SESSION_FLAGS_ENCRYPTED)
		return -ENOKEY;
	if ((__u32)session->value[1] != transport)
		return -EPROTONOSUPPORT;
	if (session->value[2] && session->value[2] != epoch)
		return -ESTALE;
	*session_out = session;
	return 0;
}

static int
trustix_datapath_outer_parse_skb_locked(struct sk_buff *skb,
					const struct trustix_datapath_ioc_classify *classify,
					__u8 ip_header_len, __u8 l4_header_len)
{
	struct trustix_datapath_tixt_frame frame = {};
	struct trustix_datapath_state_slot *session;
	struct trustix_datapath_state_slot *wire;
	const __u8 *network;
	const __u8 *tixt;
	__u32 total_len;
	__u32 tixt_len;
	__u16 transport_len;
	bool reverse = false;
	int ret;

	if (!skb || !classify)
		return -EINVAL;
	if (ip_header_len != 20)
		return -EPROTONOSUPPORT;
	network = skb_network_header(skb);
	if (!network)
		return -EINVAL;
	total_len = trustix_datapath_get_be16(network + 2);
	if (total_len > skb->len)
		return -EMSGSIZE;
	switch (classify->protocol) {
	case IPPROTO_UDP:
		if (l4_header_len != 8)
			return -EPROTONOSUPPORT;
		if (total_len < 28 + TRUSTIX_DATAPATH_MIN_FRAME_HEADER_LEN)
			return -EPROTONOSUPPORT;
		transport_len = trustix_datapath_get_be16(network + 24);
		if (transport_len < 8 ||
		    (__u32)transport_len != total_len - ip_header_len)
			return -EMSGSIZE;
		tixt = network + 28;
		tixt_len = (__u32)transport_len - 8;
		break;
	case IPPROTO_TCP:
		if (l4_header_len != 20)
			return -EPROTONOSUPPORT;
		if (total_len < 40 + TRUSTIX_DATAPATH_MIN_FRAME_HEADER_LEN)
			return -EPROTONOSUPPORT;
		tixt = network + 40;
		tixt_len = total_len - 40;
		break;
	default:
		return -EPROTONOSUPPORT;
	}

	ret = trustix_datapath_parse_tixt_header(tixt, tixt_len, &frame);
	if (ret)
		return ret;
	if (!(frame.flags & TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4))
		return -EPROTONOSUPPORT;
	if (frame.wire_len != tixt_len)
		return -EMSGSIZE;
	wire = trustix_datapath_session_wire_for_tuple_locked(
		frame.flow_id, classify->src_ipv4, classify->dst_ipv4,
		classify->src_port, classify->dst_port, classify->protocol,
		&reverse);
	if (!wire && classify->protocol == IPPROTO_UDP &&
	    frame.header_len == TRUSTIX_DATAPATH_TIXU_HEADER_LEN)
		wire = trustix_datapath_session_wire_for_tuple_any_flow_locked(
			classify->src_ipv4, classify->dst_ipv4,
			classify->src_port, classify->dst_port,
			classify->protocol, &reverse);
	if (!wire) {
		ret = trustix_datapath_plaintext_session_for_frame_locked(
			frame.flow_id, frame.epoch, classify->protocol, &session);
		return ret;
	}
	session = trustix_datapath_session_for_flow_id_locked(wire->value[0]);
	if (!session)
		return -EHOSTUNREACH;
	if (wire->value[6] && frame.epoch != wire->value[6])
		return -ESTALE;
	if (wire->key[0] != session->key[0] ||
	    wire->key[1] != session->key[1] ||
	    wire->key[2] != session->key[2] ||
	    wire->key[3] != session->key[3])
		return -ESTALE;
	if (frame.payload_len > total_len)
		return -EMSGSIZE;
	return 0;
}

static int trustix_datapath_parse_tixt_skb_header(
	const struct sk_buff *skb, __u32 offset, __u32 remaining,
	struct trustix_datapath_tixt_frame *frame)
{
	__u8 wire[TRUSTIX_DATAPATH_TIXT_HEADER_LEN];
	__u32 copy_len;

	if (!skb || !frame)
		return -EINVAL;
	if (remaining < TRUSTIX_DATAPATH_MIN_FRAME_HEADER_LEN)
		return -ENODATA;
	if (offset > skb->len || remaining > skb->len - offset)
		return -EMSGSIZE;
	copy_len = min_t(__u32, remaining, sizeof(wire));
	if (skb_copy_bits(skb, offset, wire, copy_len))
		return -ENODATA;
	return trustix_datapath_parse_tixt_header(wire, remaining, frame);
}

static int
trustix_datapath_rx_stage_parse_skb(struct sk_buff *skb,
				    const struct trustix_datapath_ioc_classify *classify,
				    __u8 ip_header_len, __u8 l4_header_len,
				    struct trustix_datapath_rx_stage_view *view)
{
	struct trustix_datapath_tixt_frame frame = {};
	struct trustix_datapath_ioc_classify inner = {};
	const __u8 *network;
	const __u8 *tixt;
	const __u8 *inner_packet;
	__u8 inner_ip_header_len = 0;
	__u8 inner_l4_header_len = 0;
	__u32 total_len;
	__u32 tixt_offset;
	__u32 tixt_len;
	int network_offset;
	__u16 transport_len;
	int ret;

	if (!skb || !classify || !view)
		return -EINVAL;
	if (ip_header_len != 20)
		return -EPROTONOSUPPORT;
	network = skb_network_header(skb);
	if (!network)
		return -EINVAL;
	network_offset = skb_network_offset(skb);
	if (network_offset < 0 || (__u32)network_offset > skb->len)
		return -EOVERFLOW;
	total_len = trustix_datapath_get_be16(network + 2);
	if (total_len > skb->len - (__u32)network_offset)
		return -EMSGSIZE;
	switch (classify->protocol) {
	case IPPROTO_UDP:
		if (l4_header_len != 8)
			return -EPROTONOSUPPORT;
		transport_len = trustix_datapath_get_be16(network + 24);
		if (transport_len < 8 ||
		    (__u32)transport_len != total_len - ip_header_len)
			return -EMSGSIZE;
		tixt_offset = 28;
		tixt_len = (__u32)transport_len - 8;
		break;
	case IPPROTO_TCP:
		if (l4_header_len != 20)
			return -EPROTONOSUPPORT;
		if (total_len < 40)
			return -EMSGSIZE;
		tixt_offset = 40;
		tixt_len = total_len - 40;
		break;
	default:
		return -EPROTONOSUPPORT;
	}
	if (tixt_len < TRUSTIX_DATAPATH_MIN_FRAME_HEADER_LEN ||
	    tixt_offset > UINT_MAX - tixt_len)
		return -EMSGSIZE;
	if (skb_is_nonlinear(skb)) {
		this_cpu_inc(
			trustix_datapath_rx_worker_stream_offset_copy_attempts);
		if (likely(READ_ONCE(
			    trustix_datapath_rx_worker_stream_offset_copy))) {
			ret = trustix_datapath_parse_tixt_skb_header(
				skb, (__u32)network_offset + tixt_offset,
				tixt_len, &frame);
			if (ret || !(frame.flags &
				     TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4)) {
				this_cpu_inc(
					trustix_datapath_rx_worker_stream_offset_copy_errors);
				return ret ?: -EPROTONOSUPPORT;
			}
			if (frame.wire_len != tixt_len) {
				this_cpu_inc(
					trustix_datapath_rx_worker_stream_offset_copy_hits);
				this_cpu_add(
					trustix_datapath_rx_worker_stream_offset_copy_bytes,
					total_len);
				return -EMSGSIZE;
			}
		}
		this_cpu_inc(
			trustix_datapath_rx_worker_stream_offset_copy_fallbacks);
	}
	if (!pskb_may_pull(skb, (__u32)network_offset + tixt_offset + tixt_len))
		return -ENODATA;
	network = skb_network_header(skb);
	tixt = network + tixt_offset;
	ret = trustix_datapath_parse_tixt(tixt, tixt_len, &frame);
	if (ret)
		return ret;
	if (!(frame.flags & TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4))
		return -EPROTONOSUPPORT;
	if (frame.wire_len != tixt_len)
		return -EMSGSIZE;
	if (frame.payload_len > total_len)
		return -EMSGSIZE;

	inner_packet = tixt + frame.header_len;
	ret = trustix_datapath_parse_ipv4_packet(inner_packet, frame.payload_len,
						 &inner, &inner_ip_header_len,
						 &inner_l4_header_len);
	if (ret)
		return ret;
	if (inner_packet < skb->data ||
	    inner_packet - skb->data > TRUSTIX_DATAPATH_PACKET_MAX_LEN)
		return -EOVERFLOW;
	memset(view, 0, sizeof(*view));
	view->frame = frame;
	view->inner = inner;
	view->inner_packet = inner_packet;
	view->tixt_len = tixt_len;
	view->inner_offset = (__u32)(inner_packet - skb->data);
	view->inner_ip_header_len = inner_ip_header_len;
	view->inner_l4_header_len = inner_l4_header_len;
	return 0;
}

static int
trustix_datapath_rx_validate_inner_tcp_checksum_partial(
	const struct trustix_datapath_rx_stage_view *view)
{
	const struct tcphdr *tcph;
	const struct iphdr *iph;
	__sum16 expected;
	__u32 ip_header_len;
	__u32 tcp_header_len;
	__u32 total_len;
	__u32 tcp_len;
	__u32 tcp_payload_len;
	__u32 gso_size;
	__u32 gso_segs;
	__u8 incompatible_flags;
	bool secure_partial;
	bool inner_gso;

	if (!view || !(view->frame.flags &
		       TRUSTIX_DATAPATH_TIXT_FLAG_INNER_TCP_CHECKSUM_PARTIAL))
		return 0;
	incompatible_flags = TRUSTIX_DATAPATH_TIXT_FLAG_ENCRYPTED |
			     TRUSTIX_DATAPATH_TIXT_FLAG_CRYPTO_FRAGMENT;
	inner_gso = view->frame.flags &
		    TRUSTIX_DATAPATH_TIXT_FLAG_INNER_GSO;
	secure_partial = view->session_flags &
			 TRUSTIX_DATAPATH_SESSION_FLAG_RECEIVE_ENCRYPTED;
	if (view->frame.header_len != TRUSTIX_DATAPATH_TIXT_HEADER_LEN ||
	    !(view->frame.flags & TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4) ||
	    (view->frame.flags & incompatible_flags) ||
	    (!inner_gso && (view->frame.fragment_index ||
			    view->frame.fragment_count)) ||
	    (inner_gso && (!view->frame.fragment_index ||
			   view->frame.fragment_count < 2)) ||
	    view->inner.protocol != IPPROTO_TCP || !view->inner_packet ||
	    view->frame.payload_len < sizeof(*iph) + sizeof(*tcph))
		goto malformed;
	if (secure_partial) {
		if (!(view->frame.flags &
		      TRUSTIX_DATAPATH_TIXT_FLAG_KERNEL_OPENED) ||
		    inner_gso ||
		    !(view->session_flags &
		      TRUSTIX_DATAPATH_SESSION_FLAG_RECEIVE_SECURE_INNER_TCP_CHECKSUM_PARTIAL) ||
		    !(READ_ONCE(trustix_datapath_features) &
		      TRUSTIX_DATAPATH_FEATURE_SECURE_INNER_TCP_CHECKSUM_PARTIAL))
			goto malformed;
	} else if ((view->frame.flags &
		    TRUSTIX_DATAPATH_TIXT_FLAG_KERNEL_OPENED) ||
		   !(view->session_flags &
		     TRUSTIX_DATAPATH_SESSION_FLAG_RECEIVE_INNER_TCP_CHECKSUM_PARTIAL) ||
		   !(READ_ONCE(trustix_datapath_features) &
		     TRUSTIX_DATAPATH_FEATURE_INNER_TCP_CHECKSUM_PARTIAL)) {
		goto malformed;
	}
	if (inner_gso &&
	    (!(view->session_flags &
	       TRUSTIX_DATAPATH_SESSION_FLAG_RECEIVE_INNER_GSO) ||
	     !(READ_ONCE(trustix_datapath_features) &
	       TRUSTIX_DATAPATH_FEATURE_INNER_GSO)))
		goto malformed;

	iph = (const struct iphdr *)view->inner_packet;
	if (iph->version != 4 || iph->ihl < 5 ||
	    iph->protocol != IPPROTO_TCP ||
	    (iph->frag_off & htons(0x3fff)))
		goto malformed;
	ip_header_len = iph->ihl * 4;
	if (ip_header_len < sizeof(*iph) ||
	    view->frame.payload_len < ip_header_len + sizeof(*tcph))
		goto malformed;
	total_len = ntohs(iph->tot_len);
	if (total_len != view->frame.payload_len ||
	    total_len < ip_header_len + sizeof(*tcph))
		goto malformed;
	tcph = (const struct tcphdr *)((const __u8 *)iph + ip_header_len);
	tcp_header_len = tcph->doff * 4;
	if (tcp_header_len < sizeof(*tcph) ||
	    total_len < ip_header_len + tcp_header_len)
		goto malformed;
	tcp_len = total_len - ip_header_len;
	tcp_payload_len = tcp_len - tcp_header_len;
	if (inner_gso) {
		gso_size = view->frame.fragment_index;
		gso_segs = view->frame.fragment_count;
		if (!tcp_payload_len || gso_size > tcp_payload_len ||
		    DIV_ROUND_UP(tcp_payload_len, gso_size) != gso_segs)
			goto malformed;
	}
	expected = ~csum_tcpudp_magic(iph->saddr, iph->daddr, tcp_len,
				       IPPROTO_TCP, 0);
	if (tcph->check != expected)
		goto malformed;
	trustix_datapath_rx_worker_inner_tcp_checksum_partial++;
	return 0;

malformed:
	trustix_datapath_rx_worker_inner_tcp_checksum_partial_errors++;
	return -EBADMSG;
}

static int
trustix_datapath_rx_stage_validate_locked(
	const struct trustix_datapath_ioc_classify *classify,
	struct trustix_datapath_rx_stage_view *view)
{
	struct trustix_datapath_state_slot *session;
	struct trustix_datapath_state_slot *wire;
	bool reverse = false;
	int ret;

	if (!classify || !view)
		return -EINVAL;
	wire = trustix_datapath_session_wire_for_tuple_locked(
		view->frame.flow_id, classify->src_ipv4, classify->dst_ipv4,
		classify->src_port, classify->dst_port, classify->protocol,
		&reverse);
	if (!wire && classify->protocol == IPPROTO_UDP &&
	    view->frame.header_len == TRUSTIX_DATAPATH_TIXU_HEADER_LEN)
		wire = trustix_datapath_session_wire_for_tuple_any_flow_locked(
			classify->src_ipv4, classify->dst_ipv4,
			classify->src_port, classify->dst_port,
			classify->protocol, &reverse);
	if (!wire) {
		ret = trustix_datapath_plaintext_session_for_frame_locked(
			view->frame.flow_id, view->frame.epoch,
			classify->protocol, &session);
		if (ret)
			return ret;
		view->reverse = !!(session->flags &
					  TRUSTIX_DATAPATH_SESSION_FLAG_REVERSE);
		view->session_flow_id = session->value[0];
		view->session_flags = session->flags;
		return trustix_datapath_rx_validate_inner_tcp_checksum_partial(
			view);
	}
	session = trustix_datapath_session_for_flow_id_locked(wire->value[0]);
	if (!session)
		return -EHOSTUNREACH;
	if (wire->value[6] && view->frame.epoch != wire->value[6])
		return -ESTALE;
	if (wire->key[0] != session->key[0] ||
	    wire->key[1] != session->key[1] ||
	    wire->key[2] != session->key[2] ||
	    wire->key[3] != session->key[3])
		return -ESTALE;
	view->reverse = reverse;
	view->session_flow_id = session->value[0];
	view->session_flags = session->flags;
	return trustix_datapath_rx_validate_inner_tcp_checksum_partial(view);
}

static int trustix_datapath_rx_stage_validate_batch(
	const struct trustix_datapath_ioc_classify *classify,
	struct trustix_datapath_rx_stage_view *view,
	struct trustix_datapath_rx_validation_cache *cache)
{
	int ret;

	if (!classify || !view || !cache)
		return -EINVAL;
	if (cache->valid && cache->header_len == view->frame.header_len &&
	    cache->flow_id == view->frame.flow_id &&
	    cache->epoch == view->frame.epoch) {
		view->reverse = cache->reverse;
		view->session_flow_id = cache->session_flow_id;
		view->session_flags = cache->session_flags;
		return trustix_datapath_rx_validate_inner_tcp_checksum_partial(
			view);
	}

	read_lock_bh(&trustix_datapath_state_lock);
	ret = trustix_datapath_rx_stage_validate_locked(classify, view);
	read_unlock_bh(&trustix_datapath_state_lock);
	if (ret)
		return ret;

	cache->valid = true;
	cache->reverse = view->reverse;
	cache->header_len = view->frame.header_len;
	cache->flow_id = view->frame.flow_id;
	cache->epoch = view->frame.epoch;
	cache->session_flow_id = view->session_flow_id;
	cache->session_flags = view->session_flags;
	return 0;
}

static int
trustix_datapath_rx_stage_push(const struct trustix_datapath_ioc_classify *outer,
			       const struct trustix_datapath_rx_stage_view *view)
{
	struct trustix_datapath_rx_stage_slot *slot;
	__u8 *dst;
	unsigned long irqflags;

	if (!outer || !view || !view->inner_packet)
		return -EINVAL;
	if (!view->frame.payload_len ||
	    view->frame.payload_len > TRUSTIX_DATAPATH_PACKET_MAX_LEN)
		return -EMSGSIZE;
	spin_lock_irqsave(&trustix_datapath_rx_stage_lock, irqflags);
	if (!trustix_datapath_rx_stage_ring || !trustix_datapath_rx_stage_data ||
	    !trustix_datapath_rx_stage_capacity) {
		trustix_datapath_rx_stage_dropped++;
		spin_unlock_irqrestore(&trustix_datapath_rx_stage_lock,
				       irqflags);
		return -ENOSPC;
	}
	if (trustix_datapath_rx_stage_count ==
	    trustix_datapath_rx_stage_capacity) {
		trustix_datapath_rx_stage_ring
			[trustix_datapath_rx_stage_head].valid = false;
		trustix_datapath_rx_stage_head =
			(trustix_datapath_rx_stage_head + 1) %
			trustix_datapath_rx_stage_capacity;
		trustix_datapath_rx_stage_count--;
		trustix_datapath_rx_stage_overwritten++;
	}
	slot = &trustix_datapath_rx_stage_ring[trustix_datapath_rx_stage_tail];
	dst = trustix_datapath_rx_stage_data +
	      (trustix_datapath_rx_stage_tail *
	       TRUSTIX_DATAPATH_PACKET_MAX_LEN);
	memcpy(dst, view->inner_packet, view->frame.payload_len);
	memset(slot, 0, sizeof(*slot));
	slot->valid = true;
	slot->len = view->frame.payload_len;
	slot->id = ++trustix_datapath_rx_stage_next_id;
	slot->flow_id = view->frame.flow_id;
	slot->epoch = view->frame.epoch;
	slot->sequence = view->frame.sequence;
	slot->payload_len = view->frame.payload_len;
	slot->tixt_flags = view->frame.flags;
	slot->session_flags = view->session_flags;
	slot->outer_src_ipv4 = outer->src_ipv4;
	slot->outer_dst_ipv4 = outer->dst_ipv4;
	slot->outer_src_port = outer->src_port;
	slot->outer_dst_port = outer->dst_port;
	slot->outer_protocol = outer->protocol;
	slot->inner_protocol = view->inner.protocol;
	slot->inner_src_ipv4 = view->inner.src_ipv4;
	slot->inner_dst_ipv4 = view->inner.dst_ipv4;
	slot->inner_src_port = view->inner.src_port;
	slot->inner_dst_port = view->inner.dst_port;
	slot->inner_ip_header_len = view->inner_ip_header_len;
	slot->inner_l4_header_len = view->inner_l4_header_len;
	trustix_datapath_rx_stage_tail =
		(trustix_datapath_rx_stage_tail + 1) %
		trustix_datapath_rx_stage_capacity;
	trustix_datapath_rx_stage_count++;
	trustix_datapath_rx_stage_staged++;
	spin_unlock_irqrestore(&trustix_datapath_rx_stage_lock, irqflags);
	return 0;
}

static int trustix_datapath_rx_worker_target_dev(struct sk_buff *skb,
						 struct net_device **target_dev,
						 int target_ifindex)
{
	struct net_device *dev;

	if (!skb || !target_dev)
		return -EINVAL;
	*target_dev = NULL;
	dev = skb->dev;
	if (!dev)
		return -ENODEV;
	if (target_ifindex > 0)
		*target_dev = dev_get_by_index(dev_net(dev), target_ifindex);
	if (target_ifindex > 0 && !*target_dev)
		return -ENODEV;
	if (!*target_dev) {
		*target_dev = dev;
		dev_hold(*target_dev);
	}
	return 0;
}

static bool
trustix_datapath_rx_worker_dev_ready(struct net_device *dev)
{
	if (!dev)
		return false;
	if (dev->type != ARPHRD_ETHER)
		return false;
	if (dev->reg_state != NETREG_REGISTERED)
		return false;
	if (!(READ_ONCE(dev->flags) & IFF_UP))
		return false;
	if (!netif_device_present(dev) || !netif_running(dev))
		return false;
	return true;
}

static int
trustix_datapath_rx_worker_target_dev_hint(struct sk_buff *skb,
					   struct net_device **target_dev,
					   int target_ifindex,
					   struct net_device *target_dev_hint)
{
	if (!target_dev)
		return -EINVAL;
	*target_dev = NULL;
	if (target_dev_hint) {
		dev_hold(target_dev_hint);
		*target_dev = target_dev_hint;
		return 0;
	}
	return trustix_datapath_rx_worker_target_dev(skb, target_dev,
						    target_ifindex);
}

static int trustix_datapath_rx_worker_build_inner_gso_skb(
	struct sk_buff *source_skb, __u32 inner_offset,
	const struct trustix_datapath_tixt_frame *frame,
	struct net_device *target_dev, struct sk_buff **inner_skb_out)
{
	struct skb_shared_info *shinfo;
	struct sk_buff *skb;
	const struct tcphdr *tcph;
	const struct iphdr *iph;
	__u32 ip_header_len;
	__u32 tcp_header_len;
	__u32 total_len;
	__u32 tcp_payload_len;
	__u32 expected_segs;
	__u32 pull_len;
	int ret;

	if (inner_skb_out)
		*inner_skb_out = NULL;
	if (!source_skb || !frame || !target_dev || !inner_skb_out ||
	    !(frame->flags & TRUSTIX_DATAPATH_TIXT_FLAG_INNER_GSO) ||
	    !frame->payload_len || !frame->fragment_index ||
	    frame->fragment_count < 2 || inner_offset > source_skb->len ||
	    frame->payload_len > source_skb->len - inner_offset)
		return -EINVAL;

	skb = skb_clone(source_skb, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;
	ret = skb_cow_head(skb, ETH_HLEN);
	if (ret)
		goto error;
	if (check_add_overflow(inner_offset,
			       (__u32)(sizeof(*iph) + sizeof(*tcph)),
			       &pull_len) ||
	    pull_len > skb->len || !pskb_may_pull(skb, pull_len)) {
		ret = -ENODATA;
		goto error;
	}
	if (inner_offset && !skb_pull(skb, inner_offset)) {
		ret = -ENODATA;
		goto error;
	}
	ret = pskb_trim(skb, frame->payload_len);
	if (ret)
		goto error;
	if (!pskb_may_pull(skb, sizeof(*iph))) {
		ret = -ENODATA;
		goto error;
	}
	iph = (const struct iphdr *)skb->data;
	if (iph->version != 4 || iph->ihl < 5 ||
	    iph->protocol != IPPROTO_TCP ||
	    (iph->frag_off & htons(0x3fff))) {
		ret = -EPROTONOSUPPORT;
		goto error;
	}
	ip_header_len = iph->ihl * 4;
	if (ip_header_len < sizeof(*iph) ||
	    !pskb_may_pull(skb, ip_header_len + sizeof(*tcph))) {
		ret = -ENODATA;
		goto error;
	}
	iph = (const struct iphdr *)skb->data;
	tcph = (const struct tcphdr *)(skb->data + ip_header_len);
	tcp_header_len = tcph->doff * 4;
	total_len = ntohs(iph->tot_len);
	if (tcp_header_len < sizeof(*tcph) || tcp_header_len > 60 ||
	    total_len != frame->payload_len ||
	    total_len < ip_header_len + tcp_header_len) {
		ret = -EINVAL;
		goto error;
	}
	if (!pskb_may_pull(skb, ip_header_len + tcp_header_len)) {
		ret = -ENODATA;
		goto error;
	}
	tcp_payload_len = total_len - ip_header_len - tcp_header_len;
	expected_segs = DIV_ROUND_UP(tcp_payload_len,
				     (__u32)frame->fragment_index);
	if (!tcp_payload_len || expected_segs != frame->fragment_count) {
		ret = -EINVAL;
		goto error;
	}

	skb_orphan(skb);
	skb->protocol = htons(ETH_P_IP);
	skb->pkt_type = PACKET_OUTGOING;
	skb->encapsulation = 0;
	skb->csum = 0;
	skb->csum_level = 0;
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, ip_header_len);
	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum_start = skb_transport_header(skb) - skb->head;
	skb->csum_offset = offsetof(struct tcphdr, check);
	shinfo = skb_shinfo(skb);
	shinfo->gso_size = frame->fragment_index;
	shinfo->gso_segs = frame->fragment_count;
	shinfo->gso_type = SKB_GSO_TCPV4;
	*inner_skb_out = skb;
	return 0;

error:
	kfree_skb(skb);
	return ret;
}

static void trustix_datapath_inner_gso_reassembly_reset_locked(
	struct trustix_datapath_inner_gso_reassembly_slot *slot)
{
	__u8 *data;

	if (!slot)
		return;
	data = slot->data;
	memset(slot, 0, sizeof(*slot));
	slot->data = data;
}

static unsigned long trustix_datapath_inner_gso_reassembly_expire_locked(
	struct trustix_datapath_inner_gso_reassembly_slot *slot,
	bool on_start, bool on_sweep)
{
	__u32 missing = 0;
	unsigned long stream_last_progress;

	if (!slot || !slot->active)
		return 0;
	stream_last_progress = slot->stream_last_progress;
	if (slot->wire_len > slot->received_len)
		missing = slot->wire_len - slot->received_len;
	trustix_datapath_rx_worker_inner_gso_timeouts++;
	if (on_sweep)
		trustix_datapath_rx_worker_inner_gso_timeouts_on_sweep++;
	else if (on_start)
		trustix_datapath_rx_worker_inner_gso_timeouts_on_start++;
	else
		trustix_datapath_rx_worker_inner_gso_timeouts_on_append++;
	trustix_datapath_rx_worker_inner_gso_timeout_missing_bytes += missing;
	if (missing >
	    trustix_datapath_rx_worker_inner_gso_timeout_max_missing_bytes)
		trustix_datapath_rx_worker_inner_gso_timeout_max_missing_bytes =
			missing;
	trustix_datapath_inner_gso_reassembly_reset_locked(slot);
	return stream_last_progress;
}

static void trustix_datapath_sweep_inner_gso_reassembly(void)
{
	unsigned long oldest_progress = 0;
	unsigned long flags;
	unsigned long now = jiffies;
	unsigned int expired = 0;
	unsigned int set;

	if (!READ_ONCE(trustix_datapath_inner_gso_reassembly_data))
		return;
	for (set = 0; set < TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_SETS;
	     set++) {
		unsigned int first =
			set * TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_PROBES;
		unsigned int i;

		spin_lock_irqsave(
			&trustix_datapath_inner_gso_reassembly_locks[set],
			flags);
		for (i = 0; i < TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_PROBES;
		     i++) {
			struct trustix_datapath_inner_gso_reassembly_slot *slot =
				&trustix_datapath_inner_gso_reassembly_slots[
					first + i];
			unsigned long progress;

			if (!slot->active || time_before(now, slot->expires))
				continue;
			progress =
				trustix_datapath_inner_gso_reassembly_expire_locked(
					slot, false, true);
			if (progress &&
			    (!oldest_progress ||
			     time_before(progress, oldest_progress)))
				oldest_progress = progress;
			expired++;
		}
		spin_unlock_irqrestore(
			&trustix_datapath_inner_gso_reassembly_locks[set],
			flags);
	}
	while (expired--) {
		trustix_datapath_inner_gso_record_reassembly_timeout(
			oldest_progress);
	}
}

static void trustix_datapath_inner_gso_reassembly_key_init(
	struct trustix_datapath_inner_gso_reassembly_key *key,
	const struct sk_buff *skb,
	const struct trustix_datapath_ioc_classify *outer,
	int target_ifindex)
{
	memset(key, 0, sizeof(*key));
	key->net = skb && skb->dev ? dev_net(skb->dev) : NULL;
	key->src_ipv4 = outer->src_ipv4;
	key->dst_ipv4 = outer->dst_ipv4;
	key->src_port = outer->src_port;
	key->dst_port = outer->dst_port;
	key->ifindex = skb && skb->dev ? skb->dev->ifindex : 0;
	key->target_ifindex = target_ifindex;
}

static bool trustix_datapath_inner_gso_reassembly_key_equal(
	const struct trustix_datapath_inner_gso_reassembly_key *left,
	const struct trustix_datapath_inner_gso_reassembly_key *right)
{
	return left && right && left->net == right->net &&
	       left->src_ipv4 == right->src_ipv4 &&
	       left->dst_ipv4 == right->dst_ipv4 &&
	       left->src_port == right->src_port &&
	       left->dst_port == right->dst_port &&
	       left->ifindex == right->ifindex &&
	       left->target_ifindex == right->target_ifindex;
}

static unsigned int trustix_datapath_inner_gso_reassembly_set(
	const struct trustix_datapath_inner_gso_reassembly_key *key);

static void trustix_datapath_inner_gso_reassembly_record_progress(
	const struct sk_buff *skb,
	const struct trustix_datapath_ioc_classify *outer,
	int target_ifindex, const struct trustix_datapath_tixt_frame *frame)
{
	struct trustix_datapath_inner_gso_reassembly_key key;
	unsigned long flags;
	unsigned long now = jiffies;
	unsigned int set;
	unsigned int first;
	unsigned int i;

	if (!skb || !outer || !frame)
		return;
	trustix_datapath_inner_gso_reassembly_key_init(
		&key, skb, outer, target_ifindex);
	set = trustix_datapath_inner_gso_reassembly_set(&key);
	first = set * TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_PROBES;
	spin_lock_irqsave(&trustix_datapath_inner_gso_reassembly_locks[set],
			  flags);
	for (i = 0; i < TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_PROBES; i++) {
		struct trustix_datapath_inner_gso_reassembly_slot *slot =
			&trustix_datapath_inner_gso_reassembly_slots[first + i];

		if (!slot->active || slot->flow_id != frame->flow_id ||
		    slot->epoch != frame->epoch ||
		    !trustix_datapath_inner_gso_reassembly_key_equal(
			    &slot->key, &key))
			continue;
		slot->stream_last_progress = now;
	}
	spin_unlock_irqrestore(
		&trustix_datapath_inner_gso_reassembly_locks[set], flags);
	trustix_datapath_inner_gso_probation_record_success(
		skb, outer, target_ifindex, frame);
}

static unsigned int trustix_datapath_inner_gso_reassembly_set(
	const struct trustix_datapath_inner_gso_reassembly_key *key)
{
	__u64 hash_key[4];

	hash_key[0] = ((__u64)key->src_ipv4 << 32) | key->dst_ipv4;
	hash_key[1] = ((__u64)key->src_port << 48) |
		       ((__u64)key->dst_port << 32) |
		       (__u32)key->ifindex;
	hash_key[2] = (unsigned long)key->net;
	hash_key[3] = (__u32)key->target_ifindex;
	return trustix_datapath_key_hash(hash_key) &
	       (TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_SETS - 1U);
}

static unsigned long trustix_datapath_inner_gso_probation_last_activity(
	const struct trustix_datapath_inner_gso_probation_slot *slot)
{
	if (!slot)
		return 0;
	if (time_after(slot->last_claim, slot->last_success))
		return slot->last_claim;
	return slot->last_success;
}

static unsigned int trustix_datapath_inner_gso_probation_set(
	const struct trustix_datapath_inner_gso_reassembly_key *key,
	__u64 flow_id, __u64 epoch)
{
	__u64 hash_key[4];

	hash_key[0] = ((__u64)key->src_ipv4 << 32) | key->dst_ipv4;
	hash_key[1] = ((__u64)key->src_port << 48) |
		       ((__u64)key->dst_port << 32) |
		       (__u32)key->ifindex;
	hash_key[2] = (__u64)(unsigned long)key->net ^ flow_id;
	hash_key[3] = ((__u64)(__u32)key->target_ifindex << 32) ^ epoch;
	return trustix_datapath_key_hash(hash_key) &
	       (TRUSTIX_DATAPATH_INNER_GSO_PROBATION_SETS - 1U);
}

static bool trustix_datapath_inner_gso_probation_slot_matches(
	const struct trustix_datapath_inner_gso_probation_slot *slot,
	const struct trustix_datapath_inner_gso_reassembly_key *key,
	__u64 flow_id, __u64 epoch)
{
	return slot && slot->active && slot->flow_id == flow_id &&
	       slot->epoch == epoch &&
	       trustix_datapath_inner_gso_reassembly_key_equal(&slot->key,
							 key);
}

static struct trustix_datapath_inner_gso_probation_slot *
trustix_datapath_inner_gso_probation_get_locked(
	const struct trustix_datapath_inner_gso_reassembly_key *key,
	__u64 flow_id, __u64 epoch, unsigned int set, unsigned long now,
	bool create)
{
	struct trustix_datapath_inner_gso_probation_slot *empty = NULL;
	struct trustix_datapath_inner_gso_probation_slot *stale = NULL;
	unsigned long stale_activity = 0;
	unsigned int stable_ms;
	unsigned int first;
	unsigned int i;

	first = set * TRUSTIX_DATAPATH_INNER_GSO_PROBATION_PROBES;
	stable_ms = trustix_datapath_inner_gso_bounded_ms(
		READ_ONCE(trustix_datapath_inner_gso_stable_ms),
		TRUSTIX_DATAPATH_INNER_GSO_STABLE_MS_DEFAULT);
	for (i = 0; i < TRUSTIX_DATAPATH_INNER_GSO_PROBATION_PROBES; i++) {
		struct trustix_datapath_inner_gso_probation_slot *slot =
			&trustix_datapath_inner_gso_probation_slots[first + i];
		unsigned long activity;

		if (trustix_datapath_inner_gso_probation_slot_matches(
			    slot, key, flow_id, epoch))
			return slot;
		if (!slot->active) {
			if (!empty)
				empty = slot;
			continue;
		}
		activity = trustix_datapath_inner_gso_probation_last_activity(
			slot);
		if (activity &&
		    time_before(now, activity + msecs_to_jiffies(stable_ms)))
			continue;
		if (!stale || !activity ||
		    (stale_activity && time_before(activity, stale_activity))) {
			stale = slot;
			stale_activity = activity;
		}
	}
	if (!create)
		return NULL;
	if (!empty)
		empty = stale;
	if (!empty) {
		trustix_datapath_inner_gso_probation_collisions++;
		return NULL;
	}
	if (empty->active)
		trustix_datapath_inner_gso_probation_evictions++;
	memset(empty, 0, sizeof(*empty));
	empty->active = true;
	empty->flow_id = flow_id;
	empty->epoch = epoch;
	empty->key = *key;
	return empty;
}

static void trustix_datapath_clear_inner_gso_probation_matching(
	bool all, __u64 flow_id, __u64 epoch)
{
	unsigned long flags;
	unsigned int set;

	for (set = 0; set < TRUSTIX_DATAPATH_INNER_GSO_PROBATION_SETS;
	     set++) {
		unsigned int first =
			set * TRUSTIX_DATAPATH_INNER_GSO_PROBATION_PROBES;
		unsigned int i;

		spin_lock_irqsave(
			&trustix_datapath_inner_gso_probation_locks[set], flags);
		for (i = 0; i < TRUSTIX_DATAPATH_INNER_GSO_PROBATION_PROBES;
		     i++) {
			struct trustix_datapath_inner_gso_probation_slot *slot =
				&trustix_datapath_inner_gso_probation_slots[
					first + i];

			if (!slot->active ||
			    (!all &&
			     (slot->flow_id != flow_id ||
			      (epoch && slot->epoch != epoch))))
				continue;
			memset(slot, 0, sizeof(*slot));
		}
		spin_unlock_irqrestore(
			&trustix_datapath_inner_gso_probation_locks[set], flags);
	}
}

static void trustix_datapath_inner_gso_probation_record_success(
	const struct sk_buff *skb,
	const struct trustix_datapath_ioc_classify *outer,
	int target_ifindex, const struct trustix_datapath_tixt_frame *frame)
{
	struct trustix_datapath_inner_gso_probation_slot *slot;
	struct trustix_datapath_inner_gso_reassembly_key key;
	unsigned long flags;
	unsigned long now = jiffies;
	unsigned int set;

	if (!skb || !outer || !frame || !frame->flow_id)
		return;
	trustix_datapath_inner_gso_reassembly_key_init(
		&key, skb, outer, target_ifindex);
	set = trustix_datapath_inner_gso_probation_set(
		&key, frame->flow_id, frame->epoch);
	spin_lock_irqsave(&trustix_datapath_inner_gso_probation_locks[set],
			  flags);
	slot = trustix_datapath_inner_gso_probation_get_locked(
		&key, frame->flow_id, frame->epoch, set, now, true);
	if (slot) {
		slot->first_claim = 0;
		slot->claims_since_success = 0;
		slot->last_success = now;
		trustix_datapath_inner_gso_probation_successes++;
	}
	spin_unlock_irqrestore(
		&trustix_datapath_inner_gso_probation_locks[set], flags);
}

static void trustix_datapath_inner_gso_probation_record_claim(
	const struct sk_buff *skb,
	const struct trustix_datapath_ioc_classify *outer,
	int target_ifindex, __u64 flow_id, __u64 epoch)
{
	struct trustix_datapath_inner_gso_probation_slot *slot;
	struct trustix_datapath_inner_gso_reassembly_key key;
	unsigned int no_progress_ms;
	unsigned long first_claim = 0;
	unsigned long flags;
	unsigned long now = jiffies;
	unsigned long no_progress_jiffies;
	unsigned int set;
	bool trip = false;

	if (!skb || !outer || !flow_id ||
	    unlikely(!trustix_datapath_inner_gso_runtime_permitted()))
		return;
	no_progress_ms = trustix_datapath_inner_gso_bounded_ms(
		READ_ONCE(trustix_datapath_inner_gso_no_progress_ms),
		TRUSTIX_DATAPATH_INNER_GSO_NO_PROGRESS_MS_DEFAULT);
	no_progress_jiffies = max_t(unsigned long, 1,
				    msecs_to_jiffies(no_progress_ms));
	trustix_datapath_inner_gso_reassembly_key_init(
		&key, skb, outer, target_ifindex);
	set = trustix_datapath_inner_gso_probation_set(&key, flow_id, epoch);
	spin_lock_irqsave(&trustix_datapath_inner_gso_probation_locks[set],
			  flags);
	if (unlikely(!trustix_datapath_inner_gso_runtime_permitted()))
		goto out_unlock;
	slot = trustix_datapath_inner_gso_probation_get_locked(
		&key, flow_id, epoch, set, now, true);
	if (!slot)
		goto out_unlock;
	trustix_datapath_inner_gso_probation_claims++;
	if (slot->last_claim &&
	    time_after(now, slot->last_claim + no_progress_jiffies)) {
		slot->first_claim = 0;
		slot->claims_since_success = 0;
		trustix_datapath_inner_gso_probation_idle_resets++;
	}
	if (!slot->first_claim) {
		slot->first_claim = now;
		trustix_datapath_inner_gso_probation_arms++;
	}
	if (slot->claims_since_success < UINT_MAX)
		slot->claims_since_success++;
	slot->last_claim = now;
	if (slot->claims_since_success >=
		    TRUSTIX_DATAPATH_INNER_GSO_PROBATION_MIN_CLAIMS &&
	    time_after_eq(now, slot->first_claim + no_progress_jiffies)) {
		first_claim = slot->first_claim;
		slot->first_claim = 0;
		slot->claims_since_success = 0;
		trip = true;
	}

out_unlock:
	spin_unlock_irqrestore(
		&trustix_datapath_inner_gso_probation_locks[set], flags);
	if (trip)
		trustix_datapath_inner_gso_record_probation_no_progress(
			first_claim);
}

static int trustix_datapath_inner_gso_reassembly_insert_range_locked(
	struct trustix_datapath_inner_gso_reassembly_slot *slot,
	__u32 start, __u32 end)
{
	__u32 merged_start = start;
	__u32 merged_end = end;
	__u32 removed_len = 0;
	unsigned int first = 0;
	unsigned int last;
	unsigned int removed;

	if (!slot || !slot->active || start >= end || end > slot->wire_len ||
	    slot->range_count >
		    TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_MAX_RANGES)
		return -EINVAL;
	while (first < slot->range_count &&
	       slot->ranges[first].end < start)
		first++;
	last = first;
	while (last < slot->range_count &&
	       slot->ranges[last].start <= merged_end) {
		merged_start = min(merged_start, slot->ranges[last].start);
		merged_end = max(merged_end, slot->ranges[last].end);
		removed_len += slot->ranges[last].end -
			       slot->ranges[last].start;
		last++;
	}
	removed = last - first;
	if (!removed) {
		if (slot->range_count >=
		    TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_MAX_RANGES)
			return -ENOSPC;
		memmove(&slot->ranges[first + 1], &slot->ranges[first],
			(slot->range_count - first) * sizeof(slot->ranges[0]));
		slot->range_count++;
	} else {
		memmove(&slot->ranges[first + 1], &slot->ranges[last],
			(slot->range_count - last) * sizeof(slot->ranges[0]));
		slot->range_count = slot->range_count - removed + 1;
	}
	slot->ranges[first].start = merged_start;
	slot->ranges[first].end = merged_end;
	slot->received_len = slot->received_len - removed_len +
			     merged_end - merged_start;
	slot->buffered_len = slot->range_count && !slot->ranges[0].start ?
			     slot->ranges[0].end : 0;
	slot->next_seq = slot->start_seq + slot->buffered_len;
	return 0;
}

static int trustix_datapath_tix_tcp_payload_info(
	const struct sk_buff *skb, __u8 ip_header_len, __u8 l4_header_len,
	__u32 *payload_offset, __u32 *payload_len, __u32 *sequence)
{
	const struct tcphdr *tcph;
	const struct iphdr *iph;
	int network_offset;
	__u32 total_len;

	if (!skb || !payload_offset || !payload_len || !sequence ||
	    ip_header_len != sizeof(*iph) || l4_header_len != sizeof(*tcph))
		return -EINVAL;
	network_offset = skb_network_offset(skb);
	if (network_offset < 0 || (__u32)network_offset > skb->len ||
	    skb->len - (__u32)network_offset < ip_header_len + l4_header_len)
		return -EMSGSIZE;
	iph = ip_hdr(skb);
	if (!iph || iph->protocol != IPPROTO_TCP)
		return -EPROTONOSUPPORT;
	total_len = ntohs(iph->tot_len);
	if (total_len < ip_header_len + l4_header_len ||
	    total_len > skb->len - (__u32)network_offset)
		return -EMSGSIZE;
	tcph = (const struct tcphdr *)(skb_network_header(skb) +
					 ip_header_len);
	if (tcph->syn || tcph->fin || tcph->rst)
		return -EPROTONOSUPPORT;
	*payload_offset = (__u32)network_offset + ip_header_len +
			  l4_header_len;
	*payload_len = total_len - ip_header_len - l4_header_len;
	*sequence = ntohl(tcph->seq);
	return *payload_len ? 0 : -ENODATA;
}

static int trustix_datapath_inner_gso_reassembly_start(
	struct sk_buff *skb,
	const struct trustix_datapath_ioc_classify *outer,
	int target_ifindex, __u32 frame_offset, __u32 available_len,
	const struct trustix_datapath_tixt_frame *frame, __u32 frame_sequence,
	bool account_timeout_faults)
{
	struct trustix_datapath_inner_gso_reassembly_key key;
	struct trustix_datapath_inner_gso_reassembly_slot *duplicate = NULL;
	struct trustix_datapath_inner_gso_reassembly_slot *empty = NULL;
	unsigned long flags;
	unsigned int set;
	unsigned int first;
	unsigned int i;
	unsigned int active = 0;
	unsigned int expired_faults = 0;
	unsigned long expired_oldest_progress = 0;
	int ret = 0;

	if (!skb || !outer || !frame ||
	    frame->header_len < TRUSTIX_DATAPATH_MIN_FRAME_HEADER_LEN ||
	    !frame->wire_len ||
	    frame->wire_len > TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_FRAME_MAX ||
	    available_len < frame->header_len ||
	    available_len >= frame->wire_len || frame_offset > skb->len ||
	    available_len > skb->len - frame_offset)
		return -EINVAL;
	if (!READ_ONCE(trustix_datapath_inner_gso_reassembly_data)) {
		trustix_datapath_rx_worker_inner_gso_oom++;
		return -ENOMEM;
	}
	if (unlikely(!trustix_datapath_inner_gso_runtime_permitted()))
		return -EAGAIN;

	trustix_datapath_inner_gso_reassembly_key_init(
		&key, skb, outer, target_ifindex);
	set = trustix_datapath_inner_gso_reassembly_set(&key);
	first = set * TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_PROBES;
	spin_lock_irqsave(&trustix_datapath_inner_gso_reassembly_locks[set],
			  flags);
	if (unlikely(!trustix_datapath_inner_gso_runtime_permitted())) {
		ret = -EAGAIN;
		goto out_unlock;
	}
	for (i = 0; i < TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_PROBES; i++) {
		struct trustix_datapath_inner_gso_reassembly_slot *slot =
			&trustix_datapath_inner_gso_reassembly_slots[first + i];

		if (slot->active && time_after_eq(jiffies, slot->expires)) {
			unsigned long progress =
				trustix_datapath_inner_gso_reassembly_expire_locked(
					slot, true, false);

			if (progress &&
			    (!expired_oldest_progress ||
			     time_before(progress, expired_oldest_progress)))
				expired_oldest_progress = progress;
			expired_faults++;
		}
		if (slot->active &&
		    trustix_datapath_inner_gso_reassembly_key_equal(
			    &slot->key, &key) &&
		    slot->flow_id == frame->flow_id &&
		    slot->epoch == frame->epoch &&
		    slot->start_seq == frame_sequence && !duplicate)
			duplicate = slot;
		if (slot->active)
			active++;
		else if (!empty)
			empty = slot;
	}
	if (duplicate) {
		trustix_datapath_rx_worker_inner_gso_duplicate_starts++;
		if (!duplicate->data || !duplicate->wire_len ||
		    duplicate->wire_len != frame->wire_len ||
		    duplicate->received_len >= duplicate->wire_len) {
			ret = -EBADMSG;
			goto out_unlock;
		}
		if (skb_copy_bits(skb, frame_offset, duplicate->data,
				  available_len)) {
			ret = -ENODATA;
			goto out_unlock;
		}
		ret = trustix_datapath_inner_gso_reassembly_insert_range_locked(
			duplicate, 0, available_len);
		if (ret)
			goto out_unlock;
		duplicate->expires =
			trustix_datapath_inner_gso_reassembly_deadline();
		goto out_unlock;
	}
	if (!empty) {
		trustix_datapath_rx_worker_inner_gso_collisions++;
		ret = -ENOSPC;
		goto out_unlock;
	}
	if (!empty->data) {
		trustix_datapath_rx_worker_inner_gso_oom++;
		ret = -ENOMEM;
		goto out_unlock;
	}
	if (skb_copy_bits(skb, frame_offset, empty->data, available_len)) {
		ret = -ENODATA;
		goto out_unlock;
	}
	empty->active = true;
	empty->flow_id = frame->flow_id;
	empty->epoch = frame->epoch;
	empty->key = key;
	empty->start_seq = frame_sequence;
	empty->next_seq = frame_sequence + available_len;
	empty->wire_len = frame->wire_len;
	empty->buffered_len = available_len;
	empty->received_len = available_len;
	empty->range_count = 1;
	empty->ranges[0].start = 0;
	empty->ranges[0].end = available_len;
	empty->expires = trustix_datapath_inner_gso_reassembly_deadline();
	empty->stream_last_progress = jiffies;
	trustix_datapath_rx_worker_inner_gso_reassembly_started++;
	if (active + 1 >
	    trustix_datapath_rx_worker_inner_gso_reassembly_high_watermark)
		trustix_datapath_rx_worker_inner_gso_reassembly_high_watermark =
			active + 1;

out_unlock:
	spin_unlock_irqrestore(
		&trustix_datapath_inner_gso_reassembly_locks[set], flags);
	if (account_timeout_faults) {
		while (expired_faults) {
			expired_faults--;
			trustix_datapath_inner_gso_record_reassembly_timeout(
				expired_oldest_progress);
		}
	}
	return ret;
}

static int trustix_datapath_inner_gso_reassembly_start_live(
	struct sk_buff *skb,
	const struct trustix_datapath_ioc_classify *outer,
	int target_ifindex, __u32 frame_offset, __u32 available_len,
	const struct trustix_datapath_tixt_frame *frame, __u32 frame_sequence,
	bool account_timeout_faults)
{
	struct trustix_datapath_state_slot *session = NULL;
	int ret;

	if (!frame)
		return -EINVAL;
	/*
	 * Keep session replacement and slot admission in state -> reassembly
	 * lock order. This closes the race where an old frame could enter after
	 * the updater had already cleared that session's stale slots.
	 */
	read_lock_bh(&trustix_datapath_state_lock);
	ret = trustix_datapath_plaintext_session_for_frame_locked(
		frame->flow_id, frame->epoch, IPPROTO_TCP, &session);
	if (ret || !(session->flags &
		     TRUSTIX_DATAPATH_SESSION_FLAG_RECEIVE_INNER_GSO)) {
		ret = -EAGAIN;
		goto out_state_unlock;
	}
	ret = trustix_datapath_inner_gso_reassembly_start(
		skb, outer, target_ifindex, frame_offset, available_len, frame,
		frame_sequence, account_timeout_faults);

out_state_unlock:
	read_unlock_bh(&trustix_datapath_state_lock);
	return ret;
}

static int trustix_datapath_inner_gso_reassembly_append(
	struct sk_buff *skb,
	const struct trustix_datapath_ioc_classify *outer,
	__u8 ip_header_len, __u8 l4_header_len, int target_ifindex,
	struct sk_buff **completed_skb, __u32 *tail_offset, __u32 *tail_len,
	bool account_timeout_faults)
{
	struct trustix_datapath_inner_gso_reassembly_key key;
	struct trustix_datapath_inner_gso_reassembly_slot *matched = NULL;
	struct sk_buff *completed = NULL;
	unsigned long flags;
	unsigned int set;
	unsigned int first;
	unsigned int i;
	__u32 payload_offset;
	__u32 payload_len;
	__u32 sequence;
	__u32 append_len;
	__u32 matched_offset = 0;
	__s32 closest_delta = 0;
	bool matched_expired = false;
	bool tuple_active = false;
	bool have_closest_delta = false;
	unsigned int expired_faults = 0;
	unsigned long expired_oldest_progress = 0;
	int ret;

	if (completed_skb)
		*completed_skb = NULL;
	if (tail_offset)
		*tail_offset = 0;
	if (tail_len)
		*tail_len = 0;
	if (!skb || !outer || !completed_skb || !tail_offset || !tail_len)
		return -EINVAL;
	if (unlikely(!trustix_datapath_inner_gso_runtime_permitted()))
		return -EAGAIN;
	ret = trustix_datapath_tix_tcp_payload_info(
		skb, ip_header_len, l4_header_len, &payload_offset,
		&payload_len, &sequence);
	if (ret)
		return ret;
	trustix_datapath_inner_gso_reassembly_key_init(
		&key, skb, outer, target_ifindex);
	set = trustix_datapath_inner_gso_reassembly_set(&key);
	first = set * TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_PROBES;
	spin_lock_irqsave(&trustix_datapath_inner_gso_reassembly_locks[set],
			  flags);
	if (unlikely(!trustix_datapath_inner_gso_runtime_permitted())) {
		ret = -EAGAIN;
		goto out_unlock;
	}
	for (i = 0; i < TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_PROBES; i++) {
		struct trustix_datapath_inner_gso_reassembly_slot *slot =
			&trustix_datapath_inner_gso_reassembly_slots[first + i];

		if (!slot->active ||
		    !trustix_datapath_inner_gso_reassembly_key_equal(
			    &slot->key, &key))
			continue;
		if (time_after_eq(jiffies, slot->expires)) {
			unsigned long progress;

			if (sequence - slot->start_seq < slot->wire_len)
				matched_expired = true;
			progress =
				trustix_datapath_inner_gso_reassembly_expire_locked(
					slot, false, false);
			if (progress &&
			    (!expired_oldest_progress ||
			     time_before(progress, expired_oldest_progress)))
				expired_oldest_progress = progress;
			expired_faults++;
			continue;
		}
		tuple_active = true;
		{
			__s32 delta = (__s32)(sequence - slot->next_seq);
			__s64 magnitude = delta < 0 ? -(__s64)delta : delta;
			__s64 closest_magnitude =
				closest_delta < 0 ? -(__s64)closest_delta :
						    closest_delta;

			if (!have_closest_delta || magnitude < closest_magnitude) {
				closest_delta = delta;
				have_closest_delta = true;
			}
		}
		if (sequence - slot->start_seq < slot->wire_len && !matched) {
			matched = slot;
			matched_offset = sequence - slot->start_seq;
			break;
		}
	}
	if (!matched) {
		trustix_datapath_rx_worker_inner_gso_continuation_drops++;
		if (matched_expired) {
			trustix_datapath_rx_worker_inner_gso_continuation_orphans++;
			ret = -ETIMEDOUT;
		} else if (tuple_active) {
			trustix_datapath_rx_worker_inner_gso_sequence_gaps++;
			trustix_datapath_rx_worker_inner_gso_last_sequence_gap =
				closest_delta;
			if (closest_delta < 0)
				trustix_datapath_rx_worker_inner_gso_sequence_gap_behind++;
			else
				trustix_datapath_rx_worker_inner_gso_sequence_gap_ahead++;
			ret = -EILSEQ;
		} else {
			trustix_datapath_rx_worker_inner_gso_continuation_orphans++;
			ret = -ENOENT;
		}
		goto out_unlock;
	}
	if (!matched->data || !matched->wire_len ||
	    matched->received_len >= matched->wire_len ||
	    !matched->range_count) {
		trustix_datapath_inner_gso_reassembly_reset_locked(matched);
		trustix_datapath_rx_worker_inner_gso_continuation_drops++;
		ret = -EINVAL;
		goto out_unlock;
	}
	append_len = min(payload_len, matched->wire_len - matched_offset);
	if (skb_copy_bits(skb, payload_offset,
			  matched->data + matched_offset, append_len)) {
		trustix_datapath_inner_gso_reassembly_reset_locked(matched);
		trustix_datapath_rx_worker_inner_gso_continuation_drops++;
		ret = -ENODATA;
		goto out_unlock;
	}
	ret = trustix_datapath_inner_gso_reassembly_insert_range_locked(
		matched, matched_offset, matched_offset + append_len);
	if (ret) {
		trustix_datapath_inner_gso_reassembly_reset_locked(matched);
		trustix_datapath_rx_worker_inner_gso_continuation_drops++;
		goto out_unlock;
	}
	matched->expires = trustix_datapath_inner_gso_reassembly_deadline();
	trustix_datapath_rx_worker_inner_gso_continuation_matched++;
	*tail_len = payload_len - append_len;
	if (*tail_len)
		*tail_offset = payload_offset + append_len;
	if (matched->received_len < matched->wire_len) {
		ret = 0;
		goto out_unlock;
	}
	completed = alloc_skb(matched->wire_len, GFP_ATOMIC);
	if (!completed) {
		trustix_datapath_rx_worker_inner_gso_oom++;
		trustix_datapath_rx_worker_inner_gso_continuation_drops++;
		trustix_datapath_inner_gso_reassembly_reset_locked(matched);
		ret = -ENOMEM;
		goto out_unlock;
	}
	skb_put_data(completed, matched->data, matched->wire_len);
	trustix_datapath_inner_gso_reassembly_reset_locked(matched);
	*completed_skb = completed;
	ret = 0;

out_unlock:
	spin_unlock_irqrestore(
		&trustix_datapath_inner_gso_reassembly_locks[set], flags);
	if (account_timeout_faults) {
		while (expired_faults) {
			expired_faults--;
			trustix_datapath_inner_gso_record_reassembly_timeout(
				expired_oldest_progress);
		}
	}
	return ret;
}

static int trustix_datapath_rx_worker_process_tixt_frame(
	struct sk_buff *frame_skb, struct sk_buff *queue_source_skb,
	const struct trustix_datapath_ioc_classify *outer,
	struct net_device *target_dev, __u32 frame_offset,
	const struct trustix_datapath_tixt_frame *frame,
	struct trustix_datapath_rx_validation_cache *validation_cache,
	unsigned int *queued_frames)
{
	struct trustix_datapath_rx_stage_view view = {};
	struct trustix_datapath_ioc_classify inner = {};
	struct sk_buff *inner_skb = NULL;
	__u8 inner_header[sizeof(struct iphdr) + 60];
	__u8 inner_ip_header_len = 0;
	__u8 inner_l4_header_len = 0;
	__u8 *regular_packet = NULL;
	__u32 inner_offset;
	__u32 copy_len;
	unsigned int represented_frames = 1;
	unsigned int queued = 0;
	bool inner_gso;
	int ret;

	if (queued_frames)
		*queued_frames = 0;
	if (!frame_skb || !outer || !target_dev || !frame ||
	    !validation_cache || !queued_frames || !frame->wire_len ||
	    frame_offset > frame_skb->len ||
	    frame->wire_len > frame_skb->len - frame_offset ||
	    frame->payload_len > TRUSTIX_DATAPATH_PACKET_MAX_LEN ||
	    check_add_overflow(frame_offset, (__u32)frame->header_len,
			       &inner_offset) ||
	    inner_offset > frame_skb->len ||
	    frame->payload_len > frame_skb->len - inner_offset)
		return -EMSGSIZE;
	inner_gso = frame->flags & TRUSTIX_DATAPATH_TIXT_FLAG_INNER_GSO;
	copy_len = min_t(__u32, frame->payload_len, sizeof(inner_header));
	if (skb_copy_bits(frame_skb, inner_offset, inner_header, copy_len))
		return -ENODATA;
	ret = trustix_datapath_parse_ipv4_packet(
		inner_header, frame->payload_len, &inner,
		&inner_ip_header_len, &inner_l4_header_len);
	if (ret)
		return ret;
	view.frame = *frame;
	view.inner = inner;
	view.inner_packet = inner_header;
	view.tixt_len = frame->wire_len;
	view.inner_offset = inner_offset;
	view.inner_ip_header_len = inner_ip_header_len;
	view.inner_l4_header_len = inner_l4_header_len;
	ret = trustix_datapath_rx_stage_validate_batch(
		outer, &view, validation_cache);
	if (ret)
		return ret;

	if (inner_gso) {
		represented_frames = frame->fragment_count;
		ret = trustix_datapath_rx_worker_build_inner_gso_skb(
			frame_skb, inner_offset, frame, target_dev, &inner_skb);
		if (ret)
			goto out;
		ret = trustix_datapath_rx_worker_prepare_l2_gso_skb(
			inner_skb, target_dev);
		if (ret)
			goto out;
	} else {
		regular_packet = kmalloc(frame->payload_len, GFP_ATOMIC);
		if (!regular_packet) {
			ret = -ENOMEM;
			goto out;
		}
		if (skb_copy_bits(frame_skb, inner_offset, regular_packet,
				  frame->payload_len)) {
			ret = -ENODATA;
			goto out;
		}
		ret = trustix_datapath_rx_worker_build_xmit_inner_skb_flags(
			target_dev, regular_packet, frame->payload_len,
			frame->flags, &inner_skb);
		if (ret)
			goto out;
	}
	ret = trustix_datapath_rx_worker_queue_l2_skb_from_hook(
		queue_source_skb, target_dev, &inner_skb, inner_skb->len,
		represented_frames, &queued);
	if (ret || !queued) {
		if (!ret)
			ret = -EIO;
		goto out;
	}
	*queued_frames = queued;
	if (inner_gso) {
		trustix_datapath_rx_worker_inner_gso_packets++;
		trustix_datapath_rx_worker_inner_gso_segments +=
			frame->fragment_count;
		trustix_datapath_inner_gso_reassembly_record_progress(
			queue_source_skb, outer, target_dev->ifindex, frame);
	} else {
		trustix_datapath_rx_worker_inner_gso_regular_frames++;
	}

out:
	kfree(regular_packet);
	kfree_skb(inner_skb);
	return ret;
}

static int trustix_datapath_rx_worker_try_inner_gso(
	struct sk_buff *skb, const struct trustix_datapath_ioc_classify *outer,
	__u8 ip_header_len, __u8 l4_header_len, int target_ifindex,
	struct net_device *target_dev_hint, __u8 tcp_shard,
	bool enforce_session_state, bool *candidate, unsigned int *queued_frames)
{
	struct trustix_datapath_rx_validation_cache validation_cache = {};
	struct trustix_datapath_tixt_frame partial_frame = {};
	struct net_device *target_dev = NULL;
	__u32 tixt_offset;
	__u32 tixt_len;
	__u32 cursor_offset;
	__u32 remaining;
	__u32 tcp_sequence;
	unsigned int complete_frames = 0;
	unsigned int inner_frames = 0;
	unsigned int queued_total = 0;
	bool has_inner_gso = false;
	bool partial = false;
	bool stored_partial = false;
	int ret = 0;

	if (candidate)
		*candidate = false;
	if (queued_frames)
		*queued_frames = 0;
	if (!skb || !outer || !candidate || !queued_frames ||
	    outer->protocol != IPPROTO_TCP || ip_header_len != 20 ||
	    l4_header_len != 20)
		return -EOPNOTSUPP;
	ret = trustix_datapath_tix_tcp_payload_info(
		skb, ip_header_len, l4_header_len, &tixt_offset, &tixt_len,
		&tcp_sequence);
	if (ret)
		return ret;

	/*
	 * GRO may concatenate adjacent outer GSO packets. Scan the complete
	 * TIX stream first so a regular frame followed by inner-GSO (or the
	 * reverse transition) is consumed by one path instead of being treated
	 * as malformed trailing bytes.
	 */
	cursor_offset = tixt_offset;
	remaining = tixt_len;
	while (remaining) {
		struct trustix_datapath_tixt_frame frame = {};

		if (complete_frames + (partial ? 1U : 0U) >=
		    TRUSTIX_DATAPATH_RX_WORKER_STREAM_MAX_FRAMES)
			return has_inner_gso ? -E2BIG : -EOPNOTSUPP;
		ret = trustix_datapath_parse_tixt_skb_header(
			skb, cursor_offset, remaining, &frame);
		if (ret)
			return has_inner_gso ? ret : -EOPNOTSUPP;
		if (frame.flags & TRUSTIX_DATAPATH_TIXT_FLAG_INNER_GSO) {
			has_inner_gso = true;
			inner_frames++;
		}
		if (!frame.wire_len ||
		    frame.payload_len > TRUSTIX_DATAPATH_PACKET_MAX_LEN)
			return has_inner_gso ? -EMSGSIZE : -EOPNOTSUPP;
		if (frame.wire_len > remaining) {
			partial = true;
			partial_frame = frame;
			break;
		}
		cursor_offset += frame.wire_len;
		remaining -= frame.wire_len;
		complete_frames++;
	}
	if (!has_inner_gso)
		return -EOPNOTSUPP;
	*candidate = true;
	trustix_datapath_rx_worker_inner_gso_candidates += inner_frames;
	if (unlikely(!trustix_datapath_inner_gso_runtime_permitted()))
		return -EAGAIN;
	if (partial)
		trustix_datapath_rx_worker_inner_gso_partial_frames++;
	if (complete_frames > 1) {
		trustix_datapath_rx_worker_inner_gso_stream_packets++;
		trustix_datapath_rx_worker_inner_gso_stream_frames +=
			complete_frames;
	}
	if (!complete_frames && partial) {
		if (!tcp_shard)
			return -EMSGSIZE;
		if (enforce_session_state)
			ret = trustix_datapath_inner_gso_reassembly_start_live(
				skb, outer, target_ifindex, cursor_offset,
				remaining, &partial_frame,
				tcp_sequence + (cursor_offset - tixt_offset), true);
		else
			ret = trustix_datapath_inner_gso_reassembly_start(
				skb, outer, target_ifindex, cursor_offset,
				remaining, &partial_frame,
				tcp_sequence + (cursor_offset - tixt_offset), false);
		if (ret) {
			trustix_datapath_rx_worker_inner_gso_errors++;
			return ret;
		}
		return 0;
	}
	ret = trustix_datapath_rx_worker_target_dev_hint(
		skb, &target_dev, target_ifindex, target_dev_hint);
	if (ret) {
		trustix_datapath_rx_worker_inner_gso_errors++;
		return ret;
	}
	if (!trustix_datapath_rx_worker_dev_ready(target_dev)) {
		trustix_datapath_rx_worker_inner_gso_errors++;
		ret = -ENETDOWN;
		goto out;
	}

	cursor_offset = tixt_offset;
	remaining = tixt_len;
	while (complete_frames) {
		struct trustix_datapath_tixt_frame frame = {};
		unsigned int frame_queued = 0;

		ret = trustix_datapath_parse_tixt_skb_header(
			skb, cursor_offset, remaining, &frame);
		if (ret)
			goto frame_error;
		if (!frame.wire_len || frame.wire_len > remaining) {
			ret = -EMSGSIZE;
			goto frame_error;
		}
		ret = trustix_datapath_rx_worker_process_tixt_frame(
			skb, skb, outer, target_dev, cursor_offset, &frame,
			&validation_cache, &frame_queued);
		if (ret)
			goto frame_error;
		queued_total += frame_queued;
		cursor_offset += frame.wire_len;
		remaining -= frame.wire_len;
		complete_frames--;
		continue;

frame_error:
		if (ret == -EBADMSG || ret == -EINVAL ||
		    ret == -EPROTONOSUPPORT || ret == -EMSGSIZE)
			trustix_datapath_rx_worker_inner_gso_malformed++;
		else
			trustix_datapath_rx_worker_inner_gso_errors++;
		goto out;
	}
	if (partial) {
		if (!tcp_shard) {
			ret = -EMSGSIZE;
			goto out;
		}
		if (enforce_session_state)
			ret = trustix_datapath_inner_gso_reassembly_start_live(
				skb, outer, target_ifindex, cursor_offset,
				remaining, &partial_frame,
				tcp_sequence + (cursor_offset - tixt_offset), true);
		else
			ret = trustix_datapath_inner_gso_reassembly_start(
				skb, outer, target_ifindex, cursor_offset,
				remaining, &partial_frame,
				tcp_sequence + (cursor_offset - tixt_offset), false);
		if (ret) {
			trustix_datapath_rx_worker_inner_gso_errors++;
			goto out;
		}
		stored_partial = true;
	}
	if (!queued_total && !stored_partial) {
		trustix_datapath_rx_worker_inner_gso_errors++;
		ret = -EIO;
		goto out;
	}
	*queued_frames = queued_total;
	ret = 0;
out:
	if (queued_total)
		*queued_frames = queued_total;
	if (target_dev)
		dev_put(target_dev);
	return ret;
}

static int trustix_datapath_rx_worker_consume_inner_gso_continuation(
	struct sk_buff *skb,
	const struct trustix_datapath_ioc_classify *outer,
	__u8 ip_header_len, __u8 l4_header_len, int target_ifindex,
	struct net_device *target_dev_hint, unsigned int *queued_frames)
{
	struct trustix_datapath_rx_validation_cache validation_cache = {};
	struct trustix_datapath_tixt_frame frame = {};
	struct net_device *target_dev = NULL;
	struct sk_buff *completed_skb = NULL;
	__u32 payload_offset;
	__u32 payload_len;
	__u32 tcp_sequence;
	__u32 tail_offset = 0;
	__u32 tail_len = 0;
	__u32 cursor_offset;
	__u32 remaining;
	unsigned int queued_total = 0;
	unsigned int tail_frames = 0;
	int ret;

	if (queued_frames)
		*queued_frames = 0;
	if (!skb || !outer || !queued_frames)
		return -EINVAL;
	ret = trustix_datapath_inner_gso_reassembly_append(
		skb, outer, ip_header_len, l4_header_len, target_ifindex,
		&completed_skb, &tail_offset, &tail_len, true);
	if (ret)
		return ret;
	if (!completed_skb && !tail_len)
		return 0;
	ret = trustix_datapath_tix_tcp_payload_info(
		skb, ip_header_len, l4_header_len, &payload_offset,
		&payload_len, &tcp_sequence);
	if (ret)
		goto error;
	if (completed_skb) {
		ret = trustix_datapath_parse_tixt_skb_header(
			completed_skb, 0, completed_skb->len, &frame);
		if (ret || frame.wire_len != completed_skb->len) {
			ret = ret ?: -EMSGSIZE;
			goto malformed;
		}
	}
	ret = trustix_datapath_rx_worker_target_dev_hint(
		skb, &target_dev, target_ifindex, target_dev_hint);
	if (ret)
		goto error;
	if (!trustix_datapath_rx_worker_dev_ready(target_dev)) {
		ret = -ENETDOWN;
		goto error;
	}
	if (completed_skb) {
		unsigned int queued = 0;

		ret = trustix_datapath_rx_worker_process_tixt_frame(
			completed_skb, skb, outer, target_dev, 0, &frame,
			&validation_cache, &queued);
		if (ret)
			goto frame_error;
		queued_total += queued;
		trustix_datapath_rx_worker_inner_gso_reassembly_completed++;
		trustix_datapath_inner_gso_record_reassembly_success();
	}

	cursor_offset = tail_offset;
	remaining = tail_len;
	while (remaining) {
		unsigned int queued = 0;

		if (tail_frames >=
		    TRUSTIX_DATAPATH_RX_WORKER_STREAM_MAX_FRAMES) {
			ret = -E2BIG;
			goto malformed;
		}
		memset(&frame, 0, sizeof(frame));
		ret = trustix_datapath_parse_tixt_skb_header(
			skb, cursor_offset, remaining, &frame);
		if (ret)
			goto malformed;
		if (!frame.wire_len ||
		    frame.payload_len > TRUSTIX_DATAPATH_PACKET_MAX_LEN) {
			ret = -EMSGSIZE;
			goto malformed;
		}
		if (frame.flags & TRUSTIX_DATAPATH_TIXT_FLAG_INNER_GSO)
			trustix_datapath_rx_worker_inner_gso_candidates++;
		if (frame.wire_len > remaining) {
			trustix_datapath_rx_worker_inner_gso_partial_frames++;
			ret = trustix_datapath_inner_gso_reassembly_start_live(
				skb, outer, target_ifindex, cursor_offset,
				remaining, &frame,
				tcp_sequence +
					(cursor_offset - payload_offset),
				true);
			if (ret)
				goto frame_error;
			remaining = 0;
			break;
		}
		ret = trustix_datapath_rx_worker_process_tixt_frame(
			skb, skb, outer, target_dev, cursor_offset, &frame,
			&validation_cache, &queued);
		if (ret)
			goto frame_error;
		queued_total += queued;
		tail_frames++;
		cursor_offset += frame.wire_len;
		remaining -= frame.wire_len;
	}
	if (tail_frames) {
		trustix_datapath_rx_worker_inner_gso_tail_frames += tail_frames;
		trustix_datapath_rx_worker_inner_gso_stream_packets++;
		trustix_datapath_rx_worker_inner_gso_stream_frames +=
			tail_frames + (completed_skb ? 1 : 0);
	}
	*queued_frames = queued_total;
	ret = 0;
	goto out;

malformed:
	trustix_datapath_rx_worker_inner_gso_malformed++;
	goto drop;
frame_error:
	if (ret == -EBADMSG || ret == -EINVAL ||
	    ret == -EPROTONOSUPPORT || ret == -EMSGSIZE)
		trustix_datapath_rx_worker_inner_gso_malformed++;
	else
		trustix_datapath_rx_worker_inner_gso_errors++;
	goto drop;
error:
	trustix_datapath_rx_worker_inner_gso_errors++;
drop:
	trustix_datapath_rx_worker_inner_gso_continuation_drops++;
out:
	if (queued_total)
		*queued_frames = queued_total;
	if (target_dev)
		dev_put(target_dev);
	kfree_skb(completed_skb);
	return ret;
}

static bool
trustix_datapath_rx_worker_can_steal_skb(
	struct sk_buff *skb, const struct trustix_datapath_rx_stage_view *view)
{
	if (!READ_ONCE(trustix_datapath_rx_worker_steal_skb))
		return false;
	/*
	 * Do not take ownership of the hook skb in the first-release datapath.
	 * The old stolen-skb variants could race the netfilter caller and reboot
	 * test nodes under TIX-TCP load. Keep the knobs writable for profile
	 * compatibility, but route traffic through the validated copy/worker path.
	 */
	(void)skb;
	(void)view;
	trustix_datapath_rx_worker_steal_fallbacks++;
	return false;
}

static bool
trustix_datapath_rx_worker_payload_fits_target(
	const struct trustix_datapath_rx_stage_view *view,
	const struct net_device *target_dev)
{
	if (!view || !target_dev || !view->frame.payload_len)
		return false;
	if (!target_dev->mtu)
		return true;
	if (view->frame.payload_len <= target_dev->mtu)
		return true;
	return view->inner.protocol == IPPROTO_TCP;
}

static void
trustix_datapath_rx_worker_mark_inner_checksum(struct sk_buff *skb)
{
	const struct iphdr *iph;

	if (!skb || skb->len < sizeof(*iph)) {
		if (skb)
			skb->ip_summed = CHECKSUM_NONE;
		return;
	}
	iph = (const struct iphdr *)skb->data;
	if (iph->version == 4 &&
	    (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP))
		skb->ip_summed = CHECKSUM_UNNECESSARY;
	else
		skb->ip_summed = CHECKSUM_NONE;
}

static __sum16
trustix_datapath_rx_worker_l4_checksum(struct iphdr *iph, void *l4,
				       __u32 l4_len, __u8 protocol)
{
	__wsum sum;

	sum = csum_partial(l4, l4_len, 0);
	return csum_tcpudp_magic(iph->saddr, iph->daddr, l4_len, protocol,
				 sum);
}

static __sum16
trustix_datapath_rx_worker_tcp_checksum_append_payload(
	struct tcphdr *tcph, __u32 old_tcp_len, __u32 new_tcp_len,
	const void *payload, __u32 payload_len)
{
	__wsum payload_sum;
	__sum16 check;
	__wsum sum;

	if (!tcph || !payload || !payload_len || old_tcp_len > U16_MAX ||
	    new_tcp_len > U16_MAX)
		return 0;
	check = tcph->check;
	csum_replace2(&check, htons((__u16)old_tcp_len),
		      htons((__u16)new_tcp_len));
	sum = ~csum_unfold(check);
	payload_sum = csum_partial(payload, payload_len, 0);
	sum = csum_block_add(sum, payload_sum, old_tcp_len);
	return csum_fold(sum);
}

static void
trustix_datapath_rx_worker_fix_ipv4_header_checksum(struct iphdr *iph,
						    __u32 ip_header_len)
{
	iph->check = 0;
	iph->check = (__force __sum16)htons(
		(__u16)trustix_datapath_ipv4_checksum((const __u8 *)iph,
						      ip_header_len));
}

static bool
trustix_datapath_rx_worker_trust_tcp_checksum(struct iphdr *iph,
					      __u32 ip_header_len,
					      __u32 l4_len,
					      struct tcphdr **tcph_out)
{
	struct tcphdr *tcph;
	unsigned int min_len;
	__u32 tcp_header_len;
	__u32 payload_len;
	bool trust_ack_only;

	min_len = READ_ONCE(
		trustix_datapath_rx_worker_xmit_trust_tcp_checksum_min_len);
	trust_ack_only = READ_ONCE(
		trustix_datapath_rx_worker_xmit_trust_tcp_checksum_ack_only);
	if ((!min_len && !trust_ack_only) || iph->protocol != IPPROTO_TCP ||
	    l4_len < sizeof(*tcph))
		return false;
	tcph = (struct tcphdr *)((__u8 *)iph + ip_header_len);
	tcp_header_len = tcph->doff * 4;
	if (tcph->doff < 5 || tcp_header_len < sizeof(*tcph) ||
	    l4_len < tcp_header_len)
		return false;
	payload_len = l4_len - tcp_header_len;
	if (!payload_len) {
		if (!trust_ack_only || !tcph->ack || tcph->syn || tcph->fin ||
		    tcph->rst)
			return false;
		if (trustix_datapath_rx_worker_l4_checksum(
			    iph, tcph, l4_len, IPPROTO_TCP)) {
			trustix_datapath_rx_worker_checksum_trust_fallbacks++;
			return false;
		}
		if (tcph_out)
			*tcph_out = tcph;
		return true;
	}
	if (payload_len < min_len)
		return false;
	if (trustix_datapath_rx_worker_l4_checksum(iph, tcph, l4_len,
						   IPPROTO_TCP)) {
		trustix_datapath_rx_worker_checksum_trust_fallbacks++;
		return false;
	}
	if (tcph_out)
		*tcph_out = tcph;
	return true;
}

static __always_inline bool trustix_datapath_rx_worker_hot_stats_enabled(void)
{
	return READ_ONCE(trustix_datapath_rx_worker_hot_stats);
}

static __always_inline void
trustix_datapath_rx_worker_mark_self_generated(struct sk_buff *skb)
{
	if (!skb)
		return;
	if (!(skb->mark & TRUSTIX_DATAPATH_SKB_MARK_RX_WORKER)) {
		skb->mark |= TRUSTIX_DATAPATH_SKB_MARK_RX_WORKER;
		trustix_datapath_rx_worker_self_marked++;
	}
}

static __always_inline void
trustix_datapath_rx_worker_request_tc_skip(struct sk_buff *skb)
{
#if defined(CONFIG_NET_XGRESS)
	if (!skb)
		return;
	if (!READ_ONCE(trustix_datapath_rx_worker_tc_skip_classify))
		return;
	if (!skb->tc_skip_classify) {
		skb->tc_skip_classify = 1;
		trustix_datapath_rx_worker_tc_skip_requests++;
	}
#else
	(void)skb;
#endif
}

static __always_inline void
trustix_datapath_rx_worker_record_xmit_target(struct net_device *dev)
{
	if (!dev)
		return;
	WRITE_ONCE(trustix_datapath_rx_worker_last_target_ifindex,
		   dev->ifindex);
	WRITE_ONCE(trustix_datapath_rx_worker_last_target_type,
		   dev->type);
	WRITE_ONCE(trustix_datapath_rx_worker_last_target_priv_flags,
		   dev->priv_flags);
	if (dev->priv_flags & IFF_EBRIDGE)
		trustix_datapath_rx_worker_bridge_targets++;
}

static __always_inline void
trustix_datapath_rx_worker_prepare_self_generated_xmit(
	struct sk_buff *skb, struct net_device *dev)
{
	if (skb && dev) {
		struct iphdr *iph = NULL;
		unsigned int transport_offset = ETH_HLEN;

		skb_orphan(skb);
		skb_scrub_packet(skb, true);
		skb->dev = dev;
		if (skb->len >= ETH_HLEN) {
			skb_reset_mac_header(skb);
			skb->protocol = eth_hdr(skb)->h_proto;
			if (skb->protocol == htons(ETH_P_IP) &&
			    skb->len >= ETH_HLEN + sizeof(*iph)) {
				skb_set_network_header(skb, ETH_HLEN);
				iph = (struct iphdr *)skb_network_header(skb);
				if (iph->version == 4 && iph->ihl >= 5 &&
				    skb->len >=
					    ETH_HLEN +
						    (unsigned int)iph->ihl * 4) {
					transport_offset +=
						(unsigned int)iph->ihl * 4;
					skb_set_transport_header(
						skb, transport_offset);
				}
			}
		} else {
			skb_reset_mac_header(skb);
			skb->protocol = htons(ETH_P_IP);
		}
		skb->pkt_type = PACKET_OUTGOING;
		skb->mac_len = ETH_HLEN;
		if (!skb_is_gso(skb) && skb->ip_summed != CHECKSUM_PARTIAL) {
			skb->ip_summed = CHECKSUM_NONE;
			skb->csum = 0;
			skb->csum_start = 0;
			skb->csum_offset = 0;
		}
		skb->encapsulation = 0;
		skb->csum_level = 0;
		skb_reset_inner_headers(skb);
		skb_set_queue_mapping(skb, 0);
		memset(skb->cb, 0, sizeof(skb->cb));
		trustix_datapath_rx_worker_xmit_scrubbed++;
	}
	trustix_datapath_rx_worker_mark_self_generated(skb);
	trustix_datapath_rx_worker_request_tc_skip(skb);
	trustix_datapath_rx_worker_record_xmit_target(dev);
}

static __always_inline void
trustix_datapath_rx_worker_record_xmit_ret(int ret)
{
	WRITE_ONCE(trustix_datapath_rx_worker_last_xmit_ret, ret);
	if (ret == NET_XMIT_SUCCESS)
		trustix_datapath_rx_worker_xmit_ok++;
	else if (ret == NET_XMIT_CN)
		trustix_datapath_rx_worker_xmit_cn++;
	else {
		WRITE_ONCE(trustix_datapath_rx_worker_last_xmit_error_ret,
			   ret);
		if (ret == NET_XMIT_DROP)
			trustix_datapath_rx_worker_xmit_drop++;
		else
			trustix_datapath_rx_worker_xmit_other_ret_errors++;
		trustix_datapath_rx_worker_xmit_ret_errors++;
	}
}

static __always_inline void
trustix_datapath_rx_worker_count_injected(unsigned int packets)
{
	trustix_datapath_rx_worker_injected += packets;
}

static __always_inline void
trustix_datapath_rx_worker_count_xmit_packets(unsigned int packets)
{
	if (trustix_datapath_rx_worker_hot_stats_enabled())
		trustix_datapath_rx_worker_xmit_packets += packets;
}

static __always_inline void
trustix_datapath_rx_worker_count_receive_packets(unsigned int packets)
{
	if (trustix_datapath_rx_worker_hot_stats_enabled())
		trustix_datapath_rx_worker_receive_packets += packets;
}

static __always_inline void
trustix_datapath_rx_worker_count_inline_xmit(unsigned int packets)
{
	if (trustix_datapath_rx_worker_hot_stats_enabled())
		trustix_datapath_rx_worker_inline_xmit_packets += packets;
}

static __always_inline void
trustix_datapath_rx_worker_count_pair_stored(unsigned int packets)
{
	if (trustix_datapath_rx_worker_hot_stats_enabled())
		trustix_datapath_rx_worker_inline_pair_stored += packets;
}

static __always_inline void
trustix_datapath_rx_worker_count_pair_packets(unsigned int packets)
{
	if (trustix_datapath_rx_worker_hot_stats_enabled())
		trustix_datapath_rx_worker_inline_pair_packets += packets;
}

static __always_inline void
trustix_datapath_rx_worker_count_pair_flushes(unsigned int packets)
{
	if (trustix_datapath_rx_worker_hot_stats_enabled())
		trustix_datapath_rx_worker_inline_pair_flushes += packets;
}

static __always_inline void
trustix_datapath_rx_worker_count_single_coalesce_stored(unsigned int packets)
{
	if (trustix_datapath_rx_worker_hot_stats_enabled())
		trustix_datapath_rx_worker_single_coalesce_stored += packets;
}

static __always_inline void
trustix_datapath_rx_worker_count_single_coalesce(unsigned int packets,
						 unsigned int frames)
{
	if (!trustix_datapath_rx_worker_hot_stats_enabled())
		return;
	trustix_datapath_rx_worker_single_coalesce_packets += packets;
	trustix_datapath_rx_worker_single_coalesce_frames += frames;
}

static __always_inline void
trustix_datapath_rx_worker_count_single_coalesce_flushes(unsigned int packets)
{
	if (trustix_datapath_rx_worker_hot_stats_enabled())
		trustix_datapath_rx_worker_single_coalesce_flushes += packets;
}

static __always_inline void
trustix_datapath_rx_worker_count_stream_coalesce(unsigned int packets,
						 unsigned int frames)
{
	if (!trustix_datapath_rx_worker_hot_stats_enabled())
		return;
	trustix_datapath_rx_worker_stream_coalesce_packets += packets;
	trustix_datapath_rx_worker_stream_coalesce_frames += frames;
}

static __always_inline void
trustix_datapath_rx_worker_count_stream_packets(unsigned int packets,
						unsigned int frames)
{
	if (!trustix_datapath_rx_worker_hot_stats_enabled())
		return;
	trustix_datapath_rx_worker_stream_packets += packets;
	trustix_datapath_rx_worker_stream_frames += frames;
}

static __always_inline void
trustix_datapath_rx_worker_count_stream_batch(unsigned int packets,
					      unsigned int frames)
{
	if (!trustix_datapath_rx_worker_hot_stats_enabled())
		return;
	trustix_datapath_rx_worker_stream_batch_packets += packets;
	trustix_datapath_rx_worker_stream_batch_frames += frames;
}

static __always_inline void
trustix_datapath_rx_worker_count_checksum_fixed(unsigned int packets)
{
	if (trustix_datapath_rx_worker_hot_stats_enabled())
		trustix_datapath_rx_worker_checksum_fixed += packets;
}

static __always_inline void
trustix_datapath_rx_worker_count_inline_copy_csum_hits(unsigned int packets)
{
	if (trustix_datapath_rx_worker_hot_stats_enabled())
		trustix_datapath_rx_worker_inline_xmit_copy_csum_hits += packets;
}

static __always_inline void
trustix_datapath_rx_worker_count_dst_mac_hits(unsigned int packets)
{
	if (trustix_datapath_rx_worker_hot_stats_enabled())
		trustix_datapath_rx_worker_dst_mac_hits += packets;
}

static __always_inline void
trustix_datapath_rx_worker_count_hash_tx_queue(__u16 queue)
{
	trustix_datapath_rx_worker_xmit_hash_tx_queue_sets++;
	switch (queue) {
	case 0:
		trustix_datapath_rx_worker_xmit_hash_tx_queue_q0++;
		break;
	case 1:
		trustix_datapath_rx_worker_xmit_hash_tx_queue_q1++;
		break;
	case 2:
		trustix_datapath_rx_worker_xmit_hash_tx_queue_q2++;
		break;
	case 3:
		trustix_datapath_rx_worker_xmit_hash_tx_queue_q3++;
		break;
	case 4:
		trustix_datapath_rx_worker_xmit_hash_tx_queue_q4++;
		break;
	case 5:
		trustix_datapath_rx_worker_xmit_hash_tx_queue_q5++;
		break;
	case 6:
		trustix_datapath_rx_worker_xmit_hash_tx_queue_q6++;
		break;
	case 7:
		trustix_datapath_rx_worker_xmit_hash_tx_queue_q7++;
		break;
	default:
		trustix_datapath_rx_worker_xmit_hash_tx_queue_other++;
		break;
	}
}

static void
trustix_datapath_tx_plaintext_count_hash_tx_queue(__u16 queue)
{
	trustix_datapath_tx_plaintext_hash_tx_queue_sets++;
	switch (queue) {
	case 0:
		trustix_datapath_tx_plaintext_hash_tx_queue_q0++;
		break;
	case 1:
		trustix_datapath_tx_plaintext_hash_tx_queue_q1++;
		break;
	case 2:
		trustix_datapath_tx_plaintext_hash_tx_queue_q2++;
		break;
	case 3:
		trustix_datapath_tx_plaintext_hash_tx_queue_q3++;
		break;
	case 4:
		trustix_datapath_tx_plaintext_hash_tx_queue_q4++;
		break;
	case 5:
		trustix_datapath_tx_plaintext_hash_tx_queue_q5++;
		break;
	case 6:
		trustix_datapath_tx_plaintext_hash_tx_queue_q6++;
		break;
	case 7:
		trustix_datapath_tx_plaintext_hash_tx_queue_q7++;
		break;
	default:
		trustix_datapath_tx_plaintext_hash_tx_queue_other++;
		break;
	}
}

static __always_inline __u16
trustix_datapath_tx_plaintext_hash_tx_queue_for_transport(
	__u32 hash, unsigned int txq_count, __u8 outer_protocol,
	bool partition_transport)
{
	unsigned int subset_count;
	__u32 mixed;

	if (!txq_count)
		return 0;
	mixed = trustix_datapath_rx_worker_mix_hash(hash);
	if (!partition_transport || txq_count <= 1)
		return (__u16)(mixed % txq_count);

	switch (outer_protocol) {
	case IPPROTO_UDP:
		subset_count = (txq_count + 1) / 2;
		return (__u16)((mixed % subset_count) * 2);
	case IPPROTO_TCP:
		subset_count = txq_count / 2;
		return (__u16)((mixed % subset_count) * 2 + 1);
	default:
		return (__u16)(mixed % txq_count);
	}
}

static __always_inline __u16
trustix_datapath_tx_plaintext_tix_tcp_shard_tx_queue(
	__u8 shard, unsigned int txq_count, bool partition_transport)
{
	unsigned int subset_count;

	if (!txq_count)
		return 0;
	if (!partition_transport || txq_count <= 1)
		return (__u16)(shard % txq_count);

	subset_count = txq_count / 2;
	return (__u16)((shard % subset_count) * 2 + 1);
}

static bool trustix_datapath_rx_worker_hash_ipv4_at_offset(
	struct sk_buff *skb, unsigned int offset, unsigned int head_len,
	__u32 *hash_out)
{
	const struct udphdr *udph;
	const struct tcphdr *tcph;
	const struct iphdr *iph;
	__u32 ip_header_len;
	__u32 l4_offset;
	__u32 hash;

	if (!skb || !hash_out || offset > head_len ||
	    head_len - offset < sizeof(*iph))
		return false;
	iph = (const struct iphdr *)(skb->data + offset);
	if (iph->version != 4 || iph->ihl < 5)
		return false;
	ip_header_len = iph->ihl * 4;
	if (ip_header_len < sizeof(*iph) ||
	    offset + ip_header_len > head_len)
		return false;
	hash = (__force __u32)iph->saddr ^
	       ((__force __u32)iph->daddr << 7) ^
	       ((__force __u32)iph->daddr >> 9) ^
	       ((__u32)iph->protocol << 24);
	l4_offset = offset + ip_header_len;
	switch (iph->protocol) {
	case IPPROTO_TCP:
		if (l4_offset + sizeof(*tcph) <= head_len) {
			tcph = (const struct tcphdr *)(skb->data + l4_offset);
			hash ^= ((__force __u16)tcph->source << 16) |
				(__force __u16)tcph->dest;
		}
		break;
	case IPPROTO_UDP:
		if (l4_offset + sizeof(*udph) <= head_len) {
			udph = (const struct udphdr *)(skb->data + l4_offset);
			hash ^= ((__force __u16)udph->source << 16) |
				(__force __u16)udph->dest;
		}
		break;
	default:
		break;
	}
	*hash_out = hash;
	return true;
}

static bool trustix_datapath_rx_worker_hash_inner_ipv4(
	struct sk_buff *skb, unsigned int head_len, __u32 *hash_out)
{
	const struct ethhdr *eth;
	unsigned int offset;

	offset = skb_network_offset(skb);
	if (trustix_datapath_rx_worker_hash_ipv4_at_offset(
		    skb, offset, head_len, hash_out))
		return true;
	if (head_len >= ETH_HLEN + sizeof(struct iphdr)) {
		eth = (const struct ethhdr *)skb->data;
		if (eth->h_proto == htons(ETH_P_IP) &&
		    trustix_datapath_rx_worker_hash_ipv4_at_offset(
			    skb, ETH_HLEN, head_len, hash_out))
			return true;
	}
	return trustix_datapath_rx_worker_hash_ipv4_at_offset(
		skb, 0, head_len, hash_out);
}

static void
trustix_datapath_rx_worker_set_hash_tx_queue(struct sk_buff *skb,
					     const struct net_device *dev)
{
	unsigned int txq_count;
	unsigned int head_len;
	__u32 hash;
	__u16 queue;

	if (!READ_ONCE(trustix_datapath_rx_worker_xmit_hash_tx_queue))
		return;
	if (!skb || !dev)
		goto fallback;
	txq_count = READ_ONCE(dev->real_num_tx_queues);
	if (txq_count <= 1)
		return;
	head_len = skb_headlen(skb);
	if (!trustix_datapath_rx_worker_hash_inner_ipv4(skb, head_len,
							&hash))
		goto fallback;
	queue = (__u16)(trustix_datapath_rx_worker_mix_hash(hash) %
			txq_count);
	skb_set_queue_mapping(skb, queue);
	trustix_datapath_rx_worker_count_hash_tx_queue(queue);
	return;

fallback:
	trustix_datapath_rx_worker_xmit_hash_tx_queue_fallbacks++;
}

static bool trustix_datapath_tx_plaintext_hash_outer_inner_ipv4(
	struct sk_buff *skb, __u32 *hash_out)
{
	const struct iphdr *outer_iph;
	const struct udphdr *outer_udph;
	const struct tcphdr *outer_tcph;
	unsigned int head_len;
	unsigned int network_offset;
	unsigned int outer_ip_header_len;
	unsigned int outer_l4_offset;
	unsigned int tixt_offset;
	unsigned int tixt_len;
	__u32 outer_total_len;
	__u16 outer_transport_len;

	if (!skb || !hash_out)
		return false;
	head_len = skb_headlen(skb);
	network_offset = skb_network_offset(skb);
	if (network_offset > head_len ||
	    head_len - network_offset < sizeof(*outer_iph))
		return false;
	outer_iph = (const struct iphdr *)(skb->data + network_offset);
	if (outer_iph->version != 4 || outer_iph->ihl < 5)
		return false;
	outer_ip_header_len = outer_iph->ihl * 4;
	if (outer_ip_header_len < sizeof(*outer_iph) ||
	    network_offset + outer_ip_header_len > head_len)
		return false;
	outer_total_len = ntohs(outer_iph->tot_len);
	if (outer_total_len < outer_ip_header_len ||
	    outer_total_len > skb->len - network_offset)
		return false;
	outer_l4_offset = network_offset + outer_ip_header_len;
	switch (outer_iph->protocol) {
	case IPPROTO_UDP:
		if (outer_l4_offset > head_len ||
		    head_len - outer_l4_offset < sizeof(*outer_udph))
			return false;
		outer_udph = (const struct udphdr *)(skb->data +
						     outer_l4_offset);
		outer_transport_len = ntohs(outer_udph->len);
		if (outer_transport_len < sizeof(*outer_udph) ||
		    outer_transport_len > outer_total_len - outer_ip_header_len)
			return false;
		tixt_offset = outer_l4_offset + sizeof(*outer_udph);
		tixt_len = outer_transport_len - sizeof(*outer_udph);
		break;
	case IPPROTO_TCP:
		if (outer_l4_offset > head_len ||
		    head_len - outer_l4_offset < sizeof(*outer_tcph))
			return false;
		outer_tcph = (const struct tcphdr *)(skb->data +
						     outer_l4_offset);
		if (outer_tcph->doff < 5)
			return false;
		outer_transport_len = outer_tcph->doff * 4;
		if (outer_transport_len < sizeof(*outer_tcph) ||
		    outer_transport_len > outer_total_len - outer_ip_header_len)
			return false;
		tixt_offset = outer_l4_offset + outer_transport_len;
		tixt_len = outer_total_len - outer_ip_header_len -
			   outer_transport_len;
		break;
	default:
		return false;
	}
	if (tixt_len < TRUSTIX_DATAPATH_TIXT_HEADER_LEN ||
	    tixt_offset > head_len ||
	    head_len - tixt_offset <
		    TRUSTIX_DATAPATH_TIXT_HEADER_LEN + sizeof(struct iphdr))
		return false;
	if (!trustix_datapath_frame_magic_supported(skb->data + tixt_offset))
		return false;
	if (trustix_datapath_get_be16(skb->data + tixt_offset + 6) !=
	    TRUSTIX_DATAPATH_TIXT_HEADER_LEN)
		return false;
	if (!(skb->data[tixt_offset + 5] & TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4))
		return false;
	return trustix_datapath_rx_worker_hash_ipv4_at_offset(
		skb, tixt_offset + TRUSTIX_DATAPATH_TIXT_HEADER_LEN,
		head_len, hash_out);
}

static __always_inline __u32
trustix_datapath_tx_plaintext_hash_outer_tuple(
	const struct trustix_datapath_tx_plan *plan)
{
	__u32 hash;

	if (!plan)
		return 0;
	hash = plan->local_ipv4 ^
	       (plan->remote_ipv4 << 7) ^
	       (plan->remote_ipv4 >> 9) ^
	       ((__u32)plan->local_port << 16) ^
	       (__u32)plan->remote_port ^
	       ((__u32)plan->outer_protocol << 24);
	return hash ?: 1;
}

static bool
trustix_datapath_tx_plaintext_cpu_for_queue(__u16 queue,
					    unsigned int *cpu_out)
{
	unsigned int online_cpus;
	unsigned int cpu;

	if (!cpu_out)
		return false;
	online_cpus = num_online_cpus();
	if (!online_cpus)
		return false;
	cpu = cpumask_nth(queue % online_cpus, cpu_online_mask);
	if (cpu >= nr_cpu_ids)
		return false;
	*cpu_out = cpu;
	return true;
}

static __always_inline void
trustix_datapath_tx_plaintext_set_xps_sender_cpu(struct sk_buff *skb,
						 __u16 queue)
{
#ifdef CONFIG_XPS
	unsigned int cpu;

	if (!skb ||
	    !trustix_datapath_tx_plaintext_cpu_for_queue(queue, &cpu)) {
		trustix_datapath_tx_plaintext_xps_sender_cpu_fallbacks++;
		return;
	}
	/* sender_cpu is encoded as cpu + 1; zero means unset. */
	skb->sender_cpu = cpu + 1;
	trustix_datapath_tx_plaintext_xps_sender_cpu_sets++;
#else
	(void)skb;
	(void)queue;
#endif
}

static void
trustix_datapath_tx_plaintext_set_hash_tx_queue(struct sk_buff *skb,
						const struct net_device *dev,
						const struct trustix_datapath_tx_plan *plan)
{
	bool partition_transport;
	bool hash_tx_queue;
	bool tix_tcp_port_sharding;
	unsigned int txq_count;
	__u8 outer_protocol;
	__u32 hash;
	__u32 mixed;
	__u16 queue;

	if (!skb || !dev)
		goto fallback;
	outer_protocol = plan ? plan->outer_protocol : 0;
	hash_tx_queue = READ_ONCE(
		trustix_datapath_tx_plaintext_hash_tx_queue);
	if (!hash_tx_queue) {
		skb_set_queue_mapping(skb, 0);
		return;
	}
	txq_count = READ_ONCE(dev->real_num_tx_queues);
	if (txq_count <= 1)
		return;
	/* One outer TCP tuple must stay on one TX queue to preserve sequence order. */
	tix_tcp_port_sharding =
		trustix_datapath_tx_plan_tix_tcp_port_sharding_active(plan);
	if (tix_tcp_port_sharding) {
		hash = trustix_datapath_tx_plaintext_hash_outer_tuple(plan);
		trustix_datapath_tx_plaintext_outer_tuple_hash_sets++;
	} else {
		hash = plan ? plan->inner_flow_hash : 0;
		if (hash)
			trustix_datapath_tx_plaintext_inner_flow_hash_sets++;
	}
	if (!hash &&
	    !trustix_datapath_tx_plaintext_hash_outer_inner_ipv4(skb, &hash)) {
		if (plan) {
			hash = trustix_datapath_tx_plaintext_hash_outer_tuple(plan) ^
			       (__u32)plan->flow_id ^
			       ((__u32)(plan->flow_id >> 32) << 3);
		} else {
			goto fallback;
		}
	}
	mixed = trustix_datapath_rx_worker_mix_hash(hash);
	skb_set_hash(skb, mixed, PKT_HASH_TYPE_L4);
	partition_transport = READ_ONCE(
		trustix_datapath_tx_plaintext_hash_tx_queue_partition_transport);
	if (tix_tcp_port_sharding) {
		queue = trustix_datapath_tx_plaintext_tix_tcp_shard_tx_queue(
			plan->outer_tcp_port_shard, txq_count,
			partition_transport);
		this_cpu_inc(
			trustix_datapath_tx_plaintext_tix_tcp_shard_tx_queue_sets);
	} else {
		queue = trustix_datapath_tx_plaintext_hash_tx_queue_for_transport(
			hash, txq_count, outer_protocol, partition_transport);
	}
	skb_set_queue_mapping(skb, queue);
	trustix_datapath_tx_plaintext_set_xps_sender_cpu(skb, queue);
	trustix_datapath_tx_plaintext_count_hash_tx_queue(queue);
	if (partition_transport) {
		switch (outer_protocol) {
		case IPPROTO_UDP:
			trustix_datapath_tx_plaintext_hash_tx_queue_partition_udp_sets++;
			break;
		case IPPROTO_TCP:
			trustix_datapath_tx_plaintext_hash_tx_queue_partition_tcp_sets++;
			break;
		default:
			trustix_datapath_tx_plaintext_hash_tx_queue_partition_fallbacks++;
			break;
		}
	}
	return;

fallback:
	trustix_datapath_tx_plaintext_hash_tx_queue_fallbacks++;
}

static __always_inline void
trustix_datapath_rx_worker_apply_xmit_more(struct sk_buff *skb, bool more)
{
	/*
	 * Modern kernels pass xmit_more as a netdev_start_xmit() argument
	 * derived from skb lists/qdisc batching; sk_buff no longer exposes a
	 * per-packet xmit_more field. Keep the module parameter as a no-op
	 * diagnostic until this path grows a real skb-list TX batch.
	 */
	(void)skb;
	(void)more;
}

static bool trustix_datapath_rx_worker_dev_is_veth(const struct net_device *dev)
{
	if (!dev || !dev->rtnl_link_ops || !dev->rtnl_link_ops->kind)
		return false;
	return strcmp(dev->rtnl_link_ops->kind, "veth") == 0;
}

static struct net_device *
trustix_datapath_rx_worker_get_peer_dev(struct net_device *dev)
{
	struct net_device *peer_dev = NULL;
	const struct net_device_ops *ops;

	if (!dev)
		return NULL;
	rcu_read_lock();
	ops = READ_ONCE(dev->netdev_ops);
	if (ops && ops->ndo_get_peer_dev) {
		peer_dev = ops->ndo_get_peer_dev(dev);
		if (peer_dev && peer_dev != dev)
			dev_hold(peer_dev);
		else
			peer_dev = NULL;
	}
	rcu_read_unlock();
	return peer_dev;
}

static int trustix_datapath_rx_worker_deliver_veth_peer_skb(
	struct sk_buff *skb, struct net_device *dev)
{
	struct net_device *peer_dev;
	struct net *net;
	int iflink;
	int ret;

	if (!skb || !dev)
		return -EINVAL;
	if (!trustix_datapath_rx_worker_dev_is_veth(dev))
		return -EOPNOTSUPP;
	peer_dev = trustix_datapath_rx_worker_get_peer_dev(dev);
	if (!peer_dev) {
		iflink = dev_get_iflink(dev);
		if (iflink <= 0 || iflink == dev->ifindex)
			return -EOPNOTSUPP;
		net = dev_net(dev);
		peer_dev = dev_get_by_index(net, iflink);
		if (!peer_dev || peer_dev == dev) {
			if (peer_dev)
				dev_put(peer_dev);
			return -EOPNOTSUPP;
		}
	}
	if (!trustix_datapath_rx_worker_dev_ready(peer_dev)) {
		dev_put(peer_dev);
		return -ENETDOWN;
	}
	skb->pkt_type = PACKET_HOST;
	ret = dev_forward_skb(peer_dev, skb);
	dev_put(peer_dev);
	if (ret == NET_RX_SUCCESS) {
		trustix_datapath_rx_worker_xmit_peer_forward_packets++;
		trustix_datapath_rx_worker_record_xmit_ret(NET_XMIT_SUCCESS);
		return 0;
	}
	trustix_datapath_rx_worker_xmit_peer_forward_errors++;
	trustix_datapath_rx_worker_record_xmit_ret(ret);
	return -ENOBUFS;
}

static int trustix_datapath_rx_worker_deliver_xmit_skb(struct sk_buff *skb,
						       struct net_device *dev,
						       bool xmit_more)
{
	bool force_dev_forward;
	bool veth_peer_forward;
	int ret;

	trustix_datapath_rx_worker_prepare_self_generated_xmit(skb, dev);
	trustix_datapath_rx_worker_set_hash_tx_queue(skb, dev);
	trustix_datapath_rx_worker_apply_xmit_more(skb, xmit_more);
	force_dev_forward =
		READ_ONCE(trustix_datapath_rx_worker_xmit_dev_forward);
	veth_peer_forward =
		READ_ONCE(trustix_datapath_rx_worker_xmit_veth_peer_forward);
	if (force_dev_forward ||
	    (veth_peer_forward &&
	     trustix_datapath_rx_worker_dev_is_veth(dev))) {
		ret = trustix_datapath_rx_worker_deliver_veth_peer_skb(skb,
								       dev);
		if (!ret) {
			trustix_datapath_rx_worker_xmit_dev_forward_packets++;
			return 0;
		}
		if (ret == -EOPNOTSUPP) {
			trustix_datapath_rx_worker_xmit_peer_forward_unsupported++;
			goto queue_xmit;
		}
		trustix_datapath_rx_worker_xmit_dev_forward_errors++;
		if (ret == -ENETDOWN)
			kfree_skb(skb);
		return ret == -ENETDOWN ? ret : -ENOBUFS;
	}
queue_xmit:
	ret = dev_queue_xmit(skb);
	trustix_datapath_rx_worker_record_xmit_ret(ret);
	if (ret == NET_XMIT_SUCCESS || ret == NET_XMIT_CN)
		return 0;
	return -ENOBUFS;
}

static bool
trustix_datapath_rx_worker_tcpv4_partial_csum_dev_supported(
	const struct net_device *dev)
{
	netdev_features_t features;

	if (!dev)
		return false;
	features = READ_ONCE(dev->features);
	if (features & NETIF_F_HW_CSUM)
		return true;
#ifdef NETIF_F_IP_CSUM
	if (features & NETIF_F_IP_CSUM)
		return true;
#endif
	return false;
}

static bool
trustix_datapath_rx_worker_partial_csum_requires_software(
	const struct net_device *dev)
{
	const struct rtnl_link_ops *link_ops;

	if (!dev)
		return true;
	if (dev->priv_flags & IFF_EBRIDGE)
		return true;
	link_ops = READ_ONCE(dev->rtnl_link_ops);
	return link_ops && READ_ONCE(link_ops->kind);
}

static int
trustix_datapath_rx_worker_normalize_inner_tcp_partial_checksum(
	struct sk_buff *skb)
{
	struct tcphdr *tcph;
	struct iphdr *iph;
	__sum16 expected;
	__u32 ip_header_len;
	__u32 tcp_header_len;
	__u32 total_len;
	__u32 tcp_len;
	unsigned int network_offset;
	unsigned int csum_start;

	if (!skb || skb->ip_summed != CHECKSUM_PARTIAL)
		return 0;
	network_offset = skb_network_offset(skb);
	if (network_offset > skb->len ||
	    skb->len - network_offset < sizeof(*iph) + sizeof(*tcph))
		return -EINVAL;
	if (!pskb_may_pull(skb, network_offset + sizeof(*iph)) ||
	    skb_headlen(skb) < network_offset + sizeof(*iph))
		return -ENODATA;
	iph = (struct iphdr *)(skb->data + network_offset);
	if (iph->version != 4 || iph->ihl < 5 ||
	    iph->protocol != IPPROTO_TCP ||
	    (iph->frag_off & htons(0x3fff)))
		return -EPROTONOSUPPORT;
	ip_header_len = iph->ihl * 4;
	if (ip_header_len < sizeof(*iph) ||
	    skb->len - network_offset < ip_header_len + sizeof(*tcph) ||
	    !pskb_may_pull(skb, network_offset + ip_header_len +
					 sizeof(*tcph)) ||
	    skb_headlen(skb) < network_offset + ip_header_len +
				 sizeof(*tcph))
		return -ENODATA;
	iph = (struct iphdr *)(skb->data + network_offset);
	total_len = ntohs(iph->tot_len);
	if (total_len < ip_header_len + sizeof(*tcph) ||
	    total_len > skb->len - network_offset)
		return -EBADMSG;
	tcph = (struct tcphdr *)((__u8 *)iph + ip_header_len);
	tcp_header_len = tcph->doff * 4;
	if (tcp_header_len < sizeof(*tcph) ||
	    total_len < ip_header_len + tcp_header_len)
		return -EBADMSG;
	tcp_len = total_len - ip_header_len;
	expected = ~csum_tcpudp_magic(iph->saddr, iph->daddr, tcp_len,
				       IPPROTO_TCP, 0);
	if (tcph->check != expected)
		return -EBADMSG;
	csum_start = (unsigned char *)tcph - skb->head;
	if (csum_start > U16_MAX)
		return -EOVERFLOW;
	if (skb->csum_start == csum_start &&
	    skb->csum_offset == offsetof(struct tcphdr, check))
		return 0;
	skb_set_transport_header(skb, network_offset + ip_header_len);
	skb->csum_start = csum_start;
	skb->csum_offset = offsetof(struct tcphdr, check);
	trustix_datapath_rx_worker_partial_checksum_metadata_repairs++;
	return 0;
}

static bool
trustix_datapath_rx_worker_partial_csum_supported(struct sk_buff *skb,
						 struct net_device *dev)
{
	netdev_features_t features;

	if (!skb || skb->ip_summed != CHECKSUM_PARTIAL)
		return true;
	if (!dev)
		return false;
	/* Software links can advertise HW_CSUM while handing the skb to RX. */
	if (!skb_is_gso(skb) &&
	    trustix_datapath_rx_worker_partial_csum_requires_software(dev))
		return false;
	features = READ_ONCE(dev->features);
	if (features & NETIF_F_HW_CSUM)
		return true;
#ifdef NETIF_F_IP_CSUM
	if (skb->protocol == htons(ETH_P_IP) && (features & NETIF_F_IP_CSUM))
		return true;
#endif
#ifdef NETIF_F_IPV6_CSUM
	if (skb->protocol == htons(ETH_P_IPV6) &&
	    (features & NETIF_F_IPV6_CSUM))
		return true;
#endif
	return false;
}

static int
trustix_datapath_rx_worker_finish_partial_checksum(struct sk_buff *skb,
						  struct net_device *dev)
{
	int ret;

	if (!skb || skb->ip_summed != CHECKSUM_PARTIAL)
		return 0;
	ret = trustix_datapath_rx_worker_normalize_inner_tcp_partial_checksum(
		skb);
	if (ret) {
		trustix_datapath_rx_worker_checksum_errors++;
		return ret;
	}
	if (trustix_datapath_rx_worker_partial_csum_supported(skb, dev))
		return 0;
	trustix_datapath_rx_worker_partial_checksum_software_fallbacks++;
	ret = skb_checksum_help(skb);
	if (ret) {
		trustix_datapath_rx_worker_checksum_errors++;
		return ret;
	}
	trustix_datapath_rx_worker_count_checksum_fixed(1);
	return 0;
}

static __always_inline bool
trustix_datapath_rx_worker_tixt_inner_tcp_checksum_partial(__u8 flags)
{
	return flags &
	       TRUSTIX_DATAPATH_TIXT_FLAG_INNER_TCP_CHECKSUM_PARTIAL;
}

static int
trustix_datapath_rx_worker_restore_inner_tcp_checksum_partial(
	struct sk_buff *skb, __u8 tixt_flags)
{
	struct tcphdr *tcph;
	struct iphdr *iph;
	__sum16 expected;
	__u32 ip_header_len;
	__u32 tcp_header_len;
	__u32 total_len;
	__u32 tcp_len;

	if (!trustix_datapath_rx_worker_tixt_inner_tcp_checksum_partial(
		    tixt_flags))
		return 0;
	if (!skb ||
	    (tixt_flags & (TRUSTIX_DATAPATH_TIXT_FLAG_ENCRYPTED |
			   TRUSTIX_DATAPATH_TIXT_FLAG_CRYPTO_FRAGMENT)) ||
	    skb->len < sizeof(*iph) + sizeof(*tcph))
		return -EBADMSG;
	if (!pskb_may_pull(skb, sizeof(*iph)) ||
	    skb_headlen(skb) < sizeof(*iph))
		return -ENODATA;
	iph = (struct iphdr *)skb->data;
	if (iph->version != 4 || iph->ihl < 5 ||
	    iph->protocol != IPPROTO_TCP ||
	    (iph->frag_off & htons(0x3fff)))
		return -EBADMSG;
	ip_header_len = iph->ihl * 4;
	if (ip_header_len < sizeof(*iph) ||
	    skb->len < ip_header_len + sizeof(*tcph) ||
	    !pskb_may_pull(skb, ip_header_len + sizeof(*tcph)) ||
	    skb_headlen(skb) < ip_header_len + sizeof(*tcph))
		return -ENODATA;
	iph = (struct iphdr *)skb->data;
	total_len = ntohs(iph->tot_len);
	if (total_len != skb->len ||
	    total_len < ip_header_len + sizeof(*tcph))
		return -EBADMSG;
	tcph = (struct tcphdr *)(skb->data + ip_header_len);
	tcp_header_len = tcph->doff * 4;
	if (tcp_header_len < sizeof(*tcph) ||
	    total_len < ip_header_len + tcp_header_len)
		return -EBADMSG;
	tcp_len = total_len - ip_header_len;
	expected = ~csum_tcpudp_magic(iph->saddr, iph->daddr, tcp_len,
				       IPPROTO_TCP, 0);
	if (tcph->check != expected)
		return -EBADMSG;
	trustix_datapath_rx_worker_fix_ipv4_header_checksum(iph,
							   ip_header_len);
	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum_start = (unsigned char *)tcph - skb->head;
	skb->csum_offset = offsetof(struct tcphdr, check);
	return 0;
}

static bool
trustix_datapath_rx_worker_prepare_tcp_partial_checksum(struct sk_buff *skb)
{
	struct tcphdr *tcph;
	struct iphdr *iph;
	__u32 ip_header_len;
	__u32 tcp_header_len;
	__u32 total_len;
	__u32 tcp_len;

	if (!skb || !READ_ONCE(trustix_datapath_rx_worker_xmit_tcp_partial_csum) ||
	    skb->len < sizeof(*iph))
		return false;
	if (!pskb_may_pull(skb, sizeof(*iph)) ||
	    skb_headlen(skb) < sizeof(*iph))
		return false;
	iph = (struct iphdr *)skb->data;
	if (iph->version != 4 || iph->ihl < 5 ||
	    iph->protocol != IPPROTO_TCP ||
	    (iph->frag_off & htons(0x3fff)))
		return false;
	ip_header_len = iph->ihl * 4;
	if (ip_header_len < sizeof(*iph) ||
	    skb->len < ip_header_len + sizeof(*tcph))
		return false;
	if (!pskb_may_pull(skb, ip_header_len + sizeof(*tcph)) ||
	    skb_headlen(skb) < ip_header_len + sizeof(*tcph))
		return false;
	iph = (struct iphdr *)skb->data;
	total_len = ntohs(iph->tot_len);
	if (total_len < ip_header_len + sizeof(*tcph) || total_len > skb->len)
		return false;
	tcph = (struct tcphdr *)(skb->data + ip_header_len);
	tcp_header_len = tcph->doff * 4;
	if (tcp_header_len < sizeof(*tcph) ||
	    total_len < ip_header_len + tcp_header_len)
		return false;
	if (!pskb_may_pull(skb, ip_header_len + tcp_header_len) ||
	    skb_headlen(skb) < ip_header_len + tcp_header_len)
		return false;
	iph = (struct iphdr *)skb->data;
	tcph = (struct tcphdr *)(skb->data + ip_header_len);
	tcp_len = total_len - ip_header_len;
	tcph->check = ~csum_tcpudp_magic(iph->saddr, iph->daddr, tcp_len,
					 IPPROTO_TCP, 0);
	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum_start = (unsigned char *)tcph - skb->head;
	skb->csum_offset = offsetof(struct tcphdr, check);
	trustix_datapath_rx_worker_checksum_partial++;
	return true;
}

static int
trustix_datapath_rx_worker_fix_inner_checksums(struct sk_buff *skb)
{
	struct udphdr *udph;
	struct tcphdr *tcph;
	struct iphdr *iph;
	__u32 ip_header_len;
	__u32 total_len;
	__u32 l4_len;

	if (!skb || !READ_ONCE(trustix_datapath_rx_worker_xmit_fix_checksums))
		return 0;
	if (skb_is_gso(skb))
		return 0;
	if (skb->len < sizeof(*iph))
		return -EINVAL;
	iph = (struct iphdr *)skb->data;
	if (iph->version != 4 || iph->ihl < 5)
		return -EPROTONOSUPPORT;
	ip_header_len = iph->ihl * 4;
	if (ip_header_len < sizeof(*iph) || skb->len < ip_header_len)
		return -EINVAL;
	total_len = ntohs(iph->tot_len);
	if (total_len < ip_header_len || total_len > skb->len)
		return -EMSGSIZE;
	if (iph->frag_off & htons(0x3fff))
		return 0;
	trustix_datapath_rx_worker_fix_ipv4_header_checksum(iph,
							   ip_header_len);
	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		trustix_datapath_rx_worker_checksum_ipv4_only++;
		return 0;
	}
	l4_len = total_len - ip_header_len;
	switch (iph->protocol) {
	case IPPROTO_TCP:
		if (trustix_datapath_rx_worker_trust_tcp_checksum(
			    iph, ip_header_len, l4_len, &tcph)) {
			trustix_datapath_rx_worker_checksum_trusted++;
			trustix_datapath_rx_worker_checksum_ipv4_only++;
			return 0;
		}
		if (l4_len < sizeof(*tcph))
			return -EINVAL;
		tcph = (struct tcphdr *)((__u8 *)iph + ip_header_len);
		if (tcph->doff < 5 || l4_len < (__u32)tcph->doff * 4)
			return -EINVAL;
		tcph->check = 0;
		tcph->check = trustix_datapath_rx_worker_l4_checksum(
			iph, tcph, l4_len, IPPROTO_TCP);
		break;
	case IPPROTO_UDP:
		if (l4_len < sizeof(*udph))
			return -EINVAL;
		udph = (struct udphdr *)((__u8 *)iph + ip_header_len);
		if (ntohs(udph->len) < sizeof(*udph) ||
		    ntohs(udph->len) > l4_len)
			return -EINVAL;
		udph->check = 0;
		udph->check = trustix_datapath_rx_worker_l4_checksum(
			iph, udph, ntohs(udph->len), IPPROTO_UDP);
		if (!udph->check)
			udph->check = CSUM_MANGLED_0;
		break;
	default:
		break;
	}
	trustix_datapath_rx_worker_count_checksum_fixed(1);
	return 0;
}

static __always_inline __u64
trustix_datapath_rx_worker_mac_to_u64(const __u8 *addr)
{
	return ((__u64)addr[0] << 40) | ((__u64)addr[1] << 32) |
	       ((__u64)addr[2] << 24) | ((__u64)addr[3] << 16) |
	       ((__u64)addr[4] << 8) | (__u64)addr[5];
}

static __always_inline void
trustix_datapath_rx_worker_u64_to_mac(__u64 value, __u8 *addr)
{
	addr[0] = value >> 40;
	addr[1] = value >> 32;
	addr[2] = value >> 24;
	addr[3] = value >> 16;
	addr[4] = value >> 8;
	addr[5] = value;
}

static void
trustix_datapath_rx_worker_prepare_inner_skb(struct sk_buff *skb,
					     const struct net_device *dev,
					     bool xmit)
{
	struct skb_shared_info *shinfo;
	struct tcphdr *tcph;
	const struct iphdr *iph;
	__u32 gso_size;
	__u32 payload_len;
	__u32 tcp_header_len;
	__u32 tcp_len;
	__u32 total_len;
	__u32 ip_header_len;
	__u32 segs;
	bool partial_prepared = false;
	bool premarked_gso;

	if (!skb)
		return;
	premarked_gso = skb_is_gso(skb);
	skb->encapsulation = 0;
	skb->csum = 0;
	skb->csum_level = 0;
	shinfo = skb_shinfo(skb);
	if (!premarked_gso) {
		shinfo->gso_size = 0;
		shinfo->gso_segs = 0;
		shinfo->gso_type = 0;
	}
	if (xmit && !premarked_gso)
		skb->ip_summed = CHECKSUM_NONE;
	else if (!xmit)
		trustix_datapath_rx_worker_mark_inner_checksum(skb);
	if (premarked_gso)
		return;
	if (xmit &&
	    trustix_datapath_rx_worker_tcpv4_partial_csum_dev_supported(dev))
		partial_prepared =
			trustix_datapath_rx_worker_prepare_tcp_partial_checksum(skb);
	if (!dev || !dev->mtu || skb->len <= dev->mtu ||
	    skb->len < sizeof(*iph))
		return;
	iph = (const struct iphdr *)skb->data;
	if (iph->version != 4 || iph->ihl < 5 ||
	    iph->protocol != IPPROTO_TCP ||
	    (iph->frag_off & htons(0x3fff)))
		return;
	ip_header_len = iph->ihl * 4;
	if (ip_header_len < sizeof(*iph) ||
	    skb->len < ip_header_len + sizeof(*tcph))
		return;
	tcph = (struct tcphdr *)(skb->data + ip_header_len);
	tcp_header_len = tcph->doff * 4;
	total_len = ntohs(iph->tot_len);
	if (tcp_header_len < sizeof(*tcph) ||
	    total_len < ip_header_len + tcp_header_len ||
	    skb->len < total_len ||
	    dev->mtu <= ip_header_len + tcp_header_len)
		return;
	tcp_len = total_len - ip_header_len;
	payload_len = tcp_len - tcp_header_len;
	if (!payload_len)
		return;
	gso_size = dev->mtu - ip_header_len - tcp_header_len;
	if (!gso_size)
		return;
	segs = DIV_ROUND_UP(payload_len, gso_size);
	if (!segs || segs > U16_MAX)
		return;
	shinfo->gso_size = gso_size;
	shinfo->gso_type = SKB_GSO_TCPV4;
	shinfo->gso_segs = segs;
	if (xmit) {
		tcph->check = ~csum_tcpudp_magic(iph->saddr, iph->daddr,
						 tcp_len, IPPROTO_TCP, 0);
		skb->ip_summed = CHECKSUM_PARTIAL;
		skb->csum_start = (unsigned char *)tcph - skb->head;
		skb->csum_offset = offsetof(struct tcphdr, check);
		if (!partial_prepared)
			trustix_datapath_rx_worker_checksum_partial++;
	}
}

static bool
trustix_datapath_rx_worker_lookup_inner_dst_mac(struct sk_buff *skb,
						const struct net_device *dev,
						__u8 *addr)
{
	const struct iphdr *iph;
	struct neighbour *neigh;
	struct net_device *peer_dev;
	unsigned int offset;
	bool ok = false;

	if (!skb || !dev || !addr || dev->type != ARPHRD_ETHER)
		return false;
	offset = skb_network_offset(skb);
	if (offset > skb->len || skb->len - offset < sizeof(*iph))
		return false;
	iph = (const struct iphdr *)skb_network_header(skb);
	if (iph->version != 4 || iph->ihl < 5)
		return false;
	if (READ_ONCE(trustix_datapath_rx_worker_xmit_dst_mac_seq_cache)) {
		unsigned int seq;
		bool cached;

		do {
			seq = read_seqbegin(
				&trustix_datapath_rx_worker_seq_mac_cache_lock);
			cached = trustix_datapath_rx_worker_mac_cache_lookup(
				&trustix_datapath_rx_worker_seq_mac_cache,
				dev->ifindex, iph->daddr, addr);
		} while (read_seqretry(
			&trustix_datapath_rx_worker_seq_mac_cache_lock, seq));
		if (cached) {
			trustix_datapath_rx_worker_dst_mac_cache_hits++;
			return true;
		}
		trustix_datapath_rx_worker_dst_mac_cache_misses++;
	}
	if (READ_ONCE(trustix_datapath_rx_worker_xmit_dst_mac_cache)) {
		unsigned long flags;

		spin_lock_irqsave(&trustix_datapath_rx_worker_mac_cache_lock,
				  flags);
		if (trustix_datapath_rx_worker_mac_cache_lookup(
			    &trustix_datapath_rx_worker_mac_cache, dev->ifindex,
			    iph->daddr, addr)) {
			spin_unlock_irqrestore(
				&trustix_datapath_rx_worker_mac_cache_lock,
				flags);
			trustix_datapath_rx_worker_dst_mac_cache_hits++;
			return true;
		}
		spin_unlock_irqrestore(&trustix_datapath_rx_worker_mac_cache_lock,
				       flags);
		trustix_datapath_rx_worker_dst_mac_cache_misses++;
	}
	if (READ_ONCE(trustix_datapath_rx_worker_xmit_dst_mac_pcpu_cache)) {
		struct trustix_datapath_rx_worker_mac_cache *cache;

		cache = get_cpu_ptr(
			trustix_datapath_rx_worker_pcpu_mac_cache);
		if (trustix_datapath_rx_worker_mac_cache_lookup(
			    cache, dev->ifindex, iph->daddr, addr)) {
			put_cpu_ptr(cache);
			trustix_datapath_rx_worker_dst_mac_cache_hits++;
			return true;
		}
		put_cpu_ptr(cache);
		trustix_datapath_rx_worker_dst_mac_cache_misses++;
	}
	neigh = neigh_lookup(&arp_tbl, &iph->daddr, (struct net_device *)dev);
	if (neigh) {
		if ((READ_ONCE(neigh->nud_state) & NUD_VALID) &&
		    is_valid_ether_addr(neigh->ha)) {
			ether_addr_copy(addr, neigh->ha);
			ok = true;
		}
		neigh_release(neigh);
	}
	if (!ok && trustix_datapath_rx_worker_dev_is_veth(dev)) {
		peer_dev = trustix_datapath_rx_worker_get_peer_dev(
			(struct net_device *)dev);
		if (peer_dev) {
			if (is_valid_ether_addr(peer_dev->dev_addr)) {
				ether_addr_copy(addr, peer_dev->dev_addr);
				ok = true;
				trustix_datapath_rx_worker_dst_mac_veth_peer_hits++;
			}
			dev_put(peer_dev);
		}
	}
	if (ok && READ_ONCE(trustix_datapath_rx_worker_xmit_dst_mac_cache)) {
		unsigned long flags;

		spin_lock_irqsave(&trustix_datapath_rx_worker_mac_cache_lock,
				  flags);
		trustix_datapath_rx_worker_mac_cache_store(
			&trustix_datapath_rx_worker_mac_cache, dev->ifindex,
			iph->daddr, addr);
		spin_unlock_irqrestore(&trustix_datapath_rx_worker_mac_cache_lock,
				       flags);
	}
	if (ok && READ_ONCE(trustix_datapath_rx_worker_xmit_dst_mac_pcpu_cache)) {
		struct trustix_datapath_rx_worker_mac_cache *cache;

		cache = get_cpu_ptr(
			trustix_datapath_rx_worker_pcpu_mac_cache);
		trustix_datapath_rx_worker_mac_cache_store(
			cache, dev->ifindex, iph->daddr, addr);
		put_cpu_ptr(cache);
	}
	if (ok && READ_ONCE(trustix_datapath_rx_worker_xmit_dst_mac_seq_cache)) {
		unsigned long flags;

		write_seqlock_irqsave(
			&trustix_datapath_rx_worker_seq_mac_cache_lock, flags);
		trustix_datapath_rx_worker_mac_cache_store(
			&trustix_datapath_rx_worker_seq_mac_cache,
			dev->ifindex, iph->daddr, addr);
		write_sequnlock_irqrestore(
			&trustix_datapath_rx_worker_seq_mac_cache_lock, flags);
	}
	return ok;
}

static void trustix_datapath_rx_worker_fill_inner_eth(struct sk_buff *skb,
						      struct net_device *dev,
						      bool xmit)
{
	struct ethhdr *eth;

	eth = eth_hdr(skb);
	if (xmit) {
		if (is_valid_ether_addr(dev->dev_addr))
			ether_addr_copy(eth->h_source, dev->dev_addr);
		else
			eth_zero_addr(eth->h_source);
		if (trustix_datapath_rx_worker_lookup_inner_dst_mac(
			    skb, dev, eth->h_dest)) {
			trustix_datapath_rx_worker_count_dst_mac_hits(1);
		} else {
			eth_broadcast_addr(eth->h_dest);
			trustix_datapath_rx_worker_dst_mac_broadcast++;
		}
	} else {
		eth_zero_addr(eth->h_source);
		if (is_valid_ether_addr(dev->dev_addr))
			ether_addr_copy(eth->h_dest, dev->dev_addr);
		else
			eth_zero_addr(eth->h_dest);
	}
	eth->h_proto = htons(ETH_P_IP);
}

static int
trustix_datapath_rx_worker_deliver_inner_skb_more(struct sk_buff *skb,
						  struct net_device *dev,
						  bool inline_context,
						  bool xmit_more)
{
	int ret;

	if (READ_ONCE(trustix_datapath_rx_worker_xmit)) {
		if (!trustix_datapath_rx_worker_dev_ready(dev)) {
			kfree_skb(skb);
			trustix_datapath_rx_worker_deliver_errors++;
			WRITE_ONCE(trustix_datapath_rx_worker_last_deliver_ret,
				   -ENETDOWN);
			return -ENETDOWN;
		}
		skb->dev = dev;
		skb->protocol = htons(ETH_P_IP);
		skb->pkt_type = PACKET_OUTGOING;
		if (skb_is_gso(skb))
			return trustix_datapath_rx_worker_xmit_inner_gso(
				skb, dev, xmit_more);
		ret = trustix_datapath_rx_worker_finish_partial_checksum(skb,
									dev);
		if (ret) {
			kfree_skb(skb);
			trustix_datapath_rx_worker_deliver_errors++;
			WRITE_ONCE(trustix_datapath_rx_worker_last_deliver_ret,
				   ret);
			return ret;
		}
		if (READ_ONCE(trustix_datapath_rx_worker_direct_xmit))
			trustix_datapath_rx_worker_direct_xmit_safe_fallbacks++;
		ret = trustix_datapath_rx_worker_deliver_xmit_skb(skb, dev,
								  xmit_more);
		if (!ret) {
			trustix_datapath_rx_worker_count_xmit_packets(1);
			WRITE_ONCE(trustix_datapath_rx_worker_last_deliver_ret,
				   0);
			return 0;
		}
		trustix_datapath_rx_worker_deliver_errors++;
		WRITE_ONCE(trustix_datapath_rx_worker_last_deliver_ret,
			   -ENOBUFS);
		return -ENOBUFS;
	}
	if (!trustix_datapath_rx_worker_dev_ready(dev)) {
		kfree_skb(skb);
		trustix_datapath_rx_worker_deliver_errors++;
		WRITE_ONCE(trustix_datapath_rx_worker_last_deliver_ret,
			   -ENETDOWN);
		return -ENETDOWN;
	}
	ret = trustix_datapath_rx_worker_finish_partial_checksum(skb, NULL);
	if (ret) {
		kfree_skb(skb);
		trustix_datapath_rx_worker_deliver_errors++;
		WRITE_ONCE(trustix_datapath_rx_worker_last_deliver_ret, ret);
		return ret;
	}
	skb->dev = dev;
	skb->protocol = eth_type_trans(skb, dev);
	skb->pkt_type = PACKET_HOST;
	trustix_datapath_rx_worker_mark_self_generated(skb);
	if (inline_context &&
	    READ_ONCE(trustix_datapath_rx_worker_inline_receive))
		trustix_datapath_rx_worker_inline_receive_safe_fallbacks++;
	ret = netif_rx(skb);
	if (ret == NET_RX_SUCCESS) {
		trustix_datapath_rx_worker_count_receive_packets(1);
		WRITE_ONCE(trustix_datapath_rx_worker_last_deliver_ret, 0);
		return 0;
	}
	trustix_datapath_rx_worker_deliver_errors++;
	WRITE_ONCE(trustix_datapath_rx_worker_last_deliver_ret, -ENOBUFS);
	return -ENOBUFS;
}

static int trustix_datapath_rx_worker_deliver_inner_skb(struct sk_buff *skb,
							struct net_device *dev,
							bool inline_context)
{
	return trustix_datapath_rx_worker_deliver_inner_skb_more(
		skb, dev, inline_context, false);
}

static int trustix_datapath_rx_worker_sanitize_inner_gso_skb(
	struct sk_buff *skb, struct net_device *dev)
{
	struct skb_shared_info *shinfo;
	struct tcphdr *tcph;
	struct iphdr *iph;
	__u32 ip_header_len;
	__u32 tcp_header_len;
	__u32 total_len;
	__u32 tcp_len;
	__u32 payload_len;
	__u32 gso_size;
	__u32 gso_segs;

	if (!skb || !dev || !skb_is_gso(skb))
		return -EINVAL;
	if (skb->len < ETH_HLEN + sizeof(*iph))
		return -EINVAL;
	if (!pskb_may_pull(skb, ETH_HLEN + sizeof(*iph)) ||
	    skb_headlen(skb) < ETH_HLEN + sizeof(*iph))
		return -ENODATA;

	skb->dev = dev;
	skb->protocol = htons(ETH_P_IP);
	skb->pkt_type = PACKET_OUTGOING;
	skb->encapsulation = 0;
	skb->csum = 0;
	skb->csum_level = 0;
	skb_reset_mac_header(skb);
	skb_set_network_header(skb, ETH_HLEN);
	iph = (struct iphdr *)skb_network_header(skb);
	if (iph->version != 4 || iph->ihl < 5 ||
	    iph->protocol != IPPROTO_TCP ||
	    (iph->frag_off & htons(0x3fff)))
		return -EPROTONOSUPPORT;
	ip_header_len = iph->ihl * 4;
	if (ip_header_len < sizeof(*iph) ||
	    skb->len < ETH_HLEN + ip_header_len + sizeof(*tcph))
		return -EINVAL;
	if (!pskb_may_pull(skb, ETH_HLEN + ip_header_len + sizeof(*tcph)) ||
	    skb_headlen(skb) < ETH_HLEN + ip_header_len + sizeof(*tcph))
		return -ENODATA;
	iph = (struct iphdr *)skb_network_header(skb);
	tcph = (struct tcphdr *)((__u8 *)iph + ip_header_len);
	tcp_header_len = tcph->doff * 4;
	total_len = ntohs(iph->tot_len);
	if (tcp_header_len < sizeof(*tcph) ||
	    total_len < ip_header_len + tcp_header_len ||
	    total_len > skb->len - ETH_HLEN ||
	    skb->len < ETH_HLEN + total_len)
		return -EINVAL;
	if (!pskb_may_pull(skb, ETH_HLEN + ip_header_len + tcp_header_len) ||
	    skb_headlen(skb) <
		    ETH_HLEN + ip_header_len + tcp_header_len)
		return -ENODATA;
	iph = (struct iphdr *)skb_network_header(skb);
	tcph = (struct tcphdr *)((__u8 *)iph + ip_header_len);
	tcp_len = total_len - ip_header_len;
	payload_len = tcp_len - tcp_header_len;
	if (!payload_len)
		return -EINVAL;

	shinfo = skb_shinfo(skb);
	gso_size = shinfo->gso_size;
	if (!gso_size || gso_size > payload_len)
		return -EINVAL;
	gso_segs = DIV_ROUND_UP(payload_len, gso_size);
	if (gso_segs < 2 || gso_segs > U16_MAX)
		return -EINVAL;

	iph->tot_len = htons((__u16)total_len);
	trustix_datapath_rx_worker_fix_ipv4_header_checksum(iph,
							   ip_header_len);
	skb_set_transport_header(skb, ETH_HLEN + ip_header_len);
	tcph = tcp_hdr(skb);
	tcph->check = ~csum_tcpudp_magic(iph->saddr, iph->daddr, tcp_len,
					 IPPROTO_TCP, 0);
	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum_start = skb_transport_header(skb) - skb->head;
	skb->csum_offset = offsetof(struct tcphdr, check);
	shinfo->gso_size = gso_size;
	shinfo->gso_segs = gso_segs;
	shinfo->gso_type = SKB_GSO_TCPV4;
	skb->mac_len = ETH_HLEN;
	skb_reset_inner_headers(skb);
	WRITE_ONCE(trustix_datapath_rx_worker_stream_coalesce_last_len,
		   total_len);
	WRITE_ONCE(trustix_datapath_rx_worker_stream_coalesce_last_gso_size,
		   shinfo->gso_size);
	WRITE_ONCE(trustix_datapath_rx_worker_stream_coalesce_last_gso_segs,
		   shinfo->gso_segs);
	WRITE_ONCE(trustix_datapath_rx_worker_stream_coalesce_last_gso_type,
		   shinfo->gso_type);
	return 0;
}

static bool
trustix_datapath_rx_worker_inner_gso_xmit_supported(struct sk_buff *skb,
						    struct net_device *dev)
{
	struct skb_shared_info *shinfo;

	if (!skb || !dev || !skb_is_gso(skb))
		return false;
	if (!trustix_datapath_dev_supports_tcpv4_gso(dev))
		return false;
	shinfo = skb_shinfo(skb);
	if (!shinfo->gso_size || shinfo->gso_segs < 2)
		return false;
	if ((shinfo->gso_type & SKB_GSO_TCPV4) != SKB_GSO_TCPV4)
		return false;
	return true;
}

static int
trustix_datapath_rx_worker_xmit_inner_gso_direct(struct sk_buff *skb,
						 struct net_device *dev,
						 bool xmit_more)
{
	struct skb_shared_info *shinfo;
	unsigned int gso_segs;
	int ret;

	if (!skb || !dev || !skb_is_gso(skb))
		return -EINVAL;
	ret = trustix_datapath_rx_worker_sanitize_inner_gso_skb(skb, dev);
	if (ret) {
		trustix_datapath_rx_worker_gso_xmit_errors++;
		WRITE_ONCE(trustix_datapath_rx_worker_last_deliver_ret, ret);
		kfree_skb(skb);
		return ret;
	}
	ret = trustix_datapath_rx_worker_finish_partial_checksum(skb, dev);
	if (ret) {
		trustix_datapath_rx_worker_gso_xmit_errors++;
		WRITE_ONCE(trustix_datapath_rx_worker_last_deliver_ret, ret);
		kfree_skb(skb);
		return ret;
	}
	shinfo = skb_shinfo(skb);
	gso_segs = shinfo->gso_segs ?: DIV_ROUND_UP(
		ntohs(ip_hdr(skb)->tot_len) - ip_hdr(skb)->ihl * 4 -
			tcp_hdr(skb)->doff * 4,
		shinfo->gso_size);
	ret = trustix_datapath_rx_worker_deliver_xmit_skb(skb, dev,
							  xmit_more);
	if (!ret) {
		trustix_datapath_rx_worker_count_xmit_packets(gso_segs);
		trustix_datapath_rx_worker_gso_xmit_packets++;
		trustix_datapath_rx_worker_gso_xmit_segments += gso_segs;
		WRITE_ONCE(trustix_datapath_rx_worker_last_deliver_ret, 0);
		return 0;
	}
	trustix_datapath_rx_worker_deliver_errors++;
	trustix_datapath_rx_worker_gso_xmit_errors++;
	WRITE_ONCE(trustix_datapath_rx_worker_last_deliver_ret,
		   ret ? ret : -ENOBUFS);
	return ret ? ret : -ENOBUFS;
}

static int trustix_datapath_rx_worker_xmit_inner_gso(
	struct sk_buff *skb, struct net_device *dev, bool xmit_more)
{
	if (!READ_ONCE(trustix_datapath_rx_worker_stream_coalesce_software_segment) &&
	    trustix_datapath_rx_worker_inner_gso_xmit_supported(skb, dev))
		return trustix_datapath_rx_worker_xmit_inner_gso_direct(
			skb, dev, xmit_more);
	trustix_datapath_rx_worker_gso_xmit_fallbacks++;
	return trustix_datapath_rx_worker_xmit_inner_gso_segments(skb, dev);
}

static int trustix_datapath_rx_worker_xmit_inner_gso_segments(
	struct sk_buff *skb, struct net_device *dev)
{
	struct skb_shared_info *shinfo;
	struct tcphdr *tcph;
	struct iphdr *iph;
	__u32 ip_header_len;
	__u32 tcp_header_len;
	__u32 total_len;
	__u32 tcp_len;
	__u32 payload_len;
	__u32 gso_size;
	__u32 payload_offset = 0;
	__u32 seq;
	__u32 expected_segs;
	unsigned int delivered = 0;
	unsigned int errors = 0;
	unsigned int seg_index = 0;
	int first_error = 0;
	int ret;

	if (!skb || !dev || !skb_is_gso(skb))
		return -EINVAL;
	if (!trustix_datapath_rx_worker_dev_ready(dev)) {
		kfree_skb(skb);
		trustix_datapath_rx_worker_stream_coalesce_segment_errors++;
		WRITE_ONCE(
			trustix_datapath_rx_worker_stream_coalesce_last_segment_ret,
			-ENETDOWN);
		WRITE_ONCE(trustix_datapath_rx_worker_last_deliver_ret,
			   -ENETDOWN);
		return -ENETDOWN;
	}
	ret = trustix_datapath_rx_worker_sanitize_inner_gso_skb(skb, dev);
	if (ret) {
		trustix_datapath_rx_worker_stream_coalesce_segment_errors++;
		WRITE_ONCE(
			trustix_datapath_rx_worker_stream_coalesce_last_segment_ret,
			ret);
		WRITE_ONCE(trustix_datapath_rx_worker_last_deliver_ret, ret);
		kfree_skb(skb);
		return ret;
	}

	iph = (struct iphdr *)skb_network_header(skb);
	tcph = (struct tcphdr *)skb_transport_header(skb);
	ip_header_len = iph->ihl * 4;
	tcp_header_len = tcph->doff * 4;
	total_len = ntohs(iph->tot_len);
	tcp_len = total_len - ip_header_len;
	payload_len = tcp_len - tcp_header_len;
	shinfo = skb_shinfo(skb);
	gso_size = shinfo->gso_size;
	seq = ntohl(tcph->seq);

	if (!gso_size || !payload_len) {
		ret = -EINVAL;
		trustix_datapath_rx_worker_stream_coalesce_segment_errors++;
		WRITE_ONCE(
			trustix_datapath_rx_worker_stream_coalesce_last_segment_ret,
			ret);
		WRITE_ONCE(trustix_datapath_rx_worker_last_deliver_ret, ret);
		kfree_skb(skb);
		return ret;
	}
	expected_segs = DIV_ROUND_UP(payload_len, gso_size);
	if (expected_segs < 2 ||
	    expected_segs > TRUSTIX_DATAPATH_RX_WORKER_STREAM_MAX_FRAMES ||
	    (shinfo->gso_segs && shinfo->gso_segs != expected_segs)) {
		ret = -EINVAL;
		trustix_datapath_rx_worker_stream_coalesce_segment_errors++;
		WRITE_ONCE(
			trustix_datapath_rx_worker_stream_coalesce_last_segment_ret,
			ret);
		WRITE_ONCE(trustix_datapath_rx_worker_last_deliver_ret, ret);
		kfree_skb(skb);
		return ret;
	}

	while (payload_offset < payload_len) {
		struct sk_buff *seg;
		struct tcphdr *seg_tcph;
		struct iphdr *seg_iph;
		__u32 seg_payload_len;
		__u32 seg_inner_len;
		__u32 alloc_len;
		__u8 *data;

		seg_payload_len = min_t(__u32, payload_len - payload_offset,
					gso_size);
		if (check_add_overflow(ip_header_len + tcp_header_len,
				       seg_payload_len, &seg_inner_len) ||
		    check_add_overflow((__u32)ETH_HLEN, seg_inner_len,
				       &alloc_len)) {
			errors++;
			if (!first_error)
				first_error = -EOVERFLOW;
			break;
		}
		seg = netdev_alloc_skb_ip_align(dev, alloc_len);
		if (!seg) {
			trustix_datapath_rx_worker_alloc_errors++;
			errors++;
			if (!first_error)
				first_error = -ENOMEM;
			break;
		}
		data = skb_put(seg, alloc_len);
		memcpy(data + ETH_HLEN, iph, ip_header_len + tcp_header_len);
		ret = skb_copy_bits(skb,
				    ETH_HLEN + ip_header_len +
					    tcp_header_len + payload_offset,
				    data + ETH_HLEN + ip_header_len +
					    tcp_header_len,
				    seg_payload_len);
		if (ret) {
			kfree_skb(seg);
			errors++;
			if (!first_error)
				first_error = ret;
			break;
		}

		seg_iph = (struct iphdr *)(data + ETH_HLEN);
		seg_tcph = (struct tcphdr *)(data + ETH_HLEN +
					     ip_header_len);
		seg_iph->tot_len = htons((__u16)seg_inner_len);
		seg_iph->id = htons(ntohs(iph->id) + seg_index);
		trustix_datapath_rx_worker_fix_ipv4_header_checksum(
			seg_iph, ip_header_len);
		seg_tcph->seq = htonl(seq + payload_offset);
		if (seg_tcph->psh &&
		    payload_offset + seg_payload_len < payload_len)
			seg_tcph->psh = 0;
		seg_tcph->check = 0;
		seg_tcph->check = trustix_datapath_rx_worker_l4_checksum(
			seg_iph, seg_tcph, tcp_header_len + seg_payload_len,
			IPPROTO_TCP);

		seg->dev = dev;
		seg->protocol = htons(ETH_P_IP);
		seg->pkt_type = PACKET_OUTGOING;
		seg->encapsulation = 0;
		seg->csum = 0;
		seg->csum_level = 0;
		seg->ip_summed = CHECKSUM_UNNECESSARY;
		seg->csum_start = 0;
		seg->csum_offset = 0;
		skb_reset_mac_header(seg);
		skb_set_network_header(seg, ETH_HLEN);
		skb_set_transport_header(seg, ETH_HLEN + ip_header_len);
		seg->mac_len = ETH_HLEN;
		skb_reset_inner_headers(seg);
		memset(seg->cb, 0, sizeof(seg->cb));
		trustix_datapath_rx_worker_fill_inner_eth(seg, dev, true);
		if (!trustix_datapath_rx_worker_dev_ready(dev)) {
			kfree_skb(seg);
			errors++;
			if (!first_error)
				first_error = -ENETDOWN;
			payload_offset += seg_payload_len;
			seg_index++;
			continue;
		}
		ret = trustix_datapath_rx_worker_deliver_xmit_skb(
			seg, dev, payload_offset + seg_payload_len < payload_len);
		if (!ret) {
			delivered++;
			payload_offset += seg_payload_len;
			seg_index++;
			continue;
		}
		errors++;
		if (!first_error)
			first_error = ret ? ret : -ENOBUFS;
		payload_offset += seg_payload_len;
		seg_index++;
	}
	kfree_skb(skb);
	if (delivered) {
		trustix_datapath_rx_worker_count_xmit_packets(delivered);
		trustix_datapath_rx_worker_stream_coalesce_segment_batches++;
		trustix_datapath_rx_worker_stream_coalesce_segment_skbs +=
			delivered;
	}
	if (errors) {
		trustix_datapath_rx_worker_deliver_errors += errors;
		trustix_datapath_rx_worker_stream_coalesce_segment_errors +=
			errors;
		WRITE_ONCE(trustix_datapath_rx_worker_last_deliver_ret,
			   first_error ? first_error : -ENOBUFS);
		return first_error ? first_error : -ENOBUFS;
	}
	WRITE_ONCE(trustix_datapath_rx_worker_last_deliver_ret, 0);
	WRITE_ONCE(trustix_datapath_rx_worker_stream_coalesce_last_segment_ret,
		   0);
	return delivered ? 0 : -EIO;
}

static int trustix_datapath_rx_worker_xmit_coalesced_inner_skb(
	struct sk_buff *skb, struct net_device *target_dev, bool inline_context,
	unsigned int frames, bool *queued_out)
{
	int ret;

	if (queued_out)
		*queued_out = false;
	if (!skb)
		return -EINVAL;
	if (!target_dev) {
		kfree_skb(skb);
		return -EINVAL;
	}
	if (!frames)
		frames = 1;
	if (inline_context) {
		trustix_datapath_rx_worker_stream_coalesce_inline_queue_fallbacks++;
		kfree_skb(skb);
		return -EOPNOTSUPP;
	}
	trustix_datapath_rx_worker_prepare_inner_skb(skb, target_dev, true);
	ret = trustix_datapath_rx_worker_fix_inner_checksums(skb);
	if (ret) {
		kfree_skb(skb);
		trustix_datapath_rx_worker_checksum_errors++;
		return ret;
	}
	if (skb->len < sizeof(struct iphdr)) {
		kfree_skb(skb);
		return -EINVAL;
	}
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, (skb->data[0] & 0x0f) * 4);
	if (skb_cow_head(skb, ETH_HLEN)) {
		kfree_skb(skb);
		return -ENOMEM;
	}
	skb_push(skb, ETH_HLEN);
	skb_reset_mac_header(skb);
	skb_set_network_header(skb, ETH_HLEN);
	skb_set_transport_header(skb,
				 ETH_HLEN + (skb->data[ETH_HLEN] & 0x0f) * 4);
	skb->mac_len = ETH_HLEN;
	skb_reset_inner_headers(skb);
	trustix_datapath_rx_worker_fill_inner_eth(skb, target_dev, true);
	if (skb_is_gso(skb))
		return trustix_datapath_rx_worker_xmit_inner_gso(
			skb, target_dev, false);
	return trustix_datapath_rx_worker_deliver_inner_skb(
		skb, target_dev, inline_context);
}

static unsigned int
trustix_datapath_rx_worker_inline_pair_flush_jiffies_value(void)
{
	unsigned int value = READ_ONCE(
		trustix_datapath_rx_worker_inline_pair_flush_jiffies);

	if (value > HZ)
		return HZ;
	return value;
}

static unsigned int
trustix_datapath_rx_worker_inline_coalesce_max_frames_value(void)
{
	unsigned int value = READ_ONCE(
		trustix_datapath_rx_worker_inline_coalesce_max_frames);

	if (value < 2)
		return 2;
	if (value > TRUSTIX_DATAPATH_RX_WORKER_INLINE_PAIR_MAX_FRAMES)
		return TRUSTIX_DATAPATH_RX_WORKER_INLINE_PAIR_MAX_FRAMES;
	return value;
}

static __u32 trustix_datapath_rx_worker_inline_pair_hash(
	const struct trustix_datapath_rx_worker_coalesce_state *state,
	int target_ifindex)
{
	__u32 hash;

	if (!state)
		return 0;
	hash = (__force __u32)state->saddr ^
	       ((__force __u32)state->daddr << 7) ^
	       ((__force __u32)state->daddr >> 9) ^
	       ((__force __u16)state->source << 16) ^
	       (__force __u16)state->dest ^ (__u32)target_ifindex;
	hash ^= hash >> 16;
	hash *= 0x7feb352dU;
	hash ^= hash >> 15;
	return hash ?: 1;
}

static void
trustix_datapath_rx_worker_inline_pair_detach_locked(
	struct trustix_datapath_rx_worker_inline_pair_slot *slot,
	bool block_reuse,
	struct net_device **target_dev, struct sk_buff **skb,
	__u8 **packets, __u32 *lens, unsigned int *frames,
	struct trustix_datapath_rx_worker_coalesce_state *state)
{
	unsigned int i;

	if (target_dev)
		*target_dev = NULL;
	if (skb)
		*skb = NULL;
	if (frames)
		*frames = 0;
	if (packets) {
		for (i = 0; i < TRUSTIX_DATAPATH_RX_WORKER_INLINE_PAIR_MAX_FRAMES;
		     i++)
			packets[i] = NULL;
	}
	if (lens)
		memset(lens, 0, sizeof(__u32) *
				  TRUSTIX_DATAPATH_RX_WORKER_INLINE_PAIR_MAX_FRAMES);
	if (state)
		memset(state, 0, sizeof(*state));
	if (!slot || !slot->valid)
		return;
	slot->flush_reuse_blocked = block_reuse;
	if (target_dev)
		*target_dev = slot->target_dev;
	else if (slot->target_dev)
		dev_put(slot->target_dev);
	if (skb)
		*skb = slot->skb;
	else
		kfree_skb(slot->skb);
	if (frames)
		*frames = slot->frames;
	for (i = 0; i < TRUSTIX_DATAPATH_RX_WORKER_INLINE_PAIR_MAX_FRAMES;
	     i++) {
		if (packets)
			packets[i] = slot->packets[i];
		else
			kfree(slot->packets[i]);
		if (lens)
			lens[i] = slot->lens[i];
		slot->packets[i] = NULL;
		slot->lens[i] = 0;
	}
	if (state)
		*state = slot->state;
	slot->valid = false;
	slot->target_dev = NULL;
	slot->target_ifindex = 0;
	slot->hash = 0;
	slot->skb = NULL;
	slot->frames = 0;
	memset(&slot->state, 0, sizeof(slot->state));
}

static void
trustix_datapath_rx_worker_inline_pair_allow_reuse(
	struct trustix_datapath_rx_worker_inline_pair_slot *slot)
{
	unsigned long flags;

	if (!slot)
		return;
	spin_lock_irqsave(&slot->lock, flags);
	slot->flush_reuse_blocked = false;
	spin_unlock_irqrestore(&slot->lock, flags);
}

static void
trustix_datapath_rx_worker_inline_pair_cancel_detached_flush(
	struct trustix_datapath_rx_worker_inline_pair_slot *slot)
{
	if (!slot)
		return;
	if (cancel_delayed_work(&slot->flush_work))
		trustix_datapath_rx_worker_inline_pair_allow_reuse(slot);
}

static int trustix_datapath_rx_worker_inline_pair_xmit_single(
	struct net_device *target_dev, __u8 *packet, __u32 len,
	bool inline_context)
{
	struct sk_buff *inner_skb = NULL;
	int ret;

	if (!target_dev || !packet || !len)
		return -EINVAL;
	ret = trustix_datapath_rx_worker_build_xmit_inner_skb(
		target_dev, packet, len, &inner_skb);
	if (ret) {
		trustix_datapath_rx_worker_inline_pair_errors++;
		return ret;
	}
	if (inline_context) {
		ret = trustix_datapath_rx_worker_queue_l2_skb_from_hook(
			NULL, target_dev, &inner_skb, inner_skb->len, 1, NULL);
		if (!ret) {
			trustix_datapath_rx_worker_count_pair_flushes(1);
			return 0;
		}
		kfree_skb(inner_skb);
		trustix_datapath_rx_worker_dropped++;
		trustix_datapath_rx_worker_inline_xmit_errors++;
		trustix_datapath_rx_worker_inline_pair_errors++;
		return ret;
	}
	ret = trustix_datapath_rx_worker_deliver_inner_skb(
		inner_skb, target_dev, inline_context);
	if (!ret) {
		trustix_datapath_rx_worker_count_injected(1);
		trustix_datapath_rx_worker_count_inline_xmit(1);
		trustix_datapath_rx_worker_count_pair_flushes(1);
		return 0;
	}
	trustix_datapath_rx_worker_dropped++;
	trustix_datapath_rx_worker_inline_xmit_errors++;
	trustix_datapath_rx_worker_inline_pair_errors++;
	return ret;
}

static int trustix_datapath_rx_worker_prepare_l2_gso_skb(
	struct sk_buff *skb, struct net_device *target_dev)
{
	struct iphdr *iph;
	__u32 ip_header_len;

	if (!skb || !target_dev || !skb_is_gso(skb))
		return -EINVAL;
	if (skb->len < sizeof(*iph))
		return -EINVAL;
	if (!pskb_may_pull(skb, sizeof(*iph)) ||
	    skb_headlen(skb) < sizeof(*iph))
		return -ENODATA;
	iph = (struct iphdr *)skb->data;
	if (iph->version != 4 || iph->ihl < 5)
		return -EPROTONOSUPPORT;
	ip_header_len = iph->ihl * 4;
	if (ip_header_len < sizeof(*iph) ||
	    skb->len < ip_header_len + sizeof(struct tcphdr))
		return -EINVAL;
	if (!pskb_may_pull(skb, ip_header_len + sizeof(struct tcphdr)) ||
	    skb_headlen(skb) < ip_header_len + sizeof(struct tcphdr))
		return -ENODATA;
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, ip_header_len);
	if (skb_cow_head(skb, ETH_HLEN))
		return -ENOMEM;
	skb_push(skb, ETH_HLEN);
	skb_reset_mac_header(skb);
	skb_set_network_header(skb, ETH_HLEN);
	skb_set_transport_header(skb, ETH_HLEN + ip_header_len);
	skb->mac_len = ETH_HLEN;
	skb_reset_inner_headers(skb);
	trustix_datapath_rx_worker_fill_inner_eth(skb, target_dev, true);
	return 0;
}

static int trustix_datapath_rx_worker_inline_pair_xmit_packets_gso(
	struct net_device *target_dev, __u8 **packets, __u32 *lens,
	unsigned int frames,
	const struct trustix_datapath_rx_worker_coalesce_state *state,
	const __u8 *extra_packet, __u32 extra_len, bool inline_context)
{
	struct trustix_datapath_rx_worker_pending_copy
		*pending = NULL;
	struct sk_buff *skb = NULL;
	unsigned int total_frames = frames;
	unsigned int i;
	int ret;

	if (!target_dev || !packets || !lens || !state || !state->active)
		return -EINVAL;
	if (extra_packet && extra_len)
		total_frames++;
	if (total_frames < 2 ||
	    total_frames > TRUSTIX_DATAPATH_RX_WORKER_INLINE_PAIR_MAX_FRAMES)
		return -EINVAL;
	pending = kcalloc(total_frames, sizeof(*pending), GFP_ATOMIC);
	if (!pending) {
		trustix_datapath_rx_worker_alloc_errors++;
		return -ENOMEM;
	}
	for (i = 0; i < frames; i++) {
		if (!packets[i] || !lens[i]) {
			ret = -EINVAL;
			goto out_free_pending;
		}
		pending[i].source_packet = packets[i];
		pending[i].len = lens[i];
	}
	if (extra_packet && extra_len) {
		pending[frames].source_packet = extra_packet;
		pending[frames].len = extra_len;
	}
	skb = trustix_datapath_rx_worker_build_coalesced_gso_skb(
		target_dev, state, pending, total_frames, true);
	if (!skb) {
		ret = -EOPNOTSUPP;
		goto out_free_pending;
	}
	ret = trustix_datapath_rx_worker_prepare_l2_gso_skb(skb, target_dev);
	if (ret) {
		kfree_skb(skb);
		goto out_free_pending;
	}
	if (inline_context) {
		ret = trustix_datapath_rx_worker_queue_l2_skb_from_hook(
			NULL, target_dev, &skb, skb->len, total_frames, NULL);
		if (!ret) {
			trustix_datapath_rx_worker_count_pair_flushes(
				total_frames);
			trustix_datapath_rx_worker_count_pair_packets(
				total_frames);
			kfree(pending);
			return 0;
		}
		kfree_skb(skb);
		trustix_datapath_rx_worker_dropped += total_frames;
		trustix_datapath_rx_worker_inline_xmit_errors += total_frames;
		trustix_datapath_rx_worker_inline_pair_errors++;
		goto out_free_pending;
	}
	ret = trustix_datapath_rx_worker_xmit_inner_gso(skb, target_dev, false);
	if (!ret) {
		trustix_datapath_rx_worker_count_injected(total_frames);
		trustix_datapath_rx_worker_count_inline_xmit(total_frames);
		trustix_datapath_rx_worker_count_pair_flushes(total_frames);
		trustix_datapath_rx_worker_count_pair_packets(total_frames);
		trustix_datapath_rx_worker_count_stream_coalesce(
			1, total_frames);
		kfree(pending);
		return 0;
	}
	trustix_datapath_rx_worker_dropped += total_frames;
	trustix_datapath_rx_worker_inline_xmit_errors += total_frames;
	trustix_datapath_rx_worker_inline_pair_errors++;
out_free_pending:
	kfree(pending);
	return ret;
}

static void
trustix_datapath_rx_worker_inline_pair_flush_slot(
	struct trustix_datapath_rx_worker_inline_pair_slot *slot,
	bool inline_context)
{
	struct net_device *target_dev = NULL;
	unsigned long flags;
	__u8 *packets[TRUSTIX_DATAPATH_RX_WORKER_INLINE_PAIR_MAX_FRAMES];
	__u32 lens[TRUSTIX_DATAPATH_RX_WORKER_INLINE_PAIR_MAX_FRAMES];
	struct sk_buff *held_skb = NULL;
	struct trustix_datapath_rx_worker_coalesce_state state = {};
	unsigned int frames = 0;
	unsigned int i;

	if (!slot)
		return;
	spin_lock_irqsave(&slot->lock, flags);
	if (!slot->valid) {
		slot->flush_reuse_blocked = false;
		spin_unlock_irqrestore(&slot->lock, flags);
		return;
	}
	trustix_datapath_rx_worker_inline_pair_detach_locked(
		slot, false, &target_dev, &held_skb, packets, lens, &frames,
		&state);
	spin_unlock_irqrestore(&slot->lock, flags);
	if (!frames)
		return;
	if (held_skb) {
		if (target_dev)
			trustix_datapath_rx_worker_inline_pair_xmit_skb_frames(
				target_dev, held_skb, inline_context, frames);
		else
			kfree_skb(held_skb);
		held_skb = NULL;
	}
	if (!held_skb && target_dev && frames > 1 &&
	    !trustix_datapath_rx_worker_inline_pair_xmit_packets_gso(
		    target_dev, packets, lens, frames, &state, NULL, 0,
		    inline_context)) {
		for (i = 0; i < frames &&
			    i < TRUSTIX_DATAPATH_RX_WORKER_INLINE_PAIR_MAX_FRAMES;
		     i++) {
			kfree(packets[i]);
			packets[i] = NULL;
		}
		dev_put(target_dev);
		return;
	}
	for (i = 0; i < frames &&
		    i < TRUSTIX_DATAPATH_RX_WORKER_INLINE_PAIR_MAX_FRAMES;
	     i++) {
		if (!packets[i])
			continue;
		trustix_datapath_rx_worker_inline_pair_xmit_single(
			target_dev, packets[i], lens[i], inline_context);
		kfree(packets[i]);
	}
	if (target_dev)
		dev_put(target_dev);
}

static void trustix_datapath_rx_worker_inline_pair_flush_work(
	struct work_struct *work)
{
	struct delayed_work *dwork = to_delayed_work(work);
	struct trustix_datapath_rx_worker_inline_pair_slot *slot =
		container_of(dwork,
			     struct trustix_datapath_rx_worker_inline_pair_slot,
			     flush_work);

	trustix_datapath_rx_worker_inline_pair_flush_slot(slot, false);
}

static void trustix_datapath_rx_worker_inline_pair_drop_all(void)
{
	struct net_device *target_dev = NULL;
	unsigned long flags;
	__u8 *packets[TRUSTIX_DATAPATH_RX_WORKER_INLINE_PAIR_MAX_FRAMES];
	__u32 lens[TRUSTIX_DATAPATH_RX_WORKER_INLINE_PAIR_MAX_FRAMES];
	struct sk_buff *held_skb = NULL;
	unsigned int frames = 0;
	unsigned int i;
	unsigned int j;

	for (i = 0; i < TRUSTIX_DATAPATH_RX_WORKER_INLINE_PAIR_SLOTS; i++) {
		struct trustix_datapath_rx_worker_inline_pair_slot *slot =
			&trustix_datapath_rx_worker_inline_pair_slots[i];

		cancel_delayed_work_sync(&slot->flush_work);
		spin_lock_irqsave(&slot->lock, flags);
		trustix_datapath_rx_worker_inline_pair_detach_locked(
			slot, false, &target_dev, &held_skb, packets, lens,
			&frames, NULL);
		spin_unlock_irqrestore(&slot->lock, flags);
		kfree_skb(held_skb);
		held_skb = NULL;
		for (j = 0; j < frames &&
			    j < TRUSTIX_DATAPATH_RX_WORKER_INLINE_PAIR_MAX_FRAMES;
		     j++)
			kfree(packets[j]);
		if (target_dev)
			dev_put(target_dev);
		target_dev = NULL;
		frames = 0;
	}
}

static bool trustix_datapath_rx_worker_inline_pair_store(
	struct trustix_datapath_rx_worker_inline_pair_slot *slot,
	struct net_device *target_dev, int target_ifindex, __u32 hash,
	const struct trustix_datapath_rx_worker_coalesce_state *state,
	const __u8 *packet, __u32 len)
{
	struct sk_buff *hold_skb = NULL;
	unsigned long flags;
	__u8 *copy = NULL;
	unsigned int max_frames;
	__u32 extra_tailroom = 0;

	max_frames = trustix_datapath_rx_worker_inline_coalesce_max_frames_value();
	if (state && state->gso_size && max_frames > 1 &&
	    !check_mul_overflow((__u32)(max_frames - 1), state->gso_size,
				&extra_tailroom))
		trustix_datapath_rx_worker_build_xmit_inner_skb_hold(
			target_dev, packet, len, extra_tailroom, &hold_skb);
	if (!hold_skb) {
		copy = kmemdup(packet, len, GFP_ATOMIC);
		if (!copy) {
			trustix_datapath_rx_worker_alloc_errors++;
			trustix_datapath_rx_worker_inline_pair_errors++;
			return false;
		}
	}
	spin_lock_irqsave(&slot->lock, flags);
	if (slot->valid || slot->flush_reuse_blocked) {
		spin_unlock_irqrestore(&slot->lock, flags);
		kfree_skb(hold_skb);
		kfree(copy);
		trustix_datapath_rx_worker_inline_pair_misses++;
		return false;
	}
	dev_hold(target_dev);
	slot->valid = true;
	slot->target_dev = target_dev;
	slot->target_ifindex = target_ifindex;
	slot->hash = hash;
	slot->state = *state;
	slot->skb = hold_skb;
	slot->packets[0] = copy;
	slot->lens[0] = len;
	slot->frames = 1;
	spin_unlock_irqrestore(&slot->lock, flags);
	mod_delayed_work(system_wq, &slot->flush_work,
			 trustix_datapath_rx_worker_inline_pair_flush_jiffies_value());
	trustix_datapath_rx_worker_count_pair_stored(1);
	return true;
}

static bool trustix_datapath_rx_worker_inline_pair_coalesce_view(
	struct net_device *target_dev,
	const struct trustix_datapath_rx_stage_view *view,
	int target_ifindex)
{
	struct trustix_datapath_rx_worker_coalesce_state cur_state = {};
	struct trustix_datapath_rx_worker_coalesce_state merged = {};
	struct trustix_datapath_rx_worker_inline_pair_slot *slot;
	struct sk_buff *held_skb = NULL;
	struct net_device *held_dev = NULL;
	unsigned long flags;
	__u8 *held_packets[TRUSTIX_DATAPATH_RX_WORKER_INLINE_PAIR_MAX_FRAMES];
	__u32 held_lens[TRUSTIX_DATAPATH_RX_WORKER_INLINE_PAIR_MAX_FRAMES];
	struct trustix_datapath_rx_worker_coalesce_state held_state = {};
	unsigned int held_frames = 0;
	unsigned int max_frames;
	unsigned int frames;
	unsigned int i;
	__u32 hash;
	bool hit = false;
	bool appended = false;
	int ret;

	if (!READ_ONCE(trustix_datapath_rx_worker_inline_pair_coalesce))
		return false;
	if (!target_dev || !view || !view->inner_packet ||
	    view->inner.protocol != IPPROTO_TCP || !view->frame.payload_len)
		return false;
	if (trustix_datapath_rx_worker_tixt_inner_tcp_checksum_partial(
		    view->frame.flags))
		return false;
	ret = trustix_datapath_rx_worker_coalesce_accept(
		&cur_state, view->inner_packet, view->frame.payload_len);
	if (ret)
		return false;
	hash = trustix_datapath_rx_worker_inline_pair_hash(&cur_state,
							  target_ifindex);
	slot = &trustix_datapath_rx_worker_inline_pair_slots
			[hash & (TRUSTIX_DATAPATH_RX_WORKER_INLINE_PAIR_SLOTS - 1)];
	max_frames = trustix_datapath_rx_worker_inline_coalesce_max_frames_value();

	spin_lock_irqsave(&slot->lock, flags);
	if (slot->valid) {
		merged = slot->state;
		if (slot->target_dev == target_dev &&
		    slot->target_ifindex == target_ifindex &&
		    slot->hash == hash &&
		    !trustix_datapath_rx_worker_coalesce_accept(
			    &merged, view->inner_packet,
			    view->frame.payload_len)) {
			if (slot->frames + 1 >= max_frames) {
				hit = true;
				trustix_datapath_rx_worker_inline_pair_detach_locked(
					slot, true, &held_dev, &held_skb,
					held_packets, held_lens, &held_frames,
					&held_state);
			} else {
				__u8 *copy = NULL;

				if (slot->skb &&
				    !READ_ONCE(trustix_datapath_rx_worker_stream_coalesce_partial_csum)) {
					ret = trustix_datapath_rx_worker_inline_pair_append_held_skb(
						slot->skb, slot->target_dev, &merged,
						view->inner_packet,
						view->frame.payload_len);
					if (!ret) {
						slot->state = merged;
						slot->frames++;
						appended = true;
						trustix_datapath_rx_worker_count_pair_stored(1);
					} else {
						trustix_datapath_rx_worker_inline_pair_errors++;
						trustix_datapath_rx_worker_inline_pair_detach_locked(
							slot, true, &held_dev,
							&held_skb, held_packets,
							held_lens, &held_frames,
							&held_state);
					}
				} else {
					copy = kmemdup(view->inner_packet,
						       view->frame.payload_len,
						       GFP_ATOMIC);
					if (copy) {
						slot->state = merged;
						slot->packets[slot->frames] = copy;
						slot->lens[slot->frames] =
							view->frame.payload_len;
						slot->frames++;
						appended = true;
						trustix_datapath_rx_worker_count_pair_stored(1);
					} else {
						trustix_datapath_rx_worker_alloc_errors++;
						trustix_datapath_rx_worker_inline_pair_errors++;
						trustix_datapath_rx_worker_inline_pair_detach_locked(
							slot, true, &held_dev,
							&held_skb, held_packets,
							held_lens, &held_frames,
							&held_state);
					}
				}
			}
		} else {
			trustix_datapath_rx_worker_inline_pair_misses++;
			trustix_datapath_rx_worker_inline_pair_detach_locked(
				slot, true, &held_dev, &held_skb, held_packets,
				held_lens, &held_frames, &held_state);
		}
	}
	spin_unlock_irqrestore(&slot->lock, flags);

	if (appended) {
		mod_delayed_work(system_wq, &slot->flush_work,
				 trustix_datapath_rx_worker_inline_pair_flush_jiffies_value());
		return true;
	}

	if (hit) {
		trustix_datapath_rx_worker_inline_pair_cancel_detached_flush(
			slot);
		frames = held_frames + 1;
		if (held_skb) {
			if (held_frames && held_dev)
				ret = trustix_datapath_rx_worker_inline_pair_append_held_skb(
					held_skb, held_dev, &merged,
					view->inner_packet,
					view->frame.payload_len);
			else
				ret = -EINVAL;
			if (!ret) {
				ret = trustix_datapath_rx_worker_inline_pair_xmit_skb_frames(
					held_dev, held_skb, true, frames);
				held_skb = NULL;
				if (!ret) {
					WRITE_ONCE(
						trustix_datapath_rx_worker_last_push_ret,
						0);
				} else {
					trustix_datapath_rx_worker_dropped += frames;
					trustix_datapath_rx_worker_inline_xmit_errors +=
						frames;
					trustix_datapath_rx_worker_inline_pair_errors++;
					trustix_datapath_rx_worker_stream_coalesce_errors++;
				}
				if (held_dev)
					dev_put(held_dev);
				return true;
			}
			trustix_datapath_rx_worker_inline_pair_errors++;
			if (held_dev)
				trustix_datapath_rx_worker_inline_pair_xmit_skb_frames(
					held_dev, held_skb, true, held_frames);
			else
				kfree_skb(held_skb);
			held_skb = NULL;
			if (held_dev) {
				dev_put(held_dev);
				held_dev = NULL;
			}
			return trustix_datapath_rx_worker_inline_pair_store(
				slot, target_dev, target_ifindex, hash, &cur_state,
				view->inner_packet, view->frame.payload_len);
		}
	{
		unsigned int delivered = 0;
		unsigned int fallback_errors = 0;

		ret = trustix_datapath_rx_worker_inline_pair_xmit_packets_gso(
			held_dev ?: target_dev, held_packets, held_lens,
			held_frames, &merged, view->inner_packet,
			view->frame.payload_len, true);
		if (!ret) {
			for (i = 0; i < held_frames &&
				    i < TRUSTIX_DATAPATH_RX_WORKER_INLINE_PAIR_MAX_FRAMES;
			     i++) {
				kfree(held_packets[i]);
				held_packets[i] = NULL;
			}
			if (held_dev)
				dev_put(held_dev);
			WRITE_ONCE(trustix_datapath_rx_worker_last_push_ret, 0);
			return true;
		}
		trustix_datapath_rx_worker_stream_coalesce_inline_queue_fallbacks++;
		for (i = 0; i < held_frames &&
			    i < TRUSTIX_DATAPATH_RX_WORKER_INLINE_PAIR_MAX_FRAMES;
		     i++) {
			if (!held_packets[i])
				continue;
			ret = trustix_datapath_rx_worker_inline_pair_xmit_single(
				held_dev ?: target_dev, held_packets[i],
				held_lens[i], true);
			if (ret)
				fallback_errors++;
			else
				delivered++;
			kfree(held_packets[i]);
			held_packets[i] = NULL;
		}
		ret = trustix_datapath_rx_worker_inline_pair_xmit_single(
			target_dev, (__u8 *)view->inner_packet,
			view->frame.payload_len, true);
		if (ret)
			fallback_errors++;
		else
			delivered++;
		if (delivered)
			trustix_datapath_rx_worker_count_pair_packets(
				delivered);
		if (fallback_errors)
			trustix_datapath_rx_worker_stream_coalesce_errors++;
		if (held_dev)
			dev_put(held_dev);
		return true;
	}
	}

	if (held_frames) {
		trustix_datapath_rx_worker_inline_pair_cancel_detached_flush(
			slot);
		if (held_skb) {
			trustix_datapath_rx_worker_inline_pair_xmit_skb_frames(
				held_dev, held_skb, true, held_frames);
			held_skb = NULL;
		}
		if (!held_skb && held_dev && held_frames > 1 &&
		    !trustix_datapath_rx_worker_inline_pair_xmit_packets_gso(
			    held_dev, held_packets, held_lens, held_frames,
			    &held_state, NULL, 0, true)) {
			for (i = 0; i < held_frames &&
				    i < TRUSTIX_DATAPATH_RX_WORKER_INLINE_PAIR_MAX_FRAMES;
			     i++) {
				kfree(held_packets[i]);
				held_packets[i] = NULL;
			}
			dev_put(held_dev);
			return trustix_datapath_rx_worker_inline_pair_store(
				slot, target_dev, target_ifindex, hash, &cur_state,
				view->inner_packet, view->frame.payload_len);
		}
		for (i = 0; i < held_frames &&
			    i < TRUSTIX_DATAPATH_RX_WORKER_INLINE_PAIR_MAX_FRAMES;
		     i++) {
			if (!held_packets[i])
				continue;
			trustix_datapath_rx_worker_inline_pair_xmit_single(
				held_dev, held_packets[i], held_lens[i],
				true);
			kfree(held_packets[i]);
		}
		if (held_dev)
			dev_put(held_dev);
	}
	return trustix_datapath_rx_worker_inline_pair_store(
		slot, target_dev, target_ifindex, hash, &cur_state,
		view->inner_packet, view->frame.payload_len);
}

static bool trustix_datapath_rx_worker_room_available(unsigned int frames)
{
	unsigned long irqflags;
	bool available;

	if (!frames)
		frames = 1;
	spin_lock_irqsave(&trustix_datapath_rx_worker_lock, irqflags);
	available = trustix_datapath_rx_worker_ring &&
		    trustix_datapath_rx_worker_capacity &&
		    trustix_datapath_rx_worker_count <=
			    trustix_datapath_rx_worker_capacity &&
		    frames <= trustix_datapath_rx_worker_capacity -
				      trustix_datapath_rx_worker_count;
	spin_unlock_irqrestore(&trustix_datapath_rx_worker_lock, irqflags);
	return available;
}

static int
trustix_datapath_rx_worker_push_stolen_target(
	struct sk_buff *skb, const struct trustix_datapath_rx_stage_view *view,
	struct net_device *target_dev)
{
	struct trustix_datapath_rx_worker_slot *slot;
	unsigned long irqflags;

	if (!skb || !view || !view->inner_packet || !target_dev)
		return -EINVAL;
	if (!READ_ONCE(trustix_datapath_rx_worker_inject))
		goto err_not_supported;
	if (!view->frame.payload_len ||
	    view->frame.payload_len > TRUSTIX_DATAPATH_PACKET_MAX_LEN)
		goto err_msgsize;
	if (!trustix_datapath_rx_worker_can_steal_skb(skb, view))
		goto err_not_supported;
	if (!trustix_datapath_rx_worker_payload_fits_target(view,
							    target_dev))
		goto err_not_supported;
	if (!trustix_datapath_rx_worker_dev_ready(target_dev))
		goto err_not_ready;

	spin_lock_irqsave(&trustix_datapath_rx_worker_lock, irqflags);
	if (!trustix_datapath_rx_worker_ring ||
	    !trustix_datapath_rx_worker_capacity) {
		trustix_datapath_rx_worker_queue_full_fallbacks++;
		spin_unlock_irqrestore(&trustix_datapath_rx_worker_lock,
				       irqflags);
		dev_put(target_dev);
		return -ENOSPC;
	}
	if (trustix_datapath_rx_worker_count >=
	    trustix_datapath_rx_worker_capacity) {
		trustix_datapath_rx_worker_queue_full_fallbacks++;
		spin_unlock_irqrestore(&trustix_datapath_rx_worker_lock,
				       irqflags);
		dev_put(target_dev);
		return -ENOSPC;
	}
	slot = &trustix_datapath_rx_worker_ring
			[trustix_datapath_rx_worker_tail];
	trustix_datapath_rx_worker_release_slot(slot);
	slot->valid = true;
	slot->len = view->frame.payload_len;
	slot->inner_offset = view->inner_offset;
	slot->tixt_flags = view->frame.flags;
	slot->frames = 1;
	slot->ifindex = skb->dev ? skb->dev->ifindex : 0;
	slot->target_ifindex = target_dev->ifindex;
	slot->target_dev = target_dev;
	slot->skb = skb;
	slot->stolen_skb = true;
	trustix_datapath_rx_worker_tail =
		(trustix_datapath_rx_worker_tail + 1) %
		trustix_datapath_rx_worker_capacity;
	trustix_datapath_rx_worker_count++;
	trustix_datapath_rx_worker_queued++;
	trustix_datapath_rx_worker_stolen++;
	spin_unlock_irqrestore(&trustix_datapath_rx_worker_lock, irqflags);
	trustix_datapath_rx_worker_kick();
	return 0;

err_msgsize:
	dev_put(target_dev);
	return -EMSGSIZE;

err_not_ready:
	dev_put(target_dev);
	return -ENETDOWN;

err_not_supported:
	dev_put(target_dev);
	return -EOPNOTSUPP;
}

static int
trustix_datapath_rx_worker_push_copy(
	struct sk_buff *skb, const struct trustix_datapath_rx_stage_view *view,
	int target_ifindex)
{
	struct trustix_datapath_rx_worker_slot *slot;
	struct net_device *target_dev = NULL;
	struct sk_buff *inner_skb = NULL;
	__u8 *packet;
	unsigned long irqflags;
	int ret;

	if (!skb || !view || !view->inner_packet)
		return -EINVAL;
	if (!READ_ONCE(trustix_datapath_rx_worker_inject))
		return -EOPNOTSUPP;
	if (!view->frame.payload_len ||
	    view->frame.payload_len > TRUSTIX_DATAPATH_PACKET_MAX_LEN)
		return -EMSGSIZE;
	ret = trustix_datapath_rx_worker_target_dev(skb, &target_dev,
						    target_ifindex);
	if (ret)
		return ret;
	if (!trustix_datapath_rx_worker_payload_fits_target(view,
							    target_dev)) {
		dev_put(target_dev);
		return -EOPNOTSUPP;
	}
	if (!trustix_datapath_rx_worker_dev_ready(target_dev)) {
		dev_put(target_dev);
		return -ENETDOWN;
	}
	if (!trustix_datapath_rx_worker_room_available(1)) {
		trustix_datapath_rx_worker_queue_full_fallbacks++;
		dev_put(target_dev);
		return -ENOSPC;
	}
	if (READ_ONCE(trustix_datapath_rx_worker_queue_skb)) {
		inner_skb = trustix_datapath_rx_worker_build_inner_skb(
			target_dev, view->inner_packet, view->frame.payload_len);
		if (!inner_skb)
			trustix_datapath_rx_worker_queued_skb_fallbacks++;
	}
	if (!inner_skb)
		packet = kmemdup(view->inner_packet, view->frame.payload_len,
				 GFP_ATOMIC);
	else
		packet = NULL;
	if (!packet && !inner_skb) {
		trustix_datapath_rx_worker_alloc_errors++;
		dev_put(target_dev);
		return -ENOMEM;
	}
	spin_lock_irqsave(&trustix_datapath_rx_worker_lock, irqflags);
	if (!trustix_datapath_rx_worker_ring ||
	    !trustix_datapath_rx_worker_capacity) {
		trustix_datapath_rx_worker_queue_full_fallbacks++;
		spin_unlock_irqrestore(&trustix_datapath_rx_worker_lock,
				       irqflags);
		dev_put(target_dev);
		kfree(packet);
		kfree_skb(inner_skb);
		return -ENOSPC;
	}
	if (trustix_datapath_rx_worker_count >=
	    trustix_datapath_rx_worker_capacity) {
		trustix_datapath_rx_worker_queue_full_fallbacks++;
		spin_unlock_irqrestore(&trustix_datapath_rx_worker_lock,
				       irqflags);
		dev_put(target_dev);
		kfree(packet);
		kfree_skb(inner_skb);
		return -ENOSPC;
	}
	slot = &trustix_datapath_rx_worker_ring
			[trustix_datapath_rx_worker_tail];
	trustix_datapath_rx_worker_release_slot(slot);
	slot->valid = true;
	slot->len = view->frame.payload_len;
	slot->tixt_flags = view->frame.flags;
	slot->frames = 1;
	slot->ifindex = skb->dev ? skb->dev->ifindex : 0;
	slot->target_ifindex = target_dev->ifindex;
	slot->target_dev = target_dev;
	slot->packet = packet;
	slot->skb = inner_skb;
	if (inner_skb)
		trustix_datapath_rx_worker_queued_skb++;
	trustix_datapath_rx_worker_tail =
		(trustix_datapath_rx_worker_tail + 1) %
		trustix_datapath_rx_worker_capacity;
	trustix_datapath_rx_worker_count++;
	trustix_datapath_rx_worker_queued++;
	spin_unlock_irqrestore(&trustix_datapath_rx_worker_lock, irqflags);
	trustix_datapath_rx_worker_kick();
	return 0;
}

static int
trustix_datapath_rx_worker_push(struct sk_buff *skb,
				const struct trustix_datapath_rx_stage_view *view,
				bool *defer_stolen, int target_ifindex,
				struct net_device *target_dev_hint,
				struct net_device **defer_target_dev)
{
	struct net_device *target_dev = NULL;
	int ret;

	if (defer_stolen)
		*defer_stolen = false;
	if (defer_target_dev)
		*defer_target_dev = NULL;
	if (!skb || !view || !view->inner_packet) {
		WRITE_ONCE(trustix_datapath_rx_worker_last_push_ret,
			   -EINVAL);
		return -EINVAL;
	}
	if (!READ_ONCE(trustix_datapath_rx_worker_inject)) {
		WRITE_ONCE(trustix_datapath_rx_worker_last_push_ret,
			   -EOPNOTSUPP);
		return -EOPNOTSUPP;
	}
	ret = trustix_datapath_rx_worker_target_dev_hint(
		skb, &target_dev, target_ifindex, target_dev_hint);
	if (ret) {
		WRITE_ONCE(trustix_datapath_rx_worker_last_push_ret, ret);
		return ret;
	}
	if (!trustix_datapath_rx_worker_payload_fits_target(view,
							    target_dev)) {
		dev_put(target_dev);
		WRITE_ONCE(trustix_datapath_rx_worker_last_push_ret,
			   -EOPNOTSUPP);
		return -EOPNOTSUPP;
	}
	if (!trustix_datapath_rx_worker_dev_ready(target_dev)) {
		dev_put(target_dev);
		WRITE_ONCE(trustix_datapath_rx_worker_last_push_ret,
			   -ENETDOWN);
		return -ENETDOWN;
	}
	if (trustix_datapath_rx_worker_can_steal_skb(skb, view)) {
		if (!trustix_datapath_rx_worker_room_available(1)) {
			trustix_datapath_rx_worker_queue_full_fallbacks++;
			dev_put(target_dev);
			WRITE_ONCE(trustix_datapath_rx_worker_last_push_ret,
				   -ENOSPC);
			return -ENOSPC;
		}
		if (defer_stolen)
			*defer_stolen = true;
		if (defer_target_dev) {
			*defer_target_dev = target_dev;
			target_dev = NULL;
		}
		if (target_dev)
			dev_put(target_dev);
		WRITE_ONCE(trustix_datapath_rx_worker_last_push_ret, 0);
		return 0;
	}
	dev_put(target_dev);
	ret = trustix_datapath_rx_worker_push_copy(skb, view, target_ifindex);
	WRITE_ONCE(trustix_datapath_rx_worker_last_push_ret, ret);
	return ret;
}

static void trustix_datapath_rx_worker_free_pending_copies(
	struct trustix_datapath_rx_worker_pending_copy *pending,
	unsigned int frames)
{
	unsigned int i;

	if (!pending)
		return;
	for (i = 0; i < frames; i++) {
		kfree_skb(pending[i].skb);
		pending[i].skb = NULL;
		kfree(pending[i].packet);
		pending[i].packet = NULL;
		pending[i].source_packet = NULL;
		pending[i].source_skb = NULL;
		pending[i].source_offset = 0;
		pending[i].len = 0;
		pending[i].tixt_flags = 0;
	}
}

static struct sk_buff *
trustix_datapath_rx_worker_build_inner_skb_pending(
	struct net_device *target_dev,
	const struct trustix_datapath_rx_worker_pending_copy *pending)
{
	struct sk_buff *inner_skb;
	__u8 *dst;

	if (!target_dev || !pending || !pending->len ||
	    target_dev->type != ARPHRD_ETHER)
		return NULL;
	inner_skb = netdev_alloc_skb_ip_align(
		target_dev, ETH_HLEN + pending->len);
	if (!inner_skb)
		return NULL;
	skb_reserve(inner_skb, ETH_HLEN);
	dst = skb_put(inner_skb, pending->len);
	if (trustix_datapath_rx_worker_pending_copy_bits(
		    pending, 0, dst, pending->len)) {
		kfree_skb(inner_skb);
		return NULL;
	}
	return inner_skb;
}

static int trustix_datapath_rx_worker_materialize_pending_copies(
	struct net_device *target_dev,
	struct trustix_datapath_rx_worker_pending_copy *pending,
	unsigned int frames)
{
	unsigned int i;

	if (!target_dev || !pending || !frames)
		return -EINVAL;
	for (i = 0; i < frames; i++) {
		if ((pending[i].packet || pending[i].skb) && pending[i].len)
			continue;
		if ((!pending[i].source_packet && !pending[i].source_skb) ||
		    !pending[i].len)
			return -EINVAL;
		if (READ_ONCE(trustix_datapath_rx_worker_queue_skb)) {
			pending[i].skb =
				trustix_datapath_rx_worker_build_inner_skb_pending(
					target_dev, &pending[i]);
			if (!pending[i].skb) {
				trustix_datapath_rx_worker_queued_skb_fallbacks++;
			}
		}
		if (!pending[i].skb) {
			__u8 *packet = kmalloc(pending[i].len, GFP_ATOMIC);

			if (packet && trustix_datapath_rx_worker_pending_copy_bits(
					      &pending[i], 0, packet,
					      pending[i].len)) {
				kfree(packet);
				packet = NULL;
			}
			pending[i].packet = packet;
		}
		if (!pending[i].packet && !pending[i].skb) {
			trustix_datapath_rx_worker_alloc_errors++;
			return -ENOMEM;
		}
	}
	return 0;
}


static int trustix_datapath_rx_worker_enqueue_pending_copies(
	struct sk_buff *skb, struct net_device *target_dev,
	struct trustix_datapath_rx_worker_pending_copy *pending,
	unsigned int frames, unsigned int *queued_frames)
{
	struct trustix_datapath_rx_worker_slot *slot;
	unsigned long irqflags;
	unsigned int i;
	unsigned int queued = 0;
	int ret = 0;

	if (queued_frames)
		*queued_frames = 0;
	if (!skb || !target_dev || !pending || !frames)
		return -EINVAL;

	spin_lock_irqsave(&trustix_datapath_rx_worker_lock, irqflags);
	if (!trustix_datapath_rx_worker_ring ||
	    !trustix_datapath_rx_worker_capacity ||
	    trustix_datapath_rx_worker_count >
		    trustix_datapath_rx_worker_capacity ||
	    frames > trustix_datapath_rx_worker_capacity -
			     trustix_datapath_rx_worker_count) {
		trustix_datapath_rx_worker_queue_full_fallbacks += frames;
		spin_unlock_irqrestore(&trustix_datapath_rx_worker_lock,
				       irqflags);
		return -ENOSPC;
	}
	for (i = 0; i < frames; i++) {
		if ((!pending[i].packet && !pending[i].skb) ||
		    !pending[i].len) {
			ret = -EINVAL;
			break;
		}
		slot = &trustix_datapath_rx_worker_ring
				[trustix_datapath_rx_worker_tail];
		trustix_datapath_rx_worker_release_slot(slot);
		slot->valid = true;
		slot->len = pending[i].len;
		slot->tixt_flags = pending[i].tixt_flags;
		slot->frames = 1;
		slot->ifindex = skb->dev ? skb->dev->ifindex : 0;
		slot->target_ifindex = target_dev->ifindex;
		slot->target_dev = target_dev;
		dev_hold(target_dev);
		slot->packet = pending[i].packet;
		slot->skb = pending[i].skb;
		if (slot->skb)
			trustix_datapath_rx_worker_queued_skb++;
		pending[i].packet = NULL;
		pending[i].skb = NULL;
		pending[i].source_packet = NULL;
		pending[i].source_skb = NULL;
		pending[i].source_offset = 0;
		pending[i].len = 0;
		pending[i].tixt_flags = 0;
		trustix_datapath_rx_worker_tail =
			(trustix_datapath_rx_worker_tail + 1) %
			trustix_datapath_rx_worker_capacity;
		trustix_datapath_rx_worker_count++;
		trustix_datapath_rx_worker_queued++;
		queued++;
	}
	spin_unlock_irqrestore(&trustix_datapath_rx_worker_lock, irqflags);

	if (queued_frames)
		*queued_frames = queued;
	if (queued)
		trustix_datapath_rx_worker_kick();
	return ret;
}

static int trustix_datapath_rx_worker_enqueue_pending_skb(
	struct sk_buff *source_skb, struct net_device *target_dev,
	struct sk_buff *inner_skb, __u32 len, unsigned int frames,
	bool skb_l2_ready, unsigned int *queued_frames)
{
	struct trustix_datapath_rx_worker_slot *slot;
	unsigned long irqflags;
	int ret = 0;

	if (queued_frames)
		*queued_frames = 0;
	if (!target_dev || !inner_skb || !len || !frames)
		return -EINVAL;

	spin_lock_irqsave(&trustix_datapath_rx_worker_lock, irqflags);
	if (!trustix_datapath_rx_worker_ring ||
	    !trustix_datapath_rx_worker_capacity) {
		trustix_datapath_rx_worker_queue_full_fallbacks += frames;
		ret = -ENOSPC;
		goto out_unlock;
	}
	if (trustix_datapath_rx_worker_count >=
	    trustix_datapath_rx_worker_capacity) {
		trustix_datapath_rx_worker_queue_full_fallbacks += frames;
		ret = -ENOSPC;
		goto out_unlock;
	}
	slot = &trustix_datapath_rx_worker_ring
			[trustix_datapath_rx_worker_tail];
	trustix_datapath_rx_worker_release_slot(slot);
	slot->valid = true;
	slot->len = len;
	slot->frames = frames;
	slot->ifindex = source_skb && source_skb->dev ?
				source_skb->dev->ifindex : 0;
	slot->target_ifindex = target_dev->ifindex;
	slot->target_dev = target_dev;
	dev_hold(target_dev);
	slot->skb = inner_skb;
	slot->skb_l2_ready = skb_l2_ready;
	trustix_datapath_rx_worker_queued_skb++;
	trustix_datapath_rx_worker_tail =
		(trustix_datapath_rx_worker_tail + 1) %
		trustix_datapath_rx_worker_capacity;
	trustix_datapath_rx_worker_count++;
	trustix_datapath_rx_worker_queued++;
	if (queued_frames)
		*queued_frames = frames;

out_unlock:
	spin_unlock_irqrestore(&trustix_datapath_rx_worker_lock, irqflags);
	if (!ret)
		trustix_datapath_rx_worker_kick();
	return ret;
}

static int trustix_datapath_rx_worker_queue_l2_skb_from_hook(
	struct sk_buff *source_skb, struct net_device *target_dev,
	struct sk_buff **inner_skb, __u32 len, unsigned int frames,
	unsigned int *queued_frames)
{
	struct sk_buff *skb;
	unsigned int queued = 0;
	int ret;

	if (queued_frames)
		*queued_frames = 0;
	if (!inner_skb || !*inner_skb || !target_dev || !len)
		return -EINVAL;
	if (!frames)
		frames = 1;
	if (READ_ONCE(trustix_datapath_rx_worker_inline_xmit) &&
	    READ_ONCE(trustix_datapath_rx_worker_xmit) &&
	    ((frames == 1 && !skb_is_gso(*inner_skb)) ||
	     (READ_ONCE(trustix_datapath_rx_worker_direct_xmit) &&
	      skb_is_gso(*inner_skb)))) {
		skb = *inner_skb;
		*inner_skb = NULL;
		ret = trustix_datapath_rx_worker_deliver_inner_skb(
			skb, target_dev, true);
		if (!ret) {
			trustix_datapath_rx_worker_count_injected(frames);
			trustix_datapath_rx_worker_count_inline_xmit(frames);
			WRITE_ONCE(trustix_datapath_rx_worker_last_push_ret, 0);
			if (queued_frames)
				*queued_frames = frames;
			return 0;
		}
		trustix_datapath_rx_worker_dropped += frames;
		trustix_datapath_rx_worker_inline_xmit_errors += frames;
		WRITE_ONCE(trustix_datapath_rx_worker_last_push_ret, ret);
		return ret;
	}
	ret = trustix_datapath_rx_worker_enqueue_pending_skb(
		source_skb, target_dev, *inner_skb, len, frames, true, &queued);
	if (ret)
		return ret;
	*inner_skb = NULL;
	trustix_datapath_rx_worker_inline_xmit_hook_queue_fallbacks +=
		queued ?: frames;
	if (queued_frames)
		*queued_frames = queued;
	return 0;
}

static __always_inline bool
trustix_datapath_rx_worker_tixt_inner_l4_checksum_valid(__u8 flags)
{
	return (flags &
		TRUSTIX_DATAPATH_TIXT_FLAG_INNER_L4_CHECKSUM_VALID) &&
	       !(flags &
		 TRUSTIX_DATAPATH_TIXT_FLAG_INNER_TCP_CHECKSUM_PARTIAL);
}

static bool trustix_datapath_rx_worker_build_xmit_inner_skb_copy_csum(
	struct net_device *target_dev, const __u8 *packet, __u32 len,
	__u32 extra_tailroom, __u8 tixt_flags,
	struct sk_buff **inner_skb_out)
{
	const struct udphdr *src_udph;
	const struct tcphdr *src_tcph;
	const struct iphdr *src_iph;
	struct sk_buff *inner_skb;
	struct udphdr *udph;
	struct tcphdr *tcph;
	struct iphdr *iph;
	__wsum l4_sum;
	__u8 *dst;
	__u32 ip_header_len;
	__u32 l4_len;
	__u32 total_len;
	__u32 alloc_len;
	bool inner_tcp_checksum_partial =
		trustix_datapath_rx_worker_tixt_inner_tcp_checksum_partial(
			tixt_flags);
	bool trust_inner_l4_checksum =
		trustix_datapath_rx_worker_tixt_inner_l4_checksum_valid(
			tixt_flags);
	bool tcp_partial_csum = false;
	bool l4_checksum_rebuilt = true;

	if (inner_skb_out)
		*inner_skb_out = NULL;
	if (!READ_ONCE(trustix_datapath_rx_worker_inline_xmit_copy_csum) ||
	    !READ_ONCE(trustix_datapath_rx_worker_xmit_fix_checksums))
		return false;
	if (!target_dev || !packet || !len || !inner_skb_out ||
	    len < sizeof(*src_iph) || target_dev->type != ARPHRD_ETHER)
		return false;
	if (target_dev->mtu && len > target_dev->mtu)
		return false;
	src_iph = (const struct iphdr *)packet;
	if (src_iph->version != 4 || src_iph->ihl < 5 ||
	    (src_iph->frag_off & htons(0x3fff)))
		return false;
	ip_header_len = src_iph->ihl * 4;
	if (ip_header_len < sizeof(*src_iph) || len < ip_header_len)
		return false;
	total_len = ntohs(src_iph->tot_len);
	if (total_len < ip_header_len || total_len > len || total_len != len)
		return false;
	l4_len = total_len - ip_header_len;
	switch (src_iph->protocol) {
	case IPPROTO_TCP:
		if (l4_len < sizeof(*src_tcph))
			return false;
		src_tcph = (const struct tcphdr *)(packet + ip_header_len);
		if (src_tcph->doff < 5 || l4_len < (__u32)src_tcph->doff * 4)
			return false;
		break;
	case IPPROTO_UDP:
		if (l4_len < sizeof(*src_udph))
			return false;
		src_udph = (const struct udphdr *)(packet + ip_header_len);
		if (ntohs(src_udph->len) < sizeof(*src_udph) ||
		    ntohs(src_udph->len) > l4_len)
			return false;
		l4_len = ntohs(src_udph->len);
		break;
	default:
		return false;
	}
	if (check_add_overflow((__u32)ETH_HLEN, len, &alloc_len) ||
	    check_add_overflow(alloc_len, extra_tailroom, &alloc_len))
		return false;
	inner_skb = netdev_alloc_skb_ip_align(target_dev, alloc_len);
	if (!inner_skb) {
		trustix_datapath_rx_worker_alloc_errors++;
		return false;
	}
	skb_reserve(inner_skb, ETH_HLEN);
	dst = skb_put(inner_skb, len);
	memcpy(dst, packet, len);
	iph = (struct iphdr *)dst;
	trustix_datapath_rx_worker_fix_ipv4_header_checksum(iph,
							   ip_header_len);
	switch (iph->protocol) {
	case IPPROTO_TCP:
		tcph = (struct tcphdr *)(dst + ip_header_len);
		if (inner_tcp_checksum_partial) {
			__sum16 expected = ~csum_tcpudp_magic(
				iph->saddr, iph->daddr, l4_len,
				IPPROTO_TCP, 0);

			if (tcph->check != expected) {
				kfree_skb(inner_skb);
				return false;
			}
			tcp_partial_csum = true;
			l4_checksum_rebuilt = false;
		} else if (trust_inner_l4_checksum) {
			trustix_datapath_rx_worker_checksum_trusted++;
			trustix_datapath_rx_worker_checksum_ipv4_only++;
			l4_checksum_rebuilt = false;
		} else if (READ_ONCE(trustix_datapath_rx_worker_xmit_tcp_partial_csum) &&
		    trustix_datapath_rx_worker_tcpv4_partial_csum_dev_supported(
			    target_dev)) {
			tcph->check = ~csum_tcpudp_magic(
				iph->saddr, iph->daddr, l4_len, IPPROTO_TCP,
				0);
			tcp_partial_csum = true;
			l4_checksum_rebuilt = false;
			trustix_datapath_rx_worker_checksum_partial++;
		} else if (trustix_datapath_rx_worker_trust_tcp_checksum(
			    iph, ip_header_len, l4_len, &tcph)) {
			trustix_datapath_rx_worker_checksum_trusted++;
			trustix_datapath_rx_worker_checksum_ipv4_only++;
			l4_checksum_rebuilt = false;
		} else {
			tcph->check = 0;
			l4_sum = csum_partial(tcph, l4_len, 0);
			tcph->check = csum_tcpudp_magic(
				iph->saddr, iph->daddr, l4_len, IPPROTO_TCP,
				l4_sum);
		}
		break;
	case IPPROTO_UDP:
		udph = (struct udphdr *)(dst + ip_header_len);
		if (trust_inner_l4_checksum) {
			trustix_datapath_rx_worker_checksum_trusted++;
			trustix_datapath_rx_worker_checksum_ipv4_only++;
			l4_checksum_rebuilt = false;
		} else {
			udph->check = 0;
			l4_sum = csum_partial(udph, l4_len, 0);
			udph->check = csum_tcpudp_magic(iph->saddr,
							iph->daddr, l4_len,
							IPPROTO_UDP, l4_sum);
			if (!udph->check)
				udph->check = CSUM_MANGLED_0;
		}
		break;
	default:
		kfree_skb(inner_skb);
		return false;
	}
	inner_skb->csum = 0;
	if (tcp_partial_csum) {
		inner_skb->ip_summed = CHECKSUM_PARTIAL;
		inner_skb->csum_start = (unsigned char *)tcph - inner_skb->head;
		inner_skb->csum_offset = offsetof(struct tcphdr, check);
	} else {
		inner_skb->ip_summed = CHECKSUM_UNNECESSARY;
		inner_skb->csum_start = 0;
		inner_skb->csum_offset = 0;
	}
	inner_skb->csum_level = 0;
	skb_reset_network_header(inner_skb);
	skb_set_transport_header(inner_skb, ip_header_len);
	skb_push(inner_skb, ETH_HLEN);
	skb_reset_mac_header(inner_skb);
	skb_set_network_header(inner_skb, ETH_HLEN);
	skb_set_transport_header(inner_skb, ETH_HLEN + ip_header_len);
	inner_skb->mac_len = ETH_HLEN;
	trustix_datapath_rx_worker_fill_inner_eth(inner_skb, target_dev, true);
	if (l4_checksum_rebuilt)
		trustix_datapath_rx_worker_count_checksum_fixed(1);
	trustix_datapath_rx_worker_count_inline_copy_csum_hits(1);
	*inner_skb_out = inner_skb;
	return true;
}

static int trustix_datapath_rx_worker_build_xmit_inner_skb_flags(
	struct net_device *target_dev, const __u8 *packet, __u32 len,
	__u8 tixt_flags,
	struct sk_buff **inner_skb_out)
{
	struct sk_buff *inner_skb;
	int ret;

	if (inner_skb_out)
		*inner_skb_out = NULL;
	if (!target_dev || !packet || !len || !inner_skb_out)
		return -EINVAL;
	if (target_dev->type != ARPHRD_ETHER)
		return -EPROTONOSUPPORT;
	if (trustix_datapath_rx_worker_build_xmit_inner_skb_copy_csum(
		    target_dev, packet, len, 0, tixt_flags,
		    inner_skb_out))
		return 0;
	trustix_datapath_rx_worker_inline_xmit_copy_csum_fallbacks++;
	inner_skb = trustix_datapath_rx_worker_build_inner_skb(
		target_dev, packet, len);
	if (!inner_skb) {
		trustix_datapath_rx_worker_alloc_errors++;
		return -ENOMEM;
	}
	trustix_datapath_rx_worker_prepare_inner_skb(inner_skb, target_dev,
						    true);
	ret = trustix_datapath_rx_worker_restore_inner_tcp_checksum_partial(
		inner_skb, tixt_flags);
	if (!ret)
		ret = trustix_datapath_rx_worker_fix_inner_checksums(inner_skb);
	if (ret) {
		kfree_skb(inner_skb);
		trustix_datapath_rx_worker_checksum_errors++;
		return ret;
	}
	if (inner_skb->len < sizeof(struct iphdr)) {
		kfree_skb(inner_skb);
		return -EINVAL;
	}
	skb_reset_network_header(inner_skb);
	skb_set_transport_header(inner_skb,
				 (inner_skb->data[0] & 0x0f) * 4);
	if (skb_cow_head(inner_skb, ETH_HLEN)) {
		kfree_skb(inner_skb);
		return -ENOMEM;
	}
	skb_push(inner_skb, ETH_HLEN);
	skb_reset_mac_header(inner_skb);
	skb_set_network_header(inner_skb, ETH_HLEN);
	skb_set_transport_header(
		inner_skb,
		ETH_HLEN + (inner_skb->data[ETH_HLEN] & 0x0f) * 4);
	inner_skb->mac_len = ETH_HLEN;
	trustix_datapath_rx_worker_fill_inner_eth(inner_skb, target_dev, true);
	*inner_skb_out = inner_skb;
	return 0;
}

static int trustix_datapath_rx_worker_build_xmit_inner_skb(
	struct net_device *target_dev, const __u8 *packet, __u32 len,
	struct sk_buff **inner_skb_out)
{
	return trustix_datapath_rx_worker_build_xmit_inner_skb_flags(
		target_dev, packet, len, 0, inner_skb_out);
}

static struct sk_buff *
trustix_datapath_rx_worker_build_direct_gso_skb(
	struct net_device *target_dev, const __u8 *packet, __u32 len)
{
	const struct tcphdr *src_tcph;
	const struct iphdr *src_iph;
	struct skb_shared_info *shinfo;
	struct sk_buff *skb;
	struct tcphdr *tcph;
	struct iphdr *iph;
	__u8 *dst;
	__u32 ip_header_len;
	__u32 tcp_header_len;
	__u32 total_len;
	__u32 tcp_len;
	__u32 payload_len;
	__u32 gso_size;
	__u32 gso_segs;

	if (!target_dev || !packet || len < sizeof(*src_iph) + sizeof(*src_tcph)) {
		trustix_datapath_rx_worker_direct_gso_parse_misses++;
		return NULL;
	}
	if (target_dev->type != ARPHRD_ETHER ||
	    !trustix_datapath_dev_supports_tcpv4_gso(target_dev)) {
		trustix_datapath_rx_worker_direct_gso_cap_misses++;
		return NULL;
	}
	src_iph = (const struct iphdr *)packet;
	if (src_iph->version != 4 || src_iph->ihl < 5 ||
	    src_iph->protocol != IPPROTO_TCP ||
	    (src_iph->frag_off & htons(0x3fff))) {
		trustix_datapath_rx_worker_direct_gso_parse_misses++;
		return NULL;
	}
	ip_header_len = src_iph->ihl * 4;
	if (ip_header_len < sizeof(*src_iph) ||
	    len < ip_header_len + sizeof(*src_tcph)) {
		trustix_datapath_rx_worker_direct_gso_parse_misses++;
		return NULL;
	}
	total_len = ntohs(src_iph->tot_len);
	if (total_len != len) {
		trustix_datapath_rx_worker_direct_gso_parse_misses++;
		return NULL;
	}
	if (target_dev->mtu && total_len <= target_dev->mtu) {
		trustix_datapath_rx_worker_direct_gso_mtu_misses++;
		return NULL;
	}
	src_tcph = (const struct tcphdr *)(packet + ip_header_len);
	tcp_header_len = src_tcph->doff * 4;
	if (tcp_header_len < sizeof(*src_tcph) ||
	    tcp_header_len > 60 ||
	    total_len < ip_header_len + tcp_header_len) {
		trustix_datapath_rx_worker_direct_gso_parse_misses++;
		return NULL;
	}
	if (!trustix_datapath_rx_worker_tcp_flags_supported(src_tcph)) {
		trustix_datapath_rx_worker_direct_gso_parse_misses++;
		return NULL;
	}
	tcp_len = total_len - ip_header_len;
	payload_len = tcp_len - tcp_header_len;
	if (!payload_len) {
		trustix_datapath_rx_worker_direct_gso_parse_misses++;
		return NULL;
	}
	gso_size = target_dev->mtu > ip_header_len + tcp_header_len ?
			   target_dev->mtu - ip_header_len - tcp_header_len :
			   payload_len;
	if (!gso_size || gso_size > payload_len) {
		trustix_datapath_rx_worker_direct_gso_mtu_misses++;
		return NULL;
	}
	gso_segs = DIV_ROUND_UP(payload_len, gso_size);
	if (gso_segs < 2 || gso_segs > U16_MAX) {
		trustix_datapath_rx_worker_direct_gso_mtu_misses++;
		return NULL;
	}

	skb = netdev_alloc_skb_ip_align(target_dev, ETH_HLEN + total_len);
	if (!skb) {
		trustix_datapath_rx_worker_alloc_errors++;
		return NULL;
	}
	skb_reserve(skb, ETH_HLEN);
	dst = skb_put(skb, total_len);
	memcpy(dst, packet, total_len);
	iph = (struct iphdr *)dst;
	trustix_datapath_rx_worker_fix_ipv4_header_checksum(iph,
							   ip_header_len);
	tcph = (struct tcphdr *)(dst + ip_header_len);
	tcph->check = ~csum_tcpudp_magic(iph->saddr, iph->daddr, tcp_len,
					 IPPROTO_TCP, 0);
	skb->csum = 0;
	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum_start = (unsigned char *)tcph - skb->head;
	skb->csum_offset = offsetof(struct tcphdr, check);
	skb->csum_level = 0;
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, ip_header_len);
	shinfo = skb_shinfo(skb);
	shinfo->gso_size = gso_size;
	shinfo->gso_segs = gso_segs;
	shinfo->gso_type = SKB_GSO_TCPV4;
	WRITE_ONCE(trustix_datapath_rx_worker_stream_coalesce_last_len,
		   total_len);
	WRITE_ONCE(trustix_datapath_rx_worker_stream_coalesce_last_gso_size,
		   shinfo->gso_size);
	WRITE_ONCE(trustix_datapath_rx_worker_stream_coalesce_last_gso_segs,
		   shinfo->gso_segs);
	WRITE_ONCE(trustix_datapath_rx_worker_stream_coalesce_last_gso_type,
		   shinfo->gso_type);
	if (total_len >
	    READ_ONCE(trustix_datapath_rx_worker_stream_coalesce_max_len))
		WRITE_ONCE(trustix_datapath_rx_worker_stream_coalesce_max_len,
			   total_len);
	return skb;
}

static bool trustix_datapath_rx_worker_direct_gso_xmit_view(
	struct net_device *target_dev,
	const struct trustix_datapath_rx_stage_view *view)
{
	struct sk_buff *inner_skb;
	int ret;

	if (!READ_ONCE(trustix_datapath_rx_worker_stream_coalesce_gso) ||
	    !READ_ONCE(trustix_datapath_rx_worker_xmit) ||
	    !READ_ONCE(trustix_datapath_rx_worker_inline_xmit) ||
	    !READ_ONCE(trustix_datapath_rx_worker_direct_xmit) ||
	    !target_dev || !view || !view->inner_packet ||
	    view->inner.protocol != IPPROTO_TCP)
		return false;
	if (!target_dev->mtu || view->frame.payload_len <= target_dev->mtu)
		return false;
	trustix_datapath_rx_worker_direct_gso_attempts++;
	inner_skb = trustix_datapath_rx_worker_build_direct_gso_skb(
		target_dev, view->inner_packet, view->frame.payload_len);
	if (!inner_skb)
		return false;
	ret = trustix_datapath_rx_worker_prepare_l2_gso_skb(inner_skb,
							   target_dev);
	if (!ret)
		ret = trustix_datapath_rx_worker_queue_l2_skb_from_hook(
			NULL, target_dev, &inner_skb, inner_skb ? inner_skb->len : 0,
			1, NULL);
	kfree_skb(inner_skb);
	if (!ret) {
		trustix_datapath_rx_worker_direct_gso_hits++;
		trustix_datapath_rx_worker_count_stream_coalesce(1, 1);
		return true;
	}
	trustix_datapath_rx_worker_stream_coalesce_errors++;
	trustix_datapath_rx_worker_direct_gso_xmit_errors++;
	return false;
}

static unsigned int
trustix_datapath_rx_worker_single_coalesce_max_frames_value(void)
{
	unsigned int value = READ_ONCE(
		trustix_datapath_rx_worker_single_coalesce_max_frames);

	if (value < 2)
		return 2;
	if (value > TRUSTIX_DATAPATH_RX_WORKER_SINGLE_COALESCE_MAX_FRAMES)
		return TRUSTIX_DATAPATH_RX_WORKER_SINGLE_COALESCE_MAX_FRAMES;
	return value;
}

static unsigned int
trustix_datapath_rx_worker_single_coalesce_flush_jiffies_value(void)
{
	unsigned int value = READ_ONCE(
		trustix_datapath_rx_worker_single_coalesce_flush_jiffies);

	if (value > HZ)
		return HZ;
	return value;
}

static void
trustix_datapath_rx_worker_single_coalesce_detach_locked(
	struct trustix_datapath_rx_worker_single_coalesce_slot *slot,
	struct net_device **target_dev, __u8 **packets, __u32 *lens,
	__u8 *tixt_flags, unsigned int *frames,
	struct trustix_datapath_rx_worker_coalesce_state *state)
{
	unsigned int i;

	if (target_dev)
		*target_dev = NULL;
	if (frames)
		*frames = 0;
	if (packets) {
		for (i = 0;
		     i < TRUSTIX_DATAPATH_RX_WORKER_SINGLE_COALESCE_MAX_FRAMES;
		     i++)
			packets[i] = NULL;
	}
	if (lens)
		memset(lens, 0,
		       sizeof(__u32) *
			       TRUSTIX_DATAPATH_RX_WORKER_SINGLE_COALESCE_MAX_FRAMES);
	if (tixt_flags)
		memset(tixt_flags, 0,
		       sizeof(__u8) *
			       TRUSTIX_DATAPATH_RX_WORKER_SINGLE_COALESCE_MAX_FRAMES);
	if (state)
		memset(state, 0, sizeof(*state));
	if (!slot || !slot->valid)
		return;
	if (target_dev)
		*target_dev = slot->target_dev;
	else if (slot->target_dev)
		dev_put(slot->target_dev);
	if (frames)
		*frames = slot->frames;
	for (i = 0;
	     i < TRUSTIX_DATAPATH_RX_WORKER_SINGLE_COALESCE_MAX_FRAMES; i++) {
		if (packets)
			packets[i] = slot->packets[i];
		else
			kfree(slot->packets[i]);
		if (lens)
			lens[i] = slot->lens[i];
		if (tixt_flags)
			tixt_flags[i] = slot->tixt_flags[i];
		slot->packets[i] = NULL;
		slot->lens[i] = 0;
		slot->tixt_flags[i] = 0;
	}
	if (state)
		*state = slot->state;
	slot->valid = false;
	slot->target_dev = NULL;
	slot->target_ifindex = 0;
	slot->hash = 0;
	slot->frames = 0;
	memset(&slot->state, 0, sizeof(slot->state));
}

static bool
trustix_datapath_rx_worker_single_coalesce_store_locked(
	struct trustix_datapath_rx_worker_single_coalesce_slot *slot,
	struct net_device *target_dev, int target_ifindex, __u32 hash,
	const struct trustix_datapath_rx_worker_coalesce_state *state,
	__u8 **packet, __u32 len, __u8 tixt_flags)
{
	if (!slot || !target_dev || !state || !state->active || !packet ||
	    !*packet || !len || slot->valid)
		return false;
	dev_hold(target_dev);
	slot->valid = true;
	slot->target_dev = target_dev;
	slot->target_ifindex = target_ifindex;
	slot->hash = hash;
	slot->state = *state;
	slot->packets[0] = *packet;
	slot->lens[0] = len;
	slot->tixt_flags[0] = tixt_flags;
	slot->frames = 1;
	*packet = NULL;
	trustix_datapath_rx_worker_count_single_coalesce_stored(1);
	return true;
}

static void trustix_datapath_rx_worker_single_coalesce_free_packets(
	struct net_device *target_dev, __u8 **packets, unsigned int frames)
{
	unsigned int i;

	for (i = 0;
	     i < frames &&
	     i < TRUSTIX_DATAPATH_RX_WORKER_SINGLE_COALESCE_MAX_FRAMES;
	     i++) {
		kfree(packets[i]);
		packets[i] = NULL;
	}
	if (target_dev)
		dev_put(target_dev);
}

static int trustix_datapath_rx_worker_single_coalesce_xmit_singles(
	struct net_device *target_dev, __u8 **packets, __u32 *lens,
	__u8 *tixt_flags, unsigned int frames)
{
	unsigned int delivered = 0;
	unsigned int errors = 0;
	unsigned int i;

	if (!target_dev || !packets || !lens || !frames)
		return -EINVAL;
	for (i = 0;
	     i < frames &&
	     i < TRUSTIX_DATAPATH_RX_WORKER_SINGLE_COALESCE_MAX_FRAMES;
	     i++) {
		struct sk_buff *inner_skb = NULL;
		int ret;

		if (!packets[i] || !lens[i])
			continue;
		ret = trustix_datapath_rx_worker_build_xmit_inner_skb_flags(
			target_dev, packets[i], lens[i],
			tixt_flags ? tixt_flags[i] : 0, &inner_skb);
		if (!ret)
			ret = trustix_datapath_rx_worker_queue_l2_skb_from_hook(
				NULL, target_dev, &inner_skb,
				inner_skb ? inner_skb->len : 0, 1, NULL);
		kfree_skb(inner_skb);
		if (ret) {
			errors++;
			trustix_datapath_rx_worker_single_coalesce_errors++;
			continue;
		}
		delivered++;
	}
	if (delivered)
		trustix_datapath_rx_worker_count_single_coalesce_flushes(
			delivered);
	if (errors)
		return -ENOBUFS;
	return delivered ? 0 : -EINVAL;
}

static int trustix_datapath_rx_worker_single_coalesce_xmit_packets(
	struct net_device *target_dev, __u8 **packets, __u32 *lens,
	__u8 *tixt_flags, unsigned int frames,
	const struct trustix_datapath_rx_worker_coalesce_state *state)
{
	struct trustix_datapath_rx_worker_pending_copy *pending = NULL;
	struct sk_buff *skb = NULL;
	unsigned int i;
	int ret;

	if (!target_dev || !packets || !lens || !state || !state->active ||
	    !frames ||
	    frames > TRUSTIX_DATAPATH_RX_WORKER_SINGLE_COALESCE_MAX_FRAMES)
		return -EINVAL;
	if (frames < 2)
		return trustix_datapath_rx_worker_single_coalesce_xmit_singles(
			target_dev, packets, lens, tixt_flags, frames);
	pending = kcalloc(frames, sizeof(*pending), GFP_ATOMIC);
	if (!pending) {
		trustix_datapath_rx_worker_alloc_errors++;
		trustix_datapath_rx_worker_single_coalesce_errors++;
		return trustix_datapath_rx_worker_single_coalesce_xmit_singles(
			target_dev, packets, lens, tixt_flags, frames);
	}
	for (i = 0; i < frames; i++) {
		if (!packets[i] || !lens[i]) {
			kfree(pending);
			return -EINVAL;
		}
		pending[i].source_packet = packets[i];
		pending[i].len = lens[i];
		pending[i].tixt_flags = tixt_flags ? tixt_flags[i] : 0;
	}
	skb = trustix_datapath_rx_worker_build_coalesced_gso_skb(
		target_dev, state, pending, frames, true);
	if (!skb) {
		trustix_datapath_rx_worker_single_coalesce_errors++;
		ret = trustix_datapath_rx_worker_single_coalesce_xmit_singles(
			target_dev, packets, lens, tixt_flags, frames);
		kfree(pending);
		return ret;
	}
	ret = trustix_datapath_rx_worker_prepare_l2_gso_skb(skb, target_dev);
	if (!ret)
		ret = trustix_datapath_rx_worker_queue_l2_skb_from_hook(
			NULL, target_dev, &skb, skb ? skb->len : 0, frames,
			NULL);
	kfree_skb(skb);
	kfree(pending);
	if (!ret) {
		trustix_datapath_rx_worker_count_single_coalesce(1, frames);
		trustix_datapath_rx_worker_count_stream_coalesce(1, frames);
		return 0;
	}
	trustix_datapath_rx_worker_single_coalesce_errors++;
	return trustix_datapath_rx_worker_single_coalesce_xmit_singles(
		target_dev, packets, lens, tixt_flags, frames);
}

static void
trustix_datapath_rx_worker_single_coalesce_flush_detached(
	struct net_device *target_dev, __u8 **packets, __u32 *lens,
	__u8 *tixt_flags, unsigned int frames,
	const struct trustix_datapath_rx_worker_coalesce_state *state)
{
	if (frames && target_dev)
		trustix_datapath_rx_worker_single_coalesce_xmit_packets(
			target_dev, packets, lens, tixt_flags, frames, state);
	trustix_datapath_rx_worker_single_coalesce_free_packets(target_dev,
								packets,
								frames);
}

static void
trustix_datapath_rx_worker_single_coalesce_flush_slot(
	struct trustix_datapath_rx_worker_single_coalesce_slot *slot)
{
	struct net_device *target_dev = NULL;
	unsigned long flags;
	__u8 *packets[TRUSTIX_DATAPATH_RX_WORKER_SINGLE_COALESCE_MAX_FRAMES];
	__u32 lens[TRUSTIX_DATAPATH_RX_WORKER_SINGLE_COALESCE_MAX_FRAMES];
	__u8 tixt_flags[TRUSTIX_DATAPATH_RX_WORKER_SINGLE_COALESCE_MAX_FRAMES];
	struct trustix_datapath_rx_worker_coalesce_state state = {};
	unsigned int frames = 0;

	if (!slot)
		return;
	spin_lock_irqsave(&slot->lock, flags);
	trustix_datapath_rx_worker_single_coalesce_detach_locked(
		slot, &target_dev, packets, lens, tixt_flags, &frames,
		&state);
	spin_unlock_irqrestore(&slot->lock, flags);
	trustix_datapath_rx_worker_single_coalesce_flush_detached(
		target_dev, packets, lens, tixt_flags, frames, &state);
}

static void trustix_datapath_rx_worker_single_coalesce_flush_work(
	struct work_struct *work)
{
	struct delayed_work *dwork = to_delayed_work(work);
	struct trustix_datapath_rx_worker_single_coalesce_slot *slot =
		container_of(
			dwork,
			struct trustix_datapath_rx_worker_single_coalesce_slot,
			flush_work);

	trustix_datapath_rx_worker_single_coalesce_flush_slot(slot);
}

static void trustix_datapath_rx_worker_single_coalesce_drop_all(void)
{
	struct net_device *target_dev = NULL;
	unsigned long flags;
	__u8 *packets[TRUSTIX_DATAPATH_RX_WORKER_SINGLE_COALESCE_MAX_FRAMES];
	__u32 lens[TRUSTIX_DATAPATH_RX_WORKER_SINGLE_COALESCE_MAX_FRAMES];
	__u8 tixt_flags[TRUSTIX_DATAPATH_RX_WORKER_SINGLE_COALESCE_MAX_FRAMES];
	unsigned int frames = 0;
	unsigned int i;
	unsigned int j;

	for (i = 0; i < TRUSTIX_DATAPATH_RX_WORKER_SINGLE_COALESCE_SLOTS; i++) {
		struct trustix_datapath_rx_worker_single_coalesce_slot *slot =
			&trustix_datapath_rx_worker_single_coalesce_slots[i];

		cancel_delayed_work_sync(&slot->flush_work);
		spin_lock_irqsave(&slot->lock, flags);
		trustix_datapath_rx_worker_single_coalesce_detach_locked(
			slot, &target_dev, packets, lens, tixt_flags, &frames,
			NULL);
		spin_unlock_irqrestore(&slot->lock, flags);
		for (j = 0;
		     j < frames &&
		     j < TRUSTIX_DATAPATH_RX_WORKER_SINGLE_COALESCE_MAX_FRAMES;
		     j++)
			kfree(packets[j]);
		if (target_dev)
			dev_put(target_dev);
		target_dev = NULL;
		frames = 0;
	}
}

static bool trustix_datapath_rx_worker_single_coalesce_view(
	struct net_device *target_dev,
	const struct trustix_datapath_rx_stage_view *view,
	int target_ifindex)
{
	struct trustix_datapath_rx_worker_coalesce_state cur_state = {};
	struct trustix_datapath_rx_worker_coalesce_state merged = {};
	struct trustix_datapath_rx_worker_single_coalesce_slot *slot;
	struct net_device *held_dev = NULL;
	__u8 *held_packets[TRUSTIX_DATAPATH_RX_WORKER_SINGLE_COALESCE_MAX_FRAMES];
	__u32 held_lens[TRUSTIX_DATAPATH_RX_WORKER_SINGLE_COALESCE_MAX_FRAMES];
	__u8 held_flags[TRUSTIX_DATAPATH_RX_WORKER_SINGLE_COALESCE_MAX_FRAMES];
	struct trustix_datapath_rx_worker_coalesce_state held_state = {};
	unsigned int held_frames = 0;
	unsigned int max_frames;
	unsigned long flags;
	__u8 *packet = NULL;
	__u32 hash;
	bool appended = false;
	bool flush_with_current = false;
	bool stored = false;
	int ret;

	if (!READ_ONCE(trustix_datapath_rx_worker_single_coalesce) ||
	    !READ_ONCE(trustix_datapath_rx_worker_stream_coalesce_gso) ||
	    !READ_ONCE(trustix_datapath_rx_worker_xmit) ||
	    !READ_ONCE(trustix_datapath_rx_worker_inline_xmit) ||
	    !target_dev || !view || !view->inner_packet ||
	    view->inner.protocol != IPPROTO_TCP || !view->frame.payload_len ||
	    target_dev->type != ARPHRD_ETHER ||
	    !trustix_datapath_dev_supports_tcpv4_gso(target_dev))
		return false;
	packet = kmemdup(view->inner_packet, view->frame.payload_len,
			 GFP_ATOMIC);
	if (!packet) {
		trustix_datapath_rx_worker_alloc_errors++;
		trustix_datapath_rx_worker_single_coalesce_errors++;
		return false;
	}
	ret = trustix_datapath_rx_worker_coalesce_accept(
		&cur_state, packet, view->frame.payload_len);
	if (ret)
		goto miss;
	hash = trustix_datapath_rx_worker_inline_pair_hash(&cur_state,
							  target_ifindex);
	slot = &trustix_datapath_rx_worker_single_coalesce_slots
			[hash & (TRUSTIX_DATAPATH_RX_WORKER_SINGLE_COALESCE_SLOTS - 1)];
	max_frames = trustix_datapath_rx_worker_single_coalesce_max_frames_value();

	spin_lock_irqsave(&slot->lock, flags);
	if (slot->valid) {
		merged = slot->state;
		if (slot->target_dev == target_dev &&
		    slot->target_ifindex == target_ifindex &&
		    slot->hash == hash &&
		    !trustix_datapath_rx_worker_coalesce_accept(
			    &merged, packet, view->frame.payload_len)) {
			if (slot->frames + 1 >= max_frames) {
				trustix_datapath_rx_worker_single_coalesce_detach_locked(
					slot, &held_dev, held_packets,
					held_lens, held_flags, &held_frames,
					&held_state);
				held_state = merged;
				flush_with_current = true;
			} else if (slot->frames <
				   TRUSTIX_DATAPATH_RX_WORKER_SINGLE_COALESCE_MAX_FRAMES) {
				slot->state = merged;
				slot->packets[slot->frames] = packet;
				slot->lens[slot->frames] =
					view->frame.payload_len;
				slot->tixt_flags[slot->frames] =
					view->frame.flags;
				slot->frames++;
				packet = NULL;
				appended = true;
				trustix_datapath_rx_worker_count_single_coalesce_stored(1);
			}
		} else {
			trustix_datapath_rx_worker_single_coalesce_misses++;
			trustix_datapath_rx_worker_single_coalesce_detach_locked(
				slot, &held_dev, held_packets, held_lens,
				held_flags, &held_frames, &held_state);
			stored =
				trustix_datapath_rx_worker_single_coalesce_store_locked(
					slot, target_dev, target_ifindex, hash,
					&cur_state, &packet,
					view->frame.payload_len,
					view->frame.flags);
		}
	} else {
		stored =
			trustix_datapath_rx_worker_single_coalesce_store_locked(
				slot, target_dev, target_ifindex, hash,
				&cur_state, &packet, view->frame.payload_len,
				view->frame.flags);
	}
	spin_unlock_irqrestore(&slot->lock, flags);

	if (appended || stored) {
		mod_delayed_work(
			system_wq, &slot->flush_work,
			trustix_datapath_rx_worker_single_coalesce_flush_jiffies_value());
		trustix_datapath_rx_worker_single_coalesce_flush_detached(
			held_dev, held_packets, held_lens, held_flags,
			held_frames, &held_state);
		kfree(packet);
		return true;
	}

	if (flush_with_current) {
		if (held_frames <
		    TRUSTIX_DATAPATH_RX_WORKER_SINGLE_COALESCE_MAX_FRAMES) {
			held_packets[held_frames] = packet;
			held_lens[held_frames] = view->frame.payload_len;
			held_flags[held_frames] = view->frame.flags;
			held_frames++;
			packet = NULL;
			trustix_datapath_rx_worker_count_single_coalesce_stored(1);
		}
		trustix_datapath_rx_worker_single_coalesce_flush_detached(
			held_dev, held_packets, held_lens, held_flags,
			held_frames, &held_state);
		kfree(packet);
		return true;
	}

miss:
	kfree(packet);
	if (held_frames || held_dev)
		trustix_datapath_rx_worker_single_coalesce_flush_detached(
			held_dev, held_packets, held_lens, held_flags,
			held_frames, &held_state);
	return false;
}

static bool trustix_datapath_rx_worker_build_xmit_inner_skb_hold(
	struct net_device *target_dev, const __u8 *packet, __u32 len,
	__u32 extra_tailroom, struct sk_buff **inner_skb_out)
{
	if (inner_skb_out)
		*inner_skb_out = NULL;
	if (!READ_ONCE(trustix_datapath_rx_worker_inline_pair_hold_skb) ||
	    READ_ONCE(trustix_datapath_rx_worker_stream_coalesce_partial_csum))
		return false;
	return trustix_datapath_rx_worker_build_xmit_inner_skb_copy_csum(
		target_dev, packet, len, extra_tailroom, 0,
		inner_skb_out);
}

static int trustix_datapath_rx_worker_inline_pair_xmit_skb_frames(
	struct net_device *target_dev, struct sk_buff *skb,
	bool inline_context, unsigned int frames)
{
	int ret;

	if (!skb)
		return -EINVAL;
	if (!frames)
		frames = 1;
	if (!target_dev) {
		kfree_skb(skb);
		return -EINVAL;
	}
	if (inline_context) {
		ret = trustix_datapath_rx_worker_queue_l2_skb_from_hook(
			NULL, target_dev, &skb, skb->len, frames, NULL);
		if (!ret) {
			trustix_datapath_rx_worker_count_pair_flushes(frames);
			if (frames > 1) {
				trustix_datapath_rx_worker_count_pair_packets(frames);
				trustix_datapath_rx_worker_count_stream_coalesce(
					1, frames);
			}
			return 0;
		}
		kfree_skb(skb);
		trustix_datapath_rx_worker_dropped += frames;
		trustix_datapath_rx_worker_inline_xmit_errors += frames;
		trustix_datapath_rx_worker_inline_pair_errors++;
		return ret;
	}
	if (skb_is_gso(skb)) {
		ret = trustix_datapath_rx_worker_xmit_inner_gso(
			skb, target_dev, false);
		if (!ret) {
			trustix_datapath_rx_worker_count_injected(frames);
			if (inline_context)
				trustix_datapath_rx_worker_count_inline_xmit(
					frames);
			trustix_datapath_rx_worker_count_pair_flushes(frames);
			if (frames > 1) {
				trustix_datapath_rx_worker_count_pair_packets(frames);
				trustix_datapath_rx_worker_count_stream_coalesce(
					1, frames);
			}
			return 0;
		}
		trustix_datapath_rx_worker_dropped += frames;
		trustix_datapath_rx_worker_inline_xmit_errors += frames;
		trustix_datapath_rx_worker_inline_pair_errors++;
		return ret;
	}
	ret = trustix_datapath_rx_worker_deliver_inner_skb(
		skb, target_dev, inline_context);
	if (!ret) {
		trustix_datapath_rx_worker_count_injected(frames);
		trustix_datapath_rx_worker_count_inline_xmit(frames);
		trustix_datapath_rx_worker_count_pair_flushes(frames);
		if (frames > 1) {
			trustix_datapath_rx_worker_count_pair_packets(frames);
			trustix_datapath_rx_worker_count_stream_coalesce(1,
									 frames);
		}
		return 0;
	}
	trustix_datapath_rx_worker_dropped += frames;
	trustix_datapath_rx_worker_inline_xmit_errors += frames;
	trustix_datapath_rx_worker_inline_pair_errors++;
	return ret;
}

static int trustix_datapath_rx_worker_inline_pair_append_held_skb(
	struct sk_buff *skb, struct net_device *target_dev,
	const struct trustix_datapath_rx_worker_coalesce_state *state,
	const __u8 *packet, __u32 len)
{
	struct skb_shared_info *shinfo;
	const struct iphdr *frame_iph;
	struct tcphdr *tcph;
	struct iphdr *iph;
	__u32 frame_payload_len;
	__u32 header_len;
	__u32 old_tcp_len;
	__u32 tcp_len;
	__u32 gso_segs;
	__u8 *dst;

	if (!skb || !target_dev || !state || !state->active || !packet ||
	    !len || state->total_len > 0xffff)
		return -EINVAL;
	header_len = sizeof(struct iphdr) + state->tcp_header_len;
	if (len < header_len || skb->len < ETH_HLEN + header_len)
		return -EINVAL;
	frame_iph = (const struct iphdr *)packet;
	if (ntohs(frame_iph->tot_len) < header_len ||
	    ntohs(frame_iph->tot_len) > len)
		return -EINVAL;
	frame_payload_len = ntohs(frame_iph->tot_len) - header_len;
	if (!frame_payload_len || frame_payload_len > state->gso_size ||
	    skb_tailroom(skb) < frame_payload_len)
		return -ENOSPC;
	dst = skb_put(skb, frame_payload_len);
	memcpy(dst, packet + header_len, frame_payload_len);
	iph = (struct iphdr *)(skb->data + ETH_HLEN);
	tcph = (struct tcphdr *)((__u8 *)iph + sizeof(*iph));
	old_tcp_len = ntohs(iph->tot_len) - sizeof(*iph);
	iph->tot_len = htons((__u16)state->total_len);
	trustix_datapath_rx_worker_fix_ipv4_header_checksum(iph,
							   sizeof(*iph));
	tcp_len = state->total_len - sizeof(*iph);
	tcph->check =
		trustix_datapath_rx_worker_tcp_checksum_append_payload(
			tcph, old_tcp_len, tcp_len, packet + header_len,
			frame_payload_len);
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	skb->csum = 0;
	skb->csum_level = 0;
	skb->csum_start = 0;
	skb->csum_offset = 0;
	skb_reset_network_header(skb);
	skb_set_network_header(skb, ETH_HLEN);
	skb_set_transport_header(skb, ETH_HLEN + sizeof(*iph));
	skb->mac_len = ETH_HLEN;
	skb_reset_inner_headers(skb);
	gso_segs = DIV_ROUND_UP(state->payload_len, state->gso_size);
	if (!gso_segs || gso_segs > U16_MAX)
		return -EINVAL;
	shinfo = skb_shinfo(skb);
	shinfo->gso_size = state->gso_size;
	shinfo->gso_segs = gso_segs;
	shinfo->gso_type = SKB_GSO_TCPV4;
	WRITE_ONCE(trustix_datapath_rx_worker_stream_coalesce_last_len,
		   skb->len - ETH_HLEN);
	WRITE_ONCE(trustix_datapath_rx_worker_stream_coalesce_last_gso_size,
		   shinfo->gso_size);
	WRITE_ONCE(trustix_datapath_rx_worker_stream_coalesce_last_gso_segs,
		   shinfo->gso_segs);
	WRITE_ONCE(trustix_datapath_rx_worker_stream_coalesce_last_gso_type,
		   shinfo->gso_type);
	if (skb->len - ETH_HLEN >
	    READ_ONCE(trustix_datapath_rx_worker_stream_coalesce_max_len))
		WRITE_ONCE(trustix_datapath_rx_worker_stream_coalesce_max_len,
			   skb->len - ETH_HLEN);
	return 0;
}

static int trustix_datapath_rx_worker_queue_stream_gso_from_pending(
	struct sk_buff *source_skb, struct net_device *target_dev,
	struct trustix_datapath_rx_worker_pending_copy *pending,
	unsigned int frames, unsigned int *queued_frames)
{
	struct trustix_datapath_rx_worker_coalesce_state coalesce = {};
	struct sk_buff *inner_skb = NULL;
	unsigned int queued = 0;
	unsigned int i;
	int ret;

	if (queued_frames)
		*queued_frames = 0;
	if (!READ_ONCE(trustix_datapath_rx_worker_stream_coalesce_gso) ||
	    !READ_ONCE(trustix_datapath_rx_worker_xmit) ||
	    !source_skb || !target_dev || !pending || frames < 2)
		return -EOPNOTSUPP;
	if (target_dev->type != ARPHRD_ETHER)
		return -EPROTONOSUPPORT;
	for (i = 0; i < frames; i++) {
		ret = trustix_datapath_rx_worker_coalesce_accept_pending(
			&coalesce, &pending[i]);
		if (ret) {
			trustix_datapath_rx_worker_stream_direct_gso_fallbacks++;
			return ret;
		}
	}
	inner_skb = trustix_datapath_rx_worker_build_coalesced_gso_skb(
		target_dev, &coalesce, pending, frames, true);
	if (!inner_skb) {
		trustix_datapath_rx_worker_stream_direct_gso_fallbacks++;
		return -EOPNOTSUPP;
	}
	ret = trustix_datapath_rx_worker_prepare_l2_gso_skb(inner_skb,
							   target_dev);
	if (ret) {
		kfree_skb(inner_skb);
		trustix_datapath_rx_worker_stream_direct_gso_errors++;
		return ret;
	}
	ret = trustix_datapath_rx_worker_queue_l2_skb_from_hook(
		source_skb, target_dev, &inner_skb, inner_skb->len, frames,
		&queued);
	if (ret) {
		kfree_skb(inner_skb);
		trustix_datapath_rx_worker_stream_direct_gso_errors++;
		return ret;
	}
	trustix_datapath_rx_worker_stream_direct_gso_packets++;
	trustix_datapath_rx_worker_stream_direct_gso_frames += frames;
	trustix_datapath_rx_worker_count_stream_coalesce(1, frames);
	if (queued_frames)
		*queued_frames = queued ?: frames;
	WRITE_ONCE(trustix_datapath_rx_worker_last_push_ret, 0);
	return 0;
}

static int trustix_datapath_rx_worker_inline_steal_xmit_view(
	struct sk_buff *skb, const struct trustix_datapath_rx_stage_view *view,
	struct net_device *target_dev, bool *stolen)
{
	struct udphdr *udph;
	struct tcphdr *tcph;
	struct iphdr *iph;
	__u32 ip_header_len;
	__u32 l4_len;
	__u32 total_len;
	__u32 end;
	int ret;

	if (stolen)
		*stolen = false;
	if (!READ_ONCE(trustix_datapath_rx_worker_steal_skb) ||
	    !READ_ONCE(trustix_datapath_rx_worker_inline_stolen) ||
	    !READ_ONCE(trustix_datapath_rx_worker_xmit))
		return -EOPNOTSUPP;
	if (!skb || !view || !target_dev || !view->inner_packet ||
	    !view->frame.payload_len)
		return -EINVAL;
	if (!trustix_datapath_rx_worker_dev_ready(target_dev))
		return -ENETDOWN;
	if (target_dev->type != ARPHRD_ETHER)
		return -EPROTONOSUPPORT;
	if (skb_cloned(skb) || skb_shared(skb) || skb_header_cloned(skb) ||
	    skb_is_nonlinear(skb)) {
		trustix_datapath_rx_worker_steal_fallbacks++;
		return -EOPNOTSUPP;
	}
	if (view->inner_offset > skb_headlen(skb) ||
	    view->frame.payload_len > skb_headlen(skb) - view->inner_offset) {
		trustix_datapath_rx_worker_steal_fallbacks++;
		return -EOPNOTSUPP;
	}
	if (check_add_overflow(view->inner_offset, view->frame.payload_len,
			       &end) ||
	    end > skb->len) {
		trustix_datapath_rx_worker_steal_fallbacks++;
		return -EOPNOTSUPP;
	}
	if (target_dev->mtu && view->frame.payload_len > target_dev->mtu) {
		trustix_datapath_rx_worker_steal_fallbacks++;
		return -EOPNOTSUPP;
	}
	if (skb_headroom(skb) + view->inner_offset < ETH_HLEN) {
		trustix_datapath_rx_worker_steal_fallbacks++;
		return -EOPNOTSUPP;
	}

	iph = (struct iphdr *)(skb->data + view->inner_offset);
	if (view->frame.payload_len < sizeof(*iph) || iph->version != 4 ||
	    iph->ihl < 5 || (iph->frag_off & htons(0x3fff))) {
		trustix_datapath_rx_worker_steal_fallbacks++;
		return -EOPNOTSUPP;
	}
	ip_header_len = iph->ihl * 4;
	if (ip_header_len < sizeof(*iph) ||
	    view->frame.payload_len < ip_header_len) {
		trustix_datapath_rx_worker_steal_fallbacks++;
		return -EOPNOTSUPP;
	}
	total_len = ntohs(iph->tot_len);
	if (total_len != view->frame.payload_len ||
	    total_len < ip_header_len) {
		trustix_datapath_rx_worker_steal_fallbacks++;
		return -EOPNOTSUPP;
	}
	l4_len = total_len - ip_header_len;
	switch (iph->protocol) {
	case IPPROTO_TCP:
		if (l4_len < sizeof(*tcph)) {
			trustix_datapath_rx_worker_steal_fallbacks++;
			return -EOPNOTSUPP;
		}
		tcph = (struct tcphdr *)((__u8 *)iph + ip_header_len);
		if (tcph->doff < 5 || l4_len < (__u32)tcph->doff * 4) {
			trustix_datapath_rx_worker_steal_fallbacks++;
			return -EOPNOTSUPP;
		}
		break;
	case IPPROTO_UDP:
		if (l4_len < sizeof(*udph)) {
			trustix_datapath_rx_worker_steal_fallbacks++;
			return -EOPNOTSUPP;
		}
		udph = (struct udphdr *)((__u8 *)iph + ip_header_len);
		if (ntohs(udph->len) < sizeof(*udph) ||
		    ntohs(udph->len) > l4_len) {
			trustix_datapath_rx_worker_steal_fallbacks++;
			return -EOPNOTSUPP;
		}
		break;
	default:
		trustix_datapath_rx_worker_steal_fallbacks++;
		return -EOPNOTSUPP;
	}

	skb_pull(skb, view->inner_offset);
	skb_trim(skb, view->frame.payload_len);
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, ip_header_len);
	skb->protocol = htons(ETH_P_IP);
	skb->pkt_type = PACKET_OUTGOING;
	skb->encapsulation = 0;
	skb->csum = 0;
	skb->csum_level = 0;
	skb_reset_inner_headers(skb);

	if (trustix_datapath_rx_worker_tixt_inner_l4_checksum_valid(
		    view->frame.flags)) {
		iph = ip_hdr(skb);
		trustix_datapath_rx_worker_fix_ipv4_header_checksum(
			iph, ip_header_len);
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		skb->csum_start = 0;
		skb->csum_offset = 0;
		trustix_datapath_rx_worker_checksum_trusted++;
		trustix_datapath_rx_worker_checksum_ipv4_only++;
	} else {
		trustix_datapath_rx_worker_prepare_inner_skb(skb, target_dev,
							    true);
		ret = trustix_datapath_rx_worker_restore_inner_tcp_checksum_partial(
			skb, view->frame.flags);
		if (!ret)
			ret = trustix_datapath_rx_worker_fix_inner_checksums(skb);
		if (ret) {
			if (stolen)
				*stolen = true;
			kfree_skb(skb);
			trustix_datapath_rx_worker_checksum_errors++;
			trustix_datapath_rx_worker_steal_errors++;
			trustix_datapath_rx_worker_dropped++;
			WRITE_ONCE(trustix_datapath_rx_worker_last_push_ret,
				   ret);
			return 0;
		}
	}

	if (skb_headroom(skb) < ETH_HLEN) {
		if (stolen)
			*stolen = true;
		kfree_skb(skb);
		trustix_datapath_rx_worker_steal_errors++;
		trustix_datapath_rx_worker_dropped++;
		WRITE_ONCE(trustix_datapath_rx_worker_last_push_ret, -ENOSPC);
		return 0;
	}
	skb_push(skb, ETH_HLEN);
	skb_reset_mac_header(skb);
	skb_set_network_header(skb, ETH_HLEN);
	skb_set_transport_header(skb, ETH_HLEN + ip_header_len);
	skb->mac_len = ETH_HLEN;
	trustix_datapath_rx_worker_fill_inner_eth(skb, target_dev, true);

	if (stolen)
		*stolen = true;
	ret = trustix_datapath_rx_worker_deliver_inner_skb(skb, target_dev,
							   true);
	if (!ret) {
		trustix_datapath_rx_worker_stolen++;
		trustix_datapath_rx_worker_inline_injected++;
		trustix_datapath_rx_worker_count_injected(1);
		trustix_datapath_rx_worker_count_inline_xmit(1);
		WRITE_ONCE(trustix_datapath_rx_worker_last_push_ret, 0);
		return 0;
	}
	trustix_datapath_rx_worker_steal_errors++;
	trustix_datapath_rx_worker_inline_errors++;
	trustix_datapath_rx_worker_dropped++;
	WRITE_ONCE(trustix_datapath_rx_worker_last_push_ret, ret);
	return 0;
}

static int trustix_datapath_rx_worker_inline_xmit_view(
	struct sk_buff *skb, const struct trustix_datapath_rx_stage_view *view,
	int target_ifindex, struct net_device *target_dev_hint,
	bool *stolen)
{
	struct net_device *target_dev = NULL;
	struct sk_buff *inner_skb = NULL;
	int ret;

	if (stolen)
		*stolen = false;
	if (!READ_ONCE(trustix_datapath_rx_worker_inline_xmit) ||
	    !READ_ONCE(trustix_datapath_rx_worker_xmit))
		return -EOPNOTSUPP;
	if (!skb || !view || !view->inner_packet || !view->frame.payload_len)
		return -EINVAL;
	if (view->frame.payload_len > TRUSTIX_DATAPATH_PACKET_MAX_LEN)
		return -EMSGSIZE;
	ret = trustix_datapath_rx_worker_target_dev_hint(
		skb, &target_dev, target_ifindex, target_dev_hint);
	if (ret)
		return ret;
	if (!trustix_datapath_rx_worker_payload_fits_target(view,
							    target_dev)) {
		ret = -EOPNOTSUPP;
		goto out;
	}
	if (!trustix_datapath_rx_worker_dev_ready(target_dev)) {
		ret = -ENETDOWN;
		goto out;
	}
	ret = trustix_datapath_rx_worker_inline_steal_xmit_view(
		skb, view, target_dev, stolen);
	if (!ret) {
		goto out;
	}
	if (trustix_datapath_rx_worker_direct_gso_xmit_view(target_dev,
							    view)) {
		ret = 0;
		goto out;
	}
	if (trustix_datapath_rx_worker_single_coalesce_view(
		    target_dev, view, target_ifindex)) {
		ret = 0;
		goto out;
	}
	if (trustix_datapath_rx_worker_inline_pair_coalesce_view(
		    target_dev, view, target_ifindex)) {
		ret = 0;
		goto out;
	}
	ret = trustix_datapath_rx_worker_build_xmit_inner_skb_flags(
		target_dev, view->inner_packet, view->frame.payload_len,
		view->frame.flags, &inner_skb);
	if (ret)
		goto out;
	ret = trustix_datapath_rx_worker_queue_l2_skb_from_hook(
		skb, target_dev, &inner_skb, inner_skb->len, 1, NULL);
	if (!ret)
		WRITE_ONCE(trustix_datapath_rx_worker_last_push_ret, 0);
out:
	kfree_skb(inner_skb);
	if (target_dev)
		dev_put(target_dev);
	if (ret && ret != -ENOSPC)
		trustix_datapath_rx_worker_inline_xmit_errors++;
	return ret;
}

static int
trustix_datapath_rx_worker_inline_xmit_stream_copy(
	struct sk_buff *skb, const struct trustix_datapath_ioc_classify *outer,
	__u32 total_len, __u32 tixt_offset, unsigned int expected_frames,
	int target_ifindex, unsigned int *xmit_frames)
{
	struct trustix_datapath_rx_worker_pending_copy *pending;
	struct trustix_datapath_rx_stage_view view = {};
	struct trustix_datapath_rx_validation_cache validation_cache = {};
	struct trustix_datapath_ioc_classify inner = {};
	struct net_device *target_dev = NULL;
	const __u8 *network;
	const __u8 *cursor;
	const __u8 *inner_packet;
	__u8 inner_ip_header_len;
	__u8 inner_l4_header_len;
	__u32 remaining;
	unsigned int delivered = 0;
	unsigned int errors = 0;
	unsigned int frames = 0;
	unsigned int i;
	int first_error = 0;
	int ret;

	if (xmit_frames)
		*xmit_frames = 0;
	if (!READ_ONCE(trustix_datapath_rx_worker_inline_xmit) ||
	    !READ_ONCE(trustix_datapath_rx_worker_xmit))
		return -EOPNOTSUPP;
	if (!skb || !outer || !expected_frames ||
	    expected_frames > TRUSTIX_DATAPATH_RX_WORKER_STREAM_MAX_FRAMES)
		return -EINVAL;
	ret = trustix_datapath_rx_worker_target_dev(skb, &target_dev,
						    target_ifindex);
	if (ret)
		return ret;
	if (target_dev->type != ARPHRD_ETHER) {
		ret = -EPROTONOSUPPORT;
		goto out_dev;
	}
	if (!trustix_datapath_rx_worker_dev_ready(target_dev)) {
		ret = -ENETDOWN;
		goto out_dev;
	}
	pending = kcalloc(expected_frames, sizeof(*pending), GFP_ATOMIC);
	if (!pending) {
		trustix_datapath_rx_worker_alloc_errors++;
		ret = -ENOMEM;
		goto out_dev;
	}
	network = skb_network_header(skb);
	cursor = network + tixt_offset;
	remaining = total_len - tixt_offset;
	while (remaining) {
		if (frames >= expected_frames) {
			ret = -E2BIG;
			goto error;
		}
		memset(&view, 0, sizeof(view));
		ret = trustix_datapath_parse_tixt_header(cursor, remaining,
							 &view.frame);
		if (ret)
			goto error;
		if (!(view.frame.flags &
		      TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4) ||
		    !view.frame.wire_len ||
		    view.frame.wire_len > remaining ||
		    !view.frame.payload_len ||
		    view.frame.payload_len > TRUSTIX_DATAPATH_PACKET_MAX_LEN) {
			ret = -EPROTONOSUPPORT;
			goto error;
		}
		inner_packet = cursor + view.frame.header_len;
		ret = trustix_datapath_parse_ipv4_packet(
			inner_packet, view.frame.payload_len, &inner,
			&inner_ip_header_len, &inner_l4_header_len);
		if (ret)
			goto error;
		if (inner_packet < skb->data ||
		    inner_packet - skb->data > TRUSTIX_DATAPATH_PACKET_MAX_LEN) {
			ret = -EOVERFLOW;
			goto error;
		}
		view.inner = inner;
		view.inner_packet = inner_packet;
		view.tixt_len = view.frame.wire_len;
		view.inner_offset = (__u32)(inner_packet - skb->data);
		view.inner_ip_header_len = inner_ip_header_len;
		view.inner_l4_header_len = inner_l4_header_len;
		ret = trustix_datapath_rx_stage_validate_batch(
			outer, &view, &validation_cache);
		if (ret)
			goto error;
		if (!trustix_datapath_rx_worker_payload_fits_target(
			    &view, target_dev)) {
			ret = -EOPNOTSUPP;
			goto error;
		}
		pending[frames].source_packet = inner_packet;
		pending[frames].len = view.frame.payload_len;
		pending[frames].tixt_flags = view.frame.flags;
		frames++;
		cursor += view.frame.wire_len;
		remaining -= view.frame.wire_len;
	}
	if (frames != expected_frames) {
		ret = -EIO;
		goto error;
	}
	for (i = 0; i < frames; i++) {
		ret = trustix_datapath_rx_worker_build_xmit_inner_skb_flags(
			target_dev, pending[i].source_packet, pending[i].len,
			pending[i].tixt_flags,
			&pending[i].skb);
		if (ret)
			goto error;
	}
	for (i = 0; i < frames; i++) {
		struct sk_buff *inner_skb = pending[i].skb;

		pending[i].skb = NULL;
		ret = trustix_datapath_rx_worker_queue_l2_skb_from_hook(
			skb, target_dev, &inner_skb, inner_skb->len, 1, NULL);
		pending[i].skb = inner_skb;
		if (ret) {
			errors++;
			if (!first_error)
				first_error = ret;
			continue;
		}
		delivered++;
	}
	if (delivered) {
		trustix_datapath_rx_worker_count_stream_batch(1,
							      delivered);
	}
	if (errors && delivered) {
		trustix_datapath_rx_worker_dropped += errors;
		trustix_datapath_rx_worker_inline_xmit_errors += errors;
	}
	if (xmit_frames)
		*xmit_frames = delivered;
	trustix_datapath_rx_worker_free_pending_copies(pending, frames);
	kfree(pending);
	dev_put(target_dev);
	return delivered ? 0 : (first_error ? first_error : -ENOBUFS);

error:
	trustix_datapath_rx_worker_inline_xmit_errors++;
	trustix_datapath_rx_worker_free_pending_copies(pending, frames);
	kfree(pending);
out_dev:
	if (target_dev)
		dev_put(target_dev);
	return ret;
}

static int
trustix_datapath_rx_worker_push_stream_batch_source(
	struct sk_buff *skb, const struct trustix_datapath_ioc_classify *outer,
	__u32 total_len, __u32 tixt_offset, unsigned int expected_frames,
	int target_ifindex, unsigned int *queued_frames, bool force_queue,
	bool offset_copy, const __u8 *linear_network)
{
	struct trustix_datapath_rx_worker_pending_copy *pending = NULL;
	struct trustix_datapath_rx_stage_view view = {};
	struct trustix_datapath_rx_validation_cache validation_cache = {};
	struct trustix_datapath_ioc_classify inner = {};
	struct net_device *target_dev = NULL;
	__u8 inner_header[sizeof(struct iphdr) + 60];
	const __u8 *network;
	const __u8 *cursor;
	const __u8 *inner_packet;
	__u8 inner_ip_header_len;
	__u8 inner_l4_header_len;
	__u32 cursor_offset = 0;
	__u32 inner_offset;
	__u32 remaining;
	unsigned int frames = 0;
	unsigned int queued = 0;
	int network_offset;
	int ret;

	if (queued_frames)
		*queued_frames = 0;
	if (!force_queue &&
	    !READ_ONCE(trustix_datapath_rx_worker_stream_batch_queue))
		return -EOPNOTSUPP;
	if (!skb || !outer || !expected_frames || total_len < tixt_offset ||
	    expected_frames > TRUSTIX_DATAPATH_RX_WORKER_STREAM_MAX_FRAMES)
		return -EINVAL;
	ret = trustix_datapath_rx_worker_target_dev(skb, &target_dev,
						    target_ifindex);
	if (ret)
		return ret;
	if (!trustix_datapath_rx_worker_dev_ready(target_dev)) {
		ret = -ENETDOWN;
		goto error;
	}
	pending = kcalloc(expected_frames, sizeof(*pending), GFP_ATOMIC);
	if (!pending) {
		trustix_datapath_rx_worker_alloc_errors++;
		ret = -ENOMEM;
		goto error;
	}
	if (linear_network) {
		network = linear_network;
		network_offset = 0;
		offset_copy = false;
		cursor = network + tixt_offset;
	} else {
		network = skb_network_header(skb);
		if (!network) {
			ret = -EINVAL;
			goto error;
		}
		network_offset = skb_network_offset(skb);
		if (network_offset < 0 ||
		    (__u32)network_offset > skb->len ||
		    tixt_offset > skb->len - (__u32)network_offset) {
			ret = -EOVERFLOW;
			goto error;
		}
	}
	if (!linear_network && offset_copy) {
		cursor = NULL;
		cursor_offset = (__u32)network_offset + tixt_offset;
	} else if (!linear_network) {
		cursor = network + tixt_offset;
	}
	remaining = total_len - tixt_offset;
	while (remaining) {
		__u32 inner_header_len;

		if (frames >= expected_frames) {
			ret = -E2BIG;
			goto error;
		}
		memset(&view, 0, sizeof(view));
		if (offset_copy)
			ret = trustix_datapath_parse_tixt_skb_header(
				skb, cursor_offset, remaining, &view.frame);
		else
			ret = trustix_datapath_parse_tixt_header(
				cursor, remaining, &view.frame);
		if (ret)
			goto error;
		if (!(view.frame.flags &
		      TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4) ||
		    !view.frame.wire_len ||
		    view.frame.wire_len > remaining ||
		    !view.frame.payload_len ||
		    view.frame.payload_len > TRUSTIX_DATAPATH_PACKET_MAX_LEN) {
			ret = -EPROTONOSUPPORT;
			goto error;
		}
		if (offset_copy) {
			if (check_add_overflow(cursor_offset,
				       (__u32)view.frame.header_len,
				       &inner_offset) ||
			    inner_offset > skb->len ||
			    view.frame.payload_len > skb->len - inner_offset) {
				ret = -EMSGSIZE;
				goto error;
			}
			inner_header_len = min_t(__u32,
				view.frame.payload_len, sizeof(inner_header));
			if (skb_copy_bits(skb, inner_offset, inner_header,
					  inner_header_len)) {
				ret = -ENODATA;
				goto error;
			}
			inner_packet = inner_header;
		} else {
			inner_packet = cursor + view.frame.header_len;
			inner_offset = linear_network ?
				(__u32)(inner_packet - linear_network) :
				(__u32)(inner_packet - skb->data);
		}
		ret = trustix_datapath_parse_ipv4_packet(
			inner_packet, view.frame.payload_len, &inner,
			&inner_ip_header_len, &inner_l4_header_len);
		if (ret)
			goto error;
		if (inner_offset > TRUSTIX_DATAPATH_PACKET_MAX_LEN) {
			ret = -EOVERFLOW;
			goto error;
		}
		view.inner = inner;
		view.inner_packet = inner_packet;
		view.tixt_len = view.frame.wire_len;
		view.inner_offset = inner_offset;
		view.inner_ip_header_len = inner_ip_header_len;
		view.inner_l4_header_len = inner_l4_header_len;
		ret = trustix_datapath_rx_stage_validate_batch(
			outer, &view, &validation_cache);
		if (ret)
			goto error;
		if (!trustix_datapath_rx_worker_payload_fits_target(
			    &view, target_dev)) {
			ret = -EOPNOTSUPP;
			goto error;
		}
		if (offset_copy) {
			pending[frames].source_skb = skb;
			pending[frames].source_offset = inner_offset;
		} else {
			pending[frames].source_packet = inner_packet;
		}
		pending[frames].len = view.frame.payload_len;
		pending[frames].tixt_flags = view.frame.flags;
		frames++;
		if (offset_copy)
			cursor_offset += view.frame.wire_len;
		else
			cursor += view.frame.wire_len;
		remaining -= view.frame.wire_len;
	}
	if (frames != expected_frames) {
		ret = -EIO;
		goto error;
	}
	if (frames > 1 &&
	    READ_ONCE(trustix_datapath_rx_worker_stream_coalesce_gso)) {
		ret = trustix_datapath_rx_worker_queue_stream_gso_from_pending(
			skb, target_dev, pending, frames, &queued);
		if (!ret) {
			if (queued_frames)
				*queued_frames = queued ?: frames;
			trustix_datapath_rx_worker_count_stream_batch(
				1, queued ?: frames);
			kfree(pending);
			dev_put(target_dev);
			return 0;
		}
		trustix_datapath_rx_worker_stream_coalesce_inline_queue_fallbacks++;
	}
	ret = trustix_datapath_rx_worker_materialize_pending_copies(
		target_dev, pending, frames);
	if (ret)
		goto error;
	ret = trustix_datapath_rx_worker_enqueue_pending_copies(
		skb, target_dev, pending, frames, &queued);
	if (ret || queued != frames)
		goto error;
	if (queued_frames)
		*queued_frames = queued;
	trustix_datapath_rx_worker_count_stream_batch(1, queued);
	WRITE_ONCE(trustix_datapath_rx_worker_last_push_ret, 0);
	kfree(pending);
	dev_put(target_dev);
	return 0;

error:
	trustix_datapath_rx_worker_free_pending_copies(pending, frames);
	kfree(pending);
	if (target_dev)
		dev_put(target_dev);
	trustix_datapath_rx_worker_stream_batch_errors++;
	WRITE_ONCE(trustix_datapath_rx_worker_last_push_ret, ret);
	return ret;
}

static int
trustix_datapath_rx_worker_push_stream_batch_copy(
	struct sk_buff *skb, const struct trustix_datapath_ioc_classify *outer,
	__u32 total_len, __u32 tixt_offset, unsigned int expected_frames,
	int target_ifindex, unsigned int *queued_frames, bool force_queue,
	bool offset_copy)
{
	return trustix_datapath_rx_worker_push_stream_batch_source(
		skb, outer, total_len, tixt_offset, expected_frames,
		target_ifindex, queued_frames, force_queue, offset_copy, NULL);
}

static bool
trustix_datapath_rx_worker_stream_inline_xmit_needs_batch(
	const struct sk_buff *skb, __u32 total_len)
{
	const struct skb_shared_info *shinfo;

	if (!skb || !total_len)
		return false;
	if (skb_is_gso(skb))
		return true;
	if (skb->len > total_len)
		return true;
	if (skb_headlen(skb) < total_len)
		return true;
	shinfo = skb_shinfo(skb);
	return shinfo->nr_frags || shinfo->frag_list;
}

static int
trustix_datapath_rx_worker_push_stream(
	struct sk_buff *skb, const struct trustix_datapath_ioc_classify *outer,
	__u8 ip_header_len, __u8 l4_header_len, int target_ifindex,
	unsigned int *queued_frames)
{
	struct trustix_datapath_rx_stage_view view = {};
	struct trustix_datapath_ioc_classify inner = {};
	const __u8 *network;
	const __u8 *cursor;
	const __u8 *inner_packet;
	__u8 inner_ip_header_len;
	__u8 inner_l4_header_len;
	__u32 total_len;
	__u32 tixt_offset;
	__u32 cursor_offset = 0;
	__u32 remaining;
	__u16 transport_len;
	unsigned int frames = 0;
	bool consumer_validates_frames;
	bool inline_xmit;
	bool inline_xmit_needs_batch = false;
	bool offset_copy;
	bool stream_batch_queue;
	bool worker_xmit;
	int network_offset;
	int ret;

	if (queued_frames)
		*queued_frames = 0;
	if (!READ_ONCE(trustix_datapath_rx_worker_stream_tcp))
		return -EOPNOTSUPP;
	if (!READ_ONCE(trustix_datapath_rx_worker_inject))
		return -EOPNOTSUPP;
	if (!skb || !outer)
		return -EINVAL;
	if (ip_header_len != 20)
		return -EPROTONOSUPPORT;
	network = skb_network_header(skb);
	if (!network)
		return -EINVAL;
	network_offset = skb_network_offset(skb);
	if (network_offset < 0 || (__u32)network_offset > skb->len)
		return -EOVERFLOW;
	total_len = trustix_datapath_get_be16(network + 2);
	if (total_len > skb->len - (__u32)network_offset)
		return -EMSGSIZE;
	switch (outer->protocol) {
	case IPPROTO_UDP:
		if (l4_header_len != 8)
			return -EPROTONOSUPPORT;
		transport_len = trustix_datapath_get_be16(network + 24);
		if (transport_len < 8 ||
		    (__u32)transport_len != total_len - ip_header_len)
			return -EMSGSIZE;
		tixt_offset = 28;
		break;
	case IPPROTO_TCP:
		if (l4_header_len != 20)
			return -EPROTONOSUPPORT;
		tixt_offset = 40;
		break;
	default:
		return -EPROTONOSUPPORT;
	}
	if (total_len < tixt_offset + TRUSTIX_DATAPATH_MIN_FRAME_HEADER_LEN)
		return -EPROTONOSUPPORT;
	inline_xmit_needs_batch =
		trustix_datapath_rx_worker_stream_inline_xmit_needs_batch(
			skb, total_len);
	inline_xmit = READ_ONCE(trustix_datapath_rx_worker_inline_xmit);
	worker_xmit = READ_ONCE(trustix_datapath_rx_worker_xmit);
	stream_batch_queue =
		READ_ONCE(trustix_datapath_rx_worker_stream_batch_queue);
	consumer_validates_frames =
		(inline_xmit && worker_xmit) || stream_batch_queue;
	offset_copy = consumer_validates_frames && skb_is_nonlinear(skb) &&
		      READ_ONCE(trustix_datapath_rx_worker_stream_offset_copy);
	if (!offset_copy &&
	    !pskb_may_pull(skb, (__u32)network_offset + total_len))
		return -ENODATA;

	network = skb_network_header(skb);
	if (offset_copy) {
		cursor = NULL;
		cursor_offset = (__u32)network_offset + tixt_offset;
	} else {
		cursor = network + tixt_offset;
	}
	remaining = total_len - tixt_offset;
	while (remaining) {
		if (frames >= TRUSTIX_DATAPATH_RX_WORKER_STREAM_MAX_FRAMES) {
			ret = -E2BIG;
			goto error;
		}
		memset(&view, 0, sizeof(view));
		if (offset_copy)
			ret = trustix_datapath_parse_tixt_skb_header(
				skb, cursor_offset, remaining, &view.frame);
		else
			ret = trustix_datapath_parse_tixt_header(
				cursor, remaining, &view.frame);
		if (ret)
			goto error;
		if (!(view.frame.flags &
		      TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4) ||
		    !view.frame.wire_len ||
		    view.frame.wire_len > remaining ||
		    !view.frame.payload_len ||
		    view.frame.payload_len > TRUSTIX_DATAPATH_PACKET_MAX_LEN) {
			ret = -EPROTONOSUPPORT;
			goto error;
		}
		if (!consumer_validates_frames) {
			inner_packet = cursor + view.frame.header_len;
			ret = trustix_datapath_parse_ipv4_packet(
				inner_packet, view.frame.payload_len, &inner,
				&inner_ip_header_len, &inner_l4_header_len);
			if (ret)
				goto error;
			if (inner_packet < skb->data ||
			    inner_packet - skb->data >
				    TRUSTIX_DATAPATH_PACKET_MAX_LEN) {
				ret = -EOVERFLOW;
				goto error;
			}

			view.inner = inner;
			view.inner_packet = inner_packet;
			view.tixt_len = view.frame.wire_len;
			view.inner_offset = (__u32)(inner_packet - skb->data);
			view.inner_ip_header_len = inner_ip_header_len;
			view.inner_l4_header_len = inner_l4_header_len;
			read_lock_bh(&trustix_datapath_state_lock);
			ret = trustix_datapath_rx_stage_validate_locked(outer,
								 &view);
			read_unlock_bh(&trustix_datapath_state_lock);
			if (ret)
				goto error;
		}
		frames++;
		if (offset_copy)
			cursor_offset += view.frame.wire_len;
		else
			cursor += view.frame.wire_len;
		remaining -= view.frame.wire_len;
	}
	if (!frames)
		return -ENODATA;
	if (inline_xmit && worker_xmit) {
		if (inline_xmit_needs_batch ||
		    (frames > 1 &&
		     READ_ONCE(trustix_datapath_rx_worker_stream_coalesce_gso))) {
			if (inline_xmit_needs_batch)
				trustix_datapath_rx_worker_stream_inline_batch_fallbacks++;
			ret = trustix_datapath_rx_worker_push_stream_batch_copy(
				skb, outer, total_len, tixt_offset, frames,
				target_ifindex, queued_frames, true,
				offset_copy);
			if (!ret)
				trustix_datapath_rx_worker_count_stream_packets(
					1, frames);
			return ret;
		}
		ret = trustix_datapath_rx_worker_inline_xmit_stream_copy(
			skb, outer, total_len, tixt_offset, frames,
			target_ifindex, queued_frames);
		if (!ret && queued_frames && *queued_frames) {
			trustix_datapath_rx_worker_count_stream_packets(1, *queued_frames);
		}
		return ret;
	}
	if (stream_batch_queue) {
		ret = trustix_datapath_rx_worker_push_stream_batch_copy(
			skb, outer, total_len, tixt_offset, frames,
			target_ifindex, queued_frames, false, offset_copy);
		if (!ret) {
			trustix_datapath_rx_worker_count_stream_packets(1, frames);
		}
		return ret;
	}

	if (offset_copy) {
		ret = -EOPNOTSUPP;
		goto error;
	}
	cursor = network + tixt_offset;
	remaining = total_len - tixt_offset;
	frames = 0;
	while (remaining) {
		memset(&view, 0, sizeof(view));
		ret = trustix_datapath_parse_tixt_header(cursor, remaining,
							 &view.frame);
		if (ret)
			goto error;
		if (!view.frame.wire_len || view.frame.wire_len > remaining ||
		    !view.frame.payload_len) {
			ret = -EMSGSIZE;
			goto error;
		}
		inner_packet = cursor + view.frame.header_len;
		ret = trustix_datapath_parse_ipv4_packet(
			inner_packet, view.frame.payload_len, &inner,
			&inner_ip_header_len, &inner_l4_header_len);
		if (ret)
			goto error;
		view.inner = inner;
		view.inner_packet = inner_packet;
		view.tixt_len = view.frame.wire_len;
		view.inner_offset = (__u32)(inner_packet - skb->data);
		view.inner_ip_header_len = inner_ip_header_len;
		view.inner_l4_header_len = inner_l4_header_len;
		ret = trustix_datapath_rx_worker_push_copy(skb, &view,
							   target_ifindex);
		if (ret) {
			trustix_datapath_rx_worker_stream_queue_errors++;
			goto error;
		}
		frames++;
		cursor += view.frame.wire_len;
		remaining -= view.frame.wire_len;
	}
	if (queued_frames)
		*queued_frames = frames;
	trustix_datapath_rx_worker_count_stream_packets(1, frames);
	WRITE_ONCE(trustix_datapath_rx_worker_last_push_ret, 0);
	return 0;

error:
	trustix_datapath_rx_worker_stream_errors++;
	WRITE_ONCE(trustix_datapath_rx_worker_last_push_ret, ret);
	return ret;
}

static int
trustix_datapath_rx_worker_inject_stolen_skb(
	struct trustix_datapath_rx_worker_slot *slot, bool inline_context)
{
	struct sk_buff *skb;
	__u32 end;
	int ret;
	int rx_ret;

	if (!slot || !slot->skb || !slot->target_dev || !slot->len)
		return -EINVAL;
	if (slot->target_dev->type != ARPHRD_ETHER)
		return -EPROTONOSUPPORT;
	skb = slot->skb;
	if (slot->inner_offset > skb->len ||
	    slot->len > skb->len - slot->inner_offset)
		return -EMSGSIZE;
	end = slot->inner_offset + slot->len;
	if (!pskb_may_pull(skb, end))
		return -ENODATA;
	skb_pull(skb, slot->inner_offset);
	skb_trim(skb, slot->len);
	skb_orphan(skb);
	skb_scrub_packet(skb, true);
	trustix_datapath_rx_worker_prepare_inner_skb(
		skb, slot->target_dev,
		READ_ONCE(trustix_datapath_rx_worker_xmit));
	ret = 0;
	if (READ_ONCE(trustix_datapath_rx_worker_xmit))
		ret = trustix_datapath_rx_worker_restore_inner_tcp_checksum_partial(
			skb, slot->tixt_flags);
	if (!ret && READ_ONCE(trustix_datapath_rx_worker_xmit))
		ret = trustix_datapath_rx_worker_fix_inner_checksums(skb);
	if (ret) {
		trustix_datapath_rx_worker_checksum_errors++;
		return ret;
	}
	if (skb_cow_head(skb, ETH_HLEN))
		return -ENOMEM;
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, (skb->data[0] & 0x0f) * 4);
	skb_push(skb, ETH_HLEN);
	skb_reset_mac_header(skb);
	skb_reset_mac_len(skb);
	trustix_datapath_rx_worker_fill_inner_eth(skb, slot->target_dev,
						  READ_ONCE(trustix_datapath_rx_worker_xmit));
	slot->skb = NULL;
	rx_ret = trustix_datapath_rx_worker_deliver_inner_skb(
		skb, slot->target_dev, inline_context);
	return rx_ret;
}

static int
trustix_datapath_rx_worker_inject_stolen_inline_target(
	struct sk_buff *skb, const struct trustix_datapath_rx_stage_view *view,
	struct net_device *target_dev)
{
	struct trustix_datapath_rx_worker_slot slot = {};
	int ret;

	if (!skb || !view || !target_dev)
		return -EINVAL;
	if (!READ_ONCE(trustix_datapath_rx_worker_inline_stolen))
		goto err_not_supported;
	if (!READ_ONCE(trustix_datapath_rx_worker_inject))
		goto err_not_supported;
	if (!view->frame.payload_len ||
	    view->frame.payload_len > TRUSTIX_DATAPATH_PACKET_MAX_LEN)
		goto err_msgsize;
	if (!trustix_datapath_rx_worker_can_steal_skb(skb, view))
		goto err_not_supported;
	if (!trustix_datapath_rx_worker_payload_fits_target(view,
							    target_dev)) {
		goto err_not_supported;
	}
	if (target_dev->type != ARPHRD_ETHER) {
		dev_put(target_dev);
		return -EPROTONOSUPPORT;
	}
	if (!trustix_datapath_rx_worker_dev_ready(target_dev)) {
		dev_put(target_dev);
		return -ENETDOWN;
	}

	slot.valid = true;
	slot.len = view->frame.payload_len;
	slot.inner_offset = view->inner_offset;
	slot.tixt_flags = view->frame.flags;
	slot.ifindex = skb->dev ? skb->dev->ifindex : 0;
	slot.target_ifindex = target_dev->ifindex;
	slot.target_dev = target_dev;
	slot.skb = skb;
	slot.stolen_skb = true;
	ret = trustix_datapath_rx_worker_inject_stolen_skb(&slot, true);
	if (!ret) {
		trustix_datapath_rx_worker_inline_injected++;
		trustix_datapath_rx_worker_count_injected(1);
		WRITE_ONCE(trustix_datapath_rx_worker_last_push_ret, 0);
	} else {
		trustix_datapath_rx_worker_inline_errors++;
		trustix_datapath_rx_worker_steal_errors++;
		if (!slot.skb) {
			trustix_datapath_rx_worker_dropped++;
			ret = 0;
		}
		WRITE_ONCE(trustix_datapath_rx_worker_last_push_ret, ret);
	}
	dev_put(target_dev);
	return ret;

err_msgsize:
	dev_put(target_dev);
	return -EMSGSIZE;

err_not_supported:
	dev_put(target_dev);
	return -EOPNOTSUPP;
}

static bool trustix_datapath_rx_worker_has_pending(void)
{
	unsigned long irqflags;
	bool pending;

	spin_lock_irqsave(&trustix_datapath_rx_worker_lock, irqflags);
	pending = trustix_datapath_rx_worker_ring &&
		  trustix_datapath_rx_worker_capacity &&
		  trustix_datapath_rx_worker_count;
	spin_unlock_irqrestore(&trustix_datapath_rx_worker_lock, irqflags);
	return pending;
}

static const __u8 *trustix_datapath_rx_worker_slot_packet(
	const struct trustix_datapath_rx_worker_slot *slot, __u32 *len)
{
	if (len)
		*len = 0;
	if (!slot || !slot->valid || !slot->len || slot->stolen_skb)
		return NULL;
	if (slot->packet) {
		if (len)
			*len = slot->len;
		return slot->packet;
	}
	if (slot->skb && !slot->skb_l2_ready && !skb_is_gso(slot->skb) &&
	    slot->skb->len >= slot->len &&
	    skb_headlen(slot->skb) >= slot->len) {
		if (len)
			*len = slot->len;
		return slot->skb->data;
	}
	return NULL;
}

static void trustix_datapath_rx_worker_deliver_normal_slot(
	struct trustix_datapath_rx_worker_slot *slot)
{
	struct sk_buff *inner_skb;
	unsigned int frames;
	int ret;

	if (!slot)
		return;
	if (!slot->valid || !slot->target_dev || !slot->len ||
	    (!slot->packet && !slot->skb)) {
		trustix_datapath_rx_worker_release_slot(slot);
		trustix_datapath_rx_worker_dropped++;
		return;
	}
	frames = slot->frames ?: 1;
	if (slot->target_dev->type != ARPHRD_ETHER) {
		trustix_datapath_rx_worker_dropped += frames;
		trustix_datapath_rx_worker_release_slot(slot);
		return;
	}
	if (slot->skb_l2_ready) {
		inner_skb = slot->skb;
		slot->skb = NULL;
		if (trustix_datapath_rx_worker_deliver_inner_skb(
			    inner_skb, slot->target_dev, false) == 0)
			trustix_datapath_rx_worker_count_injected(frames);
		else
			trustix_datapath_rx_worker_dropped += frames;
		trustix_datapath_rx_worker_release_slot(slot);
		return;
	}
	if (slot->skb) {
		inner_skb = slot->skb;
		slot->skb = NULL;
	} else {
		inner_skb = trustix_datapath_rx_worker_build_inner_skb(
			slot->target_dev, slot->packet, slot->len);
		if (!inner_skb) {
			trustix_datapath_rx_worker_dropped++;
			trustix_datapath_rx_worker_release_slot(slot);
			return;
		}
	}
	trustix_datapath_rx_worker_prepare_inner_skb(
		inner_skb, slot->target_dev,
		READ_ONCE(trustix_datapath_rx_worker_xmit));
	if (READ_ONCE(trustix_datapath_rx_worker_xmit))
		ret = trustix_datapath_rx_worker_restore_inner_tcp_checksum_partial(
			inner_skb, slot->tixt_flags);
	else
		ret = 0;
	if (!ret && READ_ONCE(trustix_datapath_rx_worker_xmit))
		ret = trustix_datapath_rx_worker_fix_inner_checksums(inner_skb);
	if (ret) {
		kfree_skb(inner_skb);
		trustix_datapath_rx_worker_checksum_errors++;
		trustix_datapath_rx_worker_dropped++;
		trustix_datapath_rx_worker_release_slot(slot);
		return;
	}
	skb_reset_network_header(inner_skb);
	skb_set_transport_header(inner_skb,
				 (inner_skb->data[0] & 0x0f) * 4);
	if (skb_cow_head(inner_skb, ETH_HLEN)) {
		kfree_skb(inner_skb);
		trustix_datapath_rx_worker_dropped++;
		trustix_datapath_rx_worker_release_slot(slot);
		return;
	}
	skb_push(inner_skb, ETH_HLEN);
	skb_reset_mac_header(inner_skb);
	skb_set_network_header(inner_skb, ETH_HLEN);
	skb_set_transport_header(inner_skb,
				 ETH_HLEN + (inner_skb->data[ETH_HLEN] & 0x0f) * 4);
	inner_skb->mac_len = ETH_HLEN;
	trustix_datapath_rx_worker_fill_inner_eth(
		inner_skb, slot->target_dev,
		READ_ONCE(trustix_datapath_rx_worker_xmit));
	if (trustix_datapath_rx_worker_deliver_inner_skb(
		    inner_skb, slot->target_dev, false) == 0)
		trustix_datapath_rx_worker_count_injected(frames);
	else
		trustix_datapath_rx_worker_dropped += frames;
	trustix_datapath_rx_worker_release_slot(slot);
}

static bool trustix_datapath_rx_worker_try_drain_coalesced(
	struct trustix_datapath_rx_worker_slot *first, unsigned int max_frames,
	unsigned int *processed_extra)
{
	struct trustix_datapath_rx_worker_pending_copy *pending = NULL;
	struct trustix_datapath_rx_worker_coalesce_state coalesce = {};
	struct trustix_datapath_rx_worker_slot *slots;
	struct sk_buff *coalesced_skb = NULL;
	struct net_device *target_dev = NULL;
	unsigned long irqflags;
	const __u8 *packet;
	unsigned int frames = 0;
	unsigned int i;
	__u32 len = 0;
	bool handled = false;
	bool have_second = false;
	int ret;

	if (processed_extra)
		*processed_extra = 0;
	if (!READ_ONCE(trustix_datapath_rx_worker_xmit) ||
	    !READ_ONCE(trustix_datapath_rx_worker_stream_coalesce_gso) ||
	    !first || !first->valid || first->stolen_skb ||
	    !first->target_dev || first->target_dev->type != ARPHRD_ETHER ||
	    max_frames < 2)
		return false;

	packet = trustix_datapath_rx_worker_slot_packet(first, &len);
	if (!packet || trustix_datapath_rx_worker_coalesce_accept(
			       &coalesce, packet, len))
		return false;

	if (max_frames > TRUSTIX_DATAPATH_RX_WORKER_STREAM_MAX_FRAMES)
		max_frames = TRUSTIX_DATAPATH_RX_WORKER_STREAM_MAX_FRAMES;
	if (max_frames >
	    READ_ONCE(trustix_datapath_rx_worker_coalesce_scratch_capacity))
		max_frames = READ_ONCE(
			trustix_datapath_rx_worker_coalesce_scratch_capacity);
	if (max_frames < 2)
		return false;
	slots = READ_ONCE(trustix_datapath_rx_worker_coalesce_slots);
	pending = READ_ONCE(trustix_datapath_rx_worker_coalesce_pending);
	if (!slots || !pending)
		return false;
	memset(slots, 0, max_frames * sizeof(*slots));
	memset(pending, 0, max_frames * sizeof(*pending));

	spin_lock_irqsave(&trustix_datapath_rx_worker_lock, irqflags);
	if (trustix_datapath_rx_worker_count &&
	    trustix_datapath_rx_worker_ring &&
	    trustix_datapath_rx_worker_capacity) {
		struct trustix_datapath_rx_worker_coalesce_state probe =
			coalesce;
		struct trustix_datapath_rx_worker_slot *candidate;
		const __u8 *candidate_packet;
		__u32 candidate_len = 0;

		candidate = &trustix_datapath_rx_worker_ring
				     [trustix_datapath_rx_worker_head];
		candidate_packet =
			(candidate->valid && !candidate->stolen_skb &&
			 candidate->target_dev == first->target_dev &&
			 candidate->target_ifindex == first->target_ifindex) ?
				trustix_datapath_rx_worker_slot_packet(
					candidate, &candidate_len) :
				NULL;
		if (candidate_packet &&
		    !trustix_datapath_rx_worker_coalesce_accept(
			    &probe, candidate_packet, candidate_len))
			have_second = true;
	}
	spin_unlock_irqrestore(&trustix_datapath_rx_worker_lock, irqflags);
	if (!have_second)
		return false;

	slots[0] = *first;
	memset(first, 0, sizeof(*first));
	pending[0].source_packet = packet;
	pending[0].len = len;
	pending[0].tixt_flags = slots[0].tixt_flags;
	frames = 1;

	spin_lock_irqsave(&trustix_datapath_rx_worker_lock, irqflags);
	while (frames < max_frames && trustix_datapath_rx_worker_count &&
	       trustix_datapath_rx_worker_ring &&
	       trustix_datapath_rx_worker_capacity) {
		struct trustix_datapath_rx_worker_slot *candidate;
		__u32 candidate_len = 0;
		const __u8 *candidate_packet;

		candidate = &trustix_datapath_rx_worker_ring
				     [trustix_datapath_rx_worker_head];
		if (!candidate->valid || candidate->stolen_skb ||
		    candidate->target_dev != slots[0].target_dev ||
		    candidate->target_ifindex != slots[0].target_ifindex)
			break;
		candidate_packet = trustix_datapath_rx_worker_slot_packet(
			candidate, &candidate_len);
		if (!candidate_packet ||
		    trustix_datapath_rx_worker_coalesce_accept(
			    &coalesce, candidate_packet, candidate_len))
			break;
		slots[frames] = *candidate;
		memset(candidate, 0, sizeof(*candidate));
		pending[frames].source_packet = candidate_packet;
		pending[frames].len = candidate_len;
		pending[frames].tixt_flags = slots[frames].tixt_flags;
		trustix_datapath_rx_worker_head =
			(trustix_datapath_rx_worker_head + 1) %
			trustix_datapath_rx_worker_capacity;
		if (trustix_datapath_rx_worker_count)
			trustix_datapath_rx_worker_count--;
		frames++;
	}
	spin_unlock_irqrestore(&trustix_datapath_rx_worker_lock, irqflags);

	if (frames < 2) {
		*first = slots[0];
		memset(&slots[0], 0, sizeof(slots[0]));
		goto out;
	}

	coalesced_skb = trustix_datapath_rx_worker_build_coalesced_gso_skb(
		slots[0].target_dev, &coalesce, pending, frames, true);
	if (!coalesced_skb) {
		trustix_datapath_rx_worker_stream_coalesce_errors++;
		for (i = 0; i < frames; i++)
			trustix_datapath_rx_worker_deliver_normal_slot(&slots[i]);
		handled = true;
		goto out;
	}

	target_dev = slots[0].target_dev;
	dev_hold(target_dev);
	for (i = 0; i < frames; i++)
		trustix_datapath_rx_worker_release_slot(&slots[i]);

	ret = trustix_datapath_rx_worker_xmit_coalesced_inner_skb(
		coalesced_skb, target_dev, false, frames, NULL);
	coalesced_skb = NULL;
	if (!ret) {
		trustix_datapath_rx_worker_count_injected(frames);
		trustix_datapath_rx_worker_count_stream_coalesce(1, frames);
	} else {
		trustix_datapath_rx_worker_dropped += frames;
	}
	dev_put(target_dev);
	handled = true;

out:
	if (processed_extra && handled && frames > 1)
		*processed_extra = frames - 1;
	memset(pending, 0, max_frames * sizeof(*pending));
	memset(slots, 0, max_frames * sizeof(*slots));
	return handled;
}

static void trustix_datapath_rx_worker_run(struct work_struct *work)
{
	struct trustix_datapath_rx_worker_slot slot = {};
	unsigned long irqflags;
	unsigned int budget;
	unsigned int processed = 0;

	trustix_datapath_rx_worker_runs++;
	budget = READ_ONCE(trustix_datapath_rx_worker_budget);
	if (!budget)
		budget = TRUSTIX_DATAPATH_RX_WORKER_DEFAULT_BUDGET;

	for (;;) {
		if (processed >= budget) {
			if (trustix_datapath_rx_worker_has_pending())
				trustix_datapath_rx_worker_kick();
			cond_resched();
			return;
		}
		memset(&slot, 0, sizeof(slot));
		spin_lock_irqsave(&trustix_datapath_rx_worker_lock, irqflags);
		if (!trustix_datapath_rx_worker_count ||
		    !trustix_datapath_rx_worker_ring ||
		    !trustix_datapath_rx_worker_capacity) {
			spin_unlock_irqrestore(&trustix_datapath_rx_worker_lock,
					       irqflags);
			return;
		}
		slot = trustix_datapath_rx_worker_ring
			       [trustix_datapath_rx_worker_head];
		memset(&trustix_datapath_rx_worker_ring
			       [trustix_datapath_rx_worker_head],
		       0, sizeof(trustix_datapath_rx_worker_ring
					[trustix_datapath_rx_worker_head]));
		trustix_datapath_rx_worker_head =
			(trustix_datapath_rx_worker_head + 1) %
			trustix_datapath_rx_worker_capacity;
		if (trustix_datapath_rx_worker_count)
			trustix_datapath_rx_worker_count--;
		spin_unlock_irqrestore(&trustix_datapath_rx_worker_lock,
				       irqflags);
		processed++;
		trustix_datapath_rx_worker_run_processed++;

		if (slot.stolen_skb) {
			if (slot.valid && slot.target_dev && slot.skb &&
			    slot.len &&
			    trustix_datapath_rx_worker_inject_stolen_skb(
				    &slot, false) == 0) {
				trustix_datapath_rx_worker_count_injected(1);
			} else {
				trustix_datapath_rx_worker_dropped++;
				trustix_datapath_rx_worker_steal_errors++;
			}
			trustix_datapath_rx_worker_release_slot(&slot);
			continue;
		}

		if (READ_ONCE(trustix_datapath_rx_worker_stream_coalesce_gso)) {
			unsigned int processed_extra = 0;
			unsigned int max_frames = budget - processed + 1;

			if (trustix_datapath_rx_worker_try_drain_coalesced(
				    &slot, max_frames, &processed_extra)) {
				processed += processed_extra;
				continue;
			}
		}
		trustix_datapath_rx_worker_deliver_normal_slot(&slot);
	}
}

static int
trustix_datapath_secure_rx_preprocess_skb(
	struct sk_buff *skb,
	const struct trustix_datapath_ioc_classify *outer,
	__u8 ip_header_len, __u8 l4_header_len, int target_ifindex,
	bool *claimed, unsigned int *opened_frames)
{
	struct trustix_datapath_rx_crypto_plan plan = {};
	struct trustix_datapath_tixt_frame frame = {};
	struct trustix_datapath_secure_rx_scratch *scratch = NULL;
	struct trustix_aead_direct_open_replay_op *open_op;
	struct iphdr *iph;
	__u8 *network;
	__u8 *source;
	__u8 *destination;
	__u8 *secure_header;
	__u8 *ciphertext;
	__u32 source_offset;
	__u32 destination_offset;
	__u32 remaining;
	__u32 total_len;
	__u32 cipher_len;
	__u32 plain_len;
	__u64 opened_bytes = 0;
	unsigned int frames = 0;
	unsigned int queued_frames = 0;
	int network_offset;
	bool plan_valid = false;
	enum trustix_datapath_secure_rx_error_stage error_stage =
		TRUSTIX_DATAPATH_SECURE_RX_ERROR_NONE;
	int ret;

	if (claimed)
		*claimed = false;
	if (opened_frames)
		*opened_frames = 0;
	if (!skb || !outer || !claimed || !opened_frames)
		return -EINVAL;
	if (!(READ_ONCE(trustix_datapath_features) &
	      TRUSTIX_DATAPATH_FEATURE_SECURE_TIX_TCP_FULL_DATAPATH) ||
	    outer->protocol != IPPROTO_TCP || ip_header_len != 20 ||
	    l4_header_len != 20 ||
	    !trustix_datapath_crypto_open_replay_batch)
		return -EOPNOTSUPP;

	network_offset = skb_network_offset(skb);
	if (network_offset < 0 || (__u32)network_offset > skb->len)
		return -EOVERFLOW;
	if (!pskb_may_pull(skb, (__u32)network_offset + 40 +
				 TRUSTIX_DATAPATH_TIXT_HEADER_LEN))
		return -ENODATA;
	network = skb_network_header(skb);
	if (!network)
		return -EINVAL;
	total_len = trustix_datapath_get_be16(network + 2);
	if (total_len < 40 + TRUSTIX_DATAPATH_TIXT_HEADER_LEN ||
	    total_len > skb->len - (__u32)network_offset)
		return -EMSGSIZE;
	source = network + 40;
	if (!(source[5] & TRUSTIX_DATAPATH_TIXT_FLAG_ENCRYPTED))
		return -EOPNOTSUPP;
	*claimed = true;
	if (trustix_datapath_get_be32(source) != TRUSTIX_DATAPATH_TIXT_MAGIC) {
		error_stage = TRUSTIX_DATAPATH_SECURE_RX_ERROR_FRAME_VALIDATE;
		ret = -EPROTONOSUPPORT;
		goto error;
	}
	if (skb_is_gso(skb))
		trustix_datapath_secure_rx_gso_packets++;
	if (skb_is_nonlinear(skb))
		trustix_datapath_secure_rx_nonlinear_packets++;
	if (skb_cloned(skb))
		trustix_datapath_secure_rx_cloned_packets++;
	/* A process-context receive must not race same-CPU softirq scratch use. */
	local_bh_disable();
	scratch = get_cpu_ptr(trustix_datapath_secure_rx_scratch);
	if (!scratch->packet) {
		error_stage = TRUSTIX_DATAPATH_SECURE_RX_ERROR_COPY;
		ret = -ENOMEM;
		goto error;
	}
	ret = skb_copy_bits(skb, (__u32)network_offset, scratch->packet,
			    total_len);
	if (ret) {
		error_stage = TRUSTIX_DATAPATH_SECURE_RX_ERROR_COPY;
		goto error;
	}
	network = scratch->packet;

	source_offset = 40;
	destination_offset = 40;
	remaining = total_len - source_offset;
	while (remaining) {
		if (frames >= TRUSTIX_DATAPATH_RX_WORKER_STREAM_MAX_FRAMES) {
			error_stage = TRUSTIX_DATAPATH_SECURE_RX_ERROR_FRAME_LIMIT;
			ret = -E2BIG;
			goto error;
		}
		memset(&frame, 0, sizeof(frame));
		source = network + source_offset;
		ret = trustix_datapath_parse_tixt_header(
			source, remaining, &frame);
		if (ret) {
			error_stage = TRUSTIX_DATAPATH_SECURE_RX_ERROR_FRAME_PARSE;
			goto error;
		}
		if (frame.header_len != TRUSTIX_DATAPATH_TIXT_HEADER_LEN ||
		    (frame.flags &
		     ~TRUSTIX_DATAPATH_TIXT_FLAG_INNER_TCP_CHECKSUM_PARTIAL) !=
			    (TRUSTIX_DATAPATH_TIXT_FLAG_ENCRYPTED |
			     TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4) ||
		    frame.fragment_index || frame.fragment_count ||
		    !frame.wire_len || frame.wire_len > remaining ||
		    frame.payload_len < TRUSTIX_DATAPATH_SECURE_OVERHEAD) {
			error_stage = TRUSTIX_DATAPATH_SECURE_RX_ERROR_FRAME_VALIDATE;
			ret = -EBADMSG;
			goto error;
		}

		if (!plan_valid) {
			read_lock_bh(&trustix_datapath_state_lock);
			ret = trustix_datapath_rx_crypto_plan_locked(
				outer, &frame, &plan);
			read_unlock_bh(&trustix_datapath_state_lock);
			if (ret) {
				error_stage = TRUSTIX_DATAPATH_SECURE_RX_ERROR_PLAN;
				goto error;
			}
			plan_valid = true;
		} else if (plan.flow_id != frame.flow_id ||
			   plan.epoch != frame.epoch) {
			error_stage = TRUSTIX_DATAPATH_SECURE_RX_ERROR_PLAN;
			ret = -EPROTO;
			goto error;
		}
		if ((frame.flags &
		     TRUSTIX_DATAPATH_TIXT_FLAG_INNER_TCP_CHECKSUM_PARTIAL) &&
		    (!(plan.session_flags &
		       TRUSTIX_DATAPATH_SESSION_FLAG_RECEIVE_SECURE_INNER_TCP_CHECKSUM_PARTIAL) ||
		     !(READ_ONCE(trustix_datapath_features) &
		       TRUSTIX_DATAPATH_FEATURE_SECURE_INNER_TCP_CHECKSUM_PARTIAL))) {
			error_stage = TRUSTIX_DATAPATH_SECURE_RX_ERROR_PLAN;
			ret = -EPROTONOSUPPORT;
			goto error;
		}

		secure_header = source + frame.header_len;
		ret = trustix_datapath_secure_validate_header(
			secure_header, plan.suite, plan.epoch, frame.sequence);
		if (ret) {
			error_stage = TRUSTIX_DATAPATH_SECURE_RX_ERROR_HEADER;
			goto error;
		}
		ciphertext = secure_header + TRUSTIX_DATAPATH_SECURE_HEADER_LEN;
		cipher_len = frame.payload_len -
			     TRUSTIX_DATAPATH_SECURE_HEADER_LEN;
		plain_len = cipher_len - TRUSTIX_DATAPATH_SECURE_TAG_LEN;
		if (!plain_len || plain_len > TRUSTIX_DATAPATH_PACKET_MAX_LEN ||
		    opened_bytes > U64_MAX - plain_len) {
			error_stage = TRUSTIX_DATAPATH_SECURE_RX_ERROR_FRAME_VALIDATE;
			ret = -EMSGSIZE;
			goto error;
		}
		open_op = &scratch->ops[frames];
		open_op->src = ciphertext;
		open_op->dst = ciphertext;
		open_op->cipher_len = cipher_len;
		open_op->sequence = frame.sequence;
		trustix_datapath_secure_prepare_nonce(
			open_op->nonce, plan.receive_iv, frame.sequence);

		source_offset += frame.wire_len;
		destination_offset += TRUSTIX_DATAPATH_TIXT_HEADER_LEN +
				      plain_len;
		remaining -= frame.wire_len;
		opened_bytes += plain_len;
		frames++;
	}
	if (!frames || source_offset != total_len ||
	    destination_offset >= source_offset) {
		error_stage = TRUSTIX_DATAPATH_SECURE_RX_ERROR_LAYOUT;
		ret = -EBADMSG;
		goto error;
	}
	ret = trustix_datapath_crypto_open_replay_batch(
		plan.receive_slot, plan.receive_generation, scratch->ops, frames,
		plan.replay_floor, plan.replay_window);
	if (ret == -ENOENT)
		ret = -ESTALE;
	if (ret) {
		error_stage = TRUSTIX_DATAPATH_SECURE_RX_ERROR_CRYPTO;
		goto error;
	}

	source_offset = 40;
	destination_offset = 40;
	remaining = total_len - source_offset;
	while (remaining) {
		memset(&frame, 0, sizeof(frame));
		source = network + source_offset;
		ret = trustix_datapath_parse_tixt_header(
			source, remaining, &frame);
		if (ret) {
			error_stage = TRUSTIX_DATAPATH_SECURE_RX_ERROR_FRAME_PARSE;
			goto error;
		}
		secure_header = source + frame.header_len;
		ciphertext = secure_header + TRUSTIX_DATAPATH_SECURE_HEADER_LEN;
		cipher_len = frame.payload_len -
			     TRUSTIX_DATAPATH_SECURE_HEADER_LEN;
		plain_len = cipher_len - TRUSTIX_DATAPATH_SECURE_TAG_LEN;
		ret = trustix_datapath_secure_validate_inner_tcp_checksum(
			ciphertext, plain_len,
			frame.flags &
				TRUSTIX_DATAPATH_TIXT_FLAG_INNER_TCP_CHECKSUM_PARTIAL);
		if (ret) {
			trustix_datapath_secure_rx_inner_tcp_checksum_errors++;
			error_stage = TRUSTIX_DATAPATH_SECURE_RX_ERROR_CHECKSUM;
			goto error;
		}
		if (frame.flags &
		    TRUSTIX_DATAPATH_TIXT_FLAG_INNER_TCP_CHECKSUM_PARTIAL)
			trustix_datapath_secure_rx_inner_tcp_checksum_partial++;
		else if (plain_len >= sizeof(struct iphdr) &&
			 ciphertext[0] >> 4 == 4 &&
			 ciphertext[9] == IPPROTO_TCP)
			trustix_datapath_secure_rx_inner_tcp_checksum_full++;
		destination = network + destination_offset;
		memmove(destination + TRUSTIX_DATAPATH_TIXT_HEADER_LEN,
			ciphertext, plain_len);
		trustix_datapath_build_tixt_header(
			destination,
			TRUSTIX_DATAPATH_TIXT_FLAG_KERNEL_OPENED |
				TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4 |
				(frame.flags &
				 TRUSTIX_DATAPATH_TIXT_FLAG_INNER_TCP_CHECKSUM_PARTIAL),
			frame.flow_id, frame.epoch, frame.sequence, plain_len,
			0, 0);
		source_offset += frame.wire_len;
		destination_offset += TRUSTIX_DATAPATH_TIXT_HEADER_LEN +
				      plain_len;
		remaining -= frame.wire_len;
	}
	if (destination_offset > TRUSTIX_DATAPATH_PACKET_MAX_LEN) {
		error_stage = TRUSTIX_DATAPATH_SECURE_RX_ERROR_LAYOUT;
		ret = -EOVERFLOW;
		goto error;
	}

	iph = (struct iphdr *)network;
	iph->tot_len = htons((__u16)destination_offset);
	trustix_datapath_rx_worker_fix_ipv4_header_checksum(
		iph, ip_header_len);
	ret = trustix_datapath_rx_worker_push_stream_batch_source(
		skb, outer, destination_offset, 40, frames, target_ifindex,
		&queued_frames, true, false, network);
	if (ret || queued_frames != frames) {
		error_stage = TRUSTIX_DATAPATH_SECURE_RX_ERROR_DELIVERY;
		if (!ret)
			ret = -EIO;
		goto error;
	}
	put_cpu_ptr(scratch);
	scratch = NULL;
	local_bh_enable();
	trustix_datapath_secure_rx_packets++;
	trustix_datapath_secure_rx_frames += frames;
	trustix_datapath_secure_rx_bytes += opened_bytes;
	if (frames > READ_ONCE(trustix_datapath_secure_rx_max_frames))
		WRITE_ONCE(trustix_datapath_secure_rx_max_frames, frames);
	*opened_frames = queued_frames;
	return 0;

error:
	if (scratch) {
		put_cpu_ptr(scratch);
		local_bh_enable();
	}
	trustix_datapath_secure_rx_record_error(error_stage, ret);
	if (ret == -ESTALE)
		trustix_datapath_secure_rx_stale++;
	else
		trustix_datapath_secure_rx_errors++;
	return ret ?: -EIO;
}

static int
trustix_datapath_rx_prepare_skb(struct sk_buff *skb,
				const struct trustix_datapath_ioc_classify *classify,
				__u8 ip_header_len, __u8 l4_header_len,
				struct trustix_datapath_rx_stage_view *view)
{
	int ret;

	if (!view)
		return -EINVAL;
	ret = trustix_datapath_rx_stage_parse_skb(
		skb, classify, ip_header_len, l4_header_len, view);
	if (ret)
		return ret;
	read_lock_bh(&trustix_datapath_state_lock);
	ret = trustix_datapath_rx_stage_validate_locked(classify, view);
	read_unlock_bh(&trustix_datapath_state_lock);
	return ret;
}

static void
trustix_datapath_rx_stage_fill_metadata(
	struct trustix_datapath_ioc_rx_stage *request,
	const struct trustix_datapath_rx_stage_slot *slot)
{
	request->id = slot->id;
	request->flow_id = slot->flow_id;
	request->epoch = slot->epoch;
	request->sequence = slot->sequence;
	request->payload_len = slot->payload_len;
	request->tixt_flags = slot->tixt_flags;
	request->session_flags = slot->session_flags;
	request->outer_src_ipv4 = slot->outer_src_ipv4;
	request->outer_dst_ipv4 = slot->outer_dst_ipv4;
	request->outer_src_port = slot->outer_src_port;
	request->outer_dst_port = slot->outer_dst_port;
	request->outer_protocol = slot->outer_protocol;
	request->inner_protocol = slot->inner_protocol;
	request->inner_src_ipv4 = slot->inner_src_ipv4;
	request->inner_dst_ipv4 = slot->inner_dst_ipv4;
	request->inner_src_port = slot->inner_src_port;
	request->inner_dst_port = slot->inner_dst_port;
	request->inner_ip_header_len = slot->inner_ip_header_len;
	request->inner_l4_header_len = slot->inner_l4_header_len;
}

static void
trustix_datapath_rx_stage_fill_status(
	struct trustix_datapath_ioc_rx_stage *request)
{
	request->queue_len = trustix_datapath_rx_stage_count;
	request->capacity = trustix_datapath_rx_stage_capacity;
	request->slot_len = TRUSTIX_DATAPATH_PACKET_MAX_LEN;
	request->staged = trustix_datapath_rx_stage_staged;
	request->popped = trustix_datapath_rx_stage_popped;
	request->dropped = trustix_datapath_rx_stage_dropped;
	request->overwritten = trustix_datapath_rx_stage_overwritten;
}

static int
trustix_datapath_rx_stage_apply(struct trustix_datapath_ioc_rx_stage *request,
				__u8 *out)
{
	struct trustix_datapath_rx_stage_slot slot_copy = {};
	__u32 index;
	__u32 len;
	bool have_slot = false;
	bool pop = false;
	int ret = 0;
	unsigned long irqflags;

	if (!request)
		return -EINVAL;
	spin_lock_irqsave(&trustix_datapath_rx_stage_lock, irqflags);
	switch (request->op) {
	case TRUSTIX_DATAPATH_RX_STAGE_OP_QUERY:
		trustix_datapath_rx_stage_fill_status(request);
		break;
	case TRUSTIX_DATAPATH_RX_STAGE_OP_PEEK:
	case TRUSTIX_DATAPATH_RX_STAGE_OP_POP:
		pop = request->op == TRUSTIX_DATAPATH_RX_STAGE_OP_POP;
		if (!trustix_datapath_rx_stage_count ||
		    !trustix_datapath_rx_stage_ring ||
		    !trustix_datapath_rx_stage_data ||
		    !trustix_datapath_rx_stage_capacity) {
			ret = -ENOENT;
			trustix_datapath_rx_stage_fill_status(request);
			break;
		}
		index = trustix_datapath_rx_stage_head;
		slot_copy = trustix_datapath_rx_stage_ring[index];
		if (!slot_copy.valid) {
			ret = -ENOENT;
			trustix_datapath_rx_stage_fill_status(request);
			break;
		}
		len = slot_copy.len;
		if (!out || request->out_len < len) {
			request->written_len = len;
			trustix_datapath_rx_stage_fill_metadata(request,
							       &slot_copy);
			trustix_datapath_rx_stage_fill_status(request);
			ret = -ENOSPC;
			break;
		}
		memcpy(out,
		       trustix_datapath_rx_stage_data +
			       (index * TRUSTIX_DATAPATH_PACKET_MAX_LEN),
		       len);
		request->written_len = len;
		trustix_datapath_rx_stage_fill_metadata(request, &slot_copy);
		have_slot = true;
		if (pop) {
			memset(&trustix_datapath_rx_stage_ring[index], 0,
			       sizeof(trustix_datapath_rx_stage_ring[index]));
			trustix_datapath_rx_stage_head =
				(trustix_datapath_rx_stage_head + 1) %
				trustix_datapath_rx_stage_capacity;
			if (trustix_datapath_rx_stage_count)
				trustix_datapath_rx_stage_count--;
			trustix_datapath_rx_stage_popped++;
		}
		trustix_datapath_rx_stage_fill_status(request);
		break;
	case TRUSTIX_DATAPATH_RX_STAGE_OP_CLEAR:
		if (trustix_datapath_rx_stage_ring &&
		    trustix_datapath_rx_stage_capacity) {
			memset(trustix_datapath_rx_stage_ring, 0,
			       array_size(trustix_datapath_rx_stage_capacity,
					  sizeof(*trustix_datapath_rx_stage_ring)));
		}
		trustix_datapath_rx_stage_head = 0;
		trustix_datapath_rx_stage_tail = 0;
		trustix_datapath_rx_stage_count = 0;
		trustix_datapath_rx_stage_fill_status(request);
		break;
	default:
		ret = -EINVAL;
		break;
	}
	spin_unlock_irqrestore(&trustix_datapath_rx_stage_lock, irqflags);
	if (have_slot && !request->written_len)
		ret = -EIO;
	return ret;
}

static bool trustix_datapath_tix_tcp_synthetic_marker(
	const struct sk_buff *skb,
	const struct trustix_datapath_ioc_classify *classify,
	__u8 ip_header_len, __u8 l4_header_len)
{
	const struct tcphdr *tcph;
	const __u8 *network;
	__u32 total_len;

	if (!skb || !classify || classify->protocol != IPPROTO_TCP ||
	    ip_header_len != sizeof(struct iphdr) ||
	    l4_header_len != sizeof(struct tcphdr))
		return false;
	network = skb_network_header(skb);
	if (!network)
		return false;
	total_len = trustix_datapath_get_be16(network + 2);
	if (total_len <= ip_header_len + l4_header_len)
		return false;
	tcph = (const struct tcphdr *)(network + ip_header_len);
	return tcph->ack && !tcph->syn && !tcph->fin && !tcph->rst &&
	       tcph->ack_seq == 0;
}

static bool trustix_datapath_claim_plaintext_tix_tcp_skb(
	struct sk_buff *skb,
	const struct trustix_datapath_ioc_classify *classify,
	__u8 ip_header_len, __u8 l4_header_len, bool frame_magic,
	__u32 *session_flags, bool *continuation, __u8 *shard_out,
	__u64 *flow_id_out, __u64 *epoch_out)
{
	struct trustix_datapath_state_slot *session;
	struct trustix_datapath_state_slot *wire;
	bool marker;
	bool reverse = false;
	bool matched_reverse = false;
	bool claimed = false;
	__u8 shard = 0;

	if (session_flags)
		*session_flags = 0;
	if (continuation)
		*continuation = false;
	if (shard_out)
		*shard_out = 0;
	if (flow_id_out)
		*flow_id_out = 0;
	if (epoch_out)
		*epoch_out = 0;
	if (!skb || !classify || classify->protocol != IPPROTO_TCP ||
	    ip_header_len != sizeof(struct iphdr) ||
	    l4_header_len != sizeof(struct tcphdr) ||
	    ntohs(ip_hdr(skb)->tot_len) <= ip_header_len + l4_header_len)
		return false;
	marker = trustix_datapath_tix_tcp_synthetic_marker(
		skb, classify, ip_header_len, l4_header_len);

	read_lock_bh(&trustix_datapath_state_lock);
	wire = trustix_datapath_session_wire_for_tuple_any_flow_locked(
		classify->src_ipv4, classify->dst_ipv4,
		classify->src_port, classify->dst_port, IPPROTO_TCP,
		&reverse);
	if (!wire || !reverse)
		goto out;
	session = trustix_datapath_session_for_flow_id_locked(wire->value[0]);
	if (!session || !(session->flags &
			 TRUSTIX_DATAPATH_SESSION_FLAG_KERNEL_FLOW) ||
	    !trustix_datapath_session_wire_tuple_matches_locked(
		    wire, session, classify->src_ipv4, classify->dst_ipv4,
		    classify->src_port, classify->dst_port,
		    &matched_reverse, &shard) || !matched_reverse)
		goto out;

	/* New senders reserve shard zero for the real control connection. */
	claimed = shard || marker || frame_magic;
	if (!claimed)
		goto out;
	if (session_flags)
		*session_flags = session->flags;
	if (continuation)
		*continuation = !frame_magic;
	if (shard_out)
		*shard_out = shard;
	if (flow_id_out)
		*flow_id_out = session->value[0];
	if (epoch_out)
		*epoch_out = session->value[2];
out:
	read_unlock_bh(&trustix_datapath_state_lock);
	return claimed;
}

static int
trustix_datapath_outer_pull_skb(struct sk_buff *skb,
				const struct trustix_datapath_ioc_classify *classify,
				__u8 ip_header_len, __u8 l4_header_len)
{
	const __u8 *network;
	const __u8 *frame;
	__u32 total_len;
	__u16 transport_len;

	if (!skb || !classify)
		return -EINVAL;
	if (ip_header_len != 20)
		return -EPROTONOSUPPORT;
	network = skb_network_header(skb);
	if (!network)
		return -EINVAL;
	total_len = trustix_datapath_get_be16(network + 2);
	if (total_len > skb->len)
		return -EMSGSIZE;
	switch (classify->protocol) {
	case IPPROTO_UDP:
		if (l4_header_len != 8)
			return -EPROTONOSUPPORT;
		if (total_len < 28 + TRUSTIX_DATAPATH_MIN_FRAME_HEADER_LEN)
			return -EPROTONOSUPPORT;
		if (!pskb_may_pull(skb,
				   28 + TRUSTIX_DATAPATH_MIN_FRAME_HEADER_LEN))
			return -ENODATA;
		network = skb_network_header(skb);
		frame = network + 28;
		if (!trustix_datapath_frame_magic_supported(frame))
			return -EPROTONOSUPPORT;
		transport_len = trustix_datapath_get_be16(network + 24);
		if (transport_len < 8 ||
		    (__u32)transport_len != total_len - ip_header_len)
			return -EPROTONOSUPPORT;
		return 0;
	case IPPROTO_TCP:
		if (l4_header_len != 20)
			return -EPROTONOSUPPORT;
		if (total_len < 40 + TRUSTIX_DATAPATH_MIN_FRAME_HEADER_LEN)
			return -EPROTONOSUPPORT;
		if (!pskb_may_pull(skb,
				   40 + TRUSTIX_DATAPATH_MIN_FRAME_HEADER_LEN))
			return -ENODATA;
		network = skb_network_header(skb);
		frame = network + 40;
		if (!trustix_datapath_frame_magic_supported(frame))
			return -EPROTONOSUPPORT;
		return 0;
	default:
		return -EPROTONOSUPPORT;
	}
}

static int
trustix_datapath_outer_magic_check_packet(const __u8 *packet, __u32 packet_len,
					  __u8 *ip_header_len,
					  __u8 *l4_header_len)
{
	struct trustix_datapath_ioc_classify classify = {};
	const __u8 *frame;
	__u16 transport_len;
	int ret;

	ret = trustix_datapath_parse_ipv4_packet(packet, packet_len, &classify,
						 ip_header_len,
						 l4_header_len);
	if (ret)
		return ret;
	if (*ip_header_len != 20)
		return -EOPNOTSUPP;
	switch (classify.protocol) {
	case IPPROTO_UDP:
		if (*l4_header_len != 8)
			return -EBADMSG;
		if (packet_len < 28 + TRUSTIX_DATAPATH_MIN_FRAME_HEADER_LEN)
			return -EPROTONOSUPPORT;
		transport_len = trustix_datapath_get_be16(packet + 24);
		if (transport_len < 8 ||
		    (__u32)transport_len != packet_len - *ip_header_len)
			return -EMSGSIZE;
		frame = packet + 28;
		break;
	case IPPROTO_TCP:
		if (*l4_header_len != 20)
			return -EOPNOTSUPP;
		if (packet_len < 40 + TRUSTIX_DATAPATH_MIN_FRAME_HEADER_LEN)
			return -EPROTONOSUPPORT;
		frame = packet + 40;
		break;
	default:
		return -EPROTONOSUPPORT;
	}
	return trustix_datapath_frame_magic_supported(frame) ? 0 :
		-EPROTONOSUPPORT;
}

static __always_inline bool
trustix_datapath_hook_dev_matches_ifindex(const struct net_device *dev,
					  int ifindex)
{
	struct net_device *master;
	bool matched = false;

	if (!dev || ifindex <= 0)
		return false;
	if (dev->ifindex == ifindex)
		return true;
	rcu_read_lock();
	master = netdev_master_upper_dev_get_rcu((struct net_device *)dev);
	if (master && master->ifindex == ifindex) {
		trustix_datapath_hook_master_ifindex_matches++;
		matched = true;
	}
	rcu_read_unlock();
	return matched;
}

static __always_inline bool
trustix_datapath_hook_packet_matches_ifindex(
	const struct trustix_datapath_hook_entry *hook,
	const struct sk_buff *skb,
	const struct nf_hook_state *state)
{
	int ifindex;

	if (!hook)
		return false;
	ifindex = READ_ONCE(hook->ifindex);
	if (ifindex <= 0)
		return true;
	if (state && trustix_datapath_hook_dev_matches_ifindex(state->in,
							      ifindex))
		return true;
	if (skb && trustix_datapath_hook_dev_matches_ifindex(skb->dev,
							    ifindex))
		return true;
	return false;
}

static __always_inline bool
trustix_datapath_account_parse_error_hot(
	const struct trustix_datapath_hook_entry *hook)
{
	struct trustix_datapath_pcpu_hot_stats *stats;
	struct trustix_datapath_hook_hot_counters *hook_stats;
	unsigned int index;

	if (!hook)
		return false;
	index = READ_ONCE(hook->stats_index);
	if (unlikely(index >= TRUSTIX_DATAPATH_HOOK_MAX))
		return false;
	local_bh_disable();
	stats = this_cpu_ptr(trustix_datapath_pcpu_hot_stats);
	hook_stats = &stats->hooks[index];
	u64_stats_update_begin(&stats->syncp);
	hook_stats->seen++;
	hook_stats->parse_errors++;
	hook_stats->pass++;
	stats->packet.parse_errors++;
	u64_stats_update_end(&stats->syncp);
	local_bh_enable();
	return true;
}

static __always_inline bool
trustix_datapath_account_tx_plaintext_hot(
	const struct trustix_datapath_hook_entry *hook, __u32 packet_len,
	const struct trustix_datapath_ioc_classify *classify)
{
	struct trustix_datapath_pcpu_hot_stats *stats;
	struct trustix_datapath_hook_hot_counters *hook_stats;
	unsigned int index;

	if (!hook || !classify)
		return false;
	index = READ_ONCE(hook->stats_index);
	if (unlikely(index >= TRUSTIX_DATAPATH_HOOK_MAX))
		return false;
	local_bh_disable();
	stats = this_cpu_ptr(trustix_datapath_pcpu_hot_stats);
	hook_stats = &stats->hooks[index];
	u64_stats_update_begin(&stats->syncp);
	hook_stats->seen++;
	hook_stats->classified++;
	hook_stats->drop++;
	switch (classify->route_flags) {
	case TRUSTIX_DATAPATH_ROUTE_FLAG_UNICAST:
		stats->packet.unicast_routes++;
		break;
	case TRUSTIX_DATAPATH_ROUTE_FLAG_LOCAL:
		stats->packet.local_routes++;
		break;
	case TRUSTIX_DATAPATH_ROUTE_FLAG_BLACKHOLE:
		stats->packet.blackhole_routes++;
		break;
	case TRUSTIX_DATAPATH_ROUTE_FLAG_REJECT:
		stats->packet.reject_routes++;
		break;
	default:
		break;
	}
	stats->packet.packets++;
	stats->packet.bytes += packet_len;
	u64_stats_update_end(&stats->syncp);
	local_bh_enable();
	return true;
}

static __always_inline bool
trustix_datapath_account_rx_worker_hot(
	const struct trustix_datapath_hook_entry *hook, bool outer_candidate,
	int outer_ret, int worker_ret, bool rx_preview, bool rx_stage,
	bool rx_worker, unsigned int worker_stream_frames)
{
	struct trustix_datapath_pcpu_hot_stats *stats;
	struct trustix_datapath_hook_hot_counters *hook_stats;
	unsigned int index;

	if (!hook)
		return false;
	index = READ_ONCE(hook->stats_index);
	if (unlikely(index >= TRUSTIX_DATAPATH_HOOK_MAX))
		return false;
	local_bh_disable();
	stats = this_cpu_ptr(trustix_datapath_pcpu_hot_stats);
	hook_stats = &stats->hooks[index];
	u64_stats_update_begin(&stats->syncp);
	hook_stats->seen++;
	if (outer_candidate) {
		hook_stats->outer_seen++;
		if (!outer_ret)
			hook_stats->outer_parsed++;
		else if (outer_ret == -EHOSTUNREACH || outer_ret == -ENOKEY ||
			 outer_ret == -ESTALE)
			hook_stats->outer_session_misses++;
		else if (outer_ret != -EPROTONOSUPPORT)
			hook_stats->outer_parse_errors++;
		if (rx_preview) {
			if (!outer_ret)
				hook_stats->rx_preview++;
			else if (outer_ret != -EPROTONOSUPPORT)
				hook_stats->rx_preview_errors++;
		}
		if (rx_stage) {
			if (!outer_ret)
				hook_stats->rx_stage++;
			else if (outer_ret != -EPROTONOSUPPORT)
				hook_stats->rx_stage_errors++;
		}
		if (rx_worker) {
			if (!outer_ret && !worker_ret)
				hook_stats->rx_worker++;
			else if (outer_ret != -EPROTONOSUPPORT ||
				 worker_ret != -EPROTONOSUPPORT)
				hook_stats->rx_worker_errors++;
		}
	}
	hook_stats->classified++;
	hook_stats->drop++;
	if (worker_stream_frames > 1)
		hook_stats->rx_worker += worker_stream_frames - 1;
	u64_stats_update_end(&stats->syncp);
	local_bh_enable();
	return true;
}

static unsigned int
trustix_datapath_nf_hook(void *priv, struct sk_buff *skb,
			 const struct nf_hook_state *state)
{
	struct trustix_datapath_hook_entry *hook = priv;
	struct trustix_datapath_ioc_classify classify = {};
	struct trustix_datapath_rx_stage_view rx_view = {};
	struct net_device *target_dev_hint;
	__u8 ip_header_len = 0;
	__u8 l4_header_len = 0;
	__u8 plaintext_rx_shard = 0;
	int target_ifindex;
	int outer_ret = -EPROTONOSUPPORT;
	int secure_rx_ret = -EOPNOTSUPP;
	int worker_ret = -EPROTONOSUPPORT;
	int tx_ret = -EPROTONOSUPPORT;
	__u64 plaintext_rx_flow_id = 0;
	__u64 plaintext_rx_epoch = 0;
	__u32 plaintext_rx_session_flags = 0;
	__u32 hook_flags;
	bool outer_candidate = false;
	bool plaintext_rx_claimed = false;
	bool plaintext_rx_continuation = false;
	bool plaintext_rx_delivered = false;
	bool plaintext_rx_failed = false;
	bool rx_prepared = false;
	bool secure_rx_claimed = false;
	bool rx_preview = false;
	bool rx_stage = false;
	bool rx_worker = false;
	bool worker_queued = false;
	bool worker_defer_stolen = false;
	bool worker_inner_gso_candidate = false;
	bool worker_inline_stolen = false;
	bool worker_stream_queued = false;
	struct net_device *worker_defer_target_dev = NULL;
	unsigned int worker_stream_frames = 0;
	unsigned int secure_rx_frames = 0;
	int ret;

	if (!skb || !hook || !READ_ONCE(hook->registered))
		return NF_ACCEPT;
	if (!trustix_datapath_hook_packet_matches_ifindex(hook, skb, state)) {
		trustix_datapath_hook_ifindex_skips++;
		return NF_ACCEPT;
	}
	target_ifindex = READ_ONCE(hook->target_ifindex);
	target_dev_hint = READ_ONCE(hook->target_dev);
	hook_flags = READ_ONCE(hook->flags);
	if (skb->mark & (TRUSTIX_DATAPATH_SKB_MARK_TX_PLAINTEXT |
			 TRUSTIX_DATAPATH_SKB_MARK_RX_WORKER)) {
		if (skb->mark & TRUSTIX_DATAPATH_SKB_MARK_TX_PLAINTEXT)
			trustix_datapath_tx_plaintext_mark_skips++;
		if (skb->mark & TRUSTIX_DATAPATH_SKB_MARK_RX_WORKER)
			trustix_datapath_rx_worker_mark_skips++;
		return NF_ACCEPT;
	}
	ret = trustix_datapath_parse_skb_ipv4(skb, &classify, &ip_header_len,
					      &l4_header_len);
	if (ret) {
		if (likely(trustix_datapath_account_parse_error_hot(hook)))
			return NF_ACCEPT;
		write_lock_bh(&trustix_datapath_state_lock);
		hook->seen++;
		hook->parse_errors++;
		trustix_datapath_packet_parse_errors++;
		hook->pass++;
		write_unlock_bh(&trustix_datapath_state_lock);
		return NF_ACCEPT;
	}
	if (hook_flags & (TRUSTIX_DATAPATH_HOOK_FLAG_TX_PLAINTEXT |
			  TRUSTIX_DATAPATH_HOOK_FLAG_TX_SECURE_TIX_TCP)) {
		tx_ret = trustix_datapath_tx_plaintext_skb(
			skb, &classify, target_ifindex, target_dev_hint,
			hook_flags);
		if (!tx_ret) {
			if (likely(trustix_datapath_account_tx_plaintext_hot(
				    hook, skb->len, &classify)))
				return NF_DROP;
			write_lock_bh(&trustix_datapath_state_lock);
			hook->seen++;
			hook->classified++;
			hook->drop++;
			trustix_datapath_account_packet_classify_locked(
				skb->len, &classify, 0);
			write_unlock_bh(&trustix_datapath_state_lock);
			return NF_DROP;
		}
	}
	if (classify.protocol == IPPROTO_UDP || classify.protocol == IPPROTO_TCP) {
		if (classify.protocol == IPPROTO_UDP)
			trustix_datapath_debug_record_udp(skb, &classify,
							  ip_header_len);
		rx_preview = hook_flags & TRUSTIX_DATAPATH_HOOK_FLAG_RX_PREVIEW;
		rx_stage = hook_flags & TRUSTIX_DATAPATH_HOOK_FLAG_RX_STAGE;
		rx_worker = hook_flags & TRUSTIX_DATAPATH_HOOK_FLAG_RX_WORKER;
		if (classify.protocol == IPPROTO_TCP &&
		    !READ_ONCE(trustix_datapath_rx_worker_tcp))
			rx_worker = false;
		outer_ret = trustix_datapath_outer_pull_skb(
			skb, &classify, ip_header_len, l4_header_len);
		outer_candidate = outer_ret != -EPROTONOSUPPORT;
		if (rx_worker && classify.protocol == IPPROTO_TCP &&
		    !(hook_flags &
		      TRUSTIX_DATAPATH_HOOK_FLAG_RX_SECURE_TIX_TCP_ONLY)) {
			plaintext_rx_claimed =
				trustix_datapath_claim_plaintext_tix_tcp_skb(
					skb, &classify, ip_header_len,
					l4_header_len, !outer_ret,
					&plaintext_rx_session_flags,
					&plaintext_rx_continuation,
					&plaintext_rx_shard,
					&plaintext_rx_flow_id,
					&plaintext_rx_epoch);
		}
		if (plaintext_rx_claimed && plaintext_rx_continuation &&
		    plaintext_rx_shard &&
		    (plaintext_rx_session_flags &
		     TRUSTIX_DATAPATH_SESSION_FLAG_RECEIVE_INNER_GSO) &&
		    !(plaintext_rx_session_flags &
		      TRUSTIX_DATAPATH_SESSION_FLAGS_ENCRYPTED)) {
			trustix_datapath_inner_gso_probation_record_claim(
				skb, &classify, target_ifindex,
				plaintext_rx_flow_id, plaintext_rx_epoch);
			worker_inner_gso_candidate = true;
			outer_candidate = true;
			worker_ret =
				trustix_datapath_rx_worker_consume_inner_gso_continuation(
					skb, &classify, ip_header_len,
					l4_header_len, target_ifindex,
					target_dev_hint,
					&worker_stream_frames);
			if (!worker_ret) {
				outer_ret = 0;
				worker_stream_queued = true;
			} else {
				outer_ret = worker_ret;
			}
		}
		if (outer_candidate)
			trustix_datapath_debug_record_outer(1, outer_ret,
							    worker_ret, skb,
							    &classify,
							    ip_header_len,
							    l4_header_len);
		if (!outer_ret && rx_worker && !worker_stream_queued &&
		    classify.protocol == IPPROTO_TCP) {
			secure_rx_ret =
				trustix_datapath_secure_rx_preprocess_skb(
					skb, &classify, ip_header_len,
					l4_header_len, target_ifindex,
					&secure_rx_claimed, &secure_rx_frames);
			if (secure_rx_claimed) {
				if (secure_rx_ret) {
					outer_ret = secure_rx_ret;
				} else if (secure_rx_frames) {
					worker_ret = 0;
					worker_stream_frames = secure_rx_frames;
					worker_stream_queued = true;
				} else {
					outer_ret = -EIO;
				}
			}
		}
		if ((hook_flags &
		     TRUSTIX_DATAPATH_HOOK_FLAG_RX_SECURE_TIX_TCP_ONLY) &&
		    !secure_rx_claimed)
			return NF_ACCEPT;
		if (!outer_ret && rx_worker && !worker_stream_queued) {
			worker_ret = trustix_datapath_rx_worker_try_inner_gso(
				skb, &classify, ip_header_len, l4_header_len,
				target_ifindex, target_dev_hint,
				plaintext_rx_shard, true,
				&worker_inner_gso_candidate,
				&worker_stream_frames);
			if (worker_inner_gso_candidate) {
				if (!worker_ret) {
					outer_ret = 0;
					worker_stream_queued = true;
				} else {
					outer_ret = worker_ret;
				}
			}
		}
		if (!worker_inner_gso_candidate && !worker_stream_queued &&
		    !outer_ret &&
		    (rx_preview || rx_stage || rx_worker)) {
			outer_ret = trustix_datapath_rx_prepare_skb(
				skb, &classify, ip_header_len, l4_header_len,
				&rx_view);
			rx_prepared = !outer_ret;
			if (outer_ret == -EMSGSIZE && rx_worker &&
			    (classify.protocol == IPPROTO_TCP ||
			     classify.protocol == IPPROTO_UDP) &&
			    READ_ONCE(trustix_datapath_rx_worker_stream_tcp)) {
				worker_ret = trustix_datapath_rx_worker_push_stream(
					skb, &classify, ip_header_len,
					l4_header_len, target_ifindex,
					&worker_stream_frames);
				if (!worker_ret && worker_stream_frames) {
					outer_ret = 0;
					worker_stream_queued = true;
				}
			}
			if (rx_prepared && rx_worker &&
			    rx_view.inner.protocol == IPPROTO_TCP &&
			    !READ_ONCE(trustix_datapath_rx_worker_tcp))
				rx_worker = false;
			trustix_datapath_debug_record_outer(2, outer_ret,
							    worker_ret, skb,
							    &classify,
							    ip_header_len,
							    l4_header_len);
		}
		if (!outer_ret && rx_stage && rx_prepared) {
			outer_ret = trustix_datapath_rx_stage_push(&classify,
								   &rx_view);
			trustix_datapath_debug_record_outer(3, outer_ret,
							    worker_ret, skb,
							    &classify,
							    ip_header_len,
							    l4_header_len);
		}
		if (!outer_ret && rx_worker && rx_prepared) {
			if (READ_ONCE(trustix_datapath_rx_worker_inline_xmit) &&
			    READ_ONCE(trustix_datapath_rx_worker_xmit))
				worker_ret =
					trustix_datapath_rx_worker_inline_xmit_view(
						skb, &rx_view, target_ifindex,
						target_dev_hint,
						&worker_inline_stolen);
			else
				worker_ret = trustix_datapath_rx_worker_push(
					skb, &rx_view, &worker_defer_stolen,
					target_ifindex, target_dev_hint,
					&worker_defer_target_dev);
			trustix_datapath_debug_record_outer(4, outer_ret,
							    worker_ret, skb,
							    &classify,
							    ip_header_len,
							    l4_header_len);
		}
		worker_queued = worker_inner_gso_candidate ||
				(rx_worker && rx_prepared && !worker_ret);
		if (worker_stream_queued)
			worker_queued = true;
		plaintext_rx_delivered = worker_stream_queued ||
			(worker_inner_gso_candidate && !worker_ret) ||
			(rx_worker && rx_prepared && !worker_ret);
		plaintext_rx_failed = plaintext_rx_claimed &&
				      !secure_rx_claimed &&
				      !plaintext_rx_delivered;
		if (plaintext_rx_failed)
			trustix_datapath_rx_worker_tix_tcp_claimed_drops++;
		if (trustix_datapath_inner_gso_error_trips_circuit(worker_ret) &&
		    ((plaintext_rx_failed &&
		     (plaintext_rx_session_flags &
		      TRUSTIX_DATAPATH_SESSION_FLAG_RECEIVE_INNER_GSO)) ||
		     (worker_inner_gso_candidate && worker_ret)))
			trustix_datapath_inner_gso_record_runtime_fault();
	}

	if (worker_queued &&
	    likely(trustix_datapath_account_rx_worker_hot(
		    hook, outer_candidate, outer_ret, worker_ret, rx_preview,
		    rx_stage, rx_worker, worker_stream_frames)))
		goto hook_accounted;

	write_lock_bh(&trustix_datapath_state_lock);
	hook->seen++;
	if (outer_candidate) {
		hook->outer_seen++;
		/*
		 * rx_prepare validates the outer wire/session before the worker
		 * takes ownership. Re-parsing here repeats the same state walk on
		 * every RX fast-path packet.
		 */
		if (!outer_ret && !worker_stream_queued && !rx_prepared)
			outer_ret = trustix_datapath_outer_parse_skb_locked(
				skb, &classify, ip_header_len, l4_header_len);
		trustix_datapath_debug_record_outer(5, outer_ret, worker_ret,
						    skb, &classify,
						    ip_header_len,
						    l4_header_len);
		if (!outer_ret)
			hook->outer_parsed++;
		else if (outer_ret == -EHOSTUNREACH || outer_ret == -ENOKEY ||
			 outer_ret == -ESTALE)
			hook->outer_session_misses++;
		else if (outer_ret != -EPROTONOSUPPORT)
			hook->outer_parse_errors++;
		if (rx_preview) {
			if (!outer_ret)
				hook->rx_preview++;
			else if (outer_ret != -EPROTONOSUPPORT)
				hook->rx_preview_errors++;
		}
		if (rx_stage) {
			if (!outer_ret)
				hook->rx_stage++;
			else if (outer_ret != -EPROTONOSUPPORT)
				hook->rx_stage_errors++;
		}
		if (rx_worker) {
			if (!outer_ret && !worker_ret)
				hook->rx_worker++;
			else if (outer_ret != -EPROTONOSUPPORT ||
				 worker_ret != -EPROTONOSUPPORT)
				hook->rx_worker_errors++;
		}
	}
	if (worker_queued) {
		/* The RX worker already owns the packet; avoid a second route lookup. */
		ret = 0;
		hook->classified++;
	} else if (secure_rx_claimed || plaintext_rx_claimed) {
		/* Claimed tunnel data is either consumed by the worker or dropped. */
		ret = outer_ret ?: worker_ret;
		if (!ret)
			ret = -EIO;
	} else {
		ret = trustix_datapath_classify_locked(&classify);
		if (ret == 0)
			hook->classified++;
		else if (ret == -ENOENT)
			hook->route_misses++;
		else if (ret == -EHOSTUNREACH)
			hook->session_misses++;
		trustix_datapath_account_packet_classify_locked(skb->len,
								&classify,
								ret);
	}
	if (worker_queued || secure_rx_claimed || plaintext_rx_claimed) {
		hook->drop++;
		if (worker_queued && worker_stream_frames > 1)
			hook->rx_worker += worker_stream_frames - 1;
	} else {
		hook->pass++;
	}
	write_unlock_bh(&trustix_datapath_state_lock);

hook_accounted:
	if (worker_defer_stolen) {
		bool inline_attempted = false;

		if (READ_ONCE(trustix_datapath_rx_worker_inline_stolen)) {
			inline_attempted = true;
			worker_ret =
				trustix_datapath_rx_worker_inject_stolen_inline_target(
					skb, &rx_view,
					worker_defer_target_dev);
		} else {
			worker_ret =
				trustix_datapath_rx_worker_push_stolen_target(
					skb, &rx_view,
					worker_defer_target_dev);
		}
		worker_defer_target_dev = NULL;
		if (!worker_ret)
			return NF_STOLEN;
		write_lock_bh(&trustix_datapath_state_lock);
		hook->rx_worker_errors++;
		if (!inline_attempted)
			trustix_datapath_rx_worker_steal_errors++;
		hook->drop++;
		write_unlock_bh(&trustix_datapath_state_lock);
		return NF_DROP;
	}
	if (worker_defer_target_dev)
		dev_put(worker_defer_target_dev);
	if (worker_inline_stolen)
		return NF_STOLEN;
	if (secure_rx_claimed)
		worker_queued = true;
	if (plaintext_rx_claimed)
		worker_queued = true;
	return worker_queued ? NF_DROP : NF_ACCEPT;
}

static bool
trustix_datapath_hook_name_matches(
	const struct trustix_datapath_hook_entry *entry,
	const char *ifname)
{
	if (!ifname || !ifname[0])
		return true;
	return strncmp(entry->ifname, ifname, sizeof(entry->ifname)) == 0;
}

static struct trustix_datapath_hook_entry *
trustix_datapath_hook_find_locked(struct net *net, int ifindex,
				  const char *ifname, bool include_in_use)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(trustix_datapath_hooks); i++) {
		struct trustix_datapath_hook_entry *entry =
			&trustix_datapath_hooks[i];

		if (include_in_use) {
			if (!entry->in_use)
				continue;
		} else if (!entry->registered) {
			continue;
		}
		if (entry->net != net)
			continue;
		if (ifindex > 0 && entry->ifindex != ifindex)
			continue;
		if (!trustix_datapath_hook_name_matches(entry, ifname))
			continue;
		return entry;
	}
	return NULL;
}

static struct trustix_datapath_hook_entry *
trustix_datapath_hook_free_locked(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(trustix_datapath_hooks); i++) {
		if (!trustix_datapath_hooks[i].in_use)
			return &trustix_datapath_hooks[i];
	}
	return NULL;
}

static bool trustix_datapath_hooks_registered_locked(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(trustix_datapath_hooks); i++) {
		if (trustix_datapath_hooks[i].registered)
			return true;
	}
	return false;
}

static void
trustix_datapath_fill_hook_locked(
	struct trustix_datapath_ioc_hook *hook,
	const struct trustix_datapath_hook_entry *entry)
{
	struct trustix_datapath_hook_hot_counters hot = {};
	__u32 op = hook->op;
	__u32 requested_flags = hook->flags;

	memset(hook, 0, sizeof(*hook));
	hook->version = TRUSTIX_DATAPATH_IOC_VERSION;
	hook->op = op;
	if (!entry || !entry->registered) {
		hook->flags = requested_flags;
		return;
	}
	hook->attached = 1U;
	hook->flags = entry->flags;
	hook->ifindex = entry->ifindex;
	hook->target_ifindex = entry->target_ifindex;
	memcpy(hook->ifname, entry->ifname, sizeof(hook->ifname) - 1);
	memcpy(hook->target_ifname, entry->target_ifname,
	       sizeof(hook->target_ifname) - 1);
	trustix_datapath_read_hook_hot_counters(entry->stats_index, &hot);
	trustix_datapath_subtract_hook_hot_counters(&hot, &entry->hot_base);
	hook->seen = entry->seen + hot.seen;
	hook->classified = entry->classified + hot.classified;
	hook->parse_errors = entry->parse_errors + hot.parse_errors;
	hook->route_misses = entry->route_misses + hot.route_misses;
	hook->session_misses = entry->session_misses + hot.session_misses;
	hook->pass = entry->pass + hot.pass;
	hook->drop = entry->drop + hot.drop;
	hook->outer_seen = entry->outer_seen + hot.outer_seen;
	hook->outer_parsed = entry->outer_parsed + hot.outer_parsed;
	hook->outer_parse_errors =
		entry->outer_parse_errors + hot.outer_parse_errors;
	hook->outer_session_misses =
		entry->outer_session_misses + hot.outer_session_misses;
	hook->rx_preview = entry->rx_preview + hot.rx_preview;
	hook->rx_preview_errors =
		entry->rx_preview_errors + hot.rx_preview_errors;
	hook->rx_stage = entry->rx_stage + hot.rx_stage;
	hook->rx_stage_errors = entry->rx_stage_errors + hot.rx_stage_errors;
	hook->rx_worker = entry->rx_worker + hot.rx_worker;
	hook->rx_worker_errors =
		entry->rx_worker_errors + hot.rx_worker_errors;
	hook->rx_worker_injected = trustix_datapath_rx_worker_injected;
	hook->rx_worker_dropped = trustix_datapath_rx_worker_dropped +
				  trustix_datapath_rx_worker_overwritten +
				  trustix_datapath_rx_worker_alloc_errors;
}

static void
trustix_datapath_hook_reset_counters_locked(
	struct trustix_datapath_hook_entry *entry)
{
	if (entry) {
		trustix_datapath_read_hook_hot_counters(entry->stats_index,
						&entry->hot_base);
		entry->seen = 0;
		entry->classified = 0;
		entry->parse_errors = 0;
		entry->route_misses = 0;
		entry->session_misses = 0;
		entry->pass = 0;
		entry->drop = 0;
		entry->outer_seen = 0;
		entry->outer_parsed = 0;
		entry->outer_parse_errors = 0;
		entry->outer_session_misses = 0;
		entry->rx_preview = 0;
		entry->rx_preview_errors = 0;
		entry->rx_stage = 0;
		entry->rx_stage_errors = 0;
		entry->rx_worker = 0;
		entry->rx_worker_errors = 0;
	}
	trustix_datapath_rx_worker_queued = 0;
	trustix_datapath_rx_worker_injected = 0;
	trustix_datapath_rx_worker_dropped = 0;
	trustix_datapath_rx_worker_overwritten = 0;
	trustix_datapath_rx_worker_queue_full_fallbacks = 0;
	trustix_datapath_rx_worker_alloc_errors = 0;
	trustix_datapath_rx_worker_xmit_packets = 0;
	trustix_datapath_rx_worker_xmit_ok = 0;
	trustix_datapath_rx_worker_xmit_cn = 0;
	trustix_datapath_rx_worker_xmit_ret_errors = 0;
	trustix_datapath_rx_worker_xmit_drop = 0;
	trustix_datapath_rx_worker_xmit_other_ret_errors = 0;
	trustix_datapath_rx_worker_xmit_dev_forward_packets = 0;
	trustix_datapath_rx_worker_xmit_dev_forward_errors = 0;
	trustix_datapath_rx_worker_xmit_peer_forward_packets = 0;
	trustix_datapath_rx_worker_xmit_peer_forward_errors = 0;
	trustix_datapath_rx_worker_xmit_peer_forward_unsupported = 0;
	trustix_datapath_rx_worker_direct_xmit_safe_fallbacks = 0;
	trustix_datapath_rx_worker_inline_receive_safe_fallbacks = 0;
	trustix_datapath_rx_worker_receive_packets = 0;
	trustix_datapath_rx_worker_deliver_errors = 0;
	trustix_datapath_rx_worker_xmit_hash_tx_queue_sets = 0;
	trustix_datapath_rx_worker_xmit_hash_tx_queue_fallbacks = 0;
	trustix_datapath_rx_worker_xmit_hash_tx_queue_q0 = 0;
	trustix_datapath_rx_worker_xmit_hash_tx_queue_q1 = 0;
	trustix_datapath_rx_worker_xmit_hash_tx_queue_q2 = 0;
	trustix_datapath_rx_worker_xmit_hash_tx_queue_q3 = 0;
	trustix_datapath_rx_worker_xmit_hash_tx_queue_q4 = 0;
	trustix_datapath_rx_worker_xmit_hash_tx_queue_q5 = 0;
	trustix_datapath_rx_worker_xmit_hash_tx_queue_q6 = 0;
	trustix_datapath_rx_worker_xmit_hash_tx_queue_q7 = 0;
	trustix_datapath_rx_worker_xmit_hash_tx_queue_other = 0;
	trustix_datapath_rx_worker_xmit_more_sets = 0;
	trustix_datapath_rx_worker_last_push_ret = 0;
	trustix_datapath_rx_worker_last_deliver_ret = 0;
	trustix_datapath_rx_worker_last_xmit_ret = 0;
	trustix_datapath_rx_worker_last_xmit_error_ret = 0;
	trustix_datapath_rx_worker_queue_work_calls = 0;
	trustix_datapath_rx_worker_queue_work_enqueued = 0;
	trustix_datapath_rx_worker_runs = 0;
	trustix_datapath_rx_worker_run_processed = 0;
	trustix_datapath_rx_worker_stolen = 0;
	trustix_datapath_rx_worker_steal_fallbacks = 0;
	trustix_datapath_rx_worker_steal_errors = 0;
	trustix_datapath_rx_worker_inline_injected = 0;
	trustix_datapath_rx_worker_inline_errors = 0;
	trustix_datapath_rx_worker_inline_xmit_packets = 0;
	trustix_datapath_rx_worker_inline_xmit_errors = 0;
	trustix_datapath_rx_worker_inline_xmit_hook_queue_fallbacks = 0;
	trustix_datapath_rx_worker_inline_xmit_copy_csum_hits = 0;
	trustix_datapath_rx_worker_inline_xmit_copy_csum_fallbacks = 0;
	trustix_datapath_rx_worker_stream_packets = 0;
	trustix_datapath_rx_worker_stream_frames = 0;
	trustix_datapath_rx_worker_stream_errors = 0;
	trustix_datapath_rx_worker_stream_queue_errors = 0;
	trustix_datapath_rx_worker_stream_batch_packets = 0;
	trustix_datapath_rx_worker_stream_batch_frames = 0;
	trustix_datapath_rx_worker_stream_batch_errors = 0;
	trustix_datapath_rx_worker_stream_inline_batch_fallbacks = 0;
	trustix_datapath_reset_percpu_ullong(
		&trustix_datapath_rx_worker_stream_offset_copy_attempts);
	trustix_datapath_reset_percpu_ullong(
		&trustix_datapath_rx_worker_stream_offset_copy_hits);
	trustix_datapath_reset_percpu_ullong(
		&trustix_datapath_rx_worker_stream_offset_copy_bytes);
	trustix_datapath_reset_percpu_ullong(
		&trustix_datapath_rx_worker_stream_offset_copy_fallbacks);
	trustix_datapath_reset_percpu_ullong(
		&trustix_datapath_rx_worker_stream_offset_copy_errors);
	trustix_datapath_rx_worker_checksum_fixed = 0;
	trustix_datapath_rx_worker_checksum_trusted = 0;
	trustix_datapath_rx_worker_checksum_trust_fallbacks = 0;
	trustix_datapath_rx_worker_checksum_ipv4_only = 0;
	trustix_datapath_rx_worker_checksum_partial = 0;
	trustix_datapath_rx_worker_checksum_errors = 0;
	trustix_datapath_rx_worker_inner_tcp_checksum_partial = 0;
	trustix_datapath_rx_worker_inner_tcp_checksum_partial_errors = 0;
	trustix_datapath_rx_worker_inner_gso_candidates = 0;
	trustix_datapath_rx_worker_inner_gso_packets = 0;
	trustix_datapath_rx_worker_inner_gso_segments = 0;
	trustix_datapath_rx_worker_inner_gso_partial_frames = 0;
	trustix_datapath_rx_worker_inner_gso_malformed = 0;
	trustix_datapath_rx_worker_inner_gso_errors = 0;
	trustix_datapath_rx_worker_inner_gso_stream_packets = 0;
	trustix_datapath_rx_worker_inner_gso_stream_frames = 0;
	trustix_datapath_rx_worker_inner_gso_regular_frames = 0;
	trustix_datapath_rx_worker_inner_gso_continuation_drops = 0;
	trustix_datapath_rx_worker_inner_gso_reassembly_started = 0;
	trustix_datapath_rx_worker_inner_gso_reassembly_completed = 0;
	trustix_datapath_rx_worker_inner_gso_continuation_matched = 0;
	trustix_datapath_rx_worker_inner_gso_continuation_orphans = 0;
	trustix_datapath_rx_worker_inner_gso_sequence_gaps = 0;
	trustix_datapath_rx_worker_inner_gso_sequence_gap_ahead = 0;
	trustix_datapath_rx_worker_inner_gso_sequence_gap_behind = 0;
	trustix_datapath_rx_worker_inner_gso_last_sequence_gap = 0;
	trustix_datapath_rx_worker_inner_gso_timeouts = 0;
	trustix_datapath_rx_worker_inner_gso_timeouts_on_start = 0;
	trustix_datapath_rx_worker_inner_gso_timeouts_on_append = 0;
	trustix_datapath_rx_worker_inner_gso_timeout_missing_bytes = 0;
	trustix_datapath_rx_worker_inner_gso_timeout_max_missing_bytes = 0;
	trustix_datapath_rx_worker_inner_gso_duplicate_starts = 0;
	trustix_datapath_rx_worker_inner_gso_collisions = 0;
	trustix_datapath_rx_worker_inner_gso_reassembly_high_watermark = 0;
	trustix_datapath_rx_worker_inner_gso_oom = 0;
	trustix_datapath_rx_worker_inner_gso_tail_frames = 0;
	trustix_datapath_rx_worker_tix_tcp_claimed_drops = 0;
	trustix_datapath_rx_worker_partial_checksum_software_fallbacks = 0;
	trustix_datapath_rx_worker_partial_checksum_metadata_repairs = 0;
	trustix_datapath_rx_worker_dst_mac_hits = 0;
	trustix_datapath_rx_worker_dst_mac_veth_peer_hits = 0;
	trustix_datapath_rx_worker_dst_mac_cache_hits = 0;
	trustix_datapath_rx_worker_dst_mac_cache_misses = 0;
	trustix_datapath_rx_worker_dst_mac_broadcast = 0;
	trustix_datapath_rx_worker_queued_skb = 0;
	trustix_datapath_rx_worker_queued_skb_fallbacks = 0;
	trustix_datapath_rx_worker_mark_skips = 0;
	trustix_datapath_hook_ifindex_skips = 0;
	trustix_datapath_hook_master_ifindex_matches = 0;
	trustix_datapath_rx_worker_self_marked = 0;
	trustix_datapath_rx_worker_tc_skip_requests = 0;
	trustix_datapath_rx_worker_xmit_scrubbed = 0;
	trustix_datapath_rx_worker_bridge_targets = 0;
	trustix_datapath_rx_worker_last_target_ifindex = 0;
	trustix_datapath_rx_worker_last_target_type = 0;
	trustix_datapath_rx_worker_last_target_priv_flags = 0;
	trustix_datapath_rx_worker_stream_coalesce_packets = 0;
	trustix_datapath_rx_worker_stream_coalesce_frames = 0;
	trustix_datapath_rx_worker_stream_coalesce_errors = 0;
	trustix_datapath_reset_percpu_ullong(
		&trustix_datapath_rx_worker_stream_coalesce_nonlinear_attempts);
	trustix_datapath_reset_percpu_ullong(
		&trustix_datapath_rx_worker_stream_coalesce_nonlinear_hits);
	trustix_datapath_reset_percpu_ullong(
		&trustix_datapath_rx_worker_stream_coalesce_nonlinear_frags);
	trustix_datapath_reset_percpu_ullong(
		&trustix_datapath_rx_worker_stream_coalesce_nonlinear_bytes);
	trustix_datapath_reset_percpu_ullong(
		&trustix_datapath_rx_worker_stream_coalesce_nonlinear_fallbacks);
	trustix_datapath_reset_percpu_ullong(
		&trustix_datapath_rx_worker_stream_coalesce_nonlinear_errors);
	trustix_datapath_reset_percpu_ullong(
		&trustix_datapath_rx_worker_stream_coalesce_page_frag_cache_attempts);
	trustix_datapath_reset_percpu_ullong(
		&trustix_datapath_rx_worker_stream_coalesce_page_frag_cache_hits);
	trustix_datapath_reset_percpu_ullong(
		&trustix_datapath_rx_worker_stream_coalesce_page_frag_cache_fallbacks);
	trustix_datapath_reset_percpu_ullong(
		&trustix_datapath_rx_worker_stream_coalesce_page_frag_cache_errors);
	trustix_datapath_rx_worker_stream_coalesce_segment_batches = 0;
	trustix_datapath_rx_worker_stream_coalesce_segment_skbs = 0;
	trustix_datapath_rx_worker_stream_coalesce_segment_errors = 0;
	trustix_datapath_rx_worker_gso_xmit_packets = 0;
	trustix_datapath_rx_worker_gso_xmit_segments = 0;
	trustix_datapath_rx_worker_gso_xmit_fallbacks = 0;
	trustix_datapath_rx_worker_gso_xmit_errors = 0;
	trustix_datapath_rx_worker_direct_gso_attempts = 0;
	trustix_datapath_rx_worker_direct_gso_hits = 0;
	trustix_datapath_rx_worker_direct_gso_parse_misses = 0;
	trustix_datapath_rx_worker_direct_gso_cap_misses = 0;
	trustix_datapath_rx_worker_direct_gso_mtu_misses = 0;
	trustix_datapath_rx_worker_direct_gso_xmit_errors = 0;
	trustix_datapath_rx_worker_stream_coalesce_partial_csum_fallbacks = 0;
	trustix_datapath_rx_worker_stream_coalesce_checksum_fallbacks = 0;
	trustix_datapath_rx_worker_stream_coalesce_inline_queue_fallbacks = 0;
	trustix_datapath_rx_worker_stream_direct_gso_packets = 0;
	trustix_datapath_rx_worker_stream_direct_gso_frames = 0;
	trustix_datapath_rx_worker_stream_direct_gso_fallbacks = 0;
	trustix_datapath_rx_worker_stream_direct_gso_errors = 0;
	trustix_datapath_rx_worker_stream_coalesce_last_len = 0;
	trustix_datapath_rx_worker_stream_coalesce_last_gso_size = 0;
	trustix_datapath_rx_worker_stream_coalesce_last_gso_segs = 0;
	trustix_datapath_rx_worker_stream_coalesce_last_gso_type = 0;
	trustix_datapath_rx_worker_stream_coalesce_max_len = 0;
	trustix_datapath_rx_worker_stream_coalesce_last_segment_ret = 0;
	trustix_datapath_rx_worker_inline_pair_stored = 0;
	trustix_datapath_rx_worker_inline_pair_packets = 0;
	trustix_datapath_rx_worker_inline_pair_flushes = 0;
	trustix_datapath_rx_worker_inline_pair_misses = 0;
	trustix_datapath_rx_worker_inline_pair_errors = 0;
	trustix_datapath_rx_worker_single_coalesce_stored = 0;
	trustix_datapath_rx_worker_single_coalesce_packets = 0;
	trustix_datapath_rx_worker_single_coalesce_frames = 0;
	trustix_datapath_rx_worker_single_coalesce_flushes = 0;
	trustix_datapath_rx_worker_single_coalesce_misses = 0;
	trustix_datapath_rx_worker_single_coalesce_errors = 0;
	trustix_datapath_tx_plaintext_packets = 0;
	trustix_datapath_tx_plaintext_bytes = 0;
	trustix_datapath_tx_plaintext_inner_tcp_checksum_partial = 0;
	trustix_datapath_tx_plaintext_inner_tcp_checksum_partial_fallbacks = 0;
	trustix_datapath_tx_plaintext_inner_gso_attempts = 0;
	trustix_datapath_tx_plaintext_inner_gso_packets = 0;
	trustix_datapath_tx_plaintext_inner_gso_segments = 0;
	trustix_datapath_tx_plaintext_inner_gso_fallbacks = 0;
	trustix_datapath_tx_plaintext_inner_gso_errors = 0;
	trustix_datapath_tx_plaintext_inner_gso_metadata_scrubs = 0;
	trustix_datapath_tx_plaintext_gso_skips = 0;
	trustix_datapath_tx_plaintext_gso_segments = 0;
	trustix_datapath_tx_plaintext_gso_errors = 0;
	trustix_datapath_tx_plaintext_outer_gso_packets = 0;
	trustix_datapath_tx_plaintext_outer_gso_segments = 0;
	trustix_datapath_tx_plaintext_ipv4_fragment_packets = 0;
	trustix_datapath_tx_plaintext_ipv4_fragments = 0;
	trustix_datapath_tx_plaintext_ipv4_fragment_errors = 0;
	trustix_datapath_tx_plaintext_outer_gso_fallbacks = 0;
	trustix_datapath_tx_plaintext_outer_gso_errors = 0;
	trustix_datapath_reset_percpu_ullong(
		&trustix_datapath_tx_plaintext_outer_gso_page_pool_attempts);
	trustix_datapath_reset_percpu_ullong(
		&trustix_datapath_tx_plaintext_outer_gso_page_pool_hits);
	trustix_datapath_reset_percpu_ullong(
		&trustix_datapath_tx_plaintext_outer_gso_page_pool_fallbacks);
	trustix_datapath_reset_percpu_ullong(
		&trustix_datapath_tx_plaintext_outer_gso_page_pool_errors);
	trustix_datapath_tx_plaintext_payload_fast_copy_linear_hits = 0;
	trustix_datapath_tx_plaintext_payload_fast_copy_frag_hits = 0;
	trustix_datapath_tx_plaintext_payload_fast_copy_fallbacks = 0;
	trustix_datapath_tx_plaintext_payload_fast_copy_errors = 0;
	trustix_datapath_reset_percpu_ullong(
		&trustix_datapath_tx_plaintext_payload_copy_csum_attempts);
	trustix_datapath_reset_percpu_ullong(
		&trustix_datapath_tx_plaintext_payload_copy_csum_hits);
	trustix_datapath_reset_percpu_ullong(
		&trustix_datapath_tx_plaintext_payload_copy_csum_fallbacks);
	trustix_datapath_reset_percpu_ullong(
		&trustix_datapath_tx_plaintext_payload_copy_csum_errors);
	trustix_datapath_tx_plaintext_encrypted_skips = 0;
	trustix_datapath_tx_plaintext_route_misses = 0;
	trustix_datapath_tx_plaintext_no_routes = 0;
	trustix_datapath_tx_plaintext_non_unicast_routes = 0;
	trustix_datapath_tx_plaintext_no_sessions = 0;
	trustix_datapath_tx_plaintext_no_wires = 0;
	trustix_datapath_tx_plaintext_stale_wires = 0;
	trustix_datapath_tx_plaintext_unsupported_transports = 0;
	trustix_datapath_tx_plaintext_invalid_plans = 0;
	trustix_datapath_tx_plaintext_last_plan_ret = 0;
	trustix_datapath_tx_plaintext_last_src_ipv4 = 0;
	trustix_datapath_tx_plaintext_last_dst_ipv4 = 0;
	trustix_datapath_tx_plaintext_last_src_port = 0;
	trustix_datapath_tx_plaintext_last_dst_port = 0;
	trustix_datapath_tx_plaintext_last_protocol = 0;
	trustix_datapath_tx_plaintext_last_build_ret = 0;
	trustix_datapath_tx_plaintext_last_build_stage = 0;
	trustix_datapath_tx_plaintext_last_build_inner_len = 0;
	trustix_datapath_tx_plaintext_last_build_skb_len = 0;
	trustix_datapath_tx_plaintext_last_build_network_offset = 0;
	trustix_datapath_tx_plaintext_last_build_protocol = 0;
	trustix_datapath_tx_plaintext_build_errors = 0;
	trustix_datapath_tx_plaintext_xmit_errors = 0;
	trustix_datapath_tx_plaintext_inline_xmit_packets = 0;
	trustix_datapath_tx_plaintext_inline_xmit_errors = 0;
	trustix_datapath_tx_plaintext_direct_xmit_packets = 0;
	trustix_datapath_tx_plaintext_direct_xmit_errors = 0;
	trustix_datapath_tx_plaintext_direct_xmit_fallbacks = 0;
	trustix_datapath_tx_plaintext_direct_xmit_neigh_misses = 0;
	trustix_datapath_tx_plaintext_direct_xmit_dst_mac_cache_hits = 0;
	trustix_datapath_tx_plaintext_direct_xmit_dst_mac_cache_misses = 0;
	trustix_datapath_tx_plaintext_direct_xmit_dst_mac_cache_invalidations = 0;
	trustix_datapath_tx_plaintext_hash_tx_queue_sets = 0;
	trustix_datapath_tx_plaintext_inner_flow_hash_sets = 0;
	trustix_datapath_tx_plaintext_outer_tuple_hash_sets = 0;
	trustix_datapath_tx_plaintext_xps_sender_cpu_sets = 0;
	trustix_datapath_tx_plaintext_xps_sender_cpu_fallbacks = 0;
	trustix_datapath_tx_plaintext_tix_tcp_port_shard_sets = 0;
	trustix_datapath_reset_percpu_ullong(
		&trustix_datapath_tx_plaintext_tix_tcp_shard_tx_queue_sets);
	trustix_datapath_tx_plaintext_tix_tcp_shard_sequence_hits = 0;
	trustix_datapath_tx_plaintext_tix_tcp_shard_sequence_fallbacks = 0;
	trustix_datapath_reset_percpu_ullong(
		&trustix_datapath_tx_plaintext_tix_tcp_ordered_xmits);
	trustix_datapath_tx_plaintext_tix_tcp_sequence_assign_errors = 0;
	trustix_datapath_rx_tix_tcp_port_shard_matches = 0;
	trustix_datapath_tx_plaintext_hash_tx_queue_fallbacks = 0;
	trustix_datapath_tx_plaintext_hash_tx_queue_q0 = 0;
	trustix_datapath_tx_plaintext_hash_tx_queue_q1 = 0;
	trustix_datapath_tx_plaintext_hash_tx_queue_q2 = 0;
	trustix_datapath_tx_plaintext_hash_tx_queue_q3 = 0;
	trustix_datapath_tx_plaintext_hash_tx_queue_q4 = 0;
	trustix_datapath_tx_plaintext_hash_tx_queue_q5 = 0;
	trustix_datapath_tx_plaintext_hash_tx_queue_q6 = 0;
	trustix_datapath_tx_plaintext_hash_tx_queue_q7 = 0;
	trustix_datapath_tx_plaintext_hash_tx_queue_other = 0;
	trustix_datapath_tx_plaintext_dst_mac_cache_invalidate();
	trustix_datapath_tx_plaintext_stream_coalesce_packets = 0;
	trustix_datapath_tx_plaintext_stream_coalesce_frames = 0;
	trustix_datapath_tx_plaintext_stream_coalesce_stored = 0;
	trustix_datapath_tx_plaintext_stream_coalesce_misses = 0;
	trustix_datapath_tx_plaintext_stream_coalesce_attempts = 0;
	trustix_datapath_tx_plaintext_stream_coalesce_payload_frames = 0;
	trustix_datapath_tx_plaintext_stream_coalesce_ack_only_frames = 0;
	trustix_datapath_tx_plaintext_stream_coalesce_slot_hits = 0;
	trustix_datapath_tx_plaintext_stream_coalesce_slot_conflicts = 0;
	trustix_datapath_tx_plaintext_stream_coalesce_full_flushes = 0;
	trustix_datapath_tx_plaintext_stream_coalesce_timer_flushes = 0;
	trustix_datapath_tx_plaintext_stream_coalesce_single_flushes = 0;
	trustix_datapath_tx_plaintext_stream_coalesce_multi_flushes = 0;
	trustix_datapath_tx_plaintext_stream_coalesce_errors = 0;
	trustix_datapath_tx_plaintext_queued = 0;
	trustix_datapath_tx_plaintext_queue_drops = 0;
	trustix_datapath_tx_plaintext_queue_work_calls = 0;
	trustix_datapath_tx_plaintext_queue_work_enqueued = 0;
	trustix_datapath_tx_plaintext_runs = 0;
	trustix_datapath_tx_plaintext_run_processed = 0;
	trustix_datapath_tx_plaintext_mark_skips = 0;
	trustix_datapath_rx_stage_clear();
}

static int
trustix_datapath_hook_attach(struct trustix_datapath_ioc_hook *hook)
{
	struct trustix_datapath_hook_entry *entry;
	struct net_device *dev = NULL;
	struct net_device *target_dev = NULL;
	struct net *net;
	struct net *hook_net;
	char ifname[TRUSTIX_DATAPATH_IFNAME_MAX];
	char target_ifname[TRUSTIX_DATAPATH_IFNAME_MAX];
	int ret;

	net = trustix_datapath_current_net();
	memset(ifname, 0, sizeof(ifname));
	memcpy(ifname, hook->ifname, sizeof(ifname) - 1);
	memset(target_ifname, 0, sizeof(target_ifname));
	memcpy(target_ifname, hook->target_ifname,
	       sizeof(target_ifname) - 1);
	if (!ifname[0] && hook->ifindex <= 0)
		return -EINVAL;
	if (hook->ifindex > 0)
		dev = dev_get_by_index(net, hook->ifindex);
	else
		dev = dev_get_by_name(net, ifname);
	if (!dev)
		return -ENODEV;
	hook_net = dev_net(dev);
	get_net(hook_net);
	if (hook->target_ifindex > 0)
		target_dev = dev_get_by_index(hook_net,
					      hook->target_ifindex);
	else if (target_ifname[0])
		target_dev = dev_get_by_name(hook_net, target_ifname);
	if ((hook->target_ifindex > 0 || target_ifname[0]) && !target_dev) {
		dev_put(dev);
		put_net(hook_net);
		return -ENODEV;
	}

	write_lock_bh(&trustix_datapath_state_lock);
	if (trustix_datapath_hook_find_locked(hook_net, dev->ifindex,
					      dev->name, true)) {
		write_unlock_bh(&trustix_datapath_state_lock);
		dev_put(dev);
		if (target_dev)
			dev_put(target_dev);
		put_net(hook_net);
		return -EALREADY;
	}
	entry = trustix_datapath_hook_free_locked();
	if (!entry) {
		write_unlock_bh(&trustix_datapath_state_lock);
		dev_put(dev);
		if (target_dev)
			dev_put(target_dev);
		put_net(hook_net);
		return -ENOSPC;
	}
	memset(entry, 0, sizeof(*entry));
	entry->in_use = true;
	entry->stats_index = entry - trustix_datapath_hooks;
	entry->net = hook_net;
	entry->target_dev = target_dev;
	entry->ifindex = dev->ifindex;
	entry->target_ifindex =
		target_dev ? target_dev->ifindex : 0;
	entry->flags =
		hook->flags & (TRUSTIX_DATAPATH_HOOK_FLAG_RX_PREVIEW |
			       TRUSTIX_DATAPATH_HOOK_FLAG_RX_STAGE |
			       TRUSTIX_DATAPATH_HOOK_FLAG_RX_WORKER |
			       TRUSTIX_DATAPATH_HOOK_FLAG_TX_PLAINTEXT |
			       TRUSTIX_DATAPATH_HOOK_FLAG_TX_SECURE_TIX_TCP |
			       TRUSTIX_DATAPATH_HOOK_FLAG_RX_SECURE_TIX_TCP_ONLY);
	strscpy(entry->ifname, dev->name, sizeof(entry->ifname));
	if (target_dev)
		strscpy(entry->target_ifname, target_dev->name,
			sizeof(entry->target_ifname));
	entry->ops.hook = trustix_datapath_nf_hook;
	entry->ops.pf = NFPROTO_IPV4;
	entry->ops.hooknum = NF_INET_PRE_ROUTING;
	entry->ops.priority = NF_IP_PRI_FIRST;
	entry->ops.dev = dev;
	entry->ops.priv = entry;
	trustix_datapath_hook_reset_counters_locked(entry);
	target_dev = NULL;
	write_unlock_bh(&trustix_datapath_state_lock);

	ret = nf_register_net_hook(hook_net, &entry->ops);
	dev_put(dev);
	if (target_dev)
		dev_put(target_dev);
	if (ret) {
		struct net_device *entry_target_dev;

		write_lock_bh(&trustix_datapath_state_lock);
		entry_target_dev = entry->target_dev;
		memset(entry, 0, sizeof(*entry));
		write_unlock_bh(&trustix_datapath_state_lock);
		if (entry_target_dev)
			dev_put(entry_target_dev);
		put_net(hook_net);
		return ret;
	}

	write_lock_bh(&trustix_datapath_state_lock);
	entry->registered = true;
	trustix_datapath_fill_hook_locked(hook, entry);
	write_unlock_bh(&trustix_datapath_state_lock);
	return 0;
}

static int
trustix_datapath_hook_detach(struct trustix_datapath_ioc_hook *hook)
{
	struct trustix_datapath_hook_entry *entry;
	struct net_device *target_dev = NULL;
	struct net *hook_net;
	struct nf_hook_ops *ops;
	struct net *net;
	char ifname[TRUSTIX_DATAPATH_IFNAME_MAX];

	net = trustix_datapath_current_net();
	memset(ifname, 0, sizeof(ifname));
	memcpy(ifname, hook->ifname, sizeof(ifname) - 1);

	write_lock_bh(&trustix_datapath_state_lock);
	entry = trustix_datapath_hook_find_locked(net, hook->ifindex, ifname,
						  false);
	if (!entry) {
		trustix_datapath_fill_hook_locked(hook, NULL);
		write_unlock_bh(&trustix_datapath_state_lock);
		return -ENOENT;
	}
	hook_net = entry->net;
	ops = &entry->ops;
	target_dev = entry->target_dev;
	entry->target_dev = NULL;
	entry->registered = false;
	trustix_datapath_fill_hook_locked(hook, NULL);
	write_unlock_bh(&trustix_datapath_state_lock);

	nf_unregister_net_hook(hook_net ? hook_net : &init_net, ops);
	trustix_datapath_rx_worker_drop_pending_sync();
	trustix_datapath_tx_plaintext_drop_pending_sync();

	write_lock_bh(&trustix_datapath_state_lock);
	entry->in_use = false;
	entry->net = NULL;
	memset(entry, 0, sizeof(*entry));
	write_unlock_bh(&trustix_datapath_state_lock);
	if (target_dev)
		dev_put(target_dev);
	if (hook_net)
		put_net(hook_net);
	return 0;
}

static void trustix_datapath_hook_detach_all(void)
{
	struct trustix_datapath_hook_entry *entry;
	struct nf_hook_ops *ops[TRUSTIX_DATAPATH_HOOK_MAX];
	struct net *nets[TRUSTIX_DATAPATH_HOOK_MAX];
	struct net_device *target_devs[TRUSTIX_DATAPATH_HOOK_MAX];
	unsigned int target_dev_count = 0;
	unsigned int count = 0;
	unsigned int i;

	write_lock_bh(&trustix_datapath_state_lock);
	for (i = 0; i < ARRAY_SIZE(trustix_datapath_hooks); i++) {
		entry = &trustix_datapath_hooks[i];
		if (!entry->registered)
			continue;
		ops[count] = &entry->ops;
		nets[count] = entry->net;
		if (entry->target_dev &&
		    target_dev_count < ARRAY_SIZE(target_devs)) {
			target_devs[target_dev_count++] = entry->target_dev;
			entry->target_dev = NULL;
		}
		entry->registered = false;
		count++;
	}
	write_unlock_bh(&trustix_datapath_state_lock);

	for (i = 0; i < count; i++)
		nf_unregister_net_hook(nets[i] ? nets[i] : &init_net, ops[i]);
	trustix_datapath_rx_worker_drop_pending_sync();
	trustix_datapath_tx_plaintext_drop_pending_sync();

	write_lock_bh(&trustix_datapath_state_lock);
	for (i = 0; i < ARRAY_SIZE(trustix_datapath_hooks); i++) {
		entry = &trustix_datapath_hooks[i];
		if (entry->target_dev &&
		    target_dev_count < ARRAY_SIZE(target_devs)) {
			target_devs[target_dev_count++] = entry->target_dev;
			entry->target_dev = NULL;
		}
		if (entry->in_use && entry->net)
			put_net(entry->net);
		memset(entry, 0, sizeof(*entry));
	}
	write_unlock_bh(&trustix_datapath_state_lock);
	for (i = 0; i < target_dev_count; i++)
		dev_put(target_devs[i]);
}

static void trustix_datapath_hook_release_netdev(struct net_device *dev)
{
	struct trustix_datapath_hook_entry *entry;
	struct trustix_datapath_hook_entry *clear[TRUSTIX_DATAPATH_HOOK_MAX];
	struct nf_hook_ops *ops[TRUSTIX_DATAPATH_HOOK_MAX];
	struct net *nets[TRUSTIX_DATAPATH_HOOK_MAX];
	struct net *put_nets[TRUSTIX_DATAPATH_HOOK_MAX];
	struct net_device *target_devs[TRUSTIX_DATAPATH_HOOK_MAX];
	unsigned int clear_count = 0;
	unsigned int count = 0;
	unsigned int put_net_count = 0;
	unsigned int target_dev_count = 0;
	unsigned int i;

	if (!dev)
		return;

	write_lock_bh(&trustix_datapath_state_lock);
	for (i = 0; i < ARRAY_SIZE(trustix_datapath_hooks); i++) {
		bool hook_dev_match;
		bool target_dev_match;

		entry = &trustix_datapath_hooks[i];
		if (!entry->in_use)
			continue;
		hook_dev_match = entry->registered &&
				 (entry->ops.dev == dev ||
				  entry->ifindex == dev->ifindex);
		target_dev_match = entry->target_dev == dev;
		if (!hook_dev_match && !target_dev_match)
			continue;
		/* A source-hook match clears the whole entry below as well. */
		if (entry->target_dev) {
			target_devs[target_dev_count++] = entry->target_dev;
			entry->target_dev = NULL;
			entry->target_ifindex = 0;
			memset(entry->target_ifname, 0,
			       sizeof(entry->target_ifname));
		}
		if (!hook_dev_match)
			continue;
		if (count < ARRAY_SIZE(ops)) {
			ops[count] = &entry->ops;
			nets[count] = entry->net;
			count++;
		}
		entry->registered = false;
		/* Keep the slot reserved until nf_unregister_net_hook returns. */
		if (clear_count < ARRAY_SIZE(clear))
			clear[clear_count++] = entry;
	}
	write_unlock_bh(&trustix_datapath_state_lock);

	for (i = 0; i < count; i++)
		nf_unregister_net_hook(nets[i] ? nets[i] : &init_net, ops[i]);

	write_lock_bh(&trustix_datapath_state_lock);
	for (i = 0; i < clear_count; i++) {
		struct net *net = clear[i]->net;

		memset(clear[i], 0, sizeof(*clear[i]));
		if (net && put_net_count < ARRAY_SIZE(put_nets))
			put_nets[put_net_count++] = net;
	}
	write_unlock_bh(&trustix_datapath_state_lock);

	for (i = 0; i < put_net_count; i++)
		put_net(put_nets[i]);
	/*
	 * A hook callback can have copied target_dev immediately before the
	 * notifier cleared the entry. Source-device matches are synchronized by
	 * nf_unregister_net_hook(), but a target-only unregister leaves the hook
	 * installed. Wait for those readers before dropping the saved device ref.
	 */
	if (target_dev_count)
		synchronize_net();
	for (i = 0; i < target_dev_count; i++)
		dev_put(target_devs[i]);
}

static void trustix_datapath_release_netdev_refs(struct net_device *dev)
{
	if (!dev)
		return;

	trustix_datapath_hook_release_netdev(dev);
	trustix_datapath_rx_worker_drop_pending_sync();
	trustix_datapath_tx_plaintext_drop_pending_sync();
}

static int trustix_datapath_netdev_event(struct notifier_block *nb,
					 unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);

	if (event == NETDEV_UNREGISTER)
		trustix_datapath_release_netdev_refs(dev);
	return NOTIFY_DONE;
}

static struct notifier_block trustix_datapath_netdev_notifier = {
	.notifier_call = trustix_datapath_netdev_event,
};

static int trustix_datapath_netevent(struct notifier_block *nb,
				     unsigned long event, void *ptr)
{
	struct neighbour *neigh = ptr;
	unsigned int invalidated;

	if (event != NETEVENT_NEIGH_UPDATE || !neigh || !neigh->dev ||
	    neigh->tbl != &arp_tbl)
		return NOTIFY_DONE;
	invalidated =
		trustix_datapath_tx_plaintext_dst_mac_cache_invalidate_ifindex(
			neigh->dev->ifindex);
	trustix_datapath_tx_plaintext_direct_xmit_dst_mac_cache_invalidations +=
		invalidated;
	return NOTIFY_DONE;
}

static struct notifier_block trustix_datapath_netevent_notifier = {
	.notifier_call = trustix_datapath_netevent,
};

static int
trustix_datapath_hook_apply(struct trustix_datapath_ioc_hook *hook)
{
	int ret = 0;

	if (!hook)
		return -EINVAL;
	switch (hook->op) {
	case TRUSTIX_DATAPATH_HOOK_OP_ATTACH:
		mutex_lock(&trustix_datapath_selftest_mutex);
		ret = trustix_datapath_hook_attach(hook);
		mutex_unlock(&trustix_datapath_selftest_mutex);
		break;
	case TRUSTIX_DATAPATH_HOOK_OP_DETACH:
		mutex_lock(&trustix_datapath_selftest_mutex);
		ret = trustix_datapath_hook_detach(hook);
		mutex_unlock(&trustix_datapath_selftest_mutex);
		break;
	case TRUSTIX_DATAPATH_HOOK_OP_QUERY:
	{
		struct trustix_datapath_hook_entry *entry;
		struct net *net = trustix_datapath_current_net();
		char ifname[TRUSTIX_DATAPATH_IFNAME_MAX];

		memset(ifname, 0, sizeof(ifname));
		memcpy(ifname, hook->ifname, sizeof(ifname) - 1);
		read_lock_bh(&trustix_datapath_state_lock);
		entry = trustix_datapath_hook_find_locked(net, hook->ifindex,
							  ifname, false);
		trustix_datapath_fill_hook_locked(hook, entry);
		read_unlock_bh(&trustix_datapath_state_lock);
		break;
	}
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

static int trustix_datapath_selftest_state_table(void)
{
	struct trustix_datapath_state_table table = {};
	struct trustix_datapath_ioc_state state = {};
	int ret;

	ret = trustix_datapath_alloc_table(&table, 2);
	if (ret)
		return ret;

	state.version = TRUSTIX_DATAPATH_IOC_VERSION;
	state.kind = TRUSTIX_DATAPATH_STATE_KIND_ROUTE;
	state.op = TRUSTIX_DATAPATH_STATE_OP_UPSERT;
	state.flags = 0x55;
	state.key[0] = 0x0a000001ULL;
	state.key[1] = 24;
	state.value[0] = 0x01020304ULL;
	state.value[1] = 1500;

	ret = trustix_datapath_state_apply_to_table(&table, &state, false);
	if (ret)
		goto out;
	if (table.count != 1) {
		ret = -EINVAL;
		goto out;
	}

	memset(state.value, 0, sizeof(state.value));
	state.flags = 0;
	state.op = TRUSTIX_DATAPATH_STATE_OP_GET;
	ret = trustix_datapath_state_apply_to_table(&table, &state, false);
	if (ret)
		goto out;
	if (state.flags != 0x55 || state.value[0] != 0x01020304ULL ||
	    state.value[1] != 1500) {
		ret = -EINVAL;
		goto out;
	}

	state.op = TRUSTIX_DATAPATH_STATE_OP_DELETE;
	ret = trustix_datapath_state_apply_to_table(&table, &state, false);
	if (ret)
		goto out;
	if (table.count != 0)
		goto invalid;

	memset(&state, 0, sizeof(state));
	state.version = TRUSTIX_DATAPATH_IOC_VERSION;
	state.kind = TRUSTIX_DATAPATH_STATE_KIND_FLOW;
	state.op = TRUSTIX_DATAPATH_STATE_OP_UPSERT;
	state.flags = 0x10;
	state.key[0] = 0x10ULL;
	state.value[0] = 0x100ULL;
	ret = trustix_datapath_state_apply_to_table(&table, &state, false);
	if (ret)
		goto out;
	memset(&state, 0, sizeof(state));
	state.version = TRUSTIX_DATAPATH_IOC_VERSION;
	state.kind = TRUSTIX_DATAPATH_STATE_KIND_FLOW;
	state.op = TRUSTIX_DATAPATH_STATE_OP_UPSERT;
	state.flags = 0x20;
	state.key[0] = 0x20ULL;
	state.value[0] = 0x200ULL;
	ret = trustix_datapath_state_apply_to_table(&table, &state, false);
	if (ret)
		goto out;
	state.op = TRUSTIX_DATAPATH_STATE_OP_DELETE;
	ret = trustix_datapath_state_apply_to_table(&table, &state, false);
	if (ret)
		goto out;
	memset(state.value, 0, sizeof(state.value));
	state.flags = 0;
	state.op = TRUSTIX_DATAPATH_STATE_OP_GET;
	state.key[0] = 0x10ULL;
	ret = trustix_datapath_state_apply_to_table(&table, &state, false);
	if (ret)
		goto out;
	if (state.flags != 0x10 || state.value[0] != 0x100ULL)
		goto invalid;
	memset(&state, 0, sizeof(state));
	state.version = TRUSTIX_DATAPATH_IOC_VERSION;
	state.kind = TRUSTIX_DATAPATH_STATE_KIND_FLOW;
	state.op = TRUSTIX_DATAPATH_STATE_OP_UPSERT;
	state.flags = 0x30;
	state.key[0] = 0x30ULL;
	state.value[0] = 0x300ULL;
	ret = trustix_datapath_state_apply_to_table(&table, &state, false);
	if (ret)
		goto out;
	if (table.count != 2)
		goto invalid;
	goto out;

invalid:
		ret = -EINVAL;

out:
	trustix_datapath_free_table(&table);
	return ret;
}

static int trustix_datapath_selftest_classify(void)
{
	struct trustix_datapath_state_table saved_routes = trustix_datapath_routes;
	struct trustix_datapath_state_table saved_sessions =
		trustix_datapath_sessions;
	struct trustix_datapath_state_table saved_flows = trustix_datapath_flows;
	struct trustix_datapath_state_table saved_session_wires =
		trustix_datapath_session_wires;
	struct trustix_datapath_ioc_state state = {};
	struct trustix_datapath_ioc_classify classify = {};
	int ret;

	memset(&trustix_datapath_routes, 0, sizeof(trustix_datapath_routes));
	memset(&trustix_datapath_sessions, 0, sizeof(trustix_datapath_sessions));
	memset(&trustix_datapath_flows, 0, sizeof(trustix_datapath_flows));
	memset(&trustix_datapath_session_wires, 0,
	       sizeof(trustix_datapath_session_wires));
	ret = trustix_datapath_alloc_table(&trustix_datapath_routes, 4);
	if (ret)
		goto restore;
	ret = trustix_datapath_alloc_table(&trustix_datapath_sessions, 4);
	if (ret)
		goto free_routes;
	ret = trustix_datapath_alloc_table(&trustix_datapath_flows, 4);
	if (ret)
		goto free_sessions;
	ret = trustix_datapath_alloc_table(&trustix_datapath_session_wires, 4);
	if (ret)
		goto free_flows;

	state.version = TRUSTIX_DATAPATH_IOC_VERSION;
	state.kind = TRUSTIX_DATAPATH_STATE_KIND_ROUTE;
	state.op = TRUSTIX_DATAPATH_STATE_OP_UPSERT;
	state.flags = TRUSTIX_DATAPATH_ROUTE_FLAG_UNICAST;
	state.key[0] = 0x0a520000ULL;
	state.key[1] = 24;
	state.key[2] = 0x1111ULL;
	state.key[3] = 0x2222ULL;
	state.value[0] = 10;
	ret = trustix_datapath_state_apply_locked(&state);
	if (ret)
		goto free_all;

	memset(&state, 0, sizeof(state));
	state.version = TRUSTIX_DATAPATH_IOC_VERSION;
	state.kind = TRUSTIX_DATAPATH_STATE_KIND_SESSION;
	state.op = TRUSTIX_DATAPATH_STATE_OP_UPSERT;
	state.flags = TRUSTIX_DATAPATH_SESSION_FLAG_KERNEL_FLOW;
	state.key[0] = 0x1111ULL;
	state.key[1] = 0x2222ULL;
	state.value[0] = 0x9988776655443322ULL;
	state.value[7] = 3;
	ret = trustix_datapath_state_apply_locked(&state);
	if (ret)
		goto free_all;

	memset(&state, 0, sizeof(state));
	state.version = TRUSTIX_DATAPATH_IOC_VERSION;
	state.kind = TRUSTIX_DATAPATH_STATE_KIND_FLOW;
	state.op = TRUSTIX_DATAPATH_STATE_OP_UPSERT;
	trustix_datapath_flow_key(state.key, 0x0a520001U, 0x0a520009U, 12345,
				  5201, 6);
	state.value[0] = 0x1111ULL;
	state.value[1] = 0x2222ULL;
	state.value[2] = 3;
	ret = trustix_datapath_state_apply_locked(&state);
	if (ret)
		goto free_all;

	classify.version = TRUSTIX_DATAPATH_IOC_VERSION;
	classify.src_ipv4 = 0x0a520001U;
	classify.dst_ipv4 = 0x0a520009U;
	classify.src_port = 12345;
	classify.dst_port = 5201;
	classify.protocol = 6;
	ret = trustix_datapath_classify_locked(&classify);
	if (ret)
		goto free_all;
	if (classify.route_flags != TRUSTIX_DATAPATH_ROUTE_FLAG_UNICAST ||
	    classify.prefix_len != 24 ||
	    classify.flow_id != 0x9988776655443322ULL ||
	    classify.session_flags != TRUSTIX_DATAPATH_SESSION_FLAG_KERNEL_FLOW) {
		ret = -EINVAL;
		goto free_all;
	}

free_all:
	trustix_datapath_free_table(&trustix_datapath_session_wires);
free_flows:
	trustix_datapath_free_table(&trustix_datapath_flows);
free_sessions:
	trustix_datapath_free_table(&trustix_datapath_sessions);
free_routes:
	trustix_datapath_free_table(&trustix_datapath_routes);
restore:
	trustix_datapath_routes = saved_routes;
	trustix_datapath_sessions = saved_sessions;
	trustix_datapath_flows = saved_flows;
	trustix_datapath_session_wires = saved_session_wires;
	return ret;
}

static void
trustix_datapath_build_ipv4_udp(__u8 *packet, __u32 packet_len,
				__u32 src_ipv4, __u32 dst_ipv4,
				__u16 src_port, __u16 dst_port)
{
	memset(packet, 0, packet_len);
	packet[0] = 0x45;
	trustix_datapath_put_be16(packet + 2, (__u16)packet_len);
	packet[8] = 64;
	packet[9] = 17;
	trustix_datapath_put_be32(packet + 12, src_ipv4);
	trustix_datapath_put_be32(packet + 16, dst_ipv4);
	trustix_datapath_put_be16(packet + 20, src_port);
	trustix_datapath_put_be16(packet + 22, dst_port);
	trustix_datapath_put_be16(packet + 24, (__u16)(packet_len - 20));
}

static int trustix_datapath_selftest_packet_classify(void)
{
	struct trustix_datapath_state_table saved_routes = trustix_datapath_routes;
	struct trustix_datapath_state_table saved_sessions =
		trustix_datapath_sessions;
	struct trustix_datapath_state_table saved_flows = trustix_datapath_flows;
	struct trustix_datapath_state_table saved_session_wires =
		trustix_datapath_session_wires;
	struct trustix_datapath_ioc_state state = {};
	struct trustix_datapath_ioc_packet_classify packet_classify = {};
	__u8 packet[60];
	__u64 saved_packets = trustix_datapath_packets_seen;
	__u64 saved_bytes = trustix_datapath_bytes_seen;
	__u64 saved_parse_errors = trustix_datapath_packet_parse_errors;
	__u64 saved_route_misses = trustix_datapath_packet_route_misses;
	__u64 saved_session_misses = trustix_datapath_packet_session_misses;
	__u64 saved_unicast = trustix_datapath_packet_unicast_routes;
	__u64 saved_local = trustix_datapath_packet_local_routes;
	__u64 saved_blackhole = trustix_datapath_packet_blackhole_routes;
	__u64 saved_reject = trustix_datapath_packet_reject_routes;
	int ret;

	memset(&trustix_datapath_routes, 0, sizeof(trustix_datapath_routes));
	memset(&trustix_datapath_sessions, 0, sizeof(trustix_datapath_sessions));
	memset(&trustix_datapath_flows, 0, sizeof(trustix_datapath_flows));
	memset(&trustix_datapath_session_wires, 0,
	       sizeof(trustix_datapath_session_wires));
	trustix_datapath_packets_seen = 0;
	trustix_datapath_bytes_seen = 0;
	trustix_datapath_packet_parse_errors = 0;
	trustix_datapath_packet_route_misses = 0;
	trustix_datapath_packet_session_misses = 0;
	trustix_datapath_packet_unicast_routes = 0;
	trustix_datapath_packet_local_routes = 0;
	trustix_datapath_packet_blackhole_routes = 0;
	trustix_datapath_packet_reject_routes = 0;

	ret = trustix_datapath_alloc_table(&trustix_datapath_routes, 4);
	if (ret)
		goto restore;
	ret = trustix_datapath_alloc_table(&trustix_datapath_sessions, 4);
	if (ret)
		goto free_routes;
	ret = trustix_datapath_alloc_table(&trustix_datapath_flows, 4);
	if (ret)
		goto free_sessions;
	ret = trustix_datapath_alloc_table(&trustix_datapath_session_wires, 4);
	if (ret)
		goto free_flows;

	state.version = TRUSTIX_DATAPATH_IOC_VERSION;
	state.kind = TRUSTIX_DATAPATH_STATE_KIND_ROUTE;
	state.op = TRUSTIX_DATAPATH_STATE_OP_UPSERT;
	state.flags = TRUSTIX_DATAPATH_ROUTE_FLAG_UNICAST;
	state.key[0] = 0x0a520000ULL;
	state.key[1] = 24;
	state.key[2] = 0x1111ULL;
	state.key[3] = 0x2222ULL;
	ret = trustix_datapath_state_apply_locked(&state);
	if (ret)
		goto free_all;

	memset(&state, 0, sizeof(state));
	state.version = TRUSTIX_DATAPATH_IOC_VERSION;
	state.kind = TRUSTIX_DATAPATH_STATE_KIND_SESSION;
	state.op = TRUSTIX_DATAPATH_STATE_OP_UPSERT;
	state.flags = TRUSTIX_DATAPATH_SESSION_FLAG_KERNEL_FLOW;
	state.key[0] = 0x1111ULL;
	state.key[1] = 0x2222ULL;
	state.value[0] = 0x9988776655443322ULL;
	state.value[7] = 3;
	ret = trustix_datapath_state_apply_locked(&state);
	if (ret)
		goto free_all;

	memset(&state, 0, sizeof(state));
	state.version = TRUSTIX_DATAPATH_IOC_VERSION;
	state.kind = TRUSTIX_DATAPATH_STATE_KIND_FLOW;
	state.op = TRUSTIX_DATAPATH_STATE_OP_UPSERT;
	trustix_datapath_flow_key(state.key, 0x0a520001U, 0x0a520009U, 12345,
				  5201, 17);
	state.value[0] = 0x1111ULL;
	state.value[1] = 0x2222ULL;
	state.value[2] = 3;
	ret = trustix_datapath_state_apply_locked(&state);
	if (ret)
		goto free_all;

	trustix_datapath_build_ipv4_udp(packet, sizeof(packet), 0x0a520001U,
					0x0a520009U, 12345, 5201);
	packet_classify.version = TRUSTIX_DATAPATH_IOC_VERSION;
	packet_classify.packet_len = sizeof(packet);
	ret = trustix_datapath_packet_classify_locked(&packet_classify, packet);
	if (ret)
		goto free_all;
	if (packet_classify.src_ipv4 != 0x0a520001U ||
	    packet_classify.dst_ipv4 != 0x0a520009U ||
	    packet_classify.src_port != 12345 ||
	    packet_classify.dst_port != 5201 ||
	    packet_classify.protocol != 17 ||
	    packet_classify.ip_header_len != 20 ||
	    packet_classify.l4_header_len != 8 ||
	    packet_classify.route_flags != TRUSTIX_DATAPATH_ROUTE_FLAG_UNICAST ||
	    packet_classify.prefix_len != 24 ||
	    packet_classify.flow_id != 0x9988776655443322ULL ||
	    packet_classify.session_flags != TRUSTIX_DATAPATH_SESSION_FLAG_KERNEL_FLOW ||
	    packet_classify.packets_seen != 1 ||
	    packet_classify.bytes_seen != sizeof(packet)) {
		ret = -EINVAL;
		goto free_all;
	}

	trustix_datapath_put_be16(packet + 2, 18);
	packet_classify = (struct trustix_datapath_ioc_packet_classify){
		.version = TRUSTIX_DATAPATH_IOC_VERSION,
		.packet_len = sizeof(packet),
	};
	ret = trustix_datapath_packet_classify_locked(&packet_classify, packet);
	if (ret != -EMSGSIZE) {
		ret = -EINVAL;
		goto free_all;
	}
	if (trustix_datapath_packet_parse_errors != 1) {
		ret = -EINVAL;
		goto free_all;
	}
	ret = 0;

free_all:
	trustix_datapath_free_table(&trustix_datapath_session_wires);
free_flows:
	trustix_datapath_free_table(&trustix_datapath_flows);
free_sessions:
	trustix_datapath_free_table(&trustix_datapath_sessions);
free_routes:
	trustix_datapath_free_table(&trustix_datapath_routes);
restore:
	trustix_datapath_routes = saved_routes;
	trustix_datapath_sessions = saved_sessions;
	trustix_datapath_flows = saved_flows;
	trustix_datapath_session_wires = saved_session_wires;
	trustix_datapath_packets_seen = saved_packets;
	trustix_datapath_bytes_seen = saved_bytes;
	trustix_datapath_packet_parse_errors = saved_parse_errors;
	trustix_datapath_packet_route_misses = saved_route_misses;
	trustix_datapath_packet_session_misses = saved_session_misses;
	trustix_datapath_packet_unicast_routes = saved_unicast;
	trustix_datapath_packet_local_routes = saved_local;
	trustix_datapath_packet_blackhole_routes = saved_blackhole;
	trustix_datapath_packet_reject_routes = saved_reject;
	return ret;
}

static int trustix_datapath_selftest_tixt_encap(void)
{
	struct trustix_datapath_state_table saved_routes = trustix_datapath_routes;
	struct trustix_datapath_state_table saved_sessions =
		trustix_datapath_sessions;
	struct trustix_datapath_state_table saved_flows = trustix_datapath_flows;
	struct trustix_datapath_state_table saved_session_wires =
		trustix_datapath_session_wires;
	struct trustix_datapath_ioc_state state = {};
	struct trustix_datapath_ioc_tixt_encap encap = {};
	struct trustix_datapath_tixt_frame frame = {};
	__u8 inner[60];
	__u8 out[TRUSTIX_DATAPATH_TIXT_HEADER_LEN + sizeof(inner)];
	int ret;

	memset(&trustix_datapath_routes, 0, sizeof(trustix_datapath_routes));
	memset(&trustix_datapath_sessions, 0, sizeof(trustix_datapath_sessions));
	memset(&trustix_datapath_flows, 0, sizeof(trustix_datapath_flows));
	memset(&trustix_datapath_session_wires, 0,
	       sizeof(trustix_datapath_session_wires));
	ret = trustix_datapath_alloc_table(&trustix_datapath_routes, 4);
	if (ret)
		goto restore;
	ret = trustix_datapath_alloc_table(&trustix_datapath_sessions, 4);
	if (ret)
		goto free_routes;
	ret = trustix_datapath_alloc_table(&trustix_datapath_flows, 4);
	if (ret)
		goto free_sessions;
	ret = trustix_datapath_alloc_table(&trustix_datapath_session_wires, 4);
	if (ret)
		goto free_flows;

	state.version = TRUSTIX_DATAPATH_IOC_VERSION;
	state.kind = TRUSTIX_DATAPATH_STATE_KIND_ROUTE;
	state.op = TRUSTIX_DATAPATH_STATE_OP_UPSERT;
	state.flags = TRUSTIX_DATAPATH_ROUTE_FLAG_UNICAST;
	state.key[0] = 0x0a520000ULL;
	state.key[1] = 24;
	state.key[2] = 0x1111ULL;
	state.key[3] = 0x2222ULL;
	ret = trustix_datapath_state_apply_locked(&state);
	if (ret)
		goto free_all;

	memset(&state, 0, sizeof(state));
	state.version = TRUSTIX_DATAPATH_IOC_VERSION;
	state.kind = TRUSTIX_DATAPATH_STATE_KIND_SESSION;
	state.op = TRUSTIX_DATAPATH_STATE_OP_UPSERT;
	state.flags = TRUSTIX_DATAPATH_SESSION_FLAG_KERNEL_FLOW;
	state.key[0] = 0x1111ULL;
	state.key[1] = 0x2222ULL;
	state.value[0] = 0x9988776655443322ULL;
	ret = trustix_datapath_state_apply_locked(&state);
	if (ret)
		goto free_all;

	trustix_datapath_build_ipv4_udp(inner, sizeof(inner), 0x0a520001U,
					0x0a520009U, 12345, 5201);
	encap.version = TRUSTIX_DATAPATH_IOC_VERSION;
	encap.inner_len = sizeof(inner);
	encap.out_len = sizeof(out);
	encap.sequence = 77;
	ret = trustix_datapath_tixt_encap_locked(&encap, inner, out);
	if (ret)
		goto free_all;
	if (encap.written_len != sizeof(out) ||
	    encap.flow_id != 0x9988776655443322ULL ||
	    encap.route_flags != TRUSTIX_DATAPATH_ROUTE_FLAG_UNICAST ||
	    encap.prefix_len != 24 ||
	    encap.session_flags != TRUSTIX_DATAPATH_SESSION_FLAG_KERNEL_FLOW) {
		ret = -EINVAL;
		goto free_all;
	}
	ret = trustix_datapath_parse_tixt(out, encap.written_len, &frame);
	if (ret)
		goto free_all;
	if (frame.flags != TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4 ||
	    frame.flow_id != 0x9988776655443322ULL || frame.sequence != 77 ||
	    frame.payload_len != sizeof(inner) ||
	    memcmp(out + TRUSTIX_DATAPATH_TIXT_HEADER_LEN, inner,
		   sizeof(inner))) {
		ret = -EINVAL;
		goto free_all;
	}

free_all:
	trustix_datapath_free_table(&trustix_datapath_session_wires);
free_flows:
	trustix_datapath_free_table(&trustix_datapath_flows);
free_sessions:
	trustix_datapath_free_table(&trustix_datapath_sessions);
free_routes:
	trustix_datapath_free_table(&trustix_datapath_routes);
restore:
	trustix_datapath_routes = saved_routes;
	trustix_datapath_sessions = saved_sessions;
	trustix_datapath_flows = saved_flows;
	trustix_datapath_session_wires = saved_session_wires;
	return ret;
}

static int trustix_datapath_selftest_tixt_decap(void)
{
	struct trustix_datapath_state_table saved_routes = trustix_datapath_routes;
	struct trustix_datapath_state_table saved_sessions =
		trustix_datapath_sessions;
	struct trustix_datapath_state_table saved_flows = trustix_datapath_flows;
	struct trustix_datapath_state_table saved_session_wires =
		trustix_datapath_session_wires;
	struct trustix_datapath_ioc_state state = {};
	struct trustix_datapath_ioc_tixt_encap encap = {};
	struct trustix_datapath_ioc_tixt_decap decap = {};
	__u8 inner[60];
	__u8 wire[TRUSTIX_DATAPATH_TIXT_HEADER_LEN + sizeof(inner)];
	__u8 out[sizeof(inner)];
	int ret;

	memset(&trustix_datapath_routes, 0, sizeof(trustix_datapath_routes));
	memset(&trustix_datapath_sessions, 0, sizeof(trustix_datapath_sessions));
	memset(&trustix_datapath_flows, 0, sizeof(trustix_datapath_flows));
	memset(&trustix_datapath_session_wires, 0,
	       sizeof(trustix_datapath_session_wires));
	ret = trustix_datapath_alloc_table(&trustix_datapath_routes, 4);
	if (ret)
		goto restore;
	ret = trustix_datapath_alloc_table(&trustix_datapath_sessions, 4);
	if (ret)
		goto free_routes;
	ret = trustix_datapath_alloc_table(&trustix_datapath_flows, 4);
	if (ret)
		goto free_sessions;
	ret = trustix_datapath_alloc_table(&trustix_datapath_session_wires, 4);
	if (ret)
		goto free_flows;

	state.version = TRUSTIX_DATAPATH_IOC_VERSION;
	state.kind = TRUSTIX_DATAPATH_STATE_KIND_ROUTE;
	state.op = TRUSTIX_DATAPATH_STATE_OP_UPSERT;
	state.flags = TRUSTIX_DATAPATH_ROUTE_FLAG_UNICAST;
	state.key[0] = 0x0a520000ULL;
	state.key[1] = 24;
	state.key[2] = 0x1111ULL;
	state.key[3] = 0x2222ULL;
	ret = trustix_datapath_state_apply_locked(&state);
	if (ret)
		goto free_all;

	memset(&state, 0, sizeof(state));
	state.version = TRUSTIX_DATAPATH_IOC_VERSION;
	state.kind = TRUSTIX_DATAPATH_STATE_KIND_SESSION;
	state.op = TRUSTIX_DATAPATH_STATE_OP_UPSERT;
	state.flags = TRUSTIX_DATAPATH_SESSION_FLAG_KERNEL_FLOW;
	state.key[0] = 0x1111ULL;
	state.key[1] = 0x2222ULL;
	state.value[0] = 0x9988776655443322ULL;
	ret = trustix_datapath_state_apply_locked(&state);
	if (ret)
		goto free_all;

	trustix_datapath_build_ipv4_udp(inner, sizeof(inner), 0x0a520001U,
					0x0a520009U, 12345, 5201);
	encap.version = TRUSTIX_DATAPATH_IOC_VERSION;
	encap.inner_len = sizeof(inner);
	encap.out_len = sizeof(wire);
	encap.sequence = 88;
	ret = trustix_datapath_tixt_encap_locked(&encap, inner, wire);
	if (ret)
		goto free_all;

	decap.version = TRUSTIX_DATAPATH_IOC_VERSION;
	decap.wire_len = encap.written_len;
	decap.out_len = sizeof(out);
	ret = trustix_datapath_tixt_decap_locked(&decap, wire, out);
	if (ret)
		goto free_all;
	if (decap.written_len != sizeof(inner) ||
	    decap.flow_id != 0x9988776655443322ULL || decap.sequence != 88 ||
	    decap.payload_len != sizeof(inner) ||
	    decap.tixt_flags != TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4 ||
	    decap.session_flags != TRUSTIX_DATAPATH_SESSION_FLAG_KERNEL_FLOW ||
	    memcmp(out, inner, sizeof(inner))) {
		ret = -EINVAL;
		goto free_all;
	}

free_all:
	trustix_datapath_free_table(&trustix_datapath_session_wires);
free_flows:
	trustix_datapath_free_table(&trustix_datapath_flows);
free_sessions:
	trustix_datapath_free_table(&trustix_datapath_sessions);
free_routes:
	trustix_datapath_free_table(&trustix_datapath_routes);
restore:
	trustix_datapath_routes = saved_routes;
	trustix_datapath_sessions = saved_sessions;
	trustix_datapath_flows = saved_flows;
	trustix_datapath_session_wires = saved_session_wires;
	return ret;
}

static int trustix_datapath_selftest_tix_tcp_shard_sequences(void)
{
	struct trustix_datapath_tx_plan plan = {};
	struct sk_buff *skb = NULL;
	struct tcphdr *tcph;
	struct iphdr *iph;
	atomic64_t *sequences = READ_ONCE(
		trustix_datapath_outer_tcp_shard_sequences);
	__u64 saved_features = READ_ONCE(trustix_datapath_features);
	__u64 saved_hits =
		trustix_datapath_tx_plaintext_tix_tcp_shard_sequence_hits;
	__u64 saved_fallbacks =
		trustix_datapath_tx_plaintext_tix_tcp_shard_sequence_fallbacks;
	__s64 saved_first;
	__s64 saved_second;
	__sum16 partial_check;
	__u8 *packet;
	__u32 first_index = 3;
	__u32 second_index = TRUSTIX_DATAPATH_TIX_TCP_PORT_SHARDS + 3;
	__u32 outer_len = sizeof(*iph) + sizeof(*tcph) + 64;
	unsigned int i;
	int ret = 0;

	if (!sequences ||
	    READ_ONCE(trustix_datapath_outer_tcp_sequence_flow_slots) < 2)
		return -EINVAL;
	saved_first = atomic64_read(&sequences[first_index]);
	saved_second = atomic64_read(&sequences[second_index]);
	atomic64_set(&sequences[first_index], 1000);
	atomic64_set(&sequences[second_index], 2000);
	WRITE_ONCE(trustix_datapath_features,
		   saved_features |
			   TRUSTIX_DATAPATH_FEATURE_TIX_TCP_PORT_SHARDING);
	plan.outer_protocol = IPPROTO_TCP;
	plan.session_flags =
		TRUSTIX_DATAPATH_SESSION_FLAG_SEND_TIX_TCP_PORT_SHARDING;
	plan.outer_tcp_port_shard = 3;
	plan.outer_tcp_sequence_flow_slot = 0;
	if (trustix_datapath_tx_outer_tcp_next_seq(&plan, 100) != 1000 ||
	    trustix_datapath_tx_outer_tcp_next_seq(&plan, 50) != 1100) {
		ret = -EINVAL;
		goto restore;
	}
	plan.outer_tcp_sequence_flow_slot = 1;
	if (trustix_datapath_tx_outer_tcp_next_seq(&plan, 75) != 2000) {
		ret = -EINVAL;
		goto restore;
	}

	/* Final sequence assignment must also repair a software checksum. */
	skb = alloc_skb(outer_len, GFP_KERNEL);
	if (!skb) {
		ret = -ENOMEM;
		goto restore;
	}
	packet = skb_put(skb, outer_len);
	memset(packet, 0, outer_len);
	trustix_datapath_build_outer_ipv4(packet, outer_len, IPPROTO_TCP,
					 0xc0000201U, 0xc6336402U);
	trustix_datapath_put_be16(packet + sizeof(*iph), 12345);
	trustix_datapath_put_be16(packet + sizeof(*iph) + 2, 443);
	packet[sizeof(*iph) + 12] = 0x50;
	packet[sizeof(*iph) + 13] = 0x18;
	trustix_datapath_put_be16(packet + sizeof(*iph) + 14, 65535);
	for (i = sizeof(*iph) + sizeof(*tcph); i < outer_len; i++)
		packet[i] = (__u8)(i * 17U + 3U);
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, sizeof(*iph));
	iph = ip_hdr(skb);
	tcph = tcp_hdr(skb);
	tcph->check = trustix_datapath_rx_worker_l4_checksum(
		iph, tcph, outer_len - sizeof(*iph), IPPROTO_TCP);
	skb->ip_summed = CHECKSUM_NONE;
	plan.outer_tcp_sequence_flow_slot = 0;
	atomic64_set(&sequences[first_index], 3000);
	ret = trustix_datapath_tx_assign_outer_tcp_sequence(skb, &plan);
	if (ret || ntohl(tcph->seq) != 3000 ||
	    trustix_datapath_rx_worker_l4_checksum(
		    iph, tcph, outer_len - sizeof(*iph), IPPROTO_TCP)) {
		ret = ret ?: -EINVAL;
		goto restore;
	}

	/* CHECKSUM_PARTIAL stores only the pseudo-header seed. */
	tcph->seq = 0;
	tcph->check = ~csum_tcpudp_magic(
		iph->saddr, iph->daddr, outer_len - sizeof(*iph),
		IPPROTO_TCP, 0);
	partial_check = tcph->check;
	skb->ip_summed = CHECKSUM_PARTIAL;
	atomic64_set(&sequences[first_index], 4000);
	ret = trustix_datapath_tx_assign_outer_tcp_sequence(skb, &plan);
	if (ret || ntohl(tcph->seq) != 4000 || tcph->check != partial_check)
		ret = ret ?: -EINVAL;

restore:
	kfree_skb(skb);
	atomic64_set(&sequences[first_index], saved_first);
	atomic64_set(&sequences[second_index], saved_second);
	trustix_datapath_tx_plaintext_tix_tcp_shard_sequence_hits = saved_hits;
	trustix_datapath_tx_plaintext_tix_tcp_shard_sequence_fallbacks =
		saved_fallbacks;
	WRITE_ONCE(trustix_datapath_features, saved_features);
	return ret;
}

static int trustix_datapath_selftest_session_wire(void)
{
	static const __u16 parallel_tcp_ports[] = {
		48500, 48501, 48503, 48504,
	};
	struct trustix_datapath_state_table table = {};
	struct trustix_datapath_ioc_classify classify = {
		.src_ipv4 = 0x0a00400aU,
		.dst_ipv4 = 0x0a01400aU,
		.dst_port = 15201,
		.protocol = IPPROTO_TCP,
	};
	struct trustix_datapath_ioc_state state = {};
	struct trustix_datapath_state_slot session = {};
	struct trustix_datapath_state_slot wire = {};
	__u64 saved_features = READ_ONCE(trustix_datapath_features);
	__u16 shard_mask = 0;
	bool reverse = false;
	__u8 shard = 0;
	unsigned int i;
	int ret;

	ret = trustix_datapath_selftest_tix_tcp_shard_sequences();
	if (ret)
		return ret;

	if (trustix_datapath_tix_tcp_port_for_shard(20000, 0) != 20000 ||
	    trustix_datapath_tix_tcp_port_for_shard(20000, 15) != 20015 ||
	    trustix_datapath_tix_tcp_port_for_shard(65535, 0) != 65535 ||
	    trustix_datapath_tix_tcp_port_for_shard(65535, 15) != 65520 ||
	    !trustix_datapath_tix_tcp_port_shard_match(20000, 20007,
						 &shard) ||
	    shard != 7 ||
	    trustix_datapath_tix_tcp_port_shard_match(20000, 19999, NULL))
		return -EINVAL;
	for (i = 0; i < ARRAY_SIZE(parallel_tcp_ports); i++) {
		classify.src_port = parallel_tcp_ports[i];
		shard = trustix_datapath_tix_tcp_port_shard_for_hash(
			trustix_datapath_inner_flow_hash(&classify));
		if (!shard)
			return -EINVAL;
		shard_mask |= BIT(shard);
	}
	if (hweight16(shard_mask) != ARRAY_SIZE(parallel_tcp_ports))
		return -EINVAL;

	ret = trustix_datapath_alloc_table(&table, 2);
	if (ret)
		return ret;

	state.version = TRUSTIX_DATAPATH_IOC_VERSION;
	state.kind = TRUSTIX_DATAPATH_STATE_KIND_SESSION_WIRE;
	state.op = TRUSTIX_DATAPATH_STATE_OP_UPSERT;
	state.flags = 0x7;
	state.key[0] = 0x1111ULL;
	state.key[1] = 0x2222ULL;
	state.key[2] = 0x3333ULL;
	state.key[3] = 0x4444ULL;
	state.value[0] = 0x9988776655443322ULL;
	state.value[1] = 0xc0000201ULL;
	state.value[2] = 0xc6336402ULL;
	state.value[3] = (51820ULL << 16) | 17041ULL;
	state.value[4] = 1;
	state.value[5] = 64000;
	state.value[6] = 9;
	state.value[7] = 2;

	ret = trustix_datapath_state_apply_to_table(&table, &state, false);
	if (ret)
		goto out;

	memset(state.value, 0, sizeof(state.value));
	state.flags = 0;
	state.op = TRUSTIX_DATAPATH_STATE_OP_GET;
	ret = trustix_datapath_state_apply_to_table(&table, &state, false);
	if (ret)
		goto delete_record;
	if (state.flags != 0x7 ||
	    state.value[0] != 0x9988776655443322ULL ||
	    state.value[1] != 0xc0000201ULL ||
	    state.value[2] != 0xc6336402ULL ||
	    state.value[3] != ((51820ULL << 16) | 17041ULL) ||
	    state.value[4] != 1 || state.value[5] != 64000 ||
	    state.value[6] != 9 || state.value[7] != 2)
		ret = -EINVAL;
	if (ret)
		goto delete_record;

	session.used = true;
	session.flags = TRUSTIX_DATAPATH_SESSION_FLAG_KERNEL_FLOW |
			TRUSTIX_DATAPATH_SESSION_FLAG_SEND_TIX_TCP_PORT_SHARDING |
			TRUSTIX_DATAPATH_SESSION_FLAG_RECEIVE_TIX_TCP_PORT_SHARDING;
	session.value[0] = 0x9988776655443322ULL;
	wire.used = true;
	wire.value[0] = session.value[0];
	wire.value[1] = 0xc0000201ULL;
	wire.value[2] = 0xc6336402ULL;
	wire.value[3] = (20000ULL << 16) | 30000ULL;
	wire.value[4] = TRUSTIX_DATAPATH_TRANSPORT_TIX_TCP;
	WRITE_ONCE(trustix_datapath_features,
		   saved_features |
			   TRUSTIX_DATAPATH_FEATURE_TIX_TCP_PORT_SHARDING);
	if (!trustix_datapath_session_wire_tuple_matches_locked(
		    &wire, &session, 0xc0000201U, 0xc6336402U, 20003,
		    30000, &reverse, &shard) || reverse || shard != 3 ||
	    !trustix_datapath_session_wire_tuple_matches_locked(
		    &wire, &session, 0xc6336402U, 0xc0000201U, 30005,
		    20000, &reverse, &shard) || !reverse || shard != 5) {
		ret = -EINVAL;
		goto restore_features;
	}
	session.flags &=
		~TRUSTIX_DATAPATH_SESSION_FLAG_RECEIVE_TIX_TCP_PORT_SHARDING;
	if (trustix_datapath_session_wire_tuple_matches_locked(
		    &wire, &session, 0xc6336402U, 0xc0000201U, 30005,
		    20000, &reverse, &shard))
		ret = -EINVAL;

restore_features:
	WRITE_ONCE(trustix_datapath_features, saved_features);

delete_record:
	state.op = TRUSTIX_DATAPATH_STATE_OP_DELETE;
	(void)trustix_datapath_state_apply_to_table(&table, &state, false);
out:
	trustix_datapath_free_table(&table);
	return ret;
}

static int trustix_datapath_selftest_tx_plaintext_payload_copy_csum(void)
{
	__u8 packet[sizeof(struct iphdr) + 24 + 33] __aligned(4);
	__u8 copied_payload[33];
	const __u32 tcp_header_lens[] = { sizeof(struct tcphdr), 24 };
	const __u32 payload_lens[] = { 32, 33 };
	struct tcphdr *tcph;
	struct iphdr *iph;
	__sum16 expected;
	__sum16 merged;
	__wsum chunked_sum;
	__wsum payload_sum;
	unsigned int i;
	unsigned int j;

	for (i = 0; i < ARRAY_SIZE(tcp_header_lens); i++) {
		for (j = 0; j < ARRAY_SIZE(payload_lens); j++) {
			__u32 tcp_header_len = tcp_header_lens[i];
			__u32 payload_len = payload_lens[j];
			__u8 *payload;
			unsigned int k;
			unsigned int split;

			memset(packet, 0, sizeof(packet));
			iph = (struct iphdr *)packet;
			tcph = (struct tcphdr *)(packet + sizeof(*iph));
			payload = (__u8 *)tcph + tcp_header_len;
			iph->saddr = htonl(0xc0000201U);
			iph->daddr = htonl(0xc6336402U);
			tcph->source = htons(12345);
			tcph->dest = htons(443);
			tcph->seq = htonl(0x10203040U);
			tcph->doff = tcp_header_len / 4;
			tcph->ack = 1;
			for (k = 0; k < tcp_header_len - sizeof(*tcph); k++)
				((__u8 *)(tcph + 1))[k] = (__u8)(0xa0U + k);
			for (k = 0; k < payload_len; k++)
				payload[k] = (__u8)(k * 17U + 3U);

			tcph->check = 0;
			expected = trustix_datapath_rx_worker_l4_checksum(
				iph, tcph, tcp_header_len + payload_len,
				IPPROTO_TCP);
			payload_sum = csum_partial(payload, payload_len, 0);
			merged = trustix_datapath_tx_plaintext_tcp_checksum(
				iph, tcph, tcp_header_len, payload_len, true,
				payload_sum);
			if (merged != expected)
				return -EINVAL;

			memset(copied_payload, 0, sizeof(copied_payload));
			payload_sum = csum_partial_copy_nocheck(
				payload, copied_payload, payload_len);
			if (memcmp(copied_payload, payload, payload_len) ||
			    trustix_datapath_tx_plaintext_tcp_checksum(
				    iph, tcph, tcp_header_len, payload_len, true,
				    payload_sum) != expected)
				return -EINVAL;

			for (split = 1; split < payload_len; split++) {
				memset(copied_payload, 0,
				       sizeof(copied_payload));
				chunked_sum = csum_partial_copy_nocheck(
					payload, copied_payload, split);
				payload_sum = csum_partial_copy_nocheck(
					payload + split,
					copied_payload + split,
					payload_len - split);
				chunked_sum = csum_block_add(
					chunked_sum, payload_sum, split);
				if (memcmp(copied_payload, payload, payload_len) ||
				    trustix_datapath_tx_plaintext_tcp_checksum(
					    iph, tcph, tcp_header_len,
					    payload_len, true, chunked_sum) !=
					    expected)
					return -EINVAL;
			}
			if (trustix_datapath_tx_plaintext_tcp_checksum(
				    iph, tcph, tcp_header_len, payload_len, false,
				    0) != expected)
				return -EINVAL;
		}
	}
	return 0;
}

static int trustix_datapath_selftest_outer_build(void)
{
	struct trustix_datapath_state_table saved_routes = trustix_datapath_routes;
	struct trustix_datapath_state_table saved_sessions =
		trustix_datapath_sessions;
	struct trustix_datapath_state_table saved_flows = trustix_datapath_flows;
	struct trustix_datapath_state_table saved_session_wires =
		trustix_datapath_session_wires;
	struct trustix_datapath_ioc_state state = {};
	struct trustix_datapath_ioc_outer_build build = {};
	__u8 inner[60];
	__u8 out[20 + 8 + TRUSTIX_DATAPATH_TIXT_HEADER_LEN + sizeof(inner)];
	int ret;

	memset(&trustix_datapath_routes, 0, sizeof(trustix_datapath_routes));
	memset(&trustix_datapath_sessions, 0, sizeof(trustix_datapath_sessions));
	memset(&trustix_datapath_flows, 0, sizeof(trustix_datapath_flows));
	memset(&trustix_datapath_session_wires, 0,
	       sizeof(trustix_datapath_session_wires));
	ret = trustix_datapath_alloc_table(&trustix_datapath_routes, 4);
	if (ret)
		goto restore;
	ret = trustix_datapath_alloc_table(&trustix_datapath_sessions, 4);
	if (ret)
		goto free_routes;
	ret = trustix_datapath_alloc_table(&trustix_datapath_flows, 4);
	if (ret)
		goto free_sessions;
	ret = trustix_datapath_alloc_table(&trustix_datapath_session_wires, 4);
	if (ret)
		goto free_flows;

	state.version = TRUSTIX_DATAPATH_IOC_VERSION;
	state.kind = TRUSTIX_DATAPATH_STATE_KIND_ROUTE;
	state.op = TRUSTIX_DATAPATH_STATE_OP_UPSERT;
	state.flags = TRUSTIX_DATAPATH_ROUTE_FLAG_UNICAST;
	state.key[0] = 0x0a520000ULL;
	state.key[1] = 24;
	state.key[2] = 0x1111ULL;
	state.key[3] = 0x2222ULL;
	ret = trustix_datapath_state_apply_locked(&state);
	if (ret)
		goto free_all;

	memset(&state, 0, sizeof(state));
	state.version = TRUSTIX_DATAPATH_IOC_VERSION;
	state.kind = TRUSTIX_DATAPATH_STATE_KIND_SESSION;
	state.op = TRUSTIX_DATAPATH_STATE_OP_UPSERT;
	state.flags = TRUSTIX_DATAPATH_SESSION_FLAG_KERNEL_FLOW |
		      TRUSTIX_DATAPATH_SESSION_FLAG_SYNTHETIC_FALLBACK;
	state.key[0] = 0x1111ULL;
	state.key[1] = 0x2222ULL;
	state.key[3] = 0x3333ULL;
	state.value[0] = 0x1122334455667788ULL;
	state.value[1] = TRUSTIX_DATAPATH_TRANSPORT_UDP;
	state.value[7] = 3;
	ret = trustix_datapath_state_apply_locked(&state);
	if (ret)
		goto free_all;

	memset(&state, 0, sizeof(state));
	state.version = TRUSTIX_DATAPATH_IOC_VERSION;
	state.kind = TRUSTIX_DATAPATH_STATE_KIND_SESSION_WIRE;
	state.op = TRUSTIX_DATAPATH_STATE_OP_UPSERT;
	state.flags = 0x7;
	state.key[0] = 0x1111ULL;
	state.key[1] = 0x2222ULL;
	state.key[3] = 0x3333ULL;
	state.value[0] = 0x1122334455667788ULL;
	state.value[1] = 0xc0000201ULL;
	state.value[2] = 0xc6336402ULL;
	state.value[3] = (51820ULL << 16) | 17041ULL;
	state.value[4] = TRUSTIX_DATAPATH_TRANSPORT_UDP;
	state.value[5] = sizeof(out);
	state.value[6] = 9;
	state.value[7] = 3;
	ret = trustix_datapath_state_apply_locked(&state);
	if (ret)
		goto free_all;

	memset(&state, 0, sizeof(state));
	state.version = TRUSTIX_DATAPATH_IOC_VERSION;
	state.kind = TRUSTIX_DATAPATH_STATE_KIND_SESSION;
	state.op = TRUSTIX_DATAPATH_STATE_OP_UPSERT;
	state.flags = TRUSTIX_DATAPATH_SESSION_FLAG_KERNEL_FLOW;
	state.key[0] = 0x1111ULL;
	state.key[1] = 0x2222ULL;
	state.value[0] = 0x9988776655443322ULL;
	state.value[1] = TRUSTIX_DATAPATH_TRANSPORT_UDP;
	state.value[7] = 3;
	ret = trustix_datapath_state_apply_locked(&state);
	if (ret)
		goto free_all;

	memset(&state, 0, sizeof(state));
	state.version = TRUSTIX_DATAPATH_IOC_VERSION;
	state.kind = TRUSTIX_DATAPATH_STATE_KIND_SESSION_WIRE;
	state.op = TRUSTIX_DATAPATH_STATE_OP_UPSERT;
	state.flags = 0x7;
	state.key[0] = 0x1111ULL;
	state.key[1] = 0x2222ULL;
	state.value[0] = 0x9988776655443322ULL;
	state.value[1] = 0xc0000201ULL;
	state.value[2] = 0xc6336402ULL;
	state.value[3] = (51820ULL << 16) | 17041ULL;
	state.value[4] = TRUSTIX_DATAPATH_TRANSPORT_UDP;
	state.value[5] = sizeof(out);
	state.value[6] = 9;
	ret = trustix_datapath_state_apply_locked(&state);
	if (ret)
		goto free_all;

	memset(&state, 0, sizeof(state));
	state.version = TRUSTIX_DATAPATH_IOC_VERSION;
	state.kind = TRUSTIX_DATAPATH_STATE_KIND_FLOW;
	state.op = TRUSTIX_DATAPATH_STATE_OP_UPSERT;
	trustix_datapath_flow_key(state.key, 0x0a520001U, 0x0a520009U, 12345,
				  5201, 17);
	state.value[0] = 0x1111ULL;
	state.value[1] = 0x2222ULL;
	state.value[2] = 3;
	ret = trustix_datapath_state_apply_locked(&state);
	if (ret)
		goto free_all;

	trustix_datapath_build_ipv4_udp(inner, sizeof(inner), 0x0a520001U,
					0x0a520009U, 12345, 5201);
	build.version = TRUSTIX_DATAPATH_IOC_VERSION;
	build.inner_len = sizeof(inner);
	build.out_len = sizeof(out);
	build.sequence = 123;
	ret = trustix_datapath_outer_build_locked(&build, inner, out);
	if (ret)
		goto free_all;
	if (build.written_len != sizeof(out) ||
	    build.flow_id != 0x1122334455667788ULL ||
	    build.epoch != 9 ||
	    build.route_flags != TRUSTIX_DATAPATH_ROUTE_FLAG_UNICAST ||
	    build.prefix_len != 24 ||
	    build.session_flags !=
		    (TRUSTIX_DATAPATH_SESSION_FLAG_KERNEL_FLOW |
		     TRUSTIX_DATAPATH_SESSION_FLAG_SYNTHETIC_FALLBACK) ||
	    build.local_ipv4 != 0xc0000201U ||
	    build.remote_ipv4 != 0xc6336402U ||
	    build.local_port != 51820 ||
	    build.remote_port != 17041 ||
	    build.outer_protocol != IPPROTO_UDP ||
	    build.tixt_len != TRUSTIX_DATAPATH_TIXT_HEADER_LEN + sizeof(inner) ||
	    out[9] != IPPROTO_UDP ||
	    trustix_datapath_get_be32(out + 12) != 0xc0000201U ||
	    trustix_datapath_get_be32(out + 16) != 0xc6336402U ||
	    trustix_datapath_get_be16(out + 20) != 51820 ||
	    trustix_datapath_get_be16(out + 22) != 17041 ||
	    trustix_datapath_get_be32(out + 28) != TRUSTIX_DATAPATH_TIXT_MAGIC ||
	    trustix_datapath_get_be64(out + 36) != 0x1122334455667788ULL ||
	    trustix_datapath_get_be64(out + 52) != 123 ||
	    memcmp(out + 28 + TRUSTIX_DATAPATH_TIXT_HEADER_LEN, inner,
		   sizeof(inner))) {
		ret = -EINVAL;
		goto free_all;
	}

free_all:
	trustix_datapath_free_table(&trustix_datapath_session_wires);
free_flows:
	trustix_datapath_free_table(&trustix_datapath_flows);
free_sessions:
	trustix_datapath_free_table(&trustix_datapath_sessions);
free_routes:
	trustix_datapath_free_table(&trustix_datapath_routes);
restore:
	trustix_datapath_routes = saved_routes;
	trustix_datapath_sessions = saved_sessions;
	trustix_datapath_flows = saved_flows;
	trustix_datapath_session_wires = saved_session_wires;
	return ret;
}

static int trustix_datapath_selftest_outer_parse(void)
{
	struct trustix_datapath_state_table saved_routes = trustix_datapath_routes;
	struct trustix_datapath_state_table saved_sessions =
		trustix_datapath_sessions;
	struct trustix_datapath_state_table saved_flows = trustix_datapath_flows;
	struct trustix_datapath_state_table saved_session_wires =
		trustix_datapath_session_wires;
	struct trustix_datapath_ioc_state state = {};
	struct trustix_datapath_ioc_outer_build build = {};
	struct trustix_datapath_ioc_outer_parse parse = {};
	struct trustix_datapath_state_slot *session = NULL;
	__u8 inner[60];
	__u8 outer[20 + 8 + TRUSTIX_DATAPATH_TIXT_HEADER_LEN + sizeof(inner)];
	__u8 out[sizeof(inner)];
	__u8 ip_header_len = 0;
	__u8 l4_header_len = 0;
	int ret;

	memset(&trustix_datapath_routes, 0, sizeof(trustix_datapath_routes));
	memset(&trustix_datapath_sessions, 0, sizeof(trustix_datapath_sessions));
	memset(&trustix_datapath_flows, 0, sizeof(trustix_datapath_flows));
	memset(&trustix_datapath_session_wires, 0,
	       sizeof(trustix_datapath_session_wires));
	ret = trustix_datapath_alloc_table(&trustix_datapath_routes, 4);
	if (ret)
		goto restore;
	ret = trustix_datapath_alloc_table(&trustix_datapath_sessions, 4);
	if (ret)
		goto free_routes;
	ret = trustix_datapath_alloc_table(&trustix_datapath_flows, 4);
	if (ret)
		goto free_sessions;
	ret = trustix_datapath_alloc_table(&trustix_datapath_session_wires, 4);
	if (ret)
		goto free_flows;

	state.version = TRUSTIX_DATAPATH_IOC_VERSION;
	state.kind = TRUSTIX_DATAPATH_STATE_KIND_ROUTE;
	state.op = TRUSTIX_DATAPATH_STATE_OP_UPSERT;
	state.flags = TRUSTIX_DATAPATH_ROUTE_FLAG_UNICAST;
	state.key[0] = 0x0a520000ULL;
	state.key[1] = 24;
	state.key[2] = 0x1111ULL;
	state.key[3] = 0x2222ULL;
	ret = trustix_datapath_state_apply_locked(&state);
	if (ret)
		goto free_all;

	memset(&state, 0, sizeof(state));
	state.version = TRUSTIX_DATAPATH_IOC_VERSION;
	state.kind = TRUSTIX_DATAPATH_STATE_KIND_SESSION;
	state.op = TRUSTIX_DATAPATH_STATE_OP_UPSERT;
	state.flags = TRUSTIX_DATAPATH_SESSION_FLAG_KERNEL_FLOW;
	state.key[0] = 0x1111ULL;
	state.key[1] = 0x2222ULL;
	state.value[0] = 0x9988776655443322ULL;
	state.value[1] = TRUSTIX_DATAPATH_TRANSPORT_UDP;
	state.value[7] = 3;
	ret = trustix_datapath_state_apply_locked(&state);
	if (ret)
		goto free_all;

	memset(&state, 0, sizeof(state));
	state.version = TRUSTIX_DATAPATH_IOC_VERSION;
	state.kind = TRUSTIX_DATAPATH_STATE_KIND_SESSION_WIRE;
	state.op = TRUSTIX_DATAPATH_STATE_OP_UPSERT;
	state.flags = 0x7;
	state.key[0] = 0x1111ULL;
	state.key[1] = 0x2222ULL;
	state.value[0] = 0x9988776655443322ULL;
	state.value[1] = 0xc0000201ULL;
	state.value[2] = 0xc6336402ULL;
	state.value[3] = (51820ULL << 16) | 17041ULL;
	state.value[4] = TRUSTIX_DATAPATH_TRANSPORT_UDP;
	state.value[5] = sizeof(outer);
	state.value[6] = 9;
	ret = trustix_datapath_state_apply_locked(&state);
	if (ret)
		goto free_all;

	memset(&state, 0, sizeof(state));
	state.version = TRUSTIX_DATAPATH_IOC_VERSION;
	state.kind = TRUSTIX_DATAPATH_STATE_KIND_FLOW;
	state.op = TRUSTIX_DATAPATH_STATE_OP_UPSERT;
	trustix_datapath_flow_key(state.key, 0x0a520001U, 0x0a520009U, 12345,
				  5201, 17);
	state.value[0] = 0x1111ULL;
	state.value[1] = 0x2222ULL;
	state.value[2] = 3;
	ret = trustix_datapath_state_apply_locked(&state);
	if (ret)
		goto free_all;

	trustix_datapath_build_ipv4_udp(inner, sizeof(inner), 0x0a520001U,
					0x0a520009U, 12345, 5201);
	build.version = TRUSTIX_DATAPATH_IOC_VERSION;
	build.inner_len = sizeof(inner);
	build.out_len = sizeof(outer);
	build.sequence = 123;
	ret = trustix_datapath_outer_build_locked(&build, inner, outer);
	if (ret)
		goto free_all;
	ret = trustix_datapath_outer_magic_check_packet(outer, build.written_len,
						       &ip_header_len,
						       &l4_header_len);
	if (ret)
		goto free_all;
	outer[28] = 0;
	ret = trustix_datapath_outer_magic_check_packet(outer, build.written_len,
						       &ip_header_len,
						       &l4_header_len);
	if (ret != -EPROTONOSUPPORT) {
		ret = -EINVAL;
		goto free_all;
	}
	outer[28] = 'T';

	parse.version = TRUSTIX_DATAPATH_IOC_VERSION;
	parse.outer_len = build.written_len;
	parse.out_len = sizeof(out);
	ret = trustix_datapath_outer_parse_locked(&parse, outer, out);
	if (ret)
		goto free_all;
	if (parse.written_len != sizeof(inner) ||
	    parse.flow_id != 0x9988776655443322ULL ||
	    parse.epoch != 9 ||
	    parse.sequence != 123 ||
	    parse.payload_len != sizeof(inner) ||
	    parse.tixt_flags != TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4 ||
	    parse.session_flags != TRUSTIX_DATAPATH_SESSION_FLAG_KERNEL_FLOW ||
	    parse.local_ipv4 != 0xc0000201U ||
	    parse.remote_ipv4 != 0xc6336402U ||
	    parse.local_port != 51820 ||
	    parse.remote_port != 17041 ||
	    parse.outer_protocol != IPPROTO_UDP ||
	    parse.tixt_len != TRUSTIX_DATAPATH_TIXT_HEADER_LEN + sizeof(inner) ||
	    parse.flags & TRUSTIX_DATAPATH_OUTER_PARSE_FLAG_REVERSE ||
	    memcmp(out, inner, sizeof(inner))) {
		ret = -EINVAL;
		goto free_all;
	}

	trustix_datapath_clear_table(&trustix_datapath_session_wires);
	ret = trustix_datapath_plaintext_session_for_frame_locked(
		0x9988776655443322ULL, 9, IPPROTO_UDP, &session);
	if (ret || !session || session->value[0] != 0x9988776655443322ULL) {
		ret = -EINVAL;
		goto free_all;
	}
	session->flags |= TRUSTIX_DATAPATH_SESSION_FLAG_ENCRYPTED;
	ret = trustix_datapath_plaintext_session_for_frame_locked(
		0x9988776655443322ULL, 9, IPPROTO_UDP, &session);
	if (ret != -ENOKEY) {
		ret = -EINVAL;
		goto free_all;
	}
	ret = 0;

free_all:
	trustix_datapath_free_table(&trustix_datapath_session_wires);
free_flows:
	trustix_datapath_free_table(&trustix_datapath_flows);
free_sessions:
	trustix_datapath_free_table(&trustix_datapath_sessions);
free_routes:
	trustix_datapath_free_table(&trustix_datapath_routes);
restore:
	trustix_datapath_routes = saved_routes;
	trustix_datapath_sessions = saved_sessions;
	trustix_datapath_flows = saved_flows;
	trustix_datapath_session_wires = saved_session_wires;
	return ret;
}

static void
trustix_datapath_build_tixt_header(__u8 *wire, __u8 flags, __u64 flow_id,
				   __u64 epoch, __u64 sequence,
				   __u32 payload_len, __u16 fragment_index,
				   __u16 fragment_count)
{
	trustix_datapath_put_be32(wire, TRUSTIX_DATAPATH_TIXT_MAGIC);
	wire[4] = TRUSTIX_DATAPATH_TIXT_VERSION;
	wire[5] = flags;
	trustix_datapath_put_be16(wire + 6, TRUSTIX_DATAPATH_TIXT_HEADER_LEN);
	trustix_datapath_put_be64(wire + 8, flow_id);
	trustix_datapath_put_be64(wire + 16, epoch);
	trustix_datapath_put_be64(wire + 24, sequence);
	trustix_datapath_put_be32(wire + 32, payload_len);
	trustix_datapath_put_be16(wire + 36, fragment_index);
	trustix_datapath_put_be16(wire + 38, fragment_count);
}

static int trustix_datapath_selftest_rx_worker_mac_cache(void)
{
	struct trustix_datapath_rx_worker_mac_cache *cache;
	const __u8 first[ETH_ALEN] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
	const __u8 second[ETH_ALEN] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 };
	const __u8 updated[ETH_ALEN] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x03 };
	__u8 addr[ETH_ALEN];
	unsigned int set;
	unsigned int i;
	bool expired = false;
	int ret = 0;

	cache = kzalloc(sizeof(*cache), GFP_KERNEL);
	if (!cache)
		return -ENOMEM;
	trustix_datapath_rx_worker_mac_cache_store(cache, 10,
						      htonl(0x0a400001), first);
	trustix_datapath_rx_worker_mac_cache_store(cache, 10,
						      htonl(0x0a400081), second);
	if (!trustix_datapath_rx_worker_mac_cache_lookup(
		    cache, 10, htonl(0x0a400001), addr) ||
	    !ether_addr_equal(addr, first)) {
		ret = -EINVAL;
		goto out;
	}
	if (!trustix_datapath_rx_worker_mac_cache_lookup(
		    cache, 10, htonl(0x0a400081), addr) ||
	    !ether_addr_equal(addr, second)) {
		ret = -EINVAL;
		goto out;
	}

	trustix_datapath_rx_worker_mac_cache_store(cache, 10,
						      htonl(0x0a400001), updated);
	if (!trustix_datapath_rx_worker_mac_cache_lookup(
		    cache, 10, htonl(0x0a400001), addr) ||
	    !ether_addr_equal(addr, updated)) {
		ret = -EINVAL;
		goto out;
	}
	if (!trustix_datapath_rx_worker_mac_cache_lookup(
		    cache, 10, htonl(0x0a400081), addr) ||
	    !ether_addr_equal(addr, second))
		ret = -EINVAL;
	if (ret)
		goto out;
	set = trustix_datapath_rx_worker_mac_cache_set(
		10, htonl(0x0a400001));
	for (i = 0; i < TRUSTIX_DATAPATH_RX_WORKER_MAC_CACHE_WAYS; i++) {
		struct trustix_datapath_rx_worker_mac_cache_entry *entry =
			&cache->entries[
				set * TRUSTIX_DATAPATH_RX_WORKER_MAC_CACHE_WAYS + i];

		if (!entry->valid || entry->ifindex != 10 ||
		    entry->dst_ipv4 != htonl(0x0a400001))
			continue;
		entry->expires = jiffies - 1;
		expired = true;
		break;
	}
	if (!expired || trustix_datapath_rx_worker_mac_cache_lookup(
				cache, 10, htonl(0x0a400001), addr))
		ret = -EINVAL;
out:
	kfree(cache);
	return ret;
}

static int trustix_datapath_selftest_tx_plaintext_mac_cache(void)
{
	struct trustix_datapath_tx_plaintext_mac_cache *cache;
	struct trustix_datapath_tx_plan plan = {
		.local_ipv4 = 0x0a000001,
		.remote_ipv4 = 0x0a000002,
		.remote_port = 13000,
		.outer_protocol = IPPROTO_UDP,
	};
	struct net_device *dev;
	const __u8 mac[ETH_ALEN] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
	__u8 addr[ETH_ALEN];
	unsigned int set;
	unsigned int i;
	bool expired = false;
	int ret = 0;

	cache = kzalloc(sizeof(*cache), GFP_KERNEL);
	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!cache || !dev) {
		kfree(cache);
		kfree(dev);
		return -ENOMEM;
	}
	dev->ifindex = 10;
	for (i = 0; i < 16; i++) {
		plan.local_port = 20000 + i;
		plan.outer_protocol = (i & 1) ? IPPROTO_TCP : IPPROTO_UDP;
		trustix_datapath_tx_plaintext_mac_cache_store(
			cache, dev, &plan, mac);
	}
	for (i = 0; i < 16; i++) {
		plan.local_port = 20000 + i;
		plan.outer_protocol = (i & 1) ? IPPROTO_TCP : IPPROTO_UDP;
		if (!trustix_datapath_tx_plaintext_mac_cache_lookup(
			    cache, dev, &plan, addr) ||
		    !ether_addr_equal(addr, mac)) {
			ret = -EINVAL;
			break;
		}
	}
	if (ret)
		goto out;
	plan.local_port = 20000;
	plan.outer_protocol = IPPROTO_UDP;
	set = trustix_datapath_tx_plaintext_dst_mac_cache_set(dev, &plan);
	for (i = 0; i < TRUSTIX_DATAPATH_TX_PLAINTEXT_MAC_CACHE_WAYS; i++) {
		struct trustix_datapath_tx_plaintext_mac_cache_entry *entry =
			&cache->entries[
				set * TRUSTIX_DATAPATH_TX_PLAINTEXT_MAC_CACHE_WAYS + i];

		if (!entry->valid || entry->ifindex != dev->ifindex ||
		    entry->local_port != htons(plan.local_port) ||
		    entry->protocol != plan.outer_protocol)
			continue;
		entry->expires = jiffies - 1;
		expired = true;
		break;
	}
	if (!expired || trustix_datapath_tx_plaintext_mac_cache_lookup(
				cache, dev, &plan, addr))
		ret = -EINVAL;
	if (ret)
		goto out;
	trustix_datapath_tx_plaintext_mac_cache_store(cache, dev, &plan, mac);
	if (trustix_datapath_tx_plaintext_mac_cache_invalidate(
		    cache, dev->ifindex) != 16) {
		ret = -EINVAL;
		goto out;
	}
	if (trustix_datapath_tx_plaintext_mac_cache_lookup(
		    cache, dev, &plan, addr))
		ret = -EINVAL;
	if (ret)
		goto out;
	dev->ifindex = 10;
	trustix_datapath_tx_plaintext_mac_cache_store(cache, dev, &plan, mac);
	dev->ifindex = 11;
	trustix_datapath_tx_plaintext_mac_cache_store(cache, dev, &plan, mac);
	if (trustix_datapath_tx_plaintext_mac_cache_invalidate(cache, 10) != 1) {
		ret = -EINVAL;
		goto out;
	}
	dev->ifindex = 10;
	if (trustix_datapath_tx_plaintext_mac_cache_lookup(
		    cache, dev, &plan, addr)) {
		ret = -EINVAL;
		goto out;
	}
	dev->ifindex = 11;
	if (!trustix_datapath_tx_plaintext_mac_cache_lookup(
		    cache, dev, &plan, addr) ||
	    !ether_addr_equal(addr, mac))
		ret = -EINVAL;
out:
	kfree(dev);
	kfree(cache);
	return ret;
}

static int trustix_datapath_selftest_tx_plaintext_hash_tx_queue(void)
{
	unsigned int cpu;
	unsigned int i;
	__u16 queue;
	__u16 seen_partitioned_tcp = 0;
	__u16 seen_partitioned_udp = 0;
	__u16 seen_unpartitioned = 0;

	for (i = 0; i < 1024; i++) {
		queue = trustix_datapath_tx_plaintext_hash_tx_queue_for_transport(
			i, 4, IPPROTO_UDP, true);
		if (queue >= 4)
			return -EINVAL;
		seen_partitioned_udp |= (__u16)(1U << queue);

		queue = trustix_datapath_tx_plaintext_hash_tx_queue_for_transport(
			i, 4, IPPROTO_TCP, true);
		if (queue >= 4 || !(queue & 1))
			return -EINVAL;
		seen_partitioned_tcp |= (__u16)(1U << queue);

		queue = trustix_datapath_tx_plaintext_hash_tx_queue_for_transport(
			i, 4, IPPROTO_UDP, false);
		if (queue >= 4)
			return -EINVAL;
		seen_unpartitioned |= (__u16)(1U << queue);
	}
	if (seen_partitioned_udp != 0x05 || seen_partitioned_tcp != 0x0a ||
	    seen_unpartitioned != 0x0f)
		return -EINVAL;
	for (i = 0; i < 128; i++) {
		queue = trustix_datapath_tx_plaintext_hash_tx_queue_for_transport(
			i, 2, IPPROTO_UDP, true);
		if (queue != 0 ||
		    trustix_datapath_tx_plaintext_hash_tx_queue_for_transport(
			    i, 2, IPPROTO_TCP, true) != 1)
			return -EINVAL;

		queue = trustix_datapath_tx_plaintext_hash_tx_queue_for_transport(
			i, 3, IPPROTO_UDP, true);
		if (queue >= 3 || (queue & 1))
			return -EINVAL;
		if (trustix_datapath_tx_plaintext_hash_tx_queue_for_transport(
			    i, 3, IPPROTO_TCP, true) != 1)
			return -EINVAL;
	}
	for (i = 0; i < TRUSTIX_DATAPATH_TIX_TCP_PORT_SHARDS; i++) {
		queue = trustix_datapath_tx_plaintext_tix_tcp_shard_tx_queue(
			(__u8)i, 8, false);
		if (queue != i % 8)
			return -EINVAL;
		queue = trustix_datapath_tx_plaintext_tix_tcp_shard_tx_queue(
			(__u8)i, 8, true);
		if (queue != (i % 4) * 2 + 1)
			return -EINVAL;
	}
	if (trustix_datapath_tx_plaintext_tix_tcp_shard_tx_queue(
		    7, 0, false) != 0 ||
	    trustix_datapath_tx_plaintext_tix_tcp_shard_tx_queue(
		    7, 1, false) != 0)
		return -EINVAL;

	if (!trustix_datapath_tx_plaintext_cpu_for_queue(0, &cpu) ||
	    cpu >= nr_cpu_ids || !cpu_online(cpu))
		return -EINVAL;
	return 0;
}

static void
trustix_datapath_build_tixt(__u8 *wire, __u8 flags, __u64 flow_id,
			    __u64 epoch, __u64 sequence, __u32 payload_len,
			    __u16 fragment_index, __u16 fragment_count)
{
	memset(wire, 0, TRUSTIX_DATAPATH_TIXT_HEADER_LEN + payload_len);
	trustix_datapath_build_tixt_header(wire, flags, flow_id, epoch,
					   sequence, payload_len,
					   fragment_index, fragment_count);
}

static int
trustix_datapath_parse_tixt(const __u8 *wire, __u32 len,
			    struct trustix_datapath_tixt_frame *frame)
{
	__u32 wire_len;
	int ret;

	ret = trustix_datapath_parse_tixt_header(wire, len, frame);
	if (ret)
		return ret;
	wire_len = (__u32)frame->header_len + frame->payload_len;
	if (len < wire_len)
		return -EMSGSIZE;
	return 0;
}

static int
trustix_datapath_parse_tixt_header(const __u8 *wire, __u32 len,
				   struct trustix_datapath_tixt_frame *frame)
{
	__u32 header_len;
	__u32 magic;
	__u32 payload_len;
	__u32 wire_len;
	__u16 fragment_index;
	__u16 fragment_count;
	__u8 flags;

	if (!wire || !frame)
		return -EINVAL;
	if (len < TRUSTIX_DATAPATH_MIN_FRAME_HEADER_LEN)
		return -ENODATA;
	magic = trustix_datapath_get_be32(wire);
	if (magic != TRUSTIX_DATAPATH_TIXT_MAGIC &&
	    magic != TRUSTIX_DATAPATH_TIXU_MAGIC)
		return -EPROTONOSUPPORT;
	if (wire[4] != TRUSTIX_DATAPATH_TIXT_VERSION)
		return -EPROTONOSUPPORT;
	header_len = trustix_datapath_get_be16(wire + 6);
	if (magic == TRUSTIX_DATAPATH_TIXT_MAGIC &&
	    header_len != TRUSTIX_DATAPATH_TIXT_HEADER_LEN)
		return -EBADMSG;
	if (magic == TRUSTIX_DATAPATH_TIXU_MAGIC &&
	    header_len != TRUSTIX_DATAPATH_TIXU_HEADER_LEN)
		return -EBADMSG;
	if (len < header_len)
		return -ENODATA;

	flags = wire[5];
	if (flags & ~TRUSTIX_DATAPATH_TIXT_KNOWN_FLAGS)
		return -EPROTONOSUPPORT;
	if ((flags &
	     TRUSTIX_DATAPATH_TIXT_FLAG_INNER_TCP_CHECKSUM_PARTIAL) &&
	    (magic != TRUSTIX_DATAPATH_TIXT_MAGIC ||
	     !(flags & TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4) ||
	     (flags & TRUSTIX_DATAPATH_TIXT_FLAG_CRYPTO_FRAGMENT) ||
	     (flags & (TRUSTIX_DATAPATH_TIXT_FLAG_ENCRYPTED |
		       TRUSTIX_DATAPATH_TIXT_FLAG_KERNEL_OPENED)) ==
		     (TRUSTIX_DATAPATH_TIXT_FLAG_ENCRYPTED |
		      TRUSTIX_DATAPATH_TIXT_FLAG_KERNEL_OPENED)))
		return -EBADMSG;

	if (magic == TRUSTIX_DATAPATH_TIXT_MAGIC)
		payload_len = trustix_datapath_get_be32(wire + 32);
	else
		payload_len = trustix_datapath_get_be32(wire + 24);
	if (payload_len > TRUSTIX_DATAPATH_TIXT_MAX_PAYLOAD)
		return -EMSGSIZE;
	if (payload_len > UINT_MAX - header_len)
		return -EMSGSIZE;
	wire_len = header_len + payload_len;

	if (magic == TRUSTIX_DATAPATH_TIXT_MAGIC) {
		fragment_index = trustix_datapath_get_be16(wire + 36);
		fragment_count = trustix_datapath_get_be16(wire + 38);
	} else {
		fragment_index = trustix_datapath_get_be16(wire + 28);
		fragment_count = trustix_datapath_get_be16(wire + 30);
	}
	if (flags & TRUSTIX_DATAPATH_TIXT_FLAG_INNER_GSO) {
		if (magic != TRUSTIX_DATAPATH_TIXT_MAGIC ||
		    (flags & (TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4 |
			      TRUSTIX_DATAPATH_TIXT_FLAG_INNER_TCP_CHECKSUM_PARTIAL)) !=
			    (TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4 |
			     TRUSTIX_DATAPATH_TIXT_FLAG_INNER_TCP_CHECKSUM_PARTIAL) ||
		    (flags & (TRUSTIX_DATAPATH_TIXT_FLAG_ENCRYPTED |
			      TRUSTIX_DATAPATH_TIXT_FLAG_KERNEL_OPENED |
			      TRUSTIX_DATAPATH_TIXT_FLAG_CRYPTO_FRAGMENT)) ||
		    !fragment_index || fragment_count < 2)
			return -EBADMSG;
	} else {
		if (fragment_count == 0) {
			if (fragment_index != 0)
				return -EBADMSG;
			if (flags & TRUSTIX_DATAPATH_TIXT_FLAG_CRYPTO_FRAGMENT)
				return -EBADMSG;
		} else if (fragment_index >= fragment_count) {
			return -EBADMSG;
		}
		if ((flags &
		     TRUSTIX_DATAPATH_TIXT_FLAG_INNER_TCP_CHECKSUM_PARTIAL) &&
		    (fragment_index || fragment_count))
			return -EBADMSG;
	}

	frame->flags = flags;
	frame->header_len = (__u8)header_len;
	frame->flow_id = trustix_datapath_get_be64(wire + 8);
	if (magic == TRUSTIX_DATAPATH_TIXT_MAGIC) {
		frame->epoch = trustix_datapath_get_be64(wire + 16);
		frame->sequence = trustix_datapath_get_be64(wire + 24);
	} else {
		frame->epoch = 0;
		frame->sequence = trustix_datapath_get_be64(wire + 16);
	}
	frame->payload_len = payload_len;
	frame->fragment_index = fragment_index;
	frame->fragment_count = fragment_count;
	frame->wire_len = wire_len;
	return 0;
}

static int trustix_datapath_selftest_tixt_frame(void)
{
	struct trustix_datapath_tixt_frame frame;
	__u8 wire[TRUSTIX_DATAPATH_TIXT_HEADER_LEN + 32];
	__u8 tixu[TRUSTIX_DATAPATH_TIXU_HEADER_LEN + 20];
	int ret;

	trustix_datapath_build_tixt(wire,
				    TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4,
				    0x1020304050607080ULL, 7, 11, 20, 0, 0);
	wire[TRUSTIX_DATAPATH_TIXT_HEADER_LEN] = 0x45;
	trustix_datapath_put_be16(wire + TRUSTIX_DATAPATH_TIXT_HEADER_LEN + 2,
				  20);
	ret = trustix_datapath_parse_tixt(wire, sizeof(wire), &frame);
	if (ret)
		return ret;
	if (frame.flags != TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4 ||
	    frame.flow_id != 0x1020304050607080ULL || frame.epoch != 7 ||
	    frame.sequence != 11 || frame.payload_len != 20 ||
	    frame.fragment_index != 0 || frame.fragment_count != 0 ||
	    frame.wire_len != TRUSTIX_DATAPATH_TIXT_HEADER_LEN + 20)
		return -EINVAL;

	wire[0] ^= 0xff;
	if (trustix_datapath_parse_tixt(wire, sizeof(wire), &frame) == 0)
		return -EINVAL;

	memset(tixu, 0, sizeof(tixu));
	trustix_datapath_put_be32(tixu, TRUSTIX_DATAPATH_TIXU_MAGIC);
	tixu[4] = TRUSTIX_DATAPATH_TIXT_VERSION;
	tixu[5] = TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4;
	trustix_datapath_put_be16(tixu + 6, TRUSTIX_DATAPATH_TIXU_HEADER_LEN);
	trustix_datapath_put_be64(tixu + 8, 0x1020304050607080ULL);
	trustix_datapath_put_be64(tixu + 16, 12);
	trustix_datapath_put_be32(tixu + 24, 20);
	tixu[TRUSTIX_DATAPATH_TIXU_HEADER_LEN] = 0x45;
	trustix_datapath_put_be16(tixu + TRUSTIX_DATAPATH_TIXU_HEADER_LEN + 2,
				  20);
	ret = trustix_datapath_parse_tixt(tixu, sizeof(tixu), &frame);
	if (ret)
		return ret;
	if (frame.header_len != TRUSTIX_DATAPATH_TIXU_HEADER_LEN ||
	    frame.flags != TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4 ||
	    frame.flow_id != 0x1020304050607080ULL || frame.epoch != 0 ||
	    frame.sequence != 12 || frame.payload_len != 20 ||
	    frame.fragment_index != 0 || frame.fragment_count != 0 ||
	    frame.wire_len != TRUSTIX_DATAPATH_TIXU_HEADER_LEN + 20)
		return -EINVAL;
	return 0;
}

static int trustix_datapath_selftest_tixt_stream_skb(
	const __u8 *stream, __u32 len, __u32 second_offset)
{
	struct trustix_datapath_rx_worker_pending_copy pending = {};
	struct trustix_datapath_tixt_frame frame = {};
	const __u32 linear_len = 17;
	struct sk_buff *skb;
	struct page *page;
	void *page_addr;
	__u8 copied[16];
	int ret = 0;

	if (!stream || len <= linear_len || len - linear_len > PAGE_SIZE ||
	    second_offset >= len)
		return -EINVAL;
	skb = alloc_skb(linear_len, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;
	memcpy(skb_put(skb, linear_len), stream, linear_len);
	page = alloc_page(GFP_KERNEL);
	if (!page) {
		ret = -ENOMEM;
		goto out;
	}
	page_addr = kmap_local_page(page);
	memcpy(page_addr, stream + linear_len, len - linear_len);
	kunmap_local(page_addr);
	skb_add_rx_frag(skb, 0, page, 0, len - linear_len, PAGE_SIZE);

	if (!skb_is_nonlinear(skb) || skb_headlen(skb) != linear_len) {
		ret = -EINVAL;
		goto out;
	}
	ret = trustix_datapath_parse_tixt_skb_header(skb, 0, len, &frame);
	if (ret || frame.wire_len != second_offset) {
		ret = ret ?: -EINVAL;
		goto out;
	}
	ret = trustix_datapath_parse_tixt_skb_header(
		skb, second_offset, len - second_offset, &frame);
	if (ret)
		goto out;
	pending.source_skb = skb;
	pending.source_offset = second_offset;
	pending.len = frame.wire_len;
	ret = trustix_datapath_rx_worker_pending_copy_bits(
		&pending, 7, copied, sizeof(copied));
	if (ret)
		goto out;
	if (memcmp(copied, stream + second_offset + 7, sizeof(copied)) ||
	    skb_headlen(skb) != linear_len)
		ret = -EINVAL;

out:
	kfree_skb(skb);
	return ret;
}

static int trustix_datapath_selftest_tixt_stream(void)
{
	struct trustix_datapath_tixt_frame frame;
	__u8 stream[(TRUSTIX_DATAPATH_TIXT_HEADER_LEN + 24) * 2];
	__u32 cursor = 0;
	int ret;

	memset(stream, 0, sizeof(stream));
	trustix_datapath_build_tixt(stream,
				    TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4,
				    1, 2, 3, 24, 0, 0);
	cursor += TRUSTIX_DATAPATH_TIXT_HEADER_LEN + 24;
	trustix_datapath_build_tixt(stream + cursor,
				    TRUSTIX_DATAPATH_TIXT_FLAG_ENCRYPTED |
					    TRUSTIX_DATAPATH_TIXT_FLAG_CRYPTO_FRAGMENT,
				    4, 5, 6, 12, 0, 2);

	ret = trustix_datapath_parse_tixt(stream, sizeof(stream), &frame);
	if (ret || frame.wire_len != TRUSTIX_DATAPATH_TIXT_HEADER_LEN + 24)
		return ret ? ret : -EINVAL;
	cursor = frame.wire_len;
	ret = trustix_datapath_parse_tixt(stream + cursor,
					  sizeof(stream) - cursor, &frame);
	if (ret)
		return ret;
	if (frame.flow_id != 4 || frame.epoch != 5 || frame.sequence != 6 ||
	    frame.payload_len != 12 || frame.fragment_index != 0 ||
	    frame.fragment_count != 2 ||
	    frame.wire_len != TRUSTIX_DATAPATH_TIXT_HEADER_LEN + 12)
		return -EINVAL;
	return trustix_datapath_selftest_tixt_stream_skb(
		stream, sizeof(stream), TRUSTIX_DATAPATH_TIXT_HEADER_LEN + 24);
}

static int
trustix_datapath_selftest_inner_tcp_checksum_partial(void)
{
	__u8 packet[sizeof(struct iphdr) + sizeof(struct tcphdr) + 33]
		__aligned(4);
	__u8 wire[TRUSTIX_DATAPATH_TIXT_HEADER_LEN + sizeof(packet)];
	struct trustix_datapath_tixt_frame frame = {};
	struct trustix_datapath_rx_stage_view view = {};
	struct trustix_datapath_tx_plan plan = {};
	struct rtnl_link_ops virtual_link_ops = {
		.kind = "veth",
	};
	struct net_device *test_dev = NULL;
	struct sk_buff *skb = NULL;
	struct tcphdr *tcph;
	struct iphdr *iph;
	__sum16 full_checksum;
	__sum16 partial_seed;
	__u64 saved_fallbacks =
		trustix_datapath_rx_worker_partial_checksum_software_fallbacks;
	__u64 saved_repairs =
		trustix_datapath_rx_worker_partial_checksum_metadata_repairs;
	__u64 saved_checksum_fixed =
		trustix_datapath_rx_worker_checksum_fixed;
	__u64 saved_checksum_errors =
		trustix_datapath_rx_worker_checksum_errors;
	__u64 saved_partial_frames =
		trustix_datapath_rx_worker_inner_tcp_checksum_partial;
	__u64 saved_partial_errors =
		trustix_datapath_rx_worker_inner_tcp_checksum_partial_errors;
	__u64 saved_features = READ_ONCE(trustix_datapath_features);
	unsigned int i;
	int ret = 0;

	memset(packet, 0, sizeof(packet));
	iph = (struct iphdr *)packet;
	tcph = (struct tcphdr *)(packet + sizeof(*iph));
	iph->version = 4;
	iph->ihl = sizeof(*iph) / 4;
	iph->tot_len = htons(sizeof(packet));
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->saddr = htonl(0xc0000201U);
	iph->daddr = htonl(0xc6336402U);
	tcph->source = htons(12345);
	tcph->dest = htons(443);
	tcph->seq = htonl(0x10203040U);
	tcph->doff = sizeof(*tcph) / 4;
	tcph->ack = 1;
	for (i = sizeof(*iph) + sizeof(*tcph); i < sizeof(packet); i++)
		packet[i] = (__u8)(i * 17U + 3U);
	full_checksum = trustix_datapath_rx_worker_l4_checksum(
		iph, tcph, sizeof(packet) - sizeof(*iph), IPPROTO_TCP);
	if (!trustix_datapath_tx_plaintext_prepare_inner_tcp_checksum_partial(
		    packet, sizeof(packet))) {
		ret = -EINVAL;
		goto out;
	}
	partial_seed = ~csum_tcpudp_magic(
		iph->saddr, iph->daddr, sizeof(packet) - sizeof(*iph),
		IPPROTO_TCP, 0);
	if (tcph->check != partial_seed) {
		ret = -EINVAL;
		goto out;
	}
	WRITE_ONCE(trustix_datapath_features,
		   saved_features |
		   TRUSTIX_DATAPATH_FEATURE_INNER_TCP_CHECKSUM_PARTIAL);
	plan.session_flags =
		TRUSTIX_DATAPATH_SESSION_FLAG_RECEIVE_INNER_TCP_CHECKSUM_PARTIAL;
	if (trustix_datapath_tx_plaintext_inner_tcp_checksum_partial_enabled(
		    &plan)) {
		ret = -EINVAL;
		goto out;
	}
	plan.session_flags =
		TRUSTIX_DATAPATH_SESSION_FLAG_SEND_INNER_TCP_CHECKSUM_PARTIAL;
	if (!trustix_datapath_tx_plaintext_inner_tcp_checksum_partial_enabled(
		     &plan)) {
		ret = -EINVAL;
		goto out;
	}
	plan.secure = true;
	plan.session_flags |=
		TRUSTIX_DATAPATH_SESSION_FLAG_SEND_ENCRYPTED;
	if (trustix_datapath_tx_plaintext_inner_tcp_checksum_partial_enabled(
		    &plan)) {
		ret = -EINVAL;
		goto out;
	}
	view.frame.flags = TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4 |
			   TRUSTIX_DATAPATH_TIXT_FLAG_INNER_TCP_CHECKSUM_PARTIAL;
	view.frame.header_len = TRUSTIX_DATAPATH_TIXT_HEADER_LEN;
	view.frame.payload_len = sizeof(packet);
	view.inner.protocol = IPPROTO_TCP;
	view.inner_packet = packet;
	view.session_flags =
		TRUSTIX_DATAPATH_SESSION_FLAG_RECEIVE_INNER_TCP_CHECKSUM_PARTIAL;
	ret = trustix_datapath_rx_validate_inner_tcp_checksum_partial(&view);
	if (ret || trustix_datapath_rx_worker_inner_tcp_checksum_partial !=
			   saved_partial_frames + 1) {
		ret = ret ?: -EINVAL;
		goto out;
	}
	view.session_flags =
		TRUSTIX_DATAPATH_SESSION_FLAG_SEND_INNER_TCP_CHECKSUM_PARTIAL;
	ret = trustix_datapath_rx_validate_inner_tcp_checksum_partial(&view);
	if (ret != -EBADMSG ||
	    trustix_datapath_rx_worker_inner_tcp_checksum_partial_errors !=
		    saved_partial_errors + 1) {
		ret = -EINVAL;
		goto out;
	}
	ret = 0;

	trustix_datapath_build_tixt(
		wire, TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4 |
			      TRUSTIX_DATAPATH_TIXT_FLAG_INNER_TCP_CHECKSUM_PARTIAL,
		1, 2, 3, sizeof(packet), 0, 0);
	memcpy(wire + TRUSTIX_DATAPATH_TIXT_HEADER_LEN, packet,
	       sizeof(packet));
	ret = trustix_datapath_parse_tixt(wire, sizeof(wire), &frame);
	if (ret || frame.flags !=
			   (TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4 |
			    TRUSTIX_DATAPATH_TIXT_FLAG_INNER_TCP_CHECKSUM_PARTIAL)) {
		ret = ret ?: -EINVAL;
		goto out;
	}
	wire[5] |= TRUSTIX_DATAPATH_TIXT_FLAG_ENCRYPTED;
	if (trustix_datapath_parse_tixt(wire, sizeof(wire), &frame)) {
		ret = -EINVAL;
		goto out;
	}
	wire[5] |= TRUSTIX_DATAPATH_TIXT_FLAG_KERNEL_OPENED;
	if (!trustix_datapath_parse_tixt(wire, sizeof(wire), &frame)) {
		ret = -EINVAL;
		goto out;
	}
	wire[5] &= ~TRUSTIX_DATAPATH_TIXT_FLAG_KERNEL_OPENED;
	wire[5] &= ~TRUSTIX_DATAPATH_TIXT_FLAG_ENCRYPTED;
	trustix_datapath_put_be16(wire + 38, 2);
	if (!trustix_datapath_parse_tixt(wire, sizeof(wire), &frame)) {
		ret = -EINVAL;
		goto out;
	}

	test_dev = kzalloc(sizeof(*test_dev), GFP_KERNEL);
	if (!test_dev) {
		ret = -ENOMEM;
		goto out;
	}
	test_dev->features = NETIF_F_HW_CSUM;
	if (trustix_datapath_rx_worker_partial_csum_requires_software(
		    test_dev)) {
		ret = -EINVAL;
		goto out;
	}
	test_dev->rtnl_link_ops = &virtual_link_ops;
	if (!trustix_datapath_rx_worker_partial_csum_requires_software(
		     test_dev)) {
		ret = -EINVAL;
		goto out;
	}
	test_dev->rtnl_link_ops = NULL;
	test_dev->priv_flags = IFF_EBRIDGE;
	if (!trustix_datapath_rx_worker_partial_csum_requires_software(
		     test_dev)) {
		ret = -EINVAL;
		goto out;
	}
	test_dev->priv_flags = 0;

	skb = alloc_skb(ETH_HLEN + sizeof(packet), GFP_KERNEL);
	if (!skb) {
		ret = -ENOMEM;
		goto out;
	}
	skb_reserve(skb, ETH_HLEN);
	memcpy(skb_put(skb, sizeof(packet)), packet, sizeof(packet));
	ret = trustix_datapath_rx_worker_restore_inner_tcp_checksum_partial(
		skb, TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4 |
			     TRUSTIX_DATAPATH_TIXT_FLAG_INNER_TCP_CHECKSUM_PARTIAL);
	if (ret || skb->ip_summed != CHECKSUM_PARTIAL) {
		ret = ret ?: -EINVAL;
		goto out;
	}
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, sizeof(struct iphdr));
	skb_push(skb, ETH_HLEN);
	skb_reset_mac_header(skb);
	skb_set_network_header(skb, ETH_HLEN);
	skb_set_transport_header(skb, ETH_HLEN + sizeof(struct iphdr));
	skb->mac_len = ETH_HLEN;
	skb->protocol = htons(ETH_P_IP);
	ret = trustix_datapath_rx_worker_finish_partial_checksum(skb,
								test_dev);
	if (ret || skb->ip_summed != CHECKSUM_PARTIAL) {
		ret = ret ?: -EINVAL;
		goto out;
	}
	skb->csum = 0;
	test_dev->rtnl_link_ops = &virtual_link_ops;
	ret = trustix_datapath_rx_worker_finish_partial_checksum(skb,
								test_dev);
	if (ret || skb->ip_summed == CHECKSUM_PARTIAL ||
	    trustix_datapath_rx_worker_partial_checksum_metadata_repairs !=
		    saved_repairs + 1 ||
	    trustix_datapath_rx_worker_partial_checksum_software_fallbacks !=
		    saved_fallbacks + 1) {
		ret = ret ?: -EINVAL;
		goto out;
	}
	tcph = (struct tcphdr *)(skb_network_header(skb) +
				 sizeof(struct iphdr));
	if (tcph->check != full_checksum) {
		ret = -EINVAL;
		goto out;
	}

	skb_pull(skb, ETH_HLEN);
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, sizeof(struct iphdr));
	tcph = (struct tcphdr *)(skb->data + sizeof(struct iphdr));
	tcph->check ^= htons(1);
	ret = trustix_datapath_rx_worker_restore_inner_tcp_checksum_partial(
		skb, TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4 |
			     TRUSTIX_DATAPATH_TIXT_FLAG_INNER_TCP_CHECKSUM_PARTIAL);
	if (ret != -EBADMSG)
		ret = -EINVAL;
	else
		ret = 0;

out:
	kfree_skb(skb);
	kfree(test_dev);
	WRITE_ONCE(trustix_datapath_features, saved_features);
	trustix_datapath_rx_worker_partial_checksum_software_fallbacks =
		saved_fallbacks;
	trustix_datapath_rx_worker_partial_checksum_metadata_repairs =
		saved_repairs;
	trustix_datapath_rx_worker_checksum_fixed = saved_checksum_fixed;
	trustix_datapath_rx_worker_checksum_errors = saved_checksum_errors;
	trustix_datapath_rx_worker_inner_tcp_checksum_partial =
		saved_partial_frames;
	trustix_datapath_rx_worker_inner_tcp_checksum_partial_errors =
		saved_partial_errors;
	return ret;
}

static struct sk_buff *
trustix_datapath_selftest_tix_tcp_segment(const struct sk_buff *source,
					  __u32 source_offset,
					  __u32 payload_len,
					  __u32 sequence_delta)
{
	const __u32 outer_header_len =
		sizeof(struct iphdr) + sizeof(struct tcphdr);
	struct sk_buff *skb;
	struct tcphdr *tcph;
	struct iphdr *iph;

	if (!source || source_offset < outer_header_len ||
	    source_offset > source->len ||
	    payload_len > source->len - source_offset ||
	    payload_len > U16_MAX - outer_header_len)
		return NULL;
	skb = alloc_skb(outer_header_len + payload_len, GFP_KERNEL);
	if (!skb)
		return NULL;
	if (skb_copy_bits(source, 0, skb_put(skb, outer_header_len),
			  outer_header_len) ||
	    skb_copy_bits(source, source_offset,
			  skb_put(skb, payload_len), payload_len)) {
		kfree_skb(skb);
		return NULL;
	}
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, sizeof(struct iphdr));
	iph = ip_hdr(skb);
	tcph = tcp_hdr(skb);
	iph->tot_len = htons((__u16)skb->len);
	tcph->seq = htonl(ntohl(tcph->seq) + sequence_delta);
	trustix_datapath_rx_worker_fix_ipv4_header_checksum(
		iph, sizeof(*iph));
	return skb;
}

static int trustix_datapath_selftest_inner_gso(void)
{
	const __u32 payload_len = 3000;
	const __u32 tcp_header_len = 60;
	const __u32 inner_len = sizeof(struct iphdr) +
				tcp_header_len + payload_len;
	const __u32 inner_offset = sizeof(struct iphdr) +
				   sizeof(struct tcphdr) +
				   TRUSTIX_DATAPATH_TIXT_HEADER_LEN;
	struct trustix_datapath_rx_stage_view view = {};
	struct trustix_datapath_ioc_classify outer = {};
	struct trustix_datapath_tixt_frame frame = {};
	struct trustix_datapath_tixt_frame scoped_frame = {};
	struct trustix_datapath_tixt_frame tail_frame = {};
	struct trustix_datapath_inner_gso_reassembly_key reassembly_key;
	struct trustix_datapath_tx_plan plan = {};
	struct net_device *test_dev = NULL;
	struct sk_buff *inner_skb = NULL;
	struct sk_buff *outer_skb = NULL;
	struct sk_buff *stream_outer_skb = NULL;
	struct sk_buff *partial_outer_skb = NULL;
	struct sk_buff *continuation_skb = NULL;
	struct sk_buff *reassembled_skb = NULL;
	struct sk_buff *restored_skb = NULL;
	struct sk_buff *split_outer_skb = NULL;
	struct skb_shared_info *shinfo;
	struct tcphdr *tcph;
	struct iphdr *iph;
	struct iphdr *outer_iph;
	struct page *page = NULL;
	struct page *split_page = NULL;
	void *page_addr;
	__u8 wire[TRUSTIX_DATAPATH_TIXT_HEADER_LEN];
	__u8 header[sizeof(struct iphdr) + 60];
	__u8 sample[32];
	__u8 sample_expected[32];
	__u64 saved_features = READ_ONCE(trustix_datapath_features);
	__u64 saved_partial_frames =
		trustix_datapath_rx_worker_inner_tcp_checksum_partial;
	__u64 saved_partial_errors =
		trustix_datapath_rx_worker_inner_tcp_checksum_partial_errors;
	__u64 saved_inner_gso_candidates =
		trustix_datapath_rx_worker_inner_gso_candidates;
	__u64 saved_inner_gso_partial_frames =
		trustix_datapath_rx_worker_inner_gso_partial_frames;
	__u64 saved_reassembly_started =
		trustix_datapath_rx_worker_inner_gso_reassembly_started;
	__u64 saved_continuation_matched =
		trustix_datapath_rx_worker_inner_gso_continuation_matched;
	__u64 saved_continuation_orphans =
		trustix_datapath_rx_worker_inner_gso_continuation_orphans;
	__u64 saved_continuation_drops =
		trustix_datapath_rx_worker_inner_gso_continuation_drops;
	__u64 saved_session_clears =
		trustix_datapath_rx_worker_inner_gso_session_clears;
	__u64 saved_session_slots_cleared =
		trustix_datapath_rx_worker_inner_gso_session_slots_cleared;
	__u64 saved_sequence_gaps =
		trustix_datapath_rx_worker_inner_gso_sequence_gaps;
	__u64 saved_sequence_gap_ahead =
		trustix_datapath_rx_worker_inner_gso_sequence_gap_ahead;
	__u64 saved_sequence_gap_behind =
		trustix_datapath_rx_worker_inner_gso_sequence_gap_behind;
	int saved_last_sequence_gap =
		trustix_datapath_rx_worker_inner_gso_last_sequence_gap;
	__u64 saved_reassembly_timeouts =
		trustix_datapath_rx_worker_inner_gso_timeouts;
	__u64 saved_timeouts_on_start =
		trustix_datapath_rx_worker_inner_gso_timeouts_on_start;
	__u64 saved_timeouts_on_append =
		trustix_datapath_rx_worker_inner_gso_timeouts_on_append;
	__u64 saved_timeouts_on_sweep =
		trustix_datapath_rx_worker_inner_gso_timeouts_on_sweep;
	__u64 saved_timeout_missing_bytes =
		trustix_datapath_rx_worker_inner_gso_timeout_missing_bytes;
	__u64 saved_timeout_max_missing_bytes =
		trustix_datapath_rx_worker_inner_gso_timeout_max_missing_bytes;
	__u64 saved_duplicate_starts =
		trustix_datapath_rx_worker_inner_gso_duplicate_starts;
	__u64 saved_collisions =
		trustix_datapath_rx_worker_inner_gso_collisions;
	__u64 saved_reassembly_high_watermark =
		trustix_datapath_rx_worker_inner_gso_reassembly_high_watermark;
	__u64 concurrent_started;
	__u64 concurrent_matched;
	__u64 capacity_collisions;
	__u64 out_of_order_matched;
	unsigned int gso_segs = 0;
	unsigned int queued_frames = 0;
	unsigned int scoped_active = 0;
	unsigned int i;
	unsigned int reassembly_set;
	unsigned long reassembly_flags;
	unsigned long circuit_flags;
	unsigned long saved_circuit_until;
	unsigned long saved_fault_window_start;
	unsigned long saved_timeout_window_start;
	unsigned long saved_last_recovery;
	unsigned int saved_fault_window_count;
	unsigned int saved_timeout_window_count;
	unsigned int saved_timeout_success_credit;
	unsigned int saved_timeout_last_ratio_ppm;
	unsigned int saved_backoff_level;
	unsigned int saved_last_cooldown_ms;
	unsigned long long saved_runtime_faults;
	unsigned long long saved_circuit_trips;
	unsigned long long saved_timeout_circuit_trips;
	unsigned long long saved_timeout_ratio_suppressions;
	unsigned long long saved_no_progress_circuit_trips;
	unsigned long long saved_circuit_recoveries;
	unsigned long long saved_probation_arms;
	unsigned long long saved_probation_claims;
	unsigned long long saved_probation_successes;
	unsigned long long saved_probation_failures;
	unsigned long long saved_probation_idle_resets;
	unsigned long long saved_probation_evictions;
	unsigned long long saved_probation_collisions;
	unsigned int saved_last_no_progress_ms;
	bool saved_auto_recover;
	bool saved_circuit_open;
	bool saved_circuit_recovering;
	bool reassembly_found;
	__u32 continuation_payload_len;
	__u32 first_continuation_len;
	__u32 first_frame_sequence;
	__u32 second_frame_sequence;
	__u32 tail_offset = 0;
	__u32 tail_len = 0;
	__u32 split_head_len = inner_offset - 16;
	__u32 split_frag_len;
	bool candidate = false;
	int ret = 0;

	if (trustix_datapath_inner_gso_error_trips_circuit(0) ||
	    trustix_datapath_inner_gso_error_trips_circuit(-ETIMEDOUT) ||
	    trustix_datapath_inner_gso_error_trips_circuit(-ENOENT) ||
	    trustix_datapath_inner_gso_error_trips_circuit(-EILSEQ) ||
	    trustix_datapath_inner_gso_error_trips_circuit(-EAGAIN) ||
	    !trustix_datapath_inner_gso_error_trips_circuit(-ENOMEM))
		return -EINVAL;
	{
		unsigned int observed_ratio = 0;

		if (trustix_datapath_inner_gso_timeout_success_credit_cap(
			    TRUSTIX_DATAPATH_INNER_GSO_TIMEOUT_THRESHOLD_DEFAULT,
			    TRUSTIX_DATAPATH_INNER_GSO_TIMEOUT_RATIO_PPM_DEFAULT) !=
			    1280U ||
		    trustix_datapath_inner_gso_timeout_ratio_trips(
			    64, 1280,
			    TRUSTIX_DATAPATH_INNER_GSO_TIMEOUT_RATIO_PPM_DEFAULT,
			    &observed_ratio) ||
		    observed_ratio >=
			    TRUSTIX_DATAPATH_INNER_GSO_TIMEOUT_RATIO_PPM_DEFAULT ||
		    !trustix_datapath_inner_gso_timeout_ratio_trips(
			    64, 80,
			    TRUSTIX_DATAPATH_INNER_GSO_TIMEOUT_RATIO_PPM_DEFAULT,
			    &observed_ratio) ||
		    observed_ratio <
			    TRUSTIX_DATAPATH_INNER_GSO_TIMEOUT_RATIO_PPM_DEFAULT ||
		    !trustix_datapath_inner_gso_timeout_ratio_trips(
			    64, 1280, 0, &observed_ratio))
			return -EINVAL;
	}

	test_dev = kzalloc(sizeof(*test_dev), GFP_KERNEL);
	if (!test_dev)
		return -ENOMEM;
	spin_lock_irqsave(&trustix_datapath_inner_gso_circuit_lock,
			  circuit_flags);
	saved_circuit_open = trustix_datapath_inner_gso_circuit_open;
	saved_circuit_recovering =
		trustix_datapath_inner_gso_circuit_recovering;
	saved_circuit_until = trustix_datapath_inner_gso_circuit_until;
	saved_fault_window_start =
		trustix_datapath_inner_gso_fault_window_start;
	saved_timeout_window_start =
		trustix_datapath_inner_gso_timeout_window_start;
	saved_last_recovery = trustix_datapath_inner_gso_last_recovery;
	saved_fault_window_count =
		trustix_datapath_inner_gso_fault_window_count;
	saved_timeout_window_count =
		trustix_datapath_inner_gso_timeout_window_count;
	saved_timeout_success_credit =
		trustix_datapath_inner_gso_timeout_success_credit;
	saved_timeout_last_ratio_ppm =
		trustix_datapath_inner_gso_timeout_last_ratio_ppm;
	saved_backoff_level = trustix_datapath_inner_gso_backoff_level;
	saved_last_cooldown_ms =
		trustix_datapath_inner_gso_last_cooldown_ms;
	saved_runtime_faults = trustix_datapath_inner_gso_runtime_faults;
	saved_circuit_trips = trustix_datapath_inner_gso_circuit_trips;
	saved_timeout_circuit_trips =
		trustix_datapath_inner_gso_timeout_circuit_trips;
	saved_timeout_ratio_suppressions =
		trustix_datapath_inner_gso_timeout_ratio_suppressions;
	saved_no_progress_circuit_trips =
		trustix_datapath_inner_gso_no_progress_circuit_trips;
	saved_circuit_recoveries =
		trustix_datapath_inner_gso_circuit_recoveries;
	saved_probation_arms = trustix_datapath_inner_gso_probation_arms;
	saved_probation_claims = trustix_datapath_inner_gso_probation_claims;
	saved_probation_successes =
		trustix_datapath_inner_gso_probation_successes;
	saved_probation_failures =
		trustix_datapath_inner_gso_probation_failures;
	saved_probation_idle_resets =
		trustix_datapath_inner_gso_probation_idle_resets;
	saved_probation_evictions =
		trustix_datapath_inner_gso_probation_evictions;
	saved_probation_collisions =
		trustix_datapath_inner_gso_probation_collisions;
	saved_last_no_progress_ms =
		trustix_datapath_inner_gso_last_no_progress_ms;
	saved_auto_recover =
		READ_ONCE(trustix_datapath_inner_gso_auto_recover);
	spin_unlock_irqrestore(&trustix_datapath_inner_gso_circuit_lock,
			       circuit_flags);
	test_dev->type = ARPHRD_ETHER;
	test_dev->mtu = 1500;
	test_dev->features = NETIF_F_TSO | NETIF_F_HW_CSUM;

	inner_skb = alloc_skb(LL_MAX_HEADER + sizeof(struct iphdr) +
				      tcp_header_len, GFP_KERNEL);
	if (!inner_skb) {
		ret = -ENOMEM;
		goto out;
	}
	skb_reserve(inner_skb, LL_MAX_HEADER);
	iph = (struct iphdr *)skb_put(inner_skb, sizeof(*iph));
	tcph = (struct tcphdr *)skb_put(inner_skb, tcp_header_len);
	memset(iph, 0, sizeof(*iph) + tcp_header_len);
	iph->version = 4;
	iph->ihl = sizeof(*iph) / 4;
	iph->tot_len = htons((__u16)inner_len);
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->saddr = htonl(0xc0000201U);
	iph->daddr = htonl(0xc6336402U);
	tcph->source = htons(12345);
	tcph->dest = htons(443);
	tcph->seq = htonl(0x10203040U);
	tcph->doff = tcp_header_len / 4;
	tcph->ack = 1;
	tcph->check = ~csum_tcpudp_magic(
		iph->saddr, iph->daddr, inner_len - sizeof(*iph),
		IPPROTO_TCP, 0);
	trustix_datapath_rx_worker_fix_ipv4_header_checksum(iph,
						   sizeof(*iph));
	page = alloc_page(GFP_KERNEL);
	if (!page) {
		ret = -ENOMEM;
		goto out;
	}
	page_addr = kmap_local_page(page);
	for (i = 0; i < payload_len; i++)
		((__u8 *)page_addr)[i] = (__u8)(i * 17U + 3U);
	kunmap_local(page_addr);
	skb_add_rx_frag(inner_skb, 0, page, 0, payload_len, PAGE_SIZE);
	page = NULL;
	skb_reset_network_header(inner_skb);
	skb_set_transport_header(inner_skb, sizeof(*iph));
	inner_skb->protocol = htons(ETH_P_IP);
	inner_skb->ip_summed = CHECKSUM_PARTIAL;
	inner_skb->csum_start = skb_transport_header(inner_skb) -
				inner_skb->head;
	inner_skb->csum_offset = offsetof(struct tcphdr, check);
	shinfo = skb_shinfo(inner_skb);
	shinfo->gso_size = 1000;
	shinfo->gso_segs = 3;
	shinfo->gso_type = SKB_GSO_TCPV4;

	plan.flow_id = 7;
	plan.epoch = 11;
	plan.session_flags =
		TRUSTIX_DATAPATH_SESSION_FLAG_SEND_INNER_TCP_CHECKSUM_PARTIAL |
		TRUSTIX_DATAPATH_SESSION_FLAG_SEND_INNER_GSO;
	plan.local_ipv4 = 0xc000020aU;
	plan.remote_ipv4 = 0xc633640aU;
	plan.local_port = 20000;
	plan.remote_port = 30000;
	plan.outer_protocol = IPPROTO_TCP;
	/* The logical transport limit must never override the egress MTU. */
	plan.max_packet_size = 65535;
	WRITE_ONCE(trustix_datapath_features,
		   saved_features |
			   TRUSTIX_DATAPATH_FEATURE_INNER_TCP_CHECKSUM_PARTIAL |
			   TRUSTIX_DATAPATH_FEATURE_INNER_GSO);
	ret = trustix_datapath_tx_build_inner_gso_skb(
		inner_skb, &plan, test_dev, &outer_skb, &gso_segs);
	if (ret)
		goto out;
	if (gso_segs != 3 || !skb_is_gso(outer_skb) ||
	    !skb_is_nonlinear(outer_skb) ||
	    skb_shinfo(outer_skb)->gso_size != 1460 ||
	    skb_shinfo(outer_skb)->gso_segs != 3 ||
	    outer_skb->len != inner_offset + inner_len) {
		ret = -EINVAL;
		goto out;
	}
	if (trustix_datapath_tx_validate_outer_skb_mtu(outer_skb,
						      test_dev)) {
		ret = -EINVAL;
		goto out;
	}
	shinfo = skb_shinfo(outer_skb);
	shinfo->gso_size = 1461;
	if (trustix_datapath_tx_validate_outer_skb_mtu(outer_skb,
						      test_dev) != -EMSGSIZE) {
		ret = -EINVAL;
		goto out;
	}
	shinfo->gso_size = 1460;
	if (skb_copy_bits(outer_skb, sizeof(struct iphdr) +
				       sizeof(struct tcphdr),
			  wire, sizeof(wire))) {
		ret = -ENODATA;
		goto out;
	}
	ret = trustix_datapath_parse_tixt_header(
		wire, TRUSTIX_DATAPATH_TIXT_HEADER_LEN + inner_len, &frame);
	if (ret || frame.flags !=
			   (TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4 |
			    TRUSTIX_DATAPATH_TIXT_FLAG_INNER_TCP_CHECKSUM_PARTIAL |
			    TRUSTIX_DATAPATH_TIXT_FLAG_INNER_GSO) ||
	    frame.payload_len != inner_len || frame.fragment_index != 1000 ||
	    frame.fragment_count != 3) {
		ret = ret ?: -EINVAL;
		goto out;
	}
	stream_outer_skb = alloc_skb(sizeof(struct iphdr) +
					    sizeof(struct tcphdr) +
					    frame.wire_len * 2, GFP_KERNEL);
	if (!stream_outer_skb) {
		ret = -ENOMEM;
		goto out;
	}
	if (skb_copy_bits(outer_skb, 0,
			  skb_put(stream_outer_skb, outer_skb->len),
			  outer_skb->len) ||
	    skb_copy_bits(outer_skb,
			  sizeof(struct iphdr) + sizeof(struct tcphdr),
			  skb_put(stream_outer_skb, frame.wire_len),
			  frame.wire_len)) {
		ret = -ENODATA;
		goto out;
	}
	skb_reset_network_header(stream_outer_skb);
	skb_set_transport_header(stream_outer_skb, sizeof(struct iphdr));
	outer_iph = ip_hdr(stream_outer_skb);
	outer_iph->tot_len = htons((__u16)stream_outer_skb->len);
	trustix_datapath_rx_worker_fix_ipv4_header_checksum(
		outer_iph, sizeof(*outer_iph));
	partial_outer_skb = skb_clone(outer_skb, GFP_KERNEL);
	if (!partial_outer_skb) {
		ret = -ENOMEM;
		goto out;
	}
	ret = skb_linearize(partial_outer_skb);
	if (ret)
		goto out;
	ret = pskb_trim(partial_outer_skb, 1500);
	if (ret)
		goto out;
	outer_iph = ip_hdr(partial_outer_skb);
	outer_iph->tot_len = htons((__u16)partial_outer_skb->len);
	trustix_datapath_rx_worker_fix_ipv4_header_checksum(
		outer_iph, sizeof(*outer_iph));
	outer.protocol = IPPROTO_TCP;
	ret = trustix_datapath_rx_worker_try_inner_gso(
		partial_outer_skb, &outer, sizeof(struct iphdr),
		sizeof(struct tcphdr), 0, NULL, 1, false, &candidate,
		&queued_frames);
	if (ret || !candidate || queued_frames ||
	    trustix_datapath_rx_worker_inner_gso_candidates !=
		    saved_inner_gso_candidates + 1 ||
	    trustix_datapath_rx_worker_inner_gso_partial_frames !=
		    saved_inner_gso_partial_frames + 1 ||
	    trustix_datapath_rx_worker_inner_gso_reassembly_started !=
		    saved_reassembly_started + 1) {
		ret = -EINVAL;
		goto out;
	}
	continuation_payload_len =
		outer_skb->len - partial_outer_skb->len;
	first_continuation_len =
		min_t(__u32, 800, continuation_payload_len - 1);
	continuation_skb = trustix_datapath_selftest_tix_tcp_segment(
		outer_skb, partial_outer_skb->len, first_continuation_len,
		partial_outer_skb->len -
			(sizeof(struct iphdr) + sizeof(struct tcphdr)));
	if (!continuation_skb) {
		ret = -ENOMEM;
		goto out;
	}
	ret = trustix_datapath_inner_gso_reassembly_append(
		continuation_skb, &outer, sizeof(struct iphdr),
		sizeof(struct tcphdr), 0, &reassembled_skb, &tail_offset,
		&tail_len, false);
	if (ret || reassembled_skb || tail_offset || tail_len ||
	    trustix_datapath_rx_worker_inner_gso_continuation_matched !=
		    saved_continuation_matched + 1) {
		ret = -EINVAL;
		goto out;
	}
	kfree_skb(continuation_skb);
	continuation_skb = trustix_datapath_selftest_tix_tcp_segment(
		outer_skb, partial_outer_skb->len + first_continuation_len,
		continuation_payload_len - first_continuation_len,
		partial_outer_skb->len -
				(sizeof(struct iphdr) + sizeof(struct tcphdr)) +
			first_continuation_len);
	if (!continuation_skb) {
		ret = -ENOMEM;
		goto out;
	}
	ret = trustix_datapath_inner_gso_reassembly_append(
		continuation_skb, &outer, sizeof(struct iphdr),
		sizeof(struct tcphdr), 0, &reassembled_skb, &tail_offset,
		&tail_len, false);
	if (ret || !reassembled_skb || tail_len ||
	    trustix_datapath_rx_worker_inner_gso_continuation_matched !=
		    saved_continuation_matched + 2 ||
	    reassembled_skb->len != frame.wire_len) {
		ret = -EINVAL;
		goto out;
	}
	for (i = 0; i < reassembled_skb->len; i += sizeof(sample)) {
		__u32 compare_len =
			min_t(__u32, sizeof(sample), reassembled_skb->len - i);

		if (skb_copy_bits(reassembled_skb, i, sample, compare_len) ||
		    skb_copy_bits(outer_skb,
				  sizeof(struct iphdr) +
					  sizeof(struct tcphdr) + i,
				  sample_expected, compare_len) ||
		    memcmp(sample, sample_expected, compare_len)) {
			ret = -EINVAL;
			goto out;
		}
	}
	kfree_skb(reassembled_skb);
	reassembled_skb = NULL;
	kfree_skb(continuation_skb);
	continuation_skb = NULL;
	/* Fill a one-byte sequence gap after the later range arrives first. */
	trustix_datapath_clear_inner_gso_reassembly();

	candidate = false;
	queued_frames = 0;
	ret = trustix_datapath_rx_worker_try_inner_gso(
		partial_outer_skb, &outer, sizeof(struct iphdr),
		sizeof(struct tcphdr), 0, NULL, 1, false, &candidate,
		&queued_frames);
	if (ret || !candidate || queued_frames) {
		ret = -EINVAL;
		goto out;
	}
	out_of_order_matched =
		trustix_datapath_rx_worker_inner_gso_continuation_matched;
	continuation_skb = trustix_datapath_selftest_tix_tcp_segment(
		outer_skb, partial_outer_skb->len + 1,
		continuation_payload_len - 1,
		partial_outer_skb->len -
				(sizeof(struct iphdr) + sizeof(struct tcphdr)) +
			1);
	if (!continuation_skb) {
		ret = -ENOMEM;
		goto out;
	}
	ret = trustix_datapath_inner_gso_reassembly_append(
		continuation_skb, &outer, sizeof(struct iphdr),
		sizeof(struct tcphdr), 0, &reassembled_skb, &tail_offset,
		&tail_len, false);
	if (ret || reassembled_skb || tail_offset || tail_len ||
	    trustix_datapath_rx_worker_inner_gso_continuation_matched !=
		    out_of_order_matched + 1) {
		ret = -EINVAL;
		goto out;
	}
	kfree_skb(continuation_skb);
	continuation_skb = trustix_datapath_selftest_tix_tcp_segment(
		outer_skb, partial_outer_skb->len, 1,
		partial_outer_skb->len -
			(sizeof(struct iphdr) + sizeof(struct tcphdr)));
	if (!continuation_skb) {
		ret = -ENOMEM;
		goto out;
	}
	ret = trustix_datapath_inner_gso_reassembly_append(
		continuation_skb, &outer, sizeof(struct iphdr),
		sizeof(struct tcphdr), 0, &reassembled_skb, &tail_offset,
		&tail_len, false);
	if (ret || !reassembled_skb || tail_len ||
	    reassembled_skb->len != frame.wire_len ||
	    trustix_datapath_rx_worker_inner_gso_continuation_matched !=
		    out_of_order_matched + 2) {
		ret = -EINVAL;
		goto out;
	}
	kfree_skb(reassembled_skb);
	reassembled_skb = NULL;
	kfree_skb(continuation_skb);
	continuation_skb = NULL;

	/* A continuation outside every active frame remains fail-closed. */
	candidate = false;
	queued_frames = 0;
	ret = trustix_datapath_rx_worker_try_inner_gso(
		partial_outer_skb, &outer, sizeof(struct iphdr),
		sizeof(struct tcphdr), 0, NULL, 1, false, &candidate,
		&queued_frames);
	if (ret || !candidate || queued_frames) {
		ret = -EINVAL;
		goto out;
	}
	continuation_skb = trustix_datapath_selftest_tix_tcp_segment(
		outer_skb, partial_outer_skb->len, 1, frame.wire_len + 1);
	if (!continuation_skb) {
		ret = -ENOMEM;
		goto out;
	}
	ret = trustix_datapath_inner_gso_reassembly_append(
		continuation_skb, &outer, sizeof(struct iphdr),
		sizeof(struct tcphdr), 0, &reassembled_skb, &tail_offset,
		&tail_len, false);
	if (ret != -EILSEQ || reassembled_skb ||
	    trustix_datapath_rx_worker_inner_gso_sequence_gaps !=
		    saved_sequence_gaps + 1) {
		ret = -EINVAL;
		goto out;
	}
	kfree_skb(continuation_skb);
	continuation_skb = NULL;
	trustix_datapath_clear_inner_gso_reassembly();

	candidate = false;
	queued_frames = 0;
	ret = trustix_datapath_rx_worker_try_inner_gso(
		partial_outer_skb, &outer, sizeof(struct iphdr),
		sizeof(struct tcphdr), 0, NULL, 1, false, &candidate,
		&queued_frames);
	if (ret || !candidate || queued_frames) {
		ret = -EINVAL;
		goto out;
	}
	trustix_datapath_inner_gso_reassembly_key_init(
		&reassembly_key, partial_outer_skb, &outer, 0);
	reassembly_set =
		trustix_datapath_inner_gso_reassembly_set(&reassembly_key);
	reassembly_found = false;
	spin_lock_irqsave(
		&trustix_datapath_inner_gso_reassembly_locks[reassembly_set],
		reassembly_flags);
	for (i = 0; i < TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_PROBES; i++) {
		struct trustix_datapath_inner_gso_reassembly_slot *slot =
			&trustix_datapath_inner_gso_reassembly_slots[
				reassembly_set *
					TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_PROBES +
				i];

		if (!slot->active ||
		    !trustix_datapath_inner_gso_reassembly_key_equal(
			    &slot->key, &reassembly_key))
			continue;
		slot->expires = jiffies - 1;
		reassembly_found = true;
		break;
	}
	spin_unlock_irqrestore(
		&trustix_datapath_inner_gso_reassembly_locks[reassembly_set],
		reassembly_flags);
	if (!reassembly_found) {
		ret = -EINVAL;
		goto out;
	}
	continuation_skb = trustix_datapath_selftest_tix_tcp_segment(
		outer_skb, partial_outer_skb->len, continuation_payload_len,
		partial_outer_skb->len -
			(sizeof(struct iphdr) + sizeof(struct tcphdr)));
	if (!continuation_skb) {
		ret = -ENOMEM;
		goto out;
	}
	ret = trustix_datapath_inner_gso_reassembly_append(
		continuation_skb, &outer, sizeof(struct iphdr),
		sizeof(struct tcphdr), 0, &reassembled_skb, &tail_offset,
		&tail_len, false);
	if (ret != -ETIMEDOUT || reassembled_skb ||
	    trustix_datapath_rx_worker_inner_gso_timeouts !=
		    saved_reassembly_timeouts + 1) {
		ret = -EINVAL;
		goto out;
	}
	kfree_skb(continuation_skb);
	continuation_skb = NULL;
	first_frame_sequence = ntohl(tcp_hdr(partial_outer_skb)->seq);

	/*
	 * One stale partial slot is a packet-loss sample, not proof that the
	 * receive path stopped. Expiration stays governed by the timeout-burst
	 * threshold even when that individual stream has gone idle. Active
	 * continuation traffic without successful delivery is covered by the
	 * probation test below.
	 */
	{
		unsigned int no_progress_ms =
			trustix_datapath_inner_gso_bounded_ms(
				READ_ONCE(
					trustix_datapath_inner_gso_no_progress_ms),
				TRUSTIX_DATAPATH_INNER_GSO_NO_PROGRESS_MS_DEFAULT);
		unsigned long stale_progress =
			jiffies - max_t(unsigned long, 1,
				msecs_to_jiffies(no_progress_ms)) - 1;
		unsigned long long sweep_timeouts =
			trustix_datapath_rx_worker_inner_gso_timeouts_on_sweep;
		unsigned long long no_progress_trips =
			trustix_datapath_inner_gso_no_progress_circuit_trips;
		unsigned long long circuit_trips =
			trustix_datapath_inner_gso_circuit_trips;

		ret = trustix_datapath_inner_gso_reassembly_start(
			partial_outer_skb, &outer, 0,
			sizeof(struct iphdr) + sizeof(struct tcphdr),
			partial_outer_skb->len -
				(sizeof(struct iphdr) + sizeof(struct tcphdr)),
			&frame, first_frame_sequence, false);
		if (ret)
			goto out;
		trustix_datapath_inner_gso_reassembly_record_progress(
			partial_outer_skb, &outer, 0, &frame);
		reassembly_found = false;
		spin_lock_irqsave(
			&trustix_datapath_inner_gso_reassembly_locks[
				reassembly_set],
			reassembly_flags);
		for (i = 0; i < TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_PROBES;
		     i++) {
			struct trustix_datapath_inner_gso_reassembly_slot *slot =
				&trustix_datapath_inner_gso_reassembly_slots[
					reassembly_set *
						TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_PROBES +
					i];

			if (!slot->active || slot->flow_id != frame.flow_id ||
			    slot->epoch != frame.epoch)
				continue;
			slot->expires = jiffies - 1;
			reassembly_found = true;
			break;
		}
		spin_unlock_irqrestore(
			&trustix_datapath_inner_gso_reassembly_locks[
				reassembly_set],
			reassembly_flags);
		if (!reassembly_found) {
			ret = -EINVAL;
			goto out;
		}
		trustix_datapath_sweep_inner_gso_reassembly();
		if (trustix_datapath_inner_gso_circuit_open ||
		    trustix_datapath_inner_gso_no_progress_circuit_trips !=
			    no_progress_trips ||
		    trustix_datapath_rx_worker_inner_gso_timeouts_on_sweep !=
			    sweep_timeouts + 1) {
			ret = -EINVAL;
			goto out;
		}

		ret = trustix_datapath_inner_gso_reassembly_start(
			partial_outer_skb, &outer, 0,
			sizeof(struct iphdr) + sizeof(struct tcphdr),
			partial_outer_skb->len -
				(sizeof(struct iphdr) + sizeof(struct tcphdr)),
			&frame, first_frame_sequence, false);
		if (ret)
			goto out;
		reassembly_found = false;
		spin_lock_irqsave(
			&trustix_datapath_inner_gso_reassembly_locks[
				reassembly_set],
			reassembly_flags);
		for (i = 0; i < TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_PROBES;
		     i++) {
			struct trustix_datapath_inner_gso_reassembly_slot *slot =
				&trustix_datapath_inner_gso_reassembly_slots[
					reassembly_set *
						TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_PROBES +
					i];

			if (!slot->active || slot->flow_id != frame.flow_id ||
			    slot->epoch != frame.epoch)
				continue;
			slot->stream_last_progress = stale_progress;
			slot->expires = jiffies - 1;
			reassembly_found = true;
			break;
		}
		spin_unlock_irqrestore(
			&trustix_datapath_inner_gso_reassembly_locks[
				reassembly_set],
			reassembly_flags);
		if (!reassembly_found) {
			ret = -EINVAL;
			goto out;
		}
		trustix_datapath_sweep_inner_gso_reassembly();
		if (trustix_datapath_inner_gso_circuit_open ||
		    trustix_datapath_inner_gso_no_progress_circuit_trips !=
			    no_progress_trips ||
		    trustix_datapath_inner_gso_circuit_trips !=
			    circuit_trips ||
		    trustix_datapath_rx_worker_inner_gso_timeouts_on_sweep !=
			    sweep_timeouts + 2) {
			ret = -EINVAL;
			goto out;
		}
	}

	/* Continuation activity without delivery must survive an empty slot set. */
	{
		struct trustix_datapath_inner_gso_probation_slot *slot;
		unsigned int no_progress_ms =
			trustix_datapath_inner_gso_bounded_ms(
				READ_ONCE(
					trustix_datapath_inner_gso_no_progress_ms),
				TRUSTIX_DATAPATH_INNER_GSO_NO_PROGRESS_MS_DEFAULT);
		unsigned long stale_claim =
			jiffies - max_t(unsigned long, 1,
				msecs_to_jiffies(no_progress_ms)) - 1;
		unsigned long long probation_arms =
			trustix_datapath_inner_gso_probation_arms;
		unsigned long long probation_claims =
			trustix_datapath_inner_gso_probation_claims;
		unsigned long long probation_successes =
			trustix_datapath_inner_gso_probation_successes;
		unsigned long long probation_failures =
			trustix_datapath_inner_gso_probation_failures;
		unsigned long long no_progress_trips =
			trustix_datapath_inner_gso_no_progress_circuit_trips;
		unsigned long long circuit_trips =
			trustix_datapath_inner_gso_circuit_trips;
		unsigned int probation_set;
		unsigned long probation_flags;

		trustix_datapath_clear_inner_gso_probation_matching(
			true, 0, 0);
		trustix_datapath_inner_gso_probation_record_success(
			partial_outer_skb, &outer, 0, &frame);
		trustix_datapath_inner_gso_probation_record_claim(
			partial_outer_skb, &outer, 0, frame.flow_id,
			frame.epoch);
		trustix_datapath_inner_gso_reassembly_key_init(
			&reassembly_key, partial_outer_skb, &outer, 0);
		probation_set = trustix_datapath_inner_gso_probation_set(
			&reassembly_key, frame.flow_id, frame.epoch);
		spin_lock_irqsave(
			&trustix_datapath_inner_gso_probation_locks[
				probation_set],
			probation_flags);
		slot = trustix_datapath_inner_gso_probation_get_locked(
			&reassembly_key, frame.flow_id, frame.epoch,
			probation_set, jiffies, false);
		if (slot) {
			slot->first_claim = stale_claim;
			slot->last_claim = jiffies;
			slot->claims_since_success = 1;
		}
		spin_unlock_irqrestore(
			&trustix_datapath_inner_gso_probation_locks[
				probation_set],
			probation_flags);
		if (!slot) {
			ret = -EINVAL;
			goto out;
		}

		/* A successful delivery cancels an aged observation window. */
		trustix_datapath_inner_gso_probation_record_success(
			partial_outer_skb, &outer, 0, &frame);
		trustix_datapath_inner_gso_probation_record_claim(
			partial_outer_skb, &outer, 0, frame.flow_id,
			frame.epoch);
		if (trustix_datapath_inner_gso_circuit_open ||
		    trustix_datapath_inner_gso_probation_failures !=
			    probation_failures) {
			ret = -EINVAL;
			goto out;
		}

		spin_lock_irqsave(
			&trustix_datapath_inner_gso_probation_locks[
				probation_set],
			probation_flags);
		slot = trustix_datapath_inner_gso_probation_get_locked(
			&reassembly_key, frame.flow_id, frame.epoch,
			probation_set, jiffies, false);
		if (slot) {
			slot->first_claim = stale_claim;
			slot->last_claim = jiffies;
			slot->claims_since_success =
				TRUSTIX_DATAPATH_INNER_GSO_PROBATION_MIN_CLAIMS - 1;
		}
		spin_unlock_irqrestore(
			&trustix_datapath_inner_gso_probation_locks[
				probation_set],
			probation_flags);
		if (!slot) {
			ret = -EINVAL;
			goto out;
		}
		trustix_datapath_inner_gso_probation_record_claim(
			partial_outer_skb, &outer, 0, frame.flow_id,
			frame.epoch);
		if (!trustix_datapath_inner_gso_circuit_open ||
		    trustix_datapath_inner_gso_probation_arms <
			    probation_arms + 2 ||
		    trustix_datapath_inner_gso_probation_claims <
			    probation_claims + 3 ||
		    trustix_datapath_inner_gso_probation_successes !=
			    probation_successes + 2 ||
		    trustix_datapath_inner_gso_probation_failures !=
			    probation_failures + 1 ||
		    trustix_datapath_inner_gso_no_progress_circuit_trips !=
			    no_progress_trips + 1 ||
		    trustix_datapath_inner_gso_circuit_trips !=
			    circuit_trips + 1 ||
		    trustix_datapath_inner_gso_last_no_progress_ms <
			    no_progress_ms) {
			ret = -EINVAL;
			goto out;
		}
		spin_lock_irqsave(&trustix_datapath_inner_gso_circuit_lock,
				  circuit_flags);
		trustix_datapath_inner_gso_fault_window_start = jiffies;
		trustix_datapath_inner_gso_fault_window_count = 0;
		trustix_datapath_inner_gso_timeout_window_start = jiffies;
		trustix_datapath_inner_gso_timeout_window_count = 0;
		trustix_datapath_inner_gso_timeout_success_credit = 0;
		trustix_datapath_inner_gso_circuit_recovering = false;
		smp_store_release(&trustix_datapath_inner_gso_circuit_open,
				  false);
		spin_unlock_irqrestore(
			&trustix_datapath_inner_gso_circuit_lock, circuit_flags);
		trustix_datapath_clear_inner_gso_probation_matching(
			true, 0, 0);
	}

	/* Complete two partial frames on one tuple in reverse order. */
	trustix_datapath_clear_inner_gso_reassembly();
	second_frame_sequence = first_frame_sequence + frame.wire_len;
	concurrent_started =
		trustix_datapath_rx_worker_inner_gso_reassembly_started;
	concurrent_matched =
		trustix_datapath_rx_worker_inner_gso_continuation_matched;
	ret = trustix_datapath_inner_gso_reassembly_start(
		partial_outer_skb, &outer, 0,
		sizeof(struct iphdr) + sizeof(struct tcphdr),
		partial_outer_skb->len -
			(sizeof(struct iphdr) + sizeof(struct tcphdr)),
		&frame, first_frame_sequence, false);
	if (ret)
		goto out;
	ret = trustix_datapath_inner_gso_reassembly_start(
		partial_outer_skb, &outer, 0,
		sizeof(struct iphdr) + sizeof(struct tcphdr),
		partial_outer_skb->len -
			(sizeof(struct iphdr) + sizeof(struct tcphdr)),
		&frame, second_frame_sequence, false);
	if (ret ||
	    trustix_datapath_rx_worker_inner_gso_reassembly_started !=
		    concurrent_started + 2) {
		ret = -EINVAL;
		goto out;
	}
	/* Retransmitting a frame head refreshes its slot without displacement. */
	ret = trustix_datapath_inner_gso_reassembly_start(
		partial_outer_skb, &outer, 0,
		sizeof(struct iphdr) + sizeof(struct tcphdr),
		partial_outer_skb->len -
			(sizeof(struct iphdr) + sizeof(struct tcphdr)),
		&frame, first_frame_sequence, false);
	if (ret ||
	    trustix_datapath_rx_worker_inner_gso_reassembly_started !=
		    concurrent_started + 2) {
		ret = -EINVAL;
		goto out;
	}
	continuation_skb = trustix_datapath_selftest_tix_tcp_segment(
		outer_skb, partial_outer_skb->len, continuation_payload_len,
		frame.wire_len + partial_outer_skb->len -
			(sizeof(struct iphdr) + sizeof(struct tcphdr)));
	if (!continuation_skb) {
		ret = -ENOMEM;
		goto out;
	}
	ret = trustix_datapath_inner_gso_reassembly_append(
		continuation_skb, &outer, sizeof(struct iphdr),
		sizeof(struct tcphdr), 0, &reassembled_skb, &tail_offset,
		&tail_len, false);
	if (ret || !reassembled_skb || tail_len ||
	    reassembled_skb->len != frame.wire_len ||
	    trustix_datapath_rx_worker_inner_gso_continuation_matched !=
		    concurrent_matched + 1) {
		ret = -EINVAL;
		goto out;
	}
	kfree_skb(reassembled_skb);
	reassembled_skb = NULL;
	kfree_skb(continuation_skb);
	continuation_skb = trustix_datapath_selftest_tix_tcp_segment(
		outer_skb, partial_outer_skb->len, continuation_payload_len,
		partial_outer_skb->len -
			(sizeof(struct iphdr) + sizeof(struct tcphdr)));
	if (!continuation_skb) {
		ret = -ENOMEM;
		goto out;
	}
	ret = trustix_datapath_inner_gso_reassembly_append(
		continuation_skb, &outer, sizeof(struct iphdr),
		sizeof(struct tcphdr), 0, &reassembled_skb, &tail_offset,
		&tail_len, false);
	if (ret || !reassembled_skb || tail_len ||
	    reassembled_skb->len != frame.wire_len ||
	    trustix_datapath_rx_worker_inner_gso_continuation_matched !=
		    concurrent_matched + 2) {
		ret = -EINVAL;
		goto out;
	}
	kfree_skb(reassembled_skb);
	reassembled_skb = NULL;
	kfree_skb(continuation_skb);
	continuation_skb = NULL;

	/* Session replacement clears only the retired flow's partial frames. */
	trustix_datapath_clear_inner_gso_reassembly();
	concurrent_started =
		trustix_datapath_rx_worker_inner_gso_reassembly_started;
	scoped_frame = frame;
	scoped_frame.flow_id++;
	scoped_frame.epoch++;
	ret = trustix_datapath_inner_gso_reassembly_start(
		partial_outer_skb, &outer, 0,
		sizeof(struct iphdr) + sizeof(struct tcphdr),
		partial_outer_skb->len -
			(sizeof(struct iphdr) + sizeof(struct tcphdr)),
		&frame, first_frame_sequence, false);
	if (ret)
		goto out;
	ret = trustix_datapath_inner_gso_reassembly_start(
		partial_outer_skb, &outer, 0,
		sizeof(struct iphdr) + sizeof(struct tcphdr),
		partial_outer_skb->len -
			(sizeof(struct iphdr) + sizeof(struct tcphdr)),
		&scoped_frame, first_frame_sequence, false);
	if (ret ||
	    trustix_datapath_rx_worker_inner_gso_reassembly_started !=
		    concurrent_started + 2) {
		ret = -EINVAL;
		goto out;
	}
	trustix_datapath_clear_inner_gso_reassembly_for_session(
		frame.flow_id, frame.epoch);
	scoped_active = 0;
	for (i = 0; i < TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_SLOTS; i++) {
		struct trustix_datapath_inner_gso_reassembly_slot *slot =
			&trustix_datapath_inner_gso_reassembly_slots[i];

		if (!slot->active)
			continue;
		if (slot->flow_id != scoped_frame.flow_id ||
		    slot->epoch != scoped_frame.epoch) {
			ret = -EINVAL;
			goto out;
		}
		scoped_active++;
	}
	if (scoped_active != 1 ||
	    trustix_datapath_rx_worker_inner_gso_session_clears !=
		    saved_session_clears + 1 ||
	    trustix_datapath_rx_worker_inner_gso_session_slots_cleared !=
		    saved_session_slots_cleared + 1) {
		ret = -EINVAL;
		goto out;
	}

	/* A full table rejects a new head without displacing active frames. */
	trustix_datapath_clear_inner_gso_reassembly();
	concurrent_started =
		trustix_datapath_rx_worker_inner_gso_reassembly_started;
	capacity_collisions =
		trustix_datapath_rx_worker_inner_gso_collisions;
	for (i = 0; i < TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_SLOTS; i++) {
		ret = trustix_datapath_inner_gso_reassembly_start(
			partial_outer_skb, &outer, 0,
			sizeof(struct iphdr) + sizeof(struct tcphdr),
			partial_outer_skb->len -
				(sizeof(struct iphdr) + sizeof(struct tcphdr)),
			&frame, first_frame_sequence + i * frame.wire_len,
			false);
		if (ret)
			goto out;
	}
	ret = trustix_datapath_inner_gso_reassembly_start(
		partial_outer_skb, &outer, 0,
		sizeof(struct iphdr) + sizeof(struct tcphdr),
		partial_outer_skb->len -
			(sizeof(struct iphdr) + sizeof(struct tcphdr)),
		&frame,
		first_frame_sequence +
			TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_SLOTS *
				frame.wire_len,
		false);
	if (ret != -ENOSPC ||
	    trustix_datapath_rx_worker_inner_gso_reassembly_started !=
		    concurrent_started +
			    TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_SLOTS ||
	    trustix_datapath_rx_worker_inner_gso_reassembly_high_watermark !=
		    TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_SLOTS ||
	    trustix_datapath_rx_worker_inner_gso_collisions !=
		    capacity_collisions + 1) {
		ret = -EINVAL;
		goto out;
	}
	ret = 0;
	/* Recovery must discard stale slots before the peer resumes inner-GSO. */
	spin_lock_irqsave(&trustix_datapath_inner_gso_circuit_lock,
			  circuit_flags);
	trustix_datapath_inner_gso_circuit_open = true;
	trustix_datapath_inner_gso_circuit_recovering = false;
	trustix_datapath_inner_gso_circuit_until = jiffies;
	spin_unlock_irqrestore(&trustix_datapath_inner_gso_circuit_lock,
			       circuit_flags);
	WRITE_ONCE(trustix_datapath_inner_gso_auto_recover, false);
	ret = trustix_datapath_inner_gso_reassembly_start(
		partial_outer_skb, &outer, 0,
		sizeof(struct iphdr) + sizeof(struct tcphdr),
		partial_outer_skb->len -
			(sizeof(struct iphdr) + sizeof(struct tcphdr)),
		&frame, first_frame_sequence, false);
	if (ret != -EAGAIN) {
		ret = -EINVAL;
		goto out;
	}
	if (trustix_datapath_inner_gso_runtime_ready_now() ||
	    trustix_datapath_inner_gso_circuit_recoveries !=
		    saved_circuit_recoveries) {
		ret = -EINVAL;
		goto out;
	}
	WRITE_ONCE(trustix_datapath_inner_gso_auto_recover, true);
	if (!trustix_datapath_inner_gso_runtime_ready_now() ||
	    trustix_datapath_inner_gso_circuit_recoveries !=
		    saved_circuit_recoveries + 1) {
		ret = -EINVAL;
		goto out;
	}
	for (i = 0; i < TRUSTIX_DATAPATH_INNER_GSO_REASSEMBLY_SLOTS; i++) {
		if (trustix_datapath_inner_gso_reassembly_slots[i].active) {
			ret = -EINVAL;
			goto out;
		}
	}

	/* A later frame may arrive after the current frame's final-byte range. */
	trustix_datapath_clear_inner_gso_reassembly();
	candidate = false;
	queued_frames = 0;
	ret = trustix_datapath_rx_worker_try_inner_gso(
		partial_outer_skb, &outer, sizeof(struct iphdr),
		sizeof(struct tcphdr), 0, NULL, 1, false, &candidate,
		&queued_frames);
	if (ret || !candidate || queued_frames ||
	    partial_outer_skb->len <=
		    sizeof(struct iphdr) + sizeof(struct tcphdr) ||
	    partial_outer_skb->len -
			    (sizeof(struct iphdr) + sizeof(struct tcphdr)) + 1 >=
		    frame.wire_len) {
		ret = -EINVAL;
		goto out;
	}
	first_continuation_len =
		partial_outer_skb->len -
		(sizeof(struct iphdr) + sizeof(struct tcphdr)) + 1;
	continuation_payload_len = frame.wire_len - first_continuation_len +
				   frame.wire_len;
	continuation_skb = trustix_datapath_selftest_tix_tcp_segment(
		stream_outer_skb,
		sizeof(struct iphdr) + sizeof(struct tcphdr) +
			first_continuation_len,
		continuation_payload_len, first_continuation_len);
	if (!continuation_skb) {
		ret = -ENOMEM;
		goto out;
	}
	ret = trustix_datapath_inner_gso_reassembly_append(
		continuation_skb, &outer, sizeof(struct iphdr),
		sizeof(struct tcphdr), 0, &reassembled_skb, &tail_offset,
		&tail_len, false);
	if (ret || reassembled_skb || tail_len != frame.wire_len ||
	    tail_offset != sizeof(struct iphdr) + sizeof(struct tcphdr) +
			   frame.wire_len - first_continuation_len) {
		ret = -EINVAL;
		goto out;
	}
	ret = trustix_datapath_parse_tixt_skb_header(
		continuation_skb, tail_offset, tail_len, &tail_frame);
	if (ret || tail_frame.wire_len != frame.wire_len ||
	    tail_frame.flags != frame.flags) {
		ret = ret ?: -EINVAL;
		goto out;
	}
	kfree_skb(continuation_skb);
	continuation_skb = trustix_datapath_selftest_tix_tcp_segment(
		stream_outer_skb,
		partial_outer_skb->len, 1,
		partial_outer_skb->len -
			(sizeof(struct iphdr) + sizeof(struct tcphdr)));
	if (!continuation_skb) {
		ret = -ENOMEM;
		goto out;
	}
	ret = trustix_datapath_inner_gso_reassembly_append(
		continuation_skb, &outer, sizeof(struct iphdr),
		sizeof(struct tcphdr), 0, &reassembled_skb, &tail_offset,
		&tail_len, false);
	if (ret || !reassembled_skb || tail_len ||
	    reassembled_skb->len != frame.wire_len) {
		ret = -EINVAL;
		goto out;
	}
	kfree_skb(reassembled_skb);
	reassembled_skb = NULL;
	kfree_skb(continuation_skb);
	continuation_skb = NULL;
	ret = 0;
	if (skb_copy_bits(outer_skb, inner_offset, header, sizeof(header))) {
		ret = -ENODATA;
		goto out;
	}
	view.frame = frame;
	view.inner.protocol = IPPROTO_TCP;
	view.inner_packet = header;
	view.session_flags =
		TRUSTIX_DATAPATH_SESSION_FLAG_RECEIVE_INNER_TCP_CHECKSUM_PARTIAL |
		TRUSTIX_DATAPATH_SESSION_FLAG_RECEIVE_INNER_GSO;
	ret = trustix_datapath_rx_validate_inner_tcp_checksum_partial(&view);
	if (ret)
		goto out;
	if (outer_skb->len <= split_head_len ||
	    outer_skb->len - split_head_len > PAGE_SIZE) {
		ret = -EINVAL;
		goto out;
	}
	split_outer_skb = alloc_skb(split_head_len, GFP_KERNEL);
	if (!split_outer_skb) {
		ret = -ENOMEM;
		goto out;
	}
	if (skb_copy_bits(outer_skb, 0, skb_put(split_outer_skb,
						 split_head_len),
			  split_head_len)) {
		ret = -ENODATA;
		goto out;
	}
	split_frag_len = outer_skb->len - split_head_len;
	split_page = alloc_page(GFP_KERNEL);
	if (!split_page) {
		ret = -ENOMEM;
		goto out;
	}
	page_addr = kmap_local_page(split_page);
	ret = skb_copy_bits(outer_skb, split_head_len, page_addr,
			    split_frag_len);
	kunmap_local(page_addr);
	if (ret)
		goto out;
	skb_add_rx_frag(split_outer_skb, 0, split_page, 0, split_frag_len,
			PAGE_SIZE);
	split_page = NULL;
	if (!skb_is_nonlinear(split_outer_skb) ||
	    skb_headlen(split_outer_skb) >= inner_offset) {
		ret = -EINVAL;
		goto out;
	}
	ret = trustix_datapath_rx_worker_build_inner_gso_skb(
		split_outer_skb, inner_offset, &frame, test_dev, &restored_skb);
	if (ret)
		goto out;
	if (restored_skb->len != inner_len ||
	    !skb_is_nonlinear(restored_skb) ||
	    skb_shinfo(restored_skb)->gso_size != 1000 ||
	    skb_shinfo(restored_skb)->gso_segs != 3 ||
	    skb_shinfo(restored_skb)->gso_type != SKB_GSO_TCPV4 ||
	    skb_copy_bits(restored_skb, sizeof(struct iphdr) +
					 tcp_header_len,
			  sample, sizeof(sample))) {
		ret = -EINVAL;
		goto out;
	}
	for (i = 0; i < sizeof(sample); i++) {
		if (sample[i] != (__u8)(i * 17U + 3U)) {
			ret = -EINVAL;
			goto out;
		}
	}
	view.frame.fragment_count = 2;
	if (trustix_datapath_rx_validate_inner_tcp_checksum_partial(&view) !=
	    -EBADMSG) {
		ret = -EINVAL;
		goto out;
	}
	trustix_datapath_build_tixt_header(
		wire, TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4 |
			      TRUSTIX_DATAPATH_TIXT_FLAG_INNER_GSO,
		1, 2, 3, inner_len, 1000, 3);
	if (!trustix_datapath_parse_tixt_header(
		    wire, TRUSTIX_DATAPATH_TIXT_HEADER_LEN, &frame))
		ret = -EINVAL;

out:
	trustix_datapath_clear_inner_gso_reassembly();
	trustix_datapath_clear_inner_gso_probation_matching(true, 0, 0);
	if (page)
		__free_page(page);
	if (split_page)
		__free_page(split_page);
	kfree_skb(restored_skb);
	kfree_skb(reassembled_skb);
	kfree_skb(continuation_skb);
	kfree_skb(split_outer_skb);
	kfree_skb(partial_outer_skb);
	kfree_skb(stream_outer_skb);
	kfree_skb(outer_skb);
	kfree_skb(inner_skb);
	kfree(test_dev);
	WRITE_ONCE(trustix_datapath_features, saved_features);
	trustix_datapath_rx_worker_inner_tcp_checksum_partial =
		saved_partial_frames;
	trustix_datapath_rx_worker_inner_tcp_checksum_partial_errors =
		saved_partial_errors;
	trustix_datapath_rx_worker_inner_gso_candidates =
		saved_inner_gso_candidates;
	trustix_datapath_rx_worker_inner_gso_partial_frames =
		saved_inner_gso_partial_frames;
	trustix_datapath_rx_worker_inner_gso_reassembly_started =
		saved_reassembly_started;
	trustix_datapath_rx_worker_inner_gso_continuation_matched =
		saved_continuation_matched;
	trustix_datapath_rx_worker_inner_gso_continuation_orphans =
		saved_continuation_orphans;
	trustix_datapath_rx_worker_inner_gso_continuation_drops =
		saved_continuation_drops;
	trustix_datapath_rx_worker_inner_gso_session_clears =
		saved_session_clears;
	trustix_datapath_rx_worker_inner_gso_session_slots_cleared =
		saved_session_slots_cleared;
	trustix_datapath_rx_worker_inner_gso_sequence_gaps =
		saved_sequence_gaps;
	trustix_datapath_rx_worker_inner_gso_sequence_gap_ahead =
		saved_sequence_gap_ahead;
	trustix_datapath_rx_worker_inner_gso_sequence_gap_behind =
		saved_sequence_gap_behind;
	trustix_datapath_rx_worker_inner_gso_last_sequence_gap =
		saved_last_sequence_gap;
	trustix_datapath_rx_worker_inner_gso_timeouts =
		saved_reassembly_timeouts;
	trustix_datapath_rx_worker_inner_gso_timeouts_on_start =
		saved_timeouts_on_start;
	trustix_datapath_rx_worker_inner_gso_timeouts_on_append =
		saved_timeouts_on_append;
	trustix_datapath_rx_worker_inner_gso_timeouts_on_sweep =
		saved_timeouts_on_sweep;
	trustix_datapath_rx_worker_inner_gso_timeout_missing_bytes =
		saved_timeout_missing_bytes;
	trustix_datapath_rx_worker_inner_gso_timeout_max_missing_bytes =
		saved_timeout_max_missing_bytes;
	trustix_datapath_rx_worker_inner_gso_duplicate_starts =
		saved_duplicate_starts;
	trustix_datapath_rx_worker_inner_gso_collisions = saved_collisions;
	trustix_datapath_rx_worker_inner_gso_reassembly_high_watermark =
		saved_reassembly_high_watermark;
	spin_lock_irqsave(&trustix_datapath_inner_gso_circuit_lock,
			  circuit_flags);
	trustix_datapath_inner_gso_circuit_open = saved_circuit_open;
	trustix_datapath_inner_gso_circuit_recovering =
		saved_circuit_recovering;
	trustix_datapath_inner_gso_circuit_until = saved_circuit_until;
	trustix_datapath_inner_gso_fault_window_start =
		saved_fault_window_start;
	trustix_datapath_inner_gso_timeout_window_start =
		saved_timeout_window_start;
	trustix_datapath_inner_gso_last_recovery = saved_last_recovery;
	trustix_datapath_inner_gso_fault_window_count =
		saved_fault_window_count;
	trustix_datapath_inner_gso_timeout_window_count =
		saved_timeout_window_count;
	trustix_datapath_inner_gso_timeout_success_credit =
		saved_timeout_success_credit;
	trustix_datapath_inner_gso_timeout_last_ratio_ppm =
		saved_timeout_last_ratio_ppm;
	trustix_datapath_inner_gso_backoff_level = saved_backoff_level;
	trustix_datapath_inner_gso_last_cooldown_ms =
		saved_last_cooldown_ms;
	trustix_datapath_inner_gso_runtime_faults = saved_runtime_faults;
	trustix_datapath_inner_gso_circuit_trips = saved_circuit_trips;
	trustix_datapath_inner_gso_timeout_circuit_trips =
		saved_timeout_circuit_trips;
	trustix_datapath_inner_gso_timeout_ratio_suppressions =
		saved_timeout_ratio_suppressions;
	trustix_datapath_inner_gso_no_progress_circuit_trips =
		saved_no_progress_circuit_trips;
	trustix_datapath_inner_gso_circuit_recoveries =
		saved_circuit_recoveries;
	trustix_datapath_inner_gso_probation_arms = saved_probation_arms;
	trustix_datapath_inner_gso_probation_claims = saved_probation_claims;
	trustix_datapath_inner_gso_probation_successes =
		saved_probation_successes;
	trustix_datapath_inner_gso_probation_failures =
		saved_probation_failures;
	trustix_datapath_inner_gso_probation_idle_resets =
		saved_probation_idle_resets;
	trustix_datapath_inner_gso_probation_evictions =
		saved_probation_evictions;
	trustix_datapath_inner_gso_probation_collisions =
		saved_probation_collisions;
	trustix_datapath_inner_gso_last_no_progress_ms =
		saved_last_no_progress_ms;
	WRITE_ONCE(trustix_datapath_inner_gso_auto_recover,
		   saved_auto_recover);
	spin_unlock_irqrestore(&trustix_datapath_inner_gso_circuit_lock,
			       circuit_flags);
	return ret;
}

static int trustix_datapath_selftest_secure_tix_tcp(void)
{
	if (!(READ_ONCE(trustix_datapath_enable_features) &
	      TRUSTIX_DATAPATH_FEATURE_SECURE_TIX_TCP_FULL_DATAPATH))
		return 0;
	if (!trustix_datapath_crypto_ready ||
	    !trustix_datapath_crypto_selftest ||
	    !trustix_datapath_crypto_slot_generation ||
	    !trustix_datapath_crypto_reserve_sequences ||
	    !trustix_datapath_crypto_seal_batch ||
	    !trustix_datapath_crypto_open_replay_batch ||
	    !trustix_datapath_crypto_ready())
		return -EOPNOTSUPP;
	return trustix_datapath_crypto_selftest();
}

static int
trustix_datapath_selftest_secure_inner_tcp_checksum_partial(void)
{
	__u8 packet[sizeof(struct iphdr) + sizeof(struct tcphdr) + 33]
		__aligned(4);
	__u8 wire[TRUSTIX_DATAPATH_TIXT_HEADER_LEN + sizeof(packet)];
	struct trustix_datapath_tixt_frame frame = {};
	struct trustix_datapath_tx_plan plan = {};
	struct tcphdr *tcph;
	struct iphdr *iph;
	__u64 saved_features = READ_ONCE(trustix_datapath_features);
	unsigned int i;
	int ret = 0;

	if (!(READ_ONCE(trustix_datapath_enable_features) &
	      TRUSTIX_DATAPATH_FEATURE_SECURE_INNER_TCP_CHECKSUM_PARTIAL))
		return 0;
	if (!(READ_ONCE(trustix_datapath_enable_features) &
	      TRUSTIX_DATAPATH_FEATURE_SECURE_TIX_TCP_FULL_DATAPATH))
		return -EOPNOTSUPP;

	memset(packet, 0, sizeof(packet));
	iph = (struct iphdr *)packet;
	tcph = (struct tcphdr *)(packet + sizeof(*iph));
	iph->version = 4;
	iph->ihl = sizeof(*iph) / 4;
	iph->tot_len = htons(sizeof(packet));
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->saddr = htonl(0xc0000201U);
	iph->daddr = htonl(0xc6336402U);
	tcph->source = htons(12345);
	tcph->dest = htons(443);
	tcph->seq = htonl(0x10203040U);
	tcph->doff = sizeof(*tcph) / 4;
	tcph->ack = 1;
	for (i = sizeof(*iph) + sizeof(*tcph); i < sizeof(packet); i++)
		packet[i] = (__u8)(i * 17U + 3U);

	WRITE_ONCE(trustix_datapath_features,
		   saved_features |
			   TRUSTIX_DATAPATH_FEATURE_SECURE_INNER_TCP_CHECKSUM_PARTIAL);
	plan.secure = true;
	plan.session_flags = TRUSTIX_DATAPATH_SESSION_FLAG_SEND_ENCRYPTED |
		TRUSTIX_DATAPATH_SESSION_FLAG_SEND_SECURE_INNER_TCP_CHECKSUM_PARTIAL;
	if (!trustix_datapath_tx_secure_inner_tcp_checksum_partial_enabled(
		     &plan)) {
		ret = -EINVAL;
		goto out;
	}
	plan.session_flags = TRUSTIX_DATAPATH_SESSION_FLAG_SEND_ENCRYPTED |
		TRUSTIX_DATAPATH_SESSION_FLAG_SEND_INNER_TCP_CHECKSUM_PARTIAL;
	if (trustix_datapath_tx_secure_inner_tcp_checksum_partial_enabled(
		    &plan)) {
		ret = -EINVAL;
		goto out;
	}

	if (!trustix_datapath_tx_plaintext_prepare_inner_tcp_checksum_partial(
		    packet, sizeof(packet)) ||
	    trustix_datapath_secure_validate_inner_tcp_checksum(
		    packet, sizeof(packet), true) ||
	    !trustix_datapath_secure_validate_inner_tcp_checksum(
		    packet, sizeof(packet), false)) {
		ret = -EINVAL;
		goto out;
	}
	trustix_datapath_build_tixt_header(
		wire, TRUSTIX_DATAPATH_TIXT_FLAG_ENCRYPTED |
			      TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4 |
			      TRUSTIX_DATAPATH_TIXT_FLAG_INNER_TCP_CHECKSUM_PARTIAL,
		1, 2, 3, sizeof(packet), 0, 0);
	memcpy(wire + TRUSTIX_DATAPATH_TIXT_HEADER_LEN, packet,
	       sizeof(packet));
	if (trustix_datapath_parse_tixt_header(wire, sizeof(wire), &frame) ||
	    !(frame.flags &
	      TRUSTIX_DATAPATH_TIXT_FLAG_INNER_TCP_CHECKSUM_PARTIAL)) {
		ret = -EINVAL;
		goto out;
	}
	wire[5] = TRUSTIX_DATAPATH_TIXT_FLAG_KERNEL_OPENED |
		  TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4 |
		  TRUSTIX_DATAPATH_TIXT_FLAG_INNER_TCP_CHECKSUM_PARTIAL;
	if (trustix_datapath_parse_tixt_header(wire, sizeof(wire), &frame)) {
		ret = -EINVAL;
		goto out;
	}

	tcph->check ^= htons(1);
	if (!trustix_datapath_secure_validate_inner_tcp_checksum(
		    packet, sizeof(packet), true)) {
		ret = -EINVAL;
		goto out;
	}
	tcph->check = 0;
	tcph->check = trustix_datapath_rx_worker_l4_checksum(
		iph, tcph, sizeof(packet) - sizeof(*iph), IPPROTO_TCP);
	if (trustix_datapath_secure_validate_inner_tcp_checksum(
		    packet, sizeof(packet), false) ||
	    !trustix_datapath_secure_validate_inner_tcp_checksum(
		    packet, sizeof(packet), true)) {
		ret = -EINVAL;
		goto out;
	}
	packet[sizeof(packet) - 1] ^= 1;
	if (!trustix_datapath_secure_validate_inner_tcp_checksum(
		    packet, sizeof(packet), false)) {
		ret = -EINVAL;
		goto out;
	}
	packet[sizeof(packet) - 1] ^= 1;

	iph->protocol = IPPROTO_UDP;
	if (trustix_datapath_secure_validate_inner_tcp_checksum(
		    packet, sizeof(packet), false) ||
	    !trustix_datapath_secure_validate_inner_tcp_checksum(
		    packet, sizeof(packet), true)) {
		ret = -EINVAL;
		goto out;
	}
	iph->tot_len = htons(sizeof(packet) - 1);
	if (!trustix_datapath_secure_validate_inner_tcp_checksum(
		    packet, sizeof(packet), false))
		ret = -EINVAL;

out:
	WRITE_ONCE(trustix_datapath_features, saved_features);
	return ret;
}

static void trustix_datapath_run_selftests(__u64 requested, __u64 *passed,
					   __u64 *failed)
{
	__u64 pass = 0;
	__u64 fail = 0;

	if (!requested)
		requested = TRUSTIX_DATAPATH_SELFTEST_ALL;
	if (requested & ~TRUSTIX_DATAPATH_SELFTEST_ALL)
		fail |= requested & ~TRUSTIX_DATAPATH_SELFTEST_ALL;
	if (requested & TRUSTIX_DATAPATH_SELFTEST_TIXT_FRAME) {
		if (trustix_datapath_selftest_tixt_frame())
			fail |= TRUSTIX_DATAPATH_SELFTEST_TIXT_FRAME;
		else
			pass |= TRUSTIX_DATAPATH_SELFTEST_TIXT_FRAME;
	}
	if (requested & TRUSTIX_DATAPATH_SELFTEST_TIXT_STREAM) {
		if (trustix_datapath_selftest_tixt_stream())
			fail |= TRUSTIX_DATAPATH_SELFTEST_TIXT_STREAM;
		else
			pass |= TRUSTIX_DATAPATH_SELFTEST_TIXT_STREAM;
	}
	if (requested & TRUSTIX_DATAPATH_SELFTEST_STATE_TABLE) {
		if (trustix_datapath_selftest_state_table() ||
		    trustix_datapath_selftest_rx_worker_mac_cache() ||
		    trustix_datapath_selftest_tx_plaintext_mac_cache() ||
		    trustix_datapath_selftest_tx_plaintext_hash_tx_queue())
			fail |= TRUSTIX_DATAPATH_SELFTEST_STATE_TABLE;
		else
			pass |= TRUSTIX_DATAPATH_SELFTEST_STATE_TABLE;
	}
	if (requested & TRUSTIX_DATAPATH_SELFTEST_CLASSIFY) {
		if (trustix_datapath_selftest_classify())
			fail |= TRUSTIX_DATAPATH_SELFTEST_CLASSIFY;
		else
			pass |= TRUSTIX_DATAPATH_SELFTEST_CLASSIFY;
	}
	if (requested & TRUSTIX_DATAPATH_SELFTEST_PACKET_CLASSIFY) {
		if (trustix_datapath_selftest_packet_classify())
			fail |= TRUSTIX_DATAPATH_SELFTEST_PACKET_CLASSIFY;
		else
			pass |= TRUSTIX_DATAPATH_SELFTEST_PACKET_CLASSIFY;
	}
	if (requested & TRUSTIX_DATAPATH_SELFTEST_TIXT_ENCAP) {
		if (trustix_datapath_selftest_tixt_encap())
			fail |= TRUSTIX_DATAPATH_SELFTEST_TIXT_ENCAP;
		else
			pass |= TRUSTIX_DATAPATH_SELFTEST_TIXT_ENCAP;
	}
	if (requested & TRUSTIX_DATAPATH_SELFTEST_TIXT_DECAP) {
		if (trustix_datapath_selftest_tixt_decap())
			fail |= TRUSTIX_DATAPATH_SELFTEST_TIXT_DECAP;
		else
			pass |= TRUSTIX_DATAPATH_SELFTEST_TIXT_DECAP;
	}
	if (requested & TRUSTIX_DATAPATH_SELFTEST_SESSION_WIRE) {
		if (trustix_datapath_selftest_session_wire())
			fail |= TRUSTIX_DATAPATH_SELFTEST_SESSION_WIRE;
		else
			pass |= TRUSTIX_DATAPATH_SELFTEST_SESSION_WIRE;
	}
	if (requested & TRUSTIX_DATAPATH_SELFTEST_OUTER_BUILD) {
		if (trustix_datapath_selftest_outer_build() ||
		    trustix_datapath_selftest_tx_plaintext_payload_copy_csum())
			fail |= TRUSTIX_DATAPATH_SELFTEST_OUTER_BUILD;
		else
			pass |= TRUSTIX_DATAPATH_SELFTEST_OUTER_BUILD;
	}
	if (requested & TRUSTIX_DATAPATH_SELFTEST_OUTER_PARSE) {
		if (trustix_datapath_selftest_outer_parse())
			fail |= TRUSTIX_DATAPATH_SELFTEST_OUTER_PARSE;
		else
			pass |= TRUSTIX_DATAPATH_SELFTEST_OUTER_PARSE;
	}
	if (requested &
	    TRUSTIX_DATAPATH_SELFTEST_INNER_TCP_CHECKSUM_PARTIAL) {
		if (trustix_datapath_selftest_inner_tcp_checksum_partial())
			fail |=
				TRUSTIX_DATAPATH_SELFTEST_INNER_TCP_CHECKSUM_PARTIAL;
		else
			pass |=
				TRUSTIX_DATAPATH_SELFTEST_INNER_TCP_CHECKSUM_PARTIAL;
	}
	if (requested & TRUSTIX_DATAPATH_SELFTEST_INNER_GSO) {
		if (trustix_datapath_selftest_inner_gso())
			fail |= TRUSTIX_DATAPATH_SELFTEST_INNER_GSO;
		else
			pass |= TRUSTIX_DATAPATH_SELFTEST_INNER_GSO;
	}
	if (requested & TRUSTIX_DATAPATH_SELFTEST_SECURE_TIX_TCP) {
		if (trustix_datapath_selftest_secure_tix_tcp())
			fail |= TRUSTIX_DATAPATH_SELFTEST_SECURE_TIX_TCP;
		else
			pass |= TRUSTIX_DATAPATH_SELFTEST_SECURE_TIX_TCP;
	}
	if (requested &
	    TRUSTIX_DATAPATH_SELFTEST_SECURE_INNER_TCP_CHECKSUM_PARTIAL) {
		if (trustix_datapath_selftest_secure_inner_tcp_checksum_partial())
			fail |=
				TRUSTIX_DATAPATH_SELFTEST_SECURE_INNER_TCP_CHECKSUM_PARTIAL;
		else
			pass |=
				TRUSTIX_DATAPATH_SELFTEST_SECURE_INNER_TCP_CHECKSUM_PARTIAL;
	}

	if (passed)
		*passed = pass;
	if (failed)
		*failed = fail;
}

static void
trustix_datapath_update_features_from_selftests(__u64 passed, __u64 failed)
{
	__u64 requested_features;
	__u64 active_features = 0;
	__u32 flags = 0;

	if ((passed & (TRUSTIX_DATAPATH_SELFTEST_TIXT_FRAME |
		       TRUSTIX_DATAPATH_SELFTEST_TIXT_STREAM)) ==
		    (TRUSTIX_DATAPATH_SELFTEST_TIXT_FRAME |
		     TRUSTIX_DATAPATH_SELFTEST_TIXT_STREAM) &&
	    !(failed & (TRUSTIX_DATAPATH_SELFTEST_TIXT_FRAME |
			TRUSTIX_DATAPATH_SELFTEST_TIXT_STREAM))) {
		flags |= TRUSTIX_DATAPATH_FLAG_TIXT_SELFTEST_OK;
	}

	requested_features = READ_ONCE(trustix_datapath_enable_features) &
			     TRUSTIX_DATAPATH_KNOWN_FEATURES;
	if ((requested_features & TRUSTIX_DATAPATH_FEATURE_FULL_DATAPATH) &&
	    (passed & TRUSTIX_DATAPATH_SELFTEST_FULL_DATAPATH) ==
		    TRUSTIX_DATAPATH_SELFTEST_FULL_DATAPATH &&
	    !(failed & TRUSTIX_DATAPATH_SELFTEST_FULL_DATAPATH) &&
	    READ_ONCE(trustix_datapath_rx_worker_inject) &&
	    READ_ONCE(trustix_datapath_rx_worker_ring) &&
	    READ_ONCE(trustix_datapath_rx_worker_capacity) &&
	    READ_ONCE(trustix_datapath_rx_worker_wq) &&
	    READ_ONCE(trustix_datapath_tx_plaintext)) {
		active_features |= TRUSTIX_DATAPATH_FEATURE_FULL_DATAPATH;
	}
	if ((requested_features &
	     TRUSTIX_DATAPATH_FEATURE_INNER_TCP_CHECKSUM_PARTIAL) &&
	    (active_features & TRUSTIX_DATAPATH_FEATURE_FULL_DATAPATH) &&
	    (passed & TRUSTIX_DATAPATH_SELFTEST_INNER_TCP_CHECKSUM_PARTIAL) &&
	    !(failed &
	      TRUSTIX_DATAPATH_SELFTEST_INNER_TCP_CHECKSUM_PARTIAL))
		active_features |=
			TRUSTIX_DATAPATH_FEATURE_INNER_TCP_CHECKSUM_PARTIAL;
	if ((requested_features & TRUSTIX_DATAPATH_FEATURE_INNER_GSO) &&
	    (active_features &
	     (TRUSTIX_DATAPATH_FEATURE_FULL_DATAPATH |
	      TRUSTIX_DATAPATH_FEATURE_INNER_TCP_CHECKSUM_PARTIAL)) ==
		    (TRUSTIX_DATAPATH_FEATURE_FULL_DATAPATH |
		     TRUSTIX_DATAPATH_FEATURE_INNER_TCP_CHECKSUM_PARTIAL) &&
	    (passed & TRUSTIX_DATAPATH_SELFTEST_INNER_GSO) &&
	    !(failed & TRUSTIX_DATAPATH_SELFTEST_INNER_GSO))
		active_features |= TRUSTIX_DATAPATH_FEATURE_INNER_GSO;
	if ((requested_features &
	     TRUSTIX_DATAPATH_FEATURE_TIX_TCP_PORT_SHARDING) &&
	    (active_features & TRUSTIX_DATAPATH_FEATURE_FULL_DATAPATH) &&
	    (passed & (TRUSTIX_DATAPATH_SELFTEST_SESSION_WIRE |
		       TRUSTIX_DATAPATH_SELFTEST_OUTER_BUILD |
		       TRUSTIX_DATAPATH_SELFTEST_OUTER_PARSE)) ==
		    (TRUSTIX_DATAPATH_SELFTEST_SESSION_WIRE |
		     TRUSTIX_DATAPATH_SELFTEST_OUTER_BUILD |
		     TRUSTIX_DATAPATH_SELFTEST_OUTER_PARSE) &&
	    !(failed & (TRUSTIX_DATAPATH_SELFTEST_SESSION_WIRE |
			TRUSTIX_DATAPATH_SELFTEST_OUTER_BUILD |
			TRUSTIX_DATAPATH_SELFTEST_OUTER_PARSE)) &&
	    READ_ONCE(trustix_datapath_outer_tcp_shard_sequences) &&
	    READ_ONCE(trustix_datapath_outer_tcp_sequence_flow_slots))
		active_features |=
			TRUSTIX_DATAPATH_FEATURE_TIX_TCP_PORT_SHARDING;
	if ((requested_features &
	     TRUSTIX_DATAPATH_FEATURE_SECURE_TIX_TCP_FULL_DATAPATH) &&
	    (active_features & TRUSTIX_DATAPATH_FEATURE_FULL_DATAPATH) &&
	    (passed & TRUSTIX_DATAPATH_SELFTEST_SECURE_TIX_TCP) &&
	    !(failed & TRUSTIX_DATAPATH_SELFTEST_SECURE_TIX_TCP) &&
	    trustix_datapath_crypto_ready &&
	    trustix_datapath_crypto_ready())
		active_features |=
			TRUSTIX_DATAPATH_FEATURE_SECURE_TIX_TCP_FULL_DATAPATH;
	if ((requested_features &
	     TRUSTIX_DATAPATH_FEATURE_SECURE_INNER_TCP_CHECKSUM_PARTIAL) &&
	    (active_features &
	     TRUSTIX_DATAPATH_FEATURE_SECURE_TIX_TCP_FULL_DATAPATH) &&
	    (passed &
	     TRUSTIX_DATAPATH_SELFTEST_SECURE_INNER_TCP_CHECKSUM_PARTIAL) &&
	    !(failed &
	      TRUSTIX_DATAPATH_SELFTEST_SECURE_INNER_TCP_CHECKSUM_PARTIAL))
		active_features |=
			TRUSTIX_DATAPATH_FEATURE_SECURE_INNER_TCP_CHECKSUM_PARTIAL;
	if (active_features)
		flags |= TRUSTIX_DATAPATH_FLAG_FEATURES_ACTIVE;
	WRITE_ONCE(trustix_datapath_selftests, passed);
	WRITE_ONCE(trustix_datapath_selftest_failures, failed);
	WRITE_ONCE(trustix_datapath_features, active_features);
	WRITE_ONCE(trustix_datapath_safe_features, active_features);
	WRITE_ONCE(trustix_datapath_unsafe_features,
		   requested_features & ~active_features);
	WRITE_ONCE(trustix_datapath_flags, flags);
}

static void trustix_datapath_refresh_features(void)
{
	__u64 passed = READ_ONCE(trustix_datapath_selftests);
	__u64 failed = READ_ONCE(trustix_datapath_selftest_failures);

	trustix_datapath_update_features_from_selftests(passed, failed);
}

static int trustix_datapath_open(struct inode *inode, struct file *file)
{
	return 0;
}

static long trustix_datapath_ioctl(struct file *file, unsigned int cmd,
				   unsigned long arg)
{
	struct trustix_datapath_ioc_query query;
	struct trustix_datapath_ioc_selftest selftest;
	struct trustix_datapath_ioc_state state;
	struct trustix_datapath_ioc_state_stats stats;
	struct trustix_datapath_ioc_state_batch batch;
	struct trustix_datapath_ioc_classify classify;
	struct trustix_datapath_ioc_packet_classify packet_classify;
	struct trustix_datapath_ioc_packet_stats packet_stats;
	struct trustix_datapath_packet_hot_counters packet_hot;
	struct trustix_datapath_ioc_hook hook;
	struct trustix_datapath_ioc_tixt_encap encap;
	struct trustix_datapath_ioc_tixt_decap decap;
	struct trustix_datapath_ioc_outer_build outer_build;
	struct trustix_datapath_ioc_outer_parse outer_parse;
	struct trustix_datapath_ioc_rx_stage rx_stage;
	struct trustix_datapath_ioc_state __user *user_records;
	struct trustix_datapath_ioc_state *records;
	__u8 *packet_buf;
	__u8 *encap_inner;
	__u8 *encap_out;
	__u8 *decap_wire;
	__u8 *decap_out;
	__u8 *outer_inner;
	__u8 *outer_out;
	__u8 *outer_wire;
	__u8 *outer_parse_out;
	__u8 *rx_stage_out;
	__u64 requested;
	__u64 passed;
	__u64 failed;
	size_t records_size;
	__u32 i;
	bool rebuild_lookup_caches;
	int ret;

	switch (cmd) {
	case TRUSTIX_DATAPATH_IOC_QUERY:
		if (copy_from_user(&query, (void __user *)arg, sizeof(query)))
			return -EFAULT;
		if (query.version != TRUSTIX_DATAPATH_IOC_VERSION)
			return -EINVAL;
		trustix_datapath_refresh_features();
		memset(&query, 0, sizeof(query));
		query.version = TRUSTIX_DATAPATH_IOC_VERSION;
		query.module_abi_version = TRUSTIX_DATAPATH_ABI_VERSION;
		query.datapath_abi_version = TRUSTIX_DATAPATH_IOC_VERSION;
		query.features = READ_ONCE(trustix_datapath_features);
		query.safe_features = READ_ONCE(trustix_datapath_safe_features);
		query.unsafe_features = READ_ONCE(trustix_datapath_unsafe_features);
		query.flags = READ_ONCE(trustix_datapath_flags);
		query.reserved0 = READ_ONCE(trustix_datapath_selftests);
		query.reserved1 = READ_ONCE(trustix_datapath_selftest_failures);
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
		passed = 0;
		failed = 0;
		ret = 0;
		mutex_lock(&trustix_datapath_selftest_mutex);
		read_lock_bh(&trustix_datapath_state_lock);
		if (trustix_datapath_hooks_registered_locked())
			ret = -EBUSY;
		read_unlock_bh(&trustix_datapath_state_lock);
		if (!ret) {
			trustix_datapath_run_selftests(requested, &passed,
						       &failed);
			if (requested == TRUSTIX_DATAPATH_SELFTEST_ALL)
				trustix_datapath_update_features_from_selftests(
					passed, failed);
			else
				trustix_datapath_refresh_features();
		}
		mutex_unlock(&trustix_datapath_selftest_mutex);
		memset(&selftest, 0, sizeof(selftest));
		selftest.version = TRUSTIX_DATAPATH_IOC_VERSION;
		selftest.result = ret ? ret : (failed ? -EINVAL : 0);
		selftest.requested = requested;
		selftest.passed = passed;
		selftest.failed = failed;
		selftest.features = READ_ONCE(trustix_datapath_features);
		selftest.flags = READ_ONCE(trustix_datapath_flags);
		if (copy_to_user((void __user *)arg, &selftest,
				 sizeof(selftest)))
			return -EFAULT;
		return 0;
	case TRUSTIX_DATAPATH_IOC_STATE:
		if (copy_from_user(&state, (void __user *)arg, sizeof(state)))
			return -EFAULT;
		if (state.version != TRUSTIX_DATAPATH_IOC_VERSION)
			return -EINVAL;
		mutex_lock(&trustix_datapath_selftest_mutex);
		write_lock_bh(&trustix_datapath_state_lock);
		ret = trustix_datapath_state_apply_locked(&state);
		write_unlock_bh(&trustix_datapath_state_lock);
		mutex_unlock(&trustix_datapath_selftest_mutex);
		state.result = ret;
		if (copy_to_user((void __user *)arg, &state, sizeof(state)))
			return -EFAULT;
		return 0;
	case TRUSTIX_DATAPATH_IOC_STATE_STATS:
		if (copy_from_user(&stats, (void __user *)arg, sizeof(stats)))
			return -EFAULT;
		if (stats.version != TRUSTIX_DATAPATH_IOC_VERSION)
			return -EINVAL;
		mutex_lock(&trustix_datapath_selftest_mutex);
		read_lock_bh(&trustix_datapath_state_lock);
		memset(&stats, 0, sizeof(stats));
		stats.version = TRUSTIX_DATAPATH_IOC_VERSION;
		stats.max_routes = trustix_datapath_routes.capacity;
		stats.routes = trustix_datapath_routes.count;
		stats.max_sessions = trustix_datapath_sessions.capacity;
		stats.sessions = trustix_datapath_sessions.count;
		stats.max_flows = trustix_datapath_flows.capacity;
		stats.flows = trustix_datapath_flows.count;
		stats.max_session_wires = trustix_datapath_session_wires.capacity;
		stats.session_wires = trustix_datapath_session_wires.count;
		stats.upserts = trustix_datapath_state_upserts;
		stats.deletes = trustix_datapath_state_deletes;
		stats.clears = trustix_datapath_state_clears;
		stats.get_hits = trustix_datapath_state_get_hits;
		stats.get_misses = trustix_datapath_state_get_misses;
		stats.table_full = trustix_datapath_state_table_full;
		read_unlock_bh(&trustix_datapath_state_lock);
		mutex_unlock(&trustix_datapath_selftest_mutex);
		if (copy_to_user((void __user *)arg, &stats, sizeof(stats)))
			return -EFAULT;
		return 0;
	case TRUSTIX_DATAPATH_IOC_STATE_BATCH:
		if (copy_from_user(&batch, (void __user *)arg, sizeof(batch)))
			return -EFAULT;
		if (batch.version != TRUSTIX_DATAPATH_IOC_VERSION)
			return -EINVAL;
		if (!batch.records_ptr && batch.count)
			return -EINVAL;
		if (batch.count > TRUSTIX_DATAPATH_STATE_BATCH_MAX)
			return -E2BIG;
		user_records = (struct trustix_datapath_ioc_state __user *)
				       (unsigned long)batch.records_ptr;
		records = NULL;
		records_size = array_size(batch.count, sizeof(*records));
		if (batch.count && records_size == SIZE_MAX)
			return -EOVERFLOW;
		if (batch.count) {
			records = vzalloc(records_size);
			if (!records)
				return -ENOMEM;
			if (copy_from_user(records, user_records, records_size)) {
				vfree(records);
				return -EFAULT;
			}
		}
		ret = 0;
		batch.applied = 0;
		rebuild_lookup_caches = false;
		mutex_lock(&trustix_datapath_selftest_mutex);
		write_lock_bh(&trustix_datapath_state_lock);
		for (i = 0; i < batch.count; i++) {
			state = records[i];
			if (state.version != TRUSTIX_DATAPATH_IOC_VERSION) {
				ret = -EINVAL;
				state.result = ret;
				records[i] = state;
				break;
			}
			ret = trustix_datapath_state_apply_locked_maybe_rebuild(
				&state, false);
			state.result = ret;
			records[i] = state;
			if (ret)
				break;
			if (state.op != TRUSTIX_DATAPATH_STATE_OP_GET &&
			    trustix_datapath_state_kind_affects_lookup_caches(
				    state.kind))
				rebuild_lookup_caches = true;
			batch.applied++;
		}
		if (rebuild_lookup_caches)
			trustix_datapath_rebuild_lookup_caches_locked();
		write_unlock_bh(&trustix_datapath_state_lock);
		mutex_unlock(&trustix_datapath_selftest_mutex);
		if (records &&
		    copy_to_user(user_records, records, records_size)) {
			vfree(records);
			return -EFAULT;
		}
		vfree(records);
		batch.result = ret;
		if (copy_to_user((void __user *)arg, &batch, sizeof(batch)))
			return -EFAULT;
		return 0;
	case TRUSTIX_DATAPATH_IOC_CLASSIFY:
		if (copy_from_user(&classify, (void __user *)arg,
				   sizeof(classify)))
			return -EFAULT;
		if (classify.version != TRUSTIX_DATAPATH_IOC_VERSION)
			return -EINVAL;
		mutex_lock(&trustix_datapath_selftest_mutex);
		read_lock_bh(&trustix_datapath_state_lock);
		ret = trustix_datapath_classify_locked(&classify);
		read_unlock_bh(&trustix_datapath_state_lock);
		mutex_unlock(&trustix_datapath_selftest_mutex);
		classify.result = ret;
		if (copy_to_user((void __user *)arg, &classify,
				 sizeof(classify)))
			return -EFAULT;
		return 0;
	case TRUSTIX_DATAPATH_IOC_PACKET_CLASSIFY:
		if (copy_from_user(&packet_classify, (void __user *)arg,
				   sizeof(packet_classify)))
			return -EFAULT;
		if (packet_classify.version != TRUSTIX_DATAPATH_IOC_VERSION)
			return -EINVAL;
		if (!packet_classify.packet_ptr || !packet_classify.packet_len)
			return -EINVAL;
		if (packet_classify.packet_len > TRUSTIX_DATAPATH_PACKET_MAX_LEN)
			return -EMSGSIZE;
		packet_buf = memdup_user((void __user *)(unsigned long)
						 packet_classify.packet_ptr,
					 packet_classify.packet_len);
		if (IS_ERR(packet_buf))
			return PTR_ERR(packet_buf);
		mutex_lock(&trustix_datapath_selftest_mutex);
		write_lock_bh(&trustix_datapath_state_lock);
		ret = trustix_datapath_packet_classify_locked(&packet_classify,
							      packet_buf);
		write_unlock_bh(&trustix_datapath_state_lock);
		mutex_unlock(&trustix_datapath_selftest_mutex);
		kfree(packet_buf);
		packet_classify.result = ret;
		if (copy_to_user((void __user *)arg, &packet_classify,
				 sizeof(packet_classify)))
			return -EFAULT;
		return 0;
	case TRUSTIX_DATAPATH_IOC_PACKET_STATS:
		if (copy_from_user(&packet_stats, (void __user *)arg,
				   sizeof(packet_stats)))
			return -EFAULT;
		if (packet_stats.version != TRUSTIX_DATAPATH_IOC_VERSION)
			return -EINVAL;
		mutex_lock(&trustix_datapath_selftest_mutex);
		read_lock_bh(&trustix_datapath_state_lock);
		memset(&packet_stats, 0, sizeof(packet_stats));
		packet_stats.version = TRUSTIX_DATAPATH_IOC_VERSION;
		trustix_datapath_read_packet_hot_counters(&packet_hot);
		packet_stats.packets =
			trustix_datapath_packets_seen + packet_hot.packets;
		packet_stats.bytes =
			trustix_datapath_bytes_seen + packet_hot.bytes;
		packet_stats.parse_errors =
			trustix_datapath_packet_parse_errors +
			packet_hot.parse_errors;
		packet_stats.route_misses =
			trustix_datapath_packet_route_misses +
			packet_hot.route_misses;
		packet_stats.session_misses =
			trustix_datapath_packet_session_misses +
			packet_hot.session_misses;
		packet_stats.unicast_routes =
			trustix_datapath_packet_unicast_routes +
			packet_hot.unicast_routes;
		packet_stats.local_routes =
			trustix_datapath_packet_local_routes +
			packet_hot.local_routes;
		packet_stats.blackhole_routes =
			trustix_datapath_packet_blackhole_routes +
			packet_hot.blackhole_routes;
		packet_stats.reject_routes =
			trustix_datapath_packet_reject_routes +
			packet_hot.reject_routes;
		read_unlock_bh(&trustix_datapath_state_lock);
		mutex_unlock(&trustix_datapath_selftest_mutex);
		if (copy_to_user((void __user *)arg, &packet_stats,
				 sizeof(packet_stats)))
			return -EFAULT;
		return 0;
	case TRUSTIX_DATAPATH_IOC_HOOK:
		if (copy_from_user(&hook, (void __user *)arg, sizeof(hook)))
			return -EFAULT;
		if (hook.version != TRUSTIX_DATAPATH_IOC_VERSION)
			return -EINVAL;
		ret = trustix_datapath_hook_apply(&hook);
		hook.result = ret;
		if (copy_to_user((void __user *)arg, &hook, sizeof(hook)))
			return -EFAULT;
		return 0;
	case TRUSTIX_DATAPATH_IOC_TIXT_ENCAP:
		if (copy_from_user(&encap, (void __user *)arg, sizeof(encap)))
			return -EFAULT;
		if (encap.version != TRUSTIX_DATAPATH_IOC_VERSION)
			return -EINVAL;
		if (!encap.inner_ptr || !encap.out_ptr || !encap.inner_len ||
		    !encap.out_len)
			return -EINVAL;
		if (encap.inner_len > TRUSTIX_DATAPATH_TIXT_MAX_PAYLOAD ||
		    encap.out_len > TRUSTIX_DATAPATH_TIXT_HEADER_LEN +
					    TRUSTIX_DATAPATH_TIXT_MAX_PAYLOAD)
			return -EMSGSIZE;
		encap_inner = memdup_user((void __user *)(unsigned long)
						  encap.inner_ptr,
					  encap.inner_len);
		if (IS_ERR(encap_inner))
			return PTR_ERR(encap_inner);
		encap_out = kzalloc(encap.out_len, GFP_KERNEL);
		if (!encap_out) {
			kfree(encap_inner);
			return -ENOMEM;
		}
		mutex_lock(&trustix_datapath_selftest_mutex);
		write_lock_bh(&trustix_datapath_state_lock);
		ret = trustix_datapath_tixt_encap_locked(&encap, encap_inner,
							 encap_out);
		write_unlock_bh(&trustix_datapath_state_lock);
		mutex_unlock(&trustix_datapath_selftest_mutex);
		encap.result = ret;
		if (!ret &&
		    copy_to_user((void __user *)(unsigned long)encap.out_ptr,
				 encap_out, encap.written_len)) {
			kfree(encap_out);
			kfree(encap_inner);
			return -EFAULT;
		}
		kfree(encap_out);
		kfree(encap_inner);
		if (copy_to_user((void __user *)arg, &encap, sizeof(encap)))
			return -EFAULT;
		return 0;
	case TRUSTIX_DATAPATH_IOC_TIXT_DECAP:
		if (copy_from_user(&decap, (void __user *)arg, sizeof(decap)))
			return -EFAULT;
		if (decap.version != TRUSTIX_DATAPATH_IOC_VERSION)
			return -EINVAL;
		if (!decap.wire_ptr || !decap.out_ptr || !decap.wire_len ||
		    !decap.out_len)
			return -EINVAL;
		if (decap.wire_len > TRUSTIX_DATAPATH_TIXT_HEADER_LEN +
					    TRUSTIX_DATAPATH_TIXT_MAX_PAYLOAD ||
		    decap.out_len > TRUSTIX_DATAPATH_TIXT_MAX_PAYLOAD)
			return -EMSGSIZE;
		decap_wire = memdup_user((void __user *)(unsigned long)
						 decap.wire_ptr,
					 decap.wire_len);
		if (IS_ERR(decap_wire))
			return PTR_ERR(decap_wire);
		decap_out = kzalloc(decap.out_len, GFP_KERNEL);
		if (!decap_out) {
			kfree(decap_wire);
			return -ENOMEM;
		}
		mutex_lock(&trustix_datapath_selftest_mutex);
		write_lock_bh(&trustix_datapath_state_lock);
		ret = trustix_datapath_tixt_decap_locked(&decap, decap_wire,
							 decap_out);
		write_unlock_bh(&trustix_datapath_state_lock);
		mutex_unlock(&trustix_datapath_selftest_mutex);
		decap.result = ret;
		if (!ret &&
		    copy_to_user((void __user *)(unsigned long)decap.out_ptr,
				 decap_out, decap.written_len)) {
			kfree(decap_out);
			kfree(decap_wire);
			return -EFAULT;
		}
		kfree(decap_out);
		kfree(decap_wire);
		if (copy_to_user((void __user *)arg, &decap, sizeof(decap)))
			return -EFAULT;
		return 0;
	case TRUSTIX_DATAPATH_IOC_OUTER_BUILD:
		if (copy_from_user(&outer_build, (void __user *)arg,
				   sizeof(outer_build)))
			return -EFAULT;
		if (outer_build.version != TRUSTIX_DATAPATH_IOC_VERSION)
			return -EINVAL;
		if (!outer_build.inner_ptr || !outer_build.out_ptr ||
		    !outer_build.inner_len || !outer_build.out_len)
			return -EINVAL;
		if (outer_build.inner_len > TRUSTIX_DATAPATH_TIXT_MAX_PAYLOAD ||
		    outer_build.out_len > 20 + 20 +
					    TRUSTIX_DATAPATH_TIXT_HEADER_LEN +
					    TRUSTIX_DATAPATH_TIXT_MAX_PAYLOAD)
			return -EMSGSIZE;
		outer_inner = memdup_user((void __user *)(unsigned long)
						  outer_build.inner_ptr,
					  outer_build.inner_len);
		if (IS_ERR(outer_inner))
			return PTR_ERR(outer_inner);
		outer_out = kzalloc(outer_build.out_len, GFP_KERNEL);
		if (!outer_out) {
			kfree(outer_inner);
			return -ENOMEM;
		}
		mutex_lock(&trustix_datapath_selftest_mutex);
		write_lock_bh(&trustix_datapath_state_lock);
		ret = trustix_datapath_outer_build_locked(&outer_build,
							  outer_inner,
							  outer_out);
		write_unlock_bh(&trustix_datapath_state_lock);
		mutex_unlock(&trustix_datapath_selftest_mutex);
		outer_build.result = ret;
		if (!ret &&
		    copy_to_user((void __user *)(unsigned long)
					 outer_build.out_ptr,
				 outer_out, outer_build.written_len)) {
			kfree(outer_out);
			kfree(outer_inner);
			return -EFAULT;
		}
		kfree(outer_out);
		kfree(outer_inner);
		if (copy_to_user((void __user *)arg, &outer_build,
				 sizeof(outer_build)))
			return -EFAULT;
		return 0;
	case TRUSTIX_DATAPATH_IOC_OUTER_PARSE:
		if (copy_from_user(&outer_parse, (void __user *)arg,
				   sizeof(outer_parse)))
			return -EFAULT;
		if (outer_parse.version != TRUSTIX_DATAPATH_IOC_VERSION)
			return -EINVAL;
		if (!outer_parse.outer_ptr || !outer_parse.out_ptr ||
		    !outer_parse.outer_len || !outer_parse.out_len)
			return -EINVAL;
		if (outer_parse.outer_len > TRUSTIX_DATAPATH_PACKET_MAX_LEN ||
		    outer_parse.out_len > TRUSTIX_DATAPATH_TIXT_MAX_PAYLOAD)
			return -EMSGSIZE;
		outer_wire = memdup_user((void __user *)(unsigned long)
						 outer_parse.outer_ptr,
					 outer_parse.outer_len);
		if (IS_ERR(outer_wire))
			return PTR_ERR(outer_wire);
		outer_parse_out = kzalloc(outer_parse.out_len, GFP_KERNEL);
		if (!outer_parse_out) {
			kfree(outer_wire);
			return -ENOMEM;
		}
		mutex_lock(&trustix_datapath_selftest_mutex);
		write_lock_bh(&trustix_datapath_state_lock);
		ret = trustix_datapath_outer_parse_locked(&outer_parse,
							  outer_wire,
							  outer_parse_out);
		write_unlock_bh(&trustix_datapath_state_lock);
		mutex_unlock(&trustix_datapath_selftest_mutex);
		outer_parse.result = ret;
		if (!ret &&
		    copy_to_user((void __user *)(unsigned long)
					 outer_parse.out_ptr,
				 outer_parse_out, outer_parse.written_len)) {
			kfree(outer_parse_out);
			kfree(outer_wire);
			return -EFAULT;
		}
		kfree(outer_parse_out);
		kfree(outer_wire);
		if (copy_to_user((void __user *)arg, &outer_parse,
				 sizeof(outer_parse)))
			return -EFAULT;
		return 0;
	case TRUSTIX_DATAPATH_IOC_RX_STAGE:
		if (copy_from_user(&rx_stage, (void __user *)arg,
				   sizeof(rx_stage)))
			return -EFAULT;
		if (rx_stage.version != TRUSTIX_DATAPATH_IOC_VERSION)
			return -EINVAL;
		rx_stage_out = NULL;
		if (rx_stage.op == TRUSTIX_DATAPATH_RX_STAGE_OP_PEEK ||
		    rx_stage.op == TRUSTIX_DATAPATH_RX_STAGE_OP_POP) {
			if (rx_stage.out_len > TRUSTIX_DATAPATH_PACKET_MAX_LEN)
				return -EMSGSIZE;
			if (rx_stage.out_len && !rx_stage.out_ptr)
				return -EINVAL;
			if (rx_stage.out_len) {
				rx_stage_out = kzalloc(rx_stage.out_len,
						       GFP_KERNEL);
				if (!rx_stage_out)
					return -ENOMEM;
			}
		}
		ret = trustix_datapath_rx_stage_apply(&rx_stage,
						      rx_stage_out);
		rx_stage.result = ret;
		if (!ret && rx_stage.written_len && rx_stage_out &&
		    copy_to_user((void __user *)(unsigned long)
					 rx_stage.out_ptr,
				 rx_stage_out, rx_stage.written_len)) {
			kfree(rx_stage_out);
			return -EFAULT;
		}
		kfree(rx_stage_out);
		if (copy_to_user((void __user *)arg, &rx_stage,
				 sizeof(rx_stage)))
			return -EFAULT;
		return 0;
	default:
		return -ENOTTY;
	}
}

static const struct file_operations trustix_datapath_fops = {
	.owner = THIS_MODULE,
	.open = trustix_datapath_open,
	.unlocked_ioctl = trustix_datapath_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = trustix_datapath_ioctl,
#endif
};

static struct miscdevice trustix_datapath_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "trustix_datapath",
	.fops = &trustix_datapath_fops,
	.mode = 0600,
};

static int __init trustix_datapath_init(void)
{
	__u64 passed = 0;
	__u64 failed = 0;
	unsigned int i;
	int ret;

	for (i = 0; i < TRUSTIX_DATAPATH_OUTER_TCP_ORDER_LOCKS; i++)
		spin_lock_init(&trustix_datapath_outer_tcp_order_locks[i]);
	ret = trustix_datapath_alloc_pcpu_hot_stats();
	if (ret)
		return ret;
	ret = trustix_datapath_alloc_secure_rx_scratch();
	if (ret)
		goto free_pcpu_hot_stats;
	trustix_datapath_crypto_api_get();
	ret = trustix_datapath_alloc_rx_worker_pcpu_mac_cache();
	if (ret)
		goto put_crypto_api;
	ret = trustix_datapath_alloc_state();
	if (ret)
		goto free_pcpu_mac_cache;
	trustix_datapath_run_selftests(TRUSTIX_DATAPATH_SELFTEST_ALL, &passed,
				       &failed);
	trustix_datapath_update_features_from_selftests(passed, failed);
	ret = misc_register(&trustix_datapath_miscdev);
	if (ret) {
		trustix_datapath_free_state();
		goto free_pcpu_mac_cache;
	}
	ret = register_netdevice_notifier(&trustix_datapath_netdev_notifier);
	if (ret) {
		misc_deregister(&trustix_datapath_miscdev);
		trustix_datapath_free_state();
		goto free_pcpu_mac_cache;
	}
	ret = register_netevent_notifier(&trustix_datapath_netevent_notifier);
	if (ret) {
		unregister_netdevice_notifier(&trustix_datapath_netdev_notifier);
		misc_deregister(&trustix_datapath_miscdev);
		trustix_datapath_free_state();
		goto free_pcpu_mac_cache;
	}
	trustix_datapath_init_tx_outer_gso_page_pools();
	return ret;

free_pcpu_mac_cache:
	trustix_datapath_free_rx_worker_pcpu_mac_cache();
put_crypto_api:
	trustix_datapath_crypto_api_put();
	trustix_datapath_free_secure_rx_scratch();
free_pcpu_hot_stats:
	trustix_datapath_free_pcpu_hot_stats();
	return ret;
}

static void __exit trustix_datapath_exit(void)
{
	unregister_netevent_notifier(&trustix_datapath_netevent_notifier);
	unregister_netdevice_notifier(&trustix_datapath_netdev_notifier);
	trustix_datapath_hook_detach_all();
	synchronize_net();
	misc_deregister(&trustix_datapath_miscdev);
	/* Delayed coalesce work can allocate from the TX page pools. */
	trustix_datapath_free_state();
	trustix_datapath_rx_worker_drain_page_frag_caches();
	trustix_datapath_destroy_tx_outer_gso_page_pools();
	trustix_datapath_free_rx_worker_pcpu_mac_cache();
	trustix_datapath_crypto_api_put();
	trustix_datapath_free_secure_rx_scratch();
	trustix_datapath_free_pcpu_hot_stats();
}

module_init(trustix_datapath_init);
module_exit(trustix_datapath_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TrustIX");
MODULE_DESCRIPTION("TrustIX full datapath kernel module");
MODULE_VERSION("0.1.0");
