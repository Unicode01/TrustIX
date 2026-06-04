#include <linux/fs.h>
#include <linux/atomic.h>
#include <linux/etherdevice.h>
#include <linux/err.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ioctl.h>
#include <linux/ip.h>
#include <linux/limits.h>
#include <linux/miscdevice.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/module.h>
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
#include <linux/uaccess.h>
#include <linux/udp.h>
#include <linux/workqueue.h>
#include <net/arp.h>
#include <net/checksum.h>
#if defined(__has_include)
#if __has_include(<net/gso.h>)
#include <net/gso.h>
#endif
#else
#include <net/gso.h>
#endif
#include <net/ip.h>
#include <net/net_namespace.h>
#include <net/neighbour.h>
#include <net/route.h>

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
#define TRUSTIX_DATAPATH_KNOWN_FEATURES \
	(TRUSTIX_DATAPATH_FEATURE_FULL_DATAPATH)

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
#define TRUSTIX_DATAPATH_SELFTEST_ALL \
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

#define TRUSTIX_DATAPATH_STATE_KIND_ROUTE 1U
#define TRUSTIX_DATAPATH_STATE_KIND_SESSION 2U
#define TRUSTIX_DATAPATH_STATE_KIND_FLOW 3U
#define TRUSTIX_DATAPATH_STATE_KIND_SESSION_WIRE 4U

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
#define TRUSTIX_DATAPATH_IFNAME_MAX 16U

#define TRUSTIX_DATAPATH_HOOK_OP_ATTACH 1U
#define TRUSTIX_DATAPATH_HOOK_OP_DETACH 2U
#define TRUSTIX_DATAPATH_HOOK_OP_QUERY 3U

#define TRUSTIX_DATAPATH_ENCAP_FLAG_NONE 0U

#define TRUSTIX_DATAPATH_ROUTE_FLAG_UNICAST 1U
#define TRUSTIX_DATAPATH_ROUTE_FLAG_LOCAL 2U
#define TRUSTIX_DATAPATH_ROUTE_FLAG_BLACKHOLE 3U
#define TRUSTIX_DATAPATH_ROUTE_FLAG_REJECT 4U

#define TRUSTIX_DATAPATH_SESSION_FLAG_KERNEL_FLOW BIT(2)
#define TRUSTIX_DATAPATH_SESSION_FLAG_ENCRYPTED BIT(3)
#define TRUSTIX_DATAPATH_SESSION_FLAG_SEND_ENCRYPTED BIT(4)
#define TRUSTIX_DATAPATH_SESSION_FLAG_RECEIVE_ENCRYPTED BIT(5)
#define TRUSTIX_DATAPATH_SESSION_FLAGS_ENCRYPTED \
	(TRUSTIX_DATAPATH_SESSION_FLAG_ENCRYPTED | \
	 TRUSTIX_DATAPATH_SESSION_FLAG_SEND_ENCRYPTED | \
	 TRUSTIX_DATAPATH_SESSION_FLAG_RECEIVE_ENCRYPTED)
#define TRUSTIX_DATAPATH_TRANSPORT_UDP 1U
#define TRUSTIX_DATAPATH_TRANSPORT_EXPERIMENTAL_TCP 2U
#define TRUSTIX_DATAPATH_OUTER_PARSE_FLAG_REVERSE BIT(0)
#define TRUSTIX_DATAPATH_HOOK_FLAG_RX_PREVIEW BIT(0)
#define TRUSTIX_DATAPATH_HOOK_FLAG_RX_STAGE BIT(1)
#define TRUSTIX_DATAPATH_HOOK_FLAG_RX_WORKER BIT(2)
#define TRUSTIX_DATAPATH_HOOK_FLAG_TX_PLAINTEXT BIT(3)

#define TRUSTIX_DATAPATH_RX_STAGE_OP_QUERY 1U
#define TRUSTIX_DATAPATH_RX_STAGE_OP_PEEK 2U
#define TRUSTIX_DATAPATH_RX_STAGE_OP_POP 3U
#define TRUSTIX_DATAPATH_RX_STAGE_OP_CLEAR 4U
#define TRUSTIX_DATAPATH_RX_STAGE_DEFAULT_SLOTS 16U
#define TRUSTIX_DATAPATH_RX_STAGE_MAX_SLOTS 1024U
#define TRUSTIX_DATAPATH_RX_WORKER_DEFAULT_SLOTS 16U
#define TRUSTIX_DATAPATH_RX_WORKER_MAX_SLOTS 1024U
#define TRUSTIX_DATAPATH_RX_WORKER_DEFAULT_BUDGET 64U
#define TRUSTIX_DATAPATH_RX_WORKER_STREAM_MAX_FRAMES 64U
#define TRUSTIX_DATAPATH_RX_WORKER_INLINE_PAIR_SLOTS 256U
#define TRUSTIX_DATAPATH_RX_WORKER_INLINE_PAIR_MAX_FRAMES 4U
#define TRUSTIX_DATAPATH_HOOK_MAX 16U

#define TRUSTIX_DATAPATH_TIXT_MAGIC 0x54495854U
#define TRUSTIX_DATAPATH_TIXU_MAGIC 0x54495855U
#define TRUSTIX_DATAPATH_TIXT_VERSION 1U
#define TRUSTIX_DATAPATH_TIXT_HEADER_LEN 40U
#define TRUSTIX_DATAPATH_TIXU_HEADER_LEN 32U
#define TRUSTIX_DATAPATH_MIN_FRAME_HEADER_LEN TRUSTIX_DATAPATH_TIXU_HEADER_LEN
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
};

struct trustix_datapath_state_table {
	struct trustix_datapath_state_slot *slots;
	__u32 capacity;
	__u32 count;
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
	int ifindex;
	int target_ifindex;
	struct net_device *target_dev;
	__u8 *packet;
	struct sk_buff *skb;
	bool stolen_skb;
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

struct trustix_datapath_tx_plan {
	__u64 flow_id;
	__u64 epoch;
	__u64 session_flags;
	__u32 local_ipv4;
	__u32 remote_ipv4;
	__u16 local_port;
	__u16 remote_port;
	__u8 outer_protocol;
	__u32 max_packet_size;
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
	__u8 header[sizeof(struct iphdr) + 60];
};

struct trustix_datapath_rx_worker_pending_copy {
	__u8 *packet;
	const __u8 *source_packet;
	struct sk_buff *skb;
	__u32 len;
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
static bool trustix_datapath_rx_worker_build_xmit_inner_skb_hold(
	struct net_device *target_dev, const __u8 *packet, __u32 len,
	__u32 extra_tailroom, struct sk_buff **inner_skb_out);
static int trustix_datapath_rx_worker_inline_pair_xmit_skb_frames(
	struct net_device *target_dev, struct sk_buff *skb,
	bool inline_context, unsigned int frames);
static int trustix_datapath_rx_worker_inline_pair_append_held_skb(
	struct sk_buff *skb, struct net_device *target_dev,
	const struct trustix_datapath_rx_worker_coalesce_state *state,
	const __u8 *packet, __u32 len);
static void trustix_datapath_rx_worker_inline_pair_flush_work(
	struct work_struct *work);
static void trustix_datapath_rx_worker_inline_pair_drop_all(void);

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

static bool trustix_datapath_rx_worker_inject;
module_param_named(rx_worker_inject, trustix_datapath_rx_worker_inject, bool,
		   0644);
MODULE_PARM_DESC(rx_worker_inject,
		 "Enable experimental TrustIX RX worker netif_rx reinjection");

static bool trustix_datapath_tx_plaintext;
module_param_named(tx_plaintext, trustix_datapath_tx_plaintext, bool, 0644);
MODULE_PARM_DESC(tx_plaintext,
		 "Enable TrustIX plaintext LAN-to-underlay TX ownership");

static bool trustix_datapath_rx_worker_steal_skb;
module_param_named(rx_worker_steal_skb, trustix_datapath_rx_worker_steal_skb,
		   bool, 0644);
MODULE_PARM_DESC(rx_worker_steal_skb,
		 "Enable experimental TrustIX RX worker stolen-skb reinjection");

static bool trustix_datapath_rx_worker_inline_stolen;
module_param_named(rx_worker_inline_stolen,
		   trustix_datapath_rx_worker_inline_stolen, bool, 0644);
MODULE_PARM_DESC(rx_worker_inline_stolen,
		 "Enable experimental direct netif_rx reinjection for stolen RX skbs");

static bool trustix_datapath_rx_worker_inline_receive;
module_param_named(rx_worker_inline_receive,
		   trustix_datapath_rx_worker_inline_receive, bool, 0644);
MODULE_PARM_DESC(rx_worker_inline_receive,
		 "Use netif_receive_skb for experimental stolen RX skb reinjection instead of netif_rx backlog");

static bool trustix_datapath_rx_worker_xmit;
module_param_named(rx_worker_xmit, trustix_datapath_rx_worker_xmit, bool, 0644);
MODULE_PARM_DESC(rx_worker_xmit,
		 "Transmit decapsulated TrustIX RX worker packets out the target LAN device instead of reinjecting them into local RX");

static bool trustix_datapath_rx_worker_direct_xmit;
module_param_named(rx_worker_direct_xmit,
		   trustix_datapath_rx_worker_direct_xmit, bool, 0644);
MODULE_PARM_DESC(rx_worker_direct_xmit,
		 "Use dev_direct_xmit for RX worker target-device transmission; experimental and off by default");

static bool trustix_datapath_rx_worker_xmit_hash_tx_queue;
module_param_named(rx_worker_xmit_hash_tx_queue,
		   trustix_datapath_rx_worker_xmit_hash_tx_queue, bool,
		   0644);
MODULE_PARM_DESC(rx_worker_xmit_hash_tx_queue,
		 "Hash RX worker LAN xmit skbs across target-device TX queues; experimental and off by default");

static bool trustix_datapath_rx_worker_xmit_more;
module_param_named(rx_worker_xmit_more,
		   trustix_datapath_rx_worker_xmit_more, bool, 0644);
MODULE_PARM_DESC(rx_worker_xmit_more,
		 "Set skb xmit_more on consecutive RX worker dev_queue_xmit packets; experimental and off by default");

static bool trustix_datapath_rx_worker_inline_xmit;
module_param_named(rx_worker_inline_xmit,
		   trustix_datapath_rx_worker_inline_xmit, bool, 0644);
MODULE_PARM_DESC(rx_worker_inline_xmit,
		 "Transmit validated multi-frame RX worker TCP packets directly from the netfilter hook instead of queueing worker slots");

static bool trustix_datapath_rx_worker_inline_xmit_copy_csum = true;
module_param_named(rx_worker_inline_xmit_copy_csum,
		   trustix_datapath_rx_worker_inline_xmit_copy_csum, bool,
		   0644);
MODULE_PARM_DESC(rx_worker_inline_xmit_copy_csum,
		 "Copy and checksum RX worker inline xmit TCP/UDP packets in one pass");

static bool trustix_datapath_rx_worker_hot_stats = true;
module_param_named(rx_worker_hot_stats,
		   trustix_datapath_rx_worker_hot_stats, bool, 0644);
MODULE_PARM_DESC(rx_worker_hot_stats,
		 "Update high-frequency RX worker success counters on datapath hot paths");

static bool trustix_datapath_rx_worker_inline_pair_coalesce;
module_param_named(rx_worker_inline_pair_coalesce,
		   trustix_datapath_rx_worker_inline_pair_coalesce, bool,
		   0644);
MODULE_PARM_DESC(rx_worker_inline_pair_coalesce,
		 "Pair adjacent validated single-frame inline xmit TCP packets into full-checksum inner GSO skbs");

static bool trustix_datapath_rx_worker_inline_pair_hold_skb;
module_param_named(rx_worker_inline_pair_hold_skb,
		   trustix_datapath_rx_worker_inline_pair_hold_skb, bool,
		   0644);
MODULE_PARM_DESC(rx_worker_inline_pair_hold_skb,
		 "Cache first inline TCP pair frame as a prepared skb to avoid a second copy on pair hit");

static unsigned int trustix_datapath_rx_worker_inline_pair_flush_jiffies = 1;
module_param_named(rx_worker_inline_pair_flush_jiffies,
		   trustix_datapath_rx_worker_inline_pair_flush_jiffies,
		   uint, 0644);
MODULE_PARM_DESC(rx_worker_inline_pair_flush_jiffies,
		 "Delayed flush interval for unmatched inline pair coalesce packets");

static unsigned int trustix_datapath_rx_worker_inline_coalesce_max_frames = 2;
module_param_named(rx_worker_inline_coalesce_max_frames,
		   trustix_datapath_rx_worker_inline_coalesce_max_frames,
		   uint, 0644);
MODULE_PARM_DESC(rx_worker_inline_coalesce_max_frames,
		 "Maximum adjacent inline xmit TCP packets coalesced before transmit; clamped to 2..4");

static bool trustix_datapath_rx_worker_xmit_fix_checksums = true;
module_param_named(rx_worker_xmit_fix_checksums,
		   trustix_datapath_rx_worker_xmit_fix_checksums, bool,
		   0644);
MODULE_PARM_DESC(rx_worker_xmit_fix_checksums,
		 "Rebuild inner IPv4/TCP/UDP checksums before RX worker dev_queue_xmit delivery");

static unsigned int trustix_datapath_rx_worker_xmit_trust_tcp_checksum_min_len;
module_param_named(rx_worker_xmit_trust_tcp_checksum_min_len,
		   trustix_datapath_rx_worker_xmit_trust_tcp_checksum_min_len,
		   uint, 0644);
MODULE_PARM_DESC(rx_worker_xmit_trust_tcp_checksum_min_len,
		 "Trust already-complete TCP checksums for RX worker xmit packets with at least this many payload bytes; 0 disables");

static bool trustix_datapath_rx_worker_xmit_trust_tcp_checksum_ack_only;
module_param_named(rx_worker_xmit_trust_tcp_checksum_ack_only,
		   trustix_datapath_rx_worker_xmit_trust_tcp_checksum_ack_only,
		   bool, 0644);
MODULE_PARM_DESC(rx_worker_xmit_trust_tcp_checksum_ack_only,
		 "Trust already-complete TCP checksums for RX worker xmit ACK-only packets; experimental and off by default");

static bool trustix_datapath_rx_worker_xmit_tcp_partial_csum;
module_param_named(rx_worker_xmit_tcp_partial_csum,
		   trustix_datapath_rx_worker_xmit_tcp_partial_csum, bool,
		   0644);
MODULE_PARM_DESC(rx_worker_xmit_tcp_partial_csum,
		 "Use CHECKSUM_PARTIAL for RX worker TCP dev_queue_xmit delivery instead of rebuilding L4 checksums in the worker");

static bool trustix_datapath_rx_worker_xmit_dst_mac_cache;
module_param_named(rx_worker_xmit_dst_mac_cache,
		   trustix_datapath_rx_worker_xmit_dst_mac_cache, bool, 0644);
MODULE_PARM_DESC(rx_worker_xmit_dst_mac_cache,
		 "Cache the last RX worker xmit destination MAC lookup by output device and inner IPv4 destination");

static bool trustix_datapath_rx_worker_xmit_dst_mac_pcpu_cache;
module_param_named(rx_worker_xmit_dst_mac_pcpu_cache,
		   trustix_datapath_rx_worker_xmit_dst_mac_pcpu_cache, bool,
		   0644);
MODULE_PARM_DESC(rx_worker_xmit_dst_mac_pcpu_cache,
		 "Cache the last RX worker xmit destination MAC lookup per CPU by output device and inner IPv4 destination");

static bool trustix_datapath_rx_worker_xmit_dst_mac_seq_cache;
module_param_named(rx_worker_xmit_dst_mac_seq_cache,
		   trustix_datapath_rx_worker_xmit_dst_mac_seq_cache, bool,
		   0644);
MODULE_PARM_DESC(rx_worker_xmit_dst_mac_seq_cache,
		 "Cache the last RX worker xmit destination MAC lookup with seqlock readers by output device and inner IPv4 destination");

static bool trustix_datapath_rx_worker_queue_skb;
module_param_named(rx_worker_queue_skb,
		   trustix_datapath_rx_worker_queue_skb, bool, 0644);
MODULE_PARM_DESC(rx_worker_queue_skb,
		 "Queue prebuilt inner skbs for RX worker delivery instead of queueing copied packet buffers");

static bool trustix_datapath_rx_worker_stream_coalesce_gso;
module_param_named(rx_worker_stream_coalesce_gso,
		   trustix_datapath_rx_worker_stream_coalesce_gso, bool,
		   0644);
MODULE_PARM_DESC(rx_worker_stream_coalesce_gso,
		 "Coalesce verified RX worker TCP stream frames into one inner TCPv4 GSO skb before LAN xmit delivery");

static bool trustix_datapath_rx_worker_stream_coalesce_software_segment;
module_param_named(rx_worker_stream_coalesce_software_segment,
		   trustix_datapath_rx_worker_stream_coalesce_software_segment,
		   bool, 0644);
MODULE_PARM_DESC(rx_worker_stream_coalesce_software_segment,
		 "Software-segment RX worker coalesced TCPv4 GSO skbs before LAN xmit delivery");

static bool trustix_datapath_rx_worker_stream_coalesce_partial_csum = true;
module_param_named(rx_worker_stream_coalesce_partial_csum,
		   trustix_datapath_rx_worker_stream_coalesce_partial_csum,
		   bool, 0644);
MODULE_PARM_DESC(rx_worker_stream_coalesce_partial_csum,
		 "Use CHECKSUM_PARTIAL metadata on RX worker coalesced TCPv4 GSO skbs");

static bool trustix_datapath_rx_worker_steal_xmit;
module_param_named(rx_worker_steal_xmit,
		   trustix_datapath_rx_worker_steal_xmit, bool, 0644);
MODULE_PARM_DESC(rx_worker_steal_xmit,
		 "Allow experimental stolen underlay skbs to be transmitted via dev_queue_xmit");

static bool trustix_datapath_rx_worker_steal_tcp;
module_param_named(rx_worker_steal_tcp, trustix_datapath_rx_worker_steal_tcp,
		   bool, 0644);
MODULE_PARM_DESC(rx_worker_steal_tcp,
		 "Allow experimental stolen-skb RX worker delivery for inner TCP packets");

static bool trustix_datapath_rx_worker_tcp;
module_param_named(rx_worker_tcp, trustix_datapath_rx_worker_tcp, bool, 0644);
MODULE_PARM_DESC(rx_worker_tcp,
		 "Allow experimental TrustIX RX worker to claim TCP transport frames");

static bool trustix_datapath_rx_worker_stream_tcp;
module_param_named(rx_worker_stream_tcp,
		   trustix_datapath_rx_worker_stream_tcp, bool, 0644);
MODULE_PARM_DESC(rx_worker_stream_tcp,
		 "Allow TrustIX RX worker to parse multi-frame TCP TIXT payloads");

static bool trustix_datapath_rx_worker_stream_batch_queue;
module_param_named(rx_worker_stream_batch_queue,
		   trustix_datapath_rx_worker_stream_batch_queue, bool, 0644);
MODULE_PARM_DESC(rx_worker_stream_batch_queue,
		 "Batch queue copied frames from multi-frame TCP TIXT payloads");

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

static unsigned long long trustix_datapath_rx_worker_dst_mac_hits;
module_param_named(rx_worker_dst_mac_hits,
		   trustix_datapath_rx_worker_dst_mac_hits, ullong, 0444);
MODULE_PARM_DESC(rx_worker_dst_mac_hits,
		 "TrustIX RX worker xmit packets that found a valid neighbour destination MAC");

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
static struct trustix_datapath_state_table trustix_datapath_routes;
static struct trustix_datapath_state_table trustix_datapath_sessions;
static struct trustix_datapath_state_table trustix_datapath_flows;
static struct trustix_datapath_state_table trustix_datapath_session_wires;
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

static unsigned long long trustix_datapath_tx_plaintext_gso_skips;
module_param_named(tx_plaintext_gso_skips,
		   trustix_datapath_tx_plaintext_gso_skips, ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_gso_skips,
		 "TrustIX plaintext TX packets skipped because the ingress skb is GSO");

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

static unsigned long long trustix_datapath_tx_plaintext_build_errors;
module_param_named(tx_plaintext_build_errors,
		   trustix_datapath_tx_plaintext_build_errors, ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_build_errors,
		 "TrustIX plaintext TX packet allocation, copy, or framing errors");

static unsigned long long trustix_datapath_tx_plaintext_xmit_errors;
module_param_named(tx_plaintext_xmit_errors,
		   trustix_datapath_tx_plaintext_xmit_errors, ullong, 0444);
MODULE_PARM_DESC(tx_plaintext_xmit_errors,
		 "TrustIX plaintext TX underlay route or transmit errors");

static atomic64_t trustix_datapath_tx_sequence = ATOMIC64_INIT(0);

struct trustix_datapath_hook_entry {
	struct nf_hook_ops ops;
	bool in_use;
	bool registered;
	struct net *net;
	struct net_device *target_dev;
	__u32 flags;
	int ifindex;
	int target_ifindex;
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
};

static struct trustix_datapath_hook_entry
	trustix_datapath_hooks[TRUSTIX_DATAPATH_HOOK_MAX];
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

struct trustix_datapath_rx_worker_mac_cache {
	int ifindex;
	__be32 dst_ipv4;
	__u8 addr[ETH_ALEN];
	bool valid;
};

struct trustix_datapath_rx_worker_seq_mac_cache {
	int ifindex;
	__be32 dst_ipv4;
	__u64 addr64;
	bool valid;
};

static DEFINE_SPINLOCK(trustix_datapath_rx_worker_mac_cache_lock);
static struct trustix_datapath_rx_worker_mac_cache
	trustix_datapath_rx_worker_mac_cache;
static DEFINE_PER_CPU(struct trustix_datapath_rx_worker_mac_cache,
		      trustix_datapath_rx_worker_pcpu_mac_cache);
static DEFINE_SEQLOCK(trustix_datapath_rx_worker_seq_mac_cache_lock);
static struct trustix_datapath_rx_worker_seq_mac_cache
	trustix_datapath_rx_worker_seq_mac_cache;

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
	trustix_datapath_rx_worker_alloc_errors = 0;
	trustix_datapath_rx_worker_xmit_packets = 0;
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
	trustix_datapath_rx_worker_stolen = 0;
	trustix_datapath_rx_worker_steal_fallbacks = 0;
	trustix_datapath_rx_worker_steal_errors = 0;
	trustix_datapath_rx_worker_inline_injected = 0;
	trustix_datapath_rx_worker_inline_errors = 0;
	trustix_datapath_rx_worker_inline_xmit_packets = 0;
	trustix_datapath_rx_worker_inline_xmit_errors = 0;
	trustix_datapath_rx_worker_inline_xmit_copy_csum_hits = 0;
	trustix_datapath_rx_worker_inline_xmit_copy_csum_fallbacks = 0;
	trustix_datapath_rx_worker_stream_packets = 0;
	trustix_datapath_rx_worker_stream_frames = 0;
	trustix_datapath_rx_worker_stream_errors = 0;
	trustix_datapath_rx_worker_stream_queue_errors = 0;
	trustix_datapath_rx_worker_stream_batch_packets = 0;
	trustix_datapath_rx_worker_stream_batch_frames = 0;
	trustix_datapath_rx_worker_stream_batch_errors = 0;
	trustix_datapath_rx_worker_checksum_fixed = 0;
	trustix_datapath_rx_worker_checksum_trusted = 0;
	trustix_datapath_rx_worker_checksum_ipv4_only = 0;
	trustix_datapath_rx_worker_checksum_partial = 0;
	trustix_datapath_rx_worker_checksum_errors = 0;
	trustix_datapath_rx_worker_dst_mac_hits = 0;
	trustix_datapath_rx_worker_dst_mac_cache_hits = 0;
	trustix_datapath_rx_worker_dst_mac_cache_misses = 0;
	trustix_datapath_rx_worker_dst_mac_broadcast = 0;
	trustix_datapath_rx_worker_queued_skb = 0;
	trustix_datapath_rx_worker_queued_skb_fallbacks = 0;
	trustix_datapath_rx_worker_stream_coalesce_packets = 0;
	trustix_datapath_rx_worker_stream_coalesce_frames = 0;
	trustix_datapath_rx_worker_stream_coalesce_errors = 0;
	trustix_datapath_rx_worker_stream_coalesce_segment_batches = 0;
	trustix_datapath_rx_worker_stream_coalesce_segment_skbs = 0;
	trustix_datapath_rx_worker_stream_coalesce_segment_errors = 0;
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
	    state->ack_seq != ntohl(tcph->ack_seq) ||
	    state->window != tcph->window || state->urg_ptr != tcph->urg_ptr ||
	    state->tcp_flags !=
		    trustix_datapath_rx_worker_tcp_flags_byte(tcph))
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

static struct sk_buff *
trustix_datapath_rx_worker_build_coalesced_gso_skb(
	struct net_device *target_dev,
	const struct trustix_datapath_rx_worker_coalesce_state *state,
	struct trustix_datapath_rx_worker_pending_copy *pending,
	unsigned int frames)
{
	struct skb_shared_info *shinfo;
	struct tcphdr *tcph;
	struct iphdr *iph;
	struct sk_buff *skb;
	unsigned int i;
	__u8 *dst;
	__u32 header_len;
	__u32 copied_payload = 0;
	__u32 first_tcp_len;
	__u32 payload_offset;
	__u32 tcp_len;
	__u32 gso_segs;
	bool l4_checksum_rebuilt = true;
	bool tcp_checksum_trusted = false;

	if (!target_dev || !state || !state->active || !pending ||
	    frames < 2 || !state->gso_size || !state->payload_len ||
	    state->total_len > 0xffff)
		return NULL;
	gso_segs = DIV_ROUND_UP(state->payload_len, state->gso_size);
	if (!gso_segs || gso_segs > U16_MAX)
		return NULL;
	header_len = sizeof(struct iphdr) + state->tcp_header_len;
	skb = netdev_alloc_skb_ip_align(target_dev,
					ETH_HLEN + state->total_len);
	if (!skb)
		return NULL;
	skb_reserve(skb, ETH_HLEN);
	dst = skb_put(skb, state->total_len);
	memcpy(dst, state->header, header_len);
	payload_offset = header_len;
	for (i = 0; i < frames; i++) {
		const struct iphdr *frame_iph;
		__u32 frame_payload_len;
		const __u8 *frame_packet;

		frame_packet = pending[i].packet ?: pending[i].source_packet;
		if (!frame_packet || !pending[i].len ||
		    pending[i].len < header_len) {
			kfree_skb(skb);
			return NULL;
		}
		frame_iph = (const struct iphdr *)frame_packet;
		frame_payload_len = ntohs(frame_iph->tot_len);
		if (frame_payload_len < header_len ||
		    frame_payload_len > pending[i].len) {
			kfree_skb(skb);
			return NULL;
		}
		frame_payload_len -= header_len;
		if (payload_offset + copied_payload + frame_payload_len >
		    state->total_len) {
			kfree_skb(skb);
			return NULL;
		}
		memcpy(dst + payload_offset + copied_payload,
		       frame_packet + header_len, frame_payload_len);
		copied_payload += frame_payload_len;
	}
	if (copied_payload != state->payload_len) {
		kfree_skb(skb);
		return NULL;
	}
	iph = (struct iphdr *)skb->data;
	tcph = (struct tcphdr *)(skb->data + sizeof(*iph));
	first_tcp_len = ntohs(iph->tot_len) - sizeof(*iph);
	if (!READ_ONCE(trustix_datapath_rx_worker_stream_coalesce_partial_csum) &&
	    trustix_datapath_rx_worker_trust_tcp_checksum(
		    iph, sizeof(*iph), first_tcp_len, &tcph)) {
		tcp_len = first_tcp_len;
		for (i = 1; i < frames; i++) {
			const struct iphdr *frame_iph;
			const __u8 *frame_packet;
			__u32 frame_payload_len;
			__u32 frame_total_len;

			frame_packet = pending[i].packet ?: pending[i].source_packet;
			if (!frame_packet || pending[i].len < header_len) {
				kfree_skb(skb);
				return NULL;
			}
			frame_iph = (const struct iphdr *)frame_packet;
			frame_total_len = ntohs(frame_iph->tot_len);
			if (frame_total_len < header_len ||
			    frame_total_len > pending[i].len) {
				kfree_skb(skb);
				return NULL;
			}
			frame_payload_len = frame_total_len - header_len;
			tcph->check =
				trustix_datapath_rx_worker_tcp_checksum_append_payload(
					tcph, tcp_len,
					tcp_len + frame_payload_len,
					frame_packet + header_len,
					frame_payload_len);
			tcp_len += frame_payload_len;
		}
		if (tcp_len != state->total_len - sizeof(*iph)) {
			kfree_skb(skb);
			return NULL;
		}
		tcp_checksum_trusted = true;
		l4_checksum_rebuilt = false;
	}
	iph->tot_len = htons((__u16)state->total_len);
	trustix_datapath_rx_worker_fix_ipv4_header_checksum(iph,
							   sizeof(*iph));
	if (READ_ONCE(trustix_datapath_rx_worker_stream_coalesce_partial_csum)) {
		tcph->check = ~csum_tcpudp_magic(
			iph->saddr, iph->daddr,
			state->total_len - sizeof(*iph), IPPROTO_TCP, 0);
		skb->ip_summed = CHECKSUM_PARTIAL;
		skb->csum_start = (unsigned char *)tcph - skb->head;
		skb->csum_offset = offsetof(struct tcphdr, check);
		l4_checksum_rebuilt = false;
	} else if (tcp_checksum_trusted) {
		trustix_datapath_rx_worker_checksum_trusted++;
		trustix_datapath_rx_worker_checksum_ipv4_only++;
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		skb->csum_start = 0;
		skb->csum_offset = 0;
	} else {
		tcph->check = 0;
		tcph->check = trustix_datapath_rx_worker_l4_checksum(
			iph, tcph, state->total_len - sizeof(*iph),
			IPPROTO_TCP);
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		skb->csum_start = 0;
		skb->csum_offset = 0;
	}
	if (l4_checksum_rebuilt &&
	    READ_ONCE(trustix_datapath_rx_worker_hot_stats))
		trustix_datapath_rx_worker_checksum_fixed++;
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
	unsigned long irqflags;
	__u32 i;

	spin_lock_irqsave(&trustix_datapath_rx_worker_lock, irqflags);
	if (trustix_datapath_rx_worker_ring &&
	    trustix_datapath_rx_worker_capacity) {
		for (i = 0; i < trustix_datapath_rx_worker_capacity; i++)
			trustix_datapath_rx_worker_release_slot(
				&trustix_datapath_rx_worker_ring[i]);
	}
	trustix_datapath_rx_worker_head = 0;
	trustix_datapath_rx_worker_tail = 0;
	trustix_datapath_rx_worker_count = 0;
	spin_unlock_irqrestore(&trustix_datapath_rx_worker_lock, irqflags);
}

static void trustix_datapath_free_rx_worker(void)
{
	struct trustix_datapath_rx_worker_slot *ring;
	unsigned long irqflags;

	if (trustix_datapath_rx_worker_wq) {
		flush_workqueue(trustix_datapath_rx_worker_wq);
		destroy_workqueue(trustix_datapath_rx_worker_wq);
		trustix_datapath_rx_worker_wq = NULL;
	}
	trustix_datapath_rx_worker_inline_pair_drop_all();
	trustix_datapath_rx_worker_clear();
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
	ret = trustix_datapath_alloc_table(&trustix_datapath_routes,
					   trustix_datapath_max_routes);
	if (ret)
		goto free_rx_worker;
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
	write_lock_bh(&trustix_datapath_state_lock);
	trustix_datapath_publish_state_counts_locked();
	write_unlock_bh(&trustix_datapath_state_lock);
	return 0;

free_flows:
	trustix_datapath_free_table(&trustix_datapath_flows);
free_sessions:
	trustix_datapath_free_table(&trustix_datapath_sessions);
free_routes:
	trustix_datapath_free_table(&trustix_datapath_routes);
free_rx_worker:
	trustix_datapath_free_rx_worker();
free_rx_stage:
	trustix_datapath_free_rx_stage();
	return ret;
}

static void trustix_datapath_free_state(void)
{
	write_lock_bh(&trustix_datapath_state_lock);
	trustix_datapath_free_table(&trustix_datapath_session_wires);
	trustix_datapath_free_table(&trustix_datapath_flows);
	trustix_datapath_free_table(&trustix_datapath_sessions);
	trustix_datapath_free_table(&trustix_datapath_routes);
	trustix_datapath_publish_state_counts_locked();
	write_unlock_bh(&trustix_datapath_state_lock);
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

	if (!table || !table->slots)
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

	if (!table || !table->slots)
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

static void trustix_datapath_clear_table(struct trustix_datapath_state_table *table)
{
	if (!table || !table->slots)
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

	if (!table || !table->slots)
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

static int
trustix_datapath_state_apply_locked(struct trustix_datapath_ioc_state *state)
{
	struct trustix_datapath_state_table *table;

	table = trustix_datapath_table_for_kind(state->kind);
	return trustix_datapath_state_apply_to_table(table, state, true);
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
	__u32 best_bits = 0;
	__u32 i;

	if (!trustix_datapath_routes.slots)
		return NULL;
	for (i = 0; i < trustix_datapath_routes.capacity; i++) {
		struct trustix_datapath_state_slot *slot =
			&trustix_datapath_routes.slots[i];
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

static struct trustix_datapath_state_slot *
trustix_datapath_session_for_route_locked(struct trustix_datapath_state_slot *route,
					  struct trustix_datapath_state_slot *flow)
{
	struct trustix_datapath_state_slot *best = NULL;
	__u64 next_hop_hash = 0;
	__u64 endpoint_hash = 0;
	__u64 pool_index = 0;
	__u32 i;

	if (!route || !trustix_datapath_sessions.slots)
		return NULL;
	next_hop_hash = route->key[2];
	endpoint_hash = route->key[3];
	if (flow) {
		if (flow->value[0])
			next_hop_hash = flow->value[0];
		if (flow->value[1])
			endpoint_hash = flow->value[1];
		pool_index = flow->value[2];
	}
	for (i = 0; i < trustix_datapath_sessions.capacity; i++) {
		struct trustix_datapath_state_slot *slot =
			&trustix_datapath_sessions.slots[i];

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
		best = slot;
		break;
	}
	if (best || !flow)
		return best;
	for (i = 0; i < trustix_datapath_sessions.capacity; i++) {
		struct trustix_datapath_state_slot *slot =
			&trustix_datapath_sessions.slots[i];

		if (!slot->used)
			continue;
		if (!(slot->flags & TRUSTIX_DATAPATH_SESSION_FLAG_KERNEL_FLOW))
			continue;
		if (next_hop_hash && slot->key[0] != next_hop_hash)
			continue;
		if (endpoint_hash && slot->key[1] != endpoint_hash)
			continue;
		return slot;
	}
	return NULL;
}

static struct trustix_datapath_state_slot *
trustix_datapath_session_for_flow_id_locked(__u64 flow_id)
{
	__u32 i;

	if (!flow_id || !trustix_datapath_sessions.slots)
		return NULL;
	for (i = 0; i < trustix_datapath_sessions.capacity; i++) {
		struct trustix_datapath_state_slot *slot =
			&trustix_datapath_sessions.slots[i];

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
	if (!key || !trustix_datapath_session_wires.slots)
		return NULL;
	return trustix_datapath_find_slot(&trustix_datapath_session_wires, key);
}

static struct trustix_datapath_state_slot *
trustix_datapath_session_wire_for_tuple_locked(__u64 flow_id,
					       __u32 src_ipv4, __u32 dst_ipv4,
					       __u16 src_port, __u16 dst_port,
					       __u8 protocol,
					       bool *reverse)
{
	__u32 transport;
	__u32 i;

	if (reverse)
		*reverse = false;
	if (!flow_id || !trustix_datapath_session_wires.slots)
		return NULL;
	switch (protocol) {
	case IPPROTO_UDP:
		transport = TRUSTIX_DATAPATH_TRANSPORT_UDP;
		break;
	case IPPROTO_TCP:
		transport = TRUSTIX_DATAPATH_TRANSPORT_EXPERIMENTAL_TCP;
		break;
	default:
		return NULL;
	}
	for (i = 0; i < trustix_datapath_session_wires.capacity; i++) {
		struct trustix_datapath_state_slot *slot =
			&trustix_datapath_session_wires.slots[i];
		__u32 local_ipv4;
		__u32 remote_ipv4;
		__u16 local_port;
		__u16 remote_port;

		if (!slot->used)
			continue;
		if (slot->value[0] != flow_id ||
		    (__u32)slot->value[4] != transport)
			continue;
		local_ipv4 = (__u32)slot->value[1];
		remote_ipv4 = (__u32)slot->value[2];
		local_port = (__u16)(slot->value[3] >> 16);
		remote_port = (__u16)slot->value[3];
		if (local_ipv4 == src_ipv4 && remote_ipv4 == dst_ipv4 &&
		    local_port == src_port && remote_port == dst_port)
			return slot;
		if (local_ipv4 == dst_ipv4 && remote_ipv4 == src_ipv4 &&
		    local_port == dst_port && remote_port == src_port) {
			if (reverse)
				*reverse = true;
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
	__u32 transport;
	__u32 i;

	if (reverse)
		*reverse = false;
	if (!trustix_datapath_session_wires.slots)
		return NULL;
	switch (protocol) {
	case IPPROTO_UDP:
		transport = TRUSTIX_DATAPATH_TRANSPORT_UDP;
		break;
	case IPPROTO_TCP:
		transport = TRUSTIX_DATAPATH_TRANSPORT_EXPERIMENTAL_TCP;
		break;
	default:
		return NULL;
	}
	for (i = 0; i < trustix_datapath_session_wires.capacity; i++) {
		struct trustix_datapath_state_slot *slot =
			&trustix_datapath_session_wires.slots[i];
		__u32 local_ipv4;
		__u32 remote_ipv4;
		__u16 local_port;
		__u16 remote_port;

		if (!slot->used)
			continue;
		if ((__u32)slot->value[4] != transport)
			continue;
		local_ipv4 = (__u32)slot->value[1];
		remote_ipv4 = (__u32)slot->value[2];
		local_port = (__u16)(slot->value[3] >> 16);
		remote_port = (__u16)slot->value[3];
		if (local_ipv4 == src_ipv4 && remote_ipv4 == dst_ipv4 &&
		    local_port == src_port && remote_port == dst_port)
			return slot;
		if (local_ipv4 == dst_ipv4 && remote_ipv4 == src_ipv4 &&
		    local_port == dst_port && remote_port == src_port) {
			if (reverse)
				*reverse = true;
			return slot;
		}
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
	if (fragment & 0x1fffU)
		return -EOPNOTSUPP;

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
	case TRUSTIX_DATAPATH_TRANSPORT_EXPERIMENTAL_TCP:
		outer_protocol = IPPROTO_TCP;
		outer_header_len = 20 + 20;
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

	route = trustix_datapath_route_lookup_locked(classify->dst_ipv4);
	if (!route)
		return -ENOENT;
	classify->route_flags = route->flags;
	classify->prefix_len = (__u32)route->key[1];
	if (route->flags != TRUSTIX_DATAPATH_ROUTE_FLAG_UNICAST)
		return -EHOSTUNREACH;

	trustix_datapath_flow_key(flow_key, classify->src_ipv4,
				  classify->dst_ipv4, classify->src_port,
				  classify->dst_port, classify->protocol);
	flow = trustix_datapath_find_slot(&trustix_datapath_flows, flow_key);
	session = trustix_datapath_session_for_route_locked(route, flow);
	if (!session)
		return -EHOSTUNREACH;
	classify->flow_id = session->value[0];
	classify->session_flags = session->flags;
	if (session->flags & TRUSTIX_DATAPATH_SESSION_FLAGS_ENCRYPTED)
		return -EOPNOTSUPP;

	wire = trustix_datapath_session_wire_for_key_locked(session->key);
	if (!wire)
		return -ENOKEY;
	if (wire->value[0] != session->value[0])
		return -ESTALE;

	transport = (__u32)wire->value[4];
	switch (transport) {
	case TRUSTIX_DATAPATH_TRANSPORT_UDP:
		plan->outer_protocol = IPPROTO_UDP;
		break;
	case TRUSTIX_DATAPATH_TRANSPORT_EXPERIMENTAL_TCP:
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
	return 0;
}

static int
trustix_datapath_tx_build_outer_skb(struct sk_buff *inner_skb,
				    const struct trustix_datapath_tx_plan *plan,
				    __u32 inner_len, struct sk_buff **out_skb)
{
	struct sk_buff *skb;
	__u8 *packet;
	__u8 *tixt;
	__u32 outer_header_len;
	__u32 tixt_len;
	__u32 outer_len;
	__u64 sequence;
	int ret;

	if (!inner_skb || !plan || !out_skb)
		return -EINVAL;
	*out_skb = NULL;
	if (!inner_len || inner_len > TRUSTIX_DATAPATH_TIXT_MAX_PAYLOAD)
		return -EMSGSIZE;

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
	tixt_len = TRUSTIX_DATAPATH_TIXT_HEADER_LEN + inner_len;
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
	memset(packet, 0, outer_len);

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
		packet[32] = 0x50;
		packet[33] = 0x18;
		trustix_datapath_put_be16(packet + 34, 65535);
		tixt = packet + 40;
	}

	sequence = (__u64)atomic64_inc_return(&trustix_datapath_tx_sequence);
	trustix_datapath_build_tixt(tixt, TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4,
				    plan->flow_id, plan->epoch, sequence,
				    inner_len, 0, 0);
	ret = skb_copy_bits(inner_skb, skb_network_offset(inner_skb),
			    tixt + TRUSTIX_DATAPATH_TIXT_HEADER_LEN,
			    inner_len);
	if (ret) {
		kfree_skb(skb);
		return ret;
	}

	skb_reset_network_header(skb);
	skb_set_transport_header(skb, 20);
	skb->protocol = htons(ETH_P_IP);
	skb->ip_summed = CHECKSUM_NONE;
	skb->pkt_type = PACKET_OUTGOING;
	*out_skb = skb;
	return 0;
}

static int
trustix_datapath_tx_send_outer_skb(struct sk_buff *skb,
				   struct net_device *target_dev,
				   const struct trustix_datapath_tx_plan *plan)
{
	struct flowi4 fl4 = {};
	struct rtable *rt;
	struct net *net;
	int ret;

	if (!skb || !target_dev || !plan)
		return -EINVAL;
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
	ret = ip_local_out(net, NULL, skb);
	if (ret)
		return ret;
	return 0;
}

static int
trustix_datapath_tx_plaintext_skb(struct sk_buff *skb,
				  struct trustix_datapath_ioc_classify *classify,
				  int target_ifindex,
				  struct net_device *target_dev_hint)
{
	struct trustix_datapath_tx_plan plan;
	struct net_device *target_dev = NULL;
	struct sk_buff *outer_skb = NULL;
	const struct iphdr *iph;
	__u32 inner_len;
	int ret;

	if (!READ_ONCE(trustix_datapath_tx_plaintext))
		return -EPROTONOSUPPORT;
	if (!skb || !classify)
		return -EINVAL;
	if (skb_is_gso(skb)) {
		trustix_datapath_tx_plaintext_gso_skips++;
		return -EOPNOTSUPP;
	}
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
		if (ret == -EOPNOTSUPP)
			trustix_datapath_tx_plaintext_encrypted_skips++;
		else
			trustix_datapath_tx_plaintext_route_misses++;
		goto out_dev;
	}

	if (!pskb_may_pull(skb, skb_network_offset(skb) + sizeof(*iph))) {
		ret = -ENODATA;
		trustix_datapath_tx_plaintext_build_errors++;
		goto out_dev;
	}
	iph = ip_hdr(skb);
	if (!iph || iph->version != 4 || iph->ihl < 5) {
		ret = -EPROTONOSUPPORT;
		trustix_datapath_tx_plaintext_build_errors++;
		goto out_dev;
	}
	inner_len = ntohs(iph->tot_len);
	if (!inner_len || inner_len > skb->len - skb_network_offset(skb)) {
		ret = -EMSGSIZE;
		trustix_datapath_tx_plaintext_build_errors++;
		goto out_dev;
	}

	ret = trustix_datapath_tx_build_outer_skb(skb, &plan, inner_len,
						 &outer_skb);
	if (ret) {
		trustix_datapath_tx_plaintext_build_errors++;
		goto out_dev;
	}
	ret = trustix_datapath_tx_send_outer_skb(outer_skb, target_dev, &plan);
	outer_skb = NULL;
	if (ret) {
		trustix_datapath_tx_plaintext_xmit_errors++;
		goto out_dev;
	}

	trustix_datapath_tx_plaintext_packets++;
	trustix_datapath_tx_plaintext_bytes += inner_len;
out_dev:
	if (outer_skb)
		kfree_skb(outer_skb);
	dev_put(target_dev);
	return ret;
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
	if (frame.payload_len > total_len)
		return -EMSGSIZE;
	return 0;
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
	__u16 transport_len;
	int ret;

	if (!skb || !classify || !view)
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
	if (!pskb_may_pull(skb, tixt_offset + tixt_len))
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
trustix_datapath_rx_stage_validate_locked(
	const struct trustix_datapath_ioc_classify *classify,
	struct trustix_datapath_rx_stage_view *view)
{
	struct trustix_datapath_state_slot *session;
	struct trustix_datapath_state_slot *wire;
	bool reverse = false;

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
	if (!wire)
		return -ENOKEY;
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

static bool
trustix_datapath_rx_worker_can_steal_skb(
	struct sk_buff *skb, const struct trustix_datapath_rx_stage_view *view)
{
	__u32 end;

	if (!READ_ONCE(trustix_datapath_rx_worker_steal_skb))
		return false;
	if (!skb || !view || !view->frame.payload_len)
		return false;
	if (READ_ONCE(trustix_datapath_rx_worker_xmit) &&
	    !READ_ONCE(trustix_datapath_rx_worker_steal_xmit)) {
		trustix_datapath_rx_worker_steal_fallbacks++;
		return false;
	}
	if (view->inner.protocol == IPPROTO_TCP &&
	    !READ_ONCE(trustix_datapath_rx_worker_steal_tcp)) {
		trustix_datapath_rx_worker_steal_fallbacks++;
		return false;
	}
	if (skb_is_gso(skb)) {
		trustix_datapath_rx_worker_steal_fallbacks++;
		return false;
	}
	if (view->inner_offset > skb->len ||
	    view->frame.payload_len > skb->len - view->inner_offset) {
		trustix_datapath_rx_worker_steal_fallbacks++;
		return false;
	}
	end = view->inner_offset + view->frame.payload_len;
	if (skb_headlen(skb) < end) {
		trustix_datapath_rx_worker_steal_fallbacks++;
		return false;
	}
	return true;
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
		if (tcph_out)
			*tcph_out = tcph;
		return true;
	}
	if (payload_len < min_len)
		return false;
	if (tcph_out)
		*tcph_out = tcph;
	return true;
}

static __always_inline bool trustix_datapath_rx_worker_hot_stats_enabled(void)
{
	return READ_ONCE(trustix_datapath_rx_worker_hot_stats);
}

static __always_inline void
trustix_datapath_rx_worker_count_injected(unsigned int packets)
{
	if (trustix_datapath_rx_worker_hot_stats_enabled())
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

static void
trustix_datapath_rx_worker_set_hash_tx_queue(struct sk_buff *skb,
					     const struct net_device *dev)
{
	const struct udphdr *udph;
	const struct tcphdr *tcph;
	const struct iphdr *iph;
	unsigned int txq_count;
	unsigned int offset;
	unsigned int head_len;
	__u32 ip_header_len;
	__u32 l4_offset;
	__u32 hash;
	__u16 queue;

	if (!READ_ONCE(trustix_datapath_rx_worker_xmit_hash_tx_queue))
		return;
	if (!skb || !dev)
		goto fallback;
	txq_count = READ_ONCE(dev->real_num_tx_queues);
	if (txq_count <= 1)
		goto fallback;
	offset = skb_network_offset(skb);
	head_len = skb_headlen(skb);
	if (offset > head_len || head_len - offset < sizeof(*iph))
		goto fallback;
	iph = (const struct iphdr *)(skb->data + offset);
	if (iph->version != 4 || iph->ihl < 5)
		goto fallback;
	ip_header_len = iph->ihl * 4;
	if (ip_header_len < sizeof(*iph) ||
	    offset + ip_header_len > head_len)
		goto fallback;
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
	queue = (__u16)(trustix_datapath_rx_worker_mix_hash(hash) %
			txq_count);
	skb_set_queue_mapping(skb, queue);
	trustix_datapath_rx_worker_count_hash_tx_queue(queue);
	return;

fallback:
	trustix_datapath_rx_worker_xmit_hash_tx_queue_fallbacks++;
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
	iph = (struct iphdr *)skb->data;
	if (iph->version != 4 || iph->ihl < 5 ||
	    iph->protocol != IPPROTO_TCP ||
	    (iph->frag_off & htons(0x3fff)))
		return false;
	ip_header_len = iph->ihl * 4;
	if (ip_header_len < sizeof(*iph) ||
	    skb->len < ip_header_len + sizeof(*tcph))
		return false;
	total_len = ntohs(iph->tot_len);
	if (total_len < ip_header_len + sizeof(*tcph) || total_len > skb->len)
		return false;
	tcph = (struct tcphdr *)(skb->data + ip_header_len);
	tcp_header_len = tcph->doff * 4;
	if (tcp_header_len < sizeof(*tcph) ||
	    total_len < ip_header_len + tcp_header_len)
		return false;
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
	if (xmit)
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
		__u64 cached_addr;
		__be32 cached_dst;
		int cached_ifindex;
		bool cached_valid;

		do {
			seq = read_seqbegin(
				&trustix_datapath_rx_worker_seq_mac_cache_lock);
			cached_valid =
				trustix_datapath_rx_worker_seq_mac_cache.valid;
			cached_ifindex =
				trustix_datapath_rx_worker_seq_mac_cache.ifindex;
			cached_dst =
				trustix_datapath_rx_worker_seq_mac_cache.dst_ipv4;
			cached_addr =
				trustix_datapath_rx_worker_seq_mac_cache.addr64;
		} while (read_seqretry(
			&trustix_datapath_rx_worker_seq_mac_cache_lock, seq));
		if (cached_valid && cached_ifindex == dev->ifindex &&
		    cached_dst == iph->daddr) {
			trustix_datapath_rx_worker_u64_to_mac(cached_addr, addr);
			trustix_datapath_rx_worker_dst_mac_cache_hits++;
			return true;
		}
		trustix_datapath_rx_worker_dst_mac_cache_misses++;
	}
	if (READ_ONCE(trustix_datapath_rx_worker_xmit_dst_mac_cache)) {
		unsigned long flags;

		spin_lock_irqsave(&trustix_datapath_rx_worker_mac_cache_lock,
				  flags);
		if (trustix_datapath_rx_worker_mac_cache.valid &&
		    trustix_datapath_rx_worker_mac_cache.ifindex ==
			    dev->ifindex &&
		    trustix_datapath_rx_worker_mac_cache.dst_ipv4 ==
			    iph->daddr) {
			ether_addr_copy(addr,
					trustix_datapath_rx_worker_mac_cache.addr);
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
			&trustix_datapath_rx_worker_pcpu_mac_cache);
		if (cache->valid && cache->ifindex == dev->ifindex &&
		    cache->dst_ipv4 == iph->daddr) {
			ether_addr_copy(addr, cache->addr);
			put_cpu_ptr(cache);
			trustix_datapath_rx_worker_dst_mac_cache_hits++;
			return true;
		}
		put_cpu_ptr(cache);
		trustix_datapath_rx_worker_dst_mac_cache_misses++;
	}
	neigh = neigh_lookup(&arp_tbl, &iph->daddr, (struct net_device *)dev);
	if (!neigh)
		return false;
	if ((READ_ONCE(neigh->nud_state) & NUD_VALID) &&
	    is_valid_ether_addr(neigh->ha)) {
		ether_addr_copy(addr, neigh->ha);
		ok = true;
	}
	neigh_release(neigh);
	if (ok && READ_ONCE(trustix_datapath_rx_worker_xmit_dst_mac_cache)) {
		unsigned long flags;

		spin_lock_irqsave(&trustix_datapath_rx_worker_mac_cache_lock,
				  flags);
		trustix_datapath_rx_worker_mac_cache.ifindex = dev->ifindex;
		trustix_datapath_rx_worker_mac_cache.dst_ipv4 = iph->daddr;
		ether_addr_copy(trustix_datapath_rx_worker_mac_cache.addr,
				addr);
		trustix_datapath_rx_worker_mac_cache.valid = true;
		spin_unlock_irqrestore(&trustix_datapath_rx_worker_mac_cache_lock,
				       flags);
	}
	if (ok && READ_ONCE(trustix_datapath_rx_worker_xmit_dst_mac_pcpu_cache)) {
		struct trustix_datapath_rx_worker_mac_cache *cache;

		cache = get_cpu_ptr(
			&trustix_datapath_rx_worker_pcpu_mac_cache);
		cache->ifindex = dev->ifindex;
		cache->dst_ipv4 = iph->daddr;
		ether_addr_copy(cache->addr, addr);
		cache->valid = true;
		put_cpu_ptr(cache);
	}
	if (ok && READ_ONCE(trustix_datapath_rx_worker_xmit_dst_mac_seq_cache)) {
		unsigned long flags;

		write_seqlock_irqsave(
			&trustix_datapath_rx_worker_seq_mac_cache_lock, flags);
		trustix_datapath_rx_worker_seq_mac_cache.ifindex =
			dev->ifindex;
		trustix_datapath_rx_worker_seq_mac_cache.dst_ipv4 =
			iph->daddr;
		trustix_datapath_rx_worker_seq_mac_cache.addr64 =
			trustix_datapath_rx_worker_mac_to_u64(addr);
		trustix_datapath_rx_worker_seq_mac_cache.valid = true;
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
		skb->dev = dev;
		skb->protocol = htons(ETH_P_IP);
		skb->pkt_type = PACKET_OUTGOING;
		trustix_datapath_rx_worker_set_hash_tx_queue(skb, dev);
		trustix_datapath_rx_worker_apply_xmit_more(skb, xmit_more);
		if (READ_ONCE(trustix_datapath_rx_worker_direct_xmit))
			ret = dev_direct_xmit(skb, skb_get_queue_mapping(skb));
		else
			ret = dev_queue_xmit(skb);
		if (ret == NET_XMIT_SUCCESS || ret == NET_XMIT_CN) {
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
	skb->dev = dev;
	skb->protocol = eth_type_trans(skb, dev);
	skb->pkt_type = PACKET_HOST;
	if (inline_context &&
	    READ_ONCE(trustix_datapath_rx_worker_inline_receive))
		ret = netif_receive_skb(skb);
	else
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

static int trustix_datapath_rx_worker_xmit_inner_gso_segments(
	struct sk_buff *skb, struct net_device *dev)
{
	struct sk_buff *segs;
	struct sk_buff *seg;
	struct sk_buff *next;
	netdev_features_t features = NETIF_F_SG | NETIF_F_HW_CSUM;
	unsigned int delivered = 0;
	unsigned int errors = 0;
	int first_error = 0;
	int ret;

	if (!skb || !dev || !skb_is_gso(skb))
		return -EINVAL;
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
	segs = skb_gso_segment(skb, features);
	if (IS_ERR(segs)) {
		trustix_datapath_rx_worker_stream_coalesce_segment_errors++;
		ret = PTR_ERR(segs);
		WRITE_ONCE(
			trustix_datapath_rx_worker_stream_coalesce_last_segment_ret,
			ret);
		WRITE_ONCE(trustix_datapath_rx_worker_last_deliver_ret, ret);
		kfree_skb(skb);
		return ret;
	}
	if (!segs) {
		trustix_datapath_rx_worker_stream_coalesce_segment_errors++;
		WRITE_ONCE(
			trustix_datapath_rx_worker_stream_coalesce_last_segment_ret,
			-EIO);
		WRITE_ONCE(trustix_datapath_rx_worker_last_deliver_ret, -EIO);
		kfree_skb(skb);
		return -EIO;
	}
	WRITE_ONCE(trustix_datapath_rx_worker_stream_coalesce_last_segment_ret,
		   0);
	kfree_skb(skb);

	for (seg = segs; seg; seg = next) {
		next = seg->next;
		seg->next = NULL;
		seg->prev = NULL;
		skb_dst_drop(seg);
		skb_orphan(seg);
		memset(seg->cb, 0, sizeof(seg->cb));
		seg->dev = dev;
		seg->protocol = htons(ETH_P_IP);
		seg->pkt_type = PACKET_OUTGOING;
		skb_reset_mac_header(seg);
		skb_set_network_header(seg, ETH_HLEN);
		if (seg->len >= ETH_HLEN + sizeof(struct iphdr))
			skb_set_transport_header(
				seg, ETH_HLEN + (seg->data[ETH_HLEN] & 0x0f) * 4);
		seg->mac_len = ETH_HLEN;
		if (skb_is_gso(seg))
			skb_gso_reset(seg);
		trustix_datapath_rx_worker_set_hash_tx_queue(seg, dev);
		trustix_datapath_rx_worker_apply_xmit_more(seg, next);
		ret = dev_queue_xmit(seg);
		if (ret == NET_XMIT_SUCCESS || ret == NET_XMIT_CN) {
			delivered++;
			continue;
		}
		errors++;
		if (!first_error)
			first_error = ret ? ret : -ENOBUFS;
	}
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
	return delivered ? 0 : -EIO;
}

static int trustix_datapath_rx_worker_xmit_coalesced_inner_skb(
	struct sk_buff *skb, struct net_device *target_dev, bool inline_context)
{
	int ret;

	if (!skb)
		return -EINVAL;
	if (!target_dev) {
		kfree_skb(skb);
		return -EINVAL;
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
	if (READ_ONCE(trustix_datapath_rx_worker_stream_coalesce_software_segment))
		return trustix_datapath_rx_worker_xmit_inner_gso_segments(
			skb, target_dev);
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
		NULL);
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
	struct trustix_datapath_rx_worker_pending_copy pending[
		TRUSTIX_DATAPATH_RX_WORKER_INLINE_PAIR_MAX_FRAMES] = {};
	struct trustix_datapath_rx_worker_coalesce_state cur_state = {};
	struct trustix_datapath_rx_worker_coalesce_state merged = {};
	struct trustix_datapath_rx_worker_inline_pair_slot *slot;
	struct sk_buff *coalesced_skb = NULL;
	struct sk_buff *held_skb = NULL;
	struct net_device *held_dev = NULL;
	unsigned long flags;
	__u8 *held_packets[TRUSTIX_DATAPATH_RX_WORKER_INLINE_PAIR_MAX_FRAMES];
	__u32 held_lens[TRUSTIX_DATAPATH_RX_WORKER_INLINE_PAIR_MAX_FRAMES];
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
					NULL);
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
							NULL);
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
							NULL);
					}
				}
			}
		} else {
			trustix_datapath_rx_worker_inline_pair_misses++;
			trustix_datapath_rx_worker_inline_pair_detach_locked(
				slot, true, &held_dev, &held_skb, held_packets,
				held_lens, &held_frames, NULL);
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
				ret = trustix_datapath_rx_worker_deliver_inner_skb(
					held_skb, held_dev, true);
				held_skb = NULL;
				if (!ret) {
					trustix_datapath_rx_worker_count_injected(frames);
					trustix_datapath_rx_worker_count_inline_xmit(frames);
					trustix_datapath_rx_worker_count_pair_packets(frames);
					trustix_datapath_rx_worker_count_stream_coalesce(1, frames);
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
		for (i = 0; i < held_frames &&
			    i < TRUSTIX_DATAPATH_RX_WORKER_INLINE_PAIR_MAX_FRAMES;
		     i++) {
			pending[i].source_packet = held_packets[i];
			pending[i].len = held_lens[i];
		}
		if (held_frames < TRUSTIX_DATAPATH_RX_WORKER_INLINE_PAIR_MAX_FRAMES) {
			pending[held_frames].source_packet = view->inner_packet;
			pending[held_frames].len = view->frame.payload_len;
		}
		coalesced_skb =
			trustix_datapath_rx_worker_build_coalesced_gso_skb(
				target_dev, &merged, pending, frames);
		if (coalesced_skb) {
			ret = trustix_datapath_rx_worker_xmit_coalesced_inner_skb(
				coalesced_skb, target_dev, true);
			coalesced_skb = NULL;
		} else {
			ret = -ENOMEM;
			trustix_datapath_rx_worker_inline_pair_errors++;
		}
	if (!ret) {
		trustix_datapath_rx_worker_count_injected(frames);
		trustix_datapath_rx_worker_count_inline_xmit(frames);
		trustix_datapath_rx_worker_count_pair_packets(frames);
		trustix_datapath_rx_worker_count_stream_coalesce(1, frames);
	} else {
			trustix_datapath_rx_worker_dropped += frames;
			trustix_datapath_rx_worker_inline_xmit_errors +=
				frames;
			trustix_datapath_rx_worker_inline_pair_errors++;
			trustix_datapath_rx_worker_stream_coalesce_errors++;
		}
		for (i = 0; i < held_frames &&
			    i < TRUSTIX_DATAPATH_RX_WORKER_INLINE_PAIR_MAX_FRAMES;
		     i++)
			kfree(held_packets[i]);
		if (held_dev)
			dev_put(held_dev);
		return true;
	}

	if (held_frames) {
		trustix_datapath_rx_worker_inline_pair_cancel_detached_flush(
			slot);
		if (held_skb) {
			trustix_datapath_rx_worker_inline_pair_xmit_skb_frames(
				held_dev, held_skb, true, held_frames);
			held_skb = NULL;
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

	spin_lock_irqsave(&trustix_datapath_rx_worker_lock, irqflags);
	if (!trustix_datapath_rx_worker_ring ||
	    !trustix_datapath_rx_worker_capacity) {
		trustix_datapath_rx_worker_dropped++;
		spin_unlock_irqrestore(&trustix_datapath_rx_worker_lock,
				       irqflags);
		dev_put(target_dev);
		return -ENOSPC;
	}
	if (trustix_datapath_rx_worker_count ==
	    trustix_datapath_rx_worker_capacity) {
		trustix_datapath_rx_worker_release_slot(
			&trustix_datapath_rx_worker_ring
				 [trustix_datapath_rx_worker_head]);
		trustix_datapath_rx_worker_head =
			(trustix_datapath_rx_worker_head + 1) %
			trustix_datapath_rx_worker_capacity;
		trustix_datapath_rx_worker_count--;
		trustix_datapath_rx_worker_overwritten++;
	}
	slot = &trustix_datapath_rx_worker_ring
			[trustix_datapath_rx_worker_tail];
	trustix_datapath_rx_worker_release_slot(slot);
	slot->valid = true;
	slot->len = view->frame.payload_len;
	slot->inner_offset = view->inner_offset;
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
	if (trustix_datapath_rx_worker_wq)
		queue_work(trustix_datapath_rx_worker_wq,
			   &trustix_datapath_rx_worker_work);
	return 0;

err_msgsize:
	dev_put(target_dev);
	return -EMSGSIZE;

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
		trustix_datapath_rx_worker_dropped++;
		spin_unlock_irqrestore(&trustix_datapath_rx_worker_lock,
				       irqflags);
		dev_put(target_dev);
		kfree(packet);
		kfree_skb(inner_skb);
		return -ENOSPC;
	}
	if (trustix_datapath_rx_worker_count ==
	    trustix_datapath_rx_worker_capacity) {
		trustix_datapath_rx_worker_release_slot(
			&trustix_datapath_rx_worker_ring
				 [trustix_datapath_rx_worker_head]);
		trustix_datapath_rx_worker_head =
			(trustix_datapath_rx_worker_head + 1) %
			trustix_datapath_rx_worker_capacity;
		trustix_datapath_rx_worker_count--;
		trustix_datapath_rx_worker_overwritten++;
	}
	slot = &trustix_datapath_rx_worker_ring
			[trustix_datapath_rx_worker_tail];
	trustix_datapath_rx_worker_release_slot(slot);
	slot->valid = true;
	slot->len = view->frame.payload_len;
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
	if (trustix_datapath_rx_worker_wq)
		queue_work(trustix_datapath_rx_worker_wq,
			   &trustix_datapath_rx_worker_work);
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
	if (trustix_datapath_rx_worker_can_steal_skb(skb, view)) {
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
		pending[i].len = 0;
	}
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
		if (!pending[i].source_packet || !pending[i].len)
			return -EINVAL;
		if (READ_ONCE(trustix_datapath_rx_worker_queue_skb)) {
			pending[i].skb =
				trustix_datapath_rx_worker_build_inner_skb(
					target_dev, pending[i].source_packet,
					pending[i].len);
			if (!pending[i].skb) {
				trustix_datapath_rx_worker_queued_skb_fallbacks++;
				pending[i].packet = kmemdup(
					pending[i].source_packet, pending[i].len,
					GFP_ATOMIC);
			}
		} else {
			pending[i].packet = kmemdup(pending[i].source_packet,
						    pending[i].len,
						    GFP_ATOMIC);
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
	for (i = 0; i < frames; i++) {
		if ((!pending[i].packet && !pending[i].skb) ||
		    !pending[i].len) {
			ret = -EINVAL;
			break;
		}
		if (!trustix_datapath_rx_worker_ring ||
		    !trustix_datapath_rx_worker_capacity) {
			trustix_datapath_rx_worker_dropped += frames - i;
			ret = -ENOSPC;
			break;
		}
		if (trustix_datapath_rx_worker_count ==
		    trustix_datapath_rx_worker_capacity) {
			trustix_datapath_rx_worker_release_slot(
				&trustix_datapath_rx_worker_ring
					 [trustix_datapath_rx_worker_head]);
			trustix_datapath_rx_worker_head =
				(trustix_datapath_rx_worker_head + 1) %
				trustix_datapath_rx_worker_capacity;
			trustix_datapath_rx_worker_count--;
			trustix_datapath_rx_worker_overwritten++;
		}
		slot = &trustix_datapath_rx_worker_ring
				[trustix_datapath_rx_worker_tail];
		trustix_datapath_rx_worker_release_slot(slot);
		slot->valid = true;
		slot->len = pending[i].len;
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
		pending[i].len = 0;
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
	if (queued && trustix_datapath_rx_worker_wq)
		queue_work(trustix_datapath_rx_worker_wq,
			   &trustix_datapath_rx_worker_work);
	return ret;
}

static int trustix_datapath_rx_worker_enqueue_pending_skb(
	struct sk_buff *source_skb, struct net_device *target_dev,
	struct sk_buff *inner_skb, __u32 len, unsigned int frames,
	unsigned int *queued_frames)
{
	struct trustix_datapath_rx_worker_slot *slot;
	unsigned long irqflags;
	int ret = 0;

	if (queued_frames)
		*queued_frames = 0;
	if (!source_skb || !target_dev || !inner_skb || !len || !frames)
		return -EINVAL;

	spin_lock_irqsave(&trustix_datapath_rx_worker_lock, irqflags);
	if (!trustix_datapath_rx_worker_ring ||
	    !trustix_datapath_rx_worker_capacity) {
		trustix_datapath_rx_worker_dropped += frames;
		ret = -ENOSPC;
		goto out_unlock;
	}
	if (trustix_datapath_rx_worker_count ==
	    trustix_datapath_rx_worker_capacity) {
		trustix_datapath_rx_worker_release_slot(
			&trustix_datapath_rx_worker_ring
				 [trustix_datapath_rx_worker_head]);
		trustix_datapath_rx_worker_head =
			(trustix_datapath_rx_worker_head + 1) %
			trustix_datapath_rx_worker_capacity;
		trustix_datapath_rx_worker_count--;
		trustix_datapath_rx_worker_overwritten++;
	}
	slot = &trustix_datapath_rx_worker_ring
			[trustix_datapath_rx_worker_tail];
	trustix_datapath_rx_worker_release_slot(slot);
	slot->valid = true;
	slot->len = len;
	slot->ifindex = source_skb->dev ? source_skb->dev->ifindex : 0;
	slot->target_ifindex = target_dev->ifindex;
	slot->target_dev = target_dev;
	dev_hold(target_dev);
	slot->skb = inner_skb;
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
	if (!ret && trustix_datapath_rx_worker_wq)
		queue_work(trustix_datapath_rx_worker_wq,
			   &trustix_datapath_rx_worker_work);
	return ret;
}

static bool trustix_datapath_rx_worker_build_xmit_inner_skb_copy_csum(
	struct net_device *target_dev, const __u8 *packet, __u32 len,
	__u32 extra_tailroom,
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
	bool l4_checksum_rebuilt = true;

	if (inner_skb_out)
		*inner_skb_out = NULL;
	if (!READ_ONCE(trustix_datapath_rx_worker_inline_xmit_copy_csum) ||
	    !READ_ONCE(trustix_datapath_rx_worker_xmit_fix_checksums) ||
	    READ_ONCE(trustix_datapath_rx_worker_xmit_tcp_partial_csum))
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
		if (trustix_datapath_rx_worker_trust_tcp_checksum(
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
		udph->check = 0;
		l4_sum = csum_partial(udph, l4_len, 0);
		udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
						l4_len, IPPROTO_UDP, l4_sum);
		if (!udph->check)
			udph->check = CSUM_MANGLED_0;
		break;
	default:
		kfree_skb(inner_skb);
		return false;
	}
	inner_skb->ip_summed = CHECKSUM_UNNECESSARY;
	inner_skb->csum = 0;
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

static int trustix_datapath_rx_worker_build_xmit_inner_skb(
	struct net_device *target_dev, const __u8 *packet, __u32 len,
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
		    target_dev, packet, len, 0, inner_skb_out))
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
		target_dev, packet, len, extra_tailroom, inner_skb_out);
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

static int trustix_datapath_rx_worker_inline_xmit_view(
	struct sk_buff *skb, const struct trustix_datapath_rx_stage_view *view,
	int target_ifindex, struct net_device *target_dev_hint)
{
	struct net_device *target_dev = NULL;
	struct sk_buff *inner_skb = NULL;
	int ret;

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
	if (trustix_datapath_rx_worker_inline_pair_coalesce_view(
		    target_dev, view, target_ifindex)) {
		ret = 0;
		goto out;
	}
	ret = trustix_datapath_rx_worker_build_xmit_inner_skb(
		target_dev, view->inner_packet, view->frame.payload_len,
		&inner_skb);
	if (ret)
		goto out;
	ret = trustix_datapath_rx_worker_deliver_inner_skb(inner_skb,
							   target_dev, true);
	inner_skb = NULL;
	if (!ret) {
		trustix_datapath_rx_worker_count_injected(1);
		trustix_datapath_rx_worker_count_inline_xmit(1);
	} else {
		trustix_datapath_rx_worker_dropped++;
		trustix_datapath_rx_worker_inline_xmit_errors++;
	}
out:
	kfree_skb(inner_skb);
	if (target_dev)
		dev_put(target_dev);
	if (ret)
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
	struct trustix_datapath_rx_worker_coalesce_state coalesce = {};
	struct trustix_datapath_rx_stage_view view = {};
	struct trustix_datapath_ioc_classify inner = {};
	struct net_device *target_dev = NULL;
	struct sk_buff *coalesced_skb = NULL;
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
	bool try_coalesce;
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
	pending = kcalloc(expected_frames, sizeof(*pending), GFP_ATOMIC);
	if (!pending) {
		trustix_datapath_rx_worker_alloc_errors++;
		ret = -ENOMEM;
		goto out_dev;
	}
	try_coalesce = READ_ONCE(trustix_datapath_rx_worker_stream_coalesce_gso);
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
		read_lock_bh(&trustix_datapath_state_lock);
		ret = trustix_datapath_rx_stage_validate_locked(outer, &view);
		read_unlock_bh(&trustix_datapath_state_lock);
		if (ret)
			goto error;
		if (!trustix_datapath_rx_worker_payload_fits_target(
			    &view, target_dev)) {
			ret = -EOPNOTSUPP;
			goto error;
		}
		if (try_coalesce &&
		    trustix_datapath_rx_worker_coalesce_accept(
			    &coalesce, inner_packet,
			    view.frame.payload_len))
			try_coalesce = false;
		pending[frames].source_packet = inner_packet;
		pending[frames].len = view.frame.payload_len;
		frames++;
		cursor += view.frame.wire_len;
		remaining -= view.frame.wire_len;
	}
	if (frames != expected_frames) {
		ret = -EIO;
		goto error;
	}
	if (try_coalesce && coalesce.active && frames > 1) {
		coalesced_skb =
			trustix_datapath_rx_worker_build_coalesced_gso_skb(
				target_dev, &coalesce, pending, frames);
		if (coalesced_skb) {
			ret = trustix_datapath_rx_worker_xmit_coalesced_inner_skb(
				coalesced_skb, target_dev, true);
			coalesced_skb = NULL;
			if (!ret) {
				trustix_datapath_rx_worker_count_injected(frames);
				trustix_datapath_rx_worker_count_inline_xmit(
					frames);
				trustix_datapath_rx_worker_count_stream_coalesce(
					1, frames);
				if (xmit_frames)
					*xmit_frames = frames;
				trustix_datapath_rx_worker_free_pending_copies(
					pending, frames);
				kfree(pending);
				dev_put(target_dev);
				return 0;
			}
			trustix_datapath_rx_worker_dropped += frames;
			trustix_datapath_rx_worker_inline_xmit_errors += frames;
			trustix_datapath_rx_worker_stream_coalesce_errors++;
			goto error;
		}
		trustix_datapath_rx_worker_stream_coalesce_errors++;
	}
	for (i = 0; i < frames; i++) {
		ret = trustix_datapath_rx_worker_build_xmit_inner_skb(
			target_dev, pending[i].source_packet, pending[i].len,
			&pending[i].skb);
		if (ret)
			goto error;
	}
	for (i = 0; i < frames; i++) {
		struct sk_buff *inner_skb = pending[i].skb;

		pending[i].skb = NULL;
		ret = trustix_datapath_rx_worker_deliver_inner_skb_more(
			inner_skb, target_dev, true, i + 1 < frames);
		if (ret) {
			errors++;
			if (!first_error)
				first_error = ret;
			continue;
		}
		delivered++;
	}
	if (delivered) {
		trustix_datapath_rx_worker_count_injected(delivered);
		trustix_datapath_rx_worker_count_inline_xmit(delivered);
	}
	if (errors) {
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
	kfree_skb(coalesced_skb);
	trustix_datapath_rx_worker_inline_xmit_errors++;
	trustix_datapath_rx_worker_free_pending_copies(pending, frames);
	kfree(pending);
out_dev:
	if (target_dev)
		dev_put(target_dev);
	return ret;
}

static int
trustix_datapath_rx_worker_push_stream_batch_copy(
	struct sk_buff *skb, const struct trustix_datapath_ioc_classify *outer,
	__u32 total_len, __u32 tixt_offset, unsigned int expected_frames,
	int target_ifindex, unsigned int *queued_frames)
{
	struct trustix_datapath_rx_worker_pending_copy *pending;
	struct trustix_datapath_rx_worker_coalesce_state coalesce = {};
	struct trustix_datapath_rx_stage_view view = {};
	struct trustix_datapath_ioc_classify inner = {};
	struct net_device *target_dev = NULL;
	struct sk_buff *coalesced_skb = NULL;
	const __u8 *network;
	const __u8 *cursor;
	const __u8 *inner_packet;
	__u8 inner_ip_header_len;
	__u8 inner_l4_header_len;
	__u32 remaining;
	unsigned int frames = 0;
	unsigned int queued = 0;
	bool try_coalesce;
	int ret;

	if (queued_frames)
		*queued_frames = 0;
	if (!READ_ONCE(trustix_datapath_rx_worker_stream_batch_queue))
		return -EOPNOTSUPP;
	if (!skb || !outer || !expected_frames ||
	    expected_frames > TRUSTIX_DATAPATH_RX_WORKER_STREAM_MAX_FRAMES)
		return -EINVAL;
	ret = trustix_datapath_rx_worker_target_dev(skb, &target_dev,
						    target_ifindex);
	if (ret)
		return ret;
	pending = kcalloc(expected_frames, sizeof(*pending), GFP_ATOMIC);
	if (!pending) {
		trustix_datapath_rx_worker_alloc_errors++;
		ret = -ENOMEM;
		goto error;
	}
	try_coalesce = READ_ONCE(trustix_datapath_rx_worker_xmit) &&
		       READ_ONCE(trustix_datapath_rx_worker_stream_coalesce_gso);
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
		read_lock_bh(&trustix_datapath_state_lock);
		ret = trustix_datapath_rx_stage_validate_locked(outer, &view);
		read_unlock_bh(&trustix_datapath_state_lock);
		if (ret)
			goto error;
		if (!trustix_datapath_rx_worker_payload_fits_target(
			    &view, target_dev)) {
			ret = -EOPNOTSUPP;
			goto error;
		}
		if (try_coalesce &&
		    trustix_datapath_rx_worker_coalesce_accept(
			    &coalesce, inner_packet,
			    view.frame.payload_len))
			try_coalesce = false;
		pending[frames].source_packet = inner_packet;
		pending[frames].len = view.frame.payload_len;
		frames++;
		cursor += view.frame.wire_len;
		remaining -= view.frame.wire_len;
	}
	if (frames != expected_frames) {
		ret = -EIO;
		goto error;
	}
	if (try_coalesce && coalesce.active && frames > 1) {
		coalesced_skb =
			trustix_datapath_rx_worker_build_coalesced_gso_skb(
				target_dev, &coalesce, pending, frames);
		if (coalesced_skb) {
			ret = trustix_datapath_rx_worker_enqueue_pending_skb(
				skb, target_dev, coalesced_skb,
				coalesce.total_len, frames, &queued);
			if (ret)
				goto error;
			coalesced_skb = NULL;
			if (queued_frames)
				*queued_frames = queued;
			trustix_datapath_rx_worker_count_stream_batch(1, queued);
			trustix_datapath_rx_worker_count_stream_coalesce(1, queued);
			trustix_datapath_rx_worker_free_pending_copies(
				pending, frames);
			kfree(pending);
			dev_put(target_dev);
			WRITE_ONCE(trustix_datapath_rx_worker_last_push_ret, 0);
			return 0;
		}
		trustix_datapath_rx_worker_stream_coalesce_errors++;
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
	kfree_skb(coalesced_skb);
	trustix_datapath_rx_worker_free_pending_copies(pending, frames);
	kfree(pending);
	if (target_dev)
		dev_put(target_dev);
	trustix_datapath_rx_worker_stream_batch_errors++;
	WRITE_ONCE(trustix_datapath_rx_worker_last_push_ret, ret);
	return ret;
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
	__u32 remaining;
	unsigned int frames = 0;
	int ret;

	if (queued_frames)
		*queued_frames = 0;
	if (!READ_ONCE(trustix_datapath_rx_worker_stream_tcp))
		return -EOPNOTSUPP;
	if (!READ_ONCE(trustix_datapath_rx_worker_inject))
		return -EOPNOTSUPP;
	if (!skb || !outer || outer->protocol != IPPROTO_TCP)
		return -EINVAL;
	if (ip_header_len != 20 || l4_header_len != 20)
		return -EPROTONOSUPPORT;
	network = skb_network_header(skb);
	if (!network)
		return -EINVAL;
	total_len = trustix_datapath_get_be16(network + 2);
	if (total_len > skb->len)
		return -EMSGSIZE;
	tixt_offset = 40;
	if (total_len < tixt_offset + TRUSTIX_DATAPATH_MIN_FRAME_HEADER_LEN)
		return -EPROTONOSUPPORT;
	if (!pskb_may_pull(skb, total_len))
		return -ENODATA;

	network = skb_network_header(skb);
	cursor = network + tixt_offset;
	remaining = total_len - tixt_offset;
	while (remaining) {
		if (frames >= TRUSTIX_DATAPATH_RX_WORKER_STREAM_MAX_FRAMES) {
			ret = -E2BIG;
			goto error;
		}
		memset(&view, 0, sizeof(view));
		ret = trustix_datapath_parse_tixt_header(cursor, remaining,
							 &view.frame);
		if (ret)
			goto error;
		if (!(view.frame.flags &
		      TRUSTIX_DATAPATH_TIXT_FLAG_INNER_IPV4)) {
			ret = -EPROTONOSUPPORT;
			goto error;
		}
		if (!view.frame.wire_len ||
		    view.frame.wire_len > remaining) {
			ret = -EMSGSIZE;
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
		read_lock_bh(&trustix_datapath_state_lock);
		ret = trustix_datapath_rx_stage_validate_locked(outer, &view);
		read_unlock_bh(&trustix_datapath_state_lock);
		if (ret)
			goto error;
		frames++;
		cursor += view.frame.wire_len;
		remaining -= view.frame.wire_len;
	}
	if (!frames)
		return -ENODATA;
	if (READ_ONCE(trustix_datapath_rx_worker_inline_xmit) &&
	    READ_ONCE(trustix_datapath_rx_worker_xmit)) {
		ret = trustix_datapath_rx_worker_inline_xmit_stream_copy(
			skb, outer, total_len, tixt_offset, frames,
			target_ifindex, queued_frames);
		if (!ret && queued_frames && *queued_frames) {
			trustix_datapath_rx_worker_count_stream_packets(1, *queued_frames);
		}
		return ret;
	}
	if (READ_ONCE(trustix_datapath_rx_worker_stream_batch_queue)) {
		ret = trustix_datapath_rx_worker_push_stream_batch_copy(
			skb, outer, total_len, tixt_offset, frames,
			target_ifindex, queued_frames);
		if (!ret) {
			trustix_datapath_rx_worker_count_stream_packets(1, frames);
		}
		return ret;
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
	if (READ_ONCE(trustix_datapath_rx_worker_xmit) &&
	    trustix_datapath_rx_worker_fix_inner_checksums(skb)) {
		trustix_datapath_rx_worker_checksum_errors++;
		return -EBADMSG;
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

	slot.valid = true;
	slot.len = view->frame.payload_len;
	slot.inner_offset = view->inner_offset;
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
	if (slot->skb && !skb_is_gso(slot->skb) &&
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

	if (!slot)
		return;
	if (!slot->valid || !slot->target_dev || !slot->len ||
	    (!slot->packet && !slot->skb)) {
		trustix_datapath_rx_worker_release_slot(slot);
		trustix_datapath_rx_worker_dropped++;
		return;
	}
	if (slot->target_dev->type != ARPHRD_ETHER) {
		trustix_datapath_rx_worker_dropped++;
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
	if (READ_ONCE(trustix_datapath_rx_worker_xmit) &&
	    trustix_datapath_rx_worker_fix_inner_checksums(inner_skb)) {
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
		trustix_datapath_rx_worker_count_injected(1);
	else
		trustix_datapath_rx_worker_dropped++;
	trustix_datapath_rx_worker_release_slot(slot);
}

static bool trustix_datapath_rx_worker_try_drain_coalesced(
	struct trustix_datapath_rx_worker_slot *first, unsigned int max_frames,
	unsigned int *processed_extra)
{
	struct trustix_datapath_rx_worker_pending_copy *pending;
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
		slots[0].target_dev, &coalesce, pending, frames);
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
		coalesced_skb, target_dev, false);
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

	budget = READ_ONCE(trustix_datapath_rx_worker_budget);
	if (!budget)
		budget = TRUSTIX_DATAPATH_RX_WORKER_DEFAULT_BUDGET;

	for (;;) {
		if (processed >= budget) {
			if (trustix_datapath_rx_worker_has_pending() &&
			    trustix_datapath_rx_worker_wq)
				queue_work(trustix_datapath_rx_worker_wq,
					   &trustix_datapath_rx_worker_work);
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
	int target_ifindex;
	int outer_ret = -EPROTONOSUPPORT;
	int worker_ret = -EPROTONOSUPPORT;
	int tx_ret = -EPROTONOSUPPORT;
	__u32 hook_flags;
	bool outer_candidate = false;
	bool rx_prepared = false;
	bool rx_preview = false;
	bool rx_stage = false;
	bool rx_worker = false;
	bool worker_queued = false;
	bool worker_defer_stolen = false;
	bool worker_stream_queued = false;
	struct net_device *worker_defer_target_dev = NULL;
	unsigned int worker_stream_frames = 0;
	int ret;

	if (!skb || !hook || !READ_ONCE(hook->registered))
		return NF_ACCEPT;
	target_ifindex = READ_ONCE(hook->target_ifindex);
	target_dev_hint = READ_ONCE(hook->target_dev);
	ret = trustix_datapath_parse_skb_ipv4(skb, &classify, &ip_header_len,
					      &l4_header_len);
	if (ret) {
		write_lock_bh(&trustix_datapath_state_lock);
		hook->seen++;
		hook->parse_errors++;
		trustix_datapath_packet_parse_errors++;
		hook->pass++;
		write_unlock_bh(&trustix_datapath_state_lock);
		return NF_ACCEPT;
	}
	hook_flags = READ_ONCE(hook->flags);
	if (hook_flags & TRUSTIX_DATAPATH_HOOK_FLAG_TX_PLAINTEXT) {
		tx_ret = trustix_datapath_tx_plaintext_skb(
			skb, &classify, target_ifindex, target_dev_hint);
		if (!tx_ret) {
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
		if (outer_candidate)
			trustix_datapath_debug_record_outer(1, outer_ret,
							    worker_ret, skb,
							    &classify,
							    ip_header_len,
							    l4_header_len);
		if (!outer_ret && (rx_preview || rx_stage || rx_worker)) {
			outer_ret = trustix_datapath_rx_prepare_skb(
				skb, &classify, ip_header_len, l4_header_len,
				&rx_view);
			rx_prepared = !outer_ret;
			if (outer_ret == -EMSGSIZE && rx_worker &&
			    classify.protocol == IPPROTO_TCP &&
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
						target_dev_hint);
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
		worker_queued = rx_worker && rx_prepared && !worker_ret;
		if (worker_stream_queued)
			worker_queued = true;
	}

	write_lock_bh(&trustix_datapath_state_lock);
	hook->seen++;
	if (outer_candidate) {
		hook->outer_seen++;
		if (!outer_ret && !worker_stream_queued)
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
	ret = trustix_datapath_classify_locked(&classify);
	if (ret == 0)
		hook->classified++;
	else if (ret == -ENOENT)
		hook->route_misses++;
	else if (ret == -EHOSTUNREACH)
		hook->session_misses++;
	trustix_datapath_account_packet_classify_locked(skb->len, &classify,
							ret);
	if (worker_queued) {
		hook->drop++;
		if (worker_stream_frames > 1)
			hook->rx_worker += worker_stream_frames - 1;
	} else {
		hook->pass++;
	}
	write_unlock_bh(&trustix_datapath_state_lock);
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

static void
trustix_datapath_fill_hook_locked(
	struct trustix_datapath_ioc_hook *hook,
	const struct trustix_datapath_hook_entry *entry)
{
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
	hook->seen = entry->seen;
	hook->classified = entry->classified;
	hook->parse_errors = entry->parse_errors;
	hook->route_misses = entry->route_misses;
	hook->session_misses = entry->session_misses;
	hook->pass = entry->pass;
	hook->drop = entry->drop;
	hook->outer_seen = entry->outer_seen;
	hook->outer_parsed = entry->outer_parsed;
	hook->outer_parse_errors = entry->outer_parse_errors;
	hook->outer_session_misses = entry->outer_session_misses;
	hook->rx_preview = entry->rx_preview;
	hook->rx_preview_errors = entry->rx_preview_errors;
	hook->rx_stage = entry->rx_stage;
	hook->rx_stage_errors = entry->rx_stage_errors;
	hook->rx_worker = entry->rx_worker;
	hook->rx_worker_errors = entry->rx_worker_errors;
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
	trustix_datapath_rx_worker_alloc_errors = 0;
	trustix_datapath_rx_worker_xmit_packets = 0;
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
	trustix_datapath_rx_worker_stolen = 0;
	trustix_datapath_rx_worker_steal_fallbacks = 0;
	trustix_datapath_rx_worker_steal_errors = 0;
	trustix_datapath_rx_worker_inline_injected = 0;
	trustix_datapath_rx_worker_inline_errors = 0;
	trustix_datapath_rx_worker_inline_xmit_packets = 0;
	trustix_datapath_rx_worker_inline_xmit_errors = 0;
	trustix_datapath_rx_worker_inline_xmit_copy_csum_hits = 0;
	trustix_datapath_rx_worker_inline_xmit_copy_csum_fallbacks = 0;
	trustix_datapath_rx_worker_stream_packets = 0;
	trustix_datapath_rx_worker_stream_frames = 0;
	trustix_datapath_rx_worker_stream_errors = 0;
	trustix_datapath_rx_worker_stream_queue_errors = 0;
	trustix_datapath_rx_worker_stream_batch_packets = 0;
	trustix_datapath_rx_worker_stream_batch_frames = 0;
	trustix_datapath_rx_worker_stream_batch_errors = 0;
	trustix_datapath_rx_worker_checksum_fixed = 0;
	trustix_datapath_rx_worker_checksum_trusted = 0;
	trustix_datapath_rx_worker_checksum_ipv4_only = 0;
	trustix_datapath_rx_worker_checksum_partial = 0;
	trustix_datapath_rx_worker_checksum_errors = 0;
	trustix_datapath_rx_worker_dst_mac_hits = 0;
	trustix_datapath_rx_worker_dst_mac_cache_hits = 0;
	trustix_datapath_rx_worker_dst_mac_cache_misses = 0;
	trustix_datapath_rx_worker_dst_mac_broadcast = 0;
	trustix_datapath_rx_worker_queued_skb = 0;
	trustix_datapath_rx_worker_queued_skb_fallbacks = 0;
	trustix_datapath_rx_worker_stream_coalesce_packets = 0;
	trustix_datapath_rx_worker_stream_coalesce_frames = 0;
	trustix_datapath_rx_worker_stream_coalesce_errors = 0;
	trustix_datapath_rx_worker_stream_coalesce_segment_batches = 0;
	trustix_datapath_rx_worker_stream_coalesce_segment_skbs = 0;
	trustix_datapath_rx_worker_stream_coalesce_segment_errors = 0;
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
	trustix_datapath_tx_plaintext_packets = 0;
	trustix_datapath_tx_plaintext_bytes = 0;
	trustix_datapath_tx_plaintext_gso_skips = 0;
	trustix_datapath_tx_plaintext_encrypted_skips = 0;
	trustix_datapath_tx_plaintext_route_misses = 0;
	trustix_datapath_tx_plaintext_build_errors = 0;
	trustix_datapath_tx_plaintext_xmit_errors = 0;
	trustix_datapath_rx_stage_clear();
	trustix_datapath_rx_worker_clear();
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
	entry->net = hook_net;
	entry->target_dev = target_dev;
	entry->ifindex = dev->ifindex;
	entry->target_ifindex =
		target_dev ? target_dev->ifindex : 0;
	entry->flags =
		hook->flags & (TRUSTIX_DATAPATH_HOOK_FLAG_RX_PREVIEW |
			       TRUSTIX_DATAPATH_HOOK_FLAG_RX_STAGE |
			       TRUSTIX_DATAPATH_HOOK_FLAG_RX_WORKER |
			       TRUSTIX_DATAPATH_HOOK_FLAG_TX_PLAINTEXT);
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

static int
trustix_datapath_hook_apply(struct trustix_datapath_ioc_hook *hook)
{
	int ret = 0;

	if (!hook)
		return -EINVAL;
	switch (hook->op) {
	case TRUSTIX_DATAPATH_HOOK_OP_ATTACH:
		ret = trustix_datapath_hook_attach(hook);
		break;
	case TRUSTIX_DATAPATH_HOOK_OP_DETACH:
		ret = trustix_datapath_hook_detach(hook);
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

static int trustix_datapath_selftest_session_wire(void)
{
	struct trustix_datapath_state_table table = {};
	struct trustix_datapath_ioc_state state = {};
	int ret;

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

delete_record:
	state.op = TRUSTIX_DATAPATH_STATE_OP_DELETE;
	(void)trustix_datapath_state_apply_to_table(&table, &state, false);
out:
	trustix_datapath_free_table(&table);
	return ret;
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
	    build.flow_id != 0x9988776655443322ULL ||
	    build.epoch != 9 ||
	    build.route_flags != TRUSTIX_DATAPATH_ROUTE_FLAG_UNICAST ||
	    build.prefix_len != 24 ||
	    build.session_flags != TRUSTIX_DATAPATH_SESSION_FLAG_KERNEL_FLOW ||
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
	    trustix_datapath_get_be64(out + 36) != 0x9988776655443322ULL ||
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
trustix_datapath_build_tixt(__u8 *wire, __u8 flags, __u64 flow_id,
			    __u64 epoch, __u64 sequence, __u32 payload_len,
			    __u16 fragment_index, __u16 fragment_count)
{
	memset(wire, 0, TRUSTIX_DATAPATH_TIXT_HEADER_LEN + payload_len);
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

	if (magic == TRUSTIX_DATAPATH_TIXT_MAGIC)
		payload_len = trustix_datapath_get_be32(wire + 32);
	else
		payload_len = trustix_datapath_get_be32(wire + 24);
	if (payload_len > TRUSTIX_DATAPATH_TIXT_MAX_PAYLOAD)
		return -EMSGSIZE;
	if (payload_len > UINT_MAX - header_len)
		return -EMSGSIZE;
	wire_len = header_len + payload_len;
	if (wire_len > len)
		return -EMSGSIZE;

	if (magic == TRUSTIX_DATAPATH_TIXT_MAGIC) {
		fragment_index = trustix_datapath_get_be16(wire + 36);
		fragment_count = trustix_datapath_get_be16(wire + 38);
	} else {
		fragment_index = trustix_datapath_get_be16(wire + 28);
		fragment_count = trustix_datapath_get_be16(wire + 30);
	}
	if (fragment_count == 0) {
		if (fragment_index != 0)
			return -EBADMSG;
		if (flags & TRUSTIX_DATAPATH_TIXT_FLAG_CRYPTO_FRAGMENT)
			return -EBADMSG;
	} else if (fragment_index >= fragment_count) {
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

static int trustix_datapath_selftest_tixt_stream(void)
{
	struct trustix_datapath_tixt_frame frame;
	__u8 stream[(TRUSTIX_DATAPATH_TIXT_HEADER_LEN + 24) * 2];
	__u32 cursor = 0;
	int ret;

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
	return 0;
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
		if (trustix_datapath_selftest_state_table())
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
		if (trustix_datapath_selftest_outer_build())
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

	if (passed)
		*passed = pass;
	if (failed)
		*failed = fail;
}

static void trustix_datapath_refresh_features(void)
{
	__u64 passed = 0;
	__u64 failed = 0;
	__u64 requested_features;
	__u64 active_features = 0;
	__u32 flags = 0;

	trustix_datapath_run_selftests(TRUSTIX_DATAPATH_SELFTEST_ALL, &passed,
				       &failed);
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
	    (passed & TRUSTIX_DATAPATH_SELFTEST_ALL) ==
		    TRUSTIX_DATAPATH_SELFTEST_ALL &&
	    !(failed & TRUSTIX_DATAPATH_SELFTEST_ALL) &&
	    READ_ONCE(trustix_datapath_rx_worker_inject) &&
	    READ_ONCE(trustix_datapath_rx_worker_ring) &&
	    READ_ONCE(trustix_datapath_rx_worker_capacity) &&
	    READ_ONCE(trustix_datapath_rx_worker_wq) &&
	    READ_ONCE(trustix_datapath_tx_plaintext)) {
		active_features |= TRUSTIX_DATAPATH_FEATURE_FULL_DATAPATH;
	}
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
	struct trustix_datapath_ioc_hook hook;
	struct trustix_datapath_ioc_tixt_encap encap;
	struct trustix_datapath_ioc_tixt_decap decap;
	struct trustix_datapath_ioc_outer_build outer_build;
	struct trustix_datapath_ioc_outer_parse outer_parse;
	struct trustix_datapath_ioc_rx_stage rx_stage;
	struct trustix_datapath_ioc_state __user *user_records;
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
	__u32 i;
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
		trustix_datapath_run_selftests(requested, &passed, &failed);
		trustix_datapath_refresh_features();
		memset(&selftest, 0, sizeof(selftest));
		selftest.version = TRUSTIX_DATAPATH_IOC_VERSION;
		selftest.result = failed ? -EINVAL : 0;
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
		write_lock_bh(&trustix_datapath_state_lock);
		ret = trustix_datapath_state_apply_locked(&state);
		write_unlock_bh(&trustix_datapath_state_lock);
		state.result = ret;
		if (copy_to_user((void __user *)arg, &state, sizeof(state)))
			return -EFAULT;
		return 0;
	case TRUSTIX_DATAPATH_IOC_STATE_STATS:
		if (copy_from_user(&stats, (void __user *)arg, sizeof(stats)))
			return -EFAULT;
		if (stats.version != TRUSTIX_DATAPATH_IOC_VERSION)
			return -EINVAL;
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
		ret = 0;
		write_lock_bh(&trustix_datapath_state_lock);
		for (i = 0; i < batch.count; i++) {
			if (copy_from_user(&state, &user_records[i],
					   sizeof(state))) {
				ret = -EFAULT;
				break;
			}
			if (state.version != TRUSTIX_DATAPATH_IOC_VERSION) {
				ret = -EINVAL;
				break;
			}
			ret = trustix_datapath_state_apply_locked(&state);
			state.result = ret;
			if (copy_to_user(&user_records[i], &state,
					 sizeof(state))) {
				ret = -EFAULT;
				break;
			}
			if (ret)
				break;
			batch.applied++;
		}
		write_unlock_bh(&trustix_datapath_state_lock);
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
		read_lock_bh(&trustix_datapath_state_lock);
		ret = trustix_datapath_classify_locked(&classify);
		read_unlock_bh(&trustix_datapath_state_lock);
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
		write_lock_bh(&trustix_datapath_state_lock);
		ret = trustix_datapath_packet_classify_locked(&packet_classify,
							      packet_buf);
		write_unlock_bh(&trustix_datapath_state_lock);
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
		read_lock_bh(&trustix_datapath_state_lock);
		memset(&packet_stats, 0, sizeof(packet_stats));
		packet_stats.version = TRUSTIX_DATAPATH_IOC_VERSION;
		packet_stats.packets = trustix_datapath_packets_seen;
		packet_stats.bytes = trustix_datapath_bytes_seen;
		packet_stats.parse_errors =
			trustix_datapath_packet_parse_errors;
		packet_stats.route_misses =
			trustix_datapath_packet_route_misses;
		packet_stats.session_misses =
			trustix_datapath_packet_session_misses;
		packet_stats.unicast_routes =
			trustix_datapath_packet_unicast_routes;
		packet_stats.local_routes = trustix_datapath_packet_local_routes;
		packet_stats.blackhole_routes =
			trustix_datapath_packet_blackhole_routes;
		packet_stats.reject_routes =
			trustix_datapath_packet_reject_routes;
		read_unlock_bh(&trustix_datapath_state_lock);
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
		write_lock_bh(&trustix_datapath_state_lock);
		ret = trustix_datapath_tixt_encap_locked(&encap, encap_inner,
							 encap_out);
		write_unlock_bh(&trustix_datapath_state_lock);
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
		write_lock_bh(&trustix_datapath_state_lock);
		ret = trustix_datapath_tixt_decap_locked(&decap, decap_wire,
							 decap_out);
		write_unlock_bh(&trustix_datapath_state_lock);
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
		write_lock_bh(&trustix_datapath_state_lock);
		ret = trustix_datapath_outer_build_locked(&outer_build,
							  outer_inner,
							  outer_out);
		write_unlock_bh(&trustix_datapath_state_lock);
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
		write_lock_bh(&trustix_datapath_state_lock);
		ret = trustix_datapath_outer_parse_locked(&outer_parse,
							  outer_wire,
							  outer_parse_out);
		write_unlock_bh(&trustix_datapath_state_lock);
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
	int ret;

	ret = trustix_datapath_alloc_state();
	if (ret)
		return ret;
	trustix_datapath_refresh_features();
	ret = misc_register(&trustix_datapath_miscdev);
	if (ret)
		trustix_datapath_free_state();
	return ret;
}

static void __exit trustix_datapath_exit(void)
{
	trustix_datapath_hook_detach_all();
	misc_deregister(&trustix_datapath_miscdev);
	trustix_datapath_free_state();
}

module_init(trustix_datapath_init);
module_exit(trustix_datapath_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TrustIX");
MODULE_DESCRIPTION("TrustIX full datapath kernel module");
MODULE_VERSION("0.1.0");
