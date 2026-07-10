// SPDX-License-Identifier: GPL-2.0
// TrustIX skb datapath helper kfuncs.
//
// This module owns packet/header/GSO helpers. It intentionally keeps direct
// device xmit and software GSO segmentation out of the TC kfunc hot path until
// those paths have target-kernel soak tests.
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/atomic.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/etherdevice.h>
#include <linux/highmem.h>
#include <linux/hrtimer.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/netdevice.h>
#include <linux/notifier.h>
#include <linux/overflow.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>
#include <linux/version.h>
#include <linux/workqueue.h>
#if defined(__has_include)
#if __has_include(<linux/unaligned.h>)
#include <linux/unaligned.h>
#else
#include <asm/unaligned.h>
#endif
#else
#include <asm/unaligned.h>
#endif
#include <net/checksum.h>
#include <net/dst.h>
#if defined(__has_include)
#if __has_include(<net/gso.h>)
#include <net/gso.h>
#endif
#else
#include <net/gso.h>
#endif

#include "trustix_datapath_helpers_internal.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
#define kmap_local_page(page) kmap_atomic(page)
#define kunmap_local(addr) kunmap_atomic(addr)
#endif

#ifndef BTF_KFUNCS_START
#define BTF_KFUNCS_START(name) BTF_SET8_START(name)
#endif
#ifndef BTF_KFUNCS_END
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

#define TRUSTIX_DATAPATH_FEATURE_KFUNC_TC BIT_ULL(2)
#define TRUSTIX_DATAPATH_FEATURE_GSO_SKB BIT_ULL(6)
#define TRUSTIX_DATAPATH_FEATURE_ROUTE_TCP_KFUNC BIT_ULL(8)
#define TRUSTIX_DATAPATH_FEATURE_ROUTE_TCP_XMIT_KFUNC BIT_ULL(9)

#define TRUSTIX_SKB_CLEAR_TX_OFFLOAD_CSUM BIT(0)
#define TRUSTIX_SKB_CLEAR_TX_OFFLOAD_GSO BIT(1)
#define TRUSTIX_SKB_CLEAR_TX_OFFLOAD_ENCAP BIT(2)
#define TRUSTIX_KUDP_TX_UDP_HEADER_PARTIAL_CSUM BIT(8)
#define TRUSTIX_TIXT_TX_FINALIZE_TCP_PARTIAL_CSUM BIT(8)
#define TRUSTIX_TIXT_TX_FINALIZE_TCP_TRUST_INNER_CSUM BIT(9)
#define TRUSTIX_TIXT_TX_FINALIZE_TCP_TRUST_PARTIAL_INNER_CSUM BIT(10)
#define TRUSTIX_TIXT_TX_FINALIZE_TCP_TRUST_VALIDATED_LEN BIT(11)
#define TRUSTIX_KUDP_RX_DECAP_L2_TRUST_INNER_L4_CSUM BIT(0)
#define TRUSTIX_KUDP_RX_PARSE_EXPERIMENTAL_TCP_ONLY BIT(0)
#define TRUSTIX_KUDP_RX_PARSE_KERNEL_UDP_ONLY BIT(1)
#define TRUSTIX_KUDP_RX_PARSE_DECAP_L2_LOCAL_DELIVERED 1
#define TRUSTIX_KUDP_RX_PARSE_DECAP_L2_STOLEN 2
#define TRUSTIX_KUDP_HEADER_LEN 32
#define TRUSTIX_KUDP_MAGIC 0x54495855U
#define TRUSTIX_KUDP_FLAG_ENCRYPTED BIT(0)
#define TRUSTIX_KUDP_FLAG_KERNEL_OPENED BIT(1)
#define TRUSTIX_KUDP_FLAG_CRYPTO_FRAGMENT BIT(2)
#define TRUSTIX_KUDP_FLAG_INNER_IPV4 BIT(3)
#define TRUSTIX_TIXT_HEADER_LEN 40
#define TRUSTIX_TIXT_TCP_OUTER_OVERHEAD \
	((u32)sizeof(struct iphdr) + (u32)sizeof(struct tcphdr) + \
	 (u32)TRUSTIX_TIXT_HEADER_LEN)
#define TRUSTIX_TIXT_TCP_OUTER_HEADER_LEN \
	(ETH_HLEN + sizeof(struct iphdr) + sizeof(struct tcphdr) + \
	 TRUSTIX_TIXT_HEADER_LEN)
#define TRUSTIX_TIXT_MAGIC 0x54495854U
#define TRUSTIX_TIXT_FLAG_ENCRYPTED BIT(0)
#define TRUSTIX_TIXT_FLAG_KERNEL_OPENED BIT(1)
#define TRUSTIX_TIXT_FLAG_INNER_IPV4 BIT(3)
#define TRUSTIX_TIXT_TX_GSO_SEGMENTS_STOLEN 4
#define TRUSTIX_KUDP_TX_FLOW_FLAG_SECURE BIT(0)
#define TRUSTIX_KUDP_TX_FLOW_FLAG_TRUST_INNER_CSUM BIT(1)
#define TRUSTIX_KUDP_TX_FLOW_FLAG_EXPERIMENTAL_TCP BIT(3)
#define TRUSTIX_KUDP_TX_FLOW_FLAG_SKIP_OUTER_TCP_CSUM BIT(4)
#define TRUSTIX_KUDP_TX_ROUTE_FLAG_INLINE_FLOW BIT(1)
#define TRUSTIX_KUDP_TX_ROUTE_FLAG_BYPASS BIT(2)
#define TRUSTIX_SKB_CB_RX_NEXT_HOP 0
#define TRUSTIX_SKB_CB_RX_OUTER_LEN 4
#define TRUSTIX_TIXT_TX_GSO_MAX_SEGMENTS 128
#define TRUSTIX_TIXT_RX_STREAM_MAX_FRAMES 64
#define TRUSTIX_TIXT_RX_STREAM_PARSE_LINEAR_MAX (256U * 1024U)
#define TRUSTIX_TIXT_TX_ROUTE_STREAM_MAX_FRAMES 64
#define TRUSTIX_TIXT_TX_ROUTE_SYNC_STREAM_MAX_FRAMES 40
#define TRUSTIX_TIXT_TX_ROUTE_SYNC_STREAM_MAX_BATCHES \
	DIV_ROUND_UP(TRUSTIX_TIXT_TX_GSO_MAX_SEGMENTS, 2)
#define TRUSTIX_ROUTE_TCP_GSO_ASYNC_CROSS_ITEM_LOOKAHEAD_MAX 16
#define TRUSTIX_TIXT_RX_SINGLE_COALESCE_SLOTS 512
#define TRUSTIX_TIXT_RX_SINGLE_COALESCE_MAX_FRAMES 64
#define TRUSTIX_TIXT_RX_SINGLE_COALESCE_DIRECT_LIST_MAX_FRAMES 4
#define TRUSTIX_TIXT_RX_SINGLE_COALESCE_DIRECT_LIST_DEFAULT_MAX_FRAMES 4
#define TRUSTIX_TIXT_RX_SINGLE_COALESCE_HEADER_MAX \
	(sizeof(struct iphdr) + 60U)
#define TRUSTIX_TIXT_RX_SINGLE_COALESCE_PAYLOAD_MAX \
	(0xffffU - sizeof(struct iphdr) - sizeof(struct tcphdr))
#define TRUSTIX_TIXT_RX_SINGLE_COALESCE_MIN_PAYLOAD 512U
#define TRUSTIX_TIXT_RX_SINGLE_COALESCE_LINEAR_MAX 32768U
#define TRUSTIX_TIXT_RX_SINGLE_COALESCE_PAGE_MAX \
	DIV_ROUND_UP(TRUSTIX_TIXT_RX_SINGLE_COALESCE_PAYLOAD_MAX, PAGE_SIZE)
#define TRUSTIX_TIXT_RX_SINGLE_COALESCE_SPILL_PAGE_MAX \
	DIV_ROUND_UP(TRUSTIX_TIXT_RX_SINGLE_COALESCE_PAYLOAD_MAX - \
		     TRUSTIX_TIXT_RX_SINGLE_COALESCE_LINEAR_MAX, PAGE_SIZE)
#define TRUSTIX_TIXT_TX_ROUTE_GSO_INNER_HEADER_MAX \
	(sizeof(struct iphdr) + 60U)
#define TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN 24U
#define TRUSTIX_KERNEL_CRYPTO_FRAME_TAG_LEN 16U
#define TRUSTIX_KERNEL_CRYPTO_FRAME_MAX 4095U
#define TRUSTIX_KERNEL_CRYPTO_PLAIN_MAX \
	(TRUSTIX_KERNEL_CRYPTO_FRAME_MAX - TRUSTIX_KERNEL_CRYPTO_FRAME_TAG_LEN)
#define TRUSTIX_TIXT_TX_SECURE_PAYLOAD_OVERHEAD \
	(TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN + \
	 TRUSTIX_KERNEL_CRYPTO_FRAME_TAG_LEN)
#define TRUSTIX_KUDP_UDP_OUTER_HEADER_LEN \
	(ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr) + \
	 TRUSTIX_KUDP_HEADER_LEN)
#define TRUSTIX_KUDP_SECURE_UDP_OUTER_OVERHEAD \
	((u32)sizeof(struct iphdr) + (u32)sizeof(struct udphdr) + \
	 (u32)TRUSTIX_KUDP_HEADER_LEN + \
	 (u32)TRUSTIX_TIXT_TX_SECURE_PAYLOAD_OVERHEAD)
#define TRUSTIX_ROUTE_TCP_GSO_ASYNC_MAX_QUEUE_SHARDS 8
#define TRUSTIX_TIXT_TX_ROUTE_TCP_XMIT_STOLEN 5
#define TRUSTIX_TIXT_TX_ROUTE_TCP_XMIT_QUEUED 6

struct trustix_kudp_tx_udp_header_args {
	u8 l2[ETH_HLEN];
	__be32 saddr;
	__be32 daddr;
	__be16 source;
	__be16 dest;
	u16 ip_tot_len;
	u16 udp_len;
	u16 ip_check_base;
	u64 flow_id;
	u64 sequence;
	u32 payload_len;
	u32 flags;
};

struct trustix_kudp_rx_decap_l2_dev_args {
	u32 outer_len;
	u32 ifindex;
	u64 l2_head;
	u32 l2_tail0;
	u32 l2_tail1;
	u32 flags;
};

struct trustix_kudp_rx_parse_args {
	u32 static_dest_port;
	u32 flags;
	u64 l2_head;
	u32 l2_tail0;
	u32 l2_tail1;
	u32 decap_flags;
	u32 local_ipv4;
	u32 local_ipv4_mask;
	u32 local_ifindex;
	u32 egress_ifindex;
};

struct trustix_tixt_tx_tcp_header_args {
	u8 l2[ETH_HLEN];
	__be32 saddr;
	__be32 daddr;
	__be16 source;
	__be16 dest;
	u16 ip_tot_len;
	u16 ip_check_base;
	u32 pad0;
	u64 flow_id;
	u64 sequence;
	u32 payload_len;
	u32 flags;
};

struct trustix_kudp_tx_flow_value {
	u64 sequence;
	__be32 saddr;
	__be32 daddr;
	__be16 source;
	__be16 dest;
	u32 ifindex;
	u32 destination_mac0;
	u16 destination_mac1;
	u16 ipv4_check_udp;
	u32 source_mac0;
	u16 source_mac1;
	u16 ipv4_check_tcp;
	u32 mtu;
	u32 flags;
};

struct trustix_kudp_tx_route_value {
	u64 flow_id;
	u64 flow_id_1;
	u64 flow_id_2;
	u64 flow_id_3;
	u64 flow_id_4;
	u64 flow_id_5;
	u64 flow_id_6;
	u64 flow_id_7;
	u64 flow_id_8;
	u32 flow_mask;
	u32 flags;
	struct trustix_kudp_tx_flow_value inline_flow_1;
	struct trustix_kudp_tx_flow_value inline_flow_2;
	struct trustix_kudp_tx_flow_value inline_flow_3;
	struct trustix_kudp_tx_flow_value inline_flow_4;
	struct trustix_kudp_tx_flow_value inline_flow_5;
	struct trustix_kudp_tx_flow_value inline_flow_6;
	struct trustix_kudp_tx_flow_value inline_flow_7;
	struct trustix_kudp_tx_flow_value inline_flow_8;
};

struct trustix_tixt_tx_flow_header_args {
	u64 flow_id;
	u32 payload_len;
	u32 clear_flags;
};

struct trustix_tixt_tx_route_header_args {
	u32 clear_flags;
	u32 reserved;
};

struct trustix_tixt_tx_route_gso_args {
	u32 clear_flags;
	u32 reserved;
};

struct trustix_tixt_tx_secure_route_gso_args {
	u32 clear_flags;
	u32 slot_id;
	u16 suite;
	u16 reserved0;
	u64 epoch;
	u64 flow_id;
	u8 iv[12];
	u32 reserved1;
};

struct trustix_aead_direct_batch_op {
	const u8 *src;
	u8 *dst;
	u32 plain_len;
	u8 nonce[12];
};

typedef int (*trustix_kernel_direct_seal_batch_fn)(
	u32 slot_id, const struct trustix_aead_direct_batch_op *ops,
	u32 count);

extern int trustix_kernel_direct_seal_batch(
	u32 slot_id, const struct trustix_aead_direct_batch_op *ops,
	u32 count);

static trustix_kernel_direct_seal_batch_fn
trustix_kernel_direct_seal_batch_get(void)
{
	return symbol_get(trustix_kernel_direct_seal_batch);
}

struct trustix_tixt_rx_single_coalesce_frame {
	const u8 *inner;
	u32 inner_len;
	u32 tcp_header_len;
	u32 payload_len;
	u32 payload_offset;
	__be32 saddr;
	__be32 daddr;
	__be16 source;
	__be16 dest;
	u32 seq;
	u32 ack_seq;
	__be16 window;
	__be16 urg_ptr;
	__sum16 tcp_check;
	u8 tcp_flags;
};

struct trustix_tixt_rx_single_coalesce_emit {
	struct sk_buff *skb;
	struct sk_buff *skb_list;
	struct net_device *dev;
	u32 gso_size;
	unsigned int frames;
	unsigned int list_frames;
};

struct trustix_tixt_rx_single_coalesce_slot {
	spinlock_t lock;
	struct delayed_work flush_work;
	struct net_device *dev;
	bool armed;
	u32 armed_ifindex;
	u32 armed_passes;
	u64 l2_head;
	u32 l2_tail0;
	u32 l2_tail1;
	u32 decap_flags;
	__be32 saddr;
	__be32 daddr;
	__be16 source;
	__be16 dest;
	__be16 window;
	__be16 urg_ptr;
	u32 skb_hash;
	u32 tcp_header_len;
	u32 next_seq;
	u32 ack_seq;
	u8 tcp_flags;
	u32 gso_size;
	u32 frame_count;
	u32 seqs[TRUSTIX_TIXT_RX_SINGLE_COALESCE_DIRECT_LIST_MAX_FRAMES];
	__sum16 tcp_checks[TRUSTIX_TIXT_RX_SINGLE_COALESCE_DIRECT_LIST_MAX_FRAMES];
	u8 frame_headers[TRUSTIX_TIXT_RX_SINGLE_COALESCE_DIRECT_LIST_MAX_FRAMES]
			[TRUSTIX_TIXT_RX_SINGLE_COALESCE_HEADER_MAX];
	u32 total_payload;
	u32 payload_linear_len;
	u32 payload_cap;
	u32 payload_page_len;
	u32 payload_page_cap;
	bool payload_page_only;
	bool flush_queued;
	struct page *payload_pages[
		TRUSTIX_TIXT_RX_SINGLE_COALESCE_PAGE_MAX];
	u8 header[TRUSTIX_TIXT_RX_SINGLE_COALESCE_HEADER_MAX];
	u8 *payload;
};

struct trustix_route_tcp_gso_async_queue_shard {
	struct list_head queue;
	spinlock_t lock;
	bool scheduled;
	bool delay_pending;
	unsigned int depth_defers;
	struct delayed_work work;
	struct hrtimer schedule_timer;
};

static bool trustix_datapath_helpers_registered;
static bool trustix_tixt_tx_plain_skip_sequence;
static bool trustix_tixt_tx_plain_ack_only;
static bool trustix_route_tcp_gso;
static bool trustix_route_tcp_gso_sync_stream;
static bool trustix_route_tcp_gso_sync_stream_outer_gso = true;
static unsigned int trustix_route_tcp_gso_sync_stream_max_frames = 8;
static bool trustix_route_tcp_gso_async;
static bool trustix_route_tcp_gso_async_dev_xmit;
static bool trustix_route_tcp_gso_async_prefer;
static unsigned int trustix_route_tcp_gso_async_limit = 256;
static unsigned long trustix_route_tcp_gso_async_bytes_limit = 32UL * 1024UL * 1024UL;
static unsigned int trustix_route_tcp_gso_async_worker_item_budget = 16;
static unsigned int trustix_route_tcp_gso_async_worker_segment_budget = 512;
static unsigned int trustix_route_tcp_gso_async_worker_emit_budget;
static unsigned int trustix_route_tcp_gso_async_worker_resched_stride = 1;
static unsigned int trustix_route_tcp_gso_async_worker_dequeue_batch = 1;
static unsigned int trustix_route_tcp_gso_async_worker_min_queue_depth;
static unsigned int trustix_route_tcp_gso_async_worker_max_depth_defers;
static unsigned int trustix_route_tcp_gso_async_worker_schedule_delay_jiffies;
static unsigned int trustix_route_tcp_gso_async_worker_schedule_delay_usecs;
static bool trustix_route_tcp_gso_async_worker_schedule_delay_no_accel;
static unsigned int trustix_route_tcp_gso_async_worker_budget_reschedule_delay_jiffies;
static unsigned int trustix_route_tcp_gso_async_worker_budget_reschedule_delay_usecs;
static bool trustix_route_tcp_gso_async_hot_stats;
static unsigned int trustix_route_tcp_gso_async_max_segments_per_item = 64;
static bool trustix_route_tcp_gso_async_force_software_outer_csum = true;
static bool trustix_route_tcp_gso_async_force_inner_checksum = true;
static bool trustix_route_tcp_gso_async_direct_xmit;
static bool trustix_route_tcp_gso_async_xmit_more;
static unsigned int trustix_route_tcp_gso_async_xmit_cn_sleep_usecs;
static unsigned int trustix_route_tcp_gso_async_xmit_busy_retries = 2;
static unsigned int trustix_route_tcp_gso_async_xmit_busy_sleep_usecs;
static bool trustix_route_tcp_gso_async_ordered_queue = true;
static bool trustix_route_tcp_gso_async_unbound_worker;
static bool trustix_route_tcp_gso_async_sharded_queue;
static unsigned int trustix_route_tcp_gso_async_queue_shards = 4;
static bool trustix_route_tcp_gso_async_flow_shard_queue;
static bool trustix_route_tcp_gso_async_stream;
static bool trustix_route_tcp_gso_async_stream_direct_build;
static bool trustix_route_tcp_gso_async_stream_direct_build_inner_csum = true;
static bool trustix_route_tcp_gso_async_stream_direct_build_fast_copy = true;
static bool trustix_route_tcp_gso_async_stream_direct_build_frag_fast_copy = true;
static bool trustix_route_tcp_gso_async_stream_direct_build_frag_fast_copy_cross_page;
static bool trustix_route_tcp_gso_async_stream_nonlinear_direct_build;
static bool trustix_route_tcp_gso_async_stream_software_segment = true;
static unsigned int trustix_route_tcp_gso_async_stream_max_frames = 16;
static bool trustix_route_tcp_gso_async_stream_allow_virtio_net;
static bool trustix_route_tcp_gso_async_stream_outer_gso;
static bool trustix_route_tcp_gso_async_stream_outer_gso_hard_enable;
static bool trustix_route_tcp_gso_async_secure_seal_batch;
static atomic64_t trustix_route_tcp_gso_secure_outer_sequence =
	ATOMIC64_INIT(0);
static bool trustix_route_tcp_gso_async_stream_cross_item_batch;
static bool trustix_route_tcp_gso_async_stream_cross_item_dequeue_batch;
static bool trustix_route_tcp_gso_async_stream_cross_item_tail_stitch;
static bool trustix_route_tcp_gso_async_stream_cross_item_debug;
static unsigned int trustix_route_tcp_gso_async_stream_cross_item_max_frames;
static unsigned int trustix_route_tcp_gso_async_stream_cross_item_lookahead;
static bool trustix_route_tcp_gso_async_stream_cross_item_dynamic_cap;
static unsigned int trustix_route_tcp_gso_async_stream_cross_item_dynamic_low_frames;
static unsigned int trustix_route_tcp_gso_async_stream_cross_item_dynamic_queue_depth;
static bool trustix_route_tcp_gso_async_reslice_to_mtu;
static bool trustix_route_tcp_gso_async_hash_tx_queue;
static bool trustix_route_tcp_gso_async_yield_on_xmit_cn;
static bool trustix_route_tcp_xmit_worker;
static bool trustix_route_tcp_xmit_worker_steal;
static unsigned int trustix_route_tcp_xmit_worker_queue_limit = 4096;
static unsigned int trustix_route_tcp_xmit_worker_budget = 64;
static bool trustix_kudp_rx_hot_stats;
static bool trustix_tixt_rx_stream_parse;
static bool trustix_tixt_rx_stream_xmit_extra;
static bool trustix_tixt_rx_stream_ordered_list;
static bool trustix_tixt_rx_stream_gso_xmit = true;
static bool trustix_tixt_rx_stream_coalesce_gso;
static bool trustix_tixt_rx_stream_nonlinear_parse;
static bool trustix_tixt_rx_single_coalesce_gso;
static bool trustix_tixt_rx_single_coalesce_skip_tcp_csum;
static bool trustix_tixt_rx_single_coalesce_direct_list = true;
static bool trustix_tixt_rx_single_coalesce_page_only;
static bool trustix_tixt_rx_single_coalesce_linear_build;
static bool trustix_tixt_rx_single_coalesce_hybrid_head;
static bool trustix_tixt_rx_single_coalesce_netif_rx;
static bool trustix_tixt_rx_single_coalesce_schedule_once;
static bool trustix_tixt_rx_single_coalesce_stream_fallback = true;
static bool trustix_tixt_rx_stream_coalesce_mark_gso;
static bool trustix_tixt_rx_single_coalesce_mark_gso;
static bool trustix_tixt_rx_coalesce_mark_gso_partial_csum = true;
static bool trustix_tixt_rx_coalesce_segment_gso = true;
static bool trustix_tixt_rx_single_coalesce_hot_stats;
static bool trustix_tixt_rx_single_coalesce_defer_full_flush;
static bool trustix_tixt_rx_single_coalesce_keep_full_timer;
static bool trustix_tixt_rx_single_coalesce_set_hash;
static unsigned int trustix_tixt_rx_backlog_worker_budget = 2048;
static unsigned int trustix_tixt_rx_backlog_worker_queue_limit = 8192;
static unsigned int trustix_tixt_rx_single_coalesce_schedule_stride = 1;
static unsigned int trustix_tixt_rx_stream_max_frames = 16;
static unsigned int trustix_tixt_rx_single_coalesce_max_frames = 16;
static unsigned int trustix_tixt_rx_single_coalesce_direct_list_max_frames =
	TRUSTIX_TIXT_RX_SINGLE_COALESCE_DIRECT_LIST_DEFAULT_MAX_FRAMES;
static unsigned int trustix_tixt_rx_single_coalesce_flush_jiffies = 1;
static unsigned int trustix_tixt_rx_single_coalesce_warmup_frames = 1;
static unsigned int trustix_tixt_rx_single_coalesce_linear_max =
	TRUSTIX_TIXT_RX_SINGLE_COALESCE_LINEAR_MAX;

static atomic_t trustix_route_tcp_gso_async_inflight_atomic;
static atomic_long_t trustix_route_tcp_gso_async_queued_bytes_atomic;
static unsigned int trustix_route_tcp_gso_async_inflight;
static unsigned long trustix_route_tcp_gso_async_queued_bytes;
static unsigned long trustix_route_tcp_gso_async_queued_bytes_high;
static unsigned long trustix_route_tcp_gso_async_queued;
static unsigned long trustix_route_tcp_gso_async_calls;
static unsigned long trustix_route_tcp_gso_async_invalid_args;
static unsigned long trustix_route_tcp_gso_async_disabled;
static unsigned long trustix_netdev_unregister_events;
static unsigned long trustix_netdev_unregister_probe_ignored;
static unsigned long trustix_netdev_unregister_flushes;
static unsigned long trustix_route_tcp_gso_async_no_dev;
static unsigned long trustix_route_tcp_gso_async_no_gso;
static unsigned long trustix_route_tcp_gso_async_invalid_flags;
static unsigned long trustix_route_tcp_gso_async_flow_errors;
static unsigned long trustix_route_tcp_gso_async_plan_errors;
static unsigned long trustix_route_tcp_gso_async_linear_plans;
static unsigned long trustix_route_tcp_gso_async_no_ifindex;
static unsigned long trustix_route_tcp_gso_async_no_out_dev;
static unsigned long trustix_route_tcp_gso_async_mtu_errors;
static unsigned long trustix_route_tcp_gso_async_queue_full;
static unsigned long trustix_route_tcp_gso_async_queue_bytes_full;
static unsigned long trustix_route_tcp_gso_async_alloc_errors;
static unsigned long trustix_route_tcp_gso_async_clone_errors;
static unsigned long trustix_route_tcp_gso_async_workers;
static unsigned long trustix_route_tcp_gso_async_worker_runs;
static unsigned long trustix_route_tcp_gso_async_worker_budget_yields;
static unsigned long trustix_route_tcp_gso_async_worker_emit_budget_yields;
static unsigned long trustix_route_tcp_gso_async_worker_dequeue_batches;
static unsigned long trustix_route_tcp_gso_async_worker_dequeue_items;
static unsigned long trustix_route_tcp_gso_async_worker_depth_defers;
static unsigned long trustix_route_tcp_gso_async_worker_depth_defer_exhausted;
static unsigned long trustix_route_tcp_gso_async_worker_schedule_delays;
static unsigned long trustix_route_tcp_gso_async_worker_schedule_delay_accels;
static unsigned long trustix_route_tcp_gso_async_worker_schedule_delay_accel_suppressed;
static unsigned long trustix_route_tcp_gso_async_worker_budget_usleeps;
static unsigned long trustix_route_tcp_gso_async_segment_errors;
static unsigned long trustix_route_tcp_gso_async_prepare_errors;
static unsigned long trustix_route_tcp_gso_async_txq_stopped_drops;
static unsigned long trustix_route_tcp_gso_async_txq_stopped_queued;
static unsigned int trustix_route_tcp_gso_async_txq_stopped_backoff_retries;
static unsigned int trustix_route_tcp_gso_async_txq_stopped_backoff_sleep_usecs;
static unsigned long trustix_route_tcp_gso_async_txq_stopped_backoff_attempts;
static unsigned long trustix_route_tcp_gso_async_txq_stopped_backoff_sleeps;
static unsigned long trustix_route_tcp_gso_async_txq_stopped_backoff_yields;
static unsigned long trustix_route_tcp_gso_async_txq_stopped_backoff_recovered;
static unsigned long trustix_route_tcp_gso_async_txq_stopped_backoff_still_stopped;
static unsigned long trustix_route_tcp_gso_async_xmit_packets;
static unsigned long trustix_route_tcp_gso_async_xmit_errors;
static unsigned long trustix_route_tcp_gso_async_xmit_cn;
static unsigned long trustix_route_tcp_gso_async_xmit_more_sets;
static unsigned long trustix_route_tcp_gso_async_xmit_busy_retry_attempts;
static unsigned long trustix_route_tcp_gso_async_xmit_busy_retry_successes;
static unsigned long trustix_route_tcp_gso_async_xmit_busy_retry_failures;
static unsigned long trustix_route_tcp_gso_direct_xmit_attempts;
static unsigned long trustix_route_tcp_gso_direct_xmit_successes;
static unsigned long trustix_route_tcp_gso_direct_xmit_cn;
static unsigned long trustix_route_tcp_gso_direct_xmit_busy;
static unsigned long trustix_route_tcp_gso_direct_xmit_busy_fallbacks;
static unsigned long trustix_route_tcp_gso_direct_xmit_drops;
static unsigned long trustix_route_tcp_gso_direct_xmit_errors;
static unsigned long trustix_route_tcp_gso_direct_xmit_not_ready;
static unsigned long trustix_route_tcp_gso_async_stream_batches;
static unsigned long trustix_route_tcp_gso_async_stream_frames;
static unsigned long trustix_route_tcp_gso_async_stream_software_segments;
static unsigned long trustix_route_tcp_gso_async_stream_fallbacks;
static unsigned long trustix_route_tcp_gso_async_stream_errors;
static unsigned long trustix_route_tcp_gso_async_stream_xmit_errors;
static unsigned long trustix_route_tcp_gso_async_stream_direct_builds;
static unsigned long trustix_route_tcp_gso_async_stream_direct_frames;
static unsigned long trustix_route_tcp_gso_async_stream_direct_fallbacks;
static unsigned long trustix_route_tcp_gso_async_stream_direct_errors;
static unsigned long trustix_route_tcp_gso_async_stream_direct_fast_copy_hits;
static unsigned long trustix_route_tcp_gso_async_stream_direct_fast_copy_fallbacks;
static unsigned long trustix_route_tcp_gso_async_stream_direct_frag_fast_copy_hits;
static unsigned long trustix_route_tcp_gso_async_stream_direct_frag_fast_copy_fallbacks;
static unsigned long trustix_route_tcp_gso_async_stream_direct_frag_fast_copy_cross_page_hits;
static unsigned long trustix_route_tcp_gso_async_stream_direct_frag_fast_copy_cross_page;
static unsigned long trustix_route_tcp_gso_async_stream_direct_frag_fast_copy_misses;
static unsigned long trustix_route_tcp_gso_async_stream_nonlinear_direct_builds;
static unsigned long trustix_route_tcp_gso_async_stream_nonlinear_direct_frames;
static unsigned long trustix_route_tcp_gso_async_stream_nonlinear_direct_frags;
static unsigned long trustix_route_tcp_gso_async_stream_nonlinear_direct_bytes;
static unsigned long trustix_route_tcp_gso_async_stream_nonlinear_direct_fallbacks;
static unsigned long trustix_route_tcp_gso_async_stream_nonlinear_direct_errors;
static unsigned long trustix_route_tcp_gso_async_stream_outer_gso_batches;
static unsigned long trustix_route_tcp_gso_async_stream_outer_gso_frames;
static unsigned long trustix_route_tcp_gso_async_stream_outer_gso_fallbacks;
static unsigned long trustix_route_tcp_gso_async_stream_outer_gso_errors;
static unsigned long trustix_route_tcp_gso_async_stream_outer_gso_blocked;
static unsigned long trustix_route_tcp_gso_async_stream_outer_gso_virtio_blocked;
static unsigned long trustix_route_tcp_gso_async_stream_outer_gso_verify_errors;
static unsigned long trustix_route_tcp_gso_async_stream_cross_item_batches;
static unsigned long trustix_route_tcp_gso_async_stream_cross_item_items;
static unsigned long trustix_route_tcp_gso_async_stream_cross_item_frames;
static unsigned long trustix_route_tcp_gso_async_stream_cross_item_dequeue_batches;
static unsigned long trustix_route_tcp_gso_async_stream_cross_item_dequeue_items;
static unsigned long trustix_route_tcp_gso_async_stream_cross_item_fallbacks;
static unsigned long trustix_route_tcp_gso_async_stream_cross_item_errors;
static unsigned long trustix_route_tcp_gso_async_stream_cross_item_tail_stitch_batches;
static unsigned long trustix_route_tcp_gso_async_stream_cross_item_tail_stitch_items;
static unsigned long trustix_route_tcp_gso_async_stream_cross_item_tail_stitch_frames;
static unsigned long trustix_route_tcp_gso_async_stream_cross_item_tail_stitch_prefix_frames;
static unsigned long trustix_route_tcp_gso_async_stream_cross_item_tail_stitch_fallbacks;
static unsigned long trustix_route_tcp_gso_async_stream_cross_item_tail_stitch_errors;
static unsigned long trustix_route_tcp_gso_async_stream_cross_item_skip_disabled;
static unsigned long trustix_route_tcp_gso_async_stream_cross_item_skip_first_shape;
static unsigned long trustix_route_tcp_gso_async_stream_cross_item_skip_first_tail;
static unsigned long trustix_route_tcp_gso_async_stream_cross_item_skip_first_room;
static unsigned long trustix_route_tcp_gso_async_stream_cross_item_skip_no_next;
static unsigned long trustix_route_tcp_gso_async_stream_cross_item_skip_candidate_shape;
static unsigned long trustix_route_tcp_gso_async_stream_cross_item_skip_candidate_room;
static unsigned long trustix_route_tcp_gso_async_stream_cross_item_skip_candidate_sequence;
static unsigned long trustix_route_tcp_gso_async_stream_cross_item_skip_candidate_template;
static unsigned long trustix_route_tcp_gso_async_stream_cross_item_lookahead_hits;
static unsigned long trustix_route_tcp_gso_async_stream_cross_item_lookahead_misses;
static unsigned long trustix_route_tcp_gso_async_stream_cross_item_lookahead_scans;
static unsigned long trustix_route_tcp_gso_async_stream_cross_item_lookahead_blocked;
static unsigned long trustix_route_tcp_gso_async_stream_cross_item_dynamic_cap_high;
static unsigned long trustix_route_tcp_gso_async_stream_cross_item_dynamic_cap_low;
static int trustix_route_tcp_gso_async_stream_cross_item_last_ret;
static unsigned int trustix_route_tcp_gso_async_stream_cross_item_last_stage;
static unsigned int trustix_route_tcp_gso_async_stream_cross_item_last_items;
static unsigned int trustix_route_tcp_gso_async_stream_cross_item_last_frames;
static unsigned int trustix_route_tcp_gso_async_stream_cross_item_last_stream_payload_len;
static unsigned int trustix_route_tcp_gso_async_stream_cross_item_last_outer_gso_size;
static unsigned int trustix_route_tcp_gso_async_stream_cross_item_last_first_frame_len;
static unsigned int trustix_route_tcp_gso_async_stream_cross_item_last_last_frame_len;
static unsigned long trustix_route_tcp_gso_async_reslice_plans;
static unsigned long trustix_route_tcp_gso_sync_calls;
static unsigned long trustix_route_tcp_gso_sync_segments;
static unsigned long trustix_route_tcp_gso_sync_fallbacks;
static unsigned long trustix_route_tcp_gso_sync_errors;
static unsigned long trustix_route_tcp_gso_sync_xmit_errors;
static unsigned long trustix_route_tcp_gso_sync_async_redirects;
static unsigned long trustix_route_tcp_gso_sync_stream_attempts;
static unsigned long trustix_route_tcp_gso_sync_stream_batches;
static unsigned long trustix_route_tcp_gso_sync_stream_frames;
static unsigned long trustix_route_tcp_gso_sync_stream_fallbacks;
static unsigned long trustix_route_tcp_gso_sync_stream_errors;
static unsigned long trustix_route_tcp_gso_sync_stream_xmit_errors;
static unsigned long trustix_route_tcp_gso_sync_stream_build_errors;
static unsigned long trustix_route_tcp_gso_sync_stream_build_busy;
static unsigned long trustix_route_tcp_gso_sync_stream_build_nomem;
static unsigned long trustix_route_tcp_gso_sync_stream_build_unsupported;
static unsigned long trustix_route_tcp_gso_sync_stream_ready_errors;
static unsigned long trustix_route_tcp_gso_sync_stream_partial_xmits;
static unsigned long trustix_route_tcp_gso_direct_xmit_safe_fallbacks;
static unsigned long trustix_route_tcp_gso_async_prefer_sync_bypasses;
static unsigned long trustix_route_tcp_gso_async_hash_tx_queue_sets;
static unsigned long trustix_route_tcp_gso_async_hash_tx_queue_fallbacks;
static unsigned long trustix_route_tcp_gso_async_hash_tx_queue_q0;
static unsigned long trustix_route_tcp_gso_async_hash_tx_queue_q1;
static unsigned long trustix_route_tcp_gso_async_hash_tx_queue_q2;
static unsigned long trustix_route_tcp_gso_async_hash_tx_queue_q3;
static unsigned long trustix_route_tcp_gso_async_hash_tx_queue_q4;
static unsigned long trustix_route_tcp_gso_async_hash_tx_queue_q5;
static unsigned long trustix_route_tcp_gso_async_hash_tx_queue_q6;
static unsigned long trustix_route_tcp_gso_async_hash_tx_queue_q7;
static unsigned long trustix_route_tcp_gso_async_hash_tx_queue_other;
static unsigned int trustix_route_tcp_gso_async_last_gso_size;
static unsigned int trustix_route_tcp_gso_async_last_gso_segs;
static unsigned int trustix_route_tcp_gso_async_last_gso_type;
static unsigned int trustix_route_tcp_gso_async_last_skb_len;
static unsigned int trustix_route_tcp_gso_async_max_skb_len;
static unsigned int trustix_route_tcp_gso_async_max_headlen;
static unsigned int trustix_route_tcp_gso_async_last_segment_count;
static unsigned int trustix_route_tcp_gso_async_last_payload_len;
static unsigned int trustix_route_tcp_gso_async_last_max_wire_len;
static int trustix_route_tcp_gso_async_last_plan_ret;
static unsigned int trustix_route_tcp_gso_async_last_plan_mtu;
static unsigned int trustix_route_tcp_gso_async_last_plan_max_inner_len;
static unsigned int trustix_route_tcp_gso_async_last_plan_gso_payload_len;
static unsigned int trustix_route_tcp_gso_async_last_plan_resliced;
static int trustix_route_tcp_gso_async_stream_last_software_ret;
static int trustix_route_tcp_gso_async_stream_last_software_stage;
static unsigned int trustix_route_tcp_gso_async_stream_last_len;
static unsigned int trustix_route_tcp_gso_async_stream_last_headlen;
static unsigned int trustix_route_tcp_gso_async_stream_last_gso_size;
static unsigned int trustix_route_tcp_gso_async_stream_last_gso_segs;
static unsigned int trustix_route_tcp_gso_async_stream_last_gso_type;
static unsigned int trustix_route_tcp_gso_async_stream_last_offsets;
static int trustix_route_tcp_gso_sync_stream_last_ret;
static int trustix_route_tcp_gso_sync_stream_last_stage;
static unsigned int trustix_route_tcp_gso_sync_stream_last_batch_count;
static unsigned int trustix_route_tcp_gso_sync_stream_last_batch_frames;
static unsigned int trustix_route_tcp_gso_sync_stream_last_len;
static unsigned int trustix_route_tcp_gso_sync_stream_last_gso_size;
static unsigned int trustix_route_tcp_gso_sync_stream_last_gso_segs;
static unsigned int trustix_route_tcp_gso_sync_stream_last_gso_type;
static LIST_HEAD(trustix_route_tcp_gso_async_queue);
static DEFINE_SPINLOCK(trustix_route_tcp_gso_async_lock);
static bool trustix_route_tcp_gso_async_scheduled;
static unsigned int trustix_route_tcp_gso_async_depth_defers;
static bool trustix_route_tcp_gso_async_delay_pending;
static struct hrtimer trustix_route_tcp_gso_async_schedule_timer;
static struct workqueue_struct *trustix_route_tcp_gso_async_wq;
static struct kmem_cache *trustix_route_tcp_gso_async_work_cache;
static struct kmem_cache *trustix_route_tcp_gso_async_cross_item_cache;
static bool trustix_route_tcp_gso_async_quiescing;
static void trustix_route_tcp_gso_async_worker_fn(struct work_struct *work);
static void trustix_route_tcp_gso_async_shard_worker_fn(struct work_struct *work);
static enum hrtimer_restart
trustix_route_tcp_gso_async_schedule_timer_fn(struct hrtimer *timer);
static enum hrtimer_restart
trustix_route_tcp_gso_async_shard_schedule_timer_fn(struct hrtimer *timer);

static void trustix_hrtimer_setup(struct hrtimer *timer,
				  enum hrtimer_restart (*function)(struct hrtimer *),
				  clockid_t clock_id,
				  enum hrtimer_mode mode)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 17, 0)
	hrtimer_setup(timer, function, clock_id, mode);
#else
	hrtimer_init(timer, clock_id, mode);
	timer->function = function;
#endif
}
static DECLARE_DELAYED_WORK(trustix_route_tcp_gso_async_work,
			    trustix_route_tcp_gso_async_worker_fn);
static struct trustix_route_tcp_gso_async_queue_shard
	trustix_route_tcp_gso_async_shards[
		TRUSTIX_ROUTE_TCP_GSO_ASYNC_MAX_QUEUE_SHARDS];
static void trustix_tixt_rx_single_coalesce_flush_work(
				struct work_struct *work);
static void trustix_tixt_rx_stream_free_skb_list(struct sk_buff *head);
static void trustix_tixt_rx_single_coalesce_drop_all(void);
static struct trustix_tixt_rx_single_coalesce_slot
	trustix_tixt_rx_single_coalesce_slots[
		TRUSTIX_TIXT_RX_SINGLE_COALESCE_SLOTS];
static bool trustix_tixt_rx_single_coalesce_slots_ready;

static unsigned int trustix_route_tcp_xmit_worker_depth;
static unsigned long trustix_route_tcp_xmit_worker_enqueued;
static unsigned long trustix_route_tcp_xmit_worker_cloned;
static unsigned long trustix_route_tcp_xmit_worker_stolen;
static unsigned long trustix_route_tcp_xmit_worker_no_dev;
static unsigned long trustix_route_tcp_xmit_worker_queue_full;
static unsigned long trustix_route_tcp_xmit_worker_alloc_errors;
static unsigned long trustix_route_tcp_xmit_worker_header_errors;
static unsigned long trustix_route_tcp_xmit_worker_xmit_ok;
static unsigned long trustix_route_tcp_xmit_worker_xmit_errors;
static unsigned long trustix_route_tcp_xmit_worker_flush_drops;
static unsigned long trustix_route_tcp_xmit_worker_disabled;
static struct sk_buff_head trustix_route_tcp_xmit_worker_queue;
static bool trustix_route_tcp_xmit_worker_scheduled;
static void trustix_route_tcp_xmit_worker_fn(struct work_struct *work);
static void trustix_route_tcp_xmit_worker_flush(void);
static void trustix_route_tcp_gso_async_flush(void);
static DECLARE_WORK(trustix_route_tcp_xmit_work,
		    trustix_route_tcp_xmit_worker_fn);
static bool trustix_datapath_helpers_netdev_notifier_registered;

static unsigned long trustix_tixt_rx_stream_candidates;
static unsigned long trustix_tixt_rx_stream_disabled;
static unsigned long trustix_tixt_rx_stream_parse_errors;
static unsigned long trustix_tixt_rx_stream_frames;
static unsigned long trustix_tixt_rx_stream_xmit_packets;
static unsigned long trustix_tixt_rx_stream_xmit_errors;
static unsigned long trustix_tixt_rx_stream_gso_batches;
static unsigned long trustix_tixt_rx_stream_gso_frames;
static unsigned long trustix_tixt_rx_stream_gso_fallbacks;
static unsigned long trustix_tixt_rx_stream_gso_errors;
static unsigned long trustix_tixt_rx_stream_gso_xmit_errors;
static unsigned long trustix_tixt_rx_stream_coalesce_batches;
static unsigned long trustix_tixt_rx_stream_coalesce_frames;
static unsigned long trustix_tixt_rx_stream_coalesce_fallbacks;
static unsigned long trustix_tixt_rx_stream_coalesce_errors;
static unsigned long trustix_tixt_rx_stream_coalesce_xmit_errors;
static unsigned long trustix_tixt_rx_stream_ordered_list_batches;
static unsigned long trustix_tixt_rx_stream_ordered_list_frames;
static unsigned long trustix_tixt_rx_stream_ordered_list_errors;
static unsigned long trustix_tixt_rx_stream_backlog_packets;
static unsigned long trustix_tixt_rx_stream_backlog_drops;
static unsigned int trustix_tixt_rx_backlog_worker_depth;
static unsigned long trustix_tixt_rx_backlog_worker_enqueued;
static unsigned long trustix_tixt_rx_backlog_worker_delivered;
static unsigned long trustix_tixt_rx_backlog_worker_drops;
static unsigned long trustix_tixt_rx_backlog_worker_queue_full;
static unsigned long trustix_tixt_rx_backlog_worker_disabled;
static unsigned long trustix_tixt_rx_backlog_worker_runs;
static unsigned long trustix_tixt_rx_coalesce_segment_batches;
static unsigned long trustix_tixt_rx_coalesce_segment_frames;
static unsigned long trustix_tixt_rx_coalesce_segment_errors;
static unsigned long trustix_tixt_rx_coalesce_segment_backlog_packets;
static unsigned long trustix_tixt_rx_coalesce_segment_backlog_drops;
static unsigned long trustix_tixt_rx_coalesce_partial_csum_fallbacks;
static unsigned long trustix_tixt_rx_stream_nonlinear_parse_hits;
static unsigned long trustix_tixt_rx_single_coalesce_candidates;
static unsigned long trustix_tixt_rx_single_coalesce_batches;
static unsigned long trustix_tixt_rx_single_coalesce_frames;
static unsigned long trustix_tixt_rx_single_coalesce_flushes;
static unsigned long trustix_tixt_rx_single_coalesce_fallbacks;
static unsigned long trustix_tixt_rx_single_coalesce_errors;
static unsigned long trustix_tixt_rx_single_coalesce_xmit_errors;
static unsigned long trustix_tixt_rx_single_coalesce_collisions;
static unsigned long trustix_tixt_rx_single_coalesce_hash_misses;
static unsigned long trustix_tixt_rx_single_coalesce_seq_misses;
static unsigned long trustix_tixt_rx_single_coalesce_dev_misses;
static unsigned long trustix_tixt_rx_single_coalesce_flow_misses;
static unsigned long trustix_tixt_rx_single_coalesce_header_misses;
static unsigned long trustix_tixt_rx_single_coalesce_gso_size_misses;
static unsigned long trustix_tixt_rx_single_coalesce_ack_variations;
static unsigned long trustix_tixt_rx_single_coalesce_window_variations;
static unsigned long trustix_tixt_rx_single_coalesce_flags_variations;
static unsigned long trustix_tixt_rx_single_coalesce_tcp_csum_skipped;
static unsigned long trustix_tixt_rx_single_coalesce_tcp_csum_computed;
static unsigned long trustix_tixt_rx_single_coalesce_direct_list_batches;
static unsigned long trustix_tixt_rx_single_coalesce_direct_list_frames;
static unsigned long trustix_tixt_rx_single_coalesce_direct_list_errors;
static unsigned long trustix_tixt_rx_single_coalesce_direct_list_fallbacks;
static unsigned long trustix_tixt_rx_single_coalesce_nonlinear_batches;
static unsigned long trustix_tixt_rx_single_coalesce_nonlinear_frags;
static unsigned long trustix_tixt_rx_single_coalesce_nonlinear_errors;
static unsigned long trustix_tixt_rx_single_coalesce_page_transfer_batches;
static unsigned long trustix_tixt_rx_single_coalesce_page_transfer_pages;
static unsigned long trustix_tixt_rx_single_coalesce_page_transfer_bytes;
static unsigned long trustix_tixt_rx_single_coalesce_page_only_batches;
static unsigned long trustix_tixt_rx_single_coalesce_page_only_pages;
static unsigned long trustix_tixt_rx_single_coalesce_page_only_bytes;
static unsigned long trustix_tixt_rx_single_coalesce_page_only_errors;
static unsigned long trustix_tixt_rx_single_coalesce_linear_build_batches;
static unsigned long trustix_tixt_rx_single_coalesce_linear_build_bytes;
static unsigned long trustix_tixt_rx_single_coalesce_linear_build_fallbacks;
static unsigned long trustix_tixt_rx_single_coalesce_linear_build_errors;
static unsigned long trustix_tixt_rx_single_coalesce_linear_max_bytes;
static unsigned long trustix_tixt_rx_single_coalesce_hybrid_head_batches;
static unsigned long trustix_tixt_rx_single_coalesce_hybrid_head_bytes;
static unsigned long trustix_tixt_rx_single_coalesce_netif_rx_packets;
static unsigned long trustix_tixt_rx_single_coalesce_netif_rx_drops;
static unsigned long trustix_tixt_rx_single_coalesce_schedules;
static unsigned long trustix_tixt_rx_single_coalesce_schedule_skips;
static unsigned long trustix_tixt_rx_single_coalesce_warmup_passes;
static unsigned long trustix_tixt_rx_single_coalesce_stream_fallbacks;
static unsigned long trustix_tixt_rx_single_coalesce_stream_fallback_frames;
static unsigned long trustix_tixt_rx_single_coalesce_defer_full_flushes;
static unsigned long trustix_tixt_rx_single_coalesce_full_cancel_skips;
static unsigned long trustix_tixt_rx_single_coalesce_hash_sets;
static unsigned long trustix_tixt_rx_single_coalesce_parse_bad_outer;
static unsigned long trustix_tixt_rx_single_coalesce_parse_short;
static unsigned long trustix_tixt_rx_single_coalesce_parse_bad_len;
static unsigned long trustix_tixt_rx_single_coalesce_parse_not_tcp;
static unsigned long trustix_tixt_rx_single_coalesce_parse_fragment;
static unsigned long trustix_tixt_rx_single_coalesce_parse_totlen_mismatch;
static unsigned long trustix_tixt_rx_single_coalesce_parse_bad_tcp;
static unsigned long trustix_tixt_rx_single_coalesce_parse_tcp_flags;
static unsigned long trustix_tixt_rx_single_coalesce_parse_no_payload;
static unsigned int trustix_tixt_rx_single_coalesce_last_inner_proto;
static unsigned int trustix_tixt_rx_single_coalesce_last_inner_len;
static unsigned int trustix_tixt_rx_single_coalesce_last_inner_tot_len;
static unsigned int trustix_tixt_rx_single_coalesce_last_payload_len;
static unsigned int trustix_tixt_rx_single_coalesce_last_tcp_header_len;
static struct sk_buff_head trustix_tixt_rx_backlog_worker_queue;
static bool trustix_tixt_rx_backlog_worker_scheduled;
static bool trustix_tixt_rx_backlog_worker_quiescing = true;
static void trustix_tixt_rx_backlog_worker_fn(struct work_struct *work);
static void trustix_tixt_rx_backlog_worker_flush(void);
static DECLARE_WORK(trustix_tixt_rx_backlog_work,
		    trustix_tixt_rx_backlog_worker_fn);
static unsigned long trustix_kudp_rx_parse_calls;
static unsigned long trustix_kudp_rx_parse_udp_calls;
static unsigned long trustix_kudp_rx_parse_tcp_calls;
static unsigned long trustix_kudp_rx_parse_gso_packets;
static unsigned long trustix_kudp_rx_parse_gso_segs;
static unsigned long trustix_kudp_rx_parse_udp_gso_fraglist;
static unsigned long trustix_kudp_rx_parse_len_bytes;
static unsigned long trustix_kudp_rx_parse_headlen_bytes;
static unsigned long trustix_kudp_rx_parse_nonlinear_packets;
static unsigned long trustix_kudp_rx_parse_ret_einval;
static unsigned long trustix_kudp_rx_parse_ret_emsgsize;
static unsigned long trustix_kudp_rx_parse_ret_ebadmsg;
static unsigned long trustix_kudp_rx_parse_ret_enodata;
static unsigned long trustix_kudp_rx_parse_ret_eacces;
static unsigned long trustix_kudp_rx_parse_ret_eproto;
static unsigned long trustix_kudp_rx_parse_ret_eprotonosupport;
static unsigned long trustix_kudp_rx_parse_ret_enodev;
static unsigned long trustix_kudp_rx_parse_ret_enomem;
static unsigned long trustix_kudp_rx_parse_ret_other;
static unsigned long trustix_kudp_rx_decap_calls;
static unsigned long trustix_kudp_rx_decap_gso_packets;
static unsigned long trustix_kudp_rx_decap_gso_preserved;
static unsigned long trustix_kudp_rx_decap_gso_reset;
static unsigned long trustix_kudp_rx_decap_len_bytes;
static unsigned long trustix_kudp_rx_decap_ret_einval;
static unsigned long trustix_kudp_rx_decap_ret_emsgsize;
static unsigned long trustix_kudp_rx_decap_ret_ebadmsg;
static unsigned long trustix_kudp_rx_decap_ret_enodata;
static unsigned long trustix_kudp_rx_decap_ret_eacces;
static unsigned long trustix_kudp_rx_decap_ret_eproto;
static unsigned long trustix_kudp_rx_decap_ret_eprotonosupport;
static unsigned long trustix_kudp_rx_decap_ret_enodev;
static unsigned long trustix_kudp_rx_decap_ret_enomem;
static unsigned long trustix_kudp_rx_decap_ret_other;
static unsigned int trustix_kudp_rx_last_gso_size;
static unsigned int trustix_kudp_rx_last_gso_segs;
static unsigned int trustix_kudp_rx_last_gso_type;
static unsigned int trustix_kudp_rx_last_skb_len;
static unsigned int trustix_kudp_rx_max_skb_len;
static unsigned int trustix_kudp_rx_max_headlen;

static int trustix_tixt_rx_single_coalesce_gso_set(
				const char *val,
				const struct kernel_param *kp)
{
	bool enabled;
	int ret;

	ret = kstrtobool(val, &enabled);
	if (ret)
		return ret;
	if (READ_ONCE(trustix_tixt_rx_single_coalesce_slots_ready))
		trustix_tixt_rx_single_coalesce_drop_all();
	WRITE_ONCE(trustix_tixt_rx_single_coalesce_gso, enabled);
	return 0;
}

static int trustix_tixt_rx_single_coalesce_gso_get(
				char *buf,
				const struct kernel_param *kp)
{
	return sysfs_emit(buf, "%c\n",
			  READ_ONCE(trustix_tixt_rx_single_coalesce_gso) ?
			  'Y' : 'N');
}

static const struct kernel_param_ops trustix_tixt_rx_single_coalesce_gso_ops = {
	.set = trustix_tixt_rx_single_coalesce_gso_set,
	.get = trustix_tixt_rx_single_coalesce_gso_get,
};

static int trustix_tixt_rx_single_coalesce_linear_max_set(
				const char *val,
				const struct kernel_param *kp)
{
	unsigned int value;
	int ret;

	ret = kstrtouint(val, 0, &value);
	if (ret)
		return ret;
	if (READ_ONCE(trustix_tixt_rx_single_coalesce_slots_ready))
		trustix_tixt_rx_single_coalesce_drop_all();
	WRITE_ONCE(trustix_tixt_rx_single_coalesce_linear_max, value);
	return 0;
}

static int trustix_tixt_rx_single_coalesce_linear_max_get(
				char *buf,
				const struct kernel_param *kp)
{
	return sysfs_emit(buf, "%u\n",
			  READ_ONCE(trustix_tixt_rx_single_coalesce_linear_max));
}

static const struct kernel_param_ops trustix_tixt_rx_single_coalesce_linear_max_ops = {
	.set = trustix_tixt_rx_single_coalesce_linear_max_set,
	.get = trustix_tixt_rx_single_coalesce_linear_max_get,
};

static bool trustix_route_tcp_gso_async_param_quiesce_begin(void)
{
	if (!READ_ONCE(trustix_datapath_helpers_registered))
		return false;
	WRITE_ONCE(trustix_route_tcp_gso_async_quiescing, true);
	smp_mb();
	trustix_route_tcp_gso_async_flush();
	return true;
}

static void trustix_route_tcp_gso_async_param_quiesce_end(bool quiesced)
{
	if (!quiesced)
		return;
	trustix_route_tcp_gso_async_flush();
	smp_mb();
	WRITE_ONCE(trustix_route_tcp_gso_async_quiescing, false);
}

static int trustix_route_tcp_gso_quiesced_bool_set(const char *val,
						   const struct kernel_param *kp)
{
	bool value;
	bool quiesced;
	int ret;

	if (!kp || !kp->arg)
		return -EINVAL;
	ret = kstrtobool(val, &value);
	if (ret)
		return ret;
	quiesced = trustix_route_tcp_gso_async_param_quiesce_begin();
	WRITE_ONCE(*(bool *)kp->arg, value);
	trustix_route_tcp_gso_async_param_quiesce_end(quiesced);
	return 0;
}

static const struct kernel_param_ops trustix_route_tcp_gso_quiesced_bool_ops = {
	.set = trustix_route_tcp_gso_quiesced_bool_set,
	.get = param_get_bool,
};

static int trustix_route_tcp_xmit_worker_bool_set(const char *val,
						  const struct kernel_param *kp)
{
	bool value;
	int ret;

	if (!kp || !kp->arg)
		return -EINVAL;
	ret = kstrtobool(val, &value);
	if (ret)
		return ret;
	WRITE_ONCE(*(bool *)kp->arg, value);
	if (READ_ONCE(trustix_datapath_helpers_registered))
		trustix_route_tcp_xmit_worker_flush();
	return 0;
}

static const struct kernel_param_ops trustix_route_tcp_xmit_worker_bool_ops = {
	.set = trustix_route_tcp_xmit_worker_bool_set,
	.get = param_get_bool,
};

static int trustix_route_tcp_gso_quiesced_uint_set(const char *val,
						   const struct kernel_param *kp)
{
	unsigned int value;
	bool quiesced;
	int ret;

	if (!kp || !kp->arg)
		return -EINVAL;
	ret = kstrtouint(val, 0, &value);
	if (ret)
		return ret;
	quiesced = trustix_route_tcp_gso_async_param_quiesce_begin();
	WRITE_ONCE(*(unsigned int *)kp->arg, value);
	trustix_route_tcp_gso_async_param_quiesce_end(quiesced);
	return 0;
}

static const struct kernel_param_ops trustix_route_tcp_gso_quiesced_uint_ops = {
	.set = trustix_route_tcp_gso_quiesced_uint_set,
	.get = param_get_uint,
};

static int trustix_route_tcp_gso_quiesced_ulong_set(const char *val,
						    const struct kernel_param *kp)
{
	unsigned long value;
	bool quiesced;
	int ret;

	if (!kp || !kp->arg)
		return -EINVAL;
	ret = kstrtoul(val, 0, &value);
	if (ret)
		return ret;
	quiesced = trustix_route_tcp_gso_async_param_quiesce_begin();
	WRITE_ONCE(*(unsigned long *)kp->arg, value);
	trustix_route_tcp_gso_async_param_quiesce_end(quiesced);
	return 0;
}

static const struct kernel_param_ops trustix_route_tcp_gso_quiesced_ulong_ops = {
	.set = trustix_route_tcp_gso_quiesced_ulong_set,
	.get = param_get_ulong,
};

module_param_named(tixt_tx_plain_skip_sequence,
		   trustix_tixt_tx_plain_skip_sequence, bool, 0644);
MODULE_PARM_DESC(tixt_tx_plain_skip_sequence,
		 "Write zero TIXT sequence numbers in plaintext TX helper paths");

module_param_named(tixt_tx_plain_ack_only,
		   trustix_tixt_tx_plain_ack_only, bool, 0644);
MODULE_PARM_DESC(tixt_tx_plain_ack_only,
		 "Emit ACK-only outer TCP flags instead of PSH+ACK in plaintext TIXT TX helpers");

module_param_cb(route_tcp_gso, &trustix_route_tcp_gso_quiesced_bool_ops,
		&trustix_route_tcp_gso, 0644);
MODULE_PARM_DESC(route_tcp_gso,
		 "Enable experimental route-TCP GSO worker path; off by default");

module_param_named(route_tcp_gso_sync_stream,
		   trustix_route_tcp_gso_sync_stream, bool, 0644);
MODULE_PARM_DESC(route_tcp_gso_sync_stream,
		 "Request copied TIXT stream batching for route-TCP GSO; kfunc callers are redirected to the async worker before segmentation/xmit");

module_param_named(route_tcp_gso_sync_stream_outer_gso,
		   trustix_route_tcp_gso_sync_stream_outer_gso, bool, 0644);
MODULE_PARM_DESC(route_tcp_gso_sync_stream_outer_gso,
		 "Allow synchronous route-TCP stream batches to use outer TCP GSO when the underlay device supports TSO/HW checksum");

module_param_named(route_tcp_gso_sync_stream_max_frames,
		   trustix_route_tcp_gso_sync_stream_max_frames, uint, 0644);
MODULE_PARM_DESC(route_tcp_gso_sync_stream_max_frames,
		 "Maximum TIXT frames copied into one synchronous route-TCP stream batch; clamped to 1..16");

module_param_cb(route_tcp_gso_async, &trustix_route_tcp_gso_quiesced_bool_ops,
		&trustix_route_tcp_gso_async, 0644);
MODULE_PARM_DESC(route_tcp_gso_async,
		 "Clone route-TCP GSO skbs in TC context and segment/transmit from a worker; off by default");

module_param_cb(route_tcp_gso_async_dev_xmit,
		&trustix_route_tcp_gso_quiesced_bool_ops,
		&trustix_route_tcp_gso_async_dev_xmit, 0644);
MODULE_PARM_DESC(route_tcp_gso_async_dev_xmit,
		 "Final gate for route-TCP GSO async dev_queue_xmit from worker context");

module_param_cb(route_tcp_gso_async_prefer,
		&trustix_route_tcp_gso_quiesced_bool_ops,
		&trustix_route_tcp_gso_async_prefer, 0644);
MODULE_PARM_DESC(route_tcp_gso_async_prefer,
		 "Prefer route-TCP GSO async worker before the synchronous stream path; off by default because some virtio_net/public-host combinations reboot under async outer-GSO stress");

module_param_cb(route_tcp_gso_async_limit,
		&trustix_route_tcp_gso_quiesced_uint_ops,
		&trustix_route_tcp_gso_async_limit, 0644);
MODULE_PARM_DESC(route_tcp_gso_async_limit,
		 "Maximum route-TCP GSO async work items in flight; 0 disables the limit");

module_param_cb(route_tcp_gso_async_bytes_limit,
		&trustix_route_tcp_gso_quiesced_ulong_ops,
		&trustix_route_tcp_gso_async_bytes_limit, 0644);
MODULE_PARM_DESC(route_tcp_gso_async_bytes_limit,
		 "Maximum cloned route-TCP GSO async skb bytes in flight; 0 disables the limit");

module_param_cb(route_tcp_gso_async_worker_item_budget,
		&trustix_route_tcp_gso_quiesced_uint_ops,
		&trustix_route_tcp_gso_async_worker_item_budget, 0644);
MODULE_PARM_DESC(route_tcp_gso_async_worker_item_budget,
		 "Maximum route-TCP GSO async items processed by one worker pass; 0 disables the budget");

module_param_cb(route_tcp_gso_async_worker_segment_budget,
		&trustix_route_tcp_gso_quiesced_uint_ops,
		&trustix_route_tcp_gso_async_worker_segment_budget, 0644);
MODULE_PARM_DESC(route_tcp_gso_async_worker_segment_budget,
		 "Maximum route-TCP GSO async segments transmitted by one worker pass; 0 disables the budget");

module_param_cb(route_tcp_gso_async_worker_emit_budget,
		&trustix_route_tcp_gso_quiesced_uint_ops,
		&trustix_route_tcp_gso_async_worker_emit_budget, 0644);
MODULE_PARM_DESC(route_tcp_gso_async_worker_emit_budget,
		 "Maximum route-TCP GSO async output batches emitted by one worker pass; 0 disables the budget");

module_param_cb(route_tcp_gso_async_worker_resched_stride,
		&trustix_route_tcp_gso_quiesced_uint_ops,
		&trustix_route_tcp_gso_async_worker_resched_stride, 0644);
MODULE_PARM_DESC(route_tcp_gso_async_worker_resched_stride,
		 "Call cond_resched every N route-TCP GSO async work items; 0 disables voluntary reschedule in the worker");

module_param_cb(route_tcp_gso_async_worker_dequeue_batch,
		&trustix_route_tcp_gso_quiesced_uint_ops,
		&trustix_route_tcp_gso_async_worker_dequeue_batch, 0644);
MODULE_PARM_DESC(route_tcp_gso_async_worker_dequeue_batch,
		 "Experimentally move up to N route-TCP GSO async work items to a worker-local list per queue lock; 1 disables local batching");

module_param_cb(route_tcp_gso_async_worker_min_queue_depth,
		&trustix_route_tcp_gso_quiesced_uint_ops,
		&trustix_route_tcp_gso_async_worker_min_queue_depth, 0644);
MODULE_PARM_DESC(route_tcp_gso_async_worker_min_queue_depth,
		 "Experimentally defer a route-TCP GSO async worker pass until the shard queue reaches this depth; 0 disables");

module_param_cb(route_tcp_gso_async_worker_max_depth_defers,
		&trustix_route_tcp_gso_quiesced_uint_ops,
		&trustix_route_tcp_gso_async_worker_max_depth_defers, 0644);
MODULE_PARM_DESC(route_tcp_gso_async_worker_max_depth_defers,
		 "Maximum consecutive route-TCP GSO async worker depth defers before draining anyway");

module_param_cb(route_tcp_gso_async_worker_schedule_delay_jiffies,
		&trustix_route_tcp_gso_quiesced_uint_ops,
		&trustix_route_tcp_gso_async_worker_schedule_delay_jiffies,
		0644);
MODULE_PARM_DESC(route_tcp_gso_async_worker_schedule_delay_jiffies,
		 "Delay the first route-TCP GSO async worker drain by this many jiffies so adjacent shard items can batch; 0 disables");

module_param_cb(route_tcp_gso_async_worker_schedule_delay_usecs,
		&trustix_route_tcp_gso_quiesced_uint_ops,
		&trustix_route_tcp_gso_async_worker_schedule_delay_usecs,
		0644);
MODULE_PARM_DESC(route_tcp_gso_async_worker_schedule_delay_usecs,
		 "Delay the first route-TCP GSO async worker drain by this many microseconds using an hrtimer; clamped to 20ms and ignored when jiffies delay is nonzero");

module_param_cb(route_tcp_gso_async_worker_schedule_delay_no_accel,
		&trustix_route_tcp_gso_quiesced_bool_ops,
		&trustix_route_tcp_gso_async_worker_schedule_delay_no_accel,
		0644);
MODULE_PARM_DESC(route_tcp_gso_async_worker_schedule_delay_no_accel,
		 "Keep delayed route-TCP GSO async worker drains delayed even after the shard reaches the schedule depth");

module_param_cb(route_tcp_gso_async_worker_budget_reschedule_delay_jiffies,
		&trustix_route_tcp_gso_quiesced_uint_ops,
		&trustix_route_tcp_gso_async_worker_budget_reschedule_delay_jiffies,
		0644);
MODULE_PARM_DESC(route_tcp_gso_async_worker_budget_reschedule_delay_jiffies,
		 "Delay route-TCP GSO async worker reschedule after a budget yield by this many jiffies; 0 disables pacing");

module_param_cb(route_tcp_gso_async_worker_budget_reschedule_delay_usecs,
		&trustix_route_tcp_gso_quiesced_uint_ops,
		&trustix_route_tcp_gso_async_worker_budget_reschedule_delay_usecs,
		0644);
MODULE_PARM_DESC(route_tcp_gso_async_worker_budget_reschedule_delay_usecs,
		 "Sleep this many microseconds before immediate route-TCP GSO async worker reschedule after a budget yield; clamped to 20ms and ignored when jiffies delay is nonzero");

module_param_named(route_tcp_gso_async_hot_stats,
		   trustix_route_tcp_gso_async_hot_stats, bool, 0644);
MODULE_PARM_DESC(route_tcp_gso_async_hot_stats,
		 "Collect detailed per-frame route-TCP GSO async counters; off by default for throughput runs");

module_param_cb(route_tcp_gso_async_max_segments_per_item,
		&trustix_route_tcp_gso_quiesced_uint_ops,
		&trustix_route_tcp_gso_async_max_segments_per_item, 0644);
MODULE_PARM_DESC(route_tcp_gso_async_max_segments_per_item,
		 "Maximum route-TCP GSO async segments accepted from one skb; 0 disables the guard");

module_param_cb(route_tcp_gso_async_force_software_outer_csum,
		&trustix_route_tcp_gso_quiesced_bool_ops,
		&trustix_route_tcp_gso_async_force_software_outer_csum, 0644);
MODULE_PARM_DESC(route_tcp_gso_async_force_software_outer_csum,
		 "Force route-TCP GSO async segments to carry complete outer TCP checksums");

module_param_cb(route_tcp_gso_async_force_inner_checksum,
		&trustix_route_tcp_gso_quiesced_bool_ops,
		&trustix_route_tcp_gso_async_force_inner_checksum, 0644);
MODULE_PARM_DESC(route_tcp_gso_async_force_inner_checksum,
		 "Force route-TCP GSO async to complete inner TCP checksums before encapsulation");

module_param_cb(route_tcp_gso_async_direct_xmit,
		&trustix_route_tcp_gso_quiesced_bool_ops,
		&trustix_route_tcp_gso_async_direct_xmit, 0644);
MODULE_PARM_DESC(route_tcp_gso_async_direct_xmit,
		 "Request route-TCP GSO direct xmit; current safe implementation records the request and uses validated dev_queue_xmit instead of panic-prone dev_direct_xmit");
module_param_cb(route_tcp_gso_unsafe_xmit,
		&trustix_route_tcp_gso_quiesced_bool_ops,
		&trustix_route_tcp_gso_async_direct_xmit, 0644);
MODULE_PARM_DESC(route_tcp_gso_unsafe_xmit,
		 "Legacy alias for route_tcp_gso_async_direct_xmit; kept for old test profiles, implemented as safe dev_queue_xmit");
module_param_cb(route_tcp_unsafe_xmit_hard_enable,
		&trustix_route_tcp_gso_quiesced_bool_ops,
		&trustix_route_tcp_gso_async_direct_xmit, 0644);
MODULE_PARM_DESC(route_tcp_unsafe_xmit_hard_enable,
		 "Legacy route-TCP unsafe-xmit gate; accepted as a safe direct-xmit request without dev_direct_xmit");

module_param_named(route_tcp_gso_async_xmit_more,
		   trustix_route_tcp_gso_async_xmit_more, bool, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_xmit_more,
		 "Set skb xmit_more on consecutive route-TCP GSO async dev_queue_xmit packets; experimental and off by default");

module_param_named(route_tcp_gso_async_yield_on_xmit_cn,
		   trustix_route_tcp_gso_async_yield_on_xmit_cn, bool, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_yield_on_xmit_cn,
		 "Call cond_resched after route-TCP GSO async dev_queue_xmit reports NET_XMIT_CN; experimental and off by default");

module_param_cb(route_tcp_gso_async_xmit_cn_sleep_usecs,
		&trustix_route_tcp_gso_quiesced_uint_ops,
		&trustix_route_tcp_gso_async_xmit_cn_sleep_usecs, 0644);
MODULE_PARM_DESC(route_tcp_gso_async_xmit_cn_sleep_usecs,
		 "Sleep this many microseconds after NET_XMIT_CN in the route-TCP GSO async worker; 0 disables and values are clamped to 20000us");

module_param_cb(route_tcp_gso_async_xmit_busy_retries,
		&trustix_route_tcp_gso_quiesced_uint_ops,
		&trustix_route_tcp_gso_async_xmit_busy_retries, 0644);
MODULE_PARM_DESC(route_tcp_gso_async_xmit_busy_retries,
		 "Retry route-TCP GSO async xmit readiness this many times when the TX queue is transiently busy; values are clamped to 16");

module_param_cb(route_tcp_gso_async_xmit_busy_sleep_usecs,
		&trustix_route_tcp_gso_quiesced_uint_ops,
		&trustix_route_tcp_gso_async_xmit_busy_sleep_usecs, 0644);
MODULE_PARM_DESC(route_tcp_gso_async_xmit_busy_sleep_usecs,
		 "Sleep this many microseconds between route-TCP GSO async TX-busy retries; 0 yields only and values are clamped to 20000us");

module_param_cb(route_tcp_gso_async_ordered_queue,
		&trustix_route_tcp_gso_quiesced_bool_ops,
		&trustix_route_tcp_gso_async_ordered_queue, 0644);
MODULE_PARM_DESC(route_tcp_gso_async_ordered_queue,
		 "Preserve route-TCP GSO async queue ordering; single worker in this module keeps order regardless");

module_param_cb(route_tcp_gso_async_unbound_worker,
		&trustix_route_tcp_gso_quiesced_bool_ops,
		&trustix_route_tcp_gso_async_unbound_worker, 0644);
MODULE_PARM_DESC(route_tcp_gso_async_unbound_worker,
		 "Queue route-TCP GSO async workers on a dedicated unbound high-priority workqueue; off uses system workqueue");

module_param_cb(route_tcp_gso_async_sharded_queue,
		&trustix_route_tcp_gso_quiesced_bool_ops,
		&trustix_route_tcp_gso_async_sharded_queue, 0644);
MODULE_PARM_DESC(route_tcp_gso_async_sharded_queue,
		 "Shard route-TCP GSO async work across multiple worker items by inner-flow hash; off by default");

module_param_cb(route_tcp_gso_async_queue_shards,
		&trustix_route_tcp_gso_quiesced_uint_ops,
		&trustix_route_tcp_gso_async_queue_shards, 0644);
MODULE_PARM_DESC(route_tcp_gso_async_queue_shards,
		 "Number of route-TCP GSO async worker shards when sharding is enabled; clamped to 1..8");

module_param_cb(route_tcp_gso_async_flow_shard_queue,
		&trustix_route_tcp_gso_quiesced_bool_ops,
		&trustix_route_tcp_gso_async_flow_shard_queue, 0644);
MODULE_PARM_DESC(route_tcp_gso_async_flow_shard_queue,
		 "Experimentally shard route-TCP GSO async work by selected outer flow id instead of inner-flow hash");

module_param_cb(route_tcp_gso_async_stream,
		&trustix_route_tcp_gso_quiesced_bool_ops,
		&trustix_route_tcp_gso_async_stream, 0644);
MODULE_PARM_DESC(route_tcp_gso_async_stream,
		 "Enable conservative route-TCP async TIXT stream batching");

module_param_cb(route_tcp_gso_async_stream_direct_build,
		&trustix_route_tcp_gso_quiesced_bool_ops,
		&trustix_route_tcp_gso_async_stream_direct_build, 0644);
MODULE_PARM_DESC(route_tcp_gso_async_stream_direct_build,
		 "Enable direct-build route-TCP stream batching before worker xmit");

module_param_cb(route_tcp_gso_async_stream_direct_build_inner_csum,
		&trustix_route_tcp_gso_quiesced_bool_ops,
		&trustix_route_tcp_gso_async_stream_direct_build_inner_csum,
		0644);
MODULE_PARM_DESC(route_tcp_gso_async_stream_direct_build_inner_csum,
		 "Reserved direct-build stream inner checksum switch");

module_param_cb(route_tcp_gso_async_stream_direct_build_fast_copy,
		&trustix_route_tcp_gso_quiesced_bool_ops,
		&trustix_route_tcp_gso_async_stream_direct_build_fast_copy,
		0644);
MODULE_PARM_DESC(route_tcp_gso_async_stream_direct_build_fast_copy,
		 "Use direct memcpy/csum from linear inner skb payloads while direct-building route-TCP stream packets");

module_param_cb(route_tcp_gso_async_stream_direct_build_frag_fast_copy,
		&trustix_route_tcp_gso_quiesced_bool_ops,
		&trustix_route_tcp_gso_async_stream_direct_build_frag_fast_copy,
		0644);
MODULE_PARM_DESC(route_tcp_gso_async_stream_direct_build_frag_fast_copy,
		 "Use direct kmap memcpy/csum from single-page skb frags while direct-building route-TCP stream packets");

module_param_named(route_tcp_gso_async_stream_direct_build_frag_fast_copy_cross_page,
		   trustix_route_tcp_gso_async_stream_direct_build_frag_fast_copy_cross_page,
		   bool, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_stream_direct_build_frag_fast_copy_cross_page,
		 "Experimentally allow direct route-TCP stream frag fast-copy to span page boundaries");

module_param_named(route_tcp_gso_async_stream_nonlinear_direct_build,
		   trustix_route_tcp_gso_async_stream_nonlinear_direct_build,
		   bool, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_stream_nonlinear_direct_build,
		 "Build route-TCP direct stream batches with a small linear head and page frags; experimental and off by default");

module_param_cb(route_tcp_gso_async_stream_software_segment,
		&trustix_route_tcp_gso_quiesced_bool_ops,
		&trustix_route_tcp_gso_async_stream_software_segment, 0644);
MODULE_PARM_DESC(route_tcp_gso_async_stream_software_segment,
		 "Build MTU-sized multi-frame TIXT stream packets after software GSO segmentation");

module_param_cb(route_tcp_gso_async_stream_max_frames,
		&trustix_route_tcp_gso_quiesced_uint_ops,
		&trustix_route_tcp_gso_async_stream_max_frames, 0644);
MODULE_PARM_DESC(route_tcp_gso_async_stream_max_frames,
		 "Maximum TIXT frames packed into one route-TCP async stream packet");

module_param_cb(route_tcp_gso_async_stream_allow_virtio_net,
		&trustix_route_tcp_gso_quiesced_bool_ops,
		&trustix_route_tcp_gso_async_stream_allow_virtio_net, 0644);
MODULE_PARM_DESC(route_tcp_gso_async_stream_allow_virtio_net,
		 "Allow route-TCP outer GSO to remain offloaded on virtio_net; "
		 "disabled by default to avoid unstable receive-side skb shapes");

module_param_cb(route_tcp_gso_async_stream_outer_gso,
		&trustix_route_tcp_gso_quiesced_bool_ops,
		&trustix_route_tcp_gso_async_stream_outer_gso, 0644);
MODULE_PARM_DESC(route_tcp_gso_async_stream_outer_gso,
		 "Build route-TCP stream batches as outer TCP GSO skbs aligned to TIXT frame boundaries");

module_param_cb(route_tcp_gso_async_stream_outer_gso_hard_enable,
		&trustix_route_tcp_gso_quiesced_bool_ops,
		&trustix_route_tcp_gso_async_stream_outer_gso_hard_enable,
		0644);
MODULE_PARM_DESC(route_tcp_gso_async_stream_outer_gso_hard_enable,
		 "Deprecated compatibility knob; route-TCP outer GSO is now gated by device feature checks and skb validation");

module_param_cb(route_tcp_gso_async_secure_seal_batch,
		&trustix_route_tcp_gso_quiesced_bool_ops,
		&trustix_route_tcp_gso_async_secure_seal_batch, 0644);
MODULE_PARM_DESC(route_tcp_gso_async_secure_seal_batch,
		 "Seal multiple secure route-TCP GSO frames under one crypto batch call; off by default to avoid occasional bad AEAD tags on some kernels/CPUs");

module_param_cb(route_tcp_gso_async_stream_cross_item_batch,
		&trustix_route_tcp_gso_quiesced_bool_ops,
		&trustix_route_tcp_gso_async_stream_cross_item_batch, 0644);
MODULE_PARM_DESC(route_tcp_gso_async_stream_cross_item_batch,
		 "Experimentally merge consecutive route-TCP async direct-build work items into larger outer TCP GSO skbs");

module_param_cb(route_tcp_gso_async_stream_cross_item_dequeue_batch,
		&trustix_route_tcp_gso_quiesced_bool_ops,
		&trustix_route_tcp_gso_async_stream_cross_item_dequeue_batch,
		0644);
MODULE_PARM_DESC(route_tcp_gso_async_stream_cross_item_dequeue_batch,
		 "Experimentally batch-dequeue route-TCP async cross-item candidates under one queue lock");

module_param_named(route_tcp_gso_async_stream_cross_item_tail_stitch,
		   trustix_route_tcp_gso_async_stream_cross_item_tail_stitch,
		   bool, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_stream_cross_item_tail_stitch,
		 "Experimentally split a route-TCP async direct-build prefix and stitch its tail with adjacent items");

module_param_cb(route_tcp_gso_async_stream_cross_item_debug,
		&trustix_route_tcp_gso_quiesced_bool_ops,
		&trustix_route_tcp_gso_async_stream_cross_item_debug, 0644);
MODULE_PARM_DESC(route_tcp_gso_async_stream_cross_item_debug,
		 "Collect route-TCP async cross-item batch miss reason counters");

module_param_cb(route_tcp_gso_async_stream_cross_item_max_frames,
		&trustix_route_tcp_gso_quiesced_uint_ops,
		&trustix_route_tcp_gso_async_stream_cross_item_max_frames,
		0644);
MODULE_PARM_DESC(route_tcp_gso_async_stream_cross_item_max_frames,
		 "Maximum TIXT frames packed into one route-TCP async cross-item outer-GSO packet; 0 follows route_tcp_gso_async_stream_max_frames");

module_param_cb(route_tcp_gso_async_stream_cross_item_lookahead,
		&trustix_route_tcp_gso_quiesced_uint_ops,
		&trustix_route_tcp_gso_async_stream_cross_item_lookahead,
		0644);
MODULE_PARM_DESC(route_tcp_gso_async_stream_cross_item_lookahead,
		 "Experimentally scan a bounded number of queued route-TCP async items for cross-item batch candidates without reordering same-flow sequence");

module_param_cb(route_tcp_gso_async_stream_cross_item_dynamic_cap,
		&trustix_route_tcp_gso_quiesced_bool_ops,
		&trustix_route_tcp_gso_async_stream_cross_item_dynamic_cap,
		0644);
MODULE_PARM_DESC(route_tcp_gso_async_stream_cross_item_dynamic_cap,
		 "Experimentally lower the route-TCP async cross-item outer-GSO frame cap until the candidate queue reaches route_tcp_gso_async_stream_cross_item_dynamic_queue_depth");

module_param_cb(route_tcp_gso_async_stream_cross_item_dynamic_low_frames,
		&trustix_route_tcp_gso_quiesced_uint_ops,
		&trustix_route_tcp_gso_async_stream_cross_item_dynamic_low_frames,
		0644);
MODULE_PARM_DESC(route_tcp_gso_async_stream_cross_item_dynamic_low_frames,
		 "Low route-TCP async cross-item frame cap used before the dynamic-cap queue-depth threshold is reached");

module_param_cb(route_tcp_gso_async_stream_cross_item_dynamic_queue_depth,
		&trustix_route_tcp_gso_quiesced_uint_ops,
		&trustix_route_tcp_gso_async_stream_cross_item_dynamic_queue_depth,
		0644);
MODULE_PARM_DESC(route_tcp_gso_async_stream_cross_item_dynamic_queue_depth,
		 "Candidate queue depth required before route-TCP async cross-item dynamic cap uses the normal max-frame cap");

module_param_named(route_tcp_gso_async_reslice_to_mtu,
		   trustix_route_tcp_gso_async_reslice_to_mtu, bool, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_reslice_to_mtu,
		 "Allow experimental route-TCP async GSO to reslice jumbo inner GSO skbs down to the route MTU; off by default");

module_param_cb(route_tcp_gso_async_hash_tx_queue,
		&trustix_route_tcp_gso_quiesced_bool_ops,
		&trustix_route_tcp_gso_async_hash_tx_queue, 0644);
MODULE_PARM_DESC(route_tcp_gso_async_hash_tx_queue,
		 "Map route-TCP GSO async outer skbs to TX queues from the inner flow hash");

module_param_named(route_tcp_gso_async_inflight,
		   trustix_route_tcp_gso_async_inflight, uint, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_inflight,
		 "Current route-TCP GSO async work items in flight");

module_param_named(route_tcp_gso_async_queued_bytes,
		   trustix_route_tcp_gso_async_queued_bytes, ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_queued_bytes,
		 "Current cloned route-TCP GSO async skb bytes in flight");

module_param_named(route_tcp_gso_async_queued_bytes_high,
		   trustix_route_tcp_gso_async_queued_bytes_high, ulong,
		   0444);
MODULE_PARM_DESC(route_tcp_gso_async_queued_bytes_high,
		 "High-water mark for cloned route-TCP GSO async skb bytes in flight");

module_param_named(route_tcp_gso_async_queued,
		   trustix_route_tcp_gso_async_queued, ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_queued,
		 "Route-TCP GSO async work items queued from kfunc context");

module_param_named(route_tcp_gso_async_calls,
		   trustix_route_tcp_gso_async_calls, ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_calls,
		 "Route-TCP GSO async kfunc attempts");

module_param_named(route_tcp_gso_async_invalid_args,
		   trustix_route_tcp_gso_async_invalid_args, ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_invalid_args,
		 "Route-TCP GSO async kfunc attempts rejected for null arguments");

module_param_named(route_tcp_gso_async_disabled,
		   trustix_route_tcp_gso_async_disabled, ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_disabled,
		 "Route-TCP GSO async attempts rejected because the path is disabled");

module_param_named(netdev_unregister_events,
		   trustix_netdev_unregister_events, ulong, 0444);
MODULE_PARM_DESC(netdev_unregister_events,
		 "NETDEV_UNREGISTER events observed by the TrustIX helper notifier");

module_param_named(netdev_unregister_probe_ignored,
		   trustix_netdev_unregister_probe_ignored, ulong, 0444);
MODULE_PARM_DESC(netdev_unregister_probe_ignored,
		 "TrustIX tunnel capability-probe netdev unregisters ignored by the helper notifier");

module_param_named(netdev_unregister_flushes,
		   trustix_netdev_unregister_flushes, ulong, 0444);
MODULE_PARM_DESC(netdev_unregister_flushes,
		 "NETDEV_UNREGISTER events that quiesced and flushed TrustIX helper queues");

module_param_named(route_tcp_gso_async_no_dev,
		   trustix_route_tcp_gso_async_no_dev, ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_no_dev,
		 "Route-TCP GSO async attempts rejected because skb->dev is missing");

module_param_named(route_tcp_gso_async_no_gso,
		   trustix_route_tcp_gso_async_no_gso, ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_no_gso,
		 "Route-TCP GSO async attempts rejected because skb has no GSO metadata");

module_param_named(route_tcp_gso_async_invalid_flags,
		   trustix_route_tcp_gso_async_invalid_flags, ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_invalid_flags,
		 "Route-TCP GSO async attempts rejected for invalid flags");

module_param_named(route_tcp_gso_async_flow_errors,
		   trustix_route_tcp_gso_async_flow_errors, ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_flow_errors,
		 "Route-TCP GSO async attempts rejected by route/flow validation");

module_param_named(route_tcp_gso_async_plan_errors,
		   trustix_route_tcp_gso_async_plan_errors, ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_plan_errors,
		 "Route-TCP GSO async attempts rejected by inner GSO planning");

module_param_named(route_tcp_gso_async_linear_plans,
		   trustix_route_tcp_gso_async_linear_plans, ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_linear_plans,
		 "Route-TCP GSO async plans accepted from large linear TCP skbs without GSO metadata");

module_param_named(route_tcp_gso_async_no_ifindex,
		   trustix_route_tcp_gso_async_no_ifindex, ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_no_ifindex,
		 "Route-TCP GSO async attempts rejected because the selected flow has no ifindex");

module_param_named(route_tcp_gso_async_no_out_dev,
		   trustix_route_tcp_gso_async_no_out_dev, ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_no_out_dev,
		 "Route-TCP GSO async attempts rejected because the output device was not found");

module_param_named(route_tcp_gso_async_mtu_errors,
		   trustix_route_tcp_gso_async_mtu_errors, ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_mtu_errors,
		 "Route-TCP GSO async attempts rejected by MTU checks");

module_param_named(route_tcp_gso_async_queue_full,
		   trustix_route_tcp_gso_async_queue_full, ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_queue_full,
		 "Route-TCP GSO async attempts rejected because the queue was full");

module_param_named(route_tcp_gso_async_queue_bytes_full,
		   trustix_route_tcp_gso_async_queue_bytes_full, ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_queue_bytes_full,
		 "Route-TCP GSO async attempts rejected because cloned bytes would exceed the limit");

module_param_named(route_tcp_gso_async_alloc_errors,
		   trustix_route_tcp_gso_async_alloc_errors, ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_alloc_errors,
		 "Route-TCP GSO async work item allocation failures");

module_param_named(route_tcp_gso_async_clone_errors,
		   trustix_route_tcp_gso_async_clone_errors, ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_clone_errors,
		 "Route-TCP GSO async skb clone failures");

module_param_named(route_tcp_gso_async_workers,
		   trustix_route_tcp_gso_async_workers, ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_workers,
		 "Route-TCP GSO async work items processed");

module_param_named(route_tcp_gso_async_worker_runs,
		   trustix_route_tcp_gso_async_worker_runs, ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_worker_runs,
		 "Route-TCP GSO async worker pass count");

module_param_named(route_tcp_gso_async_worker_budget_yields,
		   trustix_route_tcp_gso_async_worker_budget_yields, ulong,
		   0444);
MODULE_PARM_DESC(route_tcp_gso_async_worker_budget_yields,
		 "Route-TCP GSO async worker passes that yielded because of budgets");

module_param_named(route_tcp_gso_async_worker_emit_budget_yields,
		   trustix_route_tcp_gso_async_worker_emit_budget_yields,
		   ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_worker_emit_budget_yields,
		 "Route-TCP GSO async worker passes that yielded because of the output batch budget");

module_param_named(route_tcp_gso_async_worker_dequeue_batches,
		   trustix_route_tcp_gso_async_worker_dequeue_batches, ulong,
		   0444);
MODULE_PARM_DESC(route_tcp_gso_async_worker_dequeue_batches,
		 "Route-TCP GSO async worker local dequeue batches");

module_param_named(route_tcp_gso_async_worker_dequeue_items,
		   trustix_route_tcp_gso_async_worker_dequeue_items, ulong,
		   0444);
MODULE_PARM_DESC(route_tcp_gso_async_worker_dequeue_items,
		 "Route-TCP GSO async work items moved into worker-local batches");

module_param_named(route_tcp_gso_async_worker_depth_defers,
		   trustix_route_tcp_gso_async_worker_depth_defers, ulong,
		   0444);
MODULE_PARM_DESC(route_tcp_gso_async_worker_depth_defers,
		 "Route-TCP GSO async worker passes deferred to wait for more same-shard work");

module_param_named(route_tcp_gso_async_worker_depth_defer_exhausted,
		   trustix_route_tcp_gso_async_worker_depth_defer_exhausted,
		   ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_worker_depth_defer_exhausted,
		 "Route-TCP GSO async worker depth defer attempts exhausted before queue reached the target depth");

module_param_named(route_tcp_gso_async_worker_schedule_delays,
		   trustix_route_tcp_gso_async_worker_schedule_delays, ulong,
		   0444);
MODULE_PARM_DESC(route_tcp_gso_async_worker_schedule_delays,
		 "Route-TCP GSO async worker drains initially delayed for batching");

module_param_named(route_tcp_gso_async_worker_schedule_delay_accels,
		   trustix_route_tcp_gso_async_worker_schedule_delay_accels,
		   ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_worker_schedule_delay_accels,
		 "Delayed route-TCP GSO async worker drains accelerated because shard depth reached the target");

module_param_named(route_tcp_gso_async_worker_schedule_delay_accel_suppressed,
		   trustix_route_tcp_gso_async_worker_schedule_delay_accel_suppressed,
		   ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_worker_schedule_delay_accel_suppressed,
		 "Delayed route-TCP GSO async worker accelerations suppressed to preserve the batching delay window");

module_param_named(route_tcp_gso_async_worker_budget_usleeps,
		   trustix_route_tcp_gso_async_worker_budget_usleeps,
		   ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_worker_budget_usleeps,
		 "Route-TCP GSO async worker microsecond sleeps after budget yields");

module_param_named(route_tcp_gso_async_segment_errors,
		   trustix_route_tcp_gso_async_segment_errors, ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_segment_errors,
		 "Route-TCP GSO async skb_gso_segment failures");

module_param_named(route_tcp_gso_async_prepare_errors,
		   trustix_route_tcp_gso_async_prepare_errors, ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_prepare_errors,
		 "Route-TCP GSO async segment encapsulation failures");

module_param_named(route_tcp_gso_async_txq_stopped_drops,
		   trustix_route_tcp_gso_async_txq_stopped_drops, ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_txq_stopped_drops,
		 "Route-TCP GSO async segments dropped because the selected TX queue was stopped");

module_param_named(route_tcp_gso_async_txq_stopped_queued,
		   trustix_route_tcp_gso_async_txq_stopped_queued, ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_txq_stopped_queued,
		 "Route-TCP GSO async skbs handed to dev_queue_xmit while the selected TX queue was transiently stopped");

module_param_cb(route_tcp_gso_async_txq_stopped_backoff_retries,
		&trustix_route_tcp_gso_quiesced_uint_ops,
		&trustix_route_tcp_gso_async_txq_stopped_backoff_retries,
		0644);
MODULE_PARM_DESC(route_tcp_gso_async_txq_stopped_backoff_retries,
		 "Retry/sleep this many times before sending a route-TCP GSO async skb while its selected TX queue is stopped; 0 disables");

module_param_cb(route_tcp_gso_async_txq_stopped_backoff_sleep_usecs,
		&trustix_route_tcp_gso_quiesced_uint_ops,
		&trustix_route_tcp_gso_async_txq_stopped_backoff_sleep_usecs,
		0644);
MODULE_PARM_DESC(route_tcp_gso_async_txq_stopped_backoff_sleep_usecs,
		 "Sleep this many microseconds for each route-TCP GSO async stopped-TXQ backoff attempt; 0 yields only and values are clamped to 20000us");

module_param_named(route_tcp_gso_async_txq_stopped_backoff_attempts,
		   trustix_route_tcp_gso_async_txq_stopped_backoff_attempts,
		   ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_txq_stopped_backoff_attempts,
		 "Route-TCP GSO async stopped-TXQ backoff attempts");

module_param_named(route_tcp_gso_async_txq_stopped_backoff_sleeps,
		   trustix_route_tcp_gso_async_txq_stopped_backoff_sleeps,
		   ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_txq_stopped_backoff_sleeps,
		 "Route-TCP GSO async stopped-TXQ backoff attempts that slept");

module_param_named(route_tcp_gso_async_txq_stopped_backoff_yields,
		   trustix_route_tcp_gso_async_txq_stopped_backoff_yields,
		   ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_txq_stopped_backoff_yields,
		 "Route-TCP GSO async stopped-TXQ backoff attempts that yielded");

module_param_named(route_tcp_gso_async_txq_stopped_backoff_recovered,
		   trustix_route_tcp_gso_async_txq_stopped_backoff_recovered,
		   ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_txq_stopped_backoff_recovered,
		 "Route-TCP GSO async stopped-TXQ backoffs after which the selected TX queue resumed");

module_param_named(route_tcp_gso_async_txq_stopped_backoff_still_stopped,
		   trustix_route_tcp_gso_async_txq_stopped_backoff_still_stopped,
		   ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_txq_stopped_backoff_still_stopped,
		 "Route-TCP GSO async stopped-TXQ backoffs after which the selected TX queue was still stopped or could not sleep");

module_param_named(route_tcp_gso_async_xmit_packets,
		   trustix_route_tcp_gso_async_xmit_packets, ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_xmit_packets,
		 "Route-TCP GSO async wire packets accepted by the network stack");

module_param_named(route_tcp_gso_async_xmit_errors,
		   trustix_route_tcp_gso_async_xmit_errors, ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_xmit_errors,
		 "Route-TCP GSO async wire packets rejected by the network stack");

module_param_named(route_tcp_gso_async_xmit_cn,
		   trustix_route_tcp_gso_async_xmit_cn, ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_xmit_cn,
		 "Route-TCP GSO async wire packets accepted with NET_XMIT_CN congestion notification");

module_param_named(route_tcp_gso_async_xmit_more_sets,
		   trustix_route_tcp_gso_async_xmit_more_sets, ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_xmit_more_sets,
		 "Route-TCP GSO async skbs sent with skb xmit_more set");

module_param_named(route_tcp_gso_async_xmit_busy_retry_attempts,
		   trustix_route_tcp_gso_async_xmit_busy_retry_attempts,
		   ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_xmit_busy_retry_attempts,
		 "Route-TCP GSO async TX-busy readiness retry attempts");

module_param_named(route_tcp_gso_async_xmit_busy_retry_successes,
		   trustix_route_tcp_gso_async_xmit_busy_retry_successes,
		   ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_xmit_busy_retry_successes,
		 "Route-TCP GSO async TX-busy readiness retries that recovered");

module_param_named(route_tcp_gso_async_xmit_busy_retry_failures,
		   trustix_route_tcp_gso_async_xmit_busy_retry_failures,
		   ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_xmit_busy_retry_failures,
		 "Route-TCP GSO async TX-busy readiness retries that still failed");

module_param_named(route_tcp_gso_async_stream_batches,
		   trustix_route_tcp_gso_async_stream_batches, ulong, 0444);
module_param_named(route_tcp_gso_async_stream_frames,
		   trustix_route_tcp_gso_async_stream_frames, ulong, 0444);
module_param_named(route_tcp_gso_async_stream_software_segments,
		   trustix_route_tcp_gso_async_stream_software_segments, ulong,
		   0444);
module_param_named(route_tcp_gso_async_stream_fallbacks,
		   trustix_route_tcp_gso_async_stream_fallbacks, ulong, 0444);
module_param_named(route_tcp_gso_async_stream_errors,
		   trustix_route_tcp_gso_async_stream_errors, ulong, 0444);
module_param_named(route_tcp_gso_async_stream_xmit_errors,
		   trustix_route_tcp_gso_async_stream_xmit_errors, ulong, 0444);
module_param_named(route_tcp_gso_async_stream_direct_builds,
		   trustix_route_tcp_gso_async_stream_direct_builds, ulong,
		   0444);
module_param_named(route_tcp_gso_async_stream_direct_frames,
		   trustix_route_tcp_gso_async_stream_direct_frames, ulong,
		   0444);
module_param_named(route_tcp_gso_async_stream_direct_fallbacks,
		   trustix_route_tcp_gso_async_stream_direct_fallbacks, ulong,
		   0444);
module_param_named(route_tcp_gso_async_stream_direct_errors,
		   trustix_route_tcp_gso_async_stream_direct_errors, ulong,
		   0444);
module_param_named(route_tcp_gso_async_stream_direct_fast_copy_hits,
		   trustix_route_tcp_gso_async_stream_direct_fast_copy_hits,
		   ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_stream_direct_fast_copy_hits,
		 "Route-TCP direct stream payload copies served from linear skb data");
module_param_named(route_tcp_gso_async_stream_direct_fast_copy_fallbacks,
		   trustix_route_tcp_gso_async_stream_direct_fast_copy_fallbacks,
		   ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_stream_direct_fast_copy_fallbacks,
		 "Route-TCP direct stream payload copies that fell back to skb_copy_bits");
module_param_named(route_tcp_gso_async_stream_direct_frag_fast_copy_hits,
		   trustix_route_tcp_gso_async_stream_direct_frag_fast_copy_hits,
		   ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_stream_direct_frag_fast_copy_hits,
		 "Route-TCP direct stream payload copies served from skb frags");
module_param_named(route_tcp_gso_async_stream_direct_frag_fast_copy_fallbacks,
		   trustix_route_tcp_gso_async_stream_direct_frag_fast_copy_fallbacks,
		   ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_stream_direct_frag_fast_copy_fallbacks,
		 "Route-TCP direct stream payload copies that fell back after checking skb frags");
module_param_named(route_tcp_gso_async_stream_direct_frag_fast_copy_cross_page_hits,
		   trustix_route_tcp_gso_async_stream_direct_frag_fast_copy_cross_page_hits,
		   ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_stream_direct_frag_fast_copy_cross_page_hits,
		 "Route-TCP direct stream skb frag fast-copy candidates served across page boundaries");
module_param_named(route_tcp_gso_async_stream_direct_frag_fast_copy_cross_page,
		   trustix_route_tcp_gso_async_stream_direct_frag_fast_copy_cross_page,
		   ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_stream_direct_frag_fast_copy_cross_page,
		 "Route-TCP direct stream skb frag fast-copy candidates rejected for crossing a page boundary while cross-page fast-copy is disabled");
module_param_named(route_tcp_gso_async_stream_direct_frag_fast_copy_misses,
		   trustix_route_tcp_gso_async_stream_direct_frag_fast_copy_misses,
		   ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_stream_direct_frag_fast_copy_misses,
		 "Route-TCP direct stream skb frag fast-copy candidates rejected because no single frag covered the payload");
module_param_named(route_tcp_gso_async_stream_nonlinear_direct_builds,
		   trustix_route_tcp_gso_async_stream_nonlinear_direct_builds,
		   ulong, 0444);
module_param_named(route_tcp_gso_async_stream_nonlinear_direct_frames,
		   trustix_route_tcp_gso_async_stream_nonlinear_direct_frames,
		   ulong, 0444);
module_param_named(route_tcp_gso_async_stream_nonlinear_direct_frags,
		   trustix_route_tcp_gso_async_stream_nonlinear_direct_frags,
		   ulong, 0444);
module_param_named(route_tcp_gso_async_stream_nonlinear_direct_bytes,
		   trustix_route_tcp_gso_async_stream_nonlinear_direct_bytes,
		   ulong, 0444);
module_param_named(route_tcp_gso_async_stream_nonlinear_direct_fallbacks,
		   trustix_route_tcp_gso_async_stream_nonlinear_direct_fallbacks,
		   ulong, 0444);
module_param_named(route_tcp_gso_async_stream_nonlinear_direct_errors,
		   trustix_route_tcp_gso_async_stream_nonlinear_direct_errors,
		   ulong, 0444);
module_param_named(route_tcp_gso_async_stream_outer_gso_batches,
		   trustix_route_tcp_gso_async_stream_outer_gso_batches, ulong,
		   0444);
module_param_named(route_tcp_gso_async_stream_outer_gso_frames,
		   trustix_route_tcp_gso_async_stream_outer_gso_frames, ulong,
		   0444);
module_param_named(route_tcp_gso_async_stream_outer_gso_fallbacks,
		   trustix_route_tcp_gso_async_stream_outer_gso_fallbacks, ulong,
		   0444);
module_param_named(route_tcp_gso_async_stream_outer_gso_errors,
		   trustix_route_tcp_gso_async_stream_outer_gso_errors, ulong,
		   0444);
module_param_named(route_tcp_gso_async_stream_outer_gso_blocked,
		   trustix_route_tcp_gso_async_stream_outer_gso_blocked,
		   ulong, 0444);
module_param_named(route_tcp_gso_async_stream_outer_gso_virtio_blocked,
		   trustix_route_tcp_gso_async_stream_outer_gso_virtio_blocked,
		   ulong, 0444);
module_param_named(route_tcp_gso_async_stream_outer_gso_verify_errors,
		   trustix_route_tcp_gso_async_stream_outer_gso_verify_errors,
		   ulong, 0444);
module_param_named(route_tcp_gso_async_stream_cross_item_batches,
		   trustix_route_tcp_gso_async_stream_cross_item_batches,
		   ulong, 0444);
module_param_named(route_tcp_gso_async_stream_cross_item_items,
		   trustix_route_tcp_gso_async_stream_cross_item_items,
		   ulong, 0444);
module_param_named(route_tcp_gso_async_stream_cross_item_frames,
		   trustix_route_tcp_gso_async_stream_cross_item_frames,
		   ulong, 0444);
module_param_named(route_tcp_gso_async_stream_cross_item_dequeue_batches,
		   trustix_route_tcp_gso_async_stream_cross_item_dequeue_batches,
		   ulong, 0444);
module_param_named(route_tcp_gso_async_stream_cross_item_dequeue_items,
		   trustix_route_tcp_gso_async_stream_cross_item_dequeue_items,
		   ulong, 0444);
module_param_named(route_tcp_gso_async_stream_cross_item_fallbacks,
		   trustix_route_tcp_gso_async_stream_cross_item_fallbacks,
		   ulong, 0444);
module_param_named(route_tcp_gso_async_stream_cross_item_errors,
		   trustix_route_tcp_gso_async_stream_cross_item_errors,
		   ulong, 0444);
module_param_named(route_tcp_gso_async_stream_cross_item_tail_stitch_batches,
		   trustix_route_tcp_gso_async_stream_cross_item_tail_stitch_batches,
		   ulong, 0444);
module_param_named(route_tcp_gso_async_stream_cross_item_tail_stitch_items,
		   trustix_route_tcp_gso_async_stream_cross_item_tail_stitch_items,
		   ulong, 0444);
module_param_named(route_tcp_gso_async_stream_cross_item_tail_stitch_frames,
		   trustix_route_tcp_gso_async_stream_cross_item_tail_stitch_frames,
		   ulong, 0444);
module_param_named(route_tcp_gso_async_stream_cross_item_tail_stitch_prefix_frames,
		   trustix_route_tcp_gso_async_stream_cross_item_tail_stitch_prefix_frames,
		   ulong, 0444);
module_param_named(route_tcp_gso_async_stream_cross_item_tail_stitch_fallbacks,
		   trustix_route_tcp_gso_async_stream_cross_item_tail_stitch_fallbacks,
		   ulong, 0444);
module_param_named(route_tcp_gso_async_stream_cross_item_tail_stitch_errors,
		   trustix_route_tcp_gso_async_stream_cross_item_tail_stitch_errors,
		   ulong, 0444);
module_param_named(route_tcp_gso_async_stream_cross_item_skip_disabled,
		   trustix_route_tcp_gso_async_stream_cross_item_skip_disabled,
		   ulong, 0444);
module_param_named(route_tcp_gso_async_stream_cross_item_skip_first_shape,
		   trustix_route_tcp_gso_async_stream_cross_item_skip_first_shape,
		   ulong, 0444);
module_param_named(route_tcp_gso_async_stream_cross_item_skip_first_tail,
		   trustix_route_tcp_gso_async_stream_cross_item_skip_first_tail,
		   ulong, 0444);
module_param_named(route_tcp_gso_async_stream_cross_item_skip_first_room,
		   trustix_route_tcp_gso_async_stream_cross_item_skip_first_room,
		   ulong, 0444);
module_param_named(route_tcp_gso_async_stream_cross_item_skip_no_next,
		   trustix_route_tcp_gso_async_stream_cross_item_skip_no_next,
		   ulong, 0444);
module_param_named(route_tcp_gso_async_stream_cross_item_skip_candidate_shape,
		   trustix_route_tcp_gso_async_stream_cross_item_skip_candidate_shape,
		   ulong, 0444);
module_param_named(route_tcp_gso_async_stream_cross_item_skip_candidate_room,
		   trustix_route_tcp_gso_async_stream_cross_item_skip_candidate_room,
		   ulong, 0444);
module_param_named(route_tcp_gso_async_stream_cross_item_skip_candidate_sequence,
		   trustix_route_tcp_gso_async_stream_cross_item_skip_candidate_sequence,
		   ulong, 0444);
module_param_named(route_tcp_gso_async_stream_cross_item_skip_candidate_template,
		   trustix_route_tcp_gso_async_stream_cross_item_skip_candidate_template,
		   ulong, 0444);
module_param_named(route_tcp_gso_async_stream_cross_item_lookahead_hits,
		   trustix_route_tcp_gso_async_stream_cross_item_lookahead_hits,
		   ulong, 0444);
module_param_named(route_tcp_gso_async_stream_cross_item_lookahead_misses,
		   trustix_route_tcp_gso_async_stream_cross_item_lookahead_misses,
		   ulong, 0444);
module_param_named(route_tcp_gso_async_stream_cross_item_lookahead_scans,
		   trustix_route_tcp_gso_async_stream_cross_item_lookahead_scans,
		   ulong, 0444);
module_param_named(route_tcp_gso_async_stream_cross_item_lookahead_blocked,
		   trustix_route_tcp_gso_async_stream_cross_item_lookahead_blocked,
		   ulong, 0444);
module_param_named(route_tcp_gso_async_stream_cross_item_dynamic_cap_high,
		   trustix_route_tcp_gso_async_stream_cross_item_dynamic_cap_high,
		   ulong, 0444);
module_param_named(route_tcp_gso_async_stream_cross_item_dynamic_cap_low,
		   trustix_route_tcp_gso_async_stream_cross_item_dynamic_cap_low,
		   ulong, 0444);
module_param_named(route_tcp_gso_async_stream_cross_item_last_ret,
		   trustix_route_tcp_gso_async_stream_cross_item_last_ret,
		   int, 0444);
module_param_named(route_tcp_gso_async_stream_cross_item_last_stage,
		   trustix_route_tcp_gso_async_stream_cross_item_last_stage,
		   uint, 0444);
module_param_named(route_tcp_gso_async_stream_cross_item_last_items,
		   trustix_route_tcp_gso_async_stream_cross_item_last_items,
		   uint, 0444);
module_param_named(route_tcp_gso_async_stream_cross_item_last_frames,
		   trustix_route_tcp_gso_async_stream_cross_item_last_frames,
		   uint, 0444);
module_param_named(route_tcp_gso_async_stream_cross_item_last_stream_payload_len,
		   trustix_route_tcp_gso_async_stream_cross_item_last_stream_payload_len,
		   uint, 0444);
module_param_named(route_tcp_gso_async_stream_cross_item_last_outer_gso_size,
		   trustix_route_tcp_gso_async_stream_cross_item_last_outer_gso_size,
		   uint, 0444);
module_param_named(route_tcp_gso_async_stream_cross_item_last_first_frame_len,
		   trustix_route_tcp_gso_async_stream_cross_item_last_first_frame_len,
		   uint, 0444);
module_param_named(route_tcp_gso_async_stream_cross_item_last_last_frame_len,
		   trustix_route_tcp_gso_async_stream_cross_item_last_last_frame_len,
		   uint, 0444);
module_param_named(route_tcp_gso_async_reslice_plans,
		   trustix_route_tcp_gso_async_reslice_plans, ulong, 0444);
module_param_named(route_tcp_gso_sync_calls,
		   trustix_route_tcp_gso_sync_calls, ulong, 0444);
module_param_named(route_tcp_gso_sync_segments,
		   trustix_route_tcp_gso_sync_segments, ulong, 0444);
module_param_named(route_tcp_gso_sync_fallbacks,
		   trustix_route_tcp_gso_sync_fallbacks, ulong, 0444);
module_param_named(route_tcp_gso_sync_errors,
		   trustix_route_tcp_gso_sync_errors, ulong, 0444);
module_param_named(route_tcp_gso_sync_xmit_errors,
		   trustix_route_tcp_gso_sync_xmit_errors, ulong, 0444);
module_param_named(route_tcp_gso_sync_async_redirects,
		   trustix_route_tcp_gso_sync_async_redirects, ulong, 0444);
module_param_named(route_tcp_gso_sync_stream_attempts,
		   trustix_route_tcp_gso_sync_stream_attempts, ulong, 0444);
module_param_named(route_tcp_gso_sync_stream_batches,
		   trustix_route_tcp_gso_sync_stream_batches, ulong, 0444);
module_param_named(route_tcp_gso_sync_stream_frames,
		   trustix_route_tcp_gso_sync_stream_frames, ulong, 0444);
module_param_named(route_tcp_gso_sync_stream_fallbacks,
		   trustix_route_tcp_gso_sync_stream_fallbacks, ulong, 0444);
module_param_named(route_tcp_gso_sync_stream_errors,
		   trustix_route_tcp_gso_sync_stream_errors, ulong, 0444);
module_param_named(route_tcp_gso_sync_stream_xmit_errors,
		   trustix_route_tcp_gso_sync_stream_xmit_errors, ulong, 0444);
module_param_named(route_tcp_gso_sync_stream_build_errors,
		   trustix_route_tcp_gso_sync_stream_build_errors, ulong,
		   0444);
module_param_named(route_tcp_gso_sync_stream_build_busy,
		   trustix_route_tcp_gso_sync_stream_build_busy, ulong, 0444);
module_param_named(route_tcp_gso_sync_stream_build_nomem,
		   trustix_route_tcp_gso_sync_stream_build_nomem, ulong, 0444);
module_param_named(route_tcp_gso_sync_stream_build_unsupported,
		   trustix_route_tcp_gso_sync_stream_build_unsupported, ulong,
		   0444);
module_param_named(route_tcp_gso_sync_stream_ready_errors,
		   trustix_route_tcp_gso_sync_stream_ready_errors, ulong,
		   0444);
module_param_named(route_tcp_gso_sync_stream_partial_xmits,
		   trustix_route_tcp_gso_sync_stream_partial_xmits, ulong,
		   0444);
module_param_named(route_tcp_gso_direct_xmit_safe_fallbacks,
		   trustix_route_tcp_gso_direct_xmit_safe_fallbacks, ulong,
		   0444);
module_param_named(route_tcp_gso_direct_xmit_attempts,
		   trustix_route_tcp_gso_direct_xmit_attempts, ulong, 0444);
module_param_named(route_tcp_gso_direct_xmit_successes,
		   trustix_route_tcp_gso_direct_xmit_successes, ulong, 0444);
module_param_named(route_tcp_gso_direct_xmit_cn,
		   trustix_route_tcp_gso_direct_xmit_cn, ulong, 0444);
module_param_named(route_tcp_gso_direct_xmit_busy,
		   trustix_route_tcp_gso_direct_xmit_busy, ulong, 0444);
module_param_named(route_tcp_gso_direct_xmit_busy_fallbacks,
		   trustix_route_tcp_gso_direct_xmit_busy_fallbacks, ulong,
		   0444);
module_param_named(route_tcp_gso_direct_xmit_drops,
		   trustix_route_tcp_gso_direct_xmit_drops, ulong, 0444);
module_param_named(route_tcp_gso_direct_xmit_errors,
		   trustix_route_tcp_gso_direct_xmit_errors, ulong, 0444);
module_param_named(route_tcp_gso_direct_xmit_not_ready,
		   trustix_route_tcp_gso_direct_xmit_not_ready, ulong, 0444);
module_param_named(route_tcp_gso_async_prefer_sync_bypasses,
		   trustix_route_tcp_gso_async_prefer_sync_bypasses, ulong,
		   0444);
module_param_named(route_tcp_gso_sync_stream_last_ret,
		   trustix_route_tcp_gso_sync_stream_last_ret, int, 0444);
module_param_named(route_tcp_gso_sync_stream_last_stage,
		   trustix_route_tcp_gso_sync_stream_last_stage, int, 0444);
module_param_named(route_tcp_gso_sync_stream_last_batch_count,
		   trustix_route_tcp_gso_sync_stream_last_batch_count, uint,
		   0444);
module_param_named(route_tcp_gso_sync_stream_last_batch_frames,
		   trustix_route_tcp_gso_sync_stream_last_batch_frames, uint,
		   0444);
module_param_named(route_tcp_gso_sync_stream_last_len,
		   trustix_route_tcp_gso_sync_stream_last_len, uint, 0444);
module_param_named(route_tcp_gso_sync_stream_last_gso_size,
		   trustix_route_tcp_gso_sync_stream_last_gso_size, uint,
		   0444);
module_param_named(route_tcp_gso_sync_stream_last_gso_segs,
		   trustix_route_tcp_gso_sync_stream_last_gso_segs, uint,
		   0444);
module_param_named(route_tcp_gso_sync_stream_last_gso_type,
		   trustix_route_tcp_gso_sync_stream_last_gso_type, uint,
		   0444);
module_param_named(route_tcp_gso_async_hash_tx_queue_sets,
		   trustix_route_tcp_gso_async_hash_tx_queue_sets, ulong, 0444);
MODULE_PARM_DESC(route_tcp_gso_async_hash_tx_queue_sets,
		 "Route-TCP GSO async outer skbs assigned to a hashed TX queue");
module_param_named(route_tcp_gso_async_hash_tx_queue_fallbacks,
		   trustix_route_tcp_gso_async_hash_tx_queue_fallbacks, ulong,
		   0444);
MODULE_PARM_DESC(route_tcp_gso_async_hash_tx_queue_fallbacks,
		 "Route-TCP GSO async hashed TX queue assignments skipped because the device has one or no TX queues");
module_param_named(route_tcp_gso_async_hash_tx_queue_q0,
		   trustix_route_tcp_gso_async_hash_tx_queue_q0, ulong, 0444);
module_param_named(route_tcp_gso_async_hash_tx_queue_q1,
		   trustix_route_tcp_gso_async_hash_tx_queue_q1, ulong, 0444);
module_param_named(route_tcp_gso_async_hash_tx_queue_q2,
		   trustix_route_tcp_gso_async_hash_tx_queue_q2, ulong, 0444);
module_param_named(route_tcp_gso_async_hash_tx_queue_q3,
		   trustix_route_tcp_gso_async_hash_tx_queue_q3, ulong, 0444);
module_param_named(route_tcp_gso_async_hash_tx_queue_q4,
		   trustix_route_tcp_gso_async_hash_tx_queue_q4, ulong, 0444);
module_param_named(route_tcp_gso_async_hash_tx_queue_q5,
		   trustix_route_tcp_gso_async_hash_tx_queue_q5, ulong, 0444);
module_param_named(route_tcp_gso_async_hash_tx_queue_q6,
		   trustix_route_tcp_gso_async_hash_tx_queue_q6, ulong, 0444);
module_param_named(route_tcp_gso_async_hash_tx_queue_q7,
		   trustix_route_tcp_gso_async_hash_tx_queue_q7, ulong, 0444);
module_param_named(route_tcp_gso_async_hash_tx_queue_other,
		   trustix_route_tcp_gso_async_hash_tx_queue_other, ulong,
		   0444);
MODULE_PARM_DESC(route_tcp_gso_async_hash_tx_queue_other,
		 "Route-TCP GSO async hashed TX queue assignments beyond the first 8 queues");
module_param_named(route_tcp_gso_async_last_gso_size,
		   trustix_route_tcp_gso_async_last_gso_size, uint, 0444);
module_param_named(route_tcp_gso_async_last_gso_segs,
		   trustix_route_tcp_gso_async_last_gso_segs, uint, 0444);
module_param_named(route_tcp_gso_async_last_gso_type,
		   trustix_route_tcp_gso_async_last_gso_type, uint, 0444);
module_param_named(route_tcp_gso_async_last_skb_len,
		   trustix_route_tcp_gso_async_last_skb_len, uint, 0444);
module_param_named(route_tcp_gso_async_max_skb_len,
		   trustix_route_tcp_gso_async_max_skb_len, uint, 0444);
module_param_named(route_tcp_gso_async_max_headlen,
		   trustix_route_tcp_gso_async_max_headlen, uint, 0444);
module_param_named(route_tcp_gso_async_last_segment_count,
		   trustix_route_tcp_gso_async_last_segment_count, uint,
		   0444);
module_param_named(route_tcp_gso_async_last_payload_len,
		   trustix_route_tcp_gso_async_last_payload_len, uint, 0444);
module_param_named(route_tcp_gso_async_last_max_wire_len,
		   trustix_route_tcp_gso_async_last_max_wire_len, uint,
		   0444);
module_param_named(route_tcp_gso_async_last_plan_ret,
		   trustix_route_tcp_gso_async_last_plan_ret, int, 0444);
module_param_named(route_tcp_gso_async_last_plan_mtu,
		   trustix_route_tcp_gso_async_last_plan_mtu, uint, 0444);
module_param_named(route_tcp_gso_async_last_plan_max_inner_len,
		   trustix_route_tcp_gso_async_last_plan_max_inner_len, uint,
		   0444);
module_param_named(route_tcp_gso_async_last_plan_gso_payload_len,
		   trustix_route_tcp_gso_async_last_plan_gso_payload_len, uint,
		   0444);
module_param_named(route_tcp_gso_async_last_plan_resliced,
		   trustix_route_tcp_gso_async_last_plan_resliced, uint,
		   0444);
module_param_named(route_tcp_gso_async_stream_last_software_ret,
		   trustix_route_tcp_gso_async_stream_last_software_ret, int,
		   0444);
module_param_named(route_tcp_gso_async_stream_last_software_stage,
		   trustix_route_tcp_gso_async_stream_last_software_stage, int,
		   0444);
module_param_named(route_tcp_gso_async_stream_last_len,
		   trustix_route_tcp_gso_async_stream_last_len, uint, 0444);
module_param_named(route_tcp_gso_async_stream_last_headlen,
		   trustix_route_tcp_gso_async_stream_last_headlen, uint,
		   0444);
module_param_named(route_tcp_gso_async_stream_last_gso_size,
		   trustix_route_tcp_gso_async_stream_last_gso_size, uint,
		   0444);
module_param_named(route_tcp_gso_async_stream_last_gso_segs,
		   trustix_route_tcp_gso_async_stream_last_gso_segs, uint,
		   0444);
module_param_named(route_tcp_gso_async_stream_last_gso_type,
		   trustix_route_tcp_gso_async_stream_last_gso_type, uint,
		   0444);
module_param_named(route_tcp_gso_async_stream_last_offsets,
		   trustix_route_tcp_gso_async_stream_last_offsets, uint,
		   0444);

module_param_cb(route_tcp_xmit_worker,
		&trustix_route_tcp_xmit_worker_bool_ops,
		&trustix_route_tcp_xmit_worker, 0644);
MODULE_PARM_DESC(route_tcp_xmit_worker,
		 "Enable experimental route TCP xmit via a TrustIX worker instead of direct TC-context xmit");
module_param_cb(route_tcp_dev_xmit,
		&trustix_route_tcp_xmit_worker_bool_ops,
		&trustix_route_tcp_xmit_worker, 0644);
MODULE_PARM_DESC(route_tcp_dev_xmit,
		 "Legacy alias for route_tcp_xmit_worker; xmit is isolated to the worker and uses dev_queue_xmit");

module_param_named(route_tcp_xmit_worker_steal,
		   trustix_route_tcp_xmit_worker_steal, bool, 0644);
MODULE_PARM_DESC(route_tcp_xmit_worker_steal,
		 "Compatibility knob for the old route TCP steal mode; current safe worker always clones the skb");

module_param_named(route_tcp_xmit_worker_queue_limit,
		   trustix_route_tcp_xmit_worker_queue_limit, uint, 0644);
MODULE_PARM_DESC(route_tcp_xmit_worker_queue_limit,
		 "Maximum queued experimental route TCP worker packets before the kfunc falls back");

module_param_named(route_tcp_xmit_worker_budget,
		   trustix_route_tcp_xmit_worker_budget, uint, 0644);
MODULE_PARM_DESC(route_tcp_xmit_worker_budget,
		 "Maximum experimental route TCP packets transmitted per worker pass");

module_param_named(route_tcp_xmit_worker_depth,
		   trustix_route_tcp_xmit_worker_depth, uint, 0444);
MODULE_PARM_DESC(route_tcp_xmit_worker_depth,
		 "Current queued experimental route TCP worker packets");

module_param_named(route_tcp_xmit_worker_enqueued,
		   trustix_route_tcp_xmit_worker_enqueued, ulong, 0444);
MODULE_PARM_DESC(route_tcp_xmit_worker_enqueued,
		 "Experimental route TCP worker packets accepted from kfuncs");

module_param_named(route_tcp_xmit_worker_cloned,
		   trustix_route_tcp_xmit_worker_cloned, ulong, 0444);
MODULE_PARM_DESC(route_tcp_xmit_worker_cloned,
		 "Experimental route TCP worker packets accepted through the clone-and-drop-original path");

module_param_named(route_tcp_xmit_worker_stolen,
		   trustix_route_tcp_xmit_worker_stolen, ulong, 0444);
MODULE_PARM_DESC(route_tcp_xmit_worker_stolen,
		 "Experimental route TCP worker packets accepted through the TC_ACT_STOLEN original-skb path");

module_param_named(route_tcp_xmit_worker_no_dev,
		   trustix_route_tcp_xmit_worker_no_dev, ulong, 0444);
MODULE_PARM_DESC(route_tcp_xmit_worker_no_dev,
		 "Experimental route TCP worker packets rejected because the egress device could not be referenced");

module_param_named(route_tcp_xmit_worker_queue_full,
		   trustix_route_tcp_xmit_worker_queue_full, ulong, 0444);
MODULE_PARM_DESC(route_tcp_xmit_worker_queue_full,
		 "Experimental route TCP worker packets rejected because the queue was full");

module_param_named(route_tcp_xmit_worker_alloc_errors,
		   trustix_route_tcp_xmit_worker_alloc_errors, ulong, 0444);
MODULE_PARM_DESC(route_tcp_xmit_worker_alloc_errors,
		 "Experimental route TCP worker packet allocation failures");

module_param_named(route_tcp_xmit_worker_header_errors,
		   trustix_route_tcp_xmit_worker_header_errors, ulong, 0444);
MODULE_PARM_DESC(route_tcp_xmit_worker_header_errors,
		 "Experimental route TCP worker packets dropped because header preparation failed");

module_param_named(route_tcp_xmit_worker_xmit_ok,
		   trustix_route_tcp_xmit_worker_xmit_ok, ulong, 0444);
MODULE_PARM_DESC(route_tcp_xmit_worker_xmit_ok,
		 "Experimental route TCP worker packets handed to the network stack successfully");

module_param_named(route_tcp_xmit_worker_xmit_errors,
		   trustix_route_tcp_xmit_worker_xmit_errors, ulong, 0444);
MODULE_PARM_DESC(route_tcp_xmit_worker_xmit_errors,
		 "Experimental route TCP worker packets rejected by the network stack");

module_param_named(route_tcp_xmit_worker_flush_drops,
		   trustix_route_tcp_xmit_worker_flush_drops, ulong, 0444);
MODULE_PARM_DESC(route_tcp_xmit_worker_flush_drops,
		 "Experimental route TCP worker packets dropped during module teardown");

module_param_named(route_tcp_xmit_worker_disabled,
		   trustix_route_tcp_xmit_worker_disabled, ulong, 0444);
MODULE_PARM_DESC(route_tcp_xmit_worker_disabled,
		 "Experimental route TCP worker packets rejected because the worker was disabled or quiescing");

module_param_named(kudp_rx_hot_stats, trustix_kudp_rx_hot_stats, bool, 0644);
MODULE_PARM_DESC(kudp_rx_hot_stats,
		 "Enable TrustIX kernel UDP/TIXT RX helper hot-path counters");

module_param_named(tixt_rx_stream_parse,
		   trustix_tixt_rx_stream_parse, bool, 0644);
MODULE_PARM_DESC(tixt_rx_stream_parse,
		 "Enable experimental TIXT stream parsing in the RX parse-decap kfunc");

module_param_named(tixt_rx_stream_xmit_extra,
		   trustix_tixt_rx_stream_xmit_extra, bool, 0644);
MODULE_PARM_DESC(tixt_rx_stream_xmit_extra,
		 "Inject extra frames from a multi-frame TIXT stream after the first frame is decapped in-place");

module_param_named(tixt_rx_stream_ordered_list,
		   trustix_tixt_rx_stream_ordered_list, bool, 0644);
MODULE_PARM_DESC(tixt_rx_stream_ordered_list,
		 "Copy every frame from a multi-frame TIXT stream into a receive list and return STOLEN so TCP sees in-stream order; invalid devices or malformed frames fall back to normal RX handling");

module_param_named(tixt_rx_stream_gso_xmit,
		   trustix_tixt_rx_stream_gso_xmit, bool, 0644);
MODULE_PARM_DESC(tixt_rx_stream_gso_xmit,
		 "Allow experimental TIXT RX stream extra-frame injection; reserved for future GSO-aware injection");

module_param_named(tixt_rx_stream_coalesce_gso,
		   trustix_tixt_rx_stream_coalesce_gso, bool, 0644);
MODULE_PARM_DESC(tixt_rx_stream_coalesce_gso,
		 "Coalesce compatible plaintext TIXT stream frames into one RX skb");

module_param_named(tixt_rx_stream_coalesce_mark_gso,
		   trustix_tixt_rx_stream_coalesce_mark_gso, bool, 0644);
MODULE_PARM_DESC(tixt_rx_stream_coalesce_mark_gso,
		 "Mark coalesced TIXT stream RX skbs as TCPv4 GSO; off keeps them as large local-delivery skbs");

module_param_named(tixt_rx_stream_nonlinear_parse,
		   trustix_tixt_rx_stream_nonlinear_parse, bool, 0644);
MODULE_PARM_DESC(tixt_rx_stream_nonlinear_parse,
		 "Parse multi-frame TIXT TCP streams from nonlinear/GRO skbs using skb_header_pointer; failures fall back to the linear pull/normal RX path");

module_param_cb(tixt_rx_single_coalesce_gso,
		&trustix_tixt_rx_single_coalesce_gso_ops, NULL, 0644);
MODULE_PARM_DESC(tixt_rx_single_coalesce_gso,
		 "Coalesce compatible single-frame plaintext TIXT RX skbs into GSO skbs; toggling drains existing coalesce state");

module_param_named(tixt_rx_single_coalesce_mark_gso,
		   trustix_tixt_rx_single_coalesce_mark_gso, bool, 0644);
MODULE_PARM_DESC(tixt_rx_single_coalesce_mark_gso,
		 "Mark single-frame coalesced RX skbs as TCPv4 GSO; off keeps them as large local-delivery skbs");

module_param_named(tixt_rx_coalesce_mark_gso_partial_csum,
		   trustix_tixt_rx_coalesce_mark_gso_partial_csum, bool,
		   0644);
MODULE_PARM_DESC(tixt_rx_coalesce_mark_gso_partial_csum,
		 "Legacy compatibility request for CHECKSUM_PARTIAL on coalesced TIXT RX GSO skbs; current safe path keeps complete checksums unless software segmenting");

module_param_named(tixt_rx_coalesce_segment_gso,
		   trustix_tixt_rx_coalesce_segment_gso, bool, 0644);
MODULE_PARM_DESC(tixt_rx_coalesce_segment_gso,
		 "Segment coalesced TIXT RX GSO skbs before publishing them through the RX stack");

module_param_named(tixt_rx_backlog_worker_budget,
		   trustix_tixt_rx_backlog_worker_budget, uint, 0644);
MODULE_PARM_DESC(tixt_rx_backlog_worker_budget,
		 "Maximum skb count delivered by one deferred TIXT RX backlog worker run");

module_param_named(tixt_rx_single_coalesce_skip_tcp_csum,
		   trustix_tixt_rx_single_coalesce_skip_tcp_csum, bool, 0644);
MODULE_PARM_DESC(tixt_rx_single_coalesce_skip_tcp_csum,
		 "Trust CHECKSUM_UNNECESSARY on single-frame RX coalesced skbs without recomputing aggregate TCP checksum");

module_param_named(tixt_rx_single_coalesce_direct_list,
		   trustix_tixt_rx_single_coalesce_direct_list, bool, 0644);
MODULE_PARM_DESC(tixt_rx_single_coalesce_direct_list,
		 "For single-frame TIXT RX coalesce, publish a directly-built skb list instead of building a GSO skb and segmenting it");

module_param_named(tixt_rx_single_coalesce_direct_list_max_frames,
		   trustix_tixt_rx_single_coalesce_direct_list_max_frames,
		   uint, 0644);
MODULE_PARM_DESC(tixt_rx_single_coalesce_direct_list_max_frames,
		 "Maximum coalesced frames allowed through direct-list RX; 0 or 1 disables direct-list without disabling GSO segmentation fallback");

module_param_named(tixt_rx_single_coalesce_page_only,
		   trustix_tixt_rx_single_coalesce_page_only, bool, 0644);
MODULE_PARM_DESC(tixt_rx_single_coalesce_page_only,
		 "Store single-frame RX coalesced payload directly in page frags instead of a linear payload buffer");

module_param_named(tixt_rx_single_coalesce_linear_build,
		   trustix_tixt_rx_single_coalesce_linear_build, bool, 0644);
MODULE_PARM_DESC(tixt_rx_single_coalesce_linear_build,
		 "Build single-frame RX coalesced GSO skbs as large linear skbs when allocation succeeds");

module_param_named(tixt_rx_single_coalesce_hybrid_head,
		   trustix_tixt_rx_single_coalesce_hybrid_head, bool, 0644);
MODULE_PARM_DESC(tixt_rx_single_coalesce_hybrid_head,
		 "Keep buffered linear payload in the skb head and attach only spill pages for nonlinear single-frame RX coalesced GSO skbs");

module_param_named(tixt_rx_single_coalesce_netif_rx,
		   trustix_tixt_rx_single_coalesce_netif_rx, bool, 0644);
MODULE_PARM_DESC(tixt_rx_single_coalesce_netif_rx,
		 "Publish single-frame RX coalesced GSO skbs through netif_rx backlog instead of direct netif_receive_skb");

module_param_named(tixt_rx_single_coalesce_schedule_once,
		   trustix_tixt_rx_single_coalesce_schedule_once, bool, 0644);
MODULE_PARM_DESC(tixt_rx_single_coalesce_schedule_once,
		 "Schedule one delayed flush per single-frame RX coalesce slot instead of refreshing it for every appended frame");

module_param_named(tixt_rx_single_coalesce_stream_fallback,
		   trustix_tixt_rx_single_coalesce_stream_fallback, bool,
		   0644);
MODULE_PARM_DESC(tixt_rx_single_coalesce_stream_fallback,
		 "Let single-frame RX coalescing steal large/GSO outer TCP skbs through the TIXT stream parser");

module_param_named(tixt_rx_single_coalesce_hot_stats,
		   trustix_tixt_rx_single_coalesce_hot_stats, bool, 0644);
MODULE_PARM_DESC(tixt_rx_single_coalesce_hot_stats,
		 "Enable per-frame diagnostic counters in the single-frame RX coalescer");

module_param_named(tixt_rx_single_coalesce_defer_full_flush,
		   trustix_tixt_rx_single_coalesce_defer_full_flush, bool,
		   0644);
MODULE_PARM_DESC(tixt_rx_single_coalesce_defer_full_flush,
		 "Defer full single-frame RX coalesce slot flushes to system_wq instead of publishing from the outer RX softirq");

module_param_named(tixt_rx_single_coalesce_keep_full_timer,
		   trustix_tixt_rx_single_coalesce_keep_full_timer, bool,
		   0644);
MODULE_PARM_DESC(tixt_rx_single_coalesce_keep_full_timer,
		 "Keep the delayed tail-flush timer pending after a full synchronous single-frame RX coalesce flush");

module_param_named(tixt_rx_single_coalesce_set_hash,
		   trustix_tixt_rx_single_coalesce_set_hash, bool, 0644);
MODULE_PARM_DESC(tixt_rx_single_coalesce_set_hash,
		 "Set a stable L4 hash on single-frame RX coalesced GSO skbs");

module_param_named(tixt_rx_backlog_worker_queue_limit,
		   trustix_tixt_rx_backlog_worker_queue_limit, uint, 0644);
MODULE_PARM_DESC(tixt_rx_backlog_worker_queue_limit,
		 "Maximum queued TIXT RX stream/coalesce skbs awaiting safe worker-context LAN reinjection");

module_param_named(tixt_rx_single_coalesce_schedule_stride,
		   trustix_tixt_rx_single_coalesce_schedule_stride, uint, 0644);
MODULE_PARM_DESC(tixt_rx_single_coalesce_schedule_stride,
		 "Refresh delayed single-frame RX coalesce flush every N appended frames; 1 preserves legacy per-frame refresh");

module_param_named(tixt_rx_stream_max_frames,
		   trustix_tixt_rx_stream_max_frames, uint, 0644);
MODULE_PARM_DESC(tixt_rx_stream_max_frames,
		 "Maximum TIXT frames parsed from one outer TCP payload");

module_param_named(tixt_rx_single_coalesce_max_frames,
		   trustix_tixt_rx_single_coalesce_max_frames, uint, 0644);
MODULE_PARM_DESC(tixt_rx_single_coalesce_max_frames,
		 "Maximum single-frame TIXT skbs coalesced into one RX GSO skb");

module_param_named(tixt_rx_single_coalesce_flush_jiffies,
		   trustix_tixt_rx_single_coalesce_flush_jiffies, uint, 0644);
MODULE_PARM_DESC(tixt_rx_single_coalesce_flush_jiffies,
		 "Delayed flush interval for single-frame TIXT RX coalescing; 0 schedules an immediate workqueue flush");

module_param_named(tixt_rx_single_coalesce_warmup_frames,
		   trustix_tixt_rx_single_coalesce_warmup_frames, uint,
		   0644);
MODULE_PARM_DESC(tixt_rx_single_coalesce_warmup_frames,
		 "Compatible payload frames to pass through before a single-frame RX coalesce slot starts stealing; 1 preserves legacy behavior");

module_param_cb(tixt_rx_single_coalesce_linear_max,
		&trustix_tixt_rx_single_coalesce_linear_max_ops, NULL, 0644);
MODULE_PARM_DESC(tixt_rx_single_coalesce_linear_max,
		 "Maximum reusable linear payload bytes for single-frame TIXT RX coalescing; writes drain existing coalesce state");

module_param_named(tixt_rx_stream_candidates,
		   trustix_tixt_rx_stream_candidates, ulong, 0444);
module_param_named(tixt_rx_stream_disabled,
		   trustix_tixt_rx_stream_disabled, ulong, 0444);
module_param_named(tixt_rx_stream_parse_errors,
		   trustix_tixt_rx_stream_parse_errors, ulong, 0444);
module_param_named(tixt_rx_stream_frames,
		   trustix_tixt_rx_stream_frames, ulong, 0444);
module_param_named(tixt_rx_stream_xmit_packets,
		   trustix_tixt_rx_stream_xmit_packets, ulong, 0444);
module_param_named(tixt_rx_stream_xmit_errors,
		   trustix_tixt_rx_stream_xmit_errors, ulong, 0444);
module_param_named(tixt_rx_stream_gso_batches,
		   trustix_tixt_rx_stream_gso_batches, ulong, 0444);
module_param_named(tixt_rx_stream_gso_frames,
		   trustix_tixt_rx_stream_gso_frames, ulong, 0444);
module_param_named(tixt_rx_stream_gso_fallbacks,
		   trustix_tixt_rx_stream_gso_fallbacks, ulong, 0444);
module_param_named(tixt_rx_stream_gso_errors,
		   trustix_tixt_rx_stream_gso_errors, ulong, 0444);
module_param_named(tixt_rx_stream_gso_xmit_errors,
		   trustix_tixt_rx_stream_gso_xmit_errors, ulong, 0444);
module_param_named(tixt_rx_stream_coalesce_batches,
		   trustix_tixt_rx_stream_coalesce_batches, ulong, 0444);
module_param_named(tixt_rx_stream_coalesce_frames,
		   trustix_tixt_rx_stream_coalesce_frames, ulong, 0444);
module_param_named(tixt_rx_stream_coalesce_fallbacks,
		   trustix_tixt_rx_stream_coalesce_fallbacks, ulong, 0444);
module_param_named(tixt_rx_stream_coalesce_errors,
		   trustix_tixt_rx_stream_coalesce_errors, ulong, 0444);
module_param_named(tixt_rx_stream_coalesce_xmit_errors,
		   trustix_tixt_rx_stream_coalesce_xmit_errors, ulong, 0444);
module_param_named(tixt_rx_stream_ordered_list_batches,
		   trustix_tixt_rx_stream_ordered_list_batches, ulong, 0444);
module_param_named(tixt_rx_stream_ordered_list_frames,
		   trustix_tixt_rx_stream_ordered_list_frames, ulong, 0444);
module_param_named(tixt_rx_stream_ordered_list_errors,
		   trustix_tixt_rx_stream_ordered_list_errors, ulong, 0444);
module_param_named(tixt_rx_stream_backlog_packets,
		   trustix_tixt_rx_stream_backlog_packets, ulong, 0444);
module_param_named(tixt_rx_stream_backlog_drops,
		   trustix_tixt_rx_stream_backlog_drops, ulong, 0444);
module_param_named(tixt_rx_backlog_worker_depth,
		   trustix_tixt_rx_backlog_worker_depth, uint, 0444);
module_param_named(tixt_rx_backlog_worker_enqueued,
		   trustix_tixt_rx_backlog_worker_enqueued, ulong, 0444);
module_param_named(tixt_rx_backlog_worker_delivered,
		   trustix_tixt_rx_backlog_worker_delivered, ulong, 0444);
module_param_named(tixt_rx_backlog_worker_drops,
		   trustix_tixt_rx_backlog_worker_drops, ulong, 0444);
module_param_named(tixt_rx_backlog_worker_queue_full,
		   trustix_tixt_rx_backlog_worker_queue_full, ulong, 0444);
module_param_named(tixt_rx_backlog_worker_disabled,
		   trustix_tixt_rx_backlog_worker_disabled, ulong, 0444);
module_param_named(tixt_rx_backlog_worker_runs,
		   trustix_tixt_rx_backlog_worker_runs, ulong, 0444);
module_param_named(tixt_rx_coalesce_segment_batches,
		   trustix_tixt_rx_coalesce_segment_batches, ulong, 0444);
module_param_named(tixt_rx_coalesce_segment_frames,
		   trustix_tixt_rx_coalesce_segment_frames, ulong, 0444);
module_param_named(tixt_rx_coalesce_segment_errors,
		   trustix_tixt_rx_coalesce_segment_errors, ulong, 0444);
module_param_named(tixt_rx_coalesce_segment_backlog_packets,
		   trustix_tixt_rx_coalesce_segment_backlog_packets, ulong,
		   0444);
module_param_named(tixt_rx_coalesce_segment_backlog_drops,
		   trustix_tixt_rx_coalesce_segment_backlog_drops, ulong,
		   0444);
module_param_named(tixt_rx_coalesce_partial_csum_fallbacks,
		   trustix_tixt_rx_coalesce_partial_csum_fallbacks, ulong,
		   0444);
module_param_named(tixt_rx_stream_nonlinear_parse_hits,
		   trustix_tixt_rx_stream_nonlinear_parse_hits, ulong, 0444);
module_param_named(tixt_rx_single_coalesce_candidates,
		   trustix_tixt_rx_single_coalesce_candidates, ulong, 0444);
module_param_named(tixt_rx_single_coalesce_batches,
		   trustix_tixt_rx_single_coalesce_batches, ulong, 0444);
module_param_named(tixt_rx_single_coalesce_frames,
		   trustix_tixt_rx_single_coalesce_frames, ulong, 0444);
module_param_named(tixt_rx_single_coalesce_flushes,
		   trustix_tixt_rx_single_coalesce_flushes, ulong, 0444);
module_param_named(tixt_rx_single_coalesce_fallbacks,
		   trustix_tixt_rx_single_coalesce_fallbacks, ulong, 0444);
module_param_named(tixt_rx_single_coalesce_errors,
		   trustix_tixt_rx_single_coalesce_errors, ulong, 0444);
module_param_named(tixt_rx_single_coalesce_xmit_errors,
		   trustix_tixt_rx_single_coalesce_xmit_errors, ulong, 0444);
module_param_named(tixt_rx_single_coalesce_collisions,
		   trustix_tixt_rx_single_coalesce_collisions, ulong, 0444);
module_param_named(tixt_rx_single_coalesce_hash_misses,
		   trustix_tixt_rx_single_coalesce_hash_misses, ulong, 0444);
module_param_named(tixt_rx_single_coalesce_seq_misses,
		   trustix_tixt_rx_single_coalesce_seq_misses, ulong, 0444);
module_param_named(tixt_rx_single_coalesce_dev_misses,
		   trustix_tixt_rx_single_coalesce_dev_misses, ulong, 0444);
module_param_named(tixt_rx_single_coalesce_flow_misses,
		   trustix_tixt_rx_single_coalesce_flow_misses, ulong, 0444);
module_param_named(tixt_rx_single_coalesce_header_misses,
		   trustix_tixt_rx_single_coalesce_header_misses, ulong, 0444);
module_param_named(tixt_rx_single_coalesce_gso_size_misses,
		   trustix_tixt_rx_single_coalesce_gso_size_misses, ulong,
		   0444);
module_param_named(tixt_rx_single_coalesce_ack_variations,
		   trustix_tixt_rx_single_coalesce_ack_variations, ulong,
		   0444);
module_param_named(tixt_rx_single_coalesce_window_variations,
		   trustix_tixt_rx_single_coalesce_window_variations, ulong,
		   0444);
module_param_named(tixt_rx_single_coalesce_flags_variations,
		   trustix_tixt_rx_single_coalesce_flags_variations, ulong,
		   0444);
module_param_named(tixt_rx_single_coalesce_tcp_csum_skipped,
		   trustix_tixt_rx_single_coalesce_tcp_csum_skipped, ulong,
		   0444);
module_param_named(tixt_rx_single_coalesce_tcp_csum_computed,
		   trustix_tixt_rx_single_coalesce_tcp_csum_computed, ulong,
		   0444);
module_param_named(tixt_rx_single_coalesce_direct_list_batches,
		   trustix_tixt_rx_single_coalesce_direct_list_batches,
		   ulong, 0444);
module_param_named(tixt_rx_single_coalesce_direct_list_frames,
		   trustix_tixt_rx_single_coalesce_direct_list_frames,
		   ulong, 0444);
module_param_named(tixt_rx_single_coalesce_direct_list_errors,
		   trustix_tixt_rx_single_coalesce_direct_list_errors,
		   ulong, 0444);
module_param_named(tixt_rx_single_coalesce_direct_list_fallbacks,
		   trustix_tixt_rx_single_coalesce_direct_list_fallbacks,
		   ulong, 0444);
module_param_named(tixt_rx_single_coalesce_nonlinear_batches,
		   trustix_tixt_rx_single_coalesce_nonlinear_batches, ulong,
		   0444);
module_param_named(tixt_rx_single_coalesce_nonlinear_frags,
		   trustix_tixt_rx_single_coalesce_nonlinear_frags, ulong,
		   0444);
module_param_named(tixt_rx_single_coalesce_nonlinear_errors,
		   trustix_tixt_rx_single_coalesce_nonlinear_errors, ulong,
		   0444);
module_param_named(tixt_rx_single_coalesce_page_transfer_batches,
		   trustix_tixt_rx_single_coalesce_page_transfer_batches,
		   ulong, 0444);
module_param_named(tixt_rx_single_coalesce_page_transfer_pages,
		   trustix_tixt_rx_single_coalesce_page_transfer_pages,
		   ulong, 0444);
module_param_named(tixt_rx_single_coalesce_page_transfer_bytes,
		   trustix_tixt_rx_single_coalesce_page_transfer_bytes,
		   ulong, 0444);
module_param_named(tixt_rx_single_coalesce_page_only_batches,
		   trustix_tixt_rx_single_coalesce_page_only_batches,
		   ulong, 0444);
module_param_named(tixt_rx_single_coalesce_page_only_pages,
		   trustix_tixt_rx_single_coalesce_page_only_pages,
		   ulong, 0444);
module_param_named(tixt_rx_single_coalesce_page_only_bytes,
		   trustix_tixt_rx_single_coalesce_page_only_bytes,
		   ulong, 0444);
module_param_named(tixt_rx_single_coalesce_page_only_errors,
		   trustix_tixt_rx_single_coalesce_page_only_errors,
		   ulong, 0444);
module_param_named(tixt_rx_single_coalesce_linear_build_batches,
		   trustix_tixt_rx_single_coalesce_linear_build_batches,
		   ulong, 0444);
module_param_named(tixt_rx_single_coalesce_linear_build_bytes,
		   trustix_tixt_rx_single_coalesce_linear_build_bytes,
		   ulong, 0444);
module_param_named(tixt_rx_single_coalesce_linear_build_fallbacks,
		   trustix_tixt_rx_single_coalesce_linear_build_fallbacks,
		   ulong, 0444);
module_param_named(tixt_rx_single_coalesce_linear_build_errors,
		   trustix_tixt_rx_single_coalesce_linear_build_errors,
		   ulong, 0444);
module_param_named(tixt_rx_single_coalesce_linear_max_bytes,
		   trustix_tixt_rx_single_coalesce_linear_max_bytes,
		   ulong, 0444);
module_param_named(tixt_rx_single_coalesce_hybrid_head_batches,
		   trustix_tixt_rx_single_coalesce_hybrid_head_batches,
		   ulong, 0444);
module_param_named(tixt_rx_single_coalesce_hybrid_head_bytes,
		   trustix_tixt_rx_single_coalesce_hybrid_head_bytes,
		   ulong, 0444);
module_param_named(tixt_rx_single_coalesce_netif_rx_packets,
		   trustix_tixt_rx_single_coalesce_netif_rx_packets,
		   ulong, 0444);
module_param_named(tixt_rx_single_coalesce_netif_rx_drops,
		   trustix_tixt_rx_single_coalesce_netif_rx_drops, ulong,
		   0444);
module_param_named(tixt_rx_single_coalesce_schedules,
		   trustix_tixt_rx_single_coalesce_schedules, ulong, 0444);
module_param_named(tixt_rx_single_coalesce_schedule_skips,
		   trustix_tixt_rx_single_coalesce_schedule_skips, ulong, 0444);
module_param_named(tixt_rx_single_coalesce_warmup_passes,
		   trustix_tixt_rx_single_coalesce_warmup_passes, ulong,
		   0444);
module_param_named(tixt_rx_single_coalesce_stream_fallbacks,
		   trustix_tixt_rx_single_coalesce_stream_fallbacks, ulong,
		   0444);
module_param_named(tixt_rx_single_coalesce_stream_fallback_frames,
		   trustix_tixt_rx_single_coalesce_stream_fallback_frames,
		   ulong, 0444);
module_param_named(tixt_rx_single_coalesce_defer_full_flushes,
		   trustix_tixt_rx_single_coalesce_defer_full_flushes,
		   ulong, 0444);
module_param_named(tixt_rx_single_coalesce_full_cancel_skips,
		   trustix_tixt_rx_single_coalesce_full_cancel_skips,
		   ulong, 0444);
module_param_named(tixt_rx_single_coalesce_hash_sets,
		   trustix_tixt_rx_single_coalesce_hash_sets, ulong, 0444);
module_param_named(tixt_rx_single_coalesce_parse_bad_outer,
		   trustix_tixt_rx_single_coalesce_parse_bad_outer, ulong,
		   0444);
module_param_named(tixt_rx_single_coalesce_parse_short,
		   trustix_tixt_rx_single_coalesce_parse_short, ulong, 0444);
module_param_named(tixt_rx_single_coalesce_parse_bad_len,
		   trustix_tixt_rx_single_coalesce_parse_bad_len, ulong,
		   0444);
module_param_named(tixt_rx_single_coalesce_parse_not_tcp,
		   trustix_tixt_rx_single_coalesce_parse_not_tcp, ulong,
		   0444);
module_param_named(tixt_rx_single_coalesce_parse_fragment,
		   trustix_tixt_rx_single_coalesce_parse_fragment, ulong,
		   0444);
module_param_named(tixt_rx_single_coalesce_parse_totlen_mismatch,
		   trustix_tixt_rx_single_coalesce_parse_totlen_mismatch,
		   ulong, 0444);
module_param_named(tixt_rx_single_coalesce_parse_bad_tcp,
		   trustix_tixt_rx_single_coalesce_parse_bad_tcp, ulong,
		   0444);
module_param_named(tixt_rx_single_coalesce_parse_tcp_flags,
		   trustix_tixt_rx_single_coalesce_parse_tcp_flags, ulong,
		   0444);
module_param_named(tixt_rx_single_coalesce_parse_no_payload,
		   trustix_tixt_rx_single_coalesce_parse_no_payload, ulong,
		   0444);
module_param_named(tixt_rx_single_coalesce_last_inner_proto,
		   trustix_tixt_rx_single_coalesce_last_inner_proto, uint,
		   0444);
module_param_named(tixt_rx_single_coalesce_last_inner_len,
		   trustix_tixt_rx_single_coalesce_last_inner_len, uint,
		   0444);
module_param_named(tixt_rx_single_coalesce_last_inner_tot_len,
		   trustix_tixt_rx_single_coalesce_last_inner_tot_len, uint,
		   0444);
module_param_named(tixt_rx_single_coalesce_last_payload_len,
		   trustix_tixt_rx_single_coalesce_last_payload_len, uint,
		   0444);
module_param_named(tixt_rx_single_coalesce_last_tcp_header_len,
		   trustix_tixt_rx_single_coalesce_last_tcp_header_len, uint,
		   0444);

module_param_named(kudp_rx_parse_calls,
		   trustix_kudp_rx_parse_calls, ulong, 0444);
module_param_named(kudp_rx_parse_udp_calls,
		   trustix_kudp_rx_parse_udp_calls, ulong, 0444);
module_param_named(kudp_rx_parse_tcp_calls,
		   trustix_kudp_rx_parse_tcp_calls, ulong, 0444);
module_param_named(kudp_rx_parse_gso_packets,
		   trustix_kudp_rx_parse_gso_packets, ulong, 0444);
module_param_named(kudp_rx_parse_gso_segs,
		   trustix_kudp_rx_parse_gso_segs, ulong, 0444);
module_param_named(kudp_rx_parse_udp_gso_fraglist,
		   trustix_kudp_rx_parse_udp_gso_fraglist, ulong, 0444);
module_param_named(kudp_rx_parse_len_bytes,
		   trustix_kudp_rx_parse_len_bytes, ulong, 0444);
module_param_named(kudp_rx_parse_headlen_bytes,
		   trustix_kudp_rx_parse_headlen_bytes, ulong, 0444);
module_param_named(kudp_rx_parse_nonlinear_packets,
		   trustix_kudp_rx_parse_nonlinear_packets, ulong, 0444);
module_param_named(kudp_rx_parse_ret_einval,
		   trustix_kudp_rx_parse_ret_einval, ulong, 0444);
module_param_named(kudp_rx_parse_ret_emsgsize,
		   trustix_kudp_rx_parse_ret_emsgsize, ulong, 0444);
module_param_named(kudp_rx_parse_ret_ebadmsg,
		   trustix_kudp_rx_parse_ret_ebadmsg, ulong, 0444);
module_param_named(kudp_rx_parse_ret_enodata,
		   trustix_kudp_rx_parse_ret_enodata, ulong, 0444);
module_param_named(kudp_rx_parse_ret_eacces,
		   trustix_kudp_rx_parse_ret_eacces, ulong, 0444);
module_param_named(kudp_rx_parse_ret_eproto,
		   trustix_kudp_rx_parse_ret_eproto, ulong, 0444);
module_param_named(kudp_rx_parse_ret_eprotonosupport,
		   trustix_kudp_rx_parse_ret_eprotonosupport, ulong, 0444);
module_param_named(kudp_rx_parse_ret_enodev,
		   trustix_kudp_rx_parse_ret_enodev, ulong, 0444);
module_param_named(kudp_rx_parse_ret_enomem,
		   trustix_kudp_rx_parse_ret_enomem, ulong, 0444);
module_param_named(kudp_rx_parse_ret_other,
		   trustix_kudp_rx_parse_ret_other, ulong, 0444);
module_param_named(kudp_rx_decap_calls,
		   trustix_kudp_rx_decap_calls, ulong, 0444);
module_param_named(kudp_rx_decap_gso_packets,
		   trustix_kudp_rx_decap_gso_packets, ulong, 0444);
module_param_named(kudp_rx_decap_gso_preserved,
		   trustix_kudp_rx_decap_gso_preserved, ulong, 0444);
module_param_named(kudp_rx_decap_gso_reset,
		   trustix_kudp_rx_decap_gso_reset, ulong, 0444);
module_param_named(kudp_rx_decap_len_bytes,
		   trustix_kudp_rx_decap_len_bytes, ulong, 0444);
module_param_named(kudp_rx_decap_ret_einval,
		   trustix_kudp_rx_decap_ret_einval, ulong, 0444);
module_param_named(kudp_rx_decap_ret_emsgsize,
		   trustix_kudp_rx_decap_ret_emsgsize, ulong, 0444);
module_param_named(kudp_rx_decap_ret_ebadmsg,
		   trustix_kudp_rx_decap_ret_ebadmsg, ulong, 0444);
module_param_named(kudp_rx_decap_ret_enodata,
		   trustix_kudp_rx_decap_ret_enodata, ulong, 0444);
module_param_named(kudp_rx_decap_ret_eacces,
		   trustix_kudp_rx_decap_ret_eacces, ulong, 0444);
module_param_named(kudp_rx_decap_ret_eproto,
		   trustix_kudp_rx_decap_ret_eproto, ulong, 0444);
module_param_named(kudp_rx_decap_ret_eprotonosupport,
		   trustix_kudp_rx_decap_ret_eprotonosupport, ulong, 0444);
module_param_named(kudp_rx_decap_ret_enodev,
		   trustix_kudp_rx_decap_ret_enodev, ulong, 0444);
module_param_named(kudp_rx_decap_ret_enomem,
		   trustix_kudp_rx_decap_ret_enomem, ulong, 0444);
module_param_named(kudp_rx_decap_ret_other,
		   trustix_kudp_rx_decap_ret_other, ulong, 0444);
module_param_named(kudp_rx_last_gso_size,
		   trustix_kudp_rx_last_gso_size, uint, 0444);
module_param_named(kudp_rx_last_gso_segs,
		   trustix_kudp_rx_last_gso_segs, uint, 0444);
module_param_named(kudp_rx_last_gso_type,
		   trustix_kudp_rx_last_gso_type, uint, 0444);
module_param_named(kudp_rx_last_skb_len,
		   trustix_kudp_rx_last_skb_len, uint, 0444);
module_param_named(kudp_rx_max_skb_len,
		   trustix_kudp_rx_max_skb_len, uint, 0444);
module_param_named(kudp_rx_max_headlen,
		   trustix_kudp_rx_max_headlen, uint, 0444);

static __always_inline bool trustix_tixt_tx_plain_skip_sequence_enabled(void)
{
	return READ_ONCE(trustix_tixt_tx_plain_skip_sequence);
}

static __always_inline u64 trustix_tixt_tx_plain_wire_sequence(u64 sequence)
{
	if (trustix_tixt_tx_plain_skip_sequence_enabled())
		return 0;
	return sequence;
}

static __always_inline bool trustix_tixt_tx_plain_ack_only_enabled(void)
{
	return READ_ONCE(trustix_tixt_tx_plain_ack_only);
}

static __always_inline unsigned int
trustix_route_tcp_xmit_worker_queue_limit_value(void)
{
	unsigned int limit = READ_ONCE(trustix_route_tcp_xmit_worker_queue_limit);

	return limit ? limit : 1;
}

static __always_inline unsigned int
trustix_route_tcp_xmit_worker_budget_value(void)
{
	unsigned int budget = READ_ONCE(trustix_route_tcp_xmit_worker_budget);

	return budget ? budget : 1;
}

static __always_inline unsigned int
trustix_route_tcp_gso_async_stream_max_frames_value(void)
{
	unsigned int max_frames =
		READ_ONCE(trustix_route_tcp_gso_async_stream_max_frames);

	if (!max_frames)
		return 1;
	if (max_frames > TRUSTIX_TIXT_TX_ROUTE_SYNC_STREAM_MAX_FRAMES)
		return TRUSTIX_TIXT_TX_ROUTE_SYNC_STREAM_MAX_FRAMES;
	return max_frames;
}

static __always_inline unsigned int
trustix_route_tcp_gso_sync_stream_max_frames_value(void)
{
	unsigned int max_frames =
		READ_ONCE(trustix_route_tcp_gso_sync_stream_max_frames);

	if (!max_frames)
		return 1;
	if (max_frames > TRUSTIX_TIXT_TX_ROUTE_SYNC_STREAM_MAX_FRAMES)
		return TRUSTIX_TIXT_TX_ROUTE_SYNC_STREAM_MAX_FRAMES;
	return max_frames;
}

static __always_inline unsigned int
trustix_route_tcp_gso_async_stream_cross_item_max_frames_value(
				unsigned int stream_max_frames)
{
	unsigned int max_frames = READ_ONCE(
		trustix_route_tcp_gso_async_stream_cross_item_max_frames);

	if (!max_frames)
		return stream_max_frames;
	if (max_frames < 2)
		max_frames = 2;
	if (max_frames > TRUSTIX_TIXT_TX_ROUTE_STREAM_MAX_FRAMES)
		max_frames = TRUSTIX_TIXT_TX_ROUTE_STREAM_MAX_FRAMES;
	return min(max_frames, stream_max_frames);
}

static __always_inline unsigned int
trustix_route_tcp_gso_async_stream_cross_item_dynamic_low_frames_value(
				unsigned int max_frames)
{
	unsigned int low_frames = READ_ONCE(
		trustix_route_tcp_gso_async_stream_cross_item_dynamic_low_frames);

	if (!low_frames)
		return 0;
	if (low_frames < 2)
		low_frames = 2;
	if (low_frames > TRUSTIX_TIXT_TX_ROUTE_STREAM_MAX_FRAMES)
		low_frames = TRUSTIX_TIXT_TX_ROUTE_STREAM_MAX_FRAMES;
	return min(low_frames, max_frames);
}

static __always_inline bool trustix_route_tcp_gso_async_hot_stats_enabled(void)
{
	return READ_ONCE(trustix_route_tcp_gso_async_hot_stats);
}

static __always_inline unsigned int trustix_tixt_rx_stream_max_frames_value(void)
{
	unsigned int max_frames = READ_ONCE(trustix_tixt_rx_stream_max_frames);

	if (!max_frames)
		return 1;
	if (max_frames > TRUSTIX_TIXT_RX_STREAM_MAX_FRAMES)
		return TRUSTIX_TIXT_RX_STREAM_MAX_FRAMES;
	return max_frames;
}

static __always_inline bool trustix_kudp_rx_hot_stats_enabled(void)
{
	return READ_ONCE(trustix_kudp_rx_hot_stats);
}

static void trustix_kudp_rx_record_shape(struct sk_buff *skb, u32 outer_protocol)
{
	struct skb_shared_info *shinfo;
	unsigned int headlen;

	if (!trustix_kudp_rx_hot_stats_enabled() || !skb)
		return;
	shinfo = skb_shinfo(skb);
	headlen = skb_headlen(skb);
	trustix_kudp_rx_parse_calls++;
	if (outer_protocol == IPPROTO_UDP)
		trustix_kudp_rx_parse_udp_calls++;
	else if (outer_protocol == IPPROTO_TCP)
		trustix_kudp_rx_parse_tcp_calls++;
	if (shinfo->gso_size) {
		trustix_kudp_rx_parse_gso_packets++;
		trustix_kudp_rx_parse_gso_segs += shinfo->gso_segs;
	}
#ifdef SKB_GSO_FRAGLIST
	if (shinfo->gso_type & SKB_GSO_FRAGLIST)
		trustix_kudp_rx_parse_udp_gso_fraglist++;
#endif
	if (skb_is_nonlinear(skb))
		trustix_kudp_rx_parse_nonlinear_packets++;
	trustix_kudp_rx_parse_len_bytes += skb->len;
	trustix_kudp_rx_parse_headlen_bytes += headlen;
	WRITE_ONCE(trustix_kudp_rx_last_gso_size, shinfo->gso_size);
	WRITE_ONCE(trustix_kudp_rx_last_gso_segs, shinfo->gso_segs);
	WRITE_ONCE(trustix_kudp_rx_last_gso_type, shinfo->gso_type);
	WRITE_ONCE(trustix_kudp_rx_last_skb_len, skb->len);
	if (skb->len > READ_ONCE(trustix_kudp_rx_max_skb_len))
		WRITE_ONCE(trustix_kudp_rx_max_skb_len, skb->len);
	if (headlen > READ_ONCE(trustix_kudp_rx_max_headlen))
		WRITE_ONCE(trustix_kudp_rx_max_headlen, headlen);
}

static int trustix_kudp_rx_record_parse_ret(int ret)
{
	if (!trustix_kudp_rx_hot_stats_enabled() || !ret)
		return ret;
	switch (ret) {
	case -EINVAL:
		trustix_kudp_rx_parse_ret_einval++;
		break;
	case -EMSGSIZE:
		trustix_kudp_rx_parse_ret_emsgsize++;
		break;
	case -EBADMSG:
		trustix_kudp_rx_parse_ret_ebadmsg++;
		break;
	case -ENODATA:
		trustix_kudp_rx_parse_ret_enodata++;
		break;
	case -EACCES:
		trustix_kudp_rx_parse_ret_eacces++;
		break;
	case -EPROTO:
		trustix_kudp_rx_parse_ret_eproto++;
		break;
	case -EPROTONOSUPPORT:
		trustix_kudp_rx_parse_ret_eprotonosupport++;
		break;
	case -ENODEV:
		trustix_kudp_rx_parse_ret_enodev++;
		break;
	case -ENOMEM:
		trustix_kudp_rx_parse_ret_enomem++;
		break;
	default:
		trustix_kudp_rx_parse_ret_other++;
		break;
	}
	return ret;
}

static int trustix_kudp_rx_record_decap_ret(int ret)
{
	if (!trustix_kudp_rx_hot_stats_enabled() || !ret)
		return ret;
	switch (ret) {
	case -EINVAL:
		trustix_kudp_rx_decap_ret_einval++;
		break;
	case -EMSGSIZE:
		trustix_kudp_rx_decap_ret_emsgsize++;
		break;
	case -EBADMSG:
		trustix_kudp_rx_decap_ret_ebadmsg++;
		break;
	case -ENODATA:
		trustix_kudp_rx_decap_ret_enodata++;
		break;
	case -EACCES:
		trustix_kudp_rx_decap_ret_eacces++;
		break;
	case -EPROTO:
		trustix_kudp_rx_decap_ret_eproto++;
		break;
	case -EPROTONOSUPPORT:
		trustix_kudp_rx_decap_ret_eprotonosupport++;
		break;
	case -ENODEV:
		trustix_kudp_rx_decap_ret_enodev++;
		break;
	case -ENOMEM:
		trustix_kudp_rx_decap_ret_enomem++;
		break;
	default:
		trustix_kudp_rx_decap_ret_other++;
		break;
	}
	return ret;
}

static __always_inline int trustix_skb_ensure_push_head(struct sk_buff *skb,
							u32 push_len)
{
	if (unlikely(skb_headroom(skb) < push_len || skb_header_cloned(skb))) {
		if (skb_cow_head(skb, push_len))
			return -ENOMEM;
	}
	return 0;
}

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

static __always_inline void trustix_skb_clear_csum_metadata(struct sk_buff *skb)
{
	skb->ip_summed = CHECKSUM_NONE;
	skb->csum = 0;
	skb->csum_start = 0;
	skb->csum_offset = 0;
	skb->csum_level = 0;
}

static __always_inline __sum16
trustix_ipv4_l4_partial_check_from_ip_base(u16 ip_check_base, u32 l4_len)
{
	u32 sum = ip_check_base;

	sum += 0xffffU ^ 0x4500U;
	sum += 0xffffU ^ 0x4000U;
	sum += 0xffffU ^ 0x4000U;
	sum += l4_len;
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return (__sum16)htons((u16)sum);
}

static bool trustix_skb_preserve_inner_tcpv4_gso(struct sk_buff *skb)
{
	struct skb_shared_info *shinfo;
	struct iphdr *iph;
	struct tcphdr *tcph;
	u32 tcp_offset;
	u32 payload_len;
	u32 tcp_len;
	u32 tcp_hlen;
	u32 total_len;
	u32 need;
	u32 ihl;
	u32 segs;

	if (!skb)
		return false;
	shinfo = skb_shinfo(skb);
	if (!shinfo->gso_size)
		return false;

	need = ETH_HLEN + sizeof(*iph);
	if (skb->len < need)
		return false;
	if (unlikely(!pskb_may_pull(skb, need)) || need > skb_headlen(skb))
		return false;

	iph = (struct iphdr *)(skb->data + ETH_HLEN);
	if (iph->version != 4 || iph->ihl < 5 ||
	    iph->protocol != IPPROTO_TCP ||
	    (iph->frag_off & htons(0x3fff)))
		return false;

	ihl = iph->ihl * 4;
	tcp_offset = ETH_HLEN + ihl;
	need = tcp_offset + sizeof(*tcph);
	if (skb->len < need)
		return false;
	if (unlikely(!pskb_may_pull(skb, need)) || need > skb_headlen(skb))
		return false;

	iph = (struct iphdr *)(skb->data + ETH_HLEN);
	tcph = (struct tcphdr *)(skb->data + tcp_offset);
	total_len = ntohs(iph->tot_len);
	tcp_hlen = tcph->doff * 4;
	if (tcp_hlen < sizeof(*tcph) || total_len < ihl + tcp_hlen)
		return false;
	if (skb->len < ETH_HLEN + total_len)
		return false;

	tcp_len = total_len - ihl;
	payload_len = tcp_len - tcp_hlen;
	if (!payload_len)
		return false;

	segs = DIV_ROUND_UP(payload_len, shinfo->gso_size);
	if (!segs || segs > U16_MAX)
		return false;
	if (!shinfo->gso_segs)
		shinfo->gso_segs = segs;

	shinfo->gso_type |= SKB_GSO_TCPV4;
	shinfo->gso_type &= ~SKB_GSO_TCPV6;
#ifdef SKB_GSO_UDP_TUNNEL
	shinfo->gso_type &= ~SKB_GSO_UDP_TUNNEL;
#endif
#ifdef SKB_GSO_UDP_TUNNEL_CSUM
	shinfo->gso_type &= ~SKB_GSO_UDP_TUNNEL_CSUM;
#endif
#ifdef SKB_GSO_TUNNEL_REMCSUM
	shinfo->gso_type &= ~SKB_GSO_TUNNEL_REMCSUM;
#endif
#ifdef SKB_GSO_PARTIAL
	shinfo->gso_type &= ~SKB_GSO_PARTIAL;
#endif
	skb_set_transport_header(skb, tcp_offset);
	skb_reset_inner_headers(skb);
	return true;
}

static void trustix_tixt_rx_coalesced_mark_tcpv4_gso(struct sk_buff *skb,
						     u32 gso_size,
						     unsigned int gso_segs)
{
	struct skb_shared_info *shinfo;
	struct iphdr *iph;
	struct tcphdr *tcph;

	if (!skb || !gso_size || gso_segs < 2)
		return;
	if (skb->len < sizeof(*iph) + sizeof(*tcph))
		return;
	if (sizeof(*iph) + sizeof(*tcph) > skb_headlen(skb))
		return;

	iph = (struct iphdr *)skb_network_header(skb);
	tcph = (struct tcphdr *)skb_transport_header(skb);
	if (iph->version != 4 || iph->ihl != 5 ||
	    iph->protocol != IPPROTO_TCP || tcph->doff < 5)
		return;

	shinfo = skb_shinfo(skb);
	shinfo->gso_size = gso_size;
	shinfo->gso_type = SKB_GSO_TCPV4;
	shinfo->gso_segs = gso_segs;
	skb->mac_len = ETH_HLEN;
	skb_reset_inner_headers(skb);

	if (READ_ONCE(trustix_tixt_rx_coalesce_mark_gso_partial_csum))
		trustix_tixt_rx_coalesce_partial_csum_fallbacks++;
}

static int __maybe_unused trustix_tixt_rx_coalesced_prepare_tcpv4_gso_partial(
	struct sk_buff *skb)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	u32 ip_len;
	u32 tcp_len;
	u32 tcp_hlen;

	if (!skb || !skb_is_gso(skb))
		return -EINVAL;
	if (skb->len < ETH_HLEN + sizeof(*iph) + sizeof(*tcph))
		return -EINVAL;
	if (!pskb_may_pull(skb, ETH_HLEN + sizeof(*iph) + sizeof(*tcph)) ||
	    skb_headlen(skb) < ETH_HLEN + sizeof(*iph) + sizeof(*tcph))
		return -ENODATA;
	iph = (struct iphdr *)skb_network_header(skb);
	tcph = (struct tcphdr *)skb_transport_header(skb);
	if (iph->version != 4 || iph->ihl != 5 ||
	    iph->protocol != IPPROTO_TCP || tcph->doff < 5 ||
	    (iph->frag_off & htons(0x3fff)))
		return -EPROTONOSUPPORT;
	ip_len = ntohs(iph->tot_len);
	tcp_hlen = tcph->doff * 4;
	if (ip_len < sizeof(*iph) + tcp_hlen ||
	    ip_len > skb->len - ETH_HLEN)
		return -EMSGSIZE;
	tcp_len = ip_len - sizeof(*iph);
	tcph->check = ~csum_tcpudp_magic(iph->saddr, iph->daddr,
					 tcp_len, IPPROTO_TCP, 0);
	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum_start = skb_transport_header(skb) - skb->head;
	skb->csum_offset = offsetof(struct tcphdr, check);
	return 0;
}

static void trustix_tixt_rx_free_receive_list(struct list_head *head)
{
	struct sk_buff *skb;
	struct sk_buff *tmp;

	list_for_each_entry_safe(skb, tmp, head, list) {
		list_del_init(&skb->list);
		kfree_skb(skb);
	}
}

static unsigned int trustix_tixt_rx_backlog_worker_queue_limit_value(void)
{
	unsigned int value = READ_ONCE(trustix_tixt_rx_backlog_worker_queue_limit);

	if (!value)
		return 1;
	if (value > 65536)
		return 65536;
	return value;
}

static unsigned int trustix_tixt_rx_backlog_worker_budget_value(void)
{
	unsigned int value = READ_ONCE(trustix_tixt_rx_backlog_worker_budget);

	if (!value)
		return 1;
	if (value > 65536)
		return 65536;
	return value;
}

static void trustix_tixt_rx_backlog_worker_fn(struct work_struct *work)
{
	struct sk_buff *skb;
	bool reschedule = false;
	unsigned int budget = trustix_tixt_rx_backlog_worker_budget_value();
	unsigned int done = 0;
	int ret;

	trustix_tixt_rx_backlog_worker_runs++;
	while (done < budget && (skb = skb_dequeue(
		       &trustix_tixt_rx_backlog_worker_queue)) != NULL) {
		ret = netif_receive_skb(skb);
		if (ret == NET_RX_DROP)
			trustix_tixt_rx_backlog_worker_drops++;
		else
			trustix_tixt_rx_backlog_worker_delivered++;
		done++;
	}

	spin_lock_bh(&trustix_tixt_rx_backlog_worker_queue.lock);
	WRITE_ONCE(trustix_tixt_rx_backlog_worker_depth,
		   skb_queue_len(&trustix_tixt_rx_backlog_worker_queue));
	if (skb_queue_empty(&trustix_tixt_rx_backlog_worker_queue)) {
		WRITE_ONCE(trustix_tixt_rx_backlog_worker_scheduled, false);
	} else {
		reschedule = true;
	}
	spin_unlock_bh(&trustix_tixt_rx_backlog_worker_queue.lock);

	if (reschedule)
		schedule_work(&trustix_tixt_rx_backlog_work);
}

static void trustix_tixt_rx_backlog_worker_flush(void)
{
	struct sk_buff *skb;

	cancel_work_sync(&trustix_tixt_rx_backlog_work);
	while ((skb = skb_dequeue(&trustix_tixt_rx_backlog_worker_queue)) != NULL) {
		trustix_tixt_rx_backlog_worker_drops++;
		kfree_skb(skb);
	}
	WRITE_ONCE(trustix_tixt_rx_backlog_worker_depth, 0);
	WRITE_ONCE(trustix_tixt_rx_backlog_worker_scheduled, false);
}

static int trustix_tixt_rx_publish_one_backlog(struct sk_buff *skb,
					      unsigned long *packets,
					      unsigned long *drops)
{
	bool schedule_worker;

	if (!skb)
		return -EINVAL;
	skb->next = NULL;
	INIT_LIST_HEAD(&skb->list);
	if (READ_ONCE(trustix_tixt_rx_backlog_worker_quiescing) ||
	    !READ_ONCE(trustix_datapath_helpers_registered)) {
		trustix_tixt_rx_backlog_worker_disabled++;
		if (drops)
			(*drops)++;
		kfree_skb(skb);
		return -EOPNOTSUPP;
	}

	spin_lock_bh(&trustix_tixt_rx_backlog_worker_queue.lock);
	if (skb_queue_len(&trustix_tixt_rx_backlog_worker_queue) >=
	    trustix_tixt_rx_backlog_worker_queue_limit_value()) {
		spin_unlock_bh(&trustix_tixt_rx_backlog_worker_queue.lock);
		trustix_tixt_rx_backlog_worker_queue_full++;
		if (drops)
			(*drops)++;
		kfree_skb(skb);
		return -EIO;
	}
	schedule_worker = !READ_ONCE(trustix_tixt_rx_backlog_worker_scheduled);
	if (schedule_worker)
		WRITE_ONCE(trustix_tixt_rx_backlog_worker_scheduled, true);
	__skb_queue_tail(&trustix_tixt_rx_backlog_worker_queue, skb);
	WRITE_ONCE(trustix_tixt_rx_backlog_worker_depth,
		   skb_queue_len(&trustix_tixt_rx_backlog_worker_queue));
	spin_unlock_bh(&trustix_tixt_rx_backlog_worker_queue.lock);

	trustix_tixt_rx_backlog_worker_enqueued++;
	if (packets)
		(*packets)++;
	if (schedule_worker)
		schedule_work(&trustix_tixt_rx_backlog_work);
	return 0;
}

static unsigned int
trustix_tixt_rx_publish_skb_chain_backlog(struct sk_buff *head,
					  unsigned long *packets,
					  unsigned long *drops)
{
	struct sk_buff *next;
	struct sk_buff *drop_head = NULL;
	struct sk_buff *drop_tail = NULL;
	unsigned int count = 0;
	unsigned int depth;
	unsigned int limit;
	bool schedule_worker;

	if (!head)
		return 0;
	if (READ_ONCE(trustix_tixt_rx_backlog_worker_quiescing) ||
	    !READ_ONCE(trustix_datapath_helpers_registered)) {
		while (head) {
			next = head->next;
			head->next = NULL;
			trustix_tixt_rx_backlog_worker_disabled++;
			if (drops)
				(*drops)++;
			kfree_skb(head);
			head = next;
			count++;
		}
		return count;
	}

	limit = trustix_tixt_rx_backlog_worker_queue_limit_value();
	spin_lock_bh(&trustix_tixt_rx_backlog_worker_queue.lock);
	depth = skb_queue_len(&trustix_tixt_rx_backlog_worker_queue);
	schedule_worker = !READ_ONCE(trustix_tixt_rx_backlog_worker_scheduled);
	if (schedule_worker)
		WRITE_ONCE(trustix_tixt_rx_backlog_worker_scheduled, true);

	while (head) {
		next = head->next;
		head->next = NULL;
		head->prev = NULL;
		INIT_LIST_HEAD(&head->list);
		if (depth >= limit) {
			trustix_tixt_rx_backlog_worker_queue_full++;
			if (drops)
				(*drops)++;
			if (!drop_head)
				drop_head = head;
			else
				drop_tail->next = head;
			drop_tail = head;
			count++;
			head = next;
			continue;
		}
		__skb_queue_tail(&trustix_tixt_rx_backlog_worker_queue, head);
		depth++;
		trustix_tixt_rx_backlog_worker_enqueued++;
		if (packets)
			(*packets)++;
		head = next;
		count++;
	}
	WRITE_ONCE(trustix_tixt_rx_backlog_worker_depth, depth);
	spin_unlock_bh(&trustix_tixt_rx_backlog_worker_queue.lock);

	while (drop_head) {
		next = drop_head->next;
		drop_head->next = NULL;
		kfree_skb(drop_head);
		drop_head = next;
	}
	if (schedule_worker)
		schedule_work(&trustix_tixt_rx_backlog_work);
	return count;
}

static unsigned int
trustix_tixt_rx_publish_receive_list_backlog(struct list_head *rx_list,
					     unsigned long *packets,
					     unsigned long *drops)
{
	struct sk_buff *skb;
	struct sk_buff *tmp;
	LIST_HEAD(drop_list);
	unsigned int count = 0;
	unsigned int depth;
	unsigned int limit;
	bool schedule_worker;

	if (!rx_list || list_empty(rx_list))
		return 0;
	if (READ_ONCE(trustix_tixt_rx_backlog_worker_quiescing) ||
	    !READ_ONCE(trustix_datapath_helpers_registered)) {
		list_for_each_entry_safe(skb, tmp, rx_list, list) {
			list_del_init(&skb->list);
			trustix_tixt_rx_backlog_worker_disabled++;
			if (drops)
				(*drops)++;
			kfree_skb(skb);
			count++;
		}
		return count;
	}

	limit = trustix_tixt_rx_backlog_worker_queue_limit_value();
	spin_lock_bh(&trustix_tixt_rx_backlog_worker_queue.lock);
	depth = skb_queue_len(&trustix_tixt_rx_backlog_worker_queue);
	schedule_worker = !READ_ONCE(trustix_tixt_rx_backlog_worker_scheduled);
	if (schedule_worker)
		WRITE_ONCE(trustix_tixt_rx_backlog_worker_scheduled, true);

	list_for_each_entry_safe(skb, tmp, rx_list, list) {
		list_del_init(&skb->list);
		if (depth >= limit) {
			trustix_tixt_rx_backlog_worker_queue_full++;
			if (drops)
				(*drops)++;
			list_add_tail(&skb->list, &drop_list);
			count++;
			continue;
		}
		__skb_queue_tail(&trustix_tixt_rx_backlog_worker_queue, skb);
		depth++;
		trustix_tixt_rx_backlog_worker_enqueued++;
		if (packets)
			(*packets)++;
		count++;
	}
	WRITE_ONCE(trustix_tixt_rx_backlog_worker_depth, depth);
	spin_unlock_bh(&trustix_tixt_rx_backlog_worker_queue.lock);

	trustix_tixt_rx_free_receive_list(&drop_list);
	if (schedule_worker)
		schedule_work(&trustix_tixt_rx_backlog_work);
	return count;
}

static __sum16 trustix_ipv4_header_check20(const u8 *iph);

static int trustix_tixt_rx_prepare_segment_for_receive(struct sk_buff *skb,
						       struct net_device *dev,
						       const u8 l2[ETH_HLEN])
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	u32 ip_len;
	u32 ihl;
	u32 tcp_hlen;

	if (!skb || !dev || !l2)
		return -EINVAL;

	skb->dev = dev;
	skb->next = NULL;
	skb->prev = NULL;
	skb_dst_drop(skb);
	skb_orphan(skb);
	memset(skb->cb, 0, sizeof(skb->cb));

	if (skb->len >= ETH_HLEN + sizeof(struct iphdr) &&
	    pskb_may_pull(skb, ETH_HLEN + sizeof(struct iphdr)) &&
	    get_unaligned_be16(skb->data + offsetof(struct ethhdr, h_proto)) ==
		    ETH_P_IP &&
	    (skb->data[ETH_HLEN] >> 4) == 4) {
		skb_reset_mac_header(skb);
	} else if (skb->len >= sizeof(struct iphdr) &&
		   pskb_may_pull(skb, sizeof(struct iphdr)) &&
		   (skb->data[0] >> 4) == 4) {
		if (skb_cow_head(skb, ETH_HLEN))
			return -ENOMEM;
		memcpy(skb_push(skb, ETH_HLEN), l2, ETH_HLEN);
		skb_reset_mac_header(skb);
	} else {
		return -EPROTONOSUPPORT;
	}

	skb->protocol = eth_type_trans(skb, dev);
	if (skb->protocol != htons(ETH_P_IP))
		return -EPROTONOSUPPORT;
	skb_reset_network_header(skb);
	if (skb->len < sizeof(*iph) ||
	    !pskb_may_pull(skb, sizeof(*iph)) ||
	    sizeof(*iph) > skb_headlen(skb))
		return -ENODATA;

	iph = ip_hdr(skb);
	if (iph->version != 4 || iph->ihl < 5 ||
	    iph->protocol != IPPROTO_TCP ||
	    (iph->frag_off & htons(0x3fff)))
		return -EPROTONOSUPPORT;
	ihl = iph->ihl * 4;
	if (ihl < sizeof(*iph) || skb->len < ihl + sizeof(*tcph) ||
	    !pskb_may_pull(skb, ihl + sizeof(*tcph)) ||
	    ihl + sizeof(*tcph) > skb_headlen(skb))
		return -ENODATA;

	iph = ip_hdr(skb);
	ip_len = ntohs(iph->tot_len);
	if (ip_len < ihl + sizeof(*tcph) || ip_len > skb->len)
		return -EMSGSIZE;
	if (ip_len < skb->len)
		skb_trim(skb, ip_len);

	skb_set_transport_header(skb, ihl);
	tcph = tcp_hdr(skb);
	tcp_hlen = tcph->doff * 4;
	if (tcp_hlen < sizeof(*tcph) || ip_len < ihl + tcp_hlen)
		return -EPROTONOSUPPORT;

	if (skb_is_gso(skb))
		skb_gso_reset(skb);
	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		int ret = skb_checksum_help(skb);

		if (ret)
			return ret;
	}

	skb->skb_iif = dev->ifindex;
	skb->pkt_type = PACKET_HOST;
	skb->encapsulation = 0;
	skb->csum = 0;
	skb->csum_start = 0;
	skb->csum_offset = 0;
	skb->csum_level = 0;
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	return 0;
}

static int trustix_tixt_rx_coalesced_segment_and_publish(struct sk_buff *skb,
							 struct net_device *dev,
							 u32 fallback_gso_size,
							 unsigned int frames)
{
	LIST_HEAD(rx_list);
	struct sk_buff *seg;
	struct skb_shared_info *shinfo;
	struct iphdr *iph;
	struct tcphdr *tcph;
	u8 l2[ETH_HLEN];
	u32 ip_header_len;
	u32 tcp_header_len;
	u32 total_len;
	u32 tcp_len;
	u32 payload_len;
	u32 payload_offset = 0;
	u32 gso_size;
	u32 seq;
	unsigned int count = 0;
	unsigned int expected;
	int ret;

	if (!skb || !dev)
		return -EINVAL;
	if (!READ_ONCE(trustix_tixt_rx_coalesce_segment_gso))
		return 0;
	if (skb_headroom(skb) < ETH_HLEN) {
		trustix_tixt_rx_coalesce_segment_errors++;
		kfree_skb(skb);
		return -EINVAL;
	}

	skb_push(skb, ETH_HLEN);
	skb_reset_mac_header(skb);
	skb_set_network_header(skb, ETH_HLEN);
	skb_set_transport_header(skb, ETH_HLEN + sizeof(struct iphdr));
	skb->mac_len = ETH_HLEN;
	skb->protocol = htons(ETH_P_IP);
	memcpy(l2, skb->data, ETH_HLEN);

	if (skb->len < ETH_HLEN + sizeof(*iph) + sizeof(*tcph) ||
	    !pskb_may_pull(skb, ETH_HLEN + sizeof(*iph) + sizeof(*tcph)) ||
	    skb_headlen(skb) < ETH_HLEN + sizeof(*iph) + sizeof(*tcph)) {
		trustix_tixt_rx_coalesce_segment_errors++;
		kfree_skb(skb);
		return -ENODATA;
	}
	iph = (struct iphdr *)(skb->data + ETH_HLEN);
	if (iph->version != 4 || iph->ihl != 5 ||
	    iph->protocol != IPPROTO_TCP ||
	    (iph->frag_off & htons(0x3fff))) {
		trustix_tixt_rx_coalesce_segment_errors++;
		kfree_skb(skb);
		return -EPROTONOSUPPORT;
	}
	ip_header_len = iph->ihl * 4;
	if (skb->len < ETH_HLEN + ip_header_len + sizeof(*tcph) ||
	    !pskb_may_pull(skb, ETH_HLEN + ip_header_len + sizeof(*tcph)) ||
	    skb_headlen(skb) < ETH_HLEN + ip_header_len + sizeof(*tcph)) {
		trustix_tixt_rx_coalesce_segment_errors++;
		kfree_skb(skb);
		return -ENODATA;
	}
	iph = (struct iphdr *)(skb->data + ETH_HLEN);
	tcph = (struct tcphdr *)(skb->data + ETH_HLEN + ip_header_len);
	tcp_header_len = tcph->doff * 4;
	total_len = ntohs(iph->tot_len);
	if (tcp_header_len < sizeof(*tcph) || tcp_header_len > 60 ||
	    total_len < ip_header_len + tcp_header_len ||
	    total_len > skb->len - ETH_HLEN) {
		trustix_tixt_rx_coalesce_segment_errors++;
		kfree_skb(skb);
		return -EMSGSIZE;
	}
	tcp_len = total_len - ip_header_len;
	payload_len = tcp_len - tcp_header_len;
	shinfo = skb_shinfo(skb);
	gso_size = shinfo->gso_size ? shinfo->gso_size : fallback_gso_size;
	if (!payload_len || !gso_size || gso_size > payload_len) {
		trustix_tixt_rx_coalesce_segment_errors++;
		kfree_skb(skb);
		return -EINVAL;
	}
	expected = DIV_ROUND_UP(payload_len, gso_size);
	if (expected < 2 || expected > TRUSTIX_TIXT_RX_STREAM_MAX_FRAMES) {
		trustix_tixt_rx_coalesce_segment_errors++;
		kfree_skb(skb);
		return -EINVAL;
	}
	seq = ntohl(tcph->seq);

	while (payload_offset < payload_len) {
		struct iphdr *seg_iph;
		struct tcphdr *seg_tcph;
		u32 seg_payload_len;
		u32 seg_inner_len;
		u8 *dst;
		__wsum sum;

		seg_payload_len = min_t(u32, payload_len - payload_offset,
					gso_size);
		if (check_add_overflow(ip_header_len + tcp_header_len,
				       seg_payload_len, &seg_inner_len) ||
		    seg_inner_len > 0xffff) {
			ret = -EMSGSIZE;
			goto fail;
		}
		seg = netdev_alloc_skb_ip_align(dev, ETH_HLEN + seg_inner_len);
		if (!seg) {
			ret = -ENOMEM;
			goto fail;
		}
		skb_reserve(seg, ETH_HLEN);
		dst = skb_put(seg, seg_inner_len);
		memcpy(dst, iph, ip_header_len + tcp_header_len);
		ret = skb_copy_bits(skb,
				    ETH_HLEN + ip_header_len +
					    tcp_header_len + payload_offset,
				    dst + ip_header_len + tcp_header_len,
				    seg_payload_len);
		if (ret) {
			kfree_skb(seg);
			goto fail;
		}

		seg_iph = (struct iphdr *)dst;
		seg_tcph = (struct tcphdr *)(dst + ip_header_len);
		seg_iph->tot_len = htons((u16)seg_inner_len);
		seg_iph->id = htons(ntohs(iph->id) + count);
		seg_iph->check = 0;
		seg_iph->check = trustix_ipv4_header_check20((const u8 *)seg_iph);
		seg_tcph->seq = htonl(seq + payload_offset);
		seg_tcph->check = 0;
		sum = csum_partial(seg_tcph,
				   tcp_header_len + seg_payload_len, 0);
		seg_tcph->check = csum_tcpudp_magic(
			seg_iph->saddr, seg_iph->daddr,
			tcp_header_len + seg_payload_len, IPPROTO_TCP, sum);

		ret = trustix_tixt_rx_prepare_segment_for_receive(seg, dev, l2);
		if (ret) {
			kfree_skb(seg);
			goto fail;
		}
		INIT_LIST_HEAD(&seg->list);
		list_add_tail(&seg->list, &rx_list);
		count++;
		payload_offset += seg_payload_len;
	}
	kfree_skb(skb);
	if (!count) {
		trustix_tixt_rx_coalesce_segment_errors++;
		return -EIO;
	}
	trustix_tixt_rx_publish_receive_list_backlog(
		&rx_list, &trustix_tixt_rx_coalesce_segment_backlog_packets,
		&trustix_tixt_rx_coalesce_segment_backlog_drops);
	trustix_tixt_rx_coalesce_segment_batches++;
	trustix_tixt_rx_coalesce_segment_frames += frames ? frames : count;
	return count;

fail:
	kfree_skb(skb);
	trustix_tixt_rx_free_receive_list(&rx_list);
	trustix_tixt_rx_coalesce_segment_errors++;
	return ret ? ret : -EIO;
}

static __always_inline u32 trustix_csum_add_be16_buf(u32 sum, const u8 *src,
						     u32 len)
{
	while (len > 1) {
		sum += get_unaligned_be16(src);
		src += 2;
		len -= 2;
	}
	if (len)
		sum += (u32)*src << 8;
	return sum;
}

static __always_inline u32 trustix_csum_add_ipv4_pair(u32 sum, __be32 saddr,
						      __be32 daddr)
{
	u32 src = ntohl(saddr);
	u32 dst = ntohl(daddr);

	sum += src >> 16;
	sum += src & 0xffff;
	sum += dst >> 16;
	sum += dst & 0xffff;
	return sum;
}

static __always_inline u16 trustix_csum_fold16(u32 sum)
{
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (u16)~sum;
}

static __always_inline u16 trustix_ipv4_l4_pseudo_csum(__be32 saddr,
						       __be32 daddr,
						       u8 protocol, u32 len)
{
	u32 sum = 0;

	sum = trustix_csum_add_ipv4_pair(sum, saddr, daddr);
	sum += protocol;
	sum += len;
	return trustix_csum_fold16(sum);
}

static __always_inline void
trustix_kudp_tx_write_udp_header(u8 *dst,
				 const struct trustix_kudp_tx_udp_header_args *args,
				 bool partial_csum)
{
	struct iphdr *iph;
	struct udphdr *udph;
	u8 *kudp;
	u32 sum;
	u16 check;

	memcpy(dst, args->l2, ETH_HLEN);

	iph = (struct iphdr *)(dst + ETH_HLEN);
	memset(iph, 0, sizeof(*iph));
	iph->version = 4;
	iph->ihl = 5;
	iph->tot_len = htons(args->ip_tot_len);
	iph->frag_off = htons(0x4000);
	iph->ttl = 64;
	iph->protocol = IPPROTO_UDP;
	iph->saddr = args->saddr;
	iph->daddr = args->daddr;
	sum = args->ip_check_base;
	sum += args->ip_tot_len;
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	check = ~sum;
	if (!check)
		check = 0xffff;
	iph->check = htons(check);

	udph = (struct udphdr *)(dst + ETH_HLEN + sizeof(*iph));
	udph->source = args->source;
	udph->dest = args->dest;
	udph->len = htons(args->udp_len);
	if (partial_csum)
		udph->check = trustix_ipv4_l4_partial_check_from_ip_base(
			args->ip_check_base, args->udp_len);
	else
		udph->check = 0;

	kudp = (u8 *)(udph + 1);
	put_unaligned_be32(TRUSTIX_KUDP_MAGIC, kudp);
	kudp[4] = 1;
	kudp[5] = TRUSTIX_KUDP_FLAG_INNER_IPV4 | (u8)args->flags;
	put_unaligned_be16(TRUSTIX_KUDP_HEADER_LEN, kudp + 6);
	put_unaligned_be64(args->flow_id, kudp + 8);
	put_unaligned_be64(args->sequence, kudp + 16);
	put_unaligned_be32(args->payload_len, kudp + 24);
	put_unaligned_be16(0, kudp + 28);
	put_unaligned_be16(0, kudp + 30);
}

static __always_inline void
trustix_tixt_tx_write_tcp_header(u8 *dst,
				 const struct trustix_tixt_tx_tcp_header_args *args,
				 bool partial_csum, bool full_csum)
{
	u8 *iph;
	u8 *tcph;
	u8 *tixt;
	u32 tcp_len;
	u32 sum;
	u16 check;
	__sum16 tcp_check;

	memcpy(dst, args->l2, ETH_HLEN);

	iph = dst + ETH_HLEN;
	put_unaligned_be16(0x4500, iph);
	put_unaligned_be16(args->ip_tot_len,
			   iph + offsetof(struct iphdr, tot_len));
	put_unaligned_be16(0, iph + offsetof(struct iphdr, id));
	put_unaligned_be16(0x4000, iph + offsetof(struct iphdr, frag_off));
	*(iph + offsetof(struct iphdr, ttl)) = 64;
	*(iph + offsetof(struct iphdr, protocol)) = IPPROTO_TCP;
	put_unaligned(args->saddr,
		      (__be32 *)(iph + offsetof(struct iphdr, saddr)));
	put_unaligned(args->daddr,
		      (__be32 *)(iph + offsetof(struct iphdr, daddr)));
	sum = args->ip_check_base;
	sum += args->ip_tot_len;
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	check = ~sum;
	if (!check)
		check = 0xffff;
	put_unaligned_be16(check, iph + offsetof(struct iphdr, check));

	tcph = iph + sizeof(struct iphdr);
	put_unaligned(args->source,
		      (__be16 *)(tcph + offsetof(struct tcphdr, source)));
	put_unaligned(args->dest,
		      (__be16 *)(tcph + offsetof(struct tcphdr, dest)));
	put_unaligned_be32((u32)args->sequence,
			   tcph + offsetof(struct tcphdr, seq));
	put_unaligned_be32(1, tcph + offsetof(struct tcphdr, ack_seq));
	if (trustix_tixt_tx_plain_ack_only_enabled())
		put_unaligned_be16(0x5010, tcph + 12);
	else
		put_unaligned_be16(0x5018, tcph + 12);
	put_unaligned_be16(0xffff, tcph + offsetof(struct tcphdr, window));
	put_unaligned_be16(0, tcph + offsetof(struct tcphdr, check));
	put_unaligned_be16(0, tcph + offsetof(struct tcphdr, urg_ptr));

	tixt = tcph + sizeof(struct tcphdr);
	put_unaligned_be32(TRUSTIX_TIXT_MAGIC, tixt);
	tixt[4] = 1;
	tixt[5] = TRUSTIX_TIXT_FLAG_INNER_IPV4 | (u8)args->flags;
	put_unaligned_be16(TRUSTIX_TIXT_HEADER_LEN, tixt + 6);
	put_unaligned_be64(args->flow_id, tixt + 8);
	put_unaligned_be64(0, tixt + 16);
	put_unaligned_be64(args->sequence, tixt + 24);
	put_unaligned_be32(args->payload_len, tixt + 32);
	put_unaligned_be16(0, tixt + 36);
	put_unaligned_be16(0, tixt + 38);

	tcp_len = sizeof(struct tcphdr) + TRUSTIX_TIXT_HEADER_LEN +
		  args->payload_len;
	if (partial_csum) {
		tcp_check = trustix_ipv4_l4_partial_check_from_ip_base(
			args->ip_check_base, tcp_len);
		put_unaligned(tcp_check,
			      (__sum16 *)(tcph + offsetof(struct tcphdr,
							  check)));
	} else if (full_csum) {
		tcp_check = csum_tcpudp_magic(args->saddr, args->daddr,
					      tcp_len, IPPROTO_TCP,
					      csum_partial(tcph, tcp_len, 0));
		put_unaligned(tcp_check,
			      (__sum16 *)(tcph + offsetof(struct tcphdr,
							  check)));
	}
}

static __always_inline void
trustix_tixt_tx_write_flow_tcp_header(
				u8 *dst,
				const struct trustix_kudp_tx_flow_value *flow,
				u64 flow_id, u64 sequence, u32 payload_len,
				u16 ip_tot_len, bool partial_csum)
{
	u8 *iph;
	u8 *tcph;
	u8 *tixt;
	u32 tcp_len;
	u32 sum;
	u16 check;
	u16 ip_check_base;
	__sum16 tcp_check;
	u16 tail1;

	memcpy(dst, &flow->destination_mac0, sizeof(flow->destination_mac0));
	memcpy(dst + 4, &flow->destination_mac1,
	       sizeof(flow->destination_mac1));
	memcpy(dst + 6, &flow->source_mac0, sizeof(flow->source_mac0));
	memcpy(dst + 10, &flow->source_mac1, sizeof(flow->source_mac1));
	tail1 = htons(ETH_P_IP);
	memcpy(dst + 12, &tail1, sizeof(tail1));

	iph = dst + ETH_HLEN;
	put_unaligned_be16(0x4500, iph);
	put_unaligned_be16(ip_tot_len, iph + offsetof(struct iphdr, tot_len));
	put_unaligned_be16(0, iph + offsetof(struct iphdr, id));
	put_unaligned_be16(0x4000, iph + offsetof(struct iphdr, frag_off));
	*(iph + offsetof(struct iphdr, ttl)) = 64;
	*(iph + offsetof(struct iphdr, protocol)) = IPPROTO_TCP;
	put_unaligned(flow->saddr,
		      (__be32 *)(iph + offsetof(struct iphdr, saddr)));
	put_unaligned(flow->daddr,
		      (__be32 *)(iph + offsetof(struct iphdr, daddr)));
	ip_check_base = READ_ONCE(flow->ipv4_check_tcp);
	sum = ip_check_base;
	sum += ip_tot_len;
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	check = ~sum;
	if (!check)
		check = 0xffff;
	put_unaligned_be16(check, iph + offsetof(struct iphdr, check));

	tcph = iph + sizeof(struct iphdr);
	put_unaligned(flow->source,
		      (__be16 *)(tcph + offsetof(struct tcphdr, source)));
	put_unaligned(flow->dest,
		      (__be16 *)(tcph + offsetof(struct tcphdr, dest)));
	put_unaligned_be32((u32)sequence, tcph + offsetof(struct tcphdr, seq));
	put_unaligned_be32(1, tcph + offsetof(struct tcphdr, ack_seq));
	if (trustix_tixt_tx_plain_ack_only_enabled())
		put_unaligned_be16(0x5010, tcph + 12);
	else
		put_unaligned_be16(0x5018, tcph + 12);
	put_unaligned_be16(0xffff, tcph + offsetof(struct tcphdr, window));
	put_unaligned_be16(0, tcph + offsetof(struct tcphdr, check));
	put_unaligned_be16(0, tcph + offsetof(struct tcphdr, urg_ptr));

	tixt = tcph + sizeof(struct tcphdr);
	put_unaligned_be32(TRUSTIX_TIXT_MAGIC, tixt);
	tixt[4] = 1;
	tixt[5] = TRUSTIX_TIXT_FLAG_INNER_IPV4;
	put_unaligned_be16(TRUSTIX_TIXT_HEADER_LEN, tixt + 6);
	put_unaligned_be64(flow_id, tixt + 8);
	put_unaligned_be64(0, tixt + 16);
	put_unaligned_be64(sequence, tixt + 24);
	put_unaligned_be32(payload_len, tixt + 32);
	put_unaligned_be16(0, tixt + 36);
	put_unaligned_be16(0, tixt + 38);

	tcp_len = sizeof(struct tcphdr) + TRUSTIX_TIXT_HEADER_LEN +
		  payload_len;
	if (partial_csum) {
		tcp_check = trustix_ipv4_l4_partial_check_from_ip_base(
			ip_check_base, tcp_len);
	} else {
		tcp_check = csum_tcpudp_magic(flow->saddr, flow->daddr,
					      tcp_len, IPPROTO_TCP,
					      csum_partial(tcph, tcp_len, 0));
	}
	put_unaligned(tcp_check,
		      (__sum16 *)(tcph + offsetof(struct tcphdr, check)));
}

static bool
trustix_tixt_tx_trusted_inner_tcp_csum(
				struct sk_buff *skb,
				const struct trustix_tixt_tx_tcp_header_args *args,
				u32 header_len, u32 tcp_len)
{
	const struct iphdr *inner_iph;
	const struct tcphdr *inner_tcph;
	const struct udphdr *inner_udph;
	struct tcphdr *outer_tcph;
	u32 inner_needed = header_len + sizeof(struct iphdr);
	u32 inner_l4_len;
	u32 sum = 0;

	if (!skb || !args || args->payload_len < sizeof(struct iphdr))
		return false;
	if (unlikely(!pskb_may_pull(skb, inner_needed)))
		return false;
	if (inner_needed > skb_headlen(skb))
		return false;

	inner_iph = (const struct iphdr *)(skb->data + header_len);
	if (inner_iph->version != 4 || inner_iph->ihl != 5 ||
	    ntohs(inner_iph->tot_len) != args->payload_len ||
	    (inner_iph->frag_off & htons(0x3fff)))
		return false;
	inner_l4_len = args->payload_len - sizeof(*inner_iph);

	switch (inner_iph->protocol) {
	case IPPROTO_TCP:
		if (inner_l4_len < sizeof(struct tcphdr))
			return false;
		inner_needed = header_len + sizeof(struct iphdr) +
			       sizeof(struct tcphdr);
		if (unlikely(!pskb_may_pull(skb, inner_needed)) ||
		    inner_needed > skb_headlen(skb))
			return false;
		inner_iph = (const struct iphdr *)(skb->data + header_len);
		inner_tcph = (const struct tcphdr *)(inner_iph + 1);
		if (!inner_tcph->check)
			return false;
		break;
	case IPPROTO_UDP:
		if (inner_l4_len < sizeof(struct udphdr))
			return false;
		inner_needed = header_len + sizeof(struct iphdr) +
			       sizeof(struct udphdr);
		if (unlikely(!pskb_may_pull(skb, inner_needed)) ||
		    inner_needed > skb_headlen(skb))
			return false;
		inner_iph = (const struct iphdr *)(skb->data + header_len);
		inner_udph = (const struct udphdr *)(inner_iph + 1);
		if (ntohs(inner_udph->len) != inner_l4_len ||
		    !inner_udph->check)
			return false;
		break;
	default:
		return false;
	}

	outer_tcph = (struct tcphdr *)(skb->data + ETH_HLEN +
				       sizeof(struct iphdr));
	outer_tcph->check = 0;
	sum = trustix_csum_add_ipv4_pair(sum, args->saddr, args->daddr);
	sum += IPPROTO_TCP;
	sum += tcp_len;
	sum = trustix_csum_add_be16_buf(sum, (const u8 *)outer_tcph,
					sizeof(struct tcphdr) +
					TRUSTIX_TIXT_HEADER_LEN);
	sum = trustix_csum_add_be16_buf(sum, (const u8 *)inner_iph,
					sizeof(struct iphdr));
	sum += trustix_ipv4_l4_pseudo_csum(inner_iph->saddr,
					   inner_iph->daddr,
					   inner_iph->protocol,
					   inner_l4_len);
	outer_tcph->check = htons(trustix_csum_fold16(sum));
	return true;
}

__bpf_kfunc_start_defs();

__bpf_kfunc int trustix_kernel_skb_clear_tx_offload(struct sk_buff *skb,
						    u32 flags)
{
	if (!skb)
		return -EINVAL;
	if (flags & TRUSTIX_SKB_CLEAR_TX_OFFLOAD_CSUM)
		trustix_skb_clear_csum_metadata(skb);
	if (flags & TRUSTIX_SKB_CLEAR_TX_OFFLOAD_ENCAP)
		skb->encapsulation = 0;
	if (flags & TRUSTIX_SKB_CLEAR_TX_OFFLOAD_GSO)
		skb_gso_reset(skb);
	return 0;
}

__bpf_kfunc int trustix_kernel_skb_fix_inner_tcp_csum(struct sk_buff *skb,
						      u32 inner_ip_offset,
						      u32 inner_len, u32 flags)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	u32 tcp_offset;
	u32 tcp_len;
	__wsum sum;
	int ret;

	if (!skb || flags)
		return -EINVAL;
	if (inner_len < sizeof(struct iphdr) + sizeof(struct tcphdr) ||
	    inner_len > 1500)
		return -EINVAL;
	if (inner_ip_offset > U16_MAX ||
	    inner_ip_offset + inner_len < inner_ip_offset ||
	    inner_ip_offset + inner_len > skb->len)
		return -EINVAL;
	if (unlikely(!pskb_may_pull(skb, inner_ip_offset + sizeof(*iph))))
		return -EINVAL;

	iph = (struct iphdr *)(skb->data + inner_ip_offset);
	if (iph->version != 4 || iph->ihl != 5 || iph->protocol != IPPROTO_TCP)
		return -EPROTONOSUPPORT;
	if (ntohs(iph->tot_len) != inner_len)
		return -EINVAL;
	if (iph->frag_off & htons(0x3fff))
		return -EINVAL;

	tcp_offset = inner_ip_offset + sizeof(*iph);
	if (unlikely(!pskb_may_pull(skb, tcp_offset + sizeof(*tcph))) ||
	    tcp_offset + sizeof(*tcph) > skb_headlen(skb))
		return -EINVAL;
	ret = trustix_skb_ensure_writable_head(skb, tcp_offset + sizeof(*tcph));
	if (ret)
		return ret;

	iph = (struct iphdr *)(skb->data + inner_ip_offset);
	tcph = (struct tcphdr *)(skb->data + tcp_offset);
	tcp_len = inner_len - sizeof(*iph);
	if (tcph->doff < 5 || tcp_len < tcph->doff * 4)
		return -EINVAL;
	if (tcp_offset + tcp_len < tcp_offset ||
	    tcp_offset + tcp_len > skb->len)
		return -EINVAL;

	tcph->check = 0;
	sum = skb_checksum(skb, tcp_offset, tcp_len, 0);
	tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, tcp_len,
					IPPROTO_TCP, sum);
	trustix_skb_clear_csum_metadata(skb);
	skb->encapsulation = 0;
	return 1;
}

static int trustix_tixt_tx_fix_inner_l4_csum(struct sk_buff *skb,
					     u32 inner_ip_offset,
					     u32 inner_len)
{
	struct udphdr *udph;
	struct iphdr *iph;
	struct tcphdr *tcph;
	u32 l4_offset;
	u32 l4_len;
	u32 ihl;
	__wsum sum;
	__sum16 check;
	int ret;

	if (!skb)
		return -EINVAL;
	if (inner_len < sizeof(struct iphdr) || inner_len > 1500)
		return -EPROTONOSUPPORT;
	if (inner_ip_offset > U16_MAX ||
	    inner_ip_offset + inner_len < inner_ip_offset ||
	    inner_ip_offset + inner_len > skb->len)
		return -EINVAL;
	if (unlikely(!pskb_may_pull(skb, inner_ip_offset + sizeof(*iph))) ||
	    inner_ip_offset + sizeof(*iph) > skb_headlen(skb))
		return -EPROTONOSUPPORT;

	iph = (struct iphdr *)(skb->data + inner_ip_offset);
	if (iph->version != 4 || iph->ihl < 5)
		return -EPROTONOSUPPORT;
	ihl = iph->ihl * 4;
	if (ihl < sizeof(*iph) || inner_len < ihl ||
	    ntohs(iph->tot_len) != inner_len ||
	    (iph->frag_off & htons(0x3fff)))
		return -EPROTONOSUPPORT;
	l4_offset = inner_ip_offset + ihl;
	l4_len = inner_len - ihl;

	switch (iph->protocol) {
	case IPPROTO_TCP:
		if (l4_len < sizeof(*tcph))
			return -EPROTONOSUPPORT;
		if (unlikely(!pskb_may_pull(skb, l4_offset + sizeof(*tcph))) ||
		    l4_offset + sizeof(*tcph) > skb_headlen(skb))
			return -EPROTONOSUPPORT;
		ret = trustix_skb_ensure_writable_head(skb,
						       l4_offset + sizeof(*tcph));
		if (ret)
			return ret;
		iph = (struct iphdr *)(skb->data + inner_ip_offset);
		tcph = (struct tcphdr *)(skb->data + l4_offset);
		if (tcph->doff < 5 || l4_len < tcph->doff * 4)
			return -EPROTONOSUPPORT;
		ret = trustix_skb_ensure_writable_head(skb,
						       l4_offset + tcph->doff * 4);
		if (ret)
			return ret;
		iph = (struct iphdr *)(skb->data + inner_ip_offset);
		tcph = (struct tcphdr *)(skb->data + l4_offset);
		tcph->check = 0;
		sum = skb_checksum(skb, l4_offset, l4_len, 0);
		tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
						l4_len, IPPROTO_TCP, sum);
		trustix_skb_clear_csum_metadata(skb);
		skb->encapsulation = 0;
		return 1;
	case IPPROTO_UDP:
		if (l4_len < sizeof(*udph))
			return -EPROTONOSUPPORT;
		if (unlikely(!pskb_may_pull(skb, l4_offset + sizeof(*udph))) ||
		    l4_offset + sizeof(*udph) > skb_headlen(skb))
			return -EPROTONOSUPPORT;
		ret = trustix_skb_ensure_writable_head(skb,
						       l4_offset + sizeof(*udph));
		if (ret)
			return ret;
		iph = (struct iphdr *)(skb->data + inner_ip_offset);
		udph = (struct udphdr *)(skb->data + l4_offset);
		if (ntohs(udph->len) != l4_len)
			return -EPROTONOSUPPORT;
		if (!udph->check && skb->ip_summed != CHECKSUM_PARTIAL)
			return 0;
		udph->check = 0;
		sum = skb_checksum(skb, l4_offset, l4_len, 0);
		check = csum_tcpudp_magic(iph->saddr, iph->daddr, l4_len,
					  IPPROTO_UDP, sum);
		udph->check = check ? check : CSUM_MANGLED_0;
		trustix_skb_clear_csum_metadata(skb);
		skb->encapsulation = 0;
		return 1;
	default:
		if (skb->ip_summed == CHECKSUM_PARTIAL) {
			ret = skb_checksum_help(skb);
			if (ret)
				return ret;
		}
		return 0;
	}
}

static void trustix_write_l2_header(u8 *dst, u64 l2_head, u32 l2_tail0,
				    u32 l2_tail1)
{
	u16 tail1 = (u16)l2_tail1;

	memcpy(dst, &l2_head, sizeof(l2_head));
	memcpy(dst + 8, &l2_tail0, sizeof(l2_tail0));
	memcpy(dst + 12, &tail1, sizeof(tail1));
}

static int trustix_skb_kudp_rx_decap_l2_inner(struct sk_buff *skb,
					      u32 outer_len, u64 l2_head,
					      u32 l2_tail0, u32 l2_tail1,
					      u32 flags)
{
	struct iphdr *iph;
	u32 min_pull;
	u32 write_len;
	u8 *dst;
	bool trust_inner_l4_checksum = false;
	int ret;

	if (!skb)
		return -EINVAL;
	if (flags & ~TRUSTIX_KUDP_RX_DECAP_L2_TRUST_INNER_L4_CSUM)
		return -EINVAL;
	if (outer_len < sizeof(struct iphdr) || outer_len > 256)
		return -EINVAL;
	if (check_add_overflow((u32)ETH_HLEN + outer_len,
			       (u32)sizeof(struct iphdr), &min_pull))
		return -EINVAL;
	if (check_add_overflow(outer_len, (u32)ETH_HLEN, &write_len))
		return -EINVAL;
	if (skb->len < min_pull)
		return -EINVAL;
	if (unlikely(min_pull > skb_headlen(skb) &&
		     !pskb_may_pull(skb, min_pull)))
		return -EINVAL;
	ret = trustix_skb_ensure_writable_head(skb, write_len);
	if (ret)
		return ret;

	dst = skb->data + outer_len;
	trustix_write_l2_header(dst, l2_head, l2_tail0, l2_tail1);

	if (unlikely(!skb_pull(skb, outer_len)))
		return -EINVAL;

	skb_reset_mac_header(skb);
	skb_set_network_header(skb, ETH_HLEN);
	if (skb_headlen(skb) >= ETH_HLEN + sizeof(*iph)) {
		iph = (struct iphdr *)(skb->data + ETH_HLEN);
		if (iph->version == 4 && iph->ihl >= 5 &&
		    skb->len >= ETH_HLEN + iph->ihl * 4) {
			u32 total_len = ntohs(iph->tot_len);
			u32 ihl = iph->ihl * 4;
			u32 l4_len;

			skb_set_transport_header(skb, ETH_HLEN + ihl);
			if ((flags & TRUSTIX_KUDP_RX_DECAP_L2_TRUST_INNER_L4_CSUM) &&
			    !(iph->frag_off & htons(0x3fff)) &&
			    total_len >= ihl &&
			    skb->len >= ETH_HLEN + total_len) {
				l4_len = total_len - ihl;
				if ((iph->protocol == IPPROTO_TCP &&
				     l4_len >= sizeof(struct tcphdr)) ||
				    (iph->protocol == IPPROTO_UDP &&
				     l4_len >= sizeof(struct udphdr)))
					trust_inner_l4_checksum = true;
			}
		}
	}
	skb->protocol = htons(ETH_P_IP);
	skb->ip_summed = trust_inner_l4_checksum ? CHECKSUM_UNNECESSARY :
						 CHECKSUM_NONE;
	skb->csum = 0;
	skb->encapsulation = 0;
	skb->csum_level = 0;
	skb->mac_len = ETH_HLEN;
	if (skb_shinfo(skb)->gso_size) {
		if (!trustix_skb_preserve_inner_tcpv4_gso(skb))
			skb_gso_reset(skb);
	}
	return 0;
}

static int trustix_skb_kudp_rx_decap_l2(struct sk_buff *skb, u32 outer_len,
					u64 l2_head, u32 l2_tail0,
					u32 l2_tail1, u32 flags)
{
	struct skb_shared_info *shinfo;
	bool had_gso = false;
	bool has_gso = false;
	int ret;

	if (trustix_kudp_rx_hot_stats_enabled() && skb) {
		shinfo = skb_shinfo(skb);
		had_gso = shinfo->gso_size != 0;
		trustix_kudp_rx_decap_calls++;
		trustix_kudp_rx_decap_len_bytes += skb->len;
		if (had_gso)
			trustix_kudp_rx_decap_gso_packets++;
	}
	ret = trustix_skb_kudp_rx_decap_l2_inner(skb, outer_len, l2_head,
						 l2_tail0, l2_tail1, flags);
	if (trustix_kudp_rx_hot_stats_enabled() && skb && !ret && had_gso) {
		has_gso = skb_shinfo(skb)->gso_size != 0;
		if (has_gso)
			trustix_kudp_rx_decap_gso_preserved++;
		else
			trustix_kudp_rx_decap_gso_reset++;
	}
	return trustix_kudp_rx_record_decap_ret(ret);
}

static bool trustix_tixt_tcp_outer_has_extra_tail(const struct sk_buff *skb,
						  u32 ip_len)
{
	u32 ip_end;

	if (!skb)
		return false;
	if (check_add_overflow((u32)ETH_HLEN, ip_len, &ip_end))
		return true;
	return skb->len > ip_end;
}

static bool trustix_tixt_tcp_outer_has_stream_tail(const struct sk_buff *skb,
						   u32 ip_len)
{
	u8 magic_buf[sizeof(u32)];
	const u8 *tail;
	u32 ip_end;
	u32 tail_len;

	if (!skb)
		return false;
	if (check_add_overflow((u32)ETH_HLEN, ip_len, &ip_end))
		return false;
	if (skb->len <= ip_end)
		return false;
	tail_len = skb->len - ip_end;
	if (tail_len < TRUSTIX_TIXT_HEADER_LEN + sizeof(struct iphdr))
		return false;
	tail = skb_header_pointer(skb, ip_end, sizeof(magic_buf),
				  magic_buf);
	if (!tail)
		return false;
	return get_unaligned_be32(tail) == TRUSTIX_TIXT_MAGIC;
}

static bool trustix_tixt_rx_tcp_outer_needs_stream_parse(struct sk_buff *skb)
{
	struct skb_shared_info *shinfo;
	u8 magic_buf[sizeof(u32)];
	const u8 *magic;
	u32 payload_offset;
	u32 payload_len;
	u32 ip_len;
	u8 *data;

	if (!skb)
		return false;
	if (skb->len < ETH_HLEN + sizeof(struct iphdr) + sizeof(struct tcphdr) ||
	    skb_headlen(skb) < ETH_HLEN + sizeof(struct iphdr) + sizeof(struct tcphdr))
		return false;
	data = skb->data;
	if (get_unaligned_be16(data + 12) != ETH_P_IP ||
	    data[ETH_HLEN] != 0x45 ||
	    data[ETH_HLEN + offsetof(struct iphdr, protocol)] != IPPROTO_TCP)
		return false;
	ip_len = get_unaligned_be16(data + ETH_HLEN +
				    offsetof(struct iphdr, tot_len));
	if (trustix_tixt_tcp_outer_has_stream_tail(skb, ip_len))
		return true;
	if (data[ETH_HLEN + sizeof(struct iphdr) + 12] != 0x50)
		return false;
	if (ip_len < sizeof(struct iphdr) + sizeof(struct tcphdr) +
		     TRUSTIX_TIXT_HEADER_LEN + sizeof(struct iphdr))
		return false;
	if (skb->len < ETH_HLEN + ip_len)
		return false;
	shinfo = skb_shinfo(skb);
	if (!shinfo->gso_size || shinfo->gso_segs < 2)
		return false;
	payload_len = ip_len - sizeof(struct iphdr) - sizeof(struct tcphdr);
	if (payload_len <= shinfo->gso_size ||
	    shinfo->gso_size < TRUSTIX_TIXT_HEADER_LEN + sizeof(struct iphdr))
		return false;
	payload_offset = ETH_HLEN + sizeof(struct iphdr) + sizeof(struct tcphdr);
	magic = skb_header_pointer(skb, payload_offset, sizeof(magic_buf),
				   magic_buf);
	if (!magic)
		return false;
	return get_unaligned_be32(magic) == TRUSTIX_TIXT_MAGIC;
}

static bool trustix_tixt_tcp_outer_extra_tail_is_single_gso(
					const struct sk_buff *skb,
					u32 payload_offset, u32 inner_len,
					const struct iphdr *inner_iph)
{
	const struct skb_shared_info *shinfo;
	u32 full_end;

	if (!skb || !inner_iph)
		return false;
	shinfo = skb_shinfo(skb);
	if (!shinfo->gso_size || inner_iph->protocol != IPPROTO_TCP)
		return false;
	if (check_add_overflow(payload_offset, inner_len, &full_end))
		return false;
	return full_end == skb->len;
}

static int
trustix_skb_kudp_rx_parse_plain(struct sk_buff *skb,
				const struct trustix_kudp_rx_parse_args *args,
				u32 outer_protocol, u32 *outer_len,
				u32 *next_hop)
{
	const struct iphdr *inner_iph;
	u32 min_len;
	u32 frame_offset;
	u32 frame_len;
	u32 l4_header_len;
	u32 payload_offset;
	u32 payload_len_field;
	u32 port_offset;
	u32 outer_overhead;
	u32 skb_len;
	u32 ip_len;
	u32 inner_len;
	u32 segment_len;
	u32 expected_len;
	u8 frame_flags;
	u8 *data;

	if (!skb || !args || !outer_len || !next_hop)
		return -EINVAL;
	if (args->flags & ~(TRUSTIX_KUDP_RX_PARSE_EXPERIMENTAL_TCP_ONLY |
			    TRUSTIX_KUDP_RX_PARSE_KERNEL_UDP_ONLY))
		return -EINVAL;
	if ((args->flags & TRUSTIX_KUDP_RX_PARSE_EXPERIMENTAL_TCP_ONLY) &&
	    (args->flags & TRUSTIX_KUDP_RX_PARSE_KERNEL_UDP_ONLY))
		return -EINVAL;
	if (outer_protocol != IPPROTO_UDP && outer_protocol != IPPROTO_TCP)
		return -EINVAL;
	if ((args->flags & TRUSTIX_KUDP_RX_PARSE_EXPERIMENTAL_TCP_ONLY) &&
	    outer_protocol != IPPROTO_TCP)
		return -EPROTONOSUPPORT;
	if ((args->flags & TRUSTIX_KUDP_RX_PARSE_KERNEL_UDP_ONLY) &&
	    outer_protocol != IPPROTO_UDP)
		return -EPROTONOSUPPORT;

	if (outer_protocol == IPPROTO_UDP) {
		frame_offset = ETH_HLEN + sizeof(struct iphdr) +
			       sizeof(struct udphdr);
		frame_len = TRUSTIX_KUDP_HEADER_LEN;
		l4_header_len = sizeof(struct udphdr);
		payload_offset = frame_offset + frame_len;
		payload_len_field = frame_offset + 24;
		port_offset = ETH_HLEN + sizeof(struct iphdr) +
			      offsetof(struct udphdr, dest);
		outer_overhead = sizeof(struct iphdr) + sizeof(struct udphdr) +
				 frame_len;
	} else {
		frame_offset = ETH_HLEN + sizeof(struct iphdr) +
			       sizeof(struct tcphdr);
		frame_len = TRUSTIX_TIXT_HEADER_LEN;
		l4_header_len = sizeof(struct tcphdr);
		payload_offset = frame_offset + frame_len;
		payload_len_field = frame_offset + 32;
		port_offset = ETH_HLEN + sizeof(struct iphdr) +
			      offsetof(struct tcphdr, dest);
		outer_overhead = sizeof(struct iphdr) + sizeof(struct tcphdr) +
				 frame_len;
	}
	min_len = payload_offset + sizeof(struct iphdr);
	if (skb->len < min_len)
		return -ENODATA;
	if (unlikely(min_len > skb_headlen(skb) &&
		     !pskb_may_pull(skb, min_len)))
		return -ENODATA;
	if (min_len > skb_headlen(skb))
		return -ENODATA;

	data = skb->data;
	if (get_unaligned_be16(data + 12) != ETH_P_IP)
		return -EPROTONOSUPPORT;
	if (data[ETH_HLEN] != 0x45)
		return -EPROTONOSUPPORT;
	if (get_unaligned_be16(data + ETH_HLEN +
			       offsetof(struct iphdr, frag_off)) & 0x3fff)
		return -EPROTONOSUPPORT;
	if (data[ETH_HLEN + offsetof(struct iphdr, protocol)] !=
	    outer_protocol)
		return -EPROTONOSUPPORT;
	ip_len = get_unaligned_be16(data + ETH_HLEN +
				    offsetof(struct iphdr, tot_len));
	if (ip_len < sizeof(struct iphdr) + l4_header_len + frame_len)
		return -EMSGSIZE;
	skb_len = skb->len;
	if (skb_len < ETH_HLEN + ip_len)
		return -EMSGSIZE;
	if (outer_protocol == IPPROTO_TCP &&
	    trustix_tixt_tcp_outer_has_stream_tail(skb, ip_len))
		return -EPROTONOSUPPORT;
	if (outer_protocol == IPPROTO_TCP &&
	    trustix_tixt_rx_tcp_outer_needs_stream_parse(skb))
		return -EPROTONOSUPPORT;

	if (outer_protocol == IPPROTO_UDP) {
		u16 udp_len = get_unaligned_be16(data + ETH_HLEN +
						 sizeof(struct iphdr) +
						 offsetof(struct udphdr, len));

		if (udp_len != ip_len - sizeof(struct iphdr))
			return -EPROTONOSUPPORT;
		if (get_unaligned_be32(data + frame_offset) !=
		    TRUSTIX_KUDP_MAGIC)
			return -EPROTONOSUPPORT;
		if (data[frame_offset + 4] != 1 ||
		    get_unaligned_be16(data + frame_offset + 6) != frame_len)
			return -EBADMSG;
		frame_flags = data[frame_offset + 5];
		if ((frame_flags & TRUSTIX_KUDP_FLAG_INNER_IPV4) !=
		    TRUSTIX_KUDP_FLAG_INNER_IPV4)
			return -EPROTONOSUPPORT;
		if (frame_flags & (TRUSTIX_KUDP_FLAG_ENCRYPTED |
				   TRUSTIX_KUDP_FLAG_CRYPTO_FRAGMENT))
			return -EPROTONOSUPPORT;
		if (frame_flags & ~(TRUSTIX_KUDP_FLAG_KERNEL_OPENED |
				    TRUSTIX_KUDP_FLAG_INNER_IPV4))
			return -EPROTONOSUPPORT;
	} else {
		if (data[ETH_HLEN + sizeof(struct iphdr) + 12] != 0x50)
			return -EPROTONOSUPPORT;
		if (get_unaligned_be32(data + frame_offset) !=
		    TRUSTIX_TIXT_MAGIC)
			return -EPROTONOSUPPORT;
		if (data[frame_offset + 4] != 1 ||
		    get_unaligned_be16(data + frame_offset + 6) != frame_len)
			return -EBADMSG;
		frame_flags = data[frame_offset + 5];
		if ((frame_flags & TRUSTIX_TIXT_FLAG_INNER_IPV4) !=
		    TRUSTIX_TIXT_FLAG_INNER_IPV4)
			return -EPROTONOSUPPORT;
		if (frame_flags & TRUSTIX_TIXT_FLAG_ENCRYPTED)
			return -EPROTONOSUPPORT;
		if (frame_flags & ~(TRUSTIX_TIXT_FLAG_KERNEL_OPENED |
				    TRUSTIX_TIXT_FLAG_INNER_IPV4))
			return -EPROTONOSUPPORT;
	}

	if (args->static_dest_port &&
	    get_unaligned_be16(data + port_offset) != args->static_dest_port)
		return -EACCES;

	inner_len = get_unaligned_be32(data + payload_len_field);
	if (inner_len < sizeof(struct iphdr))
		return -EMSGSIZE;
	if (payload_offset + sizeof(struct iphdr) > skb_headlen(skb))
		return -ENODATA;
	inner_iph = (const struct iphdr *)(data + payload_offset);
	if (inner_iph->version != 4 || inner_iph->ihl != 5)
		return -EBADMSG;
	if (outer_protocol == IPPROTO_TCP &&
	    trustix_tixt_tcp_outer_has_extra_tail(skb, ip_len) &&
	    !trustix_tixt_tcp_outer_extra_tail_is_single_gso(
		    skb, payload_offset, inner_len, inner_iph))
		return -EPROTONOSUPPORT;
	if (ntohs(inner_iph->tot_len) == inner_len) {
		segment_len = inner_len;
	} else {
		struct skb_shared_info *shinfo = skb_shinfo(skb);
		u32 tcp_header_len;

		if (!shinfo->gso_size || inner_iph->protocol != IPPROTO_TCP)
			return -EMSGSIZE;
		if (payload_offset + sizeof(struct iphdr) +
		    sizeof(struct tcphdr) > skb_headlen(skb))
			return -ENODATA;
		tcp_header_len = (data[payload_offset + sizeof(struct iphdr) +
				       12] >> 4) * 4;
		if (tcp_header_len < sizeof(struct tcphdr))
			return -EMSGSIZE;
		segment_len = sizeof(struct iphdr) + tcp_header_len +
			      shinfo->gso_size;
		if (segment_len > inner_len)
			return -EMSGSIZE;
	}

	expected_len = segment_len + outer_overhead;
	if (expected_len != ip_len) {
		struct skb_shared_info *shinfo = skb_shinfo(skb);
		u32 carried_len;

		if (!shinfo->gso_size || inner_iph->protocol != IPPROTO_TCP)
			return -EMSGSIZE;
		if (ip_len > expected_len || ip_len < outer_overhead)
			return -EMSGSIZE;
		carried_len = ip_len - outer_overhead;
		if (carried_len > inner_len)
			return -EMSGSIZE;
	}

	*next_hop = inner_iph->daddr;
	*outer_len = outer_overhead;
	return 0;
}

struct trustix_tixt_rx_stream_frame {
	u32 frame_offset;
	u32 payload_offset;
	u32 payload_len;
	u32 next_hop;
};

static u32 trustix_ipv4_header_check20_base(const u8 *iph);
static __sum16 trustix_ipv4_header_check20_from_base(u32 sum, u32 tot_len);
static __sum16 trustix_ipv4_header_check20(const u8 *iph);

static bool trustix_tixt_rx_stream_local_match(
				const struct trustix_kudp_rx_parse_args *args,
				u32 next_hop)
{
	u32 local_mask;

	if (!args || !args->local_ifindex || !args->local_ipv4)
		return false;
	local_mask = args->local_ipv4_mask;
	if (!local_mask)
		local_mask = ~0U;
	return ((next_hop ^ args->local_ipv4) & local_mask) == 0;
}

static bool trustix_tixt_rx_stream_trust_l4_csum(const u8 *inner, u32 inner_len,
						 u32 flags)
{
	const struct iphdr *iph;
	u32 ihl;
	u32 l4_len;

	if (!(flags & TRUSTIX_KUDP_RX_DECAP_L2_TRUST_INNER_L4_CSUM))
		return false;
	if (!inner || inner_len < sizeof(*iph))
		return false;
	iph = (const struct iphdr *)inner;
	if (iph->version != 4 || iph->ihl < 5 ||
	    ntohs(iph->tot_len) != inner_len ||
	    (iph->frag_off & htons(0x3fff)))
		return false;
	ihl = iph->ihl * 4;
	if (ihl < sizeof(*iph) || inner_len < ihl)
		return false;
	l4_len = inner_len - ihl;
	if (iph->protocol == IPPROTO_TCP && l4_len >= sizeof(struct tcphdr))
		return true;
	if (iph->protocol == IPPROTO_UDP && l4_len >= sizeof(struct udphdr))
		return true;
	return false;
}

static void trustix_tixt_rx_stream_free_skb_list(struct sk_buff *head)
{
	struct sk_buff *next;

	while (head) {
		next = head->next;
		head->next = NULL;
		kfree_skb(head);
		head = next;
	}
}

static bool trustix_tixt_rx_dev_ready(const struct net_device *dev)
{
	if (!dev)
		return false;
	if (dev->reg_state != NETREG_REGISTERED)
		return false;
	if (!(READ_ONCE(dev->flags) & IFF_UP))
		return false;
	return netif_device_present(dev) && netif_running(dev);
}

static int trustix_tixt_rx_stream_parse_one(const u8 *data, u32 frame_offset,
					    u32 payload_end,
					    struct trustix_tixt_rx_stream_frame *frame)
{
	const struct iphdr *inner_iph;
	u32 payload_offset;
	u32 payload_len;
	u32 frame_end;
	u8 frame_flags;

	if (!data || !frame)
		return -EINVAL;
	if (frame_offset > payload_end ||
	    payload_end - frame_offset < TRUSTIX_TIXT_HEADER_LEN +
					 sizeof(struct iphdr))
		return -ENODATA;
	if (get_unaligned_be32(data + frame_offset) != TRUSTIX_TIXT_MAGIC)
		return -EPROTONOSUPPORT;
	if (data[frame_offset + 4] != 1 ||
	    get_unaligned_be16(data + frame_offset + 6) !=
		    TRUSTIX_TIXT_HEADER_LEN)
		return -EBADMSG;
	frame_flags = data[frame_offset + 5];
	if ((frame_flags & TRUSTIX_TIXT_FLAG_INNER_IPV4) !=
	    TRUSTIX_TIXT_FLAG_INNER_IPV4)
		return -EPROTONOSUPPORT;
	if (frame_flags & TRUSTIX_TIXT_FLAG_ENCRYPTED)
		return -EPROTONOSUPPORT;
	if (frame_flags & ~(TRUSTIX_TIXT_FLAG_KERNEL_OPENED |
			    TRUSTIX_TIXT_FLAG_INNER_IPV4))
		return -EPROTONOSUPPORT;
	payload_len = get_unaligned_be32(data + frame_offset + 32);
	if (payload_len < sizeof(struct iphdr) || payload_len > 0xffff)
		return -EMSGSIZE;
	payload_offset = frame_offset + TRUSTIX_TIXT_HEADER_LEN;
	if (payload_offset < frame_offset ||
	    check_add_overflow(payload_offset, payload_len, &frame_end))
		return -EMSGSIZE;
	if (frame_end > payload_end)
		return -EMSGSIZE;

	inner_iph = (const struct iphdr *)(data + payload_offset);
	if (inner_iph->version != 4 || inner_iph->ihl != 5)
		return -EBADMSG;
	if (ntohs(inner_iph->tot_len) != payload_len)
		return -EMSGSIZE;
	frame->frame_offset = frame_offset;
	frame->payload_offset = payload_offset;
	frame->payload_len = payload_len;
	frame->next_hop = inner_iph->daddr;
	return 0;
}

static int
trustix_tixt_rx_stream_parse_one_skb(
				struct sk_buff *skb, u32 frame_offset,
				u32 payload_end,
				struct trustix_tixt_rx_stream_frame *frame)
{
	u8 tixt_header[TRUSTIX_TIXT_HEADER_LEN];
	struct iphdr inner_iph_buf;
	const struct iphdr *inner_iph;
	const u8 *tixt;
	u32 payload_offset;
	u32 payload_len;
	u32 frame_end;
	u8 frame_flags;

	if (!skb || !frame)
		return -EINVAL;
	if (frame_offset > payload_end ||
	    payload_end - frame_offset < TRUSTIX_TIXT_HEADER_LEN +
					 sizeof(struct iphdr))
		return -ENODATA;
	tixt = skb_header_pointer(skb, frame_offset,
				  TRUSTIX_TIXT_HEADER_LEN, tixt_header);
	if (!tixt)
		return -ENODATA;
	if (get_unaligned_be32(tixt) != TRUSTIX_TIXT_MAGIC)
		return -EPROTONOSUPPORT;
	if (tixt[4] != 1 ||
	    get_unaligned_be16(tixt + 6) != TRUSTIX_TIXT_HEADER_LEN)
		return -EBADMSG;
	frame_flags = tixt[5];
	if ((frame_flags & TRUSTIX_TIXT_FLAG_INNER_IPV4) !=
	    TRUSTIX_TIXT_FLAG_INNER_IPV4)
		return -EPROTONOSUPPORT;
	if (frame_flags & TRUSTIX_TIXT_FLAG_ENCRYPTED)
		return -EPROTONOSUPPORT;
	if (frame_flags & ~(TRUSTIX_TIXT_FLAG_KERNEL_OPENED |
			    TRUSTIX_TIXT_FLAG_INNER_IPV4))
		return -EPROTONOSUPPORT;
	payload_len = get_unaligned_be32(tixt + 32);
	if (payload_len < sizeof(struct iphdr) || payload_len > 0xffff)
		return -EMSGSIZE;
	payload_offset = frame_offset + TRUSTIX_TIXT_HEADER_LEN;
	if (payload_offset < frame_offset ||
	    check_add_overflow(payload_offset, payload_len, &frame_end))
		return -EMSGSIZE;
	if (frame_end > payload_end)
		return -EMSGSIZE;

	inner_iph = skb_header_pointer(skb, payload_offset,
				       sizeof(inner_iph_buf), &inner_iph_buf);
	if (!inner_iph)
		return -ENODATA;
	if (inner_iph->version != 4 || inner_iph->ihl != 5)
		return -EBADMSG;
	if (ntohs(inner_iph->tot_len) != payload_len)
		return -EMSGSIZE;
	frame->frame_offset = frame_offset;
	frame->payload_offset = payload_offset;
	frame->payload_len = payload_len;
	frame->next_hop = inner_iph->daddr;
	return 0;
}

static int trustix_tixt_rx_stream_parse_frames(
				struct sk_buff *skb,
				const struct trustix_kudp_rx_parse_args *args,
				struct trustix_tixt_rx_stream_frame *frames,
				unsigned int *frame_count,
				u32 *outer_len)
{
	u32 frame_offset = ETH_HLEN + sizeof(struct iphdr) +
			   sizeof(struct tcphdr);
	u32 payload_end;
	u32 ip_payload_end;
	u32 cursor;
	u32 ip_len;
	u32 max_frames;
	bool nonlinear_parse = false;
	bool stream_tail = false;
	u8 *data;
	int ret;

	if (!skb || !args || !frames || !frame_count || !outer_len)
		return -EINVAL;
	*frame_count = 0;
	*outer_len = sizeof(struct iphdr) + sizeof(struct tcphdr) +
		     TRUSTIX_TIXT_HEADER_LEN;
	if (args->flags & TRUSTIX_KUDP_RX_PARSE_KERNEL_UDP_ONLY)
		return -EAGAIN;
	if (skb->len < frame_offset + TRUSTIX_TIXT_HEADER_LEN +
		       sizeof(struct iphdr))
		return -EAGAIN;
	if (unlikely(frame_offset + TRUSTIX_TIXT_HEADER_LEN +
			     sizeof(struct iphdr) > skb_headlen(skb) &&
		     !pskb_may_pull(skb, frame_offset +
					     TRUSTIX_TIXT_HEADER_LEN +
					     sizeof(struct iphdr))))
		return -EAGAIN;
	if (frame_offset + TRUSTIX_TIXT_HEADER_LEN + sizeof(struct iphdr) >
	    skb_headlen(skb))
		return -EAGAIN;

	data = skb->data;
	if (get_unaligned_be16(data + 12) != ETH_P_IP || data[ETH_HLEN] != 0x45)
		return -EAGAIN;
	if (get_unaligned_be16(data + ETH_HLEN +
			       offsetof(struct iphdr, frag_off)) & 0x3fff)
		return -EAGAIN;
	if (data[ETH_HLEN + offsetof(struct iphdr, protocol)] != IPPROTO_TCP)
		return -EAGAIN;
	if (data[ETH_HLEN + sizeof(struct iphdr) + 12] != 0x50)
		return -EAGAIN;
	if (args->static_dest_port &&
	    get_unaligned_be16(data + ETH_HLEN + sizeof(struct iphdr) +
			       offsetof(struct tcphdr, dest)) !=
		    args->static_dest_port)
		return -EAGAIN;

	ip_len = get_unaligned_be16(data + ETH_HLEN +
				    offsetof(struct iphdr, tot_len));
	if (ip_len < sizeof(struct iphdr) + sizeof(struct tcphdr) +
		     TRUSTIX_TIXT_HEADER_LEN + sizeof(struct iphdr))
		return -EAGAIN;
	if (skb->len < ETH_HLEN + ip_len)
		return -EAGAIN;
	ip_payload_end = ETH_HLEN + ip_len;
	payload_end = ip_payload_end;
	stream_tail = trustix_tixt_tcp_outer_has_stream_tail(skb, ip_len);
	if (stream_tail) {
		if (skb->len > TRUSTIX_TIXT_RX_STREAM_PARSE_LINEAR_MAX)
			return -EAGAIN;
		payload_end = skb->len;
	}
	if (payload_end > skb_headlen(skb) &&
	    (READ_ONCE(trustix_tixt_rx_stream_nonlinear_parse) ||
	     skb_is_gso(skb))) {
		nonlinear_parse = true;
		trustix_tixt_rx_stream_nonlinear_parse_hits++;
	} else if (unlikely(payload_end > skb_headlen(skb) &&
		     !pskb_may_pull(skb, payload_end)))
		return -ENODATA;
	if (!nonlinear_parse && payload_end > skb_headlen(skb))
		return -ENODATA;

	data = skb->data;
	cursor = frame_offset;
	max_frames = trustix_tixt_rx_stream_max_frames_value();
	while (cursor < payload_end) {
		if (*frame_count >= max_frames) {
			trustix_tixt_rx_stream_parse_errors++;
			return -EPROTONOSUPPORT;
		}
		if (nonlinear_parse)
			ret = trustix_tixt_rx_stream_parse_one_skb(
				skb, cursor, payload_end,
				&frames[*frame_count]);
		else
			ret = trustix_tixt_rx_stream_parse_one(
				data, cursor, payload_end,
				&frames[*frame_count]);
		if (ret) {
			if (*frame_count == 0 && !stream_tail)
				return -EAGAIN;
			trustix_tixt_rx_stream_parse_errors++;
			return ret;
		}
		cursor = frames[*frame_count].payload_offset +
			 frames[*frame_count].payload_len;
		(*frame_count)++;
	}
	if (*frame_count < 2 && !stream_tail)
		return -EAGAIN;
	if (*frame_count < 2)
		return -EPROTONOSUPPORT;
	trustix_tixt_rx_stream_candidates++;
	trustix_tixt_rx_stream_frames += *frame_count;
	return 0;
}

static int trustix_tixt_rx_stream_build_extra_list(
				struct sk_buff *skb, struct net_device *dev,
				const struct trustix_kudp_rx_parse_args *args,
				const struct trustix_tixt_rx_stream_frame *frames,
				unsigned int frame_count,
				unsigned int start_frame,
				struct sk_buff **head_out)
{
	struct sk_buff *head = NULL;
	struct sk_buff *tail = NULL;
	struct sk_buff *rx_skb;
	unsigned int i;
	u32 total_len;
	u8 *dst;
	const struct iphdr *iph;
	int ret;

	if (!skb || !dev || !args || !frames || !head_out)
		return -EINVAL;
	*head_out = NULL;
	if (start_frame >= frame_count)
		return 0;
	if (!trustix_tixt_rx_dev_ready(dev)) {
		trustix_tixt_rx_stream_xmit_errors++;
		return -ENETDOWN;
	}
	for (i = start_frame; i < frame_count; i++) {
		if (!trustix_tixt_rx_stream_local_match(args, frames[i].next_hop)) {
			trustix_tixt_rx_stream_disabled++;
			trustix_tixt_rx_stream_free_skb_list(head);
			return -EPROTONOSUPPORT;
		}
		if (check_add_overflow((u32)ETH_HLEN, frames[i].payload_len,
				       &total_len)) {
			trustix_tixt_rx_stream_parse_errors++;
			trustix_tixt_rx_stream_free_skb_list(head);
			return -EMSGSIZE;
		}
		rx_skb = netdev_alloc_skb_ip_align(dev, total_len);
		if (!rx_skb) {
			trustix_tixt_rx_stream_xmit_errors++;
			trustix_tixt_rx_stream_free_skb_list(head);
			return -EPROTONOSUPPORT;
		}
		skb_reserve(rx_skb, ETH_HLEN);
		dst = skb_put(rx_skb, frames[i].payload_len);
		ret = skb_copy_bits(skb, frames[i].payload_offset, dst,
				    frames[i].payload_len);
		if (ret) {
			kfree_skb(rx_skb);
			trustix_tixt_rx_stream_xmit_errors++;
			trustix_tixt_rx_stream_free_skb_list(head);
			return -ENODATA;
		}
		skb_reset_network_header(rx_skb);
		iph = (const struct iphdr *)rx_skb->data;
		if (iph->version == 4 && iph->ihl >= 5 &&
		    rx_skb->len >= iph->ihl * 4)
			skb_set_transport_header(rx_skb, iph->ihl * 4);
		if (skb_cow_head(rx_skb, ETH_HLEN)) {
			kfree_skb(rx_skb);
			trustix_tixt_rx_stream_xmit_errors++;
			trustix_tixt_rx_stream_free_skb_list(head);
			return -EPROTONOSUPPORT;
		}
		dst = skb_push(rx_skb, ETH_HLEN);
		skb_reset_mac_header(rx_skb);
		trustix_write_l2_header(dst, args->l2_head, args->l2_tail0,
					args->l2_tail1);
		rx_skb->dev = dev;
		if (!trustix_tixt_rx_dev_ready(dev)) {
			kfree_skb(rx_skb);
			trustix_tixt_rx_stream_xmit_errors++;
			trustix_tixt_rx_stream_free_skb_list(head);
			return -ENETDOWN;
		}
		rx_skb->protocol = eth_type_trans(rx_skb, dev);
		rx_skb->skb_iif = dev->ifindex;
		rx_skb->pkt_type = PACKET_HOST;
		rx_skb->encapsulation = 0;
		rx_skb->csum = 0;
		rx_skb->csum_level = 0;
		rx_skb->ip_summed = trustix_tixt_rx_stream_trust_l4_csum(
					     dst, frames[i].payload_len,
					     args->decap_flags) ?
					     CHECKSUM_UNNECESSARY :
					     CHECKSUM_NONE;
		rx_skb->next = NULL;
		if (tail)
			tail->next = rx_skb;
		else
			head = rx_skb;
		tail = rx_skb;
	}
	*head_out = head;
	return 0;
}

static unsigned int trustix_tixt_rx_stream_publish_extra_list(struct sk_buff *head)
{
	struct sk_buff *next;
	unsigned int count = 0;
	int ret;

	if (!head)
		return 0;
	if (!trustix_tixt_rx_dev_ready(head->dev)) {
		trustix_tixt_rx_stream_free_skb_list(head);
		trustix_tixt_rx_stream_xmit_errors++;
		return 0;
	}

	if (READ_ONCE(trustix_tixt_rx_stream_gso_xmit)) {
		count = trustix_tixt_rx_publish_skb_chain_backlog(
			head, &trustix_tixt_rx_stream_backlog_packets,
			&trustix_tixt_rx_stream_backlog_drops);
		if (count) {
			trustix_tixt_rx_stream_gso_batches++;
			trustix_tixt_rx_stream_gso_frames += count;
			trustix_tixt_rx_stream_xmit_packets += count;
		}
		return count;
	}

	while (head) {
		next = head->next;
		head->next = NULL;
		ret = trustix_tixt_rx_publish_one_backlog(
			head, &trustix_tixt_rx_stream_backlog_packets,
			&trustix_tixt_rx_stream_backlog_drops);
		if (ret)
			trustix_tixt_rx_stream_xmit_errors++;
		else
			trustix_tixt_rx_stream_xmit_packets++;
		head = next;
		count++;
	}
	return count;
}

static bool trustix_tixt_rx_single_coalesce_stream_fallback_enabled(void)
{
	return READ_ONCE(trustix_tixt_rx_single_coalesce_stream_fallback) &&
	       READ_ONCE(trustix_tixt_rx_single_coalesce_gso);
}

static bool trustix_tixt_rx_stream_parse_wanted(struct sk_buff *skb)
{
	if (READ_ONCE(trustix_tixt_rx_stream_parse))
		return true;
	if (trustix_tixt_rx_tcp_outer_needs_stream_parse(skb))
		return true;
	if (!trustix_tixt_rx_single_coalesce_stream_fallback_enabled() || !skb)
		return false;
	return skb_is_gso(skb) ||
	       skb->len > ETH_HLEN + TRUSTIX_TIXT_TCP_OUTER_OVERHEAD +
			  ETH_DATA_LEN;
}

static int trustix_tixt_rx_stream_try_coalesce_gso(
				struct sk_buff *skb, struct net_device *dev,
				const struct trustix_kudp_rx_parse_args *args,
				const struct trustix_tixt_rx_stream_frame *frames,
				unsigned int frame_count)
{
	const u32 ip_header_len = sizeof(struct iphdr);
	u8 first_header[TRUSTIX_TIXT_RX_SINGLE_COALESCE_HEADER_MAX];
	struct sk_buff *rx_skb;
	struct tcphdr *tcph;
	struct iphdr *iph;
	__be32 first_saddr = 0;
	__be32 first_daddr = 0;
	__be16 first_source = 0;
	__be16 first_dest = 0;
	u32 tcp_header_len = 0;
	u32 total_payload = 0;
	u32 total_inner_len;
	u32 expected_seq = 0;
	u32 gso_size = 0;
	u32 tcp_len;
	u32 total_len;
	u8 *dst;
	u8 *pos;
	u8 *l2;
	__wsum sum;
	unsigned int i;
	bool have_first_header = false;
	bool single_stream_fallback =
		trustix_tixt_rx_single_coalesce_stream_fallback_enabled();
	bool mark_rx_gso =
		READ_ONCE(trustix_tixt_rx_stream_coalesce_mark_gso);
	bool skip_tcp_csum =
		(single_stream_fallback &&
		 READ_ONCE(trustix_tixt_rx_single_coalesce_skip_tcp_csum));
	int ret;

	if (!READ_ONCE(trustix_tixt_rx_stream_coalesce_gso) &&
	    !single_stream_fallback)
		return 0;
	if (!skb || !dev || !args || !frames || frame_count < 2)
		return 0;
	if (!(args->decap_flags & TRUSTIX_KUDP_RX_DECAP_L2_TRUST_INNER_L4_CSUM)) {
		trustix_tixt_rx_stream_coalesce_fallbacks++;
		return 0;
	}

	for (i = 0; i < frame_count; i++) {
		struct iphdr cur_iph_buf;
		struct tcphdr cur_tcph_buf;
		const struct iphdr *cur_iph;
		const struct tcphdr *cur_tcph;
		u32 cur_payload_offset;
		u32 cur_tcp_header_len;
		u32 cur_payload_len;
		u32 cur_seq;

		if (!trustix_tixt_rx_stream_local_match(args, frames[i].next_hop)) {
			trustix_tixt_rx_stream_disabled++;
			return -EPROTONOSUPPORT;
		}
		if (frames[i].payload_len < ip_header_len + sizeof(*cur_tcph)) {
			trustix_tixt_rx_stream_coalesce_fallbacks++;
			return 0;
		}
		cur_iph = skb_header_pointer(skb, frames[i].payload_offset,
					     sizeof(cur_iph_buf),
					     &cur_iph_buf);
		if (!cur_iph) {
			trustix_tixt_rx_stream_coalesce_fallbacks++;
			return 0;
		}
		if (cur_iph->version != 4 || cur_iph->ihl != 5 ||
		    cur_iph->protocol != IPPROTO_TCP ||
		    (cur_iph->frag_off & htons(0x3fff)) ||
		    ntohs(cur_iph->tot_len) != frames[i].payload_len) {
			trustix_tixt_rx_stream_coalesce_fallbacks++;
			return 0;
		}
		cur_tcph = skb_header_pointer(skb,
					      frames[i].payload_offset +
						      ip_header_len,
					      sizeof(cur_tcph_buf),
					      &cur_tcph_buf);
		if (!cur_tcph) {
			trustix_tixt_rx_stream_coalesce_fallbacks++;
			return 0;
		}
		cur_tcp_header_len = cur_tcph->doff * 4;
		if (cur_tcp_header_len < sizeof(*cur_tcph) ||
		    cur_tcp_header_len >
			    TRUSTIX_TIXT_RX_SINGLE_COALESCE_HEADER_MAX -
				    sizeof(struct iphdr) ||
		    frames[i].payload_len < ip_header_len + cur_tcp_header_len) {
			trustix_tixt_rx_stream_coalesce_fallbacks++;
			return 0;
		}
		cur_payload_len = frames[i].payload_len - ip_header_len -
				  cur_tcp_header_len;
		if (!cur_payload_len) {
			trustix_tixt_rx_stream_coalesce_fallbacks++;
			return 0;
		}
		cur_seq = ntohl(cur_tcph->seq);
		if (!i) {
			first_saddr = cur_iph->saddr;
			first_daddr = cur_iph->daddr;
			first_source = cur_tcph->source;
			first_dest = cur_tcph->dest;
			tcp_header_len = cur_tcp_header_len;
			gso_size = cur_payload_len;
			expected_seq = cur_seq;
			ret = skb_copy_bits(skb, frames[i].payload_offset,
					    first_header,
					    ip_header_len + tcp_header_len);
			if (ret) {
				trustix_tixt_rx_stream_coalesce_fallbacks++;
				return 0;
			}
			have_first_header = true;
		} else {
			if (cur_iph->saddr != first_saddr ||
			    cur_iph->daddr != first_daddr ||
			    cur_tcph->source != first_source ||
			    cur_tcph->dest != first_dest ||
			    cur_tcp_header_len != tcp_header_len ||
			    cur_seq != expected_seq ||
			    cur_payload_len > gso_size ||
			    (i + 1 < frame_count && cur_payload_len != gso_size)) {
				trustix_tixt_rx_stream_coalesce_fallbacks++;
				return 0;
			}
		}
		if (check_add_overflow(total_payload, cur_payload_len,
				       &total_payload)) {
			trustix_tixt_rx_stream_coalesce_fallbacks++;
			return 0;
		}
		cur_payload_offset = frames[i].payload_offset + ip_header_len +
				     cur_tcp_header_len;
		if (cur_payload_offset < frames[i].payload_offset) {
			trustix_tixt_rx_stream_coalesce_fallbacks++;
			return 0;
		}
		expected_seq += cur_payload_len;
	}
	if (!have_first_header || !gso_size ||
	    check_add_overflow(ip_header_len + tcp_header_len, total_payload,
			       &total_inner_len) ||
	    total_inner_len > 0xffff ||
	    check_add_overflow((u32)ETH_HLEN, total_inner_len, &total_len)) {
		trustix_tixt_rx_stream_coalesce_fallbacks++;
		return 0;
	}

	rx_skb = netdev_alloc_skb_ip_align(dev, total_len);
	if (!rx_skb) {
		trustix_tixt_rx_stream_coalesce_errors++;
		return -ENOMEM;
	}
	skb_reserve(rx_skb, ETH_HLEN);
	dst = skb_put(rx_skb, total_inner_len);
	memcpy(dst, first_header, ip_header_len + tcp_header_len);
	pos = dst + ip_header_len + tcp_header_len;
	for (i = 0; i < frame_count; i++) {
		u32 payload_src = frames[i].payload_offset + ip_header_len +
				  tcp_header_len;
		u32 cur_payload_len = frames[i].payload_len - ip_header_len -
				      tcp_header_len;

		if (payload_src < frames[i].payload_offset ||
		    skb_copy_bits(skb, payload_src, pos, cur_payload_len)) {
			kfree_skb(rx_skb);
			trustix_tixt_rx_stream_coalesce_errors++;
			return -ENODATA;
		}
		pos += cur_payload_len;
	}
	if (pos != dst + total_inner_len) {
		kfree_skb(rx_skb);
		trustix_tixt_rx_stream_coalesce_errors++;
		return -EINVAL;
	}

	iph = (struct iphdr *)dst;
	iph->tot_len = htons(total_inner_len);
	iph->check = 0;
	iph->check = trustix_ipv4_header_check20((const u8 *)iph);
	tcph = (struct tcphdr *)(dst + ip_header_len);
	tcp_len = tcp_header_len + total_payload;
	if (!skip_tcp_csum) {
		tcph->check = 0;
		sum = csum_partial(tcph, tcp_len, 0);
		tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
						tcp_len, IPPROTO_TCP, sum);
	}

	skb_reset_network_header(rx_skb);
	skb_set_transport_header(rx_skb, ip_header_len);
	l2 = skb_push(rx_skb, ETH_HLEN);
	skb_reset_mac_header(rx_skb);
	trustix_write_l2_header(l2, args->l2_head, args->l2_tail0,
				args->l2_tail1);
	rx_skb->dev = dev;
	rx_skb->protocol = eth_type_trans(rx_skb, dev);
	rx_skb->skb_iif = dev->ifindex;
	rx_skb->pkt_type = PACKET_HOST;
	rx_skb->encapsulation = 0;
	rx_skb->csum = 0;
	rx_skb->csum_level = 0;
	rx_skb->ip_summed = CHECKSUM_UNNECESSARY;
	if (mark_rx_gso && frame_count > 1)
		trustix_tixt_rx_coalesced_mark_tcpv4_gso(
			rx_skb, gso_size, frame_count);
	if (mark_rx_gso && skb_is_gso(rx_skb) &&
	    READ_ONCE(trustix_tixt_rx_coalesce_segment_gso)) {
		ret = trustix_tixt_rx_coalesced_segment_and_publish(
			rx_skb, dev, gso_size, frame_count);
		if (ret > 0) {
			trustix_tixt_rx_stream_coalesce_batches++;
			trustix_tixt_rx_stream_coalesce_frames += frame_count;
			trustix_tixt_rx_stream_xmit_packets += frame_count;
			if (single_stream_fallback &&
			    !READ_ONCE(trustix_tixt_rx_stream_coalesce_gso)) {
				trustix_tixt_rx_single_coalesce_stream_fallbacks++;
				trustix_tixt_rx_single_coalesce_stream_fallback_frames +=
					frame_count;
			}
			return 1;
		}
		trustix_tixt_rx_stream_coalesce_xmit_errors++;
		return ret ? ret : -EIO;
	}

	ret = trustix_tixt_rx_publish_one_backlog(
		rx_skb, &trustix_tixt_rx_stream_backlog_packets,
		&trustix_tixt_rx_stream_backlog_drops);
	if (ret) {
		trustix_tixt_rx_stream_coalesce_xmit_errors++;
		return ret;
	}
	trustix_tixt_rx_stream_coalesce_batches++;
	trustix_tixt_rx_stream_coalesce_frames += frame_count;
	trustix_tixt_rx_stream_xmit_packets += frame_count;
	if (single_stream_fallback &&
	    !READ_ONCE(trustix_tixt_rx_stream_coalesce_gso)) {
		trustix_tixt_rx_single_coalesce_stream_fallbacks++;
		trustix_tixt_rx_single_coalesce_stream_fallback_frames +=
			frame_count;
	}
	return 1;
}

static unsigned int trustix_tixt_rx_single_coalesce_max_frames_value(void)
{
	unsigned int max_frames =
		READ_ONCE(trustix_tixt_rx_single_coalesce_max_frames);

	if (max_frames < 2)
		return 2;
	if (max_frames > TRUSTIX_TIXT_RX_SINGLE_COALESCE_MAX_FRAMES)
		return TRUSTIX_TIXT_RX_SINGLE_COALESCE_MAX_FRAMES;
	return max_frames;
}

static unsigned int trustix_tixt_rx_single_coalesce_direct_list_max_frames_value(void)
{
	unsigned int max_frames =
		READ_ONCE(trustix_tixt_rx_single_coalesce_direct_list_max_frames);

	if (max_frames < 2)
		return 0;
	if (max_frames > TRUSTIX_TIXT_RX_SINGLE_COALESCE_MAX_FRAMES)
		return TRUSTIX_TIXT_RX_SINGLE_COALESCE_MAX_FRAMES;
	return max_frames;
}

static u32 trustix_tixt_rx_single_coalesce_linear_max_value(void)
{
	unsigned int linear_max =
		READ_ONCE(trustix_tixt_rx_single_coalesce_linear_max);

	if (linear_max < TRUSTIX_TIXT_RX_SINGLE_COALESCE_LINEAR_MAX)
		return TRUSTIX_TIXT_RX_SINGLE_COALESCE_LINEAR_MAX;
	if (linear_max > TRUSTIX_TIXT_RX_SINGLE_COALESCE_PAYLOAD_MAX)
		return TRUSTIX_TIXT_RX_SINGLE_COALESCE_PAYLOAD_MAX;
	return linear_max;
}

static unsigned int trustix_tixt_rx_single_coalesce_flush_jiffies_value(void)
{
	unsigned int flush_jiffies =
		READ_ONCE(trustix_tixt_rx_single_coalesce_flush_jiffies);

	if (flush_jiffies > 16)
		return 16;
	return flush_jiffies;
}

static unsigned int trustix_tixt_rx_single_coalesce_warmup_frames_value(void)
{
	unsigned int warmup =
		READ_ONCE(trustix_tixt_rx_single_coalesce_warmup_frames);

	if (!warmup)
		return 1;
	if (warmup > TRUSTIX_TIXT_RX_SINGLE_COALESCE_MAX_FRAMES)
		return TRUSTIX_TIXT_RX_SINGLE_COALESCE_MAX_FRAMES;
	return warmup;
}

static u32 trustix_tixt_rx_single_coalesce_mix32(u32 value)
{
	value ^= value >> 16;
	value *= 0x7feb352dU;
	value ^= value >> 15;
	value *= 0x846ca68bU;
	value ^= value >> 16;
	return value;
}

static u32 trustix_tixt_rx_single_coalesce_hash_value(
				const struct net_device *dev,
				__be32 saddr, __be32 daddr,
				__be16 source, __be16 dest)
{
	u32 hash = (__force u32)saddr ^ rol32((__force u32)daddr, 13);
	u32 ports = ((__force u16)source << 16) | (__force u16)dest;

	hash ^= rol32(ports, 7);
	if (dev)
		hash ^= (u32)dev->ifindex * 0x9e3779b9U;
	hash = trustix_tixt_rx_single_coalesce_mix32(hash);
	return hash ?: 1;
}

static u8 trustix_tixt_rx_single_coalesce_flags_class(u8 flags)
{
	return flags & ~(u8)0x08;
}

static bool trustix_tixt_rx_single_coalesce_flow_match(
				const struct trustix_tixt_rx_single_coalesce_slot *slot,
				const struct trustix_tixt_rx_single_coalesce_frame *frame)
{
	return slot->saddr == frame->saddr &&
	       slot->daddr == frame->daddr &&
	       slot->source == frame->source &&
	       slot->dest == frame->dest;
}

static bool trustix_tixt_rx_single_coalesce_shape_match(
				const struct trustix_tixt_rx_single_coalesce_slot *slot,
				const struct trustix_tixt_rx_single_coalesce_frame *frame)
{
	return slot->tcp_header_len == frame->tcp_header_len &&
	       slot->urg_ptr == frame->urg_ptr &&
	       trustix_tixt_rx_single_coalesce_flags_class(slot->tcp_flags) ==
		       trustix_tixt_rx_single_coalesce_flags_class(
			       frame->tcp_flags);
}

static void trustix_tixt_rx_single_coalesce_record_relaxed_diffs(
				const struct trustix_tixt_rx_single_coalesce_slot *slot,
				const struct trustix_tixt_rx_single_coalesce_frame *frame)
{
	if (slot->ack_seq != frame->ack_seq)
		trustix_tixt_rx_single_coalesce_ack_variations++;
	if (slot->window != frame->window)
		trustix_tixt_rx_single_coalesce_window_variations++;
	if (slot->tcp_flags != frame->tcp_flags)
		trustix_tixt_rx_single_coalesce_flags_variations++;
}

static bool trustix_tixt_rx_single_coalesce_match(
				const struct trustix_tixt_rx_single_coalesce_slot *slot,
				const struct net_device *dev,
				const struct trustix_tixt_rx_single_coalesce_frame *frame)
{
	return slot->frame_count &&
	       slot->dev == dev &&
	       trustix_tixt_rx_single_coalesce_flow_match(slot, frame) &&
	       trustix_tixt_rx_single_coalesce_shape_match(slot, frame) &&
	       (!slot->gso_size || frame->payload_len <= slot->gso_size) &&
	       slot->next_seq == frame->seq;
}

static bool trustix_tixt_rx_single_coalesce_armed_match(
				const struct trustix_tixt_rx_single_coalesce_slot *slot,
				const struct net_device *dev,
				const struct trustix_tixt_rx_single_coalesce_frame *frame)
{
	return slot->armed &&
	       slot->armed_ifindex == (dev ? dev->ifindex : 0) &&
	       trustix_tixt_rx_single_coalesce_flow_match(slot, frame) &&
	       trustix_tixt_rx_single_coalesce_shape_match(slot, frame) &&
	       slot->gso_size == frame->payload_len &&
	       slot->next_seq == frame->seq;
}

static void trustix_tixt_rx_single_coalesce_record_miss(
				const struct trustix_tixt_rx_single_coalesce_slot *slot,
				const struct net_device *dev,
				const struct trustix_tixt_rx_single_coalesce_frame *frame)
{
	bool same_dev = slot->frame_count ? slot->dev == dev :
			(slot->armed ?
			 slot->armed_ifindex == (dev ? dev->ifindex : 0) :
			 slot->dev == dev);

	if (!same_dev) {
		trustix_tixt_rx_single_coalesce_dev_misses++;
		trustix_tixt_rx_single_coalesce_hash_misses++;
		return;
	}
	if (!trustix_tixt_rx_single_coalesce_flow_match(slot, frame)) {
		trustix_tixt_rx_single_coalesce_flow_misses++;
		trustix_tixt_rx_single_coalesce_hash_misses++;
		return;
	}
	if (!trustix_tixt_rx_single_coalesce_shape_match(slot, frame)) {
		trustix_tixt_rx_single_coalesce_header_misses++;
		trustix_tixt_rx_single_coalesce_hash_misses++;
		return;
	}
	if (slot->gso_size && frame->payload_len > slot->gso_size) {
		trustix_tixt_rx_single_coalesce_gso_size_misses++;
		trustix_tixt_rx_single_coalesce_hash_misses++;
		return;
	}
	trustix_tixt_rx_single_coalesce_seq_misses++;
}

static void trustix_tixt_rx_single_coalesce_reset_locked(
				struct trustix_tixt_rx_single_coalesce_slot *slot)
{
	slot->dev = NULL;
	slot->armed = false;
	slot->armed_ifindex = 0;
	slot->armed_passes = 0;
	slot->l2_head = 0;
	slot->l2_tail0 = 0;
	slot->l2_tail1 = 0;
	slot->decap_flags = 0;
	slot->saddr = 0;
	slot->daddr = 0;
	slot->source = 0;
	slot->dest = 0;
	slot->window = 0;
	slot->urg_ptr = 0;
	slot->skb_hash = 0;
	memset(slot->header, 0, sizeof(slot->header));
	slot->tcp_header_len = 0;
	slot->next_seq = 0;
	slot->ack_seq = 0;
	slot->tcp_flags = 0;
	slot->gso_size = 0;
	slot->frame_count = 0;
	memset(slot->seqs, 0, sizeof(slot->seqs));
	memset(slot->tcp_checks, 0, sizeof(slot->tcp_checks));
	memset(slot->frame_headers, 0, sizeof(slot->frame_headers));
	slot->total_payload = 0;
	slot->payload_linear_len = 0;
	slot->payload_page_len = 0;
	slot->payload_page_only = false;
	slot->flush_queued = false;
}

static int trustix_tixt_rx_single_coalesce_ensure_payload_locked(
				struct trustix_tixt_rx_single_coalesce_slot *slot,
				u32 needed)
{
	u32 linear_needed;
	u32 page_needed;
	u32 linear_max;
	u32 cap;
	u8 *payload;

	if (needed > TRUSTIX_TIXT_RX_SINGLE_COALESCE_PAYLOAD_MAX)
		return -EMSGSIZE;
	if (slot->payload_page_only) {
		while (slot->payload_page_cap * PAGE_SIZE < needed) {
			if (slot->payload_page_cap >=
			    TRUSTIX_TIXT_RX_SINGLE_COALESCE_PAGE_MAX)
				return -EMSGSIZE;
			slot->payload_pages[slot->payload_page_cap] =
				alloc_page(GFP_ATOMIC);
			if (!slot->payload_pages[slot->payload_page_cap])
				return -ENOMEM;
			slot->payload_page_cap++;
		}
		return 0;
	}
	linear_max = trustix_tixt_rx_single_coalesce_linear_max_value();
	linear_needed = min(needed, linear_max);
	if (linear_needed > slot->payload_cap) {
		cap = slot->payload_cap ? slot->payload_cap : 4096;
		while (cap < linear_needed &&
		       cap < linear_max)
			cap <<= 1;
		if (cap < linear_needed)
			cap = linear_needed;
		if (cap > linear_max)
			cap = linear_max;
		payload = krealloc(slot->payload, cap, GFP_ATOMIC);
		if (!payload)
			return -ENOMEM;
		slot->payload = payload;
		slot->payload_cap = cap;
		if (cap > trustix_tixt_rx_single_coalesce_linear_max_bytes)
			trustix_tixt_rx_single_coalesce_linear_max_bytes = cap;
	}
	page_needed = needed > linear_max ? needed - linear_max : 0;
	while (slot->payload_page_cap * PAGE_SIZE < page_needed) {
		if (slot->payload_page_cap >=
		    TRUSTIX_TIXT_RX_SINGLE_COALESCE_SPILL_PAGE_MAX)
			return -EMSGSIZE;
		slot->payload_pages[slot->payload_page_cap] =
			alloc_page(GFP_ATOMIC);
		if (!slot->payload_pages[slot->payload_page_cap])
			return -ENOMEM;
		slot->payload_page_cap++;
	}
	return 0;
}

static void trustix_tixt_rx_single_coalesce_copy_payload_locked(
				struct trustix_tixt_rx_single_coalesce_slot *slot,
				u32 offset, const u8 *src, u32 len)
{
	u32 copy_len;
	u32 page_index;
	u32 page_offset;
	u32 linear_max;
	void *addr;

	linear_max = trustix_tixt_rx_single_coalesce_linear_max_value();
	while (len) {
		if (slot->payload_page_only) {
			page_index = offset / PAGE_SIZE;
			page_offset = offset % PAGE_SIZE;
			copy_len = min_t(u32, len, PAGE_SIZE - page_offset);
			addr = kmap_local_page(slot->payload_pages[page_index]);
			memcpy((u8 *)addr + page_offset, src, copy_len);
			kunmap_local(addr);
			offset += copy_len;
			src += copy_len;
			len -= copy_len;
			continue;
		}
		if (offset < linear_max) {
			copy_len = min_t(u32, len,
					 linear_max - offset);
			memcpy(slot->payload + offset, src, copy_len);
			offset += copy_len;
			src += copy_len;
			len -= copy_len;
			continue;
		}
		page_offset = offset - linear_max;
		page_index = page_offset / PAGE_SIZE;
		page_offset %= PAGE_SIZE;
		copy_len = min_t(u32, len, PAGE_SIZE - page_offset);
		addr = kmap_local_page(slot->payload_pages[page_index]);
		memcpy((u8 *)addr + page_offset, src, copy_len);
		kunmap_local(addr);
		offset += copy_len;
		src += copy_len;
		len -= copy_len;
	}
}

static __wsum trustix_tixt_rx_single_coalesce_payload_csum_locked(
				const struct trustix_tixt_rx_single_coalesce_slot *slot,
				__wsum sum)
{
	u32 copy_len;
	u32 remaining;
	u32 offset = 0;
	u32 page_index = 0;
	void *addr;

	if (slot->payload_linear_len)
		sum = csum_partial(slot->payload, slot->payload_linear_len,
				   sum);
	remaining = slot->payload_page_len;
	while (remaining) {
		copy_len = min_t(u32, remaining, PAGE_SIZE);
		addr = kmap_local_page(slot->payload_pages[page_index]);
		sum = csum_partial((u8 *)addr + offset, copy_len, sum);
		kunmap_local(addr);
		remaining -= copy_len;
		page_index++;
		offset = 0;
	}
	return sum;
}

static void trustix_tixt_rx_single_coalesce_copy_pages_to_linear_locked(
				const struct trustix_tixt_rx_single_coalesce_slot *slot,
				u8 *dst)
{
	u32 copy_len;
	u32 remaining;
	u32 page_index = 0;
	void *addr;

	remaining = slot->payload_page_len;
	while (remaining) {
		copy_len = min_t(u32, remaining, PAGE_SIZE);
		addr = kmap_local_page(slot->payload_pages[page_index]);
		memcpy(dst, addr, copy_len);
		kunmap_local(addr);
		dst += copy_len;
		remaining -= copy_len;
		page_index++;
	}
}

static int trustix_tixt_rx_single_coalesce_copy_payload_range_locked(
				const struct trustix_tixt_rx_single_coalesce_slot *slot,
				u32 offset, u8 *dst, u32 len)
{
	u32 copy_len;
	u32 linear_max;
	u32 page_index;
	u32 page_offset;
	void *addr;

	if (!slot || !dst)
		return -EINVAL;
	if (check_add_overflow(offset, len, &copy_len) ||
	    copy_len > slot->total_payload)
		return -EMSGSIZE;

	linear_max = slot->payload_page_only ? 0 :
		     trustix_tixt_rx_single_coalesce_linear_max_value();
	while (len) {
		if (!slot->payload_page_only && offset < linear_max) {
			copy_len = min_t(u32, len, linear_max - offset);
			if (offset + copy_len > slot->payload_linear_len)
				return -EMSGSIZE;
			memcpy(dst, slot->payload + offset, copy_len);
			offset += copy_len;
			dst += copy_len;
			len -= copy_len;
			continue;
		}

		if (slot->payload_page_only) {
			page_offset = offset;
		} else {
			if (offset < linear_max)
				return -EMSGSIZE;
			page_offset = offset - linear_max;
		}
		page_index = page_offset / PAGE_SIZE;
		page_offset %= PAGE_SIZE;
		if (page_index >= slot->payload_page_cap ||
		    !slot->payload_pages[page_index])
			return -ENODATA;
		copy_len = min_t(u32, len, PAGE_SIZE - page_offset);
		addr = kmap_local_page(slot->payload_pages[page_index]);
		memcpy(dst, (u8 *)addr + page_offset, copy_len);
		kunmap_local(addr);
		offset += copy_len;
		dst += copy_len;
		len -= copy_len;
	}
	return 0;
}

static int trustix_tixt_rx_single_coalesce_copy_to_skb_frag(
				struct sk_buff *skb, const u8 *src, u32 len)
{
	struct page *page;
	unsigned int frag;
	unsigned int copy_len;
	void *addr;

	while (len) {
		frag = skb_shinfo(skb)->nr_frags;
		if (frag >= MAX_SKB_FRAGS)
			return -EMSGSIZE;
		page = alloc_page(GFP_ATOMIC);
		if (!page)
			return -ENOMEM;
		copy_len = min_t(u32, len, PAGE_SIZE);
		addr = kmap_local_page(page);
		memcpy(addr, src, copy_len);
		kunmap_local(addr);
		skb_add_rx_frag(skb, frag, page, 0, copy_len, PAGE_SIZE);
		src += copy_len;
		len -= copy_len;
		trustix_tixt_rx_single_coalesce_nonlinear_frags++;
	}
	return 0;
}

static unsigned int trustix_tixt_rx_single_coalesce_frag_count(u32 len)
{
	return len ? DIV_ROUND_UP(len, (u32)PAGE_SIZE) : 0;
}

static int trustix_tixt_rx_single_coalesce_add_payload_frags(
				struct sk_buff *skb,
				struct trustix_tixt_rx_single_coalesce_slot *slot,
				u32 linear_consumed)
{
	struct page *page;
	unsigned int frag;
	unsigned int linear_frags;
	unsigned int page_count;
	unsigned int page_frags;
	unsigned int page_index;
	u32 copy_len;
	u32 linear_len = 0;
	u32 remaining;
	int ret;

	if (linear_consumed < slot->payload_linear_len)
		linear_len = slot->payload_linear_len - linear_consumed;
	linear_frags = trustix_tixt_rx_single_coalesce_frag_count(linear_len);
	page_count =
		trustix_tixt_rx_single_coalesce_frag_count(slot->payload_page_len);
	page_frags = page_count;
	if (linear_frags + page_frags >
	    MAX_SKB_FRAGS - skb_shinfo(skb)->nr_frags)
		return -EMSGSIZE;
	for (page_index = 0; page_index < page_count; page_index++) {
		if (!slot->payload_pages[page_index])
			return -ENOMEM;
	}
	if (linear_consumed < slot->payload_linear_len) {
		ret = trustix_tixt_rx_single_coalesce_copy_to_skb_frag(
			skb, slot->payload + linear_consumed,
			slot->payload_linear_len - linear_consumed);
		if (ret)
			return ret;
	}
	remaining = slot->payload_page_len;
	for (page_index = 0; page_index < page_count; page_index++) {
		frag = skb_shinfo(skb)->nr_frags;
		page = slot->payload_pages[page_index];
		copy_len = min_t(u32, remaining, PAGE_SIZE);
		slot->payload_pages[page_index] = NULL;
		skb_add_rx_frag(skb, frag, page, 0, copy_len, PAGE_SIZE);
		trustix_tixt_rx_single_coalesce_nonlinear_frags++;
		trustix_tixt_rx_single_coalesce_page_transfer_pages++;
		trustix_tixt_rx_single_coalesce_page_transfer_bytes += copy_len;
		if (slot->payload_page_only) {
			trustix_tixt_rx_single_coalesce_page_only_pages++;
			trustix_tixt_rx_single_coalesce_page_only_bytes +=
				copy_len;
		}
		remaining -= copy_len;
	}
	if (page_count) {
		trustix_tixt_rx_single_coalesce_page_transfer_batches++;
		if (slot->payload_page_only)
			trustix_tixt_rx_single_coalesce_page_only_batches++;
	}
	for (page_index = page_count; page_index < slot->payload_page_cap;
	     page_index++) {
		if (slot->payload_pages[page_index]) {
			__free_page(slot->payload_pages[page_index]);
			slot->payload_pages[page_index] = NULL;
		}
	}
	slot->payload_page_cap = 0;
	slot->payload_page_len = 0;
	return 0;
}

static int trustix_tixt_rx_single_coalesce_build_direct_list_locked(
				struct trustix_tixt_rx_single_coalesce_slot *slot,
				struct trustix_tixt_rx_single_coalesce_emit *emit)
{
	struct sk_buff *head = NULL;
	struct sk_buff *tail = NULL;
	struct sk_buff *rx_skb;
	struct tcphdr *tcph;
	struct iphdr *iph;
	struct net_device *dev;
	u32 header_len;
	u32 payload_offset = 0;
	u32 remaining;
	u32 payload_len;
	u32 inner_len;
	u32 tcp_len;
	u32 seq;
	u8 *dst;
	u8 *l2;
	bool skip_tcp_csum;
	unsigned int count = 0;
	unsigned int direct_max_frames;
	unsigned int i;
	int ret = 0;

	if (!slot || !emit || !slot->dev || slot->frame_count < 2 ||
	    !slot->gso_size)
		return 0;
	if (!READ_ONCE(trustix_tixt_rx_single_coalesce_direct_list) ||
	    !READ_ONCE(trustix_tixt_rx_single_coalesce_mark_gso) ||
	    !READ_ONCE(trustix_tixt_rx_coalesce_segment_gso))
		return 0;
	direct_max_frames =
		trustix_tixt_rx_single_coalesce_direct_list_max_frames_value();
	if (!direct_max_frames || slot->frame_count > direct_max_frames)
		return 0;

	dev = slot->dev;
	header_len = sizeof(struct iphdr) + slot->tcp_header_len;
	if (slot->tcp_header_len < sizeof(struct tcphdr) ||
	    header_len > TRUSTIX_TIXT_RX_SINGLE_COALESCE_HEADER_MAX ||
	    slot->total_payload < slot->gso_size)
		return 0;

	remaining = slot->total_payload;
	seq = slot->next_seq - slot->total_payload;
	skip_tcp_csum =
		READ_ONCE(trustix_tixt_rx_single_coalesce_skip_tcp_csum);
	for (i = 0; i < slot->frame_count; i++) {
		if (!remaining) {
			ret = -EINVAL;
			goto fail;
		}
		payload_len = min(remaining, slot->gso_size);
		if (i + 1 < slot->frame_count &&
		    payload_len != slot->gso_size) {
			ret = -EINVAL;
			goto fail;
		}
		if (check_add_overflow(header_len, payload_len, &inner_len) ||
		    inner_len > 0xffff) {
			ret = -EMSGSIZE;
			goto fail;
		}
		if (i >= TRUSTIX_TIXT_RX_SINGLE_COALESCE_DIRECT_LIST_MAX_FRAMES) {
			ret = -EINVAL;
			goto fail;
		}

		rx_skb = netdev_alloc_skb_ip_align(dev, ETH_HLEN + inner_len);
		if (!rx_skb) {
			ret = -ENOMEM;
			goto fail;
		}
		skb_reserve(rx_skb, ETH_HLEN);
		dst = skb_put(rx_skb, inner_len);
		if (i < TRUSTIX_TIXT_RX_SINGLE_COALESCE_DIRECT_LIST_MAX_FRAMES)
			memcpy(dst, slot->frame_headers[i], header_len);
		else
			memcpy(dst, slot->header, header_len);
		ret = trustix_tixt_rx_single_coalesce_copy_payload_range_locked(
			slot, payload_offset, dst + header_len, payload_len);
		if (ret) {
			kfree_skb(rx_skb);
			goto fail;
		}

		iph = (struct iphdr *)dst;
		tcph = (struct tcphdr *)(dst + sizeof(struct iphdr));
		iph->tot_len = htons(inner_len);
		iph->check = 0;
		iph->check = trustix_ipv4_header_check20((const u8 *)iph);
		tcph->seq = htonl(slot->seqs[i] ? slot->seqs[i] : seq);
		tcp_len = slot->tcp_header_len + payload_len;
		if (skip_tcp_csum) {
			/* The receive side is explicitly configured to trust it. */
		} else if (slot->tcp_checks[i]) {
			tcph->check = slot->tcp_checks[i];
		} else {
			__wsum sum;

			tcph->check = 0;
			sum = csum_partial(tcph, tcp_len, 0);
			tcph->check = csum_tcpudp_magic(
				iph->saddr, iph->daddr, tcp_len,
				IPPROTO_TCP, sum);
		}

		skb_reset_network_header(rx_skb);
		skb_set_transport_header(rx_skb, sizeof(struct iphdr));
		l2 = skb_push(rx_skb, ETH_HLEN);
		skb_reset_mac_header(rx_skb);
		trustix_write_l2_header(l2, slot->l2_head, slot->l2_tail0,
					slot->l2_tail1);
		rx_skb->dev = dev;
		rx_skb->protocol = eth_type_trans(rx_skb, dev);
		rx_skb->skb_iif = dev->ifindex;
		rx_skb->pkt_type = PACKET_HOST;
		rx_skb->encapsulation = 0;
		rx_skb->csum = 0;
		rx_skb->csum_start = 0;
		rx_skb->csum_offset = 0;
		rx_skb->csum_level = 0;
		rx_skb->ip_summed = CHECKSUM_UNNECESSARY;
		if (READ_ONCE(trustix_tixt_rx_single_coalesce_set_hash) &&
		    slot->skb_hash)
			skb_set_hash(rx_skb, slot->skb_hash, PKT_HASH_TYPE_L4);
		rx_skb->next = NULL;
		if (tail)
			tail->next = rx_skb;
		else
			head = rx_skb;
		tail = rx_skb;
		count++;
		payload_offset += payload_len;
		remaining -= payload_len;
		seq += payload_len;
	}
	if (remaining || count != slot->frame_count) {
		ret = -EINVAL;
		goto fail;
	}

	if (skip_tcp_csum)
		trustix_tixt_rx_single_coalesce_tcp_csum_skipped++;
	else
		trustix_tixt_rx_single_coalesce_tcp_csum_computed++;
	emit->skb_list = head;
	emit->dev = dev;
	emit->gso_size = slot->gso_size;
	emit->frames = slot->frame_count;
	emit->list_frames = count;
	trustix_tixt_rx_single_coalesce_reset_locked(slot);
	return 1;

fail:
	trustix_tixt_rx_stream_free_skb_list(head);
	trustix_tixt_rx_single_coalesce_direct_list_errors++;
	return ret ? ret : -EIO;
}

static void trustix_tixt_rx_single_coalesce_build_locked(
				struct trustix_tixt_rx_single_coalesce_slot *slot,
				struct trustix_tixt_rx_single_coalesce_emit *emit)
{
	struct sk_buff *rx_skb;
	struct tcphdr *tcph;
	struct iphdr *iph;
	struct net_device *dev;
	u32 tcp_len;
	u32 header_len;
	u32 linear_inner_len;
	u32 linear_payload_len;
	u32 total_inner_len;
	bool linear_build;
	bool hybrid_head;
	bool nonlinear;
	bool skip_tcp_csum;
	bool mark_rx_gso;
	int ret;
	u8 *dst;
	u8 *l2;
	__wsum sum;
	__sum16 tcp_check = 0;

	memset(emit, 0, sizeof(*emit));
	if (!slot || !slot->frame_count || !slot->dev)
		return;
	dev = slot->dev;
	if (check_add_overflow((u32)sizeof(struct iphdr) +
				       slot->tcp_header_len,
			       slot->total_payload, &total_inner_len) ||
	    total_inner_len > 0xffff) {
		trustix_tixt_rx_single_coalesce_errors++;
		emit->dev = dev;
		trustix_tixt_rx_single_coalesce_reset_locked(slot);
		return;
	}
	header_len = sizeof(struct iphdr) + slot->tcp_header_len;
	ret = trustix_tixt_rx_single_coalesce_build_direct_list_locked(slot,
								      emit);
	if (ret > 0)
		return;
	if (ret < 0)
		trustix_tixt_rx_single_coalesce_direct_list_fallbacks++;

	linear_build = READ_ONCE(trustix_tixt_rx_single_coalesce_linear_build) &&
		       !slot->payload_page_only &&
		       (slot->payload_page_len || total_inner_len > 32768);
	nonlinear = !linear_build &&
		    (slot->payload_page_only || slot->payload_page_len ||
		     total_inner_len > 32768);
	hybrid_head = nonlinear &&
		      READ_ONCE(trustix_tixt_rx_single_coalesce_hybrid_head) &&
		      !slot->payload_page_only && slot->payload_linear_len;
	linear_payload_len = hybrid_head ? slot->payload_linear_len :
			     (nonlinear ? 0 : slot->total_payload);
	linear_inner_len = header_len + linear_payload_len;
	rx_skb = netdev_alloc_skb_ip_align(dev, ETH_HLEN + linear_inner_len);
	if (!rx_skb && hybrid_head) {
		hybrid_head = false;
		linear_payload_len = 0;
		linear_inner_len = header_len;
		rx_skb = netdev_alloc_skb_ip_align(dev,
						   ETH_HLEN +
						   linear_inner_len);
	}
	if (!rx_skb && linear_build) {
		trustix_tixt_rx_single_coalesce_linear_build_fallbacks++;
		nonlinear = true;
		linear_payload_len = 0;
		linear_inner_len = header_len;
		rx_skb = netdev_alloc_skb_ip_align(dev,
						   ETH_HLEN +
						   linear_inner_len);
	}
	if (!rx_skb) {
		trustix_tixt_rx_single_coalesce_errors++;
		if (linear_build)
			trustix_tixt_rx_single_coalesce_linear_build_errors++;
		emit->dev = dev;
		trustix_tixt_rx_single_coalesce_reset_locked(slot);
		return;
	}
	skb_reserve(rx_skb, ETH_HLEN);
	dst = skb_put(rx_skb, linear_inner_len);
	memcpy(dst, slot->header, header_len);
	tcph = (struct tcphdr *)(dst + sizeof(struct iphdr));
	tcph->ack_seq = htonl(slot->ack_seq);
	tcph->window = slot->window;
	tcph->urg_ptr = slot->urg_ptr;
	tcph->psh = !!(slot->tcp_flags & 0x08);
	if (linear_payload_len) {
		if (slot->payload_linear_len)
			memcpy(dst + header_len, slot->payload,
			       slot->payload_linear_len);
		if (slot->payload_page_len)
			trustix_tixt_rx_single_coalesce_copy_pages_to_linear_locked(
				slot, dst + header_len +
				slot->payload_linear_len);
	}
	iph = (struct iphdr *)dst;
	iph->tot_len = htons(total_inner_len);
	iph->check = 0;
	iph->check = trustix_ipv4_header_check20((const u8 *)iph);
	tcp_len = slot->tcp_header_len + slot->total_payload;
	mark_rx_gso = READ_ONCE(trustix_tixt_rx_single_coalesce_mark_gso);
	skip_tcp_csum =
		READ_ONCE(trustix_tixt_rx_single_coalesce_skip_tcp_csum);
	if (!skip_tcp_csum) {
		tcph->check = 0;
		sum = csum_partial(tcph, slot->tcp_header_len, 0);
		sum = trustix_tixt_rx_single_coalesce_payload_csum_locked(slot,
									  sum);
		tcp_check = csum_tcpudp_magic(iph->saddr, iph->daddr,
					      tcp_len, IPPROTO_TCP, sum);
	}
	if (nonlinear) {
		ret = trustix_tixt_rx_single_coalesce_add_payload_frags(
			rx_skb, slot, linear_payload_len);
		if (ret) {
			kfree_skb(rx_skb);
			trustix_tixt_rx_single_coalesce_errors++;
			trustix_tixt_rx_single_coalesce_nonlinear_errors++;
			if (slot->payload_page_only)
				trustix_tixt_rx_single_coalesce_page_only_errors++;
			emit->dev = dev;
			trustix_tixt_rx_single_coalesce_reset_locked(slot);
			return;
		}
		trustix_tixt_rx_single_coalesce_nonlinear_batches++;
	}

	if (skip_tcp_csum) {
		trustix_tixt_rx_single_coalesce_tcp_csum_skipped++;
	} else {
		tcph->check = tcp_check;
		trustix_tixt_rx_single_coalesce_tcp_csum_computed++;
	}
	if (linear_build && !nonlinear) {
		trustix_tixt_rx_single_coalesce_linear_build_batches++;
		trustix_tixt_rx_single_coalesce_linear_build_bytes +=
			slot->total_payload;
	}
	if (hybrid_head) {
		trustix_tixt_rx_single_coalesce_hybrid_head_batches++;
		trustix_tixt_rx_single_coalesce_hybrid_head_bytes +=
			linear_payload_len;
	}

	skb_reset_network_header(rx_skb);
	skb_set_transport_header(rx_skb, sizeof(struct iphdr));
	l2 = skb_push(rx_skb, ETH_HLEN);
	skb_reset_mac_header(rx_skb);
	trustix_write_l2_header(l2, slot->l2_head, slot->l2_tail0,
				slot->l2_tail1);
	rx_skb->dev = dev;
	rx_skb->protocol = eth_type_trans(rx_skb, dev);
	rx_skb->skb_iif = dev->ifindex;
	rx_skb->pkt_type = PACKET_HOST;
	rx_skb->encapsulation = 0;
	rx_skb->csum = 0;
	rx_skb->csum_level = 0;
	rx_skb->ip_summed = CHECKSUM_UNNECESSARY;
	if (READ_ONCE(trustix_tixt_rx_single_coalesce_set_hash) &&
	    slot->skb_hash) {
		skb_set_hash(rx_skb, slot->skb_hash, PKT_HASH_TYPE_L4);
		trustix_tixt_rx_single_coalesce_hash_sets++;
	}
	if (mark_rx_gso && slot->frame_count > 1)
		trustix_tixt_rx_coalesced_mark_tcpv4_gso(
			rx_skb, slot->gso_size, slot->frame_count);
	emit->skb = rx_skb;
	emit->dev = dev;
	emit->gso_size = slot->gso_size;
	emit->frames = slot->frame_count;
	trustix_tixt_rx_single_coalesce_reset_locked(slot);
}

static void trustix_tixt_rx_single_coalesce_publish(
				struct trustix_tixt_rx_single_coalesce_emit *emit)
{
	int ret;
	bool published = false;

	if (!emit || !emit->dev)
		return;
	if (emit->skb) {
		if (emit->frames > 1 && emit->gso_size &&
		    READ_ONCE(trustix_tixt_rx_coalesce_segment_gso)) {
			ret = trustix_tixt_rx_coalesced_segment_and_publish(
				emit->skb, emit->dev, emit->gso_size,
				emit->frames);
			emit->skb = NULL;
			published = ret > 0;
		} else {
			ret = trustix_tixt_rx_publish_one_backlog(
				emit->skb,
				&trustix_tixt_rx_single_coalesce_netif_rx_packets,
				&trustix_tixt_rx_single_coalesce_netif_rx_drops);
			published = !ret;
		}
		if (!published) {
			trustix_tixt_rx_single_coalesce_xmit_errors++;
		} else {
			trustix_tixt_rx_single_coalesce_batches++;
			trustix_tixt_rx_single_coalesce_frames += emit->frames;
		}
	}
	if (emit->skb_list) {
		LIST_HEAD(rx_list);
		struct sk_buff *skb = emit->skb_list;
		struct sk_buff *next;
		unsigned int count = 0;

		while (skb) {
			next = skb->next;
			skb->next = NULL;
			INIT_LIST_HEAD(&skb->list);
			list_add_tail(&skb->list, &rx_list);
			count++;
			skb = next;
		}
		if (count) {
			trustix_tixt_rx_publish_receive_list_backlog(
				&rx_list,
				&trustix_tixt_rx_single_coalesce_netif_rx_packets,
				&trustix_tixt_rx_single_coalesce_netif_rx_drops);
			trustix_tixt_rx_single_coalesce_batches++;
			trustix_tixt_rx_single_coalesce_frames +=
				emit->frames;
			trustix_tixt_rx_single_coalesce_direct_list_batches++;
			trustix_tixt_rx_single_coalesce_direct_list_frames +=
				emit->list_frames ? emit->list_frames : count;
		}
	}
	dev_put(emit->dev);
	memset(emit, 0, sizeof(*emit));
}

static void trustix_tixt_rx_single_coalesce_flush_slot(
				struct trustix_tixt_rx_single_coalesce_slot *slot)
{
	struct trustix_tixt_rx_single_coalesce_emit emit;

	spin_lock_bh(&slot->lock);
	trustix_tixt_rx_single_coalesce_build_locked(slot, &emit);
	spin_unlock_bh(&slot->lock);
	if (emit.skb)
		trustix_tixt_rx_single_coalesce_flushes++;
	trustix_tixt_rx_single_coalesce_publish(&emit);
}

static void trustix_tixt_rx_single_coalesce_drop_all(void)
{
	struct trustix_tixt_rx_single_coalesce_slot *slot;
	struct net_device *dev;
	unsigned int page_index;
	unsigned int i;

	for (i = 0; i < TRUSTIX_TIXT_RX_SINGLE_COALESCE_SLOTS; i++) {
		slot = &trustix_tixt_rx_single_coalesce_slots[i];
		cancel_delayed_work_sync(&slot->flush_work);
		spin_lock_bh(&slot->lock);
		dev = slot->dev;
		slot->dev = NULL;
		trustix_tixt_rx_single_coalesce_reset_locked(slot);
		kfree(slot->payload);
		slot->payload = NULL;
		slot->payload_cap = 0;
		for (page_index = 0; page_index < slot->payload_page_cap;
		     page_index++) {
			__free_page(slot->payload_pages[page_index]);
			slot->payload_pages[page_index] = NULL;
		}
		slot->payload_page_cap = 0;
		slot->payload_page_len = 0;
		spin_unlock_bh(&slot->lock);
		if (dev)
			dev_put(dev);
	}
}

static void trustix_tixt_rx_single_coalesce_init_slots(void)
{
	unsigned int i;

	for (i = 0; i < TRUSTIX_TIXT_RX_SINGLE_COALESCE_SLOTS; i++) {
		spin_lock_init(&trustix_tixt_rx_single_coalesce_slots[i].lock);
		INIT_DELAYED_WORK(
			&trustix_tixt_rx_single_coalesce_slots[i].flush_work,
			trustix_tixt_rx_single_coalesce_flush_work);
	}
	WRITE_ONCE(trustix_tixt_rx_single_coalesce_slots_ready, true);
}

static void trustix_tixt_rx_single_coalesce_flush_work(
				struct work_struct *work)
{
	struct delayed_work *dwork = to_delayed_work(work);
	struct trustix_tixt_rx_single_coalesce_slot *slot =
		container_of(dwork, struct trustix_tixt_rx_single_coalesce_slot,
			     flush_work);

	if (!READ_ONCE(trustix_tixt_rx_single_coalesce_slots_ready))
		return;
	trustix_tixt_rx_single_coalesce_flush_slot(slot);
}

static int trustix_tixt_rx_single_coalesce_parse(
				struct sk_buff *skb, u32 outer_len,
				struct trustix_tixt_rx_single_coalesce_frame *frame)
{
	const u8 *inner;
	const struct iphdr *iph;
	const struct tcphdr *tcph;
	u32 frame_offset;
	u32 payload_offset;
	u32 inner_len;
	u32 tcp_header_len;
	u32 payload_len;
	bool hot_stats;

	if (!skb || !frame || outer_len != TRUSTIX_TIXT_TCP_OUTER_OVERHEAD) {
		trustix_tixt_rx_single_coalesce_parse_bad_outer++;
		return -EINVAL;
	}
	hot_stats = READ_ONCE(trustix_tixt_rx_single_coalesce_hot_stats);
	frame_offset = ETH_HLEN + sizeof(struct iphdr) + sizeof(struct tcphdr);
	payload_offset = ETH_HLEN + outer_len;
	if (skb->len < payload_offset + sizeof(struct iphdr)) {
		trustix_tixt_rx_single_coalesce_parse_short++;
		return -ENODATA;
	}
	if (unlikely(payload_offset + sizeof(struct iphdr) > skb_headlen(skb) &&
		     !pskb_may_pull(skb, payload_offset +
					     sizeof(struct iphdr)))) {
		trustix_tixt_rx_single_coalesce_parse_short++;
		return -ENODATA;
	}
	if (payload_offset + sizeof(struct iphdr) > skb_headlen(skb)) {
		trustix_tixt_rx_single_coalesce_parse_short++;
		return -ENODATA;
	}
	inner_len = get_unaligned_be32(skb->data + frame_offset + 32);
	if (hot_stats)
		WRITE_ONCE(trustix_tixt_rx_single_coalesce_last_inner_len,
			   inner_len);
	if (inner_len < sizeof(struct iphdr) + sizeof(struct tcphdr) ||
	    payload_offset + inner_len > skb->len) {
		trustix_tixt_rx_single_coalesce_parse_bad_len++;
		return -EMSGSIZE;
	}
	if (unlikely(payload_offset + inner_len > skb_headlen(skb) &&
		     !pskb_may_pull(skb, payload_offset + inner_len))) {
		trustix_tixt_rx_single_coalesce_parse_short++;
		return -ENODATA;
	}
	if (payload_offset + inner_len > skb_headlen(skb)) {
		trustix_tixt_rx_single_coalesce_parse_short++;
		return -ENODATA;
	}
	inner = skb->data + payload_offset;
	iph = (const struct iphdr *)inner;
	if (hot_stats) {
		WRITE_ONCE(trustix_tixt_rx_single_coalesce_last_inner_proto,
			   (unsigned int)iph->protocol);
		WRITE_ONCE(trustix_tixt_rx_single_coalesce_last_inner_tot_len,
			   (unsigned int)ntohs(iph->tot_len));
	}
	if (iph->version != 4 || iph->ihl != 5 ||
	    iph->protocol != IPPROTO_TCP) {
		trustix_tixt_rx_single_coalesce_parse_not_tcp++;
		return -EPROTONOSUPPORT;
	}
	if (iph->frag_off & htons(0x3fff)) {
		trustix_tixt_rx_single_coalesce_parse_fragment++;
		return -EPROTONOSUPPORT;
	}
	if (ntohs(iph->tot_len) != inner_len) {
		trustix_tixt_rx_single_coalesce_parse_totlen_mismatch++;
		return -EPROTONOSUPPORT;
	}
	tcph = (const struct tcphdr *)(inner + sizeof(*iph));
	tcp_header_len = tcph->doff * 4;
	if (hot_stats)
		WRITE_ONCE(trustix_tixt_rx_single_coalesce_last_tcp_header_len,
			   tcp_header_len);
	if (tcp_header_len < sizeof(*tcph) ||
	    tcp_header_len > 60 ||
	    inner_len < sizeof(*iph) + tcp_header_len) {
		trustix_tixt_rx_single_coalesce_parse_bad_tcp++;
		return -EPROTONOSUPPORT;
	}
	if (tcph->syn || tcph->fin || tcph->rst) {
		trustix_tixt_rx_single_coalesce_parse_tcp_flags++;
		return -EPROTONOSUPPORT;
	}
	if (!tcph->ack || tcph->urg || tcph->ece || tcph->cwr) {
		trustix_tixt_rx_single_coalesce_parse_tcp_flags++;
		return -EPROTONOSUPPORT;
	}
	payload_len = inner_len - sizeof(*iph) - tcp_header_len;
	if (hot_stats)
		WRITE_ONCE(trustix_tixt_rx_single_coalesce_last_payload_len,
			   payload_len);
	if (payload_len < TRUSTIX_TIXT_RX_SINGLE_COALESCE_MIN_PAYLOAD ||
	    payload_len > TRUSTIX_TIXT_RX_SINGLE_COALESCE_PAYLOAD_MAX) {
		trustix_tixt_rx_single_coalesce_parse_no_payload++;
		return -EPROTONOSUPPORT;
	}

	frame->inner = inner;
	frame->inner_len = inner_len;
	frame->tcp_header_len = tcp_header_len;
	frame->payload_len = payload_len;
	frame->payload_offset = sizeof(*iph) + tcp_header_len;
	frame->saddr = iph->saddr;
	frame->daddr = iph->daddr;
	frame->source = tcph->source;
	frame->dest = tcph->dest;
	frame->seq = ntohl(tcph->seq);
	frame->ack_seq = ntohl(tcph->ack_seq);
	frame->window = tcph->window;
	frame->urg_ptr = tcph->urg_ptr;
	frame->tcp_check = tcph->check;
	frame->tcp_flags = ((u8)tcph->fin) |
			   ((u8)tcph->syn << 1) |
			   ((u8)tcph->rst << 2) |
			   ((u8)tcph->psh << 3) |
			   ((u8)tcph->ack << 4) |
			   ((u8)tcph->urg << 5) |
			   ((u8)tcph->ece << 6) |
			   ((u8)tcph->cwr << 7);
	return 0;
}

static int trustix_tixt_rx_single_coalesce_try(
				struct sk_buff *skb, struct net_device *dev,
				const struct trustix_kudp_rx_parse_args *args,
				u32 outer_len)
{
	struct trustix_tixt_rx_single_coalesce_emit emit;
	struct trustix_tixt_rx_single_coalesce_slot *slot;
	struct trustix_tixt_rx_single_coalesce_frame frame;
	struct net_device *drop_dev = NULL;
	unsigned int max_frames;
	unsigned int schedule_stride;
	unsigned int warmup_frames;
	unsigned int index;
	u32 skb_hash;
	bool flush_now = false;
	bool new_slot = false;
	bool schedule = false;
	bool defer_full_flush = false;
	bool slot_page_only = false;
	unsigned long schedule_delay = 0;
	u32 needed;
	int ret;

	memset(&emit, 0, sizeof(emit));
	if (!READ_ONCE(trustix_tixt_rx_single_coalesce_gso))
		return 0;
	if (!READ_ONCE(trustix_tixt_rx_single_coalesce_slots_ready))
		return 0;
	if (!skb || !dev || !args ||
	    !(args->decap_flags & TRUSTIX_KUDP_RX_DECAP_L2_TRUST_INNER_L4_CSUM))
		return 0;
	ret = trustix_tixt_rx_single_coalesce_parse(skb, outer_len, &frame);
	if (ret) {
		trustix_tixt_rx_single_coalesce_fallbacks++;
		return 0;
	}
	max_frames = trustix_tixt_rx_single_coalesce_max_frames_value();
	schedule_stride = READ_ONCE(
		trustix_tixt_rx_single_coalesce_schedule_stride);
	warmup_frames = trustix_tixt_rx_single_coalesce_warmup_frames_value();
	skb_hash = trustix_tixt_rx_single_coalesce_hash_value(dev,
		frame.saddr, frame.daddr, frame.source, frame.dest);
	index = skb_hash & (TRUSTIX_TIXT_RX_SINGLE_COALESCE_SLOTS - 1);
	slot = &trustix_tixt_rx_single_coalesce_slots[index];

	spin_lock_bh(&slot->lock);
	if (!slot->frame_count) {
		if (!trustix_tixt_rx_single_coalesce_armed_match(slot, dev,
								 &frame)) {
			if (slot->armed)
				trustix_tixt_rx_single_coalesce_record_miss(
					slot, dev, &frame);
			slot->dev = NULL;
			slot->armed = true;
			slot->armed_ifindex = dev ? dev->ifindex : 0;
			slot->armed_passes = 1;
			slot->l2_head = args->l2_head;
			slot->l2_tail0 = args->l2_tail0;
			slot->l2_tail1 = args->l2_tail1;
			slot->decap_flags = args->decap_flags;
			slot->saddr = frame.saddr;
			slot->daddr = frame.daddr;
			slot->source = frame.source;
			slot->dest = frame.dest;
			slot->window = frame.window;
			slot->urg_ptr = frame.urg_ptr;
			slot->skb_hash = skb_hash;
			slot->tcp_header_len = frame.tcp_header_len;
			slot->next_seq = frame.seq + frame.payload_len;
			slot->ack_seq = frame.ack_seq;
			slot->tcp_flags = frame.tcp_flags;
			slot->gso_size = frame.payload_len;
			spin_unlock_bh(&slot->lock);
			trustix_tixt_rx_single_coalesce_warmup_passes++;
			return 0;
		}
		if (slot->armed_passes < warmup_frames) {
			slot->armed_passes++;
			slot->next_seq = frame.seq + frame.payload_len;
			spin_unlock_bh(&slot->lock);
			trustix_tixt_rx_single_coalesce_warmup_passes++;
			return 0;
		}
	}
	if (slot->frame_count &&
	    !trustix_tixt_rx_single_coalesce_match(slot, dev, &frame)) {
		trustix_tixt_rx_single_coalesce_collisions++;
		trustix_tixt_rx_single_coalesce_record_miss(slot, dev, &frame);
		trustix_tixt_rx_single_coalesce_build_locked(slot, &emit);
		cancel_delayed_work(&slot->flush_work);
		if (!trustix_tixt_rx_single_coalesce_armed_match(slot, dev,
								 &frame)) {
			slot->dev = NULL;
			slot->armed = true;
			slot->armed_ifindex = dev ? dev->ifindex : 0;
			slot->armed_passes = 1;
			slot->l2_head = args->l2_head;
			slot->l2_tail0 = args->l2_tail0;
			slot->l2_tail1 = args->l2_tail1;
			slot->decap_flags = args->decap_flags;
			slot->saddr = frame.saddr;
			slot->daddr = frame.daddr;
			slot->source = frame.source;
			slot->dest = frame.dest;
			slot->window = frame.window;
			slot->urg_ptr = frame.urg_ptr;
			slot->skb_hash = skb_hash;
			slot->tcp_header_len = frame.tcp_header_len;
			slot->next_seq = frame.seq + frame.payload_len;
			slot->ack_seq = frame.ack_seq;
			slot->tcp_flags = frame.tcp_flags;
			slot->gso_size = frame.payload_len;
			spin_unlock_bh(&slot->lock);
			trustix_tixt_rx_single_coalesce_publish(&emit);
			trustix_tixt_rx_single_coalesce_warmup_passes++;
			return 0;
		}
		if (slot->armed_passes < warmup_frames) {
			slot->armed_passes++;
			slot->next_seq = frame.seq + frame.payload_len;
			spin_unlock_bh(&slot->lock);
			trustix_tixt_rx_single_coalesce_publish(&emit);
			trustix_tixt_rx_single_coalesce_warmup_passes++;
			return 0;
		}
	}
	if (!slot->frame_count) {
		dev_hold(dev);
		slot->dev = dev;
		slot->l2_head = args->l2_head;
		slot->l2_tail0 = args->l2_tail0;
		slot->l2_tail1 = args->l2_tail1;
		slot->decap_flags = args->decap_flags;
		slot->saddr = frame.saddr;
		slot->daddr = frame.daddr;
		slot->source = frame.source;
		slot->dest = frame.dest;
		slot->window = frame.window;
		slot->urg_ptr = frame.urg_ptr;
		slot->skb_hash = skb_hash;
		slot->tcp_header_len = frame.tcp_header_len;
		slot->next_seq = frame.seq;
		slot->ack_seq = frame.ack_seq;
		slot->tcp_flags = frame.tcp_flags;
		slot->gso_size = frame.payload_len;
		slot->total_payload = 0;
		slot->payload_page_only =
			READ_ONCE(trustix_tixt_rx_single_coalesce_page_only);
		memcpy(slot->header, frame.inner,
		       sizeof(struct iphdr) + frame.tcp_header_len);
		new_slot = true;
	}
	if (!new_slot &&
	    !trustix_tixt_rx_single_coalesce_match(slot, dev, &frame)) {
		spin_unlock_bh(&slot->lock);
		trustix_tixt_rx_single_coalesce_publish(&emit);
		trustix_tixt_rx_single_coalesce_fallbacks++;
		return 0;
	}
	if (!new_slot)
		trustix_tixt_rx_single_coalesce_record_relaxed_diffs(slot,
								     &frame);
	if (slot->frame_count >= TRUSTIX_TIXT_RX_SINGLE_COALESCE_MAX_FRAMES) {
		trustix_tixt_rx_single_coalesce_build_locked(slot, &emit);
		spin_unlock_bh(&slot->lock);
		trustix_tixt_rx_single_coalesce_publish(&emit);
		trustix_tixt_rx_single_coalesce_fallbacks++;
		return 0;
	}
	if (check_add_overflow(slot->total_payload, frame.payload_len,
			       &needed) ||
	    sizeof(struct iphdr) + frame.tcp_header_len + needed > 0xffff ||
	    needed > TRUSTIX_TIXT_RX_SINGLE_COALESCE_PAYLOAD_MAX) {
		trustix_tixt_rx_single_coalesce_build_locked(slot, &emit);
		spin_unlock_bh(&slot->lock);
		trustix_tixt_rx_single_coalesce_publish(&emit);
		trustix_tixt_rx_single_coalesce_fallbacks++;
		return 0;
	}
	ret = trustix_tixt_rx_single_coalesce_ensure_payload_locked(slot,
								   needed);
	if (ret) {
		slot_page_only = slot->payload_page_only;
		if (!slot->frame_count && slot->dev) {
			drop_dev = slot->dev;
			slot->dev = NULL;
			trustix_tixt_rx_single_coalesce_reset_locked(slot);
		} else {
			trustix_tixt_rx_single_coalesce_build_locked(slot,
								     &emit);
		}
		spin_unlock_bh(&slot->lock);
		trustix_tixt_rx_single_coalesce_publish(&emit);
		if (drop_dev)
			dev_put(drop_dev);
		trustix_tixt_rx_single_coalesce_errors++;
		if (slot_page_only)
			trustix_tixt_rx_single_coalesce_page_only_errors++;
		return 0;
	}
	trustix_tixt_rx_single_coalesce_copy_payload_locked(
		slot, slot->total_payload,
		frame.inner + frame.payload_offset, frame.payload_len);
	slot->total_payload = needed;
	if (slot->payload_page_only) {
		slot->payload_linear_len = 0;
		slot->payload_page_len = slot->total_payload;
	} else {
		u32 linear_max =
			trustix_tixt_rx_single_coalesce_linear_max_value();

		slot->payload_linear_len = min(slot->total_payload,
					       linear_max);
		slot->payload_page_len =
			slot->total_payload > linear_max ?
			slot->total_payload - linear_max : 0;
	}
	slot->next_seq = frame.seq + frame.payload_len;
	slot->ack_seq = frame.ack_seq;
	slot->window = frame.window;
	slot->urg_ptr = frame.urg_ptr;
	slot->tcp_flags = frame.tcp_flags;
	if (slot->frame_count <
	    TRUSTIX_TIXT_RX_SINGLE_COALESCE_DIRECT_LIST_MAX_FRAMES) {
		slot->seqs[slot->frame_count] = frame.seq;
		slot->tcp_checks[slot->frame_count] = frame.tcp_check;
		memcpy(slot->frame_headers[slot->frame_count], frame.inner,
		       sizeof(struct iphdr) + frame.tcp_header_len);
	}
	slot->frame_count++;
	if (READ_ONCE(trustix_tixt_rx_single_coalesce_hot_stats))
		trustix_tixt_rx_single_coalesce_candidates++;
	if (slot->frame_count >= max_frames ||
	    frame.payload_len != slot->gso_size)
		flush_now = true;
	else if (new_slot ||
		 (!READ_ONCE(trustix_tixt_rx_single_coalesce_schedule_once) &&
		  (schedule_stride <= 1 ||
		   slot->frame_count % schedule_stride == 0)))
		schedule = true;
	else if (READ_ONCE(trustix_tixt_rx_single_coalesce_hot_stats))
		trustix_tixt_rx_single_coalesce_schedule_skips++;
	if (flush_now) {
		defer_full_flush =
			READ_ONCE(trustix_tixt_rx_single_coalesce_defer_full_flush) &&
			slot->frame_count >= max_frames &&
			frame.payload_len == slot->gso_size;
		if (defer_full_flush) {
			if (!slot->flush_queued) {
				slot->flush_queued = true;
				schedule = true;
				schedule_delay = 0;
				trustix_tixt_rx_single_coalesce_defer_full_flushes++;
			}
		} else {
			trustix_tixt_rx_single_coalesce_build_locked(slot,
								     &emit);
			if (READ_ONCE(trustix_tixt_rx_single_coalesce_keep_full_timer)) {
				trustix_tixt_rx_single_coalesce_full_cancel_skips++;
			} else {
				cancel_delayed_work(&slot->flush_work);
			}
		}
	}
	spin_unlock_bh(&slot->lock);

	if (schedule) {
		trustix_tixt_rx_single_coalesce_schedules++;
		if (!defer_full_flush)
			schedule_delay =
				trustix_tixt_rx_single_coalesce_flush_jiffies_value();
		mod_delayed_work(system_wq, &slot->flush_work,
				 schedule_delay);
	}
	trustix_tixt_rx_single_coalesce_publish(&emit);
	return 1;
}

static int trustix_tixt_rx_stream_decap_local(
				struct sk_buff *skb,
				const struct trustix_kudp_rx_parse_args *args,
				const struct trustix_tixt_rx_stream_frame *frames,
				unsigned int frame_count, u32 outer_len,
				bool forced_stream_parse)
{
	struct sk_buff *extra_head = NULL;
	struct net_device *dev;
	struct net *net;
	u32 first_len;
	bool stream_parse = READ_ONCE(trustix_tixt_rx_stream_parse);
	bool stream_xmit_extra = READ_ONCE(trustix_tixt_rx_stream_xmit_extra);
	bool single_stream_fallback =
		trustix_tixt_rx_single_coalesce_stream_fallback_enabled();
	bool allow_stream_parse = stream_parse || single_stream_fallback ||
				  forced_stream_parse;
	bool allow_stream_xmit_extra = stream_xmit_extra ||
				       single_stream_fallback ||
				       forced_stream_parse;
	unsigned int published;
	int ret;

	if (!skb || !args || !frames || frame_count < 2)
		return -EINVAL;
	if (!allow_stream_parse || !allow_stream_xmit_extra) {
		trustix_tixt_rx_stream_disabled++;
		return -EPROTONOSUPPORT;
	}
	if (!trustix_tixt_rx_stream_local_match(args, frames[0].next_hop)) {
		trustix_tixt_rx_stream_disabled++;
		return -EPROTONOSUPPORT;
	}
	if (!skb->dev)
		return -ENODEV;

	net = dev_net(skb->dev);
	rcu_read_lock();
	dev = dev_get_by_index_rcu(net, args->local_ifindex);
	if (!dev) {
		rcu_read_unlock();
		return -ENODEV;
	}
	dev_hold(dev);
	rcu_read_unlock();

	if (forced_stream_parse) {
		ret = trustix_tixt_rx_stream_build_extra_list(
			skb, dev, args, frames, frame_count, 0, &extra_head);
		if (ret) {
			dev_put(dev);
			return ret;
		}
		if (!extra_head) {
			trustix_tixt_rx_stream_ordered_list_errors++;
			dev_put(dev);
			return -ENODATA;
		}
		published = trustix_tixt_rx_stream_publish_extra_list(
			extra_head);
		trustix_tixt_rx_stream_ordered_list_batches++;
		trustix_tixt_rx_stream_ordered_list_frames += published;
		if (published != frame_count)
			trustix_tixt_rx_stream_ordered_list_errors++;
		dev_put(dev);
		return TRUSTIX_KUDP_RX_PARSE_DECAP_L2_STOLEN;
	}

	ret = trustix_tixt_rx_stream_try_coalesce_gso(skb, dev, args, frames,
						      frame_count);
	if (ret > 0) {
		dev_put(dev);
		return TRUSTIX_KUDP_RX_PARSE_DECAP_L2_STOLEN;
	}
	if (ret < 0) {
		dev_put(dev);
		return ret;
	}

	if (READ_ONCE(trustix_tixt_rx_stream_ordered_list)) {
		ret = trustix_tixt_rx_stream_build_extra_list(
			skb, dev, args, frames, frame_count, 0, &extra_head);
		if (ret) {
			trustix_tixt_rx_stream_ordered_list_errors++;
			dev_put(dev);
			return ret;
		}
		if (!extra_head) {
			trustix_tixt_rx_stream_ordered_list_errors++;
			dev_put(dev);
			return -ENODATA;
		}
		published = trustix_tixt_rx_stream_publish_extra_list(
			extra_head);
		trustix_tixt_rx_stream_ordered_list_batches++;
		trustix_tixt_rx_stream_ordered_list_frames += published;
		if (published != frame_count)
			trustix_tixt_rx_stream_ordered_list_errors++;
		dev_put(dev);
		return TRUSTIX_KUDP_RX_PARSE_DECAP_L2_STOLEN;
	}

	ret = trustix_tixt_rx_stream_build_extra_list(skb, dev, args, frames,
						      frame_count, 1,
						      &extra_head);
	if (ret) {
		dev_put(dev);
		return ret;
	}

	ret = trustix_skb_kudp_rx_decap_l2(skb, outer_len, args->l2_head,
					   args->l2_tail0, args->l2_tail1,
					   args->decap_flags);
	if (ret) {
		trustix_tixt_rx_stream_free_skb_list(extra_head);
		dev_put(dev);
		return ret;
	}
	first_len = ETH_HLEN + frames[0].payload_len;
	if (skb->len > first_len) {
		ret = pskb_trim(skb, first_len);
		if (ret) {
			trustix_tixt_rx_stream_free_skb_list(extra_head);
			dev_put(dev);
			return ret;
		}
		skb_gso_reset(skb);
	}
	skb->dev = dev;
	skb->skb_iif = dev->ifindex;
	skb->pkt_type = PACKET_HOST;
	trustix_tixt_rx_stream_publish_extra_list(extra_head);
	if (single_stream_fallback && !stream_parse) {
		trustix_tixt_rx_single_coalesce_stream_fallbacks++;
		trustix_tixt_rx_single_coalesce_stream_fallback_frames +=
			frame_count;
	}
	dev_put(dev);
	return TRUSTIX_KUDP_RX_PARSE_DECAP_L2_LOCAL_DELIVERED;
}

static int
trustix_skb_kudp_rx_parse_decap_l2(
				struct sk_buff *skb,
				const struct trustix_kudp_rx_parse_args *args)
{
	struct trustix_tixt_rx_stream_frame stream_frames[TRUSTIX_TIXT_RX_STREAM_MAX_FRAMES];
	struct net_device *dev = NULL;
	struct net *net = NULL;
	unsigned int stream_frame_count = 0;
	u32 outer_len = 0;
	u32 next_hop = 0;
	u32 outer_protocol;
	bool forced_stream_parse = false;
	bool local_dev = false;
	int ret;

	if (!skb || !args)
		return trustix_kudp_rx_record_parse_ret(-EINVAL);
	if (args->decap_flags &
	    ~TRUSTIX_KUDP_RX_DECAP_L2_TRUST_INNER_L4_CSUM)
		return trustix_kudp_rx_record_parse_ret(-EINVAL);
	if (args->local_ifindex && !args->local_ipv4)
		return trustix_kudp_rx_record_parse_ret(-EINVAL);
	if (args->local_ifindex && !skb->dev)
		return trustix_kudp_rx_record_parse_ret(-ENODEV);
	if (skb->len < ETH_HLEN + sizeof(struct iphdr))
		return trustix_kudp_rx_record_parse_ret(-ENODATA);
	if (unlikely(ETH_HLEN + sizeof(struct iphdr) > skb_headlen(skb) &&
		     !pskb_may_pull(skb, ETH_HLEN + sizeof(struct iphdr))))
		return trustix_kudp_rx_record_parse_ret(-ENODATA);
	if (ETH_HLEN + sizeof(struct iphdr) > skb_headlen(skb))
		return trustix_kudp_rx_record_parse_ret(-ENODATA);

	outer_protocol = *(u8 *)(skb->data + ETH_HLEN +
				 offsetof(struct iphdr, protocol));
	trustix_kudp_rx_record_shape(skb, outer_protocol);
	if (outer_protocol == IPPROTO_TCP) {
		forced_stream_parse =
			trustix_tixt_rx_tcp_outer_needs_stream_parse(skb);
	}
	if (outer_protocol == IPPROTO_TCP &&
	    (forced_stream_parse || trustix_tixt_rx_stream_parse_wanted(skb))) {
		ret = trustix_tixt_rx_stream_parse_frames(
			skb, args, stream_frames, &stream_frame_count,
			&outer_len);
		if (!ret)
			return trustix_kudp_rx_record_parse_ret(
				trustix_tixt_rx_stream_decap_local(
					skb, args, stream_frames,
					stream_frame_count, outer_len,
					forced_stream_parse));
		if (forced_stream_parse)
			return trustix_kudp_rx_record_parse_ret(
				ret == -EAGAIN ? -EPROTO : ret);
		if (ret != -EAGAIN)
			return trustix_kudp_rx_record_parse_ret(ret);
	}
	ret = trustix_skb_kudp_rx_parse_plain(skb, args, outer_protocol,
					      &outer_len, &next_hop);
	if (ret)
		return trustix_kudp_rx_record_parse_ret(ret);

	if (args->local_ifindex) {
		u32 local_mask = args->local_ipv4_mask;

		if (!local_mask)
			local_mask = ~0U;
		local_dev = ((next_hop ^ args->local_ipv4) & local_mask) == 0;
	}
	if (local_dev) {
		net = dev_net(skb->dev);
		rcu_read_lock();
		dev = dev_get_by_index_rcu(net, args->local_ifindex);
		if (!dev) {
			rcu_read_unlock();
			return trustix_kudp_rx_record_parse_ret(-ENODEV);
		}
		dev_hold(dev);
		rcu_read_unlock();
		if (outer_protocol == IPPROTO_TCP &&
		    trustix_tixt_rx_single_coalesce_try(skb, dev, args,
							outer_len) > 0) {
			dev_put(dev);
			return TRUSTIX_KUDP_RX_PARSE_DECAP_L2_STOLEN;
		}
	}

	ret = trustix_skb_kudp_rx_decap_l2(skb, outer_len, args->l2_head,
					   args->l2_tail0, args->l2_tail1,
					   args->decap_flags);
	if (ret) {
		if (local_dev)
			dev_put(dev);
		return trustix_kudp_rx_record_parse_ret(ret);
	}

	if (local_dev) {
		skb->dev = dev;
		skb->skb_iif = dev->ifindex;
		skb->pkt_type = PACKET_HOST;
		dev_put(dev);
		return TRUSTIX_KUDP_RX_PARSE_DECAP_L2_LOCAL_DELIVERED;
	}
	memcpy(skb->cb + TRUSTIX_SKB_CB_RX_NEXT_HOP, &next_hop,
	       sizeof(next_hop));
	memcpy(skb->cb + TRUSTIX_SKB_CB_RX_OUTER_LEN, &outer_len,
	       sizeof(outer_len));
	return 0;
}

__bpf_kfunc int trustix_kernel_skb_kudp_rx_decap_l2(struct __sk_buff *ctx,
						    u32 outer_len,
						    u64 l2_head,
						    u32 l2_tail0,
						    u32 l2_tail1)
{
	struct sk_buff *skb = trustix_bpf_ctx_skb(ctx);

	return trustix_skb_kudp_rx_decap_l2(skb, outer_len, l2_head,
					    l2_tail0, l2_tail1,
					    l2_tail1 >> 16);
}

__bpf_kfunc int
trustix_kernel_skb_kudp_rx_decap_l2_dev(
				struct __sk_buff *ctx,
				const struct trustix_kudp_rx_decap_l2_dev_args *args)
{
	struct sk_buff *skb = trustix_bpf_ctx_skb(ctx);
	struct net_device *dev;
	struct net *net;
	int ret;

	if (!skb || !args || !args->ifindex)
		return -EINVAL;
	if (args->flags & ~TRUSTIX_KUDP_RX_DECAP_L2_TRUST_INNER_L4_CSUM)
		return -EINVAL;
	if (!skb->dev)
		return -ENODEV;

	net = dev_net(skb->dev);
	rcu_read_lock();
	dev = dev_get_by_index_rcu(net, args->ifindex);
	if (!dev) {
		rcu_read_unlock();
		return -ENODEV;
	}
	dev_hold(dev);
	rcu_read_unlock();
	ret = trustix_skb_kudp_rx_decap_l2(skb, args->outer_len,
					   args->l2_head, args->l2_tail0,
					   args->l2_tail1, args->flags);
	if (!ret) {
		skb->dev = dev;
		skb->skb_iif = dev->ifindex;
		skb->pkt_type = PACKET_HOST;
	}
	dev_put(dev);
	return ret;
}

__bpf_kfunc int
trustix_kernel_skb_kudp_rx_parse_decap_l2(
				struct __sk_buff *ctx,
				const struct trustix_kudp_rx_parse_args *args)
{
	struct sk_buff *skb = trustix_bpf_ctx_skb(ctx);

	return trustix_skb_kudp_rx_parse_decap_l2(skb, args);
}

__bpf_kfunc int trustix_kernel_skb_tixt_fix_outer_tcp_csum(struct sk_buff *skb,
							   u32 flags)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	u32 ip_len;
	u32 tcp_offset;
	u32 tcp_len;
	u32 tixt_offset;
	u32 min_len;
	__wsum sum;
	bool partial_csum;

	if (!skb)
		return -EINVAL;
	if (flags & ~(TRUSTIX_SKB_CLEAR_TX_OFFLOAD_GSO |
		      TRUSTIX_TIXT_TX_FINALIZE_TCP_PARTIAL_CSUM))
		return -EINVAL;
	min_len = ETH_HLEN + sizeof(*iph) + sizeof(*tcph) +
		  TRUSTIX_TIXT_HEADER_LEN;
	if (skb->len < min_len)
		return -EINVAL;
	if (unlikely(!pskb_may_pull(skb, min_len)))
		return -EINVAL;
	if (skb_ensure_writable(skb, ETH_HLEN + sizeof(*iph) +
				     sizeof(*tcph)))
		return -EFAULT;
	if (ETH_HLEN + sizeof(*iph) + sizeof(*tcph) > skb_headlen(skb))
		return -EINVAL;

	iph = (struct iphdr *)(skb->data + ETH_HLEN);
	if (iph->version != 4 || iph->ihl != 5 ||
	    iph->protocol != IPPROTO_TCP)
		return -EPROTONOSUPPORT;
	if (iph->frag_off & htons(0x3fff))
		return -EINVAL;
	ip_len = ntohs(iph->tot_len);
	if (ip_len < sizeof(*iph) + sizeof(*tcph) + TRUSTIX_TIXT_HEADER_LEN ||
	    skb->len != ETH_HLEN + ip_len)
		return -EINVAL;

	tcp_offset = ETH_HLEN + sizeof(*iph);
	tcp_len = ip_len - sizeof(*iph);
	if (unlikely(!pskb_may_pull(skb, tcp_offset + sizeof(*tcph) +
					 TRUSTIX_TIXT_HEADER_LEN)))
		return -EINVAL;
	if (skb_ensure_writable(skb, tcp_offset + sizeof(*tcph)))
		return -EFAULT;
	if (tcp_offset + sizeof(*tcph) + TRUSTIX_TIXT_HEADER_LEN >
	    skb_headlen(skb))
		return -EINVAL;

	iph = (struct iphdr *)(skb->data + ETH_HLEN);
	tcph = (struct tcphdr *)(skb->data + tcp_offset);
	if (tcph->doff != 5 ||
	    tcp_len < sizeof(*tcph) + TRUSTIX_TIXT_HEADER_LEN)
		return -EINVAL;
	tixt_offset = tcp_offset + sizeof(*tcph);
	if (get_unaligned_be32(skb->data + tixt_offset) != TRUSTIX_TIXT_MAGIC)
		return -EINVAL;
	if (*(skb->data + tixt_offset + 4) != 1 ||
	    get_unaligned_be16(skb->data + tixt_offset + 6) !=
		    TRUSTIX_TIXT_HEADER_LEN)
		return -EINVAL;
	if ((*(skb->data + tixt_offset + 5) & TRUSTIX_TIXT_FLAG_INNER_IPV4) !=
	    TRUSTIX_TIXT_FLAG_INNER_IPV4)
		return -EINVAL;
	if (get_unaligned_be32(skb->data + tixt_offset + 32) !=
	    tcp_len - sizeof(*tcph) - TRUSTIX_TIXT_HEADER_LEN)
		return -EINVAL;

	partial_csum = flags & TRUSTIX_TIXT_TX_FINALIZE_TCP_PARTIAL_CSUM;
	tcph->check = 0;
	skb_reset_mac_header(skb);
	skb_set_network_header(skb, ETH_HLEN);
	skb_set_transport_header(skb, tcp_offset);
	skb->mac_len = ETH_HLEN;
	skb->protocol = htons(ETH_P_IP);
	if (partial_csum) {
		tcph->check = ~csum_tcpudp_magic(iph->saddr, iph->daddr,
						 tcp_len, IPPROTO_TCP, 0);
		skb->ip_summed = CHECKSUM_PARTIAL;
		skb->csum_start = skb_transport_header(skb) - skb->head;
		skb->csum_offset = offsetof(struct tcphdr, check);
	} else {
		sum = skb_checksum(skb, tcp_offset, tcp_len, 0);
		tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
						tcp_len, IPPROTO_TCP, sum);
		trustix_skb_clear_csum_metadata(skb);
	}
	skb->encapsulation = 0;
	if (flags & TRUSTIX_SKB_CLEAR_TX_OFFLOAD_GSO)
		skb_gso_reset(skb);
	return 0;
}

__bpf_kfunc int
trustix_kernel_skb_tixt_tx_finalize_tcp_header(
				struct sk_buff *skb,
				const struct trustix_tixt_tx_tcp_header_args *args,
				u32 clear_flags)
{
	u32 header_len = ETH_HLEN + sizeof(struct iphdr) +
			 sizeof(struct tcphdr) + TRUSTIX_TIXT_HEADER_LEN;
	u32 ip_tot_len;
	u32 total_len;
	bool gso;
	bool partial_csum;
	u8 *dst;
	int ret;

	if (!skb || !args)
		return -EINVAL;
	if (args->flags & ~TRUSTIX_TIXT_FLAG_ENCRYPTED)
		return -EINVAL;
	if (clear_flags & ~(TRUSTIX_SKB_CLEAR_TX_OFFLOAD_CSUM |
			    TRUSTIX_SKB_CLEAR_TX_OFFLOAD_GSO |
			    TRUSTIX_SKB_CLEAR_TX_OFFLOAD_ENCAP |
			    TRUSTIX_TIXT_TX_FINALIZE_TCP_PARTIAL_CSUM |
			    TRUSTIX_TIXT_TX_FINALIZE_TCP_TRUST_INNER_CSUM))
		return -EINVAL;
	if ((clear_flags & TRUSTIX_TIXT_TX_FINALIZE_TCP_PARTIAL_CSUM) &&
	    (clear_flags & TRUSTIX_TIXT_TX_FINALIZE_TCP_TRUST_INNER_CSUM))
		return -EINVAL;
	if (args->payload_len > 1500)
		return -EINVAL;
	ip_tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) +
		     TRUSTIX_TIXT_HEADER_LEN + args->payload_len;
	if (args->ip_tot_len != ip_tot_len)
		return -EINVAL;
	if (check_add_overflow((u32)ETH_HLEN, ip_tot_len, &total_len))
		return -EINVAL;
	gso = skb_shinfo(skb)->gso_size;
	if (!gso && skb->len != total_len)
		return -EINVAL;
	if (gso && skb->len < total_len)
		return -EINVAL;
	ret = trustix_skb_ensure_writable_head(skb, header_len);
	if (ret)
		return ret;

	dst = skb->data;
	partial_csum = clear_flags & TRUSTIX_TIXT_TX_FINALIZE_TCP_PARTIAL_CSUM;
	trustix_tixt_tx_write_tcp_header(dst, args, partial_csum, true);

	skb_reset_mac_header(skb);
	skb_set_network_header(skb, ETH_HLEN);
	skb_set_transport_header(skb, ETH_HLEN + sizeof(struct iphdr));
	skb->mac_len = ETH_HLEN;
	skb->protocol = htons(ETH_P_IP);
	if (partial_csum) {
		skb->ip_summed = CHECKSUM_PARTIAL;
		skb->csum_start = skb_transport_header(skb) - skb->head;
		skb->csum_offset = offsetof(struct tcphdr, check);
	} else {
		trustix_skb_clear_csum_metadata(skb);
	}
	skb->encapsulation = 0;
	if (clear_flags & TRUSTIX_SKB_CLEAR_TX_OFFLOAD_GSO)
		skb_gso_reset(skb);
	return 0;
}

__bpf_kfunc int
trustix_kernel_skb_tixt_tx_set_tcp_partial_csum(struct sk_buff *skb,
						u32 clear_flags)
{
	u32 header_len = ETH_HLEN + sizeof(struct iphdr) + sizeof(struct tcphdr);
	struct iphdr *iph;
	struct tcphdr *tcph;

	if (!skb)
		return -EINVAL;
	if (clear_flags & ~(TRUSTIX_SKB_CLEAR_TX_OFFLOAD_CSUM |
			    TRUSTIX_SKB_CLEAR_TX_OFFLOAD_GSO |
			    TRUSTIX_SKB_CLEAR_TX_OFFLOAD_ENCAP))
		return -EINVAL;
	if (skb->len < header_len)
		return -EINVAL;
	if (unlikely(header_len > skb_headlen(skb) &&
		     !pskb_may_pull(skb, header_len)))
		return -EINVAL;
	if (header_len > skb_headlen(skb))
		return -EINVAL;

	iph = (struct iphdr *)(skb->data + ETH_HLEN);
	tcph = (struct tcphdr *)(skb->data + ETH_HLEN + sizeof(*iph));
	if (iph->version != 4 || iph->ihl != 5 ||
	    iph->protocol != IPPROTO_TCP || tcph->doff != 5)
		return -EPROTONOSUPPORT;

	skb_reset_mac_header(skb);
	skb_set_network_header(skb, ETH_HLEN);
	skb_set_transport_header(skb, ETH_HLEN + sizeof(*iph));
	skb->mac_len = ETH_HLEN;
	skb->protocol = htons(ETH_P_IP);
	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum_start = skb_transport_header(skb) - skb->head;
	skb->csum_offset = offsetof(struct tcphdr, check);
	skb->encapsulation = 0;
	if (clear_flags & TRUSTIX_SKB_CLEAR_TX_OFFLOAD_GSO)
		skb_gso_reset(skb);
	return 0;
}

__bpf_kfunc int
trustix_kernel_skb_tixt_tx_push_tcp_header(
				struct sk_buff *skb,
				const struct trustix_tixt_tx_tcp_header_args *args,
				u32 clear_flags)
{
	u32 header_len = ETH_HLEN + sizeof(struct iphdr) +
			 sizeof(struct tcphdr) + TRUSTIX_TIXT_HEADER_LEN;
	u32 push_len = header_len - ETH_HLEN;
	u32 ip_tot_len;
	u32 old_len;
	u32 tcp_len;
	u32 total_len;
	bool partial_csum;
	struct tcphdr *tcph;
	u8 *dst;
	int ret;

	if (!skb || !args)
		return -EINVAL;
	if (args->flags & ~TRUSTIX_TIXT_FLAG_ENCRYPTED)
		return -EINVAL;
	if (clear_flags & ~(TRUSTIX_SKB_CLEAR_TX_OFFLOAD_CSUM |
			    TRUSTIX_SKB_CLEAR_TX_OFFLOAD_GSO |
			    TRUSTIX_SKB_CLEAR_TX_OFFLOAD_ENCAP |
			    TRUSTIX_TIXT_TX_FINALIZE_TCP_PARTIAL_CSUM |
			    TRUSTIX_TIXT_TX_FINALIZE_TCP_TRUST_INNER_CSUM))
		return -EINVAL;
	if ((clear_flags & TRUSTIX_TIXT_TX_FINALIZE_TCP_PARTIAL_CSUM) &&
	    (clear_flags & TRUSTIX_TIXT_TX_FINALIZE_TCP_TRUST_INNER_CSUM))
		return -EINVAL;
	if (args->payload_len > 1500)
		return -EINVAL;
	ip_tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) +
		     TRUSTIX_TIXT_HEADER_LEN + args->payload_len;
	if (args->ip_tot_len != ip_tot_len)
		return -EINVAL;
	if (check_add_overflow((u32)ETH_HLEN, args->payload_len, &old_len))
		return -EINVAL;
	if (check_add_overflow((u32)ETH_HLEN, ip_tot_len, &total_len))
		return -EINVAL;
	if (skb->len != old_len)
		return -EINVAL;
	if (unlikely(!pskb_may_pull(skb, ETH_HLEN)))
		return -EINVAL;
	if (skb_ensure_writable(skb, ETH_HLEN))
		return -EFAULT;
	if (ETH_HLEN > skb_headlen(skb))
		return -EINVAL;
	if (trustix_skb_ensure_push_head(skb, push_len))
		return -ENOMEM;

	skb_reset_inner_headers(skb);
	skb_push(skb, push_len);
	if (skb->len != total_len || header_len > skb_headlen(skb))
		return -EINVAL;

	dst = skb->data;
	partial_csum = clear_flags & TRUSTIX_TIXT_TX_FINALIZE_TCP_PARTIAL_CSUM;
	trustix_tixt_tx_write_tcp_header(dst, args, partial_csum, false);

	skb_reset_mac_header(skb);
	skb_set_network_header(skb, ETH_HLEN);
	skb_set_transport_header(skb, ETH_HLEN + sizeof(struct iphdr));
	skb->mac_len = ETH_HLEN;
	skb->protocol = htons(ETH_P_IP);
	if (partial_csum) {
		skb->ip_summed = CHECKSUM_PARTIAL;
		skb->csum_start = skb_transport_header(skb) - skb->head;
		skb->csum_offset = offsetof(struct tcphdr, check);
	} else {
		tcp_len = sizeof(struct tcphdr) + TRUSTIX_TIXT_HEADER_LEN +
			  args->payload_len;
		if (!(clear_flags & TRUSTIX_TIXT_TX_FINALIZE_TCP_TRUST_INNER_CSUM) ||
		    !trustix_tixt_tx_trusted_inner_tcp_csum(skb, args,
							   header_len,
							   tcp_len)) {
			tcph = (struct tcphdr *)(skb->data + ETH_HLEN +
						 sizeof(struct iphdr));
			tcph->check =
				trustix_ipv4_l4_partial_check_from_ip_base(
					args->ip_check_base, tcp_len);
			skb->ip_summed = CHECKSUM_PARTIAL;
			skb->csum_start = skb_transport_header(skb) - skb->head;
			skb->csum_offset = offsetof(struct tcphdr, check);
			ret = skb_checksum_help(skb);
			if (ret)
				return ret;
		}
		trustix_skb_clear_csum_metadata(skb);
	}
	skb->encapsulation = 0;
	if (clear_flags & TRUSTIX_SKB_CLEAR_TX_OFFLOAD_GSO)
		skb_gso_reset(skb);
	return 0;
}

__bpf_kfunc int
trustix_kernel_skb_tixt_tx_push_flow_tcp_header(
				struct sk_buff *skb,
				struct trustix_kudp_tx_flow_value *flow,
				const struct trustix_tixt_tx_flow_header_args *args)
{
	struct trustix_tixt_tx_tcp_header_args header = {};
	struct tcphdr *tcph;
	u32 flow_flags;
	u32 clear_flags;
	u32 header_len = ETH_HLEN + sizeof(struct iphdr) +
			 sizeof(struct tcphdr) + TRUSTIX_TIXT_HEADER_LEN;
	u32 push_len = header_len - ETH_HLEN;
	u32 old_len;
	u32 tcp_len;
	u32 total_len;
	bool partial_csum;
	u64 sequence;
	u16 tail1;
	u8 *dst;
	int ret;

	if (!skb || !flow || !args)
		return -EINVAL;
	if (args->payload_len > 1500)
		return -EINVAL;
	clear_flags = args->clear_flags;
	if (clear_flags & ~(TRUSTIX_SKB_CLEAR_TX_OFFLOAD_CSUM |
			    TRUSTIX_SKB_CLEAR_TX_OFFLOAD_GSO |
			    TRUSTIX_SKB_CLEAR_TX_OFFLOAD_ENCAP |
			    TRUSTIX_TIXT_TX_FINALIZE_TCP_PARTIAL_CSUM |
			    TRUSTIX_TIXT_TX_FINALIZE_TCP_TRUST_INNER_CSUM))
		return -EINVAL;
	if ((clear_flags & TRUSTIX_TIXT_TX_FINALIZE_TCP_PARTIAL_CSUM) &&
	    (clear_flags & TRUSTIX_TIXT_TX_FINALIZE_TCP_TRUST_INNER_CSUM))
		return -EINVAL;

	flow_flags = READ_ONCE(flow->flags);
	if (!(flow_flags & TRUSTIX_KUDP_TX_FLOW_FLAG_EXPERIMENTAL_TCP) ||
	    (flow_flags & TRUSTIX_KUDP_TX_FLOW_FLAG_SECURE) ||
	    (flow_flags & TRUSTIX_KUDP_TX_FLOW_FLAG_SKIP_OUTER_TCP_CSUM))
		return -EPROTONOSUPPORT;
	if (check_add_overflow((u32)ETH_HLEN, args->payload_len, &old_len))
		return -EINVAL;
	if (skb->len != old_len)
		return -EINVAL;

	header.saddr = flow->saddr;
	header.daddr = flow->daddr;
	header.source = flow->source;
	header.dest = flow->dest;
	header.ip_tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) +
			    TRUSTIX_TIXT_HEADER_LEN + args->payload_len;
	if (check_add_overflow((u32)ETH_HLEN, (u32)header.ip_tot_len,
			       &total_len))
		return -EINVAL;
	header.ip_check_base = READ_ONCE(flow->ipv4_check_tcp);
	header.flow_id = args->flow_id;
	header.payload_len = args->payload_len;
	memcpy(header.l2, &flow->destination_mac0, sizeof(flow->destination_mac0));
	memcpy(header.l2 + 4, &flow->destination_mac1, sizeof(flow->destination_mac1));
	memcpy(header.l2 + 6, &flow->source_mac0, sizeof(flow->source_mac0));
	memcpy(header.l2 + 10, &flow->source_mac1, sizeof(flow->source_mac1));
	tail1 = htons(ETH_P_IP);
	memcpy(header.l2 + 12, &tail1, sizeof(tail1));

	if (trustix_tixt_tx_plain_skip_sequence_enabled())
		sequence = 0;
	else
		sequence = atomic64_fetch_add(args->payload_len +
					      TRUSTIX_TIXT_HEADER_LEN,
					      (atomic64_t *)&flow->sequence) + 1;
	header.sequence = sequence;

	if (trustix_skb_ensure_push_head(skb, push_len))
		return -ENOMEM;
	skb_reset_inner_headers(skb);
	skb_push(skb, push_len);
	if (skb->len != total_len || header_len > skb_headlen(skb))
		return -EINVAL;

	dst = skb->data;
	partial_csum = clear_flags & TRUSTIX_TIXT_TX_FINALIZE_TCP_PARTIAL_CSUM;
	trustix_tixt_tx_write_tcp_header(dst, &header, partial_csum, false);

	skb_reset_mac_header(skb);
	skb_set_network_header(skb, ETH_HLEN);
	skb_set_transport_header(skb, ETH_HLEN + sizeof(struct iphdr));
	skb->mac_len = ETH_HLEN;
	skb->protocol = htons(ETH_P_IP);
	if (partial_csum) {
		skb->ip_summed = CHECKSUM_PARTIAL;
		skb->csum_start = skb_transport_header(skb) - skb->head;
		skb->csum_offset = offsetof(struct tcphdr, check);
	} else {
		tcp_len = sizeof(struct tcphdr) + TRUSTIX_TIXT_HEADER_LEN +
			  args->payload_len;
		if (!(clear_flags & TRUSTIX_TIXT_TX_FINALIZE_TCP_TRUST_INNER_CSUM) ||
		    !trustix_tixt_tx_trusted_inner_tcp_csum(skb, &header,
							   header_len,
							   tcp_len)) {
			tcph = (struct tcphdr *)(skb->data + ETH_HLEN +
						 sizeof(struct iphdr));
			tcph->check =
				trustix_ipv4_l4_partial_check_from_ip_base(
					header.ip_check_base, tcp_len);
			skb->ip_summed = CHECKSUM_PARTIAL;
			skb->csum_start = skb_transport_header(skb) - skb->head;
			skb->csum_offset = offsetof(struct tcphdr, check);
			ret = skb_checksum_help(skb);
			if (ret)
				return ret;
		}
		trustix_skb_clear_csum_metadata(skb);
	}
	skb->encapsulation = 0;
	if (clear_flags & TRUSTIX_SKB_CLEAR_TX_OFFLOAD_GSO)
		skb_gso_reset(skb);
	return 0;
}

__bpf_kfunc int
trustix_kernel_skb_tixt_tx_finalize_flow_tcp_header(
				struct sk_buff *skb,
				struct trustix_kudp_tx_flow_value *flow,
				const struct trustix_tixt_tx_flow_header_args *args)
{
	u32 header_len = ETH_HLEN + sizeof(struct iphdr) +
			 sizeof(struct tcphdr) + TRUSTIX_TIXT_HEADER_LEN;
	u32 flow_flags;
	u32 clear_flags;
	u32 ip_tot_len;
	u32 total_len;
	bool partial_csum;
	bool trust_validated_len;
	bool gso;
	u64 sequence;
	u8 *dst;
	int ret;

	if (!skb || !flow || !args)
		return -EINVAL;
	if (args->payload_len > 1500)
		return -EINVAL;
	clear_flags = args->clear_flags;
	if (clear_flags & ~(TRUSTIX_SKB_CLEAR_TX_OFFLOAD_CSUM |
			    TRUSTIX_SKB_CLEAR_TX_OFFLOAD_GSO |
			    TRUSTIX_SKB_CLEAR_TX_OFFLOAD_ENCAP |
			    TRUSTIX_TIXT_TX_FINALIZE_TCP_PARTIAL_CSUM |
			    TRUSTIX_TIXT_TX_FINALIZE_TCP_TRUST_INNER_CSUM |
			    TRUSTIX_TIXT_TX_FINALIZE_TCP_TRUST_VALIDATED_LEN))
		return -EINVAL;
	if ((clear_flags & TRUSTIX_TIXT_TX_FINALIZE_TCP_PARTIAL_CSUM) &&
	    (clear_flags & TRUSTIX_TIXT_TX_FINALIZE_TCP_TRUST_INNER_CSUM))
		return -EINVAL;

	flow_flags = READ_ONCE(flow->flags);
	if (!(flow_flags & TRUSTIX_KUDP_TX_FLOW_FLAG_EXPERIMENTAL_TCP) ||
	    (flow_flags & TRUSTIX_KUDP_TX_FLOW_FLAG_SECURE) ||
	    (flow_flags & TRUSTIX_KUDP_TX_FLOW_FLAG_SKIP_OUTER_TCP_CSUM))
		return -EPROTONOSUPPORT;

	ip_tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) +
		     TRUSTIX_TIXT_HEADER_LEN + args->payload_len;
	if (check_add_overflow((u32)ETH_HLEN, ip_tot_len, &total_len))
		return -EINVAL;
	trust_validated_len =
		clear_flags & TRUSTIX_TIXT_TX_FINALIZE_TCP_TRUST_VALIDATED_LEN;
	if (trust_validated_len) {
		if (skb->len < total_len)
			return -EINVAL;
	} else {
		gso = skb_shinfo(skb)->gso_size;
		if (!gso && skb->len != total_len)
			return -EINVAL;
		if (gso && skb->len < total_len)
			return -EINVAL;
	}
	ret = trustix_skb_ensure_writable_head(skb, header_len);
	if (ret)
		return ret;

	if (trustix_tixt_tx_plain_skip_sequence_enabled())
		sequence = 0;
	else
		sequence = atomic64_fetch_add(args->payload_len +
					      TRUSTIX_TIXT_HEADER_LEN,
					      (atomic64_t *)&flow->sequence) + 1;

	dst = skb->data;
	partial_csum = clear_flags & TRUSTIX_TIXT_TX_FINALIZE_TCP_PARTIAL_CSUM;
	trustix_tixt_tx_write_flow_tcp_header(dst, flow, args->flow_id,
					      sequence, args->payload_len,
					      ip_tot_len, partial_csum);

	skb_reset_mac_header(skb);
	skb_set_network_header(skb, ETH_HLEN);
	skb_set_transport_header(skb, ETH_HLEN + sizeof(struct iphdr));
	skb->mac_len = ETH_HLEN;
	skb->protocol = htons(ETH_P_IP);
	if (partial_csum) {
		skb->ip_summed = CHECKSUM_PARTIAL;
		skb->csum_start = skb_transport_header(skb) - skb->head;
		skb->csum_offset = offsetof(struct tcphdr, check);
	} else {
		trustix_skb_clear_csum_metadata(skb);
	}
	skb->encapsulation = 0;
	if (clear_flags & TRUSTIX_SKB_CLEAR_TX_OFFLOAD_GSO)
		skb_gso_reset(skb);
	return 0;
}

static __always_inline u32
trustix_tixt_tx_inner_hash(const u8 *data, const u8 *data_end)
{
	u32 hash = 0;
	u32 ports;
	u32 ihl;
	const u8 *l4;

	if (!data || !data_end ||
	    data + ETH_HLEN + sizeof(struct iphdr) > data_end)
		return 0;
	ihl = (data[ETH_HLEN] & 0x0f) << 2;
	if (ihl < sizeof(struct iphdr))
		return 0;
	hash = get_unaligned((const u32 *)(data + ETH_HLEN +
					   offsetof(struct iphdr, saddr)));
	hash ^= get_unaligned((const u32 *)(data + ETH_HLEN +
					    offsetof(struct iphdr, daddr)));
	hash ^= ((u32)data[ETH_HLEN + offsetof(struct iphdr, protocol)]) << 16;
	l4 = data + ETH_HLEN + ihl;
	if (l4 + sizeof(ports) <= data_end) {
		ports = get_unaligned((const u32 *)l4);
		hash ^= ports;
	}
	hash ^= hash >> 16;
	hash ^= hash >> 8;
	return hash;
}

static __always_inline const struct trustix_kudp_tx_flow_value *
trustix_tixt_tx_select_inline_flow(const u8 *data, const u8 *data_end,
				   const struct trustix_kudp_tx_route_value *route,
				   u64 *flow_id)
{
	u32 flow_mask;
	u32 index;

	if (!route || !flow_id)
		return NULL;
	if (!(READ_ONCE(route->flags) & TRUSTIX_KUDP_TX_ROUTE_FLAG_INLINE_FLOW))
		return NULL;
	flow_mask = READ_ONCE(route->flow_mask);
	if (!flow_mask) {
		*flow_id = READ_ONCE(route->flow_id);
		if (!*flow_id)
			*flow_id = READ_ONCE(route->flow_id_1);
		return &route->inline_flow_1;
	}
	index = trustix_tixt_tx_inner_hash(data, data_end) & flow_mask;
	switch (index) {
	case 0:
		*flow_id = READ_ONCE(route->flow_id_1);
		return &route->inline_flow_1;
	case 1:
		*flow_id = READ_ONCE(route->flow_id_2);
		return &route->inline_flow_2;
	case 2:
		*flow_id = READ_ONCE(route->flow_id_3);
		return &route->inline_flow_3;
	case 3:
		*flow_id = READ_ONCE(route->flow_id_4);
		return &route->inline_flow_4;
	case 4:
		*flow_id = READ_ONCE(route->flow_id_5);
		return &route->inline_flow_5;
	case 5:
		*flow_id = READ_ONCE(route->flow_id_6);
		return &route->inline_flow_6;
	case 6:
		*flow_id = READ_ONCE(route->flow_id_7);
		return &route->inline_flow_7;
	default:
		*flow_id = READ_ONCE(route->flow_id_8);
		return &route->inline_flow_8;
	}
}

static __always_inline const struct trustix_kudp_tx_flow_value *
trustix_tixt_tx_select_inline_flow_id(
				   const struct trustix_kudp_tx_route_value *route,
				   u64 selected_flow_id)
{
	if (!route || !selected_flow_id)
		return NULL;
	if (!(READ_ONCE(route->flags) & TRUSTIX_KUDP_TX_ROUTE_FLAG_INLINE_FLOW))
		return NULL;
	if (READ_ONCE(route->flow_id) == selected_flow_id)
		return &route->inline_flow_1;
	if (READ_ONCE(route->flow_id_1) == selected_flow_id)
		return &route->inline_flow_1;
	if (READ_ONCE(route->flow_id_2) == selected_flow_id)
		return &route->inline_flow_2;
	if (READ_ONCE(route->flow_id_3) == selected_flow_id)
		return &route->inline_flow_3;
	if (READ_ONCE(route->flow_id_4) == selected_flow_id)
		return &route->inline_flow_4;
	if (READ_ONCE(route->flow_id_5) == selected_flow_id)
		return &route->inline_flow_5;
	if (READ_ONCE(route->flow_id_6) == selected_flow_id)
		return &route->inline_flow_6;
	if (READ_ONCE(route->flow_id_7) == selected_flow_id)
		return &route->inline_flow_7;
	if (READ_ONCE(route->flow_id_8) == selected_flow_id)
		return &route->inline_flow_8;
	return NULL;
}

static __always_inline bool
trustix_tixt_tx_route_has_flow_id(
				   const struct trustix_kudp_tx_route_value *route,
				   u64 selected_flow_id)
{
	if (!route || !selected_flow_id)
		return false;
	if (READ_ONCE(route->flow_id) == selected_flow_id)
		return true;
	if (READ_ONCE(route->flow_id_1) == selected_flow_id)
		return true;
	if (READ_ONCE(route->flow_id_2) == selected_flow_id)
		return true;
	if (READ_ONCE(route->flow_id_3) == selected_flow_id)
		return true;
	if (READ_ONCE(route->flow_id_4) == selected_flow_id)
		return true;
	if (READ_ONCE(route->flow_id_5) == selected_flow_id)
		return true;
	if (READ_ONCE(route->flow_id_6) == selected_flow_id)
		return true;
	if (READ_ONCE(route->flow_id_7) == selected_flow_id)
		return true;
	if (READ_ONCE(route->flow_id_8) == selected_flow_id)
		return true;
	return false;
}

static int
trustix_tixt_tx_validate_route_plain_flow_pulled(
				const u8 *data, const u8 *data_end,
				struct trustix_kudp_tx_route_value *route,
				const struct trustix_kudp_tx_flow_value **flow,
				u64 *flow_id)
{
	const struct trustix_kudp_tx_flow_value *selected;
	u32 flow_flags;

	if (!data || !data_end || !route || !flow || !flow_id)
		return -EINVAL;
	if (READ_ONCE(route->flags) & TRUSTIX_KUDP_TX_ROUTE_FLAG_BYPASS)
		return -EPROTONOSUPPORT;
	selected = trustix_tixt_tx_select_inline_flow(data, data_end, route,
						     flow_id);
	if (!selected || !*flow_id)
		return -EPROTONOSUPPORT;
	flow_flags = READ_ONCE(selected->flags);
	if (!(flow_flags & TRUSTIX_KUDP_TX_FLOW_FLAG_EXPERIMENTAL_TCP) ||
	    (flow_flags & TRUSTIX_KUDP_TX_FLOW_FLAG_SECURE) ||
	    (flow_flags & TRUSTIX_KUDP_TX_FLOW_FLAG_SKIP_OUTER_TCP_CSUM))
		return -EPROTONOSUPPORT;
	*flow = selected;
	return 0;
}

static int
trustix_tixt_tx_validate_route_plain_flow(struct sk_buff *skb,
				struct trustix_kudp_tx_route_value *route,
				const struct trustix_kudp_tx_flow_value **flow,
				u64 *flow_id)
{
	if (!skb)
		return -EINVAL;
	if (unlikely(!pskb_may_pull(skb, ETH_HLEN + sizeof(struct iphdr))))
		return -EPROTONOSUPPORT;
	if (ETH_HLEN + sizeof(struct iphdr) > skb_headlen(skb))
		return -EPROTONOSUPPORT;
	return trustix_tixt_tx_validate_route_plain_flow_pulled(
		skb->data, skb->data + skb_headlen(skb), route, flow,
		flow_id);
}

static int
trustix_tixt_tx_validate_route_secure_flow_pulled(
				const u8 *data, const u8 *data_end,
				struct trustix_kudp_tx_route_value *route,
				u64 selected_flow_id,
				const struct trustix_kudp_tx_flow_value *provided_flow,
				const struct trustix_kudp_tx_flow_value **flow,
				u64 *flow_id)
{
	const struct trustix_kudp_tx_flow_value *selected;
	u32 flow_flags;

	if (!data || !data_end || !route || !flow || !flow_id)
		return -EINVAL;
	if (READ_ONCE(route->flags) & TRUSTIX_KUDP_TX_ROUTE_FLAG_BYPASS)
		return -EPROTONOSUPPORT;
	if (provided_flow && selected_flow_id) {
		if (!trustix_tixt_tx_route_has_flow_id(route, selected_flow_id))
			return -EPROTONOSUPPORT;
		selected = provided_flow;
		*flow_id = selected_flow_id;
	} else if (selected_flow_id) {
		selected = trustix_tixt_tx_select_inline_flow_id(route,
								selected_flow_id);
		*flow_id = selected ? selected_flow_id : 0;
	} else {
		selected = trustix_tixt_tx_select_inline_flow(data, data_end,
							     route, flow_id);
	}
	if (!selected || !*flow_id)
		return -EPROTONOSUPPORT;
	flow_flags = READ_ONCE(selected->flags);
	if (!(flow_flags & TRUSTIX_KUDP_TX_FLOW_FLAG_SECURE) ||
	    (flow_flags & TRUSTIX_KUDP_TX_FLOW_FLAG_SKIP_OUTER_TCP_CSUM))
		return -EPROTONOSUPPORT;
	*flow = selected;
	return 0;
}

static int
trustix_tixt_tx_validate_route_secure_flow(struct sk_buff *skb,
				struct trustix_kudp_tx_route_value *route,
				u64 selected_flow_id,
				const struct trustix_kudp_tx_flow_value *provided_flow,
				const struct trustix_kudp_tx_flow_value **flow,
				u64 *flow_id)
{
	if (!skb)
		return -EINVAL;
	if (unlikely(!pskb_may_pull(skb, ETH_HLEN + sizeof(struct iphdr))))
		return -EPROTONOSUPPORT;
	if (ETH_HLEN + sizeof(struct iphdr) > skb_headlen(skb))
		return -EPROTONOSUPPORT;
	return trustix_tixt_tx_validate_route_secure_flow_pulled(
		skb->data, skb->data + skb_headlen(skb), route,
		selected_flow_id, provided_flow, flow, flow_id);
}

__bpf_kfunc int
trustix_kernel_skb_tixt_tx_push_route_tcp_header(
				struct __sk_buff *ctx,
				struct trustix_kudp_tx_route_value *route,
				const struct trustix_tixt_tx_route_header_args *args)
{
	const struct trustix_kudp_tx_flow_value *flow;
	struct trustix_tixt_tx_tcp_header_args csum_args;
	struct sk_buff *skb = trustix_bpf_ctx_skb(ctx);
	struct tcphdr *tcph;
	u32 clear_flags;
	u32 header_len = ETH_HLEN + sizeof(struct iphdr) +
			 sizeof(struct tcphdr) + TRUSTIX_TIXT_HEADER_LEN;
	u32 push_len = header_len - ETH_HLEN;
	u32 inner_len;
	u32 tcp_len;
	u32 wire_len;
	u32 skb_len;
	u64 sequence;
	u64 flow_id;
	u8 *data;
	u8 *data_end;
	bool partial_csum;
	__wsum sum;
	int ret;

	if (!skb || !route || !args)
		return -EINVAL;
	clear_flags = args->clear_flags;
	if (clear_flags & ~(TRUSTIX_SKB_CLEAR_TX_OFFLOAD_CSUM |
			    TRUSTIX_SKB_CLEAR_TX_OFFLOAD_GSO |
			    TRUSTIX_SKB_CLEAR_TX_OFFLOAD_ENCAP |
			    TRUSTIX_TIXT_TX_FINALIZE_TCP_PARTIAL_CSUM |
			    TRUSTIX_TIXT_TX_FINALIZE_TCP_TRUST_INNER_CSUM))
		return -EINVAL;
	if ((clear_flags & TRUSTIX_TIXT_TX_FINALIZE_TCP_PARTIAL_CSUM) &&
	    (clear_flags & TRUSTIX_TIXT_TX_FINALIZE_TCP_TRUST_INNER_CSUM))
		return -EINVAL;

	skb_len = READ_ONCE(skb->len);
	if (skb_len < ETH_HLEN + sizeof(struct iphdr))
		return -EINVAL;
	inner_len = skb_len - ETH_HLEN;
	if (inner_len > 1500)
		return -EPROTONOSUPPORT;
	if (unlikely(!pskb_may_pull(skb, ETH_HLEN + sizeof(struct iphdr))))
		return -EPROTONOSUPPORT;
	if (ETH_HLEN + sizeof(struct iphdr) > skb_headlen(skb))
		return -EPROTONOSUPPORT;
	data = skb->data;
	data_end = data + skb_headlen(skb);
	if (data[ETH_HLEN] != 0x45)
		return -EPROTONOSUPPORT;
	if (get_unaligned_be16(data + ETH_HLEN +
			       offsetof(struct iphdr, frag_off)) & 0x3fff)
		return -EPROTONOSUPPORT;
	if (ntohs(((struct iphdr *)(data + ETH_HLEN))->tot_len) != inner_len)
		return -EPROTONOSUPPORT;
	if (check_add_overflow(inner_len, (u32)sizeof(struct iphdr) +
			       (u32)sizeof(struct tcphdr) +
			       (u32)TRUSTIX_TIXT_HEADER_LEN, &wire_len))
		return -EINVAL;

	ret = trustix_tixt_tx_validate_route_plain_flow_pulled(
		data, data_end, route, &flow, &flow_id);
	if (ret)
		return ret;
	if (READ_ONCE(flow->mtu) && wire_len > READ_ONCE(flow->mtu))
		return -EMSGSIZE;

	ret = trustix_tixt_tx_fix_inner_l4_csum(skb, ETH_HLEN, inner_len);
	if (ret < 0)
		return ret;

	if (trustix_tixt_tx_plain_skip_sequence_enabled())
		sequence = 0;
	else
		sequence = atomic64_fetch_add(inner_len +
					      TRUSTIX_TIXT_HEADER_LEN,
					      (atomic64_t *)&((struct trustix_kudp_tx_flow_value *)flow)->sequence) + 1;

	if (trustix_skb_ensure_push_head(skb, push_len))
		return -ENOMEM;
	skb_reset_inner_headers(skb);
	skb_push(skb, push_len);
	if (skb->len != ETH_HLEN + wire_len || header_len > skb_headlen(skb))
		return -EINVAL;
	data = skb->data;
	partial_csum = clear_flags & TRUSTIX_TIXT_TX_FINALIZE_TCP_PARTIAL_CSUM;
	if (partial_csum) {
		trustix_tixt_tx_write_flow_tcp_header(data, flow, flow_id,
						      sequence, inner_len,
						      wire_len, true);
	} else {
		struct trustix_tixt_tx_tcp_header_args header = {};
		u16 tail1;

		header.saddr = flow->saddr;
		header.daddr = flow->daddr;
		header.source = flow->source;
		header.dest = flow->dest;
		header.ip_tot_len = wire_len;
		header.ip_check_base = READ_ONCE(flow->ipv4_check_tcp);
		header.flow_id = flow_id;
		header.payload_len = inner_len;
		header.sequence = sequence;
		memcpy(header.l2, &flow->destination_mac0,
		       sizeof(flow->destination_mac0));
		memcpy(header.l2 + 4, &flow->destination_mac1,
		       sizeof(flow->destination_mac1));
		memcpy(header.l2 + 6, &flow->source_mac0,
		       sizeof(flow->source_mac0));
		memcpy(header.l2 + 10, &flow->source_mac1,
		       sizeof(flow->source_mac1));
		tail1 = htons(ETH_P_IP);
		memcpy(header.l2 + 12, &tail1, sizeof(tail1));
		trustix_tixt_tx_write_tcp_header(data, &header, false, false);
	}

	skb_reset_mac_header(skb);
	skb_set_network_header(skb, ETH_HLEN);
	skb_set_transport_header(skb, ETH_HLEN + sizeof(struct iphdr));
	skb->mac_len = ETH_HLEN;
	skb->protocol = htons(ETH_P_IP);
	if (partial_csum) {
		skb->ip_summed = CHECKSUM_PARTIAL;
		skb->csum_start = skb_transport_header(skb) - skb->head;
		skb->csum_offset = offsetof(struct tcphdr, check);
	} else {
		tcp_len = sizeof(struct tcphdr) + TRUSTIX_TIXT_HEADER_LEN +
			  inner_len;
		tcph = (struct tcphdr *)(skb->data + ETH_HLEN +
					 sizeof(struct iphdr));
		if (clear_flags & TRUSTIX_TIXT_TX_FINALIZE_TCP_TRUST_INNER_CSUM) {
			memset(&csum_args, 0, sizeof(csum_args));
			csum_args.saddr = READ_ONCE(flow->saddr);
			csum_args.daddr = READ_ONCE(flow->daddr);
			csum_args.payload_len = inner_len;
			if (trustix_tixt_tx_trusted_inner_tcp_csum(
				    skb, &csum_args, header_len, tcp_len))
				goto route_csum_done;
		}
		tcph->check = 0;
		sum = skb_checksum(skb, ETH_HLEN + sizeof(struct iphdr),
				   tcp_len, 0);
		tcph->check = csum_tcpudp_magic(READ_ONCE(flow->saddr),
						READ_ONCE(flow->daddr),
						tcp_len, IPPROTO_TCP, sum);
route_csum_done:
		trustix_skb_clear_csum_metadata(skb);
	}
	skb->encapsulation = 0;
	if (clear_flags & TRUSTIX_SKB_CLEAR_TX_OFFLOAD_GSO)
		skb_gso_reset(skb);
	return (int)READ_ONCE(flow->ifindex);
}

static int
trustix_tixt_tx_prepare_route_tcp_snapshot(
				struct sk_buff *skb,
				const struct trustix_kudp_tx_flow_value *flow,
				u64 flow_id, u32 clear_flags)
{
	struct trustix_tixt_tx_tcp_header_args csum_args;
	struct tcphdr *tcph;
	u32 header_len = ETH_HLEN + sizeof(struct iphdr) +
			 sizeof(struct tcphdr) + TRUSTIX_TIXT_HEADER_LEN;
	u32 push_len = header_len - ETH_HLEN;
	u32 inner_len;
	u32 tcp_len;
	u32 wire_len;
	u32 skb_len;
	u64 sequence;
	u8 *data;
	bool partial_csum;
	__wsum sum;
	int ret;

	if (!skb || !flow || !flow_id)
		return -EINVAL;
	clear_flags &= ~TRUSTIX_TIXT_TX_FINALIZE_TCP_TRUST_PARTIAL_INNER_CSUM;
	if (clear_flags & ~(TRUSTIX_SKB_CLEAR_TX_OFFLOAD_CSUM |
			    TRUSTIX_SKB_CLEAR_TX_OFFLOAD_GSO |
			    TRUSTIX_SKB_CLEAR_TX_OFFLOAD_ENCAP |
			    TRUSTIX_TIXT_TX_FINALIZE_TCP_PARTIAL_CSUM |
			    TRUSTIX_TIXT_TX_FINALIZE_TCP_TRUST_INNER_CSUM))
		return -EINVAL;
	if ((clear_flags & TRUSTIX_TIXT_TX_FINALIZE_TCP_PARTIAL_CSUM) &&
	    (clear_flags & TRUSTIX_TIXT_TX_FINALIZE_TCP_TRUST_INNER_CSUM))
		return -EINVAL;

	skb_len = READ_ONCE(skb->len);
	if (skb_len < ETH_HLEN + sizeof(struct iphdr))
		return -EINVAL;
	inner_len = skb_len - ETH_HLEN;
	if (inner_len > 1500)
		return -EPROTONOSUPPORT;
	if (unlikely(!pskb_may_pull(skb, ETH_HLEN + sizeof(struct iphdr))))
		return -EPROTONOSUPPORT;
	if (ETH_HLEN + sizeof(struct iphdr) > skb_headlen(skb))
		return -EPROTONOSUPPORT;
	data = skb->data;
	if (data[ETH_HLEN] != 0x45)
		return -EPROTONOSUPPORT;
	if (get_unaligned_be16(data + ETH_HLEN +
			       offsetof(struct iphdr, frag_off)) & 0x3fff)
		return -EPROTONOSUPPORT;
	if (ntohs(((struct iphdr *)(data + ETH_HLEN))->tot_len) != inner_len)
		return -EPROTONOSUPPORT;
	if (check_add_overflow(inner_len, (u32)sizeof(struct iphdr) +
			       (u32)sizeof(struct tcphdr) +
			       (u32)TRUSTIX_TIXT_HEADER_LEN, &wire_len))
		return -EINVAL;
	if (READ_ONCE(flow->mtu) && wire_len > READ_ONCE(flow->mtu))
		return -EMSGSIZE;

	ret = trustix_tixt_tx_fix_inner_l4_csum(skb, ETH_HLEN, inner_len);
	if (ret < 0)
		return ret;

	if (trustix_tixt_tx_plain_skip_sequence_enabled())
		sequence = 0;
	else
		sequence = READ_ONCE(flow->sequence) + 1;

	if (trustix_skb_ensure_push_head(skb, push_len))
		return -ENOMEM;
	skb_reset_inner_headers(skb);
	skb_push(skb, push_len);
	if (skb->len != ETH_HLEN + wire_len || header_len > skb_headlen(skb))
		return -EINVAL;

	data = skb->data;
	partial_csum = clear_flags & TRUSTIX_TIXT_TX_FINALIZE_TCP_PARTIAL_CSUM;
	if (partial_csum) {
		trustix_tixt_tx_write_flow_tcp_header(data, flow, flow_id,
						      sequence, inner_len,
						      wire_len, true);
	} else {
		struct trustix_tixt_tx_tcp_header_args header = {};
		u16 tail1;

		header.saddr = flow->saddr;
		header.daddr = flow->daddr;
		header.source = flow->source;
		header.dest = flow->dest;
		header.ip_tot_len = wire_len;
		header.ip_check_base = READ_ONCE(flow->ipv4_check_tcp);
		header.flow_id = flow_id;
		header.payload_len = inner_len;
		header.sequence = sequence;
		memcpy(header.l2, &flow->destination_mac0,
		       sizeof(flow->destination_mac0));
		memcpy(header.l2 + 4, &flow->destination_mac1,
		       sizeof(flow->destination_mac1));
		memcpy(header.l2 + 6, &flow->source_mac0,
		       sizeof(flow->source_mac0));
		memcpy(header.l2 + 10, &flow->source_mac1,
		       sizeof(flow->source_mac1));
		tail1 = htons(ETH_P_IP);
		memcpy(header.l2 + 12, &tail1, sizeof(tail1));
		trustix_tixt_tx_write_tcp_header(data, &header, false, false);
	}

	skb_reset_mac_header(skb);
	skb_set_network_header(skb, ETH_HLEN);
	skb_set_transport_header(skb, ETH_HLEN + sizeof(struct iphdr));
	skb->mac_len = ETH_HLEN;
	skb->protocol = htons(ETH_P_IP);
	if (partial_csum) {
		skb->ip_summed = CHECKSUM_PARTIAL;
		skb->csum_start = skb_transport_header(skb) - skb->head;
		skb->csum_offset = offsetof(struct tcphdr, check);
	} else {
		tcp_len = sizeof(struct tcphdr) + TRUSTIX_TIXT_HEADER_LEN +
			  inner_len;
		tcph = (struct tcphdr *)(skb->data + ETH_HLEN +
					 sizeof(struct iphdr));
		if (clear_flags & TRUSTIX_TIXT_TX_FINALIZE_TCP_TRUST_INNER_CSUM) {
			memset(&csum_args, 0, sizeof(csum_args));
			csum_args.saddr = READ_ONCE(flow->saddr);
			csum_args.daddr = READ_ONCE(flow->daddr);
			csum_args.payload_len = inner_len;
			if (trustix_tixt_tx_trusted_inner_tcp_csum(
				    skb, &csum_args, header_len, tcp_len))
				goto route_snapshot_csum_done;
		}
		tcph->check = 0;
		sum = skb_checksum(skb, ETH_HLEN + sizeof(struct iphdr),
				   tcp_len, 0);
		tcph->check = csum_tcpudp_magic(READ_ONCE(flow->saddr),
						READ_ONCE(flow->daddr),
						tcp_len, IPPROTO_TCP, sum);
route_snapshot_csum_done:
		trustix_skb_clear_csum_metadata(skb);
	}
	skb->encapsulation = 0;
	if (clear_flags & TRUSTIX_SKB_CLEAR_TX_OFFLOAD_GSO)
		skb_gso_reset(skb);
	return 0;
}

static int trustix_tixt_tx_sanitize_route_gso_xmit_skb(struct sk_buff *skb,
						       struct net_device *out_dev);

static void trustix_route_tcp_xmit_worker_fn(struct work_struct *work)
{
	unsigned int budget = trustix_route_tcp_xmit_worker_budget_value();
	struct sk_buff_head batch;
	unsigned int batched = 0;
	bool reschedule = false;
	struct sk_buff *skb;

	skb_queue_head_init(&batch);
	spin_lock_bh(&trustix_route_tcp_xmit_worker_queue.lock);
	while (batched < budget &&
	       (skb = __skb_dequeue(&trustix_route_tcp_xmit_worker_queue))) {
		__skb_queue_tail(&batch, skb);
		batched++;
	}
	if (batched)
		WRITE_ONCE(trustix_route_tcp_xmit_worker_depth,
			   skb_queue_len(&trustix_route_tcp_xmit_worker_queue));
	if (!batched)
		WRITE_ONCE(trustix_route_tcp_xmit_worker_scheduled, false);
	spin_unlock_bh(&trustix_route_tcp_xmit_worker_queue.lock);
	if (!batched)
		return;

	while ((skb = __skb_dequeue(&batch))) {
		struct net_device *dev;
		int ret;

		dev = skb->dev;
		ret = trustix_tixt_tx_sanitize_route_gso_xmit_skb(skb, dev);
		if (ret) {
			trustix_route_tcp_xmit_worker_xmit_errors++;
			kfree_skb(skb);
			if (dev)
				dev_put(dev);
			continue;
		}
		ret = dev_queue_xmit(skb);
		if (ret == NET_XMIT_SUCCESS || ret == NET_XMIT_CN)
			trustix_route_tcp_xmit_worker_xmit_ok++;
		else
			trustix_route_tcp_xmit_worker_xmit_errors++;
		dev_put(dev);
	}

	spin_lock_bh(&trustix_route_tcp_xmit_worker_queue.lock);
	if (skb_queue_empty(&trustix_route_tcp_xmit_worker_queue))
		WRITE_ONCE(trustix_route_tcp_xmit_worker_scheduled, false);
	else
		reschedule = true;
	spin_unlock_bh(&trustix_route_tcp_xmit_worker_queue.lock);
	if (reschedule)
		schedule_work(&trustix_route_tcp_xmit_work);
}

static void trustix_route_tcp_xmit_worker_flush(void)
{
	struct sk_buff_head drop_list;
	struct sk_buff *skb;

	cancel_work_sync(&trustix_route_tcp_xmit_work);
	skb_queue_head_init(&drop_list);
	spin_lock_bh(&trustix_route_tcp_xmit_worker_queue.lock);
	skb_queue_splice_init(&trustix_route_tcp_xmit_worker_queue, &drop_list);
	WRITE_ONCE(trustix_route_tcp_xmit_worker_depth, 0);
	WRITE_ONCE(trustix_route_tcp_xmit_worker_scheduled, false);
	spin_unlock_bh(&trustix_route_tcp_xmit_worker_queue.lock);

	while ((skb = __skb_dequeue(&drop_list))) {
		struct net_device *dev = skb->dev;
		trustix_route_tcp_xmit_worker_flush_drops++;
		kfree_skb(skb);
		if (dev)
			dev_put(dev);
	}
}

struct trustix_tixt_tx_route_gso_template {
	struct net_device *out_dev;
	u8 base[TRUSTIX_TIXT_TCP_OUTER_HEADER_LEN];
	__be32 saddr;
	__be32 daddr;
	u32 mtu;
	u16 ip_check_base;
	u16 tx_queue_mapping;
	bool partial_csum;
	bool trust_inner_csum;
	bool trust_partial_inner_csum;
	bool secure;
	bool kernel_udp;
	bool use_tx_queue_mapping;
	bool stream_outer_gso;
};

struct trustix_tixt_tx_route_gso_stream_direct_frame {
	u64 sequence;
	u32 payload_offset;
	u32 payload_len;
	u32 inner_len;
	u32 plain_inner_len;
};

struct trustix_tixt_tx_route_gso_stream_direct_ref {
	struct trustix_tixt_tx_route_gso_async_work *item;
	struct trustix_tixt_tx_route_gso_stream_direct_frame frame;
};

struct trustix_tixt_tx_route_gso_async_work {
	struct list_head list;
	struct sk_buff *skb;
	struct trustix_tixt_tx_route_gso_template tmpl;
	u64 flow_id;
	u64 sequence;
	u64 outer_sequence;
	u64 sequence_cost;
	u32 queued_len;
	u32 segment_count;
	u32 gso_payload_len;
	u32 tcp_header_len;
	u32 payload_len;
	u32 inner_header_len;
	u32 inner_ip_check_base;
	u32 inner_tcp_seq_base;
	u32 queue_hash;
	__be32 inner_flow_saddr;
	__be32 inner_flow_daddr;
	__be16 inner_flow_sport;
	__be16 inner_flow_dport;
	u32 route_flow_mask;
	u32 secure_slot_id;
	u16 secure_suite;
	u16 secure_reserved;
	u64 secure_epoch;
	bool resliced;
	bool inner_flow_key_ready;
	bool inner_header_ready;
	bool sync_redirect;
	bool xmit_more;
	netdev_features_t gso_features;
	u8 secure_iv[12];
	u8 inner_header[TRUSTIX_TIXT_TX_ROUTE_GSO_INNER_HEADER_MAX];
	struct trustix_tixt_tx_route_gso_stream_direct_frame
		direct_frames[TRUSTIX_TIXT_TX_ROUTE_STREAM_MAX_FRAMES];
	struct trustix_aead_direct_batch_op
		direct_seal_ops[TRUSTIX_TIXT_TX_ROUTE_STREAM_MAX_FRAMES];
};

struct trustix_tixt_tx_route_gso_stream_frame {
	struct sk_buff *seg;
	u64 sequence;
	u32 inner_len;
};

static int
trustix_tixt_tx_route_gso_async_prepare_inner_header(
				struct trustix_tixt_tx_route_gso_async_work *item)
{
	struct tcphdr *tcph;
	struct iphdr *iph;
	u32 inner_header_len;
	int ret;

	if (!item || !item->skb ||
	    item->tcp_header_len < sizeof(struct tcphdr) ||
	    item->tcp_header_len > 60)
		return -EINVAL;
	if (check_add_overflow((u32)sizeof(struct iphdr),
			       item->tcp_header_len, &inner_header_len) ||
	    inner_header_len > sizeof(item->inner_header))
		return -EMSGSIZE;
	if (item->skb->len < ETH_HLEN + inner_header_len)
		return -EMSGSIZE;
	if (unlikely(!pskb_may_pull(item->skb,
				    ETH_HLEN + inner_header_len)))
		return -ENODATA;
	if (ETH_HLEN + inner_header_len > skb_headlen(item->skb))
		return -ENODATA;
	ret = skb_copy_bits(item->skb, ETH_HLEN, item->inner_header,
			    inner_header_len);
	if (ret)
		return ret;
	iph = (struct iphdr *)item->inner_header;
	tcph = (struct tcphdr *)(item->inner_header + sizeof(*iph));
	if (iph->version != 4 || iph->ihl != 5 ||
	    iph->protocol != IPPROTO_TCP ||
	    tcph->doff * 4 != item->tcp_header_len)
		return -EPROTONOSUPPORT;
	item->inner_header_len = inner_header_len;
	item->inner_header_ready = true;
	iph->tot_len = 0;
	iph->check = 0;
	item->inner_ip_check_base =
		trustix_ipv4_header_check20_base((const u8 *)iph);
	item->inner_tcp_seq_base = ntohl(tcph->seq);
	return 0;
}

static void trustix_route_tcp_gso_async_record_shape(struct sk_buff *skb)
{
	struct skb_shared_info *shinfo;
	unsigned int headlen;

	if (!skb)
		return;
	shinfo = skb_shinfo(skb);
	headlen = skb_headlen(skb);
	WRITE_ONCE(trustix_route_tcp_gso_async_last_gso_size,
		   shinfo->gso_size);
	WRITE_ONCE(trustix_route_tcp_gso_async_last_gso_segs,
		   shinfo->gso_segs);
	WRITE_ONCE(trustix_route_tcp_gso_async_last_gso_type,
		   shinfo->gso_type);
	WRITE_ONCE(trustix_route_tcp_gso_async_last_skb_len, skb->len);
	if (skb->len > READ_ONCE(trustix_route_tcp_gso_async_max_skb_len))
		WRITE_ONCE(trustix_route_tcp_gso_async_max_skb_len, skb->len);
	if (headlen > READ_ONCE(trustix_route_tcp_gso_async_max_headlen))
		WRITE_ONCE(trustix_route_tcp_gso_async_max_headlen, headlen);
}

static int trustix_tixt_tx_validate_route_gso_clear_flags(u32 clear_flags)
{
	if (clear_flags & ~(TRUSTIX_SKB_CLEAR_TX_OFFLOAD_CSUM |
			    TRUSTIX_SKB_CLEAR_TX_OFFLOAD_GSO |
			    TRUSTIX_SKB_CLEAR_TX_OFFLOAD_ENCAP |
			    TRUSTIX_TIXT_TX_FINALIZE_TCP_PARTIAL_CSUM |
			    TRUSTIX_TIXT_TX_FINALIZE_TCP_TRUST_INNER_CSUM |
			    TRUSTIX_TIXT_TX_FINALIZE_TCP_TRUST_PARTIAL_INNER_CSUM))
		return -EINVAL;
	if ((clear_flags & TRUSTIX_TIXT_TX_FINALIZE_TCP_PARTIAL_CSUM) &&
	    (clear_flags & TRUSTIX_TIXT_TX_FINALIZE_TCP_TRUST_INNER_CSUM))
		return -EINVAL;
	return 0;
}

static int
trustix_tixt_tx_gso_plan_inner(struct sk_buff *skb,
			       u32 route_mtu,
			       bool allow_reslice,
			       u32 frame_payload_extra,
			       u32 *segment_count,
			       u64 *sequence_cost,
			       u32 *max_wire_len,
			       u32 *gso_payload_len,
			       u32 *tcp_header_len_out,
			       u32 *payload_len_out,
			       bool *resliced_out)
{
	struct skb_shared_info *shinfo;
	const struct iphdr *iph;
	const struct tcphdr *tcph;
	u64 fixed_cost;
	u64 total_cost;
	u32 gso_size;
	u32 inner_header_len;
	u32 max_inner_len;
	u32 max_inner_payload_len;
	u32 max_payload_len;
	u32 planned_wire_len;
	u32 payload_len;
	u32 count;
	u32 tcp_header_len;
	u32 ip_len;
	bool has_gso;
	bool resliced = false;

	if (!skb || !segment_count || !sequence_cost || !max_wire_len ||
	    !gso_payload_len || !tcp_header_len_out || !payload_len_out ||
	    !resliced_out)
		return -EINVAL;
	WRITE_ONCE(trustix_route_tcp_gso_async_last_plan_ret, 0);
	WRITE_ONCE(trustix_route_tcp_gso_async_last_plan_mtu, route_mtu);
	WRITE_ONCE(trustix_route_tcp_gso_async_last_plan_max_inner_len, 0);
	WRITE_ONCE(trustix_route_tcp_gso_async_last_plan_gso_payload_len, 0);
	WRITE_ONCE(trustix_route_tcp_gso_async_last_plan_resliced, 0);
	if (skb->len < ETH_HLEN + sizeof(struct iphdr) + sizeof(struct tcphdr))
		return -EPROTONOSUPPORT;
	if (unlikely(!pskb_may_pull(skb, ETH_HLEN + sizeof(struct iphdr) +
					 sizeof(struct tcphdr))))
		return -EPROTONOSUPPORT;
	if (ETH_HLEN + sizeof(struct iphdr) + sizeof(struct tcphdr) >
	    skb_headlen(skb))
		return -EPROTONOSUPPORT;

	iph = (const struct iphdr *)(skb->data + ETH_HLEN);
	if (iph->version != 4 || iph->ihl != 5 ||
	    iph->protocol != IPPROTO_TCP ||
	    (iph->frag_off & htons(0x3fff)))
		return -EPROTONOSUPPORT;
	ip_len = ntohs(iph->tot_len);
	if (ip_len < sizeof(struct iphdr) + sizeof(struct tcphdr) ||
	    skb->len < ETH_HLEN + ip_len)
		return -EPROTONOSUPPORT;

	tcph = (const struct tcphdr *)(skb->data + ETH_HLEN +
				       sizeof(struct iphdr));
	tcp_header_len = tcph->doff * 4;
	if (tcp_header_len < sizeof(struct tcphdr) ||
	    ip_len < sizeof(struct iphdr) + tcp_header_len)
		return -EPROTONOSUPPORT;
	shinfo = skb_shinfo(skb);
	gso_size = READ_ONCE(shinfo->gso_size);
	has_gso = gso_size != 0;
	if (has_gso &&
	    (shinfo->gso_type & SKB_GSO_TCPV4) != SKB_GSO_TCPV4)
		return -EPROTONOSUPPORT;
	if (!has_gso && skb->len != ETH_HLEN + ip_len)
		return -EPROTONOSUPPORT;
	inner_header_len = (u32)sizeof(struct iphdr) + tcp_header_len;
	if (skb->len > ETH_HLEN + ip_len) {
		if (skb->len < ETH_HLEN + inner_header_len)
			return -EPROTONOSUPPORT;
		payload_len = skb->len - ETH_HLEN - inner_header_len;
	} else {
		payload_len = ip_len - inner_header_len;
	}
	if (!payload_len)
		return -EPROTONOSUPPORT;
	max_payload_len = has_gso ? min(payload_len, gso_size) : payload_len;
	if (route_mtu) {
		u32 max_inner_l3_len;

		if (route_mtu <= TRUSTIX_TIXT_TCP_OUTER_OVERHEAD +
				 frame_payload_extra +
				 inner_header_len)
			return -EMSGSIZE;
		max_inner_l3_len = route_mtu -
				    TRUSTIX_TIXT_TCP_OUTER_OVERHEAD -
				    frame_payload_extra;
		max_inner_payload_len = max_inner_l3_len - inner_header_len;
		if (!max_inner_payload_len)
			return -EMSGSIZE;
		if (max_payload_len > max_inner_payload_len) {
			if (has_gso && !allow_reslice && !frame_payload_extra)
				return -EMSGSIZE;
			max_payload_len = max_inner_payload_len;
			resliced = true;
		}
	} else {
		max_inner_payload_len = 1500U > inner_header_len ?
					1500U - inner_header_len : 0;
		if (!max_inner_payload_len ||
		    max_payload_len > max_inner_payload_len)
			return -EMSGSIZE;
	}
	if (frame_payload_extra) {
		u32 max_secure_payload_len;

		if (inner_header_len >= TRUSTIX_KERNEL_CRYPTO_PLAIN_MAX)
			return -EMSGSIZE;
		max_secure_payload_len =
			TRUSTIX_KERNEL_CRYPTO_PLAIN_MAX - inner_header_len;
		if (!max_secure_payload_len)
			return -EMSGSIZE;
		if (max_payload_len > max_secure_payload_len) {
			max_payload_len = max_secure_payload_len;
			resliced = true;
		}
	}
	count = DIV_ROUND_UP(payload_len, max_payload_len);
	if (!count)
		return -EPROTONOSUPPORT;
	if (count > TRUSTIX_TIXT_TX_GSO_MAX_SEGMENTS)
		return -E2BIG;
	if (check_add_overflow(inner_header_len, max_payload_len,
			       &max_inner_len))
		return -EINVAL;
	if (check_add_overflow(max_inner_len,
			       TRUSTIX_TIXT_TCP_OUTER_OVERHEAD +
				       frame_payload_extra,
			       &planned_wire_len))
		return -EINVAL;
	if (check_mul_overflow((u64)count,
			       (u64)sizeof(struct iphdr) +
			       (u64)tcp_header_len +
			       (u64)TRUSTIX_TIXT_HEADER_LEN +
			       (u64)frame_payload_extra,
			       &fixed_cost))
		return -EOVERFLOW;
	if (check_add_overflow((u64)payload_len, fixed_cost, &total_cost))
		return -EOVERFLOW;
	if (!total_cost)
		return -EIO;

	*segment_count = count;
	*sequence_cost = total_cost;
	*max_wire_len = planned_wire_len;
	*gso_payload_len = max_payload_len;
	*tcp_header_len_out = tcp_header_len;
	*payload_len_out = payload_len;
	*resliced_out = resliced;
	WRITE_ONCE(trustix_route_tcp_gso_async_last_plan_max_inner_len,
		   max_inner_len);
	WRITE_ONCE(trustix_route_tcp_gso_async_last_plan_gso_payload_len,
		   max_payload_len);
	WRITE_ONCE(trustix_route_tcp_gso_async_last_plan_resliced,
		   resliced ? 1U : 0U);
	if (!has_gso)
		trustix_route_tcp_gso_async_linear_plans++;
	return 0;
}

static int
trustix_tixt_tx_gso_segment_inner(struct sk_buff *skb,
				  struct sk_buff **segments,
				  u32 *segment_count,
	u64 *sequence_cost,
	u32 *max_wire_len,
	u32 *gso_payload_len,
	u32 *tcp_header_len_out,
	u32 *payload_len_out,
	netdev_features_t features)
{
	bool resliced = false;
	int ret;

	if (!segments)
		return -EINVAL;
	ret = trustix_tixt_tx_gso_plan_inner(skb, 0, false, 0, segment_count,
					     sequence_cost, max_wire_len,
					     gso_payload_len,
					     tcp_header_len_out,
					     payload_len_out, &resliced);
	if (ret)
		return ret;

	skb_reset_mac_header(skb);
	skb_set_network_header(skb, ETH_HLEN);
	skb_set_transport_header(skb, ETH_HLEN + sizeof(struct iphdr));
	skb->mac_len = ETH_HLEN;
	*segments = skb_gso_segment(skb, features);
	if (IS_ERR(*segments))
		return PTR_ERR(*segments);
	if (!*segments)
		return -EIO;
	return 0;
}

static void
trustix_tixt_tx_init_route_gso_template(
				const struct trustix_kudp_tx_flow_value *flow,
				struct net_device *out_dev, u64 flow_id,
				u32 clear_flags,
				struct trustix_tixt_tx_route_gso_template *tmpl)
{
	struct tcphdr *tcph;
	struct iphdr *iph;
	u8 *tixt;
	u16 tail1;

	memset(tmpl, 0, sizeof(*tmpl));
	tmpl->out_dev = out_dev;
	tmpl->partial_csum =
		clear_flags & TRUSTIX_TIXT_TX_FINALIZE_TCP_PARTIAL_CSUM;
	tmpl->trust_inner_csum =
		clear_flags & TRUSTIX_TIXT_TX_FINALIZE_TCP_TRUST_INNER_CSUM;
	tmpl->trust_partial_inner_csum =
		clear_flags &
		TRUSTIX_TIXT_TX_FINALIZE_TCP_TRUST_PARTIAL_INNER_CSUM;
	tmpl->stream_outer_gso =
		READ_ONCE(trustix_route_tcp_gso_async_stream_outer_gso);
	tmpl->saddr = READ_ONCE(flow->saddr);
	tmpl->daddr = READ_ONCE(flow->daddr);
	tmpl->mtu = READ_ONCE(flow->mtu);
	tmpl->ip_check_base = READ_ONCE(flow->ipv4_check_tcp);

	memcpy(tmpl->base, &flow->destination_mac0,
	       sizeof(flow->destination_mac0));
	memcpy(tmpl->base + 4, &flow->destination_mac1,
	       sizeof(flow->destination_mac1));
	memcpy(tmpl->base + 6, &flow->source_mac0,
	       sizeof(flow->source_mac0));
	memcpy(tmpl->base + 10, &flow->source_mac1,
	       sizeof(flow->source_mac1));
	tail1 = htons(ETH_P_IP);
	memcpy(tmpl->base + 12, &tail1, sizeof(tail1));
	iph = (struct iphdr *)(tmpl->base + ETH_HLEN);
	iph->version = 4;
	iph->ihl = 5;
	iph->frag_off = htons(0x4000);
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->saddr = tmpl->saddr;
	iph->daddr = tmpl->daddr;

	tcph = (struct tcphdr *)(tmpl->base + ETH_HLEN + sizeof(*iph));
	tcph->source = READ_ONCE(flow->source);
	tcph->dest = READ_ONCE(flow->dest);
	tcph->doff = 5;
	tcph->ack = 1;
	tcph->ack_seq = htonl(1);
	if (!trustix_tixt_tx_plain_ack_only_enabled())
		tcph->psh = 1;
	tcph->window = htons(0xffff);

	tixt = (u8 *)(tcph + 1);
	put_unaligned_be32(TRUSTIX_TIXT_MAGIC, tixt);
	tixt[4] = 1;
	tixt[5] = TRUSTIX_TIXT_FLAG_INNER_IPV4;
	put_unaligned_be16(TRUSTIX_TIXT_HEADER_LEN, tixt + 6);
	put_unaligned_be64(flow_id, tixt + 8);
}

static void
trustix_tixt_tx_init_secure_route_gso_template(
				const struct trustix_kudp_tx_flow_value *flow,
				struct net_device *out_dev, u64 flow_id,
				u32 clear_flags,
				struct trustix_tixt_tx_route_gso_template *tmpl)
{
	struct udphdr *udph;
	struct iphdr *iph;
	u8 *tixt;
	u8 *kudp;
	u16 tail1;

	if (READ_ONCE(flow->flags) & TRUSTIX_KUDP_TX_FLOW_FLAG_EXPERIMENTAL_TCP) {
		trustix_tixt_tx_init_route_gso_template(flow, out_dev, flow_id,
							clear_flags, tmpl);
		tmpl->secure = true;
		tixt = tmpl->base + ETH_HLEN + sizeof(struct iphdr) +
		       sizeof(struct tcphdr);
		tixt[5] = TRUSTIX_TIXT_FLAG_ENCRYPTED | TRUSTIX_TIXT_FLAG_INNER_IPV4;
		return;
	}

	memset(tmpl, 0, sizeof(*tmpl));
	tmpl->out_dev = out_dev;
	tmpl->secure = true;
	tmpl->kernel_udp = true;
	tmpl->saddr = READ_ONCE(flow->saddr);
	tmpl->daddr = READ_ONCE(flow->daddr);
	tmpl->mtu = READ_ONCE(flow->mtu);
	tmpl->ip_check_base = READ_ONCE(flow->ipv4_check_udp);

	memcpy(tmpl->base, &flow->destination_mac0,
	       sizeof(flow->destination_mac0));
	memcpy(tmpl->base + 4, &flow->destination_mac1,
	       sizeof(flow->destination_mac1));
	memcpy(tmpl->base + 6, &flow->source_mac0,
	       sizeof(flow->source_mac0));
	memcpy(tmpl->base + 10, &flow->source_mac1,
	       sizeof(flow->source_mac1));
	tail1 = htons(ETH_P_IP);
	memcpy(tmpl->base + 12, &tail1, sizeof(tail1));

	iph = (struct iphdr *)(tmpl->base + ETH_HLEN);
	iph->version = 4;
	iph->ihl = 5;
	iph->frag_off = htons(0x4000);
	iph->ttl = 64;
	iph->protocol = IPPROTO_UDP;
	iph->saddr = tmpl->saddr;
	iph->daddr = tmpl->daddr;

	udph = (struct udphdr *)(tmpl->base + ETH_HLEN + sizeof(*iph));
	udph->source = READ_ONCE(flow->source);
	udph->dest = READ_ONCE(flow->dest);

	kudp = (u8 *)(udph + 1);
	put_unaligned_be32(TRUSTIX_KUDP_MAGIC, kudp);
	kudp[4] = 1;
	kudp[5] = TRUSTIX_KUDP_FLAG_ENCRYPTED | TRUSTIX_KUDP_FLAG_INNER_IPV4;
	put_unaligned_be16(TRUSTIX_KUDP_HEADER_LEN, kudp + 6);
	put_unaligned_be64(flow_id, kudp + 8);
}

static void
trustix_tixt_tx_route_gso_template_set_tx_queue_hash(
				struct trustix_tixt_tx_route_gso_template *tmpl,
				u32 hash)
{
	unsigned int txq_count;

	if (!READ_ONCE(trustix_route_tcp_gso_async_hash_tx_queue))
		return;
	if (!tmpl || !tmpl->out_dev)
		return;
	txq_count = READ_ONCE(tmpl->out_dev->real_num_tx_queues);
	if (txq_count <= 1) {
		if (READ_ONCE(trustix_route_tcp_gso_async_hot_stats))
			trustix_route_tcp_gso_async_hash_tx_queue_fallbacks++;
		return;
	}
	tmpl->use_tx_queue_mapping = true;
	tmpl->tx_queue_mapping = (u16)(hash % txq_count);
}

static __always_inline void
trustix_tixt_tx_write_route_gso_header(u8 *dst,
				const struct trustix_tixt_tx_route_gso_template *tmpl,
				u32 wire_len, u32 inner_len, u64 sequence)
{
	struct tcphdr *tcph;
	struct iphdr *iph;
	u32 tcp_len;
	u32 sum;
	u16 check;
	u8 *tixt;

	memcpy(dst, tmpl->base, sizeof(tmpl->base));

	iph = (struct iphdr *)(dst + ETH_HLEN);
	iph->tot_len = htons(wire_len);
	sum = tmpl->ip_check_base;
	sum += wire_len;
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	check = ~sum;
	if (!check)
		check = 0xffff;
	iph->check = htons(check);

	tcph = (struct tcphdr *)(dst + ETH_HLEN + sizeof(*iph));
	tcph->seq = htonl((u32)sequence);

	tixt = (u8 *)(tcph + 1);
	put_unaligned_be64(0, tixt + 16);
	put_unaligned_be64(sequence, tixt + 24);
	put_unaligned_be32(inner_len, tixt + 32);
	put_unaligned_be16(0, tixt + 36);
	put_unaligned_be16(0, tixt + 38);

	if (tmpl->partial_csum) {
		tcp_len = sizeof(*tcph) + TRUSTIX_TIXT_HEADER_LEN +
			  inner_len;
		tcph->check = trustix_ipv4_l4_partial_check_from_ip_base(
			tmpl->ip_check_base, tcp_len);
	}
}

static int trustix_tixt_tx_validate_route_gso_stream_frame(
				struct sk_buff *skb, u32 frame_offset,
				u32 frame_len)
{
	u8 tixt_buf[TRUSTIX_TIXT_HEADER_LEN];
	struct iphdr inner_iph_buf;
	const struct iphdr *inner_iph;
	const u8 *tixt;
	u32 frame_end;
	u32 payload_offset;
	u32 payload_len;
	u8 frame_flags;

	if (!skb || frame_len < TRUSTIX_TIXT_HEADER_LEN + sizeof(*inner_iph))
		return -EINVAL;
	if (check_add_overflow(frame_offset, frame_len, &frame_end))
		return -EOVERFLOW;
	if (frame_end > skb->len)
		return -EMSGSIZE;
	if (check_add_overflow(frame_offset, TRUSTIX_TIXT_HEADER_LEN,
			       &payload_offset))
		return -EOVERFLOW;
	if (payload_offset > frame_end)
		return -EMSGSIZE;

	tixt = skb_header_pointer(skb, frame_offset, TRUSTIX_TIXT_HEADER_LEN,
				  tixt_buf);
	if (!tixt)
		return -ENODATA;
	if (get_unaligned_be32(tixt) != TRUSTIX_TIXT_MAGIC)
		return -EBADMSG;
	if (tixt[4] != 1 ||
	    get_unaligned_be16(tixt + 6) != TRUSTIX_TIXT_HEADER_LEN)
		return -EBADMSG;
	frame_flags = tixt[5];
	if ((frame_flags & TRUSTIX_TIXT_FLAG_INNER_IPV4) !=
	    TRUSTIX_TIXT_FLAG_INNER_IPV4)
		return -EPROTONOSUPPORT;
	payload_len = get_unaligned_be32(tixt + 32);
	if (payload_len != frame_len - TRUSTIX_TIXT_HEADER_LEN ||
	    payload_len < sizeof(*inner_iph) || payload_len > 0xffff)
		return -EMSGSIZE;
	if (frame_flags & TRUSTIX_TIXT_FLAG_ENCRYPTED) {
		u8 secure_buf[TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN];
		const u8 *secure;

		if (frame_flags & ~(TRUSTIX_TIXT_FLAG_ENCRYPTED |
				    TRUSTIX_TIXT_FLAG_INNER_IPV4))
			return -EPROTONOSUPPORT;
		if (payload_len < TRUSTIX_TIXT_TX_SECURE_PAYLOAD_OVERHEAD +
				  sizeof(*inner_iph) ||
		    payload_len > TRUSTIX_KERNEL_CRYPTO_FRAME_MAX)
			return -EMSGSIZE;
		secure = skb_header_pointer(skb, payload_offset,
					    TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN,
					    secure_buf);
		if (!secure)
			return -ENODATA;
		if (get_unaligned_be32(secure) != 0x54495844U ||
		    secure[4] != 1)
			return -EBADMSG;
		return 0;
	}
	if (frame_flags & ~(TRUSTIX_TIXT_FLAG_KERNEL_OPENED |
			    TRUSTIX_TIXT_FLAG_INNER_IPV4))
		return -EPROTONOSUPPORT;

	inner_iph = skb_header_pointer(skb, payload_offset,
				       sizeof(inner_iph_buf), &inner_iph_buf);
	if (!inner_iph)
		return -ENODATA;
	if (inner_iph->version != 4 || inner_iph->ihl < 5 ||
	    ntohs(inner_iph->tot_len) != payload_len ||
	    (inner_iph->frag_off & htons(0x3fff)))
		return -EBADMSG;
	return 0;
}

static int trustix_tixt_tx_validate_route_gso_xmit_skb_gso(
				struct sk_buff *skb, struct net_device *out_dev)
{
	const u32 outer_l3_l4_len = sizeof(struct iphdr) +
				    sizeof(struct tcphdr);
	const u32 outer_header_len = ETH_HLEN + outer_l3_l4_len;
	struct skb_shared_info *shinfo;
	const struct tcphdr *tcph;
	const struct iphdr *iph;
	netdev_features_t features;
	u32 payload_len;
	u32 gso_wire_len;
	u32 expected_segs;
	u32 frame_offset;
	u32 frame_len;
	u32 remaining;
	u32 ip_len;
	int ret;

	if (!skb || !out_dev)
		return -EINVAL;
	if (!skb_is_gso(skb))
		return 0;
	shinfo = skb_shinfo(skb);
	if (!shinfo->gso_size || shinfo->gso_segs < 2)
		return -EINVAL;
	if (shinfo->gso_segs > TRUSTIX_TIXT_TX_ROUTE_STREAM_MAX_FRAMES)
		return -E2BIG;
	if ((shinfo->gso_type & SKB_GSO_TCPV4) != SKB_GSO_TCPV4)
		return -EOPNOTSUPP;
	if (skb->protocol != htons(ETH_P_IP) || skb->mac_len != ETH_HLEN)
		return -EINVAL;
	if (skb_headlen(skb) < outer_header_len ||
	    skb->len <= outer_header_len)
		return -EINVAL;
	if (skb_network_header(skb) != skb->data + ETH_HLEN ||
	    skb_transport_header(skb) !=
		    skb->data + ETH_HLEN + sizeof(struct iphdr))
		return -EINVAL;
	iph = (const struct iphdr *)(skb->data + ETH_HLEN);
	tcph = (const struct tcphdr *)(skb->data + ETH_HLEN + sizeof(*iph));
	if (iph->version != 4 || iph->ihl != 5 ||
	    iph->protocol != IPPROTO_TCP ||
	    (iph->frag_off & htons(0x3fff)) ||
	    tcph->doff != 5)
		return -EINVAL;
	ip_len = ntohs(iph->tot_len);
	if (ip_len != skb->len - ETH_HLEN)
		return -EINVAL;
	if (skb->ip_summed != CHECKSUM_PARTIAL ||
	    skb->csum_start != (skb_transport_header(skb) - skb->head) ||
	    skb->csum_offset != offsetof(struct tcphdr, check))
		return -EINVAL;

	payload_len = skb->len - outer_header_len;
	expected_segs = DIV_ROUND_UP(payload_len, shinfo->gso_size);
	if (expected_segs != shinfo->gso_segs)
		return -EINVAL;
	if (check_add_overflow(outer_l3_l4_len, (u32)shinfo->gso_size,
			       &gso_wire_len))
		return -EMSGSIZE;
	if (gso_wire_len > READ_ONCE(out_dev->mtu))
		return -EMSGSIZE;
	frame_offset = outer_header_len;
	remaining = payload_len;
	while (remaining) {
		frame_len = min_t(u32, remaining, shinfo->gso_size);
		ret = trustix_tixt_tx_validate_route_gso_stream_frame(
			skb, frame_offset, frame_len);
		if (ret)
			return ret;
		if (remaining > shinfo->gso_size &&
		    frame_len != shinfo->gso_size)
			return -EINVAL;
		frame_offset += frame_len;
		remaining -= frame_len;
	}

	features = netif_skb_features(skb);
	if (skb_is_nonlinear(skb) && !(features & NETIF_F_SG))
		return -EOPNOTSUPP;
	if (!(features & NETIF_F_TSO) || !(features & NETIF_F_HW_CSUM))
		return -EOPNOTSUPP;
	if (!skb_gso_ok(skb, features))
		return -EOPNOTSUPP;
	return 0;
}

static bool trustix_route_tcp_gso_async_can_txq_backoff_sleep(void)
{
	return !in_interrupt() && !irqs_disabled() && !in_atomic();
}

static void
trustix_tixt_tx_route_gso_maybe_backoff_stopped_txq(struct netdev_queue *txq)
{
	unsigned int retries =
		READ_ONCE(trustix_route_tcp_gso_async_txq_stopped_backoff_retries);
	unsigned int sleep_usecs = READ_ONCE(
		trustix_route_tcp_gso_async_txq_stopped_backoff_sleep_usecs);
	unsigned int i;

	if (!txq || !netif_xmit_stopped(txq))
		return;
	trustix_route_tcp_gso_async_txq_stopped_queued++;
	if (!retries)
		return;
	if (!trustix_route_tcp_gso_async_can_txq_backoff_sleep()) {
		trustix_route_tcp_gso_async_txq_stopped_backoff_still_stopped++;
		return;
	}
	retries = min_t(unsigned int, retries, 16U);
	sleep_usecs = min_t(unsigned int, sleep_usecs, 20000U);
	for (i = 0; i < retries; i++) {
		trustix_route_tcp_gso_async_txq_stopped_backoff_attempts++;
		if (sleep_usecs) {
			trustix_route_tcp_gso_async_txq_stopped_backoff_sleeps++;
			usleep_range(sleep_usecs,
				     sleep_usecs + min_t(unsigned int,
							 sleep_usecs, 1000U));
		} else {
			trustix_route_tcp_gso_async_txq_stopped_backoff_yields++;
			cond_resched();
		}
		if (!netif_xmit_stopped(txq)) {
			trustix_route_tcp_gso_async_txq_stopped_backoff_recovered++;
			return;
		}
	}
	trustix_route_tcp_gso_async_txq_stopped_backoff_still_stopped++;
}

static int trustix_tixt_tx_sanitize_route_gso_xmit_skb(struct sk_buff *skb,
						       struct net_device *out_dev)
{
	struct netdev_queue *txq;
	unsigned int txq_count;
	int ret;

	if (!skb || !out_dev)
		return -EINVAL;
	if (!netif_running(out_dev) || !netif_carrier_ok(out_dev))
		return -ENETDOWN;
	skb->dev = out_dev;
	ret = trustix_tixt_tx_validate_route_gso_xmit_skb_gso(skb, out_dev);
	if (ret) {
		trustix_route_tcp_gso_async_stream_outer_gso_verify_errors++;
		return ret;
	}
	if (skb->len > out_dev->mtu + out_dev->hard_header_len) {
		struct skb_shared_info *shinfo = skb_shinfo(skb);
		u32 gso_wire_len;

		if (!skb_is_gso(skb) || !shinfo->gso_size)
			return -EMSGSIZE;
		if (check_add_overflow((u32)sizeof(struct iphdr) +
					       (u32)sizeof(struct tcphdr),
				       shinfo->gso_size, &gso_wire_len))
			return -EMSGSIZE;
		if (gso_wire_len > out_dev->mtu)
			return -EMSGSIZE;
	}

	skb_scrub_packet(skb, true);
	skb_orphan(skb);
	skb_dst_drop(skb);
	skb->dev = out_dev;
	skb->protocol = htons(ETH_P_IP);
	skb->priority = 0;
	skb_reset_mac_header(skb);
	skb_set_network_header(skb, ETH_HLEN);
	skb_set_transport_header(skb, ETH_HLEN + sizeof(struct iphdr));
	skb->mac_len = ETH_HLEN;

	txq_count = READ_ONCE(out_dev->real_num_tx_queues);
	if (!txq_count)
		return -ENODEV;
	if (skb_get_queue_mapping(skb) >= txq_count)
		skb_set_queue_mapping(skb, 0);
	txq = netdev_get_tx_queue(out_dev, skb_get_queue_mapping(skb));
	trustix_tixt_tx_route_gso_maybe_backoff_stopped_txq(txq);
	return 0;
}

static void trustix_tixt_tx_route_gso_apply_tx_queue(
				struct sk_buff *skb,
				const struct trustix_tixt_tx_route_gso_template *tmpl)
{
	if (!skb || !tmpl || !tmpl->use_tx_queue_mapping)
		return;
	skb_set_queue_mapping(skb, tmpl->tx_queue_mapping);
	trustix_route_tcp_gso_async_hash_tx_queue_sets++;
	switch (tmpl->tx_queue_mapping) {
	case 0:
		trustix_route_tcp_gso_async_hash_tx_queue_q0++;
		break;
	case 1:
		trustix_route_tcp_gso_async_hash_tx_queue_q1++;
		break;
	case 2:
		trustix_route_tcp_gso_async_hash_tx_queue_q2++;
		break;
	case 3:
		trustix_route_tcp_gso_async_hash_tx_queue_q3++;
		break;
	case 4:
		trustix_route_tcp_gso_async_hash_tx_queue_q4++;
		break;
	case 5:
		trustix_route_tcp_gso_async_hash_tx_queue_q5++;
		break;
	case 6:
		trustix_route_tcp_gso_async_hash_tx_queue_q6++;
		break;
	case 7:
		trustix_route_tcp_gso_async_hash_tx_queue_q7++;
		break;
	default:
		trustix_route_tcp_gso_async_hash_tx_queue_other++;
		break;
	}
}

static bool trustix_tixt_tx_route_gso_xmit_ready(struct sk_buff *skb)
{
	struct net_device *out_dev;
	unsigned int txq_count;

	if (!skb)
		return false;
	out_dev = skb->dev;
	if (!out_dev || !netif_running(out_dev) || !netif_carrier_ok(out_dev))
		return false;
	txq_count = READ_ONCE(out_dev->real_num_tx_queues);
	if (!txq_count)
		return false;
	if (skb_get_queue_mapping(skb) >= txq_count)
		return false;
	return true;
}

static bool trustix_tixt_tx_route_gso_xmit_ready_async(struct sk_buff *skb)
{
	unsigned int retries =
		READ_ONCE(trustix_route_tcp_gso_async_xmit_busy_retries);
	unsigned int sleep_usecs =
		READ_ONCE(trustix_route_tcp_gso_async_xmit_busy_sleep_usecs);
	unsigned int i;

	if (likely(trustix_tixt_tx_route_gso_xmit_ready(skb)))
		return true;
	retries = min_t(unsigned int, retries, 16U);
	sleep_usecs = min_t(unsigned int, sleep_usecs, 20000U);
	for (i = 0; i < retries; i++) {
		trustix_route_tcp_gso_async_xmit_busy_retry_attempts++;
		if (sleep_usecs)
			usleep_range(sleep_usecs,
				     sleep_usecs + min_t(unsigned int,
							 sleep_usecs, 1000U));
		else
			cond_resched();
		if (likely(trustix_tixt_tx_route_gso_xmit_ready(skb))) {
			trustix_route_tcp_gso_async_xmit_busy_retry_successes++;
			return true;
		}
	}
	trustix_route_tcp_gso_async_xmit_busy_retry_failures++;
	return false;
}

static __always_inline void
trustix_tixt_tx_route_gso_apply_xmit_more(struct sk_buff *skb, bool more)
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

static __always_inline bool
trustix_route_tcp_gso_async_xmit_accepted(int ret)
{
	unsigned int sleep_usecs;

	if (likely(ret == NET_XMIT_SUCCESS))
		return true;
	if (ret != NET_XMIT_CN)
		return false;
	trustix_route_tcp_gso_async_xmit_cn++;
	if (READ_ONCE(trustix_route_tcp_gso_async_yield_on_xmit_cn))
		cond_resched();
	sleep_usecs = READ_ONCE(trustix_route_tcp_gso_async_xmit_cn_sleep_usecs);
	if (sleep_usecs) {
		sleep_usecs = min_t(unsigned int, sleep_usecs, 20000U);
		usleep_range(sleep_usecs,
			     sleep_usecs + min_t(unsigned int, sleep_usecs,
						 1000U));
	}
	return true;
}

static __always_inline int
trustix_tixt_tx_route_gso_safe_xmit(struct sk_buff *skb,
				    bool direct_requested)
{
	int ret;

	if (!skb)
		return -EINVAL;
	if (direct_requested) {
		trustix_route_tcp_gso_direct_xmit_attempts++;
		trustix_route_tcp_gso_direct_xmit_safe_fallbacks++;
	}
	ret = dev_queue_xmit(skb);
	if (likely(trustix_route_tcp_gso_async_xmit_accepted(ret)))
		return 0;
	return -EIO;
}

static int
trustix_tixt_tx_prepare_one_segment(struct sk_buff *seg,
				const struct trustix_tixt_tx_route_gso_template *tmpl,
				u32 inner_len, u64 sequence)
{
	struct trustix_tixt_tx_tcp_header_args csum_args;
	struct net_device *out_dev;
	struct tcphdr *tcph;
	__wsum sum;
	u32 header_len = TRUSTIX_TIXT_TCP_OUTER_HEADER_LEN;
	u32 tcp_len;
	u32 wire_len;
	u32 push_len = header_len - ETH_HLEN;
	bool partial_csum;
	int ret;

	if (!seg || !tmpl || !tmpl->out_dev)
		return -EINVAL;
	out_dev = tmpl->out_dev;
	partial_csum = tmpl->partial_csum;
	if (seg->len < ETH_HLEN + sizeof(struct iphdr))
		return -EPROTONOSUPPORT;
	if (unlikely(!pskb_may_pull(seg, ETH_HLEN + sizeof(struct iphdr))))
		return -EPROTONOSUPPORT;
	if (ETH_HLEN + sizeof(struct iphdr) > skb_headlen(seg))
		return -EPROTONOSUPPORT;
	if (inner_len < sizeof(struct iphdr) + sizeof(struct tcphdr) ||
	    seg->len < ETH_HLEN + inner_len)
		return -EPROTONOSUPPORT;
	if (inner_len > 1500)
		return -EMSGSIZE;
	wire_len = inner_len + TRUSTIX_TIXT_TCP_OUTER_OVERHEAD;
	skb_reset_mac_header(seg);
	skb_set_network_header(seg, ETH_HLEN);
	skb_set_transport_header(seg, ETH_HLEN + sizeof(struct iphdr));
	seg->mac_len = ETH_HLEN;
	if (seg->ip_summed == CHECKSUM_PARTIAL &&
	    !tmpl->trust_partial_inner_csum) {
		ret = skb_checksum_help(seg);
		if (ret)
			return ret;
	}

	if (trustix_skb_ensure_push_head(seg, push_len))
		return -ENOMEM;
	skb_reset_inner_headers(seg);
	skb_push(seg, push_len);
	if (seg->len != ETH_HLEN + wire_len || header_len > skb_headlen(seg))
		return -EINVAL;

	trustix_tixt_tx_write_route_gso_header(seg->data, tmpl, wire_len,
					       inner_len, sequence);
	skb_reset_mac_header(seg);
	skb_set_network_header(seg, ETH_HLEN);
	skb_set_transport_header(seg, ETH_HLEN + sizeof(struct iphdr));
	seg->mac_len = ETH_HLEN;
	seg->protocol = htons(ETH_P_IP);
	seg->dev = out_dev;
	skb_dst_drop(seg);
	skb_orphan(seg);
	trustix_tixt_tx_route_gso_apply_tx_queue(seg, tmpl);

	if (partial_csum) {
		seg->ip_summed = CHECKSUM_PARTIAL;
		seg->csum_start = skb_transport_header(seg) - seg->head;
		seg->csum_offset = offsetof(struct tcphdr, check);
	} else {
		tcp_len = sizeof(struct tcphdr) + TRUSTIX_TIXT_HEADER_LEN +
			  inner_len;
		memset(&csum_args, 0, sizeof(csum_args));
		csum_args.saddr = tmpl->saddr;
		csum_args.daddr = tmpl->daddr;
		csum_args.payload_len = inner_len;
		if (!tmpl->trust_inner_csum ||
		    !trustix_tixt_tx_trusted_inner_tcp_csum(seg, &csum_args,
							   header_len,
							   tcp_len)) {
			tcph = (struct tcphdr *)(seg->data + ETH_HLEN +
						 sizeof(struct iphdr));
			tcph->check = 0;
			sum = skb_checksum(seg, ETH_HLEN + sizeof(struct iphdr),
					   tcp_len, 0);
			tcph->check = csum_tcpudp_magic(tmpl->saddr,
							tmpl->daddr, tcp_len,
							IPPROTO_TCP, sum);
		}
		trustix_skb_clear_csum_metadata(seg);
	}
	seg->encapsulation = 0;
	seg->csum_level = 0;
	skb_gso_reset(seg);
	return trustix_tixt_tx_sanitize_route_gso_xmit_skb(seg, out_dev);
}

static u32 trustix_tixt_tx_route_gso_stream_mtu(
				const struct trustix_tixt_tx_route_gso_template *tmpl)
{
	u32 mtu = 0;

	if (!tmpl || !tmpl->out_dev)
		return 0;
	mtu = READ_ONCE(tmpl->out_dev->mtu);
	if (READ_ONCE(tmpl->mtu) && (!mtu || READ_ONCE(tmpl->mtu) < mtu))
		mtu = READ_ONCE(tmpl->mtu);
	return mtu;
}

static u32 trustix_tixt_tx_route_gso_effective_mtu(
				const struct trustix_kudp_tx_flow_value *flow,
				struct net_device *out_dev)
{
	u32 mtu = 0;
	u32 flow_mtu = 0;

	if (out_dev)
		mtu = READ_ONCE(out_dev->mtu);
	if (flow)
		flow_mtu = READ_ONCE(flow->mtu);
	if (flow_mtu && (!mtu || flow_mtu < mtu))
		mtu = flow_mtu;
	return mtu;
}

static bool trustix_tixt_tx_route_gso_virtio_net(
				const struct net_device *out_dev)
{
	const struct device *parent;
	const struct device_driver *driver;

	if (!out_dev)
		return false;
	parent = READ_ONCE(out_dev->dev.parent);
	if (!parent)
		return false;
	driver = READ_ONCE(parent->driver);
	return driver && driver->name && !strcmp(driver->name, "virtio_net");
}

static bool trustix_tixt_tx_route_gso_outer_gso_capable(
				const struct trustix_tixt_tx_route_gso_template *tmpl,
				bool record_block)
{
	struct net_device *out_dev;
	netdev_features_t features;

	if (!tmpl || !tmpl->out_dev)
		return false;
	out_dev = tmpl->out_dev;
	if (!READ_ONCE(trustix_route_tcp_gso_async_stream_allow_virtio_net) &&
	    trustix_tixt_tx_route_gso_virtio_net(out_dev)) {
		if (record_block) {
			trustix_route_tcp_gso_async_stream_outer_gso_blocked++;
			trustix_route_tcp_gso_async_stream_outer_gso_virtio_blocked++;
		}
		return false;
	}
	features = READ_ONCE(out_dev->features);
	if (!(features & NETIF_F_TSO) || !(features & NETIF_F_HW_CSUM)) {
		if (record_block)
			trustix_route_tcp_gso_async_stream_outer_gso_blocked++;
		return false;
	}
	return true;
}

static bool trustix_tixt_tx_route_gso_outer_gso_ready(
				const struct trustix_tixt_tx_route_gso_template *tmpl,
				bool record_block)
{
	if (!tmpl || !tmpl->partial_csum || !tmpl->stream_outer_gso)
		return false;
	return trustix_tixt_tx_route_gso_outer_gso_capable(tmpl,
							   record_block);
}

static void trustix_tixt_tx_route_gso_stream_record(int ret, int stage,
						    struct sk_buff *skb,
						    unsigned int frames)
{
	struct skb_shared_info *shinfo;

	WRITE_ONCE(trustix_route_tcp_gso_async_stream_last_software_ret, ret);
	WRITE_ONCE(trustix_route_tcp_gso_async_stream_last_software_stage,
		   stage);
	if (!skb)
		return;
	shinfo = skb_shinfo(skb);
	WRITE_ONCE(trustix_route_tcp_gso_async_stream_last_len, skb->len);
	WRITE_ONCE(trustix_route_tcp_gso_async_stream_last_headlen,
		   skb_headlen(skb));
	WRITE_ONCE(trustix_route_tcp_gso_async_stream_last_gso_size,
		   shinfo->gso_size);
	WRITE_ONCE(trustix_route_tcp_gso_async_stream_last_gso_segs, frames);
	WRITE_ONCE(trustix_route_tcp_gso_async_stream_last_gso_type,
		   shinfo->gso_type);
	WRITE_ONCE(trustix_route_tcp_gso_async_stream_last_offsets,
		   ((u32)(ETH_HLEN + sizeof(struct iphdr)) << 16) |
		   (u32)(ETH_HLEN + sizeof(struct iphdr) +
			 sizeof(struct tcphdr)));
}

static void
trustix_tixt_tx_route_gso_sync_stream_record(int ret, int stage,
					     struct sk_buff *skb,
					     unsigned int frames,
					     unsigned int batches)
{
	struct skb_shared_info *shinfo;

	WRITE_ONCE(trustix_route_tcp_gso_sync_stream_last_ret, ret);
	WRITE_ONCE(trustix_route_tcp_gso_sync_stream_last_stage, stage);
	WRITE_ONCE(trustix_route_tcp_gso_sync_stream_last_batch_count,
		   batches);
	WRITE_ONCE(trustix_route_tcp_gso_sync_stream_last_batch_frames,
		   frames);
	if (!skb)
		return;
	shinfo = skb_shinfo(skb);
	WRITE_ONCE(trustix_route_tcp_gso_sync_stream_last_len, skb->len);
	WRITE_ONCE(trustix_route_tcp_gso_sync_stream_last_gso_size,
		   shinfo->gso_size);
	WRITE_ONCE(trustix_route_tcp_gso_sync_stream_last_gso_segs,
		   shinfo->gso_segs);
	WRITE_ONCE(trustix_route_tcp_gso_sync_stream_last_gso_type,
		   shinfo->gso_type);
}

static __always_inline void
trustix_tixt_tx_write_route_gso_stream_tixt(
				u8 *dst,
				const struct trustix_tixt_tx_route_gso_template *tmpl,
				u32 inner_len, u64 sequence)
{
	const u32 tixt_offset = ETH_HLEN + sizeof(struct iphdr) +
				sizeof(struct tcphdr);

	memcpy(dst, tmpl->base + tixt_offset, TRUSTIX_TIXT_HEADER_LEN);
	put_unaligned_be64(0, dst + 16);
	put_unaligned_be64(sequence, dst + 24);
	put_unaligned_be32(inner_len, dst + 32);
	put_unaligned_be16(0, dst + 36);
	put_unaligned_be16(0, dst + 38);
}

static __always_inline void
trustix_kudp_tx_write_secure_route_gso_header(
				u8 *dst,
				const struct trustix_tixt_tx_route_gso_template *tmpl,
				u32 secure_payload_len, u64 sequence)
{
	u32 udp_len = sizeof(struct udphdr) + TRUSTIX_KUDP_HEADER_LEN +
		      secure_payload_len;
	u32 l3_len = sizeof(struct iphdr) + udp_len;
	u32 sum;
	u16 check;

	memcpy(dst, tmpl->base, TRUSTIX_KUDP_UDP_OUTER_HEADER_LEN);
	put_unaligned_be16(l3_len, dst + ETH_HLEN + 2);
	put_unaligned_be16(0, dst + ETH_HLEN + 10);
	sum = tmpl->ip_check_base;
	sum += l3_len;
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	check = ~sum;
	if (!check)
		check = 0xffff;
	put_unaligned_be16(check, dst + ETH_HLEN + 10);
	put_unaligned_be64(sequence, dst + ETH_HLEN + sizeof(struct iphdr) +
			   sizeof(struct udphdr) + 16);
	put_unaligned_be32(secure_payload_len, dst + ETH_HLEN +
			   sizeof(struct iphdr) + sizeof(struct udphdr) + 24);
	put_unaligned_be16(udp_len, dst + ETH_HLEN + sizeof(struct iphdr) +
			   4);
}

static __always_inline void
trustix_tixt_tx_prepare_secure_nonce(u8 *nonce, const u8 *iv, u64 sequence)
{
	unsigned int i;

	for (i = 0; i < 12; i++)
		nonce[i] = iv[i];
	nonce[4] = (u8)(sequence >> 56);
	nonce[5] = (u8)(sequence >> 48);
	nonce[6] = (u8)(sequence >> 40);
	nonce[7] = (u8)(sequence >> 32);
	nonce[8] = (u8)(sequence >> 24);
	nonce[9] = (u8)(sequence >> 16);
	nonce[10] = (u8)(sequence >> 8);
	nonce[11] = (u8)sequence;
}

static __always_inline void
trustix_tixt_tx_write_secure_header(u8 *dst, u16 suite, u64 epoch,
				    u64 sequence)
{
	dst[0] = 'T';
	dst[1] = 'I';
	dst[2] = 'X';
	dst[3] = 'D';
	dst[4] = 1;
	dst[5] = (u8)suite;
	dst[6] = 0;
	dst[7] = 0;
	put_unaligned_be64(epoch, dst + 8);
	put_unaligned_be64(sequence, dst + 16);
}

static u32 trustix_ipv4_header_check20_base(const u8 *iph)
{
	u32 sum = 0;
	int i;

	for (i = 0; i < (int)sizeof(struct iphdr); i += 2)
		sum += get_unaligned_be16(iph + i);
	return sum;
}

static __sum16 trustix_ipv4_header_check20_from_base(u32 sum, u32 tot_len)
{
	u16 check;

	sum += tot_len;
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	check = ~((u16)sum);
	if (!check)
		check = 0xffff;
	return htons(check);
}

static __sum16 trustix_ipv4_header_check20(const u8 *iph)
{
	return trustix_ipv4_header_check20_from_base(
		trustix_ipv4_header_check20_base(iph), 0);
}

static struct sk_buff *
trustix_tixt_tx_build_route_gso_stream_skb(
				const struct trustix_tixt_tx_route_gso_template *tmpl,
				const struct trustix_tixt_tx_route_gso_stream_frame *frames,
				unsigned int frame_count, u32 stream_payload_len,
				u64 outer_sequence, bool allow_outer_gso,
				gfp_t gfp_mask, int *ret_out)
{
	const u32 outer_header_len = ETH_HLEN + sizeof(struct iphdr) +
				     sizeof(struct tcphdr);
	struct sk_buff *skb;
	struct tcphdr *tcph;
	struct iphdr *iph;
	u32 total_len;
	u32 tcp_len;
	u32 l3_len;
	u32 mtu;
	u32 outer_gso_size = 0;
	u32 sum;
	u16 check;
	bool outer_gso = false;
	u8 *data;
	u8 *pos;
	unsigned int i;
	int ret;

	if (!tmpl || !tmpl->out_dev || !frames || !frame_count) {
		ret = -EINVAL;
		goto out_ret;
	}
	if (check_add_overflow((u32)sizeof(struct tcphdr),
			       stream_payload_len, &tcp_len) ||
	    check_add_overflow((u32)sizeof(struct iphdr), tcp_len, &l3_len) ||
	    check_add_overflow((u32)ETH_HLEN, l3_len, &total_len)) {
		ret = -EOVERFLOW;
		goto out_ret;
	}
	mtu = trustix_tixt_tx_route_gso_stream_mtu(tmpl);
	if (!mtu) {
		ret = -EMSGSIZE;
		goto out_ret;
	}
	if (l3_len > 0xffff) {
		ret = -EMSGSIZE;
		goto out_ret;
	}
	if (allow_outer_gso && frame_count > 1 &&
	    trustix_tixt_tx_route_gso_outer_gso_ready(tmpl, false)) {
		u32 frame_len;

		if (check_add_overflow((u32)TRUSTIX_TIXT_HEADER_LEN,
				       frames[0].inner_len, &outer_gso_size)) {
			ret = -EOVERFLOW;
			goto out_ret;
		}
		if (sizeof(struct iphdr) + sizeof(struct tcphdr) +
			    outer_gso_size > mtu) {
			ret = -EMSGSIZE;
			goto out_ret;
		}
		for (i = 0; i < frame_count; i++) {
			if (check_add_overflow((u32)TRUSTIX_TIXT_HEADER_LEN,
					       frames[i].inner_len,
					       &frame_len)) {
				ret = -EOVERFLOW;
				goto out_ret;
			}
			if (i + 1 < frame_count && frame_len != outer_gso_size) {
				ret = -EOPNOTSUPP;
				goto out_ret;
			}
			if (i + 1 == frame_count && frame_len > outer_gso_size) {
				ret = -EOPNOTSUPP;
				goto out_ret;
			}
		}
		outer_gso = true;
	} else if (l3_len > mtu) {
		if (allow_outer_gso ||
		    READ_ONCE(trustix_route_tcp_gso_async_stream_outer_gso))
			trustix_route_tcp_gso_async_stream_outer_gso_fallbacks++;
		ret = -EMSGSIZE;
		goto out_ret;
	}

	skb = alloc_skb(total_len + NET_SKB_PAD, gfp_mask);
	if (!skb) {
		ret = -ENOMEM;
		goto out_ret;
	}
	skb_reserve(skb, NET_SKB_PAD);
	data = skb_put(skb, total_len);
	memcpy(data, tmpl->base, outer_header_len);
	pos = data + outer_header_len;

	iph = (struct iphdr *)(data + ETH_HLEN);
	iph->tot_len = htons(l3_len);
	sum = tmpl->ip_check_base;
	sum += l3_len;
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	check = ~sum;
	if (!check)
		check = 0xffff;
	iph->check = htons(check);

	tcph = (struct tcphdr *)(data + ETH_HLEN + sizeof(*iph));
	tcph->seq = htonl((u32)outer_sequence);
	tcph->check = 0;

	for (i = 0; i < frame_count; i++) {
		trustix_tixt_tx_write_route_gso_stream_tixt(
			pos, tmpl, frames[i].inner_len, frames[i].sequence);
		pos += TRUSTIX_TIXT_HEADER_LEN;
		ret = skb_copy_bits(frames[i].seg, ETH_HLEN, pos,
				    frames[i].inner_len);
		if (ret) {
			kfree_skb(skb);
			goto out_ret;
		}
		pos += frames[i].inner_len;
	}
	if (pos != data + total_len) {
		kfree_skb(skb);
		ret = -EINVAL;
		goto out_ret;
	}

	skb->dev = tmpl->out_dev;
	skb->protocol = htons(ETH_P_IP);
	skb_reset_mac_header(skb);
	skb_set_network_header(skb, ETH_HLEN);
	skb_set_transport_header(skb, ETH_HLEN + sizeof(struct iphdr));
	skb->mac_len = ETH_HLEN;
	skb->encapsulation = 0;
	skb->csum = 0;
	skb->csum_level = 0;
	skb_gso_reset(skb);
	trustix_tixt_tx_route_gso_apply_tx_queue(skb, tmpl);
	if (outer_gso) {
		struct skb_shared_info *shinfo = skb_shinfo(skb);

		tcph->check = trustix_ipv4_l4_partial_check_from_ip_base(
			tmpl->ip_check_base, tcp_len);
		skb->ip_summed = CHECKSUM_PARTIAL;
		skb->csum_start = skb_transport_header(skb) - skb->head;
		skb->csum_offset = offsetof(struct tcphdr, check);
		shinfo->gso_size = outer_gso_size;
		shinfo->gso_segs = frame_count;
		shinfo->gso_type = SKB_GSO_TCPV4;
	} else if (tmpl->partial_csum) {
		tcph->check = trustix_ipv4_l4_partial_check_from_ip_base(
			tmpl->ip_check_base, tcp_len);
		skb->ip_summed = CHECKSUM_PARTIAL;
		skb->csum_start = skb_transport_header(skb) - skb->head;
		skb->csum_offset = offsetof(struct tcphdr, check);
	} else {
		tcph->check = csum_tcpudp_magic(
			tmpl->saddr, tmpl->daddr, tcp_len, IPPROTO_TCP,
			csum_partial(tcph, tcp_len, 0));
		skb->ip_summed = CHECKSUM_NONE;
	}
	ret = trustix_tixt_tx_sanitize_route_gso_xmit_skb(skb, tmpl->out_dev);
	if (ret) {
		kfree_skb(skb);
		goto out_ret;
	}
	if (ret_out)
		*ret_out = 0;
	return skb;

out_ret:
	if (ret_out)
		*ret_out = ret;
	return ERR_PTR(ret);
}

static int
trustix_tixt_tx_copy_route_gso_stream_frag_fast(
				struct sk_buff *src, u32 src_offset,
				u8 *dst, u32 len, bool csum,
				__wsum *sum_out)
{
	const struct skb_shared_info *shinfo;
	const skb_frag_t *frag;
	u32 frag_start;
	u32 frag_end;
	u32 page_offset;
	u32 copied;
	u32 page_in_frag;
	u32 page_in_frag_offset;
	u32 copy_len;
	u32 first_page_room;
	void *addr;
	__wsum chunk_sum;
	__wsum sum = 0;
	unsigned int i;

	if (!src || !dst || !len || (csum && !sum_out))
		return -EINVAL;
	if (src_offset < skb_headlen(src))
		return -ENOENT;
	shinfo = skb_shinfo(src);
	frag_start = skb_headlen(src);
	for (i = 0; i < shinfo->nr_frags; i++) {
		frag = &shinfo->frags[i];
		if (check_add_overflow(frag_start, (u32)skb_frag_size(frag),
				       &frag_end))
			return -EOVERFLOW;
		if (src_offset >= frag_end) {
			frag_start = frag_end;
			continue;
		}
		if (src_offset < frag_start)
			return -ENOENT;
		if (len > frag_end - src_offset) {
			if (trustix_route_tcp_gso_async_hot_stats_enabled())
				trustix_route_tcp_gso_async_stream_direct_frag_fast_copy_misses++;
			return -ENOENT;
		}
		page_offset = skb_frag_off(frag) + (src_offset - frag_start);
		first_page_room = PAGE_SIZE - (page_offset & (PAGE_SIZE - 1));
		if (len > first_page_room &&
		    !READ_ONCE(trustix_route_tcp_gso_async_stream_direct_build_frag_fast_copy_cross_page)) {
			if (trustix_route_tcp_gso_async_hot_stats_enabled())
				trustix_route_tcp_gso_async_stream_direct_frag_fast_copy_cross_page++;
			return -ENOENT;
		}
		copied = 0;
		while (copied < len) {
			page_in_frag = page_offset + copied;
			page_in_frag_offset = page_in_frag & (PAGE_SIZE - 1);
			copy_len = min_t(u32, len - copied,
					 PAGE_SIZE - page_in_frag_offset);
			addr = kmap_local_page(skb_frag_page(frag) +
					       (page_in_frag >> PAGE_SHIFT));
			if (csum) {
				chunk_sum = csum_partial_copy_nocheck(
					(u8 *)addr + page_in_frag_offset,
					dst + copied, copy_len);
				sum = csum_block_add(sum, chunk_sum, copied);
			} else {
				memcpy(dst + copied,
				       (u8 *)addr + page_in_frag_offset,
				       copy_len);
			}
			kunmap_local(addr);
			copied += copy_len;
		}
		if (csum)
			*sum_out = sum;
		if (trustix_route_tcp_gso_async_hot_stats_enabled()) {
			if (len > first_page_room)
				trustix_route_tcp_gso_async_stream_direct_frag_fast_copy_cross_page_hits++;
			trustix_route_tcp_gso_async_stream_direct_frag_fast_copy_hits++;
		}
		return 0;
	}
	if (trustix_route_tcp_gso_async_hot_stats_enabled())
		trustix_route_tcp_gso_async_stream_direct_frag_fast_copy_misses++;
	return -ENOENT;
}

static bool
trustix_tixt_tx_route_gso_stream_direct_sanitize_tcp_flags(
				const struct trustix_tixt_tx_route_gso_async_work *item,
				const struct trustix_tixt_tx_route_gso_stream_direct_frame *frame,
				struct tcphdr *tcph);

static int
trustix_tixt_tx_copy_route_gso_stream_direct_plain_inner(
				struct trustix_tixt_tx_route_gso_async_work *item,
				u8 *dst,
				const struct trustix_tixt_tx_route_gso_stream_direct_frame *frame,
				bool fix_inner_csum)
{
	struct sk_buff *src;
	u32 tcp_header_len;
	u32 inner_header_len;
	struct tcphdr *tcph;
	struct iphdr *iph;
	u32 tcp_len;
	u32 payload_src;
	u8 *payload_dst;
	__wsum header_sum;
	__wsum payload_sum = 0;
	__wsum sum;
	bool flags_changed;
	int ret;

	if (!item || !item->skb || !dst || !frame ||
	    !item->inner_header_ready ||
	    item->tcp_header_len < sizeof(struct tcphdr))
		return -EINVAL;
	src = item->skb;
	tcp_header_len = item->tcp_header_len;
	inner_header_len = item->inner_header_len;
	if (!inner_header_len ||
	    inner_header_len > sizeof(item->inner_header) ||
	    frame->inner_len != inner_header_len + frame->payload_len)
		return -EINVAL;
	if (check_add_overflow((u32)ETH_HLEN + inner_header_len,
			       frame->payload_offset, &payload_src) ||
	    check_add_overflow(payload_src, frame->payload_len, &tcp_len) ||
	    tcp_len > src->len)
		return -EMSGSIZE;
	memcpy(dst, item->inner_header, inner_header_len);
	payload_dst = dst + inner_header_len;
	if (READ_ONCE(trustix_route_tcp_gso_async_stream_direct_build_fast_copy) &&
	    payload_src <= skb_headlen(src) &&
	    frame->payload_len <= skb_headlen(src) - payload_src) {
		memcpy(payload_dst, src->data + payload_src,
		       frame->payload_len);
		if (fix_inner_csum)
			payload_sum = csum_partial(payload_dst,
						   frame->payload_len, 0);
		if (trustix_route_tcp_gso_async_hot_stats_enabled())
			trustix_route_tcp_gso_async_stream_direct_fast_copy_hits++;
	} else {
		if (trustix_route_tcp_gso_async_hot_stats_enabled())
			trustix_route_tcp_gso_async_stream_direct_fast_copy_fallbacks++;
		if (READ_ONCE(trustix_route_tcp_gso_async_stream_direct_build_frag_fast_copy) &&
		    trustix_tixt_tx_copy_route_gso_stream_frag_fast(
			    src, payload_src, payload_dst, frame->payload_len,
			    fix_inner_csum, &payload_sum) == 0)
			goto payload_ready;
		if (trustix_route_tcp_gso_async_hot_stats_enabled())
			trustix_route_tcp_gso_async_stream_direct_frag_fast_copy_fallbacks++;
		if (fix_inner_csum)
			payload_sum = skb_copy_and_csum_bits(src, payload_src,
							     payload_dst,
							     frame->payload_len);
		else {
			ret = skb_copy_bits(src, payload_src, payload_dst,
					    frame->payload_len);
			if (ret)
				return ret;
		}
	}

payload_ready:
	iph = (struct iphdr *)dst;
	tcph = (struct tcphdr *)(dst + sizeof(*iph));
	iph->tot_len = htons(frame->inner_len);
	iph->check = trustix_ipv4_header_check20_from_base(
		item->inner_ip_check_base, frame->inner_len);
	tcph->seq = htonl(item->inner_tcp_seq_base + frame->payload_offset);
	flags_changed =
		trustix_tixt_tx_route_gso_stream_direct_sanitize_tcp_flags(
			item, frame, tcph);
	if (flags_changed && !fix_inner_csum)
		return -EOPNOTSUPP;
	if (fix_inner_csum) {
		tcp_len = tcp_header_len + frame->payload_len;
		tcph->check = 0;
		header_sum = csum_partial(tcph, tcp_header_len, 0);
		sum = csum_block_add(header_sum, payload_sum,
				     tcp_header_len);
		tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
						tcp_len, IPPROTO_TCP, sum);
	} else {
		tcph->check = 0;
	}
	return 0;
}

static bool
trustix_tixt_tx_route_gso_stream_direct_sanitize_tcp_flags(
				const struct trustix_tixt_tx_route_gso_async_work *item,
				const struct trustix_tixt_tx_route_gso_stream_direct_frame *frame,
				struct tcphdr *tcph)
{
	u32 payload_end;
	bool changed = false;
	bool first;
	bool last;

	if (!item || !frame || !tcph ||
	    check_add_overflow(frame->payload_offset, frame->payload_len,
			       &payload_end))
		return false;

	first = frame->payload_offset == 0;
	last = payload_end >= item->payload_len;

	if (!first && tcph->cwr) {
		tcph->cwr = 0;
		changed = true;
	}
	if (!last) {
		if (tcph->psh) {
			tcph->psh = 0;
			changed = true;
		}
		if (tcph->fin) {
			tcph->fin = 0;
			changed = true;
		}
	}
	return changed;
}

static int
trustix_tixt_tx_copy_route_gso_stream_direct_secure_inner(
				struct trustix_tixt_tx_route_gso_async_work *item,
				u8 *dst,
				const struct trustix_tixt_tx_route_gso_stream_direct_frame *frame,
				bool fix_inner_csum,
				struct trustix_aead_direct_batch_op *op)
{
	struct trustix_tixt_tx_route_gso_stream_direct_frame plain_frame;
	u8 *plain;
	u32 plain_inner_len;
	int ret;

	if (!item || !dst || !frame || !op || !item->tmpl.secure)
		return -EINVAL;
	plain_inner_len = frame->plain_inner_len;
	if (!plain_inner_len ||
	    frame->inner_len != plain_inner_len + TRUSTIX_TIXT_TX_SECURE_PAYLOAD_OVERHEAD)
		return -EINVAL;
	trustix_tixt_tx_write_secure_header(dst, item->secure_suite,
					    item->secure_epoch,
					    frame->sequence);
	plain = dst + TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN;
	plain_frame = *frame;
	plain_frame.inner_len = plain_inner_len;
	ret = trustix_tixt_tx_copy_route_gso_stream_direct_plain_inner(
		item, plain, &plain_frame, fix_inner_csum);
	if (ret)
		return ret;
	trustix_tixt_tx_prepare_secure_nonce(op->nonce, item->secure_iv,
					     frame->sequence);
	op->src = plain;
	op->dst = plain;
	op->plain_len = plain_inner_len;
	return 0;
}

static int
trustix_tixt_tx_copy_route_gso_stream_direct_inner(
				struct trustix_tixt_tx_route_gso_async_work *item,
				u8 *dst,
				const struct trustix_tixt_tx_route_gso_stream_direct_frame *frame,
				bool fix_inner_csum,
				struct trustix_aead_direct_batch_op *op)
{
	if (item && item->tmpl.secure)
		return trustix_tixt_tx_copy_route_gso_stream_direct_secure_inner(
			item, dst, frame, fix_inner_csum, op);
	return trustix_tixt_tx_copy_route_gso_stream_direct_plain_inner(
		item, dst, frame, fix_inner_csum);
}

static int
trustix_tixt_tx_copy_route_gso_stream_direct_ref_inner(
				const struct trustix_tixt_tx_route_gso_stream_direct_ref *ref,
				u8 *dst, bool fix_inner_csum,
				struct trustix_aead_direct_batch_op *op)
{
	if (!ref)
		return -EINVAL;
	return trustix_tixt_tx_copy_route_gso_stream_direct_inner(
		ref->item, dst, &ref->frame, fix_inner_csum, op);
}

struct trustix_tixt_tx_route_gso_nonlinear_builder {
	struct page *pages[MAX_SKB_FRAGS];
	u32 lens[MAX_SKB_FRAGS];
	unsigned int nr_frags;
	u32 len;
};

static void
trustix_tixt_tx_route_gso_nonlinear_builder_free(
				struct trustix_tixt_tx_route_gso_nonlinear_builder *builder)
{
	unsigned int i;

	if (!builder)
		return;
	for (i = 0; i < builder->nr_frags; i++) {
		if (builder->pages[i])
			__free_page(builder->pages[i]);
		builder->pages[i] = NULL;
		builder->lens[i] = 0;
	}
	builder->nr_frags = 0;
	builder->len = 0;
}

static int
trustix_tixt_tx_route_gso_nonlinear_builder_page(
				struct trustix_tixt_tx_route_gso_nonlinear_builder *builder)
{
	struct page *page;
	unsigned int index;

	if (!builder)
		return -EINVAL;
	if (builder->nr_frags &&
	    builder->lens[builder->nr_frags - 1] < PAGE_SIZE)
		return 0;
	if (builder->nr_frags >= MAX_SKB_FRAGS)
		return -EMSGSIZE;
	page = alloc_page(GFP_KERNEL | __GFP_NOWARN);
	if (!page)
		return -ENOMEM;
	index = builder->nr_frags++;
	builder->pages[index] = page;
	builder->lens[index] = 0;
	return 0;
}

static int
trustix_tixt_tx_route_gso_nonlinear_builder_new_page(
				struct trustix_tixt_tx_route_gso_nonlinear_builder *builder)
{
	struct page *page;
	unsigned int index;

	if (!builder)
		return -EINVAL;
	if (builder->nr_frags >= MAX_SKB_FRAGS)
		return -EMSGSIZE;
	page = alloc_page(GFP_KERNEL | __GFP_NOWARN);
	if (!page)
		return -ENOMEM;
	index = builder->nr_frags++;
	builder->pages[index] = page;
	builder->lens[index] = 0;
	return 0;
}

static int
trustix_tixt_tx_route_gso_nonlinear_reserve_contiguous(
				struct trustix_tixt_tx_route_gso_nonlinear_builder *builder,
				u32 len, u8 **ptr)
{
	unsigned int index;
	u32 offset;
	void *addr;
	int ret;

	if (!builder || !ptr || !len)
		return -EINVAL;
	if (len > PAGE_SIZE)
		return -EMSGSIZE;
	if (!builder->nr_frags ||
	    PAGE_SIZE - builder->lens[builder->nr_frags - 1] < len) {
		ret = trustix_tixt_tx_route_gso_nonlinear_builder_new_page(
			builder);
		if (ret)
			return ret;
	}
	index = builder->nr_frags - 1;
	offset = builder->lens[index];
	addr = page_address(builder->pages[index]);
	if (!addr)
		return -EOPNOTSUPP;
	*ptr = (u8 *)addr + offset;
	return 0;
}

static int
trustix_tixt_tx_route_gso_nonlinear_commit_contiguous(
				struct trustix_tixt_tx_route_gso_nonlinear_builder *builder,
				u32 len)
{
	unsigned int index;

	if (!builder || !builder->nr_frags || !len)
		return -EINVAL;
	index = builder->nr_frags - 1;
	if (len > PAGE_SIZE - builder->lens[index])
		return -EMSGSIZE;
	builder->lens[index] += len;
	builder->len += len;
	return 0;
}

static int
trustix_tixt_tx_route_gso_nonlinear_append(
				struct trustix_tixt_tx_route_gso_nonlinear_builder *builder,
				const u8 *src, u32 len)
{
	unsigned int index;
	u32 copy_len;
	u32 offset;
	void *addr;
	int ret;

	if (!builder || (!src && len))
		return -EINVAL;
	while (len) {
		ret = trustix_tixt_tx_route_gso_nonlinear_builder_page(
			builder);
		if (ret)
			return ret;
		index = builder->nr_frags - 1;
		offset = builder->lens[index];
		copy_len = min_t(u32, len, PAGE_SIZE - offset);
		addr = kmap_local_page(builder->pages[index]);
		memcpy((u8 *)addr + offset, src, copy_len);
		kunmap_local(addr);
		builder->lens[index] += copy_len;
		builder->len += copy_len;
		src += copy_len;
		len -= copy_len;
	}
	return 0;
}

static int
trustix_tixt_tx_route_gso_nonlinear_append_skb_payload(
				struct trustix_tixt_tx_route_gso_nonlinear_builder *builder,
				struct sk_buff *src, u32 src_offset, u32 len,
				bool csum, __wsum *sum_out)
{
	unsigned int index;
	u32 copied = 0;
	u32 copy_len;
	u32 offset;
	void *addr;
	__wsum chunk_sum;
	__wsum sum = 0;
	int ret;

	if (!builder || !src || (csum && !sum_out))
		return -EINVAL;
	while (copied < len) {
		ret = trustix_tixt_tx_route_gso_nonlinear_builder_page(
			builder);
		if (ret)
			return ret;
		index = builder->nr_frags - 1;
		offset = builder->lens[index];
		copy_len = min_t(u32, len - copied, PAGE_SIZE - offset);
		addr = kmap_local_page(builder->pages[index]);
		if (csum) {
			chunk_sum = skb_copy_and_csum_bits(
				src, src_offset + copied,
				(u8 *)addr + offset, copy_len);
			sum = csum_block_add(sum, chunk_sum, copied);
			ret = 0;
		} else {
			ret = skb_copy_bits(src, src_offset + copied,
					    (u8 *)addr + offset, copy_len);
		}
		kunmap_local(addr);
		if (ret)
			return ret;
		builder->lens[index] += copy_len;
		builder->len += copy_len;
		copied += copy_len;
	}
	if (csum)
		*sum_out = sum;
	return 0;
}

static int
trustix_tixt_tx_route_gso_nonlinear_patch(
				struct trustix_tixt_tx_route_gso_nonlinear_builder *builder,
				u32 offset, const void *src, u32 len)
{
	unsigned int i;
	const u8 *from = src;
	u32 frag_offset;
	u32 copy_len;
	void *addr;

	if (!builder || !src || !len)
		return -EINVAL;
	frag_offset = offset;
	for (i = 0; i < builder->nr_frags; i++) {
		if (frag_offset >= builder->lens[i]) {
			frag_offset -= builder->lens[i];
			continue;
		}
		copy_len = min_t(u32, len, builder->lens[i] - frag_offset);
		if (!copy_len)
			return -EMSGSIZE;
		addr = kmap_local_page(builder->pages[i]);
		memcpy((u8 *)addr + frag_offset, from, copy_len);
		kunmap_local(addr);
		from += copy_len;
		len -= copy_len;
		frag_offset = 0;
		if (!len)
			return 0;
	}
	return -EMSGSIZE;
}

static int
trustix_tixt_tx_route_gso_nonlinear_attach(
				struct trustix_tixt_tx_route_gso_nonlinear_builder *builder,
				struct sk_buff *skb)
{
	unsigned int i;

	if (!builder || !skb)
		return -EINVAL;
	for (i = 0; i < builder->nr_frags; i++) {
		if (!builder->pages[i] || !builder->lens[i])
			return -EINVAL;
		skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags,
				builder->pages[i], 0, builder->lens[i],
				PAGE_SIZE);
		builder->pages[i] = NULL;
		trustix_route_tcp_gso_async_stream_nonlinear_direct_frags++;
		trustix_route_tcp_gso_async_stream_nonlinear_direct_bytes +=
			builder->lens[i];
		builder->lens[i] = 0;
	}
	builder->nr_frags = 0;
	builder->len = 0;
	return 0;
}

static int
trustix_tixt_tx_append_route_gso_stream_direct_nonlinear(
				struct trustix_tixt_tx_route_gso_async_work *item,
				struct trustix_tixt_tx_route_gso_nonlinear_builder *builder,
				const struct trustix_tixt_tx_route_gso_template *tmpl,
				const struct trustix_tixt_tx_route_gso_stream_direct_frame *frame,
				bool fix_inner_csum)
{
	struct sk_buff *src;
	u32 tcp_header_len;
	u32 inner_header_len;
	u8 header[TRUSTIX_TIXT_HEADER_LEN + sizeof(struct iphdr) + 60];
	u32 tcp_check_offset;
	u32 payload_src;
	u32 payload_end;
	struct tcphdr *tcph;
	struct iphdr *iph;
	__wsum header_sum;
	__wsum payload_sum = 0;
	__wsum sum;
	u32 stream_offset;
	u32 tcp_len;
	bool flags_changed;
	int ret;

	if (!item || !item->skb || !builder || !tmpl || !frame ||
	    !item->inner_header_ready ||
	    item->tcp_header_len < sizeof(struct tcphdr) ||
	    item->tcp_header_len > 60)
		return -EINVAL;
	src = item->skb;
	tcp_header_len = item->tcp_header_len;
	inner_header_len = item->inner_header_len;
	if (!inner_header_len ||
	    inner_header_len > sizeof(item->inner_header) ||
	    frame->inner_len != inner_header_len + frame->payload_len ||
	    inner_header_len > sizeof(header) - TRUSTIX_TIXT_HEADER_LEN)
		return -EINVAL;
	if (check_add_overflow((u32)ETH_HLEN + inner_header_len,
			       frame->payload_offset, &payload_src) ||
	    check_add_overflow(payload_src, frame->payload_len,
			       &payload_end) ||
	    payload_end > src->len)
		return -EMSGSIZE;

	trustix_tixt_tx_write_route_gso_stream_tixt(
		header, tmpl, frame->inner_len, frame->sequence);
	memcpy(header + TRUSTIX_TIXT_HEADER_LEN, item->inner_header,
	       inner_header_len);

	iph = (struct iphdr *)(header + TRUSTIX_TIXT_HEADER_LEN);
	tcph = (struct tcphdr *)((u8 *)iph + sizeof(*iph));
	iph->tot_len = htons(frame->inner_len);
	iph->check = trustix_ipv4_header_check20_from_base(
		item->inner_ip_check_base, frame->inner_len);
	tcph->seq = htonl(item->inner_tcp_seq_base + frame->payload_offset);
	flags_changed =
		trustix_tixt_tx_route_gso_stream_direct_sanitize_tcp_flags(
			item, frame, tcph);
	if (flags_changed && !fix_inner_csum)
		return -EOPNOTSUPP;
	tcph->check = 0;
	if (fix_inner_csum)
		header_sum = csum_partial(tcph, tcp_header_len, 0);

	stream_offset = builder->len;
	ret = trustix_tixt_tx_route_gso_nonlinear_append(
		builder, header, TRUSTIX_TIXT_HEADER_LEN + inner_header_len);
	if (ret)
		return ret;
	ret = trustix_tixt_tx_route_gso_nonlinear_append_skb_payload(
		builder, src, payload_src, frame->payload_len,
		fix_inner_csum, &payload_sum);
	if (ret)
		return ret;
	if (fix_inner_csum) {
		tcp_len = tcp_header_len + frame->payload_len;
		sum = csum_block_add(header_sum, payload_sum,
				     tcp_header_len);
		tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
						tcp_len, IPPROTO_TCP, sum);
		tcp_check_offset = stream_offset + TRUSTIX_TIXT_HEADER_LEN +
				   sizeof(struct iphdr) +
				   offsetof(struct tcphdr, check);
		ret = trustix_tixt_tx_route_gso_nonlinear_patch(
			builder, tcp_check_offset, &tcph->check,
			sizeof(tcph->check));
		if (ret)
			return ret;
	}
	return 0;
}

static int
trustix_tixt_tx_append_route_gso_stream_direct_secure_nonlinear(
				struct trustix_tixt_tx_route_gso_async_work *item,
				struct trustix_tixt_tx_route_gso_nonlinear_builder *builder,
				const struct trustix_tixt_tx_route_gso_template *tmpl,
				const struct trustix_tixt_tx_route_gso_stream_direct_frame *frame,
				bool fix_inner_csum,
				struct trustix_aead_direct_batch_op *op)
{
	struct trustix_tixt_tx_route_gso_stream_direct_frame plain_frame;
	u8 *frame_buf;
	u8 *plain;
	u32 frame_len;
	u32 plain_inner_len;
	int ret;

	if (!item || !builder || !tmpl || !frame || !op || !tmpl->secure)
		return -EINVAL;
	plain_inner_len = frame->plain_inner_len;
	if (!plain_inner_len ||
	    frame->inner_len != plain_inner_len + TRUSTIX_TIXT_TX_SECURE_PAYLOAD_OVERHEAD)
		return -EINVAL;
	if (check_add_overflow((u32)TRUSTIX_TIXT_HEADER_LEN,
			       frame->inner_len, &frame_len))
		return -EOVERFLOW;
	ret = trustix_tixt_tx_route_gso_nonlinear_reserve_contiguous(
		builder, frame_len, &frame_buf);
	if (ret)
		return ret;

	trustix_tixt_tx_write_route_gso_stream_tixt(
		frame_buf, tmpl, frame->inner_len, frame->sequence);
	trustix_tixt_tx_write_secure_header(
		frame_buf + TRUSTIX_TIXT_HEADER_LEN, item->secure_suite,
		item->secure_epoch, frame->sequence);
	plain = frame_buf + TRUSTIX_TIXT_HEADER_LEN +
		TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN;

	plain_frame = *frame;
	plain_frame.inner_len = plain_inner_len;
	ret = trustix_tixt_tx_copy_route_gso_stream_direct_plain_inner(
		item, plain, &plain_frame, fix_inner_csum);
	if (ret)
		return ret;

	trustix_tixt_tx_prepare_secure_nonce(op->nonce, item->secure_iv,
					     frame->sequence);
	op->src = plain;
	op->dst = plain;
	op->plain_len = plain_inner_len;
	return trustix_tixt_tx_route_gso_nonlinear_commit_contiguous(
		builder, frame_len);
}

static int
trustix_tixt_tx_route_gso_direct_seal_ops(u32 slot_id,
					  const struct trustix_aead_direct_batch_op *ops,
					  u32 count)
{
	trustix_kernel_direct_seal_batch_fn seal_batch;
	u32 i;
	int ret;

	if (!ops || !count)
		return -EINVAL;
	seal_batch = trustix_kernel_direct_seal_batch_get();
	if (!seal_batch)
		return -EOPNOTSUPP;
	if (READ_ONCE(trustix_route_tcp_gso_async_secure_seal_batch)) {
		ret = seal_batch(slot_id, ops, count);
		goto out_put;
	}
	for (i = 0; i < count; i++) {
		ret = seal_batch(slot_id, &ops[i], 1);
		if (ret)
			goto out_put;
	}
	ret = 0;
out_put:
	symbol_put_addr(seal_batch);
	return ret;
}

static struct sk_buff *
trustix_tixt_tx_build_route_gso_stream_direct_nonlinear_skb(
				struct trustix_tixt_tx_route_gso_async_work *item,
				const struct trustix_tixt_tx_route_gso_stream_direct_frame *frames,
				unsigned int frame_count, u32 stream_payload_len,
				u64 outer_sequence, bool fix_inner_csum,
				int *ret_out)
{
	const u32 outer_header_len = ETH_HLEN + sizeof(struct iphdr) +
				     sizeof(struct tcphdr);
	struct trustix_tixt_tx_route_gso_nonlinear_builder builder = {};
	struct trustix_tixt_tx_route_gso_template *tmpl;
	struct skb_shared_info *shinfo;
	struct sk_buff *skb;
	struct tcphdr *tcph;
	struct iphdr *iph;
	u32 total_len;
	u32 tcp_len;
	u32 l3_len;
	u32 mtu;
	u32 outer_gso_size = 0;
	u32 sum;
	u16 check;
	u8 *data;
	struct trustix_aead_direct_batch_op *seal_ops = NULL;
	u32 seal_count = 0;
	unsigned int i;
	int ret;

	if (!item || !item->skb || !frames || !frame_count) {
		ret = -EINVAL;
		goto out_ret;
	}
	tmpl = &item->tmpl;
	if (!tmpl->out_dev) {
		ret = -EINVAL;
		goto out_ret;
	}
	if (!trustix_tixt_tx_route_gso_outer_gso_ready(tmpl, true) ||
	    frame_count <= 1) {
		ret = -EOPNOTSUPP;
		goto out_ret;
	}
	if (check_add_overflow((u32)sizeof(struct tcphdr),
			       stream_payload_len, &tcp_len) ||
	    check_add_overflow((u32)sizeof(struct iphdr), tcp_len, &l3_len) ||
	    check_add_overflow((u32)ETH_HLEN, l3_len, &total_len)) {
		ret = -EOVERFLOW;
		goto out_ret;
	}
	mtu = trustix_tixt_tx_route_gso_stream_mtu(tmpl);
	if (!mtu) {
		ret = -EMSGSIZE;
		goto out_ret;
	}
	if (l3_len > 0xffff) {
		ret = -EMSGSIZE;
		goto out_ret;
	}
	if (stream_payload_len > (u32)MAX_SKB_FRAGS * (u32)PAGE_SIZE) {
		ret = -EMSGSIZE;
		goto out_ret;
	}
	if (tmpl->secure)
		seal_ops = item->direct_seal_ops;
	if (check_add_overflow((u32)TRUSTIX_TIXT_HEADER_LEN,
			       frames[0].inner_len, &outer_gso_size)) {
		ret = -EOVERFLOW;
		goto out_free_seal_ops;
	}
	if (sizeof(struct iphdr) + sizeof(struct tcphdr) +
		    outer_gso_size > mtu) {
		ret = -EMSGSIZE;
		goto out_free_seal_ops;
	}
	for (i = 0; i < frame_count; i++) {
		u32 frame_len;

		if (check_add_overflow((u32)TRUSTIX_TIXT_HEADER_LEN,
				       frames[i].inner_len, &frame_len)) {
			ret = -EOVERFLOW;
			goto out_free_seal_ops;
		}
		if (i + 1 < frame_count && frame_len != outer_gso_size) {
			ret = -EOPNOTSUPP;
			goto out_free_seal_ops;
		}
		if (i + 1 == frame_count && frame_len > outer_gso_size) {
			ret = -EOPNOTSUPP;
			goto out_free_seal_ops;
		}
	}

	skb = alloc_skb(outer_header_len + NET_SKB_PAD, GFP_KERNEL);
	if (!skb) {
		ret = -ENOMEM;
		goto out_free_seal_ops;
	}
	skb_reserve(skb, NET_SKB_PAD);
	data = skb_put(skb, outer_header_len);
	memcpy(data, tmpl->base, outer_header_len);

	iph = (struct iphdr *)(data + ETH_HLEN);
	iph->tot_len = htons(l3_len);
	sum = tmpl->ip_check_base;
	sum += l3_len;
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	check = ~sum;
	if (!check)
		check = 0xffff;
	iph->check = htons(check);

	tcph = (struct tcphdr *)(data + ETH_HLEN + sizeof(*iph));
	tcph->seq = htonl((u32)outer_sequence);
	tcph->check = trustix_ipv4_l4_partial_check_from_ip_base(
		tmpl->ip_check_base, tcp_len);

	for (i = 0; i < frame_count; i++) {
		if (tmpl->secure) {
			ret = trustix_tixt_tx_append_route_gso_stream_direct_secure_nonlinear(
				item, &builder, tmpl, &frames[i],
				fix_inner_csum, &seal_ops[seal_count]);
			if (!ret)
				seal_count++;
		} else {
			ret = trustix_tixt_tx_append_route_gso_stream_direct_nonlinear(
				item, &builder, tmpl, &frames[i],
				fix_inner_csum);
		}
		if (ret) {
			kfree_skb(skb);
			goto out_free_builder;
		}
	}
	if (seal_ops) {
		ret = trustix_tixt_tx_route_gso_direct_seal_ops(
			item->secure_slot_id, seal_ops, seal_count);
		if (ret) {
			kfree_skb(skb);
			goto out_free_builder;
		}
	}
	if (builder.len != stream_payload_len) {
		kfree_skb(skb);
		ret = -EINVAL;
		goto out_free_builder;
	}
	ret = trustix_tixt_tx_route_gso_nonlinear_attach(&builder, skb);
	if (ret) {
		kfree_skb(skb);
		goto out_free_builder;
	}

	skb->dev = tmpl->out_dev;
	skb->protocol = htons(ETH_P_IP);
	skb_reset_mac_header(skb);
	skb_set_network_header(skb, ETH_HLEN);
	skb_set_transport_header(skb, ETH_HLEN + sizeof(struct iphdr));
	skb->mac_len = ETH_HLEN;
	skb->encapsulation = 0;
	skb->csum = 0;
	skb->csum_level = 0;
	skb_gso_reset(skb);
	trustix_tixt_tx_route_gso_apply_tx_queue(skb, tmpl);
	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum_start = skb_transport_header(skb) - skb->head;
	skb->csum_offset = offsetof(struct tcphdr, check);
	shinfo = skb_shinfo(skb);
	shinfo->gso_size = outer_gso_size;
	shinfo->gso_segs = frame_count;
	shinfo->gso_type = SKB_GSO_TCPV4;

	ret = trustix_tixt_tx_sanitize_route_gso_xmit_skb(skb, tmpl->out_dev);
	if (ret) {
		kfree_skb(skb);
		goto out_ret;
	}
	if (ret_out)
		*ret_out = 0;
	return skb;

out_free_builder:
	trustix_tixt_tx_route_gso_nonlinear_builder_free(&builder);
out_free_seal_ops:
out_ret:
	if (ret_out)
		*ret_out = ret;
	return ERR_PTR(ret);
}

static struct sk_buff *
trustix_tixt_tx_build_route_gso_stream_direct_skb(
				struct trustix_tixt_tx_route_gso_async_work *item,
				const struct trustix_tixt_tx_route_gso_stream_direct_frame *frames,
				unsigned int frame_count, u32 stream_payload_len,
				u64 outer_sequence, bool fix_inner_csum,
				int *ret_out)
{
	const u32 outer_header_len = ETH_HLEN + sizeof(struct iphdr) +
				     sizeof(struct tcphdr);
	struct trustix_tixt_tx_route_gso_template *tmpl;
	struct sk_buff *skb;
	struct tcphdr *tcph;
	struct iphdr *iph;
	u32 total_len;
	u32 tcp_len;
	u32 l3_len;
	u32 mtu;
	u32 outer_gso_size = 0;
	u32 sum;
	u16 check;
	bool outer_gso = false;
	u8 *data;
	u8 *pos;
	struct trustix_aead_direct_batch_op *seal_ops = NULL;
	u32 seal_count = 0;
	unsigned int i;
	int ret;

	if (!item || !item->skb || !frames || !frame_count) {
		ret = -EINVAL;
		goto out_ret;
	}
	tmpl = &item->tmpl;
	if (!tmpl->out_dev) {
		ret = -EINVAL;
		goto out_ret;
	}
	if (check_add_overflow((u32)sizeof(struct tcphdr),
			       stream_payload_len, &tcp_len) ||
	    check_add_overflow((u32)sizeof(struct iphdr), tcp_len, &l3_len) ||
	    check_add_overflow((u32)ETH_HLEN, l3_len, &total_len)) {
		ret = -EOVERFLOW;
		goto out_ret;
	}
	mtu = trustix_tixt_tx_route_gso_stream_mtu(tmpl);
	if (!mtu) {
		ret = -EMSGSIZE;
		goto out_ret;
	}
	if (l3_len > 0xffff) {
		ret = -EMSGSIZE;
		goto out_ret;
	}
	if (trustix_tixt_tx_route_gso_outer_gso_ready(tmpl, true) &&
	    frame_count > 1) {
		u32 frame_len;

		if (check_add_overflow((u32)TRUSTIX_TIXT_HEADER_LEN,
				       frames[0].inner_len, &outer_gso_size)) {
			ret = -EOVERFLOW;
			goto out_ret;
		}
		if (sizeof(struct iphdr) + sizeof(struct tcphdr) +
			    outer_gso_size > mtu) {
			ret = -EMSGSIZE;
			goto out_ret;
		}
		for (i = 0; i < frame_count; i++) {
			if (check_add_overflow((u32)TRUSTIX_TIXT_HEADER_LEN,
					       frames[i].inner_len,
					       &frame_len)) {
				ret = -EOVERFLOW;
				goto out_ret;
			}
			if (i + 1 < frame_count && frame_len != outer_gso_size) {
				ret = -EOPNOTSUPP;
				goto out_ret;
			}
			if (i + 1 == frame_count && frame_len > outer_gso_size) {
				ret = -EOPNOTSUPP;
				goto out_ret;
			}
		}
		outer_gso = true;
	} else if (l3_len > mtu) {
		if (READ_ONCE(trustix_route_tcp_gso_async_stream_outer_gso))
			trustix_route_tcp_gso_async_stream_outer_gso_fallbacks++;
		ret = -EMSGSIZE;
		goto out_ret;
	}

	skb = alloc_skb(total_len + NET_SKB_PAD, GFP_KERNEL);
	if (!skb) {
		ret = -ENOMEM;
		goto out_ret;
	}
	skb_reserve(skb, NET_SKB_PAD);
	data = skb_put(skb, total_len);
	memcpy(data, tmpl->base, outer_header_len);
	pos = data + outer_header_len;

	iph = (struct iphdr *)(data + ETH_HLEN);
	iph->tot_len = htons(l3_len);
	sum = tmpl->ip_check_base;
	sum += l3_len;
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	check = ~sum;
	if (!check)
		check = 0xffff;
	iph->check = htons(check);

	tcph = (struct tcphdr *)(data + ETH_HLEN + sizeof(*iph));
	tcph->seq = htonl((u32)outer_sequence);
	tcph->check = 0;

	if (tmpl->secure)
		seal_ops = item->direct_seal_ops;

	for (i = 0; i < frame_count; i++) {
		trustix_tixt_tx_write_route_gso_stream_tixt(
			pos, tmpl, frames[i].inner_len, frames[i].sequence);
		pos += TRUSTIX_TIXT_HEADER_LEN;
		ret = trustix_tixt_tx_copy_route_gso_stream_direct_inner(
			item, pos, &frames[i], fix_inner_csum,
			seal_ops ? &seal_ops[seal_count] : NULL);
		if (ret) {
			kfree_skb(skb);
			goto out_free_seal_ops;
		}
		if (seal_ops)
			seal_count++;
		pos += frames[i].inner_len;
	}
	if (seal_ops) {
		ret = trustix_tixt_tx_route_gso_direct_seal_ops(
			item->secure_slot_id, seal_ops, seal_count);
		if (ret) {
			kfree_skb(skb);
			goto out_free_seal_ops;
		}
	}
	if (pos != data + total_len) {
		kfree_skb(skb);
		ret = -EINVAL;
		goto out_free_seal_ops;
	}

	skb->dev = tmpl->out_dev;
	skb->protocol = htons(ETH_P_IP);
	skb_reset_mac_header(skb);
	skb_set_network_header(skb, ETH_HLEN);
	skb_set_transport_header(skb, ETH_HLEN + sizeof(struct iphdr));
	skb->mac_len = ETH_HLEN;
	skb->encapsulation = 0;
	skb->csum = 0;
	skb->csum_level = 0;
	skb_gso_reset(skb);
	trustix_tixt_tx_route_gso_apply_tx_queue(skb, tmpl);
	if (outer_gso) {
		struct skb_shared_info *shinfo = skb_shinfo(skb);

		tcph->check = trustix_ipv4_l4_partial_check_from_ip_base(
			tmpl->ip_check_base, tcp_len);
		skb->ip_summed = CHECKSUM_PARTIAL;
		skb->csum_start = skb_transport_header(skb) - skb->head;
		skb->csum_offset = offsetof(struct tcphdr, check);
		shinfo->gso_size = outer_gso_size;
		shinfo->gso_segs = frame_count;
		shinfo->gso_type = SKB_GSO_TCPV4;
	} else if (tmpl->partial_csum) {
		tcph->check = trustix_ipv4_l4_partial_check_from_ip_base(
			tmpl->ip_check_base, tcp_len);
		skb->ip_summed = CHECKSUM_PARTIAL;
		skb->csum_start = skb_transport_header(skb) - skb->head;
		skb->csum_offset = offsetof(struct tcphdr, check);
	} else {
		tcph->check = csum_tcpudp_magic(
			tmpl->saddr, tmpl->daddr, tcp_len, IPPROTO_TCP,
			csum_partial(tcph, tcp_len, 0));
		skb->ip_summed = CHECKSUM_NONE;
	}
	ret = trustix_tixt_tx_sanitize_route_gso_xmit_skb(skb, tmpl->out_dev);
	if (ret) {
		kfree_skb(skb);
		goto out_free_seal_ops;
	}
	if (ret_out)
		*ret_out = 0;
	return skb;

out_free_seal_ops:
out_ret:
	if (ret_out)
		*ret_out = ret;
	return ERR_PTR(ret);
}

static struct sk_buff *
trustix_kudp_tx_build_secure_route_gso_frame_skb(
				struct trustix_tixt_tx_route_gso_async_work *item,
				const struct trustix_tixt_tx_route_gso_stream_direct_frame *frame,
				bool fix_inner_csum, int *ret_out)
{
	struct trustix_tixt_tx_route_gso_template *tmpl;
	struct trustix_aead_direct_batch_op op = {};
	struct sk_buff *skb;
	u32 secure_payload_len;
	u32 l3_len;
	u32 total_len;
	u32 mtu;
	u8 *data;
	int ret;

	if (!item || !item->skb || !frame || !item->tmpl.secure ||
	    !item->tmpl.kernel_udp) {
		ret = -EINVAL;
		goto out_ret;
	}
	tmpl = &item->tmpl;
	if (!tmpl->out_dev) {
		ret = -EINVAL;
		goto out_ret;
	}
	secure_payload_len = frame->inner_len;
	if (!secure_payload_len ||
	    check_add_overflow((u32)sizeof(struct iphdr) +
				       (u32)sizeof(struct udphdr) +
				       (u32)TRUSTIX_KUDP_HEADER_LEN,
			       secure_payload_len,
			       &l3_len) ||
	    check_add_overflow((u32)ETH_HLEN, l3_len, &total_len)) {
		ret = -EOVERFLOW;
		goto out_ret;
	}
	mtu = trustix_tixt_tx_route_gso_stream_mtu(tmpl);
	if (!mtu || l3_len > mtu || l3_len > 0xffff) {
		ret = -EMSGSIZE;
		goto out_ret;
	}
	skb = alloc_skb(total_len + NET_SKB_PAD, GFP_KERNEL);
	if (!skb) {
		ret = -ENOMEM;
		goto out_ret;
	}
	skb_reserve(skb, NET_SKB_PAD);
	data = skb_put(skb, total_len);
	trustix_kudp_tx_write_secure_route_gso_header(
		data, tmpl, secure_payload_len, frame->sequence);
	trustix_tixt_tx_write_secure_header(
		data + TRUSTIX_KUDP_UDP_OUTER_HEADER_LEN, item->secure_suite,
		item->secure_epoch, frame->sequence);
	ret = trustix_tixt_tx_copy_route_gso_stream_direct_secure_inner(
		item, data + TRUSTIX_KUDP_UDP_OUTER_HEADER_LEN, frame,
		fix_inner_csum, &op);
	if (ret) {
		kfree_skb(skb);
		goto out_ret;
	}
	ret = trustix_tixt_tx_route_gso_direct_seal_ops(
		item->secure_slot_id, &op, 1);
	if (ret) {
		kfree_skb(skb);
		goto out_ret;
	}

	skb->dev = tmpl->out_dev;
	skb->protocol = htons(ETH_P_IP);
	skb_reset_mac_header(skb);
	skb_set_network_header(skb, ETH_HLEN);
	skb_set_transport_header(skb, ETH_HLEN + sizeof(struct iphdr));
	skb->mac_len = ETH_HLEN;
	skb->encapsulation = 0;
	skb->csum = 0;
	skb->csum_level = 0;
	skb_gso_reset(skb);
	trustix_skb_clear_csum_metadata(skb);
	trustix_tixt_tx_route_gso_apply_tx_queue(skb, tmpl);
	ret = trustix_tixt_tx_sanitize_route_gso_xmit_skb(skb, tmpl->out_dev);
	if (ret) {
		kfree_skb(skb);
		goto out_ret;
	}
	if (ret_out)
		*ret_out = 0;
	return skb;

out_ret:
	if (ret_out)
		*ret_out = ret;
	return ERR_PTR(ret);
}

static struct sk_buff *
trustix_tixt_tx_build_route_gso_stream_direct_ref_nonlinear_skb(
				const struct trustix_tixt_tx_route_gso_template *tmpl,
				const struct trustix_tixt_tx_route_gso_stream_direct_ref *refs,
				unsigned int frame_count, u32 stream_payload_len,
				u64 outer_sequence, bool fix_inner_csum,
				int *ret_out)
{
	const u32 outer_header_len = ETH_HLEN + sizeof(struct iphdr) +
				     sizeof(struct tcphdr);
	struct trustix_tixt_tx_route_gso_nonlinear_builder builder = {};
	struct skb_shared_info *shinfo;
	struct sk_buff *skb;
	struct tcphdr *tcph;
	struct iphdr *iph;
	u32 total_len;
	u32 tcp_len;
	u32 l3_len;
	u32 mtu;
	u32 outer_gso_size = 0;
	u32 sum;
	u16 check;
	u8 *data;
	struct trustix_aead_direct_batch_op *seal_ops = NULL;
	u32 seal_count = 0;
	unsigned int i;
	int ret;

	if (!tmpl || !tmpl->out_dev || !refs || !frame_count) {
		ret = -EINVAL;
		goto out_ret;
	}
	if (!trustix_tixt_tx_route_gso_outer_gso_ready(tmpl, true) ||
	    frame_count <= 1) {
		ret = -EOPNOTSUPP;
		goto out_ret;
	}
	if (check_add_overflow((u32)sizeof(struct tcphdr),
			       stream_payload_len, &tcp_len) ||
	    check_add_overflow((u32)sizeof(struct iphdr), tcp_len, &l3_len) ||
	    check_add_overflow((u32)ETH_HLEN, l3_len, &total_len)) {
		ret = -EOVERFLOW;
		goto out_ret;
	}
	mtu = trustix_tixt_tx_route_gso_stream_mtu(tmpl);
	if (!mtu) {
		ret = -EMSGSIZE;
		goto out_ret;
	}
	if (l3_len > 0xffff ||
	    stream_payload_len > (u32)MAX_SKB_FRAGS * (u32)PAGE_SIZE) {
		ret = -EMSGSIZE;
		goto out_ret;
	}
	if (check_add_overflow((u32)TRUSTIX_TIXT_HEADER_LEN,
			       refs[0].frame.inner_len, &outer_gso_size)) {
		ret = -EOVERFLOW;
		goto out_ret;
	}
	if (sizeof(struct iphdr) + sizeof(struct tcphdr) +
		    outer_gso_size > mtu) {
		ret = -EMSGSIZE;
		goto out_ret;
	}
	for (i = 0; i < frame_count; i++) {
		u32 frame_len;

		if (!refs[i].item) {
			ret = -EINVAL;
			goto out_ret;
		}
		if (tmpl->secure &&
		    (!refs[i].item->tmpl.secure ||
		     refs[i].item->secure_slot_id != refs[0].item->secure_slot_id)) {
			ret = -EINVAL;
			goto out_ret;
		}
		if (check_add_overflow((u32)TRUSTIX_TIXT_HEADER_LEN,
				       refs[i].frame.inner_len, &frame_len)) {
			ret = -EOVERFLOW;
			goto out_ret;
		}
		if (i + 1 < frame_count && frame_len != outer_gso_size) {
			ret = -EOPNOTSUPP;
			goto out_ret;
		}
		if (i + 1 == frame_count && frame_len > outer_gso_size) {
			ret = -EOPNOTSUPP;
			goto out_ret;
		}
	}

	skb = alloc_skb(outer_header_len + NET_SKB_PAD, GFP_KERNEL);
	if (!skb) {
		ret = -ENOMEM;
		goto out_ret;
	}
	skb_reserve(skb, NET_SKB_PAD);
	data = skb_put(skb, outer_header_len);
	memcpy(data, tmpl->base, outer_header_len);

	iph = (struct iphdr *)(data + ETH_HLEN);
	iph->tot_len = htons(l3_len);
	sum = tmpl->ip_check_base;
	sum += l3_len;
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	check = ~sum;
	if (!check)
		check = 0xffff;
	iph->check = htons(check);

	tcph = (struct tcphdr *)(data + ETH_HLEN + sizeof(*iph));
	tcph->seq = htonl((u32)outer_sequence);
	tcph->check = trustix_ipv4_l4_partial_check_from_ip_base(
		tmpl->ip_check_base, tcp_len);

	if (tmpl->secure) {
		seal_ops = kcalloc(frame_count, sizeof(*seal_ops), GFP_KERNEL);
		if (!seal_ops) {
			kfree_skb(skb);
			ret = -ENOMEM;
			goto out_ret;
		}
	}
	for (i = 0; i < frame_count; i++) {
		if (tmpl->secure) {
			ret = trustix_tixt_tx_append_route_gso_stream_direct_secure_nonlinear(
				refs[i].item, &builder, tmpl, &refs[i].frame,
				fix_inner_csum, &seal_ops[seal_count]);
			if (!ret)
				seal_count++;
		} else {
			ret = trustix_tixt_tx_append_route_gso_stream_direct_nonlinear(
				refs[i].item, &builder, tmpl, &refs[i].frame,
				fix_inner_csum);
		}
		if (ret) {
			kfree_skb(skb);
			goto out_free_builder;
		}
	}
	if (tmpl->secure) {
		ret = trustix_tixt_tx_route_gso_direct_seal_ops(
			refs[0].item->secure_slot_id, seal_ops, seal_count);
		if (ret) {
			kfree_skb(skb);
			goto out_free_builder;
		}
	}
	if (builder.len != stream_payload_len) {
		kfree_skb(skb);
		ret = -EINVAL;
		goto out_free_builder;
	}
	ret = trustix_tixt_tx_route_gso_nonlinear_attach(&builder, skb);
	if (ret) {
		kfree_skb(skb);
		goto out_free_builder;
	}

	skb->dev = tmpl->out_dev;
	skb->protocol = htons(ETH_P_IP);
	skb_reset_mac_header(skb);
	skb_set_network_header(skb, ETH_HLEN);
	skb_set_transport_header(skb, ETH_HLEN + sizeof(struct iphdr));
	skb->mac_len = ETH_HLEN;
	skb->encapsulation = 0;
	skb->csum = 0;
	skb->csum_level = 0;
	skb_gso_reset(skb);
	trustix_tixt_tx_route_gso_apply_tx_queue(skb, tmpl);
	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum_start = skb_transport_header(skb) - skb->head;
	skb->csum_offset = offsetof(struct tcphdr, check);
	shinfo = skb_shinfo(skb);
	shinfo->gso_size = outer_gso_size;
	shinfo->gso_segs = frame_count;
	shinfo->gso_type = SKB_GSO_TCPV4;

	ret = trustix_tixt_tx_sanitize_route_gso_xmit_skb(skb, tmpl->out_dev);
	if (ret) {
		kfree_skb(skb);
		goto out_ret;
	}
	if (ret_out)
		*ret_out = 0;
	kfree(seal_ops);
	return skb;

out_free_builder:
	trustix_tixt_tx_route_gso_nonlinear_builder_free(&builder);
out_ret:
	kfree(seal_ops);
	if (ret_out)
		*ret_out = ret;
	return ERR_PTR(ret);
}

static struct sk_buff *
trustix_tixt_tx_build_route_gso_stream_direct_ref_skb(
				const struct trustix_tixt_tx_route_gso_template *tmpl,
				const struct trustix_tixt_tx_route_gso_stream_direct_ref *refs,
				unsigned int frame_count, u32 stream_payload_len,
				u64 outer_sequence, bool fix_inner_csum,
				int *ret_out)
{
	const u32 outer_header_len = ETH_HLEN + sizeof(struct iphdr) +
				     sizeof(struct tcphdr);
	struct sk_buff *skb;
	struct tcphdr *tcph;
	struct iphdr *iph;
	u32 total_len;
	u32 tcp_len;
	u32 l3_len;
	u32 mtu;
	u32 outer_gso_size = 0;
	u32 sum;
	u16 check;
	u8 *data;
	u8 *pos;
	struct trustix_aead_direct_batch_op *seal_ops = NULL;
	u32 seal_count = 0;
	unsigned int i;
	int ret;

	if (!tmpl || !tmpl->out_dev || !refs || !frame_count) {
		ret = -EINVAL;
		goto out_ret;
	}
	if (!trustix_tixt_tx_route_gso_outer_gso_ready(tmpl, true) ||
	    frame_count <= 1) {
		ret = -EOPNOTSUPP;
		goto out_ret;
	}
	if (check_add_overflow((u32)sizeof(struct tcphdr),
			       stream_payload_len, &tcp_len) ||
	    check_add_overflow((u32)sizeof(struct iphdr), tcp_len, &l3_len) ||
	    check_add_overflow((u32)ETH_HLEN, l3_len, &total_len)) {
		ret = -EOVERFLOW;
		goto out_ret;
	}
	mtu = trustix_tixt_tx_route_gso_stream_mtu(tmpl);
	if (!mtu) {
		ret = -EMSGSIZE;
		goto out_ret;
	}
	if (l3_len > 0xffff) {
		ret = -EMSGSIZE;
		goto out_ret;
	}
	if (check_add_overflow((u32)TRUSTIX_TIXT_HEADER_LEN,
			       refs[0].frame.inner_len, &outer_gso_size)) {
		ret = -EOVERFLOW;
		goto out_ret;
	}
	if (sizeof(struct iphdr) + sizeof(struct tcphdr) +
		    outer_gso_size > mtu) {
		ret = -EMSGSIZE;
		goto out_ret;
	}
	for (i = 0; i < frame_count; i++) {
		u32 frame_len;

		if (!refs[i].item) {
			ret = -EINVAL;
			goto out_ret;
		}
		if (tmpl->secure &&
		    (!refs[i].item->tmpl.secure ||
		     refs[i].item->secure_slot_id != refs[0].item->secure_slot_id)) {
			ret = -EINVAL;
			goto out_ret;
		}
		if (check_add_overflow((u32)TRUSTIX_TIXT_HEADER_LEN,
				       refs[i].frame.inner_len, &frame_len)) {
			ret = -EOVERFLOW;
			goto out_ret;
		}
		if (i + 1 < frame_count && frame_len != outer_gso_size) {
			ret = -EOPNOTSUPP;
			goto out_ret;
		}
		if (i + 1 == frame_count && frame_len > outer_gso_size) {
			ret = -EOPNOTSUPP;
			goto out_ret;
		}
	}

	skb = alloc_skb(total_len + NET_SKB_PAD, GFP_KERNEL);
	if (!skb) {
		ret = -ENOMEM;
		goto out_ret;
	}
	skb_reserve(skb, NET_SKB_PAD);
	data = skb_put(skb, total_len);
	memcpy(data, tmpl->base, outer_header_len);
	pos = data + outer_header_len;

	iph = (struct iphdr *)(data + ETH_HLEN);
	iph->tot_len = htons(l3_len);
	sum = tmpl->ip_check_base;
	sum += l3_len;
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	check = ~sum;
	if (!check)
		check = 0xffff;
	iph->check = htons(check);

	tcph = (struct tcphdr *)(data + ETH_HLEN + sizeof(*iph));
	tcph->seq = htonl((u32)outer_sequence);
	tcph->check = 0;

	if (tmpl->secure) {
		seal_ops = kcalloc(frame_count, sizeof(*seal_ops), GFP_KERNEL);
		if (!seal_ops) {
			kfree_skb(skb);
			ret = -ENOMEM;
			goto out_ret;
		}
	}
	for (i = 0; i < frame_count; i++) {
		trustix_tixt_tx_write_route_gso_stream_tixt(
			pos, tmpl, refs[i].frame.inner_len,
			refs[i].frame.sequence);
		pos += TRUSTIX_TIXT_HEADER_LEN;
		ret = trustix_tixt_tx_copy_route_gso_stream_direct_ref_inner(
			&refs[i], pos, fix_inner_csum,
			tmpl->secure ? &seal_ops[seal_count] : NULL);
		if (ret) {
			kfree_skb(skb);
			goto out_ret;
		}
		if (tmpl->secure)
			seal_count++;
		pos += refs[i].frame.inner_len;
	}
	if (tmpl->secure) {
		ret = trustix_tixt_tx_route_gso_direct_seal_ops(
			refs[0].item->secure_slot_id, seal_ops, seal_count);
		if (ret) {
			kfree_skb(skb);
			goto out_ret;
		}
	}
	if (pos != data + total_len) {
		kfree_skb(skb);
		ret = -EINVAL;
		goto out_ret;
	}

	skb->dev = tmpl->out_dev;
	skb->protocol = htons(ETH_P_IP);
	skb_reset_mac_header(skb);
	skb_set_network_header(skb, ETH_HLEN);
	skb_set_transport_header(skb, ETH_HLEN + sizeof(struct iphdr));
	skb->mac_len = ETH_HLEN;
	skb->encapsulation = 0;
	skb->csum = 0;
	skb->csum_level = 0;
	skb_gso_reset(skb);
	trustix_tixt_tx_route_gso_apply_tx_queue(skb, tmpl);

	tcph->check = trustix_ipv4_l4_partial_check_from_ip_base(
		tmpl->ip_check_base, tcp_len);
	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum_start = skb_transport_header(skb) - skb->head;
	skb->csum_offset = offsetof(struct tcphdr, check);
	skb_shinfo(skb)->gso_size = outer_gso_size;
	skb_shinfo(skb)->gso_segs = frame_count;
	skb_shinfo(skb)->gso_type = SKB_GSO_TCPV4;

	ret = trustix_tixt_tx_sanitize_route_gso_xmit_skb(skb, tmpl->out_dev);
	if (ret) {
		kfree_skb(skb);
		goto out_ret;
	}
	if (ret_out)
		*ret_out = 0;
	kfree(seal_ops);
	return skb;

out_ret:
	kfree(seal_ops);
	if (ret_out)
		*ret_out = ret;
	return ERR_PTR(ret);
}

static int trustix_tixt_tx_route_gso_stream_send_batch(
				const struct trustix_tixt_tx_route_gso_template *tmpl,
				const struct trustix_tixt_tx_route_gso_stream_frame *frames,
				unsigned int frame_count, u32 stream_payload_len,
				u64 outer_sequence, bool xmit_more)
{
	struct sk_buff *skb;
	bool outer_gso;
	int ret;

	skb = trustix_tixt_tx_build_route_gso_stream_skb(
		tmpl, frames, frame_count, stream_payload_len, outer_sequence,
		trustix_tixt_tx_route_gso_outer_gso_ready(tmpl, true),
		GFP_KERNEL, &ret);
	if (IS_ERR(skb))
		return ret;
	outer_gso = skb_is_gso(skb);
	trustix_tixt_tx_route_gso_stream_record(0, 0, skb, frame_count);
	if (unlikely(!trustix_tixt_tx_route_gso_xmit_ready_async(skb))) {
		kfree_skb(skb);
		return -EBUSY;
	}
	trustix_tixt_tx_route_gso_apply_xmit_more(skb, xmit_more);
	ret = trustix_tixt_tx_route_gso_safe_xmit(
		skb, READ_ONCE(trustix_route_tcp_gso_async_direct_xmit));
	if (unlikely(ret)) {
		trustix_route_tcp_gso_async_stream_xmit_errors++;
		trustix_tixt_tx_route_gso_stream_record(-EIO, 6, NULL,
							frame_count);
		return -EIO;
	}
	trustix_route_tcp_gso_async_stream_batches++;
	trustix_route_tcp_gso_async_stream_frames += frame_count;
	trustix_route_tcp_gso_async_stream_software_segments += frame_count;
	if (outer_gso) {
		trustix_route_tcp_gso_async_stream_outer_gso_batches++;
		trustix_route_tcp_gso_async_stream_outer_gso_frames +=
			frame_count;
	}
	trustix_route_tcp_gso_async_xmit_packets++;
	return 0;
}

static void trustix_tixt_tx_free_skb_array(struct sk_buff **skbs,
					   unsigned int count)
{
	unsigned int i;

	if (!skbs)
		return;
	for (i = 0; i < count; i++) {
		if (skbs[i]) {
			kfree_skb(skbs[i]);
			skbs[i] = NULL;
		}
	}
}

static int __maybe_unused
trustix_tixt_tx_route_gso_sync_try_stream(
				const struct trustix_tixt_tx_route_gso_template *tmpl,
				struct sk_buff *segs,
				u32 segment_count,
				u32 gso_payload_len,
				u32 tcp_header_len,
				u32 payload_len,
				u64 sequence_start,
				unsigned int *sent_frames)
{
	struct trustix_tixt_tx_route_gso_stream_frame frames[
		TRUSTIX_TIXT_TX_ROUTE_SYNC_STREAM_MAX_FRAMES];
	struct sk_buff *batches[
		TRUSTIX_TIXT_TX_ROUTE_SYNC_STREAM_MAX_BATCHES] = {};
	u16 batch_frames[
		TRUSTIX_TIXT_TX_ROUTE_SYNC_STREAM_MAX_BATCHES] = {};
	struct sk_buff *seg = segs;
	u64 sequence = sequence_start;
	u32 payload_remaining = payload_len;
	u32 prepared = 0;
	unsigned int max_frames;
	unsigned int batch_count = 0;
	unsigned int sent = 0;
	bool allow_outer_gso;
	int ret;
	int stage = 0;

	if (sent_frames)
		*sent_frames = 0;
	if (!READ_ONCE(trustix_route_tcp_gso_sync_stream))
		return 0;
	if (!tmpl || !segs || !segment_count || !gso_payload_len ||
	    tcp_header_len < sizeof(struct tcphdr)) {
		trustix_tixt_tx_route_gso_sync_stream_record(-EINVAL, 1,
							     NULL, 0, 0);
		return 0;
	}
	allow_outer_gso = READ_ONCE(trustix_route_tcp_gso_sync_stream_outer_gso);
	if (!allow_outer_gso) {
		trustix_tixt_tx_route_gso_sync_stream_record(-EOPNOTSUPP, 2,
							     NULL, 0, 0);
		return 0;
	}

	max_frames = trustix_route_tcp_gso_sync_stream_max_frames_value();
	if (max_frames < 2) {
		trustix_tixt_tx_route_gso_sync_stream_record(-EOPNOTSUPP, 3,
							     NULL, 0, 0);
		return 0;
	}
	trustix_route_tcp_gso_sync_stream_attempts++;

	while (seg && prepared < segment_count && payload_remaining) {
		u64 batch_sequence = sequence;
		u32 stream_payload_len = 0;
		unsigned int frame_count = 0;
		struct sk_buff *skb;

		while (seg && prepared < segment_count &&
		       payload_remaining && frame_count < max_frames &&
		       frame_count < ARRAY_SIZE(frames)) {
			u32 seg_payload_len;
			u32 inner_len;
			u32 frame_len;
			u32 next_payload_len;
			u32 next_l3_len;

			seg_payload_len = min(payload_remaining,
					      gso_payload_len);
			if (check_add_overflow((u32)sizeof(struct iphdr),
					       tcp_header_len, &inner_len) ||
			    check_add_overflow(inner_len, seg_payload_len,
					       &inner_len) ||
			    check_add_overflow((u32)TRUSTIX_TIXT_HEADER_LEN,
					       inner_len, &frame_len) ||
			    check_add_overflow(stream_payload_len, frame_len,
					       &next_payload_len) ||
			    check_add_overflow((u32)sizeof(struct iphdr) +
						       (u32)sizeof(struct tcphdr),
					       next_payload_len, &next_l3_len)) {
				ret = -EOVERFLOW;
				stage = 10;
				goto fallback;
			}
			if (frame_count && next_l3_len > 0xffff)
				break;
			if (!frame_count && next_l3_len > 0xffff) {
				ret = -EMSGSIZE;
				stage = 11;
				goto fallback;
			}
			frames[frame_count].seg = seg;
			frames[frame_count].sequence =
				trustix_tixt_tx_plain_wire_sequence(sequence);
			frames[frame_count].inner_len = inner_len;
			stream_payload_len = next_payload_len;
			sequence += frame_len;
			payload_remaining -= seg_payload_len;
			seg = seg->next;
			prepared++;
			frame_count++;
		}
		if (!frame_count) {
			ret = -EIO;
			stage = 12;
			goto fallback;
		}
		if (batch_count >= ARRAY_SIZE(batches)) {
			ret = -E2BIG;
			stage = 13;
			goto fallback;
		}
		skb = trustix_tixt_tx_build_route_gso_stream_skb(
			tmpl, frames, frame_count, stream_payload_len,
			trustix_tixt_tx_plain_wire_sequence(batch_sequence),
			true, GFP_ATOMIC | __GFP_NOWARN, &ret);
		if (IS_ERR(skb)) {
			stage = 14;
			trustix_route_tcp_gso_sync_stream_build_errors++;
			if (ret == -EBUSY)
				trustix_route_tcp_gso_sync_stream_build_busy++;
			else if (ret == -ENOMEM)
				trustix_route_tcp_gso_sync_stream_build_nomem++;
			else if (ret == -EOPNOTSUPP || ret == -EMSGSIZE)
				trustix_route_tcp_gso_sync_stream_build_unsupported++;
			goto fallback;
		}
		trustix_tixt_tx_route_gso_sync_stream_record(0, 20, skb,
							     frame_count,
							     batch_count + 1);
		batches[batch_count] = skb;
		batch_frames[batch_count] = frame_count;
		batch_count++;
	}
	if (prepared != segment_count || payload_remaining || seg) {
		ret = -EINVAL;
		stage = 15;
		goto fallback;
	}
	for (prepared = 0; prepared < batch_count; prepared++) {
		if (unlikely(!trustix_tixt_tx_route_gso_xmit_ready(
				     batches[prepared]))) {
			ret = -EBUSY;
			stage = 16;
			trustix_route_tcp_gso_sync_stream_ready_errors++;
			goto fallback;
		}
	}
	for (prepared = 0; prepared < batch_count; prepared++) {
		struct sk_buff *skb = batches[prepared];

		batches[prepared] = NULL;
		trustix_tixt_tx_route_gso_apply_xmit_more(
			skb, prepared + 1 < batch_count);
		ret = trustix_tixt_tx_route_gso_safe_xmit(skb, false);
		if (unlikely(ret)) {
			trustix_route_tcp_gso_sync_stream_xmit_errors++;
			trustix_route_tcp_gso_sync_xmit_errors++;
			trustix_tixt_tx_route_gso_sync_stream_record(
				ret, 17, NULL, sent, batch_count);
		} else {
			sent += batch_frames[prepared];
		}
	}
	if (batch_count)
		trustix_route_tcp_gso_sync_stream_batches += batch_count;
	if (sent) {
		trustix_route_tcp_gso_sync_stream_frames += sent;
		trustix_route_tcp_gso_sync_segments += sent;
		trustix_route_tcp_gso_async_xmit_packets += batch_count;
	}
	if (sent_frames)
		*sent_frames = sent;
	if (sent && sent < segment_count)
		trustix_route_tcp_gso_sync_stream_partial_xmits++;
	if (!sent) {
		trustix_route_tcp_gso_sync_stream_errors++;
		trustix_tixt_tx_route_gso_sync_stream_record(-EIO, 18, NULL,
							     sent,
							     batch_count);
	} else if (sent == segment_count) {
		trustix_tixt_tx_route_gso_sync_stream_record(0, 0, NULL,
							     sent,
							     batch_count);
	}
	return 1;

fallback:
	trustix_tixt_tx_free_skb_array(batches, batch_count);
	trustix_route_tcp_gso_sync_stream_fallbacks++;
	trustix_tixt_tx_route_gso_sync_stream_record(ret, stage, NULL,
						     prepared, batch_count);
	if (ret && ret != -EOPNOTSUPP && ret != -EBUSY)
		trustix_route_tcp_gso_sync_stream_errors++;
	return 0;
}

static struct sk_buff *
trustix_tixt_tx_route_gso_stream_build_direct_batch(
				struct trustix_tixt_tx_route_gso_async_work *item,
				const struct trustix_tixt_tx_route_gso_stream_direct_frame *frames,
				unsigned int frame_count, u32 stream_payload_len,
				u64 outer_sequence, bool fix_inner_csum,
				bool *nonlinear_out, int *ret_out)
{
	struct sk_buff *skb;
	bool nonlinear = false;
	int ret;

	if (nonlinear_out)
		*nonlinear_out = false;
	if (READ_ONCE(trustix_route_tcp_gso_async_stream_nonlinear_direct_build)) {
		skb = trustix_tixt_tx_build_route_gso_stream_direct_nonlinear_skb(
			item, frames, frame_count, stream_payload_len,
			outer_sequence, fix_inner_csum, &ret);
		if (!IS_ERR(skb)) {
			nonlinear = true;
		} else {
			trustix_route_tcp_gso_async_stream_nonlinear_direct_fallbacks++;
			skb = trustix_tixt_tx_build_route_gso_stream_direct_skb(
				item, frames, frame_count, stream_payload_len,
				outer_sequence, fix_inner_csum, &ret);
		}
	} else {
		skb = trustix_tixt_tx_build_route_gso_stream_direct_skb(
			item, frames, frame_count, stream_payload_len,
			outer_sequence, fix_inner_csum, &ret);
	}
	if (IS_ERR(skb)) {
		if (ret_out)
			*ret_out = ret;
		return skb;
	}
	if (nonlinear_out)
		*nonlinear_out = nonlinear;
	if (ret_out)
		*ret_out = 0;
	return skb;
}

static int trustix_tixt_tx_route_gso_stream_xmit_direct_batch(
				struct sk_buff *skb, unsigned int frame_count,
				bool nonlinear, bool xmit_more)
{
	bool outer_gso;
	int ret;

	if (!skb)
		return -EINVAL;
	outer_gso = skb_is_gso(skb);
	trustix_tixt_tx_route_gso_stream_record(0, 0, skb, frame_count);
	if (unlikely(!trustix_tixt_tx_route_gso_xmit_ready_async(skb))) {
		if (nonlinear)
			trustix_route_tcp_gso_async_stream_nonlinear_direct_errors++;
		kfree_skb(skb);
		return -EBUSY;
	}
	trustix_tixt_tx_route_gso_apply_xmit_more(skb, xmit_more);
	ret = trustix_tixt_tx_route_gso_safe_xmit(
		skb, READ_ONCE(trustix_route_tcp_gso_async_direct_xmit));
	if (unlikely(ret)) {
		trustix_route_tcp_gso_async_stream_xmit_errors++;
		if (nonlinear)
			trustix_route_tcp_gso_async_stream_nonlinear_direct_errors++;
		trustix_tixt_tx_route_gso_stream_record(-EIO, 6, NULL,
							frame_count);
		return -EIO;
	}
	trustix_route_tcp_gso_async_stream_batches++;
	trustix_route_tcp_gso_async_stream_frames += frame_count;
	trustix_route_tcp_gso_async_stream_direct_builds++;
	trustix_route_tcp_gso_async_stream_direct_frames += frame_count;
	if (nonlinear) {
		trustix_route_tcp_gso_async_stream_nonlinear_direct_builds++;
		trustix_route_tcp_gso_async_stream_nonlinear_direct_frames +=
			frame_count;
	}
	if (outer_gso) {
		trustix_route_tcp_gso_async_stream_outer_gso_batches++;
		trustix_route_tcp_gso_async_stream_outer_gso_frames +=
			frame_count;
	}
	trustix_route_tcp_gso_async_xmit_packets++;
	return 0;
}

static int trustix_tixt_tx_route_gso_stream_send_direct_batch(
				struct trustix_tixt_tx_route_gso_async_work *item,
				const struct trustix_tixt_tx_route_gso_stream_direct_frame *frames,
				unsigned int frame_count, u32 stream_payload_len,
				u64 outer_sequence, bool fix_inner_csum,
				bool xmit_more)
{
	struct sk_buff *skb;
	bool nonlinear = false;
	int ret;

	skb = trustix_tixt_tx_route_gso_stream_build_direct_batch(
		item, frames, frame_count, stream_payload_len, outer_sequence,
		fix_inner_csum, &nonlinear, &ret);
	if (IS_ERR(skb))
		return ret;
	return trustix_tixt_tx_route_gso_stream_xmit_direct_batch(
		skb, frame_count, nonlinear, xmit_more);
}

static int trustix_tixt_tx_route_gso_stream_send_direct_ref_batch(
				const struct trustix_tixt_tx_route_gso_template *tmpl,
				const struct trustix_tixt_tx_route_gso_stream_direct_ref *refs,
				unsigned int frame_count, u32 stream_payload_len,
				u64 outer_sequence, bool fix_inner_csum,
				bool xmit_more)
{
	struct sk_buff *skb;
	bool nonlinear = false;
	int ret;

	if (READ_ONCE(trustix_route_tcp_gso_async_stream_nonlinear_direct_build)) {
		skb = trustix_tixt_tx_build_route_gso_stream_direct_ref_nonlinear_skb(
			tmpl, refs, frame_count, stream_payload_len,
			outer_sequence, fix_inner_csum, &ret);
		if (!IS_ERR(skb)) {
			nonlinear = true;
		} else {
			trustix_route_tcp_gso_async_stream_nonlinear_direct_fallbacks++;
			skb = trustix_tixt_tx_build_route_gso_stream_direct_ref_skb(
				tmpl, refs, frame_count, stream_payload_len,
				outer_sequence, fix_inner_csum, &ret);
		}
	} else {
		skb = trustix_tixt_tx_build_route_gso_stream_direct_ref_skb(
			tmpl, refs, frame_count, stream_payload_len,
			outer_sequence, fix_inner_csum, &ret);
	}
	if (IS_ERR(skb))
		return ret;
	trustix_tixt_tx_route_gso_stream_record(0, 0, skb, frame_count);
	if (unlikely(!trustix_tixt_tx_route_gso_xmit_ready_async(skb))) {
		if (nonlinear)
			trustix_route_tcp_gso_async_stream_nonlinear_direct_errors++;
		kfree_skb(skb);
		return -EBUSY;
	}
	trustix_tixt_tx_route_gso_apply_xmit_more(skb, xmit_more);
	ret = trustix_tixt_tx_route_gso_safe_xmit(
		skb, READ_ONCE(trustix_route_tcp_gso_async_direct_xmit));
	if (unlikely(ret)) {
		trustix_route_tcp_gso_async_stream_xmit_errors++;
		if (nonlinear)
			trustix_route_tcp_gso_async_stream_nonlinear_direct_errors++;
		trustix_tixt_tx_route_gso_stream_record(-EIO, 6, NULL,
							frame_count);
		return -EIO;
	}
	trustix_route_tcp_gso_async_stream_batches++;
	trustix_route_tcp_gso_async_stream_frames += frame_count;
	trustix_route_tcp_gso_async_stream_direct_builds++;
	trustix_route_tcp_gso_async_stream_direct_frames += frame_count;
	if (nonlinear) {
		trustix_route_tcp_gso_async_stream_nonlinear_direct_builds++;
		trustix_route_tcp_gso_async_stream_nonlinear_direct_frames +=
			frame_count;
	}
	trustix_route_tcp_gso_async_stream_outer_gso_batches++;
	trustix_route_tcp_gso_async_stream_outer_gso_frames += frame_count;
	trustix_route_tcp_gso_async_xmit_packets++;
	return 0;
}

static bool trustix_route_tcp_gso_async_queue_work(struct delayed_work *work,
						  unsigned long delay)
{
	if (READ_ONCE(trustix_route_tcp_gso_async_quiescing))
		return false;
	if (READ_ONCE(trustix_route_tcp_gso_async_unbound_worker) &&
	    trustix_route_tcp_gso_async_wq)
		return queue_delayed_work(trustix_route_tcp_gso_async_wq,
					  work, delay);
	return schedule_delayed_work(work, delay);
}

static bool trustix_route_tcp_gso_async_mod_work(struct delayed_work *work,
						unsigned long delay)
{
	if (READ_ONCE(trustix_route_tcp_gso_async_quiescing))
		return false;
	if (READ_ONCE(trustix_route_tcp_gso_async_unbound_worker) &&
	    trustix_route_tcp_gso_async_wq)
		return mod_delayed_work(trustix_route_tcp_gso_async_wq,
					work, delay);
	return mod_delayed_work(system_wq, work, delay);
}

static bool trustix_route_tcp_gso_async_try_queue_now(struct delayed_work *work)
{
	return trustix_route_tcp_gso_async_queue_work(work, 0);
}

static enum hrtimer_restart
trustix_route_tcp_gso_async_schedule_timer_fn(struct hrtimer *timer)
{
	WRITE_ONCE(trustix_route_tcp_gso_async_delay_pending, false);
	if (READ_ONCE(trustix_route_tcp_gso_async_quiescing))
		return HRTIMER_NORESTART;
	trustix_route_tcp_gso_async_try_queue_now(
		&trustix_route_tcp_gso_async_work);
	return HRTIMER_NORESTART;
}

static enum hrtimer_restart
trustix_route_tcp_gso_async_shard_schedule_timer_fn(struct hrtimer *timer)
{
	struct trustix_route_tcp_gso_async_queue_shard *shard =
		container_of(timer, struct trustix_route_tcp_gso_async_queue_shard,
			    schedule_timer);

	WRITE_ONCE(shard->delay_pending, false);
	if (READ_ONCE(trustix_route_tcp_gso_async_quiescing))
		return HRTIMER_NORESTART;
	trustix_route_tcp_gso_async_try_queue_now(&shard->work);
	return HRTIMER_NORESTART;
}

static unsigned int trustix_route_tcp_gso_async_schedule_delay_usecs(void)
{
	unsigned int delay =
		READ_ONCE(trustix_route_tcp_gso_async_worker_schedule_delay_usecs);

	return min_t(unsigned int, delay, 20000U);
}

static bool trustix_route_tcp_gso_async_queue_schedule_timer(
				struct delayed_work *work,
				struct hrtimer *timer,
				unsigned int delay_usecs)
{
	if (READ_ONCE(trustix_route_tcp_gso_async_quiescing))
		return false;
	if (!delay_usecs)
		return trustix_route_tcp_gso_async_queue_work(work, 0);
	hrtimer_start(timer, ns_to_ktime((u64)delay_usecs * 1000ULL),
		      HRTIMER_MODE_REL);
	return true;
}

static void trustix_route_tcp_gso_async_cancel_schedule_timer(
				struct hrtimer *timer)
{
	hrtimer_cancel(timer);
}

static unsigned int trustix_route_tcp_gso_async_budget_reschedule_delay_usecs(void)
{
	unsigned int delay = READ_ONCE(
		trustix_route_tcp_gso_async_worker_budget_reschedule_delay_usecs);

	return min_t(unsigned int, delay, 20000U);
}

static void trustix_route_tcp_gso_async_budget_sleep(unsigned long delay_jiffies)
{
	unsigned int delay_usecs;

	if (delay_jiffies)
		return;
	delay_usecs = trustix_route_tcp_gso_async_budget_reschedule_delay_usecs();
	if (!delay_usecs)
		return;
	trustix_route_tcp_gso_async_worker_budget_usleeps++;
	usleep_range(delay_usecs, delay_usecs + min_t(unsigned int, delay_usecs, 1000U));
}

static int trustix_tixt_tx_route_gso_async_try_stream_direct(
				struct trustix_tixt_tx_route_gso_async_work *item,
				u32 *sent_frames)
{
	struct trustix_tixt_tx_route_gso_stream_direct_frame *frames;
	struct sk_buff *batches[
		TRUSTIX_TIXT_TX_ROUTE_SYNC_STREAM_MAX_BATCHES] = {};
	u16 batch_frames[
		TRUSTIX_TIXT_TX_ROUTE_SYNC_STREAM_MAX_BATCHES] = {};
	bool batch_nonlinear[
		TRUSTIX_TIXT_TX_ROUTE_SYNC_STREAM_MAX_BATCHES] = {};
	u64 batch_sequence;
	u64 outer_sequence;
	u64 sequence;
	u32 payload_remaining;
	u32 payload_offset = 0;
	u32 stream_payload_len = 0;
	u32 stream_packets = 0;
	u32 stream_frames = 0;
	u32 max_frames;
	u32 mtu;
	u32 frame_payload_extra;
	u32 frame_count = 0;
	u32 prepared = 0;
	unsigned int batch_count = 0;
	bool fix_inner_csum;
	bool outer_gso;
	int ret = 0;
	int stage = 0;

	if (sent_frames)
		*sent_frames = 0;
	if (!item || !item->skb || !sent_frames) {
		trustix_tixt_tx_route_gso_stream_record(-EINVAL, 9, NULL, 0);
		return -EINVAL;
	}
	if (!READ_ONCE(trustix_route_tcp_gso_async_stream) ||
	    !READ_ONCE(trustix_route_tcp_gso_async_stream_direct_build))
		return 0;

	max_frames = trustix_route_tcp_gso_async_stream_max_frames_value();
	mtu = trustix_tixt_tx_route_gso_stream_mtu(&item->tmpl);
	if (max_frames < 2 || !mtu) {
		trustix_route_tcp_gso_async_stream_direct_fallbacks++;
		trustix_tixt_tx_route_gso_stream_record(-EOPNOTSUPP, 10,
							NULL, 0);
		return 0;
	}
	ret = trustix_tixt_tx_route_gso_async_prepare_inner_header(item);
	if (ret) {
		trustix_route_tcp_gso_async_stream_direct_fallbacks++;
		trustix_tixt_tx_route_gso_stream_record(ret, 11, NULL, 0);
		return 0;
	}
	frames = item->direct_frames;

	fix_inner_csum = (item->tmpl.secure &&
			  !item->tmpl.trust_partial_inner_csum) ||
		READ_ONCE(trustix_route_tcp_gso_async_stream_direct_build_inner_csum);
	outer_gso = trustix_tixt_tx_route_gso_outer_gso_ready(&item->tmpl,
							      true);
	frame_payload_extra = item->tmpl.secure ?
		TRUSTIX_TIXT_TX_SECURE_PAYLOAD_OVERHEAD : 0;
	sequence = item->sequence;
	outer_sequence = item->tmpl.secure ? item->outer_sequence :
		item->sequence;
	batch_sequence = outer_sequence;
	payload_remaining = item->payload_len;
	while (prepared < item->segment_count && payload_remaining) {
		u32 seg_payload_len = min(payload_remaining,
					  item->gso_payload_len);
		u32 plain_inner_len;
		u32 inner_len;
		u32 frame_len;
		u32 next_payload_len;
		u32 next_l3_len;

		if (check_add_overflow((u32)sizeof(struct iphdr) +
					       item->tcp_header_len,
				       seg_payload_len, &plain_inner_len) ||
		    check_add_overflow(plain_inner_len, frame_payload_extra,
				       &inner_len) ||
		    check_add_overflow(item->tmpl.kernel_udp ?
					       (u32)TRUSTIX_KUDP_HEADER_LEN :
					       (u32)TRUSTIX_TIXT_HEADER_LEN,
				       inner_len, &frame_len)) {
			ret = -EMSGSIZE;
			stage = 12;
			goto fail;
		}
		if (item->tmpl.kernel_udp &&
		    sizeof(struct iphdr) + sizeof(struct udphdr) + frame_len >
			    mtu) {
			ret = -EMSGSIZE;
			stage = 12;
			goto fail;
		}
		if (!item->tmpl.kernel_udp &&
		    sizeof(struct iphdr) + sizeof(struct tcphdr) + frame_len >
			    mtu) {
			ret = -EMSGSIZE;
			stage = 12;
			goto fail;
		}
		if (item->tmpl.kernel_udp) {
			struct sk_buff *skb;

			frames[0].sequence = sequence;
			frames[0].payload_offset = payload_offset;
			frames[0].payload_len = seg_payload_len;
			frames[0].inner_len = inner_len;
			frames[0].plain_inner_len = plain_inner_len;
			skb = trustix_kudp_tx_build_secure_route_gso_frame_skb(
				item, &frames[0], fix_inner_csum, &ret);
			if (IS_ERR(skb)) {
				stage = 14;
				goto fail;
			}
			if (batch_count >= ARRAY_SIZE(batches)) {
				kfree_skb(skb);
				ret = -E2BIG;
				stage = 14;
				goto fail;
			}
			batches[batch_count] = skb;
			batch_frames[batch_count] = 1;
			batch_nonlinear[batch_count] = false;
			batch_count++;
			stream_payload_len += frame_len;
			sequence++;
			payload_offset += seg_payload_len;
			payload_remaining -= seg_payload_len;
			prepared++;
			continue;
		}
		if (check_add_overflow(stream_payload_len, frame_len,
				       &next_payload_len) ||
		    check_add_overflow((u32)sizeof(struct iphdr) +
					       (u32)sizeof(struct tcphdr),
				       next_payload_len, &next_l3_len)) {
			ret = -EOVERFLOW;
			stage = 13;
			goto fail;
		}
		if (frame_count &&
		    (frame_count >= max_frames ||
		     next_l3_len > 0xffff ||
		     (!outer_gso && next_l3_len > mtu))) {
			struct sk_buff *skb;
			bool nonlinear = false;

			if (batch_count >= ARRAY_SIZE(batches)) {
				ret = -E2BIG;
				stage = 14;
				goto fail;
			}
			skb = trustix_tixt_tx_route_gso_stream_build_direct_batch(
				item, frames, frame_count, stream_payload_len,
				item->tmpl.secure ? batch_sequence :
					trustix_tixt_tx_plain_wire_sequence(
						batch_sequence),
				fix_inner_csum, &nonlinear, &ret);
			if (IS_ERR(skb)) {
				stage = 14;
				goto fail;
			}
			batches[batch_count] = skb;
			batch_frames[batch_count] = frame_count;
			batch_nonlinear[batch_count] = nonlinear;
			batch_count++;
			frame_count = 0;
			stream_payload_len = 0;
			batch_sequence = outer_sequence;
		}
		if (frame_count >= max_frames) {
			ret = -EMSGSIZE;
			stage = 15;
			goto fail;
		}
		frames[frame_count].sequence = item->tmpl.secure ?
			sequence : trustix_tixt_tx_plain_wire_sequence(sequence);
		frames[frame_count].payload_offset = payload_offset;
		frames[frame_count].payload_len = seg_payload_len;
		frames[frame_count].inner_len = inner_len;
		frames[frame_count].plain_inner_len =
			item->tmpl.secure ? plain_inner_len : 0;
		frame_count++;
		stream_payload_len += frame_len;
		outer_sequence += frame_len;
		sequence += item->tmpl.secure ? 1 : frame_len;
		payload_offset += seg_payload_len;
		payload_remaining -= seg_payload_len;
		prepared++;
	}
	if (prepared != item->segment_count || payload_remaining) {
		ret = -EINVAL;
		stage = 16;
		goto fail;
	}
	if (frame_count) {
		struct sk_buff *skb;
		bool nonlinear = false;

		if (batch_count >= ARRAY_SIZE(batches)) {
			ret = -E2BIG;
			stage = 14;
			goto fail;
		}
		skb = trustix_tixt_tx_route_gso_stream_build_direct_batch(
			item, frames, frame_count, stream_payload_len,
			item->tmpl.secure ? batch_sequence :
				trustix_tixt_tx_plain_wire_sequence(batch_sequence),
			fix_inner_csum, &nonlinear, &ret);
		if (IS_ERR(skb)) {
			stage = 14;
			goto fail;
		}
		batches[batch_count] = skb;
		batch_frames[batch_count] = frame_count;
		batch_nonlinear[batch_count] = nonlinear;
		batch_count++;
	}
	if (!batch_count) {
		trustix_route_tcp_gso_async_stream_direct_fallbacks++;
		trustix_tixt_tx_route_gso_stream_record(-EOPNOTSUPP, 17,
							NULL, 0);
		return 0;
	}
	for (prepared = 0; prepared < batch_count; prepared++) {
		if (unlikely(!trustix_tixt_tx_route_gso_xmit_ready_async(
				     batches[prepared]))) {
			ret = -EBUSY;
			stage = 18;
			goto fail;
		}
	}
	for (prepared = 0; prepared < batch_count; prepared++) {
		struct sk_buff *skb = batches[prepared];
		bool xmit_more = prepared + 1 < batch_count || item->xmit_more;

		batches[prepared] = NULL;
		ret = trustix_tixt_tx_route_gso_stream_xmit_direct_batch(
			skb, batch_frames[prepared],
			batch_nonlinear[prepared], xmit_more);
		if (ret) {
			stage = 19;
			goto fail;
		}
		stream_packets++;
		stream_frames += batch_frames[prepared];
	}
	*sent_frames = stream_frames;
	return 1;

fail:
	trustix_tixt_tx_free_skb_array(batches, batch_count);
	if (!stream_packets) {
		trustix_route_tcp_gso_async_stream_direct_fallbacks++;
		trustix_tixt_tx_route_gso_stream_record(ret, stage, NULL, 0);
		return 0;
	}
	trustix_route_tcp_gso_async_stream_direct_errors++;
	trustix_tixt_tx_route_gso_stream_record(ret, stage, NULL,
						stream_frames);
	*sent_frames = stream_frames;
	return ret ? ret : -EIO;
}

static int trustix_tixt_tx_route_gso_async_try_stream(
				struct trustix_tixt_tx_route_gso_async_work *item,
				struct sk_buff *segs, u32 segment_count,
				u32 gso_payload_len, u32 tcp_header_len,
				u32 payload_len, u32 *sent_frames)
{
	struct trustix_tixt_tx_route_gso_stream_frame *frames;
	struct sk_buff *seg;
	u64 batch_sequence;
	u64 sequence;
	u32 payload_remaining;
	u32 stream_payload_len = 0;
	u32 stream_packets = 0;
	u32 stream_frames = 0;
	u32 prepared = 0;
	u32 max_frames;
	u32 mtu;
	u32 first_payload_len;
	u32 first_inner_len;
	u32 first_frame_len;
	u32 frame_count = 0;
	int ret = 0;
	int stage = 0;

	if (sent_frames)
		*sent_frames = 0;
	if (!item || !segs || !sent_frames) {
		trustix_tixt_tx_route_gso_stream_record(-EINVAL, 1, NULL, 0);
		return -EINVAL;
	}
	if (!READ_ONCE(trustix_route_tcp_gso_async_stream) &&
	    !(item->sync_redirect &&
	      READ_ONCE(trustix_route_tcp_gso_sync_stream)))
		return 0;
	if (READ_ONCE(trustix_route_tcp_gso_async_stream_direct_build))
		trustix_route_tcp_gso_async_stream_direct_fallbacks++;
	if (!READ_ONCE(trustix_route_tcp_gso_async_stream_software_segment)) {
		trustix_route_tcp_gso_async_stream_fallbacks++;
		trustix_tixt_tx_route_gso_stream_record(-EOPNOTSUPP, 1,
							NULL, 0);
		return 0;
	}

	if (item->sync_redirect &&
	    !READ_ONCE(trustix_route_tcp_gso_async_stream))
		max_frames = trustix_route_tcp_gso_sync_stream_max_frames_value();
	else
		max_frames = trustix_route_tcp_gso_async_stream_max_frames_value();
	mtu = trustix_tixt_tx_route_gso_stream_mtu(&item->tmpl);
	first_payload_len = min(payload_len, gso_payload_len);
	first_inner_len = sizeof(struct iphdr) + tcp_header_len +
			  first_payload_len;
	first_frame_len = TRUSTIX_TIXT_HEADER_LEN + first_inner_len;
	if (max_frames < 2 || !mtu ||
	    sizeof(struct iphdr) + sizeof(struct tcphdr) +
		    (first_frame_len * 2) > mtu) {
		trustix_route_tcp_gso_async_stream_fallbacks++;
		trustix_tixt_tx_route_gso_stream_record(-EOPNOTSUPP, 2,
							NULL, 0);
		return 0;
	}
	frames = kmalloc_array(max_frames, sizeof(*frames), GFP_KERNEL);
	if (!frames) {
		trustix_route_tcp_gso_async_stream_fallbacks++;
		trustix_tixt_tx_route_gso_stream_record(-ENOMEM, 9, NULL, 0);
		return 0;
	}

	sequence = item->sequence;
	batch_sequence = sequence;
	payload_remaining = payload_len;
	for (seg = segs; seg; seg = seg->next) {
		u32 seg_payload_len;
		u32 inner_len;
		u32 frame_len;
		u32 next_payload_len;
		u32 next_l3_len;

		if (unlikely(prepared >= segment_count ||
			     prepared >= TRUSTIX_TIXT_TX_GSO_MAX_SEGMENTS ||
			     !payload_remaining)) {
			ret = -EINVAL;
			stage = 3;
			goto fail;
		}
		seg_payload_len = min(payload_remaining, gso_payload_len);
		inner_len = sizeof(struct iphdr) + tcp_header_len +
			    seg_payload_len;
		frame_len = TRUSTIX_TIXT_HEADER_LEN + inner_len;
		if (seg->len < ETH_HLEN + inner_len ||
		    check_add_overflow(stream_payload_len, frame_len,
				       &next_payload_len) ||
		    check_add_overflow((u32)sizeof(struct iphdr) +
					       (u32)sizeof(struct tcphdr),
				       next_payload_len, &next_l3_len) ||
		    sizeof(struct iphdr) + sizeof(struct tcphdr) + frame_len >
			    mtu) {
			ret = -EMSGSIZE;
			stage = 4;
			goto fail;
		}
		if (frame_count &&
		    (frame_count >= max_frames || next_l3_len > mtu)) {
			ret = trustix_tixt_tx_route_gso_stream_send_batch(
				&item->tmpl, frames, frame_count,
				stream_payload_len,
				trustix_tixt_tx_plain_wire_sequence(
					batch_sequence),
				true);
			if (ret) {
				stage = 6;
				goto fail;
			}
			stream_packets++;
			stream_frames += frame_count;
			frame_count = 0;
			stream_payload_len = 0;
			batch_sequence = sequence;
		}
		if (seg->ip_summed == CHECKSUM_PARTIAL &&
		    !item->tmpl.trust_partial_inner_csum) {
			ret = skb_checksum_help(seg);
			if (ret) {
				stage = 5;
				goto fail;
			}
		}
		frames[frame_count].seg = seg;
		frames[frame_count].inner_len = inner_len;
		frames[frame_count].sequence =
			trustix_tixt_tx_plain_wire_sequence(sequence);
		frame_count++;
		stream_payload_len += frame_len;
		sequence += frame_len;
		payload_remaining -= seg_payload_len;
		prepared++;
	}
	if (!prepared || prepared != segment_count || payload_remaining) {
		ret = -EINVAL;
		stage = 7;
		goto fail;
	}
	if (frame_count) {
		ret = trustix_tixt_tx_route_gso_stream_send_batch(
			&item->tmpl, frames, frame_count, stream_payload_len,
			trustix_tixt_tx_plain_wire_sequence(batch_sequence),
			item->xmit_more);
		if (ret) {
			stage = 6;
			goto fail;
		}
		stream_packets++;
		stream_frames += frame_count;
	}
	if (!stream_packets || !stream_frames) {
		trustix_route_tcp_gso_async_stream_fallbacks++;
		trustix_tixt_tx_route_gso_stream_record(-EOPNOTSUPP, 8,
							NULL, 0);
		kfree(frames);
		return 0;
	}
	*sent_frames = stream_frames;
	kfree(frames);
	return 1;

fail:
	if (!stream_packets) {
		trustix_route_tcp_gso_async_stream_fallbacks++;
		trustix_tixt_tx_route_gso_stream_record(ret, stage, NULL, 0);
		kfree(frames);
		return 0;
	}
	trustix_route_tcp_gso_async_stream_errors++;
	trustix_tixt_tx_route_gso_stream_record(ret, stage, NULL, frame_count);
	*sent_frames = stream_frames;
	kfree(frames);
	return ret ? ret : -EIO;
}

static void trustix_tixt_tx_free_skb_list(struct sk_buff *skb)
{
	struct sk_buff *next;

	while (skb) {
		next = skb->next;
		skb->next = NULL;
		kfree_skb(skb);
		skb = next;
	}
}

static unsigned long trustix_route_tcp_gso_async_reserve_bytes(u32 len)
{
	long queued_after;

	if (!len)
		return READ_ONCE(trustix_route_tcp_gso_async_queued_bytes);
	queued_after = atomic_long_add_return(
		len, &trustix_route_tcp_gso_async_queued_bytes_atomic);
	if (queued_after < 0)
		queued_after = 0;
	WRITE_ONCE(trustix_route_tcp_gso_async_queued_bytes,
		   (unsigned long)queued_after);
	if ((unsigned long)queued_after >
	    READ_ONCE(trustix_route_tcp_gso_async_queued_bytes_high))
		WRITE_ONCE(trustix_route_tcp_gso_async_queued_bytes_high,
			   (unsigned long)queued_after);
	return (unsigned long)queued_after;
}

static void trustix_route_tcp_gso_async_release_bytes(u32 len)
{
	long queued_after;

	if (!len)
		return;
	queued_after = atomic_long_sub_return(
		len, &trustix_route_tcp_gso_async_queued_bytes_atomic);
	WRITE_ONCE(trustix_route_tcp_gso_async_queued_bytes,
		   queued_after > 0 ? (unsigned long)queued_after : 0);
}

static void trustix_tixt_tx_route_gso_async_complete(
				struct trustix_tixt_tx_route_gso_async_work *item)
{
	u32 queued_len;
	int inflight;

	if (!item)
		return;
	queued_len = READ_ONCE(item->queued_len);
	trustix_route_tcp_gso_async_release_bytes(queued_len);
	if (item->tmpl.out_dev)
		dev_put(item->tmpl.out_dev);
	if (item->skb)
		kfree_skb(item->skb);
	inflight = atomic_dec_return(&trustix_route_tcp_gso_async_inflight_atomic);
	WRITE_ONCE(trustix_route_tcp_gso_async_inflight,
		   inflight > 0 ? (unsigned int)inflight : 0);
	if (trustix_route_tcp_gso_async_work_cache)
		kmem_cache_free(trustix_route_tcp_gso_async_work_cache, item);
	else
		kfree(item);
}

static unsigned int trustix_route_tcp_gso_async_queue_shards_value(void)
{
	unsigned int shards = READ_ONCE(trustix_route_tcp_gso_async_queue_shards);

	if (!shards)
		return 1;
	if (shards > TRUSTIX_ROUTE_TCP_GSO_ASYNC_MAX_QUEUE_SHARDS)
		return TRUSTIX_ROUTE_TCP_GSO_ASYNC_MAX_QUEUE_SHARDS;
	return shards;
}

static unsigned int trustix_route_tcp_gso_async_queue_depth(
				const struct list_head *queue,
				unsigned int limit)
{
	struct trustix_tixt_tx_route_gso_async_work *item;
	unsigned int depth = 0;

	if (!queue || !limit)
		return 0;
	list_for_each_entry(item, queue, list) {
		if (++depth >= limit)
			break;
	}
	return depth;
}

static unsigned int
trustix_route_tcp_gso_async_cross_item_effective_max_frames(
				struct list_head *queue,
				spinlock_t *lock,
				bool queue_private,
				unsigned int stream_max_frames)
{
	unsigned int max_frames =
		trustix_route_tcp_gso_async_stream_cross_item_max_frames_value(
			stream_max_frames);
	unsigned int low_frames;
	unsigned int depth_target;
	bool depth_ready = false;

	if (!READ_ONCE(trustix_route_tcp_gso_async_stream_cross_item_dynamic_cap))
		return max_frames;

	low_frames =
		trustix_route_tcp_gso_async_stream_cross_item_dynamic_low_frames_value(
			max_frames);
	depth_target = READ_ONCE(
		trustix_route_tcp_gso_async_stream_cross_item_dynamic_queue_depth);
	if (!low_frames || !depth_target || low_frames >= max_frames)
		return max_frames;
	if (depth_target > TRUSTIX_TIXT_TX_ROUTE_STREAM_MAX_FRAMES)
		depth_target = TRUSTIX_TIXT_TX_ROUTE_STREAM_MAX_FRAMES;

	if (queue) {
		if (!queue_private && lock)
			spin_lock_bh(lock);
		if ((queue_private || lock) &&
		    trustix_route_tcp_gso_async_queue_depth(queue,
							   depth_target) >=
			    depth_target)
			depth_ready = true;
		if (!queue_private && lock)
			spin_unlock_bh(lock);
	}
	if (depth_ready) {
		trustix_route_tcp_gso_async_stream_cross_item_dynamic_cap_high++;
		return max_frames;
	}

	trustix_route_tcp_gso_async_stream_cross_item_dynamic_cap_low++;
	return low_frames;
}

static u32 trustix_route_tcp_gso_async_hash_mix(u32 hash)
{
	hash ^= hash >> 16;
	hash *= 0x7feb352dU;
	hash ^= hash >> 15;
	return hash ? hash : 1;
}

static u32 trustix_route_tcp_gso_async_flow_fallback_hash(u64 flow_id)
{
	u32 hash = (u32)flow_id ^ (u32)(flow_id >> 32);

	return trustix_route_tcp_gso_async_hash_mix(hash);
}

static bool
trustix_route_tcp_gso_async_same_inner_tcp_flow(
				const struct trustix_tixt_tx_route_gso_async_work *a,
				const struct trustix_tixt_tx_route_gso_async_work *b)
{
	return a && b && a->inner_flow_key_ready && b->inner_flow_key_ready &&
	       a->inner_flow_saddr == b->inner_flow_saddr &&
	       a->inner_flow_daddr == b->inner_flow_daddr &&
	       a->inner_flow_sport == b->inner_flow_sport &&
	       a->inner_flow_dport == b->inner_flow_dport;
}

static u32 trustix_route_tcp_gso_async_hash_skb(
				struct sk_buff *skb, u64 flow_id,
				struct trustix_tixt_tx_route_gso_async_work *item)
{
	const struct tcphdr *tcph;
	const struct iphdr *iph;
	unsigned int off;
	u32 hash;

	hash = (u32)flow_id ^ (u32)(flow_id >> 32);
	if (!skb)
		return trustix_route_tcp_gso_async_hash_mix(hash);
	if (skb_headlen(skb) < ETH_HLEN + sizeof(*iph))
		return trustix_route_tcp_gso_async_hash_mix(hash);
	iph = (const struct iphdr *)(skb->data + ETH_HLEN);
	if (iph->version != 4 || iph->ihl < 5)
		return trustix_route_tcp_gso_async_hash_mix(hash);
	off = ETH_HLEN + iph->ihl * 4;
	hash ^= (__force u32)iph->saddr;
	hash ^= ((__force u32)iph->daddr << 16) |
		((__force u32)iph->daddr >> 16);
	hash ^= (u32)iph->protocol << 24;
	if (iph->protocol == IPPROTO_TCP &&
	    skb_headlen(skb) >= off + sizeof(*tcph)) {
		tcph = (const struct tcphdr *)(skb->data + off);
		hash ^= ((u32)ntohs(tcph->source) << 16) |
			(u32)ntohs(tcph->dest);
		if (item) {
			item->inner_flow_saddr = iph->saddr;
			item->inner_flow_daddr = iph->daddr;
			item->inner_flow_sport = tcph->source;
			item->inner_flow_dport = tcph->dest;
			item->inner_tcp_seq_base = ntohl(tcph->seq);
			item->inner_flow_key_ready = true;
		}
	}
	return trustix_route_tcp_gso_async_hash_mix(hash);
}

static unsigned int trustix_tixt_tx_route_gso_async_process_item(
				struct trustix_tixt_tx_route_gso_async_work *item);
static unsigned long trustix_route_tcp_gso_async_budget_reschedule_delay(void);
static bool trustix_route_tcp_gso_async_cross_item_enabled(void);

struct trustix_route_tcp_gso_async_cross_item_batch {
	struct trustix_tixt_tx_route_gso_async_work *items[
		TRUSTIX_TIXT_TX_ROUTE_STREAM_MAX_FRAMES];
	bool complete_item[TRUSTIX_TIXT_TX_ROUTE_STREAM_MAX_FRAMES];
	struct trustix_tixt_tx_route_gso_stream_direct_ref refs[
		TRUSTIX_TIXT_TX_ROUTE_STREAM_MAX_FRAMES];
	unsigned int item_count;
	unsigned int frame_count;
	u32 stream_payload_len;
	u32 outer_gso_size;
	u32 last_frame_len;
	u32 next_inner_tcp_seq;
	u64 outer_sequence;
	u64 next_sequence;
	u64 next_frame_sequence;
	bool fix_inner_csum;
};

static struct trustix_route_tcp_gso_async_cross_item_batch *
trustix_route_tcp_gso_async_cross_item_batch_alloc(void)
{
	if (trustix_route_tcp_gso_async_cross_item_cache)
		return kmem_cache_zalloc(
			trustix_route_tcp_gso_async_cross_item_cache,
			GFP_KERNEL);
	return kzalloc(sizeof(struct trustix_route_tcp_gso_async_cross_item_batch),
		       GFP_KERNEL);
}

static void trustix_route_tcp_gso_async_cross_item_batch_free(
				struct trustix_route_tcp_gso_async_cross_item_batch *batch)
{
	if (!batch)
		return;
	if (trustix_route_tcp_gso_async_cross_item_cache)
		kmem_cache_free(trustix_route_tcp_gso_async_cross_item_cache,
				batch);
	else
		kfree(batch);
}

static bool
trustix_route_tcp_gso_async_cross_item_template_match(
				const struct trustix_tixt_tx_route_gso_async_work *a,
				const struct trustix_tixt_tx_route_gso_async_work *b)
{
	if (!a || !b)
		return false;
	if (a->flow_id != b->flow_id ||
	    a->queue_hash != b->queue_hash ||
	    a->route_flow_mask != b->route_flow_mask ||
	    a->tmpl.out_dev != b->tmpl.out_dev ||
	    a->tmpl.saddr != b->tmpl.saddr ||
	    a->tmpl.daddr != b->tmpl.daddr ||
	    a->tmpl.mtu != b->tmpl.mtu ||
	    a->tmpl.ip_check_base != b->tmpl.ip_check_base ||
	    a->tmpl.tx_queue_mapping != b->tmpl.tx_queue_mapping ||
	    a->tmpl.partial_csum != b->tmpl.partial_csum ||
	    a->tmpl.trust_inner_csum != b->tmpl.trust_inner_csum ||
	    a->tmpl.trust_partial_inner_csum !=
		    b->tmpl.trust_partial_inner_csum ||
	    a->tmpl.secure != b->tmpl.secure ||
	    a->tmpl.kernel_udp != b->tmpl.kernel_udp ||
	    a->tmpl.use_tx_queue_mapping != b->tmpl.use_tx_queue_mapping ||
	    a->tmpl.stream_outer_gso != b->tmpl.stream_outer_gso ||
	    a->tcp_header_len != b->tcp_header_len ||
	    a->gso_payload_len != b->gso_payload_len ||
	    a->gso_features != b->gso_features)
		return false;
	if (a->tmpl.secure &&
	    (a->secure_slot_id != b->secure_slot_id ||
	     a->secure_suite != b->secure_suite ||
	     a->secure_epoch != b->secure_epoch ||
	     memcmp(a->secure_iv, b->secure_iv, sizeof(a->secure_iv))))
		return false;
	return !memcmp(a->tmpl.base, b->tmpl.base, sizeof(a->tmpl.base));
}

static u64
trustix_route_tcp_gso_async_item_outer_sequence(
				const struct trustix_tixt_tx_route_gso_async_work *item)
{
	if (!item)
		return 0;
	return item->tmpl.secure ? item->outer_sequence : item->sequence;
}

static u64
trustix_route_tcp_gso_async_item_frame_sequence_cost(
				const struct trustix_tixt_tx_route_gso_async_work *item)
{
	if (!item)
		return 0;
	return item->tmpl.secure ? item->segment_count : item->sequence_cost;
}

static bool
trustix_route_tcp_gso_async_fix_inner_csum(
				const struct trustix_tixt_tx_route_gso_async_work *item)
{
	return (item && item->tmpl.secure &&
		!item->tmpl.trust_partial_inner_csum) ||
	       READ_ONCE(trustix_route_tcp_gso_async_stream_direct_build_inner_csum);
}

static bool
trustix_route_tcp_gso_async_cross_item_full_tail(
				const struct trustix_tixt_tx_route_gso_async_work *item)
{
	return item && item->gso_payload_len &&
	       item->payload_len % item->gso_payload_len == 0;
}

static bool
trustix_route_tcp_gso_async_cross_item_payload_room(u32 stream_payload_len,
						    u64 append_len)
{
	const u32 stream_payload_limit = 0xffffU - sizeof(struct iphdr) -
					 sizeof(struct tcphdr);

	if (stream_payload_len > stream_payload_limit)
		return false;
	if (append_len > (u64)(stream_payload_limit - stream_payload_len))
		return false;
	return true;
}

static void trustix_route_tcp_gso_async_cross_item_record_miss(unsigned int reason)
{
	if (!READ_ONCE(trustix_route_tcp_gso_async_stream_cross_item_debug))
		return;
	switch (reason) {
	case 1:
		trustix_route_tcp_gso_async_stream_cross_item_skip_disabled++;
		break;
	case 2:
		trustix_route_tcp_gso_async_stream_cross_item_skip_first_shape++;
		break;
	case 3:
		trustix_route_tcp_gso_async_stream_cross_item_skip_first_tail++;
		break;
	case 4:
		trustix_route_tcp_gso_async_stream_cross_item_skip_first_room++;
		break;
	case 5:
		trustix_route_tcp_gso_async_stream_cross_item_skip_no_next++;
		break;
	case 6:
		trustix_route_tcp_gso_async_stream_cross_item_skip_candidate_shape++;
		break;
	case 7:
		trustix_route_tcp_gso_async_stream_cross_item_skip_candidate_room++;
		break;
	case 8:
		trustix_route_tcp_gso_async_stream_cross_item_skip_candidate_sequence++;
		break;
	case 9:
		trustix_route_tcp_gso_async_stream_cross_item_skip_candidate_template++;
		break;
	default:
		break;
	}
}

static void
trustix_route_tcp_gso_async_cross_item_record_result(
				int ret, unsigned int stage,
				const struct trustix_route_tcp_gso_async_cross_item_batch *batch)
{
	unsigned int first_frame_len = 0;

	if (batch && batch->frame_count && batch->refs[0].frame.inner_len)
		first_frame_len = TRUSTIX_TIXT_HEADER_LEN +
				  batch->refs[0].frame.inner_len;
	WRITE_ONCE(trustix_route_tcp_gso_async_stream_cross_item_last_ret,
		   ret);
	WRITE_ONCE(trustix_route_tcp_gso_async_stream_cross_item_last_stage,
		   stage);
	WRITE_ONCE(trustix_route_tcp_gso_async_stream_cross_item_last_items,
		   batch ? batch->item_count : 0);
	WRITE_ONCE(trustix_route_tcp_gso_async_stream_cross_item_last_frames,
		   batch ? batch->frame_count : 0);
	WRITE_ONCE(trustix_route_tcp_gso_async_stream_cross_item_last_stream_payload_len,
		   batch ? batch->stream_payload_len : 0);
	WRITE_ONCE(trustix_route_tcp_gso_async_stream_cross_item_last_outer_gso_size,
		   batch ? batch->outer_gso_size : 0);
	WRITE_ONCE(trustix_route_tcp_gso_async_stream_cross_item_last_first_frame_len,
		   first_frame_len);
	WRITE_ONCE(trustix_route_tcp_gso_async_stream_cross_item_last_last_frame_len,
		   batch ? batch->last_frame_len : 0);
}

static bool
trustix_route_tcp_gso_async_cross_item_candidate(
				const struct trustix_tixt_tx_route_gso_async_work *first,
				const struct trustix_tixt_tx_route_gso_async_work *item,
				u64 expected_outer_sequence,
				u64 expected_frame_sequence,
				u32 expected_inner_tcp_seq,
				unsigned int frame_count,
				u32 stream_payload_len,
				unsigned int max_frames,
				unsigned int *reason)
{
	if (reason)
		*reason = 0;
	if (!first || !item || !item->skb)
		return false;
	if (item->resliced || !item->sequence_cost || !item->segment_count ||
	    item->segment_count > max_frames ||
	    frame_count + item->segment_count > max_frames) {
		if (reason)
			*reason = 1;
		return false;
	}
	if (!trustix_route_tcp_gso_async_cross_item_payload_room(
		    stream_payload_len, item->sequence_cost)) {
		if (reason)
			*reason = 2;
		return false;
	}
	if (item->tmpl.secure) {
		if (item->outer_sequence != expected_outer_sequence ||
		    item->sequence != expected_frame_sequence) {
			if (reason)
				*reason = 3;
			return false;
		}
	} else if (trustix_tixt_tx_plain_skip_sequence_enabled()) {
		if (!trustix_route_tcp_gso_async_same_inner_tcp_flow(first,
								    item)) {
			if (reason)
				*reason = 4;
			return false;
		}
		if (item->inner_tcp_seq_base != expected_inner_tcp_seq) {
			if (reason)
				*reason = 3;
			return false;
		}
	} else if (!trustix_tixt_tx_plain_skip_sequence_enabled() &&
		   item->sequence != expected_outer_sequence) {
		if (reason)
			*reason = 3;
		return false;
	}
	if (!trustix_route_tcp_gso_async_cross_item_template_match(first,
								  item)) {
		if (reason)
			*reason = 4;
		return false;
	}
	return true;
}

static void
trustix_route_tcp_gso_async_cross_item_record_candidate_miss(
				unsigned int reason)
{
	if (reason == 1)
		trustix_route_tcp_gso_async_cross_item_record_miss(6);
	else if (reason == 2)
		trustix_route_tcp_gso_async_cross_item_record_miss(7);
	else if (reason == 3)
		trustix_route_tcp_gso_async_cross_item_record_miss(8);
	else if (reason == 4)
		trustix_route_tcp_gso_async_cross_item_record_miss(9);
}

static unsigned int
trustix_route_tcp_gso_async_cross_item_lookahead_value(void)
{
	unsigned int value =
		READ_ONCE(trustix_route_tcp_gso_async_stream_cross_item_lookahead);

	if (!value)
		return 0;
	return min_t(unsigned int, value,
		     TRUSTIX_ROUTE_TCP_GSO_ASYNC_CROSS_ITEM_LOOKAHEAD_MAX);
}

static bool
trustix_route_tcp_gso_async_cross_item_same_stream(
				const struct trustix_tixt_tx_route_gso_async_work *first,
				const struct trustix_tixt_tx_route_gso_async_work *item)
{
	if (!first || !item)
		return false;
	if (trustix_tixt_tx_plain_skip_sequence_enabled() &&
	    !first->tmpl.secure && !item->tmpl.secure) {
		if (first->inner_flow_key_ready && item->inner_flow_key_ready)
			return trustix_route_tcp_gso_async_same_inner_tcp_flow(
				first, item);
		return first->queue_hash == item->queue_hash;
	}
	if (first->flow_id == item->flow_id)
		return true;
	return trustix_route_tcp_gso_async_cross_item_template_match(first,
								    item);
}

static struct trustix_tixt_tx_route_gso_async_work *
trustix_route_tcp_gso_async_cross_item_find_locked(
				struct list_head *queue,
				const struct trustix_tixt_tx_route_gso_async_work *first,
				u64 expected_outer_sequence,
				u64 expected_frame_sequence,
				u32 expected_inner_tcp_seq,
				unsigned int frame_count,
				u32 stream_payload_len,
				unsigned int max_frames,
				bool remove,
				bool record_lookahead,
				unsigned int *reason_out)
{
	struct trustix_tixt_tx_route_gso_async_work *item;
	struct trustix_tixt_tx_route_gso_async_work *tmp;
	unsigned int lookahead =
		trustix_route_tcp_gso_async_cross_item_lookahead_value();
	unsigned int scan_limit = lookahead ? lookahead : 1;
	unsigned int scanned = 0;
	unsigned int reason = 0;

	if (reason_out)
		*reason_out = 0;
	if (!queue || list_empty(queue))
		return NULL;

	list_for_each_entry_safe(item, tmp, queue, list) {
		unsigned int candidate_reason = 0;
		bool same_stream;

		if (++scanned > scan_limit)
			break;
		if (record_lookahead && lookahead)
			trustix_route_tcp_gso_async_stream_cross_item_lookahead_scans++;
		if (trustix_route_tcp_gso_async_cross_item_candidate(
			    first, item, expected_outer_sequence,
			    expected_frame_sequence, expected_inner_tcp_seq,
			    frame_count,
			    stream_payload_len, max_frames,
			    &candidate_reason)) {
			if (record_lookahead && lookahead && scanned > 1)
				trustix_route_tcp_gso_async_stream_cross_item_lookahead_hits++;
			if (remove)
				list_del_init(&item->list);
			if (reason_out)
				*reason_out = 0;
			return item;
		}

		same_stream =
			trustix_route_tcp_gso_async_cross_item_same_stream(first,
									  item);
		if (!reason)
			reason = candidate_reason;
		if (same_stream) {
			if (record_lookahead && lookahead)
				trustix_route_tcp_gso_async_stream_cross_item_lookahead_blocked++;
			reason = candidate_reason;
			break;
		}

		if (!lookahead) {
			reason = candidate_reason;
			break;
		}
	}

	if (record_lookahead && lookahead)
		trustix_route_tcp_gso_async_stream_cross_item_lookahead_misses++;
	if (reason_out)
		*reason_out = reason;
	return NULL;
}

static int
trustix_route_tcp_gso_async_cross_item_collect(
				struct trustix_route_tcp_gso_async_cross_item_batch *batch,
				struct trustix_tixt_tx_route_gso_async_work *item,
				unsigned int max_frames)
{
	u32 payload_remaining;
	u32 payload_offset = 0;
	u32 prepared = 0;
	u32 frame_payload_extra;
	u32 mtu;
	int ret;

	if (!batch || !item || !item->skb || !max_frames)
		return -EINVAL;
	if (item->resliced || !item->segment_count ||
	    batch->frame_count + item->segment_count > max_frames)
		return -EOPNOTSUPP;
	mtu = trustix_tixt_tx_route_gso_stream_mtu(&item->tmpl);
	if (!mtu)
		return -EMSGSIZE;
	ret = trustix_tixt_tx_route_gso_async_prepare_inner_header(item);
	if (ret)
		return ret;

	frame_payload_extra = item->tmpl.secure ?
		TRUSTIX_TIXT_TX_SECURE_PAYLOAD_OVERHEAD : 0;
	payload_remaining = item->payload_len;
	while (prepared < item->segment_count && payload_remaining) {
		struct trustix_tixt_tx_route_gso_stream_direct_ref *ref;
		u32 seg_payload_len = min(payload_remaining,
					  item->gso_payload_len);
		u32 plain_inner_len;
		u32 inner_len;
		u32 frame_len;
		u32 next_payload_len;
		u32 next_l3_len;

		if (check_add_overflow((u32)sizeof(struct iphdr) +
					       item->tcp_header_len,
				       seg_payload_len, &plain_inner_len) ||
		    check_add_overflow(plain_inner_len, frame_payload_extra,
				       &inner_len) ||
		    check_add_overflow((u32)TRUSTIX_TIXT_HEADER_LEN,
				       inner_len, &frame_len) ||
		    sizeof(struct iphdr) + sizeof(struct tcphdr) + frame_len >
			    mtu)
			return -EMSGSIZE;
		if (!batch->outer_gso_size)
			batch->outer_gso_size = frame_len;
		if (frame_len > batch->outer_gso_size)
			return -EOPNOTSUPP;
		if (batch->frame_count &&
		    batch->last_frame_len != batch->outer_gso_size)
			return -EOPNOTSUPP;
		if (frame_len != batch->outer_gso_size &&
		    prepared + 1 < item->segment_count)
			return -EOPNOTSUPP;
		if (check_add_overflow(batch->stream_payload_len, frame_len,
				       &next_payload_len) ||
		    check_add_overflow((u32)sizeof(struct iphdr) +
					       (u32)sizeof(struct tcphdr),
				       next_payload_len, &next_l3_len))
			return -EOVERFLOW;
		if (next_l3_len > 0xffff || batch->frame_count >= max_frames)
			return -EMSGSIZE;

		ref = &batch->refs[batch->frame_count];
		ref->item = item;
		ref->frame.sequence = item->tmpl.secure ?
			batch->next_frame_sequence :
			trustix_tixt_tx_plain_wire_sequence(batch->next_sequence);
		ref->frame.payload_offset = payload_offset;
		ref->frame.payload_len = seg_payload_len;
		ref->frame.inner_len = inner_len;
		ref->frame.plain_inner_len =
			item->tmpl.secure ? plain_inner_len : 0;
		batch->frame_count++;
		batch->stream_payload_len = next_payload_len;
		batch->last_frame_len = frame_len;
		batch->next_sequence += frame_len;
		batch->next_frame_sequence += item->tmpl.secure ? 1 :
			frame_len;
		if (!item->tmpl.secure &&
		    trustix_tixt_tx_plain_skip_sequence_enabled())
			batch->next_inner_tcp_seq =
				item->inner_tcp_seq_base + item->payload_len;
		payload_offset += seg_payload_len;
		payload_remaining -= seg_payload_len;
		prepared++;
	}
	if (prepared != item->segment_count || payload_remaining)
		return -EINVAL;
	return 0;
}

static int
trustix_route_tcp_gso_async_cross_item_collect_range(
				struct trustix_route_tcp_gso_async_cross_item_batch *batch,
				struct trustix_tixt_tx_route_gso_async_work *item,
				unsigned int start_frame,
				unsigned int frame_count,
				unsigned int max_frames)
{
	u32 payload_remaining;
	u32 payload_offset = 0;
	u32 prepared = 0;
	unsigned int stop_frame;
	u32 frame_payload_extra;
	u32 mtu;
	int ret;

	if (!batch || !item || !item->skb || !max_frames)
		return -EINVAL;
	if (item->resliced || !item->segment_count ||
	    start_frame >= item->segment_count || !frame_count ||
	    check_add_overflow(start_frame, frame_count, &stop_frame) ||
	    stop_frame > item->segment_count ||
	    batch->frame_count + frame_count > max_frames)
		return -EOPNOTSUPP;
	mtu = trustix_tixt_tx_route_gso_stream_mtu(&item->tmpl);
	if (!mtu)
		return -EMSGSIZE;
	ret = trustix_tixt_tx_route_gso_async_prepare_inner_header(item);
	if (ret)
		return ret;

	frame_payload_extra = item->tmpl.secure ?
		TRUSTIX_TIXT_TX_SECURE_PAYLOAD_OVERHEAD : 0;
	payload_remaining = item->payload_len;
	while (prepared < item->segment_count && payload_remaining) {
		struct trustix_tixt_tx_route_gso_stream_direct_ref *ref;
		u32 seg_payload_len = min(payload_remaining,
					  item->gso_payload_len);
		u32 plain_inner_len;
		u32 inner_len;
		u32 frame_len;
		u32 next_payload_len;
		u32 next_l3_len;

		if (prepared < start_frame) {
			payload_offset += seg_payload_len;
			payload_remaining -= seg_payload_len;
			prepared++;
			continue;
		}
		if (prepared >= stop_frame)
			break;
		if (check_add_overflow((u32)sizeof(struct iphdr) +
					       item->tcp_header_len,
				       seg_payload_len, &plain_inner_len) ||
		    check_add_overflow(plain_inner_len, frame_payload_extra,
				       &inner_len) ||
		    check_add_overflow((u32)TRUSTIX_TIXT_HEADER_LEN,
				       inner_len, &frame_len) ||
		    sizeof(struct iphdr) + sizeof(struct tcphdr) + frame_len >
			    mtu)
			return -EMSGSIZE;
		if (!batch->outer_gso_size)
			batch->outer_gso_size = frame_len;
		if (frame_len > batch->outer_gso_size)
			return -EOPNOTSUPP;
		if (batch->frame_count &&
		    batch->last_frame_len != batch->outer_gso_size)
			return -EOPNOTSUPP;
		if (frame_len != batch->outer_gso_size &&
		    prepared + 1 < item->segment_count)
			return -EOPNOTSUPP;
		if (check_add_overflow(batch->stream_payload_len, frame_len,
				       &next_payload_len) ||
		    check_add_overflow((u32)sizeof(struct iphdr) +
					       (u32)sizeof(struct tcphdr),
				       next_payload_len, &next_l3_len))
			return -EOVERFLOW;
		if (next_l3_len > 0xffff || batch->frame_count >= max_frames)
			return -EMSGSIZE;

		ref = &batch->refs[batch->frame_count];
		ref->item = item;
		ref->frame.sequence = item->tmpl.secure ?
			batch->next_frame_sequence :
			trustix_tixt_tx_plain_wire_sequence(batch->next_sequence);
		ref->frame.payload_offset = payload_offset;
		ref->frame.payload_len = seg_payload_len;
		ref->frame.inner_len = inner_len;
		ref->frame.plain_inner_len =
			item->tmpl.secure ? plain_inner_len : 0;
		batch->frame_count++;
		batch->stream_payload_len = next_payload_len;
		batch->last_frame_len = frame_len;
		batch->next_sequence += frame_len;
		batch->next_frame_sequence += item->tmpl.secure ? 1 :
			frame_len;
		if (!item->tmpl.secure &&
		    trustix_tixt_tx_plain_skip_sequence_enabled())
			batch->next_inner_tcp_seq =
				item->inner_tcp_seq_base + payload_offset +
				seg_payload_len;
		payload_offset += seg_payload_len;
		payload_remaining -= seg_payload_len;
		prepared++;
	}
	if (prepared != stop_frame)
		return -EINVAL;
	return 0;
}

static int
trustix_route_tcp_gso_async_direct_prefix_frames(
				struct trustix_tixt_tx_route_gso_async_work *item,
				struct trustix_tixt_tx_route_gso_stream_direct_frame *frames,
				unsigned int frame_count,
				u32 *stream_payload_len_out)
{
	u32 payload_remaining;
	u32 payload_offset = 0;
	u32 stream_payload_len = 0;
	u64 sequence;
	unsigned int prepared = 0;
	u32 mtu;
	int ret;

	if (!item || !item->skb || !frames || !frame_count ||
	    !stream_payload_len_out)
		return -EINVAL;
	if (item->resliced || !item->segment_count ||
	    frame_count > item->segment_count ||
	    frame_count > TRUSTIX_TIXT_TX_ROUTE_STREAM_MAX_FRAMES)
		return -EOPNOTSUPP;
	mtu = trustix_tixt_tx_route_gso_stream_mtu(&item->tmpl);
	if (!mtu)
		return -EMSGSIZE;
	ret = trustix_tixt_tx_route_gso_async_prepare_inner_header(item);
	if (ret)
		return ret;

	sequence = item->sequence;
	payload_remaining = item->payload_len;
	while (prepared < frame_count && payload_remaining) {
		u32 seg_payload_len = min(payload_remaining,
					  item->gso_payload_len);
		u32 inner_len;
		u32 frame_len;
		u32 next_payload_len;
		u32 next_l3_len;

		if (check_add_overflow((u32)sizeof(struct iphdr) +
					       item->tcp_header_len,
				       seg_payload_len, &inner_len) ||
		    check_add_overflow((u32)TRUSTIX_TIXT_HEADER_LEN,
				       inner_len, &frame_len) ||
		    check_add_overflow(stream_payload_len, frame_len,
				       &next_payload_len) ||
		    check_add_overflow((u32)sizeof(struct iphdr) +
					       (u32)sizeof(struct tcphdr),
				       next_payload_len, &next_l3_len) ||
		    sizeof(struct iphdr) + sizeof(struct tcphdr) + frame_len >
			    mtu ||
		    next_l3_len > 0xffff)
			return -EMSGSIZE;

		frames[prepared].sequence =
			trustix_tixt_tx_plain_wire_sequence(sequence);
		frames[prepared].payload_offset = payload_offset;
		frames[prepared].payload_len = seg_payload_len;
		frames[prepared].inner_len = inner_len;
		stream_payload_len = next_payload_len;
		sequence += frame_len;
		payload_offset += seg_payload_len;
		payload_remaining -= seg_payload_len;
		prepared++;
	}
	if (prepared != frame_count)
		return -EINVAL;
	*stream_payload_len_out = stream_payload_len;
	return 0;
}

static unsigned int
trustix_route_tcp_gso_async_cross_item_fallback(
				struct trustix_route_tcp_gso_async_cross_item_batch *batch)
{
	unsigned int i;
	unsigned int sent = 0;

	if (!batch)
		return 0;
	for (i = 0; i < batch->item_count; i++) {
		if (batch->complete_item[i]) {
			trustix_tixt_tx_route_gso_async_complete(batch->items[i]);
			continue;
		}
		sent += trustix_tixt_tx_route_gso_async_process_item(
			batch->items[i]);
	}
	trustix_route_tcp_gso_async_stream_cross_item_fallbacks++;
	return sent;
}

static unsigned int
trustix_route_tcp_gso_async_process_cross_item_batch(
				struct trustix_route_tcp_gso_async_cross_item_batch *batch)
{
	unsigned int i;
	int ret;

	if (!batch || batch->item_count < 2 || batch->frame_count < 2) {
		trustix_route_tcp_gso_async_cross_item_record_result(
			-EINVAL, 1, batch);
		return trustix_route_tcp_gso_async_cross_item_fallback(batch);
	}
	ret = trustix_tixt_tx_route_gso_stream_send_direct_ref_batch(
		&batch->items[0]->tmpl, batch->refs, batch->frame_count,
		batch->stream_payload_len,
		batch->items[0]->tmpl.secure ? batch->outer_sequence :
			trustix_tixt_tx_plain_wire_sequence(
				batch->outer_sequence),
		batch->fix_inner_csum, false);
	if (ret) {
		trustix_route_tcp_gso_async_cross_item_record_result(
			ret, 2, batch);
		trustix_route_tcp_gso_async_stream_cross_item_errors++;
		return trustix_route_tcp_gso_async_cross_item_fallback(batch);
	}
	trustix_route_tcp_gso_async_cross_item_record_result(0, 0, batch);
	trustix_route_tcp_gso_async_stream_cross_item_batches++;
	trustix_route_tcp_gso_async_stream_cross_item_items +=
		batch->item_count;
	trustix_route_tcp_gso_async_stream_cross_item_frames +=
		batch->frame_count;
	for (i = 0; i < batch->item_count; i++)
		trustix_tixt_tx_route_gso_async_complete(batch->items[i]);
	return batch->frame_count;
}

static __always_inline void
trustix_route_tcp_gso_async_candidate_queue_lock(spinlock_t *lock,
						 bool queue_private)
{
	if (!queue_private && lock)
		spin_lock_bh(lock);
}

static __always_inline void
trustix_route_tcp_gso_async_candidate_queue_unlock(spinlock_t *lock,
						   bool queue_private)
{
	if (!queue_private && lock)
		spin_unlock_bh(lock);
}

static unsigned int
trustix_route_tcp_gso_async_worker_try_cross_item_batch_dequeue(
				struct list_head *queue, spinlock_t *lock,
				bool queue_private,
				struct trustix_tixt_tx_route_gso_async_work *first,
				u32 first_stream_payload_len,
				unsigned int max_frames,
				unsigned int *items_out)
{
	struct trustix_tixt_tx_route_gso_async_work *collected[
		TRUSTIX_TIXT_TX_ROUTE_STREAM_MAX_FRAMES];
	struct trustix_route_tcp_gso_async_cross_item_batch *batch;
	struct trustix_tixt_tx_route_gso_async_work *item;
	u32 stream_payload_len = first_stream_payload_len;
	u64 next_outer_sequence =
		trustix_route_tcp_gso_async_item_outer_sequence(first) +
		first->sequence_cost;
	u64 next_frame_sequence = first->sequence +
		trustix_route_tcp_gso_async_item_frame_sequence_cost(first);
	u32 next_inner_tcp_seq = first->inner_tcp_seq_base + first->payload_len;
	unsigned int frame_count = first->segment_count;
	unsigned int collected_count = 0;
	unsigned int reason = 0;
	unsigned int i;
	unsigned int sent;
	int ret;

	if (items_out)
		*items_out = 0;
	if (!READ_ONCE(trustix_route_tcp_gso_async_stream_cross_item_dequeue_batch))
		return 0;
	if (max_frames <= first->segment_count ||
	    max_frames > ARRAY_SIZE(collected))
		return 0;

	trustix_route_tcp_gso_async_candidate_queue_lock(lock, queue_private);
	while (!list_empty(queue) &&
	       collected_count + 1 < ARRAY_SIZE(collected)) {
		item = trustix_route_tcp_gso_async_cross_item_find_locked(
			queue, first, next_outer_sequence, next_frame_sequence,
			next_inner_tcp_seq, frame_count, stream_payload_len,
			max_frames, true, true, &reason);
		if (!item)
			break;
		collected[collected_count++] = item;
		next_outer_sequence += item->sequence_cost;
		next_frame_sequence +=
			trustix_route_tcp_gso_async_item_frame_sequence_cost(item);
		next_inner_tcp_seq += item->payload_len;
		stream_payload_len += (u32)item->sequence_cost;
		frame_count += item->segment_count;
		if (frame_count >= max_frames ||
		    !trustix_route_tcp_gso_async_cross_item_full_tail(item))
			break;
	}
	trustix_route_tcp_gso_async_candidate_queue_unlock(lock, queue_private);

	if (!collected_count) {
		trustix_route_tcp_gso_async_cross_item_record_candidate_miss(
			reason);
		return 0;
	}

	batch = trustix_route_tcp_gso_async_cross_item_batch_alloc();
	if (!batch) {
		trustix_route_tcp_gso_async_stream_cross_item_errors++;
		sent = trustix_tixt_tx_route_gso_async_process_item(first);
		for (i = 0; i < collected_count; i++)
			sent += trustix_tixt_tx_route_gso_async_process_item(
				collected[i]);
		if (items_out)
			*items_out = 1 + collected_count;
		return sent;
	}
	batch->items[0] = first;
	batch->item_count = 1;
	batch->outer_sequence =
		trustix_route_tcp_gso_async_item_outer_sequence(first);
	batch->next_sequence = batch->outer_sequence;
	batch->next_frame_sequence = first->sequence;
	batch->next_inner_tcp_seq = first->inner_tcp_seq_base;
	batch->fix_inner_csum =
		trustix_route_tcp_gso_async_fix_inner_csum(first);
	ret = trustix_route_tcp_gso_async_cross_item_collect(batch, first,
							    max_frames);
	if (ret) {
		trustix_route_tcp_gso_async_cross_item_record_result(
			ret, 3, batch);
		trustix_route_tcp_gso_async_stream_cross_item_errors++;
		sent = trustix_route_tcp_gso_async_cross_item_fallback(batch);
		trustix_route_tcp_gso_async_cross_item_batch_free(batch);
		for (i = 0; i < collected_count; i++)
			sent += trustix_tixt_tx_route_gso_async_process_item(
				collected[i]);
		if (items_out)
			*items_out = 1 + collected_count;
		return sent;
	}

	for (i = 0; i < collected_count; i++) {
		item = collected[i];
		if (batch->frame_count >= max_frames ||
		    batch->item_count >= ARRAY_SIZE(batch->items) ||
		    batch->last_frame_len != batch->outer_gso_size)
			break;
		ret = trustix_route_tcp_gso_async_cross_item_collect(
			batch, item, max_frames);
		batch->items[batch->item_count++] = item;
		if (ret) {
			trustix_route_tcp_gso_async_cross_item_record_result(
				ret, 4, batch);
			trustix_route_tcp_gso_async_stream_cross_item_errors++;
			sent = trustix_route_tcp_gso_async_cross_item_fallback(
				batch);
			trustix_route_tcp_gso_async_cross_item_batch_free(batch);
			for (i++; i < collected_count; i++)
				sent += trustix_tixt_tx_route_gso_async_process_item(
					collected[i]);
			if (items_out)
				*items_out = 1 + collected_count;
			return sent;
		}
	}
	for (; i < collected_count; i++) {
		batch->items[batch->item_count++] = collected[i];
		trustix_route_tcp_gso_async_cross_item_record_result(
			-EOPNOTSUPP, 5, batch);
		trustix_route_tcp_gso_async_stream_cross_item_errors++;
		sent = trustix_route_tcp_gso_async_cross_item_fallback(batch);
		trustix_route_tcp_gso_async_cross_item_batch_free(batch);
		for (i++; i < collected_count; i++)
			sent += trustix_tixt_tx_route_gso_async_process_item(
				collected[i]);
		if (items_out)
			*items_out = 1 + collected_count;
		return sent;
	}

	if (items_out)
		*items_out = batch->item_count;
	trustix_route_tcp_gso_async_stream_cross_item_dequeue_batches++;
	trustix_route_tcp_gso_async_stream_cross_item_dequeue_items +=
		batch->item_count;
	sent = trustix_route_tcp_gso_async_process_cross_item_batch(batch);
	trustix_route_tcp_gso_async_cross_item_batch_free(batch);
	return sent;
}

static bool
trustix_route_tcp_gso_async_worker_try_tail_stitch(
				struct list_head *queue, spinlock_t *lock,
				bool queue_private,
				struct trustix_tixt_tx_route_gso_async_work *first,
				bool queue_had_next,
				unsigned int *sent_out,
				unsigned int *items_out)
{
	struct trustix_route_tcp_gso_async_cross_item_batch *batch;
	struct trustix_tixt_tx_route_gso_async_work *item;
	const u32 stream_payload_limit = 0xffffU - sizeof(struct iphdr) -
					 sizeof(struct tcphdr);
	u32 frame_len;
	u32 inner_len;
	u32 prefix_payload_len;
	u32 tail_payload_len;
	u32 prefix_stream_payload_len;
	unsigned int max_frames;
	unsigned int prefix_frames;
	unsigned int tail_frames;
	unsigned int fit_frames;
	unsigned int reason;
	unsigned int sent = 0;
	int ret;

	if (sent_out)
		*sent_out = 0;
	if (items_out)
		*items_out = 0;
	if (!READ_ONCE(trustix_route_tcp_gso_async_stream_cross_item_tail_stitch) ||
	    !queue_had_next || !first || !first->skb || first->resliced ||
	    first->tmpl.secure ||
	    first->route_flow_mask ||
	    !trustix_route_tcp_gso_async_cross_item_enabled() ||
	    trustix_tixt_tx_plain_skip_sequence_enabled())
		return false;
	if (!trustix_route_tcp_gso_async_cross_item_full_tail(first))
		return false;
	max_frames = trustix_route_tcp_gso_async_cross_item_effective_max_frames(
		queue, lock, queue_private,
		trustix_route_tcp_gso_async_stream_max_frames_value());
	if (max_frames < 3 ||
	    first->segment_count < 3 ||
	    first->segment_count > max_frames ||
	    first->segment_count > TRUSTIX_TIXT_TX_ROUTE_STREAM_MAX_FRAMES)
		return false;
	if (trustix_route_tcp_gso_async_cross_item_payload_room(
		    0, first->sequence_cost))
		return false;
	if (check_add_overflow((u32)sizeof(struct iphdr) +
				       first->tcp_header_len,
			       first->gso_payload_len, &inner_len) ||
	    check_add_overflow((u32)TRUSTIX_TIXT_HEADER_LEN, inner_len,
			       &frame_len) ||
	    !frame_len || frame_len > stream_payload_limit)
		return false;
	fit_frames = min_t(unsigned int, max_frames,
			   stream_payload_limit / frame_len);
	if (fit_frames < 2 || fit_frames >= first->segment_count)
		return false;
	prefix_frames = fit_frames;
	tail_frames = first->segment_count - prefix_frames;
	if (!tail_frames ||
	    check_mul_overflow((u32)prefix_frames, frame_len,
			       &prefix_payload_len) ||
	    check_mul_overflow((u32)tail_frames, frame_len,
			       &tail_payload_len))
		return false;

	trustix_route_tcp_gso_async_candidate_queue_lock(lock, queue_private);
	if (list_empty(queue)) {
		trustix_route_tcp_gso_async_candidate_queue_unlock(lock,
								   queue_private);
		trustix_route_tcp_gso_async_stream_cross_item_tail_stitch_fallbacks++;
		return false;
	}
	item = list_first_entry(queue, struct trustix_tixt_tx_route_gso_async_work,
			       list);
	if (!trustix_route_tcp_gso_async_cross_item_candidate(
		    first, item, first->sequence + prefix_payload_len +
			    tail_payload_len,
		    first->sequence + prefix_payload_len + tail_payload_len,
		    0, tail_frames, tail_payload_len, max_frames, &reason)) {
		trustix_route_tcp_gso_async_candidate_queue_unlock(lock,
								   queue_private);
		trustix_route_tcp_gso_async_stream_cross_item_tail_stitch_fallbacks++;
		return false;
	}
	trustix_route_tcp_gso_async_candidate_queue_unlock(lock, queue_private);

	batch = trustix_route_tcp_gso_async_cross_item_batch_alloc();
	if (!batch)
		return false;
	batch->items[0] = first;
	batch->item_count = 1;
	batch->outer_sequence = first->sequence + prefix_payload_len;
	batch->next_sequence = batch->outer_sequence;
	batch->next_frame_sequence = batch->outer_sequence;
	batch->next_inner_tcp_seq = first->inner_tcp_seq_base;
	batch->fix_inner_csum =
		trustix_route_tcp_gso_async_fix_inner_csum(first);
	ret = trustix_route_tcp_gso_async_cross_item_collect_range(
		batch, first, prefix_frames, tail_frames, max_frames);
	if (ret)
		goto out_not_attempted;

	trustix_route_tcp_gso_async_candidate_queue_lock(lock, queue_private);
	if (list_empty(queue)) {
		trustix_route_tcp_gso_async_candidate_queue_unlock(lock,
								   queue_private);
		goto out_not_attempted;
	}
	item = list_first_entry(queue, struct trustix_tixt_tx_route_gso_async_work,
			       list);
	if (!trustix_route_tcp_gso_async_cross_item_candidate(
		    first, item, batch->next_sequence,
		    batch->next_frame_sequence, batch->next_inner_tcp_seq,
		    batch->frame_count, batch->stream_payload_len,
		    max_frames, &reason)) {
		trustix_route_tcp_gso_async_candidate_queue_unlock(lock,
								   queue_private);
		goto out_not_attempted;
	}
	list_del_init(&item->list);
	trustix_route_tcp_gso_async_candidate_queue_unlock(lock, queue_private);

	ret = trustix_route_tcp_gso_async_cross_item_collect(batch, item,
							    max_frames);
	if (ret) {
		batch->items[batch->item_count++] = item;
		trustix_route_tcp_gso_async_stream_cross_item_tail_stitch_errors++;
		trustix_route_tcp_gso_async_stream_cross_item_errors++;
		sent = trustix_route_tcp_gso_async_cross_item_fallback(batch);
		goto out_handled;
	}
	batch->items[batch->item_count++] = item;

	for (;;) {
		if (batch->frame_count >= max_frames ||
		    batch->item_count >= ARRAY_SIZE(batch->items) ||
		    batch->last_frame_len != batch->outer_gso_size)
			break;
		trustix_route_tcp_gso_async_candidate_queue_lock(lock,
								 queue_private);
		if (list_empty(queue)) {
			trustix_route_tcp_gso_async_candidate_queue_unlock(
				lock, queue_private);
			break;
		}
		item = list_first_entry(queue,
					struct trustix_tixt_tx_route_gso_async_work,
					list);
		if (!trustix_route_tcp_gso_async_cross_item_candidate(
			    first, item, batch->next_sequence,
			    batch->next_frame_sequence,
			    batch->next_inner_tcp_seq, batch->frame_count,
			    batch->stream_payload_len, max_frames, &reason)) {
			trustix_route_tcp_gso_async_candidate_queue_unlock(
				lock, queue_private);
			break;
		}
		list_del_init(&item->list);
		trustix_route_tcp_gso_async_candidate_queue_unlock(
			lock, queue_private);

		ret = trustix_route_tcp_gso_async_cross_item_collect(
			batch, item, max_frames);
		if (ret) {
			batch->items[batch->item_count++] = item;
			trustix_route_tcp_gso_async_stream_cross_item_tail_stitch_errors++;
			trustix_route_tcp_gso_async_stream_cross_item_errors++;
			sent = trustix_route_tcp_gso_async_cross_item_fallback(
				batch);
			goto out_handled;
		}
		batch->items[batch->item_count++] = item;
	}

	ret = trustix_route_tcp_gso_async_direct_prefix_frames(
		first, first->direct_frames, prefix_frames,
		&prefix_stream_payload_len);
	if (ret) {
		trustix_route_tcp_gso_async_stream_cross_item_tail_stitch_errors++;
		trustix_route_tcp_gso_async_stream_cross_item_errors++;
		sent = trustix_route_tcp_gso_async_cross_item_fallback(batch);
		goto out_handled;
	}
	ret = trustix_tixt_tx_route_gso_stream_send_direct_batch(
		first, first->direct_frames, prefix_frames,
		prefix_stream_payload_len, first->sequence,
		batch->fix_inner_csum, true);
	if (ret) {
		trustix_route_tcp_gso_async_stream_cross_item_tail_stitch_errors++;
		trustix_route_tcp_gso_async_stream_cross_item_errors++;
		sent = trustix_route_tcp_gso_async_cross_item_fallback(batch);
		goto out_handled;
	}
	batch->complete_item[0] = true;
	sent += prefix_frames;
	trustix_route_tcp_gso_async_stream_cross_item_tail_stitch_prefix_frames +=
		prefix_frames;

	ret = trustix_tixt_tx_route_gso_stream_send_direct_ref_batch(
		&first->tmpl, batch->refs, batch->frame_count,
		batch->stream_payload_len,
		trustix_tixt_tx_plain_wire_sequence(batch->outer_sequence),
		batch->fix_inner_csum, false);
	if (ret) {
		trustix_route_tcp_gso_async_stream_cross_item_tail_stitch_errors++;
		trustix_route_tcp_gso_async_stream_cross_item_errors++;
		sent += trustix_route_tcp_gso_async_cross_item_fallback(batch);
		goto out_handled;
	}
	trustix_route_tcp_gso_async_stream_cross_item_batches++;
	trustix_route_tcp_gso_async_stream_cross_item_items +=
		batch->item_count;
	trustix_route_tcp_gso_async_stream_cross_item_frames +=
		batch->frame_count;
	trustix_route_tcp_gso_async_stream_cross_item_tail_stitch_batches++;
	trustix_route_tcp_gso_async_stream_cross_item_tail_stitch_items +=
		batch->item_count;
	trustix_route_tcp_gso_async_stream_cross_item_tail_stitch_frames +=
		batch->frame_count;
	for (reason = 0; reason < batch->item_count; reason++)
		trustix_tixt_tx_route_gso_async_complete(batch->items[reason]);
	sent += batch->frame_count;

out_handled:
	if (items_out)
		*items_out = batch->item_count;
	if (sent_out)
		*sent_out = sent;
	trustix_route_tcp_gso_async_cross_item_batch_free(batch);
	return true;

out_not_attempted:
	trustix_route_tcp_gso_async_cross_item_batch_free(batch);
	trustix_route_tcp_gso_async_stream_cross_item_tail_stitch_fallbacks++;
	return false;
}

static unsigned int trustix_tixt_tx_route_gso_async_process_item(
				struct trustix_tixt_tx_route_gso_async_work *item)
{
	struct sk_buff *segs = NULL;
	struct sk_buff *seg;
	struct sk_buff *next;
	u64 ignored_sequence_cost = 0;
	u32 ignored_max_wire_len = 0;
	u32 gso_payload_len = 0;
	u32 payload_remaining = 0;
	u32 segment_count = 0;
	u32 tcp_header_len = 0;
	u32 prepared = 0;
	u32 sent = 0;
	u32 stream_sent_frames = 0;
	u64 sequence;
	int ret;

	trustix_route_tcp_gso_async_workers++;
	if (!item->resliced || item->tmpl.secure) {
		ret = trustix_tixt_tx_route_gso_async_try_stream_direct(
			item, &stream_sent_frames);
		if (ret > 0) {
			trustix_tixt_tx_route_gso_async_complete(item);
			return stream_sent_frames;
		}
		if (ret < 0) {
			trustix_tixt_tx_route_gso_async_complete(item);
			return stream_sent_frames;
		}
		if (item->tmpl.secure) {
			trustix_route_tcp_gso_async_stream_direct_fallbacks++;
			trustix_tixt_tx_route_gso_async_complete(item);
			return 0;
		}
	} else if (item->gso_payload_len) {
		struct skb_shared_info *shinfo = skb_shinfo(item->skb);

		shinfo->gso_size = item->gso_payload_len;
		shinfo->gso_segs = item->segment_count;
	}

	ret = trustix_tixt_tx_gso_segment_inner(item->skb, &segs,
						&segment_count,
						&ignored_sequence_cost,
						&ignored_max_wire_len,
						&gso_payload_len,
						&tcp_header_len,
						&payload_remaining,
						item->gso_features);
	if (ret) {
		trustix_route_tcp_gso_async_segment_errors++;
		trustix_tixt_tx_route_gso_async_complete(item);
		return 0;
	}
	kfree_skb(item->skb);
	item->skb = NULL;
	if (segment_count != item->segment_count ||
	    gso_payload_len != item->gso_payload_len ||
	    tcp_header_len != item->tcp_header_len ||
	    payload_remaining != item->payload_len) {
		trustix_route_tcp_gso_async_segment_errors++;
		trustix_tixt_tx_free_skb_list(segs);
		trustix_tixt_tx_route_gso_async_complete(item);
		return 0;
	}

	ret = trustix_tixt_tx_route_gso_async_try_stream(
		item, segs, segment_count, gso_payload_len, tcp_header_len,
		payload_remaining, &stream_sent_frames);
	if (ret > 0) {
		trustix_tixt_tx_free_skb_list(segs);
		trustix_tixt_tx_route_gso_async_complete(item);
		return stream_sent_frames;
	}
	if (ret < 0) {
		trustix_tixt_tx_free_skb_list(segs);
		trustix_tixt_tx_route_gso_async_complete(item);
		return stream_sent_frames;
	}

	sequence = item->sequence;
	for (seg = segs; seg; seg = seg->next) {
		u32 seg_payload_len;
		u32 inner_len;

		if (unlikely(prepared >= segment_count ||
			     prepared >= TRUSTIX_TIXT_TX_GSO_MAX_SEGMENTS ||
			     !payload_remaining)) {
			trustix_route_tcp_gso_async_prepare_errors++;
			trustix_tixt_tx_free_skb_list(segs);
			trustix_tixt_tx_route_gso_async_complete(item);
			return 0;
		}
		seg_payload_len = min(payload_remaining, item->gso_payload_len);
		inner_len = sizeof(struct iphdr) + item->tcp_header_len +
			    seg_payload_len;
		ret = trustix_tixt_tx_prepare_one_segment(seg, &item->tmpl,
							  inner_len,
							  trustix_tixt_tx_plain_wire_sequence(
								  sequence));
		if (unlikely(ret)) {
			if (ret == -EBUSY)
				trustix_route_tcp_gso_async_txq_stopped_drops++;
			trustix_route_tcp_gso_async_prepare_errors++;
			trustix_tixt_tx_free_skb_list(segs);
			trustix_tixt_tx_route_gso_async_complete(item);
			return 0;
		}
		sequence += (u64)inner_len + (u64)TRUSTIX_TIXT_HEADER_LEN;
		payload_remaining -= seg_payload_len;
		prepared++;
	}
	if (!prepared || prepared != segment_count || payload_remaining) {
		trustix_route_tcp_gso_async_prepare_errors++;
		trustix_tixt_tx_free_skb_list(segs);
		trustix_tixt_tx_route_gso_async_complete(item);
		return 0;
	}

	for (seg = segs; seg; seg = next) {
		if (unlikely(!trustix_tixt_tx_route_gso_xmit_ready_async(seg))) {
			trustix_route_tcp_gso_async_txq_stopped_drops++;
			trustix_tixt_tx_free_skb_list(seg);
			break;
		}
		next = seg->next;
		seg->next = NULL;
		trustix_tixt_tx_route_gso_apply_xmit_more(
			seg, next || item->xmit_more);
		ret = trustix_tixt_tx_route_gso_safe_xmit(
			seg, READ_ONCE(trustix_route_tcp_gso_async_direct_xmit));
		if (unlikely(ret))
			trustix_route_tcp_gso_async_xmit_errors++;
		else
			sent++;
	}
	if (sent)
		trustix_route_tcp_gso_async_xmit_packets += sent;
	trustix_tixt_tx_route_gso_async_complete(item);
	return sent;
}

static bool
trustix_route_tcp_gso_async_cross_item_enabled(void)
{
	return READ_ONCE(trustix_route_tcp_gso_async_stream_cross_item_batch) &&
	       READ_ONCE(trustix_route_tcp_gso_async_stream) &&
	       READ_ONCE(trustix_route_tcp_gso_async_stream_direct_build) &&
	       !READ_ONCE(trustix_route_tcp_gso_async_stream_software_segment) &&
	       READ_ONCE(trustix_route_tcp_gso_async_stream_outer_gso) &&
	       !READ_ONCE(trustix_route_tcp_gso_async_direct_xmit);
}

static unsigned int
trustix_route_tcp_gso_async_worker_try_cross_item(
				struct list_head *queue, spinlock_t *lock,
				bool queue_private,
				struct trustix_tixt_tx_route_gso_async_work *first,
				bool queue_had_next,
				unsigned int *items_out)
{
	struct trustix_route_tcp_gso_async_cross_item_batch *batch;
	struct trustix_tixt_tx_route_gso_async_work *item;
	u32 first_stream_payload_len;
	unsigned int max_frames;
	unsigned int batch_items;
	unsigned int reason;
	unsigned int sent;
	unsigned int tail_sent;
	bool first_candidate_checked = false;
	int ret;

	if (items_out)
		*items_out = 0;
	if (!first || !first->skb || first->resliced ||
	    first->tmpl.kernel_udp ||
	    !trustix_route_tcp_gso_async_cross_item_enabled()) {
		trustix_route_tcp_gso_async_cross_item_record_miss(1);
		return trustix_tixt_tx_route_gso_async_process_item(first);
	}
	max_frames = trustix_route_tcp_gso_async_cross_item_effective_max_frames(
		queue, lock, queue_private,
		trustix_route_tcp_gso_async_stream_max_frames_value());
	if (max_frames < 2 ||
	    first->segment_count > TRUSTIX_TIXT_TX_ROUTE_STREAM_MAX_FRAMES) {
		trustix_route_tcp_gso_async_cross_item_record_miss(2);
		return trustix_tixt_tx_route_gso_async_process_item(first);
	}
	if (!trustix_route_tcp_gso_async_cross_item_full_tail(first)) {
		trustix_route_tcp_gso_async_cross_item_record_miss(3);
		return trustix_tixt_tx_route_gso_async_process_item(first);
	}
	if (first->segment_count >= max_frames) {
		if (trustix_route_tcp_gso_async_worker_try_tail_stitch(
			    queue, lock, queue_private, first, queue_had_next,
			    &tail_sent, items_out))
			return tail_sent;
		trustix_route_tcp_gso_async_cross_item_record_miss(2);
		return trustix_tixt_tx_route_gso_async_process_item(first);
	}
	if (!trustix_route_tcp_gso_async_cross_item_payload_room(
		    0, first->sequence_cost)) {
		if (trustix_route_tcp_gso_async_worker_try_tail_stitch(
			    queue, lock, queue_private, first, queue_had_next,
			    &tail_sent, items_out))
			return tail_sent;
		trustix_route_tcp_gso_async_cross_item_record_miss(4);
		return trustix_tixt_tx_route_gso_async_process_item(first);
	}
	first_stream_payload_len = (u32)first->sequence_cost;
	if (!queue_had_next) {
		trustix_route_tcp_gso_async_cross_item_record_miss(5);
		return trustix_tixt_tx_route_gso_async_process_item(first);
	}

	if (READ_ONCE(trustix_route_tcp_gso_async_stream_cross_item_dequeue_batch)) {
		batch_items = 0;
		sent = trustix_route_tcp_gso_async_worker_try_cross_item_batch_dequeue(
			queue, lock, queue_private, first,
			first_stream_payload_len, max_frames, &batch_items);
		if (batch_items) {
			if (items_out)
				*items_out = batch_items;
			return sent;
		}
		return trustix_tixt_tx_route_gso_async_process_item(first);
	}

	trustix_route_tcp_gso_async_candidate_queue_lock(lock, queue_private);
	if (list_empty(queue)) {
		trustix_route_tcp_gso_async_candidate_queue_unlock(lock,
								   queue_private);
		trustix_route_tcp_gso_async_cross_item_record_miss(5);
		return trustix_tixt_tx_route_gso_async_process_item(first);
	}
	item = trustix_route_tcp_gso_async_cross_item_find_locked(
		queue, first,
		trustix_route_tcp_gso_async_item_outer_sequence(first) +
			first->sequence_cost,
		first->sequence +
			trustix_route_tcp_gso_async_item_frame_sequence_cost(first),
		first->inner_tcp_seq_base + first->payload_len,
		first->segment_count, first_stream_payload_len, max_frames,
		false, true, &reason);
	if (!item) {
		trustix_route_tcp_gso_async_candidate_queue_unlock(lock,
								   queue_private);
		trustix_route_tcp_gso_async_cross_item_record_candidate_miss(
			reason);
		return trustix_tixt_tx_route_gso_async_process_item(first);
	}
	first_candidate_checked = true;
	trustix_route_tcp_gso_async_candidate_queue_unlock(lock, queue_private);

	batch = trustix_route_tcp_gso_async_cross_item_batch_alloc();
	if (!batch) {
		trustix_route_tcp_gso_async_stream_cross_item_errors++;
		return trustix_tixt_tx_route_gso_async_process_item(first);
	}
	batch->items[0] = first;
	batch->item_count = 1;
	batch->outer_sequence =
		trustix_route_tcp_gso_async_item_outer_sequence(first);
	batch->next_sequence = batch->outer_sequence;
	batch->next_frame_sequence = first->sequence;
	batch->next_inner_tcp_seq = first->inner_tcp_seq_base;
	batch->fix_inner_csum =
		trustix_route_tcp_gso_async_fix_inner_csum(first);
	ret = trustix_route_tcp_gso_async_cross_item_collect(batch, first,
							    max_frames);
	if (ret) {
		trustix_route_tcp_gso_async_cross_item_record_result(
			ret, 3, batch);
		trustix_route_tcp_gso_async_stream_cross_item_errors++;
		trustix_route_tcp_gso_async_cross_item_batch_free(batch);
		return trustix_tixt_tx_route_gso_async_process_item(first);
	}

	for (;;) {
		if (batch->frame_count >= max_frames ||
		    batch->item_count >= ARRAY_SIZE(batch->items) ||
		    batch->last_frame_len != batch->outer_gso_size)
			break;
		trustix_route_tcp_gso_async_candidate_queue_lock(lock,
								 queue_private);
		if (list_empty(queue)) {
			trustix_route_tcp_gso_async_candidate_queue_unlock(
				lock, queue_private);
			break;
		}
		item = trustix_route_tcp_gso_async_cross_item_find_locked(
			queue, first, batch->next_sequence,
			batch->next_frame_sequence, batch->next_inner_tcp_seq,
			batch->frame_count, batch->stream_payload_len,
			max_frames, true, first_candidate_checked ? false : true,
			&reason);
		first_candidate_checked = false;
		if (!item) {
			trustix_route_tcp_gso_async_candidate_queue_unlock(
				lock, queue_private);
			trustix_route_tcp_gso_async_cross_item_record_candidate_miss(
				reason);
			break;
		}
		trustix_route_tcp_gso_async_candidate_queue_unlock(
			lock, queue_private);

		ret = trustix_route_tcp_gso_async_cross_item_collect(
			batch, item, max_frames);
		if (ret) {
			batch->items[batch->item_count++] = item;
			trustix_route_tcp_gso_async_cross_item_record_result(
				ret, 4, batch);
			trustix_route_tcp_gso_async_stream_cross_item_errors++;
			if (items_out)
				*items_out = batch->item_count;
			sent = trustix_route_tcp_gso_async_cross_item_fallback(
				batch);
			trustix_route_tcp_gso_async_cross_item_batch_free(batch);
			return sent;
		}
		batch->items[batch->item_count++] = item;
	}
	if (items_out)
		*items_out = batch->item_count;
	if (batch->item_count < 2)
		sent = trustix_route_tcp_gso_async_cross_item_fallback(batch);
	else
		sent = trustix_route_tcp_gso_async_process_cross_item_batch(
			batch);
	trustix_route_tcp_gso_async_cross_item_batch_free(batch);
	return sent;
}

static void trustix_route_tcp_gso_async_worker_drain(
				struct list_head *queue, spinlock_t *lock,
				bool *scheduled, unsigned int *depth_defers,
				bool *delay_pending,
				struct delayed_work *work)
{
	struct trustix_tixt_tx_route_gso_async_work *item;
	unsigned int item_budget =
		READ_ONCE(trustix_route_tcp_gso_async_worker_item_budget);
	unsigned int segment_budget =
		READ_ONCE(trustix_route_tcp_gso_async_worker_segment_budget);
	unsigned int emit_budget =
		READ_ONCE(trustix_route_tcp_gso_async_worker_emit_budget);
	unsigned int resched_stride =
		READ_ONCE(trustix_route_tcp_gso_async_worker_resched_stride);
	unsigned int dequeue_batch =
		READ_ONCE(trustix_route_tcp_gso_async_worker_dequeue_batch);
	unsigned int min_queue_depth =
		READ_ONCE(trustix_route_tcp_gso_async_worker_min_queue_depth);
	unsigned int max_depth_defers =
		READ_ONCE(trustix_route_tcp_gso_async_worker_max_depth_defers);
	LIST_HEAD(local);
	unsigned int items = 0;
	unsigned int segments = 0;
	unsigned int emits = 0;
	bool queue_had_next;
	bool reschedule = false;

	trustix_route_tcp_gso_async_worker_runs++;
	if (delay_pending)
		WRITE_ONCE(*delay_pending, false);
	if (min_queue_depth > 1 && max_depth_defers) {
		unsigned int depth;
		unsigned int defers;

		if (min_queue_depth > TRUSTIX_TIXT_TX_ROUTE_STREAM_MAX_FRAMES)
			min_queue_depth = TRUSTIX_TIXT_TX_ROUTE_STREAM_MAX_FRAMES;
		for (;;) {
			spin_lock_bh(lock);
			if (list_empty(queue)) {
				if (depth_defers)
					WRITE_ONCE(*depth_defers, 0);
				if (delay_pending)
					WRITE_ONCE(*delay_pending, false);
				WRITE_ONCE(*scheduled, false);
				spin_unlock_bh(lock);
				return;
			}
			depth = trustix_route_tcp_gso_async_queue_depth(
				queue, min_queue_depth);
			defers = depth_defers ? READ_ONCE(*depth_defers) : 0;
			if (depth >= min_queue_depth ||
			    defers >= max_depth_defers)
				break;
			if (depth_defers)
				WRITE_ONCE(*depth_defers, defers + 1);
			spin_unlock_bh(lock);
			trustix_route_tcp_gso_async_worker_depth_defers++;
			cond_resched();
		}
		if (depth_defers)
			WRITE_ONCE(*depth_defers, 0);
		if (depth < min_queue_depth)
			trustix_route_tcp_gso_async_worker_depth_defer_exhausted++;
		spin_unlock_bh(lock);
	} else if (depth_defers) {
		WRITE_ONCE(*depth_defers, 0);
	}
	if (dequeue_batch < 1)
		dequeue_batch = 1;
	if (dequeue_batch > TRUSTIX_TIXT_TX_ROUTE_STREAM_MAX_FRAMES)
		dequeue_batch = TRUSTIX_TIXT_TX_ROUTE_STREAM_MAX_FRAMES;
	for (;;) {
		if ((item_budget && items >= item_budget) ||
		    (segment_budget && segments >= segment_budget)) {
			trustix_route_tcp_gso_async_worker_budget_yields++;
			reschedule = true;
			break;
		}
		if (emit_budget && emits >= emit_budget) {
			trustix_route_tcp_gso_async_worker_budget_yields++;
			trustix_route_tcp_gso_async_worker_emit_budget_yields++;
			reschedule = true;
			break;
		}
		if (dequeue_batch <= 1) {
			spin_lock_bh(lock);
			if (list_empty(queue)) {
				if (depth_defers)
					WRITE_ONCE(*depth_defers, 0);
				if (delay_pending)
					WRITE_ONCE(*delay_pending, false);
				WRITE_ONCE(*scheduled, false);
				spin_unlock_bh(lock);
				return;
			}
			item = list_first_entry(
				queue,
				struct trustix_tixt_tx_route_gso_async_work,
				list);
			list_del_init(&item->list);
			queue_had_next = !list_empty(queue);
			spin_unlock_bh(lock);
			{
				unsigned int processed_items = 1;

				item->xmit_more = queue_had_next;
				segments +=
					trustix_route_tcp_gso_async_worker_try_cross_item(
						queue, lock, false, item,
						queue_had_next, &processed_items);
				items += processed_items ? processed_items : 1;
				emits++;
			}
			if (resched_stride && items % resched_stride == 0)
				cond_resched();
			continue;
		}
		if (list_empty(&local)) {
			unsigned int pulled = 0;

			spin_lock_bh(lock);
			while (!list_empty(queue) && pulled < dequeue_batch) {
				item = list_first_entry(
					queue,
					struct trustix_tixt_tx_route_gso_async_work,
					list);
				list_del_init(&item->list);
				list_add_tail(&item->list, &local);
				pulled++;
			}
			if (!pulled) {
				if (depth_defers)
					WRITE_ONCE(*depth_defers, 0);
				if (delay_pending)
					WRITE_ONCE(*delay_pending, false);
				WRITE_ONCE(*scheduled, false);
				spin_unlock_bh(lock);
				return;
			}
			queue_had_next = !list_empty(queue) ||
					 !list_is_singular(&local);
			spin_unlock_bh(lock);
			if (pulled > 1) {
				trustix_route_tcp_gso_async_worker_dequeue_batches++;
				trustix_route_tcp_gso_async_worker_dequeue_items +=
					pulled;
			}
		} else {
			queue_had_next = !list_is_singular(&local);
		}
		item = list_first_entry(&local,
					struct trustix_tixt_tx_route_gso_async_work,
					list);
		list_del_init(&item->list);

		{
			unsigned int processed_items = 1;

			item->xmit_more = queue_had_next;
			segments +=
				trustix_route_tcp_gso_async_worker_try_cross_item(
					&local, NULL, true, item,
					queue_had_next, &processed_items);
			items += processed_items ? processed_items : 1;
			emits++;
		}
		if (resched_stride && items % resched_stride == 0)
			cond_resched();
	}

	if (!list_empty(&local)) {
		spin_lock_bh(lock);
		list_splice_init(&local, queue);
		WRITE_ONCE(*scheduled, true);
		spin_unlock_bh(lock);
	}
	if (reschedule && !READ_ONCE(trustix_route_tcp_gso_async_quiescing)) {
		unsigned long delay =
			trustix_route_tcp_gso_async_budget_reschedule_delay();

		trustix_route_tcp_gso_async_budget_sleep(delay);
		trustix_route_tcp_gso_async_queue_work(work, delay);
	}
}

static void trustix_route_tcp_gso_async_worker_fn(struct work_struct *work)
{
	trustix_route_tcp_gso_async_worker_drain(
		&trustix_route_tcp_gso_async_queue,
		&trustix_route_tcp_gso_async_lock,
		&trustix_route_tcp_gso_async_scheduled,
		&trustix_route_tcp_gso_async_depth_defers,
		&trustix_route_tcp_gso_async_delay_pending,
		&trustix_route_tcp_gso_async_work);
}

static void trustix_route_tcp_gso_async_shard_worker_fn(struct work_struct *work)
{
	struct trustix_route_tcp_gso_async_queue_shard *shard =
		container_of(to_delayed_work(work),
			     struct trustix_route_tcp_gso_async_queue_shard,
			     work);

	trustix_route_tcp_gso_async_worker_drain(
		&shard->queue, &shard->lock, &shard->scheduled,
		&shard->depth_defers, &shard->delay_pending, &shard->work);
}

static unsigned long trustix_route_tcp_gso_async_schedule_delay(void)
{
	unsigned int delay =
		READ_ONCE(trustix_route_tcp_gso_async_worker_schedule_delay_jiffies);

	return min_t(unsigned int, delay, HZ / 10);
}

static unsigned long trustix_route_tcp_gso_async_budget_reschedule_delay(void)
{
	unsigned int delay = READ_ONCE(
		trustix_route_tcp_gso_async_worker_budget_reschedule_delay_jiffies);

	return min_t(unsigned int, delay, HZ / 10);
}

static unsigned int trustix_route_tcp_gso_async_schedule_depth(void)
{
	unsigned int depth =
		READ_ONCE(trustix_route_tcp_gso_async_worker_min_queue_depth);

	if (depth < 2)
		return 0;
	return min_t(unsigned int, depth, TRUSTIX_TIXT_TX_ROUTE_STREAM_MAX_FRAMES);
}

static bool trustix_route_tcp_gso_async_depth_ready(struct list_head *queue,
						    unsigned int target)
{
	return target > 1 &&
	       trustix_route_tcp_gso_async_queue_depth(queue, target) >= target;
}

static int trustix_tixt_tx_route_gso_async_enqueue(
				struct trustix_tixt_tx_route_gso_async_work *item)
{
	struct trustix_route_tcp_gso_async_queue_shard *shard;
	unsigned int shard_count;
	unsigned int shard_index;
	unsigned int schedule_depth;
	unsigned long delay_jiffies;
	unsigned int delay_usecs;
	bool has_delay;
	bool no_accel;
	bool accel = false;
	bool accel_suppressed = false;
	bool wake = false;

	if (!item)
		return -EINVAL;
	if (READ_ONCE(trustix_route_tcp_gso_async_quiescing))
		return -ESHUTDOWN;
	delay_jiffies = trustix_route_tcp_gso_async_schedule_delay();
	delay_usecs = delay_jiffies ? 0 :
		trustix_route_tcp_gso_async_schedule_delay_usecs();
	has_delay = delay_jiffies || delay_usecs;
	schedule_depth = has_delay ? trustix_route_tcp_gso_async_schedule_depth() : 0;
	no_accel = has_delay &&
		READ_ONCE(trustix_route_tcp_gso_async_worker_schedule_delay_no_accel);
	if (READ_ONCE(trustix_route_tcp_gso_async_sharded_queue)) {
		shard_count = trustix_route_tcp_gso_async_queue_shards_value();
		if (shard_count > 1) {
			shard_index = item->queue_hash % shard_count;
			shard = &trustix_route_tcp_gso_async_shards[shard_index];
			spin_lock_bh(&shard->lock);
			list_add_tail(&item->list, &shard->queue);
			if (!READ_ONCE(shard->scheduled)) {
				WRITE_ONCE(shard->scheduled, true);
				if (has_delay)
					WRITE_ONCE(shard->delay_pending, true);
				wake = true;
			} else if (READ_ONCE(shard->delay_pending) &&
				   trustix_route_tcp_gso_async_depth_ready(
					   &shard->queue, schedule_depth)) {
				if (no_accel) {
					accel_suppressed = true;
				} else {
					WRITE_ONCE(shard->delay_pending, false);
					accel = true;
				}
			}
			spin_unlock_bh(&shard->lock);
			if (wake) {
				if (has_delay)
					trustix_route_tcp_gso_async_worker_schedule_delays++;
				if (delay_usecs)
					trustix_route_tcp_gso_async_queue_schedule_timer(
						&shard->work, &shard->schedule_timer,
						delay_usecs);
				else
					trustix_route_tcp_gso_async_queue_work(
						&shard->work, delay_jiffies);
			} else if (accel) {
				if (delay_usecs)
					trustix_route_tcp_gso_async_cancel_schedule_timer(
						&shard->schedule_timer);
				trustix_route_tcp_gso_async_worker_schedule_delay_accels++;
				trustix_route_tcp_gso_async_mod_work(
					&shard->work, 0);
			} else if (accel_suppressed) {
				trustix_route_tcp_gso_async_worker_schedule_delay_accel_suppressed++;
			}
			return 0;
		}
	}
	spin_lock_bh(&trustix_route_tcp_gso_async_lock);
	list_add_tail(&item->list, &trustix_route_tcp_gso_async_queue);
	if (!READ_ONCE(trustix_route_tcp_gso_async_scheduled)) {
		WRITE_ONCE(trustix_route_tcp_gso_async_scheduled, true);
		if (has_delay)
			WRITE_ONCE(trustix_route_tcp_gso_async_delay_pending,
				   true);
		wake = true;
	} else if (READ_ONCE(trustix_route_tcp_gso_async_delay_pending) &&
		   trustix_route_tcp_gso_async_depth_ready(
			   &trustix_route_tcp_gso_async_queue, schedule_depth)) {
		if (no_accel) {
			accel_suppressed = true;
		} else {
			WRITE_ONCE(trustix_route_tcp_gso_async_delay_pending,
				   false);
			accel = true;
		}
	}
	spin_unlock_bh(&trustix_route_tcp_gso_async_lock);
	if (wake) {
		if (has_delay)
			trustix_route_tcp_gso_async_worker_schedule_delays++;
		if (delay_usecs)
			trustix_route_tcp_gso_async_queue_schedule_timer(
				&trustix_route_tcp_gso_async_work,
				&trustix_route_tcp_gso_async_schedule_timer,
				delay_usecs);
		else
			trustix_route_tcp_gso_async_queue_work(
				&trustix_route_tcp_gso_async_work,
				delay_jiffies);
	} else if (accel) {
		if (delay_usecs)
			trustix_route_tcp_gso_async_cancel_schedule_timer(
				&trustix_route_tcp_gso_async_schedule_timer);
		trustix_route_tcp_gso_async_worker_schedule_delay_accels++;
		trustix_route_tcp_gso_async_mod_work(
			&trustix_route_tcp_gso_async_work, 0);
	} else if (accel_suppressed) {
		trustix_route_tcp_gso_async_worker_schedule_delay_accel_suppressed++;
	}
	return 0;
}

static int
trustix_kernel_skb_tixt_tx_segment_route_tcp_gso_async_ex(
				struct sk_buff *skb,
				struct trustix_kudp_tx_route_value *route,
				const struct trustix_kudp_tx_flow_value *provided_flow,
				const struct trustix_tixt_tx_route_gso_args *args,
				const struct trustix_tixt_tx_secure_route_gso_args *secure_args,
				bool sync_redirect)
{
	const struct trustix_kudp_tx_flow_value *flow;
	struct trustix_tixt_tx_route_gso_async_work *item;
	struct net_device *out_dev;
	struct sk_buff *clone;
	u64 flow_id;
	u64 sequence;
	u64 outer_sequence;
	u64 sequence_cost = 0;
	u32 ifindex;
	u32 gso_payload_len = 0;
	u32 max_wire_len = 0;
	u32 payload_len = 0;
	u32 segment_count = 0;
	u32 segment_limit;
	u32 tcp_header_len = 0;
	u32 limit;
	u32 clear_flags;
	u32 queued_len;
	u32 route_mtu;
	u32 inner_queue_hash;
	u32 frame_payload_extra;
	unsigned long bytes_limit;
	unsigned long queued_bytes;
	bool bytes_reserved = false;
	bool allow_reslice = false;
	bool resliced = false;
	bool secure = secure_args != NULL;
	netdev_features_t gso_features = 0;
	int inflight;
	int ret;

	trustix_route_tcp_gso_async_calls++;
	if (!skb || !route || (!args && !secure_args)) {
		trustix_route_tcp_gso_async_invalid_args++;
		return -EINVAL;
	}
	trustix_route_tcp_gso_async_record_shape(skb);
	if (!READ_ONCE(trustix_route_tcp_gso) ||
	    (!sync_redirect && !READ_ONCE(trustix_route_tcp_gso_async)) ||
	    (!sync_redirect && !READ_ONCE(trustix_route_tcp_gso_async_dev_xmit)) ||
	    READ_ONCE(trustix_route_tcp_gso_async_quiescing)) {
		trustix_route_tcp_gso_async_disabled++;
		return -EPROTONOSUPPORT;
	}
	if (!skb->dev) {
		trustix_route_tcp_gso_async_no_dev++;
		return -ENODEV;
	}
	clear_flags = secure ? secure_args->clear_flags : args->clear_flags;
	if (READ_ONCE(trustix_route_tcp_gso_async_force_software_outer_csum))
		clear_flags &= ~TRUSTIX_TIXT_TX_FINALIZE_TCP_PARTIAL_CSUM;
	if (READ_ONCE(trustix_route_tcp_gso_async_force_inner_checksum))
		clear_flags &=
			~TRUSTIX_TIXT_TX_FINALIZE_TCP_TRUST_PARTIAL_INNER_CSUM;
	ret = trustix_tixt_tx_validate_route_gso_clear_flags(clear_flags);
	if (ret) {
		trustix_route_tcp_gso_async_invalid_flags++;
		return ret;
	}
	if (secure)
		ret = trustix_tixt_tx_validate_route_secure_flow(skb, route,
								 READ_ONCE(secure_args->flow_id),
								 provided_flow,
								 &flow,
								 &flow_id);
	else
		ret = trustix_tixt_tx_validate_route_plain_flow(skb, route,
								&flow,
								&flow_id);
	if (ret) {
		trustix_route_tcp_gso_async_flow_errors++;
		return ret;
	}
	ifindex = READ_ONCE(flow->ifindex);
	if (!ifindex) {
		trustix_route_tcp_gso_async_no_ifindex++;
		return -ENODEV;
	}
	if (skb->dev->ifindex == ifindex) {
		out_dev = skb->dev;
		dev_hold(out_dev);
	} else {
		out_dev = dev_get_by_index(dev_net(skb->dev), ifindex);
	}
	if (!out_dev) {
		trustix_route_tcp_gso_async_no_out_dev++;
		return -ENODEV;
	}
	route_mtu = trustix_tixt_tx_route_gso_effective_mtu(flow, out_dev);
	allow_reslice =
		READ_ONCE(trustix_route_tcp_gso_async_reslice_to_mtu) &&
		READ_ONCE(trustix_route_tcp_gso_async_stream) &&
		(READ_ONCE(trustix_route_tcp_gso_async_stream_direct_build) ||
		 READ_ONCE(trustix_route_tcp_gso_async_stream_software_segment));
	frame_payload_extra = secure ? TRUSTIX_TIXT_TX_SECURE_PAYLOAD_OVERHEAD :
		0;
	ret = trustix_tixt_tx_gso_plan_inner(skb, route_mtu, allow_reslice,
					     frame_payload_extra,
					     &segment_count, &sequence_cost,
					     &max_wire_len, &gso_payload_len,
					     &tcp_header_len, &payload_len,
					     &resliced);
	WRITE_ONCE(trustix_route_tcp_gso_async_last_plan_ret, ret);
	if (ret) {
		dev_put(out_dev);
		if (!READ_ONCE(skb_shinfo(skb)->gso_size))
			trustix_route_tcp_gso_async_no_gso++;
		trustix_route_tcp_gso_async_plan_errors++;
		return ret;
	}
	segment_limit =
		READ_ONCE(trustix_route_tcp_gso_async_max_segments_per_item);
	if (segment_limit && segment_count > segment_limit) {
		dev_put(out_dev);
		trustix_route_tcp_gso_async_plan_errors++;
		WRITE_ONCE(trustix_route_tcp_gso_async_last_plan_ret, -E2BIG);
		return -E2BIG;
	}
	WRITE_ONCE(trustix_route_tcp_gso_async_last_segment_count,
		   segment_count);
	WRITE_ONCE(trustix_route_tcp_gso_async_last_payload_len,
		   payload_len);
	WRITE_ONCE(trustix_route_tcp_gso_async_last_max_wire_len,
		   max_wire_len);
	if (resliced)
		trustix_route_tcp_gso_async_reslice_plans++;

	queued_len = READ_ONCE(skb->truesize);
	if (!queued_len)
		queued_len = READ_ONCE(skb->len);
	bytes_limit = READ_ONCE(trustix_route_tcp_gso_async_bytes_limit);
	if (bytes_limit) {
		queued_bytes = trustix_route_tcp_gso_async_reserve_bytes(
			queued_len);
		bytes_reserved = true;
		if (queued_bytes > bytes_limit) {
			dev_put(out_dev);
			trustix_route_tcp_gso_async_release_bytes(queued_len);
			trustix_route_tcp_gso_async_queue_bytes_full++;
			return -EAGAIN;
		}
	}

	if (route_mtu && max_wire_len > route_mtu) {
		dev_put(out_dev);
		if (bytes_reserved)
			trustix_route_tcp_gso_async_release_bytes(queued_len);
		trustix_route_tcp_gso_async_mtu_errors++;
		return -EMSGSIZE;
	}

	limit = READ_ONCE(trustix_route_tcp_gso_async_limit);
	inflight = atomic_inc_return(&trustix_route_tcp_gso_async_inflight_atomic);
	WRITE_ONCE(trustix_route_tcp_gso_async_inflight,
		   inflight > 0 ? (unsigned int)inflight : 0);
	if (limit && inflight > limit) {
		inflight = atomic_dec_return(
			&trustix_route_tcp_gso_async_inflight_atomic);
		WRITE_ONCE(trustix_route_tcp_gso_async_inflight,
			   inflight > 0 ? (unsigned int)inflight : 0);
		dev_put(out_dev);
		if (bytes_reserved)
			trustix_route_tcp_gso_async_release_bytes(queued_len);
		trustix_route_tcp_gso_async_queue_full++;
		return -EAGAIN;
	}

	if (trustix_route_tcp_gso_async_work_cache)
		item = kmem_cache_zalloc(trustix_route_tcp_gso_async_work_cache,
					 GFP_ATOMIC);
	else
		item = kzalloc(sizeof(*item), GFP_ATOMIC);
	if (!item) {
		inflight = atomic_dec_return(
			&trustix_route_tcp_gso_async_inflight_atomic);
		WRITE_ONCE(trustix_route_tcp_gso_async_inflight,
			   inflight > 0 ? (unsigned int)inflight : 0);
		dev_put(out_dev);
		if (bytes_reserved)
			trustix_route_tcp_gso_async_release_bytes(queued_len);
		trustix_route_tcp_gso_async_alloc_errors++;
		return -ENOMEM;
	}
	clone = skb_clone(skb, GFP_ATOMIC);
	if (!clone) {
		if (trustix_route_tcp_gso_async_work_cache)
			kmem_cache_free(trustix_route_tcp_gso_async_work_cache,
					item);
		else
			kfree(item);
		inflight = atomic_dec_return(
			&trustix_route_tcp_gso_async_inflight_atomic);
		WRITE_ONCE(trustix_route_tcp_gso_async_inflight,
			   inflight > 0 ? (unsigned int)inflight : 0);
		dev_put(out_dev);
		if (bytes_reserved)
			trustix_route_tcp_gso_async_release_bytes(queued_len);
		trustix_route_tcp_gso_async_clone_errors++;
		return -ENOMEM;
	}

	if (clear_flags &
	    TRUSTIX_TIXT_TX_FINALIZE_TCP_TRUST_PARTIAL_INNER_CSUM)
		gso_features = NETIF_F_SG | NETIF_F_HW_CSUM;

	if (secure) {
		trustix_tixt_tx_init_secure_route_gso_template(
			flow, out_dev, flow_id, clear_flags, &item->tmpl);
		item->secure_slot_id = READ_ONCE(secure_args->slot_id);
		item->secure_suite = READ_ONCE(secure_args->suite);
		item->secure_epoch = READ_ONCE(secure_args->epoch);
		memcpy(item->secure_iv, secure_args->iv,
		       sizeof(item->secure_iv));
	} else {
		trustix_tixt_tx_init_route_gso_template(flow, out_dev, flow_id,
							clear_flags,
							&item->tmpl);
	}
	if (sync_redirect && READ_ONCE(trustix_route_tcp_gso_sync_stream)) {
		item->tmpl.stream_outer_gso =
			READ_ONCE(trustix_route_tcp_gso_sync_stream_outer_gso);
	}
	if (secure) {
		sequence = atomic64_fetch_add(
			segment_count,
			(atomic64_t *)&((struct trustix_kudp_tx_flow_value *)flow)->sequence) + 1;
		outer_sequence = atomic64_fetch_add(
			sequence_cost,
			&trustix_route_tcp_gso_secure_outer_sequence) + 1;
	} else if (trustix_tixt_tx_plain_skip_sequence_enabled()) {
		sequence = 0;
		outer_sequence = 0;
	} else {
		sequence = atomic64_fetch_add(
			sequence_cost,
			(atomic64_t *)&((struct trustix_kudp_tx_flow_value *)flow)->sequence) + 1;
		outer_sequence = sequence;
	}
	item->skb = clone;
	item->flow_id = flow_id;
	item->sequence = sequence;
	item->outer_sequence = outer_sequence;
	item->sequence_cost = sequence_cost;
	item->queued_len = queued_len;
	item->segment_count = segment_count;
	item->gso_payload_len = gso_payload_len;
	item->tcp_header_len = tcp_header_len;
	item->payload_len = payload_len;
	item->inner_header_len = 0;
	item->inner_ip_check_base = 0;
	item->inner_header_ready = false;
	item->route_flow_mask = READ_ONCE(route->flow_mask);
	inner_queue_hash =
		trustix_route_tcp_gso_async_hash_skb(skb, flow_id, item);
	if (READ_ONCE(trustix_route_tcp_gso_async_flow_shard_queue)) {
		item->queue_hash =
			trustix_route_tcp_gso_async_flow_fallback_hash(flow_id);
	} else {
		item->queue_hash = inner_queue_hash;
	}
	trustix_tixt_tx_route_gso_template_set_tx_queue_hash(
		&item->tmpl, inner_queue_hash);
	item->resliced = resliced;
	item->sync_redirect = sync_redirect;
	item->gso_features = gso_features;
	INIT_LIST_HEAD(&item->list);
	if (!bytes_reserved)
		trustix_route_tcp_gso_async_reserve_bytes(queued_len);
	if (trustix_tixt_tx_route_gso_async_enqueue(item)) {
		trustix_route_tcp_gso_async_queue_full++;
		trustix_tixt_tx_route_gso_async_complete(item);
		return -EAGAIN;
	}
	trustix_route_tcp_gso_async_queued++;
	return TRUSTIX_TIXT_TX_GSO_SEGMENTS_STOLEN;
}

static int
trustix_kernel_skb_tixt_tx_segment_route_tcp_gso_async(
				struct sk_buff *skb,
				struct trustix_kudp_tx_route_value *route,
				const struct trustix_tixt_tx_route_gso_args *args,
				bool sync_redirect)
{
	return trustix_kernel_skb_tixt_tx_segment_route_tcp_gso_async_ex(
		skb, route, NULL, args, NULL, sync_redirect);
}

static int
trustix_kernel_skb_tixt_tx_segment_route_tcp_gso_sync(
				struct sk_buff *skb,
				struct trustix_kudp_tx_route_value *route,
				const struct trustix_tixt_tx_route_gso_args *args)
{
	int ret;

	trustix_route_tcp_gso_sync_calls++;
	ret = trustix_kernel_skb_tixt_tx_segment_route_tcp_gso_async(
		skb, route, args, true);
	if (ret == TRUSTIX_TIXT_TX_GSO_SEGMENTS_STOLEN) {
		trustix_route_tcp_gso_sync_async_redirects++;
		return ret;
	}
	if (ret == -EPROTONOSUPPORT || ret == -EOPNOTSUPP) {
		trustix_route_tcp_gso_sync_fallbacks++;
		return -EOPNOTSUPP;
	}
	if (ret != -EMSGSIZE)
		trustix_route_tcp_gso_sync_errors++;
	return ret;
}

static void trustix_route_tcp_gso_async_flush(void)
{
	struct trustix_tixt_tx_route_gso_async_work *item;
	struct trustix_tixt_tx_route_gso_async_work *tmp;
	LIST_HEAD(drop);
	unsigned int i;

	hrtimer_cancel(&trustix_route_tcp_gso_async_schedule_timer);
	cancel_delayed_work_sync(&trustix_route_tcp_gso_async_work);
	spin_lock_bh(&trustix_route_tcp_gso_async_lock);
	list_splice_init(&trustix_route_tcp_gso_async_queue, &drop);
	WRITE_ONCE(trustix_route_tcp_gso_async_scheduled, false);
	WRITE_ONCE(trustix_route_tcp_gso_async_delay_pending, false);
	spin_unlock_bh(&trustix_route_tcp_gso_async_lock);
	for (i = 0; i < TRUSTIX_ROUTE_TCP_GSO_ASYNC_MAX_QUEUE_SHARDS; i++) {
		struct trustix_route_tcp_gso_async_queue_shard *shard =
			&trustix_route_tcp_gso_async_shards[i];

		hrtimer_cancel(&shard->schedule_timer);
		cancel_delayed_work_sync(&shard->work);
		spin_lock_bh(&shard->lock);
		list_splice_init(&shard->queue, &drop);
		WRITE_ONCE(shard->scheduled, false);
		WRITE_ONCE(shard->delay_pending, false);
		WRITE_ONCE(shard->depth_defers, 0);
		spin_unlock_bh(&shard->lock);
	}

	list_for_each_entry_safe(item, tmp, &drop, list) {
		list_del_init(&item->list);
		trustix_tixt_tx_route_gso_async_complete(item);
	}
}

static void trustix_datapath_helpers_release_netdev_refs(struct net_device *dev)
{
	bool was_async_quiescing;
	bool was_backlog_quiescing;

	if (!dev)
		return;

	was_async_quiescing =
		READ_ONCE(trustix_route_tcp_gso_async_quiescing);
	was_backlog_quiescing =
		READ_ONCE(trustix_tixt_rx_backlog_worker_quiescing);
	WRITE_ONCE(trustix_route_tcp_gso_async_quiescing, true);
	WRITE_ONCE(trustix_tixt_rx_backlog_worker_quiescing, true);
	smp_mb();

	trustix_route_tcp_gso_async_flush();
	trustix_route_tcp_xmit_worker_flush();
	trustix_tixt_rx_backlog_worker_flush();
	trustix_tixt_rx_single_coalesce_drop_all();

	smp_mb();
	if (READ_ONCE(trustix_datapath_helpers_registered)) {
		WRITE_ONCE(trustix_tixt_rx_backlog_worker_quiescing,
			   was_backlog_quiescing);
		WRITE_ONCE(trustix_route_tcp_gso_async_quiescing,
			   was_async_quiescing);
	}
}

static bool
trustix_datapath_helpers_is_capability_probe_dev(const struct net_device *dev)
{
	if (!dev)
		return false;
	return !strncmp(dev->name, "tixcapgre", sizeof("tixcapgre") - 1) ||
	       !strncmp(dev->name, "tixcapipip", sizeof("tixcapipip") - 1) ||
	       !strncmp(dev->name, "tixcapvxlan", sizeof("tixcapvxlan") - 1);
}

static int trustix_datapath_helpers_netdev_event(struct notifier_block *nb,
						unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);

	if (event == NETDEV_UNREGISTER) {
		trustix_netdev_unregister_events++;
		if (trustix_datapath_helpers_is_capability_probe_dev(dev)) {
			trustix_netdev_unregister_probe_ignored++;
			return NOTIFY_DONE;
		}
		trustix_netdev_unregister_flushes++;
		trustix_datapath_helpers_release_netdev_refs(dev);
	}
	return NOTIFY_DONE;
}

static struct notifier_block trustix_datapath_helpers_netdev_notifier = {
	.notifier_call = trustix_datapath_helpers_netdev_event,
};

__bpf_kfunc int
trustix_kernel_skb_tixt_tx_segment_route_tcp_gso(
				struct __sk_buff *ctx,
				struct trustix_kudp_tx_route_value *route,
				const struct trustix_tixt_tx_route_gso_args *args)
{
	struct sk_buff *skb = trustix_bpf_ctx_skb(ctx);
	int ret;
	bool async_enabled;
	bool async_prefer;
	bool sync_stream_enabled;

	if (!skb || !route || !args)
		return -EINVAL;
	async_enabled = READ_ONCE(trustix_route_tcp_gso) &&
			READ_ONCE(trustix_route_tcp_gso_async) &&
			READ_ONCE(trustix_route_tcp_gso_async_dev_xmit) &&
			!READ_ONCE(trustix_route_tcp_gso_async_quiescing);
	sync_stream_enabled = READ_ONCE(trustix_route_tcp_gso) &&
			      READ_ONCE(trustix_route_tcp_gso_sync_stream);
	async_prefer = async_enabled &&
		       READ_ONCE(trustix_route_tcp_gso_async_prefer);
	if (async_prefer) {
		ret = trustix_kernel_skb_tixt_tx_segment_route_tcp_gso_async(skb,
									    route,
									    args,
									    false);
		if (ret == TRUSTIX_TIXT_TX_GSO_SEGMENTS_STOLEN ||
		    ret == -EMSGSIZE)
			return ret;
		if (ret != -EPROTONOSUPPORT && ret != -EOPNOTSUPP &&
		    ret != -EAGAIN && ret != -ENOMEM)
			return ret;
	}
	ret = trustix_kernel_skb_tixt_tx_segment_route_tcp_gso_sync(skb,
								   route,
								   args);
	if ((ret == -EPROTONOSUPPORT || ret == -EOPNOTSUPP) &&
	    async_enabled && !async_prefer && !sync_stream_enabled)
		ret = trustix_kernel_skb_tixt_tx_segment_route_tcp_gso_async(skb,
									    route,
									    args,
									    false);
	if (ret != -EPROTONOSUPPORT)
		return ret;
	return -EOPNOTSUPP;
}

__bpf_kfunc int
trustix_kernel_skb_tixt_tx_segment_secure_route_tcp_gso(
				struct __sk_buff *ctx,
				struct trustix_kudp_tx_route_value *route,
				struct trustix_kudp_tx_flow_value *flow,
				const struct trustix_tixt_tx_secure_route_gso_args *args)
{
	struct sk_buff *skb = trustix_bpf_ctx_skb(ctx);
	int ret;

	if (!skb || !route || !flow || !args)
		return -EINVAL;
	if (!READ_ONCE(args->suite))
		return -EINVAL;
	ret = trustix_kernel_skb_tixt_tx_segment_route_tcp_gso_async_ex(
		skb, route, flow, NULL, args, false);
	if (ret != -EPROTONOSUPPORT)
		return ret;
	return -EOPNOTSUPP;
}

__bpf_kfunc int
trustix_kernel_skb_tixt_tx_route_tcp(
				struct __sk_buff *ctx,
				struct trustix_kudp_tx_route_value *route,
				const struct trustix_tixt_tx_route_gso_args *args)
{
	struct trustix_tixt_tx_route_header_args linear_args;
	struct sk_buff *skb = trustix_bpf_ctx_skb(ctx);

	if (!skb || !route || !args)
		return -EINVAL;
	if (skb_shinfo(skb)->gso_size)
		return -EOPNOTSUPP;
	linear_args.clear_flags = args->clear_flags &
		~TRUSTIX_TIXT_TX_FINALIZE_TCP_TRUST_PARTIAL_INNER_CSUM;
	linear_args.reserved = args->reserved;
	return trustix_kernel_skb_tixt_tx_push_route_tcp_header(ctx, route,
								&linear_args);
}

__bpf_kfunc int
trustix_kernel_skb_tixt_tx_route_tcp_xmit(
				struct __sk_buff *ctx,
				struct trustix_kudp_tx_route_value *route,
				const struct trustix_tixt_tx_route_gso_args *args)
{
	const struct trustix_kudp_tx_flow_value *flow;
	struct trustix_kudp_tx_flow_value flow_snapshot;
	struct net_device *dev;
	struct sk_buff *skb = trustix_bpf_ctx_skb(ctx);
	struct sk_buff *tx_skb;
	u64 flow_id;
	u32 inner_len;
	u8 *data;
	u8 *data_end;
	int ifindex;
	int ret;
	bool schedule_worker;

	if (!skb || !route || !args)
		return -EINVAL;
	if (!READ_ONCE(trustix_route_tcp_xmit_worker) ||
	    READ_ONCE(trustix_route_tcp_gso_async_quiescing)) {
		trustix_route_tcp_xmit_worker_disabled++;
		return -EOPNOTSUPP;
	}
	if (!skb->dev)
		return -EOPNOTSUPP;
	if (skb_shinfo(skb)->gso_size)
		return -EOPNOTSUPP;
	if (skb->len < ETH_HLEN + sizeof(struct iphdr))
		return -EINVAL;
	inner_len = READ_ONCE(skb->len) - ETH_HLEN;
	if (unlikely(!pskb_may_pull(skb, ETH_HLEN + sizeof(struct iphdr))))
		return -EPROTONOSUPPORT;
	if (ETH_HLEN + sizeof(struct iphdr) > skb_headlen(skb))
		return -EPROTONOSUPPORT;
	data = skb->data;
	data_end = data + skb_headlen(skb);
	ret = trustix_tixt_tx_validate_route_plain_flow_pulled(
		data, data_end, route, &flow, &flow_id);
	if (ret)
		return ret;
	ifindex = READ_ONCE(flow->ifindex);
	if (ifindex <= 0)
		return -EOPNOTSUPP;
	dev = dev_get_by_index(dev_net(skb->dev), ifindex);
	if (!dev) {
		trustix_route_tcp_xmit_worker_no_dev++;
		return -EOPNOTSUPP;
	}
	tx_skb = skb_clone(skb, GFP_ATOMIC);
	if (!tx_skb) {
		dev_put(dev);
		trustix_route_tcp_xmit_worker_alloc_errors++;
		return -EOPNOTSUPP;
	}
	memcpy(&flow_snapshot, flow, sizeof(flow_snapshot));

	if (!trustix_tixt_tx_plain_skip_sequence_enabled())
		flow_snapshot.sequence = atomic64_fetch_add(
			inner_len + TRUSTIX_TIXT_HEADER_LEN,
			(atomic64_t *)&((struct trustix_kudp_tx_flow_value *)flow)->sequence);

	ret = trustix_tixt_tx_prepare_route_tcp_snapshot(
		tx_skb, &flow_snapshot, flow_id, args->clear_flags);
	if (ret) {
		trustix_route_tcp_xmit_worker_header_errors++;
		kfree_skb(tx_skb);
		dev_put(dev);
		if (ret == -EMSGSIZE)
			return ret;
		return -EOPNOTSUPP;
	}

	tx_skb->dev = dev;
	spin_lock_bh(&trustix_route_tcp_xmit_worker_queue.lock);
	if (!READ_ONCE(trustix_route_tcp_xmit_worker) ||
	    READ_ONCE(trustix_route_tcp_gso_async_quiescing)) {
		spin_unlock_bh(&trustix_route_tcp_xmit_worker_queue.lock);
		trustix_route_tcp_xmit_worker_disabled++;
		kfree_skb(tx_skb);
		dev_put(dev);
		return -EOPNOTSUPP;
	}
	if (skb_queue_len(&trustix_route_tcp_xmit_worker_queue) >=
	    trustix_route_tcp_xmit_worker_queue_limit_value()) {
		spin_unlock_bh(&trustix_route_tcp_xmit_worker_queue.lock);
		trustix_route_tcp_xmit_worker_queue_full++;
		kfree_skb(tx_skb);
		dev_put(dev);
		return -EOPNOTSUPP;
	}
	schedule_worker = !READ_ONCE(trustix_route_tcp_xmit_worker_scheduled);
	if (schedule_worker)
		WRITE_ONCE(trustix_route_tcp_xmit_worker_scheduled, true);
	__skb_queue_tail(&trustix_route_tcp_xmit_worker_queue, tx_skb);
	WRITE_ONCE(trustix_route_tcp_xmit_worker_depth,
		   skb_queue_len(&trustix_route_tcp_xmit_worker_queue));
	spin_unlock_bh(&trustix_route_tcp_xmit_worker_queue.lock);

	trustix_route_tcp_xmit_worker_enqueued++;
	trustix_route_tcp_xmit_worker_cloned++;
	if (schedule_worker)
		schedule_work(&trustix_route_tcp_xmit_work);
	return TRUSTIX_TIXT_TX_ROUTE_TCP_XMIT_QUEUED;
}

__bpf_kfunc int trustix_kernel_skb_kudp_tx_store_l2_l3_l4(struct sk_buff *skb,
							  const u8 *l2,
							  const u8 *l3,
							  const u8 *l4,
							  u32 l4_len)
{
	u32 total_len;
	u8 *dst;

	if (!skb || !l2 || !l3 || !l4)
		return -EINVAL;
	if (l4_len != 40 && l4_len != 60)
		return -EINVAL;
	if (check_add_overflow((u32)ETH_HLEN + (u32)sizeof(struct iphdr),
			       l4_len, &total_len))
		return -EINVAL;
	if (skb->len < total_len)
		return -EINVAL;
	if (unlikely(!pskb_may_pull(skb, total_len)))
		return -EINVAL;
	if (skb_ensure_writable(skb, total_len))
		return -EFAULT;
	if (total_len > skb_headlen(skb))
		return -EINVAL;

	dst = skb->data;
	memcpy(dst, l2, ETH_HLEN);
	memcpy(dst + ETH_HLEN, l3, sizeof(struct iphdr));
	memcpy(dst + ETH_HLEN + sizeof(struct iphdr), l4, l4_len);
	return 0;
}

__bpf_kfunc int
trustix_kernel_skb_kudp_tx_build_udp_header(
				struct sk_buff *skb,
				const struct trustix_kudp_tx_udp_header_args *args)
{
	u32 total_len = ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr) +
			TRUSTIX_KUDP_HEADER_LEN;
	u8 *dst;

	if (!skb || !args)
		return -EINVAL;
	if (args->flags & ~TRUSTIX_KUDP_FLAG_ENCRYPTED)
		return -EINVAL;
	if (skb->len < total_len)
		return -EINVAL;
	if (unlikely(!pskb_may_pull(skb, total_len)))
		return -EINVAL;
	if (skb_ensure_writable(skb, total_len))
		return -EFAULT;
	if (total_len > skb_headlen(skb))
		return -EINVAL;

	dst = skb->data;
	trustix_kudp_tx_write_udp_header(dst, args, false);
	return 0;
}

__bpf_kfunc int
trustix_kernel_skb_kudp_tx_finalize_udp_header(
				struct sk_buff *skb,
				const struct trustix_kudp_tx_udp_header_args *args,
				u32 clear_flags)
{
	u32 total_len = ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr) +
			TRUSTIX_KUDP_HEADER_LEN;
	struct skb_shared_info *shinfo;
	bool partial_csum;
	u8 *dst;

	if (!skb || !args)
		return -EINVAL;
	if (args->flags & ~TRUSTIX_KUDP_FLAG_ENCRYPTED)
		return -EINVAL;
	if (clear_flags & ~(TRUSTIX_SKB_CLEAR_TX_OFFLOAD_CSUM |
			    TRUSTIX_SKB_CLEAR_TX_OFFLOAD_GSO |
			    TRUSTIX_SKB_CLEAR_TX_OFFLOAD_ENCAP |
			    TRUSTIX_KUDP_TX_UDP_HEADER_PARTIAL_CSUM))
		return -EINVAL;
	if ((clear_flags & TRUSTIX_KUDP_TX_UDP_HEADER_PARTIAL_CSUM) &&
	    (clear_flags & TRUSTIX_SKB_CLEAR_TX_OFFLOAD_CSUM))
		return -EINVAL;
	if (skb->len < total_len)
		return -EINVAL;
	if (unlikely(!pskb_may_pull(skb, total_len)))
		return -EINVAL;
	if (skb_ensure_writable(skb, total_len))
		return -EFAULT;
	if (total_len > skb_headlen(skb))
		return -EINVAL;

	dst = skb->data;
	shinfo = skb_shinfo(skb);
	partial_csum = (clear_flags & TRUSTIX_KUDP_TX_UDP_HEADER_PARTIAL_CSUM) &&
		       shinfo->gso_size;
	trustix_kudp_tx_write_udp_header(dst, args, partial_csum);
	if (partial_csum) {
		skb_reset_mac_header(skb);
		skb_set_network_header(skb, ETH_HLEN);
		skb_set_transport_header(skb, ETH_HLEN + sizeof(struct iphdr));
		skb->mac_len = ETH_HLEN;
		skb->protocol = htons(ETH_P_IP);
		skb->ip_summed = CHECKSUM_PARTIAL;
		skb->csum_start = skb_transport_header(skb) - skb->head;
		skb->csum_offset = offsetof(struct udphdr, check);
		skb->encapsulation = 1;
		shinfo->gso_type |= SKB_GSO_UDP_TUNNEL;
#ifdef SKB_GSO_UDP_TUNNEL_CSUM
		shinfo->gso_type |= SKB_GSO_UDP_TUNNEL_CSUM;
#endif
	}
	if (clear_flags & TRUSTIX_SKB_CLEAR_TX_OFFLOAD_CSUM)
		trustix_skb_clear_csum_metadata(skb);
	if (clear_flags & TRUSTIX_SKB_CLEAR_TX_OFFLOAD_ENCAP)
		skb->encapsulation = 0;
	if (clear_flags & TRUSTIX_SKB_CLEAR_TX_OFFLOAD_GSO)
		skb_gso_reset(skb);
	return 0;
}

__bpf_kfunc int
trustix_kernel_skb_kudp_tx_push_udp_header(
				struct sk_buff *skb,
				const struct trustix_kudp_tx_udp_header_args *args,
				u32 flags)
{
	u32 header_len = ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr) +
			TRUSTIX_KUDP_HEADER_LEN;
	u32 push_len = header_len - ETH_HLEN;
	struct skb_shared_info *shinfo;
	bool partial_csum;
	u8 *dst;

	if (!skb || !args)
		return -EINVAL;
	if (args->flags & ~TRUSTIX_KUDP_FLAG_ENCRYPTED)
		return -EINVAL;
	if (flags & ~TRUSTIX_KUDP_TX_UDP_HEADER_PARTIAL_CSUM)
		return -EINVAL;
	if (unlikely(skb_cow_head(skb, push_len)))
		return -ENOMEM;

	skb_reset_inner_headers(skb);
	skb_push(skb, push_len);
	dst = skb->data;
	shinfo = skb_shinfo(skb);
	partial_csum = (flags & TRUSTIX_KUDP_TX_UDP_HEADER_PARTIAL_CSUM) &&
		       shinfo->gso_size;
	trustix_kudp_tx_write_udp_header(dst, args, partial_csum);

	skb_reset_mac_header(skb);
	skb_set_network_header(skb, ETH_HLEN);
	skb_set_transport_header(skb, ETH_HLEN + sizeof(struct iphdr));
	skb->mac_len = ETH_HLEN;
	skb->protocol = htons(ETH_P_IP);
	skb->encapsulation = 1;
	skb_set_inner_protocol(skb, htons(ETH_P_IP));
	skb_set_inner_mac_header(skb, header_len);
	skb_set_inner_network_header(skb, header_len);
	skb_set_inner_transport_header(skb, header_len + sizeof(struct iphdr));

	if (partial_csum) {
		skb->ip_summed = CHECKSUM_PARTIAL;
		skb->csum_start = skb_transport_header(skb) - skb->head;
		skb->csum_offset = offsetof(struct udphdr, check);
		shinfo->gso_type |= SKB_GSO_UDP_TUNNEL;
#ifdef SKB_GSO_UDP_TUNNEL_CSUM
		shinfo->gso_type |= SKB_GSO_UDP_TUNNEL_CSUM;
#endif
	} else if (shinfo->gso_size) {
		shinfo->gso_type |= SKB_GSO_UDP_TUNNEL;
	}
	return 0;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(trustix_datapath_helpers_tc_kfunc_ids)
BTF_ID_FLAGS(func, trustix_kernel_skb_clear_tx_offload)
BTF_ID_FLAGS(func, trustix_kernel_skb_fix_inner_tcp_csum)
BTF_ID_FLAGS(func, trustix_kernel_skb_kudp_rx_decap_l2)
BTF_ID_FLAGS(func, trustix_kernel_skb_kudp_rx_decap_l2_dev)
BTF_ID_FLAGS(func, trustix_kernel_skb_kudp_rx_parse_decap_l2)
BTF_ID_FLAGS(func, trustix_kernel_skb_tixt_fix_outer_tcp_csum)
BTF_ID_FLAGS(func, trustix_kernel_skb_tixt_tx_finalize_tcp_header)
BTF_ID_FLAGS(func, trustix_kernel_skb_tixt_tx_set_tcp_partial_csum)
BTF_ID_FLAGS(func, trustix_kernel_skb_tixt_tx_push_tcp_header)
BTF_ID_FLAGS(func, trustix_kernel_skb_tixt_tx_push_flow_tcp_header)
BTF_ID_FLAGS(func, trustix_kernel_skb_tixt_tx_finalize_flow_tcp_header)
BTF_ID_FLAGS(func, trustix_kernel_skb_tixt_tx_push_route_tcp_header)
BTF_ID_FLAGS(func, trustix_kernel_skb_tixt_tx_segment_route_tcp_gso)
BTF_ID_FLAGS(func, trustix_kernel_skb_tixt_tx_segment_secure_route_tcp_gso)
BTF_ID_FLAGS(func, trustix_kernel_skb_tixt_tx_route_tcp)
BTF_ID_FLAGS(func, trustix_kernel_skb_tixt_tx_route_tcp_xmit)
BTF_ID_FLAGS(func, trustix_kernel_skb_kudp_tx_store_l2_l3_l4)
BTF_ID_FLAGS(func, trustix_kernel_skb_kudp_tx_build_udp_header)
BTF_ID_FLAGS(func, trustix_kernel_skb_kudp_tx_finalize_udp_header)
BTF_ID_FLAGS(func, trustix_kernel_skb_kudp_tx_push_udp_header)
BTF_KFUNCS_END(trustix_datapath_helpers_tc_kfunc_ids)

static const struct btf_kfunc_id_set trustix_datapath_helpers_tc_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &trustix_datapath_helpers_tc_kfunc_ids,
};

void trustix_datapath_helpers_disable_panic_risk_params(void)
{
	/*
	 * First-release high-performance knobs must stay selectable so the
	 * datapath can self-degrade under validation instead of hiding unstable
	 * combinations behind module-load side effects.
	 */
}

int trustix_datapath_helpers_register(void)
{
	unsigned int i;
	int ret;

	WRITE_ONCE(trustix_route_tcp_gso_async_quiescing, false);
	WRITE_ONCE(trustix_tixt_rx_backlog_worker_quiescing, false);
	WRITE_ONCE(trustix_tixt_rx_backlog_worker_scheduled, false);
	WRITE_ONCE(trustix_tixt_rx_backlog_worker_depth, 0);
	skb_queue_head_init(&trustix_tixt_rx_backlog_worker_queue);
	skb_queue_head_init(&trustix_route_tcp_xmit_worker_queue);
	trustix_hrtimer_setup(&trustix_route_tcp_gso_async_schedule_timer,
			      trustix_route_tcp_gso_async_schedule_timer_fn,
			      CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	for (i = 0; i < TRUSTIX_ROUTE_TCP_GSO_ASYNC_MAX_QUEUE_SHARDS; i++) {
		INIT_LIST_HEAD(&trustix_route_tcp_gso_async_shards[i].queue);
		spin_lock_init(&trustix_route_tcp_gso_async_shards[i].lock);
		INIT_DELAYED_WORK(&trustix_route_tcp_gso_async_shards[i].work,
				  trustix_route_tcp_gso_async_shard_worker_fn);
		trustix_hrtimer_setup(&trustix_route_tcp_gso_async_shards[i].schedule_timer,
				      trustix_route_tcp_gso_async_shard_schedule_timer_fn,
				      CLOCK_MONOTONIC, HRTIMER_MODE_REL);
		trustix_route_tcp_gso_async_shards[i].scheduled = false;
		trustix_route_tcp_gso_async_shards[i].delay_pending = false;
		trustix_route_tcp_gso_async_shards[i].depth_defers = 0;
	}
	trustix_tixt_rx_single_coalesce_init_slots();

	trustix_route_tcp_gso_async_work_cache = kmem_cache_create(
		"trustix_route_tcp_gso_async_work",
		sizeof(struct trustix_tixt_tx_route_gso_async_work),
		0, SLAB_HWCACHE_ALIGN, NULL);
	if (!trustix_route_tcp_gso_async_work_cache)
		return -ENOMEM;

	trustix_route_tcp_gso_async_cross_item_cache = kmem_cache_create(
		"trustix_route_tcp_gso_async_cross_item",
		sizeof(struct trustix_route_tcp_gso_async_cross_item_batch),
		0, SLAB_HWCACHE_ALIGN, NULL);
	if (!trustix_route_tcp_gso_async_cross_item_cache) {
		kmem_cache_destroy(trustix_route_tcp_gso_async_work_cache);
		trustix_route_tcp_gso_async_work_cache = NULL;
		return -ENOMEM;
	}

	trustix_route_tcp_gso_async_wq = alloc_workqueue(
		"trustix_route_tcp_gso_async",
		WQ_UNBOUND | WQ_HIGHPRI | WQ_MEM_RECLAIM,
		TRUSTIX_ROUTE_TCP_GSO_ASYNC_MAX_QUEUE_SHARDS);
	if (!trustix_route_tcp_gso_async_wq) {
		kmem_cache_destroy(trustix_route_tcp_gso_async_cross_item_cache);
		trustix_route_tcp_gso_async_cross_item_cache = NULL;
		kmem_cache_destroy(trustix_route_tcp_gso_async_work_cache);
		trustix_route_tcp_gso_async_work_cache = NULL;
		return -ENOMEM;
	}

	ret = register_netdevice_notifier(
		&trustix_datapath_helpers_netdev_notifier);
	if (ret) {
		destroy_workqueue(trustix_route_tcp_gso_async_wq);
		trustix_route_tcp_gso_async_wq = NULL;
		kmem_cache_destroy(trustix_route_tcp_gso_async_cross_item_cache);
		trustix_route_tcp_gso_async_cross_item_cache = NULL;
		kmem_cache_destroy(trustix_route_tcp_gso_async_work_cache);
		trustix_route_tcp_gso_async_work_cache = NULL;
		return ret;
	}
	trustix_datapath_helpers_netdev_notifier_registered = true;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS,
					&trustix_datapath_helpers_tc_kfunc_set);
	if (ret) {
		unregister_netdevice_notifier(
			&trustix_datapath_helpers_netdev_notifier);
		trustix_datapath_helpers_netdev_notifier_registered = false;
		destroy_workqueue(trustix_route_tcp_gso_async_wq);
		trustix_route_tcp_gso_async_wq = NULL;
		kmem_cache_destroy(trustix_route_tcp_gso_async_cross_item_cache);
		trustix_route_tcp_gso_async_cross_item_cache = NULL;
		kmem_cache_destroy(trustix_route_tcp_gso_async_work_cache);
		trustix_route_tcp_gso_async_work_cache = NULL;
		return ret;
	}
	trustix_datapath_helpers_registered = true;
	return 0;
}

void trustix_datapath_helpers_unregister(void)
{
	WRITE_ONCE(trustix_datapath_helpers_registered, false);
	if (trustix_datapath_helpers_netdev_notifier_registered) {
		unregister_netdevice_notifier(
			&trustix_datapath_helpers_netdev_notifier);
		trustix_datapath_helpers_netdev_notifier_registered = false;
	}
	WRITE_ONCE(trustix_tixt_rx_single_coalesce_slots_ready, false);
	WRITE_ONCE(trustix_tixt_rx_backlog_worker_quiescing, true);
	WRITE_ONCE(trustix_route_tcp_gso_async_quiescing, true);
	WRITE_ONCE(trustix_route_tcp_gso_async_dev_xmit, false);
	WRITE_ONCE(trustix_route_tcp_gso_async_prefer, false);
	WRITE_ONCE(trustix_route_tcp_gso_async, false);
	WRITE_ONCE(trustix_route_tcp_gso, false);
	synchronize_net();
	trustix_route_tcp_gso_async_flush();
	WRITE_ONCE(trustix_route_tcp_gso_async_unbound_worker, false);
	WRITE_ONCE(trustix_route_tcp_gso_async_sharded_queue, false);
	WRITE_ONCE(trustix_route_tcp_gso_async_queue_shards, 4);
	WRITE_ONCE(trustix_route_tcp_gso_async_flow_shard_queue, false);
	WRITE_ONCE(trustix_route_tcp_gso_async_worker_dequeue_batch, 1);
	WRITE_ONCE(trustix_route_tcp_gso_async_worker_min_queue_depth, 0);
	WRITE_ONCE(trustix_route_tcp_gso_async_worker_max_depth_defers, 0);
	WRITE_ONCE(trustix_route_tcp_gso_async_worker_schedule_delay_jiffies,
		   0);
	WRITE_ONCE(trustix_route_tcp_gso_async_worker_schedule_delay_usecs,
		   0);
	WRITE_ONCE(trustix_route_tcp_gso_async_worker_schedule_delay_no_accel,
		   false);
	WRITE_ONCE(trustix_route_tcp_gso_async_worker_budget_reschedule_delay_jiffies,
		   0);
	WRITE_ONCE(trustix_route_tcp_gso_async_worker_budget_reschedule_delay_usecs,
		   0);
	WRITE_ONCE(trustix_route_tcp_gso_async_worker_emit_budget, 0);
	WRITE_ONCE(trustix_route_tcp_gso_async_stream_outer_gso, false);
	WRITE_ONCE(trustix_route_tcp_gso_async_stream_outer_gso_hard_enable,
		   false);
	WRITE_ONCE(trustix_route_tcp_gso_async_stream_cross_item_batch,
		   false);
	WRITE_ONCE(trustix_route_tcp_gso_async_stream_cross_item_dequeue_batch,
		   false);
	WRITE_ONCE(trustix_route_tcp_gso_async_stream_cross_item_tail_stitch,
		   false);
	WRITE_ONCE(trustix_route_tcp_gso_async_stream_cross_item_debug,
		   false);
	WRITE_ONCE(trustix_route_tcp_gso_async_stream_cross_item_max_frames,
		   0);
	WRITE_ONCE(trustix_route_tcp_gso_async_stream_cross_item_lookahead,
		   0);
	WRITE_ONCE(trustix_route_tcp_gso_async_stream_cross_item_dynamic_cap,
		   false);
	WRITE_ONCE(
		trustix_route_tcp_gso_async_stream_cross_item_dynamic_low_frames,
		0);
	WRITE_ONCE(
		trustix_route_tcp_gso_async_stream_cross_item_dynamic_queue_depth,
		0);
	WRITE_ONCE(trustix_route_tcp_gso_async_stream_cross_item_last_ret,
		   0);
	WRITE_ONCE(trustix_route_tcp_gso_async_stream_cross_item_last_stage,
		   0);
	WRITE_ONCE(trustix_route_tcp_gso_async_stream_cross_item_last_items,
		   0);
	WRITE_ONCE(trustix_route_tcp_gso_async_stream_cross_item_last_frames,
		   0);
	WRITE_ONCE(trustix_route_tcp_gso_async_stream_cross_item_last_stream_payload_len,
		   0);
	WRITE_ONCE(trustix_route_tcp_gso_async_stream_cross_item_last_outer_gso_size,
		   0);
	WRITE_ONCE(trustix_route_tcp_gso_async_stream_cross_item_last_first_frame_len,
		   0);
	WRITE_ONCE(trustix_route_tcp_gso_async_stream_cross_item_last_last_frame_len,
		   0);
	WRITE_ONCE(trustix_route_tcp_gso_async_stream_direct_build_fast_copy,
		   true);
	WRITE_ONCE(trustix_route_tcp_gso_async_stream_direct_build_frag_fast_copy,
		   true);
	WRITE_ONCE(trustix_route_tcp_gso_async_stream_direct_build_frag_fast_copy_cross_page,
		   false);
	WRITE_ONCE(trustix_route_tcp_gso_async_reslice_to_mtu, false);
	WRITE_ONCE(trustix_route_tcp_gso_async_hash_tx_queue, false);
	WRITE_ONCE(trustix_route_tcp_gso_async_yield_on_xmit_cn, false);
	WRITE_ONCE(trustix_route_tcp_gso_async_xmit_cn_sleep_usecs, 0);
	WRITE_ONCE(trustix_route_tcp_gso_async_xmit_busy_retries, 2);
	WRITE_ONCE(trustix_route_tcp_gso_async_xmit_busy_sleep_usecs, 0);
	trustix_tixt_rx_backlog_worker_flush();
	WRITE_ONCE(trustix_tixt_rx_backlog_worker_budget, 2048);
	WRITE_ONCE(trustix_tixt_rx_backlog_worker_queue_limit, 8192);
	WRITE_ONCE(trustix_tixt_rx_stream_ordered_list, false);
	WRITE_ONCE(trustix_tixt_rx_stream_gso_xmit, false);
	WRITE_ONCE(trustix_tixt_rx_stream_coalesce_gso, false);
	WRITE_ONCE(trustix_tixt_rx_stream_coalesce_mark_gso, false);
	WRITE_ONCE(trustix_tixt_rx_stream_nonlinear_parse, false);
	WRITE_ONCE(trustix_tixt_rx_single_coalesce_gso, false);
	WRITE_ONCE(trustix_tixt_rx_single_coalesce_mark_gso, false);
	WRITE_ONCE(trustix_tixt_rx_coalesce_mark_gso_partial_csum, false);
	WRITE_ONCE(trustix_tixt_rx_coalesce_segment_gso, false);
	WRITE_ONCE(trustix_tixt_rx_single_coalesce_direct_list, false);
	WRITE_ONCE(trustix_tixt_rx_single_coalesce_direct_list_max_frames,
		   TRUSTIX_TIXT_RX_SINGLE_COALESCE_DIRECT_LIST_DEFAULT_MAX_FRAMES);
	WRITE_ONCE(trustix_tixt_rx_single_coalesce_page_only, false);
	WRITE_ONCE(trustix_tixt_rx_single_coalesce_linear_build, false);
	WRITE_ONCE(trustix_tixt_rx_single_coalesce_hybrid_head, false);
	WRITE_ONCE(trustix_tixt_rx_single_coalesce_netif_rx, false);
	WRITE_ONCE(trustix_tixt_rx_single_coalesce_schedule_once, false);
	WRITE_ONCE(trustix_tixt_rx_single_coalesce_stream_fallback, false);
	WRITE_ONCE(trustix_tixt_rx_single_coalesce_hot_stats, false);
	WRITE_ONCE(trustix_tixt_rx_single_coalesce_defer_full_flush, false);
	WRITE_ONCE(trustix_tixt_rx_single_coalesce_keep_full_timer, false);
	WRITE_ONCE(trustix_tixt_rx_single_coalesce_set_hash, false);
	WRITE_ONCE(trustix_tixt_rx_single_coalesce_schedule_stride, 1);
	WRITE_ONCE(trustix_tixt_rx_single_coalesce_warmup_frames, 1);
	WRITE_ONCE(trustix_tixt_rx_single_coalesce_linear_max,
		   TRUSTIX_TIXT_RX_SINGLE_COALESCE_LINEAR_MAX);
	synchronize_net();
	trustix_tixt_rx_single_coalesce_drop_all();
	WRITE_ONCE(trustix_route_tcp_xmit_worker, false);
	trustix_route_tcp_xmit_worker_flush();
	if (trustix_route_tcp_gso_async_wq) {
		destroy_workqueue(trustix_route_tcp_gso_async_wq);
		trustix_route_tcp_gso_async_wq = NULL;
	}
	if (trustix_route_tcp_gso_async_cross_item_cache) {
		kmem_cache_destroy(trustix_route_tcp_gso_async_cross_item_cache);
		trustix_route_tcp_gso_async_cross_item_cache = NULL;
	}
	if (trustix_route_tcp_gso_async_work_cache) {
		kmem_cache_destroy(trustix_route_tcp_gso_async_work_cache);
		trustix_route_tcp_gso_async_work_cache = NULL;
	}
}

__u64 trustix_datapath_helpers_feature_mask(void)
{
	if (!READ_ONCE(trustix_datapath_helpers_registered))
		return 0;
	return TRUSTIX_DATAPATH_FEATURE_GSO_SKB |
	       TRUSTIX_DATAPATH_FEATURE_KFUNC_TC |
	       TRUSTIX_DATAPATH_FEATURE_ROUTE_TCP_KFUNC |
	       TRUSTIX_DATAPATH_FEATURE_ROUTE_TCP_XMIT_KFUNC;
}
