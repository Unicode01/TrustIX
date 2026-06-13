// SPDX-License-Identifier: GPL-2.0 OR MIT
// TC egress-builder for secure kernel transport TX. It runs before the generic
// TrustIX LAN ingress program, encrypts eligible inner IPv4 packets with the
// provider-owned AEAD context, builds UDP/TIXU or TCP-shaped TIXT in-place,
// and redirects to the underlay. Unsupported packets return TC_ACT_UNSPEC so
// lower-priority TrustIX and external TC filters can still handle them.
#define SEC(NAME) __attribute__((section(NAME), used))
#define __ksym __attribute__((section(".ksyms")))
#define __always_inline inline __attribute__((always_inline))
#define __noinline __attribute__((noinline))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __kptr __attribute__((btf_type_tag("kptr")))
#define barrier_var(var) asm volatile("" : "+r"(var))

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef int __s32;
typedef long long __s64;
typedef unsigned long long __u64;

#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_LPM_TRIE 11
#define BPF_MAP_TYPE_PERCPU_ARRAY 6

#define BPF_F_NO_PREALLOC 1
#define BPF_ANY 0
#define BPF_ADJ_ROOM_MAC 1
#define BPF_F_RECOMPUTE_CSUM 1
#define BPF_F_INVALIDATE_HASH 2
#define BPF_F_ADJ_ROOM_FIXED_GSO 1
#define BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 2
#define BPF_F_ADJ_ROOM_ENCAP_L4_UDP 16
#define BPF_F_ADJ_ROOM_NO_CSUM_RESET 32

const volatile __u32 trustix_kudp_tx_adjust_room_flags = 0;
const volatile __u32 trustix_kudp_tx_direct_seal_kfunc = 0;
const volatile __u32 trustix_kudp_tx_secure_skb_seal_kfunc = 0;
const volatile __u32 trustix_kudp_tx_fix_inner_checksums = 1;
const volatile __u32 trustix_kudp_tx_secure_inner_tcp_csum_kfunc = 0;
const volatile __u32 trustix_kudp_tx_secure_outer_tcp_csum_kfunc = 0;
const volatile __u32 trustix_kudp_tx_secure_outer_tcp_partial_csum_kfunc = 0;

#ifndef TRUSTIX_KUDP_SECURE_BPF_CRYPTO
#define TRUSTIX_KUDP_SECURE_BPF_CRYPTO 0
#endif

#ifndef TRUSTIX_KUDP_SECURE_SKB_SEAL_KFUNC
#define TRUSTIX_KUDP_SECURE_SKB_SEAL_KFUNC 0
#endif

#define TC_ACT_OK 0
#define TC_ACT_UNSPEC (-1)
#define TC_ACT_SHOT 2

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define TRUSTIX_TCP_FLAG_SYN 0x02
#define TRUSTIX_TCP_OPT_EOL 0
#define TRUSTIX_TCP_OPT_NOP 1
#define TRUSTIX_TCP_OPT_MSS 2
#define TRUSTIX_TCP_MSS_MIN_IPV4 536
#define TRUSTIX_TCP_MSS_MAX 65535
#define TRUSTIX_TCP_MSS_OPTION_BUDGET 40
#define TRUSTIX_KERNEL_UDP_MAGIC 0x54495855U
#define TRUSTIX_KERNEL_UDP_VERSION 1
#define TRUSTIX_KERNEL_UDP_HEADER_LEN 32
#define TRUSTIX_KERNEL_UDP_FLAG_ENCRYPTED 1
#define TRUSTIX_KERNEL_UDP_FLAG_INNER_IPV4 8
#define TRUSTIX_EXP_TCP_VERSION 1
#define TRUSTIX_EXP_TCP_HEADER_LEN 40
#define TRUSTIX_EXP_TCP_FLAG_ENCRYPTED 1
#define TRUSTIX_EXP_TCP_FLAG_INNER_IPV4 8
#define TRUSTIX_KERNEL_CRYPTO_NAMESPACE_EXPERIMENTAL_TCP 0
#define TRUSTIX_KERNEL_CRYPTO_NAMESPACE_KERNEL_UDP 1
#define TRUSTIX_KERNEL_CRYPTO_DIRECTION_SEND 1
#define TRUSTIX_KERNEL_CRYPTO_FRAME_TAG_LEN 16
#define TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN 24
#define TRUSTIX_KERNEL_CRYPTO_FRAME_MAX 4095
#define TRUSTIX_KERNEL_CRYPTO_FRAME_PADDED 4096
#define TRUSTIX_KERNEL_CRYPTO_PLAIN_MAX (TRUSTIX_KERNEL_CRYPTO_FRAME_MAX - TRUSTIX_KERNEL_CRYPTO_FRAME_TAG_LEN)
#define TRUSTIX_KERNEL_CRYPTO_REPLAY_WORDS 64
#define TRUSTIX_KERNEL_CRYPTO_CSUM_CHUNK 512
#define TRUSTIX_KUDP_SECURE_OUTER_OVERHEAD (20 + 8 + TRUSTIX_KERNEL_UDP_HEADER_LEN + TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN + TRUSTIX_KERNEL_CRYPTO_FRAME_TAG_LEN)
#define TRUSTIX_KUDP_SECURE_PACKET_HEADER_LEN (14 + 20 + 8 + TRUSTIX_KERNEL_UDP_HEADER_LEN + TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN)
#define TRUSTIX_KUDP_SECURE_CIPHER_OFFSET TRUSTIX_KUDP_SECURE_PACKET_HEADER_LEN
#define TRUSTIX_EXP_TCP_SECURE_OUTER_OVERHEAD (20 + 20 + TRUSTIX_EXP_TCP_HEADER_LEN + TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN + TRUSTIX_KERNEL_CRYPTO_FRAME_TAG_LEN)
#define TRUSTIX_EXP_TCP_SECURE_PACKET_HEADER_LEN (14 + 20 + 20 + TRUSTIX_EXP_TCP_HEADER_LEN + TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN)
#define TRUSTIX_EXP_TCP_SECURE_CIPHER_OFFSET TRUSTIX_EXP_TCP_SECURE_PACKET_HEADER_LEN
#define TRUSTIX_KTX_SECURE_PACKET_HEADER_LEN TRUSTIX_EXP_TCP_SECURE_PACKET_HEADER_LEN
#define TRUSTIX_KTX_SECURE_PACKET_MAX (TRUSTIX_KTX_SECURE_PACKET_HEADER_LEN + TRUSTIX_KERNEL_CRYPTO_FRAME_PADDED)
#define TRUSTIX_KUDP_TX_FLOW_FLAG_SECURE 1
#define TRUSTIX_KUDP_TX_FLOW_FLAG_TRUST_INNER_CHECKSUM 2
#define TRUSTIX_KUDP_TX_FLOW_FLAG_HOT_STATS 4
#define TRUSTIX_KUDP_TX_FLOW_FLAG_EXPERIMENTAL_TCP 8
#define TRUSTIX_KUDP_TX_FLOW_FLAG_SKIP_OUTER_TCP_CHECKSUM 16
#define TRUSTIX_KERNEL_CRYPTO_FLOW_FLAG_HOT_STATS 1
#define TRUSTIX_KUDP_TX_ROUTE_FLAG_BYPASS 4
#define TRUSTIX_KUDP_TX_CIPHER_BUFFER_SPLIT 0
#define TRUSTIX_KUDP_TX_CIPHER_BUFFER_PLAIN 1

#define TRUSTIX_KUDP_TX_SECURE_STAT_ATTEMPTS 34
#define TRUSTIX_KUDP_TX_SECURE_STAT_CANDIDATES 35
#define TRUSTIX_KUDP_TX_SECURE_STAT_SUCCESSES 36
#define TRUSTIX_KUDP_TX_SECURE_STAT_FALLBACKS 37
#define TRUSTIX_KUDP_TX_SECURE_STAT_NO_CONTEXT 38
#define TRUSTIX_KUDP_TX_SECURE_STAT_HEADER_ERRORS 39
#define TRUSTIX_KUDP_TX_SECURE_STAT_ENCRYPT_ERRORS 40
#define TRUSTIX_KUDP_TX_SECURE_STAT_SEQUENCE_ERRORS 41
#define TRUSTIX_KUDP_TX_SECURE_STAT_MTU_FALLBACKS 42
#define TRUSTIX_KUDP_TX_SECURE_STAT_DROPS 43
#define TRUSTIX_KUDP_TX_SECURE_STAT_ROUTE_MISSES 44
#define TRUSTIX_KUDP_TX_SECURE_STAT_FLOW_MISSES 45
#define TRUSTIX_KUDP_TX_SECURE_STAT_FLAG_MISSES 46
#define TRUSTIX_KUDP_TX_SECURE_STAT_FRAGMENT_FALLBACKS 47
#define TRUSTIX_KUDP_TX_SECURE_STAT_LEN_MISMATCHES 48
#define TRUSTIX_KUDP_TX_SECURE_STAT_NON_TCP_FALLBACKS 49
#define TRUSTIX_KUDP_TX_SECURE_STAT_SYN_FALLBACKS 50
#define TRUSTIX_KUDP_TX_SECURE_STAT_CHECKSUM_FALLBACKS 51
#define TRUSTIX_KUDP_TX_SECURE_STAT_MTU_PLAIN_MAX_FALLBACKS 52
#define TRUSTIX_KUDP_TX_SECURE_STAT_MTU_UNDERLAY_FALLBACKS 53
#define TRUSTIX_KUDP_TX_SECURE_STAT_LEN_GSO_FALLBACKS 54
#define TRUSTIX_KUDP_TX_SECURE_STAT_LEN_SHORT_FALLBACKS 55
#define TRUSTIX_KUDP_TX_SECURE_STAT_MTU_UNDERLAY_1500ISH_FALLBACKS 56
#define TRUSTIX_KUDP_TX_SECURE_STAT_MTU_UNDERLAY_JUMBO_FALLBACKS 57
#define TRUSTIX_KUDP_TX_SECURE_STAT_MTU_UNDERLAY_INNER_GT_1400_FALLBACKS 58
#define TRUSTIX_KUDP_TX_SECURE_STAT_MTU_UNDERLAY_INNER_LE_1400_FALLBACKS 59
#define TRUSTIX_KUDP_TX_SECURE_STAT_FLOW_INDEX_MISSES 176
#define TRUSTIX_KUDP_TX_SECURE_STAT_DIRECT_SLOT_MISSES 177
#define TRUSTIX_KUDP_TX_SECURE_STAT_DIRECT_SLOT_DISABLED 178
#define TRUSTIX_KUDP_TX_SECURE_STAT_SKB_SEAL_SUCCESSES 179
#define TRUSTIX_KUDP_TX_SECURE_STAT_SKB_SEAL_ERRORS 180
#define TRUSTIX_KUDP_TX_SECURE_STAT_SKB_SEAL_EINVAL 181
#define TRUSTIX_KUDP_TX_SECURE_STAT_SKB_SEAL_EOPNOTSUPP 182
#define TRUSTIX_KUDP_TX_SECURE_STAT_SKB_SEAL_EFAULT 183
#define TRUSTIX_KUDP_TX_SECURE_STAT_OUTER_TCP_CSUM_KFUNC_SUCCESSES 184
#define TRUSTIX_KUDP_TX_SECURE_STAT_OUTER_TCP_CSUM_KFUNC_ERRORS 185
#define TRUSTIX_KUDP_TX_SECURE_STAT_OUTER_TCP_PARTIAL_CSUM_KFUNC_SUCCESSES 186
#define TRUSTIX_KUDP_TX_SECURE_STAT_OUTER_TCP_PARTIAL_CSUM_KFUNC_ERRORS 187
#define TRUSTIX_KUDP_TX_SECURE_STAT_INNER_TCP_CSUM_KFUNC_SUCCESSES 188
#define TRUSTIX_KUDP_TX_SECURE_STAT_INNER_TCP_CSUM_KFUNC_FALLBACKS 189

#define TRUSTIX_TIXT_TX_FINALIZE_TCP_PARTIAL_CSUM (1U << 8)

struct __sk_buff {
    __u32 len;
    __u32 pkt_type;
    __u32 mark;
    __u32 queue_mapping;
    __u32 protocol;
    __u32 vlan_present;
    __u32 vlan_tci;
    __u32 vlan_proto;
    __u32 priority;
    __u32 ingress_ifindex;
    __u32 ifindex;
    __u32 tc_index;
    __u32 cb[5];
    __u32 hash;
    __u32 tc_classid;
    __u32 data;
    __u32 data_end;
};

struct bpf_dynptr {
    __u64 __opaque[2];
};

struct bpf_crypto_ctx {};

struct trustix_route_key {
    __u32 prefix_len;
    __u8 addr[4];
};

struct trustix_kudp_tx_flow_value {
    __u64 sequence;
    __u8 source_ip[4];
    __u8 destination_ip[4];
    __u8 source_port[2];
    __u8 destination_port[2];
    __u32 ifindex;
    __u8 destination_mac[6];
    __u16 ipv4_checksum_udp;
    __u8 source_mac[6];
    __u16 ipv4_checksum_tcp;
    __u32 mtu;
    __u32 flags;
};

struct trustix_kudp_tx_route_value {
    __u64 flow_id;
    __u64 flow_id_1;
    __u64 flow_id_2;
    __u64 flow_id_3;
    __u64 flow_id_4;
    __u64 flow_id_5;
    __u64 flow_id_6;
    __u64 flow_id_7;
    __u64 flow_id_8;
    __u32 flow_mask;
    __u32 flags;
    struct trustix_kudp_tx_flow_value inline_flow_1;
    struct trustix_kudp_tx_flow_value inline_flow_2;
    struct trustix_kudp_tx_flow_value inline_flow_3;
    struct trustix_kudp_tx_flow_value inline_flow_4;
    struct trustix_kudp_tx_flow_value inline_flow_5;
    struct trustix_kudp_tx_flow_value inline_flow_6;
    struct trustix_kudp_tx_flow_value inline_flow_7;
    struct trustix_kudp_tx_flow_value inline_flow_8;
};

struct trustix_kernel_crypto_flow_key {
    __u64 flow_id;
    __u8 direction;
    __u8 reserved[7];
};

struct trustix_kernel_crypto_ctx_value {
    struct bpf_crypto_ctx __kptr *ctx;
    __u16 suite;
    __u16 wire_format;
    __u32 flags;
    __u64 epoch;
    __u8 iv[12];
    __u32 replay_window;
    __s64 installed_unix;
    __u64 packets;
    __u64 bytes;
    __u64 last_sequence;
    __u64 replay_seen[TRUSTIX_KERNEL_CRYPTO_REPLAY_WORDS];
    __u64 replay_blocks[TRUSTIX_KERNEL_CRYPTO_REPLAY_WORDS];
};

struct trustix_kernel_crypto_direct_slot {
    __u32 slot_id;
    __u32 enabled;
    __u16 suite;
    __u16 wire_format;
    __u32 flags;
    __u64 epoch;
    __u8 iv[12];
    __u32 replay_window;
    __s64 installed_unix;
    __u64 packets;
    __u64 bytes;
    __u64 last_sequence;
    __u64 replay_seen[TRUSTIX_KERNEL_CRYPTO_REPLAY_WORDS];
    __u64 replay_blocks[TRUSTIX_KERNEL_CRYPTO_REPLAY_WORDS];
};

struct trustix_kudp_tx_scratch {
    __u8 plain[TRUSTIX_KERNEL_CRYPTO_FRAME_PADDED];
    union {
        struct {
            __u8 cipher[TRUSTIX_KERNEL_CRYPTO_FRAME_PADDED];
            __u8 header[TRUSTIX_KTX_SECURE_PACKET_HEADER_LEN];
        } split;
        __u8 packet[TRUSTIX_KTX_SECURE_PACKET_MAX];
    } io;
    __u8 nonce[12];
    __u16 suite;
    __u16 pad0;
    __u32 cipher_buffer;
    __u64 epoch;
    __u64 sequence;
};

struct trustix_l4_csum_header {
    __u8 pseudo[12];
};

struct trustix_aead_skb_direct_seal_args {
    __u32 slot_id;
    __u32 plain_offset;
    __u32 cipher_offset;
    __u32 plain_len;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 184);
    __type(key, __u32);
    __type(value, __u64);
} ix_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 4096);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct trustix_route_key);
    __type(value, struct trustix_kudp_tx_route_value);
} ix_kudp_tx_route SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct trustix_kudp_tx_flow_value);
} ix_kudp_tx_flow SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct trustix_kernel_crypto_flow_key);
    __type(value, __u32);
} trustix_kernel_crypto_flow_index_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, struct trustix_kernel_crypto_ctx_value);
} trustix_kernel_crypto_ctx_slots SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, struct trustix_kernel_crypto_direct_slot);
} trustix_kernel_crypto_direct_slots SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct trustix_kudp_tx_scratch);
} ix_kudp_tx_secure_scratch SEC(".maps");

static void *(*bpf_map_lookup_elem)(const void *map, const void *key) = (void *)1;
static long (*bpf_skb_store_bytes)(struct __sk_buff *skb, __u32 offset, const void *from, __u32 len, __u64 flags) = (void *)9;
static long (*bpf_skb_load_bytes)(const struct __sk_buff *skb, __u32 offset, void *to, __u32 len) = (void *)26;
static long (*bpf_csum_diff)(const void *from, __u32 from_size, const void *to, __u32 to_size, __u32 seed) = (void *)28;
static long (*bpf_skb_change_tail)(struct __sk_buff *skb, __u32 len, __u64 flags) = (void *)38;
static long (*bpf_skb_adjust_room)(struct __sk_buff *skb, __s32 len_diff, __u32 mode, __u64 flags) = (void *)50;
static long (*bpf_redirect)(__u32 ifindex, __u64 flags) = (void *)23;
#if TRUSTIX_KUDP_SECURE_BPF_CRYPTO
static long (*bpf_dynptr_from_mem)(void *data, __u32 size, __u64 flags, struct bpf_dynptr *ptr) = (void *)197;

extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;
extern int bpf_crypto_encrypt(struct bpf_crypto_ctx *ctx, const struct bpf_dynptr *src, const struct bpf_dynptr *dst, const struct bpf_dynptr *siv__nullable) __ksym;
#endif
extern int trustix_kernel_direct_seal(__u32 slot_id, const __u8 *src, __u8 *dst, __u32 plain_len, const __u8 *nonce) __ksym;
#if TRUSTIX_KUDP_SECURE_SKB_SEAL_KFUNC
extern int trustix_kernel_skb_direct_seal(struct __sk_buff *skb,
                                            const struct trustix_aead_skb_direct_seal_args *args,
                                            const __u8 *nonce) __ksym;
#endif
extern int trustix_kernel_skb_fix_inner_tcp_csum(struct __sk_buff *skb,
                                              __u32 inner_ip_offset,
                                              __u32 inner_len,
                                              __u32 flags) __ksym;
extern int trustix_kernel_skb_tixt_fix_outer_tcp_csum(struct __sk_buff *skb, __u32 flags) __ksym;

static __always_inline void trustix_kudp_tx_count(__u32 key)
{
    __u64 *value = bpf_map_lookup_elem(&ix_stats_map, &key);
    if (value)
        (*value)++;
}

static __always_inline int trustix_kudp_tx_hot_stats(const struct trustix_kudp_tx_flow_value *flow)
{
    return flow && (flow->flags & TRUSTIX_KUDP_TX_FLOW_FLAG_HOT_STATS);
}

static __always_inline void trustix_kudp_tx_count_hot(const struct trustix_kudp_tx_flow_value *flow,
                                                     __u32 key)
{
    if (trustix_kudp_tx_hot_stats(flow))
        trustix_kudp_tx_count(key);
}

static __always_inline int trustix_kernel_crypto_hot_stats(const struct trustix_kernel_crypto_ctx_value *state)
{
    return state && (state->flags & TRUSTIX_KERNEL_CRYPTO_FLOW_FLAG_HOT_STATS);
}

static __always_inline int trustix_kernel_crypto_direct_hot_stats(const struct trustix_kernel_crypto_direct_slot *slot)
{
    return slot && (slot->flags & TRUSTIX_KERNEL_CRYPTO_FLOW_FLAG_HOT_STATS);
}

static __always_inline __u16 trustix_read_be16(const __u8 *p)
{
    return ((__u16)p[0] << 8) | (__u16)p[1];
}

static __always_inline __u16 trustix_bswap16(__u16 value)
{
    return (value >> 8) | (value << 8);
}

static __always_inline void trustix_write_be16(__u8 *p, __u16 value)
{
    p[0] = (__u8)(value >> 8);
    p[1] = (__u8)value;
}

static __always_inline void trustix_write_be32(__u8 *p, __u32 value)
{
    p[0] = (__u8)(value >> 24);
    p[1] = (__u8)(value >> 16);
    p[2] = (__u8)(value >> 8);
    p[3] = (__u8)value;
}

static __always_inline void trustix_write_be64(__u8 *p, __u64 value)
{
    trustix_write_be32(p, (__u32)(value >> 32));
    trustix_write_be32(p + 4, (__u32)value);
}

static __always_inline __u8 *trustix_tx_cipher_ptr(struct trustix_kudp_tx_scratch *scratch)
{
    if (scratch->cipher_buffer == TRUSTIX_KUDP_TX_CIPHER_BUFFER_PLAIN)
        return scratch->plain;
    return scratch->io.split.cipher;
}

static __always_inline __u64 trustix_kudp_select_route_flow(struct trustix_kudp_tx_route_value *route,
                                                            __u8 *data,
                                                            __u8 *data_end)
{
    __u32 hash;
    __u32 next;
    __u32 ihl;
    __u8 *l4;

    if (!route)
        return 0;
    if (route->flow_mask == 0)
        return route->flow_id;
    hash = ((__u32)data[26] << 24) | ((__u32)data[27] << 16) |
           ((__u32)data[28] << 8) | data[29];
    hash ^= ((__u32)data[30] << 24) | ((__u32)data[31] << 16) |
            ((__u32)data[32] << 8) | data[33];
    hash ^= ((__u32)data[23]) << 16;
    ihl = (__u32)(data[14] & 0x0f) << 2;
    l4 = data + 14 + ihl;
    if (l4 + 4 <= data_end)
        hash ^= ((__u32)l4[0] << 24) | ((__u32)l4[1] << 16) |
                ((__u32)l4[2] << 8) | l4[3];
    next = hash >> 16;
    hash ^= next;
    next = hash >> 8;
    hash ^= next;
    switch (hash & route->flow_mask) {
    case 0:
        return route->flow_id_1;
    case 1:
        return route->flow_id_2;
    case 2:
        return route->flow_id_3;
    case 3:
        return route->flow_id_4;
    case 4:
        return route->flow_id_5;
    case 5:
        return route->flow_id_6;
    case 6:
        return route->flow_id_7;
    default:
        return route->flow_id_8;
    }
}

static __always_inline __u16 trustix_fold_checksum(__u32 sum)
{
#pragma clang loop unroll(full)
    for (int i = 0; i < 4; i++)
        sum = (sum & 0xffff) + (sum >> 16);
    return ~((__u16)sum);
}

static __always_inline void trustix_fix_ipv4_checksum(__u8 *ip)
{
    __u32 sum = 0;

    ip[10] = 0;
    ip[11] = 0;
#pragma clang loop unroll(full)
    for (int i = 0; i < 20; i += 2)
        sum += ((__u32)ip[i] << 8) | ip[i + 1];
    trustix_write_be16(ip + 10, trustix_fold_checksum(sum));
}

static __noinline int trustix_add_csum_chunk(__u8 *data, __u32 len, __u32 *sum)
{
    __s64 next;

    len &= 0x7fc;
    if (len == 0)
        return 0;
    if (len > TRUSTIX_KERNEL_CRYPTO_CSUM_CHUNK)
        return -22;
    next = bpf_csum_diff(0, 0, data, len, *sum);
    if (next < 0)
        return (int)next;
    *sum = (__u32)next;
    return 0;
}

static __noinline int trustix_add_csum_bytes(__u8 *data, __u32 len, __u32 *sum)
{
    __u32 chunk;

    if (!data || !sum)
        return -22;
    if (len > TRUSTIX_KERNEL_CRYPTO_FRAME_PADDED)
        return -22;
    if (len > 0) {
        chunk = len;
        if (chunk > TRUSTIX_KERNEL_CRYPTO_CSUM_CHUNK)
            chunk = TRUSTIX_KERNEL_CRYPTO_CSUM_CHUNK;
        if (trustix_add_csum_chunk(data, chunk, sum))
            return -22;
    }
    if (len > TRUSTIX_KERNEL_CRYPTO_CSUM_CHUNK) {
        chunk = len - TRUSTIX_KERNEL_CRYPTO_CSUM_CHUNK;
        if (chunk > TRUSTIX_KERNEL_CRYPTO_CSUM_CHUNK)
            chunk = TRUSTIX_KERNEL_CRYPTO_CSUM_CHUNK;
        if (trustix_add_csum_chunk(data + TRUSTIX_KERNEL_CRYPTO_CSUM_CHUNK, chunk, sum))
            return -22;
    }
    if (len > TRUSTIX_KERNEL_CRYPTO_CSUM_CHUNK * 2) {
        chunk = len - TRUSTIX_KERNEL_CRYPTO_CSUM_CHUNK * 2;
        if (chunk > TRUSTIX_KERNEL_CRYPTO_CSUM_CHUNK)
            chunk = TRUSTIX_KERNEL_CRYPTO_CSUM_CHUNK;
        if (trustix_add_csum_chunk(data + TRUSTIX_KERNEL_CRYPTO_CSUM_CHUNK * 2, chunk, sum))
            return -22;
    }
    if (len > TRUSTIX_KERNEL_CRYPTO_CSUM_CHUNK * 3) {
        chunk = len - TRUSTIX_KERNEL_CRYPTO_CSUM_CHUNK * 3;
        if (chunk > TRUSTIX_KERNEL_CRYPTO_CSUM_CHUNK)
            chunk = TRUSTIX_KERNEL_CRYPTO_CSUM_CHUNK;
        if (trustix_add_csum_chunk(data + TRUSTIX_KERNEL_CRYPTO_CSUM_CHUNK * 3, chunk, sum))
            return -22;
    }
    if (len > TRUSTIX_KERNEL_CRYPTO_CSUM_CHUNK * 4) {
        chunk = len - TRUSTIX_KERNEL_CRYPTO_CSUM_CHUNK * 4;
        if (chunk > TRUSTIX_KERNEL_CRYPTO_CSUM_CHUNK)
            chunk = TRUSTIX_KERNEL_CRYPTO_CSUM_CHUNK;
        if (trustix_add_csum_chunk(data + TRUSTIX_KERNEL_CRYPTO_CSUM_CHUNK * 4, chunk, sum))
            return -22;
    }
    if (len > TRUSTIX_KERNEL_CRYPTO_CSUM_CHUNK * 5) {
        chunk = len - TRUSTIX_KERNEL_CRYPTO_CSUM_CHUNK * 5;
        if (chunk > TRUSTIX_KERNEL_CRYPTO_CSUM_CHUNK)
            chunk = TRUSTIX_KERNEL_CRYPTO_CSUM_CHUNK;
        if (trustix_add_csum_chunk(data + TRUSTIX_KERNEL_CRYPTO_CSUM_CHUNK * 5, chunk, sum))
            return -22;
    }
    if (len > TRUSTIX_KERNEL_CRYPTO_CSUM_CHUNK * 6) {
        chunk = len - TRUSTIX_KERNEL_CRYPTO_CSUM_CHUNK * 6;
        if (chunk > TRUSTIX_KERNEL_CRYPTO_CSUM_CHUNK)
            chunk = TRUSTIX_KERNEL_CRYPTO_CSUM_CHUNK;
        if (trustix_add_csum_chunk(data + TRUSTIX_KERNEL_CRYPTO_CSUM_CHUNK * 6, chunk, sum))
            return -22;
    }
    if (len > TRUSTIX_KERNEL_CRYPTO_CSUM_CHUNK * 7) {
        chunk = len - TRUSTIX_KERNEL_CRYPTO_CSUM_CHUNK * 7;
        if (chunk > TRUSTIX_KERNEL_CRYPTO_CSUM_CHUNK)
            chunk = TRUSTIX_KERNEL_CRYPTO_CSUM_CHUNK;
        if (trustix_add_csum_chunk(data + TRUSTIX_KERNEL_CRYPTO_CSUM_CHUNK * 7, chunk, sum))
            return -22;
    }
    return 0;
}

static __noinline __u16 trustix_l4_checksum(const __u8 *ip,
                                            __u8 *l4,
                                            __u32 l4_len,
                                            __u8 protocol)
{
    struct trustix_l4_csum_header header = {};
    __s64 sum;
    __u32 sum32;
    __u32 padded_len;
    __u16 checksum;

    l4_len &= TRUSTIX_KERNEL_CRYPTO_FRAME_MAX;
    if (l4_len == 0 || l4_len > TRUSTIX_KERNEL_CRYPTO_PLAIN_MAX)
        return 0;

    header.pseudo[0] = ip[12];
    header.pseudo[1] = ip[13];
    header.pseudo[2] = ip[14];
    header.pseudo[3] = ip[15];
    header.pseudo[4] = ip[16];
    header.pseudo[5] = ip[17];
    header.pseudo[6] = ip[18];
    header.pseudo[7] = ip[19];
    header.pseudo[8] = 0;
    header.pseudo[9] = protocol;
    trustix_write_be16(header.pseudo + 10, (__u16)l4_len);

    padded_len = (l4_len + 3) & ~3U;
    if (padded_len > TRUSTIX_KERNEL_CRYPTO_FRAME_PADDED - 20)
        return 0;
    if (padded_len > l4_len) {
#pragma clang loop unroll(full)
        for (int i = 0; i < 3; i++) {
            __u32 offset = l4_len + (__u32)i;
            if (offset >= padded_len)
                break;
            l4[offset] = 0;
        }
    }

    sum = bpf_csum_diff(0, 0, &header, sizeof(header), 0);
    if (sum < 0)
        return 0;
    sum32 = (__u32)sum;
    if (trustix_add_csum_bytes(l4, padded_len, &sum32))
        return 0;

    checksum = trustix_bswap16(trustix_fold_checksum(sum32));
    if (checksum == 0)
        checksum = 0xffff;
    return checksum;
}

static __noinline int trustix_fix_inner_checksums(struct trustix_kudp_tx_scratch *scratch,
                                                  __u32 inner_len)
{
    __u8 *ip;
    __u8 *l4;
    __u32 l4_len;
    __u32 tcp_header_len;
    __u32 udp_len;

    if (!scratch)
        return -22;
    if (inner_len < 20 || inner_len > TRUSTIX_KERNEL_CRYPTO_PLAIN_MAX)
        return -22;
    ip = scratch->plain;
    if (ip[0] != 0x45 || trustix_read_be16(ip + 2) != inner_len)
        return -22;

    trustix_fix_ipv4_checksum(ip);
    l4 = ip + 20;
    l4_len = inner_len - 20;
    if (ip[9] == IPPROTO_TCP) {
        if (l4_len < 20)
            return -22;
        tcp_header_len = (__u32)(l4[12] >> 4) << 2;
        if (tcp_header_len < 20 || tcp_header_len > l4_len)
            return -22;
        l4[16] = 0;
        l4[17] = 0;
        trustix_write_be16(l4 + 16, trustix_l4_checksum(ip, l4, l4_len, IPPROTO_TCP));
    } else if (ip[9] == IPPROTO_UDP) {
        if (l4_len < 8)
            return -22;
        udp_len = trustix_read_be16(l4 + 4);
        if (udp_len < 8 || udp_len > l4_len)
            return -22;
        if (l4[6] == 0 && l4[7] == 0)
            return 0;
        l4[6] = 0;
        l4[7] = 0;
        trustix_write_be16(l4 + 6, trustix_l4_checksum(ip, l4, udp_len, IPPROTO_UDP));
    }
    return 0;
}

static __always_inline __u16 trustix_tcp_mss_clamp_for_mtu(__u32 mtu,
                                                          __u32 outer_overhead)
{
    __s32 mss;

    if (!mtu)
        return 0;
    mss = (__s32)mtu - (__s32)outer_overhead - 20 - TRUSTIX_TCP_MSS_OPTION_BUDGET;
    if (mss < TRUSTIX_TCP_MSS_MIN_IPV4)
        return TRUSTIX_TCP_MSS_MIN_IPV4;
    if (mss > TRUSTIX_TCP_MSS_MAX)
        return TRUSTIX_TCP_MSS_MAX;
    return (__u16)mss;
}

static __always_inline int trustix_inner_tcp_syn_candidate(struct trustix_kudp_tx_scratch *scratch,
                                                           __u32 inner_len)
{
    if (!scratch || inner_len < 40 || inner_len > TRUSTIX_KERNEL_CRYPTO_PLAIN_MAX)
        return 0;
    if (scratch->plain[0] != 0x45 || scratch->plain[9] != IPPROTO_TCP)
        return 0;
    return !!(scratch->plain[33] & TRUSTIX_TCP_FLAG_SYN);
}

static __noinline int trustix_clamp_inner_tcp_mss(struct trustix_kudp_tx_scratch *scratch,
                                                  __u32 inner_len,
                                                  __u16 clamp)
{
    __u8 *ip;
    __u8 *tcp;
    __u32 l4_len;
    __u32 tcp_header_len;
    __u32 opt_offset = 20;
    __u32 next_offset;
    __u16 current;
    __u8 kind;
    __u8 opt_len;

    if (!scratch || clamp == 0)
        return 0;
    if (inner_len < 40 || inner_len > TRUSTIX_KERNEL_CRYPTO_PLAIN_MAX)
        return 0;

    ip = scratch->plain;
    if (ip[0] != 0x45 || trustix_read_be16(ip + 2) != inner_len || ip[9] != IPPROTO_TCP)
        return 0;

    l4_len = inner_len - 20;
    if (l4_len < 20)
        return -22;
    tcp = ip + 20;
    if (!(tcp[13] & TRUSTIX_TCP_FLAG_SYN))
        return 0;

    tcp_header_len = (__u32)(tcp[12] >> 4) << 2;
    if (tcp_header_len < 20 || tcp_header_len > 60 || tcp_header_len > l4_len)
        return -22;
    if (tcp_header_len <= 20)
        return 0;

#pragma clang loop unroll(full)
    for (int i = 0; i < TRUSTIX_TCP_MSS_OPTION_BUDGET; i++) {
        if (opt_offset >= tcp_header_len || opt_offset >= 60)
            break;
        kind = tcp[opt_offset];
        if (kind == TRUSTIX_TCP_OPT_EOL)
            break;
        if (kind == TRUSTIX_TCP_OPT_NOP) {
            opt_offset++;
            continue;
        }
        if (opt_offset + 1 >= tcp_header_len || opt_offset + 1 >= 60)
            break;
        opt_len = tcp[opt_offset + 1];
        if (opt_len < 2 || opt_len > TRUSTIX_TCP_MSS_OPTION_BUDGET)
            break;
        next_offset = opt_offset + (__u32)opt_len;
        if (next_offset > tcp_header_len || next_offset > 60)
            break;
        if (kind == TRUSTIX_TCP_OPT_MSS && opt_len == 4) {
            current = trustix_read_be16(tcp + opt_offset + 2);
            if (current > clamp) {
                trustix_write_be16(tcp + opt_offset + 2, clamp);
                return 1;
            }
            return 0;
        }
        opt_offset = next_offset;
    }
    return 0;
}

static __always_inline void trustix_prepare_nonce_from_iv(__u8 *nonce,
                                                         const __u8 *iv,
                                                         __u64 sequence)
{
#pragma clang loop unroll(full)
    for (int i = 0; i < 12; i++)
        nonce[i] = iv[i];

    nonce[4] = (__u8)(sequence >> 56);
    nonce[5] = (__u8)(sequence >> 48);
    nonce[6] = (__u8)(sequence >> 40);
    nonce[7] = (__u8)(sequence >> 32);
    nonce[8] = (__u8)(sequence >> 24);
    nonce[9] = (__u8)(sequence >> 16);
    nonce[10] = (__u8)(sequence >> 8);
    nonce[11] = (__u8)sequence;
}

static __always_inline void trustix_prepare_nonce(__u8 *nonce,
                                                 const struct trustix_kernel_crypto_ctx_value *state,
                                                 __u64 sequence)
{
    trustix_prepare_nonce_from_iv(nonce, state->iv, sequence);
}

static __always_inline void trustix_prepare_direct_nonce(__u8 *nonce,
                                                        const struct trustix_kernel_crypto_direct_slot *slot,
                                                        __u64 sequence)
{
    trustix_prepare_nonce_from_iv(nonce, slot->iv, sequence);
}

static __always_inline void trustix_write_secure_header(__u8 *secure,
                                                       __u16 suite,
                                                       __u64 epoch,
                                                       __u64 sequence)
{
    secure[0] = 'T';
    secure[1] = 'I';
    secure[2] = 'X';
    secure[3] = 'D';
    secure[4] = 1;
    secure[5] = (__u8)suite;
    secure[6] = 0;
    secure[7] = 0;
    trustix_write_be64(secure + 8, epoch);
    trustix_write_be64(secure + 16, sequence);
}

#if TRUSTIX_KUDP_SECURE_SKB_SEAL_KFUNC
static __noinline int trustix_encrypt_inner_ipv4_skb_direct(struct __sk_buff *skb,
                                                            __u32 inner_len,
                                                            __u64 flow_id,
                                                            struct trustix_kudp_tx_flow_value *flow,
                                                            struct trustix_kudp_tx_scratch *scratch)
{
    struct trustix_kernel_crypto_flow_key key = {};
    struct trustix_kernel_crypto_ctx_value *state;
    struct trustix_kernel_crypto_direct_slot *direct_slot;
    __u32 *slot_index;
    __u32 wire_len;

    if (!trustix_kudp_tx_secure_skb_seal_kfunc || !scratch || !skb || !flow)
        return -95;
    if (inner_len < 20 || inner_len > TRUSTIX_KERNEL_CRYPTO_PLAIN_MAX)
        return -22;
    if (trustix_kudp_tx_fix_inner_checksums ||
        !(flow->flags & TRUSTIX_KUDP_TX_FLOW_FLAG_TRUST_INNER_CHECKSUM))
        return -95;

    key.flow_id = flow_id;
    key.direction = TRUSTIX_KERNEL_CRYPTO_DIRECTION_SEND;
    if (flow->flags & TRUSTIX_KUDP_TX_FLOW_FLAG_EXPERIMENTAL_TCP)
        key.reserved[0] = TRUSTIX_KERNEL_CRYPTO_NAMESPACE_EXPERIMENTAL_TCP;
    else
        key.reserved[0] = TRUSTIX_KERNEL_CRYPTO_NAMESPACE_KERNEL_UDP;
    slot_index = bpf_map_lookup_elem(&trustix_kernel_crypto_flow_index_map, &key);
    if (!slot_index) {
        trustix_kudp_tx_count(TRUSTIX_KUDP_TX_SECURE_STAT_FLOW_INDEX_MISSES);
        return -2;
    }
    state = bpf_map_lookup_elem(&trustix_kernel_crypto_ctx_slots, slot_index);
    direct_slot = bpf_map_lookup_elem(&trustix_kernel_crypto_direct_slots, slot_index);
    if ((!state || state->suite == 0) && !direct_slot) {
        trustix_kudp_tx_count(TRUSTIX_KUDP_TX_SECURE_STAT_DIRECT_SLOT_MISSES);
        return -2;
    }
    if (!direct_slot || !direct_slot->enabled) {
        trustix_kudp_tx_count(TRUSTIX_KUDP_TX_SECURE_STAT_DIRECT_SLOT_DISABLED);
        return -95;
    }

    scratch->sequence = __sync_fetch_and_add(&flow->sequence, 1) + 1;
    if (scratch->sequence == 0)
        return -22;
    if (state && state->suite != 0) {
        scratch->suite = state->suite;
        scratch->epoch = state->epoch;
        trustix_prepare_nonce(scratch->nonce, state, scratch->sequence);
    } else {
        scratch->suite = direct_slot->suite;
        scratch->epoch = direct_slot->epoch;
        trustix_prepare_direct_nonce(scratch->nonce, direct_slot,
                                     scratch->sequence);
    }
    scratch->cipher_buffer = direct_slot->slot_id;

    wire_len = inner_len + TRUSTIX_KERNEL_CRYPTO_FRAME_TAG_LEN;
    if (trustix_kernel_crypto_direct_hot_stats(direct_slot)) {
        direct_slot->packets++;
        direct_slot->bytes += inner_len;
    }
    if (state && trustix_kernel_crypto_hot_stats(state)) {
        state->packets++;
        state->bytes += inner_len;
    }
    return (__s32)wire_len;
}

static __always_inline int trustix_seal_shifted_inner_ipv4_skb_direct(struct __sk_buff *skb,
                                                                      __u32 cipher_offset,
                                                                      __u32 inner_len,
                                                                      struct trustix_kudp_tx_scratch *scratch)
{
    struct trustix_aead_skb_direct_seal_args args = {};
    int err;

    if (!skb || !scratch || inner_len == 0 ||
        inner_len > TRUSTIX_KERNEL_CRYPTO_PLAIN_MAX)
        return -22;
    args.slot_id = scratch->cipher_buffer;
    args.cipher_offset = cipher_offset;
    args.plain_offset = cipher_offset + TRUSTIX_KERNEL_CRYPTO_FRAME_TAG_LEN;
    args.plain_len = inner_len;
    err = trustix_kernel_skb_direct_seal(skb, &args, scratch->nonce);
    if (err != (__s32)(inner_len + TRUSTIX_KERNEL_CRYPTO_FRAME_TAG_LEN)) {
        trustix_kudp_tx_count(TRUSTIX_KUDP_TX_SECURE_STAT_SKB_SEAL_ERRORS);
        if (err == -22)
            trustix_kudp_tx_count(TRUSTIX_KUDP_TX_SECURE_STAT_SKB_SEAL_EINVAL);
        else if (err == -95)
            trustix_kudp_tx_count(TRUSTIX_KUDP_TX_SECURE_STAT_SKB_SEAL_EOPNOTSUPP);
        else if (err == -14 || err == -74)
            trustix_kudp_tx_count(TRUSTIX_KUDP_TX_SECURE_STAT_SKB_SEAL_EFAULT);
        return -74;
    }
    trustix_kudp_tx_count(TRUSTIX_KUDP_TX_SECURE_STAT_SKB_SEAL_SUCCESSES);
    return 0;
}
#endif

static __noinline int trustix_encrypt_inner_ipv4(struct __sk_buff *skb,
                                                 __u32 inner_len,
                                                 __u64 flow_id,
                                                 struct trustix_kudp_tx_flow_value *flow,
                                                 struct trustix_kudp_tx_scratch *scratch)
{
    __u8 *data = (__u8 *)(long)skb->data;
    __u8 *data_end = (__u8 *)(long)skb->data_end;
    struct trustix_kernel_crypto_flow_key key = {};
    struct trustix_kernel_crypto_ctx_value *state;
    struct trustix_kernel_crypto_direct_slot *direct_slot;
    __u32 *slot_index;
    __u32 wire_len;
    __u16 mss_clamp;
    int clamp_result;
    int fixed_inner_tcp_csum_kfunc = 0;
    int inner_tcp_syn = 0;
    int err = 0;
#if TRUSTIX_KUDP_SECURE_BPF_CRYPTO
    struct bpf_crypto_ctx *crypto_ctx;
    struct bpf_dynptr plain, cipher, nonce;
#endif

    if (!scratch || !skb)
        return -22;
    if (inner_len < 20 || inner_len > TRUSTIX_KERNEL_CRYPTO_PLAIN_MAX)
        return -22;

    if (data + 54 <= data_end && data[23] == IPPROTO_TCP &&
        (data[47] & TRUSTIX_TCP_FLAG_SYN))
        inner_tcp_syn = 1;
    if (trustix_kudp_tx_secure_inner_tcp_csum_kfunc &&
        trustix_kudp_tx_fix_inner_checksums && !inner_tcp_syn) {
        err = trustix_kernel_skb_fix_inner_tcp_csum(skb, 14, inner_len, 0);
        if (err > 0) {
            fixed_inner_tcp_csum_kfunc = 1;
            trustix_kudp_tx_count_hot(flow, TRUSTIX_KUDP_TX_SECURE_STAT_INNER_TCP_CSUM_KFUNC_SUCCESSES);
        } else {
            trustix_kudp_tx_count_hot(flow, TRUSTIX_KUDP_TX_SECURE_STAT_INNER_TCP_CSUM_KFUNC_FALLBACKS);
        }
    }
    if (bpf_skb_load_bytes(skb, 14, scratch->plain, inner_len))
        return -14;
    if (!flow)
        return -22;
    /*
     * The secure TC direct path may either trust captured inner checksums for
     * the highest-throughput profile or normalize them before encryption for
     * the compatibility profile. Without either option, punt to the fallback.
     */
    if (!trustix_kudp_tx_fix_inner_checksums &&
        !(flow->flags & TRUSTIX_KUDP_TX_FLOW_FLAG_TRUST_INNER_CHECKSUM))
        return -95;

    wire_len = inner_len + TRUSTIX_KERNEL_CRYPTO_FRAME_TAG_LEN;
#pragma clang loop unroll(full)
    for (int i = 0; i < TRUSTIX_KERNEL_CRYPTO_FRAME_TAG_LEN; i++)
        scratch->plain[inner_len + (__u32)i] = 0;

    clamp_result = 0;
    if (trustix_inner_tcp_syn_candidate(scratch, inner_len)) {
        mss_clamp = trustix_tcp_mss_clamp_for_mtu(
            flow->mtu,
            (flow->flags & TRUSTIX_KUDP_TX_FLOW_FLAG_EXPERIMENTAL_TCP)
                ? TRUSTIX_EXP_TCP_SECURE_OUTER_OVERHEAD
                : TRUSTIX_KUDP_SECURE_OUTER_OVERHEAD);
        if (mss_clamp) {
            clamp_result = trustix_clamp_inner_tcp_mss(scratch, inner_len, mss_clamp);
            if (clamp_result < 0)
                return clamp_result;
        }
    }
    if ((trustix_kudp_tx_fix_inner_checksums || clamp_result > 0) &&
        !fixed_inner_tcp_csum_kfunc) {
        err = trustix_fix_inner_checksums(scratch, inner_len);
        if (err)
            return err;
    }

    key.flow_id = flow_id;
    key.direction = TRUSTIX_KERNEL_CRYPTO_DIRECTION_SEND;
    if (flow->flags & TRUSTIX_KUDP_TX_FLOW_FLAG_EXPERIMENTAL_TCP)
        key.reserved[0] = TRUSTIX_KERNEL_CRYPTO_NAMESPACE_EXPERIMENTAL_TCP;
    else
        key.reserved[0] = TRUSTIX_KERNEL_CRYPTO_NAMESPACE_KERNEL_UDP;
    slot_index = bpf_map_lookup_elem(&trustix_kernel_crypto_flow_index_map, &key);
    if (!slot_index) {
        trustix_kudp_tx_count(TRUSTIX_KUDP_TX_SECURE_STAT_FLOW_INDEX_MISSES);
        return -2;
    }
    state = bpf_map_lookup_elem(&trustix_kernel_crypto_ctx_slots, slot_index);
    direct_slot = bpf_map_lookup_elem(&trustix_kernel_crypto_direct_slots, slot_index);
    if ((!state || state->suite == 0) && !direct_slot) {
        trustix_kudp_tx_count(TRUSTIX_KUDP_TX_SECURE_STAT_DIRECT_SLOT_MISSES);
        return -2;
    }
    if ((!state || state->suite == 0) && direct_slot && !direct_slot->enabled) {
        trustix_kudp_tx_count(TRUSTIX_KUDP_TX_SECURE_STAT_DIRECT_SLOT_DISABLED);
        return -2;
    }

    scratch->sequence = __sync_fetch_and_add(&flow->sequence, 1) + 1;
    if (scratch->sequence == 0)
        return -22;
    scratch->cipher_buffer = TRUSTIX_KUDP_TX_CIPHER_BUFFER_SPLIT;
    if (direct_slot && direct_slot->enabled &&
#if TRUSTIX_KUDP_SECURE_BPF_CRYPTO
        (trustix_kudp_tx_direct_seal_kfunc || !state || state->suite == 0)
#else
        1
#endif
    ) {
        if (state && state->suite != 0) {
            scratch->suite = state->suite;
            scratch->epoch = state->epoch;
            trustix_prepare_nonce(scratch->nonce, state, scratch->sequence);
        } else {
            scratch->suite = direct_slot->suite;
            scratch->epoch = direct_slot->epoch;
            trustix_prepare_direct_nonce(scratch->nonce, direct_slot, scratch->sequence);
        }
        err = trustix_kernel_direct_seal(direct_slot->slot_id, scratch->plain,
                                           scratch->io.split.cipher, inner_len,
                                           scratch->nonce);
        if (!err) {
            if (trustix_kernel_crypto_direct_hot_stats(direct_slot)) {
                direct_slot->packets++;
                direct_slot->bytes += inner_len;
            }
            if (state && trustix_kernel_crypto_hot_stats(state)) {
                state->packets++;
                state->bytes += inner_len;
            }
            return (__s32)wire_len;
        }
    }
    if (!state || state->suite == 0)
        return -2;
#if TRUSTIX_KUDP_SECURE_BPF_CRYPTO
    scratch->suite = state->suite;
    scratch->epoch = state->epoch;
    trustix_prepare_nonce(scratch->nonce, state, scratch->sequence);

    bpf_rcu_read_lock();
    crypto_ctx = state->ctx;
    if (!crypto_ctx) {
        err = -2;
        goto out_unlock;
    }
    if (bpf_dynptr_from_mem(scratch->plain, wire_len, 0, &plain) ||
        bpf_dynptr_from_mem(scratch->io.split.cipher, wire_len, 0, &cipher) ||
        bpf_dynptr_from_mem(scratch->nonce, sizeof(scratch->nonce), 0, &nonce)) {
        err = -14;
        goto out_unlock;
    }
    err = bpf_crypto_encrypt(crypto_ctx, &plain, &cipher, &nonce);
    bpf_rcu_read_unlock();
    if (err)
        return err;
    if (trustix_kernel_crypto_hot_stats(state)) {
        state->packets++;
        state->bytes += inner_len;
    }
    return (__s32)wire_len;

out_unlock:
    bpf_rcu_read_unlock();
    return err;
#else
    return -2;
#endif
}

static __always_inline void trustix_copy_mac(__u8 *dst, const __u8 *src)
{
#pragma clang loop unroll(full)
    for (int i = 0; i < 6; i++)
        dst[i] = src[i];
}

static __always_inline void trustix_copy_ip(__u8 *dst, const __u8 *src)
{
#pragma clang loop unroll(full)
    for (int i = 0; i < 4; i++)
        dst[i] = src[i];
}

static __always_inline void trustix_copy_port(__u8 *dst, const __u8 *src)
{
    dst[0] = src[0];
    dst[1] = src[1];
}

static __noinline int trustix_store_cipher_to_packet(struct __sk_buff *skb,
                                                     __u32 offset,
                                                     struct trustix_kudp_tx_scratch *scratch,
                                                     __u32 wire_len)
{
    __u32 bounded_wire_len;

    bounded_wire_len = wire_len & TRUSTIX_KERNEL_CRYPTO_FRAME_MAX;
    if (!skb || !scratch || bounded_wire_len < TRUSTIX_KERNEL_CRYPTO_FRAME_TAG_LEN)
        return -22;
    /*
     * The outer IPv4 checksum is precomputed and the outer UDP checksum is
     * deliberately zero. Recomputing checksum state while writing ciphertext
     * can keep TCP partial-checksum metadata alive after adjust_room and let
     * the stack write into the encrypted payload later.
     */
    return (int)bpf_skb_store_bytes(skb, offset, trustix_tx_cipher_ptr(scratch),
                                    bounded_wire_len,
                                    BPF_F_INVALIDATE_HASH);
}

static __noinline int trustix_exp_tcp_outer_checksum(struct trustix_kudp_tx_scratch *scratch,
                                                     __u32 cipher_len,
                                                     __u16 *checksum)
{
    struct trustix_l4_csum_header header = {};
    __u8 *ip;
    __u8 *tcp;
    __u8 *cipher;
    __s64 sum;
    __u32 sum32;
    __u32 l4_header_len;
    __u32 l4_len;
    __u32 padded_cipher_len;
    __u16 folded;

    if (!scratch || !checksum)
        return -22;
    cipher_len &= TRUSTIX_KERNEL_CRYPTO_FRAME_MAX;
    if (cipher_len < TRUSTIX_KERNEL_CRYPTO_FRAME_TAG_LEN)
        return -22;
    l4_header_len = TRUSTIX_EXP_TCP_SECURE_PACKET_HEADER_LEN - 14 - 20;
    l4_len = l4_header_len + cipher_len;
    if (l4_len > 0xffff)
        return -22;

    ip = scratch->io.split.header + 14;
    tcp = scratch->io.split.header + 34;
    cipher = trustix_tx_cipher_ptr(scratch);
    tcp[16] = 0;
    tcp[17] = 0;

    header.pseudo[0] = ip[12];
    header.pseudo[1] = ip[13];
    header.pseudo[2] = ip[14];
    header.pseudo[3] = ip[15];
    header.pseudo[4] = ip[16];
    header.pseudo[5] = ip[17];
    header.pseudo[6] = ip[18];
    header.pseudo[7] = ip[19];
    header.pseudo[8] = 0;
    header.pseudo[9] = IPPROTO_TCP;
    trustix_write_be16(header.pseudo + 10, (__u16)l4_len);

    sum = bpf_csum_diff(0, 0, &header, sizeof(header), 0);
    if (sum < 0)
        return (int)sum;
    sum32 = (__u32)sum;
    if (trustix_add_csum_chunk(tcp, l4_header_len, &sum32))
        return -22;

    padded_cipher_len = (cipher_len + 3) & ~3U;
    if (padded_cipher_len > TRUSTIX_KERNEL_CRYPTO_FRAME_PADDED)
        return -22;
    if (padded_cipher_len > cipher_len) {
#pragma clang loop unroll(full)
        for (int i = 0; i < 3; i++) {
            __u32 offset = cipher_len + (__u32)i;
            if (offset >= padded_cipher_len)
                break;
            cipher[offset] = 0;
        }
    }
    if (trustix_add_csum_bytes(cipher, padded_cipher_len, &sum32))
        return -22;

    folded = trustix_bswap16(trustix_fold_checksum(sum32));
    if (folded == 0)
        folded = 0xffff;
    *checksum = folded;
    return 0;
}

static __noinline void trustix_build_outer_header(struct trustix_kudp_tx_scratch *scratch,
                                                  const struct trustix_kudp_tx_flow_value *flow,
                                                  __u64 flow_id,
                                                  __u32 inner_len,
                                                  __u32 cipher_len)
{
    __u8 *data;
    __u32 payload_len = TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN + cipher_len;
    __u32 outer_len = inner_len + TRUSTIX_KUDP_SECURE_OUTER_OVERHEAD;
    __u32 udp_len = 8 + TRUSTIX_KERNEL_UDP_HEADER_LEN + payload_len;
    int experimental_tcp = flow->flags & TRUSTIX_KUDP_TX_FLOW_FLAG_EXPERIMENTAL_TCP;

    if (experimental_tcp) {
        outer_len = inner_len + TRUSTIX_EXP_TCP_SECURE_OUTER_OVERHEAD;
        data = scratch->io.split.header;
    } else {
        data = scratch->io.split.header;
    }

    trustix_copy_mac(data, flow->destination_mac);
    trustix_copy_mac(data + 6, flow->source_mac);
    data[12] = 0x08;
    data[13] = 0x00;

    data[14] = 0x45;
    data[15] = 0;
    trustix_write_be16(data + 16, (__u16)outer_len);
    data[18] = 0;
    data[19] = 0;
    data[20] = 0x40;
    data[21] = 0;
    data[22] = 64;
    data[23] = experimental_tcp ? IPPROTO_TCP : IPPROTO_UDP;
    data[24] = 0;
    data[25] = 0;
    trustix_copy_ip(data + 26, flow->source_ip);
    trustix_copy_ip(data + 30, flow->destination_ip);
    trustix_fix_ipv4_checksum(data + 14);

    trustix_copy_port(data + 34, flow->source_port);
    trustix_copy_port(data + 36, flow->destination_port);
    if (experimental_tcp) {
        trustix_write_be32(data + 38, (__u32)scratch->sequence);
        trustix_write_be32(data + 42, 1);
        data[46] = 0x50;
        data[47] = 0x18;
        trustix_write_be16(data + 48, 0xffff);
        data[50] = 0;
        data[51] = 0;
        data[52] = 0;
        data[53] = 0;

        data[54] = 'T';
        data[55] = 'I';
        data[56] = 'X';
        data[57] = 'T';
        data[58] = TRUSTIX_EXP_TCP_VERSION;
        data[59] = TRUSTIX_EXP_TCP_FLAG_ENCRYPTED | TRUSTIX_EXP_TCP_FLAG_INNER_IPV4;
        trustix_write_be16(data + 60, TRUSTIX_EXP_TCP_HEADER_LEN);
        trustix_write_be64(data + 62, flow_id);
        trustix_write_be64(data + 70, scratch->epoch);
        trustix_write_be64(data + 78, scratch->sequence);
        trustix_write_be32(data + 86, payload_len);
        data[90] = 0;
        data[91] = 0;
        data[92] = 0;
        data[93] = 0;

        trustix_write_secure_header(data + 94, scratch->suite, scratch->epoch,
                                    scratch->sequence);
        return;
    }

    trustix_write_be16(data + 38, (__u16)udp_len);
    data[40] = 0;
    data[41] = 0;

    data[42] = 'T';
    data[43] = 'I';
    data[44] = 'X';
    data[45] = 'U';
    data[46] = TRUSTIX_KERNEL_UDP_VERSION;
    data[47] = TRUSTIX_KERNEL_UDP_FLAG_ENCRYPTED | TRUSTIX_KERNEL_UDP_FLAG_INNER_IPV4;
    trustix_write_be16(data + 48, TRUSTIX_KERNEL_UDP_HEADER_LEN);
    trustix_write_be64(data + 50, flow_id);
    trustix_write_be64(data + 58, scratch->sequence);
    trustix_write_be32(data + 66, payload_len);
    data[70] = 0;
    data[71] = 0;
    data[72] = 0;
    data[73] = 0;

    trustix_write_secure_header(data + 74, scratch->suite, scratch->epoch,
                                scratch->sequence);
    /* IPv4 permits a zero UDP checksum; AEAD authenticates the payload. */
    data[40] = 0;
    data[41] = 0;
}

SEC("classifier")
int trustix_kudp_tx_secure(struct __sk_buff *skb)
{
    __u8 *data = (__u8 *)(long)skb->data;
    __u8 *data_end = (__u8 *)(long)skb->data_end;
    struct trustix_route_key route_key = {};
    struct trustix_kudp_tx_route_value *route;
    struct trustix_kudp_tx_flow_value *flow;
    struct trustix_kudp_tx_scratch *scratch;
    __u32 scratch_key = 0;
    __u32 inner_len;
    __u32 outer_len;
    __u32 outer_overhead;
    __u32 adjust_overhead;
    __u32 packet_header_len;
    __u32 cipher_offset;
    __u32 redirect_ifindex;
    __u64 flow_id;
    __u16 outer_tcp_checksum;
    int experimental_tcp;
    int skb_sealed = 0;
    int outer_tcp_csum_kfunc = 0;
    int outer_tcp_partial_csum_kfunc = 0;
#if TRUSTIX_KUDP_SECURE_SKB_SEAL_KFUNC
    int inner_tcp_syn = 0;
#endif
    int cipher_len;

    if (data + 34 > data_end)
        goto fallback;
    if (data[12] != 0x08 || data[13] != 0x00)
        goto fallback;
    if (data[14] != 0x45)
        goto fallback;

    route_key.prefix_len = 32;
    route_key.addr[0] = data[30];
    route_key.addr[1] = data[31];
    route_key.addr[2] = data[32];
    route_key.addr[3] = data[33];
    route = bpf_map_lookup_elem(&ix_kudp_tx_route, &route_key);
    if (!route)
        goto route_miss;
    if (route->flags & TRUSTIX_KUDP_TX_ROUTE_FLAG_BYPASS)
        return TC_ACT_UNSPEC;
    flow_id = trustix_kudp_select_route_flow(route, data, data_end);
    if (flow_id == 0)
        goto route_miss;
    flow = bpf_map_lookup_elem(&ix_kudp_tx_flow, &flow_id);
    if (!flow)
        goto flow_miss;
    if (!(flow->flags & TRUSTIX_KUDP_TX_FLOW_FLAG_SECURE))
        goto flag_miss;

    trustix_kudp_tx_count_hot(flow, TRUSTIX_KUDP_TX_SECURE_STAT_ATTEMPTS);
    trustix_kudp_tx_count_hot(flow, TRUSTIX_KUDP_TX_SECURE_STAT_CANDIDATES);
    if (data[20] & 0x3f || data[21])
        goto fragment_fallback;
    if (data[23] == IPPROTO_TCP) {
        if (data + 54 > data_end)
            goto len_mismatch;
#if TRUSTIX_KUDP_SECURE_SKB_SEAL_KFUNC
        if (data[47] & TRUSTIX_TCP_FLAG_SYN)
            inner_tcp_syn = 1;
#endif
    }

    inner_len = trustix_read_be16(data + 16);
    if (inner_len < 20)
        goto header_error;
    if (skb->len != 14 + inner_len) {
        if (skb->len > 14 + inner_len)
            trustix_kudp_tx_count_hot(flow, TRUSTIX_KUDP_TX_SECURE_STAT_LEN_GSO_FALLBACKS);
        else
            trustix_kudp_tx_count_hot(flow, TRUSTIX_KUDP_TX_SECURE_STAT_LEN_SHORT_FALLBACKS);
        goto len_mismatch;
    }
    /*
     * TCP packets already carry an exact inner_len here. Avoid mutating the skb
     * length in the fast path: the secure envelope is built from the validated
     * payload bytes below, and tail reshaping has been a source of TCP-only
     * mismatches during direct-path validation.
     */
    if (inner_len > TRUSTIX_KERNEL_CRYPTO_PLAIN_MAX) {
        trustix_kudp_tx_count_hot(flow, TRUSTIX_KUDP_TX_SECURE_STAT_MTU_PLAIN_MAX_FALLBACKS);
        goto mtu_fallback;
    }

    outer_overhead = TRUSTIX_KUDP_SECURE_OUTER_OVERHEAD;
    packet_header_len = TRUSTIX_KUDP_SECURE_PACKET_HEADER_LEN;
    cipher_offset = TRUSTIX_KUDP_SECURE_CIPHER_OFFSET;
    experimental_tcp = flow->flags & TRUSTIX_KUDP_TX_FLOW_FLAG_EXPERIMENTAL_TCP;
    if (experimental_tcp) {
        outer_overhead = TRUSTIX_EXP_TCP_SECURE_OUTER_OVERHEAD;
        packet_header_len = TRUSTIX_EXP_TCP_SECURE_PACKET_HEADER_LEN;
        cipher_offset = TRUSTIX_EXP_TCP_SECURE_CIPHER_OFFSET;
        if (trustix_kudp_tx_secure_outer_tcp_csum_kfunc &&
            !(flow->flags & TRUSTIX_KUDP_TX_FLOW_FLAG_SKIP_OUTER_TCP_CHECKSUM))
            outer_tcp_csum_kfunc = 1;
        if (trustix_kudp_tx_secure_outer_tcp_partial_csum_kfunc &&
            !(flow->flags & TRUSTIX_KUDP_TX_FLOW_FLAG_SKIP_OUTER_TCP_CHECKSUM)) {
            outer_tcp_csum_kfunc = 1;
            outer_tcp_partial_csum_kfunc = 1;
        }
    }

    outer_len = inner_len + outer_overhead;
    if (outer_len > 0xffff)
        goto header_error;
    if (flow->mtu && outer_len > flow->mtu) {
        trustix_kudp_tx_count_hot(flow, TRUSTIX_KUDP_TX_SECURE_STAT_MTU_UNDERLAY_FALLBACKS);
        if (flow->mtu <= 1500)
            trustix_kudp_tx_count_hot(flow, TRUSTIX_KUDP_TX_SECURE_STAT_MTU_UNDERLAY_1500ISH_FALLBACKS);
        else
            trustix_kudp_tx_count_hot(flow, TRUSTIX_KUDP_TX_SECURE_STAT_MTU_UNDERLAY_JUMBO_FALLBACKS);
        if (inner_len > 1400)
            trustix_kudp_tx_count_hot(flow, TRUSTIX_KUDP_TX_SECURE_STAT_MTU_UNDERLAY_INNER_GT_1400_FALLBACKS);
        else
            trustix_kudp_tx_count_hot(flow, TRUSTIX_KUDP_TX_SECURE_STAT_MTU_UNDERLAY_INNER_LE_1400_FALLBACKS);
        goto mtu_fallback;
    }
    scratch = bpf_map_lookup_elem(&ix_kudp_tx_secure_scratch, &scratch_key);
    if (!scratch)
        goto no_context;
    cipher_len = -95;
#if TRUSTIX_KUDP_SECURE_SKB_SEAL_KFUNC
    if (trustix_kudp_tx_secure_skb_seal_kfunc &&
        !trustix_kudp_tx_fix_inner_checksums &&
        (flow->flags & TRUSTIX_KUDP_TX_FLOW_FLAG_TRUST_INNER_CHECKSUM) &&
        !inner_tcp_syn) {
        cipher_len = trustix_encrypt_inner_ipv4_skb_direct(skb, inner_len,
                                                           flow_id, flow,
                                                           scratch);
        if (cipher_len >= 0)
            skb_sealed = 1;
    }
#endif
    if (!skb_sealed) {
        cipher_len = trustix_encrypt_inner_ipv4(skb, inner_len, flow_id,
                                                flow, scratch);
    }
    if (cipher_len < 0) {
        if (cipher_len == -95)
            goto checksum_fallback;
        if (cipher_len == -2)
            goto no_context;
        if (cipher_len == -22 || cipher_len == -74)
            goto header_error;
        if (cipher_len == -114)
            goto sequence_error;
        goto encrypt_error;
    }
    if ((__u32)cipher_len > TRUSTIX_KERNEL_CRYPTO_FRAME_MAX)
        goto header_error;

    redirect_ifindex = flow->ifindex;
    trustix_build_outer_header(scratch, flow, flow_id, inner_len,
                               (__u32)cipher_len);
    if (!skb_sealed && experimental_tcp && !outer_tcp_csum_kfunc &&
        !(flow->flags & TRUSTIX_KUDP_TX_FLOW_FLAG_SKIP_OUTER_TCP_CHECKSUM)) {
        if (trustix_exp_tcp_outer_checksum(scratch, (__u32)cipher_len, &outer_tcp_checksum))
            goto checksum_fallback;
        trustix_write_be16(scratch->io.split.header + 50, outer_tcp_checksum);
    }

    adjust_overhead = outer_overhead;
    if (bpf_skb_adjust_room(skb, adjust_overhead, BPF_ADJ_ROOM_MAC,
                            trustix_kudp_tx_adjust_room_flags))
        goto drop;
    if (!skb_sealed && bpf_skb_change_tail(skb, 14 + outer_len, 0))
        goto drop;
    if (bpf_skb_store_bytes(skb, 0, scratch->io.split.header, packet_header_len,
                            BPF_F_INVALIDATE_HASH))
        goto drop;
#if TRUSTIX_KUDP_SECURE_SKB_SEAL_KFUNC
    if (skb_sealed) {
        if (trustix_seal_shifted_inner_ipv4_skb_direct(
                skb, cipher_offset, inner_len, scratch))
            goto drop;
    }
#endif
    if (!skb_sealed &&
        trustix_store_cipher_to_packet(skb, cipher_offset, scratch, (__u32)cipher_len))
        goto drop;
    if ((skb_sealed || outer_tcp_csum_kfunc) && experimental_tcp &&
        !(flow->flags & TRUSTIX_KUDP_TX_FLOW_FLAG_SKIP_OUTER_TCP_CHECKSUM)) {
        __u32 csum_flags = outer_tcp_partial_csum_kfunc ?
            TRUSTIX_TIXT_TX_FINALIZE_TCP_PARTIAL_CSUM : 0;
        if (trustix_kernel_skb_tixt_fix_outer_tcp_csum(skb, csum_flags)) {
            if (outer_tcp_partial_csum_kfunc)
                trustix_kudp_tx_count(TRUSTIX_KUDP_TX_SECURE_STAT_OUTER_TCP_PARTIAL_CSUM_KFUNC_ERRORS);
            else
                trustix_kudp_tx_count(TRUSTIX_KUDP_TX_SECURE_STAT_OUTER_TCP_CSUM_KFUNC_ERRORS);
            trustix_kudp_tx_count(TRUSTIX_KUDP_TX_SECURE_STAT_CHECKSUM_FALLBACKS);
            goto drop;
        }
        if (outer_tcp_partial_csum_kfunc)
            trustix_kudp_tx_count(TRUSTIX_KUDP_TX_SECURE_STAT_OUTER_TCP_PARTIAL_CSUM_KFUNC_SUCCESSES);
        trustix_kudp_tx_count(TRUSTIX_KUDP_TX_SECURE_STAT_OUTER_TCP_CSUM_KFUNC_SUCCESSES);
    }
    trustix_kudp_tx_count_hot(flow, TRUSTIX_KUDP_TX_SECURE_STAT_SUCCESSES);
    return bpf_redirect(redirect_ifindex, 0);

no_context:
    trustix_kudp_tx_count(TRUSTIX_KUDP_TX_SECURE_STAT_NO_CONTEXT);
    goto fallback;

header_error:
    trustix_kudp_tx_count(TRUSTIX_KUDP_TX_SECURE_STAT_HEADER_ERRORS);
    goto drop;

encrypt_error:
    trustix_kudp_tx_count(TRUSTIX_KUDP_TX_SECURE_STAT_ENCRYPT_ERRORS);
    goto fallback;

sequence_error:
    trustix_kudp_tx_count(TRUSTIX_KUDP_TX_SECURE_STAT_SEQUENCE_ERRORS);
    goto drop;

mtu_fallback:
    trustix_kudp_tx_count(TRUSTIX_KUDP_TX_SECURE_STAT_MTU_FALLBACKS);
    goto fallback;

route_miss:
    trustix_kudp_tx_count(TRUSTIX_KUDP_TX_SECURE_STAT_ROUTE_MISSES);
    goto fallback;

flow_miss:
    trustix_kudp_tx_count(TRUSTIX_KUDP_TX_SECURE_STAT_FLOW_MISSES);
    goto fallback;

flag_miss:
    trustix_kudp_tx_count(TRUSTIX_KUDP_TX_SECURE_STAT_FLAG_MISSES);
    goto fallback;

fragment_fallback:
    trustix_kudp_tx_count(TRUSTIX_KUDP_TX_SECURE_STAT_FRAGMENT_FALLBACKS);
    goto fallback;

len_mismatch:
    trustix_kudp_tx_count(TRUSTIX_KUDP_TX_SECURE_STAT_LEN_MISMATCHES);
    goto fallback;

checksum_fallback:
    trustix_kudp_tx_count(TRUSTIX_KUDP_TX_SECURE_STAT_CHECKSUM_FALLBACKS);
    goto fallback;

fallback:
    trustix_kudp_tx_count(TRUSTIX_KUDP_TX_SECURE_STAT_FALLBACKS);
    return TC_ACT_UNSPEC;

drop:
    trustix_kudp_tx_count(TRUSTIX_KUDP_TX_SECURE_STAT_DROPS);
    return TC_ACT_SHOT;
}

char __license[] SEC("license") = "Dual MIT/GPL";
