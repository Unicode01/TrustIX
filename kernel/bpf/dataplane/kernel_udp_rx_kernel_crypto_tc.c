// SPDX-License-Identifier: GPL-2.0 OR MIT
// TC ingress secure RX direct path for encrypted kernel_udp TIXU and
// experimental_tcp TIXT frames.
// Eligible packets are opened with the provider-owned AEAD context, rewritten
// to Ethernet + inner IPv4, and redirected to the LAN. Unsupported packets use
// TC_ACT_UNSPEC so unrelated TC filters on the same hook can still run.
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
#define BPF_MAP_TYPE_PERCPU_ARRAY 6

#define BPF_ADJ_ROOM_MAC 1
#define BPF_F_RECOMPUTE_CSUM 1
#define BPF_F_INVALIDATE_HASH 2
#define BPF_F_ADJ_ROOM_NO_CSUM_RESET 32
#define BPF_F_INGRESS 1

const volatile __u32 trustix_kudp_rx_secure_adjust_room_flags = 0;
const volatile __u32 trustix_kudp_rx_secure_lan_ifindex = 0;
const volatile __u32 trustix_kudp_rx_secure_local_ipv4 = 0;
const volatile __u32 trustix_kudp_rx_secure_source_mac0 = 0;
const volatile __u16 trustix_kudp_rx_secure_source_mac1 = 0;
const volatile __u32 trustix_kudp_rx_secure_destination_mac0 = 0xffffffff;
const volatile __u16 trustix_kudp_rx_secure_destination_mac1 = 0xffff;
const volatile __u32 trustix_kudp_rx_secure_redirect_peer = 0;
const volatile __u32 trustix_kudp_rx_secure_broadcast = 0;
const volatile __u32 trustix_kudp_rx_secure_hot_stats = 0;
const volatile __u32 trustix_kudp_rx_secure_direct_open_kfunc = 0;
const volatile __u32 trustix_kudp_rx_secure_skb_open_kfunc = 0;
const volatile __u32 trustix_kudp_rx_secure_decap_l2_kfunc = 0;
const volatile __u32 trustix_kudp_rx_secure_recompute_inner_csum = 0;

#ifndef TRUSTIX_KUDP_SECURE_BPF_CRYPTO
#define TRUSTIX_KUDP_SECURE_BPF_CRYPTO 0
#endif

#define TC_ACT_OK 0
#define TC_ACT_UNSPEC (-1)
#define TC_ACT_SHOT 2

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define TRUSTIX_KERNEL_UDP_HEADER_LEN 32
#define TRUSTIX_KERNEL_UDP_FLAG_ENCRYPTED 1
#define TRUSTIX_KERNEL_UDP_FLAG_CRYPTO_FRAGMENT 4
#define TRUSTIX_KERNEL_UDP_FLAG_INNER_IPV4 8
#define TRUSTIX_EXP_TCP_HEADER_LEN 40
#define TRUSTIX_EXP_TCP_FLAG_ENCRYPTED 1
#define TRUSTIX_EXP_TCP_FLAG_CRYPTO_FRAGMENT 4
#define TRUSTIX_EXP_TCP_FLAG_INNER_IPV4 8
#define TRUSTIX_KERNEL_CRYPTO_MAX_ENTRIES 16384
#define TRUSTIX_KERNEL_CRYPTO_REPLAY_WORDS 64
#define TRUSTIX_KERNEL_CRYPTO_REPLAY_MAX ((TRUSTIX_KERNEL_CRYPTO_REPLAY_WORDS - 1) * 64)
#define TRUSTIX_KERNEL_CRYPTO_FRAME_MAX 4095
#define TRUSTIX_KERNEL_CRYPTO_FRAME_PADDED 4096
#define TRUSTIX_KERNEL_CRYPTO_FRAME_TAG_LEN 16
#define TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN 24
#define TRUSTIX_KERNEL_CRYPTO_NAMESPACE_EXPERIMENTAL_TCP 0
#define TRUSTIX_KERNEL_CRYPTO_NAMESPACE_KERNEL_UDP 1
#define TRUSTIX_KERNEL_CRYPTO_DIRECTION_RECV 2
#define TRUSTIX_KERNEL_CRYPTO_FLOW_FLAG_HOT_STATS 1
#define TRUSTIX_KERNEL_CRYPTO_FLOW_FLAG_NO_REPLAY 2
#define TRUSTIX_KUDP_RX_PLAIN_BUFFER_PLAIN 0
#define TRUSTIX_KUDP_RX_PLAIN_BUFFER_CIPHER 1
#define TRUSTIX_KUDP_SECURE_OUTER_OVERHEAD (20 + 8 + TRUSTIX_KERNEL_UDP_HEADER_LEN + TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN + TRUSTIX_KERNEL_CRYPTO_FRAME_TAG_LEN)
#define TRUSTIX_KUDP_SECURE_PACKET_HEADER_LEN (14 + 20 + 8 + TRUSTIX_KERNEL_UDP_HEADER_LEN + TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN)
#define TRUSTIX_KUDP_SECURE_CIPHER_OFFSET TRUSTIX_KUDP_SECURE_PACKET_HEADER_LEN
#define TRUSTIX_KUDP_SECURE_DECAP_LEN (20 + 8 + TRUSTIX_KERNEL_UDP_HEADER_LEN + TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN)
#define TRUSTIX_EXP_TCP_SECURE_OUTER_OVERHEAD (20 + 20 + TRUSTIX_EXP_TCP_HEADER_LEN + TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN + TRUSTIX_KERNEL_CRYPTO_FRAME_TAG_LEN)
#define TRUSTIX_EXP_TCP_SECURE_PACKET_HEADER_LEN (14 + 20 + 20 + TRUSTIX_EXP_TCP_HEADER_LEN + TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN)
#define TRUSTIX_EXP_TCP_SECURE_CIPHER_OFFSET TRUSTIX_EXP_TCP_SECURE_PACKET_HEADER_LEN
#define TRUSTIX_EXP_TCP_SECURE_DECAP_LEN (20 + 20 + TRUSTIX_EXP_TCP_HEADER_LEN + TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN)

#define TRUSTIX_KUDP_RX_SECURE_STAT_ATTEMPTS 87
#define TRUSTIX_KUDP_RX_SECURE_STAT_CANDIDATES 88
#define TRUSTIX_KUDP_RX_SECURE_STAT_SUCCESSES 89
#define TRUSTIX_KUDP_RX_SECURE_STAT_FALLBACKS 90
#define TRUSTIX_KUDP_RX_SECURE_STAT_NO_CONTEXT 91
#define TRUSTIX_KUDP_RX_SECURE_STAT_HEADER_ERRORS 92
#define TRUSTIX_KUDP_RX_SECURE_STAT_DECRYPT_ERRORS 93
#define TRUSTIX_KUDP_RX_SECURE_STAT_REPLAY_DROPS 94
#define TRUSTIX_KUDP_RX_SECURE_STAT_DROPS 95
#define TRUSTIX_KUDP_RX_SECURE_STAT_NEIGH_HITS 96
#define TRUSTIX_KUDP_RX_SECURE_STAT_NEIGH_MISSES 97
#define TRUSTIX_KUDP_RX_SECURE_STAT_ADJUST_ERRORS 98
#define TRUSTIX_KUDP_RX_SECURE_STAT_STORE_ERRORS 99
#define TRUSTIX_KUDP_RX_SECURE_STAT_BROADCASTS 100
#define TRUSTIX_KUDP_RX_SECURE_STAT_PEER_REDIRECTS 101
#define TRUSTIX_KUDP_RX_SECURE_STAT_REDIRECTS 102
#define TRUSTIX_KUDP_RX_SECURE_STAT_DBG_L2_IPV4 118
#define TRUSTIX_KUDP_RX_SECURE_STAT_DBG_L3_IPV4 119
#define TRUSTIX_KUDP_RX_SECURE_STAT_DBG_UDP 120
#define TRUSTIX_KUDP_RX_SECURE_STAT_DBG_TIXU_MAGIC 121
#define TRUSTIX_KUDP_RX_SECURE_STAT_DBG_TIXU_HEADER 122
#define TRUSTIX_KUDP_RX_SECURE_STAT_DBG_TIXU_FLAGS 123
#define TRUSTIX_KUDP_RX_SECURE_STAT_DBG_TIXU_LEN 124
#define TRUSTIX_KUDP_RX_SECURE_STAT_DBG_PORT 125
#define TRUSTIX_KUDP_RX_SECURE_STAT_DBG_SECURE_HEADER 126
#define TRUSTIX_KUDP_RX_SECURE_STAT_DBG_L3_TIXU_MAGIC 127
#define TRUSTIX_KUDP_RX_SECURE_STAT_ERR_PAYLOAD_LEN 128
#define TRUSTIX_KUDP_RX_SECURE_STAT_ERR_CIPHER_LEN 129
#define TRUSTIX_KUDP_RX_SECURE_STAT_ERR_SECURE_MAGIC 130
#define TRUSTIX_KUDP_RX_SECURE_STAT_ERR_SECURE_EPOCH 131
#define TRUSTIX_KUDP_RX_SECURE_STAT_ERR_CTX_EPOCH 132
#define TRUSTIX_KUDP_RX_SECURE_STAT_ERR_OPEN_EINVAL 133
#define TRUSTIX_KUDP_RX_SECURE_STAT_ERR_OPEN_EBADMSG 134
#define TRUSTIX_KUDP_RX_SECURE_STAT_ERR_INNER_IPV4 135

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

struct trustix_kudp_rx_neigh_value {
    __u32 ifindex;
    __u32 destination_mac0;
    __u16 destination_mac1;
    __u16 pad0;
    __u32 source_mac0;
    __u16 source_mac1;
    __u16 pad1;
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

struct trustix_kudp_rx_secure_scratch {
    __u8 cipher[TRUSTIX_KERNEL_CRYPTO_FRAME_PADDED];
    __u8 plain[TRUSTIX_KERNEL_CRYPTO_FRAME_PADDED];
    __u8 header[14];
    __u8 nonce[12];
    __u64 flow_id;
    __u64 epoch;
    __u64 sequence;
    __u32 ifindex;
    __u8 suite;
    __u8 plain_buffer;
    __u8 pad0[2];
};

struct trustix_aead_skb_direct_open_args {
    __u32 slot_id;
    __u32 cipher_offset;
    __u32 cipher_len;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 163);
    __type(key, __u32);
    __type(value, __u64);
} ix_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u8);
} ix_exp_tcp_port SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct trustix_kudp_rx_neigh_value);
} ix_kudp_rx_neigh SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, TRUSTIX_KERNEL_CRYPTO_MAX_ENTRIES);
    __type(key, struct trustix_kernel_crypto_flow_key);
    __type(value, __u32);
} trustix_kernel_crypto_flow_index_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, TRUSTIX_KERNEL_CRYPTO_MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct trustix_kernel_crypto_ctx_value);
} trustix_kernel_crypto_ctx_slots SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, TRUSTIX_KERNEL_CRYPTO_MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct trustix_kernel_crypto_direct_slot);
} trustix_kernel_crypto_direct_slots SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct trustix_kudp_rx_secure_scratch);
} ix_kudp_rx_secure_scratch SEC(".maps");

static void *(*bpf_map_lookup_elem)(const void *map, const void *key) = (void *)1;
static long (*bpf_skb_store_bytes)(struct __sk_buff *skb, __u32 offset, const void *from, __u32 len, __u64 flags) = (void *)9;
static long (*bpf_skb_load_bytes)(const struct __sk_buff *skb, __u32 offset, void *to, __u32 len) = (void *)26;
static long (*bpf_skb_change_tail)(struct __sk_buff *skb, __u32 len, __u64 flags) = (void *)38;
static long (*bpf_skb_adjust_room)(struct __sk_buff *skb, __s32 len_diff, __u32 mode, __u64 flags) = (void *)50;
static long (*bpf_redirect)(__u32 ifindex, __u64 flags) = (void *)23;
static long (*bpf_redirect_peer)(__u32 ifindex, __u64 flags) = (void *)155;
#if TRUSTIX_KUDP_SECURE_BPF_CRYPTO
static long (*bpf_dynptr_from_mem)(void *data, __u32 size, __u64 flags, struct bpf_dynptr *ptr) = (void *)197;

extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;
extern int bpf_crypto_decrypt(struct bpf_crypto_ctx *ctx, const struct bpf_dynptr *src, const struct bpf_dynptr *dst, const struct bpf_dynptr *siv__nullable) __ksym;
#endif
extern int trustix_kernel_direct_open(__u32 slot_id, const __u8 *src, __u8 *dst, __u32 cipher_len, const __u8 *nonce) __ksym;
extern int trustix_kernel_skb_direct_open(struct __sk_buff *skb,
                                            const struct trustix_aead_skb_direct_open_args *args,
                                            const __u8 *nonce) __ksym;
extern int trustix_kernel_skb_kudp_rx_decap_l2(struct __sk_buff *skb,
                                            __u32 outer_len,
                                            unsigned long long l2_head,
                                            __u32 l2_tail0,
                                            __u32 l2_tail1) __ksym;

static __always_inline void trustix_kudp_rx_secure_count(__u32 key)
{
    __u64 *value = bpf_map_lookup_elem(&ix_stats_map, &key);
    if (value)
        (*value)++;
}

static __always_inline void trustix_kudp_rx_secure_count_path(__u32 key)
{
    if (trustix_kudp_rx_secure_hot_stats)
        trustix_kudp_rx_secure_count(key);
}

static __always_inline int trustix_kernel_crypto_hot_stats(const struct trustix_kernel_crypto_ctx_value *state)
{
    return state && (state->flags & TRUSTIX_KERNEL_CRYPTO_FLOW_FLAG_HOT_STATS);
}

static __always_inline int trustix_kernel_crypto_direct_hot_stats(const struct trustix_kernel_crypto_direct_slot *slot)
{
    return slot && (slot->flags & TRUSTIX_KERNEL_CRYPTO_FLOW_FLAG_HOT_STATS);
}

static __always_inline int trustix_kernel_crypto_no_replay(const struct trustix_kernel_crypto_ctx_value *state)
{
    return state && (state->flags & TRUSTIX_KERNEL_CRYPTO_FLOW_FLAG_NO_REPLAY);
}

static __always_inline int trustix_kernel_crypto_direct_no_replay(const struct trustix_kernel_crypto_direct_slot *slot)
{
    return slot && (slot->flags & TRUSTIX_KERNEL_CRYPTO_FLOW_FLAG_NO_REPLAY);
}

static __always_inline void trustix_kudp_rx_secure_count_hot(const struct trustix_kernel_crypto_ctx_value *state,
                                                            __u32 key)
{
    if (trustix_kernel_crypto_hot_stats(state))
        trustix_kudp_rx_secure_count(key);
}

static __always_inline void trustix_kudp_rx_secure_count_direct_hot(const struct trustix_kernel_crypto_direct_slot *slot,
                                                                    __u32 key)
{
    if (trustix_kernel_crypto_direct_hot_stats(slot))
        trustix_kudp_rx_secure_count(key);
}

static __always_inline __u16 trustix_read_be16(const __u8 *p)
{
    return ((__u16)p[0] << 8) | (__u16)p[1];
}

static __always_inline __u32 trustix_read_be32(const __u8 *p)
{
    return ((__u32)p[0] << 24) | ((__u32)p[1] << 16) |
           ((__u32)p[2] << 8) | (__u32)p[3];
}

static __always_inline __u64 trustix_read_be64(const __u8 *p)
{
    return ((__u64)trustix_read_be32(p) << 32) | trustix_read_be32(p + 4);
}

static __always_inline __u8 *trustix_rx_plain_ptr(struct trustix_kudp_rx_secure_scratch *scratch)
{
    if (scratch->plain_buffer == TRUSTIX_KUDP_RX_PLAIN_BUFFER_CIPHER)
        return scratch->cipher;
    return scratch->plain;
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

static __always_inline __u32 trustix_replay_window(const struct trustix_kernel_crypto_ctx_value *state)
{
    __u32 window = state->replay_window;
    if (window == 0)
        window = TRUSTIX_KERNEL_CRYPTO_REPLAY_MAX;
    if (window > TRUSTIX_KERNEL_CRYPTO_REPLAY_MAX)
        window = TRUSTIX_KERNEL_CRYPTO_REPLAY_MAX;
    return window;
}

static __always_inline __u32 trustix_direct_replay_window(const struct trustix_kernel_crypto_direct_slot *slot)
{
    __u32 window = slot->replay_window;
    if (window == 0)
        window = TRUSTIX_KERNEL_CRYPTO_REPLAY_MAX;
    if (window > TRUSTIX_KERNEL_CRYPTO_REPLAY_MAX)
        window = TRUSTIX_KERNEL_CRYPTO_REPLAY_MAX;
    return window;
}

static __always_inline int trustix_replay_seen(const struct trustix_kernel_crypto_ctx_value *state,
                                               __u64 sequence)
{
    __u64 block = sequence >> 6;
    __u32 slot = (__u32)block & (TRUSTIX_KERNEL_CRYPTO_REPLAY_WORDS - 1);
    __u32 bit = (__u32)sequence & 63;
    __u64 mask = ((__u64)1) << bit;

    if (state->replay_blocks[slot] != block)
        return 0;
    return (state->replay_seen[slot] & mask) != 0;
}

static __always_inline int trustix_direct_replay_seen(const struct trustix_kernel_crypto_direct_slot *slot,
                                                      __u64 sequence)
{
    __u64 block = sequence >> 6;
    __u32 replay_slot = (__u32)block & (TRUSTIX_KERNEL_CRYPTO_REPLAY_WORDS - 1);
    __u32 bit = (__u32)sequence & 63;
    __u64 mask = ((__u64)1) << bit;

    if (slot->replay_blocks[replay_slot] != block)
        return 0;
    return (slot->replay_seen[replay_slot] & mask) != 0;
}

static __always_inline void trustix_replay_mark(struct trustix_kernel_crypto_ctx_value *state,
                                                __u64 sequence)
{
    __u64 block = sequence >> 6;
    __u32 slot = (__u32)block & (TRUSTIX_KERNEL_CRYPTO_REPLAY_WORDS - 1);
    __u32 bit = (__u32)sequence & 63;
    __u64 mask = ((__u64)1) << bit;

    if (state->replay_blocks[slot] != block) {
        state->replay_blocks[slot] = block;
        state->replay_seen[slot] = 0;
    }
    state->replay_seen[slot] |= mask;
}

static __always_inline void trustix_direct_replay_mark(struct trustix_kernel_crypto_direct_slot *slot,
                                                       __u64 sequence)
{
    __u64 block = sequence >> 6;
    __u32 replay_slot = (__u32)block & (TRUSTIX_KERNEL_CRYPTO_REPLAY_WORDS - 1);
    __u32 bit = (__u32)sequence & 63;
    __u64 mask = ((__u64)1) << bit;

    if (slot->replay_blocks[replay_slot] != block) {
        slot->replay_blocks[replay_slot] = block;
        slot->replay_seen[replay_slot] = 0;
    }
    slot->replay_seen[replay_slot] |= mask;
}

static __always_inline int trustix_replay_check(const struct trustix_kernel_crypto_ctx_value *state,
                                                __u64 sequence)
{
    __u32 window;
    __u64 delta;

    if (trustix_kernel_crypto_no_replay(state))
        return sequence == 0 ? -22 : 0;
    if (sequence == 0)
        return -22;
    if (sequence > state->last_sequence)
        return 0;

    window = trustix_replay_window(state);
    delta = state->last_sequence - sequence;
    if (delta >= window || delta >= TRUSTIX_KERNEL_CRYPTO_REPLAY_MAX)
        return -114;
    if (trustix_replay_seen(state, sequence))
        return -114;
    return 0;
}

static __always_inline int trustix_direct_replay_check(const struct trustix_kernel_crypto_direct_slot *slot,
                                                       __u64 sequence)
{
    __u32 window;
    __u64 delta;

    if (trustix_kernel_crypto_direct_no_replay(slot))
        return sequence == 0 ? -22 : 0;
    if (sequence == 0)
        return -22;
    if (sequence > slot->last_sequence)
        return 0;

    window = trustix_direct_replay_window(slot);
    delta = slot->last_sequence - sequence;
    if (delta >= window || delta >= TRUSTIX_KERNEL_CRYPTO_REPLAY_MAX)
        return -114;
    if (trustix_direct_replay_seen(slot, sequence))
        return -114;
    return 0;
}

static __always_inline int trustix_replay_commit(struct trustix_kernel_crypto_ctx_value *state,
                                                 __u64 sequence)
{
    __u32 window;
    __u64 delta;

    if (trustix_kernel_crypto_no_replay(state))
        return sequence == 0 ? -22 : 0;
    if (sequence == 0)
        return -22;
    if (sequence > state->last_sequence) {
        state->last_sequence = sequence;
        trustix_replay_mark(state, sequence);
        return 0;
    }

    window = trustix_replay_window(state);
    delta = state->last_sequence - sequence;
    if (delta >= window || delta >= TRUSTIX_KERNEL_CRYPTO_REPLAY_MAX)
        return -114;
    if (trustix_replay_seen(state, sequence))
        return -114;
    trustix_replay_mark(state, sequence);
    return 0;
}

static __always_inline int trustix_direct_replay_commit(struct trustix_kernel_crypto_direct_slot *slot,
                                                        __u64 sequence)
{
    __u32 window;
    __u64 delta;

    if (trustix_kernel_crypto_direct_no_replay(slot))
        return sequence == 0 ? -22 : 0;
    if (sequence == 0)
        return -22;
    if (sequence > slot->last_sequence) {
        slot->last_sequence = sequence;
        trustix_direct_replay_mark(slot, sequence);
        return 0;
    }

    window = trustix_direct_replay_window(slot);
    delta = slot->last_sequence - sequence;
    if (delta >= window || delta >= TRUSTIX_KERNEL_CRYPTO_REPLAY_MAX)
        return -114;
    if (trustix_direct_replay_seen(slot, sequence))
        return -114;
    trustix_direct_replay_mark(slot, sequence);
    return 0;
}

static __always_inline int trustix_exp_tcp_unfragmented(__u8 *frame)
{
    return frame[36] == 0 && frame[37] == 0 &&
           frame[38] == 0 && frame[39] == 0;
}

static __always_inline int trustix_kernel_udp_unfragmented(__u8 *frame)
{
    return frame[28] == 0 && frame[29] == 0 &&
           frame[30] == 0 && frame[31] == 0;
}

static __noinline int trustix_open_secure_frame(struct __sk_buff *skb,
                                                __u32 cipher_offset,
                                                __u32 cipher_len,
                                                __u8 namespace,
                                                struct trustix_kudp_rx_secure_scratch *scratch)
{
    struct trustix_kernel_crypto_flow_key key = {};
    struct trustix_kernel_crypto_ctx_value *state;
    struct trustix_kernel_crypto_direct_slot *direct_slot;
    __u32 *slot_index;
    __u32 bounded_cipher_len;
    __u32 plain_len;
    int err = 0;
#if TRUSTIX_KUDP_SECURE_BPF_CRYPTO
    struct bpf_crypto_ctx *crypto_ctx;
    struct bpf_dynptr cipher, plain, nonce;
#endif

    bounded_cipher_len = cipher_len & TRUSTIX_KERNEL_CRYPTO_FRAME_MAX;
    if (!skb || !scratch ||
        bounded_cipher_len < TRUSTIX_KERNEL_CRYPTO_FRAME_TAG_LEN + 20 ||
        bounded_cipher_len > TRUSTIX_KERNEL_CRYPTO_FRAME_MAX)
        return -22;
    cipher_len = bounded_cipher_len;
    plain_len = cipher_len - TRUSTIX_KERNEL_CRYPTO_FRAME_TAG_LEN;
    if (bpf_skb_load_bytes(skb, cipher_offset, scratch->cipher, cipher_len))
        return -14;

    key.flow_id = scratch->flow_id;
    key.direction = TRUSTIX_KERNEL_CRYPTO_DIRECTION_RECV;
    key.reserved[0] = namespace;
    slot_index = bpf_map_lookup_elem(&trustix_kernel_crypto_flow_index_map, &key);
    if (!slot_index)
        return -2;
    state = bpf_map_lookup_elem(&trustix_kernel_crypto_ctx_slots, slot_index);
    direct_slot = bpf_map_lookup_elem(&trustix_kernel_crypto_direct_slots, slot_index);
    if ((!state || state->suite == 0) && direct_slot && direct_slot->enabled) {
        if (direct_slot->epoch != scratch->epoch || scratch->suite != (__u8)direct_slot->suite) {
            trustix_kudp_rx_secure_count(TRUSTIX_KUDP_RX_SECURE_STAT_ERR_CTX_EPOCH);
            return -74;
        }
        err = trustix_direct_replay_check(direct_slot, scratch->sequence);
        if (err)
            return err;
        trustix_prepare_direct_nonce(scratch->nonce, direct_slot, scratch->sequence);
        scratch->plain_buffer = TRUSTIX_KUDP_RX_PLAIN_BUFFER_PLAIN;
        err = trustix_kernel_direct_open(direct_slot->slot_id, scratch->cipher,
                                           scratch->cipher, cipher_len,
                                           scratch->nonce);
        if (err)
            return err;
        scratch->plain_buffer = TRUSTIX_KUDP_RX_PLAIN_BUFFER_CIPHER;
        err = trustix_direct_replay_commit(direct_slot, scratch->sequence);
        if (err)
            return err;
        if (trustix_kernel_crypto_direct_hot_stats(direct_slot)) {
            direct_slot->packets++;
            direct_slot->bytes += plain_len;
        }
        trustix_kudp_rx_secure_count_direct_hot(direct_slot, TRUSTIX_KUDP_RX_SECURE_STAT_SUCCESSES);
        return (__s32)plain_len;
    }
    if (!state || state->suite == 0)
        return -2;
#if TRUSTIX_KUDP_SECURE_BPF_CRYPTO

    if (state->epoch != scratch->epoch || scratch->suite != (__u8)state->suite) {
        trustix_kudp_rx_secure_count(TRUSTIX_KUDP_RX_SECURE_STAT_ERR_CTX_EPOCH);
        return -74;
    }
    err = trustix_replay_check(state, scratch->sequence);
    if (err)
        return err;
    trustix_prepare_nonce(scratch->nonce, state, scratch->sequence);
    scratch->plain_buffer = TRUSTIX_KUDP_RX_PLAIN_BUFFER_PLAIN;
    if (trustix_kudp_rx_secure_direct_open_kfunc) {
        if (direct_slot && direct_slot->enabled) {
            err = trustix_kernel_direct_open(direct_slot->slot_id, scratch->cipher,
                                               scratch->cipher, cipher_len,
                                               scratch->nonce);
            if (!err) {
                scratch->plain_buffer = TRUSTIX_KUDP_RX_PLAIN_BUFFER_CIPHER;
                goto direct_ok;
            }
        }
    }

    bpf_rcu_read_lock();
    crypto_ctx = state->ctx;
    if (!crypto_ctx) {
        err = -2;
        goto out_unlock;
    }
    if (bpf_dynptr_from_mem(scratch->cipher, cipher_len, 0, &cipher) ||
        bpf_dynptr_from_mem(scratch->plain, cipher_len, 0, &plain) ||
        bpf_dynptr_from_mem(scratch->nonce, sizeof(scratch->nonce), 0, &nonce)) {
        err = -14;
        goto out_unlock;
    }
    err = bpf_crypto_decrypt(crypto_ctx, &cipher, &plain, &nonce);
out_unlock:
    bpf_rcu_read_unlock();
    if (err)
        return err;

direct_ok:
    err = trustix_replay_commit(state, scratch->sequence);
    if (err)
        return err;
    if (trustix_kernel_crypto_hot_stats(state)) {
        state->packets++;
        state->bytes += plain_len;
    }
    trustix_kudp_rx_secure_count_hot(state, TRUSTIX_KUDP_RX_SECURE_STAT_SUCCESSES);
    return (__s32)plain_len;
#else
    return -2;
#endif
}

static __noinline int trustix_open_secure_frame_skb_direct(
    struct __sk_buff *skb,
    __u32 cipher_offset,
    __u32 cipher_len,
    __u8 namespace,
    struct trustix_kudp_rx_secure_scratch *scratch)
{
    struct trustix_kernel_crypto_flow_key key = {};
    struct trustix_kernel_crypto_ctx_value *state;
    struct trustix_kernel_crypto_direct_slot *direct_slot;
    struct trustix_aead_skb_direct_open_args args = {};
    __u32 *slot_index;
    __u32 bounded_cipher_len;
    __u32 plain_len;
    int err;

    bounded_cipher_len = cipher_len & TRUSTIX_KERNEL_CRYPTO_FRAME_MAX;
    if (!skb || !scratch ||
        bounded_cipher_len < TRUSTIX_KERNEL_CRYPTO_FRAME_TAG_LEN + 20 ||
        bounded_cipher_len > TRUSTIX_KERNEL_CRYPTO_FRAME_MAX)
        return -22;
    cipher_len = bounded_cipher_len;
    plain_len = cipher_len - TRUSTIX_KERNEL_CRYPTO_FRAME_TAG_LEN;

    key.flow_id = scratch->flow_id;
    key.direction = TRUSTIX_KERNEL_CRYPTO_DIRECTION_RECV;
    key.reserved[0] = namespace;
    slot_index = bpf_map_lookup_elem(&trustix_kernel_crypto_flow_index_map, &key);
    if (!slot_index)
        return -2;
    state = bpf_map_lookup_elem(&trustix_kernel_crypto_ctx_slots, slot_index);
    direct_slot = bpf_map_lookup_elem(&trustix_kernel_crypto_direct_slots, slot_index);
    if (!direct_slot || !direct_slot->enabled)
        return -95;

    if ((!state || state->suite == 0) && direct_slot) {
        if (direct_slot->epoch != scratch->epoch || scratch->suite != (__u8)direct_slot->suite) {
            trustix_kudp_rx_secure_count(TRUSTIX_KUDP_RX_SECURE_STAT_ERR_CTX_EPOCH);
            return -74;
        }
        err = trustix_direct_replay_check(direct_slot, scratch->sequence);
        if (err)
            return err;
        trustix_prepare_direct_nonce(scratch->nonce, direct_slot, scratch->sequence);
        args.slot_id = direct_slot->slot_id;
        args.cipher_offset = cipher_offset;
        args.cipher_len = cipher_len;
        err = trustix_kernel_skb_direct_open(skb, &args, scratch->nonce);
        if (err < 0)
            return err;
        err = trustix_direct_replay_commit(direct_slot, scratch->sequence);
        if (err)
            return err;
        if (trustix_kernel_crypto_direct_hot_stats(direct_slot)) {
            direct_slot->packets++;
            direct_slot->bytes += plain_len;
        }
        trustix_kudp_rx_secure_count_direct_hot(direct_slot, TRUSTIX_KUDP_RX_SECURE_STAT_SUCCESSES);
        return (__s32)plain_len;
    }

    if (!state || state->suite == 0)
        return -2;
    if (state->epoch != scratch->epoch || scratch->suite != (__u8)state->suite) {
        trustix_kudp_rx_secure_count(TRUSTIX_KUDP_RX_SECURE_STAT_ERR_CTX_EPOCH);
        return -74;
    }
    err = trustix_replay_check(state, scratch->sequence);
    if (err)
        return err;
    trustix_prepare_nonce(scratch->nonce, state, scratch->sequence);
    args.slot_id = direct_slot->slot_id;
    args.cipher_offset = cipher_offset;
    args.cipher_len = cipher_len;
    err = trustix_kernel_skb_direct_open(skb, &args, scratch->nonce);
    if (err < 0)
        return err;
    err = trustix_replay_commit(state, scratch->sequence);
    if (err)
        return err;
    if (trustix_kernel_crypto_hot_stats(state)) {
        state->packets++;
        state->bytes += plain_len;
    }
    trustix_kudp_rx_secure_count_hot(state, TRUSTIX_KUDP_RX_SECURE_STAT_SUCCESSES);
    return (__s32)plain_len;
}

static __noinline int trustix_store_plain_to_packet(struct __sk_buff *skb,
                                                    struct trustix_kudp_rx_secure_scratch *scratch,
                                                    __u32 plain_len)
{
    __u32 bounded_plain_len;

    bounded_plain_len = plain_len & TRUSTIX_KERNEL_CRYPTO_FRAME_MAX;
    if (!skb || !scratch || bounded_plain_len < 20 ||
        bounded_plain_len > TRUSTIX_KERNEL_CRYPTO_FRAME_MAX)
        return -22;
    /*
     * The decrypted inner frame is already a complete IPv4 packet. Keep the
     * default path light and only recompute checksum metadata for kernels or
     * drivers that explicitly need the conservative mode.
     */
    if (trustix_kudp_rx_secure_recompute_inner_csum)
        return (int)bpf_skb_store_bytes(skb, 14, trustix_rx_plain_ptr(scratch), bounded_plain_len,
                                        BPF_F_RECOMPUTE_CSUM | BPF_F_INVALIDATE_HASH);
    return (int)bpf_skb_store_bytes(skb, 14, trustix_rx_plain_ptr(scratch), bounded_plain_len,
                                    BPF_F_INVALIDATE_HASH);
}

static __always_inline __u64 trustix_l2_head(const struct trustix_kudp_rx_secure_scratch *scratch)
{
    return ((__u64)scratch->header[0]) |
           ((__u64)scratch->header[1] << 8) |
           ((__u64)scratch->header[2] << 16) |
           ((__u64)scratch->header[3] << 24) |
           ((__u64)scratch->header[4] << 32) |
           ((__u64)scratch->header[5] << 40) |
           ((__u64)scratch->header[6] << 48) |
           ((__u64)scratch->header[7] << 56);
}

static __always_inline __u32 trustix_l2_tail0(const struct trustix_kudp_rx_secure_scratch *scratch)
{
    return ((__u32)scratch->header[8]) |
           ((__u32)scratch->header[9] << 8) |
           ((__u32)scratch->header[10] << 16) |
           ((__u32)scratch->header[11] << 24);
}

static __always_inline __u32 trustix_l2_tail1(const struct trustix_kudp_rx_secure_scratch *scratch)
{
    return ((__u32)scratch->header[12]) | ((__u32)scratch->header[13] << 8);
}

static __noinline int trustix_secure_decap_l2_kfunc(struct __sk_buff *skb,
                                                    struct trustix_kudp_rx_secure_scratch *scratch,
                                                    __u32 decap_len,
                                                    __u32 plain_len)
{
    __u32 bounded_plain_len = plain_len & TRUSTIX_KERNEL_CRYPTO_FRAME_MAX;
    __u32 bounded_decap_len = decap_len & 0xff;
    __u32 cipher_offset;
    __u32 trimmed_len;

    if (!skb || !scratch || bounded_plain_len < 20 ||
        bounded_plain_len > TRUSTIX_KERNEL_CRYPTO_FRAME_MAX ||
        bounded_decap_len < 20 || bounded_decap_len > 255)
        return -22;
    cipher_offset = 14 + bounded_decap_len;
    trimmed_len = cipher_offset + bounded_plain_len;
    if (bpf_skb_store_bytes(skb, cipher_offset, trustix_rx_plain_ptr(scratch),
                            bounded_plain_len, BPF_F_INVALIDATE_HASH))
        return -14;
    if (bpf_skb_change_tail(skb, trimmed_len, 0))
        return -14;
    return trustix_kernel_skb_kudp_rx_decap_l2(
        skb, bounded_decap_len, trustix_l2_head(scratch),
        trustix_l2_tail0(scratch), trustix_l2_tail1(scratch));
}

static __always_inline void trustix_set_header_broadcast(struct trustix_kudp_rx_secure_scratch *scratch)
{
    scratch->header[0] = (__u8)trustix_kudp_rx_secure_destination_mac0;
    scratch->header[1] = (__u8)(trustix_kudp_rx_secure_destination_mac0 >> 8);
    scratch->header[2] = (__u8)(trustix_kudp_rx_secure_destination_mac0 >> 16);
    scratch->header[3] = (__u8)(trustix_kudp_rx_secure_destination_mac0 >> 24);
    scratch->header[4] = (__u8)trustix_kudp_rx_secure_destination_mac1;
    scratch->header[5] = (__u8)(trustix_kudp_rx_secure_destination_mac1 >> 8);
    scratch->header[6] = (__u8)trustix_kudp_rx_secure_source_mac0;
    scratch->header[7] = (__u8)(trustix_kudp_rx_secure_source_mac0 >> 8);
    scratch->header[8] = (__u8)(trustix_kudp_rx_secure_source_mac0 >> 16);
    scratch->header[9] = (__u8)(trustix_kudp_rx_secure_source_mac0 >> 24);
    scratch->header[10] = (__u8)trustix_kudp_rx_secure_source_mac1;
    scratch->header[11] = (__u8)(trustix_kudp_rx_secure_source_mac1 >> 8);
    scratch->header[12] = 0x08;
    scratch->header[13] = 0x00;
    scratch->ifindex = trustix_kudp_rx_secure_lan_ifindex;
}

static __always_inline void trustix_set_header_local(struct trustix_kudp_rx_secure_scratch *scratch)
{
    __u32 source_mac0 = trustix_kudp_rx_secure_destination_mac0;
    __u16 source_mac1 = trustix_kudp_rx_secure_destination_mac1;

    /*
     * For packets delivered to the local LAN gateway address, the Ethernet
     * destination must be the LAN interface while the source should look like
     * the peer side of the veth. Reusing the local MAC for both sides can make
     * the kernel drop the redirected ingress skb before the local TCP stack sees
     * it. If no peer MAC was discovered, keep the legacy self-source fallback.
     */
    if (source_mac0 == 0xffffffff && source_mac1 == 0xffff) {
        source_mac0 = trustix_kudp_rx_secure_source_mac0;
        source_mac1 = trustix_kudp_rx_secure_source_mac1;
    }

    scratch->header[0] = (__u8)trustix_kudp_rx_secure_source_mac0;
    scratch->header[1] = (__u8)(trustix_kudp_rx_secure_source_mac0 >> 8);
    scratch->header[2] = (__u8)(trustix_kudp_rx_secure_source_mac0 >> 16);
    scratch->header[3] = (__u8)(trustix_kudp_rx_secure_source_mac0 >> 24);
    scratch->header[4] = (__u8)trustix_kudp_rx_secure_source_mac1;
    scratch->header[5] = (__u8)(trustix_kudp_rx_secure_source_mac1 >> 8);
    scratch->header[6] = (__u8)source_mac0;
    scratch->header[7] = (__u8)(source_mac0 >> 8);
    scratch->header[8] = (__u8)(source_mac0 >> 16);
    scratch->header[9] = (__u8)(source_mac0 >> 24);
    scratch->header[10] = (__u8)source_mac1;
    scratch->header[11] = (__u8)(source_mac1 >> 8);
    scratch->header[12] = 0x08;
    scratch->header[13] = 0x00;
    scratch->ifindex = trustix_kudp_rx_secure_lan_ifindex;
}

static __always_inline void trustix_set_header_neigh(struct trustix_kudp_rx_secure_scratch *scratch,
                                                     struct trustix_kudp_rx_neigh_value *neigh)
{
    scratch->header[0] = (__u8)neigh->destination_mac0;
    scratch->header[1] = (__u8)(neigh->destination_mac0 >> 8);
    scratch->header[2] = (__u8)(neigh->destination_mac0 >> 16);
    scratch->header[3] = (__u8)(neigh->destination_mac0 >> 24);
    scratch->header[4] = (__u8)neigh->destination_mac1;
    scratch->header[5] = (__u8)(neigh->destination_mac1 >> 8);
    scratch->header[6] = (__u8)neigh->source_mac0;
    scratch->header[7] = (__u8)(neigh->source_mac0 >> 8);
    scratch->header[8] = (__u8)(neigh->source_mac0 >> 16);
    scratch->header[9] = (__u8)(neigh->source_mac0 >> 24);
    scratch->header[10] = (__u8)neigh->source_mac1;
    scratch->header[11] = (__u8)(neigh->source_mac1 >> 8);
    scratch->header[12] = 0x08;
    scratch->header[13] = 0x00;
    scratch->ifindex = neigh->ifindex;
}

SEC("classifier")
int trustix_kudp_rx_secure(struct __sk_buff *skb)
{
    __u8 *data = (__u8 *)(long)skb->data;
    __u8 *data_end = (__u8 *)(long)skb->data_end;
    __u8 *ip;
    __u8 *l4;
    __u8 *frame;
    __u8 *secure;
    __u8 *frame_end;
    __u8 *secure_end;
    __u32 port_key;
    __u32 payload_len;
    __u32 cipher_len;
    __u32 outer_total_len;
    __u32 outer_overhead = TRUSTIX_EXP_TCP_SECURE_OUTER_OVERHEAD;
    __u32 cipher_offset = TRUSTIX_EXP_TCP_SECURE_CIPHER_OFFSET;
    __u32 decap_len = TRUSTIX_EXP_TCP_SECURE_DECAP_LEN;
    __u32 inner_len;
    __u32 neigh_key;
    __u64 flow_id;
    __u64 epoch;
    __u64 sequence;
    __u32 scratch_key = 0;
    __u8 namespace = TRUSTIX_KERNEL_CRYPTO_NAMESPACE_EXPERIMENTAL_TCP;
    int plain_len;
    struct trustix_kudp_rx_secure_scratch *scratch;
    struct trustix_kudp_rx_neigh_value *neigh;
    __u8 *plain;
    __u32 redirect_ingress = 0;
    __u32 skb_opened = 0;

    trustix_kudp_rx_secure_count_path(TRUSTIX_KUDP_RX_SECURE_STAT_ATTEMPTS);
    if (data + 20 + 8 + TRUSTIX_KERNEL_UDP_HEADER_LEN <= data_end && data[0] == 0x45) {
        trustix_kudp_rx_secure_count_path(TRUSTIX_KUDP_RX_SECURE_STAT_DBG_L3_IPV4);
        frame = data + 20 + 8;
        if (frame[0] == 'T' && frame[1] == 'I' && frame[2] == 'X' && frame[3] == 'U')
            trustix_kudp_rx_secure_count_path(TRUSTIX_KUDP_RX_SECURE_STAT_DBG_L3_TIXU_MAGIC);
    }
    if (data + 14 + 20 + 8 > data_end)
        goto fallback;
    if (data[12] != 0x08 || data[13] != 0x00)
        goto fallback;
    trustix_kudp_rx_secure_count_path(TRUSTIX_KUDP_RX_SECURE_STAT_DBG_L2_IPV4);
    ip = data + 14;
    if (ip[0] != 0x45)
        goto fallback;
    if (ip[6] & 0x3f || ip[7])
        goto fallback;
    outer_total_len = trustix_read_be16(ip + 2);
    if (skb->len < 14 + outer_total_len)
        goto fallback;
    if (data + 14 + outer_total_len > data_end)
        goto fallback;

    l4 = ip + 20;
    if (ip[9] == IPPROTO_TCP) {
        if (l4 + 13 > data_end)
            goto fallback;
        if (l4[12] != 0x50)
            goto fallback;
        frame = l4 + 20;
        frame_end = frame + TRUSTIX_EXP_TCP_HEADER_LEN;
        barrier_var(frame_end);
        if (frame_end > data_end)
            goto fallback;
        if (frame[0] != 'T' || frame[1] != 'I' || frame[2] != 'X' || frame[3] != 'T')
            goto fallback;
        if (frame[4] != 1 || frame[6] != 0 || frame[7] != TRUSTIX_EXP_TCP_HEADER_LEN)
            goto header_error;
        if (!(frame[5] & TRUSTIX_EXP_TCP_FLAG_ENCRYPTED) ||
            !(frame[5] & TRUSTIX_EXP_TCP_FLAG_INNER_IPV4) ||
            (frame[5] & TRUSTIX_EXP_TCP_FLAG_CRYPTO_FRAGMENT) ||
            !trustix_exp_tcp_unfragmented(frame))
            goto fallback;

        payload_len = trustix_read_be32(frame + 32);
        if (outer_total_len < 20 + 20 + TRUSTIX_EXP_TCP_HEADER_LEN + TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN + TRUSTIX_KERNEL_CRYPTO_FRAME_TAG_LEN)
            goto fallback;
        if (20 + 20 + TRUSTIX_EXP_TCP_HEADER_LEN + payload_len != outer_total_len)
            goto fallback;
        secure = frame + TRUSTIX_EXP_TCP_HEADER_LEN;
        flow_id = trustix_read_be64(frame + 8);
        epoch = trustix_read_be64(frame + 16);
        sequence = trustix_read_be64(frame + 24);
    } else if (ip[9] == IPPROTO_UDP) {
        trustix_kudp_rx_secure_count_path(TRUSTIX_KUDP_RX_SECURE_STAT_DBG_UDP);
        if (data + TRUSTIX_KUDP_SECURE_PACKET_HEADER_LEN > data_end)
            goto fallback;
        if (trustix_read_be16(l4 + 4) != outer_total_len - 20)
            goto fallback;
        frame = l4 + 8;
        frame_end = frame + TRUSTIX_KERNEL_UDP_HEADER_LEN;
        barrier_var(frame_end);
        if (frame_end > data_end)
            goto fallback;
        if (frame[0] != 'T' || frame[1] != 'I' || frame[2] != 'X' || frame[3] != 'U')
            goto fallback;
        trustix_kudp_rx_secure_count_path(TRUSTIX_KUDP_RX_SECURE_STAT_DBG_TIXU_MAGIC);
        if (frame[4] != 1 || frame[6] != 0 || frame[7] != TRUSTIX_KERNEL_UDP_HEADER_LEN)
            goto header_error;
        trustix_kudp_rx_secure_count_path(TRUSTIX_KUDP_RX_SECURE_STAT_DBG_TIXU_HEADER);
        if (!(frame[5] & TRUSTIX_KERNEL_UDP_FLAG_ENCRYPTED) ||
            !(frame[5] & TRUSTIX_KERNEL_UDP_FLAG_INNER_IPV4) ||
            (frame[5] & TRUSTIX_KERNEL_UDP_FLAG_CRYPTO_FRAGMENT) ||
            !trustix_kernel_udp_unfragmented(frame))
            goto fallback;
        trustix_kudp_rx_secure_count_path(TRUSTIX_KUDP_RX_SECURE_STAT_DBG_TIXU_FLAGS);

        payload_len = trustix_read_be32(frame + 24);
        if (outer_total_len < 20 + 8 + TRUSTIX_KERNEL_UDP_HEADER_LEN + TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN + TRUSTIX_KERNEL_CRYPTO_FRAME_TAG_LEN)
            goto fallback;
        if (20 + 8 + TRUSTIX_KERNEL_UDP_HEADER_LEN + payload_len != outer_total_len)
            goto fallback;
        trustix_kudp_rx_secure_count_path(TRUSTIX_KUDP_RX_SECURE_STAT_DBG_TIXU_LEN);
        secure = frame + TRUSTIX_KERNEL_UDP_HEADER_LEN;
        secure_end = secure + TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN;
        barrier_var(secure_end);
        if (secure_end > data_end)
            goto fallback;
        flow_id = trustix_read_be64(frame + 8);
        epoch = trustix_read_be64(secure + 8);
        sequence = trustix_read_be64(frame + 16);
        outer_overhead = TRUSTIX_KUDP_SECURE_OUTER_OVERHEAD;
        cipher_offset = TRUSTIX_KUDP_SECURE_CIPHER_OFFSET;
        decap_len = TRUSTIX_KUDP_SECURE_DECAP_LEN;
        namespace = TRUSTIX_KERNEL_CRYPTO_NAMESPACE_KERNEL_UDP;
    } else {
        goto fallback;
    }

    if (payload_len < TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN + TRUSTIX_KERNEL_CRYPTO_FRAME_TAG_LEN + 20 ||
        payload_len > TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN + TRUSTIX_KERNEL_CRYPTO_FRAME_MAX) {
        trustix_kudp_rx_secure_count_path(TRUSTIX_KUDP_RX_SECURE_STAT_ERR_PAYLOAD_LEN);
        goto header_error;
    }
    cipher_len = (payload_len - TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN) & TRUSTIX_KERNEL_CRYPTO_FRAME_MAX;
    if (cipher_len < TRUSTIX_KERNEL_CRYPTO_FRAME_TAG_LEN + 20 ||
        cipher_len > TRUSTIX_KERNEL_CRYPTO_FRAME_MAX) {
        trustix_kudp_rx_secure_count_path(TRUSTIX_KUDP_RX_SECURE_STAT_ERR_CIPHER_LEN);
        goto header_error;
    }

    port_key = ((__u32)l4[2]) | ((__u32)l4[3] << 8);
    if (!bpf_map_lookup_elem(&ix_exp_tcp_port, &port_key))
        goto fallback;
    trustix_kudp_rx_secure_count_path(TRUSTIX_KUDP_RX_SECURE_STAT_DBG_PORT);
    if (secure + TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN > data_end)
        goto fallback;

    if (secure[0] != 'T' || secure[1] != 'I' || secure[2] != 'X' ||
        secure[3] != 'D' || secure[4] != 1) {
        trustix_kudp_rx_secure_count_path(TRUSTIX_KUDP_RX_SECURE_STAT_ERR_SECURE_MAGIC);
        goto header_error;
    }
    if (trustix_read_be64(secure + 8) != epoch ||
        trustix_read_be64(secure + 16) != sequence) {
        trustix_kudp_rx_secure_count_path(TRUSTIX_KUDP_RX_SECURE_STAT_ERR_SECURE_EPOCH);
        goto header_error;
    }
    trustix_kudp_rx_secure_count_path(TRUSTIX_KUDP_RX_SECURE_STAT_DBG_SECURE_HEADER);

    scratch = bpf_map_lookup_elem(&ix_kudp_rx_secure_scratch, &scratch_key);
    if (!scratch)
        goto no_context;
    if (secure + TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN > data_end)
        goto fallback;
    scratch->flow_id = flow_id;
    scratch->epoch = epoch;
    scratch->sequence = sequence;
    scratch->suite = secure[5];
    trustix_kudp_rx_secure_count_path(TRUSTIX_KUDP_RX_SECURE_STAT_CANDIDATES);
    if (trustix_kudp_rx_secure_skb_open_kfunc) {
        plain_len = trustix_open_secure_frame_skb_direct(
            skb, cipher_offset, cipher_len, namespace, scratch);
        if (plain_len >= 0) {
            skb_opened = 1;
            goto opened;
        }
        if (plain_len != -95)
            goto open_error;
    }
    plain_len = trustix_open_secure_frame(
        skb, cipher_offset, cipher_len, namespace, scratch);
open_error:
    if (plain_len < 0) {
        if (plain_len == -2)
            goto no_context;
        if (plain_len == -114)
            goto replay_drop;
        if (plain_len == -22)
            trustix_kudp_rx_secure_count(TRUSTIX_KUDP_RX_SECURE_STAT_ERR_OPEN_EINVAL);
        if (plain_len == -74)
            trustix_kudp_rx_secure_count(TRUSTIX_KUDP_RX_SECURE_STAT_ERR_OPEN_EBADMSG);
        if (plain_len == -22 || plain_len == -74)
            goto header_error;
        goto decrypt_error;
    }
opened:
    inner_len = (__u32)plain_len;
    if (!skb_opened) {
        plain = trustix_rx_plain_ptr(scratch);
        if (inner_len < 20 || inner_len > TRUSTIX_KERNEL_CRYPTO_FRAME_MAX ||
            plain[0] != 0x45 || trustix_read_be16(plain + 2) != inner_len) {
            trustix_kudp_rx_secure_count(TRUSTIX_KUDP_RX_SECURE_STAT_ERR_INNER_IPV4);
            goto header_error;
        }
    }

    if (skb_opened) {
        neigh_key = skb->cb[0];
    } else {
        neigh_key = ((__u32)plain[16]) | ((__u32)plain[17] << 8) |
                    ((__u32)plain[18] << 16) | ((__u32)plain[19] << 24);
    }
    if (trustix_kudp_rx_secure_local_ipv4 &&
        neigh_key == trustix_kudp_rx_secure_local_ipv4) {
        if (!trustix_kudp_rx_secure_lan_ifindex)
            goto neigh_miss;
        trustix_set_header_local(scratch);
        redirect_ingress = 1;
        trustix_kudp_rx_secure_count_path(TRUSTIX_KUDP_RX_SECURE_STAT_BROADCASTS);
    } else if (trustix_kudp_rx_secure_broadcast) {
        if (!trustix_kudp_rx_secure_lan_ifindex)
            goto neigh_miss;
        trustix_set_header_broadcast(scratch);
        trustix_kudp_rx_secure_count_path(TRUSTIX_KUDP_RX_SECURE_STAT_BROADCASTS);
    } else {
        neigh = bpf_map_lookup_elem(&ix_kudp_rx_neigh, &neigh_key);
        if (!neigh)
            goto neigh_miss;
        trustix_set_header_neigh(scratch, neigh);
        trustix_kudp_rx_secure_count_path(TRUSTIX_KUDP_RX_SECURE_STAT_NEIGH_HITS);
    }
    if (!scratch->ifindex)
        goto neigh_miss;

    if (trustix_kudp_rx_secure_decap_l2_kfunc) {
        if (skb_opened) {
            if (trustix_kernel_skb_kudp_rx_decap_l2(
                    skb, decap_len, trustix_l2_head(scratch),
                    trustix_l2_tail0(scratch), trustix_l2_tail1(scratch)))
                goto adjust_error;
        } else if (trustix_secure_decap_l2_kfunc(skb, scratch, decap_len, inner_len)) {
            goto adjust_error;
        }
        if (trustix_kudp_rx_secure_redirect_peer && !redirect_ingress) {
            trustix_kudp_rx_secure_count_path(TRUSTIX_KUDP_RX_SECURE_STAT_PEER_REDIRECTS);
            return bpf_redirect_peer(scratch->ifindex, 0);
        }
        trustix_kudp_rx_secure_count_path(TRUSTIX_KUDP_RX_SECURE_STAT_REDIRECTS);
        if (redirect_ingress)
            return bpf_redirect(scratch->ifindex, BPF_F_INGRESS);
        return bpf_redirect(scratch->ifindex, 0);
    }

    if (bpf_skb_adjust_room(skb, -(__s32)(skb_opened ? decap_len : outer_overhead),
                            BPF_ADJ_ROOM_MAC,
                            trustix_kudp_rx_secure_adjust_room_flags))
        goto adjust_error;
    if (bpf_skb_store_bytes(skb, 0, scratch->header, sizeof(scratch->header), 0))
        goto store_error;
    if (!skb_opened && trustix_store_plain_to_packet(skb, scratch, inner_len))
        goto store_error;

    if (trustix_kudp_rx_secure_redirect_peer && !redirect_ingress) {
        trustix_kudp_rx_secure_count_path(TRUSTIX_KUDP_RX_SECURE_STAT_PEER_REDIRECTS);
        return bpf_redirect_peer(scratch->ifindex, 0);
    }
    trustix_kudp_rx_secure_count_path(TRUSTIX_KUDP_RX_SECURE_STAT_REDIRECTS);
    if (redirect_ingress)
        return bpf_redirect(scratch->ifindex, BPF_F_INGRESS);
    return bpf_redirect(scratch->ifindex, 0);

no_context:
    trustix_kudp_rx_secure_count(TRUSTIX_KUDP_RX_SECURE_STAT_NO_CONTEXT);
    goto fallback;

header_error:
    trustix_kudp_rx_secure_count(TRUSTIX_KUDP_RX_SECURE_STAT_HEADER_ERRORS);
    goto drop;

decrypt_error:
    trustix_kudp_rx_secure_count(TRUSTIX_KUDP_RX_SECURE_STAT_DECRYPT_ERRORS);
    goto fallback;

replay_drop:
    trustix_kudp_rx_secure_count(TRUSTIX_KUDP_RX_SECURE_STAT_REPLAY_DROPS);
    goto drop;

neigh_miss:
    trustix_kudp_rx_secure_count(TRUSTIX_KUDP_RX_SECURE_STAT_NEIGH_MISSES);
    goto fallback;

adjust_error:
    trustix_kudp_rx_secure_count(TRUSTIX_KUDP_RX_SECURE_STAT_ADJUST_ERRORS);
    goto drop;

store_error:
    trustix_kudp_rx_secure_count(TRUSTIX_KUDP_RX_SECURE_STAT_STORE_ERRORS);
    goto drop;

drop:
    trustix_kudp_rx_secure_count(TRUSTIX_KUDP_RX_SECURE_STAT_DROPS);
    return TC_ACT_SHOT;

fallback:
    trustix_kudp_rx_secure_count_path(TRUSTIX_KUDP_RX_SECURE_STAT_FALLBACKS);
    return TC_ACT_UNSPEC;
}

char __license[] SEC("license") = "Dual MIT/GPL";
