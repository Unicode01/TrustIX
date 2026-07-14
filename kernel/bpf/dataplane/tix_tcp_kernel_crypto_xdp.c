// SPDX-License-Identifier: GPL-2.0 OR MIT
// XDP classifier plus RX-side kernel AEAD open for TrustIX tix_tcp.
// TX still uses the provider program path; this attached program decrypts
// encrypted inbound TIXT/TIXU frames before redirecting them to AF_XDP
// userspace.
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

struct bpf_spin_lock {
    __u32 val;
};

#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_DEVMAP 14
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define BPF_MAP_TYPE_XSKMAP 17

#define XDP_DROP 1
#define XDP_PASS 2

#define TRUSTIX_TIX_TCP_STATS_REDIRECTED 0
#define TRUSTIX_TIX_TCP_STATS_UNAUTHORIZED_DROPS 1
#define TRUSTIX_TIX_TCP_STATS_PASS 2
#define TRUSTIX_TIX_TCP_STATS_PARSE_ERRORS 3
#define TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_OPEN_ATTEMPTS 4
#define TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_OPEN_SUCCESSES 5
#define TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_OPEN_ERRORS 6
#define TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_REPLAY_DROPS 7
#define TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_NO_CONTEXT_DROPS 8
#define TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_HEADER_ERRORS 9
#define TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_DEFERRED_TO_USERSPACE 10
#define TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_TCP_CHECKSUM_SKIPPED 11
#define TRUSTIX_TIX_TCP_STATS_QUEUE_FALLBACK 12
#define TRUSTIX_TIX_TCP_STATS_ALLOWED_INVALID_DROPS 13
#define TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_TC_RX_DIRECT_PASS 14
#define TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_PLAINTEXT_CANDIDATES 15
#define TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_INNER_IPV4_MISSES 16
#define TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_INNER_IPV4_AT88 17
#define TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_REDIRECTS 18
#define TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_NEIGH_MISSES 19
#define TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_ERRORS 20
#define TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_CANDIDATES 21
#define TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_NEIGH_HITS 22
#define TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_BROADCASTS 23
#define TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_ADJUST_HEAD_ERRORS 24
#define TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_TAIL_ERRORS 25
#define TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_POST_ADJUST_ERRORS 26
#define TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_LEN_ERRORS 27
#define TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_IFINDEX_REDIRECTS 28
#define TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_DEVMAP_REDIRECTS 29
#define TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_CONFIG_MISSES 30
#define TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_DIRECT_OPEN_SUCCESSES 31
#define TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_DIRECT_OPEN_FALLBACKS 32
#define TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_FALLBACK_OPEN_SUCCESSES 33
#define TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_PAYLOAD_LEN_ERRORS 34
#define TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_SECURE_HEADER_ERRORS 35
#define TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_FRAME_HEADER_ERRORS 36
#define TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_EPOCH_SEQUENCE_MISMATCHES 37
#define TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_CIPHER_LEN_ERRORS 38
#define TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_CIPHER_LOAD_ERRORS 39
#define TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_CONTEXT_MISSES 40
#define TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_STATE_MISSES 41
#define TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_ZERO_PLAIN_ERRORS 42
#define TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_CONTEXT_UNAVAILABLE 43
#define TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_EPOCH_MISMATCHES 44
#define TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_SUITE_MISMATCHES 45
#define TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_DYNPTR_ERRORS 46
#define TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_DECRYPT_ERRORS 47
#define TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_REPLAY_COMMIT_ERRORS 48
#define TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_STORE_ERRORS 49
#define TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_CSUM_ERRORS 50

#define TRUSTIX_KERNEL_CRYPTO_MAX_ENTRIES 4096
#define TRUSTIX_KERNEL_CRYPTO_REPLAY_WORDS 1024
#define TRUSTIX_KERNEL_CRYPTO_REPLAY_MAX ((TRUSTIX_KERNEL_CRYPTO_REPLAY_WORDS - 1) * 64)
#define TRUSTIX_KERNEL_CRYPTO_FRAME_MAX 4095
#define TRUSTIX_KERNEL_CRYPTO_FRAME_PADDED 4096
#define TRUSTIX_KERNEL_CRYPTO_FRAME_TAG_LEN 16
#define TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN 24
#define TRUSTIX_KERNEL_CRYPTO_NAMESPACE_KERNEL_UDP 1
#define TRUSTIX_KERNEL_CRYPTO_DIRECTION_RECV 2
#define TRUSTIX_TIX_TCP_HEADER_LEN 40
#define TRUSTIX_TIX_TCP_TCP_HEADER_LEN 20
#define TRUSTIX_TIX_TCP_TCP_CSUM_HEADER_LEN (12 + TRUSTIX_TIX_TCP_TCP_HEADER_LEN + TRUSTIX_TIX_TCP_HEADER_LEN)
#define TRUSTIX_KERNEL_UDP_HEADER_LEN 32
#define TRUSTIX_TIX_TCP_CSUM_CHUNK 512
#define TRUSTIX_XDP_RX_DIRECT_CSUM_CHUNK 512
#define TRUSTIX_XDP_RX_DIRECT_FRAME_MAX 1535
#define TRUSTIX_XDP_RX_DIRECT_FRAME_PADDED 1536
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define TRUSTIX_TIX_TCP_OVERHEAD (TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN + TRUSTIX_KERNEL_CRYPTO_FRAME_TAG_LEN)
#define TRUSTIX_TIX_TCP_FLAG_ENCRYPTED 1
#define TRUSTIX_TIX_TCP_FLAG_KERNEL_OPENED 2
#define TRUSTIX_TIX_TCP_FLAG_CRYPTO_FRAGMENT 4
#define TRUSTIX_TIX_TCP_FLAG_INNER_IPV4 8
#define TRUSTIX_XDP_DIRECT_FALLBACK -1
#define TRUSTIX_TIX_TCP_CONFIG_SKIP_TCP_CHECKSUM 1
#define TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_TC_RX_DIRECT 2
#define TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_XDP_OPEN 4
#define TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_XDP_PASS_OPENED 8
#define TRUSTIX_TIX_TCP_CONFIG_HOT_PATH_STATS 16
#define TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_XDP_RX_DIRECT 32
#define TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_XDP_RX_DIRECT_IFINDEX 64
#define TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_TC_RX_SECURE_DIRECT 128
#define TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_XDP_RX_SECURE_DIRECT 256
#define TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_XDP_RX_DIRECT_FIXED_L2 512
#define TRUSTIX_TIX_TCP_CONFIG_XDP_FALLBACK_PASS 1024
#define TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_XDP_RX_DIRECT_TRUST_INNER_CHECKSUM 2048
#define TRUSTIX_TIX_TCP_CONFIG_QUEUE_COUNT_SHIFT 16
#define TRUSTIX_TIX_TCP_CONFIG_QUEUE_COUNT_MASK 0xffff0000U
#define TRUSTIX_KERNEL_CRYPTO_FLOW_FLAG_HOT_STATS 1
#define TRUSTIX_KERNEL_CRYPTO_FLOW_FLAG_NO_REPLAY 2

#if defined(TRUSTIX_TIX_TCP_DIRECT_OPEN) && !defined(TRUSTIX_TIX_TCP_DIRECT_OPEN_KEEP_FALLBACK)
#define TRUSTIX_TIX_TCP_DIRECT_OPEN_ONLY 1
#endif

#if defined(TRUSTIX_TIX_TCP_DIRECT_OPEN_ONLY) && !defined(TRUSTIX_TIX_TCP_DIRECT_OPEN_KEEP_XDP_RX_DIRECT)
#define TRUSTIX_TIX_TCP_NO_XDP_RX_DIRECT 1
#endif

struct trustix_kudp_rx_neigh_value {
    __u32 ifindex;
    __u32 destination_mac0;
    __u16 destination_mac1;
    __u16 pad0;
    __u32 source_mac0;
    __u16 source_mac1;
    __u16 pad1;
};

struct trustix_kudp_rx_config_value {
    __u32 source_mac0;
    __u16 source_mac1;
    __u16 pad0;
    __u32 ifindex;
    __u32 destination_mac0;
    __u16 destination_mac1;
    __u16 pad1;
};

struct xdp_md {
    __u32 data;
    __u32 data_end;
    __u32 data_meta;
    __u32 ingress_ifindex;
    __u32 rx_queue_index;
    __u32 egress_ifindex;
};

struct bpf_dynptr {
    __u64 __opaque[2];
};

struct bpf_crypto_ctx {};

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
    struct bpf_spin_lock replay_lock;
    __u32 replay_lock_pad;
};

#ifdef TRUSTIX_TIX_TCP_DIRECT_OPEN
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
    struct bpf_spin_lock replay_lock;
    __u32 replay_lock_pad;
};
#endif

struct trustix_tix_tcp_kernel_crypto_scratch {
    __u8 cipher[TRUSTIX_KERNEL_CRYPTO_FRAME_MAX];
    __u8 plain[TRUSTIX_KERNEL_CRYPTO_FRAME_PADDED];
    __u8 nonce[12];
    __u32 plain_len;
};

struct trustix_tix_tcp_tcp_csum_header {
    __u8 pseudo[12];
    __u8 tcp[TRUSTIX_TIX_TCP_TCP_HEADER_LEN];
    __u8 frame[TRUSTIX_TIX_TCP_HEADER_LEN];
};

struct trustix_xdp_l4_csum_header {
    __u8 pseudo[12];
};

struct trustix_xdp_csum_tail {
    __u8 bytes[4];
};

struct trustix_xdp_csum_scratch {
    __u8 l4[TRUSTIX_XDP_RX_DIRECT_FRAME_PADDED];
};

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} ix_tix_tcp_xsk SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u8);
} ix_tix_tcp_port SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 51);
    __type(key, __u32);
    __type(value, __u64);
} ix_tix_tcp_stat SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} ix_tix_tcp_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct trustix_kudp_rx_neigh_value);
} ix_kudp_rx_neigh SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} ix_kudp_rx_devmap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct trustix_kudp_rx_config_value);
} ix_kudp_rx_config SEC(".maps");

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

#ifdef TRUSTIX_TIX_TCP_DIRECT_OPEN
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, TRUSTIX_KERNEL_CRYPTO_MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct trustix_kernel_crypto_direct_slot);
} trustix_kernel_crypto_direct_slots SEC(".maps");
#endif

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct trustix_tix_tcp_kernel_crypto_scratch);
} ix_tix_tcp_kernel_crypto_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct trustix_xdp_csum_scratch);
} ix_kudp_xdp_csum_scratch SEC(".maps");

static void *(*bpf_map_lookup_elem)(const void *map, const void *key) = (void *)1;
static long (*bpf_spin_lock)(struct bpf_spin_lock *lock) = (void *)93;
static long (*bpf_spin_unlock)(struct bpf_spin_lock *lock) = (void *)94;
#ifndef TRUSTIX_TIX_TCP_NO_XDP_RX_DIRECT
static long (*bpf_redirect)(__u32 ifindex, __u64 flags) = (void *)23;
#endif
static long (*bpf_redirect_map)(const void *map, __u32 key, __u64 flags) = (void *)51;
static long (*bpf_csum_diff)(const void *from, __u32 from_size, const void *to, __u32 to_size, __u32 seed) = (void *)28;
#ifndef TRUSTIX_TIX_TCP_NO_XDP_RX_DIRECT
static long (*bpf_xdp_adjust_head)(struct xdp_md *ctx, int delta) = (void *)44;
#endif
static long (*bpf_xdp_adjust_tail)(struct xdp_md *ctx, int delta) = (void *)65;
static long (*bpf_xdp_load_bytes)(struct xdp_md *ctx, __u32 offset, void *buf, __u32 len) = (void *)189;
static long (*bpf_xdp_store_bytes)(struct xdp_md *ctx, __u32 offset, void *buf, __u32 len) = (void *)190;
#ifndef TRUSTIX_TIX_TCP_DIRECT_OPEN_ONLY
static long (*bpf_dynptr_from_mem)(void *data, __u32 size, __u64 flags, struct bpf_dynptr *ptr) = (void *)197;

extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;
extern int bpf_crypto_decrypt(struct bpf_crypto_ctx *ctx, const struct bpf_dynptr *src, const struct bpf_dynptr *dst, const struct bpf_dynptr *siv__nullable) __ksym;
#endif
#ifdef TRUSTIX_TIX_TCP_DIRECT_OPEN
extern int trustix_kernel_direct_open(__u32 slot_id, const __u8 *src, __u8 *dst, __u32 cipher_len, const __u8 *nonce) __ksym;
#endif

static __always_inline void trustix_tix_tcp_count(__u32 key)
{
    __u64 *value = bpf_map_lookup_elem(&ix_tix_tcp_stat, &key);
    if (value)
        (*value)++;
}

static __always_inline __u32 trustix_tix_tcp_load_config(void)
{
    __u32 key = 0;
    __u32 *config = bpf_map_lookup_elem(&ix_tix_tcp_config, &key);

    return config ? *config : 0;
}

static __always_inline int trustix_tix_tcp_config_hot_path_stats(__u32 config)
{
    return config & TRUSTIX_TIX_TCP_CONFIG_HOT_PATH_STATS;
}

static __always_inline void trustix_tix_tcp_count_hot_config(__u32 config, __u32 key)
{
    if (trustix_tix_tcp_config_hot_path_stats(config))
        trustix_tix_tcp_count(key);
}

static __always_inline int trustix_tix_tcp_hot_path_stats(void)
{
    __u32 key = 0;
    __u32 *config = bpf_map_lookup_elem(&ix_tix_tcp_config, &key);

    return config && (*config & TRUSTIX_TIX_TCP_CONFIG_HOT_PATH_STATS);
}

static __always_inline void trustix_tix_tcp_count_hot(__u32 key)
{
    if (trustix_tix_tcp_hot_path_stats())
        trustix_tix_tcp_count(key);
}

#ifndef TRUSTIX_TIX_TCP_DIRECT_OPEN_ONLY
static __always_inline int trustix_kernel_crypto_hot_stats(const struct trustix_kernel_crypto_ctx_value *state)
{
    return state && (state->flags & TRUSTIX_KERNEL_CRYPTO_FLOW_FLAG_HOT_STATS);
}

static __always_inline int trustix_kernel_crypto_no_replay(const struct trustix_kernel_crypto_ctx_value *state)
{
    return state && (state->flags & TRUSTIX_KERNEL_CRYPTO_FLOW_FLAG_NO_REPLAY);
}
#endif

static __always_inline int trustix_kernel_udp_unfragmented(__u8 *frame)
{
    return frame[28] == 0 && frame[29] == 0 &&
           frame[30] == 0 && frame[31] == 0;
}

static __always_inline int trustix_tix_tcp_unfragmented(__u8 *frame)
{
    return frame[36] == 0 && frame[37] == 0 &&
           frame[38] == 0 && frame[39] == 0;
}

static __always_inline int trustix_inner_ipv4_tcp_control(__u8 *packet, __u32 packet_len)
{
    __u8 flags;

    if (!packet || packet_len < 40)
        return 0;
    if (packet[0] != 0x45 || packet[9] != 6)
        return 0;
    if (packet[6] & 0x3f || packet[7])
        return 0;
    flags = packet[33];
    return flags & 0x07;
}

#ifndef TRUSTIX_TIX_TCP_NO_XDP_RX_DIRECT
static __always_inline __u16 trustix_xdp_bswap16(__u16 value)
{
    return (value >> 8) | (value << 8);
}

static __always_inline void trustix_xdp_write_be16(__u8 *dst, __u16 value)
{
    dst[0] = (__u8)(value >> 8);
    dst[1] = (__u8)value;
}

static __always_inline __u16 trustix_xdp_read_be16(__u8 *src)
{
    return ((__u16)src[0] << 8) | src[1];
}

static __always_inline __u16 trustix_xdp_fold_checksum(__u32 sum)
{
#pragma clang loop unroll(full)
    for (int i = 0; i < 4; i++)
        sum = (sum & 0xffff) + (sum >> 16);
    return ~((__u16)sum);
}

static __noinline int trustix_xdp_add_csum_chunk(__u8 *data, __u32 len, __u32 *sum)
{
    __s64 next;

    len &= 0x7fc;
    if (len == 0)
        return 0;
    if (len > TRUSTIX_XDP_RX_DIRECT_CSUM_CHUNK)
        return -22;
    next = bpf_csum_diff(0, 0, data, len, *sum);
    if (next < 0)
        return (int)next;
    *sum = (__u32)next;
    return 0;
}

static __noinline int trustix_xdp_add_csum_bytes(__u8 *data, __u32 len, __u32 *sum)
{
    __u32 chunk;

    if (!data || !sum)
        return -22;
    if (len > TRUSTIX_XDP_RX_DIRECT_FRAME_PADDED)
        return -22;
    if (len > 0) {
        chunk = len;
        if (chunk > TRUSTIX_XDP_RX_DIRECT_CSUM_CHUNK)
            chunk = TRUSTIX_XDP_RX_DIRECT_CSUM_CHUNK;
        if (trustix_xdp_add_csum_chunk(data, chunk, sum))
            return -22;
    }
    if (len > TRUSTIX_XDP_RX_DIRECT_CSUM_CHUNK) {
        chunk = len - TRUSTIX_XDP_RX_DIRECT_CSUM_CHUNK;
        if (chunk > TRUSTIX_XDP_RX_DIRECT_CSUM_CHUNK)
            chunk = TRUSTIX_XDP_RX_DIRECT_CSUM_CHUNK;
        if (trustix_xdp_add_csum_chunk(data + TRUSTIX_XDP_RX_DIRECT_CSUM_CHUNK, chunk, sum))
            return -22;
    }
    if (len > TRUSTIX_XDP_RX_DIRECT_CSUM_CHUNK * 2) {
        chunk = len - TRUSTIX_XDP_RX_DIRECT_CSUM_CHUNK * 2;
        if (chunk > TRUSTIX_XDP_RX_DIRECT_CSUM_CHUNK)
            chunk = TRUSTIX_XDP_RX_DIRECT_CSUM_CHUNK;
        if (trustix_xdp_add_csum_chunk(data + TRUSTIX_XDP_RX_DIRECT_CSUM_CHUNK * 2, chunk, sum))
            return -22;
    }
    if (len > TRUSTIX_XDP_RX_DIRECT_CSUM_CHUNK * 3) {
        chunk = len - TRUSTIX_XDP_RX_DIRECT_CSUM_CHUNK * 3;
        if (chunk > TRUSTIX_XDP_RX_DIRECT_CSUM_CHUNK)
            chunk = TRUSTIX_XDP_RX_DIRECT_CSUM_CHUNK;
        if (trustix_xdp_add_csum_chunk(data + TRUSTIX_XDP_RX_DIRECT_CSUM_CHUNK * 3, chunk, sum))
            return -22;
    }
    if (len > TRUSTIX_XDP_RX_DIRECT_CSUM_CHUNK * 4) {
        chunk = len - TRUSTIX_XDP_RX_DIRECT_CSUM_CHUNK * 4;
        if (chunk > TRUSTIX_XDP_RX_DIRECT_CSUM_CHUNK)
            chunk = TRUSTIX_XDP_RX_DIRECT_CSUM_CHUNK;
        if (trustix_xdp_add_csum_chunk(data + TRUSTIX_XDP_RX_DIRECT_CSUM_CHUNK * 4, chunk, sum))
            return -22;
    }
    if (len > TRUSTIX_XDP_RX_DIRECT_CSUM_CHUNK * 5) {
        chunk = len - TRUSTIX_XDP_RX_DIRECT_CSUM_CHUNK * 5;
        if (chunk > TRUSTIX_XDP_RX_DIRECT_CSUM_CHUNK)
            chunk = TRUSTIX_XDP_RX_DIRECT_CSUM_CHUNK;
        if (trustix_xdp_add_csum_chunk(data + TRUSTIX_XDP_RX_DIRECT_CSUM_CHUNK * 5, chunk, sum))
            return -22;
    }
    if (len > TRUSTIX_XDP_RX_DIRECT_CSUM_CHUNK * 6) {
        chunk = len - TRUSTIX_XDP_RX_DIRECT_CSUM_CHUNK * 6;
        if (chunk > TRUSTIX_XDP_RX_DIRECT_CSUM_CHUNK)
            chunk = TRUSTIX_XDP_RX_DIRECT_CSUM_CHUNK;
        if (trustix_xdp_add_csum_chunk(data + TRUSTIX_XDP_RX_DIRECT_CSUM_CHUNK * 6, chunk, sum))
            return -22;
    }
    if (len > TRUSTIX_XDP_RX_DIRECT_CSUM_CHUNK * 7) {
        chunk = len - TRUSTIX_XDP_RX_DIRECT_CSUM_CHUNK * 7;
        if (chunk > TRUSTIX_XDP_RX_DIRECT_CSUM_CHUNK)
            chunk = TRUSTIX_XDP_RX_DIRECT_CSUM_CHUNK;
        if (trustix_xdp_add_csum_chunk(data + TRUSTIX_XDP_RX_DIRECT_CSUM_CHUNK * 7, chunk, sum))
            return -22;
    }
    return 0;
}

#define TRUSTIX_XDP_LOAD_L4_CHUNK(chunk)                                         \
    if (len >= copied + (chunk)) {                                               \
        if (copied > TRUSTIX_XDP_RX_DIRECT_FRAME_PADDED - (chunk))               \
            return -22;                                                          \
        if (bpf_xdp_load_bytes(ctx, packet_offset + copied,                      \
                               scratch->l4 + copied, (chunk)))                  \
            return -14;                                                          \
        copied += (chunk);                                                       \
    }

static __noinline int trustix_xdp_load_l4(struct xdp_md *ctx,
                                          __u32 packet_offset, __u32 len,
                                          struct trustix_xdp_csum_scratch *scratch)
{
    __u32 copied = 0;

    if (!scratch || len < 1 || len > TRUSTIX_XDP_RX_DIRECT_FRAME_MAX)
        return -22;
    len &= TRUSTIX_XDP_RX_DIRECT_FRAME_MAX;
    TRUSTIX_XDP_LOAD_L4_CHUNK(1024);
    TRUSTIX_XDP_LOAD_L4_CHUNK(512);
    TRUSTIX_XDP_LOAD_L4_CHUNK(256);
    TRUSTIX_XDP_LOAD_L4_CHUNK(128);
    TRUSTIX_XDP_LOAD_L4_CHUNK(64);
    TRUSTIX_XDP_LOAD_L4_CHUNK(32);
    TRUSTIX_XDP_LOAD_L4_CHUNK(16);
    TRUSTIX_XDP_LOAD_L4_CHUNK(8);
    TRUSTIX_XDP_LOAD_L4_CHUNK(4);
    TRUSTIX_XDP_LOAD_L4_CHUNK(2);
    TRUSTIX_XDP_LOAD_L4_CHUNK(1);
    return copied == len ? 0 : -22;
}

#undef TRUSTIX_XDP_LOAD_L4_CHUNK

static __noinline __u16 trustix_xdp_l4_checksum(__u8 *ip, __u8 *l4,
                                                __u32 l4_len, __u8 protocol)
{
    struct trustix_xdp_l4_csum_header header = {};
    __s64 sum;
    __u32 sum32;
    __u32 padded_len;
    __u16 checksum;

    l4_len &= TRUSTIX_XDP_RX_DIRECT_FRAME_MAX;
    if (l4_len == 0 || l4_len > TRUSTIX_XDP_RX_DIRECT_FRAME_MAX)
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
    trustix_xdp_write_be16(header.pseudo + 10, (__u16)l4_len);

    padded_len = (l4_len + 3) & ~3U;
    if (padded_len > TRUSTIX_XDP_RX_DIRECT_FRAME_PADDED)
        return 0;

    sum = bpf_csum_diff(0, 0, &header, sizeof(header), 0);
    if (sum < 0)
        return 0;
    sum32 = (__u32)sum;
    if (trustix_xdp_add_csum_bytes(l4, padded_len, &sum32))
        return 0;

    checksum = trustix_xdp_bswap16(trustix_xdp_fold_checksum(sum32));
    if (checksum == 0)
        checksum = 0xffff;
    return checksum;
}

static __always_inline int
trustix_xdp_zero_l4_padding(struct trustix_xdp_csum_scratch *scratch,
                            __u32 len)
{
    __u32 pad;

    if (!scratch || len > TRUSTIX_XDP_RX_DIRECT_FRAME_MAX)
        return -22;
    len &= TRUSTIX_XDP_RX_DIRECT_FRAME_MAX;
    pad = (4 - (len & 3)) & 3;
    if (!pad)
        return 0;
    if (len > TRUSTIX_XDP_RX_DIRECT_FRAME_PADDED - 1)
        return -22;
    scratch->l4[len] = 0;
    if (pad == 1)
        return 0;
    if (len > TRUSTIX_XDP_RX_DIRECT_FRAME_PADDED - 2)
        return -22;
    scratch->l4[len + 1] = 0;
    if (pad == 2)
        return 0;
    if (len > TRUSTIX_XDP_RX_DIRECT_FRAME_PADDED - 3)
        return -22;
    scratch->l4[len + 2] = 0;
    return 0;
}

static __noinline int trustix_xdp_fix_inner_l4_checksum(__u8 *inner,
                                                        struct xdp_md *ctx,
                                                        __u32 inner_offset,
                                                        __u32 inner_len,
                                                        __u8 *data_end)
{
    __u32 scratch_key = 0;
    struct trustix_xdp_csum_scratch *scratch;
    __u8 *l4;
    __u32 l4_len;
    __u32 tcp_header_len;
    __u32 udp_len;
    __u16 checksum;

    if (inner_len < 20 || inner_len > TRUSTIX_XDP_RX_DIRECT_FRAME_MAX)
        return -22;
    inner_len &= TRUSTIX_XDP_RX_DIRECT_FRAME_MAX;
    if (inner[0] != 0x45 || trustix_xdp_read_be16(inner + 2) != inner_len)
        return -22;
    if (inner[6] & 0x3f || inner[7])
        return -22;

    l4 = inner + 20;
    l4_len = inner_len - 20;
    if (l4_len < 1 || l4_len > TRUSTIX_XDP_RX_DIRECT_FRAME_MAX - 20)
        return -22;
    l4_len &= TRUSTIX_XDP_RX_DIRECT_FRAME_MAX;
    if (l4 + l4_len > data_end)
        return -14;
    scratch = bpf_map_lookup_elem(&ix_kudp_xdp_csum_scratch, &scratch_key);
    if (!scratch)
        return -22;
    if (inner[9] == IPPROTO_TCP) {
        if (l4 + 20 > data_end)
            return -14;
        if (l4_len < 20)
            return -22;
        tcp_header_len = (__u32)(l4[12] >> 4) << 2;
        if (tcp_header_len < 20 || tcp_header_len > l4_len)
            return -22;
        if (trustix_xdp_load_l4(ctx, inner_offset + 20, l4_len, scratch))
            return -22;
        scratch->l4[16] = 0;
        scratch->l4[17] = 0;
        if (trustix_xdp_zero_l4_padding(scratch, l4_len))
            return -22;
        checksum = trustix_xdp_l4_checksum(inner, scratch->l4, l4_len, IPPROTO_TCP);
        if (!checksum)
            return -22;
        trustix_xdp_write_be16(l4 + 16, checksum);
    } else if (inner[9] == IPPROTO_UDP) {
        if (l4 + 8 > data_end)
            return -14;
        if (l4_len < 8)
            return -22;
        udp_len = trustix_xdp_read_be16(l4 + 4);
        if (udp_len < 8 || udp_len > l4_len)
            return -22;
        if (udp_len > TRUSTIX_XDP_RX_DIRECT_FRAME_MAX - 20)
            return -22;
        udp_len &= TRUSTIX_XDP_RX_DIRECT_FRAME_MAX;
        if (l4[6] == 0 && l4[7] == 0)
            return 0;
        if (trustix_xdp_load_l4(ctx, inner_offset + 20, udp_len, scratch))
            return -22;
        scratch->l4[6] = 0;
        scratch->l4[7] = 0;
        if (trustix_xdp_zero_l4_padding(scratch, udp_len))
            return -22;
        checksum = trustix_xdp_l4_checksum(inner, scratch->l4, udp_len, IPPROTO_UDP);
        if (!checksum)
            return -22;
        trustix_xdp_write_be16(l4 + 6, checksum);
    }
    return 0;
}

static __always_inline int trustix_kernel_udp_xdp_redirect_lan(
    struct xdp_md *ctx, __u32 inner_offset, __u32 inner_len, __u32 available,
    __u32 destination_mac0, __u16 destination_mac1,
    __u32 source_mac0, __u16 source_mac1, __u32 ifindex, __u32 config)
{
    __u8 *data;
    __u8 *data_end;
    int delta = (int)inner_offset - 14;
    __u32 trim = available - inner_len;

    if (trim && bpf_xdp_adjust_tail(ctx, -(int)trim)) {
        trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_TAIL_ERRORS);
        return XDP_PASS;
    }
    if (bpf_xdp_adjust_head(ctx, delta)) {
        trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_ADJUST_HEAD_ERRORS);
        return XDP_PASS;
    }
    data = (__u8 *)(long)ctx->data;
    data_end = (__u8 *)(long)ctx->data_end;
    if (data + 14 > data_end) {
        trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_POST_ADJUST_ERRORS);
        return XDP_PASS;
    }

    *(__u16 *)(data + 0) = (__u16)destination_mac0;
    *(__u16 *)(data + 2) = (__u16)(destination_mac0 >> 16);
    *(__u16 *)(data + 4) = destination_mac1;
    *(__u16 *)(data + 6) = (__u16)source_mac0;
    *(__u16 *)(data + 8) = (__u16)(source_mac0 >> 16);
    *(__u16 *)(data + 10) = source_mac1;
    data[12] = 0x08;
    data[13] = 0x00;
    trustix_tix_tcp_count_hot_config(config, TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_REDIRECTS);
    if ((config & TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_XDP_RX_DIRECT_IFINDEX) && ifindex) {
        trustix_tix_tcp_count_hot_config(config, TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_IFINDEX_REDIRECTS);
        return bpf_redirect(ifindex, 0);
    }
    trustix_tix_tcp_count_hot_config(config, TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_DEVMAP_REDIRECTS);
    return bpf_redirect_map(&ix_kudp_rx_devmap, 0, 0);
}

static __always_inline int trustix_kernel_udp_xdp_rx_direct_inner(
    struct xdp_md *ctx, __u32 inner_offset, __u32 config)
{
    __u8 *data = (__u8 *)(long)ctx->data;
    __u8 *data_end = (__u8 *)(long)ctx->data_end;
    __u8 *inner = data + inner_offset;
    __u32 inner_len;
    __u32 available;
    __u32 key = 0;
    struct trustix_kudp_rx_neigh_value *neigh;
    struct trustix_kudp_rx_config_value *rx_config;

    trustix_tix_tcp_count_hot_config(config, TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_CANDIDATES);
    if (inner + 20 > data_end)
        goto direct_len_error;
    if (inner[0] != 0x45)
        goto direct_error;
    inner_len = ((__u32)inner[2] << 8) | inner[3];
    available = (__u32)(data_end - inner);
    if (inner_len < 20 || inner_len > available)
        goto direct_len_error;
    if (!(config & TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_XDP_RX_DIRECT_TRUST_INNER_CHECKSUM) &&
        trustix_xdp_fix_inner_l4_checksum(inner, ctx, inner_offset, inner_len, data_end)) {
        trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_CSUM_ERRORS);
        return TRUSTIX_XDP_DIRECT_FALLBACK;
    }

    if (config & TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_XDP_RX_DIRECT_FIXED_L2) {
        __u32 config_key = 0;

        rx_config = bpf_map_lookup_elem(&ix_kudp_rx_config, &config_key);
        if (!rx_config || !rx_config->ifindex) {
            trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_CONFIG_MISSES);
            return TRUSTIX_XDP_DIRECT_FALLBACK;
        }
        trustix_tix_tcp_count_hot_config(config, TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_BROADCASTS);
        return trustix_kernel_udp_xdp_redirect_lan(
            ctx, inner_offset, inner_len, available,
            rx_config->destination_mac0, rx_config->destination_mac1,
            rx_config->source_mac0, rx_config->source_mac1, rx_config->ifindex, config);
    }

    key = ((__u32)inner[16]) | ((__u32)inner[17] << 8) |
          ((__u32)inner[18] << 16) | ((__u32)inner[19] << 24);
    neigh = bpf_map_lookup_elem(&ix_kudp_rx_neigh, &key);
    if (!neigh) {
        trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_NEIGH_MISSES);
        return TRUSTIX_XDP_DIRECT_FALLBACK;
    }

    trustix_tix_tcp_count_hot_config(config, TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_NEIGH_HITS);
    return trustix_kernel_udp_xdp_redirect_lan(
        ctx, inner_offset, inner_len, available,
        neigh->destination_mac0, neigh->destination_mac1,
        neigh->source_mac0, neigh->source_mac1, neigh->ifindex, config);

direct_len_error:
    trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_LEN_ERRORS);
    return TRUSTIX_XDP_DIRECT_FALLBACK;
direct_error:
    trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_ERRORS);
    return TRUSTIX_XDP_DIRECT_FALLBACK;
}
#endif

static __always_inline __u32 trustix_tix_tcp_redirect_queue_config(struct xdp_md *ctx, __u32 config)
{
    __u32 queue_count = (config & TRUSTIX_TIX_TCP_CONFIG_QUEUE_COUNT_MASK) >>
                        TRUSTIX_TIX_TCP_CONFIG_QUEUE_COUNT_SHIFT;

    if (queue_count == 0 || ctx->rx_queue_index < queue_count)
        return ctx->rx_queue_index;

    trustix_tix_tcp_count_hot_config(config, TRUSTIX_TIX_TCP_STATS_QUEUE_FALLBACK);
    return 0;
}

static __always_inline int trustix_tix_tcp_port_allowed(__u8 *l4)
{
    __u32 dst_key = ((__u32)l4[2]) | ((__u32)l4[3] << 8);
    __u32 src_key = ((__u32)l4[0]) | ((__u32)l4[1] << 8);

    return bpf_map_lookup_elem(&ix_tix_tcp_port, &dst_key) ||
           bpf_map_lookup_elem(&ix_tix_tcp_port, &src_key);
}

static __always_inline __u16 trustix_bswap16(__u16 value)
{
    return (value >> 8) | (value << 8);
}

static __always_inline __u32 trustix_read_be32(__u8 *p)
{
    return ((__u32)p[0] << 24) | ((__u32)p[1] << 16) |
           ((__u32)p[2] << 8) | (__u32)p[3];
}

static __always_inline __u64 trustix_read_be64(__u8 *p)
{
    return ((__u64)trustix_read_be32(p) << 32) | trustix_read_be32(p + 4);
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

#ifndef TRUSTIX_TIX_TCP_DIRECT_OPEN_ONLY
static __always_inline void trustix_prepare_nonce(__u8 *nonce,
                                                 const struct trustix_kernel_crypto_ctx_value *state,
                                                 __u64 sequence)
{
    trustix_prepare_nonce_from_iv(nonce, state->iv, sequence);
}
#endif

#ifdef TRUSTIX_TIX_TCP_DIRECT_OPEN
static __always_inline void trustix_prepare_direct_nonce(__u8 *nonce,
                                                        const struct trustix_kernel_crypto_direct_slot *slot,
                                                        __u64 sequence)
{
    trustix_prepare_nonce_from_iv(nonce, slot->iv, sequence);
}

static __always_inline int trustix_kernel_crypto_direct_hot_stats(const struct trustix_kernel_crypto_direct_slot *slot)
{
    return slot && (slot->flags & TRUSTIX_KERNEL_CRYPTO_FLOW_FLAG_HOT_STATS);
}

static __always_inline int trustix_kernel_crypto_direct_no_replay(const struct trustix_kernel_crypto_direct_slot *slot)
{
    return slot && (slot->flags & TRUSTIX_KERNEL_CRYPTO_FLOW_FLAG_NO_REPLAY);
}
#endif


#ifndef TRUSTIX_TIX_TCP_DIRECT_OPEN_ONLY
static __always_inline __u32 trustix_replay_window(const struct trustix_kernel_crypto_ctx_value *state)
{
    __u32 window = state->replay_window;
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


static __always_inline int trustix_replay_commit(struct trustix_kernel_crypto_ctx_value *state,
                                                 __u64 sequence)
{
    __u32 window;
    __u64 delta;
    int replay_error = 0;

    if (trustix_kernel_crypto_no_replay(state))
        return sequence == 0 ? -22 : 0;
    if (sequence == 0)
        return -22;

    bpf_spin_lock(&state->replay_lock);
    if (sequence > state->last_sequence) {
        state->last_sequence = sequence;
        trustix_replay_mark(state, sequence);
        goto out_unlock;
    }

    window = trustix_replay_window(state);
    delta = state->last_sequence - sequence;
    if (delta >= window || delta >= TRUSTIX_KERNEL_CRYPTO_REPLAY_MAX)
        replay_error = 1;
    else if (trustix_replay_seen(state, sequence))
        replay_error = 2;
    else
        trustix_replay_mark(state, sequence);

out_unlock:
    bpf_spin_unlock(&state->replay_lock);
    return replay_error ? -114 : 0;
}
#endif

#ifdef TRUSTIX_TIX_TCP_DIRECT_OPEN
static __always_inline __u32 trustix_direct_replay_window(const struct trustix_kernel_crypto_direct_slot *slot)
{
    __u32 window = slot->replay_window;
    if (window == 0)
        window = TRUSTIX_KERNEL_CRYPTO_REPLAY_MAX;
    if (window > TRUSTIX_KERNEL_CRYPTO_REPLAY_MAX)
        window = TRUSTIX_KERNEL_CRYPTO_REPLAY_MAX;
    return window;
}

static __always_inline int trustix_direct_replay_seen(const struct trustix_kernel_crypto_direct_slot *slot,
                                                      __u64 sequence)
{
    __u64 block = sequence >> 6;
    __u32 index = (__u32)block & (TRUSTIX_KERNEL_CRYPTO_REPLAY_WORDS - 1);
    __u32 bit = (__u32)sequence & 63;
    __u64 mask = ((__u64)1) << bit;

    if (slot->replay_blocks[index] != block)
        return 0;
    return (slot->replay_seen[index] & mask) != 0;
}

static __always_inline void trustix_direct_replay_mark(struct trustix_kernel_crypto_direct_slot *slot,
                                                       __u64 sequence)
{
    __u64 block = sequence >> 6;
    __u32 index = (__u32)block & (TRUSTIX_KERNEL_CRYPTO_REPLAY_WORDS - 1);
    __u32 bit = (__u32)sequence & 63;
    __u64 mask = ((__u64)1) << bit;

    if (slot->replay_blocks[index] != block) {
        slot->replay_blocks[index] = block;
        slot->replay_seen[index] = 0;
    }
    slot->replay_seen[index] |= mask;
}

static __always_inline int trustix_direct_replay_commit(struct trustix_kernel_crypto_direct_slot *slot,
                                                        __u64 sequence)
{
    __u32 window;
    __u64 delta;
    int replay_error = 0;

    if (trustix_kernel_crypto_direct_no_replay(slot))
        return sequence == 0 ? -22 : 0;
    if (sequence == 0)
        return -22;

    bpf_spin_lock(&slot->replay_lock);
    if (sequence > slot->last_sequence) {
        slot->last_sequence = sequence;
        trustix_direct_replay_mark(slot, sequence);
        goto out_unlock;
    }

    window = trustix_direct_replay_window(slot);
    delta = slot->last_sequence - sequence;
    if (delta >= window || delta >= TRUSTIX_KERNEL_CRYPTO_REPLAY_MAX)
        replay_error = 1;
    else if (trustix_direct_replay_seen(slot, sequence))
        replay_error = 2;
    else
        trustix_direct_replay_mark(slot, sequence);

out_unlock:
    bpf_spin_unlock(&slot->replay_lock);
    return replay_error ? -114 : 0;
}
#endif


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

    /*
     * Older 6.12 verifier builds can lose the unsigned range for noinline
     * helper args and reject bpf_csum_diff() with "R4 min value is negative".
     * The mask preserves the valid 0..512, 4-byte aligned chunk sizes used by
     * the callers while giving the verifier a concrete non-negative range.
     */
    len &= 0x7fc;
    if (len == 0)
        return 0;
    if (len > TRUSTIX_TIX_TCP_CSUM_CHUNK)
        return -22;
    next = bpf_csum_diff(0, 0, data, len, *sum);
    if (next < 0)
        return (int)next;
    *sum = (__u32)next;
    return 0;
}

static __noinline int trustix_fix_tcp_checksum(__u8 *ip, __u8 *tcp, __u8 *frame,
                                               __u8 *data_end,
                                               struct trustix_tix_tcp_kernel_crypto_scratch *scratch)
{
    struct trustix_tix_tcp_tcp_csum_header header = {};
    __u32 plain_len;
    __u32 tcp_len;
    __u32 plain_padded;
    __u32 sum32;
    __u32 chunk;
    __s64 sum;

    if (!scratch)
        return -22;
    plain_len = scratch->plain_len;
    if (plain_len > TRUSTIX_KERNEL_CRYPTO_FRAME_MAX - TRUSTIX_KERNEL_CRYPTO_FRAME_TAG_LEN)
        return -22;
    tcp_len = TRUSTIX_TIX_TCP_TCP_HEADER_LEN + TRUSTIX_TIX_TCP_HEADER_LEN + plain_len;
    if (tcp + TRUSTIX_TIX_TCP_TCP_HEADER_LEN > data_end ||
        frame + TRUSTIX_TIX_TCP_HEADER_LEN > data_end)
        return -14;

    header.pseudo[0] = ip[12];
    header.pseudo[1] = ip[13];
    header.pseudo[2] = ip[14];
    header.pseudo[3] = ip[15];
    header.pseudo[4] = ip[16];
    header.pseudo[5] = ip[17];
    header.pseudo[6] = ip[18];
    header.pseudo[7] = ip[19];
    header.pseudo[8] = 0;
    header.pseudo[9] = 6;
    trustix_write_be16(header.pseudo + 10, (__u16)tcp_len);

#pragma clang loop unroll(full)
    for (int i = 0; i < TRUSTIX_TIX_TCP_TCP_HEADER_LEN; i++)
        header.tcp[i] = tcp[i];
    header.tcp[16] = 0;
    header.tcp[17] = 0;

#pragma clang loop unroll(full)
    for (int i = 0; i < TRUSTIX_TIX_TCP_HEADER_LEN; i++)
        header.frame[i] = frame[i];

    plain_padded = (plain_len + 3) & ~3U;
    if (plain_padded > TRUSTIX_KERNEL_CRYPTO_FRAME_MAX)
        return -22;
    if (plain_padded > TRUSTIX_KERNEL_CRYPTO_FRAME_PADDED)
        return -22;
    if (plain_padded > plain_len) {
#pragma clang loop unroll(full)
        for (int i = 0; i < 3; i++) {
            __u32 offset = plain_len + (__u32)i;
            if (offset >= plain_padded)
                break;
            scratch->plain[offset] = 0;
        }
    }

    sum = bpf_csum_diff(0, 0, &header, sizeof(header), 0);
    if (sum < 0)
        return (int)sum;
    sum32 = (__u32)sum;

    if (plain_padded > 0) {
        chunk = plain_padded;
        if (chunk > TRUSTIX_TIX_TCP_CSUM_CHUNK)
            chunk = TRUSTIX_TIX_TCP_CSUM_CHUNK;
        if (trustix_add_csum_chunk(scratch->plain, chunk, &sum32))
            return -22;
    }
    if (plain_padded > TRUSTIX_TIX_TCP_CSUM_CHUNK) {
        chunk = plain_padded - TRUSTIX_TIX_TCP_CSUM_CHUNK;
        if (chunk > TRUSTIX_TIX_TCP_CSUM_CHUNK)
            chunk = TRUSTIX_TIX_TCP_CSUM_CHUNK;
        if (trustix_add_csum_chunk(scratch->plain + TRUSTIX_TIX_TCP_CSUM_CHUNK, chunk, &sum32))
            return -22;
    }
    if (plain_padded > TRUSTIX_TIX_TCP_CSUM_CHUNK * 2) {
        chunk = plain_padded - TRUSTIX_TIX_TCP_CSUM_CHUNK * 2;
        if (chunk > TRUSTIX_TIX_TCP_CSUM_CHUNK)
            chunk = TRUSTIX_TIX_TCP_CSUM_CHUNK;
        if (trustix_add_csum_chunk(scratch->plain + TRUSTIX_TIX_TCP_CSUM_CHUNK * 2, chunk, &sum32))
            return -22;
    }
    if (plain_padded > TRUSTIX_TIX_TCP_CSUM_CHUNK * 3) {
        chunk = plain_padded - TRUSTIX_TIX_TCP_CSUM_CHUNK * 3;
        if (chunk > TRUSTIX_TIX_TCP_CSUM_CHUNK)
            chunk = TRUSTIX_TIX_TCP_CSUM_CHUNK;
        if (trustix_add_csum_chunk(scratch->plain + TRUSTIX_TIX_TCP_CSUM_CHUNK * 3, chunk, &sum32))
            return -22;
    }
    trustix_write_be16(tcp + 16, trustix_bswap16(trustix_fold_checksum(sum32)));
    return 0;
}

static __noinline int trustix_open_frame(struct xdp_md *ctx, __u8 *payload,
                                         __u32 payload_len, __u8 *frame,
                                         struct trustix_tix_tcp_kernel_crypto_scratch *scratch)
{
    __u8 *data = (__u8 *)(long)ctx->data;
    __u8 *data_end = (__u8 *)(long)ctx->data_end;
    __u32 *slot_index;
    struct trustix_kernel_crypto_flow_key key = {};
#ifndef TRUSTIX_TIX_TCP_DIRECT_OPEN_ONLY
    struct trustix_kernel_crypto_ctx_value *state;
    struct bpf_crypto_ctx *crypto_ctx;
    struct bpf_dynptr cipher, plain, nonce;
#endif
#ifdef TRUSTIX_TIX_TCP_DIRECT_OPEN
    struct trustix_kernel_crypto_direct_slot *direct_slot;
#endif
    volatile __u32 raw_cipher_len;
    __u32 bounded_cipher_len;
    __u32 cipher_len;
    __u32 plain_len;
    __u64 payload_offset64;
    __u32 payload_offset;
    __u64 flow_id;
    __u64 epoch;
    __u64 sequence;
    int err = 0;

    if (payload_len < TRUSTIX_TIX_TCP_OVERHEAD ||
        payload_len - TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN > TRUSTIX_KERNEL_CRYPTO_FRAME_MAX) {
        trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_PAYLOAD_LEN_ERRORS);
        return -22;
    }
    if (payload + TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN > data_end) {
        trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_SECURE_HEADER_ERRORS);
        return -14;
    }
    if (payload[0] != 'T' || payload[1] != 'I' ||
        payload[2] != 'X' || payload[3] != 'D' ||
        payload[4] != 1) {
        trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_SECURE_HEADER_ERRORS);
        return -74;
    }
    if (!frame || frame + TRUSTIX_KERNEL_UDP_HEADER_LEN > data_end) {
        trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_FRAME_HEADER_ERRORS);
        return -14;
    }
    flow_id = trustix_read_be64(frame + 8);
    if (frame[0] == 'T' && frame[1] == 'I' &&
        frame[2] == 'X' && frame[3] == 'T') {
        if (frame + TRUSTIX_TIX_TCP_HEADER_LEN > data_end) {
            trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_FRAME_HEADER_ERRORS);
            return -14;
        }
        epoch = trustix_read_be64(frame + 16);
        sequence = trustix_read_be64(frame + 24);
    } else if (frame[0] == 'T' && frame[1] == 'I' &&
               frame[2] == 'X' && frame[3] == 'U') {
        epoch = trustix_read_be64(payload + 8);
        sequence = trustix_read_be64(frame + 16);
    } else {
        trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_FRAME_HEADER_ERRORS);
        return -22;
    }
    if (trustix_read_be64(payload + 8) != epoch ||
        trustix_read_be64(payload + 16) != sequence) {
        trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_EPOCH_SEQUENCE_MISMATCHES);
        return -74;
    }

    raw_cipher_len = payload_len - TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN;
    bounded_cipher_len = raw_cipher_len & TRUSTIX_KERNEL_CRYPTO_FRAME_MAX;
    if (bounded_cipher_len != raw_cipher_len ||
        bounded_cipher_len < TRUSTIX_KERNEL_CRYPTO_FRAME_TAG_LEN) {
        trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_CIPHER_LEN_ERRORS);
        return -22;
    }
    cipher_len = bounded_cipher_len;
    plain_len = cipher_len - TRUSTIX_KERNEL_CRYPTO_FRAME_TAG_LEN;
    if (!scratch) {
        trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_CONTEXT_MISSES);
        return -2;
    }
    scratch->plain_len = plain_len;

    if (!ctx || payload < data) {
        trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_CIPHER_LOAD_ERRORS);
        return -14;
    }
    payload_offset64 = (__u64)(payload - data);
    if (payload_offset64 > 0xffffU) {
        trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_CIPHER_LOAD_ERRORS);
        return -14;
    }
    payload_offset = (__u32)payload_offset64;
    if (bpf_xdp_load_bytes(ctx, payload_offset + TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN,
                           scratch->cipher, cipher_len)) {
        trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_CIPHER_LOAD_ERRORS);
        return -14;
    }

    key.flow_id = flow_id;
    key.direction = TRUSTIX_KERNEL_CRYPTO_DIRECTION_RECV;
    if (frame[0] == 'T' && frame[1] == 'I' &&
        frame[2] == 'X' && frame[3] == 'U')
        key.reserved[0] = TRUSTIX_KERNEL_CRYPTO_NAMESPACE_KERNEL_UDP;
    slot_index = bpf_map_lookup_elem(&trustix_kernel_crypto_flow_index_map, &key);
    if (!slot_index) {
        trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_CONTEXT_MISSES);
        return -2;
    }
#ifndef TRUSTIX_TIX_TCP_DIRECT_OPEN_ONLY
    state = bpf_map_lookup_elem(&trustix_kernel_crypto_ctx_slots, slot_index);
#endif
#ifdef TRUSTIX_TIX_TCP_DIRECT_OPEN
    direct_slot = bpf_map_lookup_elem(&trustix_kernel_crypto_direct_slots, slot_index);
#endif
    if (plain_len == 0) {
        trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_ZERO_PLAIN_ERRORS);
        return -22;
    }

#ifdef TRUSTIX_TIX_TCP_DIRECT_OPEN
    if (direct_slot && direct_slot->enabled) {
        if (direct_slot->epoch != epoch) {
            trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_EPOCH_MISMATCHES);
            return -74;
        }
        if (payload[5] != (__u8)direct_slot->suite) {
            trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_SUITE_MISMATCHES);
            return -74;
        }
        trustix_prepare_direct_nonce(scratch->nonce, direct_slot, sequence);
        err = trustix_kernel_direct_open(direct_slot->slot_id,
                                           scratch->cipher,
                                           scratch->plain,
                                           cipher_len,
                                           scratch->nonce);
        if (!err) {
            err = trustix_direct_replay_commit(direct_slot, sequence);
            if (err) {
                trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_REPLAY_COMMIT_ERRORS);
                return err;
            }
            if (trustix_kernel_crypto_direct_hot_stats(direct_slot)) {
                direct_slot->packets++;
                direct_slot->bytes += plain_len;
            }
            trustix_tix_tcp_count_hot(TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_DIRECT_OPEN_SUCCESSES);
            goto direct_opened;
        }
        trustix_tix_tcp_count_hot(TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_DIRECT_OPEN_FALLBACKS);
    }
#ifdef TRUSTIX_TIX_TCP_DIRECT_OPEN_ONLY
    trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_CONTEXT_UNAVAILABLE);
    return -2;
#endif
#endif

#ifndef TRUSTIX_TIX_TCP_DIRECT_OPEN_ONLY
    if (!state) {
        trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_STATE_MISSES);
        return -2;
    }

    bpf_rcu_read_lock();
    crypto_ctx = state->ctx;
    if (!crypto_ctx) {
        trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_CONTEXT_UNAVAILABLE);
        err = -2;
        goto out_unlock;
    }
    if (state->epoch != epoch) {
        trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_EPOCH_MISMATCHES);
        err = -74;
        goto out_unlock;
    }
    if (payload[5] != (__u8)state->suite) {
        trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_SUITE_MISMATCHES);
        err = -74;
        goto out_unlock;
    }
    trustix_prepare_nonce(scratch->nonce, state, sequence);
    if (bpf_dynptr_from_mem(scratch->cipher, cipher_len, 0, &cipher) ||
        bpf_dynptr_from_mem(scratch->plain, cipher_len, 0, &plain) ||
        bpf_dynptr_from_mem(scratch->nonce, sizeof(scratch->nonce), 0, &nonce)) {
        trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_DYNPTR_ERRORS);
        err = -14;
        goto out_unlock;
    }
    err = bpf_crypto_decrypt(crypto_ctx, &cipher, &plain, &nonce);
    if (err) {
        trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_DECRYPT_ERRORS);
        goto out_unlock;
    }
out_unlock:
    bpf_rcu_read_unlock();
    if (err)
        return err;
    err = trustix_replay_commit(state, sequence);
    if (err) {
        trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_REPLAY_COMMIT_ERRORS);
        return err;
    }
    trustix_tix_tcp_count_hot(TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_FALLBACK_OPEN_SUCCESSES);
    if (trustix_kernel_crypto_hot_stats(state)) {
        state->packets++;
        state->bytes += plain_len;
    }
#endif
#ifdef TRUSTIX_TIX_TCP_DIRECT_OPEN
direct_opened:
#endif
    if (payload + plain_len > data_end) {
        trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_STORE_ERRORS);
        return -14;
    }
    if (bpf_xdp_store_bytes(ctx, payload_offset, scratch->plain, plain_len)) {
        trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_STORE_ERRORS);
        return -14;
    }
    return (__s32)plain_len;
}

SEC("xdp")
int trustix_tix_tcp(struct xdp_md *ctx)
{
    __u8 *data = (__u8 *)(long)ctx->data;
    __u8 *data_end = (__u8 *)(long)ctx->data_end;
    __u8 *ip;
    __u8 *tcp;
    __u8 *udp;
    __u8 *frame;
    __u8 *payload;
    __u32 payload_len;
    __u32 frame_end_offset;
    __u32 packet_len;
    __u32 old_total_len;
    __u32 new_total_len;
    __u32 opened_inner_ipv4;
    __u32 pass_opened_to_tc;
    __u32 config = 0;
    __u8 encrypted_flag;
    __u32 scratch_key = 0;
    struct trustix_tix_tcp_kernel_crypto_scratch *scratch;
#ifndef TRUSTIX_TIX_TCP_NO_XDP_RX_DIRECT
    int direct_action;
#endif
    int plain_len;

    if (data + 14 > data_end)
        goto parse_error;
    packet_len = (__u32)(data_end - data);
    if (data[12] != 0x08 || data[13] != 0x00)
        goto pass;

    ip = data + 14;
    if (ip + 20 > data_end)
        goto parse_error;
    if (ip[0] != 0x45)
        goto pass;
    if (ip[9] == 17)
        goto udp;
    if (ip[9] != 6)
        goto pass;

    tcp = ip + 20;
    if (tcp + 20 > data_end)
        goto parse_error;
    if (tcp[12] != 0x50)
        goto pass;

    frame = tcp + 20;
    if (frame + TRUSTIX_TIX_TCP_HEADER_LEN > data_end)
        goto pass;
    if (frame[0] != 'T' || frame[1] != 'I' ||
        frame[2] != 'X' || frame[3] != 'T')
        goto pass;
    if (frame[4] != 1 || frame[6] != 0 || frame[7] != TRUSTIX_TIX_TCP_HEADER_LEN)
        goto parse_error;

    config = trustix_tix_tcp_load_config();
    encrypted_flag = frame[5] & TRUSTIX_TIX_TCP_FLAG_ENCRYPTED;
    if (encrypted_flag &&
        (frame[5] & TRUSTIX_TIX_TCP_FLAG_INNER_IPV4) &&
        !(frame[5] & TRUSTIX_TIX_TCP_FLAG_CRYPTO_FRAGMENT) &&
        trustix_tix_tcp_unfragmented(frame) &&
        !(config & TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_XDP_RX_SECURE_DIRECT) &&
        (config & TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_TC_RX_SECURE_DIRECT)) {
        if (!trustix_tix_tcp_port_allowed(tcp))
            goto drop;
        trustix_tix_tcp_count_hot_config(config, TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_TC_RX_DIRECT_PASS);
        goto pass;
    }
    if (encrypted_flag && !(config & TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_XDP_OPEN))
        goto redirect;
    if (encrypted_flag && (frame[5] & TRUSTIX_TIX_TCP_FLAG_CRYPTO_FRAGMENT))
        goto redirect;
    if (encrypted_flag) {
        if (data + 14 + 20 + 20 + TRUSTIX_TIX_TCP_HEADER_LEN + TRUSTIX_TIX_TCP_OVERHEAD > data_end)
            goto encrypted_header_error;
    } else if (frame[5] & TRUSTIX_TIX_TCP_FLAG_KERNEL_OPENED) {
        goto parse_error;
    }

    payload_len = trustix_read_be32(frame + 32);
    if (payload_len > TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN + TRUSTIX_KERNEL_CRYPTO_FRAME_MAX)
        goto parse_error;
    if (frame + TRUSTIX_TIX_TCP_HEADER_LEN + payload_len > data_end)
        goto parse_error;

    if (!trustix_tix_tcp_port_allowed(tcp))
        goto drop;

    if (encrypted_flag) {
        payload = frame + TRUSTIX_TIX_TCP_HEADER_LEN;
        if (payload_len < TRUSTIX_TIX_TCP_OVERHEAD)
            goto encrypted_header_error;
        scratch = bpf_map_lookup_elem(&ix_tix_tcp_kernel_crypto_scratch, &scratch_key);
        if (!scratch)
            goto encrypted_defer_to_userspace;
        trustix_tix_tcp_count_hot_config(config, TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_OPEN_ATTEMPTS);
        plain_len = trustix_open_frame(ctx, payload, payload_len, frame, scratch);
        if (plain_len < 0) {
            if (plain_len == -114) {
                trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_REPLAY_DROPS);
                return XDP_DROP;
            } else if (plain_len == -2) {
                trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_DEFERRED_TO_USERSPACE);
                goto redirect;
            } else if (plain_len == -22 || plain_len == -74)
                trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_HEADER_ERRORS);
            trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_OPEN_ERRORS);
            return XDP_DROP;
        }
        old_total_len = ((__u32)ip[2] << 8) | ip[3];
        if (old_total_len < 20 + 20 + TRUSTIX_TIX_TCP_HEADER_LEN + payload_len)
            goto parse_error;
        if (ip + old_total_len > data_end)
            goto parse_error;
        opened_inner_ipv4 = (frame[5] & TRUSTIX_TIX_TCP_FLAG_INNER_IPV4) &&
                            trustix_tix_tcp_unfragmented(frame) &&
                            plain_len >= 20 && scratch->plain[0] == 0x45;
        pass_opened_to_tc = opened_inner_ipv4 &&
                            !trustix_inner_ipv4_tcp_control(scratch->plain, (__u32)plain_len) &&
                            (config & TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_XDP_PASS_OPENED);
        new_total_len = old_total_len - (payload_len - (__u32)plain_len);
        frame[5] = (frame[5] & ~TRUSTIX_TIX_TCP_FLAG_ENCRYPTED) | TRUSTIX_TIX_TCP_FLAG_KERNEL_OPENED;
        trustix_write_be32(frame + 32, (__u32)plain_len);
        trustix_write_be16(ip + 2, (__u16)new_total_len);
        trustix_fix_ipv4_checksum(ip);
        tcp[16] = 0;
        tcp[17] = 0;
        if (config & TRUSTIX_TIX_TCP_CONFIG_SKIP_TCP_CHECKSUM) {
            trustix_tix_tcp_count_hot_config(config, TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_TCP_CHECKSUM_SKIPPED);
        } else if (trustix_fix_tcp_checksum(ip, tcp, frame, data_end, scratch)) {
            trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_HEADER_ERRORS);
            trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_OPEN_ERRORS);
            return XDP_DROP;
        }
        if (bpf_xdp_adjust_tail(ctx, -((int)payload_len - plain_len)))
            goto parse_error;
        trustix_tix_tcp_count_hot_config(config, TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_OPEN_SUCCESSES);
#ifndef TRUSTIX_TIX_TCP_NO_XDP_RX_DIRECT
        if (opened_inner_ipv4 &&
            (config & TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_XDP_RX_SECURE_DIRECT)) {
            direct_action = trustix_kernel_udp_xdp_rx_direct_inner(ctx, 94, config);
            if (direct_action >= 0)
                return direct_action;
            goto redirect;
        }
#endif
        if (pass_opened_to_tc) {
            trustix_tix_tcp_count_hot_config(config, TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_TC_RX_DIRECT_PASS);
            goto pass;
        }
        goto redirect;
    } else if (frame[5] & TRUSTIX_TIX_TCP_FLAG_KERNEL_OPENED) {
        goto parse_error;
    }
    if ((frame[5] == TRUSTIX_TIX_TCP_FLAG_INNER_IPV4 ||
         frame[5] == (TRUSTIX_TIX_TCP_FLAG_KERNEL_OPENED | TRUSTIX_TIX_TCP_FLAG_INNER_IPV4)) &&
        frame[36] == 0 && frame[37] == 0 && frame[38] == 0 &&
        frame[39] == 0) {
        trustix_tix_tcp_count_hot_config(config, TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_PLAINTEXT_CANDIDATES);
        payload_len = trustix_read_be32(frame + 32);
        frame_end_offset = 0;
        if (payload_len <= 0xffff - 94)
            frame_end_offset = 94 + payload_len;
        if (frame_end_offset == packet_len &&
            frame + TRUSTIX_TIX_TCP_HEADER_LEN + 20 <= data_end &&
            frame[TRUSTIX_TIX_TCP_HEADER_LEN] == 0x45) {
#ifndef TRUSTIX_TIX_TCP_NO_XDP_RX_DIRECT
            if (config & TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_XDP_RX_DIRECT) {
                direct_action = trustix_kernel_udp_xdp_rx_direct_inner(ctx, 94, config);
                if (direct_action >= 0)
                    return direct_action;
                goto redirect;
            }
#endif
            if (config & TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_TC_RX_DIRECT) {
                trustix_tix_tcp_count_hot_config(config, TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_TC_RX_DIRECT_PASS);
                goto pass;
            }
        }
        if (frame_end_offset != 0 &&
            frame_end_offset < packet_len &&
            packet_len - frame_end_offset >= TRUSTIX_TIX_TCP_HEADER_LEN &&
            frame + TRUSTIX_TIX_TCP_HEADER_LEN + 20 <= data_end &&
            frame[TRUSTIX_TIX_TCP_HEADER_LEN] == 0x45 &&
            trustix_tix_tcp_unfragmented(frame) &&
            (config & TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_TC_RX_DIRECT)) {
            trustix_tix_tcp_count_hot_config(config, TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_TC_RX_DIRECT_PASS);
            goto pass;
        }
        trustix_tix_tcp_count_hot_config(config, TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_INNER_IPV4_MISSES);
    }

redirect:
    if (config & TRUSTIX_TIX_TCP_CONFIG_XDP_FALLBACK_PASS)
        goto pass;
    trustix_tix_tcp_count_hot_config(config, TRUSTIX_TIX_TCP_STATS_REDIRECTED);
    return bpf_redirect_map(&ix_tix_tcp_xsk, trustix_tix_tcp_redirect_queue_config(ctx, config), XDP_DROP);

udp:
    udp = ip + 20;
    if (udp + 8 > data_end)
        goto parse_error;

    frame = udp + 8;
    if (frame + TRUSTIX_KERNEL_UDP_HEADER_LEN > data_end)
        goto pass;
    if (frame[0] != 'T' || frame[1] != 'I' ||
        frame[2] != 'X' || frame[3] != 'U')
        goto pass;
    if (frame[4] != 1 || frame[6] != 0 || frame[7] != TRUSTIX_KERNEL_UDP_HEADER_LEN)
        goto parse_error;

    config = trustix_tix_tcp_load_config();
    if (!trustix_tix_tcp_port_allowed(udp))
        goto drop;
    encrypted_flag = frame[5] & TRUSTIX_TIX_TCP_FLAG_ENCRYPTED;
    if (encrypted_flag &&
        (frame[5] & TRUSTIX_TIX_TCP_FLAG_INNER_IPV4) &&
        !(frame[5] & TRUSTIX_TIX_TCP_FLAG_CRYPTO_FRAGMENT) &&
        trustix_kernel_udp_unfragmented(frame) &&
        !(config & TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_XDP_RX_SECURE_DIRECT) &&
        (config & TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_TC_RX_SECURE_DIRECT)) {
        trustix_tix_tcp_count_hot_config(config, TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_TC_RX_DIRECT_PASS);
        goto pass;
    }
    if (encrypted_flag && !(config & TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_XDP_OPEN))
        goto redirect;
    if (encrypted_flag && (frame[5] & TRUSTIX_TIX_TCP_FLAG_CRYPTO_FRAGMENT))
        goto redirect;
    if (encrypted_flag) {
        payload_len = trustix_read_be32(frame + 24);
        if (payload_len < TRUSTIX_TIX_TCP_OVERHEAD ||
            payload_len > TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN + TRUSTIX_KERNEL_CRYPTO_FRAME_MAX)
            goto encrypted_header_error;
        payload = frame + TRUSTIX_KERNEL_UDP_HEADER_LEN;
        if (payload + payload_len > data_end)
            goto parse_error;
        scratch = bpf_map_lookup_elem(&ix_tix_tcp_kernel_crypto_scratch, &scratch_key);
        if (!scratch)
            goto encrypted_defer_to_userspace;
        trustix_tix_tcp_count_hot_config(config, TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_OPEN_ATTEMPTS);
        plain_len = trustix_open_frame(ctx, payload, payload_len, frame, scratch);
        if (plain_len < 0) {
            if (plain_len == -114) {
                trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_REPLAY_DROPS);
                return XDP_DROP;
            } else if (plain_len == -2) {
                trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_DEFERRED_TO_USERSPACE);
                goto redirect;
            } else if (plain_len == -22 || plain_len == -74)
                trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_HEADER_ERRORS);
            trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_OPEN_ERRORS);
            return XDP_DROP;
        }
        old_total_len = ((__u32)ip[2] << 8) | ip[3];
        if (old_total_len < 20 + 8 + TRUSTIX_KERNEL_UDP_HEADER_LEN + payload_len)
            goto parse_error;
        if (ip + old_total_len > data_end)
            goto parse_error;
        opened_inner_ipv4 = (frame[5] & TRUSTIX_TIX_TCP_FLAG_INNER_IPV4) &&
                            trustix_kernel_udp_unfragmented(frame) &&
                            plain_len >= 20 && scratch->plain[0] == 0x45;
        pass_opened_to_tc = opened_inner_ipv4 &&
                            !trustix_inner_ipv4_tcp_control(scratch->plain, (__u32)plain_len) &&
                            (config & TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_XDP_PASS_OPENED);
        new_total_len = old_total_len - (payload_len - (__u32)plain_len);
        frame[5] = (frame[5] & ~TRUSTIX_TIX_TCP_FLAG_ENCRYPTED) | TRUSTIX_TIX_TCP_FLAG_KERNEL_OPENED;
        trustix_write_be32(frame + 24, (__u32)plain_len);
        trustix_write_be16(ip + 2, (__u16)new_total_len);
        trustix_fix_ipv4_checksum(ip);
        trustix_write_be16(udp + 4, (__u16)(8 + TRUSTIX_KERNEL_UDP_HEADER_LEN + plain_len));
        trustix_write_be16(udp + 6, 0);
        if (bpf_xdp_adjust_tail(ctx, -((int)payload_len - plain_len)))
            goto parse_error;
        trustix_tix_tcp_count_hot_config(config, TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_OPEN_SUCCESSES);
#ifndef TRUSTIX_TIX_TCP_NO_XDP_RX_DIRECT
        if (opened_inner_ipv4 &&
            (config & TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_XDP_RX_SECURE_DIRECT)) {
            direct_action = trustix_kernel_udp_xdp_rx_direct_inner(ctx, 74, config);
            if (direct_action >= 0)
                return direct_action;
            goto redirect;
        }
#endif
        if (pass_opened_to_tc) {
            trustix_tix_tcp_count_hot_config(config, TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_TC_RX_DIRECT_PASS);
            goto pass;
        }
        goto redirect;
    } else if (frame[5] & TRUSTIX_TIX_TCP_FLAG_KERNEL_OPENED) {
        goto parse_error;
    }
    if ((frame[5] == TRUSTIX_TIX_TCP_FLAG_INNER_IPV4 ||
         frame[5] == (TRUSTIX_TIX_TCP_FLAG_KERNEL_OPENED | TRUSTIX_TIX_TCP_FLAG_INNER_IPV4)) &&
        frame[28] == 0 && frame[29] == 0 && frame[30] == 0 &&
        frame[31] == 0) {
        trustix_tix_tcp_count_hot_config(config, TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_PLAINTEXT_CANDIDATES);
        if (frame + TRUSTIX_KERNEL_UDP_HEADER_LEN + 20 <= data_end &&
            frame[TRUSTIX_KERNEL_UDP_HEADER_LEN] == 0x45) {
#ifndef TRUSTIX_TIX_TCP_NO_XDP_RX_DIRECT
            if (config & TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_XDP_RX_DIRECT) {
                direct_action = trustix_kernel_udp_xdp_rx_direct_inner(ctx, 74, config);
                if (direct_action >= 0)
                    return direct_action;
                goto redirect;
            }
#endif
            if (config & TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_TC_RX_DIRECT) {
                trustix_tix_tcp_count_hot_config(config, TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_TC_RX_DIRECT_PASS);
                goto pass;
            }
        }
        if (frame + TRUSTIX_KERNEL_UDP_HEADER_LEN + 34 <= data_end &&
            frame[TRUSTIX_KERNEL_UDP_HEADER_LEN + 12] == 0x08 &&
            frame[TRUSTIX_KERNEL_UDP_HEADER_LEN + 13] == 0x00 &&
            frame[TRUSTIX_KERNEL_UDP_HEADER_LEN + 14] == 0x45) {
            trustix_tix_tcp_count_hot_config(config, TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_INNER_IPV4_AT88);
#ifndef TRUSTIX_TIX_TCP_NO_XDP_RX_DIRECT
            if (config & TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_XDP_RX_DIRECT) {
                direct_action = trustix_kernel_udp_xdp_rx_direct_inner(ctx, 88, config);
                if (direct_action >= 0)
                    return direct_action;
                goto redirect;
            }
#endif
            if (config & TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_TC_RX_DIRECT) {
                trustix_tix_tcp_count_hot_config(config, TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_TC_RX_DIRECT_PASS);
                goto pass;
            }
        }
        trustix_tix_tcp_count_hot_config(config, TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_INNER_IPV4_MISSES);
    }
    goto redirect;

drop:
    trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_UNAUTHORIZED_DROPS);
    return XDP_DROP;

encrypted_header_error:
    trustix_tix_tcp_count_hot_config(config, TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_OPEN_ATTEMPTS);
    trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_HEADER_ERRORS);
    trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_OPEN_ERRORS);
    return XDP_DROP;

encrypted_defer_to_userspace:
    trustix_tix_tcp_count_hot_config(config, TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_OPEN_ATTEMPTS);
    trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_CRYPTO_DEFERRED_TO_USERSPACE);
    goto redirect;

pass:
    if (config ? trustix_tix_tcp_config_hot_path_stats(config) : trustix_tix_tcp_hot_path_stats())
        trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_PASS);
    return XDP_PASS;

parse_error:
    trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_PARSE_ERRORS);
    return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
