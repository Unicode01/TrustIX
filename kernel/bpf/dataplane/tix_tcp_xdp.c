// SPDX-License-Identifier: GPL-2.0 OR MIT
// XDP classifier for the TrustIX AF_XDP transport fast path. This detects the
// fixed IPv4/TCP TIXT and IPv4/UDP TIXU TrustIX frame contracts, enforces the
// destination-port allowlist, counts decisions, and redirects authorized frames
// into the XSK map.
#define SEC(NAME) __attribute__((section(NAME), used))
#define __always_inline inline __attribute__((always_inline))
#define __noinline __attribute__((noinline))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef long long __s64;
typedef unsigned long long __u64;

#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_DEVMAP 14
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define BPF_MAP_TYPE_XSKMAP 17

#define XDP_DROP 1
#define XDP_PASS 2
#define XDP_REDIRECT 4

#define TRUSTIX_TIX_TCP_STATS_REDIRECTED 0
#define TRUSTIX_TIX_TCP_STATS_UNAUTHORIZED_DROPS 1
#define TRUSTIX_TIX_TCP_STATS_PASS 2
#define TRUSTIX_TIX_TCP_STATS_PARSE_ERRORS 3
#define TRUSTIX_TIX_TCP_STATS_TCP_CHECKSUM_SKIPPED 11
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
#define TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_CSUM_ERRORS 50

#define TRUSTIX_TIX_TCP_CONFIG_SKIP_TCP_CHECKSUM 1
#define TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_TC_RX_DIRECT 2
#define TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_XDP_RX_DIRECT 32
#define TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_XDP_RX_DIRECT_IFINDEX 64
#define TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_TC_RX_SECURE_DIRECT 128
#define TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_XDP_RX_SECURE_DIRECT 256
#define TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_XDP_RX_DIRECT_FIXED_L2 512
#define TRUSTIX_TIX_TCP_CONFIG_XDP_FALLBACK_PASS 1024
#define TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_XDP_RX_DIRECT_TRUST_INNER_CHECKSUM 2048
#define TRUSTIX_TIX_TCP_CONFIG_HOT_PATH_STATS 16
#define TRUSTIX_TIX_TCP_CONFIG_QUEUE_COUNT_SHIFT 16
#define TRUSTIX_TIX_TCP_CONFIG_QUEUE_COUNT_MASK 0xffff0000U
#define TRUSTIX_KERNEL_UDP_HEADER_LEN 32
#define TRUSTIX_TIX_TCP_HEADER_LEN 40
#define TRUSTIX_TIX_TCP_TCP_HEADER_LEN 20
#define TRUSTIX_XDP_RX_DIRECT_CSUM_CHUNK 512
#define TRUSTIX_XDP_RX_DIRECT_FRAME_MAX 1535
#define TRUSTIX_XDP_RX_DIRECT_FRAME_PADDED 1536
#define TRUSTIX_XDP_TCP_SMALL_CSUM_MAX 96
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define TRUSTIX_TIX_TCP_FLAG_ENCRYPTED 1
#define TRUSTIX_TIX_TCP_FLAG_KERNEL_OPENED 2
#define TRUSTIX_TIX_TCP_FLAG_CRYPTO_FRAGMENT 4
#define TRUSTIX_TIX_TCP_FLAG_INNER_IPV4 8
#define TRUSTIX_XDP_DIRECT_FALLBACK -1

struct trustix_xdp_l4_csum_header {
    __u8 pseudo[12];
};

struct trustix_xdp_csum_tail {
    __u8 bytes[4];
};

struct trustix_xdp_csum_scratch {
    __u8 l4[TRUSTIX_XDP_RX_DIRECT_FRAME_PADDED];
};

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
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct trustix_xdp_csum_scratch);
} ix_kudp_xdp_csum_scratch SEC(".maps");

static void *(*bpf_map_lookup_elem)(const void *map, const void *key) = (void *)1;
static long (*bpf_redirect)(__u32 ifindex, __u64 flags) = (void *)23;
static long (*bpf_redirect_map)(const void *map, __u32 key, __u64 flags) = (void *)51;
#if defined(TRUSTIX_TIX_TCP_XDP_RX_DIRECT_FIX_CHECKSUM) || \
    defined(TRUSTIX_TIX_TCP_XDP_RX_DIRECT_FIX_CONTROL_CHECKSUM)
static long (*bpf_csum_diff)(const void *from, __u32 from_size, const void *to, __u32 to_size, __u32 seed) = (void *)28;
#endif
#ifdef TRUSTIX_TIX_TCP_XDP_RX_DIRECT_FIX_CHECKSUM
static long (*bpf_xdp_load_bytes)(struct xdp_md *ctx, __u32 offset, void *buf, __u32 len) = (void *)189;
#endif
static long (*bpf_xdp_adjust_head)(struct xdp_md *ctx, int delta) = (void *)44;
static long (*bpf_xdp_adjust_tail)(struct xdp_md *ctx, int delta) = (void *)65;

static __always_inline void trustix_tix_tcp_count(__u32 key)
{
    __u64 *value;

    value = bpf_map_lookup_elem(&ix_tix_tcp_stat, &key);
    if (value)
        (*value)++;
}

static __always_inline void trustix_tix_tcp_count_hot_config(__u32 key, __u32 config)
{
    if (config & TRUSTIX_TIX_TCP_CONFIG_HOT_PATH_STATS)
        trustix_tix_tcp_count(key);
}

static __always_inline __u32 trustix_tix_tcp_redirect_queue_config(struct xdp_md *ctx,
                                                                   __u32 config)
{
    __u32 queue_count = (config & TRUSTIX_TIX_TCP_CONFIG_QUEUE_COUNT_MASK) >>
                        TRUSTIX_TIX_TCP_CONFIG_QUEUE_COUNT_SHIFT;

    if (queue_count == 0 || ctx->rx_queue_index < queue_count)
        return ctx->rx_queue_index;

    trustix_tix_tcp_count_hot_config(TRUSTIX_TIX_TCP_STATS_QUEUE_FALLBACK,
                                     config);
    return 0;
}

static __always_inline int trustix_tix_tcp_port_allowed(__u8 *l4)
{
    __u32 dst_key = ((__u32)l4[2]) | ((__u32)l4[3] << 8);
    __u32 src_key = ((__u32)l4[0]) | ((__u32)l4[1] << 8);

    return bpf_map_lookup_elem(&ix_tix_tcp_port, &dst_key) ||
           bpf_map_lookup_elem(&ix_tix_tcp_port, &src_key);
}

static __always_inline int trustix_kernel_udp_unfragmented(__u8 *frame)
{
    return frame[28] == 0 && frame[29] == 0 &&
           frame[30] == 0 && frame[31] == 0;
}

#if defined(TRUSTIX_TIX_TCP_XDP_RX_DIRECT_FIX_CHECKSUM) || \
    defined(TRUSTIX_TIX_TCP_XDP_RX_DIRECT_FIX_CONTROL_CHECKSUM)
static __always_inline __u16 trustix_read_be16(__u8 *src)
{
    return ((__u16)src[0] << 8) | src[1];
}

static __always_inline __u16 trustix_bswap16(__u16 value)
{
    return (value >> 8) | (value << 8);
}

static __always_inline void trustix_write_be16(__u8 *dst, __u16 value)
{
    dst[0] = (__u8)(value >> 8);
    dst[1] = (__u8)value;
}

static __always_inline __u16 trustix_fold_checksum(__u32 sum)
{
#pragma clang loop unroll(full)
    for (int i = 0; i < 4; i++)
        sum = (sum & 0xffff) + (sum >> 16);
    return ~((__u16)sum);
}
#endif

#ifdef TRUSTIX_TIX_TCP_XDP_RX_DIRECT_FIX_CHECKSUM
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
    return 0;
}

#define TRUSTIX_XDP_LOAD_L4_CHUNK(chunk)                                         \
    if (len & (chunk)) {                                                         \
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
    trustix_write_be16(header.pseudo + 10, (__u16)l4_len);

    padded_len = (l4_len + 3) & ~3U;
    if (padded_len > TRUSTIX_XDP_RX_DIRECT_FRAME_PADDED)
        return 0;

    sum = bpf_csum_diff(0, 0, &header, sizeof(header), 0);
    if (sum < 0)
        return 0;
    sum32 = (__u32)sum;
    if (trustix_xdp_add_csum_bytes(l4, padded_len, &sum32))
        return 0;

    checksum = trustix_bswap16(trustix_fold_checksum(sum32));
    if (checksum == 0)
        checksum = 0xffff;
    return checksum;
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
    __u32 padded_len;
    __u16 checksum;

    if (inner_len < 20 || inner_len > TRUSTIX_XDP_RX_DIRECT_FRAME_MAX)
        return -22;
    if (inner[0] != 0x45 || trustix_read_be16(inner + 2) != inner_len)
        return -22;
    if (inner[6] & 0x3f || inner[7])
        return -22;

    l4 = inner + 20;
    l4_len = inner_len - 20;
    if (l4 + l4_len > data_end)
        return -14;
    scratch = bpf_map_lookup_elem(&ix_kudp_xdp_csum_scratch, &scratch_key);
    if (!scratch)
        return -22;
    if (inner[9] == IPPROTO_TCP) {
        if (l4_len < 20)
            return -22;
        if (l4 + 20 > data_end)
            return -14;
        tcp_header_len = (__u32)(l4[12] >> 4) << 2;
        if (tcp_header_len < 20 || tcp_header_len > l4_len)
            return -22;
        if (trustix_xdp_load_l4(ctx, inner_offset + 20, l4_len, scratch))
            return -22;
        scratch->l4[16] = 0;
        scratch->l4[17] = 0;
        padded_len = (l4_len + 3) & ~3U;
        if (padded_len > l4_len) {
#pragma clang loop unroll(full)
            for (int i = 0; i < 3; i++) {
                __u32 offset = l4_len + (__u32)i;
                if (offset >= padded_len)
                    break;
                scratch->l4[offset] = 0;
            }
        }
        checksum = trustix_xdp_l4_checksum(inner, scratch->l4, l4_len, IPPROTO_TCP);
        if (!checksum)
            return -22;
        trustix_write_be16(l4 + 16, checksum);
    } else if (inner[9] == IPPROTO_UDP) {
        if (l4_len < 8)
            return -22;
        if (l4 + 8 > data_end)
            return -14;
        udp_len = trustix_read_be16(l4 + 4);
        if (udp_len < 8 || udp_len > l4_len)
            return -22;
        if (l4[6] == 0 && l4[7] == 0)
            return 0;
        if (trustix_xdp_load_l4(ctx, inner_offset + 20, udp_len, scratch))
            return -22;
        scratch->l4[6] = 0;
        scratch->l4[7] = 0;
        padded_len = (udp_len + 3) & ~3U;
        if (padded_len > udp_len) {
#pragma clang loop unroll(full)
            for (int i = 0; i < 3; i++) {
                __u32 offset = udp_len + (__u32)i;
                if (offset >= padded_len)
                    break;
                scratch->l4[offset] = 0;
            }
        }
        checksum = trustix_xdp_l4_checksum(inner, scratch->l4, udp_len, IPPROTO_UDP);
        if (!checksum)
            return -22;
        trustix_write_be16(l4 + 6, checksum);
    }
    return 0;
}
#endif

#ifdef TRUSTIX_TIX_TCP_XDP_RX_DIRECT_FIX_CONTROL_CHECKSUM
static __noinline int trustix_xdp_add_tcp_control_checksum(__u8 *tcp,
                                                           __u8 *data_end,
                                                           __u32 tcp_len,
                                                           __u32 *sum)
{
    struct trustix_xdp_csum_tail tail = {};
    __s64 next;

    if (!tcp || !sum)
        return -22;
#define TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(n)                  \
    if (tcp_len == (n)) {                                    \
        if (tcp + (n) > data_end)                            \
            return -14;                                      \
        next = bpf_csum_diff(0, 0, tcp, ((n) & ~3), *sum);   \
        if (next < 0)                                        \
            return (int)next;                                \
        *sum = (__u32)next;                                  \
        if (((n) & 3) != 0) {                                \
            tail.bytes[0] = tcp[((n) & ~3)];                 \
            if (((n) & 3) > 1)                               \
                tail.bytes[1] = tcp[((n) & ~3) + 1];         \
            if (((n) & 3) > 2)                               \
                tail.bytes[2] = tcp[((n) & ~3) + 2];         \
            next = bpf_csum_diff(0, 0, &tail, sizeof(tail),  \
                                 *sum);                      \
            if (next < 0)                                    \
                return (int)next;                            \
            *sum = (__u32)next;                              \
        }                                                    \
        return 0;                                            \
    }
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(20);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(21);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(22);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(23);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(24);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(25);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(26);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(27);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(28);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(29);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(30);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(31);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(32);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(33);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(34);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(35);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(36);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(37);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(38);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(39);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(40);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(41);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(42);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(43);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(44);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(45);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(46);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(47);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(48);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(49);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(50);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(51);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(52);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(53);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(54);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(55);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(56);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(57);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(58);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(59);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(60);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(61);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(62);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(63);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(64);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(65);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(66);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(67);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(68);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(69);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(70);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(71);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(72);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(73);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(74);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(75);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(76);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(77);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(78);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(79);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(80);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(81);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(82);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(83);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(84);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(85);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(86);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(87);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(88);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(89);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(90);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(91);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(92);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(93);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(94);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(95);
    TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN(96);
#undef TRUSTIX_XDP_TCP_CONTROL_CSUM_LEN
    return -22;
}

static __noinline __u16 trustix_xdp_tcp_control_checksum(__u8 *ip, __u8 *tcp,
                                                         __u8 *data_end,
                                                         __u32 tcp_len)
{
    struct trustix_xdp_l4_csum_header header = {};
    __s64 sum;
    __u32 sum32;
    __u16 checksum;

    if (tcp_len < 20 || tcp_len > TRUSTIX_XDP_TCP_SMALL_CSUM_MAX)
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
    header.pseudo[9] = IPPROTO_TCP;
    trustix_write_be16(header.pseudo + 10, (__u16)tcp_len);

    sum = bpf_csum_diff(0, 0, &header, sizeof(header), 0);
    if (sum < 0)
        return 0;
    sum32 = (__u32)sum;
    if (trustix_xdp_add_tcp_control_checksum(tcp, data_end, tcp_len, &sum32))
        return 0;
    checksum = trustix_bswap16(trustix_fold_checksum(sum32));
    if (checksum == 0)
        checksum = 0xffff;
    return checksum;
}

static __noinline int trustix_xdp_fix_inner_tcp_control_checksum(__u8 *inner,
                                                                 __u32 inner_len,
                                                                 __u8 *data_end)
{
    __u8 *tcp;
    __u32 tcp_len;
    __u32 tcp_header_len;
    __u16 checksum;

    if (inner_len < 40 || inner_len > TRUSTIX_XDP_RX_DIRECT_FRAME_MAX)
        return -22;
    if (inner[0] != 0x45 || trustix_read_be16(inner + 2) != inner_len)
        return -22;
    if (inner[6] & 0x3f || inner[7])
        return -22;
    if (inner[9] != IPPROTO_TCP)
        return 0;

    tcp = inner + 20;
    tcp_len = inner_len - 20;
    if (tcp + 20 > data_end)
        return -14;
    tcp_header_len = (__u32)(tcp[12] >> 4) << 2;
    if (tcp_header_len < 20 || tcp_header_len > tcp_len)
        return -22;
    if (tcp_len > TRUSTIX_XDP_TCP_SMALL_CSUM_MAX)
        return 0;
    if (tcp + tcp_len > data_end)
        return -14;

    tcp[16] = 0;
    tcp[17] = 0;
    checksum = trustix_xdp_tcp_control_checksum(inner, tcp, data_end, tcp_len);
    if (!checksum)
        return -22;
    trustix_write_be16(tcp + 16, checksum);
    return 0;
}
#endif

static __always_inline int trustix_tix_tcp_unfragmented(__u8 *frame)
{
    return frame[36] == 0 && frame[37] == 0 &&
           frame[38] == 0 && frame[39] == 0;
}

static __always_inline int trustix_kernel_udp_xdp_redirect_lan(
    struct xdp_md *ctx, __u32 inner_offset, __u32 inner_len, __u32 available,
    __u32 destination_mac0, __u16 destination_mac1,
    __u32 source_mac0, __u16 source_mac1,
    __u32 ifindex, __u32 config)
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
    trustix_tix_tcp_count_hot_config(TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_REDIRECTS,
                                     config);
    if ((config & TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_XDP_RX_DIRECT_IFINDEX) && ifindex) {
        trustix_tix_tcp_count_hot_config(TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_IFINDEX_REDIRECTS,
                                         config);
        return bpf_redirect(ifindex, 0);
    }
    trustix_tix_tcp_count_hot_config(TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_DEVMAP_REDIRECTS,
                                     config);
    return bpf_redirect_map(&ix_kudp_rx_devmap, 0, 0);
}

static __always_inline int trustix_kernel_udp_xdp_rx_direct_fix_inner_checksums(
    struct xdp_md *ctx, __u8 *inner, __u32 inner_offset, __u32 inner_len,
    __u8 *data_end, __u32 config_value)
{
#ifdef TRUSTIX_TIX_TCP_XDP_RX_DIRECT_FIX_CONTROL_CHECKSUM
    if (trustix_xdp_fix_inner_tcp_control_checksum(inner, inner_len, data_end)) {
        trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_CSUM_ERRORS);
        return TRUSTIX_XDP_DIRECT_FALLBACK;
    }
#endif
    if (!(config_value & TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_XDP_RX_DIRECT_TRUST_INNER_CHECKSUM)) {
#ifdef TRUSTIX_TIX_TCP_XDP_RX_DIRECT_FIX_CHECKSUM
        if (trustix_xdp_fix_inner_l4_checksum(inner, ctx, inner_offset, inner_len, data_end)) {
            trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_CSUM_ERRORS);
            return TRUSTIX_XDP_DIRECT_FALLBACK;
        }
#else
        trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_CSUM_ERRORS);
        return TRUSTIX_XDP_DIRECT_FALLBACK;
#endif
    }
    return 0;
}

static __always_inline int trustix_kernel_udp_xdp_rx_direct_inner(
    struct xdp_md *ctx, __u32 inner_offset, __u32 config_value)
{
    __u8 *data = (__u8 *)(long)ctx->data;
    __u8 *data_end = (__u8 *)(long)ctx->data_end;
    __u8 *inner = data + inner_offset;
    __u32 inner_len;
    __u32 available;
    __u32 key = 0;
    struct trustix_kudp_rx_neigh_value *neigh;
    struct trustix_kudp_rx_config_value *rx_config;

    trustix_tix_tcp_count_hot_config(TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_CANDIDATES,
                                     config_value);
    if (inner + 20 > data_end)
        goto direct_len_error;
    if (inner[0] != 0x45)
        goto direct_error;
    inner_len = ((__u32)inner[2] << 8) | inner[3];
    available = (__u32)(data_end - inner);
    if (inner_len < 20 || inner_len > available)
        goto direct_len_error;

    if (config_value & TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_XDP_RX_DIRECT_FIXED_L2) {
        __u32 config_key = 0;

        rx_config = bpf_map_lookup_elem(&ix_kudp_rx_config, &config_key);
        if (!rx_config || !rx_config->ifindex) {
            trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_CONFIG_MISSES);
            return TRUSTIX_XDP_DIRECT_FALLBACK;
        }
        trustix_tix_tcp_count_hot_config(TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_BROADCASTS,
                                         config_value);
        if (trustix_kernel_udp_xdp_rx_direct_fix_inner_checksums(ctx, inner, inner_offset, inner_len,
                                                                 data_end, config_value))
            return TRUSTIX_XDP_DIRECT_FALLBACK;
        return trustix_kernel_udp_xdp_redirect_lan(
            ctx, inner_offset, inner_len, available,
            rx_config->destination_mac0, rx_config->destination_mac1,
            rx_config->source_mac0, rx_config->source_mac1, rx_config->ifindex,
            config_value);
    }

    key = ((__u32)inner[16]) | ((__u32)inner[17] << 8) |
          ((__u32)inner[18] << 16) | ((__u32)inner[19] << 24);
    neigh = bpf_map_lookup_elem(&ix_kudp_rx_neigh, &key);
    if (!neigh) {
        trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_NEIGH_MISSES);
        return TRUSTIX_XDP_DIRECT_FALLBACK;
    }

    trustix_tix_tcp_count_hot_config(TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_NEIGH_HITS,
                                     config_value);
    if (trustix_kernel_udp_xdp_rx_direct_fix_inner_checksums(ctx, inner, inner_offset, inner_len,
                                                             data_end, config_value))
        return TRUSTIX_XDP_DIRECT_FALLBACK;
    return trustix_kernel_udp_xdp_redirect_lan(
        ctx, inner_offset, inner_len, available,
        neigh->destination_mac0, neigh->destination_mac1,
        neigh->source_mac0, neigh->source_mac1, neigh->ifindex,
        config_value);

direct_len_error:
    trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_LEN_ERRORS);
    return TRUSTIX_XDP_DIRECT_FALLBACK;
direct_error:
    trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_ERRORS);
    return TRUSTIX_XDP_DIRECT_FALLBACK;
}

SEC("xdp")
int trustix_tix_tcp(struct xdp_md *ctx)
{
    __u8 *data = (__u8 *)(long)ctx->data;
    __u8 *data_end = (__u8 *)(long)ctx->data_end;
    __u32 config_key = 0;
    __u32 config_value = 0;
    __u32 *config;
    __u32 frame_payload_len;
    __u32 frame_end_offset;
    __u32 packet_len;
    int direct_action;

    if (data + 14 > data_end)
        goto parse_error;
    packet_len = (__u32)(data_end - data);

    if (data[12] != 0x08 || data[13] != 0x00)
        goto pass;

    if (data + 34 > data_end)
        goto parse_error;

    if (data[14] != 0x45)
        goto pass;
    if (data[23] == 6)
        goto tcp;
    if (data[23] == 17)
        goto udp;
    goto pass;

tcp:
    if (data + 54 > data_end)
        goto parse_error;

    if (data[46] != 0x50)
        goto pass;
    if (data + 58 > data_end)
        goto pass;
    if (data[54] != 'T' || data[55] != 'I' ||
        data[56] != 'X' || data[57] != 'T')
        goto pass;
    config = bpf_map_lookup_elem(&ix_tix_tcp_config, &config_key);
    if (config)
        config_value = *config;
    if (config_value & TRUSTIX_TIX_TCP_CONFIG_SKIP_TCP_CHECKSUM)
        trustix_tix_tcp_count_hot_config(TRUSTIX_TIX_TCP_STATS_TCP_CHECKSUM_SKIPPED,
                                         config_value);
    if (!trustix_tix_tcp_port_allowed(data + 34))
        goto drop;
    if (data + 94 <= data_end &&
        (data[59] & TRUSTIX_TIX_TCP_FLAG_ENCRYPTED) &&
        (data[59] & TRUSTIX_TIX_TCP_FLAG_INNER_IPV4) &&
        !(data[59] & TRUSTIX_TIX_TCP_FLAG_CRYPTO_FRAGMENT) &&
        trustix_tix_tcp_unfragmented(data + 54) &&
        (config_value & TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_TC_RX_SECURE_DIRECT)) {
        trustix_tix_tcp_count_hot_config(TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_TC_RX_DIRECT_PASS,
                                         config_value);
        goto pass;
    }
    if (data + 94 <= data_end &&
        (data[59] == TRUSTIX_TIX_TCP_FLAG_INNER_IPV4 ||
         data[59] == (TRUSTIX_TIX_TCP_FLAG_KERNEL_OPENED | TRUSTIX_TIX_TCP_FLAG_INNER_IPV4)) &&
        data[90] == 0 && data[91] == 0 && data[92] == 0 && data[93] == 0) {
        trustix_tix_tcp_count_hot_config(TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_PLAINTEXT_CANDIDATES,
                                         config_value);
        frame_payload_len = ((__u32)data[86] << 24) |
                            ((__u32)data[87] << 16) |
                            ((__u32)data[88] << 8) |
                            data[89];
        frame_end_offset = 0;
        if (frame_payload_len <= 0xffff - 94)
            frame_end_offset = 94 + frame_payload_len;
        if (frame_end_offset == packet_len &&
            data + 114 <= data_end && data[94] == 0x45 &&
            trustix_tix_tcp_unfragmented(data + 54)) {
            if (config_value & TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_XDP_RX_DIRECT) {
                direct_action = trustix_kernel_udp_xdp_rx_direct_inner(ctx, 94, config_value);
                if (direct_action >= 0)
                    return direct_action;
                goto redirect;
            }
            if (config_value & TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_TC_RX_DIRECT) {
                trustix_tix_tcp_count_hot_config(TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_TC_RX_DIRECT_PASS,
                                                 config_value);
                goto pass;
            }
        }
        if (frame_end_offset != 0 &&
            frame_end_offset < packet_len &&
            packet_len - frame_end_offset >= TRUSTIX_TIX_TCP_HEADER_LEN &&
            data + 114 <= data_end && data[94] == 0x45 &&
            trustix_tix_tcp_unfragmented(data + 54) &&
            (config_value & TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_TC_RX_DIRECT)) {
            trustix_tix_tcp_count_hot_config(TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_TC_RX_DIRECT_PASS,
                                             config_value);
            goto pass;
        }
        if (data + 108 <= data_end && data[88] == 0x45)
            trustix_tix_tcp_count_hot_config(TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_INNER_IPV4_AT88,
                                             config_value);
        trustix_tix_tcp_count_hot_config(TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_INNER_IPV4_MISSES,
                                         config_value);
    }
    goto redirect;

udp:
    if (data + 42 > data_end)
        goto parse_error;

    if (data + 46 > data_end)
        goto pass;
    if (data[42] != 'T' || data[43] != 'I' ||
        data[44] != 'X' || data[45] != 'U')
        goto pass;

    config = bpf_map_lookup_elem(&ix_tix_tcp_config, &config_key);
    if (config)
        config_value = *config;
    if (!trustix_tix_tcp_port_allowed(data + 34))
        goto drop;
    if (data + 74 <= data_end &&
        (data[47] & TRUSTIX_TIX_TCP_FLAG_ENCRYPTED) &&
        (data[47] & TRUSTIX_TIX_TCP_FLAG_INNER_IPV4) &&
        !(data[47] & TRUSTIX_TIX_TCP_FLAG_CRYPTO_FRAGMENT) &&
        trustix_kernel_udp_unfragmented(data + 42) &&
        (config_value & TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_TC_RX_SECURE_DIRECT)) {
        trustix_tix_tcp_count_hot_config(TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_TC_RX_DIRECT_PASS,
                                         config_value);
        goto pass;
    }
    if (data + 74 <= data_end &&
        (data[47] == TRUSTIX_TIX_TCP_FLAG_INNER_IPV4 ||
         data[47] == (TRUSTIX_TIX_TCP_FLAG_KERNEL_OPENED | TRUSTIX_TIX_TCP_FLAG_INNER_IPV4)) &&
        data[70] == 0 && data[71] == 0 && data[72] == 0 && data[73] == 0) {
        trustix_tix_tcp_count_hot_config(TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_PLAINTEXT_CANDIDATES,
                                         config_value);
        if (data + 94 <= data_end && data[74] == 0x45 &&
            trustix_kernel_udp_unfragmented(data + 42)) {
            if (config_value & TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_XDP_RX_DIRECT) {
                direct_action = trustix_kernel_udp_xdp_rx_direct_inner(ctx, 74, config_value);
                if (direct_action >= 0)
                    return direct_action;
                goto redirect;
            }
            if (config_value & TRUSTIX_TIX_TCP_CONFIG_KERNEL_UDP_TC_RX_DIRECT) {
                trustix_tix_tcp_count_hot_config(TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_TC_RX_DIRECT_PASS,
                                                 config_value);
                goto pass;
            }
        }
        if (data + 108 <= data_end && data[88] == 0x45)
            trustix_tix_tcp_count_hot_config(TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_INNER_IPV4_AT88,
                                             config_value);
        trustix_tix_tcp_count_hot_config(TRUSTIX_TIX_TCP_STATS_KERNEL_UDP_INNER_IPV4_MISSES,
                                         config_value);
    }

redirect:
    if (config_value & TRUSTIX_TIX_TCP_CONFIG_XDP_FALLBACK_PASS)
        goto pass;
    trustix_tix_tcp_count_hot_config(TRUSTIX_TIX_TCP_STATS_REDIRECTED,
                                     config_value);
    return bpf_redirect_map(&ix_tix_tcp_xsk,
                            trustix_tix_tcp_redirect_queue_config(ctx, config_value),
                            XDP_DROP);

drop:
    trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_UNAUTHORIZED_DROPS);
    return XDP_DROP;

pass:
    if (config_value & TRUSTIX_TIX_TCP_CONFIG_HOT_PATH_STATS)
        trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_PASS);
    return XDP_PASS;

parse_error:
    trustix_tix_tcp_count(TRUSTIX_TIX_TCP_STATS_PARSE_ERRORS);
    return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
