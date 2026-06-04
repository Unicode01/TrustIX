// SPDX-License-Identifier: GPL-2.0 OR MIT
// Lightweight standalone XDP classifier for kernel_udp plaintext RX direct.
// This object is intentionally separate from the full experimental_tcp XDP
// program so TC-only kernel_udp can attach an underlay XDP decap program
// without pulling in AF_XDP, TCP-shaped TIXT, or kernel-crypto branches.
#define SEC(NAME) __attribute__((section(NAME), used))
#define __always_inline inline __attribute__((always_inline))
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

#define TRUSTIX_KERNEL_UDP_HEADER_LEN 32
#define TRUSTIX_XDP_RX_DIRECT_CSUM_CHUNK 512
#define TRUSTIX_XDP_RX_DIRECT_FRAME_MAX 1535
#define TRUSTIX_XDP_RX_DIRECT_FRAME_PADDED 1536
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define TRUSTIX_EXP_TCP_FLAG_KERNEL_OPENED 2
#define TRUSTIX_EXP_TCP_FLAG_INNER_IPV4 8
#define TRUSTIX_XDP_DIRECT_FALLBACK -1

#define TRUSTIX_EXP_TCP_CONFIG_KERNEL_UDP_XDP_RX_DIRECT 32
#define TRUSTIX_EXP_TCP_CONFIG_KERNEL_UDP_XDP_RX_DIRECT_IFINDEX 64
#define TRUSTIX_EXP_TCP_CONFIG_KERNEL_UDP_XDP_RX_DIRECT_FIXED_L2 512
#define TRUSTIX_EXP_TCP_CONFIG_XDP_FALLBACK_PASS 1024
#define TRUSTIX_EXP_TCP_CONFIG_KERNEL_UDP_XDP_RX_DIRECT_TRUST_INNER_CHECKSUM 2048
#define TRUSTIX_EXP_TCP_CONFIG_HOT_PATH_STATS 16

#define TRUSTIX_EXP_TCP_STATS_UNAUTHORIZED_DROPS 1
#define TRUSTIX_EXP_TCP_STATS_PASS 2
#define TRUSTIX_EXP_TCP_STATS_PARSE_ERRORS 3
#define TRUSTIX_EXP_TCP_STATS_KERNEL_UDP_PLAINTEXT_CANDIDATES 15
#define TRUSTIX_EXP_TCP_STATS_KERNEL_UDP_INNER_IPV4_MISSES 16
#define TRUSTIX_EXP_TCP_STATS_KERNEL_UDP_INNER_IPV4_AT88 17
#define TRUSTIX_EXP_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_REDIRECTS 18
#define TRUSTIX_EXP_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_NEIGH_MISSES 19
#define TRUSTIX_EXP_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_ERRORS 20
#define TRUSTIX_EXP_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_CANDIDATES 21
#define TRUSTIX_EXP_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_NEIGH_HITS 22
#define TRUSTIX_EXP_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_BROADCASTS 23
#define TRUSTIX_EXP_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_ADJUST_HEAD_ERRORS 24
#define TRUSTIX_EXP_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_TAIL_ERRORS 25
#define TRUSTIX_EXP_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_POST_ADJUST_ERRORS 26
#define TRUSTIX_EXP_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_LEN_ERRORS 27
#define TRUSTIX_EXP_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_IFINDEX_REDIRECTS 28
#define TRUSTIX_EXP_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_DEVMAP_REDIRECTS 29
#define TRUSTIX_EXP_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_CONFIG_MISSES 30
#define TRUSTIX_EXP_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_CSUM_ERRORS 50

struct trustix_xdp_l4_csum_header {
    __u8 pseudo[12];
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
} ix_exp_tcp_xsk SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u8);
} ix_exp_tcp_port SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 51);
    __type(key, __u32);
    __type(value, __u64);
} ix_exp_tcp_stat SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} ix_exp_tcp_config SEC(".maps");

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
static long (*bpf_csum_diff)(const void *from, __u32 from_size, const void *to, __u32 to_size, __u32 seed) = (void *)28;
static long (*bpf_xdp_adjust_head)(struct xdp_md *ctx, int delta) = (void *)44;
static long (*bpf_xdp_adjust_tail)(struct xdp_md *ctx, int delta) = (void *)65;
static long (*bpf_xdp_load_bytes)(struct xdp_md *ctx, __u32 offset, void *buf, __u32 len) = (void *)189;

static __always_inline void trustix_exp_tcp_count(__u32 key)
{
    __u64 *value = bpf_map_lookup_elem(&ix_exp_tcp_stat, &key);

    if (value)
        (*value)++;
}

static __always_inline void trustix_exp_tcp_count_hot_config(__u32 key, __u32 config)
{
    if (config & TRUSTIX_EXP_TCP_CONFIG_HOT_PATH_STATS)
        trustix_exp_tcp_count(key);
}

static __always_inline __u16 trustix_read_be16(__u8 *src)
{
    return ((__u16)src[0] << 8) | src[1];
}

static __always_inline void trustix_write_be16(__u8 *dst, __u16 value)
{
    dst[0] = (__u8)(value >> 8);
    dst[1] = (__u8)value;
}

static __always_inline __u16 trustix_bswap16(__u16 value)
{
    return (value >> 8) | (value << 8);
}

static __always_inline __u16 trustix_fold_checksum(__u32 sum)
{
#pragma clang loop unroll(full)
    for (int i = 0; i < 4; i++)
        sum = (sum & 0xffff) + (sum >> 16);
    return ~((__u16)sum);
}

static __always_inline int trustix_exp_tcp_port_allowed(__u8 *l4)
{
    __u32 dst_key = ((__u32)l4[2]) | ((__u32)l4[3] << 8);
    __u32 src_key = ((__u32)l4[0]) | ((__u32)l4[1] << 8);

    return bpf_map_lookup_elem(&ix_exp_tcp_port, &dst_key) ||
           bpf_map_lookup_elem(&ix_exp_tcp_port, &src_key);
}

static __always_inline int trustix_kernel_udp_unfragmented(__u8 *frame)
{
    return frame[28] == 0 && frame[29] == 0 &&
           frame[30] == 0 && frame[31] == 0;
}

static __always_inline void trustix_write_mac(__u8 *dst, __u32 mac0, __u16 mac1)
{
    dst[0] = (__u8)mac0;
    dst[1] = (__u8)(mac0 >> 8);
    dst[2] = (__u8)(mac0 >> 16);
    dst[3] = (__u8)(mac0 >> 24);
    dst[4] = (__u8)mac1;
    dst[5] = (__u8)(mac1 >> 8);
}

static __attribute__((noinline)) int trustix_xdp_add_csum_chunk(__u8 *data, __u32 len, __u32 *sum)
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

static __attribute__((noinline)) int trustix_xdp_add_csum_bytes(__u8 *data, __u32 len, __u32 *sum)
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

#define TRUSTIX_XDP_LOAD_L4_CHUNK(chunk)                                      \
    if (len & (chunk)) {                                                      \
        if (copied > TRUSTIX_XDP_RX_DIRECT_FRAME_PADDED - (chunk))            \
            return -22;                                                       \
        if (bpf_xdp_load_bytes(ctx, packet_offset + copied,                   \
                               scratch->l4 + copied, (chunk)))               \
            return -14;                                                       \
        copied += (chunk);                                                    \
    }

static __attribute__((noinline)) int trustix_xdp_load_l4(struct xdp_md *ctx,
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

static __attribute__((noinline)) __u16 trustix_xdp_l4_checksum(__u8 *ip, __u8 *l4,
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

static __attribute__((noinline)) int trustix_xdp_fix_inner_l4_checksum(__u8 *inner,
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
        trustix_exp_tcp_count(TRUSTIX_EXP_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_TAIL_ERRORS);
        return XDP_PASS;
    }
    if (bpf_xdp_adjust_head(ctx, delta)) {
        trustix_exp_tcp_count(TRUSTIX_EXP_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_ADJUST_HEAD_ERRORS);
        return XDP_PASS;
    }
    data = (__u8 *)(long)ctx->data;
    data_end = (__u8 *)(long)ctx->data_end;
    if (data + 14 > data_end) {
        trustix_exp_tcp_count(TRUSTIX_EXP_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_POST_ADJUST_ERRORS);
        return XDP_PASS;
    }

    trustix_write_mac(data, destination_mac0, destination_mac1);
    trustix_write_mac(data + 6, source_mac0, source_mac1);
    data[12] = 0x08;
    data[13] = 0x00;

    trustix_exp_tcp_count_hot_config(TRUSTIX_EXP_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_REDIRECTS,
                                     config);
    if ((config & TRUSTIX_EXP_TCP_CONFIG_KERNEL_UDP_XDP_RX_DIRECT_IFINDEX) && ifindex) {
        trustix_exp_tcp_count_hot_config(TRUSTIX_EXP_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_IFINDEX_REDIRECTS,
                                         config);
        return bpf_redirect(ifindex, 0);
    }

    trustix_exp_tcp_count_hot_config(TRUSTIX_EXP_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_DEVMAP_REDIRECTS,
                                     config);
    return bpf_redirect_map(&ix_kudp_rx_devmap, 0, 0);
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

    trustix_exp_tcp_count_hot_config(TRUSTIX_EXP_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_CANDIDATES,
                                     config_value);
    if (inner + 20 > data_end)
        goto direct_len_error;
    if (inner[0] != 0x45)
        goto direct_error;

    inner_len = trustix_read_be16(inner + 2);
    available = (__u32)(data_end - inner);
    if (inner_len < 20 || inner_len > available)
        goto direct_len_error;
    if (!(config_value & TRUSTIX_EXP_TCP_CONFIG_KERNEL_UDP_XDP_RX_DIRECT_TRUST_INNER_CHECKSUM) &&
        trustix_xdp_fix_inner_l4_checksum(inner, ctx, inner_offset, inner_len, data_end)) {
        trustix_exp_tcp_count(TRUSTIX_EXP_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_CSUM_ERRORS);
        return TRUSTIX_XDP_DIRECT_FALLBACK;
    }

    if (config_value & TRUSTIX_EXP_TCP_CONFIG_KERNEL_UDP_XDP_RX_DIRECT_FIXED_L2) {
        __u32 config_key = 0;

        rx_config = bpf_map_lookup_elem(&ix_kudp_rx_config, &config_key);
        if (!rx_config || !rx_config->ifindex) {
            trustix_exp_tcp_count(TRUSTIX_EXP_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_CONFIG_MISSES);
            return TRUSTIX_XDP_DIRECT_FALLBACK;
        }
        trustix_exp_tcp_count_hot_config(TRUSTIX_EXP_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_BROADCASTS,
                                         config_value);
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
        trustix_exp_tcp_count(TRUSTIX_EXP_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_NEIGH_MISSES);
        return TRUSTIX_XDP_DIRECT_FALLBACK;
    }

    trustix_exp_tcp_count_hot_config(TRUSTIX_EXP_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_NEIGH_HITS,
                                     config_value);
    return trustix_kernel_udp_xdp_redirect_lan(
        ctx, inner_offset, inner_len, available,
        neigh->destination_mac0, neigh->destination_mac1,
        neigh->source_mac0, neigh->source_mac1, neigh->ifindex,
        config_value);

direct_len_error:
    trustix_exp_tcp_count(TRUSTIX_EXP_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_LEN_ERRORS);
    return TRUSTIX_XDP_DIRECT_FALLBACK;
direct_error:
    trustix_exp_tcp_count(TRUSTIX_EXP_TCP_STATS_KERNEL_UDP_XDP_RX_DIRECT_ERRORS);
    return TRUSTIX_XDP_DIRECT_FALLBACK;
}

SEC("xdp")
int trustix_exp_tcp(struct xdp_md *ctx)
{
    __u8 *data = (__u8 *)(long)ctx->data;
    __u8 *data_end = (__u8 *)(long)ctx->data_end;
    __u32 config_key = 0;
    __u32 config_value = 0;
    __u32 *config;
    int direct_action;

    if (data + 14 > data_end)
        goto parse_error;
    if (data[12] != 0x08 || data[13] != 0x00)
        goto pass;

    if (data + 46 > data_end)
        goto parse_error;
    if (data[14] != 0x45 || data[23] != IPPROTO_UDP)
        goto pass;
    if (data[42] != 'T' || data[43] != 'I' ||
        data[44] != 'X' || data[45] != 'U')
        goto pass;

    config = bpf_map_lookup_elem(&ix_exp_tcp_config, &config_key);
    if (config)
        config_value = *config;

    if (!trustix_exp_tcp_port_allowed(data + 34))
        goto drop;
    if (!(config_value & TRUSTIX_EXP_TCP_CONFIG_KERNEL_UDP_XDP_RX_DIRECT))
        goto pass;
    if (data + 74 <= data_end &&
        (data[47] == TRUSTIX_EXP_TCP_FLAG_INNER_IPV4 ||
         data[47] == (TRUSTIX_EXP_TCP_FLAG_KERNEL_OPENED | TRUSTIX_EXP_TCP_FLAG_INNER_IPV4)) &&
        trustix_kernel_udp_unfragmented(data + 42)) {
        trustix_exp_tcp_count_hot_config(TRUSTIX_EXP_TCP_STATS_KERNEL_UDP_PLAINTEXT_CANDIDATES,
                                         config_value);
        if (data + 94 <= data_end && data[74] == 0x45) {
            direct_action = trustix_kernel_udp_xdp_rx_direct_inner(ctx, 74, config_value);
            if (direct_action >= 0)
                return direct_action;
        }
        trustix_exp_tcp_count_hot_config(TRUSTIX_EXP_TCP_STATS_KERNEL_UDP_INNER_IPV4_MISSES,
                                         config_value);
    }

pass:
    if (config_value & TRUSTIX_EXP_TCP_CONFIG_HOT_PATH_STATS)
        trustix_exp_tcp_count(TRUSTIX_EXP_TCP_STATS_PASS);
    return XDP_PASS;

drop:
    trustix_exp_tcp_count(TRUSTIX_EXP_TCP_STATS_UNAUTHORIZED_DROPS);
    return XDP_DROP;

parse_error:
    trustix_exp_tcp_count(TRUSTIX_EXP_TCP_STATS_PARSE_ERRORS);
    return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
