// SPDX-License-Identifier: GPL-2.0 OR MIT
// BPF_PROG_RUN-compatible XDP program for experimental_tcp TX kernel seal.
// It parses an Ethernet/IPv4/TCP/TIXT plaintext packet, seals the TIXT
// payload with provider-owned AEAD ctx slots, grows the packet by the secure
// envelope overhead, and refreshes IPv4/TCP checksums.
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
#define BPF_MAP_TYPE_PERCPU_ARRAY 6

#define XDP_DROP 1
#define XDP_PASS 2

#define TRUSTIX_EXP_TCP_TX_STATS_ATTEMPTS 0
#define TRUSTIX_EXP_TCP_TX_STATS_SUCCESSES 1
#define TRUSTIX_EXP_TCP_TX_STATS_ERRORS 2
#define TRUSTIX_EXP_TCP_TX_STATS_NO_CONTEXT_ERRORS 3
#define TRUSTIX_EXP_TCP_TX_STATS_HEADER_ERRORS 4
#define TRUSTIX_EXP_TCP_TX_STATS_ENCRYPT_ERRORS 5
#define TRUSTIX_EXP_TCP_TX_STATS_SEQUENCE_ERRORS 6
#define TRUSTIX_EXP_TCP_TX_STATS_TCP_CHECKSUM_SKIPPED 7

#define TRUSTIX_KERNEL_CRYPTO_MAX_ENTRIES 4096
#define TRUSTIX_KERNEL_CRYPTO_FRAME_MAX 4095
#define TRUSTIX_KERNEL_CRYPTO_FRAME_PADDED 4096
#define TRUSTIX_KERNEL_CRYPTO_FRAME_TAG_LEN 16
#define TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN 24
#define TRUSTIX_KERNEL_CRYPTO_DIRECTION_SEND 1
#define TRUSTIX_EXP_TCP_HEADER_LEN 40
#define TRUSTIX_EXP_TCP_TCP_HEADER_LEN 20
#define TRUSTIX_EXP_TCP_TCP_CSUM_HEADER_LEN (12 + TRUSTIX_EXP_TCP_TCP_HEADER_LEN + TRUSTIX_EXP_TCP_HEADER_LEN + TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN)
#define TRUSTIX_EXP_TCP_CSUM_CHUNK 512
#define TRUSTIX_EXP_TCP_OVERHEAD (TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN + TRUSTIX_KERNEL_CRYPTO_FRAME_TAG_LEN)
#define TRUSTIX_EXP_TCP_FLAG_ENCRYPTED 1
#define TRUSTIX_EXP_TCP_FLAG_KERNEL_OPENED 2
#define TRUSTIX_EXP_TCP_CONFIG_SKIP_TCP_CHECKSUM 1
#define TRUSTIX_KERNEL_CRYPTO_FLOW_FLAG_HOT_STATS 1
#define TRUSTIX_KERNEL_CRYPTO_FLOW_FLAG_NO_REPLAY 2
#define TRUSTIX_KERNEL_CRYPTO_REPLAY_WORDS 1024

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

struct trustix_exp_tcp_tx_scratch {
    __u8 plain[TRUSTIX_KERNEL_CRYPTO_FRAME_PADDED];
    __u8 cipher[TRUSTIX_KERNEL_CRYPTO_FRAME_PADDED];
    __u8 nonce[12];
    __u16 suite;
    __u32 hot_stats;
};

struct trustix_exp_tcp_tx_csum_header {
    __u8 pseudo[12];
    __u8 tcp[TRUSTIX_EXP_TCP_TCP_HEADER_LEN];
    __u8 frame[TRUSTIX_EXP_TCP_HEADER_LEN];
    __u8 secure[TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN];
};

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
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct trustix_exp_tcp_tx_scratch);
} ix_exp_tcp_tx_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} ix_exp_tcp_tx_stat SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} ix_exp_tcp_tx_config SEC(".maps");

static void *(*bpf_map_lookup_elem)(const void *map, const void *key) = (void *)1;
static long (*bpf_csum_diff)(const void *from, __u32 from_size, const void *to, __u32 to_size, __u32 seed) = (void *)28;
static long (*bpf_xdp_adjust_tail)(struct xdp_md *ctx, int delta) = (void *)65;
static long (*bpf_xdp_load_bytes)(struct xdp_md *ctx, __u32 offset, void *buf, __u32 len) = (void *)189;
static long (*bpf_xdp_store_bytes)(struct xdp_md *ctx, __u32 offset, void *buf, __u32 len) = (void *)190;
static long (*bpf_dynptr_from_mem)(void *data, __u32 size, __u64 flags, struct bpf_dynptr *ptr) = (void *)197;

extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;
extern int bpf_crypto_encrypt(struct bpf_crypto_ctx *ctx, const struct bpf_dynptr *src, const struct bpf_dynptr *dst, const struct bpf_dynptr *siv__nullable) __ksym;

static __always_inline void trustix_exp_tcp_tx_count(__u32 key)
{
    __u64 *value = bpf_map_lookup_elem(&ix_exp_tcp_tx_stat, &key);
    if (value)
        (*value)++;
}

static __always_inline int trustix_exp_tcp_tx_skip_tcp_checksum(void)
{
    __u32 key = 0;
    __u32 *config = bpf_map_lookup_elem(&ix_exp_tcp_tx_config, &key);

    return config && (*config & TRUSTIX_EXP_TCP_CONFIG_SKIP_TCP_CHECKSUM);
}

static __always_inline int trustix_kernel_crypto_hot_stats(const struct trustix_kernel_crypto_ctx_value *state)
{
    return state && (state->flags & TRUSTIX_KERNEL_CRYPTO_FLOW_FLAG_HOT_STATS);
}

static __always_inline int trustix_kernel_crypto_no_replay(const struct trustix_kernel_crypto_ctx_value *state)
{
    return state && (state->flags & TRUSTIX_KERNEL_CRYPTO_FLOW_FLAG_NO_REPLAY);
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

static __always_inline void trustix_prepare_nonce(__u8 *nonce,
                                                 const struct trustix_kernel_crypto_ctx_value *state,
                                                 __u64 sequence)
{
#pragma clang loop unroll(full)
    for (int i = 0; i < 12; i++)
        nonce[i] = state->iv[i];

    nonce[4] = (__u8)(sequence >> 56);
    nonce[5] = (__u8)(sequence >> 48);
    nonce[6] = (__u8)(sequence >> 40);
    nonce[7] = (__u8)(sequence >> 32);
    nonce[8] = (__u8)(sequence >> 24);
    nonce[9] = (__u8)(sequence >> 16);
    nonce[10] = (__u8)(sequence >> 8);
    nonce[11] = (__u8)sequence;
}

static __always_inline void trustix_write_secure_header(__u8 *secure,
                                                       __u64 epoch,
                                                       __u64 sequence,
                                                       __u16 suite)
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

static __always_inline int trustix_send_check(const struct trustix_kernel_crypto_ctx_value *state,
                                              __u64 sequence)
{
    if (trustix_kernel_crypto_no_replay(state))
        return sequence == 0 ? -22 : 0;
    if (sequence == 0)
        return -22;
    if (sequence <= state->last_sequence)
        return -114;
    return 0;
}

static __always_inline void trustix_send_mark(struct trustix_kernel_crypto_ctx_value *state,
                                              __u64 sequence)
{
    __u64 block = sequence >> 6;
    __u32 slot = (__u32)block & (TRUSTIX_KERNEL_CRYPTO_REPLAY_WORDS - 1);
    __u32 bit = (__u32)sequence & 63;

    if (state->replay_blocks[slot] != block) {
        state->replay_blocks[slot] = block;
        state->replay_seen[slot] = 0;
    }
    state->replay_seen[slot] |= ((__u64)1) << bit;
}

static __always_inline int trustix_send_commit(struct trustix_kernel_crypto_ctx_value *state,
                                               __u64 sequence)
{
    if (trustix_kernel_crypto_no_replay(state))
        return sequence == 0 ? -22 : 0;
    if (sequence == 0)
        return -22;
    if (sequence <= state->last_sequence)
        return -114;
    state->last_sequence = sequence;
    trustix_send_mark(state, sequence);
    return 0;
}

static __always_inline __u16 trustix_fold_checksum(__u32 sum)
{
#pragma clang loop unroll(full)
    for (int i = 0; i < 4; i++)
        sum = (sum & 0xffff) + (sum >> 16);
    return ~((__u16)sum);
}

#define TRUSTIX_XDP_LOAD_PLAIN_CHUNK(chunk)                                      \
    if (len & (chunk)) {                                                         \
        if (copied > TRUSTIX_KERNEL_CRYPTO_FRAME_PADDED - (chunk))                     \
            return -22;                                                          \
        if (bpf_xdp_load_bytes(ctx, packet_offset + copied,                      \
                               scratch->plain + copied, (chunk)))                \
            return -14;                                                          \
        copied += (chunk);                                                       \
    }

static __noinline int trustix_xdp_load_plain(struct xdp_md *ctx,
                                             __u32 packet_offset, __u32 len,
                                             struct trustix_exp_tcp_tx_scratch *scratch)
{
    __u32 copied = 0;

    if (!scratch || len < 1 ||
        len > TRUSTIX_KERNEL_CRYPTO_FRAME_MAX - TRUSTIX_KERNEL_CRYPTO_FRAME_TAG_LEN)
        return -22;
    TRUSTIX_XDP_LOAD_PLAIN_CHUNK(2048);
    TRUSTIX_XDP_LOAD_PLAIN_CHUNK(1024);
    TRUSTIX_XDP_LOAD_PLAIN_CHUNK(512);
    TRUSTIX_XDP_LOAD_PLAIN_CHUNK(256);
    TRUSTIX_XDP_LOAD_PLAIN_CHUNK(128);
    TRUSTIX_XDP_LOAD_PLAIN_CHUNK(64);
    TRUSTIX_XDP_LOAD_PLAIN_CHUNK(32);
    TRUSTIX_XDP_LOAD_PLAIN_CHUNK(16);
    TRUSTIX_XDP_LOAD_PLAIN_CHUNK(8);
    TRUSTIX_XDP_LOAD_PLAIN_CHUNK(4);
    TRUSTIX_XDP_LOAD_PLAIN_CHUNK(2);
    TRUSTIX_XDP_LOAD_PLAIN_CHUNK(1);
    return copied == len ? 0 : -22;
}

#undef TRUSTIX_XDP_LOAD_PLAIN_CHUNK

#define TRUSTIX_XDP_STORE_CIPHER_CHUNK(chunk)                                    \
    if (len & (chunk)) {                                                         \
        if (copied > TRUSTIX_KERNEL_CRYPTO_FRAME_PADDED - (chunk))                     \
            return -22;                                                          \
        if (bpf_xdp_store_bytes(ctx, packet_offset + copied,                     \
                                scratch->cipher + copied, (chunk)))              \
            return -14;                                                          \
        copied += (chunk);                                                       \
    }

static __noinline int trustix_xdp_store_cipher(struct xdp_md *ctx,
                                               __u32 packet_offset, __u32 len,
                                               struct trustix_exp_tcp_tx_scratch *scratch)
{
    __u32 copied = 0;

    if (!scratch || len < TRUSTIX_KERNEL_CRYPTO_FRAME_TAG_LEN ||
        len > TRUSTIX_KERNEL_CRYPTO_FRAME_MAX)
        return -22;
    TRUSTIX_XDP_STORE_CIPHER_CHUNK(2048);
    TRUSTIX_XDP_STORE_CIPHER_CHUNK(1024);
    TRUSTIX_XDP_STORE_CIPHER_CHUNK(512);
    TRUSTIX_XDP_STORE_CIPHER_CHUNK(256);
    TRUSTIX_XDP_STORE_CIPHER_CHUNK(128);
    TRUSTIX_XDP_STORE_CIPHER_CHUNK(64);
    TRUSTIX_XDP_STORE_CIPHER_CHUNK(32);
    TRUSTIX_XDP_STORE_CIPHER_CHUNK(16);
    TRUSTIX_XDP_STORE_CIPHER_CHUNK(8);
    TRUSTIX_XDP_STORE_CIPHER_CHUNK(4);
    TRUSTIX_XDP_STORE_CIPHER_CHUNK(2);
    TRUSTIX_XDP_STORE_CIPHER_CHUNK(1);
    return copied == len ? 0 : -22;
}

#undef TRUSTIX_XDP_STORE_CIPHER_CHUNK

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

    if (len == 0)
        return 0;
    len &= 0x7fffffffU;
    if (len > TRUSTIX_EXP_TCP_CSUM_CHUNK)
        return -22;
    if (len & 3)
        return -22;
    next = bpf_csum_diff(0, 0, data, len, *sum);
    if (next < 0)
        return (int)next;
    *sum = (__u32)next;
    return 0;
}

static __noinline int trustix_fix_tcp_checksum(__u8 *ip, __u8 *tcp,
                                               __u8 *data_end,
                                               struct trustix_exp_tcp_tx_scratch *scratch,
                                               __u32 cipher_len)
{
    struct trustix_exp_tcp_tx_csum_header header = {};
    __u8 *frame = tcp + TRUSTIX_EXP_TCP_TCP_HEADER_LEN;
    __u8 *secure = frame + TRUSTIX_EXP_TCP_HEADER_LEN;
    volatile __u32 raw_cipher_len;
    __u32 bounded_cipher_len;
    __u32 tcp_len;
    __u32 cipher_padded;
    __u32 sum32;
    __u32 chunk;
    __s64 sum;

    raw_cipher_len = cipher_len;
    bounded_cipher_len = raw_cipher_len & TRUSTIX_KERNEL_CRYPTO_FRAME_MAX;
    if (!scratch || bounded_cipher_len != raw_cipher_len)
        return -22;
    cipher_len = bounded_cipher_len;
    tcp_len = TRUSTIX_EXP_TCP_TCP_HEADER_LEN + TRUSTIX_EXP_TCP_HEADER_LEN +
              TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN + cipher_len;
    if (ip + 20 > data_end ||
        tcp + TRUSTIX_EXP_TCP_TCP_HEADER_LEN > data_end ||
        frame + TRUSTIX_EXP_TCP_HEADER_LEN > data_end ||
        secure + TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN > data_end)
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
    for (int i = 0; i < TRUSTIX_EXP_TCP_TCP_HEADER_LEN; i++)
        header.tcp[i] = tcp[i];
    header.tcp[16] = 0;
    header.tcp[17] = 0;

#pragma clang loop unroll(full)
    for (int i = 0; i < TRUSTIX_EXP_TCP_HEADER_LEN; i++)
        header.frame[i] = frame[i];

#pragma clang loop unroll(full)
    for (int i = 0; i < TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN; i++)
        header.secure[i] = secure[i];

    cipher_padded = (cipher_len + 3) & ~3U;
    if (cipher_padded > TRUSTIX_KERNEL_CRYPTO_FRAME_PADDED)
        return -22;
    if (cipher_padded > cipher_len) {
#pragma clang loop unroll(full)
        for (int i = 0; i < 3; i++) {
            __u32 offset = (cipher_len + (__u32)i) & (TRUSTIX_KERNEL_CRYPTO_FRAME_PADDED - 1);
            if (offset < cipher_len || offset >= cipher_padded)
                break;
            scratch->cipher[offset] = 0;
        }
    }

    sum = bpf_csum_diff(0, 0, &header, sizeof(header), 0);
    if (sum < 0)
        return (int)sum;
    sum32 = (__u32)sum;

    if (cipher_padded > 0) {
        chunk = cipher_padded;
        if (chunk > TRUSTIX_EXP_TCP_CSUM_CHUNK)
            chunk = TRUSTIX_EXP_TCP_CSUM_CHUNK;
        if (trustix_add_csum_chunk(scratch->cipher, chunk, &sum32))
            return -22;
    }
    if (cipher_padded > TRUSTIX_EXP_TCP_CSUM_CHUNK) {
        chunk = cipher_padded - TRUSTIX_EXP_TCP_CSUM_CHUNK;
        if (chunk > TRUSTIX_EXP_TCP_CSUM_CHUNK)
            chunk = TRUSTIX_EXP_TCP_CSUM_CHUNK;
        if (trustix_add_csum_chunk(scratch->cipher + TRUSTIX_EXP_TCP_CSUM_CHUNK, chunk, &sum32))
            return -22;
    }
    if (cipher_padded > TRUSTIX_EXP_TCP_CSUM_CHUNK * 2) {
        chunk = cipher_padded - TRUSTIX_EXP_TCP_CSUM_CHUNK * 2;
        if (chunk > TRUSTIX_EXP_TCP_CSUM_CHUNK)
            chunk = TRUSTIX_EXP_TCP_CSUM_CHUNK;
        if (trustix_add_csum_chunk(scratch->cipher + TRUSTIX_EXP_TCP_CSUM_CHUNK * 2, chunk, &sum32))
            return -22;
    }
    if (cipher_padded > TRUSTIX_EXP_TCP_CSUM_CHUNK * 3) {
        chunk = cipher_padded - TRUSTIX_EXP_TCP_CSUM_CHUNK * 3;
        if (chunk > TRUSTIX_EXP_TCP_CSUM_CHUNK)
            chunk = TRUSTIX_EXP_TCP_CSUM_CHUNK;
        if (trustix_add_csum_chunk(scratch->cipher + TRUSTIX_EXP_TCP_CSUM_CHUNK * 3, chunk, &sum32))
            return -22;
    }
    if (cipher_padded > TRUSTIX_EXP_TCP_CSUM_CHUNK * 4) {
        chunk = cipher_padded - TRUSTIX_EXP_TCP_CSUM_CHUNK * 4;
        if (chunk > TRUSTIX_EXP_TCP_CSUM_CHUNK)
            chunk = TRUSTIX_EXP_TCP_CSUM_CHUNK;
        if (trustix_add_csum_chunk(scratch->cipher + TRUSTIX_EXP_TCP_CSUM_CHUNK * 4, chunk, &sum32))
            return -22;
    }
    if (cipher_padded > TRUSTIX_EXP_TCP_CSUM_CHUNK * 5) {
        chunk = cipher_padded - TRUSTIX_EXP_TCP_CSUM_CHUNK * 5;
        if (chunk > TRUSTIX_EXP_TCP_CSUM_CHUNK)
            chunk = TRUSTIX_EXP_TCP_CSUM_CHUNK;
        if (trustix_add_csum_chunk(scratch->cipher + TRUSTIX_EXP_TCP_CSUM_CHUNK * 5, chunk, &sum32))
            return -22;
    }
    if (cipher_padded > TRUSTIX_EXP_TCP_CSUM_CHUNK * 6) {
        chunk = cipher_padded - TRUSTIX_EXP_TCP_CSUM_CHUNK * 6;
        if (chunk > TRUSTIX_EXP_TCP_CSUM_CHUNK)
            chunk = TRUSTIX_EXP_TCP_CSUM_CHUNK;
        if (trustix_add_csum_chunk(scratch->cipher + TRUSTIX_EXP_TCP_CSUM_CHUNK * 6, chunk, &sum32))
            return -22;
    }
    if (cipher_padded > TRUSTIX_EXP_TCP_CSUM_CHUNK * 7) {
        chunk = cipher_padded - TRUSTIX_EXP_TCP_CSUM_CHUNK * 7;
        if (chunk > TRUSTIX_EXP_TCP_CSUM_CHUNK)
            chunk = TRUSTIX_EXP_TCP_CSUM_CHUNK;
        if (trustix_add_csum_chunk(scratch->cipher + TRUSTIX_EXP_TCP_CSUM_CHUNK * 7, chunk, &sum32))
            return -22;
    }
    trustix_write_be16(tcp + 16, trustix_bswap16(trustix_fold_checksum(sum32)));
    return 0;
}

static __noinline int trustix_encrypt_payload(struct xdp_md *ctx,
                                              __u32 payload_len, __u8 *frame,
                                              struct trustix_exp_tcp_tx_scratch *scratch)
{
    __u8 *data = (__u8 *)(long)ctx->data;
    __u8 *data_end = (__u8 *)(long)ctx->data_end;
    __u8 *payload;
    __u32 *slot_index;
    struct trustix_kernel_crypto_flow_key key = {};
    struct trustix_kernel_crypto_ctx_value *state;
    struct bpf_crypto_ctx *crypto_ctx;
    struct bpf_dynptr plain, cipher, nonce;
    volatile __u32 raw_payload_len;
    volatile __u32 raw_wire_len;
    __u32 bounded_payload_len;
    __u64 payload_offset64;
    __u32 payload_offset;
    __u32 wire_len;
    __u64 flow_id;
    __u64 epoch;
    __u64 sequence;
    int err = 0;

    raw_payload_len = payload_len;
    bounded_payload_len = raw_payload_len & TRUSTIX_KERNEL_CRYPTO_FRAME_MAX;
    if (!scratch || bounded_payload_len != raw_payload_len ||
        bounded_payload_len < 1 ||
        bounded_payload_len > TRUSTIX_KERNEL_CRYPTO_FRAME_MAX - TRUSTIX_KERNEL_CRYPTO_FRAME_TAG_LEN)
        return -22;
    payload_len = bounded_payload_len;
    if (!frame || frame + TRUSTIX_EXP_TCP_HEADER_LEN > data_end)
        return -14;
    payload = frame + TRUSTIX_EXP_TCP_HEADER_LEN;
    if (payload + payload_len > data_end)
        return -14;
    if (!ctx || payload < data)
        return -14;
    payload_offset64 = (__u64)(payload - data);
    if (payload_offset64 > 0xffffU)
        return -14;
    payload_offset = (__u32)payload_offset64;

    flow_id = trustix_read_be64(frame + 8);
    epoch = trustix_read_be64(frame + 16);
    sequence = trustix_read_be64(frame + 24);
    raw_wire_len = payload_len + TRUSTIX_KERNEL_CRYPTO_FRAME_TAG_LEN;
    wire_len = raw_wire_len & TRUSTIX_KERNEL_CRYPTO_FRAME_MAX;
    if (wire_len != raw_wire_len || wire_len < TRUSTIX_KERNEL_CRYPTO_FRAME_TAG_LEN)
        return -22;
    err = trustix_xdp_load_plain(ctx, payload_offset, payload_len, scratch);
    if (err)
        return err;
#pragma clang loop unroll(full)
    for (int i = 0; i < TRUSTIX_KERNEL_CRYPTO_FRAME_TAG_LEN; i++) {
        __u32 offset = (payload_len + (__u32)i) & (TRUSTIX_KERNEL_CRYPTO_FRAME_PADDED - 1);
        if (offset < payload_len || offset >= wire_len)
            break;
        scratch->plain[offset] = 0;
    }

    key.flow_id = flow_id;
    key.direction = TRUSTIX_KERNEL_CRYPTO_DIRECTION_SEND;
    slot_index = bpf_map_lookup_elem(&trustix_kernel_crypto_flow_index_map, &key);
    if (!slot_index)
        return -2;
    state = bpf_map_lookup_elem(&trustix_kernel_crypto_ctx_slots, slot_index);
    if (!state)
        return -2;
    scratch->hot_stats = trustix_kernel_crypto_hot_stats(state);

    bpf_rcu_read_lock();
    crypto_ctx = state->ctx;
    if (!crypto_ctx) {
        err = -2;
        goto out_unlock;
    }
    if (state->epoch != epoch) {
        err = -74;
        goto out_unlock;
    }
    scratch->suite = state->suite;
    err = trustix_send_check(state, sequence);
    if (err)
        goto out_unlock;
    trustix_prepare_nonce(scratch->nonce, state, sequence);
    if (bpf_dynptr_from_mem(scratch->plain, wire_len, 0, &plain) ||
        bpf_dynptr_from_mem(scratch->cipher, wire_len, 0, &cipher) ||
        bpf_dynptr_from_mem(scratch->nonce, sizeof(scratch->nonce), 0, &nonce)) {
        err = -14;
        goto out_unlock;
    }
    err = bpf_crypto_encrypt(crypto_ctx, &plain, &cipher, &nonce);
    if (!err)
        err = trustix_send_commit(state, sequence);
    if (!err && scratch->hot_stats) {
        state->packets++;
        state->bytes += payload_len;
    }

out_unlock:
    bpf_rcu_read_unlock();
    if (err)
        return err;
    return (__s32)wire_len;
}

SEC("xdp")
int trustix_exp_tcp_tx_seal(struct xdp_md *ctx)
{
    __u8 *data = (__u8 *)(long)ctx->data;
    __u8 *data_end = (__u8 *)(long)ctx->data_end;
    __u8 *ip;
    __u8 *tcp;
    __u8 *frame;
    __u8 *payload;
    __u8 *secure;
    __u32 scratch_key = 0;
    struct trustix_exp_tcp_tx_scratch *scratch;
    __u32 payload_len;
    __u32 old_total_len;
    __u32 new_total_len;
    __u64 epoch;
    __u64 sequence;
    __u64 cipher_offset64;
    __u32 cipher_offset;
    int cipher_len;
    __u32 cipher_u32;

    trustix_exp_tcp_tx_count(TRUSTIX_EXP_TCP_TX_STATS_ATTEMPTS);
    if (data + 14 > data_end)
        goto header_error;
    if (data[12] != 0x08 || data[13] != 0x00)
        goto header_error;

    ip = data + 14;
    if (ip + 20 > data_end)
        goto header_error;
    if (ip[0] != 0x45 || ip[9] != 6)
        goto header_error;

    tcp = ip + 20;
    if (tcp + TRUSTIX_EXP_TCP_TCP_HEADER_LEN > data_end)
        goto header_error;
    if (tcp[12] != 0x50)
        goto header_error;

    frame = tcp + TRUSTIX_EXP_TCP_TCP_HEADER_LEN;
    if (frame + TRUSTIX_EXP_TCP_HEADER_LEN > data_end)
        goto header_error;
    if (frame[0] != 'T' || frame[1] != 'I' ||
        frame[2] != 'X' || frame[3] != 'T' ||
        frame[4] != 1 || frame[6] != 0 || frame[7] != TRUSTIX_EXP_TCP_HEADER_LEN)
        goto header_error;
    if (frame[5] & (TRUSTIX_EXP_TCP_FLAG_ENCRYPTED | TRUSTIX_EXP_TCP_FLAG_KERNEL_OPENED))
        goto header_error;

    payload_len = trustix_read_be32(frame + 32);
    if (payload_len > TRUSTIX_KERNEL_CRYPTO_FRAME_MAX - TRUSTIX_KERNEL_CRYPTO_FRAME_TAG_LEN)
        goto header_error;
    payload = frame + TRUSTIX_EXP_TCP_HEADER_LEN;
    if (payload + payload_len > data_end)
        goto header_error;

    epoch = trustix_read_be64(frame + 16);
    sequence = trustix_read_be64(frame + 24);
    scratch = bpf_map_lookup_elem(&ix_exp_tcp_tx_scratch, &scratch_key);
    if (!scratch)
        goto no_context_error;
    cipher_len = trustix_encrypt_payload(ctx, payload_len, frame, scratch);
    if (cipher_len < 0) {
        if (cipher_len == -2)
            goto no_context_error;
        if (cipher_len == -22 || cipher_len == -74)
            goto header_error;
        if (cipher_len == -114)
            goto sequence_error;
        trustix_exp_tcp_tx_count(TRUSTIX_EXP_TCP_TX_STATS_ENCRYPT_ERRORS);
        goto error;
    }
    cipher_u32 = (__u32)cipher_len;
    if (cipher_u32 > TRUSTIX_KERNEL_CRYPTO_FRAME_MAX)
        goto header_error;

    old_total_len = ((__u32)ip[2] << 8) | ip[3];
    if (old_total_len < 20 + TRUSTIX_EXP_TCP_TCP_HEADER_LEN + TRUSTIX_EXP_TCP_HEADER_LEN + payload_len)
        goto header_error;
    if (ip + old_total_len > data_end)
        goto header_error;
    if (bpf_xdp_adjust_tail(ctx, TRUSTIX_EXP_TCP_OVERHEAD))
        goto error;

    data = (__u8 *)(long)ctx->data;
    data_end = (__u8 *)(long)ctx->data_end;
    ip = data + 14;
    tcp = ip + 20;
    frame = tcp + TRUSTIX_EXP_TCP_TCP_HEADER_LEN;
    secure = frame + TRUSTIX_EXP_TCP_HEADER_LEN;
    if (secure + TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN > data_end)
        goto header_error;
    if (secure + TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN + cipher_u32 > data_end)
        goto header_error;

    trustix_write_secure_header(secure, epoch, sequence, scratch->suite);
    if (secure + TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN < data)
        goto header_error;
    cipher_offset64 = (__u64)(secure + TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN - data);
    if (cipher_offset64 > 0xffffU)
        goto header_error;
    cipher_offset = (__u32)cipher_offset64;
    if (trustix_xdp_store_cipher(ctx, cipher_offset, cipher_u32, scratch))
        goto header_error;

    new_total_len = old_total_len + TRUSTIX_EXP_TCP_OVERHEAD;
    frame[5] = frame[5] | TRUSTIX_EXP_TCP_FLAG_ENCRYPTED;
    trustix_write_be32(frame + 32, (__u32)(TRUSTIX_KERNEL_CRYPTO_SECURE_HEADER_LEN + cipher_len));
    trustix_write_be16(ip + 2, (__u16)new_total_len);
    trustix_fix_ipv4_checksum(ip);
    tcp[16] = 0;
    tcp[17] = 0;
    if (trustix_exp_tcp_tx_skip_tcp_checksum()) {
        if (scratch->hot_stats)
            trustix_exp_tcp_tx_count(TRUSTIX_EXP_TCP_TX_STATS_TCP_CHECKSUM_SKIPPED);
    } else if (trustix_fix_tcp_checksum(ip, tcp, data_end, scratch, cipher_u32)) {
        goto header_error;
    }

    trustix_exp_tcp_tx_count(TRUSTIX_EXP_TCP_TX_STATS_SUCCESSES);
    return XDP_PASS;

no_context_error:
    trustix_exp_tcp_tx_count(TRUSTIX_EXP_TCP_TX_STATS_NO_CONTEXT_ERRORS);
    goto error;

header_error:
    trustix_exp_tcp_tx_count(TRUSTIX_EXP_TCP_TX_STATS_HEADER_ERRORS);
    goto error;

sequence_error:
    trustix_exp_tcp_tx_count(TRUSTIX_EXP_TCP_TX_STATS_SEQUENCE_ERRORS);
    goto error;

error:
    trustix_exp_tcp_tx_count(TRUSTIX_EXP_TCP_TX_STATS_ERRORS);
    return XDP_DROP;
}

char __license[] SEC("license") = "Dual MIT/GPL";
