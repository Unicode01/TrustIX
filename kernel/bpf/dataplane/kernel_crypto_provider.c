// SPDX-License-Identifier: GPL-2.0 OR MIT
// Kernel crypto provider. The syscall programs create/release bpf_crypto_ctx
// objects; the XDP programs execute AEAD frame seal/open against provider-owned
// ctx slots for the experimental_tcp kernel crypto packet path.
#define SEC(NAME) __attribute__((section(NAME), used))
#define __ksym __attribute__((section(".ksyms")))
#define __always_inline inline __attribute__((always_inline))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __kptr __attribute__((btf_type_tag("kptr")))

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
#define BPF_ANY 0
#define XDP_PASS 2

#define TRUSTIX_KERNEL_CRYPTO_MAX_ENTRIES 4096
#define TRUSTIX_KERNEL_CRYPTO_CMD_INSTALL 1
#define TRUSTIX_KERNEL_CRYPTO_CMD_DELETE 2
#define TRUSTIX_KERNEL_CRYPTO_SUITE_AES_256_GCM_X25519 1
#define TRUSTIX_KERNEL_CRYPTO_SUITE_AES_128_GCM_X25519 2
#define TRUSTIX_KERNEL_CRYPTO_SUITE_CHACHA20_POLY1305_X25519 3
#define TRUSTIX_KERNEL_CRYPTO_WIRE_SECURE_V1 1
#define TRUSTIX_KERNEL_CRYPTO_FLOW_FLAG_HOT_STATS 1
#define TRUSTIX_KERNEL_CRYPTO_FLOW_FLAG_NO_REPLAY 2
#define TRUSTIX_KERNEL_CRYPTO_ROUNDTRIP_PLAIN_LEN 16
#define TRUSTIX_KERNEL_CRYPTO_ROUNDTRIP_TAG_LEN 16
#define TRUSTIX_KERNEL_CRYPTO_ROUNDTRIP_WIRE_LEN (TRUSTIX_KERNEL_CRYPTO_ROUNDTRIP_PLAIN_LEN + TRUSTIX_KERNEL_CRYPTO_ROUNDTRIP_TAG_LEN)
#define TRUSTIX_KERNEL_CRYPTO_FRAME_MAX 4095
#define TRUSTIX_KERNEL_CRYPTO_FRAME_TAG_LEN 16
#define TRUSTIX_KERNEL_CRYPTO_REPLAY_WORDS 1024
#define TRUSTIX_KERNEL_CRYPTO_REPLAY_MAX ((TRUSTIX_KERNEL_CRYPTO_REPLAY_WORDS - 1) * 64)

struct xdp_md {
    __u32 data;
    __u32 data_end;
};

struct bpf_dynptr {
    __u64 __opaque[2];
};

struct bpf_crypto_ctx {};

struct bpf_crypto_params {
    char type[14];
    __u8 reserved[2];
    char algo[128];
    __u8 key[256];
    __u32 key_len;
    __u32 authsize;
};

struct trustix_kernel_crypto_flow_key {
    __u64 flow_id;
    __u8 direction;
    __u8 reserved[7];
};

struct trustix_kernel_crypto_flow_value {
    __u16 suite;
    __u16 wire_format;
    __u32 flags;
    __u32 key_len;
    __u64 epoch;
    __u8 key[32];
    __u8 iv[12];
    __u32 replay_window;
    __s64 installed_unix;
    __u64 reserved[4];
};

struct trustix_kernel_crypto_command {
    __u32 op;
    __s32 result;
    __u32 slot;
    __u32 reserved;
    struct trustix_kernel_crypto_flow_key key;
    struct trustix_kernel_crypto_flow_value value;
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

struct trustix_kernel_crypto_roundtrip {
    struct trustix_kernel_crypto_flow_key key;
    __s32 result;
    __u32 reserved;
    __u8 plain[TRUSTIX_KERNEL_CRYPTO_ROUNDTRIP_WIRE_LEN];
    __u8 cipher[TRUSTIX_KERNEL_CRYPTO_ROUNDTRIP_WIRE_LEN];
    __u8 out[TRUSTIX_KERNEL_CRYPTO_ROUNDTRIP_WIRE_LEN];
    __u8 nonce[12];
};

struct trustix_kernel_crypto_frame {
    struct trustix_kernel_crypto_flow_key key;
    __s32 result;
    __u32 reserved;
    __u64 epoch;
    __u64 sequence;
    __u32 in_len;
    __u32 out_len;
    __u8 in[TRUSTIX_KERNEL_CRYPTO_FRAME_MAX];
    __u8 out[TRUSTIX_KERNEL_CRYPTO_FRAME_MAX];
    __u8 nonce[12];
    __u8 pad[4];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct trustix_kernel_crypto_command);
} trustix_kernel_crypto_cmd_map SEC(".maps");

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
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct trustix_kernel_crypto_roundtrip);
} trustix_kernel_crypto_roundtrip_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct trustix_kernel_crypto_frame);
} trustix_kernel_crypto_frame_map SEC(".maps");

static void *(*bpf_map_lookup_elem)(const void *map, const void *key) = (void *)1;
static long (*bpf_spin_lock)(struct bpf_spin_lock *lock) = (void *)93;
static long (*bpf_spin_unlock)(struct bpf_spin_lock *lock) = (void *)94;
static long (*bpf_map_update_elem)(const void *map, const void *key, const void *value, __u64 flags) = (void *)2;
static long (*bpf_map_delete_elem)(const void *map, const void *key) = (void *)3;
static void *(*bpf_kptr_xchg)(void *dst, void *ptr) = (void *)194;
static long (*bpf_dynptr_from_mem)(void *data, __u32 size, __u64 flags, struct bpf_dynptr *ptr) = (void *)197;

extern struct bpf_crypto_ctx *bpf_crypto_ctx_create(const struct bpf_crypto_params *params, __u32 params__sz, int *err) __ksym;
extern void bpf_crypto_ctx_release(struct bpf_crypto_ctx *ctx) __ksym;
extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;
extern int bpf_crypto_encrypt(struct bpf_crypto_ctx *ctx, const struct bpf_dynptr *src, const struct bpf_dynptr *dst, const struct bpf_dynptr *siv__nullable) __ksym;
extern int bpf_crypto_decrypt(struct bpf_crypto_ctx *ctx, const struct bpf_dynptr *src, const struct bpf_dynptr *dst, const struct bpf_dynptr *siv__nullable) __ksym;

static void trustix_fill_aead_params(struct bpf_crypto_params *params,
                                     const struct trustix_kernel_crypto_flow_value *value)
{
    params->type[0] = 'a'; params->type[1] = 'e'; params->type[2] = 'a'; params->type[3] = 'd';
    params->algo[0] = 'g'; params->algo[1] = 'c'; params->algo[2] = 'm'; params->algo[3] = '(';
    params->algo[4] = 'a'; params->algo[5] = 'e'; params->algo[6] = 's'; params->algo[7] = ')';
    params->key_len = value->key_len;
    params->authsize = 16;

#pragma clang loop unroll(full)
    for (int i = 0; i < 32; i++)
        params->key[i] = value->key[i];
}

static void trustix_fill_ctx_value(struct trustix_kernel_crypto_ctx_value *ctx_value,
                                   const struct trustix_kernel_crypto_flow_value *value)
{
	volatile __u64 *replay_seen = ctx_value->replay_seen;
	volatile __u64 *replay_blocks = ctx_value->replay_blocks;

	ctx_value->suite = value->suite;
	ctx_value->wire_format = value->wire_format;
	ctx_value->flags = value->flags;
    ctx_value->epoch = value->epoch;
    ctx_value->replay_window = value->replay_window;
    ctx_value->installed_unix = value->installed_unix;
    ctx_value->packets = 0;
    ctx_value->bytes = 0;
    ctx_value->last_sequence = 0;

#pragma clang loop unroll(full)
    for (int i = 0; i < 12; i++)
        ctx_value->iv[i] = value->iv[i];

#pragma clang loop unroll(disable)
	for (int i = 0; i < TRUSTIX_KERNEL_CRYPTO_REPLAY_WORDS; i++) {
		replay_seen[i] = 0;
		replay_blocks[i] = 0;
	}
}

static int trustix_kernel_crypto_validate_value(const struct trustix_kernel_crypto_flow_value *value)
{
    if (value->wire_format != TRUSTIX_KERNEL_CRYPTO_WIRE_SECURE_V1)
        return -95;
    if (value->suite == TRUSTIX_KERNEL_CRYPTO_SUITE_AES_256_GCM_X25519) {
        if (value->key_len != 32)
            return -22;
        return 0;
    }
    if (value->suite == TRUSTIX_KERNEL_CRYPTO_SUITE_AES_128_GCM_X25519) {
        if (value->key_len != 16)
            return -22;
        return 0;
    }
    /*
     * The secure protocol reserves suite id 3 for ChaCha20-Poly1305. This
     * provider deliberately rejects it until a synchronous kernel AEAD backend
     * can be exposed safely through BPF crypto kfuncs.
     */
    if (value->suite == TRUSTIX_KERNEL_CRYPTO_SUITE_CHACHA20_POLY1305_X25519)
        return -95;
    return -95;
}

static int trustix_kernel_crypto_lookup_ctx(const struct trustix_kernel_crypto_flow_key *key,
                                      struct trustix_kernel_crypto_ctx_value **state,
                                      struct bpf_crypto_ctx **crypto_ctx)
{
    __u32 *slot_index;

    slot_index = bpf_map_lookup_elem(&trustix_kernel_crypto_flow_index_map, key);
    if (!slot_index)
        return -2;
    *state = bpf_map_lookup_elem(&trustix_kernel_crypto_ctx_slots, slot_index);
    if (!*state)
        return -2;
    *crypto_ctx = (*state)->ctx;
    if (!*crypto_ctx)
        return -2;
    return 0;
}

static int trustix_kernel_crypto_hot_stats(const struct trustix_kernel_crypto_ctx_value *state)
{
    return state && (state->flags & TRUSTIX_KERNEL_CRYPTO_FLOW_FLAG_HOT_STATS);
}

static int trustix_kernel_crypto_no_replay(const struct trustix_kernel_crypto_ctx_value *state)
{
    return state && (state->flags & TRUSTIX_KERNEL_CRYPTO_FLOW_FLAG_NO_REPLAY);
}

static int trustix_kernel_crypto_prepare_nonce(struct trustix_kernel_crypto_frame *frame,
                                         const struct trustix_kernel_crypto_ctx_value *state)
{
#pragma clang loop unroll(full)
    for (int i = 0; i < 12; i++)
        frame->nonce[i] = state->iv[i];

    frame->nonce[4] = (__u8)(frame->sequence >> 56);
    frame->nonce[5] = (__u8)(frame->sequence >> 48);
    frame->nonce[6] = (__u8)(frame->sequence >> 40);
    frame->nonce[7] = (__u8)(frame->sequence >> 32);
    frame->nonce[8] = (__u8)(frame->sequence >> 24);
    frame->nonce[9] = (__u8)(frame->sequence >> 16);
    frame->nonce[10] = (__u8)(frame->sequence >> 8);
    frame->nonce[11] = (__u8)frame->sequence;
    return 0;
}

static __always_inline __u32 trustix_kernel_crypto_replay_window(const struct trustix_kernel_crypto_ctx_value *state)
{
    __u32 window = state->replay_window;

    if (window == 0)
        window = TRUSTIX_KERNEL_CRYPTO_REPLAY_MAX;
    if (window > TRUSTIX_KERNEL_CRYPTO_REPLAY_MAX)
        window = TRUSTIX_KERNEL_CRYPTO_REPLAY_MAX;
    return window;
}

static __always_inline int trustix_kernel_crypto_replay_seen(const struct trustix_kernel_crypto_ctx_value *state,
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

static __always_inline void trustix_kernel_crypto_replay_mark(struct trustix_kernel_crypto_ctx_value *state,
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

static int trustix_kernel_crypto_replay_commit(struct trustix_kernel_crypto_ctx_value *state,
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
        trustix_kernel_crypto_replay_mark(state, sequence);
        goto out_unlock;
    }

    window = trustix_kernel_crypto_replay_window(state);
    delta = state->last_sequence - sequence;
    if (delta >= window || delta >= TRUSTIX_KERNEL_CRYPTO_REPLAY_MAX)
        replay_error = 1;
    else if (trustix_kernel_crypto_replay_seen(state, sequence))
        replay_error = 2;
    else
        trustix_kernel_crypto_replay_mark(state, sequence);

out_unlock:
    bpf_spin_unlock(&state->replay_lock);
    return replay_error ? -114 : 0;
}

static int trustix_kernel_crypto_send_check(const struct trustix_kernel_crypto_ctx_value *state,
                                      __u64 sequence)
{
    if (sequence == 0)
        return -22;
    if (sequence <= state->last_sequence)
        return -114;
    return 0;
}

static int trustix_kernel_crypto_send_commit(struct trustix_kernel_crypto_ctx_value *state,
                                       __u64 sequence)
{
    if (sequence == 0)
        return -22;
    if (sequence <= state->last_sequence)
        return -114;
    state->last_sequence = sequence;
    trustix_kernel_crypto_replay_mark(state, sequence);
    return 0;
}

SEC("syscall")
int trustix_kernel_crypto_install(void *ctx)
{
    __u32 slot = 0;
    int err = 0;
    struct trustix_kernel_crypto_command *cmd;
    struct trustix_kernel_crypto_ctx_value *state;
    struct bpf_crypto_params params = {};
    struct bpf_crypto_ctx *crypto_ctx, *old;
    __u32 slot_index;

    (void)ctx;
    cmd = bpf_map_lookup_elem(&trustix_kernel_crypto_cmd_map, &slot);
    if (!cmd)
        return -2;
    cmd->result = 0;
    if (cmd->op != TRUSTIX_KERNEL_CRYPTO_CMD_INSTALL) {
        cmd->result = -22;
        return -22;
    }
    if (cmd->key.flow_id == 0) {
        cmd->result = -22;
        return -22;
    }
    if (cmd->slot >= TRUSTIX_KERNEL_CRYPTO_MAX_ENTRIES) {
        cmd->result = -28;
        return -28;
    }
    err = trustix_kernel_crypto_validate_value(&cmd->value);
    if (err) {
        cmd->result = err;
        return err;
    }
    slot_index = cmd->slot;
    state = bpf_map_lookup_elem(&trustix_kernel_crypto_ctx_slots, &slot_index);
    if (!state) {
        cmd->result = -2;
        return -2;
    }

    trustix_fill_aead_params(&params, &cmd->value);
    crypto_ctx = bpf_crypto_ctx_create(&params, sizeof(params), &err);
    if (!crypto_ctx) {
        cmd->result = err ? err : -5;
        return cmd->result;
    }

    err = bpf_map_update_elem(&trustix_kernel_crypto_flow_index_map, &cmd->key, &slot_index, BPF_ANY);
    if (err) {
        bpf_crypto_ctx_release(crypto_ctx);
        cmd->result = err;
        return err;
    }

    trustix_fill_ctx_value(state, &cmd->value);
    old = bpf_kptr_xchg(&state->ctx, crypto_ctx);
    if (old)
        bpf_crypto_ctx_release(old);
    return 0;
}

SEC("syscall")
int trustix_kernel_crypto_delete(void *ctx)
{
    __u32 slot = 0;
    struct trustix_kernel_crypto_command *cmd;
    struct trustix_kernel_crypto_ctx_value *state;
    struct bpf_crypto_ctx *old;
    __u32 *slot_index;

    (void)ctx;
    cmd = bpf_map_lookup_elem(&trustix_kernel_crypto_cmd_map, &slot);
    if (!cmd)
        return -2;
    cmd->result = 0;
    if (cmd->op != TRUSTIX_KERNEL_CRYPTO_CMD_DELETE) {
        cmd->result = -22;
        return -22;
    }
    if (cmd->key.flow_id == 0) {
        cmd->result = -22;
        return -22;
    }

    slot_index = bpf_map_lookup_elem(&trustix_kernel_crypto_flow_index_map, &cmd->key);
    if (!slot_index)
        return 0;
    state = bpf_map_lookup_elem(&trustix_kernel_crypto_ctx_slots, slot_index);
    if (state) {
        old = bpf_kptr_xchg(&state->ctx, 0);
        if (old)
            bpf_crypto_ctx_release(old);
    }
    bpf_map_delete_elem(&trustix_kernel_crypto_flow_index_map, &cmd->key);
    return 0;
}

SEC("xdp")
int trustix_kernel_crypto_frame_seal_xdp(struct xdp_md *ctx)
{
    __u32 slot = 0;
    struct trustix_kernel_crypto_frame *frame;
    struct trustix_kernel_crypto_ctx_value *state = 0;
    struct bpf_crypto_ctx *crypto_ctx = 0;
    struct bpf_dynptr plain, cipher, nonce;
    volatile __u32 raw_len;
    __u32 in_len;
    __u32 wire_len;
    int err;

    (void)ctx;
    frame = bpf_map_lookup_elem(&trustix_kernel_crypto_frame_map, &slot);
    if (!frame)
        return XDP_PASS;
    frame->result = 0;
    frame->out_len = 0;
    raw_len = frame->in_len;
    in_len = raw_len & TRUSTIX_KERNEL_CRYPTO_FRAME_MAX;
    if (frame->sequence == 0 || in_len != raw_len ||
        in_len > TRUSTIX_KERNEL_CRYPTO_FRAME_MAX - TRUSTIX_KERNEL_CRYPTO_FRAME_TAG_LEN) {
        frame->result = -22;
        return XDP_PASS;
    }
    wire_len = in_len + TRUSTIX_KERNEL_CRYPTO_FRAME_TAG_LEN;
    if (wire_len > TRUSTIX_KERNEL_CRYPTO_FRAME_MAX) {
        frame->result = -22;
        return XDP_PASS;
    }

    if (bpf_dynptr_from_mem(frame->in, wire_len, 0, &plain)) {
        frame->result = -14;
        return XDP_PASS;
    }
    if (bpf_dynptr_from_mem(frame->out, wire_len, 0, &cipher)) {
        frame->result = -14;
        return XDP_PASS;
    }
    if (bpf_dynptr_from_mem(frame->nonce, sizeof(frame->nonce), 0, &nonce)) {
        frame->result = -14;
        return XDP_PASS;
    }

    bpf_rcu_read_lock();
    err = trustix_kernel_crypto_lookup_ctx(&frame->key, &state, &crypto_ctx);
    if (!err && state->epoch != frame->epoch)
        err = -74;
    if (!err)
        err = trustix_kernel_crypto_send_check(state, frame->sequence);
    if (!err)
        err = trustix_kernel_crypto_prepare_nonce(frame, state);
    if (!err)
        err = bpf_crypto_encrypt(crypto_ctx, &plain, &cipher, &nonce);
    if (!err)
        err = trustix_kernel_crypto_send_commit(state, frame->sequence);
    if (!err && trustix_kernel_crypto_hot_stats(state)) {
        state->packets++;
        state->bytes += in_len;
    }
    bpf_rcu_read_unlock();

    if (err) {
        frame->result = err;
        return XDP_PASS;
    }
    frame->out_len = wire_len;
    frame->result = 0;
    return XDP_PASS;
}

SEC("xdp")
int trustix_kernel_crypto_frame_open_xdp(struct xdp_md *ctx)
{
    __u32 slot = 0;
    struct trustix_kernel_crypto_frame *frame;
    struct trustix_kernel_crypto_ctx_value *state = 0;
    struct bpf_crypto_ctx *crypto_ctx = 0;
    struct bpf_dynptr cipher, plain, nonce;
    volatile __u32 raw_len;
    __u32 in_len;
    __u32 plain_len;
    int err;

    (void)ctx;
    frame = bpf_map_lookup_elem(&trustix_kernel_crypto_frame_map, &slot);
    if (!frame)
        return XDP_PASS;
    frame->result = 0;
    frame->out_len = 0;
    raw_len = frame->in_len;
    in_len = raw_len & TRUSTIX_KERNEL_CRYPTO_FRAME_MAX;
    if (frame->sequence == 0 || in_len != raw_len ||
        in_len < TRUSTIX_KERNEL_CRYPTO_FRAME_TAG_LEN) {
        frame->result = -22;
        return XDP_PASS;
    }
    plain_len = in_len - TRUSTIX_KERNEL_CRYPTO_FRAME_TAG_LEN;

    if (bpf_dynptr_from_mem(frame->in, in_len, 0, &cipher)) {
        frame->result = -14;
        return XDP_PASS;
    }
    if (bpf_dynptr_from_mem(frame->out, in_len, 0, &plain)) {
        frame->result = -14;
        return XDP_PASS;
    }
    if (bpf_dynptr_from_mem(frame->nonce, sizeof(frame->nonce), 0, &nonce)) {
        frame->result = -14;
        return XDP_PASS;
    }

    bpf_rcu_read_lock();
    err = trustix_kernel_crypto_lookup_ctx(&frame->key, &state, &crypto_ctx);
    if (!err && state->epoch != frame->epoch)
        err = -74;
    if (!err)
        err = trustix_kernel_crypto_prepare_nonce(frame, state);
    if (!err)
        err = bpf_crypto_decrypt(crypto_ctx, &cipher, &plain, &nonce);
    bpf_rcu_read_unlock();

    if (!err)
        err = trustix_kernel_crypto_replay_commit(state, frame->sequence);
    if (!err && trustix_kernel_crypto_hot_stats(state)) {
        state->packets++;
        state->bytes += plain_len;
    }

    if (err) {
        frame->result = err;
        return XDP_PASS;
    }
    frame->out_len = plain_len;
    frame->result = 0;
    return XDP_PASS;
}

SEC("xdp")
int trustix_kernel_crypto_roundtrip_xdp(struct xdp_md *ctx)
{
    __u32 slot = 0;
    __u32 *slot_index;
    struct trustix_kernel_crypto_roundtrip *scratch;
    struct trustix_kernel_crypto_ctx_value *state;
    struct bpf_crypto_ctx *crypto_ctx;
    struct bpf_dynptr plain, cipher, out, nonce;
    int err = 0;

    (void)ctx;
    scratch = bpf_map_lookup_elem(&trustix_kernel_crypto_roundtrip_map, &slot);
    if (!scratch)
        return XDP_PASS;
    scratch->result = 0;

    slot_index = bpf_map_lookup_elem(&trustix_kernel_crypto_flow_index_map, &scratch->key);
    if (!slot_index) {
        scratch->result = -2;
        return XDP_PASS;
    }
    state = bpf_map_lookup_elem(&trustix_kernel_crypto_ctx_slots, slot_index);
    if (!state) {
        scratch->result = -2;
        return XDP_PASS;
    }
    if (bpf_dynptr_from_mem(scratch->plain, TRUSTIX_KERNEL_CRYPTO_ROUNDTRIP_WIRE_LEN, 0, &plain)) {
        scratch->result = -14;
        return XDP_PASS;
    }
    if (bpf_dynptr_from_mem(scratch->cipher, TRUSTIX_KERNEL_CRYPTO_ROUNDTRIP_WIRE_LEN, 0, &cipher)) {
        scratch->result = -14;
        return XDP_PASS;
    }
    if (bpf_dynptr_from_mem(scratch->out, TRUSTIX_KERNEL_CRYPTO_ROUNDTRIP_WIRE_LEN, 0, &out)) {
        scratch->result = -14;
        return XDP_PASS;
    }
    if (bpf_dynptr_from_mem(scratch->nonce, sizeof(scratch->nonce), 0, &nonce)) {
        scratch->result = -14;
        return XDP_PASS;
    }

    bpf_rcu_read_lock();
    crypto_ctx = state->ctx;
    if (!crypto_ctx) {
        bpf_rcu_read_unlock();
        scratch->result = -2;
        return XDP_PASS;
    }
    err = bpf_crypto_encrypt(crypto_ctx, &plain, &cipher, &nonce);
    if (!err)
        err = bpf_crypto_decrypt(crypto_ctx, &cipher, &out, &nonce);
    bpf_rcu_read_unlock();
    if (err) {
        scratch->result = err;
        return XDP_PASS;
    }

#pragma clang loop unroll(full)
    for (int i = 0; i < TRUSTIX_KERNEL_CRYPTO_ROUNDTRIP_PLAIN_LEN; i++) {
        if (scratch->plain[i] != scratch->out[i]) {
            scratch->result = -74;
            return XDP_PASS;
        }
    }
    scratch->result = 0;
    return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
