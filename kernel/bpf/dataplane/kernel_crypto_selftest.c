// SPDX-License-Identifier: GPL-2.0 OR MIT
// This object is only a verifier/load selftest. It is not attached to the
// production data path and it never carries TrustIX session key material.
#define SEC(NAME) __attribute__((section(NAME), used))
#define __ksym __attribute__((section(".ksyms")))
#define __always_inline inline __attribute__((always_inline))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __kptr __attribute__((btf_type_tag("kptr")))

typedef unsigned char __u8;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define BPF_MAP_TYPE_ARRAY 2
#define XDP_PASS 2
#define TC_ACT_OK 0

struct xdp_md {
    __u32 data;
    __u32 data_end;
};

struct __sk_buff {
    __u32 len;
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

struct trustix_kernel_crypto_state {
    struct bpf_crypto_ctx __kptr *ctx;
};

struct trustix_kernel_crypto_scratch {
    __u8 plain[16];
    __u8 cipher[32];
    __u8 out[16];
    __u8 nonce[12];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct trustix_kernel_crypto_state);
} trustix_kernel_crypto_state_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct trustix_kernel_crypto_scratch);
} trustix_kernel_crypto_scratch_map SEC(".maps");

static void *(*bpf_map_lookup_elem)(const void *map, const void *key) = (void *)1;
static void *(*bpf_kptr_xchg)(void *dst, void *ptr) = (void *)194;
static long (*bpf_dynptr_from_mem)(void *data, __u32 size, __u64 flags, struct bpf_dynptr *ptr) = (void *)197;

extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;
extern struct bpf_crypto_ctx *bpf_crypto_ctx_create(const struct bpf_crypto_params *params, __u32 params__sz, int *err) __ksym;
extern void bpf_crypto_ctx_release(struct bpf_crypto_ctx *ctx) __ksym;
extern int bpf_crypto_encrypt(struct bpf_crypto_ctx *ctx, const struct bpf_dynptr *src, const struct bpf_dynptr *dst, const struct bpf_dynptr *siv__nullable) __ksym;
extern int bpf_crypto_decrypt(struct bpf_crypto_ctx *ctx, const struct bpf_dynptr *src, const struct bpf_dynptr *dst, const struct bpf_dynptr *siv__nullable) __ksym;

SEC("syscall")
int trustix_kernel_crypto_init(void *ctx)
{
    __u32 key = 0;
    int err = 0;
    struct bpf_crypto_params params = {};
    struct trustix_kernel_crypto_state *state;
    struct bpf_crypto_ctx *crypto_ctx, *old;

    (void)ctx;
    params.type[0] = 'a'; params.type[1] = 'e'; params.type[2] = 'a'; params.type[3] = 'd';
    params.algo[0] = 'g'; params.algo[1] = 'c'; params.algo[2] = 'm'; params.algo[3] = '(';
    params.algo[4] = 'a'; params.algo[5] = 'e'; params.algo[6] = 's'; params.algo[7] = ')';
    params.key_len = 32;
    params.authsize = 16;

    state = bpf_map_lookup_elem(&trustix_kernel_crypto_state_map, &key);
    if (!state)
        return 0;

    crypto_ctx = bpf_crypto_ctx_create(&params, sizeof(params), &err);
    if (!crypto_ctx)
        return 0;

    old = bpf_kptr_xchg(&state->ctx, crypto_ctx);
    if (old)
        bpf_crypto_ctx_release(old);
    return 0;
}

static __always_inline int trustix_kernel_crypto_run(void)
{
    __u32 key = 0;
    int err = 0;
    struct trustix_kernel_crypto_scratch *scratch;
    struct trustix_kernel_crypto_state *state;
    struct bpf_crypto_ctx *ctx;
    struct bpf_dynptr src, enc, dec, iv;

    scratch = bpf_map_lookup_elem(&trustix_kernel_crypto_scratch_map, &key);
    state = bpf_map_lookup_elem(&trustix_kernel_crypto_state_map, &key);
    if (!scratch || !state)
        return 0;

    if (bpf_dynptr_from_mem(scratch->plain, sizeof(scratch->plain), 0, &src))
        return 0;
    if (bpf_dynptr_from_mem(scratch->cipher, sizeof(scratch->cipher), 0, &enc))
        return 0;
    if (bpf_dynptr_from_mem(scratch->out, sizeof(scratch->out), 0, &dec))
        return 0;
    if (bpf_dynptr_from_mem(scratch->nonce, sizeof(scratch->nonce), 0, &iv))
        return 0;

    bpf_rcu_read_lock();
    ctx = state->ctx;
    if (ctx) {
        err += bpf_crypto_encrypt(ctx, &src, &enc, &iv);
        err += bpf_crypto_decrypt(ctx, &enc, &dec, &iv);
    }
    bpf_rcu_read_unlock();
    return err;
}

SEC("xdp")
int trustix_kernel_crypto_xdp(struct xdp_md *ctx)
{
    (void)ctx;
    trustix_kernel_crypto_run();
    return XDP_PASS;
}

SEC("tc")
int trustix_kernel_crypto_tc(struct __sk_buff *skb)
{
    (void)skb;
    trustix_kernel_crypto_run();
    return TC_ACT_OK;
}

char __license[] SEC("license") = "Dual MIT/GPL";
