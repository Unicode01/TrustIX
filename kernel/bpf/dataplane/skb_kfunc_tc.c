// SPDX-License-Identifier: GPL-2.0 OR MIT
// Minimal TC object used to carry BTF relocation metadata for TrustIX skb
// kfunc calls that are spliced into dynamically generated programs.
#define SEC(NAME) __attribute__((section(NAME), used))
#define __ksym __attribute__((section(".ksyms")))

typedef unsigned int __u32;
typedef unsigned short __u16;

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

extern int trustix_kernel_skb_clear_tx_offload(struct __sk_buff *skb,
                                            __u32 flags) __ksym;
extern int trustix_kernel_skb_fix_inner_tcp_csum(struct __sk_buff *skb,
                                              __u32 inner_ip_offset,
                                              __u32 inner_len,
                                              __u32 flags) __ksym;
extern int trustix_kernel_skb_kudp_rx_decap_l2(struct __sk_buff *skb,
                                            __u32 outer_len,
                                            unsigned long long l2_head,
                                            __u32 l2_tail0,
                                            __u32 l2_tail1) __ksym;

struct trustix_kudp_rx_decap_l2_dev_args {
    __u32 outer_len;
    __u32 ifindex;
    unsigned long long l2_head;
    __u32 l2_tail0;
    __u32 l2_tail1;
    __u32 flags;
};

extern int trustix_kernel_skb_kudp_rx_decap_l2_dev(struct __sk_buff *skb,
    const struct trustix_kudp_rx_decap_l2_dev_args *args) __ksym;

struct trustix_kudp_rx_parse_args {
    __u32 static_dest_port;
    __u32 flags;
    unsigned long long l2_head;
    __u32 l2_tail0;
    __u32 l2_tail1;
    __u32 decap_flags;
    __u32 local_ipv4;
    __u32 local_ipv4_mask;
    __u32 local_ifindex;
    __u32 egress_ifindex;
};

extern int trustix_kernel_skb_kudp_rx_parse_decap_l2(struct __sk_buff *skb,
    const struct trustix_kudp_rx_parse_args *args) __ksym;

extern int trustix_kernel_skb_tixt_fix_outer_tcp_csum(struct __sk_buff *skb,
                                                   __u32 flags) __ksym;

struct trustix_tixt_tx_tcp_header_args {
    unsigned char l2[14];
    __u32 saddr;
    __u32 daddr;
    __u16 source;
    __u16 dest;
    __u16 ip_tot_len;
    __u16 ip_check_base;
    __u32 pad0;
    unsigned long long flow_id;
    unsigned long long sequence;
    __u32 payload_len;
    __u32 flags;
};

extern int trustix_kernel_skb_tixt_tx_finalize_tcp_header(struct __sk_buff *skb,
    const struct trustix_tixt_tx_tcp_header_args *args, __u32 clear_flags) __ksym;
extern int trustix_kernel_skb_tixt_tx_set_tcp_partial_csum(struct __sk_buff *skb,
                                                        __u32 clear_flags) __ksym;
extern int trustix_kernel_skb_tixt_tx_push_tcp_header(struct __sk_buff *skb,
    const struct trustix_tixt_tx_tcp_header_args *args, __u32 clear_flags) __ksym;

struct trustix_kudp_tx_flow_value {
    unsigned long long sequence;
    __u32 saddr;
    __u32 daddr;
    __u16 source;
    __u16 dest;
    __u32 ifindex;
    __u32 destination_mac0;
    __u16 destination_mac1;
    __u16 ipv4_check_udp;
    __u32 source_mac0;
    __u16 source_mac1;
    __u16 ipv4_check_tcp;
    __u32 mtu;
    __u32 flags;
};

struct trustix_tixt_tx_flow_header_args {
    unsigned long long flow_id;
    __u32 payload_len;
    __u32 clear_flags;
};

extern int trustix_kernel_skb_tixt_tx_push_flow_tcp_header(struct __sk_buff *skb,
    struct trustix_kudp_tx_flow_value *flow,
    const struct trustix_tixt_tx_flow_header_args *args) __ksym;
extern int trustix_kernel_skb_tixt_tx_finalize_flow_tcp_header(struct __sk_buff *skb,
    struct trustix_kudp_tx_flow_value *flow,
    const struct trustix_tixt_tx_flow_header_args *args) __ksym;

struct trustix_kudp_tx_route_value {
    unsigned long long flow_id;
    unsigned long long flow_id_1;
    unsigned long long flow_id_2;
    unsigned long long flow_id_3;
    unsigned long long flow_id_4;
    unsigned long long flow_id_5;
    unsigned long long flow_id_6;
    unsigned long long flow_id_7;
    unsigned long long flow_id_8;
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

struct trustix_tixt_tx_route_header_args {
    __u32 clear_flags;
    __u32 reserved;
};

extern int trustix_kernel_skb_tixt_tx_push_route_tcp_header(struct __sk_buff *skb,
    struct trustix_kudp_tx_route_value *route,
    const struct trustix_tixt_tx_route_header_args *args) __ksym;

struct trustix_tixt_tx_route_gso_args {
    __u32 clear_flags;
    __u32 reserved;
};

extern int trustix_kernel_skb_tixt_tx_segment_route_tcp_gso(struct __sk_buff *skb,
    struct trustix_kudp_tx_route_value *route,
    const struct trustix_tixt_tx_route_gso_args *args) __ksym;

struct trustix_tixt_tx_secure_route_gso_args {
    __u32 clear_flags;
    __u32 slot_id;
    __u16 suite;
    __u16 reserved0;
    unsigned long long epoch;
    unsigned long long flow_id;
    unsigned char iv[12];
    __u32 reserved1;
};

extern int trustix_kernel_skb_tixt_tx_segment_secure_route_tcp_gso(struct __sk_buff *skb,
    struct trustix_kudp_tx_route_value *route,
    struct trustix_kudp_tx_flow_value *flow,
    const struct trustix_tixt_tx_secure_route_gso_args *args) __ksym;
extern int trustix_kernel_skb_tixt_tx_route_tcp(struct __sk_buff *skb,
    struct trustix_kudp_tx_route_value *route,
    const struct trustix_tixt_tx_route_gso_args *args) __ksym;
extern int trustix_kernel_skb_tixt_tx_route_tcp_xmit(struct __sk_buff *skb,
    struct trustix_kudp_tx_route_value *route,
    const struct trustix_tixt_tx_route_gso_args *args) __ksym;

extern int trustix_kernel_skb_kudp_tx_store_l2_l3_l4(struct __sk_buff *skb,
                                                  const unsigned char *l2,
                                                  const unsigned char *l3,
                                                  const unsigned char *l4,
                                                  __u32 l4_len) __ksym;

struct trustix_kudp_tx_udp_header_args {
    unsigned char l2[14];
    __u32 saddr;
    __u32 daddr;
    __u16 source;
    __u16 dest;
    __u16 ip_tot_len;
    __u16 udp_len;
    __u16 ip_check_base;
    __u16 pad0;
    __u32 pad1;
    unsigned long long flow_id;
    unsigned long long sequence;
    __u32 payload_len;
    __u32 flags;
};

extern int trustix_kernel_skb_kudp_tx_build_udp_header(struct __sk_buff *skb,
    const struct trustix_kudp_tx_udp_header_args *args) __ksym;
extern int trustix_kernel_skb_kudp_tx_finalize_udp_header(struct __sk_buff *skb,
    const struct trustix_kudp_tx_udp_header_args *args, __u32 clear_flags) __ksym;
extern int trustix_kernel_skb_kudp_tx_push_udp_header(struct __sk_buff *skb,
    const struct trustix_kudp_tx_udp_header_args *args, __u32 flags) __ksym;

SEC("tc/ingress")
int trustix_skb_clear_tx_offload_tc(struct __sk_buff *skb)
{
    return trustix_kernel_skb_clear_tx_offload(skb, 0);
}

SEC("tc/ingress")
int trustix_skb_fix_inner_tcp_csum_tc(struct __sk_buff *skb)
{
    return trustix_kernel_skb_fix_inner_tcp_csum(skb, 0, 0, 0);
}

SEC("tc/ingress")
int trustix_skb_kudp_rx_decap_l2_tc(struct __sk_buff *skb)
{
    return trustix_kernel_skb_kudp_rx_decap_l2(skb, 0, 0, 0, 0);
}

SEC("tc/ingress")
int trustix_skb_kudp_rx_decap_l2_dev_tc(struct __sk_buff *skb)
{
    struct trustix_kudp_rx_decap_l2_dev_args args = {};

    return trustix_kernel_skb_kudp_rx_decap_l2_dev(skb, &args);
}

SEC("tc/ingress")
int trustix_skb_kudp_rx_parse_decap_l2_tc(struct __sk_buff *skb)
{
    struct trustix_kudp_rx_parse_args args = {};

    return trustix_kernel_skb_kudp_rx_parse_decap_l2(skb, &args);
}

SEC("tc/ingress")
int trustix_skb_tixt_fix_outer_tcp_csum_tc(struct __sk_buff *skb)
{
    return trustix_kernel_skb_tixt_fix_outer_tcp_csum(skb, 0);
}

SEC("tc/ingress")
int trustix_skb_tixt_tx_finalize_tcp_header_tc(struct __sk_buff *skb)
{
    struct trustix_tixt_tx_tcp_header_args args = {};

    return trustix_kernel_skb_tixt_tx_finalize_tcp_header(skb, &args, 0);
}

SEC("tc/ingress")
int trustix_skb_tixt_tx_set_tcp_partial_csum_tc(struct __sk_buff *skb)
{
    return trustix_kernel_skb_tixt_tx_set_tcp_partial_csum(skb, 0);
}

SEC("tc/ingress")
int trustix_skb_tixt_tx_push_tcp_header_tc(struct __sk_buff *skb)
{
    struct trustix_tixt_tx_tcp_header_args args = {};

    return trustix_kernel_skb_tixt_tx_push_tcp_header(skb, &args, 0);
}

SEC("tc/ingress")
int trustix_skb_tixt_tx_push_flow_tcp_header_tc(struct __sk_buff *skb)
{
    struct trustix_kudp_tx_flow_value flow = {};
    struct trustix_tixt_tx_flow_header_args args = {};

    return trustix_kernel_skb_tixt_tx_push_flow_tcp_header(skb, &flow, &args);
}

SEC("tc/ingress")
int trustix_skb_tixt_tx_finalize_flow_tcp_header_tc(struct __sk_buff *skb)
{
    struct trustix_kudp_tx_flow_value flow = {};
    struct trustix_tixt_tx_flow_header_args args = {};

    return trustix_kernel_skb_tixt_tx_finalize_flow_tcp_header(skb, &flow, &args);
}

SEC("tc/ingress")
int trustix_skb_tixt_tx_push_route_tcp_header_tc(struct __sk_buff *skb)
{
    struct trustix_kudp_tx_route_value route = {};
    struct trustix_tixt_tx_route_header_args args = {};

    return trustix_kernel_skb_tixt_tx_push_route_tcp_header(skb, &route, &args);
}

SEC("tc/ingress")
int trustix_skb_tixt_tx_segment_route_tcp_gso_tc(struct __sk_buff *skb)
{
    struct trustix_kudp_tx_route_value route = {};
    struct trustix_tixt_tx_route_gso_args args = {};

    return trustix_kernel_skb_tixt_tx_segment_route_tcp_gso(skb, &route, &args);
}

SEC("tc/ingress")
int trustix_skb_tixt_tx_segment_secure_route_tcp_gso_tc(struct __sk_buff *skb)
{
    return trustix_kernel_skb_tixt_tx_segment_secure_route_tcp_gso(
        skb, (struct trustix_kudp_tx_route_value *)0,
        (struct trustix_kudp_tx_flow_value *)0,
        (struct trustix_tixt_tx_secure_route_gso_args *)0);
}

SEC("tc/ingress")
int trustix_skb_tixt_tx_route_tcp_tc(struct __sk_buff *skb)
{
    struct trustix_kudp_tx_route_value route = {};
    struct trustix_tixt_tx_route_gso_args args = {};

    return trustix_kernel_skb_tixt_tx_route_tcp(skb, &route, &args);
}

SEC("tc/ingress")
int trustix_skb_tixt_tx_route_tcp_xmit_tc(struct __sk_buff *skb)
{
    struct trustix_kudp_tx_route_value route = {};
    struct trustix_tixt_tx_route_gso_args args = {};

    return trustix_kernel_skb_tixt_tx_route_tcp_xmit(skb, &route, &args);
}

SEC("tc/ingress")
int trustix_skb_kudp_tx_store_l2_l3_l4_tc(struct __sk_buff *skb)
{
    unsigned char header[94] = {};

    return trustix_kernel_skb_kudp_tx_store_l2_l3_l4(skb, header,
                                                  header + 14,
                                                  header + 34,
                                                  40);
}

SEC("tc/ingress")
int trustix_skb_kudp_tx_build_udp_header_tc(struct __sk_buff *skb)
{
    struct trustix_kudp_tx_udp_header_args args = {};

    return trustix_kernel_skb_kudp_tx_build_udp_header(skb, &args);
}

SEC("tc/ingress")
int trustix_skb_kudp_tx_finalize_udp_header_tc(struct __sk_buff *skb)
{
    struct trustix_kudp_tx_udp_header_args args = {};

    return trustix_kernel_skb_kudp_tx_finalize_udp_header(skb, &args, 0);
}

SEC("tc/ingress")
int trustix_skb_kudp_tx_push_udp_header_tc(struct __sk_buff *skb)
{
    struct trustix_kudp_tx_udp_header_args args = {};

    return trustix_kernel_skb_kudp_tx_push_udp_header(skb, &args, 0);
}

char __license[] SEC("license") = "GPL";
