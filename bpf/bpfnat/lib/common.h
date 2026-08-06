// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Ant Group Corporation.

#ifndef __LIB_COMMON_H_
#define __LIB_COMMON_H_

#include <uapi.h>
#include <bpf/bpf_helpers.h>

#ifndef memset
#define memset __builtin_memset
#endif

#ifndef memcpy
#define memcpy __builtin_memcpy
#endif

#define ETHER_ADDR_LEN 6

#define SELF_IFINDEX 2

#define DROP_INVALID -134
#define DROP_WRITE_ERROR -141
#define DROP_CSUM_L3 -153
#define DROP_CSUM_L4 -154
#define DROP_NAT_NO_MAPPING -167
#define DROP_NAT_UNSUPP_PROTO -168
#define NAT_PUNT_TO_STACK -173

#define IPPROTO_ICMP 1
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

#define ICMP_ECHOREPLY 0
#define ICMP_ECHO 8

#define TUPLE_F_OUT 0 /* Outgoing flow */
#define TUPLE_F_IN 1  /* Incoming flow */

#define PORT_MIN_NAT 0
#define PORT_MAX_NAT 65535

#define IP_CSUM_OFF (offsetof(struct iphdr, check))
#define TCP_CSUM_OFF (offsetof(struct tcphdr, check))
#define UDP_CSUM_OFF (offsetof(struct udphdr, check))

union macaddr {
    struct {
        __u32 p1;
        __u16 p2;
    };
    __u8 addr[ETHER_ADDR_LEN];
};

static __always_inline int eth_load_saddr(struct __sk_buff *skb, __u8 *mac, int off)
{
    return bpf_skb_load_bytes(skb, off + ETH_ALEN, mac, ETH_ALEN);
}

static __always_inline int eth_store_saddr(struct __sk_buff *skb, const __u8 *mac, int off)
{
    return bpf_skb_store_bytes(skb, off + ETH_ALEN, mac, ETH_ALEN, 0);
}

static __always_inline int eth_load_daddr(struct __sk_buff *skb, __u8 *mac, int off)
{
    return bpf_skb_load_bytes(skb, off, mac, ETH_ALEN);
}

static __always_inline int eth_store_daddr(struct __sk_buff *skb, const __u8 *mac, int off)
{
    return bpf_skb_store_bytes(skb, off, mac, ETH_ALEN, 0);
}

static __always_inline void eth_load_addr(void *dst, unsigned char *mac)
{
    unsigned short *d = dst;
    unsigned short *s = (unsigned short *)mac;

    d[0] = s[0];
    d[1] = s[1];
    d[2] = s[2];
}

static __always_inline bool eth_cmp(void *dst, unsigned char *mac)
{
    unsigned short *d = dst;
    unsigned short *s = (unsigned short *)mac;

    if (d[0] == s[0] && d[1] == s[1] && d[2] == s[2]) {
        return true;
    }
    return false;
}

static __always_inline void *ctx_data(const struct __sk_buff *ctx)
{
    return (void *)(unsigned long)ctx->data;
}

static __always_inline void *ctx_data_end(const struct __sk_buff *ctx)
{
    return (void *)(unsigned long)ctx->data_end;
}

static __always_inline bool ____revalidate_data_pull(struct __sk_buff *ctx, void **data_,
                                                     void **data_end_, void **l3,
                                                     const __u32 l3_len, __u32 eth_hlen)
{
    const __u64 tot_len = eth_hlen + l3_len;
    void *data_end;
    void *data;

    data_end = ctx_data_end(ctx);
    data = ctx_data(ctx);
    if (data + tot_len > data_end)
        return false;

    /* Verifier workaround: pointer arithmetic on pkt_end prohibited. */
    *data_ = data;
    *data_end_ = data_end;

    *l3 = data + eth_hlen;
    return true;
}

static __always_inline bool __revalidate_data_pull(struct __sk_buff *ctx, void **data,
                                                   void **data_end, void **l3, const __u32 l3_len)
{
    return ____revalidate_data_pull(ctx, data, data_end, l3, l3_len, ETH_HLEN);
}

#define revalidate_data(ctx, data, data_end, ip)                                                   \
    __revalidate_data_pull(ctx, data, data_end, (void **)ip, sizeof(**ip))

#endif
