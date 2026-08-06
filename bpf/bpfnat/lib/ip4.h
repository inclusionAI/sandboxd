// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Ant Group Corporation.

#ifndef __LIB_IP4_H_
#define __LIB_IP4_H_

#include <uapi.h>
#include <bpf_endian.h>

#include "common.h"
#include "log.h"

static __always_inline int ipv4_hdrlen(const struct iphdr *ip4) { return ip4->ihl * 4; }

static __always_inline void ipv4_addr_copy(__be32 *dst, const __be32 *src) { *dst = *src; }

static __always_inline int ipv4_store_daddr(struct __sk_buff *skb, __be32 *addr, int off)
{
    return bpf_skb_store_bytes(skb, off + offsetof(struct iphdr, daddr), addr, 4, 0);
}

static __always_inline int ipv4_store_saddr(struct __sk_buff *skb, __be32 *addr, int off)
{
    return bpf_skb_store_bytes(skb, off + offsetof(struct iphdr, saddr), addr, 4, 0);
}

static __always_inline bool ipv4_is_not_first_fragment(const struct iphdr *ip4)
{
    /* Ignore "More fragments" bit to catch all fragments but the first */
    return ip4->frag_off & bpf_htons(0x1FFF);
}

/* Simply a reverse of ipv4_is_not_first_fragment to avoid double negative. */
static __always_inline bool ipv4_has_l4_header(const struct iphdr *ip4)
{
    return !ipv4_is_not_first_fragment(ip4);
}

#endif
