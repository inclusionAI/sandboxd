// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Ant Group Corporation.

#ifndef __LIB_CSUM_H_
#define __LIB_CSUM_H_

#include <uapi.h>
#include <bpf_helpers.h>

#define TCP_CSUM_OFF (offsetof(struct tcphdr, check))
#define UDP_CSUM_OFF (offsetof(struct udphdr, check))

struct csum_offset {
    __u16 offset;
    __u16 flags;
};

/**
 * Determins the L4 checksum field offset and required flags
 * @arg nexthdr	L3 nextheader field
 * @arg off	Pointer to uninitialied struct csum_offset struct
 *
 * Sets off.offset to offset from start of L4 header to L4 checksum field
 * and off.flags to the required flags, namely BPF_F_MARK_MANGLED_0 for UDP.
 * For unknown L4 protocols or L4 protocols which do not have a checksum
 * field, off is initialied to 0.
 */
static __always_inline void csum_l4_offset_and_flags(__u8 nexthdr, struct csum_offset *off)
{
    switch (nexthdr) {
    case IPPROTO_TCP:
        off->offset = TCP_CSUM_OFF;
        break;
    case IPPROTO_UDP:
        off->offset = UDP_CSUM_OFF;
        off->flags = BPF_F_MARK_MANGLED_0;
        break;
    case IPPROTO_ICMP:
        break;
    }
}

/**
 * Helper to change L4 checksum
 * @arg ctx	Packet
 * @arg l4_off	Offset to L4 header
 * @arg csum	Pointer to csum_offset as extracted by csum_l4_offset_and_flags()
 * @arg from	From value or 0 if to contains csum diff
 * @arg to	To value or a csum diff
 * @arg flags	Additional flags to be passed to l4_csum_replace()
 */
static __always_inline int csum_l4_replace(struct __sk_buff *skb, __u64 l4_off,
                                           const struct csum_offset *csum, __be32 from, __be32 to,
                                           int flags)
{
    return bpf_l4_csum_replace(skb, l4_off + csum->offset, from, to, flags | csum->flags);
}

static __always_inline int ipv4_csum_update_by_diff(struct __sk_buff *skb, int l3_off, __u64 diff)
{
    return bpf_l3_csum_replace(skb, l3_off + offsetof(struct iphdr, check), 0, diff, 0);
}

#endif /* __LB_H_ */
