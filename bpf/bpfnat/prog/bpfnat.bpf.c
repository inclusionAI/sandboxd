// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Ant Group Corporation.

#include <uapi.h>
#include <bpf/bpf_helpers.h>

#include "common.h"
#include "nat.h"

char _license[] SEC("license") = "GPL";

/*
 * The physical-device programs provide the same host boundary as the
 * iptables POSTROUTING and PREROUTING hooks.  DNAT reversal must run before
 * SNAT so replies to a published port keep the node address and port.
 */
SEC("tc/sandboxd_egress")
int sandboxd_egress_bpfnat(struct __sk_buff *skb)
{
    struct ipv4_nat_target target = {
        .min_port = PORT_MIN_NAT,
        .max_port = PORT_MAX_NAT,
        .addr = 0,
        .egress_gateway = 0,
    };
    int ret = 0;

    dnat_v4_rev_nat(skb);

    if (snat_v4_prepare_state(skb, &target))
        ret = snat_v4_nat(skb, &target);

    if (ret < 0)
        return TC_ACT_SHOT;
    return TC_ACT_OK;
}

SEC("tc/sandboxd_ingress")
int sandboxd_ingress_bpfnat(struct __sk_buff *skb)
{
    struct ipv4_nat_target target = {
        .min_port = PORT_MIN_NAT,
        .max_port = PORT_MAX_NAT,
        .addr = 0,
        .egress_gateway = 0,
    };

    snat_v4_rev_nat(skb, &target);
    dnat_v4_nat(skb);
    return TC_ACT_OK;
}

/* Locally generated traffic to a node address is routed through lo. */
SEC("tc/sandboxd_local_ingress")
int sandboxd_local_ingress_bpfnat(struct __sk_buff *skb)
{
    __u32 key = 0;
    __u32 *ifindex;

    if (dnat_v4_nat(skb) <= 0)
        return TC_ACT_OK;

    ifindex = bpf_map_lookup_elem(&LOCAL_REDIRECT_MAP, &key);
    if (!ifindex || !*ifindex)
        return TC_ACT_SHOT;

    return bpf_redirect_neigh(*ifindex, 0, 0, 0);
}

/* Replies to local DNAT enter the host through the sandbox bridge. */
SEC("tc/sandboxd_bridge_ingress")
int sandboxd_bridge_ingress_bpfnat(struct __sk_buff *skb)
{
    /* ARP and IPv6 share this bridge, so a non-IPv4 parse is not an error. */
    dnat_v4_rev_nat(skb);
    return TC_ACT_OK;
}
