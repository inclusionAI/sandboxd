// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Ant Group Corporation.

#include <uapi.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

#define ACL_ALLOW 1
#define ACL_DENY 2

#define ACL_INGRESS 1
#define ACL_EGRESS 2

#define IPV4_FRAGMENT_MASK 0x3fff
#define PROTOCOL_TCP 6
#define PROTOCOL_UDP 17

struct policy_value {
    __u64 generation;
    __be32 sandbox_ip;
    __u8 traffic_enabled;
    __u8 traffic_default;
    __u8 dns_enabled;
    __u8 reserved;
};

struct rule_key {
    __u64 generation;
    __u32 ifindex;
    __be32 peer_ip;
    __be16 peer_port;
    __u8 direction;
    __u8 protocol;
    __u32 reserved;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct policy_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} POLICY_MAP SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct rule_key);
    __type(value, __u8);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} RULE_MAP SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __be32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} CONFIG_MAP SEC(".maps");

static __always_inline int rule_action(struct policy_value *policy, __u32 ifindex, __u8 direction,
                                       __u8 protocol, __be32 peer_ip, __be16 peer_port)
{
    struct rule_key key = {
        .generation = policy->generation,
        .ifindex = ifindex,
        .peer_ip = peer_ip,
        .peer_port = peer_port,
        .direction = direction,
        .protocol = protocol,
    };
    __u8 *action;
    bool allowed = false;

#define LOOKUP_RULE()                                                                              \
    do {                                                                                           \
        action = bpf_map_lookup_elem(&RULE_MAP, &key);                                             \
        if (action && *action == ACL_DENY)                                                         \
            return ACL_DENY;                                                                       \
        if (action && *action == ACL_ALLOW)                                                        \
            allowed = true;                                                                        \
    } while (0)

    LOOKUP_RULE();
    key.peer_port = 0;
    LOOKUP_RULE();
    key.protocol = 0;
    key.peer_port = peer_port;
    LOOKUP_RULE();
    key.peer_port = 0;
    LOOKUP_RULE();

#undef LOOKUP_RULE

    return allowed ? ACL_ALLOW : policy->traffic_default;
}

static __always_inline int enforce(struct __sk_buff *skb, __u8 direction)
{
    __u32 ifindex = skb->ifindex;
    struct policy_value *policy = bpf_map_lookup_elem(&POLICY_MAP, &ifindex);
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    __be32 peer_ip;
    __be16 peer_port = 0;
    __u8 protocol;
    __u32 config_key = 0;
    __be32 *bridge_ip;

    if (!policy || (!policy->traffic_enabled && !policy->dns_enabled))
        return TC_ACT_OK;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_SHOT;
    if (eth->h_proto == bpf_htons(ETH_P_ARP))
        return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_SHOT;

    iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end || iph->ihl != 5)
        return TC_ACT_SHOT;
    if (iph->frag_off & bpf_htons(IPV4_FRAGMENT_MASK))
        return TC_ACT_SHOT;

    if (direction == ACL_EGRESS) {
        if (iph->saddr != policy->sandbox_ip)
            return TC_ACT_SHOT;
        peer_ip = iph->daddr;
    } else {
        if (iph->daddr != policy->sandbox_ip)
            return TC_ACT_SHOT;
        peer_ip = iph->saddr;
    }
    protocol = iph->protocol;

    if (protocol == PROTOCOL_TCP) {
        struct tcphdr *tcp = (void *)(iph + 1);
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_SHOT;
        peer_port = direction == ACL_EGRESS ? tcp->dest : tcp->source;
    } else if (protocol == PROTOCOL_UDP) {
        struct udphdr *udp = (void *)(iph + 1);
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_SHOT;
        peer_port = direction == ACL_EGRESS ? udp->dest : udp->source;
    }

    if (policy->dns_enabled && (protocol == PROTOCOL_TCP || protocol == PROTOCOL_UDP) &&
        peer_port == bpf_htons(53)) {
        bridge_ip = bpf_map_lookup_elem(&CONFIG_MAP, &config_key);
        if (bridge_ip && peer_ip == *bridge_ip)
            return TC_ACT_OK;
        return TC_ACT_SHOT;
    }

    if (!policy->traffic_enabled)
        return TC_ACT_OK;
    return rule_action(policy, ifindex, direction, protocol, peer_ip, peer_port) == ACL_ALLOW
               ? TC_ACT_OK
               : TC_ACT_SHOT;
}

SEC("tc/sandboxd_acl_egress")
int sandboxd_acl_egress(struct __sk_buff *skb) { return enforce(skb, ACL_EGRESS); }

SEC("tc/sandboxd_acl_ingress")
int sandboxd_acl_ingress(struct __sk_buff *skb) { return enforce(skb, ACL_INGRESS); }
