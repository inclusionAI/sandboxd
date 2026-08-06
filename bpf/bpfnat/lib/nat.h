// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Ant Group Corporation.

#ifndef __LIB_NAT_H_
#define __LIB_NAT_H_

#include <bpf/bpf_helpers.h>
#include "common.h"
#include "csum.h"
#include "ip4.h"
#include "log.h"
#include "time.h"

#define SNAT_MAPPING_IPV4_SIZE 415744
#define EGRESS_POLICY_MAP_SIZE 1024
#define DNAT_RULES_MAP_SIZE 1024
#define SNAT_CONFIG_MAP_SIZE 32
#define POD_PORT_MAP_SIZE 256
#define LOCAL_REDIRECT_MAP_SIZE 1

#define EGRESS_STATIC_PREFIX (sizeof(__be32) * 8)
#define EGRESS_PREFIX_LEN(PREFIX) (EGRESS_STATIC_PREFIX + (PREFIX))
#define EGRESS_IPV4_PREFIX EGRESS_PREFIX_LEN(32)

#define PORT_MAX 65536

/* default available ports for bpfnat: [30001, 65536) */
#define DEFAULT_PORT_MIN 30001
#define DEFAULT_PORT_MAX PORT_MAX

/* src port assignment retry counter */
#define RETRY 512

#define SNAT_CONFIG_PORT_MIN_IDX 1
#define SNAT_CONFIG_PORT_MAX_IDX 2

#define CLOCK_BOOTTIME 0x7

#define TCP_FLAG_OFFSET 12

#define SECOND_TO_MICRO(second) (__u64)(second * (__u64)1000000000)
#define DEFAULT_TIMEOUT_NON_TCP 60
#define DEFAULT_TIMEOUT_TCP_SYN 60
#define DEFAULT_TIMEOUT_TCP_ESTB 21600
#define DEFAULT_TIMEOUT_TCP_CLOSE 10

enum nat_dir {
    NAT_DIR_EGRESS = TUPLE_F_OUT,
    NAT_DIR_INGRESS = TUPLE_F_IN,
};

enum ct_action {
    ACTION_UNSPEC,
    ACTION_CREATE,
    ACTION_CLOSE,
};

enum ct_status { CT_UNUSE, CT_CREATE, CT_ESTABLISH, CT_CLOSE };

enum nat_type { NAT_TYPE_SNAT, NAT_TYPE_DNAT };

struct ipv4_ct_tuple {
    /* Address fields are reversed, i.e.,
     * these field names are correct for reply direction traffic.
     */
    __be32 daddr;
    __be32 saddr;
    /* The order of dport+sport must not be changed!
     * These field names are correct for original direction traffic.
     */
    __be16 dport;
    __be16 sport;
    __u8 nexthdr;
    __u8 flags;
    __u16 pad;
};

union tcp_flags {
    struct {
        __u8 upper_bits;
        __u8 lower_bits;
        __u16 pad;
    };
    __u32 value;
};

struct nat_entry {
    __u64 created;
    __u64 host_local; /* Only single bit used. */
    __u64 pad1;       /* Future use. */
    __u64 pad2;       /* Future use. */
};

struct ipv4_nat_entry {
    struct nat_entry common;
    union {
        struct {
            __be32 to_saddr;
            __be16 to_sport;
        };
        struct {
            __be32 to_daddr;
            __be16 to_dport;
        };
    };
#ifdef BPF_TIMER_ENABLED
    struct bpf_timer timer;
#else
    __u32 last_access_time;
#endif
    int status;
    int type;
};

struct ipv4_nat_target {
    __be32 addr;
    const __u16 min_port; /* host endianness */
    const __u16 max_port; /* host endianness */
    bool egress_gateway;  /* NAT is needed because of an egress gateway policy */
};

struct dnat_target {
    __be32 addr;
    __u16 port;
};

struct egress_gw_policy_key {
    /* BPF LPM trie keys begin with a native-endian prefix length. Keeping the
     * field in this sandboxd-owned type avoids a CO-RE dependency on the
     * kernel's bpf_lpm_trie_key spelling, which changed in Linux 6.6.
     */
    __u32 prefixlen;
    __u32 saddr;
    __u32 daddr;
};

struct egress_gw_policy_entry {
    __u32 egress_ip;
};

struct dnat_rules_key {
    __u16 dport;
    __u8 protocol; // TCP/UDP
    __u8 pad;      // padding for BPF 4-byte alignment
};

struct dnat_rules_entry {
    __u32 daddr;
    __u16 dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct ipv4_ct_tuple);
    __type(value, struct ipv4_nat_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, SNAT_MAPPING_IPV4_SIZE);
} SNAT_MAPPING_IPV4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct egress_gw_policy_key);
    __type(value, struct egress_gw_policy_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, EGRESS_POLICY_MAP_SIZE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} EGRESS_POLICY_MAP SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct dnat_rules_key);
    __type(value, struct dnat_rules_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, DNAT_RULES_MAP_SIZE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} DNAT_RULES_MAP SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, SNAT_CONFIG_MAP_SIZE);
} SNAT_CONFIG_MAP SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, POD_PORT_MAP_SIZE);
} POD_PORT_MAP SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, LOCAL_REDIRECT_MAP_SIZE);
} LOCAL_REDIRECT_MAP SEC(".maps");

static __always_inline int l4_modify_port(struct __sk_buff *skb, int l4_off, int port_off,
                                          struct csum_offset *csum_off, __be16 port,
                                          __be16 old_port)
{
    if (bpf_l4_csum_replace(skb, l4_off + csum_off->offset, old_port, port,
                            sizeof(port) | csum_off->flags) < 0)
        return -1; /* TODO: status*/
    if (bpf_skb_store_bytes(skb, l4_off + port_off, &port, sizeof(port), 0) < 0)
        return -1; /* TODO: status*/
    return 0;
}

static __always_inline struct egress_gw_policy_entry *lookup_ip4_egress_gw_policy(__be32 saddr,
                                                                                  __be32 daddr)
{
    struct egress_gw_policy_key key = {
        .prefixlen = 32,
        .saddr = saddr,
        .daddr = daddr,
    };
    return (struct egress_gw_policy_entry *)bpf_map_lookup_elem(&EGRESS_POLICY_MAP, &key);
}

static __always_inline bool egress_gw_snat_needed(const struct iphdr *ip4, __be32 *snat_addr)
{
    struct egress_gw_policy_entry *egress_gw_policy;

    egress_gw_policy = lookup_ip4_egress_gw_policy(ip4->saddr, ip4->daddr);
    if (!egress_gw_policy)
        return false;

    *snat_addr = egress_gw_policy->egress_ip;
    return true;
}

static __always_inline struct dnat_rules_entry *
lookup_ip4_dnat_rules(__be32 saddr, __be32 daddr, __u16 sport, __u16 dport, __u8 protocol)
{
    struct dnat_rules_key key = {
        .dport = dport,
        .protocol = protocol,
    };
    return (struct dnat_rules_entry *)bpf_map_lookup_elem(&DNAT_RULES_MAP, &key);
}

static __always_inline bool dnat_needed(const struct ipv4_ct_tuple *tuple, __be32 *daddr,
                                        __u16 *dport)
{
    struct dnat_rules_entry *target;

    target = lookup_ip4_dnat_rules(tuple->saddr, tuple->daddr, tuple->sport, tuple->dport,
                                   tuple->nexthdr);
    if (!target)
        return false;

    *daddr = target->daddr;
    *dport = target->dport;
    return true;
}

static __always_inline void snat_v4_init_tuple(const struct iphdr *ip4, enum nat_dir dir,
                                               struct ipv4_ct_tuple *tuple)
{
    tuple->nexthdr = ip4->protocol;
    tuple->daddr = ip4->daddr;
    tuple->saddr = ip4->saddr;
    tuple->flags = dir;
}

static __always_inline void snat_v4_swap_tuple(const struct ipv4_ct_tuple *otuple,
                                               struct ipv4_ct_tuple *rtuple)
{
    memset(rtuple, 0, sizeof(*rtuple));
    rtuple->nexthdr = otuple->nexthdr;
    rtuple->daddr = otuple->saddr;
    rtuple->saddr = otuple->daddr;
    rtuple->dport = otuple->sport;
    rtuple->sport = otuple->dport;
    rtuple->flags = otuple->flags == NAT_DIR_EGRESS ? NAT_DIR_INGRESS : NAT_DIR_EGRESS;
}

static __always_inline void *__snat_lookup(void *map, const void *tuple)
{
    return bpf_map_lookup_elem(map, tuple);
}

static __always_inline int __snat_update(void *map, const void *otuple, const void *ostate,
                                         const void *rtuple, const void *rstate)
{
    int ret;

    ret = bpf_map_update_elem(map, rtuple, rstate, BPF_NOEXIST);
    if (!ret) {
        ret = bpf_map_update_elem(map, otuple, ostate, BPF_NOEXIST);
        if (ret)
            bpf_map_delete_elem(map, rtuple);
    }
    return ret;
}

static __always_inline void __snat_delete(void *map, const void *otuple, const void *rtuple)
{
    bpf_map_delete_elem(map, otuple);
    bpf_map_delete_elem(map, rtuple);
}

static __always_inline void *snat_v4_lookup(const struct ipv4_ct_tuple *tuple)
{
    return __snat_lookup(&SNAT_MAPPING_IPV4, tuple);
}

static __always_inline void snat_v4_delete(const struct ipv4_ct_tuple *otuple,
                                           const struct ipv4_ct_tuple *rtuple)
{
    __snat_delete(&SNAT_MAPPING_IPV4, otuple, rtuple);
}

static __always_inline int snat_v4_reverse_tuple(const struct ipv4_ct_tuple *otuple,
                                                 struct ipv4_ct_tuple *rtuple)
{
    struct ipv4_nat_entry *ostate;

    ostate = snat_v4_lookup(otuple);
    if (ostate) {
        snat_v4_swap_tuple(otuple, rtuple);
        rtuple->daddr = ostate->to_saddr;
        rtuple->dport = ostate->to_sport;
    }

    return ostate ? 0 : -1;
}

static __always_inline void snat_v4_delete_tuples(struct ipv4_ct_tuple *otuple)
{
    struct ipv4_ct_tuple rtuple;

    if (otuple->flags & TUPLE_F_IN)
        return;
    if (!snat_v4_reverse_tuple(otuple, &rtuple))
        snat_v4_delete(otuple, &rtuple);
}

static __always_inline void *__snat_config_lookup(void *map, const void *key)
{
    return bpf_map_lookup_elem(map, key);
}

static __always_inline void *snat_config_lookup(__u32 *config_name)
{
    return __snat_config_lookup(&SNAT_CONFIG_MAP, config_name);
}

static __always_inline __u32 get_port_config(__u32 port_config_idx, __u32 port_default)
{
    __u32 port;
    __u32 *port_config;

    port_config = snat_config_lookup(&port_config_idx);
    if (port_config == NULL) {
        port = port_default;
    } else {
        port = *port_config;
    }

    return port;
}

static __always_inline __u32 get_random_port(void)
{
    __u32 port, port_min, port_max;

    port_min = get_port_config(SNAT_CONFIG_PORT_MIN_IDX, DEFAULT_PORT_MIN);
    port_max = get_port_config(SNAT_CONFIG_PORT_MAX_IDX, DEFAULT_PORT_MAX);
    if (!(port_min > 0 && port_min < port_max && port_max <= PORT_MAX)) {
        port_min = DEFAULT_PORT_MIN;
        port_max = DEFAULT_PORT_MAX;
    }

    port = bpf_get_prandom_u32() % (port_max - port_min);

#ifdef BPFNAT_AUDIT
    log_debug(SNAT, "port_min: %d, port_max: %d, chosen_port: %d", port_min, port_max,
              port + port_min);
#endif

    return port + port_min;
}

static __always_inline bool is_port_valid(struct ipv4_ct_tuple *rtuple)
{
    __u32 port_min, port_max;
    __u32 pod_port_key = bpf_ntohs(rtuple->dport) << 16 | rtuple->nexthdr;

    port_min = get_port_config(SNAT_CONFIG_PORT_MIN_IDX, DEFAULT_PORT_MIN);
    port_max = get_port_config(SNAT_CONFIG_PORT_MAX_IDX, DEFAULT_PORT_MAX);
    if (!(port_min > 0 && port_min < port_max && port_max <= PORT_MAX)) {
        port_min = DEFAULT_PORT_MIN;
        port_max = DEFAULT_PORT_MAX;
    }

    // port is valid if:
    // 1. not used by other process running directly in pod;
    // 2. not used by other instance connecting the same remote ip and remote port
    // 3. port is in the port range for instance.
    return !bpf_map_lookup_elem(&POD_PORT_MAP, &pod_port_key) && !snat_v4_lookup(rtuple) &&
           (bpf_ntohs(rtuple->dport) >= port_min && bpf_ntohs(rtuple->dport) < port_max);
}

static __always_inline int alloc_port_v4(struct ipv4_ct_tuple *ct_tuple, __be16 *nat_port)
{
    struct ipv4_ct_tuple key;

    memcpy(&key, ct_tuple, sizeof(key));

    for (__u16 cnt = 0; cnt < RETRY; ++cnt) {
        key.dport = bpf_htons(get_random_port());
        if (is_port_valid(&key)) {
#ifdef BPFNAT_AUDIT
            uint32_t pod_port_key = bpf_ntohs(key.dport) << 16 | key.nexthdr;
            log_debug(SNAT, "[alloc_port_v4] dport: %d, proto: %d, key: %lu\n",
                      bpf_ntohs(key.dport), key.nexthdr, pod_port_key);
#endif
            *nat_port = key.dport;
            return 0;
        }
    }
    log_debug(SNAT, "alloc port failed.");
    return -1;
}

#ifdef BPF_TIMER_ENABLED
static __always_inline int nat_expire_time(const struct ipv4_ct_tuple *tuple, enum ct_action action,
                                           __u32 *expire_time)
{
    __u32 timeout_config_idx = 0;
    __u32 *timeout = snat_config_lookup(&timeout_config_idx);

    if (tuple->nexthdr != IPPROTO_TCP) {
        *expire_time = timeout != NULL ? *timeout : DEFAULT_TIMEOUT_NON_TCP;
        return 0;
    }

    switch (action) {
    case ACTION_CREATE:
        *expire_time = DEFAULT_TIMEOUT_TCP_SYN;
        return 0;
    case ACTION_UNSPEC:
        *expire_time = timeout != NULL ? *timeout : DEFAULT_TIMEOUT_TCP_ESTB;
        return 0;
    case ACTION_CLOSE:
        *expire_time = DEFAULT_TIMEOUT_TCP_CLOSE;
        return 0;
    default:
        log_error(SNAT, "invalid action for TCP connection");
        return -1;
    }
}

static __always_inline int snat_timer_cb(void *map, struct ipv4_ct_tuple *tuple)
{
    snat_v4_delete_tuples(tuple);

    return 0;
}

static __always_inline int snat_update_timer(struct ipv4_ct_tuple *tuple, enum ct_action action)
{
    struct ipv4_nat_entry *nat_entry;
    __u32 expire_time;

    nat_entry = snat_v4_lookup(tuple);

    if (nat_entry == NULL) {
        log_debug(SNAT, "failed to find snat entry for timer updating");
        return -1;
    }

    if (nat_expire_time(tuple, action, &expire_time) < 0)
        return -1;

    bpf_timer_start(&nat_entry->timer, SECOND_TO_MICRO(expire_time), 0);

    return 0;
}

static __always_inline int dnat_update_timer(struct ipv4_ct_tuple *tuple,
                                             struct ipv4_nat_entry *entry, enum ct_action action)
{
    struct ipv4_ct_tuple reverse;

    snat_v4_swap_tuple(tuple, &reverse);
    reverse.saddr = entry->to_daddr;
    reverse.sport = entry->to_dport;
    return snat_update_timer(&reverse, action);
}
#else
static __always_inline int snat_update_access_time(struct ipv4_ct_tuple *tuple,
                                                   enum ct_action action)
{
    struct ipv4_nat_entry *entry;
    __u32 now;

    entry = snat_v4_lookup(tuple);
    if (!entry) {
        return -1;
    }

    /* If TCP, update connection status */
    if (tuple->nexthdr == IPPROTO_TCP) {
        if (entry->status == CT_UNUSE) {
            log_error(SNAT, "invalid status for TCP connection");
            return -1;
        }
        switch (action) {
        case ACTION_CREATE:
            entry->status = CT_CREATE;
            break;
        case ACTION_UNSPEC:
            if (entry->status == CT_CREATE)
                entry->status = CT_ESTABLISH;
            break;
        case ACTION_CLOSE:
            entry->status = CT_CLOSE;
            break;
        default:
            log_error(SNAT, "invalid action for TCP connection");
            return -1;
        }
    }

    now = bpf_now_sec();
    entry->last_access_time = now;

    return bpf_map_update_elem(&SNAT_MAPPING_IPV4, tuple, entry, 0);
}

static __always_inline int dnat_update_access_time(struct ipv4_ct_tuple *tuple,
                                                   enum ct_action action)
{
    struct ipv4_nat_entry *entry;
    __u32 now;

    entry = snat_v4_lookup(tuple);
    if (!entry) {
        log_debug(SNAT, "dnat_update_access_time entry not found\n");
        return -1;
    }

    now = bpf_now_sec();
    entry->last_access_time = now;

    return bpf_map_update_elem(&SNAT_MAPPING_IPV4, tuple, entry, 0);
}
#endif

static __always_inline int snat_v4_update(const struct ipv4_ct_tuple *otuple,
                                          struct ipv4_nat_entry *ostate,
                                          const struct ipv4_ct_tuple *rtuple,
                                          const struct ipv4_nat_entry *rstate)
{
#ifndef BPF_TIMER_ENABLED
    __u32 now = bpf_now_sec();
    ostate->last_access_time = now;
#endif

    return __snat_update(&SNAT_MAPPING_IPV4, otuple, ostate, rtuple, rstate);
}

static __always_inline bool snat_v4_prepare_state(struct __sk_buff *skb,
                                                  struct ipv4_nat_target *target)
{
    void *data, *data_end;
    struct iphdr *ip4;

    if (!revalidate_data(skb, &data, &data_end, &ip4))
        return false;

    if (egress_gw_snat_needed(ip4, &target->addr)) {
        target->egress_gateway = true;
        return true;
    }

    return false;
}

static __always_inline int snat_v4_new_mapping(struct __sk_buff *skb, struct ipv4_ct_tuple *otuple,
                                               struct ipv4_nat_entry *ostate,
                                               const struct ipv4_nat_target *target,
                                               const struct dnat_target *dnat_target,
                                               enum ct_action action, int nat_type)
{
    int ret = DROP_NAT_NO_MAPPING;
    struct ipv4_ct_tuple rtuple;  // reverse nat key
    struct ipv4_nat_entry rstate; // reverse nat entry
    __be16 nat_port;

#ifdef BPF_TIMER_ENABLED
    struct ipv4_nat_entry *updated_tuple;
    struct ipv4_ct_tuple *timer_tuple;
    __u32 expire_time;
#endif

    /* initialize original entry and reverse entry to zero */
    memset(&rstate, 0, sizeof(rstate));
    memset(ostate, 0, sizeof(*ostate));

    if (nat_type == NAT_TYPE_SNAT) {
        /* set reverse entry nat-dst addr/port as original key src addr/port */
        rstate.to_daddr = otuple->saddr;
        rstate.to_dport = otuple->sport;

        /* set original entry nat-src addr as target src addr */
        ostate->to_saddr = target->addr;

        /* prepare reverse key */
        snat_v4_swap_tuple(otuple, &rtuple);
        rtuple.dport = ostate->to_sport = otuple->sport;
        rtuple.daddr = target->addr;
    } else if (nat_type == NAT_TYPE_DNAT) {
        rstate.to_saddr = otuple->daddr;
        rstate.to_sport = otuple->dport;

        ostate->to_daddr = dnat_target->addr;
        ostate->to_dport = dnat_target->port;

        snat_v4_swap_tuple(otuple, &rtuple);
        rtuple.saddr = dnat_target->addr;
        rtuple.sport = dnat_target->port;
    } else {
        log_error(SNAT, "invalid nat_type");
        return -1;
    }
    ostate->type = rstate.type = nat_type;

    if (nat_type == NAT_TYPE_SNAT) {
        /* initialize original entry status */
        if (otuple->nexthdr != IPPROTO_TCP) {
            ostate->status = CT_UNUSE;
        } else {
            switch (action) {
            case ACTION_CREATE:
                ostate->status = CT_CREATE;
                break;
            case ACTION_UNSPEC:
                ostate->status = CT_ESTABLISH;
                break;
            case ACTION_CLOSE:
                ostate->status = CT_CLOSE;
                break;
            default:
                log_error(SNAT, "invalid action for TCP connection");
                return -1;
            }
        }

        if (is_port_valid(&rtuple)) {
#ifdef BPFNAT_AUDIT
            uint32_t pod_port_key = bpf_ntohs(rtuple.dport) << 16 | rtuple.nexthdr;
            log_debug(SNAT, "[port valid] rtuple dport: %d, proto: %d, key: %lu\n",
                      bpf_ntohs(rtuple.dport), rtuple.nexthdr, pod_port_key);
#endif
            ret = snat_v4_update(otuple, ostate, &rtuple, &rstate);
        } else {
            /* Source port confliction. Need to choose another available sport. */
            ret = alloc_port_v4(&rtuple, &nat_port);
            if (!ret) {
                rtuple.dport = ostate->to_sport = nat_port;
                ret = snat_v4_update(otuple, ostate, &rtuple, &rstate);
            }
        }

#ifdef BPFNAT_AUDIT
        log_debug(SNAT, "otuple sport: %u, ostate to_sport: %u, rtuple dport: %u",
                  bpf_ntohs(otuple->sport), bpf_ntohs(ostate->to_sport), bpf_ntohs(rtuple.dport));
#endif

    } else {
        ret = snat_v4_update(otuple, ostate, &rtuple, &rstate);
    }

    if (ret)
        return DROP_NAT_NO_MAPPING;

#ifdef BPF_TIMER_ENABLED
    timer_tuple = nat_type == NAT_TYPE_SNAT ? otuple : &rtuple;
    updated_tuple = snat_v4_lookup(timer_tuple);
    if (!updated_tuple)
        return DROP_NAT_NO_MAPPING;

    if (bpf_timer_init(&updated_tuple->timer, &SNAT_MAPPING_IPV4, CLOCK_BOOTTIME) != 0) {
        log_error(SNAT, "failed to init bpf_timer");
        return -1;
    }
    bpf_timer_set_callback(&updated_tuple->timer, snat_timer_cb);

    if (nat_expire_time(timer_tuple, action, &expire_time) < 0)
        return -1;
    bpf_timer_start(&updated_tuple->timer, SECOND_TO_MICRO(expire_time), 0);
#endif

    return 0;
}

static __always_inline int snat_v4_nat_handle_mapping(
    struct __sk_buff *skb, struct ipv4_ct_tuple *tuple, struct ipv4_nat_entry **state,
    struct ipv4_nat_entry *tmp, __u32 off, const struct ipv4_nat_target *target,
    const struct dnat_target *dnat_target, enum ct_action action, int nat_type)
{
    int ret = 0;
    struct ipv4_nat_entry *result;

    /* check whether snat has been recorded */
    result = snat_v4_lookup(tuple);
    if (result) {
        *state = result;
#ifdef BPF_TIMER_ENABLED
        if (nat_type == NAT_TYPE_SNAT)
            ret = snat_update_timer(tuple, action);
        else
            ret = dnat_update_timer(tuple, result, action);
#else
        if (nat_type == NAT_TYPE_SNAT)
            ret = snat_update_access_time(tuple, action);
        else
            ret = dnat_update_access_time(tuple, action);
#endif
        goto ret_val;
    }

    ret = snat_v4_new_mapping(skb, tuple, (*state = tmp), target, dnat_target, action, nat_type);
ret_val:
    return ret;
}

static __always_inline int snat_v4_rewrite_egress(struct __sk_buff *skb,
                                                  struct ipv4_ct_tuple *tuple,
                                                  struct ipv4_nat_entry *state, __u32 off,
                                                  bool has_l4_header)
{
    int ret, flags = BPF_F_PSEUDO_HDR;
    struct csum_offset csum = {};
    __be32 sum_l4 = 0, sum;

    if (state->to_saddr == tuple->saddr && state->to_sport == tuple->sport) {
        ret = 0;
        goto ret_val;
    }
    sum = bpf_csum_diff(&tuple->saddr, 4, &state->to_saddr, 4, 0);
    if (has_l4_header) {
        csum_l4_offset_and_flags(tuple->nexthdr, &csum);

        if (state->to_sport != tuple->sport) {
            switch (tuple->nexthdr) {
            case IPPROTO_TCP:
            case IPPROTO_UDP:
                ret = l4_modify_port(skb, off, offsetof(struct tcphdr, source), &csum,
                                     state->to_sport, tuple->sport);
                if (ret < 0)
                    goto ret_val;
                break;
            case IPPROTO_ICMP: {
                __be32 from, to;

                if (bpf_skb_store_bytes(skb, off + offsetof(struct sandboxd_icmphdr, echo.id),
                                        &state->to_sport, sizeof(state->to_sport), 0) < 0)
                    return DROP_WRITE_ERROR;
                from = tuple->sport;
                to = state->to_sport;
                flags = 0; /* ICMPv4 has no pseudo-header */
                sum_l4 = bpf_csum_diff(&from, 4, &to, 4, 0);
                csum.offset = offsetof(struct sandboxd_icmphdr, checksum);
                break;
            }
            }
        }
    }
    if (bpf_skb_store_bytes(skb, ETH_HLEN + offsetof(struct iphdr, saddr), &state->to_saddr, 4, 0) <
        0) {
        ret = DROP_WRITE_ERROR;
        goto ret_val;
    }
    if (ipv4_csum_update_by_diff(skb, ETH_HLEN, sum) < 0) {
        ret = DROP_CSUM_L3;
        goto ret_val;
    }
    if (tuple->nexthdr == IPPROTO_ICMP)
        sum = sum_l4;
    if (csum.offset && csum_l4_replace(skb, off, &csum, 0, sum, flags) < 0) {
        ret = DROP_CSUM_L4;
        goto ret_val;
    }

    ret = 0;
ret_val:
    return ret;
}

static __always_inline enum ct_action ct_tcp_select_action(union tcp_flags flags)
{
    if (flags.value & (TCP_FLAG_RST | TCP_FLAG_FIN))
        return ACTION_CLOSE;

    if (flags.value & TCP_FLAG_SYN)
        return ACTION_CREATE;

    return ACTION_UNSPEC;
}

static __always_inline int snat_v4_nat(struct __sk_buff *skb, const struct ipv4_nat_target *target)
{
    struct sandboxd_icmphdr icmphdr;
    struct ipv4_nat_entry *state, tmp;
    struct ipv4_ct_tuple tuple = {};
    void *data, *data_end;
    struct iphdr *ip4;
    union tcp_flags tcp_flags = {.value = 0};
    enum ct_action action = ACTION_UNSPEC;

    struct {
        __be16 sport;
        __be16 dport;
    } l4hdr;
    bool icmp_echoreply = false;
    __u64 off;
    int ret;

    if (!revalidate_data(skb, &data, &data_end, &ip4))
        return DROP_INVALID;

    /* prepare ct tuple for EGRESS */
    snat_v4_init_tuple(ip4, NAT_DIR_EGRESS, &tuple);

    off = ((void *)ip4 - data) + ipv4_hdrlen(ip4);
    switch (tuple.nexthdr) {
    case IPPROTO_TCP:
    case IPPROTO_UDP:
        if (bpf_skb_load_bytes(skb, off, &l4hdr, sizeof(l4hdr)) < 0)
            return DROP_INVALID;
        tuple.dport = l4hdr.dport;
        tuple.sport = l4hdr.sport;
        if (tuple.nexthdr == IPPROTO_TCP) {
            if (bpf_skb_load_bytes(skb, off + TCP_FLAG_OFFSET, &tcp_flags, sizeof(tcp_flags)) < 0)
                return DROP_INVALID;
            action = ct_tcp_select_action(tcp_flags);
        }
        break;
    case IPPROTO_ICMP:
        if (bpf_skb_load_bytes(skb, off, &icmphdr, sizeof(icmphdr)) < 0)
            return DROP_INVALID;
        if (icmphdr.type != ICMP_ECHO && icmphdr.type != ICMP_ECHOREPLY)
            return DROP_NAT_UNSUPP_PROTO;
        if (icmphdr.type == ICMP_ECHO) {
            tuple.dport = 0;
            tuple.sport = icmphdr.echo.id;
        } else {
            tuple.dport = icmphdr.echo.id;
            tuple.sport = 0;
            icmp_echoreply = true;
        }
        break;
    default:
        return NAT_PUNT_TO_STACK;
    };

    if (icmp_echoreply) {
        ret = 0;
        goto ret_val;
    }

    /* update snat map */
    ret = snat_v4_nat_handle_mapping(skb, &tuple, &state, &tmp, off, target, NULL, action,
                                     NAT_TYPE_SNAT);
    if (ret < 0) {
        goto ret_val;
    }

    /* modify saddr to new saddr given by snat target */
    ret = snat_v4_rewrite_egress(skb, &tuple, state, off, ipv4_has_l4_header(ip4));

ret_val:
    return ret;
}

static __always_inline void snat_v4_rev_rtuple(struct ipv4_ct_tuple *rtuple,
                                               struct ipv4_nat_entry *rstate,
                                               struct ipv4_ct_tuple *otuple)
{
    otuple->nexthdr = rtuple->nexthdr;
    otuple->saddr = rstate->to_daddr;
    otuple->sport = rstate->to_dport;
    otuple->daddr = rtuple->saddr;
    otuple->dport = rtuple->sport;
    otuple->flags = rtuple->flags == NAT_DIR_EGRESS ? NAT_DIR_INGRESS : NAT_DIR_EGRESS;
}

static __always_inline void dnat_v4_rev_rtuple(struct ipv4_ct_tuple *rtuple,
                                               struct ipv4_nat_entry *rstate,
                                               struct ipv4_ct_tuple *otuple)
{
    otuple->nexthdr = rtuple->nexthdr;
    otuple->saddr = rtuple->daddr;
    otuple->sport = rtuple->dport;
    otuple->daddr = rstate->to_saddr;
    otuple->dport = rstate->to_sport;
    otuple->flags = rtuple->flags == NAT_DIR_EGRESS ? NAT_DIR_INGRESS : NAT_DIR_EGRESS;
}

static __always_inline int snat_v4_rewrite_ingress(struct __sk_buff *skb,
                                                   struct ipv4_ct_tuple *tuple,
                                                   struct ipv4_nat_entry *state, __u32 off)
{
    int ret, flags = BPF_F_PSEUDO_HDR;
    struct csum_offset csum = {};
    __be32 sum_l4 = 0, sum;

    if (state->to_daddr == tuple->daddr && state->to_dport == tuple->dport)
        return 0;
    sum = bpf_csum_diff(&tuple->daddr, 4, &state->to_daddr, 4, 0);
    csum_l4_offset_and_flags(tuple->nexthdr, &csum);
    if (state->to_dport != tuple->dport) {
        switch (tuple->nexthdr) {
        case IPPROTO_TCP:
        case IPPROTO_UDP:
            ret = l4_modify_port(skb, off, offsetof(struct tcphdr, dest), &csum, state->to_dport,
                                 tuple->dport);
            if (ret < 0)
                return ret;
            break;
        case IPPROTO_ICMP: {
            __u8 type = 0;
            __be32 from, to;

            if (bpf_skb_load_bytes(skb, off + offsetof(struct sandboxd_icmphdr, type), &type, 1) <
                0)
                return DROP_INVALID;
            if (type == ICMP_ECHO || type == ICMP_ECHOREPLY) {
                if (bpf_skb_store_bytes(skb, off + offsetof(struct sandboxd_icmphdr, echo.id),
                                        &state->to_dport, sizeof(state->to_dport), 0) < 0)
                    return DROP_WRITE_ERROR;
                from = tuple->dport;
                to = state->to_dport;
                flags = 0; /* ICMPv4 has no pseudo-header */
                sum_l4 = bpf_csum_diff(&from, 4, &to, 4, 0);
                csum.offset = offsetof(struct sandboxd_icmphdr, checksum);
            }
            break;
        }
        }
    }
    if (bpf_skb_store_bytes(skb, ETH_HLEN + offsetof(struct iphdr, daddr), &state->to_daddr, 4, 0) <
        0)
        return DROP_WRITE_ERROR;
    if (ipv4_csum_update_by_diff(skb, ETH_HLEN, sum) < 0)
        return DROP_CSUM_L3;
    if (tuple->nexthdr == IPPROTO_ICMP)
        sum = sum_l4;
    if (csum.offset && csum_l4_replace(skb, off, &csum, 0, sum, flags) < 0)
        return DROP_CSUM_L4;
    return 0;
}

static __always_inline int snat_v4_rev_nat(struct __sk_buff *skb,
                                           const struct ipv4_nat_target *target)
{
    struct sandboxd_icmphdr icmphdr;
    struct ipv4_nat_entry *state;
    struct ipv4_ct_tuple tuple = {};
    struct ipv4_ct_tuple otuple = {};
    union tcp_flags tcp_flags = {.value = 0};
    enum ct_action action = ACTION_UNSPEC;
    void *data, *data_end;
    struct iphdr *ip4;
    struct {
        __be16 sport;
        __be16 dport;
    } l4hdr;
    __u64 off;
    int ret;

    if (!revalidate_data(skb, &data, &data_end, &ip4)) {
        ret = DROP_INVALID;
        goto ret_val;
    }

    /* prepare ct tuple for INGRESS as snat key */
    snat_v4_init_tuple(ip4, NAT_DIR_INGRESS, &tuple);

    off = ((void *)ip4 - data) + ipv4_hdrlen(ip4);
    switch (tuple.nexthdr) {
    case IPPROTO_TCP:
    case IPPROTO_UDP:
        if (bpf_skb_load_bytes(skb, off, &l4hdr, sizeof(l4hdr)) < 0) {
            ret = DROP_INVALID;
            goto ret_val;
        }
        tuple.dport = l4hdr.dport;
        tuple.sport = l4hdr.sport;

        if (tuple.nexthdr == IPPROTO_TCP) {
            if (bpf_skb_load_bytes(skb, off + TCP_FLAG_OFFSET, &tcp_flags, sizeof(tcp_flags)) < 0)
                return DROP_INVALID;
            action = ct_tcp_select_action(tcp_flags);
        }
        break;
    case IPPROTO_ICMP:
        if (bpf_skb_load_bytes(skb, off, &icmphdr, sizeof(icmphdr)) < 0) {
            ret = DROP_INVALID;
            goto ret_val;
        }
        switch (icmphdr.type) {
        case ICMP_ECHO:
            tuple.dport = 0;
            tuple.sport = icmphdr.echo.id;
            break;
        case ICMP_ECHOREPLY:
            tuple.dport = icmphdr.echo.id;
            tuple.sport = 0;
            break;
        /* TODO: add other icmphdr type support, i.e. ICMP_DEST_UNREACH */
        default:
            return DROP_NAT_UNSUPP_PROTO;
        }
        break;
    default:
        return NAT_PUNT_TO_STACK;
    };

    state = snat_v4_lookup(&tuple);
    if (!state || state->type != NAT_TYPE_SNAT) {
        ret = 0;
        goto ret_val;
    }

    snat_v4_rev_rtuple(&tuple, state, &otuple);
#ifdef BPF_TIMER_ENABLED
    ret = snat_update_timer(&otuple, action);
#else
    ret = snat_update_access_time(&otuple, action);
#endif
    if (ret < 0)
        goto ret_val;

    ret = snat_v4_rewrite_ingress(skb, &tuple, state, off);

ret_val:
    return ret;
}

static __always_inline int dnat_v4_nat(struct __sk_buff *skb)
{
    struct sandboxd_icmphdr icmphdr;
    struct ipv4_nat_entry *state, tmp;
    struct ipv4_ct_tuple tuple = {};
    void *data, *data_end;
    struct iphdr *ip4;
    union tcp_flags tcp_flags = {.value = 0};
    enum ct_action action = ACTION_UNSPEC;

    struct {
        __be16 sport;
        __be16 dport;
    } l4hdr;
    __u64 off;
    int ret;

    if (!revalidate_data(skb, &data, &data_end, &ip4))
        return false;

    /* prepare ct tuple for INGRESS as snat key */
    snat_v4_init_tuple(ip4, NAT_DIR_INGRESS, &tuple);

    off = ((void *)ip4 - data) + ipv4_hdrlen(ip4);
    switch (tuple.nexthdr) {
    case IPPROTO_TCP:
    case IPPROTO_UDP:
        if (bpf_skb_load_bytes(skb, off, &l4hdr, sizeof(l4hdr)) < 0) {
            ret = DROP_INVALID;
            goto ret_val;
        }
        tuple.dport = l4hdr.dport;
        tuple.sport = l4hdr.sport;

        if (tuple.nexthdr == IPPROTO_TCP) {
            if (bpf_skb_load_bytes(skb, off + TCP_FLAG_OFFSET, &tcp_flags, sizeof(tcp_flags)) < 0)
                return DROP_INVALID;
            action = ct_tcp_select_action(tcp_flags);
        }
        break;
    case IPPROTO_ICMP:
        if (bpf_skb_load_bytes(skb, off, &icmphdr, sizeof(icmphdr)) < 0) {
            ret = DROP_INVALID;
            goto ret_val;
        }
        switch (icmphdr.type) {
        case ICMP_ECHO:
            tuple.dport = 0;
            tuple.sport = icmphdr.echo.id;
            break;
        case ICMP_ECHOREPLY:
            tuple.dport = icmphdr.echo.id;
            tuple.sport = 0;
            break;
        /* TODO: add other icmphdr type support, i.e. ICMP_DEST_UNREACH */
        default:
            return DROP_NAT_UNSUPP_PROTO;
        }
        break;
    default:
        return NAT_PUNT_TO_STACK;
    };

    struct dnat_target target = {
        .addr = 0,
        .port = 0,
    };

    bool do_dnat = false;
    do_dnat = dnat_needed(&tuple, &(target.addr), &(target.port));
    if (!do_dnat) {
        return 0;
    }

    /* update snat map */
    ret = snat_v4_nat_handle_mapping(skb, &tuple, &state, &tmp, off, NULL, &target, action,
                                     NAT_TYPE_DNAT);
    if (ret < 0) {
        goto ret_val;
    }

    /* modify daddr to new daddr given by DNAT target */
    ret = snat_v4_rewrite_ingress(skb, &tuple, state, off);

ret_val:
#ifdef BPFNAT_AUDIT
    log_debug(SNAT, "dnat retval: %d\n", ret);
#endif
    return ret < 0 ? ret : 1;
}

static __always_inline int dnat_v4_rev_nat(struct __sk_buff *skb)
{
    struct sandboxd_icmphdr icmphdr;
    struct ipv4_nat_entry *state;
    struct ipv4_ct_tuple tuple = {};
    struct ipv4_ct_tuple otuple = {};
    union tcp_flags tcp_flags = {.value = 0};
    enum ct_action action = ACTION_UNSPEC;
    void *data, *data_end;
    struct iphdr *ip4;
    struct {
        __be16 sport;
        __be16 dport;
    } l4hdr;
    __u64 off;
    int ret;

    if (!revalidate_data(skb, &data, &data_end, &ip4)) {
        ret = DROP_INVALID;
        goto ret_val;
    }

    /* prepare ct tuple for EGRESS as snat key */
    snat_v4_init_tuple(ip4, NAT_DIR_EGRESS, &tuple);

    off = ((void *)ip4 - data) + ipv4_hdrlen(ip4);
    switch (tuple.nexthdr) {
    case IPPROTO_TCP:
    case IPPROTO_UDP:
        if (bpf_skb_load_bytes(skb, off, &l4hdr, sizeof(l4hdr)) < 0) {
            ret = DROP_INVALID;
            goto ret_val;
        }
        tuple.dport = l4hdr.dport;
        tuple.sport = l4hdr.sport;

        if (tuple.nexthdr == IPPROTO_TCP) {
            if (bpf_skb_load_bytes(skb, off + TCP_FLAG_OFFSET, &tcp_flags, sizeof(tcp_flags)) < 0)
                return DROP_INVALID;
            action = ct_tcp_select_action(tcp_flags);
        }
        break;
    case IPPROTO_ICMP:
        if (bpf_skb_load_bytes(skb, off, &icmphdr, sizeof(icmphdr)) < 0) {
            ret = DROP_INVALID;
            goto ret_val;
        }
        switch (icmphdr.type) {
        case ICMP_ECHO:
            tuple.dport = 0;
            tuple.sport = icmphdr.echo.id;
            break;
        case ICMP_ECHOREPLY:
            tuple.dport = icmphdr.echo.id;
            tuple.sport = 0;
            break;
        /* TODO: add other icmphdr type support, i.e. ICMP_DEST_UNREACH */
        default:
            return DROP_NAT_UNSUPP_PROTO;
        }
        break;
    default:
        return NAT_PUNT_TO_STACK;
    };

    state = snat_v4_lookup(&tuple);
    if (!state || state->type != NAT_TYPE_DNAT) {
        ret = 0;
        goto ret_val;
    }

    dnat_v4_rev_rtuple(&tuple, state, &otuple);
#ifdef BPF_TIMER_ENABLED
    ret = snat_update_timer(&tuple, action);
#else
    ret = dnat_update_access_time(&otuple, action);
#endif
    if (ret < 0)
        goto ret_val;

    ret = snat_v4_rewrite_egress(skb, &tuple, state, off, ipv4_has_l4_header(ip4));

ret_val:
    return ret;
}

#endif
