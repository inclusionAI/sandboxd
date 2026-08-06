// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Ant Group Corporation.

#ifndef __SANDBOXD_BPF_UAPI_H_
#define __SANDBOXD_BPF_UAPI_H_

#include <stdbool.h>
#include <stddef.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>

/* The bpfnat data path only needs the fixed eight-byte ICMP echo header. */
struct sandboxd_icmphdr {
    __u8 type;
    __u8 code;
    __sum16 checksum;
    struct {
        __be16 id;
        __be16 sequence;
    } echo;
};

#endif
