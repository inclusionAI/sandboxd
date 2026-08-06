// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Ant Group Corporation.

#ifndef __LIB_TIME_H_
#define __LIB_TIME_H_

#include <uapi.h>
#include <bpf_helpers.h>

/* get current time, precision is second
 * __u32 is enough to second timestamps
 */
#define bpf_now_sec()                                                                              \
    ({                                                                                             \
        __u32 __x = bpf_ktime_get_boot_ns() / 1000000000ULL;                                       \
        __x;                                                                                       \
    })

#endif
