// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Ant Group Corporation.

#ifndef __LIB_LOG_H_
#define __LIB_LOG_H_

#include <bpf_helpers.h>

/* log level */
enum {
    DEBUG = 0,
    INFO,
    WARN,
    ERROR,
    FATAL,
};

/* log module */
enum {
    START,
    COMMON,
    LXC,
    ENDPOINT,
    IPV4,
    ND,
    ICMP4,
    CT,
    SERVICE,
    NETWORKPOLICY,
    VPCPOLICY,
    SRV6,
    PHY,
    SNAT,
    END
};

#define log_debug(module, fmt, ...) ({})
#define log_info(module, fmt, ...) ({})
#define log_warn(module, fmt, ...) ({})
#define log_error(module, fmt, ...) ({})

#endif
