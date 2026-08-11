# Copyright (c) 2026 Ant Group Corporation.
#
# SPDX-License-Identifier: Apache-2.0

ARG BPF_TOOL_IMAGE=sandboxd-bpf:clang-14.0.6-bpf2go-v0.9.1
FROM ${BPF_TOOL_IMAGE}

COPY go.mod go.sum /tmp/sandboxd-deps/

RUN cd /tmp/sandboxd-deps && go mod download

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iproute2 \
        iptables \
        iputils-ping && \
    rm -rf /var/lib/apt/lists/*

CMD ["bpfnat-test-local"]
