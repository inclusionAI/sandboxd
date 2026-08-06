# Copyright (c) 2026 Ant Group Corporation.
#
# SPDX-License-Identifier: Apache-2.0

ARG GO_BUILD_IMAGE=golang:1.25.5-bookworm@sha256:d9132cce84391efab786495288756d60e1da215b1f94e87860aeefc3d4c45b6d
FROM ${GO_BUILD_IMAGE}

ARG BPF2GO_VERSION=v0.9.1
ARG BPF_CLANG_VERSION=14.0.6
ARG BPF_CLANG_PACKAGE_VERSION=1:14.0.6-12
ARG BPF_CLANG_FORMAT_PACKAGE_VERSION=1:14.0.6-12
ARG BPF_LIBBPF_PACKAGE_VERSION=1:1.1.2-0+deb12u1
ARG BPF_LINUX_UAPI_PACKAGE_VERSION=6.1.180-1

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        clang-14="${BPF_CLANG_PACKAGE_VERSION}" \
        clang-format-14="${BPF_CLANG_FORMAT_PACKAGE_VERSION}" \
        libbpf-dev="${BPF_LIBBPF_PACKAGE_VERSION}" \
        linux-libc-dev="${BPF_LINUX_UAPI_PACKAGE_VERSION}" \
        llvm-14="${BPF_CLANG_PACKAGE_VERSION}" && \
    rm -rf /var/lib/apt/lists/* && \
    test "$(clang-14 -dumpversion)" = "${BPF_CLANG_VERSION}" && \
    clang-format-14 --version | grep -F "version ${BPF_CLANG_VERSION}" && \
    llvm-strip-14 --version | grep -F "LLVM version ${BPF_CLANG_VERSION}"

RUN GOBIN=/usr/local/bin go install \
        "github.com/cilium/ebpf/cmd/bpf2go@${BPF2GO_VERSION}"

WORKDIR /workspace

ENTRYPOINT ["make"]
CMD ["bpf-local"]
