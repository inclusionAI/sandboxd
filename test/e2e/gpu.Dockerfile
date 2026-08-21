# Copyright (c) 2026 Ant Group Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

ARG GO_BUILD_IMAGE=docker.io/library/golang:1.25.5-bookworm
ARG GPU_ROOTFS_IMAGE=nvcr.io/nvidia/k8s/cuda-sample@sha256:95ce52d6e3b11783606152f4da94af9cf84e7ca4dd63eb03c95edcc5b7bba8d9

FROM ${GO_BUILD_IMAGE} AS sandboxd-builder
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        gcc \
        git \
        libc6-dev \
        make && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /src/sandboxd
COPY . .
RUN make release && \
    CGO_ENABLED=0 go build -o output/oom-hog ./test/e2e/oom-hog

FROM ${GPU_ROOTFS_IMAGE} AS gpu-rootfs

FROM docker.io/library/ubuntu:24.04
ARG LIBNVIDIA_CONTAINER_VERSION=1.19.1-1
ENV DEBIAN_FRONTEND=noninteractive \
    E2E_DISABLE_CGROUP=1

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        busybox-static \
        ca-certificates \
        curl \
        gnupg \
        iproute2 \
        iptables \
        iputils-ping \
        jq \
        kmod \
        mount \
        netcat-openbsd \
        procps \
        tini && \
    rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    curl -fsSL --retry 10 --retry-delay 2 --retry-all-errors \
      https://nvidia.github.io/libnvidia-container/gpgkey \
      | gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg; \
    curl -fsSL --retry 10 --retry-delay 2 --retry-all-errors \
      https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list \
      | sed \
        's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' \
      > /etc/apt/sources.list.d/nvidia-container-toolkit.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      "libnvidia-container1=${LIBNVIDIA_CONTAINER_VERSION}" \
      "libnvidia-container-tools=${LIBNVIDIA_CONTAINER_VERSION}"; \
    rm -rf /var/lib/apt/lists/*

COPY third_party/runtime-versions.env /tmp/runtime-versions.env
RUN set -eux; \
    . /tmp/runtime-versions.env; \
    asset=/tmp/runsc; \
    curl -fSL --retry 10 --retry-delay 2 --retry-all-errors \
      "${GVISOR_AMD64_URL}" -o "${asset}"; \
    echo "${GVISOR_AMD64_SHA512}  ${asset}" | sha512sum -c -; \
    install -m 0755 "${asset}" /usr/local/bin/runsc; \
    rm -f "${asset}" /tmp/runtime-versions.env

COPY --from=sandboxd-builder /src/sandboxd/output/sandboxd /usr/local/bin/sandboxd
COPY --from=sandboxd-builder /src/sandboxd/output/sbox /usr/local/bin/sbox
COPY --from=sandboxd-builder /src/sandboxd/output/oom-hog /usr/local/bin/oom-hog
COPY --from=gpu-rootfs / /e2e/gpu-rootfs
COPY test/e2e/e2e-run.sh /usr/local/bin/sandboxd-e2e-run

RUN chmod 0755 \
        /usr/local/bin/sandboxd \
        /usr/local/bin/sbox \
        /usr/local/bin/runsc \
        /usr/local/bin/oom-hog \
        /usr/local/bin/sandboxd-e2e-run && \
    mkdir -p /e2e/gpu-rootfs/proc/driver/nvidia

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/sandboxd-e2e-run", "serve"]
