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

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        busybox-static \
        ca-certificates \
        cpio \
        curl \
        e2fsprogs \
        erofs-utils \
        gzip \
        iproute2 \
        iptables \
        iputils-ping \
        jq \
        kmod \
        libseccomp2 \
        mount \
        netcat-openbsd \
        procps \
        xfsprogs \
        zstd && \
    rm -rf /var/lib/apt/lists/* && \
    if [ -x /usr/sbin/iptables-legacy ]; then \
        update-alternatives --set iptables /usr/sbin/iptables-legacy; \
        update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy; \
    fi

COPY output/sandboxd /usr/local/bin/sandboxd
COPY output/sbox /usr/local/bin/sbox
COPY output/runc-shim /usr/local/bin/runc-shim
COPY output/sandbox-logger /usr/local/bin/sandbox-logger
COPY output/firecracker-agent /usr/local/bin/firecracker-agent
COPY output/oom-hog /usr/local/bin/oom-hog
COPY output/network-policy-client /usr/local/bin/network-policy-client
COPY test/e2e/e2e-run.sh /usr/local/bin/sandboxd-e2e-run

ARG E2E_RUNTIME
ARG GVISOR_RELEASE
ARG GVISOR_AMD64_SHA512
ARG GVISOR_AMD64_URL
ARG RUNC_VERSION
ARG RUNC_AMD64_SHA256
ARG RUNC_RELEASE_BASE_URL
ARG KATA_RELEASE
ARG KATA_AMD64_SHA256
ARG KATA_RELEASE_BASE_URL
ARG FIRECRACKER_RELEASE
ARG FIRECRACKER_AMD64_SHA256
ARG FIRECRACKER_AMD64_URL

RUN set -eux; \
    case "${E2E_RUNTIME}" in \
      runsc) \
        version="${GVISOR_RELEASE#release-}"; \
        test "${version}" != "${GVISOR_RELEASE}"; \
        asset=/tmp/runsc; \
        curl -fSL --retry 10 --retry-delay 2 --retry-all-errors \
          "${GVISOR_AMD64_URL}" -o "${asset}"; \
        echo "${GVISOR_AMD64_SHA512}  ${asset}" | sha512sum -c -; \
        install -m 0755 "${asset}" /usr/local/bin/runsc; \
        ;; \
      runc) \
        asset=/tmp/runc.amd64; \
        curl -fSL --retry 10 --retry-delay 2 --retry-all-errors \
          "${RUNC_RELEASE_BASE_URL}/v${RUNC_VERSION}/runc.amd64" \
          -o "${asset}"; \
        echo "${RUNC_AMD64_SHA256}  ${asset}" | sha256sum -c -; \
        install -m 0755 "${asset}" /usr/local/bin/runc; \
        ;; \
      kata) \
        archive="/tmp/kata-static-${KATA_RELEASE}-amd64.tar.zst"; \
        curl -fSL --retry 10 --retry-delay 2 --retry-all-errors \
          "${KATA_RELEASE_BASE_URL}/${KATA_RELEASE}/kata-static-${KATA_RELEASE}-amd64.tar.zst" \
          -o "${archive}"; \
        echo "${KATA_AMD64_SHA256}  ${archive}" | sha256sum -c -; \
        tar --zstd -xf "${archive}" -C / \
          ./opt/kata/runtime-rs/bin/containerd-shim-kata-v2 \
          ./opt/kata/share/defaults/kata-containers/runtime-rs/configuration-dragonball.toml \
          ./opt/kata/share/kata-containers/vmlinux-dragonball-experimental.container \
          ./opt/kata/share/kata-containers/vmlinux-6.18.35-200-dragonball-experimental \
          ./opt/kata/share/kata-containers/kata-containers.img \
          ./opt/kata/share/kata-containers/kata-ubuntu-noble.image; \
        ln -sfn configuration-dragonball.toml \
          /opt/kata/share/defaults/kata-containers/runtime-rs/configuration.toml; \
        ln -s /opt/kata/runtime-rs/bin/containerd-shim-kata-v2 \
          /usr/local/bin/containerd-shim-kata-v2; \
        chmod 0644 \
          /opt/kata/share/defaults/kata-containers/runtime-rs/configuration-dragonball.toml \
          /opt/kata/share/kata-containers/kata-containers.img \
          /opt/kata/share/kata-containers/vmlinux-dragonball-experimental.container; \
        ;; \
      firecracker) \
        archive="/tmp/firecracker-${FIRECRACKER_RELEASE}-x86_64.tgz"; \
        curl -fSL --retry 10 --retry-delay 2 --retry-all-errors \
          "${FIRECRACKER_AMD64_URL}" -o "${archive}"; \
        echo "${FIRECRACKER_AMD64_SHA256}  ${archive}" | sha256sum -c -; \
        mkdir -p /tmp/firecracker-release; \
        tar -xzf "${archive}" -C /tmp/firecracker-release; \
        bundle="/tmp/firecracker-release/release-${FIRECRACKER_RELEASE}-x86_64"; \
        test "$(jq -er '.component' "${bundle}/manifest.json")" = \
          "akernel-firecracker-runtime"; \
        test "$(jq -er '.release_tag' "${bundle}/manifest.json")" = \
          "${FIRECRACKER_RELEASE}"; \
        (cd "${bundle}"; sha256sum -c SHA256SUMS); \
        vmm_version="$(jq -er '.vmm.version' "${bundle}/manifest.json")"; \
        "${bundle}/firecracker" --version | \
          grep -F "Firecracker ${vmm_version}"; \
        install -D -m 0755 "${bundle}/firecracker" \
          /usr/local/bin/firecracker; \
        install -D -m 0644 "${bundle}/vmlinux" \
          /opt/firecracker/vmlinux; \
        install -D -m 0644 "${bundle}/kernel.config" \
          /opt/firecracker/kernel.config; \
        install -D -m 0644 "${bundle}/manifest.json" \
          /opt/firecracker/manifest.json; \
        mkdir -p /tmp/firecracker-initrd; \
        install -m 0755 /usr/local/bin/firecracker-agent \
          /tmp/firecracker-initrd/init; \
        touch -d @0 /tmp/firecracker-initrd \
          /tmp/firecracker-initrd/init; \
        (cd /tmp/firecracker-initrd; \
          find . -print0 | LC_ALL=C sort -z | \
          cpio --null --create --format=newc --owner=0:0 --reproducible | \
          gzip -n -9 > /opt/firecracker/initrd.img); \
        ;; \
      *) \
        echo "unsupported E2E runtime: ${E2E_RUNTIME}" >&2; \
        exit 1; \
        ;; \
    esac; \
    rm -rf /tmp/firecracker-initrd /tmp/firecracker-release \
      /tmp/firecracker-*.tgz /tmp/kata-static-*.tar.zst \
      /tmp/runc.amd64 /tmp/runsc; \
    chmod 0755 \
      /usr/local/bin/sandboxd \
      /usr/local/bin/sbox \
      /usr/local/bin/runc-shim \
      /usr/local/bin/sandbox-logger \
      /usr/local/bin/firecracker-agent \
      /usr/local/bin/oom-hog \
      /usr/local/bin/network-policy-client \
      /usr/local/bin/sandboxd-e2e-run

ENTRYPOINT ["/usr/local/bin/sandboxd-e2e-run"]
