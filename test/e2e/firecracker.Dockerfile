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
        e2fsprogs \
        erofs-utils \
        iproute2 \
        iptables \
        iputils-ping \
        jq \
        kmod \
        mount \
        netcat-openbsd \
        procps \
        xfsprogs && \
    rm -rf /var/lib/apt/lists/* && \
    if [ -x /usr/sbin/iptables-legacy ]; then \
        update-alternatives --set iptables /usr/sbin/iptables-legacy; \
        update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy; \
    fi

COPY output/sandboxd /usr/local/bin/sandboxd
COPY output/sbox /usr/local/bin/sbox
COPY output/oom-hog /usr/local/bin/oom-hog
COPY output/network-policy-client /usr/local/bin/network-policy-client
COPY output/firecracker /usr/local/bin/firecracker
COPY output/firecracker-vmlinux /opt/firecracker/vmlinux
COPY output/firecracker-initrd.img /opt/firecracker/initrd.img
COPY test/e2e/e2e-run.sh /usr/local/bin/sandboxd-e2e-run

RUN chmod 0755 \
        /usr/local/bin/sandboxd \
        /usr/local/bin/sbox \
        /usr/local/bin/oom-hog \
        /usr/local/bin/network-policy-client \
        /usr/local/bin/firecracker \
        /usr/local/bin/sandboxd-e2e-run && \
    chmod 0644 \
        /opt/firecracker/vmlinux \
        /opt/firecracker/initrd.img

ENTRYPOINT ["/usr/local/bin/sandboxd-e2e-run"]
