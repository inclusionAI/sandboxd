#!/usr/bin/env bash
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

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

cd "${ROOT_DIR}"
mkdir -p output

GOWORK=off GOCACHE=/tmp/go-build GOMODCACHE=/tmp/go-mod-official \
    GOTOOLCHAIN=auto make release
CGO_ENABLED=0 GOWORK=off GOCACHE=/tmp/go-build \
    GOMODCACHE=/tmp/go-mod-official GOTOOLCHAIN=auto \
    go build -o output/oom-hog ./test/e2e/oom-hog
CGO_ENABLED=0 GOWORK=off GOCACHE=/tmp/go-build \
    GOMODCACHE=/tmp/go-mod-official GOTOOLCHAIN=auto \
    go build -o output/network-policy-client \
    ./test/e2e/network-policy-client

for binary in \
    sandboxd sbox runc-shim sandbox-logger firecracker-agent \
    oom-hog network-policy-client; do
    [ -x "output/${binary}" ] || {
        printf '[runtime-binaries][error] output/%s is not executable\n' \
            "${binary}" >&2
        exit 1
    }
done
