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
VERSIONS_FILE="${RUNTIME_VERSIONS_FILE:-\
${ROOT_DIR}/third_party/runtime-versions.env}"
DOCKER="${DOCKER:-docker}"
E2E_CASE="${E2E_CASE:-${1:-}}"

log() {
    printf '[runtime-case] %s\n' "$*"
}

fail() {
    printf '[runtime-case][error] %s\n' "$*" >&2
    exit 1
}

[ -f "${VERSIONS_FILE}" ] ||
    fail "missing runtime version manifest: ${VERSIONS_FILE}"
# shellcheck source=../../third_party/runtime-versions.env
source "${VERSIONS_FILE}"

required_versions=(
    GVISOR_RELEASE
    GVISOR_AMD64_SHA512
    GVISOR_AMD64_URL
    RUNC_VERSION
    RUNC_AMD64_SHA256
    RUNC_RELEASE_BASE_URL
    KATA_RELEASE
    KATA_AMD64_SHA256
    KATA_RELEASE_BASE_URL
    FIRECRACKER_RELEASE
    FIRECRACKER_AMD64_SHA256
    FIRECRACKER_AMD64_URL
)
for version_name in "${required_versions[@]}"; do
    [ -n "${!version_name:-}" ] ||
        fail "${version_name} is empty in ${VERSIONS_FILE}"
done

case "${E2E_CASE}" in
    runsc-systrap)
        runtime=runsc
        platform=systrap
        needs_kvm=0
        run_cgroup_disabled=1
        ;;
    runsc-kvm)
        runtime=runsc
        platform=kvm
        needs_kvm=1
        run_cgroup_disabled=0
        ;;
    kata|firecracker)
        runtime="${E2E_CASE}"
        platform=systrap
        needs_kvm=1
        run_cgroup_disabled=0
        ;;
    runc)
        runtime=runc
        platform=systrap
        needs_kvm=0
        run_cgroup_disabled=0
        ;;
    *)
        fail "E2E_CASE must be runsc-systrap, runsc-kvm, kata, firecracker, or runc"
        ;;
esac

cd "${ROOT_DIR}"
for binary in \
    sandboxd sbox runc-shim sandbox-logger firecracker-agent \
    oom-hog network-policy-client; do
    [ -x "output/${binary}" ] ||
        fail "output/${binary} is missing; run make e2e-runtime-binaries first"
done
"${DOCKER}" info >/dev/null || fail "docker daemon is not accessible"
[ -c /dev/net/tun ] || fail "runtime E2E requires /dev/net/tun"
grep -qw erofs /proc/filesystems ||
    fail "runtime E2E requires host EROFS support"
if [ "${needs_kvm}" = "1" ]; then
    [ -c /dev/kvm ] || fail "${E2E_CASE} requires /dev/kvm"
    [ -r /dev/kvm ] && [ -w /dev/kvm ] ||
        fail "/dev/kvm is not readable and writable"
fi

image="${SANDBOXD_E2E_IMAGE:-sandboxd-runtime-e2e:${E2E_CASE}}"
log "building targeted image ${image}"
"${DOCKER}" build \
    --build-arg "E2E_RUNTIME=${runtime}" \
    --build-arg "GVISOR_RELEASE=${GVISOR_RELEASE}" \
    --build-arg "GVISOR_AMD64_SHA512=${GVISOR_AMD64_SHA512}" \
    --build-arg "GVISOR_AMD64_URL=${GVISOR_AMD64_URL}" \
    --build-arg "RUNC_VERSION=${RUNC_VERSION}" \
    --build-arg "RUNC_AMD64_SHA256=${RUNC_AMD64_SHA256}" \
    --build-arg "RUNC_RELEASE_BASE_URL=${RUNC_RELEASE_BASE_URL}" \
    --build-arg "KATA_RELEASE=${KATA_RELEASE}" \
    --build-arg "KATA_AMD64_SHA256=${KATA_AMD64_SHA256}" \
    --build-arg "KATA_RELEASE_BASE_URL=${KATA_RELEASE_BASE_URL}" \
    --build-arg "FIRECRACKER_RELEASE=${FIRECRACKER_RELEASE}" \
    --build-arg "FIRECRACKER_AMD64_SHA256=${FIRECRACKER_AMD64_SHA256}" \
    --build-arg "FIRECRACKER_AMD64_URL=${FIRECRACKER_AMD64_URL}" \
    -f test/e2e/runtime-suite.Dockerfile \
    -t "${image}" \
    .

log "running ${E2E_CASE}"
SANDBOXD_E2E_IMAGE="${image}" \
    SANDBOXD_E2E_CONTAINER="sandboxd-e2e-${E2E_CASE}" \
    SANDBOXD_E2E_DISABLED_CONTAINER="sandboxd-e2e-${E2E_CASE}-no-cgroup" \
    E2E_RUNTIME="${runtime}" \
    E2E_RUNSC_PLATFORM="${platform}" \
    E2E_RUN_CGROUP_DISABLED="${run_cgroup_disabled}" \
    E2E_NETWORK_SOAK=1 \
    E2E_SKIP_BUILD=1 \
    RUN_UNIT_TESTS=0 \
    bash test/e2e/run.sh
