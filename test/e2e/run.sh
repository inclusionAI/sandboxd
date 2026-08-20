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

DOCKER="${DOCKER:-docker}"
IMAGE="${SANDBOXD_E2E_IMAGE:-sandboxd-e2e:local}"
CONTAINER="${SANDBOXD_E2E_CONTAINER:-sandboxd-e2e}"
DISABLED_CONTAINER="${SANDBOXD_E2E_DISABLED_CONTAINER:-${CONTAINER}-no-cgroup}"
RUN_UNIT_TESTS="${RUN_UNIT_TESTS:-1}"
RUNSC_BINARY="${RUNSC_BINARY:-}"
RUNC_BINARY="${RUNC_BINARY:-}"
E2E_STRESS_ROUNDS="${E2E_STRESS_ROUNDS:-0}"
E2E_STRESS_CONCURRENCY="${E2E_STRESS_CONCURRENCY:-8}"
E2E_CPU_LIMIT_MODE="${E2E_CPU_LIMIT_MODE:-quota}"
E2E_RUNTIME="${E2E_RUNTIME:-all}"
E2E_RUNC_ONLY="${E2E_RUNC_ONLY:-0}"

log() {
    printf '[e2e-run] %s\n' "$*"
}

fail() {
    printf '[e2e-run][error] %s\n' "$*" >&2
    exit 1
}

cleanup_container() {
    local name
    for name in "${CONTAINER}" "${DISABLED_CONTAINER}"; do
        if "${DOCKER}" ps -a --format '{{.Names}}' | grep -qx "${name}"; then
            "${DOCKER}" rm -f "${name}" >/dev/null 2>&1 || true
        fi
    done
}
trap cleanup_container EXIT

cd "${ROOT_DIR}"

case "${E2E_RUNTIME}" in
    all|runsc|runc) ;;
    *) fail "E2E_RUNTIME must be all, runsc, or runc" ;;
esac
case "${E2E_RUNC_ONLY}" in
    0) ;;
    1)
        if [ "${E2E_RUNTIME}" != "all" ] && [ "${E2E_RUNTIME}" != "runc" ]; then
            fail "E2E_RUNC_ONLY=1 conflicts with E2E_RUNTIME=${E2E_RUNTIME}"
        fi
        E2E_RUNTIME="runc"
        ;;
    *) fail "E2E_RUNC_ONLY must be 0 or 1" ;;
esac

if [ -z "${RUNSC_BINARY}" ]; then
    for candidate in output/runsc /tmp/gvisor-runsc-bin/runsc /usr/local/bin/runsc; do
        if [ -x "${candidate}" ]; then
            RUNSC_BINARY="${candidate}"
            break
        fi
    done
fi

[ -x "${RUNSC_BINARY}" ] || fail "RUNSC_BINARY is not executable; set RUNSC_BINARY=/path/to/upstream/runsc"
if [ -z "${RUNC_BINARY}" ]; then
    for candidate in output/runc /usr/local/bin/runc /usr/bin/runc; do
        if [ -x "${candidate}" ]; then
            RUNC_BINARY="${candidate}"
            break
        fi
    done
fi
[ -x "${RUNC_BINARY}" ] || fail "RUNC_BINARY is not executable; set RUNC_BINARY=/path/to/runc"
"${DOCKER}" info >/dev/null || fail "docker daemon is not accessible"

if [ "${E2E_RUNTIME}" != "runsc" ] && ! grep -qw erofs /proc/filesystems; then
    modprobe erofs || fail "the host must provide EROFS for the runc adapter"
fi

if [ "${RUN_UNIT_TESTS}" = "1" ]; then
    log "running unit tests"
    GOWORK=off GOCACHE=/tmp/go-build GOMODCACHE=/tmp/go-mod-official GOTOOLCHAIN=auto go test ./...
fi

log "building sandboxd and sbox"
GOWORK=off GOCACHE=/tmp/go-build GOMODCACHE=/tmp/go-mod-official GOTOOLCHAIN=auto make release
CGO_ENABLED=0 GOWORK=off GOCACHE=/tmp/go-build GOMODCACHE=/tmp/go-mod-official \
    GOTOOLCHAIN=auto go build -o output/oom-hog ./test/e2e/oom-hog

log "copying runsc from ${RUNSC_BINARY}"
cp "${RUNSC_BINARY}" output/runsc
chmod 0755 output/runsc

log "copying runc from ${RUNC_BINARY}"
cp "${RUNC_BINARY}" output/runc
chmod 0755 output/runc

log "building e2e image ${IMAGE}"
"${DOCKER}" build -f test/e2e/Dockerfile -t "${IMAGE}" .

cleanup_container

log "running e2e container ${CONTAINER}"
set +e
"${DOCKER}" run \
    --name "${CONTAINER}" \
    --privileged \
    --cgroupns=host \
    --net bridge \
    -e "E2E_STRESS_ROUNDS=${E2E_STRESS_ROUNDS}" \
    -e "E2E_STRESS_CONCURRENCY=${E2E_STRESS_CONCURRENCY}" \
    -e "E2E_CPU_LIMIT_MODE=${E2E_CPU_LIMIT_MODE}" \
    -e "E2E_RUNTIME=${E2E_RUNTIME}" \
    --tmpfs /home/akernel:rw,exec,size=2g \
    --tmpfs /e2e:rw,exec,size=512m \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    "${IMAGE}"
status=$?
set -e

if [ "${status}" -ne 0 ]; then
    log "container logs"
    "${DOCKER}" logs "${CONTAINER}" >&2 || true
    exit "${status}"
fi

if [ "${E2E_RUNTIME}" = "runc" ]; then
    log "runc e2e completed"
    exit 0
fi

log "running cgroup-disabled e2e container ${DISABLED_CONTAINER}"
set +e
"${DOCKER}" run \
    --name "${DISABLED_CONTAINER}" \
    --privileged \
    --net bridge \
    -e E2E_DISABLE_CGROUP=1 \
    -e E2E_RUNTIME=runsc \
    -e E2E_CPU_LIMIT_MODE=shares \
    --tmpfs /home/akernel:rw,exec,size=2g \
    --tmpfs /e2e:rw,exec,size=512m \
    -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
    "${IMAGE}"
status=$?
set -e

if [ "${status}" -ne 0 ]; then
    log "cgroup-disabled container logs"
    "${DOCKER}" logs "${DISABLED_CONTAINER}" >&2 || true
    exit "${status}"
fi

log "e2e completed"
