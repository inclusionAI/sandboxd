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
FIRECRACKER_BINARY="${FIRECRACKER_BINARY:-}"
FIRECRACKER_KERNEL="${FIRECRACKER_KERNEL:-}"
FIRECRACKER_INITRD="${FIRECRACKER_INITRD:-}"
KATA_ROOT="${KATA_ROOT:-}"
E2E_STRESS_ROUNDS="${E2E_STRESS_ROUNDS:-0}"
E2E_STRESS_CONCURRENCY="${E2E_STRESS_CONCURRENCY:-8}"
E2E_CPU_LIMIT_MODE="${E2E_CPU_LIMIT_MODE:-quota}"
E2E_RUNTIME="${E2E_RUNTIME:-all}"
E2E_RUNC_ONLY="${E2E_RUNC_ONLY:-0}"
E2E_RUNSC_PLATFORM="${E2E_RUNSC_PLATFORM:-systrap}"
E2E_RUN_CGROUP_DISABLED="${E2E_RUN_CGROUP_DISABLED:-1}"
E2E_SKIP_BUILD="${E2E_SKIP_BUILD:-0}"
E2E_NETWORK_SOAK="${E2E_NETWORK_SOAK:-0}"
REDIS_IMAGE="${E2E_REDIS_IMAGE:-docker.io/library/redis@sha256:ff02b58f971e7d7d156a1267e283fcbbeee91773b6aa36c49dac28ecfe28eadf}"
REDIS_DNAT_HOST_PORT="${E2E_REDIS_DNAT_HOST_PORT:-18379}"
REDIS_CONTAINER="${CONTAINER}-redis"
REDIS_ROOTFS_CONTAINER="${CONTAINER}-redis-rootfs"
REDIS_NETWORK="${CONTAINER}-network"
REDIS_RESULT_KEY="sandboxd-e2e:${CONTAINER}:dnat"
REDIS_FIXTURE_DIR=""
REDIS_HOST=""

log() {
    printf '[e2e-run] %s\n' "$*"
}

fail() {
    printf '[e2e-run][error] %s\n' "$*" >&2
    exit 1
}

cleanup_container() {
    local name
    for name in \
        "${CONTAINER}" \
        "${DISABLED_CONTAINER}" \
        "${REDIS_CONTAINER}" \
        "${REDIS_ROOTFS_CONTAINER}"; do
        if "${DOCKER}" ps -a --format '{{.Names}}' | grep -qx "${name}"; then
            "${DOCKER}" rm -f "${name}" >/dev/null 2>&1 || true
        fi
    done
    "${DOCKER}" network rm "${REDIS_NETWORK}" >/dev/null 2>&1 || true
    if [ -n "${REDIS_FIXTURE_DIR}" ]; then
        rm -rf -- "${REDIS_FIXTURE_DIR}"
        REDIS_FIXTURE_DIR=""
    fi
    if [ "${E2E_SKIP_BUILD}" = "0" ] && [ "${E2E_RUNTIME}" = "kata" ]; then
        rm -rf -- "${ROOT_DIR}/output/kata"
    fi
}

prepare_network_soak() {
    if [ "${E2E_NETWORK_SOAK}" = "0" ]; then
        return
    fi

    log "preparing Redis network soak fixture"
    REDIS_FIXTURE_DIR="$(mktemp -d)"
    "${DOCKER}" create \
        --name "${REDIS_ROOTFS_CONTAINER}" \
        "${REDIS_IMAGE}" >/dev/null
    "${DOCKER}" export \
        --output "${REDIS_FIXTURE_DIR}/rootfs.tar" \
        "${REDIS_ROOTFS_CONTAINER}"
    "${DOCKER}" rm "${REDIS_ROOTFS_CONTAINER}" >/dev/null

    "${DOCKER}" network create "${REDIS_NETWORK}" >/dev/null
    "${DOCKER}" run -d \
        --name "${REDIS_CONTAINER}" \
        --network "${REDIS_NETWORK}" \
        "${REDIS_IMAGE}" \
        redis-server --save "" --appendonly no >/dev/null

    local i
    for i in $(seq 1 100); do
        if "${DOCKER}" exec "${REDIS_CONTAINER}" \
            redis-cli ping 2>/dev/null | grep -qx PONG; then
            break
        fi
        sleep 0.1
    done
    "${DOCKER}" exec "${REDIS_CONTAINER}" redis-cli ping |
        grep -qx PONG || fail "external Redis did not become ready"
    REDIS_HOST="$("${DOCKER}" inspect \
        --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
        "${REDIS_CONTAINER}")"
    [ -n "${REDIS_HOST}" ] || fail "external Redis has no container IP"
    "${DOCKER}" exec "${REDIS_CONTAINER}" \
        redis-cli set "${REDIS_RESULT_KEY}" pending >/dev/null
}

run_redis_dnat_benchmark() {
    local seen_container=0
    local redis_ready=0
    local i
    for i in $(seq 1 600); do
        if "${DOCKER}" inspect "${CONTAINER}" >/dev/null 2>&1; then
            seen_container=1
            if [ "$("${DOCKER}" inspect \
                --format '{{.State.Running}}' "${CONTAINER}")" != "true" ]; then
                return 1
            fi
        fi
        if "${DOCKER}" exec "${REDIS_CONTAINER}" \
            redis-cli -h "${CONTAINER}" -p "${REDIS_DNAT_HOST_PORT}" ping \
            2>/dev/null | grep -qx PONG; then
            redis_ready=1
            break
        fi
        sleep 0.5
    done
    if [ "${seen_container}" = "0" ] || [ "${redis_ready}" = "0" ]; then
        "${DOCKER}" exec "${REDIS_CONTAINER}" \
            redis-cli set "${REDIS_RESULT_KEY}" fail >/dev/null || true
        return 1
    fi

    local output=""
    local result=fail
    local status=1
    if output="$("${DOCKER}" exec "${REDIS_CONTAINER}" \
        redis-benchmark \
        -h "${CONTAINER}" \
        -p "${REDIS_DNAT_HOST_PORT}" \
        --csv \
        -n 20000 \
        -c 16 \
        -P 4 \
        -t set,get)" &&
        grep -q '^"SET",' <<<"${output}" &&
        grep -q '^"GET",' <<<"${output}"; then
        result=pass
        status=0
    fi
    printf '%s\n' "${output}"
    "${DOCKER}" exec "${REDIS_CONTAINER}" \
        redis-cli set "${REDIS_RESULT_KEY}" "${result}" >/dev/null
    return "${status}"
}
trap cleanup_container EXIT

cd "${ROOT_DIR}"

case "${E2E_RUNTIME}" in
    all|runsc|runc|kata|firecracker) ;;
    *) fail "E2E_RUNTIME must be all, runsc, runc, kata, or firecracker" ;;
esac
case "${E2E_RUNSC_PLATFORM}" in
    systrap|kvm) ;;
    *) fail "E2E_RUNSC_PLATFORM must be systrap or kvm" ;;
esac
case "${E2E_RUN_CGROUP_DISABLED}" in
    0|1) ;;
    *) fail "E2E_RUN_CGROUP_DISABLED must be 0 or 1" ;;
esac
case "${E2E_SKIP_BUILD}" in
    0|1) ;;
    *) fail "E2E_SKIP_BUILD must be 0 or 1" ;;
esac
case "${E2E_NETWORK_SOAK}" in
    0|1) ;;
    *) fail "E2E_NETWORK_SOAK must be 0 or 1" ;;
esac
if [ "${E2E_NETWORK_SOAK}" = "1" ] && [ "${E2E_RUNTIME}" = "all" ]; then
    fail "E2E_NETWORK_SOAK requires one selected runtime"
fi
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

if [ "${E2E_SKIP_BUILD}" = "0" ]; then
    if [ -z "${RUNSC_BINARY}" ]; then
        for candidate in output/runsc /tmp/gvisor-runsc-bin/runsc /usr/local/bin/runsc; do
            if [ -x "${candidate}" ]; then
                RUNSC_BINARY="${candidate}"
                break
            fi
        done
    fi
    if [ "${E2E_RUNTIME}" = "all" ] || [ "${E2E_RUNTIME}" = "runsc" ]; then
        [ -x "${RUNSC_BINARY}" ] ||
            fail "RUNSC_BINARY is not executable; set RUNSC_BINARY=/path/to/upstream/runsc"
    fi
    if [ -z "${RUNC_BINARY}" ]; then
        for candidate in output/runc /usr/local/bin/runc /usr/bin/runc; do
            if [ -x "${candidate}" ]; then
                RUNC_BINARY="${candidate}"
                break
            fi
        done
    fi
    if [ "${E2E_RUNTIME}" = "all" ] || [ "${E2E_RUNTIME}" = "runc" ]; then
        [ -x "${RUNC_BINARY}" ] ||
            fail "RUNC_BINARY is not executable; set RUNC_BINARY=/path/to/runc"
    fi
    if [ "${E2E_RUNTIME}" = "kata" ]; then
        if [ -z "${KATA_ROOT}" ]; then
            KATA_ROOT="/opt/kata"
        fi
        [ -x "${KATA_ROOT}/runtime-rs/bin/containerd-shim-kata-v2" ] ||
            fail "KATA_ROOT does not contain the runtime-rs shim"
        [ -f "${KATA_ROOT}/share/defaults/kata-containers/runtime-rs/configuration-dragonball.toml" ] ||
            fail "KATA_ROOT does not contain the Dragonball configuration"
        [ -f "${KATA_ROOT}/share/kata-containers/vmlinux-dragonball-experimental.container" ] ||
            fail "KATA_ROOT does not contain the Dragonball guest kernel"
        [ -f "${KATA_ROOT}/share/kata-containers/kata-containers.img" ] ||
            fail "KATA_ROOT does not contain the Kata guest image"
        [ -c /dev/kvm ] || fail "Kata e2e requires /dev/kvm"
    fi
    if [ "${E2E_RUNTIME}" = "firecracker" ]; then
        if [ -z "${FIRECRACKER_BINARY}" ]; then
            FIRECRACKER_BINARY="/usr/local/bin/firecracker"
        fi
        if [ -z "${FIRECRACKER_KERNEL}" ]; then
            FIRECRACKER_KERNEL="/opt/firecracker/vmlinux"
        fi
        if [ -z "${FIRECRACKER_INITRD}" ]; then
            FIRECRACKER_INITRD="/opt/firecracker/initrd.img"
        fi
        [ -x "${FIRECRACKER_BINARY}" ] ||
            fail "FIRECRACKER_BINARY is not executable"
        [ -f "${FIRECRACKER_KERNEL}" ] ||
            fail "FIRECRACKER_KERNEL is not a file"
        [ -f "${FIRECRACKER_INITRD}" ] ||
            fail "FIRECRACKER_INITRD is not a file"
        [ -c /dev/kvm ] || fail "Firecracker e2e requires /dev/kvm"
    fi
fi
"${DOCKER}" info >/dev/null || fail "docker daemon is not accessible"

if { [ "${E2E_RUNTIME}" = "all" ] || [ "${E2E_RUNTIME}" = "runc" ]; } &&
    ! grep -qw erofs /proc/filesystems; then
    modprobe erofs ||
        fail "the host must provide EROFS for the runc adapter"
fi

if [ "${E2E_SKIP_BUILD}" = "0" ]; then
    if [ "${RUN_UNIT_TESTS}" = "1" ]; then
        log "running unit tests"
        GOWORK=off GOCACHE=/tmp/go-build GOMODCACHE=/tmp/go-mod-official \
            GOTOOLCHAIN=auto go test ./...
    fi

    log "building sandboxd and sbox"
    GOWORK=off GOCACHE=/tmp/go-build GOMODCACHE=/tmp/go-mod-official \
        GOTOOLCHAIN=auto make release
    CGO_ENABLED=0 GOWORK=off GOCACHE=/tmp/go-build \
        GOMODCACHE=/tmp/go-mod-official GOTOOLCHAIN=auto \
        go build -o output/oom-hog ./test/e2e/oom-hog
    CGO_ENABLED=0 GOWORK=off GOCACHE=/tmp/go-build \
        GOMODCACHE=/tmp/go-mod-official GOTOOLCHAIN=auto \
        go build -o output/network-policy-client \
        ./test/e2e/network-policy-client

    DOCKERFILE="test/e2e/Dockerfile"
    if [ "${E2E_RUNTIME}" = "all" ] || [ "${E2E_RUNTIME}" = "runsc" ]; then
        log "copying runsc from ${RUNSC_BINARY}"
        cp "${RUNSC_BINARY}" output/runsc
        chmod 0755 output/runsc
    fi

    if [ "${E2E_RUNTIME}" = "all" ] || [ "${E2E_RUNTIME}" = "runc" ]; then
        log "copying runc from ${RUNC_BINARY}"
        cp "${RUNC_BINARY}" output/runc
        chmod 0755 output/runc
    fi

    if [ "${E2E_RUNTIME}" = "kata" ]; then
        DOCKERFILE="test/e2e/kata.Dockerfile"
        log "copying Kata runtime from ${KATA_ROOT}"
        rm -rf "${ROOT_DIR}/output/kata"
        mkdir -p "${ROOT_DIR}/output/kata"
        cp -a --sparse=always "${KATA_ROOT}/." "${ROOT_DIR}/output/kata/"
    fi

    if [ "${E2E_RUNTIME}" = "firecracker" ]; then
        DOCKERFILE="test/e2e/firecracker.Dockerfile"
        install -m 0755 "${FIRECRACKER_BINARY}" output/firecracker
        install -m 0644 "${FIRECRACKER_KERNEL}" output/firecracker-vmlinux
        install -m 0644 "${FIRECRACKER_INITRD}" output/firecracker-initrd.img
    fi

    log "building e2e image ${IMAGE}"
    "${DOCKER}" build -f "${DOCKERFILE}" -t "${IMAGE}" .
else
    "${DOCKER}" image inspect "${IMAGE}" >/dev/null ||
        fail "E2E_SKIP_BUILD=1 requires an existing image: ${IMAGE}"
fi

cleanup_container
prepare_network_soak

container_network_args=(--net bridge)
network_soak_args=(-e E2E_NETWORK_SOAK=0)
if [ "${E2E_NETWORK_SOAK}" = "1" ]; then
    container_network_args=(--network "${REDIS_NETWORK}")
    network_soak_args=(
        -e E2E_NETWORK_SOAK=1
        -e "E2E_REDIS_HOST=${REDIS_HOST}"
        -e "E2E_REDIS_DNAT_HOST_PORT=${REDIS_DNAT_HOST_PORT}"
        -e "E2E_REDIS_RESULT_KEY=${REDIS_RESULT_KEY}"
        -v "${REDIS_FIXTURE_DIR}:/e2e-fixtures:ro"
    )
fi

log "running e2e container ${CONTAINER}"
set +e
"${DOCKER}" run \
    --name "${CONTAINER}" \
    --init \
    --privileged \
    --cgroupns=host \
    "${container_network_args[@]}" \
    -e "E2E_STRESS_ROUNDS=${E2E_STRESS_ROUNDS}" \
    -e "E2E_STRESS_CONCURRENCY=${E2E_STRESS_CONCURRENCY}" \
    -e "E2E_CPU_LIMIT_MODE=${E2E_CPU_LIMIT_MODE}" \
    -e "E2E_RUNTIME=${E2E_RUNTIME}" \
    -e "E2E_RUNSC_PLATFORM=${E2E_RUNSC_PLATFORM}" \
    "${network_soak_args[@]}" \
    --tmpfs /home/akernel:rw,exec,size=2g \
    --tmpfs /e2e:rw,exec,size=512m \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    "${IMAGE}" &
container_run_pid=$!
set -e

soak_status=0
if [ "${E2E_NETWORK_SOAK}" = "1" ]; then
    run_redis_dnat_benchmark || soak_status=$?
fi
set +e
wait "${container_run_pid}"
status=$?
set -e
if [ "${status}" -eq 0 ] && [ "${soak_status}" -ne 0 ]; then
    status="${soak_status}"
fi

if [ "${status}" -ne 0 ]; then
    log "container logs"
    "${DOCKER}" logs "${CONTAINER}" >&2 || true
    exit "${status}"
fi

if [ "${E2E_RUN_CGROUP_DISABLED}" = "0" ] ||
    [ "${E2E_RUNTIME}" = "runc" ] ||
    [ "${E2E_RUNTIME}" = "kata" ] ||
    [ "${E2E_RUNTIME}" = "firecracker" ]; then
    log "${E2E_RUNTIME} e2e completed"
    exit 0
fi

log "running cgroup-disabled e2e container ${DISABLED_CONTAINER}"
set +e
"${DOCKER}" run \
    --name "${DISABLED_CONTAINER}" \
    --init \
    --privileged \
    --net bridge \
    -e E2E_DISABLE_CGROUP=1 \
    -e E2E_RUNTIME=runsc \
    -e "E2E_RUNSC_PLATFORM=${E2E_RUNSC_PLATFORM}" \
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
