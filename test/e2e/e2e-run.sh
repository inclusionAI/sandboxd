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

SANDBOXD_HOME="${SANDBOXD_HOME:-/home/akernel/sandboxd}"
SANDBOXD_ROOT="${SANDBOXD_ROOT:-${SANDBOXD_HOME}/root}"
SANDBOXD_STORE="${SANDBOXD_STORE:-${SANDBOXD_HOME}/store}"
FILESTORE="${E2E_FILESTORE:-${SANDBOXD_HOME}/filestore}"
CONFIG_DIR="${SANDBOXD_HOME}/config"
CONFIG_FILE="${SANDBOXD_HOME}/config.toml"
SOCKET="${SANDBOXD_SOCKET:-/run/sandboxd/sandboxd.sock}"
LOG_FILE="${SANDBOXD_LOG_FILE:-/var/log/sandboxd/e2e.log}"
ROOTFS="${E2E_ROOTFS:-/e2e/rootfs}"
EROFS_ROOTFS="${E2E_EROFS_ROOTFS:-/e2e/rootfs.erofs}"
EROFS_MOUNT_ROOT="${E2E_EROFS_MOUNT_ROOT:-/e2e/erofs-mount-root}"
EROFS_MOUNT_IMAGE="${E2E_EROFS_MOUNT_IMAGE:-/e2e/data.erofs}"
FIRECRACKER_KERNEL="${E2E_FIRECRACKER_KERNEL:-/opt/firecracker/vmlinux}"
FIRECRACKER_INITRD="${E2E_FIRECRACKER_INITRD:-/opt/firecracker/initrd.img}"
FIRECRACKER_OVERLAY_BYTES="${E2E_FIRECRACKER_OVERLAY_BYTES:-134217728}"
HOST_MOUNT="${E2E_HOST_MOUNT:-/e2e/host-mount}"
WWW_ROOT="${E2E_WWW_ROOT:-/e2e/www}"
CGROUP_ROOT="${E2E_CGROUP_ROOT:-sandboxd-e2e}"
NETWORK_CIDR="${E2E_NETWORK_CIDR:-10.88.0.1/16}"
GATEWAY_IP="${E2E_GATEWAY_IP:-10.88.0.1}"
HTTP_PORT="${E2E_HTTP_PORT:-18080}"
DNAT_HOST_PORT="${E2E_DNAT_HOST_PORT:-18181}"
DNAT_GUEST_PORT="${E2E_DNAT_GUEST_PORT:-18180}"
BRIDGE_NAME="${E2E_BRIDGE_NAME:-sandbox0}"
NETWORK_SOAK="${E2E_NETWORK_SOAK:-0}"
REDIS_HOST="${E2E_REDIS_HOST:-}"
REDIS_ROOTFS_TAR="${E2E_REDIS_ROOTFS_TAR:-/e2e-fixtures/rootfs.tar}"
REDIS_ROOTFS="${E2E_REDIS_ROOTFS:-/e2e/redis-rootfs}"
REDIS_EROFS_ROOTFS="${E2E_REDIS_EROFS_ROOTFS:-/e2e/redis-rootfs.erofs}"
REDIS_DNAT_HOST_PORT="${E2E_REDIS_DNAT_HOST_PORT:-18379}"
REDIS_GUEST_PORT="${E2E_REDIS_GUEST_PORT:-6379}"
REDIS_RESULT_KEY="${E2E_REDIS_RESULT_KEY:-}"
REDIS_BENCHMARK_REQUESTS="${E2E_REDIS_BENCHMARK_REQUESTS:-20000}"
STRESS_ROUNDS="${E2E_STRESS_ROUNDS:-0}"
STRESS_CONCURRENCY="${E2E_STRESS_CONCURRENCY:-8}"
DISABLE_CGROUP="${E2E_DISABLE_CGROUP:-0}"
CPU_LIMIT_MODE="${E2E_CPU_LIMIT_MODE:-quota}"
E2E_RUNTIME="${E2E_RUNTIME:-all}"
E2E_RUNC_ONLY="${E2E_RUNC_ONLY:-0}"
RUNSC_PLATFORM="${E2E_RUNSC_PLATFORM:-systrap}"
export RUNSC_IGNORE_CGROUPS="${DISABLE_CGROUP}"

SANDBOXD_PID=""
HTTPD_PID=""
SANDBOX_ID=""
STRESS_IDS=()
CGROUP_MODE=""
CGROUP_DIR=""
CPU_CGROUP_DIR=""

log() {
    printf '[e2e] %s\n' "$*"
}

fail() {
    printf '[e2e][error] %s\n' "$*" >&2
    exit 1
}

select_iptables_backend() {
    if iptables -t nat -L >/dev/null 2>&1; then
        return
    fi

    local backend
    local binary
    local ip6_binary
    for backend in nft legacy; do
        binary="/usr/sbin/iptables-${backend}"
        ip6_binary="/usr/sbin/ip6tables-${backend}"
        if [ ! -x "${binary}" ] || ! "${binary}" -t nat -L >/dev/null 2>&1; then
            continue
        fi
        update-alternatives --set iptables "${binary}" >/dev/null
        if [ -x "${ip6_binary}" ]; then
            update-alternatives --set ip6tables "${ip6_binary}" >/dev/null
        fi
        log "selected iptables ${backend} backend"
        return
    done

    iptables -t nat -L || fail "iptables nat table is not usable"
}

cleanup_cgroups() {
    if [ "${DISABLE_CGROUP}" = "1" ]; then
        return
    fi
    if [ "${CGROUP_MODE}" = "v2" ]; then
        if [ -d "/sys/fs/cgroup/${CGROUP_ROOT}" ]; then
            find "/sys/fs/cgroup/${CGROUP_ROOT}" -depth -type d -print 2>/dev/null | while read -r dir; do
                rmdir "${dir}" 2>/dev/null || true
            done
        fi
        return
    fi

    local subsystem
    for subsystem in /sys/fs/cgroup/*; do
        if [ -d "${subsystem}/${CGROUP_ROOT}" ]; then
            find "${subsystem}/${CGROUP_ROOT}" -depth -type d -print 2>/dev/null | while read -r dir; do
                rmdir "${dir}" 2>/dev/null || true
            done
        fi
    done
}

cleanup() {
    local status=$?
    set +e

    if [ -n "${SANDBOX_ID}" ]; then
        /usr/local/bin/sbox --address "${SOCKET}" --timeout 20s delete "${SANDBOX_ID}" >/dev/null 2>&1
    fi
    local stress_id
    for stress_id in "${STRESS_IDS[@]}"; do
        /usr/local/bin/sbox --address "${SOCKET}" --timeout 20s delete "${stress_id}" >/dev/null 2>&1
    done
    if [ -n "${HTTPD_PID}" ]; then
        kill "${HTTPD_PID}" >/dev/null 2>&1
        wait "${HTTPD_PID}" >/dev/null 2>&1
    fi
    if [ -n "${SANDBOXD_PID}" ]; then
        kill "${SANDBOXD_PID}" >/dev/null 2>&1
        wait "${SANDBOXD_PID}" >/dev/null 2>&1
    fi
    cleanup_cgroups

    if [ "${status}" -ne 0 ] && [ -f "${LOG_FILE}" ]; then
        log "sandboxd log tail"
        tail -200 "${LOG_FILE}" >&2
    fi
    if [ "${status}" -ne 0 ] && [ -d /home/akernel/logs/runsc ]; then
        local runsc_log
        while IFS= read -r runsc_log; do
            log "runsc log tail: ${runsc_log}"
            tail -200 "${runsc_log}" >&2
        done < <(find /home/akernel/logs/runsc -type f | sort)
    fi
}
trap cleanup EXIT

preflight() {
    [ "$(id -u)" = "0" ] || fail "e2e container must run as root"
    [[ "${STRESS_ROUNDS}" =~ ^[0-9]+$ ]] || fail "E2E_STRESS_ROUNDS must be a non-negative integer"
    [[ "${STRESS_CONCURRENCY}" =~ ^[1-8]$ ]] || fail "E2E_STRESS_CONCURRENCY must be between 1 and 8"
    [[ "${DISABLE_CGROUP}" =~ ^[01]$ ]] || fail "E2E_DISABLE_CGROUP must be 0 or 1"
    [[ "${NETWORK_SOAK}" =~ ^[01]$ ]] || fail "E2E_NETWORK_SOAK must be 0 or 1"
    [[ "${REDIS_BENCHMARK_REQUESTS}" =~ ^[1-9][0-9]*$ ]] || fail "E2E_REDIS_BENCHMARK_REQUESTS must be positive"
    [[ "${CPU_LIMIT_MODE}" =~ ^(shares|quota)$ ]] || fail "E2E_CPU_LIMIT_MODE must be shares or quota"
    case "${E2E_RUNTIME}" in
        all|runsc|runc|kata|firecracker) ;;
        *) fail "E2E_RUNTIME must be all, runsc, runc, kata, or firecracker" ;;
    esac
    [[ "${RUNSC_PLATFORM}" =~ ^(systrap|kvm)$ ]] || fail "E2E_RUNSC_PLATFORM must be systrap or kvm"
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
    if [ "${E2E_RUNTIME}" = "runc" ] && [ "${DISABLE_CGROUP}" = "1" ]; then
        fail "runc e2e requires sandbox-managed cgroups"
    fi
    if [ "${E2E_RUNTIME}" = "kata" ] && [ "${DISABLE_CGROUP}" = "1" ]; then
        fail "Kata e2e requires sandbox-managed cgroups"
    fi
    if [ "${E2E_RUNTIME}" = "firecracker" ] && [ "${DISABLE_CGROUP}" = "1" ]; then
        fail "Firecracker e2e requires sandbox-managed cgroups"
    fi
    if [ "${NETWORK_SOAK}" = "1" ]; then
        [ "${E2E_RUNTIME}" != "all" ] ||
            fail "network soak requires one selected runtime"
        [ -n "${REDIS_HOST}" ] || fail "network soak requires E2E_REDIS_HOST"
        [ -n "${REDIS_RESULT_KEY}" ] ||
            fail "network soak requires E2E_REDIS_RESULT_KEY"
        [ -f "${REDIS_ROOTFS_TAR}" ] ||
            fail "network soak Redis rootfs tar is missing"
    fi

    local bin
    for bin in sandboxd sbox ip iptables busybox mkfs.erofs; do
        command -v "${bin}" >/dev/null 2>&1 || fail "missing command: ${bin}"
    done
    case "${E2E_RUNTIME}" in
        all)
            for bin in runsc runc runc-shim; do
                command -v "${bin}" >/dev/null 2>&1 || fail "missing command: ${bin}"
            done
            ;;
        runsc)
            command -v runsc >/dev/null 2>&1 || fail "missing command: runsc"
            ;;
        runc)
            for bin in runc runc-shim; do
                command -v "${bin}" >/dev/null 2>&1 || fail "missing command: ${bin}"
            done
            ;;
        kata)
            command -v containerd-shim-kata-v2 >/dev/null 2>&1 ||
                fail "missing command: containerd-shim-kata-v2"
            command -v sandbox-logger >/dev/null 2>&1 ||
                fail "missing command: sandbox-logger"
            [ -c /dev/kvm ] || fail "Kata e2e requires /dev/kvm"
            [ -f /opt/kata/share/defaults/kata-containers/runtime-rs/configuration-dragonball.toml ] ||
                fail "missing Kata Dragonball configuration"
            ;;
        firecracker)
            command -v firecracker >/dev/null 2>&1 || fail "missing command: firecracker"
            command -v mkfs.ext4 >/dev/null 2>&1 || fail "missing command: mkfs.ext4"
            [ -c /dev/kvm ] || fail "Firecracker e2e requires /dev/kvm"
            [ -f "${FIRECRACKER_KERNEL}" ] || fail "missing Firecracker kernel"
            [ -f "${FIRECRACKER_INITRD}" ] || fail "missing Firecracker initrd"
            ;;
    esac

    if [ "${DISABLE_CGROUP}" = "1" ]; then
        log "cgroup management disabled; skipping writable-cgroup preflight"
    elif [ -f /sys/fs/cgroup/cgroup.controllers ]; then
        CGROUP_MODE="v2"
        CGROUP_DIR="/sys/fs/cgroup/${CGROUP_ROOT}"
        local probe="/sys/fs/cgroup/${CGROUP_ROOT}-probe-$$"
        mkdir "${probe}" || fail "cannot create v2 cgroup; run container with --privileged --cgroupns=host"
        rmdir "${probe}" || true
    elif [ -d /sys/fs/cgroup/memory ]; then
        CGROUP_MODE="v1"
        CGROUP_DIR="/sys/fs/cgroup/memory/${CGROUP_ROOT}"
        local probe="/sys/fs/cgroup/memory/${CGROUP_ROOT}-probe-$$"
        mkdir "${probe}" || fail "cannot create v1 memory cgroup; run container with --privileged --cgroupns=host"
        rmdir "${probe}" || true
        local candidate
        for candidate in /sys/fs/cgroup/cpu /sys/fs/cgroup/cpu,cpuacct /sys/fs/cgroup/cpuacct,cpu /sys/fs/cgroup/cpu*; do
            if [ -f "${candidate}/cpu.shares" ]; then
                CPU_CGROUP_DIR="${candidate}"
                break
            fi
        done
        [ -n "${CPU_CGROUP_DIR}" ] || fail "cannot locate the cgroup v1 CPU controller"
    else
        fail "neither cgroup v1 nor cgroup v2 is available"
    fi
    if [ "${DISABLE_CGROUP}" != "1" ]; then
        log "detected ${CGROUP_MODE}"
    fi

    select_iptables_backend
}

write_config() {
    mkdir -p "${CONFIG_DIR}" "${SANDBOXD_ROOT}" "${SANDBOXD_STORE}" "$(dirname "${SOCKET}")" "$(dirname "${LOG_FILE}")"

    cat > "${CONFIG_DIR}/oss.json" <<'EOF'
{
  "oss": {
    "access_key_id": "",
    "access_key_secret": "",
    "bucket": "",
    "connect_timeout": 300,
    "endpoint": "",
    "object_prefix": "/",
    "proxy": {
      "check_interval": 60,
      "fallback": true,
      "ping_url": "",
      "url": ""
    },
    "retry_limit": 3,
    "scheme": "http",
    "timeout": 300
  },
  "type": "oss"
}
EOF

    cat > "${CONFIG_DIR}/registry.json" <<'EOF'
{
  "registry": {
    "auth": "",
    "blob_url_scheme": "http",
    "connect_timeout": 300,
    "host": "",
    "proxy": {
      "check_interval": 60,
      "fallback": true,
      "ping_url": "",
      "url": ""
    },
    "repo": "",
    "scheme": "https",
    "skip_verify": true,
    "timeout": 300
  },
  "type": "registry"
}
EOF

    cat > "${CONFIG_DIR}/oss_auths.json" <<'EOF'
{}
EOF

    cat > "${CONFIG_DIR}/registry_auths.json" <<'EOF'
{"auths": {}}
EOF

    local disable_cgroup=false
    if [ "${DISABLE_CGROUP}" = "1" ]; then
        disable_cgroup=true
    fi

    local runtime_binaries
    case "${E2E_RUNTIME}" in
        all)
            runtime_binaries=$'runsc = "/usr/local/bin/runsc"\nrunc = "/usr/local/bin/runc"'
            ;;
        runsc)
            runtime_binaries='runsc = "/usr/local/bin/runsc"'
            ;;
        runc)
            runtime_binaries='runc = "/usr/local/bin/runc"'
            ;;
        kata)
            runtime_binaries='kata = "/usr/local/bin/containerd-shim-kata-v2"'
            ;;
        firecracker)
            runtime_binaries='firecracker = "/usr/local/bin/firecracker"'
            ;;
    esac

    cat > "${CONFIG_FILE}" <<EOF
rootDir = "${SANDBOXD_ROOT}"
storeDir = "${SANDBOXD_STORE}"

[plugin.network]
ip_range = "${NETWORK_CIDR}"
nat_backend = "iptables"
enable_local_dnat = true
enable_network_acl = true

[plugin.resource]
disable_cgroup = ${disable_cgroup}
cpu_limit_mode = "${CPU_LIMIT_MODE}"
cgroup_cache_size = 1
interface_cache_size = 1
cgroup_root_name = "/${CGROUP_ROOT}"
max_instance_num = 8
pids_max = 64

[plugin.runtime]
image_lib_dir = "/e2e/images"
filestore_dir = "${FILESTORE}"
filestore_dir_size = "1G"
loop_device_dir = "/dev"
overlay_tmpfs_size = "64M"

[plugin.runtime.runsc]
platform = "${RUNSC_PLATFORM}"

[plugin.runtime.runc]
state_root = "/run/sandboxd/runc"
shim_binary = "/usr/local/bin/runc-shim"
# The e2e host does not require hardware virtualization. /dev/null lets the
# suite verify opt-in character-device and OCI device-cgroup injection.
kvm_device = "/dev/null"

[plugin.runtime.kata]
config_path = "/opt/kata/share/defaults/kata-containers/runtime-rs/configuration-dragonball.toml"
kvm_device = "/dev/kvm"
dan_config_dir = "/run/kata-containers/dans"
logger_binary = "/usr/local/bin/sandbox-logger"

[plugin.runtime.firecracker]
kernel_image_path = "${FIRECRACKER_KERNEL}"
initrd_path = "${FIRECRACKER_INITRD}"
kernel_args = "console=ttyS0 reboot=k panic=1 pci=off init=/init random.trust_cpu=on"
kvm_device = "/dev/kvm"
default_vcpu_count = 1
default_memory_mib = 256
default_overlay_size_bytes = ${FIRECRACKER_OVERLAY_BYTES}

[plugin.runtime.basic_spec]
runsc = ""
runc = ""
kata = ""
firecracker = ""

[plugin.runtime.runtime_binary]
${runtime_binaries}

[plugin.image]
root = "${SANDBOXD_HOME}/image_manager"
distill_fs_bin = "/usr/local/bin/distill_fs"
oss_template = "${CONFIG_DIR}/oss.json"
nydus_template = "${CONFIG_DIR}/registry.json"
nydus_suffix = "_nydus_v3"
oss_auths_path = "${CONFIG_DIR}/oss_auths.json"
registry_auths_path = "${CONFIG_DIR}/registry_auths.json"
cgroup_memory_limit = "0"
EOF
}

prepare_rootfs() {
    rm -rf "${ROOTFS}" "${EROFS_MOUNT_ROOT}" "${HOST_MOUNT}" "${WWW_ROOT}" \
        "${REDIS_ROOTFS}"
    rm -f "${EROFS_ROOTFS}" "${EROFS_MOUNT_IMAGE}" "${REDIS_EROFS_ROOTFS}"
    mkdir -p \
        "${ROOTFS}/bin" \
        "${ROOTFS}/dev" \
        "${ROOTFS}/etc" \
        "${ROOTFS}/mnt/host" \
        "${ROOTFS}/proc" \
        "${ROOTFS}/sys" \
        "${ROOTFS}/tmp" \
        "${ROOTFS}/usr/bin" \
        "${ROOTFS}/var" \
        "${EROFS_MOUNT_ROOT}" \
        "${HOST_MOUNT}" \
        "${WWW_ROOT}"
    chmod 1777 "${ROOTFS}/tmp"

    cp /bin/busybox "${ROOTFS}/bin/busybox"
    cp /usr/local/bin/oom-hog "${ROOTFS}/bin/oom-hog"
    while read -r applet; do
        if [ "${applet}" = "busybox" ]; then
            continue
        fi
        ln -sf /bin/busybox "${ROOTFS}/bin/${applet}"
    done < <(/bin/busybox --list)

    cat > "${ROOTFS}/etc/hosts" <<'EOF'
127.0.0.1 localhost
::1 localhost ip6-localhost ip6-loopback
EOF
    cat > "${ROOTFS}/etc/resolv.conf" <<'EOF'
nameserver 8.8.8.8
EOF

    echo "host-mount-ok" > "${HOST_MOUNT}/input.txt"
    echo "sandboxd-network-ok" > "${WWW_ROOT}/health.txt"
    echo "erofs-mount-ok" > "${EROFS_MOUNT_ROOT}/input.txt"
    mkfs.erofs "${EROFS_ROOTFS}" "${ROOTFS}" >/dev/null
    mkfs.erofs "${EROFS_MOUNT_IMAGE}" "${EROFS_MOUNT_ROOT}" >/dev/null

    if [ "${NETWORK_SOAK}" = "1" ]; then
        mkdir -p "${REDIS_ROOTFS}"
        tar -xf "${REDIS_ROOTFS_TAR}" -C "${REDIS_ROOTFS}"
        mkdir -p "${REDIS_ROOTFS}/dev" "${REDIS_ROOTFS}/proc" \
            "${REDIS_ROOTFS}/sys" "${REDIS_ROOTFS}/tmp"
        chmod 1777 "${REDIS_ROOTFS}/tmp"
        mkfs.erofs "${REDIS_EROFS_ROOTFS}" "${REDIS_ROOTFS}" >/dev/null
    fi
}

crash_sandboxd() {
    log "crashing sandboxd to exercise recovery"
    kill -9 "${SANDBOXD_PID}"
    wait "${SANDBOXD_PID}" >/dev/null 2>&1 || true
    SANDBOXD_PID=""
}

crash_and_restart_sandboxd() {
    crash_sandboxd
    start_sandboxd
}

start_sandboxd() {
    log "starting sandboxd"
    /usr/local/bin/sandboxd \
        --root "${SANDBOXD_HOME}" \
        --config "${CONFIG_FILE}" \
        --socket "${SOCKET}" \
        --log-level debug \
        --log-file "${LOG_FILE}" \
        --http-address "127.0.0.1:23001" &
    SANDBOXD_PID=$!

    local i
    for i in $(seq 1 60); do
        if ! kill -0 "${SANDBOXD_PID}" >/dev/null 2>&1; then
            fail "sandboxd exited during startup"
        fi
        if [ -S "${SOCKET}" ] && /usr/local/bin/sbox --address "${SOCKET}" --timeout 5s check >/dev/null 2>&1; then
            log "sandboxd socket ready"
            return 0
        fi
        sleep 1
    done
    fail "sandboxd did not become ready"
}

start_gateway_httpd() {
    local i
    for i in $(seq 1 20); do
        if ip addr show "${BRIDGE_NAME}" >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done
    ip addr show "${BRIDGE_NAME}" >/dev/null 2>&1 || fail "sandbox bridge ${BRIDGE_NAME} was not created"

    /bin/busybox httpd -f -p "${GATEWAY_IP}:${HTTP_PORT}" -h "${WWW_ROOT}" &
    HTTPD_PID=$!
}

sbox_cmd() {
    /usr/local/bin/sbox --address "${SOCKET}" --timeout 30s "$@"
}

set_network_policy() {
    local sandbox_id="$1"
    local policy="$2"
    shift 2
    /usr/local/bin/network-policy-client \
        --address "${SOCKET}" \
        --sandbox-id "${sandbox_id}" \
        --policy "${policy}" \
        "$@"
}

http_get_without_proxy() {
    local address="$1"
    local port="$2"
    local path="$3"
    printf 'GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n' \
        "${path}" "${address}" |
        /bin/nc -w 2 "${address}" "${port}" |
        tr -d '\r' |
        awk 'body { print } /^$/ { body = 1 }' |
        tail -1
}

assert_eq() {
    local got="$1"
    local want="$2"
    local name="$3"
    if [ "${got}" != "${want}" ]; then
        fail "${name}: got ${got@Q}, want ${want@Q}"
    fi
}

run_network_acl_checks() {
    local runtime_name="$1"
    local log_slug="$2"

    log "testing ${runtime_name} TAP network ACL updates"
    set_network_policy "${SANDBOX_ID}" deny-all
    if sbox_cmd exec "${SANDBOX_ID}" /bin/wget -T 2 -t 1 -qO- \
        "http://${GATEWAY_IP}:${HTTP_PORT}/health.txt" \
        >"/tmp/${log_slug}-acl-deny.log" 2>&1; then
        cat "/tmp/${log_slug}-acl-deny.log" >&2
        fail "${runtime_name} deny-all policy allowed gateway HTTP"
    fi

    set_network_policy "${SANDBOX_ID}" allow-http \
        --peer-address "${GATEWAY_IP}" \
        --peer-port "${HTTP_PORT}"
    local got
    got="$(sbox_cmd exec "${SANDBOX_ID}" /bin/wget -qO- \
        "http://${GATEWAY_IP}:${HTTP_PORT}/health.txt")"
    assert_eq "${got}" "sandboxd-network-ok" \
        "${runtime_name} allowlisted gateway HTTP"

    set_network_policy "${SANDBOX_ID}" dns-deny-all
    got="$(sbox_cmd exec "${SANDBOX_ID}" /bin/awk \
        '/^nameserver / { print $2; exit }' /etc/resolv.conf)"
    assert_eq "${got}" "${GATEWAY_IP}" "${runtime_name} managed resolver"
    if sbox_cmd exec "${SANDBOX_ID}" \
        /bin/timeout 2 /bin/nslookup blocked.invalid \
        >"/tmp/${log_slug}-dns-deny.log" 2>&1; then
        cat "/tmp/${log_slug}-dns-deny.log" >&2
        fail "${runtime_name} DNS deny-all policy allowed a query"
    fi

    set_network_policy "${SANDBOX_ID}" clear
    got="$(sbox_cmd exec "${SANDBOX_ID}" /bin/wget -qO- \
        "http://${GATEWAY_IP}:${HTTP_PORT}/health.txt")"
    assert_eq "${got}" "sandboxd-network-ok" \
        "${runtime_name} cleared network policy"
}

run_dnat_check() {
    local runtime="$1"
    local runtime_name="$2"
    local rootfs="$3"
    local memory_mb="$4"
    local expected="${runtime}-dnat-ok"

    log "testing ${runtime_name} DNAT port forwarding"
    SANDBOX_ID="$(sbox_cmd start \
        --quiet \
        --runtime "${runtime}" \
        --sandbox-id "sbox-e2e-${runtime}-dnat" \
        --rootfs "${rootfs}" \
        --port "tcp:${DNAT_HOST_PORT}:${DNAT_GUEST_PORT}" \
        --cpu-millicores 100 \
        --memory-mb "${memory_mb}" \
        /bin/sh -c "mkdir -p /var/www; \
            echo ${expected} > /var/www/health.txt; \
            exec /bin/httpd -f -p 0.0.0.0:${DNAT_GUEST_PORT} -h /var/www")"
    wait_for_state "${SANDBOX_ID}" "SANDBOX_STATE_RUNNING" 300

    local dnat_target_ip
    dnat_target_ip="$(iptables -t nat -S PREROUTING | awk \
        -v port="${DNAT_HOST_PORT}" \
        '$0 ~ "--dport " port {
            for (field = 1; field <= NF; field++) {
                if ($field == "--to-destination") {
                    split($(field + 1), destination, ":")
                    print destination[1]
                    exit
                }
            }
        }')"
    [ -n "${dnat_target_ip}" ] ||
        fail "${runtime_name} DNAT target IP is missing"

    local direct_response=""
    local dnat_response=""
    local dnat_attempt
    for dnat_attempt in $(seq 1 100); do
        direct_response="$(http_get_without_proxy \
            "${dnat_target_ip}" "${DNAT_GUEST_PORT}" /health.txt || true)"
        if [ "${direct_response}" = "${expected}" ]; then
            break
        fi
        sleep 0.1
    done
    if [ "${direct_response}" != "${expected}" ]; then
        sbox_cmd exec "${SANDBOX_ID}" /bin/netstat -ltn >&2 || true
        sbox_cmd exec "${SANDBOX_ID}" /bin/ip address show >&2 || true
        sbox_cmd exec "${SANDBOX_ID}" /bin/ip route show >&2 || true
        ping -c 1 -W 1 "${dnat_target_ip}" >&2 || true
        ip neigh show "${dnat_target_ip}" >&2 || true
        bridge fdb show >&2 || true
        iptables -t nat -nvL OUTPUT >&2 || true
        iptables -t nat -nvL PREROUTING >&2 || true
    fi
    assert_eq "${direct_response}" "${expected}" \
        "${runtime_name} published service"

    for dnat_attempt in $(seq 1 100); do
        dnat_response="$(http_get_without_proxy \
            "${GATEWAY_IP}" "${DNAT_HOST_PORT}" /health.txt || true)"
        if [ "${dnat_response}" = "${expected}" ]; then
            break
        fi
        sleep 0.1
    done
    if [ "${dnat_response}" != "${expected}" ]; then
        iptables -t nat -nvL OUTPUT >&2 || true
        iptables -t nat -nvL PREROUTING >&2 || true
        iptables -t nat -nvL POSTROUTING >&2 || true
        ip route show >&2 || true
    fi
    assert_eq "${dnat_response}" "${expected}" \
        "${runtime_name} local DNAT"

    sbox_cmd delete "${SANDBOX_ID}"
    SANDBOX_ID=""
}

run_network_soak() {
    local runtime="${1}"
    local rootfs="${REDIS_ROOTFS}"
    if [ "${runtime}" = "firecracker" ]; then
        rootfs="${REDIS_EROFS_ROOTFS}"
    fi

    log "testing ${runtime} Redis traffic over SNAT and DNAT"
    SANDBOX_ID="$(sbox_cmd start \
        --quiet \
        --runtime "${runtime}" \
        --sandbox-id "sbox-e2e-${runtime}-redis" \
        --rootfs "${rootfs}" \
        --port "tcp:${REDIS_DNAT_HOST_PORT}:${REDIS_GUEST_PORT}" \
        --cpu-millicores 500 \
        --memory-mb 512 \
        -- \
        /usr/local/bin/redis-server \
            --save "" \
            --appendonly no \
            --protected-mode no \
            --bind 0.0.0.0 \
            --dir /tmp)"
    [ -n "${SANDBOX_ID}" ] ||
        fail "${runtime} Redis start returned empty sandbox id"
    wait_for_state "${SANDBOX_ID}" "SANDBOX_STATE_RUNNING" 300

    local i
    local got=""
    for i in $(seq 1 300); do
        got="$(sbox_cmd exec -- "${SANDBOX_ID}" \
            /usr/local/bin/redis-cli \
            -h 127.0.0.1 \
            -p "${REDIS_GUEST_PORT}" \
            ping 2>/dev/null || true)"
        if [ "${got}" = "PONG" ]; then
            break
        fi
        sleep 0.1
    done
    assert_eq "${got}" "PONG" "${runtime} guest Redis readiness"

    local egress_ip
    egress_ip="$(ip -4 route get "${REDIS_HOST}" | awk \
        '{ for (i = 1; i <= NF; i++) if ($i == "src") { print $(i + 1); exit } }')"
    [ -n "${egress_ip}" ] || fail "cannot resolve Redis egress source address"
    local clients
    clients="$(sbox_cmd exec -- "${SANDBOX_ID}" \
        /usr/local/bin/redis-cli \
        --raw \
        -h "${REDIS_HOST}" \
        -p 6379 \
        CLIENT LIST)"
    if ! grep -q "addr=${egress_ip}:" <<<"${clients}"; then
        printf '%s\n' "${clients}" >&2
        fail "${runtime} Redis did not observe the sandboxd SNAT address ${egress_ip}"
    fi

    local snat_output
    snat_output="$(sbox_cmd exec -- "${SANDBOX_ID}" \
        /usr/local/bin/redis-benchmark \
        -h "${REDIS_HOST}" \
        -p 6379 \
        --csv \
        -n "${REDIS_BENCHMARK_REQUESTS}" \
        -c 16 \
        -P 4 \
        -t set,get)"
    printf '%s\n' "${snat_output}"
    grep -q '^"SET",' <<<"${snat_output}" ||
        fail "${runtime} Redis SNAT benchmark has no SET result"
    grep -q '^"GET",' <<<"${snat_output}" ||
        fail "${runtime} Redis SNAT benchmark has no GET result"

    local dnat_result=""
    for i in $(seq 1 300); do
        dnat_result="$(sbox_cmd exec -- "${SANDBOX_ID}" \
            /usr/local/bin/redis-cli \
            --raw \
            -h "${REDIS_HOST}" \
            -p 6379 \
            GET "${REDIS_RESULT_KEY}")"
        if [ "${dnat_result}" != "pending" ] && [ -n "${dnat_result}" ]; then
            break
        fi
        sleep 0.1
    done
    assert_eq "${dnat_result}" "pass" "${runtime} Redis DNAT benchmark"

    local dnat_packets
    dnat_packets="$(iptables -t nat -nvL PREROUTING -x | awk \
        -v port="${REDIS_DNAT_HOST_PORT}" \
        '$0 ~ "dpt:" port { packets += $1 } END { print packets + 0 }')"
    [ "${dnat_packets}" -gt 0 ] ||
        fail "${runtime} Redis DNAT rule did not count ingress packets"

    sbox_cmd delete "${SANDBOX_ID}"
    SANDBOX_ID=""
}

wait_for_state() {
    local sandbox_id="$1"
    local expected="$2"
    local attempts="${3:-100}"
    local line=""
    local i
    for i in $(seq 1 "${attempts}"); do
        line="$(sbox_cmd list | grep "${sandbox_id}" || true)"
        if echo "${line}" | grep -q "${expected}"; then
            return 0
        fi
        sleep 0.1
    done
    fail "sandbox ${sandbox_id} did not reach ${expected}; last state: ${line}"
}

wait_for_exec_output() {
    local sandbox_id="$1"
    local expected="$2"
    shift 2
    local got=""
    local i
    for i in $(seq 1 100); do
        if got="$(sbox_cmd exec "${sandbox_id}" "$@" 2>/dev/null)" && \
            [ "${got}" = "${expected}" ]; then
            return 0
        fi
        sleep 0.1
    done
    fail "sandbox ${sandbox_id} command output did not become ${expected@Q}; last output: ${got@Q}"
}

wait_for_file_text() {
    local path="$1"
    local expected="$2"
    local i
    for i in $(seq 1 100); do
        if [ -f "${path}" ] && grep -Fq "${expected}" "${path}"; then
            return 0
        fi
        sleep 0.1
    done
    fail "file ${path} did not contain ${expected@Q}"
}

list_cached_taps() {
    ip -o link show master "${BRIDGE_NAME}" 2>/dev/null |
        awk -F ': ' '$2 ~ /^tap\./ { sub(/@.*/, "", $2); print $2 }' |
        sort
}

wait_for_leased_tap() {
    local tap
    local i
    for i in $(seq 1 100); do
        while IFS= read -r tap; do
            if [ -n "${tap}" ] &&
                ip -o link show "${tap}" | grep -q '<[^>]*UP'; then
                echo "${tap}"
                return 0
            fi
        done < <(list_cached_taps)
        sleep 0.1
    done
    fail "no leased TAP appeared on bridge ${BRIDGE_NAME}"
}

wait_for_cgroup_child() {
    local i
    local child=""
    for i in $(seq 1 100); do
        child="$(find "${CGROUP_DIR}" -mindepth 1 -maxdepth 1 -type d -print 2>/dev/null | head -1)"
        if [ -n "${child}" ]; then
            echo "${child}"
            return 0
        fi
        sleep 0.1
    done
    fail "no cached cgroup appeared below ${CGROUP_DIR}"
}

wait_for_cgroup_count() {
    local expected="$1"
    local count=0
    local i
    for i in $(seq 1 100); do
        count="$(find "${CGROUP_DIR}" -mindepth 1 -maxdepth 1 -type d -print 2>/dev/null | wc -l)"
        if [ "${count}" -eq "${expected}" ]; then
            return 0
        fi
        sleep 0.1
    done
    fail "cgroup child count did not reach ${expected}; last count: ${count}"
}

wait_for_process_exit() {
    local pid="$1"
    local description="$2"
    local remaining=100
    local state=""
    while [ "${remaining}" -gt 0 ]; do
        if [ ! -r "/proc/${pid}/stat" ]; then
            return 0
        fi
        state="$(sed -n 's/^.*) \([^ ]\).*/\1/p' "/proc/${pid}/stat")"
        if [ -z "${state}" ] || [ "${state}" = "Z" ]; then
            return 0
        fi
        remaining=$((remaining - 1))
        sleep 0.1
    done
    fail "${description} pid ${pid} is still running"
}

assert_cgroup_limits() {
    local child="$1"
    local cpu_millicores="$2"
    local memory_mb="$3"
    local group_name
    group_name="$(basename "${child}")"
    local shares=$((cpu_millicores * 1024 / 1000))
    if [ "${shares}" -lt 2 ]; then
        shares=2
    fi
    local quota=$((cpu_millicores * 100))
    if [ "${quota}" -lt 1000 ]; then
        quota=1000
    fi
    local memory_bytes=$((memory_mb * 1024 * 1024))

    if [ "${CGROUP_MODE}" = "v2" ]; then
        if [ "${CPU_LIMIT_MODE}" = "quota" ]; then
            assert_eq "$(tr -d '\n' < "${child}/cpu.weight")" "100" "v2 default cpu.weight"
            assert_eq "$(tr -d '\n' < "${child}/cpu.max")" "${quota} 100000" "v2 cpu.max"
        else
            local weight=$((1 + (shares - 2) * 9999 / 262142))
            assert_eq "$(tr -d '\n' < "${child}/cpu.weight")" "${weight}" "v2 cpu.weight"
            assert_eq "$(tr -d '\n' < "${child}/cpu.max")" "max 100000" "v2 unlimited cpu.max"
        fi
        assert_eq "$(tr -d '\n' < "${child}/memory.max")" "${memory_bytes}" "v2 memory.max"
        assert_eq "$(tr -d '\n' < "${child}/pids.max")" "64" "v2 pids.max"
    else
        local cpu_path="${CPU_CGROUP_DIR}/${CGROUP_ROOT}/${group_name}"
        if [ "${CPU_LIMIT_MODE}" = "quota" ]; then
            assert_eq "$(tr -d '\n' < "${cpu_path}/cpu.shares")" "1024" "v1 default cpu.shares"
            assert_eq "$(tr -d '\n' < "${cpu_path}/cpu.cfs_quota_us")" "${quota}" "v1 cpu quota"
            assert_eq "$(tr -d '\n' < "${cpu_path}/cpu.cfs_period_us")" "100000" "v1 cpu period"
        else
            assert_eq "$(tr -d '\n' < "${cpu_path}/cpu.shares")" "${shares}" "v1 cpu.shares"
            assert_eq "$(tr -d '\n' < "${cpu_path}/cpu.cfs_quota_us")" "-1" "v1 unlimited cpu quota"
        fi
        assert_eq "$(tr -d '\n' < "${child}/memory.limit_in_bytes")" "${memory_bytes}" "v1 memory.limit"
        assert_eq \
            "$(tr -d '\n' < "/sys/fs/cgroup/pids/${CGROUP_ROOT}/${group_name}/pids.max")" \
            "64" \
            "v1 pids.max"
    fi
}

wait_for_exit_code_log() {
    local sandbox_id="$1"
    local exit_code="$2"
    local i
    for i in $(seq 1 100); do
        if grep -q \
            "wait sandbox ${sandbox_id} finished.*ExitCode:${exit_code}" \
            "${LOG_FILE}"; then
            return 0
        fi
        sleep 0.1
    done
    fail "sandbox ${sandbox_id} did not record exit code ${exit_code}"
}

assert_wait_log() {
    local sandbox_id="$1"
    local oom="$2"
    local i
    for i in $(seq 1 100); do
        if grep -q "wait sandbox ${sandbox_id} finished.*oom: ${oom}" "${LOG_FILE}"; then
            return 0
        fi
        sleep 0.1
    done
    if [ "${CGROUP_MODE}" = "v2" ]; then
        find "${CGROUP_DIR}" -mindepth 1 -maxdepth 1 -type d -print 2>/dev/null | while read -r dir; do
            log "${dir}/memory.events"
            cat "${dir}/memory.events" >&2 || true
        done
    fi
    fail "sandbox ${sandbox_id} did not record oom=${oom}"
}

run_stress_checks() {
    local runtime="${1:-runsc}"
    local rootfs="${2:-${ROOTFS}}"
    if [ "${STRESS_ROUNDS}" -eq 0 ]; then
        return
    fi

    log "running ${STRESS_ROUNDS} ${runtime} stress rounds at concurrency ${STRESS_CONCURRENCY}"
    local round
    local slot
    local id
    local -a pids
    for round in $(seq 1 "${STRESS_ROUNDS}"); do
        STRESS_IDS=()
        pids=()
        for slot in $(seq 1 "${STRESS_CONCURRENCY}"); do
            id="sbox-e2e-stress-${round}-${slot}"
            STRESS_IDS+=("${id}")
            sbox_cmd start \
                --quiet \
                --runtime "${runtime}" \
                --sandbox-id "${id}" \
                --rootfs "${rootfs}" \
                --cpu-millicores 100 \
                --memory-mb 128 \
                /bin/sleep 300 >"/tmp/${id}.start.log" 2>&1 &
            pids+=("$!")
        done
        for slot in "${!pids[@]}"; do
            if ! wait "${pids[$slot]}"; then
                cat "/tmp/${STRESS_IDS[$slot]}.start.log" >&2
                fail "stress start failed for ${STRESS_IDS[$slot]}"
            fi
        done
        for id in "${STRESS_IDS[@]}"; do
            wait_for_state "${id}" "SANDBOX_STATE_RUNNING"
        done
        wait_for_cgroup_count "${STRESS_CONCURRENCY}"

        pids=()
        for id in "${STRESS_IDS[@]}"; do
            sbox_cmd delete "${id}" >"/tmp/${id}.delete.log" 2>&1 &
            pids+=("$!")
        done
        for slot in "${!pids[@]}"; do
            if ! wait "${pids[$slot]}"; then
                cat "/tmp/${STRESS_IDS[$slot]}.delete.log" >&2
                fail "stress delete failed for ${STRESS_IDS[$slot]}"
            fi
        done
        wait_for_cgroup_count 1
        STRESS_IDS=()
    done
    log "stress checks passed"
}

run_storage_quota_check() {
    local runtime="${1:-runsc}"
    local rootfs="${2:-${ROOTFS}}"

    log "testing ${runtime} writable-layer storage quota"
    SANDBOX_ID="$(sbox_cmd start \
        --quiet \
        --runtime "${runtime}" \
        --sandbox-id sbox-e2e-storage \
        --rootfs "${rootfs}" \
        --storage-mb 16 \
        /bin/sleep 300)"
    [ -n "${SANDBOX_ID}" ] || fail "storage quota start returned empty sandbox id"

    local got
    got="$(sbox_cmd exec "${SANDBOX_ID}" /bin/sh -c \
        'dd if=/dev/zero of=/var/within-quota bs=1M count=1 2>/dev/null && wc -c < /var/within-quota')"
    assert_eq "${got}" "1048576" "write below storage quota"

    if sbox_cmd exec "${SANDBOX_ID}" /bin/sh -c \
        'dd if=/dev/urandom of=/var/over-quota bs=1M count=32' \
        >/tmp/sbox-storage-quota.log 2>&1; then
        cat /tmp/sbox-storage-quota.log >&2
        fail "write above storage quota unexpectedly succeeded"
    fi
    if ! grep -qi "No space left on device" /tmp/sbox-storage-quota.log; then
        cat /tmp/sbox-storage-quota.log >&2
        fail "write above storage quota did not return ENOSPC"
    fi

    sbox_cmd exec "${SANDBOX_ID}" /bin/rm -f /var/within-quota /var/over-quota

    sbox_cmd delete "${SANDBOX_ID}"
    SANDBOX_ID=""
}

run_runc_checks() {
    log "testing runc directory rootfs, KVM injection, and recovery"
    SANDBOX_ID="$(sbox_cmd start \
        --quiet \
        --runtime runc \
        --sandbox-id sbox-e2e-runc \
        --rootfs "${ROOTFS}" \
        --cwd / \
        --enable-kvm \
        --env E2E_MARKER=runc-env-ok \
        --mount "${HOST_MOUNT}:/mnt/host" \
        --cpu-millicores 200 \
        --memory-mb 128 \
        /bin/sh -c 'echo "$E2E_MARKER" > /tmp/start-env && sleep 300')"
    [ -n "${SANDBOX_ID}" ] || fail "runc start returned empty sandbox id"
    wait_for_state "${SANDBOX_ID}" "SANDBOX_STATE_RUNNING"

    local got
    wait_for_exec_output "${SANDBOX_ID}" "runc-env-ok" /bin/cat /tmp/start-env
    got="$(sbox_cmd exec "${SANDBOX_ID}" /bin/sh -c 'echo runc-write-ok > /tmp/runc-write && cat /tmp/runc-write')"
    assert_eq "${got}" "runc-write-ok" "runc writable overlay"
    [ ! -e "${ROOTFS}/tmp/runc-write" ] || fail "runc write escaped into the source rootfs"
    got="$(sbox_cmd exec "${SANDBOX_ID}" /bin/cat /mnt/host/input.txt)"
    assert_eq "${got}" "host-mount-ok" "runc host bind mount"
    got="$(sbox_cmd exec "${SANDBOX_ID}" /bin/wget -qO- "http://${GATEWAY_IP}:${HTTP_PORT}/health.txt")"
    assert_eq "${got}" "sandboxd-network-ok" "runc sandbox network"
    sbox_cmd exec "${SANDBOX_ID}" /bin/test -c /dev/kvm
    local tty_status=0
    printf 'exit 7\n' | sbox_cmd exec -t "${SANDBOX_ID}" /bin/sh || tty_status=$?
    assert_eq "${tty_status}" "7" "runc TTY exit status"

    [ -d "${FILESTORE}/.runc/${SANDBOX_ID}/upper" ] || fail "runc upperdir is not in the shared filestore"
    local netns_path="/var/run/netns/runc-${SANDBOX_ID}"
    [ -e "${netns_path}" ] || fail "runc named network namespace is missing"
    local cache_cgroup
    cache_cgroup="$(wait_for_cgroup_child)"
    [ -d "${cache_cgroup}/runc" ] || fail "runc did not use a child below the cached cgroup"

    # Resource-pool ownership is checkpointed periodically. Let that checkpoint
    # complete before simulating the same post-start crash used by runsc below.
    sleep 6
    crash_and_restart_sandboxd
    wait_for_state "${SANDBOX_ID}" "SANDBOX_STATE_RUNNING"
    got="$(sbox_cmd exec "${SANDBOX_ID}" /bin/echo recovered-runc)"
    assert_eq "${got}" "recovered-runc" "runc exec after sandboxd restart"

    local deleted_id="${SANDBOX_ID}"
    sbox_cmd delete "${deleted_id}"
    SANDBOX_ID=""
    [ ! -e "${netns_path}" ] || fail "runc netns leaked after delete"
    [ ! -e "${FILESTORE}/.runc/${deleted_id}" ] || fail "runc storage leaked after delete"
    [ ! -e "${cache_cgroup}/runc" ] || fail "runc child cgroup leaked after delete"
    sbox_cmd delete "${deleted_id}"

    log "testing runc EROFS rootfs and EROFS mount"
    SANDBOX_ID="$(sbox_cmd start \
        --quiet \
        --runtime runc \
        --sandbox-id sbox-e2e-runc-erofs \
        --rootfs "${EROFS_ROOTFS}" \
        --mount "${EROFS_MOUNT_IMAGE}:/mnt/erofs:erofs:ro" \
        --cpu-millicores 200 \
        --memory-mb 128 \
        /bin/sleep 300)"
    wait_for_state "${SANDBOX_ID}" "SANDBOX_STATE_RUNNING"
    got="$(sbox_cmd exec "${SANDBOX_ID}" /bin/cat /mnt/erofs/input.txt)"
    assert_eq "${got}" "erofs-mount-ok" "runc EROFS mount"
    got="$(sbox_cmd exec "${SANDBOX_ID}" /bin/sh -c 'echo erofs-overlay-ok > /tmp/overlay && cat /tmp/overlay')"
    assert_eq "${got}" "erofs-overlay-ok" "runc EROFS writable overlay"
    sbox_cmd delete "${SANDBOX_ID}"
    SANDBOX_ID=""

    log "testing runc natural exit"
    SANDBOX_ID="$(sbox_cmd start \
        --quiet \
        --runtime runc \
        --sandbox-id sbox-e2e-runc-exit \
        --rootfs "${ROOTFS}" \
        --cpu-millicores 100 \
        --memory-mb 128 \
        /bin/sh -c 'exit 23')"
    wait_for_state "${SANDBOX_ID}" "SANDBOX_STATE_EXITED"
    wait_for_exit_code_log "${SANDBOX_ID}" 23
    sbox_cmd delete "${SANDBOX_ID}"
    SANDBOX_ID=""
}

run_kata_checks() {
    log "testing Kata runtime-rs with a cached TAP endpoint"
    # Keep BusyBox ash from waiting as PID 1: Kata exec exits deliver SIGCHLD
    # to the container init process and can otherwise end its foreground sleep.
    SANDBOX_ID="$(sbox_cmd start \
        --quiet \
        --runtime kata \
        --sandbox-id sbox-e2e-kata \
        --rootfs "${ROOTFS}" \
        --cwd / \
        --env E2E_MARKER=kata-env-ok \
        --mount "${HOST_MOUNT}:/mnt/host" \
        --cpu-millicores 500 \
        --memory-mb 512 \
        /bin/sh -c 'echo "$E2E_MARKER" > /tmp/start-env && exec sleep 300')"
    [ -n "${SANDBOX_ID}" ] || fail "Kata start returned empty sandbox id"
    wait_for_state "${SANDBOX_ID}" "SANDBOX_STATE_RUNNING" 300

    local cached_tap
    cached_tap="$(wait_for_leased_tap)"
    if ! ip -o link show "${cached_tap}" | grep -q '<[^>]*UP'; then
        fail "leased Kata TAP ${cached_tap} is not administratively up"
    fi
    local dan_config="/run/kata-containers/dans/${SANDBOX_ID}.json"
    [ -f "${dan_config}" ] || fail "Kata DAN configuration is missing"
    jq -e --arg tap "${cached_tap}" \
        '.devices[0].device.type == "host-tap" and
         .devices[0].device.tap_name == $tap and
         .devices[0].name == "eth0"' \
        "${dan_config}" >/dev/null ||
        fail "Kata DAN configuration does not reference cached TAP ${cached_tap}"

    local cache_cgroup
    cache_cgroup="$(wait_for_cgroup_child)"
    assert_cgroup_limits "${cache_cgroup}" 500 512

    local got
    wait_for_exec_output "${SANDBOX_ID}" "kata-env-ok" /bin/cat /tmp/start-env
    got="$(sbox_cmd exec "${SANDBOX_ID}" /bin/sh -c \
        'echo kata-write-ok > /tmp/kata-write && cat /tmp/kata-write')"
    assert_eq "${got}" "kata-write-ok" "Kata writable rootfs"
    [ ! -e "${ROOTFS}/tmp/kata-write" ] ||
        fail "Kata write escaped into the source rootfs"
    got="$(printf 'kata-stdin-ok' | sbox_cmd exec "${SANDBOX_ID}" /bin/cat)"
    assert_eq "${got}" "kata-stdin-ok" "Kata exec stdin"

    got="$(sbox_cmd exec "${SANDBOX_ID}" /bin/cat /mnt/host/input.txt)"
    assert_eq "${got}" "host-mount-ok" "Kata host bind mount"
    got="$(sbox_cmd exec "${SANDBOX_ID}" /bin/wget -qO- \
        "http://${GATEWAY_IP}:${HTTP_PORT}/health.txt")"
    assert_eq "${got}" "sandboxd-network-ok" "Kata cached TAP network"
    run_network_acl_checks "Kata" kata
    sbox_cmd stats "${SANDBOX_ID}" | grep -q "Memory Usage" ||
        fail "Kata stats output missing memory usage"

    local tty_status=0
    printf 'exit 7\n' | sbox_cmd exec -t "${SANDBOX_ID}" /bin/sh >/dev/null ||
        tty_status=$?
    assert_eq "${tty_status}" "7" "Kata TTY exit status"

    sleep 6
    crash_and_restart_sandboxd
    wait_for_state "${SANDBOX_ID}" "SANDBOX_STATE_RUNNING" 300
    got="$(sbox_cmd exec "${SANDBOX_ID}" /bin/echo recovered-kata)"
    assert_eq "${got}" "recovered-kata" "Kata exec after sandboxd restart"

    local deleted_id="${SANDBOX_ID}"
    sbox_cmd delete "${deleted_id}"
    SANDBOX_ID=""
    [ ! -e "${dan_config}" ] || fail "Kata DAN configuration leaked after delete"
    if ip -o link show "${cached_tap}" | grep -q '<[^>]*UP'; then
        fail "recycled Kata TAP ${cached_tap} remained administratively up"
    fi
    sbox_cmd delete "${deleted_id}"

    run_dnat_check kata "Kata" "${ROOTFS}" 256

    log "testing Kata natural exit"
    SANDBOX_ID="$(sbox_cmd start \
        --quiet \
        --runtime kata \
        --sandbox-id sbox-e2e-kata-exit \
        --rootfs "${ROOTFS}" \
        --cpu-millicores 100 \
        --memory-mb 256 \
        /bin/sh -c 'exit 23')"
    wait_for_state "${SANDBOX_ID}" "SANDBOX_STATE_EXITED" 300
    wait_for_exit_code_log "${SANDBOX_ID}" 23
    sbox_cmd delete "${SANDBOX_ID}"
    SANDBOX_ID=""
}

run_firecracker_checks() {
    log "testing Firecracker EROFS root, writable layer, exec, and network"
    local main_stdout="/tmp/firecracker-main.stdout"
    local main_stderr="/tmp/firecracker-main.stderr"
    rm -f "${main_stdout}" "${main_stderr}" /tmp/firecracker-exec.stderr

    SANDBOX_ID="$(sbox_cmd start \
        --quiet \
        --runtime firecracker \
        --sandbox-id sbox-e2e-firecracker \
        --rootfs "${EROFS_ROOTFS}" \
        --cwd / \
        --env E2E_MARKER=firecracker-env-ok \
        --mount "${HOST_MOUNT}/input.txt:/mnt/host/input.txt:bind:ro" \
        --mount "${EROFS_MOUNT_IMAGE}:/mnt/erofs:erofs:ro" \
        --mount "tmpfs:/mnt/ram:tmpfs:rw,nosuid,nodev,noexec,size=1m,mode=0755" \
        --stdout "${main_stdout}" \
        --stderr "${main_stderr}" \
        --cpu-millicores 1500 \
        --memory-mb 256 \
        /bin/sh -c 'echo "$E2E_MARKER" > /var/start-env; echo firecracker-main-stdout; sleep 300')"
    [ -n "${SANDBOX_ID}" ] || fail "Firecracker start returned empty sandbox id"
    wait_for_state "${SANDBOX_ID}" "SANDBOX_STATE_RUNNING"

    local cached_tap
    cached_tap="$(wait_for_leased_tap)"
    if ! ip -o link show "${cached_tap}" | grep -q '<[^>]*UP'; then
        fail "leased Firecracker TAP ${cached_tap} is not administratively up"
    fi

    local cache_cgroup
    cache_cgroup="$(wait_for_cgroup_child)"
    assert_cgroup_limits "${cache_cgroup}" 1500 256

    local got
    wait_for_exec_output "${SANDBOX_ID}" "firecracker-env-ok" /bin/cat /var/start-env
    got="$(sbox_cmd exec "${SANDBOX_ID}" /bin/sh -c \
        'echo firecracker-write-ok > /var/firecracker-write && cat /var/firecracker-write')"
    assert_eq "${got}" "firecracker-write-ok" "Firecracker writable overlay"
    got="$(sbox_cmd exec "${SANDBOX_ID}" /bin/sh -c \
        'echo tmpfs-ok > /mnt/ram/check && cat /mnt/ram/check')"
    assert_eq "${got}" "tmpfs-ok" "Firecracker private tmpfs mount"
    sbox_cmd exec "${SANDBOX_ID}" /bin/mount | grep -Fq " on /mnt/ram type tmpfs "
    got="$(sbox_cmd exec "${SANDBOX_ID}" /bin/nproc)"
    assert_eq "${got}" "2" "Firecracker guest vCPU count"

    got="$(sbox_cmd exec "${SANDBOX_ID}" /bin/cat /mnt/host/input.txt)"
    assert_eq "${got}" "host-mount-ok" "Firecracker read-only file injection"
    if sbox_cmd exec "${SANDBOX_ID}" /bin/sh -c \
        'echo changed > /mnt/host/input.txt' >/tmp/firecracker-bind-write.log 2>&1; then
        cat /tmp/firecracker-bind-write.log >&2
        fail "Firecracker read-only injected file was writable"
    fi
    assert_eq "$(cat "${HOST_MOUNT}/input.txt")" "host-mount-ok" "Firecracker host file unchanged"

    got="$(sbox_cmd exec "${SANDBOX_ID}" /bin/cat /mnt/erofs/input.txt)"
    assert_eq "${got}" "erofs-mount-ok" "Firecracker EROFS mount"
    wait_for_exec_output "${SANDBOX_ID}" "sandboxd-network-ok" \
        /bin/wget -qO- \
        "http://${GATEWAY_IP}:${HTTP_PORT}/health.txt"
    run_network_acl_checks "Firecracker" firecracker

    sbox_cmd stats "${SANDBOX_ID}" | grep -q "Memory Usage" || \
        fail "Firecracker stats output missing memory usage"

    local exec_status=0
    got="$(sbox_cmd exec "${SANDBOX_ID}" /bin/sh -c \
        'echo firecracker-exec-stdout; echo firecracker-exec-stderr >&2; exit 19' \
        2>/tmp/firecracker-exec.stderr)" || exec_status=$?
    assert_eq "${exec_status}" "19" "Firecracker exec exit status"
    assert_eq "${got}" "firecracker-exec-stdout" "Firecracker exec stdout"
    assert_eq "$(tr -d '\r\n' < /tmp/firecracker-exec.stderr)" \
        "firecracker-exec-stderr" "Firecracker exec stderr"

    local tty_status=0
    printf 'exit 7\n' | sbox_cmd exec -t "${SANDBOX_ID}" /bin/sh >/dev/null || tty_status=$?
    assert_eq "${tty_status}" "7" "Firecracker TTY exit status"

    wait_for_file_text "${main_stdout}" "firecracker-main-stdout"

    local overlay="${FILESTORE}/.firecracker/${SANDBOX_ID}/overlay.ext4"
    [ -f "${overlay}" ] || fail "Firecracker writable layer is missing from the filestore"
    assert_eq "$(stat -c %s "${overlay}")" "${FIRECRACKER_OVERLAY_BYTES}" \
        "Firecracker default writable-layer size"

    set_network_policy "${SANDBOX_ID}" allow-http \
        --peer-address "${GATEWAY_IP}" \
        --peer-port "${HTTP_PORT}"
    sleep 6
    crash_and_restart_sandboxd
    wait_for_state "${SANDBOX_ID}" "SANDBOX_STATE_RUNNING"
    got="$(sbox_cmd exec "${SANDBOX_ID}" /bin/cat /var/firecracker-write)"
    assert_eq "${got}" "firecracker-write-ok" "Firecracker exec after sandboxd restart"
    got="$(sbox_cmd exec "${SANDBOX_ID}" /bin/wget -qO- \
        "http://${GATEWAY_IP}:${HTTP_PORT}/health.txt")"
    assert_eq "${got}" "sandboxd-network-ok" \
        "Firecracker active ACL after sandboxd restart"
    set_network_policy "${SANDBOX_ID}" deny-all
    if sbox_cmd exec "${SANDBOX_ID}" /bin/timeout 2 /bin/wget -qO- \
        "http://${GATEWAY_IP}:${HTTP_PORT}/health.txt" \
        >/tmp/firecracker-acl-restored-deny.log 2>&1; then
        cat /tmp/firecracker-acl-restored-deny.log >&2
        fail "Firecracker recovered ACL accepted a denied flow"
    fi

    local deleted_id="${SANDBOX_ID}"
    sbox_cmd delete "${deleted_id}"
    SANDBOX_ID=""
    [ ! -e "${FILESTORE}/.firecracker/${deleted_id}" ] || \
        fail "Firecracker writable layer leaked after delete"
    [ ! -e "${SANDBOXD_ROOT}/containers/${deleted_id}/firecracker" ] || \
        fail "Firecracker runtime artifacts leaked after delete"
    sbox_cmd delete "${deleted_id}"
    if ip -o link show "${cached_tap}" | grep -q '<[^>]*UP'; then
        fail "recycled Firecracker TAP ${cached_tap} remained administratively up"
    fi

    log "testing Firecracker rejects directory rootfs and mounts"
    local rejected_id
    if rejected_id="$(sbox_cmd start \
        --quiet \
        --runtime firecracker \
        --sandbox-id sbox-e2e-firecracker-directory-root \
        --rootfs "${ROOTFS}" \
        --cpu-millicores 100 \
        --memory-mb 256 \
        /bin/true 2>/tmp/firecracker-directory-root.log)"; then
        sbox_cmd delete "${rejected_id}" || true
        fail "Firecracker accepted a directory rootfs"
    fi
    if rejected_id="$(sbox_cmd start \
        --quiet \
        --runtime firecracker \
        --sandbox-id sbox-e2e-firecracker-directory-mount \
        --rootfs "${EROFS_ROOTFS}" \
        --mount "${EROFS_MOUNT_ROOT}:/mnt/dir:bind:ro" \
        --cpu-millicores 100 \
        --memory-mb 256 \
        /bin/true 2>/tmp/firecracker-directory-mount.log)"; then
        sbox_cmd delete "${rejected_id}" || true
        fail "Firecracker accepted a directory mount"
    fi

    local cached_taps_before
    cached_taps_before="$(list_cached_taps)"
    log "testing Firecracker read-only EROFS root"
    SANDBOX_ID="$(sbox_cmd start \
        --quiet \
        --runtime firecracker \
        --sandbox-id sbox-e2e-firecracker-readonly \
        --rootfs "${EROFS_ROOTFS}" \
        --rootfs-readonly \
        --mount "${EROFS_MOUNT_IMAGE}:/mnt/erofs-readonly:erofs:ro" \
        --cpu-millicores 100 \
        --memory-mb 256 \
        /bin/sleep 300)"
    wait_for_state "${SANDBOX_ID}" "SANDBOX_STATE_RUNNING"
    local reused_tap
    reused_tap="$(wait_for_leased_tap)"
    local cached_taps_after
    cached_taps_after="$(list_cached_taps)"
    assert_eq "${cached_taps_after}" "${cached_taps_before}" \
        "Firecracker TAP cache did not allocate a new interface"
    if ! printf '%s\n' "${cached_taps_before}" | grep -Fxq "${reused_tap}"; then
        fail "Firecracker leased uncached TAP ${reused_tap}"
    fi
    if ! ip -o link show "${reused_tap}" | grep -q '<[^>]*UP'; then
        fail "reused Firecracker TAP ${reused_tap} is not administratively up"
    fi
    wait_for_exec_output "${SANDBOX_ID}" "firecracker-readonly-ready" \
        /bin/echo firecracker-readonly-ready
    if sbox_cmd exec "${SANDBOX_ID}" /bin/sh -c \
        'echo unexpected > /var/read-only-check' >/tmp/firecracker-readonly.log 2>&1; then
        cat /tmp/firecracker-readonly.log >&2
        fail "Firecracker read-only root accepted a write"
    fi
    got="$(sbox_cmd exec "${SANDBOX_ID}" /bin/sh -c \
        'echo tmpfs-ok > /tmp/read-only-check && cat /tmp/read-only-check')"
    assert_eq "${got}" "tmpfs-ok" "Firecracker read-only root runtime tmpfs"
    got="$(sbox_cmd exec "${SANDBOX_ID}" /bin/cat /mnt/erofs-readonly/input.txt)"
    assert_eq "${got}" "erofs-mount-ok" "Firecracker read-only EROFS mount"
    got="$(sbox_cmd exec "${SANDBOX_ID}" /bin/wget -qO- \
        "http://${GATEWAY_IP}:${HTTP_PORT}/health.txt")"
    assert_eq "${got}" "sandboxd-network-ok" \
        "Firecracker recycled TAP has no stale ACL"
    local readonly_root_id="${SANDBOX_ID}"
    sbox_cmd delete "${SANDBOX_ID}"
    SANDBOX_ID=""
    [ ! -e "${FILESTORE}/.firecracker/${readonly_root_id}" ] || \
        fail "Firecracker read-only writable layer leaked after delete"

    log "testing Firecracker natural exit while sandboxd is unavailable"
    SANDBOX_ID="$(sbox_cmd start \
        --quiet \
        --runtime firecracker \
        --sandbox-id sbox-e2e-firecracker-exit \
        --rootfs "${EROFS_ROOTFS}" \
        --cpu-millicores 100 \
        --memory-mb 256 \
        /bin/sh -c 'sleep 2; exit 23')"
    wait_for_state "${SANDBOX_ID}" "SANDBOX_STATE_RUNNING"
    local exit_cgroup
    exit_cgroup="$(wait_for_cgroup_child)"
    local exit_vmm_pid
    exit_vmm_pid="$(head -1 "${exit_cgroup}/cgroup.procs")"
    [ -n "${exit_vmm_pid}" ] || fail "Firecracker VMM PID is missing"
    crash_sandboxd
    sleep 3
    start_sandboxd
    wait_for_state "${SANDBOX_ID}" "SANDBOX_STATE_EXITED" 300
    wait_for_exit_code_log "${SANDBOX_ID}" 23
    wait_for_process_exit "${exit_vmm_pid}" "exited Firecracker VMM"
    if sbox_cmd exec "${SANDBOX_ID}" /bin/true >/tmp/firecracker-exited-exec.log 2>&1; then
        cat /tmp/firecracker-exited-exec.log >&2
        fail "Firecracker accepted exec after the sandbox process exited"
    fi
    sbox_cmd delete "${SANDBOX_ID}"
    SANDBOX_ID=""

    run_dnat_check firecracker "Firecracker" "${EROFS_ROOTFS}" 256

    run_storage_quota_check firecracker "${EROFS_ROOTFS}"
    run_stress_checks firecracker "${EROFS_ROOTFS}"
}

run_runsc_checks() {
    log "starting sandbox"
    SANDBOX_ID="$(sbox_cmd start \
        --quiet \
        --runtime runsc \
        --sandbox-id sbox-e2e-runtime \
        --rootfs "${ROOTFS}" \
        --cwd / \
        --env E2E_MARKER=start-env-ok \
        --mount "${HOST_MOUNT}:/mnt/host" \
        --cpu-millicores 100 \
        --memory-mb 128 \
        /bin/sh -c 'echo "$E2E_MARKER" > /tmp/start-env && sleep 300')"
    [ -n "${SANDBOX_ID}" ] || fail "start returned empty sandbox id"
    log "sandbox started: ${SANDBOX_ID}"
    local cache_cgroup
    cache_cgroup="$(wait_for_cgroup_child)"
    assert_cgroup_limits "${cache_cgroup}" 100 128

    local list_line
    list_line="$(sbox_cmd list | grep "${SANDBOX_ID}")" || fail "sandbox not found in list"
    echo "${list_line}" | grep -q "SANDBOX_STATE_RUNNING" || fail "sandbox is not running: ${list_line}"

    local got
    wait_for_exec_output "${SANDBOX_ID}" "start-env-ok" /bin/cat /tmp/start-env

    got="$(sbox_cmd exec "${SANDBOX_ID}" /bin/sh -c 'echo writable-ok > /tmp/e2e-write && cat /tmp/e2e-write')"
    assert_eq "${got}" "writable-ok" "writable overlay"
    grep -F -- "--overlay2=root:dir=${FILESTORE},size=64M" "${LOG_FILE}" >/dev/null || \
        fail "runsc did not use the configured file-backed root overlay"

    got="$(sbox_cmd exec "${SANDBOX_ID}" /bin/cat /mnt/host/input.txt)"
    assert_eq "${got}" "host-mount-ok" "host bind mount read"

    sbox_cmd exec "${SANDBOX_ID}" /bin/sh -c 'echo from-sandbox > /mnt/host/from-sandbox.txt'
    got="$(cat "${HOST_MOUNT}/from-sandbox.txt")"
    assert_eq "${got}" "from-sandbox" "host bind mount write"

    got="$(sbox_cmd exec "${SANDBOX_ID}" /bin/wget -qO- "http://${GATEWAY_IP}:${HTTP_PORT}/health.txt")"
    assert_eq "${got}" "sandboxd-network-ok" "sandbox network"
    run_network_acl_checks "runsc" runsc

    sbox_cmd stats "${SANDBOX_ID}" | grep -q "Memory Usage" || fail "stats output missing memory usage"

    log "deleting sandbox"
    sbox_cmd delete "${SANDBOX_ID}"
    local deleted_id="${SANDBOX_ID}"
    SANDBOX_ID=""
    if sbox_cmd inspect "${deleted_id}" >/tmp/sbox-inspect-after-delete.log 2>&1; then
        cat /tmp/sbox-inspect-after-delete.log >&2
        fail "sandbox still inspectable after delete"
    fi

    run_dnat_check runsc "runsc" "${ROOTFS}" 128
    run_storage_quota_check

    log "starting immediate OOM sandbox"
    SANDBOX_ID="$(sbox_cmd start \
        --quiet \
        --runtime runsc \
        --sandbox-id sbox-e2e-oom \
        --rootfs "${ROOTFS}" \
        --cpu-millicores 1000 \
        --memory-mb 128 \
        /bin/oom-hog)"
    wait_for_state "${SANDBOX_ID}" "SANDBOX_STATE_EXITED" 600
    assert_wait_log "${SANDBOX_ID}" true
    if [ "${CGROUP_MODE}" = "v2" ]; then
        local oom_kills
        oom_kills="$(awk '$1 == "oom_kill" { print $2 }' "${cache_cgroup}/memory.events")"
        [ "${oom_kills:-0}" -gt 0 ] || fail "v2 memory.events did not record oom_kill"
    fi
    sbox_cmd delete "${SANDBOX_ID}"
    SANDBOX_ID=""

    log "reusing OOM cgroup with different limits"
    SANDBOX_ID="$(sbox_cmd start \
        --quiet \
        --runtime runsc \
        --sandbox-id sbox-e2e-reuse \
        --rootfs "${ROOTFS}" \
        --cpu-millicores 1500 \
        --memory-mb 256 \
        /bin/sleep 300)"
    local reused_cgroup
    reused_cgroup="$(wait_for_cgroup_child)"
    assert_eq "${reused_cgroup}" "${cache_cgroup}" "cached cgroup path"
    assert_cgroup_limits "${reused_cgroup}" 1500 256
    if [ "${CPU_LIMIT_MODE}" = "quota" ]; then
        got="$(sbox_cmd exec "${SANDBOX_ID}" /bin/nproc)"
        assert_eq "${got}" "2" "runsc guest CPU count"
    fi
    sbox_cmd exec "${SANDBOX_ID}" /bin/kill -TERM 1
    wait_for_state "${SANDBOX_ID}" "SANDBOX_STATE_EXITED"
    assert_wait_log "${SANDBOX_ID}" false
    sbox_cmd delete "${SANDBOX_ID}"
    SANDBOX_ID=""

    log "testing crash recovery and OOM watcher reattachment"
    rm -f "${HOST_MOUNT}/oom-trigger"
    SANDBOX_ID="$(sbox_cmd start \
        --quiet \
        --runtime runsc \
        --sandbox-id sbox-e2e-recovery \
        --rootfs "${ROOTFS}" \
        --mount "${HOST_MOUNT}:/mnt/host" \
        --cpu-millicores 1000 \
        --memory-mb 128 \
        /bin/oom-hog --wait-file /mnt/host/oom-trigger)"
    wait_for_state "${SANDBOX_ID}" "SANDBOX_STATE_RUNNING"
    sleep 6
    crash_and_restart_sandboxd
    wait_for_state "${SANDBOX_ID}" "SANDBOX_STATE_RUNNING"
    sbox_cmd stats "${SANDBOX_ID}" | grep -q "Memory Limit" || fail "recovered stats failed"
    echo "trigger" > "${HOST_MOUNT}/oom-trigger"
    wait_for_state "${SANDBOX_ID}" "SANDBOX_STATE_EXITED" 600
    assert_wait_log "${SANDBOX_ID}" true
    sbox_cmd delete "${SANDBOX_ID}"
    SANDBOX_ID=""

    run_stress_checks
}

run_cgroup_disabled_checks() {
    log "starting sandbox without cgroup management"
    SANDBOX_ID="$(sbox_cmd start \
        --quiet \
        --runtime runsc \
        --sandbox-id sbox-e2e-no-cgroup \
        --rootfs "${ROOTFS}" \
        --cwd / \
        --env E2E_MARKER=no-cgroup-ok \
        --mount "${HOST_MOUNT}:/mnt/host" \
        --cpu-millicores 100 \
        --memory-mb 128 \
        /bin/sh -c 'echo "$E2E_MARKER" > /tmp/start-env && sleep 300')"
    [ -n "${SANDBOX_ID}" ] || fail "start returned empty sandbox id"

    local list_line
    list_line="$(sbox_cmd list | grep "${SANDBOX_ID}")" || fail "sandbox not found in list"
    echo "${list_line}" | grep -q "SANDBOX_STATE_RUNNING" || fail "sandbox is not running: ${list_line}"

    local got
    wait_for_exec_output "${SANDBOX_ID}" "no-cgroup-ok" /bin/cat /tmp/start-env
    got="$(sbox_cmd exec "${SANDBOX_ID}" /bin/cat /mnt/host/input.txt)"
    assert_eq "${got}" "host-mount-ok" "host bind mount read"

    sbox_cmd delete "${SANDBOX_ID}"
    SANDBOX_ID=""

    run_storage_quota_check
}

run_e2e() {
    preflight
    cleanup_cgroups
    write_config
    prepare_rootfs
    start_sandboxd
    start_gateway_httpd
    if [ "${DISABLE_CGROUP}" = "1" ]; then
        run_cgroup_disabled_checks
    else
        case "${E2E_RUNTIME}" in
            all)
                run_runsc_checks
                run_runc_checks
                ;;
            runsc) run_runsc_checks ;;
            runc) run_runc_checks ;;
            kata) run_kata_checks ;;
            firecracker) run_firecracker_checks ;;
        esac
        if [ "${NETWORK_SOAK}" = "1" ]; then
            run_network_soak "${E2E_RUNTIME}"
        fi
    fi
    log "e2e passed"
}

serve_sandboxd() {
    preflight
    cleanup_cgroups
    write_config
    mkdir -p "$(dirname "${LOG_FILE}")"
    log "starting sandboxd in manual debug mode"
    exec /usr/local/bin/sandboxd \
        --root "${SANDBOXD_HOME}" \
        --config "${CONFIG_FILE}" \
        --socket "${SOCKET}" \
        --log-level debug \
        --log-file "${LOG_FILE}" \
        --http-address "0.0.0.0:23001"
}

case "${1:-e2e}" in
    e2e)
        run_e2e
        ;;
    serve)
        serve_sandboxd
        ;;
    *)
        fail "unknown mode $1; expected e2e or serve"
        ;;
esac
