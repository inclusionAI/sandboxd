#!/usr/bin/env bash
# Copyright (c) 2026 Ant Group Corporation.
# Licensed under the Apache License, Version 2.0.
set -Eeuo pipefail
: "${TEST_DIR:?set a new directory visible to sandboxd}"
: "${ROOTFS:?set a Firecracker rootfs with sh, cat, tr, id and sleep}"
SOCKET="${SOCKET:-/run/sandboxd/sandboxd.sock}"
PREFIX="sbox-user-handoff-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
created_ids=()
helper() { checkpoint-restore --socket "${SOCKET}" "$@"; }
cleanup() {
    local status=$?
    trap - EXIT
    for id in "${created_ids[@]}"; do
        helper --action delete --sandbox-id "${id}" >/dev/null 2>&1 || true
    done
    exit "${status}"
}
mkdir "${TEST_DIR}"
trap cleanup EXIT
mkdir "${TEST_DIR}/workspace"
chown 1000:1001 "${TEST_DIR}/workspace"
chmod 0700 "${TEST_DIR}/workspace"
workload='set -eu
test "$(id -u):$(id -g)" = 1000:1001
tr "\000" "\n" < /run/sandboxd/restore-environ > /workspace/environment-initial
for stage in one two; do
    echo ready > /workspace/ready-$stage
    cat /run/sandboxd/checkpoint > /workspace/outcome-$stage
    tr "\000" "\n" < /run/sandboxd/restore-environ > /workspace/environment-$stage
    echo "$(id -u):$(id -g)" > /workspace/identity-$stage
    echo done > /workspace/done-$stage
done
exec sleep 600'
sbox --address "${SOCKET}" --timeout 60s start --runtime firecracker \
    --sandbox-id "${PREFIX}-source" --rootfs "${ROOTFS}" --user 1000:1001 \
    --cwd / --cpu-millicores 1000 --memory-mb 256 --storage-mb 64 \
    --env CHECKPOINT_OWNER_TEST=source \
    --stdout "${TEST_DIR}/stdout" --stderr "${TEST_DIR}/stderr" \
    --mount "${TEST_DIR}/workspace:/workspace:bind:rbind,rw" /bin/sh -c "${workload}"
created_ids+=("${PREFIX}-source")
wait_file() {
    for _ in $(seq 1 200); do
        [ -f "$1" ] && return 0
        sleep .1
    done
    echo "ERROR: timed out waiting for $1" >&2
    cat "${TEST_DIR}/stderr" >&2
    return 1
}
wait_file "${TEST_DIR}/workspace/ready-one"
grep -qx CHECKPOINT_OWNER_TEST=source "${TEST_DIR}/workspace/environment-initial"
source_id="${PREFIX}-source"
for stage in one two; do
    wait_file "${TEST_DIR}/workspace/ready-${stage}"
    helper --action checkpoint --sandbox-id "${source_id}" \
        --checkpoint-dir "${TEST_DIR}/checkpoint-${stage}" --leave-running=false
    helper --action delete --sandbox-id "${source_id}"
    jq -n --arg root "${ROOTFS}" --arg dir "${TEST_DIR}" --arg workload "${workload}" --arg stage "${stage}" \
        '{runtime:"firecracker",rootfs:{type:"LOCAL",path:$root},command:["/bin/sh","-c",$workload],cwd:"/",resources:{CPU:1000,Memory:256},writableLayerLimitBytes:"67108864",stdout:($dir+"/stdout"),stderr:($dir+"/stderr"),mounts:[{type:"bind",target:"/workspace",hostPath:($dir+"/workspace"),options:["rbind","rw"]}],envs:{CHECKPOINT_OWNER_TEST:$stage}}' \
        > "${TEST_DIR}/request-${stage}.json"
    if [ "${stage}" = two ]; then
        jq '.processUser={uid:1000,gid:1001}' "${TEST_DIR}/request-${stage}.json" > "${TEST_DIR}/request-next.json"
        mv "${TEST_DIR}/request-next.json" "${TEST_DIR}/request-${stage}.json"
    fi
    source_id="${PREFIX}-${stage}"
    helper --action restore --target-id "${source_id}" \
        --request-file "${TEST_DIR}/request-${stage}.json" --checkpoint-dir "${TEST_DIR}/checkpoint-${stage}"
    created_ids+=("${source_id}")
    wait_file "${TEST_DIR}/workspace/done-${stage}"
    sbox --address "${SOCKET}" inspect "${source_id}" > "${TEST_DIR}/inspect-${stage}.json"
    if [ "${stage}" = one ]; then
        jq -e '.process_user == {}' "${TEST_DIR}/inspect-${stage}.json" >/dev/null
    else
        jq -e '.process_user == {"uid":1000,"gid":1001}' "${TEST_DIR}/inspect-${stage}.json" >/dev/null
    fi
    test "$(cat "${TEST_DIR}/workspace/identity-${stage}")" = 1000:1001
    test ! -e "${TEST_DIR}/checkpoint-${stage}/sandboxd-process-user.json"
    if [ "${stage}" = one ] && [ -n "${DAEMON_RESTART_HELPER:-}" ]; then
        "${DAEMON_RESTART_HELPER}"
        sbox --address "${SOCKET}" inspect "${source_id}" | tee "${TEST_DIR}/inspect-recovered.json" |
            jq -e '(.state // 0) == 0 and .process_user == {}' >/dev/null
    fi
    grep -qx restore "${TEST_DIR}/workspace/outcome-${stage}"
    grep -qx "CHECKPOINT_OWNER_TEST=${stage}" "${TEST_DIR}/workspace/environment-${stage}"
    test "$(stat -c %u:%g "${TEST_DIR}/workspace/environment-${stage}")" = 1000:1001
done
printf 'PASS: non-root Firecracker FIFO and restored environment reads across two checkpoint generations\n'
