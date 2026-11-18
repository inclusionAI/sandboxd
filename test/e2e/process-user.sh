#!/usr/bin/env bash
# Copyright (c) 2026 Ant Group Corporation.
# Licensed under the Apache License, Version 2.0.
# Run against an isolated daemon. The caller owns TEST_DIR and ROOTFS.
set -Eeuo pipefail
: "${TEST_DIR:?set a new directory visible to sandboxd}"
: "${ROOTFS:?set a directory or EROFS rootfs containing /bin/sh, id and sleep}"
SOCKET="${SOCKET:-/run/sandboxd/sandboxd.sock}"
RUNTIME="${RUNTIME:-runsc}"
CHECKPOINT="${CHECKPOINT:-1}"
RUN_ID=$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
PREFIX="${SANDBOXD_USER_TEST_PREFIX:-sbox-user-${RUNTIME}}-${RUN_ID}"
created_ids=()
sbox_cmd() { sbox --address "${SOCKET}" --timeout 60s "$@"; }
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
mkdir "${TEST_DIR}/rw" "${TEST_DIR}/denied"
chown 1000:1001 "${TEST_DIR}/rw"
chmod 0700 "${TEST_DIR}/rw"
chmod 0755 "${TEST_DIR}/denied"

for mode in default root; do
    args=()
    if [ "${mode}" = root ]; then args+=(--user 0:0); fi
    sbox_cmd start --runtime "${RUNTIME}" --sandbox-id "${PREFIX}-${mode}" \
        --rootfs "${ROOTFS}" --cwd / --cpu-millicores 1000 --memory-mb 256 \
        --stdout "${TEST_DIR}/${mode}.stdout" --stderr "${TEST_DIR}/${mode}.stderr" \
        "${args[@]}" /bin/sh -c 'echo "$(id -u):$(id -g)"; exec sleep 600'
    created_ids+=("${PREFIX}-${mode}")
    for _ in $(seq 1 100); do
        grep -Eq '^0:0[[:space:]]*$' "${TEST_DIR}/${mode}.stdout" && break
        sleep .1
    done
    grep -Eq '^0:0[[:space:]]*$' "${TEST_DIR}/${mode}.stdout"
    sbox_cmd inspect "${PREFIX}-${mode}" | jq -e '.process_user == {}' >/dev/null
    helper --action delete --sandbox-id "${PREFIX}-${mode}"
done

storage_args=()
if [ "${RUNTIME}" != runc ]; then storage_args+=(--storage-mb 64); fi
workload='set -eu
echo "$(id -u):$(id -g)" > /workspace/identity
id -G > /workspace/groups
if echo forbidden > /denied/new-file; then exit 99; fi
marker=memory-from-nonroot
echo started >> /workspace/starts
echo ready > /workspace/ready
while [ ! -f /workspace/proceed ]; do sleep .1; done
echo "$marker" > /workspace/resumed
exec sleep 600'
sbox_cmd start --runtime "${RUNTIME}" --sandbox-id "${PREFIX}-source" \
    --rootfs "${ROOTFS}" --cwd / --user 1000:1001 --cpu-millicores 1000 \
    --memory-mb 256 "${storage_args[@]}" \
    --stdout "${TEST_DIR}/user.stdout" --stderr "${TEST_DIR}/user.stderr" \
    --mount "${TEST_DIR}/rw:/workspace:bind:rbind,rw" \
    --mount "${TEST_DIR}/denied:/denied:bind:rbind,rw" /bin/sh -c "${workload}"
created_ids+=("${PREFIX}-source")
for _ in $(seq 1 100); do
    [ -f "${TEST_DIR}/rw/ready" ] && break
    sleep .1
done
test "$(cat "${TEST_DIR}/rw/identity")" = 1000:1001
test "$(stat -c %u:%g "${TEST_DIR}/rw/identity")" = 1000:1001
test "$(cat "${TEST_DIR}/rw/groups")" = 1001
test ! -e "${TEST_DIR}/denied/new-file"
sbox_cmd inspect "${PREFIX}-source" | tee "${TEST_DIR}/inspect.json" |
    jq -e '.process_user == {"uid":1000,"gid":1001}' >/dev/null
printf 'PASS: %s default root, explicit root, numeric UID/GID without passwd, workspace ownership, denied write\n' "${RUNTIME}"

# The helper must restart only the caller's isolated daemon, preserving its state.
if [ -n "${DAEMON_RESTART_HELPER:-}" ]; then
    "${DAEMON_RESTART_HELPER}"
    sbox_cmd inspect "${PREFIX}-source" | tee "${TEST_DIR}/inspect-recovered.json" |
        jq -e '(.state // 0) == 0 and .process_user == {"uid":1000,"gid":1001}' >/dev/null
    test "$(wc -l < "${TEST_DIR}/rw/starts")" -eq 1
    printf 'PASS: %s daemon restart retains initial identity\n' "${RUNTIME}"
fi

if [ "${CHECKPOINT}" = 1 ]; then
    jq -n --arg runtime "${RUNTIME}" --arg root "${ROOTFS}" --arg dir "${TEST_DIR}" --arg workload "${workload}" \
        '{command:["/bin/sh","-c",$workload],stdout:($dir+"/user.stdout"),stderr:($dir+"/user.stderr"),runtime:$runtime,rootfs:{type:"LOCAL",path:$root},cwd:"/",resources:{CPU:1000,Memory:256},writableLayerLimitBytes:"67108864",mounts:[{type:"bind",target:"/workspace",hostPath:($dir+"/rw"),options:["rbind","rw"]},{type:"bind",target:"/denied",hostPath:($dir+"/denied"),options:["rbind","rw"]}]}' \
        > "${TEST_DIR}/request.json"
    helper --action checkpoint --sandbox-id "${PREFIX}-source" \
        --checkpoint-dir "${TEST_DIR}/checkpoint" --leave-running=false
    helper --action delete --sandbox-id "${PREFIX}-source"
    jq -e '.user.uid == 1000 and .user.gid == 1001' \
        "${TEST_DIR}/checkpoint/sandboxd-process-user.json" >/dev/null
    jq '.processUser={uid:0,gid:0}' "${TEST_DIR}/request.json" > "${TEST_DIR}/conflict.json"
    if helper --action restore --target-id "${PREFIX}-conflict" \
        --request-file "${TEST_DIR}/conflict.json" --checkpoint-dir "${TEST_DIR}/checkpoint" \
        > "${TEST_DIR}/conflict.log" 2>&1; then
        created_ids+=("${PREFIX}-conflict")
        echo 'ERROR: restore accepted conflicting UID/GID' >&2; exit 1
    fi
    grep -q 'conflicts with checkpoint identity' "${TEST_DIR}/conflict.log"
    helper --action restore --target-id "${PREFIX}-restored" \
        --request-file "${TEST_DIR}/request.json" --checkpoint-dir "${TEST_DIR}/checkpoint"
    created_ids+=("${PREFIX}-restored")
    sbox_cmd inspect "${PREFIX}-restored" | tee "${TEST_DIR}/inspect-restored.json" |
        jq -e '.process_user == {"uid":1000,"gid":1001}' >/dev/null
    printf 'go\n' > "${TEST_DIR}/rw/proceed"
    for _ in $(seq 1 100); do
        [ -f "${TEST_DIR}/rw/resumed" ] && break
        sleep .1
    done
    test "$(cat "${TEST_DIR}/rw/resumed")" = memory-from-nonroot
    test "$(stat -c %u:%g "${TEST_DIR}/rw/resumed")" = 1000:1001
    test "$(wc -l < "${TEST_DIR}/rw/starts")" -eq 1
    printf 'PASS: %s checkpoint identity, conflicting restore rejection, non-root resumed write\n' "${RUNTIME}"
fi
helper --action delete --sandbox-id "${PREFIX}-$([ "${CHECKPOINT}" = 1 ] && echo restored || echo source)"
test -f "${TEST_DIR}/rw/identity"
test "$(stat -c %u:%g "${TEST_DIR}/rw")" = 1000:1001
printf 'PASS: %s deletion retains caller-owned files and directory ownership\n' "${RUNTIME}"
