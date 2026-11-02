#!/usr/bin/env bash
# Copyright (c) 2026 Ant Group Corporation.
# Licensed under the Apache License, Version 2.0.

# This is server Start/Checkpoint/Start(CheckpointInfo) coverage, not runsc CLI.
set -Eeuo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/writable-hosts-common.sh"
: "${TEST_DIR:?set TEST_DIR to a new absolute directory visible to sandboxd}"
: "${ROOTFS:?set ROOTFS to the lower EROFS image or directory}"
: "${SANDBOXD_ROOT:?set SANDBOXD_ROOT to the sandboxd runtime root}"
SOCKET="${SOCKET:-/run/sandboxd/sandboxd.sock}"
RUNTIME="${RUNTIME:-runsc}"
CASE_ID="${CASE_ID:-${RUNTIME}-hosts}"
EXPECTED_HOSTNAME="${EXPECTED_HOSTNAME:-akernel}"
case "${RUNTIME}" in runsc) ;; *) echo "unsupported runtime: ${RUNTIME}" >&2; exit 1 ;; esac
[[ "${TEST_DIR}" = /* && "${ROOTFS}" = /* && "${SANDBOXD_ROOT}" = /* ]] || { echo 'absolute fixture paths required' >&2; exit 1; }
[[ "${CASE_ID}" =~ ^[a-zA-Z0-9_-]+$ ]] || { echo 'invalid CASE_ID' >&2; exit 1; }
mkdir "${TEST_DIR}"
ids=()
sbox_cmd() { sbox --address "${SOCKET}" --timeout 60s "$@"; }
helper() { checkpoint-restore --socket "${SOCKET}" "$@"; }
guest() { local id=$1; shift; sbox_cmd exec "${id}" /bin/sh -ec "$*"; }
cleanup() {
    local status=$? id
    trap - EXIT
    for id in "${ids[@]}"; do
        sbox_cmd delete "${id}" >"${TEST_DIR}/${id}.cleanup.log" 2>&1 || status=1
    done
    exit "${status}"
}
trap cleanup EXIT
trap 'echo "ERROR: ${CASE_ID} failed at line ${LINENO}" >&2' ERR
pass() { printf 'PASS: %s %s\n' "${CASE_ID}" "$*"; }
fail() { printf 'FAIL: %s %s\n' "${CASE_ID}" "$*" >&2; exit 1; }

SOURCE="sbox-${CASE_ID}-source"
RESTORED="sbox-${CASE_ID}-restored"
CLONE="sbox-${CASE_ID}-clone"
EMPTY="sbox-${CASE_ID}-empty"
DELETED="sbox-${CASE_ID}-deleted"
REQUEST="${TEST_DIR}/request.json"
CHECKPOINT="${TEST_DIR}/modified"
HOST_HOSTS_HASH="$(sha256sum /etc/hosts)"
if [ -d "${ROOTFS}" ]; then
    LOWER_HASH="$(sha256sum "${ROOTFS}/etc/hosts")"
else
    LOWER_HASH="$(sha256sum "${ROOTFS}")"
fi

ids+=("${SOURCE}")
helper --action start --runtime "${RUNTIME}" --rootfs "${ROOTFS}" \
    --sandbox-id "${SOURCE}" --request-file "${REQUEST}" \
    --response-file "${TEST_DIR}/source-response.json" \
    --memory-mb 256 --cpu 1000 --storage-mb 64 --workload-cmd "${HOSTS_WORKLOAD}"
verify_initial_hosts "${SOURCE}" "${TEST_DIR}/source-response.json" "${TEST_DIR}/source"
pass 'first process sees exact managed hosts, root:root/0644, ordinary rootfs file'

# Checkpoint output belongs to the caller, not to directories Delete owns.
owned_output="${SANDBOXD_ROOT}/containers/${SOURCE}/invalid-checkpoint"
if helper --action checkpoint --sandbox-id "${SOURCE}" --checkpoint-dir "${owned_output}" \
    --leave-running=true --snapshot-type Full > "${TEST_DIR}/owned-output.log" 2>&1; then
    fail 'checkpoint accepted source-owned output'
fi
grep -q 'overlap' "${TEST_DIR}/owned-output.log" || fail 'owned output failed for an unexpected reason'
test ! -e "${owned_output}" || fail 'rejected checkpoint left output behind'
guest "${SOURCE}" 'cmp /etc/hosts /var/hosts-at-entry; test "$(wc -l < /var/hosts-entry-count)" = 1'
pass 'source-owned checkpoint output rejected before capture; source remains usable'

guest "${SOURCE}" 'echo "192.0.2.10 appended" >> /etc/hosts
grep -q appended /etc/hosts
printf "192.0.2.20 overwritten\n" > /etc/hosts
sed -i s/overwritten/sed-replaced/ /etc/hosts
grep -q sed-replaced /etc/hosts
printf "192.0.2.21 renamed\n" > /etc/hosts.new
mv /etc/hosts.new /etc/hosts
grep -qx "192.0.2.21 renamed" /etc/hosts'
helper --action checkpoint --sandbox-id "${SOURCE}" --checkpoint-dir "${CHECKPOINT}" \
    --leave-running=false --snapshot-type Full
jq -e --arg runtime "${RUNTIME}" \
    '.schema_version == 1 and .hosts_layout == "managed_rootfs_v1" and .runtime == $runtime and .root_readonly == false' \
    "${CHECKPOINT}/managed-hosts.json" >/dev/null
test -f "${CHECKPOINT}/rootfs-seed.tar"
test "$(sha256sum "${CHECKPOINT}/rootfs-seed.tar" | cut -d' ' -f1)" = \
    "$(jq -er '.seed.sha256' "${CHECKPOINT}/managed-hosts.json")"
sbox_cmd delete "${SOURCE}"
# Delete must release the actual source bundle; no manual deletion can mask a leak.
test ! -e "${SANDBOXD_ROOT}/containers/${SOURCE}" || fail 'source bundle survived Delete'

restore() {
    local id=$1 snapshot=$2 request=${3:-${REQUEST}}
    ids+=("${id}")
    helper --action restore --target-id "${id}" --request-file "${request}" --checkpoint-dir "${snapshot}"
}
restore "${RESTORED}" "${CHECKPOINT}"
restore "${CLONE}" "${CHECKPOINT}"
guest "${RESTORED}" 'grep -qx "192.0.2.21 renamed" /etc/hosts; test "$(wc -l < /var/hosts-entry-count)" = 1; echo "192.0.2.22 target-only" >> /etc/hosts'
guest "${CLONE}" '! grep -q target-only /etc/hosts; echo "192.0.2.23 clone-only" >> /etc/hosts'
guest "${RESTORED}" '! grep -q clone-only /etc/hosts'
sbox_cmd delete "${CLONE}"
pass 'modified hosts survives source deletion; two restores are independent; entrypoint not replayed'

# The containing E2E runner owns the daemon PID. It alone handles the restart;
# this script never discovers or signals any system service.
if [ "${RESTART_HANDSHAKE:-0}" = 1 ]; then
    touch "${TEST_DIR}/restart.request"
    for attempt in $(seq 1 3000); do
        [ ! -f "${TEST_DIR}/restart.done" ] || break
        sleep 0.1
    done
    test -f "${TEST_DIR}/restart.done" || fail 'test-owned daemon restart timed out'
    guest "${RESTORED}" 'grep -q target-only /etc/hosts; ! grep -q clone-only /etc/hosts; test "$(wc -l < /var/hosts-entry-count)" = 1'
    pass 'restored instance recovered across test-owned sandboxd restart'
else
    printf 'NOT QUALIFIED: %s daemon recovery; outer runner must provide RESTART_HANDSHAKE=1\n' "${CASE_ID}"
fi

guest "${RESTORED}" ': > /etc/hosts'
helper --action checkpoint --sandbox-id "${RESTORED}" --checkpoint-dir "${TEST_DIR}/empty" \
    --leave-running=false --snapshot-type Full
sbox_cmd delete "${RESTORED}"
restore "${EMPTY}" "${TEST_DIR}/empty"
guest "${EMPTY}" 'test -f /etc/hosts; test ! -s /etc/hosts; rm /etc/hosts; test ! -e /etc/hosts'
helper --action checkpoint --sandbox-id "${EMPTY}" --checkpoint-dir "${TEST_DIR}/deleted" \
    --leave-running=false --snapshot-type Full
sbox_cmd delete "${EMPTY}"
restore "${DELETED}" "${TEST_DIR}/deleted"
guest "${DELETED}" 'test ! -e /etc/hosts; test "$(wc -l < /var/hosts-entry-count)" = 1'
sbox_cmd delete "${DELETED}"
pass 'empty and deleted hosts survive subsequent generations of checkpoint/restore'

negative() {
    local mode=$1 bad="${TEST_DIR}/bad-$1" id="sbox-${CASE_ID}-bad-$1"
    cp -a --reflink=auto "${CHECKPOINT}" "${bad}"
    case "${mode}" in
        json) printf '{broken' > "${bad}/managed-hosts.json" ;;
        version) jq '.schema_version = 999' "${bad}/managed-hosts.json" > "${bad}/new.json"; mv "${bad}/new.json" "${bad}/managed-hosts.json" ;;
        metadata) rm "${bad}/managed-hosts.json" ;;
        seed) rm "${bad}/rootfs-seed.tar" ;;
        digest) printf corrupt >> "${bad}/rootfs-seed.tar" ;;
        *) fail "unknown negative fixture ${mode}" ;;
    esac
    ids+=("${id}")
    if helper --action restore --target-id "${id}" --request-file "${REQUEST}" \
        --checkpoint-dir "${bad}" > "${TEST_DIR}/negative-${mode}.log" 2>&1; then
        fail "${mode} metadata corruption was accepted"
    fi
    # Reject the intended artifact/spec problem, not an unrelated launch failure.
    local expected
    case "${mode}" in
        json) expected='decode managed-hosts.json:.*invalid character' ;;
        version) expected='unsupported managed hosts schema version 999' ;;
        seed) expected='open hosts seed:.*rootfs-seed.tar: no such file or directory' ;;
        digest) expected='hosts seed SHA-256 mismatch' ;;
        metadata) expected='"(Mounts|Annotations)" does not match across checkpoint restore' ;;
    esac
    grep -Eq "${expected}" "${TEST_DIR}/negative-${mode}.log" || {
        cat "${TEST_DIR}/negative-${mode}.log" >&2
        fail "${mode} failed for an unexpected reason"
    }
    # Observe automatic rollback before any explicit Delete can repair it.
    test ! -e "${SANDBOXD_ROOT}/containers/${id}" || fail "${mode} leaked target bundle"
    assert_hosts_inventory_absent "${TEST_DIR}/negative-${mode}.inventory" "${id}"
    sbox_cmd delete "${id}"
    rm -rf "${bad}"
    pass "invalid ${mode} rejected without target bundle leak"
}
for mode in json version metadata seed digest; do negative "${mode}"; done

# A fresh effective-readonly root uses the retained legacy layout. This is
# intentionally separate from compatibility with a checkpoint made by old code.
READONLY="sbox-${CASE_ID}-readonly"
READONLY_RESTORED="sbox-${CASE_ID}-readonly-restored"
ids+=("${READONLY}")
helper --action start --runtime "${RUNTIME}" --rootfs "${ROOTFS}" --rootfs-readonly \
    --sandbox-id "${READONLY}" --request-file "${TEST_DIR}/readonly-request.json" \
    --memory-mb 256 --cpu 1000 --storage-mb 0 --workload-cmd 'exec /bin/sleep 300'
if guest "${READONLY}" 'echo forbidden >> /etc/hosts' > "${TEST_DIR}/readonly-write.log" 2>&1; then
    fail 'effective readonly root accepted hosts write'
fi
grep -qi 'read-only file system' "${TEST_DIR}/readonly-write.log"
helper --action checkpoint --sandbox-id "${READONLY}" --checkpoint-dir "${TEST_DIR}/readonly" \
    --leave-running=false --snapshot-type Full
jq -e '.hosts_layout == "legacy_readonly_mount" and .root_readonly == true' \
    "${TEST_DIR}/readonly/managed-hosts.json" >/dev/null
sbox_cmd delete "${READONLY}"
restore "${READONLY_RESTORED}" "${TEST_DIR}/readonly" "${TEST_DIR}/readonly-request.json"
if guest "${READONLY_RESTORED}" 'echo forbidden >> /etc/hosts' > "${TEST_DIR}/readonly-restore-write.log" 2>&1; then
    fail 'restored readonly layout accepted hosts write'
fi
grep -qi 'read-only file system' "${TEST_DIR}/readonly-restore-write.log"
sbox_cmd delete "${READONLY_RESTORED}"
pass 'effective readonly root retains readonly hosts across restore'

# Supply a genuine baseline-built fixture using the SAME pinned runtime. Never
# manufacture an old snapshot by stripping metadata from a new one.
if [ -n "${LEGACY_CHECKPOINT:-}" ] || [ -n "${LEGACY_REQUEST:-}" ]; then
    : "${LEGACY_CHECKPOINT:?pair with LEGACY_REQUEST}"
    : "${LEGACY_REQUEST:?pair with LEGACY_CHECKPOINT}"
    test ! -e "${LEGACY_CHECKPOINT}/managed-hosts.json"
    LEGACY="sbox-${CASE_ID}-legacy"
    restore "${LEGACY}" "${LEGACY_CHECKPOINT}" "${LEGACY_REQUEST}"
    if guest "${LEGACY}" 'echo forbidden >> /etc/hosts' > "${TEST_DIR}/legacy-write.log" 2>&1; then
        fail 'baseline checkpoint gained writable hosts'
    fi
    grep -qi 'read-only file system' "${TEST_DIR}/legacy-write.log"
    sbox_cmd delete "${LEGACY}"
    pass 'genuine baseline checkpoint retains readonly hosts'
else
    printf 'NOT QUALIFIED: %s pre-change checkpoint compatibility; supply LEGACY_CHECKPOINT and LEGACY_REQUEST\n' "${CASE_ID}"
fi
if [ -d "${ROOTFS}" ]; then
    test "${LOWER_HASH}" = "$(sha256sum "${ROOTFS}/etc/hosts")"
else
    test "${LOWER_HASH}" = "$(sha256sum "${ROOTFS}")"
fi
test "${HOST_HOSTS_HASH}" = "$(sha256sum /etc/hosts)"
pass 'lower image and node hosts unchanged; server RPC writable-hosts regression complete'
