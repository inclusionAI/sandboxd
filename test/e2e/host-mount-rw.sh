#!/usr/bin/env bash
# Copyright (c) 2026 Ant Group Corporation.
# Licensed under the Apache License, Version 2.0.

# Run inside a configured node with sbox and checkpoint-restore on PATH.
# The caller owns TEST_DIR and ROOTFS; preserve results for inspection.
set -Eeuo pipefail

: "${TEST_DIR:?set TEST_DIR to a new absolute directory visible to sandboxd}"
: "${ROOTFS:?set ROOTFS to an EROFS image or directory root}"
SOCKET="${SOCKET:-/run/sandboxd/sandboxd.sock}"
RUNTIME="${RUNTIME:-firecracker}"
case "${RUNTIME}" in
    runsc|firecracker|firecracker-pvm) ;;
    *) echo "unsupported runtime: ${RUNTIME}" >&2; exit 1 ;;
esac
CASE_ID="${CASE_ID:-${RUNTIME}-rw}"
SOURCE_ID="sbox-${CASE_ID}-source"
TARGET_ID="sbox-${CASE_ID}-restored"
mkdir "${TEST_DIR}"
mkdir "${TEST_DIR}/rw" "${TEST_DIR}/ro"
printf 'read-only\n' > "${TEST_DIR}/ro/input"
printf 'first\nsecond\n' > "${TEST_DIR}/rw/read-input"

sbox_cmd() { sbox --address "${SOCKET}" --timeout 60s "$@"; }
helper() { checkpoint-restore --socket "${SOCKET}" "$@"; }
guest() { sbox_cmd exec "${TARGET_ID}" /bin/sh -c "$1"; }
cleanup() {
    local status=$?
    trap - EXIT
    sbox_cmd delete "${SOURCE_ID}" || status=1
    if [ "${KEEP_RUNNING:-0}" != 1 ] || [ "${status}" != 0 ]; then
        sbox_cmd delete "${TARGET_ID}" || status=1
    fi
    exit "${status}"
}
trap cleanup EXIT
trap 'echo "ERROR: ${CASE_ID} failed at line ${LINENO}" >&2' ERR

workload='set -eu
echo started >> /app/logs/starts
exec 3>> /app/logs/active.log
echo before-checkpoint >&3
mv /app/logs/active.log /app/logs/rotated.log
: > /app/logs/active.log
exec 4< /app/logs/read-input
IFS= read -r first <&4
marker=memory-preserved
echo ready > /var/rw-ready
while [ ! -f /app/logs/proceed ]; do sleep 0.1; done
IFS= read -r second <&4
printf "%s|%s|%s\n" "$marker" "$first" "$second" >&3
echo resumed > /var/rw-resumed
while :; do sleep 1; done'

helper --action start --runtime "${RUNTIME}" --rootfs "${ROOTFS}" \
    --sandbox-id "${SOURCE_ID}" --request-file "${TEST_DIR}/request.json" \
    --memory-mb 256 --cpu 1000 --storage-mb 64 \
    --mount "${TEST_DIR}/rw:/app/logs:bind:rbind,rw" \
    --mount "${TEST_DIR}/ro:/readonly:bind:rbind,ro" \
    --workload-cmd "${workload}"
sbox_cmd exec "${SOURCE_ID}" /bin/sh -c \
    'set -eu; i=0; until test -f /var/rw-ready; do i=$((i+1)); test "$i" -lt 100; sleep 0.1; done'

# Host sees guest writes before checkpoint, including rotation of an open FD.
test "$(cat "${TEST_DIR}/rw/rotated.log")" = before-checkpoint
helper --action checkpoint --sandbox-id "${SOURCE_ID}" \
    --checkpoint-dir "${TEST_DIR}/checkpoint" --leave-running=false
sbox_cmd delete "${SOURCE_ID}"
test -f "${TEST_DIR}/rw/rotated.log"
printf 'host-after-checkpoint\n' >> "${TEST_DIR}/rw/rotated.log"
printf 'host-to-guest\n' > "${TEST_DIR}/rw/host-input"

helper --action restore --target-id "${TARGET_ID}" \
    --request-file "${TEST_DIR}/request.json" --checkpoint-dir "${TEST_DIR}/checkpoint"
printf 'go\n' > "${TEST_DIR}/rw/proceed"
guest 'set -eu; i=0; until test -f /var/rw-resumed; do i=$((i+1)); test "$i" -lt 100; sleep 0.1; done'
test "$(cat "${TEST_DIR}/rw/rotated.log")" = "$(printf 'before-checkpoint\nhost-after-checkpoint\nmemory-preserved|first|second')"
test "$(wc -l < "${TEST_DIR}/rw/starts")" -eq 1
test ! -s "${TEST_DIR}/rw/active.log"
test "$(guest 'cat /app/logs/host-input')" = host-to-guest

guest 'set -eu
mkdir /app/logs/dir
echo created > /app/logs/dir/file
echo appended >> /app/logs/dir/file
chmod 0640 /app/logs/dir/file
mv /app/logs/dir/file /app/logs/dir/renamed
cp /app/logs/dir/renamed /app/logs/deleted
rm /app/logs/deleted
sync'
test "$(cat "${TEST_DIR}/rw/dir/renamed")" = "$(printf 'created\nappended')"
test "$(stat -c %a "${TEST_DIR}/rw/dir/renamed")" = 640
test ! -e "${TEST_DIR}/rw/deleted"
if guest 'echo forbidden > /readonly/new-file'; then
    echo 'ERROR: read-only mount accepted a write' >&2
    exit 1
fi
test ! -e "${TEST_DIR}/ro/new-file"
test "$(cat "${TEST_DIR}/ro/input")" = read-only
guest 'grep " /app/logs " /proc/mounts; grep " /readonly " /proc/mounts'

if [ "${KEEP_RUNNING:-0}" != 1 ]; then
    sbox_cmd delete "${TARGET_ID}"
    test -f "${TEST_DIR}/rw/rotated.log"
fi
printf 'PASS: %s RW, RO protection, rotation, local C/R, append FD, read offset, memory and caller-owned directory\n' "${CASE_ID}"
