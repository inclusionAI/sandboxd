#!/usr/bin/env bash
# Copyright (c) 2026 Ant Group Corporation.
# Licensed under the Apache License, Version 2.0.

# Run against a test-owned daemon. The outer runner owns daemon/FUSE lifetimes
# and prepares the immutable root. Missing prerequisites are errors, not skips.
set -Eeuo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/writable-hosts-common.sh"
: "${CASE_MODE:?set CASE_MODE to nydus or relative-bind}"
: "${TEST_DIR:?set TEST_DIR to a new absolute evidence directory}"
: "${ROOTFS:?set ROOTFS to an absolute directory root}"
: "${SANDBOXD_ROOT:?set SANDBOXD_ROOT to the test daemon runtime root}"
: "${SANDBOXD_PID:?set SANDBOXD_PID to the test-owned daemon PID}"
SOCKET="${SOCKET:-/run/sandboxd/sandboxd.sock}"
CASE_ID="${CASE_ID:-hosts-${CASE_MODE}}"
EXPECTED_HOSTNAME="${EXPECTED_HOSTNAME:-akernel}"
[[ "${CASE_ID}" =~ ^[a-zA-Z0-9_-]+$ ]] || { echo 'invalid CASE_ID' >&2; exit 1; }
[[ "${TEST_DIR}" = /* && "${ROOTFS}" = /* && "${SANDBOXD_ROOT}" = /* ]] || { echo 'absolute fixture paths required' >&2; exit 1; }
[[ "${SANDBOXD_PID}" =~ ^[1-9][0-9]*$ ]] || { echo 'invalid daemon PID' >&2; exit 1; }
case "${CASE_MODE}" in nydus|relative-bind) ;; *) echo 'invalid CASE_MODE' >&2; exit 1 ;; esac
for command in sbox checkpoint-restore python3 jq sha256sum findmnt; do
    command -v "${command}" >/dev/null || { echo "missing command: ${command}" >&2; exit 1; }
done
test -d "${ROOTFS}"
test -r "/proc/${SANDBOXD_PID}/cmdline"
mkdir "${TEST_DIR}"
ids=()
proof_dirs=()
sbox_cmd() { sbox --address "${SOCKET}" --timeout 60s "$@"; }
helper() { checkpoint-restore --socket "${SOCKET}" "$@"; }
guest() { local id=$1; shift; sbox_cmd exec "${id}" /bin/sh -ec "$*"; }
pass() { printf 'PASS: %s %s\n' "${CASE_ID}" "$*"; }
fail() { printf 'FAIL: %s %s\n' "${CASE_ID}" "$*" >&2; exit 1; }
cleanup() {
    local status=$? id directory
    trap - EXIT
    for id in "${ids[@]}"; do
        sbox_cmd delete "${id}" >"${TEST_DIR}/${id}.cleanup.log" 2>&1 || status=1
    done
    for directory in "${proof_dirs[@]}"; do
        rm -f "${directory}/marker"
        rmdir "${directory}" || status=1
    done
    exit "${status}"
}
trap cleanup EXIT
trap 'echo "ERROR: ${CASE_ID} failed at line ${LINENO}" >&2' ERR

if [ "${CASE_MODE}" = nydus ]; then
    : "${DISTILL_FS_PID:?set DISTILL_FS_PID to the test-owned Nydus FUSE daemon}"
    : "${NYDUS_BOOTSTRAP:?set NYDUS_BOOTSTRAP to the mounted RAFS v5 bootstrap}"
    # Check the actual process and mount, not just a synthetic errno hook or a
    # normal directory with an empty xattr list. A no-xattr Nydus mount causes
    # Linux FUSE to translate ENOSYS into EOPNOTSUPP for flistxattr.
    python3 - "${ROOTFS}" "${DISTILL_FS_PID}" "${NYDUS_BOOTSTRAP}" <<'PY' | tee "${TEST_DIR}/nydus-prerequisites.json"
import errno
import hashlib
import json
import os
import pathlib
import subprocess
import struct
import sys

root, pid, bootstrap = sys.argv[1:]
assert pid.isdecimal() and int(pid) > 0, "invalid distill-fs PID"
args = pathlib.Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
args = [os.fsdecode(arg) for arg in args if arg]

def option(name):
    matches = [args[i + 1] for i, arg in enumerate(args[:-1]) if arg == name]
    assert len(matches) == 1, f"expected exactly one {name}: {args!r}"
    return matches[0]

assert option("--src") == "nydus", "fixture is not a Nydus mount"
assert os.path.realpath(option("--mountpoint")) == os.path.realpath(root)
assert os.path.realpath(option("--bootstrap")) == os.path.realpath(bootstrap)
fstype = subprocess.check_output(["findmnt", "-n", "-o", "FSTYPE", "--target", root], text=True).strip()
assert fstype == "fuse" or fstype.startswith("fuse."), f"expected FUSE, got {fstype!r}"
bootstrap_bytes = pathlib.Path(bootstrap).read_bytes()
magic, version, size, block_size, flags = struct.unpack("<IIIIQ", bootstrap_bytes[:24])
assert magic == 0x52414653 and version == 0x500, "fixture must be RAFS v5"
assert flags & 0x20 == 0, "Nydus fixture unexpectedly advertises HAS_XATTR"
result = {"fstype": fstype, "rafs_version": version, "rafs_flags": flags, "bootstrap_sha256": hashlib.sha256(bootstrap_bytes).hexdigest(), "flistxattr": {}}
for path in (root, os.path.join(root, "etc")):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            attrs = os.listxattr(fd)
        except OSError as error:
            assert error.errno in (errno.EOPNOTSUPP, errno.ENOTSUP, errno.ENOSYS), (path, error)
            result["flistxattr"][path] = {"errno": error.errno, "name": errno.errorcode[error.errno]}
        else:
            raise AssertionError(f"fixture must expose unsupported xattrs, got {attrs!r} for {path}")
    finally:
        os.close(fd)
print(json.dumps(result, indent=2, sort_keys=True))
PY
    pass 'actual Nydus FUSE root and /etc expose unsupported xattrs'
else
    : "${BASIC_SPEC:?set BASIC_SPEC to the configured OCI base spec}"
    jq -e '[.mounts[] | select(.destination == "/relative-proof" and .type == "bind" and .source == "../hosts-relative-shared")] | length == 1' "${BASIC_SPEC}" >/dev/null
    DAEMON_CWD="$(readlink -f "/proc/${SANDBOXD_PID}/cwd")"
    CORRECT_SOURCE="${SANDBOXD_ROOT}/containers/hosts-relative-shared"
    WRONG_SOURCE="$(realpath -m "${DAEMON_CWD}/../hosts-relative-shared")"
    test "$(realpath -m "${CORRECT_SOURCE}")" != "${WRONG_SOURCE}" || fail 'fixture does not distinguish bundle and daemon CWD'
    # Both paths must exist during Start: a CWD regression then mounts the
    # wrong existing directory instead of merely failing with ENOENT.
    for directory in "${CORRECT_SOURCE}" "${WRONG_SOURCE}"; do
        mkdir "${directory}"
        proof_dirs+=("${directory}")
    done
    printf 'bundle-relative\n' > "${CORRECT_SOURCE}/marker"
    printf 'wrong-daemon-cwd\n' > "${WRONG_SOURCE}/marker"
    pass 'bundle-relative and wrong CWD-relative sources both exist with distinct markers'
fi

SOURCE="sbox-${CASE_ID}-source"
RESTORED="sbox-${CASE_ID}-restored"
REQUEST="${TEST_DIR}/request.json"
CHECKPOINT="${TEST_DIR}/checkpoint"
sha256sum /etc/hosts > "${TEST_DIR}/host-hosts.before.sha256"
sha256sum "${ROOTFS}/etc/hosts" > "${TEST_DIR}/lower-hosts.before.sha256"
ids+=("${SOURCE}")
helper --action start --runtime runsc --rootfs "${ROOTFS}" --sandbox-id "${SOURCE}" \
    --request-file "${REQUEST}" --response-file "${TEST_DIR}/start-response.json" \
    --memory-mb 256 --cpu 1000 --storage-mb 64 --workload-cmd "${HOSTS_WORKLOAD}"
verify_initial_hosts "${SOURCE}" "${TEST_DIR}/start-response.json" "${TEST_DIR}/source"
if [ "${CASE_MODE}" = relative-bind ]; then
    printf 'bundle-relative\n' > "${TEST_DIR}/expected-relative-marker"
    sbox_cmd exec "${SOURCE}" /bin/cat /relative-proof/marker > "${TEST_DIR}/actual-relative-marker"
    cmp "${TEST_DIR}/expected-relative-marker" "${TEST_DIR}/actual-relative-marker"
fi
pass 'Start selects the intended lower and first process sees writable managed hosts'
guest "${SOURCE}" 'printf "192.0.2.21 checkpoint-marker\n" > /etc/hosts.new
mv /etc/hosts.new /etc/hosts'
helper --action checkpoint --sandbox-id "${SOURCE}" --checkpoint-dir "${CHECKPOINT}" \
    --leave-running=false --snapshot-type Full
jq -e '.schema_version == 1 and .hosts_layout == "managed_rootfs_v1" and .runtime == "runsc" and .root_readonly == false' \
    "${CHECKPOINT}/managed-hosts.json" >/dev/null
sha256sum "${CHECKPOINT}/managed-hosts.json" "${CHECKPOINT}/rootfs-seed.tar" > "${TEST_DIR}/checkpoint.before.sha256"
sbox_cmd delete "${SOURCE}"
test ! -e "${SANDBOXD_ROOT}/containers/${SOURCE}" || fail 'Delete leaked source bundle'
ids+=("${RESTORED}")
helper --action restore --target-id "${RESTORED}" --request-file "${REQUEST}" --checkpoint-dir "${CHECKPOINT}"
guest "${RESTORED}" 'grep -qx "192.0.2.21 checkpoint-marker" /etc/hosts
test "$(wc -l < /var/hosts-entry-count)" = 1
echo "192.0.2.22 restored-only" >> /etc/hosts'
if [ "${CASE_MODE}" = relative-bind ]; then
    sbox_cmd exec "${RESTORED}" /bin/cat /relative-proof/marker > "${TEST_DIR}/restored-relative-marker"
    cmp "${TEST_DIR}/expected-relative-marker" "${TEST_DIR}/restored-relative-marker"
    test "$(cat "${CORRECT_SOURCE}/marker")" = bundle-relative
    test "$(cat "${WRONG_SOURCE}/marker")" = wrong-daemon-cwd
fi
sha256sum -c "${TEST_DIR}/checkpoint.before.sha256"
sha256sum -c "${TEST_DIR}/host-hosts.before.sha256"
sha256sum -c "${TEST_DIR}/lower-hosts.before.sha256"
sbox_cmd delete "${RESTORED}"
test ! -e "${SANDBOXD_ROOT}/containers/${RESTORED}" || fail 'Delete leaked restored bundle'
assert_hosts_inventory_absent "${TEST_DIR}/inventory-after" "${SOURCE}" "${RESTORED}"
pass 'checkpoint/restore after source deletion preserves hosts and bind identity without replay or source mutation; cleanup complete'
