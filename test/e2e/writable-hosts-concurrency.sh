#!/usr/bin/env bash
# Copyright (c) 2026 Ant Group Corporation.
# Licensed under the Apache License, Version 2.0.

# Run against a dedicated test daemon. Each phase releases all clients from a
# barrier; timing measures overlapping client operations, not runtime execution slots.
set -Eeuo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/writable-hosts-common.sh"
: "${TEST_DIR:?set TEST_DIR to a fresh absolute directory}"
: "${ROOTFS:?set ROOTFS to the lower EROFS image or directory}"
: "${SANDBOXD_ROOT:?set SANDBOXD_ROOT to the daemon runtime root}"
: "${FILESTORE_ROOT:?set FILESTORE_ROOT to plugin.runtime.filestore_dir}"
SOCKET="${SOCKET:-/run/sandboxd/sandboxd.sock}"
RUNTIME="${RUNTIME:-runsc}"
COUNT="${COUNT:-8}"
CASE_ID="${CASE_ID:-${RUNTIME}-hosts-concurrency}"
EXPECTED_HOSTNAME="${EXPECTED_HOSTNAME:-akernel}"
OP_TIMEOUT_SECONDS="${OP_TIMEOUT_SECONDS:-300}"
WORKER_TIMEOUT_SECONDS="${WORKER_TIMEOUT_SECONDS:-600}"
case "${RUNTIME}" in runsc) ;; *) echo "unsupported runtime: ${RUNTIME}" >&2; exit 1 ;; esac
[[ "${COUNT}" =~ ^[0-9]+$ ]] && ((COUNT >= 2 && COUNT <= 64)) || { echo 'COUNT must be 2..64' >&2; exit 1; }
[[ "${CASE_ID}" =~ ^[a-zA-Z0-9_-]{1,48}$ ]] || { echo 'invalid CASE_ID' >&2; exit 1; }
for path in "${TEST_DIR}" "${ROOTFS}" "${SANDBOXD_ROOT}" "${FILESTORE_ROOT}"; do
    [[ "${path}" = /* ]] || { echo 'absolute fixture paths required' >&2; exit 1; }
done
for seconds in "${OP_TIMEOUT_SECONDS}" "${WORKER_TIMEOUT_SECONDS}"; do
    [[ "${seconds}" =~ ^[0-9]+$ ]] && ((seconds >= 1 && seconds <= 1800)) || { echo 'timeouts must be 1..1800 seconds' >&2; exit 1; }
done
((WORKER_TIMEOUT_SECONDS > OP_TIMEOUT_SECONDS)) || { echo 'worker timeout must exceed operation timeout' >&2; exit 1; }
PREFIX="sbox-${CASE_ID}"
export TEST_DIR ROOTFS SANDBOXD_ROOT FILESTORE_ROOT SOCKET RUNTIME COUNT CASE_ID EXPECTED_HOSTNAME OP_TIMEOUT_SECONDS WORKER_TIMEOUT_SECONDS

# Fixed-width suffixes avoid runsc treating source-1 as a prefix of source-10.
sandbox_id() { printf '%s-%s-%03d' "${PREFIX}" "$1" "$2"; }
sbox_cmd() { sbox --address "${SOCKET}" --timeout "${OP_TIMEOUT_SECONDS}s" "$@"; }
helper() { checkpoint-restore --socket "${SOCKET}" --timeout "${OP_TIMEOUT_SECONDS}s" "$@"; }
guest() { local id=$1; shift; sbox_cmd exec "${id}" /bin/sh -ec "$*"; }
fail() { printf 'FAIL: %s %s\n' "${CASE_ID}" "$*" >&2; exit 1; }
pass() { printf 'PASS: %s %s\n' "${CASE_ID}" "$*"; }

# Preserve the command's status, including expected negative restores. Each
# worker owns one event file, so no shared append lock can serialize the RPCs.
timed() {
    local operation=$1 started ended status
    shift
    started="$(date +%s%N)"
    if "$@"; then status=0; else status=$?; fi
    ended="$(date +%s%N)"
    printf '%s\t%s\t%s\t%s\t%s\n' "${operation}" "${INDEX}" "${started}" "${ended}" "${status}" >> "${PHASE_DIR}/${INDEX}.events.tsv"
    return "${status}"
}

assert_absent() {
    local id=$1
    test ! -e "${SANDBOXD_ROOT}/containers/${id}" || fail "${id} leaked a bundle"
    assert_hosts_inventory_absent "${PHASE_DIR}/${INDEX}.inventory" "${id}"
}

verify_hosts() {
    local id=$1 expected=$2
    printf '%s\n' "${expected}" > "${PHASE_DIR}/${INDEX}.expected-hosts"
    sbox_cmd exec "${id}" /bin/cat /etc/hosts > "${PHASE_DIR}/${INDEX}.actual-hosts"
    cmp "${PHASE_DIR}/${INDEX}.expected-hosts" "${PHASE_DIR}/${INDEX}.actual-hosts"
    guest "${id}" 'test "$(wc -l < /var/hosts-entry-count)" = 1; ! grep -q " /etc/hosts " /proc/mounts'
}

worker() {
    local phase=$1 id restored_index
    INDEX=$2
    PHASE_DIR="${TEST_DIR}/phases/${phase}"
    touch "${PHASE_DIR}/${INDEX}.ready"
    local deadline=$((SECONDS + 60))
    until [ -f "${PHASE_DIR}/go" ]; do
        ((SECONDS < deadline)) || fail "${phase} barrier timed out"
        sleep 0.01
    done
    case "${phase}" in
        start)
            id="$(sandbox_id source "${INDEX}")"
            timed start helper --action start --runtime "${RUNTIME}" --rootfs "${ROOTFS}" \
                --sandbox-id "${id}" --request-file "${TEST_DIR}/request-${INDEX}.json" \
                --response-file "${TEST_DIR}/response-${INDEX}.json" \
                --memory-mb 256 --cpu 500 --storage-mb 64 --workload-cmd "${HOSTS_WORKLOAD}"
            verify_initial_hosts "${id}" "${TEST_DIR}/response-${INDEX}.json" "${PHASE_DIR}/${INDEX}" 300
            ;;
        write_sources)
            id="$(sandbox_id source "${INDEX}")"
            timed write guest "${id}" "printf '192.0.2.10 source-${INDEX}\\n' > /etc/hosts"
            ;;
        verify_sources)
            verify_hosts "$(sandbox_id source "${INDEX}")" "192.0.2.10 source-${INDEX}"
            ;;
        checkpoint)
            timed checkpoint helper --action checkpoint --sandbox-id "$(sandbox_id source "${INDEX}")" \
                --checkpoint-dir "${TEST_DIR}/checkpoints/${INDEX}" --leave-running=false \
                --snapshot-type Full --checkpoint-timeout-seconds "${OP_TIMEOUT_SECONDS}"
            jq -e --arg runtime "${RUNTIME}" '.schema_version == 1 and .hosts_layout == "managed_rootfs_v1" and .runtime == $runtime and .root_readonly == false' \
                "${TEST_DIR}/checkpoints/${INDEX}/managed-hosts.json" >/dev/null
            test "$(sha256sum "${TEST_DIR}/checkpoints/${INDEX}/rootfs-seed.tar" | cut -d' ' -f1)" = \
                "$(jq -er '.seed.sha256' "${TEST_DIR}/checkpoints/${INDEX}/managed-hosts.json")"
            ;;
        delete_sources)
            id="$(sandbox_id source "${INDEX}")"
            timed delete helper --action delete --sandbox-id "${id}"
            assert_absent "${id}"
            ;;
        restore_own)
            id="$(sandbox_id own "${INDEX}")"
            timed restore helper --action restore --target-id "${id}" \
                --request-file "${TEST_DIR}/request-${INDEX}.json" --checkpoint-dir "${TEST_DIR}/checkpoints/${INDEX}"
            verify_hosts "${id}" "192.0.2.10 source-${INDEX}"
            ;;
        write_own)
            timed write guest "$(sandbox_id own "${INDEX}")" "printf '192.0.2.20 own-${INDEX}\\n' > /etc/hosts"
            ;;
        verify_own)
            verify_hosts "$(sandbox_id own "${INDEX}")" "192.0.2.20 own-${INDEX}"
            ;;
        delete_own)
            id="$(sandbox_id own "${INDEX}")"
            timed delete helper --action delete --sandbox-id "${id}"
            assert_absent "${id}"
            ;;
        fanout_mixed)
            if ((INDEX <= COUNT)); then
                id="$(sandbox_id clone "${INDEX}")"
                timed restore helper --action restore --target-id "${id}" \
                    --request-file "${TEST_DIR}/request-1.json" --checkpoint-dir "${TEST_DIR}/checkpoints/1"
                verify_hosts "${id}" '192.0.2.10 source-1'
            else
                restored_index=$((INDEX - COUNT))
                id="$(sandbox_id bad "${restored_index}")"
                if timed rejected_restore helper --action restore --target-id "${id}" \
                    --request-file "${TEST_DIR}/request-1.json" --checkpoint-dir "${TEST_DIR}/bad-checkpoint" \
                    > "${PHASE_DIR}/${INDEX}.negative.log" 2>&1; then
                    fail "${id} accepted corrupt metadata"
                fi
                grep -q 'unsupported managed hosts schema version 999' "${PHASE_DIR}/${INDEX}.negative.log"
                # This check deliberately precedes any explicit Delete.
                assert_absent "${id}"
            fi
            ;;
        write_clones)
            timed write guest "$(sandbox_id clone "${INDEX}")" "printf '192.0.2.30 clone-${INDEX}\\n' >> /etc/hosts"
            ;;
        verify_clones)
            verify_hosts "$(sandbox_id clone "${INDEX}")" "$(printf '192.0.2.10 source-1\n192.0.2.30 clone-%s' "${INDEX}")"
            ;;
        delete_clones)
            id="$(sandbox_id clone "${INDEX}")"
            timed delete helper --action delete --sandbox-id "${id}"
            assert_absent "${id}"
            ;;
        *) fail "unknown worker phase ${phase}" ;;
    esac
}

if [ "${1:-}" = --worker ]; then
    worker "$2" "$3"
    exit 0
fi
[[ $# = 0 ]] || fail 'no positional arguments supported'
for command in sbox checkpoint-restore jq python3 timeout sha256sum; do command -v "${command}" >/dev/null; done
test -e "${ROOTFS}"
test -d "${FILESTORE_ROOT}"
mkdir "${TEST_DIR}"
mkdir "${TEST_DIR}/phases" "${TEST_DIR}/checkpoints"
SCRIPT_PATH="$(cd -- "$(dirname -- "$0")" && pwd)/$(basename -- "$0")"
worker_pids=()
ids=()
for kind in source own clone bad; do
    for ((index = 1; index <= COUNT; index++)); do ids+=("$(sandbox_id "${kind}" "${index}")"); done
done
cleanup() {
    local status=$? pid id deadline
    trap - EXIT INT TERM
    # timeout runs each worker in its own process group and forwards TERM to
    # its descendants, including an RPC client still waiting on the daemon.
    for pid in "${worker_pids[@]}"; do kill -TERM "${pid}" 2>/dev/null || true; done
    for pid in "${worker_pids[@]}"; do wait "${pid}" 2>/dev/null || true; done
    deadline=$((SECONDS + 60))
    for id in "${ids[@]}"; do
        if ((SECONDS >= deadline)); then
            echo 'cleanup deadline exceeded; inspect this test daemon before reuse' >&2
            status=1
            break
        fi
        timeout --signal=TERM --kill-after=2s 12s checkpoint-restore --socket "${SOCKET}" --timeout 10s \
            --action delete --sandbox-id "${id}" > "${TEST_DIR}/${id}.cleanup.log" 2>&1 || status=1
    done
    exit "${status}"
}
sbox_cmd list > "${TEST_DIR}/inventory-before"
if awk 'NR > 1 {print $1}' "${TEST_DIR}/inventory-before" | grep -q "^${PREFIX}-"; then
    fail 'case ID is already present in inventory'
fi
HOST_HOSTS_HASH="$(sha256sum /etc/hosts)"
LOWER_FILE="${ROOTFS}"
[ ! -d "${ROOTFS}" ] || LOWER_FILE="${ROOTFS}/etc/hosts"
LOWER_HASH="$(sha256sum "${LOWER_FILE}")"
find "${FILESTORE_ROOT}" -mindepth 1 -print | LC_ALL=C sort > "${TEST_DIR}/filestore-before"
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'echo "ERROR: ${CASE_ID} failed at line ${LINENO}" >&2' ERR

run_phase() {
    local phase=$1 size=${2:-${COUNT}} index pid status=0 deadline ready
    local directory="${TEST_DIR}/phases/${phase}"
    mkdir "${directory}"
    worker_pids=()
    for ((index = 1; index <= size; index++)); do
        timeout --signal=TERM --kill-after=10s "${WORKER_TIMEOUT_SECONDS}s" bash "${SCRIPT_PATH}" --worker "${phase}" "${index}" \
            > "${directory}/${index}.log" 2>&1 &
        worker_pids+=("$!")
    done
    deadline=$((SECONDS + 60))
    while :; do
        ready=("${directory}"/*.ready)
        ((${#ready[@]} == size)) && [ -e "${ready[0]}" ] && break
        ((SECONDS < deadline)) || fail "${phase}: not all workers reached the barrier"
        sleep 0.01
    done
    touch "${directory}/go"
    for pid in "${worker_pids[@]}"; do wait "${pid}" || status=1; done
    worker_pids=()
    if ((status != 0)); then
        tail -n 40 "${directory}"/*.log >&2
        fail "${phase}: one or more workers failed"
    fi
    pass "${phase}: ${size} synchronized workers completed"
}

snapshot_manifest() {
    python3 - "${TEST_DIR}/checkpoints" <<'PY'
import hashlib
import json
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
for path in sorted(root.rglob('*')):
    if path.is_symlink():
        print(json.dumps([str(path.relative_to(root)), 'symlink', str(path.readlink())]))
    elif path.is_file():
        digest = hashlib.sha256()
        with path.open('rb') as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(block)
        print(json.dumps([str(path.relative_to(root)), path.stat().st_size, digest.hexdigest()]))
PY
}

record_live_count() {
    local phase=$1
    sbox_cmd list > "${TEST_DIR}/inventory-${phase}"
    local actual
    actual="$(awk 'NR > 1 {print $1}' "${TEST_DIR}/inventory-${phase}" | awk -v prefix="${PREFIX}-" 'index($0, prefix) == 1 {n++} END {print n+0}')"
    test "${actual}" = "${COUNT}" || fail "${phase}: expected ${COUNT} live sandbox records, got ${actual}"
    printf '%s\t%s\n' "${phase}" "${actual}" >> "${TEST_DIR}/live-counts.tsv"
}

run_phase start
record_live_count start
run_phase write_sources
run_phase verify_sources
run_phase checkpoint
snapshot_manifest > "${TEST_DIR}/checkpoints-before.jsonl"
run_phase delete_sources
run_phase restore_own
record_live_count restore_own
run_phase write_own
run_phase verify_own
run_phase delete_own
cp -a --reflink=auto "${TEST_DIR}/checkpoints/1" "${TEST_DIR}/bad-checkpoint"
jq '.schema_version = 999' "${TEST_DIR}/bad-checkpoint/managed-hosts.json" > "${TEST_DIR}/bad-checkpoint/new.json"
mv "${TEST_DIR}/bad-checkpoint/new.json" "${TEST_DIR}/bad-checkpoint/managed-hosts.json"
run_phase fanout_mixed "$((COUNT * 2))"
record_live_count fanout_mixed
run_phase write_clones
run_phase verify_clones
snapshot_manifest > "${TEST_DIR}/checkpoints-after.jsonl"
cmp "${TEST_DIR}/checkpoints-before.jsonl" "${TEST_DIR}/checkpoints-after.jsonl"
run_phase delete_clones
# Check normal/failed lifecycle cleanup before the EXIT trap's defensive Delete.
sbox_cmd list > "${TEST_DIR}/inventory-after"
if awk 'NR > 1 {print $1}' "${TEST_DIR}/inventory-after" | grep -q "^${PREFIX}-"; then fail 'sandbox records remain'; fi
for id in "${ids[@]}"; do
    test ! -e "${SANDBOXD_ROOT}/containers/${id}" || fail "${id} bundle remains"
done
find "${FILESTORE_ROOT}" -mindepth 1 -print | LC_ALL=C sort > "${TEST_DIR}/filestore-after"
cmp "${TEST_DIR}/filestore-before" "${TEST_DIR}/filestore-after"
test "${HOST_HOSTS_HASH}" = "$(sha256sum /etc/hosts)"
test "${LOWER_HASH}" = "$(sha256sum "${LOWER_FILE}")"

python3 - "${TEST_DIR}" "${RUNTIME}" "${COUNT}" <<'PY'
import json
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
summary = {'runtime': sys.argv[2], 'count': int(sys.argv[3]), 'phases': {}}
for directory in sorted((root / 'phases').iterdir()):
    rows = [line.split('\t') for file in directory.glob('*.events.tsv') for line in file.read_text().splitlines()]
    if not rows:
        continue
    events = []
    for operation, index, start, end, status in rows:
        start, end, status = int(start), int(end), int(status)
        assert end >= start, (directory.name, index, 'clock moved backwards')
        events.extend([(start, 1), (end, -1)])
    current = peak = 0
    for _, delta in sorted(events):
        current += delta
        peak = max(peak, current)
    summary['phases'][directory.name] = {'operation_count': len(rows), 'peak_client_in_flight': peak,
                                        'elapsed_seconds': (max(t for t, _ in events)-min(t for t, _ in events))/1e9}
    if directory.name in ('start', 'write_sources', 'checkpoint', 'restore_own', 'write_own', 'fanout_mixed', 'write_clones'):
        assert peak >= 2, (directory.name, 'client operations did not overlap', peak)
summary['peak_live_sandboxes_observed'] = max(int(line.split('\t')[1]) for line in (root/'live-counts.tsv').read_text().splitlines())
(root / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
print(json.dumps(summary, indent=2))
PY
pass "concurrent lifecycle, shared-snapshot isolation, failed-restore cleanup and immutable artifacts (${COUNT} live sandboxes)"
