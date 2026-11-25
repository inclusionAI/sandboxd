#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Run against an isolated configured sandboxd. The checkpoint root must be
# on the publisher mount and outside sealed_checkpoint_scratch.
set -euo pipefail
: "${SOCKET:?}" "${EROFS_ROOTFS:?}" "${CHECKPOINT_ROOT:?}"
root=$(mktemp -d "${CHECKPOINT_ROOT}/sealed-e2e-XXXXXXXX")
id="sbox-${root##*/}"
request=$(mktemp)
rpc() { checkpoint-restore --socket "$SOCKET" "$@"; }
guest() { sbox --address "$SOCKET" --timeout 30s exec "$@"; }
created=()
cleanup() {
    for vm in "${created[@]}"; do
        sbox --address "$SOCKET" --timeout 30s delete "$vm" >/dev/null 2>&1 || true
    done
    rm -rf -- "$root"
    rm -f -- "$request"
}
trap cleanup EXIT
# A random value held only in the shell variable survives snapshot/load.
# New output after removing the previous reply proves the process is live.
workload='read secret < /proc/sys/kernel/random/uuid; while :; do if [ -f /var/ask ]; then rm /var/ask; echo "$secret" > /var/reply; fi; sleep 0.1; done'
probe() {
    guest "$1" /bin/sh -ec 'rm -f /var/reply; touch /var/ask; for i in $(seq 1 80); do if [ -s /var/reply ]; then cat /var/reply; exit 0; fi; sleep 0.1; done; exit 1'
}
capture() {
    rpc --action checkpoint --sandbox-id "$1" --checkpoint-dir "$root/$2" --leave-running="$3" --checkpoint-timeout-seconds 180
}
restore() {
    created+=("$2")
    rpc --action restore --request-file "$request" --checkpoint-dir "$root/$1" --target-id "$2"
}
created+=("$id-a")
rpc --action start --runtime firecracker --rootfs "$EROFS_ROOTFS" --sandbox-id "$id-a" --request-file "$request" --memory-mb 256 --storage-mb 64 --workload-cmd "$workload"
secret=$(probe "$id-a")
test -n "$secret"
guest "$id-a" /bin/sh -ec 'echo base > /var/value; sync'
capture "$id-a" G0 true
restore G0 "$id-b"
test "$(probe "$id-b")" = "$secret"
test "$(guest "$id-b" /bin/cat /var/value)" = base
rm -rf -- "$root/G0"
if [ -n "${SEALED_FAIL_MERGE_MARKER:-}" ]; then
    # The test-only wrapper around the runtime helper consumes this marker.
    touch "$SEALED_FAIL_MERGE_MARKER"
    if capture "$id-b" failed true; then exit 1; fi
    test ! -e "$root/failed/manifest.json"
    test ! -e "$SEALED_FAIL_MERGE_MARKER"
    test "$(probe "$id-b")" = "$secret"
fi
for gen in 1 2 3 4; do
    guest "$id-b" /bin/sh -ec "echo $gen > /var/value; sync"
    live=true
    if [ "$gen" = 4 ]; then live=false; fi
    capture "$id-b" "G$gen" "$live"
    test "$(jq -r .snapshot_type "$root/G$gen/manifest.json")" = Diff
done
for gen in 4 2 1; do
    restore "G$gen" "$id-c$gen"
    test "$(guest "$id-c$gen" /bin/cat /var/value)" = "$gen"
    test "$(probe "$id-c$gen")" = "$secret"
done
echo "PASS: four sealed generations, live and stopping captures, three independent restores, file contents and process memory"
