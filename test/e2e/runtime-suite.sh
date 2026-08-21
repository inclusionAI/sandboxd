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
RUN_UNIT_TESTS="${RUN_UNIT_TESTS:-1}"

log() {
    printf '[runtime-suite] %s\n' "$*"
}

fail() {
    printf '[runtime-suite][error] %s\n' "$*" >&2
    exit 1
}

case "${RUN_UNIT_TESTS}" in
    0|1) ;;
    *) fail "RUN_UNIT_TESTS must be 0 or 1" ;;
esac

cd "${ROOT_DIR}"
if [ "${RUN_UNIT_TESTS}" = "1" ]; then
    log "running unit tests once"
    GOWORK=off GOCACHE=/tmp/go-build GOMODCACHE=/tmp/go-mod-official \
        GOTOOLCHAIN=auto go test ./...
fi

log "building sandboxd E2E binaries once"
bash test/e2e/build-binaries.sh

suite_status=0
run_case() {
    local name="$1"

    log "running ${name}"
    if ! E2E_CASE="${name}" bash test/e2e/runtime-case.sh; then
        suite_status=1
    fi
}

for name in runsc-systrap runsc-kvm kata firecracker runc; do
    run_case "${name}"
done

[ "${suite_status}" = "0" ] ||
    fail "one or more runtime E2E cases failed"
log "all runtime E2E cases passed"
