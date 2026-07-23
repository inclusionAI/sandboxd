#!/usr/bin/env bash
# Copyright (c) 2026 Ant Group Corporation.
# Licensed under the Apache License, Version 2.0.

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DOCKER="${DOCKER:-docker}"
IMAGE="${SANDBOXD_E2E_V2_IMAGE:-sandboxd-e2e-v2:local}"
RUN_ID="${SANDBOXD_E2E_V2_RUN_ID:-$$-${RANDOM}}"
CONTAINER="${SANDBOXD_E2E_V2_CONTAINER:-sandboxd-e2e-v2-${RUN_ID}}"
OWNERSHIP_LABEL="dev.sandboxd.e2e-v2.run-id"

cleanup() {
    local run_id
    run_id="$("${DOCKER}" inspect --format "{{ index .Config.Labels \"${OWNERSHIP_LABEL}\" }}" "${CONTAINER}" 2>/dev/null || true)"
    if [ "${run_id}" = "${RUN_ID}" ]; then
        "${DOCKER}" rm --force "${CONTAINER}" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

cd "${ROOT_DIR}"
"${DOCKER}" info >/dev/null || {
    echo "[e2e-v2][error] docker daemon is not accessible" >&2
    exit 1
}

if "${DOCKER}" inspect "${CONTAINER}" >/dev/null 2>&1; then
    echo "[e2e-v2][error] container ${CONTAINER} already exists; refusing to remove or reuse it" >&2
    exit 1
fi
"${DOCKER}" build \
    --file "${SCRIPT_DIR}/Dockerfile.v2" \
    --tag "${IMAGE}" \
    "${ROOT_DIR}"
"${DOCKER}" run \
    --name "${CONTAINER}" \
    --label "${OWNERSHIP_LABEL}=${RUN_ID}" \
    --privileged \
    --cgroupns host \
    --env E2E_CGROUP_VERSION=v2 \
    --env E2E_CGROUP_ROOT=sandboxd-e2e-v2 \
    --volume /sys/fs/cgroup:/sys/fs/cgroup:rw \
    "${IMAGE}"
