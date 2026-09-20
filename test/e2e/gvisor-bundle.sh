#!/usr/bin/env bash
# Copyright (c) 2026 Ant Group Corporation.
# SPDX-License-Identifier: Apache-2.0

# Source this file to validate and stage one complete local gVisor installation.
gvisor_bundle_members=(
    runsc
    containerd-shim-runsc-v1
    gvisor-bin/checkpointgofer
    gvisor-bin/gvisor-sentry-prewarmer
    gvisor-bin/gvisor_sentry
    gvisor-bin/runsc-metric-server
)

validate_gvisor_bundle() {
    local binary="$1" member source
    source="$(dirname "$(realpath "${binary}")")" || return 1
    for member in "${gvisor_bundle_members[@]}"; do
        if [ ! -f "${source}/${member}" ] || [ ! -x "${source}/${member}" ]; then
            printf 'incomplete gVisor bundle: %s; install the complete matching release archive\n' \
                "${source}/${member}" >&2
            return 1
        fi
    done
}

copy_gvisor_bundle() {
    local binary="$1" destination="$2" member source
    validate_gvisor_bundle "${binary}" || return 1
    source="$(dirname "$(realpath "${binary}")")" || return 1
    mkdir -p "${destination}/gvisor-bin"
    for member in "${gvisor_bundle_members[@]}"; do
        # RUNSC_BINARY may already point into output/. Avoid copying a file
        # onto itself while still validating every adjacent helper first.
        if [ "${source}/${member}" -ef "${destination}/${member}" ]; then
            continue
        fi
        install -m 0755 "${source}/${member}" "${destination}/${member}" || return 1
    done
}
