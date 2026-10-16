#!/usr/bin/env bash
# Wait for the suite's Redis stage before starting its DNAT readiness budget.
wait_for_redis_soak_stage() {
    local timeout_seconds="${E2E_REDIS_STAGE_TIMEOUT_SECONDS:-1800}"
    [[ "${timeout_seconds}" =~ ^[1-9][0-9]*$ ]] || return 1
    local deadline=$((SECONDS + timeout_seconds))
    local running stage
    while [ "${SECONDS}" -lt "${deadline}" ]; do
        if "${DOCKER}" inspect "${CONTAINER}" >/dev/null 2>&1; then
            running="$("${DOCKER}" inspect --format '{{.State.Running}}' "${CONTAINER}")" || return 1
            [ "${running}" = true ] || return 1
        fi
        stage="$("${DOCKER}" exec "${REDIS_CONTAINER}" redis-cli --raw GET "${REDIS_READY_KEY}")" || return 1
        if [ "${stage}" = ready ]; then return 0; fi
        sleep 0.5
    done
    printf '[e2e-run][error] suite did not reach the Redis stage in %ss\n' "${timeout_seconds}" >&2
    return 1
}
