#!/usr/bin/env bash
# Copyright (c) 2026 Ant Group Corporation.
# Licensed under the Apache License, Version 2.0.

# Sourced by e2e-run.sh in its isolated mount-contract phase.
prepare_mount_contract() {
    MOUNT_CONTRACT_DIR="${SANDBOXD_HOME}/mount-contract"
    mkdir -p "${MOUNT_CONTRACT_DIR}/baseline/nested" "${MOUNT_CONTRACT_DIR}/child"
    printf 'baseline\n' > "${MOUNT_CONTRACT_DIR}/baseline/origin"
    printf 'hidden-parent-entry\n' > "${MOUNT_CONTRACT_DIR}/baseline/nested/origin"
    printf 'child\n' > "${MOUNT_CONTRACT_DIR}/child/origin"
    local base="${CONFIG_DIR}/mount-contract.json"
    jq -n --arg parent "${MOUNT_CONTRACT_DIR}/baseline" --arg child "${MOUNT_CONTRACT_DIR}/child" '{
        ociVersion:"1.0.2", hostname:"akernel",
        process:{terminal:false,user:{uid:0,gid:0},args:["/bin/sleep","300"],env:["PATH=/bin:/usr/bin"],cwd:"/",
            capabilities:{bounding:["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FOWNER","CAP_SETGID","CAP_SETUID"],effective:["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FOWNER","CAP_SETGID","CAP_SETUID"],permitted:["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FOWNER","CAP_SETGID","CAP_SETUID"]}},
        root:{path:"rootfs",readonly:false},
        mounts:[{destination:"/proc",source:"proc",type:"proc"},
            {destination:"/dev",source:"tmpfs",type:"tmpfs"},
            {destination:"/sys",source:"sysfs",type:"sysfs",options:["ro","nosuid","noexec","nodev"]},
            {destination:"/app/logs",source:$parent,type:"bind",options:["rbind","rw","rprivate"]},
            {destination:"/app/logs/nested",source:$child,type:"bind",options:["rbind","ro","rprivate"]}],
        linux:{namespaces:[{type:"pid"},{type:"network"},{type:"ipc"},{type:"uts"},{type:"mount"}]}
    }' > "${base}"
    sed -i "s|^runsc = \"\"$|runsc = \"${base}\"|; s|^runc = \"\"$|runc = \"${base}\"|" "${CONFIG_FILE}"
}

assert_mount_contract() {
    local id="$1" mode="$2" origin="$3"
    assert_eq "$(sbox_cmd exec "${id}" /bin/cat /app/logs/origin)" "${origin}" "mount replacement source"
    assert_eq "$(sbox_cmd exec "${id}" /bin/cat /app/logs/nested/origin)" child "nested mount remains visible"
    if sbox_cmd exec "${id}" /bin/sh -c 'echo writable > /app/logs/probe' > "${MOUNT_CONTRACT_DIR}/write.log" 2>&1; then
        [ "${mode}" = rw ] || fail "read-only parent accepted a write"
    else
        [ "${mode}" = ro ] || { cat "${MOUNT_CONTRACT_DIR}/write.log" >&2; fail "writable parent rejected a write"; }
    fi
    if sbox_cmd exec "${id}" /bin/sh -c 'echo forbidden > /app/logs/nested/probe' > "${MOUNT_CONTRACT_DIR}/child-write.log" 2>&1; then
        fail "read-only nested mount accepted a write"
    fi
    [ ! -e "${MOUNT_CONTRACT_DIR}/child/probe" ] || fail "nested write escaped read-only mount"
    local spec="${SANDBOXD_ROOT}/containers/${id}/config.json"
    jq -e '([.mounts[] | select(.destination == "/app/logs")] | length) == 1 and
        (([.mounts[].destination] | index("/app/logs")) < ([.mounts[].destination] | index("/app/logs/nested")))' "${spec}" >/dev/null ||
        fail "effective OCI mount layout is not unique and parent-first"
}

run_mount_contract_checks() {
    local runtime="$1" mode source request checkpoint target opposite base_digest
    base_digest="$(sha256sum "${CONFIG_DIR}/mount-contract.json")"
    for mode in ro rw; do
        log "testing ${runtime} ${mode} baseline override and nested mount visibility"
        source="${MOUNT_CONTRACT_DIR}/${runtime}-${mode}"
        mkdir -p "${source}/nested"
        printf 'explicit\n' > "${source}/origin"
        printf 'hidden-parent-entry\n' > "${source}/nested/origin"
        request="${MOUNT_CONTRACT_DIR}/${runtime}-${mode}.json"
        checkpoint="${MOUNT_CONTRACT_DIR}/${runtime}-${mode}-checkpoint"
        SANDBOX_ID="sbox-mount-${runtime}-${mode}"
        checkpoint-restore --action start --socket "${SOCKET}" --runtime "${runtime}" \
            --rootfs "${ROOTFS}" --sandbox-id "${SANDBOX_ID}" --request-file "${request}" \
            --memory-mb 256 --storage-mb 0 --mount "${source}:/app/logs:bind:rbind,${mode}" \
            --workload-cmd 'echo started >> /var/mount-contract-starts; while :; do sleep 1; done'
        assert_mount_contract "${SANDBOX_ID}" "${mode}" explicit
        if [ "${runtime}" = runsc ]; then
            checkpoint-restore --action checkpoint --socket "${SOCKET}" --sandbox-id "${SANDBOX_ID}" \
                --checkpoint-dir "${checkpoint}" --leave-running=false
            sbox_cmd delete "${SANDBOX_ID}"
            target="${SANDBOX_ID}-restored"
            opposite=ro
            [ "${mode}" = ro ] && opposite=rw
            jq --arg mode "${opposite}" '.mounts |= map(if .target == "/app/logs" then .options = ["rbind", $mode] else . end)' \
                "${request}" > "${request}.changed"
            SANDBOX_ID="${target}-changed"
            if checkpoint-restore --action restore --socket "${SOCKET}" --target-id "${SANDBOX_ID}" \
                --checkpoint-dir "${checkpoint}" --request-file "${request}.changed" > "${request}.error" 2>&1; then
                fail "restore accepted ${mode} to ${opposite} mount change"
            fi
            grep -Eq 'Mounts.*does not match|invalid mount in the restore spec' "${request}.error" ||
                { cat "${request}.error" >&2; fail "restore failed for a reason other than mount compatibility"; }
            if sbox_cmd inspect "${SANDBOX_ID}" >/dev/null 2>&1; then
                fail "rejected restore left a tracked sandbox"
            fi
            SANDBOX_ID="${target}"
            checkpoint-restore --action restore --socket "${SOCKET}" --target-id "${SANDBOX_ID}" \
                --checkpoint-dir "${checkpoint}" --request-file "${request}"
            assert_mount_contract "${SANDBOX_ID}" "${mode}" explicit
            assert_eq "$(sbox_cmd exec "${SANDBOX_ID}" /bin/cat /var/mount-contract-starts)" started "restore did not restart workload"
            rm -rf -- "${checkpoint}"
            assert_mount_contract "${SANDBOX_ID}" "${mode}" explicit
        fi
        sbox_cmd delete "${SANDBOX_ID}"
        SANDBOX_ID=""
        assert_eq "$(cat "${source}/origin")" explicit "caller data survives sandbox deletion"
    done

    # A later sandbox without overrides must still observe the original base.
    SANDBOX_ID="sbox-mount-${runtime}-baseline"
    checkpoint-restore --action start --socket "${SOCKET}" --runtime "${runtime}" --rootfs "${ROOTFS}" \
        --sandbox-id "${SANDBOX_ID}" --request-file "${MOUNT_CONTRACT_DIR}/${runtime}-baseline.json" \
        --memory-mb 256 --storage-mb 0 --workload-cmd 'while :; do sleep 1; done'
    assert_mount_contract "${SANDBOX_ID}" rw baseline
    sbox_cmd delete "${SANDBOX_ID}"
    SANDBOX_ID=""
    assert_eq "$(sha256sum "${CONFIG_DIR}/mount-contract.json")" "${base_digest}" "shared base spec unchanged"
    log "${runtime} mount contract passed"
}

run_mount_contract_e2e() {
    preflight
    cleanup_cgroups
    write_config
    prepare_rootfs
    prepare_mount_contract
    start_sandboxd
    case "${E2E_RUNTIME}" in
        all) run_mount_contract_checks runsc; run_mount_contract_checks runc ;;
        runsc|runc) run_mount_contract_checks "${E2E_RUNTIME}" ;;
        *) fail "mount-contract requires runsc or runc" ;;
    esac
}
