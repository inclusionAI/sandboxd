#!/usr/bin/env bash
# Copyright (c) 2026 Ant Group Corporation.
# SPDX-License-Identifier: Apache-2.0

# Install a verified complete gVisor archive into a binary directory.
set -euo pipefail

if [[ $# != 3 || ! $2 =~ ^[[:xdigit:]]{128}$ ]]; then
    echo "usage: $0 ARCHIVE SHA512 BIN_DIRECTORY" >&2
    exit 1
fi
archive="$(realpath "$1")"
digest="$2"
destination="$3"
printf '%s  %s\n' "$digest" "$archive" | sha512sum --check --status

# Accept only the release layout. Reject duplicates, links, special files,
# and unexpected paths before extracting anything into the destination.
expected=$'containerd-shim-runsc-v1\ngvisor-bin/checkpointgofer\ngvisor-bin/gvisor-sentry-prewarmer\ngvisor-bin/gvisor_sentry\ngvisor-bin/runsc-metric-server\nrunsc'
actual="$(tar -tjf "$archive" | sed 's#^\./##' | sed '/^$/d; /\/$/d' | LC_ALL=C sort)"
[[ "$actual" == "$expected" ]] || {
    echo "unexpected gVisor archive members" >&2
    exit 1
}
tar -tvjf "$archive" | awk '
    substr($1, 1, 1) != "-" && substr($1, 1, 1) != "d" { bad=1 }
    END { exit bad }
'
while IFS= read -r member; do
    case "$member" in
        ./|gvisor-bin/|./gvisor-bin/) ;;
        */) echo "unexpected archive directory: $member" >&2; exit 1 ;;
    esac
done < <(tar -tjf "$archive")

mkdir -p "$destination"
destination="$(realpath "$destination")"
stage="$(mktemp -d "$destination/.gvisor-install.XXXXXX")"
trap 'rm -rf -- "$stage"' EXIT
tar -xjf "$archive" --no-same-owner --no-same-permissions -C "$stage"
mkdir -p "$destination/gvisor-bin"
while IFS= read -r member; do
    [[ -f "$stage/$member" && ! -L "$stage/$member" ]]
    install -m 0755 "$stage/$member" "$destination/$member"
done <<< "$expected"
