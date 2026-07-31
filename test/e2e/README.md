# sandboxd E2E

This flow validates the public runsc adapter with and without sandbox-managed
cgroups, without an AKernel node image.

It performs:

1. `go test ./...`
2. builds `output/sandboxd` and `output/sbox`
3. copies an externally installed runsc to `output/runsc`
4. builds a minimal image containing sandboxd, sbox, runsc, iproute2,
   iptables, and busybox
5. runs a privileged container and verifies start, list, inspect, exec, bind
   mounts, sandbox networking, stats, and delete
6. verifies CPU shares/weight, memory limit, and pids limit in the detected
   cgroup hierarchy
7. forces a memory OOM and verifies the sandbox exit event
8. reuses the cached cgroup with different limits and verifies that the OOM
   state and mutable controls do not leak between leases
9. restarts sandboxd and verifies recovery plus OOM monitoring reattachment
10. reruns start, list, exec, and delete in the experimental cgroup-disabled
    mode with `/sys/fs/cgroup` read-only

Use the tested `runsc release-20260706.0`. The adapter reads runsc state and
uses gVisor control RPCs, so another release is not assumed compatible.

```bash
RUNSC_BINARY=/usr/local/bin/runsc bash test/e2e/run.sh

# Equivalent Make target.
RUNSC_BINARY=/usr/local/bin/runsc make e2e
```

Requirements:

- an accessible Docker daemon
- a Linux host with either cgroup v1 or a unified cgroup v2 hierarchy
- permission to run privileged containers with the host cgroup namespace
- a usable iptables nat table

The test detects the host mode from `/sys/fs/cgroup/cgroup.controllers`.
There is no sandboxd configuration switch for the cgroup version. The
separate disabled-mode container does not use the host cgroup namespace and
bind-mounts the hierarchy read-only.

Set `RUN_UNIT_TESTS=0` to skip the unit-test step when rerunning only the
privileged scenario.

## GPU debug image

`gpu.Dockerfile` builds a standalone debug image with sandboxd, sbox, the
checksum-verified gVisor runsc release, `nvidia-container-cli` 1.19.1, and the
CUDA vectorAdd sample rootfs. It starts sandboxd in the experimental
cgroup-disabled mode:

```bash
docker build -f test/e2e/gpu.Dockerfile -t sandboxd-gpu:local .
docker run -d --name sandboxd-gpu --privileged --gpus all \
  -e NVIDIA_DRIVER_CAPABILITIES=compute,utility \
  sandboxd-gpu:local

id="$(docker exec sandboxd-gpu sbox start --quiet \
  --rootfs /e2e/gpu-rootfs \
  --xpu-allocation gpu:0 \
  /bin/sleep 300)"
docker exec sandboxd-gpu sbox exec "${id}" /cuda-samples/vectorAdd
docker exec sandboxd-gpu sbox delete "${id}"
```

Use `--xpu-allocation gpu:0,1` to assign more than one physical GPU. sandboxd
resolves node-local IDs to UUIDs and presents them inside the sandbox as
contiguous CUDA device indices.

For a Kubernetes Pod that shares its network namespace with other software,
select an unused `[plugin.network].ip_range` with at least 1,000 addresses (a
`/22` or larger range), for example:

```bash
E2E_DISABLE_CGROUP=1 \
E2E_NETWORK_CIDR=172.30.252.1/22 \
/usr/bin/tini -s -- /usr/local/bin/sandboxd-e2e-run serve
```

## Shutdown cleanup

Configure an unused `[plugin.network].ip_range` whenever sandboxd shares its
network namespace with other software. The E2E entrypoint selects a usable
nftables or legacy iptables frontend according to the kernel.

On SIGINT or SIGTERM, sandboxd deletes the sandboxes and network resources it
owns, including veth pairs, SNAT and DNAT rules, and the `sandbox0` bridge.
Kubernetes must allow enough termination grace time for that cleanup; SIGKILL
cannot run shutdown hooks.
