# sandboxd E2E

The privileged E2E flows validate the public runsc, runc, Kata Containers, and
Firecracker adapters without an AKernel node image. CI compiles the
project-owned binaries once and passes them to five matrix jobs. Each job
downloads its checksum-pinned runtime payload, builds a targeted image, and
runs runsc-systrap, runsc-kvm, Kata, Firecracker, or runc independently.

## Coverage

The flow:

1. runs `go test ./...` unless `RUN_UNIT_TESTS=0`;
2. builds sandboxd, sbox, runc-shim, sandbox-logger, and firecracker-agent;
3. copies the selected upstream runtime and VM artifacts into a minimal image;
4. verifies start, list, inspect, exec, environment, working directory,
   stdout/stderr, exit codes, interactive TTY, wait, stats, and delete;
5. verifies sandbox networking, per-sandbox ACLs and published-port DNAT for
   runsc, Kata, and Firecracker, plus read-only files, EROFS mounts, and
   runtime-specific rootfs handling;
6. verifies CPU, memory, pids, writable-layer limits, natural exit, crash
   recovery, idempotent cleanup, and cached-resource reuse;
7. restarts sandboxd and verifies active sandbox, network endpoint, runtime
   process, and policy recovery;
8. verifies runsc in cgroup-disabled mode with `/sys/fs/cgroup` read-only;
9. verifies runc's ephemeral netns/veth lifecycle and optional KVM injection;
10. verifies Kata consumes the shared TAP cache without creating a private
    `ktap` lifecycle; and
11. verifies Firecracker's EROFS-only root and mount contract, private ext4
    overlay, quota exhaustion, guest exec/TTY protocol, direct service access,
    local DNAT, network ACL and managed DNS replacement, crash recovery,
    stale-policy removal, exit-code recovery when the daemon is unavailable,
    and reuse of the same TAP without policy leakage.

The checksum-pinned versions are maintained in
`third_party/runtime-versions.env`. AKernel consumes the same manifest and
Firecracker runtime bundle when it packages these runtimes. gVisor is
an AKernel compatibility release based on the upstream version encoded in its
release tag. The compatibility changes and upgrade process are documented in
the repository `AGENTS.md`. The adapters consume runtime state or boot
protocols that can change, so another version is not assumed compatible until
this suite passes.

## Commands

Run the default runsc and runc suite:

```bash
RUNSC_BINARY=/usr/local/bin/runsc \
RUNC_BINARY=/usr/local/bin/runc \
make e2e
```

Build the binaries once and run every targeted image locally:

```bash
make e2e-runtime-suite
```

To validate release candidates without changing the tracked version manifest,
point the suite at a complete alternate manifest:

```bash
RUNTIME_VERSIONS_FILE=/tmp/runtime-versions.env make e2e-runtime-suite
```

The alternate manifest must define every runtime artifact, not only gVisor.
The complete suite requires KVM even though its first case uses systrap.
Targeted images download only the runtime payload selected by each case.

Build the project-owned artifacts or run one matrix-equivalent case with:

```bash
make e2e-runtime-binaries

E2E_CASE=runsc-systrap make e2e-runtime-case
E2E_CASE=runsc-kvm make e2e-runtime-case
E2E_CASE=kata make e2e-runtime-case
E2E_CASE=firecracker make e2e-runtime-case
E2E_CASE=runc make e2e-runtime-case
```

A runtime case expects `make e2e-runtime-binaries` to have populated
`output/`. CI transfers those binaries as one compressed workflow artifact.

Run one adapter:

```bash
E2E_RUNTIME=runsc \
E2E_RUNSC_PLATFORM=systrap \
RUNSC_BINARY=/usr/local/bin/runsc \
make e2e

E2E_RUNTIME=runsc \
E2E_RUNSC_PLATFORM=kvm \
RUNSC_BINARY=/usr/local/bin/runsc \
make e2e

E2E_RUNTIME=runc \
RUNC_BINARY=/usr/local/bin/runc \
make e2e

E2E_RUNTIME=kata \
KATA_ROOT=/opt/kata \
make e2e

E2E_RUNTIME=firecracker \
FIRECRACKER_BINARY=/usr/local/bin/firecracker \
FIRECRACKER_KERNEL=/opt/firecracker/vmlinux \
FIRECRACKER_INITRD=/opt/firecracker/initrd.img \
make e2e
```

`KATA_ROOT` must contain the runtime-rs shim, Dragonball configuration,
guest kernel, and guest image at their upstream archive paths. The sandbox
logger is built with sandboxd. The Firecracker kernel must provide the facilities listed in
[the runtime guide](../../doc/runtime.md), and the initrd must contain the
matching `firecracker-agent` as `/init`.

Set `RUN_UNIT_TESTS=0` to skip unit tests while rerunning a privileged
scenario. Set `E2E_STRESS_ROUNDS` to a positive number and
`E2E_STRESS_CONCURRENCY` to 1 through 8 to run concurrent lifecycle rounds.
`E2E_RUNTIME=all` means runsc plus runc; Kata and Firecracker stay explicit
for targeted images. `E2E_SKIP_BUILD=1` reuses
`SANDBOXD_E2E_IMAGE`, and `E2E_RUN_CGROUP_DISABLED=0` suppresses the second
runsc cgroup-disabled container. These controls are used by the runtime-case
wrapper.
`E2E_RUNC_ONLY=1` remains a deprecated alias for `E2E_RUNTIME=runc`.

## Host requirements

- an accessible Docker daemon;
- Linux with cgroup v1 or a unified cgroup v2 hierarchy;
- permission to run privileged containers with the host cgroup namespace;
- usable iptables filter and nat tables plus bridge netfilter;
- `/dev/net/tun` for the persistent TAP cache;
- an EROFS-capable host and permission to load its module for runc;
- usable `/dev/kvm` for runsc-kvm, Kata, and Firecracker; and
- the selected runtime artifacts described above.

The test detects cgroup mode from `/sys/fs/cgroup/cgroup.controllers`.
There is no sandboxd cgroup-version switch. The separate disabled-mode
container does not use the host cgroup namespace and bind-mounts the hierarchy
read-only. Test containers keep sandboxd state and rootfs work trees on tmpfs,
so a runsc private overlay does not nest its upper directory inside Docker's
storage driver.

GitHub Actions builds the project-owned E2E binaries once and uploads them as
a short-lived artifact. Five dependent matrix jobs then build targeted images
and run runsc with systrap, runsc with KVM, Kata, Firecracker, and runc in
parallel. The three VM jobs fail immediately when nested KVM is unavailable.
Each case has its own runner VM, so cgroups, loop devices, TAPs, and network
state cannot leak between runtimes.

## GPU debug image

`gpu.Dockerfile` builds a standalone debug image with sandboxd, sbox, the
checksum-verified gVisor runsc release, `nvidia-container-cli` 1.19.1, and the
CUDA vectorAdd sample rootfs. It starts sandboxd in experimental
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

On SIGINT or SIGTERM, sandboxd deletes its sandboxes and owned network
resources, including pooled TAPs, ephemeral runc veth pairs and namespaces,
SNAT and DNAT rules, ACL hooks, and the `sandbox0` bridge. Kubernetes must
allow enough termination grace time for cleanup; SIGKILL cannot run shutdown
hooks.
