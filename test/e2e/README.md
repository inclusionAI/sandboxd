# sandboxd E2E

The privileged E2E flows validate the public runsc, runc, Kata Containers, and
Firecracker adapters without an AKernel node image. CI compiles the
project-owned binaries once and passes them to eight matrix jobs. Each job
downloads its checksum-pinned runtime payload, builds a targeted image, and
runs runsc-systrap, runsc-kvm, Kata, Firecracker (full, incremental, and virtio-fs), or runc independently.

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
8. verifies runsc in cgroup-disabled mode with `/sys/fs/cgroup` read-only, including rolling checkpoints and independent restores when filestore reflinks are enabled;
9. verifies runc's ephemeral netns/veth lifecycle, optional KVM injection, and resolver queries against a test-only local DNS fixture before and after sandboxd restart;
10. verifies Kata consumes the shared TAP cache without creating a private
    `ktap` lifecycle;
11. checkpoints the same runsc or Firecracker sandbox ten consecutive times,
    verifies it keeps running, and restores the tenth artifact;
12. verifies Firecracker's EROFS and virtio-fs root and mount contracts, OCI/Nydus directory rootfs, private ext4 overlay, native writable ext4 mounts (including checkpoint/restore), quota exhaustion, guest exec/TTY protocol, direct service access, local DNAT, network ACL and managed DNS replacement, crash recovery, stale-policy removal, exit-code recovery when the daemon is unavailable, and reuse of the same TAP without policy leakage; and
13. runs concurrent Redis SET/GET traffic from every runtime to a sibling
    Redis container through SNAT and from that container to the sandbox's
    published port through DNAT. The test verifies the translated source
    address and the DNAT packet counter instead of treating connectivity alone
    as proof that NAT was exercised.

The runsc partial-OOM regression injects a high-score host worker into the target sandbox's cgroup, resolved from its OCI config rather than directory order in the cgroup cache. A second sandbox remains live throughout the check: the target must report OOM and exit code 137, drain its host tasks, and become uninspectable after deletion, while the guard still executes commands. On cgroup v2 the target's `oom_kill` counter must increase and `cgroup.events` must report `populated 0`.

The checksum-pinned versions are maintained in
`third_party/runtime-versions.env`. AKernel consumes the same manifest and
Firecracker runtime bundle when it packages these runtimes. gVisor is
an AKernel compatibility release based on the upstream version encoded in its
release tag. The compatibility changes and upgrade process are documented in
the repository `AGENTS.md`. The adapters consume runtime state or boot
protocols that can change, so another version is not assumed compatible until
this suite passes.

Runsc fixtures budget 256 host tasks per sandbox cgroup for startup helpers, gofer, sentry and sidecars; the other targeted runtimes retain a 64-task budget. Kernel PID accounting includes threads, and transient setup can exceed 64 tasks on large hosts even for a single guest process. The suite checks the actual cgroup v1/v2 PID limit against the selected budget. These fixture limits do not change node configuration defaults or define a guest process limit.

Both runsc platforms test `plugin.runtime.direct_resolv_conf_path` with network ACLs disabled: they check the injected file and query the isolated DNS fixture without specifying a server, before and after a daemon crash. Crash checks wait for the periodic resource-ownership checkpoint. DNS mode changes require a drained node and a successful graceful shutdown within 30 seconds, including bridge and TAP cleanup, while retaining the store. After ACLs are enabled, a new runsc sandbox must use managed DNS even without a policy. The HTTP fixture starts after mode changes have recreated the bridge.

`go test ./test/e2e` checks the DNS dependency preflight and bounded shutdown helpers without privileged workloads. It covers missing tools, paths that do not use the DNS fixture, shutdown failures and timeouts, and residual network resources.

## Commands

Run the default runsc and runc suite:

`RUNSC_BINARY` must point to `runsc` from a complete extracted gVisor release, with the matching `containerd-shim-runsc-v1` and all five executable `gvisor-bin/` helpers beside it, including `runsc-fd-parking`. The runner validates the layout before building and copies the complete installation into the image; a bare runsc is rejected rather than falling back to embedded helpers. Use `third_party/install-gvisor.sh` with the manifest's archive SHA-512 to prepare a verified installation. Locally built bundles must preserve the same layout and matching source revision; adjacency alone cannot prove binary provenance.

```bash
RUNSC_BINARY=/usr/local/bin/runsc \
RUNC_BINARY=/usr/local/bin/runc \
make e2e
```

Build the binaries once and run every targeted image locally:

```bash
E2E_HOME_FIXTURE_PARENT=/path/on/reflink-capable-xfs make e2e-runtime-suite
```

The suite and binary builder honor `GOCACHE` and `GOMODCACHE`; if unset, they retain the `/tmp/go-build` and `/tmp/go-mod-official` defaults. Set both variables to the development host's persistent data disk when building outside CI.

To validate release candidates without changing the tracked version manifest,
point the suite at a complete alternate manifest:

```bash
RUNTIME_VERSIONS_FILE=/tmp/runtime-versions.env make e2e-runtime-suite
```

The alternate manifest must define every runtime artifact, not only gVisor.
The complete suite requires KVM even though its first case uses systrap.
The privileged fixture uses a host cgroup root named after `SANDBOXD_E2E_CONTAINER` (default `sandboxd-e2e`). Select a unique container name for each local task; `E2E_CGROUP_ROOT` can explicitly select its cgroup root. Container names, networks, image tags and disk fixture directories must also be isolated when sharing a host.
Hosted CI runners must provide the required kernel features. The workflow installs the userspace KVM checker and the matching `linux-modules-extra-$(uname -r)` package when APT publishes it, then explicitly loads and probes the network, filesystem, TUN and per-case KVM prerequisites. Some Azure kernels provide the required modules without a separately published extras package. A missing module or unusable device still fails the corresponding prerequisite step; preparing a host never substitutes for running the runtime case.
The `runsc-reflink` case also requires live filestores and checkpoints on the same reflink-capable filesystem. Use `E2E_HOME_FIXTURE_PARENT` to select an XFS directory with reflink enabled. The runtime's mount namespaces must permit FICLONE between its backing-file and snapshot descriptors; some older kernels return `EXDEV` even for the same underlying filesystem. CI runs this case on Ubuntu 24.04 with a dedicated XFS fixture and fails on unsupported clones rather than skipping the test.

`runsc-reflink` repeats running checkpoints, restores the saved writable state and process, restores an independent second target from the same artifact, verifies writes do not leak between targets or modify the saved filestores, checkpoints a restored target, and checks that a restored target survives deletion of its checkpoint directory. Ordinary runsc cases keep testing the default full serialization path.
Targeted images download only the runtime payload selected by each case.

Build the project-owned artifacts or run one matrix-equivalent case with:

```bash
make e2e-runtime-binaries

E2E_CASE=runsc-systrap make e2e-runtime-case
E2E_CASE=runsc-kvm make e2e-runtime-case
E2E_CASE=kata make e2e-runtime-case
E2E_CASE=firecracker make e2e-runtime-case
E2E_CASE=firecracker-incremental make e2e-runtime-case
E2E_CASE=firecracker-virtiofs make e2e-runtime-case
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

Validate an unpublished migration-capable Firecracker and virtiofsd together
without changing `third_party/runtime-versions.env`:

```bash
TMPDIR=/xfs/build-tmp make firecracker-initrd

E2E_RUNTIME=firecracker \
E2E_FIRECRACKER_VIRTIOFS=1 \
E2E_HOME_FIXTURE_PARENT=/xfs/test-tmp \
E2E_KEEP_HOME_FIXTURE=1 \
RUN_UNIT_TESTS=0 \
FIRECRACKER_BINARY=/path/to/candidate/firecracker \
FIRECRACKER_KERNEL=/path/to/candidate/vmlinux \
FIRECRACKER_INITRD="${PWD}/output/initrd.img" \
FIRECRACKER_VIRTIOFSD=/path/to/virtiofsd \
make e2e
```

The virtio-fs mode uses a directory rootfs and a read-only directory mount in
the main lifecycle and checkpoint/restore paths. It also checks the
`virtiofs.state` sidecar and compatibility digest. Point
`E2E_HOME_FIXTURE_PARENT` at XFS to exercise reflinked checkpoint memory and
filestore data there. The keep flag retains that fixture and prints its exact
path; the default remains automatic cleanup.

The `runsc-systrap` and `runsc-kvm` CI jobs automatically run the shared writable host-directory regression. The `firecracker-virtiofs` job runs it with both EROFS and directory roots, building virtiofsd from the revision pinned in `third_party/runtime-versions.env`. The regular Firecracker jobs retain their non-virtio-fs coverage. Each regression failure fails the runtime job.

For manual runs, use `test/e2e/host-mount-rw.sh` inside an existing node with `RUNTIME=runsc` or `RUNTIME=firecracker` (the default). Firecracker requires virtio-fs enabled. Have both `sbox` and the `checkpoint-restore` test client on `PATH`. Set `ROOTFS` to a usable EROFS image or directory root and `TEST_DIR` to a new absolute directory visible at the same path to sandboxd and the test process. The test checks mixed RO/RW mounts, host/guest visibility, file operations, rotation of an open append FD, local checkpoint/delete/restore, saved memory and read offsets, and source retention after deletion. It leaves caller-owned directories and checkpoints for inspection. Repeat with both root types, using different test directories. `KEEP_RUNNING=1` retains the restored sandbox for an additional daemon crash/recovery check.

```bash
ROOTFS=/path/to/root.erofs \
TEST_DIR=/path/to/new-test-directory \
RUNTIME=runsc \
CASE_ID=runsc-rw \
bash test/e2e/host-mount-rw.sh
```

`KATA_ROOT` must contain the runtime-rs shim, Dragonball configuration,
guest kernel, and guest image at their upstream archive paths. The sandbox
logger is built with sandboxd. The Firecracker kernel must provide the facilities listed in
[the runtime guide](../../doc/runtime.md), and the initrd must contain the
matching `firecracker-agent` as `/init`.

Set `RUN_UNIT_TESTS=0` to skip unit tests while rerunning a privileged scenario. Set `E2E_STRESS_ROUNDS` to a positive number and `E2E_STRESS_CONCURRENCY` to 1 through 32 to run concurrent lifecycle rounds. Targeted runtime cases enable the Redis network soak by default. Set `E2E_NETWORK_SOAK=1` with one selected `E2E_RUNTIME` to enable it for a direct `make e2e` invocation. The harness uses a digest-pinned Redis image; `E2E_REDIS_IMAGE` can point at a preloaded equivalent when Docker Hub is not reachable.
`E2E_RUNTIME=all` means runsc plus runc; Kata and Firecracker stay explicit for targeted images. `E2E_SKIP_BUILD=1` reuses `SANDBOXD_E2E_IMAGE`, and `E2E_RUN_CGROUP_DISABLED=0` suppresses the second runsc cgroup-disabled container. These controls are used by the runtime-case wrapper.
`E2E_RUNC_ONLY=1` remains a deprecated alias for `E2E_RUNTIME=runc`.

For a Firecracker virtio-fs storage soak, set `E2E_STRESS_ROOTFS_HOST` to a host directory that contains executable `/bin/sh`, `/stress-data/large.bin`, `/stress-data/small.master`, and a populated `/stress-data/small` directory. The harness mounts it read-only into the E2E container, continuously verifies and scans it from every concurrent guest, and keeps each guest's writes in its private layer. `E2E_STRESS_CHECKPOINT=1` checkpoints and restores one guest in every round while the remaining guests continue their read workload. The host directory can be a distill-fs Nydus FUSE mount to exercise the complete Nydus-to-virtio-fs data path. Set `E2E_STRESS_ONLY=1` to skip the ordinary runtime cases when iterating on a soak; it requires Firecracker virtio-fs and at least one stress round.

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
read-only. Each test container bind-mounts a dedicated host disk directory at
`/home/akernel` for sandboxd state, rootfs work trees, and checkpoint
artifacts. This avoids both tmpfs-only checkpoint behavior and nested private
overlays in Docker's writable layer. The harness rejects a tmpfs-backed source
and verifies the mount again inside the container.

GitHub Actions builds the project-owned E2E binaries once and uploads them as a short-lived artifact. Eight dependent matrix jobs build targeted images for runsc with systrap, runsc with KVM, runsc with filestore reflinks, Kata, Firecracker (full, incremental, and virtio-fs), and runc. KVM-dependent jobs fail immediately when nested KVM is unavailable. The reflink job runs on Ubuntu 24.04 with XFS; other runtime jobs retain their existing runners. Each case has its own runner VM, so cgroups, loop devices, TAPs, and network state cannot leak between runtimes.

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

The direct DNS E2E fixture binds `192.0.2.53/32` inside the test container. When selecting a custom `E2E_NETWORK_CIDR` for a runsc, runc, or `all` run, keep that address outside the sandbox network range. These DNS test paths require `dnsmasq` and `timeout`; preflight checks them before starting sandboxd. Cgroup-disabled tests and manual `serve` mode do not run the fixture or require its tools. The fixture is test-only and does not provide production DNS forwarding.

## Shutdown cleanup

Configure an unused `[plugin.network].ip_range` whenever sandboxd shares its
network namespace with other software. The E2E entrypoint selects a usable
nftables or legacy iptables frontend according to the kernel.

On SIGINT or SIGTERM, sandboxd deletes its sandboxes and owned network
resources, including pooled TAPs, ephemeral runc veth pairs and namespaces,
SNAT and DNAT rules, ACL hooks, and the `sandbox0` bridge. Kubernetes must
allow enough termination grace time for cleanup; SIGKILL cannot run shutdown
hooks.

### PVM node validation

The optional `firecracker-pvm`, `firecracker-pvm-incremental`, and `firecracker-pvm-virtiofs` cases require a dedicated x86-64 PVM host kernel with `kvm_pvm` already loaded. They are excluded from the default hardware-KVM matrix and do not install kernels or switch host modules. Select the independently locked PVM candidate through `third_party/firecracker-pvm.json` and `prepare-firecracker-pvm.py`; the targeted image rejects a bundle whose `kernel_profile` differs from the selected runtime. Do not modify the default release pins until the exact CI candidate has been qualified and promoted. The agent initrd is built from the consuming sandboxd revision.

```sh
RUNTIME_VERSIONS_FILE=/path/to/pvm-candidate-versions.env \
  E2E_CASE=firecracker-pvm-incremental make e2e-runtime-case
RUNTIME_VERSIONS_FILE=/path/to/pvm-candidate-versions.env \
  E2E_CASE=firecracker-pvm-virtiofs make e2e-runtime-case
```

A direct `make e2e` also accepts `E2E_RUNTIME=firecracker-pvm` with explicitly selected `FIRECRACKER_BINARY`, `FIRECRACKER_KERNEL`, and matching `FIRECRACKER_INITRD`. It runs the same lifecycle and compatibility checks as hardware KVM. The virtio-fs case includes OCI/Nydus image-provider checks and requires reachable image registries; a local-directory-only run must identify any skipped image-provider checks explicitly.

The current Actions matrix covers hardware KVM, not PVM. Adding a PVM case to that matrix without preparing an isolated PVM L1 is insufficient: the backend probe must reject stock hardware KVM. A dedicated PVM qualification job should boot its own disposable L1 with a checksum-pinned distribution kernel and matched OOT module pair, run the Full, Incremental and virtio-fs cases inside it, and export kernel/module/bundle provenance, restore-integrity checks and cleanup results. Use the same candidate bundle bytes for AKernel SDK/image-provider/pressure validation before promotion. Never switch a shared runner or active cluster's KVM modules for CI, and do not infer PVM qualification from successful ordinary Firecracker jobs.

## Independent PVM candidate qualification

`.github/workflows/pvm-e2e.yml` is separate from the hardware-KVM matrix. A maintainer dispatch resolves `source_ref` (empty for the dispatch SHA, `main`, or an open `refs/pull/N/head` targeting main) before assigning an ephemeral `pvm-l1-ubuntu7` runner. Upstream dispatch uses the workflow on main; fork dispatch can qualify the fork's exact workflow SHA. Pushes to main only register the workflow and do not assign an L1. The request runs on a GitHub-hosted runner, and every checkout uses its resolved immutable SHA.

The caller selects AKernel's versioned `deploy/pvm/host-profile.json` through `host_profile_ref`: `develop` or an open `refs/pull/N/head` targeting develop. This consumer-owned file is the only source of expected host pins; sandboxd does not keep another copy. Before the consumer change lands, select its PR explicitly. For example, `gh workflow run pvm-e2e.yml --repo inclusionAI/sandboxd --ref main -f host_profile_ref=refs/pull/104/head`. After the profile lands, the default is develop. The workflow verifies the checked-out profile digest against the request job's resolved consumer commit.

The provisioner boots the unchanged qualified distro kernel with VMX/SVM hidden, sets CPU/memory/I/O limits outside the L1, supplies `/etc/akernel-pvm-ci.json`, the complete pair under `/opt/akernel-pvm-ci/modules`, and its original build receipt at `/opt/akernel-pvm-ci/host-build.json`. It starts only the private `unix:///run/pvm-ci-docker.sock` daemon. `pvm-l1.py` requires `PVM_HOST_PROFILE` or `--expected-host-profile`: it compares source/baseline, kernel identity, target-profile and prepared-tree hashes, compiler/target evidence, successful modpost and both module hashes with that committed expectation before module loading. The build receipt itself is checksum-bound by the profile, so changing the marker and module files together cannot authorize a different build. `--probe` additionally checks the real PVM MSR ABI and nonzero TSC frequency. Evidence records the expected-profile and build-receipt digests.

`python3 test/e2e/test_pvm_l1.py -v` and `python3 test/e2e/test_pvm_request.py -v` run offline negative tests without ioctls or module operations. They also run in ordinary PR CI. Missing profiles, stale source/target pins, incomplete or substituted module pairs, modified build evidence and disallowed request refs fail. Cleanup deliberately uses `--boundary-only`: this proves ownership/resource boundaries, never host-version qualification, and cannot be combined with `--probe`. The provisioner stops the L1 after the job, including cancellation/failure; workflow cleanup removes only its uniquely named containers and unloads the pair inside the L1.

`third_party/firecracker-pvm.json` selects the published `v1.16.1-akernel.4` PVM archive and retains the original Actions run/commit, artifact digest, archive digest and strict guest source as provenance. Its published archive is byte-identical to the qualified candidate. `prepare-firecracker-pvm.py` validates those bytes, provenance, x86-64 ELF files and the PVM/PIE/MPK configuration before staging the original archive into a Git-ignored build-context directory. A local `PVM_CANDIDATE_ARCHIVE` reuses exactly the pinned bytes; it cannot override the pin. An Actions distribution requires `GH_TOKEN` and never forwards its Authorization header to blob storage. After exact-byte qualification and promotion, the same descriptor can select `distribution=release` with the published repository/tag/archive URL and unchanged archive/provenance digests; public release downloads require no token or live Actions artifact. A release URL must exactly match the pinned repository, tag and filename, and every staged copy receives the same archive, ELF, provenance and configuration checks. KVM retains the ordinary runtime manifest. Selecting a PVM case reads the separate pin and cannot silently consume a KVM bundle. Unpromoted candidates expire normally; update the reviewed pin after rebuilding instead of bypassing validation. No release is promoted by this workflow.

The isolated runner's `/opt/akernel-pvm-ci/fixtures.json` identifies its anonymous local OCI/Nydus registry and pinned image fixtures. PVM runtime CI uses its Redis OCI fixture through an explicit HTTP registry scheme; ordinary E2E retains its HTTPS/default image settings. This removes public-registry connectivity from guest boot/restore acceptance without replacing image-provider tests with directory roots. Preserve failed-run artifacts; a registry-resolution timeout does not prove a guest-agent timeout.

The external Redis DNAT client waits for an explicit `ready` signal from the suite after the guest Redis responds to PING. The unchanged 300-second DNAT readiness budget starts at that stage; earlier checkpoint and host-mount tests do not consume it. The pre-stage wait is separately bounded by `E2E_REDIS_STAGE_TIMEOUT_SECONDS` (default 1800) and exits when the suite container stops. The guest-agent boot budget remains 15 seconds.
