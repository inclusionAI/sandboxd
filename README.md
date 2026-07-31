# sandboxd

**sandboxd** is the Linux sandbox lifecycle service used by [AKernel](https://github.com/akernel-dev/akernel). It exposes a small gRPC API, manages sandbox resources, and runs sandboxes with [gVisor](https://github.com/google/gvisor) or [Kata Containers](https://github.com/kata-containers/kata-containers).

## Responsibilities

- Start, wait for, inspect, measure, and delete sandboxes.
- Prepare local, OCI, Nydus, and S3-backed rootfs and mounts.
- Allocate cgroups and veth interfaces and configure iptables for NAT.
- Discover, validate, and lease scheduler-selected accelerator devices.

## Architecture

```text
gRPC service
    |
sandbox lifecycle manager
    ├── sandbox runtime adapter ──> gVisor / Kata Containers
    ├── image manager ────────────> distill-fs / OCI
    └── resource managers ────────> cgroup v1 or v2 / veth / iptables
```

## API / CLI

The public protobuf contract is [api/runtime/v1/sandbox-api.proto](api/runtime/v1/sandbox-api.proto).

The `sbox` binary is an administrative CLI for managing sandboxes.

### NVIDIA GPU sandboxes

GPU support is experimental and currently uses gVisor runsc with nvproxy. The
scheduler passes concrete node-local device IDs through
`StartRequest.xpu_allocations`; sandboxd resolves them to NVIDIA UUIDs and
maintains a local exclusive lease:

```bash
sbox start \
  --rootfs /path/to/directory-rootfs \
  --xpu-allocation gpu:0,2 \
  /bin/sleep 300
```

When `[plugin.node_resource]` is enabled, `/resource` includes the stable XPU
inventory:

```json
{"cpu":32,"mem":68719476736,"xpu":[{"type":"gpu","product_model":"l20","device_ids":[0,1]}]}
```

See [test/e2e/README.md](test/e2e/README.md#gpu-debug-image) for the validated
GPU debug image and manual CUDA test.

## Build and test

```bash
make
make test
make vet
```

The privileged E2E suite requires Docker, iptables, and the tested runsc
release. It validates both a writable cgroup v1/v2 hierarchy and the
cgroup-disabled mode with `/sys/fs/cgroup` mounted read-only:

```bash
RUNSC_BINARY=/usr/local/bin/runsc make e2e
```

See [test/e2e/README.md](test/e2e/README.md) for the developer test environment. AKernel integration is validated through the all-in-one node image and standalone deployment in the AKernel repository.

## Protobuf development

Protobuf generation uses a pinned Docker image defined by the Makefile and `tools/protobuf.Dockerfile`, independent of host-installed protobuf tools:

```bash
make protos
make check-protos
```

Commit the generated Go bindings with the corresponding protobuf change.

## Project layout

```text
api/                 public protobuf API and generated Go code
cmd/sandboxd/        sandboxd daemon
cmd/sbox/            administrative CLI
config/              configuration types and defaults
configs/             AKernel integration configuration templates
internal/server/     gRPC service and daemon orchestration
pkg/runtime/         sandbox runtime abstraction and runtime adapters
pkg/imagemanager/    rootfs and mount integration
pkg/networkmanager/  veth and iptables integration
pkg/cgroupmanager/   transparent cgroup v1/v2 integration and cache
pkg/xpumanager/      accelerator discovery, inventory, and local leases
test/e2e/            privileged runsc E2E
tools/               pinned protobuf code-generation image
```

## Known limitations

- Kata Containers requires a usable `/dev/kvm` device; nodes without KVM continue to support gVisor.
- NVIDIA GPU sandboxes require runsc, a directory/lisafs-backed rootfs,
  `nvidia-container-cli`, accessible NVIDIA devices and userspace driver
  libraries, and a host driver supported by the pinned runsc nvproxy. Kata,
  MIG, fractional GPUs, and regular-file/EROFS rootfs are not supported.
- sandboxd detects the local cgroup mode at startup. Legacy and hybrid hosts use cgroup v1; unified hosts use cgroup v2. The gRPC API and resource-cache behavior are identical in both modes.
- `[plugin.resource].disable_cgroup = true` enables an experimental/debug
  compatibility mode for environments where sandboxd cannot write the
  delegated hierarchy. sandboxd, distill-fs, and runsc then perform no cgroup
  writes; runsc sandboxes inherit the sandboxd process cgroup. Per-sandbox
  CPU, memory, and pids requests are accepted but not enforced, per-sandbox
  Stats returns `FailedPrecondition`, and non-runsc runtimes are not
  advertised. Do not use this mode when per-sandbox resource isolation is
  required.
- To minimize sandbox startup latency, sandboxd caches and reuses physical cgroups across sandbox leases. Cumulative CPU accounting and peak-memory statistics therefore cover the physical cgroup lifetime, and reclaimable charges such as page cache may remain until kernel pressure reclaims them; CPU utilization calculated from sampling deltas and configured resource limits remain correct for the active sandbox.
- The direct OCI registry client currently skips TLS certificate verification and should only be used with trusted registries.

## License

Copyright (c) 2026 Ant Group Corporation.

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE). Third-party Go modules are declared in `go.mod` and retain their respective licenses.
