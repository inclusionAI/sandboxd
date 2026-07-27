# sandboxd

**sandboxd** is the Linux sandbox lifecycle service used by [AKernel](https://github.com/akernel-dev/akernel). It exposes a small gRPC API, manages sandbox resources, and runs sandboxes with [gVisor](https://github.com/google/gvisor) or [Kata Containers](https://github.com/kata-containers/kata-containers).

## Responsibilities

- Start, wait for, inspect, measure, and delete sandboxes.
- Prepare local, OCI, Nydus, and S3-backed rootfs and mounts.
- Allocate cgroups and veth interfaces and configure iptables for NAT.

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

## Build and test

```bash
make
make test
make vet
```

The privileged E2E suite requires Docker, iptables, a writable cgroup v1 or v2 hierarchy, and the tested runsc release:

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
test/e2e/            privileged runsc E2E
tools/               pinned protobuf code-generation image
```

## Known limitations

- Kata Containers requires a usable `/dev/kvm` device; nodes without KVM continue to support gVisor.
- sandboxd detects the local cgroup mode at startup. Legacy and hybrid hosts use cgroup v1; unified hosts use cgroup v2. The gRPC API and resource-cache behavior are identical in both modes.
- To minimize sandbox startup latency, sandboxd caches and reuses physical cgroups across sandbox leases. Cumulative CPU accounting and peak-memory statistics therefore cover the physical cgroup lifetime, and reclaimable charges such as page cache may remain until kernel pressure reclaims them; CPU utilization calculated from sampling deltas and configured resource limits remain correct for the active sandbox.
- The direct OCI registry client currently skips TLS certificate verification and should only be used with trusted registries.

## License

Copyright (c) 2026 Ant Group Corporation.

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE). Third-party Go modules are declared in `go.mod` and retain their respective licenses.
