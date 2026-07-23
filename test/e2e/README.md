# sandboxd E2E

This flow validates the public runsc adapter without an AKernel node image.

It performs:

1. `go test ./...`
2. builds `output/sandboxd` and `output/sbox`
3. copies an externally installed runsc to `output/runsc`
4. builds a minimal image containing sandboxd, sbox, runsc, iproute2,
   iptables, and busybox
5. runs a privileged container and verifies start, list, inspect, exec, bind
   mounts, sandbox networking, stats, and delete

Use the tested `runsc release-20260706.0`. The adapter reads runsc state and
uses gVisor control RPCs, so another release is not assumed compatible.

```bash
RUNSC_BINARY=/usr/local/bin/runsc bash test/e2e/run.sh

# Equivalent Make target.
RUNSC_BINARY=/usr/local/bin/runsc make e2e
```

Requirements:

- an accessible Docker daemon
- a Linux host with cgroup v1
- permission to run privileged containers with the host cgroup namespace
- a usable iptables nat table

Set `RUN_UNIT_TESTS=0` to skip the unit-test step when rerunning only the
privileged scenario.

## Experimental self-contained cgroup v2 flow

The cgroup v2 flow is intended for modern Linux hosts and the Linux VM used by
Docker Desktop or OrbStack on macOS. It downloads and verifies the pinned
runsc release while building the image, so the host does not need runsc or Go.

```bash
make e2e-v2
```

The runner uses `docker build` and `docker run` directly, with the host cgroup
namespace and a read-write cgroup mount inside a privileged container; Docker
Compose is not required. Docker Desktop Enhanced Container Isolation must be
disabled for this test. The flow verifies lifecycle, bind
mounts, networking, resource files, stats, OOM reporting, crash recovery, and
cleanup. It also verifies that sandboxd does not modify the delegated parent's
`cgroup.subtree_control`. The existing `make e2e` cgroup v1 flow is unchanged.

This flow is WIP and does not make cgroup v2 production-ready. Current local
evidence covers OrbStack on macOS/arm64. Before marking the feature ready for
review, repeat the privileged lifecycle on amd64 Linux and Docker Desktop, and
run the existing `make e2e` on a real cgroup v1 host.
