# sandboxd E2E

This flow validates the public runsc adapter and transparent cgroup selection
without an AKernel node image.

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
There is no sandboxd configuration switch for the cgroup version.

Set `RUN_UNIT_TESTS=0` to skip the unit-test step when rerunning only the
privileged scenario.
