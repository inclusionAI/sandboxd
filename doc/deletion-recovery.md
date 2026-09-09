# Sandbox deletion and recovery

Sandbox deletion writes a versioned intent to the node's durable store before stopping the runtime or removing network forwarding. The intent retains the runtime name, a unique operation token, and the complete resource snapshot independently of the sandbox bundle. Runtime stop, network deactivation, filesystem release, and ACL removal may be repeated after interruption. Runtime deletion must succeed before the endpoint is disconnected and its policy removed.

Before releasing pooled resources, the server durably marks the intent as releasing. Pool allocation and sandbox ID reservation are serialized with final resource release, metadata removal, and intent completion. A failed final write leaves the intent available for retry and blocks new allocations until outstanding resource releases finish. This prevents a retried deletion from signaling or disconnecting resources that have already been handed to a new sandbox. Successful runtime teardown for unrelated sandboxes can still proceed concurrently.

Cgroup allocation persists the active lease before returning its name to the caller. Periodic and synchronous lease writes serialize both snapshot acquisition and persistence, preventing an older snapshot from overwriting a newly acknowledged allocation. Otherwise a crash in the periodic flush window could make recovery kill a live sandbox's cgroup as if it were idle.

A pooled TAP's lease removal is persisted before it enters the idle queue, where maintenance may destroy it. If persistence fails, the disconnected TAP stays leased and unavailable for reuse. Sandbox metadata removal reports errors and synchronizes its parent directory before the deletion intent can be cleared.

On restart, sandboxd restores filesystem references and retries unfinished deletions before constructing the active ACL bindings. A runtime that cannot be stopped aborts initialization; the server never suppresses missing policy state for a potentially live sandbox. Completed deletion phases are retried without requiring bundle metadata that may already be gone. Failure to initialize stops the interface manager while retaining TAPs, the bridge, SNAT, and durable leases belonging to other sandboxes. Normal service shutdown retains its existing full cleanup behavior.

The cgroup cleanup paths validate the entire PID snapshot before sending signals. PID 0, PID 1, sandboxd's own PID, and values outside Linux's positive signed 32-bit PID range are rejected. In particular, a process invisible from the reader's PID namespace can appear as PID 0 in `cgroup.procs`; it must never become a process-group `kill(0, SIGKILL)`. Cleanup continues using explicit per-process signals because supported kernels may lack the `cgroup.kill` / `CLONE_INTO_CGROUP` fix. This validation does not provide pidfd identity guarantees against PID reuse.

## Mixed-runtime TAP reuse

A persistent TAP can retain checksum and segmentation offloads enabled by Firecracker or Kata. When runsc attaches without `IFF_VNET_HDR`, it must also issue `TUNSETOFFLOAD(0)` before handing the FD to gVisor. Otherwise host TCP replies may reach gVisor with an unfinished checksum and no virtio metadata describing it. This affects both start and restore through `OpenTAP`; clearing the offloads fails closed if the ioctl fails. Linux keeps these offloads in the TAP device's `set_features` separately from the flags changed by `TUNSETIFF`; see the [Linux TUN implementation](https://github.com/torvalds/linux/blob/v6.8/drivers/net/tun.c).

Run `SANDBOXD_RUN_TAP_INTEGRATION=1 go test ./pkg/runtime/runsc -run TestOpenTAPResetsVMOffloads -count=1 -v` with `/dev/net/tun` and network administration permission inside an isolated network namespace. The test enables VM-style offloads on a persistent TAP and verifies that the real runsc handoff clears both checksum and segmentation features. Mixed runtime acceptance must probe connectivity for newly allocated sandboxes as well as survivors; monitoring survivors alone misses a broken recycled endpoint.

## Existing inconsistent nodes

A deletion interrupted by a version without this journal has no durable deletion intent. Upgrading does not infer that missing ACL state means the sandbox is safe to delete. Preserve the node's runtime, bundle, lease, and policy evidence and establish which workloads have stopped before arranging node recovery or draining it. Do not erase the database or disable ACL validation to force startup. Network preservation on initialization failure prevents further damage but cannot recreate TAPs destroyed by an older failed-start rollback.

## Verification

`make test` covers durable write failures, resource and ID reuse barriers, unchanged strict ACL restoration, interface lease persistence, and process exits during the actual server deletion path followed by recovery from the on-disk store. The process-exit tests use fake runtime handlers; privileged runsc/Firecracker validation must additionally exercise live endpoints, runtime teardown, daemon restart, and a surviving sandbox's connectivity. PID 0 regression tests execute the cleanup implementation only in a dedicated child process group so a regression cannot kill the parent test runner.
