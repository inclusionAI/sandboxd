# Runsc checkpoint and restore

Sandboxd exposes a deterministic checkpoint/restore primitive for the runsc
runtime. The caller owns the logical snapshot lifecycle; sandboxd owns the
atomic local artifact and the node-local physical sandbox record.

## Authority boundaries

Three facts must not be conflated:

- `checkpoint.img` and `manifest.json` are the immutable checkpoint artifact.
  The manifest binds the checkpoint ID, source ID, runtime, rootfs identity,
  leave-running mode, image size, and SHA-256.
- `meta.pb` is sandboxd's durable node-local record. `COMMITTED` means that a
  physical creation crossed sandboxd's publish boundary; it is not proof that
  the runtime remains alive after a process or host failure.
- The runtime handler's reconciled `List` result is the liveness authority. For
  runsc, sandboxd also verifies that the recorded PID is a non-zombie
  `runsc-sandbox` process for the exact sandbox ID; runsc's persisted
  `status=running` value alone is not a live physical fact. A restored sandbox
  is replayable from its existing response only when this check reports the
  exact ID `RUNNING`.

Sandboxd reconstructs its in-memory manager, port allocator, and network
cleanup indexes from these durable facts. It does not use a separate restore
journal outside the sandbox record and runtime state.

## Checkpoint lifecycle

Checkpoint atomically publishes `checkpoint.img` and `manifest.json` in the
requested directory below `<root_dir>/checkpoints`. Nested directories are
supported. Startup recursively removes only unpublished
`.<name>.staging-*` directories and never follows symbolic links.

`leave_running=true` leaves the source sandbox running after publication.
`leave_running=false` stops the source workload, but its sandboxd record
remains `EXITED` and `COMMITTED` until the caller deletes it. Reusing the same
sandbox ID therefore follows this sequence:

```text
Checkpoint(leave_running=false)
  -> persist CheckpointResponse and original StartRequest
  -> Delete(source sandbox ID)
  -> Restore(deterministic target sandbox ID)
```

The caller must durably retain the complete original `StartRequest`,
checkpoint ID, artifact size, and artifact SHA-256. Restore validates all of
them before creating physical state.

## Deterministic restore and replay

The normalized StartRequest and checkpoint ID form the restore identity. The
target `sandbox_id` is mandatory.

For an identical Restore request:

- Matching `COMMITTED` record plus a `RUNNING` runtime returns the existing
  authoritative ID and port mappings without allocating or restoring again.
- Matching record plus a missing, stopped, or unknown runtime is stale. Under
  the per-target restore coordinator, sandboxd deletes only that exact runtime
  and its filesystem, device, network, port, resource, and sandbox records,
  then restores the deterministic target again.
- A different restore identity, runtime, labels, or port request fails with
  `FailedPrecondition` and does not delete the existing sandbox.
- If runtime liveness cannot be queried, Restore fails with `Unavailable`.
  Sandboxd neither returns a cached success nor starts a second runtime.

At sandboxd startup, committed restore records are checked against one runtime
`List` view per handler before ports and DNAT rules are reconstructed. Running
records are retained; stale restored records are cleaned. Ordinary committed
records without a restore identity keep their existing lifecycle semantics.

## Cleanup

`DeleteCheckpoint` accepts the checkpoint ID, source ID, size, and SHA-256. It
removes only the exact committed artifact and is idempotent after that artifact
has already been deleted. Sandbox deletion independently removes the physical
runtime and node-local resource ownership; it does not implicitly delete the
checkpoint asset.
