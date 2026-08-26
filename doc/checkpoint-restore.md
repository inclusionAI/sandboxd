# Checkpoint and restore

sandboxd supports checkpointing a running sandbox into a caller-owned
directory and starting a new sandbox from that checkpoint.

## Design

The API has two operations:

1. `SandboxService.Checkpoint` checkpoints an existing sandbox.
2. The existing `Start` RPC restores a sandbox when `checkpoint_info` is set.

There is no separate restore RPC. Restore is a form of sandbox creation, so it
uses the normal `Start` path to allocate the target sandbox's filesystem,
network, cgroup, and other resources.

sandboxd coordinates the runtime operation and cleans partial output. It does
not manage checkpoint names, catalogs, storage, transfer, retention, or
compatibility negotiation. The caller chooses the checkpoint directory and
owns a successful artifact.

`ListAvailableRuntimes` reports checkpoint/restore support for each initialized
runtime handler. A supporting runtime may also advertise guest-visible
checkpoint handoff and restore-environment paths. Callers can use this metadata
to configure cooperative workloads and reject unsupported requests early, but
the `Checkpoint` and restore `Start` RPCs remain authoritative and validate the
runtime again when they execute.

## Checkpoint API

`CheckpointRequest` contains:

| Field | Meaning |
| --- | --- |
| `id` | ID of the running source sandbox |
| `checkpoint_dir` | Absolute local directory for the checkpoint artifact |
| `timeout_seconds` | Maximum time sandboxd waits for checkpoint completion |
| `compress` | Ask the runtime to compress the checkpoint image |
| `leave_running` | Keep the source running after a successful checkpoint |

`timeout_seconds` must be greater than zero and is enforced by sandboxd.
Caller cancellation may end the operation earlier. Only one checkpoint may be
in progress for a source sandbox at a time.

`checkpoint_dir` must be absolute, must not be `/`, and must not contain
symbolic links. Its parent must already exist. The leaf may be absent, in which
case sandboxd creates it, or it may be an existing empty directory. sandboxd
never overwrites a non-empty directory.

The directory is the artifact boundary. Its contents are opaque and specific
to the runtime that created them.

Firecracker checkpoints use a sandboxd-owned, versioned tar container. Sparse
components carry private PAX metadata and are not safely extractable with stock
tar tools. The version marker makes pre-format sandboxd readers reject new
archives instead of silently materializing truncated files; current readers
continue to accept legacy dense archives.

## Source and failure semantics

`leave_running` defines only the successful result:

| Result | Source sandbox |
| --- | --- |
| Success with `leave_running=true` | Continues running |
| Success with `leave_running=false` | Is stopped by the runtime |
| Error, timeout, or cancellation | State is not guaranteed |

After a successful checkpoint with `leave_running=false`, the caller still
deletes the source through the normal sandbox API to release its metadata and
resources.

On failure, sandboxd returns an error and does not force-delete or stop the
source. A runtime may make a best-effort attempt to recover a source it paused
during checkpoint. Firecracker attempts to resume its VM and publishes an
`error` handoff so a cooperative workload can leave the checkpoint barrier.
Any recovery failure is returned together with the original checkpoint error.
Because recovery is not guaranteed, the caller must still inspect and decide
how to handle the source sandbox.

The `error` outcome means that the end-to-end checkpoint interaction failed.
It does not mean that the runtime produced no artifact bytes before the
failure; sandboxd still removes that uncommitted output before returning the
error.

sandboxd cleans partial checkpoint output: it removes a leaf directory it
created, or empties a caller-provided leaf directory while preserving it.

## Restore through Start

To restore, the caller sends a normal `StartRequest` for the target sandbox and
sets:

```text
checkpoint_info: {
  checkpoint_dir: "/absolute/path/to/checkpoint"
}
```

The caller must still provide the normal `Start` configuration, including the
runtime, root filesystem, resources, mounts, and network settings. The target
should use a new sandbox ID and receives newly allocated sandboxd resources.

If restore fails, sandboxd rolls back the partially created target. It does not
modify the source or delete the checkpoint input. After `Start` succeeds, the
target no longer depends on the checkpoint directory.

## Runtime support and compatibility

| Runtime | Checkpoint and restore |
| --- | --- |
| runsc with systrap | Supported |
| runsc with KVM | Supported |
| Firecracker | Supported |
| Kata Containers | Not supported |
| runc | Not supported |

runsc advertises `/proc/gvisor/checkpoint` as its checkpoint handoff and
`/proc/gvisor/spec_environ` as its restore environment. Firecracker provides
the equivalent guest-agent endpoints at `/run/sandboxd/checkpoint` and
`/run/sandboxd/restore-environ`. These paths are runtime-neutral transport
metadata: sandboxd does not inject or interpret application-specific
environment variables. Both checkpoint handoff endpoints return a
newline-terminated `resume`, `restore`, or `error` outcome.

The runsc handoff requires gVisor `release-20260817.0-akernel.1` or a compatible
newer build. That release always exposes both read-only files and binds each
open checkpoint descriptor to the next checkpoint generation. Firecracker
matches that generation-scoped behavior: a workload must open its FIFO before
the checkpoint. Firecracker drops `resume` and `error` when no reader subscribed
to that generation, but retains one pending `restore` until the workload
reopens the FIFO so a restore cannot be lost in the generation transition. The
bundled and E2E-tested runsc version is defined by
`third_party/runtime-versions.env`; replacing it with an older binary violates
the advertised capability contract.

Unsupported runtimes return `Unimplemented`.

A checkpoint must be restored with the same runtime and a compatible runtime
binary, machine architecture, host or guest kernel, and runtime configuration.
Compression changes only the runtime-specific artifact encoding; it does not
make an artifact portable.

Incremental checkpoints, deterministic replay, migration orchestration, and
guaranteed recovery of a source after checkpoint failure are outside this
design.
