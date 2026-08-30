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
| `snapshot_type` | Checkpoint flavor: empty (automatic), `Full`, `Incremental`, or `SoftDirty` |

`timeout_seconds` must be greater than zero and is enforced by sandboxd.
Caller cancellation may end the operation earlier. Only one checkpoint may be
in progress for a source sandbox at a time.

`checkpoint_dir` must be absolute, must not be `/`, and must not contain
symbolic links. Its parent must already exist. The leaf may be absent, in which
case sandboxd creates it, or it may be an existing empty directory. sandboxd
never overwrites a non-empty directory.

The directory is the artifact boundary. Its contents are opaque and specific
to the runtime that created them.

## Firecracker artifacts and incremental checkpoints

The Firecracker runtime writes *uncompressed* checkpoint directories (layout
version 2): `manifest.json` plus the `vmstate`, `memory`, and `overlay.ext4`
components. The manifest is written last as the logical commit marker: under
normal same-boot operation, a directory that shows a manifest is complete; a
directory without one is partial output that sandboxd cleans up. The memory
file stays a plain file that Firecracker
patches in place — the layout deliberately avoids archiving or compression so
reflink sharing and incremental writes survive. `compress` has no effect on
this layout (it only applies to legacy artifacts). Legacy single-file
`checkpoint.img` archives can still be restored but are no longer written.

With `checkpoint_mode = "incremental"`, repeated checkpoints of the same
running sandbox clone the previous generation's memory (a copy-on-write
reflink when both directories share a reflink-capable filesystem) and
Firecracker rewrites only the pages that changed, both into the artifact and
on disk. The default `checkpoint_mode = "full"` writes the complete memory
file for every generation. Each generation is still a complete, independently
restorable artifact; incremental mode affects only how much host work and disk
space a generation costs.

For the low-latency path, put the live Firecracker writable layer and the
checkpoint root on the same native XFS filesystem with reflink enabled. A
cross-filesystem or non-reflink layout falls back to copying large files. A
`Full` baseline also dirties one guest-memory-sized file. After committing a
generation, sandboxd asynchronously asks Linux to start writeback for its
memory file without waiting for completion. Normal periodic checkpointing lets
that I/O overlap the interval between generations, so a later XFS reflink does
not usually inherit the previous checkpoint's buffered-I/O debt. An immediately
following generation can still catch writeback in progress and wait. Do not add
an fsync to the checkpoint RPC to hide this cost, because that only moves the
same wait into the request path.

Consecutive generations must use distinct `checkpoint_dir` values — sandboxd
refuses to overwrite a directory that already holds a checkpoint. The
incremental chain references the latest artifact's memory file directly, so a
caller that deletes or mutates the most recent checkpoint directory invalidates
the lineage: the next checkpoint takes a `Full` snapshot (see the lineage-loss
rules below); deleting older generations is always safe.

Checkpoint completion deliberately uses host page-cache semantics. Every
Firecracker snapshot request carries `deferred_sync: true`: Firecracker returns
after buffered writes, and sandboxd does not fsync the memory, state, overlay,
manifest, or checkpoint directory. After the manifest is committed and the
incremental base is adopted, a bounded sandboxd worker issues
`sync_file_range(SYNC_FILE_RANGE_WRITE)` for the memory file. This starts Linux
writeback but does not wait for I/O completion and does not strengthen the
artifact's durability contract.

On cgroup v2, sandboxd keeps snapshot page-cache charges out of the sandbox
cgroup without changing its memory limit. A container's cgroup namespace root
can still be a non-root domain cgroup in the host hierarchy, so moving a process
there can fail the no-internal-process constraint. Instead, sandboxd creates a
persistent, unbounded `sandboxd-firecracker-checkpoint` leaf directly below the
namespace root. After pausing the guest and cloning the overlay, sandboxd moves
the whole Firecracker process to that leaf only for the native snapshot request,
moves it back to the original sandbox cgroup, and only then resumes the guest.
Existing guest anonymous memory keeps its original sandbox charge while new
snapshot page cache is charged to the shared leaf. The leaf accepts concurrent
checkpoint writers and remains available across operations; its page cache is
reclaimable under normal host memory pressure. If the move back fails, sandboxd
leaves the guest paused and terminates the VMM rather than running workload
threads outside the sandbox cgroup.

Restore does not use that paused-snapshot window and still reserves transient
node memory, raises the target VMM cgroup limit, and retains the raised limit
for the sandbox lifetime. cgroup v1 and hybrid deployments also retain the
headroom fallback for checkpoint. None of these host accounting choices
changes the guest memory size, which remains fixed by the microVM
configuration. Operators must leave enough host capacity for VMM overhead,
restores, and reclaimable checkpoint page cache.

A successful checkpoint therefore means the generation is logically complete
and available for restore; it does **not** promise immediate power-loss
durability. `close(2)` does not surface delayed writeback failures, so an abrupt
host loss or a later `ENOSPC`/`EIO` can make the newest generation incomplete
even though the RPC succeeded. A caller that requires a durable external
artifact must establish that durability outside the checkpoint RPC.

Inside the pause window the overlay reflink clone happens **before** the
snapshot request: cloning first runs with a page cache that does not yet hold
the snapshot's dirty writeback (an overlay clone after the snapshot was
measured stalling for seconds behind that writeback). The clone deliberately
carries no fsync because it can wait behind dirty writeback on the same
filesystem. On cgroup v2 the pause window is therefore pause → overlay clone →
move VMM to the shared checkpoint leaf → snapshot writes → move VMM back →
resume, with no fsync on the path. The manifest remains the logical commit
point: a generation without a manifest is partial output.

A sandboxd crash between resume and manifest publication discards the newest
generation and restores from the previous one. This is sound because every
generation writes into a fresh clone and never mutates its base. Firecracker
re-arms its soft-dirty window before manifest publication, so writes the guest
performed during that gap belong to the generation discarded with the
artifact; checkpoint success is reported only after the manifest is published.

`snapshot_type` is a Firecracker-specific control, gated by
`checkpoint_mode` (`plugin.runtime.firecracker`):

- **`checkpoint_mode = "full"` (default, and the meaning of an unset value):**
  every generation is a `Full` snapshot. An empty `snapshot_type` selects
  `Full`; an explicit `Full` is allowed; an explicit `SoftDirty` or
  `Incremental` is rejected with a configuration error rather than silently
  reinterpreted. An unknown `checkpoint_mode` value fails sandboxd startup.
- **`checkpoint_mode = "incremental"`** (requires a fork VMM with the
  incremental snapshot API): an empty `snapshot_type` keeps the automatic
  tier selection (a pagemap `Incremental` generation against the memory file
  a restore loaded, `SoftDirty` windows against a previous checkpoint
  afterwards, and a `Full` baseline on a sandbox that never checkpointed).
  An explicit `Full` drops the lineage for one generation and
  has Firecracker write the whole memory file. An explicit `Incremental`
  requires the restore-established pagemap base and fails otherwise. An
  explicit `SoftDirty` requires a usable base.

Runtimes without incremental checkpoints (runsc) ignore the field.

Lineage-loss rules: the VMM keeps its soft-dirty ledger in process memory, and
an armed ledger writes only the window delta regardless of which base sandboxd
holds. Whenever sandboxd can no longer prove that its base is the one the
ledger tracks — a checkpoint failed after the VMM wrote and re-armed (snapshot
or seal error), the recorded base drifted or was
deleted, or the sandboxd daemon restarted — the lineage is marked lost and the
next checkpoint takes a `Full` snapshot. `Full` ignores the ledger and writes
the complete memory image; the window re-opens only after that write, so
subsequent deltas patch onto the `Full` artifact as a safe superset. Explicit
`SoftDirty`/`Incremental` requests fail while the lineage is lost (take a
`Full` checkpoint first); automatic selection picks `Full` on its own. A daemon
restart always marks the lineage lost for surviving sandboxes: the restart
cannot tell which generation the surviving VMM is armed against, so the
cheapest provably-safe recovery is one `Full` checkpoint per sandbox.

The manifest digests only the small VM state component. Hashing the memory file
or `overlay.ext4` is skipped because it costs seconds of CPU and page-cache
reads per GiB and would dominate checkpoint latency. Their local integrity
rests on reflink copy-on-write and Firecracker's own writes. Restores skip
components without a recorded digest. Digests are computed from the
page-cache-visible contents before manifest publication, so the manifest
attests the logical generation rather than stable-storage durability. On
restore the verification is memoized per sandboxd process: a component whose
size and mtime are unchanged since a previous successful verification is not re-hashed,
so warm starts from a stable template directory skip the cost. The tradeoff is
that a content swap which preserves both size and mtime within the filesystem's
timestamp granularity goes undetected — the same granularity the nydus
bootstrap cache accepts.

The manifest also records a `compat` tuple — sha256 digests of the Firecracker
binary, guest kernel, and initrd, plus architecture and kernel arguments —
computed once per sandboxd process. A restore compares the tuple against its
own stack and refuses on a mismatch, naming the conflicting field. Manifests
without a tuple (artifacts from before the tuple existed) restore without
stack verification.

### Storage layout for high-performance Firecracker checkpoints

Firecracker memory and the writable block image are separate checkpoint
components. Firecracker writes or patches `memory`; sandboxd snapshots the
live `overlay.ext4` into the artifact. Restore maps the artifact's `memory`
file in place and clones `overlay.ext4` into a new sandbox-owned writable
image. The artifact overlay must not be used as the restored VM's writable
image: checkpoint generations are immutable, the source may keep running, and
concurrent restores require independent writable layers.

sandboxd uses `FICLONE` for these copies when possible:

- the live writable image under
  `plugin.runtime.filestore_dir/.firecracker` to the checkpoint overlay;
- one checkpoint memory generation to the next incremental generation; and
- the checkpoint overlay to the restored sandbox's writable image.

All source and destination paths must therefore be on the **same
reflink-capable filesystem** for the complete fast path. XFS with reflink
enabled and Btrfs are supported examples. Sharing a block device is not
sufficient if the paths are in different mounted filesystems: `FICLONE`
returns `EXDEV` across filesystem boundaries. The caller should allocate
`checkpoint_dir` below the same filesystem as `filestore_dir`, but outside
the runtime-owned `.firecracker` directory. For example:

```toml
[plugin.runtime]
filestore_dir = "/var/lib/sandboxd-storage/filestore"
filestore_xfs_enabled = true
filestore_dir_size = "200G"

[plugin.runtime.firecracker]
checkpoint_mode = "incremental"
```

The caller can then allocate checkpoint directories below a separately
managed path such as
`/var/lib/sandboxd-storage/filestore/checkpoints/<checkpoint-id>`. The
checkpoint manager remains responsible for retention, quotas, and reserving
enough capacity so artifacts cannot exhaust the writable-storage filestore.
Do not place caller-owned artifacts below `.firecracker`, which sandboxd owns
as live runtime state.

Verify the deployed paths, not just the configuration text: check that the
live overlay and checkpoint root report the same filesystem/device, and run a
small `FICLONE` probe between them. A loop-mounted ext4 filestore and a
checkpoint directory on the host filesystem do not qualify, even when both
are backed by the same physical disk.

If reflink is unavailable, sandboxd preserves correctness by falling back to
a full file copy. That path is not a performance configuration. In
particular, the current fallback is not sparse-extent-aware and may
materialize holes in a sparse ext4 image, turning a cheap writable-layer
snapshot into I/O and disk usage proportional to its virtual size. The
restored writable image is live runtime state rather than a durable artifact,
so neither the reflink nor fallback path fsyncs it before starting the VM.
FICLONE or copy completion makes the contents available immediately; normal
writeback handles persistence outside restore latency. Operators should treat
an unexpected fallback as a deployment problem and monitor checkpoint
latency and physical artifact usage for evidence of it.

`checkpoint_mode = "incremental"` is the other half of the fast path. It
allows later generations to reflink the previous memory image and patch only
changed pages. A first checkpoint, an explicit `Full`, or recovery after
lineage loss still writes all guest memory. Consequently, even a correctly
configured reflink filesystem cannot make a Full memory snapshot independent
of VM memory size or backing-device throughput.

These performance settings do not change durability semantics. Checkpoint
completion remains logical and does not fsync the artifact. A caller that
needs power-loss durability or remote persistence must establish it after the
checkpoint RPC, without adding archive, compression, hashing, or synchronous
copy work back to sandboxd's pause path.

The caller should also avoid synchronously fsyncing the checkpoint root as
part of an otherwise local metadata commit. Firecracker uses
`deferred_sync=true`; on filesystems with outstanding snapshot writes, a
directory fsync immediately after renaming the staging directory can wait for
that writeback and reintroduce a memory-size-dependent tail. Keep the rename
and logical metadata commit on the request path, and perform any stronger
durability work asynchronously or in the remote publication layer.

### Guest flush before pause

Before pausing the source for a checkpoint, sandboxd asks the guest agent (over
the existing vsock control channel, protocol message type 8) to `sync()` its
writable layer, so the cloned `overlay.ext4` captures guest-buffered writes
instead of a crash-consistent mix. The request is best-effort with a bounded
budget (2 seconds): on timeout, transport error, or a guest agent that
predates the message, the checkpoint proceeds without the flush and stays
crash-consistent. The flush happens while the guest is still running, so a
successful flush adds to the checkpoint's wall time but not to the pause
window. The message never fails a checkpoint.

After the flush, sandboxd also asks the guest agent to drop its page caches
(protocol message type 9) with the same best-effort contract: cached file
pages are re-materialized by block DMA on every re-read, which re-dirties
them in the host ledger and drags them into each snapshot window, so dropping
the caches right before the pause shrinks the set a checkpoint carries. A
guest agent that predates the message declines it and the checkpoint
proceeds.

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

On failure, sandboxd returns an error and does not force-delete, stop, or
resume the source. The caller decides how to handle the source sandbox.
sandboxd only cleans partial checkpoint output: it removes a leaf directory it
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
modify the source or delete the checkpoint input.

After `Start` succeeds, the target no longer depends on the checkpoint
directory — with one exception: restoring a Firecracker v2 directory keeps the
artifact's `memory` file mapped into the restored VM, so the caller must keep
the checkpoint directory intact until the restored sandbox exits. The next
checkpoint of the restored sandbox also diffs against that memory file
(the tier-2 base below).

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
environment variables.

Unsupported runtimes return `Unimplemented`.

A checkpoint must be restored with the same runtime and a compatible runtime
binary, machine architecture, host or guest kernel, and runtime configuration.
Compression changes only the runtime-specific artifact encoding; it does not
make an artifact portable.

Incremental checkpoint scheduling (which generations a caller takes and when),
deterministic replay, migration orchestration, and automatic recovery of a
source after checkpoint failure are outside this design.
