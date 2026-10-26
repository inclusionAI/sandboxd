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

## Runsc filestore checkpoints

Runsc normally serializes application memory and writable-layer pages into its checkpoint files. Set the node-owned `[plugin.runtime.runsc] checkpoint_mode = "reflink"` to capture writable filestores with the matching gVisor bundle's `FICLONE` support instead. An unset mode or `"full"` preserves page serialization; unknown modes fail runtime initialization. This setting does not change the meaning of `snapshot_type`, which runsc ignores, or enable dirty-page incremental application-memory checkpoints.

Reflink mode passes `--skip-filestore-pages` and `--filestore-snapshot-dir=<checkpoint_dir>/filestores`. Runsc clones the backing files inside its freeze window, including for `leave_running=true`, and commits a `filestores/filestores.json` manifest. Keep this entire directory together with `checkpoint.img` and any split page files. Each checkpoint requires its own fresh directory. The live filestores and the checkpoint destination must be on the same reflink-capable filesystem, such as XFS with reflink enabled. Cross-device clones and unsupported filesystems fail; sandboxd does not silently fall back after beginning a reflink checkpoint.

Fresh sandboxes in reflink mode also receive `--filestore-parent-mountns=true`, so anonymous backing files and later checkpoint destinations reference the same launcher mount. This avoids older kernels' `EXDEV` rejection of reflinks between namespace copies of the same filesystem. The matching runtime bundle must provide this option. It pins the backing mount while the sandbox holds its filestore descriptors, so drain sandboxes before unmounting or replacing the node's filestore. An already running sandbox created in full mode keeps its original backing descriptors; recreate it before enabling reflink mode.

Restore detects this artifact layout independently of the current save mode. Before the existing Restore control RPC, sandboxd passes the artifact directory and `--filestore-clone-on-adopt=true` to `runsc create`. Each target adopts a private, immediately unlinked CoW copy; it never consumes or mutates the saved filestores. The caller can reuse the checkpoint. Restored filestores use private copies after restoration, but checkpoint memory-image and split-page files must remain available while background page loading can access them. Runsc verifies mount identities, sizes and sampled fingerprints. Sandboxd rejects partial manifests, symlinks and artifact names that escape the checkpoint directory. Checkpoints without the filestores directory retain the legacy restore path.

Sharing applies to writable-file extents, not the independently saved application-memory pages. Logical file lengths and ordinary summed `du` output do not measure unique physical storage when extents are shared. Measure filesystem usage and shared extents, including unlinked live filestores, when evaluating savings. Host directory bind contents remain caller-owned and are not captured or rolled back by this mechanism. Only anonymous disk-backed filestores are supported; self-overlay backing must not be used for these snapshots. Private tmpfs filestores require the matching gVisor anonymous-filestore mount hints.

Concurrent runsc restore holds the loader lock while loading kernel state. The pinned gVisor bundle returns a temporary state-query error while that lock is busy, allowing inventory to use its existing process-liveness check and retain the last known container status. A restoring sandbox therefore does not stall node-wide inventory or become dead solely because this state query is busy. Runtime availability checks and checkpoint/restore timeouts remain enforced.

Save and restore must use matching runtime builds. Drain sandboxes before replacing the runtime bundle; do not assume old saved state remains compatible across a gVisor upgrade. Install the complete checksum-pinned gVisor archive with its matching helpers, rather than replacing runsc alone.

## Checkpoint output synchronization

Runsc's per-execution host staging overlay uses the Linux 5.10+ `volatile` mount option. Its upper directory holds disposable mount targets and host-hook output, is recreated for each execution, and is never a recovery artifact. Without this option, tearing down one overlay synchronizes the shared backing filesystem and can block behind other sandboxes' checkpoint writes. This does not change runsc's separate guest writable filestore or the checkpoint output synchronization below. Do not reuse a volatile staging upper directory after a host crash; normal preparation removes and recreates it.

`plugin.runtime.checkpoint_sync.sync_output` defaults to `false`, preserving the existing page-cache completion contract. Set it to `true` when successful checkpoint publication must include the backing filesystem's synchronization guarantee:

```toml
[plugin.runtime.checkpoint_sync]
sync_output = true
```

The server synchronizes every regular file and directory, including the capture root's parent directory entry, after the runtime finishes capture and before acknowledging the Checkpoint RPC. In runsc reflink mode this includes the cloned files and manifest under `filestores/`. Symlinks and special files are rejected. A synchronization failure fails the RPC and cleans partial output without deleting the source sandbox; it does not roll back the runtime's checkpoint operation, so callers must reconcile source state. The request deadline and cancellation are checked between filesystem operations; an in-flight operating-system `fsync` cannot be interrupted. This option relies on the configured filesystem's persistence contract and does not configure storage replication.

## runsc background restore

`plugin.runtime.runsc.restore_concurrency` optionally limits concurrent runsc restore `Start` RPCs per sandboxd process. Omitted or zero disables this concurrency limit; only an explicitly configured positive value enables it, and valid positive values are between 1 and 1024. When enabled, the permit covers filesystem/image preparation and the runtime restore call, and is acquired before sandbox ID or resource reservation. Requests queue within their existing deadline; cancellation while queued does not create a sandbox. Cold starts, cleanup, and other runtimes do not use this limit. Background page loading can continue after `Start` returns, so this bounds active restore RPCs rather than promising that all background I/O has finished.

If a runsc inventory poll temporarily closes backend admission, a restore waits for a successful poll within the same caller deadline instead of immediately failing the accepted request. This health wait applies even when the concurrency limit is disabled. Runtime advertisement stays withdrawn while the poll is unavailable; the wait never substitutes an empty inventory or reopens health itself. Each admission wait from a caller without a deadline is bounded to one minute. Runtime inventory timeouts, actual backend validation, ownership checks, and cleanup remain enforced.

`plugin.runtime.runsc.background_restore` defaults to `false`. Setting it to `true` forwards runsc's background page-loading option through the Restore RPC. Restore can then return before the entire memory image has been loaded. Callers must retain immutable checkpoint inputs while the runtime can still access them and measure full memory availability separately from RPC completion. This setting does not change checkpoint publication or output synchronization. It is independent of `checkpoint_mode`: full and reflink checkpoints both support this option. Private restored filestore copies do not release the memory-image and split-page inputs needed by background loading.

The following Firecracker performance and durability descriptions assume the default `sync_output=false` profile. With synchronization enabled, the server adds its barrier after the runtime completes its capture, outside the runtime's guest pause window.

## Firecracker artifacts and incremental checkpoints

The Firecracker runtime writes *uncompressed* checkpoint directories (layout
version 2): `manifest.json` plus the `vmstate`, `memory`, and `overlay.ext4`
components. A VM with virtio-fs also carries `virtiofs.state`. The manifest is
written last as the logical commit marker: under
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

Runsc ignores this field; its optional filestore reflink mode is selected by node configuration instead.

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

The manifest digests the small VM state and optional virtiofsd state
components. Hashing the memory file
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
binary, guest kernel, and initrd, plus architecture and kernel arguments. A
virtio-fs checkpoint additionally records the virtiofsd digest. Values are
computed once per sandboxd process. A restore compares the tuple against its
own stack and refuses on a mismatch, naming the conflicting field. Manifests
without a tuple (artifacts from before the tuple existed) restore without stack
verification.

#### KVM backend identity

The `compat` tuple records the probed `backend` (`"pvm"` or `"kvm"`) and, on x86-64, `tsc_frequency_khz`. At daemon startup, `KVM_GET_MSR_INDEX_LIST` on the system-wide `/dev/kvm` fd distinguishes PVM using `MSR_PVM_VCPU_STRUCT` (0x4b564df1). A failed x86 backend probe prevents registration. The `firecracker` runtime requires hardware KVM, while the opt-in `firecracker-pvm` runtime requires PVM and reads `[plugin.runtime.firecracker_pvm]`. PVM is rejected on non-x86 builds; hardware KVM preserves its non-x86 behavior without using x86 MSR or TSC ioctls.

Cross-backend restores fail before starting the VMM. PVM vmstate carries backend-specific event-delivery MSRs that hardware KVM rejects at `KVM_SET_MSRS`; hardware-KVM state lacks those PVM MSRs. The gate reports an incompatibility instead of exposing a late partial MSR write failure. Daemon recovery also checks each bundle's `runtime.json`: a handler adopts only its runtime variant, and only the hardware-KVM handler retains support for legacy bundles without a marker.

Legacy checkpoint artifacts without a backend tag, including v1 archives without a manifest or a v2 manifest without `compat`, follow an asymmetric policy:

- Hardware-KVM nodes retain legacy restore behavior. Operators must confirm provenance: old experimental PVM checkpoints are also untagged and can still fail on hardware KVM.
- PVM nodes refuse artifacts whose backend cannot be verified. Produce a new checkpoint using the PVM runtime instead of relabeling an old manifest.

The tested PVM backend reports `KVM_CAP_TSC_CONTROL=0`. Registering PVM requires successful capability and non-zero frequency probes; restoring on PVM requires a recorded non-zero frequency equal to the target's frequency. Unknown or different frequencies fail compatibility verification before starting the VMM. Hardware KVM retains legacy handling for missing frequencies and lets Firecracker apply supported scaling. These checks do not establish heterogeneous CPU migration support; qualify CPU compatibility separately and use the identical VMM, kernel, initrd and virtiofsd stack as the baseline.

The opt-in strict-TSC guest candidate improves kernel clock and timer recovery when a same-frequency PVM TSC offset changes, but it does not preserve raw RDTSC/RDTSCP continuity or provide TSC scaling. Continue to validate the entire compatibility tuple. A different guest digest or `pvm_tsc` kernel argument is incompatible with an existing checkpoint; retain the original stack or recreate workloads. PVM bundles built from the older guest source remain limited to the same host/L1 boot and TSC domain until a separately qualified strict-TSC PVM bundle is selected.

Fresh Firecracker starts share a 15-second deadline across VMM API readiness, VM configuration, guest-agent health checks and guest configuration. Startup logs report these phases separately. If the VMM exits during a fresh start or restore, sandboxd cancels readiness and configuration I/O and reports the VMM exit status without waiting for the agent deadline. A failed health check preserves the attempt count and last connection or protocol error; a boot failure also records the available regular-file console tails before cleanup. Empty output paths still discard the console, so configure per-VM stdout and stderr files when collecting boot evidence. An expired or canceled context always fails an unsent guest-agent request, including the interval before the context timer publishes its deadline error.

### Storage layout for high-performance Firecracker checkpoints

Firecracker memory and the writable block image are separate checkpoint
components. Firecracker writes or patches `memory`; sandboxd snapshots the
live `overlay.ext4` into the artifact. A conventional restore maps the
artifact's `memory` file privately. A virtio-fs restore first reflink-clones it
to a sandbox-owned `memory.live` file (or copies it when reflink is unavailable)
and maps only that live file writable and shared, because virtiofsd must write
guest buffers directly. The committed checkpoint memory is never mapped
writable. Restore also clones `overlay.ext4` into a new sandbox-owned writable
image. Checkpoint components must not become live writable state: the source
may keep running, and concurrent restores require independent layers.

For a virtio-fs checkpoint, Firecracker keeps `VHOST_F_LOG_ALL` armed for the
device lifetime. While the VM is paused it stops and drains both queues,
serializes virtiofsd into `virtiofs.state`, collects the shared vhost dirty
bitmap, and includes those guest-memory ranges in every snapshot flavor before
re-enabling the queues. Restore requires the same virtio-fs/non-virtio-fs
storage layout, starts a replacement virtiofsd over the newly prepared
exports with their requested access modes, loads its sidecar before enabling queues, and resumes the
guest only after the device and memory state agree.

Writable host directory mounts are external, caller-owned state. Local restore requires the same mount layout and access modes and the original backing directories and referenced files. The checkpoint does not copy, roll back, or retain their contents; sandbox deletion only tears down the export and does not delete the source. Keep those files available for as long as checkpoints may need them. Restoring into an empty replacement directory, automatically creating new log segments, and cross-node migration of writable host directories are not supported. For append logs, use `O_APPEND`; ordinary writes retain the saved offset and can overwrite data written after the checkpoint. Replayed application execution can produce duplicate logs even with append mode. The virtiofsd export uses its default write-through policy, not `--writeback`.

Firecracker native writable mounts do not add checkpoint components. Their
directories reside in the same `overlay.ext4` as the root overlay's upper and
work directories, while the VM snapshot preserves the guest bind mounts. A
checkpoint and restore therefore carries their data and mount state through
the existing `overlay.ext4`, `memory`, and `vmstate` artifacts and applies the
same quota, clone, durability, and storage-placement behavior.

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

On cgroup-v1 hosts, source deletion removes each physical controller hierarchy once, including when controllers such as `net_cls` and `net_prio` share a mount. Already removed controller paths are skipped on retry, while the cgroup library still rejects removal of groups containing live processes. This prevents partial controller cleanup from leaving stale memory-controller entries that break later daemon recovery when their `pids.max` is absent.

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
directory — with one exception: a Firecracker v2 restore keeps the artifact's
`memory` file as its tier-2 incremental base. A conventional restore also maps
that file privately; a virtio-fs restore maps an independent shared live clone.
The caller must keep the checkpoint directory intact until the restored
sandbox exits or establishes a later complete checkpoint generation.

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

## Writable block I/O policy

New sandboxes default to `writable_io_engine = "AsyncDirect"` and `writable_cache_type = "Writeback"` in `plugin.runtime.firecracker`. The pinned Firecracker runtime bundle includes direct-I/O alignment support. Operators using an older VMM must explicitly select `Async` or `Sync`. The writable policy applies to the private ext4 disk, including native writable mounts. It does not change EROFS root disks, virtio-fs exports, or checkpoint memory-file I/O.

The VMM persists the engine and cache policy in device state and reopens the writable disk with the saved policy on restore. Changing sandboxd's defaults affects newly created VMs; it does not override the policy captured in an existing checkpoint. Checkpoint compatibility still requires matching runtime digests. Direct-I/O alignment requirements are queried again for the restored image on its destination filesystem. Request-owned alignment buffers and in-flight I/O are completed before snapshotting; completed reads reach guest memory and dirty tracking before the device state is saved. Alignment buffers are not separate checkpoint artifacts.

The destination host must support the saved I/O engine. In particular, direct engines require the destination kernel and backing filesystem to report `STATX_DIOALIGN`, normally available for ext4 and XFS on upstream Linux 6.1 or newer; asynchronous engines also require usable `io_uring`. Restore fails when those capabilities are unavailable and never automatically changes the saved engine to buffered I/O. Operators using hosts without Direct I/O alignment-query support must explicitly configure `Async` or `Sync` before creating new sandboxes; this setting cannot make an existing Direct I/O checkpoint compatible with such a host. See [host I/O compatibility and configuration](runtime.md) for details.

#### Checkpoint timing diagnostics

The Firecracker completion log keeps `layout`, `flush`, `pause`, `snapshot`, `overlay`, `resume`, `seal` and `total` timings, and splits the `seal` interval into `manifest`, `adopt`, `persist` and `writeback_queue`. The debug log separates manifest component hashing from publication, native snapshot time from both cgroup moves, and atomic state-file creation, writing, `fsync`, closing and rename. `seal` includes instance-state persistence and queue submission; it is not a measurement of guest-memory hashing or an assurance that all checkpoint data reached stable storage. Collect these timings alongside I/O and CPU-pressure measurements before attributing nested checkpoint latency to the virtualization backend.

When profiling nested PVM, keep the VMM and its vCPU threads outside ptrace. Following sandboxd forks can otherwise perturb guest startup even with a narrow displayed syscall filter. For example, `strace -f -b execve` follows sandboxd threads but detaches children when they execute another program; verify the running Firecracker process reports `TracerPid: 0`. Record outer block-I/O limits as well as CPU/memory limits. Separate virtual disks or ext4/XFS filesystems can still share one capped backing device. Memory-backed checkpoint controls are diagnostics and do not replace persistent-storage or restore qualification.
