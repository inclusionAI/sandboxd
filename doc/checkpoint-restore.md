# Checkpoint and restore

## Experimental runtime image collections

The optional `[plugin.image].management_socket` exposes immutable OCI image preparation to a trusted node runtime adapter over a private Unix socket (0700 parent, 0600 socket). It is never mounted into a sandbox. The adapter exports ROFS through an operator-owned read-only collection and registers its checked metadata with inner containerd; Docker lower content remains outside the writable checkpoint. Arbitrary sandbox host-path access is not authorized by this API.

When enabled, managed preparation, ordinary rootfs use and image mounts share OCI reference counting: deleting one rootfs cannot stop a ROFS daemon still held by another consumer. The private `/oci_mount` request requires an explicit 32-hex `owner` collection ID; anonymous service-lifetime acquires are rejected. Repeated preparation of one immutable reference for one collection is idempotent. The last collection release removes only the management acquire, preserving ordinary rootfs users. Deploy the matching runtime broker together with this Sandboxd version; older brokers that omit ownership fail before mounting. With the management socket unset, the ordinary image-service path is unchanged.

Image acquire/release serializes per reference; unrelated images do not hold a global lock across Registry or mount I/O. A waiting caller may cancel without dropping another owner's reference. Bootstrap, daemon launch and readiness share the acquire's bounded context (at most the existing 60-second preparation limit). On cancellation or timeout, preparation is joined and any launched daemon is rolled back before failure returns; a late bootstrap cannot create an unowned mount. Cleanup may extend beyond the preparation budget and cleanup errors are retained. A canceled leader does not publish a lease; live followers may retry after its rollback. Closing the management service cancels and joins its handlers before releasing service-owned leases. Snapshot durability barriers and fsync behavior are unchanged.

## Managed file-backed tmpfs

The runsc Start API accepts `extra_config` JSON with `fileBackedTmpfsMounts`, for example `{"fileBackedTmpfsMounts":[{"target":"/var/lib/akernel-image-snapshots","sizeMB":2048}]}`. Each mount uses a sandbox-owned anonymous filestore rather than guest-memory-backed file contents. This is intended for private Docker/containerd writable upper/work directories above shared read-only image roots; Dockerfiles and Compose definitions do not change.

Mount quotas are reserved from `storage_mb` and must leave a positive root filesystem quota. Targets must be canonical absolute paths and cannot overlap reserved system paths, existing mounts or other managed targets. The source directory is an empty sandbox-owned mount identity, not caller-owned writable host storage. Runtime metadata persists the opt-in so checkpoints retain the same behavior across daemon restarts even if the node default is `full`.

Checkpoints save all managed anonymous filestores with the existing reflink format and omit their file bytes from the guest memory-page stream. Restore requires the filestore manifest and clones the artifacts before adoption; source snapshots remain immutable across independent restored writers. The complete runtime bundle must support anonymous tmpfs mount hints and same-filesystem FICLONE. File backing can still incur page cache and cgroup memory charges. Guest process memory is saved separately and this feature does not implement incremental RAM snapshots. On Linux 5.10, the backing filestores and checkpoint destination must also be reached through the same mount; a second bind-mounted view can still fail FICLONE with EXDEV. Configure the checkpoint store directly beneath the filestore mount rather than binding it to a separate path, and verify a same-path clone before qualification.

The mount preparation is adapted from Tianyu Zhou's `tianyuzhou95/sandboxd` commit `4ff87a3a7779ba35b9a0b737bdf92046e35052df`; it retains the current runtime adapter, filestore validation and old-kernel parent-mount-namespace handling. This opt-in does not change unrelated sandbox checkpoint defaults.

The successful Checkpoint RPC logs `runtime_ms`, `sync_output_ms` and `total_ms` separately. With debug logging, each output synchronization emits `path`, `kind`, `logical_bytes`, `open_us`, `sync_us`, `close_us` and `total_us`, distinguishing state/page files, filestores and directories without changing synchronization order or durability. Runtime capture and the optional filesystem persistence barrier have different completion points; compare both with the runtime's own serialization/page-output timings rather than treating the whole API call as a stop-the-world interval. A file's fsync latency can include filesystem journal and lower-device flush dependencies; it does not by itself measure that file's exclusive write volume.

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

Sharing applies to writable-file extents, not the independently saved application-memory pages. Logical file lengths and ordinary summed `du` output do not measure unique physical storage when extents are shared. Measure filesystem usage and shared extents, including unlinked live filestores, when evaluating savings. Host directory bind contents remain caller-owned and are not captured or rolled back by this mechanism. The [mount override contract](runtime.md#mount-overrides) produces one effective mount per canonical destination in parent-before-child order. Restore callers must rebind the explicit external mounts with compatible type and access options; changing an explicit read-only bind to read-write, or the reverse, is not a compatible restore. Only anonymous disk-backed filestores are supported; self-overlay backing must not be used for these snapshots. Private tmpfs filestores require the matching gVisor anonymous-filestore mount hints.

Save and restore must use matching runtime builds. Drain sandboxes before replacing the runtime bundle; do not assume old saved state remains compatible across a gVisor upgrade. Install the complete checksum-pinned gVisor archive with its matching helpers, rather than replacing runsc alone.

Runsc checkpoints preserve managed `/etc/hosts` contents and existence, including empty or deleted files, without replay or regeneration for a new IP. For the writable layout, retain top-level `managed-hosts.json` and SHA-256-verified `rootfs-seed.tar` with the native checkpoint; the source sandbox may be deleted. Corrupt artifacts, incompatible layouts, checkpoint outputs overlapping the source bundle or another active output, and restore inputs overlapping the target bundle are rejected; output reservations last through cleanup. Old snapshots keep their original hosts layout; new-layout snapshots are not guaranteed to work with older sandboxd. Caller-owned mounts remain external.

## Checkpoint output synchronization

Runsc's per-execution host staging overlay first tries the Linux 5.10+ `volatile` mount option. If the kernel rejects it with `EINVAL`, preparation retries without that option for older hosts; other mount errors are returned without a compatibility retry. A failed fallback remains a preparation failure. Its upper directory holds disposable mount targets and host-hook output, is recreated for each execution, and is never a recovery artifact. Without this option, tearing down one overlay synchronizes the shared backing filesystem and can block behind other sandboxes' checkpoint writes. This does not change runsc's separate guest writable filestore or the checkpoint output synchronization below. Do not reuse a volatile staging upper directory after a host crash; normal preparation removes and recreates it.

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

`plugin.runtime.runsc.cli_gomaxprocs` separately controls the host-side runsc CLI's Go parallelism. Zero preserves the inherited environment; positive values from 1 through 1024 set its `GOMAXPROCS`. This does not increase sandbox CPU quotas, change Sentry scheduling, or change when background restore finishes. It is a node-local startup tuning option, independent of page-loading and restore-admission policies.

The following Firecracker performance and durability descriptions assume the default `sync_output=false` profile. With synchronization enabled, the server adds its barrier after the runtime completes its capture, outside the runtime's guest pause window.

## Firecracker guest wall clock

After loading a snapshot, and when resuming the continuing source after capture or a failed capture, sandboxd sends the current host Unix time over the trusted guest-agent channel. The agent sets guest `CLOCK_REALTIME` before releasing the cooperative checkpoint handoff. A missing or invalid timestamp or a failed clock update fails that handoff. This corrects wall-clock age inherited from a Golden or ordinary snapshot; it does not advance `CLOCK_MONOTONIC`, replay elapsed timers, or guarantee that arbitrary non-cooperative guest threads cannot run before synchronization. The host clock must itself be synchronized.

The guest-agent protocol is version 3. Existing checkpoint compatibility checks require the same initrd digest, so artifacts captured with the prior agent must be rebuilt, including Golden templates. No periodic time service or E2B-specific clock policy is introduced.

A continuing checkpoint still fails if its handoff request is not acknowledged. That failure does not establish whether the guest consumed the release: it may have resumed and opened the next FIFO reader before the acknowledgment was lost. Once sandboxd attempts the release, deferred cleanup does not send another outcome for that capture. Failures before the first release attempt retain the existing resume-and-error cleanup. An unacknowledged release leaves source handoff state uncertain; callers must reconcile or explicitly stop the source rather than assume either successful continuation or safe replay of an old outcome.

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

## Delete waiting and incomplete shutdown

Deleting a sandbox, including a checkpoint source or restored target, uses the normal `Delete` RPC. Calls for the same sandbox share one cleanup worker. Each RPC waiter has a default 60-second budget, including waiting for runtime deletion and synchronous host cleanup; an earlier caller deadline or cancellation ends that caller's wait sooner. Caller cancellation does not cancel the shared worker or another waiter. The worker has its own default 60-second context budget, independent of the caller. Each runtime deletion attempt is limited to 30 seconds within that worker budget; after a runtime deadline, an allocated cgroup may be drained before one retry. Joining an existing worker does not restart it or extend its context deadline.

`DeadlineExceeded` means deletion was not confirmed when that RPC returned. The worker may finish later while the daemon remains alive, so a later successful cleanup log does not contradict the earlier RPC error. An operation that ignores cancellation, including an uninterruptible kernel operation, can outlive both context budgets. The worker retains singleflight cleanup ownership until it actually returns; retries join that worker while it is still running. Once it returns an error, a later request can attempt cleanup again. A timeout is not permission to recycle resources or reuse the sandbox ID. Runtime deletion success alone does not confirm that host cleanup has finished; normal ID release is deferred until directory cleanup and exit notifications return.

Shutdown closes readiness and new `Start` admission, then attempts deletion of the currently tracked sandboxes sequentially. The 60-second waiting budget applies separately to each deletion, not to shutdown as a whole. State persistence and other shutdown work can take additional time; shutdown has no global 60-second completion guarantee.

If a deletion fails or sandboxes remain tracked, shutdown stops the sandbox manager's event processing and monitors, skips global teardown of the shared filesystem, image, network/interface, volume and ACL managers, and explicitly saves the cgroup manager's active allocations before returning. This preserves remaining state and resources that unfinished cleanup may still use; it does not undo cleanup steps that already completed. Cgroup snapshots and their database writes are serialized so an older periodic save cannot overwrite the explicit shutdown save.

If that save fails, shutdown logs the error, leaves cgroup state dirty for a possible retry, and still returns. Dirty state exists only in the current process: a later periodic flush can help only if that process remains alive and the flush succeeds. Recovery requires successfully persisted metadata and leases plus the original runtime state and backing storage. A service restart in the same Pod and host boot uses those persisted leases; [host reboot and service restart](#host-reboot-and-service-restart) describes the separate reboot rules. This path does not provide cross-Pod or cross-node recovery, create a workload checkpoint, or guarantee recovery of allocations that were never saved. A cleanup worker does not survive daemon exit; retained state must be reconciled through recovery and subsequent deletion attempts.

Already in-flight `Start` requests are not drained by this shutdown path. A request that passed admission before shutdown can still allocate resources or finish after the explicit save, and that save cannot include later allocations. Closing readiness, retaining dirty state and periodic saving do not guarantee persistence of this late state before process exit. These limits also mean that bounded RPC waiting does not force stuck kernel operations to complete or establish a fully drained shutdown.

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

### Host reboot and service restart

Sandboxd uses the Linux boot ID to distinguish a host reboot from a service restart in the same Pod. A changed boot ID retires the old kernel's cgroup and TAP lease caches before resource managers start. It preserves sandbox metadata, image-manager state, and checkpoint files for normal reconciliation; it does not resume processes, select a checkpoint, or guarantee that node-local files survive disk loss. Callers still orchestrate restore and satisfy the runtime and storage compatibility requirements above.

During the same boot, persisted leases remain authoritative and active TAP recovery continues to fail if a device is missing or has been replaced. An unstamped legacy store is adopted without clearing its leases. Unreadable boot identity, invalid persisted identity, or an unreadable lease database fails startup rather than deleting authoritative sandbox state.

An external node maintenance controller can opt in by setting `AKERNEL_REBOOT_FENCE_PATH` to an absolute path on node-local storage that survives reboot and Pod replacement. Startup rejects a fence path inside the directories it clears on Pod replacement. Sandboxd and the controller must trust each other on the node. Write access to the fence file or its parent, or the ability to connect to the mode-0600 control socket at `/run/sandboxd/reboot.sock`, confers control over node-wide admission. Without the environment variable, normal RPC admission is unchanged.

#### Maintenance fence protocol

The controller persists each attempt before sending a mutating request. The attempt is a zero-padded 20-digit Unix nanosecond timestamp, a hyphen, and 32 lowercase hexadecimal digits. Use one token for all retries and use a lexicographically newer token for each new operation on the same node.

| Request | Meaning of HTTP 204 |
| --- | --- |
| `GET /available` | The fence is open and the node can verify inventory. Missing or unhealthy configured runtimes and non-Unified cgroup modes fail preflight. |
| `PUT /close/{attempt}` | Ownership and the closed state are durable. New Start (including Restore) and Checkpoint requests return `Unavailable` while admitted work finishes. |
| `GET /drained/{attempt}` | The attempt still owns the closed fence, no admitted requests remain, and runtime inventory and cgroup v2 workload subtrees are empty. |
| `PUT /open/{attempt}` | The release is durable. Send after a verified recovery or cancellation. An open for an unused newer token can record cancellation if the close never arrived. |

HTTP 400 indicates a malformed attempt. HTTP 409 indicates conflicting state, such as another owner, a stale attempt, or work still in flight. HTTP 503 indicates unavailable verification, live workloads in inventory, or a persistence error. Drain inventory shares a five-second request budget across runtimes and does not update runtime admission health. Controllers should retry inconclusive drain checks within their own deadline and require a fresh 204 before rebooting.

Repeated close or open requests for the same state are idempotent. After a persistence error, retry with the same token and reconcile the operation before proceeding. A different token cannot release a closed fence, and a delayed close cannot reclaim a released token. If the controller loses its journal, keep the node isolated until an operator verifies node identity and the reboot outcome, then recover the original attempt from trusted state and release it through the protocol. Keep the persisted fence and its configuration in place throughout recovery.

If a crash leaves a runsc record without readable sandbox metadata, startup recovery deletes it through runsc only when it explicitly reports stopped and has no positive process ID. Tracked records and live, created, or unknown states are preserved. Runtime inspection or deletion failure closes only runsc admission and advertisement; Sandboxd startup, healthy backends, and tracked sandbox state remain available. Housekeeping retries inventory and orphan cleanup in the same bounded, single-in-flight runsc poll lane. A successful inventory alone cannot reopen runsc while orphan deletion still fails; reopening requires the entire recovery pass to succeed within its poll deadline. This does not delete caller-owned checkpoint inputs or recover their contents.

When runsc confirms a tracked instance is stopped without a positive PID, ACL recovery retires its stale binding instead of requiring the previous kernel's TAP. Its sandbox metadata is retained for the normal runtime, filesystem, and resource deletion path. Live, absent, or ambiguous state from a successful inventory keeps strict active endpoint recovery. If inventory is unavailable, ACL initialization retains the affected runsc owners without reactivating or orphan-cleaning their policy, generation, endpoint state or interface leases. Healthy backends still restore their ACLs and remain available. Runsc admission stays closed until inventory, orphan cleanup and the pending ACL restore all succeed in the same bounded poll lane; inventory success alone cannot reopen it. Recovery retries only runsc bindings, preserving other runtimes' active policies. Missing endpoint metadata for an unverified runsc owner stays quarantined until authoritative recovery; it is not permission to drop that owner. Existing ACL owners without sandbox metadata are retained during inventory failure too; a still-live untracked owner prevents runsc reopening until its ownership can be recovered. Policy updates for quarantined runsc owners return Unavailable; explicit deletion/cleanup remains available. This check uses current runtime state on every startup, including after a previous attempt advanced the boot stamp.

OCI-image mount entries own one lower ROFS acquire regardless of how many ordinary sandboxes share the entry. First acquisition and final release serialize per image, including backend I/O, while unrelated images proceed independently. With managed-image sharing enabled, this ownership composes with the managed consumers' references rather than replacing them. A failed final release, including cancellation rollback, retains retryable ownership; it must not silently drop the entry or unmount another consumer's lower.

## Writable block I/O policy

New sandboxes default to `writable_io_engine = "AsyncDirect"` and `writable_cache_type = "Writeback"` in `plugin.runtime.firecracker`. The pinned Firecracker runtime bundle includes direct-I/O alignment support. Operators using an older VMM must explicitly select `Async` or `Sync`. The writable policy applies to the private ext4 disk, including native writable mounts. It does not change EROFS root disks, virtio-fs exports, or checkpoint memory-file I/O.

The VMM persists the engine and cache policy in device state and reopens the writable disk with the saved policy on restore. Changing sandboxd's defaults affects newly created VMs; it does not override the policy captured in an existing checkpoint. Checkpoint compatibility still requires matching runtime digests. Direct-I/O alignment requirements are queried again for the restored image on its destination filesystem. Request-owned alignment buffers and in-flight I/O are completed before snapshotting; completed reads reach guest memory and dirty tracking before the device state is saved. Alignment buffers are not separate checkpoint artifacts.

The destination host must support the saved I/O engine. In particular, direct engines require the destination kernel and backing filesystem to report `STATX_DIOALIGN`, normally available for ext4 and XFS on upstream Linux 6.1 or newer; asynchronous engines also require usable `io_uring`. Restore fails when those capabilities are unavailable and never automatically changes the saved engine to buffered I/O. Operators using hosts without Direct I/O alignment-query support must explicitly configure `Async` or `Sync` before creating new sandboxes; this setting cannot make an existing Direct I/O checkpoint compatible with such a host. See [host I/O compatibility and configuration](runtime.md) for details.

#### Checkpoint timing diagnostics

The Firecracker completion log keeps `layout`, `flush`, `pause`, `snapshot`, `overlay`, `resume`, `seal` and `total` timings, and splits the `seal` interval into `manifest`, `adopt`, `persist` and `writeback_queue`. The debug log separates manifest component hashing from publication, native snapshot time from both cgroup moves, and atomic state-file creation, writing, `fsync`, closing and rename. `seal` includes instance-state persistence and queue submission; it is not a measurement of guest-memory hashing or an assurance that all checkpoint data reached stable storage. Collect these timings alongside I/O and CPU-pressure measurements before attributing nested checkpoint latency to the virtualization backend.

When profiling nested PVM, keep the VMM and its vCPU threads outside ptrace. Following sandboxd forks can otherwise perturb guest startup even with a narrow displayed syscall filter. For example, `strace -f -b execve` follows sandboxd threads but detaches children when they execute another program; verify the running Firecracker process reports `TracerPid: 0`. Record outer block-I/O limits as well as CPU/memory limits. Separate virtual disks or ext4/XFS filesystems can still share one capped backing device. Memory-backed checkpoint controls are diagnostics and do not replace persistent-storage or restore qualification.

## Managed Docker runtime collections (opt-in local preview)

An operator may configure `[plugin.managed_runtime]` with an absolute private
`root`, and named `[plugin.managed_runtime.profiles.<name>]` profiles. Each
profile specifies a digest-pinned tool `image`, `registry`, `repository_prefix`,
`registry_auth_file`, `registry_insecure`, `bootstrap_root`, `buildkit_endpoint`, `provider_url`,
`allowed_tenants` and the private upper's `writable_mb` quota. It is disabled
without an explicit profile. ADX supplies the trusted `adx.tenant_id` label;
unlisted tenants are rejected before node state is created. Clients select only
`extra_config.managedRuntimeProfile` and cannot replace reserved mounts, labels
or file-backed upper configuration.

The total writable quota must cover `writable_mb` plus `minimum_root_mb` (4096 MiB when omitted or zero). For the example 4096 MiB upper, the platform advertises an 8192 MiB minimum through ADXlet node resource labels. The SDK reserves this floor and restricts placement before creating an environment; explicit undersized requests or limits fail early. Sandboxd independently rejects a smaller total quota before creating any collection state, leaving a usable root layer rather than accepting a one-MiB remainder. Regenerate node metadata from the same profile when changing geometry.

Fresh environments acquire different opaque image collections. Sandboxd injects
read-only collection/configuration mounts into the outer sandbox and configures
the private file-backed upper. The node broker authenticates a private capability
against Sandboxd's operator-owned record. It permits immutable references under
that collection's Registry repository prefix. Docker startup flags, Registry
credentials and node paths are not part of the Harbor job or SDK handle.

Before the output durability barrier, checkpoint writes `managed-runtime.json`
containing only the collection ID, tenant and profile fingerprint. Restore
requires a matching operator profile and existing collection, otherwise it fails
closed. This file participates in the existing checkpoint directory durability
and ADX storage contract. The server does not create an empty replacement
collection on restore, and the SDK must not restart daemons/Compose services.

The compatibility fingerprint excludes `allowed_tenants`, which is checked against current policy before restore. Adding or reordering allowed tenants preserves existing authorized snapshots; revoking a tenant still denies recovery. Other captured profile fields remain part of compatibility, including tools, bootstrap and storage geometry. The earlier preview fingerprint format remains incompatible: drain its snapshots before upgrading its profile.

New collections record `lifecycle_version = 1`. A private `leases/<collection>` regular file is hard-linked by each live sandbox attempt, each in-flight capture/start operation, and the checkpoint's `.managed-runtime.lease` marker. Before invoking runtime capture, Sandboxd writes the managed descriptor and creates the actual checkpoint hard link in the requested output directory. This rejects incompatible filesystem or mount views before a non-live capture can stop the source; comparing device IDs alone is insufficient. The operation lease remains held throughout capture. Failed preflight or capture removes the output-owned descriptor and lease through normal checkpoint cleanup, while successful capture retains them with the checkpoint. A restored clone acquires a fresh attempt-specific owner before releasing its temporary start pin. Late cleanup from a failed attempt cannot release a replacement using the same sandbox ID. Deleting the original sandbox does not drop a retained checkpoint's reference; physical checkpoint removal releases its own link. Restore verifies the marker's inode identity and fails closed on a missing or copied marker instead of recreating a lease.

The node broker and Sandboxd use an exclusive `flock` on the same anchor to serialize privileged image preparation with retirement. After the last reference disappears, the node collector fences new operations, drains existing operations, unmounts only the collection's validated digest exports, releases its management references, and removes private metadata/credentials. It reads mount metadata without traversing ROFS. A partial cleanup failure retains its retirement fence for retry. Service recovery reconciles persisted live owners and local checkpoint links before admitting starts, reacquires retained image references, and refuses to replace a stale export used by a live sandbox. Unknown legacy collections have no provable lease history and remain pinned until an operator drain; upgrading does not automatically discard them.

This is a same-node, local-filesystem contract. Collection lease anchors and checkpoint output must support hard links through the same local filesystem and mount view; a second bind-mounted view may return `EXDEV`. Exported/copied/S3 checkpoints and cross-node reconstruction are unsupported for versioned managed collections. Collection retention intentionally keeps the referenced ROFS resources alive, so operators must budget both live environments and retained managed checkpoints. Releasing a local mount never authorizes deleting its immutable Registry artifact. Per-tenant credential issuance/revocation and Registry artifact GC remain separate release work.
The private Registry may use standard scoped Bearer tokens with separate build-publisher and node pull-only accounts. Shared profile accounts are not a production tenant boundary.

The node-private Registry metadata endpoint uses the image manager's own keychain and standard Registry Bearer challenge/refresh client. Runtime brokers receive bounded digest-verified metadata bytes, not Registry credentials, and retain their collection prefix authorization check before requesting metadata. Operators should separate the build publisher account from the node's pull-only account. Registry tokens are short-lived access credentials; neither their expiry nor a refreshed token replaces the snapshot's immutable image dependency or collection retention contract.

Managed profile Registry transport is operator-owned and keyed by the complete Registry authority (including port). `registry_insecure = true` selects HTTP consistently for metadata, Nydus detection/bootstrap acquisition, the actual ROFS backend and OCI fallback. Explicit `false` selects HTTPS even for private-IP/loopback authorities; it cannot be downgraded by a caller's insecure hint or the registry library's automatic HTTP fallback. Both choices are enforced at the shared client transport boundary, including lazy content reads and proxy-to-origin retries. The shared image client receives this policy at startup; guest API requests cannot change it. Profiles sharing an authority must agree on transport. Unconfigured registries retain existing behavior, including the registry library's HTTPS default for ordinary hostnames and its historical private-IP/loopback handling. A successful literal-IP smoke therefore does not qualify hostname transport; `make managed-registry-test` exercises a non-loopback hostname through a real local Registry, management Unix API, layer extraction and kernel mount in a private mount namespace. The normal storage CI job runs this regression. A profile/transport change still requires final-candidate managed checkpoint/source-deletion/restore qualification.
