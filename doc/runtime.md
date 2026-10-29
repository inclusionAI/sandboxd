# Sandbox runtimes

sandboxd supports runsc, runc, Kata Containers, and Firecracker. Runsc is the
default. Optional runtimes are advertised only after their configured
binaries, boot artifacts, and host prerequisites pass validation.

## Comparison

| Capability | runsc | runc | Kata Containers | Firecracker |
| --- | --- | --- | --- | --- |
| Kernel boundary | gVisor user-space kernel | Host Linux kernel | Dedicated guest kernel in a lightweight VM | Dedicated guest kernel in a microVM |
| Host requirements | Tested runsc binary; `/dev/kvm` when the KVM platform is selected | runc and runc-shim; writable cgroups, overlayfs, EROFS, and loop devices | Kata runtime and configuration with usable `/dev/kvm` | Firecracker, compatible kernel and initrd, `/dev/kvm`, `mkfs.ext4`, and virtiofsd when directory sharing is enabled |
| Network lifecycle | Reusable TAP from the interface pool | New netns and veth per sandbox, deleted on release | Reusable TAP from the interface pool | Reusable TAP from the interface pool |
| Root filesystem | Directory or EROFS | Directory or EROFS with a host overlay | Directory or EROFS passed into the VM | Immutable EROFS drive or opt-in virtio-fs directory, plus a private ext4 overlay |
| Read-only mounts | Bind, EROFS, and runtime-supported OCI mounts | Bind, EROFS, and OCI mounts | Bind, EROFS, and runtime-supported OCI mounts | EROFS drives, virtio-fs directories, and bounded regular-file injection |
| Writable host directory mounts | Supported | Supported | Supported | Explicit `rw` binds through virtio-fs; caller-owned data |
| Exec, interactive TTY, wait, stats, and recovery | Supported | Supported | Supported | Supported |
| Network ACL and managed DNS | Supported | Not supported | Supported | Supported |
| Published-port DNAT | Supported | Supported | Supported | Supported |
| Writable-layer quota | Supported | Not supported | Not supported | Supported |
| Checkpoint and restore | Supported (systrap and KVM) | Not supported | Not supported | Supported |
| NVIDIA GPU | Experimental nvproxy support | Not supported | Not supported | Not supported |
| Cgroup-disabled mode | Experimental | Not supported | Not supported | Not supported |
| KVM | Optional execution platform; not exposed to the sandbox | Optional guest exposure | Required by the runtime | Required by the runtime; nested KVM is not exposed |

See [Checkpoint and restore](checkpoint-restore.md) for the API design,
artifact ownership, failure semantics, and compatibility requirements.

## Selection and configuration

A start request selects a runtime by name. Each adapter must have an entry
under `plugin.runtime.runtime_binary`. Runsc uses systrap by default. Select
the KVM platform node-wide only on a host with usable nested or hardware
virtualization:

```toml
[plugin.runtime.runsc]
platform = "kvm"
```

The only accepted values are `systrap` and `kvm`; omitting the setting selects `systrap`. Runc additionally uses `plugin.runtime.runc` for its shim, state root, and optional KVM device. Kata uses `plugin.runtime.kata`. Firecracker uses `plugin.runtime.firecracker` and requires `plugin.runtime.filestore_dir`. An unavailable optional adapter is omitted while the other runtimes remain usable.

Firecracker expects KVM at `/dev/kvm`. Its kernel must include virtio block,
virtio net, vsock, EROFS, ext4, overlayfs, devtmpfs, and the cgroup controllers
needed by the guest. The optional virtio-fs path additionally requires
`CONFIG_FUSE_FS=y` and `CONFIG_VIRTIO_FS=y`; DAX stays disabled because the VMM
does not expose a shared-memory window. The initrd must contain the
matching sandboxd `firecracker-agent` as `/init`. Default artifact paths are
`/opt/firecracker/vmlinux` and `/opt/firecracker/initrd.img`; the sample
configuration shows all overrides. The default VM size is one vCPU and
512 MiB when the request does not supply resources. Requested CPU is rounded
up to a vCPU count, and guest memory must be at least 128 MiB.

### Firecracker PVM prerequisites

The opt-in `firecracker-pvm` class reads `[plugin.runtime.firecracker_pvm]` and requires a PVM host ABI; the ordinary `firecracker` class remains hardware KVM. The daemon probes `/dev/kvm` before advertising either class. Use a dedicated distribution host kernel with a matched OOT `kvm.ko`/`kvm-pvm.ko` pair from `virt-pvm/linux`'s `pvm-6.12-host-oot` source and the qualified target-version compatibility changes. Build against the running kernel's installed headers/configuration/Module.symvers; rebuilding or replacing the host kernel binary is unnecessary. AKernel's `deploy/pvm/oot-host.env` pins the tested host-module source, separately from the Firecracker PVM guest source. Keep the pair fixed for the daemon's lifetime and restart sandboxd after an operator changes the backend. Retain the distribution networking/storage modules, including legacy IPv4/IPv6 filter and connmark for AKernel standalone.

VMX/SVM is not required on the PVM host, including an L1 without nested hardware virtualization. The tested stock Ubuntu `7.0.0-30-generic` L1 hides both features: its stock Intel KVM module fails to load, while the OOT pair loads and supplies the PVM ABI. FSGSBASE, RDTSCP and CMPXCHG16B remain required. Use `nokaslr pti=off`, disable FRED and avoid KASAN; module signing must satisfy the host policy. Built-in KVM cannot be replaced by this procedure, and stock VMX/SVM modules must not be mixed with the OOT core. Stop all KVM users before switching modules. Other kernel configurations and AMD hosts need separate qualification.

Use the validated Firecracker PVM guest bundle and the initrd built from this sandboxd revision. The guest must enable `CONFIG_KVM_GUEST=y`, `CONFIG_PVM_GUEST=y`, `CONFIG_X86_PIE=y`, and `CONFIG_X86_INTEL_MEMORY_PROTECTION_KEYS=y` alongside the common AKernel filesystem/network/virtio options. Guest MPK aligns `XCR0.PKRU` with a PKU-capable host and avoids extra intercepted `XSETBV` operations in nested deployments; it does not qualify guest pkey permission enforcement. The [AKernel fork's host profile](https://github.com/hky1999/AKernel/blob/feat/pvm-oot-nopku/deploy/pvm/oot-host.env) includes the upstream OSPKE guard fix in its OOT baseline. Earlier host pins can fault at RDPKRU when booted with `nopku`; changing only the guest kernel cannot fix that host-module bug. Host PKU policy is independent of the required guest configuration.

The companion [Firecracker fork](https://github.com/hky1999/firecracker/tree/feat/pvm-strict-tsc) pins [strict-TSC guest source `ca68979e554da5c483c627ced55cb7a55f605b11`](https://github.com/hky1999/linux/commit/ca68979e554da5c483c627ced55cb7a55f605b11). It defaults to strict mode, clamps backwards pvclock TSC deltas and disables the stable-TSC/deadline fast paths. Its parser selects the mode after the effective command line is initialized, respecting built-in append/override and duplicate-option precedence. Unknown or empty modes select strict; `pvm_tsc=unsafe` retains the original clock/timer selection and is unsuitable for TSC-domain-changing restore. Raw RDTSC/RDTSCP may still move backwards and clock-heavy workloads need performance assessment.

The independent `third_party/firecracker-pvm.json` now selects the published [PVM `v1.16.1-akernel.4` bundle](https://github.com/akernel-dev/firecracker/releases/tag/v1.16.1-akernel.4). Its archive SHA-256 is `150571da7a370d647e94011768acceac1b6920a2f2e7349f0e86b05b340e112f`, identical to candidate run `38717545796`; promotion did not rebuild the VMM or guest. Public release downloads require no token or unexpired Actions artifact, and the helper retains the original build provenance and all integrity/profile checks.

The default runtime release manifest still selects an ordinary KVM archive. Existing PVM bundles built from the older guest source require the same host/L1 boot and TSC domain; selecting a profile alone does not download the new candidate. Before deploying strict TSC, build and qualify a separate PVM bundle with the matching sandboxd-built initrd and preserve backend, frequency, software-digest and kernel-argument gates. A guest update changes checkpoint compatibility; drain/recreate sandboxes or retain their original stack. Matching frequency and strict TSC do not establish heterogeneous CPU migration support. DEBUGCTL remains an optional module-source patch.

The optional nested-host DEBUGCTL optimization moves `vcpu->arch.host_debugctl = get_debugctlmsr();` from common `vcpu_enter_guest()` into VMX/SVM source paths, since PVM maintains its own saved value. It is an OOT module-source change, separate from sandboxd and the guest bundle: rebuild/install the matched modules against the unchanged distribution kernel. The OOT build excludes VMX/SVM backends; restore stock hardware KVM by unloading both OOT modules and loading the complete stock pair. AKernel's `deploy/pvm-runtime.md` and `deploy/pvm/kvm-debugctl-backend-scope.patch` explain the optional patch and the limits of the earlier performance experiment. Current OOT runtime qualification uses the unoptimized module pair. See [checkpoint compatibility](checkpoint-restore.md) for backend identity and PVM TSC-frequency restore gates.

## Resolver sources

Sandbox DNS has two modes: managed and direct. With network ACLs enabled, supported runtimes use managed DNS even when an individual sandbox has no policy. Runc uses direct DNS. When network ACLs are disabled, all runtimes use direct DNS.

- Managed DNS: `plugin.runtime.resolv_conf_path` supplies the proxy's upstream nameservers and the search/domain/options retained in generated sandbox resolver files. Each sandbox queries the managed proxy on the bridge address.
- Direct DNS: `plugin.runtime.direct_resolv_conf_path` optionally selects the resolver file injected into the sandbox. An empty value inherits `plugin.runtime.resolv_conf_path`, which defaults to `/etc/resolv.conf`. The direct override never changes managed DNS upstreams or generated resolver content.

For example, a node-local resolver may serve the proxy while direct-DNS sandboxes need a different, reachable nameserver:

```toml
[plugin.runtime]
resolv_conf_path = "/etc/resolv.conf"
direct_resolv_conf_path = "/etc/sandboxd/direct-resolv.conf"
```

In direct mode, the source path is resolved in the sandboxd process's filesystem at sandbox creation, must identify a regular file, and is injected read-only as the sandbox's `/etc/resolv.conf`. An invalid selected source fails sandbox creation without falling back to another resolver. If a runtime-provided mount or an explicit sandbox mount already owns that destination or a parent such as `/etc`, sandboxd preserves that mount and does not inspect or inject the default resolver source. Managed DNS instead owns the resolver and rejects conflicting explicit mounts, as described in [Network ACL](network-acl.md).

Configure nameservers that the sandbox can actually reach from its network environment; selecting a file does not provide DNS forwarding. In particular, a node-local loopback resolver or Docker's embedded `127.0.0.11` must not be assumed reachable, and this option does not recreate Docker container-name resolution. A flat resolver file also cannot represent systemd-resolved's per-link split-DNS routing; operators using split DNS must validate a suitable resolver path and connectivity for their deployment. This setting is not a live-update mechanism: changes to its configuration or source file are not guaranteed to update existing sandboxes. Recreate a sandbox to apply a changed resolver deterministically.

## Cancelled OCI preparation

Start passes its request context through filesystem preparation, shared-rootfs acquisition, OCI rootfs and image-volume mounting, and inherited process metadata lookup. The registry client binds that context to manifest, config and layer requests, including body reads. Cancellation interrupts blocked OCI downloads and extraction; the preparation workers finish before Start releases its reserved ID and rolls back resources. Rollback and unmount use their cleanup contexts, independently of the cancelled Start context.

A caller waiting for a shared rootfs, OCI image or layer can cancel its own wait. Cancelling one creator does not cancel another caller's context: a live rootfs waiter can retry creation, and a different image sharing a layer can acquire it after the cancelled owner finishes. Successfully cached layers retain their normal reference-count and garbage-collection policy. These guarantees cover the regular OCI path; S3/FUSE daemon startup and Nydus bootstrap lifecycle retain their existing cancellation behavior. Transport cancellation alone is not a physical-cleanup acknowledgement.

## Start timeout errors

Start reports image preparation failures with `image pull (rootfs)`, `image pull (volume <target>)` or `image pull (process metadata)` in the gRPC message, and runtime startup failures with `runtime start (<runtime>)`. Network timeouts preserve their original cause and also classify as `context.DeadlineExceeded`, including when the network timer expires before the Start request deadline. Runsc control-RPC timers and runc's startup wait timer preserve that same error identity.

An application-reported Start timeout returns gRPC `DeadlineExceeded` with the trailer `sandboxd-start-failure: true`. Consumers can retain the backend stage and reason separately from a transport deadline that expired without a backend result. The trailer confirms an application failure response; resource rollback and reconciliation keep their existing completion semantics.

Registry HTTP rejections keep their original cause and category: invalid request (400), authentication failure (401), permission denial (403), missing image/blob (404) and rate limiting (429) map to their corresponding gRPC errors. Registry request/gateway timeouts (408/504) map to `DeadlineExceeded`; connection failures and other rejections retain their own error information. This classification also applies to lazily read image config and layers.

## OOM and failed deletion

A host cgroup OOM makes the entire sandbox terminal (`OOMKilled=true`, exit code 137), even when the kernel kills only a worker and the runtime's init process remains alive. Sandboxd consumes the kernel OOM notification independently of runtime Wait and drains the remaining tasks in that sandbox's allocated cgroup. The OOM lease is guarded against reset so an old notification cannot terminate a later user of the cached cgroup. Cgroup-disabled sandboxes have no host OOM notification; guest-only OOMs remain runtime-owned.

Delete calls for one sandbox share cleanup independently of caller cancellation. Each runtime deletion attempt has a 30-second deadline. If that deadline expires and an allocated cgroup is available, sandboxd drains only that child's processes and retries runtime deletion once with a fresh 30-second deadline. Runsc command output draining is also bounded. Cleanup errors remain visible and retryable: sandbox metadata, filesystem ownership, and resource accounting are released only after the runtime deletion succeeds. This does not guarantee that uninterruptible kernel tasks can be removed; failure must never be reported as successful cleanup.

Runc checks creation cancellation before allocating runtime state and again after OCI/rootfs preparation, so a late image result does not start a shim after the create deadline. A cancelled create cannot become ready merely because an init PID marker arrived. When runc confirms that a container does not exist, deletion also removes an empty directory left before `state.json` was written. It never recursively deletes nonempty state or follows a state-directory symlink; those conditions remain visible cleanup errors. Container-absence and stopped-state classification requires a normally exited, nonzero runc process with empty stdout and an exact known stderr diagnostic, either bare or in a single error/fatal logrus text or JSON record. Signal termination, extra diagnostics, phrases embedded in filesystem paths, executable launch failures and context expiry remain errors. Failed runtime deletion preserves the shim, rootfs, mounts, private storage and server metadata/resource ownership for a later deletion attempt. Filesystem teardown also retains private storage until preceding unmounts succeed. This applies to explicit deletion and orphan reconciliation.

## Pooled TAP lifecycle

Runsc, Kata, and Firecracker consume the same interface cache. Each cache entry
is one persistent TAP attached to `sandbox0`, with an IP-derived name and
separate deterministic host and guest MAC addresses. An idle TAP is kept down.
Allocation validates its type, name, bridge attachment, MAC addresses, and
ifindex before bringing it up. Deletion first brings the TAP down, then removes
ACL state, and only then returns the lease to the idle queue. This ordering
prevents a new sandbox from observing stale policy.

The complete versioned network resource, not a reconstructed device name, is
stored with sandbox metadata. Startup recovery reattaches active leases,
rebuilds ACLs against the recovered endpoint, cleans orphaned idle devices,
and refuses to start if an active pre-TAP pooled-veth lease exists. Drain
sandboxes created by a pre-TAP release before upgrading. Runc deliberately
keeps its independent one-shot netns and veth lifecycle and does not support
network ACLs.

## Firecracker storage model

By default Firecracker accepts a regular file containing an EROFS superblock as
its root filesystem. The file may be local or exposed by an image provider
such as distill-fs, so object-storage range reads and lazy caching remain
outside the runtime adapter.

Set `virtiofs_enabled = true` to use directory-backed root filesystems and host-directory mounts with exactly one explicit access option, `ro` or `rw`. This includes OCI/Nydus rootfs directories resolved by the image manager; root image exports always remain read-only, and OCI image mounts remain unsupported. sandboxd creates one private staging tmpfs per sandbox, recursively bind-mounts each source below fixed relative paths, and starts one upstream virtiofsd selected by `virtiofsd_path` (default `/usr/local/bin/virtiofsd`). The daemon uses namespace sandboxing, disabled submount announcements and inode file handles, and `find-paths` migration mode. It adds `--readonly` when all exports are read-only. Each read-only export is protected recursively on the host with `mount_setattr`, requiring Linux 5.12 or newer; guest remounts cannot make it writable. The staging root is also read-only. Submount announcements stay disabled so directory roots can serve as overlayfs lower layers. The default `cache=auto` supports executable directory roots; virtiofsd writeback caching is not enabled.

Host binds remain caller-owned: sandbox deletion removes only the staging mounts, not their source directories or contents. Their data is outside the sandbox's `storage_mb` quota and checkpoint artifacts. Local checkpoint/restore requires retaining the original backing directories and referenced files; their content is not rolled back. There is no automatic directory allocation, retention/GC, missing-file recreation, or cross-node data migration. The image manager continues owning and garbage-collecting image sources; Firecracker creates no independent image cache or eager OCI/Nydus-to-EROFS conversion.

This mode requires the AKernel Firecracker build with the MMIO virtio-fs
frontend and vhost-user migration support, plus virtiofsd 1.14 or newer. The
frontend requires `MQ`, `REPLY_ACK`, `LOG_SHMFD`, `DEVICE_STATE`, and
`VHOST_F_LOG_ALL`; startup fails rather than silently disabling checkpoint
correctness when a backend lacks them. DAX is not supported. The private ext4 overlay remains separate from writable host binds.

Every sandbox gets a sparse ext4 image under `filestore_dir/.firecracker` and
uses it as the overlay upper and work filesystem. For a read-only root, the
guest remounts the assembled root filesystem read-only after file injection
and mount setup. An explicit writable-layer limit sizes this image, with a
16 MiB minimum. Without an explicit limit, `default_overlay_size_bytes`
applies and defaults to 10 GiB. The image is removed on sandbox deletion.

The private ext4 disk defaults to asynchronous host Direct I/O with guest flush support:

```toml
[plugin.runtime.firecracker]
writable_io_engine = "AsyncDirect"
writable_cache_type = "Writeback"
```

`writable_io_engine` accepts `Sync`, `Async`, `SyncDirect`, and `AsyncDirect`. `Sync` and `Async` use buffered host file I/O. Direct engines require the matching Firecracker build; when using an older VMM, explicitly select `Async` or `Sync`. `writable_cache_type` accepts `Writeback` (the default, honoring guest flush requests) or `Unsafe`. Unknown values fail sandboxd initialization. These settings affect only the private writable disk, including native writable mounts, and are preserved in checkpoint device state. Read-only EROFS disks, virtio-fs exports, and checkpoint memory files retain their own I/O paths.

The Direct I/O implementation requires the host filesystem to report its alignment constraints through `statx(STATX_DIOALIGN)` and requires the backing image length to satisfy those constraints. Guest buffer alignment is adapted with bounded buffers. Requests covering partial host blocks, or large requests with unaligned guest buffers, use a serialized, chunked Direct I/O path; partial writes preserve neighboring sectors after earlier I/O has completed. These exceptional requests may block the VMM event loop while they execute. There is no automatic buffered fallback. Direct I/O bypasses host file-data caching for this disk, but does not eliminate guest page cache, filesystem metadata, or VMM memory overhead. Host memory headroom remains necessary.

Host compatibility is determined by the available kernel and filesystem capabilities, not by matching the build-time Linux header package version. Upstream Linux provides `STATX_DIOALIGN` for ext4 and XFS starting with Linux 6.1; vendor kernels may backport this capability. Both `SyncDirect` and `AsyncDirect` require it, and the current VMM has no legacy XFS alignment-query fallback. An unsupported direct configuration fails VM creation or snapshot restore and is never automatically switched to buffered I/O. The asynchronous engines additionally require usable `io_uring`; Firecracker documents Linux 5.10.51 as their minimum host kernel version. See the [statx interface](https://man7.org/linux/man-pages/man2/statx.2.html) and [Firecracker asynchronous I/O requirements](https://github.com/firecracker-microvm/firecracker/blob/v1.16.1/docs/api_requests/block-io-engine.md).

On hosts without the required Direct I/O capability, explicitly select buffered I/O for new sandboxes:

```toml
[plugin.runtime.firecracker]
writable_io_engine = "Async"
writable_cache_type = "Writeback"
```

Use `Sync` instead of `Async` when the host cannot provide the required `io_uring` capabilities. Buffered engines use host file-data caching, so account for that memory in addition to guest RAM and VMM overhead. Changing this configuration does not convert an existing Direct I/O checkpoint: restore retains the saved engine and requires a host that supports it.

A Firecracker start may expose directories from that same private ext4 image
at selected guest paths. This is useful for workloads such as Docker that need
a native filesystem instead of placing their own overlay on sandboxd's root
OverlayFS. Configure the paths through the runtime-specific start configuration:

```json
{
  "nativeWritableMounts": [
    {"target": "/var/lib/docker"}
  ]
}
```

Each target is backed by a distinct, root-owned directory next to the root
overlay's `upper` and `work` directories and is bind-mounted into the guest.
It is not a host bind mount or an additional Firecracker drive. The root
overlay and every native writable mount therefore share the single ext4 image
and its writable-layer quota. Targets must be canonical absolute directory
paths, may not overlap each other, an ordinary mount, or the guest's `/dev`,
`/proc`, `/run`, `/sys`, and `/tmp` system mounts. At most 16 targets may be
requested.

EROFS and `rofs` mounts must also name regular EROFS image files and are
attached as read-only drives. Read-only regular files are injected into the
guest, limited to 1 MiB per file and 4 MiB in total; this narrow path supports
managed files such as `resolv.conf`. With virtio-fs disabled, directory roots
that were not explicitly materialized and directory binds are rejected. With
virtio-fs enabled, directory roots and explicit `ro`/`rw` directory binds use
the single shared filesystem instead of block drives. At most 24 block drives,
including an EROFS root and the overlay, may be attached. Writable regular-file binds, host
device-provider OCI updates, NVIDIA devices, and nested KVM are always
rejected instead of being silently weakened.
Private tmpfs mounts are supported with a bounded set of standard security,
ownership, mode, inode, and size options.

The private ext4 image, including native writable mount data, remains in the
filestore across sandboxd restart so the handler can recover the running VMM.
It is cleaned by normal or idempotent sandbox deletion.

### Runtime inventory failures and readiness

Periodic runtime inventories run concurrently with independent ten-second budgets. A failed or timed-out inventory closes admission and removes only that runtime class from `ListAvailableRuntimes`; existing sandbox metadata and status remain intact. A later successful inventory reopens the class. Delete and cleanup operations remain available during degradation. A handler that ignores cancellation cannot accumulate overlapping inventory calls across passes.

Process readiness checks recovery, resource/image/storage modules and the result of local housekeeping. Failed local metadata reads, status persistence or recycled-path cleanup close readiness until a successful pass. A completed successful pass taking more than five seconds emits a latency warning without closing admission afterward: checkpoint writeback can delay a small status-file sync even when the runtime and resource inventory remain healthy. Time spent waiting for external runtime inventories is accounted separately, so a slow `runsc list` cannot mark an otherwise healthy Firecracker/PVM service unready. Runtime inventory warnings identify the affected class. Backend, capacity freshness and restore compatibility checks remain enforced.

## Settling a timed-out Start

Callers may set `StartRequest.start_key` to a unique execution-attempt key while leaving `sandbox_id` empty. The generated physical sandbox ID remains independent. A key cannot be reused for another execution. Sandboxd stores the key as the managed `sandboxd.start_key` label so committed sandboxes remain discoverable after restart.

`DeleteRequest.start_key` (with an empty `id`) cancels and fences the attempt, waits for its Start handler and rollback to finish, and deletes any committed sandbox. A successful response carries `sandboxd-start-fenced: true` metadata. A client must require this acknowledgement before treating an empty inventory as proof that an unknown Start has settled. Servers that do not implement keyed deletion cannot provide that proof. A timed-out Delete can be retried; it does not remove the fence or repeat Start. Fenced keys remain terminal for the sandboxd process lifetime, including when Delete arrived before Start. After a sandboxd restart, old handlers no longer execute and the persisted label identifies any committed sandbox for cleanup. This interface does not treat an unavailable backend or failed deletion as successful cleanup.

While a keyed Start is still executing, List includes its generated ID and labels with state UNKNOWN. The inventory snapshot is synchronized with handler completion so a recovering caller cannot miss both the pending and committed forms. Deleting that physical ID cancels and waits for the pending attempt, allowing recovery after the caller has lost its in-memory Start state. Committed metadata takes precedence if both forms are visible. This inspection does not hold the Start registry lock while waiting for runtime work.
