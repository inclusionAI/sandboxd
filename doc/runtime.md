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

The only accepted values are `systrap` and `kvm`; omitting the setting selects
`systrap`. Runc additionally uses `plugin.runtime.runc` for its shim, state
root, and optional KVM device. Kata uses `plugin.runtime.kata`. Firecracker
uses `plugin.runtime.firecracker` and requires
`plugin.runtime.filestore_dir`. An unavailable optional adapter is omitted
while the other runtimes remain usable.

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

Set `virtiofs_enabled = true` to use directory-backed root filesystems and explicitly read-only host-directory mounts, including OCI/Nydus rootfs directories resolved by the image manager. OCI image mounts remain unsupported. sandboxd creates one private staging tmpfs per sandbox, recursively bind-mounts each source below fixed relative paths, and starts one upstream virtiofsd selected by `virtiofsd_path` (default `/usr/local/bin/virtiofsd`). The daemon is always started with `--readonly`, namespace sandboxing, submount announcements disabled, inode file handles disabled, and `find-paths` migration mode. Disabling submount announcements makes the staging bind mounts ordinary virtio-fs directories in the guest, so they can serve as an overlayfs lower layer. The staging binds are also remounted read-only. The image manager keeps owning and garbage-collecting the source; Firecracker creates no independent image cache. OCI and Nydus rootfs directories require this mode and are never eagerly converted to EROFS.

This mode requires the AKernel Firecracker build with the MMIO virtio-fs
frontend and vhost-user migration support, plus virtiofsd 1.14 or newer. The
frontend requires `MQ`, `REPLY_ACK`, `LOG_SHMFD`, `DEVICE_STATE`, and
`VHOST_F_LOG_ALL`; startup fails rather than silently disabling checkpoint
correctness when a backend lacks them. DAX and writable host sharing are not
supported. The sandbox's private ext4 overlay remains the only writable layer.

Every sandbox gets a sparse ext4 image under `filestore_dir/.firecracker` and
uses it as the overlay upper and work filesystem. For a read-only root, the
guest remounts the assembled root filesystem read-only after file injection
and mount setup. An explicit writable-layer limit sizes this image, with a
16 MiB minimum. Without an explicit limit, `default_overlay_size_bytes`
applies and defaults to 10 GiB. The image is removed on sandbox deletion.

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
virtio-fs enabled, directory roots and explicitly read-only directory binds use
the single shared filesystem instead of block drives. At most 24 block drives,
including an EROFS root and the overlay, may be attached. Writable binds, host
device-provider OCI updates, NVIDIA devices, and nested KVM are always
rejected instead of being silently weakened.
Private tmpfs mounts are supported with a bounded set of standard security,
ownership, mode, inode, and size options.

The private ext4 image, including native writable mount data, remains in the
filestore across sandboxd restart so the handler can recover the running VMM.
It is cleaned by normal or idempotent sandbox deletion.
