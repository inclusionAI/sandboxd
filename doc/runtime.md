# Sandbox runtimes

sandboxd supports runsc, runc, Kata Containers, and Firecracker. Runsc is the
default. Optional runtimes are advertised only after their configured
binaries, boot artifacts, and host prerequisites pass validation.

## Comparison

| Capability | runsc | runc | Kata Containers | Firecracker |
| --- | --- | --- | --- | --- |
| Kernel boundary | gVisor user-space kernel | Host Linux kernel | Dedicated guest kernel in a lightweight VM | Dedicated guest kernel in a microVM |
| Host requirements | Tested runsc binary; `/dev/kvm` when the KVM platform is selected | runc and runc-shim; writable cgroups, overlayfs, EROFS, and loop devices | Kata runtime and configuration with usable `/dev/kvm` | Firecracker, compatible kernel and initrd, `/dev/kvm`, and `mkfs.ext4` |
| Network lifecycle | Reusable TAP from the interface pool | New netns and veth per sandbox, deleted on release | Reusable TAP from the interface pool | Reusable TAP from the interface pool |
| Root filesystem | Directory or EROFS | Directory or EROFS with a host overlay | Directory or EROFS passed into the VM | Immutable EROFS drive plus a private ext4 overlay |
| Read-only mounts | Bind, EROFS, and runtime-supported OCI mounts | Bind, EROFS, and OCI mounts | Bind, EROFS, and runtime-supported OCI mounts | EROFS drives and bounded regular-file injection |
| Exec, interactive TTY, wait, stats, and recovery | Supported | Supported | Supported | Supported |
| Network ACL and managed DNS | Supported | Not supported | Supported | Supported |
| Published-port DNAT | Supported | Supported | Supported | Supported |
| Writable-layer quota | Supported | Not supported | Not supported | Supported |
| NVIDIA GPU | Experimental nvproxy support | Not supported | Not supported | Not supported |
| Cgroup-disabled mode | Experimental | Not supported | Not supported | Not supported |
| KVM | Optional execution platform; not exposed to the sandbox | Optional guest exposure | Required by the runtime | Required by the runtime; nested KVM is not exposed |

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

Firecracker uses the stock VMM API and expects KVM at `/dev/kvm`. Its kernel
must include virtio block, virtio net, vsock, EROFS, ext4, overlayfs, devtmpfs,
and the cgroup controllers needed by the guest. The initrd must contain the
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

Firecracker accepts only a regular file containing an EROFS superblock as its
root filesystem. The file may be local or exposed by an image provider such as
distill-fs, so object-storage range reads and lazy caching remain outside the
runtime adapter. sandboxd never converts an OCI or Nydus directory into a
runtime-specific image.

Every sandbox gets a sparse ext4 image under `filestore_dir/.firecracker` and
uses it as the overlay upper and work filesystem. For a read-only root, the
guest remounts the assembled root filesystem read-only after file injection
and mount setup. An explicit writable-layer limit sizes this image, with a
16 MiB minimum. Without an explicit limit, `default_overlay_size_bytes`
applies and defaults to 10 GiB. The image is removed on sandbox deletion.

EROFS and `rofs` mounts must also name regular EROFS image files and are
attached as read-only drives. Read-only regular files are injected into the
guest, limited to 1 MiB per file and 4 MiB in total; this narrow path supports
managed files such as `resolv.conf` and does not provide directory sharing. At
most 24 drives, including root and overlay, may be attached. Directory roots,
directory binds, writable binds, host device-provider OCI updates, NVIDIA
devices, and nested KVM are rejected instead of being silently weakened.
Private tmpfs mounts are supported with a bounded set of standard security,
ownership, mode, inode, and size options.

The private ext4 image remains in the filestore across sandboxd restart so the
handler can recover the running VMM. It is cleaned by normal or idempotent
sandbox deletion.
