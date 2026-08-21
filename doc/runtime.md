# Sandbox runtimes

sandboxd supports runsc, runc, and Kata Containers. Runsc is the default.
Runc and Kata are optional and are advertised only after their configured
binaries and host prerequisites pass validation.

## Comparison

| Capability | runsc | runc | Kata Containers |
| --- | --- | --- | --- |
| Kernel boundary | gVisor user-space kernel | Host Linux kernel | Dedicated guest kernel in a lightweight VM |
| Host requirements | Tested runsc binary; `/dev/kvm` when the KVM platform is selected | Executable runc and runc-shim; writable cgroups, overlayfs, EROFS, and loop devices | Kata runtime and configuration with usable `/dev/kvm` |
| Network lifecycle | Reusable TAP from the interface pool | New netns and veth per sandbox, deleted on release | Reusable TAP from the interface pool |
| Root filesystem | Directory or EROFS | Directory or EROFS with a host overlay | Directory or EROFS passed into the VM |
| Lifecycle recovery and exec | Supported | Supported | Supported |
| Network ACL and managed DNS | Supported | Not supported | Supported |
| NVIDIA GPU | Experimental nvproxy support | Not supported | Not supported |
| Cgroup-disabled mode | Experimental | Not supported | Not supported |
| KVM | Optional execution platform; not exposed to the sandbox | Optional `/dev/kvm` exposure | Required by the runtime |
| Typical use | General-purpose sandboxing | Trusted workloads needing native Linux behavior | Workloads needing a VM isolation boundary |

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
root, and optional KVM device. Kata uses `plugin.runtime.kata`. An unavailable
optional adapter is omitted while the other runtimes remain usable.

## Pooled TAP lifecycle

Runsc and Kata consume the same interface cache. Each cache entry is one
persistent TAP attached to `sandbox0`, with an IP-derived name and separate
deterministic host and guest MAC addresses. An idle TAP is kept down.
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

The runc-only `enableKVM` start option exposes the configured read-write
character device as `/dev/kvm`. Kata uses its configured KVM device internally.
