# Sandbox runtimes

sandboxd supports runsc, runc, and Kata Containers. Runsc is the default.
Runc and Kata are optional and are advertised only after their configured
binaries and host prerequisites pass validation.

## Comparison

| Capability | runsc | runc | Kata Containers |
| --- | --- | --- | --- |
| Kernel boundary | gVisor user-space kernel | Host Linux kernel | Dedicated guest kernel in a lightweight VM |
| Host requirements | Executable runsc | Executable runc and runc-shim; writable cgroups, overlayfs, EROFS, and loop devices | Kata runtime and configuration with usable `/dev/kvm` |
| Network lifecycle | Reusable veth from the interface pool | New netns and veth per sandbox, deleted on release | Reusable veth passed into the VM |
| Root filesystem | Directory or EROFS | Directory or EROFS with a host overlay | Directory or EROFS passed into the VM |
| Lifecycle recovery and exec | Supported | Supported | Supported |
| NVIDIA GPU | Experimental nvproxy support | Not supported | Not supported |
| Cgroup-disabled mode | Experimental | Not supported | Not supported |
| KVM | Not exposed | Optional `/dev/kvm` exposure | Required by the runtime |
| Typical use | General-purpose sandboxing | Trusted workloads needing native Linux behavior | Workloads needing a VM isolation boundary |

## Selection

A start request selects a runtime by name. Each adapter must also have an
entry under `plugin.runtime.runtime_binary`; runc additionally uses
`plugin.runtime.runc` for its shim, state root, and optional KVM device.
Unavailable optional adapters are omitted while the remaining runtimes stay
usable.

Runc networking is intentionally on demand: sandboxd creates a network
namespace and veth pair for each sandbox, then removes both during release.
Runsc and Kata retain the reusable interface-pool lifecycle.

The runc-only `enableKVM` start option exposes the configured read-write
character device as `/dev/kvm`. Kata uses its configured KVM device internally.
