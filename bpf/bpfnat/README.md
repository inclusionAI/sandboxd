# Embedded bpfnat backend

The `bpfnat` network backend embeds its TC eBPF object in the sandboxd
binary. At runtime it uses netlink and the BPF syscall directly, so target
nodes do not need `iptables`, `tc`, `bpftool`, a separate loader, or a systemd
unit.

The embedded data plane contains only the IPv4 SNAT and DNAT paths needed by
the `NetworkManager` interface. Its C headers and source files carry the
repository's Apache-2.0 SPDX identifier.

This backend is experimental and supports Linux 5.10 or newer. The embedded
objects use stable Linux UAPI types instead of types generated from the build
host's `vmlinux` BTF. Target nodes therefore do not need kernel BTF for CO-RE
relocation, but their kernel must provide the BPF and TC helpers used by the
program. Unsupported kernels fail while sandboxd initializes the backend.

sandboxd probes the TC program helpers available on the running kernel. It
prefers in-kernel BPF timers for connection expiry and falls back to its
userspace garbage collector when the timer helpers are unavailable or the
kernel verifier rejects the timer-enabled object. The selected `gc_mode` is
recorded in the initialization log. The two modes use separate bpffs pin
directories because their map value layouts differ.

Select the backend with:

```toml
[plugin.network]
nat_backend = "bpfnat"
enable_local_dnat = true
# bpfnat_device = "eth0"
```

`bpfnat_device` is optional. When omitted, sandboxd selects the device used by
the IPv4 default route. Local DNAT applies to non-loopback local node
addresses, matching the practical behavior of the iptables backend; callers
should connect to a node address rather than `127.0.0.1`.

The host setup must enable `net.ipv4.ip_forward=1` before starting sandboxd.
The backend validates this prerequisite and fails initialization without
changing it. When local DNAT is enabled, host setup must additionally set
`net.ipv4.conf.all.rp_filter=0`. The external device's per-interface
`rp_filter` may remain enabled.

The backend owns NAT, not host firewall policy. The deployment must allow
forwarded traffic from and to `sandbox0`; otherwise a `FORWARD` policy of
`DROP` discards packets before they reach the physical-device egress program.
Use bridge- and CIDR-scoped filter rules rather than changing the global
policy. Such rules can be managed with nftables and do not require conntrack
or NAT kernel extensions. sandboxd intentionally does not create or remove
them.

After creating `sandbox0`, sandboxd sets its interface-scoped
`net.ipv4.conf.sandbox0.accept_local=1` and
`net.ipv4.conf.sandbox0.rp_filter=0`. These values belong to the sandbox bridge
and disappear when sandboxd deletes the bridge during shutdown; sandboxd does
not save or restore previous values.

## Regenerating the object

The checked-in `bpfnat_legacy_bpfel` and `bpfnat_timer_bpfel` Go and object
files under `pkg/networkmanager/bpfnat` are the runtime artifacts.
Regeneration is only needed when changing code in this directory. Use the
project target, which builds a tool image containing the pinned Clang 14 and
`bpf2go` versions:

```sh
make bpf
```

Run `make bpf-format` before regeneration when editing C or header files.
`make check-bpf` checks C formatting and regenerates the files with the same
image, then fails if the checked-in artifacts are stale. Generation does not
inspect the running kernel or invoke `bpftool`. At runtime,
`github.com/cilium/ebpf` loads the embedded object using the BPF syscall; it
does not install or run Cilium.

Run the privileged kernel regression suite after changing the dataplane,
maps, garbage collection, or manager lifecycle:

```sh
make bpfnat-test
```

The target uses an isolated container network namespace and bpffs mount, but
it requires a Linux host that permits privileged Docker containers.
