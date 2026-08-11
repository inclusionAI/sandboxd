# Per-sandbox network ACL

Sandboxd can enforce an IPv4 packet policy and a DNS name policy for each
sandbox. Packet ACL and NAT enforcement use the same selected backend:
native netfilter for `iptables`, or TC eBPF for `bpfnat`. The managed DNS
proxy is shared by both backends.

This feature is disabled by default. Enable it on a drained node:

```toml
[plugin.network]
enable_network_acl = true
dns_proxy_concurrency_limit = 256
dns_proxy_per_sandbox_concurrency_limit = 16
```

Enabling it initializes the selected packet backend and a DNS proxy on
`sandbox0:53`.
Sandboxd manages every sandbox's `/etc/resolv.conf` so policies can be added
later without restarting the sandbox. A sandbox with no policy has no ACL
hooks and its traffic remains unrestricted. `SetNetworkPolicy` can install a
policy at any time after that sandbox reaches the running state.

Do not enable the feature while the node has existing sandboxes. Their stored
ACL bindings do not exist yet, so sandboxd deliberately fails startup instead
of silently treating them as unrestricted. Drain the node first, enable the
configuration, and then start new sandboxes.

## Host requirements

Both backends require an unused TCP and UDP port 53 on the `sandbox0` address
and at least one usable `nameserver` in sandboxd's configured
`resolv_conf_path` (or `/etc/resolv.conf` by default).

The `iptables` backend additionally requires:

- the `ip_tables`, `br_netfilter`, and conntrack kernel facilities;
- `net.bridge.bridge-nf-call-iptables=1` in sandboxd's network namespace; and
- permission to manage filter chains and delete conntrack entries for policy
  replacement, including the `connmark` match and `CONNMARK` target.

The `bpfnat` backend instead requires:

- Linux with eBPF `SCHED_CLS`, hash, LRU hash, and TC `clsact` support;
- a writable, mounted bpffs at `/sys/fs/bpf`, or permission for sandboxd to
  mount it there; and
- permission for sandboxd to load BPF programs, pin maps, and manage TC
  filters on its host veth devices.

The selected NAT backend keeps its own prerequisites. In particular, a
`bpfnat` host setup must provide `net.ipv4.ip_forward=1` and, when local DNAT
is enabled, `net.ipv4.conf.all.rp_filter=0`. Sandboxd sets
`net.ipv4.conf.sandbox0.rp_filter=0` and
`net.ipv4.conf.sandbox0.accept_local=1` when it creates the bridge; it does not
silently change the two host-wide settings. See
[the bpfnat notes](../bpf/bpfnat/README.md) for the complete backend setup.

When ACL is enabled, a request-provided mount that owns `/etc/resolv.conf` is
rejected because it could bypass managed DNS. Search domains and resolver
options from the host resolver file are retained.

## API

`StartRequest.network_policy` installs the initial policy. The
`SetNetworkPolicy` RPC atomically replaces the complete policy of a running
sandbox:

```protobuf
SetNetworkPolicyRequest {
  sandbox_id: "example"
  network_policy: {
    traffic: {
      default_action: NETWORK_POLICY_ACTION_DENY
      mode: TRAFFIC_POLICY_MODE_STATEFUL
      rules: {
        action: NETWORK_POLICY_ACTION_ALLOW
        direction: NETWORK_DIRECTION_BOTH
        protocol: NETWORK_PROTOCOL_TCP
        peer: { address: "10.88.0.1" port: 18080 }
      }
    }
  }
}
```

Sending no `network_policy` in `SetNetworkPolicyRequest` clears the current
policy. It also removes the sandbox's ACL filters, returning it to the
unrestricted fast path while preserving its registration for future updates.

Traffic rules match direction and protocol plus optional remote-peer and
sandbox-side endpoints. An omitted `peer` matches any remote address and
port; an explicitly supplied `0.0.0.0` remains an exact address. `peer.port`
is the remote port. `sandbox_port` is the destination port on ingress and the
source port on egress. Port zero means any port, and nonzero ports are valid
only for TCP or UDP. This lets a default-deny policy publish a sandbox target
port without knowing which frontend or client address will connect to it.

Use default `DENY` with `ALLOW` rules for an allowlist, or default `ALLOW`
with `DENY` rules for a denylist. If multiple rules match, `DENY` wins.
`TRAFFIC_POLICY_MODE_STATEFUL` admits reply traffic for an allowed TCP, UDP,
or ICMP flow and the related ICMP errors required for diagnostics and path
MTU discovery. `TRAFFIC_POLICY_MODE_STATELESS` evaluates every direction
independently. An unspecified mode remains stateless for compatibility with
existing callers.

The current packet-policy scope is IPv4. IPv6 and other Ethernet protocols are
dropped while either a traffic or DNS policy is active; this prevents an IPv6
resolver from bypassing DNS enforcement. ARP remains allowed. IPv4 header
options and fragments are supported. With bpfnat, the first fragment records
the ACL and NAT decision and later fragments reuse it; an out-of-order fragment
with no recorded first fragment is dropped. Native netfilter supplies the
equivalent fragment and connection tracking in iptables mode. v1 supports
exact IP addresses, not CIDRs or port ranges.

## DNS policy

A DNS denylist for `github.com` and all of its subdomains looks like:

```protobuf
DNSPolicy {
  default_action: NETWORK_POLICY_ACTION_ALLOW
  rules: {
    action: NETWORK_POLICY_ACTION_DENY
    pattern: "github.com"
  }
  rules: {
    action: NETWORK_POLICY_ACTION_DENY
    pattern: "*.github.com"
  }
}
```

Names are matched case-insensitively. A leading `*.` matches descendants but
not the suffix itself, so the two rules above are intentionally separate.
Only exact names and a leading `*.` suffix pattern are supported. International
names must be supplied as ASCII punycode. Underscores are accepted in generic
DNS owner names, including service-discovery names such as
`_grpc._tcp.example.com`. A multi-question DNS request is refused if any
question is denied, and `DENY` wins over overlapping `ALLOW` rules.

The proxy supports UDP and TCP DNS and returns `REFUSED` for a blocked query.
It does not cache answers and does not create IP ACL rules from DNS responses.
Before allocating a handler goroutine or an upstream socket, it enforces the
configured global and per-sandbox concurrency limits. Zero-valued limits use
the safe defaults shown above. Excess UDP requests receive `SERVFAIL`, while
excess TCP connections are closed immediately; work is never queued without a
bound.
When a DNS policy is active, TC permits DNS only to `sandbox0:53`, preventing
plain DNS bypass through a different resolver. DNS-over-HTTPS and direct
connections to a previously known IP are outside DNS-policy scope; combine a
DNS policy with a traffic policy when those paths must also be restricted.

## Lifecycle and recovery

Policy state is persisted in sandboxd's store. Rules for a new generation are
staged before the dataplane switches to it. Policy replacement invalidates
existing connection state immediately, so packets from a flow admitted by an
old generation cannot retain access under the new policy. The iptables backend
uses fail-closed dispatcher chains, generation-scoped connmarks, and removes
the sandbox's conntrack entries;
bpfnat keys connection and fragment state by policy generation.

With bpfnat, eBPF maps are pinned under
`/sys/fs/bpf/sandboxd/networkacl`, and TC keeps program references across an
unexpected sandboxd exit. On restart, sandboxd reopens the maps, reconciles
each active sandbox with its current host veth, and replaces the filters. The
iptables backend rebuilds its per-sandbox chains from the same persisted
policy before making them active. Both paths avoid a fail-open recovery
window.
Normal sandbox deletion removes its policy, rules, and hooks. Once all
sandboxes are gone, normal sandboxd shutdown also removes the bpfnat pinned
maps or the iptables chains owned by sandboxd.
Failed cleanup remains persisted as orphan state so startup recovery can retry
it. Sandboxd persists that orphan cleanup intent before changing policy maps,
rules, or TC filters. Kernel cleanup is idempotent and targets only sandboxd's
map keys, rule keys, and reserved TC filter identifiers. If removing the orphan
from durable state fails, the cleanup intent remains and recovery retries it.
Recovery resolves active sandbox ownership first and refuses orphan cleanup when
an active sandbox owns the same ifindex. A veth involved in a failed Start
rollback is destroyed instead of being returned to the interface pool; if
destruction also fails, the lease remains quarantined and cannot be allocated
to another sandbox.

## Verification

Unit tests run with the normal test suite. The privileged ACL target runs the
same backend-neutral conformance scenarios through iptables and bpfnat in
isolated network namespaces. It covers rule precedence and wildcarding,
stateful and stateless TCP, UDP and ICMP, published sandbox ports, related
ICMP errors, IPv4 fragments, DNS endpoint enforcement, live policy
replacement, restart recovery, and policy removal. Backend-specific TC,
pinned-map, failure-recovery, and uncached DNS proxy tests run in the same
target:

```sh
make networkacl-test
```

The independent bpfnat NAT and garbage-collection suite runs with:

```sh
make bpfnat-test
```
