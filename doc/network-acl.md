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

Enabling it initializes the selected packet backend and a DNS proxy on `sandbox0:53`. For runtimes that support network ACLs, sandboxd manages each sandbox's `/etc/resolv.conf` so policies can be added later without restarting the sandbox. A sandbox with no policy has no ACL hooks and its traffic remains unrestricted. `SetNetworkPolicy` can install a policy at any time after that sandbox reaches the running state.

Runc does not support network ACLs and is not registered with the DNS proxy. It uses `plugin.runtime.runc.resolv_conf_path` when set, otherwise the node-wide `plugin.runtime.resolv_conf_path`, unless the runtime or an explicit mount already owns `/etc/resolv.conf`, including through a parent mount such as `/etc`. Enabling ACLs on the node does not redirect runc DNS through the proxy or override these mounts. The runc-specific setting does not change the managed DNS proxy's upstream resolver or the resolver used by other runtimes. The path is a resolver file visible to the sandboxd process, not a DNS policy: its nameservers must be reachable from runc's separate network namespace. See [Runc resolver source](runtime.md#runc-resolver-source) for the Docker embedded DNS, split-DNS, and update limitations.

Do not enable the feature while the node has existing sandboxes. Their stored
ACL bindings do not exist yet, so sandboxd deliberately fails startup instead
of silently treating them as unrestricted. Drain the node first, enable the
configuration, and then start new sandboxes.

## Host requirements

Both backends require an unused TCP and UDP port 53 on the `sandbox0` address
and at least one usable `nameserver` in sandboxd's configured
`resolv_conf_path` (or `/etc/resolv.conf` by default).

The `iptables` backend additionally requires:

- the `iptables`, `ip6tables`, and `ipset` userspace commands;
- the IPv4/IPv6 filter-table, `br_netfilter`, `xt_physdev`, conntrack and
  conntrack-netlink, connmark/CONNMARK, and timeout-capable `hash:ip` ipset
  kernel facilities;
- both `net.bridge.bridge-nf-call-iptables=1` and
  `net.bridge.bridge-nf-call-ip6tables=1` in sandboxd's network namespace; and
- permission to manage filter chains and delete conntrack entries for policy
  replacement, including the `connmark` match and `CONNMARK` target.

Initialization probes the IPv4 anti-spoof and IPv6 physdev rules plus the
required ipset type, so a node with missing kernel support fails readiness
before accepting sandboxes.

The `bpfnat` backend instead requires:

- Linux 5.17 or newer for `bpf_loop`, with eBPF `SCHED_CLS`, hash, LRU hash,
  and TC `clsact` support;
- a writable, mounted bpffs at `/sys/fs/bpf`, or permission for sandboxd to
  mount it there; and
- permission for sandboxd to load BPF programs, pin maps, and manage TC
  filters on sandbox host endpoints.

The selected NAT backend keeps its own prerequisites. In particular, a
`bpfnat` host setup must provide `net.ipv4.ip_forward=1` and, when local DNAT
is enabled, `net.ipv4.conf.all.rp_filter=0`. Sandboxd sets
`net.ipv4.conf.sandbox0.rp_filter=0` and
`net.ipv4.conf.sandbox0.accept_local=1` when it creates the bridge; it does not
silently change the two host-wide settings. See
[the bpfnat notes](../bpf/bpfnat/README.md) for the complete backend setup.

For an ACL-enabled sandbox, a request-provided mount that owns `/etc/resolv.conf` is rejected because it could bypass managed DNS. Search domains and resolver options from the host resolver file are retained.

## API

`StartRequest.network_policy` installs the initial policy. The
`SetNetworkPolicy` RPC atomically replaces the complete policy of a running
sandbox:

```protobuf
SetNetworkPolicyRequest {
  sandbox_id: "example"
  network_policy: {
    schema_version: 2
    traffic: {
      ingress_default_action: NETWORK_POLICY_ACTION_ALLOW
      egress_default_action: NETWORK_POLICY_ACTION_DENY
      mode: TRAFFIC_POLICY_MODE_STATEFUL
      rules: {
        action: NETWORK_POLICY_ACTION_ALLOW
        direction: NETWORK_DIRECTION_EGRESS
        protocol: NETWORK_PROTOCOL_TCP
        peer: {
          domain: "*.example.com"
          port_range: { first: 443 last: 443 }
        }
        priority: 200
      }
    }
  }
}
```

Sending no `network_policy` in `SetNetworkPolicyRequest` clears the current
policy. It also removes the sandbox's ACL filters, returning it to the
unrestricted fast path while preserving its registration for future updates.

Schema v2 traffic rules match direction and protocol plus optional
remote-peer and sandbox-side endpoints. An omitted `peer` matches any remote
address and port. A peer may select one canonical IPv4 CIDR, one exact or
leading-wildcard domain, and an inclusive peer port range. Domain peers are
valid only on egress. `sandbox_port_range` is the destination interval on
ingress and the source interval on egress. Port ranges are valid only for TCP
or UDP. At most 256 traffic rules are accepted.

Use egress default `DENY` with `ALLOW` rules for an allowlist, or default
`ALLOW` with `DENY` rules for a denylist. Ingress has its own default. Higher
priority wins when several rules match, and `DENY` wins an equal-priority tie.
Priority zero selects the user default of 100. Integrations reserve priority
`UINT32_MAX` for platform control and published-port rules; public AKernel
clients therefore limit user priorities to `UINT32_MAX - 1`.

`TRAFFIC_POLICY_MODE_STATEFUL` admits reply traffic for an allowed TCP, UDP,
or ICMP flow and the related ICMP errors required for diagnostics and path
MTU discovery. `TRAFFIC_POLICY_MODE_STATELESS` evaluates every direction
independently. Schema v2 defaults an unspecified mode to stateful. The legacy
schema retains stateless-by-default behavior and its exact `address`, `port`,
`sandbox_port`, shared `default_action`, and deny-wins matching semantics.

The current packet-policy scope is IPv4. IPv6 is dropped while either a traffic
or DNS policy is active; this prevents an IPv6 resolver from bypassing DNS
enforcement. ARP remains allowed. Arbitrary non-IP Ethernet protocols are
outside the portable ACL contract; the TC eBPF backend drops them, while an
iptables deployment must provide any required raw-L2 isolation separately.
IPv4 header options and fragments are supported. With bpfnat, the first
fragment records the ACL and NAT decision and later fragments reuse it; an
out-of-order fragment with no recorded first fragment is dropped. A fragment
authorization derived from DNS never outlives that DNS grant, including while
sandboxd is restarting. Native netfilter supplies the equivalent fragment and
connection tracking in iptables mode. Its policy hooks match the sandbox's
assigned IPv4 address on both routed and bridged paths. Companion hooks bound
to the physical bridge port drop packets whose source or destination address
does not match that endpoint, so address spoofing cannot bypass the
per-sandbox policy. v1 supports exact IP addresses, not CIDRs or port ranges.

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
names are normalized to ASCII punycode. Underscores are accepted in generic
DNS owner names, including service-discovery names such as
`_grpc._tcp.example.com`. A multi-question DNS request is refused if any
question is denied, and `DENY` wins over overlapping `ALLOW` rules.

The proxy supports UDP and TCP DNS and returns `REFUSED` for a blocked query.
For a schema v2 domain traffic rule, the original allowed query authorizes
IPv4 answers reached through its complete CNAME chain. Sandboxd installs
generation-scoped address grants with the answer TTL, clamped to 1..3600
seconds. Resolving that original name again with an A or ANY query atomically
replaces its previous IPv4 grants; parallel AAAA and other non-IPv4 queries do
not revoke them. Expiration or replacement also deletes connection state that
depended on the changed grant. A query not covered by a domain traffic rule may
still resolve when the DNS policy allows it, but its answer creates no packet
authorization. A domain traffic rule activates the managed DNS path even when
the policy has no separate `dns` section.

Domain traffic rules ultimately enforce at IPv4 and transport layers. During a
grant's lifetime, another virtual host sharing the same address and allowed
port is not distinguishable by this ACL; use an application proxy when
hostname-level isolation is required.

The proxy does not otherwise cache answers. Before allocating a handler
goroutine or an upstream socket, it enforces the configured global and
per-sandbox concurrency limits. Zero-valued limits use the safe defaults
shown above. Excess UDP requests receive `SERVFAIL`, while excess TCP
connections are closed immediately; work is never queued without a bound.
When managed DNS is active, the packet backend permits DNS only to
`sandbox0:53`, preventing plain DNS bypass through a different resolver.
DNS-over-HTTPS and direct connections to a previously known IP are outside
DNS-policy scope; combine a DNS policy with a traffic policy when those paths
must also be restricted.

## Lifecycle and recovery

Policy state is persisted in sandboxd's store. Rules for a new generation are
staged before the dataplane switches to it. Policy replacement invalidates
existing connection state immediately, so packets from a flow admitted by an
old generation cannot retain access under the new policy. The iptables backend
uses fail-closed, generation-scoped dispatcher chains and one sandboxd-owned
connmark namespace (`0xa5c1xxxx`) for authorized stateful flows. One conntrack
entry can cross two managed sandbox endpoints, so source and destination
authorization use independent low-order role bits. ORIGINAL and REPLY packets
consume the bit owned by that endpoint's direction. Thus one sandbox cannot
authorize state on behalf of another sandbox that denied the NEW flow. Policy
replacement removes the affected sandbox's conntrack entries before the next
generation becomes reachable.
Both per-sandbox dispatchers remain on a drop barrier while a changed DNS grant
and its dependent conntrack state are replaced.
bpfnat keys connection and fragment state by policy generation and enables a
per-policy drop barrier while derived domain maps and their dependent
connection and fragment state are replaced. A failed update therefore remains
closed instead of exposing an incomplete domain deny set.

With bpfnat, eBPF maps are pinned under
`/sys/fs/bpf/sandboxd/networkacl`, and TC keeps program references across an
unexpected sandboxd exit. On restart, sandboxd reopens the maps, reconciles
each active sandbox with its current host endpoint, and replaces the filters.
ACL v2 uses a versioned connection-state map because its values include a DNS
authorization deadline. Upgrading from v1 therefore reevaluates active flows
instead of trying to open an incompatible pinned connection map; persisted v1
policies themselves remain supported.
The iptables backend rebuilds its per-sandbox chains from the same persisted
policy before making them active. Both paths avoid a fail-open recovery
window.
Normal sandbox deletion removes its policy, rules, and hooks. Once all
sandboxes are gone, normal sandboxd shutdown also removes the bpfnat pinned
maps or the iptables chains owned by sandboxd.
Failed cleanup remains persisted as orphan state so startup recovery can retry
it. Sandboxd persists that orphan cleanup intent before changing policy maps,
rules, domain sets, or TC filters. Kernel cleanup is idempotent and targets
only sandboxd's map keys, rule keys, and reserved TC filter identifiers. If
removing the orphan from durable state fails, the cleanup intent remains and
recovery retries it.
Recovery resolves active sandbox ownership first and refuses orphan cleanup
when an active sandbox owns the same ifindex. A pooled TAP involved in a failed
Start rollback is destroyed instead of being returned to the interface pool;
if destruction also fails, the lease remains quarantined and cannot be
allocated to another sandbox.

## Verification

Unit tests run with the normal test suite. The privileged ACL target runs the
same backend-neutral conformance scenarios through iptables and bpfnat in
isolated network namespaces. It covers rule precedence and wildcarding,
stateful and stateless TCP, UDP and ICMP, CIDRs, port ranges, priorities,
domain grants, published sandbox ports, related ICMP errors, IPv4 fragments,
fail-closed IPv6 handling, DNS endpoint enforcement, TTL expiry, live policy
replacement, independently enforced managed endpoints, restart recovery, and
policy removal. Backend-specific TC,
ip6tables, ipset, pinned-map,
failure-recovery, and DNS proxy tests run in the same target:

```sh
make networkacl-test
```

The independent bpfnat NAT and garbage-collection suite runs with:

```sh
make bpfnat-test
```
