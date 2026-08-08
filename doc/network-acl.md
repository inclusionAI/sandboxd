# Per-sandbox network ACL

Sandboxd can enforce an IPv4 packet policy and a DNS name policy for each
sandbox. The feature is independent of the NAT backend and works with both
`iptables` and `bpfnat`.

This feature is disabled by default. Enable it on a drained node:

```toml
[plugin.network]
enable_network_acl = true
dns_proxy_concurrency_limit = 256
dns_proxy_per_sandbox_concurrency_limit = 16
```

Enabling it initializes the eBPF maps and a DNS proxy on `sandbox0:53`.
Sandboxd manages every sandbox's `/etc/resolv.conf` so policies can be added
later without restarting the sandbox. A sandbox with no policy has no ACL TC
filters and its traffic remains unrestricted. `SetNetworkPolicy` can install a
policy at any time after that sandbox reaches the running state.

Do not enable the feature while the node has existing sandboxes. Their stored
ACL bindings do not exist yet, so sandboxd deliberately fails startup instead
of silently treating them as unrestricted. Drain the node first, enable the
configuration, and then start new sandboxes.

## Host requirements

The host must provide:

- Linux with eBPF `SCHED_CLS`, hash/array maps, and TC `clsact` support;
- a writable, mounted bpffs at `/sys/fs/bpf`, or permission for sandboxd to
  mount it there;
- permission for sandboxd to load BPF programs, pin maps, and manage TC
  filters on its host veth devices;
- an unused TCP and UDP port 53 on the `sandbox0` address; and
- at least one usable `nameserver` in sandboxd's configured
  `resolv_conf_path` (or `/etc/resolv.conf` by default).

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

Traffic rules match an exact remote IPv4 address, direction, protocol, and
optional port. Port zero means any port. A nonzero port is valid only for TCP
or UDP. Use default `DENY` with `ALLOW` rules for an allowlist, or default
`ALLOW` with `DENY` rules for a denylist. If multiple rules match, `DENY`
wins. Rules are stateless: for a default-deny TCP or UDP policy, use direction
`BOTH` when request and response traffic must both pass.

The current packet-policy scope is IPv4. IPv6 and other Ethernet protocols are
dropped while either a traffic or DNS policy is active; this prevents an IPv6
resolver from bypassing DNS enforcement. ARP remains allowed. IPv4 fragments
and IPv4 packets with header options are dropped while either packet or DNS
policy enforcement is active. v1 supports exact IP addresses, not CIDRs or
port ranges.

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
staged first, and one policy-map update switches the dataplane to that
generation. Old rules are deleted after the switch.

The eBPF maps are pinned under `/sys/fs/bpf/sandboxd/networkacl`, and TC keeps
program references across an unexpected sandboxd exit. On restart, sandboxd
reopens the maps, reconciles each active sandbox with its current host veth,
and replaces the filters. This avoids a fail-open window during recovery.
Normal sandbox deletion removes its policy, rules, and filters. Once all
sandboxes are gone, a normal sandboxd shutdown also removes the pinned maps.
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

Unit tests run with the normal test suite. The privileged dataplane, TC
lifecycle, restart-recovery, and uncached DNS proxy tests run with:

```sh
make networkacl-test
```
