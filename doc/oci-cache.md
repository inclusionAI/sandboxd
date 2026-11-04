# OCI cache retention

The sandboxd startup configuration controls the node-wide zero-reference TTL for extracted OCI layers and lowerdir chains:

```toml
[plugin.image]
oci_zero_ref_ttl = "0s"
```

An omitted or empty value keeps the default `30m` TTL. A positive Go duration such as `"2h"` changes the TTL. Zero disables time-based eviction. Negative, malformed, and overflowing durations are rejected during startup before image managers are initialized. The configuration is read at startup; changes require restarting sandboxd.

The TTL starts when the last reference is released. A new reference clears that timestamp; the next transition to zero references starts a new retention interval. Both layers and lowerdir chains use the same configured TTL. Referenced cache entries are protected from TTL and disk-pressure GC.

Background GC checks run every two minutes. With a positive TTL, zero-reference entries become eligible after that interval and are removed by a later check. With `"0s"`, disk-pressure GC remains enabled: at 85% filesystem usage it removes unreferenced entries in least-recently-used order, aiming for 75% usage or until no eligible entries remain. Disk pressure can evict an entry before a positive TTL has elapsed.

This setting does not change checkpoint retention, Nydus or distill-fs cache policies, or persistence when the image-manager root is replaced or deleted. It does not prefetch images or synchronize cache between nodes.
