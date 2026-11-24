# OCI cache retention

Multi-layer OCI root filesystems use a read-only OverlayFS mount. Sandboxd checks the serialized options against the running kernel's legacy `mount(2)` limit of one page minus one byte. Larger lists use the kernel's `fsconfig` `lowerdir+` interface with one path per layer in priority order. The kernel and the sandboxd mountinfo reader must be able to represent the full list. If they cannot, preparation fails with the applicable limit. Sandboxd verifies the mounted layer order before publishing the mount or adopting it on restart.

Single-layer images use read-only bind mounts. Sandboxd verifies the mount's read-only flag before publishing or reusing it, including when recovering a mount interrupted during its initial setup.

If cleanup of an unpublished mount fails, sandboxd retains its transaction and holds its layer references. A later request for that image retries cleanup before allocating another mount. Teardown leaves stacked mount targets and their records in place until the stack is resolved, and removes only empty mount directories. Sandboxd releases the mount record and its layer references together after detaching the mount. If the metadata update fails, teardown can retry while the detached path remains unavailable for reuse.

The sandboxd startup configuration controls the node-wide zero-reference TTL for extracted OCI layers and lowerdir chains:

```toml
[plugin.image]
oci_zero_ref_ttl = "0s"
```

An omitted or empty value keeps the default `30m` TTL. A positive Go duration such as `"2h"` changes the TTL. Zero disables time-based eviction. Negative, malformed, and overflowing durations are rejected during startup before image managers are initialized. The configuration is read at startup; changes require restarting sandboxd.

The TTL starts when the last reference is released. A new reference clears that timestamp; the next transition to zero references starts a new retention interval. Both layers and lowerdir chains use the same configured TTL. Referenced cache entries are protected from TTL and disk-pressure GC.

Background GC checks run every two minutes. With a positive TTL, zero-reference entries become eligible after that interval and are removed by a later check. With `"0s"`, disk-pressure GC remains enabled: at 85% filesystem usage it removes unreferenced entries in least-recently-used order, aiming for 75% usage or until no eligible entries remain. Disk pressure can evict an entry before a positive TTL has elapsed.

This setting does not change checkpoint retention, Nydus or distill-fs cache policies, or persistence when the image-manager root is replaced or deleted. It does not prefetch images or synchronize cache between nodes.
