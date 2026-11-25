# OCI cache retention

Multi-layer OCI root filesystems use a read-only OverlayFS mount. Sandboxd checks the serialized options against the running kernel's legacy `mount(2)` limit of one page minus one byte. Larger lists first use `fsconfig` with one `lowerdir+` option per layer in priority order. Sandboxd can retry with a single legacy `lowerdir=` list if structured setup rejects the representation or the mountinfo reader cannot verify a line that long. The shorter paths use a symlink to the existing chain cache and preserve the same layers and cache references.

The compatibility path creates a symlink per mount under the private `/run/sandboxd-oci` directory. Keep this directory writable by sandboxd and available for as long as the mounts survive, including across daemon restarts. Sandboxd verifies the symlink's destination and the read-only ordered layer list before publishing or adopting a compact mount. The mount journal covers symlink cleanup after a failed attempt or restart, and normal teardown removes the symlink after detaching the mount. If the compact options still exceed the byte limit, preparation fails with the required size, the budget, and any available kernel diagnostic.

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
