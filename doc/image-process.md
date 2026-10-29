# Injected OCI image startup

`StartRequest.inject_entrypoint` is the absolute in-sandbox path where sandboxd
injects an OCI or Nydus image's startup process configuration. An empty string
disables injection. A non-empty value is valid only when the sandbox rootfs
type is `IMAGE`; it does not change the sandbox's own command or lifecycle.

The image manager extracts `Entrypoint`, `Cmd`, `WorkingDir`, and `User` from
the OCI image config. sandboxd applies Docker's effective argv rule:

- a non-empty `Entrypoint` is followed by all `Cmd` elements;
- without `Entrypoint`, `Cmd` is the complete argv;
- when both are empty, `args` is an empty array.

Array elements are preserved exactly. sandboxd does not invoke a shell, split
strings, or expand environment variables. An empty working directory becomes
`/`.

When the option is enabled, sandboxd atomically writes this versioned JSON in
the sandbox's private `sandbox-files` directory:

```json
{
  "version": 1,
  "args": ["/usr/local/bin/docker-entrypoint.sh", "server"],
  "cwd": "/app",
  "user": "1000:1000"
}
```

The JSON file is bind-mounted read-only at the exact path supplied in
`inject_entrypoint`, for example:

```protobuf
inject_entrypoint: "/run/yuanrong/image-process.json"
```

The path must be an absolute, canonical file path and cannot be `/`. User mounts
that cover the configured path are rejected. sandboxd does not add a discovery
environment variable; the in-sandbox runtime owns how it discovers the path.

The in-sandbox runtime owns process execution and waiting. It must reject
unsupported versions, apply `cwd` and `user`, and cache the child's terminal
status. The child exiting does not terminate the sandbox or disable later exec
and file operations.

OCI and Nydus caches persist the extracted metadata. Records created by older
sandboxd versions are upgraded lazily only when inherited startup is requested,
so ordinary cached image mounts remain usable without registry access.
# Immutable ROFS metadata reuse

The existing OCI image provider retains resolved process configuration and layer/chain identities for digest-pinned references in its own metadata database after unmount. A subsequent mount can reuse verified local extracted layers without contacting the registry. Mutable tags continue through the registry path. Cached metadata holds no layer references, so normal layer GC remains effective; missing cached file data triggers the authenticated registry path and partial reservations are rolled back. Nydus images continue through the existing Nydus/ROFS provider without conversion or a second Harbor-managed image cache.
