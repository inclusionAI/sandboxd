# CI Checks

Before completing a change, run the checks relevant to it:

```sh
make check-fmt
make vet
make test
```

For protobuf changes, also run:

```sh
make check-protos
```

For changes under `bpf/bpfnat` or `pkg/networkmanager/bpfnat`, also run:

```sh
make check-bpf
make bpfnat-test
```

`make bpfnat-test` runs privileged dataplane, map, garbage-collection,
restart, and lifecycle tests in an isolated container network namespace and
bpffs mount. The default GitHub CI workflow runs it in the network dataplane
job.

When changing bpfnat behavior, extend the regular unit tests for pure parsing
and policy logic and add or update the tagged integration tests for
kernel-visible behavior and relevant boundary cases.

# Markdown and GitHub Text Formatting

Do not hard-wrap prose in Markdown documentation, GitHub pull request bodies, release descriptions, issue comments, or pull request review comments. Keep each paragraph and list item on a single logical line and let the renderer handle visual wrapping. Preserve line breaks that carry Markdown meaning, such as paragraph boundaries, lists, tables, blockquotes, and code blocks.

Git commit message bodies are the exception and should remain wrapped at approximately 72 characters as required by the repository commit rules.

# Runtime Artifact Pins

`third_party/runtime-versions.env` is the single source of truth for runtime
artifacts used by sandboxd E2E and packaged by AKernel. Keep each release,
download URL, and checksum synchronized. Do not duplicate runtime versions in
CI workflow environment variables or Dockerfiles.

gVisor is installed from the complete `gvisor.tar.bz2` release archive. Its SHA-512 pin covers the archive, not the individual runsc binary. Use `third_party/install-gvisor.sh` to validate and install runsc, the containerd shim and all `gvisor-bin/` sidecars together, preserving the adjacent directory layout. Do not mix sidecars from different releases or fall back to downloading them at runtime.

The AKernel gVisor release is a temporary compatibility build based on an upstream release tag. It carries direct-TAP compatibility fixes, the KVM address-width fix for hosts without LA57, and Docker bridge checkpoint/restore support. When updating gVisor, check which fixes upstream already includes and remove downstream patches that are no longer required. Docker bridge support does not imply support for every Docker networking mode; retain the upstream Docker-in-gVisor constraints.

Build a gVisor candidate through the gated workflow in
`akernel-dev/gvisor`, then test that exact candidate with the complete
sandboxd runtime suite and the AKernel standalone E2E. Promote the candidate
without rebuilding it. Only after promotion should this repository pin the
published release URL and its verified SHA-512 digest.

The AKernel Firecracker release is a checksum-pinned runtime bundle from
`akernel-dev/firecracker`. It reuses the official VMM binary and packages the
tested guest kernel, resolved configuration, licenses, checksums, and
provenance. Build and test an expiring candidate with sandboxd and AKernel,
then promote those exact bytes without rebuilding them. Only after promotion
should this repository update the bundle release, URL, and SHA-256 pin. The
sandboxd-built `firecracker-agent` initrd deliberately remains outside that
bundle so its guest protocol always matches the consuming sandboxd revision.

Run the complete runtime compatibility suite on a nested-KVM host with:

```sh
make e2e-runtime-suite
```

The suite builds the project binaries once, assembles targeted runtime images, and tests runsc with systrap, runsc with KVM, Kata, Firecracker, and runc. CI passes those binaries to seven independent matrix jobs. Both runsc platforms run the shared writable host-mount C/R regression. The Firecracker virtio-fs job runs it with EROFS and directory roots, using the manifest-pinned virtiofsd source; the full and incremental non-virtio-fs jobs remain separate. Keep the gVisor TAP contract, network ACL cases, and AKernel's shared manifest consumer in sync when changing this path.

# Checkpoint and Restore Contract

When changing the checkpoint/restore API, runtime support, artifact ownership,
compatibility requirements, or failure semantics, update
`doc/checkpoint-restore.md` in the same change so the public design contract
stays synchronized with the implementation.

# Firecracker Storage Contract

The Firecracker adapter uses local or image-provider-backed regular EROFS files by default. An operator may enable virtio-fs with `plugin.runtime.firecracker.virtiofs_enabled`; that path accepts directory root filesystems and explicitly `ro` or `rw` host directory mounts through one sandbox-scoped virtiofsd. Root image exports always remain read-only, enforced recursively on host staging mounts with `mount_setattr` (Linux 5.12+). The staging root is read-only and virtiofsd writeback caching remains disabled. OCI and Nydus root filesystems require virtio-fs and are consumed directly from the image manager; never eagerly materialize them as EROFS. OCI image mounts remain unsupported.

Per-sandbox managed storage comprises the private ext4 writable layer, virtio-fs staging and restored live-memory files, and runtime state. Host directory binds remain caller-owned: deleting a sandbox never deletes their contents, and `storage_mb` does not bound them. Writable host mounts support local checkpoint/restore only while the original backing directories and referenced files remain available; their contents are not snapshotted or rolled back. Do not recreate missing files or imply cross-node portability or automatic new log segments. Bounded read-only regular-file injection remains a separate startup-metadata mechanism for files such as `resolv.conf`.
