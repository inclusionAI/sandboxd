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
bpffs mount, so it is intentionally not part of the default GitHub CI
workflow.

When changing bpfnat behavior, extend the regular unit tests for pure parsing
and policy logic and add or update the tagged integration tests for
kernel-visible behavior and relevant boundary cases.

# Runtime Artifact Pins

`third_party/runtime-versions.env` is the single source of truth for runtime
artifacts used by sandboxd E2E and packaged by AKernel. Keep each release,
download URL, and checksum synchronized. Do not duplicate runtime versions in
CI workflow environment variables or Dockerfiles.

The AKernel gVisor release is a temporary compatibility build based on an
upstream release tag. It currently carries the direct-TAP `readv` seccomp fix
and the KVM address-width fix for hosts without LA57. When updating gVisor,
first check whether upstream already includes both fixes and remove downstream
patches that are no longer required.

Build a gVisor candidate through the gated workflow in
`akernel-dev/gvisor`, then test that exact candidate with the complete
sandboxd runtime suite and the AKernel standalone E2E. Promote the candidate
without rebuilding it. Only after promotion should this repository pin the
published release URL and its verified SHA-512 digest.
