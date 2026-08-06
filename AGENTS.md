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
