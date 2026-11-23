# Initial process UID/GID

`StartRequest.process_user` configures the numeric UID and primary GID in the target OCI bundle. Fresh starts use these values to launch the initial process. Both fields are unsigned 32-bit numbers; Linux's reserved value `4294967295` is rejected. No username lookup is performed, so the IDs need not appear in the guest's passwd/group databases.

```json
{"process_user": {"uid": 1000, "gid": 1000}}
```

```sh
sbox start --rootfs /srv/rootfs --user 1000:1000 --mount /srv/users/alice:/home/agentos:bind:rbind,rw /bin/sh -c 'id; exec /opt/agentos/bin/agentserver'
sbox inspect <sandbox-id>
```

Omitting `process_user` preserves the OCI base user, including its supplementary groups and umask. The default base user is root (`0:0`). Explicit `{"uid":0,"gid":0}` selects root even when the base user is non-root. A fresh override clears the previous user's supplementary groups and name and retains the base umask and capabilities. Deployers remain responsible for configuring capabilities, user namespaces and other security policy; selecting a non-root UID is not a complete isolation policy.

The common OCI loader forwards the identity to runsc, runc and Kata. Firecracker maps the resulting OCI UID/GID into the guest process credentials. `SandboxStatus.process_user` (also returned by `sbox inspect`) reports the user configured in the persisted OCI bundle, including after daemon recovery. This is configuration information: applications may change credentials, and a restored snapshot may contain credentials that differ from the destination bundle. Use an in-guest query when actual process credentials are required. `sbox exec` keeps its existing runtime-specific defaults; use its explicit `--user UID:GID` option when a particular exec identity is required.

Sandboxd does not create passwd/group entries, set HOME, change mount ownership or recursively chown caller-owned storage. For AgentOS, the deployer must prepare the user's shared directory with suitable ownership and access before mounting it; the AgentServer and tool sandbox each choose their own startup identity. Supplementary groups and per-exec defaults are outside this API's scope. Shared-storage acceptance must use the deployed client and export options; local bind tests alone do not establish NFS or MooseFS permission behavior.

Checkpoint and restore preserve process credentials through the runtime snapshot. The caller may supply `process_user` to configure the target OCI bundle for restore, or omit it to retain the base user. The field does not rewrite credentials captured in the snapshot. Callers maintain compatible target configuration, business identity and shared-storage permissions. Runtime compatibility checks still apply: runsc requires the target OCI User to match its checkpoint spec; Firecracker resumes guest credentials from VM state.

AgentOS ships sandboxd and ADX as a tested pair in the same release package and upgrades or rolls them back together. Release packaging and deployment establish compatible versions before identity forwarding is enabled. Older protobuf clients continue to work with the new server. Older servers may ignore the new field, so other integrations must establish server support before using it.

Firecracker creates its checkpoint handoff FIFO and restore-environment file with mode `0600`, owned by the initial process UID/GID. Ownership is retained when the FIFO is replaced or recreated and when restore publishes a new environment file.
