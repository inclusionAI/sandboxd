# Initial process UID/GID

`StartRequest.process_user` selects the numeric UID and primary GID of the sandbox's initial process. Both fields are unsigned 32-bit numbers; Linux's reserved value `4294967295` is rejected. No username lookup is performed, so the IDs need not appear in the guest's passwd/group databases.

```json
{"process_user": {"uid": 1000, "gid": 1000}}
```

```sh
sbox start --rootfs /srv/rootfs --user 1000:1000 --mount /srv/users/alice:/home/agentos:bind:rbind,rw /bin/sh -c 'id; exec /opt/agentos/bin/agentserver'
sbox inspect <sandbox-id>
```

Omitting `process_user` preserves the OCI base user, including its supplementary groups and umask. The default base user is root (`0:0`). Explicit `{"uid":0,"gid":0}` selects root even when the base user is non-root. A fresh override clears the previous user's supplementary groups and name and retains the base umask and capabilities. Deployers remain responsible for configuring capabilities, user namespaces and other security policy; selecting a non-root UID is not a complete isolation policy.

The common OCI loader forwards the identity to runsc, runc and Kata. Firecracker maps the resulting OCI UID/GID into the guest process credentials. `SandboxStatus.process_user` (also returned by `sbox inspect`) reports the configured initial identity from the saved OCI bundle, including after daemon recovery. It is not a live credential inspection: applications may change their own identity after startup. `sbox exec` keeps its existing runtime-specific defaults; use its explicit `--user UID:GID` option when a particular exec identity is required.

Sandboxd does not create passwd/group entries, set HOME, change mount ownership or recursively chown caller-owned storage. For AgentOS, the deployer must prepare the user's shared directory with suitable ownership and access before mounting it; the AgentServer and tool sandbox each choose their own startup identity. Supplementary groups and per-exec defaults are outside this API's scope.

Checkpoints produced by this version include `sandboxd-process-user.json`, recording the complete initial OCI user, including supplementary groups and umask. Restore without `process_user` uses that identity; an explicit matching UID/GID is accepted and conflicting IDs fail before resource allocation. Application credential changes are preserved by the runtime snapshot. Older checkpoints without the metadata retain the historical restore path when `process_user` is omitted; an explicit override is rejected because its consistency cannot be verified. These checks do not authenticate caller-owned checkpoint artifacts or replace the runtime's compatibility checks.

Deploy the new server before using the new field. Older protobuf clients continue to work with the new server. Older servers may ignore the unknown field, so a new client must not assume it is enforced by an older server. No server capability negotiation is added by this change.
