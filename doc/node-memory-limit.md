# Optional aggregate sandbox memory limit

This opt-in cgroup v2 policy caps the configured sandbox parent (for example `/sandboxd` or `/akernel`) at startup and clips node-resource reporting to the same budget. It is disabled by default. Deployments select one total reserve and remain responsible for limits on components outside the parent.

```toml
[plugin.resource.memory_limit]
enabled = true
total_reserve = "22GiB"

[plugin.image]
cgroup_memory_limit = "64GiB"
```

These settings extend an existing sandboxd configuration. The public sample uses `/sandboxd`; AKernel deployments can select `/akernel` through `cgroup_root_name`. Reporting additionally requires `[plugin.node_resource]` with `sock_path` and a `cgroup` or `kubernetes` provider. Without that module, the parent hard limit still applies. The values above are examples, not production defaults. When enabled, `total_reserve` must be a positive finite integer byte count or use `B`, `KiB`, `MiB`, `GiB` or `TiB`; `auto` and percentages are unsupported. It combines the deployment's chosen system, control, other-component and safety allowances, without creating separate reservations or component limits. No current-use samples or historical peak database are required.

The calculation is:

```text
T = min(/proc/meminfo MemTotal, finite memory.max values on parent ancestors)
candidate = round_down_to_page(T - total_reserve)
actual_max = min(candidate, existing finite parent memory.max)
reported_capacity = min(provider_capacity, actual_max)
/resource Mem = reported_capacity - active transient reservations
```

Distill-fs retains its independent `[plugin.image].cgroup_memory_limit`. That limit is not automatically deducted from the sandbox parent's limit or scheduling capacity, and enabling the parent policy does not require a finite distill-fs limit. Operators who need distill-fs covered by their node budget must include its allowance in `total_reserve` themselves. Keeping distill-fs outside that total permits the sandbox and distill-fs limits to overcommit physical memory: without a shared finite ancestor or other node protection, their combined consumption can exhaust the host before either group reaches its own limit. Distill-fs's independent limit does not bound that combined consumption.

The parent's own old limit is excluded when calculating T, so restarts do not subtract the total reserve repeatedly. At a real hierarchy root there may be no `memory.max`; a Docker cgroup namespace root can expose a finite container limit, which is included. Only visible ancestors can be inspected: container memory limits must represent the delegated node budget if higher host ancestors are hidden. The control daemon's current group is not an ancestor of a sibling `/akernel`.

For example, T=64GiB and total_reserve=22GiB give candidate=42GiB, regardless of an independent distill-fs limit of 8GiB or 64GiB. If an existing parent cap is 32GiB, it is preserved and the reporting ceiling is 32GiB. A Kubernetes provider reporting 28GiB yields 28GiB: its already-reserved capacity is clipped, not reduced by the total reserve a second time. Sandbox live usage is not subtracted from this capacity; the scheduler already tracks sandbox allocations and subtracts them from capacity.

## Configuration migration

The memory policy accepts only `enabled` and `total_reserve`. The removed `system_reserve`, `control_reserve`, `other_reserve`, `safety_buffer` and `runtime_headroom` fields are rejected when present, including zero or empty values and configurations with `enabled=false`. Mixed old and new fields are also rejected, so upgrades cannot silently ignore an old reserve or release a nonzero scheduling allowance. Replace the old fields before starting the upgraded daemon.

To preserve the previous parent candidate, set `total_reserve` to the sum of the old system, control, other and safety values **plus the previously deducted distill-fs budget**. Resolve an old `control_reserve="auto"` to its intended finite allowance explicitly; the new policy does not inspect `system.slice` for that value. For example, old system=16GiB, control=2GiB, other=0, safety=4GiB and distill-fs=64GiB become total_reserve=86GiB to retain the old candidate. Choosing 22GiB instead deliberately stops reserving the 64GiB distill-fs allowance and increases the candidate by 64GiB, although an existing stricter cap remains unchanged.

There is no separate runtime headroom setting. With an old headroom of zero, migrating the parent reserve as above also preserves its reporting ceiling. A nonzero old headroom cannot preserve both the old hard limit and the lower reporting ceiling using one reserve: omitting it raises the reporting ceiling to the hard limit, while adding it to `total_reserve` also lowers the hard limit. Select the intended policy explicitly and review the rollout conditions below.

## Capacity reporting and upgrades

With `memory_limit.enabled=true`, cgroup-provider memory capacity comes from the managed sandbox parent and its ancestors rather than sandboxd's own service group. With the policy disabled, the provider continues to use sandboxd's own cgroup. CPU discovery is unchanged.

Cgroup and Kubernetes providers preserve byte precision instead of rounding down to whole GiB. This precision behavior also applies with `memory_limit.enabled=false`. For example, a provider capacity of 10.5GiB is reported as 10.5GiB rather than 10GiB. Final advertised capacity remains subject to provider policy, the optional parent ceiling and transient reservations. YuanRong converts resource units internally; its view may have a small conversion tolerance.

## Parent memory metrics

When the node-resource module and cgroup manager are enabled, sandboxd exports the configured sandbox parent's live cgroup v2 memory values over its existing OTLP metrics connection. The OTel Collector can forward them to Prometheus with its existing remote-write pipeline; this does not add a second sandboxd `/metrics` endpoint. The reader uses `cgroup_root_name` and the selected backend mountpoint, rather than hardcoding `/akernel` or reading the hierarchy root `/`.

| OTel gauge | Prometheus name | Value |
| --- | --- | --- |
| `sandbox.parent.memory.current` | `sandbox_parent_memory_current_bytes` | The parent's `memory.current`, including descendants and cached charges. |
| `sandbox.parent.memory.max` | `sandbox_parent_memory_max_bytes` | The same parent's finite numeric `memory.max`. |

Both gauges use bytes and carry the `cgroup_path` attribute, such as `/sandboxd` or `/akernel`, alongside the existing node resource identity. A single callback reads one parent snapshot for the pair. These observations are independent of `memory_limit.enabled`: an existing finite kernel limit can be monitored without enabling automatic budget configuration. They read live kernel state, not the startup `MemoryLimit()` cache or the resource provider's schedulable capacity.

The first implementation supports cgroup v2. An absent reader, cgroup v1, a missing or malformed control file, a limit observed changing during the read, literal `memory.max=max`, or a value outside the signed 64-bit OTel range produces no pair. Errors are not reported as idle zero usage. Numeric `memory.current=0` and numeric `memory.max=0` remain valid raw observations; a zero maximum does not define a utilization ratio. Current usage may temporarily exceed a finite maximum and is not clamped.

Consumers must require a complete, fresh pair from each current node source and matching `cgroup_path`, reject nonpositive maxima, and treat missing data as unknown. In particular, Prometheus can retain previous samples after an observation stops; omission is not immediate invalidation, and a retained value must not be treated as a fresh reading or as zero. Source, membership or limit changes require rebuilding any decision observation window.

For one node the occupancy ratio is `current / max`. Across a pool, use `sum(current) / sum(max)` over the same complete node set before averaging over time. This ratio includes reclaimable cache and is not interchangeable with a working-set or `MemTotal-MemAvailable` pressure ratio. Thresholds need to account for that distinction.

The new gauges do not change the parent budget, `/resource.mem`, `node.memory.total`, individual sandbox metrics, or scheduler allocation accounting. They neither add Firecracker checkpoint sibling usage to the parent nor subtract live usage from advertised scheduling capacity.

## Startup and rollout

With the policy enabled, sandboxd writes `memory.max` only when adding a finite limit to an unlimited parent or lowering an existing finite limit. Both cases require the entire sandbox subtree to have no processes and residual `memory.current` to be no greater than the new limit. Startup refuses the change before writing if these conditions are not met; rollout runbooks must drain the subtree before either operation.

An existing finite cap that is equal to or lower than the computed candidate can be reused with live sandboxes. A higher candidate, for example after memory hot-add or a reduction in the total reserve, does not automatically raise the existing stricter cap. Draining and restarting alone does not raise it either; increasing an existing cap requires a separate operator-managed change.

Assuming the remaining configuration is valid, the following cases apply when the sandbox subtree still has processes:

| Existing `memory.max` | New candidate | Startup behavior |
| --- | --- | --- |
| `max` | 42GiB | Refuse startup; drain before adding the finite cap. |
| 42GiB | 40GiB | Refuse startup; drain before lowering the cap. |
| 42GiB | 42GiB | Reuse 42GiB without rewriting the cap. |
| 42GiB | 46GiB | Retain 42GiB without rewriting the cap. |

Startup refuses invalid configuration, exhausted reserves, missing controllers, failed writes and mismatched readback. The implementation changes only `memory.max`; `memory.high`, swap policy and group OOM policy retain existing settings. Policy changes are evaluated on a controlled restart.

New nodes with the same image and configuration calculate T at startup; different node sizes therefore receive different caps without a per-node hardcoded limit. The total reserve remains deployment policy and must be updated when component allowances change. The total reserve does not constrain outside components, so this feature cannot guarantee avoidance of all host OOMs. Continue enforcing their deployment limits and monitoring node memory pressure.
