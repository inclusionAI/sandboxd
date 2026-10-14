# Resource utilization

Implemented from [RFC #49](https://github.com/inclusionAI/sandboxd/issues/49).

When `[plugin.node_resource]` is configured, the existing Unix HTTP endpoint `GET /resource` reports cached utilization alongside scheduler capacity. For example:

```json
{
  "cpu": 32,
  "mem": 68719476736,
  "xpu": [],
  "storage": 17179869184,
  "features": ["storage-quota-v1"],
  "utilization": {
    "cpu": 0.92,
    "memory": 0.87,
    "pid": 0.88,
    "fd": 0.22,
    "disk": 0.75
  }
}
```

All five utilization fields are always present. Values are fractions from 0 to 1, clamped at 1 when consumption exceeds a limit. `null` means no usable observation; zero is a valid observation. CPU needs two samples, so it is initially `null`. The example values are illustrative.

## Sampling

The existing resource refresh loop samples every five seconds. HTTP requests read the latest cache and do not collect metrics. Sampling is read-only, works with either the Kubernetes or cgroup capacity provider, and does not require an additional configuration section.

| Field | Sources and calculation |
| --- | --- |
| `cpu` | Maximum of host busy-time fraction and applicable finite cgroup quota utilization. Host busy time uses deltas from `/proc/stat`, excludes idle and iowait, and avoids counting guest time twice. Cgroup CPU time delta is divided by elapsed time and that cgroup's quota in cores. |
| `memory` | Maximum of host `(MemTotal - MemAvailable) / MemTotal` and cgroup usage divided by a finite limit. Host fields come from `/proc/meminfo`. Cgroup usage includes charged cache. |
| `pid` | Maximum `pids.current / pids.max` across the sampled cgroups. Counts tasks, including threads. An unlimited or unavailable limit supplies no ratio. |
| `fd` | Maximum of `(allocated - unused) / maximum` from `/proc/sys/fs/file-nr` and the number of entries in `/proc/self/fd` divided by sandboxd's soft open-file limit from `/proc/self/limits`. System file handles and process descriptors are distinct constraints. |
| `disk` | `1 - Bavail / Blocks` from the same `statfs(FilestoreDir)` snapshot as `storage`, before storage overcommit. Without a usable filestore snapshot this is `null`. |

Cgroup sampling covers the daemon's own cgroup and visible ancestors. When sandboxd cgroup management is enabled, it also includes the configured sandbox root and its visible ancestors. Each ratio pairs usage and limit at the same cgroup. Discovery follows the visible mounts on each sample, supports cgroup v1 and v2, and does not enumerate individual sandbox cgroups.

For v2, CPU uses `cpu.stat` and `cpu.max`, memory uses `memory.current` and `memory.max`, and tasks use `pids.current` and `pids.max`. For v1, CPU uses `cpuacct.usage` with `cpu.cfs_quota_us` / `cpu.cfs_period_us`, and memory uses `memory.usage_in_bytes` / `memory.limit_in_bytes`. Split v1 CPU and accounting mounts must have matching membership. Unlimited v1 memory sentinels are ignored.

If one source is unavailable, other valid sources for that metric remain usable. A failed CPU read, counter reset, or changed quota restarts that source's delta baseline. An unavailable metric does not fail the resource response or change the module's liveness check. Existing scheduler-capacity caching remains intact when its provider fails.

## Storage identity and coverage

`disk` describes precisely the filesystem backing the reported `storage`. With loop-backed filestore, this is the mounted loop filesystem. With ordinary directory mode, it is the filesystem containing `FilestoreDir`. It measures physical space unavailable to ordinary allocations, including filesystem reservations. Changing the storage overcommit ratio changes advertised bytes but leaves disk occupancy unchanged.

Metrics reflect only the procfs and cgroup hierarchy visible to sandboxd. CPU saturation caused solely by cpuset restrictions is not measured separately. Without a finite cgroup task limit, `pid` is `null`; it does not estimate exhaustion from the largest PID. FD reporting covers system file handles and sandboxd itself, not every control-plane process. Disk occupancy does not measure inode exhaustion, directory quota, or I/O pressure.

## External scheduler use

An existing external collector can read the whole utilization object from the same resource query. Treat observations as advisory protection signals. The scheduler owns thresholds, pressure reasons, and isolation/recovery counters; sandboxd does not mark a node unschedulable. Consumers must tolerate absent utilization from older sandboxd versions, `null` values, and future unknown fields.

FunctionSystem integration is separate follow-up work. Its consumer can track specific CPU, memory, PID, FD, and disk pressures, require sustained high observations to enter isolation, and recover after fewer low observations. Recovery should clear only the relevant pressure while preserving lifecycle and manual isolation.

## Validation

The unit suite includes deterministic procfs fixtures, both cgroup versions, ancestor usage/limit pairing, CPU baseline changes, null/zero handling, and storage overcommit independence. Unix socket tests check the cached JSON contract. `TestModuleLiveUtilizationOverUnixSocket` exercises real Linux procfs and filestore statistics through the periodic sampler and HTTP endpoint, using a stub for the independent scheduler-capacity provider.

```sh
go test -race ./pkg/resourcemanager ./pkg/volumemanager
go test -v ./pkg/resourcemanager -run TestModuleLiveUtilizationOverUnixSocket
make check-fmt
make vet
make test
```
