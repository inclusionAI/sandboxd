// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cgroupmanager

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
)

// WorkloadsEmpty verifies that the owned cgroup v2 subtree and the optional
// runtime sibling have no processes, including processes absent from runtime
// inventories. A missing owned cgroup is never evidence of an empty node.
func (c *CgroupManager) WorkloadsEmpty(sibling string) (bool, error) {
	v2, ok := c.ops.(*cgroupV2)
	if !ok {
		return false, fmt.Errorf("workload emptiness requires a cgroup v2 hierarchy")
	}
	root := filepath.Join(v2.mountpoint, c.rootName)
	populated, err := readCgroupPopulated(filepath.Join(root, "cgroup.events"))
	if err != nil || populated || sibling == "" {
		return err == nil && !populated, err
	}
	sibling, err = normalizeCgroupRoot(sibling)
	if err != nil {
		return false, err
	}
	dir := filepath.Join(v2.mountpoint, sibling)
	populated, err = readCgroupPopulated(filepath.Join(dir, "cgroup.events"))
	if os.IsNotExist(err) {
		// An absent sibling is expected before the first checkpoint. A
		// present sibling with unreadable or missing controls is unknown.
		if _, statErr := os.Stat(dir); os.IsNotExist(statErr) {
			return true, nil
		}
	}
	return err == nil && !populated, err
}

// Prepare applies the per-sandbox controls to an allocated, already-clean
// cgroup. Cleanup and OOM state reset happen when the previous owner recycles
// the cgroup.
func (c *CgroupManager) Prepare(
	name string,
	resource *runtime.LinuxSandboxResources,
) error {
	if !belongsToRoot(name, c.rootName) || !c.usingID.Has(name) {
		return fmt.Errorf("cgroup %s is not an allocated child of %s", name, c.rootName)
	}
	if err := c.ops.update(name, sandboxResources(resource)); err != nil {
		return fmt.Errorf("update cgroup %s: %w", name, err)
	}
	return nil
}

// OOMKilled reports the flag maintained by the manager-level kernel watcher.
func (c *CgroupManager) OOMKilled(name string) (bool, error) {
	if !belongsToRoot(name, c.rootName) ||
		!c.cgroups.Has(name) ||
		!c.usingID.Has(name) {
		return false, fmt.Errorf("cgroup %s is not an active child of %s", name, c.rootName)
	}
	return c.oom.OOMKilled(name)
}

type oomLeaseWatcher interface {
	OOMEvent(string) (<-chan struct{}, error)
	killOnOOM(string, <-chan struct{}, func() error) error
}

// ErrStaleOOMLease means the notification belongs to a released/reused lease.
var ErrStaleOOMLease = errors.New("stale cgroup OOM lease")

// OOMEvent closes on the first OOM of this lease, independently of runtime
// exit. Cached cgroups receive a fresh event channel when reset.
func (c *CgroupManager) OOMEvent(name string) (<-chan struct{}, error) {
	if !belongsToRoot(name, c.rootName) || !c.usingID.Has(name) {
		return nil, fmt.Errorf("cgroup %s is not active", name)
	}
	w, ok := c.oom.(oomLeaseWatcher)
	if !ok {
		return nil, fmt.Errorf("cgroup OOM notifications unavailable")
	}
	return w.OOMEvent(name)
}

// KillOnOOM drains a failed sandbox while holding its OOM lease against reset.
// Delayed notifications cannot kill a reused cached cgroup.
func (c *CgroupManager) KillOnOOM(name string, event <-chan struct{}) error {
	w, ok := c.oom.(oomLeaseWatcher)
	if !ok {
		return fmt.Errorf("cgroup OOM notifications unavailable")
	}
	return w.killOnOOM(name, event, func() error { return c.Kill(name) })
}

// Kill drains only an allocated child. It does not release the lease; runtime
// cleanup must succeed before resource accounting can be recycled.
func (c *CgroupManager) Kill(name string) error {
	if !belongsToRoot(name, c.rootName) || !c.cgroups.Has(name) || !c.usingID.Has(name) {
		return fmt.Errorf("cgroup %s is not an active child of %s", name, c.rootName)
	}
	return c.ops.kill(name)
}

// Stats loads normalized accounting for a sandbox path or the logical root
// path "/".
func (c *CgroupManager) Stats(name string) (Stats, error) {
	if name != "/" && !belongsToRoot(name, c.rootName) {
		return Stats{}, fmt.Errorf("cgroup %s is outside owned root %s", name, c.rootName)
	}
	return c.ops.stat(name)
}

// ReadMemoryLimit reports the current memory.max (cgroup v2) or
// memory.limit_in_bytes (cgroup v1) of the named cgroup in bytes.
// Callers use it to validate live kernel state against their persisted
// steady-state limit; it must not be treated as that steady-state source
// because it may include a transient expansion left by a previous process.
func (c *CgroupManager) ReadMemoryLimit(name string) (int64, error) {
	stats, err := c.Stats(name)
	if err != nil {
		return 0, err
	}
	return int64(stats.MemoryLimitBytes), nil
}
