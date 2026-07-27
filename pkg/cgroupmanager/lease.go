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
	"fmt"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
)

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

// Stats loads normalized accounting for a sandbox path or the logical root
// path "/".
func (c *CgroupManager) Stats(name string) (Stats, error) {
	if name != "/" && !belongsToRoot(name, c.rootName) {
		return Stats{}, fmt.Errorf("cgroup %s is outside owned root %s", name, c.rootName)
	}
	return c.ops.stat(name)
}
