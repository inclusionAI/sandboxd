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
	"os"
	"path"
	"path/filepath"
	"strings"

	cgroups "github.com/containerd/cgroups/v3"
	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
)

const defaultUnifiedMountpoint = "/sys/fs/cgroup"

var requiredV2Controllers = []string{"cpu", "cpuset", "memory", "pids"}

// Stats is the cgroup-version-neutral subset exposed by sandboxd's public
// Stats RPC and sandbox metrics.
type Stats struct {
	CPUUsageNS          uint64
	CPUKernelNS         uint64
	CPUUserNS           uint64
	MemoryUsageBytes    uint64
	MemoryLimitBytes    uint64
	MemoryMaxUsageBytes uint64
}

// driver isolates cgroup-version-specific kernel operations from the shared
// allocation pool. It intentionally remains package-private.
type driver interface {
	PrepareRoot(root string) error
	Create(path string, pidsMax int64) error
	List(root string) ([]string, error)
	Update(path string, resources *runtime.LinuxSandboxResources) error
	Stats(path string) (Stats, error)
	WatchOOM(path string, onOOM func()) (func(), error)
	Kill(path string) error
	Delete(path string) error
}

func newDriver(cfg config.ResourceConfig) (driver, error) {
	normalized, err := config.NormalizeCgroupVersion(cfg.CgroupVersion)
	if err != nil {
		return nil, err
	}
	switch normalized {
	case config.CgroupVersionV1:
		return newV1Driver(), nil
	case config.CgroupVersionV2:
		parent, err := config.NormalizeCgroupParent(normalized, cfg.CgroupParent)
		if err != nil {
			return nil, err
		}
		root, err := resolvedCgroupRoot(cfg)
		if err != nil {
			return nil, err
		}
		return newV2Driver(defaultUnifiedMountpoint, parent, root), nil
	default:
		return nil, fmt.Errorf("unsupported cgroup version %q", normalized)
	}
}

func resolvedCgroupRoot(cfg config.ResourceConfig) (string, error) {
	rootName := cfg.CgroupRootName
	if rootName == "" {
		rootName = config.DefaultCgroupRoot
	}
	version, err := config.NormalizeCgroupVersion(cfg.CgroupVersion)
	if err != nil {
		return "", err
	}
	if version == config.CgroupVersionV1 {
		return rootName, nil
	}
	parent, err := config.NormalizeCgroupParent(version, cfg.CgroupParent)
	if err != nil {
		return "", err
	}
	component := strings.Trim(rootName, "/")
	if component == "" || component == "." || component == ".." || strings.Contains(component, "/") || strings.ContainsRune(component, '\\') {
		return "", fmt.Errorf("cgroup_root_name %q must be a single non-empty component for cgroup v2", rootName)
	}
	root := path.Join(parent, component)
	if root == parent {
		return "", fmt.Errorf("cgroup root %q must be below cgroup_parent %q", root, parent)
	}
	return root, nil
}

func cgroupPathOnMount(mountpoint, group string) string {
	return filepath.Join(mountpoint, strings.TrimPrefix(group, "/"))
}

// ValidateHost verifies the explicitly selected cgroup mode before any
// resource-pool goroutines start. Empty remains the historical v1 default.
func ValidateHost(cfg config.ResourceConfig) error {
	return validateHost(cfg, cgroups.Mode(), defaultUnifiedMountpoint)
}

func validateHost(cfg config.ResourceConfig, mode cgroups.CGMode, mountpoint string) error {
	normalized, err := config.NormalizeCgroupVersion(cfg.CgroupVersion)
	if err != nil {
		return err
	}
	switch normalized {
	case config.CgroupVersionV1:
		if mode == cgroups.Unified || mode == cgroups.Unavailable {
			return fmt.Errorf("cgroup_version %q requires a cgroup v1 hierarchy, detected mode %v", normalized, mode)
		}
		return nil
	case config.CgroupVersionV2:
		if mode != cgroups.Unified {
			return fmt.Errorf("cgroup_version %q requires a unified cgroup v2 hierarchy, detected mode %v", normalized, mode)
		}
		parent, err := config.NormalizeCgroupParent(normalized, cfg.CgroupParent)
		if err != nil {
			return err
		}
		return validateV2Delegation(cgroupPathOnMount(mountpoint, parent))
	default:
		return fmt.Errorf("unsupported cgroup version %q", normalized)
	}
}

func validateV2Delegation(mountpoint string) error {
	return validateV2DelegationWithProbe(mountpoint, func(parent string) (string, func() error, error) {
		probe, err := os.MkdirTemp(parent, ".sandboxd-cgroup-v2-probe-")
		return probe, func() error { return os.Remove(probe) }, err
	})
}

func validateV2DelegationWithProbe(mountpoint string, createProbe func(string) (string, func() error, error)) error {
	if err := validateV2ParentControllers(mountpoint); err != nil {
		return fmt.Errorf("validate delegated cgroup v2 parent at %s: %w", mountpoint, err)
	}

	// A writable hierarchy is not necessarily delegated: mkdir may succeed
	// while writes to cgroup.subtree_control fail. Exercise the exact nested
	// operation sandboxd needs when it creates <root>/<sandbox-id>.
	probe, removeProbe, err := createProbe(mountpoint)
	if err != nil {
		return fmt.Errorf("cgroup v2 hierarchy is not writable at %s (run with privileged host cgroup namespace and disable Enhanced Container Isolation): %w", mountpoint, err)
	}
	if err := enableV2Controllers(probe); err != nil {
		_ = removeProbe()
		return fmt.Errorf("cgroup v2 hierarchy is not delegated at %s (run with privileged host cgroup namespace and disable Enhanced Container Isolation): %w", probe, err)
	}
	if err := removeProbe(); err != nil {
		return fmt.Errorf("remove cgroup v2 delegation probe %s: %w", probe, err)
	}
	return nil
}

func validateV2ParentControllers(groupPath string) error {
	data, err := os.ReadFile(filepath.Join(groupPath, "cgroup.controllers"))
	if err != nil {
		return fmt.Errorf("read cgroup v2 controllers: %w", err)
	}
	available := make(map[string]bool)
	for _, controller := range strings.Fields(string(data)) {
		available[controller] = true
	}
	subtreeData, err := os.ReadFile(filepath.Join(groupPath, "cgroup.subtree_control"))
	if err != nil {
		return fmt.Errorf("read cgroup v2 subtree controllers: %w", err)
	}
	enabled := make(map[string]bool)
	for _, controller := range strings.Fields(string(subtreeData)) {
		enabled[controller] = true
	}
	for _, required := range requiredV2Controllers {
		if !available[required] {
			return fmt.Errorf("cgroup v2 controller %q is not available at %s", required, groupPath)
		}
		if !enabled[required] {
			return fmt.Errorf("cgroup v2 controller %q is not delegated by %s; enable it in the parent's cgroup.subtree_control", required, groupPath)
		}
	}
	return nil
}

func enableV2Controllers(groupPath string) error {
	data, err := os.ReadFile(filepath.Join(groupPath, "cgroup.controllers"))
	if err != nil {
		return fmt.Errorf("read cgroup v2 controllers: %w", err)
	}
	available := make(map[string]bool)
	for _, controller := range strings.Fields(string(data)) {
		available[controller] = true
	}
	for _, required := range requiredV2Controllers {
		if !available[required] {
			return fmt.Errorf("cgroup v2 controller %q is not available at %s", required, groupPath)
		}
	}

	subtreePath := filepath.Join(groupPath, "cgroup.subtree_control")
	current, err := os.ReadFile(subtreePath)
	if err != nil {
		return fmt.Errorf("read cgroup v2 subtree controllers: %w", err)
	}
	enabled := make(map[string]bool)
	for _, controller := range strings.Fields(string(current)) {
		enabled[controller] = true
	}
	var toggles []string
	for _, controller := range requiredV2Controllers {
		if !enabled[controller] {
			toggles = append(toggles, "+"+controller)
		}
	}
	if len(toggles) == 0 {
		return nil
	}
	f, err := os.OpenFile(subtreePath, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open cgroup v2 subtree controllers: %w", err)
	}
	if _, err = f.WriteString(strings.Join(toggles, " ")); err != nil {
		_ = f.Close()
		return fmt.Errorf("write cgroup v2 subtree controllers %v: %w", toggles, err)
	}
	return f.Close()
}
