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
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/inclusionAI/sandboxd/config"

	"github.com/containerd/cgroups/v3"
	"github.com/containerd/cgroups/v3/cgroup2"
	"github.com/opencontainers/runtime-spec/specs-go"
)

const (
	defaultV2CPUWeight = "100"
	defaultV2MemoryMax = "max"
)

type cgroupV2 struct {
	mountpoint string
}

func (*cgroupV2) mode() cgroups.CGMode { return cgroups.Unified }

func (o *cgroupV2) prepareRoot(root string, pidsMax int64) error {
	required := []string{"cpu", "memory"}
	if pidsMax > 0 {
		required = append(required, "pids")
	}
	return o.enableControllers(root, required)
}

func (o *cgroupV2) enableControllers(group string, controllers []string) error {
	current := o.mountpoint
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(group), "/"), "/")
	for _, part := range append([]string{""}, parts...) {
		if part != "" {
			current = filepath.Join(current, part)
			if err := os.MkdirAll(current, 0755); err != nil {
				return fmt.Errorf("create delegated cgroup %s: %w", current, err)
			}
		}
		availableData, err := os.ReadFile(filepath.Join(current, "cgroup.controllers"))
		if err != nil {
			return fmt.Errorf("read controllers at %s: %w", current, err)
		}
		available := make(map[string]struct{})
		for controller := range strings.FieldsSeq(string(availableData)) {
			available[controller] = struct{}{}
		}
		for _, controller := range controllers {
			if _, ok := available[controller]; !ok {
				return fmt.Errorf(
					"cgroup v2 controller %q is not delegated at %s (available: %s)",
					controller,
					current,
					strings.TrimSpace(string(availableData)),
				)
			}
		}
		value := make([]string, 0, len(controllers))
		for _, controller := range controllers {
			value = append(value, "+"+controller)
		}
		if err := os.WriteFile(
			filepath.Join(current, "cgroup.subtree_control"),
			[]byte(strings.Join(value, " ")),
			0644,
		); err != nil {
			return fmt.Errorf(
				"enable cgroup v2 controllers %v at %s: %w",
				controllers,
				current,
				err,
			)
		}
	}
	return nil
}

func (o *cgroupV2) list(root string) ([]string, error) {
	groupDirs, err := os.ReadDir(filepath.Join(o.mountpoint, root))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	result := make([]string, 0, len(groupDirs))
	for _, dir := range groupDirs {
		if dir.IsDir() {
			result = append(result, filepath.Join(root, dir.Name()))
		}
	}
	return result, nil
}

func (o *cgroupV2) create(name string, resources *specs.LinuxResources) error {
	_, err := cgroup2.NewManager(o.mountpoint, name, cgroup2.ToResources(resources))
	return err
}

func (o *cgroupV2) reset(name string) error {
	groupPath := filepath.Join(o.mountpoint, name)
	values := map[string]string{
		"cpu.weight": defaultV2CPUWeight,
		"cpu.max":    "max " + strconv.FormatUint(config.DefaultCPUPeriodMicros, 10),
		"memory.max": defaultV2MemoryMax,
	}
	for filename, value := range values {
		if err := os.WriteFile(filepath.Join(groupPath, filename), []byte(value), 0644); err != nil {
			return fmt.Errorf("reset %s for cgroup %s: %w", filename, name, err)
		}
	}
	return nil
}

func (o *cgroupV2) setPidsLimit(name string, limit int64) error {
	pidsPath := filepath.Join(o.mountpoint, name, "pids.max")
	if _, err := os.Stat(pidsPath); err != nil {
		if os.IsNotExist(err) && limit == 0 {
			return nil
		}
		return err
	}
	value := unlimitedPidsString
	if limit > 0 {
		value = strconv.FormatInt(limit, 10)
	}
	if err := os.WriteFile(pidsPath, []byte(value), 0644); err != nil {
		return fmt.Errorf("set pids.max for cgroup %s: %w", name, err)
	}
	return nil
}

func (o *cgroupV2) update(name string, resources *specs.LinuxResources) error {
	if resources == nil {
		return nil
	}
	group, err := cgroup2.Load(name, cgroup2.WithMountpoint(o.mountpoint))
	if err != nil {
		return err
	}
	return group.Update(cgroup2.ToResources(resources))
}

func (o *cgroupV2) stat(name string) (Stats, error) {
	group, err := cgroup2.Load(name, cgroup2.WithMountpoint(o.mountpoint))
	if err != nil {
		return Stats{}, err
	}
	metrics, err := group.Stat()
	if err != nil {
		return Stats{}, err
	}
	result := Stats{}
	if metrics.CPU != nil {
		result.CPUUsageNanos = usecToNS(metrics.CPU.UsageUsec)
		result.CPUUserNanos = usecToNS(metrics.CPU.UserUsec)
		result.CPUKernelNanos = usecToNS(metrics.CPU.SystemUsec)
	}
	if metrics.Memory != nil {
		result.MemoryUsageBytes = metrics.Memory.Usage
		result.MemoryLimitBytes = metrics.Memory.UsageLimit
		result.MemoryMaxUsageBytes = readUintFile(filepath.Join(o.mountpoint, name, "memory.peak"))
		if result.MemoryMaxUsageBytes == 0 {
			result.MemoryMaxUsageBytes = result.MemoryUsageBytes
		}
	}
	return result, nil
}

func readUintFile(filename string) uint64 {
	data, err := os.ReadFile(filename)
	if err != nil {
		return 0
	}
	value := strings.TrimSpace(string(data))
	if value == "max" {
		return ^uint64(0)
	}
	result, _ := strconv.ParseUint(value, 10, 64)
	return result
}

func (o *cgroupV2) newOOMWatcher() (oomWatcher, error) {
	return newV2OOMWatcher(o.mountpoint)
}

func (o *cgroupV2) kill(name string) error {
	group, err := cgroup2.Load(name, cgroup2.WithMountpoint(o.mountpoint))
	if err != nil {
		return err
	}
	processes, err := group.Procs(true)
	if err != nil {
		return err
	}
	// cgroup.kill is sticky while tasks from the previous sandbox are still
	// being reaped. Writing it for an already empty cgroup can therefore kill
	// the first process cloned into a recycled cgroup.
	if len(processes) > 0 {
		if err := group.Kill(); err != nil {
			return err
		}
	}

	for deadline := time.Now().Add(cgroupDrainTimeout); ; {
		processes, err = group.Procs(true)
		if err != nil {
			return err
		}
		tasks, tracksTasks, err := readV2PidsCurrent(
			filepath.Join(o.mountpoint, name, "pids.current"),
		)
		if err != nil {
			return err
		}
		if len(processes) == 0 && (!tracksTasks || tasks == 0) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf(
				"timed out waiting for cgroup %s to drain (%d processes, %d tasks)",
				name,
				len(processes),
				tasks,
			)
		}
		time.Sleep(cgroupDrainPoll)
	}
}

func readV2PidsCurrent(filename string) (uint64, bool, error) {
	data, err := os.ReadFile(filename)
	if os.IsNotExist(err) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("read %s: %w", filename, err)
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, true, fmt.Errorf("parse %s: %w", filename, err)
	}
	return value, true, nil
}

func (o *cgroupV2) delete(name string) error {
	group, err := cgroup2.Load(name, cgroup2.WithMountpoint(o.mountpoint))
	if err != nil {
		return err
	}
	if err := group.Delete(); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
