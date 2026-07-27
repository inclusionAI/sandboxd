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
	"strconv"
	"syscall"
	"time"

	"github.com/containerd/cgroups/v3"
	cg "github.com/containerd/cgroups/v3/cgroup1"
	"github.com/opencontainers/runtime-spec/specs-go"
)

const (
	defaultV1CPUShares  = uint64(1024)
	defaultV1MemoryMax  = int64(-1)
	unlimitedPidsString = "max"
)

type cgroupV1 struct {
	detectedMode cgroups.CGMode
}

func (o *cgroupV1) mode() cgroups.CGMode {
	if o.detectedMode == cgroups.Hybrid {
		return cgroups.Hybrid
	}
	return cgroups.Legacy
}

func (*cgroupV1) prepareRoot(root string, _ int64) error {
	memoryRoot := filepath.Join(cgroupMountpoint, "memory")
	if _, err := os.Stat(memoryRoot); err != nil {
		return fmt.Errorf("cgroup v1 memory controller is unavailable at %s: %w", memoryRoot, err)
	}
	return nil
}

func (*cgroupV1) list(root string) ([]string, error) {
	groupDirs, err := os.ReadDir(filepath.Join(cgroupMountpoint, "memory", root))
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

func (*cgroupV1) create(name string, resources *specs.LinuxResources) error {
	_, err := cg.New(cg.StaticPath(name), resources, cg.WithHiearchy(cg.Default))
	return err
}

func (*cgroupV1) reset(name string) error {
	shares := defaultV1CPUShares
	memoryLimit := defaultV1MemoryMax
	resources := &specs.LinuxResources{
		CPU:    &specs.LinuxCPU{Shares: &shares},
		Memory: &specs.LinuxMemory{Limit: &memoryLimit},
	}
	group, err := cg.Load(cg.StaticPath(name), cg.WithHiearchy(cg.Default))
	if err != nil {
		return err
	}
	return group.Update(resources)
}

func (*cgroupV1) setPidsLimit(name string, limit int64) error {
	pidsPath := filepath.Join(cgroupMountpoint, "pids", name, "pids.max")
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

func (*cgroupV1) update(name string, resources *specs.LinuxResources) error {
	group, err := cg.Load(cg.StaticPath(name), cg.WithHiearchy(cg.Default))
	if err != nil {
		return err
	}
	return group.Update(resources)
}

func (*cgroupV1) stat(name string) (Stats, error) {
	group, err := cg.Load(cg.StaticPath(name), cg.WithHiearchy(cg.Default))
	if err != nil {
		return Stats{}, err
	}
	metrics, err := group.Stat()
	if err != nil {
		return Stats{}, err
	}
	result := Stats{}
	if metrics.CPU != nil && metrics.CPU.Usage != nil {
		result.CPUUsageNanos = metrics.CPU.Usage.Total
		result.CPUUserNanos = metrics.CPU.Usage.User
		result.CPUKernelNanos = metrics.CPU.Usage.Kernel
	}
	if metrics.Memory != nil && metrics.Memory.Usage != nil {
		result.MemoryUsageBytes = metrics.Memory.Usage.Usage
		result.MemoryLimitBytes = metrics.Memory.Usage.Limit
		result.MemoryMaxUsageBytes = metrics.Memory.Usage.Max
	}
	return result, nil
}

func (*cgroupV1) newOOMWatcher() (oomWatcher, error) {
	return newV1OOMWatcher()
}

func (*cgroupV1) kill(name string) error {
	group, err := cg.Load(cg.StaticPath(name), cg.WithHiearchy(cg.Default))
	if err != nil {
		return err
	}
	processes, err := group.Processes(cg.Memory, true)
	if err != nil {
		return err
	}
	for _, process := range processes {
		if err := syscall.Kill(process.Pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			return err
		}
	}
	for deadline := time.Now().Add(cgroupDrainTimeout); ; {
		processes, err = group.Processes(cg.Memory, true)
		if err != nil {
			return err
		}
		if len(processes) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for %d processes to leave cgroup %s", len(processes), name)
		}
		time.Sleep(cgroupDrainPoll)
	}
}

func (*cgroupV1) delete(name string) error {
	group, err := cg.Load(cg.StaticPath(name), cg.WithHiearchy(cg.Default))
	if errors.Is(err, cg.ErrCgroupDeleted) {
		return nil
	}
	if err != nil {
		return err
	}
	return group.Delete()
}
