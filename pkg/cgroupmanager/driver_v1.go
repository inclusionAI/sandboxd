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
	"path"
	"path/filepath"
	"syscall"

	cg "github.com/containerd/cgroups/v3/cgroup1"
	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/internal/cgroupops"
	"github.com/opencontainers/runtime-spec/specs-go"
)

type v1Driver struct {
	handler cgroupops.CgroupHandler
}

func newV1Driver() *v1Driver {
	return &v1Driver{handler: &cgroupops.CgroupHandlerImpl{}}
}

func (d *v1Driver) PrepareRoot(string) error { return nil }

func (d *v1Driver) Create(name string, pidsMax int64) error {
	resources := &specs.LinuxResources{}
	if pidsMax > 0 {
		resources.Pids = &specs.LinuxPids{Limit: pidsMax}
	}
	_, err := d.handler.Create(cg.StaticPath(name), resources, cg.WithHiearchy(cg.Default))
	return err
}

func (d *v1Driver) List(rootName string) ([]string, error) {
	groupDirs, err := os.ReadDir(path.Join("/sys/fs/cgroup/memory", rootName))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	groups := make([]string, 0, len(groupDirs))
	for _, dir := range groupDirs {
		if dir.IsDir() {
			groups = append(groups, filepath.Join("/", rootName, dir.Name()))
		}
	}
	return groups, nil
}

func (d *v1Driver) Update(name string, resource *runtime.LinuxSandboxResources) error {
	if resource == nil {
		return nil
	}
	cgroup, err := d.handler.Load(cg.StaticPath(name), cg.WithHiearchy(cg.Default))
	if err != nil {
		return err
	}
	return cgroup.Update(linuxResources(resource))
}

func linuxResources(resource *runtime.LinuxSandboxResources) *specs.LinuxResources {
	var cpu specs.LinuxCPU
	if resource.CpuShares > 0 {
		cpu.Shares = &resource.CpuShares
	}
	if resource.CpuQuota > 0 {
		cpu.Quota = &resource.CpuQuota
	}
	if resource.CpuPeriod > 0 {
		cpu.Period = &resource.CpuPeriod
	}
	if resource.CpusetCpus != "" {
		cpu.Cpus = resource.CpusetCpus
	}
	if resource.CpusetMems != "" {
		cpu.Mems = resource.CpusetMems
	}
	var memory specs.LinuxMemory
	if resource.MemoryLimitInBytes > 0 {
		memory.Limit = &resource.MemoryLimitInBytes
	}
	return &specs.LinuxResources{CPU: &cpu, Memory: &memory}
}

func (d *v1Driver) Stats(name string) (Stats, error) {
	cgroup, err := d.handler.Load(cg.StaticPath(name), cg.WithHiearchy(cg.Default))
	if err != nil {
		return Stats{}, err
	}
	metrics, err := cgroup.Stat()
	if err != nil {
		return Stats{}, err
	}
	var result Stats
	if metrics.CPU != nil && metrics.CPU.Usage != nil {
		result.CPUUsageNS = metrics.CPU.Usage.Total
		result.CPUKernelNS = metrics.CPU.Usage.Kernel
		result.CPUUserNS = metrics.CPU.Usage.User
	}
	if metrics.Memory != nil && metrics.Memory.Usage != nil {
		result.MemoryUsageBytes = metrics.Memory.Usage.Usage
		result.MemoryLimitBytes = metrics.Memory.Usage.Limit
		result.MemoryMaxUsageBytes = metrics.Memory.Usage.Max
	}
	return result, nil
}

func (d *v1Driver) Kill(name string) error {
	cgroup, err := d.handler.Load(cg.StaticPath(name), cg.WithHiearchy(cg.Default))
	if err != nil {
		return fmt.Errorf("getting cgroup failed: %w", err)
	}
	processes, err := cgroup.Processes(cg.Memory, true)
	if err != nil {
		return fmt.Errorf("getting processes failed: %w", err)
	}
	for _, process := range processes {
		_ = syscall.Kill(process.Pid, syscall.SIGKILL)
	}
	return nil
}

func (d *v1Driver) Delete(name string) error {
	cgroup, err := d.handler.Load(cg.StaticPath(name), cg.WithHiearchy(cg.Default))
	if errors.Is(err, cg.ErrCgroupDeleted) {
		return nil
	}
	if err == nil {
		if err = cgroup.Delete(); err == nil {
			return nil
		}
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	subsystems, subsystemErr := cg.Default()
	if subsystemErr != nil {
		return subsystemErr
	}
	var errs []error
	for _, subsystem := range subsystems {
		if removeErr := os.RemoveAll(path.Join("/sys/fs/cgroup", string(subsystem.Name()), name)); removeErr != nil && !os.IsNotExist(removeErr) {
			errs = append(errs, removeErr)
		}
	}
	return errors.Join(errs...)
}

var _ driver = (*v1Driver)(nil)
