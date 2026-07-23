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
	"strconv"
	"strings"
	"sync"

	runtime "github.com/akernel-dev/sandboxd/api/runtime/v1"
	cg "github.com/containerd/cgroups/v3/cgroup2"
	cgstats "github.com/containerd/cgroups/v3/cgroup2/stats"
	"golang.org/x/sys/unix"
)

type v2Driver struct {
	unifiedMountpoint string
	parent            string
	logicalRoot       string
	rootMountpoint    string
}

func newV2Driver(mountpoint, parent, root string) *v2Driver {
	return &v2Driver{
		unifiedMountpoint: mountpoint,
		parent:            parent,
		logicalRoot:       root,
		rootMountpoint:    cgroupPathOnMount(mountpoint, root),
	}
}

func (d *v2Driver) PrepareRoot(root string) error {
	if root != d.logicalRoot {
		return fmt.Errorf("cgroup v2 root mismatch: got %q, configured %q", root, d.logicalRoot)
	}
	parentPath := cgroupPathOnMount(d.unifiedMountpoint, d.parent)
	if _, err := os.Stat(parentPath); err != nil {
		return fmt.Errorf("stat delegated cgroup v2 parent %s: %w", parentPath, err)
	}
	if err := os.Mkdir(d.rootMountpoint, 0755); err != nil && !os.IsExist(err) {
		return fmt.Errorf("create sandboxd-owned cgroup v2 root %s: %w", d.rootMountpoint, err)
	}
	if err := enableV2Controllers(d.rootMountpoint); err != nil {
		return fmt.Errorf("enable controllers in sandboxd-owned cgroup v2 root %s: %w", d.rootMountpoint, err)
	}
	return nil
}

func (d *v2Driver) relativeName(name string) (string, error) {
	prefix := strings.TrimSuffix(d.logicalRoot, "/") + "/"
	if !strings.HasPrefix(name, prefix) {
		return "", fmt.Errorf("cgroup %q is outside configured root %q", name, d.logicalRoot)
	}
	relative := strings.TrimPrefix(name, d.logicalRoot)
	if relative == "" || relative == "/" || path.Clean(relative) != relative || strings.Count(strings.Trim(relative, "/"), "/") != 0 {
		return "", fmt.Errorf("invalid sandbox cgroup path %q", name)
	}
	return relative, nil
}

func (d *v2Driver) Create(name string, pidsMax int64) error {
	relative, err := d.relativeName(name)
	if err != nil {
		return err
	}
	_, err = cg.NewManager(d.rootMountpoint, relative, initialV2Resources(pidsMax))
	return err
}

func initialV2Resources(pidsMax int64) *cg.Resources {
	if pidsMax == 0 {
		pidsMax = -1
	}
	return &cg.Resources{
		CPU:    &cg.CPU{},
		Memory: &cg.Memory{},
		Pids:   &cg.Pids{Max: pidsMax},
	}
}

func (d *v2Driver) List(rootName string) ([]string, error) {
	if rootName != d.logicalRoot {
		return nil, fmt.Errorf("cgroup v2 root mismatch: got %q, configured %q", rootName, d.logicalRoot)
	}
	groupDirs, err := os.ReadDir(d.rootMountpoint)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	groups := make([]string, 0, len(groupDirs))
	for _, dir := range groupDirs {
		if dir.IsDir() {
			groups = append(groups, filepath.Join(d.logicalRoot, dir.Name()))
		}
	}
	return groups, nil
}

func (d *v2Driver) Update(name string, resource *runtime.LinuxSandboxResources) error {
	if resource == nil {
		return nil
	}
	relative, err := d.relativeName(name)
	if err != nil {
		return err
	}
	manager, err := cg.Load(relative, cg.WithMountpoint(d.rootMountpoint))
	if err != nil {
		return err
	}
	resources := cg.ToResources(linuxResources(resource))
	// cgroup2.ToResources only emits cpu.max when CpuPeriod is present. The
	// v1 API permits updating quota alone, in which case the current period is
	// retained; preserve that behavior on v2.
	if resource.CpuQuota > 0 && resource.CpuPeriod == 0 {
		period, err := readCPUPeriod(filepath.Join(d.rootMountpoint, strings.TrimPrefix(relative, "/"), "cpu.max"))
		if err != nil {
			return fmt.Errorf("read CPU period for %s: %w", name, err)
		}
		resources.CPU.Max = cg.NewCPUMax(&resource.CpuQuota, &period)
	}
	return manager.Update(resources)
}

func (d *v2Driver) Stats(name string) (Stats, error) {
	relative, err := d.relativeName(name)
	if err != nil {
		return Stats{}, err
	}
	manager, err := cg.Load(relative, cg.WithMountpoint(d.rootMountpoint))
	if err != nil {
		return Stats{}, err
	}
	metrics, err := manager.Stat()
	if err != nil {
		return Stats{}, err
	}
	peakPath := filepath.Join(d.rootMountpoint, strings.TrimPrefix(relative, "/"), "memory.peak")
	peak, peakErr := readUintFile(peakPath)
	if peakErr == nil {
		return statsFromV2(metrics, peak), nil
	}
	if os.IsNotExist(peakErr) {
		return statsFromV2(metrics, metrics.GetMemory().GetUsage()), nil
	}
	return Stats{}, fmt.Errorf("read memory peak for %s: %w", name, peakErr)
}

func statsFromV2(metrics *cgstats.Metrics, memoryPeak uint64) Stats {
	return Stats{
		CPUUsageNS:          metrics.GetCPU().GetUsageUsec() * 1000,
		CPUKernelNS:         metrics.GetCPU().GetSystemUsec() * 1000,
		CPUUserNS:           metrics.GetCPU().GetUserUsec() * 1000,
		MemoryUsageBytes:    metrics.GetMemory().GetUsage(),
		MemoryLimitBytes:    metrics.GetMemory().GetUsageLimit(),
		MemoryMaxUsageBytes: memoryPeak,
	}
}

func (d *v2Driver) WatchOOM(name string, onOOM func()) (func(), error) {
	return d.watchOOM(name, onOOM, unix.InotifyAddWatch)
}

type inotifyAddWatchFunc func(fd int, pathname string, mask uint32) (wd int, err error)

func (d *v2Driver) watchOOM(name string, onOOM func(), addWatch inotifyAddWatchFunc) (func(), error) {
	if onOOM == nil {
		return nil, errors.New("WatchOOM: onOOM callback must not be nil")
	}
	relative, err := d.relativeName(name)
	if err != nil {
		return nil, err
	}
	eventsPath := filepath.Join(d.rootMountpoint, strings.TrimPrefix(relative, "/"), "memory.events")
	// Read the counter before installing the watch, then reconcile it once the
	// watch is active. This closes both initialization windows: an OOM between
	// the baseline read and inotify registration is caught by reconciliation,
	// while a later OOM is observed either there or through inotify.
	baseline, err := readMemoryEvent(eventsPath, "oom_kill")
	if err != nil {
		return nil, fmt.Errorf("read initial oom_kill for %s: %w", name, err)
	}
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, fmt.Errorf("create oom inotify for %s: %w", name, err)
	}
	if _, err = addWatch(fd, eventsPath, unix.IN_MODIFY|unix.IN_DELETE_SELF); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("watch %s: %w", eventsPath, err)
	}
	file := os.NewFile(uintptr(fd), fmt.Sprintf("cgroup-v2-oom:%s", name))
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("wrap oom inotify fd for %s", name)
	}

	var (
		closeOnce sync.Once
		fired     sync.Once
	)
	done := make(chan struct{})
	checkOOM := func() {
		current, readErr := readMemoryEvent(eventsPath, "oom_kill")
		if readErr == nil && current > baseline {
			fired.Do(onOOM)
		}
	}
	stop := func() {
		closeOnce.Do(func() {
			// Reconcile the counter synchronously before closing the fd. The
			// process may exit before the inotify goroutine is scheduled.
			checkOOM()
			_ = file.Close()
		})
		<-done
		checkOOM()
	}
	go func() {
		defer close(done)
		buffer := make([]byte, unix.SizeofInotifyEvent*8)
		for {
			if _, readErr := file.Read(buffer); readErr != nil {
				return
			}
			current, readErr := readMemoryEvent(eventsPath, "oom_kill")
			if readErr != nil {
				if os.IsNotExist(readErr) {
					return
				}
				continue
			}
			if current > baseline {
				fired.Do(onOOM)
				return
			}
		}
	}()
	checkOOM()
	return stop, nil
}

func (d *v2Driver) Kill(name string) error {
	relative, err := d.relativeName(name)
	if err != nil {
		return err
	}
	manager, err := cg.Load(relative, cg.WithMountpoint(d.rootMountpoint))
	if err != nil {
		return err
	}
	return manager.Kill()
}

func (d *v2Driver) Delete(name string) error {
	relative, err := d.relativeName(name)
	if err != nil {
		return err
	}
	groupPath := filepath.Join(d.rootMountpoint, strings.TrimPrefix(relative, "/"))
	if _, err := os.Stat(groupPath); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	manager, err := cg.Load(relative, cg.WithMountpoint(d.rootMountpoint))
	if err != nil {
		return err
	}
	// Kill uses cgroup.kill when available and containerd's recursive fallback
	// on older kernels. Delete then verifies that no processes remain.
	if err = manager.Kill(); err != nil {
		return fmt.Errorf("kill cgroup %s: %w", name, err)
	}
	err = manager.Delete()
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func readMemoryEvent(path, key string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == key {
			return strconv.ParseUint(fields[1], 10, 64)
		}
	}
	return 0, fmt.Errorf("event %q not found in %s", key, path)
}

func readUintFile(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	value := strings.TrimSpace(string(data))
	if value == "max" {
		return ^uint64(0), nil
	}
	return strconv.ParseUint(value, 10, 64)
}

func readCPUPeriod(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) != 2 {
		return 0, fmt.Errorf("invalid cpu.max value %q", strings.TrimSpace(string(data)))
	}
	return strconv.ParseUint(fields[1], 10, 64)
}

var _ driver = (*v2Driver)(nil)
