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
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/util"

	"github.com/containerd/cgroups/v3"
	"github.com/containerd/cgroups/v3/cgroup2"
	"github.com/opencontainers/runtime-spec/specs-go"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestNewCgroupOpsSelectsDetectedMode(t *testing.T) {
	original := detectCgroupMode
	t.Cleanup(func() { detectCgroupMode = original })

	for _, test := range []struct {
		mode    cgroups.CGMode
		version int
		wantErr bool
	}{
		{mode: cgroups.Legacy, version: 1},
		{mode: cgroups.Hybrid, version: 1},
		{mode: cgroups.Unified, version: 2},
		{mode: cgroups.Unavailable, wantErr: true},
	} {
		detectCgroupMode = func() cgroups.CGMode { return test.mode }
		ops, err := newCgroupOps()
		if test.wantErr {
			assert.Error(t, err)
			continue
		}
		require.NoError(t, err)
		assert.Equal(t, test.version, cgroupVersion(ops.mode()))
		assert.Equal(t, test.mode, ops.mode())
	}
}

func TestReadV2PidsCurrent(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	value, tracked, err := readV2PidsCurrent(missing)
	require.NoError(t, err)
	assert.Zero(t, value)
	assert.False(t, tracked)

	filename := filepath.Join(t.TempDir(), "pids.current")
	require.NoError(t, os.WriteFile(filename, []byte("17\n"), 0644))
	value, tracked, err = readV2PidsCurrent(filename)
	require.NoError(t, err)
	assert.Equal(t, uint64(17), value)
	assert.True(t, tracked)

	require.NoError(t, os.WriteFile(filename, []byte("invalid\n"), 0644))
	_, tracked, err = readV2PidsCurrent(filename)
	assert.Error(t, err)
	assert.True(t, tracked)

	require.NoError(t, os.WriteFile(filename, []byte(strconv.FormatUint(^uint64(0), 10)), 0644))
	value, tracked, err = readV2PidsCurrent(filename)
	require.NoError(t, err)
	assert.Equal(t, ^uint64(0), value)
	assert.True(t, tracked)
}

func TestSandboxResourcesConvertCoreControls(t *testing.T) {
	resource := &runtime.LinuxSandboxResources{
		CpuShares:          1024,
		CpuQuota:           50000,
		CpuPeriod:          100000,
		CpusetCpus:         "0-1",
		CpusetMems:         "0",
		MemoryLimitInBytes: 256 << 20,
	}
	linux := sandboxResources(resource)
	require.NotNil(t, linux.CPU)
	require.NotNil(t, linux.Memory)
	assert.Equal(t, resource.CpuShares, *linux.CPU.Shares)
	assert.Equal(t, resource.CpuQuota, *linux.CPU.Quota)
	assert.Equal(t, resource.CpuPeriod, *linux.CPU.Period)
	assert.Empty(t, linux.CPU.Cpus)
	assert.Empty(t, linux.CPU.Mems)
	assert.Equal(t, resource.MemoryLimitInBytes, *linux.Memory.Limit)

	v2 := cgroup2.ToResources(linux)
	require.NotNil(t, v2.CPU)
	require.NotNil(t, v2.CPU.Weight)
	assert.Equal(t, uint64(1+((1024-2)*9999)/262142), *v2.CPU.Weight)
	assert.Equal(t, "50000 100000", string(v2.CPU.Max))
	require.NotNil(t, v2.Memory)
	assert.Equal(t, resource.MemoryLimitInBytes, *v2.Memory.Max)
}

type fakeCgroupOps struct {
	calls            []string
	stats            Stats
	createdResources *specs.LinuxResources
	oom              *fakeOOMWatcher
	killErr          error
}

func (f *fakeCgroupOps) mode() cgroups.CGMode { return cgroups.Unified }
func (f *fakeCgroupOps) prepareRoot(string, int64) error {
	f.calls = append(f.calls, "prepare-root")
	return nil
}
func (f *fakeCgroupOps) list(string) ([]string, error) { return nil, nil }
func (f *fakeCgroupOps) create(_ string, resources *specs.LinuxResources) error {
	f.calls = append(f.calls, "create")
	f.createdResources = resources
	return nil
}
func (f *fakeCgroupOps) reset(string) error {
	f.calls = append(f.calls, "reset")
	return nil
}
func (f *fakeCgroupOps) setPidsLimit(string, int64) error {
	f.calls = append(f.calls, "pids")
	return nil
}
func (f *fakeCgroupOps) update(string, *specs.LinuxResources) error {
	f.calls = append(f.calls, "update")
	return nil
}
func (f *fakeCgroupOps) stat(string) (Stats, error) { return f.stats, nil }
func (f *fakeCgroupOps) newOOMWatcher() (oomWatcher, error) {
	if f.oom == nil {
		f.oom = newFakeOOMWatcher()
	}
	return f.oom, nil
}
func (f *fakeCgroupOps) kill(string) error {
	f.calls = append(f.calls, "kill")
	return f.killErr
}
func (f *fakeCgroupOps) delete(string) error {
	f.calls = append(f.calls, "delete")
	return nil
}

type fakeOOMWatcher struct {
	mu       sync.Mutex
	flags    map[string]bool
	calls    []string
	closed   bool
	resetErr error
}

func newFakeOOMWatcher() *fakeOOMWatcher {
	return &fakeOOMWatcher{flags: make(map[string]bool)}
}

func (w *fakeOOMWatcher) Add(name string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.calls = append(w.calls, "add:"+name)
	w.flags[name] = false
	return nil
}

func (w *fakeOOMWatcher) Remove(name string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.calls = append(w.calls, "remove:"+name)
	delete(w.flags, name)
}

func (w *fakeOOMWatcher) Reset(name string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.calls = append(w.calls, "reset:"+name)
	if w.resetErr != nil {
		return w.resetErr
	}
	if _, ok := w.flags[name]; !ok {
		return errors.New("not registered")
	}
	w.flags[name] = false
	return nil
}

func (w *fakeOOMWatcher) OOMKilled(name string) (bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	flag, ok := w.flags[name]
	if !ok {
		return false, errors.New("not registered")
	}
	return flag, nil
}

func (w *fakeOOMWatcher) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
	return nil
}

func (w *fakeOOMWatcher) trigger(name string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.flags[name] = true
}

func TestPrepareOnlyAppliesLeaseResources(t *testing.T) {
	oom := newFakeOOMWatcher()
	ops := &fakeCgroupOps{oom: oom}
	name := "/sandbox/lease"
	manager := &CgroupManager{
		rootName: "/sandbox",
		pidsMax:  64,
		usingID:  cmap.New[struct{}](),
		idleID:   util.New[string](""),
		cgroups:  cmap.New[struct{}](),
		ops:      ops,
		oom:      oom,
	}
	manager.cgroups.Set(name, struct{}{})
	manager.usingID.Set(name, struct{}{})
	require.NoError(t, oom.Add(name))

	require.NoError(t, manager.Prepare(name, &runtime.LinuxSandboxResources{
		CpuShares:          512,
		MemoryLimitInBytes: 128 << 20,
	}))
	assert.Equal(t, []string{"update"}, ops.calls)
	killed, err := manager.OOMKilled(name)
	require.NoError(t, err)
	assert.False(t, killed)
	oom.trigger(name)
	killed, err = manager.OOMKilled(name)
	require.NoError(t, err)
	assert.True(t, killed)
}

func TestRecycleOnlyReturnsActiveOwnedCgroups(t *testing.T) {
	oom := newFakeOOMWatcher()
	ops := &fakeCgroupOps{oom: oom}
	manager := &CgroupManager{
		rootName:  "/sandbox",
		cacheSize: 1,
		usingID:   cmap.New[struct{}](),
		idleID:    util.New[string](""),
		cgroups:   cmap.New[struct{}](),
		gcQueue:   util.New[string](""),
		gcWake:    make(chan struct{}, 1),
		ops:       ops,
		oom:       oom,
		total:     1,
	}
	name := "/sandbox/lease"
	manager.cgroups.Set(name, struct{}{})
	manager.usingID.Set(name, struct{}{})
	require.NoError(t, oom.Add(name))

	require.NoError(t, manager.Recycle("/sandbox/not-active"))
	assert.Empty(t, manager.idleID.List())

	require.NoError(t, manager.Recycle(name))
	assert.Equal(t, []string{name}, manager.idleID.List())
	assert.Equal(t, []string{"kill", "reset"}, ops.calls)
	assert.Equal(t, []string{"add:" + name, "reset:" + name}, oom.calls)

	require.NoError(t, manager.Recycle(name))
	assert.Equal(t, []string{name}, manager.idleID.List(), "duplicate recycle must not duplicate a cache entry")
}

func TestRecycleDestroysCgroupWhenCleanupFails(t *testing.T) {
	name := "/sandbox/lease"
	oom := newFakeOOMWatcher()
	ops := &fakeCgroupOps{oom: oom, killErr: assert.AnError}
	manager := &CgroupManager{
		rootName:  "/sandbox",
		cacheSize: 1,
		usingID:   cmap.New[struct{}](),
		idleID:    util.New[string](""),
		cgroups:   cmap.New[struct{}](),
		gcQueue:   util.New[string](""),
		gcWake:    make(chan struct{}, 1),
		ops:       ops,
		oom:       oom,
		total:     1,
	}
	manager.cgroups.Set(name, struct{}{})
	manager.usingID.Set(name, struct{}{})
	require.NoError(t, oom.Add(name))

	require.NoError(t, manager.Recycle(name))
	assert.Empty(t, manager.idleID.List())
	assert.False(t, manager.cgroups.Has(name))
	assert.Equal(t, []string{name}, manager.gcQueue.List())
	assert.Zero(t, manager.total)
	assert.Equal(t, []string{"kill"}, ops.calls)
	assert.Equal(t, []string{"add:" + name, "remove:" + name}, oom.calls)
}

func TestRecycleDestroysCleanCgroupWhenCacheIsFull(t *testing.T) {
	name := "/sandbox/lease"
	oom := newFakeOOMWatcher()
	ops := &fakeCgroupOps{oom: oom}
	manager := &CgroupManager{
		rootName:  "/sandbox",
		cacheSize: 0,
		usingID:   cmap.New[struct{}](),
		idleID:    util.New[string](""),
		cgroups:   cmap.New[struct{}](),
		gcQueue:   util.New[string](""),
		gcWake:    make(chan struct{}, 1),
		ops:       ops,
		oom:       oom,
		total:     1,
	}
	manager.cgroups.Set(name, struct{}{})
	manager.usingID.Set(name, struct{}{})
	require.NoError(t, oom.Add(name))

	require.NoError(t, manager.Recycle(name))
	assert.Empty(t, manager.idleID.List())
	assert.Equal(t, []string{name}, manager.gcQueue.List())
	assert.Zero(t, manager.total)
	assert.Equal(t, []string{"kill", "reset"}, ops.calls)
	assert.Equal(
		t,
		[]string{"add:" + name, "reset:" + name, "remove:" + name},
		oom.calls,
	)
}

func TestDoCreateCarriesPidsLimitIntoOps(t *testing.T) {
	ops := &fakeCgroupOps{}
	oom := newFakeOOMWatcher()
	manager := &CgroupManager{
		pidsMax:   4096,
		cgroups:   cmap.New[struct{}](),
		generator: util.NewFixedLengthIDGenerator(12, nil, util.PrefixID("/sandbox/")),
		ops:       ops,
		oom:       oom,
	}

	id, err := manager.doCreate()
	require.NoError(t, err)
	assert.NotEmpty(t, id)
	assert.Equal(t, []string{"create"}, ops.calls)
	assert.Contains(t, oom.calls, "add:"+id)
	if assert.NotNil(t, ops.createdResources) &&
		assert.NotNil(t, ops.createdResources.Pids) {
		assert.Equal(t, int64(4096), ops.createdResources.Pids.Limit)
	}
}

func TestCgroupResourcesDefaultsToUnlimitedPids(t *testing.T) {
	assert.Nil(t, (&CgroupManager{}).cgroupResources().Pids)
}

func TestV2ResetAndStats(t *testing.T) {
	mountpoint := t.TempDir()
	name := "/sandbox/lease"
	groupPath := filepath.Join(mountpoint, name)
	require.NoError(t, os.MkdirAll(groupPath, 0755))

	writeTestFile(t, filepath.Join(groupPath, "cpu.weight"), "39")
	writeTestFile(t, filepath.Join(groupPath, "cpu.max"), "50000 100000")
	writeTestFile(t, filepath.Join(groupPath, "memory.max"), "268435456")
	writeTestFile(t, filepath.Join(groupPath, "memory.swap.max"), "268435456")
	writeTestFile(t, filepath.Join(groupPath, "pids.max"), "1024")
	writeTestFile(t, filepath.Join(groupPath, "cpuset.cpus"), "0")
	writeTestFile(t, filepath.Join(groupPath, "cpuset.mems"), "0")

	ops := &cgroupV2{mountpoint: mountpoint}
	require.NoError(t, ops.reset(name))
	assertFileContents(t, filepath.Join(groupPath, "cpu.weight"), "100")
	assertFileContents(t, filepath.Join(groupPath, "cpu.max"), "max 100000")
	assertFileContents(t, filepath.Join(groupPath, "memory.max"), "max")
	assertFileContents(t, filepath.Join(groupPath, "memory.swap.max"), "268435456")
	assertFileContents(t, filepath.Join(groupPath, "pids.max"), "1024")
	assertFileContents(t, filepath.Join(groupPath, "cpuset.cpus"), "0")
	assertFileContents(t, filepath.Join(groupPath, "cpuset.mems"), "0")

	writeTestFile(t, filepath.Join(groupPath, "cgroup.controllers"), "cpu memory")
	writeTestFile(t, filepath.Join(groupPath, "cpu.stat"), "usage_usec 123\nuser_usec 80\nsystem_usec 43\n")
	writeTestFile(t, filepath.Join(groupPath, "memory.stat"), "anon 100\n")
	writeTestFile(t, filepath.Join(groupPath, "memory.current"), "4096")
	writeTestFile(t, filepath.Join(groupPath, "memory.max"), "8192")
	writeTestFile(t, filepath.Join(groupPath, "memory.peak"), "6144")
	writeTestFile(t, filepath.Join(groupPath, "memory.swap.current"), "0")
	writeTestFile(t, filepath.Join(groupPath, "memory.swap.max"), "max")
	writeTestFile(t, filepath.Join(groupPath, "memory.events"), "oom_kill 0\n")

	stats, err := ops.stat(name)
	require.NoError(t, err)
	assert.Equal(t, uint64(123000), stats.CPUUsageNanos)
	assert.Equal(t, uint64(80000), stats.CPUUserNanos)
	assert.Equal(t, uint64(43000), stats.CPUKernelNanos)
	assert.Equal(t, uint64(4096), stats.MemoryUsageBytes)
	assert.Equal(t, uint64(8192), stats.MemoryLimitBytes)
	assert.Equal(t, uint64(6144), stats.MemoryMaxUsageBytes)
}

func TestV2OOMWatcherUsesCgroupBaseline(t *testing.T) {
	mountpoint := t.TempDir()
	name := "/sandbox/lease"
	groupPath := filepath.Join(mountpoint, name)
	require.NoError(t, os.MkdirAll(groupPath, 0755))
	memoryEvents := filepath.Join(groupPath, "memory.events")
	writeTestFile(t, memoryEvents, "low 0\nhigh 0\nmax 3\noom 3\noom_kill 3\n")
	writeTestFile(t, filepath.Join(groupPath, "cgroup.events"), "populated 0\n")

	watcher, err := newV2OOMWatcher(mountpoint)
	require.NoError(t, err)
	defer watcher.Close()
	require.NoError(t, watcher.Add(name))
	writeTestFile(t, filepath.Join(groupPath, "cgroup.events"), "populated 0\n")
	killed, err := watcher.OOMKilled(name)
	require.NoError(t, err)
	assert.False(t, killed, "historical oom_kill count must not fire")

	watcher.eventsMu.Lock()
	writeTestFile(t, memoryEvents, "low 0\nhigh 0\nmax 4\noom 4\noom_kill 4\n")
	watcher.eventsMu.Unlock()
	killed, err = watcher.OOMKilled(name)
	require.NoError(t, err)
	assert.True(t, killed)

	require.NoError(t, watcher.Reset(name))
	writeTestFile(t, filepath.Join(groupPath, "cgroup.events"), "populated 0\n")
	killed, err = watcher.OOMKilled(name)
	require.NoError(t, err)
	assert.False(t, killed)
	watcher.Remove(name)
	_, err = watcher.OOMKilled(name)
	assert.Error(t, err)
}

func TestV2OOMWatcherWaitsForFinalMemoryEvent(t *testing.T) {
	mountpoint := t.TempDir()
	name := "/sandbox/lease"
	groupPath := filepath.Join(mountpoint, name)
	require.NoError(t, os.MkdirAll(groupPath, 0755))
	memoryEvents := filepath.Join(groupPath, "memory.events")
	writeTestFile(t, memoryEvents, "oom_kill 0\n")
	writeTestFile(t, filepath.Join(groupPath, "cgroup.events"), "populated 1\n")

	watcher, err := newV2OOMWatcher(mountpoint)
	require.NoError(t, err)
	defer watcher.Close()
	require.NoError(t, watcher.Add(name))

	writeDone := make(chan error, 1)
	go func() {
		time.Sleep(20 * time.Millisecond)
		writeDone <- os.WriteFile(memoryEvents, []byte("oom_kill 1\n"), 0644)
	}()
	killed, err := watcher.OOMKilled(name)
	require.NoError(t, <-writeDone)
	require.NoError(t, err)
	assert.True(t, killed)
}

func TestV1OOMWatcherMultiplexesEventFDs(t *testing.T) {
	watcher, err := newV1OOMWatcher()
	require.NoError(t, err)
	defer watcher.Close()

	for _, name := range []string{"/sandbox/a", "/sandbox/b"} {
		fd, fdErr := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
		require.NoError(t, fdErr)
		require.NoError(t, watcher.addFD(name, fd))
	}

	wakeEventFD(watcher.byName["/sandbox/b"].fd)
	require.Eventually(t, func() bool {
		killed, getErr := watcher.OOMKilled("/sandbox/b")
		return getErr == nil && killed
	}, 2*time.Second, 10*time.Millisecond)
	killed, err := watcher.OOMKilled("/sandbox/a")
	require.NoError(t, err)
	assert.False(t, killed)

	require.NoError(t, watcher.Reset("/sandbox/b"))
	killed, err = watcher.OOMKilled("/sandbox/b")
	require.NoError(t, err)
	assert.False(t, killed)
	watcher.Remove("/sandbox/b")
	_, err = watcher.OOMKilled("/sandbox/b")
	assert.Error(t, err)
}

func TestV1OOMKilledDrainsPendingEventFD(t *testing.T) {
	const name = "/sandbox/lease"
	fd, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	require.NoError(t, err)
	defer unix.Close(fd)

	entry := &v1OOMEntry{name: name, fd: fd}
	watcher := &v1OOMWatcher{
		byName: map[string]*v1OOMEntry{name: entry},
	}
	wakeEventFD(fd)

	killed, err := watcher.OOMKilled(name)
	require.NoError(t, err)
	assert.True(t, killed)

	killed, err = watcher.OOMKilled(name)
	require.NoError(t, err)
	assert.True(t, killed, "OOM flag must remain set after the eventfd is drained")
}

func TestNewCgroupManagerRejectsNegativePidsMax(t *testing.T) {
	_, err := NewCgroupManager(nil, config.ResourceConfig{PidsMax: -1}, 1)
	assert.EqualError(t, err, "pids_max must be non-negative")
}

func writeTestFile(t *testing.T, name, contents string) {
	t.Helper()
	require.NoError(t, os.WriteFile(name, []byte(contents), 0644))
}

func assertFileContents(t *testing.T, name, expected string) {
	t.Helper()
	data, err := os.ReadFile(name)
	require.NoError(t, err)
	assert.Equal(t, expected, string(data))
}
