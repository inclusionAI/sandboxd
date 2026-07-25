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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cgroups "github.com/containerd/cgroups/v3"
	cgstats "github.com/containerd/cgroups/v3/cgroup2/stats"
	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"golang.org/x/sys/unix"
)

func TestNewDriverDefaultsToV1(t *testing.T) {
	drv, err := newDriver(config.ResourceConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := drv.(*v1Driver); !ok {
		t.Fatalf("default driver type = %T, want *v1Driver", drv)
	}
}

func TestNewDriverSelectsV2(t *testing.T) {
	drv, err := newDriver(config.ResourceConfig{CgroupVersion: config.CgroupVersionV2, CgroupParent: "/", CgroupRootName: "sandbox"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := drv.(*v2Driver); !ok {
		t.Fatalf("v2 driver type = %T, want *v2Driver", drv)
	}
}

func TestNewDriverRejectsUnknownVersion(t *testing.T) {
	if _, err := newDriver(config.ResourceConfig{CgroupVersion: "auto"}); err == nil {
		t.Fatal("newDriver(auto) unexpectedly succeeded")
	}
}

func TestResolvedCgroupRoot(t *testing.T) {
	tests := []struct {
		name    string
		cfg     config.ResourceConfig
		want    string
		wantErr bool
	}{
		{name: "v1 preserves legacy root", cfg: config.ResourceConfig{CgroupRootName: "/sandbox"}, want: "/sandbox"},
		{name: "v2 root parent", cfg: config.ResourceConfig{CgroupVersion: "v2", CgroupParent: "/", CgroupRootName: "/sandbox"}, want: "/sandbox"},
		{name: "v2 delegated parent", cfg: config.ResourceConfig{CgroupVersion: "v2", CgroupParent: "/system.slice/sandboxd.service", CgroupRootName: "sandbox"}, want: "/system.slice/sandboxd.service/sandbox"},
		{name: "v2 rejects nested root name", cfg: config.ResourceConfig{CgroupVersion: "v2", CgroupParent: "/", CgroupRootName: "nested/sandbox"}, wantErr: true},
		{name: "v2 rejects empty root name after normalization", cfg: config.ResourceConfig{CgroupVersion: "v2", CgroupParent: "/", CgroupRootName: "/"}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := resolvedCgroupRoot(test.cfg)
			if test.wantErr {
				if err == nil {
					t.Fatalf("resolvedCgroupRoot(%+v) unexpectedly succeeded", test.cfg)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("resolvedCgroupRoot(%+v) = %q, want %q", test.cfg, got, test.want)
			}
		})
	}
}

func TestValidateV2Delegation(t *testing.T) {
	mountpoint := t.TempDir()
	writeFakeV2ControlFiles(t, mountpoint, "cpu cpuset memory pids\n")
	if err := os.WriteFile(filepath.Join(mountpoint, "cgroup.subtree_control"), []byte("cpu cpuset memory pids\n"), 0600); err != nil {
		t.Fatal(err)
	}
	parentBefore, err := os.ReadFile(filepath.Join(mountpoint, "cgroup.subtree_control"))
	if err != nil {
		t.Fatal(err)
	}
	var probeSubtreeControl string
	createProbe := func(parent string) (string, func() error, error) {
		probe, err := os.MkdirTemp(parent, "probe-")
		if err != nil {
			return "", nil, err
		}
		writeFakeV2ControlFiles(t, probe, "cpu cpuset memory pids\n")
		return probe, func() error {
			data, readErr := os.ReadFile(filepath.Join(probe, "cgroup.subtree_control"))
			if readErr != nil {
				return readErr
			}
			probeSubtreeControl = string(data)
			return os.RemoveAll(probe)
		}, nil
	}
	if err := validateV2DelegationWithProbe(mountpoint, createProbe); err != nil {
		t.Fatalf("validateV2Delegation: %v", err)
	}
	parentAfter, err := os.ReadFile(filepath.Join(mountpoint, "cgroup.subtree_control"))
	if err != nil {
		t.Fatal(err)
	}
	if string(parentAfter) != string(parentBefore) {
		t.Fatalf("preflight modified delegated parent subtree_control: before=%q after=%q", parentBefore, parentAfter)
	}
	for _, controller := range requiredV2Controllers {
		if !strings.Contains(probeSubtreeControl, "+"+controller) {
			t.Fatalf("probe subtree_control = %q, missing +%s", probeSubtreeControl, controller)
		}
	}

	if err := os.WriteFile(filepath.Join(mountpoint, "cgroup.controllers"), []byte("cpu memory pids\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateV2DelegationWithProbe(mountpoint, createProbe); err == nil {
		t.Fatal("validateV2Delegation unexpectedly accepted missing cpuset controller")
	}
}

func TestValidateV2DelegationRejectsUnwritableSubtreeControl(t *testing.T) {
	mountpoint := t.TempDir()
	writeFakeV2ControlFiles(t, mountpoint, "cpu cpuset memory pids\n")
	subtreeControl := filepath.Join(mountpoint, "cgroup.subtree_control")
	if err := os.Remove(subtreeControl); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(subtreeControl, 0700); err != nil {
		t.Fatal(err)
	}
	if err := validateV2DelegationWithProbe(mountpoint, nil); err == nil {
		t.Fatal("validateV2Delegation unexpectedly accepted an unusable subtree_control")
	}
}

func writeFakeV2ControlFiles(t *testing.T, path, controllers string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(path, "cgroup.controllers"), []byte(controllers), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "cgroup.subtree_control"), nil, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestValidateHostRejectsHierarchyMismatch(t *testing.T) {
	mountpoint := t.TempDir()
	if err := validateHost(config.ResourceConfig{CgroupVersion: config.CgroupVersionV1}, cgroups.Unified, mountpoint); err == nil {
		t.Fatal("v1 unexpectedly accepted a unified hierarchy")
	}
	if err := validateHost(config.ResourceConfig{CgroupVersion: config.CgroupVersionV2, CgroupParent: "/"}, cgroups.Legacy, mountpoint); err == nil {
		t.Fatal("v2 unexpectedly accepted a legacy hierarchy")
	}
}

func TestValidateHostAcceptsMatchingModes(t *testing.T) {
	if err := validateHost(config.ResourceConfig{CgroupVersion: config.CgroupVersionV1}, cgroups.Legacy, t.TempDir()); err != nil {
		t.Fatalf("v1 legacy preflight: %v", err)
	}
}

func TestLinuxResourcesPreservesExistingFields(t *testing.T) {
	resources := linuxResources(&runtime.LinuxSandboxResources{
		CpuShares:          128,
		CpuPeriod:          10000,
		CpuQuota:           8000,
		CpusetCpus:         "0",
		CpusetMems:         "0",
		MemoryLimitInBytes: 256 * 1024 * 1024,
	})
	if resources.CPU == nil || resources.CPU.Shares == nil || *resources.CPU.Shares != 128 {
		t.Fatalf("CPU shares were not preserved: %+v", resources.CPU)
	}
	if resources.CPU.Period == nil || *resources.CPU.Period != 10000 || resources.CPU.Quota == nil || *resources.CPU.Quota != 8000 {
		t.Fatalf("CPU quota/period were not preserved: %+v", resources.CPU)
	}
	if resources.CPU.Cpus != "0" || resources.CPU.Mems != "0" {
		t.Fatalf("cpuset was not preserved: %+v", resources.CPU)
	}
	if resources.Memory == nil || resources.Memory.Limit == nil || *resources.Memory.Limit != 256*1024*1024 {
		t.Fatalf("memory limit was not preserved: %+v", resources.Memory)
	}
}

func TestInitialV2ResourcesEnableRequiredControllers(t *testing.T) {
	resources := initialV2Resources(256)
	want := map[string]bool{"cpu": true, "cpuset": true, "memory": true, "pids": true}
	for _, controller := range resources.EnabledControllers() {
		delete(want, controller)
	}
	if len(want) != 0 {
		t.Fatalf("required controllers not enabled: %v", want)
	}
	if resources.Pids == nil || resources.Pids.Max != 256 {
		t.Fatalf("pids limit = %+v, want 256", resources.Pids)
	}
	if unlimited := initialV2Resources(0).Pids.Max; unlimited != -1 {
		t.Fatalf("unlimited pids = %d, want -1", unlimited)
	}
}

func TestReadMemoryEvent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "memory.events")
	if err := os.WriteFile(path, []byte("low 0\nhigh 2\noom 3\noom_kill 4\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readMemoryEvent(path, "oom_kill")
	if err != nil {
		t.Fatal(err)
	}
	if got != 4 {
		t.Fatalf("oom_kill = %d, want 4", got)
	}
}

func TestReadUintFileMax(t *testing.T) {
	path := filepath.Join(t.TempDir(), "memory.max")
	if err := os.WriteFile(path, []byte("max\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readUintFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != ^uint64(0) {
		t.Fatalf("max = %d, want MaxUint64", got)
	}
}

func TestReadCPUPeriod(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cpu.max")
	if err := os.WriteFile(path, []byte("max 250000\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readCPUPeriod(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != 250000 {
		t.Fatalf("CPU period = %d, want 250000", got)
	}
}

func TestV2DriverUpdateQuotaPreservesCurrentPeriod(t *testing.T) {
	mountpoint := t.TempDir()
	group := filepath.Join(mountpoint, "sandbox", "test")
	if err := os.MkdirAll(group, 0755); err != nil {
		t.Fatal(err)
	}
	cpuMax := filepath.Join(group, "cpu.max")
	if err := os.WriteFile(cpuMax, []byte("max 250000\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := newV2Driver(mountpoint, "/", "/sandbox").Update("/sandbox/test", &runtime.LinuxSandboxResources{CpuQuota: 50000}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(cpuMax)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data); got != "50000 250000" {
		t.Fatalf("cpu.max = %q, want %q", got, "50000 250000")
	}
}

func TestStatsFromV2ConvertsMicrosecondsToNanoseconds(t *testing.T) {
	got := statsFromV2(&cgstats.Metrics{
		CPU:    &cgstats.CPUStat{UsageUsec: 7, UserUsec: 3, SystemUsec: 4},
		Memory: &cgstats.MemoryStat{Usage: 1024, UsageLimit: 2048},
	}, 1536)
	if got.CPUUsageNS != 7000 || got.CPUUserNS != 3000 || got.CPUKernelNS != 4000 {
		t.Fatalf("unexpected CPU stats: %+v", got)
	}
	if got.MemoryUsageBytes != 1024 || got.MemoryLimitBytes != 2048 || got.MemoryMaxUsageBytes != 1536 {
		t.Fatalf("unexpected memory stats: %+v", got)
	}
}

func TestV2DriverStatsFromCgroupFiles(t *testing.T) {
	mountpoint := t.TempDir()
	group := filepath.Join(mountpoint, "sandbox", "test")
	if err := os.MkdirAll(group, 0755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"cgroup.controllers":  "cpu memory pids\n",
		"cpu.stat":            "usage_usec 11\nuser_usec 7\nsystem_usec 4\n",
		"memory.stat":         "anon 1024\n",
		"memory.events":       "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n",
		"memory.current":      "4096\n",
		"memory.max":          "8192\n",
		"memory.peak":         "6144\n",
		"memory.swap.current": "0\n",
		"memory.swap.max":     "max\n",
		"pids.current":        "2\n",
		"pids.max":            "256\n",
	}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(group, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := newV2Driver(mountpoint, "/", "/sandbox").Stats("/sandbox/test")
	if err != nil {
		t.Fatal(err)
	}
	if got.CPUUsageNS != 11000 || got.CPUUserNS != 7000 || got.CPUKernelNS != 4000 {
		t.Fatalf("unexpected CPU stats: %+v", got)
	}
	if got.MemoryUsageBytes != 4096 || got.MemoryLimitBytes != 8192 || got.MemoryMaxUsageBytes != 6144 {
		t.Fatalf("unexpected memory stats: %+v", got)
	}
}

func TestV2DriverWatchOOMFiresOnceAndStopsIdempotently(t *testing.T) {
	mountpoint := t.TempDir()
	group := filepath.Join(mountpoint, "sandbox", "test")
	if err := os.MkdirAll(group, 0755); err != nil {
		t.Fatal(err)
	}
	eventsPath := filepath.Join(group, "memory.events")
	if err := os.WriteFile(eventsPath, []byte("oom 0\noom_kill 0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	fired := make(chan struct{}, 1)
	stop, err := newV2Driver(mountpoint, "/", "/sandbox").WatchOOM("/sandbox/test", func() { fired <- struct{}{} })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)
	eventsFile, err := os.OpenFile(eventsPath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eventsFile.WriteString("oom 1\noom_kill 1\n"); err != nil {
		_ = eventsFile.Close()
		t.Fatal(err)
	}
	if err := eventsFile.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-fired:
	case <-time.After(2 * time.Second):
		t.Fatal("OOM watcher did not fire")
	}
	stop()
	stop()
}

func TestV2DriverStopReconcilesFinalOOMCounter(t *testing.T) {
	mountpoint := t.TempDir()
	group := filepath.Join(mountpoint, "sandbox", "test")
	if err := os.MkdirAll(group, 0755); err != nil {
		t.Fatal(err)
	}
	eventsPath := filepath.Join(group, "memory.events")
	if err := os.WriteFile(eventsPath, []byte("oom 0\noom_kill 0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	fired := make(chan struct{}, 1)
	stop, err := newV2Driver(mountpoint, "/", "/sandbox").WatchOOM("/sandbox/test", func() { fired <- struct{}{} })
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(eventsPath, []byte("oom 1\noom_kill 1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	stop()
	select {
	case <-fired:
	default:
		t.Fatal("stop returned before reconciling final oom_kill counter")
	}
}

func TestV2DriverWatchOOMReconcilesInitializationWindow(t *testing.T) {
	mountpoint := t.TempDir()
	group := filepath.Join(mountpoint, "sandbox", "test")
	if err := os.MkdirAll(group, 0755); err != nil {
		t.Fatal(err)
	}
	eventsPath := filepath.Join(group, "memory.events")
	if err := os.WriteFile(eventsPath, []byte("oom 0\noom_kill 0\n"), 0600); err != nil {
		t.Fatal(err)
	}

	fired := make(chan struct{}, 1)
	addWatch := func(fd int, pathname string, mask uint32) (int, error) {
		// Simulate an OOM after the baseline read but before the inotify watch
		// becomes active. The post-registration reconciliation must catch it.
		if err := os.WriteFile(eventsPath, []byte("oom 1\noom_kill 1\n"), 0600); err != nil {
			return -1, err
		}
		return unix.InotifyAddWatch(fd, pathname, mask)
	}
	stop, err := newV2Driver(mountpoint, "/", "/sandbox").watchOOM("/sandbox/test", func() {
		fired <- struct{}{}
	}, addWatch)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	select {
	case <-fired:
	case <-time.After(2 * time.Second):
		t.Fatal("OOM watcher missed an oom_kill during initialization")
	}
}

func TestV2DriverDeleteMissingGroupIsIdempotent(t *testing.T) {
	mountpoint := t.TempDir()
	if err := newV2Driver(mountpoint, "/", "/sandbox").Delete("/sandbox/missing"); err != nil {
		t.Fatalf("Delete missing group: %v", err)
	}
}
