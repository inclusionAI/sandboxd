// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package resourcemanager

import (
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/containerd/cgroups/v3"
	"github.com/moby/sys/mountinfo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const gib = int64(1 << 30)

func writeFixture(t *testing.T, filename, value string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(filename), 0755))
	require.NoError(t, os.WriteFile(filename, []byte(value), 0644))
}

func writeV2Group(t *testing.T, group, cpuMax, memoryMax string) {
	t.Helper()
	writeFixture(t, filepath.Join(group, "cpu.max"), cpuMax)
	writeFixture(t, filepath.Join(group, "memory.max"), memoryMax)
}

func TestParseSelfCgroups(t *testing.T) {
	parsed, err := parseSelfCgroups(strings.NewReader(
		"0::/node.slice/sandboxd\n" +
			"4:cpu,cpuacct:/node.slice/sandboxd\n" +
			"3:memory:/node.slice/sandboxd\n",
	))
	require.NoError(t, err)
	assert.Equal(t, "/node.slice/sandboxd", parsed.unified)
	assert.Equal(t, "/node.slice/sandboxd", parsed.controller["cpu"])
	assert.Equal(t, "/node.slice/sandboxd", parsed.controller["cpuacct"])
	assert.Equal(t, "/node.slice/sandboxd", parsed.controller["memory"])
}

func TestFindHierarchyMapsMountedSubtree(t *testing.T) {
	mount := &mountinfo.Info{
		Root:       "/node.slice",
		Mountpoint: "/sys/fs/cgroup",
		FSType:     "cgroup2",
	}
	hierarchy, err := findHierarchy(
		[]*mountinfo.Info{mount},
		"cgroup2",
		"",
		"/node.slice/sandboxd",
	)
	require.NoError(t, err)
	assert.Equal(t, "/sys/fs/cgroup", hierarchy.mountpoint)
	assert.Equal(t, "/sys/fs/cgroup/sandboxd", hierarchy.current)
}

func TestParseCPUSet(t *testing.T) {
	count, err := parseCPUSet("0-3,2-5,8,10-11\n")
	require.NoError(t, err)
	assert.Equal(t, 9, count)

	_, err = parseCPUSet("3-1")
	assert.Error(t, err)
}

func TestCgroupV2CapacityUsesMostRestrictiveAncestor(t *testing.T) {
	root := filepath.Join(t.TempDir(), "cgroup")
	parent := filepath.Join(root, "node")
	current := filepath.Join(parent, "sandboxd")
	writeV2Group(t, root, "max 100000\n", "max\n")
	writeV2Group(t, parent, "300000 100000\n", "6442450944\n")
	writeV2Group(t, current, "250000 100000\n", "8589934592\n")
	writeFixture(t, filepath.Join(current, "cpuset.cpus.effective"), "0-3\n")
	writeFixture(t, filepath.Join(root, "cpu-online"), "0-7\n")
	writeFixture(t, filepath.Join(root, "meminfo"), "MemTotal:       16777216 kB\n")

	mgr := &cgroupResourceManager{
		mode:      cgroups.Unified,
		cpu:       cgroupHierarchy{mountpoint: root, current: current},
		memory:    cgroupHierarchy{mountpoint: root, current: current},
		cpuset:    cgroupHierarchy{mountpoint: root, current: current},
		meminfo:   filepath.Join(root, "meminfo"),
		cpuOnline: filepath.Join(root, "cpu-online"),
	}
	cpu, memory, err := mgr.GetAvailableResource()
	require.NoError(t, err)
	assert.Equal(t, int64(2500), cpu)
	assert.Equal(t, 6*gib, memory)
}

func TestCgroupV2UnlimitedFallsBackToCPUSetAndHostMemory(t *testing.T) {
	root := filepath.Join(t.TempDir(), "cgroup")
	current := filepath.Join(root, "sandboxd")
	writeV2Group(t, root, "max 100000\n", "max\n")
	writeV2Group(t, current, "max 100000\n", "max\n")
	writeFixture(t, filepath.Join(current, "cpuset.cpus.effective"), "2-3\n")
	writeFixture(t, filepath.Join(root, "cpu-online"), "0-7\n")
	writeFixture(t, filepath.Join(root, "meminfo"), "MemTotal:       10485760 kB\n")

	mgr := &cgroupResourceManager{
		mode:      cgroups.Unified,
		cpu:       cgroupHierarchy{mountpoint: root, current: current},
		memory:    cgroupHierarchy{mountpoint: root, current: current},
		cpuset:    cgroupHierarchy{mountpoint: root, current: current},
		meminfo:   filepath.Join(root, "meminfo"),
		cpuOnline: filepath.Join(root, "cpu-online"),
	}
	cpu, memory, err := mgr.GetAvailableResource()
	require.NoError(t, err)
	assert.Equal(t, int64(2000), cpu)
	assert.Equal(t, 10*gib, memory)
}

func TestCgroupV1Capacity(t *testing.T) {
	testRoot := t.TempDir()
	cpuRoot := filepath.Join(testRoot, "cpu")
	memoryRoot := filepath.Join(testRoot, "memory")
	cpusetRoot := filepath.Join(testRoot, "cpuset")
	cpuCurrent := filepath.Join(cpuRoot, "sandboxd")
	memoryCurrent := filepath.Join(memoryRoot, "sandboxd")
	cpusetCurrent := filepath.Join(cpusetRoot, "sandboxd")

	writeFixture(t, filepath.Join(cpuRoot, "cpu.cfs_quota_us"), "-1\n")
	writeFixture(t, filepath.Join(cpuRoot, "cpu.cfs_period_us"), "100000\n")
	writeFixture(t, filepath.Join(cpuCurrent, "cpu.cfs_quota_us"), "150000\n")
	writeFixture(t, filepath.Join(cpuCurrent, "cpu.cfs_period_us"), "100000\n")
	writeFixture(t, filepath.Join(memoryRoot, "memory.limit_in_bytes"), strconvInt(math.MaxInt64))
	writeFixture(t, filepath.Join(memoryCurrent, "memory.limit_in_bytes"), strconvInt(3*gib))
	writeFixture(t, filepath.Join(cpusetCurrent, "cpuset.cpus"), "0-3\n")
	writeFixture(t, filepath.Join(testRoot, "cpu-online"), "0-7\n")
	writeFixture(t, filepath.Join(testRoot, "meminfo"), "MemTotal:       16777216 kB\n")

	mgr := &cgroupResourceManager{
		mode:      cgroups.Legacy,
		cpu:       cgroupHierarchy{mountpoint: cpuRoot, current: cpuCurrent},
		memory:    cgroupHierarchy{mountpoint: memoryRoot, current: memoryCurrent},
		cpuset:    cgroupHierarchy{mountpoint: cpusetRoot, current: cpusetCurrent},
		meminfo:   filepath.Join(testRoot, "meminfo"),
		cpuOnline: filepath.Join(testRoot, "cpu-online"),
	}
	cpu, memory, err := mgr.GetAvailableResource()
	require.NoError(t, err)
	assert.Equal(t, int64(1500), cpu)
	assert.Equal(t, 3*gib, memory)
}

func TestCgroupProviderReadsReadOnlyHierarchy(t *testing.T) {
	root := filepath.Join(t.TempDir(), "cgroup")
	writeV2Group(t, root, "200000 100000\n", "4294967296\n")
	writeFixture(t, filepath.Join(root, "cpuset.cpus.effective"), "0-3\n")
	writeFixture(t, filepath.Join(root, "cpu-online"), "0-7\n")
	writeFixture(t, filepath.Join(root, "meminfo"), "MemTotal:       8388608 kB\n")
	t.Cleanup(func() {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				return os.Chmod(path, 0755)
			}
			return os.Chmod(path, 0644)
		})
	})
	require.NoError(t, filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return os.Chmod(path, 0555)
		}
		return os.Chmod(path, 0444)
	}))

	mgr := &cgroupResourceManager{
		mode:      cgroups.Unified,
		cpu:       cgroupHierarchy{mountpoint: root, current: root},
		memory:    cgroupHierarchy{mountpoint: root, current: root},
		cpuset:    cgroupHierarchy{mountpoint: root, current: root},
		meminfo:   filepath.Join(root, "meminfo"),
		cpuOnline: filepath.Join(root, "cpu-online"),
	}
	cpu, memory, err := mgr.GetAvailableResource()
	require.NoError(t, err)
	assert.Equal(t, int64(2000), cpu)
	assert.Equal(t, 4*gib, memory)
}

func TestNormalizeProvider(t *testing.T) {
	for _, input := range []string{"", "kubernetes", " KUBERNETES "} {
		provider, err := normalizeProvider(input)
		require.NoError(t, err)
		assert.Equal(t, ProviderKubernetes, provider)
	}
	provider, err := normalizeProvider("CGROUP")
	require.NoError(t, err)
	assert.Equal(t, ProviderCgroup, provider)
	_, err = normalizeProvider("auto")
	assert.Error(t, err)
}

func strconvInt(value int64) string {
	return strconv.FormatInt(value, 10) + "\n"
}
