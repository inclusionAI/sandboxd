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
	"testing"

	"github.com/containerd/cgroups/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func parentMemoryFixture(t *testing.T) (*CgroupManager, string) {
	t.Helper()
	mountpoint := t.TempDir()
	root := "/tenant/sandbox-parent"
	group := filepath.Join(mountpoint, root)
	require.NoError(t, os.MkdirAll(group, 0755))
	writeTestFile(t, filepath.Join(group, "memory.current"), "256\n")
	writeTestFile(t, filepath.Join(group, "memory.max"), "4096\n")
	return &CgroupManager{rootName: root, ops: &cgroupV2{mountpoint: mountpoint}}, group
}

func TestReadParentMemoryUsesConfiguredLiveControls(t *testing.T) {
	manager, group := parentMemoryFixture(t)
	manager.rootName = "tenant//sandbox-parent/"
	// A different default-named group must not be substituted for this parent.
	decoy := filepath.Join(manager.ops.(*cgroupV2).mountpoint, "akernel")
	require.NoError(t, os.MkdirAll(decoy, 0755))
	writeTestFile(t, filepath.Join(decoy, "memory.current"), "17")
	writeTestFile(t, filepath.Join(decoy, "memory.max"), "23")

	// A zero startup budget also covers disabled automatic memory limiting.
	stats, err := manager.ReadParentMemory()
	require.NoError(t, err)
	assert.Equal(t, ParentMemoryStats{
		CgroupPath: "/tenant/sandbox-parent", CurrentBytes: 256, MaxBytes: 4096,
	}, stats)

	// Runtime changes in both controls override the cached startup budget.
	manager.memoryMax = 99999
	writeTestFile(t, filepath.Join(group, "memory.current"), "1536\n")
	writeTestFile(t, filepath.Join(group, "memory.max"), "2048\n")
	stats, err = manager.ReadParentMemory()
	require.NoError(t, err)
	assert.Equal(t, ParentMemoryStats{
		CgroupPath: "/tenant/sandbox-parent", CurrentBytes: 1536, MaxBytes: 2048,
	}, stats)
	assert.Equal(t, int64(99999), manager.MemoryLimit())
	assertFileContents(t, filepath.Join(group, "memory.current"), "1536\n")
	assertFileContents(t, filepath.Join(group, "memory.max"), "2048\n")
	assertFileContents(t, filepath.Join(decoy, "memory.current"), "17")
	assertFileContents(t, filepath.Join(decoy, "memory.max"), "23")
}

func TestReadParentMemoryFiniteAndUnlimitedValues(t *testing.T) {
	for _, test := range []struct {
		name, current, max   string
		wantCurrent, wantMax uint64
		unlimited            bool
	}{
		{name: "true zero current", current: "0", max: "4096", wantMax: 4096},
		{name: "numeric zero limit", current: "0", max: "0"},
		{name: "current equals limit", current: "4096", max: "4096", wantCurrent: 4096, wantMax: 4096},
		{name: "current above limit remains observed data", current: "4097", max: "4096", wantCurrent: 4097, wantMax: 4096},
		{name: "uint64 maximum is finite", current: "18446744073709551615", max: "18446744073709551615", wantCurrent: ^uint64(0), wantMax: ^uint64(0)},
		{name: "unlimited", current: "123", max: "max", wantCurrent: 123, unlimited: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager, group := parentMemoryFixture(t)
			writeTestFile(t, filepath.Join(group, "memory.current"), test.current+"\n")
			writeTestFile(t, filepath.Join(group, "memory.max"), test.max+"\n")
			stats, err := manager.ReadParentMemory()
			require.NoError(t, err)
			assert.Equal(t, ParentMemoryStats{
				CgroupPath: manager.rootName, CurrentBytes: test.wantCurrent,
				MaxBytes: test.wantMax, Unlimited: test.unlimited,
			}, stats)
			assertFileContents(t, filepath.Join(group, "memory.current"), test.current+"\n")
			assertFileContents(t, filepath.Join(group, "memory.max"), test.max+"\n")
		})
	}
}

func TestReadParentMemoryRejectsInvalidControls(t *testing.T) {
	for _, file := range []string{"memory.current", "memory.max"} {
		for _, value := range []string{"", " \n", "garbage", "-1", "+1", "1.5", "1 2", "0x10", "18446744073709551616", "MAX"} {
			t.Run(file+"/"+value, func(t *testing.T) {
				manager, group := parentMemoryFixture(t)
				writeTestFile(t, filepath.Join(group, file), value)
				stats, err := manager.ReadParentMemory()
				require.ErrorContains(t, err, file)
				assert.Zero(t, stats, "invalid samples must not expose partial data")
				assertFileContents(t, filepath.Join(group, file), value)
			})
		}
		t.Run(file+"/missing", func(t *testing.T) {
			manager, group := parentMemoryFixture(t)
			filename := filepath.Join(group, file)
			require.NoError(t, os.Remove(filename))
			stats, err := manager.ReadParentMemory()
			require.ErrorContains(t, err, file)
			assert.ErrorIs(t, err, os.ErrNotExist)
			assert.Zero(t, stats)
			_, err = os.Stat(filename)
			assert.ErrorIs(t, err, os.ErrNotExist, "reading must not create missing controls")
		})
	}
	manager, group := parentMemoryFixture(t)
	writeTestFile(t, filepath.Join(group, "memory.current"), "max\n")
	stats, err := manager.ReadParentMemory()
	require.ErrorContains(t, err, "memory.current")
	assert.Zero(t, stats, "literal max is accepted only for memory.max")
}

func TestReadParentMemoryRejectsUnsupportedBackends(t *testing.T) {
	fake := &fakeCgroupOps{}
	for _, backend := range []cgroupOps{nil, (*cgroupV2)(nil), &cgroupV1{}, &cgroupV1{detectedMode: cgroups.Hybrid}, fake} {
		manager := &CgroupManager{rootName: "/unused-parent", ops: backend}
		stats, err := manager.ReadParentMemory()
		require.ErrorContains(t, err, "requires cgroup v2")
		assert.Zero(t, stats)
	}
	assert.Empty(t, fake.calls, "unsupported backends must not run cgroup operations")
	var manager *CgroupManager
	stats, err := manager.ReadParentMemory()
	require.ErrorContains(t, err, "requires cgroup v2")
	assert.Zero(t, stats)
}

func TestReadParentMemoryRejectsHierarchyRoot(t *testing.T) {
	for _, root := range []string{"", " ", "/", "//", ".", "/tenant/.."} {
		manager, group := parentMemoryFixture(t)
		manager.rootName = root
		mountpoint := manager.ops.(*cgroupV2).mountpoint
		// Even valid-looking hierarchy-root files must not be read as parent data.
		writeTestFile(t, filepath.Join(mountpoint, "memory.current"), "123")
		writeTestFile(t, filepath.Join(mountpoint, "memory.max"), "456")
		stats, err := manager.ReadParentMemory()
		require.ErrorContains(t, err, "non-root", "root=%q", root)
		assert.Zero(t, stats)
		assertFileContents(t, filepath.Join(group, "memory.current"), "256\n")
		assertFileContents(t, filepath.Join(mountpoint, "memory.max"), "456")
	}
	for _, mountpoint := range []string{"", "relative"} {
		manager := &CgroupManager{rootName: "/parent", ops: &cgroupV2{mountpoint: mountpoint}}
		stats, err := manager.ReadParentMemory()
		require.ErrorContains(t, err, "mountpoint")
		assert.Zero(t, stats)
	}
}

func TestReadParentMemoryRejectsObservedCapChanges(t *testing.T) {
	for _, test := range []struct{ before, after string }{
		{before: "4096", after: "8192"},
		{before: "max", after: "0"},
		{before: "0", after: "max"},
	} {
		t.Run(test.before+" to "+test.after, func(t *testing.T) {
			manager, group := parentMemoryFixture(t)
			writeTestFile(t, filepath.Join(group, "memory.max"), test.before)
			var reads []string
			stats, err := readParentMemoryFiles(group, func(filename string) ([]byte, error) {
				reads = append(reads, filepath.Base(filename))
				if filepath.Base(filename) == "memory.current" {
					writeTestFile(t, filepath.Join(group, "memory.max"), test.after)
				}
				return os.ReadFile(filename)
			})
			require.ErrorContains(t, err, "changed during read")
			assert.Zero(t, stats)
			assert.Equal(t, []string{"memory.max", "memory.current", "memory.max"}, reads)
			assert.Zero(t, manager.MemoryLimit())
		})
	}
}

func TestReadParentMemoryRejectsInvalidSecondMaxRead(t *testing.T) {
	for _, second := range []string{"invalid", "18446744073709551616", "missing"} {
		t.Run(second, func(t *testing.T) {
			_, group := parentMemoryFixture(t)
			stats, err := readParentMemoryFiles(group, func(filename string) ([]byte, error) {
				if filepath.Base(filename) == "memory.current" {
					if second == "missing" {
						require.NoError(t, os.Remove(filepath.Join(group, "memory.max")))
					} else {
						writeTestFile(t, filepath.Join(group, "memory.max"), second)
					}
				}
				return os.ReadFile(filename)
			})
			require.ErrorContains(t, err, "memory.max")
			assert.Zero(t, stats)
			if second == "missing" {
				assert.True(t, errors.Is(err, os.ErrNotExist))
			}
		})
	}
}
