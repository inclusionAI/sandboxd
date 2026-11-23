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
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/containerd/cgroups/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func v1MemoryFixture(t *testing.T, hierarchy, usage string) string {
	t.Helper()
	groupPath := t.TempDir()
	writeV1MemoryFixture(t, groupPath, "memory.use_hierarchy", hierarchy)
	writeV1MemoryFixture(t, groupPath, "memory.usage_in_bytes", usage)
	return groupPath
}

func writeV1MemoryFixture(t *testing.T, groupPath, name, value string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(groupPath, name), []byte(value), 0644))
}

func TestReadV1MemoryHierarchy(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		value   string
		enabled bool
		wantErr bool
	}{
		{name: "disabled", value: "0\n"},
		{name: "enabled", value: "1\n", enabled: true},
		{name: "empty", wantErr: true},
		{name: "invalid number", value: "2\n", wantErr: true},
		{name: "unlimited", value: "max\n", wantErr: true},
		{name: "garbage", value: "invalid\n", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			groupPath := v1MemoryFixture(t, test.value, "0\n")
			enabled, err := readV1MemoryHierarchy(groupPath)
			if test.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.enabled, enabled)
		})
	}
	t.Run("missing control file", func(t *testing.T) {
		t.Parallel()
		_, err := readV1MemoryHierarchy(t.TempDir())
		require.Error(t, err)
		assert.ErrorIs(t, err, os.ErrNotExist)
	})
}

func TestEnableV1MemoryHierarchyEmptyRoot(t *testing.T) {
	t.Parallel()
	groupPath := v1MemoryFixture(t, "0\n", "0\n")
	setCalls := 0
	err := enableV1MemoryHierarchy(groupPath, func(filename string) error {
		setCalls++
		assert.Equal(t, filepath.Join(groupPath, "memory.use_hierarchy"), filename)
		return os.WriteFile(filename, []byte("1\n"), 0644)
	})
	require.NoError(t, err)
	assert.Equal(t, 1, setCalls)
	enabled, err := readV1MemoryHierarchy(groupPath)
	require.NoError(t, err)
	assert.True(t, enabled)
}

func TestEnableV1MemoryHierarchyAlreadyEnabledDoesNotWrite(t *testing.T) {
	t.Parallel()
	groupPath := v1MemoryFixture(t, "1\n", "0\n")
	require.NoError(t, os.Mkdir(filepath.Join(groupPath, "running-sandbox"), 0755))
	require.NoError(t, enableV1MemoryHierarchy(groupPath, func(string) error {
		t.Fatal("an enabled hierarchy must not be rewritten")
		return nil
	}))
}

func TestEnableV1MemoryHierarchyPreservesExistingFlatSubtree(t *testing.T) {
	t.Parallel()
	groupPath := v1MemoryFixture(t, "0\n", "7\n")
	childPath := filepath.Join(groupPath, "running-sandbox")
	require.NoError(t, os.Mkdir(childPath, 0755))
	writeV1MemoryFixture(t, childPath, "memory.usage_in_bytes", "1048576\n")
	err := enableV1MemoryHierarchy(groupPath, func(string) error {
		t.Fatal("an existing flat subtree must not be reconfigured")
		return nil
	})
	require.ErrorIs(t, err, errV1MemoryHierarchyDisabled)
	data, err := os.ReadFile(filepath.Join(childPath, "memory.usage_in_bytes"))
	require.NoError(t, err)
	assert.Equal(t, "1048576\n", string(data))
	enabled, err := readV1MemoryHierarchy(groupPath)
	require.NoError(t, err)
	assert.False(t, enabled)
	_, err = readV1RootMemoryUsage(groupPath)
	assert.ErrorIs(t, err, errV1MemoryHierarchyDisabled)
}

func TestEnableV1MemoryHierarchyPropagatesWriteFailures(t *testing.T) {
	t.Parallel()
	for _, errno := range []syscall.Errno{syscall.EBUSY, syscall.EACCES} {
		t.Run(errno.Error(), func(t *testing.T) {
			t.Parallel()
			groupPath := v1MemoryFixture(t, "0\n", "0\n")
			err := enableV1MemoryHierarchy(groupPath, func(filename string) error {
				return &os.PathError{Op: "write", Path: filename, Err: errno}
			})
			require.ErrorIs(t, err, errno)
			enabled, readErr := readV1MemoryHierarchy(groupPath)
			require.NoError(t, readErr)
			assert.False(t, enabled)
		})
	}
}

func TestEnableV1MemoryHierarchyVerifiesKernelResult(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name      string
		value     string
		remove    bool
		wantError error
	}{
		{name: "not enabled", value: "0\n", wantError: errV1MemoryHierarchyDisabled},
		{name: "invalid readback", value: "2\n"},
		{name: "missing readback", remove: true, wantError: os.ErrNotExist},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			groupPath := v1MemoryFixture(t, "0\n", "0\n")
			err := enableV1MemoryHierarchy(groupPath, func(filename string) error {
				if test.remove {
					return os.Remove(filename)
				}
				return os.WriteFile(filename, []byte(test.value), 0644)
			})
			require.Error(t, err)
			if test.wantError != nil {
				assert.ErrorIs(t, err, test.wantError)
			}
		})
	}
}

func TestEnableV1MemoryHierarchyRejectsUnknownCapabilityBeforeWriting(t *testing.T) {
	t.Parallel()
	groupPath := v1MemoryFixture(t, "unknown\n", "0\n")
	require.Error(t, enableV1MemoryHierarchy(groupPath, func(string) error {
		t.Fatal("an unknown hierarchy flag must not be overwritten")
		return nil
	}))
}

func TestSetV1MemoryHierarchy(t *testing.T) {
	t.Parallel()
	groupPath := v1MemoryFixture(t, "0\n", "0\n")
	require.NoError(t, setV1MemoryHierarchy(filepath.Join(groupPath, "memory.use_hierarchy")))
	enabled, err := readV1MemoryHierarchy(groupPath)
	require.NoError(t, err)
	assert.True(t, enabled)

	missing := filepath.Join(groupPath, "missing-control-file")
	err = setV1MemoryHierarchy(missing)
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.Stat(missing)
	assert.ErrorIs(t, err, os.ErrNotExist, "a missing kernel control file must not be created")
}

func TestPrepareV1MemoryRoot(t *testing.T) {
	t.Parallel()
	t.Run("creates owned root before children", func(t *testing.T) {
		t.Parallel()
		memoryMountpoint := t.TempDir()
		// A regular filesystem does not synthesize kernel control files after
		// mkdir. The missing capability is soft, but the owned root must exist.
		require.NoError(t, prepareV1MemoryRoot(memoryMountpoint, "/sandboxd"))
		info, err := os.Stat(filepath.Join(memoryMountpoint, "sandboxd"))
		require.NoError(t, err)
		assert.True(t, info.IsDir())
	})
	t.Run("enables an existing empty root", func(t *testing.T) {
		t.Parallel()
		memoryMountpoint := t.TempDir()
		groupPath := filepath.Join(memoryMountpoint, "sandboxd")
		require.NoError(t, os.Mkdir(groupPath, 0755))
		writeV1MemoryFixture(t, groupPath, "memory.use_hierarchy", "0\n")
		writeV1MemoryFixture(t, groupPath, "memory.usage_in_bytes", "0\n")
		require.NoError(t, prepareV1MemoryRoot(memoryMountpoint, "/sandboxd"))
		enabled, err := readV1MemoryHierarchy(groupPath)
		require.NoError(t, err)
		assert.True(t, enabled)
	})
	t.Run("preserves live flat root without failing startup", func(t *testing.T) {
		t.Parallel()
		memoryMountpoint := t.TempDir()
		groupPath := filepath.Join(memoryMountpoint, "sandboxd")
		require.NoError(t, os.Mkdir(groupPath, 0755))
		writeV1MemoryFixture(t, groupPath, "memory.use_hierarchy", "0\n")
		writeV1MemoryFixture(t, groupPath, "memory.usage_in_bytes", "1\n")
		require.NoError(t, os.Mkdir(filepath.Join(groupPath, "live"), 0755))
		require.NoError(t, prepareV1MemoryRoot(memoryMountpoint, "/sandboxd"))
		_, err := readV1RootMemoryUsage(groupPath)
		assert.ErrorIs(t, err, errV1MemoryHierarchyDisabled)
		info, err := os.Stat(filepath.Join(groupPath, "live"))
		require.NoError(t, err)
		assert.True(t, info.IsDir())
	})
	t.Run("missing controller fails startup", func(t *testing.T) {
		t.Parallel()
		memoryMountpoint := filepath.Join(t.TempDir(), "missing")
		require.ErrorIs(t, prepareV1MemoryRoot(memoryMountpoint, "/sandboxd"), os.ErrNotExist)
		_, err := os.Stat(memoryMountpoint)
		assert.ErrorIs(t, err, os.ErrNotExist)
	})
	t.Run("owned root cannot be created", func(t *testing.T) {
		t.Parallel()
		memoryMountpoint := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(memoryMountpoint, "sandboxd"), []byte("occupied"), 0644))
		require.Error(t, prepareV1MemoryRoot(memoryMountpoint, "/sandboxd"))
	})
}

func TestReadV1RootMemoryUsage(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		usage   string
		want    uint64
		wantErr bool
	}{
		{name: "real zero", usage: "0\n"},
		{name: "nonzero", usage: "1048576\n", want: 1048576},
		{name: "maximum uint", usage: "18446744073709551615\n", want: ^uint64(0)},
		{name: "missing value", wantErr: true},
		{name: "unlimited token", usage: "max\n", wantErr: true},
		{name: "negative", usage: "-1\n", wantErr: true},
		{name: "hexadecimal", usage: "0x10\n", wantErr: true},
		{name: "overflow", usage: "18446744073709551616\n", wantErr: true},
		{name: "garbage", usage: "invalid\n", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			groupPath := v1MemoryFixture(t, "1\n", test.usage)
			usage, err := readV1RootMemoryUsage(groupPath)
			if test.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.want, usage)
		})
	}
	t.Run("missing usage file is not zero", func(t *testing.T) {
		t.Parallel()
		groupPath := v1MemoryFixture(t, "1\n", "0\n")
		require.NoError(t, os.Remove(filepath.Join(groupPath, "memory.usage_in_bytes")))
		_, err := readV1RootMemoryUsage(groupPath)
		assert.ErrorIs(t, err, os.ErrNotExist)
	})
	t.Run("invalid hierarchy is not a successful zero", func(t *testing.T) {
		t.Parallel()
		groupPath := v1MemoryFixture(t, "2\n", "0\n")
		_, err := readV1RootMemoryUsage(groupPath)
		require.Error(t, err)
		assert.False(t, errors.Is(err, errV1MemoryHierarchyDisabled))
	})
}

func TestReadV1RootMemoryUsageRechecksHierarchyAndRecovers(t *testing.T) {
	t.Parallel()
	groupPath := v1MemoryFixture(t, "1\n", "1048576\n")
	usage, err := readV1RootMemoryUsage(groupPath)
	require.NoError(t, err)
	assert.Equal(t, uint64(1048576), usage)

	writeV1MemoryFixture(t, groupPath, "memory.use_hierarchy", "0\n")
	writeV1MemoryFixture(t, groupPath, "memory.usage_in_bytes", "0\n")
	_, err = readV1RootMemoryUsage(groupPath)
	assert.ErrorIs(t, err, errV1MemoryHierarchyDisabled)

	writeV1MemoryFixture(t, groupPath, "memory.use_hierarchy", "1\n")
	writeV1MemoryFixture(t, groupPath, "memory.usage_in_bytes", "2097152\n")
	usage, err = readV1RootMemoryUsage(groupPath)
	require.NoError(t, err)
	assert.Equal(t, uint64(2097152), usage)
}

func TestStatsRootUsesAggregateOperation(t *testing.T) {
	t.Parallel()
	expected := Stats{MemoryUsageBytes: 1048576, CPUUsageNanos: 42}
	ops := &fakeCgroupOps{stats: expected}
	manager := &CgroupManager{ops: ops, rootName: "/sandboxd"}
	stats, err := manager.StatsRoot()
	require.NoError(t, err)
	assert.Equal(t, expected, stats)
	assert.Equal(t, []string{"stat-root"}, ops.calls)

	ops.calls = nil
	stats, err = manager.Stats("/sandboxd/child")
	require.NoError(t, err)
	assert.Equal(t, expected, stats)
	assert.Empty(t, ops.calls, "individual sandbox stats must not use root aggregation")
}

func TestV1RootMemoryUsageAggregatesChildIntegration(t *testing.T) {
	const helperEnv = "SANDBOXD_TEST_V1_MEMORY_CHILD"
	const allocatedBytes = 32 << 20
	if groupPath := os.Getenv(helperEnv); groupPath != "" {
		err := os.WriteFile(filepath.Join(groupPath, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0644)
		require.NoError(t, err)
		memory := make([]byte, allocatedBytes)
		for i := 0; i < len(memory); i += os.Getpagesize() {
			memory[i] = 1
		}
		fmt.Println("ready")
		for {
			time.Sleep(time.Hour)
			runtime.KeepAlive(memory)
		}
	}
	if os.Getenv("SANDBOXD_RUN_CGROUP_INTEGRATION") != "1" {
		t.Skip("set SANDBOXD_RUN_CGROUP_INTEGRATION=1 to run")
	}
	mode := detectCgroupMode()
	if mode != cgroups.Legacy && mode != cgroups.Hybrid {
		t.Skip("requires cgroup v1")
	}

	memoryMountpoint := filepath.Join(cgroupMountpoint, "memory")
	rootName := fmt.Sprintf("/sandboxd-v1-memory-test-%d-%d", os.Getpid(), time.Now().UnixNano())
	rootPath := filepath.Join(memoryMountpoint, rootName)
	require.NoError(t, prepareV1MemoryRoot(memoryMountpoint, rootName))
	t.Cleanup(func() { assert.NoError(t, os.Remove(rootPath)) })
	enabled, err := readV1MemoryHierarchy(rootPath)
	require.NoError(t, err)
	require.True(t, enabled, "integration requires a functioning hierarchical memory root")
	childPath := filepath.Join(rootPath, "child")
	require.NoError(t, os.Mkdir(childPath, 0755))
	t.Cleanup(func() { assert.NoError(t, os.Remove(childPath)) })

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestV1RootMemoryUsageAggregatesChildIntegration$")
	cmd.Env = append(os.Environ(), helperEnv+"="+childPath)
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	scanner := bufio.NewScanner(stdout)
	require.True(t, scanner.Scan(), "child did not report a resident allocation: %v", scanner.Err())
	require.Equal(t, "ready", scanner.Text())
	childUsage, err := readV1RootMemoryUsage(childPath)
	require.NoError(t, err)
	require.GreaterOrEqual(t, childUsage, uint64(allocatedBytes/2), "child must have a substantial resident charge")
	stats, err := (&cgroupV1{}).statRoot(rootName)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, stats.MemoryUsageBytes, childUsage, "parent counter must include child resident memory")
}
