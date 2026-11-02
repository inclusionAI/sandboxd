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
	"strconv"
	"testing"

	"github.com/containerd/cgroups/v3"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const memoryMiB = int64(1 << 20)

func memoryLimitFixture(t *testing.T) (*cgroupV2, string, string, config.MemoryLimitConfig) {
	t.Helper()
	mountpoint := t.TempDir()
	root := "/pool/sandbox"
	group := filepath.Join(mountpoint, root)
	require.NoError(t, os.MkdirAll(group, 0755))
	writeTestFile(t, filepath.Join(mountpoint, "pool", "memory.max"), "max\n")
	writeTestFile(t, filepath.Join(group, "memory.max"), "max\n")
	writeTestFile(t, filepath.Join(group, "cgroup.events"), "populated 0\nfrozen 0\n")
	writeTestFile(t, filepath.Join(group, "memory.current"), "0\n")
	meminfo := filepath.Join(t.TempDir(), "meminfo")
	writeTestFile(t, meminfo, "MemTotal: 1048576 kB\nMemAvailable: 1 kB\n")
	return &cgroupV2{mountpoint: mountpoint}, root, meminfo, config.MemoryLimitConfig{
		Enabled: true, TotalReserve: "288MiB",
	}
}

func TestRootMemoryLimitCapacity(t *testing.T) {
	for _, test := range []struct {
		name, old            string
		ancestor, mountpoint int64
		populated            bool
		want                 int64
	}{
		{name: "total reserve", old: "max", want: 736},
		{name: "finite ancestor", old: "max", ancestor: 768, want: 480},
		{name: "visible mountpoint cap", old: "max", mountpoint: 640, want: 352},
		{name: "MemTotal remains upper bound", old: "max", ancestor: 2048, want: 736},
		{name: "restart excludes old root cap", old: "771751936", populated: true, want: 736},
		{name: "stricter existing cap", old: "536870912", populated: true, want: 512},
		{name: "lower existing cap", old: "805306368", want: 736},
	} {
		t.Run(test.name, func(t *testing.T) {
			ops, root, meminfo, cfg := memoryLimitFixture(t)
			group := filepath.Join(ops.mountpoint, root)
			writeTestFile(t, filepath.Join(group, "memory.max"), test.old+"\n")
			if test.ancestor != 0 {
				writeTestFile(t, filepath.Join(ops.mountpoint, "pool", "memory.max"), strconv.FormatInt(test.ancestor*memoryMiB, 10))
			}
			if test.mountpoint != 0 {
				writeTestFile(t, filepath.Join(ops.mountpoint, "memory.max"), strconv.FormatInt(test.mountpoint*memoryMiB, 10))
			}
			if test.populated {
				writeTestFile(t, filepath.Join(group, "cgroup.events"), "populated 1\n")
			}
			max, err := configureRootMemoryLimit(ops, root, cfg, meminfo, writeRootMemoryMax)
			require.NoError(t, err)
			assert.Equal(t, test.want*memoryMiB, max)
			actual, err := readMemoryMax(filepath.Join(group, "memory.max"))
			require.NoError(t, err)
			assert.Equal(t, max, actual)
		})
	}
}

func TestRootMemoryLimitRoundsConservatively(t *testing.T) {
	ops, root, meminfo, cfg := memoryLimitFixture(t)
	cfg.TotalReserve = "1B"
	writeTestFile(t, meminfo, "MemTotal: 1024 kB\n")
	max, err := configureRootMemoryLimit(ops, root, cfg, meminfo, writeRootMemoryMax)
	require.NoError(t, err)
	page := int64(os.Getpagesize())
	assert.Equal(t, (memoryMiB-1)/page*page, max)
	assert.Zero(t, max%page)
}

func TestRootMemoryLimitOffAndV1(t *testing.T) {
	cfg := config.MemoryLimitConfig{TotalReserve: "bad"}
	max, err := configureRootMemoryLimit(&cgroupV1{}, "/", cfg, "missing", nil)
	require.NoError(t, err)
	assert.Zero(t, max)
	cfg.Enabled = true
	_, err = configureRootMemoryLimit(&cgroupV1{}, "/sandbox", cfg, "missing", nil)
	require.ErrorContains(t, err, "requires cgroup v2")
	manager := &CgroupManager{memoryMax: 1234}
	max = manager.MemoryLimit()
	assert.Equal(t, int64(1234), max)
}

func TestNewCgroupManagerValidatesMemoryPolicyBeforePreparation(t *testing.T) {
	original := detectCgroupMode
	t.Cleanup(func() { detectCgroupMode = original })
	detectCgroupMode = func() cgroups.CGMode {
		t.Fatal("reserved root reached cgroup operations before validation")
		return cgroups.Unavailable
	}
	for _, root := range []string{"/", "/system.slice", "/system.slice/sandboxes", "/distillfs", "/distillfs/sandboxes"} {
		_, err := NewCgroupManager(nil, config.ResourceConfig{
			CgroupRootName: root, MemoryLimit: config.MemoryLimitConfig{Enabled: true},
		}, 1)
		require.Error(t, err, root)
	}
	for _, root := range []string{"/system.slice-other", "/distillfs-other", "/nested/sandboxes"} {
		_, err := validateMemoryLimitRoot(root)
		require.NoError(t, err, "similarly prefixed siblings remain valid")
	}
	// v1 preparation would inspect/write controller paths on the host. Its
	// rejection must occur before any such filesystem operations or DB load.
	for _, mode := range []cgroups.CGMode{cgroups.Legacy, cgroups.Hybrid} {
		detectCgroupMode = func() cgroups.CGMode { return mode }
		_, err := NewCgroupManager(nil, config.ResourceConfig{
			CgroupRootName: "/sandboxd-invalid-v1-policy", MemoryLimit: config.MemoryLimitConfig{Enabled: true},
		}, 1)
		require.ErrorContains(t, err, "requires cgroup v2")
	}
}

func TestRootMemoryLimitIgnoresSiblingLimits(t *testing.T) {
	for _, limit := range []string{"max", "1", "68719476736"} {
		t.Run(limit, func(t *testing.T) {
			ops, root, meminfo, cfg := memoryLimitFixture(t)
			for _, sibling := range []string{"distillfs", "system.slice"} {
				directory := filepath.Join(ops.mountpoint, sibling)
				require.NoError(t, os.MkdirAll(directory, 0755))
				writeTestFile(t, filepath.Join(directory, "memory.max"), limit)
			}
			max, err := configureRootMemoryLimit(ops, root, cfg, meminfo, writeRootMemoryMax)
			require.NoError(t, err)
			assert.Equal(t, 736*memoryMiB, max, "only total_reserve is deducted")
			for _, sibling := range []string{"distillfs", "system.slice"} {
				assertFileContents(t, filepath.Join(ops.mountpoint, sibling, "memory.max"), limit)
			}
		})
	}
}

func TestRootMemoryLimitRejectsInvalidTotalReserve(t *testing.T) {
	for _, value := range []string{"", "0", "0B", "-1B", "1.5GiB", "auto", "max", "9223372036854775808B"} {
		t.Run(value, func(t *testing.T) {
			ops, root, meminfo, cfg := memoryLimitFixture(t)
			cfg.TotalReserve = value
			_, err := configureRootMemoryLimit(ops, root, cfg, meminfo, func(string, int64) error {
				t.Fatal("invalid reserve attempted write")
				return nil
			})
			require.ErrorContains(t, err, "total_reserve")
		})
	}
}

func TestRootMemoryLimitRejectsUnsafePolicies(t *testing.T) {
	for _, test := range []struct {
		name   string
		modify func(*testing.T, *cgroupV2, *string, string, *config.MemoryLimitConfig)
		want   string
	}{
		{"exhausted reserve", func(_ *testing.T, _ *cgroupV2, _ *string, _ string, c *config.MemoryLimitConfig) {
			c.TotalReserve = "1GiB"
		}, "exhaust"},
		{"reserve arithmetic overflow", func(_ *testing.T, _ *cgroupV2, _ *string, _ string, c *config.MemoryLimitConfig) {
			c.TotalReserve = "9223372036854775807B"
		}, "exhaust"},
		{"less than one page", func(_ *testing.T, _ *cgroupV2, _ *string, _ string, c *config.MemoryLimitConfig) {
			c.TotalReserve = strconv.FormatInt(1024*memoryMiB-int64(os.Getpagesize())+1, 10)
		}, "less than one page"},
		{"missing MemTotal", func(t *testing.T, _ *cgroupV2, _ *string, m string, _ *config.MemoryLimitConfig) {
			writeTestFile(t, m, "MemAvailable: 1 kB")
		}, "MemTotal"},
		{"invalid MemTotal", func(t *testing.T, _ *cgroupV2, _ *string, m string, _ *config.MemoryLimitConfig) {
			writeTestFile(t, m, "MemTotal: 4 MB")
		}, "MemTotal"},
		{"root hierarchy", func(_ *testing.T, _ *cgroupV2, r *string, _ string, _ *config.MemoryLimitConfig) {
			*r = "/"
		}, "non-root"},
		{"control overlap", func(_ *testing.T, _ *cgroupV2, r *string, _ string, _ *config.MemoryLimitConfig) {
			*r = "/system.slice/sandboxes"
		}, "overlaps"},
		{"distill overlap", func(_ *testing.T, _ *cgroupV2, r *string, _ string, _ *config.MemoryLimitConfig) {
			*r = "/distillfs"
		}, "overlaps"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ops, root, meminfo, cfg := memoryLimitFixture(t)
			test.modify(t, ops, &root, meminfo, &cfg)
			_, err := configureRootMemoryLimit(ops, root, cfg, meminfo, func(string, int64) error { t.Fatal("unsafe policy attempted write"); return nil })
			require.ErrorContains(t, err, test.want)
		})
	}
}

func TestRootMemoryLimitRequiresEmptySubtreeAndControls(t *testing.T) {
	for _, test := range []struct {
		name, file, value, want string
		missing                 bool
	}{
		{"populated descendant", "cgroup.events", "populated 1\n", "empty", false},
		{"missing populated field", "cgroup.events", "frozen 0\n", "empty", false},
		{"residual above cap", "memory.current", "771751937", "residual", false},
		{"negative current", "memory.current", "-1", "residual", false},
		{"missing root max", "memory.max", "", "memory.max", true},
		{"missing current", "memory.current", "", "memory.current", true},
		{"missing events", "cgroup.events", "", "cgroup.events", true},
		{"missing ancestor", "../memory.max", "", "memory.max", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ops, root, meminfo, cfg := memoryLimitFixture(t)
			filename := filepath.Join(ops.mountpoint, root, test.file)
			if test.missing {
				require.NoError(t, os.Remove(filename))
			} else {
				writeTestFile(t, filename, test.value)
			}
			_, err := configureRootMemoryLimit(ops, root, cfg, meminfo, func(string, int64) error { t.Fatal("unsafe state attempted write"); return nil })
			require.ErrorContains(t, err, test.want)
		})
	}
	// Empty descendants can retain page cache that fits under the new ceiling.
	ops, root, meminfo, cfg := memoryLimitFixture(t)
	writeTestFile(t, filepath.Join(ops.mountpoint, root, "memory.current"), "771751936")
	_, err := configureRootMemoryLimit(ops, root, cfg, meminfo, writeRootMemoryMax)
	require.NoError(t, err)
}

func TestRootMemoryMaxRecheckAndReadback(t *testing.T) {
	ops, root, meminfo, cfg := memoryLimitFixture(t)
	group := filepath.Join(ops.mountpoint, root)
	_, err := configureRootMemoryLimit(ops, root, cfg, meminfo, func(group string, candidate int64) error {
		writeTestFile(t, filepath.Join(group, "cgroup.events"), "populated 1\n")
		return writeRootMemoryMax(group, candidate)
	})
	require.ErrorContains(t, err, "empty")
	assertFileContents(t, filepath.Join(group, "memory.max"), "max\n")
	writeTestFile(t, filepath.Join(group, "cgroup.events"), "populated 0\n")
	writeTestFile(t, filepath.Join(group, "memory.max"), "123456789012345678\n")
	// Regular files retain their suffix with O_WRONLY; this models a kernel
	// returning a cap different from the requested value.
	require.ErrorContains(t, writeRootMemoryMax(group, 637534208), "readback")
	require.NoError(t, os.Remove(filepath.Join(group, "memory.max")))
	require.Error(t, writeRootMemoryMax(group, 637534208))
	_, err = os.Stat(filepath.Join(group, "memory.max"))
	require.True(t, os.IsNotExist(err), "writer must not recreate a missing control")
}

func TestParseMemoryBytes(t *testing.T) {
	for value, want := range map[string]int64{"0": 0, "001B": 1, "4096": 4096, " 2KiB ": 2048, "3MiB": 3 << 20, "4GiB": 4 << 30, "5TiB": 5 << 40} {
		got, err := parseMemoryBytes(value)
		require.NoError(t, err, value)
		assert.Equal(t, want, got, value)
	}
	for _, value := range []string{"", "-1B", "+1B", "1.5GiB", "1GB", "1 GiB", "1e3", "10%", "max", "9223372036854775808", "8388608TiB"} {
		_, err := parseMemoryBytes(value)
		require.Error(t, err, value)
	}
}
