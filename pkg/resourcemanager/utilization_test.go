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

package resourcemanager

import (
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/moby/sys/mountinfo"
	"github.com/stretchr/testify/require"
)

func writeUtilizationFixture(t *testing.T, root, name, content string) {
	t.Helper()
	path := filepath.Join(root, name)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0644))
}

func requireUtilization(t *testing.T, want float64, got *float64) {
	t.Helper()
	require.NotNil(t, got)
	require.InDelta(t, want, *got, 0.000001)
}

func TestHostUtilizationSampling(t *testing.T) {
	proc := t.TempDir()
	writeUtilizationFixture(t, proc, "stat", "cpu 10 0 10 80 0 0 0 0 100 100\n")
	writeUtilizationFixture(t, proc, "meminfo", "MemTotal: 1000 kB\nMemAvailable: 250 kB\nMemFree: 10 kB\n")
	s := &utilizationSampler{proc: proc, now: time.Now, groups: func() []utilizationGroup { return nil }}
	first := s.Sample()
	require.Nil(t, first.CPU)
	requireUtilization(t, .75, first.Memory)
	require.Nil(t, first.PID)
	require.Nil(t, first.FD)
	require.Nil(t, first.Disk)
	writeUtilizationFixture(t, proc, "stat", "cpu 40 0 20 130 10 0 0 0 1000 1000\n")
	requireUtilization(t, .4, s.Sample().CPU) // delta total=100, idle+iowait=60
	writeUtilizationFixture(t, proc, "stat", "cpu 1 0 1 8 0 0 0 0\n")
	require.Nil(t, s.Sample().CPU) // counter reset
	require.NoError(t, os.Remove(filepath.Join(proc, "stat")))
	require.Nil(t, s.Sample().CPU)
	writeUtilizationFixture(t, proc, "stat", "cpu 50 0 20 130 10 0 0 0\n")
	require.Nil(t, s.Sample().CPU) // failed sample broke the delta baseline
	writeUtilizationFixture(t, proc, "meminfo", "MemTotal: 1000 kB\n")
	require.Nil(t, s.Sample().Memory) // do not substitute MemFree
	writeUtilizationFixture(t, proc, "meminfo", "MemTotal: 1000 kB\nMemAvailable: 1000 kB\n")
	requireUtilization(t, 0, s.Sample().Memory)
}

func TestUtilizationRatioBounds(t *testing.T) {
	for _, limit := range []float64{0, -1, math.NaN(), math.Inf(1)} {
		require.Nil(t, utilizationRatio(1, limit))
	}
	for _, usage := range []float64{-1, math.NaN(), math.Inf(1)} {
		require.Nil(t, utilizationRatio(usage, 1))
	}
	requireUtilization(t, 1, utilizationRatio(200, 100))
	requireUtilization(t, 0, utilizationRatio(0, 100))
}

func TestFDUtilization(t *testing.T) {
	proc := t.TempDir()
	writeUtilizationFixture(t, proc, "sys/fs/file-nr", "80 20 100\n")
	requireUtilization(t, .6, fdUtilization(proc))
	writeUtilizationFixture(t, proc, "self/limits", "Limit Soft Limit Hard Limit Units\nMax open files 10 100 files\n")
	for _, fd := range []string{"0", "1", "2", "3", "4", "5", "6", "7"} {
		writeUtilizationFixture(t, proc, "self/fd/"+fd, "")
	}
	requireUtilization(t, .8, fdUtilization(proc))
	writeUtilizationFixture(t, proc, "self/limits", "Max open files unlimited unlimited files\n")
	requireUtilization(t, .6, fdUtilization(proc))
	writeUtilizationFixture(t, proc, "sys/fs/file-nr", "bad data\n")
	require.Nil(t, fdUtilization(proc))
}

func TestCgroupUtilizationV1AndV2(t *testing.T) {
	for _, unified := range []bool{false, true} {
		name := "v1"
		if unified {
			name = "v2"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			memoryUsage, memoryLimit := "memory.usage_in_bytes", "memory.limit_in_bytes"
			cpuUsage := "cpuacct.usage"
			if unified {
				memoryUsage, memoryLimit, cpuUsage = "memory.current", "memory.max", "cpu.stat"
				writeUtilizationFixture(t, root, "cpu.max", "200000 100000")
				writeUtilizationFixture(t, root, cpuUsage, "usage_usec 1000000\n")
			} else {
				writeUtilizationFixture(t, root, "cpu.cfs_quota_us", "200000")
				writeUtilizationFixture(t, root, "cpu.cfs_period_us", "100000")
				writeUtilizationFixture(t, root, cpuUsage, "1000000000")
			}
			writeUtilizationFixture(t, root, memoryUsage, "80")
			writeUtilizationFixture(t, root, memoryLimit, "100")
			writeUtilizationFixture(t, root, "pids.current", "95")
			writeUtilizationFixture(t, root, "pids.max", "100")
			now := time.Unix(100, 0)
			s := &utilizationSampler{proc: t.TempDir(), now: func() time.Time { return now }, groups: func() []utilizationGroup {
				return []utilizationGroup{{kind: "cpu", path: root, accounting: root, unified: unified}, {kind: "memory", path: root, unified: unified}, {kind: "pids", path: root, unified: unified}}
			}}
			first := s.Sample()
			require.Nil(t, first.CPU)
			requireUtilization(t, .8, first.Memory)
			requireUtilization(t, .95, first.PID)
			now = now.Add(5 * time.Second)
			if unified {
				writeUtilizationFixture(t, root, cpuUsage, "usage_usec 10000000\n")
			} else {
				writeUtilizationFixture(t, root, cpuUsage, "10000000000")
			}
			requireUtilization(t, .9, s.Sample().CPU)
			writeUtilizationFixture(t, root, "pids.max", "max")
			unlimitedMemory := "9223372036854771712"
			if unified {
				unlimitedMemory = "max"
			}
			writeUtilizationFixture(t, root, memoryLimit, unlimitedMemory)
			sample := s.Sample()
			require.Nil(t, sample.PID)
			require.Nil(t, sample.Memory)
			// Changing the denominator must start a new CPU baseline.
			if unified {
				writeUtilizationFixture(t, root, "cpu.max", "100000 100000")
			} else {
				writeUtilizationFixture(t, root, "cpu.cfs_quota_us", "100000")
			}
			now = now.Add(5 * time.Second)
			require.Nil(t, s.Sample().CPU)
		})
	}
}

func TestCgroupAncestorUsageAndLimitStayPaired(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "sandbox")
	writeUtilizationFixture(t, root, "pids.current", "90")
	writeUtilizationFixture(t, root, "pids.max", "100")
	writeUtilizationFixture(t, child, "pids.current", "20")
	writeUtilizationFixture(t, child, "pids.max", "50")
	groups := utilizationGroups([]*mountinfo.Info{{Mountpoint: root, Root: "/", FSType: "cgroup2"}}, selfCgroups{unified: "/daemon"}, true, "sandbox")
	s := &utilizationSampler{proc: t.TempDir(), now: time.Now, groups: func() []utilizationGroup { return groups }}
	requireUtilization(t, .9, s.Sample().PID) // ancestor 90/100, not child 20/100
	require.NoError(t, os.Remove(filepath.Join(root, "pids.current")))
	requireUtilization(t, .4, s.Sample().PID) // valid child survives unavailable ancestor
}

func TestUtilizationCgroupDiscovery(t *testing.T) {
	mounts := []*mountinfo.Info{
		{Mountpoint: "/cg/cpu", Root: "/tenant", FSType: "cgroup", VFSOptions: "rw,cpu"},
		{Mountpoint: "/cg/cpuacct", Root: "/tenant", FSType: "cgroup", VFSOptions: "rw,cpuacct"},
		{Mountpoint: "/cg/pids", Root: "/tenant", FSType: "cgroup", VFSOptions: "rw,pids"},
	}
	self := selfCgroups{controller: map[string]string{"cpu": "/tenant/daemon", "cpuacct": "/tenant/daemon", "pids": "/tenant/daemon"}}
	groups := utilizationGroups(mounts, self, false, "sandbox")
	require.Contains(t, groups, utilizationGroup{kind: "cpu", path: "/cg/cpu/sandbox", accounting: "/cg/cpuacct/sandbox"})
	require.Contains(t, groups, utilizationGroup{kind: "pids", path: "/cg/pids/daemon"})
	require.Contains(t, groups, utilizationGroup{kind: "pids", path: "/cg/pids"})
	unique := make(map[string]bool)
	for _, group := range groups {
		key := group.kind + ":" + group.path
		require.False(t, unique[key])
		unique[key] = true
		require.NotEqual(t, "/cg", group.path)
	}
	self.controller["cpuacct"] = "/different"
	for _, group := range utilizationGroups(mounts, self, false, "") {
		require.NotEqual(t, "cpu", group.kind)
	}
	require.Empty(t, utilizationGroups(nil, self, false, "sandbox"))
}
