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
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apiresource "k8s.io/apimachinery/pkg/api/resource"
)

func TestReadOnlineResConfigValid(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "online_resource.json")
	err := os.WriteFile(configPath, []byte(`{
  "online_cgroups": ["kubepods"],
  "offline_cgroups": ["system.slice"],
  "cpu_free_over_sold_ratio": 20,
  "cpu_max_ratio": 95,
  "memory_over_sold_ratio": 10,
  "memory_free_over_sold_ratio": 15,
  "memory_reserve_ratio": 5
}`), 0o644)
	assert.NoError(t, err)

	cfg, err := readOnlineResConfig(configPath)
	assert.NoError(t, err)
	assert.Equal(t, []string{"kubepods"}, cfg.OnlineCgroups)
	assert.Equal(t, []string{"system.slice"}, cfg.OfflineCgroups)
	assert.Equal(t, 20, cfg.CpuFreeOverSoldRatio)
	assert.Equal(t, 95, cfg.CPUMaxRatio)
	assert.Equal(t, 10, cfg.MemoryOverSoldRatio)
	assert.Equal(t, 15, cfg.MemoryFreeOverSoldRatio)
	assert.Equal(t, 5, cfg.MemoryReserveRatio)
}

func TestReadOnlineResConfigInvalidRatio(t *testing.T) {
	tests := []struct {
		name       string
		payload    string
		errContain string
	}{
		{
			name: "cpu max ratio out of range",
			payload: `{
  "cpu_max_ratio": 101,
  "cpu_free_over_sold_ratio": 10,
  "memory_over_sold_ratio": 10,
  "memory_free_over_sold_ratio": 10,
  "memory_reserve_ratio": 10
}`,
			errContain: "cpu_max_ratio must be between 0 and 100",
		},
		{
			name: "cpu free oversold out of range",
			payload: `{
  "cpu_max_ratio": 90,
  "cpu_free_over_sold_ratio": -1,
  "memory_over_sold_ratio": 10,
  "memory_free_over_sold_ratio": 10,
  "memory_reserve_ratio": 10
}`,
			errContain: "cpu_free_over_sold_ratio must be between 0 and 100",
		},
		{
			name: "memory reserve ratio out of range",
			payload: `{
  "cpu_max_ratio": 90,
  "cpu_free_over_sold_ratio": 10,
  "memory_over_sold_ratio": 10,
  "memory_free_over_sold_ratio": 10,
  "memory_reserve_ratio": 101
}`,
			errContain: "memory_reserve_ratio must be between 0 and 100",
		},
		{
			name: "memory oversold out of range",
			payload: `{
  "cpu_max_ratio": 90,
  "cpu_free_over_sold_ratio": 10,
  "memory_over_sold_ratio": -1,
  "memory_free_over_sold_ratio": 10,
  "memory_reserve_ratio": 10
}`,
			errContain: "memory_over_sold_ratio must be between 0 and 100",
		},
		{
			name: "memory free oversold out of range",
			payload: `{
  "cpu_max_ratio": 90,
  "cpu_free_over_sold_ratio": 10,
  "memory_over_sold_ratio": 10,
  "memory_free_over_sold_ratio": 101,
  "memory_reserve_ratio": 10
}`,
			errContain: "memory_free_over_sold_ratio must be between 0 and 100",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "online_resource.json")
			err := os.WriteFile(configPath, []byte(tc.payload), 0o644)
			assert.NoError(t, err)

			_, err = readOnlineResConfig(configPath)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.errContain)
		})
	}
}

func TestReadOnlineResConfigErrors(t *testing.T) {
	_, err := readOnlineResConfig(filepath.Join(t.TempDir(), "not-exist.json"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open config file")

	badPath := filepath.Join(t.TempDir(), "bad.json")
	err = os.WriteFile(badPath, []byte("{"), 0o644)
	assert.NoError(t, err)

	_, err = readOnlineResConfig(badPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse JSON")
}

func TestSmoothValue(t *testing.T) {
	mgr := &onlineResourceManager{startupTime: time.Now()}

	startVal := mgr.smoothValue(100, 200)
	assert.InDelta(t, 110.0, startVal, 0.0001)

	mgr.startupTime = time.Now().Add(-90 * time.Second)
	midVal := mgr.smoothValue(100, 200)
	assert.InDelta(t, 105.5, midVal, 0.0001)

	mgr.startupTime = time.Now().Add(-4 * time.Minute)
	lateVal := mgr.smoothValue(100, 200)
	assert.InDelta(t, 101.0, lateVal, 0.0001)
}

func TestOnlineProviderRefreshesAndHonorsCloudCeiling(t *testing.T) {
	prod := corev1.ResourceList{
		corev1.ResourceCPU:    apiresource.MustParse("1250m"),
		corev1.ResourceMemory: apiresource.MustParse("8Gi"),
	}
	alloc := map[string]ResourceMap{
		"Prod": {ResourceList: prod},
		"ProdFree": {ResourceList: corev1.ResourceList{
			corev1.ResourceCPU:    apiresource.MustParse("250m"),
			corev1.ResourceMemory: apiresource.MustParse("2Gi"),
		}},
	}
	client := &stubNodeResourceClient{resp: &NodeResource{
		Status: NodeResourceStatus{NodeAllocatable: &NodeAllocatableResource{AllocatableResource: alloc}},
	}}
	policy := &recordOnlineCeiling{}
	mgr := &nodeResourceManager{nodeClt: client, onlineMgr: policy}
	for range 2 {
		cpu, mem, err := mgr.GetAvailableResource()
		require.NoError(t, err)
		require.Equal(t, int64(1500), cpu)
		require.Equal(t, int64(10<<30), mem)
	}
	delete(alloc, "ProdFree")
	prod[corev1.ResourceCPU] = apiresource.MustParse("0")
	prod[corev1.ResourceMemory] = apiresource.MustParse("0")
	cpu, mem, err := mgr.GetAvailableResource()
	require.NoError(t, err)
	require.Zero(t, cpu)
	require.Zero(t, mem)
	delete(prod, corev1.ResourceMemory)
	_, _, err = mgr.GetAvailableResource()
	require.ErrorContains(t, err, "requires explicit cpu and memory")
	client.err = assert.AnError
	_, _, err = mgr.GetAvailableResource()
	require.ErrorIs(t, err, assert.AnError)
	require.Equal(t, 3, policy.calls, "invalid or unobserved capacity cannot fall back to host limits")
}

func TestOnlineCapacityRequiresMeasuredCPU(t *testing.T) {
	root := t.TempDir()
	write := func(name, contents string) {
		t.Helper()
		file := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(file), 0755))
		require.NoError(t, os.WriteFile(file, []byte(contents), 0644))
	}
	host := filepath.Join(root, "host")
	faas := filepath.Join(root, "faas")
	write("faas/cpu.cfs_quota_us", "-1")
	write("faas/cpu.cfs_period_us", "100000")
	write("faas/cpu.shares", "1024")
	write("faas/cpuset.cpus", "0-7")
	write("faas/memory.stat", "total_active_anon 0\n")
	write("zoneinfo", "managed "+strconv.FormatInt((64<<30)/int64(os.Getpagesize()), 10)+"\n")
	mgr := &onlineResourceManager{
		cfg: CgroupConfig{
			HostCpuacctCgroupPath: host,
			FaasCpuaactCgroupPath: faas,
			FaasCpuCgroupPath:     faas,
			FaasCpusetCgroupPath:  faas,
			FaasMemCgroupPath:     faas,
			ZoneinfoPath:          filepath.Join(root, "zoneinfo"),
		},
		resCfg: OnlineResourceConfig{
			OfflineCgroups:          []string{"offline"},
			CpuFreeOverSoldRatio:    100,
			MemoryFreeOverSoldRatio: 100,
		},
		startupTime: time.Now(),
	}
	for _, sample := range []struct {
		name                string
		host, offline, faas int64
		hasHeadroom         bool
	}{
		{name: "initial zero counter is only a baseline"},
		{name: "busy interval from zero counts as measured", host: 32e9},
		{name: "idle sample makes headroom available", host: 32e9, hasHeadroom: true},
		{name: "host reset withdraws headroom", host: 1e9},
		{name: "valid interval after reset", host: 1e9, hasHeadroom: true},
		{name: "offline and faas accrue", host: 3e9, offline: 1e9, faas: 1e9, hasHeadroom: true},
		{name: "offline reset invalidates interval", host: 3e9, faas: 1e9},
		{name: "valid interval after offline reset", host: 3e9, faas: 1e9, hasHeadroom: true},
		{name: "faas reset invalidates interval", host: 3e9},
		{name: "valid interval after faas reset", host: 3e9, hasHeadroom: true},
	} {
		t.Run(sample.name, func(t *testing.T) {
			write("host/cpuacct.usage", strconv.FormatInt(sample.host, 10))
			write("host/offline/cpuacct.usage", strconv.FormatInt(sample.offline, 10))
			write("faas/cpuacct.usage", strconv.FormatInt(sample.faas, 10))
			if !mgr.prevUsageTime.IsZero() {
				mgr.prevUsageTime = time.Now().Add(-time.Second)
			}
			cpu, memory, err := mgr.GetAvailableResource(8000, 64<<30)
			require.NoError(t, err)
			require.Positive(t, memory, "CPU baseline must not suppress measured memory")
			if sample.hasHeadroom {
				require.Positive(t, cpu)
			} else {
				require.Zero(t, cpu)
			}
		})
	}
}

type recordOnlineCeiling struct{ calls int }

func (r *recordOnlineCeiling) GetAvailableResource(cpuMilli, memory int64) (int64, int64, error) {
	r.calls++
	return cpuMilli, memory, nil
}

func TestOnlineAccountingRejectsMissingOrZeroPodLimits(t *testing.T) {
	root := t.TempDir()
	mgr := &onlineResourceManager{
		cfg:    CgroupConfig{HostPidsCgroupPath: root, HostCpuCgroupPath: root, HostMemCgroupPath: root},
		resCfg: OnlineResourceConfig{OnlineCgroups: []string{"online"}},
	}
	_, _, err := mgr.allocated()
	require.ErrorIs(t, err, os.ErrNotExist)
	pod := filepath.Join(root, "online", "pod1")
	require.NoError(t, os.MkdirAll(pod, 0755))
	write := func(name, value string) {
		require.NoError(t, os.WriteFile(filepath.Join(pod, name), []byte(value), 0644))
	}
	write("pids.current", "1")
	write("cpu.cfs_quota_us", "100000")
	write("cpu.cfs_period_us", "100000")
	write("cpu.shares", "1024")
	write("memory.stat", "total_active_anon 512\nhierarchical_memory_limit 0\n")
	_, _, err = mgr.allocated()
	require.ErrorContains(t, err, "missing or zero hierarchical memory limit")
	write("memory.stat", "total_active_anon 512\nhierarchical_memory_limit 1024\n")
	cpu, memory, err := mgr.allocated()
	require.NoError(t, err)
	require.Equal(t, float64(1), cpu)
	require.Equal(t, float64(1024), memory)
}

func TestOnlinePodCgroupDisappearance(t *testing.T) {
	root := t.TempDir()
	cfg := &CgroupConfig{HostPidsCgroupPath: root, HostCpuCgroupPath: root, HostMemCgroupPath: root}
	pod := filepath.Join(root, "online", "pod1")
	require.NoError(t, os.MkdirAll(pod, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(pod, "pids.current"), []byte("1"), 0644))

	_, err := collectOnlinePods(cfg, "online")
	require.ErrorIs(t, err, os.ErrNotExist)
	require.False(t, podCgroupDisappeared(pod, err), "a live pod is missing its CPU controls")

	// Model deletion of the listed cgroup between enumerating and reading it.
	require.NoError(t, os.Remove(filepath.Join(pod, "pids.current")))
	require.NoError(t, os.Remove(pod))
	_, err = readOnlinePod(cfg, "online", "pod1")
	require.ErrorIs(t, err, os.ErrNotExist)
	require.True(t, podCgroupDisappeared(pod, err))
	require.False(t, podCgroupDisappeared(pod, os.ErrPermission))
}

type stubNodeResourceClient struct {
	resp *NodeResource
	err  error
}

func (s *stubNodeResourceClient) GetNodeResource() (*NodeResource, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.resp, nil
}
