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
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/containerd/cgroups/v3"
	"github.com/stretchr/testify/require"
)

func memoryLimitFixture(t *testing.T, mode cgroups.CGMode, max int64) (*Module, string) {
	t.Helper()
	root := t.TempDir()
	service, managed := filepath.Join(root, "service"), filepath.Join(root, "lite", "akernel")
	if mode == cgroups.Unified {
		writeV2Group(t, root, "max 100000\n", "max\n")
		writeV2Group(t, service, "250000 100000\n", strconvInt(2*gib))
		writeV2Group(t, filepath.Dir(managed), "max 100000\n", "max\n")
		writeV2Group(t, managed, "100000 100000\n", strconvInt(max))
		writeFixture(t, filepath.Join(service, "cpuset.cpus.effective"), "0-3\n")
	} else {
		for _, group := range []string{root, filepath.Dir(managed), managed, service} {
			writeFixture(t, filepath.Join(group, "cpu.cfs_quota_us"), "250000\n")
			writeFixture(t, filepath.Join(group, "cpu.cfs_period_us"), "100000\n")
			writeFixture(t, filepath.Join(group, "memory.limit_in_bytes"), strconvInt(max))
		}
		writeFixture(t, filepath.Join(service, "memory.limit_in_bytes"), strconvInt(2*gib))
		writeFixture(t, filepath.Join(service, "cpuset.cpus"), "0-3\n")
	}
	writeFixture(t, filepath.Join(root, "cpu-online"), "0-7\n")
	writeFixture(t, filepath.Join(root, "meminfo"), "MemTotal: 8388608 kB\n")
	provider := &cgroupResourceManager{mode: mode,
		cpu: cgroupHierarchy{root, service}, memory: cgroupHierarchy{root, service},
		cpuset: cgroupHierarchy{root, service}, meminfo: filepath.Join(root, "meminfo"),
		cpuOnline: filepath.Join(root, "cpu-online")}
	return &Module{nodeResource: provider, sockPath: filepath.Join(t.TempDir(), "resource.sock"),
		stopCh: make(chan struct{})}, managed
}

func TestMemoryLimitCgroupCapacityAndRestart(t *testing.T) {
	const max = 5*gib + 333
	for _, mode := range []cgroups.CGMode{cgroups.Legacy, cgroups.Unified} {
		t.Run(cgroupModeName(mode), func(t *testing.T) {
			m, managed := memoryLimitFixture(t, mode, max)
			originalProvider := *m.nodeResource.(*cgroupResourceManager)
			cpuBefore, memBefore, err := m.nodeResource.GetAvailableResource()
			require.NoError(t, err)
			require.Equal(t, 2*gib, memBefore, "unset policy uses the service memory group")
			for _, root := range []string{"/", "relative", "/lite/../akernel", "/missing"} {
				require.Error(t, m.SetMemoryLimit(root, max))
			}
			require.NoError(t, m.SetMemoryLimit("/lite/akernel", max))
			cpuAfter, mem, err := m.nodeResource.GetAvailableResource()
			require.NoError(t, err)
			require.Equal(t, cpuBefore, cpuAfter, "CPU must still use the service group")
			require.Equal(t, max, mem, "provider bytes must not round to GiB")
			m.refreshOnce()
			_, mem = m.Capacity()
			require.Equal(t, max, mem, "the parent cap is reported without a second reserve or headroom deduction")
			release, ok := m.ReserveTransientMemory("checkpoint", 777)
			require.True(t, ok)
			m.refreshOnce()
			_, mem = m.Capacity()
			require.Equal(t, max-777, mem)
			_, ok = m.ReserveTransientMemory("overflow", mem+1)
			require.False(t, ok)
			releaseRest, ok := m.ReserveTransientMemory("remaining", mem)
			require.True(t, ok)
			m.refreshOnce()
			_, mem = m.Capacity()
			require.Zero(t, mem, "an exact reservation remains deducted across refresh")
			releaseRest()
			release()
			release()
			_, mem = m.Capacity()
			require.Equal(t, max, mem)
			filename := "memory.max"
			if mode == cgroups.Legacy {
				filename = "memory.limit_in_bytes"
			}
			writeFixture(t, filepath.Join(managed, filename), strconvInt(3*gib+55))
			m.refreshOnce()
			_, mem = m.Capacity()
			require.Equal(t, 3*gib+55, mem, "lower provider capacity stays authoritative")
			m.Stop()
			restarted := &Module{nodeResource: &originalProvider}
			require.NoError(t, restarted.SetMemoryLimit("/lite/akernel", max))
			restarted.refreshOnce()
			_, mem = restarted.Capacity()
			require.Equal(t, 3*gib+55, mem, "restart reads the existing managed-root limit")
		})
	}
}

func TestMemoryLimitSocketAndMetrics(t *testing.T) {
	const max = 5*gib + 333
	m, _ := memoryLimitFixture(t, cgroups.Unified, max)
	require.NoError(t, m.SetMemoryLimit("/lite/akernel", max))
	require.NoError(t, m.Start())
	t.Cleanup(m.Stop)
	require.Eventually(t, m.Healthy, time.Second, time.Millisecond)
	_, initialMemory := m.Capacity()
	require.Equal(t, max, initialMemory, "the socket starts with the full parent memory ceiling")
	require.Error(t, m.SetMemoryLimit("/lite/akernel", max))
	require.Error(t, m.Start())
	release, ok := m.ReserveTransientMemory("checkpoint", 777)
	require.True(t, ok)
	t.Cleanup(release)
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", m.sockPath)
	}}
	t.Cleanup(transport.CloseIdleConnections)
	response, err := (&http.Client{Transport: transport, Timeout: time.Second}).Get("http://sandboxd/resource")
	require.NoError(t, err)
	defer response.Body.Close()
	var info resourceInfo
	require.NoError(t, json.NewDecoder(response.Body).Decode(&info))
	cpu, mem := m.Capacity()
	require.Equal(t, info.Cpu*1000, cpu)
	require.Equal(t, max-777, info.Mem)
	require.Equal(t, info.Mem, mem)
	observation := &recordIntObserver{}
	require.NoError(t, (&Collector{capacity: m}).memTotalCallback(context.Background(), observation))
	require.Equal(t, []int64{info.Mem}, observation.values)
}

func TestMemoryLimitValidationAndProviderStaleness(t *testing.T) {
	provider := &memoryLimitNodeResourceManager{cpu: 4500, mem: 8*gib + 111}
	m := &Module{nodeResource: provider}
	for _, max := range []int64{0, -1} {
		require.Error(t, m.SetMemoryLimit("/akernel", max))
	}
	m.refreshOnce()
	_, mem := m.Capacity()
	require.Equal(t, 8*gib+111, mem, "unset policy keeps provider capacity")
	require.NoError(t, m.SetMemoryLimit("/akernel", 1))
	m.refreshOnce()
	_, mem = m.Capacity()
	require.Equal(t, int64(1), mem, "a positive byte-sized cap must not be rounded away")
	require.NoError(t, m.SetMemoryLimit("/akernel", 5*gib+333))
	m.refreshOnce()
	_, mem = m.Capacity()
	require.Equal(t, 5*gib+333, mem)
	provider.fail.Store(true)
	m.refreshOnce()
	_, retained := m.Capacity()
	require.Equal(t, mem, retained)
	m.lastRefresh.Store(time.Now().Add(-31 * time.Second).UnixNano())
	m.refreshOnce()
	_, mem = m.Capacity()
	require.Equal(t, retained, mem, "provider failures preserve the existing cached-capacity policy")
	require.False(t, m.Healthy(), "stale capacity fails health without changing the cached value")
	provider.fail.Store(false)
	provider.mem = 0
	m.refreshOnce()
	_, mem = m.Capacity()
	require.Zero(t, mem, "legitimate zero capacity stays zero")
	provider.mem = 8*gib + 111
	m.refreshOnce()
	_, mem = m.Capacity()
	require.Equal(t, 5*gib+333, mem, "recovery must apply the ceiling again")
}

// The open-source module retains cached capacity on provider failures and uses
// Healthy to report stale data. The memory ceiling must preserve that policy.
type memoryLimitNodeResourceManager struct {
	cpu, mem int64
	fail     atomic.Bool
}

func (m *memoryLimitNodeResourceManager) GetAvailableResource() (int64, int64, error) {
	if m.fail.Load() {
		return 0, 0, errors.New("provider unavailable")
	}
	return m.cpu, m.mem, nil
}
func (*memoryLimitNodeResourceManager) Stop() {}

func TestMemoryLimitLifecycleConcurrency(t *testing.T) {
	m, _ := memoryLimitFixture(t, cgroups.Unified, 5*gib)
	require.NoError(t, m.SetMemoryLimit("/lite/akernel", 5*gib))
	require.NoError(t, m.Start())
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.Stop()
		}()
	}
	wg.Wait()
	require.Error(t, m.Start())
	require.Error(t, m.SetMemoryLimit("/lite/akernel", 5*gib))
	stopped := &Module{nodeResource: &stubNodeResourceManager{}, stopCh: make(chan struct{})}
	stopped.Stop()
	require.Error(t, stopped.Start())
	require.Error(t, stopped.SetMemoryLimit("/akernel", 5*gib))
}

func TestMemoryLimitKubernetesCapacityClipsWithoutDoubleDeduction(t *testing.T) {
	provider := &k8sWatchResourceManager{totalCPU: 4000, totalMem: 8*gib + 555,
		allocatedCPU: 500, allocatedMem: 2*gib + 111}
	m := &Module{nodeResource: provider}
	const max = 7*gib + 333
	require.NoError(t, m.SetMemoryLimit("/akernel", max))
	m.refreshOnce()
	_, mem := m.Capacity()
	require.Equal(t, 6*gib+444, mem, "the provider's deductions are not repeated")
	provider.allocatedMem = 0
	m.refreshOnce()
	_, mem = m.Capacity()
	require.Equal(t, max, mem)
	provider.allocatedMem = provider.totalMem - 777
	m.refreshOnce()
	_, mem = m.Capacity()
	require.Equal(t, int64(777), mem, "sub-GiB capacity remains schedulable")
}
