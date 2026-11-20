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
	"io"
	"net"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/xpumanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	ktesting "k8s.io/client-go/testing"
)

type stubNodeResourceManager struct {
	cpu     int64
	mem     int64
	stopped atomic.Bool
}

func TestModuleKubernetesWatchFailureAndRecoveryOverSocket(t *testing.T) {
	mgr, client := newWatchTestManager(t)
	_, err := mgr.initNodeSnapshot()
	require.NoError(t, err)
	_, err = mgr.initPodSnapshot()
	require.NoError(t, err)
	startTestResourceWatch(t, mgr, client, true, "10", watch.NewRaceFreeFake())
	podWatch := watch.NewRaceFreeFake()
	podResult := startTestResourceWatch(t, mgr, client, false, "20", podWatch)
	m := &Module{
		nodeResource: mgr,
		sockPath:     filepath.Join(t.TempDir(), "resource.sock"),
		stopCh:       make(chan struct{}),
	}
	require.NoError(t, m.Start())
	t.Cleanup(m.Stop)
	require.Eventually(t, m.Healthy, time.Second, time.Millisecond)
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", m.sockPath)
	}}
	t.Cleanup(transport.CloseIdleConnections)
	httpClient := &http.Client{Transport: transport, Timeout: time.Second}
	readResource := func() resourceInfo {
		t.Helper()
		resp, err := httpClient.Get("http://sandboxd/resource")
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var info resourceInfo
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&info))
		return info
	}
	info := readResource()
	assert.Equal(t, int64(3), info.Cpu)
	assert.Equal(t, int64(8<<30), info.Mem)

	podWatch.Stop()
	select {
	case err := <-podResult:
		require.Error(t, err)
	case <-time.After(time.Second):
		t.Fatal("pod watch did not disconnect")
	}
	lastFresh := m.lastRefresh.Load()
	m.refreshOnce()
	assert.Equal(t, lastFresh, m.lastRefresh.Load(), "a cache read must not renew provider freshness")
	assert.True(t, m.Healthy(), "short outages retain the existing grace period")
	info = readResource()
	assert.Equal(t, int64(8<<30), info.Mem)

	failRelist := true
	client.PrependReactor("list", "pods", func(ktesting.Action) (bool, kruntime.Object, error) {
		if failRelist {
			return true, nil, errors.New("API server unavailable")
		}
		return true, &corev1.PodList{
			ListMeta: metav1.ListMeta{ResourceVersion: "21"},
			Items:    []corev1.Pod{*newTestPod("default", "pod-b", "node-a", corev1.PodRunning, "1500m", "3Gi")},
		}, nil
	})
	_, err = mgr.initPodSnapshot()
	require.Error(t, err)
	m.lastRefresh.Store(time.Now().Add(-31 * time.Second).UnixNano())
	m.refreshOnce()
	assert.False(t, m.Healthy())
	info = readResource()
	assert.Zero(t, info.Cpu)
	assert.Zero(t, info.Mem, "publish an explicit zero in a successful HTTP response")

	failRelist = false
	version, err := mgr.initPodSnapshot()
	require.NoError(t, err)
	m.refreshOnce()
	assert.False(t, m.Healthy(), "a snapshot alone must not hide a disconnected watch")
	startTestResourceWatch(t, mgr, client, false, version, watch.NewRaceFreeFake())
	m.refreshOnce()
	assert.True(t, m.Healthy())
	info = readResource()
	assert.Equal(t, int64(2), info.Cpu)
	assert.Equal(t, int64(7<<30), info.Mem, "recovery replaces the stale pod requests with the complete new list")
}

type stubXPUProvider struct {
	resources []xpumanager.Resource
}

type stubEphemeralStorageProvider struct {
	capacity    uint64
	allocatable uint64
}

func (s stubEphemeralStorageProvider) EphemeralStorageCapacity() (uint64, uint64, error) {
	return s.capacity, s.allocatable, nil
}

func (s stubXPUProvider) Resources() []xpumanager.Resource {
	return s.resources
}

func (s *stubNodeResourceManager) GetAvailableResource() (int64, int64, error) {
	return s.cpu, s.mem, nil
}

func (s *stubNodeResourceManager) Stop() {
	s.stopped.Store(true)
}

func TestModuleCapacityReportsCachedAvailable(t *testing.T) {
	// Capacity must mirror the cached availability the refresh loop computes
	// and serves over the socket: availCpu is stored in cores and scaled back
	// to millicores, availMem passes through as bytes.
	m := &Module{availCpu: 47, availMem: 318 << 30}
	cpuMilli, memBytes := m.Capacity()
	assert.Equal(t, int64(47000), cpuMilli)
	assert.Equal(t, int64(318<<30), memBytes)
}

func TestModuleCapacityZeroBeforeFirstRefresh(t *testing.T) {
	// Before any refresh, the cache is zero; the collector treats (0, 0) as
	// "no data" and skips observing, so the metric is absent rather than 0.
	m := &Module{}
	cpuMilli, memBytes := m.Capacity()
	assert.Equal(t, int64(0), cpuMilli)
	assert.Equal(t, int64(0), memBytes)
}

func TestTransientMemoryReservationAffectsAdvertisedCapacity(t *testing.T) {
	m := &Module{availCpu: 4, availMem: 8 << 30}
	releaseFirst, ok := m.ReserveTransientMemory("checkpoint-a", 3<<30)
	assert.True(t, ok)
	_, ok = m.ReserveTransientMemory("checkpoint-b", 6<<30)
	assert.False(t, ok)
	releaseSecond, ok := m.ReserveTransientMemory("checkpoint-b", 5<<30)
	assert.True(t, ok)

	cpuMilli, memBytes := m.Capacity()
	assert.Equal(t, int64(4000), cpuMilli)
	assert.Zero(t, memBytes)

	releaseSecond()
	_, memBytes = m.Capacity()
	assert.Equal(t, int64(5<<30), memBytes)

	releaseFirst()
	releaseFirst()
	_, memBytes = m.Capacity()
	assert.Equal(t, int64(8<<30), memBytes)

	releaseThird, ok := m.ReserveTransientMemory("checkpoint-c", 2<<30)
	assert.True(t, ok)
	m.ReleaseTransientMemory("checkpoint-c")
	releaseThird()
	_, memBytes = m.Capacity()
	assert.Equal(t, int64(8<<30), memBytes)
}

func TestModuleServesAvailableResourceOverUnixSocket(t *testing.T) {
	resourceManager := &stubNodeResourceManager{cpu: 2500, mem: 5 << 30}
	sockPath := filepath.Join(t.TempDir(), "resource.sock")
	// The usage reader mirrors a live /akernel root rollup: Mem must keep the
	// provider capacity contract while the HTTP response exposes the usage in
	// the sandbox_mem_usage observation field, exercising the full
	// refresh→socket path rather than only in-process accessors.
	m := &Module{
		nodeResource:       resourceManager,
		sandboxMemoryUsage: func() (uint64, error) { return 2 << 30, nil },
		sockPath:           sockPath,
		stopCh:             make(chan struct{}),
		transientMemory:    make(map[string]int64),
		stalenessWindow:    30 * time.Second,
		xpu: stubXPUProvider{resources: []xpumanager.Resource{{
			Type:         "gpu",
			ProductModel: "l20",
			DeviceIDs:    []uint32{0, 2},
		}}},
	}
	require.NoError(t, m.Start())
	m.SetEphemeralStorageProvider(stubEphemeralStorageProvider{
		capacity:    200 << 30,
		allocatable: 150 << 30,
	})

	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sockPath)
		},
	}}
	assert.Eventually(t, func() bool {
		resp, err := client.Get("http://sandboxd/resource")
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return false
		}
		var info resourceInfo
		if err := json.Unmarshal(body, &info); err != nil {
			return false
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(body, &fields); err != nil {
			return false
		}
		if _, ok := fields["storage"]; !ok {
			return false
		}
		if _, ok := fields["ephemeral_storage"]; ok {
			return false
		}
		if _, ok := fields["sandbox_mem_usage"]; !ok {
			return false
		}
		return info.Cpu == 2 && info.Mem == 5<<30 &&
			assert.Equal(t, uint64(2<<30), *info.SandboxMemUsage) &&
			assert.Equal(t, uint64(150<<30), *info.Storage) &&
			assert.Equal(t, []string{storageQuotaFeature}, info.Features) &&
			assert.Equal(t, []xpumanager.Resource{{
				Type:         "gpu",
				ProductModel: "l20",
				DeviceIDs:    []uint32{0, 2},
			}}, info.Xpu)
	}, time.Second, 10*time.Millisecond)

	m.Stop()
	assert.True(t, resourceManager.stopped.Load())
}

// settableNodeResourceManager extends the stub with mutable returns so a test
// can simulate provider figures changing across refresh rounds.
type settableNodeResourceManager struct {
	cpu     int64
	mem     int64
	stopped atomic.Bool
}

func (s *settableNodeResourceManager) GetAvailableResource() (int64, int64, error) {
	return s.cpu, s.mem, nil
}

func (s *settableNodeResourceManager) Stop() {
	s.stopped.Store(true)
}

func TestRefreshOnceKeepsMemContractAndPublishesUsageField(t *testing.T) {
	// Mem keeps the historical capacity contract (consumers subtract instance
	// requests themselves); sandbox usage appears in
	// the separate observation field instead of being subtracted.
	m := &Module{
		nodeResource:       &settableNodeResourceManager{cpu: 32000, mem: 120 << 30},
		sandboxMemoryUsage: func() (uint64, error) { return 30 << 30, nil },
	}
	m.refreshOnce()
	_, memBytes := m.Capacity()
	assert.Equal(t, int64(120<<30), memBytes,
		"Mem must keep the capacity contract, not the subtracted figure")
	m.mu.RLock()
	usage, ready := m.sandboxMemUsage, m.sandboxMemUsageReady
	m.mu.RUnlock()
	assert.True(t, ready)
	assert.Equal(t, uint64(30<<30), usage)
}

func TestRefreshOnceTracksSandboxMemoryGrowthAndRelease(t *testing.T) {
	// The observation field must follow the reader in both directions across
	// successive refresh rounds while Mem stays untouched.
	usage := uint64(1 << 30)
	provider := &settableNodeResourceManager{cpu: 32000, mem: 120 << 30}
	m := &Module{
		nodeResource:       provider,
		sandboxMemoryUsage: func() (uint64, error) { return usage, nil },
	}

	usage += 39 << 30 // sandbox grows 1 GiB → 40 GiB
	m.refreshOnce()
	_, memBytes := m.Capacity()
	assert.Equal(t, int64(120<<30), memBytes)
	m.mu.RLock()
	got := m.sandboxMemUsage
	m.mu.RUnlock()
	assert.Equal(t, uint64(40<<30), got)

	usage -= 40 << 30 // sandbox releases everything
	m.refreshOnce()
	m.mu.RLock()
	got = m.sandboxMemUsage
	m.mu.RUnlock()
	assert.Equal(t, uint64(0), got)
}

func TestRefreshOnceKeepsUsageFieldOnSampleFailureWithinWindow(t *testing.T) {
	// After a successful sample, a transient stat failure keeps the last
	// published usage; Mem is unaffected either way because it is not
	// derived from the sample. Recovery follows the fresh figure.
	var fail bool
	usage := uint64(90 << 30)
	provider := &settableNodeResourceManager{cpu: 32000, mem: 120 << 30}
	m := &Module{
		nodeResource: provider,
		sandboxMemoryUsage: func() (uint64, error) {
			if fail {
				return 0, errors.New("cgroup stat unreadable")
			}
			return usage, nil
		},
		stalenessWindow: 30 * time.Second,
	}

	m.refreshOnce()
	m.mu.RLock()
	got := m.sandboxMemUsage
	m.mu.RUnlock()
	assert.Equal(t, uint64(90<<30), got)

	fail = true
	m.refreshOnce() // inside the window: keeps the last sample
	m.mu.RLock()
	got, ready := m.sandboxMemUsage, m.sandboxMemUsageReady
	m.mu.RUnlock()
	assert.True(t, ready)
	assert.Equal(t, uint64(90<<30), got, "transient failure dropped a fresh sample")
	assert.True(t, m.Healthy())

	fail = false
	usage = 100 << 30 // sampling recovers; observation follows the new truth
	m.refreshOnce()
	m.mu.RLock()
	got = m.sandboxMemUsage
	m.mu.RUnlock()
	assert.Equal(t, uint64(100<<30), got)
}

func TestRefreshOnceOmitsUsageFieldBeforeFirstSampleAndWhenStale(t *testing.T) {
	// With no successful sample yet — or once the last one is past the
	// staleness window — the observation field must be omitted (ready=false)
	// and health must fail, never a fabricated or frozen figure.
	var fail bool
	usage := uint64(40 << 30)
	provider := &settableNodeResourceManager{cpu: 32000, mem: 120 << 30}
	m := &Module{
		nodeResource: provider,
		sandboxMemoryUsage: func() (uint64, error) {
			if fail {
				return 0, errors.New("cgroup stat unreadable")
			}
			return usage, nil
		},
		stalenessWindow: 30 * time.Second,
	}

	fail = true
	m.refreshOnce() // no sample yet: not ready, unhealthy
	m.mu.RLock()
	ready := m.sandboxMemUsageReady
	m.mu.RUnlock()
	assert.False(t, ready, "first-sample failure published a usage figure")
	assert.False(t, m.Healthy())

	fail = false
	m.refreshOnce() // healthy sample
	assert.True(t, m.Healthy())

	fail = true
	// Age the last successful sample past the window.
	m.lastMemSampleAt.Store(time.Now().Add(-31 * time.Second).UnixNano())
	m.refreshOnce()
	m.mu.RLock()
	ready = m.sandboxMemUsageReady
	m.mu.RUnlock()
	assert.False(t, ready,
		"stale memory sample kept serving a frozen usage figure")
	assert.False(t, m.Healthy(),
		"stale memory sample must fail the health check")

	// Sampling recovers: the observation and health come back — degradation
	// is not a one-way latch.
	fail = false
	usage = 70 << 30
	m.refreshOnce()
	m.mu.RLock()
	ready, got := m.sandboxMemUsageReady, m.sandboxMemUsage
	m.mu.RUnlock()
	assert.True(t, ready, "recovered sample did not restore the observation")
	assert.Equal(t, uint64(70<<30), got)
	assert.True(t, m.Healthy(), "recovered sample did not restore health")
}

func TestRefreshOnceProviderFailureStillRunsStalenessDegrade(t *testing.T) {
	// A provider failure must not bypass the memory staleness policy: the
	// sampling branch still runs, so an aged sample drops out of the report
	// instead of surviving on old provider data.
	var failUsage bool
	usage := uint64(40 << 30)
	m := &Module{
		nodeResource: &failingNodeResourceManager{
			wrapped: &settableNodeResourceManager{cpu: 32000, mem: 120 << 30},
		},
		sandboxMemoryUsage: func() (uint64, error) {
			if failUsage {
				return 0, errors.New("cgroup stat unreadable")
			}
			return usage, nil
		},
		stalenessWindow: 30 * time.Second,
	}

	m.refreshOnce() // both provider and sampler healthy: observation ready
	m.mu.RLock()
	ready := m.sandboxMemUsageReady
	m.mu.RUnlock()
	assert.True(t, ready)

	// Provider fails AND the previously successful usage sample ages past
	// the window: the degraded (stale) observation must still drop out — the
	// provider failure may not short-circuit the memory staleness policy.
	m.nodeResource.(*failingNodeResourceManager).fail.Store(true)
	failUsage = true
	m.lastMemSampleAt.Store(time.Now().Add(-31 * time.Second).UnixNano())
	m.refreshOnce()
	m.mu.RLock()
	ready = m.sandboxMemUsageReady
	m.mu.RUnlock()
	assert.False(t, ready,
		"provider failure bypassed the staleness degrade of the usage sample")
	assert.False(t, m.Healthy())
}

// failingNodeResourceManager wraps another manager and can start failing.
type failingNodeResourceManager struct {
	wrapped *settableNodeResourceManager
	fail    atomic.Bool
}

func (f *failingNodeResourceManager) GetAvailableResource() (int64, int64, error) {
	if f.fail.Load() {
		return 0, 0, errors.New("provider unavailable")
	}
	return f.wrapped.GetAvailableResource()
}

func (f *failingNodeResourceManager) Stop() {}

func TestRefreshOnceProviderStalePublishesZeroCapacity(t *testing.T) {
	// When the provider has failed long enough that its data is past the
	// staleness window, /resource must publish zero capacity instead of the
	// frozen last-successful figure. The consumer's collector caches its own
	// previous response on errors and non-200 replies, so only an explicit
	// zero takes effect on the scheduler.
	provider := &failingNodeResourceManager{
		wrapped: &settableNodeResourceManager{cpu: 32000, mem: 120 << 30},
	}
	m := &Module{
		nodeResource:    provider,
		stalenessWindow: 30 * time.Second,
	}

	m.refreshOnce() // healthy: 120 GiB published
	cpuMilli, memBytes := m.Capacity()
	assert.Equal(t, int64(32000), cpuMilli)
	assert.Equal(t, int64(120<<30), memBytes)

	// Provider fails but the failure is still inside the window: the frozen
	// figure keeps serving (transient failures must not flap capacity).
	provider.fail.Store(true)
	m.refreshOnce()
	_, memBytes = m.Capacity()
	assert.Equal(t, int64(120<<30), memBytes)

	// Age the last provider success past the window: zero published.
	m.lastRefresh.Store(time.Now().Add(-31 * time.Second).UnixNano())
	m.refreshOnce()
	cpuMilli, memBytes = m.Capacity()
	assert.Zero(t, cpuMilli, "stale provider data kept serving old cpu capacity")
	assert.Zero(t, memBytes, "stale provider data kept serving old mem capacity")
	assert.False(t, m.Healthy())

	// Recovery republishes the real capacity — degradation is not a latch.
	provider.fail.Store(false)
	m.refreshOnce()
	_, memBytes = m.Capacity()
	assert.Equal(t, int64(120<<30), memBytes,
		"provider recovery did not republish real capacity")
	assert.True(t, m.Healthy())
}
