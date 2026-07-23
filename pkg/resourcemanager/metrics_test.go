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
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/embedded"

	"github.com/akernel-dev/sandboxd/pkg/sandbox"
)

func TestSandboxStatsReaderConcurrentReplacement(t *testing.T) {
	c := &Collector{sandboxStats: func(string) (sandboxStats, error) { return sandboxStats{}, nil }}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			c.setSandboxStatsReader(func(string) (sandboxStats, error) { return sandboxStats{}, nil })
		}()
		go func() {
			defer wg.Done()
			if _, err := c.readSandboxStats("/sandbox/test"); err != nil {
				t.Errorf("readSandboxStats: %v", err)
			}
		}()
	}
	wg.Wait()
}

func TestDiskStatfs(t *testing.T) {
	var stat syscall.Statfs_t
	err := syscall.Statfs("/tmp", &stat)
	require.NoError(t, err)

	total := int64(stat.Blocks) * int64(stat.Bsize)
	used := int64(stat.Blocks-stat.Bfree) * int64(stat.Bsize)
	assert.Greater(t, total, int64(0), "total disk should be > 0")
	assert.GreaterOrEqual(t, used, int64(0), "used disk should be >= 0")
	assert.LessOrEqual(t, used, total, "used should not exceed total")
}

func TestCPUUtilCalculation(t *testing.T) {
	c := &Collector{}

	// First sample — no previous data, should not produce a value.
	c.prevCPUUsage = 0
	c.prevTime = time.Time{}
	assert.Equal(t, int64(0), c.prevCPUUsage)

	// Simulate two readings 1 second apart with 500ms of CPU time.
	t0 := time.Now()
	c.prevCPUUsage = 1_000_000_000 // 1s in nanoseconds
	c.prevTime = t0

	t1 := t0.Add(1 * time.Second)
	newUsage := int64(1_500_000_000) // 1.5s

	elapsed := t1.Sub(c.prevTime).Nanoseconds()
	util := float64(newUsage-c.prevCPUUsage) / float64(elapsed)

	assert.InDelta(t, 0.5, util, 0.001, "expected ~0.5 cores utilization")
}

// fakeCapacity is a stub CapacityProvider returning fixed available values.
type fakeCapacity struct {
	cpuMilli int64
	memBytes int64
}

func (f fakeCapacity) Capacity() (int64, int64) { return f.cpuMilli, f.memBytes }

// recordObserver captures the values passed to Observe for assertions.
type recordObserver struct {
	embedded.Float64Observer
	values []float64
}

func (r *recordObserver) Observe(v float64, _ ...metric.ObserveOption) {
	r.values = append(r.values, v)
}

func TestCPULimitCallback(t *testing.T) {
	t.Run("reports node available CPU in cores", func(t *testing.T) {
		c := &Collector{capacity: fakeCapacity{cpuMilli: 64000}}
		obs := &recordObserver{}
		require.NoError(t, c.cpuLimitCallback(context.Background(), obs))
		require.Len(t, obs.values, 1)
		assert.InDelta(t, 64.0, obs.values[0], 0.001, "64000 millicores -> 64 cores")
	})

	t.Run("no provider observes nothing", func(t *testing.T) {
		c := &Collector{}
		obs := &recordObserver{}
		require.NoError(t, c.cpuLimitCallback(context.Background(), obs))
		assert.Empty(t, obs.values, "nil provider should not observe a value")
	})

	t.Run("zero available observes nothing", func(t *testing.T) {
		c := &Collector{capacity: fakeCapacity{cpuMilli: 0}}
		obs := &recordObserver{}
		require.NoError(t, c.cpuLimitCallback(context.Background(), obs))
		assert.Empty(t, obs.values, "zero (no refresh yet) should not observe 0")
	})
}

type fakeSandboxMetricsSource struct {
	targets []sandbox.MetricsTarget
}

func (f *fakeSandboxMetricsSource) SandboxMetricsTargets() []sandbox.MetricsTarget {
	return f.targets
}

func TestCollectSandboxObservations(t *testing.T) {
	source := &fakeSandboxMetricsSource{targets: []sandbox.MetricsTarget{{
		SandboxID:    "sbox-1",
		RuntimeClass: "runsc-class",
		CgroupPath:   "/akernel/sbox-1",
		CPULimit:     0.5,
		MetricLabels: map[string]string{"tenantid": "tenant-a"},
	}}}
	cpuUsage := uint64(1_000_000_000)
	c := &Collector{
		sandboxSource:  source,
		prevSandboxCPU: make(map[string]sandboxCPUSample),
		sandboxStopped: make(map[string]sandboxTombstone),
		sandboxStats: func(path string) (sandboxStats, error) {
			require.Equal(t, "/akernel/sbox-1", path)
			return sandboxStats{
				CPUUsageNS:     cpuUsage,
				MemoryUsage:    512 * 1024 * 1024,
				MemoryLimit:    1024 * 1024 * 1024,
				HasCPUUsage:    true,
				HasMemoryUsage: true,
			}, nil
		},
	}

	t0 := time.Unix(100, 0)
	first := c.collectSandboxObservations(t0)
	require.Len(t, first, 1)
	assert.Equal(t, int64(1), first[0].running)
	assert.False(t, first[0].hasCPUUsage, "first sample only establishes a baseline")
	assert.True(t, first[0].hasCPULimit)
	assert.Equal(t, 0.5, first[0].cpuLimit)
	assert.True(t, first[0].hasCPU)
	assert.True(t, first[0].hasMemory)
	assert.Equal(t, int64(1_000_000_000), first[0].cpuTotal)
	assert.Equal(t, int64(512*1024*1024), first[0].memoryUsage)
	assert.Equal(t, int64(1024*1024*1024), first[0].memoryLimit)

	cpuUsage = 2_000_000_000
	second := c.collectSandboxObservations(t0.Add(2 * time.Second))
	require.Len(t, second, 1)
	assert.True(t, second[0].hasCPUUsage)
	assert.InDelta(t, 0.5, second[0].cpuUsage, 0.001)

	current := t0.Add(4 * time.Second)
	c.now = func() time.Time { return current }
	c.MarkSandboxStopped(source.targets[0])
	source.targets = nil
	stopped := c.collectSandboxObservations(current)
	if assert.Len(t, stopped, 1) {
		assert.Equal(t, int64(0), stopped[0].running)
		assert.False(t, stopped[0].hasCPU)
		assert.False(t, stopped[0].hasMemory)
	}
	assert.Empty(t, c.prevSandboxCPU, "deleted sandboxes must not retain CPU baseline state")

	current = current.Add(sandboxTombstoneRetention)
	assert.Empty(t, c.collectSandboxObservations(current), "expired tombstones must be discarded")
}

func TestSandboxStoppedTombstoneCopiesLabelsAndWinsSnapshotRace(t *testing.T) {
	target := sandbox.MetricsTarget{
		SandboxID:    "sbox-stopped",
		RuntimeClass: "runsc",
		CgroupPath:   "/akernel/sbox-stopped",
		MetricLabels: map[string]string{"tenantid": "tenant-a"},
	}
	source := &fakeSandboxMetricsSource{targets: []sandbox.MetricsTarget{target}}
	now := time.Unix(200, 0)
	c := &Collector{
		sandboxSource:  source,
		prevSandboxCPU: make(map[string]sandboxCPUSample),
		sandboxStopped: make(map[string]sandboxTombstone),
		sandboxStats: func(string) (sandboxStats, error) {
			return sandboxStats{HasMemoryUsage: true}, nil
		},
		now: func() time.Time { return now },
	}

	c.MarkSandboxStopped(target)
	target.MetricLabels["tenantid"] = "mutated"

	observations := c.collectSandboxObservations(now)
	if assert.Len(t, observations, 1) {
		assert.Equal(t, int64(0), observations[0].running)
		assert.Equal(t, "tenant-a", observations[0].target.MetricLabels["tenantid"])
	}
}

func TestRunningObservationSurvivesCgroupReadFailure(t *testing.T) {
	source := &fakeSandboxMetricsSource{targets: []sandbox.MetricsTarget{{
		SandboxID:    "sbox-running",
		RuntimeClass: "runsc",
		CgroupPath:   "/akernel/sbox-running",
	}}}
	c := &Collector{
		sandboxSource:  source,
		prevSandboxCPU: make(map[string]sandboxCPUSample),
		sandboxStopped: make(map[string]sandboxTombstone),
		sandboxStats: func(string) (sandboxStats, error) {
			return sandboxStats{}, assert.AnError
		},
	}

	observations := c.collectSandboxObservations(time.Unix(300, 0))
	if assert.Len(t, observations, 1) {
		assert.Equal(t, int64(1), observations[0].running)
		assert.False(t, observations[0].hasCPU)
		assert.False(t, observations[0].hasMemory)
	}
}

func TestSandboxAttributes(t *testing.T) {
	attributes := sandboxAttributes(sandbox.MetricsTarget{
		SandboxID:    "sbox-real",
		RuntimeClass: "runsc-class",
		MetricLabels: map[string]string{
			"tenantid":      "tenant-a",
			"sandbox_id":    "upstream-id",
			"runtime_class": "upstream-runtime",
			"host_name":     "upstream-host",
			"invalid.key":   "ignored",
		},
	})

	got := make(map[string]string, len(attributes))
	for _, item := range attributes {
		require.Equal(t, attribute.STRING, item.Value.Type())
		got[string(item.Key)] = item.Value.AsString()
	}
	assert.Equal(t, map[string]string{
		"tenantid":      "tenant-a",
		"sandbox_id":    "sbox-real",
		"runtime_class": "runsc-class",
	}, got)
}
