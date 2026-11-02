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
	"errors"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/inclusionAI/sandboxd/pkg/cgroupmanager"
)

func newParentMemoryTestCollector(t *testing.T) (*Collector, *sdkmetric.ManualReader) {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { require.NoError(t, provider.Shutdown(context.Background())) })
	collector := &Collector{provider: provider}
	require.NoError(t, collector.registerParentMemoryMetrics(provider.Meter("parent-memory-test")))
	return collector, reader
}

func collectParentMemoryTestMetrics(reader *sdkmetric.ManualReader) (map[string]metricdata.Metrics, error) {
	var result metricdata.ResourceMetrics
	err := reader.Collect(context.Background(), &result)
	metrics := make(map[string]metricdata.Metrics)
	for _, scope := range result.ScopeMetrics {
		for _, data := range scope.Metrics {
			if strings.HasPrefix(data.Name, "sandbox.parent.memory.") {
				metrics[data.Name] = data
			}
		}
	}
	return metrics, err
}

func assertParentMemoryTestPair(t *testing.T, metrics map[string]metricdata.Metrics, stats cgroupmanager.ParentMemoryStats) {
	t.Helper()
	require.Len(t, metrics, 2)
	for name, expected := range map[string]uint64{
		"sandbox.parent.memory.current": stats.CurrentBytes,
		"sandbox.parent.memory.max":     stats.MaxBytes,
	} {
		data, ok := metrics[name]
		require.True(t, ok, "missing metric %q", name)
		assert.Equal(t, "By", data.Unit, name)
		gauge, ok := data.Data.(metricdata.Gauge[int64])
		require.True(t, ok, "%s must be an int64 gauge, got %T", name, data.Data)
		require.Len(t, gauge.DataPoints, 1, name)
		assert.Equal(t, int64(expected), gauge.DataPoints[0].Value, name)
		assert.Equal(t, []attribute.KeyValue{attribute.String("cgroup_path", stats.CgroupPath)}, gauge.DataPoints[0].Attributes.ToSlice(), name)
	}
}

func TestParentMemoryMetricsUseOneSnapshotPerCollection(t *testing.T) {
	collector, reader := newParentMemoryTestCollector(t)
	calls := 0
	collector.SetParentMemoryReader(func() (cgroupmanager.ParentMemoryStats, error) {
		calls++
		return cgroupmanager.ParentMemoryStats{
			CgroupPath:   "/custom/managed-parent",
			CurrentBytes: uint64(calls * 1024),
			MaxBytes:     uint64(calls * 4096),
		}, nil
	})
	for i := 1; i <= 2; i++ {
		metrics, err := collectParentMemoryTestMetrics(reader)
		require.NoError(t, err)
		assert.Equal(t, i, calls, "both gauges must use exactly one reader invocation")
		assertParentMemoryTestPair(t, metrics, cgroupmanager.ParentMemoryStats{
			CgroupPath: "/custom/managed-parent", CurrentBytes: uint64(i * 1024), MaxBytes: uint64(i * 4096),
		})
	}
}

func TestParentMemoryMetricsFiniteValues(t *testing.T) {
	for _, test := range []struct {
		name    string
		current uint64
		max     uint64
	}{
		{name: "zero usage", current: 0, max: 4096},
		{name: "finite zero limit", current: 0, max: 0},
		{name: "usage above lowered limit", current: 8192, max: 4096},
		{name: "int64 boundary", current: math.MaxInt64, max: math.MaxInt64},
	} {
		t.Run(test.name, func(t *testing.T) {
			collector, reader := newParentMemoryTestCollector(t)
			stats := cgroupmanager.ParentMemoryStats{CgroupPath: "/configured-parent", CurrentBytes: test.current, MaxBytes: test.max}
			collector.SetParentMemoryReader(func() (cgroupmanager.ParentMemoryStats, error) { return stats, nil })
			metrics, err := collectParentMemoryTestMetrics(reader)
			require.NoError(t, err)
			assertParentMemoryTestPair(t, metrics, stats)
		})
	}
}

func TestParentMemoryMetricsOmitInvalidSnapshot(t *testing.T) {
	for _, test := range []struct {
		name       string
		reader     func() (cgroupmanager.ParentMemoryStats, error)
		errMessage string
	}{
		{name: "reader absent", errMessage: "not configured"},
		{
			name: "read error", errMessage: "read parent memory: unavailable",
			reader: func() (cgroupmanager.ParentMemoryStats, error) {
				return cgroupmanager.ParentMemoryStats{CgroupPath: "/parent", CurrentBytes: 123, MaxBytes: 456}, errors.New("unavailable")
			},
		},
		{
			name: "unlimited", errMessage: "unlimited",
			reader: func() (cgroupmanager.ParentMemoryStats, error) {
				return cgroupmanager.ParentMemoryStats{CgroupPath: "/parent", CurrentBytes: 123, Unlimited: true}, nil
			},
		},
		{
			name: "current overflows int64", errMessage: "exceeds int64 range",
			reader: func() (cgroupmanager.ParentMemoryStats, error) {
				return cgroupmanager.ParentMemoryStats{CgroupPath: "/parent", CurrentBytes: uint64(math.MaxInt64) + 1, MaxBytes: 456}, nil
			},
		},
		{
			name: "max overflows int64", errMessage: "exceeds int64 range",
			reader: func() (cgroupmanager.ParentMemoryStats, error) {
				return cgroupmanager.ParentMemoryStats{CgroupPath: "/parent", CurrentBytes: 123, MaxBytes: math.MaxUint64}, nil
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			collector, reader := newParentMemoryTestCollector(t)
			// Schedulable node capacity must never fill in a missing parent pair.
			collector.capacity = fakeCapacity{cpuMilli: 64000, memBytes: 1 << 30}
			collector.SetParentMemoryReader(test.reader)
			_, snapshotErr := collector.parentMemorySnapshot()
			require.ErrorContains(t, snapshotErr, test.errMessage)
			metrics, err := collectParentMemoryTestMetrics(reader)
			require.NoError(t, err, "a missing parent pair must not prevent unrelated metrics from being exported")
			assert.Empty(t, metrics, "invalid snapshots must omit both gauges")
		})
	}
}

func TestParentMemoryMetricsRejectInvalidPath(t *testing.T) {
	for _, path := range []string{"", " \t", "/", "relative", "/parent/../other", "/parent//child", "/parent/"} {
		t.Run(path, func(t *testing.T) {
			collector, reader := newParentMemoryTestCollector(t)
			collector.SetParentMemoryReader(func() (cgroupmanager.ParentMemoryStats, error) {
				return cgroupmanager.ParentMemoryStats{CgroupPath: path, CurrentBytes: 123, MaxBytes: 456}, nil
			})
			_, snapshotErr := collector.parentMemorySnapshot()
			require.ErrorContains(t, snapshotErr, "invalid managed cgroup path")
			metrics, err := collectParentMemoryTestMetrics(reader)
			require.NoError(t, err)
			assert.Empty(t, metrics)
		})
	}
}

func TestParentMemoryMetricsDoNotCacheAcrossMissingCollections(t *testing.T) {
	for _, failure := range []string{"absent", "read error", "unlimited", "invalid path", "overflow"} {
		t.Run(failure, func(t *testing.T) {
			collector, reader := newParentMemoryTestCollector(t)
			first := cgroupmanager.ParentMemoryStats{CgroupPath: "/first-parent", CurrentBytes: 123, MaxBytes: 456}
			collector.SetParentMemoryReader(func() (cgroupmanager.ParentMemoryStats, error) { return first, nil })
			metrics, err := collectParentMemoryTestMetrics(reader)
			require.NoError(t, err)
			assertParentMemoryTestPair(t, metrics, first)

			if failure == "absent" {
				collector.SetParentMemoryReader(nil)
			} else {
				collector.SetParentMemoryReader(func() (cgroupmanager.ParentMemoryStats, error) {
					bad := first
					switch failure {
					case "read error":
						return bad, errors.New("temporary read failure")
					case "unlimited":
						bad.Unlimited = true
					case "invalid path":
						bad.CgroupPath = ""
					case "overflow":
						bad.MaxBytes = math.MaxUint64
					}
					return bad, nil
				})
			}
			_, snapshotErr := collector.parentMemorySnapshot()
			require.Error(t, snapshotErr)
			metrics, err = collectParentMemoryTestMetrics(reader)
			require.NoError(t, err)
			assert.Empty(t, metrics, "the previous pair must not survive a failed collection")

			fresh := cgroupmanager.ParentMemoryStats{CgroupPath: "/fresh-parent", CurrentBytes: 0, MaxBytes: 8192}
			collector.SetParentMemoryReader(func() (cgroupmanager.ParentMemoryStats, error) { return fresh, nil })
			metrics, err = collectParentMemoryTestMetrics(reader)
			require.NoError(t, err)
			assertParentMemoryTestPair(t, metrics, fresh)
		})
	}
}

func TestParentMemoryReaderMayChangeDuringCollection(t *testing.T) {
	collector, reader := newParentMemoryTestCollector(t)
	var calls atomic.Int64
	first := cgroupmanager.ParentMemoryStats{CgroupPath: "/first-parent", CurrentBytes: 123, MaxBytes: 456}
	second := cgroupmanager.ParentMemoryStats{CgroupPath: "/second-parent", CurrentBytes: 789, MaxBytes: 1024}
	firstReader := func() (cgroupmanager.ParentMemoryStats, error) { calls.Add(1); return first, nil }
	secondReader := func() (cgroupmanager.ParentMemoryStats, error) { calls.Add(1); return second, nil }
	collector.SetParentMemoryReader(firstReader)
	var setters sync.WaitGroup
	setters.Add(1)
	go func() {
		defer setters.Done()
		for range 100 {
			collector.SetParentMemoryReader(secondReader)
			collector.SetParentMemoryReader(firstReader)
		}
	}()
	defer setters.Wait()
	for range 100 {
		metrics, err := collectParentMemoryTestMetrics(reader)
		require.NoError(t, err)
		gauge, ok := metrics["sandbox.parent.memory.current"].Data.(metricdata.Gauge[int64])
		require.True(t, ok)
		require.Len(t, gauge.DataPoints, 1)
		if gauge.DataPoints[0].Value == int64(first.CurrentBytes) {
			assertParentMemoryTestPair(t, metrics, first)
		} else {
			assertParentMemoryTestPair(t, metrics, second)
		}
	}
	assert.Equal(t, int64(100), calls.Load())
}

func TestModulePropagatesParentMemoryReader(t *testing.T) {
	collector, reader := newParentMemoryTestCollector(t)
	module := &Module{collector: collector}
	stats := cgroupmanager.ParentMemoryStats{CgroupPath: "/module-parent", CurrentBytes: 123, MaxBytes: 456}
	module.SetParentMemoryReader(func() (cgroupmanager.ParentMemoryStats, error) { return stats, nil })
	metrics, err := collectParentMemoryTestMetrics(reader)
	require.NoError(t, err)
	assertParentMemoryTestPair(t, metrics, stats)

	module.SetParentMemoryReader(nil)
	metrics, err = collectParentMemoryTestMetrics(reader)
	require.NoError(t, err)
	assert.Empty(t, metrics)
	assert.NotPanics(t, func() { (&Module{}).SetParentMemoryReader(nil) })
}

// parentMemoryTestExporter exercises PeriodicReader without opening a network
// connection. Export copies only the values needed by the regression check.
type parentMemoryTestExporter struct {
	exports     int
	cpuLimit    float64
	memoryTotal int64
	names       map[string]bool
}

func (*parentMemoryTestExporter) Temporality(kind sdkmetric.InstrumentKind) metricdata.Temporality {
	return sdkmetric.DefaultTemporalitySelector(kind)
}

func (*parentMemoryTestExporter) Aggregation(kind sdkmetric.InstrumentKind) sdkmetric.Aggregation {
	return sdkmetric.DefaultAggregationSelector(kind)
}

func (e *parentMemoryTestExporter) Export(_ context.Context, metrics *metricdata.ResourceMetrics) error {
	e.exports++
	e.names = make(map[string]bool)
	for _, scope := range metrics.ScopeMetrics {
		for _, data := range scope.Metrics {
			e.names[data.Name] = true
			switch data.Name {
			case "node.cpu.limit":
				e.cpuLimit = data.Data.(metricdata.Gauge[float64]).DataPoints[0].Value
			case "node.memory.total":
				e.memoryTotal = data.Data.(metricdata.Gauge[int64]).DataPoints[0].Value
			}
		}
	}
	return nil
}

func (*parentMemoryTestExporter) ForceFlush(context.Context) error { return nil }
func (*parentMemoryTestExporter) Shutdown(context.Context) error   { return nil }

func TestParentMemoryFailurePreservesExistingMetricExport(t *testing.T) {
	for _, failure := range []string{"absent", "read error", "unlimited"} {
		t.Run(failure, func(t *testing.T) {
			exporter := &parentMemoryTestExporter{}
			reader := sdkmetric.NewPeriodicReader(exporter, sdkmetric.WithInterval(time.Hour))
			provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
			t.Cleanup(func() { require.NoError(t, provider.Shutdown(context.Background())) })
			collector := &Collector{capacity: fakeCapacity{cpuMilli: 1234, memBytes: 5678}}
			collector.SetCgroupStatsReader(func(string) (cgroupmanager.Stats, error) {
				return cgroupmanager.Stats{CPUUsageNanos: 1000, MemoryUsageBytes: 999}, nil
			})
			if failure != "absent" {
				collector.SetParentMemoryReader(func() (cgroupmanager.ParentMemoryStats, error) {
					if failure == "read error" {
						return cgroupmanager.ParentMemoryStats{}, errors.New("parent memory unavailable")
					}
					return cgroupmanager.ParentMemoryStats{CgroupPath: "/parent", CurrentBytes: 123, Unlimited: true}, nil
				})
			}
			require.NoError(t, collector.registerMetrics(provider.Meter("parent-memory-export-test")))
			require.NoError(t, provider.ForceFlush(context.Background()))
			assert.Equal(t, 1, exporter.exports)
			assert.True(t, exporter.names["node.cpu.limit"])
			assert.True(t, exporter.names["node.memory.total"])
			assert.True(t, exporter.names["node.memory.usage"])
			assert.InDelta(t, 1.234, exporter.cpuLimit, 0.000001)
			assert.Equal(t, int64(5678), exporter.memoryTotal)
			assert.False(t, exporter.names["sandbox.parent.memory.current"])
			assert.False(t, exporter.names["sandbox.parent.memory.max"])
		})
	}
}
