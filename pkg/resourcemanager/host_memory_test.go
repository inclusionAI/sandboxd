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
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/inclusionAI/sandboxd/pkg/cgroupmanager"
)

func TestParseHostMemory(t *testing.T) {
	for _, tt := range []struct {
		name, input string
		want        hostMemoryStats
		invalid     bool
	}{
		{"normal", "MemTotal: 8192 kB\nMemFree: 1024 kB\nCached: 2048 kB\nMemAvailable: 3072 kB\n", hostMemoryStats{8192 * 1024, 3072 * 1024}, false},
		{"zero available", "MemTotal: 8192 kB\nMemAvailable: 0 kB\n", hostMemoryStats{8192 * 1024, 0}, false},
		{"fully available", "MemAvailable: 8192 kB\nMemTotal: 8192 kB", hostMemoryStats{8192 * 1024, 8192 * 1024}, false},
		{"missing available", "MemTotal: 8192 kB\nMemFree: 1024 kB\n", hostMemoryStats{}, true},
		{"missing total", "MemAvailable: 1 kB\n", hostMemoryStats{}, true},
		{"zero total", "MemTotal: 0 kB\nMemAvailable: 0 kB\n", hostMemoryStats{}, true},
		{"available exceeds total", "MemTotal: 8 kB\nMemAvailable: 9 kB\n", hostMemoryStats{}, true},
		{"negative", "MemTotal: 8 kB\nMemAvailable: -1 kB\n", hostMemoryStats{}, true},
		{"overflow bytes", "MemTotal: 9007199254740992 kB\nMemAvailable: 0 kB\n", hostMemoryStats{}, true},
		{"overflow integer", "MemTotal: 999999999999999999999 kB\nMemAvailable: 0 kB\n", hostMemoryStats{}, true},
		{"bad number", "MemTotal: unknown kB\nMemAvailable: 0 kB\n", hostMemoryStats{}, true},
		{"wrong unit", "MemTotal: 8 MB\nMemAvailable: 0 kB\n", hostMemoryStats{}, true},
		{"missing unit", "MemTotal: 8\nMemAvailable: 0 kB\n", hostMemoryStats{}, true},
		{"duplicate", "MemTotal: 8 kB\nMemTotal: 8 kB\nMemAvailable: 0 kB\n", hostMemoryStats{}, true},
		{"empty", "", hostMemoryStats{}, true},
		{"truncated read", "MemTotal: 8 kB\nMemAvailable: 0 kB\n" + strings.Repeat("x", 128*1024), hostMemoryStats{}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseHostMemory(strings.NewReader(tt.input))
			if tt.invalid {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestHostMemoryMetrics(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { require.NoError(t, provider.Shutdown(context.Background())) })
	reads := 0
	fail := false
	c := &Collector{
		capacity: fakeCapacity{cpuMilli: 31000, memBytes: 122 << 30},
		hostMemory: func() (hostMemoryStats, error) {
			reads++
			if fail {
				return hostMemoryStats{}, errors.New("host meminfo unavailable")
			}
			return parseHostMemory(strings.NewReader("MemTotal: 134217728 kB\nMemAvailable: 100663296 kB\n"))
		},
	}
	// Reproduce a cgroup v2 root with no memory.current: containerd reports
	// zero without an error. Host metrics must not use that synthetic zero.
	c.SetCgroupStatsReader(func(string) (cgroupmanager.Stats, error) {
		return cgroupmanager.Stats{}, nil
	})
	require.NoError(t, c.registerMetrics(provider.Meter("test")))
	var data metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &data))
	require.Equal(t, 1, reads, "all host gauges must share one snapshot")
	values := make(map[string]int64)
	ratios := make(map[string]float64)
	for _, scope := range data.ScopeMetrics {
		for _, m := range scope.Metrics {
			switch gauge := m.Data.(type) {
			case metricdata.Gauge[int64]:
				if strings.HasPrefix(m.Name, "node.memory.") {
					require.Len(t, gauge.DataPoints, 1)
					values[m.Name] = gauge.DataPoints[0].Value
				}
			case metricdata.Gauge[float64]:
				if m.Name == "node.memory.utilization" {
					require.Len(t, gauge.DataPoints, 1)
					ratios[m.Name] = gauge.DataPoints[0].Value
				}
			}
		}
	}
	require.Equal(t, map[string]int64{
		"node.memory.usage":          32 << 30,
		"node.memory.physical.total": 128 << 30,
		"node.memory.available":      96 << 30,
		"node.memory.total":          122 << 30,
	}, values)
	require.Equal(t, 0.25, ratios["node.memory.utilization"])
	_, capacity := c.capacity.Capacity()
	require.Equal(t, int64(122<<30), capacity, "host metrics must not change schedulable capacity")

	fail = true
	data = metricdata.ResourceMetrics{}
	require.Error(t, reader.Collect(context.Background(), &data))
	for _, scope := range data.ScopeMetrics {
		for _, m := range scope.Metrics {
			if strings.HasPrefix(m.Name, "node.memory.") {
				require.Equal(t, "node.memory.total", m.Name, "failed host read must not export zero or stale host values")
			}
		}
	}
}
