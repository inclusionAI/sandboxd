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
	"bufio"
	"context"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/metric"
)

type hostMemoryStats struct {
	total     int64
	available int64
}

func readHostMemory() (hostMemoryStats, error) {
	f, err := os.Open(procMeminfoPath)
	if err != nil {
		return hostMemoryStats{}, fmt.Errorf("open host meminfo: %w", err)
	}
	defer f.Close()
	return parseHostMemory(f)
}

func parseHostMemory(r io.Reader) (hostMemoryStats, error) {
	values := make(map[string]int64, 2)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 || (fields[0] != "MemTotal:" && fields[0] != "MemAvailable:") {
			continue
		}
		if len(fields) != 3 || fields[2] != "kB" {
			return hostMemoryStats{}, fmt.Errorf("invalid host meminfo field %q", scanner.Text())
		}
		if _, exists := values[fields[0]]; exists {
			return hostMemoryStats{}, fmt.Errorf("duplicate host meminfo field %s", fields[0])
		}
		kb, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || kb < 0 || kb > math.MaxInt64/1024 {
			return hostMemoryStats{}, fmt.Errorf("invalid host meminfo value %q", fields[1])
		}
		values[fields[0]] = kb * 1024
	}
	if err := scanner.Err(); err != nil {
		return hostMemoryStats{}, fmt.Errorf("read host meminfo: %w", err)
	}
	total, hasTotal := values["MemTotal:"]
	available, hasAvailable := values["MemAvailable:"]
	if !hasTotal || !hasAvailable || total <= 0 || available > total {
		return hostMemoryStats{}, fmt.Errorf("host meminfo requires positive MemTotal and MemAvailable within [0, MemTotal]")
	}
	return hostMemoryStats{total: total, available: available}, nil
}

// Host pressure is independent of schedulable capacity and sandbox cgroups.
// In particular, the unified hierarchy root has no memory.current file.
// Read all host gauges from one meminfo snapshot to keep their ratios coherent.
func (c *Collector) registerHostMemoryMetrics(meter metric.Meter) error {
	usage, err := meter.Int64ObservableGauge("node.memory.usage",
		metric.WithUnit("By"),
		metric.WithDescription("Host memory in use: MemTotal minus MemAvailable, excluding reclaimable memory"))
	if err != nil {
		return err
	}
	total, err := meter.Int64ObservableGauge("node.memory.physical.total",
		metric.WithUnit("By"),
		metric.WithDescription("Host physical memory visible to Linux (MemTotal), not schedulable capacity"))
	if err != nil {
		return err
	}
	available, err := meter.Int64ObservableGauge("node.memory.available",
		metric.WithUnit("By"),
		metric.WithDescription("Host memory available without swapping (MemAvailable), including reclaimable memory"))
	if err != nil {
		return err
	}
	utilization, err := meter.Float64ObservableGauge("node.memory.utilization",
		metric.WithUnit("1"),
		metric.WithDescription("Host memory usage divided by physical MemTotal, in [0, 1]"))
	if err != nil {
		return err
	}
	_, err = meter.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		read := c.hostMemory
		if read == nil {
			read = readHostMemory
		}
		stats, err := read()
		if err != nil {
			// Missing data is not an idle node. Never export a synthetic zero.
			logrus.Warnf("metrics: failed to read host memory: %v", err)
			return nil
		}
		used := stats.total - stats.available
		o.ObserveInt64(usage, used)
		o.ObserveInt64(total, stats.total)
		o.ObserveInt64(available, stats.available)
		o.ObserveFloat64(utilization, float64(used)/float64(stats.total))
		logrus.Infof("metrics: node.memory.usage=%d bytes, physical.total=%d bytes, available=%d bytes", used, stats.total, stats.available)
		return nil
	}, usage, total, available, utilization)
	return err
}
