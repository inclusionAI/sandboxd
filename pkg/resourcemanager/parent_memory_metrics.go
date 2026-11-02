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
	"fmt"
	"math"
	"path"
	"strings"

	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/inclusionAI/sandboxd/pkg/cgroupmanager"
)

// SetParentMemoryReader connects parent memory metrics to the same managed
// cgroup and selected memory controller used by CgroupManager. Passing nil
// disables observations until another reader is supplied.
func (c *Collector) SetParentMemoryReader(
	reader func() (cgroupmanager.ParentMemoryStats, error),
) {
	c.cgroupStatsMu.Lock()
	c.parentMemory = reader
	c.cgroupStatsMu.Unlock()
}

func (c *Collector) registerParentMemoryMetrics(meter metric.Meter) error {
	current, err := meter.Int64ObservableGauge("sandbox.parent.memory.current",
		metric.WithUnit("By"),
		metric.WithDescription("Current memory usage of the managed parent cgroup in bytes"),
	)
	if err != nil {
		return err
	}
	maximum, err := meter.Int64ObservableGauge("sandbox.parent.memory.max",
		metric.WithUnit("By"),
		metric.WithDescription("Finite memory limit of the managed parent cgroup in bytes"),
	)
	if err != nil {
		return err
	}

	_, err = meter.RegisterCallback(func(_ context.Context, observer metric.Observer) error {
		stats, err := c.parentMemorySnapshot()
		if err != nil {
			// A callback error makes PeriodicReader skip the entire export,
			// including unrelated node and sandbox metrics.
			logrus.Debugf("metrics: parent memory snapshot unavailable: %v", err)
			return nil
		}
		attrs := metric.WithAttributes(attribute.String("cgroup_path", stats.CgroupPath))
		observer.ObserveInt64(current, int64(stats.CurrentBytes), attrs)
		observer.ObserveInt64(maximum, int64(stats.MaxBytes), attrs)
		return nil
	}, current, maximum)
	return err
}

// parentMemorySnapshot validates the complete pair before either gauge is
// observed. A missing or unusable snapshot therefore produces no observations
// in this collection, without keeping a previous value or using node capacity.
func (c *Collector) parentMemorySnapshot() (cgroupmanager.ParentMemoryStats, error) {
	c.cgroupStatsMu.RLock()
	reader := c.parentMemory
	c.cgroupStatsMu.RUnlock()
	if reader == nil {
		return cgroupmanager.ParentMemoryStats{}, errors.New("parent memory reader is not configured")
	}
	stats, err := reader()
	if err != nil {
		return cgroupmanager.ParentMemoryStats{}, fmt.Errorf("read parent memory: %w", err)
	}
	if strings.TrimSpace(stats.CgroupPath) == "" || stats.CgroupPath == "/" ||
		!path.IsAbs(stats.CgroupPath) || path.Clean(stats.CgroupPath) != stats.CgroupPath {
		return cgroupmanager.ParentMemoryStats{}, fmt.Errorf("parent memory snapshot has invalid managed cgroup path %q", stats.CgroupPath)
	}
	if stats.Unlimited {
		return cgroupmanager.ParentMemoryStats{}, fmt.Errorf("parent memory limit is unlimited for cgroup %q", stats.CgroupPath)
	}
	if stats.CurrentBytes > math.MaxInt64 || stats.MaxBytes > math.MaxInt64 {
		return cgroupmanager.ParentMemoryStats{}, fmt.Errorf("parent memory snapshot for cgroup %q exceeds int64 range (current=%d max=%d)", stats.CgroupPath, stats.CurrentBytes, stats.MaxBytes)
	}
	return stats, nil
}
