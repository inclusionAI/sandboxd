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
	"fmt"
	"os"
	"regexp"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/inclusionAI/sandboxd/internal/cgroupops"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdkresource "go.opentelemetry.io/otel/sdk/resource"

	cg "github.com/containerd/cgroups/v3/cgroup1"
	"github.com/inclusionAI/sandboxd/pkg/resourcemanager/cgroupv1"
	"github.com/inclusionAI/sandboxd/pkg/sandbox"
)

const (
	defaultCpuacctPath = "/sys/fs/cgroup/cpuacct"
	defaultMemPath     = "/sys/fs/cgroup/memory"

	collectorEndpoint = "127.0.0.1:4318"
	collectInterval   = 5 * time.Second

	// Keep stopped sandbox state for several export cycles so a transient OTLP
	// failure cannot leave the last running=1 sample visible in Prometheus.
	sandboxTombstoneRetention = 3 * collectInterval
)

var diskPaths = []string{"/", "/home/akernel"}

var prometheusLabelName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// CapacityProvider reports the node's currently-available (schedulable) CPU
// (millicores) and memory (bytes) as computed by the resource manager and
// served over the /resource socket. It is satisfied by
// resourcemanager.Module; declared locally to avoid an import cycle.
// Returns (0, 0) before the first refresh, which callbacks treat as "no
// data" and skip.
type CapacityProvider interface {
	Capacity() (int64, int64)
}

// SandboxMetricsSource supplies immutable snapshots of running sandboxes.
type SandboxMetricsSource interface {
	SandboxMetricsTargets() []sandbox.MetricsTarget
}

type sandboxStats struct {
	CPUUsageNS     uint64
	MemoryUsage    uint64
	MemoryLimit    uint64
	HasCPUUsage    bool
	HasMemoryUsage bool
}

type sandboxCPUSample struct {
	usageNS uint64
	at      time.Time
}

type sandboxTombstone struct {
	target    sandbox.MetricsTarget
	expiresAt time.Time
}

type sandboxObservation struct {
	target      sandbox.MetricsTarget
	running     int64
	cpuUsage    float64
	cpuLimit    float64
	cpuTotal    int64
	memoryUsage int64
	memoryLimit int64
	hasCPUUsage bool
	hasCPULimit bool
	hasCPU      bool
	hasMemory   bool
}

// Collector reports node CPU, memory, and disk metrics via OTel.
type Collector struct {
	provider *sdkmetric.MeterProvider

	cpuacctPath string
	memPath     string

	capacity CapacityProvider

	// state for CPU utilization delta calculation
	prevCPUUsage int64
	prevTime     time.Time

	sandboxSourceMu sync.RWMutex
	sandboxSource   SandboxMetricsSource
	sandboxStateMu  sync.Mutex
	prevSandboxCPU  map[string]sandboxCPUSample
	sandboxStopped  map[string]sandboxTombstone
	sandboxStats    func(string) (sandboxStats, error)
	now             func() time.Time

	sandboxRunning     metric.Int64ObservableGauge
	sandboxCPUUsage    metric.Float64ObservableGauge
	sandboxCPULimit    metric.Float64ObservableGauge
	sandboxCPUTotal    metric.Int64ObservableGauge
	sandboxMemoryUsage metric.Int64ObservableGauge
	sandboxMemoryLimit metric.Int64ObservableGauge
}

// NewCollector creates a Collector that exports metrics to the local
// OTel collector over HTTP (port 4318).
func NewCollector(ctx context.Context, capacity CapacityProvider) (*Collector, error) {
	exporter, err := otlpmetrichttp.New(ctx,
		otlpmetrichttp.WithEndpoint(collectorEndpoint),
		otlpmetrichttp.WithInsecure(),
	)
	if err != nil {
		return nil, err
	}

	reader := sdkmetric.NewPeriodicReader(exporter,
		sdkmetric.WithInterval(collectInterval),
	)
	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(reader),
		sdkmetric.WithResource(buildResource()),
	)

	c := &Collector{
		provider:       provider,
		cpuacctPath:    defaultCpuacctPath,
		memPath:        defaultMemPath,
		capacity:       capacity,
		prevSandboxCPU: make(map[string]sandboxCPUSample),
		sandboxStopped: make(map[string]sandboxTombstone),
		sandboxStats:   readSandboxStats,
		now:            time.Now,
	}

	meter := provider.Meter("resource-manager")
	if err := c.registerMetrics(meter); err != nil {
		provider.Shutdown(ctx)
		return nil, err
	}

	return c, nil
}

// buildResource attaches per-node identity to every exported metric so that
// centrally aggregated series can be split by node. Prefers os.Hostname()
// because the akernel-node DaemonSet runs with hostNetwork=true, so inside
// the container this returns the real host's hostname (e.g.
// "akernel-0-006002145253"), which is what operators want to see in
// dashboards. NODE_NAME (downward API spec.nodeName) is used as a fallback;
// on Alibaba clusters that value is the kubelet-registered instance ID
// (e.g. "i-f8z6xc36jyvnn6pojw9z"), which is less human friendly.
func buildResource() *sdkresource.Resource {
	nodeName := ""
	if hn, err := os.Hostname(); err == nil {
		nodeName = hn
	}
	if nodeName == "" {
		nodeName = os.Getenv("NODE_NAME")
	}
	return sdkresource.NewSchemaless(
		attribute.String("service.name", "resource-manager"),
		attribute.String("host.name", nodeName),
	)
}

// Shutdown flushes pending metrics and closes the exporter connection.
func (c *Collector) Shutdown(ctx context.Context) error {
	return c.provider.Shutdown(ctx)
}

// SetSandboxMetricsSource connects the collector to the sandbox manager after
// the manager has finished initialization.
func (c *Collector) SetSandboxMetricsSource(source SandboxMetricsSource) {
	c.sandboxSourceMu.Lock()
	c.sandboxSource = source
	c.sandboxSourceMu.Unlock()
}

// MarkSandboxStopped records an explicit terminal value without performing
// network I/O. The regular metrics callback exports running=0 for several
// collection cycles and then discards the copied labels.
func (c *Collector) MarkSandboxStopped(target sandbox.MetricsTarget) {
	now := time.Now()
	if c.now != nil {
		now = c.now()
	}
	target.MetricLabels = cloneMetricLabels(target.MetricLabels)

	c.sandboxStateMu.Lock()
	if c.sandboxStopped == nil {
		c.sandboxStopped = make(map[string]sandboxTombstone)
	}
	c.sandboxStopped[target.SandboxID] = sandboxTombstone{
		target:    target,
		expiresAt: now.Add(sandboxTombstoneRetention),
	}
	delete(c.prevSandboxCPU, target.SandboxID)
	c.sandboxStateMu.Unlock()
}

func (c *Collector) registerMetrics(meter metric.Meter) error {
	if _, err := meter.Float64ObservableGauge("node.cpu.usage",
		metric.WithUnit("{cores}"),
		metric.WithDescription("CPU cores in use (cpuacct.usage delta / wall time)"),
		metric.WithFloat64Callback(c.cpuUsageCallback),
	); err != nil {
		return err
	}

	if _, err := meter.Float64ObservableGauge("node.cpu.limit",
		metric.WithUnit("{cores}"),
		metric.WithDescription("CPU limit in cores from CFS quota"),
		metric.WithFloat64Callback(c.cpuLimitCallback),
	); err != nil {
		return err
	}

	if _, err := meter.Int64ObservableGauge("node.memory.usage",
		metric.WithUnit("By"),
		metric.WithDescription("Memory usage in bytes"),
		metric.WithInt64Callback(c.memUsageCallback),
	); err != nil {
		return err
	}

	if _, err := meter.Int64ObservableGauge("node.memory.total",
		metric.WithUnit("By"),
		metric.WithDescription("Node total schedulable memory in bytes (from NodeResourceManager.Capacity)"),
		metric.WithInt64Callback(c.memTotalCallback),
	); err != nil {
		return err
	}

	if _, err := meter.Int64ObservableGauge("node.filesystem.usage",
		metric.WithUnit("By"),
		metric.WithDescription("Filesystem used bytes"),
		metric.WithInt64Callback(c.diskUsageCallback),
	); err != nil {
		return err
	}

	if _, err := meter.Int64ObservableGauge("node.filesystem.capacity",
		metric.WithUnit("By"),
		metric.WithDescription("Filesystem total capacity in bytes"),
		metric.WithInt64Callback(c.diskCapacityCallback),
	); err != nil {
		return err
	}

	var err error
	c.sandboxRunning, err = meter.Int64ObservableGauge("sandbox.running",
		metric.WithUnit("{sandbox}"),
		metric.WithDescription("Whether the sandbox is currently running (1) or stopped (0)"),
	)
	if err != nil {
		return err
	}
	c.sandboxCPUUsage, err = meter.Float64ObservableGauge("sandbox.cpu.usage",
		metric.WithUnit("{cores}"),
		metric.WithDescription("CPU cores in use by the sandbox during the collection interval"),
	)
	if err != nil {
		return err
	}
	c.sandboxCPUTotal, err = meter.Int64ObservableGauge("sandbox.cpu.total",
		metric.WithUnit("ns"),
		metric.WithDescription("Cumulative sandbox cgroup CPU usage in nanoseconds"),
	)
	if err != nil {
		return err
	}
	c.sandboxCPULimit, err = meter.Float64ObservableGauge("sandbox.cpu.limit",
		metric.WithUnit("{cores}"),
		metric.WithDescription("Configured CPU capacity for the sandbox in cores"),
	)
	if err != nil {
		return err
	}
	c.sandboxMemoryUsage, err = meter.Int64ObservableGauge("sandbox.memory.usage",
		metric.WithUnit("By"),
		metric.WithDescription("Sandbox cgroup memory usage in bytes"),
	)
	if err != nil {
		return err
	}
	c.sandboxMemoryLimit, err = meter.Int64ObservableGauge("sandbox.memory.limit",
		metric.WithUnit("By"),
		metric.WithDescription("Sandbox cgroup memory limit in bytes"),
	)
	if err != nil {
		return err
	}
	if _, err = meter.RegisterCallback(c.sandboxMetricsCallback,
		c.sandboxRunning,
		c.sandboxCPUUsage,
		c.sandboxCPULimit,
		c.sandboxCPUTotal,
		c.sandboxMemoryUsage,
		c.sandboxMemoryLimit,
	); err != nil {
		return err
	}

	return nil
}

func readSandboxStats(cgroupPath string) (sandboxStats, error) {
	handler := &cgroupops.CgroupHandlerImpl{}
	group, err := handler.Load(cg.StaticPath(cgroupPath), cg.WithHiearchy(cg.Default))
	if err != nil {
		return sandboxStats{}, fmt.Errorf("load cgroup %s: %w", cgroupPath, err)
	}
	stats, err := group.Stat()
	if err != nil {
		return sandboxStats{}, fmt.Errorf("stat cgroup %s: %w", cgroupPath, err)
	}

	result := sandboxStats{}
	if stats.CPU != nil && stats.CPU.Usage != nil {
		result.CPUUsageNS = stats.CPU.Usage.Total
		result.HasCPUUsage = true
	}
	if stats.Memory != nil && stats.Memory.Usage != nil {
		result.MemoryUsage = stats.Memory.Usage.Usage
		result.MemoryLimit = stats.Memory.Usage.Limit
		result.HasMemoryUsage = true
	}
	return result, nil
}

func (c *Collector) getSandboxSource() SandboxMetricsSource {
	c.sandboxSourceMu.RLock()
	defer c.sandboxSourceMu.RUnlock()
	return c.sandboxSource
}

func (c *Collector) collectSandboxObservations(now time.Time) []sandboxObservation {
	source := c.getSandboxSource()
	var targets []sandbox.MetricsTarget
	if source != nil {
		targets = source.SandboxMetricsTargets()
	}

	c.sandboxStateMu.Lock()
	stopped := make(map[string]sandboxTombstone, len(c.sandboxStopped))
	for sandboxID, tombstone := range c.sandboxStopped {
		if !now.Before(tombstone.expiresAt) {
			delete(c.sandboxStopped, sandboxID)
			continue
		}
		stopped[sandboxID] = tombstone
	}
	c.sandboxStateMu.Unlock()

	active := make(map[string]struct{}, len(targets))
	observations := make([]sandboxObservation, 0, len(targets)+len(stopped))
	for _, target := range targets {
		// A lifecycle event can race with a source snapshot taken just before
		// SetExit/Delete. The explicit stopped state must win that race.
		if _, ok := stopped[target.SandboxID]; ok {
			continue
		}
		active[target.SandboxID] = struct{}{}
		observation := sandboxObservation{target: target, running: 1}
		stats, err := c.sandboxStats(target.CgroupPath)
		if err != nil {
			logrus.Debugf("metrics: failed to collect sandbox %s cgroup %s: %v", target.SandboxID, target.CgroupPath, err)
			observations = append(observations, observation)
			continue
		}

		if target.CPULimit > 0 {
			observation.cpuLimit = target.CPULimit
			observation.hasCPULimit = true
		}
		if stats.HasCPUUsage {
			observation.hasCPU = true
			observation.cpuTotal = uint64ToInt64(stats.CPUUsageNS)
		}
		if stats.HasMemoryUsage {
			observation.hasMemory = true
			observation.memoryUsage = uint64ToInt64(stats.MemoryUsage)
			observation.memoryLimit = uint64ToInt64(stats.MemoryLimit)
		}

		c.sandboxStateMu.Lock()
		if stats.HasCPUUsage {
			if previous, ok := c.prevSandboxCPU[target.SandboxID]; ok {
				elapsed := now.Sub(previous.at).Nanoseconds()
				if elapsed > 0 && stats.CPUUsageNS >= previous.usageNS {
					observation.cpuUsage = float64(stats.CPUUsageNS-previous.usageNS) / float64(elapsed)
					observation.hasCPUUsage = true
				}
			}
			c.prevSandboxCPU[target.SandboxID] = sandboxCPUSample{usageNS: stats.CPUUsageNS, at: now}
		}
		c.sandboxStateMu.Unlock()
		observations = append(observations, observation)
	}
	for _, tombstone := range stopped {
		observations = append(observations, sandboxObservation{target: tombstone.target, running: 0})
	}

	c.sandboxStateMu.Lock()
	for sandboxID := range c.prevSandboxCPU {
		if _, ok := active[sandboxID]; !ok {
			delete(c.prevSandboxCPU, sandboxID)
		}
	}
	c.sandboxStateMu.Unlock()
	return observations
}

func cloneMetricLabels(labels map[string]string) map[string]string {
	cloned := make(map[string]string, len(labels))
	for key, value := range labels {
		cloned[key] = value
	}
	return cloned
}

func uint64ToInt64(value uint64) int64 {
	const maxInt64 = uint64(1<<63 - 1)
	if value > maxInt64 {
		return int64(maxInt64)
	}
	return int64(value)
}

func sandboxAttributes(target sandbox.MetricsTarget) []attribute.KeyValue {
	labels := make(map[string]string, len(target.MetricLabels)+2)
	for key, value := range target.MetricLabels {
		if key == "host_name" || !prometheusLabelName.MatchString(key) {
			continue
		}
		labels[key] = value
	}
	labels["sandbox_id"] = target.SandboxID
	labels["runtime_class"] = target.RuntimeClass

	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	attributes := make([]attribute.KeyValue, 0, len(keys))
	for _, key := range keys {
		attributes = append(attributes, attribute.String(key, labels[key]))
	}
	return attributes
}

func (c *Collector) sandboxMetricsCallback(_ context.Context, observer metric.Observer) error {
	now := time.Now()
	if c.now != nil {
		now = c.now()
	}
	for _, observation := range c.collectSandboxObservations(now) {
		options := metric.WithAttributes(sandboxAttributes(observation.target)...)
		observer.ObserveInt64(c.sandboxRunning, observation.running, options)
		if observation.hasCPUUsage {
			observer.ObserveFloat64(c.sandboxCPUUsage, observation.cpuUsage, options)
		}
		if observation.hasCPULimit {
			observer.ObserveFloat64(c.sandboxCPULimit, observation.cpuLimit, options)
		}
		if observation.hasCPU {
			observer.ObserveInt64(c.sandboxCPUTotal, observation.cpuTotal, options)
		}
		if observation.hasMemory {
			observer.ObserveInt64(c.sandboxMemoryUsage, observation.memoryUsage, options)
			observer.ObserveInt64(c.sandboxMemoryLimit, observation.memoryLimit, options)
		}
	}
	return nil
}

// cpuUsageCallback computes CPU utilization from cpuacct.usage deltas.
func (c *Collector) cpuUsageCallback(_ context.Context, o metric.Float64Observer) error {
	usage, err := cgroupv1.ReadUsage(c.cpuacctPath, "cpuacct.usage")
	if err != nil {
		logrus.Debugf("metrics: failed to read cpuacct.usage: %v", err)
		return nil
	}

	now := time.Now()
	if c.prevCPUUsage != 0 {
		elapsed := now.Sub(c.prevTime).Nanoseconds()
		if elapsed > 0 {
			util := float64(usage-c.prevCPUUsage) / float64(elapsed)
			if util < 0 {
				util = 0
			}
			o.Observe(util)
			logrus.Infof("metrics: node.cpu.usage=%.4f cores", util)
		}
	}

	c.prevCPUUsage = usage
	c.prevTime = now
	return nil
}

// cpuLimitCallback reports the node's currently-available CPU as a core
// count: the same schedulable figure served over the /resource socket, not a
// static host size. Sourcing it from the shared cached value keeps metrics in
// lockstep with the scheduler view.
func (c *Collector) cpuLimitCallback(_ context.Context, o metric.Float64Observer) error {
	if c.capacity == nil {
		return nil
	}
	cpuMilli, _ := c.capacity.Capacity()
	if cpuMilli <= 0 {
		return nil
	}
	limit := float64(cpuMilli) / 1000.0
	o.Observe(limit)
	logrus.Infof("metrics: node.cpu.limit=%.2f cores", limit)
	return nil
}

// memUsageCallback reports node memory usage from cgroupv1.
func (c *Collector) memUsageCallback(_ context.Context, o metric.Int64Observer) error {
	mem, err := cgroupv1.ReadMemcgV1(c.memPath, "")
	if err != nil {
		logrus.Debugf("metrics: failed to read memory cgroup: %v", err)
		return nil
	}
	o.Observe(int64(mem.Usage))
	logrus.Infof("metrics: node.memory.usage=%d bytes (%.2f MiB)", mem.Usage, float64(mem.Usage)/(1024*1024))
	return nil
}

// memTotalCallback reports the node's currently-available memory as tracked
// by the resource manager: the same figure served over the /resource socket,
// matching node.cpu.limit.
func (c *Collector) memTotalCallback(_ context.Context, o metric.Int64Observer) error {
	if c.capacity == nil {
		return nil
	}
	_, memBytes := c.capacity.Capacity()
	if memBytes <= 0 {
		return nil
	}
	o.Observe(memBytes)
	logrus.Infof("metrics: node.memory.total=%d bytes", memBytes)
	return nil
}

// diskUsageCallback reports filesystem used bytes for each configured path.
func (c *Collector) diskUsageCallback(_ context.Context, o metric.Int64Observer) error {
	for _, p := range diskPaths {
		var stat syscall.Statfs_t
		if err := syscall.Statfs(p, &stat); err != nil {
			logrus.Debugf("metrics: statfs %s: %v", p, err)
			continue
		}
		used := int64(stat.Blocks-stat.Bfree) * int64(stat.Bsize)
		o.Observe(used, metric.WithAttributes(attribute.String("path", p)))
		logrus.Infof("metrics: node.filesystem.usage{path=%s}=%d bytes (%.2f GiB)", p, used, float64(used)/(1024*1024*1024))
	}
	return nil
}

// diskCapacityCallback reports filesystem total capacity for each configured path.
func (c *Collector) diskCapacityCallback(_ context.Context, o metric.Int64Observer) error {
	for _, p := range diskPaths {
		var stat syscall.Statfs_t
		if err := syscall.Statfs(p, &stat); err != nil {
			logrus.Debugf("metrics: statfs %s: %v", p, err)
			continue
		}
		total := int64(stat.Blocks) * int64(stat.Bsize)
		o.Observe(total, metric.WithAttributes(attribute.String("path", p)))
		logrus.Infof("metrics: node.filesystem.capacity{path=%s}=%d bytes (%.2f GiB)", p, total, float64(total)/(1024*1024*1024))
	}
	return nil
}
