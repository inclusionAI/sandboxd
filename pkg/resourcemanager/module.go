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
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/cgroupmanager"
	"github.com/inclusionAI/sandboxd/pkg/sandbox"
	"github.com/inclusionAI/sandboxd/pkg/xpumanager"
	"github.com/sirupsen/logrus"
)

// Module owns node-resource reporting in either cgroup or Kubernetes watch
// mode. It runs the periodic refresh loop and serves the Unix-domain
// `/resource` endpoint consumed by an external scheduler.
//
// Lifecycle:
//   - NewModule constructs the underlying NodeResourceManager.
//   - Start launches the refresh loop and HTTP listener on sockPath.
//   - Stop closes the listener and drains the background loops.
//   - Healthy reports whether at least one successful refresh has occurred
//     within the staleness window.
type Module struct {
	nodeResource NodeResourceManager
	sockPath     string

	mu                        sync.RWMutex
	availCpu                  int64
	availMem                  int64
	sandboxMemoryUsage        func() (uint64, error)
	sandboxMemUsage           uint64
	sandboxMemUsageReady      bool
	xpu                       xpuProvider
	ephemeralStorage          ephemeralStorageProvider
	ephemeralStorageCapacity  uint64
	ephemeralStorageAvailable uint64
	ephemeralStorageReady     bool
	transientMemory           map[string]int64
	memoryCeiling             int64
	started                   bool

	lastRefresh atomic.Int64 // unix-nano of most recent successful refresh
	// lastMemSampleAt records the unix-nano of the most recent successful
	// sandbox-memory sample. Zero means no sample yet. It is deliberately
	// separate from lastRefresh: provider refreshes can keep succeeding while
	// cgroup memory sampling fails, and availMem != 0 is not a valid success
	// marker either (zero available memory is a legitimate published result).
	lastMemSampleAt atomic.Int64
	stalenessWindow time.Duration
	listener        net.Listener
	stopCh          chan struct{}
	closeOnce       sync.Once
	wg              sync.WaitGroup

	collectorShutdown func(context.Context) error
	collector         *Collector
}

// resourceInfo is the JSON payload served by the /resource endpoint. CPU is
// reported in scheduler cores, while memory and writable storage use bytes.
//
// Mem keeps the historical capacity contract (provider capacity minus pod
// requests and transient reservations). Schedulers may already reserve memory
// for running sandboxes, so folding their usage into Mem charges them twice.
// Sandbox memory is exposed as the separate SandboxMemUsage observation
// field; consumers must explicitly adopt it for admission. The value is
// omitted while no fresh sample exists.
type resourceInfo struct {
	Cpu             int64                 `json:"cpu"`
	Mem             int64                 `json:"mem"`
	SandboxMemUsage *uint64               `json:"sandbox_mem_usage,omitempty"`
	Xpu             []xpumanager.Resource `json:"xpu"`
	Storage         *uint64               `json:"storage,omitempty"`
	Features        []string              `json:"features"`
}

type xpuProvider interface {
	Resources() []xpumanager.Resource
}

type ephemeralStorageProvider interface {
	EphemeralStorageCapacity() (capacityBytes, allocatableBytes uint64, err error)
}

const storageQuotaFeature = "storage-quota-v1"

// NewModule constructs the configured node-resource module. sockPath is the
// Unix socket exposed to the external collector.
func NewModule(
	sockPath string,
	provider string,
	providerConfig ...ProviderConfig,
) (*Module, error) {
	nrm, err := NewNodeResourceManager(provider, providerConfig...)
	if err != nil {
		return nil, err
	}

	m := &Module{
		nodeResource:    nrm,
		sockPath:        sockPath,
		stopCh:          make(chan struct{}),
		transientMemory: make(map[string]int64),
		stalenessWindow: 30 * time.Second,
	}

	// OTLP metrics push is best-effort: a missing collector at startup must
	// not block sandboxd from coming up.
	//
	// The collector reads m (not nrm directly) so node.cpu.limit /
	// node.memory.total report the same node-available figure the Module
	// caches and serves over the resource socket — see Module.Capacity.
	if collector, cerr := NewCollector(context.Background(), m); cerr != nil {
		logrus.Warnf("resourcemanager: metrics collector init failed: %v", cerr)
	} else {
		m.collector = collector
		m.collectorShutdown = collector.Shutdown
	}

	return m, nil
}

// SetMemoryLimit clips each refreshed provider capacity to the parent maxBytes.
// For the cgroup provider, root is the managed cgroup name within its visible
// memory-controller mount. CPU capacity continues to use sandboxd's own group.
// Other providers retain their existing policies before the capacity is clipped.
// Call this before Start, after the managed root's limit has been applied.
func (m *Module) SetMemoryLimit(root string, maxBytes int64) error {
	if maxBytes <= 0 {
		return fmt.Errorf("memory limit must be positive")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started {
		return fmt.Errorf("memory limit must be configured before Start")
	}
	select {
	case <-m.stopCh:
		return fmt.Errorf("resource manager is stopped")
	default:
	}
	if provider, ok := m.nodeResource.(*cgroupResourceManager); ok {
		if err := provider.setMemoryRoot(root); err != nil {
			return err
		}
	}
	m.memoryCeiling = maxBytes
	return nil
}

// SetSandboxMetricsSource connects the node metrics collector to sandbox
// lifecycle state once the sandbox manager is ready.
func (m *Module) SetSandboxMetricsSource(source SandboxMetricsSource) {
	if m.collector != nil {
		m.collector.SetSandboxMetricsSource(source)
	}
}

// SetXPUProvider adds the node-local accelerator inventory to /resource.
func (m *Module) SetXPUProvider(provider xpuProvider) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.xpu = provider
}

// SetEphemeralStorageProvider adds filestore writable-layer capacity and its
// capability marker to /resource. The first refresh is synchronous so a
// scheduler querying immediately after sandboxd startup sees a complete node
// resource snapshot.
func (m *Module) SetEphemeralStorageProvider(provider ephemeralStorageProvider) {
	m.mu.Lock()
	m.ephemeralStorage = provider
	m.mu.Unlock()
	m.refreshEphemeralStorage()
}

// SetCgroupStatsReader routes all cgroup-backed OTel metrics through the
// CgroupManager's auto-selected v1/v2 implementation.
func (m *Module) SetCgroupStatsReader(
	reader func(string) (cgroupmanager.Stats, error),
) {
	if m.collector != nil {
		m.collector.SetCgroupStatsReader(reader)
	}
}

// SetParentMemoryReader routes parent memory metrics through the managed
// CgroupManager's selected memory controller and configured parent cgroup.
func (m *Module) SetParentMemoryReader(
	reader func() (cgroupmanager.ParentMemoryStats, error),
) {
	if m.collector != nil {
		m.collector.SetParentMemoryReader(reader)
	}
}

// SetSandboxMemoryUsage supplies live aggregate sandbox-cgroup memory
// accounting (CgroupManager.StatsRoot plus out-of-root bookkeeping cgroups
// such as the Firecracker checkpoint subtree). When set, the refresh loop
// samples it on the same cadence and serves it as the sandbox_mem_usage
// observation field on /resource, alongside — not subtracted from — the Mem
// capacity contract. Consumers that already subtract instance requests from
// capacity must not receive usage folded into Mem, which would charge each
// running instance twice.
//
// The observation carries the same failure discipline as the capacity
// fields: a sample is kept through transient read failures only within the
// staleness window, and the field is omitted when no fresh sample exists.
//
// Callers must install this before Start: the refresh goroutine launched by
// Start must never publish an observation the first round cannot back with
// a real sample.
func (m *Module) SetSandboxMemoryUsage(fn func() (uint64, error)) {
	m.mu.Lock()
	m.sandboxMemoryUsage = fn
	m.mu.Unlock()
}

// MarkSandboxStopped records a terminal sandbox state for asynchronous export.
func (m *Module) MarkSandboxStopped(target sandbox.MetricsTarget) {
	if m.collector != nil {
		m.collector.MarkSandboxStopped(target)
	}
}

// Start launches the refresh loop and HTTP server. It returns once the
// listener is bound. The socket reports zero until the first fresh sample.
func (m *Module) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started {
		return fmt.Errorf("resource manager is already started")
	}
	select {
	case <-m.stopCh:
		return fmt.Errorf("resource manager is stopped")
	default:
	}
	if _, err := os.Stat(m.sockPath); err == nil {
		os.Remove(m.sockPath)
	}
	ln, err := net.Listen("unix", m.sockPath)
	if err != nil {
		return err
	}
	m.listener = ln
	m.started = true

	mux := http.NewServeMux()
	mux.HandleFunc("/resource", func(w http.ResponseWriter, r *http.Request) {
		m.mu.RLock()
		now := time.Now()
		cpu, mem := m.capacityLocked(now)
		info := resourceInfo{
			Cpu:      cpu,
			Mem:      mem,
			Xpu:      []xpumanager.Resource{},
			Features: []string{},
		}
		if m.sandboxMemUsageReady && freshSample(now, m.lastMemSampleAt.Load(), m.stalenessLimitLocked()) {
			usage := m.sandboxMemUsage
			info.SandboxMemUsage = &usage
		}
		if m.xpu != nil {
			info.Xpu = m.xpu.Resources()
		}
		if m.ephemeralStorageReady {
			storageBytes := m.ephemeralStorageAvailable
			info.Storage = &storageBytes
			info.Features = append(info.Features, storageQuotaFeature)
		}
		m.mu.RUnlock()
		body, _ := json.Marshal(info)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})

	m.wg.Add(2)
	go m.serve(mux)
	go m.refreshLoop()

	return nil
}

// Stop closes the unix listener and waits for the refresh loop to drain.
// Safe to call from any goroutine; idempotent. The previous select+close
// pattern races on concurrent callers (two goroutines can both pass the
// default branch and double-close stopCh, panicking). sync.Once gives a
// true single-shot close; wg.Wait stays outside so every caller blocks
// until the background loops have actually exited, not just until the
// first caller observed stopCh as closed.
func (m *Module) Stop() {
	m.closeOnce.Do(func() {
		m.mu.Lock()
		close(m.stopCh)
		listener := m.listener
		m.mu.Unlock()
		if m.nodeResource != nil {
			m.nodeResource.Stop()
		}
		if listener != nil {
			_ = listener.Close()
		}
		if m.collectorShutdown != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = m.collectorShutdown(ctx)
		}
	})
	m.wg.Wait()
}

// Healthy reports whether the latest capacity refresh was within the
// staleness window. Sandbox memory usage is a separate observation.
func (m *Module) Healthy() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return freshSample(time.Now(), m.lastRefresh.Load(), m.stalenessLimitLocked())
}

func (m *Module) stalenessLimitLocked() time.Duration {
	if m.stalenessWindow > 0 {
		return m.stalenessWindow
	}
	return 30 * time.Second
}

func freshSample(now time.Time, timestamp int64, limit time.Duration) bool {
	return timestamp != 0 && now.Sub(time.Unix(0, timestamp)) < limit
}

// Test freshness when serving readers, even if a provider or memory read
// blocks the refresh loop past the grace period.
func (m *Module) capacityLocked(now time.Time) (int64, int64) {
	if !freshSample(now, m.lastRefresh.Load(), m.stalenessLimitLocked()) {
		return 0, 0
	}
	return m.availCpu, availableAfterTransientReservations(m.availMem, m.transientMemory)
}

// Capacity returns the node's currently-available CPU (millicores) and memory
// (bytes) — the same figure the refresh loop computes via
// GetAvailableResource and serves over the /resource socket. It
// satisfies metrics.CapacityProvider so node.cpu.limit / node.memory.total
// report exactly what the resource manager tells the proxy is schedulable,
// rather than a static box size.
//
// Reading the cached values here (instead of calling GetAvailableResource
// again) keeps the metric in lockstep with the socket and avoids
// re-triggering the underlying computation's smoothing/state side effects.
// availCpu is stored in cores (the refresh loop already divided by 1000), so
// scale back to millicores to match the CapacityProvider contract. Returns
// (0, 0) before the first successful refresh, which the collector treats as
// "no data yet" and skips.
func (m *Module) Capacity() (int64, int64) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cpu, mem := m.capacityLocked(time.Now())
	return cpu * 1000, mem
}

// ReserveTransientMemory atomically removes short-lived runtime overhead from
// the node capacity advertised to the scheduler. It fails when the refreshed
// available capacity cannot cover the request. The returned release function
// is idempotent so callers can use it on every terminal path.
func (m *Module) ReserveTransientMemory(owner string, bytes int64) (func(), bool) {
	if m == nil || owner == "" || bytes <= 0 {
		return func() {}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.transientMemory == nil {
		m.transientMemory = make(map[string]int64)
	}
	_, mem := m.capacityLocked(time.Now())
	if _, exists := m.transientMemory[owner]; exists || bytes > mem {
		return func() {}, false
	}
	m.transientMemory[owner] = bytes
	return func() { m.ReleaseTransientMemory(owner) }, true
}

// ReleaseTransientMemory returns a short-lived reservation to advertised node
// capacity. It is idempotent so both the operation and a later sandbox delete
// can safely release the same owner.
func (m *Module) ReleaseTransientMemory(owner string) {
	if m == nil || owner == "" {
		return
	}
	m.mu.Lock()
	delete(m.transientMemory, owner)
	m.mu.Unlock()
}

func availableAfterTransientReservations(available int64, reservations map[string]int64) int64 {
	for _, reserved := range reservations {
		if reserved <= 0 {
			continue
		}
		if reserved >= available {
			return 0
		}
		available -= reserved
	}
	return available
}

func (m *Module) serve(mux *http.ServeMux) {
	defer m.wg.Done()
	srv := &http.Server{Handler: mux}
	// http.Serve returns when the listener is closed; that is the canonical
	// shutdown path, so log only at debug level.
	if err := srv.Serve(m.listener); err != nil && err != http.ErrServerClosed {
		logrus.Debugf("resourcemanager: /resource http server stopped: %v", err)
	}
}

func (m *Module) refreshLoop() {
	defer m.wg.Done()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	m.refreshOnce()
	for {
		select {
		case <-ticker.C:
			m.refreshOnce()
		case <-m.stopCh:
			return
		}
	}
}

func (m *Module) refreshOnce() {
	m.mu.RLock()
	sandboxMemoryUsage := m.sandboxMemoryUsage
	m.mu.RUnlock()

	cpu, mem, err := m.nodeResource.GetAvailableResource()
	providerSampleAt := time.Now()
	if err != nil {
		// A provider failure must not bypass the sandbox-memory staleness
		// policy below: keep the provider cache untouched for this round but
		// still run the usage sampling so a stale observation drops out of
		// the report instead of surviving forever on old provider data.
		logrus.Errorf("resourcemanager: refresh failed: %v", err)
		cpu = -1 // sentinel: skip publishing provider figures this round
		mem = -1
	}
	// Wire format expects CPU in cores; underlying manager returns
	// millicores (see standalone main.go for the same division).
	if cpu >= 0 {
		cpu /= 1000
	}

	// Sandbox memory lives in a root cgroup outside every pod's cgroup, so
	// no provider can see it. It is sampled on the same 5s cadence and
	// exposed as the sandbox_mem_usage observation field next to the
	// unchanged Mem capacity contract (see resourceInfo for why it is not
	// subtracted from Mem). The figure includes page cache, which errs on
	// the safe side for admission decisions that read it.
	//
	// Failure and staleness policy: after one successful sample, a failing
	// sample keeps the last published usage — but only within the staleness
	// window. Past that (or with no sample yet), the field is omitted from
	// /resource rather than serving a frozen or fabricated figure.
	// Sample outside the lock: the reader is an injected callback and must
	// never run while m.mu is held.
	var (
		sampleOK   bool
		sampleVal  uint64
		sampleWarn error
		sampleAt   time.Time
	)
	if sandboxMemoryUsage != nil {
		sampleVal, sampleWarn = sandboxMemoryUsage()
		sampleOK = sampleWarn == nil
		sampleAt = time.Now()
	}
	m.mu.Lock()
	limit := m.stalenessLimitLocked()
	if sandboxMemoryUsage != nil {
		switch {
		case sampleOK:
			m.sandboxMemUsage = sampleVal
			m.sandboxMemUsageReady = true
			m.lastMemSampleAt.Store(sampleAt.UnixNano())
		default:
			if freshSample(time.Now(), m.lastMemSampleAt.Load(), limit) {
				logrus.Warnf(
					"resourcemanager: read sandbox memory usage failed; keep last sample: %v",
					sampleWarn,
				)
			} else {
				m.sandboxMemUsageReady = false
				m.lastMemSampleAt.Store(0)
				logrus.Warnf(
					"resourcemanager: sandbox memory sample missing or stale; dropping observation field: %v",
					sampleWarn,
				)
			}
		}
	}
	if cpu >= 0 {
		if m.memoryCeiling > 0 && mem > m.memoryCeiling {
			mem = m.memoryCeiling
		}
		m.availCpu = cpu
		m.availMem = mem
		m.lastRefresh.Store(providerSampleAt.UnixNano())
	} else if !freshSample(time.Now(), m.lastRefresh.Load(), limit) {
		// Provider data is past the staleness window: publish zero capacity
		// rather than the frozen last-successful figure. The consumer's
		// collector caches its previous successful response on connection
		// errors and non-200 replies, so an error or omitted field would not
		// stop it from scheduling against the stale figure — only an explicit
		// zero propagates. Zero removes the node from admission until the
		// provider recovers and the real capacity is republished.
		m.availCpu = 0
		m.availMem = 0
		logrus.Warn(
			"resourcemanager: provider data stale; publishing zero capacity")
	}
	m.mu.Unlock()
	if cpu >= 0 {
		logrus.Debugf(
			"resourcemanager: avail cpu=%d cores mem=%d bytes sandbox_mem=%d bytes",
			cpu, mem, sandboxMemSnapshot(m),
		)
	}
	m.refreshEphemeralStorage()
}

// sandboxMemSnapshot returns the currently published sandbox-memory
// observation for debug logging; 0 when the field is absent.
func sandboxMemSnapshot(m *Module) uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.sandboxMemUsageReady {
		return 0
	}
	return m.sandboxMemUsage
}

func (m *Module) refreshEphemeralStorage() {
	m.mu.RLock()
	provider := m.ephemeralStorage
	m.mu.RUnlock()
	if provider == nil {
		return
	}
	capacity, allocatable, err := provider.EphemeralStorageCapacity()
	if err != nil {
		logrus.Errorf("resourcemanager: ephemeral storage refresh failed: %v", err)
		return
	}
	m.mu.Lock()
	m.ephemeralStorageCapacity = capacity
	m.ephemeralStorageAvailable = allocatable
	m.ephemeralStorageReady = true
	m.mu.Unlock()
	logrus.Debugf(
		"resourcemanager: ephemeral storage capacity=%d bytes allocatable=%d bytes",
		capacity,
		allocatable,
	)
}
