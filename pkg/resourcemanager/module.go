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
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/cgroupmanager"
	"github.com/inclusionAI/sandboxd/pkg/sandbox"
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

	mu       sync.RWMutex
	availCpu int64
	availMem int64

	lastRefresh atomic.Int64 // unix-nano of most recent successful refresh
	listener    net.Listener
	stopCh      chan struct{}
	closeOnce   sync.Once
	wg          sync.WaitGroup

	collectorShutdown func(context.Context) error
	collector         *Collector
}

// resourceInfo is the JSON payload served by the /resource endpoint. CPU is
// reported in cores; memory is reported in bytes.
type resourceInfo struct {
	Cpu int64 `json:"cpu"`
	Mem int64 `json:"mem"`
}

// NewModule constructs the Kubernetes-backed node-resource module. sockPath
// is the Unix socket exposed to the external collector.
func NewModule(sockPath string) (*Module, error) {
	nrm, err := NewNodeResourceManager()
	if err != nil {
		return nil, err
	}

	m := &Module{
		nodeResource: nrm,
		sockPath:     sockPath,
		stopCh:       make(chan struct{}),
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

// SetSandboxMetricsSource connects the node metrics collector to sandbox
// lifecycle state once the sandbox manager is ready.
func (m *Module) SetSandboxMetricsSource(source SandboxMetricsSource) {
	if m.collector != nil {
		m.collector.SetSandboxMetricsSource(source)
	}
}

// SetCgroupManager routes per-sandbox metrics through the selected cgroup
// driver instead of assuming the legacy v1 hierarchy.
func (m *Module) SetCgroupManager(manager *cgroupmanager.CgroupManager) {
	if m.collector != nil {
		m.collector.SetCgroupManager(manager)
	}
}

// MarkSandboxStopped records a terminal sandbox state for asynchronous export.
func (m *Module) MarkSandboxStopped(target sandbox.MetricsTarget) {
	if m.collector != nil {
		m.collector.MarkSandboxStopped(target)
	}
}

// Start launches the refresh loop and HTTP server. It returns once the
// listener is bound so external collectors can use the socket immediately.
func (m *Module) Start() error {
	if _, err := os.Stat(m.sockPath); err == nil {
		os.Remove(m.sockPath)
	}
	ln, err := net.Listen("unix", m.sockPath)
	if err != nil {
		return err
	}
	m.listener = ln

	mux := http.NewServeMux()
	mux.HandleFunc("/resource", func(w http.ResponseWriter, r *http.Request) {
		m.mu.RLock()
		info := resourceInfo{Cpu: m.availCpu, Mem: m.availMem}
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
		close(m.stopCh)
		if m.nodeResource != nil {
			m.nodeResource.Stop()
		}
		if m.listener != nil {
			_ = m.listener.Close()
		}
		if m.collectorShutdown != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = m.collectorShutdown(ctx)
		}
	})
	m.wg.Wait()
}

// Healthy reports whether the latest refresh was within the staleness
// window. ResourceManager's freshness is a leading indicator that the
// Kubernetes watch is alive.
func (m *Module) Healthy() bool {
	ts := m.lastRefresh.Load()
	if ts == 0 {
		return false
	}
	return time.Since(time.Unix(0, ts)) < 30*time.Second
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
	return m.availCpu * 1000, m.availMem
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
	cpu, mem, err := m.nodeResource.GetAvailableResource()
	if err != nil {
		logrus.Errorf("resourcemanager: refresh failed: %v", err)
		return
	}
	// Wire format expects CPU in cores; underlying manager returns
	// millicores (see standalone main.go for the same division).
	cpu /= 1000
	m.mu.Lock()
	m.availCpu = cpu
	m.availMem = mem
	m.mu.Unlock()
	m.lastRefresh.Store(time.Now().UnixNano())
	logrus.Debugf("resourcemanager: avail cpu=%d cores mem=%d bytes", cpu, mem)
}
