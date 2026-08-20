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

package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/inclusionAI/sandboxd/internal/metrics"
	"github.com/inclusionAI/sandboxd/internal/physicalstate"
	"github.com/inclusionAI/sandboxd/internal/util"
	cmap "github.com/orcaman/concurrent-map/v2"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/cgroupmanager"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"

	"github.com/golang/protobuf/proto"
	spec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
)

type Manager struct {
	// sandbox root directory
	root string
	// recyclePath receives incomplete on-disk sandbox directories. Housekeeping
	// removes them after recovery no longer needs their contents.
	recyclePath string

	sandboxes cmap.ConcurrentMap[string, *Sandbox]
	// physicalIntents caches durable INTENT metadata without publishing it
	// through Get/List. meta.pb remains authoritative across restart.
	physicalIntents *cmap.ConcurrentMap[string, *Sandbox]
	// serviceHandler maps a configured runtime name to its runsc or Kata
	// implementation. Handlers are loaded before Manager is constructed.
	serviceHandler cmap.ConcurrentMap[string, svc.Handler]

	// cgroupMgr is used only to consume the manager-level OOM flag. The server
	// owns resource allocation/release and manager shutdown.
	cgroupMgr *cgroupmanager.CgroupManager

	monitorStopChan cmap.ConcurrentMap[string, chan struct{}]

	// exitNotifiers fan-out exit notifications to any number of WaitForExit
	// callers. Created when monitor starts; closed once after SetExit has
	// persisted the terminal status, or on Delete/Stop.
	exitNotifiers cmap.ConcurrentMap[string, *exitNotifier]
	// Handle sandbox events asynchronously. Create is the exception: its
	// monitor and exit notifier are published before ReceiveEvent returns.
	syncEventChan chan Event
	// check id is valid
	idGenerator util.UniqueIDGenerator

	// lifecycleMu linearizes monitor publication with shutdown. Once stopped
	// is set, no new monitor or exit notifier may be registered.
	lifecycleMu sync.Mutex
	stopped     bool
	stopChan    chan struct{}

	healthChan chan bool

	// maxSandboxNum is the admission ceiling on concurrent sandboxes. It is the
	// converged MaxSandboxLimit shared with the cgroup and interface pools
	// (1 sandbox = 1 cgroup + 1 interface), derived from max_instance_num.
	maxSandboxNum int

	// OnSandboxStopped records terminal metrics before metadata is removed.
	// Implementations must not perform network I/O on this lifecycle path.
	OnSandboxStopped func(MetricsTarget)

	// isHousekeepingRunning prevents overlapping runtime/disk reconciliation
	// passes when one pass lasts longer than the periodic interval.
	isHousekeepingRunning atomic.Bool
}

// exitNotifier is a one-shot broadcast channel used to wake up any number of
// callers blocked in WaitForExit once a sandbox reaches its terminal state.
type exitNotifier struct {
	done      chan struct{}
	closeOnce sync.Once
}

func newExitNotifier() *exitNotifier {
	return &exitNotifier{done: make(chan struct{})}
}

func (n *exitNotifier) close() {
	n.closeOnce.Do(func() { close(n.done) })
}

func NewManager(
	root string,
	handlers cmap.ConcurrentMap[string, svc.Handler],
	healthChan chan bool,
	cgroupMgr *cgroupmanager.CgroupManager,
	maxSandboxNum int,
) (*Manager, error) {
	// prepare recycle bin
	if err := util.Os().MkdirAll(filepath.Join(root, config.RecycleBin), 0755); err != nil {
		return nil, err
	}

	if maxSandboxNum <= 0 {
		maxSandboxNum = config.DefaultMaxSandboxNum
	}

	m := &Manager{
		// Legacy on-disk directory name; retained for state-recovery compatibility.
		root:            filepath.Join(root, "containers"),
		recyclePath:     filepath.Join(root, config.RecycleBin),
		sandboxes:       cmap.New[*Sandbox](),
		serviceHandler:  handlers,
		monitorStopChan: cmap.New[chan struct{}](),
		exitNotifiers:   cmap.New[*exitNotifier](),
		cgroupMgr:       cgroupMgr,
		idGenerator:     util.NewUUIDGenerator(config.SandboxPrefix, nil),
		syncEventChan:   make(chan Event, 4096),
		stopChan:        make(chan struct{}),
		healthChan:      healthChan,
		maxSandboxNum:   maxSandboxNum,
	}

	if err := m.loadSandboxes(); err != nil {
		return nil, err
	}
	for sandboxID := range m.sandboxes.Items() {
		m.idGenerator.Reserve(sandboxID)
	}
	if m.physicalIntents != nil {
		for sandboxID := range m.physicalIntents.Items() {
			m.idGenerator.Reserve(sandboxID)
		}
	}

	// Start monitors for recovered sandboxes immediately (don't wait for housekeeping).
	for item := range m.sandboxes.IterBuffered() {
		if item.Val != nil && item.Val.Metadata != nil {
			m.startMonitorGoroutine(item.Val.Metadata, make(chan struct{}))
		}
	}
	if count := m.sandboxes.Count(); count > 0 {
		logrus.Infof("recovered %d sandboxes from disk, monitors started", count)
	}

	return m, nil
}

func (m *Manager) Start() {
	m.loop()
}

func (m *Manager) Stop() {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	if m.stopped {
		return
	}
	m.stopped = true
	close(m.stopChan)

	// Stop monitors synchronously while holding lifecycleMu. A concurrent
	// startMonitorGoroutine either publishes before this sweep or observes
	// stopped and returns without publishing.
	for item := range m.monitorStopChan.IterBuffered() {
		m.stopMonitor(item.Key)
	}

	// Wake up any pending WaitForExit callers so they don't block past
	// shutdown. lifecycleMu prevents new notifiers after this sweep.
	for item := range m.exitNotifiers.IterBuffered() {
		item.Val.close()
	}
}

// loop receive sandbox event from runtime handler or runtime lifecycle.
func (m *Manager) loop() {
	housekeepingTicker := time.NewTicker(35 * time.Second)
	defer housekeepingTicker.Stop()

	for {
		select {
		case <-housekeepingTicker.C:
			go m.housekeeping()
		case <-m.stopChan:
			logrus.Infof("sandbox manager start to stop")
			for item := range m.monitorStopChan.IterBuffered() {
				m.stopMonitor(item.Key)
			}
			return
		case event := <-m.syncEventChan:
			m.syncEvent(event)
		}
	}
}

func (m *Manager) syncEvent(event Event) {
	logrus.Infof("handle sandbox event: %+v", event)
	switch event.Type {
	// we need to start monitor here.
	case EventTypeCreate:
		m.startMonitorGoroutine(event.MetaData, make(chan struct{}))
	case EventTypeDelete:
		m.stopMonitor(event.SandboxID)
	case EventTypeExit:
		if err := m.SetExit(event.SandboxID, event.ExitCode, event.ExitedAt.String(), event.OOMKilled); err != nil {
			logrus.Errorf("set sandbox %s exit failed: %v", event.SandboxID, err)
		}
	case EventTypeStart:
		sb, ok := m.sandboxes.Get(event.SandboxID)
		if !ok {
			logrus.Warnf("sandbox %s is not ready to restart, try later", event.SandboxID)
			return
		}

		m.startMonitorGoroutine(sb.Metadata, make(chan struct{}))
	}
}

// PersistMetadata atomically records sandboxd's physical identity before the
// runtime is exposed. It deliberately does not publish the sandbox through
// List until ActivateMetadata observes the runtime status/spec files.
func (m *Manager) PersistMetadata(id string, data *physicalstate.SandboxMetadata) error {
	if data == nil || data.ID != id {
		return fmt.Errorf("sandbox metadata ID does not match %q", id)
	}
	sandboxRoot, err := util.JoinWithinRoot(m.root, id)
	if err != nil {
		return fmt.Errorf("resolve sandbox %q root: %w", id, err)
	}
	start := time.Now()

	if _, err := os.Stat(sandboxRoot); os.IsNotExist(err) {
		if err := os.MkdirAll(sandboxRoot, 0755); err != nil {
			return fmt.Errorf("create sandbox root %s: %w", sandboxRoot, err)
		}
	}
	dataFile := filepath.Join(sandboxRoot, config.SandboxMetaFile)
	bytes, err := proto.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal sandbox metadata %s: %w", data.ID, err)
	}

	if err := util.AtomicWriteFile(dataFile, bytes, 0600); err != nil {
		return fmt.Errorf("save sandbox metadata %s: %w", data.ID, err)
	}
	if data.PhysicalPhase == physicalstate.PhysicalPhase_PHYSICAL_PHASE_INTENT &&
		m.physicalIntents != nil {
		metadata := proto.Clone(data).(*physicalstate.SandboxMetadata)
		m.physicalIntents.Set(id, &Sandbox{Metadata: metadata, PATH: sandboxRoot})
	}
	logrus.Debugf("persist sandbox %s metadata success, cost %v", data.ID, time.Since(start).String())
	return nil
}

// ActivateMetadata publishes a persisted, physically created sandbox through
// the manager. PersistMetadata remains the durable source used after restart.
func (m *Manager) ActivateMetadata(id string) error {
	sandboxRoot, err := util.JoinWithinRoot(m.root, id)
	if err != nil {
		return fmt.Errorf("resolve sandbox %q root: %w", id, err)
	}
	stored, err := m.loadSandbox(sandboxRoot)
	if err != nil {
		return fmt.Errorf("load stored sandbox metadata %s: %w", id, err)
	}
	if stored.Metadata == nil ||
		stored.Metadata.PhysicalPhase == physicalstate.PhysicalPhase_PHYSICAL_PHASE_INTENT {
		return fmt.Errorf("sandbox %s physical intent is not committed: %w",
			id, errord.ErrFailedPrecondition)
	}
	if m.physicalIntents != nil {
		m.physicalIntents.Remove(id)
	}
	m.sandboxes.Set(id, stored)
	return nil
}

// StoreMetadata atomically persists and publishes metadata for an already
// materialized sandbox. New sandbox creation uses PersistMetadata before the
// runtime start and ActivateMetadata after physical creation completes.
func (m *Manager) StoreMetadata(id string, data *physicalstate.SandboxMetadata) error {
	if data != nil {
		data.PhysicalPhase = physicalstate.PhysicalPhase_PHYSICAL_PHASE_COMMITTED
	}
	if err := m.PersistMetadata(id, data); err != nil {
		return err
	}
	return m.ActivateMetadata(id)
}

func (m *Manager) housekeeping() {
	// Avoid reentry
	isRunning := m.isHousekeepingRunning.Swap(true)
	if isRunning {
		return
	}
	defer m.isHousekeepingRunning.Store(false)

	logrus.Debugf("start housekeeping: %d sandboxes", m.sandboxes.Count())
	start := time.Now()

	// 1. Health check
	defer func() {
		spent := time.Since(start)
		if spent >= config.HouseKeepingMaxCostTime {
			logrus.Warnf("housekeeping finished, cost %v which is too long", spent)
			m.healthChan <- false
		} else {
			logrus.Debugf("housekeeping finished, cost %v", spent)
			m.healthChan <- true
		}
	}()

	// 2. Maintain m.sandboxes
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cstates := make(map[string]*svc.State)

	for r, handler := range m.serviceHandler.Items() {
		states, err := handler.List(ctx)
		if err != nil {
			logrus.Errorf("list %s sandboxes failed: %v", r, err)
			continue
		}
		for idx := range states {
			cstates[states[idx].ID] = states[idx]
		}
	}

	for id, sb := range m.sandboxes.Items() {
		if sb == nil {
			m.sandboxes.Remove(id)
			continue
		}

		// check root
		if _, err := os.Stat(sb.PATH); err != nil && os.IsNotExist(err) {
			logrus.Errorf("sandbox %s root %s is not exist", id, sb.PATH)
			m.ReceiveEvent(Event{
				Type:      EventTypeDelete,
				SandboxID: id,
			})
			continue
		}

		if sb.Status != nil {
			if err := sb.Status.UpdateSync(func(status Status) (Status, error) {
				return UpdateStatusByState(cstates[id], status), nil
			}); err != nil {
				logrus.Errorf("update sandbox %s status failed: %v", id, err)
			}
		}

		// get state
		if sb.Status == nil && cstates[id] != nil {
			sb.Status = GenerateStatusFromState(cstates[id], filepath.Join(sb.PATH, config.SandboxStatusFile))
		}

		// TODO: clean up the left one
		if sb.Status == nil {
			logrus.Errorf("sandbox %s status is nil", id)
			m.sandboxes.Remove(id)
			continue
		}
	}

	// 3. Clean recycled paths
	dir, err := os.ReadDir(m.recyclePath)
	if err == nil {
		for _, d := range dir {
			os.RemoveAll(filepath.Join(m.recyclePath, d.Name()))
		}
	}

	// 4. Complement monitoring (double check strategy)
	for item := range m.sandboxes.IterBuffered() {
		m.startMonitorGoroutine(item.Val.Metadata, make(chan struct{}))
	}

	// 5. Update prometheus gauge
	metrics.RecordResourceGauge("sandbox", float64(m.sandboxes.Count()))

	// 6. Close monitor if the sandbox is deleted (double check strategy)
	for item := range m.monitorStopChan.IterBuffered() {
		// close monitor if the sandbox is deleted
		if !m.sandboxes.Has(item.Key) {
			logrus.Infof("sandbox %s is deleted, release releated resource", item.Key)
			m.ReceiveEvent(Event{
				Type:      EventTypeDelete,
				SandboxID: item.Key,
			})
		}
	}
}

// loadSandboxes load a sandbox from root.
// when the function is called, the sandbox and the metadata should exist. If not, we drop it.
// 1. load metadata
// 2. load spec
func (m *Manager) loadSandbox(sandboxRoot string) (*Sandbox, error) {
	// read bytes from sandboxRoot/metadata.pb
	b, err := os.ReadFile(filepath.Join(sandboxRoot, config.SandboxMetaFile))
	if err != nil {
		// mv sandbox root to m.root/RecycleBin if not exist
		if os.IsNotExist(err) {
			if err2 := os.Rename(sandboxRoot, filepath.Join(m.recyclePath, filepath.Base(sandboxRoot))); err2 != nil {
				logrus.Warnf("move sandbox %s to recycle bin failed: %v", sandboxRoot, err2)
			}
			return nil, err
		}

		return nil, err
	}

	// Unmarshal sandboxd-private physical metadata. Its field numbers preserve
	// compatibility with meta.pb files written before the type moved internal.
	var meta physicalstate.SandboxMetadata
	if err = proto.Unmarshal(b, &meta); err != nil {
		return nil, err
	}

	sb := new(Sandbox)
	sb.Metadata = &meta
	sb.PATH = sandboxRoot
	sb.Status, err = LoadStatus(sandboxRoot)
	if err != nil {
		logrus.Warnf("load status for sandbox %s failed: %v", sb.Metadata.ID, err)
		return nil, err
	}

	sb.Spec = new(spec.Spec)
	specByte, err := os.ReadFile(filepath.Join(sandboxRoot, config.SandboxSpecFile))
	if err != nil {
		logrus.Warnf("load spec for sandbox %s failed: %v", sb.Metadata.ID, err)
		return sb, nil
	}
	if err = json.Unmarshal(specByte, sb.Spec); err != nil {
		logrus.Warnf("load spec for sandbox %s failed: %v", sb.Metadata.ID, err)
		return sb, nil
	}

	return sb, nil
}

// loadSandboxes loads the sandboxes from sandbox root path.
func (m *Manager) loadSandboxes() error {
	// look for existing sandboxes from dir root
	list, err := os.ReadDir(m.root)
	if err != nil {
		logrus.Debugf("read dir %s failed: %v", m.root, err)
		if errors.Is(err, os.ErrNotExist) {
			if err = os.MkdirAll(m.root, 0755); err != nil {
				return err
			}
		} else {
			return err
		}
	}
	logrus.Debugf("manager loaded sandboxes under %s", m.root)

	m.sandboxes = cmap.New[*Sandbox]()
	intents := cmap.New[*Sandbox]()
	m.physicalIntents = &intents

	// load sandbox metadata and spec
	for _, sandboxDir := range list {
		if !sandboxDir.IsDir() || !strings.HasPrefix(sandboxDir.Name(), config.SandboxPrefix) {
			logrus.Debugf("manager load skip %s", sandboxDir.Name())
			continue
		}
		sb, err := m.loadSandbox(filepath.Join(m.root, sandboxDir.Name()))
		if err != nil {
			logrus.Errorf("load sandbox %s failed: %v", sandboxDir.Name(), err)
			continue
		}
		if sb.Metadata != nil &&
			sb.Metadata.PhysicalPhase == physicalstate.PhysicalPhase_PHYSICAL_PHASE_INTENT {
			m.physicalIntents.Set(sandboxDir.Name(), sb)
			continue
		}
		m.sandboxes.Set(sandboxDir.Name(), sb)
	}
	return nil
}

// Notice: Do not run this method in goroutine, it meant to start the goroutine by itself
// Maintain the serviceHandler synchronously instead of doing it in goroutine to avoid trace condition
// e.g. run `go m.startMonitor()` then run `m.Delete(id)` the Delete could run before startMonitor
func (m *Manager) startMonitorGoroutine(metaData *physicalstate.SandboxMetadata, stop chan struct{}) {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	if m.stopped {
		logrus.Debugf("ignore monitor start after sandbox manager shutdown: %s", metaData.ID)
		return
	}

	handler, ok := m.serviceHandler.Get(metaData.RuntimeHandler)
	if !ok {
		logrus.Errorf("runtime handler %s for %s not found, skip it", metaData.RuntimeHandler, metaData.ID)
		return
	}

	absent := m.monitorStopChan.SetIfAbsent(metaData.ID, stop)
	// Avoid starting monitor multi times for one sandboxID
	if !absent { // Already exist, skip
		return
	}

	// Track an exit notifier alongside the monitor so WaitForExit callers can
	// observe the terminal status once SetExit completes.
	m.exitNotifiers.SetIfAbsent(metaData.ID, newExitNotifier())

	go m.__startMonitor(metaData, stop, handler)
}

// startMonitor monitors a running sandbox for exit events.
func (m *Manager) __startMonitor(metaData *physicalstate.SandboxMetadata, stop chan struct{}, handler svc.Handler) {
	logrus.Infof("start monitor sandbox %s", metaData.ID)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cgroupName := m.oomCgroupName(metaData.ID)

	// Collect exit information asynchronously. The kernel OOM subscription
	// follows the cached cgroup lifetime inside CgroupManager.
	go func() {
		exit, err := handler.Wait(ctx, metaData.ID)
		// If context was cancelled (monitor stopped), don't send exit event.
		if ctx.Err() != nil {
			return
		}

		oom := m.oomKilled(metaData.ID, cgroupName)
		logrus.Infof("wait sandbox %s finished, err: %v, exit: %+v, oom: %v",
			metaData.ID, err, exit, oom)

		if err != nil {
			m.ReceiveEvent(Event{
				Type:      EventTypeExit,
				SandboxID: metaData.ID,
				Pid:       -1,
				ExitCode:  int32(128),
				ExitedAt:  time.Now(),
				OOMKilled: oom,
			})
			return
		}
		m.ReceiveEvent(Event{
			Type:      EventTypeExit,
			SandboxID: metaData.ID,
			Pid:       -1,
			ExitCode:  int32(exit.ExitCode),
			ExitedAt:  exit.ExitedAt,
			OOMKilled: oom,
		})
	}()

	<-stop
	logrus.Infof("stop monitor sandbox %s", metaData.ID)
}

// oomCgroupName resolves the cgroup before waiting so a concurrent Delete may
// remove sandbox metadata without invalidating the runtime wait goroutine.
func (m *Manager) oomCgroupName(sandboxID string) string {
	if m.cgroupMgr == nil {
		return ""
	}
	resource, err := m.CollectResourceByID(sandboxID)
	if err != nil {
		logrus.Warnf("oom monitor: collect resource for %s failed: %v", sandboxID, err)
		return ""
	}
	cgroupName, ok := resource.Resources[config.ResourceNameCgroup]
	if !ok || cgroupName == "" {
		logrus.Warnf("oom monitor: cgroup name missing for %s, skipping", sandboxID)
		return ""
	}
	return cgroupName
}

func (m *Manager) oomKilled(sandboxID, cgroupName string) bool {
	if m.cgroupMgr == nil || cgroupName == "" {
		return false
	}
	killed, err := m.cgroupMgr.OOMKilled(cgroupName)
	if err != nil {
		logrus.Warnf(
			"oom monitor: read cgroup %s flag for %s failed: %v",
			cgroupName,
			sandboxID,
			err,
		)
		return false
	}
	return killed
}

func (m *Manager) Get(id string) (*Sandbox, error) {
	if c, ok := m.sandboxes.Get(id); ok {
		return c, nil
	}
	return nil, errord.ErrNotFound
}

func (m *Manager) UpdateLabels(id string, labels map[string]string) error {
	c, ok := m.sandboxes.Get(id)
	if !ok {
		return errord.ErrNotFound
	}
	if labels == nil || len(labels) == 0 {
		return nil
	}
	needUpdate := false
	for k, v := range labels {
		if c.Metadata.Labels == nil {
			c.Metadata.Labels = make(map[string]string)
		}
		if c.Metadata.Labels[k] != v {
			c.Metadata.Labels[k] = v
			needUpdate = true
		}
	}
	if !needUpdate {
		return nil
	}
	return m.StoreMetadata(id, c.Metadata)
}

func (m *Manager) List(option ...ListOption) []*Sandbox {
	var sandboxes []*Sandbox
	for _, ct := range m.sandboxes.Items() {
		satisfy := true
		for _, opt := range option {
			if !opt(ct) {
				satisfy = false
				break
			}
		}
		if satisfy {
			sandboxes = append(sandboxes, ct)
		}
	}
	return sandboxes
}

// HasPhysicalRecord reports whether sandboxd owns either a published sandbox
// or a hidden creation intent for the deterministic ID.
func (m *Manager) HasPhysicalRecord(id string) bool {
	if m.sandboxes.Has(id) {
		return true
	}
	return m.physicalIntents != nil && m.physicalIntents.Has(id)
}

// ListPhysicalIntents returns immutable snapshots of incomplete physical
// records for startup reconciliation. INTENT records never appear in Get/List.
func (m *Manager) ListPhysicalIntents() []*physicalstate.SandboxMetadata {
	if m.physicalIntents == nil {
		return nil
	}
	items := m.physicalIntents.Items()
	result := make([]*physicalstate.SandboxMetadata, 0, len(items))
	for _, sb := range items {
		if sb == nil || sb.Metadata == nil {
			continue
		}
		result = append(result, proto.Clone(sb.Metadata).(*physicalstate.SandboxMetadata))
	}
	return result
}

// ListCommittedRestores returns immutable snapshots of published restore
// records. Callers must still confirm each record against the runtime handler;
// COMMITTED describes the durable sandboxd record, not runtime liveness.
func (m *Manager) ListCommittedRestores() []*physicalstate.SandboxMetadata {
	result := make([]*physicalstate.SandboxMetadata, 0)
	for _, sb := range m.sandboxes.Items() {
		if sb == nil || sb.Metadata == nil || sb.Metadata.RestoreIdentity == nil ||
			sb.Metadata.PhysicalPhase != physicalstate.PhysicalPhase_PHYSICAL_PHASE_COMMITTED {
			continue
		}
		result = append(result, proto.Clone(sb.Metadata).(*physicalstate.SandboxMetadata))
	}
	return result
}

// MetricsTarget is an immutable snapshot of the information needed to collect
// metrics for one running sandbox.
type MetricsTarget struct {
	SandboxID    string
	RuntimeClass string
	CgroupPath   string
	CPULimit     float64
	MetricLabels map[string]string
}

// SandboxMetricsTargets returns snapshots for running sandboxes. CgroupPath
// is empty when cgroup management is disabled; lifecycle gauges remain
// available while per-sandbox resource usage is omitted.
func (m *Manager) SandboxMetricsTargets() []MetricsTarget {
	targets := make([]MetricsTarget, 0, m.sandboxes.Count())
	for _, sb := range m.sandboxes.Items() {
		if sb == nil || sb.Status == nil {
			continue
		}
		if sb.Status.Get().State() != runtime.SandboxState_SANDBOX_STATE_RUNNING {
			continue
		}
		target, ok := sandboxMetricsTarget(sb)
		if !ok {
			continue
		}
		targets = append(targets, target)
	}
	return targets
}

func sandboxMetricsTarget(sb *Sandbox) (MetricsTarget, bool) {
	if sb == nil || sb.Metadata == nil || sb.Spec == nil ||
		sb.Metadata.ID == "" || sb.Metadata.RuntimeHandler == "" {
		return MetricsTarget{}, false
	}

	cgroupPath := ""
	if sb.Spec.Annotations != nil {
		cgroupPath = sb.Spec.Annotations[config.ResourceAnnotationKeyPrefix+config.ResourceNameCgroup]
	}
	if cgroupPath == "" && sb.Spec.Linux != nil {
		cgroupPath = sb.Spec.Linux.CgroupsPath
	}

	labels := make(map[string]string, len(sb.Metadata.MetricLabels)+2)
	for key, value := range sb.Metadata.MetricLabels {
		labels[key] = value
	}
	labels["sandbox_id"] = sb.Metadata.ID
	labels["runtime_class"] = sb.Metadata.RuntimeHandler
	return MetricsTarget{
		SandboxID:    sb.Metadata.ID,
		RuntimeClass: sb.Metadata.RuntimeHandler,
		CgroupPath:   cgroupPath,
		CPULimit:     sandboxCPULimit(sb.Spec),
		MetricLabels: labels,
	}, true
}

func (m *Manager) notifySandboxStopped(sb *Sandbox) {
	if m.OnSandboxStopped == nil {
		return
	}
	target, ok := sandboxMetricsTarget(sb)
	if ok {
		m.OnSandboxStopped(target)
	}
}

func sandboxCPULimit(sandboxSpec *spec.Spec) float64 {
	if sandboxSpec == nil || sandboxSpec.Linux == nil || sandboxSpec.Linux.Resources == nil ||
		sandboxSpec.Linux.Resources.CPU == nil {
		return 0
	}
	cpu := sandboxSpec.Linux.Resources.CPU
	if cpu.Quota != nil && cpu.Period != nil && *cpu.Quota > 0 && *cpu.Period > 0 {
		return float64(*cpu.Quota) / float64(*cpu.Period)
	}
	if cpu.Shares != nil && *cpu.Shares > 0 {
		return float64(*cpu.Shares) / 1024.0
	}
	return 0
}

type ListOption func(*Sandbox) bool

func ListFilterByState(state runtime.SandboxState) ListOption {
	return func(c *Sandbox) bool {
		return c.Status.Get().State() == state
	}
}

func ListFilterById(id string) ListOption {
	return func(c *Sandbox) bool {
		if c == nil || c.Metadata == nil {
			logrus.Errorf("ListFilterById: Got invalid sandbox %+v", c)
			return false
		}
		return c.Metadata.ID == id
	}
}

func ListFilterByLabels(labels map[string]string) ListOption {
	return func(c *Sandbox) bool {
		if c == nil || c.Metadata == nil {
			logrus.Errorf("ListFilterByLabels: Got invalid sandbox %+v", c)
			return false
		}

		if len(labels) == 0 {
			return true
		}

		if c.Metadata.Labels == nil {
			return false
		}

		for k, v := range labels {
			if c.Metadata.Labels[k] != v && v != "" {
				return false
			}
		}
		return true
	}
}

func (m *Manager) ReserveID(requestedID string) (string, error) {
	if m.idGenerator.Len() >= m.maxSandboxNum {
		return "", errord.ErrSandboxNumExceed
	}
	if requestedID != "" {
		if !config.IsValidSandboxID(requestedID) {
			return "", fmt.Errorf(
				"sandbox id %q must use %s<suffix> as one path component: %w",
				requestedID, config.SandboxIDPrefix, errord.ErrInvalidArgument,
			)
		}
		if !m.idGenerator.Reserve(requestedID) {
			return "", fmt.Errorf("sandbox %s: %w", requestedID, errord.ErrAlreadyExists)
		}
		return requestedID, nil
	}
	return m.idGenerator.Next()
}

func (m *Manager) ReleaseID(id string) {
	if m.idGenerator == nil {
		return
	}
	m.idGenerator.Release(id)
}

func (or OccupiedResource) ToLabels() map[string]string {
	annotations := make(map[string]string)
	for r, key := range or.Resources {
		annotations[config.ResourceAnnotationKeyPrefix+r] = key
	}
	return annotations
}

type OccupiedResource struct {
	ID        string
	Resources map[string]string
}

func (m *Manager) CollectResourceByID(id string) (OccupiedResource, error) {
	var resource OccupiedResource
	specPath, err := util.JoinWithinRoot(m.root, id, config.SandboxSpecFile)
	if err != nil {
		return resource, err
	}
	oci, err := svc.LoadSpec(specPath)
	if err != nil {
		return resource, err
	}
	resource.ID = id
	resource.Resources = make(map[string]string)
	for resourceName, key := range oci.Annotations {
		if strings.HasPrefix(resourceName, config.ResourceAnnotationKeyPrefix) {
			resourceName = strings.TrimPrefix(resourceName, config.ResourceAnnotationKeyPrefix)
			resource.Resources[resourceName] = key
		}
	}

	if _, ok := resource.Resources[config.ResourceNameCgroup]; !ok {
		if oci.Linux.CgroupsPath != "" {
			resource.Resources[config.ResourceNameCgroup] = oci.Linux.CgroupsPath
		}
	}
	logrus.Debugf("collect resource for %s success, details: %+v", id, resource.Resources)
	return resource, nil
}

func (m *Manager) CleanSandboxRoot(id string) {
	sandboxRoot, err := util.JoinWithinRoot(m.root, id)
	if err != nil {
		logrus.Warnf("refuse to clean sandbox %q: %v", id, err)
		return
	}
	if err := os.RemoveAll(sandboxRoot); err != nil {
		// Try again
		if strings.Contains(err.Error(), "directory not empty") {
			err = os.RemoveAll(sandboxRoot)
			if err != nil {
				logrus.Warnf("remove sandbox %s root failed: %v", sandboxRoot, err)
			}
		}
	}
	if m.physicalIntents != nil {
		m.physicalIntents.Remove(id)
	}
}

func (m *Manager) Delete(id string) {
	if sb, ok := m.sandboxes.Get(id); ok {
		m.notifySandboxStopped(sb)
	}

	m.ReleaseID(id)

	// clean root file.
	m.CleanSandboxRoot(id)

	if !m.sandboxes.Has(id) {
		return
	}

	m.sandboxes.Remove(id)

	// Close monitor after m.sandboxes.Remove(id) to avoid the race condition
	// that stop monitor first then housekeeping loop sandboxes and start monitor once again.
	m.stopMonitor(id)

	// Wake up any pending WaitForExit callers; subsequent calls will hit the
	// ErrNotFound fast path because the sandbox is no longer tracked.
	if n, ok := m.exitNotifiers.Pop(id); ok {
		n.close()
	}
}

func (m *Manager) stopMonitor(id string) {
	if stopChan, exists := m.monitorStopChan.Pop(id); exists {
		close(stopChan)
	}
}

func (m *Manager) ReceiveEvent(event Event) {
	if event.Type == EventTypeCreate {
		// Start returns immediately after publishing this event. Handle Create
		// synchronously so a concurrent Wait cannot observe the sandbox before
		// its exit notifier has been registered.
		m.syncEvent(event)
		return
	}
	select {
	case m.syncEventChan <- event:
		logrus.Debugf("receive event: %+v", event)
	case <-m.stopChan:
		logrus.Debugf("ignore event after sandbox manager shutdown: %+v", event)
	}
}

func (m *Manager) SetExit(id string, exitCode int32, finishAt string, oomKilled bool) error {
	sb, ok := m.sandboxes.Get(id)
	if !ok {
		return errord.ErrNotFound
	}
	if sb.Status == nil {
		return errord.ErrNotFound
	}

	// update status
	if err := sb.Status.UpdateSync(func(status Status) (Status, error) {
		status.Pid = -1
		status.ExitCode = exitCode
		status.OOMKilled = oomKilled
		if finishAt == "" || finishAt == "0" {
			finishAt = time.Now().Format(time.RFC3339Nano)
		}
		status.FinishedAt = finishAt
		return status, nil
	}); err != nil {
		logrus.Errorf("update sandbox %s status failed: %v", id, err)
	} else {
		m.notifySandboxStopped(sb)
	}
	// Broadcast the exit only after the terminal status has been persisted, so
	// WaitForExit consumers always observe the final status.
	if n, ok := m.exitNotifiers.Get(id); ok {
		n.close()
	}
	return nil
}

// WaitForExit blocks until the sandbox reaches its terminal state, ctx is
// cancelled, or the manager is shutting down.
//   - Unknown sandbox id returns errord.ErrNotFound immediately.
//   - Already-exited sandboxes (FinishedAt != "") return immediately via the
//     fast path, even if no notifier is registered (e.g. after recovery).
//   - Multiple concurrent waiters are supported; SetExit broadcasts to all.
func (m *Manager) WaitForExit(ctx context.Context, id string) (Status, error) {
	c, ok := m.sandboxes.Get(id)
	if !ok {
		return Status{}, errord.ErrNotFound
	}
	if c.Status == nil {
		return Status{}, errord.ErrNotFound
	}
	if s := c.Status.Get(); s.FinishedAt != "" {
		return s, nil
	}
	n, ok := m.exitNotifiers.Get(id)
	if !ok {
		// Fall back to a fresh status read in case the sandbox exited while
		// we were looking up the notifier.
		if s := c.Status.Get(); s.FinishedAt != "" {
			return s, nil
		}
		return Status{}, errord.ErrNotFound
	}
	select {
	case <-n.done:
		return c.Status.Get(), nil
	case <-ctx.Done():
		return Status{}, ctx.Err()
	case <-m.stopChan:
		// Manager is shutting down; surface as a context-style cancellation
		// when the caller's ctx is still live.
		if err := ctx.Err(); err != nil {
			return Status{}, err
		}
		return Status{}, context.Canceled
	}
}
