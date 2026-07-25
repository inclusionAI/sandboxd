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
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/util"
	"github.com/inclusionAI/sandboxd/pkg/cgroupmanager"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/inclusionAI/sandboxd/pkg/store"
	spec "github.com/opencontainers/runtime-spec/specs-go"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/stretchr/testify/assert"
)

func TestNewManager(t *testing.T) {
	handlers := cmap.New[svc.Handler]()
	healthChan := make(chan bool)
	cgMgr, err := cgroupmanager.NewCgroupManager(store.NewMockStore(), config.ResourceConfig{
		MaxInstanceNum:  10,
		CgroupRootName:  "huse",
		CgroupCacheSize: 8,
		ResourceAdvanceConfig: config.ResourceAdvanceConfig{
			RecyclePolicy: config.RecyclePolicyDestroy,
		},
	}, 10)
	assert.NotNil(t, cgMgr)
	assert.Nil(t, err)

	mgr, err := NewManager("/tmp/mock", handlers, healthChan, cgMgr, 10)
	assert.NotNil(t, mgr)
	assert.Nil(t, err)

	go mgr.Start()

	assert.Nil(t, mgr.loadSandboxes())
}

func newTestSandboxes(hitId string, hitLabel map[string]string) []*Sandbox {
	var sandboxes []*Sandbox

	sandboxes = append(sandboxes, nil)
	sandboxes = append(sandboxes, &Sandbox{})
	sandboxes = append(sandboxes, &Sandbox{
		Metadata: &runtime.SandboxMetadata{ID: "test-1"},
	})

	if len(hitId) != 0 {
		sandboxes = append(sandboxes, &Sandbox{
			Metadata: &runtime.SandboxMetadata{ID: hitId},
		})
	}

	sandboxes = append(sandboxes, &Sandbox{
		Metadata: &runtime.SandboxMetadata{ID: "label-not-hit", Labels: hitLabel},
	})

	sandboxes = append(sandboxes, &Sandbox{
		Metadata: &runtime.SandboxMetadata{ID: "label-hit", Labels: map[string]string{
			"test-999": "666",
		}},
	})

	return sandboxes
}

func callFilter(sandboxes []*Sandbox, opt ListOption) []*Sandbox {
	var hitSandboxes []*Sandbox
	for _, c := range sandboxes {
		if opt(c) {
			hitSandboxes = append(hitSandboxes, c)
		}
	}
	return hitSandboxes
}

func TestListFilterById(t *testing.T) {
	hitId := "hitid"
	sandboxes := newTestSandboxes(hitId, nil)

	hitSandboxes := callFilter(sandboxes, ListFilterById(hitId))

	assert.Equal(t, 1, len(hitSandboxes))
	assert.Equal(t, hitSandboxes[0].Metadata.ID, hitId)
}

func TestListFilterByLabels(t *testing.T) {
	hitLabel := map[string]string{
		"hitKey": "hitValue",
	}
	sandboxes := newTestSandboxes("", hitLabel)

	hitSandboxes := callFilter(sandboxes, ListFilterByLabels(hitLabel))

	assert.Equal(t, 1, len(hitSandboxes))
	assert.Equal(t, hitSandboxes[0].Metadata.Labels["hitKey"], "hitValue")
}

func TestSandboxMetricsTargets(t *testing.T) {
	cpuQuota := int64(50_000)
	cpuPeriod := uint64(100_000)
	running := &Sandbox{
		Metadata: &runtime.SandboxMetadata{
			ID:             "sbox-running",
			RuntimeHandler: "runsc-class",
			MetricLabels: map[string]string{
				"tenantid":      "tenant-a",
				"sandbox_id":    "upstream-id",
				"runtime_class": "upstream-runtime",
			},
		},
		Status: &statusStorage{status: Status{StartedAt: "2026-07-10T00:00:00Z"}},
		Spec: &spec.Spec{
			Annotations: map[string]string{
				config.ResourceAnnotationKeyPrefix + config.ResourceNameCgroup: "/akernel/sbox-running",
			},
			Linux: &spec.Linux{Resources: &spec.LinuxResources{CPU: &spec.LinuxCPU{
				Quota:  &cpuQuota,
				Period: &cpuPeriod,
			}}},
		},
	}
	exited := &Sandbox{
		Metadata: &runtime.SandboxMetadata{ID: "sbox-exited", RuntimeHandler: "runsc"},
		Status: &statusStorage{status: Status{
			StartedAt:  "2026-07-10T00:00:00Z",
			FinishedAt: "2026-07-10T00:01:00Z",
		}},
		Spec: &spec.Spec{Linux: &spec.Linux{CgroupsPath: "/akernel/sbox-exited"}},
	}
	withoutCgroup := &Sandbox{
		Metadata: &runtime.SandboxMetadata{ID: "sbox-no-cgroup", RuntimeHandler: "runsc"},
		Status:   &statusStorage{status: Status{StartedAt: "2026-07-10T00:00:00Z"}},
		Spec:     &spec.Spec{},
	}

	m := &Manager{sandboxes: cmap.New[*Sandbox]()}
	m.sandboxes.Set(running.Metadata.ID, running)
	m.sandboxes.Set(exited.Metadata.ID, exited)
	m.sandboxes.Set(withoutCgroup.Metadata.ID, withoutCgroup)

	targets := m.SandboxMetricsTargets()
	if assert.Len(t, targets, 1) {
		target := targets[0]
		assert.Equal(t, "sbox-running", target.SandboxID)
		assert.Equal(t, "runsc-class", target.RuntimeClass)
		assert.Equal(t, "/akernel/sbox-running", target.CgroupPath)
		assert.Equal(t, 0.5, target.CPULimit)
		assert.Equal(t, "tenant-a", target.MetricLabels["tenantid"])
		assert.Equal(t, "sbox-running", target.MetricLabels["sandbox_id"])
		assert.Equal(t, "runsc-class", target.MetricLabels["runtime_class"])

		target.MetricLabels["tenantid"] = "mutated"
		assert.Equal(t, "tenant-a", running.Metadata.MetricLabels["tenantid"])
	}
}

func TestSandboxCPULimitFallsBackToShares(t *testing.T) {
	shares := uint64(1536)
	assert.Equal(t, 1.5, sandboxCPULimit(&spec.Spec{
		Linux: &spec.Linux{Resources: &spec.LinuxResources{CPU: &spec.LinuxCPU{Shares: &shares}}},
	}))
	assert.Zero(t, sandboxCPULimit(&spec.Spec{}))
}

func TestSandboxStoppedNotificationIncludesMetricLabels(t *testing.T) {
	t.Run("SetExit notifies after persisting terminal state", func(t *testing.T) {
		m, id := newWaitForExitManager(t, "sbox-exit")
		sb, ok := m.sandboxes.Get(id)
		assert.True(t, ok)
		sb.Metadata.MetricLabels = map[string]string{"tenantid": "tenant-a"}
		sb.Spec = &spec.Spec{Linux: &spec.Linux{CgroupsPath: "/akernel/" + id}}
		var got MetricsTarget
		m.OnSandboxStopped = func(target MetricsTarget) { got = target }

		assert.NoError(t, m.SetExit(id, 0, "2026-07-11T00:01:00Z", false))
		assert.Equal(t, sb.Metadata.ID, got.SandboxID)
		assert.Equal(t, "tenant-a", got.MetricLabels["tenantid"])
		assert.Equal(t, "2026-07-11T00:01:00Z", sb.Status.Get().FinishedAt)
	})

	t.Run("Delete notifies before metadata removal", func(t *testing.T) {
		m := &Manager{
			root:            t.TempDir(),
			recyclePath:     t.TempDir(),
			sandboxes:       cmap.New[*Sandbox](),
			monitorStopChan: cmap.New[chan struct{}](),
			exitNotifiers:   cmap.New[*exitNotifier](),
		}
		sb := &Sandbox{
			Metadata: &runtime.SandboxMetadata{
				ID:             "sbox-delete-metrics",
				RuntimeHandler: "runsc",
				MetricLabels:   map[string]string{"tenantid": "tenant-a"},
			},
			Status: &statusStorage{status: Status{StartedAt: "2026-07-11T00:00:00Z"}},
			Spec:   &spec.Spec{Linux: &spec.Linux{CgroupsPath: "/akernel/sbox-delete-metrics"}},
		}
		m.sandboxes.Set(sb.Metadata.ID, sb)
		var got MetricsTarget
		m.OnSandboxStopped = func(target MetricsTarget) { got = target }

		m.Delete(sb.Metadata.ID)
		assert.Equal(t, sb.Metadata.ID, got.SandboxID)
		assert.Equal(t, "tenant-a", got.MetricLabels["tenantid"])
		assert.False(t, m.sandboxes.Has(sb.Metadata.ID))
	})
}

func TestReserveIDValidatesCustomID(t *testing.T) {
	m := &Manager{
		sandboxes:     cmap.New[*Sandbox](),
		maxSandboxNum: 10,
		idGenerator:   util.NewUUIDGenerator(config.SandboxPrefix, nil),
	}

	id, err := m.ReserveID("sbox-custom")
	assert.NoError(t, err)
	assert.Equal(t, "sbox-custom", id)

	for _, invalidID := range []string{"sandbox-custom", "sboxcustom", "sbox-"} {
		_, err := m.ReserveID(invalidID)
		assert.ErrorIs(t, err, errord.ErrInvalidArgument, invalidID)
	}
}

func TestReserveIDIsAtomicForCustomID(t *testing.T) {
	m := &Manager{
		sandboxes:     cmap.New[*Sandbox](),
		maxSandboxNum: 10,
		idGenerator:   util.NewUUIDGenerator(config.SandboxPrefix, nil),
	}

	const callers = 16
	var wait sync.WaitGroup
	wait.Add(callers)
	successes := make(chan string, callers)
	for range callers {
		go func() {
			defer wait.Done()
			if id, err := m.ReserveID("sbox-concurrent"); err == nil {
				successes <- id
			}
		}()
	}
	wait.Wait()
	close(successes)

	assert.Equal(t, []string{"sbox-concurrent"}, collectStrings(successes))
}

func collectStrings(values <-chan string) []string {
	var result []string
	for value := range values {
		result = append(result, value)
	}
	return result
}

func TestStoreMetadata(t *testing.T) {
	m := &Manager{
		root:        t.TempDir(),
		recyclePath: t.TempDir(),
		sandboxes:   cmap.New[*Sandbox](),
	}

	metadata := &runtime.SandboxMetadata{
		ID:             "test-store-metadata-111111",
		RuntimeHandler: "runsc",
	}

	assert.NoError(t, m.StoreMetadata(metadata.ID, metadata))

	assert.Equal(t, 1, m.sandboxes.Count())
	assert.True(t, m.sandboxes.Has(metadata.ID))
}

func TestStoreMetadataReturnsPersistenceFailure(t *testing.T) {
	root := t.TempDir()
	m := &Manager{
		root:        root,
		recyclePath: t.TempDir(),
		sandboxes:   cmap.New[*Sandbox](),
	}
	assert.NoError(t, os.RemoveAll(root))
	assert.NoError(t, os.WriteFile(root, []byte("not a directory"), 0600))

	metadata := &runtime.SandboxMetadata{
		ID:             "sbox-store-failure",
		RuntimeHandler: "runsc",
	}
	assert.Error(t, m.StoreMetadata(metadata.ID, metadata))
	assert.False(t, m.sandboxes.Has(metadata.ID))
}

func TestLoadSandbox(t *testing.T) {
	m := &Manager{
		root:        t.TempDir(),
		recyclePath: t.TempDir(),
		sandboxes:   cmap.New[*Sandbox](),
	}
	// Test loading failed caused by file not-exist
	_, err := m.loadSandbox(t.TempDir())

	m1 := &Manager{
		root:        t.TempDir(),
		recyclePath: "/tmp/test-load-sandbox/non-exist",
		sandboxes:   cmap.New[*Sandbox](),
	}
	assert.Error(t, err)

	// Test loading failed(file not-exist) and recycle failed
	_, err = m1.loadSandbox(t.TempDir())
	assert.Error(t, err)
}

func TestStartMonitorGoroutine(t *testing.T) {
	sandboxes := cmap.New[*Sandbox]()
	// Contains "success" to mock success
	id := "success-start-monitor-test1"

	sb := &Sandbox{
		Metadata: &runtime.SandboxMetadata{ID: id, RuntimeHandler: "runsc"},
	}
	sandboxes.Set(id, sb)

	serviceHandler := cmap.New[svc.Handler]()
	r := svc.NewFakeRuntimeHandler()
	serviceHandler.Set("runsc", r)

	m := &Manager{
		root:            t.TempDir(),
		recyclePath:     t.TempDir(),
		sandboxes:       sandboxes,
		monitorStopChan: cmap.New[chan struct{}](),
		exitNotifiers:   cmap.New[*exitNotifier](),
		serviceHandler:  serviceHandler,
	}

	stop := make(chan struct{})

	m.startMonitorGoroutine(sb.Metadata, stop)
	m.Delete(id)

	select {
	case <-stop:
	case <-time.After(5 * time.Second):
		t.Error("start Monitor did not stop in time")
	}

}

func TestHousekeeping(t *testing.T) {
	healthChan := make(chan bool)

	m := &Manager{
		root:            t.TempDir(),
		recyclePath:     t.TempDir(),
		sandboxes:       cmap.New[*Sandbox](),
		serviceHandler:  cmap.New[svc.Handler](),
		monitorStopChan: cmap.New[chan struct{}](),
		healthChan:      healthChan,
	}

	go m.housekeeping()
	go m.housekeeping()

	// Only receive once, it will block here if housekeeping run twice
	<-healthChan
	assert.False(t, m.isHousekeepingRunning.Load())

	// Mock housekeeping is running
	m.isHousekeepingRunning.Store(true)
	m.housekeeping() // should return directly and not touch the isHousekeepingRunning
	assert.True(t, m.isHousekeepingRunning.Load())

}

func dirExists(path string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	return fi.IsDir()
}

// newWaitForExitManager builds a Manager and registers a Running sandbox with
// a fresh exit notifier, mirroring what startMonitorGoroutine would set up at
// runtime. Returned id can be passed to WaitForExit / SetExit / Delete.
func newWaitForExitManager(t *testing.T, id string) (*Manager, string) {
	t.Helper()
	root := t.TempDir()
	sandboxRoot := filepath.Join(root, id)
	if err := os.MkdirAll(sandboxRoot, 0o755); err != nil {
		t.Fatalf("mkdir sandbox root: %v", err)
	}
	statusPath := filepath.Join(sandboxRoot, config.SandboxStatusFile)
	storage, err := LoadStatus(sandboxRoot)
	if err != nil {
		t.Fatalf("init status: %v", err)
	}
	_ = statusPath

	m := &Manager{
		root:            root,
		recyclePath:     t.TempDir(),
		sandboxes:       cmap.New[*Sandbox](),
		monitorStopChan: cmap.New[chan struct{}](),
		exitNotifiers:   cmap.New[*exitNotifier](),
		stopChan:        make(chan struct{}),
	}
	m.sandboxes.Set(id, &Sandbox{
		Metadata: &runtime.SandboxMetadata{ID: id, RuntimeHandler: "runsc"},
		Status:   storage,
	})
	m.exitNotifiers.Set(id, newExitNotifier())
	return m, id
}

func TestWaitForExit_NotFound(t *testing.T) {
	m := &Manager{
		sandboxes:     cmap.New[*Sandbox](),
		exitNotifiers: cmap.New[*exitNotifier](),
		stopChan:      make(chan struct{}),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := m.WaitForExit(ctx, "no-such-id")
	assert.True(t, errors.Is(err, errord.ErrNotFound), "want ErrNotFound, got %v", err)
}

func TestWaitForExit_AlreadyExitedFastPath(t *testing.T) {
	m, id := newWaitForExitManager(t, "sbox-fastpath")
	// Mark sandbox as already exited without touching the notifier; the
	// fast path should detect FinishedAt and return immediately.
	c, _ := m.sandboxes.Get(id)
	assert.NoError(t, c.Status.UpdateSync(func(s Status) (Status, error) {
		s.FinishedAt = time.Now().Format(time.RFC3339Nano)
		s.ExitCode = 7
		return s, nil
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	s, err := m.WaitForExit(ctx, id)
	assert.NoError(t, err)
	assert.Equal(t, int32(7), s.ExitCode)
}

func TestWaitForExit_BroadcastsToManyWaiters(t *testing.T) {
	m, id := newWaitForExitManager(t, "sbox-broadcast")

	const N = 16
	var wg sync.WaitGroup
	results := make([]Status, N)
	errs := make([]error, N)
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func(i int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			results[i], errs[i] = m.WaitForExit(ctx, id)
		}(i)
	}

	// Give waiters time to enter the select.
	time.Sleep(50 * time.Millisecond)
	assert.NoError(t, m.SetExit(id, 42, time.Now().Format(time.RFC3339Nano), true))

	wg.Wait()
	for i := 0; i < N; i++ {
		assert.NoError(t, errs[i], "waiter %d", i)
		assert.Equal(t, int32(42), results[i].ExitCode, "waiter %d", i)
		assert.True(t, results[i].OOMKilled, "waiter %d should observe OOMKilled", i)
		assert.NotEmpty(t, results[i].FinishedAt, "waiter %d", i)
	}
}

func TestWaitForExit_CtxCancelDoesNotAffectOthers(t *testing.T) {
	m, id := newWaitForExitManager(t, "sbox-cancel")

	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancelDone := make(chan error, 1)
	go func() {
		_, err := m.WaitForExit(cancelledCtx, id)
		cancelDone <- err
	}()

	survivorDone := make(chan error, 1)
	survivorStatus := make(chan Status, 1)
	go func() {
		ctx, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		s, err := m.WaitForExit(ctx, id)
		survivorStatus <- s
		survivorDone <- err
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-cancelDone:
		assert.True(t, errors.Is(err, context.Canceled), "want Canceled, got %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled waiter did not return")
	}

	// Survivor must still be blocked. SetExit should release it.
	select {
	case <-survivorDone:
		t.Fatal("survivor woke up before SetExit")
	case <-time.After(20 * time.Millisecond):
	}

	assert.NoError(t, m.SetExit(id, 0, time.Now().Format(time.RFC3339Nano), false))
	select {
	case err := <-survivorDone:
		assert.NoError(t, err)
		s := <-survivorStatus
		assert.Equal(t, int32(0), s.ExitCode)
	case <-time.After(2 * time.Second):
		t.Fatal("survivor not woken by SetExit")
	}
}

func TestWaitForExit_DeleteWakesWaitersThenNotFound(t *testing.T) {
	m, id := newWaitForExitManager(t, "sbox-delete")

	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := m.WaitForExit(ctx, id)
		done <- err
	}()

	time.Sleep(50 * time.Millisecond)
	m.Delete(id)

	select {
	case err := <-done:
		// Either the waiter sees the closed notifier and returns the
		// (still-Running) status with no error, or the sandbox has
		// already been removed and it sees ErrNotFound. Both are
		// acceptable terminations; what matters is that it doesn't block.
		_ = err
	case <-time.After(2 * time.Second):
		t.Fatal("waiter did not wake up after Delete")
	}

	// Subsequent calls hit the not-found fast path because Delete removed
	// the sandbox from the manager.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := m.WaitForExit(ctx, id)
	assert.True(t, errors.Is(err, errord.ErrNotFound), "want ErrNotFound after Delete, got %v", err)
}

func TestWaitForExit_StopWakesWaiters(t *testing.T) {
	m, id := newWaitForExitManager(t, "sbox-stop")
	// cgroupMgr/networkMgr left nil — Stop tolerates missing pools.

	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := m.WaitForExit(ctx, id)
		done <- err
	}()

	time.Sleep(50 * time.Millisecond)
	m.Stop()

	select {
	case err := <-done:
		// After Stop the waiter should observe the closed notifier and
		// return the current (Running) status without error, or context
		// cancellation if its ctx was canceled by some other mechanism.
		// We only assert it does not block.
		_ = err
	case <-time.After(2 * time.Second):
		t.Fatal("waiter did not wake up after Stop")
	}
}

func TestCleanSandboxRoot(t *testing.T) {
	root := t.TempDir()
	id := "test-sandbox-id"

	m := &Manager{
		root: root,
	}

	rootPath := filepath.Join(root, id)
	err := os.Mkdir(rootPath, 0755)
	assert.NoError(t, err)

	m.CleanSandboxRoot(id)
	assert.False(t, dirExists(rootPath))
}

func TestCleanSandboxRootRejectsPathEscape(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "containers")
	outside := filepath.Join(parent, "outside")
	assert.NoError(t, os.MkdirAll(root, 0755))
	assert.NoError(t, os.MkdirAll(outside, 0755))

	m := &Manager{root: root}
	m.CleanSandboxRoot("../outside")

	assert.True(t, dirExists(outside))
}
