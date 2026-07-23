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

package langrtmanager

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	api "github.com/inclusionAI/sandboxd/api/runtime/v1"
)

// mockMounter is a test ImageMounter that returns a fake path and tracks calls.
type mockMounter struct {
	mu          sync.Mutex
	mountCount  int
	umountCount int
	mountDelay  time.Duration
	mountErr    error
}

func (m *mockMounter) Mount(cfg RootfsConfig) (string, []string, error) {
	if m.mountDelay > 0 {
		time.Sleep(m.mountDelay)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.mountErr != nil {
		return "", nil, m.mountErr
	}
	m.mountCount++
	return fmt.Sprintf("/fake/rootfs/%s/%d", cfg.Path, m.mountCount), nil, nil
}

func (m *mockMounter) Umount(cfg RootfsConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.umountCount++
	return nil
}

func (m *mockMounter) MountCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mountCount
}

func (m *mockMounter) UmountCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.umountCount
}

func newTestStartRequest(id, path string) *api.StartRequest {
	return &api.StartRequest{
		SandboxID: id,
		Rootfs: &api.RootfsConfig{
			Type: api.RootfsSrcType_LOCAL,
			Source: &api.RootfsConfig_Path{
				Path: path,
			},
		},
		Runtime: "runsc",
		Command: []string{"/bin/sh"},
	}
}

func TestGetLangRuntime_NotFound(t *testing.T) {
	lm := NewLanguageRuntimeManager(&mockMounter{})
	lr := lm.GetLangRuntime("nonexistent")
	if lr != nil {
		t.Fatal("expected nil for nonexistent runtime")
	}
}

func TestAddAndGetLangRuntime(t *testing.T) {
	lm := NewLanguageRuntimeManager(&mockMounter{})

	fr := newTestStartRequest("rt-1", "/some/path")
	lr, err := lm.AddLangRuntime(fr, false)
	if err != nil {
		t.Fatalf("AddLangRuntime failed: %v", err)
	}
	if lr.ID != "rt-1" {
		t.Fatalf("expected ID rt-1, got %s", lr.ID)
	}

	got := lm.GetLangRuntime("rt-1")
	if got == nil {
		t.Fatal("expected to find runtime rt-1")
	}
	if got != lr {
		t.Fatal("expected same pointer")
	}
}

func TestAddLangRuntime_Duplicate(t *testing.T) {
	lm := NewLanguageRuntimeManager(&mockMounter{})

	fr := newTestStartRequest("rt-1", "/some/path")
	lr1, err := lm.AddLangRuntime(fr, false)
	if err != nil {
		t.Fatalf("first AddLangRuntime failed: %v", err)
	}

	lr2, err := lm.AddLangRuntime(fr, false)
	if err != nil {
		t.Fatalf("second AddLangRuntime failed: %v", err)
	}
	if lr1 != lr2 {
		t.Fatal("expected same runtime for duplicate add")
	}
}

func TestAddLangRuntime_SharedRootfs(t *testing.T) {
	mock := &mockMounter{}
	lm := NewLanguageRuntimeManager(mock)

	fr1 := newTestStartRequest("rt-1", "/shared/path")
	fr2 := newTestStartRequest("rt-2", "/shared/path")

	lr1, err := lm.AddLangRuntime(fr1, false)
	if err != nil {
		t.Fatalf("AddLangRuntime rt-1 failed: %v", err)
	}
	lr2, err := lm.AddLangRuntime(fr2, false)
	if err != nil {
		t.Fatalf("AddLangRuntime rt-2 failed: %v", err)
	}

	if lr1.RootFS != lr2.RootFS {
		t.Fatal("expected shared rootfs for same config")
	}
	if mock.MountCount() != 1 {
		t.Fatalf("expected 1 mount call, got %d", mock.MountCount())
	}
}

func TestList(t *testing.T) {
	lm := NewLanguageRuntimeManager(&mockMounter{})

	lm.AddLangRuntime(newTestStartRequest("rt-1", "/p1"), false)
	lm.AddLangRuntime(newTestStartRequest("rt-2", "/p2"), false)

	list := lm.List()
	if len(list) != 2 {
		t.Fatalf("expected 2 runtimes, got %d", len(list))
	}
}

func TestRootfsRefcountAndCleanup(t *testing.T) {
	mock := &mockMounter{}
	lm := NewLanguageRuntimeManager(mock)

	fr1 := newTestStartRequest("rt-1", "/shared")
	fr2 := newTestStartRequest("rt-2", "/shared")

	lr1, _ := lm.AddLangRuntime(fr1, true)
	lr2, _ := lm.AddLangRuntime(fr2, true)

	lr1.IncRef()
	lr2.IncRef()

	lr1.DecRef()
	if mock.UmountCount() != 0 {
		t.Fatal("rootfs should not be umounted while lr2 still references it")
	}

	lr2.DecRef()
	if mock.UmountCount() != 1 {
		t.Fatalf("expected 1 umount after all refs released, got %d", mock.UmountCount())
	}
}

func TestMountError(t *testing.T) {
	mock := &mockMounter{mountErr: fmt.Errorf("mount failed")}
	lm := NewLanguageRuntimeManager(mock)

	_, err := lm.AddLangRuntime(newTestStartRequest("rt-1", "/fail"), false)
	if err == nil {
		t.Fatal("expected error from AddLangRuntime with failing mounter")
	}

	if lm.GetLangRuntime("rt-1") != nil {
		t.Fatal("failed runtime should not be in map")
	}
}

// Scenario 1: N goroutines doing slow Add should NOT block concurrent Get for
// already-registered runtimes.
func TestScenario1_GetNotBlockedBySlowAdd(t *testing.T) {
	const (
		numAdders  = 256
		numGetters = 256
		mountDelay = 500 * time.Millisecond
	)

	mock := &mockMounter{mountDelay: mountDelay}
	lm := NewLanguageRuntimeManager(mock)

	// Pre-register some runtimes in parallel.
	const preRegistered = 32
	var setupWg sync.WaitGroup
	setupWg.Add(preRegistered)
	for i := 0; i < preRegistered; i++ {
		go func(idx int) {
			defer setupWg.Done()
			lm.AddLangRuntime(newTestStartRequest(fmt.Sprintf("existing-%d", idx), fmt.Sprintf("/existing/%d", idx)), false)
		}(i)
	}
	setupWg.Wait()

	// Launch slow adders: each creates a new runtime with a unique rootfs.
	var adderWg sync.WaitGroup
	adderWg.Add(numAdders)
	for i := 0; i < numAdders; i++ {
		go func(idx int) {
			defer adderWg.Done()
			lm.AddLangRuntime(newTestStartRequest(
				fmt.Sprintf("slow-%d", idx),
				fmt.Sprintf("/slow/%d", idx),
			), false)
		}(i)
	}

	// Wait a bit for adders to enter the slow mount path.
	time.Sleep(50 * time.Millisecond)

	// Launch getters concurrently: each reads an existing runtime.
	var getterWg sync.WaitGroup
	getterWg.Add(numGetters)
	var maxGetLatency atomic.Int64

	for i := 0; i < numGetters; i++ {
		go func(idx int) {
			defer getterWg.Done()
			id := fmt.Sprintf("existing-%d", idx%preRegistered)
			start := time.Now()
			lr := lm.GetLangRuntime(id)
			latency := time.Since(start)
			if lr == nil {
				t.Errorf("GetLangRuntime(%s) returned nil", id)
				return
			}
			// Track max latency.
			for {
				cur := maxGetLatency.Load()
				ns := int64(latency)
				if ns <= cur {
					break
				}
				if maxGetLatency.CompareAndSwap(cur, ns) {
					break
				}
			}
		}(i)
	}

	getterWg.Wait()

	maxLatency := time.Duration(maxGetLatency.Load())
	t.Logf("max Get latency: %v (mount delay: %v, adders: %d, getters: %d)", maxLatency, mountDelay, numAdders, numGetters)
	if maxLatency > 50*time.Millisecond {
		t.Fatalf("Get latency %v too high, Get is being blocked by slow Add", maxLatency)
	}

	adderWg.Wait()

	total := len(lm.List())
	expected := preRegistered + numAdders
	if total != expected {
		t.Fatalf("expected %d runtimes, got %d", expected, total)
	}
}

// Scenario 2: N goroutines adding runtimes with different rootfs configs should
// run in parallel, not be serialized by rfMu.
func TestScenario2_DifferentRootfsParallel(t *testing.T) {
	const (
		numAdders  = 256
		mountDelay = 200 * time.Millisecond
	)

	mock := &mockMounter{mountDelay: mountDelay}
	lm := NewLanguageRuntimeManager(mock)

	var wg sync.WaitGroup
	wg.Add(numAdders)

	start := time.Now()
	for i := 0; i < numAdders; i++ {
		go func(idx int) {
			defer wg.Done()
			id := fmt.Sprintf("rt-%d", idx)
			path := fmt.Sprintf("/path/%d", idx)
			if _, err := lm.AddLangRuntime(newTestStartRequest(id, path), false); err != nil {
				t.Errorf("AddLangRuntime %s failed: %v", id, err)
			}
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	// If fully serialized: numAdders * mountDelay = 256 * 200ms = 51.2s.
	// If parallel: ~mountDelay + scheduling overhead.
	// Allow generous headroom but must be far below serialized time.
	maxExpected := 3 * time.Second
	t.Logf("elapsed: %v (mount delay: %v, adders: %d, serial would be: %v)", elapsed, mountDelay, numAdders, time.Duration(numAdders)*mountDelay)
	if elapsed > maxExpected {
		t.Fatalf("concurrent adds took %v (> %v), not running in parallel", elapsed, maxExpected)
	}
	if mock.MountCount() != numAdders {
		t.Fatalf("expected %d mount calls, got %d", numAdders, mock.MountCount())
	}
	if len(lm.List()) != numAdders {
		t.Fatalf("expected %d runtimes, got %d", numAdders, len(lm.List()))
	}
}

// Scenario 3: N goroutines adding runtimes with the SAME rootfs config should
// share one rootfs and only trigger one mount (future/singleflight pattern).
func TestScenario3_SameRootfsSingleMount(t *testing.T) {
	const (
		numAdders  = 512
		mountDelay = 200 * time.Millisecond
	)

	mock := &mockMounter{mountDelay: mountDelay}
	lm := NewLanguageRuntimeManager(mock)

	var wg sync.WaitGroup
	wg.Add(numAdders)
	results := make([]*LanguageRuntime, numAdders)
	errs := make([]error, numAdders)

	start := time.Now()
	for i := 0; i < numAdders; i++ {
		go func(idx int) {
			defer wg.Done()
			id := fmt.Sprintf("rt-%d", idx)
			results[idx], errs[idx] = lm.AddLangRuntime(newTestStartRequest(id, "/shared/rootfs"), false)
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d failed: %v", i, err)
		}
	}

	// All runtimes should share the same RootFS pointer.
	sharedRootFS := results[0].RootFS
	for i := 1; i < numAdders; i++ {
		if results[i].RootFS != sharedRootFS {
			t.Fatalf("goroutine %d got different rootfs pointer", i)
		}
	}

	// Mount should only be called once (singleflight).
	if mock.MountCount() != 1 {
		t.Fatalf("expected 1 mount call, got %d", mock.MountCount())
	}

	// Should complete in roughly mountDelay, not numAdders * mountDelay.
	maxExpected := 2 * time.Second
	t.Logf("elapsed: %v (mount delay: %v, adders: %d)", elapsed, mountDelay, numAdders)
	if elapsed > maxExpected {
		t.Fatalf("took %v (> %v), singleflight not working", elapsed, maxExpected)
	}

	if len(lm.List()) != numAdders {
		t.Fatalf("expected %d runtimes, got %d", numAdders, len(lm.List()))
	}
}

// TestHighConcurrencyMixed runs a mixed workload of adds (with varied rootfs),
// gets, and lists concurrently at high parallelism to stress-test for races.
func TestHighConcurrencyMixed(t *testing.T) {
	const (
		preRegistered = 32
		numAdders     = 256
		numGetters    = 256
		numListers    = 64
	)

	mock := &mockMounter{mountDelay: 5 * time.Millisecond}
	lm := NewLanguageRuntimeManager(mock)

	for i := 0; i < preRegistered; i++ {
		lm.AddLangRuntime(newTestStartRequest(fmt.Sprintf("pre-%d", i), fmt.Sprintf("/pre/%d", i)), false)
	}

	var wg sync.WaitGroup
	var totalOps atomic.Int64

	// Adders: mix of unique rootfs, shared rootfs, and duplicate IDs.
	wg.Add(numAdders)
	for i := 0; i < numAdders; i++ {
		go func(idx int) {
			defer wg.Done()
			var id, path string
			switch {
			case idx%3 == 0:
				// Unique rootfs.
				id = fmt.Sprintf("unique-%d", idx)
				path = fmt.Sprintf("/unique/%d", idx)
			case idx%3 == 1:
				// Shared rootfs (8 buckets).
				bucket := idx % 8
				id = fmt.Sprintf("shared-%d", idx)
				path = fmt.Sprintf("/shared/%d", bucket)
			default:
				// Duplicate ID (race for same slot).
				slot := idx % 16
				id = fmt.Sprintf("dup-%d", slot)
				path = fmt.Sprintf("/dup/%d", slot)
			}
			lm.AddLangRuntime(newTestStartRequest(id, path), false)
			totalOps.Add(1)
		}(i)
	}

	// Getters: read pre-registered runtimes.
	wg.Add(numGetters)
	for i := 0; i < numGetters; i++ {
		go func(idx int) {
			defer wg.Done()
			lm.GetLangRuntime(fmt.Sprintf("pre-%d", idx%preRegistered))
			totalOps.Add(1)
		}(i)
	}

	// Listers.
	wg.Add(numListers)
	for i := 0; i < numListers; i++ {
		go func() {
			defer wg.Done()
			lm.List()
			totalOps.Add(1)
		}()
	}

	wg.Wait()

	expected := int64(numAdders + numGetters + numListers)
	if totalOps.Load() != expected {
		t.Fatalf("expected %d ops, got %d", expected, totalOps.Load())
	}
	t.Logf("completed %d ops (adders=%d, getters=%d, listers=%d), final runtimes=%d",
		totalOps.Load(), numAdders, numGetters, numListers, len(lm.List()))
}
