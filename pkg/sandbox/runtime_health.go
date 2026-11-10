// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/inclusionAI/sandboxd/config"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/sirupsen/logrus"
)

var errRuntimePollBusy = errors.New("previous runtime list still running")

// RuntimeHealthError returns the last poll failure for one backend. A newly
// loaded handler remains eligible until its first failed poll; successful
// subsequent polls reopen it without restarting sandboxd.
func (m *Manager) RuntimeHealthError(name string) error {
	if err, ok := m.runtimePollErrors.Load(name); ok {
		return err.(error)
	}
	return nil
}

// WaitRuntimeHealth waits for a successful inventory poll without reopening
// runtime advertisement or treating unavailable inventory as an empty list.
// The caller owns the deadline; cancellation does not change backend health.
func (m *Manager) WaitRuntimeHealth(ctx context.Context, name string) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if m.RuntimeHealthError(name) == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// SetRuntimeReconciler registers backend-specific startup recovery in the same
// bounded, single-in-flight lane as inventory. Admission stays closed until the
// whole poll and recovery callback succeed. A nil callback removes the hook;
// only a subsequent successful poll can reopen admission.
func (m *Manager) SetRuntimeReconciler(name string, reconcile func(context.Context, []*svc.State) error) {
	if reconcile == nil {
		m.runtimeReconcilers.Delete(name)
		return
	}
	m.runtimeReconcilers.Store(name, reconcile)
	m.runtimePollErrors.LoadOrStore(name, fmt.Errorf("runtime recovery pending"))
}

// RuntimeInventory shares housekeeping's bounded poll lane and health state.
// Failure is never returned as a successful empty inventory.
func (m *Manager) RuntimeInventory(name string, timeout time.Duration) ([]*svc.State, error) {
	handler, ok := m.serviceHandler.Get(name)
	if !ok {
		err := fmt.Errorf("runtime handler %q is unavailable", name)
		m.runtimePollErrors.Store(name, err)
		return nil, err
	}
	result, err := m.pollRuntime(name, handler, timeout)
	if err != nil {
		m.runtimePollErrors.Store(name, err)
		logrus.WithError(err).Warnf("runtime %s reconciliation unavailable", name)
		return nil, err
	}
	m.runtimePollErrors.Delete(name)
	return result, nil
}

// InspectRuntimeInventory reads the inventory under the caller's deadline.
// A slow maintenance read cannot occupy the recovery and health poll lane.
func (m *Manager) InspectRuntimeInventory(ctx context.Context, name string) ([]*svc.State, error) {
	if err := m.RuntimeHealthError(name); err != nil {
		return nil, err
	}
	handler, ok := m.serviceHandler.Get(name)
	if !ok {
		return nil, fmt.Errorf("runtime handler %q is unavailable", name)
	}
	return pollRuntimeOnce(ctx, &m.maintenancePollBusy, name, handler.List)
}

func (m *Manager) collectRuntimeStates(timeout time.Duration) (map[string]*svc.State, map[string]bool) {
	states := make(map[string]*svc.State)
	polled := make(map[string]bool)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for name := range m.serviceHandler.Items() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := m.RuntimeInventory(name, timeout)
			if err != nil {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			polled[name] = true
			for _, state := range result {
				if state != nil {
					states[state.ID] = state
				}
			}
		}()
	}
	wg.Wait()
	return states, polled
}

func (m *Manager) pollRuntime(name string, handler svc.Handler, timeout time.Duration) ([]*svc.State, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return pollRuntimeOnce(ctx, &m.runtimePollBusy, name, func(ctx context.Context) ([]*svc.State, error) {
		states, err := handler.List(ctx)
		if err == nil && name == config.RuntimeNameRunsc && m.runscRecoveryPending.Load() {
			err = m.reconcileStoppedRunscStates(ctx, handler, states)
			if err == nil {
				err = ctx.Err()
				if err == nil {
					m.runscRecoveryPending.Store(false)
				}
			}
		}
		if err == nil {
			err = ctx.Err()
		}
		if err == nil {
			if reconcile, ok := m.runtimeReconcilers.Load(name); ok {
				err = reconcile.(func(context.Context, []*svc.State) error)(ctx, states)
			}
		}
		return states, err
	})
}

func pollRuntimeOnce(ctx context.Context, lane *sync.Map, name string, list func(context.Context) ([]*svc.State, error)) ([]*svc.State, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	value, _ := lane.LoadOrStore(name, &atomic.Bool{})
	busy := value.(*atomic.Bool)
	if !busy.CompareAndSwap(false, true) {
		return nil, errRuntimePollBusy
	}
	type result struct {
		states []*svc.State
		err    error
	}
	done := make(chan result, 1)
	go func() {
		defer busy.Store(false)
		states, err := list(ctx)
		done <- result{states, err}
	}()
	// The wrapper is bounded even when a handler ignores cancellation. At
	// most one such call per runtime in this lane survives into the next pass.
	select {
	case out := <-done:
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return out.states, out.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
