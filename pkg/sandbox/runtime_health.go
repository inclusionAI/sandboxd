// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/sirupsen/logrus"
)

// RuntimeHealthError returns the last poll failure for one backend. A newly
// loaded handler remains eligible until its first failed poll; successful
// subsequent polls reopen it without restarting sandboxd.
func (m *Manager) RuntimeHealthError(name string) error {
	if err, ok := m.runtimePollErrors.Load(name); ok {
		return err.(error)
	}
	return nil
}

func (m *Manager) collectRuntimeStates(timeout time.Duration) (map[string]*svc.State, map[string]bool) {
	states := make(map[string]*svc.State)
	polled := make(map[string]bool)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for name, handler := range m.serviceHandler.Items() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := m.pollRuntime(name, handler, timeout)
			if err != nil {
				m.runtimePollErrors.Store(name, err)
				logrus.WithError(err).Warnf("runtime %s reconciliation unavailable", name)
				return
			}
			m.runtimePollErrors.Delete(name)
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
	value, _ := m.runtimePollBusy.LoadOrStore(name, &atomic.Bool{})
	busy := value.(*atomic.Bool)
	if !busy.CompareAndSwap(false, true) {
		return nil, fmt.Errorf("previous runtime list still running")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	type result struct {
		states []*svc.State
		err    error
	}
	done := make(chan result, 1)
	go func() {
		defer busy.Store(false)
		states, err := handler.List(ctx)
		done <- result{states, err}
	}()
	// The wrapper is bounded even when a handler ignores cancellation. At
	// most one such call per runtime survives into the next pass.
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
