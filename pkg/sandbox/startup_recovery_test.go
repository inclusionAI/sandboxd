// Copyright (c) 2026 Ant Group Corporation.
//
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/config"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/stretchr/testify/require"
)

type orphanRecoveryHandler struct {
	states             []*svc.State
	listErr, deleteErr error
	deleted            []string
}

func (*orphanRecoveryHandler) Start(context.Context, svc.StartConfig) error   { return nil }
func (*orphanRecoveryHandler) Wait(context.Context, string) (svc.Exit, error) { return svc.Exit{}, nil }
func (h *orphanRecoveryHandler) List(ctx context.Context) ([]*svc.State, error) {
	return h.states, h.listErr
}
func (h *orphanRecoveryHandler) Delete(ctx context.Context, id string) error {
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("cleanup requires a deadline")
	}
	h.deleted = append(h.deleted, id)
	return h.deleteErr
}

func TestStartupRecoveryRetiresStoppedRunscWithMissingMetadata(t *testing.T) {
	root := t.TempDir()
	id := "sbox-interrupted-metadata"
	// The bundle survived, but its metadata rename did not survive the crash.
	require.NoError(t, os.MkdirAll(filepath.Join(root, "containers", id), 0755))
	h := &orphanRecoveryHandler{states: []*svc.State{{ID: id, Status: svc.SandboxStatusExited, InitProcessPid: -1}}}
	handlers := cmap.New[svc.Handler]()
	handlers.Set(config.RuntimeNameRunsc, h)
	m, err := NewManager(root, handlers, make(chan bool), nil, 10)
	require.NoError(t, err)
	defer m.Stop()
	require.Equal(t, []string{id}, h.deleted)
	require.Empty(t, m.List())
}

func TestStartupRecoveryPreservesTrackedLiveAmbiguousAndForeignRecords(t *testing.T) {
	h := &orphanRecoveryHandler{states: []*svc.State{
		nil,
		{ID: "sbox-tracked", Status: svc.SandboxStatusExited, InitProcessPid: -1},
		{ID: "sbox-live", Status: svc.SandboxStatusRunning, InitProcessPid: 100},
		{ID: "sbox-inconsistent", Status: svc.SandboxStatusExited, InitProcessPid: 100},
		{ID: "sbox-unknown", Status: svc.SandboxStatusUnknown, InitProcessPid: -1},
		{ID: "sbox-created", Status: svc.SandboxStatusCreated, InitProcessPid: -1},
		{ID: "../sbox-escape", Status: svc.SandboxStatusExited, InitProcessPid: -1},
		{ID: "foreign", Status: svc.SandboxStatusExited, InitProcessPid: -1},
	}}
	handlers := cmap.New[svc.Handler]()
	handlers.Set(config.RuntimeNameRunsc, h)
	m := &Manager{serviceHandler: handlers, sandboxes: cmap.New[*Sandbox]()}
	m.sandboxes.Set("sbox-tracked", &Sandbox{})
	require.NoError(t, m.reconcileStoppedRunscOrphans())
	require.Empty(t, h.deleted)
}

func TestStartupRecoveryIsolatesRuntimeFailuresAndRetries(t *testing.T) {
	for _, listFailure := range []bool{false, true} {
		t.Run(map[bool]string{false: "delete", true: "list"}[listFailure], func(t *testing.T) {
			h := &orphanRecoveryHandler{states: []*svc.State{{ID: "sbox-stopped", Status: svc.SandboxStatusExited, InitProcessPid: -1}}}
			failure := errors.New("runtime unavailable")
			if listFailure {
				h.listErr = failure
			} else {
				h.deleteErr = failure
			}
			handlers := cmap.New[svc.Handler]()
			handlers.Set(config.RuntimeNameRunsc, h)
			handlers.Set("runc", svc.NewFakeRuntimeHandler())
			m, err := NewManager(t.TempDir(), handlers, make(chan bool, 1), nil, 10)
			require.NoError(t, err, "runsc failure must not prevent other runtimes starting")
			defer m.Stop()
			require.ErrorIs(t, m.RuntimeHealthError("runsc"), failure)
			_, polled := m.collectRuntimeStates(time.Second)
			require.True(t, polled["runc"])
			require.False(t, polled["runsc"])
			require.NoError(t, m.RuntimeHealthError("runc"))
			// A successful List cannot reopen runsc while orphan Delete fails.
			h.listErr = nil
			h.deleteErr = failure
			_, polled = m.collectRuntimeStates(time.Second)
			require.False(t, polled["runsc"])
			require.ErrorIs(t, m.RuntimeHealthError("runsc"), failure)
			h.deleteErr = nil
			_, polled = m.collectRuntimeStates(time.Second)
			require.True(t, polled["runsc"])
			require.NoError(t, m.RuntimeHealthError("runsc"))
			require.Contains(t, h.deleted, "sbox-stopped")
		})
	}
}

// A non-cooperative Delete must not accumulate retries or reopen runsc when
// its late result arrives. The next bounded complete pass owns reopening.
type blockingOrphanRecovery struct {
	svc.FakeRuntimeHandler
	calls   atomic.Int32
	release chan struct{}
}

func (h *blockingOrphanRecovery) List(context.Context) ([]*svc.State, error) {
	return []*svc.State{{ID: "sbox-stopped", Status: svc.SandboxStatusExited, InitProcessPid: -1}}, nil
}
func (h *blockingOrphanRecovery) Delete(context.Context, string) error {
	if h.calls.Add(1) == 1 {
		<-h.release
	}
	return nil
}
func TestStartupRecoveryTimeoutUsesOnePollLane(t *testing.T) {
	handler := &blockingOrphanRecovery{release: make(chan struct{})}
	t.Cleanup(func() {
		select {
		case <-handler.release:
		default:
			close(handler.release)
		}
	})
	m := &Manager{serviceHandler: cmap.New[svc.Handler](), sandboxes: cmap.New[*Sandbox]()}
	m.serviceHandler.Set("runsc", handler)
	m.serviceHandler.Set("runc", svc.NewFakeRuntimeHandler())
	m.runscRecoveryPending.Store(true)
	_, polled := m.collectRuntimeStates(20 * time.Millisecond)
	require.True(t, polled["runc"])
	require.False(t, polled["runsc"])
	require.ErrorIs(t, m.RuntimeHealthError("runsc"), context.DeadlineExceeded)
	for range 3 {
		_, polled = m.collectRuntimeStates(20 * time.Millisecond)
		require.True(t, polled["runc"])
		require.False(t, polled["runsc"])
	}
	require.EqualValues(t, 1, handler.calls.Load())
	close(handler.release)
	require.Eventually(t, func() bool {
		_, polled := m.collectRuntimeStates(20 * time.Millisecond)
		return polled["runsc"]
	}, time.Second, time.Millisecond)
	require.NoError(t, m.RuntimeHealthError("runsc"))
	require.False(t, m.runscRecoveryPending.Load())
	require.EqualValues(t, 2, handler.calls.Load(), "late cleanup cannot reopen admission by itself")
	m.collectRuntimeStates(time.Second)
	require.EqualValues(t, 2, handler.calls.Load(), "completed startup recovery must not repeatedly delete")
}
