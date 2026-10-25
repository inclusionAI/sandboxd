// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"context"
	"errors"
	api "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"sync/atomic"
	"testing"
	"time"

	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/stretchr/testify/require"
)

type runtimePollFixture struct {
	svc.FakeRuntimeHandler
	list func(context.Context) ([]*svc.State, error)
}

func (h *runtimePollFixture) List(ctx context.Context) ([]*svc.State, error) { return h.list(ctx) }

func TestWaitRuntimeHealthRequiresSuccessfulPollWithoutChangingDeadline(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	m := &Manager{serviceHandler: cmap.New[svc.Handler]()}
	m.serviceHandler.Set("runsc", &runtimePollFixture{list: func(context.Context) ([]*svc.State, error) {
		if fail.Load() {
			return nil, errors.New("inventory unavailable")
		}
		return nil, nil
	}})
	m.collectRuntimeStates(time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	done := make(chan error, 1)
	go func() { done <- m.WaitRuntimeHealth(ctx, "runsc") }()
	fail.Store(false)
	select {
	case err := <-done:
		t.Fatalf("health reopened before a successful poll: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	require.Error(t, m.RuntimeHealthError("runsc"))
	m.collectRuntimeStates(time.Second)
	require.NoError(t, <-done)
	actual, _ := ctx.Deadline()
	require.Equal(t, deadline, actual)
	require.NoError(t, m.RuntimeHealthError("runsc"))
}

func TestWaitRuntimeHealthCancellationDoesNotReopenAdmission(t *testing.T) {
	m := &Manager{}
	m.runtimePollErrors.Store("runsc", errors.New("inventory unavailable"))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, m.WaitRuntimeHealth(ctx, "runsc"), context.DeadlineExceeded)
	require.Error(t, m.RuntimeHealthError("runsc"))
}

func TestRuntimePollTimeoutIsolatedAndRecovers(t *testing.T) {
	var slow atomic.Bool
	slow.Store(true)
	m := &Manager{serviceHandler: cmap.New[svc.Handler]()}
	m.serviceHandler.Set("runsc", &runtimePollFixture{list: func(ctx context.Context) ([]*svc.State, error) {
		if slow.Load() {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return nil, nil
	}})
	m.serviceHandler.Set("firecracker-pvm", &runtimePollFixture{list: func(context.Context) ([]*svc.State, error) { return []*svc.State{{ID: "pvm-running"}}, nil }})
	started := time.Now()
	states, polled := m.collectRuntimeStates(30 * time.Millisecond)
	require.Less(t, time.Since(started), time.Second)
	require.Contains(t, states, "pvm-running")
	require.True(t, polled["firecracker-pvm"])
	require.False(t, polled["runsc"])
	require.ErrorIs(t, m.RuntimeHealthError("runsc"), context.DeadlineExceeded)
	require.NoError(t, m.RuntimeHealthError("firecracker-pvm"))
	slow.Store(false)
	require.Eventually(t, func() bool { _, p := m.collectRuntimeStates(30 * time.Millisecond); return p["runsc"] }, time.Second, time.Millisecond)
	require.NoError(t, m.RuntimeHealthError("runsc"))
}

func TestRuntimePollIgnoringCancellationDoesNotAccumulate(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	var calls atomic.Int32
	m := &Manager{serviceHandler: cmap.New[svc.Handler]()}
	m.serviceHandler.Set("runsc", &runtimePollFixture{list: func(context.Context) ([]*svc.State, error) { calls.Add(1); <-release; return nil, nil }})
	for range 4 {
		_, p := m.collectRuntimeStates(20 * time.Millisecond)
		require.False(t, p["runsc"])
	}
	require.EqualValues(t, 1, calls.Load())
	require.Error(t, m.RuntimeHealthError("runsc"))
}

func TestRuntimeListFailureDoesNotCloseProcessReadiness(t *testing.T) {
	health := make(chan bool, 1)
	m := &Manager{root: t.TempDir(), recyclePath: t.TempDir(), sandboxes: cmap.New[*Sandbox](), serviceHandler: cmap.New[svc.Handler](), monitorStopChan: cmap.New[chan struct{}](), healthChan: health}
	m.serviceHandler.Set("runsc", &runtimePollFixture{list: func(context.Context) ([]*svc.State, error) { return nil, errors.New("runsc list timed out") }})
	m.serviceHandler.Set("firecracker-pvm", svc.NewFakeRuntimeHandler())
	// Unknown status and a temporarily unavailable root must not turn a
	// failed runtime inventory into deletion of its tracked sandbox.
	id := "sbox-retained"
	m.sandboxes.Set(id, &Sandbox{Metadata: &api.SandboxMetadata{ID: id, RuntimeHandler: "runsc"}, PATH: "/not-accessible", Status: nil})
	m.monitorStopChan.Set(id, make(chan struct{}))
	m.housekeeping()
	require.True(t, m.sandboxes.Has(id))
	require.True(t, <-health)
	require.Error(t, m.RuntimeHealthError("runsc"))
	require.NoError(t, m.RuntimeHealthError("firecracker-pvm"))
}

func TestSlowRuntimeListDoesNotCloseProcessReadiness(t *testing.T) {
	health := make(chan bool, 1)
	m := &Manager{root: t.TempDir(), recyclePath: t.TempDir(), sandboxes: cmap.New[*Sandbox](), serviceHandler: cmap.New[svc.Handler](), monitorStopChan: cmap.New[chan struct{}](), healthChan: health}
	// This exceeds the real five-second process-health threshold. An error
	// with no delay would also pass the old globally timed implementation.
	m.serviceHandler.Set("runsc", &runtimePollFixture{list: func(context.Context) ([]*svc.State, error) {
		time.Sleep(5100 * time.Millisecond)
		return nil, errors.New("slow runtime inventory")
	}})
	m.serviceHandler.Set("firecracker-pvm", svc.NewFakeRuntimeHandler())
	m.housekeeping()
	require.True(t, <-health)
	require.Error(t, m.RuntimeHealthError("runsc"))
	require.NoError(t, m.RuntimeHealthError("firecracker-pvm"))
}
