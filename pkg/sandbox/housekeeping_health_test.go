// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"errors"
	"testing"
	"time"

	api "github.com/inclusionAI/sandboxd/api/runtime/v1"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/stretchr/testify/require"
)

type housekeepingStatus struct {
	StatusStorage
	delay time.Duration
	err   error
}

func (s *housekeepingStatus) UpdateSync(UpdateFunc) error {
	time.Sleep(s.delay)
	return s.err
}

func TestHousekeepingReadinessReflectsCompletedReconciliation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		delay time.Duration
		err   error
		ready bool
	}{
		{name: "slow successful status persistence", delay: 5100 * time.Millisecond, ready: true},
		{name: "failed status persistence", err: errors.New("status disk unavailable"), ready: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			health := make(chan bool, 1)
			m := &Manager{root: t.TempDir(), recyclePath: t.TempDir(), sandboxes: cmap.New[*Sandbox](), serviceHandler: cmap.New[svc.Handler](), monitorStopChan: cmap.New[chan struct{}](), healthChan: health}
			m.serviceHandler.Set("firecracker-pvm", svc.NewFakeRuntimeHandler())
			const id = "sbox-checkpoint"
			status := &housekeepingStatus{delay: tc.delay, err: tc.err}
			m.sandboxes.Set(id, &Sandbox{Metadata: &api.SandboxMetadata{ID: id, RuntimeHandler: "firecracker-pvm"}, PATH: t.TempDir(), Status: status})
			m.monitorStopChan.Set(id, make(chan struct{}))
			m.housekeeping()
			require.Equal(t, tc.ready, <-health)
			require.True(t, m.sandboxes.Has(id))
			// The next completed successful pass reopens readiness after an I/O failure.
			status.delay = 0
			status.err = nil
			m.housekeeping()
			require.True(t, <-health)
		})
	}
}
