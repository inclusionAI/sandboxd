// Copyright (c) 2026 Ant Group Corporation.
//
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"context"
	"fmt"
	"time"

	"github.com/inclusionAI/sandboxd/config"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/sirupsen/logrus"
)

// reconcileStoppedRunscOrphans runs before RPC admission or monitor startup.
// A crash can leave a durable runsc record without readable sandbox metadata;
// loadSandboxes cannot include that record in the normal deletion lifecycle.
// The runtime owns its state directory and its deletion boundary. Never unlink
// state files directly or infer that a missing bundle proves a process is dead.
func (m *Manager) reconcileStoppedRunscOrphans() error {
	handler, ok := m.serviceHandler.Get(config.RuntimeNameRunsc)
	if !ok {
		return nil
	}
	m.runscRecoveryPending.Store(true)
	_, err := m.pollRuntime(config.RuntimeNameRunsc, handler, 10*time.Second)
	return err
}

// Called only inside runsc's single in-flight poll. A failed cleanup is retried
// on the next successful inventory, before runsc can be advertised again.
func (m *Manager) reconcileStoppedRunscStates(ctx context.Context, handler svc.Handler, states []*svc.State) error {
	for _, state := range states {
		if state == nil || !config.IsValidSandboxID(state.ID) || m.sandboxes.Has(state.ID) {
			continue
		}
		if state.Status != svc.SandboxStatusExited || state.InitProcessPid > 0 {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := handler.Delete(ctx, state.ID); err != nil {
			return fmt.Errorf("delete stopped orphan runsc sandbox %s: %w", state.ID, err)
		}
		logrus.Infof("retired stopped orphan runsc sandbox %s during startup recovery", state.ID)
	}
	return nil
}
