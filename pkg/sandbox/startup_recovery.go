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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	states, err := handler.List(ctx)
	cancel()
	if err != nil {
		return fmt.Errorf("list runsc state during startup recovery: %w", err)
	}
	for _, state := range states {
		if state == nil || !config.IsValidSandboxID(state.ID) || m.sandboxes.Has(state.ID) {
			continue
		}
		if state.Status != svc.SandboxStatusExited || state.InitProcessPid > 0 {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		err := handler.Delete(ctx, state.ID)
		cancel()
		if err != nil {
			return fmt.Errorf("delete stopped orphan runsc sandbox %s: %w", state.ID, err)
		}
		logrus.Infof("retired stopped orphan runsc sandbox %s during startup recovery", state.ID)
	}
	return nil
}
