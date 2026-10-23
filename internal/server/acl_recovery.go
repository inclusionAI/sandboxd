// Copyright (c) 2026 Ant Group Corporation.
//
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"time"

	"github.com/inclusionAI/sandboxd/config"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
)

// Persisted sandbox status may still say Running after a host reboot. Query
// the runtime before restoring ACLs so dead instances do not require vanished
// TAP devices. Missing or ambiguous runtime state is not proof of termination:
// those records retain the strict active endpoint recovery path.
func (h *sandboxService) stoppedRunscForACLRecovery() (map[string]bool, error) {
	handler, ok := h.serviceHandler.Get(config.RuntimeNameRunsc)
	if !ok {
		return nil, fmt.Errorf("runsc handler is missing during network ACL recovery")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	states, err := handler.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("inspect runsc state during network ACL recovery: %w", err)
	}
	stopped := make(map[string]bool)
	for _, state := range states {
		if state != nil && state.Status == svc.SandboxStatusExited && state.InitProcessPid <= 0 {
			stopped[state.ID] = true
		}
	}
	return stopped, nil
}
