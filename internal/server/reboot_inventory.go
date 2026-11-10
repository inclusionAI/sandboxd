// Copyright (c) 2026 Ant Group Corporation.
//
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/inclusionAI/sandboxd/pkg/runtime/firecracker"
)

// RebootHandler is served only on the restricted local maintenance socket.
func (h *sandboxService) RebootHandler() http.Handler {
	if h.rebootGate == nil {
		return nil
	}
	return h.rebootGate.handler(h.rebootInventoryAvailable, h.rebootInventoryEmpty)
}

// Check eligibility before the controller pauses admission or cordons the node.
func (h *sandboxService) rebootInventoryAvailable() error {
	if !h.Healthy() || h.cgroupMgr == nil || h.sandboxManager == nil {
		return errors.New("sandbox recovery or cgroup inventory is unavailable")
	}
	runtimes := h.config.RuntimeConfig.RuntimeBinary
	if len(runtimes) == 0 {
		return errors.New("runtime inventory is unavailable")
	}
	for name := range runtimes {
		// An optional runtime may have served work before becoming
		// unavailable on a later daemon start.
		if !h.serviceHandler.Has(name) {
			return fmt.Errorf("runtime %s inventory unavailable: handler not loaded", name)
		}
		if err := h.sandboxManager.RuntimeHealthError(name); err != nil {
			return fmt.Errorf("runtime %s inventory unavailable: %w", name, err)
		}
	}
	if !h.cgroupMgr.SupportsWorkloadInventory() {
		return errors.New("reboot inventory requires a cgroup v2 hierarchy")
	}
	return nil
}

func (h *sandboxService) rebootInventoryEmpty(ctx context.Context) error {
	if err := h.rebootInventoryAvailable(); err != nil {
		return err
	}
	for name := range h.config.RuntimeConfig.RuntimeBinary {
		states, err := h.sandboxManager.InspectRuntimeInventory(ctx, name)
		if err != nil {
			return fmt.Errorf("runtime %s inventory unavailable: %w", name, err)
		}
		for _, state := range states {
			if state == nil || state.Status != svc.SandboxStatusExited {
				return fmt.Errorf("runtime %s still has live or unknown work", name)
			}
		}
	}
	for _, entry := range h.sandboxManager.List() {
		if entry == nil || entry.Status == nil || entry.Status.Get().State() != runtime.SandboxState_SANDBOX_STATE_EXITED {
			return errors.New("sandbox manager still has live or unknown work")
		}
	}
	// Firecracker can temporarily move a VMM outside its sandbox subtree.
	empty, err := h.cgroupMgr.WorkloadsEmpty(firecracker.CheckpointCgroupPath())
	if err != nil {
		return err
	}
	if !empty {
		return errors.New("sandbox cgroups still contain processes")
	}
	return ctx.Err()
}
