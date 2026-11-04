// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"time"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager/networkacl"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/sirupsen/logrus"
)

type aclRestoreFunc func(map[string]networkacl.Binding, map[string]bool) error

// A failed inventory is not evidence that retained instances stopped. Keep the
// unverified bindings/leases out of destructive ACL reconciliation and keep only
// runsc admission closed. Healthy backends still complete their strict restore.
func (h *sandboxService) initialACLBindings() (map[string]networkacl.Binding, map[string]bool, error) {
	var states []*svc.State
	unknown := false
	needsInventory := h.sandboxManager.RuntimeHealthError(config.RuntimeNameRunsc) != nil
	for _, current := range h.sandboxManager.List() {
		if current != nil && current.Metadata != nil && current.Metadata.RuntimeHandler == config.RuntimeNameRunsc {
			needsInventory = true
			break
		}
	}
	if needsInventory {
		var err error
		states, err = h.sandboxManager.RuntimeInventory(config.RuntimeNameRunsc, 10*time.Second)
		if err != nil {
			unknown = true
			h.runscACLRecoveryPending.Store(true)
			logrus.WithError(err).Warn("retaining unverified runsc ACL bindings; backend admission closed")
		}
	}
	return h.collectACLBindings(states, unknown, false)
}

func (h *sandboxService) activeACLBindings() (map[string]networkacl.Binding, error) {
	active, _, err := h.initialACLBindings()
	return active, err
}

func (h *sandboxService) restoreACLState(restore aclRestoreFunc, owners []string) error {
	active, retained, err := h.initialACLBindings()
	if err != nil {
		return err
	}
	untracked := make(map[string]bool)
	if h.runscACLRecoveryPending.Load() {
		for _, id := range owners {
			if _, known := active[id]; !known {
				retained[id] = true
				if _, err := h.sandboxManager.Get(id); err != nil {
					untracked[id] = true
				}
			}
		}
	}
	if err := restore(active, retained); err != nil {
		return err
	}
	if !h.runscACLRecoveryPending.Load() {
		return nil
	}
	h.sandboxManager.SetRuntimeReconciler(config.RuntimeNameRunsc, func(ctx context.Context, states []*svc.State) error {
		if !h.runscACLRecoveryPending.Load() {
			return nil
		}
		h.aclMu.Lock()
		defer h.aclMu.Unlock()
		if err := ctx.Err(); err != nil {
			return err
		}
		for _, state := range states {
			if state == nil || !untracked[state.ID] || (state.Status == svc.SandboxStatusExited && state.InitProcessPid <= 0) {
				continue
			}
			if _, err := h.sandboxManager.Get(state.ID); err != nil {
				return fmt.Errorf("runsc ACL owner %s still has unconfirmed runtime state without sandbox metadata", state.ID)
			}
		}
		// Only recover this backend. Other runtimes' already-restored policies
		// must not be regenerated or garbage-collected during a runsc retry.
		active, retained, err := h.collectACLBindings(states, false, true)
		if err != nil {
			return err
		}
		if err := restore(active, retained); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		h.runscACLRecoveryPending.Store(false)
		return nil
	})
	return nil
}

func (h *sandboxService) collectACLBindings(states []*svc.State, unknownRunsc, runscOnly bool) (map[string]networkacl.Binding, map[string]bool, error) {
	active := make(map[string]networkacl.Binding)
	retained := make(map[string]bool)
	stopped := make(map[string]bool)
	for _, state := range states {
		if state != nil && state.Status == svc.SandboxStatusExited && state.InitProcessPid <= 0 {
			stopped[state.ID] = true
		}
	}
	for _, current := range h.sandboxManager.List() {
		if current == nil || current.Metadata == nil || current.Metadata.RuntimeHandler == config.RuntimeNameRunc {
			continue
		}
		id := current.Metadata.ID
		runsc := current.Metadata.RuntimeHandler == config.RuntimeNameRunsc
		if runscOnly && !runsc {
			retained[id] = true
			continue
		}
		if runsc && unknownRunsc {
			retained[id] = true
		} else if runsc && stopped[id] {
			continue
		}
		binding, err := h.aclBinding(id)
		if err != nil {
			if retained[id] {
				// Missing/corrupt endpoint metadata does not authorize dropping
				// this unknown owner's persisted policy or interface lease.
				logrus.WithError(err).Warnf("retaining unresolved ACL ownership for %s", id)
				continue
			}
			return nil, nil, err
		}
		active[id] = binding
	}
	return active, retained, nil
}

func (h *sandboxService) aclBinding(id string) (networkacl.Binding, error) {
	resources, err := h.sandboxManager.CollectResourceByID(id)
	if err != nil {
		return networkacl.Binding{}, fmt.Errorf("collect network resource for sandbox %s: %w", id, err)
	}
	encoded, ok := resources.Resources[config.ResourceNameInterface]
	if !ok {
		return networkacl.Binding{}, fmt.Errorf("sandbox %s has no network resource", id)
	}
	network, err := networkmanager.NewNetResource(encoded)
	if err != nil {
		return networkacl.Binding{}, fmt.Errorf("decode network resource for sandbox %s: %w", id, err)
	}
	if network.Interface == nil || network.Interface.Name == "" {
		return networkacl.Binding{}, fmt.Errorf("sandbox %s network endpoint is missing", id)
	}
	return networkacl.Binding{SandboxID: id, IP: network.Ip, HostVeth: network.Interface.Name}, nil
}
