// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/physicalstate"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/inclusionAI/sandboxd/pkg/sandbox"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

const (
	physicalFactProbeTimeout     = 5 * time.Second
	physicalIntentCleanupTimeout = 20 * time.Second

	physicalReconcileReasonIntent         = "physical_intent_recovery"
	physicalReconcileReasonStartupRestore = "startup_restore_runtime_not_running"
	physicalReconcileReasonRestoreReplay  = "restore_replay_runtime_not_running"
)

func (h *sandboxService) runtimePhysicalFact(
	ctx context.Context,
	runtimeHandler,
	sandboxID string,
) (*svc.State, bool, error) {
	facts, err := h.runtimePhysicalFacts(ctx, runtimeHandler)
	if err != nil {
		return nil, false, fmt.Errorf("list runtime facts for sandbox %s: %w", sandboxID, err)
	}
	state, exists := facts[sandboxID]
	return state, exists, nil
}

func (h *sandboxService) runtimePhysicalFacts(
	ctx context.Context,
	runtimeHandler string,
) (map[string]*svc.State, error) {
	handler, ok := h.serviceHandler.Get(runtimeHandler)
	if !ok {
		return nil, fmt.Errorf("runtime handler %q is unavailable: %w",
			runtimeHandler, errord.ErrUnavailable)
	}
	probeCtx, cancel := context.WithTimeout(ctx, physicalFactProbeTimeout)
	defer cancel()
	states, err := handler.List(probeCtx)
	if err != nil {
		return nil, fmt.Errorf("list runtime handler %q: %w",
			runtimeHandler, errors.Join(err, errord.ErrUnavailable))
	}
	facts := make(map[string]*svc.State, len(states))
	for _, state := range states {
		if state != nil && state.ID != "" {
			facts[state.ID] = state
		}
	}
	return facts, nil
}

func (h *sandboxService) recoverPhysicalState(ctx context.Context) error {
	if err := h.fsMgr.Restore(h.sandboxManager.HasPhysicalRecord); err != nil {
		return fmt.Errorf("restore sandbox filesystem state: %w", err)
	}
	if err := h.reconcilePhysicalIntents(ctx); err != nil {
		return fmt.Errorf("reconcile sandbox physical intents: %w", err)
	}
	if err := h.reconcileCommittedRestores(ctx); err != nil {
		return fmt.Errorf("reconcile committed sandbox restores: %w", err)
	}
	if err := h.restoreSandboxNetworkFacts(); err != nil {
		return fmt.Errorf("restore sandbox network facts: %w", err)
	}
	return nil
}

func (h *sandboxService) reconcileCommittedRestores(ctx context.Context) error {
	records := h.sandboxManager.ListCommittedRestores()
	sort.Slice(records, func(i, j int) bool {
		if records[i].RuntimeHandler == records[j].RuntimeHandler {
			return records[i].ID < records[j].ID
		}
		return records[i].RuntimeHandler < records[j].RuntimeHandler
	})
	var runtimeHandler string
	var facts map[string]*svc.State
	for _, metadata := range records {
		if metadata.RuntimeHandler != runtimeHandler {
			var err error
			facts, err = h.runtimePhysicalFacts(ctx, metadata.RuntimeHandler)
			if err != nil {
				return err
			}
			runtimeHandler = metadata.RuntimeHandler
		}
		fact, exists := facts[metadata.ID]
		if exists && fact.Status == svc.SandboxStatusRunning {
			continue
		}
		if err := h.reconcilePhysicalRecord(
			ctx, metadata, exists, physicalReconcileReasonStartupRestore,
		); err != nil {
			return err
		}
	}
	return nil
}

// reconcilePhysicalIntents removes creation attempts that never reached the
// durable COMMITTED boundary. A successful Restore response is emitted only
// after COMMITTED, so retaining an INTENT can never be required for replay.
func (h *sandboxService) reconcilePhysicalIntents(ctx context.Context) error {
	intents := h.sandboxManager.ListPhysicalIntents()
	sort.Slice(intents, func(i, j int) bool {
		return intents[i].ID < intents[j].ID
	})
	for _, metadata := range intents {
		if err := h.reconcilePhysicalIntent(ctx, metadata); err != nil {
			return err
		}
	}
	return nil
}

func (h *sandboxService) reconcileRestoreRecord(
	ctx context.Context,
	request *runtime.StartRequest,
	expectedIdentity *physicalstate.RestoreIdentity,
) (bool, error) {
	if request == nil || request.SandboxID == "" {
		return false, nil
	}
	for _, metadata := range h.sandboxManager.ListPhysicalIntents() {
		if metadata.ID != request.SandboxID {
			continue
		}
		if expectedIdentity == nil || !proto.Equal(metadata.RestoreIdentity, expectedIdentity) {
			return false, fmt.Errorf(
				"sandbox %s restore identity conflicts with physical intent: %w",
				request.SandboxID,
				errord.ErrFailedPrecondition,
			)
		}
		return false, h.reconcilePhysicalIntent(ctx, metadata)
	}

	physical, err := h.sandboxManager.Get(request.SandboxID)
	if err != nil {
		if errors.Is(err, errord.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	if physical == nil || physical.Metadata == nil {
		return false, fmt.Errorf("sandbox %s physical metadata is incomplete: %w",
			request.SandboxID, errord.ErrFailedPrecondition)
	}
	metadata := physical.Metadata
	if metadata.PhysicalPhase != physicalstate.PhysicalPhase_PHYSICAL_PHASE_COMMITTED {
		return false, fmt.Errorf("sandbox %s physical record is not committed: %w",
			request.SandboxID, errord.ErrFailedPrecondition)
	}
	if expectedIdentity == nil || !proto.Equal(metadata.RestoreIdentity, expectedIdentity) {
		return false, fmt.Errorf("sandbox %s restore identity conflicts with committed record: %w",
			request.SandboxID, errord.ErrFailedPrecondition)
	}
	if metadata.RuntimeHandler != request.Runtime {
		return false, fmt.Errorf("sandbox %s runtime conflicts with committed restore record: %w",
			request.SandboxID, errord.ErrFailedPrecondition)
	}
	runtimeFact, exists, err := h.runtimePhysicalFact(ctx, metadata.RuntimeHandler, metadata.ID)
	if err != nil {
		return false, err
	}
	if exists && runtimeFact.Status == svc.SandboxStatusRunning {
		return true, nil
	}
	return false, h.reconcilePhysicalRecord(
		ctx, metadata, exists, physicalReconcileReasonRestoreReplay,
	)
}

func (h *sandboxService) reconcilePhysicalIntent(
	ctx context.Context,
	metadata *physicalstate.SandboxMetadata,
) error {
	if metadata == nil || metadata.ID == "" || metadata.RuntimeHandler == "" {
		return fmt.Errorf("physical intent metadata is incomplete: %w", errord.ErrFailedPrecondition)
	}
	_, runtimeExists, err := h.runtimePhysicalFact(ctx, metadata.RuntimeHandler, metadata.ID)
	if err != nil {
		return err
	}
	return h.reconcilePhysicalRecord(
		ctx, metadata, runtimeExists, physicalReconcileReasonIntent,
	)
}

func (h *sandboxService) reconcilePhysicalRecord(
	ctx context.Context,
	metadata *physicalstate.SandboxMetadata,
	runtimeExists bool,
	reason string,
) (resultErr error) {
	fields := logrus.Fields{
		"sandbox_id":      metadata.ID,
		"physical_phase":  metadata.PhysicalPhase.String(),
		"runtime_handler": metadata.RuntimeHandler,
		"runtime_exists":  runtimeExists,
		"reason":          reason,
	}
	entry := logrus.WithFields(fields)
	entry.Info("reconciling sandbox physical record")
	defer func() {
		if resultErr != nil {
			entry.WithError(resultErr).Error("failed to reconcile sandbox physical record")
		}
	}()
	actions := make([]string, 0, 7)
	handler, ok := h.serviceHandler.Get(metadata.RuntimeHandler)
	if !ok {
		return fmt.Errorf("runtime handler %q for physical record %s is unavailable: %w",
			metadata.RuntimeHandler, metadata.ID, errord.ErrUnavailable)
	}
	cleanupCtx, cancel := context.WithTimeout(ctx, physicalIntentCleanupTimeout)
	defer cancel()
	if runtimeExists {
		if err := handler.Delete(cleanupCtx, metadata.ID); err != nil &&
			!errors.Is(err, errord.ErrNotFound) {
			return fmt.Errorf("delete runtime for physical intent %s: %w", metadata.ID, err)
		}
		actions = append(actions, "runtime_delete")
	} else if metadata.RuntimeHandler == config.RuntimeNameRunsc {
		// Runsc Delete is deliberately idempotent: it removes both a runtime
		// when present and the private checkpoint coordination state left by a
		// pre-start restore crash. Other handlers are not required to accept an
		// absent-runtime Delete.
		if err := handler.Delete(cleanupCtx, metadata.ID); err != nil &&
			!errors.Is(err, errord.ErrNotFound) {
			return fmt.Errorf("cleanup absent runsc intent %s: %w", metadata.ID, err)
		}
		actions = append(actions, "runsc_private_state_cleanup")
	}
	if h.xpuMgr != nil {
		h.xpuMgr.Release(metadata.ID)
		actions = append(actions, "xpu_release")
	}
	if h.fsMgr != nil {
		if err := h.fsMgr.Release(metadata.ID); err != nil {
			return fmt.Errorf("release filesystem for physical intent %s: %w", metadata.ID, err)
		}
		actions = append(actions, "filesystem_release")
	}

	resources, err := h.physicalResources(metadata)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("collect resources for physical intent %s: %w", metadata.ID, err)
	}
	if cleanupErr := h.cleanupPhysicalDnatFacts(metadata, resources); cleanupErr != nil {
		return cleanupErr
	}
	if len(metadata.Ports) > 0 {
		actions = append(actions, "dnat_cleanup")
	}
	if h.networkMgr != nil {
		h.networkMgr.releaseDnatPorts(metadata.ID)
		actions = append(actions, "port_reservation_release")
	}
	if err == nil {
		if err := h.releaseStartResources(resources); err != nil {
			return fmt.Errorf("release resources for physical intent %s: %w", metadata.ID, err)
		}
		actions = append(actions, "resource_release")
	}

	h.sandboxManager.Delete(metadata.ID)
	actions = append(actions, "sandbox_record_delete")
	entry.WithField("actions", actions).Info("reconciled sandbox physical record")
	return nil
}

func (h *sandboxService) physicalResources(
	metadata *physicalstate.SandboxMetadata,
) (sandbox.OccupiedResource, error) {
	if metadata != nil && len(metadata.ResourceFacts) > 0 {
		resources := sandbox.OccupiedResource{
			ID:        metadata.ID,
			Resources: make(map[string]string, len(metadata.ResourceFacts)),
		}
		for name, value := range metadata.ResourceFacts {
			resources.Resources[name] = value
		}
		return resources, nil
	}
	return h.sandboxManager.CollectResourceByID(metadata.ID)
}

func (h *sandboxService) cleanupPhysicalDnatFacts(
	metadata *physicalstate.SandboxMetadata,
	resources sandbox.OccupiedResource,
) error {
	if h.networkMgr == nil || metadata == nil || len(metadata.Ports) == 0 {
		return nil
	}
	encoded, ok := resources.Resources[config.ResourceNameInterface]
	if !ok {
		return nil
	}
	network, err := networkmanager.NewNetResource(encoded)
	if err != nil {
		return fmt.Errorf("decode network resource for physical intent %s: %w",
			metadata.ID, err)
	}
	if network.Ip == nil {
		return fmt.Errorf("physical intent %s network IP is missing: %w",
			metadata.ID, errord.ErrFailedPrecondition)
	}
	if err := h.networkMgr.cleanupPersistedDnatRules(
		metadata.ID, metadata.Ports, network.Ip.String()); err != nil {
		return fmt.Errorf("cleanup DNAT facts for physical intent %s: %w", metadata.ID, err)
	}
	return nil
}

func (h *sandboxService) persistPhysicalResourceFacts(
	metadata *physicalstate.SandboxMetadata,
	facts map[string]string,
) error {
	if metadata == nil {
		return fmt.Errorf("physical metadata is required: %w", errord.ErrInvalidArgument)
	}
	metadata.ResourceFacts = make(map[string]string, len(facts))
	for name, value := range facts {
		metadata.ResourceFacts[name] = value
	}
	return h.sandboxManager.PersistMetadata(metadata.ID, metadata)
}
