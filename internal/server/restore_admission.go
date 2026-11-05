// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"time"

	"github.com/inclusionAI/sandboxd/config"
	"google.golang.org/grpc/status"
)

func runscRestoreConcurrency(value int) (int, error) {
	if value < 0 || value > 1024 {
		return 0, fmt.Errorf("runsc restore_concurrency must be zero or between 1 and 1024")
	}
	return value, nil
}

// The permit spans the complete Start RPC, not just runsc's restore call.
// Acquire before reserving IDs or preparing images and private filestores.
func (h *sandboxService) acquireRestoreAdmission(ctx context.Context, runtimeName, checkpointDir string) (func(), error) {
	if runtimeName != config.RuntimeNameRunsc || checkpointDir == "" {
		return func() {}, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	limit, err := runscRestoreConcurrency(h.config.RuntimeConfig.Runsc.RestoreConcurrency)
	if err != nil {
		return nil, err
	}
	if limit == 0 {
		return func() {}, nil
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Minute)
		defer cancel()
	}
	h.restoreAdmissionMu.Lock()
	if h.restoreAdmissionSlots == nil {
		h.restoreAdmissionSlots = make(chan struct{}, limit)
	}
	slots := h.restoreAdmissionSlots
	h.restoreAdmissionMu.Unlock()
	select {
	case slots <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-slots
			return nil, err
		}
		return func() { <-slots }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (h *sandboxService) checkStartRuntimeAdmission(ctx context.Context, runtimeName, checkpointDir string) error {
	if runtimeName != config.RuntimeNameRunsc || checkpointDir == "" || h.sandboxManager == nil {
		return h.checkRuntimeAdmission(runtimeName)
	}
	if err := h.checkRuntime(runtimeName); err != nil {
		return err
	}
	// SDK deadlines already include queueing and backend readiness. Do not
	// reset them. Bound callers without a deadline to one minute as well.
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Minute)
		defer cancel()
	}
	if err := h.sandboxManager.WaitRuntimeHealth(ctx, runtimeName); err != nil {
		return status.FromContextError(err).Err()
	}
	return h.checkRuntimeAdmission(runtimeName)
}
