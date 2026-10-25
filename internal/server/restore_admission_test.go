// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRestoreAdmissionBoundsWorkAndCancelledWaiterHasNoPermit(t *testing.T) {
	s := &sandboxService{}
	s.config.RuntimeConfig.Runsc.RestoreConcurrency = 1
	release, err := s.acquireRestoreAdmission(context.Background(), config.RuntimeNameRunsc, "/checkpoint")
	require.NoError(t, err)
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err = s.acquireRestoreAdmission(ctx, config.RuntimeNameRunsc, "/other")
	require.ErrorIs(t, err, context.DeadlineExceeded)
	// Cold starts and other runtimes do not consume the runsc restore slots.
	for _, request := range [][2]string{{config.RuntimeNameRunsc, ""}, {config.RuntimeNameRunc, "/checkpoint"}, {config.RuntimeNameFirecracker, "/checkpoint"}} {
		done, err := s.acquireRestoreAdmission(context.Background(), request[0], request[1])
		require.NoError(t, err)
		done()
	}
}

func TestRestoreAdmissionQueueDoesNotReserveIDOrPrepareFilesystem(t *testing.T) {
	handler := newCheckpointTestHandler()
	s := newTestService(t, map[string]svc.Handler{config.RuntimeNameRunsc: handler})
	s.config.RuntimeConfig.Runsc.RestoreConcurrency = 1
	release, err := s.acquireRestoreAdmission(context.Background(), config.RuntimeNameRunsc, "/held")
	require.NoError(t, err)
	defer release()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request := &runtime.StartRequest{
		SandboxID: "sbox-restore-queued", Runtime: config.RuntimeNameRunsc,
		Network:        "none",
		Rootfs:         &runtime.RootfsConfig{Type: runtime.RootfsSrcType_LOCAL, Source: &runtime.RootfsConfig_Path{Path: t.TempDir()}},
		CheckpointInfo: &runtime.CheckpointInfo{CheckpointDir: t.TempDir()},
	}
	require.NoError(t, os.WriteFile(filepath.Join(request.CheckpointInfo.CheckpointDir, "checkpoint.img"), []byte("saved"), 0600))
	done := make(chan error, 1)
	go func() { _, err := s.Start(ctx, request); done <- err }()
	select {
	case err := <-done:
		t.Fatalf("queued restore returned before cancellation: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	_, err = s.sandboxManager.ReserveID(request.SandboxID)
	require.NoError(t, err, "queueing must precede ID reservation")
	s.sandboxManager.ReleaseID(request.SandboxID)
	cancel()
	select {
	case err := <-done:
		require.Equal(t, codes.Canceled, status.Code(err))
	case <-time.After(time.Second):
		t.Fatal("cancelled restore did not leave the admission queue")
	}
	require.Empty(t, handler.restores)
}

func TestRestoreAdmissionDefaultLimit(t *testing.T) {
	s := &sandboxService{}
	for range 16 {
		release, err := s.acquireRestoreAdmission(context.Background(), config.RuntimeNameRunsc, "/checkpoint")
		require.NoError(t, err)
		defer release()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := s.acquireRestoreAdmission(ctx, config.RuntimeNameRunsc, "/checkpoint")
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestRestoreAdmissionReleasesCapacityAndPreservesDeadline(t *testing.T) {
	s := &sandboxService{}
	s.config.RuntimeConfig.Runsc.RestoreConcurrency = 1
	release, err := s.acquireRestoreAdmission(context.Background(), config.RuntimeNameRunsc, "/checkpoint")
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	entered := make(chan func(), 1)
	go func() {
		done, err := s.acquireRestoreAdmission(ctx, config.RuntimeNameRunsc, "/other")
		if err == nil {
			entered <- done
		}
	}()
	select {
	case <-entered:
		t.Fatal("second restore exceeded the configured concurrency")
	case <-time.After(30 * time.Millisecond):
	}
	release()
	select {
	case done := <-entered:
		done()
	case <-time.After(time.Second):
		t.Fatal("released restore slot was not reused")
	}
	actual, _ := ctx.Deadline()
	require.Equal(t, deadline, actual)
}

func TestRestoreAdmissionRejectsInvalidLimitAndAlreadyCancelledContext(t *testing.T) {
	for _, limit := range []int{-1, 1025} {
		s := &sandboxService{}
		s.config.RuntimeConfig.Runsc.RestoreConcurrency = limit
		_, err := s.acquireRestoreAdmission(context.Background(), config.RuntimeNameRunsc, "/checkpoint")
		require.Error(t, err)
	}
	s := &sandboxService{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := s.acquireRestoreAdmission(ctx, config.RuntimeNameRunsc, "/checkpoint")
	require.ErrorIs(t, err, context.Canceled)
}
