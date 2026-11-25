// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package firecracker

import (
	"context"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestSnapshotCancellationKeepsChargeUntilNativeReply(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "vmm.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	started, release := make(chan struct{}), make(chan struct{})
	var returnedToSandbox atomic.Bool
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		// A real VMM does not stop its memory write when the HTTP peer leaves.
		<-release
		w.WriteHeader(http.StatusNoContent)
	})}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- withFirecrackerProcessInCheckpointCgroup(
			"/sandbox/owned", 42,
			func() error { return newFirecrackerAPI(socket).createSnapshot(ctx, "state", "memory", "", "Full") },
			func(group string, _ int) error {
				if group == "/sandbox/owned" {
					returnedToSandbox.Store(true)
				}
				return nil
			},
			func() error { t.Error("cancellation must not terminate the source"); return nil },
		)
	}()
	<-started
	cancel()
	var early error
	earlyReturn := false
	select {
	case early = <-result:
		earlyReturn = true
	case <-time.After(50 * time.Millisecond):
	}
	if returnedToSandbox.Load() {
		t.Error("VMM moved back while the native snapshot was still writing")
	}
	if earlyReturn {
		t.Error("snapshot returned before the native action settled")
	}
	close(release)
	if !earlyReturn {
		select {
		case early = <-result:
		case <-time.After(5 * time.Second):
			t.Fatal("native completion did not release the operation")
		}
	}
	if !errors.Is(early, context.Canceled) {
		t.Fatalf("error = %v, want cancellation after native completion", early)
	}
	if !returnedToSandbox.Load() {
		t.Error("VMM did not return after native completion")
	}
}

func TestSnapshotAlreadyCanceledDoesNotDispatch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := newFirecrackerAPI(filepath.Join(t.TempDir(), "missing.sock")).createSnapshot(ctx, "state", "memory", "", "Full")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want cancellation without dispatch", err)
	}
}
