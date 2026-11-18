// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestFirecrackerCaptureWaiterRetainsPendingWorker(t *testing.T) {
	for _, cause := range []string{"caller_cancel", "operation_deadline"} {
		t.Run(cause, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			request := &runtime.CheckpointRequest{ID: "sbox-owned", TimeoutSeconds: 1}
			started, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var owned atomic.Bool
			returned := make(chan error, 1)
			go func() {
				_, err := waitForFirecrackerCapture(ctx, request, func(ctx context.Context, ownedRequest *runtime.CheckpointRequest) (*runtime.CheckpointResponse, error) {
					owned.Store(true)
					close(started)
					<-release // Model the VMM's uninterruptible native write.
					if ownedRequest.ID != "sbox-owned" {
						t.Error("worker request changed after RPC return")
					}
					owned.Store(false)
					close(finished)
					return nil, ctx.Err()
				})
				returned <- err
			}()
			<-started
			want := codes.DeadlineExceeded
			if cause == "caller_cancel" {
				cancel()
				want = codes.Canceled
			}
			select {
			case err := <-returned:
				if status.Code(err) != want {
					t.Errorf("error = %v, want %v", err, want)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("RPC waiter did not honor its deadline")
			}
			if !owned.Load() {
				t.Error("pending physical operation lost ownership on caller return")
			}
			request.ID = "sbox-reused-request"
			close(release)
			select {
			case <-finished:
			case <-time.After(5 * time.Second):
				t.Fatal("worker did not drain")
			}
		})
	}
}
