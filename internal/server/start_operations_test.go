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
	"testing"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/testregistry"
	imageapi "github.com/inclusionAI/sandboxd/pkg/imagemanager/api"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/oci"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func fenceContext() context.Context {
	return grpc.NewContextWithServerTransportStream(context.Background(), &startFailureStream{})
}

func TestDeleteStartKeyFencesRequestThatHasNotArrived(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{config.RuntimeNameRunc: svc.NewFakeRuntimeHandler()})
	for i := 0; i < 2; i++ {
		if _, err := s.Delete(fenceContext(), &runtime.DeleteRequest{StartKey: "late-attempt"}); err != nil {
			t.Fatal(err)
		}
	}
	_, err := s.Start(context.Background(), &runtime.StartRequest{StartKey: "late-attempt"})
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("late Start was not fenced: %v", err)
	}
}

func TestDeleteStartKeyCancelsBlockedOCIPreparation(t *testing.T) {
	checkBlockedStartCleanup(t, false)
}

func TestRestartInventoryFindsAndCancelsPendingStartByPhysicalID(t *testing.T) {
	checkBlockedStartCleanup(t, true)
}

func checkBlockedStartCleanup(t *testing.T, physical bool) {
	t.Helper()
	registry := testregistry.New(t, "manifest")
	manager, err := oci.NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { manager.Close() })
	worker, err := imageapi.NewHttpWorker(&imageapi.HttpWorkerConfig{OCIManager: manager})
	if err != nil {
		t.Fatal(err)
	}
	handler := &cancelStartHandler{Handler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{config.RuntimeNameRunc: handler})
	s.fsMgr = newFSManager(worker)
	startCtx, cancelStart := context.WithCancel(context.Background())
	defer cancelStart()
	done := make(chan error, 1)
	go func() {
		_, err := s.Start(startCtx, &runtime.StartRequest{StartKey: "blocked-attempt", Runtime: config.RuntimeNameRunc, Rootfs: &runtime.RootfsConfig{Type: runtime.RootfsSrcType_IMAGE, Source: &runtime.RootfsConfig_ImageUrl{ImageUrl: registry.ImageURL}}})
		done <- err
	}()
	select {
	case <-registry.Entered:
	case <-time.After(5 * time.Second):
		t.Fatal("download not reached")
	}
	deletion := &runtime.DeleteRequest{StartKey: "blocked-attempt"}
	if physical {
		// A restarted caller has lost the Start key. Its authoritative inventory
		// must still see the in-flight attempt before it commits a real sandbox.
		inventory, err := s.List(context.Background(), &runtime.ListSandboxesRequest{})
		if err != nil || len(inventory.Sandboxes) != 1 {
			t.Fatalf("pending Start is absent from recovery inventory: %v %v", inventory, err)
		}
		pending := inventory.Sandboxes[0]
		if pending.State != runtime.SandboxState_SANDBOX_STATE_UNKNOWN || pending.Labels[startKeyLabel] != "blocked-attempt" {
			t.Fatal(pending)
		}
		deletion = &runtime.DeleteRequest{ID: pending.ID}
	}
	if _, err := s.Delete(fenceContext(), deletion); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if status.Code(err) != codes.Canceled {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Start is still executing")
	}
	if handler.starts.Load() != 0 || len(s.fsMgr.rootfs.List()) != 0 || len(s.fsMgr.sandboxState) != 0 {
		t.Fatal("start or preparation ownership remains")
	}
	_, err = s.Start(context.Background(), &runtime.StartRequest{StartKey: "blocked-attempt"})
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("cancelled attempt was repeated: %v", err)
	}
}

func TestDeleteStartKeyWaitsForLateCompletionAndCanRetry(t *testing.T) {
	handler := &recordingDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	child, finish, err := s.beginStart(context.Background(), "slow-attempt")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(fenceContext(), 20*time.Millisecond)
	defer cancel()
	if _, err = s.Delete(ctx, &runtime.DeleteRequest{StartKey: "slow-attempt"}); status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("Delete overtook Start: %v", err)
	}
	if child.Err() != context.Canceled {
		t.Fatal("Start was not cancelled")
	}
	// Model a backend that completes after cancellation. Publication occurs before
	// the handler signals completion, so a retry must remove this late execution.
	const id = "sbox-late-completion"
	storeSandboxForDelete(t, s, id)
	current, err := s.sandboxManager.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	current.Metadata.Labels = map[string]string{startKeyLabel: "slow-attempt"}
	s.setStartSandbox("slow-attempt", id)
	finish()
	if _, err = s.Delete(fenceContext(), &runtime.DeleteRequest{StartKey: "slow-attempt"}); err != nil {
		t.Fatal(err)
	}
	if handler.calls != 1 || handler.sandboxID != id {
		t.Fatal("late runtime was not deleted")
	}
	if _, err = s.sandboxManager.Get(id); err == nil {
		t.Fatal("late metadata remains")
	}
}

func TestDeleteStartKeyRecoversGeneratedIdentityAfterRestart(t *testing.T) {
	handler := &recordingDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	const id = "sbox-recovered-start"
	storeSandboxForDelete(t, s, id)
	sandbox, err := s.sandboxManager.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	sandbox.Metadata.Labels = map[string]string{startKeyLabel: "recovered-attempt"}
	if err = s.sandboxManager.StoreMetadata(id, sandbox.Metadata); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Delete(fenceContext(), &runtime.DeleteRequest{StartKey: "recovered-attempt"}); err != nil {
		t.Fatal(err)
	}
	if handler.calls != 1 || handler.sandboxID != id {
		t.Fatal("recovered runtime remains")
	}
}

func TestDeleteStartKeyPreservesReusedPhysicalIdentity(t *testing.T) {
	handler := &recordingDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	_, finish, err := s.beginStart(context.Background(), "failed-attempt")
	if err != nil {
		t.Fatal(err)
	}
	const id = "sbox-reused"
	s.setStartSandbox("failed-attempt", id)
	finish()
	storeSandboxForDelete(t, s, id)
	_, err = s.Delete(fenceContext(), &runtime.DeleteRequest{StartKey: "failed-attempt"})
	if status.Code(err) != codes.FailedPrecondition || handler.calls != 0 {
		t.Fatalf("reused identity was not preserved: %v", err)
	}
}
