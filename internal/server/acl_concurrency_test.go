// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager/networkacl"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/inclusionAI/sandboxd/pkg/sandbox"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func recoveringACLService(t *testing.T, extra map[string]svc.Handler) (*sandboxService, *atomic.Int32) {
	t.Helper()
	runsc := &aclRecoveryHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler(), err: errors.New("inventory unavailable")}
	handlers := map[string]svc.Handler{config.RuntimeNameRunsc: runsc}
	for name, handler := range extra {
		handlers[name] = handler
	}
	s := newTestService(t, handlers)
	t.Cleanup(s.sandboxManager.Stop)
	s.aclMgr = &networkacl.Manager{}
	storeACLRecoverySandbox(t, s, "sbox-recovering-acl", true)
	calls := &atomic.Int32{}
	require.NoError(t, s.restoreACLState(func(context.Context, map[string]networkacl.Binding, map[string]bool) error {
		calls.Add(1)
		return nil
	}, nil))
	require.True(t, s.runscACLRecoveryPending.Load())
	runsc.err = nil
	return s, calls
}

func storeHealthyACLSandbox(t *testing.T, s *sandboxService, id string) {
	t.Helper()
	storeSandboxForDelete(t, s, id)
	current, err := s.sandboxManager.Get(id)
	require.NoError(t, err)
	metadata := proto.Clone(current.Metadata).(*runtime.SandboxMetadata)
	metadata.RuntimeHandler = config.RuntimeNameKata
	require.NoError(t, s.sandboxManager.StoreMetadata(id, metadata))
}

func TestACLRecoveryDoesNotWaitForSlowRuntimeDeletion(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	handler := &blockingDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler(), started: make(chan struct{}), release: release}
	s, calls := recoveringACLService(t, map[string]svc.Handler{config.RuntimeNameKata: handler})
	storeHealthyACLSandbox(t, s, "sbox-slow-healthy-delete")
	deleted := make(chan error, 1)
	go func() { deleted <- s.deleteSandbox(context.Background(), "sbox-slow-healthy-delete") }()
	select {
	case <-handler.started:
	case <-time.After(time.Second):
		t.Fatal("delete did not reach runtime")
	}
	recovered := make(chan error, 1)
	go func() {
		_, err := s.sandboxManager.RuntimeInventory(config.RuntimeNameRunsc, time.Second)
		recovered <- err
	}()
	select {
	case err := <-recovered:
		require.NoError(t, err)
		require.Equal(t, int32(2), calls.Load())
		require.False(t, s.runscACLRecoveryPending.Load())
	case <-time.After(200 * time.Millisecond):
		t.Error("runsc ACL recovery waited for another runtime's delete")
		unblock()
		require.NoError(t, <-recovered)
	}
	unblock()
	require.NoError(t, <-deleted)
}

func TestACLRecoveryDeadlineDoesNotBlockHealthyRequests(t *testing.T) {
	s, calls := recoveringACLService(t, map[string]svc.Handler{config.RuntimeNameKata: svc.NewFakeRuntimeHandler()})
	storeHealthyACLSandbox(t, s, "sbox-healthy-policy")
	s.aclRecoveryMu.RLock() // An in-flight ACL publication must finish first.
	var once sync.Once
	unblock := func() { once.Do(s.aclRecoveryMu.RUnlock) }
	t.Cleanup(unblock)
	_, err := s.sandboxManager.RuntimeInventory(config.RuntimeNameRunsc, 50*time.Millisecond)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	updated := make(chan error, 1)
	go func() {
		_, err := s.SetNetworkPolicy(context.Background(), &runtime.SetNetworkPolicyRequest{SandboxID: "sbox-healthy-policy"})
		updated <- err
	}()
	select {
	case err := <-updated:
		require.Equal(t, codes.NotFound, status.Code(err), "healthy request must reach the ACL manager")
	case <-time.After(200 * time.Millisecond):
		t.Error("expired recovery writer still blocked healthy requests")
		unblock()
		<-updated
	}
	require.Equal(t, int32(1), calls.Load(), "expired recovery must not restore ACL state")
	require.True(t, s.runscACLRecoveryPending.Load())
	unblock()
	require.Eventually(t, func() bool {
		_, err := s.sandboxManager.RuntimeInventory(config.RuntimeNameRunsc, time.Second)
		return err == nil
	}, time.Second, 5*time.Millisecond, "recovery must release its poll lane after cancellation")
}

func TestACLStartOwnerHandoffDoesNotQueueGlobalWriter(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{config.RuntimeNameKata: svc.NewFakeRuntimeHandler()})
	t.Cleanup(s.sandboxManager.Stop)
	// An unrelated policy update or ACL retirement may still hold a reader.
	// Starting and publishing another owner must not queue a global writer.
	s.aclRecoveryMu.RLock()
	var once sync.Once
	unblock := func() { once.Do(s.aclRecoveryMu.RUnlock) }
	t.Cleanup(unblock)
	done := make(chan error, 1)
	go func() {
		const id = "sbox-start-reader"
		s.beginACLStart(id)
		done <- s.storeStartMetadata(context.Background(), &runtime.SandboxMetadata{ID: id, RuntimeHandler: config.RuntimeNameKata}, true)
	}()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		unblock()
		<-done
		t.Fatal("starting owner handoff blocked behind an unrelated reader")
	}
	_, retained := s.aclStartingOwners.Load("sbox-start-reader")
	require.False(t, retained)
}

func TestACLStartPublicationSharesDeletionLock(t *testing.T) {
	s, _ := recoveringACLService(t, map[string]svc.Handler{config.RuntimeNameKata: svc.NewFakeRuntimeHandler()})
	const id = "sbox-start-publish"
	release, err := s.aclSandboxLocks.Acquire(context.Background(), id)
	require.NoError(t, err)
	var once sync.Once
	unblock := func() { once.Do(release) }
	t.Cleanup(unblock)
	s.beginACLStart(id)
	done := make(chan error, 1)
	go func() {
		done <- s.storeStartMetadata(context.Background(), &runtime.SandboxMetadata{ID: id, RuntimeHandler: config.RuntimeNameKata}, true)
	}()
	select {
	case err := <-done:
		t.Fatalf("publication crossed the sandbox lifecycle lock: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	_, err = s.sandboxManager.RuntimeInventory(config.RuntimeNameRunsc, time.Second)
	require.NoError(t, err, "waiting for publication must not stall recovery")
	_, retained := s.aclStartingOwners.Load(id)
	require.True(t, retained)
	unblock()
	require.NoError(t, <-done)
	_, err = s.sandboxManager.Get(id)
	require.NoError(t, err)
	_, retained = s.aclStartingOwners.Load(id)
	require.False(t, retained)
}

type blockingACLStatus struct {
	sandbox.StatusStorage
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *blockingACLStatus) Get() sandbox.Status {
	s.once.Do(func() { close(s.entered) })
	<-s.release
	return s.StatusStorage.Get()
}

func TestPolicyStatusCheckAndDeleteShareSandboxLifecycle(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	finishedDelete := make(chan struct{})
	close(finishedDelete)
	handler := &blockingDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler(), started: make(chan struct{}), release: finishedDelete}
	s := newTestService(t, map[string]svc.Handler{config.RuntimeNameRunsc: handler})
	t.Cleanup(s.sandboxManager.Stop)
	s.aclMgr = &networkacl.Manager{}
	const id = "sbox-policy-lifecycle"
	storeSandboxForDelete(t, s, id)
	current, err := s.sandboxManager.Get(id)
	require.NoError(t, err)
	gate := &blockingACLStatus{StatusStorage: current.Status, entered: make(chan struct{}), release: release}
	current.Status = gate
	updated := make(chan error, 1)
	go func() {
		_, err := s.SetNetworkPolicy(context.Background(), &runtime.SetNetworkPolicyRequest{SandboxID: id})
		updated <- err
	}()
	select {
	case <-gate.entered:
	case <-time.After(time.Second):
		t.Fatal("policy request did not check sandbox status")
	}
	deleted := make(chan error, 1)
	go func() { deleted <- s.deleteSandbox(context.Background(), id) }()
	select {
	case <-handler.started:
		t.Error("delete crossed the in-flight policy status check and can allow ID reuse")
	case <-time.After(50 * time.Millisecond):
	}
	unblock()
	require.Equal(t, codes.NotFound, status.Code(<-updated))
	require.NoError(t, <-deleted)
}
