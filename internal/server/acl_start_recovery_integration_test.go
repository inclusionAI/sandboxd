//go:build linux && networkacl_integration

// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager/networkacl"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/inclusionAI/sandboxd/pkg/store"
	"github.com/stretchr/testify/require"
)

type aclStartCall struct {
	config svc.StartConfig
	finish chan error
}

type aclStartHandler struct {
	*svc.FakeRuntimeHandler
	root          string
	started       chan aclStartCall
	deleteEntered chan struct{}
	deleteRelease chan struct{}
}

func (h *aclStartHandler) Delete(ctx context.Context, id string) error {
	if h.deleteEntered != nil {
		close(h.deleteEntered)
		select {
		case <-h.deleteRelease:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return h.FakeRuntimeHandler.Delete(ctx, id)
}

func (h *aclStartHandler) Start(ctx context.Context, cfg svc.StartConfig) error {
	root := filepath.Join(h.root, "containers", cfg.ID)
	if err := os.MkdirAll(root, 0755); err != nil {
		return err
	}
	spec, err := json.Marshal(map[string]any{"linux": map[string]any{"cgroupsPath": ""}, "annotations": cfg.Annotations})
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, config.SandboxSpecFile), spec, 0600); err != nil {
		return err
	}
	call := aclStartCall{config: cfg, finish: make(chan error, 1)}
	h.started <- call
	select {
	case err := <-call.finish:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

type aclStartFixture struct {
	service  *sandboxService
	handler  *aclStartHandler
	db       *store.BboltStoreImp
	ctx      context.Context
	wg       sync.WaitGroup
	restored chan map[string]bool
}

func newACLStartFixture(t *testing.T, backend string) *aclStartFixture {
	t.Helper()
	// The runtime handlers are controlled test doubles. Keep real interface,
	// ACL and metadata operations, without creating host cgroups for fake VMs.
	for _, name := range []string{config.RuntimeNameKata, config.RuntimeNameFirecracker} {
		original := config.RuntimeResources[name]
		config.RuntimeResources[name] = []string{config.ResourceNameInterface}
		t.Cleanup(func() { config.RuntimeResources[name] = original })
	}
	runsc := &aclRecoveryHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler(), err: errors.New("inventory unavailable")}
	handler := &aclStartHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler(), started: make(chan aclStartCall, 16)}
	s := newTestService(t, map[string]svc.Handler{config.RuntimeNameRunsc: runsc, config.RuntimeNameKata: handler, config.RuntimeNameFirecracker: handler})
	t.Cleanup(s.sandboxManager.Stop)
	handler.root = s.config.RootDir
	s.config.EnableNetworkACL = true
	db, err := store.Open(filepath.Join(t.TempDir(), "acl.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	iface, err := networkmanager.NewInterfaceManager(db, "10.251.0.1/16", 16, 0, config.NatBackendIptables)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, iface.ShutDown()) })
	s.interfaceMgr = iface
	s.networkMgr = newNetworkManager(iface, config.NatBackendIptables, false)
	s.aclMgr, err = networkacl.New(networkacl.Config{Backend: backend, BridgeIP: iface.BridgeIp, Store: db, DisableProxy: true})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.aclMgr.Close()) })
	ctx, cancel := context.WithCancel(context.Background())
	f := &aclStartFixture{service: s, handler: handler, db: db, ctx: ctx, restored: make(chan map[string]bool, 16)}
	t.Cleanup(func() {
		cancel()
		f.wg.Wait()
		for _, current := range s.sandboxManager.List() {
			require.NoError(t, s.deleteSandbox(context.Background(), current.Metadata.ID))
		}
	})
	_, err = s.sandboxManager.RuntimeInventory(config.RuntimeNameRunsc, time.Second)
	require.Error(t, err)
	require.NoError(t, s.restoreACLState(func(active map[string]networkacl.Binding, retained map[string]bool) error {
		if err := s.aclMgr.RestoreRetaining(active, retained); err != nil {
			return err
		}
		f.restored <- retained
		return nil
	}, s.aclMgr.OwnerIDs()))
	<-f.restored // Initial quarantine; subsequent calls are recovery attempts.
	require.True(t, s.runscACLRecoveryPending.Load())
	runsc.err = nil
	return f
}

func (f *aclStartFixture) start(t *testing.T, id, runtimeName string) (aclStartCall, <-chan error) {
	t.Helper()
	request := &runtime.StartRequest{
		SandboxID: id, Runtime: runtimeName,
		Rootfs:        &runtime.RootfsConfig{Type: runtime.RootfsSrcType_LOCAL, Source: &runtime.RootfsConfig_Path{Path: t.TempDir()}},
		NetworkPolicy: &runtime.NetworkPolicy{Traffic: &runtime.TrafficPolicy{DefaultAction: runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_DENY}},
	}
	done := make(chan error, 1)
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		_, err := f.service.Start(f.ctx, request)
		done <- err
	}()
	select {
	case call := <-f.handler.started:
		require.Equal(t, id, call.config.ID)
		return call, done
	case err := <-done:
		t.Fatalf("Start failed before reaching runtime: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("Start did not reach runtime")
	}
	return aclStartCall{}, nil
}

func TestIntegrationACLRecoveryDuringOverlappingStarts(t *testing.T) {
	for _, backend := range []string{config.NatBackendIptables, config.NatBackendBpfnat} {
		t.Run(backend, func(t *testing.T) {
			f := newACLStartFixture(t, backend)
			call, done := f.start(t, "sbox-start-0", config.RuntimeNameKata)
			before, err := f.db.LoadRecords("networkACLEntries.v1")
			require.NoError(t, err)
			recovered := make(chan error, 1)
			go func() {
				_, err := f.service.sandboxManager.RuntimeInventory(config.RuntimeNameRunsc, 3*time.Second)
				recovered <- err
			}()
			// Each next start reaches its runtime before its predecessor finishes.
			// There is no interval without an in-flight startup during recovery.
			for i := 1; i <= 4; i++ {
				name := config.RuntimeNameKata
				if i%2 != 0 {
					name = config.RuntimeNameFirecracker
				}
				next, nextDone := f.start(t, fmt.Sprintf("sbox-start-%d", i), name)
				call.finish <- nil
				require.NoError(t, <-done)
				call, done = next, nextDone
			}
			require.NoError(t, <-recovered, "recovery must complete while healthy runtime startup is still in flight")
			require.False(t, f.service.runscACLRecoveryPending.Load())
			require.NoError(t, f.service.checkRuntimeAdmission(config.RuntimeNameRunsc))
			after, err := f.db.LoadRecords("networkACLEntries.v1")
			require.NoError(t, err)
			require.Len(t, after, 5, "recovery must preserve unpublished owners")
			require.Equal(t, before["sbox-start-0"], after["sbox-start-0"], "healthy policy incarnation and generation must be preserved")
			require.Len(t, f.service.aclMgr.OwnerIDs(), 5)
			_, err = f.service.sandboxManager.Get(call.config.ID)
			require.Error(t, err, "last runtime has not published metadata yet")
			call.finish <- nil
			require.NoError(t, <-done)
			for _, current := range f.service.sandboxManager.List() {
				require.NoError(t, f.service.deleteSandbox(context.Background(), current.Metadata.ID))
			}
			<-f.restored
			f.service.runscACLRecoveryPending.Store(true)
			_, err = f.service.sandboxManager.RuntimeInventory(config.RuntimeNameRunsc, time.Second)
			require.NoError(t, err)
			require.Empty(t, <-f.restored, "published and deleted starts must not leave retained owners")
		})
	}
}

func TestIntegrationACLRecoveryAfterFailedStart(t *testing.T) {
	for _, stage := range []string{"runtime", "metadata"} {
		t.Run(stage, func(t *testing.T) {
			f := newACLStartFixture(t, config.NatBackendIptables)
			const id = "sbox-start-failed"
			call, done := f.start(t, id, config.RuntimeNameKata)
			_, err := f.service.sandboxManager.RuntimeInventory(config.RuntimeNameRunsc, time.Second)
			require.NoError(t, err)
			require.True(t, (<-f.restored)[id], "recovery must retain the unpublished owner")
			if stage == "metadata" {
				// Force metadata publication to fail after the runtime has started.
				require.NoError(t, os.Mkdir(filepath.Join(f.service.config.RootDir, "containers", id, config.SandboxMetaFile), 0700))
				f.handler.deleteEntered = make(chan struct{})
				f.handler.deleteRelease = make(chan struct{})
				var releaseOnce sync.Once
				release := func() { releaseOnce.Do(func() { close(f.handler.deleteRelease) }) }
				t.Cleanup(release)
				call.finish <- nil
				select {
				case <-f.handler.deleteEntered:
				case <-time.After(time.Second):
					t.Fatal("failed publication did not roll back the runtime")
				}
				f.service.runscACLRecoveryPending.Store(true)
				_, err = f.service.sandboxManager.RuntimeInventory(config.RuntimeNameRunsc, time.Second)
				require.NoError(t, err, "slow rollback must not block recovery")
				require.True(t, (<-f.restored)[id], "rollback must retain its owner until cleanup finishes")
				release()
			} else {
				call.finish <- errors.New("injected runtime startup failure")
			}
			require.Error(t, <-done)
			f.handler.deleteEntered = nil
			require.Empty(t, f.service.aclMgr.OwnerIDs())
			f.service.runscACLRecoveryPending.Store(true)
			_, err = f.service.sandboxManager.RuntimeInventory(config.RuntimeNameRunsc, time.Second)
			require.NoError(t, err)
			require.Empty(t, <-f.restored, "rollback must release its retained owner")
			// The same ID can be used again once the failed attempt has retired.
			call, done = f.start(t, id, config.RuntimeNameKata)
			call.finish <- nil
			require.NoError(t, <-done)
		})
	}
}
