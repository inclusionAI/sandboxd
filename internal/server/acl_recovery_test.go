// Copyright (c) 2026 Ant Group Corporation.
//
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager/networkacl"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type aclRecoveryHandler struct {
	*svc.FakeRuntimeHandler
	states []*svc.State
	err    error
}

func (h *aclRecoveryHandler) List(ctx context.Context) ([]*svc.State, error) {
	if _, ok := ctx.Deadline(); !ok {
		return nil, errors.New("runtime inspection requires a deadline")
	}
	return h.states, h.err
}

func storeACLRecoverySandbox(t *testing.T, s *sandboxService, id string, validEndpoint bool) {
	t.Helper()
	root := filepath.Join(s.config.RootDir, "containers", id)
	require.NoError(t, os.MkdirAll(root, 0755))
	if validEndpoint {
		endpoint := networkmanager.NetResource{Interface: &net.Interface{Name: "tap.test", Index: 20}, Ip: net.ParseIP("10.88.1.20")}
		data, err := json.Marshal(map[string]any{"linux": map[string]any{"cgroupsPath": ""}, "annotations": map[string]string{config.ResourceAnnotationKeyPrefix + config.ResourceNameInterface: endpoint.ToString()}})
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(root, config.SandboxSpecFile), data, 0600))
	}
	require.NoError(t, s.sandboxManager.StoreMetadata(id, &runtime.SandboxMetadata{ID: id, RuntimeHandler: config.RuntimeNameRunsc}))
}

func TestACLRecoverySkipsProvenStoppedRunscWithRetainedMetadata(t *testing.T) {
	h := &aclRecoveryHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{config.RuntimeNameRunsc: h})
	defer s.sandboxManager.Stop()
	const id = "sbox-cold-stopped"
	storeACLRecoverySandbox(t, s, id, false)
	// Metadata's in-memory default is Running, but the kernel lost this runtime.
	h.states = []*svc.State{nil, {ID: id, Status: svc.SandboxStatusExited, InitProcessPid: -1}}
	bindings, err := s.activeACLBindings()
	require.NoError(t, err)
	require.Empty(t, bindings)
	_, err = s.sandboxManager.Get(id)
	require.NoError(t, err, "retain metadata for normal deletion")
}

func TestACLRecoveryRetainsStrictBindingsForLiveOrAmbiguousRunsc(t *testing.T) {
	for _, state := range []*svc.State{
		{Status: svc.SandboxStatusRunning, InitProcessPid: 123},
		{Status: svc.SandboxStatusCreated, InitProcessPid: 123},
		{Status: svc.SandboxStatusUnknown, InitProcessPid: -1},
		{Status: svc.SandboxStatusExited, InitProcessPid: 123},
		nil,
	} {
		name := "missing"
		if state != nil {
			name = string(state.Status)
		}
		t.Run(name, func(t *testing.T) {
			h := &aclRecoveryHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
			s := newTestService(t, map[string]svc.Handler{config.RuntimeNameRunsc: h})
			defer s.sandboxManager.Stop()
			const id = "sbox-retained-binding"
			storeACLRecoverySandbox(t, s, id, true)
			if state != nil {
				copy := *state
				copy.ID = id
				h.states = []*svc.State{&copy}
			}
			bindings, err := s.activeACLBindings()
			require.NoError(t, err)
			require.Equal(t, "tap.test", bindings[id].HostVeth)
		})
	}
}

func TestACLRecoveryRejectsActiveMetadataErrorsButRetainsUnknownOwnership(t *testing.T) {
	h := &aclRecoveryHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{config.RuntimeNameRunsc: h})
	defer s.sandboxManager.Stop()
	const id = "sbox-live-missing-network"
	storeACLRecoverySandbox(t, s, id, false)
	h.states = []*svc.State{{ID: id, Status: svc.SandboxStatusRunning, InitProcessPid: 123}}
	_, err := s.activeACLBindings()
	require.Error(t, err)
	failure := errors.New("runtime unavailable")
	h.err = failure
	bindings, err := s.activeACLBindings()
	require.NoError(t, err)
	require.Empty(t, bindings)
	require.True(t, s.runscACLRecoveryPending.Load())
	require.ErrorIs(t, s.sandboxManager.RuntimeHealthError("runsc"), failure)
	_, err = s.sandboxManager.Get(id)
	require.NoError(t, err)
}

func TestACLRecoveryInventoryFailureRetainsBindingAndBackendIsolation(t *testing.T) {
	failure := errors.New("temporary runsc inventory failure during ACL recovery")
	h := &aclRecoveryHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler(), err: failure}
	s := newTestService(t, map[string]svc.Handler{"runsc": h, "runc": svc.NewFakeRuntimeHandler()})
	defer s.sandboxManager.Stop()
	s.config.EnableNetworkACL = true
	const id = "sbox-retained-unknown-runsc"
	storeACLRecoverySandbox(t, s, id, true)
	require.NoError(t, s.checkRuntimeAdmission("runc"))
	bindings, err := s.activeACLBindings()
	require.NoError(t, err, "ACL startup must isolate unavailable runsc inventory")
	require.Equal(t, "tap.test", bindings[id].HostVeth)
	require.Error(t, s.checkRuntimeAdmission("runsc"))
	require.NoError(t, s.checkRuntimeAdmission("runc"))
	require.True(t, s.Healthy(), "one backend must not close process readiness")
	_, err = s.sandboxManager.Get(id)
	require.NoError(t, err, "unknown runtime state must retain metadata and leases")
}

func TestACLStartupQuarantinesUnknownRunscAndRetriesBeforeReopening(t *testing.T) {
	inventoryErr := errors.New("inventory unavailable")
	aclErr := errors.New("ACL restore unavailable")
	handler := &aclRecoveryHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler(), err: inventoryErr}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler, "runc": svc.NewFakeRuntimeHandler(), "kata": svc.NewFakeRuntimeHandler()})
	defer s.sandboxManager.Stop()
	s.config.EnableNetworkACL = true
	const runscID = "sbox-retained-runsc"
	const kataID = "sbox-retained-kata"
	storeACLRecoverySandbox(t, s, runscID, true)
	storeACLRecoverySandbox(t, s, kataID, true)
	require.NoError(t, s.sandboxManager.StoreMetadata(kataID, &runtime.SandboxMetadata{ID: kataID, RuntimeHandler: "kata"}))
	before, err := s.sandboxManager.CollectResourceByID(runscID)
	require.NoError(t, err)
	var failACL atomic.Bool
	var mu sync.Mutex
	var activeCalls, retainedCalls []map[string]bool
	restore := func(active map[string]networkacl.Binding, retained map[string]bool) error {
		mu.Lock()
		defer mu.Unlock()
		ids := make(map[string]bool)
		for id := range active {
			ids[id] = true
		}
		copyRetained := make(map[string]bool)
		for id, value := range retained {
			copyRetained[id] = value
		}
		activeCalls = append(activeCalls, ids)
		retainedCalls = append(retainedCalls, copyRetained)
		if failACL.Load() {
			return aclErr
		}
		return nil
	}
	require.NoError(t, s.restoreACLState(restore, nil), "real constructor's ACL initialization must survive inventory unavailability")
	require.True(t, s.runscACLRecoveryPending.Load())
	require.True(t, retainedCalls[0][runscID])
	require.True(t, activeCalls[0][kataID])
	listed, err := s.ListAvailableRuntimes(context.Background(), &runtime.ListAvailableRuntimesRequest{})
	require.NoError(t, err)
	require.Equal(t, []string{"kata", "runc"}, listed.RuntimeClasses)
	// A healthy inventory must not reopen admission if restoring its ACL fails.
	handler.err = nil
	handler.states = []*svc.State{{ID: runscID, Status: svc.SandboxStatusRunning, InitProcessPid: 123}}
	failACL.Store(true)
	require.Eventually(t, func() bool {
		_, err := s.sandboxManager.RuntimeInventory("runsc", time.Second)
		return errors.Is(err, aclErr)
	}, time.Second, time.Millisecond)
	require.True(t, s.runscACLRecoveryPending.Load())
	require.Error(t, s.checkRuntimeAdmission("runsc"))
	require.NoError(t, s.checkRuntimeAdmission("kata"))
	require.NoError(t, s.checkRuntimeAdmission("runc"))
	require.True(t, s.Healthy())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, s.sandboxManager.WaitRuntimeHealth(ctx, "runsc"), context.DeadlineExceeded)
	failACL.Store(false)
	require.Eventually(t, func() bool { _, err := s.sandboxManager.RuntimeInventory("runsc", time.Second); return err == nil }, time.Second, time.Millisecond)
	require.False(t, s.runscACLRecoveryPending.Load())
	require.NoError(t, s.checkRuntimeAdmission("runsc"))
	after, err := s.sandboxManager.CollectResourceByID(runscID)
	require.NoError(t, err)
	require.Equal(t, before, after, "uncertain inventory must not release interface/resource ownership")
	mu.Lock()
	require.GreaterOrEqual(t, len(activeCalls), 3)
	for index := 1; index < len(activeCalls); index++ {
		require.True(t, activeCalls[index][runscID])
		require.False(t, activeCalls[index][kataID], "runsc retry must not reapply another backend's policy")
		require.True(t, retainedCalls[index][kataID])
	}
	count := len(activeCalls)
	mu.Unlock()
	_, err = s.sandboxManager.RuntimeInventory("runsc", time.Second)
	require.NoError(t, err)
	mu.Lock()
	require.Len(t, activeCalls, count, "completed ACL recovery must not repeat on each healthy poll")
	mu.Unlock()
}

func TestACLStartupRetainsUnknownOwnersWithMissingEndpointMetadata(t *testing.T) {
	handler := &aclRecoveryHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler(), err: errors.New("inventory unavailable")}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler, "runc": svc.NewFakeRuntimeHandler()})
	defer s.sandboxManager.Stop()
	const id = "sbox-unknown-missing-endpoint"
	storeACLRecoverySandbox(t, s, id, false)
	var restores atomic.Int32
	require.NoError(t, s.restoreACLState(func(active map[string]networkacl.Binding, retained map[string]bool) error {
		first := restores.Add(1) == 1
		if len(active) != 0 || retained[id] != first {
			return errors.New("unexpected quarantine ownership during authoritative recovery")
		}
		return nil
	}, nil))
	require.Error(t, s.checkRuntimeAdmission("runsc"))
	require.NoError(t, s.checkRuntimeAdmission("runc"))
	_, err := s.sandboxManager.Get(id)
	require.NoError(t, err)
	// A recovered inventory that proves the instance stopped can retire the ACL
	// binding without needing that missing endpoint, retaining normal metadata.
	handler.err = nil
	handler.states = []*svc.State{{ID: id, Status: svc.SandboxStatusExited, InitProcessPid: -1}}
	require.Eventually(t, func() bool { _, err := s.sandboxManager.RuntimeInventory("runsc", time.Second); return err == nil }, time.Second, time.Millisecond)
	require.NoError(t, s.checkRuntimeAdmission("runsc"))
	_, err = s.sandboxManager.Get(id)
	require.NoError(t, err)
}

func TestACLStartupRetainsUntrackedOwnersUntilRuntimeInventoryRecovers(t *testing.T) {
	h := &aclRecoveryHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler(), err: errors.New("inventory unavailable")}
	s := newTestService(t, map[string]svc.Handler{"runsc": h, "runc": svc.NewFakeRuntimeHandler()})
	defer s.sandboxManager.Stop()
	const id = "sbox-untracked-acl-owner"
	var calls atomic.Int32
	restore := func(active map[string]networkacl.Binding, retained map[string]bool) error {
		first := calls.Add(1) == 1
		if len(active) != 0 || retained[id] != first {
			return errors.New("untracked ACL owner was not quarantined until confirmed recovery")
		}
		return nil
	}
	require.NoError(t, s.restoreACLState(restore, []string{id}))
	require.Error(t, s.checkRuntimeAdmission("runsc"))
	require.NoError(t, s.checkRuntimeAdmission("runc"))
	h.err = nil
	h.states = []*svc.State{{ID: id, Status: svc.SandboxStatusRunning, InitProcessPid: 123}}
	require.Eventually(t, func() bool {
		_, err := s.sandboxManager.RuntimeInventory("runsc", time.Second)
		return err != nil && strings.Contains(err.Error(), "without sandbox metadata")
	}, time.Second, time.Millisecond)
	require.EqualValues(t, 1, calls.Load(), "live untracked owners must not be orphan-cleaned")
	require.NoError(t, s.checkRuntimeAdmission("runc"))
	h.states = []*svc.State{{ID: id, Status: svc.SandboxStatusExited, InitProcessPid: -1}}
	require.Eventually(t, func() bool { _, err := s.sandboxManager.RuntimeInventory("runsc", time.Second); return err == nil }, time.Second, time.Millisecond)
	require.NoError(t, s.checkRuntimeAdmission("runsc"))
	require.EqualValues(t, 2, calls.Load())
}

func TestQuarantinedRunscPolicyUpdatesWaitForACLRecovery(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler(), "runc": svc.NewFakeRuntimeHandler()})
	defer s.sandboxManager.Stop()
	const id = "sbox-quarantined-policy"
	storeACLRecoverySandbox(t, s, id, true)
	s.aclMgr = &networkacl.Manager{}
	s.runscACLRecoveryPending.Store(true)
	_, err := s.SetNetworkPolicy(context.Background(), &runtime.SetNetworkPolicyRequest{SandboxID: id})
	require.Equal(t, codes.Unavailable, status.Code(err), "unverified policy must not be activated or replaced")
	require.NoError(t, s.checkRuntimeAdmission("runc"))
	s.runscACLRecoveryPending.Store(false)
	_, err = s.SetNetworkPolicy(context.Background(), &runtime.SetNetworkPolicyRequest{SandboxID: id})
	require.Equal(t, codes.NotFound, status.Code(err), "after recovery the normal ACL manager path must resume")
}
