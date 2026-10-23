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
	"testing"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
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

func TestACLRecoveryDoesNotIgnoreInspectionOrActiveMetadataErrors(t *testing.T) {
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
	_, err = s.activeACLBindings()
	require.ErrorIs(t, err, failure)
}
