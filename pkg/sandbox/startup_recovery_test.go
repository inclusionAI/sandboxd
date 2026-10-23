// Copyright (c) 2026 Ant Group Corporation.
//
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/inclusionAI/sandboxd/config"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/stretchr/testify/require"
)

type orphanRecoveryHandler struct {
	states             []*svc.State
	listErr, deleteErr error
	deleted            []string
}

func (*orphanRecoveryHandler) Start(context.Context, svc.StartConfig) error   { return nil }
func (*orphanRecoveryHandler) Wait(context.Context, string) (svc.Exit, error) { return svc.Exit{}, nil }
func (h *orphanRecoveryHandler) List(ctx context.Context) ([]*svc.State, error) {
	return h.states, h.listErr
}
func (h *orphanRecoveryHandler) Delete(ctx context.Context, id string) error {
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("cleanup requires a deadline")
	}
	h.deleted = append(h.deleted, id)
	return h.deleteErr
}

func TestStartupRecoveryRetiresStoppedRunscWithMissingMetadata(t *testing.T) {
	root := t.TempDir()
	id := "sbox-interrupted-metadata"
	// The bundle survived, but its metadata rename did not survive the crash.
	require.NoError(t, os.MkdirAll(filepath.Join(root, "containers", id), 0755))
	h := &orphanRecoveryHandler{states: []*svc.State{{ID: id, Status: svc.SandboxStatusExited, InitProcessPid: -1}}}
	handlers := cmap.New[svc.Handler]()
	handlers.Set(config.RuntimeNameRunsc, h)
	m, err := NewManager(root, handlers, make(chan bool), nil, 10)
	require.NoError(t, err)
	defer m.Stop()
	require.Equal(t, []string{id}, h.deleted)
	require.Empty(t, m.List())
}

func TestStartupRecoveryPreservesTrackedLiveAmbiguousAndForeignRecords(t *testing.T) {
	h := &orphanRecoveryHandler{states: []*svc.State{
		nil,
		{ID: "sbox-tracked", Status: svc.SandboxStatusExited, InitProcessPid: -1},
		{ID: "sbox-live", Status: svc.SandboxStatusRunning, InitProcessPid: 100},
		{ID: "sbox-inconsistent", Status: svc.SandboxStatusExited, InitProcessPid: 100},
		{ID: "sbox-unknown", Status: svc.SandboxStatusUnknown, InitProcessPid: -1},
		{ID: "sbox-created", Status: svc.SandboxStatusCreated, InitProcessPid: -1},
		{ID: "../sbox-escape", Status: svc.SandboxStatusExited, InitProcessPid: -1},
		{ID: "foreign", Status: svc.SandboxStatusExited, InitProcessPid: -1},
	}}
	handlers := cmap.New[svc.Handler]()
	handlers.Set(config.RuntimeNameRunsc, h)
	m := &Manager{serviceHandler: handlers, sandboxes: cmap.New[*Sandbox]()}
	m.sandboxes.Set("sbox-tracked", &Sandbox{})
	require.NoError(t, m.reconcileStoppedRunscOrphans())
	require.Empty(t, h.deleted)
}

func TestStartupRecoveryPropagatesRuntimeFailures(t *testing.T) {
	for _, listFailure := range []bool{false, true} {
		t.Run(map[bool]string{false: "delete", true: "list"}[listFailure], func(t *testing.T) {
			h := &orphanRecoveryHandler{states: []*svc.State{{ID: "sbox-stopped", Status: svc.SandboxStatusExited, InitProcessPid: -1}}}
			failure := errors.New("runtime unavailable")
			if listFailure {
				h.listErr = failure
			} else {
				h.deleteErr = failure
			}
			handlers := cmap.New[svc.Handler]()
			handlers.Set(config.RuntimeNameRunsc, h)
			m, err := NewManager(t.TempDir(), handlers, make(chan bool), nil, 10)
			require.Nil(t, m)
			require.ErrorIs(t, err, failure)
		})
	}
}
