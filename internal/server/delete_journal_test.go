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
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager/networkacl"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/inclusionAI/sandboxd/pkg/sandbox"
	"github.com/inclusionAI/sandboxd/pkg/store"
	"github.com/stretchr/testify/require"
)

type deleteFaultStore struct {
	store.DbStore
	before func(string, []byte) error
	after  func(string, []byte)
}

func (s *deleteFaultStore) StoreRaw(key string, data []byte) error {
	if s.before != nil {
		if err := s.before(key, data); err != nil {
			return err
		}
	}
	if err := s.DbStore.StoreRaw(key, data); err != nil {
		return err
	}
	if s.after != nil {
		s.after(key, data)
	}
	return nil
}

type deleteErrorHandler struct{ *svc.FakeRuntimeHandler }

func (*deleteErrorHandler) Delete(context.Context, string) error {
	return errors.New("runtime still alive")
}

func TestDeleteIntentWritePrecedesRuntimeStop(t *testing.T) {
	handler := &recordingDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	defer s.sandboxManager.Stop()
	storeSandboxForDelete(t, s, "sbox-write-barrier")
	s.store = &deleteFaultStore{DbStore: s.store, before: func(string, []byte) error { return errors.New("disk unavailable") }}
	require.ErrorContains(t, s.deleteSandboxRuntime(context.Background(), "sbox-write-barrier"), "disk unavailable")
	require.Zero(t, handler.calls)
	_, err := s.sandboxManager.Get("sbox-write-barrier")
	require.NoError(t, err)
}

func TestDeleteRecoveryFailsClosedWhenRuntimeCannotStop(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{"runsc": &deleteErrorHandler{svc.NewFakeRuntimeHandler()}})
	defer s.sandboxManager.Stop()
	storeSandboxForDelete(t, s, "sbox-live")
	_, err := s.beginDelete("sbox-live")
	require.NoError(t, err)
	require.ErrorContains(t, s.recoverDeletes(context.Background()), "runtime still alive")
	_, err = s.sandboxManager.Get("sbox-live")
	require.NoError(t, err)
	pending, err := s.loadDeleteIntents()
	require.NoError(t, err)
	require.False(t, pending["sbox-live"].Releasing)
}

func TestDeleteFinalWriteFailureBlocksResourceReuse(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	defer s.sandboxManager.Stop()
	storeSandboxForDelete(t, s, "sbox-final-write")
	fault := &deleteFaultStore{DbStore: s.store, before: func(key string, data []byte) error {
		if key == deleteIntentBucket && string(data) == "{}" {
			return errors.New("journal unavailable")
		}
		return nil
	}}
	s.store = fault
	require.ErrorContains(t, s.deleteSandboxRuntime(context.Background(), "sbox-final-write"), "journal unavailable")
	// Metadata has already gone, but the durable resource snapshot must survive.
	_, err := s.sandboxManager.Get("sbox-final-write")
	require.ErrorIs(t, err, errord.ErrNotFound)
	_, err = s.prepareStartResources("runsc", "sbox-new")
	require.ErrorContains(t, err, "journal unavailable")
	fault.before = nil
	s.resourceReuseMu.Lock()
	err = s.finishReleasedDeletes()
	s.resourceReuseMu.Unlock()
	require.NoError(t, err)
	pending, err := s.loadDeleteIntents()
	require.NoError(t, err)
	require.Empty(t, pending)
}

func TestDeleteJournalPreservesConcurrentIntents(t *testing.T) {
	s := newTestService(t, nil)
	defer s.sandboxManager.Stop()
	var wg sync.WaitGroup
	for _, id := range []string{"sbox-one", "sbox-two", "sbox-three"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			intent := &deleteIntent{Token: id, Runtime: "runsc", Resource: sandbox.OccupiedResource{ID: id, Resources: map[string]string{}}}
			require.NoError(t, s.saveDeleteIntent(id, intent))
		}()
	}
	wg.Wait()
	pending, err := s.loadDeleteIntents()
	require.NoError(t, err)
	require.Len(t, pending, 3)
}

// Execute the actual server delete path in a subprocess and exit without
// defers at durable boundaries. Recovery uses only the on-disk bbolt journal
// and bundle files; no in-memory delete state crosses the process boundary.
func TestDeleteRecoveryAfterProcessExit(t *testing.T) {
	const rootEnv = "SANDBOXD_DELETE_CRASH_ROOT"
	const stageEnv = "SANDBOXD_DELETE_CRASH_STAGE"
	if root := os.Getenv(rootEnv); root != "" {
		handler := &recordingDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
		s := newTestService(t, map[string]svc.Handler{"runsc": handler})
		s.sandboxManager.Stop()
		var err error
		s.config.RootDir = root
		s.sandboxManager, err = sandbox.NewManager(root, s.serviceHandler, make(chan bool, 10), nil, 1000)
		require.NoError(t, err)
		db := store.NewStoreImp(filepath.Join(root, "metadata.db"))
		stage := os.Getenv(stageEnv)
		fault := &deleteFaultStore{DbStore: db}
		fault.after = func(key string, data []byte) {
			hit := (stage == "intent" && key == deleteIntentBucket) ||
				(stage == "runtime-stopped" && key == config.SandboxFSStateBucket) ||
				(stage == "before-resource-release" && key == deleteIntentBucket && string(data) != "{}" && handler.calls > 0)
			if hit {
				os.Exit(86)
			}
		}
		fault.before = func(key string, data []byte) error {
			if stage == "metadata-removed" && key == deleteIntentBucket && string(data) == "{}" {
				os.Exit(86)
			}
			return nil
		}
		s.store = fault
		s.fsMgr = newFSManager(nil, fault)
		storeSandboxForDelete(t, s, "sbox-crash")
		storeSandboxForDelete(t, s, "sbox-survivor")
		require.NoError(t, s.deleteSandboxRuntime(context.Background(), "sbox-crash"))
		t.Fatal("crash boundary was not reached")
	}
	for _, stage := range []string{"intent", "runtime-stopped", "before-resource-release", "metadata-removed"} {
		t.Run(stage, func(t *testing.T) {
			root := t.TempDir()
			cmd := exec.Command(os.Args[0], "-test.run=^TestDeleteRecoveryAfterProcessExit$")
			cmd.Env = append(os.Environ(), rootEnv+"="+root, stageEnv+"="+stage)
			output, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			require.ErrorAs(t, err, &exit, "%s", output)
			require.Equal(t, 86, exit.ExitCode(), "%s", output)
			handler := &recordingDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
			s := newTestService(t, map[string]svc.Handler{"runsc": handler})
			s.sandboxManager.Stop()
			s.config.RootDir = root
			s.sandboxManager, err = sandbox.NewManager(root, s.serviceHandler, make(chan bool, 10), nil, 1000)
			require.NoError(t, err)
			defer s.sandboxManager.Stop()
			s.store = store.NewStoreImp(filepath.Join(root, "metadata.db"))
			s.fsMgr = newFSManager(nil, s.store)
			pending, err := s.loadDeleteIntents()
			require.NoError(t, err)
			require.Contains(t, pending, "sbox-crash")
			require.NoError(t, s.recoverDeletes(context.Background()))
			require.NoError(t, s.recoverDeletes(context.Background()), "recovery must be idempotent")
			pending, err = s.loadDeleteIntents()
			require.NoError(t, err)
			require.Empty(t, pending)
			_, err = s.sandboxManager.Get("sbox-crash")
			require.ErrorIs(t, err, errord.ErrNotFound)
			_, err = s.sandboxManager.Get("sbox-survivor")
			require.NoError(t, err, "unrelated sandbox metadata must survive")
			if stage == "before-resource-release" || stage == "metadata-removed" {
				require.Zero(t, handler.calls)
			}
		})
	}
}

func TestDeleteRecoveryDoesNotSuppressMissingACLForSurvivor(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	defer s.sandboxManager.Stop()
	storeSandboxForDelete(t, s, "sbox-deleting")
	storeSandboxForDelete(t, s, "sbox-survivor")
	// The deleted sandbox's ACL is already absent. Only its durable deletion
	// intent authorizes finishing cleanup before live ACL restoration.
	_, err := s.beginDelete("sbox-deleting")
	require.NoError(t, err)
	s.aclMgr = &networkacl.Manager{}
	require.NoError(t, s.recoverDeletes(context.Background()))
	_, err = s.sandboxManager.Get("sbox-survivor")
	require.NoError(t, err)
	require.ErrorContains(t, s.aclMgr.Restore(map[string]networkacl.Binding{
		"sbox-survivor": {SandboxID: "sbox-survivor"},
	}), "has no managed network ACL state")
}

func TestDeleteRetryDoesNotReleaseReusedIDReservation(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	defer s.sandboxManager.Stop()
	const id = "sbox-reused"
	storeSandboxForDelete(t, s, id)
	fault := &deleteFaultStore{DbStore: s.store, before: func(key string, data []byte) error {
		if key == deleteIntentBucket && string(data) == "{}" {
			return errors.New("disk unavailable")
		}
		return nil
	}}
	s.store = fault
	require.Error(t, s.deleteSandboxRuntime(context.Background(), id))
	_, err := s.reserveSandboxID(id)
	require.ErrorContains(t, err, "disk unavailable")
	fault.before = nil
	reserved, err := s.reserveSandboxID(id)
	require.NoError(t, err)
	require.Equal(t, id, reserved)
	_, err = s.reserveSandboxID(id)
	require.ErrorIs(t, err, errord.ErrAlreadyExists)
}
