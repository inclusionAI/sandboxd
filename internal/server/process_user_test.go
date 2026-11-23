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
	"os"
	"path/filepath"
	"testing"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestResolveProcessUser(t *testing.T) {
	user, err := resolveProcessUser(nil)
	require.NoError(t, err)
	require.Nil(t, user)
	for _, requested := range []*runtime.ProcessUser{{}, {Uid: 1000, Gid: 1001}} {
		user, err := resolveProcessUser(requested)
		require.NoError(t, err)
		require.Equal(t, &svc.User{UID: requested.Uid, GID: requested.Gid}, user)
	}
	for _, requested := range []*runtime.ProcessUser{{Uid: ^uint32(0)}, {Gid: ^uint32(0)}} {
		_, err := resolveProcessUser(requested)
		require.ErrorIs(t, err, errord.ErrInvalidArgument)
	}
}

func TestStartValidatesProcessUserBeforeAllocation(t *testing.T) {
	service := newTestService(t, nil)
	directory := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(directory, "checkpoint.img"), []byte("image"), 0600))
	// Fresh and restore requests validate numeric IDs before allocating resources.
	for _, checkpoint := range []*runtime.CheckpointInfo{nil, {CheckpointDir: directory}} {
		_, err := service.Start(context.Background(), &runtime.StartRequest{CheckpointInfo: checkpoint, ProcessUser: &runtime.ProcessUser{Uid: ^uint32(0)}})
		require.Equal(t, codes.InvalidArgument, status.Code(err))
	}
}

func TestRestoreReceivesCallerConfiguredUser(t *testing.T) {
	handler := newCheckpointTestHandler()
	service := newTestService(t, map[string]svc.Handler{"runsc": handler})
	user, err := resolveProcessUser(&runtime.ProcessUser{Uid: 1000, Gid: 1001})
	require.NoError(t, err)
	directory := t.TempDir()
	require.NoError(t, service.startSandboxRuntime(context.Background(), "runsc", svc.StartConfig{ID: "sbox-restore-user", CheckpointDir: directory, ProcessUser: user}))
	require.Len(t, handler.restores, 1)
	require.Equal(t, &svc.User{UID: 1000, GID: 1001}, handler.restores[0].ProcessUser)
}

func TestCheckpointUsesRuntimeCredentials(t *testing.T) {
	handler := newCheckpointTestHandler()
	service := newTestService(t, map[string]svc.Handler{"runsc": handler})
	storeRunningSandbox(t, service, "sbox-user", "runsc")
	sb, err := service.sandboxManager.Get("sbox-user")
	require.NoError(t, err)
	sb.Spec.Process.User = specs.User{UID: 1000, GID: 1001}
	handler.checkpointFn = func(_ context.Context, config svc.CheckpointConfig) error {
		entries, err := os.ReadDir(config.Directory)
		require.NoError(t, err)
		require.Empty(t, entries)
		return nil
	}
	_, err = service.Checkpoint(context.Background(), &runtime.CheckpointRequest{ID: "sbox-user", CheckpointDir: filepath.Join(t.TempDir(), "checkpoint"), TimeoutSeconds: 5})
	require.NoError(t, err)
}

func TestListReturnsConfiguredProcessUser(t *testing.T) {
	service := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	storeRunningSandbox(t, service, "sbox-listed-user", "runsc")
	sb, err := service.sandboxManager.Get("sbox-listed-user")
	require.NoError(t, err)
	sb.Spec.Process.User = specs.User{UID: 1000, GID: 1001}
	for _, id := range []string{"", "sbox-listed-user"} {
		result, err := service.List(context.Background(), &runtime.ListSandboxesRequest{ID: id})
		require.NoError(t, err)
		require.Len(t, result.Sandboxes, 1)
		require.Equal(t, &runtime.ProcessUser{Uid: 1000, Gid: 1001}, result.Sandboxes[0].ProcessUser)
		require.Empty(t, result.Sandboxes[0].Envs)
	}
}
