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
	"path/filepath"
	"sync"
	"testing"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type checkpointTestHandler struct {
	*svc.FakeRuntimeHandler

	mu           sync.Mutex
	checkpointFn func(context.Context, svc.CheckpointConfig) error
	restoreFn    func(context.Context, svc.StartConfig) error
	checkpoints  []svc.CheckpointConfig
	restores     []svc.StartConfig
	restoreDirs  []string
	starts       []svc.StartConfig
	deleteCalls  int
}

func newCheckpointTestHandler() *checkpointTestHandler {
	return &checkpointTestHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
}

func (h *checkpointTestHandler) Start(ctx context.Context, config svc.StartConfig) error {
	h.mu.Lock()
	h.starts = append(h.starts, config)
	h.mu.Unlock()
	return nil
}

func (h *checkpointTestHandler) Delete(_ context.Context, _ string) error {
	h.mu.Lock()
	h.deleteCalls++
	h.mu.Unlock()
	return nil
}

func (h *checkpointTestHandler) Checkpoint(
	ctx context.Context,
	config svc.CheckpointConfig,
) error {
	h.mu.Lock()
	h.checkpoints = append(h.checkpoints, config)
	fn := h.checkpointFn
	h.mu.Unlock()
	if fn != nil {
		return fn(ctx, config)
	}
	return os.WriteFile(filepath.Join(config.Directory, "checkpoint.img"), []byte("image"), 0600)
}

func (h *checkpointTestHandler) Restore(
	ctx context.Context,
	config svc.StartConfig,
) error {
	h.mu.Lock()
	h.restores = append(h.restores, config)
	h.restoreDirs = append(h.restoreDirs, config.CheckpointDir)
	fn := h.restoreFn
	h.mu.Unlock()
	if fn != nil {
		return fn(ctx, config)
	}
	return nil
}

func storeRunningSandbox(t *testing.T, service *sandboxService, id, runtimeName string) {
	t.Helper()
	require.NoError(t, service.sandboxManager.StoreMetadata(id, &runtime.SandboxMetadata{
		ID:             id,
		RuntimeHandler: runtimeName,
	}))
}

func TestCheckpointForwardsRequest(t *testing.T) {
	handler := newCheckpointTestHandler()
	service := newTestService(t, map[string]svc.Handler{"runsc": handler})
	storeRunningSandbox(t, service, "sbox-checkpoint", "runsc")
	directory := filepath.Join(t.TempDir(), "checkpoint")

	response, err := service.Checkpoint(context.Background(), &runtime.CheckpointRequest{
		ID:             "sbox-checkpoint",
		CheckpointDir:  directory,
		TimeoutSeconds: 5,
		Compress:       true,
		LeaveRunning:   true,
	})
	require.NoError(t, err)
	require.NotNil(t, response)
	require.Len(t, handler.checkpoints, 1)
	assert.Equal(t, svc.CheckpointConfig{
		ID:           "sbox-checkpoint",
		Directory:    directory,
		CgroupPath:   "",
		Compress:     true,
		LeaveRunning: true,
	}, handler.checkpoints[0])
	assert.FileExists(t, filepath.Join(directory, "checkpoint.img"))
	assert.Zero(t, handler.deleteCalls)
}

func TestCheckpointFailureCleansResidualsWithoutDeletingSource(t *testing.T) {
	handler := newCheckpointTestHandler()
	handler.checkpointFn = func(_ context.Context, config svc.CheckpointConfig) error {
		require.NoError(t, os.WriteFile(
			filepath.Join(config.Directory, "partial"),
			[]byte("partial"),
			0600,
		))
		return errors.New("runtime checkpoint failed")
	}
	service := newTestService(t, map[string]svc.Handler{"runsc": handler})
	storeRunningSandbox(t, service, "sbox-failure", "runsc")
	directory := filepath.Join(t.TempDir(), "checkpoint")
	require.NoError(t, os.Mkdir(directory, 0700))

	_, err := service.Checkpoint(context.Background(), &runtime.CheckpointRequest{
		ID:             "sbox-failure",
		CheckpointDir:  directory,
		TimeoutSeconds: 5,
		LeaveRunning:   true,
	})
	require.Error(t, err)
	assert.ErrorContains(t, err, "source sandbox state is not guaranteed")
	entries, readErr := os.ReadDir(directory)
	require.NoError(t, readErr)
	assert.Empty(t, entries)
	assert.Zero(t, handler.deleteCalls)
}

func TestCheckpointTimeoutCleansCreatedDirectory(t *testing.T) {
	handler := newCheckpointTestHandler()
	handler.checkpointFn = func(ctx context.Context, config svc.CheckpointConfig) error {
		require.NoError(t, os.WriteFile(
			filepath.Join(config.Directory, "partial"),
			[]byte("partial"),
			0600,
		))
		<-ctx.Done()
		return ctx.Err()
	}
	service := newTestService(t, map[string]svc.Handler{"runsc": handler})
	storeRunningSandbox(t, service, "sbox-timeout", "runsc")
	directory := filepath.Join(t.TempDir(), "checkpoint")

	_, err := service.Checkpoint(context.Background(), &runtime.CheckpointRequest{
		ID:             "sbox-timeout",
		CheckpointDir:  directory,
		TimeoutSeconds: 1,
	})
	require.Error(t, err)
	assert.Equal(t, codes.DeadlineExceeded, status.Code(err))
	assert.NoDirExists(t, directory)
	assert.Zero(t, handler.deleteCalls)
}

func TestCheckpointRejectsConcurrentOperation(t *testing.T) {
	handler := newCheckpointTestHandler()
	started := make(chan struct{})
	release := make(chan struct{})
	handler.checkpointFn = func(_ context.Context, config svc.CheckpointConfig) error {
		close(started)
		<-release
		return os.WriteFile(filepath.Join(config.Directory, "checkpoint.img"), []byte("image"), 0600)
	}
	service := newTestService(t, map[string]svc.Handler{"runsc": handler})
	storeRunningSandbox(t, service, "sbox-concurrent", "runsc")
	root := t.TempDir()
	firstResult := make(chan error, 1)
	go func() {
		_, err := service.Checkpoint(context.Background(), &runtime.CheckpointRequest{
			ID:             "sbox-concurrent",
			CheckpointDir:  filepath.Join(root, "first"),
			TimeoutSeconds: 5,
		})
		firstResult <- err
	}()
	<-started

	_, err := service.Checkpoint(context.Background(), &runtime.CheckpointRequest{
		ID:             "sbox-concurrent",
		CheckpointDir:  filepath.Join(root, "second"),
		TimeoutSeconds: 5,
	})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	close(release)
	assert.NoError(t, <-firstResult)
}

func TestCheckpointValidatesRequestAndRuntime(t *testing.T) {
	service := newTestService(t, map[string]svc.Handler{
		"runsc": svc.NewFakeRuntimeHandler(),
	})
	storeRunningSandbox(t, service, "sbox-unsupported", "runsc")

	_, err := service.Checkpoint(context.Background(), &runtime.CheckpointRequest{
		ID:            "sbox-unsupported",
		CheckpointDir: filepath.Join(t.TempDir(), "checkpoint"),
	})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	_, err = service.Checkpoint(context.Background(), &runtime.CheckpointRequest{
		ID:             "sbox-unsupported",
		CheckpointDir:  filepath.Join(t.TempDir(), "checkpoint"),
		TimeoutSeconds: 1,
	})
	assert.Equal(t, codes.Unimplemented, status.Code(err))
}

func TestCheckpointDirectoryValidation(t *testing.T) {
	root := t.TempDir()
	t.Run("missing leaf is created and removed on cleanup", func(t *testing.T) {
		path := filepath.Join(root, "created")
		directory, err := prepareCheckpointOutputDirectory(path)
		require.NoError(t, err)
		assert.True(t, directory.created)
		require.NoError(t, directory.cleanup())
		assert.NoDirExists(t, path)
	})

	t.Run("existing empty directory is preserved on cleanup", func(t *testing.T) {
		path := filepath.Join(root, "existing")
		require.NoError(t, os.Mkdir(path, 0700))
		directory, err := prepareCheckpointOutputDirectory(path)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(path, "partial"), []byte("x"), 0600))
		require.NoError(t, directory.cleanup())
		assert.DirExists(t, path)
		entries, readErr := os.ReadDir(path)
		require.NoError(t, readErr)
		assert.Empty(t, entries)
	})

	t.Run("nonempty output is rejected", func(t *testing.T) {
		path := filepath.Join(root, "nonempty")
		require.NoError(t, os.Mkdir(path, 0700))
		require.NoError(t, os.WriteFile(filepath.Join(path, "owned"), []byte("x"), 0600))
		_, err := prepareCheckpointOutputDirectory(path)
		assert.ErrorIs(t, err, errord.ErrFailedPrecondition)
	})

	t.Run("relative path is rejected", func(t *testing.T) {
		_, err := prepareCheckpointOutputDirectory("relative/checkpoint")
		assert.ErrorIs(t, err, errord.ErrInvalidArgument)
	})

	t.Run("symbolic link component is rejected", func(t *testing.T) {
		target := filepath.Join(root, "target")
		link := filepath.Join(root, "link")
		require.NoError(t, os.Mkdir(target, 0700))
		require.NoError(t, os.Symlink(target, link))
		_, err := prepareCheckpointOutputDirectory(filepath.Join(link, "checkpoint"))
		assert.ErrorIs(t, err, errord.ErrInvalidArgument)
	})
}

func TestCheckpointInputDirectoryValidation(t *testing.T) {
	directory := t.TempDir()
	_, err := validateCheckpointInputDirectory(directory)
	assert.ErrorIs(t, err, errord.ErrFailedPrecondition)

	require.NoError(t, os.WriteFile(filepath.Join(directory, "checkpoint.img"), []byte("image"), 0600))
	got, err := validateCheckpointInputDirectory(directory)
	require.NoError(t, err)
	assert.Equal(t, directory, got)
}

func TestCheckpointGuestMemoryResources(t *testing.T) {
	limit := int64(256 << 20)
	swap := int64(512 << 20)
	got := checkpointGuestMemoryResources(&specs.Spec{
		Linux: &specs.Linux{
			Resources: &specs.LinuxResources{
				Memory: &specs.LinuxMemory{
					Limit: &limit,
					Swap:  &swap,
				},
			},
		},
	})
	require.NotNil(t, got)
	assert.Equal(t, limit, got.MemoryLimitInBytes)
	assert.Equal(t, swap, got.MemorySwapLimitInBytes)

	assert.Nil(t, checkpointGuestMemoryResources(nil))
	assert.Nil(t, checkpointGuestMemoryResources(&specs.Spec{
		Linux: &specs.Linux{
			Resources: &specs.LinuxResources{
				Memory: &specs.LinuxMemory{},
			},
		},
	}))
}

func TestStartSandboxRuntimeDispatchesRestore(t *testing.T) {
	handler := newCheckpointTestHandler()
	service := buildServiceWithOptions(AddHandler("runsc", handler))
	config := svc.StartConfig{
		ID:            "sbox-restored",
		CheckpointDir: "/checkpoints/one",
	}

	require.NoError(t, service.startSandboxRuntime(context.Background(), "runsc", config))
	require.Len(t, handler.restores, 1)
	assert.Equal(t, config, handler.restores[0])
	assert.Equal(t, "/checkpoints/one", handler.restoreDirs[0])
	assert.Empty(t, handler.starts)
}

func TestStartSandboxRuntimeUsesStartWithoutCheckpoint(t *testing.T) {
	handler := newCheckpointTestHandler()
	service := buildServiceWithOptions(AddHandler("runsc", handler))
	config := svc.StartConfig{ID: "sbox-started"}

	require.NoError(t, service.startSandboxRuntime(context.Background(), "runsc", config))
	require.Len(t, handler.starts, 1)
	assert.Equal(t, config, handler.starts[0])
	assert.Empty(t, handler.restores)
}

func TestStartSandboxRuntimeRejectsUnsupportedRestore(t *testing.T) {
	service := buildServiceWithOptions(AddHandler("runc", svc.NewFakeRuntimeHandler()))
	err := service.startSandboxRuntime(context.Background(), "runc", svc.StartConfig{
		ID:            "sbox-restored",
		CheckpointDir: "/checkpoints/one",
	})
	assert.Equal(t, codes.Unimplemented, status.Code(err))
}
