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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
)

type checkpointDirectory struct {
	path    string
	created bool
}

func (h *sandboxService) Checkpoint(
	ctx context.Context,
	request *runtime.CheckpointRequest,
) (*runtime.CheckpointResponse, error) {
	started := time.Now()
	if request == nil {
		return nil, errord.ToGRPCf(errord.ErrInvalidArgument, "checkpoint request is nil")
	}
	if strings.TrimSpace(request.ID) == "" {
		return nil, errord.ToGRPCf(errord.ErrInvalidArgument, "sandbox ID is required")
	}
	if request.TimeoutSeconds == 0 {
		return nil, errord.ToGRPCf(
			errord.ErrInvalidArgument,
			"checkpoint timeout_seconds must be greater than zero",
		)
	}

	sandbox, err := h.sandboxManager.Get(request.ID)
	if err != nil {
		return nil, errord.ToGRPC(err)
	}
	if sandbox.Metadata == nil || sandbox.Metadata.RuntimeHandler == "" {
		return nil, errord.ToGRPCf(
			errord.ErrFailedPrecondition,
			"sandbox %s has no runtime metadata",
			request.ID,
		)
	}
	if sandbox.Status == nil ||
		sandbox.Status.Get().State() != runtime.SandboxState_SANDBOX_STATE_RUNNING {
		return nil, errord.ToGRPCf(
			errord.ErrFailedPrecondition,
			"sandbox %s is not running",
			request.ID,
		)
	}
	handler, ok := h.serviceHandler.Get(sandbox.Metadata.RuntimeHandler)
	if !ok {
		return nil, errord.ToGRPC(errord.ErrNotImplemented)
	}
	checkpointHandler, ok := handler.(svc.CheckpointHandler)
	if !ok {
		return nil, errord.ToGRPCf(
			errord.ErrNotImplemented,
			"runtime %q does not support checkpoint",
			sandbox.Metadata.RuntimeHandler,
		)
	}
	if !h.beginCheckpoint(request.ID) {
		return nil, errord.ToGRPCf(
			errord.ErrFailedPrecondition,
			"checkpoint is already in progress for sandbox %s",
			request.ID,
		)
	}
	defer h.finishCheckpoint(request.ID)

	directory, err := prepareCheckpointOutputDirectory(request.CheckpointDir)
	if err != nil {
		return nil, errord.ToGRPC(err)
	}

	checkpointCtx, cancel := context.WithTimeout(
		ctx,
		time.Duration(request.TimeoutSeconds)*time.Second,
	)
	defer cancel()
	cgroupPath := ""
	var resources *runtime.LinuxSandboxResources
	if config.IsFirecrackerFamily(sandbox.Metadata.RuntimeHandler) {
		resource, resourceErr := h.sandboxManager.CollectResourceByID(request.ID)
		if resourceErr != nil {
			_ = directory.cleanup()
			return nil, errord.ToGRPC(resourceErr)
		}
		cgroupPath = resource.Resources[config.ResourceNameCgroup]
		resources = checkpointGuestMemoryResources(sandbox.Spec)
		if resources == nil {
			resources = sandbox.Status.Get().Resources
		}
	}
	captureStarted := time.Now()
	err = h.withTransientFirecrackerCheckpointMemory(
		checkpointCtx,
		sandbox.Metadata.RuntimeHandler,
		request.ID,
		cgroupPath,
		resources,
		handler,
		true,
		func() error {
			return checkpointHandler.Checkpoint(checkpointCtx, svc.CheckpointConfig{
				ID:           request.ID,
				Directory:    directory.path,
				CgroupPath:   cgroupPath,
				Compress:     request.Compress,
				LeaveRunning: request.LeaveRunning,
				SnapshotType: request.SnapshotType,
			})
		},
	)
	if err != nil {
		if checkpointCtx.Err() != nil {
			err = checkpointCtx.Err()
		}
		operationErr := fmt.Errorf(
			"checkpoint sandbox %s failed; source sandbox state is not guaranteed: %w",
			request.ID,
			err,
		)
		if cleanupErr := directory.cleanup(); cleanupErr != nil {
			operationErr = errors.Join(operationErr, fmt.Errorf(
				"clean checkpoint residuals in %s: %w",
				directory.path,
				cleanupErr,
			))
		}
		return nil, errord.ToGRPC(operationErr)
	}
	captureDuration := time.Since(captureStarted)
	syncStarted := time.Now()
	if h.config.PluginConfig.RuntimeConfig.CheckpointSync.SyncOutput {
		if err := syncCheckpointOutput(checkpointCtx, directory.path); err != nil {
			operationErr := fmt.Errorf(
				"checkpoint sandbox %s output persistence barrier failed; source sandbox state is not guaranteed: %w",
				request.ID, err,
			)
			if cleanupErr := directory.cleanup(); cleanupErr != nil {
				operationErr = errors.Join(operationErr, fmt.Errorf("clean checkpoint residuals in %s: %w", directory.path, cleanupErr))
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, errord.ToGRPC(operationErr)
			}
			return nil, errord.ToGRPCf(errord.ErrUnavailable, "%v", operationErr)
		}
	}
	logrus.WithFields(logrus.Fields{
		"sandbox_id":     request.ID,
		"runtime_ms":     float64(captureDuration.Microseconds()) / 1000,
		"sync_output":    h.config.PluginConfig.RuntimeConfig.CheckpointSync.SyncOutput,
		"sync_output_ms": float64(time.Since(syncStarted).Microseconds()) / 1000,
		"total_ms":       float64(time.Since(started).Microseconds()) / 1000,
	}).Info("checkpoint stages completed")
	return &runtime.CheckpointResponse{}, nil
}

// syncCheckpointOutput applies the backing filesystem's synchronization
// guarantee after the runtime finishes capture. Only regular files and
// directories are accepted.
func syncCheckpointOutput(ctx context.Context, root string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("checkpoint output %s is not a directory", root)
	}
	if err := syncCheckpointDirectory(ctx, root); err != nil {
		return err
	}
	// The parent contains the entry for a newly created capture directory.
	if err := syncCheckpointFile(filepath.Dir(root)); err != nil {
		return err
	}
	return ctx.Err()
}

func syncCheckpointDirectory(ctx context.Context, dir string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		path := filepath.Join(dir, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		switch {
		case info.IsDir():
			if err := syncCheckpointDirectory(ctx, path); err != nil {
				return err
			}
		case info.Mode().IsRegular():
			if err := syncCheckpointFile(path); err != nil {
				return err
			}
		default:
			return fmt.Errorf("checkpoint output %s is not a regular file or directory", path)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := syncCheckpointFile(dir); err != nil {
		return err
	}
	return ctx.Err()
}

func syncCheckpointFile(path string) error {
	started := time.Now()
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	opened := time.Now()
	kind, size := "unknown", int64(-1)
	if info, statErr := file.Stat(); statErr == nil {
		size = info.Size()
		if info.IsDir() {
			kind = "directory"
		} else if info.Mode().IsRegular() {
			kind = "file"
		}
	}
	syncStarted := time.Now()
	syncErr := file.Sync()
	synced := time.Now()
	closeErr := file.Close()
	closed := time.Now()
	err = errors.Join(syncErr, closeErr)
	fields := logrus.Fields{
		"path":          path,
		"kind":          kind,
		"logical_bytes": size,
		"open_us":       opened.Sub(started).Microseconds(),
		"sync_us":       synced.Sub(syncStarted).Microseconds(),
		"close_us":      closed.Sub(synced).Microseconds(),
		"total_us":      closed.Sub(started).Microseconds(),
	}
	entry := logrus.WithFields(fields)
	if err != nil {
		entry = entry.WithError(err)
	}
	entry.Debug("checkpoint output file sync completed")
	return err
}

// checkpointGuestMemoryResources returns the guest-visible limit persisted in
// config.json. Unlike the live cgroup limit, this value cannot be confused
// with transient host checkpoint headroom left behind by a daemon restart.
func checkpointGuestMemoryResources(
	sandboxSpec *specs.Spec,
) *runtime.LinuxSandboxResources {
	if sandboxSpec == nil || sandboxSpec.Linux == nil ||
		sandboxSpec.Linux.Resources == nil ||
		sandboxSpec.Linux.Resources.Memory == nil ||
		sandboxSpec.Linux.Resources.Memory.Limit == nil ||
		*sandboxSpec.Linux.Resources.Memory.Limit <= 0 {
		return nil
	}
	resources := &runtime.LinuxSandboxResources{
		MemoryLimitInBytes: *sandboxSpec.Linux.Resources.Memory.Limit,
	}
	if swap := sandboxSpec.Linux.Resources.Memory.Swap; swap != nil {
		resources.MemorySwapLimitInBytes = *swap
	}
	return resources
}

func (h *sandboxService) beginCheckpoint(id string) bool {
	h.checkpointMu.Lock()
	defer h.checkpointMu.Unlock()
	if h.checkpointing == nil {
		h.checkpointing = make(map[string]struct{})
	}
	if _, ok := h.checkpointing[id]; ok {
		return false
	}
	h.checkpointing[id] = struct{}{}
	return true
}

func (h *sandboxService) finishCheckpoint(id string) {
	h.checkpointMu.Lock()
	delete(h.checkpointing, id)
	h.checkpointMu.Unlock()
}

func prepareCheckpointOutputDirectory(path string) (*checkpointDirectory, error) {
	clean, err := validateCheckpointPath(path, false)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(clean)
	switch {
	case err == nil:
		if !info.IsDir() {
			return nil, fmt.Errorf(
				"checkpoint directory %s is not a directory: %w",
				clean,
				errord.ErrInvalidArgument,
			)
		}
		entries, readErr := os.ReadDir(clean)
		if readErr != nil {
			return nil, fmt.Errorf("read checkpoint directory %s: %w", clean, readErr)
		}
		if len(entries) != 0 {
			return nil, fmt.Errorf(
				"checkpoint directory %s is not empty: %w",
				clean,
				errord.ErrFailedPrecondition,
			)
		}
		return &checkpointDirectory{path: clean}, nil
	case errors.Is(err, os.ErrNotExist):
		parent := filepath.Dir(clean)
		if _, parentErr := validateCheckpointPath(parent, true); parentErr != nil {
			return nil, fmt.Errorf("invalid checkpoint parent directory: %w", parentErr)
		}
		if mkdirErr := os.Mkdir(clean, 0700); mkdirErr != nil {
			return nil, fmt.Errorf("create checkpoint directory %s: %w", clean, mkdirErr)
		}
		return &checkpointDirectory{path: clean, created: true}, nil
	default:
		return nil, fmt.Errorf("inspect checkpoint directory %s: %w", clean, err)
	}
}

func validateCheckpointInputDirectory(path string) (string, error) {
	clean, err := validateCheckpointPath(path, true)
	if err != nil {
		return "", err
	}
	entries, err := os.ReadDir(clean)
	if err != nil {
		return "", fmt.Errorf("read checkpoint directory %s: %w", clean, err)
	}
	if len(entries) == 0 {
		return "", fmt.Errorf(
			"checkpoint directory %s is empty: %w",
			clean,
			errord.ErrFailedPrecondition,
		)
	}
	return clean, nil
}

func validateCheckpointPath(path string, mustExist bool) (string, error) {
	if strings.TrimSpace(path) == "" || !filepath.IsAbs(path) {
		return "", fmt.Errorf(
			"checkpoint directory must be an absolute path: %w",
			errord.ErrInvalidArgument,
		)
	}
	clean := filepath.Clean(path)
	if clean == string(filepath.Separator) {
		return "", fmt.Errorf("checkpoint directory cannot be root: %w", errord.ErrInvalidArgument)
	}
	current := string(filepath.Separator)
	parts := strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator))
	for index, part := range parts {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) && !mustExist && index == len(parts)-1 {
			return clean, nil
		}
		if err != nil {
			return "", fmt.Errorf("inspect checkpoint path %s: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("checkpoint path %s is a symbolic link: %w", current, errord.ErrInvalidArgument)
		}
		if !info.IsDir() {
			return "", fmt.Errorf("checkpoint path %s is not a directory: %w", current, errord.ErrInvalidArgument)
		}
	}
	return clean, nil
}

func (directory *checkpointDirectory) cleanup() error {
	if directory.created {
		return os.RemoveAll(directory.path)
	}
	info, err := os.Lstat(directory.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("checkpoint path changed during cleanup")
	}
	entries, err := os.ReadDir(directory.path)
	if err != nil {
		return err
	}
	var cleanupErr error
	for _, entry := range entries {
		cleanupErr = errors.Join(cleanupErr, os.RemoveAll(filepath.Join(directory.path, entry.Name())))
	}
	return cleanupErr
}
