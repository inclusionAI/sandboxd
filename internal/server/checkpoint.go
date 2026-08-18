// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/checkpoint"
	"github.com/inclusionAI/sandboxd/internal/checkpointstate"
	"github.com/inclusionAI/sandboxd/internal/physicalstate"
	"github.com/inclusionAI/sandboxd/internal/trace"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func (h *sandboxService) Checkpoint(
	ctx context.Context,
	request *runtime.CheckpointRequest,
) (*runtime.CheckpointResponse, error) {
	if request == nil || request.ID == "" || request.CheckpointDir == "" || request.CheckpointID == "" {
		return nil, errord.ToGRPC(fmt.Errorf("id, checkpoint_dir, and checkpoint_id are required: %w", errord.ErrInvalidArgument))
	}
	checkpointDir, err := h.resolveManagedCheckpointDir(request.CheckpointDir)
	if err != nil {
		return nil, checkpointGRPCError(err)
	}
	existing, artifactErr := checkpoint.InspectAt(checkpointDir, request.CheckpointID)
	if artifactErr != nil {
		if _, statErr := os.Lstat(filepath.Join(checkpointDir, checkpoint.ManifestName)); statErr == nil || !errors.Is(statErr, os.ErrNotExist) {
			return nil, checkpointGRPCError(artifactErr)
		}
		artifactErr = fmt.Errorf("checkpoint %q: %w", request.CheckpointID, errord.ErrNotFound)
	}
	if artifactErr == nil && (existing.Manifest.SourceID != request.ID ||
		existing.Manifest.LeaveRunning != request.LeaveRunning) {
		return nil, checkpointGRPCError(fmt.Errorf(
			"checkpoint %q source or leave-running mode conflicts with replay: %w",
			request.CheckpointID,
			errord.ErrFailedPrecondition))
	}
	sandbox, err := h.sandboxManager.Get(request.ID)
	if err != nil {
		if artifactErr == nil && errors.Is(err, errord.ErrNotFound) {
			return checkpointResponse(existing), nil
		}
		return nil, checkpointGRPCError(err)
	}
	if sandbox.Metadata == nil || sandbox.Status == nil {
		return nil, checkpointGRPCError(fmt.Errorf("sandbox %s metadata is incomplete: %w", request.ID, errord.ErrFailedPrecondition))
	}

	rootfs, err := h.fsMgr.RootfsConfig(request.ID)
	if err != nil {
		return nil, checkpointGRPCError(fmt.Errorf("read source rootfs identity: %w", err))
	}
	identity, err := rootfsIdentity(rootfs)
	if err != nil {
		return nil, checkpointGRPCError(err)
	}
	source := checkpoint.SourceIdentity{
		CheckpointID: request.CheckpointID,
		SourceID:     request.ID,
		Runtime:      sandbox.Metadata.RuntimeHandler,
		RootfsSHA256: hex.EncodeToString(identity[:]),
		LeaveRunning: request.LeaveRunning,
	}
	if artifactErr == nil {
		exact, matchErr := checkpoint.MatchSource(existing, source)
		if matchErr != nil {
			return nil, checkpointGRPCError(matchErr)
		}
		return checkpointResponse(exact), nil
	}
	state := sandbox.Status.Get().State()
	if sandbox.Metadata.RuntimeHandler != config.RuntimeNameRunsc {
		return nil, checkpointGRPCError(fmt.Errorf("runtime %q does not support checkpoint: %w",
			sandbox.Metadata.RuntimeHandler, errord.ErrNotImplemented))
	}
	handler, ok := h.serviceHandler.Get(sandbox.Metadata.RuntimeHandler)
	if !ok {
		return nil, checkpointGRPCError(errord.ErrNotImplemented)
	}
	checkpointHandler, ok := handler.(managedCheckpointHandler)
	if !ok {
		return nil, checkpointGRPCError(fmt.Errorf("runtime %q does not support checkpoint: %w",
			sandbox.Metadata.RuntimeHandler, errord.ErrNotImplemented))
	}
	fingerprint, err := checkpointFingerprint(request, request.CheckpointID)
	if err != nil {
		return nil, checkpointGRPCError(err)
	}
	releaseOperation, ok := h.acquireCheckpointOperation()
	if !ok {
		return nil, checkpointGRPCError(fmt.Errorf("sandbox service is shutting down: %w", errord.ErrUnavailable))
	}
	key := checkpointstate.CheckpointKey{SandboxID: request.ID, CheckpointID: request.CheckpointID}
	attempt, execute, err := h.checkpointState.BeginCheckpoint(key, fingerprint)
	if err != nil {
		releaseOperation()
		return nil, checkpointGRPCError(err)
	}
	if execute && state != runtime.SandboxState_SANDBOX_STATE_RUNNING {
		err := fmt.Errorf("sandbox %s is %s: %w",
			request.ID, state, errord.ErrFailedPrecondition)
		h.checkpointState.Complete(attempt, err)
		releaseOperation()
		return nil, checkpointGRPCError(err)
	}
	if execute {
		operationCtx := h.checkpointOperationContext(ctx)
		go func() {
			defer releaseOperation()
			h.executeCheckpoint(operationCtx, checkpointDir, key, checkpointHandler, source,
				request.LeaveRunning, attempt)
		}()
	} else {
		releaseOperation()
	}
	if err := attempt.Wait(ctx); err != nil {
		return nil, checkpointGRPCError(err)
	}
	fact, err := checkpoint.InspectAt(checkpointDir, request.CheckpointID)
	if err != nil {
		return nil, checkpointGRPCError(err)
	}
	return checkpointResponse(fact), nil
}

func checkpointResponse(fact checkpoint.Fact) *runtime.CheckpointResponse {
	return &runtime.CheckpointResponse{
		ArtifactPath: fact.Paths.Image,
		ArtifactSize: fact.Manifest.ImageSize, ArtifactSha256: fact.Manifest.ImageSHA256,
	}
}

func (h *sandboxService) DeleteCheckpoint(
	_ context.Context,
	request *runtime.DeleteCheckpointRequest,
) (*runtime.DeleteCheckpointResponse, error) {
	if request == nil || request.CheckpointDir == "" || request.CheckpointID == "" ||
		request.SourceSandboxID == "" || request.ExpectedSize <= 0 || request.ExpectedSha256 == "" {
		return nil, checkpointGRPCError(fmt.Errorf(
			"checkpoint_dir, checkpoint_id, source_sandbox_id, expected_size, and expected_sha256 are required: %w",
			errord.ErrInvalidArgument))
	}
	checkpointDir, err := h.resolveManagedCheckpointDir(request.CheckpointDir)
	if err != nil {
		return nil, checkpointGRPCError(err)
	}
	err = checkpoint.DeleteAt(checkpointDir, checkpoint.DeleteIdentity{
		CheckpointID: request.CheckpointID,
		SourceID:     request.SourceSandboxID,
		ImageSize:    request.ExpectedSize,
		ImageSHA256:  request.ExpectedSha256,
	})
	if err != nil {
		return nil, checkpointGRPCError(err)
	}
	return &runtime.DeleteCheckpointResponse{}, nil
}

func (h *sandboxService) Restore(
	ctx context.Context,
	request *runtime.RestoreRequest,
) (*runtime.StartResponse, error) {
	if request == nil || request.Config == nil || request.CheckpointDir == "" {
		return nil, checkpointGRPCError(fmt.Errorf(
			"config and checkpoint_dir are required: %w", errord.ErrInvalidArgument))
	}
	if request.CheckpointID != "" || request.ExpectedSha256 != "" || request.ExpectedSize != 0 {
		return h.restoreCheckpoint(ctx, request)
	}
	checkpointDir, err := h.resolveManagedCheckpointDir(request.CheckpointDir)
	if err != nil {
		return nil, checkpointGRPCError(err)
	}
	startConfig, err := normalizeRestoreConfig(request.Config)
	if err != nil {
		return nil, checkpointGRPCError(err)
	}
	if startConfig.Runtime != config.RuntimeNameRunsc {
		return nil, checkpointGRPCError(fmt.Errorf(
			"runtime %q does not support restore: %w", startConfig.Runtime, errord.ErrNotImplemented))
	}
	imagePath := filepath.Join(checkpointDir, checkpoint.ImageName)
	info, err := os.Lstat(imagePath)
	if err != nil || !info.Mode().IsRegular() {
		return nil, checkpointGRPCError(fmt.Errorf(
			"legacy checkpoint image is missing or not a regular file: %w", errord.ErrFailedPrecondition))
	}
	response, err := h.createSandbox(ctx, startConfig, createOptions{checkpointImage: imagePath})
	if err != nil {
		return nil, checkpointGRPCError(err)
	}
	return response, nil
}

func (h *sandboxService) restoreCheckpoint(
	ctx context.Context,
	request *runtime.RestoreRequest,
) (*runtime.StartResponse, error) {
	if request == nil || request.Config == nil || request.Config.SandboxID == "" ||
		request.CheckpointDir == "" || request.CheckpointID == "" ||
		request.ExpectedSha256 == "" || request.ExpectedSize <= 0 {
		return nil, checkpointGRPCError(fmt.Errorf(
			"config, config.sandbox_id, checkpoint_dir, checkpoint_id, expected_sha256, and expected_size are required: %w",
			errord.ErrInvalidArgument))
	}
	checkpointDir, err := h.resolveManagedCheckpointDir(request.CheckpointDir)
	if err != nil {
		return nil, checkpointGRPCError(err)
	}
	startConfig, err := normalizeRestoreConfig(request.Config)
	if err != nil {
		return nil, checkpointGRPCError(err)
	}
	fingerprint, err := restoreFingerprint(startConfig, request.CheckpointID)
	if err != nil {
		return nil, checkpointGRPCError(err)
	}
	restoreIdentity := &physicalstate.RestoreIdentity{
		CheckpointID: request.CheckpointID, RequestSha256: fingerprint,
	}
	if existing, found, existingErr := h.existingRestorePhysicalFact(ctx, startConfig, restoreIdentity); found || existingErr != nil {
		if existingErr != nil {
			return nil, checkpointGRPCError(existingErr)
		}
		return existing, nil
	}
	imagePath, err := verifyExternalCheckpoint(checkpointDir, request.ExpectedSize, request.ExpectedSha256)
	if err != nil {
		return nil, checkpointGRPCError(err)
	}
	if startConfig.Runtime != config.RuntimeNameRunsc {
		return nil, checkpointGRPCError(fmt.Errorf(
			"runtime %q does not support restore: %w", startConfig.Runtime, errord.ErrNotImplemented))
	}
	releaseOperation, ok := h.acquireCheckpointOperation()
	if !ok {
		return nil, checkpointGRPCError(fmt.Errorf("sandbox service is shutting down: %w", errord.ErrUnavailable))
	}
	attempt, execute, err := h.checkpointState.BeginRestore(startConfig.SandboxID, fingerprint)
	if err != nil {
		releaseOperation()
		return nil, checkpointGRPCError(err)
	}
	if execute {
		operationCtx := h.checkpointOperationContext(ctx)
		go func() {
			defer releaseOperation()
			h.executeRestore(operationCtx, imagePath, startConfig, restoreIdentity, attempt)
		}()
	} else {
		releaseOperation()
	}
	if err := attempt.Wait(ctx); err != nil {
		return nil, checkpointGRPCError(err)
	}
	physical, err := h.sandboxManager.Get(startConfig.SandboxID)
	if err != nil || physical.Metadata == nil {
		return nil, checkpointGRPCError(fmt.Errorf(
			"restored sandbox physical fact is missing: %w", errord.ErrFailedPrecondition))
	}
	return &runtime.StartResponse{
		ID: startConfig.SandboxID, Ports: clonePorts(physical.Metadata.Ports),
	}, nil
}

func (h *sandboxService) existingRestorePhysicalFact(
	ctx context.Context,
	request *runtime.StartRequest,
	expectedIdentity *physicalstate.RestoreIdentity,
) (*runtime.StartResponse, bool, error) {
	if request == nil || request.SandboxID == "" {
		return nil, false, nil
	}
	physical, err := h.sandboxManager.Get(request.SandboxID)
	if err != nil {
		if errors.Is(err, errord.ErrNotFound) {
			return nil, false, nil
		}
		return nil, true, err
	}
	if physical == nil || physical.Metadata == nil {
		return nil, true, fmt.Errorf("sandbox %s physical metadata is incomplete: %w",
			request.SandboxID, errord.ErrFailedPrecondition)
	}
	metadata := physical.Metadata
	if metadata.PhysicalPhase != physicalstate.PhysicalPhase_PHYSICAL_PHASE_COMMITTED {
		return nil, true, fmt.Errorf("sandbox %s physical record is not committed: %w",
			request.SandboxID, errord.ErrFailedPrecondition)
	}
	if expectedIdentity == nil || !proto.Equal(metadata.RestoreIdentity, expectedIdentity) {
		return nil, true, fmt.Errorf("sandbox %s restore identity conflicts with replay: %w",
			request.SandboxID, errord.ErrFailedPrecondition)
	}
	if metadata.RuntimeHandler != request.Runtime {
		return nil, true, fmt.Errorf("sandbox %s runtime conflicts with restore replay: %w",
			request.SandboxID, errord.ErrFailedPrecondition)
	}
	for key, expected := range request.Labels {
		if metadata.Labels[key] != expected {
			return nil, true, fmt.Errorf("sandbox %s label %q conflicts with restore replay: %w",
				request.SandboxID, key, errord.ErrFailedPrecondition)
		}
	}
	if err := validateReplayPorts(request.SandboxID, request.Ports, metadata.Ports); err != nil {
		return nil, true, err
	}
	runtimeFact, exists, err := h.runtimePhysicalFact(ctx, metadata.RuntimeHandler, metadata.ID)
	if err != nil {
		return nil, true, err
	}
	if !exists || runtimeFact.Status != svc.SandboxStatusRunning {
		return nil, false, nil
	}
	return &runtime.StartResponse{
		ID:    metadata.ID,
		Ports: clonePorts(metadata.Ports),
	}, true, nil
}

func validateReplayPorts(sandboxID string, requested, physical []string) error {
	if len(requested) != len(physical) {
		return fmt.Errorf("sandbox %s port count conflicts with restore replay: %w",
			sandboxID, errord.ErrFailedPrecondition)
	}
	for index := range requested {
		want, wantErr := parseDnatRule(sandboxID, requested[index], "")
		actual, actualErr := parseDnatRule(sandboxID, physical[index], "")
		if wantErr != nil || actualErr != nil || actual.DstPort == 0 || !portRequestMatchesFact(want, actual) {
			return fmt.Errorf("sandbox %s port request conflicts with physical fact: %w",
				sandboxID, errord.ErrFailedPrecondition)
		}
	}
	return nil
}

func (h *sandboxService) executeRestore(
	ctx context.Context,
	imagePath string,
	startConfig *runtime.StartRequest,
	restoreIdentity *physicalstate.RestoreIdentity,
	attempt *checkpointstate.Attempt,
) {
	err := h.restorePhysicalSandbox(ctx, imagePath, startConfig, restoreIdentity)
	h.checkpointState.Complete(attempt, err)
}

func (h *sandboxService) restorePhysicalSandbox(
	ctx context.Context, imagePath string, startConfig *runtime.StartRequest,
	restoreIdentity *physicalstate.RestoreIdentity,
) error {
	running, err := h.reconcileRestoreRecord(ctx, startConfig, restoreIdentity)
	if err != nil {
		return err
	}
	if running {
		return nil
	}
	_, err = h.createSandbox(ctx, startConfig, createOptions{
		checkpointImage: imagePath,
		restoreIdentity: restoreIdentity,
		onReserved: func(_ *runtime.StartRequest, sandboxID string) error {
			if sandboxID != startConfig.SandboxID {
				return fmt.Errorf("restore reserved sandbox %q, want %q: %w",
					sandboxID, startConfig.SandboxID, errord.ErrFailedPrecondition)
			}
			return nil
		},
	})
	return err
}

func normalizeRestoreConfig(input *runtime.StartRequest) (*runtime.StartRequest, error) {
	if input == nil || input.Rootfs == nil {
		return nil, fmt.Errorf("rootfs is required: %w", errord.ErrInvalidArgument)
	}
	configCopy := proto.Clone(input).(*runtime.StartRequest)
	if rootfsLimit := configCopy.Rootfs.WritableLayerSizeBytes; rootfsLimit > 0 {
		if configCopy.WritableLayerLimitBytes > 0 && configCopy.WritableLayerLimitBytes != rootfsLimit {
			return nil, fmt.Errorf("conflicting writable layer limits: %w", errord.ErrInvalidArgument)
		}
		configCopy.WritableLayerLimitBytes = rootfsLimit
	}
	if configCopy.Runtime == "" {
		configCopy.Runtime = config.RuntimeNameRunsc
	}
	if configCopy.Cwd == "" {
		configCopy.Cwd = "/"
	}
	if configCopy.Stdout == "" {
		configCopy.Stdout = os.DevNull
	}
	if configCopy.Stderr == "" {
		configCopy.Stderr = os.DevNull
	}
	if configCopy.Network == "" {
		configCopy.Network = "sandbox"
	}
	configCopy.TraceID = ""
	return configCopy, nil
}

func restoreFingerprint(config *runtime.StartRequest, canonicalDir string) (string, error) {
	normalized, err := normalizeRestoreConfig(config)
	if err != nil {
		return "", err
	}
	identity, err := physicalstate.NewRestoreIdentity(canonicalDir, normalized)
	if err != nil {
		return "", err
	}
	return identity.RequestSha256, nil
}

func (h *sandboxService) checkpointOperationContext(requestCtx context.Context) context.Context {
	base := h.operationCtx
	if base == nil {
		base = context.Background()
	}
	traceID, spanID := trace.GetContextID(requestCtx)
	ctx := context.WithValue(base, trace.ContextKeyTraceId, traceID.String())
	return context.WithValue(ctx, trace.ContextKeySpanId, spanID.String())
}

func (h *sandboxService) executeCheckpoint(
	ctx context.Context,
	checkpointDir string,
	key checkpointstate.CheckpointKey,
	checkpointHandler managedCheckpointHandler,
	source checkpoint.SourceIdentity,
	leaveRunning bool,
	attempt *checkpointstate.Attempt,
) {
	_, err := checkpoint.PublishAt(checkpointDir, source, func(imagePath string) error {
		if err := checkpointHandler.Checkpoint(ctx, key.SandboxID, filepath.Dir(imagePath), leaveRunning); err != nil {
			return fmt.Errorf("runtime checkpoint failed: %w", err)
		}
		if leaveRunning {
			return nil
		}
		status, err := h.sandboxManager.WaitForExit(ctx, key.SandboxID)
		if err != nil {
			return fmt.Errorf("wait for sandbox exit after checkpoint: %w", err)
		}
		if state := status.State(); state != runtime.SandboxState_SANDBOX_STATE_EXITED {
			return fmt.Errorf("sandbox state after checkpoint is %s: %w", state,
				errord.ErrFailedPrecondition)
		}
		return nil
	})
	h.checkpointState.Complete(attempt, err)
}

func checkpointFingerprint(request *runtime.CheckpointRequest, canonicalDir string) (string, error) {
	normalized := proto.Clone(request).(*runtime.CheckpointRequest)
	normalized.CheckpointID = canonicalDir
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(normalized)
	if err != nil {
		return "", fmt.Errorf("marshal checkpoint request: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func verifyExternalCheckpoint(directory string, expectedSize int64, expectedSHA256 string) (string, error) {
	cleaned, err := filepath.Abs(filepath.Clean(directory))
	if err != nil {
		return "", fmt.Errorf("resolve checkpoint directory: %w", errord.ErrInvalidArgument)
	}
	info, err := os.Lstat(cleaned)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", fmt.Errorf("checkpoint directory must be a real directory: %w",
			errord.ErrFailedPrecondition)
	}
	imagePath := filepath.Join(cleaned, checkpoint.ImageName)
	image, err := os.Open(imagePath)
	if err != nil {
		return "", fmt.Errorf("open checkpoint image: %w", errord.ErrFailedPrecondition)
	}
	defer image.Close()
	imageInfo, err := image.Stat()
	if err != nil || !imageInfo.Mode().IsRegular() || imageInfo.Size() != expectedSize {
		return "", fmt.Errorf("checkpoint image size differs from SnapshotInfo: %w",
			errord.ErrFailedPrecondition)
	}
	digest := sha256.New()
	written, err := io.Copy(digest, image)
	if err != nil || written != expectedSize ||
		!strings.EqualFold(hex.EncodeToString(digest.Sum(nil)), expectedSHA256) {
		return "", fmt.Errorf("checkpoint image digest differs from SnapshotInfo: %w",
			errord.ErrFailedPrecondition)
	}
	return imagePath, nil
}

func (h *sandboxService) resolveManagedCheckpointDir(directory string) (string, error) {
	root, err := filepath.Abs(filepath.Join(h.config.RootDir, "checkpoints"))
	if err != nil {
		return "", fmt.Errorf("resolve checkpoint root: %w", errord.ErrInvalidArgument)
	}
	cleaned, err := filepath.Abs(filepath.Clean(directory))
	if err != nil {
		return "", fmt.Errorf("resolve checkpoint directory: %w", errord.ErrInvalidArgument)
	}
	relative, err := filepath.Rel(root, cleaned)
	if err != nil || relative == "." || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("checkpoint directory must be below %s: %w",
			root, errord.ErrInvalidArgument)
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return "", fmt.Errorf("create checkpoint root: %w", err)
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return "", fmt.Errorf("checkpoint root must be a real directory: %w",
			errord.ErrFailedPrecondition)
	}
	current := root
	components := strings.Split(relative, string(filepath.Separator))
	for _, component := range components {
		current = filepath.Join(current, component)
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, os.ErrNotExist) {
			break
		}
		if statErr != nil {
			return "", fmt.Errorf("inspect managed checkpoint path: %w", statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", fmt.Errorf("managed checkpoint path contains a non-directory or symlink: %w",
				errord.ErrFailedPrecondition)
		}
	}
	return cleaned, nil
}

func rootfsIdentity(rootfs *runtime.RootfsConfig) ([32]byte, error) {
	if rootfs == nil || rootfs.Source == nil {
		return [32]byte{}, fmt.Errorf("rootfs source is required: %w", errord.ErrFailedPrecondition)
	}
	normalized := proto.Clone(rootfs).(*runtime.RootfsConfig)
	normalized.WritableLayerSizeBytes = 0
	if s3 := normalized.GetS3Config(); s3 != nil {
		s3.AccessKeyID = ""
		s3.AccessKeySecret = ""
	}
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(normalized)
	if err != nil {
		return [32]byte{}, fmt.Errorf("marshal rootfs identity: %w", err)
	}
	return sha256.Sum256(data), nil
}

func checkpointGRPCError(err error) error {
	if err == nil {
		return nil
	}
	mapped := errord.ToGRPC(err)
	if _, ok := status.FromError(mapped); ok {
		return mapped
	}
	if errors.Is(err, context.Canceled) {
		return status.Error(codes.Canceled, err.Error())
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return status.Error(codes.DeadlineExceeded, err.Error())
	}
	return status.Error(codes.Internal, err.Error())
}
