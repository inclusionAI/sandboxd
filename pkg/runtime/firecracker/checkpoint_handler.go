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

package firecracker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/firecrackerproto"
	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
	runtimecommon "github.com/inclusionAI/sandboxd/pkg/runtime/internal/common"
	"github.com/sirupsen/logrus"
)

func (handler *Handler) Checkpoint(
	ctx context.Context,
	config runtimecore.CheckpointConfig,
) (retErr error) {
	sandboxID := config.ID
	imagePath := filepath.Join(
		config.Directory,
		checkpointImageName,
	)
	instance, err := handler.lookupInstance(sandboxID)
	if err != nil {
		return err
	}
	instance.operationMu.Lock()
	defer instance.operationMu.Unlock()
	state := instance.snapshot()
	if state.Exited || !state.Configured ||
		!firecrackerProcessMatches(state.PID, handler.binary, state.APIPath, state.ID) {
		return fmt.Errorf("Firecracker sandbox %s is not running", sandboxID)
	}

	api := newFirecrackerAPI(state.APIPath)
	if err := api.pause(ctx); err != nil {
		return fmt.Errorf("pause Firecracker sandbox %s: %w", sandboxID, err)
	}
	sourcePaused := true
	handoffReleased := false
	defer func() {
		if retErr == nil || handoffReleased ||
			!firecrackerProcessMatches(state.PID, handler.binary, state.APIPath, state.ID) {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(
			context.WithoutCancel(ctx),
			firecrackerAgentTimeout,
		)
		defer cancel()
		if sourcePaused {
			if err := api.resume(cleanupCtx); err != nil {
				retErr = errors.Join(
					retErr,
					fmt.Errorf("resume Firecracker sandbox %s after checkpoint failure: %w", sandboxID, err),
				)
				return
			}
			sourcePaused = false
		}
		if err := requestFirecrackerAgent(
			cleanupCtx,
			state.VsockPath,
			firecrackerproto.MessageCheckpoint,
			firecrackerproto.CheckpointRequest{Outcome: "error"},
		); err != nil {
			retErr = errors.Join(
				retErr,
				fmt.Errorf("release Firecracker sandbox %s after checkpoint failure: %w", sandboxID, err),
			)
			return
		}
		handoffReleased = true
	}()

	workDir, err := os.MkdirTemp(filepath.Dir(imagePath), ".firecracker-snapshot-")
	if err != nil {
		return fmt.Errorf("create Firecracker checkpoint staging files: %w", err)
	}
	defer os.RemoveAll(workDir)
	memoryPath := filepath.Join(workDir, firecrackerCheckpointMemoryName)
	files := firecrackerCheckpointFiles{
		State:   filepath.Join(workDir, firecrackerCheckpointStateName),
		Memory:  memoryPath,
		Overlay: state.OverlayPath,
	}
	if err := api.createSnapshot(ctx, files.State, files.Memory); err != nil {
		return fmt.Errorf("create Firecracker snapshot for %s: %w", sandboxID, err)
	}
	if err := createFirecrackerCheckpointArchive(
		ctx,
		imagePath,
		config.Compress,
		files,
	); err != nil {
		return fmt.Errorf("package Firecracker checkpoint for %s: %w", sandboxID, err)
	}
	if config.LeaveRunning {
		if err := api.resume(ctx); err != nil {
			return fmt.Errorf("resume Firecracker sandbox %s: %w", sandboxID, err)
		}
		sourcePaused = false
		if err := requestFirecrackerAgent(
			ctx,
			state.VsockPath,
			firecrackerproto.MessageCheckpoint,
			firecrackerproto.CheckpointRequest{Outcome: "resume"},
		); err != nil {
			return fmt.Errorf("release checkpointed Firecracker sandbox %s: %w", sandboxID, err)
		}
		handoffReleased = true
		return nil
	}

	handler.stopInstance(instance, true)
	if firecrackerProcessMatches(state.PID, handler.binary, state.APIPath, state.ID) {
		return fmt.Errorf("stop Firecracker sandbox %s after checkpoint", sandboxID)
	}
	if instance.finish(runtimecore.Exit{ExitedAt: time.Now(), ExitCode: 0}) && instance.shouldPersist() {
		if err := handler.persistInstance(instance); err != nil {
			logrus.Warnf("firecracker: persist checkpoint exit state for %s: %v", sandboxID, err)
		}
	}
	return nil
}

func (handler *Handler) Restore(
	ctx context.Context,
	startConfig runtimecore.StartConfig,
) (retErr error) {
	imagePath := filepath.Join(startConfig.CheckpointDir, checkpointImageName)
	if startConfig.DisableCgroup || startConfig.CgroupPath == "" {
		return errors.New("Firecracker requires a managed cgroup")
	}
	if startConfig.EnableKVM {
		return errors.New("Firecracker does not expose nested KVM to the guest")
	}
	if startConfig.SpecUpdates != nil {
		return errors.New("Firecracker does not support host device-provider OCI updates")
	}
	if startConfig.Network == nil || startConfig.Network.Interface == nil {
		return errors.New("Firecracker requires a cached TAP network")
	}
	handler.mu.RLock()
	_, alreadyRunning := handler.instances[startConfig.ID]
	handler.mu.RUnlock()
	if alreadyRunning {
		return fmt.Errorf("Firecracker sandbox %s already exists", startConfig.ID)
	}

	bundlePath, spec, err := handler.ociLoader.GenerateOci(runtimecore.OciLoadOptions{
		SandboxID:  startConfig.ID,
		Config:     startConfig,
		CgroupPath: startConfig.CgroupPath,
	})
	if err != nil {
		return fmt.Errorf("generate Firecracker restore OCI metadata: %w", err)
	}
	plan, err := prepareFirecrackerStorage(spec, startConfig)
	if err != nil {
		return err
	}
	storageDir, err := createFirecrackerStorageDirectory(handler.storageRoot, startConfig.ID)
	if err != nil {
		return err
	}
	keepStorage := false
	defer func() {
		if !keepStorage {
			retErr = errors.Join(
				retErr,
				cleanupFirecrackerOverlay(handler.storageRoot, startConfig.ID),
			)
		}
	}()

	stateDir := filepath.Join(bundlePath, firecrackerArtifactsDir)
	if err := os.Mkdir(stateDir, 0700); err != nil {
		return fmt.Errorf("create Firecracker restore state directory: %w", err)
	}
	runtimeDir := handler.runtimeDirectory(startConfig.ID)
	runtimeCreated := false
	keepRuntimeArtifacts := false
	defer func() {
		if keepRuntimeArtifacts {
			return
		}
		retErr = errors.Join(retErr, os.RemoveAll(stateDir))
		if runtimeCreated {
			retErr = errors.Join(
				retErr,
				handler.cleanupRuntimeDirectory(startConfig.ID, filepath.Join(
					runtimeDir, firecrackerAPISocket,
				)),
			)
		}
	}()
	if err := os.Mkdir(runtimeDir, 0700); err != nil {
		return fmt.Errorf("create Firecracker socket directory %s: %w", runtimeDir, err)
	}
	runtimeCreated = true
	apiPath := filepath.Join(runtimeDir, firecrackerAPISocket)
	vsockPath := filepath.Join(runtimeDir, firecrackerVsock)
	if len(apiPath) >= 100 || len(vsockPath) >= 100 {
		return fmt.Errorf("Firecracker Unix socket path is too long under %s", runtimeDir)
	}
	if err := removeFirecrackerSocket(apiPath); err != nil {
		return err
	}
	if err := removeFirecrackerSocket(vsockPath); err != nil {
		return err
	}

	checkpointFiles := firecrackerCheckpointFiles{
		State:   filepath.Join(stateDir, firecrackerCheckpointStateName),
		Memory:  filepath.Join(stateDir, firecrackerCheckpointMemoryName),
		Overlay: filepath.Join(storageDir, "overlay.ext4"),
	}
	if err := extractFirecrackerCheckpointArchive(
		ctx,
		imagePath,
		checkpointFiles,
	); err != nil {
		return err
	}
	if err := os.Symlink(checkpointFiles.Overlay, filepath.Join(
		stateDir, firecrackerCheckpointOverlayName,
	)); err != nil {
		return fmt.Errorf("link restored Firecracker writable layer: %w", err)
	}

	stdout, err := openFirecrackerOutput(startConfig.Stdout)
	if err != nil {
		return err
	}
	defer stdout.Close()
	stderr, err := openFirecrackerOutput(startConfig.Stderr)
	if err != nil {
		return err
	}
	defer stderr.Close()
	command := exec.Command(
		handler.binary,
		"--api-sock", apiPath,
		"--id", startConfig.ID,
	)
	command.Dir = stateDir
	command.Stdout = stdout
	command.Stderr = stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		return fmt.Errorf("start Firecracker restore VMM: %w", err)
	}
	instance := &firecrackerInstance{
		state: firecrackerPersistedState{
			ID:          startConfig.ID,
			PID:         command.Process.Pid,
			BundlePath:  bundlePath,
			APIPath:     apiPath,
			VsockPath:   vsockPath,
			OverlayPath: checkpointFiles.Overlay,
			CreatedAt:   time.Now().Format(time.RFC3339Nano),
		},
		done: make(chan struct{}),
	}
	handler.mu.Lock()
	handler.instances[startConfig.ID] = instance
	handler.mu.Unlock()
	go handler.waitCommand(instance, command)

	restoreSucceeded := false
	defer func() {
		if restoreSucceeded {
			return
		}
		instance.markDeleting()
		handler.stopInstance(instance, true)
		handler.mu.Lock()
		delete(handler.instances, startConfig.ID)
		handler.mu.Unlock()
	}()
	if err := attachFirecrackerProcess(startConfig.CgroupPath, command.Process.Pid); err != nil {
		return fmt.Errorf("attach restored Firecracker to cgroup: %w", err)
	}
	if err := handler.persistInstance(instance); err != nil {
		return err
	}

	readyCtx, readyCancel := context.WithTimeout(ctx, firecrackerAgentTimeout)
	api := newFirecrackerAPI(apiPath)
	if err := api.waitReady(readyCtx); err != nil {
		readyCancel()
		return err
	}
	readyCancel()
	if err := api.loadSnapshot(
		ctx,
		checkpointFiles.State,
		checkpointFiles.Memory,
		startConfig.Network.Interface.Name,
		vsockPath,
	); err != nil {
		return fmt.Errorf("load Firecracker checkpoint for %s: %w", startConfig.ID, err)
	}
	agentCtx, agentCancel := context.WithTimeout(ctx, firecrackerAgentTimeout)
	defer agentCancel()
	if err := waitForFirecrackerAgent(agentCtx, vsockPath); err != nil {
		return err
	}
	if err := requestFirecrackerAgent(
		agentCtx,
		vsockPath,
		firecrackerproto.MessageSetNetwork,
		plan.configure.Network,
	); err != nil {
		return fmt.Errorf("configure restored Firecracker network: %w", err)
	}
	if err := requestFirecrackerAgent(
		agentCtx,
		vsockPath,
		firecrackerproto.MessageCheckpoint,
		firecrackerproto.CheckpointRequest{
			Outcome:     "restore",
			Environment: plan.configure.Process.Env,
		},
	); err != nil {
		return fmt.Errorf("release restored Firecracker sandbox: %w", err)
	}
	instance.markConfigured()
	if err := handler.persistInstance(instance); err != nil {
		return err
	}
	go handler.waitGuest(instance)
	if err := runtimecommon.WriteSandboxRuntimeMarker(bundlePath, config.RuntimeNameFirecracker); err != nil {
		return fmt.Errorf("persist Firecracker restore runtime marker: %w", err)
	}
	restoreSucceeded = true
	keepStorage = true
	keepRuntimeArtifacts = true
	logrus.Infof(
		"firecracker: restored sandbox %s pid=%d",
		startConfig.ID,
		command.Process.Pid,
	)
	return nil
}
