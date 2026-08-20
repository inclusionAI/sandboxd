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

package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/inclusionAI/sandboxd/internal/physicalstate"
	"github.com/inclusionAI/sandboxd/internal/trace"
	"github.com/inclusionAI/sandboxd/internal/util"
	runscapi "github.com/inclusionAI/sandboxd/pkg/runtime/runsc"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	"github.com/sirupsen/logrus"
)

var _ Handler = &RunscHandler{}

const (
	ImageName                  = "rootfs.img"
	SplitSeparator             = "__.__"
	gvisorCheckpointImageName  = "checkpoint.img"
	runscFailureCleanupTimeout = 20 * time.Second
	runscFailureCleanupRetries = 3
	runscFailureCleanupBackoff = 50 * time.Millisecond
)

type RunscHandler struct {
	runsc     runscClient
	ociLoader OciLoader

	rootfsOverlayTmpfsSize string
	filestoreDir           string
	sandboxRoot            string
	mountEROFS             erofsImageMounter
	checkpointRoot         string
}

type runscClient interface {
	Create(context.Context, runscapi.StartArgs) error
	Start(context.Context, runscapi.StartArgs) error
	Checkpoint(context.Context, string, string, bool) error
	Restore(context.Context, runscapi.StartArgs, string) error
	Wait(context.Context, string) (int, error)
	Delete(context.Context, string, bool) error
	ListJSON(context.Context) ([]byte, error)
}

func NewRunscHandler(cfg config.Config, bin string, loader OciLoader) (*RunscHandler, error) {
	if cfg.RuntimeConfig.FilestoreDir == "" {
		return nil, fmt.Errorf("runsc requires plugin.runtime.filestore_dir")
	}
	root := cfg.RootDir
	runscRoot := filepath.Join(root, config.RuntimeNameRunsc)
	if err := os.MkdirAll(runscRoot, 0711); err != nil {
		return nil, err
	}
	runscLogDir := filepath.Join(filepath.Dir(filepath.Dir(root)), "logs", config.RuntimeNameRunsc)
	if err := os.MkdirAll(runscLogDir, 0755); err != nil {
		return nil, err
	}
	runscLogPath := filepath.Join(runscLogDir, "runsc.log")
	mountEROFS, err := newEROFSImageMounter(cfg.RuntimeConfig.LoopDeviceDir)
	if err != nil {
		return nil, fmt.Errorf("initialize EROFS loop manager: %w", err)
	}
	checkpointRoot := filepath.Join(root, config.GVisorCheckpointDirName)
	if err := os.MkdirAll(checkpointRoot, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(checkpointRoot, 0700); err != nil {
		return nil, err
	}

	return &RunscHandler{
		runsc: runscapi.NewClientWithOptions(bin, runscRoot, runscapi.Options{
			FilestoreDir:     cfg.RuntimeConfig.FilestoreDir,
			OverlayTmpfsSize: cfg.RuntimeConfig.OverlayTmpfsSize,
			DebugLogPath:     runscLogPath,
			IgnoreCgroups:    cfg.DisableCgroup,
		}),
		ociLoader:              loader,
		rootfsOverlayTmpfsSize: cfg.RuntimeConfig.OverlayTmpfsSize,
		filestoreDir:           cfg.RuntimeConfig.FilestoreDir,
		sandboxRoot:            filepath.Join(root, "containers"),
		mountEROFS:             mountEROFS,
		checkpointRoot:         checkpointRoot,
	}, nil
}

func (r *RunscHandler) Start(ctx context.Context, config StartConfig) error {
	traceID, _ := trace.GetContextID(ctx)
	startArgs, cleanupPrepared, err := r.prepareStart(config)
	if err != nil {
		return err
	}
	start := time.Now()
	if err := r.runsc.Create(ctx, startArgs); err != nil {
		return errors.Join(err, cleanupPrepared())
	}
	if err := r.runsc.Start(ctx, startArgs); err != nil {
		r.cleanupOnFailure(ctx, traceID.String(), config.ID, "runsc start failed")
		return errors.Join(err, cleanupPrepared())
	}
	logrus.WithField(trace.ContextKeyTraceId, traceID).Debugf("call runsc create/start, args: %+v, cost: %v", startArgs, time.Since(start))
	return nil
}

func (r *RunscHandler) prepareStart(startConfig StartConfig) (runscapi.StartArgs, func() error, error) {
	if startConfig.Network == nil {
		return runscapi.StartArgs{}, nil, fmt.Errorf("network is required")
	}
	rootOverlay, rootOverlaySize, err := r.resolveRootOverlay(startConfig.WritableLayerLimitBytes)
	if err != nil {
		return runscapi.StartArgs{}, nil, err
	}
	checkpointDir, err := r.newCheckpointCoordinationDir(startConfig.ID)
	if err != nil {
		return runscapi.StartArgs{}, nil, fmt.Errorf("create gVisor checkpoint coordination directory: %w", err)
	}
	cleanupCheckpoint := func() error { return os.RemoveAll(checkpointDir) }

	bundlePath, ociSpec, err := r.ociLoader.GenerateOci(OciLoadOptions{
		SandboxID:                       startConfig.ID,
		Config:                          startConfig,
		CgroupPath:                      startConfig.CgroupPath,
		UseGVisorRootfsImageAnnotations: true,
		RootfsOverlayDir:                r.filestoreDir,
		RootfsOverlaySize:               rootOverlaySize,
		ManagedAnnotations: map[string]string{
			config.GVisorCheckpointPathAnnotation:   checkpointDir,
			config.GVisorCheckpointEnableAnnotation: "false",
		},
	})
	if err != nil {
		return runscapi.StartArgs{}, nil, errors.Join(fmt.Errorf("generate OCI bundle: %w", err), cleanupCheckpoint())
	}
	mountTargetsReady, err := rootfsMountTargetsReady(bundlePath, ociSpec)
	if err != nil {
		return runscapi.StartArgs{}, nil, errors.Join(fmt.Errorf("inspect rootfs mount targets: %w", err), cleanupCheckpoint())
	}
	requiresHostWritableRootfs := startConfig.SpecUpdates != nil &&
		startConfig.SpecUpdates.RequiresHostWritableRootfs
	var cleanupNVProxyRootfs func() error
	if requiresHostWritableRootfs || !mountTargetsReady {
		cleanupNVProxyRootfs, err = prepareRunscPrivateRootfsWithMounter(
			bundlePath,
			ociSpec,
			requiresHostWritableRootfs,
			r.mountEROFS,
		)
		if err != nil {
			return runscapi.StartArgs{}, nil, errors.Join(
				fmt.Errorf("prepare private runsc rootfs: %w", err),
				cleanupCheckpoint(),
			)
		}
	}

	cleanupPrepared := func() error {
		var cleanupErr error
		if cleanupNVProxyRootfs != nil {
			cleanupErr = cleanupNVProxyRootfs()
		}
		return errors.Join(cleanupErr, cleanupCheckpoint())
	}
	return runscapi.StartArgs{
		ID:          startConfig.ID,
		BundleDir:   bundlePath,
		UserStdout:  startConfig.Stdout,
		UserStderr:  startConfig.Stderr,
		RootOverlay: rootOverlay,
		Network: runscapi.NetworkConfig{
			Interface: startConfig.Network.Interface,
			IP:        startConfig.Network.Ip,
			Mask:      startConfig.Network.Mask,
			Gateway:   startConfig.Network.Gateway,
		},
	}, cleanupPrepared, nil
}

func (r *RunscHandler) newCheckpointCoordinationDir(sandboxID string) (string, error) {
	if !config.IsValidSandboxID(sandboxID) {
		return "", fmt.Errorf("invalid sandbox id %q", sandboxID)
	}
	path, err := os.MkdirTemp(r.checkpointRoot, sandboxID+"-")
	if err != nil {
		return "", err
	}
	if err := os.Chmod(path, 0700); err != nil {
		return "", errors.Join(err, os.RemoveAll(path))
	}
	return path, nil
}

func (r *RunscHandler) Checkpoint(
	ctx context.Context, sandboxID, imagePath string, leaveRunning bool,
) error {
	return r.runsc.Checkpoint(ctx, sandboxID, imagePath, leaveRunning)
}

func (r *RunscHandler) Restore(ctx context.Context, startConfig StartConfig, imagePath string) error {
	traceID, _ := trace.GetContextID(ctx)
	startArgs, cleanupPrepared, err := r.prepareStart(startConfig)
	if err != nil {
		return err
	}
	start := time.Now()
	if err := r.runsc.Create(ctx, startArgs); err != nil {
		cleanupErr := r.cleanupRestoreOnFailure(traceID.String(), startConfig.ID, "runsc restore create failed")
		if cleanupErr != nil {
			return errors.Join(err, cleanupErr, physicalstate.ErrRestoreCleanupIncomplete)
		}
		return errors.Join(err, cleanupPrepared())
	}
	if err := r.runsc.Restore(ctx, startArgs, imagePath); err != nil {
		cleanupErr := r.cleanupRestoreOnFailure(traceID.String(), startConfig.ID, "runsc restore failed")
		if cleanupErr != nil {
			return errors.Join(err, cleanupErr, physicalstate.ErrRestoreCleanupIncomplete)
		}
		return errors.Join(err, cleanupPrepared())
	}
	if err := r.removeRestoredCoordinationImage(startArgs.BundleDir); err != nil {
		cleanupErr := r.cleanupRestoreOnFailure(
			traceID.String(), startConfig.ID, "remove restored gVisor coordination image failed",
		)
		if cleanupErr != nil {
			return errors.Join(err, cleanupErr, physicalstate.ErrRestoreCleanupIncomplete)
		}
		return errors.Join(err, cleanupPrepared())
	}
	logrus.WithField(trace.ContextKeyTraceId, traceID).Debugf(
		"call runsc create/restore, args: %+v, cost: %v", startArgs, time.Since(start),
	)
	return nil
}

func (r *RunscHandler) removeRestoredCoordinationImage(bundlePath string) error {
	checkpointDir, err := r.checkpointCoordinationDir(bundlePath)
	if err != nil {
		return fmt.Errorf("resolve restored gVisor checkpoint coordination directory: %w", err)
	}
	if checkpointDir == "" {
		return fmt.Errorf("restored gVisor checkpoint coordination directory is missing")
	}
	imagePath := filepath.Join(checkpointDir, gvisorCheckpointImageName)
	if err := os.Remove(imagePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove restored gVisor checkpoint image %q: %w", imagePath, err)
	}
	return nil
}

func (r *RunscHandler) resolveRootOverlay(limitBytes uint64) (string, string, error) {
	if r.filestoreDir == "" {
		return "", "", errors.New("writable layers require a configured filestore directory")
	}
	size := r.rootfsOverlayTmpfsSize
	if limitBytes > 0 {
		size = strconv.FormatUint(limitBytes, 10)
	}
	return runscapi.RootFileOverlay(r.filestoreDir, size), size, nil
}

func (r *RunscHandler) Delete(ctx context.Context, sandboxID string) error {
	traceID, _ := trace.GetContextID(ctx)
	start := time.Now()
	if err := r.runsc.Delete(ctx, sandboxID, true); err != nil &&
		!errors.Is(err, errord.ErrNotFound) {
		return err
	}
	if err := r.cleanupPreparedState(sandboxID); err != nil {
		return err
	}
	logrus.WithField(trace.ContextKeyTraceId, traceID).Debugf("call runsc delete, cost: %v", time.Since(start))
	return nil
}

func (r *RunscHandler) cleanupPreparedState(sandboxID string) error {
	bundlePath, err := util.JoinWithinRoot(r.sandboxRoot, sandboxID)
	if err != nil {
		return fmt.Errorf("resolve runsc sandbox bundle: %w", err)
	}
	checkpointDir, err := r.checkpointCoordinationDir(bundlePath)
	if err != nil {
		return err
	}
	cleanupErr := cleanupRunscNVProxyRootfs(bundlePath)
	if checkpointDir != "" {
		cleanupErr = errors.Join(cleanupErr, os.RemoveAll(checkpointDir))
	}
	if cleanupErr != nil {
		return cleanupErr
	}
	return nil
}

func (r *RunscHandler) checkpointCoordinationDir(bundlePath string) (string, error) {
	spec, err := LoadSpec(filepath.Join(bundlePath, config.SandboxSpecFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("load runsc OCI spec: %w", err)
	}
	path := spec.Annotations[config.GVisorCheckpointPathAnnotation]
	if path == "" {
		return "", nil
	}
	root, err := filepath.Abs(r.checkpointRoot)
	if err != nil {
		return "", err
	}
	target, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == "." || rel == ".." || filepath.IsAbs(rel) ||
		strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("gVisor checkpoint coordination path %q is outside %q", target, root)
	}
	return target, nil
}

func (r *RunscHandler) List(ctx context.Context) ([]*State, error) {
	containers := make([]*State, 0)
	output, err := r.runsc.ListJSON(ctx)
	if err != nil {
		return containers, err
	}
	if err := json.Unmarshal(output, &containers); err != nil {
		return containers, err
	}
	for _, state := range containers {
		if state == nil || state.Status != SandboxStatusRunning ||
			runscSandboxProcessMatches(state.InitProcessPid, state.ID) {
			continue
		}
		logrus.WithFields(logrus.Fields{
			"sandbox_id": state.ID,
			"pid":        state.InitProcessPid,
		}).Warn("runsc state reported RUNNING without a matching live sandbox process")
		state.Status = SandboxStatusExited
	}
	return containers, nil
}

func runscSandboxProcessMatches(pid int, sandboxID string) bool {
	if pid <= 0 || sandboxID == "" {
		return false
	}
	procDir := filepath.Join("/proc", strconv.Itoa(pid))
	stat, err := os.ReadFile(filepath.Join(procDir, "stat"))
	if err != nil {
		return false
	}
	closingParen := bytes.LastIndexByte(stat, ')')
	if closingParen < 0 {
		return false
	}
	fields := strings.Fields(string(stat[closingParen+1:]))
	if len(fields) == 0 || fields[0] == "Z" || fields[0] == "X" || fields[0] == "x" {
		return false
	}
	cmdline, err := os.ReadFile(filepath.Join(procDir, "cmdline"))
	if err != nil {
		return false
	}
	arguments := bytes.Split(bytes.TrimRight(cmdline, "\x00"), []byte{0})
	if len(arguments) == 0 || filepath.Base(string(arguments[0])) != "runsc-sandbox" {
		return false
	}
	for _, argument := range arguments[1:] {
		if string(argument) == sandboxID {
			return true
		}
	}
	return false
}

func (r *RunscHandler) Wait(ctx context.Context, sandboxID string) (Exit, error) {
	status, err := r.runsc.Wait(ctx, sandboxID)
	return Exit{
		ExitedAt: time.Now(),
		ExitCode: status,
	}, err
}

func (r *RunscHandler) cleanupRestoreOnFailure(traceID, sandboxID, msg string) error {
	ctx, cancel := context.WithTimeout(context.Background(), runscFailureCleanupTimeout)
	defer cancel()
	logrus.WithField(trace.ContextKeyTraceId, traceID).Debugf("%s", msg)
	var cleanupErr error
	for attempt := 1; attempt <= runscFailureCleanupRetries; attempt++ {
		cleanupErr = r.runsc.Delete(ctx, sandboxID, true)
		if cleanupErr == nil || errors.Is(cleanupErr, errord.ErrNotFound) {
			return nil
		}
		logrus.WithField(trace.ContextKeyTraceId, traceID).Warnf(
			"cleanup runsc sandbox %s after failure (attempt %d/%d): %v",
			sandboxID, attempt, runscFailureCleanupRetries, cleanupErr,
		)
		if attempt == runscFailureCleanupRetries {
			break
		}
		timer := time.NewTimer(time.Duration(attempt) * runscFailureCleanupBackoff)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return errors.Join(cleanupErr, ctx.Err())
		case <-timer.C:
		}
	}
	return fmt.Errorf("cleanup runsc sandbox %s after restore failure: %w", sandboxID, cleanupErr)
}

func (r *RunscHandler) cleanupOnFailure(ctx context.Context, traceID, sandboxID, msg string) {
	logrus.WithField(trace.ContextKeyTraceId, traceID).Debugf("%s", msg)
	if err := r.runsc.Delete(ctx, sandboxID, true); err != nil {
		logrus.WithField(trace.ContextKeyTraceId, traceID).Warnf(
			"cleanup runsc sandbox %s after failure: %v", sandboxID, err,
		)
	}
}
