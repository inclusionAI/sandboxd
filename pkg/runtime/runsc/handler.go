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

package runsc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/inclusionAI/sandboxd/internal/trace"
	"github.com/inclusionAI/sandboxd/internal/util"

	"github.com/inclusionAI/sandboxd/config"
	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
	runtimecommon "github.com/inclusionAI/sandboxd/pkg/runtime/internal/common"
	"github.com/sirupsen/logrus"
)

var _ runtimecore.Handler = &Handler{}
var _ runtimecore.CheckpointHandler = &Handler{}
var _ runtimecore.CheckpointRestoreCapabilitiesProvider = &Handler{}
var _ runtimecore.SandboxDefaultsProvider = &Handler{}

const (
	ImageName                  = "rootfs.img"
	SplitSeparator             = "__.__"
	checkpointImageName        = "checkpoint.img"
	runscRestoreCleanupTimeout = 20 * time.Second
	checkpointHandoffPath      = "/proc/gvisor/checkpoint"
	restoreEnvPath             = "/proc/gvisor/spec_environ"
)

// Handler manages the runsc sandbox lifecycle.
type Handler struct {
	runsc     runscClient
	ociLoader runtimecore.OciLoader

	rootfsOverlayTmpfsSize string
	filestoreDir           string
	sandboxRoot            string
	mountEROFS             runtimecommon.EROFSImageMounter
}

type runscClient interface {
	Create(context.Context, StartArgs) error
	Start(context.Context, StartArgs) error
	Checkpoint(context.Context, string, string, bool, bool) error
	Restore(context.Context, StartArgs, string) error
	Wait(context.Context, string) (int, error)
	Delete(context.Context, string, bool) error
	ListJSON(context.Context) ([]byte, error)
}

func NewHandler(cfg config.Config, bin string, loader runtimecore.OciLoader) (*Handler, error) {
	if cfg.RuntimeConfig.FilestoreDir == "" {
		return nil, fmt.Errorf("runsc requires plugin.runtime.filestore_dir")
	}
	platform, err := config.NormalizeRunscPlatform(cfg.RuntimeConfig.Runsc.Platform)
	if err != nil {
		return nil, fmt.Errorf("configure runsc: %w", err)
	}
	root := cfg.RootDir
	if err := validateExtraArgs(cfg.RuntimeConfig.Runsc.ExtraArgs); err != nil {
		return nil, fmt.Errorf("configure runsc: %w", err)
	}
	runscRoot := filepath.Join(root, config.RuntimeNameRunsc)
	if err := os.MkdirAll(runscRoot, 0711); err != nil {
		return nil, err
	}
	runscLogDir := filepath.Join(filepath.Dir(filepath.Dir(root)), "logs", config.RuntimeNameRunsc)
	if err := os.MkdirAll(runscLogDir, 0755); err != nil {
		return nil, err
	}
	runscLogPath := filepath.Join(runscLogDir, "runsc.log")
	mountEROFS, err := runtimecommon.NewEROFSImageMounter(cfg.RuntimeConfig.LoopDeviceDir)
	if err != nil {
		return nil, fmt.Errorf("initialize EROFS loop manager: %w", err)
	}

	return &Handler{
		runsc: NewClientWithOptions(bin, runscRoot, Options{
			ExtraArgs:        cfg.RuntimeConfig.Runsc.ExtraArgs,
			Platform:         platform,
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
	}, nil
}

func (r *Handler) SandboxDefaults() runtimecore.SandboxDefaults {
	return runtimecore.LoaderSandboxDefaults(r.ociLoader)
}

func (r *Handler) CheckpointRestoreCapabilities() runtimecore.CheckpointRestoreCapabilities {
	return runtimecore.CheckpointRestoreCapabilities{
		CheckpointHandoffPath: checkpointHandoffPath,
		RestoreEnvPath:        restoreEnvPath,
	}
}

func (r *Handler) Start(ctx context.Context, config runtimecore.StartConfig) error {
	traceID, _ := trace.GetContextID(ctx)
	if config.Network == nil {
		return fmt.Errorf("network is required")
	}

	rootOverlay, rootOverlaySize, err := r.resolveRootOverlay(config.WritableLayerLimitBytes)
	if err != nil {
		return err
	}
	bundlePath, ociSpec, err := r.ociLoader.GenerateOci(runtimecore.OciLoadOptions{
		SandboxID:                       config.ID,
		Config:                          config,
		CgroupPath:                      config.CgroupPath,
		UseGVisorRootfsImageAnnotations: true,
		RootfsOverlayDir:                r.filestoreDir,
		RootfsOverlaySize:               rootOverlaySize,
	})
	if err != nil {
		return fmt.Errorf("generate OCI bundle: %w", err)
	}
	mountTargetsReady, err := runtimecore.RootfsMountTargetsReady(bundlePath, ociSpec)
	if err != nil {
		return fmt.Errorf("inspect rootfs mount targets: %w", err)
	}
	requiresHostWritableRootfs := config.SpecUpdates != nil &&
		config.SpecUpdates.RequiresHostWritableRootfs
	var cleanupNVProxyRootfs func() error
	if requiresHostWritableRootfs || !mountTargetsReady {
		cleanupNVProxyRootfs, err = prepareRunscPrivateRootfsWithMounter(
			bundlePath,
			ociSpec,
			requiresHostWritableRootfs,
			r.mountEROFS,
		)
		if err != nil {
			return fmt.Errorf("prepare private runsc rootfs: %w", err)
		}
	}

	startArgs := StartArgs{
		ID:          config.ID,
		BundleDir:   bundlePath,
		UserStdout:  config.Stdout,
		UserStderr:  config.Stderr,
		RootOverlay: rootOverlay,
		Network: NetworkConfig{
			Interface:   config.Network.Interface,
			LinkAddress: config.Network.GuestHardwareAddr(),
			IP:          config.Network.Ip,
			Mask:        config.Network.Mask,
			Gateway:     config.Network.Gateway,
		},
	}
	start := time.Now()
	if err := r.runsc.Create(ctx, startArgs); err != nil {
		if cleanupNVProxyRootfs != nil {
			return errors.Join(err, cleanupNVProxyRootfs())
		}
		return err
	}
	if err := r.runsc.Start(ctx, startArgs); err != nil {
		r.cleanupOnFailure(ctx, traceID.String(), config.ID, "runsc start failed")
		if cleanupNVProxyRootfs != nil {
			return errors.Join(err, cleanupNVProxyRootfs())
		}
		return err
	}
	logrus.WithField(trace.ContextKeyTraceId, traceID).Debugf("call runsc create/start, args: %+v, cost: %v", startArgs, time.Since(start))
	return nil
}

func (r *Handler) Checkpoint(ctx context.Context, config runtimecore.CheckpointConfig) error {
	return r.runsc.Checkpoint(
		ctx,
		config.ID,
		config.Directory,
		config.Compress,
		config.LeaveRunning,
	)
}

func (r *Handler) Restore(
	ctx context.Context,
	config runtimecore.StartConfig,
) (retErr error) {
	traceID, _ := trace.GetContextID(ctx)
	if config.Network == nil {
		return fmt.Errorf("network is required")
	}
	rootOverlay, rootOverlaySize, err := r.resolveRootOverlay(
		config.WritableLayerLimitBytes,
	)
	if err != nil {
		return err
	}
	bundlePath, ociSpec, err := r.ociLoader.GenerateOci(runtimecore.OciLoadOptions{
		SandboxID:                       config.ID,
		Config:                          config,
		CgroupPath:                      config.CgroupPath,
		UseGVisorRootfsImageAnnotations: true,
		RootfsOverlayDir:                r.filestoreDir,
		RootfsOverlaySize:               rootOverlaySize,
	})
	if err != nil {
		return fmt.Errorf("generate OCI bundle: %w", err)
	}
	mountTargetsReady, err := runtimecore.RootfsMountTargetsReady(bundlePath, ociSpec)
	if err != nil {
		return fmt.Errorf("inspect rootfs mount targets: %w", err)
	}
	requiresHostWritableRootfs := config.SpecUpdates != nil &&
		config.SpecUpdates.RequiresHostWritableRootfs
	var cleanupNVProxyRootfs func() error
	if requiresHostWritableRootfs || !mountTargetsReady {
		cleanupNVProxyRootfs, err = prepareRunscPrivateRootfsWithMounter(
			bundlePath,
			ociSpec,
			requiresHostWritableRootfs,
			r.mountEROFS,
		)
		if err != nil {
			return fmt.Errorf("prepare private runsc rootfs: %w", err)
		}
	}
	cleanupFailure := func() error {
		cleanupCtx, cancel := context.WithTimeout(
			context.Background(),
			runscRestoreCleanupTimeout,
		)
		defer cancel()
		cleanupErr := r.runsc.Delete(cleanupCtx, config.ID, true)
		if cleanupNVProxyRootfs != nil {
			cleanupErr = errors.Join(cleanupErr, cleanupNVProxyRootfs())
		}
		return cleanupErr
	}

	startArgs := StartArgs{
		ID:          config.ID,
		BundleDir:   bundlePath,
		UserStdout:  config.Stdout,
		UserStderr:  config.Stderr,
		RootOverlay: rootOverlay,
		Network: NetworkConfig{
			Interface:   config.Network.Interface,
			LinkAddress: config.Network.GuestHardwareAddr(),
			IP:          config.Network.Ip,
			Mask:        config.Network.Mask,
			Gateway:     config.Network.Gateway,
		},
	}
	start := time.Now()
	if err := r.runsc.Create(ctx, startArgs); err != nil {
		return errors.Join(err, cleanupFailure())
	}
	imagePath := filepath.Join(config.CheckpointDir, checkpointImageName)
	if err := r.runsc.Restore(ctx, startArgs, imagePath); err != nil {
		return errors.Join(err, cleanupFailure())
	}
	logrus.WithField(trace.ContextKeyTraceId, traceID).Debugf(
		"call runsc create/restore, args: %+v, cost: %v",
		startArgs,
		time.Since(start),
	)
	return nil
}

func (r *Handler) resolveRootOverlay(limitBytes uint64) (string, string, error) {
	if r.filestoreDir == "" {
		return "", "", errors.New("writable layers require a configured filestore directory")
	}
	size := r.rootfsOverlayTmpfsSize
	if limitBytes > 0 {
		size = strconv.FormatUint(limitBytes, 10)
	}
	return RootFileOverlay(r.filestoreDir, size), size, nil
}

func (r *Handler) Delete(ctx context.Context, sandboxID string) error {
	traceID, _ := trace.GetContextID(ctx)
	start := time.Now()
	if err := r.runsc.Delete(ctx, sandboxID, true); err != nil {
		return err
	}
	bundlePath, err := util.JoinWithinRoot(r.sandboxRoot, sandboxID)
	if err != nil {
		return fmt.Errorf("resolve runsc sandbox bundle: %w", err)
	}
	if err := cleanupRunscNVProxyRootfs(bundlePath); err != nil {
		return err
	}
	logrus.WithField(trace.ContextKeyTraceId, traceID).Debugf("call runsc delete, cost: %v", time.Since(start))
	return nil
}

func (r *Handler) List(ctx context.Context) ([]*runtimecore.State, error) {
	containers := make([]*runtimecore.State, 0)
	output, err := r.runsc.ListJSON(ctx)
	if err != nil {
		return containers, err
	}
	err = json.Unmarshal(output, &containers)
	return containers, err
}

func (r *Handler) Wait(ctx context.Context, sandboxID string) (runtimecore.Exit, error) {
	status, err := r.runsc.Wait(ctx, sandboxID)
	return runtimecore.Exit{
		ExitedAt: time.Now(),
		ExitCode: status,
	}, err
}

func (r *Handler) cleanupOnFailure(ctx context.Context, traceID, sandboxID, msg string) {
	logrus.WithField(trace.ContextKeyTraceId, traceID).Debugf("%s", msg)
	if err := r.runsc.Delete(ctx, sandboxID, true); err != nil {
		logrus.WithField(trace.ContextKeyTraceId, traceID).Warnf(
			"cleanup runsc sandbox %s after failure: %v", sandboxID, err,
		)
	}
}
