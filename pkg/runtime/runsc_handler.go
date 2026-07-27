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
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/inclusionAI/sandboxd/internal/trace"
	runscapi "github.com/inclusionAI/sandboxd/pkg/runtime/runsc"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/sirupsen/logrus"
)

var _ Handler = &RunscHandler{}

const (
	ImageName      = "rootfs.img"
	SplitSeparator = "__.__"
)

type RunscHandler struct {
	runsc     runscClient
	ociLoader OciLoader

	rootfsOverlayTmpfsSize string
}

type runscClient interface {
	Create(context.Context, runscapi.StartArgs) error
	Start(context.Context, runscapi.StartArgs) error
	Wait(context.Context, string) (int, error)
	Delete(context.Context, string, bool) error
	ListJSON(context.Context) ([]byte, error)
}

func NewRunscHandler(cfg config.Config, bin string, loader OciLoader) (*RunscHandler, error) {
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

	return &RunscHandler{
		runsc: runscapi.NewClientWithOptions(bin, runscRoot, runscapi.Options{
			FilestoreDir:     cfg.RuntimeConfig.FilestoreDir,
			OverlayTmpfsSize: cfg.RuntimeConfig.OverlayTmpfsSize,
			DebugLogPath:     runscLogPath,
		}),
		ociLoader:              loader,
		rootfsOverlayTmpfsSize: cfg.RuntimeConfig.OverlayTmpfsSize,
	}, nil
}

func (r *RunscHandler) Start(ctx context.Context, config StartConfig) error {
	traceID, _ := trace.GetContextID(ctx)
	if config.Network == nil {
		return fmt.Errorf("network is required")
	}

	bundlePath, _, err := r.ociLoader.GenerateOci(OciLoadOptions{
		SandboxID:                       config.ID,
		Config:                          config,
		CgroupPath:                      config.CgroupPath,
		UseGVisorRootfsImageAnnotations: true,
		RootfsOverlayTmpfsSize:          r.rootfsOverlayTmpfsSize,
	})
	if err != nil {
		return fmt.Errorf("generate OCI bundle: %w", err)
	}

	startArgs := runscapi.StartArgs{
		ID:         config.ID,
		BundleDir:  bundlePath,
		UserStdout: config.Stdout,
		UserStderr: config.Stderr,
		Network: runscapi.NetworkConfig{
			Interface: config.Network.Interface,
			IP:        config.Network.Ip,
			Mask:      config.Network.Mask,
			Gateway:   config.Network.Gateway,
		},
	}
	start := time.Now()
	if err := r.runsc.Create(ctx, startArgs); err != nil {
		return err
	}
	if err := r.runsc.Start(ctx, startArgs); err != nil {
		r.cleanupOnFailure(ctx, traceID.String(), config.ID, "runsc start failed")
		return err
	}
	logrus.WithField(trace.ContextKeyTraceId, traceID).Debugf("call runsc create/start, args: %+v, cost: %v", startArgs, time.Since(start))
	return nil
}

func (r *RunscHandler) Delete(ctx context.Context, sandboxID string) error {
	traceID, _ := trace.GetContextID(ctx)
	start := time.Now()
	err := r.runsc.Delete(ctx, sandboxID, true)
	if err == nil {
		logrus.WithField(trace.ContextKeyTraceId, traceID).Debugf("call runsc delete, cost: %v", time.Since(start))
	}
	return err
}

func (r *RunscHandler) List(ctx context.Context) ([]*State, error) {
	containers := make([]*State, 0)
	output, err := r.runsc.ListJSON(ctx)
	if err != nil {
		return containers, err
	}
	err = json.Unmarshal(output, &containers)
	return containers, err
}

func (r *RunscHandler) Wait(ctx context.Context, sandboxID string) (Exit, error) {
	status, err := r.runsc.Wait(ctx, sandboxID)
	return Exit{
		ExitedAt: time.Now(),
		ExitCode: status,
	}, err
}

func (r *RunscHandler) cleanupOnFailure(ctx context.Context, traceID, sandboxID, msg string) {
	logrus.WithField(trace.ContextKeyTraceId, traceID).Debugf("%s", msg)
	if err := r.runsc.Delete(ctx, sandboxID, true); err != nil {
		logrus.WithField(trace.ContextKeyTraceId, traceID).Warnf(
			"cleanup runsc sandbox %s after failure: %v", sandboxID, err,
		)
	}
}
