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

	"github.com/inclusionAI/sandboxd/internal/cgroupops"
	"github.com/inclusionAI/sandboxd/internal/trace"
	"github.com/inclusionAI/sandboxd/internal/util"
	runscapi "github.com/inclusionAI/sandboxd/pkg/runtime/runsc"

	cg "github.com/containerd/cgroups/v3/cgroup1"
	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager"
	"github.com/inclusionAI/sandboxd/pkg/volumemanager"
	spec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
)

var _ RealRuntimeHandler = &RunscServiceHandler{}

const (
	ImageName      = "rootfs.img"
	SplitSeparator = "__.__"
)

type RunscServiceHandler struct {
	binary   string
	executor util.CmdExecutor
	runsc    runscClient
	// root path of sandboxd, this is used to store runtime logs if the user doesn't specify the log path
	SandboxRoot string
	RunscRoot   string
	ociLoader   OciLoader

	rootfsOverlayTmpfsSize string
}

type runscClient interface {
	Create(context.Context, runscapi.StartArgs) error
	Start(context.Context, runscapi.StartArgs) error
	Wait(context.Context, string) (int, error)
	Delete(context.Context, string, bool) error
	ListJSON(context.Context) ([]byte, error)
}

func updateCgroup(cgroupPath string, resource *runtime.LinuxSandboxResources) error {
	if resource == nil {
		return nil
	}

	cgroupHandler := &cgroupops.CgroupHandlerImpl{}
	cgroup, err := cgroupHandler.Load(cg.StaticPath(cgroupPath), cg.WithHiearchy(cg.Default))
	if err != nil {
		return err
	}

	var cpu spec.LinuxCPU
	if resource.CpuShares > 0 {
		cpu.Shares = &resource.CpuShares
	}
	if resource.CpuQuota > 0 {
		cpu.Quota = &resource.CpuQuota
	}
	if resource.CpuPeriod > 0 {
		cpu.Period = &resource.CpuPeriod
	}
	if resource.CpusetCpus != "" {
		cpu.Cpus = resource.CpusetCpus
	}
	if resource.CpusetMems != "" {
		cpu.Mems = resource.CpusetMems
	}
	var mem spec.LinuxMemory
	if resource.MemoryLimitInBytes > 0 {
		mem.Limit = &resource.MemoryLimitInBytes
	}

	cgroupResource := spec.LinuxResources{
		CPU:    &cpu,
		Memory: &mem,
	}

	return cgroup.Update(&cgroupResource)
}

// CleanupXFSMount is re-exported from pkg/volumemanager for backwards
// compatibility with anything that imported it from pkg/runtime; new code
// should call volumemanager.CleanupXFSMount directly.
func CleanupXFSMount(filestoreDir string) error {
	return volumemanager.CleanupXFSMount(filestoreDir)
}

// NewRunscServiceHandler constructs the runsc-backed runtime handler.
func NewRunscServiceHandler(cfg config.Config, bin string, loader OciLoader, volMod *volumemanager.Module) (*RunscServiceHandler, error) {
	_ = volMod

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

	rsh := &RunscServiceHandler{
		binary:   bin,
		executor: &util.SystemCmdExecutor{},
		runsc: runscapi.NewClientWithOptions(bin, runscRoot, runscapi.Options{
			FilestoreDir:     cfg.RuntimeConfig.FilestoreDir,
			OverlayTmpfsSize: cfg.RuntimeConfig.OverlayTmpfsSize,
			DebugLogPath:     runscLogPath,
		}),
		ociLoader:              loader,
		SandboxRoot:            filepath.Join(root, "containers"),
		RunscRoot:              runscRoot,
		rootfsOverlayTmpfsSize: cfg.RuntimeConfig.OverlayTmpfsSize,
	}
	return rsh, nil
}

func (r *RunscServiceHandler) StartSandbox(
	ctx context.Context,
	request *StartSandboxRequest,
	options HandlerOptions,
) (*runtime.SandboxMetadata, error) {
	// Apply cgroup resource limits before starting the container
	if request.Resource != nil && options.CgroupPath != "" {
		if err := updateCgroup(options.CgroupPath, request.Resource); err != nil {
			return nil, fmt.Errorf("set cgroup resource limits on %s failed: %v", options.CgroupPath, err)
		}
	}

	// Get Network Info from options
	device, ok := options.AdditionalAnnotations[config.ResourceAnnotationKeyPrefix+config.ResourceNameInterface]
	if !ok {
		return nil, fmt.Errorf("interface not found in options")
	}
	netDevice := &networkmanager.NetResource{}
	if err := netDevice.FromString(device); err != nil {
		return nil, fmt.Errorf("parse net device(%s) failed, err: %v", device, err)
	}

	bundlePath, specConf, err := r.ociLoader.GenerateOci(OciLoadOptions{
		SandboxID: options.SandboxID,
		Request:   request,

		CgroupPath:                      options.CgroupPath,
		AdditionalAnnotations:           options.AdditionalAnnotations,
		UseGVisorRootfsImageAnnotations: true,
		RootfsOverlayTmpfsSize:          r.rootfsOverlayTmpfsSize,
	})
	if err != nil {
		logrus.WithField(trace.ContextKeyTraceId, options.TraceID).Debugf("generate oci failed, err: %v", err)
		return nil, fmt.Errorf("generate oci failed because %v", err)
	}

	if request.Stderr == "" {
		request.Stderr = filepath.Join(r.SandboxRoot, options.SandboxID, "stderr.log")
	}
	if request.Stdout == "" {
		request.Stdout = filepath.Join(r.SandboxRoot, options.SandboxID, "stdout.log")
	}

	metaData := &runtime.SandboxMetadata{
		ID:             options.SandboxID,
		RuntimeHandler: config.RuntimeNameRunsc,
		Labels:         specConf.Annotations,
		MetricLabels:   request.MetricLabels,
		Stdout:         request.Stdout,
		Stderr:         request.Stderr,
	}

	if options.NetworkStack != "" && options.NetworkStack != "netstack" {
		return nil, fmt.Errorf("unsupported runsc network stack %q (only netstack is supported in the open-source adapter)", options.NetworkStack)
	}

	startArgs := runscapi.StartArgs{
		ID:         options.SandboxID,
		BundleDir:  bundlePath,
		UserStdout: request.Stdout,
		UserStderr: request.Stderr,
		Network: runscapi.NetworkConfig{
			Interface: netDevice.Interface,
			IP:        netDevice.Ip,
			Mask:      netDevice.Mask,
			Gateway:   netDevice.Gateway,
		},
	}
	start := time.Now()
	if err := r.runsc.Create(ctx, startArgs); err != nil {
		return metaData, err
	}
	if err := r.runsc.Start(ctx, startArgs); err != nil {
		r.cleanupOnFailure(ctx, options.TraceID, options.SandboxID, fmt.Sprintf("start failed: %v, try to delete.", err))
		return metaData, err
	}
	logrus.WithField(trace.ContextKeyTraceId, options.TraceID).Debugf("call runsc create/start, args: %+v, cost: %v", startArgs, time.Since(start))
	return metaData, nil
}

func (r *RunscServiceHandler) DeleteSandbox(
	ctx context.Context,
	request *DeleteSandboxRequest,
	options HandlerOptions) (*DeleteSandboxResponse, error) {

	start := time.Now()
	err := r.runsc.Delete(ctx, options.SandboxID, true)
	if err == nil {
		logrus.WithField(trace.ContextKeyTraceId, options.TraceID).Debugf("call runsc delete, cost: %v", time.Since(start))
	}
	return &DeleteSandboxResponse{}, err
}

func (r *RunscServiceHandler) ListSandboxes(ctx context.Context, options HandlerOptions) ([]*UnionSandboxState, error) {
	containers := make([]*UnionSandboxState, 0)
	output, err := r.runsc.ListJSON(ctx)
	if err != nil {
		return containers, err
	}
	err = json.Unmarshal(output, &containers)
	return containers, err
}

func (r *RunscServiceHandler) SandboxSpec(ctx context.Context, options HandlerOptions) (*spec.Spec, error) {
	return nil, fmt.Errorf("runsc SandboxSpec is not implemented")
}

func (r *RunscServiceHandler) Wait(ctx context.Context, options HandlerOptions) (Exit, error) {
	status, err := r.runsc.Wait(ctx, options.SandboxID)
	return Exit{
		Timestamp: time.Now(),
		Status:    status,
	}, err
}

func (r *RunscServiceHandler) ShutDown() {}

func (r *RunscServiceHandler) cleanupOnFailure(ctx context.Context, traceID, sandboxID, msg string) {
	logrus.WithField(trace.ContextKeyTraceId, traceID).Debugf("%s", msg)
	if err := r.runsc.Delete(ctx, sandboxID, true); err != nil {
		logrus.WithField(trace.ContextKeyTraceId, traceID).Warnf(
			"cleanup runsc sandbox %s after failure: %v", sandboxID, err,
		)
	}
}
