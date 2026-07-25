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
	"errors"
	"os"
	"path/filepath"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	"github.com/inclusionAI/sandboxd/pkg/volumemanager"

	spec "github.com/opencontainers/runtime-spec/specs-go"
)

// RealRuntimeHandler is the interface implemented by runtime adapters.
type RealRuntimeHandler interface {
	StartSandbox(context.Context, *StartSandboxRequest, HandlerOptions) (*runtime.SandboxMetadata, error)
	DeleteSandbox(context.Context, *DeleteSandboxRequest, HandlerOptions) (*DeleteSandboxResponse, error)
	ListSandboxes(context.Context, HandlerOptions) ([]*UnionSandboxState, error)
	SandboxSpec(context.Context, HandlerOptions) (*spec.Spec, error)

	Wait(context.Context, HandlerOptions) (Exit, error)

	// ShutDown cleans up all runtime resources before the daemon exits.
	ShutDown()
}

type HandlerOptions struct {
	TraceID   string
	SpanID    string
	SandboxID string

	// For delete
	ForceDelete bool
	// For resource
	CgroupPath string

	AdditionalAnnotations map[string]string

	// NetworkStack selects the in-sandbox network stack for runsc-backed
	// containers. The open-source adapter supports gVisor netstack only; empty
	// is treated as netstack for compatibility with older requests.
	NetworkStack string
}

type Rootfs struct {
	Type     string
	LowerDir string
	RootDir  string
}

type StartSandboxRequest struct {
	Runtime      string
	Command      []string
	Mounts       []*runtime.Mount
	Rootfs       *Rootfs
	Resource     *runtime.LinuxSandboxResources
	Envs         []*runtime.KeyValue
	Stdout       string
	Stderr       string
	Network      string
	Labels       map[string]string
	MetricLabels map[string]string
	Cwd          string
}

type StartSandboxResponse struct {
	ID string
}

type DeleteSandboxRequest struct {
	ID      string
	Timeout int64
}

type DeleteSandboxResponse struct{}

// GetRuntimeHandler constructs the per-runtime handler for sandboxd. The
// VolumeManager is required so the runsc handler knows whether to advertise
// fork (ficlone) support; pass nil for tests/probes that don't need fork.
func GetRuntimeHandler(cfg config.Config, bin, runtime string, volMod *volumemanager.Module) (RealRuntimeHandler, error) {
	// check if the binary is existed
	if _, err := os.Stat(bin); err != nil {
		return nil, err
	}

	sandboxRoot := filepath.Join(cfg.RootDir, "containers")
	switch runtime {
	case config.RuntimeNameRunsc:
		if cfg.RuntimeConfig.BasicSpec == nil {
			cfg.RuntimeConfig.BasicSpec = make(map[string]string)
		}
		loader, err := NewBundleLoader(cfg.RuntimeConfig.BasicSpec[config.RuntimeNameRunsc], sandboxRoot)
		if err != nil {
			return nil, err
		}
		return NewRunscServiceHandler(cfg, bin, loader, volMod)
	default:
		return nil, errord.ErrNotImplemented
	}
}

func NewFakeRuntimeHandler() *FakeRuntimeHandler {
	return &FakeRuntimeHandler{}
}

type FakeRuntimeHandler struct{}

func (f *FakeRuntimeHandler) StartSandbox(
	ctx context.Context,
	request *StartSandboxRequest,
	options HandlerOptions,
) (*runtime.SandboxMetadata, error) {

	return &runtime.SandboxMetadata{}, getErrorFromContext(ctx)
}

func (f *FakeRuntimeHandler) DeleteSandbox(
	ctx context.Context,
	request *DeleteSandboxRequest,
	options HandlerOptions,
) (*DeleteSandboxResponse, error) {

	return &DeleteSandboxResponse{}, getErrorFromContext(ctx)
}

func (f *FakeRuntimeHandler) ListSandboxes(ctx context.Context, options HandlerOptions) ([]*UnionSandboxState, error) {
	return []*UnionSandboxState{}, getErrorFromContext(ctx)
}

func (f *FakeRuntimeHandler) SandboxSpec(ctx context.Context, options HandlerOptions) (*spec.Spec, error) {
	return &spec.Spec{}, getErrorFromContext(ctx)
}

func (f *FakeRuntimeHandler) Wait(ctx context.Context, options HandlerOptions) (Exit, error) {
	return Exit{
		Timestamp: time.Time{},
		Status:    0,
	}, getErrorFromContext(ctx)
}

func (r *FakeRuntimeHandler) ShutDown() {}

func getErrorFromContext(ctx context.Context) error {
	if errStr, ok := ctx.Value("ERROR").(string); ok {
		return errors.New(errStr)
	}
	return nil
}

var _ RealRuntimeHandler = &FakeRuntimeHandler{}
