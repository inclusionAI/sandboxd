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
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager"
)

// Handler is the lifecycle boundary implemented by sandbox runtimes.
type Handler interface {
	Start(context.Context, StartConfig) error
	Delete(context.Context, string) error
	List(context.Context) ([]*State, error)
	Wait(context.Context, string) (Exit, error)
}

// CheckpointHandler is an optional capability implemented by runtimes that
// can save and restore caller-owned checkpoint artifacts.
type CheckpointHandler interface {
	Checkpoint(context.Context, CheckpointConfig) error
	Restore(context.Context, StartConfig) error
}

// CheckpointRestoreCapabilities describes the optional application-facing
// handoff interface exposed inside a restored sandbox. Empty paths mean the
// runtime supports transparent checkpoint/restore without application help.
type CheckpointRestoreCapabilities struct {
	CheckpointHandoffPath string
	RestoreEnvPath        string
}

// CheckpointRestoreCapabilitiesProvider optionally describes the guest-facing
// application handoff exposed by a CheckpointHandler.
type CheckpointRestoreCapabilitiesProvider interface {
	CheckpointRestoreCapabilities() CheckpointRestoreCapabilities
}

type CheckpointConfig struct {
	ID        string
	Directory string
	// CgroupPath is the runtime-owned source cgroup. It is internal runtime
	// metadata rather than a public checkpoint option.
	CgroupPath   string
	Compress     bool
	LeaveRunning bool
	// SnapshotType requests a specific checkpoint flavor ("Full",
	// "Incremental", or "SoftDirty" for Firecracker); empty leaves the
	// runtime's automatic tier selection in charge. Runtimes without
	// incremental checkpoints ignore it.
	SnapshotType string
}

// HostResourcesProvider maps guest-visible resources to the host cgroup that
// encloses a runtime process. VM handlers use it to retain private VMM
// headroom without changing resources exposed to the guest.
type HostResourcesProvider interface {
	HostResources(*runtime.LinuxSandboxResources) *runtime.LinuxSandboxResources
}

// StartRequestValidator rejects unsupported request sources before sandboxd
// prepares images and runtime resources.
type StartRequestValidator interface {
	ValidateStartRequest(*runtime.StartRequest) error
}

type StartConfig struct {
	ID                      string
	Hostname                string
	Command                 []string
	Mounts                  []*runtime.Mount
	Rootfs                  string
	RootfsReadonly          bool
	Resources               *runtime.LinuxSandboxResources
	Envs                    []*runtime.KeyValue
	Stdout                  string
	Stderr                  string
	Cwd                     string
	CgroupPath              string
	Annotations             map[string]string
	Network                 *networkmanager.NetResource
	DisableCgroup           bool
	SpecUpdates             *SpecUpdates
	WritableLayerLimitBytes uint64
	ExtraConfig             string
	EnableKVM               bool
	CheckpointDir           string
}

// SpecUpdates contains provider-resolved OCI changes. Device providers use
// this boundary so vendor-specific discovery and authorization do not leak
// into the runsc client.
type SpecUpdates struct {
	Envs        []*runtime.KeyValue
	Prestart    []Hook
	Annotations map[string]string
	// RequiresHostWritableRootfs requests a private writable rootfs view
	// before provider hooks execute. It is separate from the writable layer
	// visible to workloads after the sandbox starts.
	RequiresHostWritableRootfs bool
}

func NewFakeRuntimeHandler() *FakeRuntimeHandler {
	return &FakeRuntimeHandler{}
}

type FakeRuntimeHandler struct{}

func (f *FakeRuntimeHandler) Start(ctx context.Context, _ StartConfig) error {
	return getErrorFromContext(ctx)
}

func (f *FakeRuntimeHandler) Delete(ctx context.Context, _ string) error {
	return getErrorFromContext(ctx)
}

func (f *FakeRuntimeHandler) List(ctx context.Context) ([]*State, error) {
	return []*State{}, getErrorFromContext(ctx)
}

func (f *FakeRuntimeHandler) Wait(ctx context.Context, _ string) (Exit, error) {
	return Exit{
		ExitedAt: time.Time{},
		ExitCode: 0,
	}, getErrorFromContext(ctx)
}

func getErrorFromContext(ctx context.Context) error {
	if errStr, ok := ctx.Value("ERROR").(string); ok {
		return errors.New(errStr)
	}
	return nil
}

var _ Handler = &FakeRuntimeHandler{}
