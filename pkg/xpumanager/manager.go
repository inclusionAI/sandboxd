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

// Package xpumanager discovers node accelerators and owns the local,
// fail-closed device leases used to validate scheduler allocations.
package xpumanager

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	api "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/sirupsen/logrus"
)

const (
	TypeGPU = "gpu"
	TypeNPU = "npu"

	AllocationAnnotation = "sandbox.akernel.dev/xpu-allocation"
)

// Resource is the stable XPU capacity shape exported from /resource.
type Resource struct {
	Type         string   `json:"type"`
	ProductModel string   `json:"product_model"`
	DeviceIDs    []uint32 `json:"device_ids"`
}

// Provider is the vendor boundary below the node-local XPU coordinator.
type Provider interface {
	Type() string
	Resources() []Resource
	SupportsRuntime(string) bool
	Acquire(sandboxID, runtimeName string, allocation *api.XpuAllocation) (*svc.SpecUpdates, error)
	Release(sandboxID string)
	Healthy() (bool, error)
}

// Manager is the XPU coordinator and provider registry.
type Manager struct {
	providers map[string]Provider
}

// New constructs independent NVIDIA and optional Ascend providers. A provider
// discovery failure is non-fatal for sandboxd and does not affect other types.
func New(runscBinary string, runcConfigured bool, sandboxRoot string, xpuConfig config.XPUConfig) *Manager {
	manager := &Manager{providers: make(map[string]Provider)}
	manager.register(newNVIDIAProvider(runscBinary, runcConfigured, sandboxRoot))
	if xpuConfig.Ascend.Enabled {
		manager.register(newAscendProvider(xpuConfig.Ascend, sandboxRoot))
	}
	return manager
}

func (m *Manager) register(provider Provider) {
	if provider == nil {
		return
	}
	m.providers[provider.Type()] = provider
	if healthy, reason := provider.Healthy(); !healthy {
		logrus.Infof("xpumanager: %s provider unavailable: %v", provider.Type(), reason)
	}
}

// Resources returns a deterministic deep copy of every healthy provider's
// stable inventory. Active leases never alter this list.
func (m *Manager) Resources() []Resource {
	resources := make([]Resource, 0)
	for _, provider := range m.providers {
		if healthy, _ := provider.Healthy(); !healthy {
			continue
		}
		resources = append(resources, provider.Resources()...)
	}
	sort.Slice(resources, func(i, j int) bool {
		if resources[i].Type == resources[j].Type {
			return resources[i].ProductModel < resources[j].ProductModel
		}
		return resources[i].Type < resources[j].Type
	})
	return resources
}

// ValidateRuntime rejects unsupported type/runtime combinations before node
// resources and filesystems are prepared.
func (m *Manager) ValidateRuntime(runtimeName string, allocations []*api.XpuAllocation) error {
	if len(allocations) == 0 {
		return nil
	}
	if len(allocations) != 1 || allocations[0] == nil {
		return errors.New("exactly one XPU allocation is supported")
	}
	typeName := strings.ToLower(strings.TrimSpace(allocations[0].Type))
	provider, ok := m.providers[typeName]
	if !ok {
		return fmt.Errorf("unsupported XPU type %q", allocations[0].Type)
	}
	if !provider.SupportsRuntime(runtimeName) {
		return fmt.Errorf("XPU type %q does not support runtime %q", typeName, runtimeName)
	}
	return nil
}

// Acquire routes a trusted scheduler allocation to the matching provider.
func (m *Manager) Acquire(sandboxID, runtimeName string, allocations []*api.XpuAllocation) (*svc.SpecUpdates, error) {
	if err := m.ValidateRuntime(runtimeName, allocations); err != nil {
		return nil, err
	}
	if len(allocations) == 0 {
		return nil, nil
	}
	allocation := allocations[0]
	provider := m.providers[strings.ToLower(strings.TrimSpace(allocation.Type))]
	return provider.Acquire(sandboxID, runtimeName, allocation)
}

// Release releases every provider lease owned by sandboxID. It is idempotent.
func (m *Manager) Release(sandboxID string) {
	for _, provider := range m.providers {
		provider.Release(sandboxID)
	}
}

// ReservedEnv reports whether any accelerator provider owns key.
func ReservedEnv(key string) bool {
	return reservedNVIDIAEnv(key) || reservedAscendEnv(key)
}

// ReservedAnnotation reports whether key stores provider-owned recovery state.
func ReservedAnnotation(key string) bool {
	return key == AllocationAnnotation
}
