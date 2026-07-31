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

package xpumanager

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	api "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sampleNvidiaInfo = `
NVRM version:   570.195.03
CUDA version:   12.8

Device Index:   2
Device Minor:   2
Model:          NVIDIA L20
Brand:          Tesla
GPU UUID:       GPU-uuid-2

Device Index:   0
Device Minor:   0
Model:          NVIDIA L20
Brand:          Tesla
GPU UUID:       GPU-uuid-0
`

func testManager(t *testing.T) *Manager {
	t.Helper()
	_, devices, err := parseNvidiaInfo(sampleNvidiaInfo)
	require.NoError(t, err)
	return &Manager{
		devices:   devices,
		resources: buildResources(devices),
		leases:    make(map[string]string),
		healthy:   true,
	}
}

func TestParseNvidiaInfoAndResources(t *testing.T) {
	driver, devices, err := parseNvidiaInfo(sampleNvidiaInfo)
	require.NoError(t, err)
	assert.Equal(t, "570.195.03", driver)
	assert.Equal(t, "l20", devices[0].ProductModel)
	assert.Equal(t, "GPU-uuid-2", devices[2].UUID)
	assert.Equal(t, []Resource{{
		Type:         TypeGPU,
		ProductModel: "l20",
		DeviceIDs:    []uint32{0, 2},
	}}, buildResources(devices))
}

func TestAcquireMultipleGPUs(t *testing.T) {
	manager := testManager(t)
	updates, err := manager.Acquire("sbox-gpu", []*api.XpuAllocation{{
		Type:      "gpu",
		DeviceIds: []uint32{0, 2},
	}})
	require.NoError(t, err)
	require.Len(t, updates.Prestart, 1)
	assert.Equal(t, nvidiaRuntimeHookPath, updates.Prestart[0].Path)
	assert.Equal(t, "GPU-uuid-0,GPU-uuid-2", updates.Envs[0].Value)
	assert.Equal(t, "compute,utility", updates.Envs[1].Value)
	assert.Equal(t, "0,1", updates.Envs[2].Value)

	var record leaseRecord
	require.NoError(t, json.Unmarshal([]byte(updates.Annotations[AllocationAnnotation]), &record))
	assert.Equal(t, []uint32{0, 2}, record.DeviceIDs)
	assert.Equal(t, []string{"GPU-uuid-0", "GPU-uuid-2"}, record.DeviceUUID)
}

func TestAcquireIsAtomicAndReleaseIsIdempotent(t *testing.T) {
	manager := testManager(t)
	_, err := manager.Acquire("sbox-owner", []*api.XpuAllocation{{
		Type:      "gpu",
		DeviceIds: []uint32{0},
	}})
	require.NoError(t, err)

	_, err = manager.Acquire("sbox-other", []*api.XpuAllocation{{
		Type:      "gpu",
		DeviceIds: []uint32{2, 0},
	}})
	require.ErrorContains(t, err, "already leased")
	assert.NotContains(t, manager.leases, "GPU-uuid-2")

	manager.ReleaseSandbox("sbox-owner")
	manager.ReleaseSandbox("sbox-owner")
	_, err = manager.Acquire("sbox-other", []*api.XpuAllocation{{
		Type:      "gpu",
		DeviceIds: []uint32{2, 0},
	}})
	require.NoError(t, err)
}

func TestAcquireRejectsInvalidAllocations(t *testing.T) {
	tests := []struct {
		name       string
		allocation []*api.XpuAllocation
		errorText  string
	}{
		{name: "empty", allocation: []*api.XpuAllocation{{Type: "gpu"}}, errorText: "must not be empty"},
		{name: "duplicate", allocation: []*api.XpuAllocation{{Type: "gpu", DeviceIds: []uint32{0, 0}}}, errorText: "duplicate"},
		{name: "unknown ID", allocation: []*api.XpuAllocation{{Type: "gpu", DeviceIds: []uint32{1}}}, errorText: "not in the node inventory"},
		{name: "unknown type", allocation: []*api.XpuAllocation{{Type: "npu", DeviceIds: []uint32{0}}}, errorText: "unsupported"},
		{name: "multiple", allocation: []*api.XpuAllocation{{Type: "gpu", DeviceIds: []uint32{0}}, {Type: "gpu", DeviceIds: []uint32{2}}}, errorText: "exactly one"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := testManager(t).Acquire("sbox-test", test.allocation)
			require.ErrorContains(t, err, test.errorText)
		})
	}
}

func TestResourcesAreStableAcrossLeases(t *testing.T) {
	manager := testManager(t)
	before := manager.Resources()
	_, err := manager.Acquire("sbox-test", []*api.XpuAllocation{{
		Type:      "gpu",
		DeviceIds: []uint32{0},
	}})
	require.NoError(t, err)
	assert.Equal(t, before, manager.Resources())
}

func TestReservedEnv(t *testing.T) {
	assert.True(t, ReservedEnv("NVIDIA_VISIBLE_DEVICES"))
	assert.True(t, ReservedEnv("NVIDIA_DRIVER_CAPABILITIES"))
	assert.True(t, ReservedEnv("CUDA_VISIBLE_DEVICES"))
	assert.False(t, ReservedEnv("CUDA_VERSION"))
}

func TestReservedAnnotation(t *testing.T) {
	assert.True(t, ReservedAnnotation(AllocationAnnotation))
	assert.False(t, ReservedAnnotation("sandbox.akernel.dev/env-id"))
}

func TestRestoreLeases(t *testing.T) {
	manager := testManager(t)
	manager.sandboxRoot = t.TempDir()
	writeLeaseSpec(t, manager.sandboxRoot, leaseRecord{
		SandboxID:  "sbox-recovered",
		Type:       TypeGPU,
		DeviceIDs:  []uint32{0, 2},
		DeviceUUID: []string{"GPU-uuid-0", "GPU-uuid-2"},
	})

	require.NoError(t, manager.restoreLeases())
	assert.Equal(t, "sbox-recovered", manager.leases["GPU-uuid-0"])
	assert.Equal(t, "sbox-recovered", manager.leases["GPU-uuid-2"])
}

func TestRestoreLeasesFailsClosedOnDuplicateUUID(t *testing.T) {
	manager := testManager(t)
	manager.sandboxRoot = t.TempDir()
	writeLeaseSpec(t, manager.sandboxRoot, leaseRecord{
		SandboxID:  "sbox-first",
		Type:       TypeGPU,
		DeviceIDs:  []uint32{0},
		DeviceUUID: []string{"GPU-uuid-0"},
	})
	writeLeaseSpec(t, manager.sandboxRoot, leaseRecord{
		SandboxID:  "sbox-second",
		Type:       TypeGPU,
		DeviceIDs:  []uint32{0},
		DeviceUUID: []string{"GPU-uuid-0"},
	})

	require.ErrorContains(t, manager.restoreLeases(), "assigned to both")
}

func writeLeaseSpec(t *testing.T, sandboxRoot string, record leaseRecord) {
	t.Helper()
	rawRecord, err := json.Marshal(record)
	require.NoError(t, err)
	rawSpec, err := json.Marshal(map[string]any{
		"annotations": map[string]string{
			AllocationAnnotation: string(rawRecord),
		},
	})
	require.NoError(t, err)
	bundlePath := filepath.Join(sandboxRoot, record.SandboxID)
	require.NoError(t, os.MkdirAll(bundlePath, 0755))
	require.NoError(t, os.WriteFile(
		filepath.Join(bundlePath, config.SandboxSpecFile),
		rawSpec,
		0600,
	))
}
