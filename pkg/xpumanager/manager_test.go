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
	"context"
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

func testNVIDIAProvider(t *testing.T) *nvidiaProvider {
	t.Helper()
	_, devices, err := parseNVIDIAInfo(sampleNvidiaInfo)
	require.NoError(t, err)
	return &nvidiaProvider{
		devices:     devices,
		resources:   buildResources(devices),
		leases:      make(map[string]string),
		healthy:     true,
		runscReady:  true,
		runcEnabled: true,
	}
}

func TestNVIDIARuntimeSupportIsIndependent(t *testing.T) {
	provider := &nvidiaProvider{
		runscBinary: "/usr/local/bin/runsc",
		runcEnabled: true,
		run: func(context.Context, string, ...string) ([]byte, error) {
			return []byte("570.195.03\n"), nil
		},
	}
	require.NoError(t, provider.configureRuntimeSupport(context.Background(), "470.223.02"))
	assert.False(t, provider.SupportsRuntime(config.RuntimeNameRunsc))
	assert.True(t, provider.SupportsRuntime(config.RuntimeNameRunc))

	provider.runcEnabled = false
	require.ErrorContains(
		t,
		provider.configureRuntimeSupport(context.Background(), "470.223.02"),
		"not supported",
	)

	provider.run = func(context.Context, string, ...string) ([]byte, error) {
		return []byte("470.223.02\n"), nil
	}
	require.NoError(t, provider.configureRuntimeSupport(context.Background(), "470.223.02"))
	assert.True(t, provider.SupportsRuntime(config.RuntimeNameRunsc))
}

func TestParseNVIDIAInfoAndResources(t *testing.T) {
	driver, devices, err := parseNVIDIAInfo(sampleNvidiaInfo)
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

func TestValidateNVIDIARuntimeHook(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nvidia-container-runtime-hook")
	require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\n"), 0644))
	require.ErrorContains(t, validateNVIDIARuntimeHook(path, os.Stat), "executable regular file")
	require.NoError(t, os.Chmod(path, 0755))
	require.NoError(t, validateNVIDIARuntimeHook(path, os.Stat))
}

func TestAcquireMultipleGPUs(t *testing.T) {
	for _, runtimeName := range []string{config.RuntimeNameRunsc, config.RuntimeNameRunc} {
		t.Run(runtimeName, func(t *testing.T) {
			provider := testNVIDIAProvider(t)
			updates, err := provider.Acquire("sbox-gpu", runtimeName, &api.XpuAllocation{
				Type:      "gpu",
				DeviceIds: []uint32{0, 2},
			})
			require.NoError(t, err)
			require.Len(t, updates.Prestart, 1)
			assert.Equal(t, runtimeName == config.RuntimeNameRunsc, updates.RequiresHostWritableRootfs)
			assert.Equal(t, nvidiaRuntimeHookPath, updates.Prestart[0].Path)
			assert.Equal(t, "GPU-uuid-0,GPU-uuid-2", updates.Envs[0].Value)
			assert.Equal(t, "compute,utility", updates.Envs[1].Value)
			assert.Equal(t, "0,1", updates.Envs[2].Value)

			var record leaseRecord
			require.NoError(t, json.Unmarshal([]byte(updates.Annotations[AllocationAnnotation]), &record))
			assert.Equal(t, runtimeName, record.Runtime)
			assert.Equal(t, []uint32{0, 2}, record.SchedulerIDs)
			assert.Equal(t, []string{"GPU-uuid-0", "GPU-uuid-2"}, record.StableIDs)
		})
	}
}

func TestAcquireIsAtomicAndReleaseIsIdempotent(t *testing.T) {
	provider := testNVIDIAProvider(t)
	_, err := provider.Acquire("sbox-owner", config.RuntimeNameRunsc, &api.XpuAllocation{
		Type:      "gpu",
		DeviceIds: []uint32{0},
	})
	require.NoError(t, err)

	_, err = provider.Acquire("sbox-other", config.RuntimeNameRunsc, &api.XpuAllocation{
		Type:      "gpu",
		DeviceIds: []uint32{2, 0},
	})
	require.ErrorContains(t, err, "already leased")
	assert.NotContains(t, provider.leases, "GPU-uuid-2")

	provider.Release("sbox-owner")
	provider.Release("sbox-owner")
	_, err = provider.Acquire("sbox-other", config.RuntimeNameRunsc, &api.XpuAllocation{
		Type:      "gpu",
		DeviceIds: []uint32{2, 0},
	})
	require.NoError(t, err)
}

func TestAcquireRejectsInvalidAllocations(t *testing.T) {
	tests := []struct {
		name       string
		allocation *api.XpuAllocation
		errorText  string
	}{
		{name: "empty", allocation: &api.XpuAllocation{Type: "gpu"}, errorText: "must not be empty"},
		{name: "duplicate", allocation: &api.XpuAllocation{Type: "gpu", DeviceIds: []uint32{0, 0}}, errorText: "duplicate"},
		{name: "unknown ID", allocation: &api.XpuAllocation{Type: "gpu", DeviceIds: []uint32{1}}, errorText: "not in the node inventory"},
		{name: "unknown type", allocation: &api.XpuAllocation{Type: "npu", DeviceIds: []uint32{0}}, errorText: "invalid GPU"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := testNVIDIAProvider(t).Acquire("sbox-test", config.RuntimeNameRunsc, test.allocation)
			require.ErrorContains(t, err, test.errorText)
		})
	}
}

func TestResourcesAreStableAcrossLeases(t *testing.T) {
	provider := testNVIDIAProvider(t)
	before := provider.Resources()
	_, err := provider.Acquire("sbox-test", config.RuntimeNameRunsc, &api.XpuAllocation{
		Type:      "gpu",
		DeviceIds: []uint32{0},
	})
	require.NoError(t, err)
	assert.Equal(t, before, provider.Resources())
}

func TestReservedEnv(t *testing.T) {
	assert.True(t, ReservedEnv("NVIDIA_VISIBLE_DEVICES"))
	assert.True(t, ReservedEnv("NVIDIA_DRIVER_CAPABILITIES"))
	assert.True(t, ReservedEnv("CUDA_VISIBLE_DEVICES"))
	assert.True(t, ReservedEnv("ASCEND_VISIBLE_DEVICES"))
	assert.True(t, ReservedEnv("ASCEND_RT_VISIBLE_DEVICES"))
	assert.False(t, ReservedEnv("CUDA_VERSION"))
}

func TestManagerRejectsMixedOrUnsupportedRuntime(t *testing.T) {
	manager := &Manager{providers: map[string]Provider{TypeGPU: testNVIDIAProvider(t)}}
	require.NoError(t, manager.ValidateRuntime(config.RuntimeNameRunc, []*api.XpuAllocation{{
		Type: TypeGPU, DeviceIds: []uint32{0},
	}}))
	require.ErrorContains(t, manager.ValidateRuntime(config.RuntimeNameKata, []*api.XpuAllocation{{
		Type: TypeGPU, DeviceIds: []uint32{0},
	}}), "does not support runtime")
	require.ErrorContains(t, manager.ValidateRuntime(config.RuntimeNameRunsc, []*api.XpuAllocation{
		{Type: TypeGPU, DeviceIds: []uint32{0}},
		{Type: TypeNPU, DeviceIds: []uint32{1}},
	}), "exactly one")
	require.ErrorContains(t, manager.ValidateRuntime(config.RuntimeNameRunc, []*api.XpuAllocation{{
		Type: TypeNPU, DeviceIds: []uint32{1},
	}}), "unsupported XPU type")
}

func TestReservedAnnotation(t *testing.T) {
	assert.True(t, ReservedAnnotation(AllocationAnnotation))
	assert.False(t, ReservedAnnotation("sandbox.akernel.dev/env-id"))
}

func TestRestoreLeases(t *testing.T) {
	provider := testNVIDIAProvider(t)
	provider.sandboxRoot = t.TempDir()
	writeLeaseSpec(t, provider.sandboxRoot, leaseRecord{
		SandboxID:  "sbox-recovered",
		Type:       TypeGPU,
		DeviceIDs:  []uint32{0, 2},
		DeviceUUID: []string{"GPU-uuid-0", "GPU-uuid-2"},
	})

	require.NoError(t, provider.restoreLeases())
	assert.Equal(t, "sbox-recovered", provider.leases["GPU-uuid-0"])
	assert.Equal(t, "sbox-recovered", provider.leases["GPU-uuid-2"])
}

func TestRestoreRuncLease(t *testing.T) {
	provider := testNVIDIAProvider(t)
	provider.sandboxRoot = t.TempDir()
	writeLeaseSpec(t, provider.sandboxRoot, leaseRecord{
		SchemaVersion: leaseSchemaVersion,
		SandboxID:     "sbox-runc-recovered",
		Type:          TypeGPU,
		Runtime:       config.RuntimeNameRunc,
		ProductModel:  "l20",
		SchedulerIDs:  []uint32{0},
		StableIDs:     []string{"GPU-uuid-0"},
		Provider:      "nvidia",
	})

	require.NoError(t, provider.restoreLeases())
	assert.Equal(t, "sbox-runc-recovered", provider.leases["GPU-uuid-0"])
}

func TestRestoreLeaseRejectsUnsupportedRuntime(t *testing.T) {
	provider := testNVIDIAProvider(t)
	provider.sandboxRoot = t.TempDir()
	writeLeaseSpec(t, provider.sandboxRoot, leaseRecord{
		SchemaVersion: leaseSchemaVersion,
		SandboxID:     "sbox-kata",
		Type:          TypeGPU,
		Runtime:       config.RuntimeNameKata,
		ProductModel:  "l20",
		SchedulerIDs:  []uint32{0},
		StableIDs:     []string{"GPU-uuid-0"},
		Provider:      "nvidia",
	})

	require.ErrorContains(t, provider.restoreLeases(), "invalid GPU runtime")
}

func TestRestoreLeasesFailsClosedOnDuplicateUUID(t *testing.T) {
	provider := testNVIDIAProvider(t)
	provider.sandboxRoot = t.TempDir()
	writeLeaseSpec(t, provider.sandboxRoot, leaseRecord{
		SandboxID:  "sbox-first",
		Type:       TypeGPU,
		DeviceIDs:  []uint32{0},
		DeviceUUID: []string{"GPU-uuid-0"},
	})
	writeLeaseSpec(t, provider.sandboxRoot, leaseRecord{
		SandboxID:  "sbox-second",
		Type:       TypeGPU,
		DeviceIDs:  []uint32{0},
		DeviceUUID: []string{"GPU-uuid-0"},
	})

	require.ErrorContains(t, provider.restoreLeases(), "assigned to both")
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
