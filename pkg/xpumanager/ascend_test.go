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

func TestAscendProviderDiscoversAcquiresAndReleases(t *testing.T) {
	tempDir := t.TempDir()
	adapterPath := filepath.Join(tempDir, "fake-ascend-adapter")
	profilePath := filepath.Join(tempDir, "mounts.json")
	require.NoError(t, os.WriteFile(profilePath, []byte(`{"default":[]}`), 0600))
	require.NoError(t, os.WriteFile(adapterPath, []byte(`#!/bin/sh
case "$1" in
  version) printf '%s' '{"schema_version":1,"provider_version":"fake-v1"}' ;;
  discover) printf '%s' '{"schema_version":1,"provider_version":"fake-v1","devices":[{"scheduler_id":0,"logic_id":0,"physical_id":0,"stable_id":"die-0","product_model":"ascend310p3","generation":"310P","runtime_family":"Ascend310P","resource_family":"huawei.com/Ascend310P","raw_product":"310P3","healthy":true}]}' ;;
  edits)
    request=$(cat)
    case "$request" in
      *'"runtime_family":"Ascend310P"'*) ;;
      *) exit 3 ;;
    esac
    printf '%s' '{"schema_version":1,"provider_version":"fake-v1","devices":[{"host_path":"/dev/davinci0","container_path":"/dev/davinci0","type":"c","major":1,"minor":3,"permissions":"rwm"}],"shared_devices":[],"mounts":[],"env":{"ASCEND_RT_VISIBLE_DEVICES":"0","LD_LIBRARY_PATH":"/driver/lib:/dcmi/lib"}}'
    ;;
  *) exit 2 ;;
esac
`), 0700))

	provider := newAscendProvider(config.AscendConfig{
		Enabled: true, Adapter: adapterPath, MountProfile: profilePath,
	}, tempDir)
	healthy, reason := provider.Healthy()
	require.True(t, healthy, reason)
	assert.Equal(t, []Resource{{Type: TypeNPU, ProductModel: "ascend310p3", DeviceIDs: []uint32{0}}}, provider.Resources())
	provider.statDevice = func(path string) (string, int64, int64, error) {
		assert.Equal(t, "/dev/davinci0", path)
		return "c", 1, 3, nil
	}

	updates, err := provider.Acquire("sbox-npu", config.RuntimeNameRunc, &api.XpuAllocation{
		Type: "npu", DeviceIds: []uint32{0},
	})
	require.NoError(t, err)
	require.Len(t, updates.LinuxDevices, 1)
	require.Len(t, updates.DeviceCgroupRules, 1)
	assert.Equal(t, []string{"/driver/lib", "/dcmi/lib"}, updates.PrependLibraryPaths)
	assert.Contains(t, updates.Annotations, AllocationAnnotation)
	var record leaseRecord
	require.NoError(t, json.Unmarshal([]byte(updates.Annotations[AllocationAnnotation]), &record))
	assert.Equal(t, "ascend310p3", record.ProductModel)

	_, err = provider.Acquire("sbox-other", config.RuntimeNameRunc, &api.XpuAllocation{
		Type: "npu", DeviceIds: []uint32{0},
	})
	require.ErrorContains(t, err, "already leased")
	provider.Release("sbox-npu")
	_, err = provider.Acquire("sbox-other", config.RuntimeNameRunc, &api.XpuAllocation{
		Type: "npu", DeviceIds: []uint32{0},
	})
	require.NoError(t, err)
}

func TestAscendProviderGroupsMixedModelsAndRejectsMixedAllocation(t *testing.T) {
	provider := &ascendProvider{devices: make(map[uint32]ascendDevice)}
	err := provider.acceptDiscovery([]ascendDevice{
		{SchedulerID: 0, LogicID: 0, StableID: "a", ProductModel: "ascend910", Generation: "A3", RuntimeFamily: ascendRuntimeFamily, ResourceFamily: "huawei.com/Ascend910", Healthy: true},
		{SchedulerID: 1, LogicID: 1, StableID: "b", ProductModel: "ascend910b4", Generation: "A2", RuntimeFamily: ascendRuntimeFamily, ResourceFamily: "huawei.com/Ascend910", Healthy: true},
	})
	require.NoError(t, err)
	provider.healthy = true
	assert.Equal(t, []Resource{
		{Type: TypeNPU, ProductModel: "ascend910", DeviceIDs: []uint32{0}},
		{Type: TypeNPU, ProductModel: "ascend910b4", DeviceIDs: []uint32{1}},
	}, provider.Resources())
	provider.leases = make(map[string]string)
	_, err = provider.Acquire("mixed", config.RuntimeNameRunc, &api.XpuAllocation{Type: "npu", DeviceIds: []uint32{0, 1}})
	require.ErrorContains(t, err, "same product model")
	assert.Empty(t, provider.leases)
}

func TestAscendProviderValidatesDeviceFamilyAndUnauthorizedEdits(t *testing.T) {
	provider := &ascendProvider{devices: make(map[uint32]ascendDevice)}
	err := provider.acceptDiscovery([]ascendDevice{
		{SchedulerID: 0, LogicID: 0, StableID: "a", ProductModel: "custom-driver-model", Generation: "A3", RuntimeFamily: ascendRuntimeFamily, ResourceFamily: "huawei.com/Ascend910", Healthy: true},
	})
	require.NoError(t, err)

	provider = &ascendProvider{devices: make(map[uint32]ascendDevice)}
	err = provider.acceptDiscovery([]ascendDevice{
		{SchedulerID: 0, LogicID: 0, StableID: "a", ProductModel: "ascend910", Generation: "A1", RuntimeFamily: ascendRuntimeFamily, ResourceFamily: "huawei.com/Ascend910", Healthy: true},
	})
	require.ErrorContains(t, err, "unsupported or inconsistent Ascend device family")

	provider = &ascendProvider{devices: make(map[uint32]ascendDevice)}
	err = provider.acceptDiscovery([]ascendDevice{
		{SchedulerID: 0, LogicID: 0, StableID: "a", ProductModel: "", Generation: "A3", RuntimeFamily: ascendRuntimeFamily, ResourceFamily: "huawei.com/Ascend910", Healthy: true},
	})
	require.ErrorContains(t, err, "must not be empty")

	provider = &ascendProvider{providerVersion: "v1", statDevice: func(string) (string, int64, int64, error) {
		return "c", 1, 2, nil
	}}
	_, err = provider.validateEdits([]int32{0}, ascendRuntimeFamily, adapterEdits{
		SchemaVersion: 1, ProviderVersion: "v1",
		Devices: []adapterDevice{{HostPath: "/dev/davinci9", ContainerPath: "/dev/davinci9", Type: "c", Major: 1, Minor: 2, Permissions: "rwm"}},
	})
	require.ErrorContains(t, err, "outside the current lease")

	_, err = provider.validateEdits([]int32{0}, ascendRuntimeFamily, adapterEdits{
		SchemaVersion: 1, ProviderVersion: "v1",
		Devices:       []adapterDevice{{HostPath: "/dev/davinci0", ContainerPath: "/dev/davinci0", Type: "c", Major: 1, Minor: 2, Permissions: "rwm"}},
		SharedDevices: []adapterDevice{{HostPath: "/dev/random", ContainerPath: "/dev/davinci_manager", Type: "c", Major: 1, Minor: 2, Permissions: "rwm"}},
	})
	require.ErrorContains(t, err, "mapping")
}
