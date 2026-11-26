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
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	api "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/errord"
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
  discover) printf '%s' '{"schema_version":1,"provider_version":"fake-v1","devices":[{"scheduler_id":1,"logic_id":1,"physical_id":2,"device_node_id":2,"stable_id":"die-0","product_model":"ascend910b4","runtime_family":"Ascend910","healthy":true}]}' ;;
  edits)
    request=$(cat)
    case "$request" in
      *'"logic_ids":[1],"device_node_ids":[2],"runtime_family":"Ascend910"'*) ;;
      *) exit 3 ;;
    esac
    printf '%s' '{"schema_version":1,"provider_version":"fake-v1","devices":[{"host_path":"/dev/davinci2","container_path":"/dev/davinci2","type":"c","major":1,"minor":3,"permissions":"rwm"}],"shared_devices":[],"mounts":[],"env":{"ASCEND_RT_VISIBLE_DEVICES":"1","LD_LIBRARY_PATH":"/driver/lib:/dcmi/lib"}}'
    ;;
  *) exit 2 ;;
esac
`), 0700))

	provider := newAscendProvider(config.AscendConfig{
		Enabled: true, Adapter: adapterPath, MountProfile: profilePath,
	}, tempDir)
	healthy, reason := provider.Healthy()
	require.True(t, healthy, reason)
	assert.Equal(t, []Resource{{Type: TypeNPU, ProductModel: "ascend910b4", DeviceIDs: []uint32{1}}}, provider.Resources())
	provider.statDevice = func(path string) (string, int64, int64, error) {
		assert.Equal(t, "/dev/davinci2", path)
		return "c", 1, 3, nil
	}

	updates, err := provider.Acquire(context.Background(), "sbox-npu", config.RuntimeNameRunc, &api.XpuAllocation{
		Type: "npu", DeviceIds: []uint32{1},
	})
	require.NoError(t, err)
	require.Len(t, updates.LinuxDevices, 1)
	require.Len(t, updates.DeviceCgroupRules, 1)
	assert.Equal(t, []string{"/driver/lib", "/dcmi/lib"}, updates.PrependLibraryPaths)
	assert.Contains(t, updates.Annotations, AllocationAnnotation)
	var record leaseRecord
	require.NoError(t, json.Unmarshal([]byte(updates.Annotations[AllocationAnnotation]), &record))
	assert.Equal(t, "ascend910b4", record.ProductModel)
	assert.Equal(t, []int32{1}, record.LogicIDs)
	assert.Equal(t, "/dev/davinci2", updates.LinuxDevices[0].Path)

	_, err = provider.Acquire(context.Background(), "sbox-other", config.RuntimeNameRunc, &api.XpuAllocation{
		Type: "npu", DeviceIds: []uint32{1},
	})
	require.ErrorContains(t, err, "already leased")
	provider.Release("sbox-npu")
	_, err = provider.Acquire(context.Background(), "sbox-other", config.RuntimeNameRunc, &api.XpuAllocation{
		Type: "npu", DeviceIds: []uint32{1},
	})
	require.NoError(t, err)
}

func TestAscendProviderGroupsMixedModelsAndRejectsMixedAllocation(t *testing.T) {
	node0, node1 := int32(0), int32(1)
	provider := &ascendProvider{devices: make(map[uint32]ascendDevice)}
	err := provider.acceptDiscovery([]ascendDevice{
		{SchedulerID: 0, LogicID: 0, StableID: "a", ProductModel: "ascend910", DeviceNodeID: &node0, RuntimeFamily: "Ascend910", Healthy: true},
		{SchedulerID: 1, LogicID: 1, StableID: "b", ProductModel: "ascend910b4", DeviceNodeID: &node1, RuntimeFamily: "Ascend910", Healthy: true},
	})
	require.NoError(t, err)
	provider.healthy = true
	assert.Equal(t, []Resource{
		{Type: TypeNPU, ProductModel: "ascend910", DeviceIDs: []uint32{0}},
		{Type: TypeNPU, ProductModel: "ascend910b4", DeviceIDs: []uint32{1}},
	}, provider.Resources())
	provider.leases = make(map[string]string)
	_, err = provider.Acquire(context.Background(), "mixed", config.RuntimeNameRunc, &api.XpuAllocation{Type: "npu", DeviceIds: []uint32{0, 1}})
	require.ErrorContains(t, err, "same product model")
	assert.Empty(t, provider.leases)
}

func TestAscendProviderValidatesDiscoveryAndUnauthorizedEdits(t *testing.T) {
	node0 := int32(0)
	provider := &ascendProvider{devices: make(map[uint32]ascendDevice)}
	err := provider.acceptDiscovery([]ascendDevice{
		{SchedulerID: 0, LogicID: 0, StableID: "a", ProductModel: "custom-driver-model", DeviceNodeID: &node0, RuntimeFamily: "Ascend910", Healthy: true},
	})
	require.NoError(t, err)

	provider = &ascendProvider{devices: make(map[uint32]ascendDevice)}
	err = provider.acceptDiscovery([]ascendDevice{
		{SchedulerID: 0, LogicID: 0, StableID: "a", ProductModel: "ascend910", RuntimeFamily: "Ascend910", Healthy: true},
	})
	require.ErrorContains(t, err, "missing or invalid Ascend device node ID")

	provider = &ascendProvider{devices: make(map[uint32]ascendDevice)}
	err = provider.acceptDiscovery([]ascendDevice{
		{SchedulerID: 0, LogicID: 0, StableID: "a", ProductModel: "", DeviceNodeID: &node0, RuntimeFamily: "Ascend910", Healthy: true},
	})
	require.ErrorContains(t, err, "must not be empty")

	provider = &ascendProvider{providerVersion: "v1", statDevice: func(string) (string, int64, int64, error) {
		return "c", 1, 2, nil
	}}
	_, err = provider.validateEdits([]int32{0}, "Ascend910", adapterEdits{
		SchemaVersion: 1, ProviderVersion: "v1",
		Devices: []adapterDevice{{HostPath: "/dev/davinci9", ContainerPath: "/dev/davinci9", Type: "c", Major: 1, Minor: 2, Permissions: "rwm"}},
	})
	require.ErrorContains(t, err, "outside the current lease")

	_, err = provider.validateEdits([]int32{0}, "Ascend910", adapterEdits{
		SchemaVersion: 1, ProviderVersion: "v1",
		Devices:       []adapterDevice{{HostPath: "/dev/davinci0", ContainerPath: "/dev/davinci0", Type: "c", Major: 1, Minor: 2, Permissions: "rwm"}},
		SharedDevices: []adapterDevice{{HostPath: "/dev/random", ContainerPath: "/dev/davinci_manager", Type: "c", Major: 1, Minor: 2, Permissions: "rwm"}},
	})
	require.ErrorContains(t, err, "mapping")
}

func TestAscendCancellationPreservesResourceSampling(t *testing.T) {
	node0 := int32(0)
	tempDir := t.TempDir()
	adapterPath := filepath.Join(tempDir, "adapter")
	marker := adapterPath + ".entered"
	require.NoError(t, os.WriteFile(adapterPath, []byte(`#!/bin/sh
case "$1" in
  edits) touch "$0.entered"; exec sleep 30 ;;
  *) exit 1 ;;
esac
`), 0700))
	provider := &ascendProvider{
		config:    config.AscendConfig{Adapter: adapterPath},
		devices:   map[uint32]ascendDevice{0: {StableID: "card-0", DeviceNodeID: &node0}},
		resources: []Resource{{Type: TypeNPU, ProductModel: "ascend310p3", DeviceIDs: []uint32{0}}},
		leases:    make(map[string]string),
		healthy:   true,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	allocation := &api.XpuAllocation{Type: TypeNPU, DeviceIds: []uint32{0}}
	done := make(chan error, 1)
	go func() {
		_, err := provider.Acquire(ctx, "sbox-first", config.RuntimeNameRunc, allocation)
		done <- err
	}()
	require.Eventually(t, func() bool {
		_, err := os.Stat(marker)
		return err == nil
	}, 3*time.Second, 10*time.Millisecond)

	sampled := make(chan []Resource, 1)
	go func() { sampled <- provider.Resources() }()
	select {
	case resources := <-sampled:
		require.Len(t, resources, 1)
	case <-time.After(time.Second):
		t.Fatal("adapter blocked the resource snapshot")
	}

	_, err := provider.Acquire(ctx, "sbox-second", config.RuntimeNameRunc, allocation)
	require.ErrorContains(t, err, "already leased")
	cancel()
	select {
	case err := <-done:
		require.True(t, errors.Is(err, context.Canceled), "unexpected acquire error: %v", err)
	case <-time.After(time.Second):
		t.Fatal("adapter ignored the caller cancellation")
	}
	require.Empty(t, provider.leases)
}

func TestAscendCapacityRequiresAvailableRunc(t *testing.T) {
	provider := &ascendProvider{
		healthy:   true,
		resources: []Resource{{Type: TypeNPU, ProductModel: "ascend310p3", DeviceIDs: []uint32{0}}},
	}
	for _, available := range []bool{false, true} {
		manager := &Manager{providers: map[string]Provider{TypeNPU: provider}}
		manager.SetRuntimeAvailable(func(name string) bool {
			return available && name == config.RuntimeNameRunc
		})
		if available {
			require.Equal(t, provider.Resources(), manager.Resources())
		} else {
			require.Empty(t, manager.Resources())
			allocation := []*api.XpuAllocation{{Type: TypeNPU, DeviceIds: []uint32{0}}}
			require.ErrorIs(t, manager.ValidateRuntime(config.RuntimeNameRunc, allocation), errord.ErrUnavailable)
			_, err := manager.Acquire(context.Background(), "recovery", config.RuntimeNameRunc, allocation)
			require.ErrorIs(t, err, errord.ErrUnavailable)
			require.ErrorIs(t, manager.ValidateRuntime(config.RuntimeNameRunsc, allocation), errord.ErrInvalidArgument)
		}
	}
	manager := New("", false, t.TempDir(), config.XPUConfig{
		Ascend: config.AscendConfig{Enabled: true, Adapter: "/missing-adapter"},
	})
	require.NotContains(t, manager.providers, TypeNPU)
	require.Empty(t, manager.Resources())
}
