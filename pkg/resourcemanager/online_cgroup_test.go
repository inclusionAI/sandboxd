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

package resourcemanager

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	apiresource "k8s.io/apimachinery/pkg/api/resource"
)

func TestReadOnlineResConfigValid(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "online_resource.json")
	err := os.WriteFile(configPath, []byte(`{
  "online_cgroups": ["kubepods"],
  "offline_cgroups": ["system.slice"],
  "cpu_free_over_sold_ratio": 20,
  "cpu_max_ratio": 95,
  "memory_over_sold_ratio": 10,
  "memory_free_over_sold_ratio": 15,
  "memory_reserve_ratio": 5
}`), 0o644)
	assert.NoError(t, err)

	cfg, err := readOnlineResConfig(configPath)
	assert.NoError(t, err)
	assert.Equal(t, []string{"kubepods"}, cfg.OnlineCgroups)
	assert.Equal(t, []string{"system.slice"}, cfg.OfflineCgroups)
	assert.Equal(t, 20, cfg.CpuFreeOverSoldRatio)
	assert.Equal(t, 95, cfg.CPUMaxRatio)
	assert.Equal(t, 10, cfg.MemoryOverSoldRatio)
	assert.Equal(t, 15, cfg.MemoryFreeOverSoldRatio)
	assert.Equal(t, 5, cfg.MemoryReserveRatio)
}

func TestReadOnlineResConfigInvalidRatio(t *testing.T) {
	tests := []struct {
		name       string
		payload    string
		errContain string
	}{
		{
			name: "cpu max ratio out of range",
			payload: `{
  "cpu_max_ratio": 101,
  "cpu_free_over_sold_ratio": 10,
  "memory_over_sold_ratio": 10,
  "memory_free_over_sold_ratio": 10,
  "memory_reserve_ratio": 10
}`,
			errContain: "cpu_max_ratio must be between 0 and 100",
		},
		{
			name: "cpu free oversold out of range",
			payload: `{
  "cpu_max_ratio": 90,
  "cpu_free_over_sold_ratio": -1,
  "memory_over_sold_ratio": 10,
  "memory_free_over_sold_ratio": 10,
  "memory_reserve_ratio": 10
}`,
			errContain: "cpu_free_over_sold_ratio must be between 0 and 100",
		},
		{
			name: "memory reserve ratio out of range",
			payload: `{
  "cpu_max_ratio": 90,
  "cpu_free_over_sold_ratio": 10,
  "memory_over_sold_ratio": 10,
  "memory_free_over_sold_ratio": 10,
  "memory_reserve_ratio": 101
}`,
			errContain: "memory_reserve_ratio must be between 0 and 100",
		},
		{
			name: "memory oversold out of range",
			payload: `{
  "cpu_max_ratio": 90,
  "cpu_free_over_sold_ratio": 10,
  "memory_over_sold_ratio": -1,
  "memory_free_over_sold_ratio": 10,
  "memory_reserve_ratio": 10
}`,
			errContain: "memory_over_sold_ratio must be between 0 and 100",
		},
		{
			name: "memory free oversold out of range",
			payload: `{
  "cpu_max_ratio": 90,
  "cpu_free_over_sold_ratio": 10,
  "memory_over_sold_ratio": 10,
  "memory_free_over_sold_ratio": 101,
  "memory_reserve_ratio": 10
}`,
			errContain: "memory_free_over_sold_ratio must be between 0 and 100",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "online_resource.json")
			err := os.WriteFile(configPath, []byte(tc.payload), 0o644)
			assert.NoError(t, err)

			_, err = readOnlineResConfig(configPath)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.errContain)
		})
	}
}

func TestReadOnlineResConfigErrors(t *testing.T) {
	_, err := readOnlineResConfig(filepath.Join(t.TempDir(), "not-exist.json"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open config file")

	badPath := filepath.Join(t.TempDir(), "bad.json")
	err = os.WriteFile(badPath, []byte("{"), 0o644)
	assert.NoError(t, err)

	_, err = readOnlineResConfig(badPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse JSON")
}

func TestSmoothValue(t *testing.T) {
	mgr := &onlineResourceManager{startupTime: time.Now()}

	startVal := mgr.smoothValue(100, 200)
	assert.InDelta(t, 110.0, startVal, 0.0001)

	mgr.startupTime = time.Now().Add(-90 * time.Second)
	midVal := mgr.smoothValue(100, 200)
	assert.InDelta(t, 105.5, midVal, 0.0001)

	mgr.startupTime = time.Now().Add(-4 * time.Minute)
	lateVal := mgr.smoothValue(100, 200)
	assert.InDelta(t, 101.0, lateVal, 0.0001)
}

func TestNodeResourceManagerCapacityHelpers(t *testing.T) {
	mgr := &nodeResourceManager{}
	assert.Equal(t, int64(0), mgr.CpuCapacity())
	assert.Equal(t, int64(0), mgr.MemoryCapacity())

	mgr.resourceCfg = corev1.ResourceList{
		corev1.ResourceCPU:    apiresource.MustParse("6"),
		corev1.ResourceMemory: apiresource.MustParse("12Gi"),
	}
	assert.Equal(t, int64(6), mgr.CpuCapacity())
	assert.Equal(t, int64(12<<30), mgr.MemoryCapacity())
}

func TestNodeResourceManagerUpdateProdAndProdFree(t *testing.T) {
	mgr := &nodeResourceManager{nodeClt: &stubNodeResourceClient{resp: &NodeResource{
		Status: NodeResourceStatus{
			NodeAllocatable: &NodeAllocatableResource{
				AllocatableResource: map[string]ResourceMap{
					"Prod": {
						ResourceList: corev1.ResourceList{
							corev1.ResourceCPU:    apiresource.MustParse("4"),
							corev1.ResourceMemory: apiresource.MustParse("8Gi"),
						},
					},
					"ProdFree": {
						ResourceList: corev1.ResourceList{
							corev1.ResourceCPU:    apiresource.MustParse("1"),
							corev1.ResourceMemory: apiresource.MustParse("2Gi"),
						},
					},
				},
			},
		},
	}}}

	err := mgr.update()
	assert.NoError(t, err)
	assert.Equal(t, int64(5), mgr.CpuCapacity())
	assert.Equal(t, int64(10<<30), mgr.MemoryCapacity())
}

func TestNodeResourceManagerUpdateOnlyProd(t *testing.T) {
	mgr := &nodeResourceManager{nodeClt: &stubNodeResourceClient{resp: &NodeResource{
		Status: NodeResourceStatus{
			NodeAllocatable: &NodeAllocatableResource{
				AllocatableResource: map[string]ResourceMap{
					"Prod": {
						ResourceList: corev1.ResourceList{
							corev1.ResourceCPU:    apiresource.MustParse("2"),
							corev1.ResourceMemory: apiresource.MustParse("4Gi"),
						},
					},
				},
			},
		},
	}}}

	err := mgr.update()
	assert.NoError(t, err)
	assert.Equal(t, int64(2), mgr.CpuCapacity())
	assert.Equal(t, int64(4<<30), mgr.MemoryCapacity())
}

func TestNodeResourceManagerUpdateErrors(t *testing.T) {
	mgr := &nodeResourceManager{nodeClt: &stubNodeResourceClient{err: assert.AnError}}
	err := mgr.update()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get node resources info")

	mgr = &nodeResourceManager{nodeClt: &stubNodeResourceClient{resp: &NodeResource{
		Status: NodeResourceStatus{
			NodeAllocatable: &NodeAllocatableResource{AllocatableResource: map[string]ResourceMap{}},
		},
	}}}
	err = mgr.update()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to find Prod resource")
}

type stubNodeResourceClient struct {
	resp *NodeResource
	err  error
}

func (s *stubNodeResourceClient) GetNodeResource() (*NodeResource, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.resp, nil
}
