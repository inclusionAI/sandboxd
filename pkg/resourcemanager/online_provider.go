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
	"context"
	"encoding/json"
	"fmt"
	"math"
	"time"

	corev1 "k8s.io/api/core/v1"
	apiresource "k8s.io/apimachinery/pkg/api/resource"
)

type CgroupConfig struct {
	HostPidsCgroupPath    string
	HostCpuCgroupPath     string
	HostCpuacctCgroupPath string
	HostMemCgroupPath     string
	FaasCpuaactCgroupPath string
	FaasCpusetCgroupPath  string
	FaasCpuCgroupPath     string
	FaasMemCgroupPath     string
	ZoneinfoPath          string
}

type ResourceMap struct {
	corev1.ResourceList `json:"resources,omitempty"`
}

type NodeAllocatableResource struct {
	AllocatableResource map[string]ResourceMap `json:"resources,omitempty"`
}

type NodeResourceStatus struct {
	NodeAllocatable *NodeAllocatableResource `json:"nodeAllocatable,omitempty"`
}

type NodeResource struct {
	Status NodeResourceStatus `json:"status,omitempty"`
}

type NodeResourceClient interface {
	GetNodeResource() (*NodeResource, error)
}

func (clt *nodeClient) GetNodeResource() (*NodeResource, error) {
	nodeResource := &NodeResource{}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	data, err := clt.client.RESTClient().Get().
		AbsPath("apis", "nodes.alibabacloud.com", "v1beta1").
		Resource("noderesources").
		Name(clt.localNodeName).
		Do(ctx).
		Raw()
	if err != nil {
		return nil, fmt.Errorf("request Alibaba noderesource %s: %w", clt.localNodeName, err)
	}
	if err := json.Unmarshal(data, nodeResource); err != nil {
		return nil, fmt.Errorf("decode Alibaba noderesource %s: %w", clt.localNodeName, err)
	}
	return nodeResource, nil
}

type onlineAvailableResourceManager interface {
	GetAvailableResource(maxCPUMilli, maxMem int64) (int64, int64, error)
}

type nodeResourceManager struct {
	nodeClt   NodeResourceClient
	onlineMgr onlineAvailableResourceManager
}

func newOnlineCgroupResourceManager(configPath string) (*nodeResourceManager, error) {
	if configPath == "" {
		return nil, fmt.Errorf("online_cfg_path is required for provider %q", ProviderOnlineCgroup)
	}

	online, err := newOnlineResourceManager(nil, configPath)
	if err != nil {
		return nil, fmt.Errorf("create online cgroup resource manager: %w", err)
	}
	nodeClt, err := newNodeK8sClient()
	if err != nil {
		return nil, fmt.Errorf("create Alibaba noderesource client: %w", err)
	}

	return &nodeResourceManager{nodeClt: nodeClt, onlineMgr: online}, nil
}

func (mgr *nodeResourceManager) cloudCapacity() (int64, int64, error) {
	node, err := mgr.nodeClt.GetNodeResource()
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get node resources info: %w", err)
	}
	if node == nil || node.Status.NodeAllocatable == nil {
		return 0, 0, fmt.Errorf("Alibaba noderesource has no nodeAllocatable status")
	}
	alloc := node.Status.NodeAllocatable.AllocatableResource
	prod, ok := alloc["Prod"]
	if !ok {
		return 0, 0, fmt.Errorf("failed to find Prod resource")
	}
	cpu, hasCPU := prod.ResourceList[corev1.ResourceCPU]
	memory, hasMemory := prod.ResourceList[corev1.ResourceMemory]
	if !hasCPU || !hasMemory {
		return 0, 0, fmt.Errorf("Prod resource requires explicit cpu and memory")
	}
	free := alloc["ProdFree"].ResourceList
	freeCPU := free[corev1.ResourceCPU]
	freeMemory := free[corev1.ResourceMemory]
	if cpu.Sign() < 0 || memory.Sign() < 0 || freeCPU.Sign() < 0 || freeMemory.Sign() < 0 {
		return 0, 0, fmt.Errorf("Prod and ProdFree resource amounts must be nonnegative")
	}
	// Quantity can carry a decimal backed by a pointer. Work on copies so
	// repeated samples cannot accumulate ProdFree into the API response.
	cpu = cpu.DeepCopy()
	memory = memory.DeepCopy()
	cpu.Add(freeCPU)
	memory.Add(freeMemory)
	maxCPU := apiresource.NewMilliQuantity(math.MaxInt64, apiresource.DecimalSI)
	if cpu.Cmp(*maxCPU) > 0 || memory.CmpInt64(math.MaxInt64) > 0 {
		return 0, 0, fmt.Errorf("Alibaba noderesource capacity exceeds supported units")
	}
	return cpu.MilliValue(), memory.Value(), nil
}

func (mgr *nodeResourceManager) GetAvailableResource() (int64, int64, error) {
	cpu, memory, err := mgr.cloudCapacity()
	if err != nil {
		return 0, 0, err
	}
	return mgr.onlineMgr.GetAvailableResource(cpu, memory)
}

func (mgr *nodeResourceManager) Stop() {}

var _ NodeResourceManager = (*nodeResourceManager)(nil)
