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
	"time"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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
	GetAvailableResource(maxCPU uint32, maxMem int64) (int64, int64, error)
}

type nodeResourceManager struct {
	resourceCfg corev1.ResourceList
	nodeClt     NodeResourceClient
	onlineMgr   onlineAvailableResourceManager
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

	mgr := &nodeResourceManager{
		resourceCfg: corev1.ResourceList{},
		nodeClt:     nodeClt,
		onlineMgr:   online,
	}
	if err := mgr.update(); err != nil {
		// The cgroup policy remains usable
		// with host limits when the optional vendor capacity ceiling is
		// temporarily unavailable.
		logrus.Warnf("failed to update Alibaba node resource ceiling: %v", err)
	}
	return mgr, nil
}

func (mgr *nodeResourceManager) CpuCapacity() int64 {
	if len(mgr.resourceCfg) == 0 {
		return 0
	}
	return mgr.resourceCfg.Cpu().Value()
}

func (mgr *nodeResourceManager) MemoryCapacity() int64 {
	if len(mgr.resourceCfg) == 0 {
		return 0
	}
	return mgr.resourceCfg.Memory().Value()
}

func (mgr *nodeResourceManager) update() error {
	nodeResource, err := mgr.nodeClt.GetNodeResource()
	if err != nil {
		return fmt.Errorf("failed to get node resources info: %w", err)
	}
	if nodeResource.Status.NodeAllocatable == nil {
		return fmt.Errorf("Alibaba noderesource has no nodeAllocatable status")
	}

	prod, ok := nodeResource.Status.NodeAllocatable.AllocatableResource["Prod"]
	if !ok {
		return fmt.Errorf("failed to find Prod resource")
	}
	resources := prod.ResourceList.DeepCopy()

	if prodFree, ok := nodeResource.Status.NodeAllocatable.AllocatableResource["ProdFree"]; ok {
		cpu := resources.Cpu()
		cpu.Add(*prodFree.Cpu())
		resources[corev1.ResourceCPU] = *cpu

		memory := resources.Memory()
		memory.Add(*prodFree.Memory())
		resources[corev1.ResourceMemory] = *memory
	}
	mgr.resourceCfg = resources
	return nil
}

func (mgr *nodeResourceManager) GetAvailableResource() (int64, int64, error) {
	return mgr.onlineMgr.GetAvailableResource(
		uint32(mgr.CpuCapacity()),
		mgr.MemoryCapacity(),
	)
}

func (mgr *nodeResourceManager) Stop() {}

var _ NodeResourceManager = (*nodeResourceManager)(nil)
