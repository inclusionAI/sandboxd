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

package server

import (
	"errors"
	"fmt"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager"
	"github.com/inclusionAI/sandboxd/pkg/sandbox"
	"github.com/sirupsen/logrus"
)

type preparedStartResources struct {
	sandbox.OccupiedResource
	sandboxIP string
	network   *networkmanager.NetResource
}

func (h *sandboxService) prepareStartResources(runtimeName, sandboxID string) (*preparedStartResources, error) {
	required, err := requiredStartResources(runtimeName, h.config.DisableCgroup)
	if err != nil {
		return nil, err
	}

	resultCh := make(chan resourceResult, len(required))
	for _, name := range required {
		name := name
		go func() {
			value, network, err := h.allocateStartResource(runtimeName, sandboxID, name)
			resultCh <- resourceResult{name: name, value: value, network: network, err: err}
		}()
	}

	resources := &preparedStartResources{
		OccupiedResource: sandbox.OccupiedResource{
			ID:        sandboxID,
			Resources: make(map[string]string, len(required)),
		},
	}

	var firstErr error
	for range required {
		result := <-resultCh
		if result.err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("allocate resource %s failed: %w", result.name, result.err)
			}
			continue
		}
		resources.Resources[result.name] = result.value
		if result.network != nil {
			resources.network = result.network
			resources.sandboxIP = result.network.Ip.String()
		}
	}
	if firstErr != nil {
		if err := h.releaseStartResources(resources.OccupiedResource); err != nil {
			logrus.Warnf("rollback start resources for %s failed after allocation error: %v", sandboxID, err)
		}
		return nil, firstErr
	}
	return resources, nil
}

func requiredStartResources(runtimeName string, disableCgroup bool) ([]string, error) {
	configured := config.RuntimeResources[runtimeName]
	if configured == nil {
		return nil, fmt.Errorf("runtime %s is not supported when preparing resources", runtimeName)
	}
	if disableCgroup && runtimeName == config.RuntimeNameRunc {
		return nil, fmt.Errorf("runtime %s requires cgroup management", runtimeName)
	}
	required := make([]string, 0, len(configured))
	for _, name := range configured {
		if disableCgroup && name == config.ResourceNameCgroup {
			continue
		}
		required = append(required, name)
	}
	return required, nil
}

type resourceResult struct {
	name    string
	value   string
	network *networkmanager.NetResource
	err     error
}

func (h *sandboxService) allocateStartResource(
	runtimeName,
	sandboxID,
	name string,
) (string, *networkmanager.NetResource, error) {
	switch name {
	case config.ResourceNameCgroup:
		if h.cgroupMgr == nil {
			return "", nil, fmt.Errorf("cgroup manager not configured")
		}
		value, err := h.cgroupMgr.Allocate()
		return value, nil, err
	case config.ResourceNameInterface:
		if h.networkMgr == nil {
			return "", nil, fmt.Errorf("network manager not configured")
		}
		network, err := h.networkMgr.Prepare(runtimeName, sandboxID)
		if err != nil {
			return "", nil, err
		}
		return network.resource, network.config, nil
	default:
		return "", nil, fmt.Errorf("resource %s is not registered", name)
	}
}

func (h *sandboxService) releaseStartResources(resources sandbox.OccupiedResource) error {
	var errs []error
	for name, value := range resources.Resources {
		if err := h.releaseStartResource(name, value); err != nil {
			errs = append(errs, fmt.Errorf("release resource %s[%s] failed: %w", name, value, err))
			continue
		}
		logrus.Infof("release resource %s[%s] success", name, value)
	}
	return errors.Join(errs...)
}

func (h *sandboxService) releaseStartResource(name, value string) error {
	switch name {
	case config.ResourceNameCgroup:
		if h.cgroupMgr == nil {
			return fmt.Errorf("cgroup manager not configured")
		}
		return h.cgroupMgr.Recycle(value)
	case config.ResourceNameInterface:
		if h.networkMgr == nil {
			return fmt.Errorf("network manager not configured")
		}
		return h.networkMgr.Release(value)
	default:
		return fmt.Errorf("resource %s is not registered", name)
	}
}
