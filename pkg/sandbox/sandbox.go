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

package sandbox

import (
	"strings"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/internal/physicalstate"
	"github.com/inclusionAI/sandboxd/internal/util"
	spec "github.com/opencontainers/runtime-spec/specs-go"
)

// Sandbox contains all resources associated with the sandbox. All methods to
// mutate the internal state are thread-safe.
type Sandbox struct {
	// metadata stores the metadata of the sandbox. Can not be modified.
	Metadata *physicalstate.SandboxMetadata
	// Status stores the status of the sandbox.
	Status StatusStorage
	// PATH is the path to the sandbox's data. Under this path, there is a config.json and metadata.pb file.
	Spec *spec.Spec
	PATH string
}

type EventType string

const (
	EventTypeCreate EventType = "create"
	EventTypeStart  EventType = "start"
	EventTypeExit   EventType = "exit"
	EventTypeDelete EventType = "delete"
)

type Event struct {
	Type      EventType                      `json:"type"`
	SandboxID string                         `json:"id"`
	MetaData  *physicalstate.SandboxMetadata `json:"metadata"`
	// lifecycle information
	Pid       int32     `json:"pid"`
	ExitedAt  time.Time `json:"exited_at"`
	ExitCode  int32     `json:"exit_code"`
	OOMKilled bool      `json:"oom_killed,omitempty"`
	Reason    string    `json:"reason"`
}

func (c *Sandbox) EnvValue(key string) string {
	if c.Spec == nil || c.Spec.Process == nil {
		return ""
	}
	for _, env := range c.Spec.Process.Env {
		s := strings.Split(env, "=")
		if len(s) == 2 && s[0] == key {
			return s[1]
		}
	}
	return ""
}

func (c *Sandbox) ApiStatus() *runtime.SandboxStatus {
	if c.Status == nil || c.Metadata == nil {
		return &runtime.SandboxStatus{}
	}
	current := c.Status.Get()
	envKv := make([]*runtime.KeyValue, 0)
	var command []string
	var mounts []*runtime.Mount
	if c.Spec != nil {
		mounts = util.MountToApi(c.Spec.Mounts)
		if c.Spec.Process != nil {
			command = append([]string(nil), c.Spec.Process.Args...)
			for _, env := range c.Spec.Process.Env {
				parts := strings.SplitN(env, "=", 2)
				if len(parts) != 2 {
					continue
				}
				envKv = append(envKv, &runtime.KeyValue{Key: parts[0], Value: parts[1]})
			}
		}
	}

	copyLabels := make(map[string]string)
	if c.Metadata.Labels != nil {
		for k, v := range c.Metadata.Labels {
			copyLabels[k] = v
		}
	}
	copyMetricLabels := make(map[string]string)
	if c.Metadata.MetricLabels != nil {
		for k, v := range c.Metadata.MetricLabels {
			copyMetricLabels[k] = v
		}
	}

	var copyResource *runtime.LinuxSandboxResources
	resource := current.Resources
	if resource != nil {
		copyResourcesUnified := make(map[string]string)
		if resource.Unified != nil {
			copyResourcesUnified = make(map[string]string, len(resource.Unified))
			for k, v := range resource.Unified {
				copyResourcesUnified[k] = v
			}
		}

		copyHugePageLimits := make([]*runtime.HugepageLimit, len(resource.HugepageLimits))
		for idx := range resource.HugepageLimits {
			copyHugePageLimits[idx] = &runtime.HugepageLimit{
				PageSize: resource.HugepageLimits[idx].PageSize,
				Limit:    resource.HugepageLimits[idx].Limit,
			}
		}
		copyResource = &runtime.LinuxSandboxResources{
			CpuPeriod:              resource.CpuPeriod,
			CpuQuota:               resource.CpuQuota,
			CpuShares:              resource.CpuShares,
			MemoryLimitInBytes:     resource.MemoryLimitInBytes,
			OomScoreAdj:            resource.OomScoreAdj,
			CpusetCpus:             resource.CpusetCpus,
			CpusetMems:             resource.CpusetMems,
			HugepageLimits:         copyHugePageLimits,
			Unified:                copyResourcesUnified,
			MemorySwapLimitInBytes: resource.MemorySwapLimitInBytes,
		}
	}

	return &runtime.SandboxStatus{
		ID:           c.Metadata.ID,
		Command:      command,
		Runtime:      c.Metadata.RuntimeHandler,
		State:        current.State(),
		StartedAt:    util.MustInt64(current.StartedAt),
		FinishedAt:   util.MustInt64(current.FinishedAt),
		ExitCode:     current.ExitCode,
		Labels:       copyLabels,
		MetricLabels: copyMetricLabels,
		Mounts:       mounts,
		Envs:         envKv,
		Stdout:       c.Metadata.Stdout,
		Stderr:       c.Metadata.Stderr,
		Resources:    copyResource,
		Ports:        append([]string(nil), c.Metadata.Ports...),
	}
}
