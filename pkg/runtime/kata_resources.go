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

package runtime

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"google.golang.org/protobuf/proto"
)

const (
	kataDefaultVCPUsAnnotation  = "io.katacontainers.config.hypervisor.default_vcpus"
	kataDefaultMemoryAnnotation = "io.katacontainers.config.hypervisor.default_memory"
	kataMinimumMemoryMiB        = 64
)

func kataHostResources(
	resource *runtime.LinuxSandboxResources,
) *runtime.LinuxSandboxResources {
	if resource == nil {
		return nil
	}
	return proto.Clone(resource).(*runtime.LinuxSandboxResources)
}

// HostCgroupResources maps sandbox resources to the host cgroup enclosing a
// runtime. Kata receives a clone because its shim-facing OCI spec is sanitized
// separately, while the outer VM cgroup retains the requested CPU controls.
func HostCgroupResources(
	runtimeName string,
	resource *runtime.LinuxSandboxResources,
) *runtime.LinuxSandboxResources {
	if runtimeName == config.RuntimeNameKata ||
		runtimeName == config.RuntimeNameFirecracker {
		return kataHostResources(resource)
	}
	return resource
}

// prepareKataResourceSpec gives the VM an explicit topology while its outer
// cgroup independently enforces shares or quota. Kata's dynamic resource
// manager would otherwise interpret container CPU and memory limits as
// resources to add on top of the VM's configured topology. The shim-facing
// spec therefore omits those sizing fields; the complete spec is restored
// after Task.Create for sandboxd bookkeeping.
func prepareKataResourceSpec(
	bundlePath string,
	resource *runtime.LinuxSandboxResources,
) (func() error, error) {
	configPath := filepath.Join(bundlePath, "config.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	var completeSpec Spec
	if err := json.Unmarshal(data, &completeSpec); err != nil {
		return nil, err
	}
	if completeSpec.Annotations == nil {
		completeSpec.Annotations = make(map[string]string)
	}

	vcpus := kataVCPUs(resource)
	completeSpec.Annotations[kataDefaultVCPUsAnnotation] = strconv.FormatUint(vcpus, 10)

	if resource != nil && resource.MemoryLimitInBytes > 0 {
		memoryMiB := resource.MemoryLimitInBytes / (1024 * 1024)
		if memoryMiB < kataMinimumMemoryMiB {
			return nil, fmt.Errorf(
				"Kata requires at least %d MiB of memory, got %d MiB",
				kataMinimumMemoryMiB,
				memoryMiB,
			)
		}
		completeSpec.Annotations[kataDefaultMemoryAnnotation] = strconv.FormatInt(memoryMiB, 10)
	}

	completeData, err := json.MarshalIndent(&completeSpec, "", "  ")
	if err != nil {
		return nil, err
	}
	var shimSpec Spec
	if err := json.Unmarshal(completeData, &shimSpec); err != nil {
		return nil, err
	}
	sanitizeKataShimResources(&shimSpec)
	if err := writeKataSpec(configPath, &shimSpec); err != nil {
		return nil, err
	}

	restore := func() error {
		temporaryPath := configPath + ".tmp"
		if err := os.WriteFile(temporaryPath, completeData, 0644); err != nil {
			return err
		}
		return os.Rename(temporaryPath, configPath)
	}
	return restore, nil
}

func kataVCPUs(resource *runtime.LinuxSandboxResources) uint64 {
	if resource == nil {
		return 1
	}
	if resource.CpuQuota > 0 && resource.CpuPeriod > 0 {
		quota := uint64(resource.CpuQuota)
		return (quota-1)/resource.CpuPeriod + 1
	}
	if resource.CpuShares > 0 {
		return (resource.CpuShares-1)/1024 + 1
	}
	return 1
}

func sanitizeKataShimResources(spec *Spec) {
	if spec.Linux == nil || spec.Linux.Resources == nil {
		return
	}
	resources := spec.Linux.Resources
	if resources.CPU != nil {
		resources.CPU.Quota = nil
		resources.CPU.Period = nil
		resources.CPU.RealtimePeriod = nil
		resources.CPU.RealtimeRuntime = nil
		resources.CPU.Cpus = ""
		resources.CPU.Mems = ""
	}
	resources.Memory = nil
	resources.HugepageLimits = nil
	resources.Unified = nil
}
