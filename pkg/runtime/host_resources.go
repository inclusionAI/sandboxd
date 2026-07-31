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
	"fmt"
	"math"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"google.golang.org/protobuf/proto"
)

// HostCgroupResources maps requested resources to the host cgroup enclosing a
// runtime. Kata keeps CPU quota/period inside its VM topology. Runsc can add a
// configured runtime overhead to the effective sandbox memory budget.
func HostCgroupResources(
	runtimeName string,
	resource *runtime.LinuxSandboxResources,
	runscMemoryOverhead int64,
) (*runtime.LinuxSandboxResources, error) {
	switch runtimeName {
	case config.RuntimeNameKata:
		return kataHostResources(resource), nil
	case config.RuntimeNameRunsc:
		return runscHostResources(resource, runscMemoryOverhead)
	default:
		return resource, nil
	}
}

// runscHostResources includes runsc and host-side cache overhead in the host
// cgroup limit. Runsc uses this cgroup as the effective sandbox memory boundary
// and derives the memory reported inside the sandbox from it.
func runscHostResources(
	resource *runtime.LinuxSandboxResources,
	memoryOverhead int64,
) (*runtime.LinuxSandboxResources, error) {
	if memoryOverhead < 0 {
		return nil, fmt.Errorf("runsc host cgroup memory overhead must not be negative")
	}
	if resource == nil || resource.MemoryLimitInBytes <= 0 || memoryOverhead == 0 {
		return resource, nil
	}
	if resource.MemoryLimitInBytes > math.MaxInt64-memoryOverhead {
		return nil, fmt.Errorf("runsc host cgroup memory limit overflows int64")
	}
	result := proto.Clone(resource).(*runtime.LinuxSandboxResources)
	result.MemoryLimitInBytes += memoryOverhead
	return result, nil
}
