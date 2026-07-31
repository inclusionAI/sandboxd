// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package runtime

import (
	"math"
	"testing"

	api "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
)

func TestHostCgroupResourcesAddsRunscMemoryOverhead(t *testing.T) {
	guest := &api.LinuxSandboxResources{
		CpuShares:          1024,
		MemoryLimitInBytes: 2 << 30,
	}
	host, err := HostCgroupResources(config.RuntimeNameRunsc, guest, 2<<30)
	if err != nil {
		t.Fatal(err)
	}
	if host.MemoryLimitInBytes != 4<<30 {
		t.Fatalf("host memory limit = %d, want %d", host.MemoryLimitInBytes, int64(4<<30))
	}
	if host.CpuShares != guest.CpuShares {
		t.Fatalf("host CPU shares = %d, want %d", host.CpuShares, guest.CpuShares)
	}
	if guest.MemoryLimitInBytes != 2<<30 {
		t.Fatal("HostCgroupResources mutated the guest resource")
	}
}

func TestHostCgroupResourcesLeavesUnlimitedRunscMemoryUnchanged(t *testing.T) {
	guest := &api.LinuxSandboxResources{}
	host, err := HostCgroupResources(config.RuntimeNameRunsc, guest, 2<<30)
	if err != nil {
		t.Fatal(err)
	}
	if host != guest {
		t.Fatal("unlimited runsc resources should be returned unchanged")
	}
}

func TestHostCgroupResourcesRejectsRunscMemoryOverflow(t *testing.T) {
	guest := &api.LinuxSandboxResources{MemoryLimitInBytes: math.MaxInt64}
	if _, err := HostCgroupResources(config.RuntimeNameRunsc, guest, 1); err == nil {
		t.Fatal("HostCgroupResources accepted an overflowing memory limit")
	}
}

func TestHostCgroupResourcesRejectsNegativeRunscMemoryOverhead(t *testing.T) {
	if _, err := HostCgroupResources(config.RuntimeNameRunsc, &api.LinuxSandboxResources{}, -1); err == nil {
		t.Fatal("HostCgroupResources accepted a negative memory overhead")
	}
}
