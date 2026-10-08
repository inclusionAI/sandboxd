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

package config

import (
	"testing"

	"github.com/pelletier/go-toml"
)

func TestDefaultConfigUsesHostResolver(t *testing.T) {
	if got := DefaultConfig().RuntimeConfig.ResolvConfPath; got != "/etc/resolv.conf" {
		t.Fatalf("default resolver path = %q", got)
	}
	if got := DefaultConfig().RuntimeConfig.DirectResolvConfPath; got != "" {
		t.Fatalf("direct resolver must inherit the node default, got %q", got)
	}
}

func TestDefaultRuncPaths(t *testing.T) {
	runc := DefaultConfig().RuntimeConfig.Runc
	if runc.StateRoot != DefaultRuncStateRoot ||
		runc.ShimBinary != DefaultRuncShimBinary ||
		runc.KVMDevice != DefaultKVMDevice {
		t.Fatalf("unexpected runc defaults: %+v", runc)
	}
}

func TestDirectResolverOverrideDoesNotChangeNodeResolver(t *testing.T) {
	cfg := DefaultConfig()
	if err := toml.Unmarshal([]byte("[plugin.runtime]\ndirect_resolv_conf_path = \"/config/direct-resolv.conf\"\n"), &cfg); err != nil {
		t.Fatal(err)
	}
	if got := cfg.RuntimeConfig.DirectResolvConfPath; got != "/config/direct-resolv.conf" {
		t.Fatalf("direct resolver path = %q", got)
	}
	if got := cfg.RuntimeConfig.ResolvConfPath; got != "/etc/resolv.conf" {
		t.Fatalf("node resolver path changed to %q", got)
	}
}

func TestDefaultFirecrackerPaths(t *testing.T) {
	fc := DefaultConfig().RuntimeConfig.Firecracker
	if fc.KernelImagePath != DefaultFirecrackerKernel ||
		fc.InitrdPath != DefaultFirecrackerInitrd ||
		fc.KernelArgs != DefaultFirecrackerKernelArgs ||
		fc.KVMDevice != DefaultKVMDevice ||
		fc.DefaultVCPUCount != DefaultFirecrackerVCPUs ||
		fc.DefaultMemoryMiB != DefaultFirecrackerMemoryMiB ||
		fc.DefaultOverlaySizeBytes != DefaultFirecrackerOverlayBytes ||
		fc.VirtioFSDPath != DefaultFirecrackerVirtioFSD {
		t.Fatalf("unexpected firecracker defaults: %+v", fc)
	}
}
