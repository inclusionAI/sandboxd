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

import "testing"

func TestDefaultConfigUsesHostResolver(t *testing.T) {
	if got := DefaultConfig().RuntimeConfig.ResolvConfPath; got != "/etc/resolv.conf" {
		t.Fatalf("default resolver path = %q", got)
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
