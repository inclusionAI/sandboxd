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

import "testing"

func TestBundleLoaderSandboxDefaults(t *testing.T) {
	loader := &BundleLoader{baseSpec: &Spec{
		Hostname: "configured-host",
		Mounts:   []Mount{{Destination: "/etc/resolv.conf"}},
	}}
	defaults := loader.SandboxDefaults()
	if defaults.Hostname != "configured-host" {
		t.Fatalf("hostname = %q", defaults.Hostname)
	}
	if len(defaults.MountDestinations) != 1 ||
		defaults.MountDestinations[0] != "/etc/resolv.conf" {
		t.Fatalf("mount destinations = %v", defaults.MountDestinations)
	}
}

func TestBundleLoaderSandboxDefaultsFallback(t *testing.T) {
	defaults := (&BundleLoader{baseSpec: &Spec{}}).SandboxDefaults()
	if defaults.Hostname != DefaultSandboxHostname {
		t.Fatalf("hostname = %q, want %q", defaults.Hostname, DefaultSandboxHostname)
	}
}
