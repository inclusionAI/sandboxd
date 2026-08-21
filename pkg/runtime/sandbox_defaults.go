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

const DefaultSandboxHostname = "akernel"

// SandboxDefaults contains base-spec values needed by the common sandbox
// preparation layer before control is handed to a runtime handler.
type SandboxDefaults struct {
	Hostname          string
	MountDestinations []string
}

// SandboxDefaultsProvider is an optional extension implemented by OCI-based
// handlers. Keeping it separate from Handler preserves compatibility for
// external and test handlers.
type SandboxDefaultsProvider interface {
	SandboxDefaults() SandboxDefaults
}

func (r *BundleLoader) SandboxDefaults() SandboxDefaults {
	defaults := SandboxDefaults{Hostname: DefaultSandboxHostname}
	if r == nil || r.baseSpec == nil {
		return defaults
	}
	if r.baseSpec.Hostname != "" {
		defaults.Hostname = r.baseSpec.Hostname
	}
	defaults.MountDestinations = make([]string, 0, len(r.baseSpec.Mounts))
	for _, mount := range r.baseSpec.Mounts {
		defaults.MountDestinations = append(defaults.MountDestinations, mount.Destination)
	}
	return defaults
}

func (r *RunscHandler) SandboxDefaults() SandboxDefaults {
	return loaderSandboxDefaults(r.ociLoader)
}

func (k *KataHandler) SandboxDefaults() SandboxDefaults {
	return loaderSandboxDefaults(k.ociLoader)
}

func (r *RuncHandler) SandboxDefaults() SandboxDefaults {
	return loaderSandboxDefaults(r.ociLoader)
}

func (f *FirecrackerHandler) SandboxDefaults() SandboxDefaults {
	return loaderSandboxDefaults(f.ociLoader)
}

func loaderSandboxDefaults(loader OciLoader) SandboxDefaults {
	if provider, ok := loader.(SandboxDefaultsProvider); ok {
		return provider.SandboxDefaults()
	}

	return SandboxDefaults{Hostname: DefaultSandboxHostname}
}
