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

package config

import (
	"os"
	"testing"

	"github.com/pelletier/go-toml"
)

func TestPublicSampleConfigIsComplete(t *testing.T) {
	data, err := os.ReadFile("../configs/sandboxd.toml")
	if err != nil {
		t.Fatal(err)
	}

	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("decode sample config: %v", err)
	}

	if cfg.RootDir == "" || cfg.StoreDir == "" {
		t.Fatal("sample config must define rootDir and storeDir")
	}
	if cfg.RuntimeBinary[RuntimeNameRunsc] == "" {
		t.Fatal("sample config must define the runsc binary")
	}
	if cfg.ImageManagerRoot == "" || cfg.OSSTemplate == "" || cfg.NydusTemplate == "" {
		t.Fatal("sample config must define image-manager state and templates")
	}
	if cfg.OSSAuthsPath == "" || cfg.RegistryAuthsPath == "" {
		t.Fatal("sample config must define public credential files")
	}
	if cfg.CgroupCacheSize <= 0 || cfg.InterfaceCacheSize <= 0 || cfg.MaxInstanceNum <= 0 {
		t.Fatal("sample config must enable bounded cgroup and interface pools")
	}
	if cfg.CPULimitMode != CPULimitModeQuota {
		t.Fatalf("sample cpu_limit_mode = %q, want %q", cfg.CPULimitMode, CPULimitModeQuota)
	}
	if cfg.DNSProxyConcurrencyLimit <= 0 || cfg.DNSProxyPerSandboxConcurrencyLimit <= 0 {
		t.Fatal("sample config must bound global and per-sandbox DNS proxy concurrency")
	}
}
