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
	"math"
	"testing"

	"github.com/pelletier/go-toml"
)

func TestNormalizeRunscPlatform(t *testing.T) {
	for _, test := range []struct {
		input   string
		want    string
		wantErr bool
	}{
		{input: "", want: RunscPlatformSystrap},
		{input: " systrap ", want: RunscPlatformSystrap},
		{input: "KVM", want: RunscPlatformKVM},
		{input: "ptrace", wantErr: true},
		{input: "systrap|kvm", wantErr: true},
	} {
		got, err := NormalizeRunscPlatform(test.input)
		if test.wantErr {
			if err == nil {
				t.Errorf("NormalizeRunscPlatform(%q) unexpectedly succeeded", test.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("NormalizeRunscPlatform(%q): %v", test.input, err)
			continue
		}
		if got != test.want {
			t.Errorf("NormalizeRunscPlatform(%q) = %q, want %q", test.input, got, test.want)
		}
	}
}

func TestDefaultConfigUsesRunscSystrap(t *testing.T) {
	if got := DefaultConfig().RuntimeConfig.Runsc.Platform; got != RunscPlatformSystrap {
		t.Fatalf("DefaultConfig runsc platform = %q, want %q", got, RunscPlatformSystrap)
	}
}

func TestRunscPlatformTOML(t *testing.T) {
	var cfg Config
	if err := toml.Unmarshal([]byte(
		"[plugin.runtime.runsc]\nplatform = \"kvm\"\n",
	), &cfg); err != nil {
		t.Fatalf("decode runsc platform: %v", err)
	}
	if got := cfg.RuntimeConfig.Runsc.Platform; got != RunscPlatformKVM {
		t.Fatalf("configured runsc platform = %q, want %q", got, RunscPlatformKVM)
	}
}

func TestNormalizeCPULimitMode(t *testing.T) {
	for _, test := range []struct {
		input   string
		want    string
		wantErr bool
	}{
		{input: "", want: CPULimitModeQuota},
		{input: " shares ", want: CPULimitModeShares},
		{input: "QUOTA", want: CPULimitModeQuota},
		{input: "cpuset", wantErr: true},
	} {
		got, err := NormalizeCPULimitMode(test.input)
		if test.wantErr {
			if err == nil {
				t.Errorf("NormalizeCPULimitMode(%q) unexpectedly succeeded", test.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("NormalizeCPULimitMode(%q): %v", test.input, err)
			continue
		}
		if got != test.want {
			t.Errorf("NormalizeCPULimitMode(%q) = %q, want %q", test.input, got, test.want)
		}
	}
}

func TestDefaultConfigUsesCPUQuota(t *testing.T) {
	if got := DefaultConfig().CPULimitMode; got != CPULimitModeQuota {
		t.Fatalf("DefaultConfig cpu limit mode = %q, want %q", got, CPULimitModeQuota)
	}
}

func TestDefaultConfigUsesOrdinaryFilestore(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.FilestoreDir != DefaultFilestoreDir {
		t.Fatalf("filestore_dir = %q, want %q", cfg.FilestoreDir, DefaultFilestoreDir)
	}
	if cfg.FilestoreDirSize != "" {
		t.Fatalf("filestore_dir_size = %q, want empty", cfg.FilestoreDirSize)
	}
	if cfg.FilestoreXFSEnabled {
		t.Fatal("filestore_xfs_enabled = true, want false")
	}
	if cfg.LoopDeviceDir != DefaultLoopDeviceDir {
		t.Fatalf("loop_device_dir = %q, want %q", cfg.LoopDeviceDir, DefaultLoopDeviceDir)
	}
	if cfg.FilestoreOvercommitRatio != DefaultFilestoreOvercommitRatio {
		t.Fatalf(
			"filestore_overcommit_ratio = %g, want %g",
			cfg.FilestoreOvercommitRatio,
			DefaultFilestoreOvercommitRatio,
		)
	}
}

func TestValidateFilestoreOvercommitRatio(t *testing.T) {
	for _, test := range []struct {
		name    string
		ratio   float64
		wantErr bool
	}{
		{name: "identity", ratio: 1},
		{name: "fractional", ratio: 1.5},
		{name: "zero", ratio: 0, wantErr: true},
		{name: "below one", ratio: 0.5, wantErr: true},
		{name: "negative", ratio: -1, wantErr: true},
		{name: "nan", ratio: math.NaN(), wantErr: true},
		{name: "positive infinity", ratio: math.Inf(1), wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateFilestoreOvercommitRatio(test.ratio)
			if (err != nil) != test.wantErr {
				t.Fatalf("ValidateFilestoreOvercommitRatio(%g) error = %v", test.ratio, err)
			}
		})
	}
}

func TestFilestoreOvercommitRatioTOML(t *testing.T) {
	for _, test := range []struct {
		name string
		toml string
		want float64
	}{
		{name: "omitted", toml: "[plugin.runtime]\n", want: 1},
		{
			name: "configured",
			toml: "[plugin.runtime]\nfilestore_overcommit_ratio = 2.5\n",
			want: 2.5,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var cfg Config
			cfg.FilestoreOvercommitRatio = DefaultFilestoreOvercommitRatio
			if err := toml.Unmarshal([]byte(test.toml), &cfg); err != nil {
				t.Fatalf("decode config: %v", err)
			}
			if cfg.FilestoreOvercommitRatio != test.want {
				t.Fatalf(
					"filestore_overcommit_ratio = %g, want %g",
					cfg.FilestoreOvercommitRatio,
					test.want,
				)
			}
		})
	}
}

func TestDefaultConfigDisablesLocalDNAT(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.EnableLocalDNAT {
		t.Fatal("DefaultConfig local DNAT is enabled, want disabled")
	}
	if cfg.EnableNetworkACL {
		t.Fatal("DefaultConfig network ACL is enabled, want disabled")
	}
	if cfg.DNSProxyConcurrencyLimit != 256 || cfg.DNSProxyPerSandboxConcurrencyLimit != 16 {
		t.Fatalf(
			"DefaultConfig DNS concurrency = %d/%d, want 256/16",
			cfg.DNSProxyConcurrencyLimit,
			cfg.DNSProxyPerSandboxConcurrencyLimit,
		)
	}
}

func TestNetworkConfigEnablesLocalDNAT(t *testing.T) {
	var cfg Config
	if err := toml.Unmarshal([]byte(
		"[plugin.network]\n"+
			"nat_backend = \"bpfnat\"\n"+
			"bpfnat_device = \"eth0\"\n"+
			"enable_local_dnat = true\n"+
			"enable_network_acl = true\n"+
			"dns_proxy_concurrency_limit = 128\n"+
			"dns_proxy_per_sandbox_concurrency_limit = 8\n",
	), &cfg); err != nil {
		t.Fatalf("decode local DNAT config: %v", err)
	}
	if cfg.NatBackend != NatBackendBpfnat {
		t.Fatalf("configured NAT backend = %q, want %q", cfg.NatBackend, NatBackendBpfnat)
	}
	if cfg.BpfnatDevice != "eth0" {
		t.Fatalf("configured bpfnat device = %q, want eth0", cfg.BpfnatDevice)
	}
	if !cfg.EnableLocalDNAT {
		t.Fatal("configured local DNAT is disabled, want enabled")
	}
	if !cfg.EnableNetworkACL {
		t.Fatal("configured network ACL is disabled, want enabled")
	}
	if cfg.DNSProxyConcurrencyLimit != 128 || cfg.DNSProxyPerSandboxConcurrencyLimit != 8 {
		t.Fatalf(
			"configured DNS concurrency = %d/%d, want 128/8",
			cfg.DNSProxyConcurrencyLimit,
			cfg.DNSProxyPerSandboxConcurrencyLimit,
		)
	}
}
