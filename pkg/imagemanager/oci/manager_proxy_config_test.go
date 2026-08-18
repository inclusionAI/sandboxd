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

package oci

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigProxyURL(t *testing.T) {
	tests := []struct {
		name   string
		config string
		want   string
	}{
		{
			name: "registry proxy",
			config: `{
				"registry": {
					"proxy": {
						"url": "http://dragonfly:4001"
					}
				},
				"type": "registry"
			}`,
			want: "http://dragonfly:4001",
		},
		{
			name: "oss proxy",
			config: `{
				"oss": {
					"proxy": {
						"url": "http://oss-proxy:4001"
					}
				},
				"type": "oss"
			}`,
			want: "http://oss-proxy:4001",
		},
		{
			name: "registry proxy takes precedence",
			config: `{
				"registry": {
					"proxy": {
						"url": "http://registry-proxy:4001"
					}
				},
				"oss": {
					"proxy": {
						"url": "http://oss-proxy:4001"
					}
				}
			}`,
			want: "http://registry-proxy:4001",
		},
		{
			name: "top-level proxy is ignored",
			config: `{
				"proxy": {
					"url": "http://legacy-proxy:4001"
				}
			}`,
			want: "",
		},
		{
			name:   "proxy is not configured",
			config: `{}`,
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "registry.json")
			if err := os.WriteFile(configPath, []byte(tt.config), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}

			cfg, err := loadConfig(configPath)
			if err != nil {
				t.Fatalf("loadConfig() error: %v", err)
			}
			if got := cfg.proxyURL(); got != tt.want {
				t.Fatalf("proxyURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNilConfigProxyURL(t *testing.T) {
	var cfg *Config
	if got := cfg.proxyURL(); got != "" {
		t.Fatalf("proxyURL() = %q, want empty", got)
	}
}
