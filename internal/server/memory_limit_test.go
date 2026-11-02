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

package server

import (
	"testing"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/pelletier/go-toml"
	"github.com/stretchr/testify/require"
)

func TestMemoryLimitConfigAndIndependentDistillLimit(t *testing.T) {
	for _, value := range []string{"", "0", "256MiB", "64GiB"} {
		t.Run(value, func(t *testing.T) {
			var cfg config.Config
			require.NoError(t, toml.Unmarshal([]byte(`
[plugin.resource]
cgroup_cache_size = 1
[plugin.resource.memory_limit]
enabled = true
total_reserve = "1280MiB"
[plugin.image]
cgroup_memory_limit = "`+value+`"
`), &cfg))
			require.True(t, cfg.MemoryLimit.Enabled)
			require.Equal(t, "1280MiB", cfg.MemoryLimit.TotalReserve)
			require.Equal(t, value, cfg.CgroupMemoryLimit)
			require.NoError(t, validateMemoryLimitConfig(cfg), "parent policy does not require or derive a distill-fs reserve")
		})
	}
}

func TestMemoryLimitRequiresCgroupManagement(t *testing.T) {
	cfg := config.Config{PluginConfig: config.PluginConfig{ResourceConfig: config.ResourceConfig{
		CgroupCacheSize: 1, MemoryLimit: config.MemoryLimitConfig{Enabled: true, TotalReserve: "1GiB"},
	}}}
	require.NoError(t, validateMemoryLimitConfig(cfg))
	cfg.DisableCgroup = true
	require.ErrorContains(t, validateMemoryLimitConfig(cfg), "enabled cgroup management")
	cfg.DisableCgroup = false
	cfg.CgroupCacheSize = 0
	require.ErrorContains(t, validateMemoryLimitConfig(cfg), "positive cgroup_cache_size")
	cfg.MemoryLimit.Enabled = false
	require.NoError(t, validateMemoryLimitConfig(cfg), "disabled policy must not require cgroup management")
}
