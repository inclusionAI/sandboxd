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
	"strings"
	"testing"

	"github.com/pelletier/go-toml"
	"github.com/stretchr/testify/require"
)

func TestMemoryLimitConfigTotalReserve(t *testing.T) {
	cfg := DefaultConfig()
	require.NoError(t, toml.NewDecoder(strings.NewReader(`
[plugin.resource.memory_limit]
enabled = true
total_reserve = "22GiB"
[plugin.image]
cgroup_memory_limit = "64GiB"
`)).Decode(&cfg))
	require.Equal(t, MemoryLimitConfig{Enabled: true, TotalReserve: "22GiB"}, cfg.MemoryLimit)
	require.Equal(t, "64GiB", cfg.CgroupMemoryLimit)
	require.Equal(t, DefaultCgroupRoot, cfg.CgroupRootName, "unrelated programmatic defaults survive decoding")
}

func TestMemoryLimitConfigDisabledByDefault(t *testing.T) {
	for _, input := range []string{"", "[plugin.resource.memory_limit]\nenabled = false\n", "[plugin.resource.memory_limit]\ntotal_reserve = \"22GiB\"\n"} {
		var cfg Config
		require.NoError(t, toml.Unmarshal([]byte(input), &cfg), input)
		require.False(t, cfg.MemoryLimit.Enabled, input)
	}
}

func TestMemoryLimitConfigRejectsRemovedFields(t *testing.T) {
	for _, key := range []string{"system_reserve", "control_reserve", "other_reserve", "safety_buffer", "runtime_headroom"} {
		for _, value := range []string{`"0GiB"`, `"2GiB"`, `""`, `"auto"`, `0`} {
			for _, enabled := range []string{"false", "true"} {
				t.Run(key+"/"+value+"/"+enabled, func(t *testing.T) {
					var cfg Config
					input := "[plugin.resource.memory_limit]\nenabled = " + enabled + "\ntotal_reserve = \"22GiB\"\n" + key + " = " + value + "\n"
					err := toml.Unmarshal([]byte(input), &cfg)
					require.ErrorContains(t, err, "memory_limit."+key+" was removed")
					require.ErrorContains(t, err, "migrate to total_reserve")
				})
			}
		}
	}
	var cfg Config
	require.ErrorContains(t, toml.Unmarshal([]byte("[plugin.resource.memory_limit]\nsystem_reserve = \"16GiB\"\n"), &cfg), "was removed", "an old-only configuration cannot silently decode as a disabled policy")
}

func TestMemoryLimitConfigRejectsWrongTypesAndUnknownFields(t *testing.T) {
	for _, test := range []struct{ input, want string }{
		{`enabled = "true"`, "enabled must be a boolean"},
		{`enabled = 1`, "enabled must be a boolean"},
		{`total_reserve = 22`, "total_reserve must be a byte-size string"},
		{`total_reserve = true`, "total_reserve must be a byte-size string"},
		{`total_reserve = ["22GiB"]`, "total_reserve must be a byte-size string"},
		{`total_reserves = "22GiB"`, `unknown memory_limit field "total_reserves"`},
	} {
		t.Run(test.input, func(t *testing.T) {
			var cfg Config
			err := toml.Unmarshal([]byte("[plugin.resource.memory_limit]\n"+test.input+"\n"), &cfg)
			require.ErrorContains(t, err, test.want)
		})
	}
}
