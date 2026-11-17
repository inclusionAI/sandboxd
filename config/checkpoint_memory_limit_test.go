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
	"github.com/stretchr/testify/require"
)

func TestCheckpointMemoryBudgetTOML(t *testing.T) {
	var cfg Config
	require.NoError(t, toml.Unmarshal([]byte("[plugin.resource]\nfirecracker_checkpoint_memory_max_bytes=2147483648\n"), &cfg))
	require.EqualValues(t, 2<<30, cfg.FirecrackerCheckpointMemoryMaxBytes)
	require.Zero(t, DefaultConfig().FirecrackerCheckpointMemoryMaxBytes)
	for _, value := range []string{"true", `"2GiB"`, "1.5"} {
		t.Run(value, func(t *testing.T) {
			var bad Config
			require.Error(t, toml.Unmarshal([]byte("[plugin.resource]\nfirecracker_checkpoint_memory_max_bytes="+value+"\n"), &bad))
		})
	}
}
