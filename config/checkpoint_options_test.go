// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"testing"

	"github.com/pelletier/go-toml"
	"github.com/stretchr/testify/require"
)

func TestCheckpointOptionsDefaultOff(t *testing.T) {
	cfg := DefaultConfig()
	require.False(t, cfg.RuntimeConfig.Runsc.CheckpointDirectIO)
	require.False(t, cfg.RuntimeConfig.Runsc.BackgroundRestore)
	require.False(t, cfg.RuntimeConfig.CheckpointSync.SyncOutput)
	mode, err := NormalizeRunscCheckpointMode(cfg.RuntimeConfig.Runsc.CheckpointMode)
	require.NoError(t, err)
	require.Equal(t, "full", mode)
}

func TestCheckpointOptionsTOML(t *testing.T) {
	for _, mode := range []string{"full", "reflink"} {
		for _, background := range []bool{false, true} {
			for _, syncOutput := range []bool{false, true} {
				t.Run(fmt.Sprintf("mode=%s/background=%t/sync=%t", mode, background, syncOutput), func(t *testing.T) {
					cfg := DefaultConfig()
					input := fmt.Sprintf("[plugin.runtime.runsc]\ncheckpoint_mode=%q\nbackground_restore=%t\n[plugin.runtime.checkpoint_sync]\nsync_output=%t\n", mode, background, syncOutput)
					require.NoError(t, toml.Unmarshal([]byte(input), &cfg))
					require.Equal(t, mode, cfg.RuntimeConfig.Runsc.CheckpointMode)
					require.Equal(t, background, cfg.RuntimeConfig.Runsc.BackgroundRestore)
					require.Equal(t, syncOutput, cfg.RuntimeConfig.CheckpointSync.SyncOutput)
				})
			}
		}
	}
}

func TestRunscCheckpointDirectIOTOML(t *testing.T) {
	cfg := DefaultConfig()
	require.NoError(t, toml.Unmarshal([]byte("[plugin.runtime.runsc]\ncheckpoint_direct_io=true\n"), &cfg))
	require.True(t, cfg.RuntimeConfig.Runsc.CheckpointDirectIO)
}
