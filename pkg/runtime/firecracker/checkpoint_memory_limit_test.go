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

package firecracker

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/containerd/cgroups/v3"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/pelletier/go-toml"
	"github.com/stretchr/testify/require"
)

func TestCheckpointMemoryPolicyValidation(t *testing.T) {
	page := int64(os.Getpagesize())
	for _, test := range []struct {
		name     string
		bytes    int64
		disabled bool
		mode     cgroups.CGMode
		bad      bool
	}{
		{"unset v1", 0, false, cgroups.Legacy, false},
		{"unset disabled", 0, true, cgroups.Unified, false},
		{"finite v2", page, false, cgroups.Unified, false},
		{"negative", -page, false, cgroups.Unified, true},
		{"sub-page", 1, false, cgroups.Unified, true},
		{"not aligned", page + 1, false, cgroups.Unified, true},
		{"v1", page, false, cgroups.Legacy, true},
		{"hybrid", page, false, cgroups.Hybrid, true},
		{"disabled", page, true, cgroups.Unified, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateCheckpointMemoryLimit(test.bytes, test.disabled, test.mode)
			if test.bad {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
	cfg := config.Config{}
	cfg.FirecrackerCheckpointMemoryMaxBytes = page
	_, _, err := configureCheckpointMemory(cfg)
	require.Error(t, err, "no managed cgroup pool must fail before changing controls")
}

func TestCheckpointBudgetPathIsPerManagedRoot(t *testing.T) {
	require.Equal(t, CheckpointCgroupPathForRoot("one"), CheckpointCgroupPathForRoot("/one/"))
	require.Equal(t, CheckpointCgroupPathForRoot(""), CheckpointCgroupPathForRoot(config.DefaultCgroupRoot))
	require.NotEqual(t, CheckpointCgroupPathForRoot("/one"), CheckpointCgroupPathForRoot("/two"))
	require.NotEqual(t, CheckpointCgroupPath(), CheckpointCgroupPathForRoot("/one"))
	require.Equal(t, "/", filepath.Dir(CheckpointCgroupPathForRoot("/one/nested")))
}

func TestCheckpointBudgetRejectsOverflowedTOMLBeforeConfiguration(t *testing.T) {
	// This decoder can wrap a uint64 TOML integer into an int64 field. The
	// startup policy must still reject it before any cgroup write occurs.
	for _, text := range []string{"9223372036854775808", "18446744073709551615"} {
		var cfg config.Config
		err := toml.Unmarshal([]byte("[plugin.resource]\nfirecracker_checkpoint_memory_max_bytes="+text+"\n"), &cfg)
		if err == nil {
			require.Error(t, validateCheckpointMemoryLimit(cfg.FirecrackerCheckpointMemoryMaxBytes, false, cgroups.Unified))
		}
	}
}

func checkpointBudgetFixture(t *testing.T, directory, maximum, current, events string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(directory, 0755))
	for name, value := range map[string]string{"memory.max": maximum, "memory.current": current, "cgroup.events": events} {
		require.NoError(t, os.WriteFile(filepath.Join(directory, name), []byte(value), 0600))
	}
}

func TestConfigureCheckpointBudgetPreservesExistingScopeOnOmission(t *testing.T) {
	mount := t.TempDir()
	group, limit, err := configureFirecrackerCheckpointCgroup("/one", 0, mount, cgroups.Unified)
	require.NoError(t, err)
	require.Equal(t, CheckpointCgroupPath(), group)
	require.Zero(t, limit)
	entries, err := os.ReadDir(mount)
	require.NoError(t, err)
	require.Empty(t, entries, "default configuration must create no new cgroup")
	group = CheckpointCgroupPathForRoot("/one")
	directory := filepath.Join(mount, strings.TrimPrefix(group, "/"))
	checkpointBudgetFixture(t, directory, "max", "0", "populated 0\n")
	legacy := filepath.Join(mount, strings.TrimPrefix(CheckpointCgroupPath(), "/"))
	checkpointBudgetFixture(t, legacy, "max", "99999999", "populated 1\n")
	selected, effective, err := configureFirecrackerCheckpointCgroup("one", 4<<20, mount, cgroups.Unified)
	require.NoError(t, err)
	require.Equal(t, group, selected)
	require.EqualValues(t, 4<<20, effective)
	data, err := os.ReadFile(filepath.Join(legacy, "memory.max"))
	require.NoError(t, err)
	require.Equal(t, "max", string(data), "another daemon's legacy group must not change")
	selected, effective, err = configureFirecrackerCheckpointCgroup("one", 0, mount, cgroups.Unified)
	require.NoError(t, err)
	require.Equal(t, group, selected)
	require.EqualValues(t, 4<<20, effective, "option removal must not bypass the configured group")
}

func TestCheckpointBudgetNeverRaisesStricterExistingLimit(t *testing.T) {
	dir := t.TempDir()
	checkpointBudgetFixture(t, dir, "1048576", "99999999", "populated 1\n")
	writes := 0
	effective, err := applyCheckpointMemoryLimit(dir, 4<<20, func(string, int64) error { writes++; return errors.New("must not write") })
	require.NoError(t, err)
	require.EqualValues(t, 1<<20, effective)
	require.Zero(t, writes)
}

func TestCheckpointBudgetRejectsUnsafeLimitChanges(t *testing.T) {
	for _, test := range []struct{ name, maximum, current, events, missing string }{
		{"active", "max", "0", "populated 1\n", ""},
		{"lower active", "8388608", "0", "populated 1\n", ""},
		{"residual", "max", "4194305", "populated 0\n", ""},
		{"unknown population", "max", "0", "frozen 0\n", ""},
		{"bad population", "max", "0", "populated unknown\n", ""},
		{"bad current", "max", "unknown", "populated 0\n", ""},
		{"bad maximum", "unknown", "0", "populated 0\n", ""},
		{"zero maximum", "0", "0", "populated 0\n", ""},
		{"missing maximum", "max", "0", "populated 0\n", "memory.max"},
		{"missing current", "max", "0", "populated 0\n", "memory.current"},
		{"missing events", "max", "0", "populated 0\n", "cgroup.events"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			checkpointBudgetFixture(t, dir, test.maximum, test.current, test.events)
			if test.missing != "" {
				require.NoError(t, os.Remove(filepath.Join(dir, test.missing)))
			}
			writes := 0
			_, err := applyCheckpointMemoryLimit(dir, 4<<20, func(string, int64) error { writes++; return nil })
			require.Error(t, err)
			require.Zero(t, writes)
		})
	}
}

func TestCheckpointBudgetWriteAndReadbackFailures(t *testing.T) {
	for _, name := range []string{"write failure", "no change", "removed control"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			checkpointBudgetFixture(t, dir, "max", "0", "populated 0\n")
			_, err := applyCheckpointMemoryLimit(dir, 4<<20, func(path string, value int64) error {
				switch name {
				case "write failure":
					return os.ErrPermission
				case "removed control":
					return os.Remove(path)
				default:
					return nil
				}
			})
			require.Error(t, err)
		})
	}
	dir := t.TempDir()
	checkpointBudgetFixture(t, dir, "8388608", "1048576", "populated 0\n")
	effective, err := applyCheckpointMemoryLimit(dir, 4<<20, func(path string, value int64) error {
		return os.WriteFile(path, []byte(strconv.FormatInt(value, 10)), 0600)
	})
	require.NoError(t, err)
	require.EqualValues(t, 4<<20, effective)
}

func TestCheckpointBudgetDetectsRemovedOrLoosenedControls(t *testing.T) {
	for _, test := range []struct {
		value string
		bad   bool
	}{{"1048576", false}, {"4194304", false}, {"8388608", true}, {"max", true}, {"bad", true}} {
		t.Run(test.value, func(t *testing.T) {
			dir := t.TempDir()
			checkpointBudgetFixture(t, dir, test.value, "0", "populated 0\n")
			err := verifyCheckpointMemoryLimit(dir, 4<<20)
			if test.bad {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
	dir := filepath.Join(t.TempDir(), "absent")
	require.Error(t, verifyCheckpointMemoryLimit(dir, 4<<20))
	_, err := os.Stat(dir)
	require.ErrorIs(t, err, os.ErrNotExist)
}
