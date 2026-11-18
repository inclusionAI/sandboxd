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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/containerd/cgroups/v3"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// This exercises real kernel charging and writeback, not a VM performance
// comparison. It runs only as PID 1 inside a disposable, privately namespaced
// container with a finite envelope and an explicitly supplied XFS directory.
func TestCheckpointMemoryBudgetCgroupIntegration(t *testing.T) {
	if os.Getenv("SANDBOXD_RUN_CHECKPOINT_MEMORY_INTEGRATION") != "1" {
		t.Skip("explicit isolated-container opt-in required")
	}
	require.Equal(t, 1, os.Getpid(), "refuse controller writes outside the owned container PID namespace")
	require.Equal(t, cgroups.Unified, cgroups.Mode())
	const mount = "/sys/fs/cgroup"
	envelope, err := readCheckpointMemoryMax(filepath.Join(mount, "memory.max"))
	require.NoError(t, err)
	require.True(t, envelope > 0 && envelope <= 8<<30, "finite at-most-8-GiB container required")
	procs, err := os.ReadFile(filepath.Join(mount, "cgroup.procs"))
	require.NoError(t, err)
	require.Equal(t, []string{"1"}, strings.Fields(string(procs)), "other processes must not share the namespace root")
	fixture := os.Getenv("CHECKPOINT_BUDGET_XFS_FIXTURE")
	require.NotEmpty(t, fixture)
	var fs unix.Statfs_t
	require.NoError(t, unix.Statfs(fixture, &fs))
	require.EqualValues(t, 0x58465342, fs.Type, "fixture must be XFS")
	dir, err := os.MkdirTemp(fixture, "snapshot-cache-")
	require.NoError(t, err)
	t.Cleanup(func() {
		if !t.Failed() {
			_ = os.RemoveAll(dir)
		}
	})
	control := filepath.Join(mount, "checkpoint-budget-control")
	require.NoError(t, os.Mkdir(control, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(control, "cgroup.procs"), []byte("1"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(mount, "cgroup.subtree_control"), []byte("+memory"), 0600))
	const budget int64 = 128 << 20
	group, effective, err := configureFirecrackerCheckpointCgroup("/checkpoint-budget-test", budget, mount, cgroups.Unified)
	require.NoError(t, err)
	require.Equal(t, budget, effective)
	groupDir := filepath.Join(mount, strings.TrimPrefix(group, "/"))
	readNumber := func(name string) uint64 {
		data, err := os.ReadFile(filepath.Join(groupDir, name))
		require.NoError(t, err)
		value, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		require.NoError(t, err)
		return value
	}
	readEvents := func() map[string]uint64 {
		data, err := os.ReadFile(filepath.Join(groupDir, "memory.events"))
		require.NoError(t, err)
		out := map[string]uint64{}
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			fields := strings.Fields(line)
			require.Len(t, fields, 2)
			value, err := strconv.ParseUint(fields[1], 10, 64)
			require.NoError(t, err)
			out[fields[0]] = value
		}
		return out
	}
	before := readEvents()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	t.Cleanup(cancel)
	const writers = 8
	const fileBytes int64 = 256 << 20
	results := make(chan error, writers)
	commands := make([]*exec.Cmd, 0, writers)
	for i := 0; i < writers; i++ {
		// All writers enter the budget before starting buffered file writes.
		// Arguments are positional shell parameters, never interpolated code.
		cmd := exec.CommandContext(ctx, "sh", "-c", `set -eu; printf '%s' "$$" > "$1/cgroup.procs"; : > "$3/ready-$4"; while [ ! -f "$3/start" ]; do sleep 0.01; done; exec dd if=/dev/zero of="$2" bs=1048576 count=256`, "writer", groupDir, filepath.Join(dir, fmt.Sprint(i)), dir, fmt.Sprint(i))
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		require.NoError(t, cmd.Start())
		commands = append(commands, cmd)
		go func(cmd *exec.Cmd, i int, stderr *bytes.Buffer) {
			err := cmd.Wait()
			if err != nil {
				err = fmt.Errorf("writer %d: %w: %s", i, err, stderr.String())
			}
			results <- err
		}(cmd, i, &stderr)
	}
	t.Cleanup(func() {
		for _, cmd := range commands {
			_ = cmd.Process.Kill()
		}
	})
	for {
		ready, err := filepath.Glob(filepath.Join(dir, "ready-*"))
		require.NoError(t, err)
		if len(ready) == writers {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("writers did not reach the barrier")
		case <-time.After(10 * time.Millisecond):
		}
	}
	_, err = applyCheckpointMemoryLimit(groupDir, budget/2, func(string, int64) error { t.Fatal("must not lower an active group's limit"); return nil })
	require.Error(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "start"), nil, 0600))
	started := time.Now()
	var peak uint64
	var samples []map[string]uint64
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for done := 0; done < writers; {
		select {
		case err := <-results:
			require.NoError(t, err)
			done++
		case <-ctx.Done():
			t.Fatal("bounded writers did not finish")
		case <-ticker.C:
			current := readNumber("memory.current")
			if current > peak {
				peak = current
			}
			samples = append(samples, map[string]uint64{"elapsed_ms": uint64(time.Since(started).Milliseconds()), "current_bytes": current})
		}
	}
	writeSeconds := time.Since(started).Seconds()
	after := readEvents()
	require.Greater(t, after["max"], before["max"], "writes must exercise the actual hard limit")
	require.Equal(t, before["oom"], after["oom"])
	require.Equal(t, before["oom_kill"], after["oom_kill"])
	require.NotZero(t, peak)
	// memory.max permits short-lived accounting overshoot. Preserve the raw
	// samples and allow a small sampling margin instead of claiming byte-exact
	// instantaneous enforcement from a polling observer.
	require.LessOrEqual(t, peak, uint64(budget+16<<20))
	selected, retained, err := configureFirecrackerCheckpointCgroup("/checkpoint-budget-test", 0, mount, cgroups.Unified)
	require.NoError(t, err)
	require.Equal(t, group, selected)
	require.Equal(t, budget, retained)
	validationStarted := time.Now()
	expected := sha256.New()
	zero := make([]byte, 1<<20)
	for i := 0; i < 256; i++ {
		_, err := expected.Write(zero)
		require.NoError(t, err)
	}
	for i := 0; i < writers; i++ {
		f, err := os.OpenFile(filepath.Join(dir, fmt.Sprint(i)), os.O_RDWR, 0)
		require.NoError(t, err)
		require.NoError(t, f.Sync())
		hash := sha256.New()
		n, err := io.Copy(hash, f)
		require.NoError(t, err)
		require.Equal(t, fileBytes, n)
		require.Equal(t, expected.Sum(nil), hash.Sum(nil))
		require.NoError(t, f.Close())
	}
	report := map[string]interface{}{"writers": writers, "output_bytes": writers * fileBytes, "budget_bytes": budget, "common_ancestor_bytes": envelope, "observed_peak_bytes": peak, "write_seconds": writeSeconds, "sync_and_full_sha_seconds": time.Since(validationStarted).Seconds(), "events_before": before, "events_after": after, "samples": samples, "vm_capture_test": false, "active_lowering_rejected": true, "omitted_policy_retained": true}
	data, err := json.MarshalIndent(report, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(fixture, "result.json"), data, 0600))
	fmt.Printf("checkpoint memory kernel budget: writers=%d output=%d budget=%d observed_peak=%d seconds=%.3f\n", writers, writers*fileBytes, budget, peak, writeSeconds)
}
