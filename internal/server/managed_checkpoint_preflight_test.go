package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/managedlease"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
)

// Regression adapted from rcyw's PR #101 review. Invoke the real Checkpoint
// RPC with a fake runtime and actual hard links, without mounting filesystems.
func TestManagedCheckpointLeaseGeometryPrecedesRuntimeCapture(t *testing.T) {
	for _, test := range []struct {
		name          string
		managed       bool
		foreign       bool
		existing      bool
		failCapture   bool
		cancelCapture bool
		leaveRunning  bool
	}{
		{name: "ordinary_foreign_filesystem", foreign: true},
		{name: "managed_same_filesystem", managed: true},
		{name: "managed_live_capture", managed: true, leaveRunning: true},
		{name: "managed_foreign_filesystem", managed: true, foreign: true},
		{name: "managed_foreign_existing_directory", managed: true, foreign: true, existing: true},
		{name: "managed_capture_failure", managed: true, failCapture: true},
		{name: "managed_capture_failure_existing_directory", managed: true, failCapture: true, existing: true},
		{name: "managed_capture_cancellation", managed: true, cancelCapture: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler := newCheckpointTestHandler()
			h := newTestService(t, map[string]svc.Handler{config.RuntimeNameRunsc: handler})
			h.config.ManagedRuntimeRoot = t.TempDir()
			root := h.config.ManagedRuntimeRoot
			id := strings.Repeat("a", 32)
			storeRunningSandbox(t, h, "source", config.RuntimeNameRunsc)
			if test.managed {
				require.NoError(t, os.Mkdir(filepath.Join(root, "records"), 0700))
				require.NoError(t, h.managedLeases().Create(id))
				require.NoError(t, writePrivateJSON(filepath.Join(root, "records", id+".json"), managedRecord{
					LifecycleVersion: managedLifecycleVersion, CollectionID: id,
					TenantID: "tenant", Profile: "profile", ProfileDigest: "digest",
				}, 0600))
				state, err := h.sandboxManager.Get("source")
				require.NoError(t, err)
				state.Metadata.Labels = map[string]string{managedCollectionLabel: id}
				_, release, err := h.claimManagedSandbox(context.Background(), "source", id)
				require.NoError(t, err)
				defer release()
			}
			output := filepath.Join(t.TempDir(), "checkpoint")
			if test.foreign {
				directory, err := os.MkdirTemp("/dev/shm", "sandboxd-pr101-checkpoint-")
				require.NoError(t, err)
				t.Cleanup(func() { _ = os.RemoveAll(directory) })
				output = filepath.Join(directory, "checkpoint")
				probe := filepath.Join(root, "link-probe")
				require.NoError(t, os.WriteFile(probe, nil, 0600))
				err = os.Link(probe, filepath.Join(directory, "cross-device-probe"))
				require.True(t, errors.Is(err, syscall.EXDEV), "fixture needs different filesystems: %v", err)
			}
			if test.existing {
				require.NoError(t, os.Mkdir(output, 0700))
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			called := false
			handler.checkpointFn = func(_ context.Context, cfg svc.CheckpointConfig) error {
				called = true
				require.Equal(t, test.leaveRunning, cfg.LeaveRunning)
				if test.managed {
					require.NoError(t, h.managedLeases().VerifyPin(ctx, id, filepath.Join(cfg.Directory, managedlease.CheckpointFile)), "capture must already own its persistent lease")
					require.FileExists(t, filepath.Join(cfg.Directory, managedCheckpointFile))
				}
				require.NoError(t, os.WriteFile(filepath.Join(cfg.Directory, "checkpoint.img"), []byte("completed capture"), 0600))
				if test.failCapture {
					return errors.New("injected capture failure")
				}
				if test.cancelCapture {
					cancel()
					return ctx.Err()
				}
				return nil
			}
			_, err := h.Checkpoint(ctx, &runtime.CheckpointRequest{
				ID: "source", CheckpointDir: output, TimeoutSeconds: 5, LeaveRunning: test.leaveRunning,
			})
			failed := test.managed && test.foreign || test.failCapture || test.cancelCapture
			if test.managed {
				pending, readErr := os.ReadDir(filepath.Join(root, "pending"))
				require.NoError(t, readErr)
				require.Empty(t, pending, "operation lease survived RPC completion")
				anchor, statErr := os.Stat(filepath.Join(root, "leases", id))
				require.NoError(t, statErr)
				links := uint64(3) // anchor, live owner and completed checkpoint
				if failed {
					links = 2 // failures must release the output-owned link
				}
				require.Equal(t, links, uint64(anchor.Sys().(*syscall.Stat_t).Nlink))
			}
			if failed {
				require.Error(t, err)
				require.Equal(t, !test.foreign, called, "unsupported lease filesystem must be rejected before runtime capture")
				if test.foreign {
					require.ErrorContains(t, err, "invalid cross-device link")
				}
				if test.existing {
					entries, readErr := os.ReadDir(output)
					require.NoError(t, readErr)
					require.Empty(t, entries, "caller-owned output directory must be retained but emptied")
				} else {
					require.NoDirExists(t, output, "new output directory must be removed on failure")
				}
				return
			}
			require.NoError(t, err)
			require.True(t, called)
			_, err = os.Stat(filepath.Join(output, "checkpoint.img"))
			require.NoError(t, err)
		})
	}
}
