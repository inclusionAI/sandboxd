// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	api "github.com/inclusionAI/sandboxd/api/runtime/v1"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/stretchr/testify/require"
)

type housekeepingWriteBarrier struct {
	StatusStorage
	path     string
	staged   chan string
	resume   chan struct{}
	writeErr error
}

func (s *housekeepingWriteBarrier) UpdateSync(UpdateFunc) error {
	f, err := os.CreateTemp(filepath.Dir(s.path), ".tmp-status")
	if err != nil {
		return err
	}
	if _, err = f.WriteString("status"); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	s.staged <- f.Name()
	<-s.resume
	if s.writeErr != nil {
		return s.writeErr
	}
	if err := os.Rename(f.Name(), s.path); err != nil {
		return fmt.Errorf("checkpoint status: %w", err)
	}
	return nil
}

func TestHousekeepingConcurrentDeletePreservesReadiness(t *testing.T) {
	for _, tc := range []struct {
		name          string
		deleteRoot    bool
		rootReappears bool
		writeErr      error
		wantReady     bool
	}{
		{name: "deleted sandbox", deleteRoot: true, wantReady: true},
		{name: "retired sandbox with visible root", deleteRoot: true, rootReappears: true, wantReady: true},
		{name: "missing temporary file with live root", wantReady: false},
		{name: "permission error during delete", deleteRoot: true, writeErr: os.ErrPermission, wantReady: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			health := make(chan bool, 1)
			m := &Manager{root: t.TempDir(), recyclePath: t.TempDir(), sandboxes: cmap.New[*Sandbox](),
				serviceHandler: cmap.New[svc.Handler](), monitorStopChan: cmap.New[chan struct{}](),
				exitNotifiers: cmap.New[*exitNotifier](), healthChan: health}
			m.serviceHandler.Set("runsc", svc.NewFakeRuntimeHandler())
			const id = "sbox-deleting"
			root := filepath.Join(m.root, id)
			require.NoError(t, os.MkdirAll(root, 0700))
			status := &housekeepingWriteBarrier{path: filepath.Join(root, "status"),
				staged: make(chan string, 1), resume: make(chan struct{}), writeErr: tc.writeErr}
			m.sandboxes.Set(id, &Sandbox{Metadata: &api.SandboxMetadata{ID: id, RuntimeHandler: "runsc"}, PATH: root, Status: status})
			m.monitorStopChan.Set(id, make(chan struct{}))
			const peer = "sbox-peer"
			m.sandboxes.Set(peer, &Sandbox{Metadata: &api.SandboxMetadata{ID: peer, RuntimeHandler: "runsc"}, PATH: t.TempDir(), Status: &housekeepingStatus{}})
			m.monitorStopChan.Set(peer, make(chan struct{}))
			go m.housekeeping()
			// Pause after housekeeping's root check and temporary-file creation,
			// then perform the real Manager deletion before the atomic rename.
			defer close(status.resume)
			select {
			case temporary := <-status.staged:
				if tc.deleteRoot {
					m.Delete(id)
					if tc.rootReappears {
						// The old object is retired even when its path is visible:
						// RemoveAll can unlink a temporary file before rmdir, and
						// the path may also be recreated after a completed delete.
						require.NoError(t, os.MkdirAll(root, 0700))
					}
				} else {
					require.NoError(t, os.Remove(temporary))
				}
			case <-time.After(5 * time.Second):
				t.Fatal("housekeeping did not reach persistence")
			}
			status.resume <- struct{}{}
			select {
			case ready := <-health:
				require.Equal(t, tc.wantReady, ready)
			case <-time.After(5 * time.Second):
				t.Fatal("housekeeping did not finish")
			}
			require.Equal(t, !tc.deleteRoot, m.sandboxes.Has(id))
			require.True(t, m.sandboxes.Has(peer))
			require.True(t, m.monitorStopChan.Has(peer))
			if tc.deleteRoot {
				if tc.rootReappears {
					require.DirExists(t, root)
				} else {
					require.NoDirExists(t, root)
				}
				require.False(t, m.monitorStopChan.Has(id))
			}
			if tc.rootReappears {
				// A new object at the same ID/path must not inherit retirement.
				replacement := &housekeepingWriteBarrier{path: filepath.Join(root, "status"),
					staged: make(chan string, 1), resume: make(chan struct{})}
				defer close(replacement.resume)
				m.sandboxes.Set(id, &Sandbox{Metadata: &api.SandboxMetadata{ID: id, RuntimeHandler: "runsc"}, PATH: root, Status: replacement})
				go m.housekeeping()
				select {
				case temporary := <-replacement.staged:
					require.NoError(t, os.Remove(temporary))
				case <-time.After(5 * time.Second):
					t.Fatal("replacement did not reach persistence")
				}
				replacement.resume <- struct{}{}
				select {
				case ready := <-health:
					require.False(t, ready, "replacement persistence failure must affect readiness")
				case <-time.After(5 * time.Second):
					t.Fatal("replacement housekeeping did not finish")
				}
			}
		})
	}
}
