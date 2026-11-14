// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package firecracker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/inclusionAI/sandboxd/internal/firecrackerproto"
)

func TestFirecrackerShutdownGracePeriod(t *testing.T) {
	for _, milliseconds := range []int{-1, 0, 1, 50, 2000, 10000, 10001} {
		got, err := firecrackerShutdownGracePeriod(milliseconds)
		if milliseconds < 0 || milliseconds > 10000 {
			if err == nil {
				t.Fatalf("accepted invalid shutdown grace %d", milliseconds)
			}
			continue
		}
		want := time.Duration(milliseconds) * time.Millisecond
		if milliseconds == 0 {
			want = 2 * time.Second
		}
		if err != nil || got != want {
			t.Fatalf("grace(%d) = (%v, %v), want %v", milliseconds, got, err, want)
		}
	}
}

func TestDeletePreservesResourcesOnStopFailure(t *testing.T) {
	for _, liveVMM := range []bool{true, false} {
		name := "virtiofs_cleanup_failed"
		if liveVMM {
			name = "vmm_still_alive"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			id := "sandbox-delete-retry"
			handler := &Handler{
				binary: "unused-firecracker", sandboxRoot: filepath.Join(root, "sandboxes"),
				storageRoot: filepath.Join(root, "storage"), runtimeRoot: filepath.Join(root, "runtime"),
				shutdownGracePeriod: 50 * time.Millisecond, instances: make(map[string]*firecrackerInstance),
			}
			state := firecrackerPersistedState{ID: id, PID: 999, BundlePath: filepath.Join(root, "bundle"),
				APIPath: filepath.Join(handler.runtimeDirectory(id), firecrackerAPISocket), VirtioFS: &firecrackerVirtioFSState{}}
			markers := []string{filepath.Join(state.BundlePath, firecrackerArtifactsDir, "retained"),
				filepath.Join(filepath.Dir(state.APIPath), "retained"), filepath.Join(handler.storageRoot, id, "retained")}
			for _, marker := range markers {
				if err := os.MkdirAll(filepath.Dir(marker), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(marker, []byte("owned"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			instance := &firecrackerInstance{state: state, done: make(chan struct{})}
			handler.instances[id] = instance
			var waits []time.Duration
			var signals []syscall.Signal
			cleanupCalls := 0
			patches := gomonkey.ApplyFunc(firecrackerProcessMatches, func(int, string, string, string) bool { return liveVMM })
			defer patches.Reset()
			patches.ApplyFunc(waitFirecrackerProcess, func(_ firecrackerPersistedState, _ string, timeout time.Duration) bool {
				waits = append(waits, timeout)
				return false
			})
			patches.ApplyFunc(signalFirecrackerProcess, func(_ firecrackerPersistedState, _ string, signal syscall.Signal) error {
				signals = append(signals, signal)
				return nil
			})
			patches.ApplyFunc(requestFirecrackerAgentWaiting, func(context.Context, string, firecrackerproto.MessageType, any, time.Duration) error { return nil })
			patches.ApplyFunc(cleanupFirecrackerVirtioFS, func(*firecrackerVirtioFSState, string) error {
				cleanupCalls++
				return errors.New("virtiofs cleanup failed")
			})
			if err := handler.Delete(context.Background(), id); err == nil {
				t.Fatal("Delete reported success despite stop/cleanup failure")
			}
			if handler.instances[id] != instance {
				t.Fatal("lost retryable instance")
			}
			for _, marker := range markers {
				if _, err := os.Stat(marker); err != nil {
					t.Fatalf("removed retained resource %s: %v", marker, err)
				}
			}
			if liveVMM {
				if cleanupCalls != 0 || !reflect.DeepEqual(signals, []syscall.Signal{syscall.SIGTERM, syscall.SIGKILL}) ||
					!reflect.DeepEqual(waits, []time.Duration{50 * time.Millisecond, 500 * time.Millisecond, time.Second}) {
					t.Fatalf("unsafe stop sequence: cleanup=%d signals=%v waits=%v", cleanupCalls, signals, waits)
				}
			} else if cleanupCalls != 1 {
				t.Fatalf("cleanup calls = %d, want 1", cleanupCalls)
			}
		})
	}
}
