// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package firecracker

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/inclusionAI/sandboxd/internal/firecrackerproto"
	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
	"golang.org/x/sys/unix"
)

// Exercise the real Checkpoint and agent transport against a VMM stub and a
// socket agent with real named FIFO readers. No VM, cgroup or clock is changed.
func TestCheckpointHandoffLostACKKeepsNextFIFOBlocked(t *testing.T) {
	for _, scenario := range []struct {
		name         string
		loseACK      bool
		snapshotFail bool
		wantOutcome  string
		wantError    string
	}{
		{name: "lost_ack", loseACK: true, wantOutcome: "resume", wantError: "release checkpointed Firecracker sandbox"},
		{name: "acknowledged", wantOutcome: "resume"},
		{name: "capture_failure", snapshotFail: true, wantOutcome: "error", wantError: "create Firecracker Full snapshot"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			patches := gomonkey.ApplyFunc(firecrackerProcessMatches, func(int, string, string, string) bool { return true })
			defer patches.Reset()
			patches.ApplyFunc((*Handler).withCheckpointSnapshotMemoryCharge, func(_ *Handler, _ string, _ *firecrackerInstance, _ firecrackerPersistedState, snapshot func() error) error {
				return snapshot()
			})

			root := t.TempDir()
			handler := stackFixture(t)
			handler.checkpointMode = firecrackerCheckpointModeFull
			handler.checkpointWriteback = &checkpointWritebackScheduler{queue: make(chan string, 1)}
			bundle := filepath.Join(root, "bundle")
			if err := os.MkdirAll(filepath.Join(bundle, firecrackerArtifactsDir), 0700); err != nil {
				t.Fatal(err)
			}
			overlay := filepath.Join(root, "overlay")
			if err := os.WriteFile(overlay, make([]byte, 64<<10), 0600); err != nil {
				t.Fatal(err)
			}
			apiPath := filepath.Join(root, "api.sock")
			apiListener, err := net.Listen("unix", apiPath)
			if err != nil {
				t.Fatal(err)
			}
			apiServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer r.Body.Close()
				if r.URL.Path == "/snapshot/create" {
					if scenario.snapshotFail {
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					var request struct {
						State  string `json:"snapshot_path"`
						Memory string `json:"mem_file_path"`
					}
					if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
						t.Error(err)
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					for path, content := range map[string][]byte{request.State: []byte("vmstate"), request.Memory: make([]byte, 1<<20)} {
						if err := os.WriteFile(path, content, 0600); err != nil {
							t.Error(err)
							w.WriteHeader(http.StatusInternalServerError)
							return
						}
					}
				}
				// Like the VMM, accept Resume even when it is already running.
				w.WriteHeader(http.StatusNoContent)
			})}
			apiDone := make(chan struct{})
			go func() { defer close(apiDone); _ = apiServer.Serve(apiListener) }()
			defer func() { _ = apiServer.Close(); <-apiDone }()

			fifo := newCheckpointTestFIFO(t, root)
			defer fifo.close()
			vsockPath := filepath.Join(root, "vsock.sock")
			agentListener, err := net.Listen("unix", vsockPath)
			if err != nil {
				t.Fatal(err)
			}
			var mu sync.Mutex
			var outcomes []string
			agentDone := make(chan struct{})
			go func() {
				defer close(agentDone)
				for {
					connection, err := agentListener.Accept()
					if err != nil {
						return
					}
					func() {
						defer connection.Close()
						reader := bufio.NewReader(connection)
						if _, err := reader.ReadString('\n'); err != nil {
							t.Error(err)
							return
						}
						if _, err := io.WriteString(connection, "OK 123\n"); err != nil {
							t.Error(err)
							return
						}
						kind, payload, err := firecrackerproto.ReadMessage(reader)
						if err != nil {
							t.Error(err)
							return
						}
						if kind == firecrackerproto.MessageCheckpoint {
							var request firecrackerproto.CheckpointRequest
							if err := json.Unmarshal(payload, &request); err != nil {
								t.Error(err)
								return
							}
							mu.Lock()
							defer mu.Unlock()
							outcomes = append(outcomes, request.Outcome)
							if _, err := io.WriteString(fifo.writer, request.Outcome+"\n"); err != nil {
								t.Error(err)
								return
							}
							if len(outcomes) == 1 {
								// Consume generation one and register a real next FIFO
								// reader BEFORE losing the first control acknowledgment.
								if err := fifo.consumeAndReopen(request.Outcome); err != nil {
									t.Error(err)
									return
								}
								if scenario.loseACK {
									return
								}
							}
						}
						if err := firecrackerproto.WriteMessage(connection, firecrackerproto.MessageResponse, firecrackerproto.Response{OK: true}); err != nil {
							t.Error(err)
						}
					}()
				}
			}()
			defer func() { _ = agentListener.Close(); <-agentDone }()

			instance := &firecrackerInstance{state: firecrackerPersistedState{
				ID: "source", PID: 42, APIPath: apiPath, VsockPath: vsockPath,
				OverlayPath: overlay, BundlePath: bundle, MemoryMiB: 1, Vcpus: 1, Configured: true,
			}}
			handler.instances = map[string]*firecrackerInstance{"source": instance}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err = handler.Checkpoint(ctx, runtimecore.CheckpointConfig{ID: "source", Directory: filepath.Join(root, "capture"), LeaveRunning: true})
			if scenario.wantError == "" && err != nil || scenario.wantError != "" && (err == nil || !strings.Contains(err.Error(), scenario.wantError)) {
				t.Fatalf("checkpoint error = %v, want %q", err, scenario.wantError)
			}
			if scenario.loseACK && !errors.Is(err, io.EOF) {
				t.Fatalf("checkpoint did not propagate lost acknowledgment: %v", err)
			}
			mu.Lock()
			actual := append([]string(nil), outcomes...)
			var data [32]byte
			n, readErr := unix.Read(fifo.readerFD, data[:])
			mu.Unlock()
			if !reflect.DeepEqual(actual, []string{scenario.wantOutcome}) {
				t.Errorf("handoff outcomes = %v, want only [%s]", actual, scenario.wantOutcome)
			}
			if n > 0 || !errors.Is(readErr, unix.EAGAIN) {
				t.Fatalf("next FIFO was released by old checkpoint: %q, %v", data[:max(n, 0)], readErr)
			}
			// A later intentional handoff must still be able to release it.
			if err := requestFirecrackerAgent(ctx, vsockPath, firecrackerproto.MessageCheckpoint, firecrackerproto.CheckpointRequest{Outcome: "resume", HostTimeUnixNano: time.Now().UnixNano()}); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			n, readErr = unix.Read(fifo.readerFD, data[:])
			mu.Unlock()
			if readErr != nil || string(data[:max(n, 0)]) != "resume\n" {
				t.Fatalf("next FIFO intentional release = %q, %v", data[:max(n, 0)], readErr)
			}
		})
	}
}

type checkpointTestFIFO struct {
	path     string
	reader   *os.File
	readerFD int
	writer   *os.File
}

func newCheckpointTestFIFO(t *testing.T, root string) *checkpointTestFIFO {
	t.Helper()
	fifo := &checkpointTestFIFO{path: filepath.Join(root, "checkpoint.fifo")}
	if err := fifo.open(); err != nil {
		t.Fatal(err)
	}
	return fifo
}

func (fifo *checkpointTestFIFO) open() error {
	if err := unix.Mkfifo(fifo.path, 0600); err != nil {
		return err
	}
	reader, err := unix.Open(fifo.path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	fifo.readerFD = reader
	fifo.reader = os.NewFile(uintptr(reader), fifo.path)
	writer, err := unix.Open(fifo.path, unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		fifo.close()
		return err
	}
	fifo.writer = os.NewFile(uintptr(writer), fifo.path)
	return nil
}

func (fifo *checkpointTestFIFO) consumeAndReopen(outcome string) error {
	_ = fifo.writer.Close()
	data, err := io.ReadAll(fifo.reader)
	if err != nil {
		return err
	}
	if string(data) != outcome+"\n" {
		return fmt.Errorf("first FIFO release = %q, want %q", data, outcome)
	}
	fifo.close()
	if err := os.Remove(fifo.path); err != nil {
		return err
	}
	return fifo.open()
}

func (fifo *checkpointTestFIFO) close() {
	if fifo.reader != nil {
		_ = fifo.reader.Close()
	}
	if fifo.writer != nil {
		_ = fifo.writer.Close()
	}
}
