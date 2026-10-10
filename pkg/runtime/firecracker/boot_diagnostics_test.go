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

package firecracker

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/internal/firecrackerproto"
)

// TestReadTailFromWriterRegularFile verifies that the diagnostic reader
// returns the last n bytes from a regular file without disturbing the
// writer's offset.
func TestReadTailFromWriterRegularFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "console.log")
	full := make([]byte, 8192)
	for i := range full {
		full[i] = byte(i % 251)
	}
	if err := os.WriteFile(path, full, 0600); err != nil {
		t.Fatal(err)
	}
	writer, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()

	before, err := writer.Seek(17, io.SeekStart)
	if err != nil {
		t.Fatal(err)
	}
	tail := readTailFromWriter(writer, 4096)
	if len(tail) != 4096 {
		t.Fatalf("tail length = %d, want 4096", len(tail))
	}
	want := full[4096:]
	for i := range tail {
		if tail[i] != want[i] {
			t.Fatalf("tail[%d] = %d, want %d", i, tail[i], want[i])
		}
	}
	// The writer's offset must be unchanged.
	offset, err := writer.Seek(0, io.SeekCurrent)
	if err != nil {
		t.Fatal(err)
	}
	if offset != before {
		t.Fatalf("writer offset = %d, want %d (unchanged)", offset, before)
	}
}

// TestReadTailFromWriterEmptyFile verifies a nil return for empty files.
func TestReadTailFromWriterEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.log")
	writer, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if tail := readTailFromWriter(writer, 4096); tail != nil {
		t.Fatalf("expected nil for empty file, got %d bytes", len(tail))
	}
}

// TestReadTailFromWriterNilFile verifies a nil return for nil handles.
func TestReadTailFromWriterNilFile(t *testing.T) {
	if tail := readTailFromWriter(nil, 4096); tail != nil {
		t.Fatalf("expected nil for nil file, got %d bytes", len(tail))
	}
}

// TestReadTailFromWriterZeroBytes verifies a nil return for n<=0.
func TestReadTailFromWriterZeroBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.log")
	if err := os.WriteFile(path, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	writer, err := os.OpenFile(path, os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if tail := readTailFromWriter(writer, 0); tail != nil {
		t.Fatalf("expected nil for n=0, got %d bytes", len(tail))
	}
}

// TestReadTailFromWriterSmallFile verifies that a file smaller than n
// returns the entire content.
func TestReadTailFromWriterSmallFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "small.log")
	content := []byte("short guest console output")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	writer, err := os.OpenFile(path, os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	tail := readTailFromWriter(writer, 4096)
	if string(tail) != string(content) {
		t.Fatalf("tail = %q, want %q", tail, content)
	}
}

// TestWaitForFirecrackerAgentAttemptsInError verifies that the timeout
// error includes the attempt count and the last underlying error, so a
// daemon log can distinguish socket-not-found, vsock-connect-rejected,
// and health-check-failed without reproducing the timeout.
func TestWaitForFirecrackerAgentAttemptsInError(t *testing.T) {
	vsockPath := filepath.Join(t.TempDir(), "nonexistent.sock")
	// Verify the path truly does not exist.
	if _, statErr := os.Stat(vsockPath); !os.IsNotExist(statErr) {
		t.Fatalf("expected %s to not exist, stat: %v", vsockPath, statErr)
	}
	// First, verify a direct requestFirecrackerAgent call fails.
	directErr := requestFirecrackerAgent(
		context.Background(),
		vsockPath,
		firecrackerproto.MessageHealth,
		nil,
	)
	if directErr == nil {
		t.Fatal("requestFirecrackerAgent unexpectedly succeeded for nonexistent path")
	}
	t.Logf("direct error: %v", directErr)
	// Now run the retry loop with a short timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err := waitForFirecrackerAgent(ctx, vsockPath)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("missing socket returned %v, want DeadlineExceeded", err)
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "attempts=") {
		t.Errorf("error missing attempt count: %s", errMsg)
	}
	if !strings.Contains(errMsg, "last error:") || !strings.Contains(errMsg, "no such file or directory") {
		t.Errorf("error missing last error detail: %s", errMsg)
	}
	t.Logf("timeout error: %s", errMsg)
}

// expiredBeforeCancellation models the window between a deadline passing and
// the context timer making Err observable. It keeps the regression deterministic.
type expiredBeforeCancellation struct{ context.Context }

func (expiredBeforeCancellation) Deadline() (time.Time, bool) {
	return time.Now().Add(-time.Second), true
}

func TestAgentRequestExpiredDeadlineBeforeContextError(t *testing.T) {
	ctx := expiredBeforeCancellation{context.Background()}
	err := requestFirecrackerAgent(ctx, filepath.Join(t.TempDir(), "missing.sock"), firecrackerproto.MessageHealth, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unsent request returned %v, want DeadlineExceeded", err)
	}
	err = waitForFirecrackerAgent(ctx, filepath.Join(t.TempDir(), "missing.sock"))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("agent readiness returned %v, want DeadlineExceeded", err)
	}
}

func TestAgentRequestCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := requestFirecrackerAgent(ctx, filepath.Join(t.TempDir(), "missing.sock"), firecrackerproto.MessageHealth, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled request returned %v", err)
	}
}

func TestReadTailFromWriterPipeDoesNotBlock(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	done := make(chan []byte, 1)
	go func() { done <- readTailFromWriter(writer, 4096) }()
	select {
	case tail := <-done:
		if tail != nil {
			t.Fatalf("pipe returned %q", tail)
		}
	case <-time.After(time.Second):
		t.Fatal("diagnostic read blocked on a pipe")
	}
}
