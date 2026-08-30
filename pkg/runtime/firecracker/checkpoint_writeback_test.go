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
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCheckpointWritebackSchedulerIsBounded(t *testing.T) {
	started := make(chan string, 2)
	release := make(chan struct{})
	scheduler := newCheckpointWritebackSchedulerWith(
		1,
		1,
		func(path string) error {
			started <- path
			<-release
			return nil
		},
	)

	if !scheduler.schedule("first") {
		t.Fatal("first writeback was not scheduled")
	}
	select {
	case path := <-started:
		if path != "first" {
			t.Fatalf("first writeback path %q, want first", path)
		}
	case <-time.After(time.Second):
		t.Fatal("first writeback did not start")
	}
	if !scheduler.schedule("second") {
		t.Fatal("second writeback was not queued")
	}
	if scheduler.schedule("third") {
		t.Fatal("writeback queue accepted work beyond its bound")
	}

	release <- struct{}{}
	select {
	case path := <-started:
		if path != "second" {
			t.Fatalf("second writeback path %q, want second", path)
		}
	case <-time.After(time.Second):
		t.Fatal("second writeback did not start")
	}
	release <- struct{}{}
}

func TestStartCheckpointMemoryWriteback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "memory")
	if err := os.WriteFile(path, []byte("checkpoint"), 0600); err != nil {
		t.Fatalf("write checkpoint memory fixture: %v", err)
	}
	if err := startCheckpointMemoryWriteback(path); err != nil {
		t.Fatalf("start checkpoint memory writeback: %v", err)
	}
}

func TestStartCheckpointMemoryWritebackMissingFile(t *testing.T) {
	err := startCheckpointMemoryWriteback(filepath.Join(t.TempDir(), "missing"))
	if err == nil {
		t.Fatal("missing checkpoint memory file did not fail")
	}
}
