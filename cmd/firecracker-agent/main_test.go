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

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestContainerPathUnder(t *testing.T) {
	root := t.TempDir()
	path, err := containerPathUnder(root, "/etc/resolv.conf")
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(root, "etc/resolv.conf") {
		t.Fatalf("container path = %q", path)
	}
	for _, invalid := range []string{"relative", "/"} {
		if _, err := containerPathUnder(root, invalid); err == nil {
			t.Fatalf("accepted target %q", invalid)
		}
	}
}

func TestEnsureContainerDirectoryRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	_, err := ensureContainerDirectoryUnder(root, "/escape/data")
	if err == nil || !strings.Contains(err.Error(), "traverses symlink") {
		t.Fatalf("symlink error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "data")); !os.IsNotExist(err) {
		t.Fatalf("created directory outside root: %v", err)
	}
}

func TestPrepareContainerFileReplacesFinalSymlink(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "etc"), 0755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("safe"), 0644); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "etc/resolv.conf")
	if err := os.Symlink(outside, target); err != nil {
		t.Fatal(err)
	}
	resolved, err := prepareContainerFileUnder(root, "/etc/resolv.conf")
	if err != nil {
		t.Fatal(err)
	}
	if resolved != target {
		t.Fatalf("resolved file = %q", resolved)
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("final symlink still exists: %v", err)
	}
	data, err := os.ReadFile(outside)
	if err != nil || string(data) != "safe" {
		t.Fatalf("outside file = %q, %v", data, err)
	}
}

func TestPrepareContainerFileAtRoot(t *testing.T) {
	root := t.TempDir()
	resolved, err := prepareContainerFileUnder(root, "/entry")
	if err != nil {
		t.Fatal(err)
	}
	if resolved != filepath.Join(root, "entry") {
		t.Fatalf("root-level file = %q", resolved)
	}
}

func TestPrepareContainerFileRejectsSymlinkParent(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "etc")); err != nil {
		t.Fatal(err)
	}
	_, err := prepareContainerFileUnder(root, "/etc/resolv.conf")
	if err == nil || !strings.Contains(err.Error(), "traverses symlink") {
		t.Fatalf("symlink parent error = %v", err)
	}
}

func TestFinishExecInput(t *testing.T) {
	t.Run("pipe closes writer", func(t *testing.T) {
		writer := &recordingWriteCloser{}
		finishExecInput(writer, false)
		if !writer.closed {
			t.Fatal("pipe input was not closed")
		}
		if writer.Len() != 0 {
			t.Fatalf("pipe input = %q", writer.Bytes())
		}
	})

	t.Run("terminal sends EOF without closing master", func(t *testing.T) {
		writer := &recordingWriteCloser{}
		finishExecInput(writer, true)
		if writer.closed {
			t.Fatal("terminal master was closed")
		}
		if !bytes.Equal(writer.Bytes(), []byte{4}) {
			t.Fatalf("terminal input = %v", writer.Bytes())
		}
	})
}

func TestFirecrackerTmpfsParameters(t *testing.T) {
	flags, data, err := firecrackerTmpfsParameters([]string{
		"rw", "nosuid", "nodev", "noexec", "size=1m", "mode=0750",
	})
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.MS_NOSUID == 0 ||
		flags&unix.MS_NODEV == 0 ||
		flags&unix.MS_NOEXEC == 0 ||
		flags&unix.MS_RDONLY != 0 {
		t.Fatalf("tmpfs flags = %#x", flags)
	}
	if data != "size=1m,mode=0750" {
		t.Fatalf("tmpfs data = %q", data)
	}
	if _, _, err := firecrackerTmpfsParameters([]string{"bind"}); err == nil {
		t.Fatal("accepted unsafe tmpfs option")
	}
}

func TestCheckpointHandoff(t *testing.T) {
	root := t.TempDir()
	environment := []string{
		"RUNTIME_ID=source",
		"YR_SEED_FILE=/untrusted",
		"YR_ENV_FILE=/untrusted",
	}
	handoff, err := prepareCheckpointHandoff(root, environment)
	if err != nil {
		t.Fatal(err)
	}
	defer handoff.close()
	initialEnvironment, err := os.ReadFile(handoff.environmentPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range environment {
		if !bytes.Contains(initialEnvironment, []byte(entry+"\x00")) {
			t.Fatalf("initial environment = %q, missing %q", initialEnvironment, entry)
		}
	}

	for _, outcome := range []string{"resume", "error", "resume", "resume"} {
		if err := handoff.signal(outcome); err != nil {
			t.Fatalf("signal without reader: %v", err)
		}
	}

	for _, outcome := range []string{"resume", "restore"} {
		result := make(chan struct {
			value string
			err   error
		}, 1)
		go func() {
			data, err := os.ReadFile(handoff.fifoPath)
			result <- struct {
				value string
				err   error
			}{string(data), err}
		}()
		waitForCheckpointReader(t, handoff)
		if err := handoff.signal(outcome); err != nil {
			t.Fatal(err)
		}
		select {
		case read := <-result:
			want := outcome + "\n"
			if read.err != nil || read.value != want {
				t.Fatalf("handoff = %q, %v, want %q", read.value, read.err, want)
			}
		case <-time.After(time.Second):
			t.Fatal("checkpoint handoff timed out")
		}
	}

	if err := writeCheckpointEnvironment(
		handoff.environmentPath,
		[]string{"RUNTIME_ID=restore"},
	); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(handoff.environmentPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte("RUNTIME_ID=restore\x00")) ||
		bytes.Contains(data, []byte("RUNTIME_ID=source")) {
		t.Fatalf("restored environment = %q", data)
	}
}

func TestCheckpointHandoffDeliversRestoreAfterReaderReopens(t *testing.T) {
	handoff, err := prepareCheckpointHandoff(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer handoff.close()

	type readResult struct {
		value string
		err   error
	}
	read := func() <-chan readResult {
		result := make(chan readResult, 1)
		go func() {
			data, err := os.ReadFile(handoff.fifoPath)
			result <- readResult{value: string(data), err: err}
		}()
		return result
	}

	result := read()
	waitForCheckpointReader(t, handoff)
	if err := handoff.signal("resume"); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-result:
		if got.err != nil || got.value != "resume\n" {
			t.Fatalf("initial handoff = %q, %v", got.value, got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("initial handoff timed out")
	}

	if err := handoff.signal("restore"); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-read():
		if got.err != nil || got.value != "restore\n" {
			t.Fatalf("pending restore handoff = %q, %v", got.value, got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("restore was not delivered after the FIFO reader reopened")
	}
}

func TestCheckpointHandoffRecreatesRemovedFIFO(t *testing.T) {
	handoff, err := prepareCheckpointHandoff(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer handoff.close()
	if err := os.Remove(handoff.fifoPath); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(time.Second)
	for {
		info, statErr := os.Stat(handoff.fifoPath)
		if statErr == nil && info.Mode()&os.ModeNamedPipe != 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("checkpoint FIFO was not recreated: %v", statErr)
		}
		time.Sleep(time.Millisecond)
	}
	result := make(chan struct {
		value string
		err   error
	}, 1)
	go func() {
		data, err := os.ReadFile(handoff.fifoPath)
		result <- struct {
			value string
			err   error
		}{value: string(data), err: err}
	}()
	waitForCheckpointReader(t, handoff)
	if err := handoff.signal("resume"); err != nil {
		t.Fatal(err)
	}
	select {
	case read := <-result:
		if read.err != nil || read.value != "resume\n" {
			t.Fatalf("recreated checkpoint handoff = %q, %v", read.value, read.err)
		}
	case <-time.After(time.Second):
		t.Fatal("recreated checkpoint handoff timed out")
	}
}

func TestCheckpointHandoffCloseWithoutReader(t *testing.T) {
	handoff, err := prepareCheckpointHandoff(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{})
	go func() {
		handoff.close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("checkpoint handoff close blocked without a reader")
	}
	if err := handoff.signal("resume"); err != nil {
		t.Fatalf("signal closed handoff: %v", err)
	}
}

func waitForCheckpointReader(t *testing.T, handoff *checkpointHandoff) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		handoff.mu.Lock()
		ready := handoff.reader != nil
		handoff.mu.Unlock()
		if ready {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("checkpoint handoff reader did not register")
}

type recordingWriteCloser struct {
	bytes.Buffer
	closed bool
}

func (w *recordingWriteCloser) Close() error {
	w.closed = true
	return nil
}
