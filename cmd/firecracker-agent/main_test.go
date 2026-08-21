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

type recordingWriteCloser struct {
	bytes.Buffer
	closed bool
}

func (w *recordingWriteCloser) Close() error {
	w.closed = true
	return nil
}
