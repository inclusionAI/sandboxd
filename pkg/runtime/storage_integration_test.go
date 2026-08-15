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

package runtime

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestEROFSLoopDeviceDirIntegration(t *testing.T) {
	if os.Getenv("SANDBOXD_RUN_STORAGE_INTEGRATION") != "1" {
		t.Skip("set SANDBOXD_RUN_STORAGE_INTEGRATION=1 to run privileged storage tests")
	}
	if os.Geteuid() != 0 {
		t.Fatal("privileged storage tests must run as root")
	}
	if _, err := os.Stat("/dev/loop-control"); err != nil {
		t.Fatalf("loop-control is unavailable: %v", err)
	}

	root := t.TempDir()
	deviceDir := filepath.Join(root, "devices")
	if err := os.MkdirAll(deviceDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/loop-control", filepath.Join(deviceDir, "loop-control")); err != nil {
		t.Fatal(err)
	}

	sourceDir := filepath.Join(root, "source")
	if err := os.MkdirAll(sourceDir, 0755); err != nil {
		t.Fatal(err)
	}
	const content = "sandboxd-erofs-integration"
	if err := os.WriteFile(filepath.Join(sourceDir, "probe"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	image := filepath.Join(root, "runtime.erofs")
	if output, err := exec.Command("mkfs.erofs", image, sourceDir).CombinedOutput(); err != nil {
		t.Fatalf("create EROFS image: %v: %s", err, output)
	}

	target := filepath.Join(root, "mount")
	if err := os.MkdirAll(target, 0755); err != nil {
		t.Fatal(err)
	}
	mounter, err := newEROFSImageMounter(deviceDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := mounter(image, target); err != nil {
		t.Fatalf("mount EROFS image: %v", err)
	}
	mounted := true
	t.Cleanup(func() {
		if mounted {
			if err := syscall.Unmount(target, 0); err != nil {
				t.Errorf("unmount EROFS image: %v", err)
			}
		}
	})

	data, err := os.ReadFile(filepath.Join(target, "probe"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != content {
		t.Fatalf("EROFS content = %q, want %q", data, content)
	}
	if err := os.WriteFile(filepath.Join(target, "write-probe"), []byte("write"), 0600); err == nil {
		t.Fatal("write to read-only EROFS mount succeeded")
	}

	loopNodes, err := filepath.Glob(filepath.Join(deviceDir, "loop[0-9]*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(loopNodes) == 0 {
		t.Fatal("EROFS mount did not create a loop device node")
	}
	if err := syscall.Unmount(target, 0); err != nil {
		t.Fatalf("unmount EROFS image: %v", err)
	}
	mounted = false
	for _, node := range loopNodes {
		assertEROFSLoopDetached(t, node)
	}
}

func assertEROFSLoopDetached(t *testing.T, path string) {
	t.Helper()
	backingFilePath := filepath.Join(
		"/sys/class/block",
		filepath.Base(path),
		"loop/backing_file",
	)
	deadline := time.Now().Add(5 * time.Second)
	for {
		backingFile, err := os.ReadFile(backingFilePath)
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		if err != nil {
			t.Fatalf("read loop device backing file %s: %v", backingFilePath, err)
		}
		if strings.TrimSpace(string(backingFile)) == "" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf(
				"loop device %s remains attached to %q",
				path,
				strings.TrimSpace(string(backingFile)),
			)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
