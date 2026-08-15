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

package volumemanager

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const storageIntegrationEnv = "SANDBOXD_RUN_STORAGE_INTEGRATION"

func TestLoopBackedFilestoreIntegration(t *testing.T) {
	requireStorageIntegration(t)

	tests := []struct {
		name          string
		xfsEnabled    bool
		filesystem    string
		magic         int64
		forkSupported bool
	}{
		{name: "ext4", filesystem: "ext4", magic: 0xef53},
		{
			name:          "xfs",
			xfsEnabled:    true,
			filesystem:    "xfs",
			magic:         0x58465342,
			forkSupported: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			deviceDir := makeLoopDeviceDir(t, root)
			filestoreDir := filepath.Join(root, "filestore")
			module := NewModule(filestoreDir, "512M", test.xfsEnabled, deviceDir)

			if err := module.Start(); err != nil {
				t.Fatalf("start %s filestore: %v", test.filesystem, err)
			}
			started := true
			t.Cleanup(func() {
				if started {
					if err := module.Stop(); err != nil {
						t.Errorf("stop %s filestore: %v", test.filesystem, err)
					}
				}
			})

			if !module.Healthy() {
				t.Fatalf("%s filestore is unhealthy", test.filesystem)
			}
			if module.ForkSupported() != test.forkSupported {
				t.Fatalf(
					"%s fork support = %t, want %t",
					test.filesystem,
					module.ForkSupported(),
					test.forkSupported,
				)
			}

			var stat unix.Statfs_t
			if err := unix.Statfs(filestoreDir, &stat); err != nil {
				t.Fatalf("stat %s filestore: %v", test.filesystem, err)
			}
			if stat.Type != test.magic {
				t.Fatalf(
					"%s filesystem magic = %#x, want %#x",
					test.filesystem,
					stat.Type,
					test.magic,
				)
			}

			probe := filepath.Join(filestoreDir, "probe")
			if err := os.WriteFile(probe, []byte("storage-integration"), 0600); err != nil {
				t.Fatalf("write %s filestore: %v", test.filesystem, err)
			}
			image := filepath.Join(root, test.filesystem+".img")
			info, err := os.Stat(image)
			if err != nil {
				t.Fatalf("stat %s image: %v", test.filesystem, err)
			}
			if info.Size() != 512*1024*1024 {
				t.Fatalf("%s image size = %d, want 512 MiB", test.filesystem, info.Size())
			}

			loopNodes := loopDeviceNodes(t, deviceDir)
			if len(loopNodes) == 0 {
				t.Fatalf("%s did not create a loop device node", test.filesystem)
			}
			if err := module.Stop(); err != nil {
				t.Fatalf("stop %s filestore: %v", test.filesystem, err)
			}
			started = false
			for _, node := range loopNodes {
				assertLoopDetached(t, node)
			}
		})
	}
}

func requireStorageIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv(storageIntegrationEnv) != "1" {
		t.Skipf("set %s=1 to run privileged storage tests", storageIntegrationEnv)
	}
	if os.Geteuid() != 0 {
		t.Fatal("privileged storage tests must run as root")
	}
	if _, err := os.Stat("/dev/loop-control"); err != nil {
		t.Fatalf("loop-control is unavailable: %v", err)
	}
}

func makeLoopDeviceDir(t *testing.T, root string) string {
	t.Helper()
	deviceDir := filepath.Join(root, "devices")
	if err := os.MkdirAll(deviceDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/loop-control", filepath.Join(deviceDir, "loop-control")); err != nil {
		t.Fatal(err)
	}
	return deviceDir
}

func loopDeviceNodes(t *testing.T, deviceDir string) []string {
	t.Helper()
	nodes, err := filepath.Glob(filepath.Join(deviceDir, "loop[0-9]*"))
	if err != nil {
		t.Fatal(err)
	}
	return nodes
}

func assertLoopDetached(t *testing.T, path string) {
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
