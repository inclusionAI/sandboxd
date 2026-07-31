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
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPrepareRunscNVProxyRootfs(t *testing.T) {
	bundlePath := t.TempDir()
	lowerDir := t.TempDir()

	originalMount := mountRunscNVProxyOverlay
	originalUnmount := unmountRunscNVProxyPath
	t.Cleanup(func() {
		mountRunscNVProxyOverlay = originalMount
		unmountRunscNVProxyPath = originalUnmount
	})

	var mountedLower, mountedUpper, mountedWork, mountedTarget string
	mountRunscNVProxyOverlay = func(lower, upper, work, target string) error {
		mountedLower, mountedUpper, mountedWork, mountedTarget = lower, upper, work, target
		return nil
	}
	unmountRunscNVProxyPath = func(string, int) error {
		return syscall.EINVAL
	}

	spec := &Spec{Root: &Root{Path: lowerDir, Readonly: true}}
	cleanup, err := prepareRunscNVProxyRootfs(bundlePath, spec)
	if err != nil {
		t.Fatalf("prepareRunscNVProxyRootfs() error = %v", err)
	}
	if cleanup == nil {
		t.Fatal("prepareRunscNVProxyRootfs() returned nil cleanup")
	}
	if mountedLower != lowerDir ||
		mountedUpper != filepath.Join(bundlePath, runscNVProxyUpperDir) ||
		mountedWork != filepath.Join(bundlePath, runscNVProxyWorkDir) ||
		mountedTarget != filepath.Join(bundlePath, runscNVProxyRootfsDir) {
		t.Fatalf("unexpected overlay mount: lower=%q upper=%q work=%q target=%q",
			mountedLower, mountedUpper, mountedWork, mountedTarget)
	}
	if spec.Root.Path != runscNVProxyRootfsDir || spec.Root.Readonly {
		t.Fatalf("unexpected rewritten root: %+v", spec.Root)
	}
	if _, err := os.Stat(filepath.Join(mountedTarget, "proc", "driver", "nvidia")); err != nil {
		t.Fatalf("nvproxy procfs mount point was not created: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(bundlePath, "config.json"))
	if err != nil {
		t.Fatalf("read rewritten OCI spec: %v", err)
	}
	var written Spec
	if err := json.Unmarshal(data, &written); err != nil {
		t.Fatalf("decode rewritten OCI spec: %v", err)
	}
	if written.Root == nil || written.Root.Path != runscNVProxyRootfsDir || written.Root.Readonly {
		t.Fatalf("unexpected persisted root: %+v", written.Root)
	}

	if err := cleanup(); err != nil {
		t.Fatalf("cleanup nvproxy rootfs: %v", err)
	}
	for _, name := range []string{
		runscNVProxyRootfsDir,
		runscNVProxyUpperDir,
		runscNVProxyWorkDir,
	} {
		if _, err := os.Stat(filepath.Join(bundlePath, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("nvproxy path %q remains after cleanup: %v", name, err)
		}
	}
}

func TestCleanupRunscNVProxyRootfsDetachesBusyMount(t *testing.T) {
	bundlePath := t.TempDir()
	rootfsPath := filepath.Join(bundlePath, runscNVProxyRootfsDir)
	if err := os.MkdirAll(rootfsPath, 0755); err != nil {
		t.Fatal(err)
	}

	originalUnmount := unmountRunscNVProxyPath
	t.Cleanup(func() { unmountRunscNVProxyPath = originalUnmount })
	var flags []int
	unmountRunscNVProxyPath = func(_ string, flag int) error {
		flags = append(flags, flag)
		if flag == 0 {
			return syscall.EBUSY
		}
		return nil
	}

	if err := cleanupRunscNVProxyRootfs(bundlePath); err != nil {
		t.Fatalf("cleanupRunscNVProxyRootfs() error = %v", err)
	}
	if len(flags) != 2 || flags[0] != 0 || flags[1] != syscall.MNT_DETACH {
		t.Fatalf("unexpected unmount flags: %v", flags)
	}
}
