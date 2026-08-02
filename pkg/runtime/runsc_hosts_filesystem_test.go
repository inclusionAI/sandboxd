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
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestPrepareRunscHostsRootfsProjectsMissingTarget(t *testing.T) {
	bundlePath := t.TempDir()
	lowerDir := t.TempDir()
	if err := os.Chmod(lowerDir, 0711); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(lowerDir, "etc"), 0710); err != nil {
		t.Fatal(err)
	}
	mtime := time.Unix(1_700_000_000, 0)
	if err := os.Chtimes(filepath.Join(lowerDir, "etc"), mtime, mtime); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundlePath, "hosts"), []byte("localhost\n"), 0644); err != nil {
		t.Fatal(err)
	}

	originalMount := mountRunscHostsOverlay
	originalUnmount := unmountRunscHostsPath
	t.Cleanup(func() {
		mountRunscHostsOverlay = originalMount
		unmountRunscHostsPath = originalUnmount
	})
	var mountedProjection, mountedLower, mountedTarget string
	var projectedRoot, projectedEtc os.FileInfo
	mountRunscHostsOverlay = func(projection, lower, target string) error {
		mountedProjection, mountedLower, mountedTarget = projection, lower, target
		var err error
		projectedRoot, err = os.Stat(projection)
		if err != nil {
			return err
		}
		projectedEtc, err = os.Stat(filepath.Join(projection, "etc"))
		if err != nil {
			return err
		}
		hosts, err := os.Lstat(filepath.Join(projection, "etc", "hosts"))
		if err != nil {
			return err
		}
		if !hosts.Mode().IsRegular() || hosts.Mode().Perm() != 0644 {
			return fmt.Errorf("projected hosts mode = %v", hosts.Mode())
		}
		return nil
	}
	unmountRunscHostsPath = func(string, int) error { return syscall.EINVAL }

	spec := generatedHostsSpec(bundlePath, lowerDir)
	cleanup, err := prepareRunscHostsRootfs(bundlePath, spec)
	if err != nil {
		t.Fatalf("prepareRunscHostsRootfs() error = %v", err)
	}
	if cleanup == nil {
		t.Fatal("prepareRunscHostsRootfs() returned nil cleanup")
	}
	if mountedProjection != filepath.Join(bundlePath, runscHostsProjectionDir) ||
		mountedLower != lowerDir ||
		mountedTarget != filepath.Join(bundlePath, runscHostsRootfsDir) {
		t.Fatalf("unexpected hosts overlay: projection=%q lower=%q target=%q", mountedProjection, mountedLower, mountedTarget)
	}
	if spec.Root.Path != runscHostsRootfsDir || !spec.Root.Readonly {
		t.Fatalf("unexpected rewritten root: %+v", spec.Root)
	}
	if projectedRoot.Mode().Perm() != 0711 {
		t.Fatalf("projected root mode = %o, want 0711", projectedRoot.Mode().Perm())
	}
	if projectedEtc.Mode().Perm() != 0710 || !projectedEtc.ModTime().Equal(mtime) {
		t.Fatalf("projected /etc metadata = %v %v", projectedEtc.Mode(), projectedEtc.ModTime())
	}
	if err := cleanup(); err != nil {
		t.Fatalf("cleanup hosts rootfs: %v", err)
	}
}

func TestPrepareRunscHostsRootfsKeepsExistingTarget(t *testing.T) {
	bundlePath := t.TempDir()
	lowerDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(lowerDir, "etc"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(lowerDir, "etc", "hosts"), []byte("image hosts\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundlePath, "hosts"), []byte("localhost\n"), 0644); err != nil {
		t.Fatal(err)
	}

	originalMount := mountRunscHostsOverlay
	t.Cleanup(func() { mountRunscHostsOverlay = originalMount })
	mountRunscHostsOverlay = func(_, _, _ string) error { return errors.New("unexpected hosts overlay") }

	spec := generatedHostsSpec(bundlePath, lowerDir)
	cleanup, err := prepareRunscHostsRootfs(bundlePath, spec)
	if err != nil {
		t.Fatalf("prepareRunscHostsRootfs() error = %v", err)
	}
	if cleanup != nil || spec.Root.Path != lowerDir {
		t.Fatalf("existing target changed rootfs: cleanup=%v root=%q", cleanup != nil, spec.Root.Path)
	}
}

func TestPrepareRunscHostsRootfsRejectsSymlinkEtc(t *testing.T) {
	bundlePath := t.TempDir()
	lowerDir := t.TempDir()
	externalDir := t.TempDir()
	if err := os.Symlink(externalDir, filepath.Join(lowerDir, "etc")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundlePath, "hosts"), []byte("localhost\n"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := prepareRunscHostsRootfs(bundlePath, generatedHostsSpec(bundlePath, lowerDir))
	if err == nil || !strings.Contains(err.Error(), "/etc must be a directory") {
		t.Fatalf("prepareRunscHostsRootfs() error = %v", err)
	}
	if entries, err := os.ReadDir(externalDir); err != nil || len(entries) != 0 {
		t.Fatalf("external symlink target changed: entries=%v err=%v", entries, err)
	}
}

func TestPrepareRunscHostsRootfsSkipsEROFSPlaceholder(t *testing.T) {
	bundlePath := t.TempDir()
	spec := generatedHostsSpec(bundlePath, filepath.Join(bundlePath, "rootfs"))
	spec.Annotations = map[string]string{
		gvisorRootfsAnnotationPrefix + "type":   gvisorRootfsTypeEROFS,
		gvisorRootfsAnnotationPrefix + "source": "/images/rootfs.erofs",
	}
	cleanup, err := prepareRunscHostsRootfs(bundlePath, spec)
	if err != nil || cleanup != nil {
		t.Fatalf("EROFS placeholder preparation = cleanup:%v error:%v", cleanup != nil, err)
	}
}

func TestPrepareRunscGeneratedHostsTargetIsNoOpWithoutGeneratedMount(t *testing.T) {
	root := t.TempDir()
	lowerDir := filepath.Join(root, "missing-lower")
	upperDir := filepath.Join(root, "missing-upper")
	if err := prepareRunscGeneratedHostsTarget(root, &Spec{}, lowerDir, upperDir); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{lowerDir, upperDir} {
		if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("no-op target preparation touched %s: %v", target, err)
		}
	}
}

func TestCleanupRunscHostsRootfsDetachesBusyMount(t *testing.T) {
	bundlePath := t.TempDir()
	rootfsPath := filepath.Join(bundlePath, runscHostsRootfsDir)
	if err := os.MkdirAll(rootfsPath, 0755); err != nil {
		t.Fatal(err)
	}
	originalUnmount := unmountRunscHostsPath
	t.Cleanup(func() { unmountRunscHostsPath = originalUnmount })
	var flags []int
	unmountRunscHostsPath = func(target string, flag int) error {
		flags = append(flags, flag)
		if target == rootfsPath && flag == 0 {
			return syscall.EBUSY
		}
		return nil
	}
	if err := cleanupRunscHostsRootfs(bundlePath); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(flags, []int{0, syscall.MNT_DETACH}) {
		t.Fatalf("unmount flags = %v", flags)
	}
}

func TestCleanupRunscHostsRootfsIsNoOpWithoutHostsPaths(t *testing.T) {
	originalUnmount := unmountRunscHostsPath
	t.Cleanup(func() { unmountRunscHostsPath = originalUnmount })
	unmountRunscHostsPath = func(string, int) error {
		return errors.New("unexpected hosts unmount")
	}
	if err := cleanupRunscHostsRootfs(t.TempDir()); err != nil {
		t.Fatalf("cleanupRunscHostsRootfs() error = %v", err)
	}
}

func TestValidateRunscHostsOverlayPaths(t *testing.T) {
	for _, test := range []struct {
		path    string
		wantErr bool
	}{
		{path: "/data/sandbox/rootfs"},
		{path: "/data/sandbox,rootfs", wantErr: true},
		{path: "/data/sandbox:rootfs", wantErr: true},
		{path: `/data/sandbox\rootfs`, wantErr: true},
	} {
		err := validateRunscHostsOverlayPaths(test.path)
		if (err != nil) != test.wantErr {
			t.Fatalf("validateRunscHostsOverlayPaths(%q) error = %v, wantErr %v", test.path, err, test.wantErr)
		}
	}
}

func generatedHostsSpec(bundlePath, rootfs string) *Spec {
	return &Spec{
		Root: &Root{Path: rootfs, Readonly: true},
		Mounts: []Mount{{
			Destination: "/etc/hosts",
			Source:      filepath.Join(bundlePath, "hosts"),
			Type:        "bind",
		}},
	}
}
