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
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	procDirInfo, err := os.Stat(filepath.Join(mountedUpper, "proc", "driver", "nvidia"))
	if err != nil {
		t.Fatalf("nvproxy upper procfs mount point was not created: %v", err)
	}
	if !procDirInfo.IsDir() || procDirInfo.Mode().Perm() != 0555 {
		t.Fatalf("unexpected nvproxy upper procfs mount point: %v", procDirInfo.Mode())
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
		runscNVProxyLowerDir,
		runscNVProxyUpperDir,
		runscNVProxyWorkDir,
	} {
		if _, err := os.Stat(filepath.Join(bundlePath, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("nvproxy path %q remains after cleanup: %v", name, err)
		}
	}
}

func TestPrepareRunscNVProxyRootfsDoesNotFollowLowerSymlinks(t *testing.T) {
	for _, test := range []struct {
		name       string
		linkParent string
		linkName   string
	}{
		{
			name:     "intermediate proc symlink",
			linkName: "proc",
		},
		{
			name:       "final nvidia symlink",
			linkParent: filepath.Join("proc", "driver"),
			linkName:   "nvidia",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			bundlePath := t.TempDir()
			lowerDir := t.TempDir()
			externalDir := t.TempDir()
			if err := os.Chmod(externalDir, 0700); err != nil {
				t.Fatal(err)
			}
			linkParent := filepath.Join(lowerDir, test.linkParent)
			if err := os.MkdirAll(linkParent, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(externalDir, filepath.Join(linkParent, test.linkName)); err != nil {
				t.Fatal(err)
			}

			originalMount := mountRunscNVProxyOverlay
			originalUnmount := unmountRunscNVProxyPath
			t.Cleanup(func() {
				mountRunscNVProxyOverlay = originalMount
				unmountRunscNVProxyPath = originalUnmount
			})
			mountRunscNVProxyOverlay = func(_, upper, _, _ string) error {
				info, err := os.Stat(filepath.Join(upper, "proc", "driver", "nvidia"))
				if err != nil {
					return err
				}
				if !info.IsDir() || info.Mode().Perm() != 0555 {
					return errors.New("nvproxy upper procfs mount point was not prepared before mount")
				}
				return nil
			}
			unmountRunscNVProxyPath = func(string, int) error { return syscall.EINVAL }

			spec := &Spec{Root: &Root{Path: lowerDir, Readonly: true}}
			cleanup, err := prepareRunscNVProxyRootfs(bundlePath, spec)
			if err != nil {
				t.Fatalf("prepareRunscNVProxyRootfs() error = %v", err)
			}
			if err := cleanup(); err != nil {
				t.Fatalf("cleanup nvproxy rootfs: %v", err)
			}

			info, err := os.Stat(externalDir)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0700 {
				t.Fatalf("external directory mode changed to %o", info.Mode().Perm())
			}
			if _, err := os.Stat(filepath.Join(externalDir, "driver")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("directory was created through lower symlink: %v", err)
			}
		})
	}
}

func TestPrepareRunscNVProxyRootfsMountsEROFSImage(t *testing.T) {
	bundlePath := t.TempDir()
	placeholderRootfs := filepath.Join(bundlePath, "rootfs")
	if err := os.MkdirAll(placeholderRootfs, 0755); err != nil {
		t.Fatal(err)
	}
	rootfsImage := filepath.Join(t.TempDir(), "rootfs.img")
	if err := os.WriteFile(rootfsImage, []byte("erofs-placeholder"), 0644); err != nil {
		t.Fatal(err)
	}

	originalImageMount := mountRunscNVProxyEROFSImage
	originalOverlayMount := mountRunscNVProxyOverlay
	originalUnmount := unmountRunscNVProxyPath
	t.Cleanup(func() {
		mountRunscNVProxyEROFSImage = originalImageMount
		mountRunscNVProxyOverlay = originalOverlayMount
		unmountRunscNVProxyPath = originalUnmount
	})
	var imageSource, imageTarget, overlayLower string
	mountRunscNVProxyEROFSImage = func(source, target string) error {
		imageSource, imageTarget = source, target
		return nil
	}
	mountRunscNVProxyOverlay = func(lower, _, _, _ string) error {
		overlayLower = lower
		return nil
	}
	unmountRunscNVProxyPath = func(string, int) error { return syscall.EINVAL }

	spec := &Spec{
		Root: &Root{Path: "rootfs", Readonly: false},
		Annotations: map[string]string{
			gvisorRootfsAnnotationPrefix + "source":  rootfsImage,
			gvisorRootfsAnnotationPrefix + "type":    gvisorRootfsTypeEROFS,
			gvisorRootfsAnnotationPrefix + "overlay": "dir=/filestore",
			gvisorRootfsAnnotationPrefix + "options": "size=10G",
			"example":                                "preserved",
		},
	}
	cleanup, err := prepareRunscNVProxyRootfs(bundlePath, spec)
	if err != nil {
		t.Fatalf("prepareRunscNVProxyRootfs() error = %v", err)
	}
	expectedLower := filepath.Join(bundlePath, runscNVProxyLowerDir)
	if imageSource != rootfsImage || imageTarget != expectedLower {
		t.Fatalf("unexpected EROFS mount: source=%q target=%q", imageSource, imageTarget)
	}
	if overlayLower != expectedLower {
		t.Fatalf("overlay lower=%q, want %q", overlayLower, expectedLower)
	}
	for key := range spec.Annotations {
		if strings.HasPrefix(key, gvisorRootfsAnnotationPrefix) {
			t.Fatalf("gVisor rootfs image annotation %q was not removed", key)
		}
	}
	if spec.Annotations["example"] != "preserved" {
		t.Fatalf("unrelated annotation was not preserved: %v", spec.Annotations)
	}
	if err := cleanup(); err != nil {
		t.Fatalf("cleanup nvproxy rootfs: %v", err)
	}
}

func TestPrepareRunscNVProxyRootfsAddsOnlyRequiredHostsTarget(t *testing.T) {
	for _, test := range []struct {
		name           string
		generatedMount bool
		existingTarget bool
		wantTarget     bool
	}{
		{name: "explicit etc mount remains unchanged"},
		{name: "existing image target remains unchanged", generatedMount: true, existingTarget: true},
		{name: "missing image target is seeded", generatedMount: true, wantTarget: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			bundlePath := t.TempDir()
			lowerDir := t.TempDir()
			if test.existingTarget {
				if err := os.Mkdir(filepath.Join(lowerDir, "etc"), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(lowerDir, "etc", "hosts"), nil, 0644); err != nil {
					t.Fatal(err)
				}
			}

			originalMount := mountRunscNVProxyOverlay
			originalUnmount := unmountRunscNVProxyPath
			t.Cleanup(func() {
				mountRunscNVProxyOverlay = originalMount
				unmountRunscNVProxyPath = originalUnmount
			})
			mountRunscNVProxyOverlay = func(_, upper, _, _ string) error {
				_, err := os.Lstat(filepath.Join(upper, "etc", "hosts"))
				gotTarget := err == nil
				if err != nil && !errors.Is(err, os.ErrNotExist) {
					return err
				}
				if gotTarget != test.wantTarget {
					return fmt.Errorf("hosts target present = %v, want %v", gotTarget, test.wantTarget)
				}
				return nil
			}
			unmountRunscNVProxyPath = func(string, int) error { return syscall.EINVAL }

			spec := &Spec{Root: &Root{Path: lowerDir, Readonly: true}}
			if test.generatedMount {
				spec.Mounts = []Mount{{
					Destination: "/etc/hosts",
					Type:        "bind",
					Source:      filepath.Join(bundlePath, "hosts"),
				}}
			} else {
				spec.Mounts = []Mount{{Destination: "/etc", Type: "bind", Source: "/custom/etc"}}
			}
			cleanup, err := prepareRunscNVProxyRootfs(bundlePath, spec)
			if err != nil {
				t.Fatalf("prepareRunscNVProxyRootfs() error = %v", err)
			}
			if err := cleanup(); err != nil {
				t.Fatalf("cleanup NVProxy rootfs: %v", err)
			}
		})
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
	unmountRunscNVProxyPath = func(target string, flag int) error {
		flags = append(flags, flag)
		if target == rootfsPath {
			if flag == 0 {
				return syscall.EBUSY
			}
			return nil
		}
		return syscall.EINVAL
	}

	if err := cleanupRunscNVProxyRootfs(bundlePath); err != nil {
		t.Fatalf("cleanupRunscNVProxyRootfs() error = %v", err)
	}
	if len(flags) != 3 || flags[0] != 0 || flags[1] != syscall.MNT_DETACH || flags[2] != 0 {
		t.Fatalf("unexpected unmount flags: %v", flags)
	}
}
