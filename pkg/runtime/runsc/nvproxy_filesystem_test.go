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

package runsc

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/moby/sys/mountinfo"
)

func TestPrepareRunscPrivateRootfsSeedsReadonlyDirectoryTargets(t *testing.T) {
	bundlePath := t.TempDir()
	lowerDir := t.TempDir()
	fileSource := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(fileSource, nil, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundlePath, "config.json"), []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}

	originalMount := mountRunscNVProxyOverlay
	originalUnmount := unmountRunscNVProxyPath
	t.Cleanup(func() {
		mountRunscNVProxyOverlay = originalMount
		unmountRunscNVProxyPath = originalUnmount
	})
	mountRunscNVProxyOverlay = func(_, upper, _, _ string, _ bool) error {
		info, err := os.Lstat(filepath.Join(upper, "etc", "hosts"))
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("runsc upper file target was not prepared")
		}
		return nil
	}
	unmountRunscNVProxyPath = func(string, int) error { return syscall.EINVAL }

	spec := &runtimecore.Spec{
		Root: &runtimecore.Root{Path: lowerDir, Readonly: true},
		Mounts: []runtimecore.Mount{{
			Type: "bind", Source: fileSource, Destination: "/etc/hosts",
		}},
	}
	cleanup, err := prepareRunscPrivateRootfs(bundlePath, spec, false)
	if err != nil {
		t.Fatal(err)
	}
	if !spec.Root.Readonly {
		t.Fatal("readonly OCI root was made writable")
	}
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
}

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
	mountRunscNVProxyOverlay = func(lower, upper, work, target string, _ bool) error {
		mountedLower, mountedUpper, mountedWork, mountedTarget = lower, upper, work, target
		return nil
	}
	unmountRunscNVProxyPath = func(string, int) error {
		return syscall.EINVAL
	}

	spec := &runtimecore.Spec{Root: &runtimecore.Root{Path: lowerDir, Readonly: true}}
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
	var written runtimecore.Spec
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
			mountRunscNVProxyOverlay = func(_, upper, _, _ string, _ bool) error {
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

			spec := &runtimecore.Spec{Root: &runtimecore.Root{Path: lowerDir, Readonly: true}}
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
	originalProbeMount := mountRunscOverlayFilesystem
	originalUnmount := unmountRunscNVProxyPath
	t.Cleanup(func() {
		mountRunscNVProxyEROFSImage = originalImageMount
		mountRunscNVProxyOverlay = originalOverlayMount
		mountRunscOverlayFilesystem = originalProbeMount
		unmountRunscNVProxyPath = originalUnmount
	})
	var imageSource, imageTarget, overlayLower string
	imageMounted := false
	mountRunscNVProxyEROFSImage = func(source, target string) error {
		imageSource, imageTarget = source, target
		imageMounted = true
		return nil
	}
	overlayMounts := 0
	mountRunscNVProxyOverlay = func(lower, _, _, _ string, volatile bool) error {
		overlayMounts++
		if !imageMounted || lower != imageTarget {
			t.Fatalf("private overlay attempt %d lost the mounted EROFS lower", overlayMounts)
		}
		overlayLower = lower
		if volatile {
			return syscall.EINVAL
		}
		return nil
	}
	mountRunscOverlayFilesystem = func(_, _, _ string, _ uintptr, options string) error {
		if overlayOptionsVolatile(options) {
			return syscall.EINVAL
		}
		return nil
	}
	unmountRunscNVProxyPath = func(target string, _ int) error {
		if target == imageTarget && imageMounted {
			imageMounted = false
			return nil
		}
		return syscall.EINVAL
	}

	spec := &runtimecore.Spec{
		Root: &runtimecore.Root{Path: "rootfs", Readonly: false},
		Annotations: map[string]string{
			runtimecore.GVisorRootfsAnnotationPrefix + "source":  rootfsImage,
			runtimecore.GVisorRootfsAnnotationPrefix + "type":    runtimecore.GVisorRootfsTypeEROFS,
			runtimecore.GVisorRootfsAnnotationPrefix + "overlay": "dir=/filestore",
			runtimecore.GVisorRootfsAnnotationPrefix + "options": "size=10G",
			"example": "preserved",
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
	if overlayMounts != 2 {
		t.Fatalf("overlay attempts = %d, want primary and nonvolatile retry", overlayMounts)
	}
	for key := range spec.Annotations {
		if strings.HasPrefix(key, runtimecore.GVisorRootfsAnnotationPrefix) {
			t.Fatalf("gVisor rootfs image annotation %q was not removed", key)
		}
	}
	if spec.Annotations["example"] != "preserved" {
		t.Fatalf("unrelated annotation was not preserved: %v", spec.Annotations)
	}
	if err := cleanup(); err != nil {
		t.Fatalf("cleanup nvproxy rootfs: %v", err)
	}
	if imageMounted {
		t.Fatal("cleanup did not unmount the EROFS lower")
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

// Run in a private mount namespace with SANDBOXD_RUNSC_MOUNT_TEST=1.
func TestPrivateRootfsUsesEphemeralOverlay(t *testing.T) {
	if os.Getenv("SANDBOXD_RUNSC_MOUNT_TEST") != "1" {
		t.Skip("requires explicit opt-in inside a private mount namespace")
	}
	for _, hostWritable := range []bool{false, true} {
		t.Run(fmt.Sprintf("host-writable=%t", hostWritable), func(t *testing.T) {
			originalMount := mountRunscOverlayFilesystem
			t.Cleanup(func() { mountRunscOverlayFilesystem = originalMount })
			mountedVolatile := false
			mountRunscOverlayFilesystem = func(source, target, fstype string, flags uintptr, data string) error {
				err := originalMount(source, target, fstype, flags, data)
				if err == nil {
					mountedVolatile = overlayOptionsVolatile(data)
				}
				return err
			}
			bundle := t.TempDir()
			lower := t.TempDir()
			if !hostWritable {
				bundle = filepath.Join(bundle, `bundle,dir:\path`)
				lower = filepath.Join(lower, `lower,dir:\path`)
				for _, dir := range []string{bundle, lower} {
					if err := os.Mkdir(dir, 0755); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := os.WriteFile(filepath.Join(lower, "image-file"), []byte("image"), 0644); err != nil {
				t.Fatal(err)
			}
			spec := &runtimecore.Spec{
				Root: &runtimecore.Root{Path: lower, Readonly: true},
				Mounts: []runtimecore.Mount{{
					Type: "bind", Source: t.TempDir(), Destination: "/logs/output", Options: []string{"rw"},
				}},
			}
			cleanup, err := prepareRunscPrivateRootfs(bundle, spec, hostWritable)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := cleanup(); err != nil {
					t.Error(err)
				}
			})
			merged := filepath.Join(bundle, spec.Root.Path)
			mounts, err := mountinfo.GetMounts(mountinfo.SingleEntryFilter(merged))
			if err != nil {
				t.Fatal(err)
			}
			if len(mounts) != 1 || mounts[0].FSType != "overlay" {
				t.Fatal("private rootfs is not a distinct overlay mount")
			}
			if overlayOptionsVolatile(mounts[0].VFSOptions) != mountedVolatile {
				t.Fatalf("staging overlay options differ from successful mount: %s", mounts[0].VFSOptions)
			}
			if spec.Root.Readonly == hostWritable {
				t.Fatalf("unexpected guest root readonly=%t", spec.Root.Readonly)
			}
			if info, err := os.Stat(filepath.Join(merged, "logs", "output")); err != nil || !info.IsDir() {
				t.Fatalf("writable bind target missing from the merged root: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(lower, "logs")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("writable bind target changed the shared lower: %v", err)
			}
			if err := os.WriteFile(filepath.Join(merged, "image-file"), []byte("private"), 0644); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filepath.Join(lower, "image-file"))
			if err != nil || string(data) != "image" {
				t.Fatalf("private rootfs mutated shared lower: %q, %v", data, err)
			}
			if err := cleanup(); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{runscNVProxyRootfsDir, runscNVProxyUpperDir, runscNVProxyWorkDir} {
				if _, err := os.Lstat(filepath.Join(bundle, name)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("staging path remains after cleanup: %s, %v", name, err)
				}
			}
		})
	}
}

func TestPrivateRootfsOverlayCapabilityFallback(t *testing.T) {
	firstErr := fmt.Errorf("initial overlay failure: %w", syscall.EINVAL)
	type attempt struct {
		kind string
		err  error
	}
	for _, tc := range []struct {
		name         string
		attempts     []attempt
		wantedErrors []error
	}{
		{
			name:     "primary success",
			attempts: []attempt{{"primary", nil}},
		},
		{
			name:         "ordinary EINVAL with supported volatile",
			attempts:     []attempt{{"primary", firstErr}, {"probe", nil}},
			wantedErrors: []error{firstErr},
		},
		{
			name:         "inconclusive probe",
			attempts:     []attempt{{"primary", firstErr}, {"probe", syscall.EINVAL}, {"control", syscall.EPERM}},
			wantedErrors: []error{firstErr, syscall.EPERM},
		},
		{
			name:     "confirmed incompatibility",
			attempts: []attempt{{"primary", firstErr}, {"probe", syscall.EINVAL}, {"control", nil}, {"retry", nil}},
		},
		{
			name:         "confirmed incompatibility with failed retry",
			attempts:     []attempt{{"primary", firstErr}, {"probe", syscall.EINVAL}, {"control", nil}, {"retry", syscall.ENOENT}},
			wantedErrors: []error{firstErr, syscall.ENOENT},
		},
		{
			name:         "permission denied",
			attempts:     []attempt{{"primary", syscall.EPERM}},
			wantedErrors: []error{syscall.EPERM},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bundle := t.TempDir()
			lower := t.TempDir()
			rootfsDir := filepath.Join(bundle, runscNVProxyRootfsDir)
			upperDir := filepath.Join(bundle, runscNVProxyUpperDir)
			workDir := filepath.Join(bundle, runscNVProxyWorkDir)
			stageDirs := []string{rootfsDir, upperDir, workDir}
			probeLower := "lowerdir=" + filepath.Join(workDir, "lower1") + ":" + filepath.Join(workDir, "lower2")
			options := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", lower, upperDir, workDir)

			originalMount := mountRunscOverlayFilesystem
			originalUnmount := unmountRunscNVProxyPath
			t.Cleanup(func() {
				mountRunscOverlayFilesystem = originalMount
				unmountRunscNVProxyPath = originalUnmount
			})
			// Simulate a kernel mount and require the stage reset to unmount
			// any successful probe before creating or removing staging paths.
			mounted := false
			unmountRunscNVProxyPath = func(target string, _ int) error {
				if target == rootfsDir && mounted {
					mounted = false
					return nil
				}
				return syscall.EINVAL
			}
			calls := 0
			mountRunscOverlayFilesystem = func(source, target, fstype string, flags uintptr, data string) error {
				if mounted || calls >= len(tc.attempts) {
					t.Fatalf("unexpected mount call %d (mounted=%t): %s", calls+1, mounted, data)
				}
				if source != "overlay" || target != rootfsDir || fstype != "overlay" || flags != 0 {
					t.Fatalf("changed mount boundary: %s %s %s %d", source, target, fstype, flags)
				}
				kind, mountErr := tc.attempts[calls].kind, tc.attempts[calls].err
				var expected string
				switch kind {
				case "primary":
					expected = options + ",volatile"
				case "probe":
					expected = probeLower + ",volatile"
				case "control":
					expected = probeLower
				case "retry":
					expected = options
				}
				if data != expected {
					t.Fatalf("options = %q, want %q", data, expected)
				}
				for _, dir := range stageDirs {
					if _, err := os.Stat(filepath.Join(dir, "first-attempt")); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("%s found old staging contents in %s: %v", kind, dir, err)
					}
				}
				if kind == "primary" || kind == "retry" {
					if info, err := os.Stat(filepath.Join(upperDir, "logs", "output")); err != nil || !info.IsDir() {
						t.Fatalf("%s missing the staged writable bind target: %v", kind, err)
					}
					if entries, err := os.ReadDir(workDir); err != nil || len(entries) != 0 {
						t.Fatalf("%s workdir must be empty: %v, %v", kind, entries, err)
					}
				}
				if kind == "primary" {
					for _, dir := range stageDirs {
						if err := os.WriteFile(filepath.Join(dir, "first-attempt"), nil, 0600); err != nil {
							t.Fatal(err)
						}
					}
				}
				calls++
				mounted = mountErr == nil
				return mountErr
			}
			spec := &runtimecore.Spec{
				Root: &runtimecore.Root{Path: lower, Readonly: true},
				Mounts: []runtimecore.Mount{{
					Type: "bind", Source: t.TempDir(), Destination: "/logs/output", Options: []string{"rw"},
				}},
			}
			cleanup, err := prepareRunscPrivateRootfs(bundle, spec, false)
			if calls != len(tc.attempts) || (err == nil) != (len(tc.wantedErrors) == 0) {
				t.Fatalf("prepareRunscPrivateRootfs() after %d mounts returned %v", calls, err)
			}
			for _, wanted := range tc.wantedErrors {
				if !errors.Is(err, wanted) {
					t.Errorf("prepareRunscPrivateRootfs() error %v lost %v", err, wanted)
				}
			}
			if err == nil {
				if cleanup == nil {
					t.Fatal("successful preparation did not return cleanup")
				}
				if err := cleanup(); err != nil {
					t.Fatal(err)
				}
			} else if cleanup != nil || spec.Root.Path != lower {
				t.Fatal("failed preparation published a staged root")
			}
			if mounted {
				t.Error("staging or probe mount remains")
			}
			for _, dir := range stageDirs {
				if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("staging directory remains: %s, %v", dir, err)
				}
			}
		})
	}
}

func TestRunscLegacyOverlayMountOptionLimit(t *testing.T) {
	original := mountRunscOverlayFilesystem
	t.Cleanup(func() { mountRunscOverlayFilesystem = original })
	calls := 0
	mountRunscOverlayFilesystem = func(_, _, _ string, _ uintptr, _ string) error {
		calls++
		return nil
	}
	page := os.Getpagesize()
	if err := mountRunscLegacyOverlay("/target", strings.Repeat("a", page-1)); err != nil {
		t.Fatal(err)
	}
	if err := mountRunscLegacyOverlay("/target", strings.Repeat("a", page)); err == nil ||
		!strings.Contains(err.Error(), fmt.Sprintf("legacy mount limit of %d bytes", page)) {
		t.Fatalf("mountRunscLegacyOverlay() error = %v", err)
	}
	if calls != 1 {
		t.Fatalf("mount calls = %d, want 1", calls)
	}
}

func TestRunscOverlayEscapesPathsForMountAndCompatibilityProbe(t *testing.T) {
	original := mountRunscOverlayFilesystem
	t.Cleanup(func() { mountRunscOverlayFilesystem = original })
	var options []string
	mountRunscOverlayFilesystem = func(_, _, _ string, _ uintptr, data string) error {
		options = append(options, data)
		return nil
	}
	if err := mountRunscNVProxyOverlay(`/image:root`, `/bundle,one/upper`, `/bundle\two/work`, "/target", true); err != nil {
		t.Fatal(err)
	}
	if got, want := options[0], `lowerdir=/image\:root,upperdir=/bundle\,one/upper,workdir=/bundle\\two/work,volatile`; got != want {
		t.Errorf("staging options = %q, want %q", got, want)
	}
	probeRoot := t.TempDir()
	probeDir := filepath.Join(probeRoot, "bundle,probe")
	if unsupported, err := runscOverlayVolatileUnsupported(probeDir, filepath.Join(probeRoot, "target")); err != nil || unsupported {
		t.Fatalf("compatibility probe = %v, %v", unsupported, err)
	}
	want := "lowerdir=" + probeRoot + `/bundle\,probe/lower1:` + probeRoot + `/bundle\,probe/lower2,volatile`
	if got := options[1]; got != want {
		t.Errorf("probe options = %q, want %q", got, want)
	}
}

func overlayOptionsVolatile(options string) bool {
	return strings.Contains(","+options+",", ",volatile,") || strings.Contains(","+options+",", ",fsync=volatile,")
}

func TestPrivateRootfsOverlayMountinfoVolatileAliases(t *testing.T) {
	for _, tc := range []struct {
		options  string
		volatile bool
	}{
		{"rw,lowerdir=/lower,volatile", true},
		{"rw,lowerdir=/lower,fsync=volatile", true},
		{"rw,fsync=auto", false},
		{"rw,fsync=strict", false},
		{"rw,lowerdir=/volatile,upperdir=/fsync=volatile", false},
		{"rw,notvolatile,fsync=volatile-extra", false},
	} {
		t.Run(tc.options, func(t *testing.T) {
			if got := overlayOptionsVolatile(tc.options); got != tc.volatile {
				t.Fatalf("mountinfo %q volatile=%t, want %t", tc.options, got, tc.volatile)
			}
		})
	}
}
