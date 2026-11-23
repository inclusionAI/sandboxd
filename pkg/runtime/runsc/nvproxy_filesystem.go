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

	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
	runtimecommon "github.com/inclusionAI/sandboxd/pkg/runtime/internal/common"
)

const (
	runscNVProxyRootfsDir = "nvproxy-rootfs"
	runscNVProxyLowerDir  = "nvproxy-lower"
	runscNVProxyUpperDir  = "nvproxy-upper"
	runscNVProxyWorkDir   = "nvproxy-work"
)

var mountRunscNVProxyEROFSImage = runtimecommon.MountReadOnlyEROFSImage

var mountRunscOverlayFilesystem = syscall.Mount

var runscOverlayPathEscape = strings.NewReplacer(`\`, `\\`, `:`, `\:`, `,`, `\,`)

var mountRunscNVProxyOverlay = func(lowerDir, upperDir, workDir, target string, volatile bool) error {
	options := fmt.Sprintf(
		"lowerdir=%s,upperdir=%s,workdir=%s",
		runscOverlayPathEscape.Replace(lowerDir),
		runscOverlayPathEscape.Replace(upperDir),
		runscOverlayPathEscape.Replace(workDir),
	)
	if volatile {
		options += ",volatile"
	}
	return mountRunscLegacyOverlay(target, options)
}

func mountRunscLegacyOverlay(target, options string) error {
	if size, limit := len(options)+1, os.Getpagesize(); size > limit {
		return fmt.Errorf("overlay mount options require %d bytes including NUL, exceeding the legacy mount limit of %d bytes", size, limit)
	}
	return mountRunscOverlayFilesystem("overlay", target, "overlay", 0, options)
}

var unmountRunscNVProxyPath = func(target string, flags int) error {
	return syscall.Unmount(target, flags)
}

// prepareRunscNVProxyRootfs gives gVisor's NVIDIA legacy hook a private,
// host-writable view of the image-manager rootfs.
func prepareRunscNVProxyRootfs(bundlePath string, spec *runtimecore.Spec) (func() error, error) {
	return prepareRunscPrivateRootfs(bundlePath, spec, true)
}

// prepareRunscPrivateRootfs creates a per-sandbox overlay without modifying
// the image-manager rootfs. A host-writable view is required by the NVIDIA
// legacy hook; otherwise the original OCI readonly setting is preserved.
func prepareRunscPrivateRootfs(
	bundlePath string,
	spec *runtimecore.Spec,
	requireHostWritable bool,
) (func() error, error) {
	return prepareRunscPrivateRootfsWithMounter(
		bundlePath,
		spec,
		requireHostWritable,
		mountRunscNVProxyEROFSImage,
	)
}

func prepareRunscPrivateRootfsWithMounter(
	bundlePath string,
	spec *runtimecore.Spec,
	requireHostWritable bool,
	mountEROFS runtimecommon.EROFSImageMounter,
) (func() error, error) {
	if spec == nil || spec.Root == nil || spec.Root.Path == "" {
		return nil, errors.New("private runsc rootfs requires a root filesystem")
	}
	originalReadonly := spec.Root.Readonly
	if err := cleanupRunscNVProxyRootfs(bundlePath); err != nil {
		return nil, fmt.Errorf("clean previous private runsc rootfs: %w", err)
	}

	lowerDir := spec.Root.Path
	if !filepath.IsAbs(lowerDir) {
		lowerDir = filepath.Join(bundlePath, lowerDir)
	}
	if source, ok := runscNVProxyEROFSImageSource(spec); ok {
		lowerDir = filepath.Join(bundlePath, runscNVProxyLowerDir)
		if err := os.MkdirAll(lowerDir, 0755); err != nil {
			return nil, errors.Join(err, cleanupRunscNVProxyRootfs(bundlePath))
		}
		if err := mountEROFS(source, lowerDir); err != nil {
			return nil, errors.Join(
				fmt.Errorf("mount nvproxy EROFS rootfs %s: %w", source, err),
				cleanupRunscNVProxyRootfs(bundlePath),
			)
		}
		for key := range spec.Annotations {
			if strings.HasPrefix(key, runtimecore.GVisorRootfsAnnotationPrefix) {
				delete(spec.Annotations, key)
			}
		}
	}
	info, err := os.Stat(lowerDir)
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf("stat nvproxy rootfs %s: %w", lowerDir, err),
			cleanupRunscNVProxyRootfs(bundlePath),
		)
	}
	if !info.IsDir() {
		return nil, errors.Join(
			fmt.Errorf("nvproxy rootfs %s must be a directory", lowerDir),
			cleanupRunscNVProxyRootfs(bundlePath),
		)
	}
	if err := prepareRunscPrivateOverlay(bundlePath, lowerDir, spec.Mounts); err != nil {
		return nil, errors.Join(err, cleanupRunscNVProxyRootfs(bundlePath))
	}

	spec.Root.Path = runscNVProxyRootfsDir
	spec.Root.Readonly = originalReadonly && !requireHostWritable
	if err := writeRunscNVProxySpec(filepath.Join(bundlePath, "config.json"), spec); err != nil {
		return nil, errors.Join(err, cleanupRunscNVProxyRootfs(bundlePath))
	}
	return func() error { return cleanupRunscNVProxyRootfs(bundlePath) }, nil
}

func prepareRunscPrivateOverlay(bundlePath, lowerDir string, mounts []runtimecore.Mount) error {
	rootfsDir := filepath.Join(bundlePath, runscNVProxyRootfsDir)
	upperDir := filepath.Join(bundlePath, runscNVProxyUpperDir)
	workDir := filepath.Join(bundlePath, runscNVProxyWorkDir)
	if err := stageRunscPrivateOverlay(rootfsDir, upperDir, workDir, mounts); err != nil {
		return err
	}
	// This overlay only stages mount targets and host hook output. It is
	// recreated for every execution; guest writes use runsc's separate
	// filestore. Do not let teardown sync the entire shared upper filesystem
	// while other sandboxes are persisting checkpoints (Linux 5.10 ovl_sync_fs).
	err := mountRunscNVProxyOverlay(lowerDir, upperDir, workDir, rootfsDir, true)
	if err == nil {
		return nil
	}
	initialErr := fmt.Errorf("mount private runsc rootfs at %s: %w", rootfsDir, err)
	if !errors.Is(err, syscall.EINVAL) {
		return initialErr
	}

	reset := func() error {
		if err := unmountRunscNVProxyMount(rootfsDir); err != nil {
			return err
		}
		return removeRunscNVProxyPaths(rootfsDir, upperDir, workDir)
	}
	if err := reset(); err != nil {
		return errors.Join(initialErr, fmt.Errorf("reset private runsc staging: %w", err))
	}
	unsupported, err := runscOverlayVolatileUnsupported(workDir, rootfsDir)
	if err != nil {
		return errors.Join(initialErr, fmt.Errorf("probe overlay volatile support: %w", err))
	}
	if !unsupported {
		return initialErr
	}
	if err := reset(); err != nil {
		return errors.Join(initialErr, fmt.Errorf("reset private runsc staging after compatibility probe: %w", err))
	}
	if err := stageRunscPrivateOverlay(rootfsDir, upperDir, workDir, mounts); err != nil {
		return errors.Join(initialErr, err)
	}
	if err := mountRunscNVProxyOverlay(lowerDir, upperDir, workDir, rootfsDir, false); err != nil {
		return errors.Join(initialErr, fmt.Errorf("retry private runsc rootfs mount without volatile: %w", err))
	}
	return nil
}

func stageRunscPrivateOverlay(rootfsDir, upperDir, workDir string, mounts []runtimecore.Mount) error {
	for _, path := range []string{rootfsDir, upperDir, workDir} {
		if err := os.MkdirAll(path, 0755); err != nil {
			return err
		}
	}
	if err := runtimecore.CreateRootfsMountTargets(upperDir, mounts); err != nil {
		return fmt.Errorf("create private runsc rootfs mount targets: %w", err)
	}
	// Seed the mount point in the private upper directory before mounting the
	// overlay. The image-backed lower directory is untrusted and may contain
	// symlinks at any component of this path. Creating the directory through
	// the merged view would allow those symlinks to redirect sandboxd's
	// privileged filesystem operations outside the bundle. The upper entry
	// also masks conflicting lower entries before runsc prepares nvproxy.
	nvidiaProcDir := filepath.Join(upperDir, "proc", "driver", "nvidia")
	if err := os.MkdirAll(nvidiaProcDir, 0755); err != nil {
		return fmt.Errorf("create nvproxy upper procfs mount point: %w", err)
	}
	if err := os.Chmod(nvidiaProcDir, 0555); err != nil {
		return fmt.Errorf("set nvproxy upper procfs mount point permissions: %w", err)
	}
	return nil
}

func runscOverlayVolatileUnsupported(probeDir, target string) (bool, error) {
	first := filepath.Join(probeDir, "lower1")
	second := filepath.Join(probeDir, "lower2")
	for _, path := range []string{first, second, target} {
		if err := os.MkdirAll(path, 0755); err != nil {
			return false, err
		}
	}
	// Use a plain lower-only overlay so the parser sees volatile without the
	// production lower's stacking depth or the upper/workdir constraints. On
	// success the caller unmounts the probe before reusing the staging path.
	options := "lowerdir=" + runscOverlayPathEscape.Replace(first) + ":" + runscOverlayPathEscape.Replace(second)
	if err := mountRunscLegacyOverlay(target, options+",volatile"); !errors.Is(err, syscall.EINVAL) {
		return false, err
	}
	if err := mountRunscLegacyOverlay(target, options); err != nil {
		return false, fmt.Errorf("mount nonvolatile overlay control: %w", err)
	}
	return true, nil
}

func runscNVProxyEROFSImageSource(spec *runtimecore.Spec) (string, bool) {
	if spec == nil || spec.Annotations == nil {
		return "", false
	}
	if spec.Annotations[runtimecore.GVisorRootfsAnnotationPrefix+"type"] != runtimecore.GVisorRootfsTypeEROFS {
		return "", false
	}
	source := spec.Annotations[runtimecore.GVisorRootfsAnnotationPrefix+"source"]
	return source, source != ""
}

func cleanupRunscNVProxyRootfs(bundlePath string) error {
	rootfsDir := filepath.Join(bundlePath, runscNVProxyRootfsDir)
	if err := unmountRunscNVProxyMount(rootfsDir); err != nil {
		return err
	}
	if err := unmountRunscNVProxyMount(filepath.Join(bundlePath, runscNVProxyLowerDir)); err != nil {
		return err
	}

	return removeRunscNVProxyPaths(
		rootfsDir,
		filepath.Join(bundlePath, runscNVProxyLowerDir),
		filepath.Join(bundlePath, runscNVProxyUpperDir),
		filepath.Join(bundlePath, runscNVProxyWorkDir),
	)
}

func removeRunscNVProxyPaths(paths ...string) error {
	var result error
	for _, path := range paths {
		if err := os.RemoveAll(path); err != nil {
			result = errors.Join(result, fmt.Errorf("remove nvproxy rootfs path %s: %w", path, err))
		}
	}
	return result
}

func unmountRunscNVProxyMount(target string) error {
	if err := unmountRunscNVProxyPath(target, 0); err != nil &&
		!errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.ENOENT) {
		if !errors.Is(err, syscall.EBUSY) {
			return fmt.Errorf("unmount nvproxy rootfs %s: %w", target, err)
		}
		if detachErr := unmountRunscNVProxyPath(target, syscall.MNT_DETACH); detachErr != nil {
			return errors.Join(
				fmt.Errorf("unmount nvproxy rootfs %s: %w", target, err),
				fmt.Errorf("detach nvproxy rootfs %s: %w", target, detachErr),
			)
		}
	}
	return nil
}

func writeRunscNVProxySpec(path string, spec *runtimecore.Spec) error {
	data, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return err
	}
	temporaryPath := path + ".nvproxy.tmp"
	if err := os.WriteFile(temporaryPath, data, 0644); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}
