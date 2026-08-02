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
)

const (
	runscNVProxyRootfsDir = "nvproxy-rootfs"
	runscNVProxyLowerDir  = "nvproxy-lower"
	runscNVProxyUpperDir  = "nvproxy-upper"
	runscNVProxyWorkDir   = "nvproxy-work"
)

var mountRunscNVProxyEROFSImage = mountReadOnlyEROFSImage

var mountRunscNVProxyOverlay = func(lowerDir, upperDir, workDir, target string) error {
	options := fmt.Sprintf(
		"lowerdir=%s,upperdir=%s,workdir=%s",
		lowerDir,
		upperDir,
		workDir,
	)
	return syscall.Mount("overlay", target, "overlay", 0, options)
}

var unmountRunscNVProxyPath = func(target string, flags int) error {
	return syscall.Unmount(target, flags)
}

// prepareRunscNVProxyRootfs gives gVisor's NVIDIA legacy hook a private,
// host-writable view of the image-manager rootfs. The hook invokes
// nvidia-container-cli before the sentry-side writable overlay exists, so it
// cannot configure a shared read-only OCI mount directly.
func prepareRunscNVProxyRootfs(bundlePath string, spec *Spec) (func() error, error) {
	if spec == nil || spec.Root == nil || spec.Root.Path == "" {
		return nil, errors.New("nvproxy requires a root filesystem")
	}
	if err := cleanupRunscNVProxyRootfs(bundlePath); err != nil {
		return nil, fmt.Errorf("clean previous nvproxy rootfs: %w", err)
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
		if err := mountRunscNVProxyEROFSImage(source, lowerDir); err != nil {
			return nil, errors.Join(
				fmt.Errorf("mount nvproxy EROFS rootfs %s: %w", source, err),
				cleanupRunscNVProxyRootfs(bundlePath),
			)
		}
		for key := range spec.Annotations {
			if strings.HasPrefix(key, gvisorRootfsAnnotationPrefix) {
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
	rootfsDir := filepath.Join(bundlePath, runscNVProxyRootfsDir)
	upperDir := filepath.Join(bundlePath, runscNVProxyUpperDir)
	workDir := filepath.Join(bundlePath, runscNVProxyWorkDir)
	for _, path := range []string{rootfsDir, upperDir, workDir} {
		if err := os.MkdirAll(path, 0755); err != nil {
			return nil, errors.Join(err, cleanupRunscNVProxyRootfs(bundlePath))
		}
	}
	// Reuse NVProxy's existing private upper when the generated hosts bind
	// mount needs a target. This is a strict no-op for callers that provide
	// /etc themselves and for images that already contain a regular target.
	if err := prepareRunscGeneratedHostsTarget(bundlePath, spec, lowerDir, upperDir); err != nil {
		return nil, errors.Join(
			fmt.Errorf("prepare nvproxy hosts target: %w", err),
			cleanupRunscNVProxyRootfs(bundlePath),
		)
	}
	// Seed the mount point in the private upper directory before mounting the
	// overlay. The image-backed lower directory is untrusted and may contain
	// symlinks at any component of this path. Creating the directory through
	// the merged view would allow those symlinks to redirect sandboxd's
	// privileged filesystem operations outside the bundle. The upper entry
	// also masks conflicting lower entries before runsc prepares nvproxy.
	nvidiaProcDir := filepath.Join(upperDir, "proc", "driver", "nvidia")
	if err := os.MkdirAll(nvidiaProcDir, 0755); err != nil {
		return nil, errors.Join(
			fmt.Errorf("create nvproxy upper procfs mount point: %w", err),
			cleanupRunscNVProxyRootfs(bundlePath),
		)
	}
	if err := os.Chmod(nvidiaProcDir, 0555); err != nil {
		return nil, errors.Join(
			fmt.Errorf("set nvproxy upper procfs mount point permissions: %w", err),
			cleanupRunscNVProxyRootfs(bundlePath),
		)
	}
	if err := mountRunscNVProxyOverlay(lowerDir, upperDir, workDir, rootfsDir); err != nil {
		return nil, errors.Join(
			fmt.Errorf("mount nvproxy rootfs at %s: %w", rootfsDir, err),
			cleanupRunscNVProxyRootfs(bundlePath),
		)
	}

	spec.Root.Path = runscNVProxyRootfsDir
	spec.Root.Readonly = false
	if err := writeRunscNVProxySpec(filepath.Join(bundlePath, "config.json"), spec); err != nil {
		return nil, errors.Join(err, cleanupRunscNVProxyRootfs(bundlePath))
	}
	return func() error { return cleanupRunscNVProxyRootfs(bundlePath) }, nil
}

func runscNVProxyEROFSImageSource(spec *Spec) (string, bool) {
	if spec == nil || spec.Annotations == nil {
		return "", false
	}
	if spec.Annotations[gvisorRootfsAnnotationPrefix+"type"] != gvisorRootfsTypeEROFS {
		return "", false
	}
	source := spec.Annotations[gvisorRootfsAnnotationPrefix+"source"]
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

	var result error
	for _, name := range []string{
		runscNVProxyRootfsDir,
		runscNVProxyLowerDir,
		runscNVProxyUpperDir,
		runscNVProxyWorkDir,
	} {
		path := filepath.Join(bundlePath, name)
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

func writeRunscNVProxySpec(path string, spec *Spec) error {
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
