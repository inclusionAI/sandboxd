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
	"syscall"
)

const (
	runscNVProxyRootfsDir = "nvproxy-rootfs"
	runscNVProxyUpperDir  = "nvproxy-upper"
	runscNVProxyWorkDir   = "nvproxy-work"
)

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

	lowerDir := spec.Root.Path
	if !filepath.IsAbs(lowerDir) {
		lowerDir = filepath.Join(bundlePath, lowerDir)
	}
	info, err := os.Stat(lowerDir)
	if err != nil {
		return nil, fmt.Errorf("stat nvproxy rootfs %s: %w", lowerDir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("nvproxy rootfs %s must be a directory", lowerDir)
	}

	if err := cleanupRunscNVProxyRootfs(bundlePath); err != nil {
		return nil, fmt.Errorf("clean previous nvproxy rootfs: %w", err)
	}
	rootfsDir := filepath.Join(bundlePath, runscNVProxyRootfsDir)
	upperDir := filepath.Join(bundlePath, runscNVProxyUpperDir)
	workDir := filepath.Join(bundlePath, runscNVProxyWorkDir)
	for _, path := range []string{rootfsDir, upperDir, workDir} {
		if err := os.MkdirAll(path, 0755); err != nil {
			return nil, errors.Join(err, cleanupRunscNVProxyRootfs(bundlePath))
		}
	}
	if err := mountRunscNVProxyOverlay(lowerDir, upperDir, workDir, rootfsDir); err != nil {
		return nil, errors.Join(
			fmt.Errorf("mount nvproxy rootfs at %s: %w", rootfsDir, err),
			cleanupRunscNVProxyRootfs(bundlePath),
		)
	}
	nvidiaProcDir := filepath.Join(rootfsDir, "proc", "driver", "nvidia")
	if err := os.MkdirAll(nvidiaProcDir, 0755); err != nil {
		return nil, errors.Join(
			fmt.Errorf("create nvproxy procfs mount point: %w", err),
			cleanupRunscNVProxyRootfs(bundlePath),
		)
	}
	if err := os.Chmod(nvidiaProcDir, 0555); err != nil {
		return nil, errors.Join(
			fmt.Errorf("set nvproxy procfs mount point permissions: %w", err),
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

func cleanupRunscNVProxyRootfs(bundlePath string) error {
	rootfsDir := filepath.Join(bundlePath, runscNVProxyRootfsDir)
	if err := unmountRunscNVProxyPath(rootfsDir, 0); err != nil &&
		!errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.ENOENT) {
		if !errors.Is(err, syscall.EBUSY) {
			return fmt.Errorf("unmount nvproxy rootfs %s: %w", rootfsDir, err)
		}
		if detachErr := unmountRunscNVProxyPath(rootfsDir, syscall.MNT_DETACH); detachErr != nil {
			return errors.Join(
				fmt.Errorf("unmount nvproxy rootfs %s: %w", rootfsDir, err),
				fmt.Errorf("detach nvproxy rootfs %s: %w", rootfsDir, detachErr),
			)
		}
	}

	var result error
	for _, name := range []string{
		runscNVProxyRootfsDir,
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
