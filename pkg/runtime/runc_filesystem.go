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
	"slices"
	"strings"
	"syscall"

	runtimeapi "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/util"
	"google.golang.org/protobuf/proto"
)

const (
	runcRootfsDir       = "rootfs"
	runcRootfsLowerDir  = "runc-rootfs-lower"
	runcEROFSMountsDir  = "runc-erofs-mounts"
	runcEROFSContentDir = "lower"
	runcStorageDir      = ".runc"
)

func cloneRuncStartConfig(input StartConfig) StartConfig {
	cloned := input
	if input.Resources != nil {
		cloned.Resources = proto.Clone(input.Resources).(*runtimeapi.LinuxSandboxResources)
	}
	cloned.Mounts = make([]*runtimeapi.Mount, len(input.Mounts))
	for index, mount := range input.Mounts {
		if mount != nil {
			cloned.Mounts[index] = proto.Clone(mount).(*runtimeapi.Mount)
		}
	}
	return cloned
}

func prepareRuncMounts(
	bundlePath string,
	config *StartConfig,
	mountEROFS erofsImageMounter,
) (func() error, error) {
	if err := cleanupRuncMounts(bundlePath); err != nil {
		return nil, fmt.Errorf("clean stale runc EROFS mounts: %w", err)
	}
	mounted := make([]string, 0, len(config.Mounts))
	bySource := make(map[string]string)
	cleanup := func() error {
		var result error
		for index := len(mounted) - 1; index >= 0; index-- {
			result = errors.Join(result, unmountRuncPath(mounted[index]))
		}
		if result == nil {
			result = os.RemoveAll(filepath.Join(bundlePath, runcEROFSMountsDir))
		}
		return result
	}

	for index, mount := range config.Mounts {
		if mount == nil || mount.GetType() != erofsMountType {
			continue
		}
		if slices.Contains(mount.GetOptions(), "rw") {
			return nil, errors.Join(
				fmt.Errorf("runc EROFS mount %s cannot be writable", mount.GetTarget()),
				cleanup(),
			)
		}
		source := mount.GetHostPath()
		info, err := os.Stat(source)
		if err != nil {
			return nil, errors.Join(err, cleanup())
		}
		mount.Type = "bind"
		mount.Options = runcReadOnlyBindOptions(mount.GetOptions())
		if info.IsDir() {
			continue
		}
		if !info.Mode().IsRegular() {
			return nil, errors.Join(
				fmt.Errorf("runc EROFS mount %s must be a directory or regular file", source),
				cleanup(),
			)
		}
		source, err = filepath.EvalSymlinks(source)
		if err != nil {
			return nil, errors.Join(err, cleanup())
		}
		source, err = filepath.Abs(source)
		if err != nil {
			return nil, errors.Join(err, cleanup())
		}
		if existing, ok := bySource[source]; ok {
			mount.Source = &runtimeapi.Mount_HostPath{HostPath: existing}
			continue
		}
		target := filepath.Join(
			bundlePath,
			runcEROFSMountsDir,
			fmt.Sprintf("%d", index),
			runcEROFSContentDir,
		)
		if err := mountRuncEROFS(source, target, mountEROFS); err != nil {
			return nil, errors.Join(err, cleanup())
		}
		mounted = append(mounted, target)
		bySource[source] = target
		mount.Source = &runtimeapi.Mount_HostPath{HostPath: target}
	}
	return cleanup, nil
}

func runcReadOnlyBindOptions(options []string) []string {
	result := make([]string, 0, len(options)+2)
	for _, option := range options {
		switch {
		case option == "bind", option == "rbind", option == "rw", option == "loop":
			continue
		case strings.HasPrefix(option, "fstype="):
			continue
		default:
			result = append(result, option)
		}
	}
	if !slices.Contains(result, "ro") {
		result = append(result, "ro")
	}
	return append(result, "rbind")
}

func mountRuncEROFS(source, target string, mountEROFS erofsImageMounter) error {
	if err := os.MkdirAll(target, 0755); err != nil {
		return err
	}
	if err := mountEROFS(source, target); err != nil {
		return fmt.Errorf("mount runc EROFS image %s at %s: %w", source, target, err)
	}
	return nil
}

func prepareRuncRootfs(
	sandboxID string,
	bundlePath string,
	storageRoot string,
	spec *Spec,
	mountEROFS erofsImageMounter,
) (_ func() error, retErr error) {
	if spec.Root == nil || spec.Root.Path == "" {
		return nil, fmt.Errorf("runc rootfs path is empty")
	}
	if err := cleanupRuncRootfs(bundlePath); err != nil {
		return nil, fmt.Errorf("clean stale runc rootfs: %w", err)
	}
	lower := spec.Root.Path
	lowerMounted := false
	defer func() {
		if retErr != nil && lowerMounted {
			retErr = errors.Join(retErr, unmountRuncPath(lower))
		}
	}()
	info, err := os.Stat(lower)
	if err != nil {
		return nil, fmt.Errorf("stat runc rootfs %s: %w", lower, err)
	}
	if info.Mode().IsRegular() {
		lower = filepath.Join(bundlePath, runcRootfsLowerDir)
		if err := mountRuncEROFS(spec.Root.Path, lower, mountEROFS); err != nil {
			return nil, err
		}
		lowerMounted = true
	} else if !info.IsDir() {
		return nil, fmt.Errorf("runc rootfs %s must be a directory or regular EROFS image", lower)
	}

	storageDir, err := util.JoinWithinRoot(storageRoot, sandboxID)
	if err != nil {
		return nil, err
	}
	if err := os.RemoveAll(storageDir); err != nil {
		return nil, err
	}
	upper := filepath.Join(storageDir, "upper")
	work := filepath.Join(storageDir, "work")
	target := filepath.Join(bundlePath, runcRootfsDir)
	for _, path := range []string{upper, work, target} {
		if err := os.MkdirAll(path, 0755); err != nil {
			return nil, errors.Join(err, cleanupRuncStorage(storageRoot, sandboxID))
		}
	}
	if err := createRootfsMountTargets(upper, spec.Mounts); err != nil {
		return nil, errors.Join(err, cleanupRuncStorage(storageRoot, sandboxID))
	}
	options := fmt.Sprintf(
		"lowerdir=%s,upperdir=%s,workdir=%s",
		escapeOverlayPath(lower),
		escapeOverlayPath(upper),
		escapeOverlayPath(work),
	)
	if err := syscall.Mount("overlay", target, "overlay", 0, options); err != nil {
		return nil, errors.Join(
			fmt.Errorf("mount runc overlay at %s: %w", target, err),
			cleanupRuncStorage(storageRoot, sandboxID),
		)
	}
	lowerMounted = false
	spec.Root.Path = runcRootfsDir
	if err := writeRuncSpec(bundlePath, spec); err != nil {
		return nil, errors.Join(err, cleanupRuncRootfs(bundlePath), cleanupRuncStorage(storageRoot, sandboxID))
	}
	return func() error {
		return errors.Join(
			cleanupRuncRootfs(bundlePath),
			cleanupRuncStorage(storageRoot, sandboxID),
		)
	}, nil
}

func escapeOverlayPath(path string) string {
	return strings.NewReplacer(
		`\`, `\\`,
		`,`, `\,`,
		`:`, `\:`,
	).Replace(path)
}

func writeRuncSpec(bundlePath string, spec *Spec) error {
	data, err := util.UnescapedMarshal(spec)
	if err != nil {
		return err
	}
	return util.AtomicWriteFile(filepath.Join(bundlePath, config.SandboxSpecFile), data, 0644)
}

func cleanupRuncRootfs(bundlePath string) error {
	var result error
	result = errors.Join(result, unmountRuncPath(filepath.Join(bundlePath, runcRootfsDir)))
	result = errors.Join(result, unmountRuncPath(filepath.Join(bundlePath, runcRootfsLowerDir)))
	if result != nil {
		return result
	}
	for _, name := range []string{runcRootfsDir, runcRootfsLowerDir} {
		result = errors.Join(result, os.RemoveAll(filepath.Join(bundlePath, name)))
	}
	return result
}

func cleanupRuncMounts(bundlePath string) error {
	root := filepath.Join(bundlePath, runcEROFSMountsDir)
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var result error
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		result = errors.Join(
			result,
			unmountRuncPath(filepath.Join(root, entry.Name(), runcEROFSContentDir)),
		)
	}
	if result == nil {
		result = os.RemoveAll(root)
	}
	return result
}

func cleanupRuncStorage(storageRoot, sandboxID string) error {
	if storageRoot == "" {
		return nil
	}
	path, err := util.JoinWithinRoot(storageRoot, sandboxID)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(path); err != nil {
		return fmt.Errorf("remove runc storage %s: %w", path, err)
	}
	return nil
}

var unmountRuncPath = func(target string) error {
	for attempts := 0; attempts < 4; attempts++ {
		err := syscall.Unmount(target, 0)
		switch {
		case err == nil:
			continue
		case errors.Is(err, syscall.EINVAL), errors.Is(err, syscall.ENOENT):
			return nil
		case errors.Is(err, syscall.EBUSY):
			if detachErr := syscall.Unmount(target, syscall.MNT_DETACH); detachErr == nil {
				continue
			} else {
				return errors.Join(err, detachErr)
			}
		default:
			return err
		}
	}
	return fmt.Errorf("unmount %s exceeded retry limit", target)
}
