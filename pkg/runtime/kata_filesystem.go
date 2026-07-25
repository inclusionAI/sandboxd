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
	"slices"
	"strings"
	"syscall"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/pkg/loopdevice"
	"google.golang.org/protobuf/proto"
)

const (
	kataRootfsDir      = "rootfs"
	kataRootfsLowerDir = "rootfs-lower"
	kataRootfsUpperDir = "rootfs-upper"
	kataRootfsWorkDir  = "rootfs-work"
	kataEROFSMountDir  = "erofs-mounts"
	kataEROFSLowerDir  = "lower"
	kataEROFSMountType = "erofs"
)

type kataRootfsKind int

const (
	kataRootfsDirectory kataRootfsKind = iota
	kataRootfsEROFS
)

type kataRootfsPlan struct {
	mounts  []*shimMount
	cleanup func() error
}

var mountKataEROFSImage = func(source, target string) error {
	manager, err := loopdevice.New("/dev")
	if err != nil {
		return err
	}
	device, err := manager.AttachReadOnly(source)
	if err != nil {
		return err
	}
	if err := syscall.Mount(
		device.Path(),
		target,
		kataEROFSMountType,
		syscall.MS_RDONLY,
		"",
	); err != nil {
		return errors.Join(
			fmt.Errorf("mount EROFS loop %s at %s: %w", device.Path(), target, err),
			device.Detach(),
		)
	}
	if err := device.Release(); err != nil {
		return errors.Join(
			fmt.Errorf("release mounted EROFS loop %s: %w", device.Path(), err),
			unmountKataMount(target),
		)
	}
	return nil
}

var unmountKataPath = func(target string) error {
	return syscall.Unmount(target, 0)
}

var detachKataPath = func(target string) error {
	return syscall.Unmount(target, syscall.MNT_DETACH)
}

var mountKataOverlay = func(lowerDir, upperDir, workDir, target string) error {
	options := fmt.Sprintf(
		"lowerdir=%s,upperdir=%s,workdir=%s",
		lowerDir,
		upperDir,
		workDir,
	)
	return syscall.Mount("overlay", target, "overlay", 0, options)
}

func cloneKataStartConfig(config StartConfig) StartConfig {
	cloned := config
	if config.Resources != nil {
		cloned.Resources = proto.Clone(config.Resources).(*runtime.LinuxSandboxResources)
	}
	cloned.Mounts = make([]*runtime.Mount, len(config.Mounts))
	for index, mount := range config.Mounts {
		if mount != nil {
			cloned.Mounts[index] = proto.Clone(mount).(*runtime.Mount)
		}
	}
	return cloned
}

func classifyKataRootfs(path string) (kataRootfsKind, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, fmt.Errorf("stat Kata rootfs %s: %w", path, err)
	}
	switch {
	case info.IsDir():
		return kataRootfsDirectory, nil
	case info.Mode().IsRegular():
		return kataRootfsEROFS, nil
	default:
		return 0, fmt.Errorf("Kata rootfs %s must be a directory or regular EROFS image", path)
	}
}

func prepareKataRootfs(
	bundlePath string,
	source string,
	kind kataRootfsKind,
) (*kataRootfsPlan, error) {
	switch kind {
	case kataRootfsDirectory:
		return prepareKataDirectoryRootfs(bundlePath, source)
	case kataRootfsEROFS:
		return prepareKataEROFSRootfs(bundlePath, source)
	default:
		return nil, fmt.Errorf("unsupported Kata rootfs kind %d", kind)
	}
}

func prepareKataDirectoryRootfs(bundlePath, lowerDir string) (*kataRootfsPlan, error) {
	if err := cleanupKataRootfs(bundlePath); err != nil {
		return nil, fmt.Errorf("clean previous Kata rootfs: %w", err)
	}
	return prepareKataOverlayRootfs(bundlePath, lowerDir)
}

func prepareKataOverlayRootfs(bundlePath, lowerDir string) (*kataRootfsPlan, error) {
	rootfsDir := filepath.Join(bundlePath, kataRootfsDir)
	upperDir := filepath.Join(bundlePath, kataRootfsUpperDir)
	workDir := filepath.Join(bundlePath, kataRootfsWorkDir)
	for _, path := range []string{rootfsDir, upperDir, workDir} {
		if err := os.RemoveAll(path); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(path, 0755); err != nil {
			return nil, err
		}
	}

	if err := mountKataOverlay(lowerDir, upperDir, workDir, rootfsDir); err != nil {
		return nil, fmt.Errorf("mount Kata directory rootfs at %s: %w", rootfsDir, err)
	}
	if err := rewriteKataRootPath(bundlePath); err != nil {
		return nil, errors.Join(err, cleanupKataRootfs(bundlePath))
	}

	return &kataRootfsPlan{
		mounts: []*shimMount{{
			Type:    "bind",
			Source:  rootfsDir,
			Target:  "/",
			Options: []string{"rbind", "rw"},
		}},
		cleanup: func() error { return cleanupKataRootfs(bundlePath) },
	}, nil
}

func prepareKataEROFSRootfs(bundlePath, source string) (*kataRootfsPlan, error) {
	if err := cleanupKataRootfs(bundlePath); err != nil {
		return nil, fmt.Errorf("clean previous Kata rootfs: %w", err)
	}
	lowerDir := filepath.Join(bundlePath, kataRootfsLowerDir)
	if err := mountKataEROFSAt(source, lowerDir); err != nil {
		return nil, err
	}
	plan, err := prepareKataOverlayRootfs(bundlePath, lowerDir)
	if err != nil {
		return nil, errors.Join(err, cleanupKataRootfs(bundlePath))
	}
	return plan, nil
}

func rewriteKataRootPath(bundlePath string) error {
	configPath := filepath.Join(bundlePath, "config.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	var ociSpec Spec
	if err := json.Unmarshal(data, &ociSpec); err != nil {
		return err
	}
	if ociSpec.Root == nil {
		ociSpec.Root = &Root{}
	}
	ociSpec.Root.Path = kataRootfsDir
	ociSpec.Root.Readonly = false
	return writeKataSpec(configPath, &ociSpec)
}

func unmountKataRootfs(bundlePath string) error {
	rootfsDir := filepath.Join(bundlePath, kataRootfsDir)
	const maxUnmounts = 16
	for attempts := 0; attempts < maxUnmounts; attempts++ {
		err := unmountKataPath(rootfsDir)
		switch {
		case err == nil:
			continue
		case errors.Is(err, syscall.EINVAL), errors.Is(err, syscall.ENOENT):
			return nil
		case errors.Is(err, syscall.EBUSY):
			if detachErr := detachKataPath(rootfsDir); detachErr == nil {
				continue
			} else {
				return errors.Join(
					fmt.Errorf("unmount Kata rootfs %s: %w", rootfsDir, err),
					fmt.Errorf("detach Kata rootfs %s: %w", rootfsDir, detachErr),
				)
			}
		default:
			return fmt.Errorf("unmount Kata rootfs %s: %w", rootfsDir, err)
		}
	}
	return fmt.Errorf("unmount Kata rootfs %s exceeded %d attempts", rootfsDir, maxUnmounts)
}

func cleanupKataRootfs(bundlePath string) error {
	if err := unmountKataRootfs(bundlePath); err != nil {
		return err
	}
	if err := unmountKataMount(filepath.Join(bundlePath, kataRootfsLowerDir)); err != nil {
		return err
	}
	var result error
	for _, name := range []string{
		kataRootfsDir,
		kataRootfsLowerDir,
		kataRootfsUpperDir,
		kataRootfsWorkDir,
	} {
		path := filepath.Join(bundlePath, name)
		if err := os.RemoveAll(path); err != nil {
			result = errors.Join(result, fmt.Errorf("remove Kata rootfs path %s: %w", path, err))
		}
	}
	return result
}

// prepareKataMounts keeps directory-backed mounts on virtiofs and loop-mounts
// regular EROFS files before exposing them as read-only directories.
func prepareKataMounts(bundlePath string, config *StartConfig) (func() error, error) {
	if err := cleanupKataMounts(bundlePath); err != nil {
		return nil, fmt.Errorf("clean previous Kata EROFS mounts: %w", err)
	}
	mounted := make([]string, 0, len(config.Mounts))
	mountedBySource := make(map[string]string)
	cleanup := func() error {
		var result error
		for index := len(mounted) - 1; index >= 0; index-- {
			result = errors.Join(result, unmountKataMount(mounted[index]))
		}
		if result != nil {
			return result
		}
		mountRoot := filepath.Join(bundlePath, kataEROFSMountDir)
		if err := os.RemoveAll(mountRoot); err != nil {
			return fmt.Errorf("remove Kata EROFS mount directory %s: %w", mountRoot, err)
		}
		return nil
	}

	for index, mount := range config.Mounts {
		if mount == nil || mount.GetType() != kataEROFSMountType {
			continue
		}
		source := mount.GetHostPath()
		if source == "" {
			return nil, errors.Join(
				fmt.Errorf("Kata EROFS mount %s has no host path", mount.GetTarget()),
				cleanup(),
			)
		}
		info, err := os.Stat(source)
		if err != nil {
			return nil, errors.Join(
				fmt.Errorf("stat Kata EROFS mount %s: %w", source, err),
				cleanup(),
			)
		}

		mount.Type = "bind"
		mount.Options = kataReadOnlyBindOptions(mount.GetOptions())
		if info.IsDir() {
			continue
		}
		if !info.Mode().IsRegular() {
			return nil, errors.Join(
				fmt.Errorf("Kata EROFS mount %s must be a directory or regular file", source),
				cleanup(),
			)
		}
		source, err = filepath.EvalSymlinks(source)
		if err != nil {
			return nil, errors.Join(
				fmt.Errorf("resolve Kata EROFS mount %s: %w", source, err),
				cleanup(),
			)
		}
		source, err = filepath.Abs(source)
		if err != nil {
			return nil, errors.Join(
				fmt.Errorf("resolve absolute Kata EROFS mount %s: %w", source, err),
				cleanup(),
			)
		}
		if lowerDir, ok := mountedBySource[source]; ok {
			mount.Source = &runtime.Mount_HostPath{HostPath: lowerDir}
			continue
		}

		mountDir := filepath.Join(bundlePath, kataEROFSMountDir, fmt.Sprintf("%d", index))
		lowerDir := filepath.Join(mountDir, kataEROFSLowerDir)
		if err := mountKataEROFSAt(source, lowerDir); err != nil {
			return nil, errors.Join(err, cleanup())
		}
		mounted = append(mounted, lowerDir)
		mountedBySource[source] = lowerDir
		mount.Source = &runtime.Mount_HostPath{HostPath: lowerDir}
	}

	return cleanup, nil
}

func kataReadOnlyBindOptions(options []string) []string {
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

func mountKataEROFSAt(source, target string) error {
	if err := os.RemoveAll(target); err != nil {
		return err
	}
	if err := os.MkdirAll(target, 0755); err != nil {
		return err
	}
	// TODO: Remove this host loop-mount fallback once Kata Containers
	// reliably supports EROFS rootfs images and mounts as direct volumes.
	if err := mountKataEROFSImage(source, target); err != nil {
		return errors.Join(err, os.RemoveAll(target))
	}
	return nil
}

func cleanupKataMounts(bundlePath string) error {
	mountRoot := filepath.Join(bundlePath, kataEROFSMountDir)
	entries, err := os.ReadDir(mountRoot)
	var result error
	if err == nil {
		for index := len(entries) - 1; index >= 0; index-- {
			mountDir := filepath.Join(mountRoot, entries[index].Name())
			result = errors.Join(
				result,
				unmountKataMount(filepath.Join(mountDir, kataEROFSLowerDir)),
			)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("read Kata EROFS mount directory %s: %w", mountRoot, err)
	}
	if result != nil {
		return result
	}
	if err := os.RemoveAll(mountRoot); err != nil {
		return fmt.Errorf("remove Kata EROFS mount directory %s: %w", mountRoot, err)
	}
	return nil
}

func unmountKataMount(target string) error {
	err := unmountKataPath(target)
	if err == nil || errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOENT) {
		return nil
	}
	if errors.Is(err, syscall.EBUSY) {
		if detachErr := detachKataPath(target); detachErr == nil {
			return nil
		} else {
			return errors.Join(
				fmt.Errorf("unmount Kata EROFS input %s: %w", target, err),
				fmt.Errorf("detach Kata EROFS input %s: %w", target, detachErr),
			)
		}
	}
	return fmt.Errorf("unmount Kata EROFS input %s: %w", target, err)
}

func writeKataSpec(path string, spec *Spec) error {
	data, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return err
	}
	temporaryPath := path + ".tmp"
	if err := os.WriteFile(temporaryPath, data, 0644); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}
