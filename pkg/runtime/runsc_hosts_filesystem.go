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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	runscHostsRootfsDir     = "hosts-rootfs"
	runscHostsProjectionDir = "hosts-projection"
)

var mountRunscHostsOverlay = func(projectionDir, lowerDir, target string) error {
	options := fmt.Sprintf("lowerdir=%s:%s", projectionDir, lowerDir)
	return syscall.Mount("overlay", target, "overlay", 0, options)
}

var unmountRunscHostsPath = func(target string, flags int) error {
	return syscall.Unmount(target, flags)
}

// prepareRunscHostsRootfs creates a private read-only view only when the image
// does not already contain a regular /etc/hosts bind-mount target. It never
// modifies the shared image-manager rootfs.
func prepareRunscHostsRootfs(bundlePath string, spec *Spec) (func() error, error) {
	if spec == nil || spec.Root == nil || spec.Root.Path == "" {
		return nil, errors.New("runsc hosts preparation requires a root filesystem")
	}
	needsProjection, err := runscHostsTargetNeedsProjection(bundlePath, spec)
	if err != nil || !needsProjection {
		return nil, err
	}
	if err := cleanupRunscHostsRootfs(bundlePath); err != nil {
		return nil, fmt.Errorf("clean previous runsc hosts rootfs: %w", err)
	}

	lowerDir := spec.Root.Path
	if !filepath.IsAbs(lowerDir) {
		lowerDir = filepath.Join(bundlePath, lowerDir)
	}
	info, err := os.Stat(lowerDir)
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf("stat runsc rootfs %s: %w", lowerDir, err),
			cleanupRunscHostsRootfs(bundlePath),
		)
	}
	if !info.IsDir() {
		return nil, errors.Join(
			fmt.Errorf("runsc rootfs %s must be a directory", lowerDir),
			cleanupRunscHostsRootfs(bundlePath),
		)
	}

	rootfsDir := filepath.Join(bundlePath, runscHostsRootfsDir)
	projectionDir := filepath.Join(bundlePath, runscHostsProjectionDir)
	for _, target := range []string{rootfsDir, projectionDir} {
		if err := os.MkdirAll(target, 0755); err != nil {
			return nil, errors.Join(err, cleanupRunscHostsRootfs(bundlePath))
		}
	}
	if err := seedRunscHostsTarget(lowerDir, projectionDir); err != nil {
		return nil, errors.Join(err, cleanupRunscHostsRootfs(bundlePath))
	}
	// The projection directory is the highest-precedence lower layer. Preserve
	// root metadata so adding /etc/hosts does not change image-visible metadata.
	if err := copyRunscHostsDirectoryMetadata(lowerDir, projectionDir, info); err != nil {
		return nil, errors.Join(
			fmt.Errorf("preserve effective rootfs metadata: %w", err),
			cleanupRunscHostsRootfs(bundlePath),
		)
	}
	if err := validateRunscHostsOverlayPaths(projectionDir, lowerDir); err != nil {
		return nil, errors.Join(err, cleanupRunscHostsRootfs(bundlePath))
	}
	if err := mountRunscHostsOverlay(projectionDir, lowerDir, rootfsDir); err != nil {
		return nil, errors.Join(
			fmt.Errorf("mount runsc hosts rootfs at %s: %w", rootfsDir, err),
			cleanupRunscHostsRootfs(bundlePath),
		)
	}

	spec.Root.Path = runscHostsRootfsDir
	if err := writeRunscHostsSpec(filepath.Join(bundlePath, "config.json"), spec); err != nil {
		return nil, errors.Join(err, cleanupRunscHostsRootfs(bundlePath))
	}
	return func() error { return cleanupRunscHostsRootfs(bundlePath) }, nil
}

// prepareRunscGeneratedHostsTarget adds the generated bind-mount target to an
// existing private upper directory. Callers that do not have the generated
// hosts mount are a strict no-op.
func prepareRunscGeneratedHostsTarget(bundlePath string, spec *Spec, lowerDir, upperDir string) error {
	if !hasGeneratedRunscHostsMount(bundlePath, spec) {
		return nil
	}
	needsTarget, err := runscHostsTargetNeedsProjectionInRoot(lowerDir)
	if err != nil || !needsTarget {
		return err
	}
	return seedRunscHostsTarget(lowerDir, upperDir)
}

func runscHostsTargetNeedsProjection(bundlePath string, spec *Spec) (bool, error) {
	if !hasGeneratedRunscHostsMount(bundlePath, spec) {
		return false, nil
	}
	// EROFS annotations use a bundle-local placeholder. The annotation loader
	// creates bind-mount targets in that placeholder from spec.Mounts.
	if runscHostsUsesEROFSImage(spec) {
		return false, nil
	}
	rootfs := spec.Root.Path
	if !filepath.IsAbs(rootfs) {
		rootfs = filepath.Join(bundlePath, rootfs)
	}
	return runscHostsTargetNeedsProjectionInRoot(rootfs)
}

func runscHostsUsesEROFSImage(spec *Spec) bool {
	return spec != nil && spec.Annotations != nil &&
		spec.Annotations[gvisorRootfsAnnotationPrefix+"type"] == gvisorRootfsTypeEROFS &&
		spec.Annotations[gvisorRootfsAnnotationPrefix+"source"] != ""
}

func runscHostsTargetNeedsProjectionInRoot(rootfs string) (bool, error) {
	etcInfo, err := os.Lstat(filepath.Join(rootfs, "etc"))
	switch {
	case err == nil && !etcInfo.IsDir():
		return false, fmt.Errorf("runsc rootfs /etc must be a directory, got %s", etcInfo.Mode())
	case err != nil && !errors.Is(err, os.ErrNotExist):
		return false, fmt.Errorf("inspect runsc rootfs /etc: %w", err)
	case errors.Is(err, os.ErrNotExist):
		return true, nil
	}

	hostsInfo, err := os.Lstat(filepath.Join(rootfs, "etc", "hosts"))
	switch {
	case err == nil:
		return !hostsInfo.Mode().IsRegular(), nil
	case errors.Is(err, os.ErrNotExist):
		return true, nil
	default:
		return false, fmt.Errorf("inspect runsc rootfs /etc/hosts: %w", err)
	}
}

func hasGeneratedRunscHostsMount(bundlePath string, spec *Spec) bool {
	if spec == nil {
		return false
	}
	generatedHosts := filepath.Clean(filepath.Join(bundlePath, "hosts"))
	for _, mount := range spec.Mounts {
		if path.Clean(mount.Destination) == "/etc/hosts" &&
			mount.Type == "bind" &&
			filepath.Clean(mount.Source) == generatedHosts {
			return true
		}
	}
	return false
}

func seedRunscHostsTarget(lowerDir, upperDir string) error {
	lowerEtc := filepath.Join(lowerDir, "etc")
	upperEtc := filepath.Join(upperDir, "etc")
	info, err := os.Lstat(lowerEtc)
	switch {
	case err == nil:
		if !info.IsDir() {
			return fmt.Errorf("runsc rootfs /etc must be a directory, got %s", info.Mode())
		}
		if err := os.Mkdir(upperEtc, info.Mode().Perm()); err != nil {
			return fmt.Errorf("create projected /etc: %w", err)
		}
	case errors.Is(err, os.ErrNotExist):
		if err := os.Mkdir(upperEtc, 0755); err != nil {
			return fmt.Errorf("create projected /etc: %w", err)
		}
		info = nil
	default:
		return fmt.Errorf("inspect effective rootfs /etc metadata: %w", err)
	}

	hosts, err := os.OpenFile(filepath.Join(upperEtc, "hosts"), os.O_CREATE|os.O_EXCL|os.O_RDONLY, 0644)
	if err != nil {
		return fmt.Errorf("create projected /etc/hosts target: %w", err)
	}
	if err := hosts.Close(); err != nil {
		return fmt.Errorf("close projected /etc/hosts target: %w", err)
	}
	if info != nil {
		if err := copyRunscHostsDirectoryMetadata(lowerEtc, upperEtc, info); err != nil {
			return fmt.Errorf("preserve effective /etc metadata: %w", err)
		}
	}
	return nil
}

func copyRunscHostsDirectoryMetadata(source, target string, info os.FileInfo) error {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		if err := os.Lchown(target, int(stat.Uid), int(stat.Gid)); err != nil {
			return err
		}
	}
	mode := info.Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
	if err := os.Chmod(target, mode); err != nil {
		return err
	}
	if err := copyRunscHostsXattrs(source, target); err != nil {
		return err
	}
	mtime := info.ModTime()
	return os.Chtimes(target, mtime, mtime)
}

func copyRunscHostsXattrs(source, target string) error {
	names, err := listRunscHostsXattrs(source)
	if err != nil {
		if isIgnorableRunscHostsXattrError(err) {
			return nil
		}
		return err
	}
	for _, name := range names {
		if strings.HasPrefix(name, "trusted.overlay.") || strings.HasPrefix(name, "user.overlay.") {
			continue
		}
		value, err := getRunscHostsXattr(source, name)
		if err != nil {
			if isIgnorableRunscHostsXattrError(err) {
				continue
			}
			return err
		}
		if err := unix.Setxattr(target, name, value, 0); err != nil &&
			!isIgnorableRunscHostsXattrError(err) {
			return err
		}
	}
	return nil
}

func listRunscHostsXattrs(target string) ([]string, error) {
	size, err := unix.Listxattr(target, nil)
	if err != nil || size == 0 {
		return nil, err
	}
	buf := make([]byte, size)
	size, err = unix.Listxattr(target, buf)
	if err != nil {
		return nil, err
	}
	return splitRunscHostsXattrNames(buf[:size]), nil
}

func getRunscHostsXattr(target, name string) ([]byte, error) {
	size, err := unix.Getxattr(target, name, nil)
	if err != nil {
		return nil, err
	}
	if size == 0 {
		return []byte{}, nil
	}
	buf := make([]byte, size)
	size, err = unix.Getxattr(target, name, buf)
	if err != nil {
		return nil, err
	}
	return buf[:size], nil
}

func splitRunscHostsXattrNames(buf []byte) []string {
	names := make([]string, 0, 4)
	for len(buf) > 0 {
		index := bytes.IndexByte(buf, 0)
		if index < 0 {
			if len(buf) > 0 {
				names = append(names, string(buf))
			}
			break
		}
		if index > 0 {
			names = append(names, string(buf[:index]))
		}
		buf = buf[index+1:]
	}
	return names
}

func isIgnorableRunscHostsXattrError(err error) bool {
	return errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, unix.EPERM) || errors.Is(err, unix.ENODATA)
}

func validateRunscHostsOverlayPaths(paths ...string) error {
	for _, value := range paths {
		if strings.ContainsAny(value, ",:\\") {
			return fmt.Errorf("runsc hosts overlay path %q contains an unsupported mount-option character", value)
		}
	}
	return nil
}

func cleanupRunscHostsRootfs(bundlePath string) error {
	rootfsDir := filepath.Join(bundlePath, runscHostsRootfsDir)
	projectionDir := filepath.Join(bundlePath, runscHostsProjectionDir)
	hasHostsPaths := false
	for _, target := range []string{rootfsDir, projectionDir} {
		if _, err := os.Lstat(target); err == nil {
			hasHostsPaths = true
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect runsc hosts rootfs path %s: %w", target, err)
		}
	}
	if !hasHostsPaths {
		return nil
	}
	if err := unmountRunscHostsMount(rootfsDir); err != nil {
		return err
	}
	var result error
	for _, target := range []string{rootfsDir, projectionDir} {
		if err := os.RemoveAll(target); err != nil {
			result = errors.Join(result, fmt.Errorf("remove runsc hosts rootfs path %s: %w", target, err))
		}
	}
	return result
}

func unmountRunscHostsMount(target string) error {
	if err := unmountRunscHostsPath(target, 0); err != nil &&
		!errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.ENOENT) {
		if !errors.Is(err, syscall.EBUSY) {
			return fmt.Errorf("unmount runsc hosts rootfs %s: %w", target, err)
		}
		if detachErr := unmountRunscHostsPath(target, syscall.MNT_DETACH); detachErr != nil {
			return errors.Join(
				fmt.Errorf("unmount runsc hosts rootfs %s: %w", target, err),
				fmt.Errorf("detach runsc hosts rootfs %s: %w", target, detachErr),
			)
		}
	}
	return nil
}

func writeRunscHostsSpec(target string, spec *Spec) error {
	data, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(target), ".hosts-config-")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()
	if err := tmp.Chmod(0644); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, target)
}
