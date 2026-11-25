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

//go:build linux

package oci

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

var (
	errStructuredOverlayUnavailable = errors.New("structured OverlayFS options unavailable")
	errOverlayMountInfoLimit        = errors.New("ordered lowerdirs exceed the supported mountinfo line limit")
)

func mountReadonlyOverlay(target string, lowerDirs []string, compactData func(int) (string, error)) error {
	return mountReadonlyOverlayWith(target, lowerDirs, os.Getpagesize(), func(target, data string) error {
		if err := checkOverlayMountInfoSize(target, len(mountInfoEscape.Replace(data))); err != nil {
			return err
		}
		// A lower-only overlay is read-only. Some kernels reject MS_RDONLY
		// on the legacy path.
		return unix.Mount("overlay", target, "overlay", 0, data)
	}, mountReadonlyOverlayLayers, compactData)
}

func mountReadonlyOverlayWith(
	target string,
	lowerDirs []string,
	pageSize int,
	mountLegacy func(string, string) error,
	mountLayers func(string, []string) error,
	compactData func(int) (string, error),
) error {
	data, err := buildOverlayMountData(lowerDirs)
	if err != nil {
		return err
	}
	// The kernel terminates the copied page, leaving at most PAGE_SIZE-1
	// bytes of mount data. Check bytes after escaping delimiters.
	if len(data) < pageSize {
		return mountLegacy(target, data)
	}
	if err := mountLayers(target, lowerDirs); err != nil {
		structuredErr := fmt.Errorf("overlay options use %d bytes, exceeding the legacy mount limit of %d bytes for %d layers: %w",
			len(data), pageSize-1, len(lowerDirs), err)
		canCompact := errors.Is(err, errStructuredOverlayUnavailable) || errors.Is(err, errOverlayMountInfoLimit)
		if compactData == nil || !canCompact {
			return structuredErr
		}
		data, err := compactData(pageSize - 1)
		if err == nil {
			if err := mountLegacy(target, data); err != nil {
				return fmt.Errorf("%w (mount compact lowerdirs using %d of %d bytes: %w)", structuredErr, len(data), pageSize-1, err)
			}
			return nil
		}
		return fmt.Errorf("%w (prepare compact lowerdirs: %w)", structuredErr, err)
	}
	return nil
}

func mountReadonlyOverlayLayers(target string, lowerDirs []string) error {
	optionsBytes := 0
	for _, dir := range lowerDirs {
		optionsBytes += len(",lowerdir+=") + len(mountInfoEscapeWithColon.Replace(dir))
	}
	if err := checkOverlayMountInfoSize(target, optionsBytes); err != nil {
		return err
	}

	fsFD, err := unix.Fsopen("overlay", unix.FSOPEN_CLOEXEC)
	if err != nil {
		err = fmt.Errorf("open overlay filesystem context: %w", err)
		if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EOPNOTSUPP) {
			return fmt.Errorf("%w: %w", errStructuredOverlayUnavailable, err)
		}
		return err
	}
	defer unix.Close(fsFD)
	if err := unix.FsconfigSetFlag(fsFD, "ro"); err != nil {
		return overlayContextError(fsFD, "configure overlay read-only", err)
	}
	for i, dir := range lowerDirs {
		if err := unix.FsconfigSetString(fsFD, "lowerdir+", dir); err != nil {
			step := fmt.Sprintf("configure overlay lowerdir+ layer %d of %d (path is %d bytes)", i+1, len(lowerDirs), len(dir))
			return overlayContextError(fsFD, step, err)
		}
	}
	if err := unix.FsconfigCreate(fsFD); err != nil {
		step := fmt.Sprintf("create overlay from all %d lowerdir+ layers", len(lowerDirs))
		return overlayContextError(fsFD, step, err)
	}
	mountFD, err := unix.Fsmount(fsFD, unix.FSMOUNT_CLOEXEC, unix.MOUNT_ATTR_RDONLY)
	if err != nil {
		return fmt.Errorf("open detached read-only overlay mount: %w", err)
	}
	defer unix.Close(mountFD)
	if err := unix.MoveMount(mountFD, "", unix.AT_FDCWD, target, unix.MOVE_MOUNT_F_EMPTY_PATH); err != nil {
		return fmt.Errorf("attach ordered overlay mount: %w", err)
	}
	return nil
}

func overlayContextError(fd int, step string, cause error) error {
	var buf [4096]byte
	var messages []string
	for range 16 {
		n, err := unix.Read(fd, buf[:])
		if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EMSGSIZE) {
			continue
		}
		if err != nil || n == 0 {
			break
		}
		messages = append(messages, strings.TrimSpace(string(buf[:n])))
	}
	// Older implementations reject lowerdir+ while setting parameters or
	// when creating the filesystem. Some report only EINVAL. Retry the same
	// layers through the legacy representation before attaching any mount.
	if errors.Is(cause, unix.EINVAL) || errors.Is(cause, unix.ENAMETOOLONG) ||
		errors.Is(cause, unix.ENOSYS) || errors.Is(cause, unix.EOPNOTSUPP) {
		cause = fmt.Errorf("%w: %w", errStructuredOverlayUnavailable, cause)
	}
	if len(messages) > 0 {
		return fmt.Errorf("%s: %w (%s)", step, cause, strings.Join(messages, "; "))
	}
	return fmt.Errorf("%s: %w", step, cause)
}

func checkOverlayMountInfoSize(target string, optionsBytes int) error {
	// Keep the attached mount readable by mountinfo consumers that use the
	// default Scanner token size, including the node's cgroup discovery.
	resolvedTarget, err := absoluteMountPath(target)
	if err != nil {
		return fmt.Errorf("resolve overlay mount target: %w", err)
	}
	const mountInfoOverhead = 1024 // Fixed fields, mount IDs and optional flags.
	if len(mountInfoEscape.Replace(resolvedTarget))+mountInfoOverhead+optionsBytes >= bufio.MaxScanTokenSize {
		return fmt.Errorf("%w of %d bytes", errOverlayMountInfoLimit, bufio.MaxScanTokenSize-1)
	}
	return nil
}

func mountReadonlyBind(source, target string) error {
	if err := unix.Mount(source, target, "", uintptr(unix.MS_BIND), ""); err != nil {
		return err
	}
	return unix.Mount("", target, "", uintptr(unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY), "")
}

func unmountOverlay(target string) error {
	return unix.Unmount(target, 0)
}
