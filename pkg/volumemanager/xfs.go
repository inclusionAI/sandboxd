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

// Package volumemanager owns the shared loop-backed filestore. ext4 is the
// default bounded filesystem; XFS is optional when reflink is required.
package volumemanager

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/inclusionAI/sandboxd/pkg/loopdevice"
)

type mountedFilesystemInfo struct {
	fsType string
	source string
}

func unescapeMountInfoPath(path string) string {
	replacer := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	return replacer.Replace(path)
}

func mountedFilesystem(dir string) (mountedFilesystemInfo, error) {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return mountedFilesystemInfo{}, fmt.Errorf("read /proc/self/mountinfo: %v", err)
	}
	return parseMountedFilesystem(data, dir), nil
}

func parseMountedFilesystem(data []byte, dir string) mountedFilesystemInfo {
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, " - ", 2)
		if len(parts) != 2 {
			continue
		}
		left, right := strings.Fields(parts[0]), strings.Fields(parts[1])
		if len(left) >= 5 && len(right) >= 2 && unescapeMountInfoPath(left[4]) == dir {
			return mountedFilesystemInfo{fsType: right[0], source: unescapeMountInfoPath(right[1])}
		}
	}
	return mountedFilesystemInfo{}
}

// IsXFSMounted reports whether dir is currently mounted as XFS.
func IsXFSMounted(dir string) (bool, error) {
	info, err := mountedFilesystem(dir)
	return info.fsType == "xfs", err
}

func filestoreFSType(xfsEnabled bool) string {
	if xfsEnabled {
		return "xfs"
	}
	return "ext4"
}

func filestoreImagePath(filestoreDir string, xfsEnabled bool) string {
	return filepath.Join(filepath.Dir(filestoreDir), filestoreFSType(xfsEnabled)+".img")
}

func ensureFilestoreMount(filestoreDir, size string, xfsEnabled bool, loops *loopdevice.Manager) (*loopdevice.Device, error) {
	if err := os.MkdirAll(filestoreDir, 0755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %v", filestoreDir, err)
	}
	fsType := filestoreFSType(xfsEnabled)
	imgFile := filestoreImagePath(filestoreDir, xfsEnabled)
	mounted, err := mountedFilesystem(filestoreDir)
	if err != nil {
		return nil, err
	}
	if mounted.fsType == fsType {
		device, err := loops.Adopt(mounted.source, imgFile, false)
		if err != nil {
			return nil, fmt.Errorf("recover mounted filestore: %w", err)
		}
		return device, nil
	}
	if mounted.fsType != "" {
		return nil, fmt.Errorf("%s is mounted as %s from %s, want %s", filestoreDir, mounted.fsType, mounted.source, fsType)
	}
	if err := os.Remove(imgFile); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("remove stale filestore image %s: %w", imgFile, err)
	}
	if out, err := exec.Command("truncate", "-s", size, imgFile).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("truncate %s: %s: %v", imgFile, out, err)
	}
	if err := formatFilestoreImage(imgFile, xfsEnabled); err != nil {
		_ = os.Remove(imgFile)
		return nil, err
	}
	device, err := loops.AttachWritable(imgFile)
	if err != nil {
		_ = os.Remove(imgFile)
		return nil, err
	}
	if out, err := exec.Command("mount", "-t", fsType, "-o", "defaults,discard", "--", device.Path(), filestoreDir).CombinedOutput(); err != nil {
		_ = device.Detach()
		_ = os.Remove(imgFile)
		return nil, fmt.Errorf("mount %s %s (%s) -> %s: %s: %v", fsType, imgFile, device.Path(), filestoreDir, out, err)
	}
	return device, nil
}

// EnsureFilestoreMount creates a bounded filestore in the default /dev loop namespace.
func EnsureFilestoreMount(filestoreDir, size string, xfsEnabled bool) error {
	loops, err := loopdevice.New("/dev")
	if err != nil {
		return err
	}
	device, err := ensureFilestoreMount(filestoreDir, size, xfsEnabled, loops)
	if err != nil {
		return err
	}
	return device.Release()
}

func formatFilestoreImage(imgFile string, xfsEnabled bool) error {
	if !xfsEnabled {
		out, err := exec.Command("mkfs.ext4", "-q", "-F", imgFile).CombinedOutput()
		if err != nil {
			return fmt.Errorf("mkfs.ext4: %s: %v", out, err)
		}
		return nil
	}
	out, err := exec.Command("mkfs.xfs", "-f", "-m", "reflink=1", "-i", "nrext64=0", imgFile).CombinedOutput()
	if err == nil {
		return nil
	}
	if strings.Contains(string(out), "unknown option") && strings.Contains(string(out), "nrext64") {
		out, err = exec.Command("mkfs.xfs", "-f", "-m", "reflink=1", imgFile).CombinedOutput()
	}
	if err != nil {
		return fmt.Errorf("mkfs.xfs: %s: %v", out, err)
	}
	return nil
}

func cleanupFilestoreMount(filestoreDir string, xfsEnabled bool, device *loopdevice.Device) error {
	if filestoreDir == "" {
		return nil
	}
	fsType := filestoreFSType(xfsEnabled)
	mounted, err := mountedFilesystem(filestoreDir)
	if err != nil {
		return err
	}
	if mounted.fsType == "" {
		if device != nil {
			if err := device.Detach(); err != nil {
				return fmt.Errorf("detach unmounted filestore loop %s: %w", device.Path(), err)
			}
		}
	} else if mounted.fsType != fsType {
		return fmt.Errorf("%s is mounted as %s, want %s", filestoreDir, mounted.fsType, fsType)
	} else {
		if out, err := exec.Command("umount", filestoreDir).CombinedOutput(); err != nil {
			return fmt.Errorf("umount %s: %s: %v", filestoreDir, out, err)
		}
		if device != nil {
			if err := device.Detach(); err != nil && !errors.Is(err, syscall.ENXIO) {
				return fmt.Errorf("detach filestore loop %s: %w", device.Path(), err)
			}
		}
	}
	if err := os.Remove(filestoreImagePath(filestoreDir, xfsEnabled)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove filestore image: %w", err)
	}
	if err := os.Remove(filestoreDir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove filestore mountpoint: %w", err)
	}
	return nil
}

// CleanupFilestoreMount tears down a bounded filestore.
func CleanupFilestoreMount(filestoreDir string, xfsEnabled bool) error {
	return cleanupFilestoreMount(filestoreDir, xfsEnabled, nil)
}

// EnsureXFSMount and CleanupXFSMount retain the previous public API.
func EnsureXFSMount(filestoreDir, size string) error {
	return EnsureFilestoreMount(filestoreDir, size, true)
}

func CleanupXFSMount(filestoreDir string) error {
	return CleanupFilestoreMount(filestoreDir, true)
}
