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
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/inclusionAI/sandboxd/internal/firecrackerproto"
	"github.com/inclusionAI/sandboxd/internal/util"
)

const (
	firecrackerEROFSMagic        = uint32(0xe0f5e1e2)
	firecrackerMaxInjectedFile   = 1 << 20
	firecrackerMaxInjectedTotal  = 4 << 20
	firecrackerMinimumOverlay    = 16 << 20
	firecrackerMaximumDriveCount = 24
)

type firecrackerDrive struct {
	ID       string
	Path     string
	ReadOnly bool
}

type firecrackerStoragePlan struct {
	rootDrive   firecrackerDrive
	mountDrives []firecrackerDrive
	configure   firecrackerproto.ConfigureRequest
}

func prepareFirecrackerStorage(
	spec *Spec,
	startConfig StartConfig,
) (*firecrackerStoragePlan, error) {
	if spec == nil || spec.Root == nil || spec.Root.Path == "" {
		return nil, errors.New("Firecracker rootfs is missing")
	}
	rootPath, err := validateEROFSImage(spec.Root.Path)
	if err != nil {
		return nil, fmt.Errorf("validate Firecracker rootfs: %w", err)
	}
	if spec.Process == nil || len(spec.Process.Args) == 0 {
		return nil, errors.New("Firecracker sandbox process is missing")
	}
	if startConfig.Network == nil ||
		startConfig.Network.Interface == nil ||
		startConfig.Network.Interface.Name == "" {
		return nil, errors.New("Firecracker TAP network is missing")
	}
	if startConfig.Network.EndpointType != "" &&
		startConfig.Network.EndpointType != "tap" {
		return nil, fmt.Errorf(
			"Firecracker requires a TAP endpoint, got %q",
			startConfig.Network.EndpointType,
		)
	}
	guestMAC := startConfig.Network.GuestHardwareAddr()
	if len(guestMAC) == 0 {
		return nil, errors.New("Firecracker guest MAC is missing")
	}
	ip := startConfig.Network.Ip.To4()
	gateway := startConfig.Network.Gateway.To4()
	if ip == nil || gateway == nil || len(startConfig.Network.Mask) != net.IPv4len {
		return nil, errors.New("Firecracker requires complete IPv4 network configuration")
	}

	mounts, err := normalizeFirecrackerMounts(spec.Mounts)
	if err != nil {
		return nil, err
	}
	plan := &firecrackerStoragePlan{
		rootDrive: firecrackerDrive{
			ID:       "rootfs",
			Path:     rootPath,
			ReadOnly: true,
		},
		configure: firecrackerproto.ConfigureRequest{
			Hostname:      spec.Hostname,
			RootDevice:    "/dev/vda",
			OverlayDevice: "/dev/vdb",
			RootReadonly:  spec.Root.Readonly,
			Process: firecrackerproto.ProcessSpec{
				Args:           append([]string(nil), spec.Process.Args...),
				Env:            append([]string(nil), spec.Process.Env...),
				Cwd:            spec.Process.Cwd,
				UID:            spec.Process.User.UID,
				GID:            spec.Process.User.GID,
				AdditionalGIDs: append([]uint32(nil), spec.Process.User.AdditionalGids...),
			},
			Network: firecrackerproto.NetworkSpec{
				Interface: "eth0",
				MAC:       guestMAC.String(),
				Address:   ip.String(),
				Netmask:   net.IP(startConfig.Network.Mask).String(),
				Gateway:   gateway.String(),
			},
		},
	}

	injectedBytes := 0
	for _, mount := range mounts {
		target := filepath.Clean(mount.Destination)
		if skipFirecrackerSystemMount(mount.Type, target) {
			continue
		}
		if !filepath.IsAbs(target) || target == "/" {
			return nil, fmt.Errorf("invalid Firecracker mount target %q", mount.Destination)
		}
		switch strings.ToLower(mount.Type) {
		case "tmpfs":
			options, err := validateFirecrackerTmpfsOptions(mount.Options)
			if err != nil {
				return nil, fmt.Errorf(
					"validate Firecracker tmpfs mount %s: %w",
					target,
					err,
				)
			}
			plan.configure.Mounts = append(
				plan.configure.Mounts,
				firecrackerproto.MountSpec{
					Target: target, FSType: "tmpfs", Options: options,
				},
			)
		case "bind":
			file, size, err := firecrackerInjectedFile(mount)
			if err != nil {
				return nil, err
			}
			injectedBytes += size
			if injectedBytes > firecrackerMaxInjectedTotal {
				return nil, fmt.Errorf(
					"Firecracker injected files exceed %d bytes",
					firecrackerMaxInjectedTotal,
				)
			}
			plan.configure.Files = append(plan.configure.Files, file)
		case "erofs", "rofs":
			source, err := validateEROFSImage(mount.Source)
			if err != nil {
				return nil, fmt.Errorf(
					"validate Firecracker mount %s: %w",
					target,
					err,
				)
			}
			index := len(plan.mountDrives)
			if index+2 >= firecrackerMaximumDriveCount {
				return nil, fmt.Errorf(
					"Firecracker supports at most %d attached drives",
					firecrackerMaximumDriveCount,
				)
			}
			plan.mountDrives = append(plan.mountDrives, firecrackerDrive{
				ID:       fmt.Sprintf("mount_%d", index),
				Path:     source,
				ReadOnly: true,
			})
			plan.configure.Mounts = append(
				plan.configure.Mounts,
				firecrackerproto.MountSpec{
					Device:  firecrackerGuestBlockDevice(index + 2),
					Target:  target,
					FSType:  "erofs",
					Options: firecrackerMountOptions(mount.Options),
				},
			)
		default:
			return nil, fmt.Errorf(
				"Firecracker does not support mount type %q at %s",
				mount.Type,
				target,
			)
		}
	}
	return plan, nil
}

// normalizeFirecrackerMounts applies the OCI mount replacement rule before
// storage is materialized: when multiple mounts address the same canonical
// target, the last entry wins. This is required for managed files such as
// resolv.conf, which intentionally replace an image-provided mount.
func normalizeFirecrackerMounts(mounts []Mount) ([]Mount, error) {
	normalized := make([]Mount, 0, len(mounts))
	seenTargets := make(map[string]struct{}, len(mounts))
	for index := len(mounts) - 1; index >= 0; index-- {
		mount := mounts[index]
		target := filepath.Clean(mount.Destination)
		if !filepath.IsAbs(target) || target == "/" {
			return nil, fmt.Errorf(
				"invalid Firecracker mount target %q",
				mount.Destination,
			)
		}
		if _, exists := seenTargets[target]; exists {
			continue
		}
		seenTargets[target] = struct{}{}
		mount.Destination = target
		normalized = append(normalized, mount)
	}
	slices.Reverse(normalized)
	return normalized, nil
}

func skipFirecrackerSystemMount(mountType, target string) bool {
	switch target {
	case "/dev", "/dev/pts", "/dev/shm", "/proc", "/sys",
		"/sys/fs/cgroup", "/run", "/tmp":
		typeName := strings.ToLower(mountType)
		return typeName != "bind" && typeName != "erofs" && typeName != "rofs"
	}
	return false
}

func validateFirecrackerTmpfsOptions(options []string) ([]string, error) {
	result := make([]string, 0, len(options))
	for _, option := range options {
		switch option {
		case "ro", "rw", "nodev", "dev", "noexec", "exec", "nosuid", "suid":
			result = append(result, option)
		default:
			key, value, found := strings.Cut(option, "=")
			if !found || value == "" {
				return nil, fmt.Errorf("unsupported tmpfs option %q", option)
			}
			switch key {
			case "size", "mode", "uid", "gid", "nr_inodes":
				result = append(result, option)
			default:
				return nil, fmt.Errorf("unsupported tmpfs option %q", option)
			}
		}
	}
	return result, nil
}

func firecrackerInjectedFile(mount Mount) (firecrackerproto.FileSpec, int, error) {
	if mount.Source == "" {
		return firecrackerproto.FileSpec{}, 0, fmt.Errorf(
			"Firecracker bind mount %s has no source",
			mount.Destination,
		)
	}
	if !slices.Contains(mount.Options, "ro") ||
		slices.Contains(mount.Options, "rw") {
		return firecrackerproto.FileSpec{}, 0, fmt.Errorf(
			"Firecracker bind mount %s must be explicitly read-only",
			mount.Destination,
		)
	}
	info, err := os.Stat(mount.Source)
	if err != nil {
		return firecrackerproto.FileSpec{}, 0, err
	}
	if !info.Mode().IsRegular() {
		return firecrackerproto.FileSpec{}, 0, fmt.Errorf(
			"Firecracker only supports regular-file bind injection, got %s",
			mount.Source,
		)
	}
	if info.Size() > firecrackerMaxInjectedFile {
		return firecrackerproto.FileSpec{}, 0, fmt.Errorf(
			"Firecracker bind source %s exceeds %d bytes",
			mount.Source,
			firecrackerMaxInjectedFile,
		)
	}
	content, err := os.ReadFile(mount.Source)
	if err != nil {
		return firecrackerproto.FileSpec{}, 0, err
	}
	return firecrackerproto.FileSpec{
		Target:   mount.Destination,
		Content:  content,
		Mode:     uint32(info.Mode().Perm()),
		Readonly: true,
	}, len(content), nil
}

func firecrackerMountOptions(options []string) []string {
	result := make([]string, 0, len(options)+1)
	for _, option := range options {
		switch option {
		case "rw", "bind", "rbind":
			continue
		case "ro", "loop", "nodev", "noexec", "nosuid":
			if !slices.Contains(result, option) {
				result = append(result, option)
			}
		default:
			result = append(result, option)
		}
	}
	if !slices.Contains(result, "ro") {
		result = append(result, "ro")
	}
	return result
}

func firecrackerGuestBlockDevice(index int) string {
	// Firecracker's virtio-mmio block devices are enumerated in API insertion
	// order. The root image is vda and the writable layer is vdb.
	return fmt.Sprintf("/dev/vd%c", 'a'+index)
}

func validateEROFSImage(path string) (string, error) {
	if path == "" {
		return "", errors.New("EROFS image path is empty")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular EROFS image", resolved)
	}
	file, err := os.Open(resolved)
	if err != nil {
		return "", err
	}
	defer file.Close()
	var magic [4]byte
	if _, err := file.ReadAt(magic[:], 1024); err != nil {
		return "", err
	}
	if binary.LittleEndian.Uint32(magic[:]) != firecrackerEROFSMagic {
		return "", fmt.Errorf("%s does not contain an EROFS superblock", resolved)
	}
	return resolved, nil
}

func createFirecrackerStorageDirectory(
	storageRoot,
	sandboxID string,
) (string, error) {
	directory, err := util.JoinWithinRoot(storageRoot, sandboxID)
	if err != nil {
		return "", err
	}
	if err := os.Mkdir(directory, 0700); err != nil {
		return "", fmt.Errorf(
			"create Firecracker storage directory %s: %w",
			directory,
			err,
		)
	}
	return directory, nil
}

func createFirecrackerOverlay(
	storageRoot,
	sandboxID string,
	size uint64,
) (string, error) {
	if size < firecrackerMinimumOverlay {
		return "", fmt.Errorf(
			"Firecracker writable layer must be at least %d bytes",
			firecrackerMinimumOverlay,
		)
	}
	directory, err := util.JoinWithinRoot(storageRoot, sandboxID)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(directory)
	if err != nil {
		return "", fmt.Errorf("inspect Firecracker storage directory: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf(
			"Firecracker storage path %s is not a directory",
			directory,
		)
	}
	path := filepath.Join(directory, "overlay.ext4")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return "", err
	}
	if err := file.Truncate(int64(size)); err != nil {
		file.Close()
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	output, err := exec.Command(
		"mkfs.ext4",
		"-q",
		"-F",
		"-m", "0",
		path,
	).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("mkfs.ext4 writable layer: %w: %s", err, output)
	}
	return path, nil
}

func cleanupFirecrackerOverlay(storageRoot, sandboxID string) error {
	directory, err := util.JoinWithinRoot(storageRoot, sandboxID)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(directory); err != nil {
		return fmt.Errorf("remove Firecracker writable layer: %w", err)
	}
	return nil
}
