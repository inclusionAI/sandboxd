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

package firecracker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	firecrackerVirtioFSSharedDir = "virtiofs"
	firecrackerVirtioFSMemory    = "memory.live"
	firecrackerVirtioFSStartup   = 15 * time.Second
)

type firecrackerVirtioFSState struct {
	PID        int    `json:"pid"`
	SocketPath string `json:"socket_path"`
	SharedDir  string `json:"shared_dir"`
}

func virtioFSSocketPathIfConfigured(state *firecrackerVirtioFSState) string {
	if state == nil {
		return ""
	}
	return state.SocketPath
}

func prepareFirecrackerVirtioFSShared(
	sharedDir string,
	exports []firecrackerVirtioFSExport,
) (retErr error) {
	if len(exports) == 0 {
		return errors.New("virtio-fs export list is empty")
	}
	if err := os.Mkdir(sharedDir, 0700); err != nil {
		return fmt.Errorf("create virtio-fs shared directory: %w", err)
	}
	mounted := false
	defer func() {
		if retErr == nil {
			return
		}
		if mounted {
			unmountErr := unmountFirecrackerVirtioFSShared(sharedDir)
			retErr = errors.Join(retErr, unmountErr)
			if unmountErr != nil {
				return
			}
		}
		retErr = errors.Join(retErr, os.RemoveAll(sharedDir))
	}()
	if err := unix.Mount(
		"tmpfs",
		sharedDir,
		"tmpfs",
		unix.MS_NOSUID|unix.MS_NODEV,
		"mode=0700,size=1m",
	); err != nil {
		return fmt.Errorf("mount virtio-fs staging tmpfs: %w", err)
	}
	mounted = true
	if err := unix.Mount("", sharedDir, "", unix.MS_PRIVATE|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("make virtio-fs staging mount private: %w", err)
	}

	seen := make(map[string]struct{}, len(exports))
	for _, export := range exports {
		target, err := firecrackerVirtioFSExportPath(sharedDir, export.RelativePath)
		if err != nil {
			return err
		}
		if _, exists := seen[target]; exists {
			return fmt.Errorf("duplicate virtio-fs export path %q", export.RelativePath)
		}
		seen[target] = struct{}{}
		source, err := validateFirecrackerDirectory(export.Source)
		if err != nil {
			return fmt.Errorf("validate virtio-fs export %s: %w", export.Source, err)
		}
		if err := os.MkdirAll(target, 0700); err != nil {
			return fmt.Errorf("create virtio-fs export target %s: %w", target, err)
		}
		if err := unix.Mount(source, target, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
			return fmt.Errorf("bind virtio-fs export %s: %w", source, err)
		}
		if err := unix.Mount(
			"",
			target,
			"",
			unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NODEV,
			"",
		); err != nil {
			return fmt.Errorf("remount virtio-fs export %s read-only: %w", source, err)
		}
	}
	return nil
}

func firecrackerVirtioFSExportPath(root, relative string) (string, error) {
	if relative == "" || filepath.IsAbs(relative) {
		return "", fmt.Errorf("invalid virtio-fs export path %q", relative)
	}
	clean := filepath.Clean(relative)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("virtio-fs export path %q escapes its root", relative)
	}
	target := filepath.Join(root, clean)
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return "", fmt.Errorf("virtio-fs export path %q escapes its root", relative)
	}
	return target, nil
}

func startFirecrackerVirtioFS(
	ctx context.Context,
	binary,
	sharedDir,
	socketPath string,
	stdout,
	stderr io.Writer,
) (*firecrackerVirtioFSState, *exec.Cmd, error) {
	if err := removeFirecrackerSocket(socketPath); err != nil {
		return nil, nil, err
	}
	command := exec.Command(
		binary,
		"--shared-dir", sharedDir,
		"--socket-path", socketPath,
		"--readonly",
		"--no-announce-submounts",
		"--sandbox", "namespace",
		"--inode-file-handles=never",
		"--migration-mode", "find-paths",
		"--migration-on-error", "abort",
	)
	command.Stdout = stdout
	command.Stderr = stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		return nil, nil, fmt.Errorf("start virtiofsd: %w", err)
	}
	waitCtx, cancel := context.WithTimeout(ctx, firecrackerVirtioFSStartup)
	defer cancel()
	state := &firecrackerVirtioFSState{
		PID:        command.Process.Pid,
		SocketPath: socketPath,
		SharedDir:  sharedDir,
	}
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		info, err := os.Lstat(socketPath)
		if err == nil && info.Mode()&os.ModeSocket != 0 {
			return state, command, nil
		}
		if !firecrackerVirtioFSProcessMatches(state, binary) {
			_ = command.Wait()
			return nil, nil, errors.New("virtiofsd exited before creating its socket")
		}
		select {
		case <-waitCtx.Done():
			_ = signalFirecrackerVirtioFS(state, binary, syscall.SIGKILL)
			_ = command.Wait()
			return nil, nil, fmt.Errorf("wait for virtiofsd socket: %w", waitCtx.Err())
		case <-ticker.C:
		}
	}
}

func stopFirecrackerVirtioFS(state *firecrackerVirtioFSState, binary string) {
	if state == nil || !firecrackerVirtioFSProcessMatches(state, binary) {
		return
	}
	_ = signalFirecrackerVirtioFS(state, binary, syscall.SIGTERM)
	if waitFirecrackerVirtioFS(state, binary, 500*time.Millisecond) {
		return
	}
	_ = signalFirecrackerVirtioFS(state, binary, syscall.SIGKILL)
	_ = waitFirecrackerVirtioFS(state, binary, time.Second)
}

func waitFirecrackerVirtioFS(
	state *firecrackerVirtioFSState,
	binary string,
	timeout time.Duration,
) bool {
	deadline := time.Now().Add(timeout)
	for {
		if !firecrackerVirtioFSProcessMatches(state, binary) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func signalFirecrackerVirtioFS(
	state *firecrackerVirtioFSState,
	binary string,
	signal syscall.Signal,
) error {
	if !firecrackerVirtioFSProcessMatches(state, binary) {
		return nil
	}
	group, err := syscall.Getpgid(state.PID)
	if err == nil && group == state.PID {
		return syscall.Kill(-state.PID, signal)
	}
	return syscall.Kill(state.PID, signal)
}

func firecrackerVirtioFSProcessMatches(
	state *firecrackerVirtioFSState,
	binary string,
) bool {
	if state == nil || state.PID <= 1 || syscall.Kill(state.PID, 0) != nil {
		return false
	}
	stat, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(state.PID), "stat"))
	if err != nil {
		return false
	}
	closeParen := strings.LastIndexByte(string(stat), ')')
	if closeParen < 0 || len(stat) <= closeParen+2 || stat[closeParen+2] == 'Z' {
		return false
	}
	executable, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(state.PID), "exe"))
	if err != nil {
		return false
	}
	resolvedBinary, err := filepath.EvalSymlinks(binary)
	if err != nil {
		resolvedBinary = binary
	}
	executable = strings.TrimSuffix(executable, " (deleted)")
	if filepath.Clean(executable) != filepath.Clean(resolvedBinary) {
		return false
	}
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(state.PID), "cmdline"))
	if err != nil || len(data) == 0 {
		return false
	}
	arguments := strings.Split(strings.TrimRight(string(data), "\x00"), "\x00")
	return commandHasOption(arguments, "--socket-path", state.SocketPath) &&
		commandHasOption(arguments, "--shared-dir", state.SharedDir) &&
		commandHasOption(arguments, "--sandbox", "namespace") &&
		commandHasOption(arguments, "--migration-mode", "find-paths") &&
		commandHasOption(arguments, "--migration-on-error", "abort") &&
		commandHasFlag(arguments, "--readonly") &&
		commandHasFlag(arguments, "--no-announce-submounts") &&
		commandHasFlag(arguments, "--inode-file-handles=never")
}

func commandHasOption(arguments []string, option, value string) bool {
	for index := 0; index+1 < len(arguments); index++ {
		if arguments[index] == option && arguments[index+1] == value {
			return true
		}
	}
	return false
}

func commandHasFlag(arguments []string, flag string) bool {
	for _, argument := range arguments {
		if argument == flag {
			return true
		}
	}
	return false
}

func unmountFirecrackerVirtioFSShared(sharedDir string) error {
	err := unix.Unmount(sharedDir, unix.MNT_DETACH)
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("unmount virtio-fs shared directory %s: %w", sharedDir, err)
	}
	return nil
}

func cleanupFirecrackerVirtioFS(state *firecrackerVirtioFSState, binary string) error {
	if state == nil {
		return nil
	}
	stopFirecrackerVirtioFS(state, binary)
	unmountErr := unmountFirecrackerVirtioFSShared(state.SharedDir)
	var removeErr error
	if unmountErr == nil {
		removeErr = os.RemoveAll(state.SharedDir)
	}
	return errors.Join(
		unmountErr,
		removeFirecrackerSocket(state.SocketPath),
		removeErr,
	)
}
