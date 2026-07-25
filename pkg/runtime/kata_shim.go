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
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/containerd/ttrpc"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/emptypb"
)

const kataTaskService = "containerd.task.v2.Task"

type kataShimInstance struct {
	pid        int
	address    string
	createdAt  time.Time
	bundlePath string
}

func (k *KataHandler) startShim(
	ctx context.Context,
	sandboxID string,
	bundlePath string,
) (_ *ttrpc.Client, retErr error) {
	logPath := filepath.Join(bundlePath, "log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("prepare shim log: %w", err)
	}
	_ = logFile.Close()

	cmd := exec.CommandContext(ctx, k.binary,
		"-id", sandboxID,
		"-namespace", "sandboxd",
		"-address", "unix:///run/sandboxd",
		"-bundle", bundlePath,
		"-publish-binary", "/bin/true",
		"start",
	)
	cmd.Dir = bundlePath
	defer func() {
		if retErr == nil || !kataShimStateExists(bundlePath) {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := k.forceStopShim(cleanupCtx, sandboxID, bundlePath); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("clean up Kata shim after failed start: %w", err))
		}
	}()
	output, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
			return nil, fmt.Errorf("shim start: %w: %s", err, strings.TrimSpace(string(exitErr.Stderr)))
		}
		return nil, fmt.Errorf("shim start: %w", err)
	}

	address := strings.TrimSpace(string(output))
	if address == "" {
		addressBytes, readErr := os.ReadFile(filepath.Join(bundlePath, "address"))
		if readErr != nil {
			return nil, fmt.Errorf("shim returned an empty address: %w", readErr)
		}
		address = strings.TrimSpace(string(addressBytes))
	}
	if err := os.WriteFile(filepath.Join(bundlePath, "address"), []byte(address+"\n"), 0644); err != nil {
		return nil, fmt.Errorf("persist shim address: %w", err)
	}

	pidBytes, err := os.ReadFile(filepath.Join(bundlePath, "shim.pid"))
	if err != nil {
		return nil, fmt.Errorf("read shim pid: %w", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidBytes)))
	if err != nil || pid <= 0 {
		return nil, fmt.Errorf("invalid shim pid %q", strings.TrimSpace(string(pidBytes)))
	}

	client, err := connectKataShim(address)
	if err != nil {
		return nil, fmt.Errorf("connect shim: %w", err)
	}
	instance := &kataShimInstance{
		pid:        pid,
		address:    address,
		createdAt:  time.Now(),
		bundlePath: bundlePath,
	}
	k.shims.Set(sandboxID, instance)
	return client, nil
}

func connectKataShim(address string) (*ttrpc.Client, error) {
	socketPath := strings.TrimPrefix(strings.TrimSpace(address), "unix://")
	if socketPath == "" {
		return nil, fmt.Errorf("empty shim socket address")
	}
	connection, err := net.DialTimeout("unix", socketPath, 5*time.Second)
	if err != nil {
		var abstractErr error
		for _, name := range []string{"\x00" + socketPath, "\x00" + socketPath + "\x00"} {
			connection, abstractErr = net.DialTimeout("unix", name, 5*time.Second)
			if abstractErr == nil {
				return ttrpc.NewClient(connection), nil
			}
		}
		return nil, fmt.Errorf("dial %s: %w (abstract socket: %v)", socketPath, err, abstractErr)
	}
	return ttrpc.NewClient(connection), nil
}

func (k *KataHandler) createTask(ctx context.Context, client *ttrpc.Client, request *shimCreateTaskRequest) (*shimCreateTaskResponse, error) {
	response := &shimCreateTaskResponse{}
	if err := client.Call(ctx, kataTaskService, "Create", request, response); err != nil {
		return nil, err
	}
	return response, nil
}

func (k *KataHandler) startTask(ctx context.Context, client *ttrpc.Client, request *shimStartRequest) (*shimStartResponse, error) {
	response := &shimStartResponse{}
	if err := client.Call(ctx, kataTaskService, "Start", request, response); err != nil {
		return nil, err
	}
	return response, nil
}

func (k *KataHandler) waitTask(ctx context.Context, client *ttrpc.Client, sandboxID string) (*shimWaitResponse, error) {
	response := &shimWaitResponse{}
	if err := client.Call(ctx, kataTaskService, "Wait", &shimWaitRequest{ID: sandboxID}, response); err != nil {
		return nil, err
	}
	return response, nil
}

func (k *KataHandler) stateTask(ctx context.Context, client *ttrpc.Client, sandboxID string) (*shimStateResponse, error) {
	response := &shimStateResponse{}
	if err := client.Call(ctx, kataTaskService, "State", &shimStateRequest{ID: sandboxID}, response); err != nil {
		return nil, err
	}
	return response, nil
}

func (k *KataHandler) stopShim(ctx context.Context, sandboxID string) error {
	instance, ok := k.shims.Get(sandboxID)
	if !ok {
		bundlePath, err := k.bundlePath(sandboxID)
		if err != nil {
			return err
		}
		return k.forceStopShim(ctx, sandboxID, bundlePath)
	}
	client, err := connectKataShim(instance.address)
	if err != nil {
		return k.forceStopShim(ctx, sandboxID, instance.bundlePath)
	}
	defer client.Close()
	killCtx, cancelKill := context.WithTimeout(ctx, 5*time.Second)
	if err := client.Call(killCtx, kataTaskService, "Kill", &shimKillRequest{
		ID:     sandboxID,
		Signal: uint32(syscall.SIGKILL),
		All:    true,
	}, &emptypb.Empty{}); err != nil {
		logrus.Debugf("kata: task kill %s: %v", sandboxID, err)
	}
	cancelKill()

	waitCtx, cancelWait := context.WithTimeout(context.Background(), 5*time.Second)
	if _, err := k.waitTask(waitCtx, client, sandboxID); err != nil {
		logrus.Debugf("kata: task wait after kill %s: %v", sandboxID, err)
	}
	cancelWait()

	var stopErr error
	deleteCtx, cancelDelete := context.WithTimeout(ctx, 10*time.Second)
	deleteResponse := &shimDeleteResponse{}
	if err := client.Call(deleteCtx, kataTaskService, "Delete", &shimDeleteRequest{ID: sandboxID}, deleteResponse); err != nil {
		stopErr = fmt.Errorf("task delete: %w", err)
	}
	cancelDelete()

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	if err := client.Call(shutdownCtx, kataTaskService, "Shutdown", &shimShutdownRequest{ID: sandboxID}, &emptypb.Empty{}); err != nil {
		logrus.Debugf("kata: task shutdown %s: %v", sandboxID, err)
	}
	cancelShutdown()
	k.shims.Remove(sandboxID)

	processAlive := false
	if waitForKataProcess(instance.pid, 5*time.Second) {
		_ = syscall.Kill(instance.pid, syscall.SIGKILL)
		processAlive = waitForKataProcess(instance.pid, 3*time.Second)
	}
	if stopErr != nil || processAlive {
		if forceErr := k.forceStopShim(ctx, sandboxID, instance.bundlePath); forceErr != nil {
			return errors.Join(stopErr, fmt.Errorf("force stop: %w", forceErr))
		}
		if kataProcessAlive(instance.pid) {
			return errors.Join(stopErr, fmt.Errorf("kata shim process %d did not stop", instance.pid))
		}
	}
	return nil
}

func (k *KataHandler) forceStopShim(ctx context.Context, sandboxID, bundlePath string) error {
	cmd := exec.CommandContext(ctx, k.binary,
		"-id", sandboxID,
		"-namespace", "sandboxd",
		"-address", "unix:///run/sandboxd",
		"-bundle", bundlePath,
		"-publish-binary", "/bin/true",
		"delete",
	)
	cmd.Dir = bundlePath
	commandErr := cmd.Run()
	if pidBytes, err := os.ReadFile(filepath.Join(bundlePath, "shim.pid")); err == nil {
		if pid, parseErr := strconv.Atoi(strings.TrimSpace(string(pidBytes))); parseErr == nil && kataProcessAlive(pid) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	}
	k.shims.Remove(sandboxID)
	_ = os.Remove(filepath.Join(bundlePath, "shim.pid"))
	_ = os.Remove(filepath.Join(bundlePath, "address"))
	if commandErr != nil {
		return commandErr
	}
	return nil
}

func kataShimStateExists(bundlePath string) bool {
	for _, name := range []string{"shim.pid", "address"} {
		if _, err := os.Stat(filepath.Join(bundlePath, name)); err == nil {
			return true
		}
	}
	return false
}

func kataProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	if err != nil && err != syscall.EPERM {
		return false
	}
	stat, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return true
	}
	return kataProcessStatAlive(stat)
}

func kataProcessStatAlive(stat []byte) bool {
	stateOffset := bytes.LastIndex(stat, []byte(") "))
	return stateOffset < 0 ||
		stateOffset+2 >= len(stat) ||
		stat[stateOffset+2] != 'Z'
}

// waitForKataProcess returns true when the process is still alive at timeout.
func waitForKataProcess(pid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !kataProcessAlive(pid) {
			return false
		}
		time.Sleep(100 * time.Millisecond)
	}
	return kataProcessAlive(pid)
}

func (k *KataHandler) recoverShims() {
	entries, err := os.ReadDir(k.sandboxRoot)
	if err != nil {
		logrus.Warnf("kata: scan bundles for recovery: %v", err)
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		bundlePath := filepath.Join(k.sandboxRoot, entry.Name())
		pidBytes, err := os.ReadFile(filepath.Join(bundlePath, "shim.pid"))
		if err != nil {
			if isKataRuntimeBundle(bundlePath) {
				k.cleanupOrphanedShim(entry.Name(), bundlePath)
			}
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(pidBytes)))
		if err != nil || !kataProcessAlive(pid) {
			k.cleanupOrphanedShim(entry.Name(), bundlePath)
			continue
		}
		addressBytes, err := os.ReadFile(filepath.Join(bundlePath, "address"))
		if err != nil {
			logrus.Warnf("kata: recover %s without address: %v", entry.Name(), err)
			continue
		}
		address := strings.TrimSpace(string(addressBytes))
		client, err := connectKataShim(address)
		if err != nil {
			logrus.Warnf("kata: reconnect %s: %v", entry.Name(), err)
			continue
		}
		_ = client.Close()
		createdAt := time.Now()
		if info, statErr := entry.Info(); statErr == nil {
			createdAt = info.ModTime()
		}
		k.shims.Set(entry.Name(), &kataShimInstance{
			pid:        pid,
			address:    address,
			createdAt:  createdAt,
			bundlePath: bundlePath,
		})
		logrus.Infof("kata: recovered sandbox %s with shim pid %d", entry.Name(), pid)
	}
}

func (k *KataHandler) cleanupOrphanedShim(sandboxID, bundlePath string) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	stopErr := k.forceStopShim(ctx, sandboxID, bundlePath)
	rootfsErr := cleanupKataRootfs(bundlePath)
	mountErr := cleanupKataMounts(bundlePath)
	cleanupKataNetwork(bundlePath)
	var sharedErr error
	if stopErr == nil {
		sharedErr = k.cleanupSharedPath(sandboxID)
	}
	if err := errors.Join(stopErr, rootfsErr, mountErr, sharedErr); err != nil {
		logrus.Warnf("kata: clean orphaned sandbox %s: %v", sandboxID, err)
		return
	}
	logrus.Infof("kata: cleaned orphaned sandbox %s", sandboxID)
}
