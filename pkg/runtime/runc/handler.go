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

package runc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/runcshim"
	"github.com/inclusionAI/sandboxd/internal/util"
	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
	runtimecommon "github.com/inclusionAI/sandboxd/pkg/runtime/internal/common"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const runcCgroupLeaf = "runc"

var _ runtimecore.Handler = &Handler{}
var _ runtimecore.SandboxDefaultsProvider = &Handler{}

type runcClient interface {
	List(context.Context) ([]State, error)
	State(context.Context, string) (State, error)
	Kill(context.Context, string, string, bool) error
	Delete(context.Context, string, bool) error
}

// Handler owns host-kernel OCI lifecycle without changing the common
// server resource and filesystem preparation pipeline.
type Handler struct {
	binary      string
	shimBinary  string
	stateRoot   string
	sandboxRoot string
	storageRoot string
	kvmDevice   string
	ociLoader   runtimecore.OciLoader
	client      runcClient
	mountEROFS  runtimecommon.EROFSImageMounter
}

func NewHandler(cfg config.Config, binary string, loader runtimecore.OciLoader) (*Handler, error) {
	runcConfig := cfg.RuntimeConfig.Runc
	if runcConfig.StateRoot == "" {
		runcConfig.StateRoot = config.DefaultRuncStateRoot
	}
	if runcConfig.ShimBinary == "" {
		runcConfig.ShimBinary = config.DefaultRuncShimBinary
	}
	if runcConfig.KVMDevice == "" {
		runcConfig.KVMDevice = config.DefaultKVMDevice
	}
	if err := validateExecutable(binary, "runc binary"); err != nil {
		return nil, err
	}
	if err := validateExecutable(runcConfig.ShimBinary, "runc shim"); err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.RuntimeConfig.FilestoreDir) == "" {
		return nil, fmt.Errorf("runc requires plugin.runtime.filestore_dir")
	}
	for _, filesystem := range []string{"overlay", "erofs"} {
		if err := requireHostFilesystem("/proc/filesystems", filesystem); err != nil {
			return nil, fmt.Errorf("runc host prerequisite: %w", err)
		}
	}
	loopControl := filepath.Join(cfg.RuntimeConfig.LoopDeviceDir, "loop-control")
	if _, err := os.Stat(loopControl); err != nil {
		return nil, fmt.Errorf("runc loop control %s: %w", loopControl, err)
	}

	sandboxRoot := filepath.Join(cfg.RootDir, "containers")
	storageRoot := filepath.Join(cfg.RuntimeConfig.FilestoreDir, runcStorageDir)
	for path, mode := range map[string]os.FileMode{
		runcConfig.StateRoot: 0700,
		sandboxRoot:          0755,
		storageRoot:          0700,
	} {
		if err := os.MkdirAll(path, mode); err != nil {
			return nil, fmt.Errorf("create runc directory %s: %w", path, err)
		}
	}
	mountEROFS, err := runtimecommon.NewEROFSImageMounter(cfg.RuntimeConfig.LoopDeviceDir)
	if err != nil {
		return nil, fmt.Errorf("initialize runc EROFS mounter: %w", err)
	}
	handler := &Handler{
		binary:      binary,
		shimBinary:  runcConfig.ShimBinary,
		stateRoot:   runcConfig.StateRoot,
		sandboxRoot: sandboxRoot,
		storageRoot: storageRoot,
		kvmDevice:   runcConfig.KVMDevice,
		ociLoader:   loader,
		client:      NewClient(binary, runcConfig.StateRoot),
		mountEROFS:  mountEROFS,
	}
	if err := handler.reconcileOrphans(); err != nil {
		return nil, err
	}
	return handler, nil
}

func (r *Handler) SandboxDefaults() runtimecore.SandboxDefaults {
	return runtimecore.LoaderSandboxDefaults(r.ociLoader)
}

func validateExecutable(path, description string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%s %s: %w", description, path, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return fmt.Errorf("%s %s is not an executable regular file", description, path)
	}
	return nil
}

func requireHostFilesystem(path, filesystem string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("inspect host filesystems: %w", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) > 0 && fields[len(fields)-1] == filesystem {
			return nil
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return fmt.Errorf("host kernel filesystem %q is not registered", filesystem)
}

func runcCgroupPath(parent string) string {
	if parent == "" {
		return ""
	}
	return filepath.Join(parent, runcCgroupLeaf)
}

func (r *Handler) Start(ctx context.Context, startConfig runtimecore.StartConfig) (retErr error) {
	// Image preparation can finish after the caller's create deadline.
	// Do not allocate runtime state or launch a shim for that late result.
	if err := ctx.Err(); err != nil {
		return err
	}
	if startConfig.Network == nil {
		return fmt.Errorf("runc network is required")
	}
	if startConfig.CgroupPath == "" || startConfig.DisableCgroup {
		return fmt.Errorf("runc requires a managed cgroup")
	}
	bundlePath, err := util.JoinWithinRoot(r.sandboxRoot, startConfig.ID)
	if err != nil {
		return err
	}
	configForRunc := cloneRuncStartConfig(startConfig)
	cleanupMounts, err := prepareRuncMounts(bundlePath, &configForRunc, r.mountEROFS)
	if err != nil {
		return fmt.Errorf("prepare runc mounts: %w", err)
	}
	keepMounts := false
	defer func() {
		if !keepMounts {
			retErr = errors.Join(retErr, cleanupMounts())
		}
	}()

	netnsPath, err := runcNetworkNamespace(startConfig.Network)
	if err != nil {
		return err
	}

	bundlePath, spec, err := r.ociLoader.GenerateOci(runtimecore.OciLoadOptions{
		SandboxID:                       startConfig.ID,
		Config:                          configForRunc,
		CgroupPath:                      runcCgroupPath(startConfig.CgroupPath),
		NetworkNameSpace:                netnsPath,
		UseGVisorRootfsImageAnnotations: false,
	})
	if err != nil {
		return fmt.Errorf("generate runc OCI bundle: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ensureRuncConsoleMount(spec); err != nil {
		return err
	}
	if startConfig.EnableKVM {
		if err := configureRuncKVM(spec, r.kvmDevice); err != nil {
			return err
		}
	}
	cleanupRootfs, err := prepareRuncRootfs(
		startConfig.ID,
		bundlePath,
		r.storageRoot,
		spec,
		r.mountEROFS,
	)
	if err != nil {
		return fmt.Errorf("prepare runc rootfs: %w", err)
	}
	keepRootfs := false
	defer func() {
		if !keepRootfs {
			retErr = errors.Join(retErr, cleanupRootfs())
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}

	abortShim, err := r.launchShim(bundlePath, startConfig)
	if err != nil {
		return err
	}
	if err := r.waitStarted(ctx, bundlePath); err != nil {
		if startConfig.SpecUpdates != nil {
			// Stop the launcher and its runc CLI before the server's Delete.
			// Otherwise a late create can race with a successful absent check.
			abortShim()
			keepMounts, keepRootfs = true, true
			return err
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), config.StopTimeout)
		defer cancel()
		_ = r.client.Delete(cleanupCtx, startConfig.ID, true)
		r.stopShim(bundlePath)
		return err
	}
	if err := runtimecommon.WriteSandboxRuntimeMarker(bundlePath, config.RuntimeNameRunc); err != nil {
		if startConfig.SpecUpdates != nil {
			abortShim()
			keepMounts, keepRootfs = true, true
			return fmt.Errorf("persist runc runtime marker: %w", err)
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), config.StopTimeout)
		defer cancel()
		_ = r.client.Delete(cleanupCtx, startConfig.ID, true)
		r.stopShim(bundlePath)
		return fmt.Errorf("persist runc runtime marker: %w", err)
	}
	keepMounts = true
	keepRootfs = true
	logrus.Infof("runc: started sandbox %s", startConfig.ID)
	return nil
}

func (r *Handler) launchShim(bundlePath string, startConfig runtimecore.StartConfig) (func(), error) {
	// Successful shims outlive the Start RPC. Only an explicit abort cancels
	// the command while it is running.
	shimCtx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(
		shimCtx,
		r.shimBinary,
		"--binary", r.binary,
		"--root", r.stateRoot,
		"--bundle", bundlePath,
		"--id", startConfig.ID,
		"--stdout", startConfig.Stdout,
		"--stderr", startConfig.Stderr,
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		// runc run (the shim child) inherits the launcher's process group.
		// Kill it together with the shim so it cannot create after cleanup.
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("start runc shim: %w", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer cancel()
		_ = cmd.Wait()
	}()
	abort := func() {
		cancel()
		<-done
	}
	pidPath := filepath.Join(bundlePath, runcshim.ShimPIDFile)
	if err := util.AtomicWriteFile(pidPath, []byte(strconv.Itoa(cmd.Process.Pid)), 0644); err != nil {
		abort()
		return nil, fmt.Errorf("persist runc shim pid: %w", err)
	}
	return abort, nil
}

func (r *Handler) waitStarted(ctx context.Context, bundlePath string) error {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	timer := time.NewTimer(config.DefaultTimeout)
	defer timer.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := os.Stat(filepath.Join(bundlePath, runcshim.InitPIDFile)); err == nil {
			return nil
		}
		if record, err := runcshim.ReadExit(filepath.Join(bundlePath, runcshim.ExitFile)); err == nil {
			return fmt.Errorf(
				"runc failed before becoming ready: exit=%d: %s",
				record.ExitCode,
				record.RuntimeError,
			)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return fmt.Errorf("waiting for runc container start after %s: %w", config.DefaultTimeout, context.DeadlineExceeded)
		case <-ticker.C:
		}
	}
}

func (r *Handler) Delete(ctx context.Context, sandboxID string) error {
	cleanupCtx, cancel := context.WithTimeout(
		context.WithoutCancel(ctx),
		config.StopTimeout+5*time.Second,
	)
	defer cancel()
	if err := r.stopContainer(cleanupCtx, sandboxID); err != nil {
		return err
	}
	bundlePath, err := util.JoinWithinRoot(r.sandboxRoot, sandboxID)
	if err != nil {
		return err
	}
	r.stopShim(bundlePath)
	return r.cleanupFiles(bundlePath, sandboxID)
}

// Keep private storage until every preceding runtime/mount cleanup succeeds.
func (r *Handler) cleanupFiles(bundlePath, sandboxID string) error {
	if err := cleanupRuncRootfs(bundlePath); err != nil {
		return err
	}
	if err := cleanupRuncMounts(bundlePath); err != nil {
		return err
	}
	return cleanupRuncStorage(r.storageRoot, sandboxID)
}

func (r *Handler) stopContainer(ctx context.Context, sandboxID string) error {
	killErr := r.client.Kill(ctx, sandboxID, "TERM", true)
	if killErr != nil && !IsNotRunning(killErr) {
		logrus.Warnf("runc: TERM sandbox %s: %v", sandboxID, killErr)
	}
	if killErr == nil {
		stopped, err := r.waitStopped(ctx, sandboxID, config.StopTimeout)
		if err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
			logrus.Warnf("runc: wait for TERM %s: %v", sandboxID, err)
		}
		if !stopped {
			if err := r.client.Kill(ctx, sandboxID, "KILL", true); err != nil && !IsNotRunning(err) {
				logrus.Warnf("runc: KILL sandbox %s: %v", sandboxID, err)
			}
			_, _ = r.waitStopped(ctx, sandboxID, 2*time.Second)
		}
	}
	return r.client.Delete(ctx, sandboxID, true)
}

func (r *Handler) waitStopped(ctx context.Context, sandboxID string, timeout time.Duration) (bool, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		state, err := r.client.State(ctx, sandboxID)
		if IsNotFound(err) || (err == nil && state.Status == "stopped") {
			return true, nil
		}
		if err != nil {
			return false, err
		}
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-timer.C:
			return false, nil
		case <-ticker.C:
		}
	}
}

func (r *Handler) List(ctx context.Context) ([]*runtimecore.State, error) {
	states, err := r.client.List(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]*runtimecore.State, 0, len(states))
	for _, state := range states {
		bundlePath := state.Bundle
		if bundlePath == "" {
			bundlePath, _ = util.JoinWithinRoot(r.sandboxRoot, state.ID)
		}
		if !isRuncRuntimeBundle(bundlePath) {
			continue
		}
		result = append(result, &runtimecore.State{
			ID:             state.ID,
			InitProcessPid: state.PID,
			Status:         runcSandboxStatus(state.Status),
			Created:        state.Created,
		})
	}
	return result, nil
}

func runcSandboxStatus(status string) runtimecore.SandboxStatus {
	switch status {
	case "created":
		return runtimecore.SandboxStatusCreated
	case "running":
		return runtimecore.SandboxStatusRunning
	case "stopped":
		return runtimecore.SandboxStatusExited
	default:
		return runtimecore.SandboxStatusUnknown
	}
}

func (r *Handler) Wait(ctx context.Context, sandboxID string) (runtimecore.Exit, error) {
	bundlePath, err := util.JoinWithinRoot(r.sandboxRoot, sandboxID)
	if err != nil {
		return runtimecore.Exit{}, err
	}
	exitPath := filepath.Join(bundlePath, runcshim.ExitFile)
	shimPath := filepath.Join(bundlePath, runcshim.ShimPIDFile)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	missingSince := time.Time{}
	for {
		record, err := runcshim.ReadExit(exitPath)
		if err == nil {
			if record.RuntimeError != "" && !record.Started {
				return runtimecore.Exit{}, errors.New(record.RuntimeError)
			}
			return runtimecore.Exit{ExitedAt: record.ExitedAt, ExitCode: record.ExitCode}, nil
		}
		if !os.IsNotExist(err) {
			return runtimecore.Exit{}, err
		}
		if !runcShimAlive(shimPath, bundlePath, r.shimBinary) {
			if missingSince.IsZero() {
				missingSince = time.Now()
			} else if time.Since(missingSince) >= time.Second {
				return runtimecore.Exit{}, fmt.Errorf("runc shim exited without persisting container status")
			}
		} else {
			missingSince = time.Time{}
		}
		select {
		case <-ctx.Done():
			return runtimecore.Exit{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

func runcShimAlive(path, bundlePath, shimBinary string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	return err == nil && pid > 1 && runcShimProcessMatches(pid, bundlePath, shimBinary)
}

func (r *Handler) stopShim(bundlePath string) {
	data, err := os.ReadFile(filepath.Join(bundlePath, runcshim.ShimPIDFile))
	if err != nil {
		return
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 1 {
		return
	}
	if !runcShimProcessMatches(pid, bundlePath, r.shimBinary) {
		return
	}
	_ = syscall.Kill(pid, syscall.SIGTERM)
	for attempts := 0; attempts < 10; attempts++ {
		if syscall.Kill(pid, 0) != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
}

func runcShimProcessMatches(pid int, bundlePath, shimBinary string) bool {
	if syscall.Kill(pid, 0) != nil {
		return false
	}
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil || len(data) == 0 {
		return false
	}
	arguments := strings.Split(strings.TrimRight(string(data), "\x00"), "\x00")
	if len(arguments) == 0 || filepath.Base(arguments[0]) != filepath.Base(shimBinary) {
		return false
	}
	for index := 0; index+1 < len(arguments); index++ {
		if arguments[index] == "--bundle" && filepath.Clean(arguments[index+1]) == filepath.Clean(bundlePath) {
			return true
		}
	}
	return false
}

func configureRuncKVM(spec *runtimecore.Spec, source string) error {
	const target = "/dev/kvm"
	for _, mount := range spec.Mounts {
		if filepath.Clean(mount.Destination) == target {
			return fmt.Errorf("mount target %s is already configured", target)
		}
	}
	info, err := os.Stat(source)
	if err != nil {
		return fmt.Errorf("stat KVM device %s: %w", source, err)
	}
	if info.Mode()&os.ModeCharDevice == 0 {
		return fmt.Errorf("KVM path %s is not a character device", source)
	}
	device, err := os.OpenFile(source, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open KVM device %s read-write: %w", source, err)
	}
	if err := device.Close(); err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("read KVM device number for %s", source)
	}
	major := int64(unix.Major(uint64(stat.Rdev)))
	minor := int64(unix.Minor(uint64(stat.Rdev)))
	if spec.Linux == nil {
		spec.Linux = &runtimecore.Linux{}
	}
	if spec.Linux.Resources == nil {
		spec.Linux.Resources = &runtimecore.LinuxResources{}
	}
	spec.Linux.Resources.Devices = append(spec.Linux.Resources.Devices, runtimecore.LinuxDeviceCgroup{
		Allow:  true,
		Type:   "c",
		Major:  &major,
		Minor:  &minor,
		Access: "rwm",
	})
	spec.Mounts = append(spec.Mounts, runtimecore.Mount{
		Destination: target,
		Type:        "bind",
		Source:      source,
		Options:     []string{"bind", "rw", "nosuid", "noexec"},
	})
	return nil
}

func (r *Handler) reconcileOrphans() error {
	orphans := make(map[string]struct{})
	entries, err := os.ReadDir(r.storageRoot)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() || !config.IsValidSandboxID(entry.Name()) {
			continue
		}
		orphans[entry.Name()] = struct{}{}
	}
	bundles, err := os.ReadDir(r.sandboxRoot)
	if err != nil {
		return err
	}
	for _, entry := range bundles {
		if !entry.IsDir() || !config.IsValidSandboxID(entry.Name()) {
			continue
		}
		bundlePath, err := util.JoinWithinRoot(r.sandboxRoot, entry.Name())
		if err != nil {
			return err
		}
		if isRuncRuntimeBundle(bundlePath) {
			orphans[entry.Name()] = struct{}{}
		}
	}
	for sandboxID := range orphans {
		bundlePath, err := util.JoinWithinRoot(r.sandboxRoot, sandboxID)
		if err != nil {
			return err
		}
		metadataPath := filepath.Join(bundlePath, config.SandboxMetaFile)
		if _, err := os.Stat(metadataPath); err == nil {
			logrus.Debugf("runc: retaining persisted sandbox %s during reconciliation", sandboxID)
			continue
		} else if !os.IsNotExist(err) {
			return err
		}
		logrus.Warnf("runc: cleaning orphaned sandbox %s without metadata", sandboxID)
		cleanupCtx, cancel := context.WithTimeout(context.Background(), config.StopTimeout)
		deleteErr := r.client.Delete(cleanupCtx, sandboxID, true)
		cancel()
		if deleteErr != nil {
			return fmt.Errorf("delete orphaned runc sandbox %s: %w", sandboxID, deleteErr)
		}
		if err := r.cleanupFiles(bundlePath, sandboxID); err != nil {
			return fmt.Errorf("clean orphaned runc sandbox %s: %w", sandboxID, err)
		}
	}
	return nil
}

func isRuncRuntimeBundle(bundlePath string) bool {
	data, err := os.ReadFile(filepath.Join(bundlePath, "runtime.json"))
	if err != nil {
		return false
	}
	var marker struct {
		Runtime string `json:"runtime"`
	}
	return json.Unmarshal(data, &marker) == nil && marker.Runtime == config.RuntimeNameRunc
}
