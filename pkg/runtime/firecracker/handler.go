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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/containerd/cgroups/v3"
	cgroup1 "github.com/containerd/cgroups/v3/cgroup1"
	"github.com/containerd/cgroups/v3/cgroup2"
	runtimeapi "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/firecrackerproto"
	"github.com/inclusionAI/sandboxd/internal/util"
	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
	runtimecommon "github.com/inclusionAI/sandboxd/pkg/runtime/internal/common"
	"github.com/sirupsen/logrus"
)

const (
	firecrackerArtifactsDir    = "firecracker"
	firecrackerStateFilename   = "state.json"
	firecrackerAPISocket       = "api.sock"
	firecrackerVsock           = firecrackerproto.HostAgentSocketName
	firecrackerAgentTimeout    = 15 * time.Second
	firecrackerShutdownTimeout = 2 * time.Second
	// Guest flush budget before pausing for a checkpoint. Syncing a heavily
	// dirty writable layer can exceed the default 1s agent round-trip, but
	// the pause window must not grow unbounded on a stuck guest.
	firecrackerFlushTimeout = 2 * time.Second
	firecrackerMinMemoryMiB = uint32(128)
	firecrackerMaxVCPUs     = uint32(32)
	// checkpoint_mode values: the conservative default and the incremental
	// chain. An unset value normalizes to full.
	firecrackerCheckpointModeFull        = "full"
	firecrackerCheckpointModeIncremental = "incremental"
)

var (
	_ runtimecore.Handler                 = &Handler{}
	_ runtimecore.CheckpointHandler       = &Handler{}
	_ runtimecore.StartRequestValidator   = &Handler{}
	_ runtimecore.SandboxDefaultsProvider = &Handler{}
	_ runtimecore.HostResourcesProvider   = &Handler{}
)

type firecrackerPersistedState struct {
	ID          string `json:"id"`
	PID         int    `json:"pid"`
	BundlePath  string `json:"bundle_path"`
	APIPath     string `json:"api_path"`
	VsockPath   string `json:"vsock_path"`
	OverlayPath string `json:"overlay_path"`
	CreatedAt   string `json:"created_at"`
	// MemoryMiB is the guest memory size in MiB, recorded so incremental
	// checkpoints can preallocate or clone a full-size base memory file.
	MemoryMiB uint32 `json:"memory_mib,omitempty"`
	// Vcpus is the guest vCPU count at Start time, recorded so checkpoints
	// can stamp the compatibility tuple (the vmstate itself pins the count
	// for a restore).
	Vcpus uint32 `json:"vcpus,omitempty"`
	// BaseMemoryPath points at the memory image the Firecracker dirty-page
	// ledger currently tracks — the previous artifact's own memory file, or
	// the file a restore loaded.
	BaseMemoryPath string `json:"base_memory_path,omitempty"`
	// BaseMemoryIncremental marks a base that came from a restore, which the
	// Firecracker pagemap ledger (not the soft-dirty window) diffs against.
	BaseMemoryIncremental bool `json:"base_memory_incremental,omitempty"`
	// BaseMemoryLineageLost marks that the VMM dirty-page ledger may be
	// armed against a base sandboxd no longer holds: a checkpoint failed
	// after the VMM wrote and re-armed its window, or the daemon restarted
	// and cannot tell which generation the surviving VMM tracks. While set,
	// the next checkpoint must take a Full snapshot — Full ignores the
	// ledger and writes the complete memory image, and the window re-opens
	// only after that write, so patching later deltas onto the Full
	// artifact is a safe superset.
	BaseMemoryLineageLost bool   `json:"base_memory_lineage_lost,omitempty"`
	Configured            bool   `json:"configured,omitempty"`
	Exited                bool   `json:"exited,omitempty"`
	ExitedAt              string `json:"exited_at,omitempty"`
	ExitCode              int    `json:"exit_code,omitempty"`
}

type firecrackerInstance struct {
	mu          sync.RWMutex
	state       firecrackerPersistedState
	exit        runtimecore.Exit
	done        chan struct{}
	doneOnce    sync.Once
	deleting    bool
	operationMu sync.Mutex
}

func (instance *firecrackerInstance) snapshot() firecrackerPersistedState {
	instance.mu.RLock()
	defer instance.mu.RUnlock()
	return instance.state
}

func (instance *firecrackerInstance) markDeleting() {
	instance.mu.Lock()
	instance.deleting = true
	instance.mu.Unlock()
}

func (instance *firecrackerInstance) markConfigured() {
	instance.mu.Lock()
	instance.state.Configured = true
	instance.mu.Unlock()
}

func (instance *firecrackerInstance) setMemoryMiB(size uint32) {
	instance.mu.Lock()
	instance.state.MemoryMiB = size
	instance.mu.Unlock()
}

func (instance *firecrackerInstance) setVcpus(count uint32) {
	instance.mu.Lock()
	instance.state.Vcpus = count
	instance.mu.Unlock()
}

func (instance *firecrackerInstance) setBaseMemory(path string, incremental bool) {
	instance.mu.Lock()
	instance.state.BaseMemoryPath = path
	instance.state.BaseMemoryIncremental = incremental
	instance.state.BaseMemoryLineageLost = false
	instance.mu.Unlock()
}

// markBaseMemoryLineageLost drops the incremental lineage and records that
// the VMM soft-dirty ledger may still be armed against the discarded base.
// The next checkpoint must take a Full snapshot: with the ledger armed a
// SoftDirty request writes only the window delta, which would silently lose
// every page written before the discarded generation.
func (instance *firecrackerInstance) markBaseMemoryLineageLost() {
	instance.mu.Lock()
	instance.state.BaseMemoryPath = ""
	instance.state.BaseMemoryIncremental = false
	instance.state.BaseMemoryLineageLost = true
	instance.mu.Unlock()
}

// clearBaseMemory drops the incremental lineage without asserting anything
// about the VMM ledger state; only callers that know the ledger is not armed
// (a fresh sandbox that never checkpointed) may use it. Lineage-unsafe
// callers must use markBaseMemoryLineageLost instead.
func (instance *firecrackerInstance) clearBaseMemory() bool {
	instance.mu.Lock()
	changed := instance.state.BaseMemoryPath != ""
	instance.state.BaseMemoryPath = ""
	instance.state.BaseMemoryIncremental = false
	instance.mu.Unlock()
	return changed
}

func (instance *firecrackerInstance) finish(exit runtimecore.Exit) bool {
	finished := false
	instance.doneOnce.Do(func() {
		instance.mu.Lock()
		instance.exit = exit
		instance.state.Exited = true
		instance.state.ExitedAt = exit.ExitedAt.Format(time.RFC3339Nano)
		instance.state.ExitCode = exit.ExitCode
		instance.mu.Unlock()
		close(instance.done)
		finished = true
	})
	return finished
}

func (instance *firecrackerInstance) result() runtimecore.Exit {
	instance.mu.RLock()
	defer instance.mu.RUnlock()
	return instance.exit
}

func (instance *firecrackerInstance) shouldPersist() bool {
	instance.mu.RLock()
	defer instance.mu.RUnlock()
	return !instance.deleting
}

// Handler manages the Firecracker microVM lifecycle.
type Handler struct {
	binary       string
	sandboxRoot  string
	storageRoot  string
	runtimeRoot  string
	kernelPath   string
	initrdPath   string
	kernelArgs   string
	kvmDevice    string
	defaultVCPUs uint32
	defaultMem   uint32
	defaultDisk  uint64
	ociLoader    runtimecore.OciLoader

	mu        sync.RWMutex
	instances map[string]*firecrackerInstance

	// compatMu guards the cached binary/kernel digests behind the
	// compatibility tuple; hashing a vmlinux is a one-off per daemon.
	compatMu      sync.Mutex
	compatDigests *firecrackerCheckpointCompat

	// digestCache memoizes verified checkpoint component digests so warm
	// restores from a stable directory skip the re-hash.
	digestCache checkpointDigestCache

	// checkpointMode is the validated plugin.runtime.firecracker
	// checkpoint_mode: full keeps upstream Full snapshots, incremental
	// enables the three-tier chain.
	checkpointMode string

	// shrinkBeforeCheckpoint gates the pre-pause guest page-cache drop;
	// see FirecrackerConfig.ShrinkBeforeCheckpoint for why it is off by
	// default.
	shrinkBeforeCheckpoint bool

	// checkpointWriteback starts background writeback for completed memory
	// artifacts so a later XFS reflink does not inherit the previous
	// generation's buffered-I/O debt.
	checkpointWriteback *checkpointWritebackScheduler
}

var _ runtimecore.Handler = &Handler{}
var _ runtimecore.CheckpointHandler = &Handler{}
var _ runtimecore.CheckpointRestoreCapabilitiesProvider = &Handler{}

func (handler *Handler) CheckpointRestoreCapabilities() runtimecore.CheckpointRestoreCapabilities {
	return runtimecore.CheckpointRestoreCapabilities{
		CheckpointHandoffPath: firecrackerproto.CheckpointHandoffPath,
		RestoreEnvPath:        firecrackerproto.RestoreEnvPath,
	}
}

func (handler *Handler) ValidateStartRequest(
	request *runtimeapi.StartRequest,
) error {
	if rootfs := request.GetRootfs(); rootfs != nil &&
		(rootfs.GetType() == runtimeapi.RootfsSrcType_IMAGE ||
			rootfs.GetImageUrl() != "") {
		return errors.New("Firecracker does not support OCI image rootfs")
	}
	for _, mount := range request.GetMounts() {
		if mount == nil {
			continue
		}
		if _, ok := mount.GetSource().(*runtimeapi.Mount_ImageUrl); ok {
			return fmt.Errorf(
				"Firecracker does not support OCI image mount at %s",
				mount.GetTarget(),
			)
		}
	}
	return nil
}

func NewHandler(
	cfg config.Config,
	binary string,
	loader runtimecore.OciLoader,
) (*Handler, error) {
	firecrackerConfig := cfg.RuntimeConfig.Firecracker
	applyFirecrackerDefaults(&firecrackerConfig)
	binary = firecrackerConfigPath(binary)
	for description, path := range map[string]string{
		"Firecracker binary": binary,
		"Firecracker kernel": firecrackerConfig.KernelImagePath,
		"Firecracker initrd": firecrackerConfig.InitrdPath,
	} {
		if err := validateFirecrackerRegularFile(path, description, description == "Firecracker binary"); err != nil {
			return nil, err
		}
	}
	if err := validateFirecrackerKVM(firecrackerConfig.KVMDevice); err != nil {
		return nil, err
	}
	if err := validateFirecrackerCheckpointMode(firecrackerConfig.CheckpointMode); err != nil {
		return nil, err
	}
	if filepath.Clean(firecrackerConfig.KVMDevice) !=
		filepath.Clean(config.DefaultKVMDevice) {
		return nil, fmt.Errorf(
			"stock Firecracker requires KVM at %s",
			config.DefaultKVMDevice,
		)
	}
	if strings.TrimSpace(cfg.RuntimeConfig.FilestoreDir) == "" {
		return nil, errors.New("Firecracker requires plugin.runtime.filestore_dir")
	}
	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		return nil, fmt.Errorf("Firecracker requires mkfs.ext4: %w", err)
	}
	sandboxRoot := filepath.Join(cfg.RootDir, "containers")
	storageRoot := filepath.Join(cfg.RuntimeConfig.FilestoreDir, ".firecracker")
	for path, mode := range map[string]os.FileMode{
		firecrackerproto.HostRuntimeRoot: 0700,
		sandboxRoot:                      0755,
		storageRoot:                      0700,
	} {
		if err := os.MkdirAll(path, mode); err != nil {
			return nil, fmt.Errorf("create Firecracker directory %s: %w", path, err)
		}
	}
	handler := &Handler{
		binary:                 binary,
		sandboxRoot:            sandboxRoot,
		storageRoot:            storageRoot,
		runtimeRoot:            firecrackerproto.HostRuntimeRoot,
		kernelPath:             firecrackerConfig.KernelImagePath,
		initrdPath:             firecrackerConfig.InitrdPath,
		kernelArgs:             firecrackerConfig.KernelArgs,
		kvmDevice:              firecrackerConfig.KVMDevice,
		defaultVCPUs:           firecrackerConfig.DefaultVCPUCount,
		defaultMem:             firecrackerConfig.DefaultMemoryMiB,
		shrinkBeforeCheckpoint: firecrackerConfig.ShrinkBeforeCheckpoint,
		checkpointMode:         firecrackerConfig.CheckpointMode,
		checkpointWriteback:    newCheckpointWritebackScheduler(),
		defaultDisk:            firecrackerConfig.DefaultOverlaySizeBytes,
		ociLoader:              loader,
		instances:              make(map[string]*firecrackerInstance),
	}
	handler.recoverInstances()
	return handler, nil
}

func applyFirecrackerDefaults(value *config.FirecrackerConfig) {
	if value.KernelImagePath == "" {
		value.KernelImagePath = config.DefaultFirecrackerKernel
	}
	if value.InitrdPath == "" {
		value.InitrdPath = config.DefaultFirecrackerInitrd
	}
	if value.KernelArgs == "" {
		value.KernelArgs = config.DefaultFirecrackerKernelArgs
	}
	if value.KVMDevice == "" {
		value.KVMDevice = config.DefaultKVMDevice
	}
	if value.DefaultVCPUCount == 0 {
		value.DefaultVCPUCount = config.DefaultFirecrackerVCPUs
	}
	if value.DefaultMemoryMiB == 0 {
		value.DefaultMemoryMiB = config.DefaultFirecrackerMemoryMiB
	}
	if value.DefaultOverlaySizeBytes == 0 {
		value.DefaultOverlaySizeBytes = config.DefaultFirecrackerOverlayBytes
	}
	if value.CheckpointMode == "" {
		value.CheckpointMode = firecrackerCheckpointModeFull
	}
}

func validateFirecrackerCheckpointMode(mode string) error {
	switch mode {
	// "" is the unset value: applyFirecrackerDefaults normalizes it to
	// full before validation runs, but accepting it here keeps the check
	// order-independent for direct callers.
	case "", firecrackerCheckpointModeFull, firecrackerCheckpointModeIncremental:
		return nil
	default:
		return fmt.Errorf(
			"invalid firecracker checkpoint_mode %q: want %q or %q",
			mode, firecrackerCheckpointModeFull, firecrackerCheckpointModeIncremental,
		)
	}
}

func firecrackerConfigPath(path string) string {
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil {
		return resolved
	}
	return path
}

func validateFirecrackerRegularFile(path, description string, executable bool) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%s %s: %w", description, path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s %s is not a regular file", description, path)
	}
	if executable && info.Mode().Perm()&0111 == 0 {
		return fmt.Errorf("%s %s is not executable", description, path)
	}
	return nil
}

func validateFirecrackerKVM(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("Firecracker KVM device %s: %w", path, err)
	}
	if info.Mode()&os.ModeCharDevice == 0 {
		return fmt.Errorf("Firecracker KVM path %s is not a character device", path)
	}
	device, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open Firecracker KVM device %s: %w", path, err)
	}
	return device.Close()
}

func (handler *Handler) Start(
	ctx context.Context,
	startConfig runtimecore.StartConfig,
) (retErr error) {
	if startConfig.DisableCgroup || startConfig.CgroupPath == "" {
		return errors.New("Firecracker requires a managed cgroup")
	}
	if startConfig.EnableKVM {
		return errors.New("Firecracker does not expose nested KVM to the guest")
	}
	if startConfig.SpecUpdates != nil {
		return errors.New("Firecracker does not support host device-provider OCI updates")
	}
	if startConfig.Network == nil {
		return errors.New("Firecracker requires a cached TAP network")
	}
	handler.mu.RLock()
	_, alreadyRunning := handler.instances[startConfig.ID]
	handler.mu.RUnlock()
	if alreadyRunning {
		return fmt.Errorf("Firecracker sandbox %s already exists", startConfig.ID)
	}

	bundlePath, spec, err := handler.ociLoader.GenerateOci(runtimecore.OciLoadOptions{
		SandboxID:  startConfig.ID,
		Config:     startConfig,
		CgroupPath: startConfig.CgroupPath,
	})
	if err != nil {
		return fmt.Errorf("generate Firecracker OCI metadata: %w", err)
	}
	plan, err := prepareFirecrackerStorage(spec, startConfig)
	if err != nil {
		return err
	}
	_, err = createFirecrackerStorageDirectory(
		handler.storageRoot,
		startConfig.ID,
	)
	if err != nil {
		return err
	}
	keepStorage := false
	defer func() {
		if !keepStorage {
			retErr = errors.Join(
				retErr,
				cleanupFirecrackerOverlay(handler.storageRoot, startConfig.ID),
			)
		}
	}()
	overlaySize := startConfig.WritableLayerLimitBytes
	if overlaySize == 0 {
		overlaySize = handler.defaultDisk
	}
	overlayPath, err := createFirecrackerOverlay(
		handler.storageRoot,
		startConfig.ID,
		overlaySize,
	)
	if err != nil {
		return err
	}

	stateDir := filepath.Join(bundlePath, firecrackerArtifactsDir)
	if err := os.Mkdir(stateDir, 0700); err != nil {
		return fmt.Errorf("create Firecracker state directory: %w", err)
	}
	overlayLink := filepath.Join(stateDir, firecrackerCheckpointOverlayName)
	if err := os.Symlink(overlayPath, overlayLink); err != nil {
		return fmt.Errorf(
			"link Firecracker writable layer into runtime directory: %w",
			err,
		)
	}
	runtimeDir := handler.runtimeDirectory(startConfig.ID)
	runtimeCreated := false
	keepRuntimeArtifacts := false
	defer func() {
		if keepRuntimeArtifacts {
			return
		}
		retErr = errors.Join(retErr, os.RemoveAll(stateDir))
		if runtimeCreated {
			retErr = errors.Join(
				retErr,
				handler.cleanupRuntimeDirectory(startConfig.ID, filepath.Join(
					runtimeDir, firecrackerAPISocket,
				)),
			)
		}
	}()
	if err := os.Mkdir(runtimeDir, 0700); err != nil {
		return fmt.Errorf(
			"create Firecracker socket directory %s: %w", runtimeDir, err,
		)
	}
	runtimeCreated = true
	apiPath := filepath.Join(runtimeDir, firecrackerAPISocket)
	vsockPath := filepath.Join(runtimeDir, firecrackerVsock)
	if len(apiPath) >= 100 || len(vsockPath) >= 100 {
		return fmt.Errorf("Firecracker Unix socket path is too long under %s", runtimeDir)
	}
	if err := removeFirecrackerSocket(apiPath); err != nil {
		return err
	}
	if err := removeFirecrackerSocket(vsockPath); err != nil {
		return err
	}

	stdout, err := openFirecrackerOutput(startConfig.Stdout)
	if err != nil {
		return err
	}
	defer stdout.Close()
	stderr, err := openFirecrackerOutput(startConfig.Stderr)
	if err != nil {
		return err
	}
	defer stderr.Close()

	command := exec.Command(
		handler.binary,
		"--api-sock", apiPath,
		"--id", startConfig.ID,
	)
	command.Dir = stateDir
	command.Stdout = stdout
	command.Stderr = stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		return fmt.Errorf("start Firecracker VMM: %w", err)
	}
	instance := &firecrackerInstance{
		state: firecrackerPersistedState{
			ID:          startConfig.ID,
			PID:         command.Process.Pid,
			BundlePath:  bundlePath,
			APIPath:     apiPath,
			VsockPath:   vsockPath,
			OverlayPath: overlayPath,
			CreatedAt:   time.Now().Format(time.RFC3339Nano),
		},
		done: make(chan struct{}),
	}
	handler.mu.Lock()
	handler.instances[startConfig.ID] = instance
	handler.mu.Unlock()
	go handler.waitCommand(instance, command)

	startSucceeded := false
	defer func() {
		if startSucceeded {
			return
		}
		instance.markDeleting()
		handler.stopInstance(instance, true)
		handler.mu.Lock()
		delete(handler.instances, startConfig.ID)
		handler.mu.Unlock()
	}()

	if err := attachFirecrackerProcess(startConfig.CgroupPath, command.Process.Pid); err != nil {
		return fmt.Errorf("attach Firecracker to cgroup: %w", err)
	}
	if err := handler.persistInstance(instance); err != nil {
		return err
	}

	bootCtx, cancel := context.WithTimeout(ctx, firecrackerAgentTimeout)
	defer cancel()
	api := newFirecrackerAPI(apiPath)
	if err := api.waitReady(bootCtx); err != nil {
		return err
	}
	vcpus, memoryMiB, err := handler.machineSize(startConfig.Resources)
	if err != nil {
		return err
	}
	instance.setMemoryMiB(memoryMiB)
	instance.setVcpus(vcpus)
	drives := []firecrackerDrive{
		plan.rootDrive,
		{
			ID:       "overlay",
			Path:     firecrackerCheckpointOverlayName,
			ReadOnly: false,
		},
	}
	drives = append(drives, plan.mountDrives...)
	if err := configureFirecrackerVM(
		bootCtx,
		api,
		handler.kernelPath,
		handler.initrdPath,
		handler.kernelArgs,
		vcpus,
		memoryMiB,
		startConfig.Network.Interface.Name,
		startConfig.Network.GuestHardwareAddr().String(),
		vsockPath,
		drives,
	); err != nil {
		return err
	}
	if err := waitForFirecrackerAgent(bootCtx, vsockPath); err != nil {
		return err
	}
	if err := requestFirecrackerAgent(
		bootCtx,
		vsockPath,
		firecrackerproto.MessageConfigure,
		plan.configure,
	); err != nil {
		return fmt.Errorf("configure Firecracker guest: %w", err)
	}
	instance.markConfigured()
	if err := handler.persistInstance(instance); err != nil {
		return err
	}
	go handler.waitGuest(instance)
	if err := runtimecommon.WriteSandboxRuntimeMarker(bundlePath, config.RuntimeNameFirecracker); err != nil {
		return fmt.Errorf("persist Firecracker runtime marker: %w", err)
	}
	startSucceeded = true
	keepStorage = true
	keepRuntimeArtifacts = true
	logrus.Infof(
		"firecracker: started sandbox %s pid=%d vcpus=%d memory=%dMiB",
		startConfig.ID,
		command.Process.Pid,
		vcpus,
		memoryMiB,
	)
	return nil
}

func openFirecrackerOutput(path string) (*os.File, error) {
	if path == "" {
		return os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
}

func (handler *Handler) machineSize(
	resources interface {
		GetCpuQuota() int64
		GetCpuPeriod() uint64
		GetCpuShares() uint64
		GetMemoryLimitInBytes() int64
	},
) (uint32, uint32, error) {
	vcpus := uint64(handler.defaultVCPUs)
	memoryMiB := uint64(handler.defaultMem)
	if resources != nil {
		switch {
		case resources.GetCpuQuota() > 0 && resources.GetCpuPeriod() > 0:
			quota := uint64(resources.GetCpuQuota())
			vcpus = (quota-1)/resources.GetCpuPeriod() + 1
		case resources.GetCpuShares() > 0:
			vcpus = (resources.GetCpuShares()-1)/1024 + 1
		}
		if resources.GetMemoryLimitInBytes() > 0 {
			const mebibyte = uint64(1024 * 1024)
			memoryBytes := uint64(resources.GetMemoryLimitInBytes())
			memoryMiB = (memoryBytes-1)/mebibyte + 1
		}
	}
	if vcpus == 0 || vcpus > uint64(firecrackerMaxVCPUs) {
		return 0, 0, fmt.Errorf(
			"Firecracker vCPU count %d is outside 1..%d",
			vcpus,
			firecrackerMaxVCPUs,
		)
	}
	if memoryMiB < uint64(firecrackerMinMemoryMiB) {
		return 0, 0, fmt.Errorf(
			"Firecracker requires at least %d MiB of memory, got %d MiB",
			firecrackerMinMemoryMiB,
			memoryMiB,
		)
	}
	if memoryMiB > uint64(^uint32(0)) {
		return 0, 0, fmt.Errorf(
			"Firecracker memory size %d MiB exceeds the API limit",
			memoryMiB,
		)
	}
	return uint32(vcpus), uint32(memoryMiB), nil
}

func (handler *Handler) Delete(ctx context.Context, sandboxID string) error {
	instance, err := handler.lookupInstance(sandboxID)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	instance.operationMu.Lock()
	defer instance.operationMu.Unlock()
	instance.markDeleting()
	state := instance.snapshot()
	if firecrackerProcessMatches(state.PID, handler.binary, state.APIPath, state.ID) {
		shutdownCtx, cancel := context.WithTimeout(
			context.WithoutCancel(ctx),
			500*time.Millisecond,
		)
		err := requestFirecrackerAgent(
			shutdownCtx,
			state.VsockPath,
			firecrackerproto.MessageShutdown,
			nil,
		)
		cancel()
		if err != nil {
			logrus.Debugf("firecracker: guest shutdown %s: %v", sandboxID, err)
		}
	}
	handler.stopInstance(instance, false)
	handler.mu.Lock()
	delete(handler.instances, sandboxID)
	handler.mu.Unlock()
	return errors.Join(
		os.RemoveAll(filepath.Join(state.BundlePath, firecrackerArtifactsDir)),
		handler.cleanupRuntimeDirectory(sandboxID, state.APIPath),
		cleanupFirecrackerOverlay(handler.storageRoot, sandboxID),
	)
}

func (handler *Handler) runtimeDirectory(sandboxID string) string {
	return firecrackerproto.HostRuntimeDirectory(
		handler.runtimeRoot,
		sandboxID,
	)
}

func (handler *Handler) cleanupRuntimeDirectory(
	sandboxID,
	apiPath string,
) error {
	expected := handler.runtimeDirectory(sandboxID)
	if filepath.Clean(filepath.Dir(apiPath)) != filepath.Clean(expected) {
		return fmt.Errorf(
			"refuse to remove inconsistent Firecracker socket directory %s for %s",
			filepath.Dir(apiPath),
			sandboxID,
		)
	}
	if err := os.RemoveAll(expected); err != nil {
		return fmt.Errorf(
			"remove Firecracker socket directory %s: %w",
			expected,
			err,
		)
	}
	return nil
}

func (handler *Handler) List(context.Context) ([]*runtimecore.State, error) {
	handler.mu.RLock()
	instances := make([]*firecrackerInstance, 0, len(handler.instances))
	for _, instance := range handler.instances {
		instances = append(instances, instance)
	}
	handler.mu.RUnlock()
	result := make([]*runtimecore.State, 0, len(instances))
	for _, instance := range instances {
		state := instance.snapshot()
		status := runtimecore.SandboxStatusRunning
		if state.Exited ||
			!firecrackerProcessMatches(state.PID, handler.binary, state.APIPath, state.ID) {
			status = runtimecore.SandboxStatusExited
		}
		result = append(result, &runtimecore.State{
			ID:             state.ID,
			InitProcessPid: state.PID,
			Status:         status,
			Created:        state.CreatedAt,
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func (handler *Handler) Wait(
	ctx context.Context,
	sandboxID string,
) (runtimecore.Exit, error) {
	instance, err := handler.lookupInstance(sandboxID)
	if err != nil {
		return runtimecore.Exit{}, err
	}
	select {
	case <-instance.done:
		return instance.result(), nil
	case <-ctx.Done():
		return runtimecore.Exit{}, ctx.Err()
	}
}

func (handler *Handler) lookupInstance(
	sandboxID string,
) (*firecrackerInstance, error) {
	handler.mu.RLock()
	instance := handler.instances[sandboxID]
	handler.mu.RUnlock()
	if instance != nil {
		return instance, nil
	}
	bundlePath, err := util.JoinWithinRoot(handler.sandboxRoot, sandboxID)
	if err != nil {
		return nil, err
	}
	state, err := readFirecrackerState(bundlePath)
	if err != nil {
		return nil, err
	}
	if err := handler.validatePersistedState(sandboxID, bundlePath, state); err != nil {
		return nil, err
	}
	instance = handler.recoverState(state)
	handler.mu.Lock()
	if existing := handler.instances[sandboxID]; existing != nil {
		instance = existing
	} else {
		handler.instances[sandboxID] = instance
	}
	handler.mu.Unlock()
	return instance, nil
}

func (handler *Handler) waitCommand(
	instance *firecrackerInstance,
	command *exec.Cmd,
) {
	err := command.Wait()
	select {
	case <-instance.done:
		return
	case <-time.After(250 * time.Millisecond):
	}
	exit := runtimecore.Exit{ExitedAt: time.Now(), ExitCode: firecrackerHostExitCode(err)}
	if instance.finish(exit) && instance.shouldPersist() {
		if persistErr := handler.persistInstance(instance); persistErr != nil {
			logrus.Warnf("firecracker: persist exit state: %v", persistErr)
		}
	}
}

func (handler *Handler) waitGuest(
	instance *firecrackerInstance,
) {
	state := instance.snapshot()
	connection, err := firecrackerproto.DialAgent(
		state.VsockPath,
		5*time.Second,
	)
	if err != nil {
		logrus.Warnf("firecracker: wait guest %s: %v", state.ID, err)
		return
	}
	defer connection.Close()
	if err := firecrackerproto.WriteMessage(
		connection,
		firecrackerproto.MessageWait,
		nil,
	); err != nil {
		logrus.Warnf("firecracker: request guest wait %s: %v", state.ID, err)
		return
	}
	exitCode, err := firecrackerproto.ReadWaitResponse(connection)
	if err != nil {
		logrus.Warnf("firecracker: read guest exit %s: %v", state.ID, err)
		return
	}
	if !instance.finish(runtimecore.Exit{
		ExitedAt: time.Now(),
		ExitCode: exitCode,
	}) || !instance.shouldPersist() {
		return
	}
	if err := handler.persistInstance(instance); err != nil {
		logrus.Warnf("firecracker: persist guest exit state: %v", err)
		return
	}
	// The agent remains guest PID 1 after the sandbox command exits. Stop the
	// VMM once its exit status is durable so it cannot retain guest resources.
	handler.stopInstance(instance, true)
}

func (handler *Handler) stopInstance(
	instance *firecrackerInstance,
	force bool,
) {
	state := instance.snapshot()
	if !firecrackerProcessMatches(state.PID, handler.binary, state.APIPath, state.ID) {
		instance.finish(runtimecore.Exit{ExitedAt: time.Now(), ExitCode: state.ExitCode})
		return
	}
	if !force && waitFirecrackerProcess(
		state,
		handler.binary,
		firecrackerShutdownTimeout,
	) {
		return
	}
	_ = signalFirecrackerProcess(state, handler.binary, syscall.SIGTERM)
	if waitFirecrackerProcess(state, handler.binary, 500*time.Millisecond) {
		return
	}
	_ = signalFirecrackerProcess(state, handler.binary, syscall.SIGKILL)
	if !waitFirecrackerProcess(state, handler.binary, time.Second) {
		logrus.Warnf("firecracker: VMM pid %d did not exit after SIGKILL", state.PID)
	}
}

func waitFirecrackerProcess(
	state firecrackerPersistedState,
	binary string,
	timeout time.Duration,
) bool {
	deadline := time.Now().Add(timeout)
	for {
		if !firecrackerProcessMatches(
			state.PID,
			binary,
			state.APIPath,
			state.ID,
		) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func signalFirecrackerProcess(
	state firecrackerPersistedState,
	binary string,
	signal syscall.Signal,
) error {
	if !firecrackerProcessMatches(state.PID, binary, state.APIPath, state.ID) {
		return nil
	}
	group, err := syscall.Getpgid(state.PID)
	if err == nil && group == state.PID {
		return syscall.Kill(-state.PID, signal)
	}
	return syscall.Kill(state.PID, signal)
}

func firecrackerHostExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		if status, ok := exitError.Sys().(syscall.WaitStatus); ok {
			if status.Signaled() {
				return 128 + int(status.Signal())
			}
			return status.ExitStatus()
		}
	}
	return 255
}

func (handler *Handler) persistInstance(
	instance *firecrackerInstance,
) error {
	state := instance.snapshot()
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(
		state.BundlePath,
		firecrackerArtifactsDir,
		firecrackerStateFilename,
	)
	if err := util.AtomicWriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("persist Firecracker state %s: %w", path, err)
	}
	return nil
}

func readFirecrackerState(bundlePath string) (firecrackerPersistedState, error) {
	path := filepath.Join(
		bundlePath,
		firecrackerArtifactsDir,
		firecrackerStateFilename,
	)
	data, err := os.ReadFile(path)
	if err != nil {
		return firecrackerPersistedState{}, err
	}
	var state firecrackerPersistedState
	if err := json.Unmarshal(data, &state); err != nil {
		return firecrackerPersistedState{}, fmt.Errorf("decode %s: %w", path, err)
	}
	return state, nil
}

func (handler *Handler) validatePersistedState(
	sandboxID,
	bundlePath string,
	state firecrackerPersistedState,
) error {
	if state.ID != sandboxID {
		return fmt.Errorf(
			"Firecracker state ID %q does not match sandbox %q",
			state.ID,
			sandboxID,
		)
	}
	runtimeDirectory := handler.runtimeDirectory(sandboxID)
	storageDirectory, err := util.JoinWithinRoot(handler.storageRoot, sandboxID)
	if err != nil {
		return err
	}
	expected := map[string][2]string{
		"bundle": {
			filepath.Clean(state.BundlePath),
			filepath.Clean(bundlePath),
		},
		"API socket": {
			filepath.Clean(state.APIPath),
			filepath.Join(runtimeDirectory, firecrackerAPISocket),
		},
		"vsock": {
			filepath.Clean(state.VsockPath),
			filepath.Join(runtimeDirectory, firecrackerVsock),
		},
		"overlay": {
			filepath.Clean(state.OverlayPath),
			filepath.Join(storageDirectory, "overlay.ext4"),
		},
	}
	for description, paths := range expected {
		if paths[0] != paths[1] {
			return fmt.Errorf(
				"Firecracker state %s path %q does not match %q",
				description,
				paths[0],
				paths[1],
			)
		}
	}
	return nil
}

func (handler *Handler) recoverInstances() {
	entries, err := os.ReadDir(handler.sandboxRoot)
	if err != nil {
		logrus.Warnf("firecracker: scan runtime state: %v", err)
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() || !config.IsValidSandboxID(entry.Name()) {
			continue
		}
		bundlePath, err := util.JoinWithinRoot(handler.sandboxRoot, entry.Name())
		if err != nil {
			continue
		}
		state, err := readFirecrackerState(bundlePath)
		if err != nil {
			if !os.IsNotExist(err) {
				logrus.Warnf("firecracker: read state for %s: %v", entry.Name(), err)
			}
			continue
		}
		if err := handler.validatePersistedState(entry.Name(), bundlePath, state); err != nil {
			logrus.Warnf("firecracker: ignore inconsistent state for %s: %v", entry.Name(), err)
			continue
		}
		handler.instances[state.ID] = handler.recoverState(state)
	}
}

func (handler *Handler) recoverState(
	state firecrackerPersistedState,
) *firecrackerInstance {
	instance := &firecrackerInstance{state: state, done: make(chan struct{})}
	if state.Exited {
		exitTime, _ := time.Parse(time.RFC3339Nano, state.ExitedAt)
		if exitTime.IsZero() {
			exitTime = time.Now()
		}
		instance.finish(runtimecore.Exit{ExitedAt: exitTime, ExitCode: state.ExitCode})
		if firecrackerProcessMatches(state.PID, handler.binary, state.APIPath, state.ID) {
			go handler.stopInstance(instance, true)
		}
		return instance
	}
	if !firecrackerProcessMatches(state.PID, handler.binary, state.APIPath, state.ID) {
		exitTime, _ := time.Parse(time.RFC3339Nano, state.ExitedAt)
		if exitTime.IsZero() {
			exitTime = time.Now()
		}
		instance.finish(runtimecore.Exit{ExitedAt: exitTime, ExitCode: 255})
		return instance
	}
	if !state.Configured {
		logrus.Warnf(
			"firecracker: terminate incomplete sandbox %s pid=%d",
			state.ID,
			state.PID,
		)
		_ = signalFirecrackerProcess(state, handler.binary, syscall.SIGKILL)
		instance.finish(runtimecore.Exit{ExitedAt: time.Now(), ExitCode: 255})
		if err := handler.persistInstance(instance); err != nil {
			logrus.Warnf("firecracker: persist incomplete state: %v", err)
		}
		return instance
	}
	// A daemon restart cannot know which generation the surviving VMM's
	// dirty-page ledger is armed against: a checkpoint may have completed in
	// the VMM (re-arming the window) without sandboxd persisting the new
	// base. Never trust a pre-restart incremental lineage — drop the base on
	// the recovered instance itself and force the next checkpoint to Full,
	// which ignores the ledger and safely restarts the chain. Persist the
	// reset so a second restart cannot resurrect the stale base. A sandbox
	// that never checkpointed also pays one Full snapshot here; its ledger
	// is disarmed, so that is only a completeness cost, never a correctness
	// one.
	instance.markBaseMemoryLineageLost()
	if err := handler.persistInstance(instance); err != nil {
		logrus.Warnf(
			"firecracker: persist lineage reset for recovered sandbox %s: %v",
			state.ID, err,
		)
	}
	go handler.waitGuest(instance)
	go handler.monitorRecovered(instance)
	logrus.Infof("firecracker: recovered sandbox %s pid=%d", state.ID, state.PID)
	return instance
}

func (handler *Handler) monitorRecovered(
	instance *firecrackerInstance,
) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for range ticker.C {
		state := instance.snapshot()
		if firecrackerProcessMatches(state.PID, handler.binary, state.APIPath, state.ID) {
			continue
		}
		if instance.finish(runtimecore.Exit{ExitedAt: time.Now(), ExitCode: 255}) &&
			instance.shouldPersist() {
			if err := handler.persistInstance(instance); err != nil {
				logrus.Warnf("firecracker: persist recovered exit state: %v", err)
			}
		}
		return
	}
}

func firecrackerProcessMatches(pid int, binary, apiPath, id string) bool {
	if pid <= 1 || syscall.Kill(pid, 0) != nil {
		return false
	}
	stat, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return false
	}
	closeParen := strings.LastIndexByte(string(stat), ')')
	if closeParen < 0 || len(stat) <= closeParen+2 || stat[closeParen+2] == 'Z' {
		return false
	}
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil || len(data) == 0 {
		return false
	}
	arguments := strings.Split(strings.TrimRight(string(data), "\x00"), "\x00")
	if len(arguments) == 0 ||
		filepath.Clean(arguments[0]) != filepath.Clean(binary) {
		return false
	}
	executable, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if err != nil {
		return false
	}
	executable = strings.TrimSuffix(executable, " (deleted)")
	if filepath.Clean(executable) != filepath.Clean(binary) {
		return false
	}
	hasAPI := false
	hasID := false
	for index := 0; index < len(arguments); index++ {
		switch {
		case arguments[index] == "--api-sock" && index+1 < len(arguments):
			hasAPI = filepath.Clean(arguments[index+1]) == filepath.Clean(apiPath)
		case strings.HasPrefix(arguments[index], "--api-sock="):
			hasAPI = filepath.Clean(strings.TrimPrefix(arguments[index], "--api-sock=")) ==
				filepath.Clean(apiPath)
		case arguments[index] == "--id" && index+1 < len(arguments):
			hasID = arguments[index+1] == id
		case strings.HasPrefix(arguments[index], "--id="):
			hasID = strings.TrimPrefix(arguments[index], "--id=") == id
		}
	}
	return hasAPI && hasID
}

func attachFirecrackerProcess(cgroupPath string, pid int) error {
	if cgroupPath == "" || pid <= 1 {
		return errors.New("invalid Firecracker cgroup attachment")
	}
	switch mode := cgroups.Mode(); mode {
	case cgroups.Unified:
		group, err := cgroup2.Load(
			cgroupPath,
			cgroup2.WithMountpoint("/sys/fs/cgroup"),
		)
		if err != nil {
			return err
		}
		return group.AddProc(uint64(pid))
	case cgroups.Legacy, cgroups.Hybrid:
		group, err := cgroup1.Load(
			cgroup1.StaticPath(cgroupPath),
			cgroup1.WithHiearchy(cgroup1.Default),
		)
		if err != nil {
			return err
		}
		return group.AddProc(uint64(pid))
	default:
		return fmt.Errorf("cgroup mode %d is unavailable", mode)
	}
}

func waitForFirecrackerAgent(ctx context.Context, vsockPath string) error {
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		err := requestFirecrackerAgent(
			ctx,
			vsockPath,
			firecrackerproto.MessageHealth,
			nil,
		)
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for Firecracker guest agent: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func requestFirecrackerAgent(
	ctx context.Context,
	vsockPath string,
	messageType firecrackerproto.MessageType,
	value any,
) error {
	return requestFirecrackerAgentWaiting(ctx, vsockPath, messageType, value, time.Second)
}

// requestFirecrackerAgentWaiting is requestFirecrackerAgent with a caller-set
// cap on the dial timeout (used by the checkpoint flush, which may legitimately
// wait out a slow guest sync).
func requestFirecrackerAgentWaiting(
	ctx context.Context,
	vsockPath string,
	messageType firecrackerproto.MessageType,
	value any,
	maxWait time.Duration,
) error {
	timeout := maxWait
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
		if timeout <= 0 {
			return ctx.Err()
		}
		if timeout > maxWait {
			timeout = maxWait
		}
	}
	connection, err := firecrackerproto.DialAgent(vsockPath, timeout)
	if err != nil {
		return err
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if err := firecrackerproto.WriteMessage(connection, messageType, value); err != nil {
		return err
	}
	return firecrackerproto.ReadResponse(connection)
}
