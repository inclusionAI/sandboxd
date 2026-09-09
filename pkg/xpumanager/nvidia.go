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

package xpumanager

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	api "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/sirupsen/logrus"
)

const (
	nvidiaVisibleDevicesEnv  = "NVIDIA_VISIBLE_DEVICES"
	nvidiaDriverCapabilities = "NVIDIA_DRIVER_CAPABILITIES"
	cudaVisibleDevicesEnv    = "CUDA_VISIBLE_DEVICES"
	nvidiaDriverCapsValue    = "compute,utility"
	nvidiaRuntimeHookPath    = "/usr/bin/nvidia-container-runtime-hook"
	nvidiaRuntimeHookArg     = "nvidia-container-runtime-hook"
	nvidiaContainerCLI       = "nvidia-container-cli"
	nvidiaControlDevice      = "/dev/nvidiactl"
	nvidiaUVMDevice          = "/dev/nvidia-uvm"
	nvidiaDiscoveryTimeout   = 15 * time.Second
)

var nvidiaModelSeparator = regexp.MustCompile(`[^a-z0-9._-]+`)

type commandRunner func(context.Context, string, ...string) ([]byte, error)
type statFunc func(string) (os.FileInfo, error)

// Device contains NVIDIA-private identity for one scheduler-visible ID.
type Device struct {
	ID           uint32
	UUID         string
	ProductModel string
}

type nvidiaProvider struct {
	mu sync.RWMutex

	runscBinary string
	runcEnabled bool
	sandboxRoot string
	run         commandRunner
	stat        statFunc
	runscReady  bool

	devices   map[uint32]Device
	resources []Resource
	leases    map[string]string
	healthy   bool
	reason    error
}

func newNVIDIAProvider(runscBinary string, runcEnabled bool, sandboxRoot string) *nvidiaProvider {
	provider := &nvidiaProvider{
		runscBinary: runscBinary,
		runcEnabled: runcEnabled,
		sandboxRoot: sandboxRoot,
		run:         runCommand,
		stat:        os.Stat,
		devices:     make(map[uint32]Device),
		leases:      make(map[string]string),
	}
	if err := provider.discoverNVIDIA(); err != nil {
		provider.reason = err
		return provider
	}
	if err := provider.restoreLeases(); err != nil {
		provider.reason = err
		provider.resources = nil
		return provider
	}
	provider.healthy = true
	logrus.Infof("xpumanager: discovered %d schedulable NVIDIA GPU(s)", len(provider.devices))
	return provider
}

func runCommand(ctx context.Context, binary string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, binary, args...)
	output, err := command.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf(
			"%s %s: %w: %s",
			binary,
			strings.Join(args, " "),
			err,
			strings.TrimSpace(string(output)),
		)
	}
	return output, nil
}

func (m *nvidiaProvider) discoverNVIDIA() error {
	if m.runscBinary == "" && !m.runcEnabled {
		return errors.New("neither runsc nor runc runtime is configured")
	}
	cliPath, err := exec.LookPath(nvidiaContainerCLI)
	if err != nil {
		return fmt.Errorf("locate %s: %w", nvidiaContainerCLI, err)
	}
	if err := validateNVIDIARuntimeHook(nvidiaRuntimeHookPath, m.stat); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), nvidiaDiscoveryTimeout)
	defer cancel()
	infoOutput, err := m.run(ctx, cliPath, "--load-kmods", "info")
	if err != nil {
		return fmt.Errorf("discover NVIDIA devices: %w", err)
	}
	driverVersion, devices, err := parseNVIDIAInfo(string(infoOutput))
	if err != nil {
		return err
	}
	for _, path := range []string{nvidiaControlDevice, nvidiaUVMDevice} {
		if _, err := m.stat(path); err != nil {
			return fmt.Errorf("required NVIDIA device %s is unavailable: %w", path, err)
		}
	}
	if err := m.configureRuntimeSupport(ctx, driverVersion); err != nil {
		return err
	}

	m.devices = devices
	m.resources = buildResources(devices)
	return nil
}

func (m *nvidiaProvider) configureRuntimeSupport(ctx context.Context, driverVersion string) error {
	if m.runscBinary == "" {
		return nil
	}
	supportedOutput, err := m.run(ctx, m.runscBinary, "nvproxy", "list-supported-drivers")
	if err == nil && nvidiaDriverSupported(driverVersion, string(supportedOutput)) {
		m.runscReady = true
		return nil
	}
	if err != nil {
		err = fmt.Errorf("list runsc nvproxy drivers: %w", err)
	} else {
		err = fmt.Errorf("NVIDIA driver %s is not supported by %s nvproxy", driverVersion, m.runscBinary)
	}
	if !m.runcEnabled {
		return err
	}
	logrus.Warnf("xpumanager: runsc GPU support unavailable; runc remains enabled: %v", err)
	return nil
}

func validateNVIDIARuntimeHook(path string, stat statFunc) error {
	hookInfo, err := stat(path)
	if err != nil {
		return fmt.Errorf("stat NVIDIA runtime hook %s: %w", path, err)
	}
	if !hookInfo.Mode().IsRegular() || hookInfo.Mode().Perm()&0111 == 0 {
		return fmt.Errorf("NVIDIA runtime hook %s must be an executable regular file", path)
	}
	return nil
}

// ReservedEnv reports whether key is controlled by the NVIDIA provider.
func reservedNVIDIAEnv(key string) bool {
	switch key {
	case nvidiaVisibleDevicesEnv, nvidiaDriverCapabilities, cudaVisibleDevicesEnv:
		return true
	default:
		return false
	}
}

func nvidiaSpecUpdates(runtimeName string, uuids []string, recordJSON []byte) *svc.SpecUpdates {
	logicalIDs := make([]string, len(uuids))
	for index := range uuids {
		logicalIDs[index] = strconv.Itoa(index)
	}
	return &svc.SpecUpdates{
		Envs: []*api.KeyValue{
			{Key: nvidiaVisibleDevicesEnv, Value: strings.Join(uuids, ",")},
			{Key: nvidiaDriverCapabilities, Value: nvidiaDriverCapsValue},
			{Key: cudaVisibleDevicesEnv, Value: strings.Join(logicalIDs, ",")},
		},
		Prestart: []svc.Hook{{
			Path: nvidiaRuntimeHookPath,
			Args: []string{nvidiaRuntimeHookArg, "prestart"},
		}},
		Annotations: map[string]string{
			AllocationAnnotation: string(recordJSON),
		},
		RequiresHostWritableRootfs: runtimeName == config.RuntimeNameRunsc,
	}
}

func (m *nvidiaProvider) Type() string { return TypeGPU }

func (m *nvidiaProvider) SupportsRuntime(runtimeName string) bool {
	return runtimeName == config.RuntimeNameRunsc && m.runscReady ||
		runtimeName == config.RuntimeNameRunc && m.runcEnabled
}

func (m *nvidiaProvider) Healthy() (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.healthy, m.reason
}

func (m *nvidiaProvider) Resources() []Resource {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.healthy {
		return []Resource{}
	}
	resources := make([]Resource, len(m.resources))
	for index := range m.resources {
		resources[index] = m.resources[index]
		resources[index].DeviceIDs = append([]uint32(nil), m.resources[index].DeviceIDs...)
	}
	return resources
}

func (m *nvidiaProvider) Acquire(
	sandboxID, runtimeName string,
	allocation *api.XpuAllocation,
) (*svc.SpecUpdates, error) {
	if sandboxID == "" {
		return nil, errors.New("sandbox ID is required for XPU allocation")
	}
	if !m.SupportsRuntime(runtimeName) {
		return nil, fmt.Errorf("GPU allocations are unavailable for runtime %q", runtimeName)
	}
	if allocation == nil || strings.ToLower(strings.TrimSpace(allocation.Type)) != TypeGPU {
		return nil, errors.New("invalid GPU allocation")
	}
	if len(allocation.DeviceIds) == 0 {
		return nil, errors.New("XPU device IDs must not be empty")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.healthy {
		return nil, fmt.Errorf("GPU support is unavailable: %w", m.reason)
	}
	seen := make(map[uint32]struct{}, len(allocation.DeviceIds))
	devices := make([]Device, 0, len(allocation.DeviceIds))
	for _, id := range allocation.DeviceIds {
		if _, duplicate := seen[id]; duplicate {
			return nil, fmt.Errorf("duplicate GPU device ID %d", id)
		}
		seen[id] = struct{}{}
		device, ok := m.devices[id]
		if !ok {
			return nil, fmt.Errorf("GPU device ID %d is not in the node inventory", id)
		}
		if owner, leased := m.leases[device.UUID]; leased && owner != sandboxID {
			return nil, fmt.Errorf("GPU device ID %d is already leased by sandbox %s", id, owner)
		}
		devices = append(devices, device)
	}
	model := devices[0].ProductModel
	for _, device := range devices[1:] {
		if device.ProductModel != model {
			return nil, errors.New("all GPU devices in one allocation must have the same product model")
		}
	}
	uuids := make([]string, len(devices))
	for index, device := range devices {
		m.leases[device.UUID] = sandboxID
		uuids[index] = device.UUID
	}
	recordJSON, err := encodeLease(leaseRecord{
		SandboxID:       sandboxID,
		Type:            TypeGPU,
		Runtime:         runtimeName,
		ProductModel:    model,
		SchedulerIDs:    append([]uint32(nil), allocation.DeviceIds...),
		StableIDs:       append([]string(nil), uuids...),
		Provider:        "nvidia",
		ProviderVersion: "nvidia-container-cli",
	})
	if err != nil {
		for _, uuid := range uuids {
			delete(m.leases, uuid)
		}
		return nil, fmt.Errorf("encode GPU lease: %w", err)
	}
	return nvidiaSpecUpdates(runtimeName, uuids, recordJSON), nil
}

func (m *nvidiaProvider) Release(sandboxID string) {
	if sandboxID == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for uuid, owner := range m.leases {
		if owner == sandboxID {
			delete(m.leases, uuid)
		}
	}
}

func (m *nvidiaProvider) restoreLeases() error {
	leases, err := readPersistedLeases(m.sandboxRoot)
	if err != nil {
		return err
	}
	for _, persisted := range leases {
		record := persisted.record
		if record.Type != TypeGPU {
			continue
		}
		if record.SchemaVersion >= leaseSchemaVersion &&
			(record.Runtime != config.RuntimeNameRunsc && record.Runtime != config.RuntimeNameRunc) {
			return fmt.Errorf("invalid GPU runtime %q in %s", record.Runtime, persisted.bundlePath)
		}
		ids := record.SchedulerIDs
		stableIDs := record.StableIDs
		if record.SchemaVersion <= 1 {
			ids = record.DeviceIDs
			stableIDs = record.DeviceUUID
		}
		if len(ids) == 0 || len(ids) != len(stableIDs) {
			return fmt.Errorf("invalid GPU allocation annotation in %s", persisted.bundlePath)
		}
		for index, id := range ids {
			device, ok := m.devices[id]
			if !ok || device.UUID != stableIDs[index] {
				return fmt.Errorf("GPU identity changed for device ID %d in %s", id, persisted.bundlePath)
			}
			if owner, duplicate := m.leases[device.UUID]; duplicate && owner != record.SandboxID {
				return fmt.Errorf("GPU UUID %s is assigned to both %s and %s", device.UUID, owner, record.SandboxID)
			}
			m.leases[device.UUID] = record.SandboxID
		}
	}
	return nil
}

func buildResources(devices map[uint32]Device) []Resource {
	byModel := make(map[string][]uint32)
	for id, device := range devices {
		byModel[device.ProductModel] = append(byModel[device.ProductModel], id)
	}
	models := make([]string, 0, len(byModel))
	for model := range byModel {
		models = append(models, model)
	}
	sort.Strings(models)
	resources := make([]Resource, 0, len(models))
	for _, model := range models {
		ids := byModel[model]
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		resources = append(resources, Resource{
			Type:         TypeGPU,
			ProductModel: model,
			DeviceIDs:    ids,
		})
	}
	return resources
}

func parseNVIDIAInfo(output string) (string, map[uint32]Device, error) {
	driverVersion := ""
	devices := make(map[uint32]Device)
	var current *Device
	commit := func() error {
		if current == nil {
			return nil
		}
		if current.UUID == "" || current.ProductModel == "" {
			return fmt.Errorf("incomplete NVIDIA device record for index %d", current.ID)
		}
		if _, duplicate := devices[current.ID]; duplicate {
			return fmt.Errorf("duplicate NVIDIA device index %d", current.ID)
		}
		devices[current.ID] = *current
		current = nil
		return nil
	}

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch key {
		case "NVRM version":
			driverVersion = value
		case "Device Index":
			if err := commit(); err != nil {
				return "", nil, err
			}
			parsed, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return "", nil, fmt.Errorf("parse NVIDIA device index %q: %w", value, err)
			}
			current = &Device{ID: uint32(parsed)}
		case "Model":
			if current != nil {
				current.ProductModel = normalizeNVIDIAModel(value)
			}
		case "GPU UUID":
			if current != nil {
				current.UUID = value
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return "", nil, err
	}
	if err := commit(); err != nil {
		return "", nil, err
	}
	if driverVersion == "" {
		return "", nil, errors.New("NVIDIA discovery output has no NVRM version")
	}
	if len(devices) == 0 {
		return "", nil, errors.New("NVIDIA discovery output has no GPU devices")
	}
	return driverVersion, devices, nil
}

func nvidiaDriverSupported(driverVersion, output string) bool {
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) == driverVersion {
			return true
		}
	}
	return false
}

func normalizeNVIDIAModel(model string) string {
	model = strings.ToLower(strings.TrimSpace(model))
	model = strings.TrimSpace(strings.TrimPrefix(model, "nvidia "))
	model = nvidiaModelSeparator.ReplaceAllString(model, "-")
	return strings.Trim(model, "-._")
}
