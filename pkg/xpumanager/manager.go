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

// Package xpumanager discovers node accelerators and owns the local,
// fail-closed device leases used to validate scheduler allocations.
package xpumanager

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
	TypeGPU = "gpu"

	AllocationAnnotation = "sandbox.akernel.dev/xpu-allocation"

	nvidiaVisibleDevicesEnv  = "NVIDIA_VISIBLE_DEVICES"
	nvidiaDriverCapabilities = "NVIDIA_DRIVER_CAPABILITIES"
	cudaVisibleDevicesEnv    = "CUDA_VISIBLE_DEVICES"
	nvidiaDriverCapsValue    = "compute,utility"
	nvidiaRuntimeHookPath    = "/usr/bin/nvidia-container-runtime-hook"
	nvidiaRuntimeHookArg     = "nvidia-container-runtime-hook"
	nvidiaContainerCLI       = "nvidia-container-cli"
	nvidiaControlDevice      = "/dev/nvidiactl"
	nvidiaUVMDevice          = "/dev/nvidia-uvm"
	discoveryTimeout         = 15 * time.Second
)

var modelSeparator = regexp.MustCompile(`[^a-z0-9._-]+`)

// Resource is the stable XPU capacity shape exported from /resource.
type Resource struct {
	Type         string   `json:"type"`
	ProductModel string   `json:"product_model"`
	DeviceIDs    []uint32 `json:"device_ids"`
}

// Device contains provider-private identity for one scheduler-visible ID.
type Device struct {
	ID           uint32
	UUID         string
	ProductModel string
}

type leaseRecord struct {
	SandboxID  string   `json:"sandbox_id"`
	Type       string   `json:"type"`
	DeviceIDs  []uint32 `json:"device_ids"`
	DeviceUUID []string `json:"device_uuids"`
}

type commandRunner func(context.Context, string, ...string) ([]byte, error)
type statFunc func(string) (os.FileInfo, error)

// Manager owns an immutable discovery snapshot and UUID-keyed leases.
type Manager struct {
	mu sync.RWMutex

	runscBinary string
	sandboxRoot string
	run         commandRunner
	stat        statFunc

	devices   map[uint32]Device
	resources []Resource
	leases    map[string]string
	healthy   bool
	reason    error
}

// New discovers the local NVIDIA inventory. Discovery failure is intentionally
// non-fatal for sandboxd: CPU-only nodes stay usable and advertise no XPU.
func New(runscBinary, sandboxRoot string) *Manager {
	manager := &Manager{
		runscBinary: runscBinary,
		sandboxRoot: sandboxRoot,
		run:         runCommand,
		stat:        os.Stat,
		devices:     make(map[uint32]Device),
		leases:      make(map[string]string),
	}
	if err := manager.discover(context.Background()); err != nil {
		manager.reason = err
		logrus.Infof("xpumanager: NVIDIA GPU support unavailable: %v", err)
		return manager
	}
	if err := manager.restoreLeases(); err != nil {
		manager.healthy = false
		manager.resources = nil
		manager.reason = err
		logrus.Errorf("xpumanager: refusing GPU allocations after lease recovery failure: %v", err)
		return manager
	}
	manager.healthy = true
	logrus.Infof("xpumanager: discovered %d schedulable NVIDIA GPU(s)", len(manager.devices))
	return manager
}

func runCommand(ctx context.Context, binary string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, binary, args...)
	output, err := command.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("%s %s: %w: %s", binary, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

func (m *Manager) discover(parent context.Context) error {
	if m.runscBinary == "" {
		return errors.New("runsc runtime is not configured")
	}
	cliPath, err := exec.LookPath(nvidiaContainerCLI)
	if err != nil {
		return fmt.Errorf("locate %s: %w", nvidiaContainerCLI, err)
	}

	ctx, cancel := context.WithTimeout(parent, discoveryTimeout)
	defer cancel()
	infoOutput, err := m.run(ctx, cliPath, "--load-kmods", "info")
	if err != nil {
		return fmt.Errorf("discover NVIDIA devices: %w", err)
	}
	driverVersion, devices, err := parseNvidiaInfo(string(infoOutput))
	if err != nil {
		return err
	}
	supportedOutput, err := m.run(ctx, m.runscBinary, "nvproxy", "list-supported-drivers")
	if err != nil {
		return fmt.Errorf("list runsc nvproxy drivers: %w", err)
	}
	if !driverSupported(driverVersion, string(supportedOutput)) {
		return fmt.Errorf("NVIDIA driver %s is not supported by %s nvproxy", driverVersion, m.runscBinary)
	}
	for _, path := range []string{nvidiaControlDevice, nvidiaUVMDevice} {
		if _, err := m.stat(path); err != nil {
			return fmt.Errorf("required NVIDIA device %s is unavailable: %w", path, err)
		}
	}

	m.devices = devices
	m.resources = buildResources(devices)
	return nil
}

// Resources returns a deep copy of the stable capacity inventory. Active
// leases never alter this list.
func (m *Manager) Resources() []Resource {
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

// ReservedEnv reports whether key is controlled by sandboxd's XPU provider.
func ReservedEnv(key string) bool {
	switch key {
	case nvidiaVisibleDevicesEnv, nvidiaDriverCapabilities, cudaVisibleDevicesEnv:
		return true
	default:
		return false
	}
}

// ReservedAnnotation reports whether key stores provider-owned allocation
// state. Callers must not be able to forge recovery metadata through labels.
func ReservedAnnotation(key string) bool {
	return key == AllocationAnnotation
}

// Acquire validates and atomically leases all requested devices.
func (m *Manager) Acquire(sandboxID string, allocations []*api.XpuAllocation) (*svc.SpecUpdates, error) {
	if len(allocations) == 0 {
		return nil, nil
	}
	if sandboxID == "" {
		return nil, errors.New("sandbox ID is required for XPU allocation")
	}
	if len(allocations) != 1 || allocations[0] == nil {
		return nil, errors.New("exactly one XPU allocation is supported")
	}
	allocation := allocations[0]
	if strings.ToLower(strings.TrimSpace(allocation.Type)) != TypeGPU {
		return nil, fmt.Errorf("unsupported XPU type %q", allocation.Type)
	}
	if len(allocation.DeviceIds) == 0 {
		return nil, errors.New("XPU device IDs must not be empty")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.healthy {
		if m.reason != nil {
			return nil, fmt.Errorf("GPU support is unavailable: %w", m.reason)
		}
		return nil, errors.New("GPU support is unavailable")
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
	for _, device := range devices {
		m.leases[device.UUID] = sandboxID
	}

	uuids := make([]string, len(devices))
	logicalIDs := make([]string, len(devices))
	for index, device := range devices {
		uuids[index] = device.UUID
		logicalIDs[index] = strconv.Itoa(index)
	}
	record := leaseRecord{
		SandboxID:  sandboxID,
		Type:       TypeGPU,
		DeviceIDs:  append([]uint32(nil), allocation.DeviceIds...),
		DeviceUUID: append([]string(nil), uuids...),
	}
	recordJSON, err := json.Marshal(record)
	if err != nil {
		for _, uuid := range uuids {
			delete(m.leases, uuid)
		}
		return nil, fmt.Errorf("encode GPU lease: %w", err)
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
	}, nil
}

// ReleaseSandbox releases all UUID leases owned by sandboxID. It is idempotent.
func (m *Manager) ReleaseSandbox(sandboxID string) {
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

func (m *Manager) restoreLeases() error {
	entries, err := os.ReadDir(m.sandboxRoot)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read sandbox root %s: %w", m.sandboxRoot, err)
	}
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), config.SandboxIDPrefix) {
			continue
		}
		configPath := filepath.Join(m.sandboxRoot, entry.Name(), config.SandboxSpecFile)
		data, err := os.ReadFile(configPath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return fmt.Errorf("read XPU lease from %s: %w", configPath, err)
		}
		var spec struct {
			Annotations map[string]string `json:"annotations"`
		}
		if err := json.Unmarshal(data, &spec); err != nil {
			return fmt.Errorf("parse XPU lease from %s: %w", configPath, err)
		}
		raw := spec.Annotations[AllocationAnnotation]
		if raw == "" {
			continue
		}
		var record leaseRecord
		if err := json.Unmarshal([]byte(raw), &record); err != nil {
			return fmt.Errorf("parse XPU allocation annotation in %s: %w", configPath, err)
		}
		if record.SandboxID != entry.Name() || record.Type != TypeGPU ||
			len(record.DeviceIDs) == 0 || len(record.DeviceIDs) != len(record.DeviceUUID) {
			return fmt.Errorf("invalid XPU allocation annotation in %s", configPath)
		}
		for index, id := range record.DeviceIDs {
			device, ok := m.devices[id]
			if !ok || device.UUID != record.DeviceUUID[index] {
				return fmt.Errorf("GPU identity changed for device ID %d in %s", id, configPath)
			}
			if owner, duplicate := m.leases[device.UUID]; duplicate && owner != record.SandboxID {
				return fmt.Errorf("GPU UUID %s is assigned to both %s and %s", device.UUID, owner, record.SandboxID)
			}
			m.leases[device.UUID] = record.SandboxID
		}
	}
	return nil
}

func parseNvidiaInfo(output string) (string, map[uint32]Device, error) {
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
				current.ProductModel = normalizeModel(value)
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

func driverSupported(driverVersion, output string) bool {
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) == driverVersion {
			return true
		}
	}
	return false
}

func normalizeModel(model string) string {
	model = strings.ToLower(strings.TrimSpace(model))
	model = strings.TrimSpace(strings.TrimPrefix(model, "nvidia "))
	model = modelSeparator.ReplaceAllString(model, "-")
	return strings.Trim(model, "-._")
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
