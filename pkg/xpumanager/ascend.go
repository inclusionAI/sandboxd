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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	api "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
)

const (
	ascendSchemaVersion       = 1
	defaultAdapterTimeout     = 10 * time.Second
	maxAdapterInputBytes      = 1 << 20
	maxAdapterOutputBytes     = 4 << 20
	ascendRuntimeFamily       = "Ascend910"
	ascend310PRuntimeFamily   = "Ascend310P"
	ascendProviderName        = "ascend-cdi"
	ascendVisibleDevicesEnv   = "ASCEND_VISIBLE_DEVICES"
	ascendRTVisibleDevicesEnv = "ASCEND_RT_VISIBLE_DEVICES"
)

var allowedAscendSharedDevices = map[string]struct{}{
	"/dev/davinci_manager": {},
	"/dev/devmm_svm":       {},
	"/dev/hisi_hdc":        {},
	"/dev/dvpp_cmdlist":    {},
}

type adapterVersion struct {
	SchemaVersion   int    `json:"schema_version"`
	ProviderVersion string `json:"provider_version"`
}

type ascendDevice struct {
	SchedulerID    uint32 `json:"scheduler_id"`
	LogicID        int32  `json:"logic_id"`
	PhysicalID     int32  `json:"physical_id"`
	StableID       string `json:"stable_id"`
	ProductModel   string `json:"product_model"`
	Generation     string `json:"generation"`
	RuntimeFamily  string `json:"runtime_family"`
	ResourceFamily string `json:"resource_family"`
	RawProduct     string `json:"raw_product"`
	Healthy        bool   `json:"healthy"`
}

type adapterDiscovery struct {
	SchemaVersion   int            `json:"schema_version"`
	ProviderVersion string         `json:"provider_version"`
	Devices         []ascendDevice `json:"devices"`
}

type adapterEditsRequest struct {
	SchemaVersion int     `json:"schema_version"`
	LogicIDs      []int32 `json:"logic_ids"`
	RuntimeFamily string  `json:"runtime_family"`
	PhysicalOnly  bool    `json:"physical_only"`
	MountProfile  string  `json:"mount_profile"`
}

type adapterDevice struct {
	HostPath      string `json:"host_path"`
	ContainerPath string `json:"container_path"`
	Type          string `json:"type"`
	Major         int64  `json:"major"`
	Minor         int64  `json:"minor"`
	Permissions   string `json:"permissions"`
}

type adapterMount struct {
	Source      string   `json:"source"`
	Destination string   `json:"destination"`
	Type        string   `json:"type"`
	Options     []string `json:"options"`
}

type adapterEdits struct {
	SchemaVersion   int               `json:"schema_version"`
	ProviderVersion string            `json:"provider_version"`
	Devices         []adapterDevice   `json:"devices"`
	SharedDevices   []adapterDevice   `json:"shared_devices"`
	Mounts          []adapterMount    `json:"mounts"`
	Env             map[string]string `json:"env"`
}

type mountProfile map[string][]profileMountGroup

type profileMountGroup struct {
	Paths []string `json:"path"`
	Type  string   `json:"type,omitempty"`
}

type deviceStatFunc func(string) (deviceType string, major, minor int64, err error)

type boundedBuffer struct {
	bytes.Buffer
	limit    int
	overflow bool
}

func (b *boundedBuffer) Write(data []byte) (int, error) {
	originalLength := len(data)
	remaining := b.limit - b.Len()
	if remaining <= 0 {
		b.overflow = true
		return originalLength, nil
	}
	if len(data) > remaining {
		data = data[:remaining]
		b.overflow = true
	}
	_, _ = b.Buffer.Write(data)
	return originalLength, nil
}

type ascendProvider struct {
	mu sync.RWMutex

	config          config.AscendConfig
	sandboxRoot     string
	providerVersion string
	profile         mountProfile
	devices         map[uint32]ascendDevice
	resources       []Resource
	leases          map[string]string
	healthy         bool
	reason          error
	statDevice      deviceStatFunc
}

func newAscendProvider(cfg config.AscendConfig, sandboxRoot string) *ascendProvider {
	provider := &ascendProvider{
		config:      cfg,
		sandboxRoot: sandboxRoot,
		devices:     make(map[uint32]ascendDevice),
		leases:      make(map[string]string),
		statDevice:  statCharacterDevice,
	}
	if err := provider.initialize(); err != nil {
		provider.reason = err
		return provider
	}
	provider.healthy = true
	return provider
}

func (p *ascendProvider) initialize() error {
	if err := validateRootOwnedExecutable(p.config.Adapter); err != nil {
		return err
	}
	profileData, err := os.ReadFile(p.config.MountProfile)
	if err != nil {
		return fmt.Errorf("read Ascend mount profile: %w", err)
	}
	if err := json.Unmarshal(profileData, &p.profile); err != nil {
		return fmt.Errorf("parse Ascend mount profile: %w", err)
	}
	if len(p.profile) == 0 {
		return errors.New("Ascend mount profile must not be empty")
	}
	var version adapterVersion
	if err := p.invoke(defaultAdapterTimeout, nil, &version, "version", "--output=json"); err != nil {
		return fmt.Errorf("query Ascend adapter version: %w", err)
	}
	if version.SchemaVersion != ascendSchemaVersion || version.ProviderVersion == "" {
		return errors.New("Ascend adapter returned an incompatible version")
	}
	var discovery adapterDiscovery
	if err := p.invoke(defaultAdapterTimeout, nil, &discovery, "discover", "--output=json"); err != nil {
		return fmt.Errorf("discover Ascend devices: %w", err)
	}
	if discovery.SchemaVersion != ascendSchemaVersion || discovery.ProviderVersion != version.ProviderVersion {
		return errors.New("Ascend discovery schema or provider version mismatch")
	}
	p.providerVersion = version.ProviderVersion
	if err := p.acceptDiscovery(discovery.Devices); err != nil {
		return err
	}
	return p.restoreLeases()
}

func validateRootOwnedExecutable(path string) error {
	if path == "" {
		return errors.New("Ascend adapter path is required")
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat Ascend adapter %s: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return errors.New("Ascend adapter must be an executable regular file")
	}
	if info.Mode().Perm()&0022 != 0 {
		return errors.New("Ascend adapter must not be group/other writable")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Uid != 0 && os.Geteuid() == 0 {
		return errors.New("Ascend adapter must be owned by root")
	}
	return nil
}

func (p *ascendProvider) invoke(timeout time.Duration, input any, output any, args ...string) error {
	var stdin []byte
	var err error
	if input != nil {
		stdin, err = json.Marshal(input)
		if err != nil {
			return err
		}
		if len(stdin) > maxAdapterInputBytes {
			return errors.New("Ascend adapter input exceeds size limit")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	command := exec.CommandContext(ctx, p.config.Adapter, args...)
	command.Stdin = bytes.NewReader(stdin)
	stdout := &boundedBuffer{limit: maxAdapterOutputBytes}
	stderr := &boundedBuffer{limit: 64 << 10}
	command.Stdout = stdout
	command.Stderr = stderr
	err = command.Run()
	if ctx.Err() != nil {
		return fmt.Errorf("Ascend adapter timed out: %w", ctx.Err())
	}
	if err != nil {
		return fmt.Errorf("Ascend adapter failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	if stdout.overflow {
		return errors.New("Ascend adapter output exceeds size limit")
	}
	if err := json.Unmarshal(stdout.Bytes(), output); err != nil {
		return fmt.Errorf("parse Ascend adapter output: %w", err)
	}
	return nil
}

func (p *ascendProvider) acceptDiscovery(devices []ascendDevice) error {
	logicIDs := make(map[int32]struct{})
	stableIDs := make(map[string]struct{})
	for _, device := range devices {
		if !device.Healthy {
			continue
		}
		device.ProductModel = strings.ToLower(strings.TrimSpace(device.ProductModel))
		if device.ProductModel == "" {
			return errors.New("Ascend product model must not be empty")
		}
		if !validAscendDeviceFamily(device) {
			return fmt.Errorf("unsupported or inconsistent Ascend device family for product model %q", device.ProductModel)
		}
		if device.LogicID < 0 || device.StableID == "" {
			return fmt.Errorf("invalid Ascend identity for scheduler ID %d", device.SchedulerID)
		}
		if _, duplicate := p.devices[device.SchedulerID]; duplicate {
			return fmt.Errorf("duplicate Ascend scheduler ID %d", device.SchedulerID)
		}
		if _, duplicate := logicIDs[device.LogicID]; duplicate {
			return fmt.Errorf("duplicate Ascend logic ID %d", device.LogicID)
		}
		if _, duplicate := stableIDs[device.StableID]; duplicate {
			return fmt.Errorf("duplicate Ascend stable ID %q", device.StableID)
		}
		p.devices[device.SchedulerID] = device
		logicIDs[device.LogicID] = struct{}{}
		stableIDs[device.StableID] = struct{}{}
	}
	if len(p.devices) == 0 {
		return errors.New("Ascend discovery returned no healthy physical NPU")
	}
	p.resources = buildAscendResources(p.devices)
	return nil
}

func validAscendDeviceFamily(device ascendDevice) bool {
	switch device.Generation {
	case "310P":
		return device.RuntimeFamily == ascend310PRuntimeFamily && device.ResourceFamily == "huawei.com/Ascend310P"
	case "A2", "A3":
		return device.RuntimeFamily == ascendRuntimeFamily && device.ResourceFamily == "huawei.com/Ascend910"
	default:
		return false
	}
}

func buildAscendResources(devices map[uint32]ascendDevice) []Resource {
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
		resources = append(resources, Resource{Type: TypeNPU, ProductModel: model, DeviceIDs: ids})
	}
	return resources
}

func (p *ascendProvider) Type() string { return TypeNPU }

func (p *ascendProvider) SupportsRuntime(runtimeName string) bool {
	return runtimeName == config.RuntimeNameRunc
}

func (p *ascendProvider) Healthy() (bool, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.healthy, p.reason
}

func reservedAscendEnv(key string) bool {
	switch key {
	case ascendVisibleDevicesEnv, ascendRTVisibleDevicesEnv, "ASCEND_DOCKER_RUNTIME",
		"ASCEND_RUNTIME_OPTIONS", "ASCEND_RUNTIME_MOUNTS", "ASCEND_VNPU_SPECS",
		"ASCEND_ALLOW_LINK", "DISABLE_UB_MOUNT":
		return true
	default:
		return false
	}
}

func (p *ascendProvider) Resources() []Resource {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if !p.healthy {
		return []Resource{}
	}
	resources := make([]Resource, len(p.resources))
	copy(resources, p.resources)
	for index := range resources {
		resources[index].DeviceIDs = append([]uint32(nil), resources[index].DeviceIDs...)
	}
	return resources
}

func (p *ascendProvider) Acquire(
	sandboxID, runtimeName string,
	allocation *api.XpuAllocation,
) (*svc.SpecUpdates, error) {
	if sandboxID == "" || allocation == nil {
		return nil, errors.New("sandbox ID and NPU allocation are required")
	}
	if !p.SupportsRuntime(runtimeName) {
		return nil, fmt.Errorf("NPU allocations require runtime %q", config.RuntimeNameRunc)
	}
	if strings.ToLower(strings.TrimSpace(allocation.Type)) != TypeNPU {
		return nil, errors.New("invalid NPU allocation")
	}
	if len(allocation.DeviceIds) == 0 {
		return nil, errors.New("NPU device IDs must not be empty")
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.healthy {
		return nil, fmt.Errorf("NPU support is unavailable: %w", p.reason)
	}
	seen := make(map[uint32]struct{}, len(allocation.DeviceIds))
	devices := make([]ascendDevice, 0, len(allocation.DeviceIds))
	for _, id := range allocation.DeviceIds {
		if _, duplicate := seen[id]; duplicate {
			return nil, fmt.Errorf("duplicate NPU device ID %d", id)
		}
		seen[id] = struct{}{}
		device, ok := p.devices[id]
		if !ok {
			return nil, fmt.Errorf("NPU device ID %d is not in the node inventory", id)
		}
		if owner, leased := p.leases[device.StableID]; leased && owner != sandboxID {
			return nil, fmt.Errorf("NPU device ID %d is already leased by sandbox %s", id, owner)
		}
		devices = append(devices, device)
	}
	for _, device := range devices {
		p.leases[device.StableID] = sandboxID
	}
	rollback := func() {
		for _, device := range devices {
			if p.leases[device.StableID] == sandboxID {
				delete(p.leases, device.StableID)
			}
		}
	}
	logicIDs := make([]int32, len(devices))
	stableIDs := make([]string, len(devices))
	model := devices[0].ProductModel
	runtimeFamily := devices[0].RuntimeFamily
	for index, device := range devices {
		if device.ProductModel != model {
			rollback()
			return nil, errors.New("all NPU devices in one allocation must have the same product model")
		}
		if device.RuntimeFamily != runtimeFamily {
			rollback()
			return nil, errors.New("all NPU devices in one allocation must use the same runtime family")
		}
		logicIDs[index] = device.LogicID
		stableIDs[index] = device.StableID
	}
	var edits adapterEdits
	if err := p.invoke(defaultAdapterTimeout, adapterEditsRequest{
		SchemaVersion: ascendSchemaVersion,
		LogicIDs:      logicIDs,
		RuntimeFamily: runtimeFamily,
		PhysicalOnly:  true,
		MountProfile:  p.config.MountProfile,
	}, &edits, "edits", "--input=-", "--output=json"); err != nil {
		rollback()
		return nil, err
	}
	updates, err := p.validateEdits(logicIDs, runtimeFamily, edits)
	if err != nil {
		rollback()
		return nil, err
	}
	recordJSON, err := encodeLease(leaseRecord{
		SandboxID: sandboxID, Type: TypeNPU, Runtime: runtimeName,
		ProductModel: devices[0].ProductModel,
		SchedulerIDs: append([]uint32(nil), allocation.DeviceIds...),
		LogicIDs:     append([]int32(nil), logicIDs...), StableIDs: stableIDs,
		Provider: ascendProviderName, ProviderVersion: p.providerVersion,
	})
	if err != nil {
		rollback()
		return nil, err
	}
	updates.Annotations = map[string]string{AllocationAnnotation: string(recordJSON)}
	return updates, nil
}

func (p *ascendProvider) validateEdits(
	logicIDs []int32, runtimeFamily string, edits adapterEdits,
) (*svc.SpecUpdates, error) {
	if edits.SchemaVersion != ascendSchemaVersion || edits.ProviderVersion != p.providerVersion {
		return nil, errors.New("Ascend edits schema or provider version mismatch")
	}
	expectedDevices := make(map[string]struct{}, len(logicIDs))
	for _, id := range logicIDs {
		expectedDevices[fmt.Sprintf("/dev/davinci%d", id)] = struct{}{}
	}
	updates := &svc.SpecUpdates{}
	appendDevice := func(device adapterDevice, shared bool) error {
		if device.Type != "c" || device.Permissions != "rwm" || device.Major < 0 || device.Minor < 0 {
			return fmt.Errorf("invalid Ascend device edit for %s", device.ContainerPath)
		}
		if shared {
			if _, allowed := allowedAscendSharedDevices[device.ContainerPath]; !allowed {
				return fmt.Errorf("Ascend shared device %s is not allowed", device.ContainerPath)
			}
			if !sharedDeviceHostAllowed(device.HostPath, device.ContainerPath) {
				return fmt.Errorf("Ascend shared device mapping %s -> %s is not allowed", device.HostPath, device.ContainerPath)
			}
		} else {
			if _, expected := expectedDevices[device.ContainerPath]; !expected || device.HostPath != device.ContainerPath {
				return fmt.Errorf("Ascend device %s is outside the current lease", device.ContainerPath)
			}
			delete(expectedDevices, device.ContainerPath)
		}
		deviceType, major, minor, err := p.statDevice(device.HostPath)
		if err != nil || deviceType != device.Type || major != device.Major || minor != device.Minor {
			return fmt.Errorf("Ascend device identity mismatch for %s", device.HostPath)
		}
		majorCopy, minorCopy := device.Major, device.Minor
		updates.LinuxDevices = append(updates.LinuxDevices, svc.LinuxDevice{
			Path: device.ContainerPath, Type: device.Type, Major: device.Major, Minor: device.Minor,
		})
		updates.DeviceCgroupRules = append(updates.DeviceCgroupRules, svc.LinuxDeviceCgroup{
			Allow: true, Type: device.Type, Major: &majorCopy, Minor: &minorCopy, Access: device.Permissions,
		})
		return nil
	}
	for _, device := range edits.Devices {
		if err := appendDevice(device, false); err != nil {
			return nil, err
		}
	}
	if len(expectedDevices) != 0 {
		return nil, errors.New("Ascend edits did not include every leased device")
	}
	for _, device := range edits.SharedDevices {
		if err := appendDevice(device, true); err != nil {
			return nil, err
		}
	}
	for _, mount := range edits.Mounts {
		if !p.mountAllowed(runtimeFamily, mount.Source) || mount.Destination != mount.Source || mount.Type != "bind" ||
			!containsOption(mount.Options, "ro") {
			return nil, fmt.Errorf("Ascend mount %s -> %s is not an allowed read-only bind", mount.Source, mount.Destination)
		}
		if !filepath.IsAbs(mount.Source) || !filepath.IsAbs(mount.Destination) {
			return nil, errors.New("Ascend mount paths must be absolute")
		}
		updates.Mounts = append(updates.Mounts, svc.Mount{
			Destination: mount.Destination, Type: mount.Type, Source: mount.Source,
			Options: append([]string(nil), mount.Options...),
		})
	}
	for key, value := range edits.Env {
		if key == "LD_LIBRARY_PATH" {
			updates.PrependLibraryPaths = strings.Split(value, ":")
			continue
		}
		if !reservedAscendEnv(key) {
			return nil, fmt.Errorf("Ascend adapter returned unowned environment variable %q", key)
		}
		updates.Envs = append(updates.Envs, &api.KeyValue{Key: key, Value: value})
	}
	return updates, nil
}

func sharedDeviceHostAllowed(hostPath, containerPath string) bool {
	if hostPath == containerPath {
		return true
	}
	return hostPath == "/dev/davinci_manager_docker" && containerPath == "/dev/davinci_manager"
}

func (p *ascendProvider) mountAllowed(runtimeFamily, source string) bool {
	groups := p.profile[runtimeFamily]
	if len(groups) == 0 {
		groups = p.profile["default"]
	}
	for _, group := range groups {
		if strings.EqualFold(group.Type, "UB") {
			continue
		}
		for _, pattern := range group.Paths {
			if matched, err := filepath.Match(pattern, source); err == nil && matched {
				return true
			}
			if pattern == source {
				return true
			}
		}
	}
	return false
}

func containsOption(options []string, expected string) bool {
	for _, option := range options {
		if option == expected {
			return true
		}
	}
	return false
}

func (p *ascendProvider) Release(sandboxID string) {
	if sandboxID == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for stableID, owner := range p.leases {
		if owner == sandboxID {
			delete(p.leases, stableID)
		}
	}
}

func (p *ascendProvider) restoreLeases() error {
	leases, err := readPersistedLeases(p.sandboxRoot)
	if err != nil {
		return err
	}
	for _, persisted := range leases {
		record := persisted.record
		if record.Type != TypeNPU {
			continue
		}
		if record.SchemaVersion != leaseSchemaVersion || record.Runtime != config.RuntimeNameRunc ||
			record.Provider != ascendProviderName || record.ProviderVersion != p.providerVersion ||
			len(record.SchedulerIDs) == 0 || len(record.SchedulerIDs) != len(record.StableIDs) {
			return fmt.Errorf("invalid NPU allocation annotation in %s", persisted.bundlePath)
		}
		for index, id := range record.SchedulerIDs {
			device, ok := p.devices[id]
			if !ok || device.StableID != record.StableIDs[index] || device.ProductModel != record.ProductModel {
				return fmt.Errorf("NPU identity changed for device ID %d in %s", id, persisted.bundlePath)
			}
			if owner, duplicate := p.leases[device.StableID]; duplicate && owner != record.SandboxID {
				return fmt.Errorf("NPU stable ID %s is assigned to both %s and %s", device.StableID, owner, record.SandboxID)
			}
			p.leases[device.StableID] = record.SandboxID
		}
	}
	return nil
}
