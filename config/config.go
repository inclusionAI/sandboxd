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

//go:build !windows

package config

import (
	"fmt"
	"math"
	"strings"
)

const (
	CPULimitModeShares     = "shares"
	CPULimitModeQuota      = "quota"
	DefaultCPUPeriodMicros = uint64(100000)
)

const (
	RunscPlatformSystrap = "systrap"
	RunscPlatformKVM     = "kvm"
)

// Config contains all configurations for sandbox server.
type Config struct {
	// PluginConfig is the config for sandbox plugin.
	PluginConfig `toml:"plugin" json:"plugin"`
	// RootDir is the root directory path for managing sandbox service files
	// (metadata checkpoint etc.)
	RootDir string `json:"rootDir" toml:"rootDir"`
	// StoreDir is the root directory path for storing all necessary metadata.
	StoreDir string `json:"stateDir" toml:"storeDir"`
}

type PluginConfig struct {
	NetworkConfig `toml:"network" json:"network"`

	RuntimeConfig `toml:"runtime" json:"runtime"`

	ResourceConfig `toml:"resource" json:"resource"`

	NodeResourceConfig `toml:"node_resource" json:"nodeResource"`

	ImageManagerConfig `toml:"image" json:"image"`
}

// ImageManagerConfig configures image and mount lifecycle management.
type ImageManagerConfig struct {
	ImageManagerRoot  string `toml:"root" json:"root"`
	DistillFsBin      string `toml:"distill_fs_bin" json:"distillFsBin"`
	OSSTemplate       string `toml:"oss_template" json:"ossTemplate"`
	NydusTemplate     string `toml:"nydus_template" json:"nydusTemplate"`
	NydusSuffix       string `toml:"nydus_suffix" json:"nydusSuffix"`
	OSSAuthsPath      string `toml:"oss_auths_path" json:"ossAuthsPath"`
	RegistryAuthsPath string `toml:"registry_auths_path" json:"registryAuthsPath"`
	CgroupMemoryLimit string `toml:"cgroup_memory_limit" json:"cgroupMemoryLimit"`
}

// NodeResourceConfig configures optional node-resource reporting. Provider
// selects the CPU and memory capacity source; an empty value preserves the
// historical Kubernetes behavior. SockPath exposes that capacity over a Unix
// socket for an external scheduler or resource collector.
type NodeResourceConfig struct {
	Provider string `toml:"provider" json:"provider"`
	SockPath string `toml:"sock_path" json:"sockPath"`
}

// RuntimeConfig binary path of the runtime
type RuntimeConfig struct {
	RuntimeBinary map[string]string `toml:"runtime_binary" json:"runtimeBinary"`

	// ResolvConfPath is the host resolver file mounted into sandboxes when the
	// final configuration does not already provide /etc/resolv.conf.
	ResolvConfPath string `toml:"resolv_conf_path" json:"resolvConfPath"`

	// Runsc configures the gVisor runtime adapter.
	Runsc RunscConfig `toml:"runsc" json:"runsc"`

	// Kata configures the optional Kata Containers runtime adapter. Kata is
	// loaded only when runtime_binary contains a "kata" entry.
	Kata KataConfig `toml:"kata" json:"kata"`

	// Runc configures the optional host-kernel OCI runtime adapter. Runc is
	// loaded only when runtime_binary contains a "runc" entry.
	Runc RuncConfig `toml:"runc" json:"runc"`

	// Firecracker configures the optional microVM runtime adapter. It is loaded
	// only when runtime_binary contains a "firecracker" entry.
	Firecracker FirecrackerConfig `toml:"firecracker" json:"firecracker"`

	// BasicSpec is the basic spec file for different runtime type.
	BasicSpec map[string]string `toml:"basic_spec" json:"basicSpec"`

	// ImageLibDir is retained for configuration compatibility and is not used.
	ImageLibDir string `toml:"image_lib_dir" json:"imageLibDir"`

	// FilestoreDir specifies a directory for writable overlay backing files.
	// With no size configured, sandboxd uses it as an ordinary directory.
	FilestoreDir string `toml:"filestore_dir" json:"filestoreDir"`

	// FilestoreDirSize optionally bounds the shared filestore with a loop-backed
	// filesystem. ext4 is used by default; XFS is selected explicitly below.
	FilestoreDirSize string `toml:"filestore_dir_size" json:"filestoreDirSize"`

	// FilestoreOvercommitRatio converts physical filestore capacity into the
	// logical capacity advertised to and enforced for schedulers. It does not
	// change the size of the underlying ext4 or XFS filesystem.
	FilestoreOvercommitRatio float64 `toml:"filestore_overcommit_ratio" json:"filestoreOvercommitRatio"`

	// FilestoreXFSEnabled selects XFS for a bounded filestore.
	FilestoreXFSEnabled bool `toml:"filestore_xfs_enabled" json:"filestoreXFSEnabled"`

	// LoopDeviceDir contains loop-control and loopN device nodes for bounded
	// filestores and read-only EROFS images. The default is /dev; deployments
	// may point it at another mounted device namespace.
	LoopDeviceDir string `toml:"loop_device_dir" json:"loopDeviceDir"`

	// OverlayTmpfsSize specifies the size limit for the gVisor writable overlay
	// (e.g. "256M", "1G"). The name is retained for configuration compatibility.
	// When empty, no size limit is applied.
	OverlayTmpfsSize string `toml:"overlay_tmpfs_size" json:"overlayTmpfsSize"`
}

// RunscConfig contains options passed to the gVisor runsc adapter.
type RunscConfig struct {
	// Platform selects gVisor's syscall interception platform.
	Platform string `toml:"platform" json:"platform"`
}

// KataConfig contains the host paths and storage settings used by Kata.
type KataConfig struct {
	ConfigPath   string `toml:"config_path" json:"configPath"`
	KVMDevice    string `toml:"kvm_device" json:"kvmDevice"`
	DANConfigDir string `toml:"dan_config_dir" json:"danConfigDir"`
	LoggerBinary string `toml:"logger_binary" json:"loggerBinary"`
}

// RuncConfig contains host paths owned by the runc adapter.
type RuncConfig struct {
	StateRoot  string `toml:"state_root" json:"stateRoot"`
	ShimBinary string `toml:"shim_binary" json:"shimBinary"`
	KVMDevice  string `toml:"kvm_device" json:"kvmDevice"`
}

// FirecrackerConfig contains immutable guest boot artifacts and VM defaults.
type FirecrackerConfig struct {
	KernelImagePath         string `toml:"kernel_image_path" json:"kernelImagePath"`
	InitrdPath              string `toml:"initrd_path" json:"initrdPath"`
	KernelArgs              string `toml:"kernel_args" json:"kernelArgs"`
	KVMDevice               string `toml:"kvm_device" json:"kvmDevice"`
	DefaultVCPUCount        uint32 `toml:"default_vcpu_count" json:"defaultVCPUCount"`
	DefaultMemoryMiB        uint32 `toml:"default_memory_mib" json:"defaultMemoryMiB"`
	DefaultOverlaySizeBytes uint64 `toml:"default_overlay_size_bytes" json:"defaultOverlaySizeBytes"`
}

type ResourceConfig struct {
	MaxInstanceNum int `toml:"max_instance_num" json:"maxInstanceNum"`

	// CPULimitMode controls how requested CPU millicores are enforced. Shares
	// preserves the historical relative-weight behavior, while quota applies a
	// CFS bandwidth limit that runtimes can use to size their CPU topology.
	CPULimitMode string `toml:"cpu_limit_mode" json:"cpuLimitMode"`

	// DisableCgroup enables an experimental/debug compatibility mode that
	// prevents sandboxd and its runtimes from writing cgroups. Sandboxes
	// inherit sandboxd's current cgroup, and per-sandbox resource limits are
	// accepted for API compatibility but are not enforced. Only runsc is
	// available in this mode.
	DisableCgroup bool `toml:"disable_cgroup" json:"disableCgroup"`

	// CgroupRootName is the path of cgroup. Default is sandbox.
	CgroupRootName string `toml:"cgroup_root_name" json:"cgroupRootName"`
	// CgroupCacheSize is the size of cgroup cache. Default is same as max_instance_num.
	CgroupCacheSize int `toml:"cgroup_cache_size" json:"cgroupCacheSize"`
	// PidsMax is the maximum number of processes allowed in each sandbox cgroup.
	// Zero leaves the kernel default of unlimited processes unchanged.
	PidsMax int64 `toml:"pids_max" json:"pidsMax"`
	// InterfaceCacheSize is the size of interface cache. Default is same as max_instance_num.
	InterfaceCacheSize int `toml:"interface_cache_size" json:"interfaceCacheSize"`
}

// NormalizeRunscPlatform validates the configured gVisor platform. An empty
// value preserves the historical and upstream default of systrap.
func NormalizeRunscPlatform(value string) (string, error) {
	switch normalized := strings.ToLower(strings.TrimSpace(value)); normalized {
	case "", RunscPlatformSystrap:
		return RunscPlatformSystrap, nil
	case RunscPlatformKVM:
		return RunscPlatformKVM, nil
	default:
		return "", fmt.Errorf(
			"runsc platform must be %q or %q, got %q",
			RunscPlatformSystrap,
			RunscPlatformKVM,
			value,
		)
	}
}

// NormalizeCPULimitMode validates the configured CPU control mode. An empty
// value selects quota, the default enforcement mode.
func NormalizeCPULimitMode(value string) (string, error) {
	switch normalized := strings.ToLower(strings.TrimSpace(value)); normalized {
	case "", CPULimitModeQuota:
		return CPULimitModeQuota, nil
	case CPULimitModeShares:
		return CPULimitModeShares, nil
	default:
		return "", fmt.Errorf(
			"cpu_limit_mode must be %q or %q, got %q",
			CPULimitModeShares,
			CPULimitModeQuota,
			value,
		)
	}
}

// ValidateFilestoreOvercommitRatio checks the physical-to-logical storage
// multiplier. The caller supplies the default before decoding configuration so
// an explicitly configured zero is rejected rather than treated as omitted.
func ValidateFilestoreOvercommitRatio(value float64) error {
	if math.IsNaN(value) || math.IsInf(value, 0) || value < 1 {
		return fmt.Errorf("filestore_overcommit_ratio must be finite and at least 1.0, got %g", value)
	}
	return nil
}

// NetworkConfig contains network-related configuration for sandboxd.
type NetworkConfig struct {
	IPRange string `toml:"ip_range" json:"ipRange"`

	// NatBackend selects the registered NAT implementation used for SNAT/DNAT
	// rules. Empty defaults to "iptables" for backward compatibility.
	NatBackend string `toml:"nat_backend" json:"natBackend"`

	// EnableLocalDNAT forwards connections made to local addresses in
	// sandboxd's network namespace. It is intended for standalone deployments
	// whose frontend shares that namespace and is disabled by default.
	EnableLocalDNAT bool `toml:"enable_local_dnat" json:"enableLocalDNAT"`

	// BpfnatDevice overrides the IPv4 default-route interface selected by the
	// bpfnat backend. It is useful on hosts with more than one default route.
	BpfnatDevice string `toml:"bpfnat_device" json:"bpfnatDevice"`

	// EnableNetworkACL enables per-sandbox packet ACLs and the managed DNS
	// proxy. It is disabled by default so existing nodes keep their current
	// networking and resolver behavior.
	EnableNetworkACL bool `toml:"enable_network_acl" json:"enableNetworkACL"`

	// DNSProxyConcurrencyLimit bounds DNS requests and TCP connections handled
	// concurrently across all sandboxes. Zero selects the safe default.
	DNSProxyConcurrencyLimit int `toml:"dns_proxy_concurrency_limit" json:"dnsProxyConcurrencyLimit"`

	// DNSProxyPerSandboxConcurrencyLimit bounds one sandbox's share of the DNS
	// proxy. Zero selects the safe default.
	DNSProxyPerSandboxConcurrencyLimit int `toml:"dns_proxy_per_sandbox_concurrency_limit" json:"dnsProxyPerSandboxConcurrencyLimit"`
}

// DefaultConfig returns the programmatic default sandboxd configuration.
func DefaultConfig() Config {
	return Config{
		PluginConfig: PluginConfig{
			NetworkConfig: NetworkConfig{
				NatBackend:                         "iptables",
				IPRange:                            DefaultIPRange,
				DNSProxyConcurrencyLimit:           256,
				DNSProxyPerSandboxConcurrencyLimit: 16,
			},
			RuntimeConfig: RuntimeConfig{
				RuntimeBinary: map[string]string{
					RuntimeNameRunsc: DefaultRunscBinary,
				},
				ResolvConfPath: "/etc/resolv.conf",
				BasicSpec: map[string]string{
					RuntimeNameRunsc: "/home/akernel/images/config.json",
				},
				Runsc: RunscConfig{
					Platform: DefaultRunscPlatform,
				},
				Runc: RuncConfig{
					StateRoot:  DefaultRuncStateRoot,
					ShimBinary: DefaultRuncShimBinary,
					KVMDevice:  DefaultKVMDevice,
				},
				Firecracker: FirecrackerConfig{
					KernelImagePath:         DefaultFirecrackerKernel,
					InitrdPath:              DefaultFirecrackerInitrd,
					KernelArgs:              DefaultFirecrackerKernelArgs,
					KVMDevice:               DefaultKVMDevice,
					DefaultVCPUCount:        DefaultFirecrackerVCPUs,
					DefaultMemoryMiB:        DefaultFirecrackerMemoryMiB,
					DefaultOverlaySizeBytes: DefaultFirecrackerOverlayBytes,
				},
				ImageLibDir:              DefaultImageLibDir,
				FilestoreDir:             DefaultFilestoreDir,
				FilestoreOvercommitRatio: DefaultFilestoreOvercommitRatio,
				LoopDeviceDir:            DefaultLoopDeviceDir,
			},
			ResourceConfig: ResourceConfig{
				MaxInstanceNum:     DefaultMaxSandboxNum,
				CPULimitMode:       CPULimitModeQuota,
				CgroupRootName:     DefaultCgroupRoot,
				CgroupCacheSize:    DefaultMaxSandboxNum,
				InterfaceCacheSize: DefaultMaxSandboxNum,
			},
		},
		RootDir:  DefaultSandboxRootDir,
		StoreDir: DefaultStoreDir,
	}
}
