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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/util"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	"github.com/sirupsen/logrus"
)

const (
	// IgnoreResourceFieldAnnoKey , if set, will ignore the resource field in spec.
	IgnoreResourceFieldAnnoKey = "sandbox.akernel.dev/ignore-resource-field"

	// NetworkClassAnnoKey is the key of network class annotation.
	NetworkClassAnnoKey = "sandbox.akernel.dev/network-class"

	gvisorRootfsAnnotationPrefix = "dev.gvisor.spec.rootfs."
	gvisorRootfsTypeEROFS        = "erofs"
	gvisorRootfsOverlayDirPrefix = "dir="
)

type OciLoader interface {
	GenerateOci(options OciLoadOptions) (string, *Spec, error)
}

type OciLoadOptions struct {
	SandboxID string
	Config    StartConfig

	CgroupPath        string
	NetworkNameSpace  string
	OverrideBundleDir string

	OverrideRootPath string

	UseGVisorRootfsImageAnnotations bool
	RootfsOverlayDir                string
	RootfsOverlaySize               string
}

var _ OciLoader = &BundleLoader{}

// BundleLoader loads an OCI base spec and materializes per-sandbox bundle
// directories for runsc.
type BundleLoader struct {
	baseSpec        *Spec
	bundleParentDir string
}

func NewBundleLoader(baseFile, bundleDir string) (*BundleLoader, error) {
	bs := defaultSandboxSpec()
	if baseFile != "" {
		bst, err := LoadSpec(baseFile)
		if err != nil {
			logrus.Warnf("load base spec failed, use default spec. err: %v", err)
		} else {
			bs = bst
		}
	}

	// check bundle dir
	if _, err := os.Stat(bundleDir); os.IsNotExist(err) {
		if err = os.MkdirAll(bundleDir, 0755); err != nil {
			return nil, err
		}
	}
	return &BundleLoader{
		baseSpec:        bs,
		bundleParentDir: bundleDir,
	}, nil
}

func (r *BundleLoader) GenerateOci(options OciLoadOptions) (string, *Spec, error) {
	ociSpec := r.baseSpec.DeepCopy()
	if options.OverrideBundleDir == "" &&
		(options.SandboxID == "" || (!options.Config.DisableCgroup && options.CgroupPath == "")) {
		logrus.Debugf("invalid options, cg: %v", options.CgroupPath)
		return "", ociSpec, errord.ErrInvalidArgument
	}

	if ociSpec.Linux == nil {
		ociSpec.Linux = &Linux{
			Namespaces: []LinuxNamespace{},
		}
	}
	ociSpec.Linux.CgroupsPath = options.CgroupPath

	if options.Config.Cwd != "" {
		ociSpec.Process.Cwd = options.Config.Cwd
	}

	if len(options.Config.Command) > 0 {
		ociSpec.Process.Args = options.Config.Command
	}

	if len(options.Config.Envs) > 0 {
		ociSpec.Process.Env = combineEnvs(ociSpec.Process.Env, options.Config.Envs)
	}

	for _, mnt := range options.Config.Mounts {
		ociSpec.Mounts = append(ociSpec.Mounts, Mount{
			Destination: mnt.GetTarget(),
			Type:        mnt.GetType(),
			Source:      mnt.GetHostPath(),
			Options:     mnt.GetOptions(),
		})
	}

	if ociSpec.Root == nil {
		ociSpec.Root = &Root{}
	}
	ociSpec.Root.Path = options.Config.Rootfs
	if options.Config.WritableLayerLimitBytes > 0 {
		// An explicit writable-layer quota necessarily requests a writable root.
		// The image itself remains read-only; writes go to the quota-limited
		// gVisor overlay selected below.
		ociSpec.Root.Readonly = false
	}

	ociSpec.Annotations = combineAnnotations(ociSpec.Annotations, options.Config.Annotations)

	bundleDir, err := util.JoinWithinRoot(r.bundleParentDir, options.SandboxID)
	if err != nil {
		return "", ociSpec, fmt.Errorf("resolve sandbox bundle: %w", err)
	}

	if options.Config.DisableCgroup {
		ociSpec.Linux.CgroupsPath = ""
		ociSpec.Linux.Resources = nil
	} else {
		setSpecResource(ociSpec, options.Config.Resources)
	}
	if _, ok := ociSpec.Annotations[IgnoreResourceFieldAnnoKey]; ok {
		logrus.Debugf("ignore resource field for %v", options.SandboxID)
		ociSpec.Linux.Resources = nil
	}

	if options.OverrideRootPath != "" {
		ociSpec.Root.Path = options.OverrideRootPath
	}

	if options.UseGVisorRootfsImageAnnotations && options.OverrideRootPath == "" {
		if err := prepareRunscHostsMount(ociSpec, bundleDir); err != nil {
			return "", ociSpec, err
		}
		if err := applyGVisorRootfsImageAnnotations(
			ociSpec,
			bundleDir,
			options.RootfsOverlayDir,
			options.RootfsOverlaySize,
		); err != nil {
			return "", ociSpec, err
		}
	}

	// Provider-owned fields are applied last so request labels, image
	// metadata, and the base spec cannot override device authorization.
	if updates := options.Config.SpecUpdates; updates != nil {
		if len(updates.Envs) > 0 {
			ociSpec.Process.Env = combineEnvs(ociSpec.Process.Env, updates.Envs)
		}
		if len(updates.Prestart) > 0 {
			if ociSpec.Hooks == nil {
				ociSpec.Hooks = &Hooks{}
			}
			ociSpec.Hooks.Prestart = append(ociSpec.Hooks.Prestart, updates.Prestart...)
		}
		ociSpec.Annotations = combineAnnotations(ociSpec.Annotations, updates.Annotations)
	}

	ociFile := filepath.Join(bundleDir, config.SandboxSpecFile)

	// create target path r.TargetDir/SandboxID is not exist
	if _, err := os.Stat(filepath.Dir(ociFile)); os.IsNotExist(err) {
		// create target path
		if err = os.MkdirAll(filepath.Dir(ociFile), 0755); err != nil {
			return "", ociSpec, err
		}
	}

	buf, _ := util.UnescapedMarshal(ociSpec)
	logrus.Debugf("write spec to %v, content: %v", ociFile, string(buf))
	return bundleDir, ociSpec, os.WriteFile(ociFile, buf, 0644)
}

func prepareRunscHostsMount(spec *Spec, bundleDir string) error {
	for _, mount := range spec.Mounts {
		if mountOwnsDestination(mount.Destination, "/etc/hosts") {
			return nil
		}
	}

	if err := os.MkdirAll(bundleDir, 0755); err != nil {
		return fmt.Errorf("create runsc bundle for hosts file: %w", err)
	}
	hostsPath := filepath.Join(bundleDir, "hosts")
	if err := writeRunscHostsFile(hostsPath); err != nil {
		return fmt.Errorf("write runsc hosts file: %w", err)
	}
	spec.Mounts = append(spec.Mounts, Mount{
		Destination: "/etc/hosts",
		Type:        "bind",
		Source:      hostsPath,
		Options:     []string{"bind", "ro"},
	})
	return nil
}

func mountOwnsDestination(mountDestination, target string) bool {
	mountDestination = path.Clean(mountDestination)
	target = path.Clean(target)
	return mountDestination == target ||
		mountDestination == "/" ||
		strings.HasPrefix(target, mountDestination+"/")
}

func writeRunscHostsFile(target string) error {
	tmp, err := os.CreateTemp(filepath.Dir(target), ".hosts-")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()

	if err := tmp.Chmod(0644); err != nil {
		return err
	}
	if _, err := tmp.WriteString(config.LocalhostHostsFileContent); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, target); err != nil {
		return err
	}
	return nil
}

func applyGVisorRootfsImageAnnotations(
	spec *Spec,
	bundleDir string,
	overlayDir string,
	overlaySize string,
) error {
	if spec.Root == nil || spec.Root.Path == "" {
		return nil
	}

	rootfsImage := spec.Root.Path
	info, err := os.Stat(rootfsImage)
	if err != nil {
		return fmt.Errorf("stat rootfs %q: %w", rootfsImage, err)
	}
	if info.IsDir() {
		return nil
	}
	if !info.Mode().IsRegular() {
		return nil
	}
	if !filepath.IsAbs(rootfsImage) {
		abs, err := filepath.Abs(rootfsImage)
		if err != nil {
			return fmt.Errorf("resolve rootfs image %q: %w", rootfsImage, err)
		}
		rootfsImage = abs
	}

	const placeholderRootfs = "rootfs"
	placeholderRootfsPath := filepath.Join(bundleDir, placeholderRootfs)
	if err := createRootfsPlaceholder(placeholderRootfsPath, spec.Mounts); err != nil {
		return err
	}

	if spec.Annotations == nil {
		spec.Annotations = map[string]string{}
	}
	spec.Annotations[gvisorRootfsAnnotationPrefix+"source"] = rootfsImage
	spec.Annotations[gvisorRootfsAnnotationPrefix+"type"] = gvisorRootfsTypeEROFS
	if !spec.Root.Readonly {
		if overlayDir == "" {
			return errors.New("gVisor writable rootfs image requires a filestore directory")
		}
		spec.Annotations[gvisorRootfsAnnotationPrefix+"overlay"] = gvisorRootfsOverlayDirPrefix + overlayDir
		if overlaySize != "" {
			spec.Annotations[gvisorRootfsAnnotationPrefix+"options"] = "size=" + overlaySize
		}
	}
	spec.Root.Path = placeholderRootfs
	return nil
}

func createRootfsPlaceholder(root string, mounts []Mount) error {
	for _, dir := range []string{
		"dev",
		"etc",
		"home",
		"proc",
		"run",
		"sys",
		"sys/fs",
		"sys/fs/cgroup",
		"tmp",
		"var",
	} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0755); err != nil {
			return fmt.Errorf("create placeholder rootfs dir %q: %w", dir, err)
		}
	}

	for _, mount := range mounts {
		target, ok := placeholderMountTarget(root, mount.Destination)
		if !ok {
			continue
		}
		if mountSourceIsRegularFile(mount) {
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return fmt.Errorf("create placeholder parent for mount %q: %w", mount.Destination, err)
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_RDONLY, 0644)
			if err != nil {
				return fmt.Errorf("create placeholder file for mount %q: %w", mount.Destination, err)
			}
			if err := f.Close(); err != nil {
				return fmt.Errorf("close placeholder file for mount %q: %w", mount.Destination, err)
			}
			continue
		}
		if err := os.MkdirAll(target, 0755); err != nil {
			return fmt.Errorf("create placeholder dir for mount %q: %w", mount.Destination, err)
		}
	}
	return nil
}

func placeholderMountTarget(root, destination string) (string, bool) {
	if destination == "" {
		return "", false
	}
	cleaned := filepath.Clean(destination)
	if !filepath.IsAbs(cleaned) || cleaned == string(os.PathSeparator) {
		return "", false
	}
	rel, err := filepath.Rel(string(os.PathSeparator), cleaned)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return "", false
	}
	return filepath.Join(root, rel), true
}

func mountSourceIsRegularFile(mount Mount) bool {
	if mount.Type != "bind" || mount.Source == "" {
		return false
	}
	info, err := os.Stat(mount.Source)
	return err == nil && info.Mode().IsRegular()
}

func LoadSpec(baseFile string) (*Spec, error) {
	specData, err := os.ReadFile(baseFile)
	if err != nil {
		return nil, err
	}
	var spec Spec
	if err = json.Unmarshal(specData, &spec); err != nil {
		return nil, err
	}
	return &spec, nil
}

// init supported resource.
func setSpecResource(spec *Spec, resource *runtime.LinuxSandboxResources) {
	// set resource.
	if spec.Linux.Resources == nil {
		spec.Linux.Resources = &LinuxResources{}
	}

	if spec.Linux.Resources.CPU == nil {
		spec.Linux.Resources.CPU = &LinuxCPU{}
	}

	if spec.Linux.Resources.Memory == nil {
		spec.Linux.Resources.Memory = &LinuxMemory{}
	}

	if spec.Linux.Resources.Network == nil {
		spec.Linux.Resources.Network = &LinuxNetwork{}
	}

	if spec.Linux.Resources.HugepageLimits == nil {
		spec.Linux.Resources.HugepageLimits = []LinuxHugepageLimit{}
	}

	if spec.Linux.Resources.Unified == nil {
		spec.Linux.Resources.Unified = map[string]string{}
	}

	// set value.
	// CPU
	if resource.CpuShares > 0 {
		spec.Linux.Resources.CPU.Shares = &resource.CpuShares
	}
	if resource.CpuQuota > 0 {
		spec.Linux.Resources.CPU.Quota = &resource.CpuQuota
	}
	if resource.CpuPeriod > 0 {
		spec.Linux.Resources.CPU.Period = &resource.CpuPeriod
	}
	if resource.CpusetCpus != "" {
		spec.Linux.Resources.CPU.Cpus = resource.CpusetCpus
	}

	// Memory
	if resource.MemorySwapLimitInBytes > 0 {
		spec.Linux.Resources.Memory.Swap = &resource.MemorySwapLimitInBytes
	}
	if resource.MemoryLimitInBytes > 0 {
		spec.Linux.Resources.Memory.Limit = &resource.MemoryLimitInBytes
	}

	// Hugepage
	if resource.HugepageLimits != nil {
		for _, limit := range resource.HugepageLimits {
			spec.Linux.Resources.HugepageLimits = append(spec.Linux.Resources.HugepageLimits, LinuxHugepageLimit{
				Pagesize: limit.PageSize,
				Limit:    limit.Limit,
			})
		}
	}

	// Unified
	if resource.Unified != nil {
		for k, v := range resource.Unified {
			spec.Linux.Resources.Unified[k] = v
		}
	}
}

func combineAnnotations(annotations map[string]string, annoToAdd map[string]string) map[string]string {
	if annotations == nil {
		annotations = map[string]string{}
	}
	if len(annoToAdd) > 0 {
		for k, v := range annoToAdd {
			annotations[k] = v
		}
	}
	return annotations
}

func combineEnvs(envs []string, overrides []*runtime.KeyValue) []string {
	envMap := map[string]string{}
	for _, env := range envs {
		kv := strings.Split(env, "=")
		if len(kv) == 2 {
			envMap[kv[0]] = kv[1]
		}
	}
	for _, env := range overrides {
		envMap[env.Key] = env.Value
	}
	envs = []string{}
	for k, v := range envMap {
		envs = append(envs, fmt.Sprintf("%s=%s", k, v))
	}
	return envs
}

func defaultSandboxSpec() *Spec {
	return &Spec{
		Version: "1.0.0",
		Process: &Process{
			User: User{
				UID: 0,
				GID: 0,
			},
			Args: []string{
				"node",
				"index.js",
			},
			Env: []string{
				"PATH=/var/lang/bin:/usr/local/bin:/usr/bin/:/bin:/opt/bin",
				"LD_LIBRARY_PATH=/var/lang/lib:/lib64:/usr/lib64:/var/runtime:/var/runtime/lib:/var/task:/var/task/lib:/opt/lib",
				"LANG=en_US.UTF-8",
				"TERM=xterm",
			},
			Cwd: "/var/task",
			Capabilities: &LinuxCapabilities{
				Bounding: []string{
					"CAP_AUDIT_WRITE",
					"CAP_KILL",
					"CAP_NET_BIND_SERVICE",
				},
				Effective: []string{
					"CAP_AUDIT_WRITE",
					"CAP_KILL",
					"CAP_NET_BIND_SERVICE",
				},
				Inheritable: []string{
					"CAP_AUDIT_WRITE",
					"CAP_KILL",
					"CAP_NET_BIND_SERVICE",
				},
				Permitted: []string{
					"CAP_AUDIT_WRITE",
					"CAP_KILL",
					"CAP_NET_BIND_SERVICE",
				},
			},
			Rlimits: []POSIXRlimit{
				{
					Type: "RLIMIT_NOFILE",
					Hard: uint64(1024),
					Soft: uint64(1024),
				},
			},
		},
		Root: &Root{
			Path:     "rootfs",
			Readonly: true,
		},
		Hostname: "runsc",
		Mounts: []Mount{
			{
				Destination: "/proc",
				Type:        "proc",
				Source:      "proc",
			},
			{
				Destination: "/dev",
				Type:        "tmpfs",
				Source:      "tmpfs",
			},
			{
				Destination: "/sys",
				Type:        "sysfs",
				Source:      "sysfs",
				Options: []string{
					"nosuid",
					"noexec",
					"nodev",
					"ro",
				},
			},
		},
		Linux: &Linux{
			Namespaces: []LinuxNamespace{
				{
					Type: PIDNamespace,
				},
				{
					Type: NetworkNamespace,
				},
				{
					Type: IPCNamespace,
				},
				{
					Type: UTSNamespace,
				},
				{
					Type: MountNamespace,
				},
			},
		},
	}
}
