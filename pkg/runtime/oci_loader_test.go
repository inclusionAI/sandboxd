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
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
)

func Test_combineEnvs(t *testing.T) {
	type args struct {
		envs      []string
		overrides []*runtime.KeyValue
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "combineEnvs",
			args: args{
				envs: []string{"a=1", "b=2"},
				overrides: []*runtime.KeyValue{
					{
						Key:   "c",
						Value: "3",
					},
				},
			},
			want: []string{"a=1", "b=2", "c=3"},
		},
		{
			name: "combineEnvs-0",
			args: args{
				envs: []string{"a=1", "b=2"},
				overrides: []*runtime.KeyValue{
					{
						Key:   "a",
						Value: "3",
					},
				},
			},
			want: []string{"b=2", "a=3"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := combineEnvs(tt.args.envs, tt.args.overrides)
			sort.Strings(got)
			sort.Strings(tt.want)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("combineEnvs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGenerateOciPreservesEntrypoint(t *testing.T) {
	loader, err := NewBundleLoader("", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	command := []string{
		"/opt/runtime/bin/bootstrap",
		"--config",
		"/etc/sandbox/runtime.yaml",
	}
	_, spec, err := loader.GenerateOci(OciLoadOptions{
		SandboxID:  "sandbox-id",
		CgroupPath: "/sandbox/test",
		Config: StartConfig{
			Rootfs:    t.TempDir(),
			Command:   command,
			Resources: &runtime.LinuxSandboxResources{},
			Mounts: []*runtime.Mount{{
				Target: "/opt/runtime",
				Type:   "erofs",
				Source: &runtime.Mount_HostPath{HostPath: "/runtime.img"},
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(spec.Process.Args, command) {
		t.Fatalf("args = %v, want %v", spec.Process.Args, command)
	}
}

func TestGenerateOciAppliesProviderUpdatesLast(t *testing.T) {
	loader, err := NewBundleLoader("", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, spec, err := loader.GenerateOci(OciLoadOptions{
		SandboxID:  "sandbox-gpu",
		CgroupPath: "/sandbox/gpu",
		Config: StartConfig{
			Rootfs:    t.TempDir(),
			Resources: &runtime.LinuxSandboxResources{},
			Envs: []*runtime.KeyValue{{
				Key:   "NVIDIA_VISIBLE_DEVICES",
				Value: "caller-value",
			}},
			Annotations: map[string]string{
				"sandbox.akernel.dev/xpu-allocation": "caller-value",
			},
			SpecUpdates: &SpecUpdates{
				Envs: []*runtime.KeyValue{{
					Key:   "NVIDIA_VISIBLE_DEVICES",
					Value: "GPU-uuid-0,GPU-uuid-2",
				}},
				Prestart: []Hook{{
					Path: "/usr/bin/nvidia-container-runtime-hook",
					Args: []string{"nvidia-container-runtime-hook", "prestart"},
				}},
				Annotations: map[string]string{
					"sandbox.akernel.dev/xpu-allocation": "sandboxd-value",
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(spec.Process.Env, "NVIDIA_VISIBLE_DEVICES=GPU-uuid-0,GPU-uuid-2") {
		t.Fatalf("provider environment missing from %v", spec.Process.Env)
	}
	if len(spec.Hooks.Prestart) != 1 ||
		spec.Hooks.Prestart[0].Path != "/usr/bin/nvidia-container-runtime-hook" {
		t.Fatalf("provider hook missing from %+v", spec.Hooks)
	}
	if got := spec.Annotations["sandbox.akernel.dev/xpu-allocation"]; got != "sandboxd-value" {
		t.Fatalf("provider annotation = %q, want sandboxd-value", got)
	}
}

func TestGenerateOciWithoutCgroup(t *testing.T) {
	loader, err := NewBundleLoader("", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	shares := uint64(1024)
	memory := int64(512 << 20)
	_, spec, err := loader.GenerateOci(OciLoadOptions{
		SandboxID: "sandbox-no-cgroup",
		Config: StartConfig{
			Rootfs:        t.TempDir(),
			DisableCgroup: true,
			Resources: &runtime.LinuxSandboxResources{
				CpuShares:          shares,
				MemoryLimitInBytes: memory,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if spec.Linux.CgroupsPath != "" {
		t.Fatalf("cgroupsPath = %q, want empty", spec.Linux.CgroupsPath)
	}
	if spec.Linux.Resources != nil {
		t.Fatalf("Linux resources = %+v, want nil", spec.Linux.Resources)
	}
}

func TestGenerateOciRejectsEscapingSandboxID(t *testing.T) {
	loader, err := NewBundleLoader("", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = loader.GenerateOci(OciLoadOptions{
		SandboxID:  "../outside",
		CgroupPath: "/sandbox/test",
		Config: StartConfig{
			Rootfs:  t.TempDir(),
			Command: []string{"/bin/true"},
		},
	})
	if err == nil {
		t.Fatal("GenerateOci accepted a sandbox ID that escapes the bundle root")
	}
}

func TestGenerateOciUsesDiskBackedRootfsImageOverlay(t *testing.T) {
	bundleRoot := t.TempDir()
	rootfsImage := filepath.Join(t.TempDir(), "rootfs.img")
	if err := os.WriteFile(rootfsImage, []byte("erofs-placeholder"), 0644); err != nil {
		t.Fatal(err)
	}
	loader, err := NewBundleLoader("", bundleRoot)
	if err != nil {
		t.Fatal(err)
	}
	filestoreDir := filepath.Join(t.TempDir(), "filestore")
	_, spec, err := loader.GenerateOci(OciLoadOptions{
		SandboxID:  "sandbox-storage",
		CgroupPath: "/sandbox/storage",
		Config: StartConfig{
			Rootfs:                  rootfsImage,
			Resources:               &runtime.LinuxSandboxResources{},
			WritableLayerLimitBytes: 1 << 30,
		},
		UseGVisorRootfsImageAnnotations: true,
		RootfsOverlayDir:                filestoreDir,
		RootfsOverlaySize:               "1073741824",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := spec.Annotations[gvisorRootfsAnnotationPrefix+"overlay"]; got != "dir="+filestoreDir {
		t.Fatalf("rootfs overlay annotation = %q", got)
	}
	if got := spec.Annotations[gvisorRootfsAnnotationPrefix+"options"]; got != "size=1073741824" {
		t.Fatalf("rootfs options annotation = %q", got)
	}
	if spec.Root.Path != "rootfs" {
		t.Fatalf("root path = %q, want placeholder rootfs", spec.Root.Path)
	}
	if _, err := os.Stat(filepath.Join(bundleRoot, "sandbox-storage", "rootfs", "etc", "hosts")); err != nil {
		t.Fatalf("placeholder hosts mount target: %v", err)
	}
	if !hasMountDestination(spec.Mounts, "/etc/hosts") {
		t.Fatalf("hosts mount missing from %+v", spec.Mounts)
	}
}

func TestGenerateOciRejectsMemoryBackedRootfsImageOverlay(t *testing.T) {
	rootfsImage := filepath.Join(t.TempDir(), "rootfs.img")
	if err := os.WriteFile(rootfsImage, []byte("erofs-placeholder"), 0644); err != nil {
		t.Fatal(err)
	}
	loader, err := NewBundleLoader("", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	loader.baseSpec.Root.Readonly = false
	_, _, err = loader.GenerateOci(OciLoadOptions{
		SandboxID:  "sandbox-storage",
		CgroupPath: "/sandbox/storage",
		Config: StartConfig{
			Rootfs:    rootfsImage,
			Resources: &runtime.LinuxSandboxResources{},
		},
		UseGVisorRootfsImageAnnotations: true,
	})
	if err == nil || !strings.Contains(err.Error(), "requires a filestore directory") {
		t.Fatalf("GenerateOci() error = %v, want missing filestore error", err)
	}
}

func TestPrepareRunscHostsMount(t *testing.T) {
	bundleDir := t.TempDir()
	spec := &Spec{}

	if err := prepareRunscHostsMount(spec, bundleDir); err != nil {
		t.Fatal(err)
	}
	if len(spec.Mounts) != 1 {
		t.Fatalf("mount count = %d, want 1", len(spec.Mounts))
	}
	mount := spec.Mounts[0]
	if mount.Destination != "/etc/hosts" || mount.Type != "bind" {
		t.Fatalf("hosts mount = %+v", mount)
	}
	if !reflect.DeepEqual(mount.Options, []string{"bind", "ro"}) {
		t.Fatalf("hosts mount options = %v", mount.Options)
	}
	data, err := os.ReadFile(filepath.Join(bundleDir, "hosts"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != config.LocalhostHostsFileContent {
		t.Fatalf("hosts content = %q", data)
	}
}

func TestPrepareRunscHostsMountPreservesExplicitMount(t *testing.T) {
	explicit := Mount{Destination: "/etc/hosts", Source: "/custom/hosts"}
	spec := &Spec{Mounts: []Mount{explicit}}
	bundleDir := t.TempDir()

	if err := prepareRunscHostsMount(spec, bundleDir); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(spec.Mounts, []Mount{explicit}) {
		t.Fatalf("mounts = %+v, want explicit hosts mount", spec.Mounts)
	}
	if _, err := os.Stat(filepath.Join(bundleDir, "hosts")); !os.IsNotExist(err) {
		t.Fatalf("generated hosts file should be absent, err=%v", err)
	}
}

func TestPrepareRunscHostsMountPreservesExplicitParentMount(t *testing.T) {
	explicit := Mount{Destination: "/etc", Source: "/custom/etc"}
	spec := &Spec{Mounts: []Mount{explicit}}
	bundleDir := t.TempDir()

	if err := prepareRunscHostsMount(spec, bundleDir); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(spec.Mounts, []Mount{explicit}) {
		t.Fatalf("mounts = %+v, want explicit /etc mount", spec.Mounts)
	}
	if _, err := os.Stat(filepath.Join(bundleDir, "hosts")); !os.IsNotExist(err) {
		t.Fatalf("generated hosts file should be absent, err=%v", err)
	}
}

func TestPrepareRunscHostsMountReplacesStaleHostsFileAtomically(t *testing.T) {
	bundleDir := t.TempDir()
	hostsPath := filepath.Join(bundleDir, "hosts")
	staleTarget := filepath.Join(bundleDir, "stale")
	if err := os.WriteFile(staleTarget, []byte("do not replace\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(staleTarget, hostsPath); err != nil {
		t.Fatal(err)
	}

	spec := &Spec{}
	if err := prepareRunscHostsMount(spec, bundleDir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(hostsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0644 {
		t.Fatalf("hosts mode = %v, want regular 0644", info.Mode())
	}
	data, err := os.ReadFile(staleTarget)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "do not replace\n" {
		t.Fatalf("stale symlink target changed: %q", data)
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func hasMountDestination(mounts []Mount, destination string) bool {
	for _, mount := range mounts {
		if mount.Destination == destination {
			return true
		}
	}
	return false
}
