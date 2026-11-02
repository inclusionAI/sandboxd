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

func TestGenerateOciAppliesRequestedRootfsMode(t *testing.T) {
	tests := []struct {
		name               string
		baseReadonly       bool
		requestReadonly    bool
		writableLayerBytes uint64
		wantReadonly       bool
	}{
		{
			name:            "readonly request overrides writable base",
			requestReadonly: true,
			wantReadonly:    true,
		},
		{
			name:         "writable request overrides readonly base",
			baseReadonly: true,
		},
		{
			name:               "writable layer overrides readonly request",
			requestReadonly:    true,
			writableLayerBytes: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loader, err := NewBundleLoader("", t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			loader.baseSpec.Root.Readonly = tt.baseReadonly
			_, spec, err := loader.GenerateOci(OciLoadOptions{
				SandboxID:  "sandbox-rootfs-mode",
				CgroupPath: "/sandbox/rootfs-mode",
				Config: StartConfig{
					Rootfs:                  t.TempDir(),
					RootfsReadonly:          tt.requestReadonly,
					Resources:               &runtime.LinuxSandboxResources{},
					WritableLayerLimitBytes: tt.writableLayerBytes,
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if spec.Root.Readonly != tt.wantReadonly {
				t.Fatalf("root readonly = %v, want %v", spec.Root.Readonly, tt.wantReadonly)
			}
		})
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
	if got := spec.Annotations[GVisorRootfsAnnotationPrefix+"overlay"]; got != "dir="+filestoreDir {
		t.Fatalf("rootfs overlay annotation = %q", got)
	}
	if got := spec.Annotations[GVisorRootfsAnnotationPrefix+"options"]; got != "size=1073741824" {
		t.Fatalf("rootfs options annotation = %q", got)
	}
	if spec.Root.Path != "rootfs" {
		t.Fatalf("root path = %q, want placeholder rootfs", spec.Root.Path)
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

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
