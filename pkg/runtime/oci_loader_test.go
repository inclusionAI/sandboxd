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

	if err := prepareRunscHostsMount(spec, t.TempDir()); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(spec.Mounts, []Mount{explicit}) {
		t.Fatalf("mounts = %+v, want explicit hosts mount", spec.Mounts)
	}
}
