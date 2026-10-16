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
	"reflect"
	"testing"

	api "github.com/inclusionAI/sandboxd/api/runtime/v1"
)

func TestGenerateOciPreservesApplicationLibrariesWithProviderPaths(t *testing.T) {
	loader, err := NewBundleLoader("", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	loader.baseSpec.Process.Env = []string{"LD_LIBRARY_PATH=/image/lib"}
	_, spec, err := loader.GenerateOci(OciLoadOptions{
		SandboxID: "sbox-libraries", CgroupPath: "/sandbox/libraries",
		Config: StartConfig{
			Rootfs: t.TempDir(), Resources: &api.LinuxSandboxResources{},
			Envs: []*api.KeyValue{{Key: "LD_LIBRARY_PATH", Value: ":/opt/cann/lib64:/driver/lib:/application/lib::"}},
			SpecUpdates: &SpecUpdates{
				PrependLibraryPaths: []string{"/driver/lib", "", "/driver/lib"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "LD_LIBRARY_PATH=/driver/lib:/opt/cann/lib64:/application/lib"
	if !containsString(spec.Process.Env, want) {
		t.Fatalf("OCI env = %v, want %s", spec.Process.Env, want)
	}
	if containsString(spec.Process.Env, "LD_LIBRARY_PATH=/image/lib") {
		t.Fatal("request must override image libraries before driver paths are merged")
	}
}

func TestPrependLibraryPathsPreservesOtherEnvironment(t *testing.T) {
	envs := []string{"CUSTOM=a=b", "LD_LIBRARY_PATH=/application/lib"}
	got := prependLibraryPaths(envs, []string{"/driver/lib"})
	want := []string{"CUSTOM=a=b", "LD_LIBRARY_PATH=/driver/lib:/application/lib"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("env = %v, want %v", got, want)
	}
	if got := prependLibraryPaths(envs, nil); !reflect.DeepEqual(got, envs) {
		t.Fatalf("provider without library paths changed env: %v", got)
	}
}

func TestPrependLibraryPathsWithoutApplicationPath(t *testing.T) {
	got := prependLibraryPaths([]string{"PATH=/bin"}, []string{"", "/driver/lib", "/driver/lib", ""})
	want := []string{"PATH=/bin", "LD_LIBRARY_PATH=/driver/lib"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("env = %v, want %v", got, want)
	}
}
