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
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/inclusionAI/sandboxd/config"
	runtimecommon "github.com/inclusionAI/sandboxd/pkg/runtime/internal/common"
)

// Recovery must preserve runtime ownership even when both variants use the
// same binary, storage layout and containers root. Fixtures are valid exited
// instances so adoption never signals or depends on a live process.
func TestRecoverInstancesPreservesBackendRuntimeOwnership(t *testing.T) {
	root := t.TempDir()
	sandboxRoot := filepath.Join(root, "containers")
	storageRoot := filepath.Join(root, "storage")
	runtimeRoot := filepath.Join(root, "runtime")
	fixtures := []struct {
		id, marker string
		malformed  bool
	}{
		{id: "sbox-kvm", marker: config.RuntimeNameFirecracker},
		{id: "sbox-pvm", marker: config.RuntimeNameFirecrackerPVM},
		{id: "sbox-legacy"},
		{id: "sbox-other", marker: config.RuntimeNameRunsc},
		{id: "sbox-malformed", malformed: true},
	}
	for _, fixture := range fixtures {
		bundle := filepath.Join(sandboxRoot, fixture.id)
		runtimeDir := (&Handler{runtimeRoot: runtimeRoot}).runtimeDirectory(fixture.id)
		if err := os.MkdirAll(filepath.Join(bundle, firecrackerArtifactsDir), 0700); err != nil {
			t.Fatal(err)
		}
		state := firecrackerPersistedState{
			ID: fixture.id, BundlePath: bundle, Exited: true,
			APIPath:     filepath.Join(runtimeDir, firecrackerAPISocket),
			VsockPath:   filepath.Join(runtimeDir, firecrackerVsock),
			OverlayPath: filepath.Join(storageRoot, fixture.id, "overlay.ext4"),
		}
		data, err := json.Marshal(state)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(bundle, firecrackerArtifactsDir, firecrackerStateFilename), data, 0600); err != nil {
			t.Fatal(err)
		}
		if fixture.malformed {
			if err := os.WriteFile(filepath.Join(bundle, "runtime.json"), []byte("{"), 0600); err != nil {
				t.Fatal(err)
			}
		} else if fixture.marker != "" {
			if err := runtimecommon.WriteSandboxRuntimeMarker(bundle, fixture.marker); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, name := range []string{config.RuntimeNameFirecracker, config.RuntimeNameFirecrackerPVM} {
		t.Run(name, func(t *testing.T) {
			handler := &Handler{
				sandboxRoot: sandboxRoot, storageRoot: storageRoot, runtimeRoot: runtimeRoot,
				runtimeName: name, instances: make(map[string]*firecrackerInstance),
			}
			handler.recoverInstances()
			for _, fixture := range fixtures {
				_, adopted := handler.instances[fixture.id]
				expected := !fixture.malformed && (fixture.marker == name || (fixture.marker == "" && name == config.RuntimeNameFirecracker))
				if adopted != expected {
					t.Errorf("recovery of %s: adopted=%v, want %v", fixture.id, adopted, expected)
				}
			}
		})
	}
}
