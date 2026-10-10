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

package common

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// WriteSandboxRuntimeMarker records which adapter owns an OCI bundle.
func WriteSandboxRuntimeMarker(bundlePath, runtimeName string) error {
	data, err := json.Marshal(struct {
		Runtime string `json:"runtime"`
	}{Runtime: runtimeName})
	if err != nil {
		return err
	}
	temporaryPath := filepath.Join(bundlePath, ".runtime.json.tmp")
	finalPath := filepath.Join(bundlePath, "runtime.json")
	if err := os.WriteFile(temporaryPath, data, 0644); err != nil {
		return err
	}
	return os.Rename(temporaryPath, finalPath)
}

// ReadSandboxRuntimeMarker returns the runtime name recorded in an OCI
// bundle's runtime.json. An absent marker returns "" (legacy bundles
// predating the marker), which callers should treat as "unknown owner"
// and skip rather than adopt when multiple runtime variants share the
// same containers root.
func ReadSandboxRuntimeMarker(bundlePath string) (string, error) {
	data, err := os.ReadFile(filepath.Join(bundlePath, "runtime.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	var marker struct {
		Runtime string `json:"runtime"`
	}
	if err := json.Unmarshal(data, &marker); err != nil {
		return "", fmt.Errorf("decode runtime marker: %w", err)
	}
	return marker.Runtime, nil
}
