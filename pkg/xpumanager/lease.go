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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/inclusionAI/sandboxd/config"
)

const leaseSchemaVersion = 2

type leaseRecord struct {
	SchemaVersion   int      `json:"schema_version,omitempty"`
	SandboxID       string   `json:"sandbox_id"`
	Type            string   `json:"type"`
	Runtime         string   `json:"runtime,omitempty"`
	ProductModel    string   `json:"product_model,omitempty"`
	SchedulerIDs    []uint32 `json:"scheduler_ids,omitempty"`
	LogicIDs        []int32  `json:"logic_ids,omitempty"`
	StableIDs       []string `json:"stable_ids,omitempty"`
	Provider        string   `json:"provider,omitempty"`
	ProviderVersion string   `json:"provider_version,omitempty"`

	// Legacy GPU fields are accepted for rolling upgrades from schema v1.
	DeviceIDs  []uint32 `json:"device_ids,omitempty"`
	DeviceUUID []string `json:"device_uuids,omitempty"`
}

type persistedLease struct {
	bundlePath string
	record     leaseRecord
}

func encodeLease(record leaseRecord) ([]byte, error) {
	record.SchemaVersion = leaseSchemaVersion
	return json.Marshal(record)
}

func readPersistedLeases(sandboxRoot string) ([]persistedLease, error) {
	entries, err := os.ReadDir(sandboxRoot)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read sandbox root %s: %w", sandboxRoot, err)
	}
	var leases []persistedLease
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), config.SandboxIDPrefix) {
			continue
		}
		configPath := filepath.Join(sandboxRoot, entry.Name(), config.SandboxSpecFile)
		data, err := os.ReadFile(configPath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, fmt.Errorf("read XPU lease from %s: %w", configPath, err)
		}
		var spec struct {
			Annotations map[string]string `json:"annotations"`
		}
		if err := json.Unmarshal(data, &spec); err != nil {
			return nil, fmt.Errorf("parse XPU lease from %s: %w", configPath, err)
		}
		raw := spec.Annotations[AllocationAnnotation]
		if raw == "" {
			continue
		}
		var record leaseRecord
		if err := json.Unmarshal([]byte(raw), &record); err != nil {
			return nil, fmt.Errorf("parse XPU allocation annotation in %s: %w", configPath, err)
		}
		if record.SandboxID != entry.Name() || record.Type == "" {
			return nil, fmt.Errorf("invalid XPU allocation annotation in %s", configPath)
		}
		leases = append(leases, persistedLease{bundlePath: configPath, record: record})
	}
	return leases, nil
}
