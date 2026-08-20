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

package runcshim

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/inclusionAI/sandboxd/internal/util"
)

const (
	ExitVersion = 1
	ExitFile    = "runc-exit.json"
	InitPIDFile = "runc-init.pid"
	ShimPIDFile = "runc-shim.pid"
)

// ExitRecord is the durable hand-off between runc-shim and sandboxd.
type ExitRecord struct {
	Version      int       `json:"version"`
	Started      bool      `json:"started"`
	ExitCode     int       `json:"exit_code"`
	ExitedAt     time.Time `json:"exited_at"`
	RuntimeError string    `json:"runtime_error,omitempty"`
}

func ReadExit(path string) (ExitRecord, error) {
	var record ExitRecord
	data, err := os.ReadFile(path)
	if err != nil {
		return record, err
	}
	if err := json.Unmarshal(data, &record); err != nil {
		return record, err
	}
	if record.Version != ExitVersion {
		return record, fmt.Errorf("unsupported runc exit record version %d", record.Version)
	}
	return record, nil
}

func WriteExit(path string, record ExitRecord) error {
	if record.Version == 0 {
		record.Version = ExitVersion
	}
	if record.ExitedAt.IsZero() {
		record.ExitedAt = time.Now().UTC()
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return util.AtomicWriteFile(path, data, 0644)
}
