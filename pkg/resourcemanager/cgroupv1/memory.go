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

package cgroupv1

import (
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"
)

const (
	memStatFile = "memory.stat"
)

var targetCgMemUsageFields = map[string]bool{
	"total_active_anon":   true,
	"total_inactive_anon": true,
	"total_unevictable":   true,
	"total_swap":          true,
}

type Memory struct {
	Limit uint64
	Usage uint64
}

func (mi *Memory) load(memcgPath string) error {
	data, err := os.ReadFile(memcgPath)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %w", memcgPath, err)
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			continue
		}
		key := parts[0]
		if key == "hierarchical_memory_limit" {
			mi.Limit, _ = strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 64)
			continue
		}
		if !targetCgMemUsageFields[key] {
			continue
		}
		value, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 64)
		if err != nil {
			return err
		}
		mi.Usage += value
	}

	return nil
}

func ReadMemcgV1(parent, name string) (*Memory, error) {
	memcgPath := path.Join(parent, name, memStatFile)
	mi := &Memory{}
	err := mi.load(memcgPath)
	if err != nil {
		return nil, err
	}
	return mi, nil
}
