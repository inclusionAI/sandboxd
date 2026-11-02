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

package cgroupmanager

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ParentMemoryStats contains the live memory controls for the managed parent
// cgroup. CgroupPath is its hierarchy path, relative to the cgroup mountpoint.
// Only the literal memory.max value "max" sets Unlimited; a numeric zero is a
// finite limit. MaxBytes is zero when Unlimited is true.
type ParentMemoryStats struct {
	CgroupPath   string
	CurrentBytes uint64
	MaxBytes     uint64
	Unlimited    bool
}

// ReadParentMemory reads the configured parent's cgroup v2 memory controls
// without changing the hierarchy or relying on the startup memory budget.
// A cap change observed around the current-usage read invalidates the sample.
func (c *CgroupManager) ReadParentMemory() (ParentMemoryStats, error) {
	if c == nil {
		return ParentMemoryStats{}, errors.New("parent memory accounting requires cgroup v2")
	}
	v2, ok := c.ops.(*cgroupV2)
	if !ok || v2 == nil {
		return ParentMemoryStats{}, errors.New("parent memory accounting requires cgroup v2")
	}
	if strings.TrimSpace(c.rootName) == "" {
		return ParentMemoryStats{}, errors.New("parent memory accounting requires a non-root cgroup")
	}
	root, err := normalizeCgroupRoot(c.rootName)
	if err != nil {
		return ParentMemoryStats{}, err
	}
	if !filepath.IsAbs(v2.mountpoint) {
		return ParentMemoryStats{}, fmt.Errorf("invalid cgroup v2 mountpoint %q", v2.mountpoint)
	}
	stats, err := readParentMemoryFiles(filepath.Join(v2.mountpoint, root), os.ReadFile)
	if err != nil {
		return ParentMemoryStats{}, err
	}
	stats.CgroupPath = root
	return stats, nil
}

func readParentMemoryFiles(group string, readFile func(string) ([]byte, error)) (ParentMemoryStats, error) {
	read := func(name string, allowMax bool) (uint64, bool, error) {
		filename := filepath.Join(group, name)
		data, err := readFile(filename)
		if err != nil {
			return 0, false, fmt.Errorf("read %s: %w", filename, err)
		}
		value, unlimited, err := parseParentMemoryValue(strings.TrimSpace(string(data)), allowMax)
		if err != nil {
			return 0, false, fmt.Errorf("invalid %s at %s: %w", name, filename, err)
		}
		return value, unlimited, nil
	}

	before, beforeUnlimited, err := read("memory.max", true)
	if err != nil {
		return ParentMemoryStats{}, err
	}
	current, _, err := read("memory.current", false)
	if err != nil {
		return ParentMemoryStats{}, err
	}
	max, unlimited, err := read("memory.max", true)
	if err != nil {
		return ParentMemoryStats{}, err
	}
	if before != max || beforeUnlimited != unlimited {
		return ParentMemoryStats{}, fmt.Errorf("parent memory.max changed during read at %s", group)
	}
	return ParentMemoryStats{CurrentBytes: current, MaxBytes: max, Unlimited: unlimited}, nil
}

func parseParentMemoryValue(value string, allowMax bool) (uint64, bool, error) {
	if allowMax && value == "max" {
		return 0, true, nil
	}
	if value == "" {
		return 0, false, errors.New("empty value")
	}
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return 0, false, fmt.Errorf("expected unsigned decimal bytes, got %q", value)
		}
	}
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, false, fmt.Errorf("invalid unsigned decimal bytes %q: %w", value, err)
	}
	return n, false, nil
}
