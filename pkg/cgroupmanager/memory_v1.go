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

	"github.com/sirupsen/logrus"
)

var errV1MemoryHierarchyDisabled = errors.New("cgroup v1 hierarchical memory accounting is disabled")

func prepareV1MemoryRoot(memoryMountpoint, root string) error {
	if _, err := os.Stat(memoryMountpoint); err != nil {
		return fmt.Errorf("cgroup v1 memory controller is unavailable at %s: %w", memoryMountpoint, err)
	}
	groupPath := filepath.Join(memoryMountpoint, root)
	if err := os.MkdirAll(groupPath, 0755); err != nil {
		return fmt.Errorf("create cgroup v1 memory root %s: %w", groupPath, err)
	}
	// Establish accounting before the pool can create children. Old flat
	// subtrees cannot be converted in place: keep their sandboxes recoverable
	// and let statRoot report unavailable aggregation instead of inventing zero.
	if err := enableV1MemoryHierarchy(groupPath, setV1MemoryHierarchy); err != nil {
		logrus.Warnf(
			"cgroup v1 aggregate memory unavailable at %s: %v; drain the owned subtree before enabling memory.use_hierarchy=1 and restarting",
			groupPath, err,
		)
	}
	return nil
}

func enableV1MemoryHierarchy(groupPath string, setHierarchy func(string) error) error {
	enabled, err := readV1MemoryHierarchy(groupPath)
	if err != nil || enabled {
		return err
	}
	children, err := os.ReadDir(groupPath)
	if err != nil {
		return fmt.Errorf("inspect cgroup v1 memory root %s: %w", groupPath, err)
	}
	for _, child := range children {
		if child.IsDir() {
			return fmt.Errorf("cgroup %s already has children: %w", groupPath, errV1MemoryHierarchyDisabled)
		}
	}
	filename := filepath.Join(groupPath, "memory.use_hierarchy")
	if err := setHierarchy(filename); err != nil {
		return fmt.Errorf("enable hierarchical memory accounting at %s: %w", groupPath, err)
	}
	enabled, err = readV1MemoryHierarchy(groupPath)
	if err != nil {
		return err
	}
	if !enabled {
		return fmt.Errorf("verify cgroup %s: %w", groupPath, errV1MemoryHierarchyDisabled)
	}
	return nil
}

func setV1MemoryHierarchy(filename string) error {
	// Control files are supplied by the kernel; never create a substitute if
	// the cgroup disappeared between the read and write.
	file, err := os.OpenFile(filename, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	_, writeErr := file.WriteString("1")
	return errors.Join(writeErr, file.Close())
}

func readV1MemoryHierarchy(groupPath string) (bool, error) {
	filename := filepath.Join(groupPath, "memory.use_hierarchy")
	data, err := os.ReadFile(filename)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", filename, err)
	}
	switch value := strings.TrimSpace(string(data)); value {
	case "0":
		return false, nil
	case "1":
		return true, nil
	default:
		return false, fmt.Errorf("invalid memory.use_hierarchy %q at %s", value, groupPath)
	}
}

func readV1RootMemoryUsage(groupPath string) (uint64, error) {
	enabled, err := readV1MemoryHierarchy(groupPath)
	if err != nil {
		return 0, err
	}
	if !enabled {
		return 0, fmt.Errorf("aggregate memory at %s: %w", groupPath, errV1MemoryHierarchyDisabled)
	}
	filename := filepath.Join(groupPath, "memory.usage_in_bytes")
	data, err := os.ReadFile(filename)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", filename, err)
	}
	usage, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse memory.usage_in_bytes at %s: %w", groupPath, err)
	}
	return usage, nil
}
