// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package firecracker

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/containerd/cgroups/v3"
	"github.com/inclusionAI/sandboxd/config"
)

// CheckpointCgroupPathForRoot identifies an instance's snapshot sibling outside
// the sandbox parent. Equivalent root spellings share a budget; different roots
// do not change each other's limits.
func CheckpointCgroupPathForRoot(root string) string {
	if root == "" {
		root = config.DefaultCgroupRoot
	}
	normalized := filepath.Clean("/" + strings.TrimPrefix(root, "/"))
	digest := sha256.Sum256([]byte(normalized))
	return fmt.Sprintf("%s-%x", firecrackerCheckpointCgroup, digest)
}

// ValidateCheckpointMemoryLimit rejects invalid policies before optional runtime
// initialization could omit the handler instead of reporting a config error.
func ValidateCheckpointMemoryLimit(maxBytes int64, disabled bool) error {
	return validateCheckpointMemoryLimit(maxBytes, disabled, cgroups.Mode())
}

func validateCheckpointMemoryLimit(maxBytes int64, disabled bool, mode cgroups.CGMode) error {
	if maxBytes < 0 || maxBytes > 0 && maxBytes%int64(os.Getpagesize()) != 0 {
		return errors.New("firecracker_checkpoint_memory_max_bytes must be zero or positive page-aligned bytes")
	}
	if maxBytes > 0 && (disabled || mode != cgroups.Unified) {
		return errors.New("firecracker_checkpoint_memory_max_bytes requires enabled cgroup v2 management")
	}
	return nil
}

func configureCheckpointMemory(cfg config.Config) (string, int64, error) {
	if err := ValidateCheckpointMemoryLimit(cfg.FirecrackerCheckpointMemoryMaxBytes, cfg.DisableCgroup || cfg.CgroupCacheSize <= 0); err != nil {
		return "", 0, err
	}
	return configureFirecrackerCheckpointCgroup(cfg.CgroupRootName,
		cfg.FirecrackerCheckpointMemoryMaxBytes, firecrackerCgroupMountpoint, cgroups.Mode())
}

func configureFirecrackerCheckpointCgroup(root string, maxBytes int64, mountpoint string, mode cgroups.CGMode) (string, int64, error) {
	if err := validateCheckpointMemoryLimit(maxBytes, false, mode); err != nil {
		return "", 0, err
	}
	if mode != cgroups.Unified {
		return firecrackerCheckpointCgroup, 0, nil
	}
	group := CheckpointCgroupPathForRoot(root)
	directory := filepath.Join(mountpoint, strings.TrimPrefix(group, "/"))
	if maxBytes == 0 {
		if _, err := os.Stat(directory); errors.Is(err, os.ErrNotExist) {
			return firecrackerCheckpointCgroup, 0, nil
		} else if err != nil {
			return "", 0, fmt.Errorf("stat checkpoint cgroup: %w", err)
		}
		// Removing an option on restart must not route new writes around an
		// existing limit into the historical unlimited sibling.
		existing, err := readCheckpointMemoryMax(filepath.Join(directory, "memory.max"))
		return group, existing, err
	}
	if err := os.Mkdir(directory, 0755); err != nil && !errors.Is(err, os.ErrExist) {
		return "", 0, fmt.Errorf("create checkpoint budget cgroup: %w", err)
	}
	effective, err := applyCheckpointMemoryLimit(directory, maxBytes, func(path string, value int64) error {
		return os.WriteFile(path, []byte(strconv.FormatInt(value, 10)), 0644)
	})
	return group, effective, err
}

// A zero return denotes the kernel's literal max, never numeric zero.
func readCheckpointMemoryMax(path string) (int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("read checkpoint memory.max: %w", err)
	}
	text := strings.TrimSpace(string(data))
	if text == "max" {
		return 0, nil
	}
	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("invalid checkpoint memory.max %q", text)
	}
	return value, nil
}

func verifyCheckpointMemoryLimit(directory string, maxBytes int64) error {
	current, err := readCheckpointMemoryMax(filepath.Join(directory, "memory.max"))
	if err != nil {
		return err
	}
	if current == 0 || current > maxBytes {
		return fmt.Errorf("checkpoint cgroup %s memory.max is not within %d bytes", directory, maxBytes)
	}
	return nil
}

func applyCheckpointMemoryLimit(directory string, maxBytes int64, writeMax func(string, int64) error) (int64, error) {
	path := filepath.Join(directory, "memory.max")
	existing, err := readCheckpointMemoryMax(path)
	if err != nil {
		return 0, err
	}
	if existing > 0 && existing <= maxBytes {
		return existing, nil
	}
	data, err := os.ReadFile(filepath.Join(directory, "cgroup.events"))
	if err != nil {
		return 0, fmt.Errorf("read checkpoint cgroup population: %w", err)
	}
	empty := false
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "populated" {
			if fields[1] != "0" {
				return 0, errors.New("drain checkpoint cgroup before setting or lowering memory.max")
			}
			empty = true
		}
	}
	if !empty {
		return 0, errors.New("checkpoint cgroup population is unknown")
	}
	data, err = os.ReadFile(filepath.Join(directory, "memory.current"))
	if err != nil {
		return 0, fmt.Errorf("read checkpoint memory.current: %w", err)
	}
	current, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil || current > uint64(maxBytes) {
		return 0, errors.New("checkpoint residual memory exceeds the new limit or is unreadable")
	}
	if err := writeMax(path, maxBytes); err != nil {
		return 0, fmt.Errorf("set checkpoint memory.max: %w", err)
	}
	actual, err := readCheckpointMemoryMax(path)
	if err != nil {
		return 0, err
	}
	if actual != maxBytes {
		return 0, fmt.Errorf("checkpoint memory.max readback %d does not match %d", actual, maxBytes)
	}
	return actual, nil
}
