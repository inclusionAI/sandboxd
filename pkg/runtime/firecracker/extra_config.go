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
	"fmt"
	"path/filepath"
	"strings"
)

const firecrackerMaxNativeWritableMounts = 16

type firecrackerNativeWritableMount struct {
	Target string `json:"target"`
}

type firecrackerExtraConfig struct {
	NativeWritableMounts []firecrackerNativeWritableMount `json:"nativeWritableMounts,omitempty"`
}

func parseFirecrackerExtraConfig(value string) (firecrackerExtraConfig, error) {
	config := firecrackerExtraConfig{}
	if strings.TrimSpace(value) == "" {
		return config, nil
	}
	if err := json.Unmarshal([]byte(value), &config); err != nil {
		return config, fmt.Errorf("decode Firecracker extra config: %w", err)
	}
	return config, nil
}

func validateFirecrackerNativeWritableMounts(
	mounts []firecrackerNativeWritableMount,
	existingTargets []string,
) error {
	if len(mounts) > firecrackerMaxNativeWritableMounts {
		return fmt.Errorf(
			"Firecracker supports at most %d native writable mounts",
			firecrackerMaxNativeWritableMounts,
		)
	}

	for index, mount := range mounts {
		target := mount.Target
		clean := filepath.Clean(target)
		if !filepath.IsAbs(target) || clean == "/" || clean != target {
			return fmt.Errorf(
				"invalid Firecracker native writable mount target %q",
				target,
			)
		}
		for _, reserved := range []string{"/dev", "/proc", "/run", "/sys", "/tmp"} {
			if firecrackerMountTargetsOverlap(clean, reserved) {
				return fmt.Errorf(
					"Firecracker native writable mount target %q conflicts with system mount %s",
					target,
					reserved,
				)
			}
		}
		for previous := 0; previous < index; previous++ {
			if firecrackerMountTargetsOverlap(clean, mounts[previous].Target) {
				return fmt.Errorf(
					"Firecracker native writable mount targets %q and %q overlap",
					mounts[previous].Target,
					target,
				)
			}
		}
		for _, existing := range existingTargets {
			if existing == "" {
				continue
			}
			if firecrackerMountTargetsOverlap(clean, filepath.Clean(existing)) {
				return fmt.Errorf(
					"Firecracker native writable mount target %q overlaps mount target %q",
					target,
					existing,
				)
			}
		}
	}
	return nil
}

func firecrackerMountTargetsOverlap(left, right string) bool {
	left = strings.TrimSuffix(filepath.Clean(left), "/") + "/"
	right = strings.TrimSuffix(filepath.Clean(right), "/") + "/"
	return strings.HasPrefix(left, right) || strings.HasPrefix(right, left)
}
