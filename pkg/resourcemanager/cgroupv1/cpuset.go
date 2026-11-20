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
	"path"
	"strconv"
	"strings"
)

const (
	cpusetFile = "cpuset.cpus"
)

type Cpuset struct {
	Cpus map[uint32]struct{}
}

func (ci *Cpuset) HasCpu(cpu uint32) bool {
	_, ok := ci.Cpus[cpu]
	return ok
}

func (ci *Cpuset) load(cpusetPath string) error {
	cpusetStr, err := sysfsRead(cpusetPath, cpusetFile)
	if err != nil {
		return fmt.Errorf("failed to read cpuset %s/%s: %w", cpusetPath, cpusetFile, err)
	}
	ci.Cpus = make(map[uint32]struct{})

	cpusetStr = strings.TrimSpace(cpusetStr)
	if cpusetStr == "" {
		return nil
	}
	parts := strings.Split(cpusetStr, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return fmt.Errorf("invalid range format: %s", part)
			}
			startStr := strings.TrimSpace(rangeParts[0])
			endStr := strings.TrimSpace(rangeParts[1])
			start, err := strconv.Atoi(startStr)
			if err != nil {
				return fmt.Errorf("invalid start of range '%s': %w", startStr, err)
			}
			end, err := strconv.Atoi(endStr)
			if err != nil {
				return fmt.Errorf("invalid end of range '%s': %w", endStr, err)
			}
			if start > end {
				return fmt.Errorf("invalid range: start (%d) is greater than end (%d)", start, end)
			}
			for i := start; i <= end; i++ {
				ci.Cpus[uint32(i)] = struct{}{}
			}
		} else {
			cpu, err := strconv.Atoi(part)
			if err != nil {
				return fmt.Errorf("invalid cpu number '%s': %w", part, err)
			}
			ci.Cpus[uint32(cpu)] = struct{}{}
		}
	}
	return nil
}

func ReadCpuset(parent, name string) (*Cpuset, error) {
	ci := &Cpuset{}
	if err := ci.load(path.Join(parent, name)); err != nil {
		return nil, err
	}
	return ci, nil
}
