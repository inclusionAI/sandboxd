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

package networkmanager

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/containerd/cgroups/v3"
	"github.com/sirupsen/logrus"
)

const (
	v1CPUQuotaPath  = "/sys/fs/cgroup/cpu/cpu.cfs_quota_us"
	v1CPUPeriodPath = "/sys/fs/cgroup/cpu/cpu.cfs_period_us"
	v1CPUSetPath    = "/sys/fs/cgroup/cpuset/cpuset.cpus"
	v2CPUMaxPath    = "/sys/fs/cgroup/cpu.max"
	v2CPUSetPath    = "/sys/fs/cgroup/cpuset.cpus"
	v2CPUSetEffPath = "/sys/fs/cgroup/cpuset.cpus.effective"
)

// Local CPU count cache. It stays package-local so the network pool does not
// depend on cgroup-manager implementation details.
var (
	fetchCpu sync.Once
	cpuNum   int
	cpuError error
)

func getLocalCpuNum() (int, error) {
	if cpuNum > 0 {
		return cpuNum, nil
	}
	fetchCpu.Do(func() {
		cpuNum, cpuError = detectLocalCpuNum(cgroups.Mode(), os.ReadFile)
	})
	return cpuNum, cpuError
}

type readFileFunc func(string) ([]byte, error)

func detectLocalCpuNum(mode cgroups.CGMode, readFile readFileFunc) (int, error) {
	switch mode {
	case cgroups.Unified:
		data, err := readFile(v2CPUMaxPath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return getCpuCountFromCpuset(mode, readFile)
			}
			return 0, fmt.Errorf("read %s failed: %w", v2CPUMaxPath, err)
		}
		fields := strings.Fields(string(data))
		if len(fields) != 2 {
			return 0, fmt.Errorf("invalid %s value %q", v2CPUMaxPath, strings.TrimSpace(string(data)))
		}
		if fields[0] == "max" {
			return getCpuCountFromCpuset(mode, readFile)
		}
		quota, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parse CPU quota %q: %w", fields[0], err)
		}
		period, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parse CPU period %q: %w", fields[1], err)
		}
		return cpuCountFromQuota(quota, period)

	case cgroups.Legacy, cgroups.Hybrid:
		quotaData, err := readFile(v1CPUQuotaPath)
		if err != nil {
			return 0, fmt.Errorf("read %s failed: %w", v1CPUQuotaPath, err)
		}
		periodData, err := readFile(v1CPUPeriodPath)
		if err != nil {
			return 0, fmt.Errorf("read %s failed: %w", v1CPUPeriodPath, err)
		}
		quota, err := strconv.ParseInt(strings.TrimSpace(string(quotaData)), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parse CPU quota %q: %w", strings.TrimSpace(string(quotaData)), err)
		}
		period, err := strconv.ParseInt(strings.TrimSpace(string(periodData)), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parse CPU period %q: %w", strings.TrimSpace(string(periodData)), err)
		}
		if quota == -1 {
			return getCpuCountFromCpuset(mode, readFile)
		}
		return cpuCountFromQuota(quota, period)

	default:
		return 0, fmt.Errorf("cgroup filesystem is unavailable")
	}
}

func cpuCountFromQuota(quota, period int64) (int, error) {
	if quota <= 0 || period <= 0 {
		return 0, fmt.Errorf("invalid CPU quota %d and period %d", quota, period)
	}
	logrus.Debugf("local cpu quota is %v, period is %v", quota, period)
	count := quota / period
	if quota%period != 0 {
		count++
	}
	return int(count), nil
}

func getCpuCountFromCpuset(mode cgroups.CGMode, readFile readFileFunc) (int, error) {
	paths := []string{v1CPUSetPath}
	if mode == cgroups.Unified {
		paths = []string{v2CPUSetEffPath, v2CPUSetPath}
	}

	var lastErr error
	for _, path := range paths {
		data, err := readFile(path)
		if err != nil {
			lastErr = fmt.Errorf("read %s failed: %w", path, err)
			continue
		}
		count, err := parseCPUSet(string(data))
		if err == nil {
			return count, nil
		}
		lastErr = fmt.Errorf("parse %s failed: %w", path, err)
	}
	return 0, lastErr
}

func parseCPUSet(value string) (int, error) {
	cpus := strings.TrimSpace(value)
	if cpus == "" {
		return 0, fmt.Errorf("cpuset is empty")
	}

	count := 0
	for _, item := range strings.Split(cpus, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			return 0, fmt.Errorf("invalid empty CPU range")
		}
		parts := strings.Split(item, "-")
		if len(parts) == 1 {
			if _, err := strconv.Atoi(parts[0]); err != nil {
				return 0, fmt.Errorf("invalid CPU %q: %w", item, err)
			}
			count++
			continue
		}
		if len(parts) != 2 {
			return 0, fmt.Errorf("invalid CPU range %q", item)
		}
		start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			return 0, fmt.Errorf("invalid CPU range %q: %w", item, err)
		}
		end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return 0, fmt.Errorf("invalid CPU range %q: %w", item, err)
		}
		if start > end {
			return 0, fmt.Errorf("invalid descending CPU range %q", item)
		}
		count += end - start + 1
	}
	if count == 0 {
		return 0, fmt.Errorf("cpuset contains no CPUs")
	}
	return count, nil
}
