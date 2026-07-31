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

package resourcemanager

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/containerd/cgroups/v3"
	"github.com/moby/sys/mountinfo"
	"github.com/sirupsen/logrus"
)

const (
	procSelfCgroupPath = "/proc/self/cgroup"
	procMeminfoPath    = "/proc/meminfo"
	sysCPUOnlinePath   = "/sys/devices/system/cpu/online"
)

type cgroupHierarchy struct {
	mountpoint string
	current    string
}

// cgroupResourceManager reports the effective CPU and memory capacity of the
// cgroup containing sandboxd. It never creates cgroups or writes controller
// files, so it is safe to use with cgroup-disabled sandbox execution.
type cgroupResourceManager struct {
	mode      cgroups.CGMode
	cpu       cgroupHierarchy
	memory    cgroupHierarchy
	cpuset    cgroupHierarchy
	meminfo   string
	cpuOnline string
}

type selfCgroups struct {
	unified    string
	controller map[string]string
}

func newCgroupResourceManager() (*cgroupResourceManager, error) {
	selfFile, err := os.Open(procSelfCgroupPath)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", procSelfCgroupPath, err)
	}
	defer selfFile.Close()

	self, err := parseSelfCgroups(selfFile)
	if err != nil {
		return nil, err
	}
	mounts, err := mountinfo.GetMounts(mountinfo.FSTypeFilter("cgroup", "cgroup2"))
	if err != nil {
		return nil, fmt.Errorf("read cgroup mounts: %w", err)
	}

	mgr := &cgroupResourceManager{
		mode:      cgroups.Mode(),
		meminfo:   procMeminfoPath,
		cpuOnline: sysCPUOnlinePath,
	}
	switch mgr.mode {
	case cgroups.Unified:
		if self.unified == "" {
			return nil, fmt.Errorf("unified cgroup path not found in %s", procSelfCgroupPath)
		}
		hierarchy, hierarchyErr := findHierarchy(mounts, "cgroup2", "", self.unified)
		if hierarchyErr != nil {
			return nil, hierarchyErr
		}
		mgr.cpu = hierarchy
		mgr.memory = hierarchy
		mgr.cpuset = hierarchy
	case cgroups.Legacy, cgroups.Hybrid:
		mgr.cpu, err = findV1Controller(mounts, self, "cpu")
		if err != nil {
			return nil, err
		}
		mgr.memory, err = findV1Controller(mounts, self, "memory")
		if err != nil {
			return nil, err
		}
		// A v1 cpuset controller is optional. CPU quota and the online CPU
		// set still provide a safe upper bound when it is not mounted.
		if _, ok := self.controller["cpuset"]; ok {
			mgr.cpuset, err = findV1Controller(mounts, self, "cpuset")
			if err != nil {
				return nil, err
			}
		}
	case cgroups.Unavailable:
		return nil, fmt.Errorf("cgroup filesystem is unavailable")
	default:
		return nil, fmt.Errorf("unsupported cgroup mode %d", mgr.mode)
	}

	logrus.Infof(
		"node-resource cgroup provider initialized: mode=%s cgroup=%s",
		cgroupModeName(mgr.mode),
		mgr.cpu.current,
	)
	return mgr, nil
}

func findV1Controller(
	mounts []*mountinfo.Info,
	self selfCgroups,
	controller string,
) (cgroupHierarchy, error) {
	group, ok := self.controller[controller]
	if !ok {
		return cgroupHierarchy{}, fmt.Errorf(
			"cgroup v1 controller %q not found in %s",
			controller,
			procSelfCgroupPath,
		)
	}
	return findHierarchy(mounts, "cgroup", controller, group)
}

func parseSelfCgroups(reader io.Reader) (selfCgroups, error) {
	result := selfCgroups{controller: make(map[string]string)}
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.SplitN(line, ":", 3)
		if len(fields) != 3 || fields[2] == "" {
			return selfCgroups{}, fmt.Errorf("invalid cgroup membership line %q", line)
		}
		group := filepath.Clean(fields[2])
		if !filepath.IsAbs(group) {
			return selfCgroups{}, fmt.Errorf("cgroup membership path is not absolute: %q", fields[2])
		}
		if fields[1] == "" {
			result.unified = group
			continue
		}
		for _, controller := range strings.Split(fields[1], ",") {
			if controller != "" {
				result.controller[controller] = group
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return selfCgroups{}, fmt.Errorf("read cgroup membership: %w", err)
	}
	return result, nil
}

func findHierarchy(
	mounts []*mountinfo.Info,
	fsType string,
	controller string,
	group string,
) (cgroupHierarchy, error) {
	for _, mount := range mounts {
		if mount.FSType != fsType {
			continue
		}
		if fsType == "cgroup" && !commaListContains(mount.VFSOptions, controller) {
			continue
		}
		current, err := mapCgroupPath(mount, group)
		if err != nil {
			continue
		}
		return cgroupHierarchy{
			mountpoint: filepath.Clean(mount.Mountpoint),
			current:    current,
		}, nil
	}
	name := fsType
	if controller != "" {
		name += " " + controller
	}
	return cgroupHierarchy{}, fmt.Errorf("%s hierarchy not found for cgroup %s", name, group)
}

func commaListContains(list, value string) bool {
	for _, item := range strings.Split(list, ",") {
		if item == value {
			return true
		}
	}
	return false
}

func mapCgroupPath(mount *mountinfo.Info, group string) (string, error) {
	mountRoot := filepath.Clean(mount.Root)
	group = filepath.Clean(group)
	relative, err := filepath.Rel(mountRoot, group)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("cgroup %s is outside mount root %s", group, mountRoot)
	}
	return filepath.Join(mount.Mountpoint, relative), nil
}

func (m *cgroupResourceManager) GetAvailableResource() (int64, int64, error) {
	cpuMilli, err := m.cpuCapacity()
	if err != nil {
		return 0, 0, err
	}
	memoryBytes, err := m.memoryCapacity()
	if err != nil {
		return 0, 0, err
	}
	logrus.Debugf(
		"node-resource cgroup capacity: cpu=%dm memory=%d bytes",
		cpuMilli,
		memoryBytes,
	)
	return cpuMilli, memoryBytes, nil
}

func (*cgroupResourceManager) Stop() {}

func (m *cgroupResourceManager) cpuCapacity() (int64, error) {
	candidates := make([]int64, 0, 3)
	if online, err := readCPUSetFile(m.cpuOnline); err == nil && online > 0 {
		candidates = append(candidates, int64(online)*1000)
	} else if fallback := runtime.NumCPU(); fallback > 0 {
		candidates = append(candidates, int64(fallback)*1000)
	}

	if !hierarchyEmpty(m.cpuset) {
		cpuset, err := readEffectiveCPUSet(m.cpuset, m.mode)
		if err != nil {
			return 0, err
		}
		if cpuset > 0 {
			candidates = append(candidates, int64(cpuset)*1000)
		}
	}

	quota, limited, err := readCPUQuota(m.cpu, m.mode)
	if err != nil {
		return 0, err
	}
	if limited {
		candidates = append(candidates, quota)
	}

	result := minPositive(candidates...)
	if result == 0 {
		return 0, fmt.Errorf("could not determine effective cgroup CPU capacity")
	}
	return result, nil
}

func (m *cgroupResourceManager) memoryCapacity() (int64, error) {
	candidates := make([]int64, 0, 2)
	if hostMemory, err := readMemTotal(m.meminfo); err == nil && hostMemory > 0 {
		candidates = append(candidates, hostMemory)
	}

	limit, limited, err := readMemoryLimit(m.memory, m.mode)
	if err != nil {
		return 0, err
	}
	if limited {
		candidates = append(candidates, limit)
	}

	result := minPositive(candidates...)
	if result == 0 {
		return 0, fmt.Errorf("could not determine effective cgroup memory capacity")
	}
	// Match the Kubernetes provider's conservative, stable wire value.
	if rounded := (result >> 30) << 30; rounded > 0 {
		result = rounded
	}
	return result, nil
}

func readCPUQuota(hierarchy cgroupHierarchy, mode cgroups.CGMode) (int64, bool, error) {
	var minimum int64
	for _, group := range hierarchyAncestors(hierarchy) {
		var milli int64
		var limited bool
		var err error
		if mode == cgroups.Unified {
			milli, limited, err = readV2CPUQuota(filepath.Join(group, "cpu.max"))
		} else {
			milli, limited, err = readV1CPUQuota(group)
		}
		if err != nil {
			return 0, false, err
		}
		if limited && (minimum == 0 || milli < minimum) {
			minimum = milli
		}
	}
	return minimum, minimum > 0, nil
}

func readV2CPUQuota(filename string) (int64, bool, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return 0, false, fmt.Errorf("read %s: %w", filename, err)
	}
	fields := strings.Fields(string(data))
	if len(fields) != 2 {
		return 0, false, fmt.Errorf("invalid cpu.max value %q in %s", strings.TrimSpace(string(data)), filename)
	}
	period, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || period <= 0 {
		return 0, false, fmt.Errorf("invalid cpu.max period %q in %s", fields[1], filename)
	}
	if fields[0] == "max" {
		return 0, false, nil
	}
	quota, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil || quota <= 0 {
		return 0, false, fmt.Errorf("invalid cpu.max quota %q in %s", fields[0], filename)
	}
	return quotaToMilli(quota, period, filename)
}

func readV1CPUQuota(group string) (int64, bool, error) {
	quotaPath := filepath.Join(group, "cpu.cfs_quota_us")
	periodPath := filepath.Join(group, "cpu.cfs_period_us")
	quota, err := readInt64File(quotaPath)
	if err != nil {
		return 0, false, err
	}
	if quota < 0 {
		return 0, false, nil
	}
	period, err := readInt64File(periodPath)
	if err != nil {
		return 0, false, err
	}
	if quota == 0 || period <= 0 {
		return 0, false, fmt.Errorf("invalid cgroup v1 CPU quota=%d period=%d in %s", quota, period, group)
	}
	return quotaToMilli(quota, period, quotaPath)
}

func quotaToMilli(quota, period int64, source string) (int64, bool, error) {
	if quota > math.MaxInt64/1000 {
		return 0, false, fmt.Errorf("CPU quota overflows millicores in %s", source)
	}
	milli := quota * 1000 / period
	if milli <= 0 {
		return 0, false, fmt.Errorf("CPU quota is below one millicore in %s", source)
	}
	return milli, true, nil
}

func readEffectiveCPUSet(hierarchy cgroupHierarchy, mode cgroups.CGMode) (int, error) {
	filenames := []string{"cpuset.cpus", "cpuset.effective_cpus"}
	if mode == cgroups.Unified {
		filenames = []string{"cpuset.cpus.effective", "cpuset.cpus"}
	}
	for _, group := range hierarchyAncestors(hierarchy) {
		for _, name := range filenames {
			filename := filepath.Join(group, name)
			data, err := os.ReadFile(filename)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return 0, fmt.Errorf("read %s: %w", filename, err)
			}
			if strings.TrimSpace(string(data)) == "" {
				continue
			}
			count, parseErr := parseCPUSet(string(data))
			if parseErr != nil {
				return 0, fmt.Errorf("parse %s: %w", filename, parseErr)
			}
			return count, nil
		}
	}
	return 0, nil
}

func readCPUSetFile(filename string) (int, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return 0, err
	}
	return parseCPUSet(string(data))
}

type cpuRange struct {
	first int
	last  int
}

func parseCPUSet(value string) (int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	ranges := make([]cpuRange, 0, strings.Count(value, ",")+1)
	for _, field := range strings.Split(value, ",") {
		bounds := strings.SplitN(strings.TrimSpace(field), "-", 2)
		first, err := strconv.Atoi(bounds[0])
		if err != nil || first < 0 {
			return 0, fmt.Errorf("invalid CPU %q", field)
		}
		last := first
		if len(bounds) == 2 {
			last, err = strconv.Atoi(bounds[1])
			if err != nil || last < first {
				return 0, fmt.Errorf("invalid CPU range %q", field)
			}
		}
		ranges = append(ranges, cpuRange{first: first, last: last})
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].first < ranges[j].first })
	count := 0
	last := -1
	for _, item := range ranges {
		if item.last <= last {
			continue
		}
		first := item.first
		if first <= last {
			first = last + 1
		}
		count += item.last - first + 1
		last = item.last
	}
	return count, nil
}

func readMemoryLimit(hierarchy cgroupHierarchy, mode cgroups.CGMode) (int64, bool, error) {
	var minimum int64
	filename := "memory.limit_in_bytes"
	if mode == cgroups.Unified {
		filename = "memory.max"
	}
	for _, group := range hierarchyAncestors(hierarchy) {
		path := filepath.Join(group, filename)
		data, err := os.ReadFile(path)
		if err != nil {
			return 0, false, fmt.Errorf("read %s: %w", path, err)
		}
		value := strings.TrimSpace(string(data))
		if value == "max" {
			continue
		}
		limit, err := strconv.ParseInt(value, 10, 64)
		if err != nil || limit <= 0 {
			return 0, false, fmt.Errorf("invalid memory limit %q in %s", value, path)
		}
		if minimum == 0 || limit < minimum {
			minimum = limit
		}
	}
	return minimum, minimum > 0, nil
}

func readMemTotal(filename string) (int64, error) {
	file, err := os.Open(filename)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || fields[0] != "MemTotal:" {
			continue
		}
		kilobytes, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || kilobytes <= 0 || kilobytes > math.MaxInt64/1024 {
			return 0, fmt.Errorf("invalid MemTotal in %s", filename)
		}
		return kilobytes * 1024, nil
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("MemTotal not found in %s", filename)
}

func readInt64File(filename string) (int64, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", filename, err)
	}
	value, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", filename, err)
	}
	return value, nil
}

func hierarchyAncestors(hierarchy cgroupHierarchy) []string {
	if hierarchyEmpty(hierarchy) {
		return nil
	}
	root := filepath.Clean(hierarchy.mountpoint)
	current := filepath.Clean(hierarchy.current)
	result := make([]string, 0, 4)
	for {
		result = append(result, current)
		if current == root {
			return result
		}
		parent := filepath.Dir(current)
		if parent == current || !pathWithin(parent, root) {
			return result
		}
		current = parent
	}
}

func hierarchyEmpty(hierarchy cgroupHierarchy) bool {
	return hierarchy.mountpoint == "" || hierarchy.current == ""
}

func pathWithin(path, root string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator))
}

func minPositive(values ...int64) int64 {
	var result int64
	for _, value := range values {
		if value > 0 && (result == 0 || value < result) {
			result = value
		}
	}
	return result
}

func cgroupModeName(mode cgroups.CGMode) string {
	switch mode {
	case cgroups.Unified:
		return "v2"
	case cgroups.Legacy:
		return "v1"
	case cgroups.Hybrid:
		return "hybrid-v1"
	default:
		return "unavailable"
	}
}
