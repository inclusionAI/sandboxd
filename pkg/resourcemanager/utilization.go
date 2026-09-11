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

package resourcemanager

import (
	"bufio"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/containerd/cgroups/v3"
	"github.com/moby/sys/mountinfo"
)

// Utilization contains advisory fractions, independent of scheduler capacity.
// A nil field is encoded as null, distinguishing unavailable data from zero.
type Utilization struct {
	CPU    *float64 `json:"cpu"`
	Memory *float64 `json:"memory"`
	PID    *float64 `json:"pid"`
	FD     *float64 `json:"fd"`
	Disk   *float64 `json:"disk"`
}

type utilizationSource interface{ Sample() Utilization }

type utilizationGroup struct {
	kind       string
	path       string
	accounting string // CPU accounting may have a separate v1 mount.
	unified    bool
}

type cpuObservation struct {
	usage uint64
	idle  uint64
	at    time.Time
	limit float64
}

type utilizationSampler struct {
	proc     string
	now      func() time.Time
	groups   func() []utilizationGroup
	previous map[string]cpuObservation
}

func newUtilizationSampler(sandboxRoot string) *utilizationSampler {
	return &utilizationSampler{
		proc: "/proc", now: time.Now,
		groups:   func() []utilizationGroup { return discoverUtilizationGroups(sandboxRoot) },
		previous: make(map[string]cpuObservation),
	}
}

// Sample performs bounded, read-only work: no per-sandbox or process-tree scan.
// Only this sampler's refresh-loop goroutine calls Sample.
func (s *utilizationSampler) Sample() Utilization {
	now := s.now()
	next := make(map[string]cpuObservation)
	result := Utilization{Memory: hostMemoryUtilization(s.proc), FD: fdUtilization(s.proc)}
	if current, ok := hostCPUObservation(s.proc); ok {
		next["host"] = current
		if previous, exists := s.previous["host"]; exists && current.usage > previous.usage && current.idle >= previous.idle {
			total, idle := current.usage-previous.usage, current.idle-previous.idle
			if idle <= total {
				result.CPU = utilizationRatio(float64(total-idle), float64(total))
			}
		}
	}
	for _, group := range s.groups() {
		switch group.kind {
		case "cpu":
			current, ok := cgroupCPUObservation(group)
			if !ok {
				continue
			}
			current.at = now
			key := group.path
			next[key] = current
			previous, exists := s.previous[key]
			elapsed := now.Sub(previous.at).Seconds()
			if exists && current.limit == previous.limit && current.usage >= previous.usage && elapsed > 0 {
				ratio := utilizationRatio(float64(current.usage-previous.usage)/float64(time.Second), elapsed*current.limit)
				result.CPU = maximumUtilization(result.CPU, ratio)
			}
		case "memory":
			usage, limit := "memory.usage_in_bytes", "memory.limit_in_bytes"
			if group.unified {
				usage, limit = "memory.current", "memory.max"
			}
			result.Memory = maximumUtilization(result.Memory, cgroupUtilization(group.path, usage, limit, !group.unified))
		case "pids":
			result.PID = maximumUtilization(result.PID, cgroupUtilization(group.path, "pids.current", "pids.max", false))
		}
	}
	s.previous = next
	return result
}

func utilizationRatio(usage, limit float64) *float64 {
	if math.IsNaN(usage) || math.IsInf(usage, 0) || math.IsNaN(limit) || math.IsInf(limit, 0) || usage < 0 || limit <= 0 {
		return nil
	}
	value := math.Min(usage/limit, 1)
	return &value
}

func maximumUtilization(a, b *float64) *float64 {
	if a == nil || (b != nil && *b > *a) {
		return b
	}
	return a
}

func readUintFile(path string) (uint64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	return value, err == nil
}

func cgroupUtilization(path, usageFile, limitFile string, v1Memory bool) *float64 {
	limit, ok := readUintFile(filepath.Join(path, limitFile))
	// v1 represents unlimited memory with a page-aligned LONG_MAX sentinel.
	if !ok || limit == 0 || (v1Memory && limit >= 1<<60) {
		return nil
	}
	usage, ok := readUintFile(filepath.Join(path, usageFile))
	if !ok {
		return nil
	}
	return utilizationRatio(float64(usage), float64(limit))
}

func hostCPUObservation(proc string) (cpuObservation, bool) {
	data, err := os.ReadFile(filepath.Join(proc, "stat"))
	if err != nil {
		return cpuObservation{}, false
	}
	fields := strings.Fields(strings.SplitN(string(data), "\n", 2)[0])
	if len(fields) < 5 || fields[0] != "cpu" {
		return cpuObservation{}, false
	}
	result := cpuObservation{}
	// user, nice, system, idle, iowait, irq, softirq, steal. guest is already
	// included in user/nice, so additional fields must not be added again.
	for i := 1; i < len(fields) && i <= 8; i++ {
		value, err := strconv.ParseUint(fields[i], 10, 64)
		if err != nil || value > math.MaxUint64-result.usage {
			return cpuObservation{}, false
		}
		result.usage += value
		if i == 4 || i == 5 {
			result.idle += value
		}
	}
	return result, true
}

func hostMemoryUtilization(proc string) *float64 {
	data, err := os.ReadFile(filepath.Join(proc, "meminfo"))
	if err != nil {
		return nil
	}
	var total, available uint64
	var haveTotal, haveAvailable bool
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[2] != "kB" {
			continue
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			total, haveTotal = value, true
		case "MemAvailable:":
			available, haveAvailable = value, true
		}
	}
	if !haveTotal || !haveAvailable || available > total {
		return nil
	}
	return utilizationRatio(float64(total-available), float64(total))
}

func fdUtilization(proc string) *float64 {
	var result *float64
	if data, err := os.ReadFile(filepath.Join(proc, "sys/fs/file-nr")); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) == 3 {
			allocated, e1 := strconv.ParseUint(fields[0], 10, 64)
			unused, e2 := strconv.ParseUint(fields[1], 10, 64)
			limit, e3 := strconv.ParseUint(fields[2], 10, 64)
			if e1 == nil && e2 == nil && e3 == nil && unused <= allocated {
				result = utilizationRatio(float64(allocated-unused), float64(limit))
			}
		}
	}
	data, err := os.ReadFile(filepath.Join(proc, "self/limits"))
	if err != nil {
		return result
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 6 || strings.Join(fields[:3], " ") != "Max open files" {
			continue
		}
		limit, err := strconv.ParseUint(fields[3], 10, 64)
		if err != nil {
			break
		}
		entries, err := os.ReadDir(filepath.Join(proc, "self/fd"))
		if err == nil {
			result = maximumUtilization(result, utilizationRatio(float64(len(entries)), float64(limit)))
		}
		break
	}
	return result
}

func cgroupCPUObservation(group utilizationGroup) (cpuObservation, bool) {
	var milli int64
	var limited bool
	var err error
	var usage uint64
	var ok bool
	if group.unified {
		milli, limited, err = readV2CPUQuota(filepath.Join(group.path, "cpu.max"))
		if err != nil || !limited {
			return cpuObservation{}, false
		}
		data, readErr := os.ReadFile(filepath.Join(group.path, "cpu.stat"))
		if readErr != nil {
			return cpuObservation{}, false
		}
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) == 2 && fields[0] == "usage_usec" {
				value, parseErr := strconv.ParseUint(fields[1], 10, 64)
				if parseErr == nil && value <= math.MaxUint64/uint64(time.Microsecond) {
					usage, ok = value*uint64(time.Microsecond), true
				}
				break
			}
		}
	} else {
		milli, limited, err = readV1CPUQuota(group.path)
		if err != nil || !limited {
			return cpuObservation{}, false
		}
		usage, ok = readUintFile(filepath.Join(group.accounting, "cpuacct.usage"))
	}
	return cpuObservation{usage: usage, limit: float64(milli) / 1000}, ok
}

func discoverUtilizationGroups(sandboxRoot string) []utilizationGroup {
	data, err := os.Open(procSelfCgroupPath)
	if err != nil {
		return nil
	}
	defer data.Close()
	self, err := parseSelfCgroups(data)
	if err != nil {
		return nil
	}
	mounts, err := mountinfo.GetMounts(mountinfo.FSTypeFilter("cgroup", "cgroup2"))
	if err != nil {
		return nil
	}
	return utilizationGroups(mounts, self, cgroups.Mode() == cgroups.Unified, sandboxRoot)
}

func utilizationGroups(mounts []*mountinfo.Info, self selfCgroups, unified bool, sandboxRoot string) []utilizationGroup {
	var result []utilizationGroup
	seen := make(map[string]bool)
	for _, kind := range []string{"cpu", "memory", "pids"} {
		fsType, controller, membership := "cgroup", kind, self.controller[kind]
		if unified {
			fsType, controller, membership = "cgroup2", "", self.unified
		}
		if membership == "" {
			continue
		}
		hierarchy, err := findHierarchy(mounts, fsType, controller, membership)
		if err != nil {
			continue
		}
		paths := hierarchyAncestors(hierarchy)
		if sandboxRoot != "" {
			root := filepath.Join(hierarchy.mountpoint, filepath.Clean("/"+sandboxRoot))
			paths = append(paths, hierarchyAncestors(cgroupHierarchy{mountpoint: hierarchy.mountpoint, current: root})...)
		}
		for _, path := range paths {
			key := kind + ":" + path
			if seen[key] {
				continue
			}
			seen[key] = true
			group := utilizationGroup{kind: kind, path: path, unified: unified}
			if kind == "cpu" && !unified {
				// A split cpuacct hierarchy is usable only when membership matches.
				// Resolve each ancestor's logical path to preserve usage/limit scope.
				if self.controller["cpuacct"] != membership {
					continue
				}
				for _, mount := range mounts {
					if mount.Mountpoint != hierarchy.mountpoint {
						continue
					}
					relative, relErr := filepath.Rel(hierarchy.mountpoint, path)
					if relErr != nil {
						continue
					}
					logical := filepath.Join(mount.Root, relative)
					accounting, acctErr := findHierarchy(mounts, "cgroup", "cpuacct", logical)
					if acctErr == nil {
						group.accounting = accounting.current
					}
					break
				}
				if group.accounting == "" {
					continue
				}
			}
			result = append(result, group)
		}
	}
	return result
}
