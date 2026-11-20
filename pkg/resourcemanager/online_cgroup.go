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
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/inclusionAI/sandboxd/pkg/resourcemanager/cgroupv1"
	"github.com/inclusionAI/sandboxd/pkg/resourcemanager/sysutils"
)

const (
	defaultHostCpuCgroupPath     = "/host/proc/1/root/sys/fs/cgroup/cpu"
	defaultHostCpuacctCgroupPath = "/host/proc/1/root/sys/fs/cgroup/cpuacct"
	defaultHostMemCgroupPath     = "/host/proc/1/root/sys/fs/cgroup/memory"
	defaultHostPidsCgroupPath    = "/host/proc/1/root/sys/fs/cgroup/pids"
	faasMemCgroupPath            = "/sys/fs/cgroup/memory/"
	faasCpuacctCgroupPath        = "/sys/fs/cgroup/cpuacct/"
	faasCpusetCgroupPath         = "/sys/fs/cgroup/cpuset/"
	faasCpuCgroupPath            = "/sys/fs/cgroup/cpu/"
	zoneinfoPath                 = "/proc/zoneinfo"
)

var (
	defaultCgroupCfg = CgroupConfig{
		HostPidsCgroupPath:    defaultHostPidsCgroupPath,
		HostCpuCgroupPath:     defaultHostCpuCgroupPath,
		HostCpuacctCgroupPath: defaultHostCpuacctCgroupPath,
		HostMemCgroupPath:     defaultHostMemCgroupPath,
		FaasCpuaactCgroupPath: faasCpuacctCgroupPath,
		FaasCpusetCgroupPath:  faasCpusetCgroupPath,
		FaasCpuCgroupPath:     faasCpuCgroupPath,
		FaasMemCgroupPath:     faasMemCgroupPath,
		ZoneinfoPath:          zoneinfoPath,
	}
)

type podInfo struct {
	// cgroup info
	cfs *cgroupv1.CfsInfo
	mem *cgroupv1.Memory
}

type OnlineResourceConfig struct {
	OnlineCgroups           []string `json:"online_cgroups"`
	OfflineCgroups          []string `json:"offline_cgroups"`
	CpuFreeOverSoldRatio    int      `json:"cpu_free_over_sold_ratio"`
	CPUMaxRatio             int      `json:"cpu_max_ratio"`
	MemoryOverSoldRatio     int      `json:"memory_over_sold_ratio"`
	MemoryFreeOverSoldRatio int      `json:"memory_free_over_sold_ratio"`
	MemoryReserveRatio      int      `json:"memory_reserve_ratio"`
}

func collectOnlinePods(cfg *CgroupConfig, onlineRootCgroup string) ([]*podInfo, error) {
	// from pids cgroup
	podParent := path.Join(cfg.HostPidsCgroupPath, onlineRootCgroup)
	entries, err := os.ReadDir(podParent)
	if err != nil {
		return nil, fmt.Errorf("failed to list cgroup %s: %w", podParent, err)
	}
	var pods []*podInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if !strings.HasPrefix(entry.Name(), "pod") {
			continue
		}
		pod, err := readOnlinePod(cfg, onlineRootCgroup, entry.Name())
		if err != nil {
			if podCgroupDisappeared(path.Join(podParent, entry.Name()), err) {
				continue
			}
			return nil, err
		}
		if pod != nil {
			pods = append(pods, pod)
		}
	}
	return pods, nil
}

func readOnlinePod(cfg *CgroupConfig, root, name string) (*podInfo, error) {
	pids, err := cgroupv1.ReadPidsInfo(path.Join(cfg.HostPidsCgroupPath, root), name)
	if err != nil || pids.Current == 0 {
		return nil, err
	}
	cfs, err := cgroupv1.ReadCfsInfo(path.Join(cfg.HostCpuCgroupPath, root), name)
	if err != nil {
		return nil, err
	}
	mem, err := cgroupv1.ReadMemcgV1(path.Join(cfg.HostMemCgroupPath, root), name)
	if err != nil {
		return nil, err
	}
	if mem.Limit == 0 {
		return nil, fmt.Errorf("missing or zero hierarchical memory limit for active cgroup %s/%s", root, name)
	}
	return &podInfo{cfs: cfs, mem: mem}, nil
}

// Only ignore a missing control file if the listed pod cgroup itself is gone.
func podCgroupDisappeared(podPath string, readErr error) bool {
	if !errors.Is(readErr, os.ErrNotExist) {
		return false
	}
	_, err := os.Stat(podPath)
	return errors.Is(err, os.ErrNotExist)
}

type onlineResourceManager struct {
	cfg           CgroupConfig
	resCfg        OnlineResourceConfig
	prevCPUUsage  []int64
	prevUsageTime time.Time
	lastReportCpu float64
	lastReportMem float64
	startupTime   time.Time
}

func (mgr *onlineResourceManager) listPods() ([]*podInfo, error) {
	var pods []*podInfo
	for _, rootCgroup := range mgr.resCfg.OnlineCgroups {
		onlinePods, err := collectOnlinePods(&mgr.cfg, rootCgroup)
		if err != nil {
			return nil, err
		}
		pods = append(pods, onlinePods...)
	}
	return pods, nil
}

func (mgr *onlineResourceManager) cpuUsage(now time.Time) (cores float64, measured bool, err error) {
	rootCpuacct, err := cgroupv1.ReadCPUAcctWithoutPercpu(mgr.cfg.HostCpuacctCgroupPath, now)
	if err != nil {
		return 0, false, fmt.Errorf("failed to read root cpuacct.usage: %w", err)
	}
	counters := make([]int64, 0, len(mgr.resCfg.OfflineCgroups)+2)
	counters = append(counters, rootCpuacct.Usage)
	for _, rootCgroup := range mgr.resCfg.OfflineCgroups {
		cpuacct, err := cgroupv1.ReadCPUAcctWithoutPercpu(path.Join(mgr.cfg.HostCpuacctCgroupPath, rootCgroup), now)
		if err != nil {
			return 0, false, fmt.Errorf("failed to read %s cpuacct.usage: %w", rootCgroup, err)
		}
		counters = append(counters, cpuacct.Usage)
	}
	faasCpuacct, err := cgroupv1.ReadCPUAcctWithoutPercpu(mgr.cfg.FaasCpuaactCgroupPath, now)
	if err != nil {
		return 0, false, fmt.Errorf("failed to read faas cpuacct.usage: %w", err)
	}
	counters = append(counters, faasCpuacct.Usage)

	previous := mgr.prevCPUUsage
	elapsed := now.Sub(mgr.prevUsageTime)
	mgr.prevCPUUsage, mgr.prevUsageTime = counters, now
	if len(previous) != len(counters) || elapsed <= 0 {
		return 0, false, nil
	}
	// Check each counter before subtracting the excluded groups. A reset can
	// be hidden by the other counters when comparing only the net total.
	for i, counter := range counters {
		if counter < previous[i] {
			return 0, false, nil
		}
	}
	onlineCPUTime := float64(counters[0] - previous[0])
	for i := 1; i < len(counters); i++ {
		onlineCPUTime -= float64(counters[i] - previous[i])
	}
	return math.Max(onlineCPUTime/float64(elapsed.Nanoseconds()), 0), true, nil
}

func (mgr *onlineResourceManager) memUsage() (float64, error) {
	usage := float64(0)
	for _, rootCgroup := range mgr.resCfg.OnlineCgroups {
		mi, err := cgroupv1.ReadMemcgV1(mgr.cfg.HostMemCgroupPath, rootCgroup)
		if err != nil {
			return 0, fmt.Errorf("failed to read %s/%s mem usage: %w", mgr.cfg.HostMemCgroupPath, rootCgroup, err)
		}
		usage += float64(mi.Usage)
	}
	faasMi, err := cgroupv1.ReadMemcgV1(mgr.cfg.FaasMemCgroupPath, "")
	if err != nil {
		return 0, fmt.Errorf("failed to read %s mem usage: %w", mgr.cfg.FaasMemCgroupPath, err)
	}
	return math.Max(0, usage-float64(faasMi.Usage)), nil
}

func (mgr *onlineResourceManager) allocated() (float64, float64, error) {
	podsInfo, err := mgr.listPods()
	if err != nil {
		return 0, 0, err
	}
	var (
		cpuAllocated float64
		memAllocated float64
	)
	for _, pod := range podsInfo {
		// Ignore active pods below the existing readiness threshold.
		if float64(pod.mem.Usage)/float64(pod.mem.Limit) < 0.10 {
			continue
		}
		cpuAllocated += float64(pod.cfs.Shares) / float64(1024)
		memAllocated += float64(pod.mem.Limit)
	}
	return cpuAllocated, memAllocated, nil
}

func (mgr *onlineResourceManager) smoothValue(oldValue float64, newValue float64) float64 {
	// During first 3 minutes after startup, give more weight to new values
	elapsed := time.Since(mgr.startupTime)
	startupPeriod := 3 * time.Minute

	if elapsed <= startupPeriod {
		// Gradually transition from 0.8/0.2 to 0.99/0.01 over 3 minutes
		ratio := float64(elapsed) / float64(startupPeriod)
		oldWeight := 0.9 + (0.09 * ratio) // 0.90 -> 0.99
		newWeight := 1.0 - oldWeight
		return oldValue*oldWeight + newValue*newWeight
	}

	// After startup period, use original fixed weights
	return oldValue*0.99 + newValue*0.01
}

func (mgr *onlineResourceManager) GetAvailableResource(maxCPUMilli, maxMem int64) (int64, int64, error) {
	cfsQuota, err := cgroupv1.ReadCfsInfo(mgr.cfg.FaasCpuCgroupPath, "")
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get faas cfs info %s: %w", mgr.cfg.FaasCpuCgroupPath, err)
	}
	cpusetInfo, err := cgroupv1.ReadCpuset(mgr.cfg.FaasCpusetCgroupPath, "")
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get faas cpuset info %s: %w", mgr.cfg.FaasCpusetCgroupPath, err)
	}
	memInfo, err := sysutils.GetMemInfoFromZoneInfo(mgr.cfg.ZoneinfoPath)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read zoneinfo %s: %w", mgr.cfg.ZoneinfoPath, err)
	}
	maxCpuFixed := math.Min(float64(len(cpusetInfo.Cpus)), float64(maxCPUMilli)/1000)
	maxMemFixed := math.Min(float64(maxMem), float64(memInfo.Total))
	allocatedCpu, allocatedMem, err := mgr.allocated()
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get alloced info: %w", err)
	}
	allocatedCpu = math.Min(maxCpuFixed, allocatedCpu)
	allocatedMem = math.Min(maxMemFixed, allocatedMem)
	notAllocatedCpu := maxCpuFixed - allocatedCpu
	notAllocatedMem := maxMemFixed - allocatedMem

	memUsed, err := mgr.memUsage()
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get mem usage: %w", err)
	}
	memUsed += float64(memInfo.UnReclaimableKernel)
	cpuUsed, cpuMeasured, err := mgr.cpuUsage(time.Now())
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get cpu usage: %w", err)
	}
	// Withdraw CPU headroom while establishing a baseline. Returning an
	// error here would keep advertising the previous CPU value after a reset.
	cpuResource := 0.0
	if cpuMeasured {
		cpuResource = allocatedCpu*float64(mgr.resCfg.CPUMaxRatio)/float64(100) - cpuUsed +
			notAllocatedCpu*float64(mgr.resCfg.CpuFreeOverSoldRatio)/float64(100)
		if cfsQuota.Quota > 0 {
			quotaCPU := float64(cfsQuota.Quota) / float64(cfsQuota.Period)
			cpuResource = math.Min(cpuResource, quotaCPU)
		}
	}
	memResource := math.Min(
		allocatedMem*(1.0-float64(mgr.resCfg.MemoryReserveRatio)/float64(100))-memUsed,
		allocatedMem*float64(mgr.resCfg.MemoryOverSoldRatio)/float64(100),
	) + notAllocatedMem*float64(mgr.resCfg.MemoryFreeOverSoldRatio)/float64(100)
	logrus.Infof("report online resource info: "+
		"cpu (alloc: %f, left: %f, used: %f, measured: %t, resource: %f, last: %f), "+
		"mem (alloc: %f, left: %f, used: %f, resource: %f, last: %f)",
		allocatedCpu, notAllocatedCpu, cpuUsed, cpuMeasured, cpuResource, mgr.lastReportCpu,
		allocatedMem, notAllocatedMem, memUsed, memResource, mgr.lastReportMem)
	cpuResource = math.Max(0.0, cpuResource)
	memResource = math.Max(0.0, memResource)

	if cpuResource > mgr.lastReportCpu {
		cpuResource = mgr.smoothValue(mgr.lastReportCpu, cpuResource)
	}
	if memResource > mgr.lastReportMem {
		memResource = mgr.smoothValue(mgr.lastReportMem, memResource)
	}
	mgr.lastReportCpu = cpuResource
	mgr.lastReportMem = memResource

	return int64(cpuResource * 1000), (int64(memResource) >> 30) << 30, nil
}

func readOnlineResConfig(cfgPath string) (OnlineResourceConfig, error) {
	file, err := os.Open(cfgPath)
	if err != nil {
		return OnlineResourceConfig{}, fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	var config OnlineResourceConfig
	if err := json.NewDecoder(file).Decode(&config); err != nil {
		return OnlineResourceConfig{}, fmt.Errorf("failed to parse JSON: %w", err)
	}

	if config.CPUMaxRatio < 0 || config.CPUMaxRatio > 100 {
		return OnlineResourceConfig{}, fmt.Errorf("cpu_max_ratio must be between 0 and 100")
	}

	if config.CpuFreeOverSoldRatio < 0 || config.CpuFreeOverSoldRatio > 100 {
		return OnlineResourceConfig{}, fmt.Errorf("cpu_free_over_sold_ratio must be between 0 and 100")
	}

	if config.MemoryReserveRatio < 0 || config.MemoryReserveRatio > 100 {
		return OnlineResourceConfig{}, fmt.Errorf("memory_reserve_ratio must be between 0 and 100")
	}

	if config.MemoryOverSoldRatio < 0 || config.MemoryOverSoldRatio > 100 {
		return OnlineResourceConfig{}, fmt.Errorf("memory_over_sold_ratio must be between 0 and 100")
	}

	if config.MemoryFreeOverSoldRatio < 0 || config.MemoryFreeOverSoldRatio > 100 {
		return OnlineResourceConfig{}, fmt.Errorf("memory_free_over_sold_ratio must be between 0 and 100")
	}

	return config, nil
}

func newOnlineResourceManager(cgConfig *CgroupConfig, resCfgPath string) (*onlineResourceManager, error) {
	if cgConfig == nil {
		cgConfig = &defaultCgroupCfg
	}
	if resCfgPath == "" {
		return nil, fmt.Errorf("online resource config path is required")
	}
	resCfg, err := readOnlineResConfig(resCfgPath)
	if err != nil {
		return nil, err
	}
	// default report 1C,1G
	mgr := &onlineResourceManager{
		cfg:           *cgConfig,
		resCfg:        resCfg,
		lastReportCpu: 1.0,
		lastReportMem: float64(1 << 30),
		startupTime:   time.Now(),
	}
	return mgr, nil
}
