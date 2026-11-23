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
	"errors"
	"math"
	"strconv"
	"strings"
	"time"
)

const (
	UsagePercpuFile = "cpuacct.usage_percpu"
	UsageFile       = "cpuacct.usage"
)

var (
	ErrTotalCPUCoresDifferent        = errors.New("total CPU cores different")
	ErrNewTimestampBeforOldTimestamp = errors.New("new timestamp before old timestamp")
	ErrNilCPUAcct                    = errors.New("cpu acct is nil")
)

type CPUAcct struct {
	RecordTime time.Time

	// reports the CPU time (in nanoseconds) consumed on each CPU by all tasks in this cgroup (including tasks lower in the hierarchy).
	UsagePercpu *UsagePercpu
	// reports the total CPU time in nanoseconds for all tasks in the cgroup.
	Usage int64
}

type UsagePercpu struct {
	Usages []int64
}

type UtilPercpu struct {
	Utils []float64
}

func (u *UtilPercpu) SubUppperZero(utilPercpu *UtilPercpu) {
	if utilPercpu == nil {
		return
	}
	if len(u.Utils) != len(utilPercpu.Utils) {
		return
	}
	for index := 0; index < len(u.Utils); index++ {
		u.Utils[index] = math.Max(0, u.Utils[index]-utilPercpu.Utils[index])
	}
}

func (u *UtilPercpu) DeepCopy() *UtilPercpu {
	res := &UtilPercpu{
		Utils: make([]float64, len(u.Utils)),
	}
	for index := 0; index < len(u.Utils); index++ {
		res.Utils[index] = u.Utils[index]
	}
	return res
}

func ReadCPUAcct(cgroupPath string, timestamp time.Time) (*CPUAcct, error) {
	res := &CPUAcct{
		RecordTime: timestamp,
	}

	// read content
	usagePercpu, err := ReadUsagePercpu(cgroupPath, UsagePercpuFile)
	if err != nil {
		return res, err
	}
	usage, err := ReadUsage(cgroupPath, UsageFile)
	if err != nil {
		return res, err
	}
	// format res and return
	res.UsagePercpu = usagePercpu
	res.Usage = usage

	return res, nil
}

func ReadCPUAcctWithoutPercpu(cgroupPath string, timestamp time.Time) (*CPUAcct, error) {
	res := &CPUAcct{
		RecordTime: timestamp,
	}

	usage, err := ReadUsage(cgroupPath, UsageFile)
	if err != nil {
		return res, err
	}
	// format res and return
	res.Usage = usage

	return res, nil
}

func ReadUsagePercpu(cgroupPath string, fileName string) (*UsagePercpu, error) {
	res := UsagePercpu{
		Usages: make([]int64, 0),
	}
	content, err := sysfsRead(cgroupPath, fileName)
	if err != nil {
		return &res, err
	} else {
		usageStr := strings.Trim(content, " \n")
		usagesStrSlice := strings.Split(usageStr, " ")
		for _, usageStr := range usagesStrSlice {
			usage, err := strconv.ParseInt(usageStr, 10, 64)
			if err != nil {
				return &res, err
			}
			res.Usages = append(res.Usages, usage)
		}
	}
	return &res, nil
}

func ReadUsage(cgroupPath string, fileName string) (int64, error) {
	return rawInt(cgroupPath, fileName)
}

func (c *CPUAcct) CalUsagePercpuNano(newCPUAcct *CPUAcct) (*UsagePercpu, error) {
	res := UsagePercpu{
		Usages: make([]int64, 0),
	}
	if (c.UsagePercpu == nil) || (newCPUAcct.UsagePercpu == nil) {
		return &res, ErrNilCPUAcct
	}
	if len(newCPUAcct.UsagePercpu.Usages) != len(c.UsagePercpu.Usages) {
		return &res, ErrTotalCPUCoresDifferent
	}
	for index := 0; index < len(newCPUAcct.UsagePercpu.Usages); index += 1 {
		value := newCPUAcct.UsagePercpu.Usages[index] - c.UsagePercpu.Usages[index]
		if value < 0 {
			value = 0
		}
		res.Usages = append(res.Usages, value)
	}
	return &res, nil
}

func (c *CPUAcct) CalUtilPercpu(newCPUAcct *CPUAcct) (*UtilPercpu, error) {
	res := UtilPercpu{
		Utils: make([]float64, 0),
	}

	timeDuration := newCPUAcct.RecordTime.Sub(c.RecordTime)
	if timeDuration <= 0 {
		return &res, ErrNewTimestampBeforOldTimestamp
	}
	usagePercpu, err := c.CalUsagePercpuNano(newCPUAcct)
	if err != nil {
		return &res, err
	}
	for index := 0; index < len(usagePercpu.Usages); index += 1 {
		res.Utils = append(res.Utils, float64(usagePercpu.Usages[index])/float64(timeDuration.Nanoseconds()))
	}
	return &res, nil
}

func (c *CPUAcct) CalUsageNano(newCPUAcct *CPUAcct) (int64, error) {
	if newCPUAcct == nil {
		return 0, ErrNilCPUAcct
	}
	res := newCPUAcct.Usage - c.Usage
	if res < 0 {
		res = 0
	}
	return res, nil
}

func (c *CPUAcct) CalUsage(newCPUAcct *CPUAcct) (float64, error) {
	if newCPUAcct == nil {
		return 0.0, ErrNilCPUAcct
	}
	timeDuration := newCPUAcct.RecordTime.Sub(c.RecordTime)
	if timeDuration <= 0 {
		return 0, ErrNewTimestampBeforOldTimestamp
	}
	usageNano, _ := c.CalUsageNano(newCPUAcct)
	return float64(usageNano) / float64(timeDuration.Nanoseconds()), nil
}
