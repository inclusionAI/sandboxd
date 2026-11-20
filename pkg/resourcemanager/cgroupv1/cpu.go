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
)

const (
	cfsQuotaFile  = "cpu.cfs_quota_us"
	cfsPeriodFile = "cpu.cfs_period_us"
	cfsSharesFile = "cpu.shares"
)

type CfsInfo struct {
	Quota  int64
	Period int64
	Shares int64
}

func (ci *CfsInfo) load(cpuCgroupPath string) error {
	var err error

	ci.Quota, err = rawInt(cpuCgroupPath, cfsQuotaFile)
	if err != nil {
		return fmt.Errorf("failed to read quota %s: %w", cpuCgroupPath, err)
	}
	ci.Period, err = rawInt(cpuCgroupPath, cfsPeriodFile)
	if err != nil {
		return fmt.Errorf("failed to read period %s: %w", cpuCgroupPath, err)
	}
	ci.Shares, err = rawInt(cpuCgroupPath, cfsSharesFile)
	if err != nil {
		return fmt.Errorf("failed to read shares %s: %w", cpuCgroupPath, err)
	}
	return nil
}

func ReadCfsInfo(parent, name string) (*CfsInfo, error) {
	ci := &CfsInfo{}
	if err := ci.load(path.Join(parent, name)); err != nil {
		return nil, err
	}
	return ci, nil
}
