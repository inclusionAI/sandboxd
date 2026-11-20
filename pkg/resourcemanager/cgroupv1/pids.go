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
	pidsCurrentFile = "pids.current"
)

type Pids struct {
	Current uint32
}

func (pi *Pids) load(pidCgroupPath string) error {
	v, err := rawInt(pidCgroupPath, pidsCurrentFile)
	if err != nil {
		return fmt.Errorf("failed to load pids cgroup %s: %w", pidCgroupPath, err)
	}
	pi.Current = uint32(v)
	return nil
}

func ReadPidsInfo(parent, name string) (*Pids, error) {
	pi := &Pids{}
	if err := pi.load(path.Join(parent, name)); err != nil {
		return nil, err
	}
	return pi, nil
}
