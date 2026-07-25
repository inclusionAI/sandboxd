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

package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/util"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/sirupsen/logrus"
)

// The sandbox state machine in the sandbox service:
//
//                         +              +
//                         |              |
//                         | Create       | Load
//                         |              |
//                    +----v----+         |
//                    |         |         |
//                    | Running <---------+-----------+
//                    |         |         |           |
//                    +----+-----         |           |
//                         |              |           |
//                         | Stop/Exit    |           |
//                         |              |           |
//                    +----v----+         |           |
//                    |         <---------+      +----v----+
//                    |  EXITED |                |         |
//                    |         <----------------+ UNKNOWN |
//                    +----+----+       Stop     |         |
//                         |                     +---------+
//                         | Delete
//                         v
//                      DELETED

// statusVersion is current version of sandbox status.
const statusVersion = "v1"

// versionedStatus is the internal used versioned sandbox status.
type versionedStatus struct {
	// Version indicates the version of the versioned sandbox status.
	Version string
	Status
}

// Status is the status of a sandbox.
type Status struct {
	// Pid is the init process id of the sandbox.
	Pid int
	// StartedAt is the started timestamp.
	StartedAt string
	// FinishedAt is the finished timestamp.
	FinishedAt string
	// ExitCode is the sandbox exit code.
	ExitCode int32
	// OOMKilled indicates the sandbox's init process was killed by the
	// kernel OOM killer (detected via the memory cgroup oom_control eventfd).
	// Defaults to false, including for status files written by older versions.
	OOMKilled bool `json:"oom_killed,omitempty"`
	// Unknown indicates that the sandbox status is not fully loaded.
	// This field doesn't need to be checkpointed.
	Unknown bool `json:"-"`
	// Resources has sandbox runtime resource constraints
	Resources *runtime.LinuxSandboxResources
}

// Equal compares two Status values for equality without reflection.
func (s Status) Equal(other Status) bool {
	if s.Pid != other.Pid || s.StartedAt != other.StartedAt ||
		s.FinishedAt != other.FinishedAt || s.ExitCode != other.ExitCode ||
		s.OOMKilled != other.OOMKilled ||
		s.Unknown != other.Unknown {
		return false
	}
	if s.Resources == nil && other.Resources == nil {
		return true
	}
	if s.Resources == nil || other.Resources == nil {
		return false
	}
	return s.Resources.CpuPeriod == other.Resources.CpuPeriod &&
		s.Resources.CpuQuota == other.Resources.CpuQuota &&
		s.Resources.CpuShares == other.Resources.CpuShares &&
		s.Resources.CpusetCpus == other.Resources.CpusetCpus &&
		s.Resources.CpusetMems == other.Resources.CpusetMems &&
		s.Resources.MemoryLimitInBytes == other.Resources.MemoryLimitInBytes &&
		s.Resources.MemorySwapLimitInBytes == other.Resources.MemorySwapLimitInBytes &&
		s.Resources.OomScoreAdj == other.Resources.OomScoreAdj
}

// State returns current state of the sandbox based on the sandbox status.
func (s Status) State() runtime.SandboxState {
	if s.Unknown {
		return runtime.SandboxState_SANDBOX_STATE_UNKNOWN
	}
	if s.FinishedAt != "" {
		return runtime.SandboxState_SANDBOX_STATE_EXITED
	}
	if s.StartedAt != "0" {
		return runtime.SandboxState_SANDBOX_STATE_RUNNING
	}
	return runtime.SandboxState_SANDBOX_STATE_UNKNOWN
}

// encode encodes Status into bytes in json format.
func (s *Status) encode() ([]byte, error) {
	return json.Marshal(&versionedStatus{
		Version: statusVersion,
		Status:  *s,
	})
}

// decode decodes Status from bytes.
func (s *Status) decode(data []byte) error {
	versioned := &versionedStatus{}
	if err := json.Unmarshal(data, versioned); err != nil {
		return err
	}
	// Handle old version after upgrade.
	switch versioned.Version {
	case statusVersion:
		*s = versioned.Status
		return nil
	}
	return errors.New("unsupported version")
}

// UpdateFunc is function used to update the sandbox status. If there
// is an error, the update will be rolled back.
type UpdateFunc func(Status) (Status, error)

// StatusStorage manages the sandbox status with a storage backend.
type StatusStorage interface {
	// Get a sandbox status.
	Get() Status
	// UpdateSync updates the sandbox status and the on disk checkpoint.
	// Note that the update MUST be applied in one transaction.
	UpdateSync(UpdateFunc) error
	// Update the sandbox status. Note that the update MUST be applied
	// in one transaction.
	Update(UpdateFunc) error
	// Delete the sandbox status.
	// Note:
	// * Delete should be idempotent.
	// * The status must be deleted in one transaction.
	Delete() error
}

// LoadStatus loads sandbox status from checkpoint. There shouldn't be threads
// writing to the file during loading.
func LoadStatus(sandboxRoot string) (StatusStorage, error) {
	path := filepath.Join(sandboxRoot, config.SandboxStatusFile)
	data, err := os.ReadFile(path)
	if err != nil {
		// init status with Running
		if os.IsNotExist(err) {
			return &statusStorage{
				path: path,
				status: Status{
					Unknown:   false,
					StartedAt: time.Now().Format(time.RFC3339),
				},
			}, nil
		}
		return nil, fmt.Errorf("failed to read status from %q: %w", path, err)
	}
	var status Status
	if err := status.decode(data); err != nil {
		return nil, fmt.Errorf("failed to decode status %q: %w", data, err)
	}
	return &statusStorage{
		path:   path,
		status: status,
	}, nil
}

func GenerateStatusFromState(state *svc.State, path string) StatusStorage {
	s := &statusStorage{
		status: Status{
			Pid:        state.InitProcessPid,
			StartedAt:  state.Created,
			FinishedAt: "",
			ExitCode:   0,
			Unknown:    false,
			Resources:  nil,
		},
		path: path,
	}

	// means sandboxd didn't catch the exit event
	if state.Status != svc.SandboxStatusRunning {
		s.status.FinishedAt = time.Now().String()
	}
	return s
}

func UpdateStatusByState(state *svc.State, status Status) Status {
	if state == nil {
		return status
	}
	switch state.Status {
	case svc.SandboxStatusRunning:
		status.Pid = state.InitProcessPid
		status.StartedAt = state.Created
		status.FinishedAt = ""
		status.ExitCode = -1
		status.Unknown = false
	case svc.SandboxStatusExited:
		status.Unknown = false
		status.Pid = state.InitProcessPid
		status.StartedAt = state.Created
		if status.FinishedAt == "" {
			status.FinishedAt = time.Now().String()
		}
	}
	return status
}

type statusStorage struct {
	sync.RWMutex
	path   string
	status Status
}

// Get a copy of sandbox status.
func (s *statusStorage) Get() Status {
	s.RLock()
	defer s.RUnlock()
	// Deep copy is needed in case some fields in Status are updated after Get()
	// is called.
	return deepCopyOf(s.status)
}

func deepCopyOf(s Status) Status {
	copy := s
	// Resources is the only field that is a pointer, and therefore needs
	// a manual deep copy.
	// This will need updates when new fields are added to ContainerResources.
	if s.Resources == nil {
		return copy
	}
	copy.Resources = &runtime.LinuxSandboxResources{}
	if s.Resources != nil {
		hugepageLimits := make([]*runtime.HugepageLimit, 0, len(s.Resources.HugepageLimits))
		for _, l := range s.Resources.HugepageLimits {
			if l != nil {
				hugepageLimits = append(hugepageLimits, &runtime.HugepageLimit{
					PageSize: l.PageSize,
					Limit:    l.Limit,
				})
			}
		}
		copy.Resources = &runtime.LinuxSandboxResources{
			CpuPeriod:              s.Resources.CpuPeriod,
			CpuQuota:               s.Resources.CpuQuota,
			CpuShares:              s.Resources.CpuShares,
			CpusetCpus:             s.Resources.CpusetCpus,
			CpusetMems:             s.Resources.CpusetMems,
			MemoryLimitInBytes:     s.Resources.MemoryLimitInBytes,
			MemorySwapLimitInBytes: s.Resources.MemorySwapLimitInBytes,
			OomScoreAdj:            s.Resources.OomScoreAdj,
			Unified:                s.Resources.Unified,
			HugepageLimits:         hugepageLimits,
		}
	}
	return copy
}

// UpdateSync updates the sandbox status and the on disk checkpoint.
func (s *statusStorage) UpdateSync(u UpdateFunc) error {
	s.Lock()
	defer s.Unlock()
	newStatus, err := u(s.status)
	if err != nil {
		return err
	}

	// Don't do update if the new status equal with the old status
	if s.status.Equal(newStatus) {
		return nil
	}

	data, err := newStatus.encode()
	if err != nil {
		return fmt.Errorf("failed to encode status: %w", err)
	}

	if err := util.Os().WriteFile(s.path, data, 0600); err != nil {
		return fmt.Errorf("failed to checkpoint status to %q: %w", s.path, err)
	}

	logrus.Debugf("updateSync changed new status: %+v, old status: %+v", newStatus, s.status)

	s.status = newStatus
	return nil
}

// Update the sandbox status.
func (s *statusStorage) Update(u UpdateFunc) error {
	s.Lock()
	defer s.Unlock()
	newStatus, err := u(s.status)
	if err != nil {
		return err
	}
	s.status = newStatus
	return nil
}

// Delete deletes the sandbox status from disk atomically.
func (s *statusStorage) Delete() error {
	temp := filepath.Dir(s.path) + ".del-" + filepath.Base(s.path)
	if err := os.Rename(s.path, temp); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.RemoveAll(temp)
}
