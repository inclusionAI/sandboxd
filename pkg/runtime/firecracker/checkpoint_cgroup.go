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

package firecracker

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/containerd/cgroups/v3"
)

const (
	firecrackerCheckpointRootCgroup = "/"
	firecrackerCheckpointCgroup     = "/sandboxd-firecracker-checkpoint"
	firecrackerCgroupMountpoint     = "/sys/fs/cgroup"
)

type firecrackerProcessMover func(string, int) error

// withCheckpointSnapshotMemoryCharge moves the whole paused VMM to a shared,
// unbounded cgroup v2 leaf for the native snapshot write. Existing guest memory
// keeps its sandbox charge while new snapshot page cache stays outside it.
func (handler *Handler) withCheckpointSnapshotMemoryCharge(
	sandboxCgroup string,
	instance *firecrackerInstance,
	state firecrackerPersistedState,
	snapshot func() error,
) error {
	if cgroups.Mode() != cgroups.Unified {
		return snapshot()
	}
	if err := ensureFirecrackerCheckpointCgroup(); err != nil {
		return err
	}
	return withFirecrackerProcessInCheckpointCgroup(
		sandboxCgroup,
		state.PID,
		snapshot,
		attachFirecrackerProcess,
		func() error {
			handler.stopInstance(instance, true)
			if firecrackerProcessMatches(
				state.PID,
				handler.binary,
				state.APIPath,
				state.ID,
			) {
				return fmt.Errorf("Firecracker VMM pid %d is still running", state.PID)
			}
			return nil
		},
	)
}

func ensureFirecrackerCheckpointCgroup() error {
	directory := filepath.Join(
		firecrackerCgroupMountpoint,
		strings.TrimPrefix(firecrackerCheckpointCgroup, "/"),
	)
	if err := os.Mkdir(directory, 0755); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create Firecracker checkpoint cgroup: %w", err)
	}
	return nil
}

func withFirecrackerProcessInCheckpointCgroup(
	sandboxCgroup string,
	pid int,
	snapshot func() error,
	move firecrackerProcessMover,
	terminate func() error,
) error {
	cleanSandboxCgroup := filepath.Clean(sandboxCgroup)
	if sandboxCgroup == "" || cleanSandboxCgroup == firecrackerCheckpointRootCgroup ||
		cleanSandboxCgroup == firecrackerCheckpointCgroup {
		return fmt.Errorf("Firecracker checkpoint requires a non-root sandbox cgroup")
	}
	started := time.Now()
	if err := move(firecrackerCheckpointCgroup, pid); err != nil {
		return fmt.Errorf("move paused Firecracker VMM to checkpoint cgroup: %w", err)
	}

	movedOut := time.Now()
	snapshotErr := snapshot()
	snapshotted := time.Now()
	if err := move(sandboxCgroup, pid); err != nil {
		moveErr := fmt.Errorf(
			"move paused Firecracker VMM back to sandbox cgroup %s: %w",
			sandboxCgroup,
			err,
		)
		stopErr := terminate()
		if stopErr != nil {
			stopErr = fmt.Errorf(
				"terminate Firecracker VMM after cgroup rollback failure: %w",
				stopErr,
			)
		}
		return errors.Join(snapshotErr, moveErr, stopErr)
	}
	logrus.WithFields(logrus.Fields{
		"pid": pid, "move_out_us": movedOut.Sub(started).Microseconds(),
		"native_snapshot_us": snapshotted.Sub(movedOut).Microseconds(),
		"move_back_us":       time.Since(snapshotted).Microseconds(),
	}).Debug("firecracker: snapshot cgroup phases")
	return snapshotErr
}
