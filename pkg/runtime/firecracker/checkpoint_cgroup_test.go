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
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestFirecrackerCheckpointCgroupMigration(t *testing.T) {
	for _, test := range []struct {
		name          string
		snapshotErr   error
		cancelContext bool
	}{
		{name: "success"},
		{name: "snapshot failure", snapshotErr: errors.New("snapshot failed")},
		{name: "context cancellation", cancelContext: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var events []string
			move := func(path string, pid int) error {
				events = append(events, fmt.Sprintf("move:%s:%d", path, pid))
				return nil
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if test.cancelContext {
				cancel()
			}
			err := withFirecrackerProcessInCheckpointCgroup(
				"/akernel/sbox-test",
				firecrackerCheckpointCgroup,
				42,
				func() error {
					events = append(events, "snapshot")
					if test.cancelContext {
						return ctx.Err()
					}
					return test.snapshotErr
				},
				move,
				func() error {
					events = append(events, "terminate")
					return nil
				},
			)
			wantErr := test.snapshotErr
			if test.cancelContext {
				wantErr = context.Canceled
			}
			if !errors.Is(err, wantErr) {
				t.Fatalf("error = %v, want %v", err, wantErr)
			}
			want := []string{
				"move:/sandboxd-firecracker-checkpoint:42",
				"snapshot",
				"move:/akernel/sbox-test:42",
			}
			if fmt.Sprint(events) != fmt.Sprint(want) {
				t.Fatalf("events = %v, want %v", events, want)
			}
		})
	}
}

func TestFirecrackerCheckpointCgroupInitialMoveFailure(t *testing.T) {
	moveErr := errors.New("move failed")
	snapshotCalled := false
	terminateCalled := false
	err := withFirecrackerProcessInCheckpointCgroup(
		"/akernel/sbox-test",
		firecrackerCheckpointCgroup,
		42,
		func() error {
			snapshotCalled = true
			return nil
		},
		func(string, int) error { return moveErr },
		func() error {
			terminateCalled = true
			return nil
		},
	)
	if !errors.Is(err, moveErr) {
		t.Fatalf("error = %v, want %v", err, moveErr)
	}
	if snapshotCalled || terminateCalled {
		t.Fatalf(
			"snapshot called = %t, terminate called = %t",
			snapshotCalled, terminateCalled,
		)
	}
}

func TestFirecrackerCheckpointCgroupRollbackFailureStopsVMM(t *testing.T) {
	rollbackErr := errors.New("rollback failed")
	terminateErr := errors.New("VMM survived")
	moveCount := 0
	terminated := false
	err := withFirecrackerProcessInCheckpointCgroup(
		"/akernel/sbox-test",
		firecrackerCheckpointCgroup,
		42,
		func() error { return nil },
		func(string, int) error {
			moveCount++
			if moveCount == 2 {
				return rollbackErr
			}
			return nil
		},
		func() error {
			terminated = true
			return terminateErr
		},
	)
	if !errors.Is(err, rollbackErr) || !errors.Is(err, terminateErr) {
		t.Fatalf("error = %v, want rollback and termination failures", err)
	}
	if !terminated {
		t.Fatal("VMM was not terminated after cgroup rollback failure")
	}
}

func TestFirecrackerCheckpointRejectsRootSourceCgroup(t *testing.T) {
	moveCalled := false
	err := withFirecrackerProcessInCheckpointCgroup(
		"/",
		firecrackerCheckpointCgroup,
		42,
		func() error { return nil },
		func(string, int) error {
			moveCalled = true
			return nil
		},
		func() error { return nil },
	)
	if err == nil || moveCalled {
		t.Fatalf("error = %v, move called = %t", err, moveCalled)
	}
}
