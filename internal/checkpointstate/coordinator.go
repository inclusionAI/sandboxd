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

// Package checkpointstate coordinates only concurrent RPC execution. Durable
// checkpoint and sandbox facts live in checkpoint.Store and sandbox.Manager.
package checkpointstate

import (
	"context"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type CheckpointKey struct {
	SandboxID    string
	CheckpointID string
}

type Attempt struct {
	coordinator  *Coordinator
	operationKey string
	lockKeys     []string
	fingerprint  string
	done         chan struct{}
	err          error
}

func (a *Attempt) Wait(ctx context.Context) error {
	select {
	case <-a.done:
		return a.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

type Coordinator struct {
	mu         sync.Mutex
	operations map[string]*Attempt
	locks      map[string]*Attempt
	deleting   map[string]struct{}
}

func NewCoordinator() *Coordinator {
	return &Coordinator{
		operations: make(map[string]*Attempt),
		locks:      make(map[string]*Attempt),
		deleting:   make(map[string]struct{}),
	}
}

func (c *Coordinator) BeginCheckpoint(
	key CheckpointKey,
	fingerprint string,
) (*Attempt, bool, error) {
	if key.SandboxID == "" || key.CheckpointID == "" {
		return nil, false, status.Error(codes.InvalidArgument,
			"checkpoint sandbox and artifact IDs are required")
	}
	return c.begin(
		"checkpoint:"+key.SandboxID,
		[]string{"sandbox:" + key.SandboxID, "artifact:" + key.CheckpointID},
		key.SandboxID,
		fingerprint,
	)
}

func (c *Coordinator) BeginRestore(
	targetSandboxID string,
	fingerprint string,
) (*Attempt, bool, error) {
	if targetSandboxID == "" {
		return nil, false, status.Error(codes.InvalidArgument,
			"restore target sandbox ID is required")
	}
	return c.begin(
		"restore:"+targetSandboxID,
		[]string{"sandbox:" + targetSandboxID},
		targetSandboxID,
		fingerprint,
	)
}

func (c *Coordinator) begin(
	operationKey string,
	lockKeys []string,
	sandboxID string,
	fingerprint string,
) (*Attempt, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if existing := c.operations[operationKey]; existing != nil {
		if existing.fingerprint != fingerprint {
			return nil, false, status.Errorf(codes.FailedPrecondition,
				"sandbox %q already has a conflicting operation", sandboxID)
		}
		return existing, false, nil
	}
	if _, deleting := c.deleting[sandboxID]; deleting {
		return nil, false, status.Errorf(codes.FailedPrecondition,
			"sandbox %q is being deleted", sandboxID)
	}
	for _, key := range lockKeys {
		if owner := c.locks[key]; owner != nil {
			return nil, false, status.Errorf(codes.FailedPrecondition,
				"physical operation lock %q is already held", key)
		}
	}
	attempt := &Attempt{
		coordinator:  c,
		operationKey: operationKey,
		lockKeys:     append([]string(nil), lockKeys...),
		fingerprint:  fingerprint,
		done:         make(chan struct{}),
	}
	c.operations[operationKey] = attempt
	for _, key := range lockKeys {
		c.locks[key] = attempt
	}
	return attempt, true, nil
}

func (c *Coordinator) Complete(attempt *Attempt, err error) {
	if attempt == nil || attempt.coordinator != c {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.operations[attempt.operationKey] != attempt {
		return
	}
	delete(c.operations, attempt.operationKey)
	for _, key := range attempt.lockKeys {
		if c.locks[key] == attempt {
			delete(c.locks, key)
		}
	}
	attempt.err = err
	close(attempt.done)
}

func (c *Coordinator) BeginDelete(sandboxID string) error {
	if sandboxID == "" {
		return status.Error(codes.InvalidArgument, "sandbox ID is required")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, deleting := c.deleting[sandboxID]; deleting {
		return status.Errorf(codes.FailedPrecondition,
			"sandbox %q is already being deleted", sandboxID)
	}
	if c.locks["sandbox:"+sandboxID] != nil {
		return status.Errorf(codes.FailedPrecondition,
			"sandbox %q has an active physical operation", sandboxID)
	}
	c.deleting[sandboxID] = struct{}{}
	return nil
}

func (c *Coordinator) EndDelete(sandboxID string) {
	c.mu.Lock()
	delete(c.deleting, sandboxID)
	c.mu.Unlock()
}
