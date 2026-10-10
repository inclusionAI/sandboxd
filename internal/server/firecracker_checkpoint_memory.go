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

package server

import (
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/containerd/cgroups/v3"
	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"google.golang.org/protobuf/proto"
)

const minimumFirecrackerCheckpointHeadroom = int64(512 * 1024 * 1024)

func firecrackerCheckpointReservationOwner(sandboxID string) string {
	return "firecracker-checkpoint:" + sandboxID
}

func firecrackerCheckpointHeadroom(guestMemory int64) int64 {
	if guestMemory <= 0 {
		return 0
	}
	if guestMemory > math.MaxInt64/3*2 {
		return math.MaxInt64
	}
	headroom := guestMemory + guestMemory/2
	if headroom < minimumFirecrackerCheckpointHeadroom {
		return minimumFirecrackerCheckpointHeadroom
	}
	return headroom
}

func addResourceMemory(resource *runtime.LinuxSandboxResources, bytes int64) {
	if resource == nil || bytes <= 0 {
		return
	}
	resource.MemoryLimitInBytes = saturatingAdd(resource.MemoryLimitInBytes, bytes)
	if resource.MemorySwapLimitInBytes > 0 {
		resource.MemorySwapLimitInBytes = saturatingAdd(resource.MemorySwapLimitInBytes, bytes)
	}
}

func saturatingAdd(value, increment int64) int64 {
	if increment <= 0 {
		return value
	}
	if value > math.MaxInt64-increment {
		return math.MaxInt64
	}
	return value + increment
}

func (h *sandboxService) withTransientFirecrackerCheckpointMemory(
	ctx context.Context,
	runtimeName string,
	sandboxID string,
	cgroupPath string,
	guestResources *runtime.LinuxSandboxResources,
	handler svc.Handler,
	isCheckpoint bool,
	operation func() error,
) error {
	if !config.IsFirecrackerFamily(runtimeName) {
		return operation()
	}
	releaseSlot, err := h.acquireFirecrackerCheckpointMemorySlot(ctx)
	if err != nil {
		return err
	}
	defer releaseSlot()

	// On cgroup v2 the paused VMM is moved to an unbounded sibling cgroup only
	// while Firecracker writes the snapshot, so checkpoint needs no limit change.
	if isCheckpoint && cgroups.Mode() == cgroups.Unified {
		return operation()
	}

	if h.cgroupMgr == nil || cgroupPath == "" {
		return fmt.Errorf("Firecracker checkpoint requires a managed cgroup")
	}
	if h.resourceMod == nil {
		return errors.New("Firecracker checkpoint requires node memory reservation")
	}
	normalResources := guestResources
	if provider, ok := handler.(svc.HostResourcesProvider); ok {
		normalResources = provider.HostResources(guestResources)
	} else if guestResources != nil {
		normalResources = proto.Clone(guestResources).(*runtime.LinuxSandboxResources)
	}
	if normalResources == nil || normalResources.MemoryLimitInBytes <= 0 {
		return fmt.Errorf(
			"Firecracker checkpoint needs the persisted guest memory limit for sandbox %s",
			sandboxID,
		)
	}
	headroom := firecrackerCheckpointHeadroom(normalResources.MemoryLimitInBytes)
	if headroom == 0 {
		return fmt.Errorf(
			"Firecracker checkpoint headroom is zero for sandbox %s (memory limit %d)",
			sandboxID, normalResources.MemoryLimitInBytes,
		)
	}
	expandedResources := proto.Clone(normalResources).(*runtime.LinuxSandboxResources)
	addResourceMemory(expandedResources, headroom)
	liveLimit, readErr := h.cgroupMgr.ReadMemoryLimit(cgroupPath)
	if readErr != nil {
		return fmt.Errorf(
			"read Firecracker checkpoint cgroup memory limit for sandbox %s: %w",
			sandboxID, readErr,
		)
	}
	raiseLimit, err := shouldRaiseFirecrackerCheckpointMemoryLimit(
		normalResources.MemoryLimitInBytes,
		expandedResources.MemoryLimitInBytes,
		liveLimit,
	)
	if err != nil {
		return fmt.Errorf(
			"validate Firecracker checkpoint cgroup memory limit for sandbox %s: %w",
			sandboxID, err,
		)
	}
	releaseReservation, reserved := h.resourceMod.ReserveTransientMemory(
		firecrackerCheckpointReservationOwner(sandboxID),
		headroom,
	)
	if !reserved {
		return fmt.Errorf(
			"insufficient node memory for Firecracker checkpoint: need %d bytes of transient headroom",
			headroom,
		)
	}
	if raiseLimit {
		if err := h.cgroupMgr.Prepare(cgroupPath, expandedResources); err != nil {
			releaseReservation()
			return fmt.Errorf("raise Firecracker checkpoint cgroup memory limit: %w", err)
		}
	}
	operationErr := operation()
	// Keep the expanded host limit after the operation. Firecracker's guest
	// memory remains fixed, while the extra cgroup space holds VMM overhead and
	// reclaimable checkpoint page cache without risking a post-resume OOM.
	releaseReservation()
	return operationErr
}

// shouldRaiseFirecrackerCheckpointMemoryLimit recognizes both the normal
// initial limit and the exact expanded limit retained after an earlier
// checkpoint. Any other live value is ambiguous, so checkpoint fails closed
// rather than compounding headroom or overwriting an external change.
func shouldRaiseFirecrackerCheckpointMemoryLimit(
	normalLimit int64,
	expandedLimit int64,
	liveLimit int64,
) (bool, error) {
	switch {
	case normalLimit <= 0 || expandedLimit <= normalLimit:
		return false, fmt.Errorf(
			"invalid expected limits: normal=%d expanded=%d",
			normalLimit, expandedLimit,
		)
	case liveLimit == normalLimit:
		return true, nil
	case liveLimit == expandedLimit:
		return false, nil
	default:
		return false, fmt.Errorf(
			"unexpected live limit %d; expected normal %d or expanded %d",
			liveLimit, normalLimit, expandedLimit,
		)
	}
}

func (h *sandboxService) acquireFirecrackerCheckpointMemorySlot(
	ctx context.Context,
) (func(), error) {
	h.firecrackerCheckpointMemorySlotMu.Lock()
	if h.firecrackerCheckpointMemorySlot == nil {
		h.firecrackerCheckpointMemorySlot = make(chan struct{}, 1)
	}
	slot := h.firecrackerCheckpointMemorySlot
	h.firecrackerCheckpointMemorySlotMu.Unlock()

	select {
	case slot <- struct{}{}:
		return func() { <-slot }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
