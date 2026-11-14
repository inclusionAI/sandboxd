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
	"math"
	"testing"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFirecrackerCheckpointHeadroom(t *testing.T) {
	assert.Zero(t, firecrackerCheckpointHeadroom(0))
	assert.Equal(t, minimumFirecrackerCheckpointHeadroom, firecrackerCheckpointHeadroom(64<<20))
	assert.Equal(t, int64(6<<30), firecrackerCheckpointHeadroom(4<<30))
	assert.Equal(t, int64(math.MaxInt64), firecrackerCheckpointHeadroom(math.MaxInt64))
}

func TestAddResourceMemory(t *testing.T) {
	resources := &runtime.LinuxSandboxResources{
		MemoryLimitInBytes:     4 << 30,
		MemorySwapLimitInBytes: 4 << 30,
	}
	addResourceMemory(resources, 6<<30)
	assert.Equal(t, int64(10<<30), resources.MemoryLimitInBytes)
	assert.Equal(t, int64(10<<30), resources.MemorySwapLimitInBytes)

	resources.MemoryLimitInBytes = math.MaxInt64 - 1
	addResourceMemory(resources, 2)
	assert.Equal(t, int64(math.MaxInt64), resources.MemoryLimitInBytes)
}

func TestFirecrackerCheckpointMemorySlotHonorsCancellation(t *testing.T) {
	service := &sandboxService{}
	release, err := service.acquireFirecrackerCheckpointMemorySlot(
		context.Background(),
	)
	assert.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err = service.acquireFirecrackerCheckpointMemorySlot(ctx)
	assert.ErrorIs(t, err, context.DeadlineExceeded)

	release()
	release, err = service.acquireFirecrackerCheckpointMemorySlot(
		context.Background(),
	)
	assert.NoError(t, err)
	release()
}

func TestFirecrackerCheckpointConcurrencyValidation(t *testing.T) {
	for _, value := range []int{-1, 1025} {
		_, err := firecrackerCheckpointConcurrency(value)
		require.Error(t, err)
	}
	for _, value := range []int{0, 1, 4, 32, 1024} {
		limit, err := firecrackerCheckpointConcurrency(value)
		require.NoError(t, err)
		require.Equal(t, max(1, value), limit)
	}
}

func TestFirecrackerRestoreMemorySlotsDefaultToSharedPool(t *testing.T) {
	service := &sandboxService{}
	release, err := service.acquireFirecrackerCheckpointMemorySlot(context.Background())
	require.NoError(t, err)
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err = service.acquireFirecrackerRestoreMemorySlot(ctx)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestFirecrackerRestoreMemorySlotsCanBeBoundedIndependently(t *testing.T) {
	service := &sandboxService{}
	service.config.ResourceConfig.FirecrackerRestoreConcurrency = 4
	releaseCheckpoint, err := service.acquireFirecrackerCheckpointMemorySlot(context.Background())
	require.NoError(t, err)
	defer releaseCheckpoint()
	var releases []func()
	for range 4 {
		release, err := service.acquireFirecrackerRestoreMemorySlot(context.Background())
		require.NoError(t, err)
		releases = append(releases, release)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err = service.acquireFirecrackerRestoreMemorySlot(ctx)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	_, err = service.acquireFirecrackerCheckpointMemorySlot(ctx)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	releases[0]()
	release, err := service.acquireFirecrackerRestoreMemorySlot(context.Background())
	require.NoError(t, err)
	release()
	for _, release := range releases[1:] {
		release()
	}
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	_, err = service.acquireFirecrackerRestoreMemorySlot(ctx)
	require.ErrorIs(t, err, context.Canceled)
}

func TestFirecrackerCheckpointMemorySlotsBoundAndReuseCapacity(t *testing.T) {
	service := &sandboxService{}
	service.config.ResourceConfig.FirecrackerCheckpointConcurrency = 4
	var releases []func()
	for range 4 {
		release, err := service.acquireFirecrackerCheckpointMemorySlot(context.Background())
		require.NoError(t, err)
		releases = append(releases, release)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := service.acquireFirecrackerCheckpointMemorySlot(ctx)
	require.ErrorIs(t, err, context.Canceled)
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err = service.acquireFirecrackerCheckpointMemorySlot(ctx)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	releases[0]()
	release, err := service.acquireFirecrackerCheckpointMemorySlot(context.Background())
	require.NoError(t, err)
	release()
	for _, release := range releases[1:] {
		release()
	}
	// A cancelled request must not consume even an immediately available slot.
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	_, err = service.acquireFirecrackerCheckpointMemorySlot(ctx)
	require.ErrorIs(t, err, context.Canceled)
	for range 4 {
		release, err := service.acquireFirecrackerCheckpointMemorySlot(context.Background())
		require.NoError(t, err)
		t.Cleanup(release)
	}
}

func TestShouldRaiseFirecrackerCheckpointMemoryLimit(t *testing.T) {
	tests := []struct {
		name      string
		live      int64
		wantRaise bool
		wantErr   bool
	}{
		{name: "normal", live: 320 << 20, wantRaise: true},
		{name: "retained expanded", live: 832 << 20},
		{name: "unexpected", live: 576 << 20, wantErr: true},
		{name: "unlimited or invalid", live: 0, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raise, err := shouldRaiseFirecrackerCheckpointMemoryLimit(
				320<<20,
				832<<20,
				test.live,
			)
			if test.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, test.wantRaise, raise)
		})
	}
}
