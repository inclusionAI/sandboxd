// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

// Package contextlock provides locks with cancellable acquisition.
package contextlock

import (
	"context"
	"math"
	"sync"

	"golang.org/x/sync/semaphore"
)

// RWMutex is a reader/writer lock whose exclusive wait can be cancelled.
// A queued writer prevents later readers from passing it. Cancellation removes
// that waiter and admits the next requests. The zero value is ready for use;
// like sync.RWMutex, it must not be copied after use or acquired recursively.
type RWMutex struct {
	once sync.Once
	sem  *semaphore.Weighted
}

func (m *RWMutex) semaphore() *semaphore.Weighted {
	m.once.Do(func() { m.sem = semaphore.NewWeighted(math.MaxInt64) })
	return m.sem
}

func (m *RWMutex) RLock() {
	_ = m.semaphore().Acquire(context.Background(), 1)
}

func (m *RWMutex) TryRLock() bool {
	return m.semaphore().TryAcquire(1)
}

func (m *RWMutex) RUnlock() {
	m.semaphore().Release(1)
}

func (m *RWMutex) Lock() {
	_ = m.LockContext(context.Background())
}

func (m *RWMutex) LockContext(ctx context.Context) error {
	return m.semaphore().Acquire(ctx, math.MaxInt64)
}

func (m *RWMutex) Unlock() {
	m.semaphore().Release(math.MaxInt64)
}
