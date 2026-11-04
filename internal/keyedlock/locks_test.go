// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package keyedlock

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCancellationDoesNotEvictAnActiveKeyOrLeakCompletedKeys(t *testing.T) {
	var locks Locks
	release, err := locks.Acquire(context.Background(), "one")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := locks.Acquire(ctx, "one"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiter did not cancel: %v", err)
	}
	independent, err := locks.Acquire(context.Background(), "two")
	if err != nil {
		t.Fatal(err)
	}
	independent()
	acquired := make(chan func(), 1)
	go func() {
		unlock, err := locks.Acquire(context.Background(), "one")
		if err != nil {
			t.Error(err)
			return
		}
		acquired <- unlock
	}()
	select {
	case unlock := <-acquired:
		unlock()
		t.Fatal("canceled waiter evicted an active key")
	case <-time.After(20 * time.Millisecond):
	}
	release()
	select {
	case unlock := <-acquired:
		unlock()
	case <-time.After(time.Second):
		t.Fatal("live waiter lost its gate")
	}
	locks.mu.Lock()
	defer locks.mu.Unlock()
	if len(locks.entries) != 0 {
		t.Fatal("completed operation locks leaked")
	}
}
