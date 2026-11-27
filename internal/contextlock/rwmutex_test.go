// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package contextlock

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func waitForWriter(t *testing.T, mu *RWMutex) {
	t.Helper()
	require.Eventually(t, func() bool {
		if mu.TryRLock() {
			mu.RUnlock()
			return false
		}
		return true
	}, time.Second, time.Millisecond)
}

func TestWriterPrecedesLaterReaders(t *testing.T) {
	var mu RWMutex
	mu.RLock()
	var first sync.Once
	releaseFirst := func() { first.Do(mu.RUnlock) }
	t.Cleanup(releaseFirst)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	writer := make(chan error, 1)
	release := make(chan struct{})
	var once sync.Once
	releaseWriter := func() { once.Do(func() { close(release) }) }
	t.Cleanup(releaseWriter)
	go func() {
		err := mu.LockContext(ctx)
		writer <- err
		if err == nil {
			<-release
			mu.Unlock()
		}
	}()
	waitForWriter(t, &mu)
	reader := make(chan struct{})
	go func() { mu.RLock(); mu.RUnlock(); close(reader) }()
	releaseFirst()
	require.NoError(t, <-writer)
	select {
	case <-reader:
		t.Fatal("later reader passed the queued writer")
	default:
	}
	releaseWriter()
	select {
	case <-reader:
	case <-time.After(time.Second):
		t.Fatal("reader did not continue after the writer")
	}
}

func TestCancelledWriterLetsReadersProceed(t *testing.T) {
	var mu RWMutex
	mu.RLock()
	defer mu.RUnlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	writer := make(chan error, 1)
	go func() { writer <- mu.LockContext(ctx) }()
	waitForWriter(t, &mu)
	reader := make(chan struct{})
	go func() { mu.RLock(); mu.RUnlock(); close(reader) }()
	cancel()
	require.ErrorIs(t, <-writer, context.Canceled)
	select {
	case <-reader:
	case <-time.After(time.Second):
		t.Fatal("cancelled writer still blocked a reader")
	}
}
