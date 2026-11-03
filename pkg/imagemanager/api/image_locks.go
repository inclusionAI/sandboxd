package api

import (
	"context"
	"sync"
)

// imageOperationLocks serializes one image's acquire/release without holding a
// global lock during registry or filesystem I/O. Waiters retain their own
// cancellation; entries cannot be evicted while any waiter still references them.
type imageOperationLocks struct {
	mu      sync.Mutex
	entries map[string]*imageOperationLock
}

type imageOperationLock struct {
	gate  chan struct{}
	users int
}

func (l *imageOperationLocks) lock(ctx context.Context, key string) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	l.mu.Lock()
	if l.entries == nil {
		l.entries = make(map[string]*imageOperationLock)
	}
	entry := l.entries[key]
	if entry == nil {
		entry = &imageOperationLock{gate: make(chan struct{}, 1)}
		l.entries[key] = entry
	}
	entry.users++
	l.mu.Unlock()
	release := func() {
		l.mu.Lock()
		entry.users--
		if entry.users == 0 {
			delete(l.entries, key)
		}
		l.mu.Unlock()
	}
	select {
	case entry.gate <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-entry.gate
			release()
			return nil, err
		}
		return func() { <-entry.gate; release() }, nil
	case <-ctx.Done():
		release()
		return nil, ctx.Err()
	}
}
