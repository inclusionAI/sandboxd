package keyedlock

import (
	"context"
	"sync"
)

// Locks serializes one image's acquire/release without holding a
// global lock during registry or filesystem I/O. Waiters retain their own
// cancellation; entries cannot be evicted while any waiter still references them.
type Locks struct {
	mu      sync.Mutex
	entries map[string]*operationLock
}

type operationLock struct {
	gate  chan struct{}
	users int
}

// Acquire waits for the key or caller cancellation. The returned release must
// be called exactly once; the zero value is ready for use.
func (l *Locks) Acquire(ctx context.Context, key string) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	l.mu.Lock()
	if l.entries == nil {
		l.entries = make(map[string]*operationLock)
	}
	entry := l.entries[key]
	if entry == nil {
		entry = &operationLock{gate: make(chan struct{}, 1)}
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
