// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package networkacl

import (
	"sync"

	"github.com/inclusionAI/sandboxd/pkg/errord"
)

// Pointer identity fences waiters from a later registration of the same ID.
// users includes waiters, so a reserved endpoint cannot be reaped underneath an
// operation. The global index lock is never held while acquiring an active op.
type entryOperation struct {
	mu    sync.Mutex
	users int
}

func (m *Manager) operationLocked(id string) *entryOperation {
	if m.operations == nil {
		m.operations = make(map[string]*entryOperation)
	}
	op := m.operations[id]
	if op == nil {
		op = &entryOperation{}
		m.operations[id] = op
	}
	return op
}

func (m *Manager) acquireOperation(id string, orphan bool) (*entryOperation, persistedEntry, error) {
	m.mu.Lock()
	entry, ok := m.entries[id]
	if m.closed {
		m.mu.Unlock()
		return nil, entry, errord.ErrUnavailable
	}
	if !ok || (!orphan && (entry.Orphaned || m.removals[id] != nil)) {
		m.mu.Unlock()
		return nil, entry, errord.ErrNotFound
	}
	op := m.operationLocked(id)
	op.users++
	m.mu.Unlock()
	op.mu.Lock()
	m.mu.RLock()
	current, ok := m.entries[id]
	valid := ok && m.operations[id] == op && current.Incarnation == entry.Incarnation && (orphan || (!current.Orphaned && m.removals[id] == nil))
	m.mu.RUnlock()
	if !valid {
		m.releaseOperation(id, op)
		return nil, current, errord.ErrNotFound
	}
	return op, current, nil
}

func (m *Manager) releaseOperation(id string, op *entryOperation) {
	m.mu.Lock()
	op.users--
	if _, ok := m.entries[id]; !ok && m.operations[id] == op && op.users == 0 {
		delete(m.operations, id)
	}
	// Release while holding the index lock so a new registration cannot capture
	// the old guard between observing zero users and unlocking it.
	op.mu.Unlock()
	m.mu.Unlock()
}

func (m *Manager) publishEntry(id string, entry persistedEntry) {
	m.mu.Lock()
	m.entries[id] = entry
	m.mu.Unlock()
}
