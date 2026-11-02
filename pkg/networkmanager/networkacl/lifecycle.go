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

package networkacl

import (
	"fmt"

	"github.com/inclusionAI/sandboxd/pkg/errord"
)

type removal struct {
	done chan struct{}
	err  error
}

// Remove joins an in-flight removal before waiting on the endpoint operation.
// Reservations survive kernel or persistence failure and are released only after
// durable deletion, so stale work can never affect a replacement endpoint.
func (m *Manager) Remove(sandboxID string) error {
	m.lifecycleMu.RLock()
	defer m.lifecycleMu.RUnlock()
	return m.remove(sandboxID)
}

func (m *Manager) remove(id string) (result error) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return errord.ErrUnavailable
	}
	if pending := m.removals[id]; pending != nil {
		m.mu.Unlock()
		<-pending.done
		return pending.err
	}
	if _, ok := m.entries[id]; !ok {
		m.mu.Unlock()
		return nil
	}
	if m.removals == nil {
		m.removals = make(map[string]*removal)
	}
	pending := &removal{done: make(chan struct{})}
	m.removals[id] = pending
	m.mu.Unlock()
	defer func() { m.mu.Lock(); pending.err = result; delete(m.removals, id); close(pending.done); m.mu.Unlock() }()
	op, entry, err := m.acquireOperation(id, true)
	if err != nil {
		if err == errord.ErrNotFound {
			return nil
		}
		return err
	}
	defer m.releaseOperation(id, op)
	return m.removeEntry(id, entry)
}

// Caller owns this endpoint's operation lock and the lifecycle read barrier.
func (m *Manager) removeEntry(id string, entry persistedEntry) error {
	m.mu.RLock()
	err := m.checkCleanupOwnershipLocked(id, entry)
	m.mu.RUnlock()
	if err != nil {
		return err
	}
	if !entry.Orphaned {
		entry.Orphaned = true
		entry.Revision++
		if err := m.persistEntry(id, &entry); err != nil {
			return fmt.Errorf("persist network ACL cleanup intent: %w", err)
		}
		m.mu.Lock()
		m.entries[id] = entry
		if m.sourceIndex[entry.IP] == id {
			delete(m.sourceIndex, entry.IP)
		}
		m.mu.Unlock()
	}
	if err := m.cleanupKernel(entry); err != nil {
		return fmt.Errorf("clean network ACL for %s: %w", id, err)
	}
	if err := m.persistEntry(id, nil); err != nil {
		return fmt.Errorf("persist removal of cleaned network ACL state: %w", err)
	}
	m.mu.Lock()
	delete(m.entries, id)
	m.mu.Unlock()
	return nil
}

func (m *Manager) checkCleanupOwnershipLocked(sandboxID string, entry persistedEntry) error {
	for otherID, other := range m.entries {
		if otherID == sandboxID {
			continue
		}
		conflicts := other.IfIndex == entry.IfIndex || other.IP == entry.IP || other.HostVeth == entry.HostVeth
		if conflicts && (!other.Orphaned || m.removals[otherID] != nil) {
			return fmt.Errorf("refusing cleanup of ifindex %d owned by active sandbox %s", entry.IfIndex, otherID)
		}
	}
	return nil
}
