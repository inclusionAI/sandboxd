// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package networkacl

import (
	"net"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/store"
	"github.com/stretchr/testify/require"
)

func TestOrphanCleanupClaimsOnlyCapturedIncarnation(t *testing.T) {
	captured := persistedEntry{Incarnation: "selected-orphan", Revision: 1, IP: "10.88.0.2", HostVeth: "old-tap", IfIndex: 12, Orphaned: true, KernelPolicyAbsent: true}
	for _, tc := range []struct {
		name        string
		incarnation string
		orphan      bool
	}{
		{"active replacement", "replacement", false},
		{"orphan replacement", "replacement", true},
		{"reactivated owner", captured.Incarnation, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			current := captured
			current.Incarnation, current.Orphaned = tc.incarnation, tc.orphan
			db := &failNthStore{MockStore: store.NewMockStore()}
			cleaned := 0
			m := &Manager{store: db, entries: map[string]persistedEntry{"same-id": current}, sourceIndex: map[string]string{}, iptables: &iptablesBackend{
				deleteConntrackForIP: func(net.IP) error { cleaned++; return nil },
			}}
			require.NoError(t, m.persistLocked())
			writes := db.writes
			m.lifecycleMu.RLock()
			err := m.remove("same-id", &captured)
			m.lifecycleMu.RUnlock()
			require.NoError(t, err)
			require.Zero(t, cleaned, "a stale orphan selection must not touch the replacement's kernel state")
			require.Equal(t, writes, db.writes, "a stale orphan selection must not persist cleanup intent or deletion")
			require.Equal(t, current, m.entries["same-id"])
			require.Empty(t, m.removals)
			loaded := &Manager{store: db, entries: map[string]persistedEntry{}}
			require.NoError(t, loaded.loadState())
			require.Equal(t, current, loaded.entries["same-id"])
		})
	}
}

func TestOrphanCleanupRemovesMatchingCapturedOwner(t *testing.T) {
	entry := persistedEntry{Incarnation: "selected-orphan", Revision: 1, IP: "10.88.0.2", HostVeth: "old-tap", IfIndex: 12, Orphaned: true, KernelPolicyAbsent: true}
	cleaned := 0
	m := &Manager{store: store.NewMockStore(), entries: map[string]persistedEntry{"same-id": entry}, sourceIndex: map[string]string{}, iptables: &iptablesBackend{
		deleteConntrackForIP: func(net.IP) error { cleaned++; return nil },
	}}
	m.lifecycleMu.RLock()
	err := m.remove("same-id", &entry)
	m.lifecycleMu.RUnlock()
	require.NoError(t, err)
	require.Equal(t, 1, cleaned)
	require.Empty(t, m.entries)
	require.Empty(t, m.removals)
	loaded := &Manager{store: m.store, entries: map[string]persistedEntry{}}
	require.NoError(t, loaded.loadState())
	require.Empty(t, loaded.entries)
}
