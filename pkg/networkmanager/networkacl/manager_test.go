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
	"encoding/json"
	"errors"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReconcilePersistsCleanupIntentBeforeKernelMutation(t *testing.T) {
	stateStore := &failNthStore{MockStore: store.NewMockStore()}
	entry := persistedEntry{
		IP: "10.88.0.2", HostVeth: "acl-old", IfIndex: 1234,
	}
	manager := &Manager{
		store:       stateStore,
		entries:     map[string]persistedEntry{"old": entry},
		sourceIndex: map[string]string{entry.IP: "old"},
	}
	require.NoError(t, manager.persistLocked())

	// With nil BPF objects any attempted kernel cleanup would panic. Failing the
	// intent write must return before cleanup is reached and leave durable state
	// describing the entry as active.
	stateStore.failAt = stateStore.writes + 1
	err := manager.reconcileOrphansLocked(map[string]persistedEntry{"old": entry})
	require.ErrorContains(t, err, "cleanup intent")

	inMemory := manager.entries["old"]
	assert.False(t, inMemory.Orphaned)
	assert.Equal(t, "old", manager.sourceIndex[entry.IP])

	raw, err := stateStore.LoadRaw(stateStoreKey)
	require.NoError(t, err)
	var state persistedState
	require.NoError(t, json.Unmarshal(raw, &state))
	assert.False(t, state.Entries["old"].Orphaned)
}

func TestLoadStateDropsLegacyCleanupFields(t *testing.T) {
	stateStore := store.NewMockStore()
	legacy := []byte(`{"entries":{"old":{"ip":"10.88.0.2","host_veth":"acl-old","ifindex":42,"generation":3,"policy":{},"orphaned":true,"link_mac":"02:00:00:00:00:01","kernel_cleaned":true}}}`)
	require.NoError(t, stateStore.StoreRaw(stateStoreKey, legacy))

	manager := &Manager{store: stateStore, entries: make(map[string]persistedEntry)}
	require.NoError(t, manager.loadState())
	entry, exists := manager.entries["old"]
	require.True(t, exists)
	assert.True(t, entry.Orphaned)
	assert.Equal(t, 42, entry.IfIndex)
	assert.Equal(t, uint64(3), entry.Generation)

	require.NoError(t, manager.persistLocked())
	raw, err := stateStore.LoadRaw(stateStoreKey)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "link_mac")
	assert.NotContains(t, string(raw), "kernel_cleaned")
}

func TestCleanupRefusesIfIndexOwnedByActiveSandbox(t *testing.T) {
	orphan := persistedEntry{
		IP: "10.88.0.2", HostVeth: "acl-old", IfIndex: 42, Orphaned: true,
	}
	active := persistedEntry{
		IP: "10.88.0.3", HostVeth: "acl-new", IfIndex: 42,
	}
	manager := &Manager{entries: map[string]persistedEntry{
		"old": orphan,
		"new": active,
	}}

	err := manager.cleanupEntryLocked("old", orphan)
	require.ErrorContains(t, err, "owned by active sandbox new")
}

func TestReconcileRetriesAfterRemovalPersistFailure(t *testing.T) {
	stateStore := &failNthStore{MockStore: store.NewMockStore()}
	entry := persistedEntry{
		IP: "10.88.0.2", HostVeth: "acl-old", Orphaned: true,
	}
	manager := &Manager{
		store:       stateStore,
		entries:     map[string]persistedEntry{"old": entry},
		sourceIndex: map[string]string{entry.IP: "old"},
	}
	require.NoError(t, manager.persistLocked())

	// The cleanup intent is already durable, but removing the cleaned entry from
	// the store fails. The orphan must remain durable and in memory for an
	// idempotent retry. IfIndex zero keeps this unit test independent of kernel
	// BPF state.
	stateStore.failAt = stateStore.writes + 1
	err := manager.reconcileOrphansLocked(map[string]persistedEntry{"old": entry})
	require.ErrorContains(t, err, "removal of cleaned network ACL state")
	retained, exists := manager.entries["old"]
	require.True(t, exists)
	assert.True(t, retained.Orphaned)
	assert.NotContains(t, manager.sourceIndex, entry.IP)

	raw, err := stateStore.LoadRaw(stateStoreKey)
	require.NoError(t, err)
	var state persistedState
	require.NoError(t, json.Unmarshal(raw, &state))
	assert.True(t, state.Entries["old"].Orphaned)

	stateStore.failAt = 0
	require.NoError(t, manager.reconcileOrphansLocked(map[string]persistedEntry{"old": retained}))
	assert.NotContains(t, manager.entries, "old")
	raw, err = stateStore.LoadRaw(stateStoreKey)
	require.NoError(t, err)
	state = persistedState{}
	require.NoError(t, json.Unmarshal(raw, &state))
	assert.Empty(t, state.Entries)
}

type failNthStore struct {
	*store.MockStore
	writes int
	failAt int
}

func (s *failNthStore) StoreRaw(key string, data []byte) error {
	s.writes++
	if s.failAt != 0 && s.writes == s.failAt {
		return errors.New("injected raw store failure")
	}
	return s.MockStore.StoreRaw(key, data)
}
