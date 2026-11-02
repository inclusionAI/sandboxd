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
	"errors"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/store"
	"github.com/stretchr/testify/require"
)

func TestSlowRemovalDoesNotBlockUnrelatedRegistration(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	old := persistedEntry{IP: "10.88.0.2", HostVeth: "old-tap", IfIndex: 1234}
	m := &Manager{store: store.NewMockStore(), entries: map[string]persistedEntry{"old": old}, sourceIndex: map[string]string{old.IP: "old"}, iptables: &iptablesBackend{client: newMemoryIPTables(), ipv6Client: newMemoryIPTables(), deleteConntrackForIP: func(net.IP) error { close(entered); <-release; return nil }}}
	removed := make(chan error, 1)
	go func() { removed <- m.Remove("old") }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("cleanup did not enter")
	}
	registered := make(chan error, 1)
	go func() {
		registered <- m.Register(Binding{SandboxID: "new", IP: net.ParseIP("10.88.0.3"), HostVeth: "lo"}, Policy{})
	}()
	select {
	case err := <-registered:
		require.NoError(t, err)
	case <-time.After(time.Second):
		close(release)
		<-removed
		<-registered
		t.Fatal("unrelated registration waited for kernel cleanup")
	}
	close(release)
	require.NoError(t, <-removed)
	require.Contains(t, m.entries, "new")
}

func TestRemovalReservesEndpointAndJoinsConcurrentDelete(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	old := persistedEntry{IP: "10.88.0.2", HostVeth: "lo", IfIndex: 1, KernelPolicyAbsent: true}
	var calls atomic.Int32
	m := &Manager{store: store.NewMockStore(), entries: map[string]persistedEntry{"old": old}, sourceIndex: map[string]string{old.IP: "old"}, iptables: &iptablesBackend{deleteConntrackForIP: func(net.IP) error { calls.Add(1); close(entered); <-release; return nil }}}
	done := make(chan error, 2)
	go func() { done <- m.Remove("old") }()
	<-entered
	// The durable orphan is a reservation, not permission to reuse an IP/link.
	err := m.Register(Binding{SandboxID: "replacement", IP: net.ParseIP(old.IP), HostVeth: "lo"}, Policy{})
	require.ErrorIs(t, err, errord.ErrUnavailable)
	require.ErrorIs(t, m.SetPolicy("old", Policy{}), errord.ErrNotFound)
	go func() { done <- m.Remove("old") }()
	close(release)
	require.NoError(t, <-done)
	require.NoError(t, <-done)
	require.Equal(t, int32(1), calls.Load())
	require.NoError(t, m.Register(Binding{SandboxID: "replacement", IP: net.ParseIP(old.IP), HostVeth: "lo"}, Policy{}))
}

func TestDifferentEndpointsCleanConcurrently(t *testing.T) {
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	entries := map[string]persistedEntry{"one": {IP: "10.88.0.2", HostVeth: "tap1", IfIndex: 11, KernelPolicyAbsent: true}, "two": {IP: "10.88.0.3", HostVeth: "tap2", IfIndex: 12, KernelPolicyAbsent: true}}
	m := &Manager{store: store.NewMockStore(), entries: entries, sourceIndex: map[string]string{"10.88.0.2": "one", "10.88.0.3": "two"}, iptables: &iptablesBackend{deleteConntrackForIP: func(net.IP) error { entered <- struct{}{}; <-release; return nil }}}
	done := make(chan error, 2)
	go func() { done <- m.Remove("one") }()
	go func() { done <- m.Remove("two") }()
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-time.After(time.Second):
			close(release)
			t.Fatal("independent cleanups serialized")
		}
	}
	close(release)
	require.NoError(t, <-done)
	require.NoError(t, <-done)
	require.Empty(t, m.entries)
}

func TestFailedCleanupSurvivesStoreRestartAndReconciles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metadata.db")
	db, err := store.Open(path)
	require.NoError(t, err)
	entry := persistedEntry{IP: "10.88.0.2", HostVeth: "old", IfIndex: 12, KernelPolicyAbsent: true}
	m := &Manager{store: db, entries: map[string]persistedEntry{"old": entry}, sourceIndex: map[string]string{entry.IP: "old"}, iptables: &iptablesBackend{deleteConntrackForIP: func(net.IP) error { return errors.New("injected cleanup error") }}}
	require.NoError(t, m.persistLocked())
	require.ErrorContains(t, m.Remove("old"), "injected cleanup error")
	require.True(t, m.entries["old"].Orphaned)
	require.NoError(t, db.Close())
	recovered, err := store.Open(path)
	require.NoError(t, err)
	defer recovered.Close()
	m2 := &Manager{store: recovered, entries: map[string]persistedEntry{}, sourceIndex: map[string]string{}, iptables: &iptablesBackend{deleteConntrackForIP: func(net.IP) error { return nil }}}
	require.NoError(t, m2.loadState())
	require.True(t, m2.entries["old"].Orphaned)
	require.NoError(t, m2.Restore(map[string]Binding{}))
	require.Empty(t, m2.entries)
	records, err := recovered.LoadRecords(entryStoreKey)
	require.NoError(t, err)
	require.Empty(t, records)
}

func TestRemovalFinalWriteFailureKeepsOrphanAndUnrelatedEntry(t *testing.T) {
	db := &failNthStore{MockStore: store.NewMockStore()}
	entry := persistedEntry{IP: "10.88.0.2", HostVeth: "old", IfIndex: 12, KernelPolicyAbsent: true}
	m := &Manager{store: db, entries: map[string]persistedEntry{"old": entry}, sourceIndex: map[string]string{entry.IP: "old"}, iptables: &iptablesBackend{deleteConntrackForIP: func(net.IP) error { return nil }}}
	require.NoError(t, m.persistLocked())
	db.failAt = db.writes + 2
	require.ErrorContains(t, m.Remove("old"), "persist removal")
	require.True(t, m.entries["old"].Orphaned)
	require.NoError(t, m.Register(Binding{SandboxID: "peer", IP: net.ParseIP("10.88.0.3"), HostVeth: "lo"}, Policy{}))
	require.NoError(t, m.Remove("old"))
	require.Contains(t, m.entries, "peer")
	require.NotContains(t, m.entries, "old")
}

func TestCloseWaitsForInflightCleanup(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	old := persistedEntry{IP: "10.88.0.2", HostVeth: "old", IfIndex: 11, KernelPolicyAbsent: true}
	peer := persistedEntry{IP: "10.88.0.3", HostVeth: "peer", IfIndex: 12, KernelPolicyAbsent: true}
	m := &Manager{store: store.NewMockStore(), entries: map[string]persistedEntry{"old": old, "peer": peer}, sourceIndex: map[string]string{}, iptables: &iptablesBackend{deleteConntrackForIP: func(net.IP) error { close(entered); <-release; return nil }}}
	removed := make(chan error, 1)
	go func() { removed <- m.Remove("old") }()
	<-entered
	closed := make(chan error, 1)
	go func() { closed <- m.Close() }()
	select {
	case <-closed:
		t.Fatal("close did not drain cleanup")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	require.NoError(t, <-removed)
	require.NoError(t, <-closed)
	require.ErrorIs(t, m.Remove("peer"), errord.ErrUnavailable)
	require.ErrorIs(t, m.Restore(nil), errord.ErrUnavailable)
}

func TestFailedPolicyAttemptRevokesNeverInstalledProof(t *testing.T) {
	entry := persistedEntry{IP: "10.88.0.2", HostVeth: "tap", IfIndex: 12, KernelPolicyAbsent: true}
	client := newMemoryIPTables()
	client.failOne = func(operation, chain string, rules []string) bool { return operation == "append" }
	m := &Manager{store: store.NewMockStore(), entries: map[string]persistedEntry{"old": entry}, sourceIndex: map[string]string{}, iptables: &iptablesBackend{client: client, ipv6Client: newMemoryIPTables(), ipset: &recordingIPSet{}, deleteConntrackForIP: func(net.IP) error { return nil }}}
	err := m.SetPolicy("old", Policy{Traffic: &TrafficPolicy{DefaultAction: actionDeny}})
	require.Error(t, err)
	require.False(t, m.entries["old"].KernelPolicyAbsent)
}

func TestDuplicateRemovalReturnsOriginalFailure(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	injected := errors.New("cleanup failed")
	var calls atomic.Int32
	old := persistedEntry{IP: "10.88.0.2", HostVeth: "old", IfIndex: 11, KernelPolicyAbsent: true}
	m := &Manager{store: store.NewMockStore(), entries: map[string]persistedEntry{"old": old}, sourceIndex: map[string]string{}, iptables: &iptablesBackend{deleteConntrackForIP: func(net.IP) error {
		if calls.Add(1) == 1 {
			close(entered)
		}
		<-release
		return injected
	}}}
	done := make(chan error, 2)
	go func() { done <- m.Remove("old") }()
	<-entered
	go func() { done <- m.Remove("old") }()
	// The first operation is deliberately blocked while its duplicate joins.
	time.Sleep(20 * time.Millisecond)
	close(release)
	require.ErrorIs(t, <-done, injected)
	require.ErrorIs(t, <-done, injected)
	require.Equal(t, int32(1), calls.Load(), "duplicate must join, not rerun cleanup on a later incarnation")
}

func TestRemoveIntentFailureLeavesEndpointActive(t *testing.T) {
	db := &failNthStore{MockStore: store.NewMockStore()}
	old := persistedEntry{IP: "10.88.0.2", HostVeth: "old", IfIndex: 11, KernelPolicyAbsent: true}
	calls := 0
	m := &Manager{store: db, entries: map[string]persistedEntry{"old": old}, sourceIndex: map[string]string{old.IP: "old"}, iptables: &iptablesBackend{deleteConntrackForIP: func(net.IP) error { calls++; return nil }}}
	require.NoError(t, m.persistLocked())
	db.failAt = db.writes + 1
	require.ErrorContains(t, m.Remove("old"), "cleanup intent")
	require.Zero(t, calls)
	require.False(t, m.entries["old"].Orphaned)
	require.Equal(t, "old", m.sourceIndex[old.IP])
}
