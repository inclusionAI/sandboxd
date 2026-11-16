// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/store"
	"github.com/stretchr/testify/require"
)

type gatedFSStore struct {
	store.DbStore
	entered chan []byte
	proceed chan error
}

func (s *gatedFSStore) StoreRaw(key string, data []byte) error {
	s.entered <- append([]byte(nil), data...)
	if err := <-s.proceed; err != nil {
		return err
	}
	return s.DbStore.StoreRaw(key, data)
}
func batchManager(t *testing.T) (*fsManager, *gatedFSStore) {
	t.Helper()
	db := &gatedFSStore{DbStore: store.NewStoreImp(filepath.Join(t.TempDir(), "state.db")), entered: make(chan []byte, 64), proceed: make(chan error, 64)}
	return newFSManager(newFSTestImageService(), db), db
}
func prepareBatch(t *testing.T, m *fsManager, id string) *preparedFS {
	t.Helper()
	p, err := m.Prepare(context.Background(), fsTestStartRequest(id))
	require.NoError(t, err)
	return p
}
func TestFSBatchWaitsForItsOwnDurableSnapshot(t *testing.T) {
	m, db := batchManager(t)
	first := make(chan error, 1)
	p := prepareBatch(t, m, "first")
	go func() { first <- m.Commit("first", p) }()
	<-db.entered
	const n = 32
	results := make(chan error, n)
	for i := range n {
		id := fmt.Sprintf("child-%d", i)
		p := prepareBatch(t, m, id)
		go func() { results <- m.Commit(id, p) }()
	}
	require.Eventually(t, func() bool { m.queueMu.Lock(); defer m.queueMu.Unlock(); return len(m.pending) == n }, time.Second, time.Millisecond)
	m.mu.Lock()
	count := len(m.sandboxState)
	m.mu.Unlock()
	require.Zero(t, count, "uncommitted state must not be published")
	db.proceed <- nil
	require.NoError(t, <-first)
	var snapshot storedSandboxFSStates
	require.NoError(t, json.Unmarshal(<-db.entered, &snapshot))
	require.Len(t, snapshot.Items, n+1)
	select {
	case <-results:
		t.Fatal("returned before batch commit")
	default:
	}
	late := make(chan error, 1)
	last := prepareBatch(t, m, "late")
	go func() { late <- m.Commit("late", last) }()
	require.Eventually(t, func() bool { m.queueMu.Lock(); defer m.queueMu.Unlock(); return len(m.pending) == 1 }, time.Second, time.Millisecond)
	db.proceed <- nil
	for range n {
		require.NoError(t, <-results)
	}
	require.NoError(t, json.Unmarshal(<-db.entered, &snapshot))
	require.Len(t, snapshot.Items, n+2)
	select {
	case <-late:
		t.Fatal("late request borrowed preceding commit")
	default:
	}
	db.proceed <- nil
	require.NoError(t, <-late)
	raw, err := db.LoadRaw(config.SandboxFSStateBucket)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &snapshot))
	require.Len(t, snapshot.Items, n+2)
	// Recovery reconstructs every rootfs and shared mount reference from the real DB.
	db.proceed <- nil
	restored := newFSManager(newFSTestImageService(), db)
	// Restore stores one snapshot, so use the ungated backing store for recovery.
	restored.store = db.DbStore
	require.NoError(t, restored.Restore(func(string) bool { return true }))
	require.Len(t, restored.sandboxState, n+2)
	require.Equal(t, n+2, restored.oci.entries["registry.example/data:latest"].refcount)
}
func TestFSBatchFailureRetainsOwnershipAndReleaseCanRetry(t *testing.T) {
	m, db := batchManager(t)
	p := prepareBatch(t, m, "existing")
	done := make(chan error, 1)
	go func() { done <- m.Commit("existing", p) }()
	<-db.entered
	db.proceed <- nil
	require.NoError(t, <-done)
	blocked := prepareBatch(t, m, "blocker")
	go func() { done <- m.Commit("blocker", blocked) }()
	<-db.entered
	const n = 8
	results := make(chan error, n)
	pending := make([]*preparedFS, n)
	for i := range n {
		id := fmt.Sprintf("failed-%d", i)
		pending[i] = prepareBatch(t, m, id)
		p := pending[i]
		go func() { results <- m.Commit(id, p) }()
	}
	require.Eventually(t, func() bool { m.queueMu.Lock(); defer m.queueMu.Unlock(); return len(m.pending) == n }, time.Second, time.Millisecond)
	db.proceed <- nil
	require.NoError(t, <-done)
	<-db.entered
	db.proceed <- errors.New("batch failed")
	for range n {
		require.ErrorContains(t, <-results, "batch failed")
	}
	m.mu.Lock()
	count := len(m.sandboxState)
	m.mu.Unlock()
	require.Equal(t, 2, count)
	for _, p := range pending {
		p.Rollback()
	}
	go func() { done <- m.Release("existing") }()
	<-db.entered
	db.proceed <- errors.New("release failed")
	require.ErrorContains(t, <-done, "release failed")
	require.NotNil(t, m.sandboxRootfs["existing"])
	require.Len(t, m.sandboxState, 2)
	go func() { done <- m.Release("existing") }()
	<-db.entered
	db.proceed <- nil
	require.NoError(t, <-done)
	require.Len(t, m.sandboxState, 1)
}
func TestFSBatchShutdownDrainsAcknowledgments(t *testing.T) {
	m, db := batchManager(t)
	p := prepareBatch(t, m, "one")
	commit := make(chan error, 1)
	go func() { commit <- m.Commit("one", p) }()
	<-db.entered
	stopped := make(chan struct{})
	go func() { m.Shutdown(); close(stopped) }()
	select {
	case <-stopped:
		t.Fatal("shutdown passed uncommitted request")
	case <-time.After(10 * time.Millisecond):
	}
	db.proceed <- nil
	require.NoError(t, <-commit)
	<-db.entered
	db.proceed <- nil
	<-stopped
	require.ErrorContains(t, m.Commit("late", p), "shut down")
	require.ErrorContains(t, m.Release("late"), "shut down")
}
