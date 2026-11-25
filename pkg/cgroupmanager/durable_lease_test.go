// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package cgroupmanager

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/util"
	"github.com/inclusionAI/sandboxd/pkg/store"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/stretchr/testify/require"
)

type gatedCgroupStore struct {
	store.DbStore
	entered chan []byte
	proceed chan error
}

func (s *gatedCgroupStore) StoreRaw(key string, data []byte) error {
	s.entered <- append([]byte(nil), data...)
	if err := <-s.proceed; err != nil {
		return err
	}
	return s.DbStore.StoreRaw(key, data)
}
func durableManager(t *testing.T) (*CgroupManager, *gatedCgroupStore) {
	t.Helper()
	db := &gatedCgroupStore{DbStore: store.NewStoreImp(filepath.Join(t.TempDir(), "state.db")), entered: make(chan []byte, 64), proceed: make(chan error, 64)}
	c := &CgroupManager{db: db, usingID: cmap.New[struct{}](), idleID: util.New(""), cgroups: cmap.New[struct{}](), total: 1, max: 1, stopCh: make(chan struct{}), oom: newFakeOOMWatcher()}
	c.cgroups.Set("/sandbox/one", struct{}{})
	c.idleID.Push("/sandbox/one")
	return c, db
}
func TestCgroupAllocateWaitsForDurableLease(t *testing.T) {
	c, db := durableManager(t)
	result := make(chan string, 1)
	errch := make(chan error, 1)
	go func() { id, err := c.Allocate(); result <- id; errch <- err }()
	var snap storedCgroupIDs
	require.NoError(t, json.Unmarshal(<-db.entered, &snap))
	require.Equal(t, []string{"/sandbox/one"}, snap.Items)
	select {
	case <-result:
		t.Fatal("handed out uncommitted cgroup")
	default:
	}
	db.proceed <- nil
	require.Equal(t, "/sandbox/one", <-result)
	require.NoError(t, <-errch)
	raw, err := db.LoadRaw(config.CgroupBucket)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &snap))
	require.Equal(t, []string{"/sandbox/one"}, snap.Items)
}
func TestCgroupAllocateFailureRequiresDurableRollbackBeforeReuse(t *testing.T) {
	for _, rollbackFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "rollback", true: "quarantine"}[rollbackFails], func(t *testing.T) {
			c, db := durableManager(t)
			done := make(chan error, 1)
			go func() {
				id, err := c.Allocate()
				if id != "" {
					done <- errors.New("handed out failed lease")
					return
				}
				done <- err
			}()
			<-db.entered
			db.proceed <- errors.New("injected lease commit failure")
			var snap storedCgroupIDs
			require.NoError(t, json.Unmarshal(<-db.entered, &snap))
			require.Empty(t, snap.Items)
			require.Zero(t, c.idleID.Length())
			if rollbackFails {
				db.proceed <- errors.New("injected rollback failure")
			} else {
				db.proceed <- nil
			}
			require.ErrorContains(t, <-done, "injected lease commit failure")
			require.Equal(t, rollbackFails, c.usingID.Has("/sandbox/one"))
			if rollbackFails {
				require.Zero(t, c.idleID.Length())
			} else {
				require.Equal(t, 1, c.idleID.Length())
			}
			require.Equal(t, 1, c.total)
		})
	}
}
func TestCgroupConcurrentBarriersShareOnlySuccessfulCoveredSnapshot(t *testing.T) {
	c, db := durableManager(t)
	c.usingID.Set("first", struct{}{})
	first := make(chan error, 1)
	go func() { first <- c.store() }()
	<-db.entered
	const n = 32
	results := make(chan error, n)
	c.usingID.Set("later", struct{}{})
	for range n {
		go func() { results <- c.store() }()
	}
	require.Eventually(t, func() bool { return c.storeRequest.Load() == n+1 }, time.Second, time.Millisecond)
	db.proceed <- nil
	require.NoError(t, <-first)
	var snap storedCgroupIDs
	require.NoError(t, json.Unmarshal(<-db.entered, &snap))
	require.ElementsMatch(t, []string{"first", "later"}, snap.Items)
	select {
	case err := <-results:
		t.Fatalf("acknowledged later request before commit: %v", err)
	default:
	}
	db.proceed <- nil
	for range n {
		require.NoError(t, <-results)
	}
	select {
	case <-db.entered:
		t.Fatal("covered requests redundantly committed")
	default:
	}
}
func TestCgroupFailedSnapshotDoesNotAcknowledgeWaitingBarrier(t *testing.T) {
	c, db := durableManager(t)
	first := make(chan error, 1)
	go func() { first <- c.store() }()
	<-db.entered
	next := make(chan error, 1)
	go func() { next <- c.store() }()
	require.Eventually(t, func() bool { return c.storeRequest.Load() == 2 }, time.Second, time.Millisecond)
	db.proceed <- errors.New("failed commit")
	require.ErrorContains(t, <-first, "failed commit")
	<-db.entered
	select {
	case <-next:
		t.Fatal("failed snapshot covered a waiter")
	default:
	}
	db.proceed <- nil
	require.NoError(t, <-next)
}
func TestCgroupUnrecordedPopulatedOrUnknownGroupsRemainQuarantined(t *testing.T) {
	for _, tc := range []struct {
		name      string
		populated bool
		err       error
		want      bool
	}{
		{"empty", false, nil, false}, {"populated", true, nil, true}, {"unknown", false, errors.New("unreadable"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := durableManager(t)
			ops := &fakeCgroupOps{populatedState: tc.populated, populatedErr: tc.err}
			c.ops = ops
			require.Equal(t, tc.want, c.quarantineUnrecordedGroup("/sandbox/legacy"))
			require.Equal(t, tc.want, c.usingID.Has("/sandbox/legacy"))
			require.Empty(t, ops.calls, "recovery must not kill or reset an unrecorded workload")
		})
	}
}
func TestCgroupShutdownWaitsForInFlightLease(t *testing.T) {
	c, db := durableManager(t)
	allocated := make(chan error, 1)
	go func() { _, err := c.Allocate(); allocated <- err }()
	<-db.entered
	stopped := make(chan error, 1)
	go func() { stopped <- c.ShutDown() }()
	select {
	case <-stopped:
		t.Fatal("shutdown passed an in-flight allocation")
	case <-time.After(10 * time.Millisecond):
	}
	db.proceed <- nil
	require.NoError(t, <-allocated)
	<-db.entered
	db.proceed <- nil
	require.NoError(t, <-stopped)
	id, err := c.Allocate()
	require.Error(t, err)
	require.Empty(t, id)
}
