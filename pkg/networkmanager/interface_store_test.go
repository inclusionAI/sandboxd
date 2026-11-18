// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package networkmanager

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/store"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/stretchr/testify/require"
)

type gatedLeaseStore struct {
	store.DbStore
	entered chan []byte
	proceed chan error
}

func (s *gatedLeaseStore) StoreRaw(key string, data []byte) error {
	s.entered <- append([]byte(nil), data...)
	if err := <-s.proceed; err != nil {
		return err
	}
	return s.DbStore.StoreRaw(key, data)
}

func TestLeaseStoreDoesNotAcknowledgeLaterMutationWithEarlierCommit(t *testing.T) {
	db := &gatedLeaseStore{DbStore: store.NewStoreImp(filepath.Join(t.TempDir(), "leases.db")),
		entered: make(chan []byte, 2), proceed: make(chan error, 2)}
	m := &InterfaceManager{db: db, usingInterfaces: cmap.New[struct{}]()}
	m.usingInterfaces.Set("first", struct{}{})
	first := make(chan error, 1)
	go func() { first <- m.store() }()
	var snapshot storedInterfaceIDs
	require.NoError(t, json.Unmarshal(<-db.entered, &snapshot))
	require.Equal(t, []string{"first"}, snapshot.Items)
	m.usingInterfaces.Set("later", struct{}{})
	later := make(chan error, 1)
	go func() { later <- m.store() }()
	require.Eventually(t, func() bool { return m.storeRequest.Load() == 2 }, time.Second, time.Millisecond)
	db.proceed <- nil
	require.NoError(t, <-first)
	require.NoError(t, json.Unmarshal(<-db.entered, &snapshot))
	require.ElementsMatch(t, []string{"first", "later"}, snapshot.Items)
	select {
	case err := <-later:
		t.Fatalf("later mutation acknowledged before its commit: %v", err)
	default:
	}
	db.proceed <- nil
	require.NoError(t, <-later)
	stored, err := db.LoadRaw(config.BridgeIpBucket)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(stored, &snapshot))
	require.ElementsMatch(t, []string{"first", "later"}, snapshot.Items)
}

func TestLeaseStoreCoalescesConcurrentDurabilityBarriers(t *testing.T) {
	db := &gatedLeaseStore{DbStore: store.NewStoreImp(filepath.Join(t.TempDir(), "leases.db")),
		entered: make(chan []byte, 2), proceed: make(chan error, 2)}
	m := &InterfaceManager{db: db, usingInterfaces: cmap.New[struct{}]()}
	m.usingInterfaces.Set("first", struct{}{})
	first := make(chan error, 1)
	go func() { first <- m.store() }()
	<-db.entered
	const followers = 32
	var wg sync.WaitGroup
	errors := make(chan error, followers)
	for i := 0; i < followers; i++ {
		wg.Go(func() { errors <- m.store() })
	}
	require.Eventually(t, func() bool { return m.storeRequest.Load() == followers+1 }, time.Second, time.Millisecond)
	db.proceed <- nil
	require.NoError(t, <-first)
	<-db.entered
	select {
	case err := <-errors:
		t.Fatalf("uncommitted barrier returned: %v", err)
	default:
	}
	db.proceed <- nil
	wg.Wait()
	for i := 0; i < followers; i++ {
		require.NoError(t, <-errors)
	}
	select {
	case <-db.entered:
		t.Fatal("covered barriers performed a redundant commit")
	default:
	}
}

func TestLeaseStoreFailureDoesNotCoverWaitingBarrier(t *testing.T) {
	db := &gatedLeaseStore{DbStore: store.NewStoreImp(filepath.Join(t.TempDir(), "leases.db")),
		entered: make(chan []byte, 2), proceed: make(chan error, 2)}
	m := &InterfaceManager{db: db, usingInterfaces: cmap.New[struct{}]()}
	m.usingInterfaces.Set("retained", struct{}{})
	first := make(chan error, 1)
	go func() { first <- m.store() }()
	<-db.entered
	later := make(chan error, 1)
	go func() { later <- m.store() }()
	require.Eventually(t, func() bool { return m.storeRequest.Load() == 2 }, time.Second, time.Millisecond)
	db.proceed <- errors.New("injected commit failure")
	require.ErrorContains(t, <-first, "injected commit failure")
	<-db.entered
	select {
	case err := <-later:
		t.Fatalf("failed commit covered a waiting barrier: %v", err)
	default:
	}
	db.proceed <- nil
	require.NoError(t, <-later)
}
