// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package store

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/errord"
	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"
)

func TestRecordMigrationAndConcurrentDurability(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := Open(path)
	require.NoError(t, err)
	require.NoError(t, db.StoreRaw("legacy", []byte("old")))
	require.NoError(t, db.InitRecords("entries", "legacy", map[string][]byte{"initial": []byte("v1")}))
	marker, err := db.LoadRaw("legacy")
	require.NoError(t, err)
	require.Equal(t, "migrated-to-records:entries", string(marker))
	var wg sync.WaitGroup
	failures := make(chan error, 200)
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			failures <- db.StoreRecords("entries", map[string][]byte{fmt.Sprint(i): []byte("committed")})
		}(i)
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		require.NoError(t, err)
	}
	require.NoError(t, db.Close())
	db, err = Open(path)
	require.NoError(t, err)
	defer db.Close()
	records, err := db.LoadRecords("entries")
	require.NoError(t, err)
	require.Len(t, records, 201)
	for key := range records {
		records[key] = nil
	}
	require.NoError(t, db.StoreRecords("entries", records))
	// Empty migrated state must not resurrect a legacy snapshot on restart.
	require.NoError(t, db.InitRecords("entries", "legacy", map[string][]byte{"initial": []byte("stale")}))
	records, err = db.LoadRecords("entries")
	require.NoError(t, err)
	require.Empty(t, records)
	require.NoError(t, db.Close())
	require.Error(t, db.StoreRecords("entries", map[string][]byte{"late": []byte("no")}))
}

func TestMigrationFailurePreservesLegacy(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "state.db"))
	require.NoError(t, err)
	defer db.Close()
	require.NoError(t, db.StoreRaw("legacy", []byte("original")))
	require.Error(t, db.InitRecords("entries", "legacy", map[string][]byte{"": []byte("invalid key")}))
	raw, err := db.LoadRaw("legacy")
	require.NoError(t, err)
	require.Equal(t, "original", string(raw))
	_, err = db.LoadRecords("entries")
	require.ErrorIs(t, err, errord.ErrNotFound)
}

func TestCloseSettlesSaturatedRecordWriters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := Open(path)
	require.NoError(t, err)
	require.NoError(t, db.InitRecords("entries", "legacy", nil))
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan error, 256)
	for i := 0; i < 256; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results <- db.StoreRecords("entries", map[string][]byte{fmt.Sprint(i): []byte("committed")})
		}(i)
	}
	close(start)
	require.NoError(t, db.Close())
	wg.Wait()
	close(results)
	succeeded := 0
	for err := range results {
		if err == nil {
			succeeded++
		} else {
			require.ErrorIs(t, err, bolt.ErrDatabaseNotOpen)
		}
	}
	reopened, err := Open(path)
	require.NoError(t, err)
	defer reopened.Close()
	records, err := reopened.LoadRecords("entries")
	require.NoError(t, err)
	require.Len(t, records, succeeded)
}
