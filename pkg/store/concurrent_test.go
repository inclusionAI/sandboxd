// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRealStoreConcurrentConsumersRetainEveryCommittedValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db := NewStoreImp(path)
	const n = 64
	errors := make(chan error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			key := fmt.Sprintf("owner-%d", i)
			data := []byte(key)
			if err := db.StoreRaw(key, data); err != nil {
				errors <- err
				return
			}
			got, err := db.LoadRaw(key)
			if err != nil {
				errors <- err
				return
			}
			if string(got) != key {
				errors <- fmt.Errorf("value changed for %s", key)
			}
		}()
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		require.NoError(t, err)
	}
	recovered := NewStoreImp(path)
	for i := range n {
		key := fmt.Sprintf("owner-%d", i)
		got, err := recovered.LoadRaw(key)
		require.NoError(t, err)
		require.Equal(t, key, string(got))
	}
	// Failed encoding releases both the process mutex and the OS file lock.
	require.Error(t, db.Store("invalid", new(string)))
	require.NoError(t, db.StoreRaw("after-failure", []byte("committed")))
	got, err := recovered.LoadRaw("after-failure")
	require.NoError(t, err)
	require.Equal(t, "committed", string(got))
}
