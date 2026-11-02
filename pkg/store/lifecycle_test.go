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

package store

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"
)

func TestSharedHandleConcurrentTransactionsAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metadata.db")
	db, err := Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for worker := 0; worker < 16; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				key := fmt.Sprintf("%d/%d", worker, i)
				if err := db.StoreRaw(key, []byte(key)); err != nil {
					errs <- err
					return
				}
				raw, err := db.LoadRaw(key)
				if err != nil {
					errs <- err
					return
				}
				if string(raw) != key {
					errs <- fmt.Errorf("lost value %s", key)
					return
				}
			}
		}(worker)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	require.NoError(t, db.Close())
	require.NoError(t, db.Close())
	require.ErrorIs(t, db.StoreRaw("late", nil), bolt.ErrDatabaseNotOpen)
	reopened, err := Open(path)
	require.NoError(t, err)
	defer reopened.Close()
	for worker := 0; worker < 16; worker++ {
		for i := 0; i < 20; i++ {
			key := fmt.Sprintf("%d/%d", worker, i)
			raw, err := reopened.LoadRaw(key)
			require.NoError(t, err)
			require.Equal(t, key, string(raw))
		}
	}
}

func TestCloseDrainsActiveTransaction(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "metadata.db"))
	require.NoError(t, err)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- db.update(func(tx *bolt.Tx) error {
			close(entered)
			<-release
			b, err := tx.CreateBucketIfNotExists([]byte("test"))
			if err != nil {
				return err
			}
			return b.Put([]byte("key"), []byte("value"))
		})
	}()
	<-entered
	closed := make(chan error, 1)
	go func() { closed <- db.Close() }()
	select {
	case <-closed:
		t.Fatal("close passed active transaction")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	require.NoError(t, <-done)
	require.NoError(t, <-closed)
}

func TestFailedOpenCanRetryAndDoesNotLeakFileLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metadata.db")
	owner, err := Open(path)
	require.NoError(t, err)
	contender := NewStoreImp(path)
	require.ErrorIs(t, contender.StoreRaw("key", nil), bolt.ErrTimeout)
	require.NoError(t, owner.Close())
	require.NoError(t, contender.StoreRaw("key", []byte("value")))
	require.NoError(t, contender.Close())
	reopened, err := Open(path)
	require.NoError(t, err)
	require.NoError(t, reopened.Close())
}
