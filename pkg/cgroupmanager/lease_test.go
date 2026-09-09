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

package cgroupmanager

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/util"
	"github.com/inclusionAI/sandboxd/pkg/store"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/stretchr/testify/require"
)

type leaseFaultStore struct {
	store.DbStore
	writeErr error
}

func (s *leaseFaultStore) StoreRaw(key string, data []byte) error {
	if s.writeErr != nil {
		return s.writeErr
	}
	return s.DbStore.StoreRaw(key, data)
}

func TestCgroupAllocationPersistsBeforeHandoff(t *testing.T) {
	for _, cached := range []bool{true, false} {
		name := "created"
		if cached {
			name = "cached"
		}
		t.Run(name, func(t *testing.T) {
			const id = "/sandbox/test"
			db := &leaseFaultStore{DbStore: store.NewMockStore()}
			c := &CgroupManager{db: db, usingID: cmap.New[struct{}](), idleID: util.New(""), max: 1, stopCh: make(chan struct{}), createReqs: make(chan *createRequest)}
			if cached {
				c.idleID.Push(id)
			} else {
				go func() { req := <-c.createReqs; req.result <- createResult{id: id} }()
			}
			allocated, err := c.Allocate()
			require.NoError(t, err)
			require.Equal(t, id, allocated)
			data, err := db.LoadRaw(config.CgroupBucket)
			require.NoError(t, err)
			var persisted storedCgroupIDs
			require.NoError(t, json.Unmarshal(data, &persisted))
			require.Equal(t, []string{id}, persisted.Items)
		})
	}
}

func TestCgroupAllocationFailsBeforeHandoffOnStoreError(t *testing.T) {
	const id = "/sandbox/test"
	db := &leaseFaultStore{DbStore: store.NewMockStore(), writeErr: errors.New("disk unavailable")}
	c := &CgroupManager{db: db, usingID: cmap.New[struct{}](), idleID: util.New("")}
	c.idleID.Push(id)
	allocated, err := c.Allocate()
	require.ErrorContains(t, err, "disk unavailable")
	require.Empty(t, allocated)
	require.False(t, c.usingID.Has(id))
	require.Equal(t, []string{id}, c.idleID.List())
	db.writeErr = nil
	allocated, err = c.Allocate()
	require.NoError(t, err)
	require.Equal(t, id, allocated)
}
