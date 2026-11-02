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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/containerd/typeurl/v2"
	"github.com/gogo/protobuf/types"
	"github.com/golang/protobuf/proto"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/types/known/anypb"
)

type DbStore interface {
	Store(key string, data interface{}) error
	Load(key string) (*types.Any, error)
	StoreRaw(key string, data []byte) error
	LoadRaw(key string) ([]byte, error)
}

var _ DbStore = &BboltStoreImp{}

// BboltStoreImp owns one database handle. Close drains active transactions and
// prevents subsequent operations from reopening the file.
type BboltStoreImp struct {
	path       string
	mu         sync.RWMutex
	db         *bolt.DB
	closed     bool
	batchOnce  sync.Once
	batchSlots chan struct{}
}

// NewStoreImp retains lazy construction for callers that handle I/O errors on
// their first operation. Server construction uses Open to fail before startup.
func NewStoreImp(path string) *BboltStoreImp { return &BboltStoreImp{path: path} }

func Open(path string) (*BboltStoreImp, error) {
	s := NewStoreImp(path)
	if err := s.withDB(func(*bolt.DB) error { return nil }); err != nil {
		return nil, err
	}
	return s, nil
}

func (f *BboltStoreImp) withDB(fn func(*bolt.DB) error) error {
	for {
		f.mu.RLock()
		if f.closed {
			f.mu.RUnlock()
			return bolt.ErrDatabaseNotOpen
		}
		if f.db != nil {
			defer f.mu.RUnlock()
			return fn(f.db)
		}
		f.mu.RUnlock()
		f.mu.Lock()
		if f.closed {
			f.mu.Unlock()
			return bolt.ErrDatabaseNotOpen
		}
		if f.db == nil {
			if err := os.MkdirAll(filepath.Dir(f.path), 0777); err != nil {
				f.mu.Unlock()
				return err
			}
			db, err := bolt.Open(f.path, 0777, &bolt.Options{Timeout: time.Second})
			if err != nil {
				f.mu.Unlock()
				return err
			}
			db.MaxBatchDelay = time.Millisecond
			db.MaxBatchSize = 128
			f.db = db
		}
		f.mu.Unlock()
	}
}

func (f *BboltStoreImp) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	if f.db != nil {
		return f.db.Close()
	}
	return nil
}

func (f *BboltStoreImp) update(fn func(*bolt.Tx) error) error {
	return f.withDB(func(db *bolt.DB) error { return db.Update(fn) })
}
func (f *BboltStoreImp) view(fn func(*bolt.Tx) error) error {
	return f.withDB(func(db *bolt.DB) error { return db.View(fn) })
}

func (f *BboltStoreImp) Store(key string, data interface{}) error {
	return f.update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte(key))
		if err != nil {
			return err
		}
		dataAny, err := MarshalAnyToProto(data)
		if err != nil {
			return err
		}

		message := FromAny(dataAny)

		result, err := proto.Marshal(message)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(key), result)
	})
}

type DecodeType struct {
	Content []byte `json:"content"`
}

func (f *BboltStoreImp) StoreRaw(key string, data []byte) error {
	return f.update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte(key))
		if err != nil {
			return err
		}
		return bucket.Put([]byte(key), append([]byte(nil), data...))
	})
}

func (f *BboltStoreImp) Load(key string) (*types.Any, error) {

	out := types.Any{}
	return &out, f.view(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(key))
		if bucket == nil {
			return errord.ErrNotFound
		}

		bytes := bucket.Get([]byte(key))
		if bytes == nil {
			return nil
		}

		return proto.Unmarshal(bytes, &out)
	})
}

func (f *BboltStoreImp) LoadRaw(key string) ([]byte, error) {

	var out []byte
	if err := f.view(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(key))
		if bucket == nil {
			return errord.ErrNotFound
		}
		bytes := bucket.Get([]byte(key))
		if bytes == nil {
			return errord.ErrNotFound
		}
		out = append([]byte(nil), bytes...)
		return nil
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// FromAny converts typeurl.Any to anypb.Any.
func FromAny(from typeurl.Any) *anypb.Any {
	if from == nil {
		return nil
	}

	if pbany, ok := from.(*anypb.Any); ok {
		return pbany
	}

	return &anypb.Any{
		TypeUrl: from.GetTypeUrl(),
		Value:   from.GetValue(),
	}
}

func MarshalAnyToProto(from interface{}) (*anypb.Any, error) {
	any, err := typeurl.MarshalAny(from)
	if err != nil {
		return nil, err
	}
	return FromAny(any), nil
}

func NewMockStore() *MockStore {
	return &MockStore{
		data: make(map[string][]byte),
	}
}

type MockStore struct {
	data map[string][]byte
	sync.Mutex
}

func (m *MockStore) Store(key string, data interface{}) error {
	m.Lock()
	defer m.Unlock()

	dataAny, err := MarshalAnyToProto(data)
	if err != nil {
		return err
	}

	message := FromAny(dataAny)
	if strings.Contains(message.String(), "failed") {
		return errord.ErrInvalidArgument
	}

	result, err := proto.Marshal(message)
	if err != nil {
		return err
	}

	m.data[key] = result
	return nil
}

func (m *MockStore) StoreRaw(key string, data []byte) error {
	m.Lock()
	defer m.Unlock()

	if strings.Contains(string(data), "failed") {
		return errord.ErrInvalidArgument
	}
	m.data[key] = append([]byte(nil), data...)
	return nil
}

func (m *MockStore) Load(key string) (*types.Any, error) {
	m.Lock()
	defer m.Unlock()
	if data, ok := m.data[key]; ok {
		any := &types.Any{}
		return any, proto.Unmarshal(data, any)
	}
	return nil, errord.ErrNotFound
}

func (m *MockStore) LoadRaw(key string) ([]byte, error) {
	m.Lock()
	defer m.Unlock()
	if data, ok := m.data[key]; ok {
		return append([]byte(nil), data...), nil
	}
	return nil, errord.ErrNotFound
}

var _ DbStore = &MockStore{}
